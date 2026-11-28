# sigs: 指紋データベースを作る

ストリップされた Rust のバイナリ（マルウェアなど）の関数に名前を付けるための、指紋のデータベース（`unforge sig match` と Mekiki で読む `.db` ファイル）を、GitHub Actions で作ります。指紋とデータベースの形式は [crates/unforge-sigs/README.md](../crates/unforge-sigs/README.md) を見てください。

ワークフローは [.github/workflows/sigs.yml](../.github/workflows/sigs.yml) です。毎週日曜日（04:41 UTC）に動くほか、Actions の画面から手で動かせます（`workflow_dispatch`）。

## 作るもの

成果物（artifact）は二つで、30 日残ります。

| artifact | 中身 |
|---|---|
| `sig-std` | Rust の版ごとの標準ライブラリのデータベース `std-<版>-<コミット 9 桁>.db`、版と rustc のコミットの対応表 `TOOLCHAINS.tsv`、版ごとの詳細 `std-<版>-<コミット>.json`、`SHA256SUMS` |
| `sig-crates` | crate の版と rustc ごとのデータベース `<crate>-<版>-rustc<rustc の版>.db`、それを rustc ごとにまとめた `crates-rustc<rustc の版>.db`、一覧 `CRATES.tsv`、`SHA256SUMS` |

どちらにも、作ったときの unforge のコミット（`UNFORGE_COMMIT`）と元の一覧（`toolchains.txt`、`crates.toml`）が入ります。実行ごとの表（crate、版、バイナリの数、追加した関数の数、結果）は、その実行の Summary に出ます。

- **std**: [toolchains.txt](toolchains.txt) の版ごとに、その版の rustc で、このリポジトリの std だけのプログラム（`testdata/src/` の実行ファイル 5 本と [std/](std/) の 2 本）を、3 つのターゲット（`x86_64-unknown-linux-gnu`、`x86_64-unknown-linux-musl`、`i686-unknown-linux-musl`）と 6 つのプロファイル（opt-level 3 / s / z、デバッグ、opt-level 3 で panic=abort、opt-level z で LTO・codegen-units 1・panic=abort）でビルドし、シンボルを残したまま一つのデータベースにします。std はビルド済みで配られるので、同じ版ならどのプログラムでも同じコードですが、ジェネリック関数と `#[inline]` の関数は使う側の最適化レベルでコンパイルされるので、プロファイルを変えて入れています。
- **crate**: [crates.toml](crates.toml) の crate と版ごとに、crates.io に公開されたソースを取ってきて、その crate 自身の試験・例・ベンチ（`cargo test --no-run --release`）をビルドします。crate ごとの専用のプログラムは書きません。試験と例は crate の API をひととおり呼ぶので、その実行ファイルに crate のコードの多くが入ります。リリースビルドの既定の設定で、シンボルは残し、DWARF は落とします（`strip = "debuginfo"`）。

## rustc のコミット

unforge は、マルウェアの中のパス（`/rustc/<40 桁のコミット>/library/...`）から、それをビルドした rustc のコミットを読み取ります。std のデータベースは、そのコミットのものを使ってください。

- ファイル名の `<コミット 9 桁>` と、`TOOLCHAINS.tsv` の `rustc_commit`（40 桁、`rustc -vV` の `commit-hash`）が、そのコミットです。
- データベース自身も、元にしたバイナリの依存（`rustc <コミット>`、`tokio 1.54.1` など）を覚えています。`unforge sig match` は、対象のバイナリの依存のうち、データベースが知らないものを表示します。

```sh
unforge sig match --db std-1.99.0-b940084d7.db malware > /dev/null   # 足りない rustc のコミットや crate が表示される
```

## 使い方

Actions の画面で `sigs` の実行を開き、下の Artifacts から `sig-std` と `sig-crates` を落とします（zip です）。`gh` なら:

```sh
gh run list -R RustSecJP/unforge -w sigs
gh run download <run-id> -R RustSecJP/unforge -n sig-std -D sig-std
gh run download <run-id> -R RustSecJP/unforge -n sig-crates -D sig-crates
sha256sum -c sig-std/SHA256SUMS
```

`unforge sig match` で使うときは、対象の rustc のコミットの std と、入っている crate のデータベースを一つにまとめます。

```sh
unforge sig build -o malware.db sig-std/std-1.99.0-b940084d7.db sig-crates/crates-rustc1.99.0.db
unforge sig match --db malware.db path/to/stripped
```

Mekiki では、「File → Load Fingerprint Databases…」で `.db` を選びます（Mekiki のデータフォルダーの `signatures/` に写され、次に開くファイルから使われます）。読み込んだデータベースはすべてまとめて使われるので、std は対象の rustc のコミットのものだけを入れてください。別の版の std を一緒に入れると、版の違う同じ名前の関数が衝突して、`ambiguous` が増えます。

## 版と crate を足す

- **Rust の版**: [toolchains.txt](toolchains.txt) に一行足します。正式な版だけです（`1.100.1` のような小さい版も、コミットが違うので別に入れます）。`rust-toolchain.toml` の版は必ず入れてください（入っていないと `prepare` が止まります）。新しいプログラムを [std/](std/) に足すときは、std だけで、edition 2021 で、`unsafe` を使わず、一覧の一番古い版でもビルドできるようにしてください（`rustc +<版> --edition 2021 sigs/std/<名前>.rs` で確かめられます）。
- **crate**: [crates.toml](crates.toml) に `[[crate]]` を足します。版は `=` で固定する正確な版です。版ごとにコードが違い、マルウェアは古い版を使っていることが多いので、よく使われる版を複数入れるのがよいです。`features` で試す機能を、`env` でビルドのときに要る環境変数を指定できます（どちらも厳しく確かめます）。ビルドできる機能の組み合わせは、`features`、`--all-features`、既定、`--lib` の順に試し、使ったものを Summary に出します。
- **crate を作る rustc**: `crates.toml` の `rustc` に版を足すと、crate ごとにその版でもビルドします（ジョブの数がその分だけ増えます）。
- 一つの crate が失敗しても、ワークフロー全体は止まりません。失敗は Summary の表に出ます。

## 安全のための決まり

crates.io の crate をビルドすると、その crate と依存のビルドスクリプトと手続きマクロ（他人のコード）が動きます。それは GitHub Actions の `crate-build` ジョブの中だけで行い、手元のパソコンでは決して行いません（`sigs/scripts/build-crate.sh` は GitHub Actions の外では動きません）。

- どのジョブにも秘密の値は渡さず、トークンは読み取りだけです（`permissions: contents: read`）。チェックアウトはトークンを残しません（`persist-credentials: false`）。
- crate は `$RUNNER_TEMP` の中、チェックアウトの外で、専用の `CARGO_HOME` を使ってビルドします。crate の中の `.cargo/` と `rust-toolchain` は消し、rustc はこちらで決めます。
- unforge は、他人のコードが動くどのジョブよりも先に、`tools` ジョブでこのチェックアウトから作ります。他人のコードが動く `crate-build` の機械には unforge を置きません。ビルドした実行ファイルは、データとして別のジョブ（`crate-db`、他人のコードが一度も動いていない新しい機械）に渡し、そこで sha256 を確かめた unforge で読むだけです。実行ファイルは決して実行しません。
- キャッシュは使いません。他人のコードのビルド結果が、unforge のビルドに混ざらないようにするためです。
- crate のデータベースの名前は、その crate の作者が書いたコードから来ています。ほかのシンボルと同じく、手がかりとして扱ってください。成果物の実行ファイルやデータベースは信用できないデータとして扱い、解析だけに使ってください。
