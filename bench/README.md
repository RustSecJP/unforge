# bench: unforge のベンチマーク

unforge の目的は、マルウェア解析者がストリップされた Rust バイナリを読めるように
することです。このディレクトリは、その達成度を機械的に点数にする仕組みです。
点数は「ストリップ済みバイナリから unforge が復元したもの」と「同じバイナリの
デバッグ情報（DWARF）から取り出した正解」の比較で決まります。今後の改善は、
この点数を上げることを目標に何度も自動で繰り返す前提です。

```
bench/
  corpus.toml            コーパスに入れる crates.io のクレートとビルドバリアント
  build-testdata.sh      testdata/src の自前プログラムからコーパスを作る（ローカル可）
  scripts/
    build-crate.sh       crates.io のクレートをビルドする（GitHub Actions 専用）
    corpus.py            corpus.toml の読み取り（ワークフロー用）
    write-meta.py        <id>.meta.json を書く
  results/<日付>-<split>.json   採点結果（unforge-bench run の出力）
  corpus/                ローカルで作ったコーパス（コミットしない）
crates/unforge-analysis  採点される解析 API（Analysis::functions / dependencies）
crates/unforge-bench     正解の抽出（truth）、採点（score）、一括採点（run）
.github/workflows/bench-corpus.yml   crates.io コーパスを作るワークフロー
```

## 指標と、解析者にとっての意味

すべて 0〜100 の百分率です。

### M1 関数の境界

ストリップされたバイナリにはシンボルがなく、どこからどこまでが一つの関数か
わかりません。関数の境目がわからないと、逆アセンブラの出力は読めず、関数単位の
名前付けやシグネチャ照合もできません。

- **開始位置**: 復元した関数の開始アドレスが正解と完全に一致した数で、
  適合率（precision）・再現率（recall）・F1 を出します。
- **バイト被覆**: 復元した `[start, start + size)` の和集合と、正解の和集合の
  重なりで P/R/F1 を出します。開始位置は合っていても大きさが違う場合を見ます。

正解の関数は、アドレスを持つすべての `DW_TAG_subprogram`（インライン関数の
アウトオブライン版を含む）、DWARF のない関数シンボル（C ランタイム、静的リンクの
libc、アセンブリ）、エントリポイントです。

### M2 クレートの帰属

Rust のバイナリでは、コードの大半が標準ライブラリと依存クレートです。解析者が
本当に読みたいのは、マルウェア作者が書いた部分（user）だけです。M2 は、M1 で
開始位置を正しく見つけた関数について、次のどれかを当てられたかを見ます。

- `user`: ビルドしたパッケージ自身のコード
- `dep:<crate>`: 依存クレートのコード（クレート名まで一致して正解）
- `std`: 標準ライブラリ、std が同梱するクレート、C ランタイムなど

数字は三つあります。

- **accuracy**（正解率）: 見つけた関数のうちグループが正しい割合。総合点に使います。
- **user/lib**: 「作者のコードか、それ以外か」の二値の正解率。解析者にとって
  一番大事な区別なので別に出します。
- **coverage**: 正しく帰属できた関数 ÷ 正解の全関数。

グループを答えなかった関数は不正解です。何も見つけられなかったときは 0 です。

正解のクレートは、関数を囲む一番外側の `DW_TAG_namespace` です（定義した
クレート。`core` のジェネリック関数を利用者のコードが使ってできた実体は `core`）。
グループは宣言ファイルのパスで決めます: `/rustc/<commit>/...` と
`/rust/deps/...` は std、`registry/src/<index>/<crate>-<ver>/...` はビルドした
パッケージなら user、それ以外は依存です。パスがないときは CU 名と Cargo.lock で
決めます（詳しくは `crates/unforge-bench/src/truth.rs` の先頭）。

### M3 依存クレートの復元

どのクレートのどのバージョンが入っているかは、既知の脆弱性、使われている
暗号・通信ライブラリ、ビルド環境の推定に直結します。M3 は、バイナリから
復元した（パッケージ名, バージョン）の組と正解を比べた P/R/F1 です。名前の
`-` と `_`、大文字小文字は区別しません。名前だけで比べた F1 も参考に出します。

正解は Cargo.lock のパッケージのうち、実際にコードがバイナリに入っているもの
です（Cargo.lock には Windows 用など、ビルドされないパッケージも並ぶため）。
ツールチェーンも重要な手がかりなので、`rustc` をコミットハッシュ付きで一つの
依存として数えます。

### 総合点

- **total** = (M1 開始位置 F1 + M2 accuracy + M3 F1) / 3
- **total_strict** = (M1 開始位置 F1 + M2 coverage + M3 F1) / 3

M2 accuracy は「見つけた関数の中での正解率」なので、自信のある少数の関数だけを
答えると上がってしまいます。自動改善でこれを利用しないよう、total と一緒に
total_strict も必ず見てください（両方が下がらないこと）。

## コーパス

### 形式

コーパスは一つのディレクトリに、バイナリごとに次の 4 ファイルを置いたものです。

| ファイル | 内容 |
|---|---|
| `<id>.debug` | `debug = 2`（完全な DWARF）でビルドしたバイナリ |
| `<id>.stripped` | 同じファイルを `objcopy --strip-all` したもの。採点はこちらだけを解析します |
| `<id>.meta.json` | クレート、バージョン、バイナリ名、ターゲット、バリアント、`rustc -vV`、両ファイルの sha256、ビルドに使った Cargo.lock |
| `<id>.truth.json` | `unforge-bench truth` が DWARF から作った正解 |

`<id>` は crates.io のものが `<crate>-<version>-<bin>-<gnu|musl>-<variant>`、
testdata のものが `<program>-<gnu|musl>-<variant>` です。

### crates.io のコーパス（GitHub Actions）

`bench/corpus.toml` に、Rust 製マルウェアによくある依存（reqwest / hyper / tokio、
chacha20poly1305 / sha2 / aes、flate2 / zip、base64 / serde_json、sysinfo /
walkdir、clap）を持つ有名なバイナリクレートを、正確なバージョンで並べています。
`cargo install --locked` で、クレートに同梱の Cargo.lock のとおりにビルドします。

v0 のバリアントは次の三つです（いずれも `codegen-units = 1`、`debug = 2`、
x86_64-unknown-linux-gnu）。

| 名前 | opt-level | lto | panic |
|---|---|---|---|
| `o0` | 0 | off | unwind |
| `o3` | 3 | off | unwind |
| `oz-fat-abort` | z | fat | abort（マルウェアに多いサイズ優先の設定） |

`o2-fat` は定義だけして無効にしています。aarch64 は今後の課題です。

ワークフロー `bench-corpus`（毎週月曜に自動実行、手動でも実行可）が全クレートを
ビルドし、testdata の分も加えて、一つの成果物 `bench-corpus` にまとめます。
成果物には、その時点のコミットでの採点結果（`<日付>-all.json`、
`summary.txt`）も入ります。一つのクレートが失敗しても全体は止まらず、失敗は
`FAILED-<crate>.txt` に残ります。

```sh
gh workflow run bench-corpus            # 手動実行
gh run download <run-id> -n bench-corpus -D bench/corpus/crates
```

### testdata のコーパス（ローカル）

`testdata/src` の自前プログラム（collections、enums、traits、panics、
ffi_statics）を、上と同じ三つのバリアントで、gnu（glibc 動的リンク）と
musl（静的リンク）の両方についてビルドします。rustc を直接呼ぶだけで、cargo も
ビルドスクリプトも使いません。

```sh
cargo build --release -p unforge-bench
bench/build-testdata.sh                 # bench/corpus/testdata に 30 件
```

## 採点の仕方

```sh
B=target/release/unforge-bench

# 正解を作る（<stem>.meta.json が隣にあれば自動で読みます）
$B truth bench/corpus/testdata/enums-gnu-o3.debug -o enums.truth.json

# 1 件を採点（--json で機械向けの出力）
$B score --stripped bench/corpus/testdata/enums-gnu-o3.stripped --truth enums.truth.json

# コーパス全体を採点し、bench/results/<日付>-<split>.json に書く
$B run bench/corpus/testdata
$B run bench/corpus/crates --split train
```

`run` は `<id>.truth.json` がなければ `<id>.debug` からその場で正解を作ります
（ファイルには書きません）。結果には 1 件ごとの全指標と、全体・split 別・
バリアント別の平均（1 バイナリを 1 票とする単純平均）が入ります。

## train / eval の分け方と改善のルール

各クレートは、名前（`-`/`_` と大文字小文字をそろえたもの）の FNV-1a 64 ビット
ハッシュを 10 で割った余りが 0〜2 なら eval、それ以外なら train です
（約 30% が eval）。バージョンやバリアントが違っても、同じクレートは必ず同じ側に
入ります。どちらに入るかは `unforge-bench split <crate>...` で確かめられます。

現在の割り当て:

| split | crates.io | testdata |
|---|---|---|
| train | ripgrep, hyperfine, xh, miniserve, oha, tokei, zoxide, ouch, bottom | collections, enums |
| eval | fd-find, bat, du-dust, sd, rage, git-delta | traits, panics, ffi_statics |

ルール:

1. **eval のクレートは調整に一切使いません。** シグネチャやバイト列パターンの
   抽出、閾値の決定、失敗例を見ての手直しは、すべて train だけで行います。
   eval の個々の結果を見て直すことも調整に含みます。
2. **改善は、eval の点数を上げ、かつ train の点数を下げないものだけを採用します。**
   total と total_strict の両方で確かめます。
3. eval の数字は採否の判断にだけ使い、変更前後の `run --split eval` の集計値
   （平均）だけを比べます。

コーパスにクレートを足すときも、どちらに入るかは名前で自動的に決まります。
ルールを変えると過去の結果と比べられなくなるので、split の規則は変えないで
ください（`run.rs` のテストで固定しています）。

## 安全上の注意（ビルドスクリプト）

crates.io のクレートをビルドすると、そのクレートと全依存のビルドスクリプト
（`build.rs`）と手続きマクロが、ビルドするマシンの上で実行されます。これは
第三者のコードです。

- crates.io のクレートのビルドは **GitHub Actions の中だけ** で行います。
  手元のマシンでは、unforge 自身と `testdata/src` の自前プログラムしか
  ビルドしません。
- ワークフローはシークレットを使わず、権限は `contents: read` だけで、
  checkout はトークンを残しません（`persist-credentials: false`）。ビルドは
  チェックアウトの外（`$RUNNER_TEMP`）で行います。
- `bench/scripts/build-crate.sh` は `GITHUB_ACTIONS=true` のとき以外は
  実行を拒否します。
- コーパスのバイナリは信頼できないものとして扱い、解析だけして、実行しないで
  ください。

## 既知の制約（v0）

- 正解のクレートとグループは DWARF の名前空間と宣言パスから決めています。
  DWARF を持たない依存の C/アセンブリ（ring、zstd-sys などの一部）は、
  シンボル名がなければ std として数えます。
- `[profile.release.package.<name>]` のようなクレートごとの上書きがあると、
  meta.json のバリアントと実際の設定が一部のクレートで違うことがあります。
- 圧縮された DWARF セクションは読みません（GitHub の ubuntu-latest の
  既定では圧縮されません）。
- testdata には依存クレートがないため、testdata だけの M3 は `rustc` の
  1 件だけで決まります。

## ベースライン（2026-11-21、testdata 30 件）

初期実装は逆アセンブルをせず、残っているシンボル（ストリップ後は `.dynsym` だけ）と
エントリポイントから関数を、ロードされるバイト列のソースパスから依存を拾うだけです。
`results/2026-11-21-all.json` が全件の結果です。

| 集計 | 件数 | M1 開始 F1 | M1 バイト F1 | M2 acc | M2 user/lib | M3 F1 | total | strict |
|---|---|---|---|---|---|---|---|---|
| 全体 | 30 | 0.31 | 0.00 | 0.00 | 0.00 | 100.00 | 33.44 | 33.44 |
| train | 12 | 0.31 | 0.00 | 0.00 | 0.00 | 100.00 | 33.44 | 33.44 |
| eval | 18 | 0.31 | 0.00 | 0.00 | 0.00 | 100.00 | 33.44 | 33.44 |
| o0 | 10 | 0.24 | 0.00 | 0.00 | 0.00 | 100.00 | 33.41 | 33.41 |
| o3 | 10 | 0.30 | 0.00 | 0.00 | 0.00 | 100.00 | 33.43 | 33.43 |
| oz-fat-abort | 10 | 0.38 | 0.00 | 0.00 | 0.00 | 100.00 | 33.46 | 33.46 |
