# unforge

Rust でビルドされたバイナリを、Rust として読むための部品の集まりです。デスクトップアプリ [Mekiki](../README.ja.md) の中身として使っています。

今あるのは、その土台となる ELF と Windows の PE（`.exe` / `.dll`）の読み取りと、x86 / x86-64 の逆アセンブルと、ストリップされたバイナリの関数に指紋で名前を付ける仕組みです。

- **unforge-elf**: 壊れた ELF や、わざと崩した ELF でも、読めるところまで読む ELF リーダーです。
  - パニックしません。`unsafe` も使いません（`#![forbid(unsafe_code)]`）。
  - データをコピーせず、`zerocopy` で入力のバイト列を直接読みます。
  - 読み取れないのは、ELF のヘッダーすら読めない場合だけです。それ以外の異常は、すべて診断（`audit`）として報告します。Linux カーネルが無視する欄の異常で、読み取りが止まることはありません。
  - 解釈を選ばなければならない場面では、選んだ解釈と、その手がかりと、ほかの候補を記録します。
  - ファイルの中のオフセットと大きさは、すべてオーバーフローを確かめてから使います。ふつうの読み取りでは、メモリを確保しません。
- **unforge-pe**: Windows の PE/COFF（`.exe` / `.dll`）を、壊れていても読めるところまで読むリーダーです。unforge-elf と同じく、パニックせず、`unsafe` を使わず、異常は診断として報告します。
  - DOS ヘッダー、COFF ヘッダー、オプショナルヘッダー（PE32 / PE32+）、データディレクトリ、セクション表を読みます。
  - RVA からファイルの位置への対応は、Windows のローダーと同じ規則で求めます（`PointerToRawData` の下位 9 ビットを無視する、`SizeOfRawData` をファイルの境界に切り上げる、`SectionAlignment` が 4096 未満ならファイルをそのまま写す、など）。
  - インポート（DLL 名、名前か序数、IAT の位置）、エクスポート（転送を含む）、ベース再配置、x64 の `.pdata`（`RUNTIME_FUNCTION`、ストリップされた PE で関数の境界を知る一番の手がかり）、TLS コールバック、デバッグディレクトリと CodeView の PDB パス、MinGW の COFF シンボルを読みます。
  - 試験用に、最小の PE をその場で組み立てる `synth` も持っています。
- **unforge-disasm**: x86 / x86-64 の機械語を、Intel 記法の命令の並びに戻します。
  - 命令ごとに、アドレス、長さ、命令の文字列、制御の流れ（呼び出し、ジャンプ、条件ジャンプ、リターンなど）、飛び先や RIP 相対で指すアドレスを返します。
  - ELF の関数のバイト列は、`PT_LOAD` セグメントを通して探します。ファイルの終わりで切れたセグメントや、`p_filesz` より先（ゼロで埋まる部分）は読みません。大きさの分からない関数は、最初のリターンまで（最大 4096 バイト）を読みます。
  - PE の関数のバイト列は、セクションの対応を通して探します（アドレスは `ImageBase + RVA`）。セクションのうちファイルにない部分（ゼロで埋まる部分）は読みません。CPU は COFF の machine で決めます（`0x8664` は x86-64、`0x14c` は x86）。
  - 命令の解読には [iced-x86](https://crates.io/crates/iced-x86) を使います。ワークスペースでただ一つのサードパーティの命令デコーダーで、使う機能（`std`、`decoder`、`intel`、`instr_info`）だけを有効にしています。
  - 解読できないバイトは 1 バイトの `(bad)` として報告し、次のバイトから続けます。どんな入力でもパニックしません。
- **unforge-sigs**: 関数の指紋（配置で変わるアドレスや分岐先を伏せた命令列のハッシュ）を作り、シンボルの残っているバイナリから指紋のデータベースを作って、ストリップされたバイナリの関数に名前を付けます（IDA の FLIRT、Ghidra の Function ID と同じ考え方）。
  - 同じ std を含む別のプログラムどうしで、精度 99〜100 %、再現率 85〜87 %（testdata のプログラム、リリースビルド）。詳しい数字と正規化の規則は [crates/unforge-sigs/README.md](../crates/unforge-sigs/README.md) にあります。
  - データベースは版付きのバイナリ形式で、同じ入力からは必ず同じバイト列になります。
- **unforge**（CLI）: ELF のヘッダー、セグメント、セクション、シンボルを表示します。PE のヘッダー、セクション、インポート、エクスポート、`.pdata`、TLS コールバックを表示します（`unforge pe`）。x86 / x86-64 の関数を、ELF でも PE でも逆アセンブルして表示します（呼び出し先が見つかった関数や、PE の IAT を通した呼び出しなら、その名前も添えます）。指紋のデータベースを作り、それで関数に名前を付けます。
- **unforge-report**: 解析の結果（関数、crate とその版、セクション、セグメント、警告）を、画面で使う形にまとめます。
- **Mekiki**（`mekiki/`）: 解析の結果を見るデスクトップアプリです。詳しくは [mekiki/README.md](../mekiki/README.md) を見てください。

```sh
cargo run -p unforge -- elf --header --segments --sections --symbols path/to/binary
cargo run -p unforge -- elf --strict --loader-checks path/to/binary
cargo run -p unforge -- pe --imports --pdata path/to/malware.exe
cargo run -p unforge -- disasm --addr 0x140001000 path/to/malware.exe
cargo run -p unforge -- disasm --function main --count 50 path/to/binary
cargo run -p unforge -- disasm --addr 0x401000 path/to/binary
cargo run -p unforge -- sig build -o std.db path/to/with-symbols...
cargo run -p unforge -- sig match --db std.db path/to/stripped
```

## 試験

```sh
cargo test
```

- `crates/unforge-elf/tests/`: 境界の試験、ファズで見つかった入力の再実行、実際のバイナリとの突き合わせ（`object` と `goblin` の結果と比べる）。
- `crates/unforge-disasm/tests/`: 試験の実行ファイル自身の関数を逆アセンブルし、`objdump -d -M intel` の結果と命令の区切りと名前を比べます（objdump がなければ飛ばします）。壊れた ELF や乱数のバイト列でパニックしないことも確かめます。
- `crates/unforge-sigs/tests/`: 試験の実行ファイル自身と、その場で `rustc` でビルドした std だけの小さなプログラム二つ（ストリップは `objcopy`）で、名前の付け直しの精度と再現率を確かめます（rustc か objcopy がなければ飛ばします）。壊れた ELF や乱数のバイト列、壊れたデータベースでパニックしないことも確かめます。
- `testdata/`: 試験に使う実際のバイナリを作るための Rust のプログラムと、ビルド用のスクリプト（`testdata/build.sh`）。作ったバイナリは commit していません。詳しくは [testdata/README.md](../testdata/README.md) を見てください。
- `fuzz/`: cargo-fuzz のファズ対象。既知の違いは [fuzz/KNOWN_DIVERGENCES.md](../fuzz/KNOWN_DIVERGENCES.md) にあります。

## ライセンス

MIT または Apache-2.0 のどちらかを選んで利用できます（[LICENSE-MIT](../LICENSE-MIT)、[LICENSE-APACHE](../LICENSE-APACHE)）。

RustSecJP は非公式のコミュニティです。Rust Project、Rust Foundation とは提携していません。
