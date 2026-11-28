# unforge

Rust でビルドされたバイナリを、Rust として読むための道具です（作成中、v0.1）。

今あるのは、その土台となる ELF の読み取りと、x86 / x86-64 の逆アセンブルです。

- **unforge-elf**: 壊れた ELF や、わざと崩した ELF でも、読めるところまで読む ELF リーダーです。
  - パニックしません。`unsafe` も使いません（`#![forbid(unsafe_code)]`）。
  - データをコピーせず、`zerocopy` で入力のバイト列を直接読みます。
  - 読み取れないのは、ELF のヘッダーすら読めない場合だけです。それ以外の異常は、すべて診断（`audit`）として報告します。Linux カーネルが無視する欄の異常で、読み取りが止まることはありません。
  - 解釈を選ばなければならない場面では、選んだ解釈と、その手がかりと、ほかの候補を記録します。
  - ファイルの中のオフセットと大きさは、すべてオーバーフローを確かめてから使います。ふつうの読み取りでは、メモリを確保しません。
- **unforge-disasm**: x86 / x86-64 の機械語を、Intel 記法の命令の並びに戻します。
  - 命令ごとに、アドレス、長さ、命令の文字列、制御の流れ（呼び出し、ジャンプ、条件ジャンプ、リターンなど）、飛び先や RIP 相対で指すアドレスを返します。
  - ELF の関数のバイト列は、`PT_LOAD` セグメントを通して探します。ファイルの終わりで切れたセグメントや、`p_filesz` より先（ゼロで埋まる部分）は読みません。大きさの分からない関数は、最初のリターンまで（最大 4096 バイト）を読みます。
  - 命令の解読には [iced-x86](https://crates.io/crates/iced-x86) を使います。ワークスペースでただ一つのサードパーティの命令デコーダーで、使う機能（`std`、`decoder`、`intel`、`instr_info`）だけを有効にしています。
  - 解読できないバイトは 1 バイトの `(bad)` として報告し、次のバイトから続けます。どんな入力でもパニックしません。
- **unforge**（CLI）: ELF のヘッダー、セグメント、セクション、シンボルを表示します。x86 / x86-64 の関数を逆アセンブルして表示します（呼び出し先が見つかった関数なら、その名前も添えます）。

```sh
cargo run -p unforge -- elf --header --segments --sections --symbols path/to/binary
cargo run -p unforge -- elf --strict --loader-checks path/to/binary
cargo run -p unforge -- disasm --function main --count 50 path/to/binary
cargo run -p unforge -- disasm --addr 0x401000 path/to/binary
```

## 試験

```sh
cargo test
```

- `crates/unforge-elf/tests/`: 境界の試験、ファズで見つかった入力の再実行、実際のバイナリとの突き合わせ（`object` と `goblin` の結果と比べる）。
- `crates/unforge-disasm/tests/`: 試験の実行ファイル自身の関数を逆アセンブルし、`objdump -d -M intel` の結果と命令の区切りと名前を比べます（objdump がなければ飛ばします）。壊れた ELF や乱数のバイト列でパニックしないことも確かめます。
- `testdata/`: 試験に使う実際のバイナリを作るための Rust のプログラムと、ビルド用のスクリプト（`testdata/build.sh`）。作ったバイナリは commit していません。詳しくは [testdata/README.md](testdata/README.md) を見てください。
- `fuzz/`: cargo-fuzz のファズ対象。既知の違いは [fuzz/KNOWN_DIVERGENCES.md](fuzz/KNOWN_DIVERGENCES.md) にあります。

## ライセンス

MIT または Apache-2.0 のどちらかを選んで利用できます（[LICENSE-MIT](LICENSE-MIT)、[LICENSE-APACHE](LICENSE-APACHE)）。

RustSecJP は非公式のコミュニティです。Rust Project、Rust Foundation とは提携していません。
