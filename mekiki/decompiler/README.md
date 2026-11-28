# mekiki-decomp

Mekiki の Decompile 窓で使う逆コンパイラです。Ghidra の C++ 逆コンパイラ（`ghidra/`）を、Ghidra の Java 部分なしで動かします。Mekiki が別のプロセスとして起動するので、解析中に落ちても Mekiki 本体は落ちません。

- `ghidra/`: Ghidra 12.2 の `Ghidra/Features/Decompiler/src/decompile/cpp` から、逆コンパイルに必要なファイルだけを写したものです（変更なし）。Apache License 2.0（`ghidra/LICENSE.txt`、`LICENSE-APACHE-2.0`）。
- `specs/x86/`: Ghidra 12.2 の `Ghidra/Processors/x86/data/languages` から、実行時に必要なファイル（`.ldefs` `.sla` `.cspec` `.pspec`）だけを写したものです。Apache License 2.0。
- `src/mekiki_decomp.cc`: unforge から渡されたセグメントと関数名で Ghidra の解析器を組み立て、標準入力の命令に従って逆コンパイルする部分です。

```sh
cargo build --release
printf 'seg 0 0 13ce4 R\nseg 14cf0 13cf0 3b790 RE\ndecompile 150a0\n' | target/release/mekiki-decomp specs/x86 path/to/binary x86:LE:64:default:gcc
```
