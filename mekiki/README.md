# Mekiki

unforge の解析結果を見るためのデスクトップアプリです（作成中）。Ghidra の CodeBrowser に近い窓の組み方で、Rust のバイナリに入っている crate・関数・セクションを見られます。

- 解析はこのパソコンの中だけで行います。ファイルはどこにも送りません。
- 中身は `crates/unforge-report`（unforge-elf と unforge-analysis の結果をまとめる部品）を Tauri から直接呼んでいます。

## 画面

| 場所 | 内容 |
| --- | --- |
| Program Tree | セグメントとセクション。押すと Listing がその場所へ移ります |
| Symbol Tree | 関数を「自分のコード」「crate ごと」「標準ライブラリ」「持ち主不明」に分けて表示。下の欄で絞り込めます |
| Listing | 読み込まれるセクションを、アドレス順に 16 バイトずつ表示。関数の始まりに見出しが入ります（逆アセンブルは別のブランチで作成中） |
| Inspector | 選んだ関数・crate・セクション・警告の詳細。crate は crates.io と docs.rs へのリンク付き |
| 下の窓 | Console（記録）、Functions・Crates・Warnings の表（並べ替えと絞り込みができます） |

キー操作: `Ctrl+O` 開く、`G`（か `Ctrl+K`）アドレス・関数・セクション・crate へ移動、`Alt+←` / `Alt+→` 戻る・進む、Listing の中では `↑` `↓` `PageUp` `PageDown` `Home` `End`。

## 動かし方

Node.js と Rust、それに Tauri が必要とするライブラリ（Linux なら `libwebkit2gtk-4.1-dev` など、[Tauri の説明](https://v2.tauri.app/start/prerequisites/)を参照）を入れてから:

```sh
cd mekiki
npm install
npm run dev            # アプリとして開発用に起動
npm run build          # src-tauri/target/release/ にアプリを作る
npm run dev:web        # ブラウザで画面だけ確認する（http://localhost:5176）
npm test               # 画面側の単体テスト
```

`src-tauri` は unforge のワークスペースに入れていません（ルートの `Cargo.toml` の `exclude`）。Tauri が使う多くの crate を、unforge 本体の `Cargo.lock` に混ぜないためです。
