# ライセンス規約（リポ固有。OSS 系ビヘイビア）

## 本体ライセンス

- 中核 crate は Apache License 2.0 単独（全文はルートの `LICENSE-APACHE`。OSS-3）。各 crate の `Cargo.toml` の `license = "Apache-2.0"` は `[workspace.package]` で共通化し、`license.workspace = true` で継承する
- 汎用再利用可能な補助 crate は `MIT OR Apache-2.0` を選択肢として残す。採用する場合は crate ごとにユーザー承認を経て、その crate の `Cargo.toml` で `license = "MIT OR Apache-2.0"` を直書きする（workspace 継承を使わない）
- 採用済みの補助 crate: `fandhe-container-plugin`（`crates/plugin/`。外部の plugin の作者もリンクする境界ライブラリ。[#13](https://github.com/Fandhe-AI/fandhe-container/issues/13) のオーナー判断 2026-10-10・TASK-3）
- ライセンス全文はルートの `LICENSE-APACHE`（Apache License 2.0）と `LICENSE-MIT`（MIT License。`Copyright (c) 2026 The fandhe-container Authors`）に置く。`LICENSE` という名前のファイルは置かない

## 依存ライセンス

- 依存は MIT / Apache-2.0 / BSD / ISC / Unlicense / Zlib 等の permissive ライセンスに限る（`deny.toml` の許可リスト）
- GPL / LGPL / AGPL 系・MPL-2.0 等のコピーレフト系の依存は導入しない
- `cargo deny check licenses`（`make deny`・`make ci`・CI の rust-ci に含まれる）で許可外ライセンスを検出したら fail させる（OSS-4・OSS-5・REPAIR-9）

## 非 Cargo 資産

- ビルド時に埋め込むデータ（seccomp プロファイル・CDI サンプル等）・外部テストスイート・VM イメージ / カーネルは `cargo deny` の対象外になる。導入時にライセンスを手動確認し、帰属表示の要否をユーザーに確認する

## subagent への適用

- ライセンス判断が必要な事項（新規ライセンスの許可・補助 crate のデュアルライセンス化・帰属表示の要否）は Agent が決めず、ユーザーへ報告する
