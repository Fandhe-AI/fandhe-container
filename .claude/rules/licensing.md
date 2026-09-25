# ライセンス規約（リポ固有。OSS 系ビヘイビア）

## 本体ライセンス

- 中核 crate は Apache License 2.0 単独（`LICENSE`。OSS-3）。各 crate の `Cargo.toml` に `license = "Apache-2.0"` を記載する（`[workspace.package]` で共通化）
- 汎用再利用可能な補助 crate は `MIT OR Apache-2.0` を選択肢として残す。採用する場合は crate ごとにユーザー承認を経て、`LICENSE-MIT` の追加要否も併せて判断する

## 依存ライセンス

- 依存は MIT / Apache-2.0 / BSD / ISC / Unlicense / Zlib 等の permissive ライセンスに限る（`deny.toml` の許可リスト）
- GPL / LGPL / AGPL 系・MPL-2.0 等のコピーレフト系の依存は導入しない
- `cargo deny check licenses`（`make deny`・`make ci`・CI の rust-ci に含まれる）で許可外ライセンスを検出したら fail させる（OSS-4・OSS-5・REPAIR-9）

## 非 Cargo 資産

- ビルド時に埋め込むデータ（seccomp プロファイル・CDI サンプル等）・外部テストスイート・VM イメージ / カーネルは `cargo deny` の対象外になる。導入時にライセンスを手動確認し、帰属表示の要否をユーザーに確認する

## subagent への適用

- ライセンス判断が必要な事項（新規ライセンスの許可・補助 crate のデュアルライセンス化・帰属表示の要否）は Agent が決めず、ユーザーへ報告する
