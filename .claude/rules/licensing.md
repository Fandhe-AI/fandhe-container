# ライセンス規約（リポ固有。OSS 系ビヘイビア）

## 本体ライセンス

- 中核 crate は Apache License 2.0 単独（全文はルートの `LICENSE-APACHE`。OSS-3）。各 crate の `Cargo.toml` の `license = "Apache-2.0"` は `[workspace.package]` で共通化し、`license.workspace = true` で継承する
- 汎用再利用可能な補助 crate は `MIT OR Apache-2.0` を選択肢として残す。採用する場合は crate ごとにユーザー承認を経て、その crate の `Cargo.toml` で `license = "MIT OR Apache-2.0"` を直書きする（workspace 継承を使わない）
- 採用済みの補助 crate: `fandhe-container-plugin`（`crates/plugin/`。外部の plugin の作者もリンクする境界ライブラリ。[#13](https://github.com/Fandhe-AI/fandhe-container/issues/13) のオーナー判断 2026-10-10・TASK-3）
- ライセンス全文はルートの `LICENSE-APACHE`（Apache License 2.0）と `LICENSE-MIT`（MIT License。`Copyright (c) 2026 The fandhe-container Authors`）に置く。第三者（Apache-2.0）の成果物から写した部分の帰属告知はルートの `NOTICE` に置く（#1894・OSS-3・OSS-5）。`LICENSE` という名前のファイルは置かない

## 依存ライセンス

- 依存は MIT / Apache-2.0 / BSD / ISC / Unlicense / Zlib 等の permissive ライセンスに限る（`deny.toml` の許可リスト）
- GPL / LGPL / AGPL 系・MPL-2.0 等のコピーレフト系の依存は導入しない
- `cargo deny check licenses`（`make deny`・`make ci`・CI の rust-ci に含まれる）で許可外ライセンスを検出したら fail させる（OSS-4・OSS-5・REPAIR-9）
- サードパーティのライセンス表記は `make third-party-licenses`（cargo-about。`about.toml` の `accepted` は `deny.toml` の allow と同期させる。TASK-103.1）で生成する。cargo-about は Dockerfile で版固定導入し、CI は platform-ci（ubuntu）の `make install-cargo-about` と `make third-party-licenses` で実行する（TASK-103.2。版は Makefile の CARGO_ABOUT_VERSION）

## 非 Cargo 資産

- ビルド時に埋め込むデータ（seccomp プロファイル・CDI サンプル等）・外部テストスイート・VM イメージ / カーネルは `cargo deny` の対象外になる。導入時にライセンスを手動確認し、帰属表示の要否をユーザーに確認する
- 外部の資産（定数一覧・プロファイル・スキーマ等）を写す前に、元リポジトリの LICENSE と NOTICE の有無を commit 指定で一次情報から確認する
- 元に NOTICE がある場合は、Apache-2.0 4(d) に従い関係する帰属行を、出典（リポジトリ・ファイル・commit）と対応するファイルつきでルート `NOTICE` に追記する。関係しない告知の除外の要否は Agent が決めず、ユーザーに報告する
- 元に NOTICE が無い場合は、定義ファイルの先頭と doc に出典を書く（#800 の形）
- `NOTICE` の追記と定義ファイルの出典記載は同じ PR で整合させる

## 配布物への同梱

- 配布物（バイナリ・パッケージ・コンテナイメージ・アーカイブ）には `LICENSE-APACHE`・`LICENSE-MIT`・`NOTICE`・`make third-party-licenses` の出力を同梱する
- 現状は crates.io 公開も配布物の生成も無効（全 crate が `publish = false`、`release.yml` は発火条件を無効化中）で、同梱の自動化は無い。公開・配布を有効化する前に、crate パッケージとバイナリ配布物へ `NOTICE` を含める設計を行う

## subagent への適用

- ライセンス判断が必要な事項（新規ライセンスの許可・補助 crate のデュアルライセンス化・帰属表示の要否）は Agent が決めず、ユーザーへ報告する
