# 宣言的起動設定（複数コンテナ定義）

複数コンテナ定義の書式方針（独自 TOML 正本＋ `compose.yaml` 変換ツール）と、実装を担うタスクとの境界を記録する。

- 方針の決定日: 2026-09-23（D-17・ユーザー選択）
- 関連 issue: #31（TASK-82）・#32（TASK-82.1）
- ステータス: #33（TASK-82.h1）で最終承認待ち
- 対象ビヘイビア: CLI-4（参照先は STACK-1）
- 対象マイルストーン: MS-12（複数コンテナ定義完成。`06-roadmap.md`）

## 方針

- 書式は独自 TOML を正本とする。トップレベルは `[project]`・`[services.<name>]`・`[networks.<name>]`・`[volumes.<name>]`・`[secrets.<name>]`・`[configs.<name>]`（STACK-1）。対象キーの一覧は STACK-1 を参照する（本ドキュメントへの転記はしない）
- 移行用に `compose.yaml` → TOML の片方向変換ツールを付ける。キーは convert・warning・error-incompatible・error-unsupported-yet の 4 分類で扱い、変換レポートを出す（STACK-3）。明示フラグ `--downgrade` による格下げもある（STACK-3・TASK-182）。詳細は各 ID を参照する
- Docker Compose との完全互換（1:1 の互換レイヤー）と Docker Engine API 互換は対象外（D-16、`04-behavior/README.md` の除外事項）。「独自書式＋片方向変換」という本方針はこの除外事項と矛盾しない（D-17）
- `build:` キーは変換時にエラーとし、外部ビルド手順を案内する（STACK-7）

## 経緯

- D-17（`01-brainstorm.md`「方針追記 3」）で本方式を決定した
- PoC-16（`03-poc/compose-toml-conversion/`）で、TOML スキーマの Rust 型化・変換器・キー分類・往復検証が実装可能なことを実証した。変換可率の判定基準は STACK-4 を参照する（一次判定対象コーパスの名称・件数・内容は本ドキュメントに転記しない）
- これを根拠に CLI-4 を Could・検討中から Must・確定に格上げし、STACK-1 を正とする参照項目に改めた（`screen-cli.md` CLI-4）。STACK-1〜STACK-10 は `api-stack.md` に定義されている。個々のビヘイビアのステータスは本ドキュメントでは断定せず、範囲で参照する

## 実装の担当

実装は G11（`api-stack.md`）が担う。**本 TASK（TASK-82）では実装を行わず、検討メモのみを成果物とする**（#31 の受け入れ条件）。以下の TASK は `06-roadmap.md` の MS-12（複数コンテナ定義完成）に属する。

| TASK | 内容 |
| ---- | ---- |
| TASK-149 | TOML スキーマの型定義 |
| TASK-150 | `depends_on` の起動順制御 |
| TASK-151 | `compose.yaml` 変換器 |
| TASK-182 | `--downgrade` フラグ |
| TASK-152 | 実コーパスでの変換可率計測 |
| TASK-153 | 変換不能キーの追加分類 |
| TASK-154 | `build:` のエラー処理 |
| TASK-155 | プロジェクト単位 CLI |
| TASK-156 | GPU 予約から CDI への変換 |
| TASK-187〜188 | `profiles`（STACK-10。2026-09-24 追加） |

crate 配置は、TOML スキーマ・起動順・プロジェクト単位 CLI を `crates/stack/`、`compose.yaml` 変換器を独立した crate・バイナリの `crates/compose-convert/`（`fandhe-container-compose-convert`。compose-convert → stack の一方向依存）とする（#9・TASK-1.h1 で確定。詳細は `crate-naming.md`）。

## 未決事項

- `01-brainstorm.md` の未解決疑問点 13（ビルド機能の扱い）・15（既存 compose 構成の移行方針）は未決のまま（STACK-7 の未解決疑問点）。決まったものとしては扱わない

## 見直し

STACK 系のビヘイビアや G11 のタスク定義が spec 側で変わったら、本ドキュメントも追従して更新する。spec と食い違った場合は spec を正とする。
