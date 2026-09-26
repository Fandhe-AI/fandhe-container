# CLAUDE.md

## Overview

Rust でフルスクラッチ開発する軽量なコンテナ実行基盤の実装リポジトリ。Docker の課題（リソース消費の大きさ・ボリューム I/O のボトルネック・macOS / Windows での VM 越境オーバーヘッド）の是正を目指す。

- **本リポは public**。仕様・ビヘイビア定義の SSOT は private リポ [fandhe-container-spec](https://github.com/Fandhe-AI/fandhe-container-spec)（`docs/spec` submodule の `04-behavior/`）。spec の内容は本リポに載せてよいが、ビヘイビア ID を併記して SSOT へ辿れるようにする（[spec-reference](.claude/rules/spec-reference.md)）
- 実装方針の要点は README「実装方針（要点）」を参照（フルスクラッチ・OCI / CRI 互換・I/O レイヤー再設計・3 OS 一級対応・plugin 分割・GPU / network / 複数コンテナ定義 / 監視・AI 自己補修）
- 依存は最小・`=x.y.z` 完全固定・ユーザー承認制。youki / Firecracker / Cloud Hypervisor / rust-vmm のコード・クレートは使わない（[dependency-policy](.claude/rules/dependency-policy.md)）。ライセンスは中核 Apache-2.0 単独（[licensing](.claude/rules/licensing.md)）
- **実装の着手はユーザーの明示指示を経てから**行う。タスク定義は spec の `05-tasks.md`（TASK-n・グループ G0〜G12）、マイルストーンは `06-roadmap.md`（MS-1〜14）
- 進捗・ステータスは本ファイルに逐次記録しない（Issue で管理する）

## Repository Structure

「（予定）」は spec のタスク定義に基づく計画上の配置で、まだ存在しない。crate の短縮名は spec の仮称で、TASK-1（REPAIR-1）で確定する。

```text
fandhe-container/
├── CLAUDE.md                      # Claude 運用方針（本ファイル）
├── AGENTS.md                      # AI PR レビュー観点集 / ビルド・回帰確認コマンド（REPAIR-10）
├── README.md                      # 概要・実装方針（要点）・開発環境構築
├── MAINTAINERS.md                 # メンテナンス体制・コアチーム（TASK-100・OSS-6）
├── LICENSE                        # Apache License 2.0
├── rust-toolchain.toml            # stable + rustfmt/clippy（単一真実源）
├── .editorconfig / .gitattributes # インデント・改行（LF 固定）・文字コード規約
├── skills-lock.json               # 導入スキルのロックファイル
├── Makefile                       # 開発タスク集約（lint-docs・fmt・clippy・test・deny・docker-*。`make help`）
├── lefthook.yml                   # git hooks（整形・秘密情報検査・commit-msg・pre-push）
├── commitlint.config.mjs          # commitlint 設定（type を 9 種に限定）
├── Dockerfile / compose.yaml      # 開発コンテナ（環境非依存の `make docker-ci`）
├── .markdownlint.jsonc / .yamllint / .editorconfig-checker.json  # lint-docs 設定
├── deny.toml                      # cargo-deny 設定（ライセンス・advisories・sources 検査）
├── Cargo.toml                     #（予定）workspace 定義
├── crates/                        #（予定。crate 名前空間は fandhe-container-*）
│   ├── io/                        #   I/O 共有層（バッチ write-back・フラッシュバリア・FS 正規化）
│   ├── core/                      #   実行層（namespace・cgroups v2・seccomp/Landlock・rootless）
│   ├── supervisor/                #   コンテナごとの軽量監視プロセス
│   ├── oci/ / cri/                #   OCI イメージ・ライフサイクル / CRI
│   ├── platform-macos/ / platform-windows/ / microvm/  # プラットフォーム層
│   ├── gpu/ / net/                #   GPU パススルー（CDI）/ network
│   ├── plugin-api/                #   plugin 境界機構（UDS＋長さ接頭辞フレーム）
│   ├── cli/ / stack/              #   統一 CLI / 複数コンテナ定義（TOML・compose 変換）
│   └── plugin-*/                  #   fandhe-container-plugin-cri / -macos / -windows / -microvm / -mcp
├── scripts/ / benches/            #（予定）依存禁止判定等 / ベンチ回帰（REPAIR-8）
├── docs/
│   ├── design/                    # 設計決定・拡張点・リソース効率目標
│   │   ├── orchestration-scope.md # オーケストレーション スコープ（TASK-5・CRI-8）
│   │   ├── from-scratch-policy.md # フルスクラッチ方針・依存基準（TASK-7・MS-0）
│   │   ├── resource-efficiency-target.md  # リソース効率目標値（TASK-48・CORE-8）
│   │   ├── declarative-config.md  # 宣言的起動設定の方針メモ（TASK-82・CLI-4）
│   │   ├── small-model-repair-policy.md  # 小型モデル自己補修方針（TASK-92・REPAIR-11/13/14）
│   │   └── crate-naming.md        # crate 短縮名・plugin crate 配置のドラフト（TASK-1・REPAIR-1）
│   └── spec/                      # fandhe-container-spec submodule（private・要アクセス権）
├── .github/workflows/             # ai-review・update-external（稼働）/ ci・release（発火条件無効化中）
├── .agents/skills/                # npx skills add の導入実体
└── .claude/
    ├── agents/                    # カテゴリ別 subagent 定義
    ├── rules/                     # 運用ルール
    ├── skills/                    # 導入スキル（.agents/skills への symlink）
    ├── workflows/                 # implement-issue-tree.js（相対 symlink）
    └── settings.json              # SessionStart / PostToolUse hooks
```

## 委譲方針（必読）

main セッションはオーケストレーションに徹し、調査・実装・レビューは subagent へ委譲してコンテキスト消費を抑える。詳細は [delegation](.claude/rules/delegation.md)（調査）・[delegation-impl](.claude/rules/delegation-impl.md)（実装）を参照。

### パスベース切り替え表

| 対象 | 調査 | 作成・編集 |
| ---- | ---- | ---------- |
| `crates/io/` | explorer | io-builder |
| `crates/core/`・`crates/supervisor/` | explorer | runtime-builder |
| `crates/oci/`・`crates/cri/`・`plugin-cri` | explorer | oci-cri-builder |
| `crates/platform-*/`・`crates/microvm/`・`plugin-macos` / `-windows` / `-microvm` | explorer | platform-builder |
| `crates/gpu/` | explorer | gpu-builder |
| `crates/net/` | explorer | net-builder |
| `crates/plugin-api/`・`plugin-mcp` | explorer | plugin-builder |
| `crates/cli/`・`crates/stack/` | explorer | cli-stack-builder |
| `Cargo.toml`・CI・`deny.toml`・`Makefile`・`lefthook.yml`・`Dockerfile`・`scripts/`・`benches/` | explorer | infra-builder |
| `docs/spec/`（private） | explorer | 変更しない（spec リポ側で管理） |
| 外部仕様（OCI / CRI・Linux カーネル API・Virtualization.framework・WSL2・KVM・CDI・MCP） | reference-researcher | — |
| テスト・lint | test-runner / linter | — |
| ドキュメント・`AGENTS.md`・`.claude/`（agents・rules・settings.json） | explorer | docs-writer |

### model 配分表

| 用途 | model |
| ---- | ----- |
| 複雑な横断判断・アーキテクチャ設計（crate 境界・core/plugin 境界・拡張点トレイト・I/O 契約） | opus または fable（fable は特に大規模設計・横断判断の最上位 tier） |
| 調査・生成・実装・レビュー | sonnet |
| 機械的集計・lint・ドキュメント更新 | haiku |

## Sub-agents

| カテゴリ | subagent_type | model | 役割 |
| -------- | ------------- | ----- | ---- |
| research | explorer | sonnet | コードベース・spec 横断調査 |
| research | reference-researcher | sonnet | 外部仕様・依存候補クレートの調査 |
| implement | io-builder | sonnet | io crate（I/O 共有層・フラッシュバリア・FS 正規化） |
| implement | runtime-builder | sonnet | core・supervisor crate（分離・cgroups・seccomp/Landlock・監視プロセス） |
| implement | oci-cri-builder | sonnet | oci・cri crate・plugin-cri（イメージ・ライフサイクル・CRI） |
| implement | platform-builder | sonnet | macOS / Windows / microVM の platform・plugin crate |
| implement | gpu-builder | sonnet | gpu crate（CDI・`/dev/dxg`・Venus） |
| implement | net-builder | sonnet | net crate（netlink・nftables・bridge/veth/netns・DNS） |
| implement | plugin-builder | sonnet | plugin-api crate・plugin-mcp（境界機構・信頼性検証・MCP） |
| implement | cli-stack-builder | sonnet | cli・stack crate（統一 CLI・TOML / compose 変換） |
| implement | infra-builder | sonnet | workspace・3 OS CI・5 段階ゲート・deny・Makefile・Dockerfile・scripts・benches |
| testing | test-runner | sonnet | cargo test / clippy 実行と失敗解析（実機前提テストの区別を含む） |
| quality | reviewer | sonnet | 設計原則・AI 自己補修性・フルスクラッチ方針・規約準拠のレビュー |
| quality | security-auditor | sonnet | 分離・plugin 信頼境界・外部入力・unsafe/FFI・OWASP 監査 |
| quality | linter | haiku | rustfmt / clippy / cargo deny / lint-docs 等の機械的確認 |
| docs | docs-writer | haiku | README・CLAUDE.md・AGENTS.md・docs/design・.claude/ 更新 |

## Rules

| ファイル | 内容 |
| -------- | ---- |
| [delegation.md](.claude/rules/delegation.md) | 調査フェーズの委譲原則・パスベース切り替え |
| [delegation-impl.md](.claude/rules/delegation-impl.md) | 実装フェーズの委譲マッピング・標準フロー・着手条件（明示指示・人間担当タスク・root 権限） |
| [coding-rust.md](.claude/rules/coding-rust.md) | Rust 規約（crate / plugin 境界・型設計・外部入力・タイムアウト・unsafe/syscall・クロスプラットフォーム・テスト） |
| [security.md](.claude/rules/security.md) | 秘密情報・コンテナ分離・plugin 境界・OWASP Top 10 |
| [japanese-style.md](.claude/rules/japanese-style.md) | 日本語出力スタイル |
| [conventional-commits.md](.claude/rules/conventional-commits.md) | Conventional Commits 詳細規約（type/scope 一覧） |
| [code-comment-style.md](.claude/rules/code-comment-style.md) | コメント規約（役割・呼び出し文脈・契約・スタブの将来仕様） |
| [out-of-scope-tracking.md](.claude/rules/out-of-scope-tracking.md) | スコープ外事項の Issue 追跡フロー |
| [spec-reference.md](.claude/rules/spec-reference.md) | **リポ固有**: spec（SSOT）の参照・ID 併記・編集禁止 |
| [dependency-policy.md](.claude/rules/dependency-policy.md) | **リポ固有**: フルスクラッチ・禁止クレート・`=x.y.z` 固定・ユーザー承認制 |
| [licensing.md](.claude/rules/licensing.md) | **リポ固有**: 中核 Apache-2.0 単独・補助 crate の選択肢・コピーレフト禁止 |
| [ci.md](.claude/rules/ci.md) | **リポ固有**: ローカルゲート・5 段階 CI ゲート・3 OS CI・実機前提テストの扱い |

## Current Skills

`npx skills add`（Fandhe-AI/agent-cli-skills・Fandhe-AI/agent-reference-skills）で導入済み。ロックは `skills-lock.json`。

- **ワークフロー系**: create-commit / create-pr / create-issue / create-issue-tree / create-plan / implement-issue / implement-issue-tree / implement-review / implement-review-pr / update-issue-tree / update-docs / comment-code
- **メンテ系**: init-claude / update-claude / contribute-skill / setup-repo-guards
- **リファレンス系**: rust / github-docs / commitlint / lefthook / editorconfig / anthropic-claude-code / anthropic-claude-code-extend / anthropic-api-tools-mcp / nvidia-cuda / dgx-spark / proxmox-ve / windows-interop-modernize

## Conventions

- **ローカル検証**: `make fmt-check`・`make lint`・`make test`（まとめて `make ci`）を通してからコミットする（[ci](.claude/rules/ci.md)）。ビルド・テストは `docs/spec` 抜きで成立させる
- **日本語**: やりとり・報告・コミット説明文・コード内コメントは日本語（プログラム出力文字列は英語）
- **Conventional Commits**: `--no-verify` 禁止
- **セキュリティレビュー**: PR 作成前に OWASP Top 10＋コンテナ分離・plugin 信頼境界を確認
- **ユーザー承認フロー**: 実装の着手 / 依存の追加・更新 / `unsafe` の新規追加 / ライセンス判断 / root 権限コマンドの実行 / Issue 起票 / 既存ファイル上書き / implement-issue の実装開始（計画承認後）は必ずユーザー承認を経る
- **spec 参照**: `docs/spec` の内容を引用・要約する際は TASK-n・ビヘイビア ID（`<PREFIX>-<N>`）・MS-n を併記する。`docs/spec` は本リポから編集しない
- **implement-issue-tree**: `.claude/workflows/implement-issue-tree.js`（相対 symlink）を named workflow として利用できる

## hooks（settings.json）

- **SessionStart**: 日本語・委譲・Conventional Commits・`--no-verify` 禁止・spec 参照（ID 併記）・依存承認制とフルスクラッチ・実装着手条件・root 権限コマンドのリマインダーを表示
- **PostToolUse**（Edit|Write）: `*.rs` 編集後に rustfmt で自動整形。edition はルート `Cargo.toml` から取得し（未作成時は 2024）、jq / rustfmt 未導入時は何もしない。整形失敗で作業を止めない
