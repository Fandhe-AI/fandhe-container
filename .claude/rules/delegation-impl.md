# 委譲ルール（作成・編集フェーズ）

## 原則

コードの作成・編集は担当レイヤの builder Agent へ委譲し、main は計画・レビュー・統合に徹する。

## パスベース委譲マッピング（実装）

crate の短縮名は spec の仮称（`05-tasks.md` 冒頭）。TASK-1（REPAIR-1）で確定したら本表を実名へ更新する。

| 対象パス | 委譲先 Agent | model |
| -------- | ------------ | ----- |
| `crates/io/`（I/O 共有層・バッチ write-back・フラッシュバリア・FS 正規化） | io-builder | sonnet |
| `crates/core/`・`crates/supervisor/`（namespace・cgroups v2・seccomp/Landlock・rootless・監査ログ・監視プロセス） | runtime-builder | sonnet |
| `crates/oci/`・`crates/cri/`・`fandhe-container-plugin-cri`（イメージ・ライフサイクル・CRI） | oci-cri-builder | sonnet |
| `crates/platform-macos/`・`crates/platform-windows/`・`crates/microvm/`・`fandhe-container-plugin-macos` / `-windows` / `-microvm` | platform-builder | sonnet |
| `crates/gpu/`（CDI・`/dev/dxg`・Venus） | gpu-builder | sonnet |
| `crates/net/`（netlink・nftables・bridge/veth/netns・DNS） | net-builder | sonnet |
| `crates/plugin-api/`・`fandhe-container-plugin-mcp`（plugin 境界機構・MCP サーバー） | plugin-builder | sonnet |
| `crates/cli/`・`crates/stack/`（統一 CLI・TOML / compose 変換） | cli-stack-builder | sonnet |
| ルート `Cargo.toml`・`.github/workflows/`・`deny.toml`・`Makefile`・`lefthook.yml`・`Dockerfile`・`compose.yaml`・`scripts/`・`benches/` | infra-builder | sonnet |
| テスト実行・失敗解析（`make test` / `make lint`） | test-runner | sonnet |
| コードレビュー | reviewer | sonnet |
| セキュリティ監査 | security-auditor | sonnet |
| lint・整形の機械的確認 | linter | haiku |
| README・CLAUDE.md・`AGENTS.md`・`docs/design/`・`.claude/`（agents・rules・settings.json）更新 | docs-writer | haiku |

複数 crate に跨る変更は crate ごとに builder を分けて委譲する（独立していれば並列可）。
crate 境界・拡張点トレイト（PLUG-1）・I/O 契約（IO-1・IO-2）の設計変更は builder に任せず main（opus / fable）で設計してから委譲する。

## 実装フローの標準形

1. 計画（main。必要に応じて explorer で事前調査）
2. 実装（builder へ委譲）
3. 検証（test-runner → 失敗があれば builder へ差し戻し）
4. レビュー（reviewer / security-auditor。分離・特権・plugin 境界に触れる変更は security-auditor 必須）
5. コミット（create-commit スキル。Conventional Commits・`--no-verify` 禁止）

## 着手条件（本リポ固有）

- **実装の着手はユーザーの明示指示を経てから行う**（ロードマップ上の着手判定とは別に、個別の開始指示を待つ）
- spec のタスク定義で担当が「人間」「共同」のタスク（実機実測・環境調達・技術選定・ライセンス判断・段階判定等）には Agent から単独で着手しない。準備作業（計測スクリプト作成等）に留め、判断事項はユーザーへ報告する
- 依存（Cargo.toml の dependencies）の追加・更新は builder に委譲せず、必ずユーザー承認を経る（[dependency-policy](./dependency-policy.md)）
- root 権限・ホストのネットワーク / cgroup 設定を変更するコマンドは、ユーザーの明示指示なしに実行しない
- スコープ外の発見事項は放置せず [out-of-scope-tracking](./out-of-scope-tracking.md) に従い追跡する
