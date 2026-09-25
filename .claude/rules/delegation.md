# 委譲ルール（調査・設計フェーズ）

## 原則

main セッションはオーケストレーションに徹し、コンテキスト消費の大きい作業
（ファイルの大量読み込み・横断検索・外部仕様調査）は subagent へ委譲する。
main が直接ファイルを読むのは、委譲結果の確認や小さなピンポイント参照に限る。

## パスベース切り替え表（調査）

| 対象パス・内容 | 委譲先 Agent | model |
| -------------- | ------------ | ----- |
| `crates/` 配下のコード調査・構造把握・影響範囲 | explorer | sonnet |
| `docs/spec/`（private submodule）のタスク・ビヘイビア・PoC 成果物の参照 | explorer | sonnet |
| OCI / CRI・Linux カーネル API・Virtualization.framework・WSL2・KVM・CDI・MCP 等の外部仕様 | reference-researcher | sonnet |
| 依存候補クレートの調査（ライセンス・メンテ状況） | reference-researcher | sonnet |
| テスト失敗の解析 | test-runner | sonnet |
| lint・フォーマット状況の確認 | linter | haiku |

## model 配分

| 用途 | model |
| ---- | ----- |
| 複雑な横断判断・アーキテクチャ設計（crate 境界・core/plugin 境界・拡張点トレイト・I/O 契約） | opus または fable（fable は特に大規模設計・横断判断の最上位 tier） |
| 調査・生成・実装・レビュー | sonnet |
| 機械的集計・lint・ドキュメント更新 | haiku |

## 注意

- spec の内容を報告する際はビヘイビア ID・TASK-n を併記する（[spec-reference](./spec-reference.md)）
- `docs/spec` は環境によって未解決（private・要アクセス権）。未取得なら `git submodule update --init docs/spec` を案内し、推測で補わない
- 複数の独立した調査は 1 メッセージで並列に委譲する
