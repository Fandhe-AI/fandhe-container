# CI・ローカル検証規約（リポ固有。REPAIR 系ビヘイビア）

## ローカルゲート（コミット・PR 前）

```bash
make fmt-check   # cargo fmt --all --check
make lint        # cargo clippy --workspace --all-targets -- -D warnings
make test        # cargo test --workspace
make ci          # 上記 + lint-docs + deny を一括実行
```

- テストは変更のたびに全件実行し、失敗・警告を 1 件でも残したまま進めない（fail-closed）
- Cargo.toml・メンバー crate が未作成の間、cargo 系ターゲットは Makefile 側で skip される（HAS_CARGO / HAS_MEMBERS）

## CI の構成（REPAIR-7 の 5 段階ゲート）

1. ビルド（`cargo build`・型検査）
2. ユニット / 統合テスト
3. タイムアウト保護された結合試験（ACK 未送信等のハングを検出。REPAIR-5）
4. ベンチ回帰チェック（15% 超の悪化で fail。REPAIR-8）
5. セキュリティチェック（`cargo deny`・禁止 API / 禁止クレート検査。REPAIR-9・MVM-4）

現状の `.github/workflows/ci.yml` は lint-docs・1・2・5（rust-base-ci）相当・4（`bench-regression` ジョブ）を持ち、発火条件は `workflow_dispatch`・`pull_request`・`push`（main）で稼働している（TASK-86.1・TASK-86.3・REPAIR-7）。3 は該当タスク（#36）で追加する。

`bench-regression` ジョブは `make bench-check-selftest`（比較スクリプトの自己テスト）→ `make bench-check`（ベンチ実行・基準値比較）の順に実行する。現時点では `benches/benches/regression_placeholder.rs`（決定的な固定値の stub）と `benches/baseline.json`（`placeholder: true` の暫定値）で動作確認する段階にあり、実測を伴う本物のベンチ・基準値への置き換えはそれぞれ TASK-113・TASK-88 で行う。

## 3 OS CI（macOS・Windows・Linux 一級対応）

- 各 OS のネイティブランナーでビルド・テストする（クロスコンパイル前提にしない）
- matrix は ubuntu / macos / windows の 3 OS を必須とし、特定 OS のみの skip で CI を通さない
- OS 依存のファイルシステム挙動（パス・大文字小文字・ロック・改行）のテストは 3 OS すべてで実行する
- ベンチ回帰チェック（`bench-regression` ジョブ）は例外として ubuntu-latest 単独で実行する。ベンチの数値は OS 間の実行環境差で比較できず、3 OS matrix にしても意味のある回帰検出にならないため（本節の「3 OS 必須」はビルド・テストのゲートを対象とする規則であり、ベンチ回帰チェックはその対象外）

## 実機前提テスト

- root 権限・KVM・GPU・特定カーネル版数（Landlock ABI 等）・WSL2 を要するテストは、GitHub ホステッド runner で実行できないため既定のテスト集合から明示的に分離する（分離の仕組みは該当タスクで決め、`AGENTS.md` に実行コマンドと必要環境を記す）
- 分離したテストには理由（必要な権限・環境）とビヘイビア ID を記し、実機での実行結果を PR に記録する
- 既定のテスト集合で動くはずのテストを、CI 通過のために実機前提テストへ移さない
- 実機での実測・判定が「人間」担当のタスクは、Agent は計測スクリプトの準備までに留める

## ワークフロー変更時の注意

- GitHub Actions のサードパーティ action はコミット SHA で固定する（`Fandhe-AI/actions` のみ `@latest` を許可）
- `permissions` は最小権限で明示する
- secrets を `pull_request` イベントのログへ出力しない
- CI 設定の変更は infra-builder が担当し、reviewer / security-auditor のレビューを経る
