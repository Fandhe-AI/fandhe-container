# ベンチ基準値の校正記録

`benches/baseline.json`（ベンチ回帰チェックの基準値）を実測で確定するための校正記録の枠と、試行ログを残す。

- 対象ビヘイビア: REPAIR-8（主要ベンチが直近基準値より 15% 超悪化したら CI を fail させる。基準値は各ベンチ対象の初回実装完了時に実測して確定する）
- 関連タスク: TASK-88（#227）・TASK-88.1（#228。生成パイプライン `scripts/bench/generate_baseline.sh`・`make bench-baseline`）・TASK-88.2（#229。本記録）・TASK-88.h1（#230。基準値の妥当性判断。人間担当）
- 対象マイルストーン: MS-2 Phase 3
- ステータス: **実測は未実施**。`benches/baseline.json` は `placeholder: true` の暫定値のまま（実装済みを装わない。REPAIR-3）

## 校正対象の metric

| metric | 向き | 単位 | 状態 |
| ---- | ---- | ---- | ---- |
| 小ファイル多数ワークロードの files/s | `higher_is_better` | 未確定（ベンチ実装時に `benches/metrics.json` で確定） | 対応するベンチが未実装 |
| コンテナ起動レイテンシ p95 | `lower_is_better` | 未確定（同上） | 対応するベンチが未実装。計測には TASK-29（create/start）の完了も必要 |
| plugin 境界 代表操作 A の inproc / framed / Δp50（`plugin_boundary_op_a_{inproc,framed,delta}_p50`） | `lower_is_better`（ns） | 未確定（実測は未実施） | TASK-113.1・113.3 で実装済み。metrics.json・`BENCH_NAMES` に登録済み。baseline 未登録 |
| plugin 境界 代表操作 B の inproc / framed / Δp50（`plugin_boundary_list_images_{inproc,framed,delta}_p50`） | `lower_is_better`（ns） | 未確定（実測は未実施） | TASK-113.2・113.3 で実装済み。登録状況は上と同じ |

## 校正記録（試行ログ）

実測日時は UTC・ISO 8601。実行環境は OS 種別・アーキテクチャ・CPU コア数程度に一般化し、ホスト名・IP・ユーザー名・アカウント識別子は書かない。

| 試行日時（UTC） | 実行環境 | 対象ベンチ | 結果 | 備考 |
| ---- | ---- | ---- | ---- | ---- |
| 2026-09-30 | Linux x86_64（ローカル開発機。ドライランのみ） | `regression_placeholder` のみ | 実測不可。files/s・起動 p95 のベンチが存在しない | `make bench-baseline` を一時パス出力で実行し exit 0 で生成できることのみ確認（パイプライン疎通）。生成物は破棄し、`benches/baseline.json` は変更していない |

## 実測の前提条件

1. files/s ベンチと起動 p95 ベンチが `benches/benches/` に実装され、Makefile の `BENCH_NAMES` と `benches/metrics.json` に登録されている
2. 起動 p95 は TASK-29（コンテナ create/start）が完了している
3. 計測環境の扱いが TASK-88.h1 で決まっている（下記）

現状は `BENCH_NAMES := regression_placeholder plugin_boundary plugin_boundary_list_images`・metric は placeholder 2 件と plugin 境界 6 件（TASK-113.3 で登録）。`make bench-check` の対象は placeholder のみで、baseline 再生成時は `bench-check` の対象ベンチも同じ集合に揃えること（baseline と results の集合不一致は比較スクリプトが exit 2 にする）。metric だけを先に追加すると `generate_baseline.sh` は `results are missing metrics` で exit 2 になる（fail-closed。設計どおり）。

## 再実行手順

```bash
# ドライラン（一時パスへ出力。コミット対象の baseline.json を上書きしない）
make bench-baseline BENCH_BASELINE_OUT=<一時ファイルの絶対パス> BENCH_ENVIRONMENT="<一般化した環境説明>"

# 本番生成（前提条件充足後）。生成後に往復検証と比較を確認する
make bench-baseline BENCH_ENVIRONMENT="<一般化した環境説明>"
make bench-check
```

placeholder ベンチの結果を `benches/baseline.json` へ書き出さない。値が偽物のまま `generated_at`・`environment` が付き、校正済みに見えてしまうため。校正記録なしに baseline を書き換える差分は回帰検出の後退として扱う（`AGENTS.md`「ベンチ回帰」）。

## TASK-88.h1（人間担当）への判断事項

- 計測環境: `bench-regression` は ubuntu-latest 単独で実行される。ローカル実機の値を基準にすると CI 上の比較が意味を持たない。CI runner 上で採るか、環境差の扱いを決める
- 試行回数と集計: 単発か複数回の中央値か（生成器は 1 ベンチにつき results 1 ファイル）
- 起動 p95 の計測権限: namespace 操作に root / rootless のどちらを使うか。実機前提テストとして分離するか（`.claude/rules/ci.md`）
- 15% 閾値と、placeholder 段階をいつ終了するか

## 既知の欠落（要ユーザー確認）

files/s ベンチと起動 p95 ベンチを実装するタスクが見当たらない。TASK-88.1（#228）は実ベンチの実装を TASK-113 へ送ったが、TASK-113（#269）は plugin 制御面往復レイテンシのベンチで、2 metric を扱わない。spec 側のタスク定義の補完が必要な可能性がある（spec は本リポから編集しない）。

## 関連

- `scripts/bench/generate_baseline.sh`・`scripts/check-bench-regression.sh`
- `AGENTS.md`「タイムアウト保護された結合試験・ベンチ回帰」節
