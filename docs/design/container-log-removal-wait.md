# コンテナログ削除の閉鎖待ちと失敗の内訳（SUP-7・CRI-2・REPAIR-4・REPAIR-5）

plugin-cri の `RemoveContainer`（`CoreLifecycleRuntime::delete`）は、core の delete が成功した後にコンテナログ
（`<root>/@container-logs/<id>.log*`・ロック）を消す（#2593）。本書は、その残りだった 2 件（#2634。TASK-164 追補・TASK-114 追補）の判断記録である。

## 背景（窓の発生箇所）

- `SupervisedLifecycle::stop` は状態ストアが `Stopped` になった時点で返る
- supervisor は `Stopped` を記録した後に、seccomp hub の `finish`・ログ hub の drain（それぞれ `terminate` で上限づけ。既定
  `StartTimeouts::DEFAULT_TERMINATE` = 5 秒）を行い、最後にプロセスが終わって sink のロック `<id>.log.lock`（flock）が解放される
- つまり「Stopped が記録された」と「ロックが解放された」の間に最悪で約 10 秒の窓がある。この間のログ削除は
  `FailedPrecondition` になり、ログとロックファイルが残る（delete 自体は `Ok`）
- `stop` の直後に force なしで delete したときも同じ窓がある。対策は force に限らず delete のログ削除全体に入れた

## 方式の比較と決定

| 方式 | 採否 | 理由 |
| ---- | ---- | ---- |
| A: sink の閉鎖を期限つきで待ってから消す | 採用 | 新しい永続状態を作らない（CORE-1 の常駐デーモン無しと整合）。試験が決定的に書ける |
| B: 後で再試行（plugin 内の遅延スレッド） | 不採用 | スレッド数の上限管理と plugin 再起動時の取りこぼしが増える |
| C: 次の操作で回収 | 不採用 | 回収の起点と、同じ ID の再作成との排他の設計が新たに要る |

## 実装

- `fandhe_container_supervisor::logs::remove_container_logs_guarded_bounded_waiting`: 1 回の試行（既存の
  `remove_container_logs_guarded_bounded`）を `FailedPrecondition` のあいだ 50ms 間隔（`CONTAINER_LOG_LOCK_POLL`）で
  `CONTAINER_LOG_LOCK_WAIT`（10 秒）まで繰り返す
  - 試し直すのは `FailedPrecondition` だけ。`Timeout`・`InvalidArgument`・`Internal` は即座に返す（fail-closed）
  - `guard` は試行ごとにロック保持中に評価され、`false`（同じ ID が再作成済み）なら 0 件で成功し試し直さない
  - 待ちは呼び出し元スレッドの sleep で、作業スレッドの同時実行枠（`MAX_INFLIGHT_LOG_REMOVALS` = 8。supervisor ログの削除と共有）は
    試行の間しか占めない
- `CoreLifecycleRuntime::with_container_log_lock_wait`: 試験用に待ちを短くできる（上限は `CONTAINER_LOG_LOCK_WAIT` に切り詰める）

## 期限と予算（REPAIR-5）

- ログ削除全体の最悪は「待ち 10 秒 + 最後の試行 5 秒」= 15 秒
- force delete の最悪: stop 17 秒（`2 × (KillTimeout::DEFAULT 5 秒 + 1 秒) + STOP_KILL_WAIT 5 秒`）+ supervisor ログ 5 秒 +
  コンテナログ 15 秒 = 37 秒で、`PLUGIN_RUNTIME_TIMEOUT`（60.9 秒）に収まる。不等式は結合試験
  `repair5_force_delete_worst_case_fits_runtime_timeout` で機械照合する

## 観測（REPAIR-4）

失敗時は従来の `container_log_remove`（成否）に加えて、コード別の操作名にも Failure を 1 件計上する。語彙は固定の 5 種:
`container_log_remove.failed_precondition`・`.timeout`・`.invalid_argument`・`.internal`・`.other`。記録器の名前の種類の上限
（`MAX_TRACKED_OPS`）を食い潰さないよう、語彙を絞り、失敗が起きたときにだけ作る。出力は定期の `op_stats` に載る。

## 残る制約・対象外

- terminate は最大 600 秒まで設定できる。既定を超えて窓が 10 秒を超えたときは待ち切れず、`FailedPrecondition` として計上してログを残す
  （1 ID あたり世代数 × 上限に収まる）。後から回収する経路は作らない
- CLI の `delete` にも `stop` 直後に同じ窓がある。新しい関数へ差し替えるかは別 issue の候補（CLI-1・SUP-7）
- `DeleteResponse` に後始末の結果を載せることは #2633（PR #2685）の担当
