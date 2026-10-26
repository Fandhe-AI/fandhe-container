# コンテナログ削除の閉鎖待ちと失敗の内訳（SUP-7・CRI-2・REPAIR-4・REPAIR-5）

plugin-cri の `RemoveContainer`（`CoreLifecycleRuntime::delete`）は、core の delete が成功した後にコンテナログ
（`<root>/@container-logs/<id>.log*`・ロック）を消す（#2593）。本書は、その残りだった 2 件（#2634。TASK-164 追補・TASK-114 追補）と、ID を使い回さない場合の回収・create 前の回収の配線（#2760）の判断記録である。

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
| C: 次の操作で回収 | 限定して採用（#2698・#2760） | 起点は「同じ ID の `create`（CLI と plugin-cri の `CreateContainer`）、core を呼ぶ前」。排他は既存の guard（ロック保持中に状態の不在を確認）で足りる |
| D: plugin-cri の起動時に 1 回、`@container-logs` を走査して回収 | 採用（#2760） | CRI は ID を使い回さず C が効かないため。常駐スレッドを増やさず、delete の予算も変えない。方式は下の「ID を使い回さない場合の残りの回収」 |
| E: delete のたびに走査 | 不採用 | delete の予算（force delete の最悪 47 秒）にディレクトリ走査が乗り、`PLUGIN_RUNTIME_TIMEOUT` の再設計が要る |

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
- force delete の最悪（plugin-cri）: stop 17 秒（`2 × (KillTimeout::DEFAULT 5 秒 + 1 秒) + STOP_KILL_WAIT 5 秒`）+ supervisor ログ 5 秒 +
  コンテナログ 15 秒 + 起動オプション文書の掃除 10 秒（#2760）= 47 秒で、`PLUGIN_RUNTIME_TIMEOUT`（60.9 秒）に収まる。不等式は結合試験
  `repair5_force_delete_worst_case_fits_runtime_timeout` で機械照合する
- `CreateContainer` の最悪（plugin-cri。#2760）: ログ回収 5 秒 + 起動オプション文書の掃除 10 秒 + 状態ロック `STATE_LOCK_TIMEOUT` 5 秒 +
  create の監査記録 2 回（`2 × RECORD_WAIT_LIMIT` 11.45 秒 = 22.9 秒）= 42.9 秒で、同じく 60.9 秒に収まる
  （`repair5_create_worst_case_fits_runtime_timeout`）。bundle の用意（`BundleProvider::prepare`）と core の create のファイル I/O 自体の上限は
  従来どおりこの内訳の外にある（既存の残余。今回は直さない）

## 待ち切れなかったことの区別（#2760）

delete のログ削除の待ち（`CONTAINER_LOG_LOCK_WAIT` = 10 秒）を超えて sink が開いていた場合、次の 2 案のうち **(b) を採用**した。

- (a) 記録された terminate に合わせて待ちを伸ばす: 不採用。本番の supervisor は常に `StartTimeouts::default()`（terminate 5 秒）で動き、
  terminate を指定する経路も、状態記録に残す欄も無い（読むべき「記録された terminate」が存在しない）。待ちを 600 秒まで伸ばすと
  force delete の最悪値の不等式も成り立たない
- (b) 待ち切れなかったことを構造化した警告で区別する: 採用。`remove_container_logs_guarded_bounded_waiting` が
  `FailedPrecondition` を返すのは `lock_wait` を使い切ったときだけ（途中の `FailedPrecondition` は試し直す）なので、この意味は一意に決まる。
  足りないのは明示だけだった。警告行に閉じた語彙の `"reason":"sink_open_after_wait"` を足す（`FailedPrecondition` のときだけ。他のコードには付けず、
  既存の行と互換）。対象は plugin-cri の `container_delete_cleanup`（`target: container_log`）と CLI の stderr 警告。語彙は
  `fandhe_container_supervisor::logs::REASON_SINK_OPEN_AFTER_WAIT` に 1 つだけ置いて共有する。記録器の操作名
  `container_log_remove.failed_precondition` を「待ち切れなかった」と定義し直した（語彙は増やさない。`MAX_TRACKED_OPS` を守る）
- 残余: terminate を設定できるようにする将来の変更では、設定値を状態記録へ残し、この待ちを見直す（REPAIR-3）

## ID を使い回さない場合の残りの回収（#2760）

CRI は ID を使い回さないため、delete の待ちを超えて残ったログは「同じ ID の create」では回収されない。plugin-cri の起動時に 1 回だけ
`@container-logs` を走査して回収する（`fandhe_container_supervisor::logs::sweep_stale_container_logs`。plugin-cri の `serve` が
`open_audit_relay`〔単一スレッド前提〕の後、サーブの開始を待たせない `spawn_blocking` で呼ぶ）。

1. ディレクトリを `check_dir`（祖先 symlink・他者書き込み可を拒否）の後に列挙する。上限はエントリ 2^20 件・ID 4096 件・全体 30 秒
2. 名前から stem を取り出す（`<stem>.log`・`<stem>.log.lock`・`<stem>.log.<数字>`）。stem を ID に戻す（`encode_file_stem` の逆変換）。
   戻した ID を符号化し直して元の stem と一致すること、`ContainerId` として妥当なことを必ず照合する。照合に失敗した名前
   （大文字入り、不正な `_` の並び、非 UTF-8 等）は **帰属を確定できないので消さない**（`skipped_undecodable`）
3. 各 ID について既存の `remove_container_logs_guarded_bounded` を待たずに 1 回だけ呼ぶ（1 回の期限は 5 秒）。削除そのもの（ロック・名前空間の検査・
   symlink を辿らない unlink）は既存の経路に任せ、走査側は自前でパスを組んで消さない
   - ロックが取れない（生きている sink）→ 見送る（`skipped_live`）
   - guard は状態ストアが `NotFound` のときだけ真。記録がある ID（読み取りに失敗した場合を含む）は消さない（`skipped_present`）。guard はロック保持中に評価される
4. 結果は構造化ログ 1 行（`event: container_log_sweep`。件数だけで、パス・ID は含めない）と、消せた ID ごとの op `container_log_reclaim` の Success で観測する

範囲外（残余。REPAIR-3）: plugin-cri が動いている間に発生した残りは次の起動まで残る。CLI の `--root` が plugin-cri と異なる状態ルートは走査しない。

## 観測（REPAIR-4）

失敗時は従来の `container_log_remove`（成否）に加えて、コード別の操作名にも Failure を 1 件計上する。語彙は固定の 5 種:
`container_log_remove.failed_precondition`・`.timeout`・`.invalid_argument`・`.internal`・`.other`。記録器の名前の種類の上限
（`MAX_TRACKED_OPS`）を食い潰さないよう、語彙を絞り、失敗が起きたときにだけ作る。出力は定期の `op_stats` に載る。

## 残る制約・対象外

- terminate は最大 600 秒まで設定できる。既定を超えて窓が 10 秒を超えたときは待ち切れず、`FailedPrecondition`（`reason: sink_open_after_wait`）として計上してログを残す
  （1 ID あたり世代数 × 上限に収まる）。残りは CLI の同じ ID の `create`、plugin-cri の `CreateContainer`（同じ ID）、plugin-cri の次の起動時の走査で回収される
- CLI の `delete` も同じ待ち（`remove_container_logs_guarded_bounded_waiting`）を使い、結果を `DeleteResponse` の
  `supervisor_log` / `container_log` に載せる（#2698）。CLI の後始末の最悪は supervisor ログ 5 秒 + 待ち 10 秒 + 最後の試行 5 秒 = 20 秒
  （`repair5_cli_delete_cleanup_budget_fits_20s`）
- 同じ ID の `create` 前の回収（#2698・#2760）: core を呼ぶ前に、待たずに 1 回だけ（上限 5 秒）消す。本体は
  `fandhe_container_supervisor::logs::reclaim_stale_container_logs` で、CLI（`reclaim_stale_container_log`）と plugin-cri
  （`CoreLifecycleRuntime::reclaim_before_create`）が共有する。古い supervisor が生きていれば何も消さず、状態がある ID は guard で消さない。
  best effort で create の成否は変えない（ただし回収が期限切れ `Timeout` のときは、作業スレッドを残したまま監査記録の fork〔単一スレッド前提。SEC-4〕へ進まないよう core を呼ばず `TIMEOUT` で create を失敗させる。CRI 層は `state` が `NotFound` であることを確かめて資源を解放する）。観測は op 名 `container_log_reclaim`（消した Success・エラーの Failure）
- 上記で回収できない残り（生きている sink が続く・状態がある ID・帰属できない名前）は手動で消す（`docs/setup/container-log-recovery.md`）
