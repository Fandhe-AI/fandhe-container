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
  （`repair5_create_worst_case_fits_runtime_timeout`）。bundle の用意と core の create の残りのファイル I/O は次節で扱う

## `CreateContainer` の bundle の用意と core の create（#2821・CRI-2・REPAIR-5・ERR-1・OCI-1）

待ちが無制限になり得る箇所を列挙し、2 段で上限づける。

| 箇所 | 扱い |
| ---- | ---- |
| `BundleLock::acquire_resolved`（core） | 待たない（`try_lock`。取れなければ即 `FailedPrecondition`） |
| `StateStore::create` の `@lock`・監査記録 2 回・ログ回収・起動オプション文書の掃除 | 上の 42.9 秒の内訳に入っている |
| `load_config`・`/etc/passwd`・`/etc/group`・image config の読み取り | 大きさの上限で有界（config 4 MiB・1 MiB・65,536 行）。通常ファイル以外は開く前に拒否 |
| `write_new_file`（config.json・resolv.conf）・状態ストアの書き込みと fsync | 小さなファイル数個。デバイス停止以外は有限 |
| blob の sha256 検証（`VerifiedLayerBlob::open`） | 合計 16 GiB（`DEFAULT_MAX_IMAGE_BYTES`）・層は最大 128。**1 本ごとに期限を確かめる**（今回の変更） |
| レイヤー展開（`extract_image_layers_with_options`） | 100 万エントリ・8 GiB で有界。途中では打ち切れず、前後でだけ期限を確かめる |
| 失敗時の後始末 | 展開した量に比例（展開の上限で有界） |

- RPC 側: 応答は `PLUGIN_RUNTIME_TIMEOUT`（60.9 秒）で打ち切られ DEADLINE_EXCEEDED になる。worker は打ち切れないが、記録・件数枠・bundle は
  worker の終了まで保持され、期限超過の失敗は bundle を残さない（`InFlightGuard`）
- worker 側: 残存は `PLUGIN_ROOTFS_DEADLINE`（600 秒。plugin-cri が明示。値は既定のまま）+ 分割できない区間 1 つ分の超過 + core の create の
  42.9 秒。同時に残る worker は `MAX_CONTAINERS` の件数枠で有界。照合は `repair5_create_worker_residual_is_bounded`
- 上限づけない理由: 展開のエントリ単位の打ち切りは oci の公開 API の変更を要する。期限の数値の見直しはオーナー判断。どちらも大きさの上限で有限
- 範囲外: core の `create_with_image*`（CRI の経路では呼ばれない）・RPC 超過後の dispatch 前の打ち切り・デバイス停止による I/O の停止
- 残る制約: 展開中は打ち切れない（REPAIR-3）

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

## CLI の起動オプション I/O の枠待ち（#2834・CLI-1・REPAIR-5・ERR-2）

作業枠（上限 8）はプロセス共有のため、同一プロセスで `create` を並行して呼ぶと（libtest の並列試験など）起動オプション文書の
I/O が一時的に満杯になり、即時 `Busy` を「結果なし」として `TIMEOUT` に誤分類していた（`stop_control_channel` の間欠失敗の原因）。
CLI の `prepare_options_file`・`rollback_options`・`read_env_files` は `supervisor_log::run_bounded_waiting` を使い、枠の空きを
呼び出し側の期限の範囲で待つ（期限は延ばさない。待った時間は期限から引く）。待っても空かなければ job を実行せず
`RESOURCE_EXHAUSTED`、期限切れ・起動失敗・panic は従来どおり `TIMEOUT`。plugin-cri が使う `run_bounded_classified` の即時 `Busy` は変えない。

### 繰り返し実行の記録（#2890・CLI-1・REPAIR-12）

Issue #2868 の修正後の main（commit `4819cc9d`）で `stop_control_channel`（libtest ハーネスの 10 試験。プロセス内で並列）を
`make repeat-test PACKAGE=fandhe-container-cli TEST_BIN=stop_control_channel SUCCESS_LINE='test sec1_err2_stop_without_supervisor_is_unavailable_and_does_not_kill ... ok' COUNT=100`
で繰り返した（ローカル。`nproc`=10・カーネル 7.0.0-34-generic）。いずれかの試験が失敗すると終了コードが非 0 になり、回が失敗として数えられる。

| 条件 | 回数 | passed | failed |
| ---- | ---- | ------ | ------ |
| A1: 既定の並列度（10 スレッド）・追加負荷なし（100 回 × 3 バッチ） | 300 | 300 | 0 |
| A2: `RUST_TEST_THREADS=32`・`yes` を 10 本走らせた CPU 負荷（100 回 × 3 バッチ） | 300 | 300 | 0 |

- 報告元の `sec1_err2_stop_without_supervisor_is_unavailable_and_does_not_kill`・`sup9_sup3_stop_in_backoff_cancels_pending_restart` は、
  #2868 の後の 600 回で一度も失敗しなかった。報告元 PR（#2861・#2864）は #2868 のマージ前のブランチで、#2868 が直した枠満杯の誤分類で説明できる。したがって製品・試験コードは変えていない
- 計測の注意: 最初に成功行を `sup9_sup3_stop_in_backoff_cancels_pending_restart ... ok` にした試行は 300 回中 1 回が `missing-success-line` と数えられた。
  出力は 10 試験とも ok・終了コード 0 で、並列試験の supervisor の JSON ログがその `... ok` の行の途中へ割り込み、行全体の完全一致に外れただけだった（試験の失敗ではない）。
  supervisor を起動しない `sec1_err2_...` の行へ変えると割り込まない。libtest の並列出力を行照合する場合は、標準出力に何も書かない試験の行を選ぶ
- 範囲外: `run_bounded` の他の呼び出し元の即時 `Busy` は #2894、`binary_entry.rs` の間欠失敗は #2766 で追跡する

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
