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
- force delete の後始末の最悪（plugin-cri）: ログ 2 件 20 秒（共有の待ち 10 秒 + supervisor ログの最後の試行 5 秒 + コンテナログの最後の試行 5 秒。#2964）
  に加えて起動オプション文書の掃除 10 秒（#2760）で 30 秒。stop 17 秒（`2 × (KillTimeout::DEFAULT 5 秒 + 1 秒) + STOP_KILL_WAIT 5 秒`）と足すと 47 秒で、
  `PLUGIN_FORCE_DELETE_DEADLINE` と一致する。core の delete と bundle の解放を含めた全体は「`RemoveContainer` の全体の上限と kubelet の期限」節
  （#3027）。不等式は結合試験 `repair5_force_delete_worst_case_fits_runtime_timeout` で機械照合する
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
| レイヤー展開（`extract_image_layers_bounded`） | 100 万エントリ・8 GiB で有界。**エントリ単位で期限と取り消しを確かめる**（#2899）。分割できないのは 1 エントリの書き込みと tar 終端後の読み捨て |
| 失敗時の後始末 | 展開した量に比例（展開の上限で有界） |

- RPC 側: 応答は `PLUGIN_RUNTIME_TIMEOUT`（60.9 秒）で打ち切られ DEADLINE_EXCEEDED になる。worker は打ち切れないが、記録・件数枠・bundle は
  worker の終了まで保持され、期限超過の失敗は bundle を残さない（`InFlightGuard`）
- worker 側: 残存は `PLUGIN_ROOTFS_DEADLINE`（600 秒。plugin-cri が明示。値は既定のまま）+ 分割できない区間 1 つ分の超過 + core の create の
  42.9 秒。同時に残る worker は `MAX_CONTAINERS` の件数枠で有界。照合は `repair5_create_worker_residual_is_bounded`
- 期限の数値の見直しはオーナー判断（値は変えない）
- 範囲外: core の `create_with_image*`（CRI の経路では呼ばれない）・デバイス停止による I/O の停止
  （`PullImage` の展開への期限の配線は次の小節。#2967）
- 残る制約: 1 エントリの本体の書き込み（最大 `max_total_bytes`）・blob 1 本の sha256 検証・失敗時の削除は途中で止められない（REPAIR-3）

### RPC の期限切れの後の worker（#2899・CRI-2・REPAIR-5・REPAIR-3）

- 打ち切り: `CreateContainer` の RPC 側は `AbandonOnDrop` を持ち、期限切れ（`Timeout`）と future の破棄（kubelet の取り消し・grpc-timeout）の
  どちらでも、worker との共有の決着（`SetUpSettlement`）を「手放し」へ進めて取り消しの旗を立てる（atomic の store だけ。RPC スレッドで外部処理をしない）
- worker の確認点: bundle 用意の前（手放し済みなら `prepare` もしない）→ 展開のエントリごと（旗で `Timeout`、rootfs は消す）→ **dispatch の直前**
  （`settle_by_worker` の compare_exchange。負けたら `outcome_unknown` は偽のまま `release` と記録の除去）。dispatch の可否は 1 回の
  compare_exchange で決まるため、呼び出し側と worker が同時に「確定」することはない
- dispatch 後は打ち切らない: core の create は外部プロセス（supervisor）とファイル I/O を伴い、途中で止める口が無く、止めても実行層に資源が
  残りうる。この区間は既存の `outcome_unknown`・`confirm_removed` で扱う。最悪は core の create 42.9 秒 + 失敗時の削除確認 60.9 秒（103.8 秒）で、
  `PLUGIN_ROOTFS_DEADLINE` に収まる（`repair5_create_worker_residual_is_bounded`）
- 取り消し後の worker の残存: 次の確認点までの分割できない区間（blob 1 本の検証・1 エントリの書き込み）+ 展開物の削除。いずれも大きさの上限で有界
- 残余（REPAIR-3）: 手放した worker が止まるまで記録・名前キーは残るため、kubelet が即座に再試行すると名前の衝突になりうる。
  `PLUGIN_ROOTFS_DEADLINE` の 600 秒は、取り消しが届かない場合の上限として残る
- 照合: `repair5_extract_*`（oci の単体）・`repair5_cancel_during_extraction_*`（cri の rootfs）・`repair5_create_timeout_during_prepare_*`・
  `repair5_create_future_drop_during_prepare_*`（cri の worker）・`err3_bundle_prepare_timeout_maps_to_deadline_exceeded_and_releases`（prepare の Timeout → DEADLINE_EXCEEDED → `release`）

### `PullImage` の展開の期限と取り消し（#2967・CRI-3・OCI-1・REPAIR-5・REPAIR-3）

- 経路: `CriImageService::pull` → `spawn_blocking` → `OciImagePuller::pull_inner` → `stage_and_unpack`（blob ごと）→ `ensure_rootfs`
  （公開済みの命中、または層ごとの `VerifiedLayerBlob` の検証、または `extract_image_layers_bounded`。`verify_only` を含む）→
  `write_unpack_record` / `rename` → publish の直前の確認 → `PullSession::publish`
- 期限は共有する: pull の開始から `pull_deadline`（本番 540 秒）の絶対時刻を 1 つだけ求め、展開の `ExtractBudget` へそのまま渡す。
  不採用の案は「展開に別の予算を持たせる」で、pull 全体が 540 秒を超えうるため、plugin-cri の `PLUGIN_REQUEST_TIMEOUT`（600 秒）との不等式
  （`repair5_pull_deadline_fits_inside_request_timeout`）が崩れる。`CreateContainer` 側の `PLUGIN_ROOTFS_DEADLINE` は別 RPC の予算で関係しない
- 確認点（取り消しの旗 → 期限の順。どちらも `Timeout` = gRPC `DEADLINE_EXCEEDED`）: pull の先頭（取り消し済みなら通信しない）→ 認証の後 →
  manifest の後 → blob ごとの前 → 再認証ループの試行ごと → 最後の blob の後 → 層ごとの検証の前 → 展開のエントリごと → 展開の後 →
  publish の直前（最後の打ち切り点）。publish が確定した後は取り消されていても成功を返す（OCI-7）
- 打ち切り時: `unpack/` は `remove_extracted_tree`、ステージングは `PullSession::abort` が消し、在庫・タグ・リースは残らない
- RPC 側: `PullImage` は `CancelOnDrop` を持ち、future の破棄（kubelet の取り消し・`PLUGIN_REQUEST_TIMEOUT`）で取り消しの旗を立てる
  （atomic の store だけ。worker の完了後は disarm）。worker は次の確認点で止まり、`PullSlot` も早く戻る
- 取り消しの口: `ImagePuller::pull_cancellable`（既定は旗を無視して `pull`。`PullRequest` は変えない）
- 分割できない区間: blob 1 本の取得（`blob_request_timeout` で有界）・blob 1 本の sha256 検証・1 エントリの書き込み・失敗時の削除。
  worker の最悪の残存は `pull_deadline` + 分割できない区間 1 つ分
- 残余（REPAIR-3）: 取り消しが `publish` と handler の `upsert` の間に届くと、永続在庫には登録されるが `CriImageService` のメモリのストアは
  更新されない（従来の gRPC タイムアウトにもある窓で、再試行がキャッシュ命中で揃える）。oci の `fetch_blob` の通信を途中で取り消す口は無い。
  期限の数値（540 秒・1 時間）の見直しはオーナー判断
- 照合: `cri3_repair5_pull_cancel_during_extraction_*`・`cri3_repair5_pull_cancel_during_fetch_*`・`cri3_repair5_pull_cancelled_before_start_*`・
  `cri3_repair5_extraction_shares_the_pull_deadline`・`cri3_repair5_dropped_pull_rpc_cancels_worker_and_releases_slot`

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
- 計測の注意: 最初に成功行を `sup9_sup3_stop_in_backoff_cancels_pending_restart ... ok` にした試行は 300 回中 1 回が `missing-success-line` と数えられた（#2962 以降は `LIBTEST_NAME` で回せば libtest の `--logfile` で判定するため割り込まれず、「標準出力に何も書かない試験の行を選ぶ」回避は不要になった。以下は当時の記録）。
  出力は 10 試験とも ok・終了コード 0 で、並列試験の supervisor の JSON ログがその `... ok` の行の途中へ割り込み、行全体の完全一致に外れただけだった（試験の失敗ではない）。
  supervisor を起動しない `sec1_err2_...` の行へ変えると割り込まない。libtest の並列出力を行照合する場合は、標準出力に何も書かない試験の行を選ぶ
- 範囲外: `run_bounded` の他の呼び出し元の即時 `Busy` は #2894、`binary_entry.rs` の間欠失敗は #2766 で追跡する

## `run_bounded` 系の枠の満杯の分類（#2894・CLI-1・SUP-7・REPAIR-4・REPAIR-5・ERR-1）

`run_bounded`（`Option`）と `run_log_removal_bounded` は、枠の満杯（何も実行していない）を期限切れと同じ値（`None`・`LogRemoval::TimedOut`）に潰していた。
判定基準は「何も実行せず即時に失敗したのか、期限まで待った結果なのか」。枠の満杯は `RESOURCE_EXHAUSTED`（または `LogRemoval::Busy`・`workers_busy`）、期限切れは従来どおり `TIMEOUT` にする。
`run_bounded`（`Option`）は製品の呼び出し元が無くなったため削除した（#2965・REPAIR-1）。結果を持ち帰る期限つき実行は `run_bounded_classified`（即時 `Busy`）か `run_bounded_waiting`（枠を待つ）を使う。

| 箇所 | 方針 | 新しい分類 |
| ---- | ---- | ---------- |
| `container_options::store::remove_stale_bounded`（CLI の delete 後の掃除、plugin-cri の create 前・delete 後の掃除） | `run_bounded_classified` へ替える（待たない） | 枠の満杯 `RESOURCE_EXHAUSTED`（`container options file removal workers are busy`）／期限切れ `TIMEOUT` |
| `logs::sweep_stale_container_logs`（plugin-cri の起動時の走査）の初期走査とループ | `run_bounded_classified` へ替える（待たない） | `SweepReport::workers_busy`（枠の満杯）／`timed_out`（期限切れ）に分ける |
| `supervisor_log::run_log_removal_bounded`（旧 plugin-cri の `remove_supervisor_log`。#2964 で `remove_guarded_bounded_waiting` に置換） | `LogRemoval::Busy` を追加 | 現在は `remove_guarded_bounded_waiting` の `Err(ResourceExhausted)` を `Kept { ResourceExhausted }`（記録器は Failure）に写す |
| `logs::remove_container_logs_guarded_bounded` ほか `run_bounded_classified` の呼び出し元 | 変更なし（#2760 で区別済み） | `ResourceExhausted` |
| CLI の `create` の起動オプション I/O（`run_bounded_waiting`） | 変更なし（#2834） | `RESOURCE_EXHAUSTED`／`TIMEOUT` |
| CLI の `stop_delete.rs` `remove_supervisor_log`（`run_bounded` の `Option`） | #2920 で `run_bounded_classified` 系（`remove_guarded_bounded_waiting`）へ移行済み。`Option` 版の `run_bounded` は #2965 で削除 | 枠の満杯 `RESOURCE_EXHAUSTED`／期限切れ `TIMEOUT` |
| CLI の `emit_warning_bounded` | 変更なし（結果を捨てるため、分類は外へ出ない） | — |

待たない理由: plugin-cri の即時 `Busy` は #2760 の判断（常駐プロセスで止まった作業が枠を埋めたとき、さらに待ちを重ねない）で、CLI の delete と起動時の走査は
失敗しても成否が変わらない best effort の後始末で、枠が埋まるのは止まった作業が残るときだけのため待っても空く見込みが低い。create の枠待ち（#2834）は
並列実行で一時的に満杯になることが原因だったので事情が異なる。

変更しない箇所（理由つき）:

- 枠を持たない同名の関数: `start_entry.rs` の `run_bounded`（呼ぶたびに spawn して bool を返す）、`cri/runtime_service.rs` の `run_bounded`（spawn の失敗は `Unavailable`、期限は `timeout` で区別済み）
- ロック待ち: core の `state_store.rs` と oci の `image_management/store.rs` の `lock_file_until`・`lock_table_until` は、`WouldBlock` の間は期限まで再試行し、`Timeout` を返すのは実際に期限まで待ったときだけ。即時の失敗を期限切れとして返す形ではない
- 記録器の操作名の語彙（`container_log_remove.*` の 5 種）は増やさない

ワイヤー・観測の変化: code 名（`RESOURCE_EXHAUSTED`・`TIMEOUT`）は既存で、新しい名前は無い。枠の満杯のときの code が `TIMEOUT` から `RESOURCE_EXHAUSTED` に変わる行は、
CLI の delete の起動オプション文書の警告、plugin-cri の `container_delete_cleanup`（`target: supervisor_log`・`container_options`）。
`container_log_sweep` の行にキー `workers_busy`（bool）が加わり、枠の満杯で打ち切ったときは `timed_out: false`・`workers_busy: true` になる。
試験: `crates/supervisor/tests/bounded_slot_busy.rs`（3 関数の満杯と期限切れの具体値）。

## 観測（REPAIR-4）

失敗時は従来の `container_log_remove`（成否）に加えて、コード別の操作名にも Failure を 1 件計上する。語彙は固定の 5 種:
`container_log_remove.failed_precondition`・`.timeout`・`.invalid_argument`・`.internal`・`.other`。記録器の名前の種類の上限
（`MAX_TRACKED_OPS`）を食い潰さないよう、語彙を絞り、失敗が起きたときにだけ作る。出力は定期の `op_stats` に載る。

## 残る制約・対象外

- terminate は最大 600 秒まで設定できる。既定を超えて窓が 10 秒を超えたときは待ち切れず、`FailedPrecondition`（`reason: sink_open_after_wait`）として計上してログを残す
  （1 ID あたり世代数 × 上限に収まる）。残りは CLI の同じ ID の `create`、plugin-cri の `CreateContainer`（同じ ID）、plugin-cri の次の起動時の走査で回収される
- CLI の `delete` も同じ待ち（`remove_container_logs_guarded_bounded_waiting`）を使い、結果を `DeleteResponse` の
  `supervisor_log` / `container_log` に載せる（#2698）。CLI の後始末の最悪は、待ち 10 秒（2 つのログで共有。下記）+ supervisor ログの最後の試行 5 秒 +
  コンテナログの最後の試行 5 秒 = 20 秒（`repair5_cli_delete_cleanup_budget_fits_20s`）
- 同じ ID の `create` 前の回収（#2698・#2760）: core を呼ぶ前に、待たずに 1 回だけ（上限 5 秒）消す。本体は
  `fandhe_container_supervisor::logs::reclaim_stale_container_logs` で、CLI（`reclaim_stale_container_log`）と plugin-cri
  （`CoreLifecycleRuntime::reclaim_before_create`）が共有する。古い supervisor が生きていれば何も消さず、状態がある ID は guard で消さない。
  best effort で create の成否は変えない（ただし回収が期限切れ `Timeout` のときは、作業スレッドを残したまま監査記録の fork〔単一スレッド前提。SEC-4〕へ進まないよう core を呼ばず `TIMEOUT` で create を失敗させる。CRI 層は `state` が `NotFound` であることを確かめて資源を解放する）。観測は op 名 `container_log_reclaim`（消した Success・エラーの Failure）
- 上記で回収できない残り（生きている sink が続く・状態がある ID・帰属できない名前）は手動で消す（`docs/setup/container-log-recovery.md`）

## supervisor ログ側の待ち（#2892・SUP-7・CLI-1・REPAIR-5）

- 窓: supervisor ログの flock は supervisor プロセスの終了で外れる。コンテナログの sink は drain の終わりに閉じるので、
  supervisor ログの解放はそれより後になる。`stop` 直後の `delete` は、従来は supervisor ログを 1 回しか試さず、
  `FailedPrecondition` の警告でログを残していた（PR #2865 の CI で `start_stop_delete_real` が 2 回失敗）
- 方式: `supervisor_log::remove_guarded_bounded_waiting`。`FailedPrecondition` の間だけ 50 ms 間隔（`CONTAINER_LOG_LOCK_POLL`）で
  試し直し、他のエラーは即座に返す。guard（`id_is_still_deleted`）は試行ごとにロック保持中に評価し、待つ間に同じ ID が
  再作成されていても新しいインスタンスのログを消さない。1 回の試行の分類はコンテナログと同じ
  （枠の満杯 `RESOURCE_EXHAUSTED`・期限切れ `TIMEOUT`）
- 予算: CLI の `finish_delete` が 10 秒の期限（`CONTAINER_LOG_LOCK_WAIT`）を 2 つのログで共有し、コンテナログには
  supervisor ログの待ちの残りを渡す。最悪は 10 + 5 + 5 = 20 秒で従来と同じ。
  supervisor ログが解放されればコンテナログの sink は既に閉じており、ほぼ即座に消せる。
  supervisor が止まっていて待ち切れない場合は、コンテナログも同じ理由で取れない可能性が高く、1 回の試行で警告にする
- 不採用: 2 つのログで 10 秒ずつ独立に待つ案。最悪が 30 秒になり、`start_stop_delete_real` の `CLI_TIMEOUT`（30 秒）に並び、
  上の 20 秒の予算の記述と試験が崩れる
- 失敗の扱い: 待ち切れなければ `Kept { FailedPrecondition }` と、コンテナログと同じ語彙の `reason: "sink_open_after_wait"` つきの警告
- 待ちを超えて残った supervisor ログは、次の同じ ID の start で世代として回る（CRI は ID を使い回さないため、実質は手動の回収。
  `docs/setup/container-log-recovery.md` はコンテナログが対象で supervisor ログは含まない。残余。REPAIR-3）

## plugin-cri の `RemoveContainer` の supervisor ログ側の待ち（#2964・SUP-7・CRI-2・REPAIR-4・REPAIR-5）

- 従来: `remove_bounded`（1 回だけ）は中の失敗を握りつぶして `Finished` を返すため、ロック保持中でログが残っても `Removed`・Success と
  報告していた（観測の欠落）。CLI と同じ構造に揃える
- 方式: `CoreLifecycleRuntime::delete` が `container_log_lock_wait`（既定 10 秒）を期限として決め、supervisor ログを
  `remove_guarded_bounded_waiting`（guard は状態ストアの `NotFound`。試行ごとにロック保持中に評価）で処理し、
  コンテナログには残り（`deadline - now`）を渡す
- 予算: supervisor ログにかかる時間を t（t ≤ 10 + 5）とすると、コンテナログは max(0, 10 - t) + 5 以下で、合計は max(t, 10) + 5 ≤ 20 秒。
  force delete の最悪は stop 17 + ログ 20 + 起動オプション文書 10 = 47 秒で従来と同じ。`PLUGIN_RUNTIME_TIMEOUT`（60.9 秒）に収まり、
  RPC 側は `run_bounded(runtime_timeout)` で打ち切る。core の delete と bundle の解放の上限、kubelet の `--runtime-request-timeout` との関係は
  #3027 で解消した（次節）
- 不採用: 独立に待つ案。最悪 30 秒で 47 秒が 57 秒になり、余裕が 3.9 秒しか残らない
- 観測の変化（REPAIR-4）: ロック保持中は `Kept { FailedPrecondition }`・記録器 `supervisor_log_remove` の Failure、`target: supervisor_log` の
  警告行に `reason: sink_open_after_wait`。`Internal`・`InvalidArgument` も握りつぶさず `Kept { code }` で出る。
  code 名（`FAILED_PRECONDITION`・`TIMEOUT`・`RESOURCE_EXHAUSTED`）は既存のまま。`reason` は既存の閉じた語彙で、新しい語彙は足さない
- 試験: `sup7_cri2_2964_force_delete_waits_for_supervisor_log_release`・
  `sup7_repair5_2964_force_delete_keeps_supervisor_log_when_lock_outlives_wait`・
  `repair5_2964_force_delete_shares_wait_between_both_logs`（`crates/plugin-cri/tests/lifecycle_supervisor.rs`）。guard の偽（再作成された
  インスタンスのログを消さない）は supervisor 側 `remove_guarded` の試験が担う

## `RemoveContainer` の全体の上限と kubelet の期限（#3027・CRI-2・SUP-7・REPAIR-3・REPAIR-5）

従来の内訳（#2964。47 秒）には、core の `oci_runtime::delete` と、CRI 層 `runtime_remove_one` の bundle の解放が入っていなかった。

### core の delete の待ち

成功の経路の待ちはすべて定数で有界で、数え方の規則は「`StateStore` の呼び出し 1 回につき `STATE_LOCK_TIMEOUT`（5 秒）を 1 回」。

| 段 | 上限 |
| -- | ---- |
| `StateStore::get`（最初） | 5 秒 |
| `ContainerCgroupRemover::scope`（`/proc/self/cgroup` の読み取り） | 待ちなし |
| `StateStore::get`（cgroup の配置が記録されているときの revision の再確認） | 5 秒 |
| cgroup の削除（残った `exec-*` の掃除全体で 1 つの `EXEC_SWEEP_DELETE_TIMEOUT` と rmdir） | 5 秒 |
| `StateStore::delete` | 5 秒 |

合計 20 秒（`oci_runtime::delete` の module doc「待ちの上限」。get の回数は単体試験 `repair5_3027_delete_store_calls_are_bounded` で固定）。
plugin-cri は `create_with_image` を使わず状態レコードに `image_rootfs` が無いため、`BundleLock`（`LOCK_NB` で待たない）と rootfs の削除
（`USERNS_REMOVE_BUDGET`）を通らない。rootfs の削除は次項の bundle の解放が担う。

### 全体の期限

後始末の前の合計は、stop 17 秒 + 状態の読み取り 5 秒（`stop_live_before_force_delete`）+ core 20 秒 = 42 秒。これに後始末の最悪 30 秒を
そのまま足すと 72 秒で `PLUGIN_RUNTIME_TIMEOUT`（60.9 秒）を超える。状態ロックがどれも上限近くまで待つ病的な場合にしか起きないが、
不等式は崩れていたため、`CoreLifecycleRuntime::delete` に全体の期限 `PLUGIN_FORCE_DELETE_DEADLINE`（47 秒 = 従来の最悪の値）を持たせた。

- 後始末の各段（supervisor ログ・コンテナログ・起動オプション文書）は、いまの上限と期限までの残りの小さい方で試す。ロックの待ちと 1 回の試行の
  和が残りを超えないようにし、残りが小さいときは半分ずつ渡す（試行の期限は上限であり通常は短時間で終わるため、残りを全部渡すと待ちが消える）
- 残りが 0 の段は試さず、`Kept { code: Timeout }`（起動オプション文書は警告行と記録器の Failure）として残す。消さずに残す側に倒し、
  起動時の走査と手順書（`docs/setup/container-log-recovery.md`）で回収できる。新しい `reason` の語彙は足さない
- 全体の最悪は max(42, 47) = 47 秒で、`PLUGIN_RUNTIME_TIMEOUT` との余裕 13.9 秒は I/O の時間と、stop の中の状態ロックの待ち（下の残余）に充てる
- 通常（後始末の前が 17 秒以下）は後始末に 30 秒以上残るため、挙動は変わらない
- 照合: `repair5_cri2_3027_remove_container_worst_case_fits_runtime_timeout`（42・47・72 秒の具体値）・
  `repair5_cri2_3027_force_delete_cuts_cleanup_at_deadline`・`repair5_cri2_3027_force_delete_skips_cleanup_when_deadline_exhausted`
- 不採用: `PLUGIN_RUNTIME_TIMEOUT` を上げる案（値は supervisor の受信期限 + 2 秒から導いていて、変更はオーナー判断）。core の `StateStore` 呼び出しに
  共通の deadline を通す案（トレイトの変更で PLUG-1 の拡張点に響く）。2 回目の `get` を消す案（早期終了の意味が変わる）

### bundle の解放

`SpecBundleProvider::release` はロックの待ちが無い。I/O の量は件数で抑えられている（走査の深さ `MAX_REMOVE_DEPTH`、1 ディレクトリの繰り返し
`MAX_DRAIN_PASSES`、展開時の件数 `DEFAULT_MAX_LAYER_ENTRIES` × レイヤー数 `MAX_LAYERS`）が、時間を定数で抑える仕組みは無い。RPC は
`run_bounded` で打ち切られ（`HangingRelease` の試験が実証済み）、記録は `in_flight` のまま残り worker の終了で確定する。時間で打ち切る解放は
本 issue では入れず、残余とした。

### kubelet の `--runtime-request-timeout` との関係

一次情報（kubernetes/kubernetes のタグ `v1.37.1`。`crates/cri/proto` の cri-api `v0.37.1` と同系列）:

- `pkg/kubelet/apis/config/v1beta1/defaults.go` 187〜188 行: `RuntimeRequestTimeout` の既定は 2 分
- `cmd/kubelet/app/options/options.go` 459 行: 説明は「pull・logs・exec・attach 以外の runtime の要求の期限。期限を過ぎると kubelet は要求を取り消し、
  エラーにして後で再試行する」
- `pkg/kubelet/kubelet.go` 416 行: `WithConnectionTimeout(kubeCfg.RuntimeRequestTimeout.Duration)` で `RemoteRuntimeService` を組み立て、
  `staging/src/k8s.io/cri-client/pkg/remote_runtime.go` 211 行で `timeout` に入る
- 同 557〜560 行: `RemoveContainer` は `context.WithTimeout(ctx, r.timeout)`。猶予秒は足さない
- `pkg/kubelet/kuberuntime/kuberuntime_gc.go` 150 行: GC の `removeContainer` が失敗してもログに残して続け、`kubelet.go` 229 行の
  `ContainerGCPeriod`（1 分）ごとの次の GC で再試行する。`kubelet.go` 2796 行の `ContainerDied` の契機でも `cleanUpContainersInPod` が呼ばれる

関係:

- 既定の 120 秒 > `PLUGIN_RUNTIME_TIMEOUT`（60.9 秒）なので、plugin-cri が先に構造化された `DEADLINE_EXCEEDED` を返す。食い違いは無い
- 利用者が `--runtime-request-timeout` を 60.9 秒未満にすると、kubelet が先に取り消す。応答の future は捨てられるが、worker は取り消されず走り続ける。
  次の再試行は、記録が `in_flight` の間は `FAILED_PRECONDITION`（container operation in progress）になり、worker が終わってから成功する。
  下限の推奨値を文書に書くかはオーナーの判断（本 issue では書かない）

### guard の偽（再作成済みの ID）

`sup7_cri2_3027_force_delete_keeps_supervisor_log_when_id_recreated` が plugin-cri の経路で、同じ ID が再作成済みのとき supervisor ログを消さず、
警告行も出さないことを固定する。0 件で成功した結果が `Removed` と報告される観測のずれは、`CleanupOutcome` の意味を変えるため本 issue では直さず、
試験で現状の値を固定した。

### 残余（REPAIR-3）

- 時間で打ち切る bundle の解放と、`RemoveContainer` の worker の取り消し（Create の `AbandonOnDrop` に当たるもの）は無い。Create の巻き戻しの
  `InFlightGuard::drop` の `release` にも時間の上限が無い
- `RemovePodSandbox` は `runtime_remove_one` をコンテナの数だけ順に回すため、kubelet の 1 回の期限を超えうる
- stop の 17 秒は、ポーリングの中と kill の中の状態ロックの待ちを数えていない
- `repair5_create_worst_case_fits_runtime_timeout` は状態ロックを 1 回と数えている。本節の規則との照合は未了
