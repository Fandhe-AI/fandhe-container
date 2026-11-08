# ioeventfd 通知スレッドの停止を wake 用 eventfd で即時にする判断記録（#4160・MVM-1・CORE-7・REPAIR-5）

対象は `crates/microvm/src/microvm.rs` の `IoEventPoller`（専用スレッド `microvm-ioevent`）と `crates/microvm/src/device.rs` の `StopSignal`。
親 issue は #4109（#3698 の対象外の切り出し）、同じ `step` を変えた #4101（異常 revents）の後続。

## 背景

`IoEventPoller` は ioeventfd を `poll(2)` で待つが、停止要求（`StopSignal`）は eventfd ではなく condvar とフラグだった。
そのため停止を取り込むには `poll` を一定時間で戻すしかなく、従来は `IOEVENT_WAIT_SLICE`（10 ms）周期で起床していた。
アイドル時でも VM 1 台につき毎秒約 100 回起床し、VM 数に比例して増える。

## 判断: 即時化する

`StopSignal` に wake 用 eventfd の登録口（`add_waker`）を足し、`request()` がフラグ・condvar に続けて鳴らす。
`IoEventPoller` は自前の wake eventfd を `poll` の末尾の slot に加え、`VcpuLoopBody::stop_waker` で `Weak` を `spawn_loops_gated` に渡す
（スレッド起動前に登録するので、登録前の要求は `vcpu_loop` 先頭のフラグ確認で、登録後の要求は eventfd で捕まる）。
`poll` の待ちは後詰めの `IOEVENT_IDLE_WAIT`（1 s）にする。

- 変更のコストは小さい（eventfd 1 本、`poll` の fd 1 つ、配線少々）。新しい `unsafe` も sys の宣言も足さない（既存の `eventfd_new`・`poll_readable`・`irq::EventFd` を使う）。
- CORE-7 の目標値（`resource-efficiency-target.md`）は RSS で決まり、起床回数は RSS を動かさない。**CORE-7 の数値への直接の影響は無い**。
  関係するのはアイドル時の CPU とタイマー起床で、リソース消費を最小にする方針（CORE-7〜9 の設計制約）と、既存 rustdoc の再評価条件（REPAIR-3）に当たる。

### 却下案: 10 ms のまま残す

毎秒 100 回の起床を許す根拠を示す必要があり、既存の rustdoc の「wake 用 eventfd へ置き換える」方針とも合わない。

## 実測（アイドル時の起床回数）

試験 `mvm1_4160_idle_poller_wakes_rarely` が、固有名のスレッドの `/proc/self/task/<tid>/status` の `voluntary_ctxt_switches` を 500 ms で数える
（`/proc` が読めない環境は skip せず失敗）。環境は Linux 7.0.0-34-generic・debug ビルド。

| 状態 | 500 ms あたりの自発的コンテキストスイッチ | 毎秒換算 |
| ---- | ---------------------------------------- | -------- |
| 変更前（10 ms 周期） | 50 | 約 100 |
| 変更後（`IOEVENT_IDLE_WAIT` = 1 s） | 0 | 1 以下 |

手順: `cargo test -p fandhe-container-microvm mvm1_4160_idle -- --nocapture` が `mvm4160 idle wakeups in 500ms: N` を出す。
変更前の値は、同じ試験を変更前のコードに当てて採った。

## `IOEVENT_IDLE_WAIT` の値の根拠

- 通常の停止は wake で即時に届く。この値は wake が効かなかったときの後詰めの上限である。
- `sys::poll_readable` は 60 s で頭打ちにするため、無期限にはできない。
- `RunningMicroVm` の drop の待ち上限（5 s）より十分短くしないと、wake が効かないときに drop の期限が意味を失う（REPAIR-5）。コンパイル時に検査している。

## 停止の契約が保たれる理由

- `StopSignal` が持つのは `Weak<EventFd>` だけで、fd の所有は poller の body。`vcpu_loop` の body の drop が guard の完了通知より先に走るので、
  「`stop` が `Ok` で戻った時点で fd・mmap・irqfd は解放済み」の契約はそのまま成り立つ（試験 `mvm1_4160_spawn_loops_registers_wake_and_releases_it`）。
- wake を鳴らせなかった場合は構造化ログ 1 行（`op=microvm.stop_wake`）を出す。停止自体は後詰めの上限で有限時間に取り込まれる。
- wake slot の異常 revents は events と同じく fail-closed（`Finish(Failed(Internal))`、ログは `target=wake`）。

## 再評価条件

- TAP の到着通知（TASK-117）を入れて `NetRxPoller` と統合するとき（REPAIR-3）。
- `op=microvm.stop_wake` のログが実環境で観測されたとき。

## 残余

- `NetRxPoller` は `StopSignal::wait_requested`（condvar）で既に即時に止まるため変えていない。
- 各 vCPU スレッドの起床（`VCPU_POLL_INTERVAL` の 100 ms 周期）は本件の範囲外。
