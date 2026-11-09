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
- 各 vCPU スレッドの起床（`VCPU_POLL_INTERVAL` の周期）は本件の範囲外。#4229 で判断した（下の節）。

## vCPU スレッドの `VCPU_POLL_INTERVAL` の判断（#4229・MVM-1・CORE-7・REPAIR-5）

`#4160` の残余だった vCPU スレッドの周期起床を、100 ms のまま残すか・延ばすか・無くすかを判断した。**100 ms から 1 s へ延ばした。**

### 背景

vCPU スレッドは `run_once` を期限つきで 1 回ずつ呼ぶ。1 回ごとに監視スレッド `kvm-run-deadline` を生成・join し、期限切れで `immediate_exit` と kick を立てて
`KVM_RUN` を `-EINTR` で戻し、再入する。アイドル（HLT 中）でもこれが期限ごとに起きる。停止要求は condvar の通知で監視スレッドへ即時に届き、kick で
`KVM_RUN` を中断するので、期限は停止の遅延を決めない。期限が停止に効くのは通知の経路が届かなかったとき（後詰め）だけである。

### 実測（x86_64・Linux 7.0.0-34-generic・debug ビルド・1 vCPU・`hlt; jmp -3` のゲスト）

「起床」は期限切れの件数（`KVM_RUN` の再入）と、vCPU スレッドの自発的コンテキストスイッチ（`voluntary_ctxt_switches`）の両方で数えた。

| 状態 | 期限切れ（毎秒） | 自発的コンテキストスイッチ（毎秒） |
| ---- | ---------------- | ---------------------------------- |
| 変更前（100 ms） | 約 10（500 ms で 4〜5） | 約 20（500 ms で 8〜10） |
| 変更後（1 s） | 1（5 s で 5） | 約 2（5 s で 10） |

手順: `cargo test -p fandhe-container-microvm --test kvm_device -- --ignored kvm_device_idle_halted --nocapture` が
`mvm4229 idle vcpu in 5003ms: deadline_expiries=5 voluntary_switches=10` を出す（変更前の値は、同じ計測を 500 ms の窓で変更前のコードに当てて採った）。
vCPU あたりの起床は約 10 分の 1 になる。RSS は動かないため CORE-7 の数値には直接効かず、効くのはアイドル時の CPU とタイマー起床（CORE-7〜9 の最小リソースの設計制約）である。

### 判断と根拠

- **1 s にした**。停止は通知と kick で即時なので、期限は後詰めの上限でよい（`IOEVENT_IDLE_WAIT` と同じ考え方）。
- **無くさない**。`run_once` が 0 と `RUN_DEADLINE_MAX`（3600 s）超を拒否し、無期限にできない。後詰めがあることで、通知の経路が将来壊れても有限時間で `vcpu_loop` 先頭の停止の確認に戻れる。
- **100 ms のまま残さない**。眠っている vCPU も kick だけで即時に戻ることを実機で確かめた（下）ため、短い期限に停止上の根拠が無い。
- 上限は drop の待ち（`DROP_STOP_WAIT` = 5 s）未満をコンパイル時に検査する。越えると wake が効かないときの drop の期限が意味を失う（REPAIR-5）。`RUN_DEADLINE_MAX` 以下も検査する。
- 期限切れに依存する処理は無い（期限切れは `RunClass::Continue` で、`deadline_exceeded` の件数が終了ログに出るだけ）。ホストからの割り込み注入（COM1 の `push_input`・net の受信ポーラー・ioeventfd）は vCPU の戻りに依らない。

### 停止の契約が保たれる理由

- `kvm_device_stop_kicks_halted_guest_immediately`: HLT で眠る vCPU（最初の期限切れの前後の 2 場面）の `stop` が 50 ms 未満（実測は約 10〜17 ms、全体の回収を含む）で `Requested` になる。
- `kvm_device_stop_kicks_spinning_guest_immediately`: 閾値を `VCPU_POLL_INTERVAL / 2` から間隔に依らない 50 ms に固定した（間隔を延ばして判別力を落とさない）。
- `mvm1_4229_vcpu_poll_interval_is_backstop`（KVM 不要）: `vcpu_loop` が `step` へ `VCPU_POLL_INTERVAL` を渡すこと。

### 再評価条件

- `op=microvm.vcpu_loop` の `deadline_exceeded` が停止の後詰めとして効いた形跡（停止要求から kick より長い遅延）が実環境で観測されたとき。
- `run_once` ごとの監視スレッドの生成をなくす改修（常駐の監視スレッド化）は #4288 で実施済み（下の「vCPU の期限監視スレッドの常駐化」の節）。
- aarch64 の実機（#3781・人間担当・未実施）で、電源 off の AP の停止が kick で即時でないと分かったとき。
- HVF の `VCPU_RUN_SLICE` を見直すとき。

### 残余

- `run_once` ごとの `kvm-run-deadline` スレッドの生成・join は #4288 で常駐 1 本に置き換えた（下の節）。この節の実測値は生成・join が残っていた時点のもの。
- HVF（macOS）の `VCPU_RUN_SLICE`（100 ms）は別の値・別の停止経路のため本件の対象外。
- aarch64 は未検証。モジュール doc の電源 off の AP の記述は「kick で戻る想定」とし、確認済みを装わない（REPAIR-3）。

## vCPU の期限監視スレッドの常駐化（#4288・MVM-1・CORE-7・REPAIR-5）

### 背景

#4229 の後も `VcpuFd::run_bounded` は `KVM_RUN` のたびに `thread::scope` の中で `kvm-run-deadline` を生成し、終わるたびに join していた
（clone とスタック確保・解放が `run_once` の回数だけ起きる。アイドルでは期限切れごと、実行中は exit ごと）。

### 判断: vCPU ごとに常駐 1 本にする

- 監視スレッド（`device::RunWatchdog`）は最初の `run_once` で 1 本だけ作り、以後は `KVM_RUN` ごとに「武装（仕事を渡す）→ `KVM_RUN` → 完了を知らせる → 解除の応答（ack）を待つ」だけを行う。
  監視の本体は従来の `watch_run` のまま（停止要求・期限・kick の契約は #3736 のまま）。
- **kick の宛先の生存**: scoped thread の join に頼れなくなるため、`sys::KickCell`（宛先の `pthread_t` を入れる mutex つきのセル）に置き換えた。
  vCPU スレッドが `KickCell::armed` の閉包の中（= `KVM_RUN` の発行中）にだけ自分を入れ、戻る前（panic の巻き戻しを含む）に空へ戻す。
  `kick` は mutex を保持したまま `pthread_kill` するので、解除後に送信が残ることも、終了したスレッドへ送ることも無い。新しい FFI 宣言は無く、`unsafe` は `sys` 内の既存宣言の呼び出しだけ。
- **`kvm_run` の mmap の共有**: 監視スレッドは `Arc<KvmRunMap>` の clone を武装中だけ持ち（`immediate_exit` の atomic 書き込みだけ）、ack の前に落とす。
  IN・MMIO read の応答の書き戻し（`handle_exit`）は `Arc::get_mut` の排他でだけ行い、取れなければ `Internal` で fail-closed にする（handshake が崩れたことの検出を兼ねる）。
- **`StopSignal`** は `Arc<StopState>` の薄い包み（`Clone` は共有）にし、武装中だけ監視スレッドが clone を持つ。`step` の署名・公開 API は変えない。
- fail-closed（REPAIR-5）: 監視スレッドの死亡・ack の期限切れ（`RUN_WATCHDOG_ACK_WAIT` = 1 s）・前回の仕事の取り残し・二重武装は、期限なしで実行せず `Internal`。
  drop は `Shutdown` を伝え、`RUN_WATCHDOG_JOIN_WAIT`（1 s）以内に終われば join、超えたら切り離して `op=microvm.run_watchdog_join outcome=error code=deadline_exceeded` を 1 行出す。
  待機中のスレッドは所有物の clone を持たないので、切り離しても解放済みの契約は崩れない。2 定数の和は `DROP_STOP_WAIT` 未満をコンパイル時に検査する。
- 計装: `RunStats::watchdog_spawns`（監視スレッドの生成回数）を足し、`op=microvm.vcpu_loop` の終了ログに `watchdog_spawns=` を出す。

### 却下案

- 生の `Send` ハンドルで offset 1 のバイトを触る案: `sys` の `unsafe` が増える。`Arc<KvmRunMap>` なら既存の atomic 書き込みを再利用できる。
- eventfd で武装・解除を知らせる案: `watch_run` が既に condvar で待つため、fd を増やす利点が無い。
- 公開の `run_once` だけ従来の生成方式で残す案: 2 経路の維持費が掛かる。公開の `run_once` も同じ常駐経路を通す（呼び出しごとに信号は作る）。

### 実測（x86_64・Linux 7.0.0-34-generic・debug ビルド・1 vCPU・HLT ゲスト・5 回の期限切れ）

| 状態 | 監視スレッドの生成 | vCPU スレッドの自発的コンテキストスイッチ（5 s） |
| ---- | ------------------ | ---------------------------------------------- |
| 変更前（#4229 の 1 s） | `run_once` の回数（6 回の期限切れで 6 回以上） | 10 |
| 変更後 | 1 | 10 |

手順: `cargo test -p fandhe-container-microvm --test kvm_device -- --ignored --exact kvm_device_idle_halted_vcpu_wakeups --nocapture` が
`mvm4229 idle vcpu in 5001ms: deadline_expiries=5 voluntary_switches=10` と `mvm4288 idle vcpu: deadline_exceeded=6 watchdog_spawns=1` を出す。
変更前の値は同じ試験を変更前のコード（origin/main）に当てて採った（生成回数は変更前は計装が無く、1 回の `run_once` に 1 回の生成という構造から数える）。
**起床回数（自発的コンテキストスイッチ）は変わらない**（期限切れ 1 回あたり `KVM_RUN` の眠りと ack の待ちで約 2 回）。減ったのは期限切れ・exit ごとの
スレッドの clone・スタックの確保と解放・join で、これらは自発的コンテキストスイッチの数には現れない。RSS・CORE-7 の数値への直接の影響は無い。

### 照合

- `mvm1_4288_resident_watchdog_spawns_once`（KVM 不要）: 期限切れ 50 回と正常終了 50 回を交互に繰り返しても、kick を出したスレッドの ID が 1 種類・名前つきスレッドが 1 本・drop 後は 0 本で、各回の結末が具体値どおり。
- `mvm1_4288_resident_watchdog_*`: 武装中の停止要求の kick・待機中は kick しない・死亡と ack 切れの fail-closed・drop が上限内で終わる。
- `kvm_device_idle_halted_vcpu_wakeups`（実機）: 期限切れ 6 回以上で `watchdog_spawns == 1`。停止の即時性の試験（50 ms 閾値）は変えていない（武装・解除の handshake の費用の回帰ガード）。

### 再評価条件・残余

- D 状態で KILL が効かない vCPU は、ack 待ちが `RUN_WATCHDOG_ACK_WAIT` で切れて `Internal` になる（期限なしでは続けない）。
- aarch64 の実機（#3781・人間担当）は未検証。HVF（macOS）は別の停止経路のため対象外。
