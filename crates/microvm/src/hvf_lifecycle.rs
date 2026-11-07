//! macOS microVM の停止と資源の解放順序の OS 非依存コア（TASK-192.16・#3798・MVM-5・MVM-1・REPAIR-5）。`unsafe` なし。
//!
//! 役割: `hvf::microvm` の `RunningHvfMicroVm::stop` と、stop を経ない drop の両方が通る「vCPU スレッドを期限つきで止める →
//! 止まったと確かめられたときだけ資源を決まった順で解放する」手順を 1 か所に置く。`hv_*` を呼ばないため、`LoopHandle` と偽の
//! 資源（drop の順を記録する型）で Linux の PR CI でも単体試験が走る（macOS の PR CI は型検査のみ）。
//! 呼び出し元は `hvf::microvm`（macOS かつ aarch64 限定）。終了理由の語彙は Linux 版（`microvm::RunningMicroVm::stop`・#887）と
//! 共有の `crate::stop::StopReason`、停止の期限の上限も Linux の `STOP_DEADLINE_MAX` と同じ 60 秒（[`VCPU_STOP_DEADLINE_MAX`]）。
//!
//! # 解放順序（[`stop_and_release`]）
//! 1. 停止要求を立てて kick（`hv_vcpus_exit`）し、vCPU スレッドの報告を期限まで待つ（待つ間も kick し直す。`LoopHandle::stop`）。
//!    スレッドは実行ループを抜けたら、owning thread 自身で vCPU を `hv_vcpu_destroy` し、続けて捕捉していた `Arc<VmWithGic>` を
//!    落としてから報告を送る。つまり `Ok` で戻った時点で vCPU は破棄済みで、スレッド側の VM への参照も無い。
//!    止まりを確かめる対象は vCPU 群と、RAM に触る補助スレッド（macOS の受信ポーラー `hvf-net-rx`。[`StopWithAux`]。#4030）。
//!    補助スレッドは kick（世代番号の通知）で即座に起き、期限は vCPU と共有（下限 [`AUX_STOP_MIN`]）。スレッドは終了の直前に
//!    transport・RAM のスロットの clone・割り込み線を落としてから報告する。
//! 2. `Ok` のときだけ、デバイス → ゲスト RAM → VM の順に drop する。
//!    - デバイス: `GicSpiLine` の保持と dispatcher を VM より先に落とす。VM の破棄後に古い線から注入されないことは、`VmWithGic` の
//!      生存フラグでも守られる（二重の防御）。
//!    - ゲスト RAM: `GuestMapping` の drop は `hv_vm_unmap` が成功したときだけ backing を munmap する（失敗ならリークする）。
//!      対応付けは `Arc<HvVm>` を保持するため、unmap は必ず `hv_vm_destroy` より前になる。unmap の後でなければ munmap しない
//!      （ゲストがまだ書けうるメモリを解放しない）。
//!    - VM: 最後の `Arc<VmWithGic>` の drop が GIC とともに `hv_vm_destroy` を行い、成功したら「1 プロセス 1 VM」の占有を戻す。
//! 3. 期限切れ（`TIMEOUT`）などで止まりが確かめられなかったときは、ゲスト RAM の対応付けを `mem::forget` でリークする
//!    （fail-closed）。残る資源と回収の方法は `hvf::microvm` のモジュール doc。
//!
//! # 複数 vCPU（#3884）
//! 止まりの確認は「N 台すべてが報告した」こと（`hvf_loop::stop_all`。parked の AP を含む）。1 台でも確かめられなければ RAM を
//! リークする。AP の exit（SYSTEM_OFF・fail-closed の停止）は `VcpuSet::is_finished` が VM 全体の終了として伝え、停止時の集約でその理由を返す（#3891）。

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use crate::error::{MicrovmError, MicrovmErrorCode};
use crate::hvf_abi::HvRunStats;
use crate::hvf_loop::{LoopHandle, VCPU_STOP_DEADLINE_MAX, VcpuKick, VcpuSetStopReport, log_line};
use crate::stop::StopReason;

/// stop を経ない drop が vCPU スレッドの停止を待つ期限（REPAIR-5。Linux の `DROP_STOP_WAIT` と同値）。
pub const DROP_STOP_DEADLINE: Duration = Duration::from_secs(5);

/// 期限つきで止められる vCPU スレッドの操作口（`LoopHandle` の抽象。単体試験で差し替えるため）。
pub trait VcpuStopper {
    /// 停止を要求し、`deadline` まで終了報告を待つ。`Ok` で戻った時点で vCPU は破棄済みであること。
    fn stop(self, deadline: Duration) -> Result<VcpuSetStopReport, MicrovmError>;
}

impl<K: VcpuKick> VcpuStopper for LoopHandle<K> {
    fn stop(self, deadline: Duration) -> Result<VcpuSetStopReport, MicrovmError> {
        LoopHandle::stop(self, deadline).map(VcpuSetStopReport::single)
    }
}

/// vCPU 以外で、ゲスト RAM とデバイスに触るスレッド（受信ポーラー `hvf-net-rx`。#4030）の期限つきの停止口。
///
/// `Ok` で戻った時点で、そのスレッドが持つ資源（transport・RAM のスロットの clone・割り込み線）は解放済みであること。
pub trait AuxStopper {
    /// 停止を要求し、`deadline` まで終了報告を待つ。
    fn stop(self, deadline: Duration) -> Result<StopReason, MicrovmError>;
}

/// 補助スレッドの停止に与える下限（vCPU の停止で期限を使い切っていても、起こして報告を受ける分だけは試みる。#4030）。
pub const AUX_STOP_MIN: Duration = Duration::from_millis(100);

/// vCPU 群と補助スレッド（受信ポーラー）をまとめて止める [`VcpuStopper`]（#4030・MVM-5・MVM-1・REPAIR-5）。
///
/// [`stop_and_release`] の解放順（devices、memory、vm）は変えず、その前段の「止まりを確かめる」対象に補助スレッドを足す。
/// 先に vCPU を止め、続けて残り時間（下限 [`AUX_STOP_MIN`]）で補助スレッドを止める。どちらかが `Err` なら `Err`
/// （止まりを確かめられないスレッドが RAM を握っているので、呼び出し元は RAM を解放しない。fail-closed）。
/// vCPU の停止が `Err` でも補助スレッドの停止は必ず試みる（スレッドを放置しない）。
pub struct StopWithAux<S, A> {
    /// vCPU 群。
    pub vcpus: S,
    /// 補助スレッド（無ければ `None`）。
    pub aux: Option<A>,
}

impl<S: VcpuStopper, A: AuxStopper> VcpuStopper for StopWithAux<S, A> {
    /// 報告の `reason` は、vCPU が `Requested` で補助が `Requested` 以外ならその補助の理由にする（受信ポーラーの失敗は
    /// `VmShutdown` 経由で vCPU を `Requested` のまま止めるため、失敗が報告から消えないようにする）。
    fn stop(self, deadline: Duration) -> Result<VcpuSetStopReport, MicrovmError> {
        let started = std::time::Instant::now();
        let vcpu_result = self.vcpus.stop(deadline);
        let aux_result = self
            .aux
            .map(|a| a.stop(deadline.saturating_sub(started.elapsed()).max(AUX_STOP_MIN)));
        let mut report = vcpu_result?;
        if let Some(r) = aux_result {
            let reason = r?;
            if report.reason == StopReason::Requested {
                report.reason = reason;
            }
        }
        Ok(report)
    }
}

/// デバイスの解放を期限つきで試み、成否を返す口（`hvf::microvm` のデバイスバスが実装する。REPAIR-5・MVM-5）。
///
/// `dispatcher()` の clone を持つ呼び出し元がロックを保持している間は、デバイスを手放せない。その失敗を黙って成功扱いに
/// せず、[`stop_and_release`] が RAM・VM を解放しない（リークする）判断に使う。
pub trait ReleaseDevices {
    /// `deadline` まで再試行してデバイスを手放す。手放せなければ `DeadlineExceeded`。
    fn release_devices(&mut self, deadline: Duration) -> Result<(), MicrovmError>;
}

/// ゲスト RAM の解放を期限つきで試みる口（`GuestMemorySlot` が実装する。REPAIR-5・MVM-5・#4092）。
///
/// vCPU の停止を確かめた後に呼ぶ。vCPU スレッドが RAM の lock を持ったまま戻らない場合に備え、取得は `deadline` で打ち切り、
/// 取れなければリークして `DeadlineExceeded` を返す。
pub trait ReleaseMemory {
    /// `deadline` まで試みて RAM を手放す。手放せなければ（リークして）`DeadlineExceeded`。
    fn release_memory(self, deadline: Duration) -> Result<(), MicrovmError>;
}

/// 停止確認後の RAM 取得に与える下限（停止の期限を使い切っていても、空いている lock の取得だけは試みる）。
pub const MEMORY_RELEASE_MIN: Duration = Duration::from_millis(100);

/// デバイスの解放を待つ期限（vCPU は停止済みなので、競合はデバイス操作の保持者だけ）。
pub const DEVICE_RELEASE_DEADLINE: Duration = Duration::from_secs(1);

/// 停止の終了報告（拡張できる構造。真偽値・文字列で返さない）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct HvfStopReport {
    /// 終了理由（Linux と共有の語彙）。ゲスト起因（`GuestShutdown`・`Failed(..)`）で先に終わっていた場合もその理由。
    /// 複数 vCPU では vCPU 0 から順に見て最初の `Requested` 以外（`VcpuSetStopReport::reason`）。
    pub reason: StopReason,
    /// 全 vCPU の累積の実行統計の合計。
    pub stats: HvRunStats,
    /// 最長の vCPU スレッドの開始から終了までの時間。
    pub elapsed: Duration,
    /// 回収した vCPU の台数（AP の parked スレッドを含む。#3884）。
    pub vcpu_count: u32,
    /// vCPU ごとの実行統計（index 順。`[0]` が BSP。#3884）。
    pub per_vcpu: Vec<HvRunStats>,
}

/// 解放の対象。drop 順は [`stop_and_release`] が決める（フィールドの宣言順には依らない）。
#[derive(Debug)]
pub struct Resources<D, M, V> {
    /// virtio-mmio のデバイス群と dispatcher。
    pub devices: D,
    /// ゲスト RAM（対応付けの所有者）。
    pub memory: M,
    /// GIC つきの VM。
    pub vm: V,
}

/// 停止を試み、止まりを確かめられたときだけ資源を devices → memory → vm の順に drop する（モジュール doc の「解放順序」）。
///
/// - `deadline` が 0 または [`VCPU_STOP_DEADLINE_MAX`] 超なら `InvalidArgument`。ただし資源を持ったまま返さず、
///   [`DROP_STOP_DEADLINE`] で同じ手順を行ってからエラーを返す（不正な引数で解放が漏れないように）。
/// - 期限切れ・`Internal` は止まりを確かめられていない。`memory` をリークし（`mem::forget`）、`devices`・`vm` は drop する
///   （`vm` の `Arc` は vCPU スレッドと、リークした対応付けも保持するため、VM の破棄は起きない）。エラーをそのまま返す。
pub fn stop_and_release<S, D, M, V>(
    op: &'static str,
    stopper: S,
    deadline: Duration,
    resources: Resources<D, M, V>,
) -> Result<HvfStopReport, MicrovmError>
where
    S: VcpuStopper,
    D: ReleaseDevices,
    M: ReleaseMemory,
{
    let invalid = deadline.is_zero() || deadline > VCPU_STOP_DEADLINE_MAX;
    let effective = if invalid {
        DROP_STOP_DEADLINE
    } else {
        deadline
    };
    let Resources {
        mut devices,
        memory,
        vm,
    } = resources;
    // 処理開始時に終了時刻の基準を 1 回だけ取り、vCPU の停止待ちとデバイス解放待ちで同じ期限を共有する（REPAIR-5）。
    let started = std::time::Instant::now();
    let result = stopper.stop(effective);
    let outcome = match result {
        Ok(report) => match release_within(&mut devices, effective, started) {
            Ok(()) => {
                drop(devices);
                // vCPU は全台止まっているので lock は空いている。それでも取得は期限つき（REPAIR-5）。
                let remaining = effective.saturating_sub(started.elapsed());
                match memory.release_memory(remaining.max(MEMORY_RELEASE_MIN)) {
                    Ok(()) => {
                        drop(vm);
                        Ok(HvfStopReport {
                            reason: report.reason,
                            stats: report.stats,
                            elapsed: report.elapsed,
                            vcpu_count: u32::try_from(report.per_vcpu.len()).unwrap_or(u32::MAX),
                            per_vcpu: report.per_vcpu.iter().map(|r| r.stats).collect(),
                        })
                    }
                    Err(e) => {
                        // RAM の取得に失敗（リーク済み）。
                        drop(vm);
                        Err(e)
                    }
                }
            }
            Err(e) => {
                // デバイス（backend）が dispatcher に残っている。デバイス → RAM → VM の順を守れないため RAM を解放しない。
                drop(devices);
                std::mem::forget(memory);
                drop(vm);
                Err(e)
            }
        },
        Err(e) => {
            // 止まりを確かめられていない。ゲストがまだ書けうるメモリを解放しない。
            drop(devices);
            std::mem::forget(memory);
            drop(vm);
            Err(e)
        }
    };
    match &outcome {
        Ok(r) => {
            let (level, result) = match r.reason {
                StopReason::Failed(_) => ("error", "error"),
                _ => ("info", "ok"),
            };
            log_line(format_args!(
                "level={level} op={op} outcome={result} reason={} released=true",
                r.reason.as_str()
            ));
        }
        Err(e) => log_line(format_args!(
            "level=error op={op} outcome=error code={} released=false leaked=guest_ram,vm,vcpu_thread",
            e.code().as_str()
        )),
    }
    if invalid {
        return Err(MicrovmError::new(
            MicrovmErrorCode::InvalidArgument,
            "stop deadline must be in (0, 60s]",
        ));
    }
    outcome
}

/// teardown の開始を記録し、開始後の vCPU 作成を拒否するための印（TASK-192.16・#3798・MVM-5）。
///
/// Apple の `hv_gic_create` の記述は「vCPU が走り出すとトポロジーは確定する」「vCPU を破棄するのは VM を teardown するときだけ」。
/// 本 crate は pause・vCPU の再作成・hot-unplug を持たないため、vCPU の破棄は teardown の一部としてだけ起きる。この印は、
/// vCPU スレッドが破棄の直前に立て、以後の `VmWithGic::create_vcpu` を拒否することで、破棄の後の再作成を書けなくする。
#[derive(Debug, Default)]
pub struct TeardownMark(AtomicBool);

impl TeardownMark {
    /// 未開始の印を作る。
    pub fn new() -> Self {
        Self::default()
    }

    /// teardown を始める（vCPU を破棄する直前に呼ぶ）。
    pub fn begin(&self) {
        self.0.store(true, Ordering::Release);
    }

    /// teardown 開始後なら `FailedPrecondition`。vCPU を作る前に呼ぶ。
    pub fn check_can_create_vcpu(&self) -> Result<(), MicrovmError> {
        if self.0.load(Ordering::Acquire) {
            return Err(MicrovmError::new(
                MicrovmErrorCode::FailedPrecondition,
                "vm teardown has begun; creating a vcpu is refused",
            ));
        }
        Ok(())
    }
}

/// 期限の残り（`effective - started.elapsed()`）と [`DEVICE_RELEASE_DEADLINE`] の小さい方でデバイスを手放す。
/// 残りが 0 なら解放を試みず `DeadlineExceeded` を返す（REPAIR-5）。
fn release_within<D: ReleaseDevices>(
    devices: &mut D,
    effective: Duration,
    started: std::time::Instant,
) -> Result<(), MicrovmError> {
    let remaining = effective.saturating_sub(started.elapsed());
    if remaining.is_zero() {
        return Err(MicrovmError::new(
            MicrovmErrorCode::DeadlineExceeded,
            "stop deadline exhausted before devices were released",
        ));
    }
    devices.release_devices(remaining.min(DEVICE_RELEASE_DEADLINE))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hvf_loop::{LoopStart, spawn_loop};
    use std::sync::{Arc, Mutex, mpsc};

    #[derive(Debug)]
    struct FakeKick;

    impl VcpuKick for FakeKick {
        fn kick(&self) -> Result<(), MicrovmError> {
            Ok(())
        }
    }

    /// drop された順を記録する資源。
    struct Rec(&'static str, Arc<Mutex<Vec<&'static str>>>);

    impl ReleaseDevices for Rec {
        fn release_devices(&mut self, _deadline: Duration) -> Result<(), MicrovmError> {
            Ok(())
        }
    }

    impl ReleaseMemory for Rec {
        fn release_memory(self, _deadline: Duration) -> Result<(), MicrovmError> {
            Ok(())
        }
    }

    /// 解放に失敗するデバイス。
    struct StuckDevices(Rec);

    impl ReleaseDevices for StuckDevices {
        fn release_devices(&mut self, _deadline: Duration) -> Result<(), MicrovmError> {
            assert_eq!(self.0.0, "devices");
            Err(MicrovmError::new(
                MicrovmErrorCode::DeadlineExceeded,
                "stuck",
            ))
        }
    }

    impl Drop for Rec {
        fn drop(&mut self) {
            if let Ok(mut v) = self.1.lock() {
                v.push(self.0);
            }
        }
    }

    fn resources(log: &Arc<Mutex<Vec<&'static str>>>) -> Resources<Rec, Rec, Rec> {
        Resources {
            devices: Rec("devices", Arc::clone(log)),
            memory: Rec("memory", Arc::clone(log)),
            vm: Rec("vm", Arc::clone(log)),
        }
    }

    const LONG: Duration = Duration::from_secs(5);

    /// 停止フラグを見て終わる素直な vCPU スレッド（`ready` の後に停止要求を待つ）。
    fn responsive() -> LoopHandle<FakeKick> {
        spawn_loop::<FakeKick, _>("hvf-test", LONG, |start: LoopStart<FakeKick>| {
            let stop = start.ready(FakeKick);
            while !stop.load(Ordering::Acquire) {
                std::thread::sleep(Duration::from_millis(1));
            }
            (StopReason::Requested, HvRunStats::default())
        })
        .unwrap()
    }

    /// 渡された期限を記録するデバイス。
    struct RecordDeadline(Arc<Mutex<Option<Duration>>>);

    impl ReleaseDevices for RecordDeadline {
        fn release_devices(&mut self, deadline: Duration) -> Result<(), MicrovmError> {
            *self.0.lock().unwrap() = Some(deadline);
            Ok(())
        }
    }

    /// REPAIR-5・REPAIR-12・TASK-192.16: 短い停止期限ではデバイス解放へ渡す期限が残り時間以下に絞られ、
    /// 期限を使い切っていれば解放を試みず `DeadlineExceeded` になる。
    #[test]
    fn repair5_3798_device_release_shares_stop_deadline() {
        let seen = Arc::new(Mutex::new(None));
        let mut d = RecordDeadline(Arc::clone(&seen));
        release_within(&mut d, Duration::from_millis(10), std::time::Instant::now()).unwrap();
        let got = seen.lock().unwrap().unwrap();
        assert!(got <= Duration::from_millis(10), "got {got:?}");
        // 長い期限では DEVICE_RELEASE_DEADLINE で頭打ち。
        release_within(&mut d, LONG, std::time::Instant::now()).unwrap();
        assert_eq!(seen.lock().unwrap().unwrap(), DEVICE_RELEASE_DEADLINE);
        // 期限を使い切った場合は解放を呼ばない。
        *seen.lock().unwrap() = None;
        let past = std::time::Instant::now() - Duration::from_millis(50);
        let e = release_within(&mut d, Duration::from_millis(10), past).unwrap_err();
        assert_eq!(e.code(), MicrovmErrorCode::DeadlineExceeded);
        assert!(seen.lock().unwrap().is_none());
    }

    /// MVM-5・TASK-192.16: 成功時の解放順は devices → memory → vm で、報告の理由は `Requested`。
    #[test]
    fn mvm5_3798_stop_releases_in_order() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let report =
            stop_and_release("hvf.microvm.stop", responsive(), LONG, resources(&log)).unwrap();
        assert_eq!(report.reason, StopReason::Requested);
        assert_eq!(*log.lock().unwrap(), vec!["devices", "memory", "vm"]);
    }

    /// MVM-5・TASK-192.16: ゲスト起因で先に終わっていた場合も、その理由を報告して解放する。
    #[test]
    fn mvm5_3798_guest_shutdown_reason_is_reported() {
        let h = spawn_loop::<FakeKick, _>("hvf-test", LONG, |start: LoopStart<FakeKick>| {
            let _stop = start.ready(FakeKick);
            (StopReason::GuestShutdown, HvRunStats::default())
        })
        .unwrap();
        let t = std::time::Instant::now();
        while !h.is_finished() && t.elapsed() < LONG {
            std::thread::sleep(Duration::from_millis(1));
        }
        let log = Arc::new(Mutex::new(Vec::new()));
        let report = stop_and_release("hvf.microvm.stop", h, LONG, resources(&log)).unwrap();
        assert_eq!(report.reason, StopReason::GuestShutdown);
        assert_eq!(*log.lock().unwrap(), vec!["devices", "memory", "vm"]);
    }

    /// MVM-5・TASK-192.16: ゲストの未対応 exit による失敗も `Failed(..)` として報告し、解放する。
    #[test]
    fn mvm5_3798_failed_reason_is_reported() {
        let h = spawn_loop::<FakeKick, _>("hvf-test", LONG, |start: LoopStart<FakeKick>| {
            let _stop = start.ready(FakeKick);
            (
                StopReason::Failed(MicrovmErrorCode::Unimplemented),
                HvRunStats::default(),
            )
        })
        .unwrap();
        let log = Arc::new(Mutex::new(Vec::new()));
        let report = stop_and_release("hvf.microvm.stop", h, LONG, resources(&log)).unwrap();
        assert_eq!(
            report.reason,
            StopReason::Failed(MicrovmErrorCode::Unimplemented)
        );
        assert_eq!(log.lock().unwrap().len(), 3);
    }

    /// REPAIR-5・MVM-5・TASK-192.16: 応答しない vCPU スレッドへの停止は `TIMEOUT` になり、ゲスト RAM を解放せずリークする。
    #[test]
    fn repair5_mvm5_3798_stop_deadline_expired_is_timeout_and_keeps_resources() {
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let h = spawn_loop::<FakeKick, _>("hvf-test", LONG, move |start: LoopStart<FakeKick>| {
            let _stop = start.ready(FakeKick);
            // 停止フラグを無視して、テストの終わりまで返らない。
            let _ = release_rx.recv();
            (StopReason::Requested, HvRunStats::default())
        })
        .unwrap();
        let log = Arc::new(Mutex::new(Vec::new()));
        let e = stop_and_release(
            "hvf.microvm.stop",
            h,
            Duration::from_millis(50),
            resources(&log),
        )
        .unwrap_err();
        assert_eq!(e.code(), MicrovmErrorCode::DeadlineExceeded);
        assert_eq!(e.code().as_str(), "TIMEOUT");
        // memory は drop されない（リーク）。devices と vm の手放しだけが起きる。
        assert_eq!(*log.lock().unwrap(), vec!["devices", "vm"]);
        let _ = release_tx.send(());
    }

    /// 渡された期限いっぱいまで待ってから失敗するデバイス（別スレッドが dispatcher をロックし続けている状況の模擬）。
    struct LockedDevices;

    impl ReleaseDevices for LockedDevices {
        fn release_devices(&mut self, deadline: Duration) -> Result<(), MicrovmError> {
            std::thread::sleep(deadline);
            Err(MicrovmError::new(
                MicrovmErrorCode::DeadlineExceeded,
                "locked",
            ))
        }
    }

    /// REPAIR-5・REPAIR-12・TASK-192.16: dispatcher がロックされたままでも `stop(10ms)` は期限の近くで `TIMEOUT` を返し、
    /// デバイス解放に固定の 1 秒（`DEVICE_RELEASE_DEADLINE`）を別枠で与えない。
    #[test]
    fn repair5_3798_stop_with_locked_devices_returns_near_deadline() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let r = Resources {
            devices: LockedDevices,
            memory: Rec("memory", Arc::clone(&log)),
            vm: Rec("vm", Arc::clone(&log)),
        };
        let deadline = Duration::from_millis(10);
        let t = std::time::Instant::now();
        let e = stop_and_release("hvf.microvm.stop", responsive(), deadline, r).unwrap_err();
        let took = t.elapsed();
        assert_eq!(e.code().as_str(), "TIMEOUT");
        assert!(
            took < deadline + Duration::from_millis(400),
            "took {took:?} for deadline {deadline:?}"
        );
        assert!(took < DEVICE_RELEASE_DEADLINE, "took {took:?}");
        // memory は解放されずリークする。
        assert_eq!(*log.lock().unwrap(), vec!["vm"]);
    }

    /// REPAIR-5・MVM-5・TASK-192.16: デバイスの解放に失敗したら成功扱いにせず、RAM を解放しない。
    #[test]
    fn repair5_mvm5_3798_device_release_failure_is_error_and_keeps_memory() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let r = Resources {
            devices: StuckDevices(Rec("devices", Arc::clone(&log))),
            memory: Rec("memory", Arc::clone(&log)),
            vm: Rec("vm", Arc::clone(&log)),
        };
        let e = stop_and_release("hvf.microvm.stop", responsive(), LONG, r).unwrap_err();
        assert_eq!(e.code(), MicrovmErrorCode::DeadlineExceeded);
        assert_eq!(*log.lock().unwrap(), vec!["devices", "vm"]);
    }

    /// REPAIR-5・TASK-192.16: 0 と 60 秒超は `InvalidArgument`。資源は漏らさず順に解放する。
    #[test]
    fn mvm5_3798_invalid_deadline_rejected() {
        for d in [Duration::ZERO, Duration::from_secs(61)] {
            let log = Arc::new(Mutex::new(Vec::new()));
            let e =
                stop_and_release("hvf.microvm.stop", responsive(), d, resources(&log)).unwrap_err();
            assert_eq!(e.code(), MicrovmErrorCode::InvalidArgument);
            assert_eq!(*log.lock().unwrap(), vec!["devices", "memory", "vm"]);
        }
    }

    /// MVM-5・TASK-192.16: teardown の開始後は vCPU の作成が `FailedPrecondition`。
    #[test]
    fn mvm5_3798_teardown_mark_refuses_vcpu_creation() {
        let m = TeardownMark::new();
        assert!(m.check_can_create_vcpu().is_ok());
        m.begin();
        let e = m.check_can_create_vcpu().unwrap_err();
        assert_eq!(e.code(), MicrovmErrorCode::FailedPrecondition);
    }

    /// 停止要求で終わる parked の AP の模擬。
    fn parked() -> LoopHandle<FakeKick> {
        spawn_loop::<FakeKick, _>("hvf-vcpu-1", LONG, |start: LoopStart<FakeKick>| {
            let stop = start.ready(FakeKick);
            while !stop.load(Ordering::Acquire) {
                std::thread::sleep(Duration::from_millis(1));
            }
            (StopReason::Requested, HvRunStats::default())
        })
        .unwrap()
    }

    /// 停止要求を無視して `release_rx` が解かれるまで返らない vCPU の模擬。
    fn stuck(release_rx: mpsc::Receiver<()>) -> LoopHandle<FakeKick> {
        spawn_loop::<FakeKick, _>("hvf-vcpu-2", LONG, move |start: LoopStart<FakeKick>| {
            let _stop = start.ready(FakeKick);
            let _ = release_rx.recv();
            (StopReason::Requested, HvRunStats::default())
        })
        .unwrap()
    }

    /// `LoopHandle` の集合を 1 つの `VcpuStopper` として扱う試験用の包み。
    struct Set(Vec<LoopHandle<FakeKick>>);

    impl VcpuStopper for Set {
        fn stop(self, deadline: Duration) -> Result<VcpuSetStopReport, MicrovmError> {
            crate::hvf_loop::stop_all(self.0, deadline)
        }
    }

    /// MVM-5・MVM-1・#3884: N 台が全部止まれば devices → memory → vm の順で解放し、台数と vCPU ごとの統計を報告する。
    #[test]
    fn mvm5_3884_stop_and_release_waits_for_all_vcpus() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let set = Set(vec![responsive(), parked(), parked()]);
        let report = stop_and_release("hvf.microvm.stop", set, LONG, resources(&log)).unwrap();
        assert_eq!(report.reason, StopReason::Requested);
        assert_eq!(report.vcpu_count, 3);
        assert_eq!(report.per_vcpu.len(), 3);
        assert_eq!(*log.lock().unwrap(), vec!["devices", "memory", "vm"]);
    }

    /// REPAIR-5・MVM-5・#3884: 1 台でも止まりを確かめられなければ RAM をリークする（devices と vm の手放しだけ）。
    #[test]
    fn repair5_mvm5_3884_one_stuck_vcpu_keeps_memory() {
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let log = Arc::new(Mutex::new(Vec::new()));
        let set = Set(vec![responsive(), parked(), stuck(release_rx)]);
        let e = stop_and_release(
            "hvf.microvm.stop",
            set,
            Duration::from_millis(100),
            resources(&log),
        )
        .unwrap_err();
        assert_eq!(e.code(), MicrovmErrorCode::DeadlineExceeded);
        assert_eq!(*log.lock().unwrap(), vec!["devices", "vm"]);
        let _ = release_tx.send(());
    }

    /// REPAIR-5・MVM-5・MVM-1・#4092: route が RAM の lock を持ったまま戻らない（応答しないバックエンド）状況でも、
    /// stop は vCPU の停止と期限つきの RAM 取得で戻り、RAM を解放（drop）しない。
    #[cfg(any(target_os = "linux", all(target_os = "macos", target_arch = "aarch64")))]
    #[test]
    fn repair5_4092_stop_with_ram_lock_held_returns_near_deadline_and_leaks() {
        use crate::guest_memory::{GuestAddress, GuestMemory, HeapBacking};
        use crate::guest_memory_slot::GuestMemorySlot;
        let slot = GuestMemorySlot::new(
            GuestMemory::new(GuestAddress::new(0x1000), HeapBacking::new(0x100).unwrap()).unwrap(),
        );
        let held = slot.clone();
        let (locked_tx, locked_rx) = mpsc::channel::<()>();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let h = std::thread::spawn(move || {
            let _ = held.with_memory(|_| {
                let _ = locked_tx.send(());
                let _ = release_rx.recv();
                Ok(())
            });
        });
        locked_rx.recv().unwrap();
        let log = Arc::new(Mutex::new(Vec::new()));
        let r = Resources {
            devices: Rec("devices", Arc::clone(&log)),
            memory: slot.clone(),
            vm: Rec("vm", Arc::clone(&log)),
        };
        let t = std::time::Instant::now();
        let e = stop_and_release(
            "hvf.microvm.stop",
            responsive(),
            Duration::from_millis(50),
            r,
        )
        .unwrap_err();
        assert_eq!(e.code(), MicrovmErrorCode::DeadlineExceeded);
        assert!(
            t.elapsed() < Duration::from_secs(3),
            "took {:?}",
            t.elapsed()
        );
        let _ = release_tx.send(());
        h.join().unwrap();
        // 中身は取り出されていない（リーク）。
        assert!(slot.with_memory(|_| Ok(())).is_ok());
    }

    /// 補助スレッドの偽物（渡された期限を記録する）。
    struct FakeAux(
        Arc<Mutex<Option<Duration>>>,
        Result<StopReason, MicrovmError>,
    );

    impl AuxStopper for FakeAux {
        fn stop(self, deadline: Duration) -> Result<StopReason, MicrovmError> {
            *self.0.lock().unwrap() = Some(deadline);
            self.1
        }
    }

    fn aux(r: Result<StopReason, MicrovmError>) -> (FakeAux, Arc<Mutex<Option<Duration>>>) {
        let seen = Arc::new(Mutex::new(None));
        (FakeAux(Arc::clone(&seen), r), seen)
    }

    /// MVM-5・REPAIR-5・#4030: 補助が `Requested` なら従来どおり devices、memory、vm の順に解放される。
    #[test]
    fn mvm5_4030_aux_ok_keeps_release_order() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let (a, seen) = aux(Ok(StopReason::Requested));
        let stopper = StopWithAux {
            vcpus: responsive(),
            aux: Some(a),
        };
        let r = stop_and_release("test", stopper, LONG, resources(&log)).unwrap();
        assert_eq!(r.reason, StopReason::Requested);
        assert_eq!(r.vcpu_count, 1);
        assert_eq!(*log.lock().unwrap(), vec!["devices", "memory", "vm"]);
        let got = seen.lock().unwrap().unwrap();
        assert!(got <= LONG && got >= AUX_STOP_MIN, "{got:?}");
    }

    /// 補助の失敗は、vCPU が `Requested` でも報告の理由に残る。
    #[test]
    fn mvm5_4030_aux_failure_reason_is_reported() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let (a, _) = aux(Ok(StopReason::Failed(MicrovmErrorCode::Internal)));
        let stopper = StopWithAux {
            vcpus: responsive(),
            aux: Some(a),
        };
        let r = stop_and_release("test", stopper, LONG, resources(&log)).unwrap();
        assert_eq!(r.reason, StopReason::Failed(MicrovmErrorCode::Internal));
        assert_eq!(*log.lock().unwrap(), vec!["devices", "memory", "vm"]);
    }

    /// 補助の停止を確かめられなければ RAM を解放しない（リーク）。補助は呼ばれ、`Err` が返る。
    #[test]
    fn mvm5_4030_aux_timeout_leaks_memory() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let (a, seen) = aux(Err(MicrovmError::new(
            MicrovmErrorCode::DeadlineExceeded,
            "aux stuck",
        )));
        let stopper = StopWithAux {
            vcpus: responsive(),
            aux: Some(a),
        };
        let e = stop_and_release("test", stopper, LONG, resources(&log)).unwrap_err();
        assert_eq!(e.code(), MicrovmErrorCode::DeadlineExceeded);
        assert!(seen.lock().unwrap().is_some());
        assert_eq!(*log.lock().unwrap(), vec!["devices", "vm"]);
    }

    /// 期限を使い切っていても補助には下限 `AUX_STOP_MIN` が渡る。
    #[test]
    fn repair5_4030_aux_gets_minimum_deadline() {
        let (a, seen) = aux(Ok(StopReason::Requested));
        let stopper = StopWithAux {
            vcpus: responsive(),
            aux: Some(a),
        };
        stopper.stop(Duration::from_nanos(1)).ok();
        assert_eq!(seen.lock().unwrap().unwrap(), AUX_STOP_MIN);
    }

    /// 補助なしは vCPU 単独と同じ結果になる。
    #[test]
    fn mvm5_4030_no_aux_is_same_as_vcpus_alone() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let stopper = StopWithAux::<LoopHandle<FakeKick>, FakeAux> {
            vcpus: responsive(),
            aux: None,
        };
        let r = stop_and_release("test", stopper, LONG, resources(&log)).unwrap();
        assert_eq!(r.reason, StopReason::Requested);
        assert_eq!(*log.lock().unwrap(), vec!["devices", "memory", "vm"]);
    }
}
