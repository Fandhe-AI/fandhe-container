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
//! 3. 期限切れ（`TIMEOUT`）・`Internal` で止まりを確かめられなかったときは、ゲスト RAM を解放せず、手放すだけにする
//!    （[`ReleaseMemory::detach`]）。vCPU スレッドが [`drop_vcpu_thread_state`] で自分の保持（vCPU の破棄 → デバイス参照 →
//!    スロットの clone → VM）を順に落とすと、最後の `Arc` の drop で unmap → munmap、続いて `hv_vm_destroy` が走る（#4032）。
//!    切り離した vCPU スレッドが終わるまでは何も解放されず、終わった後に 1 回ずつ回収される。呼び出し元の契約は、全 vCPU スレッドが
//!    スロットの clone と VM の `Arc` を持ち、vCPU を破棄した後に落とすこと（`hvf::vcpu::ExitHandlers::guest_memory`）。
//!    #4034 の実機確認では、切り離した vCPU スレッドの終了後に `op=hvf.vm_unmap outcome=error` が出ず、同じプロセスで VM を作り直せた
//!    （`hv_vm_destroy` が失敗すると排他を戻さないため、作り直せたことは destroy の成功を意味する。間接の根拠）。回収がそのスレッドの上で
//!    成功したことを直接示す行（`op=hvf.deferred_reclaim`）は #4146 で足した。次の実機確認で照合する。
//!    例外: 補助スレッドの停止を確かめられなかった場合（[`StopOutcome::aux_unconfirmed`]。#4030）は、補助が RAM をまだ触りうるため遅延回収に回さず
//!    RAM をリークする（`mem::forget`）。
//!    例外: `release_devices` の失敗（デバイスの保持者が lock を持つ。期限切れの経路でも手放しの前に確かめ、失敗なら回収に回さない）では、デバイス → RAM → VM の順を強制できないため、従来どおり
//!    RAM をリークする（`mem::forget`）。RAM の取得失敗（`take_within` の期限切れ・毒化）も、vCPU は停止確認済みで lock を持つ
//!    のがホスト側のスレッドのため、`GuestMemorySlot` 側でリークする（別の経路。見直しは本 issue の範囲外）。
//!
//! # 複数 vCPU（#3884）
//! 止まりの確認は「N 台すべてが報告した」こと（`hvf_loop::stop_all`。parked の AP を含む）。1 台でも確かめられなければ RAM を
//! 手放すだけにし、残った vCPU スレッドの終了後に回収する（#4032）。AP の exit（SYSTEM_OFF・fail-closed の停止）は `VcpuSet::is_finished` が VM 全体の終了として伝え、停止時の集約でその理由を返す（#3891）。

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use crate::error::{MicrovmError, MicrovmErrorCode};
use crate::hvf_abi::HvRunStats;
use crate::hvf_loop::{LoopHandle, VCPU_STOP_DEADLINE_MAX, VcpuKick, VcpuSetStopReport, log_line};
use crate::stop::{StopReason, UnmapTally};

/// stop を経ない drop が vCPU スレッドの停止を待つ期限（REPAIR-5。Linux の `DROP_STOP_WAIT` と同値）。
pub const DROP_STOP_DEADLINE: Duration = Duration::from_secs(5);

/// 期限つきで止められる vCPU スレッドの操作口（`LoopHandle` の抽象。単体試験で差し替えるため）。
pub trait VcpuStopper {
    /// 停止を要求し、`deadline` まで終了報告を待つ。`Ok` で戻った時点で vCPU は破棄済みであること。
    fn stop(self, deadline: Duration) -> Result<VcpuSetStopReport, MicrovmError>;

    /// [`VcpuStopper::stop`] に加え、補助スレッドの停止を確かめられなかったか（`aux_unconfirmed`）を返す（#4030・#4032）。
    ///
    /// 補助を持たない実装は既定のまま（常に `false`）。補助の停止が未確認なら、補助がゲスト RAM をまだ触りうるため、
    /// vCPU スレッドの終了後の遅延回収に回さず RAM を解放しない（[`stop_and_release`]）。
    fn stop_detailed(self, deadline: Duration) -> StopOutcome
    where
        Self: Sized,
    {
        StopOutcome {
            result: self.stop(deadline),
            aux_unconfirmed: false,
        }
    }
}

/// [`VcpuStopper::stop_detailed`] の戻り（拡張できる構造）。
#[derive(Debug)]
pub struct StopOutcome {
    /// vCPU 群（と補助）の停止の結果。
    pub result: Result<VcpuSetStopReport, MicrovmError>,
    /// 補助スレッドの停止を確かめられなかった（期限切れ・`Err`）。
    pub aux_unconfirmed: bool,
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
        self.stop_detailed(deadline).result
    }

    /// 補助の停止が `Err` なら `aux_unconfirmed` を立てる（vCPU 側の結果より優先して RAM を解放しない。#4030）。
    fn stop_detailed(self, deadline: Duration) -> StopOutcome {
        let started = std::time::Instant::now();
        let vcpu_result = self.vcpus.stop(deadline);
        let aux_result = self
            .aux
            .map(|a| a.stop(deadline.saturating_sub(started.elapsed()).max(AUX_STOP_MIN)));
        let aux_unconfirmed = matches!(aux_result, Some(Err(_)));
        let result = (|| {
            let mut report = vcpu_result?;
            if let Some(r) = aux_result {
                let reason = r?;
                if report.reason == StopReason::Requested {
                    report.reason = reason;
                }
            }
            Ok(report)
        })();
        StopOutcome {
            result,
            aux_unconfirmed,
        }
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

    /// vCPU の停止を確かめられなかったときに呼ぶ。ゲストが書きうる中身を解放せずに、この参照だけを手放す（#4032）。
    ///
    /// 共有型（`GuestMemorySlot`）は `Arc` を 1 つ減らすだけで、中身は最後の保持者（切り離した vCPU スレッド）の drop で
    /// 1 回だけ解放される。既定実装は持たない（各実装が「中身を解放しない手放し方」を決める）。
    fn detach(self);
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
    /// ゲスト RAM の backing の munmap の失敗件数（VM ごと。観測専用で停止の合否には使わない。MVM-5・REPAIR-4・#4411）。
    /// 正常系では RAM を落とした後の最終値。0 でない場合は backing をリークしている（固定の 1 行 `op=hvf.host_unmap`
    /// も出る）。`hv_vm_unmap` の失敗は含まない（別カウンタの `vm_unmap_failures`。`op=hvf.vm_unmap`）。
    /// ゲストへ対応付ける前の `HostMapping` の失敗も含まない。
    pub unmap_failures: u64,
    /// `hv_vm_unmap` の失敗件数（VM ごと。`sys::hvf::GuestMapping` の drop の経路のみ。観測専用で停止の合否には使わない。
    /// MVM-5・REPAIR-4・#4439）。同じ VM について出た `op=hvf.vm_unmap` の行数と一致し、0 でも集約行の
    /// ` vm_unmap_failures=` に出す。失敗した backing はリークし munmap されないため、`unmap_failures` とは互いに素。
    /// 集約行の時点の値で、期限切れ・遅延回収の経路で後から回収する失敗は含まない（`op=hvf.deferred_reclaim` で観測）。
    pub vm_unmap_failures: u64,
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
    /// munmap の失敗を数える VM ごとの集約先。読むだけで drop 順には関与しない（`unmap_failures=` に出す。#4411）。
    pub unmap: Arc<UnmapTally>,
    /// `hv_vm_unmap` の失敗を数える VM ごとの集約先（`unmap` とは別インスタンス）。読むだけで drop 順には関与しない
    /// （`vm_unmap_failures=` に出す。#4439）。
    pub vm_unmap: Arc<UnmapTally>,
}

/// `sys::hvf::GuestMapping` の drop で `hv_vm_unmap` が失敗したときの記録（固定の 1 行と VM ごとの件数。
/// MVM-5・REPAIR-4・#4032・#4439）。行数と件数を一致させるため、行の出力と加算をここ 1 か所に置く。
/// 呼び出し元は macOS aarch64 の `sys::hvf` だけ（他 OS では単体試験のみ）。
#[cfg_attr(
    not(all(target_os = "macos", target_arch = "aarch64")),
    allow(dead_code)
)]
pub(crate) fn report_vm_unmap_failure(code: MicrovmErrorCode, tally: &UnmapTally) {
    log_line(format_args!(
        "level=error op=hvf.vm_unmap outcome=error code={} leaked=guest_ram",
        code.as_str()
    ));
    tally.record_failure();
}

/// 停止を試み、止まりを確かめられたときだけ資源を devices → memory → vm の順に drop する（モジュール doc の「解放順序」）。
///
/// - `deadline` が 0 または [`VCPU_STOP_DEADLINE_MAX`] 超なら `InvalidArgument`。ただし資源を持ったまま返さず、
///   [`DROP_STOP_DEADLINE`] で同じ手順を行ってからエラーを返す（不正な引数で解放が漏れないように）。
/// - 期限切れ・`Internal` は止まりを確かめられていない。`memory` は [`ReleaseMemory::detach`] で手放し、`devices`・`vm` は drop する
///   （`vm` の `Arc` は切り離した vCPU スレッドと対応付けが保持するため、VM の破棄は起きない）。RAM と VM の回収は、
///   そのスレッドが [`drop_vcpu_thread_state`] で最後の `Arc` を落とした時点で行われる（#4032）。エラーをそのまま返す。
/// - 補助スレッドの停止を確かめられなかった場合（[`StopOutcome::aux_unconfirmed`]）は、vCPU の結果に依らず `memory` をリークする
///   （遅延回収に回さない。補助が RAM を触りうる。#4030）。`devices`・`vm` は drop する。
/// - `release_devices` の失敗は、デバイスの保持者が lock を持ち、デバイスが RAM・VM より後に落ちうる。順序を守れないため
///   `memory` をリークする（`mem::forget`。モジュール doc の例外）。
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
        unmap,
        vm_unmap,
    } = resources;
    // 処理開始時に終了時刻の基準を 1 回だけ取り、vCPU の停止待ちとデバイス解放待ちで同じ期限を共有する（REPAIR-5）。
    let started = std::time::Instant::now();
    let StopOutcome {
        result,
        aux_unconfirmed,
    } = stopper.stop_detailed(effective);
    // `Err` の組の 2 つ目はログの `released=false` 以降。経路ごとに、回収待ち（`deferred`）とリーク（`leaked`）を分ける。
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
                            // 資源を落とした後に下で確定値を入れる。
                            unmap_failures: 0,
                            vm_unmap_failures: 0,
                        })
                    }
                    Err(e) => {
                        // RAM の取得に失敗（`GuestMemorySlot` 側でリーク済み）。
                        drop(vm);
                        Err((e, "leaked=guest_ram,vm"))
                    }
                }
            }
            Err(e) => {
                // デバイス（backend）が dispatcher に残っている。デバイス → RAM → VM の順を守れないため RAM を解放しない。
                drop(devices);
                std::mem::forget(memory);
                drop(vm);
                Err((e, "leaked=guest_ram,vm"))
            }
        },
        Err(e) if aux_unconfirmed => {
            // 補助スレッド（受信ポーラー）の停止を確かめられていない。補助はゲスト RAM をまだ触りうるため、
            // vCPU スレッドの終了後の遅延回収にも回さず RAM を解放しない（#4030 の契約。use-after-free の防止）。
            drop(devices);
            std::mem::forget(memory);
            drop(vm);
            Err((e, "leaked=guest_ram,vm,aux_thread"))
        }
        Err(e) => {
            // 止まりを確かめられていない。ゲストがまだ書けうるメモリを解放せず、参照だけ手放す。
            // 切り離した vCPU スレッドが最後の `Arc` を落としたときに RAM → VM の順で回収される（#4032）。
            // ただしデバイスを手放せたと確かめられたときだけ（devices → RAM → VM の順。MVM-5・REPAIR-5）。dispatcher の保持者が
            // lock を持つなどでデバイスが残る場合は、後で RAM と VM が先に落ちうるため RAM を回収に回さずリークする。
            // 待ちは停止の期限を使い切った後でも [`MEMORY_RELEASE_MIN`] に限る。
            match devices.release_devices(MEMORY_RELEASE_MIN) {
                Ok(()) => {
                    drop(devices);
                    memory.detach();
                    drop(vm);
                    Err((e, "deferred=guest_ram,vm leaked=vcpu_thread"))
                }
                Err(_) => {
                    drop(devices);
                    std::mem::forget(memory);
                    drop(vm);
                    Err((e, "leaked=guest_ram,vm,vcpu_thread"))
                }
            }
        }
    };
    // 全経路の drop を終えた後の値。期限切れ・遅延回収の経路では、切り離した vCPU スレッドが後で回収する RAM の失敗は
    // 含まない（後からの回収は `op=hvf.deferred_reclaim`（munmap の失敗は `failed=host_ram`。#4440）と `op=hvf.host_unmap` で観測。#4411）。
    let unmap_failures = unmap.count();
    let vm_unmap_failures = vm_unmap.count();
    let mut outcome = outcome;
    if let Ok(r) = &mut outcome {
        r.unmap_failures = unmap_failures;
        r.vm_unmap_failures = vm_unmap_failures;
    }
    match &outcome {
        Ok(r) => {
            let (level, result) = match r.reason {
                StopReason::Failed(_) => ("error", "error"),
                _ => ("info", "ok"),
            };
            log_line(format_args!(
                "level={level} op={op} outcome={result} reason={} released=true unmap_failures={unmap_failures} vm_unmap_failures={vm_unmap_failures}",
                r.reason.as_str()
            ));
        }
        Err((e, tail)) => log_line(format_args!(
            "level=error op={op} outcome=error code={} released=false {tail} unmap_failures={unmap_failures} vm_unmap_failures={vm_unmap_failures}",
            e.code().as_str()
        )),
    }
    if invalid {
        return Err(MicrovmError::new(
            MicrovmErrorCode::InvalidArgument,
            "stop deadline must be in (0, 60s]",
        ));
    }
    outcome.map_err(|(e, _)| e)
}

/// 切り離されうる vCPU スレッドが、終了時に自分の保持を決まった順で落とす（#4032・MVM-5・MVM-1・REPAIR-5）。
///
/// 呼び出し元は `hvf::vcpu` の vCPU スレッドの終わり（`spawn_gated` / `spawn_parked_ap`）。vCPU の破棄（`drop(exec)`）は呼び出し元が
/// 先に行う（vCPU は `VmWithGic` を借用するため、VM を渡す前に破棄しないと借用検査が通らない。型で順序が守られる）。親が [`stop_and_release`] で期限切れに
/// なって切り離しても、スレッドが後で自力で終わればここで、vCPU の破棄 →（本関数）デバイスの参照 → ゲスト RAM のスロットの clone → VM の順に
/// 1 回ずつ落ちる。スレッドが最後の保持者なら、スロットの drop で `hv_vm_unmap` → munmap、続く VM の drop で GIC と
/// `hv_vm_destroy` が走る。対応付けが `Arc<HvVm>` を握るため、VM の破棄が unmap より先になることは型で起きない。
///
/// 複数 vCPU でも、各スレッドは「デバイス → スロット」の順に落とすので、最後のスロットの drop は全スレッドのデバイスの drop より後になる。
/// 残余: panic で巻き戻る場合の drop 順は保証しない（`run_loop` の panic は想定外）。回収の成功は、`hvf_loop::spawn_loop` が
/// スレッドの終わりに [`take_thread_reclaim`] で読み、`op=hvf.deferred_reclaim` の行で出す（#4146。実機での照合は人間担当）。
pub fn drop_vcpu_thread_state<H, M, V>(handlers: H, memory: M, vm: V) {
    drop(handlers);
    drop(memory);
    drop(vm);
}

/// このスレッドで実際に起きた `hv_vm_unmap`（ゲスト RAM の解放）・`hv_vm_destroy`（VM の破棄）の結果の記録（#4146・MVM-5・REPAIR-4）。
///
/// 書き手は macOS の `sys::hvf` の drop（`GuestMapping`・`HvVm`）、読み手は `hvf_loop::spawn_loop` のスレッド本体（`body` が戻った後に
/// [`take_thread_reclaim`]）。期限切れで切り離した vCPU スレッドが最後の保持者として回収したときだけ、そのスレッドの記録が埋まる。
/// 通常の `stop` では親のスレッドが回収するので、vCPU スレッドの記録は空のまま終わり、行は出ない。
/// 同じ種類が複数回記録されたときは `Err` を優先し、最初の `Err` を残す。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ThreadReclaim {
    /// このスレッドで実行した `hv_vm_unmap` の結果。
    pub guest_ram: Option<Result<(), MicrovmErrorCode>>,
    /// このスレッドで実行した backing の munmap の結果（#4440）。書き手は `sys::hvf::HostMapping` の drop で、VM へ対応付けた
    /// backing だけを記録する（`hv_vm_unmap` が成功した後に走るため、`guest_ram` の `Ok` と対になる。対応付け前の backing は対象外）。
    /// 試験専用の明示 `GuestMapping::unmap()` の経路では `guest_ram` は記録されず `host_ram` だけが記録される（製品の vCPU スレッドでは使わない）。
    pub host_ram: Option<Result<(), MicrovmErrorCode>>,
    /// このスレッドで実行した `hv_vm_destroy` の結果。
    pub vm: Option<Result<(), MicrovmErrorCode>>,
}

thread_local! {
    static THREAD_RECLAIM: std::cell::Cell<ThreadReclaim> = const {
        std::cell::Cell::new(ThreadReclaim { guest_ram: None, host_ram: None, vm: None })
    };
}

fn merge_result(
    old: Option<Result<(), MicrovmErrorCode>>,
    new: Result<(), MicrovmErrorCode>,
) -> Option<Result<(), MicrovmErrorCode>> {
    match old {
        Some(Err(e)) => Some(Err(e)),
        _ => Some(new),
    }
}

/// 呼び出しスレッドで `hv_vm_unmap` を実行した結果を記録する（`sys::hvf::GuestMapping` の drop から。#4146）。
/// スレッドローカルの破棄中は何も記録しない（drop の中で panic させない）。
pub fn record_guest_ram_unmap(r: Result<(), MicrovmErrorCode>) {
    let _ = THREAD_RECLAIM.try_with(|c| {
        let mut v = c.get();
        v.guest_ram = merge_result(v.guest_ram, r);
        c.set(v);
    });
}

/// 呼び出しスレッドで backing の munmap を実行した結果を記録する（`sys::hvf::HostMapping` の drop から。#4440・MVM-5・REPAIR-4）。
/// スレッドローカルの破棄中は何も記録しない（drop の中で panic させない）。
pub fn record_host_ram_unmap(r: Result<(), MicrovmErrorCode>) {
    let _ = THREAD_RECLAIM.try_with(|c| {
        let mut v = c.get();
        v.host_ram = merge_result(v.host_ram, r);
        c.set(v);
    });
}

/// 呼び出しスレッドで `hv_vm_destroy` を実行した結果を記録する（`sys::hvf::HvVm` の drop から。#4146）。
pub fn record_vm_destroy(r: Result<(), MicrovmErrorCode>) {
    let _ = THREAD_RECLAIM.try_with(|c| {
        let mut v = c.get();
        v.vm = merge_result(v.vm, r);
        c.set(v);
    });
}

/// 呼び出しスレッドの記録を取り出して空に戻す（`hvf_loop::spawn_loop` のスレッド本体から。#4146）。
pub fn take_thread_reclaim() -> ThreadReclaim {
    THREAD_RECLAIM
        .try_with(|c| c.replace(ThreadReclaim::default()))
        .unwrap_or_default()
}

/// 遅延回収の記録を 1 行にする（#4146・MVM-5・REPAIR-4）。記録が空なら `None`（行を出さない）。
///
/// 成功は `level=info op=hvf.deferred_reclaim outcome=ok thread=<name> released=guest_ram,host_ram,vm`（実行した分だけ並べる）。
/// 1 つでも失敗していれば `level=error ... outcome=error` で、成功した名前を `released=`、失敗した名前を `failed=`、最初の失敗の
/// コードを `code=` に出す。名前の並びは常に `guest_ram`、`host_ram`、`vm` の順（実際の解放順 `hv_vm_unmap` → munmap → `hv_vm_destroy`。#4440）。
/// `hv_vm_unmap` が失敗すると munmap は走らないため、`guest_ram` と `host_ram` の失敗は同時には起きない。
pub fn deferred_reclaim_line(thread: &str, r: ThreadReclaim) -> Option<String> {
    if r.guest_ram.is_none() && r.host_ram.is_none() && r.vm.is_none() {
        return None;
    }
    let mut released: Vec<&str> = Vec::new();
    let mut failed: Vec<&str> = Vec::new();
    let mut code: Option<MicrovmErrorCode> = None;
    for (name, res) in [
        ("guest_ram", r.guest_ram),
        ("host_ram", r.host_ram),
        ("vm", r.vm),
    ] {
        match res {
            Some(Ok(())) => released.push(name),
            Some(Err(e)) => {
                failed.push(name);
                code.get_or_insert(e);
            }
            None => {}
        }
    }
    Some(match code {
        None => format!(
            "level=info op=hvf.deferred_reclaim outcome=ok thread={thread} released={}",
            released.join(",")
        ),
        Some(c) => {
            let rel = if released.is_empty() {
                String::new()
            } else {
                format!(" released={}", released.join(","))
            };
            format!(
                "level=error op=hvf.deferred_reclaim outcome=error thread={thread}{rel} failed={} code={}",
                failed.join(","),
                c.as_str()
            )
        }
    })
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

        fn detach(self) {
            drop(self);
        }
    }

    /// `GuestMemorySlot` の模擬。clone は `Arc` の複製で、中身（`Rec`）は最後の `Arc` の drop か `release_memory` の取り出しで
    /// 1 回だけ drop される。
    #[derive(Clone)]
    struct SharedRam(Arc<Mutex<Option<Rec>>>);

    impl SharedRam {
        fn new(log: &Arc<Mutex<Vec<&'static str>>>) -> Self {
            Self(Arc::new(Mutex::new(Some(Rec("memory", Arc::clone(log))))))
        }

        /// 解放時に munmap だけ失敗する模擬（#4440）。
        fn with_munmap_failure(log: &Arc<Mutex<Vec<&'static str>>>) -> Self {
            Self(Arc::new(Mutex::new(Some(Rec(
                "memory_munmap_fails",
                Arc::clone(log),
            )))))
        }
    }

    impl ReleaseMemory for SharedRam {
        fn release_memory(self, _deadline: Duration) -> Result<(), MicrovmError> {
            let taken = self.0.lock().unwrap().take();
            drop(taken);
            Ok(())
        }

        fn detach(self) {
            drop(self);
        }
    }

    fn snapshot(log: &Arc<Mutex<Vec<&'static str>>>) -> Vec<&'static str> {
        log.lock().unwrap().clone()
    }

    /// 親が期限切れで切り離した vCPU スレッド。`release_rx` が解かれるまで返らず、返る前に
    /// `exec` の破棄の後に [`drop_vcpu_thread_state`] で `handlers` → `ram` の clone → `vm` の clone を落とし、`done_tx` に知らせる。
    fn detached_vcpu(
        log: &Arc<Mutex<Vec<&'static str>>>,
        ram: SharedRam,
        vm: Arc<Rec>,
        release_rx: mpsc::Receiver<()>,
        done_tx: mpsc::Sender<()>,
    ) -> LoopHandle<FakeKick> {
        let log = Arc::clone(log);
        spawn_loop::<FakeKick, _>("hvf-test", LONG, move |start: LoopStart<FakeKick>| {
            let _stop = start.ready(FakeKick);
            // 停止フラグを無視して、解除されるまで返らない。
            let _ = release_rx.recv();
            drop(Rec("exec", Arc::clone(&log)));
            drop_vcpu_thread_state(Rec("handlers", log), ram, vm);
            let _ = done_tx.send(());
            (StopReason::Requested, HvRunStats::default())
        })
        .unwrap()
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
            // 実際の drop で起きる解放の記録の模擬（`sys::hvf` の drop と同じ呼び出し。#4146）。
            match self.0 {
                "memory" => {
                    record_guest_ram_unmap(Ok(()));
                    record_host_ram_unmap(Ok(()));
                }
                // munmap だけ失敗する場合の注入（#4440）。
                "memory_munmap_fails" => {
                    record_guest_ram_unmap(Ok(()));
                    record_host_ram_unmap(Err(MicrovmErrorCode::Internal));
                }
                "vm" => record_vm_destroy(Ok(())),
                _ => {}
            }
        }
    }

    fn resources(log: &Arc<Mutex<Vec<&'static str>>>) -> Resources<Rec, Rec, Rec> {
        Resources {
            devices: Rec("devices", Arc::clone(log)),
            memory: Rec("memory", Arc::clone(log)),
            vm: Rec("vm", Arc::clone(log)),
            unmap: Arc::default(),
            vm_unmap: Arc::default(),
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

    /// MVM-5・MVM-1・#4032: [`drop_vcpu_thread_state`] は handlers → memory → vm の順に 1 回ずつ落とす。
    #[test]
    fn mvm5_4032_vcpu_thread_state_drop_order() {
        let log = Arc::new(Mutex::new(Vec::new()));
        drop_vcpu_thread_state(
            Rec("handlers", Arc::clone(&log)),
            Rec("memory", Arc::clone(&log)),
            Rec("vm", Arc::clone(&log)),
        );
        assert_eq!(snapshot(&log), vec!["handlers", "memory", "vm"]);
    }

    /// REPAIR-5・MVM-5・MVM-1・#4032（旧 #3798）: 応答しない vCPU スレッドへの停止は `TIMEOUT` になる。その時点では何も解放されず
    /// （RAM と VM は切り離したスレッドが持つ）、スレッドが後で終わると vCPU → デバイス参照 → RAM → VM の順に 1 回ずつ回収される。
    #[test]
    fn repair5_mvm5_4032_timeout_reclaims_after_vcpu_ends_in_order() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let ram = SharedRam::new(&log);
        let vm = Arc::new(Rec("vm", Arc::clone(&log)));
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let (done_tx, done_rx) = mpsc::channel::<()>();
        let h = detached_vcpu(&log, ram.clone(), Arc::clone(&vm), release_rx, done_tx);
        let r = Resources {
            devices: Rec("devices", Arc::clone(&log)),
            memory: ram,
            vm,
            unmap: Arc::default(),
            vm_unmap: Arc::default(),
        };
        let e = stop_and_release("hvf.microvm.stop", h, Duration::from_millis(50), r).unwrap_err();
        assert_eq!(e.code(), MicrovmErrorCode::DeadlineExceeded);
        assert_eq!(e.code().as_str(), "TIMEOUT");
        // 親が手放したのはデバイスと自分の参照だけ。RAM・VM は vCPU スレッドが終わるまで解放されない。
        assert_eq!(snapshot(&log), vec!["devices"]);
        std::thread::sleep(Duration::from_millis(50));
        assert_eq!(snapshot(&log), vec!["devices"]);
        release_tx.send(()).unwrap();
        done_rx.recv_timeout(LONG).unwrap();
        assert_eq!(
            snapshot(&log),
            vec!["devices", "exec", "handlers", "memory", "vm"]
        );
    }

    /// MVM-5・MVM-1・#4032: 通常の停止では vCPU スレッドの clone が先に落ち、RAM と VM は stop が 1 回だけ解放する（二重 drop なし）。
    #[test]
    fn mvm5_4032_normal_stop_drops_each_once() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let ram = SharedRam::new(&log);
        let vm = Arc::new(Rec("vm", Arc::clone(&log)));
        let (ram_t, vm_t, log_t) = (ram.clone(), Arc::clone(&vm), Arc::clone(&log));
        let h = spawn_loop::<FakeKick, _>("hvf-test", LONG, move |start: LoopStart<FakeKick>| {
            let stop = start.ready(FakeKick);
            while !stop.load(Ordering::Acquire) {
                std::thread::sleep(Duration::from_millis(1));
            }
            drop(Rec("exec", Arc::clone(&log_t)));
            drop_vcpu_thread_state(Rec("handlers", log_t), ram_t, vm_t);
            (StopReason::Requested, HvRunStats::default())
        })
        .unwrap();
        let r = Resources {
            devices: Rec("devices", Arc::clone(&log)),
            memory: ram.clone(),
            vm,
            unmap: Arc::default(),
            vm_unmap: Arc::default(),
        };
        stop_and_release("hvf.microvm.stop", h, LONG, r).unwrap();
        assert_eq!(
            snapshot(&log),
            vec!["exec", "handlers", "devices", "memory", "vm"]
        );
        // 残りの clone を落としても増えない（中身は取り出し済み）。
        drop(ram);
        assert_eq!(snapshot(&log).len(), 5);
    }

    /// REPAIR-4・MVM-5・#4146: 遅延回収の行は固定語彙で、空なら出ない。
    #[test]
    fn repair4_mvm5_4146_deferred_reclaim_line_formats() {
        let ok = Some(Ok(()));
        let line = |g, v| {
            deferred_reclaim_line(
                "hvf-vcpu-0",
                ThreadReclaim {
                    guest_ram: g,
                    host_ram: None,
                    vm: v,
                },
            )
        };
        let line3 = |g, h, v| {
            deferred_reclaim_line(
                "hvf-vcpu-0",
                ThreadReclaim {
                    guest_ram: g,
                    host_ram: h,
                    vm: v,
                },
            )
        };
        assert_eq!(line(None, None), None);
        assert_eq!(line3(None, None, None), None);
        assert_eq!(
            line3(ok, ok, ok).as_deref(),
            Some(
                "level=info op=hvf.deferred_reclaim outcome=ok thread=hvf-vcpu-0 released=guest_ram,host_ram,vm"
            )
        );
        assert_eq!(
            line3(None, ok, None).as_deref(),
            Some(
                "level=info op=hvf.deferred_reclaim outcome=ok thread=hvf-vcpu-0 released=host_ram"
            )
        );
        assert_eq!(
            line3(ok, Some(Err(MicrovmErrorCode::Internal)), ok).as_deref(),
            Some(
                "level=error op=hvf.deferred_reclaim outcome=error thread=hvf-vcpu-0 released=guest_ram,vm failed=host_ram code=INTERNAL"
            )
        );
        assert_eq!(
            line(ok, ok).as_deref(),
            Some(
                "level=info op=hvf.deferred_reclaim outcome=ok thread=hvf-vcpu-0 released=guest_ram,vm"
            )
        );
        assert_eq!(
            line(ok, None).as_deref(),
            Some(
                "level=info op=hvf.deferred_reclaim outcome=ok thread=hvf-vcpu-0 released=guest_ram"
            )
        );
        assert_eq!(
            line(None, ok).as_deref(),
            Some("level=info op=hvf.deferred_reclaim outcome=ok thread=hvf-vcpu-0 released=vm")
        );
        assert_eq!(
            line(ok, Some(Err(MicrovmErrorCode::Internal))).as_deref(),
            Some(
                "level=error op=hvf.deferred_reclaim outcome=error thread=hvf-vcpu-0 released=guest_ram failed=vm code=INTERNAL"
            )
        );
        assert_eq!(
            line(Some(Err(MicrovmErrorCode::Internal)), None).as_deref(),
            Some(
                "level=error op=hvf.deferred_reclaim outcome=error thread=hvf-vcpu-0 failed=guest_ram code=INTERNAL"
            )
        );
    }

    /// REPAIR-4・MVM-5・#4146: take は記録を空に戻し、同じ種類の記録は `Err` が残る。
    #[test]
    fn repair4_mvm5_4146_thread_reclaim_take_resets_and_prefers_err() {
        let _ = take_thread_reclaim();
        record_guest_ram_unmap(Ok(()));
        record_guest_ram_unmap(Err(MicrovmErrorCode::Internal));
        record_guest_ram_unmap(Ok(()));
        record_host_ram_unmap(Ok(()));
        record_host_ram_unmap(Err(MicrovmErrorCode::Internal));
        record_host_ram_unmap(Ok(()));
        record_vm_destroy(Ok(()));
        assert_eq!(
            take_thread_reclaim(),
            ThreadReclaim {
                guest_ram: Some(Err(MicrovmErrorCode::Internal)),
                host_ram: Some(Err(MicrovmErrorCode::Internal)),
                vm: Some(Ok(())),
            }
        );
        assert_eq!(take_thread_reclaim(), ThreadReclaim::default());
    }

    /// MVM-5・REPAIR-4・#4146: 期限切れで切り離した vCPU スレッドが最後の保持者として回収したとき、そのスレッドの記録に
    /// unmap と destroy の成功が残り、行になる。
    #[test]
    fn mvm5_repair4_4146_deferred_reclaim_recorded_on_vcpu_thread() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let ram = SharedRam::new(&log);
        let vm = Arc::new(Rec("vm", Arc::clone(&log)));
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let (rec_tx, rec_rx) = mpsc::channel::<ThreadReclaim>();
        let (ram_t, vm_t, log_t) = (ram.clone(), Arc::clone(&vm), Arc::clone(&log));
        let h = spawn_loop::<FakeKick, _>("hvf-test", LONG, move |start: LoopStart<FakeKick>| {
            let _stop = start.ready(FakeKick);
            let _ = release_rx.recv();
            drop_vcpu_thread_state(Rec("handlers", log_t), ram_t, vm_t);
            let _ = rec_tx.send(take_thread_reclaim());
            (StopReason::Requested, HvRunStats::default())
        })
        .unwrap();
        let r = Resources {
            devices: Rec("devices", Arc::clone(&log)),
            memory: ram,
            vm,
            unmap: Arc::default(),
            vm_unmap: Arc::default(),
        };
        let _ = take_thread_reclaim();
        let e = stop_and_release("hvf.microvm.stop", h, Duration::from_millis(50), r).unwrap_err();
        assert_eq!(e.code(), MicrovmErrorCode::DeadlineExceeded);
        // 親のスレッドでは何も回収していない。
        assert_eq!(take_thread_reclaim(), ThreadReclaim::default());
        release_tx.send(()).unwrap();
        let rec = rec_rx.recv_timeout(LONG).unwrap();
        assert_eq!(
            rec,
            ThreadReclaim {
                guest_ram: Some(Ok(())),
                host_ram: Some(Ok(())),
                vm: Some(Ok(())),
            }
        );
        assert_eq!(
            deferred_reclaim_line("hvf-test", rec).as_deref(),
            Some(
                "level=info op=hvf.deferred_reclaim outcome=ok thread=hvf-test released=guest_ram,host_ram,vm"
            )
        );
    }

    /// MVM-5・REPAIR-4・#4440: 遅延回収で munmap が失敗すると、vCPU スレッドの記録に `host_ram` の `Err` が残り、
    /// 行が `outcome=error`・`failed=host_ram` になる。親のスレッドは何も記録しない。
    #[test]
    fn mvm5_repair4_4440_deferred_reclaim_reports_munmap_failure() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let ram = SharedRam::with_munmap_failure(&log);
        let vm = Arc::new(Rec("vm", Arc::clone(&log)));
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let (rec_tx, rec_rx) = mpsc::channel::<ThreadReclaim>();
        let (ram_t, vm_t, log_t) = (ram.clone(), Arc::clone(&vm), Arc::clone(&log));
        let h = spawn_loop::<FakeKick, _>("hvf-test", LONG, move |start: LoopStart<FakeKick>| {
            let _stop = start.ready(FakeKick);
            let _ = release_rx.recv();
            drop_vcpu_thread_state(Rec("handlers", log_t), ram_t, vm_t);
            let _ = rec_tx.send(take_thread_reclaim());
            (StopReason::Requested, HvRunStats::default())
        })
        .unwrap();
        let r = Resources {
            devices: Rec("devices", Arc::clone(&log)),
            memory: ram,
            vm,
            unmap: Arc::default(),
            vm_unmap: Arc::default(),
        };
        let _ = take_thread_reclaim();
        let e = stop_and_release("hvf.microvm.stop", h, Duration::from_millis(50), r).unwrap_err();
        assert_eq!(e.code(), MicrovmErrorCode::DeadlineExceeded);
        assert_eq!(take_thread_reclaim(), ThreadReclaim::default());
        release_tx.send(()).unwrap();
        let rec = rec_rx.recv_timeout(LONG).unwrap();
        assert_eq!(
            rec,
            ThreadReclaim {
                guest_ram: Some(Ok(())),
                host_ram: Some(Err(MicrovmErrorCode::Internal)),
                vm: Some(Ok(())),
            }
        );
        assert_eq!(
            deferred_reclaim_line("hvf-test", rec).as_deref(),
            Some(
                "level=error op=hvf.deferred_reclaim outcome=error thread=hvf-test released=guest_ram,vm failed=host_ram code=INTERNAL"
            )
        );
    }

    /// MVM-5・REPAIR-4・#4146: 通常の停止では vCPU スレッドの記録は空のままで（行が出ない）、回収は親のスレッドで起きる。
    #[test]
    fn mvm5_repair4_4146_normal_stop_records_nothing_on_vcpu_thread() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let ram = SharedRam::new(&log);
        let vm = Arc::new(Rec("vm", Arc::clone(&log)));
        let (ram_t, vm_t, log_t) = (ram.clone(), Arc::clone(&vm), Arc::clone(&log));
        let (rec_tx, rec_rx) = mpsc::channel::<ThreadReclaim>();
        let h = spawn_loop::<FakeKick, _>("hvf-test", LONG, move |start: LoopStart<FakeKick>| {
            let stop = start.ready(FakeKick);
            while !stop.load(Ordering::Acquire) {
                std::thread::sleep(Duration::from_millis(1));
            }
            drop_vcpu_thread_state(Rec("handlers", log_t), ram_t, vm_t);
            let _ = rec_tx.send(take_thread_reclaim());
            (StopReason::Requested, HvRunStats::default())
        })
        .unwrap();
        let r = Resources {
            devices: Rec("devices", Arc::clone(&log)),
            memory: ram,
            vm,
            unmap: Arc::default(),
            vm_unmap: Arc::default(),
        };
        let _ = take_thread_reclaim();
        stop_and_release("hvf.microvm.stop", h, LONG, r).unwrap();
        let vcpu_side = rec_rx.recv_timeout(LONG).unwrap();
        assert_eq!(vcpu_side, ThreadReclaim::default());
        assert_eq!(deferred_reclaim_line("hvf-test", vcpu_side), None);
        assert_eq!(
            take_thread_reclaim(),
            ThreadReclaim {
                guest_ram: Some(Ok(())),
                host_ram: Some(Ok(())),
                vm: Some(Ok(())),
            }
        );
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
            unmap: Arc::default(),
            vm_unmap: Arc::default(),
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
            unmap: Arc::default(),
            vm_unmap: Arc::default(),
        };
        let e = stop_and_release("hvf.microvm.stop", responsive(), LONG, r).unwrap_err();
        assert_eq!(e.code(), MicrovmErrorCode::DeadlineExceeded);
        assert_eq!(*log.lock().unwrap(), vec!["devices", "vm"]);
    }

    /// REPAIR-5・MVM-5・#4032: 止まりを確かめられなくても、デバイスを手放せなければ RAM を回収に回さない（リーク）。
    /// 後で切り離したスレッドが終わっても RAM（`SharedRam` の中身）は drop されない。
    #[test]
    fn repair5_mvm5_4032_timeout_with_stuck_devices_leaks_memory() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let ram = SharedRam::new(&log);
        let vm = Arc::new(Rec("vm", Arc::clone(&log)));
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let (done_tx, done_rx) = mpsc::channel::<()>();
        let stuck = detached_vcpu(&log, ram.clone(), Arc::clone(&vm), release_rx, done_tx);
        let r = Resources {
            devices: StuckDevices(Rec("devices", Arc::clone(&log))),
            memory: ram,
            vm,
            unmap: Arc::default(),
            vm_unmap: Arc::default(),
        };
        let e = stop_and_release(
            "hvf.microvm.stop",
            Set(vec![stuck]),
            Duration::from_millis(100),
            r,
        )
        .unwrap_err();
        assert_eq!(e.code(), MicrovmErrorCode::DeadlineExceeded);
        release_tx.send(()).unwrap();
        done_rx.recv_timeout(LONG).unwrap();
        let seen = snapshot(&log);
        assert!(!seen.contains(&"memory"), "RAM must be leaked: {seen:?}");
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

    /// REPAIR-5・MVM-5・#3884・#4032: 1 台でも止まりを確かめられなければ RAM を解放しない。devices と vm の手放しだけが起き、
    /// 止まらなかった vCPU スレッドが終わると RAM と VM が回収される。
    #[test]
    fn repair5_mvm5_3884_one_stuck_vcpu_defers_memory_to_its_thread() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let ram = SharedRam::new(&log);
        let vm = Arc::new(Rec("vm", Arc::clone(&log)));
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let (done_tx, done_rx) = mpsc::channel::<()>();
        let stuck = detached_vcpu(&log, ram.clone(), Arc::clone(&vm), release_rx, done_tx);
        let set = Set(vec![responsive(), parked(), stuck]);
        let r = Resources {
            devices: Rec("devices", Arc::clone(&log)),
            memory: ram,
            vm,
            unmap: Arc::default(),
            vm_unmap: Arc::default(),
        };
        let e =
            stop_and_release("hvf.microvm.stop", set, Duration::from_millis(100), r).unwrap_err();
        assert_eq!(e.code(), MicrovmErrorCode::DeadlineExceeded);
        assert_eq!(snapshot(&log), vec!["devices"]);
        release_tx.send(()).unwrap();
        done_rx.recv_timeout(LONG).unwrap();
        assert_eq!(
            snapshot(&log),
            vec!["devices", "exec", "handlers", "memory", "vm"]
        );
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
            unmap: Arc::default(),
            vm_unmap: Arc::default(),
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

    /// 解放の中で munmap の失敗を `n` 件数える RAM の模擬（`HostMapping` の drop の代役。#4411）。
    struct FailingRam(Arc<UnmapTally>, u32);

    impl ReleaseMemory for FailingRam {
        fn release_memory(self, _deadline: Duration) -> Result<(), MicrovmError> {
            for _ in 0..self.1 {
                self.0.record_failure();
            }
            Ok(())
        }

        fn detach(self) {}
    }

    /// 停止の集約行（`op=hvf.microvm.stop` の行だけ）を捕捉して返す。
    fn stop_lines(
        r: Resources<Rec, FailingRam, Rec>,
    ) -> (Result<HvfStopReport, MicrovmError>, Vec<String>) {
        crate::hvf_loop::capture_log_lines(|| {
            stop_and_release("hvf.microvm.stop", responsive(), LONG, r)
        })
    }

    /// MVM-5・REPAIR-4・#4411: munmap の失敗件数が `HvfStopReport` と集約行の `unmap_failures=` に具体値で一致する。
    /// 失敗なしの対照は 0（0 でも省かない）。
    #[test]
    fn mvm5_4411_unmap_failures_reach_stop_report_and_line() {
        for (n, want) in [(2u32, 2u64), (0, 0)] {
            let log = Arc::new(Mutex::new(Vec::new()));
            let tally = Arc::new(UnmapTally::default());
            let r = Resources {
                devices: Rec("devices", Arc::clone(&log)),
                memory: FailingRam(Arc::clone(&tally), n),
                vm: Rec("vm", Arc::clone(&log)),
                unmap: tally,
                vm_unmap: Arc::default(),
            };
            let (res, lines) = stop_lines(r);
            let rep = res.unwrap();
            assert_eq!(rep.unmap_failures, want);
            assert_eq!(rep.vm_unmap_failures, 0);
            let own: Vec<_> = lines
                .iter()
                .filter(|l| l.contains("op=hvf.microvm.stop"))
                .collect();
            assert_eq!(
                own,
                vec![&format!(
                    "level=info op=hvf.microvm.stop outcome=ok reason=requested released=true unmap_failures={want} vm_unmap_failures=0"
                )]
            );
        }
    }

    /// MVM-5・REPAIR-4・#4411: 異常系（`outcome=error`）の集約行にも `unmap_failures=` が出る。
    #[test]
    fn mvm5_4411_error_line_carries_unmap_failures() {
        for want in [1u64, 0] {
            let log = Arc::new(Mutex::new(Vec::new()));
            let tally = Arc::new(UnmapTally::default());
            for _ in 0..want {
                tally.record_failure();
            }
            let r = Resources {
                devices: StuckDevices(Rec("devices", Arc::clone(&log))),
                memory: Rec("memory", Arc::clone(&log)),
                vm: Rec("vm", Arc::clone(&log)),
                unmap: tally,
                vm_unmap: Arc::default(),
            };
            let (res, lines) = crate::hvf_loop::capture_log_lines(|| {
                stop_and_release("hvf.microvm.stop", responsive(), LONG, r)
            });
            assert!(res.is_err());
            let own: Vec<_> = lines
                .iter()
                .filter(|l| l.contains("op=hvf.microvm.stop"))
                .collect();
            assert_eq!(
                own,
                vec![&format!(
                    "level=error op=hvf.microvm.stop outcome=error code=TIMEOUT released=false leaked=guest_ram,vm unmap_failures={want} vm_unmap_failures=0"
                )]
            );
        }
    }

    /// 解放の中で `hv_vm_unmap` の失敗を `n` 件数える RAM の模擬（`GuestMapping` の drop の代役。製品と同じ
    /// [`report_vm_unmap_failure`] を通す。#4439）。
    struct VmUnmapFailingRam(Arc<UnmapTally>, u32);

    impl ReleaseMemory for VmUnmapFailingRam {
        fn release_memory(self, _deadline: Duration) -> Result<(), MicrovmError> {
            for _ in 0..self.1 {
                report_vm_unmap_failure(MicrovmErrorCode::Internal, &self.0);
            }
            Ok(())
        }

        fn detach(self) {}
    }

    fn vm_unmap_res(
        n: u32,
        unmap: &Arc<UnmapTally>,
        vm_unmap: &Arc<UnmapTally>,
    ) -> Resources<Rec, VmUnmapFailingRam, Rec> {
        let log = Arc::new(Mutex::new(Vec::new()));
        Resources {
            devices: Rec("devices", Arc::clone(&log)),
            memory: VmUnmapFailingRam(Arc::clone(vm_unmap), n),
            vm: Rec("vm", log),
            unmap: Arc::clone(unmap),
            vm_unmap: Arc::clone(vm_unmap),
        }
    }

    /// MVM-5・REPAIR-4・#4439: `hv_vm_unmap` の失敗件数が報告と集約行（stop・drop の両 op）の ` vm_unmap_failures=` に
    /// 具体値で一致し、`op=hvf.vm_unmap` の行数とも一致する。`unmap_failures` は 0 のまま。
    #[test]
    fn mvm5_4439_vm_unmap_failures_reach_stop_report_and_line() {
        for op in ["hvf.microvm.stop", "hvf.microvm.drop"] {
            for (n, want) in [(1u32, 1u64), (0, 0)] {
                let unmap = Arc::new(UnmapTally::default());
                let vm_unmap = Arc::new(UnmapTally::default());
                let r = vm_unmap_res(n, &unmap, &vm_unmap);
                let (res, lines) = crate::hvf_loop::capture_log_lines(|| {
                    stop_and_release(op, responsive(), LONG, r)
                });
                let rep = res.unwrap();
                assert_eq!(rep.vm_unmap_failures, want);
                assert_eq!(rep.unmap_failures, 0);
                assert_eq!(unmap.count(), 0);
                let own: Vec<_> = lines.iter().filter(|l| l.contains(op)).collect();
                assert_eq!(
                    own,
                    vec![&format!(
                        "level=info op={op} outcome=ok reason=requested released=true unmap_failures=0 vm_unmap_failures={want}"
                    )]
                );
                let vm_lines: Vec<_> = lines
                    .iter()
                    .filter(|l| l.contains("op=hvf.vm_unmap"))
                    .collect();
                assert_eq!(vm_lines.len() as u64, want);
                for l in vm_lines {
                    assert_eq!(
                        l,
                        "level=error op=hvf.vm_unmap outcome=error code=INTERNAL leaked=guest_ram"
                    );
                }
            }
        }
    }

    /// MVM-5・REPAIR-4・#4439: 異常系の集約行にも ` vm_unmap_failures=` が出る。
    #[test]
    fn mvm5_4439_error_line_carries_vm_unmap_failures() {
        for want in [1u64, 0] {
            let log = Arc::new(Mutex::new(Vec::new()));
            let vm_unmap = Arc::new(UnmapTally::default());
            for _ in 0..want {
                vm_unmap.record_failure();
            }
            let r = Resources {
                devices: StuckDevices(Rec("devices", Arc::clone(&log))),
                memory: Rec("memory", Arc::clone(&log)),
                vm: Rec("vm", Arc::clone(&log)),
                unmap: Arc::default(),
                vm_unmap,
            };
            let (res, lines) = crate::hvf_loop::capture_log_lines(|| {
                stop_and_release("hvf.microvm.stop", responsive(), LONG, r)
            });
            assert!(res.is_err());
            let own: Vec<_> = lines
                .iter()
                .filter(|l| l.contains("op=hvf.microvm.stop"))
                .collect();
            assert_eq!(
                own,
                vec![&format!(
                    "level=error op=hvf.microvm.stop outcome=error code=TIMEOUT released=false leaked=guest_ram,vm unmap_failures=0 vm_unmap_failures={want}"
                )]
            );
        }
    }

    /// MVM-5・REPAIR-4・#4439: 記録関数は固定の 1 行を出して件数を 1 つ増やす。
    #[test]
    fn mvm5_4439_report_vm_unmap_failure_emits_line_and_counts() {
        let tally = UnmapTally::default();
        let ((), lines) = crate::hvf_loop::capture_log_lines(|| {
            report_vm_unmap_failure(MicrovmErrorCode::Internal, &tally);
            report_vm_unmap_failure(MicrovmErrorCode::Internal, &tally);
        });
        assert_eq!(tally.count(), 2);
        assert_eq!(
            lines,
            vec![
                "level=error op=hvf.vm_unmap outcome=error code=INTERNAL leaked=guest_ram"
                    .to_string();
                2
            ]
        );
    }
}
