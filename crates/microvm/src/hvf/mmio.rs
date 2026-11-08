//! MMIO（ISV=1 の data abort）の exit 処理（TASK-192.10・#3793・MVM-5・MVM-1・MVM-4）。
//!
//! 役割: `hvf::vcpu` の実行ループが分類した data abort を、Linux 版と共有する `ExitDispatcher`（virtio-mmio の
//! デバイスモデル）へ渡す入口。復号済みの [`DataAbort`] と IPA から `VcpuExit::Mmio` を作り（変換規則は OS 非依存の
//! `crate::mmio_abort`）、読み出しの応答を `SRT` の汎用レジスタへ書き戻し、PC を進める。
//! シグネチャは `hvf::vcpu` との契約で変えない。
//!
//! # 契約
//! - PC を進める責務はここにある（data abort は faulting 命令自身を指すため、ESR の IL の分だけ進める）。
//! - どのデバイスにも当たらないアクセスは Linux 版と同じく続行する（読み出しは全バイト 0xFF、書き込みは捨てる）。
//!   実装前（#3791 時点）の doc の「窓の外は `Failed` で止める」は #3793 の要件で上書きした。回数は [`MmioHandler::unhandled_count`] で観測する。
//! - stage 1 のページテーブル引き中の fault（`s1ptw`）と translation fault 以外（permission fault 等）は MMIO として扱わず
//!   fail-closed で止める（`mmio_abort::ensure_mmio_fault`）。
//! - ゲスト由来のアドレス・値は信頼しない。長さは SAS で 1..=8 に限られ、dispatcher も再検査する。
//!
//! # 実機で確かめた前提（#3803）
//! - Hypervisor.framework は例外 exit で PC を自動では進めない。data abort の exit 時点の PC は faulting 命令を指していた。
//! - `HvVcpuExitException.physical_address` は下位ビットを含む完全な IPA である。窓 + 4 への書き込みの exit で確かめた
//!   （`hvf_device_spi_reaches_guest` の準備完了の書き込み）。
//!
//! # 未実装（REPAIR-3）
//! - `InterruptACK` の後処理（level 扱いの SPI の deassert / resample。#3863）は [`MmioHandler::with_ack_routes`] で結ぶ。
//!   route の無いデバイスは回数（[`MmioHandler::interrupt_ack_count`]）だけ数えて続行する。後処理の結果（deassert / 上げ直しの回数）は
//!   [`MmioHandler::with_ack_tallies`] の共有計数で外から読める（観測専用。`DeviceReset` の resample は別の項目 `resets` に数える。#4014・#4170）。
//! - route の無いデバイスは `QueueNotify` を数えて [`MmioHandler::last_queue_notify`] に残すだけで、キューは処理せず続行する。
//!   virtio-block（#4028）と virtio-net（#4029）は [`MmioHandler::with_queue_notify_routes`] で結んだ route が処理する
//!   （失敗は VM を止める）。net のホスト側の到着を契機にした受信は #4030。
//! - ゲストが big-endian（`SCTLR_EL1.EE` / `E0E`）の場合は扱わない（little-endian 固定）。

use crate::dispatch::{DeviceId, DispatchOutcome, ExitDispatcher, MmioAccess};
use crate::error::{MicrovmError, MicrovmErrorCode};
use crate::esr::{AccessDirection, DataAbort};
use crate::hvf_abi::{HvReg, HvVcpuExitException};
use crate::hvf_loop::{ExitAction, log_line};
use crate::interrupt::{InterruptAckRoute, InterruptAckTally, QueueNotifyRoute};
use crate::mmio_abort;
use crate::stop::StopReason;
use crate::sys::HvVcpu;
use crate::virtio_mmio::MmioWriteOutcome;
use std::sync::{Arc, Mutex};

/// MMIO ハンドラの状態（デバイスバスと観測用の計数）。
#[derive(Debug, Default)]
pub struct MmioHandler {
    dispatcher: Arc<Mutex<ExitDispatcher>>,
    unhandled: u64,
    queue_notifies: u64,
    last_queue_notify: Option<(DeviceId, u16)>,
    /// `InterruptACK` の後処理（level 扱いの線の deassert / resample。#3863）。route の無いデバイスは計数だけ。
    ack_routes: Vec<(DeviceId, Arc<dyn InterruptAckRoute>)>,
    interrupt_acks: u64,
    /// ACK の後処理の結果の累計（観測専用。全 vCPU のハンドラが同じ `Arc` を共有する。#4014）。
    ack_tallies: Vec<(DeviceId, Arc<InterruptAckTally>)>,
    /// `QueueNotify` の virtqueue 処理（#4028）。route の無いデバイスは計数だけで続行する（block・net は #4028・#4029 で route を結ぶ）。
    queue_routes: Vec<(DeviceId, Arc<dyn QueueNotifyRoute>)>,
}

impl MmioHandler {
    /// デバイス未登録のハンドラを作る（全アクセスが未登録として扱われる）。
    pub fn new() -> Self {
        Self::default()
    }

    /// 登録済みの dispatcher を持つハンドラを作る。
    pub fn with_dispatcher(dispatcher: ExitDispatcher) -> Self {
        Self::with_shared_dispatcher(Arc::new(Mutex::new(dispatcher)))
    }

    /// 組み立て済み VM が持つ共有 dispatcher（`HvfMicroVm::dispatcher`）を使うハンドラを作る（#3793）。
    pub fn with_shared_dispatcher(dispatcher: Arc<Mutex<ExitDispatcher>>) -> Self {
        Self {
            dispatcher,
            ..Self::default()
        }
    }

    /// デバイスごとの `InterruptACK` の後処理を足す（#3863・MVM-5）。
    pub fn with_ack_routes(mut self, routes: Vec<(DeviceId, Arc<dyn InterruptAckRoute>)>) -> Self {
        self.ack_routes = routes;
        self
    }

    /// デバイスごとの `InterruptACK` の後処理の結果の計数を足す（#4014・MVM-5）。計数は `HvfDeviceBus` が 1 回だけ作り、
    /// 全 vCPU のハンドラが同じ実体を共有する。route の成功時だけ数え、失敗は従来どおり VM を止める。
    pub fn with_ack_tallies(mut self, tallies: Vec<(DeviceId, Arc<InterruptAckTally>)>) -> Self {
        self.ack_tallies = tallies;
        self
    }

    /// デバイスごとの `QueueNotify` の処理（virtqueue の処理と完了の割り込み。#4028・MVM-5・MVM-1）を足す。
    /// route は `HvfDeviceBus` が 1 回だけ作り、全 vCPU のハンドラが同じ実体（`Arc`）を共有する。
    pub fn with_queue_notify_routes(
        mut self,
        routes: Vec<(DeviceId, Arc<dyn QueueNotifyRoute>)>,
    ) -> Self {
        self.queue_routes = routes;
        self
    }

    /// `InterruptACK` を受けた回数（#3863）。
    pub fn interrupt_ack_count(&self) -> u64 {
        self.interrupt_acks
    }

    /// 共有 dispatcher のハンドル（デバイスの追加登録用）。
    pub fn dispatcher(&self) -> &Arc<Mutex<ExitDispatcher>> {
        &self.dispatcher
    }

    /// どのデバイスにも当たらなかったアクセスの回数（REPAIR-4）。
    pub fn unhandled_count(&self) -> u64 {
        self.unhandled
    }

    /// `QueueNotify` を受けた回数（観測用。route の有無・成否とは関係なく数える。REPAIR-4）。
    pub fn queue_notify_count(&self) -> u64 {
        self.queue_notifies
    }

    /// ACK / `DeviceReset` の後処理（resample）を呼んで計数する。`reset` なら `resets`、そうでなければ ACK の計数に数える（#4170）。
    /// 失敗は VM を止める（fail-closed）。route が無ければ何もしない。vCPU を要さないため単体で試験できる。
    fn run_ack_route(&self, device: &DeviceId, reset: bool) -> Result<(), MicrovmError> {
        if let Some((_, route)) = self.ack_routes.iter().find(|(id, _)| id == device) {
            let report = route.on_interrupt_ack()?;
            if let Some((_, tally)) = self.ack_tallies.iter().find(|(id, _)| id == device) {
                if reset {
                    tally.record_reset();
                } else {
                    tally.record(&report);
                }
            }
        }
        Ok(())
    }

    /// 最後に受けた `QueueNotify`（デバイスとキュー番号）。
    pub fn last_queue_notify(&self) -> Option<(DeviceId, u16)> {
        self.last_queue_notify
    }
}

fn internal(msg: &'static str) -> MicrovmError {
    MicrovmError::new(MicrovmErrorCode::Internal, msg)
}

/// 組み立てた MMIO exit を dispatcher へ渡し、結果に応じた計数と route の呼び出しまでを行う（#4231・MVM-5・MVM-1）。
///
/// [`handle_data_abort`] の vCPU（`hv_*`）に触れない部分で、実機なしで `QueueNotify` / `QueueStopped` などの振り分けを
/// 試験できる継ぎ目。dispatcher の lock は dispatch の式の終わりで解放し、route へ進む（lock の順は変えない）。
/// 戻りの `Some(action)` は route が VM の停止を求めた場合で、呼び出し元は PC を進めずにそのまま返す。
fn dispatch_and_route(
    handler: &mut MmioHandler,
    exit: &crate::exit::VcpuExit,
) -> Result<(DispatchOutcome, Option<ExitAction>), MicrovmError> {
    // dispatcher の lock はこの式の終わりで解放する（ACK の後処理でトランスポートの lock を取るため、同時保持しない）。
    let outcome = handler
        .dispatcher
        .lock()
        .map_err(|_| internal("mmio dispatcher lock poisoned"))?
        .dispatch(exit)?;
    match &outcome {
        DispatchOutcome::Mmio {
            device,
            access: MmioAccess::Write(MmioWriteOutcome::InterruptAcknowledged),
        } => {
            handler.interrupt_acks = handler.interrupt_acks.saturating_add(1);
            handler.run_ack_route(device, false)?;
        }
        // Status=0 のリセットは `interrupt_status` を 0 にするため、level 線が上がったままにならないよう
        // ACK と同じ後処理（resample）を呼ぶ（MVM-5。`interrupt_acks` と ACK の計数には含めず、別カウンタ `resets` に数える。#4170）。
        DispatchOutcome::Mmio {
            device,
            access: MmioAccess::Write(MmioWriteOutcome::DeviceReset),
        } => {
            handler.run_ack_route(device, true)?;
        }
        DispatchOutcome::Mmio {
            device,
            access: MmioAccess::Write(MmioWriteOutcome::QueueNotify(q)),
        } => {
            handler.queue_notifies = handler.queue_notifies.saturating_add(1);
            handler.last_queue_notify = Some((*device, *q));
            // route は「dispatcher → transport → memory」の順で lock を取る（#4026 の契約）。dispatcher の lock は上の式で
            // 解放済み。受理判定（`accept_queue_notify`）は `QueueNotify` を返す前に済んでいるため、ここで二重にしない。
            if let Some((_, route)) = handler.queue_routes.iter().find(|(id, _)| id == device) {
                let result = route.on_queue_notify(*q);
                let action = mmio_abort::queue_notify_action(&result);
                if let ExitAction::Stop(reason) = action {
                    // `Ok(Stop)` は `run_loop_exit` が診断を出さないため、ここで 1 行出す（固定の語と数値だけ。ERR-1・REPAIR-4）。
                    let source = if result.is_err() { "route" } else { "queue" };
                    let code = match reason {
                        StopReason::Failed(c) => c.as_str(),
                        _ => "unknown",
                    };
                    log_line(format_args!(
                        "level=error op=hvf.mmio.queue_notify outcome=error source={source} code={code} device={} queue={q}",
                        device.index()
                    ));
                    return Ok((outcome, Some(action)));
                }
            }
        }
        DispatchOutcome::Unhandled { .. } => {
            handler.unhandled = handler.unhandled.saturating_add(1);
        }
        _ => {}
    }

    Ok((outcome, None))
}

/// data abort を処理する。MMIO を dispatcher へ渡し、読み出しなら応答を `SRT` へ書き、PC を進めて続行する。
pub fn handle_data_abort(
    vcpu: &mut HvVcpu<'_>,
    handler: &mut MmioHandler,
    abort: &DataAbort,
    exception: &HvVcpuExitException,
) -> Result<ExitAction, MicrovmError> {
    mmio_abort::ensure_mmio_fault(abort)?;

    let write_value = if abort.direction == AccessDirection::Write {
        if abort.register.is_zero_register() {
            mmio_abort::write_source_value(abort, None)
        } else {
            let reg = HvReg::x(abort.register.get()).ok_or_else(|| internal("invalid SRT"))?;
            mmio_abort::write_source_value(abort, Some(vcpu.get_reg(reg)?))
        }
    } else {
        0
    };

    let exit = mmio_abort::mmio_exit_from_abort(abort, exception.physical_address, write_value);
    let (outcome, stop) = dispatch_and_route(handler, &exit)?;
    if let Some(action) = stop {
        // PC は進めない。VM は止まり、書き込みなので SRT へ返す応答も無い。
        return Ok(action);
    }

    if abort.direction == AccessDirection::Read {
        let resp = outcome
            .read_response()
            .ok_or_else(|| internal("mmio read produced no response"))?;
        if let Some(v) = mmio_abort::read_register_value(abort, resp)? {
            let reg = HvReg::x(abort.register.get()).ok_or_else(|| internal("invalid SRT"))?;
            vcpu.set_reg(reg, v)?;
        }
    }

    let pc = vcpu.get_reg(HvReg::PC)?;
    vcpu.set_reg(HvReg::PC, mmio_abort::next_pc(pc, exception.syndrome)?)?;
    Ok(ExitAction::Continue)
}

#[cfg(test)]
mod tests {
    //! macOS かつ aarch64 のネイティブでだけ走る（`hv_*` は呼ばない）。MVM-5・MVM-1・REPAIR-3・REPAIR-12。
    use super::*;
    use crate::virtio_block::{MemoryBlockBackend, VirtioBlock};
    use crate::virtio_mmio::VirtioMmioTransport;

    /// ACK の route はデバイスの識別子で引かれ、保持される（#3863）。`hv_*` を呼ばないため vCPU の経路は別途実機で確かめる（#4015）。
    #[test]
    fn mvm5_3863_ack_routes_are_kept() {
        use crate::interrupt::{InterruptAckReport, LineResample};
        #[derive(Debug)]
        struct Fake;
        impl InterruptAckRoute for Fake {
            fn on_interrupt_ack(&self) -> Result<InterruptAckReport, MicrovmError> {
                Ok(InterruptAckReport {
                    remaining: 0,
                    resample: LineResample::Deasserted,
                })
            }
        }
        let mut d = ExitDispatcher::new();
        let block = VirtioMmioTransport::new(VirtioBlock::new(
            MemoryBlockBackend::new(16 * 512, false).unwrap(),
        ))
        .unwrap();
        let id = d
            .register_mmio(0x0a00_0000, 0x200, Box::new(block))
            .unwrap();
        let h = MmioHandler::with_dispatcher(d).with_ack_routes(vec![(id, Arc::new(Fake))]);
        assert_eq!(h.interrupt_ack_count(), 0);
        assert_eq!(h.ack_routes.len(), 1);
    }

    /// ACK の計数はデバイスの識別子で引かれ、保持される（#4014）。vCPU の経路は実機で確かめる（`hvf_kernel_boot`）。
    #[test]
    fn mvm5_4014_ack_tallies_are_kept() {
        let mut d = ExitDispatcher::new();
        let block = VirtioMmioTransport::new(VirtioBlock::new(
            MemoryBlockBackend::new(16 * 512, false).unwrap(),
        ))
        .unwrap();
        let id = d
            .register_mmio(0x0a00_0000, 0x200, Box::new(block))
            .unwrap();
        let tally = Arc::new(InterruptAckTally::default());
        let h = MmioHandler::with_dispatcher(d).with_ack_tallies(vec![(id, Arc::clone(&tally))]);
        assert_eq!(h.ack_tallies.len(), 1);
        assert_eq!(tally.snapshot().acks, 0);
    }

    /// `DeviceReset` の後処理は `resets` だけを加算し、ACK の計数（`acks`）を動かさない（#4170・MVM-5）。
    #[test]
    fn mvm5_4170_device_reset_counts_resets_not_acks() {
        use crate::interrupt::{InterruptAckReport, LineResample};
        #[derive(Debug)]
        struct Fake;
        impl InterruptAckRoute for Fake {
            fn on_interrupt_ack(&self) -> Result<InterruptAckReport, MicrovmError> {
                Ok(InterruptAckReport {
                    remaining: 0,
                    resample: LineResample::Deasserted,
                })
            }
        }
        let mut d = ExitDispatcher::new();
        let block = VirtioMmioTransport::new(VirtioBlock::new(
            MemoryBlockBackend::new(16 * 512, false).unwrap(),
        ))
        .unwrap();
        let id = d
            .register_mmio(0x0a00_0000, 0x200, Box::new(block))
            .unwrap();
        let tally = Arc::new(InterruptAckTally::default());
        let h = MmioHandler::with_dispatcher(d)
            .with_ack_routes(vec![(id, Arc::new(Fake))])
            .with_ack_tallies(vec![(id, Arc::clone(&tally))]);
        h.run_ack_route(&id, true).unwrap();
        assert_eq!(tally.snapshot().resets, 1);
        assert_eq!(tally.snapshot().acks, 0);
        h.run_ack_route(&id, false).unwrap();
        assert_eq!(tally.snapshot().resets, 1);
        assert_eq!(tally.snapshot().acks, 1);
    }

    /// `QueueNotify` の route はデバイスの識別子で引かれ、保持される（#4028）。vCPU の経路は実機で確かめる（`hvf_microvm`）。
    #[test]
    fn mvm5_4028_queue_notify_routes_are_kept() {
        use crate::interrupt::QueueNotifyReport;
        #[derive(Debug)]
        struct Fake;
        impl QueueNotifyRoute for Fake {
            fn on_queue_notify(&self, _q: u16) -> Result<QueueNotifyReport, MicrovmError> {
                Err(internal("fake"))
            }
        }
        let mut d = ExitDispatcher::new();
        let block = VirtioMmioTransport::new(VirtioBlock::new(
            MemoryBlockBackend::new(16 * 512, false).unwrap(),
        ))
        .unwrap();
        let id = d
            .register_mmio(0x0a00_0000, 0x200, Box::new(block))
            .unwrap();
        let h =
            MmioHandler::with_dispatcher(d).with_queue_notify_routes(vec![(id, Arc::new(Fake))]);
        assert_eq!(h.queue_notify_count(), 0);
        assert_eq!(h.queue_routes.len(), 1);
        assert_eq!(h.queue_routes[0].0, id);
    }

    /// 共有の dispatcher へ後から登録したデバイスが、ハンドラ側から見える（同じ実体を指す）。
    #[test]
    fn mvm5_shared_dispatcher_is_same_instance() {
        let shared = Arc::new(Mutex::new(ExitDispatcher::new()));
        let handler = MmioHandler::with_shared_dispatcher(Arc::clone(&shared));
        assert!(Arc::ptr_eq(handler.dispatcher(), &shared));
        assert_eq!(Arc::strong_count(&shared), 2);
        let block = VirtioMmioTransport::new(VirtioBlock::new(
            MemoryBlockBackend::new(16 * 512, false).unwrap(),
        ))
        .unwrap();
        shared
            .lock()
            .unwrap()
            .register_mmio(0x0a00_0000, 0x200, Box::new(block))
            .unwrap();
        // MagicValue（offset 0）がハンドラ経由の dispatcher から 0x7472_6976 で読める。
        let exit = crate::exit::VcpuExit::Mmio {
            phys_addr: 0x0a00_0000,
            data: [0; 8],
            len: 4,
            is_write: false,
        };
        let out = handler
            .dispatcher()
            .lock()
            .unwrap()
            .dispatch(&exit)
            .unwrap();
        assert_eq!(out.read_response(), Some(&0x7472_6976u32.to_le_bytes()[..]));
    }

    /// `queue_stopped` / `reset` の呼び出しだけを記録して本物のデバイスへ委譲するアダプタ（#4231）。
    struct Recording<D: crate::virtio_mmio::VirtioDevice> {
        inner: D,
        stopped: Vec<u16>,
    }

    impl<D: crate::virtio_mmio::VirtioDevice> crate::virtio_mmio::VirtioDevice for Recording<D> {
        fn device_type(&self) -> crate::virtio_mmio::VirtioDeviceType {
            self.inner.device_type()
        }
        fn device_features(&self) -> crate::virtio_mmio::FeatureBits {
            self.inner.device_features()
        }
        fn queue_max_sizes(&self) -> &[u16] {
            self.inner.queue_max_sizes()
        }
        fn read_config(&self, offset: u64, data: &mut [u8]) {
            self.inner.read_config(offset, data)
        }
        fn write_config(&mut self, offset: u64, data: &[u8]) {
            self.inner.write_config(offset, data)
        }
        fn accepts_features(&self, features: crate::virtio_mmio::FeatureBits) -> bool {
            self.inner.accepts_features(features)
        }
        fn activate(
            &mut self,
            f: crate::virtio_mmio::FeatureBits,
            q: &[crate::virtio_mmio::QueueConfig],
        ) -> Result<(), MicrovmError> {
            self.inner.activate(f, q)
        }
        fn queue_stopped(&mut self, index: u16) {
            self.stopped.push(index);
            self.inner.queue_stopped(index);
        }
        fn reset(&mut self) {
            self.inner.reset();
        }
    }

    /// 呼ばれた回数だけを数える `QueueNotifyRoute`。呼ばれたら失敗を返す（停止後の通知が route に届かないことの確認用）。
    #[derive(Debug, Default)]
    struct CountingRoute(std::sync::atomic::AtomicU32);

    impl QueueNotifyRoute for CountingRoute {
        fn on_queue_notify(
            &self,
            _queue: u16,
        ) -> Result<crate::interrupt::QueueNotifyReport, MicrovmError> {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err(internal("counting route called"))
        }
    }

    fn mmio(addr: u64, value: u32, is_write: bool) -> crate::exit::VcpuExit {
        let mut data = [0u8; 8];
        data[..4].copy_from_slice(&value.to_le_bytes());
        crate::exit::VcpuExit::Mmio {
            phys_addr: addr,
            data,
            len: 4,
            is_write,
        }
    }

    fn write_reg(h: &mut MmioHandler, base: u64, reg: u64, v: u32) -> MmioWriteOutcome {
        let (out, stop) = dispatch_and_route(h, &mmio(base + reg, v, true)).unwrap();
        assert_eq!(stop, None);
        match out {
            DispatchOutcome::Mmio {
                access: MmioAccess::Write(o),
                ..
            } => o,
            other => panic!("expected mmio write, got {other:?}"),
        }
    }

    /// MVM-5・MVM-1・#4231: `handle_data_abort` の振り分け（`dispatch_and_route`）を通した `QueueReady=0` で
    /// `queue_stopped` がちょうど 1 回呼ばれ、`QueueNotify` の route・計数は動かない。`HvfDeviceBus::bind` と同じく
    /// `SharedTransport` を登録する。回数は `Recording` が直接数える。`hv_*` は呼ばない。
    #[test]
    fn mvm5_4231_queue_ready_zero_stops_once_via_mmio_handler() {
        use crate::virtio_mmio::{SharedTransport, reg};
        const BASE: u64 = 0x0a00_0000;
        let transport = Arc::new(Mutex::new(
            VirtioMmioTransport::new(Recording {
                inner: VirtioBlock::new(MemoryBlockBackend::new(16 * 512, false).unwrap()),
                stopped: Vec::new(),
            })
            .unwrap(),
        ));
        let mut d = ExitDispatcher::new();
        let id = d
            .register_mmio(
                BASE,
                0x200,
                Box::new(SharedTransport(Arc::clone(&transport))),
            )
            .unwrap();
        let route = Arc::new(CountingRoute::default());
        let mut h = MmioHandler::with_dispatcher(d)
            .with_queue_notify_routes(vec![(id, Arc::clone(&route) as Arc<dyn QueueNotifyRoute>)]);

        // 交渉 → キュー 0 の設定 → DRIVER_OK。
        write_reg(&mut h, BASE, reg::STATUS, 1);
        write_reg(&mut h, BASE, reg::STATUS, 3);
        write_reg(&mut h, BASE, reg::DEVICE_FEATURES_SEL, 0);
        let low = {
            let (out, _) =
                dispatch_and_route(&mut h, &mmio(BASE + reg::DEVICE_FEATURES, 0, false)).unwrap();
            let r = out.read_response().unwrap();
            u32::from_le_bytes([r[0], r[1], r[2], r[3]])
        };
        write_reg(&mut h, BASE, reg::DRIVER_FEATURES_SEL, 0);
        write_reg(&mut h, BASE, reg::DRIVER_FEATURES, low);
        write_reg(&mut h, BASE, reg::DRIVER_FEATURES_SEL, 1);
        write_reg(&mut h, BASE, reg::DRIVER_FEATURES, 1);
        assert_eq!(
            write_reg(&mut h, BASE, reg::STATUS, 11),
            MmioWriteOutcome::FeaturesAccepted
        );
        write_reg(&mut h, BASE, reg::QUEUE_SEL, 0);
        write_reg(&mut h, BASE, reg::QUEUE_NUM, 16);
        write_reg(&mut h, BASE, reg::QUEUE_DESC_LOW, 0x1000);
        write_reg(&mut h, BASE, reg::QUEUE_DRIVER_LOW, 0x2000);
        write_reg(&mut h, BASE, reg::QUEUE_DEVICE_LOW, 0x3000);
        write_reg(&mut h, BASE, reg::QUEUE_READY, 1);
        assert_eq!(
            write_reg(&mut h, BASE, reg::STATUS, 15),
            MmioWriteOutcome::DeviceActivated
        );
        assert!(transport.lock().unwrap().device().stopped.is_empty());

        assert_eq!(
            write_reg(&mut h, BASE, reg::QUEUE_READY, 0),
            MmioWriteOutcome::QueueStopped(0)
        );
        assert_eq!(transport.lock().unwrap().device().stopped, vec![0u16]);

        // 2 回目は増えない。
        assert_eq!(
            write_reg(&mut h, BASE, reg::QUEUE_READY, 0),
            MmioWriteOutcome::Handled
        );
        assert_eq!(transport.lock().unwrap().device().stopped, vec![0u16]);

        // 停止後の QueueNotify は無視され、計数も route も動かない。
        assert!(matches!(
            write_reg(&mut h, BASE, reg::QUEUE_NOTIFY, 0),
            MmioWriteOutcome::Ignored(_)
        ));
        assert_eq!(h.queue_notify_count(), 0);
        assert_eq!(route.0.load(std::sync::atomic::Ordering::SeqCst), 0);
    }
}
