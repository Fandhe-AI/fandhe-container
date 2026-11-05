//! HVF の SPI 宛先決定（`SpiRouting`）から通知・VM 共有の統計までの結合試験（#3974・MVM-5・REPAIR-4・REPAIR-12）。
//!
//! `hvf::gic` の sink が assert 成功のたびにたどる手順（`resolve` → 初回ログ判定 → `WfiWakeSet::notify_target`）を、
//! `hv_gic_get_distributor_reg` の代わりに偽の `GicdRegisterRead` で再現する。Hypervisor.framework は使わないため
//! 既定のテスト集合で 3 OS とも走る。実機（macOS / aarch64）での ARE と IROUTER の実値は `tests/hvf_device.rs`
//! （実機前提）が担う。

use std::cell::{Cell, RefCell};
use std::time::Duration;

use fandhe_container_microvm::error::{MicrovmError, MicrovmErrorCode};
use fandhe_container_microvm::hvf_abi::GicDistributorReg;
use fandhe_container_microvm::hvf_wake::{
    GicdRegisterRead, SpiRouteFallback, SpiRouteHint, SpiRouting, WakeOutcome, WfiWakeSet, WfiWaker,
};

const VCPUS: u32 = 4;
const INTID: u32 = 48;

struct FakeGicd {
    ctlr: RefCell<Result<u64, MicrovmErrorCode>>,
    irouter: RefCell<Result<u64, MicrovmErrorCode>>,
    irouter_reads: Cell<u32>,
}

impl FakeGicd {
    fn new(ctlr: Result<u64, MicrovmErrorCode>, irouter: Result<u64, MicrovmErrorCode>) -> Self {
        Self {
            ctlr: RefCell::new(ctlr),
            irouter: RefCell::new(irouter),
            irouter_reads: Cell::new(0),
        }
    }
}

impl GicdRegisterRead for FakeGicd {
    fn read(&self, reg: GicDistributorReg) -> Result<u64, MicrovmError> {
        let cell = if reg == GicDistributorReg::ctlr() {
            &self.ctlr
        } else {
            self.irouter_reads.set(self.irouter_reads.get() + 1);
            &self.irouter
        };
        (*cell.borrow()).map_err(|c| MicrovmError::new(c, "fake gicd read failed"))
    }
}

/// sink の assert 成功後の手順。通知の結果として「起きたスロットの一覧」を返す。
fn assert_spi(
    routing: &SpiRouting,
    gicd: &FakeGicd,
    set: &WfiWakeSet,
    wakers: &[WfiWaker],
    hint: &SpiRouteHint,
) -> (Option<SpiRouteFallback>, bool, Vec<u32>) {
    let d = routing.resolve(gicd, INTID, hint.get(), set.vcpus());
    set.notify_target(d.target);
    // 待ち手は既読位置を持つため、vCPU スレッドと同じく最初に取った clone を使い続ける。
    let woken = (0..VCPUS)
        .filter(|i| wakers[*i as usize].wait(Duration::ZERO) == WakeOutcome::Notified)
        .collect();
    (d.fallback, d.first, woken)
}

#[test]
fn mvm5_repair4_12_3974_are_enabled_routes_to_irouter_target_only() {
    let routing = SpiRouting::default();
    let set = WfiWakeSet::new(VCPUS).unwrap();
    let wakers: Vec<_> = (0..VCPUS).map(|i| set.handle(i).unwrap()).collect();
    let hint = SpiRouteHint::unknown();
    // ARE = 1、IROUTER = affinity 2。
    let gicd = FakeGicd::new(Ok(0x10), Ok(0x2));
    let (fb, first, woken) = assert_spi(&routing, &gicd, &set, &wakers, &hint);
    assert_eq!((fb, first, woken), (None, false, vec![2]));
    assert_eq!(routing.snapshot().total(), 0);
}

#[test]
fn mvm5_repair4_12_3974_are_disabled_falls_back_and_counts_per_vm() {
    let routing = SpiRouting::default();
    let shared = routing.clone();
    let set = WfiWakeSet::new(VCPUS).unwrap();
    let wakers: Vec<_> = (0..VCPUS).map(|i| set.handle(i).unwrap()).collect();
    let hint = SpiRouteHint::unknown();
    let gicd = FakeGicd::new(Ok(0x0), Ok(0x2));

    // 未学習: 全台を起こす。初回だけ first。
    let (fb, first, woken) = assert_spi(&routing, &gicd, &set, &wakers, &hint);
    assert_eq!(fb, Some(SpiRouteFallback::AreDisabled));
    assert!(first);
    assert_eq!(woken, vec![0, 1, 2, 3]);

    // ヒントを学習したらそのスロットだけ。2 回目は first でない。
    hint.record(3);
    let (fb, first, woken) = assert_spi(&routing, &gicd, &set, &wakers, &hint);
    assert_eq!(
        (fb, first, woken),
        (Some(SpiRouteFallback::AreDisabled), false, vec![3])
    );

    // ARE = 0 では IROUTER を読まない。件数は clone（別の線の sink）と共有される。
    assert_eq!(gicd.irouter_reads.get(), 0);
    assert_eq!(shared.snapshot().count(SpiRouteFallback::AreDisabled), 2);
    assert_eq!(shared.snapshot().total(), 2);

    // ゲストが ARE を立てると、次の assert から IROUTER（affinity 2）を使う。
    *gicd.ctlr.borrow_mut() = Ok(0x10);
    let (fb, first, woken) = assert_spi(&routing, &gicd, &set, &wakers, &hint);
    assert_eq!((fb, first, woken), (None, false, vec![2]));
    assert_eq!(gicd.irouter_reads.get(), 1);
    assert_eq!(shared.snapshot().total(), 2);
}

#[test]
fn mvm5_repair4_12_3974_read_failure_is_counted_by_reason() {
    let routing = SpiRouting::default();
    let set = WfiWakeSet::new(VCPUS).unwrap();
    let wakers: Vec<_> = (0..VCPUS).map(|i| set.handle(i).unwrap()).collect();
    let hint = SpiRouteHint::unknown();
    let gicd = FakeGicd::new(Err(MicrovmErrorCode::Unimplemented), Ok(0x1));
    let (fb, first, woken) = assert_spi(&routing, &gicd, &set, &wakers, &hint);
    assert_eq!((fb, first), (Some(SpiRouteFallback::Unavailable), true));
    assert_eq!(woken, vec![0, 1, 2, 3]);
    let s = routing.snapshot();
    assert_eq!(s.count(SpiRouteFallback::Unavailable), 1);
    assert_eq!(s.count(SpiRouteFallback::Failed), 0);
    assert_eq!(s.total(), 1);
}
