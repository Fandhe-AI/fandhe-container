//! virtio-mmio の窓の観測（STATUS・QUEUE_READY・DRIVER_FEATURES への書き込みの集計）と交渉結果の照合の共有補助
//! （#4289・MVM-5・MVM-1・REPAIR-1・REPAIR-12）。
//!
//! `tests/kernel_boot.rs`（Linux・KVM。`RunObserver::record` の `RunRecord::value` から [`VirtioWindows::record_value`] へ）と
//! `tests/hvf_kernel_boot.rs`（macOS・HVF。`VcpuExitObserver::on_value` から同じ入口へ）が
//! `#[path = "support/virtio_window.rs"] mod virtio_window;` で取り込む。窓の集計と features の組み立て・照合・結果行の書式を
//! 両方で共有し、検査の食い違いを防ぐ。窓は 2 つ（[`WindowKind::Block`]・[`WindowKind::Net`]）。
//!
//! 試験専用の補助で、製品コードからは参照されない。値はゲスト由来（untrusted）で、`record_value` は数えるだけにし、
//! 割り当て・待ち・添字アクセス・`unwrap` をしない（vCPU スレッドから同期で呼ばれる。REPAIR-5）。
//! 未使用警告: 取り込み側が使わない項目で `dead_code` が出ないよう、単体試験からすべての項目を参照する。

use fandhe_container_microvm::exit::ExitValue;
use fandhe_container_microvm::virtio_mmio::reg;
use std::sync::atomic::{AtomicU64, Ordering};

/// MMIO の窓 1 つ分の観測値（virtio-mmio の STATUS・QUEUE_READY への書き込み）。
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct WindowStats {
    /// DRIVER_OK を含む最初の STATUS 書き込みの値。
    pub driver_ok_first: Option<u32>,
    /// FAILED を含む STATUS 書き込みの件数。
    pub failed_writes: u64,
    /// STATUS への 4 バイト書き込みの総数。
    pub status_writes: u64,
    /// QUEUE_READY へ値 1 を書いた回数。
    pub queue_ready_one: u64,
    /// FEATURES_OK を含み DRIVER_OK を含まない最初の STATUS 書き込みの値（Linux は `0x0B`。#4234）。
    pub features_ok_first: Option<u32>,
    /// 上記の条件の STATUS 書き込みの件数。
    pub features_ok_writes: u64,
    /// 最初の FEATURES_OK 書き込みの時点でドライバが書いていた features（`lo | hi << 32`）。
    /// 下位・上位のどちらかのページが未書き込みなら `None`（#4234・MVM-1・MVM-5）。
    pub driver_features: Option<u64>,
    /// `DRIVER_FEATURES` を sel 0・1 以外のときに書いた件数（トランスポートの `InvalidSelector` に対応。診断用）。
    pub driver_features_bad_sel: u64,
}

/// 窓 1 つ分の atomic カウンタ（`len == 0` は未設定）。
#[derive(Debug, Default)]
struct Window {
    base: AtomicU64,
    len: AtomicU64,
    driver_ok_first: AtomicU64,
    failed_writes: AtomicU64,
    status_writes: AtomicU64,
    queue_ready_one: AtomicU64,
    /// 最後に `DRIVER_FEATURES_SEL` へ書かれた値（#4234）。
    driver_features_sel: AtomicU64,
    /// 作業中の下位・上位ページ（`NO_VALUE` = 未書き込み。Status=0 でトランスポートの reset に合わせて戻す）。
    driver_features_lo: AtomicU64,
    driver_features_hi: AtomicU64,
    driver_features_bad_sel: AtomicU64,
    features_ok_first: AtomicU64,
    features_ok_writes: AtomicU64,
    /// FEATURES_OK 時点のスナップショットが保存済みか（値が `u64::MAX` でも番兵と衝突しないよう別に持つ）。
    features_snapshot_valid: AtomicU64,
    features_snapshot: AtomicU64,
}

const NO_VALUE: u64 = u64::MAX;
/// virtio 仕様 2.1 の Device Status ビット（DRIVER_OK = 4・FAILED = 128）。
const STATUS_DRIVER_OK: u32 = 4;
const STATUS_FAILED: u32 = 128;
const STATUS_FEATURES_OK: u32 = 8;
/// `VIRTIO_F_RING_RESET`（virtio 1.2 のビット 40）。`virtio_ring_reset.rs` の同名定数の双子で、lib に公開定数を
/// 足すと「対応済み」に見えるため試験側に置く（REPAIR-3。#4234・#4169・MVM-1・MVM-5）。
pub const VIRTIO_F_RING_RESET_BIT: u32 = 40;
/// 観測する窓の種別（`microvm::VirtioDeviceKind` は Linux 専用のため、試験側に小さな enum を持つ）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowKind {
    Block,
    Net,
}

impl WindowKind {
    fn index(self) -> usize {
        match self {
            WindowKind::Block => 0,
            WindowKind::Net => 1,
        }
    }
}

/// 窓 2 つ（0 = virtio-block、1 = virtio-net）の atomic 集計体。
#[derive(Debug)]
pub struct VirtioWindows {
    windows: [Window; 2],
}

impl Default for VirtioWindows {
    fn default() -> Self {
        Self::new()
    }
}

impl VirtioWindows {
    pub fn new() -> Self {
        let obs = Self {
            windows: [Window::default(), Window::default()],
        };
        for w in &obs.windows {
            w.driver_ok_first.store(NO_VALUE, Ordering::Relaxed);
            w.features_ok_first.store(NO_VALUE, Ordering::Relaxed);
            w.driver_features_lo.store(NO_VALUE, Ordering::Relaxed);
            w.driver_features_hi.store(NO_VALUE, Ordering::Relaxed);
        }
        obs
    }

    /// 窓の範囲（ゲスト物理アドレスの先頭と長さ）を結ぶ。`len == 0` は未設定として何も数えない。
    pub fn bind(&self, kind: WindowKind, base: u64, len: u64) {
        if let Some(w) = self.windows.get(kind.index()) {
            w.base.store(base, Ordering::Relaxed);
            w.len.store(len, Ordering::Relaxed);
        }
    }

    pub fn stats(&self, kind: WindowKind) -> WindowStats {
        let Some(w) = self.windows.get(kind.index()) else {
            return WindowStats::default();
        };
        let first = w.driver_ok_first.load(Ordering::Relaxed);
        WindowStats {
            driver_ok_first: u32::try_from(first).ok(),
            failed_writes: w.failed_writes.load(Ordering::Relaxed),
            status_writes: w.status_writes.load(Ordering::Relaxed),
            queue_ready_one: w.queue_ready_one.load(Ordering::Relaxed),
            features_ok_first: u32::try_from(w.features_ok_first.load(Ordering::Relaxed)).ok(),
            features_ok_writes: w.features_ok_writes.load(Ordering::Relaxed),
            driver_features: (w.features_snapshot_valid.load(Ordering::Relaxed) == 1)
                .then(|| w.features_snapshot.load(Ordering::Relaxed)),
            driver_features_bad_sel: w.driver_features_bad_sel.load(Ordering::Relaxed),
        }
    }

    /// MMIO の書き込み値（4 バイト）を窓へ数える。窓の外・読み出し・4 バイト以外・PIO は数えない。
    pub fn record_value(&self, value: &ExitValue) {
        let ExitValue::Mmio {
            phys_addr,
            is_write: true,
            data,
            ..
        } = *value
        else {
            return;
        };
        let Ok(bytes) = <[u8; 4]>::try_from(data.as_bytes()) else {
            return;
        };
        let value = u32::from_le_bytes(bytes);
        for w in &self.windows {
            let len = w.len.load(Ordering::Relaxed);
            let Some(off) = phys_addr.checked_sub(w.base.load(Ordering::Relaxed)) else {
                continue;
            };
            if len == 0 || off >= len {
                continue;
            }
            if off == reg::STATUS {
                w.status_writes.fetch_add(1, Ordering::Relaxed);
                if value == 0 {
                    // トランスポートの reset に合わせる。FEATURES_OK 時点のスナップショットは消さない。
                    w.driver_features_sel.store(0, Ordering::Relaxed);
                    w.driver_features_lo.store(NO_VALUE, Ordering::Relaxed);
                    w.driver_features_hi.store(NO_VALUE, Ordering::Relaxed);
                }
                if value & STATUS_FEATURES_OK != 0 && value & STATUS_DRIVER_OK == 0 {
                    w.features_ok_writes.fetch_add(1, Ordering::Relaxed);
                    let _ = w.features_ok_first.compare_exchange(
                        NO_VALUE,
                        u64::from(value),
                        Ordering::Relaxed,
                        Ordering::Relaxed,
                    );
                    let lo = w.driver_features_lo.load(Ordering::Relaxed);
                    let hi = w.driver_features_hi.load(Ordering::Relaxed);
                    if let (Ok(lo), Ok(hi)) = (u32::try_from(lo), u32::try_from(hi))
                        && w.features_snapshot_valid
                            .compare_exchange(0, 1, Ordering::Relaxed, Ordering::Relaxed)
                            .is_ok()
                    {
                        w.features_snapshot
                            .store(assemble_driver_features(lo, hi), Ordering::Relaxed);
                    }
                }
                if value & STATUS_FAILED != 0 {
                    w.failed_writes.fetch_add(1, Ordering::Relaxed);
                }
                if value & STATUS_DRIVER_OK != 0 {
                    let _ = w.driver_ok_first.compare_exchange(
                        NO_VALUE,
                        u64::from(value),
                        Ordering::Relaxed,
                        Ordering::Relaxed,
                    );
                }
            } else if off == reg::QUEUE_READY && value == 1 {
                w.queue_ready_one.fetch_add(1, Ordering::Relaxed);
            } else if off == reg::DRIVER_FEATURES_SEL {
                w.driver_features_sel
                    .store(u64::from(value), Ordering::Relaxed);
            } else if off == reg::DRIVER_FEATURES {
                match w.driver_features_sel.load(Ordering::Relaxed) {
                    0 => w
                        .driver_features_lo
                        .store(u64::from(value), Ordering::Relaxed),
                    1 => w
                        .driver_features_hi
                        .store(u64::from(value), Ordering::Relaxed),
                    _ => {
                        w.driver_features_bad_sel.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }
    }
}

/// ドライバが書いた下位・上位ページから features を組む（virtio-mmio の `DRIVER_FEATURES` は 32 ビットずつ。#4234）。
pub fn assemble_driver_features(lo: u32, hi: u32) -> u64 {
    u64::from(lo) | (u64::from(hi) << 32)
}

/// features のビット `bit` を 0 / 1 で返す（範囲外は 0。panic しない）。
pub fn feature_bit(features: u64, bit: u32) -> u8 {
    u8::from(features.checked_shr(bit).is_some_and(|v| v & 1 == 1))
}

/// 結果行に付ける交渉結果の固定書式（`prefix` は block+net の両方を出す場合の `block_` 等。#4234）。
pub fn features_result_fields(prefix: &str, s: &WindowStats) -> String {
    let ok = s
        .features_ok_first
        .map_or_else(|| "none".to_string(), |v| format!("0x{v:02x}"));
    match s.driver_features {
        Some(f) => format!(
            "{prefix}features_ok={ok} {prefix}driver_features=0x{f:016x} {prefix}ring_reset={}",
            feature_bit(f, VIRTIO_F_RING_RESET_BIT)
        ),
        None => {
            format!("{prefix}features_ok={ok} {prefix}driver_features=none {prefix}ring_reset=none")
        }
    }
}

/// 実ゲストの交渉結果を照合する（#4234・MVM-1・MVM-5）。FEATURES_OK は 1 回・値 `0x0B`、ドライバの features の
/// 上位ページはちょうど `0x1`（VERSION_1 のみ。デバイスの上位の提示はこれだけで、部分集合でない要求は拒否される）、
/// ビット 40（RING_RESET）は 0、下位ページは提示集合 `offered_low` の部分集合であること。
pub fn assert_features_negotiated(s: &WindowStats, offered_low: u64, label: &str, diag: &str) {
    assert_eq!(
        s.features_ok_first,
        Some(0x0B),
        "{label} FEATURES_OK: {diag}"
    );
    assert_eq!(
        s.features_ok_writes, 1,
        "{label} FEATURES_OK writes: {diag}"
    );
    assert_eq!(s.driver_features_bad_sel, 0, "{label} bad sel: {diag}");
    let Some(f) = s.driver_features else {
        panic!("{label} driver features not observed: {diag}");
    };
    assert_eq!(
        feature_bit(f, VIRTIO_F_RING_RESET_BIT),
        0,
        "{label} RING_RESET: {diag}"
    );
    assert_eq!(f >> 32, 1, "{label} upper page: {diag}");
    assert_eq!(
        f & 0xffff_ffff & !offered_low,
        0,
        "{label} lower page: {diag}"
    );
}

/// virtio-block が提示しうる下位ページ（読み取り専用の有無を問わず）。
pub const BLOCK_OFFERED_LOW: u64 = fandhe_container_microvm::virtio_block::VIRTIO_BLK_F_SIZE_MAX
    | fandhe_container_microvm::virtio_block::VIRTIO_BLK_F_SEG_MAX
    | fandhe_container_microvm::virtio_block::VIRTIO_BLK_F_RO
    | fandhe_container_microvm::virtio_block::VIRTIO_BLK_F_FLUSH;
/// virtio-net が提示する下位ページ。
pub const NET_OFFERED_LOW: u64 = fandhe_container_microvm::virtio_net::VIRTIO_NET_F_MAC;

#[cfg(test)]
mod tests {
    use super::*;
    use fandhe_container_microvm::exit::ExitData;

    fn mmio_write(addr: u64, value: u32) -> ExitValue {
        ExitValue::Mmio {
            phys_addr: addr,
            len: 4,
            is_write: true,
            data: ExitData::from_slice(&value.to_le_bytes()),
        }
    }

    /// 窓の外・読み出し・値の長さ違い・PIO は数えず、block と net の窓を取り違えない。
    #[test]
    fn mvm5_4289_window_counts_status_and_queue_ready() {
        let obs = VirtioWindows::new();
        let (blk, net) = (0xd000_0000u64, 0xd000_1000u64);
        obs.bind(WindowKind::Block, blk, 0x1000);
        obs.bind(WindowKind::Net, net, 0x1000);
        obs.record_value(&mmio_write(0xd000_2000 + reg::STATUS, 0x0F));
        obs.record_value(&mmio_write(0xcfff_f000, 0x0F));
        let mut read = mmio_write(blk + reg::STATUS, 0x0F);
        if let ExitValue::Mmio { is_write, .. } = &mut read {
            *is_write = false;
        }
        obs.record_value(&read);
        assert_eq!(obs.stats(WindowKind::Block), WindowStats::default());
        assert_eq!(obs.stats(WindowKind::Net), WindowStats::default());
        for v in [0u32, 1, 3, 11, 15, 0x8F] {
            obs.record_value(&mmio_write(blk + reg::STATUS, v));
        }
        obs.record_value(&mmio_write(blk + reg::QUEUE_READY, 1));
        obs.record_value(&mmio_write(blk + reg::QUEUE_READY, 0));
        assert_eq!(
            obs.stats(WindowKind::Block),
            WindowStats {
                driver_ok_first: Some(0x0F),
                failed_writes: 1,
                status_writes: 6,
                queue_ready_one: 1,
                features_ok_first: Some(0x0B),
                features_ok_writes: 1,
                driver_features: None,
                driver_features_bad_sel: 0,
            }
        );
        assert_eq!(obs.stats(WindowKind::Net), WindowStats::default());
        obs.record_value(&mmio_write(net + reg::QUEUE_READY, 1));
        assert_eq!(obs.stats(WindowKind::Net).queue_ready_one, 1);
    }

    /// FEATURES_OK 時点の driver features をページ順に依らず組み立てる（旧 `mvm1_4234_*` の移動。KVM・HVF 共通）。
    #[test]
    fn mvm5_4289_window_assembles_driver_features_at_features_ok() {
        let obs = VirtioWindows::new();
        let (blk, net) = (0xd000_0000u64, 0xd000_1000u64);
        obs.bind(WindowKind::Block, blk, 0x1000);
        obs.bind(WindowKind::Net, net, 0x1000);
        let w = |base: u64, off: u64, v: u32| obs.record_value(&mmio_write(base + off, v));
        w(blk, reg::STATUS, 0);
        w(blk, reg::STATUS, 1);
        w(blk, reg::STATUS, 3);
        w(blk, reg::DRIVER_FEATURES_SEL, 1);
        w(blk, reg::DRIVER_FEATURES, 0x1);
        w(blk, reg::DRIVER_FEATURES_SEL, 0);
        w(blk, reg::DRIVER_FEATURES, 0x0000_0206);
        w(blk, reg::STATUS, 0x0B);
        w(blk, reg::STATUS, 0x0F);
        let b = obs.stats(WindowKind::Block);
        assert_eq!(b.driver_features, Some(0x0000_0001_0000_0206));
        assert_eq!(b.features_ok_first, Some(0x0B));
        assert_eq!(b.features_ok_writes, 1);
        assert_eq!(b.driver_ok_first, Some(0x0F));
        assert_features_negotiated(&b, BLOCK_OFFERED_LOW, "block", "unit");
        assert_eq!(obs.stats(WindowKind::Net).driver_features, None);
        w(net, reg::DRIVER_FEATURES_SEL, 0);
        w(net, reg::DRIVER_FEATURES, 0x20);
        w(net, reg::DRIVER_FEATURES_SEL, 1);
        w(net, reg::DRIVER_FEATURES, 0x1);
        w(net, reg::STATUS, 0x0B);
        let n = obs.stats(WindowKind::Net);
        assert_eq!(n.driver_features, Some(0x0000_0001_0000_0020));
        assert_features_negotiated(&n, NET_OFFERED_LOW, "net", "unit");
        // reset してもスナップショットは残り、2 回目の FEATURES_OK でも上書きしない（件数だけ増える）。
        w(net, reg::STATUS, 0);
        w(net, reg::DRIVER_FEATURES_SEL, 1);
        w(net, reg::DRIVER_FEATURES, 0x101);
        w(net, reg::DRIVER_FEATURES_SEL, 0);
        w(net, reg::DRIVER_FEATURES, 0);
        w(net, reg::STATUS, 0x0B);
        let n = obs.stats(WindowKind::Net);
        assert_eq!(n.driver_features, Some(0x0000_0001_0000_0020));
        assert_eq!(n.features_ok_writes, 2);
        // sel=2 はページに入らず数えるだけ。
        w(blk, reg::DRIVER_FEATURES_SEL, 2);
        w(blk, reg::DRIVER_FEATURES, 0xffff_ffff);
        let b = obs.stats(WindowKind::Block);
        assert_eq!(b.driver_features_bad_sel, 1);
        assert_eq!(b.driver_features, Some(0x0000_0001_0000_0206));
    }

    /// 片方のページしか書かずに FEATURES_OK を書いた窓は features を組まない。
    #[test]
    fn mvm5_4289_window_single_page_does_not_assemble_features() {
        let obs = VirtioWindows::new();
        let blk = 0xd000_0000u64;
        obs.bind(WindowKind::Block, blk, 0x1000);
        obs.record_value(&mmio_write(blk + reg::DRIVER_FEATURES_SEL, 1));
        obs.record_value(&mmio_write(blk + reg::DRIVER_FEATURES, 1));
        obs.record_value(&mmio_write(blk + reg::STATUS, 0x0B));
        let b = obs.stats(WindowKind::Block);
        assert_eq!(b.driver_features, None);
        assert_eq!(b.features_ok_first, Some(0x0B));
        assert_eq!(
            features_result_fields("", &b),
            "features_ok=0x0b driver_features=none ring_reset=none"
        );
    }

    /// ビット 40 の判定と結果行の書式（陽性対照つき）。
    #[test]
    fn mvm5_4289_ring_reset_bit_and_result_fields() {
        let f = assemble_driver_features(0x20, 0x1);
        assert_eq!(f, 0x0000_0001_0000_0020);
        assert_eq!(feature_bit(f, 40), 0);
        assert_eq!(feature_bit(assemble_driver_features(0x20, 0x101), 40), 1);
        assert_eq!(feature_bit(f, 64), 0);
        assert_eq!(VIRTIO_F_RING_RESET_BIT, 40);
        let s = WindowStats {
            driver_ok_first: Some(0x0F),
            failed_writes: 0,
            status_writes: 5,
            queue_ready_one: 1,
            features_ok_first: Some(0x0B),
            features_ok_writes: 1,
            driver_features: Some(f),
            driver_features_bad_sel: 0,
        };
        assert_eq!(
            features_result_fields("", &s),
            "features_ok=0x0b driver_features=0x0000000100000020 ring_reset=0"
        );
        assert_eq!(
            features_result_fields("net_", &s),
            "net_features_ok=0x0b net_driver_features=0x0000000100000020 net_ring_reset=0"
        );
        assert_eq!(
            features_result_fields("", &WindowStats::default()),
            "features_ok=none driver_features=none ring_reset=none"
        );
        // STATUS の各ビットの定数を参照（取り込み側が使わなくても dead_code にしない）。
        assert_eq!(STATUS_DRIVER_OK | STATUS_FEATURES_OK | STATUS_FAILED, 140);
    }
}
