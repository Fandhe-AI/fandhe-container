//! 実 Linux カーネルの起動完走の結合試験（MVM-1・REPAIR-5・REPAIR-12・TASK-75.5・#3771）。`--ignored` 指定時だけ走る。
//! 入力検査・ゲスト出力の照合は `support/guest_boot.rs` と共有する（macOS の `hvf_kernel_boot.rs` と同じ。#3986・MVM-5・REPAIR-1）。
//!
//! これまでの実機前提試験（`microvm.rs` 等）は合成ペイロードだけを動かす。本試験は利用者が用意した x86_64 の
//! bzImage と、#3770 の最小 initrd（`scripts/build-microvm-test-initrd.sh`）で `MicroVm::assemble` →
//! `load_kernel` → `start` を通し、実カーネルが userspace の `/init` まで到達してゲスト起因で止まることを照合する。
//!
//! 必要環境: Linux x86_64・`/dev/kvm` の読み書き権限（root 不要）・bzImage・`make microvm-test-initrd-build` の出力。
//! 環境変数: `FANDHE_CONTAINER_MICROVM_KERNEL`（必須）・`_INITRD`・`_CMDLINE`・`_BOOT_TIMEOUT_SECS`（任意。既定は定数参照）。
//!
//! 観測手段: ゲストの `/init` が COM1 へ書く固定文字列（`MARKER`）を `SerialConsole` から行単位でちょうど 1 回数え、
//! 停止理由が `StopReason::GuestShutdown`（`/init` の `reboot(RESTART)` → `reboot=t` の triple fault → `KVM_EXIT_SHUTDOWN`）、
//! 起点が vCPU 0、エラー 0 件、UART の取りこぼし 0 バイトであることを具体値で照合する。期限切れで `stop` した
//! `Requested` は合格にしない（失敗の診断経路）。
//!
//! 全体期限（REPAIR-5）: `.cargo/config.toml` の watchdog は `--ignored` を素通しするため、本試験自身の
//! ポーリング期限・`stop` の期限・外側の `recv_timeout` が唯一の層になる。前提欠如は skip せず
//! `kernel_boot: PRECONDITION FAILED (test environment, not a regression)` で落とす。
//! ただし `KvmDevice::open` の失敗は、環境を示すコード（`NOT_FOUND`・`PERMISSION_DENIED`・`UNIMPLEMENTED`）のときだけこの行で落とし、
//! それ以外は `kernel_boot: open: ...` の別の 1 行目で落とす（回帰を環境の問題に見せない。`support/kvm_precondition.rs`・#3992）。
//!
//! 追加の構成（#3865・MVM-1・REPAIR-12。いずれも同じ実機前提の形）:
//! - vCPU 2 台: MP テーブル（#3888。`mptable_x86`）で AP が Linux にオンラインになる。2 台構成で最後まで起動し、
//!   BSP 起因の停止で 2 台とも回収される（`vcpu_count` = 2・起点 vCPU 0）ことに加え、`smp: Brought up 1 node, 2 CPUs` の行が
//!   ちょうど 1 回出ることを照合する。
//! - virtio-block 1 台（1 MiB・読み取り専用）: 起動元は initrd のまま。観測器が STATUS への書き込みで DRIVER_OK を含む
//!   最初の値 `0x0F`・FAILED 0 件・QUEUE_READY=1 の回数 1 を、backend が `read_at` 1 回以上かつ offset 0 を読んだ回 1 回以上を照合する。
//! - virtio-block の中身の照合（#3889・MVM-1・REPAIR-12）: `MICROVM_TEST_INITRD_VARIANT=block-read make microvm-test-initrd-build`
//!   の initrd（`FANDHE_CONTAINER_MICROVM_BLOCK_INITRD`。既定 `target/microvm-test-initrd/x86_64-block-read/initrd.cpio`）は、
//!   `/dev/vda` の先頭 512 バイトを読み、先頭 32 バイトが `BLOCK_SENTINEL` と一致したときだけ `BLOCK_OK_MARKER` を出す
//!   （不一致・失敗は `BLOCK_MISMATCH_MARKER`）。backend の offset 0 に sentinel を置いた構成で一致 marker 1 回・不一致 0 回、
//!   0 埋めの構成（陰性対照）で不一致 marker 1 回・一致 0 回を照合し、ゲストに中身が届いたことを end-to-end で示す。
//!   カーネルには `CONFIG_DEVTMPFS=y` が要る（init が `/dev` に devtmpfs をマウントする）。
//! - virtio-net 1 台: STATUS の DRIVER_OK `0x0F`・FAILED 0 件・QUEUE_READY=1 の回数 2（receiveq・transmitq）。既定の initrd
//!   には interface を上げる userspace が無いので、この試験では RX・TX を照合しない。
//! - virtio-net の TX の照合（#3894・MVM-1・REPAIR-12）: `MICROVM_TEST_INITRD_VARIANT=net-tx make microvm-test-initrd-build`
//!   の initrd（`FANDHE_CONTAINER_MICROVM_NET_TX_INITRD`。既定 `target/microvm-test-initrd/x86_64-net-tx/initrd.cpio`）は、
//!   AF_PACKET で `eth0` を上げて固定フレーム（`NET_TX_FRAME`・60 バイト）を 1 回送り、`sendto` が 60 を返したときだけ
//!   `NET_TX_OK_MARKER` を出す（失敗は `NET_TX_FAILED_MARKER`）。backend が受けたフレームの中に `NET_TX_FRAME` と完全一致する
//!   ものが 1 件以上あることを照合する（カーネルが IPv6 の RS 等を出すことがあるため、一致以外のフレームは許す）。
//!   net 0 台の陰性対照では `SIOCGIFINDEX` が失敗し、失敗 marker が出ることを照合する。
//!   カーネルには `CONFIG_PACKET=y` が要る。
//! - virtio-net の RX の照合（#3919・MVM-1・REPAIR-12）: `MICROVM_TEST_INITRD_VARIANT=net-rx make microvm-test-initrd-build`
//!   の initrd（`FANDHE_CONTAINER_MICROVM_NET_RX_INITRD`。既定 `target/microvm-test-initrd/x86_64-net-rx/initrd.cpio`）は、
//!   AF_PACKET（protocol 0x88B6）で `eth0` を上げ、`SO_RCVTIMEO` 5 秒で `recvfrom` し、`NET_RX_FRAME`（60 バイト）と完全一致
//!   したときだけ `NET_RX_OK_MARKER` を出す（期限切れ・失敗・不一致 16 回は `NET_RX_FAILED_MARKER`）。陽性は backend に
//!   フレームを 1 件積んでおく構成で、ok marker 1 回・failed 0 回・`delivered == 1` を照合する。積むのは起動前だが、
//!   受信ポーラー（`interrupt::poll_net_rx`）は DRIVER_OK と receiveq の ready が揃うまで `recv` を呼ばないので、渡るのは
//!   DRIVER_OK の後になる（ゲストの受信バッファがまだ無ければ device が 1 件を保持して次の poll で配送する）。Linux の NAPI は
//!   IFF_UP で有効になり、`/init` は IFF_UP より前に socket を作る。陰性対照は virtio-net はあるがフレームを積まない構成で、
//!   failed marker 1 回・ok 0 回・`delivered == 0` を照合する（ゲストの待ちは約 5 秒 1 回）。この陰性対照だけでは
//!   「AF_PACKET が使えず早く失敗した」場合と区別できないため、陽性と同じ実行（`--test-threads=1`）で回すこと。
//!
//! 既知のリスク（起動が止まったときの切り分け）: `crates/microvm/src` には PIT・RTC・i8042 のモデルが無く、未登録 PIO の
//! IN は 0xFF 埋めになる。IRQ 4 も未実装（8250 はポーリングに落ちる想定）。MP テーブル（#3888）でゲストは
//! IOAPIC モードになり、Linux の `check_timer` が PIT 無しで失敗して止まる可能性が高い。止まる場合は `_CMDLINE` で
//! `no_timer_check`（必要なら `tsc=reliable`）を試し、原因ごとに別 issue にする。virtio の probe が失敗した場合も試験の欠陥ではなく
//! device model 側の別 issue として扱う。
//! aarch64 は `mod arm64`（#3897・#3898。陽性と initrd 無しの負の対照の 2 件。`console=ttyS0` で FDT の `ns16550a` を選び、
//! marker ちょうど 1 回・UART の取りこぼし 0 を照合する。vCPU 2 台の陽性 1 件を #3899 で足し、3 件。2 台は `SMP: Total of 2 processors activated.`・`smp: Brought up 1 node, 2 CPUs`・`CPU1: Booted secondary processor 0x0000000001` を照合する）。シリアルは SPI 1（INTID 33）の level 割り込み
//! （FDT は `interrupts = <0 1 4>`。`KVM_IRQ_LINE` で結線。#3943）で、送信は THRE 割り込みで進む（以前の割り込みなしのポーリングでは
//! 送信が timer の周期にしか進まず、reboot 直前の marker が出切らず 0 回になりえた）。それでも marker 0 回で落ちた場合は #3781 で観測する。
//! 陽性は `ttyS0 at MMIO 0x9000000 (irq = N, ...)` の行がちょうど 1 行で `N != 0` であることも照合する（#3958。ポーリングへの退行の検出）。
//! aarch64 の virtio-block（#3947・MVM-1・REPAIR-12）: `MICROVM_TEST_INITRD_ARCH=aarch64 MICROVM_TEST_INITRD_VARIANT=block-read
//! make microvm-test-initrd-build` の initrd（`FANDHE_CONTAINER_MICROVM_BLOCK_INITRD`。既定
//! `target/microvm-test-initrd/aarch64-block-read/initrd.cpio`）で、陽性（sentinel あり）・負の対照（block デバイス無し）・
//! 陰性対照（0 埋め）の 3 件を足す。割り込みは FDT の既定の edge-rising の SPI。カーネルは `CONFIG_VIRTIO_MMIO`（DT 経由で
//! `_CMDLINE_DEVICES` は不要）・`CONFIG_VIRTIO_BLK`・`CONFIG_BLOCK`・`CONFIG_DEVTMPFS` が要る。
//! aarch64 の virtio-net（#3957・MVM-1・REPAIR-12）: 既定の initrd と観測器（`VirtioWindowObserver`。x86_64 と共有）で、net 1 台の陽性
//! （DRIVER_OK `0x0F`・FAILED 0 件・QUEUE_READY=1 の回数 2）・net 0 台の負の対照（組み立て済みの net 0 件・観測値すべて 0）・
//! block+net の窓の区別（block は QUEUE_READY 1 回・net は 2 回）の 3 件を足す。カーネルには `CONFIG_NET`・`CONFIG_NETDEVICES`・
//! `CONFIG_VIRTIO_NET` も要る。実機の記録は #3781（Agent は実カーネルで未確認）。
//! aarch64 の net-tx・net-rx（#3966・MVM-1・REPAIR-12）: 専用 initrd（`MICROVM_TEST_INITRD_ARCH=aarch64 MICROVM_TEST_INITRD_VARIANT=net-tx|net-rx`。
//! 環境変数 `FANDHE_CONTAINER_MICROVM_NET_TX_INITRD`・`_NET_RX_INITRD`）で TX・RX の中身を照合する。TX は backend が受けた
//! フレームに `NET_TX_FRAME` と完全一致するものがあること、RX は積んだ `NET_RX_FRAME` がちょうど 1 件配送されゲストが完全一致で
//! 受けたことを、marker 行の回数・DRIVER_OK・QUEUE_READY とあわせて見る（陽性と負の対照が各 1 件）。カーネルには `CONFIG_PACKET` も要る。
//! 実機での実行と記録は #3781（人間担当）。Agent は実カーネルでの起動を確かめていない。
#![cfg(target_os = "linux")]

/// 前提欠如と回帰の振り分けの正本（環境を示すコードだけ前提欠如にする。#3992）。
#[path = "support/kvm_precondition.rs"]
mod kvm_precondition;

/// `KvmDevice::open` の失敗を、環境を示すコードだけ `PRECONDITION FAILED` にして落とす（MVM-1・REPAIR-4・#3992）。
/// 呼び出しはテストスレッドのまま行う（worker 内 panic では 1 行目が変わるため）。
fn open_kvm() -> fandhe_container_microvm::device::KvmDevice {
    fandhe_container_microvm::device::KvmDevice::open()
        .unwrap_or_else(|e| panic!("{}", kvm_precondition::open_failure_line("kernel_boot", &e)))
}

// macOS の `hvf_kernel_boot.rs` と共有する補助（入力検査・ゲスト出力の照合。#3986・MVM-5・REPAIR-1）。
// `#[path]` の基準が変わるため、インライン module の中ではなくファイルの先頭に置く。
/// `/init` が出す固定文字列。正本は `scripts/build-microvm-test-initrd.sh` の `init_message`（単体テストで照合）。
/// x86_64 と aarch64 の試験が共有する（#3898。複製しない・REPAIR-1）。
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
#[path = "support/guest_boot.rs"]
mod guest_boot;
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
use guest_boot::{MARKER, count_lines_ending_with, count_marker_lines, escape_tail};

/// block-read の initrd が `/dev/vda` の先頭と比べる 32 バイト。正本は `scripts/build-microvm-test-initrd.sh` の
/// `block_sentinel`（x86 の単体テストで照合）。x86_64 と aarch64（#3947）の試験が共有する（複製しない・REPAIR-1）。
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
const BLOCK_SENTINEL: &[u8; 32] = b"fandhe-microvm-block-sentinel-01";
/// sentinel 一致時に block-read の `/init` が出す固定文字列（正本は同スクリプトの `block_ok_message`）。
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
const BLOCK_OK_MARKER: &str = "fandhe-microvm-test: block sentinel ok v1";
/// 不一致・読み出し失敗時に出す固定文字列（正本は同スクリプトの `block_mismatch_message`）。
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
const BLOCK_MISMATCH_MARKER: &str = "fandhe-microvm-test: block sentinel mismatch v1";

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
use fandhe_container_microvm::device::{RunObserver, RunOutcome, RunRecord};
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
use fandhe_container_microvm::exit::{ExitData, ExitValue};
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
use fandhe_container_microvm::microvm::VirtioDeviceKind;
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
use fandhe_container_microvm::virtio_mmio::reg;
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
use std::time::Duration;

// x86_64・aarch64 の virtio-net 試験が共有する観測器（#3957。複製しない・REPAIR-1）。
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
/// MMIO の窓 1 つ分の観測値（virtio-mmio の STATUS・QUEUE_READY への書き込み）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct WindowStats {
    /// DRIVER_OK を含む最初の STATUS 書き込みの値。
    driver_ok_first: Option<u32>,
    /// FAILED を含む STATUS 書き込みの件数。
    failed_writes: u64,
    /// STATUS への 4 バイト書き込みの総数。
    status_writes: u64,
    /// QUEUE_READY へ値 1 を書いた回数。
    queue_ready_one: u64,
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
/// 窓 1 つ分の atomic カウンタ（`len == 0` は未設定）。
#[derive(Debug, Default)]
struct Window {
    base: AtomicU64,
    len: AtomicU64,
    driver_ok_first: AtomicU64,
    failed_writes: AtomicU64,
    status_writes: AtomicU64,
    queue_ready_one: AtomicU64,
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
const NO_VALUE: u64 = u64::MAX;
/// virtio 仕様 2.1 の Device Status ビット（DRIVER_OK = 4・FAILED = 128）。
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
const STATUS_DRIVER_OK: u32 = 4;
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
const STATUS_FAILED: u32 = 128;
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
/// virtio-net に見せる固定の locally administered なダミー MAC。
const NET_MAC: [u8; 6] = [0x02, 0xfc, 0x00, 0x00, 0x38, 0x65];

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn window_index(kind: VirtioDeviceKind) -> usize {
    match kind {
        VirtioDeviceKind::Block => 0,
        _ => 1,
    }
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
/// vCPU スレッドから同期で呼ばれ、virtio-mmio の窓への書き込みを atomic で数える観測器（#3865・MVM-1）。
/// `record` では割り当ても待ちもしない。値はゲスト由来（untrusted）で、範囲外は数えるだけにする。
#[derive(Debug)]
struct VirtioWindowObserver {
    /// 0 = virtio-block、1 = virtio-net。
    windows: [Window; 2],
    exits: AtomicU64,
    /// vCPU 0 以外（AP）の exit 件数（診断用）。
    ap_exits: AtomicU64,
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
impl VirtioWindowObserver {
    fn new() -> Self {
        let obs = Self {
            windows: [Window::default(), Window::default()],
            exits: AtomicU64::new(0),
            ap_exits: AtomicU64::new(0),
        };
        for w in &obs.windows {
            w.driver_ok_first.store(NO_VALUE, Ordering::Relaxed);
        }
        obs
    }

    fn bind(&self, kind: VirtioDeviceKind, base: u64, len: u64) {
        if let Some(w) = self.windows.get(window_index(kind)) {
            w.base.store(base, Ordering::Relaxed);
            w.len.store(len, Ordering::Relaxed);
        }
    }

    fn stats(&self, kind: VirtioDeviceKind) -> WindowStats {
        let w = &self.windows[window_index(kind)];
        let first = w.driver_ok_first.load(Ordering::Relaxed);
        WindowStats {
            driver_ok_first: u32::try_from(first).ok(),
            failed_writes: w.failed_writes.load(Ordering::Relaxed),
            status_writes: w.status_writes.load(Ordering::Relaxed),
            queue_ready_one: w.queue_ready_one.load(Ordering::Relaxed),
        }
    }
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
impl RunObserver for VirtioWindowObserver {
    fn record(&self, record: &RunRecord) {
        if let RunOutcome::Exit(_) = record.outcome {
            self.exits.fetch_add(1, Ordering::Relaxed);
            if record.vcpu_id != 0 {
                self.ap_exits.fetch_add(1, Ordering::Relaxed);
            }
        }
        let Some(ExitValue::Mmio {
            phys_addr,
            is_write: true,
            data,
            ..
        }) = record.value
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
            }
        }
    }

    fn wants_values(&self) -> bool {
        true
    }
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn synthetic_mmio_write(vcpu_id: u32, addr: u64, value: u32) -> RunRecord {
    RunRecord {
        vcpu_id,
        outcome: RunOutcome::Exit("mmio"),
        elapsed: Duration::ZERO,
        value: Some(ExitValue::Mmio {
            phys_addr: addr,
            len: 4,
            is_write: true,
            data: ExitData::from_slice(&value.to_le_bytes()),
        }),
    }
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
#[test]
fn mvm1_3865_observer_counts_status_and_queue_ready() {
    let obs = VirtioWindowObserver::new();
    let (blk, net) = (0xd000_0000u64, 0xd000_1000u64);
    obs.bind(VirtioDeviceKind::Block, blk, 0x1000);
    obs.bind(VirtioDeviceKind::Net, net, 0x1000);
    // 窓の外・読み出し・値なしは数えない。
    obs.record(&synthetic_mmio_write(0, 0xd000_2000 + reg::STATUS, 0x0F));
    obs.record(&synthetic_mmio_write(0, 0xcfff_f000, 0x0F));
    let mut read = synthetic_mmio_write(0, blk + reg::STATUS, 0x0F);
    if let Some(ExitValue::Mmio { is_write, .. }) = read.value.as_mut() {
        *is_write = false;
    }
    obs.record(&read);
    let mut none = synthetic_mmio_write(0, blk + reg::STATUS, 0x0F);
    none.value = None;
    obs.record(&none);
    let zero = WindowStats {
        driver_ok_first: None,
        failed_writes: 0,
        status_writes: 0,
        queue_ready_one: 0,
    };
    assert_eq!(obs.stats(VirtioDeviceKind::Block), zero);
    assert_eq!(obs.stats(VirtioDeviceKind::Net), zero);
    // block: ACK→DRIVER→FEATURES_OK→DRIVER_OK の順。DRIVER_OK を含む最初の値が残る。
    for v in [0u32, 1, 3, 11, 15, 0x8F] {
        obs.record(&synthetic_mmio_write(0, blk + reg::STATUS, v));
    }
    obs.record(&synthetic_mmio_write(0, blk + reg::QUEUE_READY, 1));
    obs.record(&synthetic_mmio_write(0, blk + reg::QUEUE_READY, 0));
    assert_eq!(
        obs.stats(VirtioDeviceKind::Block),
        WindowStats {
            driver_ok_first: Some(0x0F),
            failed_writes: 1,
            status_writes: 6,
            queue_ready_one: 1,
        }
    );
    // net の窓は取り違えない。
    assert_eq!(obs.stats(VirtioDeviceKind::Net), zero);
    obs.record(&synthetic_mmio_write(1, net + reg::QUEUE_READY, 1));
    obs.record(&synthetic_mmio_write(0, net + reg::QUEUE_READY, 1));
    assert_eq!(obs.stats(VirtioDeviceKind::Net).queue_ready_one, 2);
    assert_eq!(obs.stats(VirtioDeviceKind::Block).queue_ready_one, 1);
    assert_eq!(obs.ap_exits.load(Ordering::Relaxed), 1);
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
use fandhe_container_microvm::error::MicrovmError;
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
use fandhe_container_microvm::virtio_net::{MAX_MEMORY_FRAMES, MemoryNetBackend, NetBackend};
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
use std::sync::{Arc, Mutex};

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
/// net-tx の initrd が成功時・失敗時に出す固定文字列。正本は `scripts/build-microvm-test-initrd.sh` の
/// `net_tx_ok_message`・`net_tx_failed_message`（単体テストで照合）。
const NET_TX_OK_MARKER: &str = "fandhe-microvm-test: net tx ok v1";
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
const NET_TX_FAILED_MARKER: &str = "fandhe-microvm-test: net tx failed v1";
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
/// net-tx の initrd が送る固定の Ethernet フレーム（60 バイト）。宛先 02:fc:00:00:38:66・送信元は `NET_MAC`・
/// EtherType 0x88B5（IEEE 802 Local Experimental）・ペイロード 46 バイト。正本はスクリプトの `net_tx_frame_header_hex`
/// と `net_tx_payload`（単体テストで照合）。
const NET_TX_FRAME: [u8; 60] = [
    0x02, 0xfc, 0x00, 0x00, 0x38, 0x66, 0x02, 0xfc, 0x00, 0x00, 0x38, 0x65, 0x88, 0xb5, b'f', b'a',
    b'n', b'd', b'h', b'e', b'-', b'm', b'i', b'c', b'r', b'o', b'v', b'm', b'-', b'n', b'e', b't',
    b'-', b't', b'x', b'-', b'p', b'a', b'y', b'l', b'o', b'a', b'd', b'-', b'0', b'1', b'2', b'3',
    b'4', b'5', b'6', b'7', b'8', b'9', b'a', b'b', b'c', b'd', b'e', b'f',
];
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
/// net-rx の initrd が成功時・失敗時に出す固定文字列。正本は `scripts/build-microvm-test-initrd.sh` の
/// `net_rx_ok_message`・`net_rx_failed_message`（単体テストで照合）。
const NET_RX_OK_MARKER: &str = "fandhe-microvm-test: net rx ok v1";
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
const NET_RX_FAILED_MARKER: &str = "fandhe-microvm-test: net rx failed v1";
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
/// net-rx の initrd が待ち受ける固定の Ethernet フレーム（60 バイト）。宛先は `NET_MAC`（eth0 の MAC）・
/// 送信元 02:fc:00:00:38:66・EtherType 0x88B6・ペイロード 46 バイト。正本はスクリプトの `net_rx_frame_header_hex`
/// と `net_rx_payload`（単体テストで照合）。
const NET_RX_FRAME: [u8; 60] = [
    0x02, 0xfc, 0x00, 0x00, 0x38, 0x65, 0x02, 0xfc, 0x00, 0x00, 0x38, 0x66, 0x88, 0xb6, b'f', b'a',
    b'n', b'd', b'h', b'e', b'-', b'm', b'i', b'c', b'r', b'o', b'v', b'm', b'-', b'n', b'e', b't',
    b'-', b'r', b'x', b'-', b'p', b'a', b'y', b'l', b'o', b'a', b'd', b'-', b'0', b'1', b'2', b'3',
    b'4', b'5', b'6', b'7', b'8', b'9', b'a', b'b', b'c', b'd', b'e', b'f',
];

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
/// 送信件数・受信試行回数と、受けたフレームの写し（#3894。保持は `MAX_MEMORY_FRAMES` 件まで）。
#[derive(Debug, Default)]
struct NetCounters {
    sent: AtomicU64,
    recv_calls: AtomicU64,
    /// `recv` がフレームを返した回数（#3919。ホストからゲストへ渡した件数）。
    delivered: AtomicU64,
    frames: Mutex<Vec<Vec<u8>>>,
    dropped: AtomicU64,
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
impl NetCounters {
    /// フレームを写す。上限を超えた分は保持せず `dropped` だけ数える（無制限の確保をしない）。
    fn capture(&self, frame: &[u8]) {
        let mut g = self.frames.lock().unwrap_or_else(|e| e.into_inner());
        if g.len() >= MAX_MEMORY_FRAMES {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        } else {
            g.push(frame.to_vec());
        }
    }
    fn snapshot(&self) -> Vec<Vec<u8>> {
        self.frames
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
#[derive(Debug)]
struct CountingNetBackend {
    inner: MemoryNetBackend,
    counters: Arc<NetCounters>,
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
impl CountingNetBackend {
    fn new() -> (Self, Arc<NetCounters>) {
        let counters = Arc::new(NetCounters::default());
        (
            Self {
                inner: MemoryNetBackend::new(),
                counters: counters.clone(),
            },
            counters,
        )
    }
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
impl CountingNetBackend {
    /// 起動前にフレームを 1 件積んだ backend（#3919。net-rx の陽性）。配送は受信ポーラーが DRIVER_OK の後に行う。
    fn with_inbound(frame: &[u8]) -> (Self, Arc<NetCounters>) {
        let (mut b, c) = Self::new();
        b.inner
            .push_inbound(frame)
            .expect("push a fixed 60-byte frame");
        (b, c)
    }
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
impl NetBackend for CountingNetBackend {
    fn send(&mut self, frame: &[u8]) -> Result<(), MicrovmError> {
        self.counters.sent.fetch_add(1, Ordering::Relaxed);
        self.counters.capture(frame);
        self.inner.send(frame)
    }
    fn recv(&mut self, buf: &mut [u8]) -> Result<Option<usize>, MicrovmError> {
        self.counters.recv_calls.fetch_add(1, Ordering::Relaxed);
        let r = self.inner.recv(buf);
        if matches!(r, Ok(Some(_))) {
            self.counters.delivered.fetch_add(1, Ordering::Relaxed);
        }
        r
    }
}
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
/// 先頭 `n` バイトの 16 進表記（診断用）。
fn hex_prefix(b: &[u8], n: usize) -> String {
    b.iter().take(n).map(|x| format!("{x:02x}")).collect()
}

/// net の固定フレーム・marker・計数 backend の単体試験（KVM 不要。x86_64・aarch64 のどちらでも既定で走る。MVM-1・REPAIR-12・#3966）。
#[cfg(all(test, any(target_arch = "x86_64", target_arch = "aarch64")))]
mod net_fixture_tests {
    use super::{
        CountingNetBackend, NET_MAC, NET_RX_FAILED_MARKER, NET_RX_FRAME, NET_RX_OK_MARKER,
        NET_TX_FAILED_MARKER, NET_TX_FRAME, NET_TX_OK_MARKER,
    };
    use fandhe_container_microvm::virtio_net::{MAX_MEMORY_FRAMES, NetBackend};
    use std::path::Path;
    use std::sync::atomic::Ordering;

    #[test]
    fn mvm1_3894_net_tx_strings_match_initrd_script() {
        let script = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../scripts/build-microvm-test-initrd.sh");
        let text = std::fs::read_to_string(script).unwrap();
        let find = |prefix: &str| -> Vec<String> {
            text.lines()
                .filter_map(|l| l.strip_prefix(prefix))
                .filter_map(|l| l.strip_suffix('"'))
                .map(str::to_owned)
                .collect()
        };
        let header = find("net_tx_frame_header_hex=\"");
        let payload = find("net_tx_payload=\"");
        assert_eq!(header.len(), 1);
        assert_eq!(payload.len(), 1);
        let hdr = header.first().unwrap();
        let mut frame: Vec<u8> = (0..hdr.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(hdr.get(i..i + 2).unwrap(), 16).unwrap())
            .collect();
        assert_eq!(frame.len(), 14);
        frame.extend_from_slice(payload.first().unwrap().as_bytes());
        assert_eq!(frame.as_slice(), &NET_TX_FRAME[..]);
        assert_eq!(NET_TX_FRAME.len(), 60);
        assert_eq!(frame.get(6..12), Some(&NET_MAC[..]));
        assert_eq!(frame.get(12..14), Some(&[0x88, 0xb5][..]));
        assert_eq!(
            find("net_tx_ok_message=\""),
            vec![NET_TX_OK_MARKER.to_owned()]
        );
        assert_eq!(
            find("net_tx_failed_message=\""),
            vec![NET_TX_FAILED_MARKER.to_owned()]
        );
    }

    #[test]
    fn mvm1_3919_net_rx_strings_match_initrd_script() {
        let script = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../scripts/build-microvm-test-initrd.sh");
        let text = std::fs::read_to_string(script).unwrap();
        let find = |prefix: &str| -> Vec<String> {
            text.lines()
                .filter_map(|l| l.strip_prefix(prefix))
                .filter_map(|l| l.strip_suffix('"'))
                .map(str::to_owned)
                .collect()
        };
        let header = find("net_rx_frame_header_hex=\"");
        let payload = find("net_rx_payload=\"");
        assert_eq!(header.len(), 1);
        assert_eq!(payload.len(), 1);
        let hdr = header.first().unwrap();
        let mut frame: Vec<u8> = (0..hdr.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(hdr.get(i..i + 2).unwrap(), 16).unwrap())
            .collect();
        assert_eq!(frame.len(), 14);
        frame.extend_from_slice(payload.first().unwrap().as_bytes());
        assert_eq!(frame.as_slice(), &NET_RX_FRAME[..]);
        assert_eq!(NET_RX_FRAME.len(), 60);
        assert_eq!(frame.get(0..6), Some(&NET_MAC[..]));
        assert_eq!(
            frame.get(6..12),
            Some(&[0x02, 0xfc, 0x00, 0x00, 0x38, 0x66][..])
        );
        assert_eq!(frame.get(12..14), Some(&[0x88, 0xb6][..]));
        assert_ne!(NET_RX_FRAME, NET_TX_FRAME);
        assert_eq!(
            find("net_rx_ok_message=\""),
            vec![NET_RX_OK_MARKER.to_owned()]
        );
        assert_eq!(
            find("net_rx_failed_message=\""),
            vec![NET_RX_FAILED_MARKER.to_owned()]
        );
    }

    #[test]
    fn mvm1_3919_inbound_backend_delivers_once() {
        let (mut b, c) = CountingNetBackend::with_inbound(&NET_RX_FRAME);
        let mut buf = [0u8; 128];
        assert_eq!(b.recv(&mut buf).unwrap(), Some(60));
        assert_eq!(buf.get(..60), Some(&NET_RX_FRAME[..]));
        assert_eq!(b.recv(&mut buf).unwrap(), None);
        assert_eq!(c.delivered.load(Ordering::Relaxed), 1);
        assert_eq!(c.recv_calls.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn mvm1_3894_frame_capturing_backend() {
        let (mut b, c) = CountingNetBackend::new();
        b.send(&NET_TX_FRAME).unwrap();
        b.send(&[0u8; 14]).unwrap();
        assert_eq!(c.sent.load(Ordering::Relaxed), 2);
        let snap = c.snapshot();
        assert_eq!(snap.len(), 2);
        assert_eq!(snap.first().map(Vec::as_slice), Some(&NET_TX_FRAME[..]));
        assert_eq!(snap.get(1).map(Vec::len), Some(14));
        let mut buf = [0u8; 64];
        assert_eq!(b.recv(&mut buf).unwrap(), None);
        // 上限を超えた分は保持せず dropped だけ増える。
        for _ in 0..MAX_MEMORY_FRAMES + 3 {
            c.capture(&[1u8; 14]);
        }
        assert_eq!(c.snapshot().len(), MAX_MEMORY_FRAMES);
        assert_eq!(c.dropped.load(Ordering::Relaxed), 5);
    }
}

#[cfg(target_arch = "x86_64")]
mod x86 {
    use super::guest_boot::{SMP_ONLINE_LINE, read_bounded};
    use super::{
        BLOCK_MISMATCH_MARKER, BLOCK_OK_MARKER, BLOCK_SENTINEL, CountingNetBackend, MARKER,
        NET_MAC, NET_RX_FAILED_MARKER, NET_RX_FRAME, NET_RX_OK_MARKER, NET_TX_FAILED_MARKER,
        NET_TX_FRAME, NET_TX_OK_MARKER, VirtioWindowObserver, count_lines_ending_with,
        count_marker_lines, escape_tail, guest_boot, hex_prefix,
    };
    use fandhe_container_microvm::device::{KvmDevice, RunObserver};
    use fandhe_container_microvm::error::{MicrovmError, MicrovmErrorCode};
    use fandhe_container_microvm::microvm::{
        MicroVm, MicroVmConfig, NetDeviceConfig, StopReason, VirtioDeviceKind,
    };
    use fandhe_container_microvm::virtio_block::{BlockBackend, MemoryBlockBackend};
    use fandhe_container_microvm::virtio_net::{MemoryNetBackend, NetBackend};
    use std::path::Path;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, mpsc};
    use std::time::{Duration, Instant};

    const DEFAULT_CMDLINE: &str = "console=ttyS0 reboot=t";
    const DEFAULT_TIMEOUT_SECS: u64 = 60;
    const KERNEL_CAP: u64 = fandhe_container_microvm::boot_x86::MAX_KERNEL_IMAGE_BYTES;
    const INITRD_CAP: u64 = 64 << 20;
    /// シリアル出力の蓄積上限（無制限確保の防止）。
    const OUTPUT_CAP: usize = 4 << 20;
    const STOP_DEADLINE: Duration = Duration::from_secs(10);
    const SLACK: Duration = Duration::from_secs(15);
    const TAIL_BYTES: usize = 4096;

    /// 前提欠如の panic の 1 行目（CI・人間が見分ける固定形式）。
    fn precondition(reason: &str) -> ! {
        panic!("kernel_boot: PRECONDITION FAILED (test environment, not a regression): {reason}")
    }

    fn parse_boot_timeout(raw: Option<&str>) -> Result<u64, String> {
        guest_boot::parse_boot_timeout_or(raw, DEFAULT_TIMEOUT_SECS)
    }

    fn validate_cmdline(raw: Option<&str>) -> Result<String, String> {
        guest_boot::validate_cmdline_or(raw, DEFAULT_CMDLINE)
    }

    struct Outcome {
        reason: StopReason,
        origin_vcpu: Option<u32>,
        vcpu_count: u32,
        errors: u64,
        exits: u64,
        output: Vec<u8>,
        uart_dropped: u64,
        timed_out: bool,
        elapsed: Duration,
    }

    impl Outcome {
        /// 失敗時の診断文字列。`extra` に観測器・backend のカウンタを載せる。
        fn diag(&self, extra: &str) -> String {
            format!(
                "reason={:?} exits={} elapsed={:?} timed_out={} {extra} serial_tail={}",
                self.reason,
                self.exits,
                self.elapsed,
                self.timed_out,
                escape_tail(&self.output, TAIL_BYTES)
            )
        }
    }

    /// `read_at` の回数・offset 0 を読んだ回数・読んだバイト数・書き込み・flush の件数。
    #[derive(Debug, Default)]
    struct BlockCounters {
        reads: AtomicU64,
        offset0_reads: AtomicU64,
        read_bytes: AtomicU64,
        writes: AtomicU64,
        flushes: AtomicU64,
    }

    /// 呼び出しを数える block backend（ゲストからは読み取り専用）。`start` の後も試験側がカウンタを見られるよう
    /// `Arc` で共有する。`with_sentinel` は offset 0 に sentinel を置く（ゲストの書き込みは wrapper が拒否する）。
    #[derive(Debug)]
    struct CountingBlockBackend {
        inner: MemoryBlockBackend,
        counters: Arc<BlockCounters>,
    }

    impl CountingBlockBackend {
        /// offset 0 に `sentinel` を置いた backend（`None` は 0 埋め）。置くために内側は書き込み可で作り、
        /// `read_only()` を true にして `write_at` は wrapper 自身が拒否する（lib は変えない）。
        fn with_sentinel(capacity: u64, sentinel: Option<&[u8]>) -> (Self, Arc<BlockCounters>) {
            let counters = Arc::new(BlockCounters::default());
            let mut inner = MemoryBlockBackend::new(capacity, false).expect("valid capacity");
            if let Some(s) = sentinel {
                inner.write_at(0, s).expect("sentinel fits in capacity");
            }
            (
                Self {
                    inner,
                    counters: counters.clone(),
                },
                counters,
            )
        }

        fn new(capacity: u64) -> (Self, Arc<BlockCounters>) {
            let counters = Arc::new(BlockCounters::default());
            let inner = MemoryBlockBackend::new(capacity, true).expect("valid capacity");
            (
                Self {
                    inner,
                    counters: counters.clone(),
                },
                counters,
            )
        }
    }

    impl BlockBackend for CountingBlockBackend {
        fn capacity_bytes(&self) -> u64 {
            self.inner.capacity_bytes()
        }
        fn read_only(&self) -> bool {
            true
        }
        fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<(), MicrovmError> {
            self.counters.reads.fetch_add(1, Ordering::Relaxed);
            if offset == 0 {
                self.counters.offset0_reads.fetch_add(1, Ordering::Relaxed);
            }
            self.counters
                .read_bytes
                .fetch_add(buf.len() as u64, Ordering::Relaxed);
            self.inner.read_at(offset, buf)
        }
        fn write_at(&mut self, offset: u64, data: &[u8]) -> Result<(), MicrovmError> {
            self.counters.writes.fetch_add(1, Ordering::Relaxed);
            let _ = (offset, data);
            Err(MicrovmError::new(
                MicrovmErrorCode::PermissionDenied,
                "test block backend is read-only for the guest",
            ))
        }
        fn flush(&mut self) -> Result<(), MicrovmError> {
            self.counters.flushes.fetch_add(1, Ordering::Relaxed);
            self.inner.flush()
        }
    }

    /// 前提の検査済みの入力（カーネル・initrd・cmdline・期限・KVM）。
    struct Inputs {
        dev: KvmDevice,
        kernel: Vec<u8>,
        initrd: Vec<u8>,
        cmdline: String,
        secs: u64,
    }

    /// 使う initrd の種類（`scripts/build-microvm-test-initrd.sh` の variant に対応）。
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum InitrdKind {
        /// 固定文字列を書いて reboot するだけの版（`FANDHE_CONTAINER_MICROVM_INITRD`）。
        Default,
        /// `/dev/vda` の先頭を sentinel と比べる版（`FANDHE_CONTAINER_MICROVM_BLOCK_INITRD`。#3889）。
        BlockRead,
        /// `eth0` を上げて固定フレームを 1 回送る版（`FANDHE_CONTAINER_MICROVM_NET_TX_INITRD`。#3894）。
        NetTx,
        /// `eth0` を上げて固定フレームを受ける版（`FANDHE_CONTAINER_MICROVM_NET_RX_INITRD`。#3919）。
        NetRx,
    }

    fn inputs() -> Inputs {
        inputs_for(InitrdKind::Default)
    }

    /// 前提の検査はすべてテストスレッドで行う（worker 内 panic では 1 行目が PRECONDITION FAILED にならない）。
    fn inputs_for(kind: InitrdKind) -> Inputs {
        let (env_name, default_rel, build_hint) = match kind {
            InitrdKind::Default => (
                "FANDHE_CONTAINER_MICROVM_INITRD",
                "../../target/microvm-test-initrd/x86_64/initrd.cpio",
                "make microvm-test-initrd-build",
            ),
            InitrdKind::BlockRead => (
                "FANDHE_CONTAINER_MICROVM_BLOCK_INITRD",
                "../../target/microvm-test-initrd/x86_64-block-read/initrd.cpio",
                "MICROVM_TEST_INITRD_VARIANT=block-read make microvm-test-initrd-build",
            ),
            InitrdKind::NetTx => (
                "FANDHE_CONTAINER_MICROVM_NET_TX_INITRD",
                "../../target/microvm-test-initrd/x86_64-net-tx/initrd.cpio",
                "MICROVM_TEST_INITRD_VARIANT=net-tx make microvm-test-initrd-build",
            ),
            InitrdKind::NetRx => (
                "FANDHE_CONTAINER_MICROVM_NET_RX_INITRD",
                "../../target/microvm-test-initrd/x86_64-net-rx/initrd.cpio",
                "MICROVM_TEST_INITRD_VARIANT=net-rx make microvm-test-initrd-build",
            ),
        };
        let kernel_path = match std::env::var("FANDHE_CONTAINER_MICROVM_KERNEL") {
            Ok(p) if !p.is_empty() => p,
            _ => precondition(
                "FANDHE_CONTAINER_MICROVM_KERNEL is not set (path to an x86_64 bzImage)",
            ),
        };
        let kernel = read_bounded(Path::new(&kernel_path), KERNEL_CAP)
            .unwrap_or_else(|e| precondition(&format!("kernel image: {e}")));
        let initrd_path = match std::env::var(env_name) {
            Ok(p) if !p.is_empty() => std::path::PathBuf::from(p),
            _ => Path::new(env!("CARGO_MANIFEST_DIR")).join(default_rel),
        };
        let initrd = read_bounded(&initrd_path, INITRD_CAP)
            .unwrap_or_else(|e| precondition(&format!("initrd (run `{build_hint}`): {e}")));
        let cmdline = validate_cmdline(
            std::env::var("FANDHE_CONTAINER_MICROVM_CMDLINE")
                .ok()
                .as_deref(),
        )
        .unwrap_or_else(|e| precondition(&e));
        let secs = parse_boot_timeout(
            std::env::var("FANDHE_CONTAINER_MICROVM_BOOT_TIMEOUT_SECS")
                .ok()
                .as_deref(),
        )
        .unwrap_or_else(|e| precondition(&e));
        let dev = super::open_kvm();
        Inputs {
            dev,
            kernel,
            initrd,
            cmdline,
            secs,
        }
    }

    fn boot<B, N>(
        inp: Inputs,
        config: MicroVmConfig<B, N>,
        observer: Option<Arc<VirtioWindowObserver>>,
        boot_timeout: Duration,
    ) -> Result<Outcome, String>
    where
        B: BlockBackend + Send + 'static,
        N: NetBackend + Send + 'static,
    {
        let started = Instant::now();
        let vcpus = usize::try_from(config.vcpu_count).unwrap_or(0);
        let mut vm: MicroVm<B, N> =
            MicroVm::assemble(&inp.dev, config).map_err(|e| format!("assemble failed: {e}"))?;
        if let Some(obs) = &observer {
            // アドレスは直書きせず、組み立て済みの配置から取る。start は MicroVm を消費するので観測は start の前に付ける。
            for info in vm.devices() {
                obs.bind(info.slot.kind, info.slot.mmio_base, info.slot.mmio_len);
            }
            let dynobs: Arc<dyn RunObserver> = obs.clone();
            for i in 0..vcpus {
                if let Some(v) = vm.vcpu_mut(i) {
                    v.set_observer(dynobs.clone());
                }
            }
        }
        let loaded = vm
            .load_kernel(&inp.kernel, Some(&inp.initrd), &inp.cmdline)
            .map_err(|e| format!("load_kernel failed: {e}"))?;
        let console = vm.serial_console();
        let running = vm
            .start(&loaded)
            .map_err(|e| format!("start failed: {e}"))?;
        let mut output: Vec<u8> = Vec::new();
        let mut timed_out = false;
        loop {
            let chunk = console
                .take_output()
                .map_err(|e| format!("serial read failed: {e}"))?;
            output.extend_from_slice(&chunk);
            if output.len() > OUTPUT_CAP {
                return Err("serial output exceeded 4 MiB".into());
            }
            if running.is_finished() {
                break;
            }
            if started.elapsed() >= boot_timeout {
                timed_out = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let report = running
            .stop(STOP_DEADLINE)
            .map_err(|e| format!("stop failed: {e}"))?;
        let tail = console
            .take_output()
            .map_err(|e| format!("serial read failed: {e}"))?;
        output.extend_from_slice(&tail);
        let stats = console
            .stats()
            .map_err(|e| format!("serial stats failed: {e}"))?;
        Ok(Outcome {
            reason: report.reason,
            origin_vcpu: report.origin_vcpu,
            vcpu_count: report.vcpu_count,
            errors: report.stats.errors,
            exits: report.stats.exits,
            output,
            uart_dropped: stats.dropped_bytes,
            timed_out,
            elapsed: started.elapsed(),
        })
    }

    /// 別スレッドで `boot` を回し、全体期限で必ず戻る（REPAIR-5）。
    fn run_boot<B, N>(
        inp: Inputs,
        config: MicroVmConfig<B, N>,
        observer: Option<Arc<VirtioWindowObserver>>,
    ) -> Outcome
    where
        B: BlockBackend + Send + 'static,
        N: NetBackend + Send + 'static,
    {
        let secs = inp.secs;
        let boot_timeout = Duration::from_secs(secs);
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(boot(inp, config, observer, boot_timeout));
        });
        // REPAIR-5: 止まった vCPU スレッドが残っても、全体期限で必ず試験を終える。
        match rx.recv_timeout(boot_timeout + STOP_DEADLINE + SLACK) {
            Ok(Ok(o)) => o,
            Ok(Err(e)) => panic!("kernel_boot: boot sequence failed: {e}"),
            Err(e) => panic!("kernel_boot: DEADLINE EXCEEDED ({e}) after {secs}s boot budget"),
        }
    }

    /// 全構成で共通の起動の照合（marker 1 回・GuestShutdown・起点 vCPU 0・エラー 0・取りこぼし 0・期限内）。
    fn assert_boot_ok(o: &Outcome, vcpus: u32, diag: &str) {
        assert_boot_ok_with_marker(o, MARKER, vcpus, diag);
    }

    /// `assert_boot_ok` の marker を差し替えられる版（block-read の initrd 用。#3889）。
    fn assert_boot_ok_with_marker(o: &Outcome, marker: &str, vcpus: u32, diag: &str) {
        assert_eq!(
            count_marker_lines(&o.output, marker),
            1,
            "marker line {marker:?}: {diag}"
        );
        assert_eq!(o.reason, StopReason::GuestShutdown, "stop reason: {diag}");
        assert_eq!(o.origin_vcpu, Some(0), "origin vcpu: {diag}");
        assert_eq!(o.vcpu_count, vcpus, "vcpu count: {diag}");
        assert_eq!(o.errors, 0, "run errors: {diag}");
        assert_eq!(o.uart_dropped, 0, "uart dropped bytes: {diag}");
        assert!(!o.timed_out, "boot timed out: {diag}");
    }

    const KCONFIG_HINT: &str = "if counters are zero, check the guest kernel config: CONFIG_VIRTIO_MMIO_CMDLINE_DEVICES, CONFIG_VIRTIO_BLK, CONFIG_VIRTIO_NET, CONFIG_BLOCK, CONFIG_MSDOS_PARTITION, CONFIG_DEVTMPFS, CONFIG_PACKET";

    #[test]
    #[ignore = "requires read/write access to /dev/kvm (MVM-1)"]
    fn kernel_boot_real_kernel_reaches_init_and_shuts_down() {
        let inp = inputs();
        let config: MicroVmConfig<MemoryBlockBackend, MemoryNetBackend> = MicroVmConfig {
            vcpu_count: 1,
            mem_size: 256 << 20,
            block: vec![],
            net: vec![],
        };
        let o = run_boot(inp, config, None);
        let diag = o.diag("");
        assert_boot_ok(&o, 1, &diag);
        eprintln!(
            "kernel_boot: ok reason=guest_shutdown elapsed_ms={} serial_bytes={} exits={}",
            o.elapsed.as_millis(),
            o.output.len(),
            o.exits
        );
    }

    /// vCPU 2 台（#3865・#3888・MVM-1）。MP テーブルで AP が Linux にオンラインになる。2 台構成の VM が実カーネルで最後まで起動し、
    /// BSP 起因の停止で 2 台とも回収されること、`smp: Brought up 1 node, 2 CPUs` の行がちょうど 1 回出ることを照合する。
    #[test]
    #[ignore = "requires read/write access to /dev/kvm (MVM-1)"]
    fn kernel_boot_two_vcpus_reaches_init_and_shuts_down() {
        let inp = inputs();
        let config: MicroVmConfig<MemoryBlockBackend, MemoryNetBackend> = MicroVmConfig {
            vcpu_count: 2,
            mem_size: 256 << 20,
            block: vec![],
            net: vec![],
        };
        let obs = Arc::new(VirtioWindowObserver::new());
        let o = run_boot(inp, config, Some(obs.clone()));
        let smp_online = count_lines_ending_with(&o.output, SMP_ONLINE_LINE);
        let extra = format!(
            "ap_exits={} smp_online_lines={smp_online}",
            obs.ap_exits.load(Ordering::Relaxed)
        );
        let diag = o.diag(&extra);
        assert_boot_ok(&o, 2, &diag);
        assert_eq!(
            smp_online, 1,
            "expected exactly one `{SMP_ONLINE_LINE}` line (MP table must bring the AP online)\n{diag}"
        );
        eprintln!(
            "kernel_boot: ok case=two_vcpus reason=guest_shutdown vcpu_count=2 elapsed_ms={} {extra}",
            o.elapsed.as_millis()
        );
    }

    /// virtio-block 1 台（1 MiB・読み取り専用。#3865・MVM-1）。起動元は initrd のまま、カーネルの virtio_blk の
    /// probe とパーティション走査でブロックが読まれることをホスト側で観測する。
    #[test]
    #[ignore = "requires read/write access to /dev/kvm (MVM-1)"]
    fn kernel_boot_with_virtio_block_reads_disk() {
        let inp = inputs();
        let (backend, counters) = CountingBlockBackend::new(1 << 20);
        let config: MicroVmConfig<CountingBlockBackend, MemoryNetBackend> = MicroVmConfig {
            vcpu_count: 1,
            mem_size: 256 << 20,
            block: vec![backend],
            net: vec![],
        };
        let obs = Arc::new(VirtioWindowObserver::new());
        let o = run_boot(inp, config, Some(obs.clone()));
        let s = obs.stats(VirtioDeviceKind::Block);
        let reads = counters.reads.load(Ordering::Relaxed);
        let off0 = counters.offset0_reads.load(Ordering::Relaxed);
        let extra = format!(
            "block={s:?} reads={reads} offset0_reads={off0} read_bytes={} writes={} flushes={} hint=\"{KCONFIG_HINT}\"",
            counters.read_bytes.load(Ordering::Relaxed),
            counters.writes.load(Ordering::Relaxed),
            counters.flushes.load(Ordering::Relaxed),
        );
        let diag = o.diag(&extra);
        assert_boot_ok(&o, 1, &diag);
        assert_eq!(s.driver_ok_first, Some(0x0F), "block DRIVER_OK: {diag}");
        assert_eq!(s.failed_writes, 0, "block FAILED writes: {diag}");
        assert_eq!(s.queue_ready_one, 1, "block QUEUE_READY=1 count: {diag}");
        assert!(reads >= 1, "block read_at count: {diag}");
        assert!(off0 >= 1, "block offset-0 reads: {diag}");
        eprintln!(
            "kernel_boot: ok case=virtio_block driver_ok=0x0f queue_ready=1 reads={reads} offset0_reads={off0} elapsed_ms={}",
            o.elapsed.as_millis()
        );
    }

    /// block-read の 2 件に共通の本体。`sentinel` を backend の offset 0 に置いて起動し、`expect`（期待する marker）が
    /// ちょうど 1 回・`other`（もう一方の marker）と既定の `MARKER` が 0 回であることを含む共通の照合をする。
    fn run_block_read(sentinel: Option<&[u8]>, expect: &str, other: &str, case: &str) {
        let inp = inputs_for(InitrdKind::BlockRead);
        let (backend, counters) = CountingBlockBackend::with_sentinel(1 << 20, sentinel);
        let config: MicroVmConfig<CountingBlockBackend, MemoryNetBackend> = MicroVmConfig {
            vcpu_count: 1,
            mem_size: 256 << 20,
            block: vec![backend],
            net: vec![],
        };
        let obs = Arc::new(VirtioWindowObserver::new());
        let o = run_boot(inp, config, Some(obs.clone()));
        let s = obs.stats(VirtioDeviceKind::Block);
        let reads = counters.reads.load(Ordering::Relaxed);
        let off0 = counters.offset0_reads.load(Ordering::Relaxed);
        let extra = format!(
            "block={s:?} reads={reads} offset0_reads={off0} writes={} hint=\"{KCONFIG_HINT}\"",
            counters.writes.load(Ordering::Relaxed),
        );
        let diag = o.diag(&extra);
        assert_boot_ok_with_marker(&o, expect, 1, &diag);
        assert_eq!(
            count_marker_lines(&o.output, other),
            0,
            "opposite marker {other:?} must not appear: {diag}"
        );
        assert_eq!(
            count_marker_lines(&o.output, MARKER),
            0,
            "default init marker must not appear with the block-read initrd: {diag}"
        );
        assert_eq!(s.driver_ok_first, Some(0x0F), "block DRIVER_OK: {diag}");
        assert_eq!(s.failed_writes, 0, "block FAILED writes: {diag}");
        assert_eq!(s.queue_ready_one, 1, "block QUEUE_READY=1 count: {diag}");
        // init の read が backend まで届いた回数は照合しない（パーティション走査で sector 0 が page cache に載り
        // init の read が backend に届かないことがあるため）。ゲストに中身が届いた証跡は marker である。
        assert!(reads >= 1, "block read_at count: {diag}");
        assert!(off0 >= 1, "block offset-0 reads: {diag}");
        eprintln!(
            "kernel_boot: ok case={case} marker={expect:?} reads={reads} offset0_reads={off0} elapsed_ms={}",
            o.elapsed.as_millis()
        );
    }

    /// virtio-block の中身の照合（#3889・MVM-1・REPAIR-12）。offset 0 に sentinel を置いた backend を block-read の
    /// initrd で読ませ、`/dev/vda` の先頭がゲストに届いたときだけ出る一致 marker をちょうど 1 回数える。
    #[test]
    #[ignore = "requires read/write access to /dev/kvm (MVM-1)"]
    fn kernel_boot_with_virtio_block_init_reads_sentinel() {
        run_block_read(
            Some(BLOCK_SENTINEL),
            BLOCK_OK_MARKER,
            BLOCK_MISMATCH_MARKER,
            "virtio_block_sentinel",
        );
    }

    /// 陰性対照（#3889）。同じ initrd で backend が 0 埋めのとき不一致 marker が出て一致 marker が出ないこと。
    /// 比較が素通しで一致を出していないことを示す。
    #[test]
    #[ignore = "requires read/write access to /dev/kvm (MVM-1)"]
    fn kernel_boot_with_virtio_block_init_detects_mismatch() {
        run_block_read(
            None,
            BLOCK_MISMATCH_MARKER,
            BLOCK_OK_MARKER,
            "virtio_block_mismatch",
        );
    }

    /// virtio-net 1 台（#3865・MVM-1）。ドライバの probe が DRIVER_OK まで進み、receiveq・transmitq の 2 本が
    /// QUEUE_READY になることを照合する（RX・TX は interface を上げる userspace が無いので照合しない）。
    #[test]
    #[ignore = "requires read/write access to /dev/kvm (MVM-1)"]
    fn kernel_boot_with_virtio_net_reaches_driver_ok() {
        let inp = inputs();
        let (backend, counters) = CountingNetBackend::new();
        let config: MicroVmConfig<MemoryBlockBackend, CountingNetBackend> = MicroVmConfig {
            vcpu_count: 1,
            mem_size: 256 << 20,
            block: vec![],
            net: vec![NetDeviceConfig {
                backend,
                mac: NET_MAC,
            }],
        };
        let obs = Arc::new(VirtioWindowObserver::new());
        let o = run_boot(inp, config, Some(obs.clone()));
        let s = obs.stats(VirtioDeviceKind::Net);
        let extra = format!(
            "net={s:?} sent={} recv_calls={} hint=\"{KCONFIG_HINT}\"",
            counters.sent.load(Ordering::Relaxed),
            counters.recv_calls.load(Ordering::Relaxed),
        );
        let diag = o.diag(&extra);
        assert_boot_ok(&o, 1, &diag);
        assert_eq!(s.driver_ok_first, Some(0x0F), "net DRIVER_OK: {diag}");
        assert_eq!(s.failed_writes, 0, "net FAILED writes: {diag}");
        assert_eq!(s.queue_ready_one, 2, "net QUEUE_READY=1 count: {diag}");
        eprintln!(
            "kernel_boot: ok case=virtio_net driver_ok=0x0f queue_ready=2 elapsed_ms={}",
            o.elapsed.as_millis()
        );
    }

    /// virtio-net の TX の照合（#3894・MVM-1・REPAIR-12）。net-tx の initrd が `eth0` を上げて送った固定フレームが
    /// backend まで届いたことを、完全一致するフレームが 1 件以上あることで示す。
    #[test]
    #[ignore = "requires read/write access to /dev/kvm (MVM-1)"]
    fn kernel_boot_with_virtio_net_init_sends_frame() {
        let inp = inputs_for(InitrdKind::NetTx);
        let (backend, counters) = CountingNetBackend::new();
        let config: MicroVmConfig<MemoryBlockBackend, CountingNetBackend> = MicroVmConfig {
            vcpu_count: 1,
            mem_size: 256 << 20,
            block: vec![],
            net: vec![NetDeviceConfig {
                backend,
                mac: NET_MAC,
            }],
        };
        let obs = Arc::new(VirtioWindowObserver::new());
        let o = run_boot(inp, config, Some(obs.clone()));
        let s = obs.stats(VirtioDeviceKind::Net);
        let frames = counters.snapshot();
        let matched = frames
            .iter()
            .filter(|f| f.as_slice() == NET_TX_FRAME)
            .count();
        let others: Vec<String> = frames
            .iter()
            .filter(|f| f.as_slice() != NET_TX_FRAME)
            .take(4)
            .map(|f| hex_prefix(f, 32))
            .collect();
        let extra = format!(
            "net={s:?} total_frames={} dropped={} matched={matched} other_frames_head={others:?} hint=\"{KCONFIG_HINT}\"",
            frames.len(),
            counters.dropped.load(Ordering::Relaxed),
        );
        let diag = o.diag(&extra);
        assert_boot_ok_with_marker(&o, NET_TX_OK_MARKER, 1, &diag);
        assert_eq!(
            count_marker_lines(&o.output, NET_TX_FAILED_MARKER),
            0,
            "net tx failed marker must not appear: {diag}"
        );
        assert_eq!(
            count_marker_lines(&o.output, MARKER),
            0,
            "default init marker must not appear with the net-tx initrd: {diag}"
        );
        assert_eq!(s.driver_ok_first, Some(0x0F), "net DRIVER_OK: {diag}");
        assert_eq!(s.failed_writes, 0, "net FAILED writes: {diag}");
        assert_eq!(s.queue_ready_one, 2, "net QUEUE_READY=1 count: {diag}");
        assert!(
            matched >= 1,
            "backend received no frame equal to NET_TX_FRAME: {diag}"
        );
        eprintln!(
            "kernel_boot: ok case=virtio_net_tx frames={} matched={matched} elapsed_ms={}",
            frames.len(),
            o.elapsed.as_millis()
        );
    }

    /// 陰性対照（#3894）。net 0 台では `SIOCGIFINDEX` が失敗するので失敗 marker が出て、成功 marker は出ないこと。
    /// marker の区別と init の失敗経路を実カーネルで確かめる。
    #[test]
    #[ignore = "requires read/write access to /dev/kvm (MVM-1)"]
    fn kernel_boot_net_tx_init_without_net_device_reports_failure() {
        let inp = inputs_for(InitrdKind::NetTx);
        let config: MicroVmConfig<MemoryBlockBackend, CountingNetBackend> = MicroVmConfig {
            vcpu_count: 1,
            mem_size: 256 << 20,
            block: vec![],
            net: vec![],
        };
        let o = run_boot(inp, config, None);
        let diag = o.diag(&format!("hint=\"{KCONFIG_HINT}\""));
        assert_boot_ok_with_marker(&o, NET_TX_FAILED_MARKER, 1, &diag);
        assert_eq!(
            count_marker_lines(&o.output, NET_TX_OK_MARKER),
            0,
            "net tx ok marker must not appear without a net device: {diag}"
        );
        eprintln!(
            "kernel_boot: ok case=virtio_net_tx_no_device elapsed_ms={}",
            o.elapsed.as_millis()
        );
    }

    /// virtio-net の RX の照合（#3919・MVM-1・REPAIR-12）。backend に積んだ固定フレームが、受信ポーラー経由で
    /// 実 Linux の virtio_net から AF_PACKET まで届き、initrd が完全一致を確かめて ok marker を出すこと。
    #[test]
    #[ignore = "requires read/write access to /dev/kvm (MVM-1)"]
    fn kernel_boot_with_virtio_net_init_receives_frame() {
        let inp = inputs_for(InitrdKind::NetRx);
        let (backend, counters) = CountingNetBackend::with_inbound(&NET_RX_FRAME);
        let config: MicroVmConfig<MemoryBlockBackend, CountingNetBackend> = MicroVmConfig {
            vcpu_count: 1,
            mem_size: 256 << 20,
            block: vec![],
            net: vec![NetDeviceConfig {
                backend,
                mac: NET_MAC,
            }],
        };
        let obs = Arc::new(VirtioWindowObserver::new());
        let o = run_boot(inp, config, Some(obs.clone()));
        let s = obs.stats(VirtioDeviceKind::Net);
        let delivered = counters.delivered.load(Ordering::Relaxed);
        let extra = format!(
            "net={s:?} frames_sent={} recv_calls={} delivered={delivered} hint=\"{KCONFIG_HINT}\"",
            counters.sent.load(Ordering::Relaxed),
            counters.recv_calls.load(Ordering::Relaxed),
        );
        let diag = o.diag(&extra);
        assert_boot_ok_with_marker(&o, NET_RX_OK_MARKER, 1, &diag);
        assert_eq!(
            count_marker_lines(&o.output, NET_RX_FAILED_MARKER),
            0,
            "net rx failed marker must not appear: {diag}"
        );
        assert_eq!(
            count_marker_lines(&o.output, MARKER),
            0,
            "default init marker must not appear with the net-rx initrd: {diag}"
        );
        assert_eq!(s.driver_ok_first, Some(0x0F), "net DRIVER_OK: {diag}");
        assert_eq!(s.failed_writes, 0, "net FAILED writes: {diag}");
        assert_eq!(s.queue_ready_one, 2, "net QUEUE_READY=1 count: {diag}");
        assert_eq!(delivered, 1, "frames delivered to the guest: {diag}");
        eprintln!(
            "kernel_boot: ok case=virtio_net_rx delivered={delivered} elapsed_ms={}",
            o.elapsed.as_millis()
        );
    }

    /// 陰性対照（#3919）。virtio-net はあるがフレームを渡さないと、ゲストは期限（約 5 秒）で failed marker を出し、
    /// ok marker は出ないこと。net 0 台にすると `SIOCSIFFLAGS` で失敗して受信の経路を通らないため、net は 1 台つける。
    /// 限界: これだけでは「AF_PACKET が使えず早く失敗した」場合と区別できない。経路が使えることは
    /// 陽性（`kernel_boot_with_virtio_net_init_receives_frame`）が示すので、同じ実行で回す。
    #[test]
    #[ignore = "requires read/write access to /dev/kvm (MVM-1)"]
    fn kernel_boot_net_rx_init_without_frame_reports_failure() {
        let inp = inputs_for(InitrdKind::NetRx);
        let (backend, counters) = CountingNetBackend::new();
        let config: MicroVmConfig<MemoryBlockBackend, CountingNetBackend> = MicroVmConfig {
            vcpu_count: 1,
            mem_size: 256 << 20,
            block: vec![],
            net: vec![NetDeviceConfig {
                backend,
                mac: NET_MAC,
            }],
        };
        let obs = Arc::new(VirtioWindowObserver::new());
        let o = run_boot(inp, config, Some(obs.clone()));
        let s = obs.stats(VirtioDeviceKind::Net);
        let delivered = counters.delivered.load(Ordering::Relaxed);
        let recv_calls = counters.recv_calls.load(Ordering::Relaxed);
        let extra = format!(
            "net={s:?} recv_calls={recv_calls} delivered={delivered} hint=\"{KCONFIG_HINT}\""
        );
        let diag = o.diag(&extra);
        assert_boot_ok_with_marker(&o, NET_RX_FAILED_MARKER, 1, &diag);
        assert_eq!(
            count_marker_lines(&o.output, NET_RX_OK_MARKER),
            0,
            "net rx ok marker must not appear without a frame: {diag}"
        );
        assert_eq!(
            count_marker_lines(&o.output, MARKER),
            0,
            "default init marker must not appear with the net-rx initrd: {diag}"
        );
        assert_eq!(s.driver_ok_first, Some(0x0F), "net DRIVER_OK: {diag}");
        assert_eq!(s.failed_writes, 0, "net FAILED writes: {diag}");
        assert_eq!(s.queue_ready_one, 2, "net QUEUE_READY=1 count: {diag}");
        assert!(recv_calls >= 1, "rx poller never ran: {diag}");
        assert_eq!(delivered, 0, "no frame must be delivered: {diag}");
        eprintln!(
            "kernel_boot: ok case=virtio_net_rx_no_frame elapsed_ms={}",
            o.elapsed.as_millis()
        );
    }

    #[test]
    fn mvm1_3865_counting_block_backend() {
        let (mut b, c) = CountingBlockBackend::new(4096);
        assert!(b.read_only());
        assert_eq!(b.capacity_bytes(), 4096);
        let mut buf = [0u8; 512];
        b.read_at(0, &mut buf).unwrap();
        b.read_at(512, &mut buf).unwrap();
        assert!(b.write_at(0, &buf).is_err());
        b.flush().unwrap();
        assert_eq!(c.reads.load(Ordering::Relaxed), 2);
        assert_eq!(c.offset0_reads.load(Ordering::Relaxed), 1);
        assert_eq!(c.read_bytes.load(Ordering::Relaxed), 1024);
        assert_eq!(c.writes.load(Ordering::Relaxed), 1);
        assert_eq!(c.flushes.load(Ordering::Relaxed), 1);
    }
    #[test]
    fn mvm1_3889_block_strings_match_initrd_script() {
        let script = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../scripts/build-microvm-test-initrd.sh");
        let text = std::fs::read_to_string(script).unwrap();
        let find = |prefix: &str| -> Vec<String> {
            text.lines()
                .filter_map(|l| l.strip_prefix(prefix))
                .filter_map(|l| l.strip_suffix('"'))
                .map(str::to_owned)
                .collect()
        };
        assert_eq!(
            find("block_sentinel=\""),
            vec![String::from_utf8(BLOCK_SENTINEL.to_vec()).unwrap()]
        );
        assert_eq!(
            find("block_ok_message=\""),
            vec![BLOCK_OK_MARKER.to_owned()]
        );
        assert_eq!(
            find("block_mismatch_message=\""),
            vec![BLOCK_MISMATCH_MARKER.to_owned()]
        );
        assert_eq!(BLOCK_SENTINEL.len(), 32);
    }

    #[test]
    fn mvm1_3889_sentinel_backend() {
        let (mut b, c) = CountingBlockBackend::with_sentinel(4096, Some(BLOCK_SENTINEL));
        assert!(b.read_only());
        let mut buf = [0u8; 512];
        b.read_at(0, &mut buf).unwrap();
        assert_eq!(buf.get(..32), Some(&BLOCK_SENTINEL[..]));
        assert!(buf.get(32..).unwrap().iter().all(|x| *x == 0));
        assert!(b.write_at(0, &[0xFF; 32]).is_err());
        b.read_at(0, &mut buf).unwrap();
        assert_eq!(buf.get(..32), Some(&BLOCK_SENTINEL[..]));
        assert_eq!(c.reads.load(Ordering::Relaxed), 2);
        assert_eq!(c.writes.load(Ordering::Relaxed), 1);
        let (mut z, _) = CountingBlockBackend::with_sentinel(4096, None);
        z.read_at(0, &mut buf).unwrap();
        assert!(buf.iter().all(|x| *x == 0));
    }

    #[test]
    fn mvm1_3771_marker_matches_initrd_script() {
        let script = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../scripts/build-microvm-test-initrd.sh");
        let text = std::fs::read_to_string(script).unwrap();
        let found: Vec<&str> = text
            .lines()
            .filter_map(|l| l.strip_prefix("init_message=\""))
            .filter_map(|l| l.strip_suffix('"'))
            .collect();
        assert_eq!(found, vec![MARKER]);
    }

    #[test]
    fn mvm1_3771_parse_boot_timeout() {
        assert_eq!(parse_boot_timeout(None), Ok(60));
        assert_eq!(parse_boot_timeout(Some("1")), Ok(1));
        assert_eq!(parse_boot_timeout(Some("600")), Ok(600));
        for bad in ["0", "601", "abc", "", "-1"] {
            assert!(parse_boot_timeout(Some(bad)).is_err(), "{bad}");
        }
    }

    #[test]
    fn mvm1_3771_validate_cmdline() {
        assert_eq!(validate_cmdline(None).unwrap(), "console=ttyS0 reboot=t");
        assert_eq!(validate_cmdline(Some("quiet")).unwrap(), "quiet");
        assert!(validate_cmdline(Some("")).is_err());
        assert!(validate_cmdline(Some("a\nb")).is_err());
    }
}

/// aarch64 の実カーネル起動試験（#3897・MVM-1・REPAIR-5・REPAIR-12）。
///
/// arm64 の非圧縮 `Image` と `MICROVM_TEST_INITRD_ARCH=aarch64 make microvm-test-initrd-build` の initrd（`/init` は
/// write の後に `reboot(RESTART)`）で `assemble` → `load_kernel` → `start` を通し、PSCI SYSTEM_RESET が
/// `KVM_EXIT_SYSTEM_EVENT` として `StopReason::GuestShutdown` に分類されること（#3896）を照合する。
/// ホスト要件: Linux aarch64・`/dev/kvm` の読み書き（root 不要）・in-kernel vGICv3（GICv2 のみのホストは `assemble` で失敗）・
/// `KVM_CAP_ARM_PSCI_0_2`。シリアルは MMIO の ns16550a を SPI 1 の level 割り込みで結線済み（#3898・#3943）で、停止理由・起点 vCPU・
/// エラー件数・期限に加え、marker の回数と UART の取りこぼし 0 を照合する。範囲外: SMP（#3899）・virtio。
/// x86 の同名ヘルパーと同じ契約の入力検査を複製している（x86 側の件数・挙動を変えないため）。
/// 実機での実行と記録は #3781（人間担当）。Agent は実カーネルでの起動を確かめていない。
#[cfg(target_arch = "aarch64")]
mod arm64 {
    use super::guest_boot::{
        AP_BOOTED_PREFIX, ARM64_SMP_TOTAL_LINE, SMP_ONLINE_LINE, TtyAddress, TtyReport,
        count_lines_containing, force_panic_zero, parse_tty_report, read_bounded,
        smp_disabling_param,
    };
    use super::{
        BLOCK_MISMATCH_MARKER, BLOCK_OK_MARKER, BLOCK_SENTINEL, CountingNetBackend, MARKER,
        NET_MAC, NET_RX_FAILED_MARKER, NET_RX_FRAME, NET_RX_OK_MARKER, NET_TX_FAILED_MARKER,
        NET_TX_FRAME, NET_TX_OK_MARKER, VirtioWindowObserver, count_lines_ending_with,
        count_marker_lines, escape_tail, guest_boot, hex_prefix,
    };
    use fandhe_container_microvm::arm64_layout::ARM64_SERIAL_BASE;
    use fandhe_container_microvm::boot_arm64::Arm64ImageHeader;
    use fandhe_container_microvm::device::{KvmDevice, RunObserver};
    use fandhe_container_microvm::microvm::{
        MicroVm, MicroVmConfig, NetDeviceConfig, StopReason, VirtioDeviceKind,
    };
    use fandhe_container_microvm::virtio_block::{BlockBackend, MemoryBlockBackend};
    use std::path::Path;
    use std::sync::atomic::Ordering;
    use std::sync::{Arc, mpsc};
    use std::time::{Duration, Instant};

    /// `panic=` を含まない無害な既定値。x86 の `reboot=t` は arm64 に当たらない。`console=ttyS0` は FDT の `ns16550a`
    /// （`/chosen/stdout-path`。#3898）を 8250 のコンソールとして選ぶ。
    const DEFAULT_CMDLINE: &str = "console=ttyS0 rdinit=/init";
    /// UART の出力の蓄積の上限（x86 と同じ。超過は Err にして無制限確保を避ける。REPAIR-5）。
    const OUTPUT_CAP: usize = 4 << 20;
    const DEFAULT_TIMEOUT_SECS: u64 = 60;
    /// `MicroVmConfig` に既定値が無いため x86 と同じ 256 MiB とする。
    const RAM_SIZE: u64 = 256 << 20;
    const KERNEL_CAP: u64 = fandhe_container_microvm::boot_x86::MAX_KERNEL_IMAGE_BYTES;
    const INITRD_CAP: u64 = 64 << 20;
    const STOP_DEADLINE: Duration = Duration::from_secs(10);
    const SLACK: Duration = Duration::from_secs(15);

    fn precondition(reason: &str) -> ! {
        panic!("kernel_boot: PRECONDITION FAILED (test environment, not a regression): {reason}")
    }

    fn parse_boot_timeout(raw: Option<&str>) -> Result<u64, String> {
        guest_boot::parse_boot_timeout_or(raw, DEFAULT_TIMEOUT_SECS)
    }

    fn validate_cmdline(raw: Option<&str>) -> Result<String, String> {
        guest_boot::validate_cmdline_or(raw, DEFAULT_CMDLINE)
    }

    struct Inputs {
        dev: KvmDevice,
        kernel: Vec<u8>,
        initrd: Option<Vec<u8>>,
        cmdline: String,
        secs: u64,
    }

    /// 使う initrd の種類（`scripts/build-microvm-test-initrd.sh` の variant に対応。`--arch aarch64`）。
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum InitrdKind {
        /// initrd 無し（負の対照）。
        None,
        /// 固定文字列を書いて reboot するだけの版（`FANDHE_CONTAINER_MICROVM_INITRD`）。
        Default,
        /// `/dev/vda` の先頭を sentinel と比べる版（`FANDHE_CONTAINER_MICROVM_BLOCK_INITRD`。#3947）。
        BlockRead,
        /// `eth0` を上げて固定フレームを 1 回送る版（`FANDHE_CONTAINER_MICROVM_NET_TX_INITRD`。#3966）。
        NetTx,
        /// `eth0` を上げて固定フレームを受ける版（`FANDHE_CONTAINER_MICROVM_NET_RX_INITRD`。#3966）。
        NetRx,
    }

    /// initrd の種類ごとの（環境変数名・既定の相対パス・生成コマンドのヒント）。`None` には initrd が無い。
    fn initrd_spec(kind: InitrdKind) -> Option<(&'static str, &'static str, &'static str)> {
        match kind {
            InitrdKind::None => None,
            InitrdKind::Default => Some((
                "FANDHE_CONTAINER_MICROVM_INITRD",
                "../../target/microvm-test-initrd/aarch64/initrd.cpio",
                "MICROVM_TEST_INITRD_ARCH=aarch64 make microvm-test-initrd-build",
            )),
            InitrdKind::BlockRead => Some((
                "FANDHE_CONTAINER_MICROVM_BLOCK_INITRD",
                "../../target/microvm-test-initrd/aarch64-block-read/initrd.cpio",
                "MICROVM_TEST_INITRD_ARCH=aarch64 MICROVM_TEST_INITRD_VARIANT=block-read make microvm-test-initrd-build",
            )),
            InitrdKind::NetTx => Some((
                "FANDHE_CONTAINER_MICROVM_NET_TX_INITRD",
                "../../target/microvm-test-initrd/aarch64-net-tx/initrd.cpio",
                "MICROVM_TEST_INITRD_ARCH=aarch64 MICROVM_TEST_INITRD_VARIANT=net-tx make microvm-test-initrd-build",
            )),
            InitrdKind::NetRx => Some((
                "FANDHE_CONTAINER_MICROVM_NET_RX_INITRD",
                "../../target/microvm-test-initrd/aarch64-net-rx/initrd.cpio",
                "MICROVM_TEST_INITRD_ARCH=aarch64 MICROVM_TEST_INITRD_VARIANT=net-rx make microvm-test-initrd-build",
            )),
        }
    }

    /// 前提の検査はすべてテストスレッドで行う（x86 と同じ方針）。
    fn inputs(kind: InitrdKind) -> Inputs {
        let kernel_path = match std::env::var("FANDHE_CONTAINER_MICROVM_KERNEL") {
            Ok(p) if !p.is_empty() => p,
            _ => {
                precondition("FANDHE_CONTAINER_MICROVM_KERNEL is not set (path to an arm64 Image)")
            }
        };
        let kernel = read_bounded(Path::new(&kernel_path), KERNEL_CAP)
            .unwrap_or_else(|e| precondition(&format!("kernel image: {e}")));
        if let Err(e) = Arm64ImageHeader::parse(&kernel) {
            precondition(&format!(
                "kernel image is not an uncompressed arm64 Image: {e}"
            ));
        }
        let initrd = initrd_spec(kind).map(|(env_name, default_rel, hint)| {
            let path = match std::env::var(env_name) {
                Ok(p) if !p.is_empty() => std::path::PathBuf::from(p),
                _ => Path::new(env!("CARGO_MANIFEST_DIR")).join(default_rel),
            };
            read_bounded(&path, INITRD_CAP)
                .unwrap_or_else(|e| precondition(&format!("initrd (run `{hint}`): {e}")))
        });
        let cmdline = validate_cmdline(
            std::env::var("FANDHE_CONTAINER_MICROVM_CMDLINE")
                .ok()
                .as_deref(),
        )
        .unwrap_or_else(|e| precondition(&e));
        let secs = parse_boot_timeout(
            std::env::var("FANDHE_CONTAINER_MICROVM_BOOT_TIMEOUT_SECS")
                .ok()
                .as_deref(),
        )
        .unwrap_or_else(|e| precondition(&e));
        let dev = super::open_kvm();
        Inputs {
            dev,
            kernel,
            initrd,
            cmdline,
            secs,
        }
    }

    struct Outcome {
        reason: StopReason,
        origin_vcpu: Option<u32>,
        vcpu_count: u32,
        errors: u64,
        exits: u64,
        output: Vec<u8>,
        uart_dropped: u64,
        timed_out: bool,
        elapsed: Duration,
        /// 組み立て済みの virtio-net の台数（#3957。負の対照で「net が無い」ことの裏づけ）。
        net_slots: usize,
        /// 組み立て済みの virtio-block の台数（#3957）。
        block_slots: usize,
    }

    impl Outcome {
        /// 診断。ゲスト由来の出力は末尾 4096 バイトだけをエスケープして載せる。
        fn diag(&self) -> String {
            format!(
                "reason={:?} origin={:?} errors={} exits={} elapsed={:?} timed_out={} uart_dropped={} output_len={} tail={}",
                self.reason,
                self.origin_vcpu,
                self.errors,
                self.exits,
                self.elapsed,
                self.timed_out,
                self.uart_dropped,
                self.output.len(),
                escape_tail(&self.output, 4096)
            )
        }
    }

    fn boot(
        inp: Inputs,
        cmdline: String,
        boot_timeout: Duration,
        vcpus: u32,
        block: Vec<MemoryBlockBackend>,
        net: Vec<NetDeviceConfig<CountingNetBackend>>,
        observer: Option<Arc<VirtioWindowObserver>>,
    ) -> Result<Outcome, String> {
        let started = Instant::now();
        let vcpu_n = usize::try_from(vcpus).unwrap_or(0);
        let config: MicroVmConfig<MemoryBlockBackend, CountingNetBackend> = MicroVmConfig {
            vcpu_count: vcpus,
            mem_size: RAM_SIZE,
            block,
            net,
        };
        let mut vm =
            MicroVm::assemble(&inp.dev, config).map_err(|e| format!("assemble failed: {e}"))?;
        let devices = vm.devices();
        let net_slots = devices
            .iter()
            .filter(|d| d.slot.kind == VirtioDeviceKind::Net)
            .count();
        let block_slots = devices
            .iter()
            .filter(|d| d.slot.kind == VirtioDeviceKind::Block)
            .count();
        if let Some(obs) = &observer {
            // アドレスは直書きせず、組み立て済みの配置から取る。start は MicroVm を消費するので観測は start の前に付ける。
            for info in &devices {
                obs.bind(info.slot.kind, info.slot.mmio_base, info.slot.mmio_len);
            }
            let dynobs: Arc<dyn RunObserver> = obs.clone();
            for i in 0..vcpu_n {
                if let Some(v) = vm.vcpu_mut(i) {
                    v.set_observer(dynobs.clone());
                }
            }
        }
        let loaded = vm
            .load_kernel(&inp.kernel, inp.initrd.as_deref(), &cmdline)
            .map_err(|e| format!("load_kernel failed: {e}"))?;
        // start の前に取っておく（停止後も clone がバッファを保持する）。
        let serial = vm.serial_console();
        let running = vm
            .start(&loaded)
            .map_err(|e| format!("start failed: {e}"))?;
        let mut output: Vec<u8> = Vec::new();
        let mut timed_out = false;
        loop {
            let chunk = serial
                .take_output()
                .map_err(|e| format!("take_output failed: {e}"))?;
            output.extend_from_slice(&chunk);
            if output.len() > OUTPUT_CAP {
                return Err("guest serial output exceeded the test cap".into());
            }
            if running.is_finished() {
                break;
            }
            if started.elapsed() >= boot_timeout {
                timed_out = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        // 期限切れでも必ず stop で vCPU を回収する（REPAIR-5）。
        let report = running
            .stop(STOP_DEADLINE)
            .map_err(|e| format!("stop failed: {e}"))?;
        // 停止までの出力を取り切る（停止の報告は vCPU スレッドの送信完了後なので欠けない）。
        let tail = serial
            .take_output()
            .map_err(|e| format!("take_output failed: {e}"))?;
        output.extend_from_slice(&tail);
        let uart_dropped = serial
            .stats()
            .map_err(|e| format!("uart stats failed: {e}"))?
            .dropped_bytes;
        Ok(Outcome {
            reason: report.reason,
            origin_vcpu: report.origin_vcpu,
            vcpu_count: report.vcpu_count,
            errors: report.stats.errors,
            exits: report.stats.exits,
            output,
            uart_dropped,
            timed_out,
            elapsed: started.elapsed(),
            net_slots,
            block_slots,
        })
    }

    /// 別スレッドで `boot` を回し、全体期限で必ず戻る（watchdog は `--ignored` を素通しするため唯一の層）。
    fn run_boot(
        inp: Inputs,
        cmdline: String,
        vcpus: u32,
        block: Vec<MemoryBlockBackend>,
        net: Vec<NetDeviceConfig<CountingNetBackend>>,
        observer: Option<Arc<VirtioWindowObserver>>,
    ) -> (Outcome, Duration) {
        let secs = inp.secs;
        let boot_timeout = Duration::from_secs(secs);
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(boot(
                inp,
                cmdline,
                boot_timeout,
                vcpus,
                block,
                net,
                observer,
            ));
        });
        match rx.recv_timeout(boot_timeout + STOP_DEADLINE + SLACK) {
            Ok(Ok(o)) => (o, boot_timeout),
            Ok(Err(e)) => panic!("kernel_boot: boot sequence failed: {e}"),
            Err(e) => panic!("kernel_boot: DEADLINE EXCEEDED ({e}) after {secs}s boot budget"),
        }
    }

    /// 陽性（#3897・MVM-1）。`/init` の reboot（PSCI SYSTEM_RESET）が `GuestShutdown`・起点 vCPU 0 で止まる。
    #[test]
    #[ignore = "requires read/write access to /dev/kvm (MVM-1)"]
    fn kernel_boot_real_kernel_reaches_init_and_shuts_down() {
        let inp = inputs(InitrdKind::Default);
        let cmdline = force_panic_zero(&inp.cmdline);
        let (o, boot_timeout) = run_boot(inp, cmdline, 1, vec![], vec![], None);
        let diag = o.diag();
        assert_eq!(o.reason, StopReason::GuestShutdown, "stop reason: {diag}");
        assert_eq!(o.origin_vcpu, Some(0), "origin vcpu: {diag}");
        assert_eq!(o.vcpu_count, 1, "vcpu count: {diag}");
        assert_eq!(o.errors, 0, "run errors: {diag}");
        assert!(!o.timed_out, "boot timed out: {diag}");
        assert!(o.elapsed < boot_timeout, "elapsed over budget: {diag}");
        assert_eq!(
            count_marker_lines(&o.output, MARKER),
            1,
            "init marker must appear exactly once: {diag}"
        );
        assert_eq!(o.uart_dropped, 0, "uart dropped bytes: {diag}");
        // ポーリングへの退行の検出（#3958）。irq = 0 は DT に interrupts が無い印。値は virq なので != 0 だけを見る。
        let irq = match parse_tty_report(&o.output, "ttyS0") {
            TtyReport::Found {
                address: TtyAddress::Mmio(base),
                irq,
            } => {
                assert_eq!(base, ARM64_SERIAL_BASE, "ttyS0 MMIO base: {diag}");
                irq
            }
            other => panic!("ttyS0 report not found exactly once as MMIO: {other:?}: {diag}"),
        };
        assert_ne!(
            irq, 0,
            "ttyS0 is polled (irq = 0); serial interrupt wiring regressed: {diag}"
        );
        eprintln!(
            "kernel_boot: ok arch=aarch64 reason=guest_shutdown ttys0_irq={irq} elapsed_ms={} exits={}",
            o.elapsed.as_millis(),
            o.exits
        );
    }

    /// 負の対照（#3897）。initrd が無いと rootfs の mount に失敗して panic し、`panic=0` でループするので期限まで止まらない。
    /// 既定 60 秒を使い切る。陽性と同じ実行・同じカーネルで回すこと（対照の結果が陽性の `GuestShutdown` の意味を裏づける）。
    /// `Failed(..)` が出たら device model 側の別 issue。カーネルは `CONFIG_PANIC_TIMEOUT=0` かつ組み込み initramfs 無しが前提。
    #[test]
    #[ignore = "requires read/write access to /dev/kvm (MVM-1)"]
    fn kernel_boot_without_initrd_does_not_shut_down() {
        let inp = inputs(InitrdKind::None);
        let cmdline = force_panic_zero(&inp.cmdline);
        let (o, _) = run_boot(inp, cmdline, 1, vec![], vec![], None);
        let diag = o.diag();
        assert_ne!(o.reason, StopReason::GuestShutdown, "stop reason: {diag}");
        assert_eq!(o.reason, StopReason::Requested, "stop reason: {diag}");
        assert!(o.timed_out, "expected budget exhaustion: {diag}");
        assert_eq!(o.origin_vcpu, None, "origin vcpu: {diag}");
        assert_eq!(o.vcpu_count, 1, "vcpu count: {diag}");
        assert_eq!(o.errors, 0, "run errors: {diag}");
        assert_eq!(
            count_marker_lines(&o.output, MARKER),
            0,
            "init marker must not appear without an initrd: {diag}"
        );
        assert_eq!(o.uart_dropped, 0, "uart dropped bytes: {diag}");
    }

    /// virtio-block 用の backend（1 MiB）。`sentinel` があれば offset 0 に書く。試験の欠陥（容量・書き込みの失敗）は panic にする。
    fn block_backend(sentinel: Option<&[u8]>) -> MemoryBlockBackend {
        let mut b = MemoryBlockBackend::new(1 << 20, false).expect("valid block capacity");
        if let Some(s) = sentinel {
            b.write_at(0, s).expect("sentinel fits in capacity");
        }
        b
    }

    /// block-read の 3 件に共通の本体（#3947・MVM-1・REPAIR-12）。`block` の台数（0 または 1）で起動し、`expect`（期待する
    /// marker）がちょうど 1 回、`other`（もう一方の marker）と既定の `MARKER` が 0 回、`GuestShutdown`・起点 vCPU 0・
    /// エラー 0・UART の取りこぼし 0・期限内であることを照合する。割り込みは FDT の既定の edge-rising の SPI を使う。
    /// 届いた証跡は marker で取る（page cache の都合で init の read が backend に届かない場合があるため read 回数は見ない）。
    fn run_block_read(block: Vec<MemoryBlockBackend>, expect: &str, other: &str, case: &str) {
        let inp = inputs(InitrdKind::BlockRead);
        let cmdline = force_panic_zero(&inp.cmdline);
        let (o, boot_timeout) = run_boot(inp, cmdline, 1, block, vec![], None);
        let diag = o.diag();
        assert_eq!(o.reason, StopReason::GuestShutdown, "stop reason: {diag}");
        assert_eq!(o.origin_vcpu, Some(0), "origin vcpu: {diag}");
        assert_eq!(o.vcpu_count, 1, "vcpu count: {diag}");
        assert_eq!(o.errors, 0, "run errors: {diag}");
        assert!(!o.timed_out, "boot timed out: {diag}");
        assert!(o.elapsed < boot_timeout, "elapsed over budget: {diag}");
        assert_eq!(
            count_marker_lines(&o.output, expect),
            1,
            "marker {expect:?} must appear exactly once: {diag}"
        );
        assert_eq!(
            count_marker_lines(&o.output, other),
            0,
            "opposite marker {other:?} must not appear: {diag}"
        );
        assert_eq!(
            count_marker_lines(&o.output, MARKER),
            0,
            "default init marker must not appear with the block-read initrd: {diag}"
        );
        assert_eq!(o.uart_dropped, 0, "uart dropped bytes: {diag}");
        eprintln!(
            "kernel_boot: ok arch=aarch64 case={case} marker={expect:?} elapsed_ms={} exits={}",
            o.elapsed.as_millis(),
            o.exits
        );
    }

    /// 陽性（#3947）。virtio-block 1 台（offset 0 に sentinel）を block-read の initrd で読ませ、`/dev/vda` の先頭が
    /// ゲストに届いたときだけ出る一致 marker をちょうど 1 回数える。device は FDT の `virtio,mmio` ノードで見つかる
    /// （カーネルは `CONFIG_VIRTIO_MMIO`・`CONFIG_VIRTIO_BLK`・`CONFIG_BLOCK`・`CONFIG_DEVTMPFS`）。
    #[test]
    #[ignore = "requires read/write access to /dev/kvm (MVM-1)"]
    fn kernel_boot_with_virtio_block_init_reads_sentinel() {
        run_block_read(
            vec![block_backend(Some(BLOCK_SENTINEL))],
            BLOCK_OK_MARKER,
            BLOCK_MISMATCH_MARKER,
            "virtio_block_sentinel",
        );
    }

    /// 負の対照（#3947）。同じ initrd で block デバイスが無いと `openat("/dev/vda")` が失敗して不一致 marker が出る。
    /// 期限を使い切らず `GuestShutdown` で速く決定的に終わる。陽性と同じ実行で回すこと。
    #[test]
    #[ignore = "requires read/write access to /dev/kvm (MVM-1)"]
    fn kernel_boot_block_read_init_without_block_device_reports_mismatch() {
        run_block_read(
            vec![],
            BLOCK_MISMATCH_MARKER,
            BLOCK_OK_MARKER,
            "virtio_block_absent",
        );
    }

    /// 陰性対照（#3947）。backend が 0 埋めのとき不一致 marker が出て一致 marker が出ない（比較が素通しでないことを示す）。
    #[test]
    #[ignore = "requires read/write access to /dev/kvm (MVM-1)"]
    fn kernel_boot_with_virtio_block_init_detects_mismatch() {
        run_block_read(
            vec![block_backend(None)],
            BLOCK_MISMATCH_MARKER,
            BLOCK_OK_MARKER,
            "virtio_block_mismatch",
        );
    }

    /// MVM-1・#3947: virtio の SPI は既定で edge-rising（試験の前提。level の構成は `Unimplemented` で拒否される）。
    #[test]
    fn mvm1_3947_arm64_virtio_spi_default_is_edge_rising() {
        use fandhe_container_microvm::arm64_layout::Arm64Layout;
        use fandhe_container_microvm::interrupt::IrqTrigger;
        let l = Arm64Layout::new(RAM_SIZE, 1, 1).expect("valid layout");
        assert_eq!(l.virtio_spi_trigger, IrqTrigger::EdgeRising);
    }

    /// arm64 の virtio-net 試験の失敗時の切り分け（#3957）。カウンタが 0 のとき guest カーネルの設定を疑う。
    const KCONFIG_HINT: &str = "if net counters are zero, check the guest kernel config: CONFIG_NET, CONFIG_NETDEVICES, CONFIG_VIRTIO_MMIO, CONFIG_VIRTIO_NET, CONFIG_PACKET (virtio-mmio is discovered via the FDT, so CONFIG_VIRTIO_MMIO_CMDLINE_DEVICES is not needed)";

    /// virtio-net 用の backend 1 台分の構成（固定 MAC `NET_MAC`）。
    fn net_config() -> NetDeviceConfig<CountingNetBackend> {
        net_config_with(CountingNetBackend::new().0)
    }

    /// 指定の backend を包んだ virtio-net 1 台分の構成（計数・写しを読む試験用。固定 MAC `NET_MAC`）。
    fn net_config_with(backend: CountingNetBackend) -> NetDeviceConfig<CountingNetBackend> {
        NetDeviceConfig {
            backend,
            mac: NET_MAC,
        }
    }

    /// 既定の initrd（`MARKER` を出して reboot する版）の起動の共通照合（#3957）。
    fn assert_default_boot_ok(o: &Outcome, boot_timeout: Duration, diag: &str) {
        assert_eq!(o.reason, StopReason::GuestShutdown, "stop reason: {diag}");
        assert_eq!(o.origin_vcpu, Some(0), "origin vcpu: {diag}");
        assert_eq!(o.vcpu_count, 1, "vcpu count: {diag}");
        assert_eq!(o.errors, 0, "run errors: {diag}");
        assert!(!o.timed_out, "boot timed out: {diag}");
        assert!(o.elapsed < boot_timeout, "elapsed over budget: {diag}");
        assert_eq!(
            count_marker_lines(&o.output, MARKER),
            1,
            "init marker must appear exactly once: {diag}"
        );
        assert_eq!(o.uart_dropped, 0, "uart dropped bytes: {diag}");
    }

    /// virtio-net 1 台の陽性（#3957・MVM-1・REPAIR-12）。ドライバの probe が DRIVER_OK `0x0F` まで進み、receiveq・transmitq の
    /// 2 本が QUEUE_READY になることを照合する。既定の initrd には interface を上げる userspace が無いので RX・TX は照合しない
    /// （TX・RX の中身は専用 initrd の試験が照合する。#3966）。割り込みは FDT の既定の edge-rising の SPI。
    /// Agent は実カーネルで未確認。実機の記録は #3781。
    #[test]
    #[ignore = "requires read/write access to /dev/kvm (MVM-1)"]
    fn kernel_boot_with_virtio_net_reaches_driver_ok() {
        let inp = inputs(InitrdKind::Default);
        let cmdline = force_panic_zero(&inp.cmdline);
        let obs = Arc::new(VirtioWindowObserver::new());
        let (o, boot_timeout) = run_boot(
            inp,
            cmdline,
            1,
            vec![],
            vec![net_config()],
            Some(obs.clone()),
        );
        let s = obs.stats(VirtioDeviceKind::Net);
        let diag = format!(
            "{} net={s:?} net_slots={} hint=\"{KCONFIG_HINT}\"",
            o.diag(),
            o.net_slots
        );
        assert_default_boot_ok(&o, boot_timeout, &diag);
        assert_eq!(o.net_slots, 1, "assembled net devices: {diag}");
        assert_eq!(s.driver_ok_first, Some(0x0F), "net DRIVER_OK: {diag}");
        assert_eq!(s.failed_writes, 0, "net FAILED writes: {diag}");
        assert_eq!(s.queue_ready_one, 2, "net QUEUE_READY=1 count: {diag}");
        eprintln!(
            "kernel_boot: ok arch=aarch64 case=virtio_net driver_ok=0x0f queue_ready=2 elapsed_ms={} exits={}",
            o.elapsed.as_millis(),
            o.exits
        );
    }

    /// 負の対照（#3957）。net 0 台で観測器だけ付けると、組み立て済みの net が 0 件で、net の窓の観測値が全部 0 になる。
    /// 陽性の DRIVER_OK が net デバイス由来であることを裏づけるため、陽性と同じ実行（`--test-threads=1`）で回すこと。
    #[test]
    #[ignore = "requires read/write access to /dev/kvm (MVM-1)"]
    fn kernel_boot_without_virtio_net_reports_no_driver_ok() {
        let inp = inputs(InitrdKind::Default);
        let cmdline = force_panic_zero(&inp.cmdline);
        let obs = Arc::new(VirtioWindowObserver::new());
        let (o, boot_timeout) = run_boot(inp, cmdline, 1, vec![], vec![], Some(obs.clone()));
        let s = obs.stats(VirtioDeviceKind::Net);
        let diag = format!("{} net={s:?} net_slots={}", o.diag(), o.net_slots);
        assert_default_boot_ok(&o, boot_timeout, &diag);
        assert_eq!(o.net_slots, 0, "assembled net devices: {diag}");
        assert_eq!(s.driver_ok_first, None, "net DRIVER_OK: {diag}");
        assert_eq!(s.failed_writes, 0, "net FAILED writes: {diag}");
        assert_eq!(s.status_writes, 0, "net STATUS writes: {diag}");
        assert_eq!(s.queue_ready_one, 0, "net QUEUE_READY=1 count: {diag}");
    }

    /// block 1 台と net 1 台を同時に付けた窓の区別（#3957）。FDT の block → net の順と SPI の割り当てが窓を取り違えず、
    /// block は QUEUE_READY 1 回、net は 2 回で、どちらも DRIVER_OK `0x0F`・FAILED 0 件になることを照合する。
    #[test]
    #[ignore = "requires read/write access to /dev/kvm (MVM-1)"]
    fn kernel_boot_with_virtio_block_and_net_reaches_driver_ok() {
        let inp = inputs(InitrdKind::Default);
        let cmdline = force_panic_zero(&inp.cmdline);
        let obs = Arc::new(VirtioWindowObserver::new());
        let (o, boot_timeout) = run_boot(
            inp,
            cmdline,
            1,
            vec![block_backend(None)],
            vec![net_config()],
            Some(obs.clone()),
        );
        let b = obs.stats(VirtioDeviceKind::Block);
        let n = obs.stats(VirtioDeviceKind::Net);
        let diag = format!(
            "{} block={b:?} net={n:?} block_slots={} net_slots={} hint=\"{KCONFIG_HINT}\"",
            o.diag(),
            o.block_slots,
            o.net_slots
        );
        assert_default_boot_ok(&o, boot_timeout, &diag);
        assert_eq!(o.block_slots, 1, "assembled block devices: {diag}");
        assert_eq!(o.net_slots, 1, "assembled net devices: {diag}");
        assert_eq!(b.driver_ok_first, Some(0x0F), "block DRIVER_OK: {diag}");
        assert_eq!(b.failed_writes, 0, "block FAILED writes: {diag}");
        assert_eq!(b.queue_ready_one, 1, "block QUEUE_READY=1 count: {diag}");
        assert_eq!(n.driver_ok_first, Some(0x0F), "net DRIVER_OK: {diag}");
        assert_eq!(n.failed_writes, 0, "net FAILED writes: {diag}");
        assert_eq!(n.queue_ready_one, 2, "net QUEUE_READY=1 count: {diag}");
        eprintln!(
            "kernel_boot: ok arch=aarch64 case=virtio_block_and_net block_queue_ready=1 net_queue_ready=2 elapsed_ms={} exits={}",
            o.elapsed.as_millis(),
            o.exits
        );
    }

    /// MVM-1・#3947: initrd の種類ごとの環境変数名・既定パス、sentinel つき backend の読み戻し。
    #[test]
    fn mvm1_3947_arm64_block_initrd_paths_and_backend() {
        assert_eq!(initrd_spec(InitrdKind::None), None);
        let (env, rel, hint) =
            initrd_spec(InitrdKind::BlockRead).expect("block-read has an initrd");
        assert_eq!(env, "FANDHE_CONTAINER_MICROVM_BLOCK_INITRD");
        assert!(rel.ends_with("aarch64-block-read/initrd.cpio"), "{rel}");
        assert!(
            hint.contains("MICROVM_TEST_INITRD_VARIANT=block-read"),
            "{hint}"
        );
        let (env, rel, _) = initrd_spec(InitrdKind::Default).expect("default has an initrd");
        assert_eq!(env, "FANDHE_CONTAINER_MICROVM_INITRD");
        assert!(rel.ends_with("aarch64/initrd.cpio"), "{rel}");
        let mut buf = [0u8; 32];
        let mut with = block_backend(Some(BLOCK_SENTINEL));
        with.read_at(0, &mut buf).expect("read sentinel");
        assert_eq!(&buf, BLOCK_SENTINEL);
        let mut zero = block_backend(None);
        zero.read_at(0, &mut buf).expect("read zeros");
        assert_eq!(buf, [0u8; 32]);
    }

    /// net-tx・net-rx の 4 件に共通の起動後の照合（#3966・MVM-1・REPAIR-5・REPAIR-12）。`GuestShutdown`・起点 vCPU 0・
    /// vCPU 1 台・エラー 0・期限内・UART の取りこぼし 0 を見て、`expect` の marker がちょうど 1 回、`other`（反対の marker）と
    /// 既定の `MARKER` が 0 回であることを具体値で照合する。
    fn assert_net_init_boot(
        o: &Outcome,
        boot_timeout: Duration,
        expect: &str,
        other: &str,
        diag: &str,
    ) {
        assert_eq!(o.reason, StopReason::GuestShutdown, "stop reason: {diag}");
        assert_eq!(o.origin_vcpu, Some(0), "origin vcpu: {diag}");
        assert_eq!(o.vcpu_count, 1, "vcpu count: {diag}");
        assert_eq!(o.errors, 0, "run errors: {diag}");
        assert!(!o.timed_out, "boot timed out: {diag}");
        assert!(o.elapsed < boot_timeout, "elapsed over budget: {diag}");
        assert_eq!(
            count_marker_lines(&o.output, expect),
            1,
            "marker {expect:?} must appear exactly once: {diag}"
        );
        assert_eq!(
            count_marker_lines(&o.output, other),
            0,
            "opposite marker {other:?} must not appear: {diag}"
        );
        assert_eq!(
            count_marker_lines(&o.output, MARKER),
            0,
            "default init marker must not appear with the net initrd: {diag}"
        );
        assert_eq!(o.uart_dropped, 0, "uart dropped bytes: {diag}");
    }

    /// 陽性（#3966）。net-tx の initrd が `eth0` を上げて `NET_TX_FRAME` を 1 回送り、`sendto` が 60 を返したときだけ出る
    /// ok marker をちょうど 1 回数える。DRIVER_OK `0x0F`・QUEUE_READY 2 本に加え、backend が受けたフレームの中に
    /// `NET_TX_FRAME` と完全一致するものが 1 件以上あることを照合する（他のフレーム〔DHCP 等〕は許し、診断にだけ載せる）。
    /// カーネルは `CONFIG_PACKET` も要る。Agent は実カーネルで未確認。実機の記録は #3781。
    #[test]
    #[ignore = "requires read/write access to /dev/kvm (MVM-1)"]
    fn kernel_boot_with_virtio_net_init_sends_frame() {
        let inp = inputs(InitrdKind::NetTx);
        let cmdline = force_panic_zero(&inp.cmdline);
        let obs = Arc::new(VirtioWindowObserver::new());
        let (backend, counters) = CountingNetBackend::new();
        let (o, boot_timeout) = run_boot(
            inp,
            cmdline,
            1,
            vec![],
            vec![net_config_with(backend)],
            Some(obs.clone()),
        );
        let s = obs.stats(VirtioDeviceKind::Net);
        let frames = counters.snapshot();
        let matched = frames
            .iter()
            .filter(|f| f.as_slice() == NET_TX_FRAME)
            .count();
        let others: Vec<String> = frames
            .iter()
            .filter(|f| f.as_slice() != NET_TX_FRAME)
            .take(4)
            .map(|f| hex_prefix(f, 32))
            .collect();
        let diag = format!(
            "{} net={s:?} net_slots={} total_frames={} dropped={} matched={matched} other_frames_head={others:?} hint=\"{KCONFIG_HINT}\"",
            o.diag(),
            o.net_slots,
            frames.len(),
            counters.dropped.load(Ordering::Relaxed)
        );
        assert_net_init_boot(
            &o,
            boot_timeout,
            NET_TX_OK_MARKER,
            NET_TX_FAILED_MARKER,
            &diag,
        );
        assert_eq!(o.net_slots, 1, "assembled net devices: {diag}");
        assert_eq!(s.driver_ok_first, Some(0x0F), "net DRIVER_OK: {diag}");
        assert_eq!(s.failed_writes, 0, "net FAILED writes: {diag}");
        assert_eq!(s.queue_ready_one, 2, "net QUEUE_READY=1 count: {diag}");
        assert!(
            matched >= 1,
            "backend received no frame equal to NET_TX_FRAME: {diag}"
        );
        eprintln!(
            "kernel_boot: ok arch=aarch64 case=virtio_net_tx matched={matched} total_frames={} elapsed_ms={} exits={}",
            frames.len(),
            o.elapsed.as_millis(),
            o.exits
        );
    }

    /// 負の対照（#3966）。net-tx の initrd で net デバイスが無いと `eth0` が無く `SIOCGIFINDEX` が失敗して failed marker が出る。
    /// ok marker は出ない。陽性と同じ実行（`--test-threads=1`）で回すこと。
    #[test]
    #[ignore = "requires read/write access to /dev/kvm (MVM-1)"]
    fn kernel_boot_net_tx_init_without_net_device_reports_failure() {
        let inp = inputs(InitrdKind::NetTx);
        let cmdline = force_panic_zero(&inp.cmdline);
        let (o, boot_timeout) = run_boot(inp, cmdline, 1, vec![], vec![], None);
        let diag = format!(
            "{} net_slots={} hint=\"{KCONFIG_HINT}\"",
            o.diag(),
            o.net_slots
        );
        assert_net_init_boot(
            &o,
            boot_timeout,
            NET_TX_FAILED_MARKER,
            NET_TX_OK_MARKER,
            &diag,
        );
        assert_eq!(o.net_slots, 0, "assembled net devices: {diag}");
        eprintln!(
            "kernel_boot: ok arch=aarch64 case=virtio_net_tx_absent elapsed_ms={} exits={}",
            o.elapsed.as_millis(),
            o.exits
        );
    }

    /// 陽性（#3966）。net-rx の initrd が `eth0` を上げて `recvfrom` で待つ間に、backend に積んだ `NET_RX_FRAME` が受信ポーラーから
    /// 渡り、完全一致したときだけ出る ok marker をちょうど 1 回数える。DRIVER_OK `0x0F`・QUEUE_READY 2 本・配送 1 件を照合する。
    /// 割り込みは FDT の既定の edge-rising の SPI（used ring の通知が届かないと期限切れの failed になる）。
    /// Agent は実カーネルで未確認。実機の記録は #3781。
    #[test]
    #[ignore = "requires read/write access to /dev/kvm (MVM-1)"]
    fn kernel_boot_with_virtio_net_init_receives_frame() {
        let inp = inputs(InitrdKind::NetRx);
        let cmdline = force_panic_zero(&inp.cmdline);
        let obs = Arc::new(VirtioWindowObserver::new());
        let (backend, counters) = CountingNetBackend::with_inbound(&NET_RX_FRAME);
        let (o, boot_timeout) = run_boot(
            inp,
            cmdline,
            1,
            vec![],
            vec![net_config_with(backend)],
            Some(obs.clone()),
        );
        let s = obs.stats(VirtioDeviceKind::Net);
        let recv_calls = counters.recv_calls.load(Ordering::Relaxed);
        let delivered = counters.delivered.load(Ordering::Relaxed);
        let diag = format!(
            "{} net={s:?} net_slots={} frames_sent={} recv_calls={recv_calls} delivered={delivered} hint=\"{KCONFIG_HINT}\"",
            o.diag(),
            o.net_slots,
            counters.sent.load(Ordering::Relaxed)
        );
        assert_net_init_boot(
            &o,
            boot_timeout,
            NET_RX_OK_MARKER,
            NET_RX_FAILED_MARKER,
            &diag,
        );
        assert_eq!(o.net_slots, 1, "assembled net devices: {diag}");
        assert_eq!(s.driver_ok_first, Some(0x0F), "net DRIVER_OK: {diag}");
        assert_eq!(s.failed_writes, 0, "net FAILED writes: {diag}");
        assert_eq!(s.queue_ready_one, 2, "net QUEUE_READY=1 count: {diag}");
        assert_eq!(delivered, 1, "exactly one frame must be delivered: {diag}");
        eprintln!(
            "kernel_boot: ok arch=aarch64 case=virtio_net_rx delivered={delivered} elapsed_ms={} exits={}",
            o.elapsed.as_millis(),
            o.exits
        );
    }

    /// 負の対照（#3966）。net-rx の initrd でフレームを積まないと、受信待ちが `SO_RCVTIMEO`（5 秒）で切れて failed marker が出る。
    /// 受信ポーラーは動いた（`recv_calls >= 1`）が配送は 0 件。AF_PACKET が使えず早く失敗した場合とは marker だけでは区別
    /// できないため、陽性と同じ実行で回して陽性側の成功と対で読むこと。
    #[test]
    #[ignore = "requires read/write access to /dev/kvm (MVM-1)"]
    fn kernel_boot_net_rx_init_without_frame_reports_failure() {
        let inp = inputs(InitrdKind::NetRx);
        let cmdline = force_panic_zero(&inp.cmdline);
        let obs = Arc::new(VirtioWindowObserver::new());
        let (backend, counters) = CountingNetBackend::new();
        let (o, boot_timeout) = run_boot(
            inp,
            cmdline,
            1,
            vec![],
            vec![net_config_with(backend)],
            Some(obs.clone()),
        );
        let s = obs.stats(VirtioDeviceKind::Net);
        let recv_calls = counters.recv_calls.load(Ordering::Relaxed);
        let delivered = counters.delivered.load(Ordering::Relaxed);
        let diag = format!(
            "{} net={s:?} net_slots={} recv_calls={recv_calls} delivered={delivered} hint=\"{KCONFIG_HINT}\"",
            o.diag(),
            o.net_slots
        );
        assert_net_init_boot(
            &o,
            boot_timeout,
            NET_RX_FAILED_MARKER,
            NET_RX_OK_MARKER,
            &diag,
        );
        assert_eq!(o.net_slots, 1, "assembled net devices: {diag}");
        assert_eq!(s.driver_ok_first, Some(0x0F), "net DRIVER_OK: {diag}");
        assert_eq!(s.failed_writes, 0, "net FAILED writes: {diag}");
        assert_eq!(s.queue_ready_one, 2, "net QUEUE_READY=1 count: {diag}");
        assert!(recv_calls >= 1, "rx poller never ran: {diag}");
        assert_eq!(delivered, 0, "no frame must be delivered: {diag}");
        eprintln!(
            "kernel_boot: ok arch=aarch64 case=virtio_net_rx_no_frame elapsed_ms={} exits={}",
            o.elapsed.as_millis(),
            o.exits
        );
    }

    /// MVM-1・#3966: net-tx・net-rx の initrd の環境変数名・既定パス・生成コマンドのヒント。
    #[test]
    fn mvm1_3966_arm64_net_initrd_paths() {
        let (env, rel, hint) = initrd_spec(InitrdKind::NetTx).expect("net-tx has an initrd");
        assert_eq!(env, "FANDHE_CONTAINER_MICROVM_NET_TX_INITRD");
        assert!(rel.ends_with("aarch64-net-tx/initrd.cpio"), "{rel}");
        assert!(
            hint.contains("MICROVM_TEST_INITRD_VARIANT=net-tx"),
            "{hint}"
        );
        assert!(hint.contains("MICROVM_TEST_INITRD_ARCH=aarch64"), "{hint}");
        let (env, rel, hint) = initrd_spec(InitrdKind::NetRx).expect("net-rx has an initrd");
        assert_eq!(env, "FANDHE_CONTAINER_MICROVM_NET_RX_INITRD");
        assert!(rel.ends_with("aarch64-net-rx/initrd.cpio"), "{rel}");
        assert!(
            hint.contains("MICROVM_TEST_INITRD_VARIANT=net-rx"),
            "{hint}"
        );
        assert!(hint.contains("MICROVM_TEST_INITRD_ARCH=aarch64"), "{hint}");
    }

    /// 2 台構成の陽性（#3899・MVM-1・REPAIR-5・REPAIR-12）。AP が PSCI CPU_ON でオンラインになり、2 台とも回収される。
    #[test]
    #[ignore = "requires read/write access to /dev/kvm and a kernel with CONFIG_SMP (MVM-1)"]
    fn kernel_boot_two_vcpus_reaches_init_and_shuts_down() {
        let inp = inputs(InitrdKind::Default);
        if let Some(p) = smp_disabling_param(&inp.cmdline) {
            precondition(&format!(
                "cmdline disables SMP (`{p}`); remove it for the two-vCPU case"
            ));
        }
        let cmdline = force_panic_zero(&inp.cmdline);
        let (o, boot_timeout) = run_boot(inp, cmdline, 2, vec![], vec![], None);
        let diag = o.diag();
        assert_eq!(o.reason, StopReason::GuestShutdown, "stop reason: {diag}");
        // reboot は CPU 0 から行われる（`migrate_to_reboot_cpu`）。
        assert_eq!(o.origin_vcpu, Some(0), "origin vcpu: {diag}");
        assert_eq!(o.vcpu_count, 2, "vcpu count: {diag}");
        assert_eq!(o.errors, 0, "run errors: {diag}");
        assert!(!o.timed_out, "boot timed out: {diag}");
        assert!(o.elapsed < boot_timeout, "elapsed over budget: {diag}");
        assert_eq!(
            count_marker_lines(&o.output, MARKER),
            1,
            "init marker must appear exactly once: {diag}"
        );
        assert_eq!(o.uart_dropped, 0, "uart dropped bytes: {diag}");
        for line in [ARM64_SMP_TOTAL_LINE, SMP_ONLINE_LINE] {
            assert_eq!(
                count_lines_ending_with(&o.output, line),
                1,
                "expected exactly one `{line}` line: {diag}"
            );
        }
        assert_eq!(
            count_lines_containing(&o.output, AP_BOOTED_PREFIX),
            1,
            "expected exactly one `{AP_BOOTED_PREFIX}` line (MPIDR must match the FDT): {diag}"
        );
        eprintln!(
            "kernel_boot: ok arch=aarch64 case=two_vcpus reason=guest_shutdown elapsed_ms={} exits={}",
            o.elapsed.as_millis(),
            o.exits
        );
    }

    /// MVM-1・#3899: 既定の cmdline は SMP を無効化しない（行照合・指定の見分けは `guest_boot` の単体試験）。
    #[test]
    fn mvm1_3899_arm64_default_cmdline_keeps_smp() {
        assert_eq!(smp_disabling_param(DEFAULT_CMDLINE), None);
    }

    /// MVM-1・#3898: 既定の cmdline は `console=ttyS0` を含み、`force_panic_zero` 後も `panic=0` が末尾に残る。
    #[test]
    fn mvm1_3898_arm64_default_cmdline_selects_ttys0() {
        assert_eq!(DEFAULT_CMDLINE, "console=ttyS0 rdinit=/init");
        assert_eq!(
            force_panic_zero(DEFAULT_CMDLINE),
            "console=ttyS0 rdinit=/init panic=0"
        );
    }
}
/// x86_64・aarch64 以外では `assemble` が `Unimplemented` であることの確認（aarch64 は `mod arm64`・#3897）。
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
mod other {
    use fandhe_container_microvm::error::MicrovmErrorCode;
    use fandhe_container_microvm::microvm::{MicroVm, MicroVmConfig, NetDeviceConfig};
    use fandhe_container_microvm::virtio_block::MemoryBlockBackend;
    use fandhe_container_microvm::virtio_net::MemoryNetBackend;

    fn assert_unimplemented(config: MicroVmConfig<MemoryBlockBackend, MemoryNetBackend>) {
        let dev = super::open_kvm();
        assert_eq!(
            MicroVm::assemble(&dev, config).unwrap_err().code(),
            MicrovmErrorCode::Unimplemented
        );
    }

    #[test]
    #[ignore = "requires read/write access to /dev/kvm (MVM-1)"]
    fn kernel_boot_real_kernel_reaches_init_and_shuts_down() {
        assert_unimplemented(MicroVmConfig {
            vcpu_count: 1,
            mem_size: 1 << 20,
            block: vec![],
            net: vec![],
        });
    }

    #[test]
    #[ignore = "requires read/write access to /dev/kvm (MVM-1)"]
    fn kernel_boot_two_vcpus_reaches_init_and_shuts_down() {
        assert_unimplemented(MicroVmConfig {
            vcpu_count: 2,
            mem_size: 1 << 20,
            block: vec![],
            net: vec![],
        });
    }

    #[test]
    #[ignore = "requires read/write access to /dev/kvm (MVM-1)"]
    fn kernel_boot_with_virtio_block_reads_disk() {
        assert_unimplemented(MicroVmConfig {
            vcpu_count: 1,
            mem_size: 1 << 20,
            block: vec![MemoryBlockBackend::new(1 << 20, true).unwrap()],
            net: vec![],
        });
    }

    #[test]
    #[ignore = "requires read/write access to /dev/kvm (MVM-1)"]
    fn kernel_boot_with_virtio_block_init_reads_sentinel() {
        assert_unimplemented(MicroVmConfig {
            vcpu_count: 1,
            mem_size: 1 << 20,
            block: vec![MemoryBlockBackend::new(1 << 20, true).unwrap()],
            net: vec![],
        });
    }

    #[test]
    #[ignore = "requires read/write access to /dev/kvm (MVM-1)"]
    fn kernel_boot_with_virtio_block_init_detects_mismatch() {
        assert_unimplemented(MicroVmConfig {
            vcpu_count: 1,
            mem_size: 1 << 20,
            block: vec![MemoryBlockBackend::new(1 << 20, true).unwrap()],
            net: vec![],
        });
    }

    #[test]
    #[ignore = "requires read/write access to /dev/kvm (MVM-1)"]
    fn kernel_boot_with_virtio_net_init_sends_frame() {
        assert_unimplemented(MicroVmConfig {
            vcpu_count: 1,
            mem_size: 1 << 20,
            block: vec![],
            net: vec![NetDeviceConfig {
                backend: MemoryNetBackend::new(),
                mac: [0x02, 0xfc, 0x00, 0x00, 0x38, 0x65],
            }],
        });
    }

    #[test]
    #[ignore = "requires read/write access to /dev/kvm (MVM-1)"]
    fn kernel_boot_net_tx_init_without_net_device_reports_failure() {
        assert_unimplemented(MicroVmConfig {
            vcpu_count: 1,
            mem_size: 1 << 20,
            block: vec![],
            net: vec![],
        });
    }

    #[test]
    #[ignore = "requires read/write access to /dev/kvm (MVM-1)"]
    fn kernel_boot_with_virtio_net_init_receives_frame() {
        assert_unimplemented(MicroVmConfig {
            vcpu_count: 1,
            mem_size: 1 << 20,
            block: vec![],
            net: vec![NetDeviceConfig {
                backend: MemoryNetBackend::new(),
                mac: [0x02, 0xfc, 0x00, 0x00, 0x38, 0x65],
            }],
        });
    }

    #[test]
    #[ignore = "requires read/write access to /dev/kvm (MVM-1)"]
    fn kernel_boot_net_rx_init_without_frame_reports_failure() {
        assert_unimplemented(MicroVmConfig {
            vcpu_count: 1,
            mem_size: 1 << 20,
            block: vec![],
            net: vec![NetDeviceConfig {
                backend: MemoryNetBackend::new(),
                mac: [0x02, 0xfc, 0x00, 0x00, 0x38, 0x65],
            }],
        });
    }

    #[test]
    #[ignore = "requires read/write access to /dev/kvm (MVM-1)"]
    fn kernel_boot_with_virtio_net_reaches_driver_ok() {
        assert_unimplemented(MicroVmConfig {
            vcpu_count: 1,
            mem_size: 1 << 20,
            block: vec![],
            net: vec![NetDeviceConfig {
                backend: MemoryNetBackend::new(),
                mac: [0x02, 0xfc, 0x00, 0x00, 0x38, 0x65],
            }],
        });
    }
}
