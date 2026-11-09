//! macOS（HVF）で実 Linux カーネルを `/init` まで起動する実機前提の結合試験（MVM-5・MVM-1・REPAIR-5・REPAIR-12・TASK-192・#3986）。
//! `--ignored` 指定時だけ走る。`tests/kernel_boot.rs` の `arm64`（KVM。#3897・#3898）の macOS 対応物で、`hvf_microvm.rs`（#3799）が
//! 合成 arm64 Image で確かめた `HvfMicroVm::assemble` → `start` → ゲスト起因の停止 → `stop` を、利用者が用意した
//! 実 Linux の arm64 `Image` と最小 initrd（`scripts/build-microvm-test-initrd.sh`）で通す。人間担当の #3988 が実機で実行する。
//!
//! 必要環境: Apple Silicon の macOS 15 以降、`com.apple.security.hypervisor` 付きの ad-hoc 署名（`tests/hvf.entitlements`）、
//! 非圧縮の arm64 `Image`、`MICROVM_TEST_INITRD_ARCH=aarch64 make microvm-test-initrd-build` の出力。root は不要。
//! 手順は `docs/verification/real-machine-tests.md` の `hvf_kernel_boot` の項。1 プロセス 1 VM のため `--test-threads=1` で実行する。
//! 環境変数: `FANDHE_CONTAINER_MICROVM_KERNEL`（必須）・`_INITRD`（既定 `target/microvm-test-initrd/aarch64/initrd.cpio`）・
//! `_SERIAL_INITRD`（UART 試験用。既定 `target/microvm-test-initrd/aarch64-serial-echo/initrd.cpio`。#3987）・
//! `_BLOCK_INITRD`（block-read 用。既定 `target/microvm-test-initrd/aarch64-block-read/initrd.cpio`。#4014）・
//! `_CMDLINE`（既定 `console=ttyS0 rdinit=/init`。末尾に `panic=0` を足す）・`_BOOT_TIMEOUT_SECS`（1..=600、既定 60）。
//!
//! 観測手段: ゲストの `/init` がシリアル（ns16550a の MMIO）へ書く固定文字列（`MARKER`）を行単位でちょうど 1 回数え、停止理由が
//! `StopReason::GuestShutdown`（`/init` の `reboot(RESTART)` → PSCI SYSTEM_RESET → `hvc` の exit）、エラー 0 件、UART の取りこぼし
//! 0 バイトであることを具体値で照合する。`ttyS0 at MMIO 0x9000000 (irq = N, ...)` の行から、シリアルが割り込みで結線されている
//! こと（`N != 0`）も見る。期限切れで `stop` した `Requested` は合格にしない。負の対照は initrd 無しで、期限まで止まらないことを見る。
//! 起点 vCPU は `HvfStopReport` に無いため照合しない（`kernel_boot` の KVM 版との差）。
//!
//! UART の送受信（#3987・MVM-5・MVM-1。`serial-echo` の initrd）: ゲストが `/dev/ttyS0` へ送信 FIFO（16 バイト）の 10 倍の行を書いて
//! `tcdrain` し（THRE 割り込み #3892 が進まないと止まる）、ready を出す。ホストの起動スレッド（vCPU 以外のホストスレッド）が
//! `SerialConsole::push_input`（#3893）で改行つきの行を 4 回押し、ゲストが読んだ行へ接頭辞を付けて書き戻すことを、
//! 「接頭辞 + 入力」の行がちょうど 1 回出ることで照合する（tty の ECHO は入力そのものを返すため、入力の文字列だけでは根拠にならない）。
//! 割り込みは `/proc/interrupts` を 2 回（最初と最後に）出させ、`ttyS0` の行の回数が `SERIAL_RX_ROUNDS + 1` 以上増えることで見る。
//! 下限が「送信バイト数 / 16」でない理由: Linux の 8250 の割り込みハンドラは IIR が保留を返す間は同じ呼び出しの中で回るため、
//! 即時に THRE が立つモデルでは長い行でも 1 回で済みうる（8250_core.c の挙動。版を固定した照合は未実施）。
//! 入力だけの増分は分離しない（snapshot の出力自体が送信割り込みを起こすため）。入力の経路の証跡は書き戻しの行と `input_read_bytes`。
//! `push_input` からゲストの RBR 読み出しまでの遅れ（試験内の `WFI_WAIT_MAX`〔10 ms の基準。#4039〕との比較用）は観測の行へ出すだけで assert しない
//! （実行環境で揺れる。判定は #3988）。負の対照は入力を押さない版で、ゲストが rx timeout に落ち、書き戻しが入力に由来することを裏づける。
//! `/init` は最初に `syslog(CONSOLE_OFF)` で printk を止める（非同期の printk が行の途中へ割り込み、行単位の照合が偽の失敗になるのを防ぐ）。
//! vCPU 2 台の陽性（#3998。`hvf_kernel_boot_two_vcpus_reaches_init_and_shuts_down`）: AP（vCPU 1）は PSCI CPU_ON で起動する
//! （#3803 が合成ゲストで確認済み）。上の 1 台と同じ照合に加え、起動ログの
//! `SMP: Total of 2 processors activated.`・`smp: Brought up 1 node, 2 CPUs`・`CPU1: Booted secondary processor 0x0000000001`
//! （FDT の `cpu@1` の `reg` と一致した MPIDR）が各ちょうど 1 行、vCPU 1 の `runs` が 1 以上（`exits` の下限は置かない。GIC つきの
//! 実機では WFI も `VTIMER_ACTIVATED` も exit しないため。#3803・#3994）であることを見る。`CONFIG_SMP`・`CONFIG_NR_CPUS` 2 以上の要件は
//! `kernel_boot` の aarch64 の項と同じ。cmdline の `nosmp`・`maxcpus=` は前提欠如（skip せず失敗）、`quiet` や 7 未満の `loglevel=` は
//! 行が出ず照合で落ちる。exit 種別（`wfx` 等）は `VcpuExitObserver::on_exit` が vCPU 番号を持たないため全 vCPU の合計のまま。
//!
//! 全体期限（REPAIR-5）: `.cargo/config.toml` の watchdog は `--ignored` を素通しするため、本試験自身の `Watchdog`
//! （超過で `hvf_kernel_boot: WATCHDOG EXPIRED` と終了コード 124）・ポーリング期限・`stop` の期限・外側の `recv_timeout` が層になる。
//! 前提欠如は skip せず `hvf_kernel_boot: PRECONDITION FAILED (test environment, not a regression)` で落とす。
//!
//! 既知のリスク（起動が止まったときの切り分け。いずれも試験を緩めず、原因ごとに別 issue にする）:
//! - 実カーネルは合成 Image が踏まなかった exit（システムレジスタの trap・SMC・ISV=0 の data abort）を踏みうる。`hvf_loop` は
//!   これらを fail-closed で `Failed(..)` にする。`Failed(..)` は device model 側の問題であり、試験の欠陥ではない。
//! - 実カーネルでの I-cache の clean の要否は未確認（`hvf/microvm.rs` の範囲外の項目・#3988）。起動できないときの切り分け先。
//! - 内側の期限で panic すると起動スレッドが残り、同じプロセスの次の試験は VM の作成で `FailedPrecondition` になりうる。
//!   `stop` の期限切れでは、切り離した vCPU スレッドが終わるまで RAM と VM が残り同じプロセスで作り直せない（終了後は回収される。#4032）。いずれも先に出た失敗を原因として読む。
//! - 2 台の reboot では `smp_send_stop` が AP の停止を最大約 1 秒待つ。2 台で止まったときの `Failed(..)` も device model 側の
//!   別 issue で、試験を緩めない（#3998）。
//! - `guest/kernel/arm64-guest.config` は Virtualization.framework 用で `SERIAL_8250` などが無く、本試験の Image には使えない。
//!
//! virtio-block の block-read（#4014・MVM-5・MVM-1。`block-read` の initrd: `_BLOCK_INITRD`、既定
//! `target/microvm-test-initrd/aarch64-block-read/initrd.cpio`）: backend の offset 0 に `BLOCK_SENTINEL` を置いた virtio-block 1 台を
//! 載せ、ゲストが `/dev/vda` の先頭 32 バイトを読んで一致したときだけ出す `BLOCK_OK_MARKER` がちょうど 1 回、`BLOCK_MISMATCH_MARKER` と
//! 既定の `MARKER` が 0 回であることを見る。virtio の SPI は FDT の既定の edge-rising と `IrqTrigger::LevelHigh` の 2 構成で起動する
//! （FDT の trigger と HVF の線の注入方式は同じ layout から決まり、食い違えば `bind` が拒否する）。HVF の `QueueNotify` の処理
//! （#4028）と、level の線の ACK 後の deassert / 上げ直し（#3863）が実カーネルで働くことの照合である。`InterruptACK` の後処理の結果は
//! `RunningHvfMicroVm::interrupt_ack_counts` で読み、結果行に `acks=`・`deasserted=`・`reasserted=`・`not_applicable=`・`resets=`（`DeviceReset` 後の resample の回数。#4170・#4230）として出すだけで
//! assert しない（判断材料。評価は #3988）。カーネルは `CONFIG_VIRTIO_MMIO`・`CONFIG_VIRTIO_BLK`・`CONFIG_BLOCK`・`CONFIG_DEVTMPFS`
//! （`kernel_boot` の aarch64 の項と同じ）。負の対照は block デバイス無しで、不一致 marker が出る（一致 marker が block に由来する裏づけ）。
//!
//! 交渉結果の観測（#4289・MVM-5・MVM-1）: lib の `VcpuExitObserver::wants_values` / `on_value`（opt-in。MMIO の書き込み値を vCPU スレッドから
//! dispatch の前に渡す。vCPU 番号は渡らない）で、観測器 `HvfBootObserver` が block の窓の `DRIVER_FEATURES`・STATUS を集計する
//! （窓の集計と照合は `support/virtio_window.rs` で KVM の `kernel_boot.rs` と共有）。block-read の陽性 2 件は、FEATURES_OK `0x0B` が
//! ちょうど 1 回・ビット 40（`VIRTIO_F_RING_RESET`。`docs/design/microvm-virtio-ring-reset.md`）が 0・上位ページがちょうど `0x1`
//! （VERSION_1 のみ）・下位ページが提示集合の部分集合・DRIVER_OK `0x0F`・FAILED 0 件・QUEUE_READY=1 がちょうど 1 回であることを照合し、
//! 結果行へ `features_ok=0x0b driver_features=0x... ring_reset=0` を足す。負の対照（block 無し）は窓が無いこと（`None`）を見る。
//! 実機での確認は #3988（人間担当）。Agent は実行していない。
//!
//! 未実装（REPAIR-3）: virtio-net の `QueueNotify`（#4029）は未結線のため net は載せない。
//! 実機での実行と記録は #3988（人間担当）。Agent は実カーネルでの起動を確かめていない（`serial-echo` と `block-read` の `/init` も未実行）。
#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

#[path = "support/guest_boot.rs"]
mod guest_boot;
/// virtio-mmio の窓の集計と交渉結果の照合（`kernel_boot.rs` の KVM 版と共有。#4289・REPAIR-1）。
#[path = "support/virtio_window.rs"]
mod virtio_window;

use fandhe_container_microvm::arm64_layout::{ARM64_SERIAL_BASE, ARM64_SERIAL_SPI, Arm64Layout};
use fandhe_container_microvm::boot_arm64::Arm64ImageHeader;
use fandhe_container_microvm::error::MicrovmErrorCode;
use fandhe_container_microvm::exit::ExitValue;
use fandhe_container_microvm::hvf::{
    HvfDeviceKind, HvfMicroVm, HvfMicroVmConfig, VcpuThreadConfig, VmWithGic,
};
use fandhe_container_microvm::hvf_abi::HvRunStats;
use fandhe_container_microvm::hvf_loop::{ExitCounts, ExitKind, VcpuExitObserver};
use fandhe_container_microvm::interrupt::{InterruptAckCounts, IrqTrigger};
use fandhe_container_microvm::stop::StopReason;
use fandhe_container_microvm::uart::{SerialConsole, UartStats};
use fandhe_container_microvm::virtio_block::{BlockBackend, MemoryBlockBackend};
use fandhe_container_microvm::virtio_net::MemoryNetBackend;
use guest_boot::{
    AP_BOOTED_PREFIX, ARM64_SMP_TOTAL_LINE, BLOCK_MISMATCH_MARKER, BLOCK_OK_MARKER, BLOCK_SENTINEL,
    MARKER, SERIAL_FAILED, SERIAL_OK, SERIAL_READY, SERIAL_RX_PREFIX, SERIAL_RX_ROUNDS,
    SERIAL_RX_TIMEOUT, SERIAL_TX_LINE, SMP_ONLINE_LINE, TtyAddress, TtyReport,
    count_lines_containing, count_lines_ending_with, count_marker_lines, escape_tail,
    force_panic_zero, parse_irq_rows, parse_tty_report, read_bounded, smp_disabling_param,
};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};
use virtio_window::{
    BLOCK_OFFERED_LOW, VirtioWindows, WindowKind, WindowStats, assert_features_negotiated,
    features_result_fields,
};

/// `console=ttyS0` で FDT の `ns16550a` を 8250 のコンソールに選び、`rdinit=/init` で initrd の `/init` を起動する。
const DEFAULT_CMDLINE: &str = "console=ttyS0 rdinit=/init";
const DEFAULT_TIMEOUT_SECS: u64 = 60;
const RAM_SIZE: u64 = 256 << 20;
const KERNEL_CAP: u64 = fandhe_container_microvm::boot_x86::MAX_KERNEL_IMAGE_BYTES;
const INITRD_CAP: u64 = 64 << 20;
/// シリアル出力の蓄積上限（無制限確保の防止）。
const OUTPUT_CAP: usize = 4 << 20;
/// `stop` の期限（`stop` 自身の上限 60 秒以内）。
/// 入力の遅れの比較用の基準（製品の `WFI_WAIT_MAX` を #4039 で消したため試験内に持つ）。
const WFI_WAIT_MAX: Duration = Duration::from_millis(10);
const STOP_DEADLINE: Duration = Duration::from_secs(10);
/// 外側の `recv_timeout` が内側（起動スレッドの全体）より余裕を持つための上乗せ。
const SLACK: Duration = Duration::from_secs(15);
/// `Watchdog` が内側の期限（`boot_timeout + STOP_DEADLINE + SLACK`）より後に効くための上乗せ。
const WATCHDOG_MARGIN: Duration = Duration::from_secs(30);
const TAIL_BYTES: usize = 4096;

/// 前提欠如の panic の 1 行目（CI・人間が見分ける固定形式）。
fn precondition(reason: &str) -> ! {
    panic!("hvf_kernel_boot: PRECONDITION FAILED (test environment, not a regression): {reason}")
}

/// 試験全体の期限。内側の `recv_timeout` より必ず長い。固定値にしないのは、`_BOOT_TIMEOUT_SECS` が最大 600 秒で、
/// 負の対照が既定 60 秒を使い切るため（REPAIR-5）。
fn overall_deadline(boot_timeout_secs: u64) -> Duration {
    Duration::from_secs(boot_timeout_secs) + STOP_DEADLINE + SLACK + WATCHDOG_MARGIN
}

/// 期限 watchdog。panic しても止めて join する RAII ガード（`hvf_microvm.rs` と同じ形）。
struct Watchdog(Arc<AtomicBool>, Option<std::thread::JoinHandle<()>>);

impl Watchdog {
    fn start(deadline: Duration) -> Self {
        let flag = Arc::new(AtomicBool::new(false));
        let f = Arc::clone(&flag);
        let h = std::thread::spawn(move || {
            let start = Instant::now();
            while start.elapsed() < deadline {
                if f.load(Ordering::Acquire) {
                    return;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            eprintln!("hvf_kernel_boot: WATCHDOG EXPIRED");
            std::process::exit(124);
        });
        Watchdog(flag, Some(h))
    }
}

impl Drop for Watchdog {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
        if let Some(h) = self.1.take() {
            let _ = h.join();
        }
    }
}

/// 起動の入力（前提の検査はすべてテストスレッドで済ませる）。
struct Inputs {
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
    /// UART の送受信を照合する版（`FANDHE_CONTAINER_MICROVM_SERIAL_INITRD`。#3987）。
    SerialEcho,
    /// `/dev/vda` の先頭を読んで sentinel と比べる版（`FANDHE_CONTAINER_MICROVM_BLOCK_INITRD`。#4014）。
    BlockRead,
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
        InitrdKind::SerialEcho => Some((
            "FANDHE_CONTAINER_MICROVM_SERIAL_INITRD",
            "../../target/microvm-test-initrd/aarch64-serial-echo/initrd.cpio",
            "MICROVM_TEST_INITRD_ARCH=aarch64 MICROVM_TEST_INITRD_VARIANT=serial-echo make microvm-test-initrd-build",
        )),
        InitrdKind::BlockRead => Some((
            "FANDHE_CONTAINER_MICROVM_BLOCK_INITRD",
            "../../target/microvm-test-initrd/aarch64-block-read/initrd.cpio",
            "MICROVM_TEST_INITRD_ARCH=aarch64 MICROVM_TEST_INITRD_VARIANT=block-read make microvm-test-initrd-build",
        )),
    }
}

/// 前提を検査して入力を作る。欠如は skip せず `precondition` で落とす。`kind` が `None` なら initrd を読まない（負の対照）。
/// 呼び出し順: 期限の解釈 → watchdog の開始（`start_watchdog`）→ 本関数。ここでの読み込みは上限つき・`O_NONBLOCK`。
fn inputs(kind: InitrdKind, secs: u64) -> Inputs {
    let kernel_path = match std::env::var("FANDHE_CONTAINER_MICROVM_KERNEL") {
        Ok(p) if !p.is_empty() => p,
        _ => precondition("FANDHE_CONTAINER_MICROVM_KERNEL is not set (path to an arm64 Image)"),
    };
    let kernel = read_bounded(Path::new(&kernel_path), KERNEL_CAP)
        .unwrap_or_else(|e| precondition(&format!("kernel image: {e}")));
    if let Err(e) = Arm64ImageHeader::parse(&kernel) {
        precondition(&format!(
            "kernel image is not an uncompressed arm64 Image: {e}"
        ));
    }
    let initrd = initrd_spec(kind).map(|(var, default_rel, hint)| {
        let path = match std::env::var(var) {
            Ok(p) if !p.is_empty() => std::path::PathBuf::from(p),
            _ => Path::new(env!("CARGO_MANIFEST_DIR")).join(default_rel),
        };
        read_bounded(&path, INITRD_CAP)
            .unwrap_or_else(|e| precondition(&format!("initrd (run `{hint}`): {e}")))
    });
    let cmdline = guest_boot::validate_cmdline_or(
        std::env::var("FANDHE_CONTAINER_MICROVM_CMDLINE")
            .ok()
            .as_deref(),
        DEFAULT_CMDLINE,
    )
    .unwrap_or_else(|e| precondition(&e));
    Inputs {
        kernel,
        initrd,
        cmdline: force_panic_zero(&cmdline),
        secs,
    }
}

/// 環境変数の期限を解釈する。不正は前提欠如。
fn boot_timeout_secs() -> u64 {
    guest_boot::parse_boot_timeout_or(
        std::env::var("FANDHE_CONTAINER_MICROVM_BOOT_TIMEOUT_SECS")
            .ok()
            .as_deref(),
        DEFAULT_TIMEOUT_SECS,
    )
    .unwrap_or_else(|e| precondition(&e))
}

/// 配置（virtio 窓 0・既定のシリアル）。block-read 以外の試験が使う（block・net は載せない）。
fn layout(vcpus: u32) -> Arm64Layout {
    Arm64Layout::new(RAM_SIZE, vcpus, 0)
        .and_then(Arm64Layout::with_default_serial)
        .unwrap_or_else(|e| panic!("hvf_kernel_boot: layout: {e}"))
}

/// block-read の配置（vCPU 1 台・virtio 窓 1 つ・既定のシリアル）。virtio の SPI の trigger は `trigger` にする。
/// FDT の trigger と HVF の線の注入方式は同じ layout から決まる（`bind` が `check_virtio_injection` で照合。#4014）。
fn block_layout(trigger: IrqTrigger) -> Arm64Layout {
    let mut l = Arm64Layout::new(RAM_SIZE, 1, 1)
        .and_then(Arm64Layout::with_default_serial)
        .unwrap_or_else(|e| panic!("hvf_kernel_boot: block layout: {e}"));
    l.virtio_spi_trigger = trigger;
    l
}

/// backend の offset 0 に `sentinel` を置いた 1 MiB の block backend（`kernel_boot` の aarch64 版と同じ）。
fn block_backend(sentinel: Option<&[u8]>) -> MemoryBlockBackend {
    let mut b = MemoryBlockBackend::new(1 << 20, false).expect("valid block capacity");
    if let Some(s) = sentinel {
        b.write_at(0, s).expect("sentinel fits in capacity");
    }
    b
}

/// 起動する構成（配置と block backend）。vCPU 数は `layout.vcpus`。
struct BootPlan {
    layout: Arm64Layout,
    block: Vec<MemoryBlockBackend>,
}

impl BootPlan {
    /// virtio 無しで vCPU `vcpus` 台（既存の試験）。
    fn plain(vcpus: u32) -> Self {
        Self {
            layout: layout(vcpus),
            block: Vec::new(),
        }
    }
}

/// 環境の前提（権限）を、組み立てとは別に先に確かめる。権限不足だけを環境の問題とし、それ以外の失敗はそのまま出す（#3989）。
fn require_vm_with_gic(layout: &Arm64Layout) {
    match VmWithGic::create(layout) {
        Ok(vm) => drop(vm),
        Err(e) if e.code() == MicrovmErrorCode::PermissionDenied => precondition(&e.to_string()),
        Err(e) => panic!("hvf_kernel_boot: gic: {e}"),
    }
}

/// 起動 1 回の結果。
struct Outcome {
    reason: StopReason,
    vcpu_count: u32,
    errors: u64,
    exits: u64,
    /// vCPU ごとの実行統計（index 順。`[0]` が BSP）。
    per_vcpu: Vec<HvRunStats>,
    output: Vec<u8>,
    uart_dropped: u64,
    /// 停止後の UART の計数（入力の受理・読み出し・破棄。#3987）。
    uart: UartStats,
    /// `push_input` からゲストの RBR 読み出しまでの遅れ（往復ごと。`Interaction::SerialEcho` のみ）。
    rx_latencies: Vec<Duration>,
    /// 対話の状態機械が失敗したときの理由（失敗でも `stop` まで進める。REPAIR-5）。
    interaction_error: Option<String>,
    timed_out: bool,
    elapsed: Duration,
    /// exit の種別ごとの回数（診断・#3988 の判断材料。値は assert しない）。全 vCPU の合計で、vCPU ごとの内訳は取れない。
    wfx: u64,
    vtimer: u64,
    data_abort: u64,
    hvc: u64,
    /// block 0 台目の `InterruptACK` 後処理の計数（停止前に読む。block 無しは `None`。値は assert しない。#4014）。
    ack: Option<InterruptAckCounts>,
    /// block 0 台目の SPI の INTID（block 無しは `None`）。
    block_spi_intid: Option<u32>,
    /// block の窓の観測値（STATUS・QUEUE_READY・DRIVER_FEATURES への書き込み。block を載せた構成だけ `Some`。#4289）。
    block_window: Option<WindowStats>,
}

/// HVF の観測器（#4289）。exit の種別の集計（`ExitCounts`）と、MMIO の値の窓ごとの集計（`VirtioWindows`。KVM の
/// `VirtioWindowObserver` と共有の補助）をまとめる。`VcpuThreadConfig::observer` の枠は 1 つのためこの型で包む。
/// 値は vCPU スレッドから同期で渡る（割り当て・待ちなし。値はゲスト由来で数えるだけ）。
#[derive(Debug, Default)]
struct HvfBootObserver {
    counts: ExitCounts,
    windows: VirtioWindows,
}

impl VcpuExitObserver for HvfBootObserver {
    fn on_exit(&self, kind: ExitKind) {
        self.counts.on_exit(kind);
    }

    fn wants_values(&self) -> bool {
        true
    }

    fn on_value(&self, value: &ExitValue) {
        self.windows.record_value(value);
    }
}

/// vCPU ごとの統計を空白なしの 1 トークンにする（行の照合・grep をしやすくする。診断と成功行が共有）。
fn per_vcpu_summary(stats: &[HvRunStats]) -> String {
    stats
        .iter()
        .enumerate()
        .map(|(i, s)| {
            format!(
                "vcpu{i}(runs={},exits={},deadline_exceeded={},errors={},run_ms={})",
                s.runs,
                s.exits,
                s.deadline_exceeded,
                s.errors,
                s.total_elapsed.as_millis()
            )
        })
        .collect::<Vec<_>>()
        .join(";")
}

impl Outcome {
    fn diag(&self) -> String {
        format!(
            "reason={:?} vcpus={} errors={} exits={} per_vcpu={} wfx={} vtimer={} data_abort={} hvc={} \
             ack={:?} block_spi_intid={:?} block_window={:?} timed_out={} elapsed={:?} uart_dropped={} uart={:?} rx_latencies={:?} interaction_error={:?} \
             output_len={} output_tail=\"{}\"",
            self.reason,
            self.vcpu_count,
            self.errors,
            self.exits,
            per_vcpu_summary(&self.per_vcpu),
            self.wfx,
            self.vtimer,
            self.data_abort,
            self.hvc,
            self.ack,
            self.block_spi_intid,
            self.block_window,
            self.timed_out,
            self.elapsed,
            self.uart_dropped,
            self.uart,
            self.rx_latencies,
            self.interaction_error,
            self.output.len(),
            escape_tail(&self.output, TAIL_BYTES)
        )
    }
}

/// 起動スレッドの中でホスト側が行う対話。`RunningHvfMicroVm` は `!Send` なので閉包にせず、データ（`Send`）として渡して
/// 起動スレッドの中で駆動する。`push_input` は vCPU ではないホストスレッドから呼ぶ（`hv_gic_set_spi` の非 vCPU スレッドからの経路。#3803）。
enum Interaction {
    /// 何もしない（既存の 2 試験と、入力を押さない負の対照）。
    None,
    /// `serial-echo` の initrd に対し、ready を見て 4 回の行を押し、書き戻しを待つ。
    SerialEcho(SerialEcho),
}

/// 押す行。往復ごとに別の文字列にし、内容と順序の取り違えを検出する。
fn echo_input(round: usize) -> String {
    format!("echo-{round}\n")
}

/// 書き戻しの行（`SERIAL_RX_PREFIX` + 入力から改行を除いたもの）。
fn echo_reply(round: usize) -> String {
    format!("{SERIAL_RX_PREFIX}echo-{round}")
}

/// `push_input` の前に待機中のゲストへ空ける間隔。待機中（WFI）の起床を測るため。
const ECHO_IDLE: Duration = Duration::from_millis(50);
/// RBR の読み出しを待つ上限（スピン。sleep しない）。
const ECHO_READ_WAIT: Duration = Duration::from_secs(2);
/// 書き戻しの行を待つ上限。
const ECHO_REPLY_WAIT: Duration = Duration::from_secs(3);

#[derive(Debug, Clone, Copy)]
enum EchoStage {
    WaitReady,
    Idle(Instant),
    AwaitReply(Instant),
    Done,
}

struct SerialEcho {
    stage: EchoStage,
    round: usize,
    pushed_bytes: u64,
    latencies: Vec<Duration>,
    error: Option<String>,
}

impl SerialEcho {
    fn new() -> Self {
        Self {
            stage: EchoStage::WaitReady,
            round: 0,
            pushed_bytes: 0,
            latencies: Vec::new(),
            error: None,
        }
    }

    /// 1 ループ分進める。失敗は `error` に残して `Done` にする（呼び出し側が loop を抜けて必ず `stop` する）。
    fn step(&mut self, serial: &SerialConsole, output: &[u8]) {
        match self.stage {
            EchoStage::WaitReady => {
                if count_marker_lines(output, SERIAL_READY) >= 1 {
                    self.stage = EchoStage::Idle(Instant::now());
                }
            }
            EchoStage::Idle(since) => {
                if since.elapsed() >= ECHO_IDLE {
                    self.push(serial);
                }
            }
            EchoStage::AwaitReply(since) => {
                if count_marker_lines(output, &echo_reply(self.round)) >= 1 {
                    self.round += 1;
                    self.stage = if self.round >= SERIAL_RX_ROUNDS {
                        EchoStage::Done
                    } else {
                        EchoStage::Idle(Instant::now())
                    };
                } else if since.elapsed() >= ECHO_REPLY_WAIT {
                    self.fail(format!("no reply line for round {}", self.round));
                }
            }
            EchoStage::Done => {}
        }
    }

    fn fail(&mut self, reason: String) {
        self.error = Some(reason);
        self.stage = EchoStage::Done;
    }

    /// 1 行を押し、ゲストが RBR を読むまでをスピンで測る。
    fn push(&mut self, serial: &SerialConsole) {
        let line = echo_input(self.round);
        let before = match serial.stats() {
            Ok(st) => st,
            Err(e) => return self.fail(format!("stats failed: {e}")),
        };
        let t0 = Instant::now();
        match serial.push_input(line.as_bytes()) {
            Ok(r) if r.accepted == line.len() && r.dropped == 0 => {}
            Ok(r) => return self.fail(format!("push_input partial: {r:?}")),
            Err(e) => return self.fail(format!("push_input failed: {e}")),
        }
        self.pushed_bytes += line.len() as u64;
        let target = before.input_read_bytes + line.len() as u64;
        loop {
            match serial.stats() {
                Ok(st) if st.input_read_bytes >= target => {
                    self.latencies.push(t0.elapsed());
                    break;
                }
                Ok(_) if t0.elapsed() >= ECHO_READ_WAIT => {
                    return self.fail(format!("guest did not read round {}", self.round));
                }
                Ok(_) => std::thread::yield_now(),
                Err(e) => return self.fail(format!("stats failed: {e}")),
            }
        }
        self.stage = EchoStage::AwaitReply(Instant::now());
    }
}

/// 起動して停止まで見る。`RunningHvfMicroVm` は `!Send` なので、組み立てから停止までこのスレッドの中で完結させる。
/// `kernel_boot` の `boot` と同じ順序: `serial_console` を start の前に取り、10 ms ごと（対話中は 1 ms）に取り出し、
/// 期限切れ・対話の失敗でも必ず `stop` する。
fn boot(inp: Inputs, plan: BootPlan, mut interaction: Interaction) -> Result<Outcome, String> {
    let started = Instant::now();
    let boot_timeout = Duration::from_secs(inp.secs);
    let obs = Arc::new(HvfBootObserver::default());
    let vcpus = plan.layout.vcpus;
    let config: HvfMicroVmConfig<MemoryBlockBackend, MemoryNetBackend> = HvfMicroVmConfig {
        layout: plan.layout,
        vcpus,
        kernel: inp.kernel,
        initrd: inp.initrd,
        cmdline: inp.cmdline,
        block: plan.block,
        net: Vec::new(),
        vcpu: VcpuThreadConfig {
            observer: Some(obs.clone()),
            ..Default::default()
        },
        serial: true,
    };
    let vm = HvfMicroVm::assemble(config).map_err(|e| format!("assemble failed: {e}"))?;
    let serial = vm
        .serial_console()
        .ok_or_else(|| "serial console is not enabled".to_string())?;
    let block_info = vm
        .devices()
        .into_iter()
        .find(|d| d.kind == HvfDeviceKind::Block);
    // 窓は start の前に結ぶ（ゲストの最初の書き込みを取りこぼさない。#4289）。block を載せない構成では結ばない。
    if let Some(b) = block_info {
        obs.windows
            .bind(WindowKind::Block, b.window.base.raw(), b.window.size);
    }
    let running = vm.start().map_err(|e| format!("start failed: {e}"))?;
    let mut output: Vec<u8> = Vec::new();
    let mut timed_out = false;
    let mut interaction_error: Option<String> = None;
    let poll_interval = match interaction {
        Interaction::None => Duration::from_millis(10),
        Interaction::SerialEcho(_) => Duration::from_millis(1),
    };
    loop {
        let chunk = serial
            .take_output()
            .map_err(|e| format!("take_output failed: {e}"))?;
        output.extend_from_slice(&chunk);
        if output.len() > OUTPUT_CAP {
            return Err("guest serial output exceeded the test cap".into());
        }
        if let Interaction::SerialEcho(echo) = &mut interaction {
            echo.step(&serial, &output);
            if let Some(e) = echo.error.clone() {
                interaction_error = Some(e);
                break;
            }
        }
        if running.is_finished() {
            break;
        }
        if started.elapsed() >= boot_timeout {
            timed_out = true;
            break;
        }
        std::thread::sleep(poll_interval);
    }
    // 起動予算の判定に使う経過時間は、停止条件を判定した直後（stop の前）に採る。
    // stop の join・出力の取り切りの時間を予算に含めない（timed_out の判定時点と揃える）。
    let elapsed = started.elapsed();
    // ACK の後処理の計数は `stop` が self を消費する前に読む（#4014）。期限切れのときは vCPU が走行中で値が揺れうる。
    let ack = block_info.and_then(|b| {
        running
            .interrupt_ack_counts()
            .into_iter()
            .find(|c| c.id == b.id)
            .map(|c| c.counts)
    });
    // 期限切れでも必ず stop で vCPU を回収する（REPAIR-5）。
    let report = running
        .stop(STOP_DEADLINE)
        .map_err(|e| format!("stop failed: {e}"))?;
    // 停止までの出力を取り切る。
    let tail = serial
        .take_output()
        .map_err(|e| format!("take_output failed: {e}"))?;
    output.extend_from_slice(&tail);
    let uart = serial
        .stats()
        .map_err(|e| format!("uart stats failed: {e}"))?;
    let rx_latencies = match interaction {
        Interaction::None => Vec::new(),
        Interaction::SerialEcho(e) => e.latencies,
    };
    Ok(Outcome {
        reason: report.reason,
        vcpu_count: report.vcpu_count,
        errors: report.stats.errors,
        exits: report.stats.exits,
        per_vcpu: report.per_vcpu,
        output,
        uart_dropped: uart.dropped_bytes,
        uart,
        rx_latencies,
        interaction_error,
        timed_out,
        elapsed,
        wfx: obs.counts.count(ExitKind::Wfx),
        vtimer: obs.counts.count(ExitKind::Vtimer),
        data_abort: obs.counts.count(ExitKind::DataAbort),
        hvc: obs.counts.count(ExitKind::Hvc),
        ack,
        block_spi_intid: block_info.map(|b| b.spi_intid),
        block_window: block_info.map(|_| obs.windows.stats(WindowKind::Block)),
    })
}

/// 別スレッドで `boot` を回し、外側の `recv_timeout` で必ず戻る。
fn run_boot(inp: Inputs, plan: BootPlan, interaction: Interaction) -> (Outcome, Duration) {
    let secs = inp.secs;
    let boot_timeout = Duration::from_secs(secs);
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(boot(inp, plan, interaction));
    });
    match rx.recv_timeout(boot_timeout + STOP_DEADLINE + SLACK) {
        Ok(Ok(o)) => (o, boot_timeout),
        Ok(Err(e)) => panic!("hvf_kernel_boot: boot sequence failed: {e}"),
        Err(e) => panic!("hvf_kernel_boot: DEADLINE EXCEEDED ({e}) after {secs}s boot budget"),
    }
}

/// 起動の陽性に共通の照合（vCPU 数だけが 1 台・2 台で違う）。`ttyS0` の irq を返す。
fn assert_boot_ok(o: &Outcome, vcpus: u32, boot_timeout: Duration, diag: &str) -> u32 {
    assert_eq!(o.reason, StopReason::GuestShutdown, "stop reason: {diag}");
    assert_eq!(o.vcpu_count, vcpus, "vcpu count: {diag}");
    assert_eq!(o.errors, 0, "run errors: {diag}");
    assert!(!o.timed_out, "boot timed out: {diag}");
    assert!(o.elapsed < boot_timeout, "elapsed over budget: {diag}");
    assert_eq!(
        count_marker_lines(&o.output, MARKER),
        1,
        "init marker must appear exactly once: {diag}"
    );
    assert_eq!(o.uart_dropped, 0, "uart dropped bytes: {diag}");
    // ポーリングへの退行の検出。irq = 0 は DT に interrupts が無い印。値は virq なので != 0 だけを見る。
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
    irq
}

/// 陽性。`/init` の reboot（PSCI SYSTEM_RESET）が `GuestShutdown` で止まり、marker がちょうど 1 回出る。
#[test]
#[ignore = "requires Apple silicon macOS 15+ and a binary signed with com.apple.security.hypervisor (MVM-5)"]
fn hvf_kernel_boot_real_kernel_reaches_init_and_shuts_down() {
    let secs = boot_timeout_secs();
    let _wd = Watchdog::start(overall_deadline(secs));
    let inp = inputs(InitrdKind::Default, secs);
    require_vm_with_gic(&layout(1));
    let (o, boot_timeout) = run_boot(inp, BootPlan::plain(1), Interaction::None);
    let diag = o.diag();
    let irq = assert_boot_ok(&o, 1, boot_timeout, &diag);
    eprintln!(
        "hvf_kernel_boot: ok arch=aarch64 reason=guest_shutdown ttys0_irq={irq} elapsed_ms={} exits={} wfx={} vtimer={} data_abort={} hvc={} per_vcpu={}",
        o.elapsed.as_millis(),
        o.exits,
        o.wfx,
        o.vtimer,
        o.data_abort,
        o.hvc,
        per_vcpu_summary(&o.per_vcpu)
    );
}

/// 2 台構成の陽性（#3998・MVM-5・MVM-1・REPAIR-5・REPAIR-12）。AP が PSCI CPU_ON でオンラインになり、2 台とも回収される。
#[test]
#[ignore = "requires Apple silicon macOS 15+, a binary signed with com.apple.security.hypervisor and a kernel with CONFIG_SMP (MVM-5)"]
fn hvf_kernel_boot_two_vcpus_reaches_init_and_shuts_down() {
    let secs = boot_timeout_secs();
    let _wd = Watchdog::start(overall_deadline(secs));
    let inp = inputs(InitrdKind::Default, secs);
    if let Some(p) = smp_disabling_param(&inp.cmdline) {
        precondition(&format!(
            "cmdline disables SMP (`{p}`); remove it for the two-vCPU case"
        ));
    }
    require_vm_with_gic(&layout(2));
    let (o, boot_timeout) = run_boot(inp, BootPlan::plain(2), Interaction::None);
    let diag = o.diag();
    let irq = assert_boot_ok(&o, 2, boot_timeout, &diag);
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
    assert_eq!(o.per_vcpu.len(), 2, "per-vcpu stats: {diag}");
    // AP が実際に走ったこと（`hvf_device_smp_cpu_on_boots_ap` と同じ基準。exits の下限は根拠が無いので見ない）。
    let ap_runs = o.per_vcpu.get(1).map(|s| s.runs).unwrap_or(0);
    assert!(ap_runs >= 1, "vcpu 1 never ran (ap_runs={ap_runs}): {diag}");
    eprintln!(
        "hvf_kernel_boot: ok arch=aarch64 case=two_vcpus reason=guest_shutdown ttys0_irq={irq} elapsed_ms={} exits={} wfx={} vtimer={} data_abort={} hvc={} per_vcpu={}",
        o.elapsed.as_millis(),
        o.exits,
        o.wfx,
        o.vtimer,
        o.data_abort,
        o.hvc,
        per_vcpu_summary(&o.per_vcpu)
    );
}

/// 負の対照。initrd が無いと rootfs の mount に失敗して panic し、`panic=0` でループするので期限まで止まらない。
/// 既定 60 秒を使い切る。陽性と同じ実行・同じカーネルで回すこと（対照の結果が陽性の `GuestShutdown` の意味を裏づける）。
/// `Failed(..)` が出たら device model 側の別 issue。カーネルは `CONFIG_PANIC_TIMEOUT=0` かつ組み込み initramfs 無しが前提。
#[test]
#[ignore = "requires Apple silicon macOS 15+ and a binary signed with com.apple.security.hypervisor (MVM-5)"]
fn hvf_kernel_boot_without_initrd_does_not_shut_down() {
    let secs = boot_timeout_secs();
    let _wd = Watchdog::start(overall_deadline(secs));
    let inp = inputs(InitrdKind::None, secs);
    require_vm_with_gic(&layout(1));
    let (o, _) = run_boot(inp, BootPlan::plain(1), Interaction::None);
    let diag = o.diag();
    assert_ne!(o.reason, StopReason::GuestShutdown, "stop reason: {diag}");
    assert_eq!(o.reason, StopReason::Requested, "stop reason: {diag}");
    assert!(o.timed_out, "expected budget exhaustion: {diag}");
    assert_eq!(o.vcpu_count, 1, "vcpu count: {diag}");
    assert_eq!(o.errors, 0, "run errors: {diag}");
    assert_eq!(
        count_marker_lines(&o.output, MARKER),
        0,
        "init marker must not appear without an initrd: {diag}"
    );
    assert_eq!(o.uart_dropped, 0, "uart dropped bytes: {diag}");
}

/// block-read の 3 件に共通の本体（#4014・MVM-5・MVM-1・REPAIR-12）。`expect`（期待する marker）がちょうど 1 回、`other`（もう一方）と
/// 既定の `MARKER` が 0 回、`GuestShutdown`・エラー 0・UART の取りこぼし 0・期限内であることを具体値で照合する。
/// ACK の後処理の計数は結果行に出すだけで assert しない（判断は #3988）。届いた証跡は marker で取る。
fn run_block_read(plan: BootPlan, expect: &str, other: &str, case: &str) {
    let block_present = !plan.block.is_empty();
    let secs = boot_timeout_secs();
    let _wd = Watchdog::start(overall_deadline(secs));
    let inp = inputs(InitrdKind::BlockRead, secs);
    require_vm_with_gic(&plan.layout);
    let trigger = plan.layout.virtio_spi_trigger;
    let (o, boot_timeout) = run_boot(inp, plan, Interaction::None);
    let diag = o.diag();
    assert_eq!(o.reason, StopReason::GuestShutdown, "stop reason: {diag}");
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
    // 交渉結果（#4289・MVM-5・MVM-1）。block を載せた構成だけ照合し、載せない負の対照では窓が無いことを見る。
    match (block_present, o.block_window) {
        (true, Some(s)) => {
            assert_features_negotiated(&s, BLOCK_OFFERED_LOW, "block", &diag);
            assert_eq!(s.driver_ok_first, Some(0x0F), "block DRIVER_OK: {diag}");
            assert_eq!(s.failed_writes, 0, "block FAILED writes: {diag}");
            assert_eq!(s.queue_ready_one, 1, "block QUEUE_READY=1 count: {diag}");
        }
        (false, None) => {}
        (present, window) => panic!(
            "block window observation mismatch (block present={present}, window={window:?}): {diag}"
        ),
    }
    eprintln!("{}", block_result_line(&o, case, trigger));
}

/// block-read の結果行（数値と固定の語だけ。ゲストの文字列は入れない）。block 無しの ack 系は `none`。`resets` は `DeviceReset`（Status=0）後の resample の回数で `acks` に含めない（#4170・#4230。観測専用）。
fn block_result_line(o: &Outcome, case: &str, trigger: IrqTrigger) -> String {
    let trigger = match trigger {
        IrqTrigger::EdgeRising => "edge_rising",
        IrqTrigger::LevelHigh => "level_high",
        _ => "other",
    };
    let spi = o
        .block_spi_intid
        .map_or_else(|| "none".to_owned(), |v| v.to_string());
    let ack = match o.ack {
        Some(c) => format!(
            "acks={} deasserted={} reasserted={} not_applicable={} resets={}",
            c.acks, c.deasserted, c.reasserted, c.not_applicable, c.resets
        ),
        None => {
            "acks=none deasserted=none reasserted=none not_applicable=none resets=none".to_owned()
        }
    };
    // 交渉結果（#4289）。block 無しは none。`ring_reset=0` は VIRTIO_F_RING_RESET（ビット 40）を受けていないこと。
    let features = match &o.block_window {
        Some(s) => features_result_fields("", s),
        None => "features_ok=none driver_features=none ring_reset=none".to_owned(),
    };
    format!(
        "hvf_kernel_boot: block ok arch=aarch64 case={case} trigger={trigger} spi_intid={spi} elapsed_ms={} exits={} data_abort={} wfx={} {ack} {features}",
        o.elapsed.as_millis(),
        o.exits,
        o.data_abort,
        o.wfx
    )
}

/// 陽性（edge-rising。#4014）。virtio-block 1 台（offset 0 に sentinel）を block-read の initrd で読ませ、`/dev/vda` の先頭が
/// ゲストに届いたときだけ出る一致 marker をちょうど 1 回数える。FDT の virtio の割り込みは既定の edge-rising。
#[test]
#[ignore = "requires Apple silicon macOS 15+ and a binary signed with com.apple.security.hypervisor (MVM-5)"]
fn hvf_kernel_boot_block_read_edge_reads_sentinel() {
    run_block_read(
        BootPlan {
            layout: block_layout(IrqTrigger::EdgeRising),
            block: vec![block_backend(Some(BLOCK_SENTINEL))],
        },
        BLOCK_OK_MARKER,
        BLOCK_MISMATCH_MARKER,
        "block_read_edge",
    );
}

/// 陽性（LevelHigh。#4014・#3863）。FDT の trigger を level-high にし、HVF の線を level 注入にして同じ照合を行う。
/// ACK 後の deassert / 上げ直しが働かず線が張り付くと、起動が止まるか割り込みが届かず一致 marker が出ない。
#[test]
#[ignore = "requires Apple silicon macOS 15+ and a binary signed with com.apple.security.hypervisor (MVM-5)"]
fn hvf_kernel_boot_block_read_level_high_reads_sentinel() {
    run_block_read(
        BootPlan {
            layout: block_layout(IrqTrigger::LevelHigh),
            block: vec![block_backend(Some(BLOCK_SENTINEL))],
        },
        BLOCK_OK_MARKER,
        BLOCK_MISMATCH_MARKER,
        "block_read_level_high",
    );
}

/// 負の対照（#4014）。同じ initrd で block デバイスが無いと `/dev/vda` を開けず不一致 marker が出る。期限を使い切らず
/// `GuestShutdown` で速く決定的に終わる。陽性と同じ実行・同じカーネルで回すこと。
#[test]
#[ignore = "requires Apple silicon macOS 15+ and a binary signed with com.apple.security.hypervisor (MVM-5)"]
fn hvf_kernel_boot_block_read_without_block_device_reports_mismatch() {
    run_block_read(
        BootPlan::plain(1),
        BLOCK_MISMATCH_MARKER,
        BLOCK_OK_MARKER,
        "block_read_absent",
    );
}

/// 行頭が `prefix` の行の件数（`SERIAL_RX_TIMEOUT` の行は接頭辞を共有するので除く）。
fn count_reply_like_lines(output: &[u8]) -> usize {
    output
        .split(|b| *b == b'\n')
        .map(|l| l.strip_suffix(b"\r").unwrap_or(l))
        .filter(|l| {
            l.starts_with(SERIAL_RX_PREFIX.as_bytes()) && *l != SERIAL_RX_TIMEOUT.as_bytes()
        })
        .count()
}

/// `serial-echo` の共通の停止条件（陽性・負の対照の両方）。
fn assert_serial_common(o: &Outcome, diag: &str) {
    assert_eq!(o.reason, StopReason::GuestShutdown, "stop reason: {diag}");
    assert_eq!(o.vcpu_count, 1, "vcpu count: {diag}");
    assert_eq!(o.errors, 0, "run errors: {diag}");
    assert!(!o.timed_out, "boot timed out: {diag}");
    assert_eq!(o.interaction_error, None, "interaction: {diag}");
    assert_eq!(o.uart.dropped_bytes, 0, "uart output dropped: {diag}");
    assert_eq!(o.uart.irq_line_errors, 0, "irq line errors: {diag}");
    assert_eq!(
        count_marker_lines(&o.output, SERIAL_TX_LINE),
        1,
        "tx line (10x the FIFO) must complete exactly once: {diag}"
    );
    assert_eq!(
        count_marker_lines(&o.output, SERIAL_READY),
        1,
        "ready line: {diag}"
    );
    assert_eq!(
        count_marker_lines(&o.output, SERIAL_FAILED),
        0,
        "guest reported a syscall failure: {diag}"
    );
    assert_eq!(
        count_marker_lines(&o.output, MARKER),
        0,
        "plain init marker must not appear: {diag}"
    );
}

/// UART の送信（THRE 割り込み）・受信（`push_input`）・SPI 33 の割り込み数を実 Linux で確かめる（#3987・MVM-5・MVM-1）。
#[test]
#[ignore = "requires Apple silicon macOS 15+ and a binary signed with com.apple.security.hypervisor (MVM-5)"]
fn hvf_kernel_boot_serial_echo_tx_rx_and_irq_count() {
    let secs = boot_timeout_secs();
    let _wd = Watchdog::start(overall_deadline(secs));
    let inp = inputs(InitrdKind::SerialEcho, secs);
    require_vm_with_gic(&layout(1));
    let (o, boot_timeout) = run_boot(
        inp,
        BootPlan::plain(1),
        Interaction::SerialEcho(SerialEcho::new()),
    );
    let diag = o.diag();
    assert_serial_common(&o, &diag);
    assert!(o.elapsed < boot_timeout, "elapsed over budget: {diag}");
    assert_eq!(
        count_marker_lines(&o.output, SERIAL_OK),
        1,
        "ok line: {diag}"
    );
    assert_eq!(
        count_marker_lines(&o.output, SERIAL_RX_TIMEOUT),
        0,
        "guest timed out waiting for input: {diag}"
    );
    let mut pushed = 0u64;
    for round in 0..SERIAL_RX_ROUNDS {
        assert_eq!(
            count_marker_lines(&o.output, &echo_reply(round)),
            1,
            "reply line for round {round} must appear exactly once: {diag}"
        );
        pushed += echo_input(round).len() as u64;
    }
    assert_eq!(
        count_reply_like_lines(&o.output),
        SERIAL_RX_ROUNDS,
        "unexpected extra reply-like lines: {diag}"
    );
    assert_eq!(o.rx_latencies.len(), SERIAL_RX_ROUNDS, "latencies: {diag}");
    assert_eq!(o.uart.input_received_bytes, pushed, "received: {diag}");
    assert_eq!(o.uart.input_read_bytes, pushed, "guest read: {diag}");
    assert_eq!(o.uart.input_dropped_bytes, 0, "input dropped: {diag}");
    assert_eq!(
        o.uart.input_flushed_bytes, 0,
        "input flushed by an FCR reset: {diag}"
    );
    assert_eq!(o.uart.input_buffered_bytes, 0, "input left over: {diag}");
    let rows = parse_irq_rows(&o.output, "ttyS0")
        .unwrap_or_else(|e| panic!("hvf_kernel_boot: /proc/interrupts: {e}: {diag}"));
    let [before, after] = rows.as_slice() else {
        panic!("ttyS0 must appear in exactly two /proc/interrupts dumps: {rows:?}: {diag}");
    };
    // SPI n の hwirq（GIC の INTID）は n + 32。
    assert_eq!(before.hwirq, ARM64_SERIAL_SPI + 32, "hwirq: {diag}");
    assert_eq!(after.hwirq, before.hwirq, "hwirq changed: {diag}");
    assert!(before.level && after.level, "trigger must be Level: {diag}");
    assert!(
        after.count > before.count + SERIAL_RX_ROUNDS as u64,
        "ttyS0 interrupt count grew too little ({} -> {}): {diag}",
        before.count,
        after.count
    );
    let max = o.rx_latencies.iter().max().copied().unwrap_or_default();
    eprintln!(
        "hvf_kernel_boot: serial ok arch=aarch64 rounds={SERIAL_RX_ROUNDS} rx_latency_us={:?} rx_latency_max_us={} \
         wfi_wait_max_ms={} within_wfi_wait_max={} irq_before={} irq_after={} hwirq={} exits={} wfx={}",
        o.rx_latencies
            .iter()
            .map(|d| d.as_micros())
            .collect::<Vec<_>>(),
        max.as_micros(),
        WFI_WAIT_MAX.as_millis(),
        max <= WFI_WAIT_MAX,
        before.count,
        after.count,
        before.hwirq,
        o.exits,
        o.wfx
    );
}

/// 負の対照。入力を押さないと、ゲストは rx timeout に落ち、書き戻しの行・ok の行が出ない（書き戻しが `push_input` に由来する裏づけ）。
/// 陽性と同じ initrd・同じカーネルで回すこと。ゲストの待ちは 5 秒。
#[test]
#[ignore = "requires Apple silicon macOS 15+ and a binary signed with com.apple.security.hypervisor (MVM-5)"]
fn hvf_kernel_boot_serial_echo_without_input_times_out() {
    let secs = boot_timeout_secs();
    let _wd = Watchdog::start(overall_deadline(secs));
    let inp = inputs(InitrdKind::SerialEcho, secs);
    require_vm_with_gic(&layout(1));
    let (o, _) = run_boot(inp, BootPlan::plain(1), Interaction::None);
    let diag = o.diag();
    assert_serial_common(&o, &diag);
    assert_eq!(
        count_marker_lines(&o.output, SERIAL_RX_TIMEOUT),
        1,
        "rx timeout line: {diag}"
    );
    assert_eq!(
        count_marker_lines(&o.output, SERIAL_OK),
        0,
        "ok line without input: {diag}"
    );
    assert_eq!(
        count_reply_like_lines(&o.output),
        0,
        "reply-like lines without input: {diag}"
    );
    assert_eq!(o.uart.input_received_bytes, 0, "received: {diag}");
    assert_eq!(o.uart.input_read_bytes, 0, "guest read: {diag}");
    let rows = parse_irq_rows(&o.output, "ttyS0")
        .unwrap_or_else(|e| panic!("hvf_kernel_boot: /proc/interrupts: {e}: {diag}"));
    assert_eq!(rows.len(), 1, "only the first dump runs: {rows:?}: {diag}");
    // 5 秒の待機中の WFI / vtimer の exit の回数の直接の観測（#3988 で値が採れなかった。assert しない。#4039）。
    eprintln!(
        "hvf_kernel_boot: serial timeout arch=aarch64 exits={} wfx={} vtimer={}",
        o.exits, o.wfx, o.vtimer
    );
}

/// watchdog の期限は、内側（起動スレッド全体）の期限より常に長い（既定と最大の 2 点。REPAIR-5・MVM-5）。
#[test]
fn mvm5_3986_overall_deadline_exceeds_inner_budget() {
    let inner = |secs: u64| Duration::from_secs(secs) + STOP_DEADLINE + SLACK;
    assert_eq!(overall_deadline(60), Duration::from_secs(115));
    assert_eq!(overall_deadline(600), Duration::from_secs(655));
    for secs in [1, 60, 600] {
        assert!(overall_deadline(secs) > inner(secs), "{secs}");
        assert_eq!(overall_deadline(secs) - inner(secs), WATCHDOG_MARGIN);
    }
}

/// 試験の配置は virtio 窓 0・シリアルあり・vCPU 数の指定どおりで、FDT の virtio の割り込みの既定は edge-rising のまま
/// （block-read の 2 構成の試験は #4014 で足した。配置は `block_layout`）。
#[test]
fn mvm5_3986_layout_without_virtio_is_valid() {
    let l = layout(1);
    assert_eq!(l.vcpus, 1);
    assert_eq!(l.virtio_mmio_count, 0);
    assert_eq!(
        l.serial.expect("default serial window").base.raw(),
        ARM64_SERIAL_BASE
    );
    assert_eq!(l.virtio_spi_trigger, IrqTrigger::EdgeRising);
    assert_eq!(layout(2).vcpus, 2);
}

/// block-read の配置は virtio 窓 1 つ・シリアルあり・trigger の指定どおりで、LevelHigh は HVF の注入方式と整合する（#4014）。
#[test]
fn mvm5_4014_block_layout_follows_trigger() {
    let e = block_layout(IrqTrigger::EdgeRising);
    assert_eq!(e.vcpus, 1);
    assert_eq!(e.virtio_mmio_count, 1);
    assert_eq!(e.virtio_spi_trigger, IrqTrigger::EdgeRising);
    let l = block_layout(IrqTrigger::LevelHigh);
    assert_eq!(l.virtio_mmio_count, 1);
    assert_eq!(l.virtio_spi_trigger, IrqTrigger::LevelHigh);
    assert_eq!(
        l.serial.expect("default serial window").base.raw(),
        ARM64_SERIAL_BASE
    );
    assert_eq!(
        l.virtio_mmio_window(0).expect("window 0").base.raw(),
        0x0a00_0000
    );
    assert!(l.check_virtio_injection(IrqTrigger::LevelHigh).is_ok());
    assert!(l.check_virtio_injection(IrqTrigger::EdgeRising).is_err());
    assert!(e.check_virtio_injection(IrqTrigger::EdgeRising).is_ok());
}

/// 結果行は数値と固定の語だけで、ack の計数が無いときは `none` になる（#4014）。
#[test]
fn mvm5_4014_block_result_line_shape() {
    // `InterruptAckCounts` は `non_exhaustive` なので既定値のフィールドを書き換えて作る。
    let mut counts = InterruptAckCounts::default();
    counts.acks = 5;
    counts.deasserted = 4;
    counts.reasserted = 1;
    counts.resets = 2;
    let o = Outcome {
        reason: StopReason::GuestShutdown,
        vcpu_count: 1,
        errors: 0,
        exits: 10,
        per_vcpu: Vec::new(),
        output: Vec::new(),
        uart_dropped: 0,
        uart: UartStats::default(),
        rx_latencies: Vec::new(),
        interaction_error: None,
        timed_out: false,
        elapsed: Duration::from_millis(1234),
        wfx: 3,
        vtimer: 0,
        data_abort: 7,
        hvc: 1,
        ack: Some(counts),
        block_spi_intid: Some(48),
        block_window: Some(WindowStats {
            features_ok_first: Some(0x0B),
            driver_features: Some(0x0000_0001_0000_0206),
            ..WindowStats::default()
        }),
    };
    assert_eq!(
        block_result_line(&o, "block_read_level_high", IrqTrigger::LevelHigh),
        "hvf_kernel_boot: block ok arch=aarch64 case=block_read_level_high trigger=level_high spi_intid=48 \
         elapsed_ms=1234 exits=10 data_abort=7 wfx=3 acks=5 deasserted=4 reasserted=1 not_applicable=0 resets=2 \
         features_ok=0x0b driver_features=0x0000000100000206 ring_reset=0"
    );
    let none = Outcome {
        ack: None,
        block_spi_intid: None,
        block_window: None,
        ..o
    };
    assert!(
        block_result_line(&none, "block_read_absent", IrqTrigger::EdgeRising).ends_with(
            "spi_intid=none elapsed_ms=1234 exits=10 data_abort=7 wfx=3 acks=none deasserted=none reasserted=none not_applicable=none resets=none features_ok=none driver_features=none ring_reset=none"
        )
    );
}

/// #4289・MVM-5・MVM-1: HVF の観測器は MMIO の値を窓へ集計し、exit の種別を数え、値を求める（opt-in）。
/// 実 VM は使わず、合成の `ExitValue::Mmio` を `on_value` へ直接与える。
#[test]
fn mvm5_4289_hvf_observer_routes_values_to_windows() {
    use fandhe_container_microvm::exit::ExitData;
    use fandhe_container_microvm::virtio_mmio::reg;
    let obs = HvfBootObserver::default();
    assert!(obs.wants_values());
    let base = 0x0a00_0000u64;
    obs.windows.bind(WindowKind::Block, base, 0x200);
    let write = |off: u64, v: u32| {
        obs.on_value(&ExitValue::Mmio {
            phys_addr: base + off,
            len: 4,
            is_write: true,
            data: ExitData::from_slice(&v.to_le_bytes()),
        })
    };
    // 窓の外への書き込みは数えない。
    obs.on_value(&ExitValue::Mmio {
        phys_addr: base + 0x1000 + reg::STATUS,
        len: 4,
        is_write: true,
        data: ExitData::from_slice(&0x0Bu32.to_le_bytes()),
    });
    write(reg::DRIVER_FEATURES_SEL, 0);
    write(reg::DRIVER_FEATURES, 0x0000_0206);
    write(reg::DRIVER_FEATURES_SEL, 1);
    write(reg::DRIVER_FEATURES, 0x1);
    write(reg::STATUS, 0x0B);
    write(reg::STATUS, 0x0F);
    let s = obs.windows.stats(WindowKind::Block);
    assert_eq!(s.driver_features, Some(0x0000_0001_0000_0206));
    assert_eq!(s.features_ok_first, Some(0x0B));
    assert_eq!(s.features_ok_writes, 1);
    assert_eq!(s.driver_ok_first, Some(0x0F));
    assert_eq!(s.status_writes, 2);
    assert_features_negotiated(&s, BLOCK_OFFERED_LOW, "block", "unit");
    obs.on_exit(ExitKind::DataAbort);
    obs.on_exit(ExitKind::DataAbort);
    assert_eq!(obs.counts.count(ExitKind::DataAbort), 2);
    assert_eq!(obs.counts.count(ExitKind::Hvc), 0);
}

/// initrd の種類ごとの環境変数名・既定パス・ヒント（#3987）。`None` には initrd が無い。
#[test]
fn mvm5_3987_initrd_spec_names() {
    assert_eq!(initrd_spec(InitrdKind::None), None);
    assert_eq!(
        initrd_spec(InitrdKind::Default),
        Some((
            "FANDHE_CONTAINER_MICROVM_INITRD",
            "../../target/microvm-test-initrd/aarch64/initrd.cpio",
            "MICROVM_TEST_INITRD_ARCH=aarch64 make microvm-test-initrd-build"
        ))
    );
    assert_eq!(
        initrd_spec(InitrdKind::SerialEcho),
        Some((
            "FANDHE_CONTAINER_MICROVM_SERIAL_INITRD",
            "../../target/microvm-test-initrd/aarch64-serial-echo/initrd.cpio",
            "MICROVM_TEST_INITRD_ARCH=aarch64 MICROVM_TEST_INITRD_VARIANT=serial-echo make microvm-test-initrd-build"
        ))
    );
    assert_eq!(
        initrd_spec(InitrdKind::BlockRead),
        Some((
            "FANDHE_CONTAINER_MICROVM_BLOCK_INITRD",
            "../../target/microvm-test-initrd/aarch64-block-read/initrd.cpio",
            "MICROVM_TEST_INITRD_ARCH=aarch64 MICROVM_TEST_INITRD_VARIANT=block-read make microvm-test-initrd-build"
        ))
    );
}

/// 押す行と書き戻しの行の組み立て（改行つきの入力・改行なしの照合行。往復ごとに別の文字列）。
#[test]
fn mvm5_3987_echo_lines_are_distinct_per_round() {
    assert_eq!(echo_input(0), "echo-0\n");
    assert_eq!(echo_reply(3), "fandhe-microvm-test: serial rx echo-3");
    let replies: Vec<String> = (0..SERIAL_RX_ROUNDS).map(echo_reply).collect();
    for (i, a) in replies.iter().enumerate() {
        assert_eq!(a.len() + 1, SERIAL_RX_PREFIX.len() + echo_input(i).len());
        for b in replies.iter().skip(i + 1) {
            assert_ne!(a, b);
        }
    }
    // 接頭辞を共有する rx timeout の行は「書き戻しに似た行」に数えない。
    let out = format!(
        "{SERIAL_RX_TIMEOUT}\n{}\r\nx{}\n",
        echo_reply(0),
        echo_reply(1)
    );
    assert_eq!(count_reply_like_lines(out.as_bytes()), 1);
    assert_eq!(count_marker_lines(out.as_bytes(), &echo_reply(0)), 1);
    assert_eq!(count_marker_lines(out.as_bytes(), &echo_reply(1)), 0);
    // 状態機械は ready の前は進まず、時間の定数は上限の関係を保つ。
    assert!(matches!(SerialEcho::new().stage, EchoStage::WaitReady));
    assert!(ECHO_IDLE < ECHO_READ_WAIT && ECHO_READ_WAIT < ECHO_REPLY_WAIT);
    assert_eq!(SERIAL_RX_ROUNDS, 4);
}

/// vCPU ごとの統計の整形は空白なしの 1 トークンで、空の入力は空文字列（MVM-5・#3998）。
#[test]
fn mvm5_3998_per_vcpu_summary_lists_each_vcpu() {
    let a = HvRunStats {
        runs: 12,
        exits: 9,
        deadline_exceeded: 3,
        errors: 0,
        total_elapsed: Duration::from_millis(810),
    };
    let b = HvRunStats {
        runs: 7,
        exits: 4,
        deadline_exceeded: 3,
        errors: 0,
        total_elapsed: Duration::from_millis(790),
    };
    assert_eq!(
        per_vcpu_summary(&[a, b]),
        "vcpu0(runs=12,exits=9,deadline_exceeded=3,errors=0,run_ms=810);\
         vcpu1(runs=7,exits=4,deadline_exceeded=3,errors=0,run_ms=790)"
    );
    assert_eq!(per_vcpu_summary(&[]), "");
}

/// 既定の cmdline は SMP を無効化せず、`force_panic_zero` 後も同じ（2 台の試験が前提欠如にならない。MVM-5・#3998）。
#[test]
fn mvm5_3998_default_cmdline_keeps_smp() {
    assert_eq!(smp_disabling_param(DEFAULT_CMDLINE), None);
    assert_eq!(
        smp_disabling_param(&force_panic_zero(DEFAULT_CMDLINE)),
        None
    );
}
