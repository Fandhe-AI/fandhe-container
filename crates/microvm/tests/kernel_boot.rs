//! 実 Linux カーネルの起動完走の結合試験（MVM-1・REPAIR-5・REPAIR-12・TASK-75.5・#3771）。`--ignored` 指定時だけ走る。
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
//! marker ちょうど 1 回・UART の取りこぼし 0 を照合する。vCPU 2 台の陽性 1 件を #3899 で足し、3 件。2 台は `SMP: Total of 2 processors activated.`・`smp: Brought up 1 node, 2 CPUs`・`CPU1: Booted secondary processor 0x0000000001` を照合する）。シリアルはポーリング（FDT に `interrupts` 無し。
//! Linux の 8250 は irq = 0 で timer ポーリング）で、送信は timer の周期ごとに進む。`/init` は write の直後に reboot するため、
//! marker が出切る前に `GuestShutdown` になり marker 0 回で落ちた場合は、試験の欠陥ではなく割り込み未結線の帰結で、#3943 で直す。
//! 実機での実行と記録は #3781（人間担当）。Agent は実カーネルでの起動を確かめていない。
#![cfg(target_os = "linux")]

/// `/init` が出す固定文字列。正本は `scripts/build-microvm-test-initrd.sh` の `init_message`（単体テストで照合）。
/// x86_64 と aarch64 の試験が共有する（#3898。複製しない・REPAIR-1）。
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
const MARKER: &str = "fandhe-microvm-test: init ok v1";

/// 行単位の完全一致の件数（tty の ONLCR による `\r\n` を許容。部分一致・混入は数えない）。
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn count_marker_lines(output: &[u8], marker: &str) -> usize {
    output
        .split(|b| *b == b'\n')
        .filter(|line| line.strip_suffix(b"\r").unwrap_or(line) == marker.as_bytes())
        .count()
}

/// 行末が `suffix` で終わる行の件数（`\r` は除く。接頭辞の時刻表示を許し、行頭の混入は区別しない）。
/// x86_64 の SMP 照合（#3888）と aarch64 の SMP 照合（#3899）が共有する（複製しない・REPAIR-1）。
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn count_lines_ending_with(output: &[u8], suffix: &str) -> usize {
    output
        .split(|b| *b == b'\n')
        .filter(|line| {
            line.strip_suffix(b"\r")
                .unwrap_or(line)
                .ends_with(suffix.as_bytes())
        })
        .count()
}

/// 非信頼のゲスト出力を、末尾 `n` バイトだけエスケープして診断に載せる（端末制御の注入を防ぐ）。
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn escape_tail(output: &[u8], n: usize) -> String {
    let start = output.len().saturating_sub(n);
    output
        .get(start..)
        .unwrap_or(&[])
        .escape_ascii()
        .to_string()
}

#[cfg(target_arch = "x86_64")]
mod x86 {
    use super::{MARKER, count_lines_ending_with, count_marker_lines, escape_tail};
    use fandhe_container_microvm::device::{KvmDevice, RunObserver, RunOutcome, RunRecord};
    use fandhe_container_microvm::error::{MicrovmError, MicrovmErrorCode};
    use fandhe_container_microvm::exit::{ExitData, ExitValue};
    use fandhe_container_microvm::microvm::{
        MicroVm, MicroVmConfig, NetDeviceConfig, StopReason, VirtioDeviceKind,
    };
    use fandhe_container_microvm::virtio_block::{BlockBackend, MemoryBlockBackend};
    use fandhe_container_microvm::virtio_mmio::reg;
    use fandhe_container_microvm::virtio_net::{MAX_MEMORY_FRAMES, MemoryNetBackend, NetBackend};
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    use std::path::Path;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex, mpsc};
    use std::time::{Duration, Instant};

    /// block-read の initrd が `/dev/vda` の先頭と比べる 32 バイト。正本は `scripts/build-microvm-test-initrd.sh` の
    /// `block_sentinel`（単体テストで照合）。
    const BLOCK_SENTINEL: &[u8; 32] = b"fandhe-microvm-block-sentinel-01";
    /// net-tx の initrd が成功時・失敗時に出す固定文字列。正本は `scripts/build-microvm-test-initrd.sh` の
    /// `net_tx_ok_message`・`net_tx_failed_message`（単体テストで照合）。
    const NET_TX_OK_MARKER: &str = "fandhe-microvm-test: net tx ok v1";
    const NET_TX_FAILED_MARKER: &str = "fandhe-microvm-test: net tx failed v1";
    /// net-tx の initrd が送る固定の Ethernet フレーム（60 バイト）。宛先 02:fc:00:00:38:66・送信元は `NET_MAC`・
    /// EtherType 0x88B5（IEEE 802 Local Experimental）・ペイロード 46 バイト。正本はスクリプトの `net_tx_frame_header_hex`
    /// と `net_tx_payload`（単体テストで照合）。
    const NET_TX_FRAME: [u8; 60] = [
        0x02, 0xfc, 0x00, 0x00, 0x38, 0x66, 0x02, 0xfc, 0x00, 0x00, 0x38, 0x65, 0x88, 0xb5, b'f',
        b'a', b'n', b'd', b'h', b'e', b'-', b'm', b'i', b'c', b'r', b'o', b'v', b'm', b'-', b'n',
        b'e', b't', b'-', b't', b'x', b'-', b'p', b'a', b'y', b'l', b'o', b'a', b'd', b'-', b'0',
        b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'a', b'b', b'c', b'd', b'e', b'f',
    ];
    /// net-rx の initrd が成功時・失敗時に出す固定文字列。正本は `scripts/build-microvm-test-initrd.sh` の
    /// `net_rx_ok_message`・`net_rx_failed_message`（単体テストで照合）。
    const NET_RX_OK_MARKER: &str = "fandhe-microvm-test: net rx ok v1";
    const NET_RX_FAILED_MARKER: &str = "fandhe-microvm-test: net rx failed v1";
    /// net-rx の initrd が待ち受ける固定の Ethernet フレーム（60 バイト）。宛先は `NET_MAC`（eth0 の MAC）・
    /// 送信元 02:fc:00:00:38:66・EtherType 0x88B6・ペイロード 46 バイト。正本はスクリプトの `net_rx_frame_header_hex`
    /// と `net_rx_payload`（単体テストで照合）。
    const NET_RX_FRAME: [u8; 60] = [
        0x02, 0xfc, 0x00, 0x00, 0x38, 0x65, 0x02, 0xfc, 0x00, 0x00, 0x38, 0x66, 0x88, 0xb6, b'f',
        b'a', b'n', b'd', b'h', b'e', b'-', b'm', b'i', b'c', b'r', b'o', b'v', b'm', b'-', b'n',
        b'e', b't', b'-', b'r', b'x', b'-', b'p', b'a', b'y', b'l', b'o', b'a', b'd', b'-', b'0',
        b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'a', b'b', b'c', b'd', b'e', b'f',
    ];
    /// sentinel 一致時に block-read の `/init` が出す固定文字列（正本は同スクリプトの `block_ok_message`）。
    const BLOCK_OK_MARKER: &str = "fandhe-microvm-test: block sentinel ok v1";
    /// 不一致・読み出し失敗時に出す固定文字列（正本は同スクリプトの `block_mismatch_message`）。
    const BLOCK_MISMATCH_MARKER: &str = "fandhe-microvm-test: block sentinel mismatch v1";
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

    /// 上限つきでファイルを読む。空・上限超過・通常ファイルでないものは拒否する。
    fn read_bounded(path: &Path, cap: u64) -> Result<Vec<u8>, String> {
        // REPAIR-5: 書き手のいない FIFO で open が無期限に止まらないよう O_NONBLOCK（Linux: 0o4000）で開く。
        // 通常ファイルには影響せず、FIFO・デバイス等は下の通常ファイル検査で拒否する。
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(0o4000)
            .open(path)
            .map_err(|e| format!("cannot open file: {e}"))?;
        let meta = file
            .metadata()
            .map_err(|e| format!("cannot stat file: {e}"))?;
        if !meta.is_file() {
            return Err("not a regular file".into());
        }
        if meta.len() == 0 || meta.len() > cap {
            return Err(format!("file size {} not in 1..={cap}", meta.len()));
        }
        let mut buf = Vec::new();
        file.take(cap + 1)
            .read_to_end(&mut buf)
            .map_err(|e| format!("cannot read file: {e}"))?;
        if buf.is_empty() || buf.len() as u64 > cap {
            return Err("file size changed while reading".into());
        }
        Ok(buf)
    }

    fn parse_boot_timeout(raw: Option<&str>) -> Result<u64, String> {
        match raw {
            None => Ok(DEFAULT_TIMEOUT_SECS),
            Some(s) => match s.parse::<u64>() {
                Ok(n) if (1..=600).contains(&n) => Ok(n),
                _ => Err(
                    "FANDHE_CONTAINER_MICROVM_BOOT_TIMEOUT_SECS must be an integer in 1..=600"
                        .into(),
                ),
            },
        }
    }

    fn validate_cmdline(raw: Option<&str>) -> Result<String, String> {
        let s = raw.unwrap_or(DEFAULT_CMDLINE);
        if s.is_empty() || s.bytes().any(|b| !(0x20..=0x7E).contains(&b)) {
            return Err(
                "FANDHE_CONTAINER_MICROVM_CMDLINE must be non-empty printable ASCII".into(),
            );
        }
        Ok(s.to_owned())
    }

    /// 2 CPU がオンラインになった行（Linux v6.12 `kernel/smp.c` の `smp_init()` の `pr_info`。`CONFIG_NUMA=n` で node は 1）。
    /// `CONFIG_PRINTK_TIME` の接頭辞（`[    0.1] `）を許すため、行末一致で数える。
    const SMP_ONLINE_LINE: &str = "smp: Brought up 1 node, 2 CPUs";

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

    const NO_VALUE: u64 = u64::MAX;
    /// virtio 仕様 2.1 の Device Status ビット（DRIVER_OK = 4・FAILED = 128）。
    const STATUS_DRIVER_OK: u32 = 4;
    const STATUS_FAILED: u32 = 128;
    /// virtio-net に見せる固定の locally administered なダミー MAC。
    const NET_MAC: [u8; 6] = [0x02, 0xfc, 0x00, 0x00, 0x38, 0x65];

    fn window_index(kind: VirtioDeviceKind) -> usize {
        match kind {
            VirtioDeviceKind::Block => 0,
            _ => 1,
        }
    }

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

    #[derive(Debug)]
    struct CountingNetBackend {
        inner: MemoryNetBackend,
        counters: Arc<NetCounters>,
    }

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
        let dev = KvmDevice::open().unwrap_or_else(|e| precondition(&e.to_string()));
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

    /// 先頭 `n` バイトの 16 進表記（診断用）。
    fn hex_prefix(b: &[u8], n: usize) -> String {
        b.iter().take(n).map(|x| format!("{x:02x}")).collect()
    }

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
    fn mvm1_3771_count_marker_lines() {
        let m = MARKER;
        assert_eq!(count_marker_lines(b"", m), 0);
        assert_eq!(count_marker_lines(format!("{m}\n").as_bytes(), m), 1);
        assert_eq!(count_marker_lines(format!("{m}\r\n").as_bytes(), m), 1);
        assert_eq!(count_marker_lines(m.as_bytes(), m), 1);
        assert_eq!(count_marker_lines(format!("x{m}\n").as_bytes(), m), 0);
        assert_eq!(count_marker_lines(format!("{m}y\n").as_bytes(), m), 0);
        assert_eq!(
            count_marker_lines(format!("{m}\nboot\n{m}\n").as_bytes(), m),
            2
        );
    }

    #[test]
    fn mvm1_3888_count_lines_ending_with() {
        let l = SMP_ONLINE_LINE;
        assert_eq!(count_lines_ending_with(b"", l), 0);
        assert_eq!(count_lines_ending_with(format!("{l}\r\n").as_bytes(), l), 1);
        assert_eq!(
            count_lines_ending_with(format!("[    0.123456] {l}\n").as_bytes(), l),
            1
        );
        assert_eq!(count_lines_ending_with(format!("{l}y\n").as_bytes(), l), 0);
        assert_eq!(
            count_lines_ending_with(
                b"smp: Brought up 1 node, 1 CPU\nsmp: Brought up 1 node, 12 CPUs\n",
                l
            ),
            0
        );
        assert_eq!(
            count_lines_ending_with(format!("{l}\nx\n[ 1.0] {l}\n").as_bytes(), l),
            2
        );
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

    #[test]
    fn mvm1_3771_read_bounded() {
        let dir = std::env::temp_dir().join(format!("fandhe-kernel-boot-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let ok = dir.join("ok");
        let empty = dir.join("empty");
        std::fs::write(&ok, [7u8; 8]).unwrap();
        std::fs::write(&empty, []).unwrap();
        assert_eq!(read_bounded(&ok, 8).unwrap(), vec![7u8; 8]);
        assert!(read_bounded(&ok, 7).is_err());
        assert!(read_bounded(&empty, 8).is_err());
        assert!(read_bounded(&dir, 8).is_err());
        assert!(read_bounded(&dir.join("missing"), 8).is_err());
        // 書き手のいない FIFO は期限内に明示的に拒否される（REPAIR-5）。
        let fifo = dir.join("fifo");
        let status = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap();
        assert!(status.success());
        let (tx, rx) = mpsc::channel();
        let f = fifo.clone();
        std::thread::spawn(move || {
            let _ = tx.send(read_bounded(&f, 8));
        });
        let r = rx
            .recv_timeout(Duration::from_secs(10))
            .expect("read_bounded blocked on FIFO");
        assert_eq!(r.unwrap_err(), "not a regular file");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn mvm1_3771_escape_tail() {
        assert_eq!(escape_tail(b"abc\x1b[0m\n", 100), "abc\\x1b[0m\\n");
        assert_eq!(escape_tail(b"abcdef", 3), "def");
        assert_eq!(escape_tail(b"", 3), "");
    }
}

/// aarch64 の実カーネル起動試験（#3897・MVM-1・REPAIR-5・REPAIR-12）。
///
/// arm64 の非圧縮 `Image` と `MICROVM_TEST_INITRD_ARCH=aarch64 make microvm-test-initrd-build` の initrd（`/init` は
/// write の後に `reboot(RESTART)`）で `assemble` → `load_kernel` → `start` を通し、PSCI SYSTEM_RESET が
/// `KVM_EXIT_SYSTEM_EVENT` として `StopReason::GuestShutdown` に分類されること（#3896）を照合する。
/// ホスト要件: Linux aarch64・`/dev/kvm` の読み書き（root 不要）・in-kernel vGICv3（GICv2 のみのホストは `assemble` で失敗）・
/// `KVM_CAP_ARM_PSCI_0_2`。シリアルは MMIO の ns16550a をポーリングで結線済み（#3898。割り込みは #3943）で、停止理由・起点 vCPU・
/// エラー件数・期限に加え、marker の回数と UART の取りこぼし 0 を照合する。範囲外: SMP（#3899）・virtio。
/// x86 の同名ヘルパーと同じ契約の入力検査を複製している（x86 側の件数・挙動を変えないため）。
/// 実機での実行と記録は #3781（人間担当）。Agent は実カーネルでの起動を確かめていない。
#[cfg(target_arch = "aarch64")]
mod arm64 {
    use super::{MARKER, count_lines_ending_with, count_marker_lines, escape_tail};
    use fandhe_container_microvm::boot_arm64::Arm64ImageHeader;
    use fandhe_container_microvm::device::KvmDevice;
    use fandhe_container_microvm::microvm::{MicroVm, MicroVmConfig, StopReason};
    use fandhe_container_microvm::virtio_block::MemoryBlockBackend;
    use fandhe_container_microvm::virtio_net::MemoryNetBackend;
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    use std::path::Path;
    use std::sync::mpsc;
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

    /// 上限つきでファイルを読む（x86 の `read_bounded` と同じ契約。O_NONBLOCK で FIFO の無期限待ちを防ぐ）。
    fn read_bounded(path: &Path, cap: u64) -> Result<Vec<u8>, String> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(0o4000)
            .open(path)
            .map_err(|e| format!("cannot open file: {e}"))?;
        let meta = file
            .metadata()
            .map_err(|e| format!("cannot stat file: {e}"))?;
        if !meta.is_file() {
            return Err("not a regular file".into());
        }
        if meta.len() == 0 || meta.len() > cap {
            return Err(format!("file size {} not in 1..={cap}", meta.len()));
        }
        let mut buf = Vec::new();
        file.take(cap + 1)
            .read_to_end(&mut buf)
            .map_err(|e| format!("cannot read file: {e}"))?;
        if buf.is_empty() || buf.len() as u64 > cap {
            return Err("file size changed while reading".into());
        }
        Ok(buf)
    }

    fn parse_boot_timeout(raw: Option<&str>) -> Result<u64, String> {
        match raw {
            None => Ok(DEFAULT_TIMEOUT_SECS),
            Some(s) => match s.parse::<u64>() {
                Ok(n) if (1..=600).contains(&n) => Ok(n),
                _ => Err(
                    "FANDHE_CONTAINER_MICROVM_BOOT_TIMEOUT_SECS must be an integer in 1..=600"
                        .into(),
                ),
            },
        }
    }

    fn validate_cmdline(raw: Option<&str>) -> Result<String, String> {
        let s = raw.unwrap_or(DEFAULT_CMDLINE);
        if s.is_empty() || s.bytes().any(|b| !(0x20..=0x7E).contains(&b)) {
            return Err(
                "FANDHE_CONTAINER_MICROVM_CMDLINE must be non-empty printable ASCII".into(),
            );
        }
        Ok(s.to_owned())
    }

    /// 陽性・負の対照の両方に使う cmdline。Linux の `panic=` は後勝ちなので末尾に `panic=0` を足し、利用者の `panic=N` による
    /// init 起動失敗後の自動 reboot（SYSTEM_RESET → `GuestShutdown`）を陽性が受理する偽陽性を抑える。
    fn force_panic_zero(base: &str) -> String {
        format!("{base} panic=0")
    }

    struct Inputs {
        dev: KvmDevice,
        kernel: Vec<u8>,
        initrd: Option<Vec<u8>>,
        cmdline: String,
        secs: u64,
    }

    /// 前提の検査はすべてテストスレッドで行う（x86 と同じ方針）。
    fn inputs(with_initrd: bool) -> Inputs {
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
        let initrd = if with_initrd {
            let path = match std::env::var("FANDHE_CONTAINER_MICROVM_INITRD") {
                Ok(p) if !p.is_empty() => std::path::PathBuf::from(p),
                _ => Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("../../target/microvm-test-initrd/aarch64/initrd.cpio"),
            };
            Some(read_bounded(&path, INITRD_CAP).unwrap_or_else(|e| {
                precondition(&format!(
                    "initrd (run `MICROVM_TEST_INITRD_ARCH=aarch64 make microvm-test-initrd-build`): {e}"
                ))
            }))
        } else {
            None
        };
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
        let dev = KvmDevice::open().unwrap_or_else(|e| precondition(&e.to_string()));
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
    ) -> Result<Outcome, String> {
        let started = Instant::now();
        let config: MicroVmConfig<MemoryBlockBackend, MemoryNetBackend> = MicroVmConfig {
            vcpu_count: vcpus,
            mem_size: RAM_SIZE,
            block: vec![],
            net: vec![],
        };
        let mut vm =
            MicroVm::assemble(&inp.dev, config).map_err(|e| format!("assemble failed: {e}"))?;
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
        })
    }

    /// 別スレッドで `boot` を回し、全体期限で必ず戻る（watchdog は `--ignored` を素通しするため唯一の層）。
    fn run_boot(inp: Inputs, cmdline: String, vcpus: u32) -> (Outcome, Duration) {
        let secs = inp.secs;
        let boot_timeout = Duration::from_secs(secs);
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(boot(inp, cmdline, boot_timeout, vcpus));
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
        let inp = inputs(true);
        let cmdline = force_panic_zero(&inp.cmdline);
        let (o, boot_timeout) = run_boot(inp, cmdline, 1);
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
        eprintln!(
            "kernel_boot: ok arch=aarch64 reason=guest_shutdown elapsed_ms={} exits={}",
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
        let inp = inputs(false);
        let cmdline = force_panic_zero(&inp.cmdline);
        let (o, _) = run_boot(inp, cmdline, 1);
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

    /// 2 CPU がオンラインになった行（Linux v6.12 `arch/arm64/kernel/smp.c` の `smp_cpus_done()`。arm64 固有）。行末一致。
    const ARM64_SMP_TOTAL_LINE: &str = "SMP: Total of 2 processors activated.";
    /// 汎用の `kernel/smp.c` `smp_init()` の行（x86 と同じ書式。`CONFIG_NUMA=n` で node は 1）。行末一致。
    const SMP_ONLINE_LINE: &str = "smp: Brought up 1 node, 2 CPUs";
    /// AP（vCPU 1）が起きた行の目印。`secondary_start_kernel` の `"CPU%u: Booted secondary processor 0x%010lx [0x%08x]"` のうち
    /// MPIDR（`MPIDR_HWID_BITMASK` 後の affinity）が FDT の `cpu@1` の reg（1）と一致した値を含む前半。後半（MIDR）はホスト依存のため見ない。
    const AP_BOOTED_PREFIX: &str = "CPU1: Booted secondary processor 0x0000000001";

    /// `needle` を含む行の件数（`\r` は除く。後ろにホスト依存の値が続く行用）。
    fn count_lines_containing(output: &[u8], needle: &str) -> usize {
        output
            .split(|b| *b == b'\n')
            .filter(|line| {
                line.windows(needle.len().max(1))
                    .any(|w| w == needle.as_bytes())
            })
            .count()
    }

    /// 利用者の cmdline が SMP を無効化する指定（`nosmp`・`maxcpus=`）を含めば、その理由を返す（2 CPU の照合が成り立たないため）。
    fn smp_disabling_param(cmdline: &str) -> Option<&str> {
        cmdline
            .split_ascii_whitespace()
            .find(|w| *w == "nosmp" || w.starts_with("maxcpus="))
    }

    /// 2 台構成の陽性（#3899・MVM-1・REPAIR-5・REPAIR-12）。AP が PSCI CPU_ON でオンラインになり、2 台とも回収される。
    #[test]
    #[ignore = "requires read/write access to /dev/kvm and a kernel with CONFIG_SMP (MVM-1)"]
    fn kernel_boot_two_vcpus_reaches_init_and_shuts_down() {
        let inp = inputs(true);
        if let Some(p) = smp_disabling_param(&inp.cmdline) {
            precondition(&format!(
                "cmdline disables SMP (`{p}`); remove it for the two-vCPU case"
            ));
        }
        let cmdline = force_panic_zero(&inp.cmdline);
        let (o, boot_timeout) = run_boot(inp, cmdline, 2);
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

    /// MVM-1・#3899: 2 台構成の前提検査。SMP を無効化する cmdline を見分け、既定は通す。
    #[test]
    fn mvm1_3899_arm64_smp_cmdline_guard() {
        assert_eq!(smp_disabling_param(DEFAULT_CMDLINE), None);
        assert_eq!(smp_disabling_param("console=ttyS0 nosmp"), Some("nosmp"));
        assert_eq!(smp_disabling_param("maxcpus=1 x"), Some("maxcpus=1"));
        assert_eq!(smp_disabling_param("nosmpx maxcpu=1"), None);
        let l = format!(
            "[    0.5] {ARM64_SMP_TOTAL_LINE}\r\nCPU1: Booted secondary processor 0x0000000001 [0x413fd0c1]\n"
        );
        assert_eq!(
            count_lines_ending_with(l.as_bytes(), ARM64_SMP_TOTAL_LINE),
            1
        );
        assert_eq!(count_lines_containing(l.as_bytes(), AP_BOOTED_PREFIX), 1);
        assert_eq!(
            count_lines_containing(
                b"CPU1: Booted secondary processor 0x0000000101\n",
                AP_BOOTED_PREFIX
            ),
            0
        );
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

    #[test]
    fn mvm1_3897_force_panic_zero_appends_last() {
        assert_eq!(force_panic_zero("rdinit=/init"), "rdinit=/init panic=0");
        assert_eq!(
            force_panic_zero("console=x panic=5"),
            "console=x panic=5 panic=0"
        );
        // 利用者が `rdinit=/missing panic=1` を渡しても末尾が panic=0 になる（陽性の自動再起動の偽陽性を防ぐ）。
        assert!(force_panic_zero("rdinit=/missing panic=1").ends_with(" panic=0"));
    }
}
/// x86_64・aarch64 以外では `assemble` が `Unimplemented` であることの確認（aarch64 は `mod arm64`・#3897）。
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
mod other {
    use fandhe_container_microvm::device::KvmDevice;
    use fandhe_container_microvm::error::MicrovmErrorCode;
    use fandhe_container_microvm::microvm::{MicroVm, MicroVmConfig, NetDeviceConfig};
    use fandhe_container_microvm::virtio_block::MemoryBlockBackend;
    use fandhe_container_microvm::virtio_net::MemoryNetBackend;

    fn open_kvm() -> KvmDevice {
        match KvmDevice::open() {
            Ok(d) => d,
            Err(e) => {
                panic!("kernel_boot: PRECONDITION FAILED (test environment, not a regression): {e}")
            }
        }
    }

    fn assert_unimplemented(config: MicroVmConfig<MemoryBlockBackend, MemoryNetBackend>) {
        let dev = open_kvm();
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
