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
//! 既知のリスク（起動が止まったときの切り分け）: `crates/microvm/src` には PIT・RTC・i8042 のモデルが無く、未登録 PIO の
//! IN は 0xFF 埋めになる。IRQ 4 も未実装（8250 はポーリングに落ちる想定）。止まる場合は `_CMDLINE` で
//! `tsc=reliable no_timer_check` 等を試し、原因ごとに別 issue にする。範囲外: virtio デバイス付きの起動・AP・aarch64。
//! 実機での実行と記録は #3781（人間担当）。Agent は実カーネルでの起動を確かめていない。
#![cfg(target_os = "linux")]

#[cfg(target_arch = "x86_64")]
mod x86 {
    use fandhe_container_microvm::device::KvmDevice;
    use fandhe_container_microvm::microvm::{MicroVm, MicroVmConfig, StopReason};
    use fandhe_container_microvm::virtio_block::MemoryBlockBackend;
    use fandhe_container_microvm::virtio_net::MemoryNetBackend;
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    use std::path::Path;
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    /// `/init` が出す固定文字列。正本は `scripts/build-microvm-test-initrd.sh` の `init_message`（単体テストで照合）。
    const MARKER: &str = "fandhe-microvm-test: init ok v1";
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

    /// 行単位の完全一致の件数（tty の ONLCR による `\r\n` を許容。部分一致・混入は数えない）。
    fn count_marker_lines(output: &[u8], marker: &str) -> usize {
        output
            .split(|b| *b == b'\n')
            .filter(|line| line.strip_suffix(b"\r").unwrap_or(line) == marker.as_bytes())
            .count()
    }

    /// 非信頼のゲスト出力を、末尾 `n` バイトだけエスケープして診断に載せる（端末制御の注入を防ぐ）。
    fn escape_tail(output: &[u8], n: usize) -> String {
        let start = output.len().saturating_sub(n);
        output
            .get(start..)
            .unwrap_or(&[])
            .escape_ascii()
            .to_string()
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

    fn boot(
        dev: KvmDevice,
        kernel: Vec<u8>,
        initrd: Vec<u8>,
        cmdline: String,
        boot_timeout: Duration,
    ) -> Result<Outcome, String> {
        let started = Instant::now();
        let mut vm: MicroVm<MemoryBlockBackend, MemoryNetBackend> = MicroVm::assemble(
            &dev,
            MicroVmConfig {
                vcpu_count: 1,
                mem_size: 256 << 20,
                block: vec![],
                net: vec![],
            },
        )
        .map_err(|e| format!("assemble failed: {e}"))?;
        let loaded = vm
            .load_kernel(&kernel, Some(&initrd), &cmdline)
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

    #[test]
    #[ignore = "requires read/write access to /dev/kvm (MVM-1)"]
    fn kernel_boot_real_kernel_reaches_init_and_shuts_down() {
        // 前提の検査はすべてテストスレッドで行う（worker 内 panic では 1 行目が PRECONDITION FAILED にならない）。
        let kernel_path = match std::env::var("FANDHE_CONTAINER_MICROVM_KERNEL") {
            Ok(p) if !p.is_empty() => p,
            _ => precondition(
                "FANDHE_CONTAINER_MICROVM_KERNEL is not set (path to an x86_64 bzImage)",
            ),
        };
        let kernel = read_bounded(Path::new(&kernel_path), KERNEL_CAP)
            .unwrap_or_else(|e| precondition(&format!("kernel image: {e}")));
        let initrd_path = match std::env::var("FANDHE_CONTAINER_MICROVM_INITRD") {
            Ok(p) if !p.is_empty() => std::path::PathBuf::from(p),
            _ => Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../target/microvm-test-initrd/x86_64/initrd.cpio"),
        };
        let initrd = read_bounded(&initrd_path, INITRD_CAP).unwrap_or_else(|e| {
            precondition(&format!(
                "initrd (run `make microvm-test-initrd-build`): {e}"
            ))
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
        let dev = KvmDevice::open().unwrap_or_else(|e| precondition(&e.to_string()));

        let boot_timeout = Duration::from_secs(secs);
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(boot(dev, kernel, initrd, cmdline, boot_timeout));
        });
        // REPAIR-5: 止まった vCPU スレッドが残っても、全体期限で必ず試験を終える。
        let o = match rx.recv_timeout(boot_timeout + STOP_DEADLINE + SLACK) {
            Ok(Ok(o)) => o,
            Ok(Err(e)) => panic!("kernel_boot: boot sequence failed: {e}"),
            Err(e) => panic!("kernel_boot: DEADLINE EXCEEDED ({e}) after {secs}s boot budget"),
        };
        let diag = format!(
            "reason={:?} exits={} elapsed={:?} timed_out={} serial_tail={}",
            o.reason,
            o.exits,
            o.elapsed,
            o.timed_out,
            escape_tail(&o.output, TAIL_BYTES)
        );
        assert_eq!(
            count_marker_lines(&o.output, MARKER),
            1,
            "marker line: {diag}"
        );
        assert_eq!(o.reason, StopReason::GuestShutdown, "stop reason: {diag}");
        assert_eq!(o.origin_vcpu, Some(0), "origin vcpu: {diag}");
        assert_eq!(o.vcpu_count, 1, "vcpu count: {diag}");
        assert_eq!(o.errors, 0, "run errors: {diag}");
        assert_eq!(o.uart_dropped, 0, "uart dropped bytes: {diag}");
        assert!(!o.timed_out, "boot timed out: {diag}");
        eprintln!(
            "kernel_boot: ok reason=guest_shutdown elapsed_ms={} serial_bytes={} exits={}",
            o.elapsed.as_millis(),
            o.output.len(),
            o.exits
        );
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

#[cfg(not(target_arch = "x86_64"))]
mod other {
    use fandhe_container_microvm::device::KvmDevice;
    use fandhe_container_microvm::error::MicrovmErrorCode;
    use fandhe_container_microvm::microvm::{MicroVm, MicroVmConfig};
    use fandhe_container_microvm::virtio_block::MemoryBlockBackend;
    use fandhe_container_microvm::virtio_net::MemoryNetBackend;

    #[test]
    #[ignore = "requires read/write access to /dev/kvm (MVM-1)"]
    fn kernel_boot_real_kernel_reaches_init_and_shuts_down() {
        let dev = match KvmDevice::open() {
            Ok(d) => d,
            Err(e) => {
                panic!("kernel_boot: PRECONDITION FAILED (test environment, not a regression): {e}")
            }
        };
        let config: MicroVmConfig<MemoryBlockBackend, MemoryNetBackend> = MicroVmConfig {
            vcpu_count: 1,
            mem_size: 1 << 20,
            block: vec![],
            net: vec![],
        };
        assert_eq!(
            MicroVm::assemble(&dev, config).unwrap_err().code(),
            MicrovmErrorCode::Unimplemented
        );
    }
}
