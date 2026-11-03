//! `/dev/kvm` 実機前提の起動から停止までの結合試験（MVM-1・TASK-75.5・#700）。`--ignored` 指定時だけ走る。
//! 必要環境: Linux・`/dev/kvm` の読み書き権限（`kvm` グループ等）。root は不要。
//!
//! 「最小デバイスモデルの microVM」とは vCPU 1 台・virtio-block 1 台・合成ペイロードの構成を指す。
//! 実 Linux カーネルの起動完走・AP・virtio-net を含む `start` は未実装で本試験の範囲外。
//!
//! 起動の観測手段: `RunRecord` は exit の種別名しか運ばず、停止後はホストからゲストの状態を読めない。
//! そこで合成ペイロード自身に起動状態を検証させ、結果を exit の種別の並びと停止理由へ写す。
//! ゲストは (1) RSI の boot_params の `HdrS` と `cmd_line_ptr`、(2) virtio-mmio の MagicValue と
//! DeviceID（virtio-block）を読んで照合し、すべて一致したときだけ PIO の write を 3 回出す。
//! ホストは `RunObserver` が記録した exit の並び（`mmio, mmio, io, io, io`）と `StopReason` で判定する。
//! 不一致は `ud2` で `GuestShutdown` になるため、「シャットダウン＝成功」とはみなさない。
//! 負の対照は block 無しの同じペイロードで、未登録 MMIO が 0xFF 埋めとなり照合に失敗することを確かめる。
#![cfg(target_os = "linux")]

#[cfg(target_arch = "x86_64")]
mod x86 {
    use fandhe_container_microvm::device::{KvmDevice, RunObserver, RunOutcome, RunRecord};
    use fandhe_container_microvm::microvm::{MicroVm, MicroVmConfig, StopReason};
    use fandhe_container_microvm::virtio_block::MemoryBlockBackend;
    use fandhe_container_microvm::virtio_net::MemoryNetBackend;
    use std::sync::mpsc;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    /// 記録された VM exit の種別名だけを並べる（中断・期限切れは捨てる）。
    #[derive(Debug, Default)]
    struct ExitKinds(Mutex<Vec<&'static str>>);
    impl RunObserver for ExitKinds {
        fn record(&self, record: &RunRecord) {
            if let RunOutcome::Exit(kind) = record.outcome {
                self.0.lock().unwrap().push(kind);
            }
        }
    }
    impl ExitKinds {
        fn kinds(&self) -> Vec<&'static str> {
            self.0.lock().unwrap().clone()
        }
    }

    fn wait_until(limit: Duration, mut cond: impl FnMut() -> bool) -> bool {
        let end = Instant::now() + limit;
        while Instant::now() < end {
            if cond() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        cond()
    }

    /// 合成 bzImage（64-bit エントリは payload + 0x200）。残りの payload は `ud2`（0F 0B）で埋める。
    fn synthetic_bzimage(entry_code: &[u8]) -> Vec<u8> {
        let mut img = vec![0u8; 5 * 512 + 0x1000];
        let mut put = |off: usize, d: &[u8]| img[off..off + d.len()].copy_from_slice(d);
        put(0x1F1, &[4]);
        put(0x1FE, &0xAA55u16.to_le_bytes());
        put(0x201, &[0x62]);
        put(0x202, b"HdrS");
        put(0x206, &0x020Fu16.to_le_bytes());
        put(0x211, &[1]);
        put(0x22C, &0x3FF_FFFFu32.to_le_bytes());
        put(0x230, &0x20_0000u32.to_le_bytes());
        put(0x234, &[1]);
        put(0x236, &1u16.to_le_bytes());
        put(0x238, &2047u32.to_le_bytes());
        put(0x258, &0x100_0000u64.to_le_bytes());
        put(0x260, &0x40_0000u32.to_le_bytes());
        let payload = 5 * 512;
        for (i, b) in img[payload..].iter_mut().enumerate() {
            *b = if i % 2 == 0 { 0x0F } else { 0x0B };
        }
        img[payload + 0x200..payload + 0x200 + entry_code.len()].copy_from_slice(entry_code);
        img
    }

    /// 起動状態を検証するゲストの機械語。成功時だけ PIO 0x10 へ 3 回 write して自己ループする。
    fn boot_check_payload() -> Vec<u8> {
        let mut c: Vec<u8> = Vec::new();
        let mut fixups: Vec<usize> = Vec::new();
        let mut jne = |c: &mut Vec<u8>| {
            c.extend_from_slice(&[0x75, 0x00]); // jne fail（rel8 は後で埋める）
            fixups.push(c.len() - 1);
        };
        // cmp dword [rsi+0x202], "HdrS"（zero page が RSI に入り、ロードされていること）
        c.extend_from_slice(&[0x81, 0xBE, 0x02, 0x02, 0x00, 0x00, 0x48, 0x64, 0x72, 0x53]);
        jne(&mut c);
        // cmp dword [rsi+0x228], 0x20000（cmd_line_ptr）
        c.extend_from_slice(&[0x81, 0xBE, 0x28, 0x02, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00]);
        jne(&mut c);
        // mov rbx, 0xd0000000; mov eax, [rbx]; cmp eax, 0x74726976（virtio-mmio MagicValue）
        c.extend_from_slice(&[0x48, 0xBB, 0x00, 0x00, 0x00, 0xD0, 0x00, 0x00, 0x00, 0x00]);
        c.extend_from_slice(&[0x8B, 0x03]);
        c.extend_from_slice(&[0x3D, 0x76, 0x69, 0x72, 0x74]);
        jne(&mut c);
        // mov rbx, 0xd0000008; mov eax, [rbx]; cmp eax, 2（DeviceID = virtio-block）
        c.extend_from_slice(&[0x48, 0xBB, 0x08, 0x00, 0x00, 0xD0, 0x00, 0x00, 0x00, 0x00]);
        c.extend_from_slice(&[0x8B, 0x03]);
        c.extend_from_slice(&[0x83, 0xF8, 0x02]);
        jne(&mut c);
        // mov al,'O'; out 0x10,al; mov al,'K'; out 0x10,al; mov al,'\n'; out 0x10,al; jmp $
        c.extend_from_slice(&[0xB0, b'O', 0xE6, 0x10]);
        c.extend_from_slice(&[0xB0, b'K', 0xE6, 0x10]);
        c.extend_from_slice(&[0xB0, b'\n', 0xE6, 0x10]);
        c.extend_from_slice(&[0xEB, 0xFE]);
        // fail: ud2
        let fail = c.len();
        c.extend_from_slice(&[0x0F, 0x0B]);
        for at in fixups {
            let rel = fail - (at + 1);
            c[at] = i8::try_from(rel).expect("jne rel8 must fit in i8") as u8;
        }
        c
    }

    struct Outcome {
        reason: StopReason,
        kinds: Vec<&'static str>,
        exits: u64,
        errors: u64,
        elapsed: Duration,
        obs_refs: usize,
    }

    /// 組み立て・ロード・開始・待ち・停止までを通す。`with_block` が偽なら負の対照。
    fn boot_and_stop(with_block: bool) -> Outcome {
        let dev = match KvmDevice::open() {
            Ok(d) => d,
            Err(e) => {
                panic!("microvm: PRECONDITION FAILED (test environment, not a regression): {e}")
            }
        };
        let mut vm: MicroVm<MemoryBlockBackend, MemoryNetBackend> = MicroVm::assemble(
            &dev,
            MicroVmConfig {
                vcpu_count: 1,
                mem_size: 64 << 20,
                block: if with_block {
                    vec![MemoryBlockBackend::new(16 * 512, false).unwrap()]
                } else {
                    vec![]
                },
                net: vec![],
            },
        )
        .unwrap();
        if with_block {
            assert_eq!(
                vm.devices()[0].slot.mmio_base,
                0xd000_0000,
                "payload MMIO address"
            );
        }
        let img = synthetic_bzimage(&boot_check_payload());
        let loaded = vm.load_kernel(&img, None, "console=ttyS0").unwrap();
        assert_eq!(loaded.entry.raw(), 0x100_0200);
        assert_eq!(loaded.boot_params.raw(), 0x7000);
        let obs = Arc::new(ExitKinds::default());
        vm.vcpu_mut(0).unwrap().set_observer(obs.clone());
        let running = vm.start(&loaded).unwrap();
        if with_block {
            assert!(
                wait_until(Duration::from_secs(10), || {
                    obs.kinds().iter().filter(|k| **k == "io").count() >= 3
                }),
                "guest did not reach PIO writes: {:?}",
                obs.kinds()
            );
        } else {
            assert!(
                wait_until(Duration::from_secs(10), || running.is_finished()),
                "guest did not shut down: {:?}",
                obs.kinds()
            );
        }
        let t = Instant::now();
        let report = running.stop(Duration::from_secs(5)).unwrap();
        let elapsed = t.elapsed();
        Outcome {
            reason: report.reason,
            kinds: obs.kinds(),
            exits: report.stats.exits,
            errors: report.stats.errors,
            elapsed,
            obs_refs: Arc::strong_count(&obs),
        }
    }

    /// REPAIR-5: 止まったスレッドが残っても、期限切れで試験ごと失敗にする。
    fn bounded(with_block: bool) -> Outcome {
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(boot_and_stop(with_block));
        });
        rx.recv_timeout(Duration::from_secs(60))
            .expect("boot_and_stop did not finish within 60s (or panicked)")
    }

    /// MVM-1・TASK-75.5: 最小構成の microVM が起動し、起動状態の検証に合格して停止要求で止まる。
    #[test]
    #[ignore = "requires read/write access to /dev/kvm (MVM-1)"]
    fn microvm_boots_minimal_device_model_and_stops() {
        let o = bounded(true);
        assert_eq!(o.kinds, vec!["mmio", "mmio", "io", "io", "io"]);
        assert_eq!(o.reason, StopReason::Requested);
        assert_eq!(o.exits, 5);
        assert_eq!(o.errors, 0);
        assert!(o.elapsed < Duration::from_secs(2), "{:?}", o.elapsed);
        assert_eq!(o.obs_refs, 1, "MicroVm must be dropped after stop");
    }

    /// MVM-1・TASK-75.5: 負の対照。block 無しでは MagicValue の照合に失敗し、PIO write なしで終わる。
    #[test]
    #[ignore = "requires read/write access to /dev/kvm (MVM-1)"]
    fn microvm_boot_check_fails_without_block_device() {
        let o = bounded(false);
        assert_eq!(o.kinds, vec!["mmio", "shutdown"]);
        assert_eq!(o.reason, StopReason::GuestShutdown);
        assert_eq!(o.obs_refs, 1);
    }
}

#[cfg(not(target_arch = "x86_64"))]
mod other {
    use fandhe_container_microvm::device::KvmDevice;
    use fandhe_container_microvm::error::MicrovmErrorCode;
    use fandhe_container_microvm::microvm::{MicroVm, MicroVmConfig};
    use fandhe_container_microvm::virtio_block::MemoryBlockBackend;
    use fandhe_container_microvm::virtio_net::MemoryNetBackend;

    fn assemble_is_unimplemented() {
        let dev = match KvmDevice::open() {
            Ok(d) => d,
            Err(e) => {
                panic!("microvm: PRECONDITION FAILED (test environment, not a regression): {e}")
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

    #[test]
    #[ignore = "requires read/write access to /dev/kvm (MVM-1)"]
    fn microvm_boots_minimal_device_model_and_stops() {
        assemble_is_unimplemented();
    }

    #[test]
    #[ignore = "requires read/write access to /dev/kvm (MVM-1)"]
    fn microvm_boot_check_fails_without_block_device() {
        assemble_is_unimplemented();
    }
}
