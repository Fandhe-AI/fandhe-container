//! `/dev/kvm` 実機前提の試験（MVM-1・TASK-74.1.1・TASK-74.1.2・TASK-74.4.1・TASK-74.4.2・TASK-74.2.3・TASK-74.3.2）。`--ignored` 指定時だけ走る。
//! 必要環境: Linux・`/dev/kvm` の読み書き権限（`kvm` グループ等）。root は不要。
#![cfg(target_os = "linux")]

use fandhe_container_microvm::device::KvmDevice;
use fandhe_container_microvm::error::MicrovmErrorCode;
use std::os::fd::{AsFd as _, AsRawFd as _};

#[test]
#[ignore = "requires read/write access to /dev/kvm (MVM-1)"]
fn kvm_device_open_and_create_vm() {
    let dev = match KvmDevice::open() {
        Ok(d) => d,
        Err(e) => {
            panic!("kvm_device: PRECONDITION FAILED (test environment, not a regression): {e}")
        }
    };
    assert_eq!(dev.api_version().unwrap(), 12);
    let vm1 = dev.create_vm().unwrap();
    assert!(vm1.as_fd().as_raw_fd() >= 0);
    let vm2 = dev.create_vm().unwrap();
    assert_ne!(vm1.as_fd().as_raw_fd(), vm2.as_fd().as_raw_fd());
}

/// MVM-1・TASK-74.1.2: vCPU の作成・id の重複・範囲外 id。
#[test]
#[ignore = "requires read/write access to /dev/kvm (MVM-1)"]
fn kvm_device_create_vcpu() {
    let dev = match KvmDevice::open() {
        Ok(d) => d,
        Err(e) => {
            panic!("kvm_device: PRECONDITION FAILED (test environment, not a regression): {e}")
        }
    };
    let vm = dev.create_vm().unwrap();
    let v0 = vm.create_vcpu(0).unwrap();
    let v1 = vm.create_vcpu(1).unwrap();
    assert_eq!(v0.id(), 0);
    assert_eq!(v1.id(), 1);
    assert_ne!(v0.as_fd().as_raw_fd(), v1.as_fd().as_raw_fd());
    assert_eq!(
        vm.create_vcpu(0).unwrap_err().code(),
        MicrovmErrorCode::AlreadyExists
    );
    assert_eq!(
        vm.create_vcpu(u32::MAX).unwrap_err().code(),
        MicrovmErrorCode::InvalidArgument
    );
}
/// MVM-1・TASK-74.4.1: 実機の `KVM_RUN` でゲストコード（`mov al,0x42; out 0x10,al; hlt`）が実行され、
/// IO exit と HLT exit が型つきで返ること（x86_64）。
#[cfg(target_arch = "x86_64")]
#[test]
#[ignore = "requires read/write access to /dev/kvm (MVM-1)"]
fn kvm_device_run_guest_code() {
    use fandhe_container_microvm::exit::{IoDirection, VcpuExit};
    use std::sync::mpsc;
    use std::time::Duration;

    let dev = match KvmDevice::open() {
        Ok(d) => d,
        Err(e) => {
            panic!("kvm_device: PRECONDITION FAILED (test environment, not a regression): {e}")
        }
    };
    // REPAIR-5: 止まった vCPU スレッドが残っても、期限切れでテストごと失敗にする。
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(dev.probe_guest_execution());
    });
    let probe = rx
        .recv_timeout(Duration::from_secs(30))
        .expect("probe_guest_execution did not finish within 30s")
        .unwrap();
    assert_eq!(
        probe.exits,
        vec![
            VcpuExit::Io {
                direction: IoDirection::Out,
                port: 0x10,
                size: 1,
                count: 1,
                data: vec![0x42],
            },
            VcpuExit::Hlt,
        ]
    );
}

/// aarch64 では自己診断が未実装であること（型検査と fail-closed の確認）。
#[cfg(not(target_arch = "x86_64"))]
#[test]
#[ignore = "requires read/write access to /dev/kvm (MVM-1)"]
fn kvm_device_run_guest_code() {
    let dev = match KvmDevice::open() {
        Ok(d) => d,
        Err(e) => {
            panic!("kvm_device: PRECONDITION FAILED (test environment, not a regression): {e}")
        }
    };
    assert_eq!(
        dev.probe_guest_execution().unwrap_err().code(),
        MicrovmErrorCode::Unimplemented
    );
}

/// REPAIR-5・REPAIR-4・MVM-1・TASK-74.4.1: 無限ループのゲストは期限で中断され `DeadlineExceeded` になり、
/// 統計と記録器に残る。中断後も同じ vCPU で再実行できる。診断は呼び出しスレッドが `SIGUSR2` を
/// ブロックした状態で走り、それでも中断が届く（実行中だけ解除して復元する）。x86_64 のみ。
#[cfg(target_arch = "x86_64")]
#[test]
#[ignore = "requires read/write access to /dev/kvm (MVM-1)"]
fn kvm_device_run_deadline_interrupts_spinning_guest() {
    use fandhe_container_microvm::device::RunOutcome;
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    let dev = match KvmDevice::open() {
        Ok(d) => d,
        Err(e) => {
            panic!("kvm_device: PRECONDITION FAILED (test environment, not a regression): {e}")
        }
    };
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let start = Instant::now();
        let probe = dev.probe_deadline_interrupt(Duration::from_millis(200), 2);
        let _ = tx.send((probe, start.elapsed()));
    });
    let (probe, elapsed) = rx
        .recv_timeout(Duration::from_secs(30))
        .expect("probe_deadline_interrupt did not finish within 30s");
    let probe = probe.unwrap();
    assert!(elapsed < Duration::from_secs(5));
    assert!(probe.kick_mask_restored, "SIGUSR2 mask must be restored");
    assert_eq!(
        (
            probe.stats.runs,
            probe.stats.deadline_exceeded,
            probe.stats.exits
        ),
        (2, 2, 0)
    );
    assert!(probe.stats.total_elapsed >= Duration::from_millis(400));
    assert_eq!(probe.records.len(), 2);
    assert_eq!(probe.records[0].outcome, RunOutcome::DeadlineExceeded);
    assert_eq!(probe.records[0].vcpu_id, 0);
}

/// aarch64 では未実装であること。
#[cfg(not(target_arch = "x86_64"))]
#[test]
#[ignore = "requires read/write access to /dev/kvm (MVM-1)"]
fn kvm_device_run_deadline_interrupts_spinning_guest() {
    let dev = match KvmDevice::open() {
        Ok(d) => d,
        Err(e) => {
            panic!("kvm_device: PRECONDITION FAILED (test environment, not a regression): {e}")
        }
    };
    assert_eq!(
        dev.probe_deadline_interrupt(std::time::Duration::from_millis(200), 2)
            .unwrap_err()
            .code(),
        MicrovmErrorCode::Unimplemented
    );
}

/// MVM-1・TASK-74.4.2: 実機の VM exit が登録デバイスへ振り分けられ、IN（ポート 0x10 → 0x5A）と
/// MMIO read（GPA 0x2000 → 0xA5）の応答がゲストへ書き戻されること（ゲストが受けた値を OUT し直して観測する。x86_64）。
#[cfg(target_arch = "x86_64")]
#[test]
#[ignore = "requires read/write access to /dev/kvm (MVM-1)"]
fn kvm_device_exit_dispatch() {
    use fandhe_container_microvm::exit::{IoDirection, VcpuExit};
    use std::sync::mpsc;
    use std::time::Duration;

    let dev = match KvmDevice::open() {
        Ok(d) => d,
        Err(e) => {
            panic!("kvm_device: PRECONDITION FAILED (test environment, not a regression): {e}")
        }
    };
    // REPAIR-5: 止まった vCPU スレッドが残っても、期限切れでテストごと失敗にする。
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(dev.probe_exit_dispatch());
    });
    let probe = rx
        .recv_timeout(Duration::from_secs(30))
        .expect("probe_exit_dispatch did not finish within 30s")
        .unwrap();
    let io = |direction, port, data: Vec<u8>| VcpuExit::Io {
        direction,
        port,
        size: 1,
        count: 1,
        data,
    };
    // MMIO read exit の `data` はカーネルの領域に残っていた値で意味を持たないため、照合から外す。
    let mut exits = probe.exits.clone();
    assert!(matches!(
        exits.get(2),
        Some(VcpuExit::Mmio {
            phys_addr: 0x2000,
            len: 1,
            is_write: false,
            ..
        })
    ));
    exits.remove(2);
    assert_eq!(
        exits,
        vec![
            io(IoDirection::In, 0x10, vec![]),
            io(IoDirection::Out, 0x11, vec![0x5A]),
            io(IoDirection::Out, 0x12, vec![0xA5]),
            VcpuExit::Hlt,
        ]
    );
    assert_eq!(probe.port_writes, vec![(0, 0x5A), (1, 0xA5)]);
}

/// 他 arch では自己診断が未実装であること（型検査と fail-closed の確認）。
#[cfg(not(target_arch = "x86_64"))]
#[test]
#[ignore = "requires read/write access to /dev/kvm (MVM-1)"]
fn kvm_device_exit_dispatch() {
    let dev = match KvmDevice::open() {
        Ok(d) => d,
        Err(e) => {
            panic!("kvm_device: PRECONDITION FAILED (test environment, not a regression): {e}")
        }
    };
    assert_eq!(
        dev.probe_exit_dispatch().unwrap_err().code(),
        MicrovmErrorCode::Unimplemented
    );
}
/// MVM-1・MVM-4・TASK-74.2.3: virtio-block の `QueueNotify` が ioeventfd で VM exit なしに数えられ、処理後の
/// 割り込み（irqfd）がゲストの ISR に届くこと（x86_64）。
///
/// ゲストが実際に書くのは `QueueNotify` だけで、virtqueue の中身はホストの heap 上にある（ゲストメモリを
/// KVM に登録するのは TASK-75.1）。割り込みが入る前は HLT のまま `DeadlineExceeded` になる（陰性対照）。
#[cfg(target_arch = "x86_64")]
#[test]
#[ignore = "requires read/write access to /dev/kvm (MVM-1)"]
fn kvm_device_block_queue_interrupt() {
    use fandhe_container_microvm::device::QueueInterruptProbe;
    use fandhe_container_microvm::exit::{IoDirection, VcpuExit};
    use fandhe_container_microvm::guest_memory::{GuestAddress, GuestMemory, HeapBacking};
    use fandhe_container_microvm::interrupt::{InterruptDelivery, complete_block_notify};
    use fandhe_container_microvm::virtio_block::{
        BlockQueueStats, MemoryBlockBackend, VirtioBlock,
    };
    use fandhe_container_microvm::virtio_mmio::{MmioWriteOutcome, VirtioMmioTransport, reg};
    use std::sync::mpsc;
    use std::time::Duration;

    const DESC: u64 = 0x1000;
    const AVAIL: u64 = 0x2000;
    const USED: u64 = 0x3000;
    const HDR: u64 = 0x10000;
    const DATA: u64 = 0x11000;
    const STATUS: u64 = 0x12000;

    let dev = match KvmDevice::open() {
        Ok(d) => d,
        Err(e) => {
            panic!("kvm_device: PRECONDITION FAILED (test environment, not a regression): {e}")
        }
    };
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        type T = VirtioMmioTransport<VirtioBlock<MemoryBlockBackend>>;
        let mut t = VirtioMmioTransport::new(VirtioBlock::new(
            MemoryBlockBackend::new(16 * 512, false).unwrap(),
        ))
        .unwrap();
        let wr = |t: &mut T, off, v: u32| t.write(off, &v.to_le_bytes());
        wr(&mut t, reg::STATUS, 1);
        wr(&mut t, reg::STATUS, 3);
        let mut b = [0u8; 4];
        wr(&mut t, reg::DEVICE_FEATURES_SEL, 0);
        t.read(reg::DEVICE_FEATURES, &mut b);
        wr(&mut t, reg::DRIVER_FEATURES_SEL, 0);
        wr(&mut t, reg::DRIVER_FEATURES, u32::from_le_bytes(b));
        wr(&mut t, reg::DRIVER_FEATURES_SEL, 1);
        wr(&mut t, reg::DRIVER_FEATURES, 1);
        assert_eq!(
            wr(&mut t, reg::STATUS, 11),
            MmioWriteOutcome::FeaturesAccepted
        );
        wr(&mut t, reg::QUEUE_SEL, 0);
        wr(&mut t, reg::QUEUE_NUM, 16);
        wr(&mut t, reg::QUEUE_DESC_LOW, DESC as u32);
        wr(&mut t, reg::QUEUE_DRIVER_LOW, AVAIL as u32);
        wr(&mut t, reg::QUEUE_DEVICE_LOW, USED as u32);
        wr(&mut t, reg::QUEUE_READY, 1);
        assert_eq!(
            wr(&mut t, reg::STATUS, 15),
            MmioWriteOutcome::DeviceActivated
        );

        let mut mem =
            GuestMemory::new(GuestAddress::new(0), HeapBacking::new(1 << 20).unwrap()).unwrap();
        let payload: Vec<u8> = (0..512u32).map(|i| (i % 251) as u8).collect();
        mem.write_at(GuestAddress::new(DATA), &payload).unwrap();
        mem.write_u32_le(GuestAddress::new(HDR), 1).unwrap(); // VIRTIO_BLK_T_OUT
        mem.write_at(GuestAddress::new(HDR + 8), &3u64.to_le_bytes())
            .unwrap();
        for (i, addr, len, flags, next) in [
            (0u64, HDR, 16u32, 1u16, 1u16),
            (1, DATA, 512, 1, 2),
            (2, STATUS, 1, 2, 0),
        ] {
            let at = DESC + i * 16;
            mem.write_at(GuestAddress::new(at), &addr.to_le_bytes())
                .unwrap();
            mem.write_u32_le(GuestAddress::new(at + 8), len).unwrap();
            mem.write_u16_le(GuestAddress::new(at + 12), flags).unwrap();
            mem.write_u16_le(GuestAddress::new(at + 14), next).unwrap();
        }
        mem.write_at(GuestAddress::new(STATUS), &[0xff]).unwrap();
        mem.write_u16_le(GuestAddress::new(AVAIL + 4), 0).unwrap();
        mem.write_u16_le(GuestAddress::new(AVAIL + 2), 1).unwrap();

        let mut report = None;
        let probe = dev.probe_queue_interrupt(&mut |line| {
            report = Some(complete_block_notify(&mut t, &mut mem, line)?);
            Ok(())
        });
        let written = t.device().backend().contents()[3 * 512..4 * 512].to_vec();
        let _ = tx.send((probe, report, t.interrupt_status(), written, payload));
    });
    let (probe, report, status, written, payload) = rx
        .recv_timeout(Duration::from_secs(30))
        .expect("probe_queue_interrupt did not finish within 30s");
    let probe = probe.unwrap();
    let report = report.expect("on_notify must be called");
    let out = |port, byte| VcpuExit::Io {
        direction: IoDirection::Out,
        port,
        size: 1,
        count: 1,
        data: vec![byte],
    };
    assert_eq!(
        probe,
        QueueInterruptProbe {
            ready_exit: out(0x10, 0x42),
            notify_count: 1,
            idle_outcome: MicrovmErrorCode::DeadlineExceeded,
            interrupt_exit: out(0x13, 0xA5),
        }
    );
    assert_eq!(
        report.stats,
        BlockQueueStats {
            completed: 1,
            ok: 1,
            ..BlockQueueStats::default()
        }
    );
    assert_eq!(report.delivery, InterruptDelivery::Triggered);
    assert_eq!(report.queue_error, None);
    assert_eq!(status, 1);
    assert_eq!(written, payload);
}

/// MVM-1・MVM-4・TASK-74.3.2: virtio-net の receiveq の QueueNotify(0) が ioeventfd で数えられ、
/// `complete_net_notify` の後の irqfd の割り込みがゲストの ISR に届く。ゲストが書くのは `QueueNotify(0)` だけで、
/// virtqueue の中身はホストの heap にある（KVM への登録は TASK-75.1）。送信（キュー 1）は heap の試験で確かめる。
#[cfg(target_arch = "x86_64")]
#[test]
#[ignore = "requires read/write access to /dev/kvm (MVM-1)"]
fn kvm_device_net_queue_interrupt() {
    use fandhe_container_microvm::device::QueueInterruptProbe;
    use fandhe_container_microvm::exit::{IoDirection, VcpuExit};
    use fandhe_container_microvm::guest_memory::{GuestAddress, GuestMemory, HeapBacking};
    use fandhe_container_microvm::interrupt::{
        InterruptDelivery, NetQueueStats, complete_net_notify,
    };
    use fandhe_container_microvm::virtio_mmio::{MmioWriteOutcome, VirtioMmioTransport, reg};
    use fandhe_container_microvm::virtio_net::{MemoryNetBackend, NetRxStats, VirtioNet};
    use std::sync::mpsc;
    use std::time::Duration;

    const DESC: u64 = 0x1000;
    const AVAIL: u64 = 0x2000;
    const USED: u64 = 0x3000;
    const BUF: u64 = 0x11000;

    let dev = match KvmDevice::open() {
        Ok(d) => d,
        Err(e) => {
            panic!("kvm_device: PRECONDITION FAILED (test environment, not a regression): {e}")
        }
    };
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        type T = VirtioMmioTransport<VirtioNet<MemoryNetBackend>>;
        let mut t = VirtioMmioTransport::new(VirtioNet::new(
            MemoryNetBackend::new(),
            [0x02, 0, 0, 0, 0, 0x01],
        ))
        .unwrap();
        let wr = |t: &mut T, off, v: u32| t.write(off, &v.to_le_bytes());
        wr(&mut t, reg::STATUS, 1);
        wr(&mut t, reg::STATUS, 3);
        let mut b = [0u8; 4];
        wr(&mut t, reg::DEVICE_FEATURES_SEL, 0);
        t.read(reg::DEVICE_FEATURES, &mut b);
        wr(&mut t, reg::DRIVER_FEATURES_SEL, 0);
        wr(&mut t, reg::DRIVER_FEATURES, u32::from_le_bytes(b));
        wr(&mut t, reg::DRIVER_FEATURES_SEL, 1);
        wr(&mut t, reg::DRIVER_FEATURES, 1);
        assert_eq!(
            wr(&mut t, reg::STATUS, 11),
            MmioWriteOutcome::FeaturesAccepted
        );
        for (q, d, a, u) in [(0, DESC, AVAIL, USED), (1, 0x4000, 0x5000, 0x6000)] {
            wr(&mut t, reg::QUEUE_SEL, q);
            wr(&mut t, reg::QUEUE_NUM, 16);
            wr(&mut t, reg::QUEUE_DESC_LOW, d as u32);
            wr(&mut t, reg::QUEUE_DRIVER_LOW, a as u32);
            wr(&mut t, reg::QUEUE_DEVICE_LOW, u as u32);
            wr(&mut t, reg::QUEUE_READY, 1);
        }
        assert_eq!(
            wr(&mut t, reg::STATUS, 15),
            MmioWriteOutcome::DeviceActivated
        );

        let mut mem =
            GuestMemory::new(GuestAddress::new(0), HeapBacking::new(1 << 20).unwrap()).unwrap();
        let inbound: Vec<u8> = (0..100u32).map(|i| (i % 241) as u8).collect();
        t.device_mut().backend_mut().push_inbound(&inbound).unwrap();
        // receiveq: 2048 バイトの device-writable バッファ 1 つ。
        mem.write_at(GuestAddress::new(DESC), &BUF.to_le_bytes())
            .unwrap();
        mem.write_u32_le(GuestAddress::new(DESC + 8), 2048).unwrap();
        mem.write_u16_le(GuestAddress::new(DESC + 12), 2).unwrap();
        mem.write_u16_le(GuestAddress::new(DESC + 14), 0).unwrap();
        mem.write_u16_le(GuestAddress::new(AVAIL + 4), 0).unwrap();
        mem.write_u16_le(GuestAddress::new(AVAIL + 2), 1).unwrap();

        let mut report = None;
        let probe = dev.probe_queue_interrupt(&mut |line| {
            report = Some(complete_net_notify(&mut t, &mut mem, 0, line)?);
            Ok(())
        });
        let mut got = vec![0u8; 112];
        mem.read_at(GuestAddress::new(BUF), &mut got).unwrap();
        let _ = tx.send((probe, report, t.interrupt_status(), got, inbound));
    });
    let (probe, report, status, got, inbound) = rx
        .recv_timeout(Duration::from_secs(30))
        .expect("probe_queue_interrupt did not finish within 30s");
    let probe = probe.unwrap();
    let report = report.expect("on_notify must be called");
    let out = |port, byte| VcpuExit::Io {
        direction: IoDirection::Out,
        port,
        size: 1,
        count: 1,
        data: vec![byte],
    };
    assert_eq!(
        probe,
        QueueInterruptProbe {
            ready_exit: out(0x10, 0x42),
            notify_count: 1,
            idle_outcome: MicrovmErrorCode::DeadlineExceeded,
            interrupt_exit: out(0x13, 0xA5),
        }
    );
    assert_eq!(
        report.stats,
        NetQueueStats::Rx(NetRxStats {
            completed: 1,
            delivered: 1,
            ..NetRxStats::default()
        })
    );
    assert_eq!(report.delivery, InterruptDelivery::Triggered);
    assert_eq!(report.queue_error, None);
    assert_eq!(status, 1);
    assert_eq!(&got[..12], &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0]);
    assert_eq!(&got[12..], &inbound[..]);
}

/// 他 arch では virtio-net の割り込み通知の自己診断も未実装であること（型検査と fail-closed の確認）。
#[cfg(not(target_arch = "x86_64"))]
#[test]
#[ignore = "requires read/write access to /dev/kvm (MVM-1)"]
fn kvm_device_net_queue_interrupt() {
    let dev = match KvmDevice::open() {
        Ok(d) => d,
        Err(e) => {
            panic!("kvm_device: PRECONDITION FAILED (test environment, not a regression): {e}")
        }
    };
    assert_eq!(
        dev.probe_queue_interrupt(&mut |_| Ok(()))
            .unwrap_err()
            .code(),
        MicrovmErrorCode::Unimplemented
    );
}

/// 他 arch では割り込み通知の自己診断が未実装であること（型検査と fail-closed の確認）。
#[cfg(not(target_arch = "x86_64"))]
#[test]
#[ignore = "requires read/write access to /dev/kvm (MVM-1)"]
fn kvm_device_block_queue_interrupt() {
    let dev = match KvmDevice::open() {
        Ok(d) => d,
        Err(e) => {
            panic!("kvm_device: PRECONDITION FAILED (test environment, not a regression): {e}")
        }
    };
    assert_eq!(
        dev.probe_queue_interrupt(&mut |_| Ok(()))
            .unwrap_err()
            .code(),
        MicrovmErrorCode::Unimplemented
    );
}
