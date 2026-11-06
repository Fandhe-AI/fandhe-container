//! `/dev/kvm` 実機前提の試験（MVM-1・TASK-74.1.1・TASK-74.1.2・TASK-74.4.1・TASK-74.4.2・TASK-74.2.3・TASK-74.3.2・TASK-75.1・TASK-75.2・TASK-75.3.1・TASK-75.3.2・TASK-75.4.1・TASK-75.4.2・TASK-75.5・#3733・#3734・#3735・#3738・#3918）。`--ignored` 指定時だけ走る。
//! 必要環境: Linux・`/dev/kvm` の読み書き権限（`kvm` グループ等）。root は不要。
//! aarch64 の試験（`kvm_device_arm64_*`。#3696）は、加えて aarch64 Linux ホストと in-kernel GICv3 が要る（ネイティブ arm64 の CI は無く、実機は人間担当。#2274・#3781）。
#![cfg(target_os = "linux")]

use fandhe_container_microvm::device::KvmDevice;
use fandhe_container_microvm::error::MicrovmErrorCode;
use std::os::fd::{AsFd as _, AsRawFd as _};

/// 前提欠如と回帰の振り分けの正本（環境を示すコードだけ前提欠如にする。#3992）。
#[path = "support/kvm_precondition.rs"]
mod kvm_precondition;

/// `KvmDevice::open` の失敗を、環境を示すコードだけ `PRECONDITION FAILED` にして落とす（MVM-1・REPAIR-4・#3992）。
fn open_kvm() -> KvmDevice {
    KvmDevice::open()
        .unwrap_or_else(|e| panic!("{}", kvm_precondition::open_failure_line("kvm_device", &e)))
}

/// 合成 bzImage の正本（x86_64 の実機前提試験だけが使う。複製しない・#3750）。
#[cfg(target_arch = "x86_64")]
#[path = "support/bzimage.rs"]
mod bzimage;

#[test]
#[ignore = "requires read/write access to /dev/kvm (MVM-1)"]
fn kvm_device_open_and_create_vm() {
    let dev = open_kvm();
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
    let dev = open_kvm();
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

    let dev = open_kvm();
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
    let dev = open_kvm();
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

    let dev = open_kvm();
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
    let dev = open_kvm();
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

    let dev = open_kvm();
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
    let dev = open_kvm();
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

    let dev = open_kvm();
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

    let dev = open_kvm();
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
    let dev = open_kvm();
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
    let dev = open_kvm();
    assert_eq!(
        dev.probe_queue_interrupt(&mut |_| Ok(()))
            .unwrap_err()
            .code(),
        MicrovmErrorCode::Unimplemented
    );
}

/// MVM-1・TASK-75.1: mmap したゲスト RAM を memslot に登録でき、読み書きが往復し、範囲の重なる登録は拒否される。
#[test]
#[ignore = "requires read/write access to /dev/kvm (MVM-1)"]
fn kvm_device_register_guest_memory() {
    use fandhe_container_microvm::guest_memory::GuestAddress;
    use fandhe_container_microvm::microvm::GuestRam;

    let dev = open_kvm();
    let vm = dev.create_vm().unwrap();
    let mut mem = GuestRam::new(2 << 20)
        .unwrap()
        .register(&vm, 0, GuestAddress::new(0))
        .unwrap();
    assert_eq!(mem.len(), 2 << 20);
    mem.write_at(GuestAddress::new(0x1FFFFC), &[1, 2, 3, 4])
        .unwrap();
    assert_eq!(
        mem.read_u32_le(GuestAddress::new(0x1FFFFC)).unwrap(),
        0x0403_0201
    );
    assert!(mem.write_at(GuestAddress::new(0x1FFFFD), &[0; 4]).is_err());
    // 範囲が重なる別 slot の登録は AlreadyExists。
    let err = GuestRam::new(1 << 20)
        .unwrap()
        .register(&vm, 1, GuestAddress::new(0x100000))
        .unwrap_err();
    assert_eq!(err.code(), MicrovmErrorCode::AlreadyExists);
    // 重ならない別 slot は登録できる。
    let other = GuestRam::new(1 << 20)
        .unwrap()
        .register(&vm, 1, GuestAddress::new(0x4000_0000))
        .unwrap();
    // 登録順の逆で drop しても、VM fd より先に drop しても panic しない。
    drop(vm);
    drop(other);
    drop(mem);
}

/// MVM-1・TASK-75.1: ゲストが登録済みのメモリを実際に書き、ホストから観測できる（x86_64）。
/// リセットベクタのゲストコード `mov byte cs:[0x0100], 0x5A; hlt` が `0xFFFF_0100` へ書く。
#[cfg(target_arch = "x86_64")]
#[test]
#[ignore = "requires read/write access to /dev/kvm (MVM-1)"]
fn kvm_device_guest_writes_registered_memory() {
    use fandhe_container_microvm::exit::VcpuExit;
    use fandhe_container_microvm::guest_memory::GuestAddress;
    use fandhe_container_microvm::microvm::GuestRam;
    use std::sync::mpsc;
    use std::time::Duration;

    let dev = open_kvm();
    // REPAIR-5: 止まった vCPU スレッドが残っても、期限切れでテストごと失敗にする。
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let run = || -> Result<u8, String> {
            let vm = dev.create_vm().map_err(|e| e.to_string())?;
            let mut mem = GuestRam::new(64 << 10)
                .and_then(|r| r.register(&vm, 0, GuestAddress::new(0xFFFF_0000)))
                .map_err(|e| e.to_string())?;
            let code = [0x2E, 0xC6, 0x06, 0x00, 0x01, 0x5A, 0xF4];
            mem.write_at(GuestAddress::new(0xFFFF_FFF0), &code)
                .map_err(|e| e.to_string())?;
            let mut vcpu = vm.create_vcpu(0).map_err(|e| e.to_string())?;
            for _ in 0..8 {
                match vcpu
                    .run_once(Duration::from_secs(5))
                    .map_err(|e| e.to_string())?
                {
                    VcpuExit::Interrupted => continue,
                    VcpuExit::Hlt => {
                        let mut b = [0u8; 1];
                        mem.read_at(GuestAddress::new(0xFFFF_0100), &mut b)
                            .map_err(|e| e.to_string())?;
                        drop(vcpu);
                        return Ok(b[0]);
                    }
                    other => return Err(format!("unexpected exit: {other:?}")),
                }
            }
            Err("too many interrupted runs".to_string())
        };
        let _ = tx.send(run());
    });
    let byte = rx
        .recv_timeout(Duration::from_secs(30))
        .expect("guest memory test did not finish within 30s")
        .unwrap();
    assert_eq!(byte, 0x5A);
}

/// MVM-1・TASK-75.2: デバイス・vCPU・メモリを 1 つの VM 構成体に組み立て、一貫した経路で触れること。
/// 破棄後に同じ `KvmDevice` で再度組み立てられる（資源が解放されている）ことも確かめる（x86_64）。
#[cfg(target_arch = "x86_64")]
#[test]
#[ignore = "requires read/write access to /dev/kvm (MVM-1)"]
fn kvm_device_assemble_microvm() {
    use fandhe_container_microvm::guest_memory::GuestAddress;
    use fandhe_container_microvm::interrupt::InterruptDelivery;
    use fandhe_container_microvm::microvm::{
        DeviceSlot, MicroVm, MicroVmConfig, NetDeviceConfig, QueueNotifyReport, VirtioDeviceKind,
    };
    use fandhe_container_microvm::virtio_block::MemoryBlockBackend;
    use fandhe_container_microvm::virtio_mmio::{MAGIC_VALUE, reg};
    use fandhe_container_microvm::virtio_net::MemoryNetBackend;

    let dev = open_kvm();
    let config = || MicroVmConfig {
        vcpu_count: 2,
        mem_size: 2 << 20,
        block: vec![MemoryBlockBackend::new(16 * 512, false).unwrap()],
        net: vec![NetDeviceConfig {
            backend: MemoryNetBackend::new(),
            mac: [0x02, 0, 0, 0, 0, 1],
        }],
    };
    for _ in 0..2 {
        let mut vm: MicroVm<_, _> = MicroVm::assemble(&dev, config()).unwrap();
        let ids: Vec<u32> = vm.vcpus().iter().map(|v| v.id()).collect();
        assert_eq!(ids, vec![0, 1]);
        assert_eq!(vm.memory().base(), GuestAddress::new(0));
        assert_eq!(vm.memory().len(), 2 << 20);
        vm.memory_mut()
            .write_at(GuestAddress::new(0x1000), &[0xDE, 0xAD, 0xBE, 0xEF])
            .unwrap();
        assert_eq!(
            vm.memory().read_u32_le(GuestAddress::new(0x1000)).unwrap(),
            0xEFBE_ADDE
        );
        let infos = vm.devices();
        assert_eq!(
            infos.iter().map(|i| i.slot).collect::<Vec<_>>(),
            vec![
                DeviceSlot {
                    kind: VirtioDeviceKind::Block,
                    index: 0,
                    mmio_base: 0xd000_0000,
                    mmio_len: 0x1000,
                    gsi: 5,
                },
                DeviceSlot {
                    kind: VirtioDeviceKind::Net,
                    index: 0,
                    mmio_base: 0xd000_1000,
                    mmio_len: 0x1000,
                    gsi: 6,
                },
            ]
        );
        let mut buf = [0u8; 4];
        vm.with_block(0, |t| t.read(reg::MAGIC, &mut buf)).unwrap();
        assert_eq!(u32::from_le_bytes(buf), MAGIC_VALUE);
        vm.with_net(0, |t| t.read(reg::DEVICE_ID, &mut buf))
            .unwrap();
        assert_eq!(u32::from_le_bytes(buf), 1);
        match vm.complete_queue_notify(infos[0].id, 0).unwrap() {
            QueueNotifyReport::Block(r) => assert_eq!(r.delivery, InterruptDelivery::NotNeeded),
            other => panic!("unexpected report: {other:?}"),
        }
        assert_eq!(
            vm.with_block(1, |_| ()).unwrap_err().code(),
            MicrovmErrorCode::InvalidArgument
        );
        let exit = fandhe_container_microvm::exit::VcpuExit::Hlt;
        assert_eq!(
            vm.handle_exit(2, &exit).unwrap_err().code(),
            MicrovmErrorCode::InvalidArgument
        );
    }
}

/// MVM-1・TASK-75.2: x86_64 以外では組み立てが最初の ioctl より前に `Unimplemented` で失敗する。
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
#[test]
#[ignore = "requires read/write access to /dev/kvm (MVM-1)"]
fn kvm_device_assemble_microvm() {
    use fandhe_container_microvm::microvm::{MicroVm, MicroVmConfig};
    use fandhe_container_microvm::virtio_block::MemoryBlockBackend;
    use fandhe_container_microvm::virtio_net::MemoryNetBackend;

    let dev = open_kvm();
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

/// MVM-1・TASK-75.3.1: 組み立て済みの VM へ合成 bzImage と initrd をロードし、zero page・cmdline・payload・initrd を
/// ゲストメモリから読み戻して照合する（x86_64）。実カーネルの起動は #885・#886 の範囲。
#[cfg(target_arch = "x86_64")]
#[test]
#[ignore = "requires read/write access to /dev/kvm (MVM-1)"]
fn kvm_device_load_kernel_into_assembled_microvm() {
    use fandhe_container_microvm::guest_memory::GuestAddress;
    use fandhe_container_microvm::microvm::{MicroVm, MicroVmConfig, NetDeviceConfig};
    use fandhe_container_microvm::virtio_block::MemoryBlockBackend;
    use fandhe_container_microvm::virtio_net::MemoryNetBackend;

    let dev = open_kvm();
    let mut vm = MicroVm::assemble(
        &dev,
        MicroVmConfig {
            vcpu_count: 1,
            mem_size: 64 << 20,
            block: vec![MemoryBlockBackend::new(16 * 512, false).unwrap()],
            net: vec![NetDeviceConfig {
                backend: MemoryNetBackend::new(),
                mac: [0x02, 0, 0, 0, 0, 1],
            }],
        },
    )
    .unwrap();

    // 合成 bzImage（`support/bzimage.rs`）。payload は添字依存の非ゼロ値で埋め、ロード後の内容照合に使う。
    let mut img = bzimage::header_only();
    bzimage::fill_payload(&mut img, |i| (i % 251) as u8 | 1);
    let initrd: Vec<u8> = (0..0x2000u32).map(|i| (i % 241) as u8).collect();

    let l = vm
        .load_kernel(&img, Some(&initrd), "console=ttyS0")
        .unwrap();
    assert_eq!(l.entry, GuestAddress::new(0x100_0200));
    assert_eq!(l.boot_params, GuestAddress::new(0x7000));
    assert_eq!(l.initrd, Some((GuestAddress::new(0x3FF_E000), 0x2000)));

    let read = |addr: u64, n: usize| {
        let mut b = vec![0u8; n];
        vm.memory()
            .read_at(GuestAddress::new(addr), &mut b)
            .unwrap();
        b
    };
    assert_eq!(read(0x100_0000, 0x1000), img[5 * 512..].to_vec());
    assert_eq!(read(0x3FF_E000, 0x2000), initrd);
    assert_eq!(read(0x7000 + 0x202, 4), b"HdrS".to_vec());
    assert_eq!(
        vm.memory()
            .read_u32_le(GuestAddress::new(0x7000 + 0x218))
            .unwrap(),
        0x3FF_E000
    );
    assert_eq!(
        vm.memory()
            .read_u32_le(GuestAddress::new(0x7000 + 0x21C))
            .unwrap(),
        0x2000
    );
    let want = "console=ttyS0 no_timer_check virtio_mmio.device=0x1000@0xd0000000:5 virtio_mmio.device=0x1000@0xd0001000:6\0";
    assert_eq!(read(0x2_0000, want.len()), want.as_bytes().to_vec());
}

/// MVM-1・TASK-75.3.1: x86_64 以外ではカーネルのロードが `Unimplemented`（組み立てが先に `Unimplemented` で失敗する）。
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
#[test]
#[ignore = "requires read/write access to /dev/kvm (MVM-1)"]
fn kvm_device_load_kernel_into_assembled_microvm() {
    use fandhe_container_microvm::microvm::{MicroVm, MicroVmConfig};
    use fandhe_container_microvm::virtio_block::MemoryBlockBackend;
    use fandhe_container_microvm::virtio_net::MemoryNetBackend;

    let dev = open_kvm();
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

/// MVM-1・TASK-75.3.2: ロード済みカーネルのエントリから vCPU が実行を始める（x86_64）。合成 bzImage の 64-bit エントリに置いた
/// コードが、(1) RSI（boot_params = 0x7000）を `out` で観測させ、(2) 64-bit の即値を GPA 0x1000_0000（MMIO 窓の外の未登録の
/// アドレス）へ 8 バイトで書く。1 つ目は RIP がエントリであることと RSI の設定を、2 つ目は long mode（CS.L・ページング・恒等写像）を示す。
/// in-kernel irqchip のため HLT は userspace へ出ないので、OUT と MMIO で観測する。誤った RIP は `ud2` → triple fault → `Shutdown` で速く失敗する。
#[cfg(target_arch = "x86_64")]
#[test]
#[ignore = "requires read/write access to /dev/kvm (MVM-1)"]
fn kvm_device_boot_vcpu_starts_at_kernel_entry() {
    use fandhe_container_microvm::exit::{IoDirection, VcpuExit};
    use fandhe_container_microvm::guest_memory::GuestAddress;
    use fandhe_container_microvm::microvm::{MicroVm, MicroVmConfig};
    use fandhe_container_microvm::virtio_block::MemoryBlockBackend;
    use fandhe_container_microvm::virtio_net::MemoryNetBackend;
    use std::sync::mpsc;
    use std::time::Duration;

    let dev = open_kvm();

    // 合成 bzImage（`support/bzimage.rs`）。payload の 0x200 が 64-bit エントリで、残りは ud2。
    let mut code: Vec<u8> = vec![0x89, 0xF0, 0xE7, 0x10]; // mov eax,esi ; out 0x10,eax
    code.extend_from_slice(&[0x48, 0xB8]); // movabs rax, imm64
    code.extend_from_slice(&0x1122_3344_5566_7788u64.to_le_bytes());
    code.extend_from_slice(&[0x48, 0xA3]); // movabs [moffs64], rax
    code.extend_from_slice(&0x1000_0000u64.to_le_bytes());
    let img = bzimage::synthetic_bzimage(&code);

    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut vm: MicroVm<MemoryBlockBackend, MemoryNetBackend> = MicroVm::assemble(
            &dev,
            MicroVmConfig {
                vcpu_count: 1,
                mem_size: 64 << 20,
                block: vec![],
                net: vec![],
            },
        )
        .unwrap();
        let loaded = vm.load_kernel(&img, None, "console=ttyS0").unwrap();
        assert_eq!(loaded.entry, GuestAddress::new(0x100_0200));
        vm.setup_boot_vcpu(&loaded).unwrap();
        let vcpu = vm.vcpu_mut(0).unwrap();
        // 設定直後（実行前）の値。
        let r = vcpu.regs().unwrap();
        assert_eq!(
            (r.rip, r.rsi, r.rsp, r.rbp, r.rflags),
            (0x100_0200, 0x7000, 0x8FF0, 0x8FF0, 0x2)
        );
        let next = |vcpu: &mut fandhe_container_microvm::device::VcpuFd| loop {
            match vcpu.run_once(Duration::from_secs(10)).unwrap() {
                VcpuExit::Interrupted => continue,
                e => return e,
            }
        };
        let first = next(vcpu);
        let rip_after_out = vcpu.regs().unwrap().rip;
        let second = next(vcpu);
        let _ = tx.send((first, rip_after_out, second));
    });
    let (first, rip_after_out, second) = rx
        .recv_timeout(Duration::from_secs(60))
        .expect("boot vCPU did not finish within 60s");
    // 1 つ目: RSI = boot_params が eax 経由で OUT に出る。exit 時点の RIP は OUT 命令の位置（エントリ + mov の 2 バイト）。
    assert_eq!(
        first,
        VcpuExit::Io {
            direction: IoDirection::Out,
            port: 0x10,
            size: 4,
            count: 1,
            data: 0x7000u32.to_le_bytes().to_vec(),
        }
    );
    assert_eq!(rip_after_out, 0x100_0202);
    // 2 つ目: long mode でだけ起きる 8 バイトの MMIO 書き込み。
    assert_eq!(
        second,
        VcpuExit::Mmio {
            phys_addr: 0x1000_0000,
            data: 0x1122_3344_5566_7788u64.to_le_bytes(),
            len: 8,
            is_write: true,
        }
    );
}

/// MVM-1・TASK-75.3.2: x86_64 以外ではレジスタ初期化も組み立てが先に `Unimplemented` で失敗する。
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
#[test]
#[ignore = "requires read/write access to /dev/kvm (MVM-1)"]
fn kvm_device_boot_vcpu_starts_at_kernel_entry() {
    use fandhe_container_microvm::microvm::{MicroVm, MicroVmConfig};
    use fandhe_container_microvm::virtio_block::MemoryBlockBackend;
    use fandhe_container_microvm::virtio_net::MemoryNetBackend;

    let dev = open_kvm();
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
/// MVM-1・#3735: `setup_boot_vcpu` が BSP の LAPIC の LVT LINT0 を ExtINT（マスク解除）、LINT1 を NMI にし、`KVM_GET_LAPIC` で読み戻せる。
/// 経路は `assemble` → `load_kernel` → `setup_boot_vcpu` を通す（呼び出し箇所の付け忘れを検出するため）。LINT0 は
/// `KVM_X86_QUIRK_LINT0_REENABLED` で設定前から ExtINT のことがあり判別子にならないため、設定前に NMI でなかった LINT1 を変化の証跡にする。
#[cfg(target_arch = "x86_64")]
#[test]
#[ignore = "requires read/write access to /dev/kvm (MVM-1)"]
fn kvm_device_boot_lapic_lints_read_back() {
    use fandhe_container_microvm::lapic_x86::{LvtDeliveryMode, virtual_wire_lvt};
    use fandhe_container_microvm::microvm::{MicroVm, MicroVmConfig};
    use fandhe_container_microvm::virtio_block::MemoryBlockBackend;
    use fandhe_container_microvm::virtio_net::MemoryNetBackend;

    let dev = open_kvm();

    // 合成 bzImage（ヘッダのみ。コードは使わない・実行しない。`support/bzimage.rs`）。
    let img = bzimage::header_only();

    let mut vm: MicroVm<MemoryBlockBackend, MemoryNetBackend> = MicroVm::assemble(
        &dev,
        MicroVmConfig {
            vcpu_count: 1,
            mem_size: 64 << 20,
            block: vec![],
            net: vec![],
        },
    )
    .unwrap();
    let pre = vm.vcpu_mut(0).unwrap().lapic_lints().unwrap();
    let loaded = vm.load_kernel(&img, None, "console=ttyS0").unwrap();
    vm.setup_boot_vcpu(&loaded).unwrap();
    let post = vm.vcpu_mut(0).unwrap().lapic_lints().unwrap();

    // LINT1: NMI・マスク解除（設定前は NMI かつマスク解除ではない = 変化の証跡）。
    assert_eq!(post.lint1, 0x0000_0400);
    assert!(!(pre.lint1_mode() == LvtDeliveryMode::Nmi && !pre.lint1_masked()));
    // LINT0: ExtINT・マスク解除。
    assert_eq!(post.lint0_mode(), LvtDeliveryMode::ExtInt);
    assert!(!post.lint0_masked());
    // 純粋関数と ioctl 経路の結びつき。
    assert_eq!(
        post.lint0,
        virtual_wire_lvt(pre.lint0, LvtDeliveryMode::ExtInt)
    );
    assert_eq!(
        post.lint1,
        virtual_wire_lvt(pre.lint1, LvtDeliveryMode::Nmi)
    );
}

/// MVM-1・#3735: x86_64 以外では組み立てが先に `Unimplemented` で失敗する。
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
#[test]
#[ignore = "requires read/write access to /dev/kvm (MVM-1)"]
fn kvm_device_boot_lapic_lints_read_back() {
    use fandhe_container_microvm::microvm::{MicroVm, MicroVmConfig};
    use fandhe_container_microvm::virtio_block::MemoryBlockBackend;
    use fandhe_container_microvm::virtio_net::MemoryNetBackend;

    let dev = open_kvm();
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

/// MVM-1・#3733・TASK-75.3.2: `MicroVm::assemble` が設定した `KVM_SET_CPUID2` がゲストから見える。vCPU 0 のゲストが
/// leaf 0 の vendor（EBX・EDX・ECX）と leaf 1 の APIC ID（EBX\[31:24\]）・hypervisor ビット（ECX\[31\]）を `out 0x10` で返し、
/// ホスト側の期待値（`KVM_GET_SUPPORTED_CPUID` の leaf 0 と、設定した APIC ID = 0）と具体値で照合する。
/// AP（vCPU 1 以上）の APIC ID 1 は `kvm_device_ap_starts_on_init_sipi`（#3737）が、x2APIC leaf の調整は
/// KVM 不要の単体試験 `mvm1_3733_*`（`cpuid_x86`）が照合する。
#[cfg(target_arch = "x86_64")]
#[test]
#[ignore = "requires read/write access to /dev/kvm (MVM-1)"]
fn kvm_device_cpuid_vendor_and_apic_id_reach_guest() {
    use fandhe_container_microvm::exit::{IoDirection, VcpuExit};
    use fandhe_container_microvm::microvm::{MicroVm, MicroVmConfig};
    use fandhe_container_microvm::virtio_block::MemoryBlockBackend;
    use fandhe_container_microvm::virtio_net::MemoryNetBackend;
    use std::sync::mpsc;
    use std::time::Duration;

    let dev = open_kvm();
    let host = dev.supported_cpuid().unwrap();
    let leaf0 = *host.get(0, 0).unwrap();

    // 合成 bzImage（ud2 埋め・エントリにテストコード。`support/bzimage.rs`）。
    let code: Vec<u8> = vec![
        0x31, 0xC0, 0x0F, 0xA2, // xor eax,eax ; cpuid
        0x89, 0xD8, 0xE7, 0x10, // mov eax,ebx ; out 0x10,eax
        0x89, 0xD0, 0xE7, 0x10, // mov eax,edx ; out
        0x89, 0xC8, 0xE7, 0x10, // mov eax,ecx ; out
        0xB8, 0x01, 0x00, 0x00, 0x00, 0x0F, 0xA2, // mov eax,1 ; cpuid
        0x89, 0xD8, 0xC1, 0xE8, 0x18, 0xE7, 0x10, // mov eax,ebx ; shr eax,24 ; out
        0x89, 0xC8, 0xC1, 0xE8, 0x1F, 0xE7, 0x10, // mov eax,ecx ; shr eax,31 ; out
    ];
    let img = bzimage::synthetic_bzimage(&code);

    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut vm: MicroVm<MemoryBlockBackend, MemoryNetBackend> = MicroVm::assemble(
            &dev,
            MicroVmConfig {
                vcpu_count: 1,
                mem_size: 64 << 20,
                block: vec![],
                net: vec![],
            },
        )
        .unwrap();
        let loaded = vm.load_kernel(&img, None, "console=ttyS0").unwrap();
        vm.setup_boot_vcpu(&loaded).unwrap();
        let vcpu = vm.vcpu_mut(0).unwrap();
        let mut exits = Vec::new();
        while exits.len() < 5 {
            match vcpu.run_once(Duration::from_secs(10)).unwrap() {
                VcpuExit::Interrupted => continue,
                e => exits.push(e),
            }
        }
        let _ = tx.send(exits);
    });
    let exits = rx
        .recv_timeout(Duration::from_secs(60))
        .expect("guest did not finish within 60s");
    let out = |v: u32| VcpuExit::Io {
        direction: IoDirection::Out,
        port: 0x10,
        size: 4,
        count: 1,
        data: v.to_le_bytes().to_vec(),
    };
    // vendor（EBX・EDX・ECX）、APIC ID 0、hypervisor ビット 1。
    assert_eq!(
        exits,
        vec![
            out(leaf0.ebx),
            out(leaf0.edx),
            out(leaf0.ecx),
            out(0),
            out(1)
        ]
    );
}

/// MVM-1・#3733: x86_64 以外では CPUID の設定も組み立てが先に `Unimplemented` で失敗する。
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
#[test]
#[ignore = "requires read/write access to /dev/kvm (MVM-1)"]
fn kvm_device_cpuid_vendor_and_apic_id_reach_guest() {
    use fandhe_container_microvm::microvm::{MicroVm, MicroVmConfig};
    use fandhe_container_microvm::virtio_block::MemoryBlockBackend;
    use fandhe_container_microvm::virtio_net::MemoryNetBackend;

    let dev = open_kvm();
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

/// MVM-1・#3737: AP は `KVM_MP_STATE_UNINITIALIZED` で作られ、BSP のゲストコードが送る INIT/SIPI で起動して
/// 自分の APIC ID（1）を PIO で出す。(a) 作成直後の MP 状態、(b) setup_boot_vcpu 後の AP の LINT（BSP と同じ値）、
/// (c) 起動コードの配置先、(d) BSP が INIT/SIPI を送った印（port 0x10 に 0xAA）、(f) AP の出力を具体値で照合する。
/// INIT 後の AP の LINT は quirk と版に依るため照合しない。AP は INIT/SIPI を送る前には実行しない（UNINITIALIZED の
/// `KVM_RUN` は期限まで戻らないため）。
#[cfg(target_arch = "x86_64")]
#[test]
#[ignore = "requires read/write access to /dev/kvm (MVM-1)"]
fn kvm_device_ap_starts_on_init_sipi() {
    use fandhe_container_microvm::exit::{IoDirection, VcpuExit};
    use fandhe_container_microvm::guest_memory::GuestAddress;
    use fandhe_container_microvm::lapic_x86::LvtDeliveryMode;
    use fandhe_container_microvm::microvm::{MicroVm, MicroVmConfig};
    use fandhe_container_microvm::smp_x86::{MpState, SipiVector};
    use fandhe_container_microvm::virtio_block::MemoryBlockBackend;
    use fandhe_container_microvm::virtio_net::MemoryNetBackend;
    use std::sync::mpsc;
    use std::time::Duration;

    let dev = open_kvm();

    // BSP（long mode）: ICR_HIGH に宛先 APIC ID 1、ICR_LOW に INIT（assert）と SIPI（ベクタ 1）を書き、port 0x10 へ 0xAA。
    let bsp: Vec<u8> = vec![
        0xBF, 0x10, 0x03, 0xE0, 0xFE, // mov edi,0xFEE00310
        0xC7, 0x07, 0x00, 0x00, 0x00, 0x01, // mov dword [rdi],0x01000000
        0xBF, 0x00, 0x03, 0xE0, 0xFE, // mov edi,0xFEE00300
        0xC7, 0x07, 0x00, 0x45, 0x00, 0x00, // mov dword [rdi],0x00004500 (INIT)
        0xC7, 0x07, 0x01, 0x46, 0x00, 0x00, // mov dword [rdi],0x00004601 (SIPI, vector 1)
        0xB0, 0xAA, 0xE6, 0x10, // mov al,0xAA ; out 0x10,al
        0xEB, 0xFE, // jmp $
    ];
    // 合成 bzImage（正本 support/bzimage.rs の synthetic_bzimage。BSP のコードを 64-bit エントリへ置く）。
    let img = bzimage::synthetic_bzimage(&bsp);
    // AP（real mode・CS=0x0100・IP=0）: CPUID.1 の EBX[31:24]（初期 APIC ID）を port 0x11 へ出す。
    let ap: Vec<u8> = vec![
        0x66, 0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax,1
        0x0F, 0xA2, // cpuid
        0x66, 0xC1, 0xEB, 0x18, // shr ebx,24
        0x88, 0xD8, // mov al,bl
        0xE6, 0x11, // out 0x11,al
        0xEB, 0xFE, // jmp $
    ];

    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut vm: MicroVm<MemoryBlockBackend, MemoryNetBackend> = MicroVm::assemble(
            &dev,
            MicroVmConfig {
                vcpu_count: 2,
                mem_size: 64 << 20,
                block: vec![],
                net: vec![],
            },
        )
        .unwrap();
        // (a) 作成直後の MP 状態。
        let created = (
            vm.vcpus()[0].mp_state().unwrap(),
            vm.vcpus()[1].mp_state().unwrap(),
        );
        let loaded = vm.load_kernel(&img, None, "console=ttyS0").unwrap();
        vm.setup_boot_vcpu(&loaded).unwrap();
        // (b) AP の LINT は BSP と同じ値で、INIT 前なので MP 状態は UNINITIALIZED のまま。
        let bsp_lints = vm.vcpus()[0].lapic_lints().unwrap();
        let ap_lints = vm.vcpus()[1].lapic_lints().unwrap();
        let ap_state_before = vm.vcpus()[1].mp_state().unwrap();
        // (c) 起動コードの配置。
        let placed = vm
            .write_ap_startup_code(SipiVector::new(0x01).unwrap(), &ap)
            .unwrap();
        // (d) BSP が INIT/SIPI を送る。
        let mut bsp_exit = None;
        while bsp_exit.is_none() {
            match vm
                .vcpu_mut(0)
                .unwrap()
                .run_once(Duration::from_secs(10))
                .unwrap()
            {
                VcpuExit::Interrupted => continue,
                e => bsp_exit = Some(e),
            }
        }
        // (f) AP の出力。
        let mut ap_exit = None;
        while ap_exit.is_none() {
            match vm
                .vcpu_mut(1)
                .unwrap()
                .run_once(Duration::from_secs(10))
                .unwrap()
            {
                VcpuExit::Interrupted => continue,
                e => ap_exit = Some(e),
            }
        }
        let _ = tx.send((
            created,
            bsp_lints,
            ap_lints,
            ap_state_before,
            placed,
            bsp_exit.unwrap(),
            ap_exit.unwrap(),
        ));
    });
    let (created, bsp_lints, ap_lints, ap_state_before, placed, bsp_exit, ap_exit) = rx
        .recv_timeout(Duration::from_secs(60))
        .expect("guest did not finish within 60s");

    assert_eq!(created, (MpState::Runnable, MpState::Uninitialized));
    assert_eq!(ap_lints, bsp_lints);
    assert_eq!(ap_lints.lint1, 0x0000_0400);
    assert_eq!(ap_lints.lint0_mode(), LvtDeliveryMode::ExtInt);
    assert!(!ap_lints.lint0_masked());
    assert_eq!(ap_state_before, MpState::Uninitialized);
    assert_eq!(placed, GuestAddress::new(0x1000));
    let out = |port: u16, v: u8| VcpuExit::Io {
        direction: IoDirection::Out,
        port,
        size: 1,
        count: 1,
        data: vec![v],
    };
    assert_eq!(bsp_exit, out(0x10, 0xAA));
    assert_eq!(ap_exit, out(0x11, 1));
}

/// MVM-1・#3737: x86_64 以外では AP の起動も組み立てが先に `Unimplemented` で失敗する。
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
#[test]
#[ignore = "requires read/write access to /dev/kvm (MVM-1)"]
fn kvm_device_ap_starts_on_init_sipi() {
    use fandhe_container_microvm::microvm::{MicroVm, MicroVmConfig};
    use fandhe_container_microvm::virtio_block::MemoryBlockBackend;
    use fandhe_container_microvm::virtio_net::MemoryNetBackend;

    let dev = open_kvm();
    let config: MicroVmConfig<MemoryBlockBackend, MemoryNetBackend> = MicroVmConfig {
        vcpu_count: 2,
        mem_size: 1 << 20,
        block: vec![],
        net: vec![],
    };
    assert_eq!(
        MicroVm::assemble(&dev, config).unwrap_err().code(),
        MicrovmErrorCode::Unimplemented
    );
}

/// MVM-1・TASK-75.4.1・#886: `MicroVm::start` / `RunningMicroVm::stop`。(a) 自己ループするゲストを停止要求で止め、
/// (b) ud2（#UD → 未設定の IDT でトリプルフォールト）のゲストはゲスト起因の終了として報告され、(c) vCPU 2 台でも BSP の
/// ゲスト起因の終了が全台を止め、きっかけの vCPU 番号（0）と台数（2）が報告されて両 vCPU の資源が解放される（#3738）。
/// 資源の解放は、観測器 `Arc` の参照数が 1 に戻ること（`VcpuFd`、つまり `MicroVm` 全体が drop 済み）で決定的に確かめる
/// （`/proc/self/fd` の件数は他の試験の並列スレッドで揺れるため使わない）。
#[cfg(target_arch = "x86_64")]
#[test]
#[ignore = "requires read/write access to /dev/kvm (MVM-1)"]
fn kvm_device_start_stop_microvm() {
    use fandhe_container_microvm::device::{RunObserver, RunRecord};
    use fandhe_container_microvm::microvm::{MicroVm, MicroVmConfig, StopReason};
    use fandhe_container_microvm::virtio_block::MemoryBlockBackend;
    use fandhe_container_microvm::virtio_net::MemoryNetBackend;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Duration, Instant};

    #[derive(Debug, Default)]
    struct Count(AtomicU64);
    impl RunObserver for Count {
        fn record(&self, _record: &RunRecord) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    let dev = open_kvm();
    let image = |entry_code: &[u8]| bzimage::synthetic_bzimage(entry_code);
    let assemble = |vcpu_count: u32| -> MicroVm<MemoryBlockBackend, MemoryNetBackend> {
        MicroVm::assemble(
            &dev,
            MicroVmConfig {
                vcpu_count,
                mem_size: 64 << 20,
                block: vec![],
                net: vec![],
            },
        )
        .unwrap()
    };
    let wait = |limit: Duration, mut cond: Box<dyn FnMut() -> bool + '_>| {
        let end = Instant::now() + limit;
        while Instant::now() < end {
            if cond() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        cond()
    };

    // (a) jmp $ のゲスト: 実行中に停止要求で止まる。
    let img = image(&[0xEB, 0xFE]);
    let mut vm = assemble(1);
    let loaded = vm.load_kernel(&img, None, "console=ttyS0").unwrap();
    let obs = Arc::new(Count::default());
    vm.vcpu_mut(0).unwrap().set_observer(obs.clone());
    let running = vm.start(&loaded).unwrap();
    assert!(wait(
        Duration::from_secs(10),
        Box::new(|| obs.0.load(Ordering::SeqCst) >= 1)
    ));
    let t = Instant::now();
    let report = running.stop(Duration::from_secs(5)).unwrap();
    assert_eq!(report.reason, StopReason::Requested);
    assert!(report.stats.runs >= 1);
    assert_eq!(report.stats.errors, 0);
    assert!(t.elapsed() < Duration::from_secs(2), "{:?}", t.elapsed());
    assert_eq!(Arc::strong_count(&obs), 1);

    // (b) エントリが ud2 のゲスト: ゲスト起因で終わり、stop がその理由を返す。
    let img = image(&[]);
    let mut vm = assemble(1);
    let loaded = vm.load_kernel(&img, None, "console=ttyS0").unwrap();
    let obs = Arc::new(Count::default());
    vm.vcpu_mut(0).unwrap().set_observer(obs.clone());
    let running = vm.start(&loaded).unwrap();
    assert!(wait(
        Duration::from_secs(10),
        Box::new(|| running.is_finished())
    ));
    let report = running.stop(Duration::from_secs(5)).unwrap();
    assert_eq!(report.reason, StopReason::GuestShutdown);
    assert_eq!(Arc::strong_count(&obs), 1);

    // (c) vCPU 2 台（#3738）: BSP の ud2 によるゲスト起因の終了が全台を止める。AP は UNINITIALIZED のまま
    // `KVM_RUN` の中にいて、kick で止まる。両 vCPU の観測器の参照数が 1 に戻る（全台の解放済み）まで確かめる。
    let mut vm = assemble(2);
    let loaded = vm.load_kernel(&img, None, "console=ttyS0").unwrap();
    let obs0 = Arc::new(Count::default());
    let obs1 = Arc::new(Count::default());
    vm.vcpu_mut(0).unwrap().set_observer(obs0.clone());
    vm.vcpu_mut(1).unwrap().set_observer(obs1.clone());
    let running = vm.start(&loaded).unwrap();
    assert!(wait(
        Duration::from_secs(10),
        Box::new(|| running.is_finished())
    ));
    let report = running.stop(Duration::from_secs(5)).unwrap();
    assert_eq!(report.reason, StopReason::GuestShutdown);
    assert_eq!(report.origin_vcpu, Some(0));
    assert_eq!(report.vcpu_count, 2);
    assert_eq!(Arc::strong_count(&obs0), 1);
    assert_eq!(Arc::strong_count(&obs1), 1);
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
#[test]
#[ignore = "requires read/write access to /dev/kvm (MVM-1)"]
fn kvm_device_start_stop_microvm() {
    use fandhe_container_microvm::microvm::{MicroVm, MicroVmConfig};
    use fandhe_container_microvm::virtio_block::MemoryBlockBackend;
    use fandhe_container_microvm::virtio_net::MemoryNetBackend;

    let dev = open_kvm();
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

/// MVM-1・REPAIR-5・#3738: vCPU 2 台の `start` で AP が自分のスレッドで INIT/SIPI により起動し、COM1 の THR へ自分の
/// APIC ID（1）を出す。ホストは `SerialConsole` の累積が `[0x01]` と完全一致するのを期限つきで待つ。`stop` は両スレッドを回収し
/// （観測器の参照数が 1 に戻る）、観測器の記録に vcpu_id 1 の `KVM_RUN` がある。続けて、BSP が INIT/SIPI を送らず AP が
/// UNINITIALIZED のまま `KVM_RUN` に居る状態でも、`stop` が kick で期限内（2 秒未満）に戻ることを確かめる。
#[cfg(target_arch = "x86_64")]
#[test]
#[ignore = "requires read/write access to /dev/kvm (MVM-1)"]
fn kvm_device_start_two_vcpus_runs_ap_and_stops() {
    use fandhe_container_microvm::device::{RunObserver, RunRecord};
    use fandhe_container_microvm::microvm::{MicroVm, MicroVmConfig, StopReason};
    use fandhe_container_microvm::smp_x86::SipiVector;
    use fandhe_container_microvm::virtio_block::MemoryBlockBackend;
    use fandhe_container_microvm::virtio_net::MemoryNetBackend;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    #[derive(Debug, Default)]
    struct Ids {
        total: AtomicU64,
        ids: Mutex<Vec<u32>>,
    }
    impl RunObserver for Ids {
        fn record(&self, record: &RunRecord) {
            self.total.fetch_add(1, Ordering::SeqCst);
            if let Ok(mut v) = self.ids.lock()
                && !v.contains(&record.vcpu_id)
            {
                v.push(record.vcpu_id);
            }
        }
    }

    let dev = open_kvm();
    let image = |entry_code: &[u8]| bzimage::synthetic_bzimage(entry_code);
    let assemble = || -> MicroVm<MemoryBlockBackend, MemoryNetBackend> {
        MicroVm::assemble(
            &dev,
            MicroVmConfig {
                vcpu_count: 2,
                mem_size: 64 << 20,
                block: vec![],
                net: vec![],
            },
        )
        .unwrap()
    };
    let wait = |limit: Duration, mut cond: Box<dyn FnMut() -> bool + '_>| {
        let end = Instant::now() + limit;
        while Instant::now() < end {
            if cond() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        cond()
    };

    // (a) BSP が INIT/SIPI を送り、AP が COM1 へ APIC ID を出す。
    let bsp_sipi: Vec<u8> = vec![
        0xBF, 0x10, 0x03, 0xE0, 0xFE, // mov edi,0xFEE00310
        0xC7, 0x07, 0x00, 0x00, 0x00, 0x01, // mov dword [rdi],0x01000000
        0xBF, 0x00, 0x03, 0xE0, 0xFE, // mov edi,0xFEE00300
        0xC7, 0x07, 0x00, 0x45, 0x00, 0x00, // mov dword [rdi],0x00004500 (INIT)
        0xC7, 0x07, 0x01, 0x46, 0x00, 0x00, // mov dword [rdi],0x00004601 (SIPI, vector 1)
        0xEB, 0xFE, // jmp $
    ];
    let ap: Vec<u8> = vec![
        0x66, 0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax,1
        0x0F, 0xA2, // cpuid
        0x66, 0xC1, 0xEB, 0x18, // shr ebx,24
        0x88, 0xD8, // mov al,bl
        0xBA, 0xF8, 0x03, // mov dx,0x3F8
        0xEE, // out dx,al
        0xEB, 0xFE, // jmp $
    ];
    let mut vm = assemble();
    let loaded = vm
        .load_kernel(&image(&bsp_sipi), None, "console=ttyS0")
        .unwrap();
    vm.write_ap_startup_code(SipiVector::new(0x01).unwrap(), &ap)
        .unwrap();
    let obs0 = Arc::new(Ids::default());
    let obs1 = Arc::new(Ids::default());
    vm.vcpu_mut(0).unwrap().set_observer(obs0.clone());
    vm.vcpu_mut(1).unwrap().set_observer(obs1.clone());
    let console = vm.serial_console();
    let running = vm.start(&loaded).unwrap();
    let mut seen: Vec<u8> = Vec::new();
    let arrived = wait(
        Duration::from_secs(10),
        Box::new(|| {
            seen.extend(console.take_output().unwrap());
            seen.as_slice() == [0x01]
        }),
    );
    assert!(arrived, "AP output was {seen:?}, expected [1]");
    let t = Instant::now();
    let report = running.stop(Duration::from_secs(5)).unwrap();
    assert!(t.elapsed() < Duration::from_secs(2), "{:?}", t.elapsed());
    assert_eq!(report.reason, StopReason::Requested);
    assert_eq!(report.vcpu_count, 2);
    assert_eq!(report.origin_vcpu, None);
    assert_eq!(report.stats.errors, 0);
    assert_eq!(Arc::strong_count(&obs0), 1);
    assert_eq!(Arc::strong_count(&obs1), 1);
    assert!(obs1.ids.lock().unwrap().contains(&1));
    assert!(obs1.total.load(Ordering::SeqCst) >= 1);
    assert!(obs0.ids.lock().unwrap().contains(&0));

    // (b) SIPI の前の停止: AP は UNINITIALIZED のまま `KVM_RUN` に居て、kick で止まる。
    let mut vm = assemble();
    let loaded = vm
        .load_kernel(&image(&[0xEB, 0xFE]), None, "console=ttyS0")
        .unwrap();
    let obs0 = Arc::new(Ids::default());
    let obs1 = Arc::new(Ids::default());
    vm.vcpu_mut(0).unwrap().set_observer(obs0.clone());
    vm.vcpu_mut(1).unwrap().set_observer(obs1.clone());
    let running = vm.start(&loaded).unwrap();
    assert!(wait(
        Duration::from_secs(10),
        Box::new(|| obs0.total.load(Ordering::SeqCst) >= 1)
    ));
    let t = Instant::now();
    let report = running.stop(Duration::from_secs(5)).unwrap();
    assert!(t.elapsed() < Duration::from_secs(2), "{:?}", t.elapsed());
    assert_eq!(report.reason, StopReason::Requested);
    assert_eq!(report.vcpu_count, 2);
    assert_eq!(Arc::strong_count(&obs0), 1);
    assert_eq!(Arc::strong_count(&obs1), 1);
}

/// MVM-1・#3738: x86_64 以外では組み立てが先に `Unimplemented` で失敗する。
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
#[test]
#[ignore = "requires read/write access to /dev/kvm (MVM-1)"]
fn kvm_device_start_two_vcpus_runs_ap_and_stops() {
    use fandhe_container_microvm::microvm::{MicroVm, MicroVmConfig};
    use fandhe_container_microvm::virtio_block::MemoryBlockBackend;
    use fandhe_container_microvm::virtio_net::MemoryNetBackend;

    let dev = open_kvm();
    let config: MicroVmConfig<MemoryBlockBackend, MemoryNetBackend> = MicroVmConfig {
        vcpu_count: 2,
        mem_size: 1 << 20,
        block: vec![],
        net: vec![],
    };
    assert_eq!(
        MicroVm::assemble(&dev, config).unwrap_err().code(),
        MicrovmErrorCode::Unimplemented
    );
}

/// MVM-1・TASK-75.5・#3740: ゲストが COM1（0x3f8）の THR へ書いた固定文字列を、ホストが `SerialConsole` から
/// 完全一致で取り出せる。ゲストは LSR（0x3fd）の THRE を確かめてから 1 文字ずつ OUT し、ud2 で終わる。
/// 停止（`RunningMicroVm::stop` は自身を消費）の後でも、事前に clone したハンドルから出力が欠けず取り出せる。
#[cfg(target_arch = "x86_64")]
#[test]
#[ignore = "requires read/write access to /dev/kvm (MVM-1)"]
fn kvm_device_serial_output_reaches_host() {
    use fandhe_container_microvm::microvm::{MicroVm, MicroVmConfig, StopReason};
    use fandhe_container_microvm::virtio_block::MemoryBlockBackend;
    use fandhe_container_microvm::virtio_net::MemoryNetBackend;
    use std::time::{Duration, Instant};

    const MSG: &[u8] = b"fandhe-microvm-uart-ok\r\n";

    let dev = open_kvm();
    // mov dx,0x3fd; in al,dx; test al,0x20; jz ud2; mov dx,0x3f8; (mov al,c; out dx,al)*; ud2
    let mut code: Vec<u8> = vec![0x66, 0xBA, 0xFD, 0x03, 0xEC, 0xA8, 0x20];
    let skip = 4 + 3 * MSG.len();
    assert!(skip <= 127);
    code.extend_from_slice(&[0x74, skip as u8]);
    code.extend_from_slice(&[0x66, 0xBA, 0xF8, 0x03]);
    for c in MSG {
        code.extend_from_slice(&[0xB0, *c, 0xEE]);
    }
    code.extend_from_slice(&[0x0F, 0x0B]);

    let mut img = bzimage::header_only();
    bzimage::put_entry_code(&mut img, &code);

    let mut vm: MicroVm<MemoryBlockBackend, MemoryNetBackend> = MicroVm::assemble(
        &dev,
        MicroVmConfig {
            vcpu_count: 1,
            mem_size: 64 << 20,
            block: vec![],
            net: vec![],
        },
    )
    .unwrap();
    let loaded = vm.load_kernel(&img, None, "console=ttyS0").unwrap();
    let console = vm.serial_console();
    let running = vm.start(&loaded).unwrap();
    let end = Instant::now() + Duration::from_secs(10);
    while !running.is_finished() && Instant::now() < end {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(running.is_finished());
    let stats = running.serial_console().stats().unwrap();
    assert_eq!(stats.written_bytes, MSG.len() as u64);
    assert_eq!(stats.dropped_bytes, 0);
    assert_eq!(stats.loopback_discarded, 0);
    let report = running.stop(Duration::from_secs(5)).unwrap();
    assert_eq!(report.reason, StopReason::GuestShutdown);
    assert_eq!(console.take_output().unwrap(), MSG);
    assert!(console.take_output().unwrap().is_empty());
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
#[test]
#[ignore = "requires read/write access to /dev/kvm (MVM-1)"]
fn kvm_device_serial_output_reaches_host() {
    use fandhe_container_microvm::microvm::{MicroVm, MicroVmConfig};
    use fandhe_container_microvm::virtio_block::MemoryBlockBackend;
    use fandhe_container_microvm::virtio_net::MemoryNetBackend;

    let dev = open_kvm();
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

/// COM1（IRQ 4）の割り込みが IOAPIC pin 4 経由でゲストへ届くことの合成ゲストを組む（#3918）。
/// IDT はホストが GPA `IDT_BASE` に置く（vector 0x30 の 64-bit 割り込みゲート）。ゲストは lidt → PIC 全マスク
/// （GSI 4 は PIC にも入り、BSP の LINT0 は ExtINT で解除済みのため、マスクしないと vector 4 で届く）→ LAPIC SVR の
/// software enable → IOAPIC pin 4 を vector 0x30・fixed・edge・active high・unmask・宛先 APIC ID 0 にする
/// （Linux と MP テーブルと同じ経路で pin 4 の routing まで確かめる）→ IER に `ier` を書き → sti → hlt ループ。
/// handler は IIR を読み（線が下がる）、IER = 0 にして IIR の値を THR へ出し、LSR.DR なら RBR も THR へ出して ud2 で終わる。
/// 戻り値は (エントリのコード, handler のエントリからの offset)。
#[cfg(target_arch = "x86_64")]
fn com1_irq_guest_code(ier: u8, idtr_gpa: u32) -> (Vec<u8>, usize) {
    let mut c: Vec<u8> = Vec::new();
    // mov eax, idtr_gpa; lidt [rax]
    c.push(0xB8);
    c.extend_from_slice(&idtr_gpa.to_le_bytes());
    c.extend_from_slice(&[0x0F, 0x01, 0x18]);
    // mov al,0xFF; out 0x21,al; out 0xA1,al
    c.extend_from_slice(&[0xB0, 0xFF, 0xE6, 0x21, 0xE6, 0xA1]);
    // mov edi,0xFEE000F0; mov dword [rdi],0x1FF
    c.extend_from_slice(&[
        0xBF, 0xF0, 0x00, 0xE0, 0xFE, 0xC7, 0x07, 0xFF, 0x01, 0x00, 0x00,
    ]);
    // mov edi,0xFEC00000 (IOREGSEL。IOWIN は +0x10)
    c.extend_from_slice(&[0xBF, 0x00, 0x00, 0xC0, 0xFE]);
    // redirection entry の上位（index 0x19）= 0（宛先 APIC ID 0）
    c.extend_from_slice(&[0xC7, 0x07, 0x19, 0x00, 0x00, 0x00]);
    c.extend_from_slice(&[0xC7, 0x47, 0x10, 0x00, 0x00, 0x00, 0x00]);
    // 下位（index 0x18）= vector 0x30・fixed・edge・active high・unmask
    c.extend_from_slice(&[0xC7, 0x07, 0x18, 0x00, 0x00, 0x00]);
    c.extend_from_slice(&[0xC7, 0x47, 0x10, 0x30, 0x00, 0x00, 0x00]);
    // mov dx,0x3F9; mov al,ier; out dx,al; sti; L: hlt; jmp L
    c.extend_from_slice(&[
        0x66, 0xBA, 0xF9, 0x03, 0xB0, ier, 0xEE, 0xFB, 0xF4, 0xEB, 0xFD,
    ]);
    let handler = c.len();
    c.extend_from_slice(&[
        0x66, 0xBA, 0xFA, 0x03, // mov dx,0x3FA
        0xEC, // in al,dx (IIR)
        0x88, 0xC3, // mov bl,al
        0x66, 0xBA, 0xF9, 0x03, // mov dx,0x3F9
        0x30, 0xC0, // xor al,al
        0xEE, // out dx,al (IER = 0)
        0x66, 0xBA, 0xF8, 0x03, // mov dx,0x3F8
        0x88, 0xD8, // mov al,bl
        0xEE, // out dx,al (THR <- IIR)
        0x66, 0xBA, 0xFD, 0x03, // mov dx,0x3FD
        0xEC, // in al,dx (LSR)
        0xA8, 0x01, // test al,1
        0x74, 0x06, // jz ud2
        0x66, 0xBA, 0xF8, 0x03, // mov dx,0x3F8
        0xEC, // in al,dx (RBR)
        0xEE, // out dx,al (THR <- RBR)
        0x0F, 0x0B, // ud2
    ]);
    (c, handler)
}

/// `com1_irq_guest_code` のゲストを 1 回走らせる。`push` があれば、ゲストが hlt で寝た頃にホストのスレッドから
/// `push_input` する（別スレッドの `KVM_IRQ_LINE` で寝ているゲストを起こす経路）。`expect_irq` が偽なら割り込みが来ない
/// 負の対照で、期限（300 ms）内に終わらないことと `Requested` での停止を返す。
/// 戻り値は (出力, 停止理由, irq_line_errors)。
#[cfg(target_arch = "x86_64")]
fn run_com1_irq_scenario(
    ier: u8,
    push: Option<&[u8]>,
    expect_irq: bool,
) -> (Vec<u8>, fandhe_container_microvm::microvm::StopReason, u64) {
    use fandhe_container_microvm::guest_memory::GuestAddress;
    use fandhe_container_microvm::microvm::{MicroVm, MicroVmConfig};
    use fandhe_container_microvm::virtio_block::MemoryBlockBackend;
    use fandhe_container_microvm::virtio_net::MemoryNetBackend;
    use std::time::{Duration, Instant};

    /// ブート配置（0x0100_0000 台・0x0200_0000 台）と重ならない IDT の置き場。
    const IDT_BASE: u64 = 0x0300_0000;
    const IDTR_GPA: u64 = IDT_BASE + 0x1000;
    const VECTOR: u64 = 0x30;
    const BOOT_CS_SELECTOR: u16 = 0x10;

    let dev = open_kvm();
    let (code, handler) = com1_irq_guest_code(ier, IDTR_GPA as u32);
    let mut img = bzimage::header_only();
    bzimage::put_entry_code(&mut img, &code);

    let mut vm: MicroVm<MemoryBlockBackend, MemoryNetBackend> = MicroVm::assemble(
        &dev,
        MicroVmConfig {
            vcpu_count: 1,
            mem_size: 64 << 20,
            block: vec![],
            net: vec![],
        },
    )
    .unwrap();
    let loaded = vm.load_kernel(&img, None, "console=ttyS0").unwrap();
    {
        let handler_addr = bzimage::EXPECTED_ENTRY + handler as u64;
        let mut gate = [0u8; 16];
        gate[0..2].copy_from_slice(&((handler_addr & 0xFFFF) as u16).to_le_bytes());
        gate[2..4].copy_from_slice(&BOOT_CS_SELECTOR.to_le_bytes());
        gate[5] = 0x8E; // present・DPL 0・64-bit interrupt gate
        gate[6..8].copy_from_slice(&(((handler_addr >> 16) & 0xFFFF) as u16).to_le_bytes());
        gate[8..12].copy_from_slice(&((handler_addr >> 32) as u32).to_le_bytes());
        let mut idtr = [0u8; 10];
        idtr[0..2].copy_from_slice(&((VECTOR as u16) * 16 + 15).to_le_bytes());
        idtr[2..10].copy_from_slice(&IDT_BASE.to_le_bytes());
        let mem = vm.memory_mut();
        mem.write_at(GuestAddress::new(IDT_BASE + VECTOR * 16), &gate)
            .unwrap();
        mem.write_at(GuestAddress::new(IDTR_GPA), &idtr).unwrap();
    }
    let console = vm.serial_console();
    let running = vm.start(&loaded).unwrap();
    if let Some(data) = push {
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(console.push_input(data).unwrap().accepted, data.len());
    }
    if expect_irq {
        let end = Instant::now() + Duration::from_secs(10);
        while !running.is_finished() && Instant::now() < end {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(running.is_finished(), "guest did not receive IRQ 4");
    } else {
        std::thread::sleep(Duration::from_millis(300));
        assert!(!running.is_finished(), "unexpected IRQ 4 reached the guest");
    }
    let errors = console.stats().unwrap().irq_line_errors;
    let report = running.stop(Duration::from_secs(5)).unwrap();
    (console.take_output().unwrap(), report.reason, errors)
}

/// MVM-1・MVM-5・REPAIR-3・#3918: COM1（IRQ 4）の UART の割り込み線が `KVM_IRQ_LINE` で IOAPIC pin 4 へ届き、
/// ゲストが vector 0x30 の handler で IIR を読む。(a) IER = ETBEI（THRE）→ 出力 `[0x02]`、(b) IER = ERBFI で寝ている
/// ゲストへホストが `push_input` → `[0x04, b'k']`、(c) IER = 0 では届かない（負の対照）。いずれも `irq_line_errors == 0`。
/// 実機での実行と記録は #3781（人間担当）。
#[cfg(target_arch = "x86_64")]
#[test]
#[ignore = "requires read/write access to /dev/kvm (MVM-1)"]
fn kvm_device_com1_irq4_reaches_guest() {
    use fandhe_container_microvm::microvm::StopReason;

    let (out, reason, errors) = run_com1_irq_scenario(0x02, None, true);
    assert_eq!(out, vec![0x02], "THRE scenario");
    assert_eq!(reason, StopReason::GuestShutdown);
    assert_eq!(errors, 0);

    let (out, reason, errors) = run_com1_irq_scenario(0x01, Some(b"k"), true);
    assert_eq!(out, vec![0x04, b'k'], "RDA scenario");
    assert_eq!(reason, StopReason::GuestShutdown);
    assert_eq!(errors, 0);

    let (out, reason, errors) = run_com1_irq_scenario(0x00, None, false);
    assert!(out.is_empty(), "negative control");
    assert_eq!(reason, StopReason::Requested);
    assert_eq!(errors, 0);
}

/// #3918 の試験用: x86_64 以外では組み立てが先に `Unimplemented` で失敗する（aarch64 の線は #3696・#3898）。
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
#[test]
#[ignore = "requires read/write access to /dev/kvm (MVM-1)"]
fn kvm_device_com1_irq4_reaches_guest() {
    assert_unimplemented_assemble();
}

/// MVM-1・REPAIR-5・TASK-75.4・#3736: 自己ループするゲスト（`jmp $`）に対し、`RunningMicroVm::stop` が
/// `VCPU_POLL_INTERVAL`（100ms）のポーリングを待たず、`StopSignal` の kick で即時に戻る。
/// 停止要求は run の開始直後に揃えるため、ポーリング方式なら毎回約 90ms 待ち 50ms 未満にならず、kick を外すと必ず失敗する。
#[cfg(target_arch = "x86_64")]
#[test]
#[ignore = "requires read/write access to /dev/kvm (MVM-1)"]
fn kvm_device_stop_kicks_spinning_guest_immediately() {
    use fandhe_container_microvm::device::{RunObserver, RunRecord};
    use fandhe_container_microvm::microvm::{
        MicroVm, MicroVmConfig, StopReason, VCPU_POLL_INTERVAL,
    };
    use fandhe_container_microvm::virtio_block::MemoryBlockBackend;
    use fandhe_container_microvm::virtio_net::MemoryNetBackend;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Duration, Instant};

    #[derive(Debug, Default)]
    struct Count(AtomicU64);
    impl RunObserver for Count {
        fn record(&self, _record: &RunRecord) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    let dev = open_kvm();
    let img = bzimage::synthetic_bzimage(&[0xEB, 0xFE]);

    for attempt in 0..5 {
        let mut vm: MicroVm<MemoryBlockBackend, MemoryNetBackend> = MicroVm::assemble(
            &dev,
            MicroVmConfig {
                vcpu_count: 1,
                mem_size: 64 << 20,
                block: vec![],
                net: vec![],
            },
        )
        .unwrap();
        let loaded = vm.load_kernel(&img, None, "console=ttyS0").unwrap();
        let obs = Arc::new(Count::default());
        vm.vcpu_mut(0).unwrap().set_observer(obs.clone());
        let running = vm.start(&loaded).unwrap();
        let end = Instant::now() + Duration::from_secs(10);
        while obs.0.load(Ordering::SeqCst) < 1 && Instant::now() < end {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(obs.0.load(Ordering::SeqCst) >= 1);
        // 観測器の通知は 1 回の run が戻った直後（次の run の開始直前）に来る。そこから短い固定
        // 待ちだけ置いて停止を要求し、次の run の先頭付近（ポーリング方式なら残り約 90ms）に揃える。
        std::thread::sleep(Duration::from_millis(5 + attempt));
        let t = Instant::now();
        let report = running.stop(Duration::from_secs(5)).unwrap();
        let elapsed = t.elapsed();
        assert!(
            elapsed < VCPU_POLL_INTERVAL / 2,
            "attempt {attempt}: stop took {elapsed:?}"
        );
        assert_eq!(report.reason, StopReason::Requested);
        assert_eq!(report.stats.errors, 0);
        assert_eq!(Arc::strong_count(&obs), 1);
    }
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
#[test]
#[ignore = "requires read/write access to /dev/kvm (MVM-1)"]
fn kvm_device_stop_kicks_spinning_guest_immediately() {
    use fandhe_container_microvm::microvm::{MicroVm, MicroVmConfig};
    use fandhe_container_microvm::virtio_block::MemoryBlockBackend;
    use fandhe_container_microvm::virtio_net::MemoryNetBackend;

    let dev = open_kvm();
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

/// MVM-1・REPAIR-5・#3742・#3743: virtio-net 1 台の構成の `start` が成功し、`start` の後に backend へ積んだフレームが、
/// ゲストの kick（QueueNotify を含む MMIO）なしに受信ポーラー（`microvm-net-rx`）で受信バッファへ届く。
/// `start` の後はホストからゲストメモリを読めないため、ゲスト自身に used ring と受信バッファを読ませて COM1 へ出させ、
/// 完全一致で照合する。ドライバの初期化（DRIVER_OK・キュー 0/1 の ready）はホスト側が `start` の前に行い、ゲストは
/// MMIO を一切出さない（記録に MMIO の exit が 0 件）。後半はフレームを積まない負の対照で、出力が空のまま `stop` が
/// 期限内に `Requested` で戻り、net-rx スレッドを含めて backend と観測器の参照が解放される。
#[cfg(target_arch = "x86_64")]
#[test]
#[ignore = "requires read/write access to /dev/kvm (MVM-1)"]
fn kvm_device_net_rx_reaches_guest_without_kick() {
    use fandhe_container_microvm::device::{BoundedRunLog, ValueCapture};
    use fandhe_container_microvm::error::MicrovmError;
    use fandhe_container_microvm::exit::{ExitValue, IoDirection};
    use fandhe_container_microvm::guest_memory::GuestAddress;
    use fandhe_container_microvm::microvm::{MicroVm, MicroVmConfig, NetDeviceConfig, StopReason};
    use fandhe_container_microvm::virtio_block::MemoryBlockBackend;
    use fandhe_container_microvm::virtio_mmio::{DeviceStatus, reg};
    use fandhe_container_microvm::virtio_net::NetBackend;
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    /// `start` の後にフレームを積むため、試験側にも共有ハンドルを残す backend。
    #[derive(Debug, Clone, Default)]
    struct SharedNetBackend {
        inbound: Arc<Mutex<VecDeque<Vec<u8>>>>,
    }
    impl NetBackend for SharedNetBackend {
        fn send(&mut self, _frame: &[u8]) -> Result<(), MicrovmError> {
            Ok(())
        }
        fn recv(&mut self, buf: &mut [u8]) -> Result<Option<usize>, MicrovmError> {
            let mut q = self.inbound.lock().unwrap();
            let Some(frame) = q.front() else {
                return Ok(None);
            };
            let dst = buf.get_mut(..frame.len()).expect("rx buffer large enough");
            dst.copy_from_slice(frame);
            let n = frame.len();
            q.pop_front();
            Ok(Some(n))
        }
    }

    // 64 MiB の VM の内側。ブート用の配置（zero page 0x7000・テーブル 0xF000 未満・cmdline 0x20000・bzImage 0x100000）と重ならない。
    const RX_DESC: u64 = 0x0200_0000;
    const RX_AVAIL: u64 = 0x0200_1000;
    const RX_USED: u64 = 0x0200_2000;
    const TX_DESC: u64 = 0x0200_3000;
    const TX_AVAIL: u64 = 0x0200_4000;
    const TX_USED: u64 = 0x0200_5000;
    const RX_BUF: u64 = 0x0201_0000;
    const FRAME_LEN: usize = 60;
    const NET_HDR_LEN: usize = 12;
    const SENTINEL: usize = 4;
    const USED_HEAD: usize = 10; // used.idx(2) + used 要素 0 の id(4) + len(4)

    /// poll: used.idx が 0 の間 `pause` で待つ → used 先頭とバッファを COM1 へ 1 バイトずつ出力 → ud2。
    fn guest_code() -> Vec<u8> {
        let mut c: Vec<u8> = vec![0x0F, 0xB7, 0x04, 0x25]; // movzx eax, word [disp32]
        c.extend_from_slice(&((RX_USED + 2) as u32).to_le_bytes());
        c.extend_from_slice(&[0x85, 0xC0]); // test eax, eax
        c.extend_from_slice(&[0x75, 0x04]); // jnz out（pause + jmp の 4 バイトを飛ばす）
        c.extend_from_slice(&[0xF3, 0x90]); // pause
        let back = -(i32::try_from(c.len()).unwrap() + 2);
        assert!(back >= -128);
        c.extend_from_slice(&[0xEB, back as i8 as u8]); // jmp poll
        let out = |c: &mut Vec<u8>, src: u32, n: u32| {
            c.push(0xBE);
            c.extend_from_slice(&src.to_le_bytes()); // mov esi, src
            c.push(0xB9);
            c.extend_from_slice(&n.to_le_bytes()); // mov ecx, n
            c.extend_from_slice(&[0x66, 0xBA, 0xF8, 0x03]); // mov dx, 0x3f8
            c.extend_from_slice(&[0xAC, 0xEE, 0xE2, 0xFC]); // l: lodsb; out dx, al; loop l
        };
        out(&mut c, (RX_USED + 2) as u32, USED_HEAD as u32);
        out(
            &mut c,
            RX_BUF as u32,
            (NET_HDR_LEN + FRAME_LEN + SENTINEL) as u32,
        );
        c.extend_from_slice(&[0x0F, 0x0B]); // ud2
        c
    }

    let dev = open_kvm();

    // 準備: ゲストコードのロード → 受信バッファ・記述子・avail → ホスト側のドライバ初期化 → 観測器。
    let build = |backend: &SharedNetBackend| {
        let mut img = bzimage::header_only();
        bzimage::put_entry_code(&mut img, &guest_code());
        let mut vm: MicroVm<MemoryBlockBackend, SharedNetBackend> = MicroVm::assemble(
            &dev,
            MicroVmConfig {
                vcpu_count: 1,
                mem_size: 64 << 20,
                block: vec![],
                net: vec![NetDeviceConfig {
                    backend: backend.clone(),
                    mac: [2, 0, 0, 0, 0, 1],
                }],
            },
        )
        .unwrap();
        let loaded = vm.load_kernel(&img, None, "console=ttyS0").unwrap();
        let ga = GuestAddress::new;
        {
            let mem = vm.memory_mut();
            mem.write_at(ga(RX_BUF), &[0xEE; 2048]).unwrap();
            mem.write_at(ga(RX_DESC), &RX_BUF.to_le_bytes()).unwrap();
            mem.write_u32_le(ga(RX_DESC + 8), 2048).unwrap();
            mem.write_u16_le(ga(RX_DESC + 12), 2).unwrap(); // WRITE
            mem.write_u16_le(ga(RX_DESC + 14), 0).unwrap();
            mem.write_u16_le(ga(RX_AVAIL), 0).unwrap();
            mem.write_u16_le(ga(RX_AVAIL + 4), 0).unwrap();
            mem.write_u16_le(ga(RX_AVAIL + 2), 1).unwrap();
        }
        vm.with_net(0, |t| {
            let mut wr = |off: u64, v: u32| t.write(off, &v.to_le_bytes());
            wr(reg::STATUS, 1);
            wr(reg::STATUS, 3);
            wr(reg::DRIVER_FEATURES_SEL, 0);
            wr(reg::DRIVER_FEATURES, 1 << 5); // MAC
            wr(reg::DRIVER_FEATURES_SEL, 1);
            wr(reg::DRIVER_FEATURES, 1); // VERSION_1
            wr(reg::STATUS, 11);
            for (q, d, a, u) in [
                (0, RX_DESC, RX_AVAIL, RX_USED),
                (1, TX_DESC, TX_AVAIL, TX_USED),
            ] {
                wr(reg::QUEUE_SEL, q);
                wr(reg::QUEUE_NUM, 16);
                wr(reg::QUEUE_DESC_LOW, d as u32);
                wr(reg::QUEUE_DRIVER_LOW, a as u32);
                wr(reg::QUEUE_DEVICE_LOW, u as u32);
                wr(reg::QUEUE_READY, 1);
            }
            wr(reg::STATUS, 15);
            assert!(t.status().contains(DeviceStatus::DRIVER_OK));
        })
        .unwrap();
        let log = Arc::new(BoundedRunLog::new(1024, ValueCapture::Record).unwrap());
        vm.vcpu_mut(0).unwrap().set_observer(log.clone());
        (vm, loaded, log)
    };
    let wait = |limit: Duration, mut cond: Box<dyn FnMut() -> bool + '_>| {
        let end = Instant::now() + limit;
        while !cond() && Instant::now() < end {
            std::thread::sleep(Duration::from_millis(5));
        }
        cond()
    };

    // 本体: start の後にフレームを積み、kick なしで届く。
    let backend = SharedNetBackend::default();
    let (vm, loaded, log) = build(&backend);
    let running = vm.start(&loaded).unwrap();
    assert!(wait(
        Duration::from_secs(10),
        Box::new(|| !log.records().is_empty())
    ));
    assert_eq!(running.serial_console().stats().unwrap().written_bytes, 0);
    let frame: Vec<u8> = (0..FRAME_LEN).map(|i| ((i + 7) % 241) as u8).collect();
    backend.inbound.lock().unwrap().push_back(frame.clone());
    assert!(wait(
        Duration::from_secs(10),
        Box::new(|| running.is_finished())
    ));
    let console = running.serial_console();
    let report = running.stop(Duration::from_secs(5)).unwrap();
    assert_eq!(report.reason, StopReason::GuestShutdown);
    assert_eq!(report.origin_vcpu, Some(0));
    assert_eq!(report.vcpu_count, 1);
    assert_eq!(report.stats.errors, 0);

    let mut expected: Vec<u8> = vec![1, 0]; // used.idx
    expected.extend_from_slice(&0u32.to_le_bytes()); // used[0].id
    expected.extend_from_slice(&((NET_HDR_LEN + FRAME_LEN) as u32).to_le_bytes()); // used[0].len
    expected.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0]); // virtio_net_hdr（num_buffers = 1）
    expected.extend_from_slice(&frame);
    expected.extend_from_slice(&[0xEE; SENTINEL]);
    assert_eq!(console.take_output().unwrap(), expected);
    assert!(backend.inbound.lock().unwrap().is_empty());

    // ゲストの kick なし: MMIO の exit が 0 件で、PIO は port 0x3f8 への 1 バイトの OUT だけ（10 + 76 = 86 件）。
    assert_eq!(log.dropped(), 0);
    let values: Vec<ExitValue> = log.records().iter().filter_map(|r| r.value).collect();
    assert!(
        values.iter().all(|v| matches!(
            v,
            ExitValue::Pio {
                direction: IoDirection::Out,
                port: 0x3f8,
                size: 1,
                ..
            }
        )),
        "{values:?}"
    );
    assert_eq!(values.len(), USED_HEAD + NET_HDR_LEN + FRAME_LEN + SENTINEL);
    assert_eq!(Arc::strong_count(&log), 1);
    assert_eq!(Arc::strong_count(&backend.inbound), 1);

    // 負の対照: フレームなしなら出力は空のまま、stop が期限内に Requested で戻り、net-rx スレッドを含めて解放される。
    let backend = SharedNetBackend::default();
    let (vm, loaded, log) = build(&backend);
    let running = vm.start(&loaded).unwrap();
    std::thread::sleep(Duration::from_millis(200));
    assert!(!running.is_finished());
    assert_eq!(running.serial_console().stats().unwrap().written_bytes, 0);
    let t0 = Instant::now();
    let report = running.stop(Duration::from_secs(5)).unwrap();
    assert!(t0.elapsed() < Duration::from_secs(2), "{:?}", t0.elapsed());
    assert_eq!(report.reason, StopReason::Requested);
    assert_eq!(Arc::strong_count(&log), 1);
    assert_eq!(Arc::strong_count(&backend.inbound), 1);
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
#[test]
#[ignore = "requires read/write access to /dev/kvm (MVM-1)"]
fn kvm_device_net_rx_reaches_guest_without_kick() {
    assert_unimplemented_assemble();
}

/// MVM-1・TASK-75.4.2・#887: 起動の途中で失敗しても fd・mmap が解放され、エラーは ERR-1 の形（`<CODE>: <message>`）で返る。
/// net を含む構成の起動途中の失敗（解放）と、net を含む構成の `start` の成功と停止も確認する（#3743）。
#[cfg(target_arch = "x86_64")]
#[test]
#[ignore = "requires read/write access to /dev/kvm (MVM-1)"]
fn kvm_device_start_failure_releases_resources() {
    use fandhe_container_microvm::device::{RunObserver, RunRecord};
    use fandhe_container_microvm::microvm::{MicroVm, MicroVmConfig};
    use fandhe_container_microvm::virtio_block::MemoryBlockBackend;
    use fandhe_container_microvm::virtio_net::MemoryNetBackend;
    use std::sync::Arc;

    #[derive(Debug, Default)]
    struct Nop;
    impl RunObserver for Nop {
        fn record(&self, _record: &RunRecord) {}
    }

    type Vm = MicroVm<MemoryBlockBackend, MemoryNetBackend>;

    let dev = open_kvm();
    let image = bzimage::header_only();
    let assemble = |mem_size: u64, net: usize| -> Vm {
        MicroVm::assemble(
            &dev,
            MicroVmConfig {
                vcpu_count: 1,
                mem_size,
                block: vec![],
                net: (0..net)
                    .map(|_| fandhe_container_microvm::microvm::NetDeviceConfig {
                        backend: MemoryNetBackend::new(),
                        mac: [2, 0, 0, 0, 0, 1],
                    })
                    .collect(),
            },
        )
        .unwrap()
    };

    // (a) setup_boot_vcpu の失敗: 大きいメモリでロードした結果を、小さいメモリの VM の start に渡す。
    let mut big = assemble(64 << 20, 0);
    let loaded = big.load_kernel(&image, None, "console=ttyS0").unwrap();
    let mut small = assemble(2 << 20, 0);
    let obs = Arc::new(Nop);
    small.vcpu_mut(0).unwrap().set_observer(obs.clone());
    let e = small.start(&loaded).unwrap_err();
    assert_eq!(e.code(), MicrovmErrorCode::InvalidArgument);
    assert!(e.to_string().starts_with("INVALID_ARGUMENT: "), "{e}");
    assert_eq!(Arc::strong_count(&obs), 1);

    // (b1) net を含む構成でも、起動途中の失敗（小さいメモリ）で解放される。
    let mut small = assemble(2 << 20, 1);
    let obs = Arc::new(Nop);
    small.vcpu_mut(0).unwrap().set_observer(obs.clone());
    let e = small.start(&loaded).unwrap_err();
    assert_eq!(e.code(), MicrovmErrorCode::InvalidArgument);
    assert!(e.to_string().starts_with("INVALID_ARGUMENT: "), "{e}");
    assert_eq!(Arc::strong_count(&obs), 1);

    // (b2) net を含む構成の start は Unimplemented ではなく成功し、停止で解放される（#3743）。
    let spin = bzimage::synthetic_bzimage(&[0xEB, 0xFE]);
    let mut vm = assemble(64 << 20, 1);
    let loaded = vm.load_kernel(&spin, None, "console=ttyS0").unwrap();
    let obs = Arc::new(Nop);
    vm.vcpu_mut(0).unwrap().set_observer(obs.clone());
    let running = vm.start(&loaded).unwrap();
    let report = running.stop(std::time::Duration::from_secs(5)).unwrap();
    assert_eq!(
        report.reason,
        fandhe_container_microvm::microvm::StopReason::Requested
    );
    assert_eq!(Arc::strong_count(&obs), 1);

    // (c) load_kernel に不正なイメージを渡すと InvalidArgument。MicroVm は残り、drop で解放される。
    let mut vm = assemble(64 << 20, 0);
    let obs = Arc::new(Nop);
    vm.vcpu_mut(0).unwrap().set_observer(obs.clone());
    let e = vm.load_kernel(&[0u8; 16], None, "").unwrap_err();
    assert_eq!(e.code(), MicrovmErrorCode::InvalidArgument);
    assert!(e.to_string().starts_with("INVALID_ARGUMENT: "), "{e}");
    assert_eq!(Arc::strong_count(&obs), 2);
    drop(vm);
    assert_eq!(Arc::strong_count(&obs), 1);

    // (d) assemble の ioctl 前の失敗。
    let bad = |vcpu_count: u32, mem_size: u64| {
        MicroVm::<MemoryBlockBackend, MemoryNetBackend>::assemble(
            &dev,
            MicroVmConfig {
                vcpu_count,
                mem_size,
                block: vec![],
                net: vec![],
            },
        )
        .expect_err("must fail")
    };
    let e = bad(0, 1 << 20);
    assert!(e.to_string().starts_with("INVALID_ARGUMENT: "), "{e}");
    let e = bad(1, u64::MAX / 2);
    assert!(e.to_string().starts_with("INVALID_ARGUMENT: "), "{e}");

    // (e) open_at の失敗: メッセージにパスを載せない。
    let missing = std::path::Path::new("/nonexistent/fandhe-kvm-887");
    let e = KvmDevice::open_at(missing).unwrap_err();
    assert_eq!(e.code(), MicrovmErrorCode::NotFound);
    assert!(!e.message().contains("fandhe-kvm-887"), "{e}");
    let e = KvmDevice::open_at(std::path::Path::new("/dev/null")).unwrap_err();
    assert_eq!(e.code(), MicrovmErrorCode::FailedPrecondition);
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
#[test]
#[ignore = "requires read/write access to /dev/kvm (MVM-1)"]
fn kvm_device_start_failure_releases_resources() {
    let e = KvmDevice::open_at(std::path::Path::new("/nonexistent/fandhe-kvm-887")).unwrap_err();
    assert_eq!(e.code(), MicrovmErrorCode::NotFound);
    assert!(e.to_string().starts_with("NOT_FOUND: "), "{e}");
}

/// MVM-1・#3734: `KVM_SET_FPU` の設定経路が効くこと（番兵の FCW の読み戻し）と、`setup_boot_vcpu` 後の FPU が
/// fcw = 0x37F・fsw = 0・ftwx = 0 であること（`KVM_GET_FPU` の読み戻し）。
///
/// MXCSR は照合しない: 実測（Linux 7.0.0-34-generic・2026-11-03）で `KVM_GET_FPU` の mxcsr は、新規 vCPU でも
/// `KVM_SET_FPU` で 0x1F80 を書いた後でも 0 を返し（fcw は往復する）、読み戻しでは設定値を観測できなかった。
/// 設定自体は行う（`X86FpuState::boot()` に含む）。MXCSR の観測は `KVM_GET_XSAVE` かゲストの `stmxcsr`（CPUID の設定が前提）で
/// 後続に行う（REPAIR-3）。
#[cfg(target_arch = "x86_64")]
#[test]
#[ignore = "requires read/write access to /dev/kvm (MVM-1)"]
fn kvm_device_boot_fpu_reads_back() {
    use fandhe_container_microvm::boot_x86::X86FpuState;
    use fandhe_container_microvm::microvm::{MicroVm, MicroVmConfig};
    use fandhe_container_microvm::virtio_block::MemoryBlockBackend;
    use fandhe_container_microvm::virtio_net::MemoryNetBackend;

    let dev = open_kvm();
    let img = bzimage::synthetic_bzimage(&[0x0F, 0x0B]);
    let mut vm: MicroVm<MemoryBlockBackend, MemoryNetBackend> = MicroVm::assemble(
        &dev,
        MicroVmConfig {
            vcpu_count: 1,
            mem_size: 64 << 20,
            block: vec![],
            net: vec![],
        },
    )
    .unwrap();
    let loaded = vm.load_kernel(&img, None, "console=ttyS0").unwrap();
    // 番兵: 設定経路が実際に値を変えること（既定値のままでも通る試験にしない）。
    let mut sentinel = X86FpuState::boot();
    sentinel.fcw = 0x027F;
    {
        let vcpu = vm.vcpu_mut(0).unwrap();
        vcpu.set_fpu(&sentinel).unwrap();
        assert_eq!(vcpu.fpu().unwrap().fcw, 0x027F);
    }
    vm.setup_boot_vcpu(&loaded).unwrap();
    let f = vm.vcpu_mut(0).unwrap().fpu().unwrap();
    assert_eq!((f.fcw, f.fsw, f.ftwx), (0x37F, 0, 0));
    assert_eq!((f.last_opcode, f.last_ip, f.last_dp), (0, 0, 0));
}

/// MVM-1・#3734: `setup_boot_vcpu` 後の `KVM_GET_MSRS` の読み戻しが `boot_msrs()` と一致し（TSC は進むため上限つき）、
/// ゲストが RDMSR した IA32_MISC_ENABLE と、ホストが上書きした STAR が設定値どおり見える。
#[cfg(target_arch = "x86_64")]
#[test]
#[ignore = "requires read/write access to /dev/kvm (MVM-1)"]
fn kvm_device_boot_msrs_read_back_and_guest_rdmsr() {
    use fandhe_container_microvm::boot_x86::{MSR_STAR, X86MsrEntry, boot_msrs};
    use fandhe_container_microvm::exit::{IoDirection, VcpuExit};
    use fandhe_container_microvm::microvm::{MicroVm, MicroVmConfig};
    use fandhe_container_microvm::virtio_block::MemoryBlockBackend;
    use fandhe_container_microvm::virtio_net::MemoryNetBackend;
    use std::sync::mpsc;
    use std::time::Duration;

    let dev = open_kvm();
    // mov ecx,0x1A0 ; rdmsr ; out 0x10,eax ; mov eax,edx ; out 0x10,eax
    // mov ecx,0xC0000081 ; rdmsr ; out 0x10,eax ; mov eax,edx ; out 0x10,eax
    let code: Vec<u8> = vec![
        0xB9, 0xA0, 0x01, 0x00, 0x00, 0x0F, 0x32, 0xE7, 0x10, 0x89, 0xD0, 0xE7, 0x10, 0xB9, 0x81,
        0x00, 0x00, 0xC0, 0x0F, 0x32, 0xE7, 0x10, 0x89, 0xD0, 0xE7, 0x10,
    ];
    let img = bzimage::synthetic_bzimage(&code);

    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut vm: MicroVm<MemoryBlockBackend, MemoryNetBackend> = MicroVm::assemble(
            &dev,
            MicroVmConfig {
                vcpu_count: 1,
                mem_size: 64 << 20,
                block: vec![],
                net: vec![],
            },
        )
        .unwrap();
        let loaded = vm.load_kernel(&img, None, "console=ttyS0").unwrap();
        vm.setup_boot_vcpu(&loaded).unwrap();
        let vcpu = vm.vcpu_mut(0).unwrap();

        // 設定直後の読み戻し。TSC は時間とともに進むため、0 から十分小さい上限（< 2^40）で照合する。
        let table = boot_msrs();
        let indices: Vec<u32> = table.iter().map(|e| e.index).collect();
        let got = vcpu.msrs(&indices).unwrap();
        assert_eq!(got.len(), table.len());
        for (g, want) in got.iter().zip(table.iter()) {
            assert_eq!(g.index, want.index);
            if g.index == 0x10 {
                assert!(g.data < (1u64 << 40), "tsc {:#x}", g.data);
            } else {
                assert_eq!(g, want, "msr {:#x}", g.index);
            }
        }

        // STAR を上位・下位で別の値に上書きし、読み戻しとゲストの RDMSR の両方で確かめる。
        let star = 0x0023_0010_1234_5678u64;
        vcpu.set_msrs(&[X86MsrEntry::new(MSR_STAR, star)]).unwrap();
        assert_eq!(
            vcpu.msrs(&[MSR_STAR]).unwrap(),
            vec![X86MsrEntry::new(MSR_STAR, star)]
        );

        let mut outs = Vec::new();
        for _ in 0..4 {
            let exit = loop {
                match vcpu.run_once(Duration::from_secs(10)).unwrap() {
                    VcpuExit::Interrupted => continue,
                    e => break e,
                }
            };
            outs.push(exit);
        }
        let _ = tx.send(outs);
    });
    let outs = rx
        .recv_timeout(Duration::from_secs(60))
        .expect("boot vCPU did not finish within 60s");
    let out = |v: u32| VcpuExit::Io {
        direction: IoDirection::Out,
        port: 0x10,
        size: 4,
        count: 1,
        data: v.to_le_bytes().to_vec(),
    };
    // IA32_MISC_ENABLE（下位 0x1801・上位 0）と STAR（下位 0x1234_5678・上位 0x0023_0010）。
    assert_eq!(
        outs,
        vec![out(0x1801), out(0), out(0x1234_5678), out(0x0023_0010)]
    );
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
#[test]
#[ignore = "requires read/write access to /dev/kvm (MVM-1)"]
fn kvm_device_boot_fpu_reads_back() {
    assert_unimplemented_assemble();
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
#[test]
#[ignore = "requires read/write access to /dev/kvm (MVM-1)"]
fn kvm_device_boot_msrs_read_back_and_guest_rdmsr() {
    assert_unimplemented_assemble();
}

/// #3734 の試験用: x86_64 以外では組み立てが先に `Unimplemented` で失敗する。
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
fn assert_unimplemented_assemble() {
    use fandhe_container_microvm::microvm::{MicroVm, MicroVmConfig};
    use fandhe_container_microvm::virtio_block::MemoryBlockBackend;
    use fandhe_container_microvm::virtio_net::MemoryNetBackend;

    let dev = open_kvm();
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

// ---- aarch64（KVM）の vGIC・irqfd・組み立て・起動レジスタ（MVM-1・#3696）-------------------------------------
//
// ネイティブ arm64 の CI が無いため `--ignored` の実機前提試験として置く（型検査は cross-target-check の
// aarch64-unknown-linux-gnu）。実行手順は AGENTS.md「実機前提テスト」の `kvm_device` の項。

/// 合成 arm64 Image の正本（aarch64 の実機前提試験だけが使う。複製しない）。
#[cfg(target_arch = "aarch64")]
#[path = "support/arm64_image.rs"]
mod arm64_image;

/// 最小 FDT パーサの正本（`tests/arm64_layout.rs` と共有。FDT の `cpu@N` の `reg` を読む。#3899）。
#[cfg(target_arch = "aarch64")]
#[path = "support/fdt_parse.rs"]
mod fdt_parse;

#[cfg(target_arch = "aarch64")]
mod arm64 {
    use super::arm64_image::{
        BOOT_CHECK_CODE, image_with_code, synthetic_image, synthetic_image_with_code,
    };
    use super::*;
    use fandhe_container_microvm::arm64_layout::{
        ARM64_GIC_DIST_BASE, ARM64_GIC_REDIST_BASE, ARM64_RAM_BASE,
    };
    use fandhe_container_microvm::boot_arm64::ARM64_BOOT_CPSR;
    use fandhe_container_microvm::interrupt::InterruptLine as _;
    use fandhe_container_microvm::microvm::{MicroVm, MicroVmConfig, NetDeviceConfig, StopReason};
    use fandhe_container_microvm::virtio_block::MemoryBlockBackend;
    use fandhe_container_microvm::virtio_net::MemoryNetBackend;
    use std::time::{Duration, Instant};

    type Vm = MicroVm<MemoryBlockBackend, MemoryNetBackend>;

    fn open() -> KvmDevice {
        super::open_kvm()
    }

    fn config(
        vcpus: u32,
        block: usize,
        net: usize,
    ) -> MicroVmConfig<MemoryBlockBackend, MemoryNetBackend> {
        MicroVmConfig {
            vcpu_count: vcpus,
            mem_size: 64 << 20,
            block: (0..block)
                .map(|_| MemoryBlockBackend::new(16 * 512, false).unwrap())
                .collect(),
            net: (0..net)
                .map(|_| NetDeviceConfig {
                    backend: MemoryNetBackend::new(),
                    mac: [2, 0, 0, 0, 0, 1],
                })
                .collect(),
        }
    }

    /// 組み立てに失敗したら、環境を示すコードだけ前提欠如にする（#3992）。
    fn assemble_config(cfg: MicroVmConfig<MemoryBlockBackend, MemoryNetBackend>) -> Vm {
        MicroVm::assemble(&open(), cfg).unwrap_or_else(|e| {
            panic!(
                "{}",
                super::kvm_precondition::assemble_failure_line("kvm_device", &e)
            )
        })
    }

    fn assemble(block: usize, net: usize) -> Vm {
        assemble_config(config(1, block, net))
    }

    fn wait_until(limit: Duration, mut cond: impl FnMut() -> bool) -> bool {
        let end = Instant::now() + limit;
        while Instant::now() < end {
            if cond() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        cond()
    }

    /// MVM-1・#3696: vGICv3 が作られ、distributor・redistributor の GPA が `Arm64Layout` の値で読み戻せ、
    /// virtio の割り込みは SPI 16 から連番（gsi = SPI 番号）になる。
    #[test]
    #[ignore = "requires read/write access to /dev/kvm on an aarch64 host with a GICv3 (MVM-1)"]
    fn kvm_device_arm64_vgic_assemble() {
        let vm = assemble(1, 1);
        assert_eq!(vm.vgic().dist_base().unwrap(), ARM64_GIC_DIST_BASE);
        assert_eq!(vm.vgic().redist_base().unwrap(), ARM64_GIC_REDIST_BASE);
        let devs = vm.devices();
        assert_eq!(devs.len(), 2);
        assert_eq!(devs[0].slot.mmio_base, 0x0a00_0000);
        assert_eq!(devs[0].slot.gsi, 16);
        assert_eq!(devs[1].slot.mmio_base, 0x0a00_0200);
        assert_eq!(devs[1].slot.gsi, 17);
        assert_eq!(vm.memory().base().raw(), ARM64_RAM_BASE);
        // 未発火の SPI は pending でない。
        assert!(!vm.vgic().spi_pending(48).unwrap());
    }

    /// MVM-1・#3696: vGIC の初期化前の irqfd は `FailedPrecondition`（EAGAIN）で拒否され、初期化後は通る
    /// （順序の根拠は `device` のモジュール doc。構成 API は公開せず診断口 `probe_irqfd_vgic_order` を使う）。
    #[test]
    #[ignore = "requires read/write access to /dev/kvm on an aarch64 host with a GICv3 (MVM-1)"]
    fn kvm_device_arm64_irqfd_requires_initialized_vgic() {
        let p = open().probe_irqfd_vgic_order().unwrap();
        assert_eq!(
            p.before_init,
            Some((
                MicrovmErrorCode::FailedPrecondition,
                "KVM_IRQFD requires an initialized interrupt controller (vGIC)".to_string()
            ))
        );
        assert!(p.after_init_ok);
    }

    /// MVM-1・#3696: gsi 16 の irqfd を発火すると INTID 48（= 16 + 32）だけが pending になる（GSI と SPI の写像）。
    /// 注入は eventfd のワーカー経由で非同期のため、期限つきで待つ。
    #[test]
    #[ignore = "requires read/write access to /dev/kvm on an aarch64 host with a GICv3 (MVM-1)"]
    fn kvm_device_arm64_irqfd_sets_spi_pending() {
        let vm = assemble(1, 1);
        let extra = vm.vm().register_irqfd(16).unwrap();
        extra.trigger().unwrap();
        assert!(
            wait_until(Duration::from_secs(1), || vm
                .vgic()
                .spi_pending(48)
                .unwrap_or(false)),
            "SPI 16 (INTID 48) did not become pending"
        );
        assert!(
            !vm.vgic().spi_pending(49).unwrap(),
            "INTID 49 must stay clear"
        );
    }

    /// MVM-1・#3943: シリアルの SPI（INTID 33）を `KVM_IRQ_LINE` の level 線で High にすると INTID 33 だけが pending になる
    /// （線の `irq` は SPI のエンコード済みの値。GSI と INTID の取り違えがないことの照合）。vGIC の初期化前の線は拒否される。
    /// 注入は同期だが、実装に依らないよう期限つきで待つ。Low にしたときの pending の扱いは SPI の config（edge / level）に
    /// よるためここでは assert しない。
    #[test]
    #[ignore = "requires read/write access to /dev/kvm on an aarch64 host with a GICv3 (MVM-1)"]
    fn kvm_device_arm64_serial_irq_line_sets_spi_pending() {
        use fandhe_container_microvm::interrupt::{IrqLevel, LevelInterruptLine as _};
        let vm = assemble(1, 1);
        assert!(!vm.vgic().spi_pending(33).unwrap());
        let line = vm.vm().register_spi_line(33).unwrap();
        // 範囲外の INTID（SGI / PPI / 特殊 INTID）は InvalidArgument で拒否される。
        for bad in [31u32, 1020] {
            assert_eq!(
                vm.vm().register_spi_line(bad).unwrap_err().code(),
                MicrovmErrorCode::InvalidArgument
            );
        }
        line.set_level(IrqLevel::High).unwrap();
        assert!(
            wait_until(Duration::from_secs(1), || vm
                .vgic()
                .spi_pending(33)
                .unwrap_or(false)),
            "SPI 1 (INTID 33) did not become pending"
        );
        assert!(
            !vm.vgic().spi_pending(34).unwrap(),
            "INTID 34 must stay clear"
        );
    }

    /// FDT（`loaded` の範囲）をゲストメモリから読み、`/cpus/cpu@<hex>` の `reg` の第 2 セル（affinity）を返す。
    fn fdt_cpu_reg(
        vm: &Vm,
        fdt: fandhe_container_microvm::arm64_layout::MmioRegion,
        node: &str,
    ) -> u32 {
        use fandhe_container_microvm::guest_memory::GuestAddress;
        let mut blob = vec![0u8; fdt.size as usize];
        vm.memory()
            .read_at(GuestAddress::new(fdt.base.raw()), &mut blob)
            .unwrap();
        let p = super::fdt_parse::parse(&blob);
        let cells = p.cells(&format!("/cpus/{node}"), "reg");
        assert_eq!(cells.len(), 1, "{cells:?}");
        cells[0]
    }

    /// MVM-1・#3899: AP の `MPIDR_EL1`（KVM の reset 値）の affinity が FDT の `cpu@N` の `reg` と一致する。
    /// 2 台構成の vCPU 1 は 1、17 台構成の vCPU 16 は 0x100（番号 16 以上）。生の値は #3781 の記録用に出力する。
    #[test]
    #[ignore = "requires read/write access to /dev/kvm on an aarch64 host with a GICv3 and KVM_CAP_ARM_PSCI_0_2 (MVM-1)"]
    fn kvm_device_arm64_smp_ap_mpidr_matches_fdt() {
        use fandhe_container_microvm::boot_arm64::ARM64_MPIDR_AFFINITY_MASK;
        for (vcpus, idx, node, want) in [(2u32, 1usize, "cpu@1", 1u32), (17, 16, "cpu@100", 0x100)]
        {
            let mut vm = assemble_config(config(vcpus, 0, 0));
            let loaded = vm
                .load_kernel(&synthetic_image(true), None, "console=ttyS0")
                .unwrap();
            let fdt = fdt_cpu_reg(&vm, loaded.loaded().fdt, node);
            let raw = vm.vcpus()[idx].arm64_mpidr().unwrap();
            println!(
                "kvm_device: smp: mpidr vcpus={vcpus} vcpu={idx} raw={raw:#x} fdt_reg={fdt:#x}"
            );
            assert_eq!(raw & ARM64_MPIDR_AFFINITY_MASK, u64::from(fdt));
            assert_eq!(fdt, want);
            assert_ne!(raw & (1 << 31), 0, "bit 31 (RES1) must be set: {raw:#x}");
            let boot = vm.vcpus()[0].arm64_mpidr().unwrap();
            assert_eq!(boot & ARM64_MPIDR_AFFINITY_MASK, 0);
        }
    }

    /// MVM-1・REPAIR-5・#3899: 2 台構成で `b .` のゲストを start すると、電源 off の AP が `KVM_RUN` の中で眠っていても
    /// stop の kick で 2 台とも期限内に回収される。
    #[test]
    #[ignore = "requires read/write access to /dev/kvm on an aarch64 host with a GICv3 and KVM_CAP_ARM_PSCI_0_2 (MVM-1)"]
    fn kvm_device_arm64_smp_start_stop() {
        let mut vm = assemble_config(config(2, 0, 0));
        let loaded = vm
            .load_kernel(&synthetic_image(true), None, "console=ttyS0")
            .unwrap();
        let running = vm.start(&loaded).unwrap();
        std::thread::sleep(Duration::from_millis(100));
        assert!(!running.is_finished());
        let t = Instant::now();
        let report = running.stop(Duration::from_secs(5)).unwrap();
        assert_eq!(report.reason, StopReason::Requested);
        assert_eq!(report.vcpu_count, 2);
        assert_eq!(report.stats.errors, 0);
        assert!(report.stats.runs >= 1);
        assert!(t.elapsed() < Duration::from_secs(2), "{:?}", t.elapsed());
    }

    /// MVM-1・#3696: `load_kernel`（Image・FDT の配置）と `setup_boot_vcpu` の後、X0 = FDT・PC = Image の先頭・
    /// X1〜X3 = 0・PSTATE = EL1h（DAIF マスク）が読み戻せ、FDT の magic がゲストメモリにある。
    #[test]
    #[ignore = "requires read/write access to /dev/kvm on an aarch64 host with a GICv3 (MVM-1)"]
    fn kvm_device_arm64_boot_vcpu_regs() {
        use fandhe_container_microvm::guest_memory::GuestAddress;
        let mut vm = assemble(1, 0);
        let img = synthetic_image(true);
        let loaded = vm.load_kernel(&img, None, "console=ttyS0").unwrap();
        vm.setup_boot_vcpu(&loaded).unwrap();
        let regs = vm.vcpus()[0].arm64_boot_regs().unwrap();
        assert_eq!(regs.pc, ARM64_RAM_BASE + 0x8_0000);
        assert_eq!(regs.x0, loaded.loaded().fdt.base.raw());
        assert_eq!((regs.x1, regs.x2, regs.x3), (0, 0, 0));
        assert_eq!(regs.cpsr, ARM64_BOOT_CPSR);
        assert_eq!(regs.cpsr, 0x3c5);
        let mut magic = [0u8; 4];
        vm.memory()
            .read_at(GuestAddress::new(regs.x0), &mut magic)
            .unwrap();
        assert_eq!(magic, [0xd0, 0x0d, 0xfe, 0xed]);
    }

    /// MVM-1・REPAIR-5・#3696: 自分自身へ分岐するゲスト（`b .`）を `start` し、`stop` が期限内に `Requested` で
    /// 戻り、資源（vGIC・irqfd・vCPU・メモリ）が解放される。PSCI による終了は `kvm_device_arm64_psci_system_off_shuts_down`（#3896）。
    #[test]
    #[ignore = "requires read/write access to /dev/kvm on an aarch64 host with a GICv3 (MVM-1)"]
    fn kvm_device_arm64_start_stop() {
        let mut vm = assemble(1, 1);
        let img = synthetic_image(true);
        let loaded = vm.load_kernel(&img, None, "console=ttyS0").unwrap();
        let running = vm.start(&loaded).unwrap();
        std::thread::sleep(Duration::from_millis(100));
        assert!(!running.is_finished());
        let t = Instant::now();
        let report = running.stop(Duration::from_secs(5)).unwrap();
        assert_eq!(report.reason, StopReason::Requested);
        assert!(report.stats.runs >= 1);
        assert_eq!(report.stats.errors, 0);
        assert!(t.elapsed() < Duration::from_secs(2), "{:?}", t.elapsed());
    }

    /// MVM-1・MVM-4・#3896: PSCI 0.2 の SYSTEM_OFF（`hvc #0`、関数 ID `0x8400_0008`）を呼ぶゲストが
    /// `KVM_EXIT_SYSTEM_EVENT` 経由で `GuestShutdown` により停止する。負の対照は `kvm_device_arm64_start_stop`
    /// （`b .` のゲストは `Requested`）。必要環境に `KVM_CAP_ARM_PSCI_0_2` を持つホストを含む（無ければ `FailedPrecondition`）。
    #[test]
    #[ignore = "requires read/write access to /dev/kvm on an aarch64 host with a GICv3 and KVM_CAP_ARM_PSCI_0_2 (MVM-1)"]
    fn kvm_device_arm64_psci_system_off_shuts_down() {
        let mut vm = assemble(1, 1);
        // movz x0, #0x8400, lsl #16 / movk x0, #0x8 / hvc #0 / b .
        let img =
            synthetic_image_with_code(true, &[0xD2B0_8000, 0xF280_0100, 0xD400_0002, 0x1400_0000]);
        let loaded = vm.load_kernel(&img, None, "console=ttyS0").unwrap();
        let running = vm.start(&loaded).unwrap();
        assert!(wait_until(Duration::from_secs(5), || running.is_finished()));
        let report = running.stop(Duration::from_secs(5)).unwrap();
        assert_eq!(report.reason, StopReason::GuestShutdown);
        assert_eq!(report.stats.errors, 0);
    }

    /// 起動確認ゲスト（FDT の magic・virtio の MagicValue と DeviceID を確かめてから THR へ `OK\n`、続けて SYSTEM_OFF）を
    /// 走らせ、停止までの UART の出力と取りこぼし数・停止理由・errors を返す。`running` 側のハンドルの出力も同じバッファ。
    fn run_boot_check(block: usize) -> (Vec<u8>, u64, StopReason, u64) {
        let mut vm = assemble(block, 0);
        let serial = vm.serial_console();
        let img = image_with_code(&BOOT_CHECK_CODE);
        let loaded = vm.load_kernel(&img, None, "console=ttyS0").unwrap();
        let running = vm.start(&loaded).unwrap();
        let running_serial = running.serial_console();
        assert!(wait_until(Duration::from_secs(5), || running.is_finished()));
        let report = running.stop(Duration::from_secs(5)).unwrap();
        let from_running = running_serial.take_output().unwrap();
        let dropped = serial.stats().unwrap().dropped_bytes;
        // running 側で先に取り出したので、MicroVm 側のハンドルは空（同じバッファを指す証拠）。
        let leftover = serial.take_output().unwrap();
        assert!(leftover.is_empty(), "serial handles must share one buffer");
        (from_running, dropped, report.reason, report.stats.errors)
    }

    /// MVM-1・#3898: MMIO のシリアル（`0x0900_0000`）が結線され、合成ゲストの THR への書き込み `OK\n` が
    /// `serial_console().take_output()` で具体値のまま取り出せ、取りこぼしは 0。FDT の magic と virtio の MagicValue・
    /// DeviceID の検査を通ったときだけ出る。実カーネルでの確認は `kernel_boot`。
    #[test]
    #[ignore = "requires read/write access to /dev/kvm on an aarch64 host with a GICv3 and KVM_CAP_ARM_PSCI_0_2 (MVM-1)"]
    fn kvm_device_arm64_serial_boot_check_writes_thr() {
        let (out, dropped, reason, errors) = run_boot_check(1);
        assert_eq!(out, b"OK\n");
        assert_eq!(dropped, 0);
        assert_eq!(reason, StopReason::GuestShutdown);
        assert_eq!(errors, 0);
    }

    /// MVM-1・#3898: 負の対照。virtio を 0 台にすると窓が未登録（0xFF 埋め）で検査に失敗し、THR に何も書かずに
    /// SYSTEM_OFF する。出力が空であることで、上の `OK\n` がゲストの検査を経たものだと裏づける。
    #[test]
    #[ignore = "requires read/write access to /dev/kvm on an aarch64 host with a GICv3 and KVM_CAP_ARM_PSCI_0_2 (MVM-1)"]
    fn kvm_device_arm64_serial_boot_check_fails_without_block() {
        let (out, dropped, reason, errors) = run_boot_check(0);
        assert!(out.is_empty());
        assert_eq!(dropped, 0);
        assert_eq!(reason, StopReason::GuestShutdown);
        assert_eq!(errors, 0);
    }
}
