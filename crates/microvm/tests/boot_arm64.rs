//! arm64 の Image・initrd・FDT の配置と起動レジスタの値の結合試験（MVM-5・MVM-1。KVM 不要・OS 非依存・heap backing）。

use fandhe_container_microvm::arm64_layout::{
    ARM64_MAX_VCPUS, Arm64Layout, GuestFdtConfig, MmioRegion, build_guest_fdt,
};
use fandhe_container_microvm::boot_arm64::{
    ARM64_IMAGE_MAGIC, Arm64PageSize, ArmBootState, load_arm64,
};
use fandhe_container_microvm::boot_x86::MAX_KERNEL_IMAGE_BYTES;
use fandhe_container_microvm::error::MicrovmErrorCode;
use fandhe_container_microvm::guest_memory::{GuestAddress, GuestMemory, HeapBacking};

const RAM: u64 = 16 << 20;
const CMDLINE: &str = "console=hvc0 rdinit=/init";

fn image(len: usize, flags: u64) -> Vec<u8> {
    let mut v: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
    v[8..16].copy_from_slice(&0u64.to_le_bytes());
    v[16..24].copy_from_slice(&0x20_0000u64.to_le_bytes());
    v[24..32].copy_from_slice(&flags.to_le_bytes());
    v[56..60].copy_from_slice(&ARM64_IMAGE_MAGIC.to_le_bytes());
    v
}

fn mem(size: u64) -> GuestMemory<HeapBacking> {
    GuestMemory::new(
        GuestAddress::new(0x4000_0000),
        HeapBacking::new(size).unwrap(),
    )
    .unwrap()
}

fn read(m: &GuestMemory<HeapBacking>, addr: u64, len: usize) -> Vec<u8> {
    let mut b = vec![0u8; len];
    m.read_at(GuestAddress::new(addr), &mut b).unwrap();
    b
}

#[test]
fn mvm5_load_arm64_places_kernel_initrd_fdt_at_expected_gpas() {
    let layout = Arm64Layout::new(RAM, 1, 1).unwrap();
    let mut m = mem(RAM);
    let img = image(4096, 0b1010);
    let initrd: Vec<u8> = (0..1024).map(|i| (i * 7) as u8).collect();
    let (loaded, state) = load_arm64(&mut m, &img, Some(&initrd), CMDLINE, &layout).unwrap();

    assert_eq!(loaded.kernel, MmioRegion::new(0x4000_0000, 4096));
    assert_eq!(loaded.reserved_end, 0x4020_0000);
    let ir = MmioRegion::new(0x40C0_0000, 0x400);
    assert_eq!(loaded.initrd, Some(ir));
    assert_eq!(loaded.fdt.base.raw(), 0x40E0_0000);
    assert_eq!(loaded.header.page_size, Arm64PageSize::K4);
    assert!(loaded.header.placement_anywhere);
    assert!(!loaded.header.legacy);

    assert_eq!(read(&m, 0x4000_0000, 4096), img);
    assert_eq!(read(&m, 0x40C0_0000, 1024), initrd);
    let want = build_guest_fdt(&GuestFdtConfig {
        layout: &layout,
        bootargs: CMDLINE,
        initrd: Some(ir),
    })
    .unwrap();
    assert_eq!(read(&m, 0x40E0_0000, want.len()), want);
    assert_eq!(&want[..4], &0xd00d_feedu32.to_be_bytes());

    assert_eq!(
        state,
        ArmBootState {
            pc: 0x4000_0000,
            x0: 0x40E0_0000,
            x1: 0,
            x2: 0,
            x3: 0,
            cpsr: 0x3c5
        }
    );
}

#[test]
fn mvm5_load_arm64_without_initrd() {
    let layout = Arm64Layout::new(RAM, 1, 1).unwrap();
    let mut m = mem(RAM);
    let (loaded, state) = load_arm64(&mut m, &image(4096, 0b1010), None, CMDLINE, &layout).unwrap();
    assert_eq!(loaded.initrd, None);
    assert_eq!(loaded.fdt.base.raw(), 0x40E0_0000);
    assert_eq!(state.x0, 0x40E0_0000);
    let want = build_guest_fdt(&GuestFdtConfig {
        layout: &layout,
        bootargs: CMDLINE,
        initrd: None,
    })
    .unwrap();
    assert_eq!(read(&m, 0x40E0_0000, want.len()), want);
}

#[test]
fn mvm5_load_arm64_rejects_initrd_that_does_not_fit() {
    let layout = Arm64Layout::new(RAM, 1, 1).unwrap();
    let mut m = mem(RAM);
    let fit = vec![1u8; 12 << 20];
    let (loaded, _) = load_arm64(&mut m, &image(4096, 0), Some(&fit), CMDLINE, &layout).unwrap();
    assert_eq!(loaded.initrd.unwrap().base.raw(), 0x4020_0000);

    let mut m = mem(RAM);
    let big = vec![1u8; (12 << 20) + 1];
    let e = load_arm64(&mut m, &image(4096, 0), Some(&big), CMDLINE, &layout).unwrap_err();
    assert_eq!(e.code(), MicrovmErrorCode::InvalidArgument);
    assert!(read(&m, 0x4000_0000, RAM as usize).iter().all(|b| *b == 0));

    let small_layout = Arm64Layout::new(4 << 20, 1, 1).unwrap();
    let mut m = mem(4 << 20);
    let e = load_arm64(
        &mut m,
        &image(4096, 0),
        Some(&[1u8; 1024]),
        CMDLINE,
        &small_layout,
    )
    .unwrap_err();
    assert_eq!(e.code(), MicrovmErrorCode::InvalidArgument);
    assert!(read(&m, 0x4000_0000, 4 << 20).iter().all(|b| *b == 0));
}

#[test]
fn mvm5_load_arm64_rejects_bad_images() {
    let layout = Arm64Layout::new(RAM, 1, 1).unwrap();
    let mut bad_magic = image(4096, 0);
    bad_magic[56] ^= 0xff;
    let big_endian = image(4096, 1);
    let oversized = vec![0u8; MAX_KERNEL_IMAGE_BYTES as usize + 1];
    let short = vec![0u8; 63];
    for img in [bad_magic, big_endian, oversized, short] {
        let mut m = mem(RAM);
        let e = load_arm64(&mut m, &img, None, CMDLINE, &layout).unwrap_err();
        assert_eq!(e.code(), MicrovmErrorCode::InvalidArgument);
    }
}

#[test]
fn mvm5_load_arm64_rejects_memory_layout_mismatch() {
    let layout = Arm64Layout::new(RAM, 1, 1).unwrap();
    let mut wrong_len = mem(RAM - 0x1_0000);
    let e = load_arm64(&mut wrong_len, &image(4096, 0), None, CMDLINE, &layout).unwrap_err();
    assert_eq!(e.code(), MicrovmErrorCode::InvalidArgument);
    let mut wrong_base = GuestMemory::new(
        GuestAddress::new(0x4020_0000),
        HeapBacking::new(RAM).unwrap(),
    )
    .unwrap();
    let e = load_arm64(&mut wrong_base, &image(4096, 0), None, CMDLINE, &layout).unwrap_err();
    assert_eq!(e.code(), MicrovmErrorCode::InvalidArgument);
}

#[test]
fn mvm5_load_arm64_bootargs_and_vcpu_errors() {
    let layout = Arm64Layout::new(RAM, 1, 1).unwrap();
    let long = "a".repeat(2048);
    for cmd in [long.as_str(), "a\0b"] {
        let mut m = mem(RAM);
        let e = load_arm64(&mut m, &image(4096, 0), None, cmd, &layout).unwrap_err();
        assert_eq!(e.code(), MicrovmErrorCode::InvalidArgument);
    }
    let e = Arm64Layout::new(RAM, ARM64_MAX_VCPUS + 1, 1).unwrap_err();
    assert_eq!(e.code(), MicrovmErrorCode::InvalidArgument);
    // vCPU 2 は FDT 側で受理される（#3864。HVF のバックエンドは 1 vCPU のまま）。
    let smp = Arm64Layout::new(RAM, 2, 1).unwrap();
    let mut m = mem(RAM);
    let (loaded, _) = load_arm64(&mut m, &image(4096, 0), None, CMDLINE, &smp).unwrap();
    assert_eq!(
        read(&m, loaded.fdt.base.raw(), 4),
        0xd00d_feedu32.to_be_bytes()
    );
}
