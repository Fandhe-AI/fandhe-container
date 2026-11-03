//! `arm64_layout::build_guest_fdt` を公開 API だけで呼び、試験内の最小 FDT パーサで読み戻して具体値で照合する
//! 結合試験（#3788・MVM-5・MVM-1。KVM 不要・OS 非依存）。

use std::collections::HashMap;

use fandhe_container_microvm::arm64_layout::{
    Arm64Layout, GuestFdtConfig, MmioRegion, build_guest_fdt,
};
use fandhe_container_microvm::error::MicrovmErrorCode;
use fandhe_container_microvm::guest_memory::GuestAddress;

const MIB: u64 = 1024 * 1024;

fn be32(b: &[u8], off: usize) -> u32 {
    u32::from_be_bytes(b[off..off + 4].try_into().unwrap())
}

/// `(パス, プロパティ名) -> 値` と、存在するノードのパスの一覧。
struct Parsed {
    props: HashMap<(String, String), Vec<u8>>,
    nodes: Vec<String>,
}

fn parse(blob: &[u8]) -> Parsed {
    assert_eq!(be32(blob, 0), 0xd00d_feed);
    let off_struct = be32(blob, 8) as usize;
    let off_strings = be32(blob, 12) as usize;
    let mut pos = off_struct;
    let mut stack: Vec<String> = Vec::new();
    let mut props = HashMap::new();
    let mut nodes = Vec::new();
    loop {
        let tok = be32(blob, pos);
        pos += 4;
        match tok {
            1 => {
                let end = pos + blob[pos..].iter().position(|&c| c == 0).unwrap();
                let name = String::from_utf8(blob[pos..end].to_vec()).unwrap();
                pos = (end + 1 + 3) & !3;
                stack.push(name);
                let path = format!("/{}", stack[1..].join("/"));
                nodes.push(path);
            }
            2 => {
                stack.pop();
            }
            3 => {
                let len = be32(blob, pos) as usize;
                let nameoff = be32(blob, pos + 4) as usize;
                pos += 8;
                let v = blob[pos..pos + len].to_vec();
                pos = (pos + len + 3) & !3;
                let s = off_strings + nameoff;
                let e = s + blob[s..].iter().position(|&c| c == 0).unwrap();
                let name = String::from_utf8(blob[s..e].to_vec()).unwrap();
                let path = format!("/{}", stack[1..].join("/"));
                props.insert((path, name), v);
            }
            4 => continue,
            9 => break,
            t => panic!("unknown token {t}"),
        }
    }
    Parsed { props, nodes }
}

impl Parsed {
    fn get(&self, path: &str, name: &str) -> &Vec<u8> {
        self.props
            .get(&(path.to_string(), name.to_string()))
            .unwrap_or_else(|| panic!("missing {path} {name}"))
    }
    fn cells(&self, path: &str, name: &str) -> Vec<u32> {
        self.get(path, name)
            .chunks(4)
            .map(|c| u32::from_be_bytes(c.try_into().unwrap()))
            .collect()
    }
    fn has(&self, path: &str, name: &str) -> bool {
        self.props
            .contains_key(&(path.to_string(), name.to_string()))
    }
}

/// MVM-5・MVM-1: 代表構成の blob を読み戻し、各ノードの値を具体値で照合する。
#[test]
fn mvm5_3788_blob_roundtrip_values() {
    let l = Arm64Layout::new(256 * MIB, 1, 2).unwrap();
    let cfg = GuestFdtConfig {
        layout: &l,
        bootargs: "console=hvc0",
        initrd: Some(MmioRegion::new(0x4800_0000, 0x1000)),
    };
    let p = parse(&build_guest_fdt(&cfg).unwrap());

    assert_eq!(p.cells("/", "#address-cells"), vec![2]);
    assert_eq!(p.cells("/", "interrupt-parent"), vec![1]);
    assert_eq!(
        p.cells("/memory@40000000", "reg"),
        vec![0, 0x4000_0000, 0, 0x1000_0000]
    );
    assert_eq!(p.get("/memory@40000000", "device_type"), b"memory\0");
    assert_eq!(p.get("/psci", "method"), b"hvc\0");
    assert_eq!(
        p.get("/psci", "compatible"),
        b"arm,psci-1.0\0arm,psci-0.2\0"
    );
    assert_eq!(
        p.cells("/intc@8000000", "reg"),
        vec![0, 0x0800_0000, 0, 0x1_0000, 0, 0x0820_0000, 0, 0x2_0000]
    );
    assert_eq!(p.cells("/intc@8000000", "phandle"), vec![1]);
    assert_eq!(p.cells("/intc@8000000", "#interrupt-cells"), vec![3]);
    assert_eq!(
        p.cells("/timer", "interrupts"),
        vec![1, 13, 4, 1, 14, 4, 1, 11, 4, 1, 10, 4]
    );
    assert_eq!(
        p.cells("/virtio_mmio@a000000", "reg"),
        vec![0, 0x0a00_0000, 0, 0x200]
    );
    assert_eq!(
        p.cells("/virtio_mmio@a000000", "interrupts"),
        vec![0, 16, 1]
    );
    assert_eq!(
        p.cells("/virtio_mmio@a000200", "reg"),
        vec![0, 0x0a00_0200, 0, 0x200]
    );
    assert_eq!(
        p.cells("/virtio_mmio@a000200", "interrupts"),
        vec![0, 17, 1]
    );
    assert!(p.get("/virtio_mmio@a000000", "dma-coherent").is_empty());
    assert!(p.get("/virtio_mmio@a000200", "dma-coherent").is_empty());
    assert_eq!(
        p.get("/virtio_mmio@a000000", "compatible"),
        b"virtio,mmio\0"
    );

    assert_eq!(p.get("/chosen", "bootargs"), b"console=hvc0\0");
    assert_eq!(
        p.cells("/chosen", "linux,initrd-start"),
        vec![0, 0x4800_0000]
    );
    assert_eq!(p.cells("/chosen", "linux,initrd-end"), vec![0, 0x4800_1000]);
    assert!(!p.has("/chosen", "stdout-path"));

    assert_eq!(p.cells("/cpus", "#address-cells"), vec![1]);
    assert_eq!(p.cells("/cpus", "#size-cells"), vec![0]);
    assert_eq!(p.cells("/cpus/cpu@0", "reg"), vec![0]);
    assert_eq!(p.get("/cpus/cpu@0", "enable-method"), b"psci\0");
}

/// MVM-5: initrd なし・virtio 0 個ではそれぞれのプロパティ・ノードが無い。
#[test]
fn mvm5_3788_optional_parts_absent() {
    let l = Arm64Layout::new(256 * MIB, 1, 0).unwrap();
    let cfg = GuestFdtConfig {
        layout: &l,
        bootargs: "",
        initrd: None,
    };
    let p = parse(&build_guest_fdt(&cfg).unwrap());
    assert!(!p.has("/chosen", "linux,initrd-start"));
    assert!(!p.has("/chosen", "linux,initrd-end"));
    assert!(p.nodes.iter().all(|n| !n.contains("virtio_mmio@")));
}

/// MVM-5: 配置の異常は公開 API 経由で `InvalidArgument`（`build_guest_fdt` も fail-closed）。
#[test]
fn mvm5_3788_invalid_layouts_rejected() {
    assert_eq!(
        Arm64Layout::new(0, 1, 2).unwrap_err().code(),
        MicrovmErrorCode::InvalidArgument
    );
    let ok = Arm64Layout::new(256 * MIB, 1, 2).unwrap();

    let mut overlap_gic = ok.clone();
    overlap_gic.ram.base = GuestAddress::new(0x0800_0000);
    let mut overlap_virtio = ok.clone();
    overlap_virtio.virtio_mmio_base = GuestAddress::new(0x4000_0000);
    let mut over_ipa = ok.clone();
    over_ipa.ipa_limit = 0x4fff_ffff;
    for bad in [overlap_gic, overlap_virtio, over_ipa] {
        assert_eq!(
            bad.validate().unwrap_err().code(),
            MicrovmErrorCode::InvalidArgument
        );
        let cfg = GuestFdtConfig {
            layout: &bad,
            bootargs: "",
            initrd: None,
        };
        assert_eq!(
            build_guest_fdt(&cfg).unwrap_err().code(),
            MicrovmErrorCode::InvalidArgument
        );
    }
}
