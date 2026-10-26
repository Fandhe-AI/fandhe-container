//! CDI `deviceNodes` の root 前提の実機試験（GPU-2・TASK-127.1）。
//!
//! `CAP_MKNOD` が要るため既定の集合から分離している。実行:
//! `sudo -E cargo test -p fandhe-container-gpu --test cdi_device_nodes_root -- --ignored`
#![cfg(target_os = "linux")]

use fandhe_container_gpu::cdi_apply::{create_device_nodes, resolve_device_nodes};
use fandhe_container_gpu::cdi_spec::DeviceNode;
use std::os::fd::AsFd as _;
use std::os::unix::fs::MetadataExt as _;

fn node(path: &str, ty: Option<&str>, ma: Option<i64>, mi: Option<i64>) -> DeviceNode {
    DeviceNode {
        path: path.to_owned(),
        host_path: None,
        r#type: ty.map(str::to_owned),
        major: ma,
        minor: mi,
        file_mode: None,
        permissions: None,
        uid: None,
        gid: None,
    }
}

fn is_root() -> bool {
    std::fs::metadata("/proc/self")
        .map(|m| m.uid() == 0)
        .unwrap_or(false)
}

/// GPU-2: /dev/null の path だけの指定で 1:3 の文字デバイスが作られ、rdev がホストと一致する。
/// 明示指定の c 195:0 と b 7:0 も、観測した major / minor が指定どおりである。
#[test]
#[ignore = "requires root (CAP_MKNOD). GPU-2"]
fn gpu2_root_mknod_preserves_major_minor() {
    assert!(
        is_root(),
        "this test must run as root (--ignored under sudo)"
    );
    let d = std::env::temp_dir().join(format!("fc-gpu-root-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    let root = std::fs::File::open(&d).unwrap();
    let resolved = resolve_device_nodes(&[
        node("/dev/null", None, None, None),
        node("/dev/nv0", Some("c"), Some(195), Some(0)),
        node("/dev/blk0", Some("b"), Some(7), Some(0)),
    ])
    .unwrap();
    let rep = create_device_nodes(root.as_fd(), &resolved).unwrap();
    let got: Vec<(u64, u64)> = rep
        .outcomes
        .iter()
        .map(|o| (o.observed_major, o.observed_minor))
        .collect();
    assert_eq!(got, [(1, 3), (195, 0), (7, 0)]);
    let host = std::fs::symlink_metadata("/dev/null").unwrap().rdev();
    assert_eq!(
        std::fs::symlink_metadata(d.join("null")).unwrap().rdev(),
        host
    );
    let _ = std::fs::remove_dir_all(&d);
}
