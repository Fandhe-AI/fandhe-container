//! 非 GPU デバイスの CDI spec を GPU-1 のパーサ・集計が受けることの机上検証（TASK-132・#570）。
//!
//! GPU-9（CDI を GPU 以外の一般デバイスへ広げられるか）は spec で検討中のため、本試験は確定の
//! 根拠ではなく #571（TASK-132.h1。実機 PoC と判断は人間）への判断材料に過ぎない。
//! `parse_cdi_spec` → `aggregate_container_edits`（→ `normalize_cdi_spec_paths`）の公開 API だけで、
//! USB シリアル変換器と生の USB デバイスノードを想定した自作 spec（`tests/fixtures/cdi-non-gpu-*.yaml`）を
//! 通し、具体値で照合する。適用（mknod・cgroup device 等。TASK-127〜）は本試験の対象外。

use std::path::Path;

use fandhe_container_gpu::cdi_edits::aggregate_container_edits;
use fandhe_container_gpu::cdi_paths::{PathLayouts, UsrMergeLayout, normalize_cdi_spec_paths};
use fandhe_container_gpu::cdi_spec::{CdiSpecErrorCode, parse_cdi_spec, read_cdi_spec_file};

const SERIAL: &str = include_str!("fixtures/cdi-non-gpu-serial.yaml");
const USB: &str = include_str!("fixtures/cdi-non-gpu-usb.yaml");

/// GPU-1・GPU-9（検討中）・TASK-132: シリアル spec が解析・集計できる。
#[test]
fn gpu1_non_gpu_serial_spec_parses_and_aggregates() {
    let spec = parse_cdi_spec(SERIAL).unwrap();
    assert_eq!(spec.cdi_version, "0.7.0");
    assert_eq!(spec.kind, "example.com/serial");
    let names: Vec<&str> = spec.devices.iter().map(|d| d.name.as_str()).collect();
    assert_eq!(names, ["ttyusb0"]);

    let a = aggregate_container_edits(&spec, &["ttyusb0"]).unwrap();
    assert_eq!(a.device_nodes().len(), 1);
    let n = &a.device_nodes()[0];
    assert_eq!(n.path, "/dev/ttyUSB0");
    assert_eq!(n.r#type.as_deref(), Some("c"));
    assert_eq!(n.major, Some(188));
    assert_eq!(n.minor, Some(0));
    assert_eq!(n.permissions.as_deref(), Some("rw"));
    assert_eq!(n.file_mode, Some(432));
    assert_eq!(n.gid, Some(20));
    assert_eq!(a.additional_gids(), [20]);
    let env: Vec<&str> = a.env().iter().map(String::as_str).collect();
    assert_eq!(env, ["EXAMPLE_SERIAL_BAUD=115200"]);
    assert_eq!(a.hooks().len(), 0);
    assert_eq!(a.mounts().len(), 0);
    assert!(a.intel_rdt().is_none());
}

/// GPU-1・GPU-9（検討中）・TASK-132: USB spec が解析・集計できる。
#[test]
fn gpu1_non_gpu_usb_spec_parses_and_aggregates() {
    let spec = parse_cdi_spec(USB).unwrap();
    assert_eq!(spec.cdi_version, "0.5.0");
    assert_eq!(spec.kind, "example.com/usb");

    let a = aggregate_container_edits(&spec, &["bus001-dev002"]).unwrap();
    assert_eq!(a.device_nodes().len(), 1);
    let n = &a.device_nodes()[0];
    assert_eq!(n.path, "/dev/bus/usb/001/002");
    assert_eq!(n.host_path.as_deref(), Some("/dev/bus/usb/001/002"));
    assert_eq!(n.major, Some(189));
    assert_eq!(n.minor, Some(1));
    assert_eq!(n.permissions.as_deref(), Some("rwm"));
    assert_eq!(a.mounts().len(), 1);
    let m = &a.mounts()[0];
    assert_eq!(m.host_path, "/run/udev");
    assert_eq!(m.container_path, "/run/udev");
    assert_eq!(m.options, ["ro", "nosuid", "nodev", "bind"]);
    assert_eq!(a.hooks().len(), 0);
    assert_eq!(a.env().len(), 0);
}

/// GPU-1・GPU-9（検討中）・TASK-132: ファイル経路でも文字列経路と同じ値になる。
#[test]
fn gpu1_non_gpu_specs_read_from_file() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let serial = read_cdi_spec_file(&dir.join("cdi-non-gpu-serial.yaml")).unwrap();
    assert_eq!(serial, parse_cdi_spec(SERIAL).unwrap());
    let usb = read_cdi_spec_file(&dir.join("cdi-non-gpu-usb.yaml")).unwrap();
    assert_eq!(usb, parse_cdi_spec(USB).unwrap());
}

/// GPU-1・GPU-9（検討中）・TASK-132: usr-merge 正規化は `/dev`・`/run` のパスを変えない。
/// 正規化は `hostPath` 省略時に `path` の値を補う（観測した挙動。補う値は `path` と同じ）。
#[test]
fn gpu1_non_gpu_usr_merge_leaves_dev_paths_unchanged() {
    let layouts = PathLayouts::new(UsrMergeLayout::merged(), UsrMergeLayout::merged());

    let mut serial = parse_cdi_spec(SERIAL).unwrap();
    normalize_cdi_spec_paths(&mut serial, &layouts);
    let n = &serial.devices[0].container_edits.device_nodes[0];
    assert_eq!(n.path, "/dev/ttyUSB0");
    assert_eq!(n.host_path.as_deref(), Some("/dev/ttyUSB0"));

    let mut usb = parse_cdi_spec(USB).unwrap();
    normalize_cdi_spec_paths(&mut usb, &layouts);
    let e = &usb.devices[0].container_edits;
    assert_eq!(e.device_nodes[0].path, "/dev/bus/usb/001/002");
    assert_eq!(
        e.device_nodes[0].host_path.as_deref(),
        Some("/dev/bus/usb/001/002")
    );
    assert_eq!(e.mounts[0].host_path, "/run/udev");
    assert_eq!(e.mounts[0].container_path, "/run/udev");
}

/// GPU-1・GPU-9（検討中）・TASK-132: 機能ごとの最小 cdiVersion の規則が非 GPU の spec にも効く。
#[test]
fn gpu1_non_gpu_min_version_rules_apply() {
    // additionalGids は 0.7.0 以上。
    let old_serial = SERIAL.replacen("cdiVersion: 0.7.0", "cdiVersion: 0.6.0", 1);
    assert_ne!(old_serial, SERIAL);
    let e = parse_cdi_spec(&old_serial).unwrap_err();
    assert_eq!(e.code(), CdiSpecErrorCode::InvalidArgument);
    // deviceNodes[].hostPath は 0.5.0 以上。
    let old_usb = USB.replacen("cdiVersion: 0.5.0", "cdiVersion: 0.4.0", 1);
    assert_ne!(old_usb, USB);
    let e = parse_cdi_spec(&old_usb).unwrap_err();
    assert_eq!(e.code(), CdiSpecErrorCode::InvalidArgument);
}
