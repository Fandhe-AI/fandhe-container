//! `parse_cdi_spec` / `read_cdi_spec_file` から `aggregate_container_edits` までの結合試験
//! （TASK-126.2・GPU-1）。公開 API のみを使う。
use fandhe_container_gpu::cdi_edits::{
    CDI_EDITS_MAX_DEVICE_NAME_BYTES, CDI_EDITS_MAX_REQUESTED_DEVICES, CdiDeviceRequest,
    aggregate_container_edits, aggregate_container_edits_across_specs,
};
use fandhe_container_gpu::cdi_spec::{CdiSpecErrorCode, parse_cdi_spec, read_cdi_spec_file};

#[path = "../../oci/tests/support/test_root.rs"]
mod test_root;

const YAML: &str = "cdiVersion: 0.5.0
kind: nvidia.com/gpu
devices:
  - name: \"0\"
    containerEdits:
      deviceNodes:
        - path: /dev/nvidia0
  - name: \"1\"
    containerEdits:
      deviceNodes:
        - path: /dev/nvidia1
containerEdits:
  env: [A=1, B=2]
  deviceNodes:
    - path: /dev/nvidiactl
  mounts:
    - hostPath: /usr/bin/nvidia-smi
      containerPath: /usr/bin/nvidia-smi
";

#[test]
fn gpu1_parse_then_aggregate_two_devices() {
    let spec = parse_cdi_spec(YAML).unwrap();
    let a = aggregate_container_edits(&spec, &["0", "1"]).unwrap();
    let paths: Vec<&str> = a.device_nodes().iter().map(|n| n.path.as_str()).collect();
    assert_eq!(paths, ["/dev/nvidiactl", "/dev/nvidia0", "/dev/nvidia1"]);
    assert_eq!(a.env().len(), 2);
    assert_eq!(a.mounts().len(), 1);
    assert_eq!(a.hooks().len(), 0);
}

#[test]
fn gpu1_read_file_then_aggregate() {
    // 前回の残骸の上で進めない（連番・作成前削除・Drop。REPAIR-12・#3375）。
    let dir = test_root::test_root("fandhe-gpu-edits", "agg");
    let p = dir.join("nvidia.yaml");
    std::fs::write(&p, YAML).unwrap();
    let spec = read_cdi_spec_file(&p).unwrap();
    let a = aggregate_container_edits(&spec, &["1"]).unwrap();
    std::fs::remove_dir_all(&dir).ok();
    assert_eq!(a.device_nodes().len(), 2);
}

/// GPU-1・「リソース上限」: 小さな正常な spec に上限 +1 件の互いに異なる不存在名を渡すと、存在確認
/// （`NotFound`）へ進む前に `ResourceExhausted` で拒否する。上限ちょうどなら上限検証を通る。
#[test]
fn gpu1_too_many_requested_device_names_are_rejected_before_lookup() {
    let spec = parse_cdi_spec(YAML).unwrap();
    assert_eq!(CDI_EDITS_MAX_REQUESTED_DEVICES, 1024);
    let names: Vec<String> = (0..=CDI_EDITS_MAX_REQUESTED_DEVICES)
        .map(|i| format!("missing-{i}"))
        .collect();
    let refs: Vec<&str> = names.iter().map(String::as_str).collect();
    assert_eq!(refs.len(), 1025);

    let e = aggregate_container_edits(&spec, &refs).unwrap_err();
    assert_eq!(e.code(), CdiSpecErrorCode::ResourceExhausted);
    assert_eq!(e.code().as_str(), "RESOURCE_EXHAUSTED");
    assert_eq!(e.message(), "too many CDI device names were requested");

    let at_limit = refs.get(..1024).unwrap();
    let e = aggregate_container_edits(&spec, at_limit).unwrap_err();
    assert_eq!(e.code(), CdiSpecErrorCode::NotFound);

    // 上限ちょうどの件数でも、実在する名前の繰り返しは 1 件に畳んで受理する。
    let repeated = vec!["1"; CDI_EDITS_MAX_REQUESTED_DEVICES];
    let a = aggregate_container_edits(&spec, &repeated).unwrap();
    let paths: Vec<&str> = a.device_nodes().iter().map(|n| n.path.as_str()).collect();
    assert_eq!(paths, ["/dev/nvidiactl", "/dev/nvidia1"]);
}

/// GPU-1・「リソース上限」: 長すぎる要求名（上限 +1 バイト）は `ResourceExhausted`、上限ちょうどは
/// 上限検証を通る（spec に無いので `NotFound`）。
#[test]
fn gpu1_too_long_requested_device_name_is_rejected() {
    let spec = parse_cdi_spec(YAML).unwrap();
    assert_eq!(CDI_EDITS_MAX_DEVICE_NAME_BYTES, 256);
    let over = "x".repeat(257);
    let e = aggregate_container_edits(&spec, &["0", over.as_str()]).unwrap_err();
    assert_eq!(e.code(), CdiSpecErrorCode::ResourceExhausted);
    assert_eq!(e.message(), "requested CDI device name is too long");

    let at_limit = "x".repeat(256);
    let e = aggregate_container_edits(&spec, &[at_limit.as_str()]).unwrap_err();
    assert_eq!(e.code(), CdiSpecErrorCode::NotFound);
}
/// GPU-1・TASK-126.2・#1888: 2 つの spec を parse して跨いで集計すると、spec の初参照位置にトップレベルが入る。
#[test]
fn gpu1_two_specs_aggregate_interleaves_top_level() {
    let other = "cdiVersion: 0.5.0
kind: vendor.example/gpu
devices:
  - name: \"9\"
    containerEdits:
      deviceNodes:
        - path: /dev/other9
containerEdits:
  deviceNodes:
    - path: /dev/other-ctl
";
    let a = parse_cdi_spec(YAML).unwrap();
    let b = parse_cdi_spec(other).unwrap();
    let reqs = [
        CdiDeviceRequest::new(&b, "9"),
        CdiDeviceRequest::new(&a, "1"),
        CdiDeviceRequest::new(&b, "9"),
        CdiDeviceRequest::new(&a, "0"),
    ];
    let agg = aggregate_container_edits_across_specs(&reqs).unwrap();
    let paths: Vec<&str> = agg.device_nodes().iter().map(|n| n.path.as_str()).collect();
    assert_eq!(
        paths,
        [
            "/dev/other-ctl",
            "/dev/other9",
            "/dev/nvidiactl",
            "/dev/nvidia1",
            "/dev/nvidia0"
        ]
    );
}
