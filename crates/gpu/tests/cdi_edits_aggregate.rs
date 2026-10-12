//! `parse_cdi_spec` / `read_cdi_spec_file` から `aggregate_container_edits` までの結合試験
//! （TASK-126.2・GPU-1）。公開 API のみを使う。
use fandhe_container_gpu::cdi_edits::aggregate_container_edits;
use fandhe_container_gpu::cdi_spec::{parse_cdi_spec, read_cdi_spec_file};

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
    assert_eq!(paths, ["/dev/nvidia0", "/dev/nvidia1", "/dev/nvidiactl"]);
    assert_eq!(a.env().len(), 2);
    assert_eq!(a.mounts().len(), 1);
    assert_eq!(a.hooks().len(), 0);
}

#[test]
fn gpu1_read_file_then_aggregate() {
    let dir = std::env::temp_dir().join(format!("fandhe-gpu-edits-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let p = dir.join("nvidia.yaml");
    std::fs::write(&p, YAML).unwrap();
    let spec = read_cdi_spec_file(&p).unwrap();
    let a = aggregate_container_edits(&spec, &["1"]).unwrap();
    std::fs::remove_dir_all(&dir).ok();
    assert_eq!(a.device_nodes().len(), 2);
}
