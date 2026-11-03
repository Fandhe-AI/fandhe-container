//! CDI spec ファイル読み込みの結合試験（GPU-1・TASK-126.1・REPAIR-10(d)・REPAIR-12）。
//!
//! 公開 API だけで、実ファイルの正常読み込み・サイズ超過・不正 UTF-8・非通常ファイルと
//! 構造化エラー・計測を具体値で確認する。

use std::path::{Path, PathBuf};
#[cfg(unix)]
#[path = "../../core/tests/support/reap.rs"]
mod reap;

use std::sync::Mutex;

use fandhe_container_gpu::cdi_spec::{
    CDI_SPEC_MAX_INPUT_BYTES, CdiSpecErrorCode, CdiSpecReadRecorder, CdiSpecReadSample,
    parse_cdi_spec, read_cdi_spec_file, read_cdi_spec_file_with_recorder,
};

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("fandhe-gpu-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[derive(Default)]
struct Collect(Mutex<Vec<CdiSpecReadSample>>);

impl CdiSpecReadRecorder for Collect {
    fn record(&self, sample: CdiSpecReadSample) {
        self.0.lock().unwrap().push(sample);
    }
}

/// GPU-1: 実ファイルが読めて、成功が 1 件記録される。
#[test]
fn gpu1_reads_real_file_and_records_success() {
    let d = TempDir::new("ok");
    let p = d.path().join("nvidia.yaml");
    std::fs::write(
        &p,
        "cdiVersion: \"0.5.0\"\nkind: nvidia.com/gpu\ndevices:\n  - name: \"0\"\n    containerEdits:\n      deviceNodes:\n        - path: /dev/nvidia0\n",
    )
    .unwrap();
    let rec = Collect::default();
    let spec = read_cdi_spec_file_with_recorder(&p, &rec).unwrap();
    assert_eq!(spec.cdi_version, "0.5.0");
    assert_eq!(spec.kind, "nvidia.com/gpu");
    assert_eq!(spec.devices[0].name, "0");
    assert_eq!(read_cdi_spec_file(&p).unwrap(), spec);
    let samples = rec.0.lock().unwrap();
    assert_eq!(samples.len(), 1);
    assert!(samples[0].is_success());
    assert_eq!(samples[0].error_code(), None);
}

/// GPU-1: サイズ超過は ResourceExhausted、不正 UTF-8 は InvalidArgument、欠落は NotFound。
#[test]
fn gpu1_structured_errors_for_bad_files() {
    let d = TempDir::new("err");
    let big = d.path().join("big.yaml");
    std::fs::write(&big, vec![b'#'; CDI_SPEC_MAX_INPUT_BYTES + 1]).unwrap();
    let rec = Collect::default();
    let e = read_cdi_spec_file_with_recorder(&big, &rec).unwrap_err();
    assert_eq!(e.code(), CdiSpecErrorCode::ResourceExhausted);
    assert_eq!(e.code().as_str(), "RESOURCE_EXHAUSTED");

    let bad = d.path().join("bad.yaml");
    std::fs::write(&bad, [0xff, 0xfe, 0xfd]).unwrap();
    let e = read_cdi_spec_file_with_recorder(&bad, &rec).unwrap_err();
    assert_eq!(e.code(), CdiSpecErrorCode::InvalidArgument);
    assert_eq!(e.message(), "CDI spec file is not valid UTF-8");

    let e = read_cdi_spec_file_with_recorder(&d.path().join("none.yaml"), &rec).unwrap_err();
    assert_eq!(e.code(), CdiSpecErrorCode::NotFound);

    let codes: Vec<_> = rec
        .0
        .lock()
        .unwrap()
        .iter()
        .map(|s| s.error_code())
        .collect();
    assert_eq!(
        codes,
        [
            Some(CdiSpecErrorCode::ResourceExhausted),
            Some(CdiSpecErrorCode::InvalidArgument),
            Some(CdiSpecErrorCode::NotFound),
        ]
    );
}

/// GPU-1: ディレクトリ（通常ファイルでない）は拒否され、停止しない。
/// Windows ではディレクトリの open 自体が失敗するため Internal になる。
#[cfg(unix)]
#[test]
fn gpu1_rejects_non_regular_file() {
    let d = TempDir::new("dir");
    let e = read_cdi_spec_file(d.path()).unwrap_err();
    assert_eq!(e.code(), CdiSpecErrorCode::InvalidArgument);
    assert_eq!(e.message(), "CDI spec path is not a regular file");
}

/// mkfifo の終了待ちの期限（REPAIR-5）。
#[cfg(unix)]
const MKFIFO_DEADLINE: std::time::Duration = std::time::Duration::from_secs(10);

/// mkfifo を期限付きで実行する。起動失敗・失敗終了・期限超過はすべて panic（無言で省略しない）。
#[cfg(unix)]
fn make_fifo(path: &Path) {
    let mut child = std::process::Command::new("mkfifo")
        .arg(path)
        .spawn()
        .expect("mkfifo must be available to verify FIFO handling (GPU-1)");
    let start = std::time::Instant::now();
    loop {
        match child.try_wait().expect("failed to poll mkfifo") {
            Some(status) => {
                assert!(status.success(), "mkfifo failed: {status}");
                return;
            }
            None if start.elapsed() > MKFIFO_DEADLINE => {
                reap::reap_or_report(&mut child, reap::reap_within());
                panic!("mkfifo did not finish within {MKFIFO_DEADLINE:?}");
            }
            None => std::thread::sleep(std::time::Duration::from_millis(10)),
        }
    }
}

/// GPU-1: FIFO は writer がいなくても open で停止せず拒否される（Unix のみ）。
#[cfg(unix)]
#[test]
fn gpu1_rejects_fifo_without_hanging() {
    let d = TempDir::new("fifo");
    let p = d.path().join("spec.fifo");
    make_fifo(&p);
    let e = read_cdi_spec_file(&p).unwrap_err();
    assert_eq!(e.code(), CdiSpecErrorCode::InvalidArgument);
    assert_eq!(e.message(), "CDI spec path is not a regular file");
}

/// GPU-1: 文字デバイス（/dev/null）とその symlink は通常ファイルでないため拒否される（Unix のみ）。
/// open は O_NOCTTY 付きで行うため、端末デバイスでも制御端末を取得しない。
#[cfg(unix)]
#[test]
fn gpu1_rejects_char_device_and_symlink_to_it() {
    let dev = Path::new("/dev/null");
    let e = read_cdi_spec_file(dev).unwrap_err();
    assert_eq!(e.code(), CdiSpecErrorCode::InvalidArgument);
    assert_eq!(e.message(), "CDI spec path is not a regular file");

    let d = TempDir::new("devlink");
    let link = d.path().join("spec.yaml");
    std::os::unix::fs::symlink(dev, &link).expect("symlink");
    let e = read_cdi_spec_file(&link).unwrap_err();
    assert_eq!(e.code(), CdiSpecErrorCode::InvalidArgument);
    assert_eq!(e.message(), "CDI spec path is not a regular file");
}

/// GPU-1: 上限 +1 バイトが多バイト文字の途中で切れても ResourceExhausted になる。
#[test]
fn gpu1_oversize_multibyte_boundary_is_resource_exhausted() {
    let d = TempDir::new("mb");
    let p = d.path().join("mb.yaml");
    let mut data = vec![b'#'; CDI_SPEC_MAX_INPUT_BYTES - 1];
    data.extend("あ".as_bytes()); // 3 バイト文字が上限境界をまたぐ
    std::fs::write(&p, data).unwrap();
    let e = read_cdi_spec_file(&p).unwrap_err();
    assert_eq!(e.code(), CdiSpecErrorCode::ResourceExhausted);
}

const ND: &str = "{hostInterfaceName: eth1, name: net1}";

fn nd_yaml(version: &str, top: &str, dev: &str) -> String {
    format!(
        "cdiVersion: \"{version}\"\nkind: v/c\ndevices:\n  - name: a\n    containerEdits:\n      netDevices: {dev}\ncontainerEdits:\n  netDevices: {top}\n"
    )
}

/// GPU-1・REPAIR-3: `cdiVersion` と `netDevices` の組み合わせごとの受け付け範囲（#2445）。
#[test]
fn gpu1_cdi_version_acceptance_range_for_net_devices() {
    use CdiSpecErrorCode::{InvalidArgument, Unimplemented};
    let none = |v: &str| format!("cdiVersion: \"{v}\"\nkind: v/c\n");
    for v in ["0.3.0", "0.7.0", "1.1.0"] {
        assert!(parse_cdi_spec(&none(v)).is_ok(), "{v}");
    }
    assert!(parse_cdi_spec(&nd_yaml("0.7.0", "[]", "[]")).is_ok());
    let list = format!("[{ND}]");
    let cases = [
        ("0.7.0", InvalidArgument),
        ("0.8.0", InvalidArgument),
        ("1.0.0", InvalidArgument),
        ("1.1.0", Unimplemented),
        ("v1.1.0", Unimplemented),
        // 上流 version.go L99-108 と同じく未知の版は無効（#2597）。
        ("1.2.0", InvalidArgument),
        ("abc", InvalidArgument),
        ("1.1", InvalidArgument),
        ("1.1.0-rc1", InvalidArgument),
        ("", InvalidArgument),
    ];
    for (v, want) in cases {
        for y in [nd_yaml(v, &list, "[]"), nd_yaml(v, "[]", &list)] {
            let got = parse_cdi_spec(&y).unwrap_err().code();
            assert_eq!(got, want, "{v:?}");
        }
    }
    let bad = nd_yaml("1.1.0", "[{hostInterfaceName: \"a/b\", name: n}]", "[]");
    assert_eq!(parse_cdi_spec(&bad).unwrap_err().code(), InvalidArgument);
}

/// REPAIR-3: ファイル経由でも `Unimplemented` で拒否され、計測に 1 回記録される。
#[test]
fn repair3_reads_net_devices_file_as_unimplemented() {
    let d = TempDir::new("netdev");
    let p = d.path().join("net.yaml");
    std::fs::write(&p, nd_yaml("1.1.0", &format!("[{ND}]"), "[]")).unwrap();
    let rec = Collect::default();
    let e = read_cdi_spec_file_with_recorder(&p, &rec).unwrap_err();
    assert_eq!(e.code(), CdiSpecErrorCode::Unimplemented);
    let samples = rec.0.lock().unwrap();
    assert_eq!(samples.len(), 1);
    assert_eq!(
        samples[0].error_code(),
        Some(CdiSpecErrorCode::Unimplemented)
    );
}
