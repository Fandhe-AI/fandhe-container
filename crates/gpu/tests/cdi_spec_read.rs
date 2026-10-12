//! CDI spec ファイル読み込みの結合試験（GPU-1・TASK-126.1・REPAIR-10(d)・REPAIR-12）。
//!
//! 公開 API だけで、実ファイルの正常読み込み・サイズ超過・不正 UTF-8・非通常ファイルと
//! 構造化エラー・計測を具体値で確認する。

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use fandhe_container_gpu::cdi_spec::{
    CDI_SPEC_MAX_INPUT_BYTES, CdiSpecErrorCode, CdiSpecReadRecorder, CdiSpecReadSample,
    read_cdi_spec_file, read_cdi_spec_file_with_recorder,
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

/// GPU-1: FIFO は writer がいなくても open で停止せず拒否される（Unix のみ）。
#[cfg(unix)]
#[test]
fn gpu1_rejects_fifo_without_hanging() {
    let d = TempDir::new("fifo");
    let p = d.path().join("spec.fifo");
    let Ok(status) = std::process::Command::new("mkfifo").arg(&p).status() else {
        return; // mkfifo が無い環境では FIFO を作れないため検証対象外
    };
    assert!(status.success());
    let e = read_cdi_spec_file(&p).unwrap_err();
    assert_eq!(e.code(), CdiSpecErrorCode::InvalidArgument);
    assert_eq!(e.message(), "CDI spec path is not a regular file");
}
