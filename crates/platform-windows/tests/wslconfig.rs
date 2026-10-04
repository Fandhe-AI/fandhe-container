//! `.wslconfig` の virtiofs opt-in の結合試験（TASK-67.2・#373・WIN-2・REPAIR-4）。
//!
//! 公開 API（`wslconfig::load`・`enable_virtiofs_at`・計装版と `instrument`）だけを通して、新規作成・既存更新・
//! 冪等性・不正入力時の元ファイル保持と、操作ごとの計測サンプルを確認する。ファイル操作は OS 非依存の経路で、
//! 3 OS の CI で実行する（Windows 固有のアクセス制御の保持はユニットテスト側で確認する）。

use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use fandhe_container_platform_windows::error::WinErrorCode;
use fandhe_container_platform_windows::instrument::{
    WinOpKind, WinOpOutcome, WinOpRecorder, WinOpSample,
};
use fandhe_container_platform_windows::wslconfig::{
    EnableOutcome, VirtiofsState, enable_virtiofs_at, enable_virtiofs_at_with_recorder, load,
};

/// テストごとの一時ディレクトリ（Drop で削除）。
struct TmpDir(PathBuf);

impl TmpDir {
    fn new(tag: &str) -> Self {
        static N: AtomicU64 = AtomicU64::new(0);
        let p = std::env::temp_dir().join(format!(
            "fc-wslconfig-it-{tag}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&p).expect("mkdir");
        Self(p)
    }

    fn file(&self) -> PathBuf {
        self.0.join(".wslconfig")
    }

    fn entries(&self) -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(&self.0)
            .expect("read_dir")
            .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
            .collect();
        v.sort();
        v
    }
}

impl Drop for TmpDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn read(path: &Path) -> Vec<u8> {
    std::fs::read(path).expect("read")
}

/// 受け取ったサンプルを順に保持する記録先。
#[derive(Default)]
struct Collect(Mutex<Vec<WinOpSample>>);

impl WinOpRecorder for Collect {
    fn record_win_op(&self, s: &WinOpSample) {
        if let Ok(mut v) = self.0.lock() {
            v.push(*s);
        }
    }
}

impl Collect {
    fn kinds(&self) -> Vec<(WinOpKind, WinOpOutcome)> {
        self.0
            .lock()
            .map(|v| v.iter().map(|s| (s.kind(), s.outcome())).collect())
            .unwrap_or_default()
    }
}

/// WIN-2・AC2: ファイルがなければ CRLF で新規作成し、読み直すと有効。一時ファイルは残らない。
#[test]
fn win2_creates_missing_wslconfig() {
    let d = TmpDir::new("create");
    assert_eq!(load(&d.file()), Ok(None));
    assert_eq!(enable_virtiofs_at(&d.file()), Ok(EnableOutcome::Created));
    assert_eq!(read(&d.file()), b"[wsl2]\r\nvirtiofs=true\r\n");
    let cfg = load(&d.file()).expect("load").expect("exists");
    assert_eq!(cfg.virtiofs_state(), VirtiofsState::Enabled);
    assert_eq!(d.entries(), vec![".wslconfig".to_string()]);
}

/// WIN-2・AC1: 既存の他セクション・コメント・改行を保って `virtiofs=false` を更新し、再実行は書き込まない。
#[test]
fn win2_updates_existing_wslconfig_and_is_idempotent() {
    let d = TmpDir::new("update");
    std::fs::write(
        d.file(),
        "# keep\n[wsl2]\nmemory=4GB\nvirtiofs=false\n\n[boot]\nsystemd=true\n",
    )
    .expect("write");
    assert_eq!(
        enable_virtiofs_at(&d.file()),
        Ok(EnableOutcome::Updated {
            previous: VirtiofsState::Disabled
        })
    );
    let expected: &[u8] = b"# keep\n[wsl2]\nmemory=4GB\nvirtiofs=true\n\n[boot]\nsystemd=true\n";
    assert_eq!(read(&d.file()), expected);
    assert_eq!(
        enable_virtiofs_at(&d.file()),
        Ok(EnableOutcome::AlreadyEnabled)
    );
    assert_eq!(read(&d.file()), expected);
    assert_eq!(d.entries(), vec![".wslconfig".to_string()]);
}

/// WIN-2・AC3: 不正な内容のファイルは INVALID_ARGUMENT で、元のバイト列を変えず一時ファイルも残さない。
/// message には内容・パスを含めない。
#[test]
fn win2_invalid_wslconfig_is_left_untouched() {
    let d = TmpDir::new("invalid");
    let original: &[u8] = b"[wsl2\nkernelCommandLine=secret\n";
    std::fs::write(d.file(), original).expect("write");
    let e = enable_virtiofs_at(&d.file()).expect_err("must fail");
    assert_eq!(e.code(), WinErrorCode::InvalidArgument);
    assert!(!e.message().contains("secret"), "{}", e.message());
    assert!(
        !e.message().contains(&*d.0.to_string_lossy()),
        "{}",
        e.message()
    );
    assert_eq!(read(&d.file()), original);
    assert_eq!(d.entries(), vec![".wslconfig".to_string()]);
}

/// REPAIR-4・WIN-2: 計装版は操作ごとに 1 件、種別と成否を記録する。
#[test]
fn repair4_enable_virtiofs_records_outcome_per_call() {
    let d = TmpDir::new("recorder");
    let c = Collect::default();
    assert_eq!(
        enable_virtiofs_at_with_recorder(&d.file(), &c),
        Ok(EnableOutcome::Created)
    );
    std::fs::write(d.file(), "[wsl2\n").expect("write");
    let e = enable_virtiofs_at_with_recorder(&d.file(), &c).expect_err("must fail");
    assert_eq!(e.code(), WinErrorCode::InvalidArgument);
    assert_eq!(
        c.kinds(),
        vec![
            (WinOpKind::WslconfigEnableVirtiofs, WinOpOutcome::Success),
            (WinOpKind::WslconfigEnableVirtiofs, WinOpOutcome::Failure),
        ]
    );
}
