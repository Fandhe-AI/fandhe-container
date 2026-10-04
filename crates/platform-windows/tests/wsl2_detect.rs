//! WSL2 検出の結合試験（TASK-67.3・WIN-1・ERR-1・REPAIR-5・REPAIR-12）。
//!
//! 偽の `wsl.exe`（`tests/bin/fake_wsl.rs`）を実際に子プロセスとして起動し、`wsl2::test_support` 経由で
//! 公開 API と同じ処理（固定引数と `WSL_UTF8=1` での起動・期限と出力上限・出力の解析・構造化エラーへの
//! 変換）を 3 OS で確かめる。本物の `wsl.exe` は使わない（実機確認は TASK-67.6・#377）。
//! feature `wsl2-test-support` が必要（`cargo test -p fandhe-container-platform-windows --all-features`）。
//! feature なしでは本ファイル全体を外し、0 件の test target になる（Cargo.toml のコメント参照）。

#![cfg(feature = "wsl2-test-support")]

use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use fandhe_container_platform_windows::wsl2::test_support::{
    detect_with_program, list_distros_with_program, query_version_with_program,
};
use fandhe_container_platform_windows::wsl2::{DistroState, Wsl2ErrorCode, WslMajorVersion};

const TIMEOUT: Duration = Duration::from_secs(10);

/// 偽 `wsl.exe` のモード（`tests/bin/fake_wsl.rs` の表）。
const MODES: [&str; 9] = [
    "ok", "utf16", "nodistro", "v1only", "disabled", "denied", "garbage", "hang", "flood",
];

/// モードごとの名前で偽 `wsl.exe` を置いたディレクトリ。
///
/// 子プロセスの起動前に 1 回だけ全モード分を用意する（書き込み中のファイルを並行テストの fork が
/// 掴んで実行に失敗する ETXTBSY を避けるため、用意が終わるまでどのテストも起動しない）。
/// 同じファイルシステム上のハードリンクを優先し、できなければコピーする。
fn fake_dir() -> &'static Path {
    static DIR: OnceLock<PathBuf> = OnceLock::new();
    DIR.get_or_init(|| {
        let src = Path::new(env!("CARGO_BIN_EXE_fake_wsl"));
        let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("fake_wsl");
        std::fs::create_dir_all(&dir).unwrap();
        for mode in MODES {
            let dst = dir.join(file_name(mode));
            let _ = std::fs::remove_file(&dst);
            if std::fs::hard_link(src, &dst).is_err() {
                std::fs::copy(src, &dst).unwrap();
            }
        }
        dir
    })
}

fn file_name(mode: &str) -> String {
    format!("fake_wsl-{mode}{}", std::env::consts::EXE_SUFFIX)
}

fn fake(mode: &str) -> PathBuf {
    assert!(MODES.contains(&mode), "unknown mode {mode}");
    fake_dir().join(file_name(mode))
}

/// WIN-1: 正常系。バージョン・一覧（既定・状態・バージョン）・判定を具体値で返す。
#[test]
fn detect_returns_version_and_distros() {
    let s = detect_with_program(&fake("ok"), TIMEOUT).unwrap();
    assert_eq!(s.version.wsl_version, "2.1.5.0");
    assert_eq!(s.version.kernel_version, "5.15.146.1-2");
    assert_eq!(
        s.version.windows_version.as_deref(),
        Some("10.0.22631.3296")
    );
    // `WslDistro` は `#[non_exhaustive]` なので、フィールドを組にして具体値で比べる。
    let got: Vec<(&str, &DistroState, WslMajorVersion, bool)> = s
        .distros
        .iter()
        .map(|d| (d.name.as_str(), &d.state, d.version, d.is_default))
        .collect();
    assert_eq!(
        got,
        vec![
            ("Ubuntu", &DistroState::Running, WslMajorVersion::V2, true),
            (
                "docker-desktop",
                &DistroState::Stopped,
                WslMajorVersion::V2,
                false
            ),
            ("Legacy", &DistroState::Stopped, WslMajorVersion::V1, false),
        ]
    );
    assert!(s.has_wsl2_distro());
}

/// WIN-1: UTF-16LE（BOM 付き）と日本語ロケールの一覧も読める。
#[test]
fn utf16_and_japanese_output() {
    let v = query_version_with_program(&fake("utf16"), TIMEOUT).unwrap();
    assert_eq!(v.wsl_version, "2.1.5.0");
    let d = list_distros_with_program(&fake("utf16"), TIMEOUT).unwrap();
    let got: Vec<(&str, &DistroState, bool)> = d
        .iter()
        .map(|d| (d.name.as_str(), &d.state, d.is_default))
        .collect();
    assert_eq!(
        got,
        vec![
            ("Ubuntu", &DistroState::Running, true),
            ("Debian", &DistroState::Stopped, false),
        ]
    );
}

/// WIN-1: ディストリ 0 件は一覧では空、`detect` では有効化手順つきの FAILED_PRECONDITION。
#[test]
fn no_distro_is_empty_list_and_failed_precondition() {
    assert_eq!(
        list_distros_with_program(&fake("nodistro"), TIMEOUT).unwrap(),
        Vec::new()
    );
    let e = detect_with_program(&fake("nodistro"), TIMEOUT).unwrap_err();
    assert_eq!(e.code(), Wsl2ErrorCode::FailedPrecondition);
    assert!(
        e.message()
            .starts_with("no usable WSL2 distribution is available.")
    );
    assert!(e.message().contains("wsl --install"));
}

/// WIN-1: WSL1 のディストリしかなければ `detect` は FAILED_PRECONDITION。
#[test]
fn wsl1_only_is_failed_precondition() {
    let e = detect_with_program(&fake("v1only"), TIMEOUT).unwrap_err();
    assert_eq!(e.code(), Wsl2ErrorCode::FailedPrecondition);
    assert!(
        e.message()
            .starts_with("no usable WSL2 distribution is available.")
    );
}

/// ERR-1: 失敗出力の分類（無効 → FAILED_PRECONDITION＋手順、アクセス拒否 → PERMISSION_DENIED、
/// 未知の形式 → DATA_LOSS）。
#[test]
fn failures_are_structured() {
    let e = detect_with_program(&fake("disabled"), TIMEOUT).unwrap_err();
    assert_eq!(e.code(), Wsl2ErrorCode::FailedPrecondition);
    assert!(e.message().contains("wsl --install"));

    let e = query_version_with_program(&fake("denied"), TIMEOUT).unwrap_err();
    assert_eq!(e.code(), Wsl2ErrorCode::PermissionDenied);
    assert_eq!(
        e.message(),
        "wsl.exe --version failed: access denied (exit code 1). Output: Access is denied. Error code: Wsl/Service/E_ACCESSDENIED "
    );
    let e = list_distros_with_program(&fake("denied"), TIMEOUT).unwrap_err();
    assert_eq!(e.code(), Wsl2ErrorCode::PermissionDenied);

    let e = query_version_with_program(&fake("garbage"), TIMEOUT).unwrap_err();
    assert_eq!(e.code(), Wsl2ErrorCode::DataLoss);
    let e = list_distros_with_program(&fake("garbage"), TIMEOUT).unwrap_err();
    assert_eq!(e.code(), Wsl2ErrorCode::DataLoss);
}

/// REPAIR-5: 期限を過ぎたら子を終了させて TIMEOUT で戻る（60 秒は待たない）。
#[test]
fn hang_times_out() {
    let start = Instant::now();
    let e = query_version_with_program(&fake("hang"), Duration::from_millis(500)).unwrap_err();
    assert_eq!(e.code(), Wsl2ErrorCode::Timeout);
    assert!(start.elapsed() < Duration::from_secs(20));
}

/// REPAIR-5: 出力が上限（`MAX_OUTPUT_BYTES`）を超えたら RESOURCE_EXHAUSTED。
#[test]
fn flood_is_resource_exhausted() {
    let e = list_distros_with_program(&fake("flood"), TIMEOUT).unwrap_err();
    assert_eq!(e.code(), Wsl2ErrorCode::ResourceExhausted);
}

/// WIN-1: 存在しないプログラムは NOT_FOUND（WSL 未導入）。
#[test]
fn missing_program_is_not_found() {
    let missing = fake_dir().join(file_name("missing"));
    let e = detect_with_program(&missing, TIMEOUT).unwrap_err();
    assert_eq!(e.code(), Wsl2ErrorCode::NotFound);
}
