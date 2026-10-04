//! WSL2 検出の公開 API の結合試験（TASK-67.3・WIN-1・ERR-1・REPAIR-5・REPAIR-12）。
//!
//! feature なしで実行でき、環境（WSL の有無）によらず結果が決まる経路だけを確かめる（ホストの
//! `wsl.exe` は起動しない。実機の WSL2 での確認は TASK-67.6・#377）。
//! 子プロセスの起動・出力解析を含む正常系・失敗系は `tests/wsl2_detect.rs`（feature
//! `wsl2-test-support`）が偽の `wsl.exe` で検証する。

use std::time::Duration;

#[cfg(not(windows))]
use fandhe_container_platform_windows::wsl2::DEFAULT_WSL_TIMEOUT;
use fandhe_container_platform_windows::wsl2::{
    MAX_WSL_TIMEOUT, Wsl2ErrorCode, detect, list_distros, query_version,
};

/// REPAIR-5・ERR-1: 0 や上限超えのタイムアウトは、`wsl.exe` を探す前に INVALID_ARGUMENT になる。
#[test]
fn invalid_timeout_is_rejected_before_probing() {
    let too_long = MAX_WSL_TIMEOUT + Duration::from_millis(1);
    for timeout in [Duration::ZERO, too_long] {
        assert_eq!(
            detect(timeout).unwrap_err().code(),
            Wsl2ErrorCode::InvalidArgument
        );
        assert_eq!(
            query_version(timeout).unwrap_err().code(),
            Wsl2ErrorCode::InvalidArgument
        );
        assert_eq!(
            list_distros(timeout).unwrap_err().code(),
            Wsl2ErrorCode::InvalidArgument
        );
    }
    let e = detect(Duration::ZERO).unwrap_err();
    assert_eq!(e.code().as_str(), "INVALID_ARGUMENT");
    assert_eq!(e.message(), "timeout must be between 1ms and 300s");
}

/// WIN-1: Windows 以外では WSL2 を検出できず UNIMPLEMENTED（fail-closed）。
#[cfg(not(windows))]
#[test]
fn non_windows_is_unimplemented() {
    for code in [
        detect(DEFAULT_WSL_TIMEOUT).unwrap_err().code(),
        query_version(DEFAULT_WSL_TIMEOUT).unwrap_err().code(),
        list_distros(DEFAULT_WSL_TIMEOUT).unwrap_err().code(),
    ] {
        assert_eq!(code, Wsl2ErrorCode::Unimplemented);
    }
}
