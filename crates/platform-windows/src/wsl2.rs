//! WSL2 の検出・バージョン確認ラッパー（TASK-67.3・#374。WIN-1・WIN-2・ERR-1・REPAIR-5）。
//!
//! `wsl.exe --version` と `wsl.exe -l -v` を起動し、WSL2 が使えるか・どのディストリがあるか・
//! WSL / カーネル / Windows のバージョンを構造化した型で返す。Windows では WSL2 経由を MVP の
//! 主経路とするため（WIN-1）、後続の virtiofs マウント・起動（TASK-67.4・#375。WIN-2）や
//! 9P フォールバック（TASK-67.5・#376）が最初に呼ぶ前提確認がここにある。
//! 実行時は `fandhe-container-plugin-windows`（TASK-116）から別プロセスとして呼ばれる。
//!
//! 構成:
//! - `parse`: バイト列のデコードと出力解析（純粋関数。3 OS でユニットテストする）
//! - `run`: タイムアウトと出力量上限つきの外部プロセス実行器（REPAIR-5）
//! - 本ファイル: 公開 API・エラー型・`wsl.exe` のパス解決（`cfg(windows)` で分岐するのはここだけ）
//!
//! 安全性: シェルを介さず固定の引数配列で起動し、`PATH` 探索はしない（`%SystemRoot%\System32\wsl.exe`
//! の絶対パスのみ）。`wsl.exe` の出力は untrusted として扱い、不明な形式は fail-closed で `Err` にする。
//! 管理者権限を要する WSL の有効化はせず、手順の案内だけを返す。
//!
//! エラー型は本モジュール内に置いた暫定版で、crate 共通の構造化エラーは TASK-67.5（#376）で
//! `error` モジュールへ移してよい（REPAIR-3）。実機の `wsl.exe` での確認は TASK-67.6（#377）の担当。

mod parse;
mod run;

use std::error::Error;
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// 外部プロセス待ちの既定タイムアウト。WSL のコールドスタートを見込んで 10 秒とする（REPAIR-5）。
pub const DEFAULT_WSL_TIMEOUT: Duration = Duration::from_secs(10);
/// 指定できるタイムアウトの上限（これを超える値は `INVALID_ARGUMENT`）。
pub const MAX_WSL_TIMEOUT: Duration = Duration::from_secs(300);
/// `wsl.exe` の出力（stdout・stderr それぞれ）の上限バイト数。超えたら kill して拒否する。
pub const MAX_OUTPUT_BYTES: usize = 64 * 1024;
/// 受け付けるディストリ件数の上限。
pub const MAX_DISTROS: usize = 256;

/// WSL2 が使えない場合に添える有効化手順の案内（英語。ERR-1）。
const ENABLE_GUIDE: &str = "Run 'wsl --install' (or enable the \"Virtual Machine Platform\" and \"Windows Subsystem for Linux\" features), reboot, then run 'wsl --set-default-version 2'";

/// `Wsl2Error` の機械可読な分類（ERR-1）。文字列は `PluginErrorCode::as_str` と揃える。
///
/// `#[non_exhaustive]` のため、呼び出し側の `match` は `_` 分岐を持つこと。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Wsl2ErrorCode {
    /// タイムアウト値などの不正な引数。
    InvalidArgument,
    /// `wsl.exe` が存在しない（WSL 未インストール）。
    NotFound,
    /// WSL2 が無効、または使えるディストリがない（有効化手順を添える）。
    FailedPrecondition,
    /// 期限内に終了しなかった（REPAIR-5）。
    Timeout,
    /// 出力が空・未対応形式・不正なエンコーディング。
    DataLoss,
    /// 出力量・件数・行長が上限を超えた。
    ResourceExhausted,
    /// 起動権限がない。
    PermissionDenied,
    /// Windows 以外の OS。
    Unimplemented,
    /// 上記以外の I/O エラー。
    Internal,
}

impl Wsl2ErrorCode {
    /// 機械可読な `code` 文字列を返す（ERR-1）。
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::InvalidArgument => "INVALID_ARGUMENT",
            Self::NotFound => "NOT_FOUND",
            Self::FailedPrecondition => "FAILED_PRECONDITION",
            Self::Timeout => "TIMEOUT",
            Self::DataLoss => "DATA_LOSS",
            Self::ResourceExhausted => "RESOURCE_EXHAUSTED",
            Self::PermissionDenied => "PERMISSION_DENIED",
            Self::Unimplemented => "UNIMPLEMENTED",
            Self::Internal => "INTERNAL",
        }
    }
}

/// WSL2 検出系の構造化エラー（`code` と英語の `message`。ERR-1）。
///
/// `message` に生の出力は載せない。載せるのはサニタイズ済み（128 バイト以下の印字可能 ASCII）の抜粋だけ。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Wsl2Error {
    code: Wsl2ErrorCode,
    message: String,
}

impl Wsl2Error {
    /// 分類とメッセージ（英語）からエラーを作る。
    pub fn new(code: Wsl2ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    /// 機械可読な分類を返す。
    pub fn code(&self) -> Wsl2ErrorCode {
        self.code
    }

    /// 人間可読なメッセージを返す。
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for Wsl2Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code.as_str(), self.message)
    }
}

impl Error for Wsl2Error {}

/// `wsl.exe --version` の結果。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct WslVersionInfo {
    /// WSL 本体のバージョン（例: `2.1.5.0`）。
    pub wsl_version: String,
    /// WSL2 カーネルのバージョン（例: `5.15.146.1-2`）。
    pub kernel_version: String,
    /// Windows のバージョン（出力にあれば。例: `10.0.22631.3296`）。
    pub windows_version: Option<String>,
}

/// ディストリの状態。ローカライズされた未知の語は `Other` に入れる。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DistroState {
    /// 実行中。
    Running,
    /// 停止中。
    Stopped,
    /// インストール中。
    Installing,
    /// アンインストール中。
    Uninstalling,
    /// 変換中（WSL1 と WSL2 の相互変換）。
    Converting,
    /// 上記以外（サニタイズ済み・32 文字以下）。
    Other(String),
}

/// ディストリの WSL バージョン。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WslMajorVersion {
    /// WSL1。
    V1,
    /// WSL2。
    V2,
}

/// `wsl.exe -l -v` の 1 行分。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct WslDistro {
    /// ディストリ名。
    pub name: String,
    /// 状態。
    pub state: DistroState,
    /// WSL バージョン。
    pub version: WslMajorVersion,
    /// 既定のディストリか。
    pub is_default: bool,
}

/// `detect` の結果。WSL2 のディストリが 1 件以上あることを保証する。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Wsl2Status {
    /// バージョン情報。
    pub version: WslVersionInfo,
    /// 全ディストリ（WSL1 を含む）。
    pub distros: Vec<WslDistro>,
}

impl Wsl2Status {
    /// WSL2 のディストリが 1 件以上あるか。
    pub fn has_wsl2_distro(&self) -> bool {
        self.distros
            .iter()
            .any(|d| d.version == WslMajorVersion::V2)
    }
}

/// `wsl.exe --version` を実行してバージョン情報を返す。
pub fn query_version(timeout: Duration) -> Result<WslVersionInfo, Wsl2Error> {
    query_version_with_program(&wsl_exe_path()?, timeout)
}

/// `wsl.exe -l -v` を実行してディストリ一覧を返す（0 件なら空の一覧）。
pub fn list_distros(timeout: Duration) -> Result<Vec<WslDistro>, Wsl2Error> {
    list_distros_with_program(&wsl_exe_path()?, timeout)
}

/// WSL2 が使えるかを確認し、バージョンとディストリ一覧を返す。
///
/// WSL が無効、または WSL2 のディストリが 1 件もない場合は有効化手順つきの
/// `FAILED_PRECONDITION` を返す（WIN-1）。各呼び出しに `timeout` を適用する。
pub fn detect(timeout: Duration) -> Result<Wsl2Status, Wsl2Error> {
    let program = wsl_exe_path()?;
    let version = query_version_with_program(&program, timeout)?;
    let distros = list_distros_with_program(&program, timeout)?;
    evaluate(version, distros)
}

/// 実行するプログラムを差し替えられる `query_version`（テスト用）。
pub(crate) fn query_version_with_program(
    program: &Path,
    timeout: Duration,
) -> Result<WslVersionInfo, Wsl2Error> {
    check_timeout(timeout)?;
    let out = run::run_capture(
        program,
        &["--version"],
        &[("WSL_UTF8", "1")],
        timeout,
        MAX_OUTPUT_BYTES,
    )?;
    interpret_version(&out)
}

/// 実行するプログラムを差し替えられる `list_distros`（テスト用）。
pub(crate) fn list_distros_with_program(
    program: &Path,
    timeout: Duration,
) -> Result<Vec<WslDistro>, Wsl2Error> {
    check_timeout(timeout)?;
    let out = run::run_capture(
        program,
        &["-l", "-v"],
        &[("WSL_UTF8", "1")],
        timeout,
        MAX_OUTPUT_BYTES,
    )?;
    interpret_list(&out)
}

fn check_timeout(timeout: Duration) -> Result<(), Wsl2Error> {
    if timeout.is_zero() || timeout > MAX_WSL_TIMEOUT {
        return Err(Wsl2Error::new(
            Wsl2ErrorCode::InvalidArgument,
            "timeout must be between 1ms and 300s",
        ));
    }
    Ok(())
}

fn not_enabled_error() -> Wsl2Error {
    Wsl2Error::new(
        Wsl2ErrorCode::FailedPrecondition,
        format!("WSL2 is not enabled. {ENABLE_GUIDE}"),
    )
}

/// `--version` の実行結果を解釈する。
fn interpret_version(out: &run::Captured) -> Result<WslVersionInfo, Wsl2Error> {
    if !out.success {
        return Err(failure_error(out, "wsl.exe --version failed"));
    }
    parse::parse_version(&parse::decode_output(&out.stdout)?)
}

/// `-l -v` の実行結果を解釈する。ディストリ 0 件を示す失敗は空の一覧として扱う。
fn interpret_list(out: &run::Captured) -> Result<Vec<WslDistro>, Wsl2Error> {
    if !out.success {
        if matches!(parse::classify_failure(out), parse::Failure::NoDistro) {
            return Ok(Vec::new());
        }
        return Err(failure_error(out, "wsl.exe -l -v failed"));
    }
    parse::parse_distros(&parse::decode_output(&out.stdout)?)
}

/// 非ゼロ終了を、既知トークンで分類したエラーへ写す。
fn failure_error(out: &run::Captured, context: &str) -> Wsl2Error {
    match parse::classify_failure(out) {
        parse::Failure::WslDisabled => not_enabled_error(),
        _ => Wsl2Error::new(
            Wsl2ErrorCode::FailedPrecondition,
            format!(
                "{context} (exit code {}); the inbox wsl.exe may be too old, try 'wsl --update'. Output: {}",
                out.code
                    .map_or_else(|| "none".to_string(), |c| c.to_string()),
                parse::excerpt(out)
            ),
        ),
    }
}

/// バージョンとディストリ一覧から WSL2 の利用可否を判定する（純粋関数）。
fn evaluate(version: WslVersionInfo, distros: Vec<WslDistro>) -> Result<Wsl2Status, Wsl2Error> {
    let status = Wsl2Status { version, distros };
    if !status.has_wsl2_distro() {
        return Err(Wsl2Error::new(
            Wsl2ErrorCode::FailedPrecondition,
            format!("no WSL2 distribution is installed. {ENABLE_GUIDE}"),
        ));
    }
    Ok(status)
}

/// `wsl.exe` の絶対パスを `%SystemRoot%\System32\wsl.exe` から解決する（`PATH` 探索はしない）。
///
/// 64bit ターゲット前提（32bit プロセスでは WOW64 リダイレクトで System32 の見え方が変わる）。
#[cfg(windows)]
fn wsl_exe_path() -> Result<PathBuf, Wsl2Error> {
    let root = std::env::var_os("SystemRoot").map(PathBuf::from);
    let Some(root) = root.filter(|p| p.is_absolute()) else {
        return Err(Wsl2Error::new(
            Wsl2ErrorCode::FailedPrecondition,
            "SystemRoot is not set to an absolute path",
        ));
    };
    let path = root.join("System32").join("wsl.exe");
    if !path.is_file() {
        return Err(Wsl2Error::new(
            Wsl2ErrorCode::NotFound,
            format!("wsl.exe was not found. WSL is not installed. {ENABLE_GUIDE}"),
        ));
    }
    Ok(path)
}

/// Windows 以外では WSL2 を検出できない（fail-closed）。
#[cfg(not(windows))]
fn wsl_exe_path() -> Result<PathBuf, Wsl2Error> {
    Err(Wsl2Error::new(
        Wsl2ErrorCode::Unimplemented,
        "WSL2 detection is only supported on Windows",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ver() -> WslVersionInfo {
        WslVersionInfo {
            wsl_version: "2.1.5.0".into(),
            kernel_version: "5.15.146.1-2".into(),
            windows_version: None,
        }
    }

    fn distro(version: WslMajorVersion) -> WslDistro {
        WslDistro {
            name: "Ubuntu".into(),
            state: DistroState::Running,
            version,
            is_default: true,
        }
    }

    /// WIN-1・ERR-1: WSL2 のディストリがなければ案内つきの FAILED_PRECONDITION。
    #[test]
    fn evaluate_requires_v2_distro() {
        let e = evaluate(ver(), vec![distro(WslMajorVersion::V1)]).unwrap_err();
        assert_eq!(e.code(), Wsl2ErrorCode::FailedPrecondition);
        assert!(e.message().contains("wsl --install"), "{}", e.message());
        let e = evaluate(ver(), vec![]).unwrap_err();
        assert_eq!(e.code(), Wsl2ErrorCode::FailedPrecondition);
        let s = evaluate(ver(), vec![distro(WslMajorVersion::V2)]).unwrap();
        assert!(s.has_wsl2_distro());
        assert_eq!(s.distros.len(), 1);
    }

    /// REPAIR-5・ERR-1: 0 や過大なタイムアウトは INVALID_ARGUMENT。
    #[test]
    fn invalid_timeout_rejected() {
        let p = Path::new("unused");
        for t in [Duration::ZERO, Duration::from_secs(301)] {
            let e = query_version_with_program(p, t).unwrap_err();
            assert_eq!(e.code(), Wsl2ErrorCode::InvalidArgument);
            let e = list_distros_with_program(p, t).unwrap_err();
            assert_eq!(e.code(), Wsl2ErrorCode::InvalidArgument);
        }
    }

    /// WIN-1: 存在しないプログラムは NOT_FOUND（案内つき）。
    #[test]
    fn missing_program_is_not_found() {
        let p = Path::new("/nonexistent/fandhe/wsl-does-not-exist");
        let e = query_version_with_program(p, Duration::from_secs(5)).unwrap_err();
        assert_eq!(e.code(), Wsl2ErrorCode::NotFound);
        assert!(e.message().contains("wsl --install"));
    }

    /// Windows 以外では UNIMPLEMENTED。
    #[cfg(not(windows))]
    #[test]
    fn non_windows_is_unimplemented() {
        assert_eq!(
            detect(DEFAULT_WSL_TIMEOUT).unwrap_err().code(),
            Wsl2ErrorCode::Unimplemented
        );
    }

    /// ERR-1: code 文字列と Display の具体値。
    #[test]
    fn error_display() {
        let e = Wsl2Error::new(Wsl2ErrorCode::Timeout, "slow");
        assert_eq!(e.to_string(), "TIMEOUT: slow");
        assert_eq!(Wsl2ErrorCode::DataLoss.as_str(), "DATA_LOSS");
    }
}
