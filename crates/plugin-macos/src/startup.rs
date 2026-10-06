//! 起動引数の解析と socket パスの解決（TASK-115.1・#385・MAC-1・PLUG-1）。
//!
//! 呼び出し元は `main.rs` のみ。解決順は 1) `--socket <PATH>`（`--socket=<PATH>` 可）、
//! 2) 環境変数 `PLUGIN_SOCKET_ENV`（core の起動経路が設定する既存契約）、
//! 3) 既定 `RuntimeDir::from_env()` 配下の [`DEFAULT_SOCKET_NAME`]。
//!
//! 本モジュールは socket を開かない（bind も connect もしない）。解決したパスは検証済みの絶対パスで、
//! `main.rs` が `UdsStream::connect`（core が bind 済みの listener へ接続する既存契約）に使う。`sun_path` 長は既定パスを
//! `RuntimeDir::socket_path`、明示パスを本モジュールの `validate_explicit` が検証する。
//! 明示パスの配置ディレクトリの検証（所有者・権限・symlink。PLUG-12）は bind 側（core の `UdsListener::bind`）、
//! 接続時の server peer 検証は `UdsStream::connect` の責務である（TASK-115.4・#388）。
//!
//! 引数・環境変数は untrusted な外部入力として扱い、件数・合計バイト数を上限検証する。
//! エラーメッセージへ入力値は転記しない（固定文言。ログ行の偽装・情報漏えいの防止）。

use std::ffi::{OsStr, OsString};
use std::path::{Component, Path, PathBuf};

use fandhe_container_plugin::{
    ONE_SHOT_ARGS_MAX_BYTES, ONE_SHOT_ARGS_MAX_COUNT, PLUGIN_SOCKET_ENV, PluginError,
    PluginErrorCode, RuntimeDir,
};

/// socket パスを明示する起動フラグ。
pub const SOCKET_FLAG: &str = "--socket";

/// 既定の socket 名（暫定・spec 未規定。`PLUGIN_SOCKET_ENV` と同じく spec 確定時に見直す）。
pub const DEFAULT_SOCKET_NAME: &str = "plugin-macos.sock";

/// socket パスの出所。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketPathSource {
    /// 起動引数 `--socket`。
    Argument,
    /// 環境変数 `PLUGIN_SOCKET_ENV`。
    Environment,
    /// runtime directory 既定。
    RuntimeDirDefault,
}

impl SocketPathSource {
    /// 構造化ログ用の固定文字列。
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Argument => "argument",
            Self::Environment => "environment",
            Self::RuntimeDirDefault => "runtime_dir_default",
        }
    }
}

/// 解決済みの起動設定。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartupConfig {
    socket_path: PathBuf,
    source: SocketPathSource,
}

impl StartupConfig {
    /// 検証済みの socket 絶対パス。
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// パスの出所。
    pub fn source(&self) -> SocketPathSource {
        self.source
    }
}

/// 解析済みの起動引数。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StartupArgs {
    /// `--socket` の値（未検証。検証は [`resolve_socket_path`]）。
    pub socket: Option<PathBuf>,
}

/// 引数解析の結果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Invocation {
    /// `--help`。
    Help,
    /// 通常起動。
    Run(StartupArgs),
}

/// [`run`] の正常終了の種別（TASK-115.2 で `Ready` を追加）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunOutcome {
    /// 使用法の表示を要求された（呼び出し側が [`usage`] を出す）。
    HelpPrinted,
    /// 起動設定を解決できた。呼び出し側（`main.rs`）が socket へ接続して
    /// `frame_loop::serve` を駆動する（本モジュールは socket を開かない）。
    Ready(StartupConfig),
}

fn invalid(msg: &str) -> PluginError {
    PluginError::new(PluginErrorCode::InvalidArgument, msg)
}

/// 使用法の文字列。
pub fn usage() -> &'static str {
    "usage: fandhe-container-plugin-macos [--socket <ABSOLUTE_PATH>] [--help]\n"
}

/// 起動引数（`argv[0]` を除く）を解析する。
///
/// 件数・合計バイト数を `ONE_SHOT_ARGS_MAX_*` で上限検証し、未知フラグ・位置引数・
/// `--socket` の重複・値の欠落・空値は `InvalidArgument`。
pub fn parse_args<I: IntoIterator<Item = OsString>>(args: I) -> Result<Invocation, PluginError> {
    let mut count = 0usize;
    let mut total = 0usize;
    let mut socket: Option<PathBuf> = None;
    let mut help = false;
    let mut pending_value = false;
    for arg in args {
        count += 1;
        total = total.saturating_add(arg.len());
        if count > ONE_SHOT_ARGS_MAX_COUNT || total > ONE_SHOT_ARGS_MAX_BYTES {
            return Err(invalid("too many or too long arguments"));
        }
        if pending_value {
            pending_value = false;
            set_socket(&mut socket, arg.as_os_str())?;
            continue;
        }
        if arg == OsStr::new("--help") {
            help = true;
        } else if arg == OsStr::new(SOCKET_FLAG) {
            pending_value = true;
        } else if let Some(v) = strip_socket_prefix(&arg) {
            set_socket(&mut socket, v)?;
        } else {
            return Err(invalid("unknown argument"));
        }
    }
    if pending_value {
        return Err(invalid("missing value for --socket"));
    }
    if help {
        return Ok(Invocation::Help);
    }
    Ok(Invocation::Run(StartupArgs { socket }))
}

/// `--socket=<PATH>` 形式の値部分を取り出す。
///
/// unix ではパスが任意のバイト列のため `OsStr` のバイト列で接頭辞を判定し、非 UTF-8 の値も
/// `--socket <PATH>` 形式と同様に受理する。非 unix は `to_str` で判定する（Windows の
/// 孤立サロゲートを含む値は受理しない。現状 Windows は serving 未対応のため許容）。
fn strip_socket_prefix(arg: &OsStr) -> Option<&OsStr> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        arg.as_bytes()
            .strip_prefix(b"--socket=")
            .map(OsStr::from_bytes)
    }
    #[cfg(not(unix))]
    {
        arg.to_str()
            .and_then(|s| s.strip_prefix("--socket="))
            .map(OsStr::new)
    }
}

fn set_socket(slot: &mut Option<PathBuf>, value: &OsStr) -> Result<(), PluginError> {
    if slot.is_some() {
        return Err(invalid("duplicate --socket"));
    }
    if value.is_empty() {
        return Err(invalid("empty value for --socket"));
    }
    *slot = Some(PathBuf::from(value));
    Ok(())
}

/// `sockaddr_un.sun_path` の容量（終端 NUL を含むバイト数）。Linux は 108。
/// `fandhe_container_plugin` 内の同名検証（`RuntimeDir::socket_path` が使う）と同じ値で、
/// 同 crate では非公開のためここに持つ（PLUG-2）。
#[cfg(target_os = "linux")]
const SUN_PATH_CAPACITY: usize = 108;
/// macOS・BSD 系は 104。
#[cfg(all(unix, not(target_os = "linux")))]
const SUN_PATH_CAPACITY: usize = 104;

/// `path` が `sun_path` に収まる（終端 NUL を残せる）ことを確認する。非 unix は UDS 長制限なし。
fn check_sun_path_len(path: &Path) -> Result<(), PluginError> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        if path.as_os_str().as_bytes().len() >= SUN_PATH_CAPACITY {
            return Err(invalid("socket path is too long"));
        }
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

/// 明示パス（引数・環境変数）の検証: 絶対パス・`..` なし・`sun_path` 長以内（PLUG-2）。
fn validate_explicit(path: PathBuf) -> Result<PathBuf, PluginError> {
    // NUL を含むパスは UDS の sun_path として使えず後段で初めて失敗するため、ここで拒否する。
    // NUL は UTF-8 でも 1 バイトのまま保たれるため lossy 変換で全 OS 共通に検出できる。
    if path.as_os_str().to_string_lossy().contains('\0') {
        return Err(invalid("socket path must not contain NUL"));
    }
    if !path.is_absolute() {
        return Err(invalid("socket path must be absolute"));
    }
    if path.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err(invalid("socket path must not contain '..'"));
    }
    check_sun_path_len(&path)?;
    Ok(path)
}

/// socket パスを引数 → 環境変数 → 既定の順で解決する。
///
/// 環境と既定を注入できるのはユニットテストでプロセス環境を書き換えないため。
/// 環境変数が設定済みで空の場合は fail-closed で `InvalidArgument`（core が設定した値の
/// 破損を既定パスへ黙って倒さない）。既定側のエラーは握りつぶさずそのまま返す。
pub fn resolve_socket_path(
    args: &StartupArgs,
    env_socket: Option<&OsStr>,
    default: impl FnOnce() -> Result<PathBuf, PluginError>,
) -> Result<StartupConfig, PluginError> {
    if let Some(p) = &args.socket {
        return Ok(StartupConfig {
            socket_path: validate_explicit(p.clone())?,
            source: SocketPathSource::Argument,
        });
    }
    if let Some(v) = env_socket {
        if v.len() > ONE_SHOT_ARGS_MAX_BYTES {
            return Err(invalid("socket path from environment is too long"));
        }
        if v.is_empty() {
            return Err(invalid("empty socket path in environment"));
        }
        return Ok(StartupConfig {
            socket_path: validate_explicit(PathBuf::from(v))?,
            source: SocketPathSource::Environment,
        });
    }
    Ok(StartupConfig {
        socket_path: default()?,
        source: SocketPathSource::RuntimeDirDefault,
    })
}

/// 既定の socket パス（runtime directory を検証・作成する副作用あり。非 unix は `Unimplemented`）。
pub fn default_socket_path() -> Result<PathBuf, PluginError> {
    RuntimeDir::from_env()?.socket_path(DEFAULT_SOCKET_NAME)
}

/// 起動処理本体。
///
/// `--help` は `HelpPrinted`、通常起動はパス解決に成功すると `Ready` を返す。接続と送受信ループは
/// 呼び出し側（`main.rs`・`frame_loop`。TASK-115.2）の責務で、ここでは socket を開かない。
pub fn run<I: IntoIterator<Item = OsString>>(args: I) -> Result<RunOutcome, PluginError> {
    match parse_args(args)? {
        Invocation::Help => Ok(RunOutcome::HelpPrinted),
        Invocation::Run(a) => {
            let env = std::env::var_os(PLUGIN_SOCKET_ENV);
            let config = resolve_socket_path(&a, env.as_deref(), default_socket_path)?;
            Ok(RunOutcome::Ready(config))
        }
    }
}

#[cfg(test)]
mod tests {
    //! PLUG-1・MAC-1・TASK-115.1 の受け入れ条件（AC-2）を具体値で照合する。
    use super::*;

    fn os(v: &[&str]) -> Vec<OsString> {
        v.iter().map(OsString::from).collect()
    }
    fn abs(name: &str) -> PathBuf {
        std::env::temp_dir().join("dir").join(name)
    }
    fn no_default() -> Result<PathBuf, PluginError> {
        Err(PluginError::new(PluginErrorCode::Internal, "unused"))
    }
    fn parse_run(v: Vec<OsString>) -> StartupArgs {
        match parse_args(v).unwrap() {
            Invocation::Run(a) => a,
            Invocation::Help => panic!("unexpected help"),
        }
    }
    fn code<T: std::fmt::Debug>(r: Result<T, PluginError>) -> PluginErrorCode {
        r.unwrap_err().code()
    }

    #[test]
    fn socket_flag_space_form() {
        let p = abs("a.sock");
        let a = parse_run(vec![OsString::from("--socket"), p.clone().into_os_string()]);
        let c = resolve_socket_path(&a, None, no_default).unwrap();
        assert_eq!(c.socket_path(), p.as_path());
        assert_eq!(c.source(), SocketPathSource::Argument);
    }

    #[test]
    fn socket_flag_equals_form() {
        let p = abs("a.sock");
        let mut s = OsString::from("--socket=");
        s.push(p.as_os_str());
        let a = parse_run(vec![s]);
        let c = resolve_socket_path(&a, None, no_default).unwrap();
        assert_eq!(c.socket_path(), p.as_path());
    }

    #[test]
    fn env_used_when_no_argument() {
        let p = abs("e.sock");
        let c =
            resolve_socket_path(&StartupArgs::default(), Some(p.as_os_str()), no_default).unwrap();
        assert_eq!(c.socket_path(), p.as_path());
        assert_eq!(c.source(), SocketPathSource::Environment);
    }

    #[test]
    fn argument_wins_over_env() {
        let a = StartupArgs {
            socket: Some(abs("a.sock")),
        };
        let e = abs("e.sock");
        let c = resolve_socket_path(&a, Some(e.as_os_str()), no_default).unwrap();
        assert_eq!(c.socket_path(), abs("a.sock").as_path());
        assert_eq!(c.source(), SocketPathSource::Argument);
    }

    #[test]
    fn default_used_when_nothing_given() {
        let d = abs(DEFAULT_SOCKET_NAME);
        let d2 = d.clone();
        let c = resolve_socket_path(&StartupArgs::default(), None, move || Ok(d2)).unwrap();
        assert_eq!(c.socket_path(), d.as_path());
        assert_eq!(c.source(), SocketPathSource::RuntimeDirDefault);
    }

    #[test]
    fn relative_and_parent_paths_rejected() {
        let rel = StartupArgs {
            socket: Some(PathBuf::from("rel.sock")),
        };
        assert_eq!(
            code(resolve_socket_path(&rel, None, no_default)),
            PluginErrorCode::InvalidArgument
        );
        let dd = StartupArgs {
            socket: Some(abs("x").join("..").join("a.sock")),
        };
        assert_eq!(
            code(resolve_socket_path(&dd, None, no_default)),
            PluginErrorCode::InvalidArgument
        );
        let env = OsString::from("rel.sock");
        assert_eq!(
            code(resolve_socket_path(
                &StartupArgs::default(),
                Some(env.as_os_str()),
                no_default
            )),
            PluginErrorCode::InvalidArgument
        );
        assert_eq!(
            code(resolve_socket_path(
                &StartupArgs::default(),
                Some(OsStr::new("")),
                no_default
            )),
            PluginErrorCode::InvalidArgument
        );
    }

    #[test]
    fn malformed_arguments_rejected() {
        for v in [
            os(&["--socket"]),
            os(&["--socket="]),
            os(&["--socket", ""]),
            os(&["--socket", "/a", "--socket", "/b"]),
            os(&["--bogus"]),
            os(&["positional"]),
        ] {
            assert_eq!(code(parse_args(v)), PluginErrorCode::InvalidArgument);
        }
    }

    #[test]
    fn argument_limits_enforced() {
        let many = vec![OsString::from("--help"); ONE_SHOT_ARGS_MAX_COUNT + 1];
        assert_eq!(code(parse_args(many)), PluginErrorCode::InvalidArgument);
        let long = vec![OsString::from("a".repeat(ONE_SHOT_ARGS_MAX_BYTES + 1))];
        assert_eq!(code(parse_args(long)), PluginErrorCode::InvalidArgument);
    }

    #[cfg(unix)]
    fn path_of_len(n: usize) -> PathBuf {
        let mut s = String::from("/");
        s.push_str(&"a".repeat(n - 1));
        PathBuf::from(s)
    }

    /// PLUG-2: NUL を含む明示パス（引数・環境変数）は `InvalidArgument` で拒否する。
    #[test]
    fn explicit_path_with_nul_is_rejected() {
        let mut p = abs("a.sock").into_os_string();
        p.push("\0x");
        let a = StartupArgs {
            socket: Some(PathBuf::from(p.clone())),
        };
        assert_eq!(
            code(resolve_socket_path(&a, None, no_default)),
            PluginErrorCode::InvalidArgument
        );
        assert_eq!(
            code(resolve_socket_path(
                &StartupArgs::default(),
                Some(p.as_os_str()),
                no_default
            )),
            PluginErrorCode::InvalidArgument
        );
    }

    /// PLUG-2: 明示パスも `sun_path` 容量 - 1 は許可し、容量ちょうどは拒否する。
    #[cfg(unix)]
    #[test]
    fn explicit_path_sun_path_boundary() {
        let ok = path_of_len(SUN_PATH_CAPACITY - 1);
        let a = StartupArgs {
            socket: Some(ok.clone()),
        };
        assert_eq!(
            resolve_socket_path(&a, None, no_default)
                .unwrap()
                .socket_path(),
            ok.as_path()
        );
        let long = path_of_len(SUN_PATH_CAPACITY);
        let a = StartupArgs {
            socket: Some(long.clone()),
        };
        assert_eq!(
            code(resolve_socket_path(&a, None, no_default)),
            PluginErrorCode::InvalidArgument
        );
        assert_eq!(
            code(resolve_socket_path(
                &StartupArgs::default(),
                Some(long.as_os_str()),
                no_default
            )),
            PluginErrorCode::InvalidArgument
        );
    }

    /// 非 UTF-8 のパスは `--socket=` 形式でも空白区切り形式と同様に受理する。
    #[cfg(unix)]
    #[test]
    fn socket_flag_equals_form_accepts_non_utf8() {
        use std::os::unix::ffi::{OsStrExt, OsStringExt};
        let value = b"/tmp/\xff\xfe.sock".to_vec();
        let mut eq = b"--socket=".to_vec();
        eq.extend_from_slice(&value);
        let a = parse_run(vec![OsString::from_vec(eq)]);
        let b = parse_run(vec![
            OsString::from("--socket"),
            OsString::from_vec(value.clone()),
        ]);
        assert_eq!(a, b);
        assert_eq!(
            a.socket.as_deref().map(|p| p.as_os_str().as_bytes()),
            Some(value.as_slice())
        );
    }

    #[test]
    fn help_is_recognized() {
        assert_eq!(parse_args(os(&["--help"])).unwrap(), Invocation::Help);
        assert!(usage().contains("--socket"));
    }

    #[test]
    fn default_error_propagates() {
        let r = resolve_socket_path(&StartupArgs::default(), None, || {
            Err(PluginError::new(PluginErrorCode::Unimplemented, "x"))
        });
        assert_eq!(code(r), PluginErrorCode::Unimplemented);
    }
}
