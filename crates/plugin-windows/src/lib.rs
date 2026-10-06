//! fandhe-container-plugin-windows: Windows バックエンド plugin バイナリ（`fandhe-container-platform-windows` の実装を別プロセス化）。
//!
//! 本 crate は lib（起動設定の解決ロジック。本ファイル）と bin（`src/main.rs`。薄い入口）で構成する。
//! バイナリ名 `fandhe-container-plugin-windows` は発見規約の接頭辞に一致する（PLUG-4・PLUG-11）。
//! core 側 proxy が `OneShotPlugin` / `ResidentPlugin` 経由で spawn する（TASK-114）。
//! 既存契約では socket の絶対パスは `env_clear()` 後に環境変数 [`PLUGIN_SOCKET_ENV`] のみで渡る。
//!
//! # 未実装範囲（REPAIR-3）
//! 本 sub（TASK-116.1・#392）は雛形で、UDS への bind / connect・フレーム送受信（#393）、
//! `ContainerRuntime` アダプタ（#394）、peer 認証・discovery 登録（#395）、
//! シャットダウン・ヘルスチェック（#396）は未実装。実行時は WSL2 内の Linux で動く前提（WIN-1）で、
//! 非 unix ネイティブビルドでは既定パス解決が `Unimplemented` となり fail-closed になる。
//!
//! # 暫定契約（spec 未規定）
//! 引数構文 `--socket <path>` / `--socket=<path>` と既定 socket 名 [`DEFAULT_SOCKET_NAME`] は本リポ独自の暫定値。
//! 接続方向（core が bind し plugin が connect する既存契約か、plugin が bind するか）は #395 で確定する。
//!
//! 対応 ID: TASK-116・PLUG-1・PLUG-4・PLUG-11・PLUG-12・WIN-1・REPAIR-3。

use std::ffi::{OsStr, OsString};
use std::path::{Component, Path, PathBuf};

pub use fandhe_container_plugin::PLUGIN_SOCKET_ENV;
use fandhe_container_plugin::{
    ONE_SHOT_ARGS_MAX_BYTES, ONE_SHOT_ARGS_MAX_COUNT, PluginError, PluginErrorCode, RuntimeDir,
};

/// socket パスを指定する起動引数名（暫定構文）。
pub const SOCKET_ARG: &str = "--socket";

/// 既定の socket ファイル名（暫定。spec は plugin 個別の名前を規定していない）。
pub const DEFAULT_SOCKET_NAME: &str = "plugin-windows.sock";

/// socket パスの決定元。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SocketSource {
    /// 起動引数 `--socket`。
    Arg,
    /// 環境変数 [`PLUGIN_SOCKET_ENV`]。
    Env,
    /// 検証済み runtime directory 下の既定名。
    Default,
}

impl SocketSource {
    /// 構造化出力用の機械可読名。
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Arg => "arg",
            Self::Env => "env",
            Self::Default => "default",
        }
    }
}

/// 解決済みの起動設定。bind / connect 前の値であり、`sun_path` 長・配置ディレクトリの
/// 所有者 / 権限・symlink の検証は `fandhe-container-plugin` の transport 層の責務（#395。ここでは二重実装しない）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct StartupConfig {
    socket_path: PathBuf,
    socket_source: SocketSource,
}

impl StartupConfig {
    /// 解決された socket パス。
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// socket パスの決定元。
    pub fn socket_source(&self) -> SocketSource {
        self.socket_source
    }
}

fn invalid(msg: &str) -> PluginError {
    PluginError::new(PluginErrorCode::InvalidArgument, msg)
}

/// 外部入力のパスを検証する（絶対パス・`..` なし・空でない）。メッセージに入力値を含めない。
fn validate_path(value: &OsStr) -> Result<PathBuf, PluginError> {
    if value.is_empty() {
        return Err(invalid("socket path is empty"));
    }
    let path = PathBuf::from(value);
    if !path.is_absolute() {
        return Err(invalid("socket path must be absolute"));
    }
    if path.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err(invalid("socket path must not contain parent components"));
    }
    Ok(path)
}

/// 起動引数（プログラム名を除く）・環境変数値・既定パス取得関数から起動設定を解決する。
///
/// 優先順位は `--socket` ＞ 環境変数 ＞ 既定。`default_path` は引数・環境変数が無い場合に限り
/// 遅延して呼ぶ（`RuntimeDir::from_env` がディレクトリ作成・残骸掃除の副作用を持つため）。
/// argv / env は untrusted: 件数・合計バイト数の上限（親の spawn 経路と同値）、未知引数・重複・
/// 値欠落・相対パス・`..` を `InvalidArgument` で拒否する。空の環境変数は未設定扱い。
pub fn resolve_startup<I, F>(
    args: I,
    env_socket: Option<OsString>,
    default_path: F,
) -> Result<StartupConfig, PluginError>
where
    I: IntoIterator<Item = OsString>,
    F: FnOnce() -> Result<PathBuf, PluginError>,
{
    let mut count = 0usize;
    let mut bytes = 0usize;
    let mut from_arg: Option<OsString> = None;
    let mut iter = args.into_iter();
    while let Some(arg) = iter.next() {
        let value = if arg == OsStr::new(SOCKET_ARG) {
            let v = iter.next().ok_or_else(|| invalid("missing socket value"))?;
            count += 2;
            bytes = bytes.saturating_add(arg.len()).saturating_add(v.len());
            v
        } else if let Some(v) = strip_eq_form(&arg) {
            count += 1;
            bytes = bytes.saturating_add(arg.len());
            v
        } else {
            return Err(invalid("unknown argument"));
        };
        if count > ONE_SHOT_ARGS_MAX_COUNT || bytes > ONE_SHOT_ARGS_MAX_BYTES {
            return Err(invalid("too many or too large arguments"));
        }
        if from_arg.replace(value).is_some() {
            return Err(invalid("duplicate socket argument"));
        }
    }

    if let Some(v) = from_arg {
        return Ok(StartupConfig {
            socket_path: validate_path(&v)?,
            socket_source: SocketSource::Arg,
        });
    }
    if let Some(v) = env_socket.filter(|v| !v.is_empty()) {
        return Ok(StartupConfig {
            socket_path: validate_path(&v)?,
            socket_source: SocketSource::Env,
        });
    }
    Ok(StartupConfig {
        socket_path: default_path()?,
        socket_source: SocketSource::Default,
    })
}

/// `--socket=<path>` 形式の値部分を返す。
fn strip_eq_form(arg: &OsStr) -> Option<OsString> {
    let s = arg.to_str()?;
    let rest = s.strip_prefix(SOCKET_ARG)?.strip_prefix('=')?;
    Some(OsString::from(rest))
}

/// 既定 socket パス（検証済み runtime directory 直下。`/tmp` へは落とさない。PLUG-12）。
pub fn default_socket_path() -> Result<PathBuf, PluginError> {
    RuntimeDir::from_env()?.socket_path(DEFAULT_SOCKET_NAME)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    fn os(s: &str) -> OsString {
        OsString::from(s)
    }

    #[cfg(unix)]
    const ABS: &str = "/run/user/1000/a.sock";
    #[cfg(not(unix))]
    const ABS: &str = "C:\\run\\a.sock";

    fn no_default() -> Result<PathBuf, PluginError> {
        panic!("default must not be called")
    }

    fn code(r: Result<StartupConfig, PluginError>) -> PluginErrorCode {
        match r {
            Err(e) => e.code(),
            Ok(_) => panic!("expected error"),
        }
    }

    #[test]
    fn plug1_arg_both_forms() {
        let c = resolve_startup([os("--socket"), os(ABS)], None, no_default).unwrap();
        assert_eq!(c.socket_path(), Path::new(ABS));
        assert_eq!(c.socket_source(), SocketSource::Arg);
        let c = resolve_startup([os(&format!("--socket={ABS}"))], None, no_default).unwrap();
        assert_eq!(c.socket_path(), Path::new(ABS));
        assert_eq!(c.socket_source(), SocketSource::Arg);
    }

    #[test]
    fn plug1_env_only_and_arg_wins() {
        let c = resolve_startup([], Some(os(ABS)), no_default).unwrap();
        assert_eq!(c.socket_source(), SocketSource::Env);
        let other = if cfg!(unix) {
            "/x/b.sock"
        } else {
            "C:\\x\\b.sock"
        };
        let c = resolve_startup([os("--socket"), os(other)], Some(os(ABS)), no_default).unwrap();
        assert_eq!(c.socket_path(), Path::new(other));
        assert_eq!(c.socket_source(), SocketSource::Arg);
    }

    #[test]
    fn plug1_default_is_lazy() {
        let calls = Cell::new(0);
        let d = || {
            calls.set(calls.get() + 1);
            Ok(PathBuf::from("/d/plugin-windows.sock"))
        };
        let c = resolve_startup([], Some(os("")), d).unwrap();
        assert_eq!(c.socket_source(), SocketSource::Default);
        assert_eq!(c.socket_path(), Path::new("/d/plugin-windows.sock"));
        assert_eq!(calls.get(), 1);
        let calls0 = Cell::new(0);
        let d0 = || {
            calls0.set(1);
            Ok(PathBuf::new())
        };
        resolve_startup([], Some(os(ABS)), d0).unwrap();
        assert_eq!(calls0.get(), 0);
    }

    #[test]
    fn plug12_default_error_propagates() {
        let r = resolve_startup([], None, || {
            Err(PluginError::new(PluginErrorCode::Unimplemented, "x"))
        });
        assert_eq!(code(r), PluginErrorCode::Unimplemented);
    }

    #[test]
    fn plug12_rejects_invalid_inputs() {
        let cases: Vec<Vec<OsString>> = vec![
            vec![os("--socket"), os("rel/a.sock")],
            vec![os("--socket"), os("/a/../b.sock")],
            vec![os("--socket"), os("")],
            vec![os("--socket=")],
            vec![os("--socket")],
            vec![os("--bogus")],
            vec![os("--socket"), os(ABS), os("--socket"), os(ABS)],
            (0..=ONE_SHOT_ARGS_MAX_COUNT)
                .map(|_| os("--bogus"))
                .collect(),
            vec![
                os("--socket"),
                os(&format!("/{}", "a".repeat(ONE_SHOT_ARGS_MAX_BYTES))),
            ],
        ];
        for args in cases {
            assert_eq!(
                code(resolve_startup(args, None, no_default)),
                PluginErrorCode::InvalidArgument
            );
        }
        assert_eq!(
            code(resolve_startup([], Some(os("rel.sock")), no_default)),
            PluginErrorCode::InvalidArgument
        );
    }

    #[test]
    fn plug12_error_message_has_no_input_value() {
        let e =
            resolve_startup([os("--socket"), os("secret-rel/x")], None, no_default).unwrap_err();
        assert_eq!(e.message(), "socket path must be absolute");
    }
}
