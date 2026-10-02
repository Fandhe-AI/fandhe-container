//! plugin 境界の UDS 転送層（PLUG-2・TASK-107.4・#248・MS-3）。
//!
//! core 側が plugin プロセスからの接続を待ち受ける `UdsListener`（bind / listen / accept）と、
//! 受け付けた 1 接続を表す `UdsStream` を提供する。待ち受けは core 側（TASK-109・TASK-114）、
//! 接続は plugin プロセス側（#249）が使う。フレーム符号化（#245・#247）は本型の `Read` / `Write`
//! の上に載る。
//!
//! # 実装済みでない範囲（REPAIR-3）
//!
//! 本モジュールは **権限・配置・peer 認証を持たない未保護の状態** であり、
//! TASK-123・TASK-124（PLUG-12）が完了するまで本番の信頼境界として使えない。
//!
//! - socket 配置ディレクトリの検証: 親が symlink でない・他者書き込み不可・所有者一致までを
//!   bind 時に実施済み（簡易版）。0700 の厳密化は TASK-123・TASK-124（PLUG-12）
//! - socket ファイルの 0600 化は bind 直後に実施済み（umask 起因の短い窓は TASK-123 で解消）。
//!   自 UID 所有 stale socket の再 bind は TASK-123・TASK-124（PLUG-12）。
//!   本実装は既存パスを一切 unlink せず `AlreadyExists` で拒否する
//! - peer credential（`SO_PEERCRED` / `getpeereid`）検証: TASK-123・TASK-124（PLUG-12）
//! - client 接続（#249）・ACK/RPC タイムアウト（#250）・gRPC（TASK-108）
//!
//! # cfg 方針
//!
//! 実体は `cfg(unix)` の `std::os::unix::net` のみ。それ以外の OS では `bind` が
//! `Unimplemented` を返す（Windows は WIN-1 により WSL2 内の Linux 側機構に乗る）。

use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::error::{PluginError, PluginErrorCode};

/// `accept` の期限の上限。これを超える指定は `InvalidArgument`（REPAIR-5）。
///
/// #250（TASK-107.6）でタイムアウト型を導入する際、`accept` の引数型を揃える可能性がある。
pub const UDS_ACCEPT_TIMEOUT_MAX: Duration = Duration::from_secs(600);

/// plugin からの接続を待ち受ける UDS listener（PLUG-2）。
///
/// 権限・peer 認証は未実装で、TASK-123・TASK-124（PLUG-12）で実装する。
/// Drop 時は自分が作った socket ファイルに限り best-effort で削除する。
#[derive(Debug)]
pub struct UdsListener {
    inner: imp::ListenerInner,
    path: PathBuf,
}

impl UdsListener {
    /// `path` に UDS を bind し listen する（PLUG-2）。
    ///
    /// 既存パスは unlink せず `AlreadyExists` で拒否する（fail-closed）。
    /// 配置検証・0600 化・stale 処理は TASK-123・TASK-124（PLUG-12）で実装する。
    pub fn bind(path: &Path) -> Result<Self, PluginError> {
        let inner = imp::ListenerInner::bind(path)?;
        Ok(Self {
            inner,
            path: path.to_path_buf(),
        })
    }

    /// 1 接続を期限付きで受け付ける（REPAIR-5）。
    ///
    /// `timeout` が 0 または [`UDS_ACCEPT_TIMEOUT_MAX`] 超なら `InvalidArgument`、期限切れは `Timeout`。
    /// 1 呼び出しで 1 接続まで。受付ループ・同時接続数の上限は呼び出し側（TASK-109・TASK-114）の責務。
    /// 返す接続は **peer 未認証** であり、TASK-124（PLUG-12）完了までは信頼境界として使えない。
    pub fn accept(&self, timeout: Duration) -> Result<UdsStream, PluginError> {
        if timeout.is_zero() || timeout > UDS_ACCEPT_TIMEOUT_MAX {
            return Err(PluginError::new(
                PluginErrorCode::InvalidArgument,
                "accept timeout must be non-zero and within the maximum",
            ));
        }
        self.inner.accept(timeout).map(|inner| UdsStream { inner })
    }

    /// bind したパスを返す。
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for UdsListener {
    fn drop(&mut self) {
        // 自分が bind した socket と同一性が確認できる場合のみ削除する。
        // 検査と削除の間の競合窓・所有者検証は TASK-123（PLUG-12）で扱う。
        self.inner.cleanup(&self.path);
    }
}

/// 受け付けた 1 接続（未認証。TASK-124・PLUG-12 で peer credential 検証を追加する）。
///
/// #247 のフレーム符号化・#249 の client が載せられるよう `Read` / `Write` のみを提供する。
#[derive(Debug)]
pub struct UdsStream {
    inner: imp::StreamInner,
}

impl Read for UdsStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

impl Write for UdsStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// `bind` の `io::Error` を `PluginError` へ写像する。相手由来データはメッセージへ載せない。
#[cfg_attr(not(unix), allow(dead_code))]
fn map_bind_error(kind: io::ErrorKind) -> PluginError {
    let (code, message) = match kind {
        io::ErrorKind::AddrInUse | io::ErrorKind::AlreadyExists => (
            PluginErrorCode::AlreadyExists,
            "socket path is already in use",
        ),
        io::ErrorKind::PermissionDenied => (
            PluginErrorCode::PermissionDenied,
            "permission denied while binding socket",
        ),
        io::ErrorKind::NotFound => (
            PluginErrorCode::NotFound,
            "socket parent directory does not exist",
        ),
        io::ErrorKind::InvalidInput => (PluginErrorCode::InvalidArgument, "invalid socket path"),
        _ => (PluginErrorCode::Internal, "failed to bind socket"),
    };
    PluginError::new(code, message)
}

#[cfg(unix)]
mod imp {
    use super::map_bind_error;
    use crate::error::{PluginError, PluginErrorCode};
    use std::io::{self, Read, Write};
    use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::Path;
    use std::thread;
    use std::time::{Duration, Instant};

    /// accept のポーリング間隔（busy loop 回避。crates/io の ACCEPT_POLL_INTERVAL に合わせる）。
    const ACCEPT_POLL_INTERVAL: Duration = Duration::from_millis(5);

    /// bind 先の親ディレクトリ（相対パスなら cwd）。
    fn parent_of(path: &Path) -> Option<&Path> {
        match path.parent() {
            Some(p) if p.as_os_str().is_empty() => Some(Path::new(".")),
            other => other,
        }
    }

    /// 親ディレクトリが symlink でなく、group/other 書き込み不可（sticky なしの場合）であることを検証する（PLUG-12）。
    fn check_parent_dir(path: &Path) -> Result<(), PluginError> {
        let denied = |m: &'static str| PluginError::new(PluginErrorCode::PermissionDenied, m);
        let parent =
            parent_of(path).ok_or_else(|| denied("socket path has no parent directory"))?;
        let meta = std::fs::symlink_metadata(parent).map_err(|e| map_bind_error(e.kind()))?;
        if !meta.file_type().is_dir() {
            return Err(denied("socket parent is not a directory"));
        }
        if meta.mode() & 0o022 != 0 {
            return Err(denied("socket parent directory is writable by others"));
        }
        Ok(())
    }

    #[derive(Debug)]
    pub(super) struct ListenerInner {
        listener: UnixListener,
        /// bind 直後の socket の (dev, ino)。取得失敗時は None（Drop で削除しない）。
        identity: Option<(u64, u64)>,
    }

    impl ListenerInner {
        pub(super) fn bind(path: &Path) -> Result<Self, PluginError> {
            check_parent_dir(path)?;
            let listener = UnixListener::bind(path).map_err(|e| map_bind_error(e.kind()))?;
            let meta = std::fs::symlink_metadata(path).ok();
            let identity = meta.as_ref().map(|m| (m.dev(), m.ino()));
            // 以降の設定が失敗しても socket ファイルを残さないよう、先に Drop 相当の後始末を持つ値を作る。
            let inner = Self { listener, identity };
            if let Err(e) = inner.configure(path, meta.as_ref().map(|m| m.uid())) {
                inner.cleanup(path);
                return Err(e);
            }
            Ok(inner)
        }

        /// bind 直後の設定（nonblocking 化・0600 化・所有者確認。PLUG-12 の一部）。
        /// 失敗時の socket 削除は呼び出し側（`bind`）が行う。
        fn configure(&self, path: &Path, owner: Option<u32>) -> Result<(), PluginError> {
            self.listener.set_nonblocking(true).map_err(|_| {
                PluginError::new(PluginErrorCode::Internal, "failed to configure listener")
            })?;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(
                |_| PluginError::new(PluginErrorCode::Internal, "failed to restrict socket mode"),
            )?;
            // 作成直後の socket の所有者は自プロセスの euid。親ディレクトリ所有者と一致しなければ拒否する。
            let parent_uid = parent_of(path)
                .and_then(|p| std::fs::symlink_metadata(p).ok())
                .map(|m| m.uid());
            if owner.is_none() || parent_uid != owner {
                return Err(PluginError::new(
                    PluginErrorCode::PermissionDenied,
                    "socket directory is not owned by the current user",
                ));
            }
            Ok(())
        }

        pub(super) fn accept(&self, timeout: Duration) -> Result<StreamInner, PluginError> {
            let deadline = Instant::now() + timeout;
            loop {
                match self.listener.accept() {
                    Ok((stream, _)) => {
                        // macOS 等は listener の nonblocking を継承するため明示的に戻す。
                        stream.set_nonblocking(false).map_err(|_| {
                            PluginError::new(
                                PluginErrorCode::Internal,
                                "failed to configure accepted stream",
                            )
                        })?;
                        return Ok(StreamInner { stream });
                    }
                    Err(e)
                        if matches!(
                            e.kind(),
                            io::ErrorKind::WouldBlock
                                | io::ErrorKind::Interrupted
                                | io::ErrorKind::ConnectionAborted
                        ) =>
                    {
                        let now = Instant::now();
                        if now >= deadline {
                            return Err(PluginError::new(
                                PluginErrorCode::Timeout,
                                "timed out waiting for a connection",
                            ));
                        }
                        thread::sleep((deadline - now).min(ACCEPT_POLL_INTERVAL));
                    }
                    Err(_) => {
                        return Err(PluginError::new(
                            PluginErrorCode::Internal,
                            "failed to accept connection",
                        ));
                    }
                }
            }
        }

        pub(super) fn cleanup(&self, path: &Path) {
            let Some((dev, ino)) = self.identity else {
                return;
            };
            if let Ok(m) = std::fs::symlink_metadata(path)
                && m.file_type().is_socket()
                && m.dev() == dev
                && m.ino() == ino
            {
                let _ = std::fs::remove_file(path);
            }
        }
    }

    #[derive(Debug)]
    pub(super) struct StreamInner {
        stream: UnixStream,
    }

    impl StreamInner {
        pub(super) fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.stream.read(buf)
        }
        pub(super) fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.stream.write(buf)
        }
        pub(super) fn flush(&mut self) -> io::Result<()> {
            self.stream.flush()
        }
    }
}

#[cfg(not(unix))]
mod imp {
    use crate::error::{PluginError, PluginErrorCode};
    use std::io;
    use std::path::Path;
    use std::time::Duration;

    /// 構築不能（非 unix では listener を作れない）。
    #[derive(Debug)]
    pub(super) enum ListenerInner {}

    #[derive(Debug)]
    pub(super) enum StreamInner {}

    impl ListenerInner {
        pub(super) fn bind(_path: &Path) -> Result<Self, PluginError> {
            Err(PluginError::new(
                PluginErrorCode::Unimplemented,
                "unix domain socket listener is not supported on this platform",
            ))
        }
        pub(super) fn accept(&self, _timeout: Duration) -> Result<StreamInner, PluginError> {
            match *self {}
        }
        pub(super) fn cleanup(&self, _path: &Path) {
            match *self {}
        }
    }

    impl StreamInner {
        pub(super) fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
            match *self {}
        }
        pub(super) fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
            match *self {}
        }
        pub(super) fn flush(&mut self) -> io::Result<()> {
            match *self {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// PLUG-2: bind の ErrorKind 写像（具体値で照合）。
    #[test]
    fn plug2_map_bind_error_maps_io_error_kinds() {
        let cases = [
            (io::ErrorKind::AddrInUse, PluginErrorCode::AlreadyExists),
            (
                io::ErrorKind::PermissionDenied,
                PluginErrorCode::PermissionDenied,
            ),
            (io::ErrorKind::NotFound, PluginErrorCode::NotFound),
            (
                io::ErrorKind::InvalidInput,
                PluginErrorCode::InvalidArgument,
            ),
            (io::ErrorKind::Other, PluginErrorCode::Internal),
        ];
        for (kind, code) in cases {
            assert_eq!(map_bind_error(kind).code(), code);
        }
    }
}
