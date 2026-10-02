//! plugin 境界の UDS 転送層（PLUG-2・TASK-107.4・#248・MS-3）。
//!
//! core 側が plugin プロセスからの接続を待ち受ける `UdsListener`（bind / listen / accept）と、
//! 受け付けた 1 接続を表す `UdsStream` を提供する。待ち受けは core 側（TASK-109・TASK-114）、
//! 接続は plugin プロセス側（#249）が使う。フレーム符号化（#245・#247）は本型の `Read` / `Write`
//! の上に載る。
//!
//! # PLUG-12 の保護（本モジュールで実施する範囲）
//!
//! - bind 前に socket 配置ディレクトリを検証する: symlink でない・自 UID 所有・group/other の
//!   権限が一切ない（0700 相当）。他 UID はこのディレクトリを辿れないため、socket の mode が
//!   bind 直後の umask 次第でも他 UID が接続できる窓は生じない（0600 化は多層防御）
//! - 配置ディレクトリへの経路は `canonicalize` 後にルートから 1 要素ずつ `openat(O_NOFOLLOW)` で
//!   辿り（検証後に祖先が symlink へ差し替わると失敗）、bind 自体も検証済み fd 基準で行う
//!   （Linux は `/proc/self/fd/<fd>/<name>`。祖先パスを再解決しない。macOS は残余あり: `bind_in_dir` 参照）
//! - 配置ディレクトリは 1 度だけ開いた fd（検証対象そのもの）を保持し、bind 後の 0600 化
//!   （`fchmodat(dirfd, name, AT_SYMLINK_NOFOLLOW)`）と Drop 時の削除（`unlinkat(dirfd, name)`）は
//!   その fd 基準で行う。パスを再解決しないため、検証後に中間要素・`..`・symlink が差し替わっても
//!   別ファイルの chmod・削除には到達しない。bind パスの `..` は拒否する
//! - 残余: 0700 の自 UID 所有ディレクトリ内でエントリを差し替えられるのは同一 UID のみで、
//!   同一 UID は脅威モデル外（socket と同一性の照合は行わず、ディレクトリ fd 基準で名前を操作する）
//! - accept した接続の peer credential（`SO_PEERCRED` / `getpeereid`。`crate::sys`）を検証し、
//!   自 UID 以外は切断して `PermissionDenied` を返す
//! - 受け付けた接続には既定の read / write 期限を付ける（REPAIR-5）
//!
//! # 未実装の範囲（REPAIR-3）
//!
//! - 自 UID 所有 stale socket の再 bind は TASK-123・TASK-124（PLUG-12）。本実装は既存パスを
//!   一切 unlink せず `AlreadyExists` で拒否する
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

/// 受け付けた接続の既定の read / write 期限（REPAIR-5）。
/// [`UdsStream::set_io_timeout`] で変更できる（#250 で RPC タイムアウト型へ統合予定）。
pub const UDS_DEFAULT_IO_TIMEOUT: Duration = Duration::from_secs(30);

/// plugin からの接続を待ち受ける UDS listener（PLUG-2・PLUG-12）。
///
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
    /// 配置ディレクトリ（symlink 不可・自 UID 所有・0700 相当）を検証してから bind する。
    /// 相対パスは bind 時点の絶対パスへ変換して保持する（Drop 時の cwd 変更の影響を避ける）。
    /// stale 処理は TASK-123・TASK-124（PLUG-12）。
    pub fn bind(path: &Path) -> Result<Self, PluginError> {
        // `..` は bind 時点とそれ以降で解決先が変わりうるため拒否する（`std::path::absolute` は
        // `..` を残す。PLUG-12）。
        if path
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            return Err(PluginError::new(
                PluginErrorCode::InvalidArgument,
                "socket path must not contain parent directory components",
            ));
        }
        let abs = std::path::absolute(path).map_err(|_| {
            PluginError::new(PluginErrorCode::InvalidArgument, "invalid socket path")
        })?;
        let inner = imp::ListenerInner::bind(&abs)?;
        Ok(Self { inner, path: abs })
    }

    /// 1 接続を期限付きで受け付ける（REPAIR-5）。
    ///
    /// `timeout` が 0 または [`UDS_ACCEPT_TIMEOUT_MAX`] 超なら `InvalidArgument`、期限切れは `Timeout`。
    /// 1 呼び出しで 1 接続まで。受付ループ・同時接続数の上限は呼び出し側（TASK-109・TASK-114）の責務。
    /// 返す接続は peer credential が自 UID であることを確認済み。不一致は接続を切断して
    /// `PermissionDenied` を返す（呼び出し側の受付ループは継続してよい）。
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
        // 検証済み配置ディレクトリ fd 基準の unlinkat で削除する（パス再解決なし）。
        // stale socket の所有者検証・再 bind は TASK-123・TASK-124（PLUG-12）で扱う。
        self.inner.cleanup();
    }
}

/// 受け付けた 1 接続（peer credential 検証済み。PLUG-12）。read / write には
/// [`UDS_DEFAULT_IO_TIMEOUT`] の期限が付く（REPAIR-5）。
///
/// #247 のフレーム符号化・#249 の client が載せられるよう `Read` / `Write` のみを提供する。
#[derive(Debug)]
pub struct UdsStream {
    inner: imp::StreamInner,
}

impl UdsStream {
    /// read / write の期限を変更する。0 は `InvalidArgument`（無期限にしない。REPAIR-5）。
    pub fn set_io_timeout(&self, timeout: Duration) -> Result<(), PluginError> {
        self.inner.set_io_timeout(timeout)
    }
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
    use super::{UDS_DEFAULT_IO_TIMEOUT, map_bind_error};
    use crate::error::{PluginError, PluginErrorCode};
    use crate::sys;
    use std::ffi::CString;
    use std::fs::File;
    use std::io::{self, Read, Write};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::{Path, PathBuf};
    use std::thread;
    use std::time::{Duration, Instant};

    /// accept のポーリング間隔（busy loop 回避。crates/io の ACCEPT_POLL_INTERVAL に合わせる）。
    const ACCEPT_POLL_INTERVAL: Duration = Duration::from_millis(5);

    fn denied(m: &'static str) -> PluginError {
        PluginError::new(PluginErrorCode::PermissionDenied, m)
    }

    /// 親ディレクトリを開き、symlink でなく、自 UID 所有で、group/other の権限が一切ないことを
    /// 開いた fd 自体に対して検証する（PLUG-12）。以降の chmod・unlink はこの fd 基準で行う。
    /// 他 UID は辿れないため、socket の mode が umask 次第でも他 UID が接続できる窓は生じない。
    fn open_parent_dir(path: &Path, euid: u32) -> Result<(File, PathBuf), PluginError> {
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .ok_or_else(|| denied("socket path has no parent directory"))?;
        let link_meta = std::fs::symlink_metadata(parent).map_err(|e| map_bind_error(e.kind()))?;
        if !link_meta.file_type().is_dir() {
            return Err(denied("socket parent is not a directory"));
        }
        // 祖先要素の symlink は canonicalize で解決した上で、解決後の絶対パスをルートから
        // 1 要素ずつ O_NOFOLLOW で辿って fd を得る。canonicalize 後に祖先が symlink へ差し替わると
        // openat が失敗する（fail-closed。PLUG-12）。
        let canonical = std::fs::canonicalize(parent).map_err(|e| map_bind_error(e.kind()))?;
        let dir = sys::open_dir_nofollow(&canonical).map_err(|e| match e.kind() {
            io::ErrorKind::NotFound => map_bind_error(e.kind()),
            _ => denied("socket directory path could not be opened without following symlinks"),
        })?;
        let meta = dir.metadata().map_err(|e| map_bind_error(e.kind()))?;
        // 開いた fd が symlink 判定した実体と同一であること（検査と open の間の差し替え検出）。
        if !meta.file_type().is_dir()
            || meta.dev() != link_meta.dev()
            || meta.ino() != link_meta.ino()
        {
            return Err(denied("socket directory changed during bind"));
        }
        if meta.uid() != euid {
            return Err(denied("socket directory is not owned by the current user"));
        }
        if meta.mode() & 0o077 != 0 {
            return Err(denied(
                "socket directory must not be accessible by group or others",
            ));
        }
        Ok((dir, canonical))
    }

    /// 検証済みディレクトリ fd 基準で `name` に bind する（PLUG-12）。
    ///
    /// Linux: `/proc/self/fd/<fd>/<name>` 経由で bind するため、kernel が検証済み fd の指す
    /// ディレクトリ直下に socket を作る（祖先パスの再解決なし。`/proc` 不在なら失敗＝fail-closed）。
    /// 他の unix（macOS）: `bindat` 相当が無いため `canonical/name` へ bind し、直後の
    /// `configure`（fd 基準の所有者・種別確認と 0600 化）で検証する。残余: 祖先ディレクトリの
    /// 書き込み権限を持つ他主体が bind の瞬間に差し替える窓が残る（TASK-123・TASK-124 で再検討）。
    fn bind_in_dir(dir: &File, canonical: &Path, name: &Path) -> io::Result<UnixListener> {
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::io::AsRawFd;
            let _ = canonical;
            let via_fd = Path::new("/proc/self/fd")
                .join(dir.as_raw_fd().to_string())
                .join(name);
            UnixListener::bind(via_fd)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = dir;
            UnixListener::bind(canonical.join(name))
        }
    }

    #[derive(Debug)]
    pub(super) struct ListenerInner {
        listener: UnixListener,
        /// 検証済みの配置ディレクトリ fd（chmod・unlink の基準。パスを再解決しない）。
        dir: File,
        /// 配置ディレクトリ内の socket 名（NUL を含まない）。
        name: CString,
        /// bind したパス（Linux 以外の identity 取得の縮退用。Linux では使わない）。
        path: PathBuf,
        /// bind 直後の socket の識別情報。取得失敗時は None（Drop で削除しない）。
        identity: Option<sys::FileIdent>,
        /// bind 時点の自プロセスの実効 uid（accept ごとの peer 照合の基準）。
        euid: u32,
    }

    impl ListenerInner {
        /// `path` は `..` を含まない絶対パス（`UdsListener::bind` が検証・変換済み）。
        pub(super) fn bind(path: &Path) -> Result<Self, PluginError> {
            let euid = sys::effective_uid();
            let (dir, canonical) = open_parent_dir(path, euid)?;
            let file_name = path.file_name().ok_or_else(|| {
                PluginError::new(PluginErrorCode::InvalidArgument, "invalid socket path")
            })?;
            let name = CString::new(file_name.as_bytes()).map_err(|_| {
                PluginError::new(PluginErrorCode::InvalidArgument, "invalid socket path")
            })?;
            let listener = bind_in_dir(&dir, &canonical, Path::new(file_name))
                .map_err(|e| map_bind_error(e.kind()))?;
            let bound = canonical.join(file_name);
            // 以降の設定が失敗しても socket ファイルを残さないよう、先に後始末を持つ値を作る。
            let identity = sys::lstat_at(&dir, &name, &bound).ok();
            let inner = Self {
                listener,
                dir,
                name,
                path: bound,
                identity,
                euid,
            };
            if let Err(e) = inner.configure() {
                inner.cleanup();
                return Err(e);
            }
            Ok(inner)
        }

        /// bind 直後の設定（nonblocking 化・0600 化。PLUG-12）。
        /// 0600 化は検証済みディレクトリ fd 基準の `fchmodat(AT_SYMLINK_NOFOLLOW)`。差し替えで
        /// 名前が別ディレクトリへ解決された場合は ENOENT・symlink なら拒否となり失敗する（fail-closed）。
        /// 失敗時の socket 削除は呼び出し側（`bind`）が行う。
        fn configure(&self) -> Result<(), PluginError> {
            self.listener.set_nonblocking(true).map_err(|_| {
                PluginError::new(PluginErrorCode::Internal, "failed to configure listener")
            })?;
            // 作成した自 UID 所有の socket であることを確認してから 0600 化する。
            let ident = self
                .identity
                .ok_or_else(|| denied("failed to inspect bound socket"))?;
            if !ident.is_socket || ident.uid != self.euid {
                return Err(denied("bound socket is not the expected socket"));
            }
            sys::fchmodat_nofollow(&self.dir, &self.name, 0o600).map_err(|_| {
                PluginError::new(PluginErrorCode::Internal, "failed to restrict socket mode")
            })
        }

        pub(super) fn accept(&self, timeout: Duration) -> Result<StreamInner, PluginError> {
            let deadline = Instant::now() + timeout;
            loop {
                match self.listener.accept() {
                    Ok((stream, _)) => {
                        // 期限後に到着した接続は受理せず閉じて Timeout を返す（REPAIR-5。
                        // 期限直前のポーリング後のスリープ中に到着した接続が成功する経路を塞ぐ）。
                        // drop で fd を閉じるため相手は切断される。
                        if Instant::now() >= deadline {
                            return Err(PluginError::new(
                                PluginErrorCode::Timeout,
                                "timed out waiting for a connection",
                            ));
                        }
                        // 別 UID（取得不能を含む）は切断して拒否する（PLUG-12・fail-closed）。
                        // drop で fd を閉じるため相手は切断される。
                        if sys::peer_uid(&stream)? != self.euid {
                            return Err(denied("peer credential does not match the current user"));
                        }
                        // macOS 等は listener の nonblocking を継承するため明示的に戻す。
                        stream.set_nonblocking(false).map_err(|_| {
                            PluginError::new(
                                PluginErrorCode::Internal,
                                "failed to configure accepted stream",
                            )
                        })?;
                        let inner = StreamInner { stream };
                        inner.set_io_timeout(UDS_DEFAULT_IO_TIMEOUT)?;
                        return Ok(inner);
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

        /// 検証済みディレクトリ fd 基準で、bind 時と同一性（dev/ino）が一致する socket のみ
        /// unlink する（best-effort）。Linux では照合も削除もパスを再解決しない。
        pub(super) fn cleanup(&self) {
            let Some(expected) = self.identity else {
                return;
            };
            if let Ok(now) = sys::lstat_at(&self.dir, &self.name, &self.path)
                && now == expected
            {
                let _ = sys::unlinkat(&self.dir, &self.name);
            }
        }
    }

    #[derive(Debug)]
    pub(super) struct StreamInner {
        stream: UnixStream,
    }

    impl StreamInner {
        pub(super) fn set_io_timeout(&self, timeout: Duration) -> Result<(), PluginError> {
            if timeout.is_zero() {
                return Err(PluginError::new(
                    PluginErrorCode::InvalidArgument,
                    "io timeout must be non-zero",
                ));
            }
            let fail = |_| PluginError::new(PluginErrorCode::Internal, "failed to set io timeout");
            self.stream.set_read_timeout(Some(timeout)).map_err(fail)?;
            self.stream.set_write_timeout(Some(timeout)).map_err(fail)
        }
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
        pub(super) fn cleanup(&self) {
            match *self {}
        }
    }

    impl StreamInner {
        pub(super) fn set_io_timeout(&self, _timeout: Duration) -> Result<(), PluginError> {
            match *self {}
        }
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
