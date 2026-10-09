//! 起動入口（`launch`）のエラー型（GPU-6・REPAIR-4・TASK-172 F4・#1598）。
//!
//! 機械可読な固定語彙の `code` と英語の固定文 `message` だけを外へ出す。パス文字列・ゲスト由来のバイト列は含めない
//! （ログ注入の防止）。呼び出し元は `launch::run` / `launch::parse_args` と bin（`src/bin/venus-jig.rs`）で、
//! bin は [`LaunchError::to_json_line`] を stderr に 1 行出し、[`LaunchError::exit_code`] で終了する。

/// 起動失敗の種別。`as_str` の大文字スネーク表記が外部に出す code。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaunchErrorCode {
    /// 引数が不正（未知・欠落・重複・数値の解釈失敗・範囲外）。
    InvalidArgument,
    /// パスが絶対パスでない。
    PathNotAbsolute,
    /// パスに `.` / `..`・NUL・ファイル名なし等がある、またはソケットとログが同じパス。
    PathInvalid,
    /// ソケットパスが `sun_path` の上限（107 バイト）を超える。
    PathTooLong,
    /// 実行ユーザーの UID を取得できない。
    UidUnavailable,
    /// ソケットディレクトリが symlink。
    SocketDirSymlink,
    /// ソケットディレクトリがディレクトリでない。
    SocketDirNotDirectory,
    /// ソケットディレクトリの所有者が実行ユーザーでない。
    SocketDirNotOwned,
    /// ソケットディレクトリのモードが `0700` でない。
    SocketDirNotPrivate,
    /// ソケットディレクトリの祖先に symlink・他ユーザー所有・他ユーザーが差し替えられるディレクトリがある。
    SocketDirAncestorUnsafe,
    /// ソケットディレクトリを作れない。
    SocketDirCreateFailed,
    /// ログファイルの親〜`/` に symlink・他ユーザー所有・他ユーザーが差し替えられるディレクトリがある。
    LogDirUnsafe,
    /// ソケットパスに既に何かある（消さずに拒否する）。
    SocketPathExists,
    /// ログファイルのパスに既に何かある（上書きしない）。
    LogPathExists,
    /// ログファイルを開けない。
    LogOpenFailed,
    /// ログへの書き込みまたは同期に失敗した。
    LogWriteFailed,
    /// bind に失敗した。
    BindFailed,
    /// accept に失敗した。
    AcceptFailed,
    /// 期限内に接続が来なかった。
    AcceptTimeout,
    /// 接続元の UID が実行ユーザーと異なる（PLUG-12。接続を閉じて拒否した）。
    PeerUidMismatch,
    /// 接続元の UID を取得できない（PLUG-12。fail-closed で接続を閉じた）。
    PeerCredUnavailable,
    /// セッションがエラーで終わった（`cause` にセッションの code）。
    SessionFailed,
    /// Linux 以外では実行できない。
    Unsupported,
}

impl LaunchErrorCode {
    /// 外部に出す code 文字列。
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidArgument => "INVALID_ARGUMENT",
            Self::PathNotAbsolute => "PATH_NOT_ABSOLUTE",
            Self::PathInvalid => "PATH_INVALID",
            Self::PathTooLong => "PATH_TOO_LONG",
            Self::UidUnavailable => "UID_UNAVAILABLE",
            Self::SocketDirSymlink => "SOCKET_DIR_SYMLINK",
            Self::SocketDirNotDirectory => "SOCKET_DIR_NOT_DIRECTORY",
            Self::SocketDirNotOwned => "SOCKET_DIR_NOT_OWNED",
            Self::SocketDirNotPrivate => "SOCKET_DIR_NOT_PRIVATE",
            Self::SocketDirAncestorUnsafe => "SOCKET_DIR_ANCESTOR_UNSAFE",
            Self::SocketDirCreateFailed => "SOCKET_DIR_CREATE_FAILED",
            Self::LogDirUnsafe => "LOG_DIR_UNSAFE",
            Self::SocketPathExists => "SOCKET_PATH_EXISTS",
            Self::LogPathExists => "LOG_PATH_EXISTS",
            Self::LogOpenFailed => "LOG_OPEN_FAILED",
            Self::LogWriteFailed => "LOG_WRITE_FAILED",
            Self::BindFailed => "BIND_FAILED",
            Self::AcceptFailed => "ACCEPT_FAILED",
            Self::AcceptTimeout => "ACCEPT_TIMEOUT",
            Self::PeerUidMismatch => "PEER_UID_MISMATCH",
            Self::PeerCredUnavailable => "PEER_CRED_UNAVAILABLE",
            Self::SessionFailed => "SESSION_FAILED",
            Self::Unsupported => "UNSUPPORTED",
        }
    }

    /// 英語の固定文。
    pub fn message(self) -> &'static str {
        match self {
            Self::InvalidArgument => "invalid or missing command line argument",
            Self::PathNotAbsolute => "path must be absolute",
            Self::PathInvalid => "path has an invalid component or collides with another path",
            Self::PathTooLong => "socket path exceeds the sun_path limit of 107 bytes",
            Self::UidUnavailable => "cannot determine the effective uid",
            Self::SocketDirSymlink => "socket directory must not be a symlink",
            Self::SocketDirNotDirectory => "socket directory is not a directory",
            Self::SocketDirNotOwned => "socket directory is not owned by the current user",
            Self::SocketDirNotPrivate => "socket directory mode must be 0700",
            Self::SocketDirAncestorUnsafe => {
                "an ancestor of the socket directory is a symlink or can be replaced by another user"
            }
            Self::SocketDirCreateFailed => "cannot create the socket directory",
            Self::LogDirUnsafe => {
                "the log directory or an ancestor is a symlink or can be replaced by another user"
            }
            Self::SocketPathExists => "socket path already exists; remove it manually",
            Self::LogPathExists => "log path already exists; it is never overwritten",
            Self::LogOpenFailed => "cannot create the log file",
            Self::LogWriteFailed => "cannot write or sync the log file",
            Self::BindFailed => "cannot bind the unix socket",
            Self::AcceptFailed => "accept failed",
            Self::AcceptTimeout => "no connection before the accept deadline",
            Self::PeerUidMismatch => "peer uid differs from the current user; connection rejected",
            Self::PeerCredUnavailable => "cannot determine the peer uid; connection rejected",
            Self::SessionFailed => "vhost-user session ended with an error",
            Self::Unsupported => "venus-jig requires Linux",
        }
    }

    /// bind 前の検証エラー（引数・パス・ディレクトリ・既存パス）か。
    pub fn is_validation(self) -> bool {
        matches!(
            self,
            Self::InvalidArgument
                | Self::PathNotAbsolute
                | Self::PathInvalid
                | Self::PathTooLong
                | Self::SocketDirSymlink
                | Self::SocketDirNotDirectory
                | Self::SocketDirNotOwned
                | Self::SocketDirNotPrivate
                | Self::SocketDirAncestorUnsafe
                | Self::LogDirUnsafe
                | Self::SocketPathExists
                | Self::LogPathExists
        )
    }
}

/// 起動のエラー。`cause` はセッションの code（固定語彙）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LaunchError {
    /// 種別。
    pub code: LaunchErrorCode,
    /// 下位（セッション）の code。
    pub cause: Option<&'static str>,
}

impl LaunchError {
    /// 原因なしのエラー。
    pub fn new(code: LaunchErrorCode) -> Self {
        Self { code, cause: None }
    }

    /// 終了コード。bind 前の検証エラーは 2、それ以外は 1。
    pub fn exit_code(&self) -> i32 {
        if self.code.is_validation() { 2 } else { 1 }
    }

    /// stderr に出す 1 行の JSON。`cause` は公開フィールドで任意の文字列を持てるため、JSON のエスケープを通す。
    pub fn to_json_line(&self) -> String {
        let mut s = format!(
            "{{\"code\":\"{}\",\"message\":\"{}\"",
            self.code.as_str(),
            self.code.message()
        );
        if let Some(c) = self.cause {
            s.push_str(&format!(",\"cause\":\"{}\"", json_escape(c)));
        }
        s.push('}');
        s
    }
}

/// JSON 文字列の中身として安全にする（二重引用符・バックスラッシュ・制御文字をエスケープ）。
fn json_escape(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    for c in v.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

impl std::fmt::Display for LaunchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code.as_str(), self.code.message())
    }
}

impl std::error::Error for LaunchError {}
