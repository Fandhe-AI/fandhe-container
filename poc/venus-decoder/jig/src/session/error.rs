//! セッション層のエラー型（GPU-6・REPAIR-5・TASK-172 F1.4・#1519）。
//!
//! `vhost_user` の codec / transport / `virtqueue` の各エラーを包み、機械可読な固定語彙の `code` と英語の固定文
//! だけを外へ出す。frontend やゲスト由来のバイト列・fd 番号・GPA は含めない（ログ注入の防止）。
//! 呼び出し元は [`super::run`] と、状態遷移を担う `negotiation` の `Session::handle`。

use std::fmt;

use crate::vhost_user::{CodecError, CodecErrorCode, TransportError, TransportErrorCode};
use crate::virtqueue::{VirtqueueError, VirtqueueErrorCode};

/// セッションの失敗種別。`as_str` の大文字スネーク表記が外部に出す code。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionErrorCode {
    /// 要求の前提（所有・feature・メモリ表・ring の設定段階）が満たされていない。
    OutOfOrder,
    /// 広告していない feature ビットが確定値に含まれる。
    FeatureNotOffered,
    /// 必須の feature ビットが確定値に無い。
    RequiredFeatureMissing,
    /// ring の番号が 0・1 以外。
    InvalidVringIndex,
    /// 値が範囲外（キューサイズが 0・2 の冪でない・上限超、base が u16 に収まらない・enable が 0 / 1 以外）。
    InvalidValue,
    /// 添付 fd の個数が要求の種別と合わない。
    FdCountMismatch,
    /// fd を取らない要求に fd が付いていた。
    UnexpectedFds,
    /// `VRING_NOFD`（polling モード）は未対応。
    NofdUnsupported,
    /// 未対応の要求（`SET_CONFIG`）。
    UnsupportedRequest,
    /// kick の fd が閉じられた。
    KickClosed,
    /// kick から 8 バイトを読めなかった。
    InvalidKick,
    /// call への書き込みが 8 バイトに満たなかった。
    CallFailed,
    /// kick / call の fd を非ブロックにできなかった。
    FdSetupFailed,
    /// 補助スレッドの同時存在数がプロセス全体の上限に達した（残存スレッドの蓄積防止）。
    WorkerLimit,
    /// 無通信のまま idle タイムアウトに達した。
    IdleTimeout,
    /// 1 メッセージの受信・応答送信・call の書き込みが期限内に終わらなかった。
    Timeout,
    /// codec のエラー（`cause` に詳細）。
    Codec,
    /// トランスポートのエラー（`cause` に詳細）。
    Transport,
    /// virtqueue のエラー（`cause` に詳細）。
    Virtqueue,
    /// 引数（タイムアウト値）が不正。
    InvalidArgument,
}

impl SessionErrorCode {
    /// 外部に出す code 文字列。
    pub fn as_str(self) -> &'static str {
        match self {
            Self::OutOfOrder => "OUT_OF_ORDER",
            Self::FeatureNotOffered => "FEATURE_NOT_OFFERED",
            Self::RequiredFeatureMissing => "REQUIRED_FEATURE_MISSING",
            Self::InvalidVringIndex => "INVALID_VRING_INDEX",
            Self::InvalidValue => "INVALID_VALUE",
            Self::FdCountMismatch => "FD_COUNT_MISMATCH",
            Self::UnexpectedFds => "UNEXPECTED_FDS",
            Self::NofdUnsupported => "NOFD_UNSUPPORTED",
            Self::UnsupportedRequest => "UNSUPPORTED_REQUEST",
            Self::KickClosed => "KICK_CLOSED",
            Self::InvalidKick => "INVALID_KICK",
            Self::CallFailed => "CALL_FAILED",
            Self::FdSetupFailed => "FD_SETUP_FAILED",
            Self::WorkerLimit => "WORKER_LIMIT",
            Self::IdleTimeout => "IDLE_TIMEOUT",
            Self::Timeout => "TIMEOUT",
            Self::Codec => "CODEC",
            Self::Transport => "TRANSPORT",
            Self::Virtqueue => "VIRTQUEUE",
            Self::InvalidArgument => "INVALID_ARGUMENT",
        }
    }

    /// 英語の固定文。
    pub fn message(self) -> &'static str {
        match self {
            Self::OutOfOrder => "request is not allowed in the current session state",
            Self::FeatureNotOffered => "acknowledged features include bits that were not offered",
            Self::RequiredFeatureMissing => "a required feature bit is not acknowledged",
            Self::InvalidVringIndex => "vring index must be 0 or 1",
            Self::InvalidValue => "request value is out of range",
            Self::FdCountMismatch => "attached fd count does not match the request",
            Self::UnexpectedFds => "fds are attached to a request that takes none",
            Self::NofdUnsupported => "VRING_NOFD (polling mode) is not supported",
            Self::UnsupportedRequest => "request is not supported by this backend",
            Self::KickClosed => "kick fd was closed",
            Self::InvalidKick => "kick fd did not yield 8 bytes",
            Self::CallFailed => "call fd write was short",
            Self::FdSetupFailed => "kick or call fd could not be set non-blocking",
            Self::WorkerLimit => "too many fd I/O workers are alive in this process",
            Self::IdleTimeout => "no activity before the idle timeout",
            Self::Timeout => "operation did not finish before its deadline",
            Self::Codec => "vhost-user codec error",
            Self::Transport => "vhost-user transport error",
            Self::Virtqueue => "virtqueue error",
            Self::InvalidArgument => "limits must be positive and at most one hour",
        }
    }
}

/// 下位層のエラーの詳細（固定語彙のみ）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cause {
    /// codec。
    Codec(CodecErrorCode),
    /// トランスポート（コードと errno）。
    Transport(TransportErrorCode, Option<i32>),
    /// virtqueue。
    Virtqueue(VirtqueueErrorCode),
}

/// セッションのエラー。`request` は関連する要求 ID（分かる場合）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionError {
    /// 種別。
    pub code: SessionErrorCode,
    /// 関連する要求 ID。
    pub request: Option<u32>,
    /// 下位層の詳細。
    pub cause: Option<Cause>,
}

impl SessionError {
    pub(crate) fn new(code: SessionErrorCode, request: Option<u32>) -> Self {
        Self {
            code,
            request,
            cause: None,
        }
    }

    pub(crate) fn virtqueue(e: VirtqueueError, request: Option<u32>) -> Self {
        Self {
            code: SessionErrorCode::Virtqueue,
            request,
            cause: Some(Cause::Virtqueue(e.code)),
        }
    }

    pub(crate) fn transport(e: TransportError, request: Option<u32>) -> Self {
        // 期限切れは呼び出し側が区別できるよう専用 code に写す。
        if e.code == TransportErrorCode::Timeout {
            return Self::new(SessionErrorCode::Timeout, request);
        }
        Self {
            code: SessionErrorCode::Transport,
            request,
            cause: Some(Cause::Transport(e.code, e.errno)),
        }
    }
}

impl From<CodecError> for SessionError {
    fn from(e: CodecError) -> Self {
        Self {
            code: SessionErrorCode::Codec,
            request: e.request,
            cause: Some(Cause::Codec(e.code)),
        }
    }
}

impl fmt::Display for SessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.code.as_str())?;
        if let Some(r) = self.request {
            write!(f, " (request={r})")?;
        }
        write!(f, ": {}", self.code.message())?;
        match self.cause {
            Some(Cause::Codec(c)) => write!(f, " [{}]", c.as_str()),
            Some(Cause::Transport(c, _)) => write!(f, " [{}]", c.as_str()),
            Some(Cause::Virtqueue(c)) => write!(f, " [{}]", c.as_str()),
            None => Ok(()),
        }
    }
}

impl std::error::Error for SessionError {}
