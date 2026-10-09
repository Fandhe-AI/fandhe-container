//! fd 受け渡しとゲストメモリ mmap のエラー型（GPU-6・TASK-172 F1.2・#1517）。
//!
//! 呼び出し元は `fd_passing` と `guest_memory` で、将来は F1.4（セッション）が code を構造化ログへ出す。
//! 入力は frontend 由来の untrusted なので、エラーには固定語彙の code と errno だけを載せ、
//! 受け取ったバイト列・fd 番号はエコーしない（ログ注入の防止。`CodecError` と同じ流儀）。

use std::fmt;

use crate::sys::{self, SysError};

/// 機械可読なエラー種別。`as_str` の大文字スネーク表記が外部に出す code。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportErrorCode {
    /// 受け取った fd が上限（呼び出し側の `max_fds`）を超えた。
    TooManyFds,
    /// 補助データが切り詰められた（`MSG_CTRUNC`。カーネルが一部の fd を閉じた）。
    ControlTruncated,
    /// データ部が切り詰められた（`MSG_TRUNC`）。
    DataTruncated,
    /// 補助データの構造が不正（`cmsg_len` の範囲外・fd 配列の長さが 4 の倍数でない）。
    MalformedControl,
    /// `SCM_RIGHTS` 以外の補助データを受け取った。
    UnexpectedControl,
    /// 相手が接続を閉じた（0 バイト受信）。
    PeerClosed,
    /// 指定時間内に完了しなかった（REPAIR-5）。
    Timeout,
    /// 引数が不正（`max_fds` の範囲・timeout 0・空のバッファ）。
    InvalidArgument,
    /// メモリ領域の値が不正（サイズ 0・加算の overflow・上限超過）。
    InvalidRegion,
    /// ファイルが領域の末尾に届かない（EOF を超えるアクセスは SIGBUS になるため map 前に拒否する）。
    FileTooShort,
    /// fd が縮まないことを確認できない（`F_SEAL_SHRINK` が無い・seal 非対応の fd）。後から縮むと SIGBUS になるため拒否する。
    ShrinkNotSealed,
    /// 領域のゲスト物理アドレスの範囲が重なっている。
    OverlappingRegions,
    /// 領域数と受け取った fd 数が一致しない。
    FdCountMismatch,
    /// アクセスが領域の範囲外。
    OutOfBounds,
    /// OS が返したエラー（errno を持つ）。
    OsError,
    /// 対応外のアーキテクチャ。
    Unsupported,
}

impl TransportErrorCode {
    /// 全 code（添字は `as usize` と一致する。観測カウンタの添字に使う。REPAIR-4）。
    pub const ALL: [Self; 16] = [
        Self::TooManyFds,
        Self::ControlTruncated,
        Self::DataTruncated,
        Self::MalformedControl,
        Self::UnexpectedControl,
        Self::PeerClosed,
        Self::Timeout,
        Self::InvalidArgument,
        Self::InvalidRegion,
        Self::FileTooShort,
        Self::ShrinkNotSealed,
        Self::OverlappingRegions,
        Self::FdCountMismatch,
        Self::OutOfBounds,
        Self::OsError,
        Self::Unsupported,
    ];

    /// 外部へ出す固定の code 文字列。
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TooManyFds => "TOO_MANY_FDS",
            Self::ControlTruncated => "CONTROL_TRUNCATED",
            Self::DataTruncated => "DATA_TRUNCATED",
            Self::MalformedControl => "MALFORMED_CONTROL",
            Self::UnexpectedControl => "UNEXPECTED_CONTROL",
            Self::PeerClosed => "PEER_CLOSED",
            Self::Timeout => "TIMEOUT",
            Self::InvalidArgument => "INVALID_ARGUMENT",
            Self::InvalidRegion => "INVALID_REGION",
            Self::FileTooShort => "FILE_TOO_SHORT",
            Self::ShrinkNotSealed => "SHRINK_NOT_SEALED",
            Self::OverlappingRegions => "OVERLAPPING_REGIONS",
            Self::FdCountMismatch => "FD_COUNT_MISMATCH",
            Self::OutOfBounds => "OUT_OF_BOUNDS",
            Self::OsError => "OS_ERROR",
            Self::Unsupported => "UNSUPPORTED",
        }
    }
}

/// 構造化エラー。`errno` は OS が返した場合のみ。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransportError {
    /// 機械可読な種別。
    pub code: TransportErrorCode,
    /// OS のエラー番号（`OS_ERROR` のとき）。
    pub errno: Option<i32>,
}

impl TransportError {
    pub(crate) fn new(code: TransportErrorCode) -> Self {
        Self { code, errno: None }
    }

    /// `io::Error`（std の setsockopt・fstat・set_len 等）から作る。タイムアウト系は `TIMEOUT` に写す。
    pub(crate) fn from_io(e: &std::io::Error) -> Self {
        match e.raw_os_error() {
            Some(n) if n == sys::EAGAIN => Self::new(TransportErrorCode::Timeout),
            Some(n) => Self {
                code: TransportErrorCode::OsError,
                errno: Some(n),
            },
            None => Self::new(TransportErrorCode::OsError),
        }
    }

    /// syscall ラッパーの失敗から作る。`EAGAIN`（待機の期限切れ。通常は `fd_passing` が期限を管理する）は `TIMEOUT`。
    pub(crate) fn from_sys(e: SysError) -> Self {
        match e {
            SysError::Unsupported => Self::new(TransportErrorCode::Unsupported),
            SysError::Os(n) if n == sys::EAGAIN => Self::new(TransportErrorCode::Timeout),
            SysError::Os(n) => Self {
                code: TransportErrorCode::OsError,
                errno: Some(n),
            },
        }
    }

    /// 英語の固定文（入力由来の文字列を含まない）。
    pub fn message(&self) -> &'static str {
        match self.code {
            TransportErrorCode::TooManyFds => "received more file descriptors than allowed",
            TransportErrorCode::ControlTruncated => "ancillary data was truncated",
            TransportErrorCode::DataTruncated => "message data was truncated",
            TransportErrorCode::MalformedControl => "ancillary data is malformed",
            TransportErrorCode::UnexpectedControl => "unexpected ancillary data type",
            TransportErrorCode::PeerClosed => "peer closed the connection",
            TransportErrorCode::Timeout => "operation timed out",
            TransportErrorCode::InvalidArgument => "invalid argument",
            TransportErrorCode::InvalidRegion => "memory region values are invalid",
            TransportErrorCode::FileTooShort => "backing file is shorter than the region",
            TransportErrorCode::ShrinkNotSealed => "backing file is not sealed against shrinking",
            TransportErrorCode::OverlappingRegions => "memory regions overlap",
            TransportErrorCode::FdCountMismatch => "region count does not match fd count",
            TransportErrorCode::OutOfBounds => "access is outside the memory region",
            TransportErrorCode::OsError => "operating system error",
            TransportErrorCode::Unsupported => "unsupported architecture",
        }
    }
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.errno {
            Some(n) => write!(f, "{} (errno={n}): {}", self.code.as_str(), self.message()),
            None => write!(f, "{}: {}", self.code.as_str(), self.message()),
        }
    }
}

impl std::error::Error for TransportError {}
