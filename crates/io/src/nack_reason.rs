//! ファイル操作要求の拒否理由 `reason` の値表（F10・IO-5・IO-1・REPAIR-2・#3160）。
//!
//! # 役割
//! `docs/design/io-protocol.md` F10 の `reason`（u16）を、壊れた値を表現できない型
//! として 1 か所に集める。値と IoErrorCode の対応（`INVALID_ARGUMENT` /
//! `ALREADY_EXISTS` / `RESOURCE_EXHAUSTED` の 3 分類）もここが持つ。
//!
//! # 呼び出し文脈
//! - `crate::guest_files` の分類関数が `GuestFileCreator::create_file` の失敗を
//!   この値へ写す（#3160）
//! - Nack のワイヤー符号化・復号（`crate::payload`。#3161）は本型を再公開して使い、
//!   `serve_file_connection` の観測（`FileServeStats`。#3163）も同じ型を使う。値表は再定義しない
//!
//! # 契約
//! 値は追加しても版を上げない。未知の値は [`NackReason::Other`] として受理し、
//! そのまま往復できる（情報目的の値のため）。[`UnknownNackReason`] は既知の値
//! （1〜11）を持てないので、`Other(5)` のような別表現は作れない（REPAIR-2）。

use crate::error::IoErrorCode;

/// 既知の値表（1〜11）に無い [`NackReason`] の数値。
///
/// フィールドは非公開で、[`NackReason::from_wire`] だけが既知でない値から作る。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct UnknownNackReason(u16);

impl UnknownNackReason {
    /// ワイヤー上の数値。
    pub fn get(self) -> u16 {
        self.0
    }
}

/// Nack の `reason`（F10 の値表。1〜11）。reason の追加では版を上げないため
/// `#[non_exhaustive]`。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum NackReason {
    /// 1: パスの構文違反（`GuestPath`・IO-5 の形式検査）。
    PathSyntax,
    /// 2: ホストパスが 260 UTF-16 単位を超える（Windows ホストのみ）。
    HostPathTooLong,
    /// 3: 大文字小文字だけが違う既存項目との衝突。
    CaseCollision,
    /// 4: NFC / NFD の別表記の既存項目との衝突。
    NormalizationCollision,
    /// 5: 同一パスが既に存在する。
    Exists,
    /// 6: 共有ルートの外へ出る経路（祖先が symlink 等）。
    EscapesRoot,
    /// 7: 祖先がディレクトリでない。
    NotADirectory,
    /// 8: 未知のハンドル。
    UnknownHandle,
    /// 9: 開いているファイル数の上限。
    OpenFilesLimit,
    /// 10: 保持するデバイス（番兵 fd）数の上限。
    DeviceLimit,
    /// 11: 索引へ取り込む実在項目の件数上限。
    TrackedPathsLimit,
    /// 未知の値（受理して往復する）。
    Other(UnknownNackReason),
}

impl NackReason {
    /// ワイヤー上の値。
    pub fn wire_value(self) -> u16 {
        match self {
            Self::PathSyntax => 1,
            Self::HostPathTooLong => 2,
            Self::CaseCollision => 3,
            Self::NormalizationCollision => 4,
            Self::Exists => 5,
            Self::EscapesRoot => 6,
            Self::NotADirectory => 7,
            Self::UnknownHandle => 8,
            Self::OpenFilesLimit => 9,
            Self::DeviceLimit => 10,
            Self::TrackedPathsLimit => 11,
            Self::Other(unknown) => unknown.get(),
        }
    }

    /// ワイヤー上の値から復元する（未知の値は [`Self::Other`]）。
    pub fn from_wire(value: u16) -> Self {
        match value {
            1 => Self::PathSyntax,
            2 => Self::HostPathTooLong,
            3 => Self::CaseCollision,
            4 => Self::NormalizationCollision,
            5 => Self::Exists,
            6 => Self::EscapesRoot,
            7 => Self::NotADirectory,
            8 => Self::UnknownHandle,
            9 => Self::OpenFilesLimit,
            10 => Self::DeviceLimit,
            11 => Self::TrackedPathsLimit,
            other => Self::Other(UnknownNackReason(other)),
        }
    }

    /// F10 の分類（Nack の `code` の元になる `IoErrorCode`）。未知の値は `None`。
    pub fn code(self) -> Option<IoErrorCode> {
        match self {
            Self::PathSyntax
            | Self::HostPathTooLong
            | Self::EscapesRoot
            | Self::NotADirectory
            | Self::UnknownHandle => Some(IoErrorCode::InvalidArgument),
            Self::CaseCollision | Self::NormalizationCollision | Self::Exists => {
                Some(IoErrorCode::AlreadyExists)
            }
            Self::OpenFilesLimit | Self::DeviceLimit | Self::TrackedPathsLimit => {
                Some(IoErrorCode::ResourceExhausted)
            }
            Self::Other(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TABLE: [(u16, NackReason, IoErrorCode); 11] = [
        (1, NackReason::PathSyntax, IoErrorCode::InvalidArgument),
        (2, NackReason::HostPathTooLong, IoErrorCode::InvalidArgument),
        (3, NackReason::CaseCollision, IoErrorCode::AlreadyExists),
        (
            4,
            NackReason::NormalizationCollision,
            IoErrorCode::AlreadyExists,
        ),
        (5, NackReason::Exists, IoErrorCode::AlreadyExists),
        (6, NackReason::EscapesRoot, IoErrorCode::InvalidArgument),
        (7, NackReason::NotADirectory, IoErrorCode::InvalidArgument),
        (8, NackReason::UnknownHandle, IoErrorCode::InvalidArgument),
        (
            9,
            NackReason::OpenFilesLimit,
            IoErrorCode::ResourceExhausted,
        ),
        (10, NackReason::DeviceLimit, IoErrorCode::ResourceExhausted),
        (
            11,
            NackReason::TrackedPathsLimit,
            IoErrorCode::ResourceExhausted,
        ),
    ];

    /// F10 の値表（1〜11）とコード分類が具体値どおり。
    #[test]
    fn io5_nack_reason_table_matches_f10() {
        for (value, reason, code) in TABLE {
            assert_eq!(reason.wire_value(), value);
            assert_eq!(NackReason::from_wire(value), reason);
            assert_eq!(reason.code(), Some(code));
        }
    }

    /// 未知の値は `Other` として受理して往復し、コードは持たない。
    #[test]
    fn io5_nack_reason_unknown_values_round_trip() {
        for value in [0u16, 12, 1000, u16::MAX] {
            let reason = NackReason::from_wire(value);
            assert!(matches!(reason, NackReason::Other(u) if u.get() == value));
            assert_eq!(reason.wire_value(), value);
            assert_eq!(reason.code(), None);
        }
    }
}
