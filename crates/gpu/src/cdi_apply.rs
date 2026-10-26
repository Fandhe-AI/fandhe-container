//! CDI containerEdits を rootfs / コンテナ設定へ当てる層の入口（TASK-127・GPU-2・MS-10）。
//!
//! # 責務境界
//! `cdi_edits::AggregatedEdits`（集計済みの edits）を受け、コンテナの実行環境へ反映する。
//! 現状は `deviceNodes` の作成（`device_nodes` モジュール。TASK-127.1・#547）と mounts の bind 指定への変換
//! （`mounts`。TASK-127.2・#548）が実装済みで、hooks・env の適用は後続（#549・#550）、cgroup device の `permissions` は TASK-129、
//! core の実行フロー（`create_default_devices` の後・`pivot_root` の前）への配線も未実装（REPAIR-3）。
//!
//! # 呼び出し文脈
//! 呼び出し元は core の実行層（PLUG-1 の区分で CDI の適用は core 側）を想定する。ホストの `/dev` を
//! 読む `resolve_device_nodes` を `pivot_root` の前に呼び、コンテナの `/dev` のマウントのルート fd に
//! 対して `create_device_nodes` を呼ぶ。

pub mod mounts;

mod device_nodes;

pub use device_nodes::{
    CDI_APPLY_MAX_DEVICE_NODES, DeviceNodeKind, ResolvedDeviceNode, resolve_device_nodes,
};
#[cfg(target_os = "linux")]
pub use device_nodes::{
    DeviceNodeOutcome, DeviceNodeReport, DeviceNodeStatus, create_device_nodes,
};

use std::fmt;

/// 適用エラーの分類。綴りは core の `ErrorCode::as_str` に合わせる（ERR-1）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CdiApplyErrorCode {
    /// 引数（path・type・major / minor・mode 等）が不正。
    InvalidArgument,
    /// 対象（ホストのデバイス等）が無い。
    NotFound,
    /// 前提を満たさない（既存エントリとの不一致・symlink・作成後の検証失敗等）。
    FailedPrecondition,
    /// 権限不足（`mknod` の `EPERM` を含む。rootless の別経路へ黙って切り替えない）。
    PermissionDenied,
    /// 件数・長さ・深さの上限超過、または資源不足。
    ResourceExhausted,
    /// 当該 OS・アーキテクチャでは未実装。
    Unimplemented,
    /// 上記以外の内部エラー。
    Internal,
}

impl CdiApplyErrorCode {
    /// 全 variant（網羅の試験用）。
    pub const ALL: [Self; 7] = [
        Self::InvalidArgument,
        Self::NotFound,
        Self::FailedPrecondition,
        Self::PermissionDenied,
        Self::ResourceExhausted,
        Self::Unimplemented,
        Self::Internal,
    ];

    /// 機械可読な名前。
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidArgument => "INVALID_ARGUMENT",
            Self::NotFound => "NOT_FOUND",
            Self::FailedPrecondition => "FAILED_PRECONDITION",
            Self::PermissionDenied => "PERMISSION_DENIED",
            Self::ResourceExhausted => "RESOURCE_EXHAUSTED",
            Self::Unimplemented => "UNIMPLEMENTED",
            Self::Internal => "INTERNAL",
        }
    }

    /// 名前から variant を引く。
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|c| c.as_str() == name)
    }
}

/// 適用エラー。message は英語の固定文言で、spec の内容（env 等）を載せない。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CdiApplyError {
    code: CdiApplyErrorCode,
    message: &'static str,
    errno: Option<i32>,
}

impl CdiApplyError {
    pub(crate) const fn new(code: CdiApplyErrorCode, message: &'static str) -> Self {
        Self {
            code,
            message,
            errno: None,
        }
    }

    #[cfg(target_os = "linux")]
    pub(crate) const fn with_errno(mut self, errno: i32) -> Self {
        self.errno = Some(errno);
        self
    }

    /// エラー分類。
    pub fn code(&self) -> CdiApplyErrorCode {
        self.code
    }

    /// 固定文言。
    pub fn message(&self) -> &'static str {
        self.message
    }

    /// カーネルが返した errno（あれば）。
    pub fn errno(&self) -> Option<i32> {
        self.errno
    }
}

impl fmt::Display for CdiApplyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code.as_str(), self.message)?;
        if let Some(e) = self.errno {
            write!(f, " (errno {e})")?;
        }
        Ok(())
    }
}

impl std::error::Error for CdiApplyError {}

#[cfg(test)]
mod tests {
    use super::*;

    /// GPU-2・ERR-1: コードの綴りと往復。
    #[test]
    fn error_code_names_round_trip() {
        let names: Vec<&str> = CdiApplyErrorCode::ALL.iter().map(|c| c.as_str()).collect();
        assert_eq!(
            names,
            [
                "INVALID_ARGUMENT",
                "NOT_FOUND",
                "FAILED_PRECONDITION",
                "PERMISSION_DENIED",
                "RESOURCE_EXHAUSTED",
                "UNIMPLEMENTED",
                "INTERNAL"
            ]
        );
        for c in CdiApplyErrorCode::ALL {
            assert_eq!(CdiApplyErrorCode::from_name(c.as_str()), Some(c));
        }
        assert_eq!(CdiApplyErrorCode::from_name("nope"), None);
    }

    /// GPU-2: Display は code と固定文言。
    #[test]
    fn display_has_code_and_message() {
        let e = CdiApplyError::new(CdiApplyErrorCode::NotFound, "host device not found");
        assert_eq!(e.to_string(), "NOT_FOUND: host device not found");
    }
}
