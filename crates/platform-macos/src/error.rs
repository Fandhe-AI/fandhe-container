//! プラットフォーム層の構造化エラー（MAC-1・ERR-1・TASK-64.5）。
//!
//! - [`VmOp`]・[`VmError`]: `VZVirtualMachine` のライフサイクルのエラー（`vm::Vm` が返す。TASK-64.4 で導入し、
//!   TASK-64.5 で本モジュールへ移動した。`vm` モジュールからも従来のパスで再エクスポートする）。
//! - [`PlatformError`]: 設定エラー（[`ConfigError`]）とライフサイクルエラーを束ねる crate 横断の型。
//!   機械可読な `code()` と英語の `message()` を持つ（ERR-1）。
//!
//! code の体系は `config.*` / `vm.*` のドット区切りを維持する。plugin 境界の `PluginErrorCode`
//! （`INVALID_ARGUMENT` 形式）への写像は plugin 化の TASK-115 で行う（REPAIR-3: 未実装）。
//! `message()` は VZ 由来の `domain` 等をエスケープせずに埋め込む。ログ・JSON へ載せる呼び出し元は
//! 出力形式に応じてエスケープすること。

use std::fmt;
use std::time::Duration;

use crate::config::ConfigError;
use crate::vm::VmState;

/// 失敗した操作の種別。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmOp {
    Start,
    Stop,
}

impl VmOp {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            VmOp::Start => "start",
            VmOp::Stop => "stop",
        }
    }
}

/// VM ライフサイクルのエラー（ERR 系・REPAIR-4。message は英語）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum VmError {
    /// Virtualization.framework がこの環境で使えない。
    VirtualizationUnsupported,
    /// 設定が `validateWithError` に拒否された（entitlement 欠如を含む）。
    InvalidConfiguration {
        domain: String,
        code: isize,
    },
    /// 現在の状態では操作できない（`canStart` / `canStop` が false）。
    InvalidState {
        op: VmOp,
        state: VmState,
    },
    StartFailed {
        domain: String,
        code: isize,
    },
    StopFailed {
        domain: String,
        code: isize,
    },
    /// 完了通知が期限内に届かなかった（REPAIR-5）。
    Timeout {
        op: VmOp,
        after: Duration,
    },
    /// 完了通知が届く前に通知経路が失われた。
    CallbackLost {
        op: VmOp,
    },
    /// 待機タイムアウトの指定が許容範囲（`MIN_OP_TIMEOUT`..=`MAX_OP_TIMEOUT`）外（REPAIR-5・TASK-64.5）。
    InvalidTimeout {
        /// 範囲外だった項目名（`start` / `stop` / `state_query`）。
        field: &'static str,
        requested: Duration,
        min: Duration,
        max: Duration,
    },
}

impl VmError {
    /// 機械可読なエラーコード。
    pub fn code(&self) -> &'static str {
        match self {
            VmError::VirtualizationUnsupported => "vm.virtualization_unsupported",
            VmError::InvalidConfiguration { .. } => "vm.invalid_configuration",
            VmError::InvalidState { .. } => "vm.invalid_state",
            VmError::StartFailed { .. } => "vm.start_failed",
            VmError::StopFailed { .. } => "vm.stop_failed",
            VmError::Timeout { .. } => "vm.timeout",
            VmError::CallbackLost { .. } => "vm.callback_lost",
            VmError::InvalidTimeout { .. } => "vm.invalid_timeout",
        }
    }

    /// 人間可読なメッセージ（英語）。
    ///
    /// `domain` は VZ が返した NSError の domain をエスケープせずに埋め込む（`sys` で 128 文字に切り詰め済み）。
    /// ログ・JSON 等の構造化出力へ載せる呼び出し元は、出力形式に応じてエスケープすること。
    pub fn message(&self) -> String {
        match self {
            VmError::VirtualizationUnsupported => {
                "Virtualization.framework is not supported on this host".to_string()
            }
            VmError::InvalidConfiguration { domain, code } => {
                format!("virtual machine configuration was rejected ({domain}, code {code})")
            }
            VmError::InvalidState { op, state } => {
                format!(
                    "cannot {} the virtual machine in state {state:?}",
                    op.as_str()
                )
            }
            VmError::StartFailed { domain, code } => {
                format!("virtual machine failed to start ({domain}, code {code})")
            }
            VmError::StopFailed { domain, code } => {
                format!("virtual machine failed to stop ({domain}, code {code})")
            }
            VmError::Timeout { op, after } => {
                format!("{} did not complete within {after:?}", op.as_str())
            }
            VmError::CallbackLost { op } => {
                format!(
                    "completion of {} was lost before it was delivered",
                    op.as_str()
                )
            }
            VmError::InvalidTimeout {
                field,
                requested,
                min,
                max,
            } => {
                format!(
                    "{field} timeout {requested:?} is outside the allowed range {min:?}..={max:?}"
                )
            }
        }
    }
}

impl fmt::Display for VmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code(), self.message())
    }
}

impl std::error::Error for VmError {}

/// crate 横断の構造化エラー（ERR-1）。設定の検証失敗とライフサイクルの失敗を 1 つの型で返す。
///
/// 呼び出し元: `vm::Vm::launch`（macOS）と、将来の `fandhe-container-plugin-macos`（TASK-115）。
/// `code()` / `message()` は内側のエラーへそのまま委譲し、文字列を作り替えない。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PlatformError {
    /// VM 設定の検証・構築の失敗（`config.*`）。
    Config(ConfigError),
    /// VM ライフサイクルの失敗（`vm.*`）。
    Vm(VmError),
}

impl PlatformError {
    /// 機械可読なエラーコード（`config.*` または `vm.*`）。
    pub fn code(&self) -> &'static str {
        match self {
            PlatformError::Config(e) => e.code(),
            PlatformError::Vm(e) => e.code(),
        }
    }

    /// 人間可読なメッセージ（英語）。
    pub fn message(&self) -> String {
        match self {
            PlatformError::Config(e) => e.message(),
            PlatformError::Vm(e) => e.message(),
        }
    }
}

impl fmt::Display for PlatformError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code(), self.message())
    }
}

impl std::error::Error for PlatformError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            PlatformError::Config(e) => Some(e),
            PlatformError::Vm(e) => Some(e),
        }
    }
}

impl From<ConfigError> for PlatformError {
    fn from(e: ConfigError) -> Self {
        PlatformError::Config(e)
    }
}

impl From<VmError> for PlatformError {
    fn from(e: VmError) -> Self {
        PlatformError::Vm(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// MAC-1・ERR-1・TASK-64.5: 設定エラーは code / message / Display を内側のまま保つ。
    #[test]
    fn platform_error_wraps_config_error() {
        let e = PlatformError::from(ConfigError::InvalidCpuCount);
        assert_eq!(e.code(), "config.invalid_cpu_count");
        assert_eq!(
            e.to_string(),
            "config.invalid_cpu_count: cpu count must be at least 1"
        );
        assert!(std::error::Error::source(&e).is_some());
    }

    /// MAC-1・ERR-1・REPAIR-5・TASK-64.5: ライフサイクルエラーを束ねても code / message が変わらない。
    #[test]
    fn platform_error_wraps_vm_error() {
        let e = PlatformError::from(VmError::Timeout {
            op: VmOp::Start,
            after: Duration::from_secs(30),
        });
        assert_eq!(e.code(), "vm.timeout");
        assert_eq!(e.message(), "start did not complete within 30s");
        assert_eq!(
            e.to_string(),
            "vm.timeout: start did not complete within 30s"
        );
    }

    /// MAC-1・ERR-1・TASK-64.5: タイムアウト範囲外のエラー文字列。
    #[test]
    fn invalid_timeout_message_is_concrete() {
        let e = VmError::InvalidTimeout {
            field: "start",
            requested: Duration::ZERO,
            min: Duration::from_millis(100),
            max: Duration::from_secs(600),
        };
        assert_eq!(e.code(), "vm.invalid_timeout");
        assert_eq!(
            e.message(),
            "start timeout 0ns is outside the allowed range 100ms..=600s"
        );
    }
}
