//! Wait RPC の待ちの設定（CRI-5・CRI-1・REPAIR-5・TASK-62.3.2・MS-7）。
//!
//! [`super::task_service::TaskService`] の `Wait` が読む。待ち本体は core の
//! `ContainerRuntime::wait_exit`（`RuntimeAdapter::wait_exit` 経由）が持ち、ここは期限の上限と
//! 既定実装（状態の照会）の間隔のヒントだけを持つ。ttrpc の `timeout_nano` は
//! [`super::service::RequestDeadline`] で受け、実効の期限は `min(timeout_nano, WaitConfig::timeout)` になる。
//! 待ちには必ず期限を付け（REPAIR-5）、超えたら `Timeout`（gRPC の `DeadlineExceeded`）で失敗する。
//! plugin 越しでは待ち 1 回が RPC 1 回で、その RPC も自前の期限を持つ。

use std::time::Duration;

use crate::error::CriError;
/// 設定に許す最大の時間（1 日。`server` の期限系の上限と同じ）。
const MAX_WAIT_DURATION: Duration = Duration::from_secs(24 * 60 * 60);

/// Wait の期限と照会間隔。壊れた値（ゼロ・1 日超）は [`WaitConfig::new`] で拒否する（REPAIR-2）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WaitConfig {
    timeout: Duration,
    poll_interval: Duration,
}

impl WaitConfig {
    /// 期限と照会間隔から作る。どちらかがゼロ、または 1 日を超えれば `InvalidArgument`。
    pub fn new(timeout: Duration, poll_interval: Duration) -> Result<Self, CriError> {
        for (name, d) in [("timeout", timeout), ("poll_interval", poll_interval)] {
            if d.is_zero() || d > MAX_WAIT_DURATION {
                return Err(CriError::invalid_argument(format!(
                    "wait {name} must be in 1ns..=1 day"
                )));
            }
        }
        Ok(Self {
            timeout,
            poll_interval,
        })
    }

    /// 待ちの期限の上限（クライアントの `timeout_nano` はこれを超えられない）。
    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// 既定実装の状態の照会間隔（イベント駆動の実装は使わない）。
    pub fn poll_interval(&self) -> Duration {
        self.poll_interval
    }
}

impl Default for WaitConfig {
    /// 期限 60 秒・間隔 100 ミリ秒。containerd は通常期限なしで待つが、REPAIR-5 に従い shim 側で上限を設ける。
    /// 長い待ちが要る呼び出し元は `TaskService::with_wait_config` で延ばす。
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(60),
            poll_interval: Duration::from_millis(100),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 境界: ゼロと 1 日超は拒否、1 日ちょうどは受理。
    #[test]
    fn cri5_wait_config_validation() {
        let ms = Duration::from_millis(1);
        assert!(WaitConfig::new(Duration::ZERO, ms).is_err());
        assert!(WaitConfig::new(ms, Duration::ZERO).is_err());
        assert!(WaitConfig::new(MAX_WAIT_DURATION + ms, ms).is_err());
        assert!(WaitConfig::new(ms, MAX_WAIT_DURATION + ms).is_err());
        let c = WaitConfig::new(MAX_WAIT_DURATION, MAX_WAIT_DURATION).unwrap();
        assert_eq!(c.timeout(), MAX_WAIT_DURATION);
        assert_eq!(WaitConfig::default().timeout(), Duration::from_secs(60));
        assert_eq!(
            WaitConfig::default().poll_interval(),
            Duration::from_millis(100)
        );
    }
}
