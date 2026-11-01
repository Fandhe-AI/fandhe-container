//! Wait RPC の待ちの設定とポーリング本体（CRI-5・REPAIR-5・TASK-62.3.2・MS-7）。
//!
//! [`super::task_service::TaskService`] の `Wait` から呼ばれる。core の `ContainerRuntime` には
//! 終了待ちのメソッドが無いため、`state` を一定間隔で照会して `Stopped` を待つ。待ちには必ず期限を付け
//! （REPAIR-5）、超えたら `Timeout`（gRPC の `DeadlineExceeded`）で失敗する。
//! plugin 越しでは照会 1 回が RPC 1 回で、その RPC も自前の期限を持つため、1 回の Wait の最悪の所要時間は
//! 「timeout + 照会 1 回分の期限」になる。

use std::thread;
use std::time::{Duration, Instant};

use crate::adapter::{RuntimeContainerStatus, RuntimeLifecycle};
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

    /// 待ちの期限。
    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// 状態の照会間隔。
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

/// `probe` を照会して `Stopped` になるまで待つ。照会の失敗は再試行せずそのまま返す。
/// 期限の時刻にも必ず 1 回照会してから期限切れと判定する。未起動の `Created` や `Unknown` は終了扱いにしない。
pub(crate) fn wait_until_stopped(
    cfg: &WaitConfig,
    mut probe: impl FnMut() -> Result<RuntimeContainerStatus, CriError>,
) -> Result<RuntimeContainerStatus, CriError> {
    let deadline = Instant::now()
        .checked_add(cfg.timeout)
        .ok_or_else(|| CriError::internal("wait deadline overflow"))?;
    loop {
        let st = probe()?;
        if st.lifecycle == RuntimeLifecycle::Stopped {
            return Ok(st);
        }
        let now = Instant::now();
        if now >= deadline {
            return Err(CriError::timeout("wait exceeded its deadline"));
        }
        thread::sleep(cfg.poll_interval.min(deadline - now));
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
