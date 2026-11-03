//! supervisor の結合試験（`run`・`daemonless`・`restart_latency`）が共有する、実プロセスを
//! `LaunchedProcess` として扱う試験用アダプタ（REPAIR-1・REPAIR-5・SUP-1・SUP-3・#3410）。
//!
//! 本番の launcher が未提供のため、監視ループ（`run::monitor`）へ注入する起動ハンドルの代役を務める。
//! 3 本の試験で同じ形が複製されていたため 1 箇所に集約した。`Drop` で kill + 回収し、試験が失敗しても
//! プロセスを残さない。
//!
//! 契約: 取り込み元は crate ルートに `mod reap;`（`crates/core/tests/support/reap.rs` の取り込み）を
//! 宣言していること（`Drop` が `crate::reap::reap_on_drop` を呼ぶ）。ポーリング間隔は試験ごとに
//! 引数で渡す（`restart_latency` は SUP-3 の中央値 100ms 以下の計測に効くため 2ms、他は 10ms）。
//! lock の poison は `Internal` エラーで表に出す。

use std::num::NonZeroU32;
use std::process::{Child, ExitStatus};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use fandhe_container_core::oci_runtime::{LaunchedProcess, ProcessExit};
use fandhe_container_core::traits::{ErrorCode, TraitError};

fn internal(msg: &'static str) -> TraitError {
    TraitError::new(ErrorCode::Internal, msg)
}

/// 実プロセス（`std::process::Child`）を [`LaunchedProcess`] として扱う試験用アダプタ。
pub struct ChildProcess {
    pid: NonZeroU32,
    child: Mutex<Child>,
    poll: Duration,
}

impl ChildProcess {
    /// `child` を包む。`poll` は終了確認のポーリング間隔。pid が 0 なら `Internal`。
    pub fn new(child: Child, poll: Duration) -> Result<Self, TraitError> {
        let pid = NonZeroU32::new(child.id()).ok_or_else(|| internal("zero child pid"))?;
        Ok(Self {
            pid,
            child: Mutex::new(child),
            poll,
        })
    }

    /// 強制終了（SIGKILL 相当）を送る。シグナル終了の試験用（Linux の試験だけが使う）。
    #[cfg(target_os = "linux")]
    #[allow(dead_code, reason = "取り込み元の試験によっては使わない共有補助")]
    pub fn kill(&self) {
        if let Ok(mut c) = self.child.lock() {
            let _ = c.kill();
        }
    }
}

fn map_exit(status: ExitStatus) -> Result<ProcessExit, TraitError> {
    if let Some(code) = status.code() {
        return Ok(ProcessExit::Exited(code));
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(sig) = status.signal() {
            return Ok(ProcessExit::Signaled(sig));
        }
    }
    Err(internal("unrecognized exit status"))
}

impl LaunchedProcess for ChildProcess {
    fn pid(&self) -> NonZeroU32 {
        self.pid
    }

    fn wait(&self, timeout: Duration) -> Result<Option<ProcessExit>, TraitError> {
        let end = Instant::now() + timeout;
        loop {
            {
                let mut c = self
                    .child
                    .lock()
                    .map_err(|_| internal("child lock poisoned"))?;
                if let Some(status) = c.try_wait().map_err(|_| internal("try_wait failed"))? {
                    return map_exit(status).map(Some);
                }
            }
            if Instant::now() >= end {
                return Ok(None);
            }
            std::thread::sleep(self.poll);
        }
    }

    fn terminate(&self, timeout: Duration) -> Result<(), TraitError> {
        {
            let mut c = self
                .child
                .lock()
                .map_err(|_| internal("child lock poisoned"))?;
            let _ = c.kill();
        }
        match self.wait(timeout)? {
            Some(_) => Ok(()),
            None => Err(TraitError::new(ErrorCode::Timeout, "terminate timed out")),
        }
    }
}

impl Drop for ChildProcess {
    fn drop(&mut self) {
        if let Ok(c) = self.child.get_mut() {
            crate::reap::reap_on_drop(c);
        }
    }
}
