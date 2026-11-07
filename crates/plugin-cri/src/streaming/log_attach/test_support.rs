//! `log_attach` の試験用の補助（一時ディレクトリと偽の probe）。`streaming` の試験からも使う。

use std::os::unix::fs::PermissionsExt as _;
use std::sync::atomic::AtomicU8;

use super::*;

/// 0700 の一時ディレクトリ（drop で消す）。
pub(crate) struct TempDir(pub(crate) PathBuf);

impl TempDir {
    pub(crate) fn new(tag: &str) -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!(
            "fandhe-attach-{tag}-{}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("mkdir");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        Self(dir)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// 稼働状態を試験から切り替えられる probe（0: 稼働中、1: 停止、2: 不在）。
pub(crate) struct FakeProbe(pub(crate) AtomicU8);

impl FakeProbe {
    pub(crate) fn running() -> Arc<Self> {
        Arc::new(Self(AtomicU8::new(0)))
    }
}

impl AttachProbe for FakeProbe {
    fn precheck(&self, _id: &ContainerId) -> Result<(), CriError> {
        match self.0.load(Ordering::SeqCst) {
            0 => Ok(()),
            1 => Err(CriError::failed_precondition("container is not running")),
            _ => Err(CriError::not_found("container not found")),
        }
    }

    fn activity(&self, _id: &ContainerId) -> ContainerActivity {
        if self.0.load(Ordering::SeqCst) == 0 {
            ContainerActivity::Running
        } else {
            ContainerActivity::NotRunning
        }
    }
}

/// 短い間隔・指定の期限の follow 設定。
pub(crate) fn fast_follow(deadline: Duration) -> FollowOptions {
    FollowOptions::new(deadline)
        .expect("deadline")
        .with_poll_interval(Duration::from_millis(10))
        .expect("interval")
}
