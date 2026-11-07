//! `log_attach` の試験用の補助（一時ディレクトリと偽の probe）。`streaming` の試験からも使う。

use std::sync::atomic::AtomicU8;

use super::*;

/// 0700 の一時ディレクトリ。crate の `test_root`（排他作成・既存の名前は消さない・辿らない）で作り、drop で自分の分だけ消す。
pub(crate) struct TempDir(
    pub(crate) PathBuf,
    #[allow(dead_code)] crate::test_root::TestRoot,
);

impl TempDir {
    pub(crate) fn new(tag: &str) -> Self {
        let root = crate::test_root::test_root("fandhe-attach", tag);
        Self(root.to_path_buf(), root)
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
