//! start が起動を委ねる境界（`ProcessLauncher`。TASK-29.3・CORE-2・OCI-4）。
//!
//! # 役割と呼び出し元
//!
//! `start.rs` の [`start`](super::start) は検証済みの [`LaunchSpec`] を組み立て、実際のプロセス起動を
//! [`ProcessLauncher`] へ委ねる。`ContainerRuntime` の実装は plugin 側に置く（PLUG-1）ため、
//! create が `StateStore` を依存注入で受けるのと同様に、起動も依存注入とした。
//!
//! # 本番実装が未提供である理由（REPAIR-3: 実装済みを装わない）
//!
//! TASK-27 の exec フロー（`exec::spawn_container`）は「分離済み・シングルスレッド・使い捨て」の
//! 親プロセスを要求し、さらに制限ステージ（capability 削減・seccomp・Landlock。TASK-37〜39）の
//! 証跡が無い限り exec を拒否する（SEC-1・CORE-5）。任意の文脈から呼ばれる `start` はこれを
//! 保証できないため、fork した中間プロセスでの `isolate` → `spawn_container` と pid 返却・子の回収
//! を行う本番 launcher は後続 sub-issue（TASK-29 / TASK-157 系）で提供する。現時点で本 crate に
//! launcher 実装は無く、実プロセスの起動は行われない。

use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::sync::Arc;
use std::time::Duration;

use super::config::NamespaceKind;
use crate::traits::TraitError;

/// 検査済み rootfs ディレクトリのハンドル（検査対象と使用対象を同一にする。SEC-1）。
///
/// `start` が rootfs を検査した直後にディレクトリを開き、そのハンドルが検査したパスの実体（`st_dev`・
/// `st_ino`）と一致し symlink でないことを確認して保持する。launcher は `rootfs()` のパス文字列を
/// 再解決せず、このハンドル（`/proc/self/fd/<fd>` や `fchdir` 経由）から rootfs を使うこと。
/// 検査から使用までの間にパスが symlink 等へ差し替えられても、ハンドルは検査済みの実体を指し続ける。
/// Unix 以外にはハンドルの実装が無く（本番 launcher も Linux のみ。CLI-1）、空の値になる。
#[derive(Debug, Clone)]
pub struct RootfsDir {
    #[cfg(unix)]
    file: Arc<std::fs::File>,
}

impl RootfsDir {
    /// `path` のディレクトリを開き、検査済みの実体と同一であることを確認して保持する。
    #[cfg(unix)]
    pub(super) fn open_checked(path: &Path) -> Result<Self, TraitError> {
        use std::os::unix::fs::MetadataExt;
        let fail =
            |msg: &'static str| TraitError::new(crate::traits::ErrorCode::PermissionDenied, msg);
        let file = std::fs::File::open(path).map_err(|_| fail("cannot open rootfs directory"))?;
        let opened = file
            .metadata()
            .map_err(|_| fail("cannot inspect rootfs directory"))?;
        let named =
            std::fs::symlink_metadata(path).map_err(|_| fail("cannot inspect rootfs directory"))?;
        if named.file_type().is_symlink()
            || !opened.is_dir()
            || (opened.dev(), opened.ino()) != (named.dev(), named.ino())
        {
            return Err(fail("rootfs changed after validation"));
        }
        Ok(Self {
            file: Arc::new(file),
        })
    }

    /// Unix 以外ではハンドルを持たない。
    #[cfg(not(unix))]
    pub(super) fn open_checked(_path: &Path) -> Result<Self, TraitError> {
        Ok(Self {})
    }

    /// 検査済み rootfs ディレクトリのファイルハンドル。
    #[cfg(unix)]
    pub fn file(&self) -> &std::fs::File {
        &self.file
    }
}

impl PartialEq for RootfsDir {
    fn eq(&self, other: &Self) -> bool {
        #[cfg(unix)]
        {
            Arc::ptr_eq(&self.file, &other.file)
        }
        #[cfg(not(unix))]
        {
            let _ = other;
            true
        }
    }
}

impl Eq for RootfsDir {}

/// launcher へ渡す、検証済みの起動仕様。
///
/// 構築は `start` のみ（`pub(super)`）で、config パーサの上限（`CONFIG_MAX_*`）検証と
/// `validate_bundle` の rootfs 検査を通った値だけを持つ。`args` は 1 件以上・先頭は絶対パス。
/// シェルを介さず配列のまま渡すこと（インジェクション防止）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct LaunchSpec {
    rootfs: PathBuf,
    rootfs_dir: RootfsDir,
    args: Vec<String>,
    env: Vec<String>,
    hostname: Option<String>,
    namespaces: Vec<NamespaceKind>,
}

impl LaunchSpec {
    pub(super) fn new(
        rootfs: PathBuf,
        rootfs_dir: RootfsDir,
        args: Vec<String>,
        env: Vec<String>,
        hostname: Option<String>,
        namespaces: Vec<NamespaceKind>,
    ) -> Self {
        Self {
            rootfs,
            rootfs_dir,
            args,
            env,
            hostname,
            namespaces,
        }
    }

    /// 検査済みの rootfs の絶対パス（表示・記録用。使用には [`Self::rootfs_dir`] を使うこと）。
    pub fn rootfs(&self) -> &Path {
        &self.rootfs
    }

    /// 検査済み rootfs のディレクトリハンドル（SEC-1。[`RootfsDir`] 参照）。
    pub fn rootfs_dir(&self) -> &RootfsDir {
        &self.rootfs_dir
    }

    /// `process.args`（そのまま。先頭は実行ファイルの絶対パス）。
    pub fn args(&self) -> &[String] {
        &self.args
    }

    /// `process.env`（`KEY=VALUE` 形式のままの文字列）。
    pub fn env(&self) -> &[String] {
        &self.env
    }

    /// `hostname`（UTS namespace 内で設定する値）。
    pub fn hostname(&self) -> Option<&str> {
        self.hostname.as_deref()
    }

    /// 新規作成する namespace（未対応の種別は `start` が拒否済み）。
    pub fn namespaces(&self) -> &[NamespaceKind] {
        &self.namespaces
    }
}

/// 起動済みプロセスへのハンドル。
pub trait LaunchedProcess: Send {
    /// 起動したコンテナプロセスの pid。
    fn pid(&self) -> NonZeroU32;

    /// 状態の記録に失敗したときの後始末として、プロセスを終了させる。
    ///
    /// 待ちには必ず上限時間 `timeout` を設け、超過時は `ErrorCode::Timeout` を返す（REPAIR-5）。
    ///
    /// 上限内に終了しない場合は強制終了（kill）と回収（wait）まで行ってから返すこと。それでも
    /// 終了を確認できないときは `Err` を返す（`start` はこれを呼び出し元へ伝える）。
    fn terminate(&self, timeout: Duration) -> Result<(), TraitError>;
}

/// [`LaunchSpec`] からコンテナプロセスを起動する境界。
///
/// # 契約
///
/// - 起動確認（子からの通知待ち等）には必ず上限時間を設け、超過時は `ErrorCode::Timeout`（REPAIR-5）
/// - exec フローの fail-closed（制限証跡なしの exec 拒否。SEC-1・CORE-5）を回避しない
/// - 失敗時にプロセスを残さない
/// - rootfs は [`LaunchSpec::rootfs_dir`] のハンドルから使い、`rootfs()` のパスを再解決しない（SEC-1）
/// - `linux.uidMappings` / `gidMappings` は `start` が拒否済みで `LaunchSpec` に載らない。user namespace の
///   写像は launcher の責務で、コンテナ内 root（uid/gid 0）をホストの非特権 UID・GID（呼び出しプロセスの
///   euid・egid。0 なら拒否）へ写すこと。`exec::plan` / `exec::isolate` が既定でこの写像を行う（SEC-5）
/// - `LaunchSpec::namespaces` には Pid・Mount・User が必ず含まれる（`start` が検証済み。hostname があれば Uts も）
///
/// 本番実装は本 crate に未提供（モジュール doc 参照）。
pub trait ProcessLauncher: Send + Sync {
    /// プロセスを起動し、ハンドルを返す。
    fn launch(&self, spec: &LaunchSpec) -> Result<Box<dyn LaunchedProcess>, TraitError>;
}
