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

#[cfg(target_os = "linux")]
use std::ffi::OsStr;
use std::num::NonZeroU32;
#[cfg(target_os = "linux")]
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
#[cfg(target_os = "linux")]
use std::path::Component;
use std::path::{Path, PathBuf};
#[cfg(target_os = "linux")]
use std::sync::Arc;
use std::time::Duration;

use super::config::NamespaceKind;
use crate::traits::{ContainerId, ErrorCode, TraitError};

/// 検査済み rootfs ディレクトリの固定ハンドル（検査対象と使用対象を同一にする。SEC-1）。
///
/// start は `/` から bundle を経て rootfs までの**全要素**（祖先を含む）を、直前の要素の fd を起点に
/// `O_PATH|O_DIRECTORY|O_NOFOLLOW` で 1 要素ずつ開いて rootfs を固定する（`exec::mount_proc` と同じ
/// `exec::open_dir_beneath` を再利用する）。パスを別の操作で解決し直さないため、途中の祖先を symlink に
/// 差し替えても・改名しても、固定した実体は bundle 配下で辿った rootfs のまま変わらない（TOCTOU の防止）。
/// `O_PATH|O_DIRECTORY` は FIFO 等を open せず `ENOTDIR` で拒否するため、差し替えで open がブロック
/// することもない（REPAIR-5）。
///
/// launcher は `LaunchSpec::rootfs` のパス文字列を再解決せず、`as_fd`（Linux） の fd（dirfd・
/// `/proc/thread-self/fd/N`・`fchdir`）から rootfs を使うこと。fd は O_PATH のため読み書きはできない。
///
/// fd 相対の open は Linux の `sys` モジュールにしか無く、本番 launcher も Linux のみのため、Linux 以外
/// では値を作れない（start は固定段で `Unimplemented` を返す。fail-closed。CLI-1）。
#[derive(Debug, Clone)]
pub struct RootfsDir {
    #[cfg(target_os = "linux")]
    fd: Arc<OwnedFd>,
    /// Linux 以外では構築できないことを型で表す（値を持たない型）。
    #[cfg(not(target_os = "linux"))]
    never: std::convert::Infallible,
}

impl RootfsDir {
    /// `bundle`（絶対パス）配下の `rootfs` を、祖先を含む全要素を symlink 非追従で辿って固定する。
    ///
    /// `rootfs` は `validate_bundle` が返した検査済みパス（`bundle` 配下・`..` なし）。検査後に
    /// bundle 配下の要素が symlink・非ディレクトリ・不在へ変わっていれば `PermissionDenied`
    /// （`rootfs changed after validation`）、bundle 自体やその祖先が symlink を含む・ディレクトリで
    /// ないなら `InvalidArgument`。本番 launcher の `exec::prepare_rootfs` も `/` から同じ条件で rootfs を
    /// 辿るため、ここで先に拒否する。メッセージは固定文言のみ（パス・errno を含めない）。
    #[cfg(target_os = "linux")]
    pub(super) fn pin(bundle: &Path, rootfs: &Path) -> Result<Self, TraitError> {
        use crate::exec::ViolationReason;
        let invalid = |msg: &'static str| TraitError::new(ErrorCode::InvalidArgument, msg);
        if !bundle.is_absolute() {
            return Err(invalid("bundle path must be absolute"));
        }
        let rel = rootfs
            .strip_prefix(bundle)
            .map_err(|_| invalid("rootfs must be inside the bundle"))?;
        let mut names: Vec<&OsStr> = Vec::new();
        for c in rel.components() {
            match c {
                Component::Normal(n) => names.push(n),
                Component::CurDir => {}
                _ => return Err(invalid("root.path must not contain '..'")),
            }
        }
        let fd = crate::exec::open_dir_beneath(bundle, &names).map_err(|e| {
            match e.violation.as_ref().map(|v| v.reason) {
                Some(ViolationReason::PathSymlinkOrNotDirectory | ViolationReason::PathMissing) => {
                    TraitError::new(
                        ErrorCode::PermissionDenied,
                        "rootfs changed after validation",
                    )
                }
                Some(_) => invalid("bundle path must be a directory reachable without symlinks"),
                None => TraitError::new(e.code, "failed to open the rootfs directory"),
            }
        })?;
        Ok(Self { fd: Arc::new(fd) })
    }

    /// Linux 以外では rootfs を fd で固定できないため、起動仕様を作らず拒否する（fail-closed）。
    #[cfg(not(target_os = "linux"))]
    pub(super) fn pin(_bundle: &Path, _rootfs: &Path) -> Result<Self, TraitError> {
        Err(TraitError::new(
            ErrorCode::Unimplemented,
            "start requires Linux to pin the rootfs directory",
        ))
    }

    /// 固定した rootfs ディレクトリの fd（O_PATH。dirfd・`/proc/thread-self/fd/N`・`fchdir` 専用）。
    #[cfg(target_os = "linux")]
    pub fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

impl PartialEq for RootfsDir {
    fn eq(&self, other: &Self) -> bool {
        #[cfg(target_os = "linux")]
        {
            Arc::ptr_eq(&self.fd, &other.fd)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = other;
            match self.never {}
        }
    }
}

impl Eq for RootfsDir {}

/// launcher へ渡す、検証済みの起動仕様。
///
/// 構築は `start` のみ（`pub(super)`）で、一度だけ読んだ `config.json` について、config パーサの上限
/// （`CONFIG_MAX_*`）検証と `validate_bundle` の rootfs 検査・`RootfsDir::pin` の固定を通った値だけを
/// 持つ。`args` は 1 件以上・先頭は絶対パス。シェルを介さず配列のまま渡すこと（インジェクション防止）。
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

    /// 検査済み rootfs の固定ハンドル（SEC-1。[`RootfsDir`] 参照）。
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
/// - rootfs は [`LaunchSpec::rootfs_dir`] の固定ハンドルから使い、`rootfs()` のパスを再解決しない（SEC-1）
/// - `linux.uidMappings` / `gidMappings` は `start` が拒否済みで `LaunchSpec` に載らない。user namespace の
///   写像は launcher の責務で、コンテナ内 root（uid/gid 0）をホストの非特権 UID・GID（呼び出しプロセスの
///   euid・egid。0 なら拒否）へ写すこと。`exec::plan` / `exec::isolate` が既定でこの写像を行う（SEC-5）
/// - `LaunchSpec::namespaces` には Pid・Mount・User が必ず含まれる（`start` が検証済み。hostname があれば Uts も）
///
/// 本番実装は本 crate に未提供（モジュール doc 参照）。
pub trait ProcessLauncher: Send + Sync {
    /// プロセスを起動し、ハンドルを返す。
    fn launch(&self, spec: &LaunchSpec) -> Result<Box<dyn LaunchedProcess>, TraitError>;

    /// `id` の起動が生存プロセスを残していないことを確認する（中断された start の回復用。CORE-2・SEC-1）。
    ///
    /// start は launch 後・pid 記録前に異常終了すると、pid が状態に残らないまま生きたプロセスを残し得る。
    /// `recover_interrupted_start` は予約を Created へ戻す前に本メソッドを呼び、`Ok(())` のときだけ戻す
    /// （戻すと同じ ID の二重起動が可能になるため）。実装は、`id` のプロセスが存在しないと確証できる場合、
    /// または存在する場合に終了・回収したうえで `Ok(())` を返し、確証できない場合は `Err` を返すこと。
    /// 既定実装は確認手段を持たないため fail-closed で `Unimplemented` を返す。待ちには上限を設ける（REPAIR-5）。
    fn confirm_no_process(&self, id: &ContainerId) -> Result<(), TraitError> {
        let _ = id;
        Err(TraitError::new(
            ErrorCode::Unimplemented,
            "the launcher cannot confirm that no process remains for this container",
        ))
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    /// テスト用の一意なディレクトリ（終了時に削除）。
    #[cfg(target_os = "linux")]
    struct TempDir(PathBuf);

    #[cfg(target_os = "linux")]
    impl TempDir {
        fn new(name: &str) -> Self {
            let dir = std::env::temp_dir()
                .join(format!("fandhe-oci-launch-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).expect("mkdir");
            Self(dir)
        }
    }

    #[cfg(target_os = "linux")]
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[cfg(target_os = "linux")]
    fn dev_ino(meta: &std::fs::Metadata) -> (u64, u64) {
        use std::os::unix::fs::MetadataExt;
        (meta.dev(), meta.ino())
    }

    /// 固定した fd の実体（`/proc/thread-self/fd/N` 経由の fstat 相当）。
    #[cfg(target_os = "linux")]
    fn held(dir: &RootfsDir) -> (u64, u64) {
        use std::os::fd::AsRawFd;
        let meta = std::fs::metadata(format!("/proc/thread-self/fd/{}", dir.as_fd().as_raw_fd()))
            .expect("fd meta");
        dev_ino(&meta)
    }

    /// SEC-1: bundle 配下の祖先が bundle 外への symlink なら固定を拒否する（検査後の差し替え = TOCTOU）。
    #[cfg(target_os = "linux")]
    #[test]
    fn sec1_pin_rejects_symlinked_ancestor_below_bundle() {
        let t = TempDir::new("anc");
        let bundle = t.0.join("bundle");
        let outside = t.0.join("outside");
        std::fs::create_dir_all(outside.join("rootfs")).expect("outside");
        std::fs::create_dir_all(&bundle).expect("bundle");
        std::os::unix::fs::symlink(&outside, bundle.join("a")).expect("symlink");
        let err = RootfsDir::pin(&bundle, &bundle.join("a").join("rootfs")).expect_err("fail");
        assert_eq!(err.code(), ErrorCode::PermissionDenied);
        assert_eq!(err.message(), "rootfs changed after validation");
    }

    /// SEC-1・REPAIR-5: rootfs が FIFO に差し替えられていても open でブロックせず拒否する。
    #[cfg(target_os = "linux")]
    #[test]
    fn sec1_pin_rejects_fifo_without_blocking() {
        let t = TempDir::new("fifo");
        let fifo = t.0.join("rootfs");
        let status = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .expect("mkfifo");
        assert!(status.success());
        let err = RootfsDir::pin(&t.0, &fifo).expect_err("fail");
        assert_eq!(err.code(), ErrorCode::PermissionDenied);
        assert_eq!(err.message(), "rootfs changed after validation");
    }

    /// SEC-1: 固定後に祖先を改名して同名の別ディレクトリを置いても、ハンドルは元の実体を指し続ける。
    #[cfg(target_os = "linux")]
    #[test]
    fn sec1_pin_keeps_original_entity_after_ancestor_rename() {
        let t = TempDir::new("rename");
        let rootfs = t.0.join("a").join("rootfs");
        std::fs::create_dir_all(&rootfs).expect("rootfs");
        let original = dev_ino(&std::fs::metadata(&rootfs).expect("meta"));
        let dir = RootfsDir::pin(&t.0, &rootfs).expect("pin");
        std::fs::rename(t.0.join("a"), t.0.join("moved")).expect("rename");
        std::fs::create_dir_all(&rootfs).expect("replacement");
        let replacement = dev_ino(&std::fs::metadata(&rootfs).expect("meta"));
        assert_ne!(original, replacement);
        assert_eq!(held(&dir), original);
    }

    /// SEC-1: bundle 自体（または祖先）が symlink なら InvalidArgument（本番 launcher も同条件で辿る）。
    #[cfg(target_os = "linux")]
    #[test]
    fn sec1_pin_rejects_symlinked_bundle() {
        let t = TempDir::new("bl");
        let real = t.0.join("real");
        std::fs::create_dir_all(real.join("rootfs")).expect("real");
        let link = t.0.join("link");
        std::os::unix::fs::symlink(&real, &link).expect("symlink");
        let err = RootfsDir::pin(&link, &link.join("rootfs")).expect_err("fail");
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        assert_eq!(
            err.message(),
            "bundle path must be a directory reachable without symlinks"
        );
        let err = RootfsDir::pin(Path::new("rel"), Path::new("rel/rootfs")).expect_err("fail");
        assert_eq!(err.message(), "bundle path must be absolute");
    }
}
