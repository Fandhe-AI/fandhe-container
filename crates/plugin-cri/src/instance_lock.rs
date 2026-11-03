//! 状態ルートのインスタンス排他（`<状態ルート>/.cri/@instance.lock`。CRI-2・CORE-1・REPAIR-5。#2931）。
//!
//! 役割: 同じ状態ルートに plugin-cri が 2 つ同時に立ち上がらないようにする。UDS の bind は socket 単位でしか排他されず、
//! socket パスが違えば同じ状態ルートの記録・bundle・回収を 2 プロセスが競合して書いてしまうため
//! （再採用の前提。`docs/design/cri-record-readoption.md` の実装単位 R3）。
//!
//! 呼び出し元: `CriPluginBackends::production*` が、回収記録の読み込みを含む状態を変える最初の処理の前に取り、
//! backends の生存の間（プロセスが終わるまで）持ち続ける。孤児 bundle の回収（`orphan_bundles`。R8 #2937）は `&InstanceLock` を引数に取り、保持の証明として使う。
//! ロック順序は インスタンスロック（最外・常時）＞ registry の `Mutex` ＞ core の `StateStore` の `@lock`。
//!
//! 方式:
//! - ロックは空ファイル 1 つの `File::try_lock`（OS の排他ロック）を期限つき（[`INSTANCE_LOCK_TIMEOUT`]）で再試行して取る。
//!   常駐のスレッド・プロセスは増やさない（CORE-1）。pid などは書かない。
//! - **ロックファイルは消さない**（終了時もエラー時も）。unlink すると、並行して open した側が消えた inode をロックして
//!   二重に取れてしまう。OS のロックは fd の close で外れるので、残ったファイルは無害で手動回収は要らない。
//!   「後始末」として削除を足さないこと。
//! - `.cri` は 0700・同じ所有者・symlink でないことを確かめ、違反は消さずに拒否する（fail-closed）。
//!   ロックファイルは 0600 で、open の前後に通常ファイル・所有者・権限を照合する。
//! - エラー文言は固定で、パス・OS のエラー文字列を含めない（REPAIR-4）。
//!
//! fd の継承: std の `O_CLOEXEC` により exec した子（supervisor・保持役）へは渡らない。監査 relay の fork はロック取得より
//! 前に行う。残余として、exec しない fork を伴う処理（rootless のレイヤー展開の子など）は子が生きている間だけ fd を共有し得る
//! （期限つきなので再取得が遅れるだけ）。

use std::fs::{self, File, OpenOptions};
use std::path::Path;
use std::time::{Duration, Instant};

use fandhe_container_core::traits::{ErrorCode, TraitError};

/// ロックファイル名（`.cri` 直下。`@` 始まりは core の `@lock` 等と同じ流儀）。
pub const INSTANCE_LOCK_NAME: &str = "@instance.lock";
/// 取得を待つ上限（REPAIR-5）。直前の版が終了処理中でも待てる長さ（`ReclaimStore` と同じ値）。
pub const INSTANCE_LOCK_TIMEOUT: Duration = Duration::from_secs(5);
/// 期限内に取れなかった（別インスタンスが保持中の）ときの固定文言。
pub const MSG_INSTANCE_LOCK_BUSY: &str = "state root is in use by another cri plugin instance";
const MSG_PREPARE: &str = "failed to prepare the instance lock";
const MSG_LOCK: &str = "failed to lock the instance lock";
const RETRY: Duration = Duration::from_millis(5);
const CRI_DIR: &str = ".cri";

/// インスタンスロックの保持の証明。値を持っている間ロックが続き、drop（fd の close）で外れる。
/// 取得関数以外から作れない。
pub struct InstanceLock {
    _file: File,
}

impl std::fmt::Debug for InstanceLock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InstanceLock").finish_non_exhaustive()
    }
}

fn precondition() -> TraitError {
    TraitError::new(ErrorCode::FailedPrecondition, MSG_PREPARE)
}

/// `state_root` 配下の `.cri/@instance.lock` を `timeout` まで待って排他ロックする（`timeout` が 0 でも 1 回は試す）。
pub fn acquire_instance_lock_in(
    state_root: &Path,
    timeout: Duration,
) -> Result<InstanceLock, TraitError> {
    let owner = owner_of(state_root).ok_or_else(precondition)?;
    let cri = state_root.join(CRI_DIR);
    create_private_dir(&cri).map_err(|_| precondition())?;
    if !dir_is_private(&cri, owner) {
        return Err(precondition());
    }
    let path = cri.join(INSTANCE_LOCK_NAME);
    let pre = match fs::symlink_metadata(&path) {
        Ok(m) => {
            if !m.file_type().is_file() {
                return Err(precondition());
            }
            Some(m)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(_) => return Err(precondition()),
    };
    let mut opts = OpenOptions::new();
    opts.read(true).write(true).create(true).truncate(false);
    set_private_mode(&mut opts);
    let file = opts.open(&path).map_err(|_| precondition())?;
    if !verify_opened(&file, &path, owner, pre.as_ref()) {
        return Err(precondition());
    }

    let deadline = Instant::now() + timeout;
    loop {
        match file.try_lock() {
            Ok(()) => return Ok(InstanceLock { _file: file }),
            Err(std::fs::TryLockError::WouldBlock) => {
                if Instant::now() >= deadline {
                    return Err(TraitError::new(ErrorCode::Timeout, MSG_INSTANCE_LOCK_BUSY));
                }
                std::thread::sleep(RETRY);
            }
            Err(std::fs::TryLockError::Error(_)) => {
                return Err(TraitError::new(ErrorCode::Internal, MSG_LOCK));
            }
        }
    }
}

#[cfg(unix)]
fn set_private_mode(opts: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt as _;
    opts.mode(0o600);
}

#[cfg(not(unix))]
fn set_private_mode(_opts: &mut OpenOptions) {}

#[cfg(unix)]
fn create_private_dir(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt as _;
    match fs::DirBuilder::new().mode(0o700).create(path) {
        Err(e) if e.kind() != std::io::ErrorKind::AlreadyExists => Err(e),
        _ => Ok(()),
    }
}

#[cfg(not(unix))]
fn create_private_dir(path: &Path) -> std::io::Result<()> {
    match fs::create_dir(path) {
        Err(e) if e.kind() != std::io::ErrorKind::AlreadyExists => Err(e),
        _ => Ok(()),
    }
}

#[cfg(unix)]
fn owner_of(path: &Path) -> Option<u32> {
    use std::os::unix::fs::MetadataExt as _;
    fs::symlink_metadata(path).ok().map(|m| m.uid())
}

#[cfg(not(unix))]
fn owner_of(path: &Path) -> Option<u32> {
    fs::symlink_metadata(path).ok().map(|_| 0)
}

/// symlink でないディレクトリで、所有者が一致し、group / other の権限が無いか（`bundle_provider_with` と同じ基準）。
#[cfg(unix)]
fn dir_is_private(path: &Path, owner: u32) -> bool {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    fs::symlink_metadata(path).is_ok_and(|m| {
        m.file_type().is_dir() && m.uid() == owner && m.permissions().mode() & 0o077 == 0
    })
}

#[cfg(not(unix))]
fn dir_is_private(path: &Path, _owner: u32) -> bool {
    fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_dir())
}

/// open したファイルが通常ファイル・同じ所有者・0600 相当で、事前に見たものと同一かを確かめる
/// （確認と open の間の差し替えの検出）。
#[cfg(unix)]
fn verify_opened(file: &File, path: &Path, owner: u32, pre: Option<&fs::Metadata>) -> bool {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    let Ok(m) = file.metadata() else {
        return false;
    };
    if !m.file_type().is_file() || m.uid() != owner || m.permissions().mode() & 0o077 != 0 {
        return false;
    }
    // open 後のパスが今開いている実体と一致すること（symlink への差し替えを検出する）。
    let Ok(post) = fs::symlink_metadata(path) else {
        return false;
    };
    if !post.file_type().is_file() || post.dev() != m.dev() || post.ino() != m.ino() {
        return false;
    }
    pre.is_none_or(|p| p.dev() == m.dev() && p.ino() == m.ino())
}

#[cfg(not(unix))]
fn verify_opened(file: &File, _path: &Path, _owner: u32, _pre: Option<&fs::Metadata>) -> bool {
    file.metadata().is_ok_and(|m| m.file_type().is_file())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    struct Tmp(
        std::path::PathBuf,
        #[allow(dead_code)] crate::test_root::TestRoot,
    );
    impl Tmp {
        fn new() -> Self {
            static N: AtomicU32 = AtomicU32::new(0);
            let p = std::env::temp_dir().join(format!(
                "fcpc-ilock-{}-{}",
                std::process::id(),
                N.fetch_add(1, Ordering::Relaxed)
            ));
            Self::at(p)
        }

        /// 指定パスを第 1 候補に排他作成する（unix では 0700）。残骸は消さず別名で作る（REPAIR-12・#3475）。
        fn at(p: std::path::PathBuf) -> Self {
            let root = crate::test_root::test_root_at(p);
            Self(root.to_path_buf(), root)
        }
    }

    /// CRI-2・REPAIR-12・#3475: 残骸（古い `.cri/` の中身）があっても消さず別名の空ディレクトリを作り、
    /// drop 後は別名だけが消えて残骸は無傷で残る。
    #[test]
    fn cri2_repair12_ilock_tmp_leaves_stale_residue_untouched() {
        let parent = Tmp::new();
        let p = parent.0.join("stale");
        fs::create_dir_all(p.join(".cri")).expect("mkdir");
        fs::write(p.join(".cri").join("stale"), b"old").expect("write");
        let rp;
        {
            let t = Tmp::at(p.clone());
            rp = t.0.clone();
            assert_ne!(t.0, p);
            assert_eq!(fs::read_dir(&t.0).expect("read").count(), 0);
        }
        assert!(!rp.exists());
        assert_eq!(
            fs::read(p.join(".cri").join("stale")).expect("read"),
            b"old"
        );
    }

    const SHORT: Duration = Duration::from_millis(200);

    #[cfg(unix)]
    #[test]
    fn cri2_instance_lock_creates_private_dir_and_file() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        let t = Tmp::new();
        let _l = acquire_instance_lock_in(&t.0, SHORT).expect("acquire");
        let d = fs::symlink_metadata(t.0.join(".cri")).expect("dir");
        assert_eq!(d.permissions().mode() & 0o777, 0o700);
        let f = fs::symlink_metadata(t.0.join(".cri").join(INSTANCE_LOCK_NAME)).expect("file");
        assert!(f.file_type().is_file());
        assert_eq!(f.permissions().mode() & 0o777, 0o600);
        assert_eq!(f.uid(), d.uid());
        assert_eq!(f.len(), 0);
    }

    #[test]
    fn cri2_instance_lock_second_acquire_times_out_with_fixed_message() {
        let t = Tmp::new();
        let _l = acquire_instance_lock_in(&t.0, SHORT).expect("first");
        let start = Instant::now();
        let e = acquire_instance_lock_in(&t.0, SHORT).expect_err("second must fail");
        let el = start.elapsed();
        assert_eq!(e.code(), ErrorCode::Timeout);
        assert_eq!(e.message(), MSG_INSTANCE_LOCK_BUSY);
        assert!(el >= SHORT && el < Duration::from_secs(5), "elapsed {el:?}");
    }

    #[test]
    fn cri2_instance_lock_reacquire_after_drop() {
        let t = Tmp::new();
        drop(acquire_instance_lock_in(&t.0, SHORT).expect("first"));
        let p = t.0.join(".cri").join(INSTANCE_LOCK_NAME);
        assert!(p.exists(), "lock file must not be unlinked");
        let _l = acquire_instance_lock_in(&t.0, SHORT).expect("reacquire");
    }

    #[test]
    fn cri2_instance_lock_zero_timeout_tries_once() {
        let t = Tmp::new();
        let _l = acquire_instance_lock_in(&t.0, Duration::ZERO).expect("acquire");
    }

    #[cfg(unix)]
    #[test]
    fn cri2_instance_lock_rejects_symlink_lock_path() {
        let t = Tmp::new();
        let cri = t.0.join(".cri");
        create_private_dir(&cri).expect("mkdir");
        let target = t.0.join("victim");
        std::os::unix::fs::symlink(&target, cri.join(INSTANCE_LOCK_NAME)).expect("symlink");
        let e = acquire_instance_lock_in(&t.0, SHORT).expect_err("must reject");
        assert_eq!(e.code(), ErrorCode::FailedPrecondition);
        assert_eq!(e.message(), MSG_PREPARE);
        assert!(!target.exists(), "symlink target must not be created");
    }

    #[test]
    fn cri2_instance_lock_rejects_non_regular_lock_path() {
        let t = Tmp::new();
        let cri = t.0.join(".cri");
        create_private_dir(&cri).expect("mkdir");
        fs::create_dir(cri.join(INSTANCE_LOCK_NAME)).expect("mkdir lock");
        let e = acquire_instance_lock_in(&t.0, SHORT).expect_err("must reject");
        assert_eq!(e.code(), ErrorCode::FailedPrecondition);
    }

    #[cfg(unix)]
    #[test]
    fn cri2_instance_lock_rejects_insecure_cri_dir() {
        use std::os::unix::fs::PermissionsExt as _;
        let t = Tmp::new();
        let cri = t.0.join(".cri");
        fs::create_dir(&cri).expect("mkdir");
        fs::set_permissions(&cri, fs::Permissions::from_mode(0o755)).expect("chmod");
        let e = acquire_instance_lock_in(&t.0, SHORT).expect_err("must reject");
        assert_eq!(e.code(), ErrorCode::FailedPrecondition);
        let mode = fs::symlink_metadata(&cri).expect("md").permissions().mode() & 0o777;
        assert_eq!(mode, 0o755, "must not be modified");
        assert!(!cri.join(INSTANCE_LOCK_NAME).exists());
    }

    #[cfg(unix)]
    #[test]
    fn cri2_instance_lock_rejects_symlink_cri_dir() {
        let t = Tmp::new();
        let real = t.0.join("real");
        fs::create_dir(&real).expect("mkdir");
        std::os::unix::fs::symlink(&real, t.0.join(".cri")).expect("symlink");
        let e = acquire_instance_lock_in(&t.0, SHORT).expect_err("must reject");
        assert_eq!(e.code(), ErrorCode::FailedPrecondition);
        assert!(!real.join(INSTANCE_LOCK_NAME).exists());
    }
}
