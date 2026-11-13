//! VM 保持役の二重起動を防ぐ排他ロック（`flock`）と、死亡時の自動解放（MAC-4・CORE-1。設計の制約 C4）。
//!
//! macOS には pidfd も `PDEATHSIG` も無く、保持役の死亡を確実に知る手段がロックの解放だけになる。`flock` は
//! プロセスの終了（SIGKILL を含む）でカーネルが外すため、「ロックを取れた者だけが保持役である」を排他の正とする。
//! `vm_keeper::run`（保持役の入口）が起動直後に [`KeeperLock::try_acquire`] を呼び、取れなければ即座に終わる。
//! 起動役の待ち用に、期限つきで取り直す [`KeeperLock::acquire_within`] も持つ（REPAIR-5）。
//!
//! ロックファイルは検証済みの配置ディレクトリ（`RuntimeDir`。0700・自 UID・symlink 不可）の直下に置く。開いた後に
//! 「通常ファイル・配置ディレクトリと同じ所有者・group/other 権限なし」と、path の lstat と dev / ino の一致を確かめる
//! （取得の前後で別の掃除や差し替えがあっても孤立した inode のロックを排他と誤認しない。`container_options::store` と
//! 同じ流儀）。解放は `ExplicitUnlockFile` が drop で明示 unlock する（fork した子の OFD 共有への注意は
//! `flock_release` の doc 参照）。

use std::fs::{File, OpenOptions};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use fandhe_container_core::traits::{ErrorCode, TraitError};

use crate::flock_release::ExplicitUnlockFile;

/// ロックファイル名（VM 名は今回は固定の `default`。共用 VM は 1 つ。オプション方式で名前を足すときは検証つきの型にする）。
pub(crate) const LOCK_FILE_NAME: &str = "vm-keeper-default.lock";

/// 期限つき取得の `timeout` の上限（これを超える値は `InvalidArgument`。無期限相当の待ちを作らない）。
pub const ACQUIRE_TIMEOUT_MAX: Duration = Duration::from_secs(3600);

/// 期限つき取得の再試行間隔。
const POLL: Duration = Duration::from_millis(10);

fn err(code: ErrorCode, message: &'static str) -> TraitError {
    TraitError::new(code, message)
}

/// 保持役のロック。保持している間だけ、その VM の保持役を名乗れる。drop（またはプロセス終了）で解放される。
#[derive(Debug)]
pub struct KeeperLock {
    _file: ExplicitUnlockFile,
}

impl KeeperLock {
    /// ロックを 1 回だけ試す。別のプロセスが保持していれば `FailedPrecondition`（`vm keeper is already running`）。
    pub fn try_acquire(dir: &Path) -> Result<Self, TraitError> {
        let path = dir.join(LOCK_FILE_NAME);
        Self::attempt(dir, &path)?.ok_or_else(|| {
            err(
                ErrorCode::FailedPrecondition,
                "vm keeper is already running",
            )
        })
    }

    /// `timeout` まで取得を繰り返す。期限切れは `Timeout`（無期限に待たない。REPAIR-5）。
    pub fn acquire_within(dir: &Path, timeout: Duration) -> Result<Self, TraitError> {
        let path = dir.join(LOCK_FILE_NAME);
        // `Duration::MAX` 等で `Instant` が溢れても panic させない（REPAIR-5）。
        let deadline = Instant::now()
            .checked_add(timeout)
            .filter(|_| timeout <= ACQUIRE_TIMEOUT_MAX)
            .ok_or_else(|| {
                err(
                    ErrorCode::InvalidArgument,
                    "the vm keeper lock timeout is out of range",
                )
            })?;
        loop {
            if let Some(lock) = Self::attempt(dir, &path)? {
                return Ok(lock);
            }
            if Instant::now() >= deadline {
                return Err(err(
                    ErrorCode::Timeout,
                    "the vm keeper lock was not acquired in time",
                ));
            }
            std::thread::sleep(POLL);
        }
    }

    /// 1 回の試行。保持中なら `Ok(None)`。取得できても実体が差し替わっていれば取り直す（有界。無限には回らない）。
    fn attempt(dir: &Path, path: &PathBuf) -> Result<Option<Self>, TraitError> {
        // 実体の差し替えが続く場合に備えて回数を限る（通常は 1 回で終わる）。
        for _ in 0..4 {
            let file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(false)
                .mode(0o600)
                // 読み手のいない FIFO や symlink の追従で open が止まらないよう、非ブロッキング・symlink 非追従で
                // 開く（REPAIR-5）。種別は取得前に fd で検査する。
                .custom_flags(crate::logs::rotating::LOG_READ_FLAGS)
                .open(path)
                .map_err(|_| {
                    err(
                        ErrorCode::Internal,
                        "the vm keeper lock file cannot be opened",
                    )
                })?;
            if !file.metadata().is_ok_and(|m| m.is_file()) {
                return Err(err(
                    ErrorCode::PermissionDenied,
                    "the vm keeper lock file has an unexpected type, owner or mode",
                ));
            }
            match file.try_lock() {
                Ok(()) => {
                    // 取得直後に包む。以後どの経路で落ちても drop が明示 unlock する。
                    let lock = ExplicitUnlockFile::new(file);
                    let held = lock.as_file().ok_or_else(|| {
                        err(ErrorCode::Internal, "the vm keeper lock file is gone")
                    })?;
                    match verify_current(held, dir, path)? {
                        true => return Ok(Some(Self { _file: lock })),
                        // 孤立した inode を掴んだ。`lock` の drop で解放して取り直す。
                        false => continue,
                    }
                }
                Err(std::fs::TryLockError::WouldBlock) => return Ok(None),
                Err(std::fs::TryLockError::Error(_)) => {
                    return Err(err(ErrorCode::Internal, "the vm keeper lock failed"));
                }
            }
        }
        Err(err(
            ErrorCode::Internal,
            "the vm keeper lock file keeps being replaced",
        ))
    }
}

/// 掴んだ fd が検査済みの通常ファイルで、いまの path の実体と同じ（dev / ino）かを確かめる。
/// 種別・所有者・権限の違反は `PermissionDenied`、path が消えている・別の実体なら `Ok(false)`（取り直し）。
fn verify_current(held: &File, dir: &Path, path: &Path) -> Result<bool, TraitError> {
    let held_meta = held.metadata().map_err(|_| {
        err(
            ErrorCode::Internal,
            "the vm keeper lock file cannot be inspected",
        )
    })?;
    let dir_uid = std::fs::metadata(dir)
        .map_err(|_| {
            err(
                ErrorCode::Internal,
                "the vm keeper directory cannot be inspected",
            )
        })?
        .uid();
    if !held_meta.is_file() || held_meta.uid() != dir_uid || held_meta.mode() & 0o077 != 0 {
        return Err(err(
            ErrorCode::PermissionDenied,
            "the vm keeper lock file has an unexpected type, owner or mode",
        ));
    }
    let Ok(current) = std::fs::symlink_metadata(path) else {
        return Ok(false);
    };
    Ok(current.file_type().is_file()
        && current.dev() == held_meta.dev()
        && current.ino() == held_meta.ino())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn dir(tag: &str) -> (Box<dyn std::any::Any>, PathBuf) {
        let root = crate::test_root::test_root("fandhe-vm-keeper-lock-2278", tag);
        let path = root.to_path_buf();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).expect("chmod dir");
        (Box::new(root), path)
    }

    #[test]
    fn mac4_second_acquire_is_rejected_while_held() {
        let (_g, d) = dir("second");
        let first = KeeperLock::try_acquire(&d).expect("first");
        let e = KeeperLock::try_acquire(&d).expect_err("second must fail");
        assert_eq!(e.code(), ErrorCode::FailedPrecondition);
        assert_eq!(e.message(), "vm keeper is already running");
        drop(first);
        KeeperLock::try_acquire(&d).expect("acquirable after release");
    }

    #[test]
    fn mac4_acquire_within_times_out_while_held() {
        let (_g, d) = dir("within");
        let _held = KeeperLock::try_acquire(&d).expect("held");
        let start = Instant::now();
        let e = KeeperLock::acquire_within(&d, Duration::from_millis(200)).expect_err("timeout");
        let elapsed = start.elapsed();
        assert_eq!(e.code(), ErrorCode::Timeout);
        assert!(elapsed >= Duration::from_millis(200), "{elapsed:?}");
        assert!(elapsed < Duration::from_secs(2), "{elapsed:?}");
    }

    #[test]
    fn mac4_acquire_within_succeeds_after_release() {
        let (_g, d) = dir("handoff");
        let held = KeeperLock::try_acquire(&d).expect("held");
        let d2 = d.clone();
        let t = std::thread::spawn(move || KeeperLock::acquire_within(&d2, Duration::from_secs(5)));
        std::thread::sleep(Duration::from_millis(100));
        drop(held);
        assert!(t.join().expect("join").is_ok());
    }

    #[test]
    fn mac4_rejects_lock_file_with_group_or_other_access() {
        let (_g, d) = dir("mode");
        let path = d.join(LOCK_FILE_NAME);
        std::fs::write(&path, b"").expect("create");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).expect("chmod");
        let e = KeeperLock::try_acquire(&d).expect_err("wide mode");
        assert_eq!(e.code(), ErrorCode::PermissionDenied);
    }

    #[test]
    fn mac4_acquire_within_rejects_out_of_range_timeout() {
        let (_g, d) = dir("range");
        for t in [Duration::MAX, ACQUIRE_TIMEOUT_MAX + Duration::from_secs(1)] {
            let e = KeeperLock::acquire_within(&d, t).expect_err("out of range");
            assert_eq!(e.code(), ErrorCode::InvalidArgument);
        }
    }

    #[test]
    fn mac4_fifo_lock_path_does_not_block() {
        let (_g, d) = dir("fifo");
        let path = d.join(LOCK_FILE_NAME);
        // unsafe を避け、標準の mkfifo コマンドで FIFO を作る。
        let ok = std::process::Command::new("mkfifo")
            .arg(&path)
            .status()
            .is_ok_and(|s| s.success());
        assert!(ok, "mkfifo");
        let start = Instant::now();
        let e = KeeperLock::acquire_within(&d, Duration::from_millis(300)).expect_err("fifo");
        assert!(start.elapsed() < Duration::from_secs(2));
        assert_eq!(e.code(), ErrorCode::Internal);
    }

    #[test]
    fn mac4_rejects_lock_path_that_is_a_symlink() {
        let (_g, d) = dir("symlink");
        let target = d.join("target");
        std::fs::write(&target, b"").expect("target");
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).expect("chmod");
        std::os::unix::fs::symlink(&target, d.join(LOCK_FILE_NAME)).expect("symlink");
        // symlink 越しに開いても、path の lstat は symlink のため実体不一致となり取得を成立させない。
        let e = KeeperLock::try_acquire(&d).expect_err("symlink must not become the lock");
        assert_eq!(e.code(), ErrorCode::Internal);
    }
}
