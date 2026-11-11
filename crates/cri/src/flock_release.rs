//! `flock` を持つ `File` を「close だけ」に任せず、`File::unlock` で明示的に外すための crate 内部の部品。
//!
//! `flock` は open file description（OFD）に付く。ロックを持つ `File` を drop（close）するだけでは、同じ OFD を
//! 指す複製 fd が残っている間はロックが外れない。複製は、fork した子が exec か終了するまで持つ fd や、他スレッドの
//! `Command::spawn` が fork から exec までの間に作る fd である。その間、別プロセスの期限つき `try_lock` は
//! 期限切れ（`Timeout`・`LockTimeout`）になる。
//!
//! 呼び出し元は `shim_v2::bootstrap` の 3 種のロック（id・`ops.log.lock`・`daemon.log.lock`）と
//! `runtime_service::record_store::file` の `.lock`。core の `flock_release`・oci の同名モジュールと同じ形を
//! crate ごとに独立して置いている（共有の下位 crate へまとめるかは別途判断）。点検表は
//! `docs/design/flock-release-audit.md`（#4492・#4515・OCI-5・CORE-2・REPAIR-5）。`unsafe` は使わない。
//!
//! 注意: `LOCK_UN` は OFD 単位で効くため、fork した子が [`ExplicitUnlockFile`] の `Drop` を実行すると親のロックまで
//! 外れる。子の body へ本型の値をムーブしないこと。

use std::fs::File;

/// ロックの解放結果。unlock の失敗は close を止めず、呼び出し側のログ判断にだけ使う。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LockRelease {
    /// unlock に成功して閉じた。
    Unlocked,
    /// unlock に失敗したが閉じた（OS はプロセス終了か最後の close でロックを解放する）。
    UnlockFailed,
}

/// `unlock` を 1 回呼び、結果によらず `file` を閉じる。panic しない（`Drop` から呼ばれる）。
/// 製品は [`release_lock_file`]、試験は失敗を注入するためこちらを使う。
pub(crate) fn release_lock_file_with(
    file: File,
    unlock: impl FnOnce(&File) -> std::io::Result<()>,
) -> LockRelease {
    let outcome = match unlock(&file) {
        Ok(()) => LockRelease::Unlocked,
        Err(_) => LockRelease::UnlockFailed,
    };
    drop(file);
    outcome
}

/// `File::unlock` で解放する製品用の入口。
pub(crate) fn release_lock_file(file: File) -> LockRelease {
    release_lock_file_with(file, File::unlock)
}

/// ロックを取得済みの `File` を包み、drop で [`release_lock_file`] を呼ぶ RAII。
///
/// 取得（`try_lock` の成功）の後に [`Self::new`] で包む。取得に失敗した `File` はロックを持たないので包まない。
pub(crate) struct ExplicitUnlockFile(Option<File>);

impl ExplicitUnlockFile {
    /// `file`（ロック取得済み）を包む。
    pub(crate) fn new(file: File) -> Self {
        Self(Some(file))
    }

    /// 試験用: 同じ OFD を指す複製 fd を作る（fork した子が持つ fd の代役。#4515）。
    #[cfg(test)]
    pub(crate) fn clone_file_for_test(&self) -> File {
        self.0
            .as_ref()
            .expect("lock file present")
            .try_clone()
            .expect("dup lock fd")
    }
}

impl std::fmt::Debug for ExplicitUnlockFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ExplicitUnlockFile")
    }
}

impl Drop for ExplicitUnlockFile {
    /// 明示 unlock して閉じる。失敗は close を続ける（OS が最後の close かプロセス終了で外す）。
    fn drop(&mut self) {
        if let Some(file) = self.0.take() {
            let _ = release_lock_file(file);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::TryLockError;

    fn open(path: &std::path::Path) -> File {
        std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(path)
            .unwrap()
    }

    /// OCI-5・REPAIR-5（#4515）: 複製 fd が残っていても drop で明示 unlock され、陽性対照の包まない `File` は
    /// close だけでは外れない。
    #[test]
    fn oci5_repair5_4515_explicit_unlock_file_releases_despite_duplicate_fd() {
        let dir = crate::test_root::test_root("fandhe-cri-flock-release", "dup");
        let path = dir.join("lock");

        let plain = open(&path);
        plain.try_lock().unwrap();
        let dup = plain.try_clone().unwrap();
        drop(plain);
        assert!(matches!(
            open(&path).try_lock(),
            Err(TryLockError::WouldBlock)
        ));
        drop(dup);
        open(&path).try_lock().unwrap();

        let file = open(&path);
        file.try_lock().unwrap();
        let dup = file.try_clone().unwrap();
        drop(ExplicitUnlockFile::new(file));
        assert!(open(&path).try_lock().is_ok());
        drop(dup);
    }

    /// OCI-5・REPAIR-5（#4515）: unlock が失敗しても close は続き、panic しない。
    #[test]
    fn oci5_repair5_4515_release_continues_close_when_unlock_fails() {
        let dir = crate::test_root::test_root("fandhe-cri-flock-release", "fail");
        let path = dir.join("lock");
        let file = open(&path);
        file.try_lock().unwrap();
        let r = release_lock_file_with(file, |_| Err(std::io::Error::other("injected")));
        assert_eq!(r, LockRelease::UnlockFailed);
        assert!(open(&path).try_lock().is_ok());
    }
}
