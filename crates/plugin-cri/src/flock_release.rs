//! `flock` を持つ `File` を「close だけ」に任せず、`File::unlock` で明示的に外すための crate 内部部品（#4516）。
//!
//! `flock` は open file description（OFD）に付く。ロックを持つ `File` を drop（close）するだけでは、同じ OFD を
//! 指す複製 fd が残っている間はロックが外れない。複製は、exec しない fork の子が持つ fd や、他スレッドの
//! `Command::spawn` が fork から exec までの間に作る fd である。その間、別プロセスの期限つき取得は `Timeout` になる。
//!
//! 呼び出し元: [`crate::instance_lock::InstanceLock`]（状態ルートのインスタンス排他。CRI-2・CORE-1）と
//! `netsetup::reclaim_store::ReclaimStore::lock`（回収待ち記録の `.lock`。NET-1）。core の `flock_release`（#4492）と
//! 同じ形を crate ごとに独立して置く（下位 crate への共有化は別途判断）。点検表は `docs/design/flock-release-audit.md`
//! （#4492・#4516・OCI-5・REPAIR-5）。`unsafe` は使わない（std の `File::unlock`）。
//!
//! 注意: `LOCK_UN` は OFD 単位で効くため、fork した子が [`ExplicitUnlockFile`] の `Drop` を実行すると親のロックまで
//! 外れる。plugin-cri 自身には fork の原始が無く、core の fork 子は `_exit` で終わるため `Drop` は走らない。
//! 子の body へ本型の値をムーブしないこと。

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
/// 製品は [`release_lock_file`]、試験は失敗を注入するためこちらを使う（`LOCK_UN` は実環境でほぼ失敗しない）。
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

    /// 試験用: 同じ OFD を指す複製 fd を作る（fork した子が持つ fd の代役。#4516）。
    #[cfg(all(test, unix))]
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

#[cfg(all(test, unix))]
// 照合するのは flock の OFD 単位の意味論で、Windows の `LockFileEx` は複製ハンドルと close の関係が異なり
// 陽性対照の前提が成り立たないため unix に限る。
mod tests {
    use super::*;
    use std::fs::TryLockError;

    fn open_at(path: &std::path::Path) -> File {
        std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(path)
            .unwrap()
    }

    /// OCI-5・REPAIR-5（#4516）: 複製 fd が残っていても drop で明示 unlock され、陽性対照の
    /// 包まない `File` は close だけでは外れない。
    #[test]
    fn oci5_repair5_4516_explicit_unlock_file_releases_despite_duplicate_fd() {
        let root = crate::test_root::test_root("fandhe-plugin-cri-flock-release", "dup");
        let path = root.to_path_buf().join("lock");

        let plain = open_at(&path);
        plain.try_lock().unwrap();
        let dup = plain.try_clone().unwrap();
        drop(plain);
        assert!(matches!(
            open_at(&path).try_lock(),
            Err(TryLockError::WouldBlock)
        ));
        drop(dup);
        open_at(&path).try_lock().unwrap();

        let file = open_at(&path);
        file.try_lock().unwrap();
        let dup = file.try_clone().unwrap();
        drop(ExplicitUnlockFile::new(file));
        assert!(open_at(&path).try_lock().is_ok());
        drop(dup);
    }

    /// REPAIR-5（#4516）: unlock が失敗しても close は続き、`UnlockFailed` を返して panic しない。
    #[test]
    fn oci5_repair5_4516_release_continues_close_when_unlock_fails() {
        let root = crate::test_root::test_root("fandhe-plugin-cri-flock-release", "fail");
        let path = root.to_path_buf().join("lock");
        let file = open_at(&path);
        file.try_lock().unwrap();
        let out = release_lock_file_with(file, |_| Err(std::io::Error::other("injected")));
        assert_eq!(out, LockRelease::UnlockFailed);
        assert!(open_at(&path).try_lock().is_ok());
    }
}
