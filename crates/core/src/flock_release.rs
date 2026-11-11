//! `flock` を持つ `File` を「close だけ」に任せず、`File::unlock` で明示的に外すための共有部品。
//!
//! `flock` は open file description（OFD）に付く。ロックを持つ `File` を drop（close）するだけでは、同じ OFD を
//! 指す複製 fd が残っている間はロックが外れない。複製は、fork した子が exec か終了するまで持つ fd や、他スレッドの
//! `Command::spawn` が fork から exec までの間に作る fd である。その間、別プロセスの取得は期限切れになり、待たない
//! `try_lock` は「使用中」「Alive」と誤判定する（#3471 の `StoreGuard`、#1537 の `BundleLock`、#3292 の監査ログ）。
//!
//! 本モジュールは `state_store`（`@lock`）と `oci_runtime::image_rootfs`（rootfs 木のロック）から使われる
//! crate 内部の部品で、公開 API ではない。点検表は `docs/design/flock-release-audit.md`（#4492・OCI-5・CORE-2・
//! REPAIR-5）。`unsafe` は使わない（std の `File::unlock`）。
//!
//! 注意: `LOCK_UN` は OFD 単位で効くため、fork した子が [`ExplicitUnlockFile`] の `Drop` を実行すると親のロックまで
//! 外れる。core の fork 子（`sys::fork_single_threaded*`）は `_exit` で終わり親のスタックを巻き戻さないので、
//! 子で `Drop` は走らない。子の body へ本型の値をムーブしないこと。

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

    /// 試験用: 同じ OFD を指す複製 fd を作る（fork した子が持つ fd の代役。#4492）。
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

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::fs::TryLockError;

    /// OCI-5・CORE-2・REPAIR-5（#4492）: 複製 fd が残っていても drop で明示 unlock され、陽性対照の
    /// 包まない `File` は close だけでは外れない。
    #[test]
    fn oci5_repair5_4492_explicit_unlock_file_releases_despite_duplicate_fd() {
        let dir = std::env::temp_dir().join(format!("fc-4492-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("lock");
        let open = || {
            std::fs::OpenOptions::new()
                .create(true)
                .truncate(false)
                .write(true)
                .open(&path)
                .unwrap()
        };

        // 陽性対照: close だけでは複製がある間ロックが残る。
        let plain = open();
        plain.try_lock().unwrap();
        let dup = plain.try_clone().unwrap();
        drop(plain);
        assert!(matches!(open().try_lock(), Err(TryLockError::WouldBlock)));
        drop(dup);
        open().try_lock().unwrap();

        // 対象: 包んで drop すれば、複製が残っていても外れる。
        let file = open();
        file.try_lock().unwrap();
        let dup = file.try_clone().unwrap();
        drop(ExplicitUnlockFile::new(file));
        assert!(open().try_lock().is_ok());
        drop(dup);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
