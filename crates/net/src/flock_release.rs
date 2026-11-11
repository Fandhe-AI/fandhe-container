//! flock を持つ `File` を drop で明示 unlock してから閉じる RAII（#4514・#4492・OCI-5・CORE-2・REPAIR-5）。
//!
//! `flock` は open file description（OFD）に付くため、ロックを持つ `File` を close するだけでは、
//! 同じ OFD を指す複製 fd（別スレッドの `Command::spawn` が fork から exec までの間に持つ fd 等）が
//! 残っている間はロックが外れず、別プロセスの取得が `Timeout` になる。drop で `File::unlock` を呼んでから
//! 閉じることで、複製が残っても確実に外す。
//!
//! 呼び出し元: `network_store::imp` の 2 つのガード、`network::publish` の共有ポート登録ロック、
//! `add_host_dns::hosts_file` の hosts ファイルロック。点検表は `docs/design/flock-release-audit.md`。
//! core・oci の同名部品と同じ形を net に独立して置く（crate 間の共有化は別途判断）。`unsafe` は使わない。
//!
//! 注意: `LOCK_UN` は OFD 単位で効くため、fork した子の body へ本型の値をムーブしてはならない
//! （子で Drop が走ると親のロックまで外れる）。net の子は `Command::spawn` の exec 経路だけで、
//! `pre_exec` の closure はこの型を捕捉しない。

use std::fs::File;
use std::ops::{Deref, DerefMut};

/// unlock を試みてから閉じる。unlock が失敗しても close は止めない（失敗注入の試験用に結果を返す）。
#[cfg(all(test, unix))]
fn release_with(
    file: File,
    unlock: impl FnOnce(&File) -> std::io::Result<()>,
) -> std::io::Result<()> {
    let res = unlock(&file);
    drop(file);
    res
}

/// drop で明示 unlock してから閉じるロック保持用の `File`。
///
/// 取得直後に包む。`Deref`/`DerefMut` で `File` として読み書き・メタデータ参照ができる。
pub(crate) struct ExplicitUnlockFile {
    file: File,
}

impl ExplicitUnlockFile {
    /// ロックを取得済みの `File` を包む。
    pub(crate) fn new(file: File) -> Self {
        Self { file }
    }

    /// 同じ OFD を指す複製 fd を作る（fork した子が持つ fd の代役。試験用）。
    #[cfg(all(test, unix))]
    pub(crate) fn clone_file_for_test(&self) -> std::io::Result<File> {
        self.file.try_clone()
    }
}

impl Deref for ExplicitUnlockFile {
    type Target = File;
    fn deref(&self) -> &File {
        &self.file
    }
}

impl DerefMut for ExplicitUnlockFile {
    fn deref_mut(&mut self) -> &mut File {
        &mut self.file
    }
}

impl Drop for ExplicitUnlockFile {
    fn drop(&mut self) {
        // 失敗しても close（フィールドの drop）は止めず、panic もしない。
        let _ = self.file.unlock();
    }
}

impl std::fmt::Debug for ExplicitUnlockFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ExplicitUnlockFile(..)")
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::fs::{OpenOptions, TryLockError};

    fn open(path: &std::path::Path) -> File {
        OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)
            .unwrap()
    }

    /// OCI-5・REPAIR-5・#4514: 複製 fd が残っても drop で外れ、包まない File は外れない（陽性対照）。
    #[test]
    fn oci5_repair5_4514_explicit_unlock_file_releases_despite_duplicate_fd() {
        let dir = crate::test_root::test_root("fc-net-flock-release", "dup");
        let path = dir.join("lock");
        // 陽性対照。
        let plain = open(&path);
        plain.try_lock().unwrap();
        let dup = plain.try_clone().unwrap();
        drop(plain);
        assert!(matches!(
            open(&path).try_lock(),
            Err(TryLockError::WouldBlock)
        ));
        drop(dup);
        // 対象。
        let f = open(&path);
        f.try_lock().unwrap();
        let guard = ExplicitUnlockFile::new(f);
        let dup = guard.clone_file_for_test().unwrap();
        drop(guard);
        let probe = open(&path);
        assert!(probe.try_lock().is_ok());
        drop(dup);
    }

    /// REPAIR-5・#4514: unlock が失敗しても close は止まらず、close でロックが外れる。
    #[test]
    fn oci5_repair5_4514_release_continues_close_when_unlock_fails() {
        let dir = crate::test_root::test_root("fc-net-flock-release", "fail");
        let path = dir.join("lock");
        let f = open(&path);
        f.try_lock().unwrap();
        let res = release_with(f, |_| Err(std::io::Error::other("injected")));
        assert!(res.is_err());
        assert!(open(&path).try_lock().is_ok());
    }
}
