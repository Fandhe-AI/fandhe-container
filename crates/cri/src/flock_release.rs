//! `flock` を持つ `File` を「close だけ」に任せず、`File::unlock` で明示的に外すための crate 内部の部品。
//!
//! `flock` は open file description（OFD）に付く。ロックを持つ `File` を drop（close）するだけでは、同じ OFD を
//! 指す複製 fd が残っている間はロックが外れない。複製は、fork した子が exec か終了するまで持つ fd や、他スレッドの
//! `Command::spawn` が fork から exec までの間に作る fd である。その間、別プロセスの期限つき `try_lock` は
//! 期限切れ（`Timeout`・`LockTimeout`）になる。
//!
//! 呼び出し元は `shim_v2::bootstrap` の 3 種のロック（id・`ops.log.lock`・`daemon.log.lock`）と
//! `runtime_service::record_store::file` の `.lock`。core の `flock_release`・oci の同名モジュールと同じ形を
//! crate ごとに独立して置いている（複製は残し、本体の一致は共有の試験ケース（`crates/core/tests/support/flock_release_cases.rs`・`flock_release_with_cases.rs`）で照合する。判断は #4532・#4566）。点検表は
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

/// 共有の試験ケース（`crates/core/tests/support/flock_release*_cases.rs`。#4566）が使う一時ディレクトリ。
/// 戻り値の 1 つ目は後始末を持つ guard で、呼び出し側が試験の終わりまで生かす。一時ディレクトリの作り方が
/// crate ごとに違うため、共有ファイルの外のここに置く。
#[cfg(all(test, unix))]
pub(crate) fn shared_case_dir(tag: &str) -> (Box<dyn std::any::Any>, std::path::PathBuf) {
    let root = crate::test_root::test_root("fandhe-cri-flock-release-4566", tag);
    let path = root.to_path_buf();
    (Box::new(root), path)
}
