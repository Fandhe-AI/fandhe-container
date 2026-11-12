//! flock を持つ `File` を drop で明示 unlock してから閉じる RAII（#4514・#4492・OCI-5・CORE-2・REPAIR-5）。
//!
//! `flock` は open file description（OFD）に付くため、ロックを持つ `File` を close するだけでは、
//! 同じ OFD を指す複製 fd（別スレッドの `Command::spawn` が fork から exec までの間に持つ fd 等）が
//! 残っている間はロックが外れず、別プロセスの取得が `Timeout` になる。drop で `File::unlock` を呼んでから
//! 閉じることで、複製が残っても確実に外す。
//!
//! 呼び出し元: `network_store::imp` の 2 つのガード、`network::publish` の共有ポート登録ロック、
//! `add_host_dns::hosts_file` の hosts ファイルロック。点検表は `docs/design/flock-release-audit.md`。
//! core・oci・cri・plugin-cri・supervisor の同名部品と同じ形を net に独立して置く（複製は残し、本体の一致は共有の試験ケース（`crates/core/tests/support/flock_release_cases.rs`・`flock_release_with_cases.rs`）の群 A（`new`・`Drop`）と群 B（`release_lock_file_with`・`release_lock_file`・`LockRelease`）で照合する。判断は #4532・#4566・#4571）。`unsafe` は使わない。
//!
//! 注意: `LOCK_UN` は OFD 単位で効くため、fork した子の body へ本型の値をムーブしてはならない
//! （子で Drop が走ると親のロックまで外れる）。net の子は `Command::spawn` の exec 経路だけで、
//! `pre_exec` の closure はこの型を捕捉しない。

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
/// `File` へは [`Self::as_file`]・[`Self::as_file_mut`] で触る（`Deref` は panic 経路を要するため持たない。#4571）。
pub(crate) struct ExplicitUnlockFile(Option<File>);

impl ExplicitUnlockFile {
    /// `file`（ロック取得済み）を包む。
    pub(crate) fn new(file: File) -> Self {
        Self(Some(file))
    }

    /// 保持している `File` の参照（metadata・fd 参照用）。`None` は drop の後にしか起きない。
    /// 呼び出し元は `network_store::imp` と `add_host_dns::hosts_file`（どちらも Linux のみ）。
    #[cfg(target_os = "linux")]
    pub(crate) fn as_file(&self) -> Option<&File> {
        self.0.as_ref()
    }

    /// 保持している `File` の可変参照（hosts ファイルの seek・追記用）。`None` は drop の後にしか起きない。
    #[cfg(target_os = "linux")]
    pub(crate) fn as_file_mut(&mut self) -> Option<&mut File> {
        self.0.as_mut()
    }

    /// 試験用: 同じ OFD を指す複製 fd を作る（fork した子が持つ fd の代役。#4515）。
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

/// 共有の試験ケース（`crates/core/tests/support/flock_release*_cases.rs`。群 A・B。#4566・#4571）が使う一時ディレクトリ。
/// 戻り値の 1 つ目は後始末を持つ guard で、呼び出し側が試験の終わりまで生かす。
#[cfg(all(test, unix))]
pub(crate) fn shared_case_dir(tag: &str) -> (Box<dyn std::any::Any>, std::path::PathBuf) {
    let root = crate::test_root::test_root("fandhe-net-flock-release-4566", tag);
    let path = root.to_path_buf();
    (Box::new(root), path)
}
