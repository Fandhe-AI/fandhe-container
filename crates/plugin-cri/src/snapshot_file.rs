//! op-stats のスナップショットファイルを安全に開いて原子的に置き換える部品（#4335・CRI-6・REPAIR-4・SEC-1）。
//!
//! 呼び出し元: `telemetry::OpStatsFileSink`（#4337）の専用 thread が [`SnapshotTarget::replace`] を呼ぶ
//! （本部品は同期 I/O のため RPC 経路から直接呼ばない。REPAIR-5）。`main.rs` へは `--op-stats-file` として結線済み
//! （起動引数の解析は W2・#4336、起動時の [`SnapshotTarget::check_target`] と停止時の最後の書き出しは W4・#4340。設計書の更新は W5・#4341）。契約の出典は
//! `docs/design/cri-op-stats-export.md`（案 C。opt-in の絶対パスへ原子的に置き換えるスナップショット）。
//!
//! # 契約
//!
//! - 公開面は型 [`SnapshotTarget`] で、生のパスを持ち回らない。[`SnapshotTarget::open`] が置き先ディレクトリを
//!   `O_NOFOLLOW|O_DIRECTORY` で開き、fstat で「実効 UID 所有・group/other 書き込み不可（sticky の例外なし）」を要求する。
//!   以降の作成・確認・rename・削除はすべてそのディレクトリ fd 起点（`/proc/self/fd/<fd>/<名前>`）で行い、
//!   パス文字列の再解決による親の差し替えを受けない。std だけで実現し `unsafe` は足さない（`/proc` が見えない環境は open が失敗し fail-closed）。
//! - 置き換えは「同じディレクトリの一時ファイル（`O_CREAT|O_EXCL|O_NOFOLLOW`・0600）へ書く → fsync → rename → ディレクトリ fsync」。
//!   読み手は常に完全な 1 スナップショットを見る。最終名が通常ファイル以外（symlink・ディレクトリ・FIFO 等）なら置き換えずに失敗する。
//! - サイズ上限（[`SnapshotLimit`]）を超える内容は何も作らずに失敗する（計数は呼び出し側）。
//! - エラーは固定語彙の [`SnapshotError`] で、パス・errno・コンテナ ID を含めない（SEC-4）。
//! - setuid / setgid などで uid・gid の 4 値が食い違う実行は拒否する（`UntrustedProcess`）。
//!
//! # 非 Linux
//!
//! 実効 UID の確実な取得、symlink / junction / reparse point を辿らない検査、`/proc/self/fd` 相当が無いため、
//! opt-in 自体を `Unsupported` で拒否する（fail-closed。cli の `open_op_log` と同じ方針）。
//!
//! # 受容する残余
//!
//! 1. 最終名の確認と rename の間に差し替えられるのは同じ UID だけ（置き先は実効 UID 所有で g/o 書き込み不可。ディレクトリへの rename はカーネルが拒否する）。
//! 2. 祖先ディレクトリの差し替えは最初の open の瞬間だけの窓（1 要素ずつ固定する歩き方は範囲外）。
//! 3. file capability だけが付いた実行は uid・gid に現れず検出できない。
//! 4. クラッシュで残った一時ファイル（`.<名前>.tmp.<pid>.<連番>`）は回収しない。
//! 5. rename 後のディレクトリ fsync の失敗は `SyncFailed` で返すが、置き換え自体は済んでいる。

use std::fmt;
use std::num::NonZeroUsize;
use std::path::Path;

/// 1 ブロック（1 記録器分）あたりのスナップショット上限バイト数。
const BYTES_PER_BLOCK: usize = 64 * 1024;
/// 受け付けるブロック数の上限（記録器の数より十分大きい値。過大な指定を拒否する）。
const MAX_BLOCKS: usize = 64;

/// スナップショット操作の失敗（固定語彙。パス・errno・識別子を含めない。SEC-4・REPAIR-4）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SnapshotError {
    /// この OS では opt-in できない。
    Unsupported,
    /// 絶対パスでない。
    RelativePath,
    /// パスの形が不正（`.`・`..`・空の最終名・過長・NUL）。
    InvalidPath,
    /// uid・gid が持ち上がった実行、または確認できない実行。
    UntrustedProcess,
    /// 置き先ディレクトリが信頼できない（symlink・非ディレクトリ・他 UID 所有・g/o 書き込み可・開けない）。
    UntrustedDirectory,
    /// 内容がサイズ上限を超える。
    TooLarge,
    /// ブロック数が範囲外。
    LimitOutOfRange,
    /// 一時ファイルを作れない。
    CreateFailed,
    /// 一時ファイルへ書けない。
    WriteFailed,
    /// fsync に失敗した。
    SyncFailed,
    /// 最終名が通常ファイルでない。
    TargetNotRegular,
    /// rename に失敗した。
    RenameFailed,
}

impl SnapshotError {
    /// 機械可読な固定コード（W3 が `op_stats_file_failed` の行と計数へ写す）。
    pub fn code(self) -> &'static str {
        match self {
            Self::Unsupported => "unsupported",
            Self::RelativePath => "relative_path",
            Self::InvalidPath => "invalid_path",
            Self::UntrustedProcess => "untrusted_process",
            Self::UntrustedDirectory => "untrusted_directory",
            Self::TooLarge => "too_large",
            Self::LimitOutOfRange => "limit_out_of_range",
            Self::CreateFailed => "create_failed",
            Self::WriteFailed => "write_failed",
            Self::SyncFailed => "sync_failed",
            Self::TargetNotRegular => "target_not_regular",
            Self::RenameFailed => "rename_failed",
        }
    }
}

impl fmt::Display for SnapshotError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            Self::Unsupported => "op-stats snapshot file is not supported on this OS",
            Self::RelativePath => "op-stats snapshot path must be absolute",
            Self::InvalidPath => "op-stats snapshot path is malformed",
            Self::UntrustedProcess => "process credentials are not trusted for the snapshot file",
            Self::UntrustedDirectory => "op-stats snapshot directory is not trusted",
            Self::TooLarge => "op-stats snapshot exceeds the size limit",
            Self::LimitOutOfRange => "op-stats snapshot block count is out of range",
            Self::CreateFailed => "op-stats snapshot temporary file could not be created",
            Self::WriteFailed => "op-stats snapshot could not be written",
            Self::SyncFailed => "op-stats snapshot could not be synced",
            Self::TargetNotRegular => "op-stats snapshot target is not a regular file",
            Self::RenameFailed => "op-stats snapshot could not be put in place",
        };
        f.write_str(msg)
    }
}

impl std::error::Error for SnapshotError {}

/// スナップショットの上限（64 KiB × ブロック数）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnapshotLimit {
    max_bytes: usize,
}

impl SnapshotLimit {
    /// ブロック数（1..=64）から上限を作る。範囲外は `LimitOutOfRange`。
    pub fn for_blocks(blocks: NonZeroUsize) -> Result<Self, SnapshotError> {
        if blocks.get() > MAX_BLOCKS {
            return Err(SnapshotError::LimitOutOfRange);
        }
        let max_bytes = BYTES_PER_BLOCK
            .checked_mul(blocks.get())
            .ok_or(SnapshotError::LimitOutOfRange)?;
        Ok(Self { max_bytes })
    }

    /// 書ける最大バイト数。
    pub fn max_bytes(self) -> usize {
        self.max_bytes
    }
}

/// 置き換えの成功結果（将来の拡張用に構造体にしてある）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnapshotWritten {
    /// 書いたバイト数。
    pub bytes: usize,
}

/// 検証済みの置き先（ディレクトリ fd と最終名）。生のパスは保持しない。
pub struct SnapshotTarget {
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    dir: std::fs::File,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    name: std::ffi::OsString,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    euid: u32,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    limit: SnapshotLimit,
}

impl fmt::Debug for SnapshotTarget {
    /// パスを出さない（SEC-4）。
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SnapshotTarget").finish_non_exhaustive()
    }
}

impl SnapshotTarget {
    /// 置き先を検証して開く。非 Linux は常に `Unsupported`（fail-closed）。
    #[cfg(not(target_os = "linux"))]
    pub fn open(_path: &Path, _limit: SnapshotLimit) -> Result<Self, SnapshotError> {
        Err(SnapshotError::Unsupported)
    }

    /// 置き先を検証して開く（実効 UID は `/proc/self/status` から得る）。
    #[cfg(target_os = "linux")]
    pub fn open(path: &Path, limit: SnapshotLimit) -> Result<Self, SnapshotError> {
        let euid = imp::unelevated_euid()?;
        imp::open_with_euid(path, limit, euid)
    }

    /// 最終名が通常ファイルか不在であることを確かめる（symlink・ディレクトリ・FIFO 等は `TargetNotRegular`）。
    /// [`Self::open`] はディレクトリしか見ないため、起動時に最終名の不正を見つける口（#4340。fail-closed）。
    /// 非 Linux は `Unsupported`。
    #[cfg(not(target_os = "linux"))]
    pub fn check_target(&self) -> Result<(), SnapshotError> {
        Err(SnapshotError::Unsupported)
    }

    /// 最終名が通常ファイルか不在であることを確かめる（symlink・ディレクトリ・FIFO 等は `TargetNotRegular`）。
    /// [`Self::open`] はディレクトリしか見ないため、起動時に最終名の不正を見つける口（#4340。fail-closed）。
    #[cfg(target_os = "linux")]
    pub fn check_target(&self) -> Result<(), SnapshotError> {
        imp::check_final_name(self)
    }

    /// 内容を原子的に置き換える。非 Linux は `Unsupported`。
    #[cfg(not(target_os = "linux"))]
    pub fn replace(&self, _contents: &[u8]) -> Result<SnapshotWritten, SnapshotError> {
        Err(SnapshotError::Unsupported)
    }

    /// 内容を原子的に置き換える（一時ファイル → fsync → rename → ディレクトリ fsync）。
    #[cfg(target_os = "linux")]
    pub fn replace(&self, contents: &[u8]) -> Result<SnapshotWritten, SnapshotError> {
        imp::replace(self, contents)
    }
}

#[cfg(target_os = "linux")]
mod imp {
    use super::{SnapshotError, SnapshotLimit, SnapshotTarget, SnapshotWritten};
    use fandhe_container_core::open_flags::NofollowOpenFlags;
    use std::ffi::{OsStr, OsString};
    use std::io::{ErrorKind, Read, Write};
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    /// 最終名の最大バイト数（一時名 `.<名前>.tmp.<pid>.<連番>` を足しても NAME_MAX 255 に収める）。
    const MAX_NAME_BYTES: usize = 200;
    /// `/proc/self/status` の読み取り上限。
    const MAX_STATUS_BYTES: u64 = 64 * 1024;
    /// 一時名が `AlreadyExists` のときの再試行回数の上限（REPAIR-5）。
    const MAX_TMP_ATTEMPTS: usize = 4;

    static SEQ: AtomicU64 = AtomicU64::new(0);

    /// 実効 UID を返す。real・effective・saved・fs の uid と gid が揃わない実行は拒否する。
    pub(super) fn unelevated_euid() -> Result<u32, SnapshotError> {
        let mut text = String::new();
        std::fs::File::open("/proc/self/status")
            .and_then(|f| f.take(MAX_STATUS_BYTES).read_to_string(&mut text))
            .map_err(|_| SnapshotError::UntrustedProcess)?;
        check_unelevated(&text)
    }

    /// `/proc/self/status` の本文から、持ち上がっていない実効 UID を得る純関数。
    pub(super) fn check_unelevated(text: &str) -> Result<u32, SnapshotError> {
        let snap = fandhe_container_supervisor::privilege::parse_proc_status(text)
            .map_err(|_| SnapshotError::UntrustedProcess)?;
        let u = snap.uid;
        let g = snap.gid;
        let uid_ok = u.real == u.effective && u.saved == u.effective && u.fs == u.effective;
        let gid_ok = g.real == g.effective && g.saved == g.effective && g.fs == g.effective;
        if uid_ok && gid_ok {
            Ok(u.effective)
        } else {
            Err(SnapshotError::UntrustedProcess)
        }
    }

    /// 置き先ディレクトリの fstat 結果の判定（他 UID 所有を値で試験できるよう純関数にする）。
    pub(super) fn check_dir_meta(
        is_dir: bool,
        uid: u32,
        mode: u32,
        euid: u32,
    ) -> Result<(), SnapshotError> {
        if is_dir && uid == euid && mode & 0o022 == 0 {
            Ok(())
        } else {
            Err(SnapshotError::UntrustedDirectory)
        }
    }

    /// 絶対パスを（親ディレクトリ, 最終名）へ分ける。`.`・`..`・空要素・過長・NUL を拒否する。
    pub(super) fn split_path(path: &Path) -> Result<(PathBuf, OsString), SnapshotError> {
        if !path.is_absolute() {
            return Err(SnapshotError::RelativePath);
        }
        let bytes = path.as_os_str().as_bytes();
        if bytes.contains(&0) || bytes.ends_with(b"/") {
            return Err(SnapshotError::InvalidPath);
        }
        let body = bytes.get(1..).unwrap_or_default();
        if body
            .split(|b| *b == b'/')
            .any(|c| c.is_empty() || c == b"." || c == b"..")
        {
            return Err(SnapshotError::InvalidPath);
        }
        let name = path.file_name().ok_or(SnapshotError::InvalidPath)?;
        if name.is_empty() || name.as_bytes().len() > MAX_NAME_BYTES {
            return Err(SnapshotError::InvalidPath);
        }
        let parent = path.parent().ok_or(SnapshotError::InvalidPath)?;
        Ok((parent.to_path_buf(), name.to_os_string()))
    }

    fn child_via_fd(dir: &std::fs::File, name: &OsStr) -> PathBuf {
        PathBuf::from(format!("/proc/self/fd/{}", dir.as_raw_fd())).join(name)
    }

    pub(crate) fn open_with_euid(
        path: &Path,
        limit: SnapshotLimit,
        euid: u32,
    ) -> Result<SnapshotTarget, SnapshotError> {
        let flags = NofollowOpenFlags::current().ok_or(SnapshotError::Unsupported)?;
        let (parent, name) = split_path(path)?;
        let dir = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(flags.directory_nofollow_nonblock())
            .open(&parent)
            .map_err(|_| SnapshotError::UntrustedDirectory)?;
        let m = dir
            .metadata()
            .map_err(|_| SnapshotError::UntrustedDirectory)?;
        check_dir_meta(m.is_dir(), m.uid(), m.mode(), euid)?;
        Ok(SnapshotTarget {
            dir,
            name,
            euid,
            limit,
        })
    }

    pub(super) fn replace(
        t: &SnapshotTarget,
        contents: &[u8],
    ) -> Result<SnapshotWritten, SnapshotError> {
        if contents.len() > t.limit.max_bytes() {
            return Err(SnapshotError::TooLarge);
        }
        let flags = NofollowOpenFlags::current().ok_or(SnapshotError::Unsupported)?;
        let (tmp_name, mut file) = create_tmp(t, flags)?;
        let tmp_path = child_via_fd(&t.dir, &tmp_name);
        let result = write_and_install(t, &mut file, &tmp_path, contents);
        if result.is_err() {
            // 失敗時は一時ファイルを片付ける（rename 済みなら既に無く、失敗は無視。元のエラーを返す）。
            let _ = std::fs::remove_file(&tmp_path);
        }
        result.map(|()| SnapshotWritten {
            bytes: contents.len(),
        })
    }

    fn create_tmp(
        t: &SnapshotTarget,
        flags: NofollowOpenFlags,
    ) -> Result<(OsString, std::fs::File), SnapshotError> {
        for _ in 0..MAX_TMP_ATTEMPTS {
            let mut n = OsString::from(".");
            n.push(&t.name);
            n.push(format!(
                ".tmp.{}.{}",
                std::process::id(),
                SEQ.fetch_add(1, Ordering::Relaxed)
            ));
            let res = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(flags.file_nofollow_nonblock())
                .open(child_via_fd(&t.dir, &n));
            match res {
                Ok(f) => return Ok((n, f)),
                Err(e) if e.kind() == ErrorKind::AlreadyExists => continue,
                Err(_) => return Err(SnapshotError::CreateFailed),
            }
        }
        Err(SnapshotError::CreateFailed)
    }

    /// 最終名が通常ファイルか不在かを lstat で確かめる（`replace` と起動時の `check_target` が共有）。
    pub(super) fn check_final_name(t: &SnapshotTarget) -> Result<(), SnapshotError> {
        match std::fs::symlink_metadata(child_via_fd(&t.dir, &t.name)) {
            // symlink は is_file() が false になる（lstat）。FIFO・デバイス・ディレクトリも同様。
            Ok(fm) if fm.file_type().is_file() => Ok(()),
            Ok(_) => Err(SnapshotError::TargetNotRegular),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
            Err(_) => Err(SnapshotError::TargetNotRegular),
        }
    }

    fn write_and_install(
        t: &SnapshotTarget,
        file: &mut std::fs::File,
        tmp_path: &Path,
        contents: &[u8],
    ) -> Result<(), SnapshotError> {
        // umask に依らず 0600 に揃え、作ったものが想定どおりの通常ファイルかを fd から確かめる。
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|_| SnapshotError::CreateFailed)?;
        let m = file.metadata().map_err(|_| SnapshotError::CreateFailed)?;
        if !m.is_file() || m.nlink() != 1 || m.uid() != t.euid || m.mode() & 0o777 != 0o600 {
            return Err(SnapshotError::CreateFailed);
        }
        file.write_all(contents)
            .map_err(|_| SnapshotError::WriteFailed)?;
        file.sync_all().map_err(|_| SnapshotError::SyncFailed)?;
        check_final_name(t)?;
        let final_path = child_via_fd(&t.dir, &t.name);
        std::fs::rename(tmp_path, &final_path).map_err(|_| SnapshotError::RenameFailed)?;
        // rename を永続化する。失敗しても置き換え自体は済んでいる（モジュール doc の残余 5）。
        t.dir.sync_all().map_err(|_| SnapshotError::SyncFailed)
    }
}

#[cfg(test)]
mod tests;
