//! エントリポイントの封印した複製の作成（SUP-6・SEC-1・SEC-4・CORE-5・TASK-163 追補・#1531）。
//!
//! # 役割と呼び出し文脈
//!
//! 稼働中コンテナへの exec の子（`process::run_exec_child` が呼ぶ `prepare_exec_child`）が、本体の
//! `(st_dev, st_ino)` の照合を終えた後に呼ぶ。照合に使った open file description の内容を memfd へ複製して
//! 封印し（`F_SEAL_SEAL|SHRINK|GROW|WRITE` = 0x0F）、以後のシェバン・`PT_INTERP` の解析と
//! `execveat(AT_EMPTY_PATH)` をこの複製に対して行わせる。解析した内容と実行する内容が同じバイト列になり、
//! 照合の後・`execveat` の前にコンテナ側が元のファイルを書き換える TOCTOU（`interpreter.rs` の「限界」）を閉じる。
//! 設計と手順の全体は `interpreter.rs` の「封印した複製からの実行（B'）」を参照。launch 経路は対象外
//! （常駐するワークロードのメモリ増を避ける。#1314 の後）。
//!
//! # 契約
//!
//! 手順（順序固定。いずれかの失敗は fail-closed で exec しない）:
//!
//! 1. 元のファイルの実行権限をカーネルに判定させる（`sys::access_exec_via_proc`。実行ビット・`noexec`）。
//!    memfd へ複製すると元のファイルの実行権限はカーネルから見えなくなるため、複製の前に確かめる。
//!    `EACCES` は `PermissionDenied`（違反にしない。今の `execve` の `EACCES` と同じ扱い）
//! 2. `st_size` が [`MAX_SEALED_COPY_BYTES`] を超えたら違反 [`ViolationReason::EntrypointCopyTooLarge`]
//!    （確保の前に判定する。疎なファイルでも `st_size` の段階で拒否される）
//! 3. memfd を作り（名前は固定値）、固定長バッファで複製する。複製したバイト数が `st_size` と一致しない・
//!    終端の先にまだ読めるデータがある（複製中の伸縮）なら `PermissionDenied`（違反にしない。
//!    `open_entrypoint` の「開き直しの間の競合」と同じ根拠）
//! 4. 封印して（`sys::seal_for_exec`）失敗したら違反 [`ViolationReason::EntrypointCopySealUnverified`]
//! 5. 読み取り専用で開き直し、開き直した fd の seal が 0x0F ちょうどであることを再確認する（違反
//!    [`ViolationReason::EntrypointCopySealUnverified`]）。書き込み用の fd はここで閉じる（`ETXTBSY` と
//!    書き込み用 fd の exec 先への継承を避ける）
//!
//! memfd の作成失敗（`ENOSYS`・`EACCES` = `vm.memfd_noexec=2`・`EPERM` = seccomp）は前提不足のシステム
//! エラーで、違反にはせず `FailedPrecondition` で拒否する（照合だけの方式 A へ黙って戻さない）。
//!
//! 限界: LSM（AppArmor・SELinux・IMA）の exec 検査は元のファイルについて再現しない。詳細は
//! `interpreter.rs` の「限界」。

use std::ffi::CStr;
use std::fs::{File, Metadata};
use std::os::fd::{AsFd as _, BorrowedFd};
use std::os::unix::fs::FileExt as _;

use crate::sys::{self, SealError, SealSet, SysError};
use crate::traits::types::ErrorCode;

use super::process::keep_above_stdio;
use super::{ExecError, IsolationStage, ViolationReason, describe};

/// 封印した複製を作るエントリポイントの最大サイズ（バイト）。複製は exec した子の cgroup の
/// `memory.max` に計上されるため、巨大なファイルによる exec ごとの確保（DoS）を断つ上限として 256 MiB とする。
pub const MAX_SEALED_COPY_BYTES: u64 = 256 * 1024 * 1024;

/// 複製に使う固定長バッファ（バイト）。子のスタックに置くため小さく保つ。
const COPY_CHUNK_BYTES: usize = 64 * 1024;

/// memfd の名前（固定値。外部入力を混ぜない）。`/proc/<pid>/fd/N` のリンク先は
/// `/memfd:fandhe-exec-entrypoint (deleted)` に見える。
const COPY_NAME: &CStr = c"fandhe-exec-entrypoint";

const STAGE: IsolationStage = IsolationStage::Exec;

/// `file`（照合済みのエントリポイントを読み取り専用で開いた fd。`meta` はその `fstat`）の封印した複製を作り、
/// 読み取り専用で開き直した fd とその `fstat` を返す。`subject` は違反・拒否の診断に載せるエントリポイントの
/// パス。手順と契約はモジュール doc を参照。
pub(super) fn seal_entrypoint_copy(
    file: &File,
    meta: &Metadata,
    procfs: BorrowedFd<'_>,
    subject: &std::path::Path,
) -> Result<(File, Metadata), ExecError> {
    seal_copy_bounded(file, meta.len(), MAX_SEALED_COPY_BYTES, procfs, subject)
}

/// [`seal_entrypoint_copy`] の本体。`size`（元の `st_size`）と `limit` を引数に取り、単体テストが小さい上限や
/// 食い違うサイズで境界を確かめられるようにする。
pub(super) fn seal_copy_bounded(
    file: &File,
    size: u64,
    limit: u64,
    procfs: BorrowedFd<'_>,
    subject: &std::path::Path,
) -> Result<(File, Metadata), ExecError> {
    check_executable(file, procfs, subject)?;
    if size > limit {
        return Err(ExecError::from_violation_at(
            ViolationReason::EntrypointCopyTooLarge,
            Some(subject),
            STAGE,
        ));
    }
    let writer = sys::memfd_create_for_exec_copy(COPY_NAME).map_err(|e| {
        ExecError::new(
            ErrorCode::FailedPrecondition,
            STAGE,
            format!(
                "memfd_create for the executable copy of the entrypoint failed: {}",
                describe(e)
            ),
        )
    })?;
    // 標準 fd が閉じた呼び出し側では memfd が 0〜2 を取り得る。後段の標準入出力の置換で潰されないよう 3 以上へ置く。
    let writer = File::from(keep_above_stdio(writer)?);
    copy_exact(file, &writer, size, subject)?;
    let sealed = sys::seal_for_exec(writer.into()).map_err(|e| seal_violation(&e, subject))?;
    let reopened = sys::reopen_pinned_read(procfs, sealed.as_fd())
        .map_err(|e| ExecError::from_sys(e, STAGE, "reopen of the executable copy"))
        .and_then(keep_above_stdio)
        .map(File::from)?;
    // 開き直した fd が付いた seal を持つことを、書き込み用 fd とは別に確かめる。
    let actual = sys::get_seals(reopened.as_fd())
        .map_err(|e| seal_violation(&SealError::Sys(e), subject))?;
    if actual != SealSet::EXEC_COPY {
        return Err(seal_violation(
            &SealError::Unexpected {
                actual: actual.bits(),
            },
            subject,
        ));
    }
    // 書き込み用の fd を閉じる（`ETXTBSY` と、書き込み可能な fd を exec 先へ残さないため）。
    drop(sealed);
    let meta = reopened
        .metadata()
        .map_err(|e| ExecError::from_io(&e, STAGE, "stat the executable copy"))?;
    if meta.len() != size {
        return Err(changed_while_copying(subject));
    }
    Ok((reopened, meta))
}

/// 手順 1: 元のファイルをカーネルが実行できると判定するか。
fn check_executable(
    file: &File,
    procfs: BorrowedFd<'_>,
    subject: &std::path::Path,
) -> Result<(), ExecError> {
    sys::access_exec_via_proc(procfs, file.as_fd()).map_err(|e| match e {
        SysError::Os(errno) if errno == sys::EACCES => ExecError::new(
            ErrorCode::PermissionDenied,
            STAGE,
            format!("the entrypoint {subject:?} is not executable (execute bit or noexec mount)"),
        ),
        // `faccessat2` を知らないカーネル（5.8 未満）などは前提不足。照合できないまま複製しない。
        SysError::Os(errno) if errno == sys::ENOSYS => ExecError::new(
            ErrorCode::FailedPrecondition,
            STAGE,
            "faccessat2 is unavailable; cannot check that the entrypoint is executable",
        ),
        other => ExecError::from_sys(other, STAGE, "faccessat2 of the entrypoint"),
    })
}

/// 手順 3: `size` バイトを `src` から `dst` へ複製し、複製中に元が伸縮していないことを確かめる。
fn copy_exact(
    src: &File,
    dst: &File,
    size: u64,
    subject: &std::path::Path,
) -> Result<(), ExecError> {
    let mut buf = [0u8; COPY_CHUNK_BYTES];
    let mut offset = 0u64;
    while offset < size {
        let want =
            usize::try_from(size - offset).map_or(COPY_CHUNK_BYTES, |n| n.min(COPY_CHUNK_BYTES));
        let chunk = buf
            .get_mut(..want)
            .ok_or_else(|| changed_while_copying(subject))?;
        let n = match src.read_at(chunk, offset) {
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(ExecError::from_io(&e, STAGE, "read of the entrypoint")),
        };
        if n == 0 {
            // `st_size` に届く前に終端: 複製中に縮んだ。
            return Err(changed_while_copying(subject));
        }
        let written = chunk
            .get(..n)
            .ok_or_else(|| changed_while_copying(subject))?;
        dst.write_all_at(written, offset)
            .map_err(|e| ExecError::from_io(&e, STAGE, "write of the executable copy"))?;
        offset += u64::try_from(n).map_err(|_| changed_while_copying(subject))?;
    }
    // 終端の先に読めるデータがあれば複製中に伸びた。
    let mut probe = [0u8; 1];
    loop {
        match src.read_at(&mut probe, size) {
            Ok(0) => return Ok(()),
            Ok(_) => return Err(changed_while_copying(subject)),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(ExecError::from_io(&e, STAGE, "read of the entrypoint")),
        }
    }
}

/// 複製中の伸縮による拒否（違反にしない。開き直しの間の競合と同じ根拠）。
fn changed_while_copying(subject: &std::path::Path) -> ExecError {
    ExecError::new(
        ErrorCode::PermissionDenied,
        STAGE,
        format!("the entrypoint {subject:?} changed while it was being copied"),
    )
}

/// 封印を確認できなかった失敗を違反へ写す（理由コードは静的トークン。errno 等の外部由来の文字列は載せない）。
fn seal_violation(_err: &SealError, subject: &std::path::Path) -> ExecError {
    ExecError::from_violation_at(
        ViolationReason::EntrypointCopySealUnverified,
        Some(subject),
        STAGE,
    )
}
#[cfg(test)]
mod tests {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    use std::path::{Path, PathBuf};

    use super::*;

    /// 試験ごとの作業ディレクトリ（pid とラベルで一意。drop で削除）。
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(label: &str) -> Self {
            let dir = std::env::temp_dir()
                .join(format!("fandhe-sealed-copy-{label}-{}", std::process::id()));
            std::fs::create_dir_all(&dir).expect("mkdir");
            Self(dir)
        }

        /// `mode` の通常ファイルを作り、読み取り専用で開いて返す。
        fn file(&self, name: &str, content: &[u8], mode: u32) -> File {
            let path = self.0.join(name);
            std::fs::write(&path, content).expect("write");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).expect("chmod");
            File::open(&path).expect("open")
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn procfs() -> File {
        File::open("/proc").expect("open /proc")
    }

    fn violation_of(err: &ExecError) -> Option<ViolationReason> {
        err.violation.as_ref().map(|v| v.reason)
    }

    /// SUP-6・SEC-1（TASK-163 追補・#1531）: 複製の内容・サイズが元と一致し、開き直した fd の seal が 0x0F ちょうどで、
    /// リンク先が固定名の memfd になる。複製は元とは別の inode で、読み取り専用。
    #[test]
    fn sup6_sec1_task163_copy_is_exact_sealed_and_read_only() {
        let scratch = Scratch::new("exact");
        // 複数の読み取りチャンクにまたがるサイズ（チャンク 64 KiB の 2 倍強）。
        let mut content = b"#!/bin/sh\nexit 0\n".to_vec();
        content.resize(COPY_CHUNK_BYTES * 2 + 123, b'x');
        let file = scratch.file("script", &content, 0o755);
        let size = u64::try_from(content.len()).expect("size");
        let procfs = procfs();
        let (copy, meta) = seal_copy_bounded(
            &file,
            size,
            MAX_SEALED_COPY_BYTES,
            procfs.as_fd(),
            Path::new("/script"),
        )
        .expect("seal_copy_bounded");
        assert_eq!(meta.len(), size);
        let mut read_back = vec![0u8; content.len()];
        copy.read_exact_at(&mut read_back, 0).expect("read copy");
        assert_eq!(read_back, content);
        assert_eq!(sys::get_seals(copy.as_fd()).expect("seals").bits(), 0x0F);
        let link = std::fs::read_link(format!(
            "/proc/self/fd/{}",
            std::os::fd::AsRawFd::as_raw_fd(&copy)
        ))
        .expect("readlink");
        assert_eq!(
            link.to_string_lossy(),
            "/memfd:fandhe-exec-entrypoint (deleted)"
        );
        let original = file.metadata().expect("stat");
        assert_ne!((meta.dev(), meta.ino()), (original.dev(), original.ino()));
        // 読み取り専用で開き直した fd への書き込みは拒否される。
        assert!(copy.write_at(b"y", 0).is_err());
    }

    /// SEC-4・SUP-6（#1531）: 上限を超える `st_size` は違反 `entrypoint_copy_too_large`
    /// （`PermissionDenied`・段 `Exec`）。上限ちょうどは通る。
    #[test]
    fn sec4_sup6_task163_oversized_entrypoint_is_a_violation() {
        let scratch = Scratch::new("limit");
        let file = scratch.file("script", &[b'a'; 100], 0o755);
        let procfs = procfs();
        let err = seal_copy_bounded(&file, 100, 99, procfs.as_fd(), Path::new("/script"))
            .expect_err("over the limit");
        assert_eq!(
            violation_of(&err),
            Some(ViolationReason::EntrypointCopyTooLarge)
        );
        assert_eq!(err.code, ErrorCode::PermissionDenied);
        assert_eq!(err.stage, IsolationStage::Exec);
        let ok = seal_copy_bounded(&file, 100, 100, procfs.as_fd(), Path::new("/script"));
        assert_eq!(ok.expect("at the limit").1.len(), 100);
    }

    /// SEC-1（#1531）: 複製中の伸縮（`st_size` が実際より大きい・小さい）は拒否するが、違反にはしない。
    #[test]
    fn sec1_task163_size_mismatch_is_denied_without_violation() {
        let scratch = Scratch::new("mismatch");
        let file = scratch.file("script", &[b'a'; 100], 0o755);
        let procfs = procfs();
        for claimed in [101u64, 99] {
            let err = seal_copy_bounded(
                &file,
                claimed,
                MAX_SEALED_COPY_BYTES,
                procfs.as_fd(),
                Path::new("/script"),
            )
            .expect_err("size mismatch");
            assert_eq!(violation_of(&err), None, "claimed size {claimed}");
            assert_eq!(err.code, ErrorCode::PermissionDenied);
            assert_eq!(err.stage, IsolationStage::Exec);
        }
    }

    /// SEC-1（#1531）: 実行ビットのないファイルは複製の前に拒否する（memfd は元の mode を引き継がないため、
    /// 照合しないと実行できてしまう）。`PermissionDenied` で、違反にはしない。
    #[test]
    fn sec1_task163_non_executable_file_is_denied_before_copy() {
        let scratch = Scratch::new("noexec-bit");
        let file = scratch.file("script", b"#!/bin/sh\n", 0o644);
        let procfs = procfs();
        let err = seal_copy_bounded(
            &file,
            10,
            MAX_SEALED_COPY_BYTES,
            procfs.as_fd(),
            Path::new("/s"),
        )
        .expect_err("not executable");
        assert_eq!(violation_of(&err), None);
        assert_eq!(err.code, ErrorCode::PermissionDenied);
        assert_eq!(err.stage, IsolationStage::Exec);
    }

    /// SEC-4・SEC-1（#1531）: 封印の失敗（syscall の失敗・期待と異なる seal）は、どちらも違反
    /// `entrypoint_copy_seal_unverified`（`FailedPrecondition`・段 `Exec`）に写る。実 fd での失敗
    /// （memfd でない fd は `Sys`）も同じ違反になる。
    #[test]
    fn sec4_sec1_task163_seal_failures_map_to_the_violation() {
        let real = sys::seal_for_exec(File::open("/dev/null").expect("open").into())
            .expect_err("not a memfd");
        assert!(matches!(real, SealError::Sys(SysError::Os(_))), "{real:?}");
        for err in [
            real,
            SealError::Sys(SysError::Os(sys::EINVAL)),
            SealError::Unexpected { actual: 0x2F },
        ] {
            let mapped = seal_violation(&err, Path::new("/script"));
            assert_eq!(
                violation_of(&mapped),
                Some(ViolationReason::EntrypointCopySealUnverified)
            );
            assert_eq!(mapped.code, ErrorCode::FailedPrecondition);
            assert_eq!(mapped.stage, IsolationStage::Exec);
        }
    }
}
