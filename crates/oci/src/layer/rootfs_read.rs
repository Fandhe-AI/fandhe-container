//! 展開済み rootfs の中の通常ファイルを、rootfs の外へ出ずに上限つきで読む口（SEC-1・SEC-5・OCI-1・REPAIR-5。#2606）。
//!
//! # 役割
//! `fandhe-container-cri` の `ImageRootfsSource` が、イメージ config の `User` に含まれる名前を `/etc/passwd`・
//! `/etc/group` で解決するときに呼ぶ。rootfs の中身はイメージ作者が決めるため、`etc` や `etc/passwd` が
//! ホストの任意の場所（`/etc/shadow` 等）を指す symlink になりうる。パスで開くとその内容を読んでしまうので、
//! `root` を `openat2` で 1 回だけ開き、以後は fd 起点で `RESOLVE_IN_ROOT | RESOLVE_NO_SYMLINKS |
//! RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV` を付けて開く（`layer::anchored` と同じ方式）。
//!
//! # 契約
//! - 戻り値の `Ok(None)` は「存在しない」（`ENOENT`）だけ。symlink（途中・最終のどちらも）・マウント越え・
//!   非ディレクトリの途中要素・通常ファイル以外（FIFO・デバイス・ディレクトリ）はエラーで、内容を返さない
//! - `max_bytes` を超えたら `ResourceExhausted`（確保は上限に縛られる）
//! - FIFO 等でブロックしないよう、種別は `O_PATH` の fstat で読み取りの open より前に確かめ、読み取りの open は
//!   `O_NONBLOCK` を付けて同じ実体（dev・ino）であることを照合する
//! - `openat2` が使えない環境・Linux の x86_64 / aarch64 以外はパス起点へ縮退せず `Unimplemented`（fail-closed）

use std::path::Path;

use crate::error::OciError;

/// `rel` が指す rootfs 内の通常ファイルを最大 `max_bytes` バイトまで読む。存在しなければ `Ok(None)`。
///
/// `rel` の各要素は 1 コンポーネント（空・`.`・`..`・`/`・NUL を含まない）でなければ `InvalidArgument`。
pub fn read_rootfs_file(
    root: &Path,
    rel: &[&str],
    max_bytes: u64,
) -> Result<Option<Vec<u8>>, OciError> {
    imp::read_rootfs_file(root, rel, max_bytes)
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod imp {
    use std::fs::File;
    use std::io::{self, Read as _};
    use std::os::fd::AsFd as _;
    use std::os::unix::ffi::OsStrExt as _;
    use std::os::unix::fs::MetadataExt as _;
    use std::path::Path;

    use crate::error::{OciError, OciErrorCode};
    use crate::layer::extract::err;
    use crate::sys::at;

    const RESOLVE: u64 = at::RESOLVE_IN_ROOT
        | at::RESOLVE_NO_SYMLINKS
        | at::RESOLVE_NO_MAGICLINKS
        | at::RESOLVE_NO_XDEV;
    /// `RESOLVE_IN_ROOT` の競合検出（`EAGAIN`）の再試行の上限。
    const MAX_EAGAIN_RETRIES: u32 = 8;
    /// `S_IFMT` と `S_IFREG`（`include/uapi/linux/stat.h`）。
    const S_IFMT: u32 = 0o170_000;
    const S_IFREG: u32 = 0o100_000;
    /// `ENOENT`（`errno-base.h`）。
    const ENOENT: i32 = 2;

    fn changed() -> OciError {
        err(
            OciErrorCode::FailedPrecondition,
            "a rootfs path is not a plain file inside the rootfs",
        )
    }

    /// `ENOENT` は `None`（不在）、それ以外は構造化エラー。
    fn map_err(e: &io::Error) -> Option<OciError> {
        match e.raw_os_error() {
            Some(ENOENT) => None,
            Some(at::ELOOP | at::EXDEV | at::ENOTDIR | at::EAGAIN | at::EISDIR) => Some(changed()),
            Some(at::ENOSYS | at::E2BIG | at::EINVAL) => Some(err(
                OciErrorCode::Unimplemented,
                "openat2 is not available on this kernel",
            )),
            _ => Some(err(
                OciErrorCode::Internal,
                "failed to read the rootfs file",
            )),
        }
    }

    fn open_rel(root: &File, rel: &std::ffi::CStr, flags: u64) -> Result<Option<File>, OciError> {
        let mut tries = 0;
        loop {
            match at::openat2(Some(root.as_fd()), rel, flags, 0, RESOLVE) {
                Ok(fd) => return Ok(Some(File::from(fd))),
                Err(e) if e.raw_os_error() == Some(at::EAGAIN) && tries < MAX_EAGAIN_RETRIES => {
                    tries += 1;
                }
                Err(e) => return map_err(&e).map_or(Ok(None), Err),
            }
        }
    }

    pub(super) fn read_rootfs_file(
        root: &Path,
        rel: &[&str],
        max_bytes: u64,
    ) -> Result<Option<Vec<u8>>, OciError> {
        let invalid = || err(OciErrorCode::InvalidArgument, "rootfs path is invalid");
        if rel.is_empty() {
            return Err(invalid());
        }
        let rel_c = at::relative_cstring(rel).map_err(|_| invalid())?;
        let root_c = std::ffi::CString::new(root.as_os_str().as_bytes()).map_err(|_| invalid())?;
        let root_fd = at::openat2(
            None,
            &root_c,
            at::O_RDONLY | at::O_DIRECTORY | at::O_NOFOLLOW | at::O_CLOEXEC,
            0,
            0,
        )
        .map_err(|e| match e.raw_os_error() {
            Some(at::ENOSYS | at::E2BIG | at::EINVAL) => err(
                OciErrorCode::Unimplemented,
                "openat2 is not available on this kernel",
            ),
            _ => err(OciErrorCode::InvalidArgument, "rootfs root is not usable"),
        })?;
        let root_file = File::from(root_fd);

        // 1. O_PATH で実体の種別だけ確かめる（FIFO・デバイスは読み取りで開かない）。
        let Some(probe) = open_rel(
            &root_file,
            &rel_c,
            at::O_PATH | at::O_NOFOLLOW | at::O_CLOEXEC,
        )?
        else {
            return Ok(None);
        };
        let probe_meta = probe
            .metadata()
            .map_err(|_| err(OciErrorCode::Internal, "failed to inspect the rootfs file"))?;
        if probe_meta.mode() & S_IFMT != S_IFREG {
            return Err(changed());
        }
        // 2. 同じ経路を非ブロッキングで開き直し、同じ実体であることを照合する（差し替えの検出）。
        let Some(file) = open_rel(
            &root_file,
            &rel_c,
            at::O_RDONLY | at::O_NOFOLLOW | at::O_NONBLOCK | at::O_CLOEXEC,
        )?
        else {
            return Err(changed());
        };
        let meta = file
            .metadata()
            .map_err(|_| err(OciErrorCode::Internal, "failed to inspect the rootfs file"))?;
        if meta.mode() & S_IFMT != S_IFREG
            || meta.dev() != probe_meta.dev()
            || meta.ino() != probe_meta.ino()
        {
            return Err(changed());
        }
        let mut body = Vec::new();
        (&file)
            .take(max_bytes.saturating_add(1))
            .read_to_end(&mut body)
            .map_err(|_| err(OciErrorCode::Internal, "failed to read the rootfs file"))?;
        if body.len() as u64 > max_bytes {
            return Err(err(
                OciErrorCode::ResourceExhausted,
                "rootfs file exceeds the size limit",
            ));
        }
        Ok(Some(body))
    }
}

#[cfg(not(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
)))]
mod imp {
    use std::path::Path;

    use crate::error::{OciError, OciErrorCode};

    /// fd 起点の読み取りを持たない環境では、パス起点へ縮退せず拒否する（fail-closed）。
    pub(super) fn read_rootfs_file(
        _root: &Path,
        _rel: &[&str],
        _max_bytes: u64,
    ) -> Result<Option<Vec<u8>>, OciError> {
        Err(crate::layer::extract::err(
            OciErrorCode::Unimplemented,
            "rootfs file reading is not available on this platform",
        ))
    }
}

#[cfg(all(
    test,
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod tests {
    use super::*;
    use crate::error::OciErrorCode;
    use std::os::unix::fs::symlink;

    fn tmp(tag: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("fc-rootfs-read-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    /// SEC-5・OCI-1: 通常ファイルは具体的なバイト列で読め、不在は None。
    #[test]
    fn sec5_reads_plain_file_and_absent_is_none() {
        let r = tmp("plain");
        std::fs::create_dir(r.join("etc")).unwrap();
        std::fs::write(r.join("etc/passwd"), b"root:x:0:0\n").unwrap();
        assert_eq!(
            read_rootfs_file(&r, &["etc", "passwd"], 1024).unwrap(),
            Some(b"root:x:0:0\n".to_vec())
        );
        assert_eq!(read_rootfs_file(&r, &["etc", "group"], 1024).unwrap(), None);
        assert_eq!(
            read_rootfs_file(&r, &["nope", "group"], 1024).unwrap(),
            None
        );
        let _ = std::fs::remove_dir_all(&r);
    }

    /// SEC-1・SEC-5: `etc` がホスト側ディレクトリへの symlink でも内容を返さない。
    #[test]
    fn sec1_symlinked_dir_is_rejected() {
        let r = tmp("symdir");
        let host = tmp("symdir-host");
        std::fs::write(host.join("passwd"), b"host:x:0:0\n").unwrap();
        symlink(&host, r.join("etc")).unwrap();
        let e = read_rootfs_file(&r, &["etc", "passwd"], 1024).unwrap_err();
        assert_eq!(e.code(), OciErrorCode::FailedPrecondition);
        let _ = std::fs::remove_dir_all(&r);
        let _ = std::fs::remove_dir_all(&host);
    }

    /// SEC-1・SEC-5: 最終要素が symlink（ホストのファイル）でも内容を返さない。
    #[test]
    fn sec1_symlinked_file_is_rejected() {
        let r = tmp("symfile");
        let host = tmp("symfile-host");
        std::fs::write(host.join("shadow"), b"secret\n").unwrap();
        std::fs::create_dir(r.join("etc")).unwrap();
        symlink(host.join("shadow"), r.join("etc/passwd")).unwrap();
        let e = read_rootfs_file(&r, &["etc", "passwd"], 1024).unwrap_err();
        assert_eq!(e.code(), OciErrorCode::FailedPrecondition);
        let _ = std::fs::remove_dir_all(&r);
        let _ = std::fs::remove_dir_all(&host);
    }

    /// REPAIR-5: FIFO・ディレクトリはブロックせずエラー（FIFO は `mkfifo` コマンドで作る）。
    #[test]
    fn repair5_fifo_and_directory_are_rejected_without_blocking() {
        let r = tmp("fifo");
        std::fs::create_dir(r.join("etc")).unwrap();
        // REPAIR-5: 外部コマンドの待機にも期限を設け、超過時は kill して回収する。
        let mut child = std::process::Command::new("mkfifo")
            .arg(r.join("etc/passwd"))
            .spawn()
            .expect("mkfifo must be available for this test");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let ok = loop {
            match child.try_wait().expect("try_wait") {
                Some(s) => break s.success(),
                None if std::time::Instant::now() >= deadline => {
                    let _ = child.kill();
                    let _ = child.wait();
                    break false;
                }
                None => std::thread::sleep(std::time::Duration::from_millis(10)),
            }
        };
        assert!(ok, "mkfifo must be available for this test");
        let e = read_rootfs_file(&r, &["etc", "passwd"], 1024).unwrap_err();
        assert_eq!(e.code(), OciErrorCode::FailedPrecondition);
        std::fs::create_dir(r.join("etc/group")).unwrap();
        let e = read_rootfs_file(&r, &["etc", "group"], 1024).unwrap_err();
        assert_eq!(e.code(), OciErrorCode::FailedPrecondition);
        let _ = std::fs::remove_dir_all(&r);
    }

    /// REPAIR-5: 上限ちょうどは成功、-1 は ResourceExhausted。
    #[test]
    fn repair5_size_limit_boundary() {
        let r = tmp("limit");
        std::fs::write(r.join("f"), b"12345").unwrap();
        assert_eq!(
            read_rootfs_file(&r, &["f"], 5).unwrap(),
            Some(b"12345".to_vec())
        );
        let e = read_rootfs_file(&r, &["f"], 4).unwrap_err();
        assert_eq!(e.code(), OciErrorCode::ResourceExhausted);
        let _ = std::fs::remove_dir_all(&r);
    }

    /// SEC-1: `..`・空要素・空列は InvalidArgument。
    #[test]
    fn sec1_invalid_components_are_rejected() {
        let r = tmp("inv");
        let cases: [&[&str]; 4] = [&[".."], &["etc", ""], &["a/b"], &[]];
        for rel in cases {
            let e = read_rootfs_file(&r, rel, 16).unwrap_err();
            assert_eq!(e.code(), OciErrorCode::InvalidArgument);
        }
        let _ = std::fs::remove_dir_all(&r);
    }
}
