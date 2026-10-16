//! 起動する外部実行ファイル（supervisor の bin・`systemd-run`）の事前検証（TASK-190・OWASP 不安全な設計）。
//!
//! ベンチは `--supervisor-bin` / `--systemd-run` で受けた絶対パスを起動する。他ユーザーが差し替えられる実行ファイルを
//! 起動しないよう、起動前に所有者・書き込み権限・symlink・親ディレクトリを検証する。検証から exec までの TOCTOU は
//! 残る（開発者のローカル target ディレクトリを対象とする計測道具のため許容し、doc に記す）。
//! `std::os::unix::fs::MetadataExt` だけで行い、`unsafe` は使わない。

use super::StartupLatencyError;
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;

fn untrusted(message: &str) -> StartupLatencyError {
    StartupLatencyError::new("untrusted-binary", message)
}

/// 実行ファイルを検証する。絶対パス・symlink でない通常ファイル・実行ビットあり・group/other 書き込み不可・
/// 所有者が `euid` か root・親ディレクトリが other 書き込み不可、をすべて満たさなければ拒否する。
pub fn verify_executable(path: &Path, euid: u32) -> Result<(), StartupLatencyError> {
    if !path.is_absolute() {
        return Err(StartupLatencyError::new(
            "invalid-args",
            "executable path must be absolute",
        ));
    }
    let meta =
        std::fs::symlink_metadata(path).map_err(|_| untrusted("executable is not accessible"))?;
    if !meta.file_type().is_file() {
        return Err(untrusted(
            "executable must be a regular file, not a symlink",
        ));
    }
    let mode = meta.mode();
    if mode & 0o111 == 0 {
        return Err(untrusted("executable has no execute bit"));
    }
    if mode & 0o022 != 0 {
        return Err(untrusted("executable is writable by group or others"));
    }
    if meta.uid() != euid && meta.uid() != 0 {
        return Err(untrusted("executable owner is neither the caller nor root"));
    }
    let parent = path
        .parent()
        .ok_or_else(|| untrusted("executable has no parent directory"))?;
    let parent_meta =
        std::fs::metadata(parent).map_err(|_| untrusted("parent directory is not accessible"))?;
    if parent_meta.mode() & 0o002 != 0 {
        return Err(untrusted("parent directory is writable by others"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::probe_env::effective_uid;
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::PathBuf;

    /// 0700 の専用ディレクトリ（テスト後に削除）。
    struct Dir(PathBuf);

    impl Dir {
        fn new(tag: &str) -> Self {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0);
            let p = std::env::temp_dir()
                .join(format!("fc-bincheck-{tag}-{}-{nanos}", std::process::id()));
            std::fs::create_dir(&p).expect("mkdir");
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700)).expect("chmod");
            Self(p)
        }

        fn file(&self, name: &str, mode: u32) -> PathBuf {
            let f = self.0.join(name);
            std::fs::write(&f, b"x").expect("write");
            std::fs::set_permissions(&f, std::fs::Permissions::from_mode(mode)).expect("chmod");
            f
        }
    }

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn euid() -> u32 {
        effective_uid().expect("euid")
    }

    #[test]
    fn regular_0755_file_is_accepted() {
        let d = Dir::new("ok");
        assert_eq!(verify_executable(&d.file("bin", 0o755), euid()), Ok(()));
    }

    #[test]
    fn symlink_is_rejected() {
        let d = Dir::new("sym");
        let target = d.file("real", 0o755);
        let link = d.0.join("link");
        std::os::unix::fs::symlink(&target, &link).expect("symlink");
        assert_eq!(
            verify_executable(&link, euid()).expect_err("reject").code,
            "untrusted-binary"
        );
    }

    #[test]
    fn group_other_writable_is_rejected() {
        let d = Dir::new("w");
        assert_eq!(
            verify_executable(&d.file("bin", 0o777), euid())
                .expect_err("reject")
                .code,
            "untrusted-binary"
        );
    }

    #[test]
    fn relative_path_is_rejected() {
        assert_eq!(
            verify_executable(Path::new("rel/bin"), euid())
                .expect_err("reject")
                .code,
            "invalid-args"
        );
    }

    #[test]
    fn file_without_execute_bit_is_rejected() {
        let d = Dir::new("nx");
        assert_eq!(
            verify_executable(&d.file("bin", 0o644), euid())
                .expect_err("reject")
                .code,
            "untrusted-binary"
        );
    }

    #[test]
    fn foreign_owner_is_rejected() {
        let d = Dir::new("own");
        let f = d.file("bin", 0o755);
        // 所有者が自分でも root でもない UID を要求した場合は拒否される（euid を偽って照合する）。
        let other = euid().wrapping_add(12345);
        let file_owner = std::fs::metadata(&f).expect("meta").uid();
        if file_owner != 0 {
            assert_eq!(
                verify_executable(&f, other).expect_err("reject").code,
                "untrusted-binary"
            );
        }
    }
}
