//! 起動する外部実行ファイル（supervisor の bin・`systemd-run`）の事前検証（TASK-190・OWASP 不安全な設計）。
//!
//! ベンチは `--supervisor-bin` / `--systemd-run` で受けた絶対パスを起動する。他ユーザーが差し替えられる実行ファイルを
//! 起動しないよう、起動前に所有者・書き込み権限・symlink・全祖先ディレクトリを検証する。検証から exec までの TOCTOU は
//! 残る（開発者のローカル target ディレクトリを対象とする計測道具のため許容し、doc に記す）。
//! `std::os::unix::fs::MetadataExt` だけで行い、`unsafe` は使わない。

use super::StartupLatencyError;
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;

fn untrusted(message: &str) -> StartupLatencyError {
    StartupLatencyError::new("untrusted-binary", message)
}

/// 実行ファイルを検証する。絶対パス・symlink でない通常ファイル・実行ビットあり・group/other 書き込み不可・
/// 所有者が `euid` か root・全祖先ディレクトリ（字面上と実体の両方）が実効 UID か root 所有で other 書き込み不可・group 書き込み不可（sticky 付きは可）、をすべて満たさなければ拒否する。
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
    // 字面上の祖先と、symlink を解決した実体の祖先の両方を検証する。symlink の差し替えにはそれを置く
    // ディレクトリの書き込み権が要るため、字面上の祖先の検証がそれも覆う。
    let real =
        std::fs::canonicalize(path).map_err(|_| untrusted("executable is not accessible"))?;
    for chain in [path, real.as_path()] {
        for dir in chain.ancestors().skip(1) {
            verify_ancestor(dir, euid)?;
        }
    }
    Ok(())
}

/// 祖先ディレクトリ 1 つを検証する。ディレクトリで、所有者が `euid` か root で、group / other 書き込み不可であること。
/// 実効 GID はユーザー専用 group とは限らず、同じ group の別 UID が検証後に実行ファイルを差し替えられるため、
/// group 書き込み可は（自分の group でも）拒否する。umask 002 で `target/` が 0775 になる環境では
/// `chmod g-w` した場所へバイナリを置く。sticky ビット付きは `/tmp` のように他者が差し替えられないため許容する。
fn verify_ancestor(dir: &Path, euid: u32) -> Result<(), StartupLatencyError> {
    // symlink 自体の所有者を先に検証する。`metadata` は symlink を辿るため、別 UID 所有の symlink が
    // 信頼済みディレクトリを指す配置（sticky 共有ディレクトリ内で所有者が差し替えられる）を見逃す。
    let link_meta = std::fs::symlink_metadata(dir)
        .map_err(|_| untrusted("ancestor directory is not accessible"))?;
    if link_meta.file_type().is_symlink() && link_meta.uid() != euid && link_meta.uid() != 0 {
        return Err(untrusted(
            "ancestor symlink owner is neither the caller nor root",
        ));
    }
    let meta =
        std::fs::metadata(dir).map_err(|_| untrusted("ancestor directory is not accessible"))?;
    if !meta.is_dir() {
        return Err(untrusted("ancestor is not a directory"));
    }
    if meta.uid() != euid && meta.uid() != 0 {
        return Err(untrusted(
            "ancestor directory owner is neither the caller nor root",
        ));
    }
    let mode = meta.mode();
    if mode & 0o1000 == 0 {
        if mode & 0o002 != 0 {
            return Err(untrusted("ancestor directory is writable by others"));
        }
        if mode & 0o020 != 0 {
            return Err(untrusted("ancestor directory is writable by a group"));
        }
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

    /// 自分の group でも group 書き込み可の祖先は拒否する（同 group の別 UID による差し替えを防ぐ）。
    #[test]
    fn group_writable_ancestor_is_rejected_even_for_own_group() {
        let d = Dir::new("og");
        let sub = d.0.join("target");
        std::fs::create_dir(&sub).expect("mkdir");
        let f = sub.join("bin");
        std::fs::write(&f, b"x").expect("write");
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        std::fs::set_permissions(&d.0, std::fs::Permissions::from_mode(0o770)).expect("chmod");
        assert_eq!(
            verify_executable(&f, euid()).expect_err("reject").code,
            "untrusted-binary"
        );
    }

    /// group 書き込み不可（0755）の祖先配下は受け入れる。
    #[test]
    fn non_group_writable_ancestor_is_accepted() {
        let d = Dir::new("ng");
        let f = d.file("bin", 0o755);
        std::fs::set_permissions(&d.0, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        assert_eq!(verify_executable(&f, euid()), Ok(()));
    }

    /// 祖先が other 書き込み可（sticky なし）なら、実行ファイル自体が 0755 でも拒否する。
    #[test]
    fn other_writable_ancestor_is_rejected() {
        let d = Dir::new("gw");
        let sub = d.0.join("sub");
        std::fs::create_dir(&sub).expect("mkdir");
        let f = sub.join("bin");
        std::fs::write(&f, b"x").expect("write");
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        // 直近の親ではなく祖先（d.0）を group 書き込み可にする。
        std::fs::set_permissions(&d.0, std::fs::Permissions::from_mode(0o707)).expect("chmod");
        assert_eq!(
            verify_executable(&f, euid()).expect_err("reject").code,
            "untrusted-binary"
        );
    }

    /// 祖先の所有者が自分でも root でもなければ拒否する（euid を偽って照合する）。
    #[test]
    fn foreign_owned_ancestor_is_rejected() {
        let d = Dir::new("fa");
        let dir_owner = std::fs::metadata(&d.0).expect("meta").uid();
        if dir_owner != 0 {
            assert_eq!(
                verify_ancestor(&d.0, dir_owner.wrapping_add(1))
                    .expect_err("reject")
                    .code,
                "untrusted-binary"
            );
        }
    }

    /// symlink 経由で other 書き込み可の実体ディレクトリへ出る配置も拒否する。
    #[test]
    fn symlinked_ancestor_into_writable_dir_is_rejected() {
        let d = Dir::new("sl");
        let real = d.0.join("real");
        std::fs::create_dir(&real).expect("mkdir");
        let f = real.join("bin");
        std::fs::write(&f, b"x").expect("write");
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o757)).expect("chmod");
        let link = d.0.join("link");
        std::os::unix::fs::symlink(&real, &link).expect("symlink");
        assert_eq!(
            verify_executable(&link.join("bin"), euid())
                .expect_err("reject")
                .code,
            "untrusted-binary"
        );
    }

    /// 別 UID 所有の祖先 symlink は、指す先が信頼済み（root 所有）でも拒否する（euid を偽って照合する）。
    #[test]
    fn foreign_owned_ancestor_symlink_is_rejected() {
        let d = Dir::new("fl");
        let link = d.0.join("link");
        std::os::unix::fs::symlink("/", &link).expect("symlink");
        let owner = std::fs::symlink_metadata(&link).expect("meta").uid();
        if owner != 0 {
            let err = verify_ancestor(&link, owner.wrapping_add(1)).expect_err("reject");
            assert_eq!(err.code, "untrusted-binary");
            assert!(err.message.contains("symlink"), "{}", err.message);
            assert_eq!(verify_ancestor(&link, owner), Ok(()));
        }
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
