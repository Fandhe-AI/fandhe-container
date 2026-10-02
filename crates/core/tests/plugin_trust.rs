//! plugin 所有者・モード検証の結合試験（TASK-122.1・PLUG-11・REPAIR-12）。
//!
//! 公開 API のみを使い、一時ディレクトリのモードは `set_permissions` で明示して umask に
//! 依存させない。所有者不一致の実ファイル試験は chown（root）が要るため作らず、判定論理は
//! `check_owner_and_mode` の単体テストで担保する。

use std::fs;
use std::path::PathBuf;

use fandhe_container_core::plugin_trust::{
    PluginTrustErrorKind, TrustTarget, check_owner_and_mode, verify_plugin_dir,
};

/// テスト用の一意な一時ディレクトリ（終了時に削除）。
struct Tmp(PathBuf);

impl Tmp {
    fn new(tag: &str) -> Self {
        let p = std::env::temp_dir().join(format!(
            "fandhe-plugin-trust-{}-{}",
            std::process::id(),
            tag
        ));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).expect("create tmp dir");
        Self(p)
    }
}

impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn plug11_task122_1_pure_check_is_reachable_from_public_api() {
    assert_eq!(check_owner_and_mode(0, 0o755, 1000), Ok(()));
    assert_eq!(
        check_owner_and_mode(1, 0o755, 1000),
        Err(PluginTrustErrorKind::UntrustedOwner)
    );
}

#[cfg(not(target_os = "linux"))]
#[test]
fn plug11_task122_1_non_linux_is_rejected_fail_closed() {
    let tmp = Tmp::new("nonlinux");
    let err = verify_plugin_dir(&tmp.0).expect_err("must reject");
    assert_eq!(err.kind(), PluginTrustErrorKind::Unsupported);
    assert_eq!(err.target(), TrustTarget::Directory);
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use fandhe_container_core::plugin_discovery::{
        PluginDirKind, PluginSearchDir, discover_candidates,
    };
    use fandhe_container_core::plugin_trust::verify_candidate;
    use fandhe_container_core::traits::{ErrorCode, TraitError};
    use std::ffi::OsStr;
    use std::io::Read as _;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink};
    use std::path::Path;

    const NAME: &str = "fandhe-container-plugin-x";

    fn chmod(p: &Path, mode: u32) {
        fs::set_permissions(p, fs::Permissions::from_mode(mode)).expect("chmod");
    }

    /// dir を `dir_mode`、その中の plugin ファイルを `file_mode` で用意する。
    fn setup(tag: &str, dir_mode: u32, file_mode: u32) -> Tmp {
        let tmp = Tmp::new(tag);
        chmod(&tmp.0, dir_mode);
        let f = tmp.0.join(NAME);
        fs::write(&f, b"payload").expect("write");
        chmod(&f, file_mode);
        tmp
    }

    #[test]
    fn plug11_task122_1_accepts_and_hands_over_same_fd() {
        let tmp = setup("ok", 0o755, 0o755);
        let dir = verify_plugin_dir(&tmp.0).expect("dir ok");
        let v = dir.verify_file(OsStr::new(NAME)).expect("file ok");
        let md = fs::metadata(tmp.0.join(NAME)).unwrap();
        assert_eq!(v.owner_uid(), md.uid());
        assert_eq!(v.mode() & 0o7777, 0o755);
        let mut s = String::new();
        v.file().read_to_string(&mut s).unwrap();
        assert_eq!(s, "payload");
    }

    #[test]
    fn plug11_task122_1_rejects_writable_file() {
        for mode in [0o775, 0o757, 0o777] {
            let tmp = setup(&format!("fw{mode:o}"), 0o755, mode);
            let dir = verify_plugin_dir(&tmp.0).expect("dir ok");
            let err = dir.verify_file(OsStr::new(NAME)).expect_err("reject");
            assert_eq!(err.kind(), PluginTrustErrorKind::GroupOrOtherWritable);
            assert_eq!(err.target(), TrustTarget::File);
        }
    }

    #[test]
    fn plug11_task122_1_rejects_writable_dir() {
        for mode in [0o775, 0o777, 0o1777] {
            let tmp = setup(&format!("dw{mode:o}"), mode, 0o755);
            let err = verify_plugin_dir(&tmp.0).expect_err("reject");
            assert_eq!(err.kind(), PluginTrustErrorKind::GroupOrOtherWritable);
            assert_eq!(err.target(), TrustTarget::Directory);
        }
    }

    #[test]
    fn plug11_task122_1_rejects_symlinks() {
        let tmp = setup("sym", 0o755, 0o755);
        let link = tmp.0.join("fandhe-container-plugin-link");
        symlink(tmp.0.join(NAME), &link).unwrap();
        let dir = verify_plugin_dir(&tmp.0).expect("dir ok");
        let err = dir
            .verify_file(OsStr::new("fandhe-container-plugin-link"))
            .expect_err("reject");
        assert_eq!(err.kind(), PluginTrustErrorKind::NotRegularFile);

        let dlink = std::env::temp_dir().join(format!(
            "fandhe-plugin-trust-{}-dirlink",
            std::process::id()
        ));
        let _ = fs::remove_file(&dlink);
        symlink(&tmp.0, &dlink).unwrap();
        let err = verify_plugin_dir(&dlink).expect_err("reject");
        let _ = fs::remove_file(&dlink);
        assert_eq!(err.kind(), PluginTrustErrorKind::NotDirectory);
    }

    #[test]
    fn plug11_task122_1_rejects_directory_as_file() {
        let tmp = setup("dirfile", 0o755, 0o755);
        let sub = tmp.0.join("subdir");
        fs::create_dir(&sub).unwrap();
        chmod(&sub, 0o755);
        let dir = verify_plugin_dir(&tmp.0).expect("dir ok");
        let err = dir.verify_file(OsStr::new("subdir")).expect_err("reject");
        assert_eq!(err.kind(), PluginTrustErrorKind::NotRegularFile);
    }

    #[test]
    fn plug11_task122_1_held_fd_survives_path_replacement() {
        let tmp = setup("swap", 0o755, 0o755);
        let dir = verify_plugin_dir(&tmp.0).expect("dir ok");
        let v = dir.verify_file(OsStr::new(NAME)).expect("file ok");
        let other = tmp.0.join("other");
        fs::write(&other, b"evil").unwrap();
        fs::rename(&other, tmp.0.join(NAME)).unwrap();
        let mut s = String::new();
        v.into_file().read_to_string(&mut s).unwrap();
        assert_eq!(s, "payload");
    }

    #[test]
    fn plug11_task122_1_invalid_inputs() {
        let err = verify_plugin_dir(Path::new("relative/dir")).expect_err("reject");
        assert_eq!(err.kind(), PluginTrustErrorKind::InvalidPath);
        let te: TraitError = err.into();
        assert_eq!(te.code(), ErrorCode::InvalidArgument);

        let tmp = setup("inv", 0o755, 0o755);
        let dir = verify_plugin_dir(&tmp.0).expect("dir ok");
        for bad in ["../x", "a/b", "..", "."] {
            let err = dir.verify_file(OsStr::new(bad)).expect_err("reject");
            assert_eq!(err.kind(), PluginTrustErrorKind::InvalidPath, "{bad}");
        }
        let err = dir
            .verify_file(OsStr::new("fandhe-container-plugin-missing"))
            .expect_err("reject");
        assert_eq!(err.kind(), PluginTrustErrorKind::Io);
        let te: TraitError = err.into();
        assert_eq!(te.code(), ErrorCode::Internal);

        let err = verify_plugin_dir(&tmp.0.join("nope")).expect_err("reject");
        assert_eq!(err.kind(), PluginTrustErrorKind::Io);
    }

    #[test]
    fn plug11_task122_1_verify_candidate_from_discovery() {
        let tmp = setup("cand", 0o755, 0o755);
        let dirs = [PluginSearchDir::new(PluginDirKind::User, tmp.0.clone())];
        let got = discover_candidates(&dirs).expect("discover");
        assert_eq!(got.len(), 1);
        let v = verify_candidate(&got[0]).expect("verified");
        assert_eq!(v.path(), tmp.0.join(NAME));

        chmod(&tmp.0.join(NAME), 0o777);
        let err = verify_candidate(&got[0]).expect_err("reject");
        assert_eq!(err.kind(), PluginTrustErrorKind::GroupOrOtherWritable);
        let te: TraitError = err.into();
        assert_eq!(te.code(), ErrorCode::PermissionDenied);
    }
}
