//! plugin 所有者・モード検証の Linux 実ファイルシステム試験（TASK-122.1・PLUG-11・REPAIR-12）。
//!
//! 信頼起点より下だけを検証する試験専用変種 `verify_plugin_dir_below` を使うため、公開 API を
//! 増やさないよう結合試験ではなく `plugin_trust` の子モジュール（`cfg(test)` 限定）に置く。
//! 一時ディレクトリのモードは `set_permissions` で明示して umask に依存させない。所有者不一致の
//! 実ファイル試験は chown（root）が要るため作らず、判定論理は `check_owner_and_mode` の単体
//! テストで担保する。

use std::fs;
use std::path::PathBuf;

use super::imp::verify_plugin_dir_below;
use super::{
    PluginTrustError, PluginTrustErrorKind, TrustTarget, VerifiedPluginDir, verify_plugin_dir,
};

/// テスト用の一意な一時ディレクトリ（終了時に削除）。
struct Tmp(PathBuf);

/// 試験の信頼起点（これより下だけを検証する。上位の権限が開発機・CI で異なるため）。
fn anchor() -> PathBuf {
    std::env::temp_dir()
}

impl Tmp {
    fn new(tag: &str) -> Self {
        let p = anchor().join(format!(
            "fandhe-plugin-trust-{}-{}",
            std::process::id(),
            tag
        ));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).expect("create tmp dir");
        // umask（002 等）に依存させず、祖先検証を通る 0o755 に固定する。
        fs::set_permissions(&p, std::os::unix::fs::PermissionsExt::from_mode(0o755))
            .expect("chmod tmp dir");
        Self(p)
    }
}

impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// 試験用: anchor より下だけを検証する。
fn verify_dir(dir: &std::path::Path) -> Result<VerifiedPluginDir, PluginTrustError> {
    verify_plugin_dir_below(&anchor(), dir)
}

use crate::plugin_discovery::{PluginDirKind, PluginSearchDir, discover_candidates};
use crate::plugin_trust::verify_candidate;
use crate::traits::{ErrorCode, TraitError};
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
    let dir = verify_dir(&tmp.0).expect("dir ok");
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
        let dir = verify_dir(&tmp.0).expect("dir ok");
        let err = dir.verify_file(OsStr::new(NAME)).expect_err("reject");
        assert_eq!(err.kind(), PluginTrustErrorKind::GroupOrOtherWritable);
        assert_eq!(err.target(), TrustTarget::File);
    }
}

#[test]
fn plug11_task122_1_rejects_writable_dir() {
    for mode in [0o775, 0o777, 0o1777] {
        let tmp = setup(&format!("dw{mode:o}"), mode, 0o755);
        let err = verify_dir(&tmp.0).expect_err("reject");
        assert_eq!(err.kind(), PluginTrustErrorKind::GroupOrOtherWritable);
        assert_eq!(err.target(), TrustTarget::Directory);
    }
}

#[test]
fn plug11_task122_1_rejects_symlinks() {
    let tmp = setup("sym", 0o755, 0o755);
    let link = tmp.0.join("fandhe-container-plugin-link");
    symlink(tmp.0.join(NAME), &link).unwrap();
    let dir = verify_dir(&tmp.0).expect("dir ok");
    let err = dir
        .verify_file(OsStr::new("fandhe-container-plugin-link"))
        .expect_err("reject");
    assert_eq!(err.kind(), PluginTrustErrorKind::NotRegularFile);

    let dlink = anchor().join(format!(
        "fandhe-plugin-trust-{}-dirlink",
        std::process::id()
    ));
    let _ = fs::remove_file(&dlink);
    symlink(&tmp.0, &dlink).unwrap();
    let err = verify_dir(&dlink).expect_err("reject");
    let _ = fs::remove_file(&dlink);
    assert_eq!(err.kind(), PluginTrustErrorKind::NotDirectory);
}

#[test]
fn plug11_task122_1_rejects_writable_ancestor() {
    // 祖先（中間ディレクトリ）が group 書き込み可なら、探索先自体が 0o755 でも拒否する。
    let tmp = Tmp::new("anc");
    let mid = tmp.0.join("mid");
    let leaf = mid.join("leaf");
    fs::create_dir_all(&leaf).unwrap();
    chmod(&leaf, 0o755);
    chmod(&mid, 0o775);
    let err = verify_dir(&leaf).expect_err("reject");
    assert_eq!(err.kind(), PluginTrustErrorKind::GroupOrOtherWritable);
    assert_eq!(err.path(), mid.as_path());
    chmod(&mid, 0o755);
    verify_dir(&leaf).expect("ok once ancestor is tightened");
}

#[test]
fn plug11_task122_1_rejects_sticky_world_writable_ancestor() {
    // /tmp 相当（1777）配下の探索先も拒否する。
    let tmp = Tmp::new("sticky");
    let leaf = tmp.0.join("leaf");
    fs::create_dir(&leaf).unwrap();
    chmod(&leaf, 0o755);
    chmod(&tmp.0, 0o1777);
    let err = verify_dir(&leaf).expect_err("reject");
    assert_eq!(err.kind(), PluginTrustErrorKind::GroupOrOtherWritable);
    assert_eq!(err.path(), tmp.0.as_path());
    chmod(&tmp.0, 0o755);
}

#[test]
fn plug11_task122_1_rejects_symlink_ancestor() {
    let tmp = Tmp::new("ancsym");
    let real = tmp.0.join("real");
    fs::create_dir_all(real.join("leaf")).unwrap();
    chmod(&real, 0o755);
    chmod(&real.join("leaf"), 0o755);
    let link = tmp.0.join("link");
    symlink(&real, &link).unwrap();
    let err = verify_dir(&link.join("leaf")).expect_err("reject");
    assert_eq!(err.kind(), PluginTrustErrorKind::NotDirectory);
    assert_eq!(err.path(), link.as_path());
}

#[test]
fn plug11_task122_1_rejects_dotdot_components() {
    let tmp = Tmp::new("dotdot");
    fs::create_dir(tmp.0.join("a")).unwrap();
    chmod(&tmp.0.join("a"), 0o755);
    let err = verify_dir(&tmp.0.join("a").join("..")).expect_err("reject");
    assert_eq!(err.kind(), PluginTrustErrorKind::InvalidPath);
}

#[test]
fn plug11_task122_1_rejects_directory_as_file() {
    let tmp = setup("dirfile", 0o755, 0o755);
    let sub = tmp.0.join("subdir");
    fs::create_dir(&sub).unwrap();
    chmod(&sub, 0o755);
    let dir = verify_dir(&tmp.0).expect("dir ok");
    let err = dir.verify_file(OsStr::new("subdir")).expect_err("reject");
    assert_eq!(err.kind(), PluginTrustErrorKind::NotRegularFile);
}

#[test]
fn plug11_task122_1_held_fd_survives_path_replacement() {
    let tmp = setup("swap", 0o755, 0o755);
    let dir = verify_dir(&tmp.0).expect("dir ok");
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
    let dir = verify_dir(&tmp.0).expect("dir ok");
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

    let err = verify_dir(&tmp.0.join("nope")).expect_err("reject");
    assert_eq!(err.kind(), PluginTrustErrorKind::Io);
}

#[test]
fn plug11_task122_1_verify_candidate_from_discovery() {
    let tmp = setup("cand", 0o755, 0o755);
    let dirs = [PluginSearchDir::new(PluginDirKind::User, tmp.0.clone())];
    let got = discover_candidates(&dirs).expect("discover");
    assert_eq!(got.len(), 1);
    // 祖先の権限は環境依存のため anchor 起点の変種で検証する（verify_candidate と同じ手順）。
    let v = verify_dir(&tmp.0)
        .and_then(|d| d.verify_file(OsStr::new(NAME)))
        .expect("verified");
    assert_eq!(v.path(), tmp.0.join(NAME));

    chmod(&tmp.0.join(NAME), 0o777);
    let err = verify_dir(&tmp.0)
        .and_then(|d| d.verify_file(OsStr::new(NAME)))
        .expect_err("reject");
    assert_eq!(err.kind(), PluginTrustErrorKind::GroupOrOtherWritable);
    let te: TraitError = err.into();
    assert_eq!(te.code(), ErrorCode::PermissionDenied);
}

#[test]
fn plug11_task122_1_verify_candidate_rejects_world_writable_tmp_ancestor() {
    // /tmp（sticky・other 書き込み可）は祖先として拒否される。
    let base = Path::new("/tmp");
    let md = fs::metadata(base).expect("/tmp");
    assert_ne!(
        md.mode() & 0o002,
        0,
        "/tmp is expected to be world-writable"
    );
    let tmp = base.join(format!("fandhe-plugin-trust-{}-tmpanc", std::process::id()));
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir(&tmp).unwrap();
    chmod(&tmp, 0o755);
    let f = tmp.join(NAME);
    fs::write(&f, b"x").unwrap();
    chmod(&f, 0o755);
    let dirs = [PluginSearchDir::new(PluginDirKind::User, tmp.clone())];
    let got = discover_candidates(&dirs).expect("discover");
    let res = verify_candidate(&got[0]);
    let _ = fs::remove_dir_all(&tmp);
    let err = res.expect_err("reject");
    assert_eq!(err.kind(), PluginTrustErrorKind::GroupOrOtherWritable);
    assert_eq!(err.path(), base);
}

#[test]
fn plug11_task122_1_verify_candidate_accepts_under_trusted_ancestors() {
    // 公開 API `verify_candidate` の成功経路（祖先の検証を含む）。/tmp は祖先として拒否される
    // ため、開発機・CI とも group/other 書き込み不可の `$HOME` 配下に plugin を置く。
    let home = PathBuf::from(std::env::var_os("HOME").expect("HOME"));
    let base = home.join(format!("fandhe-plugin-trust-{}-okanc", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    fs::create_dir(&base).unwrap();
    chmod(&base, 0o755);
    let f = base.join(NAME);
    fs::write(&f, b"x").unwrap();
    chmod(&f, 0o755);
    let dirs = [PluginSearchDir::new(PluginDirKind::User, base.clone())];
    let got = discover_candidates(&dirs);
    let res = got
        .as_ref()
        .map_err(|_| ())
        .and_then(|g| verify_candidate(g.first().expect("one candidate")).map_err(|_| ()));
    let _ = fs::remove_dir_all(&base);
    let v = res.expect("verified via public API");
    assert_eq!(v.path(), f);
    assert_eq!(v.mode() & 0o022, 0);
}

#[test]
fn plug11_task122_1_rejects_dot_components() {
    let tmp = Tmp::new("dot");
    fs::create_dir(tmp.0.join("a")).unwrap();
    chmod(&tmp.0.join("a"), 0o755);
    let mid = PathBuf::from(format!("{}/./a", tmp.0.display()));
    let err = verify_dir(&mid).expect_err("reject mid dot");
    assert_eq!(err.kind(), PluginTrustErrorKind::InvalidPath);
    let tail = PathBuf::from(format!("{}/a/.", tmp.0.display()));
    let err = verify_dir(&tail).expect_err("reject trailing dot");
    assert_eq!(err.kind(), PluginTrustErrorKind::InvalidPath);
}
