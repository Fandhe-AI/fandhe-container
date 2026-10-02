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

/// 探索先ディレクトリ自体が symlink の場合は従来どおり拒否する（TASK-122.2 の対象外）。
#[test]
fn plug11_task122_1_rejects_directory_symlink() {
    let tmp = setup("sym", 0o755, 0o755);
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

// ---- TASK-122.2: symlink 実体解決検証（PLUG-11） ----

const LINK: &str = "fandhe-container-plugin-link";

fn verified_link(dir: &Path) -> Result<super::VerifiedPluginFile, PluginTrustError> {
    verify_dir(dir)?.verify_file(OsStr::new(LINK))
}

/// 仕様反転: TASK-122.1 では symlink を一律拒否したが、実体が信頼できれば受理する。
/// 判定は実体 inode の値で、保持 fd は実体を指し、path / resolved_path が区別される。
#[test]
fn plug11_task122_2_accepts_relative_symlink_to_real_file() {
    let tmp = setup("s2rel", 0o755, 0o755);
    symlink(NAME, tmp.0.join(LINK)).unwrap();
    let v = verified_link(&tmp.0).expect("accepted");
    let real = fs::metadata(tmp.0.join(NAME)).unwrap();
    assert_eq!(v.owner_uid(), real.uid());
    assert_eq!(v.mode() & 0o7777, 0o755);
    assert_eq!(v.file().metadata().unwrap().ino(), real.ino());
    assert_eq!(v.path(), tmp.0.join(LINK));
    assert_eq!(
        v.resolved_path(),
        fs::canonicalize(tmp.0.join(NAME)).unwrap()
    );
    let mut s = String::new();
    v.file().read_to_string(&mut s).unwrap();
    assert_eq!(s, "payload");
}

#[test]
fn plug11_task122_2_accepts_absolute_symlink_to_other_directory() {
    let tmp = setup("s2abs", 0o755, 0o755);
    let other = tmp.0.join("other");
    fs::create_dir(&other).unwrap();
    chmod(&other, 0o755);
    let real = other.join("real-plugin");
    fs::write(&real, b"abs").unwrap();
    chmod(&real, 0o755);
    symlink(&real, tmp.0.join(LINK)).unwrap();
    let v = verified_link(&tmp.0).expect("accepted");
    assert_eq!(v.resolved_path(), fs::canonicalize(&real).unwrap());
    let mut s = String::new();
    v.file().read_to_string(&mut s).unwrap();
    assert_eq!(s, "abs");
}

#[test]
fn plug11_task122_2_accepts_multi_hop_chain() {
    let tmp = setup("s2chain", 0o755, 0o755);
    symlink(NAME, tmp.0.join("h1")).unwrap();
    symlink("h1", tmp.0.join("h2")).unwrap();
    symlink("h2", tmp.0.join(LINK)).unwrap();
    let v = verified_link(&tmp.0).expect("accepted");
    assert_eq!(
        v.resolved_path(),
        fs::canonicalize(tmp.0.join(NAME)).unwrap()
    );
}

/// symlink 自体は 0o777 だが、実体が group/other 書き込み可のときだけ拒否される。
#[test]
fn plug11_task122_2_judges_real_file_not_symlink() {
    for mode in [0o775, 0o777] {
        let tmp = setup(&format!("s2w{mode:o}"), 0o755, mode);
        symlink(NAME, tmp.0.join(LINK)).unwrap();
        let err = verified_link(&tmp.0).expect_err("reject");
        assert_eq!(err.kind(), PluginTrustErrorKind::GroupOrOtherWritable);
        assert_eq!(err.target(), TrustTarget::File);
    }
}

#[test]
fn plug11_task122_2_rejects_writable_real_parent_directory() {
    let tmp = setup("s2par", 0o755, 0o755);
    let other = tmp.0.join("other");
    fs::create_dir(&other).unwrap();
    let real = other.join("real-plugin");
    fs::write(&real, b"x").unwrap();
    chmod(&real, 0o755);
    chmod(&other, 0o777);
    symlink(&real, tmp.0.join(LINK)).unwrap();
    let err = verified_link(&tmp.0).expect_err("reject");
    assert_eq!(err.kind(), PluginTrustErrorKind::GroupOrOtherWritable);
    assert_eq!(err.target(), TrustTarget::Directory);
    assert_eq!(err.path(), fs::canonicalize(&other).unwrap().as_path());
    chmod(&other, 0o755);
}

/// 公開 API（anchor なし）では、信頼できる `$HOME` 配下の symlink が `/tmp` 配下の実体を
/// 指していても `/tmp` 祖先で拒否される。
#[test]
fn plug11_task122_2_rejects_target_under_world_writable_ancestor() {
    let home = PathBuf::from(std::env::var_os("HOME").expect("HOME"));
    let base = home.join(format!("fandhe-plugin-trust-{}-s2tmp", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    fs::create_dir(&base).unwrap();
    chmod(&base, 0o755);
    let real_dir =
        PathBuf::from("/tmp").join(format!("fandhe-plugin-trust-{}-s2real", std::process::id()));
    let _ = fs::remove_dir_all(&real_dir);
    fs::create_dir(&real_dir).unwrap();
    chmod(&real_dir, 0o755);
    let real = real_dir.join(NAME);
    fs::write(&real, b"x").unwrap();
    chmod(&real, 0o755);
    symlink(&real, base.join(NAME)).unwrap();
    let dirs = [PluginSearchDir::new(PluginDirKind::User, base.clone())];
    let res = discover_candidates(&dirs)
        .map_err(|_| ())
        .and_then(|g| verify_candidate(g.first().expect("one")).map_err(|_| ()));
    let res_kind = discover_candidates(&dirs)
        .ok()
        .and_then(|g| verify_candidate(g.first()?).err());
    let _ = fs::remove_dir_all(&base);
    let _ = fs::remove_dir_all(&real_dir);
    assert!(res.is_err());
    let err = res_kind.expect("rejected");
    assert_eq!(err.kind(), PluginTrustErrorKind::GroupOrOtherWritable);
    assert_eq!(err.path(), Path::new("/tmp"));
}

#[test]
fn plug11_task122_2_detects_loops_with_symlink_loop() {
    let tmp = setup("s2loop", 0o755, 0o755);
    symlink(LINK, tmp.0.join(LINK)).unwrap();
    let err = verified_link(&tmp.0).expect_err("reject");
    assert_eq!(err.kind(), PluginTrustErrorKind::SymlinkLoop);
    let te: TraitError = err.into();
    assert_eq!(te.code(), ErrorCode::InvalidArgument);

    let tmp = setup("s2loop2", 0o755, 0o755);
    symlink("b", tmp.0.join("a")).unwrap();
    symlink("a", tmp.0.join("b")).unwrap();
    let err = verify_dir(&tmp.0)
        .and_then(|d| d.verify_file(OsStr::new("a")))
        .expect_err("reject");
    assert_eq!(err.kind(), PluginTrustErrorKind::SymlinkLoop);
}

#[test]
fn plug11_task122_2_rejects_chain_longer_than_kernel_limit() {
    let tmp = setup("s2long", 0o755, 0o755);
    symlink(NAME, tmp.0.join("n0")).unwrap();
    for i in 1..=50 {
        symlink(format!("n{}", i - 1), tmp.0.join(format!("n{i}"))).unwrap();
    }
    let err = verify_dir(&tmp.0)
        .and_then(|d| d.verify_file(OsStr::new("n50")))
        .expect_err("reject");
    assert_eq!(err.kind(), PluginTrustErrorKind::SymlinkLoop);
}

#[test]
fn plug11_task122_2_rejects_dangling_dir_and_fifo_targets() {
    let tmp = setup("s2bad", 0o755, 0o755);
    symlink("missing-target", tmp.0.join("dangling")).unwrap();
    let dir = verify_dir(&tmp.0).expect("dir ok");
    let err = dir.verify_file(OsStr::new("dangling")).expect_err("reject");
    assert_eq!(err.kind(), PluginTrustErrorKind::Io);

    let sub = tmp.0.join("subdir");
    fs::create_dir(&sub).unwrap();
    chmod(&sub, 0o755);
    symlink("subdir", tmp.0.join("tosub")).unwrap();
    let err = dir.verify_file(OsStr::new("tosub")).expect_err("reject");
    assert_eq!(err.kind(), PluginTrustErrorKind::NotRegularFile);

    let status = std::process::Command::new("mkfifo")
        .arg(tmp.0.join("pipe"))
        .status()
        .expect("mkfifo");
    assert!(status.success());
    symlink("pipe", tmp.0.join("tofifo")).unwrap();
    let err = dir.verify_file(OsStr::new("tofifo")).expect_err("reject");
    assert_eq!(err.kind(), PluginTrustErrorKind::NotRegularFile);
}

/// 検証後に symlink を張り替えても、保持 fd は検証した実体を読み続ける。
#[test]
fn plug11_task122_2_held_fd_survives_symlink_retarget() {
    let tmp = setup("s2swap", 0o755, 0o755);
    symlink(NAME, tmp.0.join(LINK)).unwrap();
    let v = verified_link(&tmp.0).expect("accepted");
    let evil = tmp.0.join("evil");
    fs::write(&evil, b"evil").unwrap();
    fs::remove_file(tmp.0.join(LINK)).unwrap();
    symlink("evil", tmp.0.join(LINK)).unwrap();
    let mut s = String::new();
    v.into_file().read_to_string(&mut s).unwrap();
    assert_eq!(s, "payload");
}

/// 実ファイル名が ` (deleted)` で終わっていても、実体が存在し信頼できれば受理する
/// （リンク先文字列だけで削除済み判定しない。PLUG-11・TASK-122.2）。
#[test]
fn plug11_task122_2_accepts_real_name_ending_with_deleted_suffix() {
    let tmp = setup("s2del", 0o755, 0o755);
    let odd = "plugin (deleted)";
    fs::rename(tmp.0.join(NAME), tmp.0.join(odd)).unwrap();
    symlink(odd, tmp.0.join(LINK)).unwrap();
    let v = verified_link(&tmp.0).expect("accepted");
    assert_eq!(
        v.resolved_path(),
        fs::canonicalize(tmp.0.join(odd)).unwrap()
    );
}
// ---- TASK-122.3: sha256 許可済みハッシュ照合（PLUG-11） ----

use crate::plugin_trust::{AllowedPluginHashes, Sha256Digest};
use std::io::Seek as _;

/// `setup` が書く内容 `payload` の sha256（`printf payload | sha256sum`）。
const PAYLOAD_SHA: &str = "239f59ed55e737c77147cf55ad0c1b030b6d7ee748a7426952f9b852d5a935e5";
/// 何にも一致しない任意の 64 桁 hex。
const OTHER_SHA: &str = "ed1b8f4f1b1c5f6d0b6e9a3f5a4c7d1f1b8d6e0a1c2e3f4a5b6c7d8e9f0a1b2c";

fn allow(hexes: &[&str]) -> AllowedPluginHashes {
    AllowedPluginHashes::from_digests(
        hexes
            .iter()
            .map(|h| Sha256Digest::from_hex(h).expect("hex")),
    )
}

fn verified(tag: &str) -> (Tmp, super::VerifiedPluginFile) {
    let tmp = setup(tag, 0o755, 0o755);
    let v = verify_dir(&tmp.0)
        .expect("dir ok")
        .verify_file(OsStr::new(NAME))
        .expect("file ok");
    (tmp, v)
}

#[test]
fn plug11_task122_3_accepts_listed_hash_and_rewinds_fd() {
    let (_t, v) = verified("h-ok");
    let hv = v.verify_hash(&allow(&[PAYLOAD_SHA])).expect("allowed");
    assert_eq!(hv.digest().to_string(), PAYLOAD_SHA);
    let mut s = String::new();
    hv.into_file().into_file().read_to_string(&mut s).unwrap();
    assert_eq!(s, "payload");
}

#[test]
fn plug11_task122_3_rejects_unlisted_hash() {
    let (_t, v) = verified("h-ng");
    let e = v.verify_hash(&allow(&[OTHER_SHA])).expect_err("reject");
    assert_eq!(e.kind(), PluginTrustErrorKind::HashMismatch);
    assert_eq!(e.target(), TrustTarget::File);
    let te: TraitError = e.into();
    assert_eq!(te.code(), ErrorCode::PermissionDenied);
}

#[test]
fn plug11_task122_3_empty_list_rejects() {
    let (_t, v) = verified("h-empty");
    let e = v
        .verify_hash(&AllowedPluginHashes::default())
        .expect_err("reject");
    assert_eq!(e.kind(), PluginTrustErrorKind::HashMismatch);
}

#[test]
fn plug11_task122_3_sha256_is_repeatable_and_leaves_offset_zero() {
    let (_t, v) = verified("h-rewind");
    let a = v.sha256().unwrap();
    let b = v.sha256().unwrap();
    assert_eq!(a, b);
    assert_eq!(a.to_string(), PAYLOAD_SHA);
    let mut f = v.file();
    assert_eq!(f.stream_position().unwrap(), 0);
}

/// 共有参照からの並行 `sha256()` が seek/read で干渉せず、常に同じダイジェストになる（PLUG-11・TASK-122.3）。
#[test]
fn plug11_task122_3_concurrent_sha256_is_consistent() {
    let (_t, v) = verified("h-concurrent");
    std::thread::scope(|s| {
        let hs: Vec<_> = (0..8)
            .map(|_| {
                s.spawn(|| {
                    (0..200)
                        .map(|_| v.sha256().unwrap().to_string())
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        for h in hs {
            for d in h.join().unwrap() {
                assert_eq!(d, PAYLOAD_SHA);
            }
        }
    });
}

/// 検証後にパスを別内容へ差し替えても、保持 fd のハッシュは検証時の内容のまま（TOCTOU 回避）。
#[test]
fn plug11_task122_3_hash_follows_held_fd_not_path() {
    let (t, v) = verified("h-swap");
    let other = t.0.join("other");
    fs::write(&other, b"evil").unwrap();
    fs::rename(&other, t.0.join(NAME)).unwrap();
    let hv = v.verify_hash(&allow(&[PAYLOAD_SHA])).expect("held fd");
    assert_eq!(hv.digest().to_string(), PAYLOAD_SHA);
}

/// symlink 経由の候補は実体 fd の内容で照合される（TASK-122.2）。
#[test]
fn plug11_task122_3_symlink_candidate_hashes_target_content() {
    let tmp = Tmp::new("h-link");
    fs::write(tmp.0.join("real"), b"payload").unwrap();
    chmod(&tmp.0.join("real"), 0o755);
    symlink("real", tmp.0.join(NAME)).unwrap();
    let v = verify_dir(&tmp.0)
        .expect("dir ok")
        .verify_file(OsStr::new(NAME))
        .expect("file ok");
    let hv = v.verify_hash(&allow(&[PAYLOAD_SHA])).expect("allowed");
    assert_eq!(hv.digest().to_string(), PAYLOAD_SHA);
}
