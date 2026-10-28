//! plugin 信頼性検証の macOS 固有試験（PLUG-11・MAC-1・TASK-122 追補・#1865・REPAIR-12）。
//!
//! Linux と共通のケースは `unix_tests` が macOS でも走らせる。ここには拡張 ACL（#1539）と、
//! macOS の既定のファイルシステム配置（`/tmp`・`/var` が symlink・`/private/tmp` が 1777）に依存する
//! ケースだけを置く。ACL の付与は `chmod +a` を期限つきで実行する（子プロセスの待ちにも期限を持たせる。REPAIR-5）。

use std::ffi::OsStr;
use std::fs;
use std::os::unix::fs::{PermissionsExt as _, symlink};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use super::imp::{acl_verdict, verify_plugin_dir_below};
use super::{
    PluginTrustError, PluginTrustErrorKind, TrustTarget, VerifiedPluginDir, verify_plugin_dir,
};
use crate::sys::SysError;
use crate::sys::plugin_fs::EBADF;

const NAME: &str = "fandhe-container-plugin-x";
const LINK: &str = "fandhe-container-plugin-link";

/// 試験の信頼起点（正規化した `temp_dir()`。これより下だけを検証する）。
fn anchor() -> PathBuf {
    fs::canonicalize(std::env::temp_dir()).expect("canonicalize temp_dir")
}

/// 試験ごとに一意な一時ディレクトリ。Drop で ACL を外してから削除する（deny delete の ACE 対策）。
struct Tmp(PathBuf);

impl Tmp {
    fn new(tag: &str) -> Self {
        let p = anchor().join(format!(
            "fandhe-plugin-trust-1865-{}-{tag}",
            std::process::id()
        ));
        strip_acl_recursive(&p);
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).expect("mkdir");
        chmod(&p, 0o755);
        Self(p)
    }
}

impl Drop for Tmp {
    fn drop(&mut self) {
        strip_acl_recursive(&self.0);
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn chmod(p: &Path, mode: u32) {
    fs::set_permissions(p, fs::Permissions::from_mode(mode)).expect("chmod");
}

/// 子プロセスを 10 秒の期限つきで待つ。期限超過なら kill し、回収も 5 秒で打ち切る（REPAIR-5）。
/// 終了状態を得られたら `Some`、期限超過・待機失敗なら `None`。
fn wait_limited(child: &mut std::process::Child) -> Option<std::process::ExitStatus> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match child.try_wait() {
            Ok(Some(st)) => return Some(st),
            Ok(None) => {}
            Err(_) => return None,
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let reap_deadline = Instant::now() + Duration::from_secs(5);
            while Instant::now() < reap_deadline {
                if !matches!(child.try_wait(), Ok(None)) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            return None;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// `chmod` 系コマンドを期限つきで実行して成功を要求する。
fn run_limited(mut cmd: Command) {
    let mut child = cmd.stdin(Stdio::null()).spawn().expect("spawn");
    match wait_limited(&mut child) {
        Some(st) => assert!(st.success(), "command failed: {st}"),
        None => panic!("command timed out"),
    }
}

/// `path` に ACE を 1 つ付ける。
fn add_ace(path: &Path, ace: &str) {
    let mut cmd = Command::new("chmod");
    cmd.arg("+a").arg(ace).arg(path);
    run_limited(cmd);
}

/// 後始末用。存在しない・ACL が無い場合の失敗は無視する。
fn strip_acl_recursive(path: &Path) {
    if path.exists()
        && let Ok(mut child) = Command::new("chmod")
            .arg("-R")
            .arg("-N")
            .arg(path)
            .stdin(Stdio::null())
            .spawn()
    {
        let _ = wait_limited(&mut child);
    }
}

fn verify_dir(dir: &Path) -> Result<VerifiedPluginDir, PluginTrustError> {
    verify_plugin_dir_below(&anchor(), dir)
}

fn verify_file_in(dir: &Path, name: &str) -> Result<super::VerifiedPluginFile, PluginTrustError> {
    verify_dir(dir)?.verify_file(OsStr::new(name))
}

fn write_plugin(dir: &Path, name: &str) -> PathBuf {
    let f = dir.join(name);
    fs::write(&f, b"x").expect("write");
    chmod(&f, 0o755);
    f
}

/// 前提の確認: ACL なしの素の構成は受理される（以降の拒否が ACL によることを示す）。
#[test]
fn plug11_1865_baseline_without_acl_is_accepted() {
    let tmp = Tmp::new("base");
    let f = write_plugin(&tmp.0, NAME);
    let v = verify_file_in(&tmp.0, NAME).expect("accepted");
    assert_eq!(v.path(), f);
}

#[test]
fn plug11_1865_rejects_file_with_extended_acl() {
    let tmp = Tmp::new("aclfile");
    let f = write_plugin(&tmp.0, NAME);
    add_ace(&f, "everyone allow write");
    let err = verify_file_in(&tmp.0, NAME).expect_err("reject");
    assert_eq!(err.kind(), PluginTrustErrorKind::ExtendedAcl);
    assert_eq!(err.target(), TrustTarget::File);
    assert_eq!(err.path(), f);
}

#[test]
fn plug11_1865_rejects_directory_with_extended_acl() {
    let tmp = Tmp::new("acldir");
    write_plugin(&tmp.0, NAME);
    add_ace(&tmp.0, "everyone allow add_file");
    let err = verify_file_in(&tmp.0, NAME).expect_err("reject");
    assert_eq!(err.kind(), PluginTrustErrorKind::ExtendedAcl);
    assert_eq!(err.target(), TrustTarget::Directory);
    assert_eq!(err.path(), tmp.0);
}

#[test]
fn plug11_1865_rejects_intermediate_ancestor_with_extended_acl() {
    let tmp = Tmp::new("aclmid");
    let mid = tmp.0.join("mid");
    let leaf = mid.join("leaf");
    fs::create_dir_all(&leaf).unwrap();
    chmod(&mid, 0o755);
    chmod(&leaf, 0o755);
    write_plugin(&leaf, NAME);
    add_ace(&mid, "everyone allow add_file");
    let err = verify_file_in(&leaf, NAME).expect_err("reject");
    assert_eq!(err.kind(), PluginTrustErrorKind::ExtendedAcl);
    assert_eq!(err.target(), TrustTarget::Directory);
    assert_eq!(err.path(), mid);
}

/// 拒否だけの ACE でも中身を解釈せず拒否する（#1539）。
#[test]
fn plug11_1865_rejects_deny_only_acl() {
    let tmp = Tmp::new("acldeny");
    let f = write_plugin(&tmp.0, NAME);
    add_ace(&f, "everyone deny delete");
    let err = verify_file_in(&tmp.0, NAME).expect_err("reject");
    assert_eq!(err.kind(), PluginTrustErrorKind::ExtendedAcl);
    assert_eq!(err.path(), f);
}

/// 所有者・モードの拒否は ACL より先に出る。
#[test]
fn plug11_1865_mode_rejection_precedes_acl() {
    let tmp = Tmp::new("aclmode");
    let f = write_plugin(&tmp.0, NAME);
    add_ace(&f, "everyone allow write");
    chmod(&f, 0o777);
    let err = verify_file_in(&tmp.0, NAME).expect_err("reject");
    assert_eq!(err.kind(), PluginTrustErrorKind::GroupOrOtherWritable);
}

/// symlink の実体ファイルに ACL があれば、symlink 側のパスで拒否する。
#[test]
fn plug11_1865_rejects_symlink_target_file_with_acl() {
    let tmp = Tmp::new("aclsymfile");
    let real_dir = tmp.0.join("real");
    fs::create_dir(&real_dir).unwrap();
    chmod(&real_dir, 0o755);
    let real = write_plugin(&real_dir, NAME);
    add_ace(&real, "everyone allow write");
    symlink(&real, tmp.0.join(LINK)).unwrap();
    let err = verify_file_in(&tmp.0, LINK).expect_err("reject");
    assert_eq!(err.kind(), PluginTrustErrorKind::ExtendedAcl);
    assert_eq!(err.target(), TrustTarget::File);
    assert_eq!(err.path(), tmp.0.join(LINK));
}

/// symlink の実体の親ディレクトリに ACL があれば、実体の親の正規パスで拒否する。
#[test]
fn plug11_1865_rejects_symlink_target_parent_with_acl() {
    let tmp = Tmp::new("aclsymdir");
    let real_dir = tmp.0.join("real");
    fs::create_dir(&real_dir).unwrap();
    chmod(&real_dir, 0o755);
    let real = write_plugin(&real_dir, NAME);
    symlink(&real, tmp.0.join(LINK)).unwrap();
    add_ace(&real_dir, "everyone allow add_file");
    let err = verify_file_in(&tmp.0, LINK).expect_err("reject");
    assert_eq!(err.kind(), PluginTrustErrorKind::ExtendedAcl);
    assert_eq!(err.target(), TrustTarget::Directory);
    assert_eq!(err.path(), fs::canonicalize(&real_dir).unwrap());
}

/// ACL 判定結果の写像（判定できなければ `Io`。fail-closed）。
#[test]
fn plug11_1865_acl_verdict_mapping() {
    assert_eq!(acl_verdict(Ok(false)), Ok(()));
    assert_eq!(
        acl_verdict(Ok(true)),
        Err(PluginTrustErrorKind::ExtendedAcl)
    );
    assert_eq!(
        acl_verdict(Err(SysError::Os(EBADF))),
        Err(PluginTrustErrorKind::Io)
    );
    assert_eq!(
        acl_verdict(Err(SysError::Unsupported)),
        Err(PluginTrustErrorKind::Io)
    );
}

/// 読み取り権限の無い祖先は `O_PATH` が無い macOS では開けず `Io` で拒否する（非 root 前提）。
#[test]
fn plug11_1865_rejects_unreadable_ancestor_with_io() {
    let tmp = Tmp::new("noread");
    let mid = tmp.0.join("mid");
    let leaf = mid.join("leaf");
    fs::create_dir_all(&leaf).unwrap();
    write_plugin(&leaf, NAME);
    chmod(&mid, 0o311);
    let res = verify_file_in(&leaf, NAME);
    chmod(&mid, 0o700);
    let err = res.expect_err("reject");
    assert_eq!(err.kind(), PluginTrustErrorKind::Io);
    assert_eq!(err.target(), TrustTarget::Directory);
    assert_eq!(err.path(), mid);
}

/// 検証を別スレッドで走らせ、10 秒の期限内に終わること（open で止まらないこと）を確かめて結果を返す（REPAIR-5）。
fn verify_with_deadline(
    dir: &Path,
    name: &str,
) -> Result<super::VerifiedPluginFile, PluginTrustError> {
    let (dir, name) = (dir.to_path_buf(), name.to_string());
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(verify_file_in(&dir, &name));
    });
    rx.recv_timeout(Duration::from_secs(10))
        .expect("verify must not block")
}

/// 読み取り権限の無い FIFO は、open していれば `EACCES` で `Io` になる。probe で `NotRegularFile` になること
/// （open していないこと）と止まらないことを照合する（#3096・PLUG-11・SEC-1。非 root 前提）。
#[test]
fn plug11_3096_rejects_unreadable_fifo_without_open() {
    let tmp = Tmp::new("fifo");
    let fifo = tmp.0.join(NAME);
    let st = Command::new("mkfifo")
        .arg(&fifo)
        .stdin(Stdio::null())
        .status()
        .expect("mkfifo");
    assert!(st.success());
    chmod(&fifo, 0o000);
    let err = verify_with_deadline(&tmp.0, NAME).expect_err("reject");
    assert_eq!(err.kind(), PluginTrustErrorKind::NotRegularFile);
    assert_eq!(err.target(), TrustTarget::File);
    assert_eq!(err.path(), fifo);
}

/// UNIX ソケットは `open(2)` すると `Io`（`EOPNOTSUPP`）になる。`NotRegularFile` なら open していない。
#[test]
fn plug11_3096_rejects_socket_without_open() {
    let tmp = Tmp::new("sock");
    let sock = tmp.0.join(NAME);
    let _l = std::os::unix::net::UnixListener::bind(&sock).expect("bind");
    let err = verify_with_deadline(&tmp.0, NAME).expect_err("reject");
    assert_eq!(err.kind(), PluginTrustErrorKind::NotRegularFile);
    assert_eq!(err.path(), sock);
}

/// symlink 経由のソケットも追従 open の前に `NotRegularFile` で拒否する。
#[test]
fn plug11_3096_rejects_symlink_to_socket_without_open() {
    let tmp = Tmp::new("lsock");
    let sock = tmp.0.join("s");
    let _l = std::os::unix::net::UnixListener::bind(&sock).expect("bind");
    symlink(&sock, tmp.0.join(LINK)).expect("symlink");
    let err = verify_with_deadline(&tmp.0, LINK).expect_err("reject");
    assert_eq!(err.kind(), PluginTrustErrorKind::NotRegularFile);
    assert_eq!(err.target(), TrustTarget::File);
}

/// symlink 経由の文字デバイス（`/dev/null`）も open せずに `NotRegularFile` で拒否する。
#[test]
fn plug11_3096_rejects_symlink_to_dev_null() {
    let tmp = Tmp::new("ldev");
    symlink("/dev/null", tmp.0.join(LINK)).expect("symlink");
    let err = verify_with_deadline(&tmp.0, LINK).expect_err("reject");
    assert_eq!(err.kind(), PluginTrustErrorKind::NotRegularFile);
}

/// 公開 API: `/tmp` は `/private/tmp` への symlink のため祖先の symlink として拒否する。
#[test]
fn plug11_1865_public_api_rejects_symlinked_tmp() {
    let err = verify_plugin_dir(Path::new("/tmp/fandhe-x")).expect_err("reject");
    assert_eq!(err.kind(), PluginTrustErrorKind::NotDirectory);
    assert_eq!(err.target(), TrustTarget::Directory);
    assert_eq!(err.path(), Path::new("/tmp"));
}

/// 公開 API: `/var` も symlink のため拒否する。
#[test]
fn plug11_1865_public_api_rejects_symlinked_var() {
    let err = verify_plugin_dir(Path::new("/var/tmp")).expect_err("reject");
    assert_eq!(err.kind(), PluginTrustErrorKind::NotDirectory);
    assert_eq!(err.path(), Path::new("/var"));
}

/// 公開 API: 実体の `/private/tmp`（1777）配下は other 書き込み可の祖先として拒否する。
#[test]
fn plug11_1865_public_api_rejects_private_tmp_ancestor() {
    let err = verify_plugin_dir(Path::new("/private/tmp")).expect_err("reject");
    assert_eq!(err.kind(), PluginTrustErrorKind::GroupOrOtherWritable);
    assert_eq!(err.path(), Path::new("/private/tmp"));
}
