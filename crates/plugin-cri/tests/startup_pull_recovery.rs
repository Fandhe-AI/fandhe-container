//! 起動時の pull 回収 GC の結合試験（OCI-7・OCI-1・REPAIR-4・REPAIR-5。#2819）。
//!
//! `adapter::recover_stale_image_pulls_in` を公開 API だけで呼び、別プロセスで生きている pull のリースは
//! 回収せず、drop 済み（クラッシュ相当）の pull だけを回収することを具体値で照合する。root 権限は不要。
#![cfg(unix)]

#[path = "support/reap.rs"]
mod reap;

use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use fandhe_container_core::observability::OpRecorder;
use fandhe_container_oci::error::OciErrorCode;
use fandhe_container_oci::image_management::{ImageStore, PullId};
use fandhe_container_oci::instrument::{
    NoopOciOpRecorder, OciOpKind, OciOpOutcome, OciOpRecorder, OciOpSample,
};
use fandhe_container_oci::reference::Digest;
use fandhe_container_plugin_cri::adapter::{
    pull_recovery_summary_line, recover_stale_image_pulls_in,
};
use std::sync::{Arc, Mutex};

const ENV_ROOT: &str = "FC_CRI_PULLREC_ROOT";
const ENV_READY: &str = "FC_CRI_PULLREC_READY";
const ENV_DONE: &str = "FC_CRI_PULLREC_DONE";
const CHILD_TEST: &str = "oci7_child_holds_live_pull";
const WAIT: Duration = Duration::from_secs(30);

fn noop() -> Arc<dyn OciOpRecorder> {
    Arc::new(NoopOciOpRecorder)
}

/// oci 側の計装を集める試験用の記録先。
#[derive(Debug, Default)]
struct Collect(Mutex<Vec<(OciOpKind, OciOpOutcome)>>);

impl OciOpRecorder for Collect {
    fn record_oci_op(&self, sample: &OciOpSample) {
        self.0
            .lock()
            .expect("lock")
            .push((sample.kind(), sample.outcome()));
    }
}

fn digest() -> Digest {
    Digest::parse(&format!("sha256:{}", "ab".repeat(32))).expect("digest")
}

fn pid(s: &str) -> PullId {
    PullId::new(s).expect("pull id")
}

/// 0700 の一時ディレクトリ（drop で消す）。
struct Tmp(PathBuf);

impl Tmp {
    fn new(tag: &str) -> Self {
        let base = std::env::temp_dir()
            .canonicalize()
            .expect("canonical temp dir");
        let p = base.join(format!("fc-cri-pullrec-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).expect("mkdir");
        fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).expect("chmod");
        Tmp(p)
    }

    fn images(&self) -> PathBuf {
        let p = self.0.join("images");
        fs::create_dir_all(&p).expect("mkdir images");
        fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).expect("chmod images");
        p
    }
}

impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn wait_for(path: &Path) -> bool {
    let start = Instant::now();
    while start.elapsed() < WAIT {
        if path.exists() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    false
}

fn put_blob(root: &Path) {
    let dir = root.join("blobs").join("sha256");
    fs::create_dir_all(&dir).expect("blobs");
    let hex = digest().as_str().trim_start_matches("sha256:").to_owned();
    let f = dir.join(hex);
    fs::write(&f, b"cached-layer").expect("blob");
    fs::set_permissions(&f, fs::Permissions::from_mode(0o600)).expect("chmod blob");
}

/// 子プロセス側: 生きている pull を保持したまま親の合図を待つ（環境変数が無ければ何もしない）。
#[test]
fn oci7_child_holds_live_pull() {
    let Ok(root) = std::env::var(ENV_ROOT) else {
        return;
    };
    let ready = PathBuf::from(std::env::var(ENV_READY).expect("ready"));
    let done = PathBuf::from(std::env::var(ENV_DONE).expect("done"));
    let store = ImageStore::open(Path::new(&root)).expect("open");
    let mut session = store.begin_pull(pid("livepull")).expect("begin");
    let _t = session.lease_existing_blob(&digest()).expect("lease");
    fs::write(&ready, b"1").expect("ready");
    // abort も publish もせず、ロックを保持したまま親の終了合図を待つ。
    let _ = wait_for(&done);
    std::process::exit(0);
}

/// OCI-7・OCI-1: 別プロセスで生きている pull のリースは回収せず、drop 済みの pull だけ回収する。
#[test]
fn oci7_startup_recovery_keeps_live_cross_process_pull_and_reclaims_dead_one() {
    let tmp = Tmp::new("mixed");
    let root = tmp.images();
    put_blob(&root);
    let ready = tmp.0.join("ready");
    let done = tmp.0.join("done");

    let mut child = Command::new(std::env::current_exe().expect("exe"))
        .args([CHILD_TEST, "--exact", "--test-threads=1", "--no-capture"])
        .env(ENV_ROOT, &root)
        .env(ENV_READY, &ready)
        .env(ENV_DONE, &done)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn child");
    if !wait_for(&ready) {
        reap::reap_or_report(&mut child, reap::REAP_WITHIN);
        panic!("child did not become ready in time");
    }

    // 死んだ pull（セッションを drop。ロックの fd が閉じ、リースとステージングが残る）。
    {
        let store = ImageStore::open(&root).expect("open");
        let mut dead = store.begin_pull(pid("deadpull")).expect("begin dead");
        let _t = dead.lease_existing_blob(&digest()).expect("lease dead");
    }

    let recorder = OpRecorder::new();
    let r = recover_stale_image_pulls_in(&root, &recorder, noop()).expect("recover");
    assert_eq!(r.reclaimed(), &[pid("deadpull")]);
    assert_eq!(r.released_leases(), &[(pid("deadpull"), 1)]);
    assert_eq!(r.kept_live(), &[pid("livepull")]);
    assert!(r.kept_undetermined().is_empty());
    assert!(r.failed().is_empty());
    assert_eq!(r.foreign_entries(), 0);
    assert!(!root.join("staging").join("deadpull").exists());
    assert!(root.join("staging").join("livepull").exists());
    let leases = ImageStore::open(&root)
        .expect("open")
        .lock()
        .expect("lock")
        .blob_references(&digest())
        .leases;
    assert_eq!(leases, vec![pid("livepull")]);
    assert_eq!(
        pull_recovery_summary_line(&r),
        "{\"level\":\"info\",\"event\":\"image_pull_recovery\",\"reclaimed\":1,\"released_leases\":1,\"kept_live\":1,\"kept_undetermined\":0,\"failed\":0,\"foreign_entries\":0}"
    );
    let snap = recorder.snapshot();
    let stat = snap
        .iter()
        .find(|s| s.name().as_str() == "image_pull_recovery")
        .expect("recorded");
    assert_eq!(stat.success(), 1);

    // 子が終われば、残っていたリースも次の回収で解放される。
    fs::write(&done, b"1").expect("done");
    let status = match reap::wait_within(&mut child, WAIT) {
        Ok(st) => st,
        Err(e) => {
            reap::reap_or_report(&mut child, reap::REAP_WITHIN);
            panic!("child did not finish after done: {e}");
        }
    };
    assert!(status.success());
    let r2 = recover_stale_image_pulls_in(&root, &recorder, noop()).expect("recover again");
    assert_eq!(r2.reclaimed(), &[pid("livepull")]);
    assert_eq!(r2.released_leases(), &[(pid("livepull"), 1)]);
    let leases = ImageStore::open(&root)
        .expect("open")
        .lock()
        .expect("lock")
        .blob_references(&digest())
        .leases;
    assert!(leases.is_empty());
}

/// 初回起動（置き場が空）は何も回収せず、ログ行を出す必要のない既定値を返す。
#[test]
fn oci7_startup_recovery_on_empty_images_root_is_noop() {
    let tmp = Tmp::new("empty");
    let root = tmp.images();
    let r = recover_stale_image_pulls_in(&root, &OpRecorder::new(), noop()).expect("recover");
    assert_eq!(r, Default::default());
}

/// fail-closed: group 書き込み可の root は信頼せず `PermissionDenied` で拒否する（起動しない根拠）。
#[test]
fn oci7_startup_recovery_rejects_untrusted_root() {
    let tmp = Tmp::new("untrusted");
    let root = tmp.images();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o770)).expect("chmod");
    let e = recover_stale_image_pulls_in(&root, &OpRecorder::new(), noop()).expect_err("untrusted");
    assert_eq!(e.code(), OciErrorCode::PermissionDenied);
}

/// REPAIR-4・OCI-1・OCI-7（#2900）: 起動時の回収は共有記録器へ `image_pull_recovery` を、oci の記録先へ
/// `RecoverStalePulls` の成功を 1 件ずつ渡す。
#[test]
fn repair4_startup_recovery_records_oci_ops_in_oci_recorder() {
    let tmp = Tmp::new("ocirec");
    let root = tmp.images();
    let shared = OpRecorder::new();
    let oci = Arc::new(Collect::default());
    recover_stale_image_pulls_in(&root, &shared, oci.clone()).expect("recover");
    let stat = shared
        .snapshot()
        .into_iter()
        .find(|s| s.name().as_str() == "image_pull_recovery")
        .expect("recorded");
    assert_eq!(stat.success(), 1);
    let got = oci.0.lock().expect("lock").clone();
    assert!(
        got.contains(&(OciOpKind::RecoverStalePulls, OciOpOutcome::Success)),
        "{got:?}"
    );
}
