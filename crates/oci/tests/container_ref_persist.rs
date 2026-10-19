//! コンテナ参照テーブルの永続化の結合試験（OCI-7・TASK-183.8 追補・#2341・REPAIR-10・REPAIR-12）。
//!
//! 公開 API（`ImageStore`）だけを使い、別プロセス（同じ試験バイナリを `--exact` で再起動した子）が
//! 登録した参照を、親が開き直して読めること、世代が再発行されないこと、manifest の在庫が無い
//! 参照があっても `image prune` が blob を消さないことを具体値で確かめる。待機には期限を置く（REPAIR-5）。

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use fandhe_container_oci::image_management::{
    ContainerRefId, ContainerRefRelease, ImageStore, ManifestComposition,
};
use fandhe_container_oci::reference::Digest;

const CHILD_TEST: &str = "oci7_persist_child_registers";
const ROOT_ENV: &str = "FC_OCI_PERSIST_TEST_ROOT";
const DEADLINE: Duration = Duration::from_secs(60);

fn d(n: u8) -> Digest {
    Digest::parse(&format!("sha256:{}", format!("{n:02x}").repeat(32))).expect("digest")
}

fn cid(s: &str) -> ContainerRefId {
    ContainerRefId::new(s).expect("id")
}

fn store(root: &std::path::Path) -> ImageStore {
    ImageStore::open(root)
        .expect("open")
        .with_timeout(Duration::from_secs(5))
}

/// 子側: manifest B（レイヤー 0x10 を共有）を在庫に入れて c1（確定）・c2（解除）・c3（未確定）を登録する。
/// 環境変数が無ければ何もしない。
#[test]
fn oci7_persist_child_registers() {
    let Some(root) = std::env::var_os(ROOT_ENV).map(PathBuf::from) else {
        return;
    };
    let s = store(&root);
    s.lock()
        .expect("lock")
        .register_manifest(
            d(0xb0),
            ManifestComposition::new(d(0xc2), vec![d(0x10), d(0x12)]).expect("comp"),
        )
        .expect("manifest");
    s.register_container_ref(&cid("c1"), &d(0xb0)).expect("c1");
    s.bind_container_ref(&cid("c1")).expect("bind c1");
    s.register_container_ref(&cid("c2"), &d(0xb0)).expect("c2");
    s.release_container_ref(&cid("c2")).expect("release c2");
    s.register_container_ref(&cid("c3"), &d(0xb0)).expect("c3");
}

fn run_child(root: &std::path::Path) {
    let mut child = Command::new(std::env::current_exe().expect("exe"))
        .args(["--exact", CHILD_TEST, "--test-threads=1", "--nocapture"])
        .env(ROOT_ENV, root)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn");
    let deadline = Instant::now() + DEADLINE;
    loop {
        if let Some(st) = child.try_wait().expect("wait") {
            assert!(st.success(), "child failed: {st}");
            return;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            panic!("child did not exit in time");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn temp_root(label: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("fc-oci-persist-it-{}-{label}", std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(p.join("blobs").join("sha256")).expect("mkdir");
    p
}

/// OCI-7・#2341: 別プロセスの登録を読み直して見え、世代（1 / 2 / 3）は再発行されず次は 4。
#[test]
fn oci7_other_process_refs_and_generations_survive() {
    let root = temp_root("gen");
    run_child(&root);

    let s = store(&root);
    assert_eq!(
        s.container_ref_registration(&cid("c1"))
            .expect("c1")
            .map(|g| g.as_raw()),
        Some(1)
    );
    // c2 は解除済み、c3 は未確定（確定済みの登録だけが registration に出る）。
    assert_eq!(s.container_ref_registration(&cid("c2")).expect("c2"), None);
    assert_eq!(s.container_ref_registration(&cid("c3")).expect("c3"), None);
    assert_eq!(
        s.release_container_ref(&cid("c2")).expect("rel c2"),
        ContainerRefRelease::NotRegistered
    );
    // 親側の在庫にも B を入れると登録できる。新しい世代は 4（1〜3 は発行済み）。
    s.lock()
        .expect("lock")
        .register_manifest(
            d(0xb0),
            ManifestComposition::new(d(0xc2), vec![d(0x10), d(0x12)]).expect("comp"),
        )
        .expect("manifest");
    s.register_container_ref(&cid("c4"), &d(0xb0)).expect("c4");
    assert_eq!(s.bind_container_ref(&cid("c4")).expect("bind").as_raw(), 4);
    let _ = std::fs::remove_dir_all(root);
}

/// OCI-7・#2341: 再起動後（親は B の在庫を持たない）でも、`image prune` は共有レイヤーを消さず、
/// 参照のある manifest B を外す対象にもしない。
#[test]
fn oci7_prune_after_restart_keeps_blobs_of_referenced_image() {
    let root = temp_root("prune");
    run_child(&root);
    for n in [0xc1u8, 0x10, 0x11] {
        let hex = format!("{n:02x}").repeat(32);
        std::fs::write(root.join("blobs").join("sha256").join(hex), b"x").expect("blob");
    }

    let s = store(&root);
    // 親は manifest A（レイヤー 0x10・0x11）だけを知る。A は無参照、B（別プロセスが参照）の構成は不明。
    let mut g = s.lock().expect("lock");
    g.register_manifest(
        d(0xa0),
        ManifestComposition::new(d(0xc1), vec![d(0x10), d(0x11)]).expect("comp"),
    )
    .expect("manifest");
    let out = g.execute_image_prune(&root).expect("prune");
    assert_eq!(out.removed_manifests, vec![d(0xa0)]);
    assert_eq!(out.deleted_blobs, Vec::<Digest>::new());
    for n in [0xc1u8, 0x10, 0x11] {
        let hex = format!("{n:02x}").repeat(32);
        assert!(root.join("blobs").join("sha256").join(hex).exists());
    }
    drop(g);
    let _ = std::fs::remove_dir_all(root);
}
