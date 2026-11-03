//! create ゲートのプロセス間排他と異常終了後の回収の結合試験（OCI-7・OCI-5・CORE-1・REPAIR-5・REPAIR-12・#2495）。
//!
//! 公開 API のみを使う。子プロセス（同じ試験バイナリを `--exact` で再起動）がイメージつき create の
//! 共有ゲートを保持したまま未確定参照を持ち、親は次を具体値で確かめる。
//! 1. 子の create 中は排他が取れず（`None`）、未確定参照を回収しない
//! 2. 子を強制終了（kill）するとカーネルがロックを外し、同じ参照を回収できる
//!
//! 待機にはすべて期限を置く（REPAIR-5）。skip・ignore はしない。

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use fandhe_container_oci::image_management::{
    ContainerRefId, ContainerStatePresence, ImageStore, ManifestComposition,
};
use fandhe_container_oci::reference::Digest;

const CHILD_TEST: &str = "oci7_gate_child_holds_create";
const ROOT_ENV: &str = "FC_OCI_GATE_TEST_ROOT";
const DEADLINE: Duration = Duration::from_secs(30);

fn d(n: u8) -> Digest {
    Digest::parse(&format!("sha256:{}", format!("{n:02x}").repeat(32))).expect("digest")
}

fn cid(s: &str) -> ContainerRefId {
    ContainerRefId::new(s).expect("id")
}

fn wait_for(path: &Path) {
    let deadline = Instant::now() + DEADLINE;
    while !path.exists() {
        assert!(Instant::now() < deadline, "marker did not appear in time");
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// 子側: 未確定参照 c1 を登録し、共有ゲートを保持したまま kill されるのを待つ。
/// 環境変数が無ければ何もしない。期限を過ぎたら自分で終了する（親が落ちた場合の孤児化防止）。
#[test]
fn oci7_gate_child_holds_create() {
    let Some(root) = std::env::var_os(ROOT_ENV).map(PathBuf::from) else {
        return;
    };
    let store = ImageStore::open(&root)
        .expect("open")
        .with_timeout(Duration::from_secs(5));
    store
        .lock()
        .expect("lock")
        .register_manifest(
            d(0xa0),
            ManifestComposition::new(d(0xc1), vec![d(0x10)]).expect("comp"),
        )
        .expect("manifest");
    let _pass = store.enter_container_create().expect("pass");
    store
        .register_container_ref(&cid("c1"), &d(0xa0))
        .expect("register");
    std::fs::write(root.join("ready"), b"").expect("ready");
    let deadline = Instant::now() + DEADLINE;
    while Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// 子の回収に許す上限（REPAIR-5: 期限なしの待ちを置かない）。
const REAP_DEADLINE: Duration = Duration::from_secs(10);

/// 子を kill し、`try_wait` のポーリングで有限の期限内に回収する。失敗・期限超過は Err。
fn kill_and_reap(child: &mut std::process::Child) -> Result<(), String> {
    child
        .kill()
        .map_err(|e| format!("kill child failed: {e}"))?;
    let deadline = Instant::now() + REAP_DEADLINE;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return Ok(()),
            Ok(None) => {}
            Err(e) => return Err(format!("try_wait child failed: {e}")),
        }
        if Instant::now() >= deadline {
            return Err("child was not reaped within the deadline after kill".to_string());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// OCI-7: 別プロセスの create 中は回収せず、そのプロセスが kill された後は同じ参照を回収できる。
#[test]
fn oci7_gate_excludes_reconcile_until_creator_is_killed() {
    let root = std::env::temp_dir().join(format!("fc-oci-gate-it-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).expect("mkdir");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).expect("chmod");
    }
    let mut child = Command::new(std::env::current_exe().expect("exe"))
        .args(["--exact", CHILD_TEST, "--test-threads=1", "--no-capture"])
        .env(ROOT_ENV, &root)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn");

    let result = std::panic::catch_unwind(|| {
        wait_for(&root.join("ready"));
        let store = ImageStore::open(&root)
            .expect("open")
            .with_timeout(Duration::from_millis(200));

        // 子の create 中: 排他は取れず、回収の入口に入れない。
        assert!(
            store
                .quiesce_container_creates()
                .expect("quiesce")
                .is_none()
        );
        assert_eq!(store.lock().expect("lock").unbound_containers().count(), 1);
    });

    // 子を強制終了する（kill はシグナル配送のみ。wait はカーネルがプロセスを回収するまで）。
    let reaped = kill_and_reap(&mut child);
    if let Err(p) = result {
        let _ = std::fs::remove_dir_all(&root);
        std::panic::resume_unwind(p);
    }
    if let Err(e) = reaped {
        let _ = std::fs::remove_dir_all(&root);
        panic!("{e}");
    }

    let store = ImageStore::open(&root)
        .expect("open")
        .with_timeout(Duration::from_secs(5));
    let q = store
        .quiesce_container_creates()
        .expect("quiesce")
        .expect("lock released by the kernel after kill");
    let outcome = store
        .reconcile_container_refs_quiesced(&q, |_| ContainerStatePresence::Absent)
        .expect("reconcile");
    assert_eq!(outcome.removed(), &[(cid("c1"), d(0xa0))]);
    assert_eq!(outcome.removed_unbound(), &[cid("c1")]);
    assert_eq!(store.lock().expect("lock").unbound_containers().count(), 0);
    let _ = std::fs::remove_dir_all(&root);
}
