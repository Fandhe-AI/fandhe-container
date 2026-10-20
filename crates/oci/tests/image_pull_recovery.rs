//! pull のクラッシュ復旧 GC の結合試験（OCI-7・TASK-183.11.2・#852）。
//!
//! 公開 API だけを通し、生きている pull は回収されず、drop された pull（クラッシュ相当）は
//! ステージングとリースが回収され、不在を確認できない残骸は残ることを具体値で照合する。

use std::fs;
use std::path::PathBuf;

use fandhe_container_oci::image_management::{ImageStore, PULL_LOCK_FILE_NAME, PullId};
use fandhe_container_oci::reference::Digest;
use sha2::{Digest as _, Sha256};

fn sha_of(data: &[u8]) -> Digest {
    let mut hex = String::new();
    for b in Sha256::digest(data) {
        hex.push_str(&format!("{b:02x}"));
    }
    Digest::parse(&format!("sha256:{hex}")).expect("digest")
}

fn pid(s: &str) -> PullId {
    PullId::new(s).expect("pull id")
}

struct Root(PathBuf);

impl Root {
    fn new(tag: &str) -> Self {
        let p = std::env::temp_dir().join(format!("fc-oci-rec-it-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(p.join("blobs").join("sha256")).expect("mkdir");
        Root(p)
    }
}

impl Drop for Root {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// OCI-7: live は残り、drop した pull は回収され、ロックファイルの無い残骸は残る。
#[test]
fn oci7_recovery_reclaims_only_confirmed_absent_pulls() {
    let root = Root::new("mixed");
    let data = b"cached-layer";
    let dg = sha_of(data);
    let hex = dg.as_str().trim_start_matches("sha256:").to_string();
    fs::write(root.0.join("blobs").join("sha256").join(&hex), data).expect("blob");
    let store = ImageStore::open(&root.0).expect("open");

    let mut live = store.begin_pull(pid("live")).expect("begin live");
    let _t = live.lease_existing_blob(&dg).expect("lease live");

    let dropped_dir = {
        let mut s = store.begin_pull(pid("crashed")).expect("begin crashed");
        let _t2 = s.lease_existing_blob(&dg).expect("lease crashed");
        s.staging_dir().to_path_buf()
    };
    let orphan = root.0.join("staging").join("orphan");
    fs::create_dir_all(&orphan).expect("orphan");
    fs::write(orphan.join("aa"), b"x").expect("orphan file");

    let r = store.recover_stale_pulls().expect("recover");
    assert_eq!(r.reclaimed(), &[pid("crashed")]);
    assert_eq!(r.released_leases(), &[(pid("crashed"), 1)]);
    assert_eq!(r.kept_live(), &[pid("live")]);
    assert_eq!(r.kept_undetermined(), &[pid("orphan")]);
    assert!(r.failed().is_empty());
    assert!(!dropped_dir.exists());
    assert!(orphan.join("aa").exists());
    assert!(live.staging_dir().join(PULL_LOCK_FILE_NAME).exists());
    let leases = store.lock().expect("lock").blob_references(&dg).leases;
    assert_eq!(leases, vec![pid("live")]);

    // 2 回目は何も回収しない（冪等）。
    let again = store.recover_stale_pulls().expect("recover again");
    assert!(again.reclaimed().is_empty());
    live.abort().expect("abort live");
}
