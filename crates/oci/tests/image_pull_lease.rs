//! pull のリース登録とステージング書き込みの結合試験（OCI-7・TASK-183.9・#474）。
//!
//! 公開 API だけを通し、既存 blob の再利用で自分の pull ID のリースが登録されること、
//! ステージング中の新規 blob が `image ls`・容量集計・参照テーブルに現れないことを照合する。
//! 公開とロールバック（#475）は `image_pull_publish.rs` で扱う。

use std::fs;
use std::path::PathBuf;

use fandhe_container_oci::image_management::{BlobReuse, ImageStore, PullId};
use fandhe_container_oci::reference::Digest;

fn d(n: u8) -> Digest {
    Digest::parse(&format!("sha256:{}", format!("{n:02x}").repeat(32))).expect("digest")
}

struct Root(PathBuf);

impl Drop for Root {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// OCI-7: 再利用はリース登録、新規取得はステージングで不可視。
#[test]
fn oci7_reuse_leases_and_staged_blob_is_invisible() {
    let root = Root(std::env::temp_dir().join(format!("fc-oci-pull-it-{}", std::process::id())));
    let _ = fs::remove_dir_all(&root.0);
    let blobs = root.0.join("blobs").join("sha256");
    fs::create_dir_all(&blobs).expect("mkdir");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&root.0, fs::Permissions::from_mode(0o700)).expect("chmod");
    }
    let cached = d(1);
    fs::write(
        blobs.join(cached.as_str().trim_start_matches("sha256:")),
        b"abc",
    )
    .expect("write");

    let store = ImageStore::open(&root.0).expect("open");
    let id = PullId::generate().expect("id");
    let mut session = store.begin_pull(id.clone()).expect("begin");

    let reuse = session.lease_existing_blob(&cached).expect("lease");
    assert!(matches!(reuse, BlobReuse::Leased(_)));

    let mut w = session.open_staged_blob(&d(2)).expect("writer");
    std::io::Write::write_all(&mut w, &[7u8; 64]).expect("write staged");
    w.commit().expect("commit");

    let guard = store.lock().expect("lock");
    assert_eq!(guard.blob_references(&cached).leases, vec![id]);
    assert_eq!(guard.list_images(&root.0).expect("ls").entries.len(), 0);
    let cache = guard.disk_usage(&root.0).expect("df").cache;
    assert_eq!(cache.blob_count, 1);
    assert_eq!(cache.bytes, 3);
    let staged_refs = guard.blob_references(&d(2));
    assert!(staged_refs.leases.is_empty());
    assert!(!staged_refs.is_referenced());
}
