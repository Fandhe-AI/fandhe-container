//! manifest の在庫・タグ・pull リースの永続化の結合試験（OCI-7・#2380・REPAIR-5・REPAIR-12）。
//!
//! 公開 API だけを使い、別プロセス（同じ試験バイナリを `--exact` で再起動した子）が公開した在庫・タグと
//! 残したリースを、親が開き直して読めること、別プロセスのリースが `image prune` と回収 GC に見える
//! ことを具体値で確かめる。子の待機には期限を置く（REPAIR-5）。

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use fandhe_container_oci::image_management::{
    BlobReuse, ImageStore, ManifestComposition, PullId, PullPublishRequest, TagKey,
};
use fandhe_container_oci::reference::{Digest, RegistryHost, Repository, Tag};
use sha2::{Digest as _, Sha256};

const PUBLISH_CHILD: &str = "oci7_inventory_child_publishes";
const LEASE_CHILD: &str = "oci7_inventory_child_leaves_lease";
const ROOT_ENV: &str = "FC_OCI_INVENTORY_TEST_ROOT";
const DEADLINE: Duration = Duration::from_secs(60);

fn sha_of(data: &[u8]) -> Digest {
    let hex: String = Sha256::digest(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    Digest::parse(&format!("sha256:{hex}")).expect("digest")
}

fn tag_key(t: &str) -> TagKey {
    TagKey::new(
        RegistryHost::parse("registry.example").expect("host"),
        Repository::parse("lib/app").expect("repo"),
        Tag::parse(t).expect("tag"),
    )
}

fn store(root: &Path) -> ImageStore {
    ImageStore::open(root)
        .expect("open")
        .with_timeout(Duration::from_secs(5))
}

fn temp_root(label: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("fc-oci-inv-it-{}-{label}", std::process::id()));
    let _ = fs::remove_dir_all(&p);
    fs::create_dir_all(p.join("blobs").join("sha256")).expect("mkdir");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).expect("chmod");
    }
    p
}

fn blob_file(root: &Path, dg: &Digest) -> PathBuf {
    let hex = dg.as_str().strip_prefix("sha256:").expect("sha256 digest");
    root.join("blobs").join("sha256").join(hex)
}

/// 子側（公開）: config・layer を取得（ステージング）して検証し、タグつきで公開する。
/// 環境変数が無ければ何もしない。
#[test]
fn oci7_inventory_child_publishes() {
    let Some(root) = std::env::var_os(ROOT_ENV).map(PathBuf::from) else {
        return;
    };
    let s = store(&root);
    let mut session = s
        .begin_pull(PullId::new("child-pub").expect("id"))
        .expect("begin");
    let mut digests = Vec::new();
    for data in [&b"child-config"[..], &b"child-layer"[..]] {
        let dg = sha_of(data);
        let mut w = session.open_staged_blob(&dg).expect("writer");
        std::io::Write::write_all(&mut w, data).expect("write");
        w.commit().expect("commit");
        session.verify_staged_blob(&dg, 1 << 20).expect("verify");
        digests.push(dg);
    }
    let comp = ManifestComposition::new(digests[0].clone(), vec![digests[1].clone()])
        .expect("composition");
    session
        .publish(PullPublishRequest::new(sha_of(b"child-manifest"), comp).with_tag(tag_key("v1")))
        .expect("publish");
}

/// 子側（リース）: 既存 blob のリースを取り、abort も publish もせずに終了する（クラッシュ相当）。
/// 環境変数が無ければ何もしない。
#[test]
fn oci7_inventory_child_leaves_lease() {
    let Some(root) = std::env::var_os(ROOT_ENV).map(PathBuf::from) else {
        return;
    };
    let s = store(&root);
    let mut session = s
        .begin_pull(PullId::new("child-lease").expect("id"))
        .expect("begin");
    let BlobReuse::Leased(_token) = session
        .lease_existing_blob(&sha_of(b"cached-layer"))
        .expect("lease")
    else {
        panic!("expected Leased");
    };
    // `PullSession` に Drop は無い。プロセス終了で OS が `@pull.lock` を解放し、リースは永続化されたまま残る。
}

fn run_child(test: &str, root: &Path) {
    let mut child = Command::new(std::env::current_exe().expect("exe"))
        .args(["--exact", test, "--test-threads=1", "--no-capture"])
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

/// OCI-7・#2380: 別プロセスが公開したイメージの在庫・構成・タグを、親が開き直して読める。
#[test]
fn oci7_published_inventory_and_tags_survive_restart() {
    let root = temp_root("publish");
    run_child(PUBLISH_CHILD, &root);

    let cfg = sha_of(b"child-config");
    let layer = sha_of(b"child-layer");
    let manifest = sha_of(b"child-manifest");
    let s = store(&root);
    let g = s.lock().expect("lock");
    let manifests: Vec<_> = g.manifests().collect();
    assert_eq!(manifests.len(), 1);
    assert_eq!(manifests[0].0, &manifest);
    assert_eq!(manifests[0].1.config(), &cfg);
    assert_eq!(manifests[0].1.layers(), std::slice::from_ref(&layer));
    assert_eq!(
        g.tags()
            .map(|(k, m)| (k.clone(), m.clone()))
            .collect::<Vec<_>>(),
        vec![(tag_key("v1"), manifest.clone())]
    );
    // 公開した blob は実体もあり、リースは公開で解放済み。
    assert!(blob_file(&root, &cfg).exists());
    assert!(blob_file(&root, &layer).exists());
    assert_eq!(g.blob_references(&layer).leases, vec![]);
    let listed = g.list_images(&root).expect("ls");
    assert_eq!(listed.entries.len(), 1);
    assert_eq!(listed.entries[0].tag, Some(tag_key("v1")));
    assert_eq!(listed.entries[0].digest, manifest);
    drop(g);
    let _ = fs::remove_dir_all(root);
}

/// OCI-7・#2380・#2400: 別プロセスが残した pull リースは、親の `image prune` が blob を守る根拠になり、
/// 不在を確認した回収 GC が解放した後は blob を回収できる。
#[test]
fn oci7_other_process_lease_guards_prune_until_recovered() {
    let root = temp_root("lease");
    let cached = sha_of(b"cached-layer");
    fs::write(blob_file(&root, &cached), b"cached-layer").expect("blob");
    run_child(LEASE_CHILD, &root);

    // 親: 在庫は空。blob は構成に入っていないため prune の対象外（未登録 blob は消さない）だが、
    // リースが永続化されていることを具体値で確かめる。
    let s = store(&root);
    assert_eq!(
        s.lock().expect("lock").blob_references(&cached).leases,
        vec![PullId::new("child-lease").expect("id")]
    );

    // 親が同じ blob を構成に含む manifest を公開済みの状態にして、無参照の prune を実行する。
    {
        let mut g = s.lock().expect("lock");
        // 構成にだけ入れてタグ・コンテナ参照は付けない（prune の候補になる）。
        g.register_manifest(
            sha_of(b"parent-manifest"),
            ManifestComposition::new(cached.clone(), vec![]).expect("comp"),
        )
        .expect("manifest");
        let out = g.execute_image_prune(&root).expect("prune");
        assert_eq!(out.removed_manifests, vec![sha_of(b"parent-manifest")]);
        assert_eq!(out.deleted_blobs, Vec::<Digest>::new());
        assert_eq!(out.kept_leased_blobs, vec![cached.clone()]);
    }
    assert!(blob_file(&root, &cached).exists(), "leased blob must stay");

    // 回収 GC が、不在を確認できた子のリースを解放して保存する。
    let rec = store(&root).recover_stale_pulls().expect("recover");
    assert_eq!(
        rec.released_leases(),
        &[(PullId::new("child-lease").expect("id"), 1)]
    );
    assert_eq!(
        store(&root)
            .lock()
            .expect("lock")
            .blob_references(&cached)
            .leases,
        vec![]
    );
    let _ = fs::remove_dir_all(root);
}
