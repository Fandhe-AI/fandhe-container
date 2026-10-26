//! イメージ管理の参照カウント・排他・GC の代表シナリオ結合試験（OCI-7・TASK-183.12・#483）。
//!
//! 個別に実装済みの参照テーブル・ストア排他・`image tag` / `image rm` / `image prune`・コンテナ参照の
//! 登録と解除・pull のリースと公開を、公開 API だけでつなぎ、各段階の参照カウントと削除結果
//! （テーブル・blob ファイルの有無・Outcome の各ベクタ）を具体値で照合する。
//! 実機での 50 並列・SIGKILL 復旧・別プロセスでの再起動後の照合は TASK-184 の担当で、ここでは扱わない。
//! コンテナ参照は `ImageStore` の入口だけで扱う（ガード越しの直接登録は永続化との読み直しで消えるため）。

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use fandhe_container_oci::error::{OciError, OciErrorCode};
use fandhe_container_oci::image_management::{
    BlobReuse, ContainerRefGeneration, ContainerRefId, ContainerRefRegistration,
    ContainerRefRelease, DeletionDurability, ImageRmKind, ImageRmOptions, ImageRmOutcome,
    ImageRmTarget, ImageStore, ImageTagChange, ImageTagSource, ManifestComposition, PullId,
    PullPublishRequest, PullSession, ReferenceTable, StagingCleanup, StoppedContainers, TagKey,
};
use fandhe_container_oci::reference::{Digest, RegistryHost, Repository, Tag};
use sha2::{Digest as _, Sha256};

fn d(n: u8) -> Digest {
    Digest::parse(&format!("sha256:{}", format!("{n:02x}").repeat(32))).expect("digest")
}

fn blob(root: &Path, n: u8) -> PathBuf {
    root.join("blobs")
        .join("sha256")
        .join(format!("{n:02x}").repeat(32))
}

fn sha_of(data: &[u8]) -> Digest {
    let mut hex = String::new();
    for b in Sha256::digest(data) {
        hex.push_str(&format!("{b:02x}"));
    }
    Digest::parse(&format!("sha256:{hex}")).expect("digest")
}

fn blob_of(root: &Path, dg: &Digest) -> PathBuf {
    root.join("blobs")
        .join("sha256")
        .join(dg.as_str().trim_start_matches("sha256:"))
}

fn tag(t: &str) -> TagKey {
    TagKey::new(
        RegistryHost::parse("registry.example").expect("host"),
        Repository::parse("lib/app").expect("repo"),
        Tag::parse(t).expect("tag"),
    )
}

fn cid(s: &str) -> ContainerRefId {
    ContainerRefId::new(s).expect("container id")
}

fn pid(s: &str) -> PullId {
    PullId::new(s).expect("pull id")
}

/// `blobs/sha256` のファイル数。
fn blob_files(root: &Path) -> usize {
    fs::read_dir(root.join("blobs").join("sha256"))
        .expect("read_dir")
        .count()
}

/// Windows はディレクトリを fsync できないため `Unconfirmed` になる。
fn confirmed() -> DeletionDurability {
    if cfg!(unix) {
        DeletionDurability::Confirmed
    } else {
        DeletionDurability::Unconfirmed
    }
}

/// 一時 root を `Drop` で消す。
struct Cleanup(PathBuf);

impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn new_root(name: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!("fc-oci-mgmt-it-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(root.join("blobs").join("sha256")).expect("mkdir");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("chmod");
    }
    root
}

struct Fixture {
    root: PathBuf,
    store: ImageStore,
    _cleanup: Cleanup,
}

/// A(0xa0) = {cfg 0xc1, 0x10, 0x11} / B(0xb0) = {cfg 0xc2, 0x10, 0x12}。0x10 は共有レイヤー。
fn graph_fixture(name: &str) -> Fixture {
    let root = new_root(name);
    let cleanup = Cleanup(root.clone());
    for n in [0xc1u8, 0xc2, 0x10, 0x11, 0x12] {
        fs::write(blob(&root, n), vec![1u8; 16]).expect("write");
    }
    let mut t = ReferenceTable::new();
    for (m, c, ls) in [
        (0xa0u8, 0xc1u8, vec![0x10u8, 0x11]),
        (0xb0, 0xc2, vec![0x10, 0x12]),
    ] {
        t.register_manifest(
            d(m),
            ManifestComposition::new(d(c), ls.into_iter().map(d).collect()).expect("comp"),
        )
        .expect("register");
    }
    let store = ImageStore::with_table(&root, t)
        .expect("store")
        .with_timeout(Duration::from_millis(100));
    Fixture {
        root,
        store,
        _cleanup: cleanup,
    }
}

fn rm(store: &ImageStore, target: ImageRmTarget) -> Result<ImageRmOutcome, OciError> {
    let mut g = store.lock().expect("lock");
    g.execute_image_rm(
        store.root(),
        &target,
        &ImageRmOptions::default(),
        &StoppedContainers::new(),
    )
}

/// OCI-7・TASK-183.12: create（コンテナ参照の登録と確定）→ `rm` の拒否と `--force` → prune → delete（参照解除）→ prune。
#[test]
fn oci7_scenario_create_delete_with_force_untag_then_prune() {
    let f = graph_fixture("create-delete");
    let c1 = cid("c1");
    let (a, b) = (d(0xa0), d(0xb0));

    let out = f
        .store
        .tag_image(&ImageTagSource::Manifest(a.clone()), tag("v1"))
        .expect("tag");
    assert_eq!(out.change, ImageTagChange::Added);

    // create: 登録 → 確定。
    assert_eq!(
        f.store.register_container_ref(&c1, &a).expect("register"),
        ContainerRefRegistration::Registered
    );
    let g1 = f.store.bind_container_ref(&c1).expect("bind");
    assert_eq!(
        f.store.container_ref_registration(&c1).expect("reg"),
        Some(g1)
    );
    {
        let g = f.store.lock().expect("lock");
        let r = g.manifest_references(&a);
        assert_eq!(r.containers, vec![c1.clone()]);
        assert_eq!(r.tags, vec![tag("v1")]);
        assert_eq!(r.count(), 2);
        let br = g.blob_references(&d(0x10));
        assert_eq!(br.referenced_via_manifests, 1);
        assert_eq!(br.referencing_manifests, vec![a.clone(), b.clone()]);
    }

    // 既定の rm はコンテナが参照しているため拒否される。
    let e = rm(&f.store, ImageRmTarget::Tag(tag("v1"))).expect_err("in use");
    assert_eq!(e.code(), OciErrorCode::FailedPrecondition);
    assert_eq!(blob_files(&f.root), 5);

    // --force でも停止中と宣言されていなければ実行中とみなして拒否する。
    {
        let mut g = f.store.lock().expect("lock");
        let e = g
            .execute_image_rm(
                f.store.root(),
                &ImageRmTarget::Tag(tag("v1")),
                &ImageRmOptions::force(),
                &StoppedContainers::new(),
            )
            .expect_err("running");
        assert_eq!(e.code(), OciErrorCode::FailedPrecondition);
    }

    // --force かつ停止中: タグだけ外れ、blob は 1 つも消えない。
    {
        let mut stopped = StoppedContainers::new();
        stopped.insert(c1.clone());
        let mut g = f.store.lock().expect("lock");
        let out = g
            .execute_image_rm(
                f.store.root(),
                &ImageRmTarget::Tag(tag("v1")),
                &ImageRmOptions::force(),
                &stopped,
            )
            .expect("force rm");
        assert_eq!(out.kind, ImageRmKind::UntagOnly);
        assert_eq!(out.untagged, vec![tag("v1")]);
        assert_eq!(out.deleted_blobs, vec![]);
        assert_eq!(out.durability, DeletionDurability::NotApplicable);
        let r = g.manifest_references(&a);
        assert_eq!(r.containers, vec![c1.clone()]);
        assert_eq!(r.tags, vec![]);
    }
    assert_eq!(blob_files(&f.root), 5);

    // prune: 無参照の B だけが消え、A と共有するレイヤー 0x10 は残る。
    {
        let mut g = f.store.lock().expect("lock");
        let out = g.execute_image_prune(f.store.root()).expect("prune");
        assert_eq!(out.removed_manifests, vec![b.clone()]);
        assert_eq!(out.deleted_blobs, vec![d(0x12), d(0xc2)]);
        assert_eq!(out.kept_shared_blobs, vec![d(0x10)]);
        assert_eq!(out.kept_leased_blobs, vec![]);
        assert_eq!(out.reclaimed_bytes, 32);
        assert_eq!(out.durability, confirmed());
    }
    for n in [0x12u8, 0xc2] {
        assert!(!blob(&f.root, n).exists());
    }
    for n in [0x10u8, 0x11, 0xc1] {
        assert!(blob(&f.root, n).exists());
    }

    // delete: 古い世代では外れず、正しい世代で外れる。
    let stale = ContainerRefGeneration::from_raw(g1.as_raw() + 1);
    assert_eq!(
        f.store.release_container_ref_if(&c1, stale).expect("stale"),
        ContainerRefRelease::NotRegistered
    );
    assert_eq!(
        f.store
            .lock()
            .expect("lock")
            .manifest_references(&a)
            .count(),
        1
    );
    assert_eq!(
        f.store.release_container_ref_if(&c1, g1).expect("release"),
        ContainerRefRelease::Released(a.clone())
    );
    assert_eq!(
        f.store
            .lock()
            .expect("lock")
            .manifest_references(&a)
            .count(),
        0
    );

    // 参照が全て外れた A も prune で回収され、ストアは空になる。
    {
        let mut g = f.store.lock().expect("lock");
        let out = g.execute_image_prune(f.store.root()).expect("prune");
        assert_eq!(out.removed_manifests, vec![a]);
        assert_eq!(out.deleted_blobs, vec![d(0x10), d(0x11), d(0xc1)]);
        assert_eq!(out.reclaimed_bytes, 48);
        assert_eq!(out.durability, confirmed());
        assert_eq!(g.manifests().count(), 0);
    }
    assert_eq!(blob_files(&f.root), 0);
    drop(f.store.lock().expect("journal settled"));
}

/// OCI-7・TASK-183.12: tag の付け替え → prune（タグ付きは残す）→ rm（複数タグは untag のみ・最後のタグで削除）。
#[test]
fn oci7_scenario_tag_move_then_prune_and_rm() {
    let f = graph_fixture("tag-prune");
    let (a, b) = (d(0xa0), d(0xb0));
    let tag_of = |src: ImageTagSource, t: &str| f.store.tag_image(&src, tag(t));

    assert_eq!(
        tag_of(ImageTagSource::Manifest(a.clone()), "v1")
            .expect("tag")
            .change,
        ImageTagChange::Added
    );
    let o = tag_of(ImageTagSource::Tag(tag("v1")), "v2").expect("tag");
    assert_eq!((o.manifest, o.change), (a.clone(), ImageTagChange::Added));
    assert_eq!(
        tag_of(ImageTagSource::Manifest(b.clone()), "v1")
            .expect("tag")
            .change,
        ImageTagChange::Moved { from: a.clone() }
    );
    {
        let g = f.store.lock().expect("lock");
        assert_eq!(g.manifest_references(&a).tags, vec![tag("v2")]);
        assert_eq!(g.manifest_references(&b).tags, vec![tag("v1")]);
    }

    // どちらもタグ付き: prune は何も消さない。
    {
        let mut g = f.store.lock().expect("lock");
        let out = g.execute_image_prune(f.store.root()).expect("prune");
        assert_eq!(out.removed_manifests, vec![]);
        assert_eq!(out.deleted_blobs, vec![]);
        assert_eq!(out.durability, DeletionDurability::NotApplicable);
    }
    assert_eq!(blob_files(&f.root), 5);

    // v2 を B へ付け替えると A が無参照になる。
    assert_eq!(
        tag_of(ImageTagSource::Manifest(b.clone()), "v2")
            .expect("tag")
            .change,
        ImageTagChange::Moved { from: a.clone() }
    );
    {
        let g = f.store.lock().expect("lock");
        assert_eq!(g.manifest_references(&a).count(), 0);
        assert_eq!(g.manifest_references(&b).tags, vec![tag("v1"), tag("v2")]);
    }
    {
        let mut g = f.store.lock().expect("lock");
        let out = g.execute_image_prune(f.store.root()).expect("prune");
        assert_eq!(out.removed_manifests, vec![a]);
        assert_eq!(out.deleted_blobs, vec![d(0x11), d(0xc1)]);
        assert_eq!(out.kept_shared_blobs, vec![d(0x10)]);
        assert_eq!(out.reclaimed_bytes, 32);
        assert_eq!(out.durability, confirmed());
    }

    // タグが 2 件ある間は untag のみ。
    let out = rm(&f.store, ImageRmTarget::Tag(tag("v1"))).expect("rm v1");
    assert_eq!(out.kind, ImageRmKind::UntagOnly);
    assert_eq!(out.untagged, vec![tag("v1")]);
    assert_eq!(out.deleted_blobs, vec![]);
    assert_eq!(out.durability, DeletionDurability::NotApplicable);
    for n in [0x10u8, 0x12, 0xc2] {
        assert!(blob(&f.root, n).exists());
    }

    // 最後のタグを外すと削除になる。
    let out = rm(&f.store, ImageRmTarget::Tag(tag("v2"))).expect("rm v2");
    assert_eq!(out.kind, ImageRmKind::Deleted);
    assert_eq!(out.untagged, vec![tag("v2")]);
    assert_eq!(out.deleted_blobs, vec![d(0x10), d(0x12), d(0xc2)]);
    assert_eq!(out.kept_blobs, vec![]);
    assert_eq!(out.durability, confirmed());
    assert_eq!(blob_files(&f.root), 0);
    {
        let g = f.store.lock().expect("journal settled");
        assert_eq!(g.manifests().count(), 0);
    }

    // 消えたタグは付け元にできず、テーブルは変わらない。
    let e = tag_of(ImageTagSource::Tag(tag("v1")), "v3").expect_err("gone");
    assert_eq!(e.code(), OciErrorCode::NotFound);
    assert_eq!(f.store.lock().expect("lock").tags().count(), 0);
}

/// ステージングへ書いて sha256 を検証し、digest を返す。
fn stage(s: &mut PullSession<'_>, data: &[u8]) -> Digest {
    let dg = sha_of(data);
    let mut w = s.open_staged_blob(&dg).expect("writer");
    std::io::Write::write_all(&mut w, data).expect("write");
    w.commit().expect("commit");
    s.verify_staged_blob(&dg, 1024).expect("verify");
    dg
}

/// OCI-7・TASK-183.12: pull の公開前は見えず、リースが並行する rm から共有 blob を守り、公開で参照に置き換わる。
#[test]
fn oci7_scenario_pull_publish_with_lease_protects_shared_blob() {
    let root = new_root("pull-lease");
    let _cleanup = Cleanup(root.clone());
    let store = ImageStore::open(&root)
        .expect("open")
        .with_timeout(Duration::from_millis(100));
    let (m_a, m_b) = (sha_of(b"manifest-a"), sha_of(b"manifest-b"));

    let mut p1 = store.begin_pull(pid("it-p1")).expect("begin");
    let cfg1 = stage(&mut p1, b"config-1");
    let shared = stage(&mut p1, b"shared-layer");
    {
        let g = store.lock().expect("lock");
        assert_eq!(g.list_images(&root).expect("ls").entries.len(), 0);
        assert_eq!(g.manifests().count(), 0);
    }
    assert!(!blob_of(&root, &shared).exists());

    let comp = ManifestComposition::new(cfg1.clone(), vec![shared.clone()]).expect("comp");
    let out = p1
        .publish(PullPublishRequest::new(m_a.clone(), comp).with_tag(tag("v1")))
        .expect("publish");
    let mut moved = vec![cfg1.clone(), shared.clone()];
    moved.sort();
    assert_eq!(out.moved_blobs, moved);
    assert_eq!(out.released_leases, 0);
    assert_eq!(out.staging, StagingCleanup::Removed);
    assert_eq!(out.tags, vec![(tag("v1"), ImageTagChange::Added)]);
    assert_eq!(
        store.lock().expect("lock").manifest_references(&m_a).tags,
        vec![tag("v1")]
    );

    // 2 本目の pull が共有レイヤーをリースする。
    let mut p2 = store.begin_pull(pid("it-p2")).expect("begin");
    let BlobReuse::Leased(_t) = p2.lease_existing_blob(&shared).expect("lease") else {
        panic!("expected Leased");
    };
    assert_eq!(
        store.lock().expect("lock").blob_references(&shared).leases,
        vec![pid("it-p2")]
    );

    // 並行する rm は config だけを消し、リース中の共有レイヤーは残す。
    let rm_out = rm(&store, ImageRmTarget::Tag(tag("v1"))).expect("rm");
    assert_eq!(rm_out.kind, ImageRmKind::Deleted);
    assert_eq!(rm_out.deleted_blobs, vec![cfg1.clone()]);
    assert_eq!(rm_out.kept_blobs, vec![shared.clone()]);
    assert!(blob_of(&root, &shared).exists());
    assert!(!blob_of(&root, &cfg1).exists());
    assert_eq!(store.lock().expect("lock").manifests().count(), 0);

    // pull 2 の公開: 共有レイヤーは再利用され、リースが参照に置き換わる。
    let cfg2 = stage(&mut p2, b"config-2");
    let comp = ManifestComposition::new(cfg2.clone(), vec![shared.clone()]).expect("comp");
    let out = p2
        .publish(PullPublishRequest::new(m_b, comp).with_tag(tag("v2")))
        .expect("publish");
    assert_eq!(out.reused_blobs, vec![shared.clone()]);
    assert_eq!(out.moved_blobs, vec![cfg2.clone()]);
    assert_eq!(out.released_leases, 1);
    {
        let g = store.lock().expect("lock");
        let br = g.blob_references(&shared);
        assert_eq!(br.leases, vec![]);
        assert_eq!(br.referenced_via_manifests, 1);
    }

    let rm_out = rm(&store, ImageRmTarget::Tag(tag("v2"))).expect("rm");
    let mut deleted = vec![cfg2, shared];
    deleted.sort();
    assert_eq!(rm_out.kind, ImageRmKind::Deleted);
    assert_eq!(rm_out.deleted_blobs, deleted);
    assert_eq!(rm_out.durability, confirmed());
    assert_eq!(blob_files(&root), 0);
    drop(store.lock().expect("journal settled"));
}

/// OCI-7・TASK-183.12: リース中の blob は prune で残り、pull の中断後は未登録 blob として残る（余分に残す側）。
#[test]
fn oci7_scenario_lease_blocks_prune_until_abort() {
    let root = new_root("lease-prune");
    let _cleanup = Cleanup(root.clone());
    let store = ImageStore::open(&root)
        .expect("open")
        .with_timeout(Duration::from_millis(100));
    let m_x = sha_of(b"manifest-x");

    let mut p1 = store.begin_pull(pid("it-q1")).expect("begin");
    let cfg_x = stage(&mut p1, b"config-x");
    let layer_x = stage(&mut p1, b"layer-x");
    let comp = ManifestComposition::new(cfg_x.clone(), vec![layer_x.clone()]).expect("comp");
    p1.publish(PullPublishRequest::new(m_x.clone(), comp))
        .expect("publish untagged");
    assert_eq!(
        store
            .lock()
            .expect("lock")
            .manifest_references(&m_x)
            .count(),
        0
    );

    let mut q3 = store.begin_pull(pid("it-q3")).expect("begin");
    let BlobReuse::Leased(_t) = q3.lease_existing_blob(&layer_x).expect("lease") else {
        panic!("expected Leased");
    };
    {
        let mut g = store.lock().expect("lock");
        let out = g.execute_image_prune(store.root()).expect("prune");
        assert_eq!(out.removed_manifests, vec![m_x]);
        assert_eq!(out.deleted_blobs, vec![cfg_x.clone()]);
        assert_eq!(out.kept_leased_blobs, vec![layer_x.clone()]);
        assert_eq!(out.kept_shared_blobs, vec![]);
    }
    assert!(blob_of(&root, &layer_x).exists());
    assert!(!blob_of(&root, &cfg_x).exists());

    let staged = q3.staging_dir().to_path_buf();
    let ab = q3.abort().expect("abort");
    assert_eq!(ab.released_leases, 1);
    assert_eq!(ab.staging, StagingCleanup::Removed);
    assert!(!staged.exists());
    {
        let g = store.lock().expect("lock");
        assert_eq!(g.blob_references(&layer_x).leases, vec![]);
        let usage = g.disk_usage(&root).expect("df");
        assert_eq!(usage.cache.unregistered_count, 1);
        assert_eq!(usage.cache.unregistered_bytes, b"layer-x".len() as u64);
    }
    // prune は未登録 blob を回収しない。
    {
        let mut g = store.lock().expect("lock");
        let out = g.execute_image_prune(store.root()).expect("prune");
        assert_eq!(out.deleted_blobs, vec![]);
    }
    assert!(blob_of(&root, &layer_x).exists());
}

/// OCI-7・TASK-183.12: 排他区間の保持中は、タグ・コンテナ参照・pull 開始・別の排他取得がすべて期限内に Timeout し、
/// 状態は変わらない。解放後は同じ操作が成功する。
#[test]
fn oci7_exclusive_section_blocks_reference_changes_in_process() {
    let f = graph_fixture("exclusive");
    let (a, c1) = (d(0xa0), cid("c1"));
    let g = f.store.lock().expect("lock");

    std::thread::scope(|s| {
        s.spawn(|| {
            let start = Instant::now();
            let codes = [
                f.store
                    .tag_image(&ImageTagSource::Manifest(a.clone()), tag("v1"))
                    .err()
                    .map(|e| e.code()),
                f.store
                    .register_container_ref(&c1, &a)
                    .err()
                    .map(|e| e.code()),
                f.store.begin_pull(pid("it-x")).err().map(|e| e.code()),
                f.store.lock().err().map(|e| e.code()),
            ];
            assert_eq!(codes, [Some(OciErrorCode::Timeout); 4]);
            assert!(start.elapsed() >= Duration::from_millis(400));
        });
    });

    assert_eq!(g.tags().count(), 0);
    assert_eq!(g.manifest_references(&a).count(), 0);
    assert!(!f.root.join("staging").join("it-x").exists());
    assert_eq!(blob_files(&f.root), 5);
    drop(g);

    assert_eq!(
        f.store
            .tag_image(&ImageTagSource::Manifest(a.clone()), tag("v1"))
            .expect("tag")
            .change,
        ImageTagChange::Added
    );
    assert_eq!(
        f.store.register_container_ref(&c1, &a).expect("register"),
        ContainerRefRegistration::Registered
    );
    let p = f.store.begin_pull(pid("it-x")).expect("begin");
    p.abort().expect("abort");
}
