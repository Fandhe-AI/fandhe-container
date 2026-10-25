//! 在庫・タグ・リースの永続化（`inventory_persist`）を、操作の入口（tag・rm・prune・復旧・pull・回収）ごとに
//! 確かめる試験（OCI-7・#2380・REPAIR-12）。
//!
//! 「別プロセス相当」は、同じ root を開いた別の `ImageStore` インスタンスで表す（インスタンスごとに
//! プロセス内のテーブルが別物で、排他取得のたびにディスクから読み直す）。実際の子プロセスによる確認は
//! `tests/image_inventory_persist.rs`。保存失敗は `inventory_persist::set_fail_save` で注入する。

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use sha2::{Digest as _, Sha256};

use super::gc_journal::{GcJournal, write_journal};
use super::inventory_persist::{IMAGE_INVENTORY_FILE_NAME, set_fail_save};
use super::usage::blob_path;
use super::{
    BlobReuse, GC_JOURNAL_FILE_NAME, ImageRmKind, ImageRmOptions, ImageRmTarget, ImageStore,
    ImageTagChange, ImageTagSource, ManifestComposition, PullId, PullPublishRequest,
    StagingCleanup, StoppedContainers, TagKey,
};
use crate::error::{OciError, OciErrorCode};
use crate::reference::{Digest, RegistryHost, Repository, Tag};

fn d(n: u8) -> Digest {
    Digest::parse(&format!("sha256:{}", format!("{n:02x}").repeat(32))).expect("digest")
}

fn tk(t: &str) -> TagKey {
    TagKey::new(
        RegistryHost::parse("registry.example").expect("host"),
        Repository::parse("lib/app").expect("repo"),
        Tag::parse(t).expect("tag"),
    )
}

fn pid(s: &str) -> PullId {
    PullId::new(s).expect("pull id")
}

fn sha_of(data: &[u8]) -> Digest {
    let hex: String = Sha256::digest(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    Digest::parse(&format!("sha256:{hex}")).expect("digest")
}

/// 保存失敗の注入を、パニックしても必ず解除する。
struct FailSave;
impl FailSave {
    fn on() -> Self {
        set_fail_save(true);
        FailSave
    }
}
impl Drop for FailSave {
    fn drop(&mut self) {
        set_fail_save(false);
    }
}

struct Root(PathBuf);
impl Root {
    fn new(label: &str) -> Self {
        static SEQ: AtomicU32 = AtomicU32::new(0);
        let p = std::env::temp_dir().join(format!(
            "fc-oci-inv-ops-{}-{}-{label}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(p.join("blobs").join("sha256")).expect("mkdir");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).expect("chmod");
        }
        Root(p)
    }
    fn put(&self, dg: &Digest) {
        let p = blob_path(&self.0, dg).expect("path");
        fs::write(&p, b"x").expect("blob");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).expect("chmod");
        }
    }
    fn exists(&self, dg: &Digest) -> bool {
        fs::symlink_metadata(blob_path(&self.0, dg).expect("path")).is_ok()
    }
    fn journal(&self) -> bool {
        fs::symlink_metadata(self.0.join(GC_JOURNAL_FILE_NAME)).is_ok()
    }
    fn store(&self) -> ImageStore {
        ImageStore::open(&self.0)
            .expect("open")
            .with_timeout(Duration::from_millis(500))
    }
}
impl Drop for Root {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// A=0xa0（config 0xc1・layers 0x10 0x11）と B=0xb0（config 0xc2・layers 0x10 0x12）を永続化して在庫に入れる。
fn seed(root: &Root) {
    for n in [0xc1, 0x10, 0x11, 0xc2, 0x12] {
        root.put(&d(n));
    }
    let s = root.store();
    let mut g = s.lock().expect("lock");
    let before = g.inventory_portion();
    g.register_manifest(
        d(0xa0),
        ManifestComposition::new(d(0xc1), vec![d(0x10), d(0x11)]).expect("comp"),
    )
    .expect("manifest a");
    g.register_manifest(
        d(0xb0),
        ManifestComposition::new(d(0xc2), vec![d(0x10), d(0x12)]).expect("comp"),
    )
    .expect("manifest b");
    g.persist_inventory(before).expect("persist");
}

fn manifests_of(s: &ImageStore) -> Vec<Digest> {
    s.lock()
        .expect("lock")
        .manifests()
        .map(|(m, _)| m.clone())
        .collect()
}

fn tags_of(s: &ImageStore) -> Vec<(TagKey, Digest)> {
    s.lock()
        .expect("lock")
        .tags()
        .map(|(k, m)| (k.clone(), m.clone()))
        .collect()
}

fn leases_of(s: &ImageStore, blob: &Digest) -> Vec<PullId> {
    s.lock().expect("lock").blob_references(blob).leases
}

fn rm_tag(s: &ImageStore, root: &Root, t: &str) -> Result<super::ImageRmOutcome, OciError> {
    let mut g = s.lock()?;
    g.execute_image_rm(
        &root.0,
        &ImageRmTarget::Tag(tk(t)),
        &ImageRmOptions::default(),
        &StoppedContainers::new(),
    )
}

/// OCI-7: `image tag` のタグは別インスタンスから見え、保存の失敗ではテーブルが戻って何も残らない。
#[test]
fn oci7_tag_is_persisted_and_rolled_back_on_save_failure() {
    let root = Root::new("tag");
    seed(&root);
    let s1 = root.store();
    let out = s1
        .tag_image(&ImageTagSource::Manifest(d(0xa0)), tk("v1"))
        .expect("tag");
    assert_eq!(out.change, ImageTagChange::Added);
    assert_eq!(tags_of(&root.store()), vec![(tk("v1"), d(0xa0))]);

    {
        let _f = FailSave::on();
        let e = s1
            .tag_image(&ImageTagSource::Manifest(d(0xb0)), tk("v2"))
            .expect_err("save fails");
        assert_eq!(e.code(), OciErrorCode::Internal);
    }
    assert_eq!(tags_of(&s1), vec![(tk("v1"), d(0xa0))]);
    assert_eq!(tags_of(&root.store()), vec![(tk("v1"), d(0xa0))]);
    // 同じ付与の再実行（Unchanged）は書かない（注入が効かず成功する）。
    let _f = FailSave::on();
    let again = s1
        .tag_image(&ImageTagSource::Manifest(d(0xa0)), tk("v1"))
        .expect("unchanged");
    assert_eq!(again.change, ImageTagChange::Unchanged);
}

/// OCI-7: `image rm` の完全削除は在庫・タグの除去を永続化してから blob を消す。
#[test]
fn oci7_rm_persists_removal_before_sweeping_blobs() {
    let root = Root::new("rm");
    seed(&root);
    let s = root.store();
    s.tag_image(&ImageTagSource::Manifest(d(0xa0)), tk("v1"))
        .expect("tag");
    let out = rm_tag(&s, &root, "v1").expect("rm");
    assert_eq!(out.kind, ImageRmKind::Deleted);
    assert_eq!(out.deleted_blobs, vec![d(0x11), d(0xc1)]);
    assert_eq!(out.kept_blobs, vec![d(0x10)]);
    let other = root.store();
    assert_eq!(manifests_of(&other), vec![d(0xb0)]);
    assert_eq!(tags_of(&other), vec![]);
}

/// OCI-7: rm の保存が失敗したら blob を 1 つも消さず、テーブルとジャーナルを元へ戻す。
#[test]
fn oci7_rm_save_failure_keeps_blobs_table_and_leaves_no_journal() {
    let root = Root::new("rm-fail");
    seed(&root);
    let s = root.store();
    s.tag_image(&ImageTagSource::Manifest(d(0xa0)), tk("v1"))
        .expect("tag");
    {
        let _f = FailSave::on();
        let e = rm_tag(&s, &root, "v1").expect_err("save fails");
        assert_eq!(e.code(), OciErrorCode::Internal);
    }
    for n in [0xc1, 0x10, 0x11, 0xc2, 0x12] {
        assert!(root.exists(&d(n)), "blob {n:#x} must stay");
    }
    assert!(!root.journal());
    assert_eq!(manifests_of(&s), vec![d(0xa0), d(0xb0)]);
    assert_eq!(tags_of(&root.store()), vec![(tk("v1"), d(0xa0))]);
}

/// OCI-7: `image prune` は manifest の除去を永続化し、保存失敗では blob を消さない。
#[test]
fn oci7_prune_persists_and_survives_save_failure() {
    let root = Root::new("prune");
    seed(&root);
    let s = root.store();
    s.tag_image(&ImageTagSource::Manifest(d(0xb0)), tk("keep"))
        .expect("tag");
    {
        let _f = FailSave::on();
        let e = s
            .lock()
            .expect("lock")
            .execute_image_prune(&root.0)
            .expect_err("save fails");
        assert_eq!(e.code(), OciErrorCode::Internal);
    }
    for n in [0xc1, 0x10, 0x11, 0xc2, 0x12] {
        assert!(root.exists(&d(n)), "blob {n:#x} must stay");
    }
    assert!(!root.journal());
    assert_eq!(manifests_of(&root.store()), vec![d(0xa0), d(0xb0)]);

    let out = s
        .lock()
        .expect("lock")
        .execute_image_prune(&root.0)
        .expect("prune");
    assert_eq!(out.removed_manifests, vec![d(0xa0)]);
    assert_eq!(out.deleted_blobs, vec![d(0x11), d(0xc1)]);
    assert_eq!(manifests_of(&root.store()), vec![d(0xb0)]);
    assert_eq!(tags_of(&root.store()), vec![(tk("keep"), d(0xb0))]);
}

/// 前回の削除（A を外し 0x11・0xc1 を消す意図）を残したジャーナルを書く。
fn journal_for_a(root: &Root) {
    write_journal(
        &super::root_handle::rh(&root.0),
        &GcJournal {
            manifests: vec![d(0xa0)],
            untag: vec![(tk("v1"), d(0xa0))],
            delete_blobs: vec![d(0x11), d(0xc1)],
            attempts: 0,
        },
    )
    .expect("journal");
}

/// OCI-7・#2400: 別インスタンス（別プロセス相当）の pull リースは、削除ジャーナルの復旧の数え直しに入り、
/// そのリースが守る blob を消さない。復旧の untag・manifest 除去は永続化される。
#[test]
fn oci7_recovery_counts_other_instances_lease_and_persists_removal() {
    let root = Root::new("recover-lease");
    seed(&root);
    root.store()
        .tag_image(&ImageTagSource::Manifest(d(0xa0)), tk("v1"))
        .expect("tag");
    // 別インスタンスが blob 0x11 のリースを持つ（pull は生きたまま）。
    let puller = root.store();
    let mut session = puller.begin_pull(pid("live-pull")).expect("begin");
    let BlobReuse::Leased(_token) = session.lease_existing_blob(&d(0x11)).expect("lease") else {
        panic!("expected Leased");
    };
    journal_for_a(&root);

    let recovered = root.store();
    let rec = recovered
        .recover_pending_deletion()
        .expect("recover")
        .expect("journal");
    assert_eq!(rec.removed_manifests, vec![d(0xa0)]);
    assert_eq!(rec.untagged, vec![tk("v1")]);
    assert_eq!(rec.kept_blobs, vec![d(0x11)]);
    assert_eq!(rec.deleted_blobs, vec![d(0xc1)]);
    assert!(root.exists(&d(0x11)), "leased blob must survive");
    assert!(!root.exists(&d(0xc1)));
    assert!(!root.journal());
    // 復旧の結果は別インスタンスからも見える。
    let fresh = root.store();
    assert_eq!(manifests_of(&fresh), vec![d(0xb0)]);
    assert_eq!(tags_of(&fresh), vec![]);
    assert_eq!(leases_of(&fresh, &d(0x11)), vec![pid("live-pull")]);
    drop(session);
}

/// OCI-7: 復旧中の保存失敗は `lock` を失敗させ、ジャーナルと blob を残す（fail-closed）。次の取得で収束する。
#[test]
fn oci7_recovery_save_failure_keeps_journal_and_blobs() {
    let root = Root::new("recover-fail");
    seed(&root);
    journal_for_a(&root);
    let s = root.store();
    {
        let _f = FailSave::on();
        let e = s.recover_pending_deletion().expect_err("save fails");
        assert_eq!(e.code(), OciErrorCode::Internal);
    }
    assert!(root.journal());
    for n in [0xc1, 0x10, 0x11, 0xc2, 0x12] {
        assert!(root.exists(&d(n)), "blob {n:#x} must stay");
    }
    let rec = s
        .recover_pending_deletion()
        .expect("retry")
        .expect("journal");
    assert_eq!(rec.removed_manifests, vec![d(0xa0)]);
    assert_eq!(rec.deleted_blobs, vec![d(0x11), d(0xc1)]);
    assert_eq!(manifests_of(&root.store()), vec![d(0xb0)]);
}

fn stage(s: &mut super::PullSession<'_>, data: &[u8]) -> Digest {
    let dg = sha_of(data);
    let path = s.staged_blob_path(&dg).expect("staged path");
    fs::write(&path, data).expect("write");
    s.verify_staged_blob(&dg, 1 << 20).expect("verify");
    dg
}

/// OCI-7: pull のリースは別インスタンスから見え、公開で manifest・タグが見えてリースは消える。
#[test]
fn oci7_pull_lease_and_publish_are_persisted() {
    let root = Root::new("pull");
    let cached = sha_of(b"cached-layer");
    fs::write(blob_path(&root.0, &cached).expect("path"), b"cached-layer").expect("blob");
    let s = root.store();
    let mut session = s.begin_pull(pid("p1")).expect("begin");
    let BlobReuse::Leased(_t) = session.lease_existing_blob(&cached).expect("lease") else {
        panic!("expected Leased");
    };
    assert_eq!(leases_of(&root.store(), &cached), vec![pid("p1")]);

    let cfg = stage(&mut session, b"config-body");
    let layer = stage(&mut session, b"layer-body");
    let comp = ManifestComposition::new(cfg, vec![cached.clone(), layer]).expect("comp");
    let m = sha_of(b"manifest-body");
    let out = session
        .publish(PullPublishRequest::new(m.clone(), comp).with_tag(tk("v1")))
        .expect("publish");
    assert_eq!(out.released_leases, 1);
    assert_eq!(out.staging, StagingCleanup::Removed);

    let other = root.store();
    assert_eq!(manifests_of(&other), vec![m.clone()]);
    assert_eq!(tags_of(&other), vec![(tk("v1"), m)]);
    assert_eq!(leases_of(&other, &cached), vec![]);
}

/// OCI-7: 公開の保存が失敗しても、公開済みの blob は消さず、manifest は在庫に残さない。
/// リースとステージングは回収 GC が片づける（余分に残す側にだけ誤る）。
#[test]
fn oci7_publish_save_failure_keeps_blobs_and_recovery_cleans_up() {
    let root = Root::new("pub-fail");
    let cached = sha_of(b"cached-layer");
    fs::write(blob_path(&root.0, &cached).expect("path"), b"cached-layer").expect("blob");
    let s = root.store();
    let mut session = s.begin_pull(pid("p1")).expect("begin");
    let BlobReuse::Leased(_t) = session.lease_existing_blob(&cached).expect("lease") else {
        panic!("expected Leased");
    };
    let cfg = stage(&mut session, b"config-body");
    let comp = ManifestComposition::new(cfg.clone(), vec![cached.clone()]).expect("comp");
    let staging_dir = session.staging_dir().to_path_buf();
    let m = sha_of(b"manifest-body");
    {
        let _f = FailSave::on();
        let e = session
            .publish(PullPublishRequest::new(m, comp).with_tag(tk("v1")))
            .expect_err("save fails");
        assert_eq!(e.code(), OciErrorCode::Internal);
    }
    assert!(root.exists(&cfg), "published blob must not be removed");
    assert_eq!(manifests_of(&root.store()), vec![]);
    assert_eq!(tags_of(&root.store()), vec![]);
    // 保存できなかったので、リースもステージングも残っている。
    assert_eq!(leases_of(&root.store(), &cached), vec![pid("p1")]);
    assert!(staging_dir.exists());

    let rec = root.store().recover_stale_pulls().expect("recover");
    assert_eq!(rec.reclaimed(), &[pid("p1")]);
    assert_eq!(rec.released_leases(), &[(pid("p1"), 1)]);
    assert_eq!(leases_of(&root.store(), &cached), vec![]);
    assert!(!staging_dir.exists());
    assert!(root.exists(&cfg));
}

/// OCI-7: abort の解放の保存が失敗したら、ステージングを消さずにエラーを返す（回収 GC が拾う）。
#[test]
fn oci7_abort_save_failure_keeps_staging_until_recovery() {
    let root = Root::new("abort-fail");
    let cached = sha_of(b"cached-layer");
    fs::write(blob_path(&root.0, &cached).expect("path"), b"cached-layer").expect("blob");
    let s = root.store();
    let mut session = s.begin_pull(pid("p1")).expect("begin");
    let BlobReuse::Leased(_t) = session.lease_existing_blob(&cached).expect("lease") else {
        panic!("expected Leased");
    };
    let staging_dir = session.staging_dir().to_path_buf();
    {
        let _f = FailSave::on();
        let e = session.abort().expect_err("save fails");
        assert_eq!(e.code(), OciErrorCode::Internal);
    }
    assert!(staging_dir.exists());
    assert_eq!(leases_of(&root.store(), &cached), vec![pid("p1")]);

    let rec = root.store().recover_stale_pulls().expect("recover");
    assert_eq!(rec.released_leases(), &[(pid("p1"), 1)]);
    assert!(!staging_dir.exists());
    assert_eq!(leases_of(&root.store(), &cached), vec![]);
}

/// OCI-7: 別インスタンスで drop された pull のリースを、回収 GC が解放して保存する（解放後は誰からも見えない）。
#[test]
fn oci7_recovery_releases_and_persists_other_instances_leases() {
    let root = Root::new("recover-pull");
    let cached = sha_of(b"cached-layer");
    fs::write(blob_path(&root.0, &cached).expect("path"), b"cached-layer").expect("blob");
    {
        let dead = root.store();
        let mut session = dead.begin_pull(pid("dead")).expect("begin");
        let BlobReuse::Leased(_t) = session.lease_existing_blob(&cached).expect("lease") else {
            panic!("expected Leased");
        };
        // abort も publish もせずに drop（プロセス終了相当。OS ロックが外れる）。
    }
    assert_eq!(leases_of(&root.store(), &cached), vec![pid("dead")]);

    let rec = root.store().recover_stale_pulls().expect("recover");
    assert_eq!(rec.released_leases(), &[(pid("dead"), 1)]);
    assert_eq!(leases_of(&root.store(), &cached), vec![]);
    assert!(Path::new(&root.0.join(IMAGE_INVENTORY_FILE_NAME)).exists());
}
