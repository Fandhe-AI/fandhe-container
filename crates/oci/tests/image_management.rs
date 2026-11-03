//! 参照テーブルの結合試験（OCI-7・TASK-183.1）。
//!
//! 公開 API（`ReferenceTable` ほか）だけを通し、manifest 登録からコンテナ・タグ・リースの
//! 登録と解除、共有 blob の保護判定までを流す。`image tag` の排他下の入口（TASK-183.4）も
//! `ImageStore` 経由で流す。永続化・CLI 経路は未実装のため対象外。

use fandhe_container_oci::error::OciErrorCode;
use fandhe_container_oci::image_management::{
    ContainerRefId, ImageStore, ImageTagChange, ImageTagSource, ManifestComposition, PullId,
    ReferenceTable, TagKey,
};
use fandhe_container_oci::reference::{Digest, RegistryHost, Repository, Tag};

#[path = "support/test_root.rs"]
mod test_root;

fn d(n: u8) -> Digest {
    Digest::parse(&format!("sha256:{}", format!("{n:02x}").repeat(32))).expect("digest")
}

fn tag(t: &str) -> TagKey {
    TagKey::new(
        RegistryHost::parse("registry.example").expect("host"),
        Repository::parse("lib/app").expect("repo"),
        Tag::parse(t).expect("tag"),
    )
}

/// OCI-7: 登録 → 参照 → 解除 → manifest 削除 → 共有 blob の保護解除までの一連の流れ。
#[test]
fn oci7_shared_blob_lifecycle_through_public_api() {
    let (ma, mb) = (d(0xa0), d(0xb0));
    let (shared, only_a, only_b) = (d(0x10), d(0x11), d(0x12));
    let c1 = ContainerRefId::new("c1").expect("id");
    let pull = PullId::new("pull-1").expect("pull");

    let mut t = ReferenceTable::new();
    t.register_manifest(
        ma.clone(),
        ManifestComposition::new(d(0xc1), vec![shared.clone(), only_a.clone()]).expect("comp"),
    )
    .expect("register a");
    t.register_manifest(
        mb.clone(),
        ManifestComposition::new(d(0xc2), vec![shared.clone(), only_b.clone()]).expect("comp"),
    )
    .expect("register b");

    // コンテナ 1 件とタグ 2 件（A に 1、B に 1）を登録する。
    t.register_container(c1.clone(), &ma).expect("container");
    assert_eq!(t.register_tag(tag("a"), &ma).expect("tag a"), None);
    assert_eq!(t.register_tag(tag("b"), &mb).expect("tag b"), None);
    assert_eq!(t.manifest_references(&ma).count(), 2);
    assert_eq!(t.manifest_references(&mb).count(), 1);
    assert_eq!(t.blob_references(&shared).referenced_via_manifests, 2);

    // 参照が残る manifest は削除できない。
    let e = t.remove_manifest(&ma).expect_err("still referenced");
    assert_eq!(e.code(), OciErrorCode::FailedPrecondition);

    // pull リースは参照の無い blob も保護する。
    assert!(!t.blob_references(&d(0x99)).is_referenced());
    assert!(t.acquire_lease(d(0x99), pull.clone()).unwrap().newly_added);
    assert!(!t.acquire_lease(d(0x99), pull.clone()).unwrap().newly_added);
    assert_eq!(t.blob_references(&d(0x99)).leases, vec![pull.clone()]);
    assert!(t.blob_references(&d(0x99)).is_referenced());

    // A の参照をすべて外すと専有 blob は未参照、共有 blob は B 経由で保護され続ける。
    assert_eq!(t.unregister_container(&c1).expect("unreg c"), ma);
    assert_eq!(t.unregister_tag(&tag("a")).expect("unreg tag"), ma);
    assert_eq!(t.manifest_references(&ma).count(), 0);
    assert!(!t.blob_references(&only_a).is_referenced());
    let sh = t.blob_references(&shared);
    assert_eq!(sh.referencing_manifests, vec![ma.clone(), mb.clone()]);
    assert_eq!(sh.referenced_via_manifests, 1);
    assert!(sh.is_referenced());

    // A を在庫から外すと shared を参照する manifest は B だけになる。
    t.remove_manifest(&ma).expect("remove a");
    assert_eq!(
        t.blob_references(&shared).referencing_manifests,
        vec![mb.clone()]
    );

    // B のタグを外すと shared も未参照になる。リースは解放するまで残る。
    t.unregister_tag(&tag("b")).expect("unreg b");
    assert!(!t.blob_references(&shared).is_referenced());
    assert!(t.blob_references(&d(0x99)).is_referenced());
    assert_eq!(t.release_all_leases(&pull), vec![d(0x99)]);
    assert!(!t.blob_references(&d(0x99)).is_referenced());
    t.remove_manifest(&mb).expect("remove b");
}

/// OCI-7: 不在 manifest への参照登録・未登録の解除は `NotFound`。
#[test]
fn oci7_missing_targets_report_not_found() {
    let mut t = ReferenceTable::new();
    let id = ContainerRefId::new("c1").expect("id");
    let e = t
        .register_container(id.clone(), &d(0xa0))
        .expect_err("no manifest");
    assert_eq!(e.code(), OciErrorCode::NotFound);
    let e = t.unregister_container(&id).expect_err("not registered");
    assert_eq!(e.code(), OciErrorCode::NotFound);
    let e = t
        .release_lease(&d(0x10), &PullId::new("p").expect("pull"))
        .expect_err("no lease");
    assert_eq!(e.code(), OciErrorCode::NotFound);
}

/// OCI-7・TASK-183.6: `ImageStore` のガード越しに `image rm --force` の untag 経路と完全削除を流す。
///
/// 受け入れ条件 1（停止中のコンテナだけが参照するイメージに force をかけても、起動に要る構成と blob が
/// テーブルとディスクに揃っている）と 2（無参照のイメージの削除で manifest・config・非共有レイヤーが消える）を
/// 確かめる。実際の `start` は oci から呼べない（core に依存しない）ため、実機での
/// `create`・`stop`・`image rm --force`・`start` の確認は TASK-184 に任せる。
#[test]
fn oci7_image_rm_force_through_store_guard() {
    use fandhe_container_oci::image_management::{
        ImageRmKind, ImageRmOptions, ImageRmTarget, ImageStore, StoppedContainers,
    };
    use std::fs;

    let root = test_root::test_root("fc-oci-it-rm", "rm");
    let blobs = root.join("blobs").join("sha256");
    fs::create_dir_all(&blobs).expect("mkdir");
    let put = |dg: &Digest| {
        let hex = dg.as_str().trim_start_matches("sha256:");
        fs::write(blobs.join(hex), dg.as_str()).expect("write blob");
    };
    let present = |dg: &Digest| {
        let hex = dg.as_str().trim_start_matches("sha256:");
        blobs.join(hex).exists()
    };

    let (ma, mb) = (d(0xa0), d(0xb0));
    let store = ImageStore::open(&root).expect("open");
    {
        let mut t = store.lock().expect("lock");
        t.register_manifest(
            ma.clone(),
            ManifestComposition::new(d(0xc1), vec![d(0x10), d(0x11)]).expect("comp"),
        )
        .expect("register a");
        t.register_manifest(
            mb.clone(),
            ManifestComposition::new(d(0xc2), vec![d(0x10), d(0x12)]).expect("comp"),
        )
        .expect("register b");
        for n in [0xc1, 0x10, 0x11, 0xc2, 0x12] {
            put(&d(n));
        }
        t.register_tag(tag("a"), &ma).expect("tag a");
        t.register_tag(tag("b"), &mb).expect("tag b");
        let c1 = ContainerRefId::new("c1").expect("id");
        t.register_container(c1.clone(), &ma).expect("container");

        // 実行中（スナップショットに無い）なら force でも拒否する。
        let e = t
            .execute_image_rm(
                store.root(),
                &ImageRmTarget::Tag(tag("a")),
                &ImageRmOptions::force(),
                &StoppedContainers::new(),
            )
            .expect_err("running");
        assert_eq!(e.code(), OciErrorCode::FailedPrecondition);

        // 停止中なら untag だけで、起動に要る blob が全部残る。
        let stopped: StoppedContainers = [c1.clone()].into_iter().collect();
        let out = t
            .execute_image_rm(
                store.root(),
                &ImageRmTarget::Tag(tag("a")),
                &ImageRmOptions::force(),
                &stopped,
            )
            .expect("force untag");
        assert_eq!(out.kind, ImageRmKind::UntagOnly);
        assert_eq!(out.untagged, vec![tag("a")]);
        assert_eq!(t.manifest_references(&ma).containers, vec![c1]);
        for n in [0xc1, 0x10, 0x11] {
            assert!(present(&d(n)), "blob {n:#x} must remain");
        }

        // 無参照の B は force なしで消え、共有でない config・レイヤーも消える。
        let out = t
            .execute_image_rm(
                store.root(),
                &ImageRmTarget::Tag(tag("b")),
                &ImageRmOptions::default(),
                &StoppedContainers::new(),
            )
            .expect("delete b");
        assert_eq!(out.kind, ImageRmKind::Deleted);
        assert_eq!(out.deleted_blobs, vec![d(0x12), d(0xc2)]);
        assert_eq!(out.kept_blobs, vec![d(0x10)]);
        assert!(t.manifests().all(|(m, _)| *m != mb));
        assert!(!present(&d(0xc2)) && !present(&d(0x12)));
        assert!(present(&d(0x10)));
    }
    let _ = fs::remove_dir_all(&root);
}

/// OCI-7（TASK-183.4）: `ImageStore` 経由のタグ付与 → 付け替え → 未登録 digest の NotFound。
#[test]
fn oci7_image_store_tag_flow_through_public_api() {
    let root = test_root::test_root("fc-oci-it-tag", "tag");
    let mut t = ReferenceTable::new();
    for (m, c, l) in [(0xa0, 0xc1, 0x10), (0xb0, 0xc2, 0x11)] {
        t.register_manifest(
            d(m),
            ManifestComposition::new(d(c), vec![d(l)]).expect("comp"),
        )
        .expect("register");
    }
    let store = ImageStore::with_table(&root, t).expect("open");

    let added = store
        .tag_image(&ImageTagSource::Manifest(d(0xa0)), tag("v1"))
        .expect("add");
    assert_eq!(added.change, ImageTagChange::Added);
    let moved = store
        .tag_image(&ImageTagSource::Manifest(d(0xb0)), tag("v1"))
        .expect("move");
    assert_eq!(moved.change, ImageTagChange::Moved { from: d(0xa0) });
    let missing = store
        .tag_image(&ImageTagSource::Manifest(d(0xee)), tag("v2"))
        .unwrap_err();
    assert_eq!(missing.code(), OciErrorCode::NotFound);
    let g = store.lock().expect("lock");
    assert_eq!(g.manifest_references(&d(0xb0)).tags, vec![tag("v1")]);
    assert_eq!(g.tags().count(), 1);
    drop(g);
    std::fs::remove_dir_all(&root).expect("cleanup");
}
