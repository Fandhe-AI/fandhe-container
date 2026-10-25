//! `image prune` の本体（OCI-7・TASK-183.7・MS-4・#476）。
//!
//! どのタグからも、どのコンテナ（実行中・停止中を問わない）からも参照されていないイメージ（manifest）と、
//! それだけが使っていたレイヤー・config の blob を回収する。判定の正の情報源は [`ReferenceTable`] だけで、
//! `StateStore` は使わない。テーブルはコンテナの状態を持たないため、コンテナ参照が 1 件でもあれば
//! 状態を区別せず保護する（fail-closed）。停止中コンテナが参照するイメージは `start` に必要なため残る。
//!
//! 呼び出し文脈: 呼び出し側が `ImageStoreGuard`（#473）を保持したまま、ガードの `DerefMut` 越しに呼ぶ。
//! 本モジュールは排他をかけない（`remove` / `usage` と同じ契約）。判定はその排他区間の内側で数え直す。
//!
//! 候補の定義（`usage` の `reclaimable_bytes` と一致する）:
//! 1. 削除する manifest = タグもコンテナ参照も 0 件の manifest（pull リースは blob だけを守る）。
//! 2. 削除する blob = 上記 manifest の構成 blob のうち、残る manifest の構成にも pull リースにも入っていないもの。
//!    共有とリースの両方に当たる blob は `kept_shared_blobs` に分類する。
//!
//! 実行順序: 削除ジャーナル（`gc_journal`。#851）を永続化し、テーブルから manifest を外し、blob ファイルを
//! 消し、`blobs/sha256` を fsync してジャーナルを削除する。途中で失敗・クラッシュしてもファイルが
//! 余分に残る側にだけ誤り、次の `ImageStore::lock` が参照を数え直して削除をやり直す。失敗した blob があっても全体は失敗させず `undeleted_blobs` に載せる。
//! `blobs` / `blobs/sha256` が symlink・非ディレクトリなら何も変えず `FailedPrecondition`。
//! blob は `symlink_metadata` で調べ、通常ファイルだけを消す（symlink は辿らず触らない）。
//!
//! 永続化（#2380）: manifest の除去は、blob を消す前に `@image-inventory.json` へ保存する
//! （`inventory_persist`）。保存に失敗したらテーブルを戻し、書いたジャーナルを片づけて、blob を 1 つも
//! 消さずにエラーを返す。
//!
//! 未実装（実装済みを装わない。REPAIR-3）: CLI 配線、どの構成にも入っていない
//! 未登録 blob の回収（pull の書き込み途中のファイルかもしれないため消さない）。

use std::collections::BTreeSet;
use std::path::Path;

use super::ReferenceTable;
use super::gc_journal::{
    DeletionDurability, GcJournal, ensure_no_pending_journal, remove_journal, settle, sweep_blobs,
    write_journal,
};
use crate::error::{OciError, OciErrorCode};
use crate::instrument::{NoopOciOpRecorder, OciOpKind, OciOpRecorder, record_oci_op};
use crate::reference::Digest;

/// `plan_image_prune` の結果（副作用なし）。各 `Vec` は digest の昇順。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct ImagePrunePlan {
    /// 削除する manifest（無参照）。
    pub manifests: Vec<Digest>,
    /// 削除する blob。
    pub delete_blobs: Vec<Digest>,
    /// 残る manifest が使うため残す blob。
    pub kept_shared_blobs: Vec<Digest>,
    /// pull リースがあるため残す blob（共有でないもの）。
    pub kept_leased_blobs: Vec<Digest>,
}

/// `execute_image_prune` の結果。各 `Vec` は digest の昇順。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct ImagePruneOutcome {
    /// テーブルから外した manifest。
    pub removed_manifests: Vec<Digest>,
    /// ディスクから消した blob。
    pub deleted_blobs: Vec<Digest>,
    /// 削除対象だったがファイルが無かった blob。
    pub absent_blobs: Vec<Digest>,
    /// 残る manifest が使うため残した blob。
    pub kept_shared_blobs: Vec<Digest>,
    /// pull リースがあるため残した blob。
    pub kept_leased_blobs: Vec<Digest>,
    /// 削除できなかった blob（通常ファイルでない・削除失敗）。ファイルは残っている。
    pub undeleted_blobs: Vec<Digest>,
    /// 消した blob ファイルの合計バイト数。
    pub reclaimed_bytes: u64,
    /// 削除の永続化の状態（消す blob があってジャーナルを使ったときだけ `Confirmed` / `Pending` / `Unconfirmed`（fsync 不可の環境）。#851）。
    pub durability: DeletionDurability,
}

fn err(code: OciErrorCode, msg: &str) -> OciError {
    OciError::new(code, msg)
}

impl ReferenceTable {
    /// `image prune` の計画を作る。副作用は無い。排他の内側で呼ぶこと。
    pub fn plan_image_prune(&self) -> ImagePrunePlan {
        let mut manifests: Vec<Digest> = Vec::new();
        let mut candidates: BTreeSet<&Digest> = BTreeSet::new();
        let mut live: BTreeSet<&Digest> = BTreeSet::new();
        for (digest, comp) in self.manifests() {
            if self.manifest_references(digest).is_referenced() {
                live.extend(comp.blobs());
            } else {
                manifests.push(digest.clone());
                candidates.extend(comp.blobs());
            }
        }
        let mut plan = ImagePrunePlan {
            manifests,
            ..ImagePrunePlan::default()
        };
        // 構成が分からない参照（在庫に無い manifest）がある間は、blob を 1 つも削除計画へ入れない（#2341）。
        let unresolved = self.has_unresolved_container_refs();
        for blob in candidates {
            if live.contains(blob) || unresolved {
                plan.kept_shared_blobs.push(blob.clone());
            } else if self.pull_leases.contains_key(blob) {
                plan.kept_leased_blobs.push(blob.clone());
            } else {
                plan.delete_blobs.push(blob.clone());
            }
        }
        plan
    }

    /// `image prune` を実行する。排他の内側（`ImageStoreGuard` 越し）で呼ぶこと。
    ///
    /// `blobs` / `blobs/sha256` が symlink・非ディレクトリなら何も変えず `FailedPrecondition`。
    pub fn execute_image_prune(&mut self, root: &Path) -> Result<ImagePruneOutcome, OciError> {
        self.execute_image_prune_with(&NoopOciOpRecorder, root)
    }

    /// 計装つきの `execute_image_prune`（エラー終了も含め結果と所要時間を記録する。REPAIR-4）。
    pub fn execute_image_prune_with(
        &mut self,
        recorder: &dyn OciOpRecorder,
        root: &Path,
    ) -> Result<ImagePruneOutcome, OciError> {
        record_oci_op(recorder, OciOpKind::PruneImages, || {
            self.execute_image_prune_inner(root)
        })
    }

    fn execute_image_prune_inner(&mut self, root: &Path) -> Result<ImagePruneOutcome, OciError> {
        // 以降の永続化操作（ジャーナル・blob の削除）は、排他区間で検査済みの root の fd を起点にする（#2638）。
        let handle = self.root_handle_for(root)?;
        let root = &*handle;
        // 未完了のテーブル操作が残る間は prune を始めない（OCI-7）。
        self.ensure_no_pending_deletion()?;
        // 片づいていない削除が残っているうちは新しい削除を始めない（lock 時の再試行が先に片づける）。
        ensure_no_pending_journal(root)?;
        // テーブルもファイルも触る前にディレクトリ構成を検証する。
        let dirs_present = root.check_blob_dirs()?;
        let plan = self.plan_image_prune();
        // テーブルを変える前に削除の意図を永続化する。書けなければ何も変えずに返す（削除前に収束）。
        let journaled = dirs_present && !plan.delete_blobs.is_empty();
        if journaled {
            write_journal(
                root,
                &GcJournal {
                    manifests: plan.manifests.clone(),
                    untag: Vec::new(),
                    delete_blobs: plan.delete_blobs.clone(),
                    attempts: 0,
                },
            )?;
        }
        let before = self.inventory_portion();
        for digest in &plan.manifests {
            // 区間内で数え直した直後なので失敗しない想定。panic は Mutex を毒化させるため Result で返す。
            if self.remove_manifest_unchecked(digest).is_err() {
                self.restore_inventory_portion(before);
                if journaled {
                    let _ = remove_journal(root);
                }
                return Err(err(OciErrorCode::Internal, "failed to remove manifest"));
            }
        }
        // manifest の除去は、blob を消す前に保存する。失敗したら戻し、ジャーナルを片づけて blob を消さずに
        // 失敗する（#2380・OCI-7）。
        if let Err(e) = self.persist_inventory(before) {
            if journaled {
                let _ = remove_journal(root);
            }
            return Err(e);
        }
        let mut out = ImagePruneOutcome {
            removed_manifests: plan.manifests,
            kept_shared_blobs: plan.kept_shared_blobs,
            kept_leased_blobs: plan.kept_leased_blobs,
            ..ImagePruneOutcome::default()
        };
        let sweep = sweep_blobs(root, &plan.delete_blobs, dirs_present);
        for (_, n) in &sweep.deleted {
            out.reclaimed_bytes = out
                .reclaimed_bytes
                .checked_add(*n)
                .ok_or_else(|| err(OciErrorCode::Internal, "size overflow"))?;
        }
        if journaled {
            out.durability = settle(
                root,
                &sweep.undeleted,
                &sweep
                    .deleted
                    .iter()
                    .map(|(d, _)| d.clone())
                    .collect::<Vec<_>>(),
                0,
                false,
            );
        }
        out.deleted_blobs = sweep.deleted.into_iter().map(|(d, _)| d).collect();
        out.absent_blobs = sweep.absent;
        out.undeleted_blobs = sweep.undeleted;
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::image_management::usage::blob_path;
    use crate::image_management::{ContainerRefId, ManifestComposition, PullId, TagKey};
    use crate::instrument::OciOpOutcome;
    use crate::reference::{RegistryHost, Repository, Tag};
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static SEQ: AtomicUsize = AtomicUsize::new(0);

    fn d(n: u8) -> Digest {
        Digest::parse(&format!("sha256:{}", format!("{n:02x}").repeat(32))).unwrap()
    }
    fn tk(t: &str) -> TagKey {
        TagKey::new(
            RegistryHost::parse("registry.example").unwrap(),
            Repository::parse("lib/app").unwrap(),
            Tag::parse(t).unwrap(),
        )
    }

    struct Root(PathBuf);
    impl Root {
        fn new() -> Self {
            let n = SEQ.fetch_add(1, Ordering::SeqCst);
            let p = std::env::temp_dir().join(format!("fc-oci-prune-{}-{n}", std::process::id()));
            let _ = fs::remove_dir_all(&p);
            fs::create_dir_all(p.join("blobs").join("sha256")).unwrap();
            Root(p)
        }
        fn put(&self, dg: &Digest, len: usize) {
            fs::write(blob_path(&self.0, dg).unwrap(), vec![0u8; len]).unwrap();
        }
        fn exists(&self, dg: &Digest) -> bool {
            fs::symlink_metadata(blob_path(&self.0, dg).unwrap()).is_ok()
        }
    }
    impl Drop for Root {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    // A=0xa0 (config 0xc1=10, layers 0x10=100, 0x11=1000), B=0xb0 (config 0xc2=20, layers 0x10, 0x12=2000)
    fn fixture(root: &Root) -> ReferenceTable {
        let mut t = ReferenceTable::new();
        t.register_manifest(
            d(0xa0),
            ManifestComposition::new(d(0xc1), vec![d(0x10), d(0x11)]).unwrap(),
        )
        .unwrap();
        t.register_manifest(
            d(0xb0),
            ManifestComposition::new(d(0xc2), vec![d(0x10), d(0x12)]).unwrap(),
        )
        .unwrap();
        for (n, len) in [
            (0xc1, 10),
            (0x10, 100),
            (0x11, 1000),
            (0xc2, 20),
            (0x12, 2000),
        ] {
            root.put(&d(n), len);
        }
        t
    }

    #[derive(Debug, Default)]
    struct Collect(std::sync::Mutex<Vec<crate::instrument::OciOpSample>>);
    impl OciOpRecorder for Collect {
        fn record_oci_op(&self, s: &crate::instrument::OciOpSample) {
            self.0.lock().unwrap().push(*s);
        }
    }

    /// 受け入れ条件 1: タグ無しでも停止中コンテナが参照するイメージは構成 blob ごと残る。
    #[test]
    fn oci7_prune_keeps_untagged_image_referenced_by_stopped_container() {
        let root = Root::new();
        let mut t = fixture(&root);
        t.register_container(ContainerRefId::new("c1").unwrap(), &d(0xa0))
            .unwrap();
        let out = t.execute_image_prune(&root.0).unwrap();
        assert_eq!(out.removed_manifests, vec![d(0xb0)]);
        assert_eq!(
            t.manifests().map(|(x, _)| x.clone()).collect::<Vec<_>>(),
            vec![d(0xa0)]
        );
        for n in [0xc1, 0x10, 0x11] {
            assert!(root.exists(&d(n)));
        }
        assert_eq!(out.kept_shared_blobs, vec![d(0x10)]);
        assert_eq!(out.deleted_blobs, vec![d(0x12), d(0xc2)]);
    }

    /// 受け入れ条件 2: 共有レイヤーは参照元が 1 つでも残れば残る。
    #[test]
    fn oci7_prune_keeps_shared_layer_while_one_referrer_remains() {
        let root = Root::new();
        let mut t = fixture(&root);
        t.register_tag(tk("v1"), &d(0xb0)).unwrap();
        let out = t.execute_image_prune(&root.0).unwrap();
        assert_eq!(out.removed_manifests, vec![d(0xa0)]);
        assert_eq!(out.kept_shared_blobs, vec![d(0x10)]);
        assert_eq!(out.deleted_blobs, vec![d(0x11), d(0xc1)]);
        assert!(root.exists(&d(0x10)));
        assert!(!root.exists(&d(0xc1)));
        assert!(!root.exists(&d(0x11)));
    }

    /// 受け入れ条件 3: 無参照のイメージとレイヤーはディスクから消える。
    #[test]
    fn oci7_prune_deletes_unreferenced_images_and_layers() {
        let root = Root::new();
        let mut t = fixture(&root);
        let out = t.execute_image_prune(&root.0).unwrap();
        assert_eq!(out.removed_manifests, vec![d(0xa0), d(0xb0)]);
        assert_eq!(out.deleted_blobs.len(), 5);
        assert_eq!(out.reclaimed_bytes, 10 + 100 + 1000 + 20 + 2000);
        assert_eq!(t.manifests().count(), 0);
        for n in [0xc1, 0x10, 0x11, 0xc2, 0x12] {
            assert!(!root.exists(&d(n)));
        }
    }

    /// `system df` の reclaimable と一致し、prune 後は 0 になる。
    #[test]
    fn oci7_prune_reclaimed_matches_disk_usage_reclaimable() {
        let root = Root::new();
        let mut t = fixture(&root);
        t.register_tag(tk("v1"), &d(0xb0)).unwrap();
        let before = t.disk_usage(&root.0).unwrap();
        let out = t.execute_image_prune(&root.0).unwrap();
        let after = t.disk_usage(&root.0).unwrap();
        assert_eq!(before.images.reclaimable_bytes, 1010);
        assert_eq!(out.reclaimed_bytes, before.images.reclaimable_bytes);
        assert_eq!(after.images.reclaimable_bytes, 0);
        assert_eq!(after.images.bytes, before.images.bytes - 1010);
    }

    #[test]
    fn oci7_prune_keeps_leased_blob() {
        let root = Root::new();
        let mut t = fixture(&root);
        t.acquire_lease(d(0x11), PullId::new("p1").unwrap())
            .unwrap();
        let out = t.execute_image_prune(&root.0).unwrap();
        assert_eq!(out.kept_leased_blobs, vec![d(0x11)]);
        assert!(root.exists(&d(0x11)));
        assert!(!out.deleted_blobs.contains(&d(0x11)));
        assert_eq!(t.manifests().count(), 0);
    }

    #[test]
    fn oci7_prune_keeps_tagged_image() {
        let root = Root::new();
        let mut t = fixture(&root);
        t.register_tag(tk("v1"), &d(0xa0)).unwrap();
        t.register_tag(tk("v2"), &d(0xb0)).unwrap();
        let out = t.execute_image_prune(&root.0).unwrap();
        assert!(out.removed_manifests.is_empty());
        assert_eq!(t.manifests().count(), 2);
    }

    #[test]
    fn oci7_prune_noop_when_nothing_dangling() {
        let root = Root::new();
        let mut t = fixture(&root);
        t.register_tag(tk("v1"), &d(0xa0)).unwrap();
        t.register_tag(tk("v2"), &d(0xb0)).unwrap();
        let snapshot = t.clone();
        let out = t.execute_image_prune(&root.0).unwrap();
        assert_eq!(t, snapshot);
        assert_eq!(out.reclaimed_bytes, 0);
        assert!(out.deleted_blobs.is_empty());
        assert!(root.exists(&d(0x12)));
    }

    #[test]
    fn oci7_prune_is_idempotent() {
        let root = Root::new();
        let mut t = fixture(&root);
        t.execute_image_prune(&root.0).unwrap();
        let out = t.execute_image_prune(&root.0).unwrap();
        assert_eq!(out, ImagePruneOutcome::default());
    }

    #[test]
    fn oci7_prune_missing_blob_file_is_absent() {
        let root = Root::new();
        let mut t = fixture(&root);
        fs::remove_file(blob_path(&root.0, &d(0x11)).unwrap()).unwrap();
        let out = t.execute_image_prune(&root.0).unwrap();
        assert_eq!(out.absent_blobs, vec![d(0x11)]);
        assert_eq!(out.reclaimed_bytes, 10 + 100 + 20 + 2000);
    }

    #[cfg(unix)]
    #[test]
    fn oci7_prune_symlinked_blob_dir_changes_nothing() {
        let root = Root::new();
        let mut t = fixture(&root);
        let real = root.0.join("real");
        fs::rename(root.0.join("blobs").join("sha256"), &real).unwrap();
        std::os::unix::fs::symlink(&real, root.0.join("blobs").join("sha256")).unwrap();
        let snapshot = t.clone();
        let e = t.execute_image_prune(&root.0).unwrap_err();
        assert_eq!(e.code(), OciErrorCode::FailedPrecondition);
        assert_eq!(t, snapshot);
        assert!(real.join("c1".repeat(32)).exists());
    }

    #[cfg(unix)]
    #[test]
    fn oci7_prune_does_not_follow_symlink_blob() {
        let root = Root::new();
        let mut t = fixture(&root);
        let target = root.0.join("target");
        fs::write(&target, b"keep").unwrap();
        let p = blob_path(&root.0, &d(0x11)).unwrap();
        fs::remove_file(&p).unwrap();
        std::os::unix::fs::symlink(&target, &p).unwrap();
        let out = t.execute_image_prune(&root.0).unwrap();
        assert_eq!(out.undeleted_blobs, vec![d(0x11)]);
        assert!(target.exists());
        assert!(fs::symlink_metadata(&p).is_ok());
    }

    #[test]
    fn oci7_prune_leaves_unregistered_cache_blobs() {
        let root = Root::new();
        let mut t = fixture(&root);
        root.put(&d(0x99), 7);
        t.execute_image_prune(&root.0).unwrap();
        assert!(root.exists(&d(0x99)));
    }

    #[test]
    fn oci7_prune_without_blob_dir_removes_manifests_only() {
        let root = Root::new();
        let mut t = fixture(&root);
        fs::remove_dir_all(root.0.join("blobs")).unwrap();
        let out = t.execute_image_prune(&root.0).unwrap();
        assert_eq!(out.removed_manifests.len(), 2);
        assert_eq!(out.absent_blobs.len(), 5);
        assert_eq!(out.reclaimed_bytes, 0);
    }

    /// REPAIR-4: 成功・失敗の両方を 1 件ずつ記録する。
    #[test]
    fn repair4_prune_outcome_is_recorded() {
        let root = Root::new();
        let mut t = fixture(&root);
        let rec = Collect::default();
        t.execute_image_prune_with(&rec, &root.0).unwrap();
        fs::remove_dir_all(root.0.join("blobs")).unwrap();
        fs::write(root.0.join("blobs"), b"x").unwrap();
        t.execute_image_prune_with(&rec, &root.0).unwrap_err();
        let v = rec.0.lock().unwrap();
        let got: Vec<_> = v
            .iter()
            .map(|s| (s.kind(), s.outcome(), s.error_code()))
            .collect();
        assert_eq!(
            got,
            vec![
                (OciOpKind::PruneImages, OciOpOutcome::Success, None),
                (
                    OciOpKind::PruneImages,
                    OciOpOutcome::Failure,
                    Some(OciErrorCode::FailedPrecondition)
                ),
            ]
        );
    }
}
