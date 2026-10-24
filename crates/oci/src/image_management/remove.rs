//! `image rm` の判定と実行（OCI-7・TASK-183.5/183.6・MS-4・#480・#481）。
//!
//! `image rm` は、タグの有無や指定方法（タグか digest か）に関係なく、コンテナが参照している
//! イメージを既定で削除しない。判定の正の情報源は [`ReferenceTable`] で、`StateStore` は引かない。
//! テーブルはコンテナの状態（実行中・停止中）を持たないため、既定経路（`plan_image_rm` /
//! `check_image_rm`）は状態を区別せず「コンテナ参照が 1 件でもあれば拒否」とする（fail-closed）。
//!
//! `--force`（TASK-183.6・#481）は 2 段構成である。
//! 1. 判定 [`ReferenceTable::plan_image_rm_with`]（`&self`・副作用なし）。呼び出し側（CLI / CRI）が
//!    ストアのガード（`ImageStoreGuard`。#473）を取る前に `StateStore` から読んだ停止中コンテナの
//!    スナップショット [`StoppedContainers`] を値で渡す。参照元のうちスナップショットに無いもの
//!    （実行中・不明・スナップショット後に作られたもの）は、`--force` でもすべて実行中とみなして拒否する。
//! 2. 実行 [`ReferenceTable::execute_image_rm`]（`&mut self`・ディスク操作）。ガードを保持したまま
//!    `DerefMut` 越しに呼ぶ前提で、本モジュールは排他をかけない。
//!
//! 結果は 3 通りである。停止中のコンテナだけが参照するイメージに `--force` を付けるとタグだけを外す
//! （`UntagOnly`。manifest・config・レイヤーは残し、そのコンテナの `start` に要る blob を欠かさない）。
//! 無参照でタグも残らないイメージは `Delete` とし、在庫から manifest を外し、他の manifest と
//! 共有せずリースも無い blob だけを消す。
//!
//! 競合: スナップショットの後にガードを取るまでの間に停止中のコンテナが起動しても、untag 経路は blob を
//! 消さないのでデータを失わない。完全削除はガードの下でコンテナ参照が 0 件のときに限る。
//!
//! 完全削除の順序は「削除ジャーナルの永続化 → テーブル更新 → ファイル削除 → fsync → ジャーナル削除」
//! （`gc_journal`。#851）。途中で失敗・クラッシュしてもファイルが余分に残る側にだけ倒れ、次の
//! `ImageStore::lock` が参照を数え直して削除をやり直す。
//! manifest 本文はディスクに保存していない（config と layer の blob だけ）ため、manifest の削除は
//! 在庫（テーブル）から外すことを指す。
//!
//! 永続化（#2380）: untag と manifest 除去は、blob を消す前に `@image-inventory.json` へ保存する
//! （`inventory_persist`）。保存に失敗したらテーブルを戻し、書いたジャーナルを片づけて、blob を 1 つも
//! 消さずにエラーを返す。
//!
//! 未実装（実装済みを装わない。REPAIR-3）: CLI の `image rm [--force]` 配線と `StateStore` からの
//! スナップショット作成（#853 以降）。
//!
//! Docker の `rmi <tag>` はタグが複数あるイメージなら untag して成功するが、既定経路は OCI-7 に従い
//! コンテナ参照があれば拒否する。pull リースは blob を守るもので manifest は守らないため、判定には
//! 含めず、blob の削除時にだけ考慮する。

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::Path;

use super::gc_journal::{
    DeletionDurability, GcJournal, ensure_no_pending_journal, remove_journal, settle, sweep_blobs,
    write_journal,
};
use super::{ContainerRefId, ReferenceTable, TagKey};
use crate::error::{OciError, OciErrorCode};
use crate::instrument::{NoopOciOpRecorder, OciOpKind, OciOpRecorder, record_oci_op};
use crate::reference::Digest;

/// エラーメッセージ内で container ID の列挙に使えるバイト数の目安（上限 1024 に対し末尾の件数分を残す）。
const MESSAGE_ID_BUDGET_BYTES: usize = 900;

/// `image rm` の対象（検証済みの newtype だけで表す）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImageRmTarget {
    /// タグで指定する。
    Tag(TagKey),
    /// manifest digest で指定する。
    Manifest(Digest),
}

/// 削除候補（無参照と判定されたイメージ）。#481 が untag・実削除に使う。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ImageRmCandidate {
    /// 対象の manifest。
    pub manifest: Digest,
    /// タグで指定された場合のそのタグ。
    pub targeted_tag: Option<TagKey>,
    /// この manifest を指す全タグ（昇順）。
    pub tags: Vec<TagKey>,
}

/// 使用中の情報。メッセージには長さ制限があるため、ID は型で全件を持つ。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ImageInUse {
    /// 対象の manifest。
    pub manifest: Digest,
    /// 参照しているコンテナ（昇順・全件）。
    pub containers: Vec<ContainerRefId>,
}

impl ImageInUse {
    /// `FailedPrecondition` のエラーにする。メッセージ末尾の件数は常に残る。
    pub fn to_error(&self) -> OciError {
        let total = self.containers.len();
        let mut msg = format!("image {} is in use by container(s): ", self.manifest);
        let mut shown = 0usize;
        for id in &self.containers {
            let sep = if shown == 0 { "" } else { ", " };
            let next = msg
                .len()
                .saturating_add(sep.len())
                .saturating_add(id.as_str().len());
            // 先頭の 1 件は必ず載せ、以降は予算内に収まる分だけ載せる。
            if shown > 0 && next > MESSAGE_ID_BUDGET_BYTES {
                break;
            }
            msg.push_str(sep);
            msg.push_str(id.as_str());
            shown += 1;
        }
        if shown < total {
            msg.push_str(", ...");
        }
        // String への write! は失敗しない。
        let _ = write!(msg, " ({total} total)");
        OciError::new(OciErrorCode::FailedPrecondition, msg)
    }
}

/// 既定の判定結果。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ImageRmDecision {
    /// コンテナ参照が無く、削除候補にできる。
    Removable(ImageRmCandidate),
    /// コンテナが参照しており、既定では削除できない。
    InUse(ImageInUse),
}

impl ReferenceTable {
    /// `image rm` の既定の判定（OCI-7）。副作用は無い。#481 の `--force` 判定もここから派生させる。
    ///
    /// 未知のタグ・digest は `NotFound`。
    pub fn plan_image_rm(&self, target: &ImageRmTarget) -> Result<ImageRmDecision, OciError> {
        let (manifest, targeted_tag) = match target {
            ImageRmTarget::Tag(key) => {
                let d = self.tag_refs.get(key).ok_or_else(|| {
                    OciError::new(OciErrorCode::NotFound, format!("tag {key} not found"))
                })?;
                (d.clone(), Some(key.clone()))
            }
            ImageRmTarget::Manifest(d) => {
                if !self.manifests.contains_key(d) {
                    return Err(OciError::new(
                        OciErrorCode::NotFound,
                        format!("image {d} not found"),
                    ));
                }
                (d.clone(), None)
            }
        };
        let refs = self.manifest_references(&manifest);
        if refs.containers.is_empty() {
            Ok(ImageRmDecision::Removable(ImageRmCandidate {
                manifest,
                targeted_tag,
                tags: refs.tags,
            }))
        } else {
            Ok(ImageRmDecision::InUse(ImageInUse {
                manifest,
                containers: refs.containers,
            }))
        }
    }

    /// 既定経路: 使用中なら `FailedPrecondition` で拒否し、無参照なら削除候補を返す。
    pub fn check_image_rm(&self, target: &ImageRmTarget) -> Result<ImageRmCandidate, OciError> {
        match self.plan_image_rm(target)? {
            ImageRmDecision::Removable(c) => Ok(c),
            ImageRmDecision::InUse(u) => Err(u.to_error()),
        }
    }
}

/// 停止中と確認できたコンテナの集合（呼び出し側が `StateStore` から作るスナップショット）。
///
/// 集合に無いコンテナは実行中とみなす（fail-closed）。oci は core に依存しないため、状態は値で受け取る。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StoppedContainers(BTreeSet<ContainerRefId>);

impl StoppedContainers {
    /// 空の集合（全コンテナを実行中とみなす）。
    pub fn new() -> Self {
        Self::default()
    }

    /// 停止中と確認できたコンテナを加える。
    pub fn insert(&mut self, id: ContainerRefId) {
        self.0.insert(id);
    }

    /// 停止中と確認されているか。
    pub fn contains(&self, id: &ContainerRefId) -> bool {
        self.0.contains(id)
    }
}

impl FromIterator<ContainerRefId> for StoppedContainers {
    fn from_iter<I: IntoIterator<Item = ContainerRefId>>(iter: I) -> Self {
        Self(iter.into_iter().collect())
    }
}

/// `image rm` のオプション。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct ImageRmOptions {
    /// 停止中のコンテナだけが参照するイメージを untag だけで通す（`--force`）。
    pub force: bool,
}

impl ImageRmOptions {
    /// `--force` を付けたオプション。
    pub fn force() -> Self {
        Self { force: true }
    }
}

/// 実行する内容（外す対象のタグと対象 manifest）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ImageRmAction {
    /// 対象の manifest。
    pub manifest: Digest,
    /// 外すタグ（昇順）。
    pub untag: Vec<TagKey>,
}

/// `--force` を含む判定結果。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ImageRmPlan {
    /// 削除できない（実行中・不明なコンテナ、または force なしの停止中コンテナの参照）。
    Refuse(ImageInUse),
    /// タグだけを外す。manifest・config・レイヤーは残す。
    UntagOnly(ImageRmAction),
    /// 全タグを外し、manifest を在庫から外し、非共有の blob を削除する。
    Delete(ImageRmAction),
}

/// 実行結果の種別。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ImageRmKind {
    /// タグだけを外した。
    UntagOnly,
    /// manifest を在庫から外し、blob を削除した。
    Deleted,
}

/// 実行結果。配列はいずれも昇順で決定的。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ImageRmOutcome {
    /// 対象の manifest。
    pub manifest: Digest,
    /// 実行の種別。
    pub kind: ImageRmKind,
    /// 外したタグ。
    pub untagged: Vec<TagKey>,
    /// 削除した blob。
    pub deleted_blobs: Vec<Digest>,
    /// 既に無かった blob。
    pub absent_blobs: Vec<Digest>,
    /// 他の manifest またはリースが守るため残した blob。
    pub kept_blobs: Vec<Digest>,
    /// 通常ファイルでない・削除に失敗したため残した blob（削除ジャーナルに残り、次の lock の再試行〔#851〕で回収する）。
    pub undeleted_blobs: Vec<Digest>,
    /// 削除の永続化の状態（完全削除でジャーナルを使ったときだけ `Confirmed` / `Pending` / `Unconfirmed`（fsync 不可の環境）。#851）。
    pub durability: DeletionDurability,
}

fn internal(msg: &str) -> OciError {
    OciError::new(OciErrorCode::Internal, msg)
}

impl ReferenceTable {
    /// `--force` を含む `image rm` の判定（OCI-7・TASK-183.6）。副作用は無い。
    ///
    /// 参照元のうち `stopped` に無いコンテナは実行中とみなして拒否する（`force` でも同じ）。
    /// 未知のタグ・digest は `NotFound`。
    pub fn plan_image_rm_with(
        &self,
        target: &ImageRmTarget,
        opts: &ImageRmOptions,
        stopped: &StoppedContainers,
    ) -> Result<ImageRmPlan, OciError> {
        let (manifest, tags, containers) = match self.plan_image_rm(target)? {
            ImageRmDecision::Removable(c) => (c.manifest, c.tags, Vec::new()),
            ImageRmDecision::InUse(u) => {
                let tags = self.manifest_references(&u.manifest).tags;
                (u.manifest, tags, u.containers)
            }
        };
        if !containers.is_empty() {
            let running: Vec<ContainerRefId> = containers
                .iter()
                .filter(|c| !stopped.contains(c))
                .cloned()
                .collect();
            if !running.is_empty() {
                return Ok(ImageRmPlan::Refuse(ImageInUse {
                    manifest,
                    containers: running,
                }));
            }
            if !opts.force {
                return Ok(ImageRmPlan::Refuse(ImageInUse {
                    manifest,
                    containers,
                }));
            }
            let untag = match target {
                ImageRmTarget::Tag(k) => vec![k.clone()],
                ImageRmTarget::Manifest(_) => tags,
            };
            return Ok(ImageRmPlan::UntagOnly(ImageRmAction { manifest, untag }));
        }
        match target {
            ImageRmTarget::Tag(k) if tags.len() > 1 => Ok(ImageRmPlan::UntagOnly(ImageRmAction {
                manifest,
                untag: vec![k.clone()],
            })),
            _ => Ok(ImageRmPlan::Delete(ImageRmAction {
                manifest,
                untag: tags,
            })),
        }
    }

    /// `image rm` の実行（計装なし）。契約は [`Self::execute_image_rm_with`]。
    pub fn execute_image_rm(
        &mut self,
        root: &Path,
        target: &ImageRmTarget,
        opts: &ImageRmOptions,
        stopped: &StoppedContainers,
    ) -> Result<ImageRmOutcome, OciError> {
        self.execute_image_rm_with(&NoopOciOpRecorder, root, target, opts, stopped)
    }

    /// 計装つきの `image rm` の実行（REPAIR-4）。
    ///
    /// ストアのガードを保持したまま呼ぶ前提（排他はかけない）。拒否のときはテーブルもディスクも変えない。
    /// 完全削除は、`blobs` / `blobs/sha256` が symlink・非ディレクトリなら何も変えずに
    /// `FailedPrecondition` とする。blob のファイル削除の失敗はエラーにせず `undeleted_blobs` に載せる
    /// （テーブルは更新済みで、`Err` は「何も起きていない」と誤読させるため）。
    pub fn execute_image_rm_with(
        &mut self,
        recorder: &dyn OciOpRecorder,
        root: &Path,
        target: &ImageRmTarget,
        opts: &ImageRmOptions,
        stopped: &StoppedContainers,
    ) -> Result<ImageRmOutcome, OciError> {
        record_oci_op(recorder, OciOpKind::RemoveImage, || {
            self.execute_image_rm_inner(root, target, opts, stopped)
        })
    }

    fn execute_image_rm_inner(
        &mut self,
        root: &Path,
        target: &ImageRmTarget,
        opts: &ImageRmOptions,
        stopped: &StoppedContainers,
    ) -> Result<ImageRmOutcome, OciError> {
        // 以降の永続化操作（ジャーナル・blob の削除）は、排他区間で検査済みの root の fd を起点にする（#2638）。
        let handle = self.root_handle_for(root)?;
        let root = &*handle;
        // 未完了のテーブル操作が残る間は rm を始めない（OCI-7）。
        self.ensure_no_pending_deletion()?;
        let (action, delete) = match self.plan_image_rm_with(target, opts, stopped)? {
            ImageRmPlan::Refuse(u) => return Err(u.to_error()),
            ImageRmPlan::UntagOnly(a) => (a, false),
            ImageRmPlan::Delete(a) => (a, true),
        };
        if delete {
            // 片づいていない削除が残っているうちは新しい削除を始めない（lock 時の再試行が先に片づける）。
            ensure_no_pending_journal(root)?;
        }
        // テーブルを変える前にディレクトリを検証する（symlink なら何も変えない）。
        let dirs_present = if delete {
            root.check_blob_dirs()?
        } else {
            false
        };
        // テーブルを変える前に削除の意図を永続化する。書けなければ何も変えずに返す（削除前に収束）。
        let planned = if delete && dirs_present {
            self.blobs_deletable_after_removal(&action.manifest)
        } else {
            Vec::new()
        };
        let journaled = !planned.is_empty();
        if journaled {
            write_journal(
                root,
                &GcJournal {
                    manifests: vec![action.manifest.clone()],
                    untag: action
                        .untag
                        .iter()
                        .map(|k| (k.clone(), action.manifest.clone()))
                        .collect(),
                    delete_blobs: planned,
                    attempts: 0,
                },
            )?;
        }
        // untag と manifest 除去は、blob を消す前に 1 回だけ保存する（#2380）。
        let before = self.inventory_portion();
        for key in &action.untag {
            if self.unregister_tag_unchecked(key).is_err() {
                self.restore_inventory_portion(before);
                if journaled {
                    let _ = remove_journal(root);
                }
                return Err(internal("planned tag vanished during image removal"));
            }
        }
        let mut outcome = ImageRmOutcome {
            manifest: action.manifest.clone(),
            kind: ImageRmKind::UntagOnly,
            untagged: action.untag,
            deleted_blobs: Vec::new(),
            absent_blobs: Vec::new(),
            kept_blobs: Vec::new(),
            undeleted_blobs: Vec::new(),
            durability: DeletionDurability::NotApplicable,
        };
        if !delete {
            // untag のみ。保存に失敗したらテーブルを戻してエラー（blob には触れていない）。
            self.persist_inventory(before)?;
            return Ok(outcome);
        }
        let composition = match self.remove_manifest_unchecked(&action.manifest) {
            Ok(c) => c,
            Err(e) => {
                self.restore_inventory_portion(before);
                if journaled {
                    let _ = remove_journal(root);
                }
                return Err(e);
            }
        };
        // 保存に失敗したら戻し、ジャーナルを片づけて blob を 1 つも消さずに失敗する（#2380・OCI-7）。
        if let Err(e) = self.persist_inventory(before) {
            if journaled {
                let _ = remove_journal(root);
            }
            return Err(e);
        }
        outcome.kind = ImageRmKind::Deleted;
        let mut to_sweep = Vec::new();
        // blobs() は BTreeSet のため昇順で決定的。
        // 構成が分からない参照（在庫に無い manifest）がある間は blob を消さない（#2341）。
        let unresolved = self.has_unresolved_container_refs();
        for blob in composition.blobs() {
            let refs = self.blob_references(blob);
            if unresolved || !refs.referencing_manifests.is_empty() || !refs.leases.is_empty() {
                outcome.kept_blobs.push(blob.clone());
            } else {
                to_sweep.push(blob.clone());
            }
        }
        let sweep = sweep_blobs(root, &to_sweep, dirs_present);
        if journaled {
            outcome.durability = settle(
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
        outcome.deleted_blobs = sweep.deleted.into_iter().map(|(d, _)| d).collect();
        outcome.absent_blobs = sweep.absent;
        outcome.undeleted_blobs = sweep.undeleted;
        Ok(outcome)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::image_management::ManifestComposition;
    use crate::image_management::usage::blob_path;
    use crate::reference::{RegistryHost, Repository, Tag};
    use std::fs;

    fn d(n: u8) -> Digest {
        Digest::parse(&format!("sha256:{}", format!("{n:02x}").repeat(32))).unwrap()
    }
    fn cid(s: &str) -> ContainerRefId {
        ContainerRefId::new(s).unwrap()
    }
    fn tk(t: &str) -> TagKey {
        TagKey::new(
            RegistryHost::parse("registry.example").unwrap(),
            Repository::parse("lib/app").unwrap(),
            Tag::parse(t).unwrap(),
        )
    }
    fn table() -> ReferenceTable {
        let mut t = ReferenceTable::new();
        for n in [0xa0, 0xb0] {
            t.register_manifest(
                d(n),
                ManifestComposition::new(d(n + 1), vec![d(0x10)]).unwrap(),
            )
            .unwrap();
        }
        t
    }

    /// 実行中コンテナ相当の参照（テーブルは状態を区別しない）で拒否され、ID がメッセージに入る。
    #[test]
    fn oci7_rm_rejects_image_used_by_running_container() {
        let mut t = table();
        t.register_tag(tk("v1"), &d(0xa0)).unwrap();
        t.register_container(cid("run-1"), &d(0xa0)).unwrap();
        let e = t.check_image_rm(&ImageRmTarget::Tag(tk("v1"))).unwrap_err();
        assert_eq!(e.code(), OciErrorCode::FailedPrecondition);
        assert!(e.message().contains("run-1"), "{}", e.message());
    }

    /// 停止中コンテナ相当の参照でも同様に拒否する。
    #[test]
    fn oci7_rm_rejects_image_used_by_stopped_container() {
        let mut t = table();
        t.register_container(cid("stopped-1"), &d(0xa0)).unwrap();
        let e = t
            .check_image_rm(&ImageRmTarget::Manifest(d(0xa0)))
            .unwrap_err();
        assert_eq!(e.code(), OciErrorCode::FailedPrecondition);
        assert!(e.message().contains("stopped-1"), "{}", e.message());
    }

    #[test]
    fn oci7_rm_rejects_with_all_container_ids_sorted() {
        let mut t = table();
        t.register_container(cid("zeta"), &d(0xa0)).unwrap();
        t.register_container(cid("alpha"), &d(0xa0)).unwrap();
        let ImageRmDecision::InUse(u) = t.plan_image_rm(&ImageRmTarget::Manifest(d(0xa0))).unwrap()
        else {
            panic!("expected InUse");
        };
        assert_eq!(u.containers, vec![cid("alpha"), cid("zeta")]);
        let m = u.to_error().message().to_string();
        assert!(m.contains("alpha, zeta"), "{m}");
        assert!(m.ends_with("(2 total)"), "{m}");
    }

    #[test]
    fn oci7_rm_rejects_by_tag_and_by_digest() {
        let mut t = table();
        t.register_tag(tk("v1"), &d(0xa0)).unwrap();
        t.register_container(cid("c1"), &d(0xa0)).unwrap();
        for target in [
            ImageRmTarget::Tag(tk("v1")),
            ImageRmTarget::Manifest(d(0xa0)),
        ] {
            let e = t.check_image_rm(&target).unwrap_err();
            assert_eq!(e.code(), OciErrorCode::FailedPrecondition);
        }
    }

    #[test]
    fn oci7_rm_rejects_untagged_image_referenced_by_container() {
        let mut t = table();
        t.register_container(cid("c1"), &d(0xb0)).unwrap();
        let e = t
            .check_image_rm(&ImageRmTarget::Manifest(d(0xb0)))
            .unwrap_err();
        assert_eq!(e.code(), OciErrorCode::FailedPrecondition);
        assert!(e.message().contains("c1"));
    }

    #[test]
    fn oci7_rm_unknown_tag_or_manifest_is_not_found() {
        let t = table();
        let e1 = t
            .check_image_rm(&ImageRmTarget::Tag(tk("nope")))
            .unwrap_err();
        let e2 = t
            .check_image_rm(&ImageRmTarget::Manifest(d(0xee)))
            .unwrap_err();
        assert_eq!(e1.code(), OciErrorCode::NotFound);
        assert_eq!(e2.code(), OciErrorCode::NotFound);
    }

    #[test]
    fn oci7_rm_unreferenced_returns_candidate() {
        let mut t = table();
        t.register_tag(tk("v2"), &d(0xa0)).unwrap();
        t.register_tag(tk("v1"), &d(0xa0)).unwrap();
        let c = t.check_image_rm(&ImageRmTarget::Tag(tk("v2"))).unwrap();
        assert_eq!(c.manifest, d(0xa0));
        assert_eq!(c.targeted_tag, Some(tk("v2")));
        assert_eq!(c.tags, vec![tk("v1"), tk("v2")]);
        let c2 = t.check_image_rm(&ImageRmTarget::Manifest(d(0xb0))).unwrap();
        assert_eq!(c2.targeted_tag, None);
        assert!(c2.tags.is_empty());
    }

    #[test]
    fn oci7_rm_message_fits_budget_with_long_ids() {
        let mut t = table();
        for i in 0..10 {
            let id = format!("{i}{}", "x".repeat(254));
            t.register_container(cid(&id), &d(0xa0)).unwrap();
        }
        let e = t
            .check_image_rm(&ImageRmTarget::Manifest(d(0xa0)))
            .unwrap_err();
        let m = e.message();
        assert!(m.len() <= 1024, "{}", m.len());
        assert!(m.contains(&format!("0{}", "x".repeat(254))));
        assert!(m.ends_with("(10 total)"), "{m}");
    }

    #[test]
    fn oci7_rm_check_does_not_mutate_table() {
        let mut t = table();
        t.register_tag(tk("v1"), &d(0xa0)).unwrap();
        t.register_container(cid("c1"), &d(0xa0)).unwrap();
        let before = t.clone();
        let _ = t.check_image_rm(&ImageRmTarget::Tag(tk("v1")));
        let _ = t.check_image_rm(&ImageRmTarget::Manifest(d(0xb0)));
        assert_eq!(t, before);
    }

    // ---- --force・実削除（TASK-183.6・#481） ----

    use crate::image_management::PullId;
    use crate::instrument::{OciOpOutcome, OciOpSample};
    use std::path::PathBuf;

    struct Root(PathBuf);
    impl Root {
        fn new(tag: &str) -> Self {
            let p = std::env::temp_dir().join(format!("fc-oci-rm-{tag}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&p);
            fs::create_dir_all(p.join("blobs").join("sha256")).unwrap();
            Root(p)
        }
        fn put(&self, dg: &Digest) {
            fs::write(blob_path(&self.0, dg).unwrap(), dg.as_str().as_bytes()).unwrap();
        }
        fn exists(&self, dg: &Digest) -> bool {
            fs::symlink_metadata(blob_path(&self.0, dg).unwrap()).is_ok()
        }
        fn files(&self) -> Vec<String> {
            let mut v: Vec<String> = fs::read_dir(self.0.join("blobs").join("sha256"))
                .unwrap()
                .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .collect();
            v.sort();
            v
        }
    }
    impl Drop for Root {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    // A=0xa0 (config 0xc1, layers 0x10 共有, 0x11 専用), B=0xb0 (config 0xc2, layers 0x10, 0x12)
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
        for n in [0xc1, 0x10, 0x11, 0xc2, 0x12] {
            root.put(&d(n));
        }
        t
    }

    fn stopped(ids: &[&str]) -> StoppedContainers {
        ids.iter().map(|s| cid(s)).collect()
    }

    fn force() -> ImageRmOptions {
        ImageRmOptions::force()
    }

    /// 実行中コンテナが参照するイメージは force でも拒否し、テーブルは変わらない。
    #[test]
    fn oci7_force_rejects_running_container() {
        let mut t = table();
        t.register_tag(tk("v1"), &d(0xa0)).unwrap();
        t.register_container(cid("run-1"), &d(0xa0)).unwrap();
        let before = t.clone();
        let target = ImageRmTarget::Tag(tk("v1"));
        let plan = t
            .plan_image_rm_with(&target, &force(), &stopped(&[]))
            .unwrap();
        let ImageRmPlan::Refuse(u) = plan else {
            panic!("expected Refuse");
        };
        assert_eq!(u.containers, vec![cid("run-1")]);
        let e = u.to_error();
        assert_eq!(e.code(), OciErrorCode::FailedPrecondition);
        assert!(e.message().contains("run-1"));
        assert_eq!(t, before);
    }

    /// 実行中と停止中が混在すると force でも拒否し、実行中のものだけを列挙する。
    #[test]
    fn oci7_force_mixed_lists_only_running() {
        let mut t = table();
        t.register_container(cid("run-1"), &d(0xa0)).unwrap();
        t.register_container(cid("stop-1"), &d(0xa0)).unwrap();
        let plan = t
            .plan_image_rm_with(
                &ImageRmTarget::Manifest(d(0xa0)),
                &force(),
                &stopped(&["stop-1"]),
            )
            .unwrap();
        let ImageRmPlan::Refuse(u) = plan else {
            panic!("expected Refuse");
        };
        assert_eq!(u.containers, vec![cid("run-1")]);
    }

    /// スナップショットに無いコンテナは実行中とみなして拒否する（fail-closed）。
    #[test]
    fn oci7_force_unknown_container_is_treated_as_running() {
        let mut t = table();
        t.register_container(cid("new-1"), &d(0xa0)).unwrap();
        let plan = t
            .plan_image_rm_with(
                &ImageRmTarget::Manifest(d(0xa0)),
                &force(),
                &stopped(&["other"]),
            )
            .unwrap();
        assert!(matches!(plan, ImageRmPlan::Refuse(_)));
    }

    /// 停止中だけでも force なしは既定どおり拒否し、全コンテナを列挙する。
    #[test]
    fn oci7_no_force_rejects_stopped_with_all_ids() {
        let mut t = table();
        t.register_container(cid("s2"), &d(0xa0)).unwrap();
        t.register_container(cid("s1"), &d(0xa0)).unwrap();
        let plan = t
            .plan_image_rm_with(
                &ImageRmTarget::Manifest(d(0xa0)),
                &ImageRmOptions::default(),
                &stopped(&["s1", "s2"]),
            )
            .unwrap();
        let ImageRmPlan::Refuse(u) = plan else {
            panic!("expected Refuse");
        };
        assert_eq!(u.containers, vec![cid("s1"), cid("s2")]);
    }

    /// 停止中だけ + force: Tag 指定はそのタグ 1 件、Manifest 指定は全タグを外す。
    #[test]
    fn oci7_force_stopped_only_untags() {
        let mut t = table();
        t.register_tag(tk("v1"), &d(0xa0)).unwrap();
        t.register_tag(tk("v2"), &d(0xa0)).unwrap();
        t.register_container(cid("s1"), &d(0xa0)).unwrap();
        let st = stopped(&["s1"]);
        let p1 = t
            .plan_image_rm_with(&ImageRmTarget::Tag(tk("v1")), &force(), &st)
            .unwrap();
        let ImageRmPlan::UntagOnly(a) = p1 else {
            panic!("expected UntagOnly");
        };
        assert_eq!(a.untag, vec![tk("v1")]);
        let p2 = t
            .plan_image_rm_with(&ImageRmTarget::Manifest(d(0xa0)), &force(), &st)
            .unwrap();
        let ImageRmPlan::UntagOnly(a) = p2 else {
            panic!("expected UntagOnly");
        };
        assert_eq!(a.untag, vec![tk("v1"), tk("v2")]);
    }

    /// 無参照で他のタグが残るなら untag のみ。最後の 1 件なら Delete。
    #[test]
    fn oci7_unreferenced_tag_rm_untags_until_last() {
        let mut t = table();
        t.register_tag(tk("v1"), &d(0xa0)).unwrap();
        t.register_tag(tk("v2"), &d(0xa0)).unwrap();
        let none = StoppedContainers::new();
        let o = ImageRmOptions::default();
        let p = t
            .plan_image_rm_with(&ImageRmTarget::Tag(tk("v1")), &o, &none)
            .unwrap();
        assert!(matches!(p, ImageRmPlan::UntagOnly(_)));
        t.unregister_tag(&tk("v1")).unwrap();
        let p = t
            .plan_image_rm_with(&ImageRmTarget::Tag(tk("v2")), &o, &none)
            .unwrap();
        let ImageRmPlan::Delete(a) = p else {
            panic!("expected Delete");
        };
        assert_eq!(a.untag, vec![tk("v2")]);
    }

    #[test]
    fn oci7_force_unknown_is_not_found() {
        let t = table();
        let st = StoppedContainers::new();
        let e = t
            .plan_image_rm_with(&ImageRmTarget::Tag(tk("nope")), &force(), &st)
            .unwrap_err();
        assert_eq!(e.code(), OciErrorCode::NotFound);
        let e = t
            .plan_image_rm_with(&ImageRmTarget::Manifest(d(0xee)), &force(), &st)
            .unwrap_err();
        assert_eq!(e.code(), OciErrorCode::NotFound);
    }

    /// 受け入れ条件 1: 停止中だけが参照するイメージを force で untag しても、起動に要る blob が揃う。
    #[test]
    fn oci7_force_untag_keeps_all_blobs_for_stopped_container() {
        let root = Root::new("untag");
        let mut t = fixture(&root);
        t.register_tag(tk("v1"), &d(0xa0)).unwrap();
        t.register_container(cid("c1"), &d(0xa0)).unwrap();
        let files_before = root.files();
        let out = t
            .execute_image_rm(
                &root.0,
                &ImageRmTarget::Tag(tk("v1")),
                &force(),
                &stopped(&["c1"]),
            )
            .unwrap();
        assert_eq!(out.kind, ImageRmKind::UntagOnly);
        assert_eq!(out.untagged, vec![tk("v1")]);
        assert!(out.deleted_blobs.is_empty());
        assert_eq!(t.tags().count(), 0);
        assert_eq!(t.manifest_references(&d(0xa0)).containers, vec![cid("c1")]);
        let comp = t.manifests().find(|(m, _)| **m == d(0xa0)).unwrap().1;
        assert_eq!(comp.config(), &d(0xc1));
        assert_eq!(comp.layers(), &[d(0x10), d(0x11)]);
        assert_eq!(root.files(), files_before);
        for n in [0xc1, 0x10, 0x11] {
            assert!(root.exists(&d(n)));
            assert_eq!(
                fs::read(blob_path(&root.0, &d(n)).unwrap()).unwrap(),
                d(n).as_str().as_bytes()
            );
        }
        let list = t.list_images(&root.0).unwrap();
        assert!(list.entries.iter().all(|e| e.missing_blobs.is_empty()));
    }

    /// 受け入れ条件 2: 無参照のイメージを force なしで削除すると、manifest・config・非共有レイヤーが消える。
    #[test]
    fn oci7_rm_unreferenced_deletes_manifest_config_and_unshared_layers() {
        let root = Root::new("delete");
        let mut t = fixture(&root);
        t.register_tag(tk("v1"), &d(0xa0)).unwrap();
        t.register_tag(tk("b"), &d(0xb0)).unwrap();
        let out = t
            .execute_image_rm(
                &root.0,
                &ImageRmTarget::Tag(tk("v1")),
                &ImageRmOptions::default(),
                &StoppedContainers::new(),
            )
            .unwrap();
        assert_eq!(out.kind, ImageRmKind::Deleted);
        assert_eq!(out.untagged, vec![tk("v1")]);
        assert_eq!(out.deleted_blobs, vec![d(0x11), d(0xc1)]);
        assert_eq!(out.kept_blobs, vec![d(0x10)]);
        assert!(out.absent_blobs.is_empty() && out.undeleted_blobs.is_empty());
        assert!(t.manifests().all(|(m, _)| *m != d(0xa0)));
        assert!(!root.exists(&d(0xc1)) && !root.exists(&d(0x11)));
        // 共有レイヤーと B の blob は残る。
        assert!(root.exists(&d(0x10)) && root.exists(&d(0xc2)) && root.exists(&d(0x12)));
    }

    /// 無参照（タグも無い）の dangling な manifest と共有する blob も残す。
    #[test]
    fn oci7_rm_keeps_blob_shared_with_dangling_manifest() {
        let root = Root::new("dangling");
        let mut t = fixture(&root);
        let out = t
            .execute_image_rm(
                &root.0,
                &ImageRmTarget::Manifest(d(0xa0)),
                &ImageRmOptions::default(),
                &StoppedContainers::new(),
            )
            .unwrap();
        assert_eq!(out.kept_blobs, vec![d(0x10)]);
        assert!(root.exists(&d(0x10)));
    }

    /// pull リースが残る blob は消さない。
    #[test]
    fn oci7_rm_keeps_leased_blob() {
        let root = Root::new("lease");
        let mut t = fixture(&root);
        t.acquire_lease(d(0x11), PullId::new("p1").unwrap())
            .unwrap();
        let out = t
            .execute_image_rm(
                &root.0,
                &ImageRmTarget::Manifest(d(0xa0)),
                &ImageRmOptions::default(),
                &StoppedContainers::new(),
            )
            .unwrap();
        assert!(out.kept_blobs.contains(&d(0x11)));
        assert!(root.exists(&d(0x11)));
        assert!(!root.exists(&d(0xc1)));
    }

    /// 拒否のときはテーブルもディスクも変わらない。
    #[test]
    fn oci7_rm_refusal_changes_nothing() {
        let root = Root::new("refuse");
        let mut t = fixture(&root);
        t.register_tag(tk("v1"), &d(0xa0)).unwrap();
        t.register_container(cid("run"), &d(0xa0)).unwrap();
        let before = t.clone();
        let files = root.files();
        let e = t
            .execute_image_rm(
                &root.0,
                &ImageRmTarget::Tag(tk("v1")),
                &force(),
                &StoppedContainers::new(),
            )
            .unwrap_err();
        assert_eq!(e.code(), OciErrorCode::FailedPrecondition);
        assert_eq!(t, before);
        assert_eq!(root.files(), files);
    }

    /// `blobs/sha256` が symlink なら何も変えずに拒否する（untag も起きない）。
    #[cfg(unix)]
    #[test]
    fn oci7_rm_symlinked_blob_dir_changes_nothing() {
        let root = Root::new("symdir");
        let mut t = fixture(&root);
        t.register_tag(tk("v1"), &d(0xa0)).unwrap();
        let dir = root.0.join("blobs").join("sha256");
        let other = root.0.join("other");
        fs::rename(&dir, &other).unwrap();
        std::os::unix::fs::symlink(&other, &dir).unwrap();
        let before = t.clone();
        let e = t
            .execute_image_rm(
                &root.0,
                &ImageRmTarget::Tag(tk("v1")),
                &ImageRmOptions::default(),
                &StoppedContainers::new(),
            )
            .unwrap_err();
        assert_eq!(e.code(), OciErrorCode::FailedPrecondition);
        assert_eq!(t, before);
        assert!(
            other
                .join(d(0xc1).as_str().trim_start_matches("sha256:"))
                .exists()
        );
    }

    /// 削除対象の blob が既に無くても成功し、`absent_blobs` に載る。
    #[test]
    fn oci7_rm_missing_blob_file_is_absent() {
        let root = Root::new("absent");
        let mut t = fixture(&root);
        fs::remove_file(blob_path(&root.0, &d(0x11)).unwrap()).unwrap();
        let out = t
            .execute_image_rm(
                &root.0,
                &ImageRmTarget::Manifest(d(0xa0)),
                &ImageRmOptions::default(),
                &StoppedContainers::new(),
            )
            .unwrap();
        assert_eq!(out.absent_blobs, vec![d(0x11)]);
        assert_eq!(out.deleted_blobs, vec![d(0xc1)]);
    }

    /// blob の位置が symlink なら辿らず、リンク先を残して `undeleted_blobs` に載せる。
    #[cfg(unix)]
    #[test]
    fn oci7_rm_does_not_follow_symlink_blob() {
        let root = Root::new("symblob");
        let mut t = fixture(&root);
        let victim = root.0.join("victim");
        fs::write(&victim, b"keep").unwrap();
        let p = blob_path(&root.0, &d(0x11)).unwrap();
        fs::remove_file(&p).unwrap();
        std::os::unix::fs::symlink(&victim, &p).unwrap();
        let out = t
            .execute_image_rm(
                &root.0,
                &ImageRmTarget::Manifest(d(0xa0)),
                &ImageRmOptions::default(),
                &StoppedContainers::new(),
            )
            .unwrap();
        assert_eq!(out.undeleted_blobs, vec![d(0x11)]);
        assert_eq!(fs::read(&victim).unwrap(), b"keep");
        assert!(fs::symlink_metadata(&p).is_ok());
    }

    #[derive(Debug, Default)]
    struct Collect(std::sync::Mutex<Vec<OciOpSample>>);
    impl OciOpRecorder for Collect {
        fn record_oci_op(&self, s: &OciOpSample) {
            self.0.lock().unwrap().push(*s);
        }
    }

    /// REPAIR-4: 成功と失敗の両方を `oci.image.rm` として記録する。
    #[test]
    fn repair4_rm_records_success_and_failure() {
        let root = Root::new("instr");
        let mut t = fixture(&root);
        t.register_container(cid("run"), &d(0xb0)).unwrap();
        let rec = Collect::default();
        let none = StoppedContainers::new();
        let o = ImageRmOptions::default();
        t.execute_image_rm_with(&rec, &root.0, &ImageRmTarget::Manifest(d(0xa0)), &o, &none)
            .unwrap();
        t.execute_image_rm_with(&rec, &root.0, &ImageRmTarget::Manifest(d(0xb0)), &o, &none)
            .unwrap_err();
        let v = rec.0.lock().unwrap();
        let got: Vec<_> = v
            .iter()
            .map(|s| (s.kind(), s.outcome(), s.error_code()))
            .collect();
        assert_eq!(
            got,
            vec![
                (OciOpKind::RemoveImage, OciOpOutcome::Success, None),
                (
                    OciOpKind::RemoveImage,
                    OciOpOutcome::Failure,
                    Some(OciErrorCode::FailedPrecondition)
                ),
            ]
        );
        assert_eq!(OciOpKind::RemoveImage.as_str(), "oci.image.rm");
    }
}
