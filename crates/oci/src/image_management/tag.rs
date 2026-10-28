//! `image tag` の操作入口（OCI-7・TASK-183.4・MS-4・#479）。
//!
//! タグの新規付与と付け替えを、ソース（既存タグまたは manifest digest）の解決・在庫の存在確認・
//! タグ登録までを 1 つの排他区間で行う。`image prune` が削除を確定させた直後の manifest に、
//! 並行した `tag` が付く競合（TOCTOU）を防ぐのが目的で、確認と登録の間に他の変更を割り込ませない。
//!
//! 呼び出し文脈: 正規の入口は `ImageStore::tag_image`（排他を取ってから本処理を呼ぶ）。
//! 将来の CLI（`image tag`）と CRI の ImageService がここを通る。`ReferenceTable::tag_image` は
//! 呼び出し側が `ImageStoreGuard` を保持している前提で、本モジュールは排他をかけない
//! （`remove` と同じ契約）。
//!
//! 契約: 失敗（ソース不在・在庫に無い manifest）の経路ではテーブルを変えない。ロック待ちの期限切れは
//! `Timeout`（REPAIR-5）、毒化したストアは `Internal`（fail-closed。#473）。
//!
//! 件数の上限: テーブル全体のタグ件数は [`MAX_TAG_REFS`] を超えない。検査は書き込み側
//! （`ReferenceTable::register_tag`）で行い、新規キーだけを拒否する（`ResourceExhausted`）。
//! 既存タグの付け替えと再付与は上限に達していても通す（#2316）。
//!
//! 永続化（#2380）: タグの付与・付け替えは、排他区間の root が設定されたテーブル（`ImageStore::lock` の
//! ガード）では `@image-inventory.json` へ保存してから結果を返す。変わらない結果（`Unchanged`）とエラーでは
//! 書かない。保存に失敗したらテーブルを戻してエラーを返す（`inventory_persist`）。
//! CLI 配線は `fandhe-container-cli` の `image tag`（#2316）。

use super::{ImageStore, ReferenceTable, TagKey};
use crate::error::{OciError, OciErrorCode};
use crate::instrument::{OciOpKind, OciOpRecorder, record_oci_op};
use crate::reference::Digest;

/// テーブル全体のタグ件数の上限（#2316・OCI-7）。
///
/// コンテナ参照の上限 `MAX_CONTAINER_REFS`（#2352）と同じ値に揃えた。`TagKey` 1 件は検証済みの
/// host・repository・tag の文字列で 1 KiB 未満のため、最大でも十数 MiB に収まる。永続化（#2380）の
/// 読み込み側も同じ定数で検査する。
pub const MAX_TAG_REFS: usize = 16_384;

/// `image tag` のソース（検証済みの newtype だけで表す）。`ImageRmTarget` と同じ形の別の型。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ImageTagSource {
    /// 既存タグが指す manifest。
    Tag(TagKey),
    /// manifest digest を直接指定する。
    Manifest(Digest),
}

/// 付与の結果の区分。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ImageTagChange {
    /// 新しいタグを付けた。
    Added,
    /// 別の manifest から付け替えた。
    Moved {
        /// 付け替え前の manifest。
        from: Digest,
    },
    /// 既に同じ manifest を指していた（冪等）。
    Unchanged,
}

/// `image tag` の結果。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ImageTagOutcome {
    /// 解決した付け先の manifest。
    pub manifest: Digest,
    /// 付けたタグ。
    pub tag: TagKey,
    /// 付与の区分。
    pub change: ImageTagChange,
}

impl ReferenceTable {
    /// `keys` のうちテーブルに未登録のもの（重複は 1 件と数える）を足しても [`MAX_TAG_REFS`] を
    /// 超えないことを確かめる。超えるなら `ResourceExhausted`（テーブルは変えない）。
    ///
    /// `register_tag`（1 件）と pull の公開（複数件。途中失敗で半端なタグを残さない事前検査）が共用する。
    pub(super) fn ensure_tag_capacity<'a>(
        &self,
        keys: impl IntoIterator<Item = &'a TagKey>,
    ) -> Result<(), OciError> {
        let fresh: std::collections::BTreeSet<&TagKey> = keys
            .into_iter()
            .filter(|k| !self.tag_refs.contains_key(*k))
            .collect();
        if self.tag_refs.len().saturating_add(fresh.len()) > MAX_TAG_REFS {
            return Err(OciError::new(
                OciErrorCode::ResourceExhausted,
                "too many image tags",
            ));
        }
        Ok(())
    }

    /// ソースを解決して `target` を付ける。呼び出し側が排他区間（ガード）を保持している前提。
    ///
    /// 解決と存在確認は書き込みの前に済ませるため、エラー時にテーブルは変わない。
    /// ソースのタグと `target` が同じなら `Unchanged` の成功。
    pub fn tag_image(
        &mut self,
        source: &ImageTagSource,
        target: TagKey,
    ) -> Result<ImageTagOutcome, OciError> {
        let manifest = match source {
            ImageTagSource::Tag(key) => self.tag_refs.get(key).cloned().ok_or_else(|| {
                OciError::new(OciErrorCode::NotFound, format!("tag {key} not found"))
            })?,
            ImageTagSource::Manifest(d) => {
                if !self.manifests.contains_key(d) {
                    return Err(OciError::new(
                        OciErrorCode::NotFound,
                        format!("image {d} not found"),
                    ));
                }
                d.clone()
            }
        };
        // register_tag 内でも在庫を確認する（タグが在庫外を指す状態への防御の二重確認）。
        let before = self.inventory_portion();
        let previous = self.register_tag(target.clone(), &manifest)?;
        // 排他区間の root があれば、変わったときだけ保存する。失敗したら戻してエラー（#2380）。
        self.persist_inventory(before)?;
        let change = match previous {
            None => ImageTagChange::Added,
            Some(prev) if prev == manifest => ImageTagChange::Unchanged,
            Some(from) => ImageTagChange::Moved { from },
        };
        Ok(ImageTagOutcome {
            manifest,
            tag: target,
            change,
        })
    }

    /// 計装つきの `tag_image`（エラー終了も含め結果と所要時間を記録する。REPAIR-4）。
    pub fn tag_image_with(
        &mut self,
        recorder: &dyn OciOpRecorder,
        source: &ImageTagSource,
        target: TagKey,
    ) -> Result<ImageTagOutcome, OciError> {
        record_oci_op(recorder, OciOpKind::TagImage, || {
            self.tag_image(source, target)
        })
    }
}

impl ImageStore {
    /// 排他区間の中で `image tag` を行う正規の入口。ソースの解決・存在確認・登録が 1 区間に収まる。
    ///
    /// 期限内に排他を取れなければ `Timeout`、毒化なら `Internal`。ガードは関数内で解放する。
    pub fn tag_image(
        &self,
        source: &ImageTagSource,
        target: TagKey,
    ) -> Result<ImageTagOutcome, OciError> {
        let mut guard = self.lock()?;
        guard.tag_image_with(self.recorder(), source, target)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::image_management::ManifestComposition;
    use crate::instrument::OciOpOutcome;
    use crate::instrument::testing::Collect;
    use crate::reference::{RegistryHost, Repository, Tag};
    use std::fs;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::thread;
    use std::time::Duration;

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

    fn table() -> ReferenceTable {
        let mut t = ReferenceTable::new();
        for (m, c, l) in [(0xa0, 0xc1, 0x10), (0xb0, 0xc2, 0x11)] {
            t.register_manifest(
                d(m),
                ManifestComposition::new(d(c), vec![d(l)]).expect("comp"),
            )
            .expect("manifest");
        }
        t
    }

    fn temp_root(label: &str) -> PathBuf {
        static SEQ: AtomicU32 = AtomicU32::new(0);
        let p = std::env::temp_dir().join(format!(
            "fc-oci-tag-{}-{}-{label}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        // PID の再利用で前回の実行の残骸と名前が衝突しうるため、作る前に消す（#3237）。
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).expect("mkdir");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).expect("chmod");
        }
        p
    }

    fn code<T: std::fmt::Debug>(r: Result<T, OciError>) -> OciErrorCode {
        r.unwrap_err().code()
    }

    fn full_table() -> ReferenceTable {
        let mut t = table();
        for i in 0..MAX_TAG_REFS {
            t.register_tag(tk(&format!("f{i}")), &d(0xa0)).unwrap();
        }
        t
    }

    /// OCI-7: 上限に達していると新規キーは ResourceExhausted で、テーブルは変わらない（#2316）。
    #[test]
    fn oci7_register_tag_at_limit_rejects_new_key_and_keeps_table() {
        let mut t = full_table();
        let before = t.clone();
        let r = t.register_tag(tk("new"), &d(0xa0));
        assert_eq!(code(r), OciErrorCode::ResourceExhausted);
        assert_eq!(t.tags().count(), MAX_TAG_REFS);
        assert_eq!(t, before);
    }

    /// OCI-7: 上限に達していても既存キーの付け替え・再付与は成功する（#2316）。
    #[test]
    fn oci7_register_tag_at_limit_allows_retag_and_same() {
        let mut t = full_table();
        assert_eq!(t.register_tag(tk("f0"), &d(0xb0)).unwrap(), Some(d(0xa0)));
        assert_eq!(t.register_tag(tk("f0"), &d(0xb0)).unwrap(), Some(d(0xb0)));
        assert_eq!(t.tags().count(), MAX_TAG_REFS);
    }

    /// OCI-7: ImageStore::tag_image 経由でも上限が効き、付け替えは通る（#2316）。
    #[test]
    fn oci7_tag_image_at_limit_is_resource_exhausted() {
        let root = temp_root("limit");
        let store = ImageStore::with_table(&root, full_table()).expect("store");
        let r = store.tag_image(&ImageTagSource::Manifest(d(0xa0)), tk("new"));
        assert_eq!(code(r), OciErrorCode::ResourceExhausted);
        let o = store
            .tag_image(&ImageTagSource::Manifest(d(0xb0)), tk("f1"))
            .unwrap();
        assert_eq!(o.change, ImageTagChange::Moved { from: d(0xa0) });
        let _ = fs::remove_dir_all(&root);
    }

    /// OCI-7: 在庫にある manifest へ digest で付与すると Added になる。
    #[test]
    fn oci7_tag_by_digest_adds_tag() {
        let mut t = table();
        let o = t
            .tag_image(&ImageTagSource::Manifest(d(0xa0)), tk("v1"))
            .unwrap();
        assert_eq!(o.manifest, d(0xa0));
        assert_eq!(o.tag, tk("v1"));
        assert_eq!(o.change, ImageTagChange::Added);
        assert_eq!(t.manifest_references(&d(0xa0)).tags, vec![tk("v1")]);
    }

    /// OCI-7: 別 manifest への付け替えは Moved で直前の付け先を返し、旧 manifest からタグが外れる。
    #[test]
    fn oci7_retag_moves_and_reports_previous() {
        let mut t = table();
        t.tag_image(&ImageTagSource::Manifest(d(0xa0)), tk("v1"))
            .unwrap();
        let o = t
            .tag_image(&ImageTagSource::Manifest(d(0xb0)), tk("v1"))
            .unwrap();
        assert_eq!(o.change, ImageTagChange::Moved { from: d(0xa0) });
        assert_eq!(t.manifest_references(&d(0xa0)).tags, vec![]);
        assert_eq!(t.manifest_references(&d(0xb0)).tags, vec![tk("v1")]);
    }

    /// OCI-7: ソースのタグで付与すると同じ manifest を指し、ソースのタグは残る。
    #[test]
    fn oci7_tag_by_source_tag_aliases_same_manifest() {
        let mut t = table();
        t.tag_image(&ImageTagSource::Manifest(d(0xa0)), tk("v1"))
            .unwrap();
        let o = t
            .tag_image(&ImageTagSource::Tag(tk("v1")), tk("latest"))
            .unwrap();
        assert_eq!(o.manifest, d(0xa0));
        assert_eq!(o.change, ImageTagChange::Added);
        assert_eq!(
            t.manifest_references(&d(0xa0)).tags,
            vec![tk("latest"), tk("v1")]
        );
    }

    /// OCI-7: 同じ付け先の再付与とソース = 付け先は Unchanged（冪等）。
    #[test]
    fn oci7_tag_same_target_is_unchanged() {
        let mut t = table();
        t.tag_image(&ImageTagSource::Manifest(d(0xa0)), tk("v1"))
            .unwrap();
        let again = t
            .tag_image(&ImageTagSource::Manifest(d(0xa0)), tk("v1"))
            .unwrap();
        assert_eq!(again.change, ImageTagChange::Unchanged);
        let same = t
            .tag_image(&ImageTagSource::Tag(tk("v1")), tk("v1"))
            .unwrap();
        assert_eq!(same.change, ImageTagChange::Unchanged);
    }

    /// OCI-7: 未登録の digest は NotFound でテーブルは変わらない。
    #[test]
    fn oci7_tag_unknown_manifest_is_not_found_and_table_unchanged() {
        let mut t = table();
        let before = t.clone();
        let r = t.tag_image(&ImageTagSource::Manifest(d(0xee)), tk("v1"));
        assert_eq!(code(r), OciErrorCode::NotFound);
        assert_eq!(t, before);
    }

    /// OCI-7: 未登録のソースのタグは NotFound でテーブルは変わらない。
    #[test]
    fn oci7_tag_unknown_source_tag_is_not_found_and_table_unchanged() {
        let mut t = table();
        let before = t.clone();
        let r = t.tag_image(&ImageTagSource::Tag(tk("nope")), tk("v1"));
        assert_eq!(code(r), OciErrorCode::NotFound);
        assert_eq!(t, before);
    }

    /// OCI-7: manifest が削除（prune の確定に相当）された後の付与は NotFound。
    #[test]
    fn oci7_tag_after_manifest_removed_is_not_found() {
        let mut t = table();
        t.remove_manifest(&d(0xa0)).unwrap();
        let r = t.tag_image(&ImageTagSource::Manifest(d(0xa0)), tk("v1"));
        assert_eq!(code(r), OciErrorCode::NotFound);
    }

    /// OCI-7: ガード保持中の `ImageStore::tag_image` は Timeout になり、解放後は成功する。
    #[test]
    fn oci7_image_store_tag_holds_exclusive_section() {
        let root = temp_root("excl");
        let store = ImageStore::with_table(&root, table())
            .unwrap()
            .with_timeout(Duration::from_millis(100));
        let src = ImageTagSource::Manifest(d(0xa0));
        {
            let guard = store.lock().unwrap();
            assert_eq!(code(store.tag_image(&src, tk("v1"))), OciErrorCode::Timeout);
            drop(guard);
        }
        assert_eq!(store.lock().unwrap().tags().count(), 0);
        let o = store.tag_image(&src, tk("v1")).unwrap();
        assert_eq!(o.change, ImageTagChange::Added);
        fs::remove_dir_all(&root).unwrap();
    }

    /// OCI-7: 排他区間で manifest が削除される間に待った tag は、解放後に NotFound になる。
    #[test]
    fn oci7_image_store_tag_after_concurrent_removal_is_not_found() {
        let root = temp_root("race");
        let store = Arc::new(
            ImageStore::with_table(&root, table())
                .unwrap()
                .with_timeout(Duration::from_secs(5)),
        );
        let mut guard = store.lock().unwrap();
        let s2 = Arc::clone(&store);
        let h = thread::spawn(move || s2.tag_image(&ImageTagSource::Manifest(d(0xa0)), tk("v1")));
        guard.remove_manifest(&d(0xa0)).unwrap();
        drop(guard);
        let r = h.join().unwrap();
        assert_eq!(code(r), OciErrorCode::NotFound);
        assert_eq!(store.lock().unwrap().tags().count(), 0);
        fs::remove_dir_all(&root).unwrap();
    }

    /// REPAIR-4: 成功と NotFound がそれぞれ TagImage の Success / Failure として記録される。
    #[test]
    fn repair4_tag_image_is_recorded() {
        let mut t = table();
        let rec = Collect::default();
        t.tag_image_with(&rec, &ImageTagSource::Manifest(d(0xa0)), tk("v1"))
            .unwrap();
        t.tag_image_with(&rec, &ImageTagSource::Manifest(d(0xee)), tk("v2"))
            .unwrap_err();
        let got: Vec<_> = rec
            .items()
            .iter()
            .map(|s| (s.kind(), s.outcome(), s.error_code()))
            .collect();
        assert_eq!(
            got,
            vec![
                (OciOpKind::TagImage, OciOpOutcome::Success, None),
                (
                    OciOpKind::TagImage,
                    OciOpOutcome::Failure,
                    Some(OciErrorCode::NotFound)
                ),
            ]
        );
    }
}
