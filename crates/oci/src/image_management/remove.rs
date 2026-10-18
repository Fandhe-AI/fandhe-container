//! `image rm` の既定の削除拒否判定（OCI-7・TASK-183.5・MS-4・#480）。
//!
//! `image rm` は、タグの有無や指定方法（タグか digest か）に関係なく、コンテナが参照している
//! イメージを既定で削除しない。判定の正の情報源は [`ReferenceTable`] だけで、`StateStore` は使わない。
//! テーブルはコンテナのライフサイクル状態（実行中・停止中）を持たないため、既定経路では状態を区別せず
//! 「コンテナ参照が 1 件でもあれば拒否」とする（fail-closed）。状態による分岐が要るのは `--force`
//! （#481）だけである。
//!
//! 本モジュールは `&self` の判定だけを行い、テーブルの untag・`remove_manifest`・ディスク上の blob
//! 削除はしない（`--force` の境界と実削除は #481、永続化は #851 以降。実装済みを装わない。REPAIR-3）。
//! 呼び出し側は、ストアのガード（`ImageStoreGuard`。#473）を保持したまま呼ぶ前提である。
//!
//! Docker の `rmi <tag>` はタグが複数あるイメージなら untag して成功するが、本実装は OCI-7 に従い
//! コンテナ参照があれば拒否する。pull リースは blob を守るもので manifest は守らないため、判定に
//! 含めない（blob 削除時の考慮は #481・#476 の担当）。

use std::fmt::Write as _;

use super::{ContainerRefId, ReferenceTable, TagKey};
use crate::error::{OciError, OciErrorCode};
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::image_management::ManifestComposition;
    use crate::reference::{RegistryHost, Repository, Tag};

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
}
