//! CRI の在庫記録（[`ImageRecord`]）の永続形式の符号化と復号（#4176・CRI-1・CRI-2・OCI-7・REPAIR-2）。
//!
//! `fandhe-container-plugin-cri` の `PersistentImageStore` が、oci の `ImageStore` の root 直下の専用ファイルへ
//! 書く / から読むバイト列の組み立てだけを担う（ファイル I/O・排他・メモリ表示は plugin-cri 側）。
//! [`ImageRecord`] の項目は非公開で plugin-cri は serde を持たないため、符号化は本モジュール（`image_service` の
//! 子）に置く。top-level digest と補助 digest を分けて保存し、[`ImageRecord::from_parts`] で読み戻すので、
//! 開き直しても `repo_digests` の並びと先頭（top-level）が変わらない。
//!
//! # 形式
//!
//! `{"version":1,"images":[{"id","repo_tags","top_level_digests","auxiliary_digests","size","uid","username","pinned"}]}`。
//! 未知のフィールドは拒否し、`images` は ID 昇順（決定的）。
//!
//! # 復号の fail-closed
//!
//! 上限超過・不正な JSON・版の不一致・検証違反・ID の重複・1 つのタグが複数イメージに付いた状態は、
//! すべて [`ImageStoreError::Corrupt`] にする（空の在庫として扱わない）。長さは確保の前に検証する。

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::{ImageRecord, ImageStoreError, MAX_IMAGES};

/// 記録ファイルの最大バイト数（無制限確保の防止）。
pub const MAX_IMAGE_RECORDS_FILE_BYTES: usize = 16 * 1024 * 1024;
/// 現在の形式の版。
const FORMAT_VERSION: u32 = 1;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFile {
    version: u32,
    images: Vec<RawImage>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawImage {
    id: String,
    repo_tags: Vec<String>,
    top_level_digests: Vec<String>,
    auxiliary_digests: Vec<String>,
    size: u64,
    uid: Option<i64>,
    username: String,
    pinned: bool,
}

/// 記録群を永続形式のバイト列にする。ID 昇順で並べる。上限を超えるなら [`ImageStoreError::StoreFull`]。
pub fn encode_image_records(records: &[ImageRecord]) -> Result<Vec<u8>, ImageStoreError> {
    encode_with_limit(records, MAX_IMAGE_RECORDS_FILE_BYTES)
}

fn encode_with_limit(records: &[ImageRecord], limit: usize) -> Result<Vec<u8>, ImageStoreError> {
    if records.len() > MAX_IMAGES {
        return Err(ImageStoreError::StoreFull);
    }
    let mut images: Vec<RawImage> = records
        .iter()
        .map(|r| RawImage {
            id: r.id.clone(),
            repo_tags: r.repo_tags.clone(),
            top_level_digests: r.top_level_digests().to_vec(),
            auxiliary_digests: r.auxiliary_digests().to_vec(),
            size: r.size,
            uid: r.uid,
            username: r.username.clone(),
            pinned: r.pinned,
        })
        .collect();
    images.sort_by(|a, b| a.id.cmp(&b.id));
    let bytes = serde_json::to_vec(&RawFile {
        version: FORMAT_VERSION,
        images,
    })
    .map_err(|_| ImageStoreError::Corrupt)?;
    if bytes.len() > limit {
        return Err(ImageStoreError::StoreFull);
    }
    Ok(bytes)
}

/// 永続形式のバイト列を記録群へ戻す。どの違反も [`ImageStoreError::Corrupt`]。
pub fn decode_image_records(bytes: &[u8]) -> Result<Vec<ImageRecord>, ImageStoreError> {
    if bytes.len() > MAX_IMAGE_RECORDS_FILE_BYTES {
        return Err(ImageStoreError::Corrupt);
    }
    let file: RawFile = serde_json::from_slice(bytes).map_err(|_| ImageStoreError::Corrupt)?;
    if file.version != FORMAT_VERSION || file.images.len() > MAX_IMAGES {
        return Err(ImageStoreError::Corrupt);
    }
    let mut ids = BTreeSet::new();
    let mut tags = BTreeSet::new();
    let mut out = Vec::with_capacity(file.images.len());
    for raw in file.images {
        let record = ImageRecord::from_parts(
            raw.id,
            raw.repo_tags,
            raw.top_level_digests,
            raw.auxiliary_digests,
            raw.size,
        )
        .and_then(|r| r.with_user(raw.uid, &raw.username))
        .map(|r| r.with_pinned(raw.pinned))
        .map_err(|_| ImageStoreError::Corrupt)?;
        if !ids.insert(record.id.clone()) {
            return Err(ImageStoreError::Corrupt);
        }
        for tag in &record.repo_tags {
            if !tags.insert(tag.clone()) {
                return Err(ImageStoreError::Corrupt);
            }
        }
        out.push(record);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(id: &str, tag: &str) -> ImageRecord {
        ImageRecord::from_parts(
            id,
            vec![tag.to_owned()],
            vec!["docker.io/library/a@sha256:idx".to_owned()],
            vec!["docker.io/library/a@sha256:plat".to_owned()],
            4096,
        )
        .expect("record")
    }

    /// CRI-2・OCI-7: top / 補助の digest の区別・uid・pinned を含めて往復で完全一致する。
    #[test]
    fn cri2_oci7_records_round_trip() {
        let a = rec("sha256:aaa", "docker.io/library/a:1")
            .with_user(Some(1000), "")
            .expect("user")
            .with_pinned(true);
        let b = rec("sha256:bbb", "docker.io/library/b:1")
            .with_user(None, "nobody")
            .expect("user");
        let bytes = encode_image_records(&[b.clone(), a.clone()]).expect("encode");
        let back = decode_image_records(&bytes).expect("decode");
        assert_eq!(back, vec![a.clone(), b]);
        assert_eq!(
            back[0].repo_digests(),
            &[
                "docker.io/library/a@sha256:idx".to_owned(),
                "docker.io/library/a@sha256:plat".to_owned()
            ]
        );
        assert_eq!(
            back[0].top_level_digests(),
            &["docker.io/library/a@sha256:idx".to_owned()]
        );
        assert_eq!(
            back[0].auxiliary_digests(),
            &["docker.io/library/a@sha256:plat".to_owned()]
        );
    }

    #[test]
    fn cri2_oci7_decode_rejects_corrupt_inputs() {
        let ok = encode_image_records(&[rec("sha256:aaa", "t:1")]).expect("encode");
        let text = String::from_utf8(ok).expect("utf8");
        let cases: Vec<String> = vec![
            "not json".to_owned(),
            text.replace("\"version\":1", "\"version\":2"),
            text.replace("\"pinned\"", "\"extra\":1,\"pinned\""),
            text.replace("\"size\":4096", "\"size\":0"),
            text.replace("sha256:aaa", &"x".repeat(2000)),
            r#"{"version":1,"images":[]"#.to_owned(),
        ];
        for case in cases {
            assert_eq!(
                decode_image_records(case.as_bytes()),
                Err(ImageStoreError::Corrupt),
                "{case}"
            );
        }
        assert!(decode_image_records(br#"{"version":1,"images":[]}"#).is_ok_and(|v| v.is_empty()));
    }

    #[test]
    fn cri2_oci7_decode_rejects_duplicate_id_and_shared_tag() {
        let one = |id: &str, tag: &str| {
            format!(
                r#"{{"id":"{id}","repo_tags":["{tag}"],"top_level_digests":[],"auxiliary_digests":[],"size":1,"uid":null,"username":"","pinned":false}}"#
            )
        };
        let dup_id = format!(
            r#"{{"version":1,"images":[{},{}]}}"#,
            one("i", "a"),
            one("i", "b")
        );
        let dup_tag = format!(
            r#"{{"version":1,"images":[{},{}]}}"#,
            one("i", "a"),
            one("j", "a")
        );
        for case in [dup_id, dup_tag] {
            assert_eq!(
                decode_image_records(case.as_bytes()),
                Err(ImageStoreError::Corrupt)
            );
        }
    }

    #[test]
    fn cri2_oci7_decode_rejects_too_many_images_and_oversize() {
        let one = r#"{"id":"i","repo_tags":[],"top_level_digests":[],"auxiliary_digests":[],"size":1,"uid":null,"username":"","pinned":false}"#;
        let many = vec![one; MAX_IMAGES + 1].join(",");
        let text = format!(r#"{{"version":1,"images":[{many}]}}"#);
        assert_eq!(
            decode_image_records(text.as_bytes()),
            Err(ImageStoreError::Corrupt)
        );
        let big = vec![b' '; MAX_IMAGE_RECORDS_FILE_BYTES + 1];
        assert_eq!(decode_image_records(&big), Err(ImageStoreError::Corrupt));
    }

    #[test]
    fn cri2_oci7_encode_rejects_over_limit() {
        let r = rec("sha256:aaa", "t:1");
        assert_eq!(
            encode_with_limit(std::slice::from_ref(&r), 10),
            Err(ImageStoreError::StoreFull)
        );
        assert!(encode_with_limit(&[r], 1 << 20).is_ok());
    }
}
