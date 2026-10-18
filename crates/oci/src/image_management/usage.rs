//! `image ls` / `system df` 相当の集計 API（OCI-7・TASK-183.3・MS-4・#478）。
//!
//! 参照テーブル（`ReferenceTable`）が持つ manifest 構成とタグを、ローカルキャッシュ
//! （`<root>/blobs/sha256/<hex>`。cri の `image_pull` と同じ配置）の実ファイルと突き合わせ、
//! 一覧の行（repository・tag・digest・サイズ）と使用容量を返す。参照テーブルはサイズを持たないため、
//! サイズはここで blob ファイルを `symlink_metadata` で読んで求める。
//!
//! 呼び出し文脈: 読み取り専用で、削除も書き込みもしない。テーブルとキャッシュの整合を取るため、
//! 呼び出し側がストア排他（#473）の内側で呼ぶ前提で、本モジュールは排他をかけない。
//! 参照テーブルに未登録のもの（pull 中のステージング）は一覧に現れない（公開完了まで見えない。OCI-7）。
//!
//! サイズの定義: キャッシュ上の blob ファイルの見かけのサイズ（圧縮済みのバイト数）。
//! 3 OS 共通の API で取れ、フィクスチャの既知合計と一致するため、割り当てブロック数は使わない。
//! 報告するサイズは digest 検証を兼ねない（内容の検証済みを装わない）。
//!
//! 未実装（実装済みを装わない。REPAIR-3）: 展開後サイズ、コンテナ（rootfs・bundle は core の領域）と
//! ステージング（#474 で配置確定後）の使用容量、CLI 経路（`image ls` / `system df` のサブコマンド）、
//! 計装。

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use super::{ReferenceTable, TagKey};
use crate::error::{OciError, OciErrorCode};
use crate::reference::Digest;

/// `blobs/sha256` 走査で数えるエントリ数の上限（無制限の走査を避ける。100 万件超は異常とみなす）。
pub const MAX_CACHE_SCAN_ENTRIES: usize = 1_048_576;

/// 一覧の 1 行。タグ 1 件につき 1 行で、タグの無い manifest は `tag` が `None` の 1 行になる。
///
/// repository 等の表示用要素は `tag`（`TagKey` の host・repository・tag）からそのまま取れる。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ImageEntry {
    /// タグ。コンテナ参照のみ・dangling の manifest では `None`。
    pub tag: Option<TagKey>,
    /// manifest の digest。
    pub digest: Digest,
    /// config と layers の blob（重複除去済み）のうち、キャッシュに存在するものの合計バイト数。
    pub size_bytes: u64,
    /// キャッシュに無い（または通常ファイルでない）blob。空なら完全。
    pub missing_blobs: Vec<Digest>,
}

/// `list_images` の結果。並びは決定的（タグ昇順、続けてタグなし manifest を digest 昇順）。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct ImageList {
    /// 一覧の行。
    pub entries: Vec<ImageEntry>,
}

/// 登録済みイメージ側の使用容量。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct ImageUsage {
    /// 登録済み manifest の件数。
    pub count: usize,
    /// 全 manifest の blob の和集合のうち存在するものの合計（共有レイヤーを二重計上しない）。
    pub bytes: u64,
    /// `bytes` のうち、どのコンテナ・タグ・pull リースからも参照されない blob の合計。
    pub reclaimable_bytes: u64,
    /// 存在しない blob の件数（和集合ベース）。
    pub missing_blobs: usize,
}

/// キャッシュ（`blobs/sha256`）側の使用容量。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct CacheUsage {
    /// 名前が小文字 hex 64 桁の通常ファイルの件数。
    pub blob_count: usize,
    /// 上記の合計バイト数。
    pub bytes: u64,
    /// どの manifest 構成にも含まれない blob の件数（未登録・取り残し）。
    pub unregistered_count: usize,
    /// 上記の合計バイト数。
    pub unregistered_bytes: u64,
    /// blob として扱わなかったエントリ数（名前が不正・通常ファイルでない）。バイトには入れない。
    pub foreign_entries: usize,
}

/// `system df` 相当の結果。containers・staging は oci では測れないため持たない（未計測）。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct DiskUsage {
    /// 登録済みイメージ側。
    pub images: ImageUsage,
    /// キャッシュ側。
    pub cache: CacheUsage,
}

fn err(code: OciErrorCode, msg: &str) -> OciError {
    OciError::new(code, msg)
}

/// blob の置き場 `<root>/blobs/sha256`。
fn blob_dir(root: &Path) -> PathBuf {
    root.join("blobs").join("sha256")
}

/// 検証済み `Digest` の hex 部だけからパスを組み立てる。
fn blob_path(root: &Path, digest: &Digest) -> Result<PathBuf, OciError> {
    let hex = digest
        .as_str()
        .strip_prefix("sha256:")
        .ok_or_else(|| err(OciErrorCode::Internal, "unsupported digest algorithm"))?;
    Ok(blob_dir(root).join(hex))
}

/// blob 1 件のサイズ。存在しない・symlink・通常ファイルでないものは `None`（辿らない）。
fn blob_size(root: &Path, digest: &Digest) -> Result<Option<u64>, OciError> {
    let path = blob_path(root, digest)?;
    match fs::symlink_metadata(&path) {
        Ok(m) if m.is_file() => Ok(Some(m.len())),
        Ok(_) => Ok(None),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
        Err(_) => Err(err(OciErrorCode::Internal, "failed to stat blob")),
    }
}

fn add(a: u64, b: u64) -> Result<u64, OciError> {
    a.checked_add(b)
        .ok_or_else(|| err(OciErrorCode::Internal, "size overflow"))
}

/// `Digest` を一度だけ計測するためのキャッシュ付きサイズ表。
struct SizeCache<'a> {
    root: &'a Path,
    sizes: BTreeMap<Digest, Option<u64>>,
}

impl<'a> SizeCache<'a> {
    fn new(root: &'a Path) -> Self {
        Self {
            root,
            sizes: BTreeMap::new(),
        }
    }

    fn get(&mut self, d: &Digest) -> Result<Option<u64>, OciError> {
        if let Some(v) = self.sizes.get(d) {
            return Ok(*v);
        }
        let v = blob_size(self.root, d)?;
        self.sizes.insert(d.clone(), v);
        Ok(v)
    }
}

impl ReferenceTable {
    /// `image ls` 相当。登録済みの manifest をタグごとの行で返す。排他の内側で呼ぶこと。
    ///
    /// 欠損 blob があっても失敗させず、行の `missing_blobs` に載せる。
    /// `blobs` / `blobs/sha256` が symlink・非ディレクトリなら `system df` と同様に辿らず
    /// `FailedPrecondition`（存在しない場合は全 blob が欠損扱い）。
    pub fn list_images(&self, root: &Path) -> Result<ImageList, OciError> {
        if checked_dir(&root.join("blobs"))? {
            checked_dir(&blob_dir(root))?;
        }
        let mut cache = SizeCache::new(root);
        let mut per_manifest: BTreeMap<&Digest, (u64, Vec<Digest>)> = BTreeMap::new();
        for (digest, comp) in self.manifests() {
            let mut total = 0u64;
            let mut missing = Vec::new();
            for blob in comp.blobs() {
                match cache.get(blob)? {
                    Some(n) => total = add(total, n)?,
                    None => missing.push(blob.clone()),
                }
            }
            per_manifest.insert(digest, (total, missing));
        }
        let mut entries = Vec::new();
        let mut tagged: BTreeSet<&Digest> = BTreeSet::new();
        for (key, digest) in self.tags() {
            let Some((size, missing)) = per_manifest.get(digest) else {
                continue;
            };
            tagged.insert(digest);
            entries.push(ImageEntry {
                tag: Some(key.clone()),
                digest: digest.clone(),
                size_bytes: *size,
                missing_blobs: missing.clone(),
            });
        }
        for (digest, (size, missing)) in &per_manifest {
            if tagged.contains(digest) {
                continue;
            }
            entries.push(ImageEntry {
                tag: None,
                digest: (*digest).clone(),
                size_bytes: *size,
                missing_blobs: missing.clone(),
            });
        }
        Ok(ImageList { entries })
    }

    /// `system df` 相当。イメージ側とキャッシュ側の使用容量を返す。排他の内側で呼ぶこと。
    ///
    /// `blobs` / `blobs/sha256` が symlink・非ディレクトリなら辿らず `FailedPrecondition`。
    /// 走査が `MAX_CACHE_SCAN_ENTRIES` を超えたら `ResourceExhausted`。
    pub fn disk_usage(&self, root: &Path) -> Result<DiskUsage, OciError> {
        let mut cache = SizeCache::new(root);
        let mut union: BTreeSet<&Digest> = BTreeSet::new();
        let mut count = 0usize;
        for (_, comp) in self.manifests() {
            count += 1;
            union.extend(comp.blobs());
        }
        let mut images = ImageUsage {
            count,
            ..ImageUsage::default()
        };
        for blob in &union {
            match cache.get(blob)? {
                Some(n) => {
                    images.bytes = add(images.bytes, n)?;
                    if !self.blob_references(blob).is_referenced() {
                        images.reclaimable_bytes = add(images.reclaimable_bytes, n)?;
                    }
                }
                None => images.missing_blobs += 1,
            }
        }
        let cache_usage = scan_cache(root, &union)?;
        Ok(DiskUsage {
            images,
            cache: cache_usage,
        })
    }
}

fn is_hex64(name: &str) -> bool {
    name.len() == 64 && name.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// ディレクトリが実在の通常ディレクトリか。存在しなければ `Ok(false)`、symlink 等は拒否。
fn checked_dir(path: &Path) -> Result<bool, OciError> {
    match fs::symlink_metadata(path) {
        Ok(m) if m.is_dir() => Ok(true),
        Ok(_) => Err(err(
            OciErrorCode::FailedPrecondition,
            "blob directory is not a plain directory",
        )),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(false),
        Err(_) => Err(err(OciErrorCode::Internal, "failed to stat blob directory")),
    }
}

fn scan_cache(root: &Path, registered: &BTreeSet<&Digest>) -> Result<CacheUsage, OciError> {
    let mut usage = CacheUsage::default();
    if !checked_dir(&root.join("blobs"))? || !checked_dir(&blob_dir(root))? {
        return Ok(usage);
    }
    let rd = fs::read_dir(blob_dir(root))
        .map_err(|_| err(OciErrorCode::Internal, "failed to read blob directory"))?;
    let mut seen = 0usize;
    for ent in rd {
        seen += 1;
        if seen > MAX_CACHE_SCAN_ENTRIES {
            return Err(err(
                OciErrorCode::ResourceExhausted,
                "too many entries in blob directory",
            ));
        }
        let ent = ent.map_err(|_| err(OciErrorCode::Internal, "failed to read blob entry"))?;
        let name = ent.file_name();
        let meta = fs::symlink_metadata(ent.path());
        let (Some(name), Ok(meta)) = (name.to_str(), meta) else {
            usage.foreign_entries += 1;
            continue;
        };
        if !is_hex64(name) || !meta.is_file() {
            usage.foreign_entries += 1;
            continue;
        }
        let digest = Digest::parse(&format!("sha256:{name}"))?;
        usage.blob_count += 1;
        usage.bytes = add(usage.bytes, meta.len())?;
        if !registered.contains(&digest) {
            usage.unregistered_count += 1;
            usage.unregistered_bytes = add(usage.unregistered_bytes, meta.len())?;
        }
    }
    Ok(usage)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::image_management::{ContainerRefId, ManifestComposition, PullId};
    use crate::reference::{RegistryHost, Repository, Tag};

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
        fn new(tag: &str) -> Self {
            let p = std::env::temp_dir().join(format!("fc-oci-usage-{tag}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&p);
            fs::create_dir_all(blob_dir(&p)).unwrap();
            Root(p)
        }
        fn put(&self, dg: &Digest, len: usize) {
            fs::write(blob_path(&self.0, dg).unwrap(), vec![0u8; len]).unwrap();
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

    /// OCI-7: タグごとに 1 行、digest とサイズは具体値。
    #[test]
    fn oci7_ls_lists_each_tag_with_digest_and_size() {
        let root = Root::new("ls-tags");
        let mut t = fixture(&root);
        t.register_tag(tk("v1"), &d(0xa0)).unwrap();
        t.register_tag(tk("v2"), &d(0xb0)).unwrap();
        let l = t.list_images(&root.0).unwrap();
        assert_eq!(l.entries.len(), 2);
        assert_eq!(l.entries[0].tag, Some(tk("v1")));
        assert_eq!(l.entries[0].digest, d(0xa0));
        assert_eq!(l.entries[0].size_bytes, 1110);
        assert_eq!(l.entries[1].size_bytes, 2120);
        assert!(l.entries[1].missing_blobs.is_empty());
    }

    /// OCI-7: タグのない manifest は tag なしで 1 回だけ載る。
    #[test]
    fn oci7_ls_untagged_manifest_listed_once_without_tag() {
        let root = Root::new("ls-untagged");
        let mut t = fixture(&root);
        t.register_tag(tk("v1"), &d(0xa0)).unwrap();
        let l = t.list_images(&root.0).unwrap();
        assert_eq!(l.entries.len(), 2);
        assert_eq!(l.entries[1].tag, None);
        assert_eq!(l.entries[1].digest, d(0xb0));
    }

    /// OCI-7: 欠損 blob は失敗にせず行に載る。
    #[test]
    fn oci7_ls_reports_missing_blob_without_failing() {
        let root = Root::new("ls-missing");
        let t = fixture(&root);
        fs::remove_file(blob_path(&root.0, &d(0x11)).unwrap()).unwrap();
        let l = t.list_images(&root.0).unwrap();
        assert_eq!(l.entries[0].missing_blobs, vec![d(0x11)]);
        assert_eq!(l.entries[0].size_bytes, 110);
    }

    /// OCI-7: symlink の blob は辿らず欠損扱い。
    #[cfg(unix)]
    #[test]
    fn oci7_ls_does_not_follow_symlinked_blob() {
        let root = Root::new("ls-symlink");
        let t = fixture(&root);
        let p = blob_path(&root.0, &d(0x11)).unwrap();
        fs::remove_file(&p).unwrap();
        std::os::unix::fs::symlink(blob_path(&root.0, &d(0x12)).unwrap(), &p).unwrap();
        let l = t.list_images(&root.0).unwrap();
        assert_eq!(l.entries[0].missing_blobs, vec![d(0x11)]);
        assert_eq!(l.entries[0].size_bytes, 110);
    }

    /// OCI-7: 共有レイヤーは二重計上しない。
    #[test]
    fn oci7_df_counts_shared_layer_once() {
        let root = Root::new("df-shared");
        let t = fixture(&root);
        let u = t.disk_usage(&root.0).unwrap();
        assert_eq!(u.images.count, 2);
        assert_eq!(u.images.bytes, 3130);
        assert_eq!(u.images.missing_blobs, 0);
        assert_eq!(u.cache.bytes, 3130);
        assert_eq!(u.cache.blob_count, 5);
    }

    /// OCI-7: 参照のある blob は回収可能に入らない。
    #[test]
    fn oci7_df_reclaimable_excludes_referenced_and_leased() {
        let root = Root::new("df-reclaim");
        let mut t = fixture(&root);
        assert_eq!(
            t.disk_usage(&root.0).unwrap().images.reclaimable_bytes,
            3130
        );
        t.register_tag(tk("v1"), &d(0xa0)).unwrap();
        assert_eq!(
            t.disk_usage(&root.0).unwrap().images.reclaimable_bytes,
            2020
        );
        t.register_container(ContainerRefId::new("c1").unwrap(), &d(0xb0))
            .unwrap();
        assert_eq!(t.disk_usage(&root.0).unwrap().images.reclaimable_bytes, 0);
        let mut t2 = fixture(&root);
        t2.acquire_lease(d(0x12), PullId::new("p1").unwrap());
        assert_eq!(
            t2.disk_usage(&root.0).unwrap().images.reclaimable_bytes,
            1130
        );
    }

    /// OCI-7: 未登録 blob と foreign エントリを分けて数える。
    #[test]
    fn oci7_df_cache_counts_unregistered_and_foreign_entries() {
        let root = Root::new("df-cache");
        let t = fixture(&root);
        root.put(&d(0x99), 500);
        fs::write(blob_dir(&root.0).join("not-a-digest"), b"x").unwrap();
        fs::create_dir(blob_dir(&root.0).join("77".repeat(32))).unwrap();
        let u = t.disk_usage(&root.0).unwrap();
        assert_eq!(u.cache.blob_count, 6);
        assert_eq!(u.cache.bytes, 3630);
        assert_eq!(u.cache.unregistered_count, 1);
        assert_eq!(u.cache.unregistered_bytes, 500);
        assert_eq!(u.cache.foreign_entries, 2);
    }

    /// OCI-7: blob ディレクトリが無ければキャッシュ側は 0。
    #[test]
    fn oci7_df_missing_blob_dir_is_zero() {
        let root = Root::new("df-nodir");
        fs::remove_dir_all(root.0.join("blobs")).unwrap();
        let u = ReferenceTable::new().disk_usage(&root.0).unwrap();
        assert_eq!(u, DiskUsage::default());
    }

    /// OCI-7: symlink の blob ディレクトリは辿らず拒否する。
    #[cfg(unix)]
    #[test]
    fn oci7_df_rejects_symlinked_blob_dir() {
        let root = Root::new("df-symlink");
        let other = root.0.join("other");
        fs::create_dir_all(&other).unwrap();
        fs::remove_dir_all(blob_dir(&root.0)).unwrap();
        std::os::unix::fs::symlink(&other, blob_dir(&root.0)).unwrap();
        let e = ReferenceTable::new().disk_usage(&root.0).unwrap_err();
        assert_eq!(e.code(), OciErrorCode::FailedPrecondition);
    }

    /// OCI-7: `image ls` も symlink の blob ディレクトリを辿らず拒否する（`system df` と一貫）。
    #[cfg(unix)]
    #[test]
    fn oci7_ls_rejects_symlinked_blob_dir() {
        let root = Root::new("ls-symlink-dir");
        let other = root.0.join("other");
        fs::create_dir_all(&other).unwrap();
        fs::remove_dir_all(blob_dir(&root.0)).unwrap();
        std::os::unix::fs::symlink(&other, blob_dir(&root.0)).unwrap();
        let e = ReferenceTable::new().list_images(&root.0).unwrap_err();
        assert_eq!(e.code(), OciErrorCode::FailedPrecondition);
    }
}
