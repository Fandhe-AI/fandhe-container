//! `image ls` / `system df` 相当の集計 API（OCI-7・TASK-183.3・MS-4・#478）。
//!
//! 参照テーブル（`ReferenceTable`）が持つ manifest 構成とタグを、ローカルキャッシュ
//! （`<root>/blobs/sha256/<hex>`。cri の `image_pull` と同じ配置）の実ファイルと突き合わせ、
//! 一覧の行（repository・tag・digest・サイズ）と使用容量を返す。参照テーブルはサイズを持たないため、
//! サイズはここで blob ファイルを（symlink を辿らず）stat して求める。
//!
//! 読み取りはすべて検査済み root の fd（`RootHandle`。#2638）起点で行う（#2695）。Linux の x86_64 / aarch64 では
//! `openat2` で root の外・symlink・マウントへ出ず、検査後に root が差し替えられても数えるのは検査済みの実体だけ。
//! 他の OS は従来どおりパス起点で、差し替えは入口の再検査（`ImageStore::lock`）だけで検出する。排他区間の中で
//! 区間の root と別のディレクトリを指すパスは `InvalidArgument` で拒否する（`root_handle_for`）。
//!
//! 呼び出し文脈: 読み取り専用で、削除も書き込みもしない。テーブルとキャッシュの整合を取るため、
//! 呼び出し側が `ImageStoreGuard`（#473）を保持したまま、ガードの `Deref` 越しに呼ぶ前提で、本モジュールは排他をかけない
//! （`remove` と同じ契約。ガードなしでテーブルを読む経路は公開 API に無い）。
//! 参照テーブルに未登録のもの（pull 中のステージング）は一覧に現れない（公開完了まで見えない。OCI-7）。
//!
//! サイズの定義: キャッシュ上の blob ファイルの見かけのサイズ（圧縮済みのバイト数）。
//! 3 OS 共通の API で取れ、フィクスチャの既知合計と一致するため、割り当てブロック数は使わない。
//! 報告するサイズは digest 検証を兼ねない（内容の検証済みを装わない）。
//!
//! ステージング（`<root>/staging/<pull-id>/`）の使用容量は `disk_usage` が `DiskUsage::staging` に載せる
//! （`staging` サブモジュール。#2222）。コンテナ（bundle・rootfs）は core の領域で oci は core に依存しないため、
//! core の `measure_container_usage` の結果を呼び出し側が [`ContainersUsage`] に写して
//! [`DiskUsage::with_containers`] で合成する。展開後サイズは重いので `disk_usage` には含めず、
//! `expanded_size_plan`（ガードの内側）と `ExpandedSizePlan::measure`（ガードの外）の二段階 API で取り、
//! [`DiskUsage::with_expanded`] で合成する（`expanded` サブモジュール）。containers・展開後の計測は
//! `ImageStoreGuard` を持ったまま行わない（他の操作が Timeout する。REPAIR-5）。
//! 手順は「ガードの外で core を計測 → ガードの内側で `disk_usage` と plan → ガードの外で `measure`」。
//!
//! 圧縮済みのバイト数（`ImageUsage::bytes`・`CacheUsage::bytes`）と展開後サイズ・コンテナの容量は別の項目で、足し合わせない。
//!
//! 未実装（実装済みを装わない。REPAIR-3）: CLI 経路（`image ls` / `system df` のサブコマンド。#2221）、
//! 展開後サイズ・staging 走査の計装（#2223）。
//!
//! 計装（REPAIR-4）: `list_images_with` / `disk_usage_with` が `OciOpRecorder` へ成功・失敗と
//! 所要時間を渡す。`list_images` / `disk_usage` は何も記録しない `NoopOciOpRecorder` 版。

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use super::root_handle::{BlobDir, RootHandle};
use super::{IMAGE_STORE_BLOB_DIR, ReferenceTable, TagKey};

mod expanded;
mod staging;
use crate::error::{OciError, OciErrorCode};
use crate::instrument::{NoopOciOpRecorder, OciOpKind, OciOpRecorder, record_oci_op};
use crate::reference::Digest;
pub use expanded::{ExpandedSizePlan, ExpandedUsage, MAX_EXPANDED_SCAN_BYTES};
pub use staging::StagingUsage;

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

/// コンテナ領域（bundle・rootfs）の使用容量。core の `ContainerDiskUsage` と同じ意味の値型で、
/// oci は core に依存しないため呼び出し側が写して [`DiskUsage::with_containers`] へ渡す。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct ContainersUsage {
    /// コンテナ数。
    pub count: usize,
    /// bundle と rootfs の通常ファイルの見かけのサイズの合計（ハードリンクは 1 回）。
    pub bytes: u64,
    /// bundle が存在しない件数。
    pub missing_bundles: usize,
    /// `config.json` を読めず rootfs を特定できなかった件数。
    pub unreadable_configs: usize,
    /// 権限不足などで読めなかったエントリ数。
    pub inaccessible_entries: usize,
    /// 別のファイルシステムのため降りなかったディレクトリ数。
    pub mount_points_skipped: usize,
}

impl ContainersUsage {
    /// 各値から作る（`#[non_exhaustive]` のため外部 crate はこの入口で組み立てる）。
    pub fn new(
        count: usize,
        bytes: u64,
        missing_bundles: usize,
        unreadable_configs: usize,
        inaccessible_entries: usize,
        mount_points_skipped: usize,
    ) -> Self {
        Self {
            count,
            bytes,
            missing_bundles,
            unreadable_configs,
            inaccessible_entries,
            mount_points_skipped,
        }
    }
}

/// `system df` 相当の結果。
///
/// `images.bytes`・`cache.bytes` は圧縮済み blob の見かけのサイズ。`containers`・`expanded` は oci 単独では
/// 測れない・重いため `None`（未計測）で始まり、呼び出し側が `with_*` で合成する。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct DiskUsage {
    /// 登録済みイメージ側。
    pub images: ImageUsage,
    /// キャッシュ側。
    pub cache: CacheUsage,
    /// pull 中のステージング領域。
    pub staging: StagingUsage,
    /// コンテナ領域。`None` は未計測。
    pub containers: Option<ContainersUsage>,
    /// 展開後サイズ。`None` は未計測。
    pub expanded: Option<ExpandedUsage>,
}

impl DiskUsage {
    /// コンテナ領域の計測結果を合成する。
    pub fn with_containers(mut self, containers: ContainersUsage) -> Self {
        self.containers = Some(containers);
        self
    }

    /// 展開後サイズの計測結果を合成する。
    pub fn with_expanded(mut self, expanded: ExpandedUsage) -> Self {
        self.expanded = Some(expanded);
        self
    }
}

fn err(code: OciErrorCode, msg: &str) -> OciError {
    OciError::new(code, msg)
}

/// blob の置き場 `<root>/blobs/sha256`。
pub(super) fn blob_dir(root: &Path) -> PathBuf {
    root.join(IMAGE_STORE_BLOB_DIR[0])
        .join(IMAGE_STORE_BLOB_DIR[1])
}

/// 検証済み `Digest` の hex 部だけからパスを組み立てる。
pub(super) fn blob_path(root: &Path, digest: &Digest) -> Result<PathBuf, OciError> {
    let hex = digest
        .as_str()
        .strip_prefix("sha256:")
        .ok_or_else(|| err(OciErrorCode::Internal, "unsupported digest algorithm"))?;
    Ok(blob_dir(root).join(hex))
}

/// `Digest` の hex 部（`sha256:` 以外は拒否）。
pub(super) fn blob_hex(digest: &Digest) -> Result<&str, OciError> {
    digest
        .as_str()
        .strip_prefix("sha256:")
        .ok_or_else(|| err(OciErrorCode::Internal, "unsupported digest algorithm"))
}

/// blob 1 件のサイズ。存在しない・symlink・通常ファイルでないものは `None`（辿らない）。
/// `dir` が `None`（`blobs/sha256` が無い）なら全 blob が欠損。
fn blob_size(dir: Option<&BlobDir>, digest: &Digest) -> Result<Option<u64>, OciError> {
    let hex = blob_hex(digest)?;
    let Some(dir) = dir else {
        return Ok(None);
    };
    match dir.stat(hex) {
        Ok(Some(m)) if m.is_file() => Ok(Some(m.len())),
        Ok(_) => Ok(None),
        Err(_) => Err(err(OciErrorCode::Internal, "failed to stat blob")),
    }
}

fn add(a: u64, b: u64) -> Result<u64, OciError> {
    a.checked_add(b)
        .ok_or_else(|| err(OciErrorCode::Internal, "size overflow"))
}

/// `Digest` を一度だけ計測するためのキャッシュ付きサイズ表。
struct SizeCache<'a> {
    dir: Option<&'a BlobDir>,
    sizes: BTreeMap<Digest, Option<u64>>,
}

impl<'a> SizeCache<'a> {
    fn new(dir: Option<&'a BlobDir>) -> Self {
        Self {
            dir,
            sizes: BTreeMap::new(),
        }
    }

    fn get(&mut self, d: &Digest) -> Result<Option<u64>, OciError> {
        if let Some(v) = self.sizes.get(d) {
            return Ok(*v);
        }
        let v = blob_size(self.dir, d)?;
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
    ///
    /// 排他区間の中で `root` が区間の root と別のディレクトリなら `InvalidArgument`（#2695。読み取りは検査済み
    /// root の fd 起点で行う）。
    pub fn list_images(&self, root: &Path) -> Result<ImageList, OciError> {
        self.list_images_with(&NoopOciOpRecorder, root)
    }

    /// 計装つきの `list_images`（エラー終了も含め結果と所要時間を記録する。REPAIR-4）。
    pub fn list_images_with(
        &self,
        recorder: &dyn OciOpRecorder,
        root: &Path,
    ) -> Result<ImageList, OciError> {
        record_oci_op(recorder, OciOpKind::ListImages, || {
            self.list_images_inner(root)
        })
    }

    fn list_images_inner(&self, root: &Path) -> Result<ImageList, OciError> {
        let handle = self.root_handle_for_read(root)?;
        self.list_images_at(&handle)
    }

    /// `list_images` の本体（検査済み root のハンドル起点。差し替え試験が直接渡す）。
    pub(super) fn list_images_at(&self, root: &RootHandle) -> Result<ImageList, OciError> {
        let blobs = root.open_blob_dir()?;
        let mut cache = SizeCache::new(blobs.as_ref());
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

    /// `system df` 相当。イメージ側・キャッシュ側・ステージングの使用容量を返す。排他の内側で呼ぶこと。
    /// `containers` と `expanded` は `None`（呼び出し側が `with_*` で合成する）。
    ///
    /// `blobs` / `blobs/sha256` が symlink・非ディレクトリなら辿らず `FailedPrecondition`。
    /// 走査が `MAX_CACHE_SCAN_ENTRIES` を超えたら `ResourceExhausted`。
    /// 排他区間の中で `root` が区間の root と別のディレクトリなら `InvalidArgument`（#2695）。
    pub fn disk_usage(&self, root: &Path) -> Result<DiskUsage, OciError> {
        self.disk_usage_with(&NoopOciOpRecorder, root)
    }

    /// 計装つきの `disk_usage`（エラー終了も含め結果と所要時間を記録する。REPAIR-4）。
    pub fn disk_usage_with(
        &self,
        recorder: &dyn OciOpRecorder,
        root: &Path,
    ) -> Result<DiskUsage, OciError> {
        record_oci_op(recorder, OciOpKind::DiskUsage, || {
            self.disk_usage_inner(root)
        })
    }

    fn disk_usage_inner(&self, root: &Path) -> Result<DiskUsage, OciError> {
        let handle = self.root_handle_for_read(root)?;
        self.disk_usage_at(&handle)
    }

    /// `disk_usage` の本体（検査済み root のハンドル起点。差し替え試験が直接渡す）。
    pub(super) fn disk_usage_at(&self, root: &RootHandle) -> Result<DiskUsage, OciError> {
        // blob を stat する前にディレクトリ構成を検証する（symlink・非ディレクトリは辿らず拒否）。
        // 開いた `blobs/sha256` を images 側と cache 側で共有し、2 つの読み取りの間の差し替えも閉じる。
        let blobs = root.open_blob_dir()?;
        let mut cache = SizeCache::new(blobs.as_ref());
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
        // 保護対象 blob（参照のある manifest の構成と、pull リース付き blob）を先に一度だけ集める。
        let mut protected: BTreeSet<&Digest> = self.pull_leases.keys().collect();
        for (digest, comp) in self.manifests() {
            if self.manifest_references(digest).is_referenced() {
                protected.extend(comp.blobs());
            }
        }
        for blob in &union {
            match cache.get(blob)? {
                Some(n) => {
                    images.bytes = add(images.bytes, n)?;
                    if !protected.contains(blob) {
                        images.reclaimable_bytes = add(images.reclaimable_bytes, n)?;
                    }
                }
                None => images.missing_blobs += 1,
            }
        }
        let cache_usage = match &blobs {
            Some(dir) => scan_cache(dir, &union)?,
            None => CacheUsage::default(),
        };
        // staging は 1 階層・メタデータだけの走査なのでガードの内側でも軽い（#2222）。
        let staging = staging::scan_staging(root)?;
        Ok(DiskUsage {
            images,
            cache: cache_usage,
            staging,
            ..DiskUsage::default()
        })
    }
}

fn is_hex64(name: &str) -> bool {
    name.len() == 64 && name.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// ディレクトリが実在の通常ディレクトリか。存在しなければ `Ok(false)`、symlink 等は拒否。
/// パス起点の実装（root_handle の非 Linux 分岐）だけが使う。
#[cfg(not(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
)))]
fn checked_dir(path: &Path) -> Result<bool, OciError> {
    use std::fs;
    use std::io::ErrorKind;
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

/// `blobs` と `blobs/sha256` を検証する。両方が通常ディレクトリなら `Ok(true)`、
/// どちらかが存在しなければ `Ok(false)`、symlink・非ディレクトリは `FailedPrecondition`。
/// パス起点の実装（root_handle の非 Linux 分岐）だけが使う。
#[cfg(not(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
)))]
pub(super) fn check_blob_dirs(root: &Path) -> Result<bool, OciError> {
    Ok(checked_dir(&root.join(IMAGE_STORE_BLOB_DIR[0]))? && checked_dir(&blob_dir(root))?)
}

fn scan_cache(dir: &BlobDir, registered: &BTreeSet<&Digest>) -> Result<CacheUsage, OciError> {
    let mut usage = CacheUsage::default();
    let rd = dir
        .entries()
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
        let Some(name) = ent.to_str() else {
            usage.foreign_entries += 1;
            continue;
        };
        // 名前が blob でないものは stat せず foreign。計測失敗（権限・I/O）は過少計上せず失敗にする。
        if !is_hex64(name) {
            usage.foreign_entries += 1;
            continue;
        }
        let meta = match dir.stat(name) {
            Ok(Some(m)) => m,
            // 列挙後に消えた blob は存在しないものとして扱う。
            Ok(None) => continue,
            Err(_) => return Err(err(OciErrorCode::Internal, "failed to stat blob entry")),
        };
        if !meta.is_file() {
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
    use std::fs;

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
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).expect("chmod");
            }
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

    /// OCI-7・#473: ストアのガード越しに ls / df を呼べる（排他の内側で集計する契約）。
    #[test]
    fn oci7_ls_and_df_run_under_store_guard() {
        let root = Root::new("guard");
        let table = fixture(&root);
        let store = crate::image_management::ImageStore::with_table(&root.0, table).unwrap();
        let guard = store.lock().unwrap();
        assert_eq!(guard.list_images(&root.0).unwrap().entries.len(), 2);
        assert_eq!(guard.disk_usage(&root.0).unwrap().images.bytes, 3130);
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
        t2.acquire_lease(d(0x12), PullId::new("p1").unwrap())
            .unwrap();
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

    /// OCI-7・#2222: staging のファイルは `cache` / `images` に混ざらず、`staging` に別計上される。
    /// containers・expanded は未計測の `None` で、`with_*` で合成した値が具体値で残る。
    #[test]
    fn oci7_df_staging_is_separate_and_containers_compose() {
        let root = Root::new("df-staging");
        let t = fixture(&root);
        let sdir = root.0.join("staging").join("p1");
        fs::create_dir_all(&sdir).unwrap();
        fs::write(sdir.join("aa"), vec![0u8; 777]).unwrap();
        let u = t.disk_usage(&root.0).unwrap();
        assert_eq!(u.images.bytes, 3130);
        assert_eq!(u.cache.bytes, 3130);
        assert_eq!(u.staging.pulls, 1);
        assert_eq!(u.staging.file_count, 1);
        assert_eq!(u.staging.bytes, 777);
        assert_eq!(u.containers, None);
        assert_eq!(u.expanded, None);
        let c = ContainersUsage::new(2, 4096, 1, 0, 0, 0);
        let u = u.with_containers(c.clone());
        assert_eq!(u.containers, Some(c));
        assert_eq!(u.images.bytes, 3130);
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

    /// OCI-7: `blobs/sha256` が通常ファイルでも `system df` は Internal でなく FailedPrecondition。
    #[test]
    fn oci7_df_rejects_non_directory_blob_dir_before_stat() {
        let root = Root::new("df-file-dir");
        let t = fixture(&root);
        fs::remove_dir_all(blob_dir(&root.0)).unwrap();
        fs::write(blob_dir(&root.0), b"x").unwrap();
        let e = t.disk_usage(&root.0).unwrap_err();
        assert_eq!(e.code(), OciErrorCode::FailedPrecondition);
    }

    /// OCI-7: `blobs` が通常ファイルでも FailedPrecondition。
    #[test]
    fn oci7_df_rejects_non_directory_blobs() {
        let root = Root::new("df-file-blobs");
        let t = fixture(&root);
        fs::remove_dir_all(root.0.join("blobs")).unwrap();
        fs::write(root.0.join("blobs"), b"x").unwrap();
        let e = t.disk_usage(&root.0).unwrap_err();
        assert_eq!(e.code(), OciErrorCode::FailedPrecondition);
    }

    /// OCI-7: blob の stat が権限不足で失敗したら過少計上せず Internal で失敗する。
    #[cfg(unix)]
    #[test]
    fn oci7_df_stat_failure_is_error_not_undercount() {
        use std::os::unix::fs::PermissionsExt;
        let root = Root::new("df-noperm");
        let t = ReferenceTable::new();
        root.put(&d(0x99), 500);
        let dir = blob_dir(&root.0);
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o444)).unwrap();
        let r = t.disk_usage(&root.0);
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        // root 実行など権限が効かない環境では成功して正しい値になる。
        match r {
            Err(e) => assert_eq!(e.code(), OciErrorCode::Internal),
            Ok(u) => assert_eq!(u.cache.bytes, 500),
        }
    }

    #[derive(Debug, Default)]
    struct Collect(std::sync::Mutex<Vec<crate::instrument::OciOpSample>>);
    impl OciOpRecorder for Collect {
        fn record_oci_op(&self, s: &crate::instrument::OciOpSample) {
            self.0.lock().unwrap().push(*s);
        }
    }

    /// REPAIR-4: 成功と失敗の両方で種別・結果・エラー code を 1 件ずつ記録する。
    #[test]
    fn repair4_ls_and_df_record_success_and_failure() {
        use crate::instrument::OciOpOutcome;
        let root = Root::new("instr");
        let t = fixture(&root);
        let rec = Collect::default();
        t.list_images_with(&rec, &root.0).unwrap();
        t.disk_usage_with(&rec, &root.0).unwrap();
        fs::remove_dir_all(blob_dir(&root.0)).unwrap();
        fs::write(blob_dir(&root.0), b"x").unwrap();
        t.list_images_with(&rec, &root.0).unwrap_err();
        t.disk_usage_with(&rec, &root.0).unwrap_err();
        let v = rec.0.lock().unwrap();
        let got: Vec<_> = v
            .iter()
            .map(|s| (s.kind(), s.outcome(), s.error_code()))
            .collect();
        assert_eq!(
            got,
            vec![
                (OciOpKind::ListImages, OciOpOutcome::Success, None),
                (OciOpKind::DiskUsage, OciOpOutcome::Success, None),
                (
                    OciOpKind::ListImages,
                    OciOpOutcome::Failure,
                    Some(OciErrorCode::FailedPrecondition)
                ),
                (
                    OciOpKind::DiskUsage,
                    OciOpOutcome::Failure,
                    Some(OciErrorCode::FailedPrecondition)
                ),
            ]
        );
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
