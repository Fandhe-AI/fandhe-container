//! レイヤーの展開後サイズ（tar ストリーム長）の計測（OCI-7・TASK-183・#2222）。
//!
//! 既存の `ImageUsage::bytes` / `CacheUsage::bytes` は圧縮済み blob の見かけのサイズで、展開後の
//! 大きさではない。展開後サイズは blob を末尾まで読み出して求めるため CPU と時間がかかる。
//! `ImageStoreGuard` を持ったまま GB 単位の展開をすると他の操作が 5 秒で Timeout するため（REPAIR-5）、
//! 二段階にする。
//!
//! 1. ガードの内側で [`ReferenceTable::expanded_size_plan`]（digest の複製だけ。ファイルに触れない）
//! 2. ガードを手放した後で [`ExpandedSizePlan::measure`]（blob は content-addressed で不変なので、
//!    ロックの外で読んでも整合する。計測中に GC で消えた blob は `missing_layers` に数える）
//!
//! 種別は mediaType を持たないため、先頭のマジックバイトで判定する（gzip と非圧縮 tar）。zstd 等は
//! 展開側も未実装なので推測せず `unmeasured_layers` に数える。gzip は EOF まで読むので CRC32 と ISIZE も
//! 検証されるが、これは digest 検証を兼ねない（検証済みを装わない）。上限超過・破損は黙って過少にせず
//! `unmeasured_layers` の件数で示す。

use std::collections::BTreeSet;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;

use super::{add, blob_hex, err};
use crate::error::{OciError, OciErrorCode};
use crate::image_management::root_handle::BlobDir;
use crate::image_management::{JournalRoot, ReferenceTable};
use crate::layer::{
    DEFAULT_MAX_UNCOMPRESSED_LAYER_BYTES, GzipLayerReader, oci_error_from_layer_io,
};
use crate::reference::Digest;

/// 1 回の計測で展開してよい合計バイト数の上限（超えたら `ResourceExhausted`）。
pub const MAX_EXPANDED_SCAN_BYTES: u64 = 256 * 1024 * 1024 * 1024;

/// 種別判定のために読む先頭バイト数（tar の `ustar` は offset 257）。
const HEADER_PROBE_BYTES: u64 = 512;

/// 展開後サイズの計測結果。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct ExpandedUsage {
    /// 共有レイヤーを 1 回だけ数えた、展開後の tar ストリーム長の合計。
    pub expanded_bytes: u64,
    /// 計測できたレイヤー数。
    pub measured_layers: usize,
    /// blob が無い（通常ファイルでない・symlink を含む）レイヤー数。
    pub missing_layers: usize,
    /// 計測しなかったレイヤー数（zstd 等の未対応形式・展開後サイズの上限超過・形式不正）。合計に含まれない。
    pub unmeasured_layers: usize,
}

/// ガードの内側で取る計測計画（レイヤー digest の和集合。config blob はレイヤーではないので含めない）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpandedSizePlan {
    layers: BTreeSet<Digest>,
    /// 計画を取った排他区間の検査済み root（#2695）。`measure` がガードの外でも、渡されたパスをこれと
    /// 照合し、読み取りをこの fd 起点に閉じ込める。単体テーブル（未設定）では `measure` がパスから開く。
    root: JournalRoot,
}

impl ReferenceTable {
    /// 展開後サイズの計測計画を作る。digest を複製するだけでファイルには触れない。排他の内側で呼ぶこと。
    pub fn expanded_size_plan(&self) -> ExpandedSizePlan {
        let mut layers = BTreeSet::new();
        for (_, comp) in self.manifests() {
            layers.extend(comp.layers().iter().cloned());
        }
        ExpandedSizePlan {
            layers,
            root: self.journal_root.share(),
        }
    }
}

/// 計測できないレイヤーの分類。
enum LayerOutcome {
    Measured(u64),
    Missing,
    Unmeasured,
}

impl ExpandedSizePlan {
    /// 計画に含まれるレイヤー数。
    pub fn layer_count(&self) -> usize {
        self.layers.len()
    }

    /// 計画のレイヤーの展開後サイズを計測する。`ImageStoreGuard` の外で呼ぶこと。
    ///
    /// `blobs` / `blobs/sha256` が symlink・非ディレクトリなら `FailedPrecondition`。合計が
    /// [`MAX_EXPANDED_SCAN_BYTES`] を超えたら `ResourceExhausted`。権限・I/O の失敗は `Internal`。
    /// 非 Unix では blob を安全に開けないため `Unimplemented`（`open_blob_nofollow` と同じ fail-closed）。
    ///
    /// 読み取りは検査済み root の fd 起点（#2695）。計画を排他区間で取った場合、`root` がその区間の root と
    /// 別のディレクトリなら `InvalidArgument`（ガードを手放した後に差し替えられたパスを読まない）。
    pub fn measure(&self, root: &Path) -> Result<ExpandedUsage, OciError> {
        let handle = self.root.resolve_read(root)?;
        let blobs = handle.open_blob_dir()?;
        let mut usage = ExpandedUsage::default();
        // 成功・失敗を問わず実際に展開した量の累計（報告用の `expanded_bytes` とは別に予算を管理する）。
        let mut scanned: u64 = 0;
        for digest in &self.layers {
            let Some(dir) = blobs.as_ref() else {
                usage.missing_layers += 1;
                continue;
            };
            let remaining = MAX_EXPANDED_SCAN_BYTES.saturating_sub(scanned);
            let (outcome, consumed) = measure_layer(dir, digest, remaining)?;
            scanned = add(scanned, consumed)?;
            if scanned > MAX_EXPANDED_SCAN_BYTES {
                return Err(err(
                    OciErrorCode::ResourceExhausted,
                    "expanded size scan exceeds the total budget",
                ));
            }
            match outcome {
                LayerOutcome::Measured(n) => {
                    usage.expanded_bytes = add(usage.expanded_bytes, n)?;
                    usage.measured_layers += 1;
                }
                LayerOutcome::Missing => usage.missing_layers += 1,
                LayerOutcome::Unmeasured => usage.unmeasured_layers += 1,
            }
        }
        Ok(usage)
    }
}

/// 1 レイヤーを計測し、結果と実際に展開した量（失敗時も含む）を返す。`remaining` は総予算の残りで、
/// 展開側の上限をこれに絞る（残りを 1 バイト超えた時点で打ち切り、呼び出し側が総予算超過を判定する）。
fn measure_layer(
    dir: &BlobDir,
    digest: &Digest,
    remaining: u64,
) -> Result<(LayerOutcome, u64), OciError> {
    // 無い・通常ファイルでない（symlink 等）・開く間に差し替えられた blob は欠損として扱う。
    let Some(mut file) = dir.open_file(blob_hex(digest)?)? else {
        return Ok((LayerOutcome::Missing, 0));
    };
    let io_internal = |_: io::Error| err(OciErrorCode::Internal, "failed to read layer blob");
    let mut header = Vec::new();
    (&mut file)
        .take(HEADER_PROBE_BYTES)
        .read_to_end(&mut header)
        .map_err(io_internal)?;
    // 同じハンドルを先頭へ戻す（パスを解決し直さない）。
    file.seek(SeekFrom::Start(0)).map_err(io_internal)?;
    if header.starts_with(&[0x1f, 0x8b]) {
        let limit = DEFAULT_MAX_UNCOMPRESSED_LAYER_BYTES.min(remaining.saturating_add(1));
        let mut reader = GzipLayerReader::new(file, limit);
        let res = io::copy(&mut reader, &mut io::sink());
        // 失敗（上限超過・CRC 不一致）でも、そこまでに展開した量は総予算へ計上する。
        let consumed = reader.total_out();
        return match res {
            Ok(_) => Ok((LayerOutcome::Measured(consumed), consumed)),
            Err(e) => {
                let oe = oci_error_from_layer_io(e);
                match oe.code() {
                    OciErrorCode::ResourceExhausted | OciErrorCode::DataLoss => {
                        Ok((LayerOutcome::Unmeasured, consumed))
                    }
                    _ => Err(oe),
                }
            }
        };
    }
    if header.get(257..262) == Some(b"ustar".as_slice()) {
        let len = file.metadata().map_err(io_internal)?.len();
        return Ok((LayerOutcome::Measured(len), len));
    }
    // zstd（28 b5 2f fd）とその他: 展開側も未実装なので推測しない。
    Ok((LayerOutcome::Unmeasured, 0))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::image_management::ManifestComposition;
    use crate::image_management::usage::blob_path;
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::fs;
    use std::io::Write;

    fn d(n: u8) -> Digest {
        Digest::parse(&format!("sha256:{}", format!("{n:02x}").repeat(32))).unwrap()
    }

    struct Root(std::path::PathBuf);
    impl Root {
        fn new(tag: &str) -> Self {
            let p =
                std::env::temp_dir().join(format!("fc-oci-expanded-{tag}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&p);
            fs::create_dir_all(blob_path(&p, &d(0)).unwrap().parent().unwrap()).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).expect("chmod");
            }
            Root(p)
        }
        fn put(&self, n: u8, bytes: &[u8]) {
            fs::write(blob_path(&self.0, &d(n)).unwrap(), bytes).unwrap();
        }
    }
    impl Drop for Root {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn gz(data: &[u8]) -> Vec<u8> {
        let mut e = GzEncoder::new(Vec::new(), Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    fn ustar(len: usize) -> Vec<u8> {
        let mut v = vec![0u8; len];
        v[257..262].copy_from_slice(b"ustar");
        v
    }

    /// 2 イメージ（A: 0x10, 0x11 / B: 0x10, 0x12）。config は含めない。
    fn table() -> ReferenceTable {
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
        t
    }

    /// OCI-7: gzip は展開後の長さ、非圧縮 tar はファイル長。共有レイヤーは 1 回だけ数える。
    #[test]
    fn oci7_expanded_counts_gzip_plain_and_shared_layer_once() {
        let r = Root::new("basic");
        let t = table();
        r.put(0x10, &gz(&vec![7u8; 100_000]));
        r.put(0x11, &ustar(2048));
        r.put(0x12, &gz(&[1u8; 5000]));
        let plan = t.expanded_size_plan();
        assert_eq!(plan.layer_count(), 3);
        let u = plan.measure(&r.0).unwrap();
        assert_eq!(
            u,
            ExpandedUsage {
                expanded_bytes: 107_048,
                measured_layers: 3,
                missing_layers: 0,
                unmeasured_layers: 0
            }
        );
        // 圧縮済みの値（ファイルの見かけのサイズ）とは別の値で並ぶ。
        let compressed = t.disk_usage(&r.0).unwrap().cache.bytes;
        assert_ne!(compressed, u.expanded_bytes);
    }

    /// OCI-7: zstd と壊れた gzip は unmeasured に数え、合計に入れない。
    #[test]
    fn oci7_expanded_unsupported_and_corrupt_are_unmeasured() {
        let r = Root::new("unmeasured");
        let t = table();
        r.put(0x10, &gz(&[0u8; 300]));
        r.put(0x11, &[0x28, 0xb5, 0x2f, 0xfd, 1, 2, 3]);
        let mut bad = gz(&[5u8; 4000]);
        let n = bad.len();
        bad.truncate(n - 12);
        r.put(0x12, &bad);
        let u = t.expanded_size_plan().measure(&r.0).unwrap();
        assert_eq!(u.expanded_bytes, 300);
        assert_eq!(u.measured_layers, 1);
        assert_eq!(u.unmeasured_layers, 2);
        assert_eq!(u.missing_layers, 0);
    }

    /// OCI-7: plan の後に blob が消えても失敗にせず missing に数える。symlink の blob は辿らない。
    #[test]
    fn oci7_expanded_missing_after_plan_and_symlink_not_followed() {
        let r = Root::new("missing");
        let t = table();
        r.put(0x10, &gz(&[0u8; 10]));
        r.put(0x11, &gz(&[0u8; 20]));
        r.put(0x12, &gz(&[0u8; 30]));
        let plan = t.expanded_size_plan();
        fs::remove_file(blob_path(&r.0, &d(0x11)).unwrap()).unwrap();
        let p12 = blob_path(&r.0, &d(0x12)).unwrap();
        let target = blob_path(&r.0, &d(0x10)).unwrap();
        fs::remove_file(&p12).unwrap();
        std::os::unix::fs::symlink(&target, &p12).unwrap();
        let u = plan.measure(&r.0).unwrap();
        assert_eq!(u.expanded_bytes, 10);
        assert_eq!(u.measured_layers, 1);
        assert_eq!(u.missing_layers, 2);
    }

    /// OCI-7: ガードの内側で plan を取り、ガードを手放した後に計測できる（ガードの外で計測する契約）。
    #[test]
    fn oci7_expanded_plan_under_guard_then_measure_outside() {
        let r = Root::new("guard");
        let t = table();
        r.put(0x10, &gz(&[0u8; 11]));
        r.put(0x11, &gz(&[0u8; 22]));
        r.put(0x12, &gz(&[0u8; 33]));
        let store = crate::image_management::ImageStore::with_table(&r.0, t).unwrap();
        let plan = {
            let guard = store.lock().unwrap();
            guard.expanded_size_plan()
        };
        // ガードは手放し済み。別の操作がロックを取れる状態で計測する。
        let _other = store.lock().unwrap();
        drop(_other);
        assert_eq!(plan.measure(&r.0).unwrap().expanded_bytes, 66);
    }

    /// OCI-7: blob ディレクトリが無ければ全レイヤーが missing。
    #[test]
    fn oci7_expanded_without_blob_dir_is_all_missing() {
        let r = Root::new("nodir");
        let t = table();
        fs::remove_dir_all(r.0.join("blobs")).unwrap();
        let u = t.expanded_size_plan().measure(&r.0).unwrap();
        assert_eq!(u.missing_layers, 3);
        assert_eq!(u.expanded_bytes, 0);
    }
}
