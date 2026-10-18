//! `image ls` / `system df` 集計 API の結合試験（OCI-7・TASK-183.3・#478）。
//!
//! 公開 API だけを通し、既知サイズの blob を持つフィクスチャの実サイズと表示値を照合する。
//! CLI 経路・展開後サイズ・containers の容量は未実装のため対象外。

use std::fs;
use std::path::PathBuf;

use fandhe_container_oci::image_management::{ManifestComposition, ReferenceTable, TagKey};
use fandhe_container_oci::reference::{Digest, RegistryHost, Repository, Tag};

fn d(n: u8) -> Digest {
    Digest::parse(&format!("sha256:{}", format!("{n:02x}").repeat(32))).expect("digest")
}

fn key(t: &str) -> TagKey {
    TagKey::new(
        RegistryHost::parse("registry.example").expect("host"),
        Repository::parse("lib/app").expect("repo"),
        Tag::parse(t).expect("tag"),
    )
}

struct Fixture {
    root: PathBuf,
    table: ReferenceTable,
    total: u64,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

/// 共有レイヤー 0x10（123457）を持つ 2 イメージ。実ファイルの合計が既知値。
fn fixture(tag: &str) -> Fixture {
    let root = std::env::temp_dir().join(format!("fc-oci-usage-it-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    let dir = root.join("blobs").join("sha256");
    fs::create_dir_all(&dir).expect("mkdir");
    let sizes: [(u8, usize); 5] = [
        (0xc1, 4096),
        (0x10, 123_457),
        (0x11, 10_000),
        (0xc2, 4096),
        (0x12, 7),
    ];
    let mut total = 0u64;
    for (n, len) in sizes {
        let hex = format!("{n:02x}").repeat(32);
        fs::write(dir.join(hex), vec![1u8; len]).expect("write");
        total += len as u64;
    }
    let mut table = ReferenceTable::new();
    table
        .register_manifest(
            d(0xa0),
            ManifestComposition::new(d(0xc1), vec![d(0x10), d(0x11)]).expect("comp"),
        )
        .expect("a");
    table
        .register_manifest(
            d(0xb0),
            ManifestComposition::new(d(0xc2), vec![d(0x10), d(0x12)]).expect("comp"),
        )
        .expect("b");
    Fixture { root, table, total }
}

/// OCI-7: `system df` の表示値が実サイズの 5% 以内（本実装は完全一致）。
#[test]
fn oci7_df_matches_fixture_total_within_5_percent() {
    let f = fixture("df");
    let u = f.table.disk_usage(&f.root).expect("df");
    assert_eq!(f.total, 141_656);
    assert_eq!(u.images.bytes, 141_656);
    assert_eq!(u.cache.bytes, 141_656);
    for reported in [u.images.bytes, u.cache.bytes] {
        assert!(reported.abs_diff(f.total) * 100 <= f.total * 5);
    }
}

/// OCI-7: `image ls` が repository・tag・digest・サイズを返す。
#[test]
fn oci7_ls_returns_repository_tag_digest_size() {
    let mut f = fixture("ls");
    f.table.register_tag(key("v1"), &d(0xa0)).expect("tag");
    let l = f.table.list_images(&f.root).expect("ls");
    assert_eq!(l.entries.len(), 2);
    let e = &l.entries[0];
    let k = e.tag.as_ref().expect("tag");
    assert_eq!(k.host.host(), "registry.example");
    assert_eq!(k.repository.as_str(), "lib/app");
    assert_eq!(k.tag.as_str(), "v1");
    assert_eq!(e.digest, d(0xa0));
    assert_eq!(e.size_bytes, 4096 + 123_457 + 10_000);
    assert!(e.missing_blobs.is_empty());
}
