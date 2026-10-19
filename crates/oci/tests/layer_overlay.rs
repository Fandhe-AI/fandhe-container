//! 複数レイヤーの重ね合わせ展開の公開 API 結合試験（TASK-52.4・OCI-1・#410）。
//! digest 検証（TASK-52.1）→ gzip 展開（TASK-52.2）→ 下位から上位への重ね展開を、外向き通信なしで具体値で確認する。

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::io::Write;
use std::path::{Path, PathBuf};

use fandhe_container_oci::error::OciErrorCode;
use fandhe_container_oci::layer::extract::{ExtractLimits, extract_layer_blobs};
use fandhe_container_oci::layer::verify_blob_digest;
use fandhe_container_oci::reference::Digest;
use sha2::{Digest as _, Sha256};

fn sha(data: &[u8]) -> Digest {
    let mut s = String::from("sha256:");
    for b in Sha256::digest(data) {
        write!(s, "{b:02x}").unwrap();
    }
    Digest::parse(&s).unwrap()
}

/// レイヤーの 1 エントリ（テスト用イメージの定義）。
enum E<'a> {
    File(&'a str, u32, &'a [u8]),
    Dir(&'a str, u32),
    #[cfg(unix)]
    Symlink(&'a str, &'a str),
    #[cfg(unix)]
    Hardlink(&'a str, &'a str),
}

fn layer_gz(entries: &[E<'_>]) -> Vec<u8> {
    let mut b = tar::Builder::new(Vec::new());
    for e in entries {
        let mut h = tar::Header::new_gnu();
        match e {
            E::File(name, mode, data) => {
                h.set_size(data.len() as u64);
                h.set_mode(*mode);
                h.set_cksum();
                b.append_data(&mut h, name, *data).unwrap();
            }
            E::Dir(name, mode) => {
                h.set_entry_type(tar::EntryType::Directory);
                h.set_size(0);
                h.set_mode(*mode);
                h.set_cksum();
                b.append_data(&mut h, name, &b""[..]).unwrap();
            }
            #[cfg(unix)]
            E::Symlink(name, target) => {
                h.set_entry_type(tar::EntryType::Symlink);
                h.set_size(0);
                h.set_mode(0o777);
                h.set_cksum();
                b.append_link(&mut h, name, target).unwrap();
            }
            #[cfg(unix)]
            E::Hardlink(name, target) => {
                h.set_entry_type(tar::EntryType::Link);
                h.set_size(0);
                h.set_mode(0o644);
                h.set_cksum();
                b.append_link(&mut h, name, target).unwrap();
            }
        }
    }
    let tar_bytes = b.into_inner().unwrap();
    let mut z = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    z.write_all(&tar_bytes).unwrap();
    z.finish().unwrap()
}

/// 一時ディレクトリ（Drop で消す。権限を戻してから消す）。
struct Tmp {
    base: PathBuf,
}

impl Tmp {
    fn new(tag: &str) -> Self {
        let base =
            std::env::temp_dir().join(format!("fc-oci-overlay-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join("root")).unwrap();
        Self { base }
    }

    fn root(&self) -> PathBuf {
        self.base.join("root")
    }

    /// 圧縮レイヤーを blob として書き、digest を検証した上でパスを返す（呼び出し契約）。
    fn blob(&self, name: &str, gz: &[u8]) -> PathBuf {
        let p = self.base.join(name);
        std::fs::write(&p, gz).unwrap();
        verify_blob_digest(&p, &sha(gz), 1 << 20).unwrap();
        p
    }
}

impl Drop for Tmp {
    fn drop(&mut self) {
        #[cfg(unix)]
        restore_perms(&self.base);
        let _ = std::fs::remove_dir_all(&self.base);
    }
}

#[cfg(unix)]
fn restore_perms(p: &Path) {
    use std::os::unix::fs::PermissionsExt as _;
    if let Ok(m) = std::fs::symlink_metadata(p)
        && m.is_dir()
    {
        let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o755));
        if let Ok(rd) = std::fs::read_dir(p) {
            for e in rd.flatten() {
                restore_perms(&e.path());
            }
        }
    }
}

fn limits() -> ExtractLimits {
    ExtractLimits::new(100, 1 << 20, 1 << 30, 1 << 20)
}

/// `root` 配下の全パス（相対・`/` 区切り）の集合。
fn tree(root: &Path) -> BTreeSet<String> {
    fn walk(dir: &Path, prefix: &str, out: &mut BTreeSet<String>) {
        for e in std::fs::read_dir(dir).unwrap() {
            let e = e.unwrap();
            let name = format!("{prefix}{}", e.file_name().into_string().unwrap());
            out.insert(name.clone());
            if e.file_type().unwrap().is_dir() {
                walk(&e.path(), &format!("{name}/"), out);
            }
        }
    }
    let mut out = BTreeSet::new();
    walk(root, "", &mut out);
    out
}

fn base_layers() -> [Vec<u8>; 3] {
    [
        layer_gz(&[
            E::File("etc/os-release", 0o644, b"ID=base\n"),
            E::File("bin/sh", 0o755, b"base-sh"),
            E::File("usr/lib/a", 0o644, b"A1"),
            E::Dir("usr/share/", 0o755),
        ]),
        layer_gz(&[
            E::File("etc/os-release", 0o644, b"ID=mid-longer\n"),
            E::File("usr/lib/b", 0o644, b"B2"),
        ]),
        layer_gz(&[
            E::File("etc/os-release", 0o644, b"ID=top\n"),
            E::File("usr/lib/a", 0o644, b"A3"),
        ]),
    ]
}

/// OCI-1: 3 レイヤーを下位から展開すると、上位が下位を上書きした最終内容になる。
#[test]
fn oci1_three_layers_overlay_final_contents() {
    let t = Tmp::new("three");
    let blobs: Vec<PathBuf> = base_layers()
        .iter()
        .enumerate()
        .map(|(i, z)| t.blob(&format!("l{i}.tar.gz"), z))
        .collect();
    let refs: Vec<&Path> = blobs.iter().map(PathBuf::as_path).collect();
    let r = extract_layer_blobs(&refs, &t.root(), 1 << 20, limits()).unwrap();

    // レイヤーごとの件数。L1 は親ディレクトリを暗黙に作るが、数えるのは tar のエントリだけ。
    assert_eq!(
        r.iter().map(|l| (l.entries, l.bytes)).collect::<Vec<_>>(),
        vec![(4, 17), (2, 16), (2, 9)]
    );
    let root = t.root();
    assert_eq!(
        std::fs::read(root.join("etc/os-release")).unwrap(),
        b"ID=top\n"
    );
    assert_eq!(std::fs::read(root.join("usr/lib/a")).unwrap(), b"A3");
    assert_eq!(std::fs::read(root.join("usr/lib/b")).unwrap(), b"B2");
    assert_eq!(std::fs::read(root.join("bin/sh")).unwrap(), b"base-sh");
    let expected: BTreeSet<String> = [
        "bin",
        "bin/sh",
        "etc",
        "etc/os-release",
        "usr",
        "usr/lib",
        "usr/lib/a",
        "usr/lib/b",
        "usr/share",
    ]
    .iter()
    .map(|s| (*s).to_string())
    .collect();
    assert_eq!(tree(&root), expected);
}

/// OCI-1: 順序が効く（逆順に重ねると最終内容が変わる）。
#[test]
fn oci1_layer_order_matters() {
    let t = Tmp::new("order");
    let ls = base_layers();
    let blobs: Vec<PathBuf> = [2usize, 1, 0]
        .iter()
        .map(|&i| t.blob(&format!("l{i}.tar.gz"), &ls[i]))
        .collect();
    let refs: Vec<&Path> = blobs.iter().map(PathBuf::as_path).collect();
    extract_layer_blobs(&refs, &t.root(), 1 << 20, limits()).unwrap();
    assert_eq!(
        std::fs::read(t.root().join("etc/os-release")).unwrap(),
        b"ID=base\n"
    );
    assert_eq!(std::fs::read(t.root().join("usr/lib/a")).unwrap(), b"A1");
}

/// OCI-1: digest が不一致の blob は検証で拒否され、展開に進まない（呼び出し契約）。
#[test]
fn oci1_digest_mismatch_blob_is_rejected_before_extract() {
    let t = Tmp::new("digest");
    let gz = base_layers()[0].clone();
    let p = t.base.join("bad.tar.gz");
    std::fs::write(&p, &gz).unwrap();
    let wrong = sha(b"something else");
    assert!(verify_blob_digest(&p, &wrong, 1 << 20).is_err());
    assert!(tree(&t.root()).is_empty());
}

/// OCI-1: 空の layer 列は InvalidArgument。
#[test]
fn oci1_empty_layer_list_is_rejected() {
    let t = Tmp::new("empty");
    let e = extract_layer_blobs(&[], &t.root(), 1 << 20, limits()).unwrap_err();
    assert_eq!(e.code(), OciErrorCode::InvalidArgument);
}

/// OCI-1: 種別をまたぐ上書き（通常ファイル↔symlink・hardlink）と mode の更新。
#[cfg(unix)]
#[test]
fn oci1_overlay_across_entry_types_and_modes() {
    use std::os::unix::fs::PermissionsExt as _;
    let t = Tmp::new("types");
    let l1 = layer_gz(&[
        E::File("a", 0o644, b"file-a"),
        E::Symlink("b", "a"),
        E::File("c", 0o644, b"c1"),
        E::File("script", 0o644, b"#!"),
        E::Dir("ro/", 0o555),
    ]);
    let l2 = layer_gz(&[
        E::Symlink("a", "c"),
        E::File("b", 0o644, b"file-b"),
        E::Hardlink("c", "script"),
        E::File("script", 0o755, b"#!/bin/sh"),
        E::File("ro/x", 0o644, b"x"),
    ]);
    let b1 = t.blob("l1.tar.gz", &l1);
    let b2 = t.blob("l2.tar.gz", &l2);
    extract_layer_blobs(&[b1.as_path(), b2.as_path()], &t.root(), 1 << 20, limits()).unwrap();
    let root = t.root();
    assert_eq!(std::fs::read_link(root.join("a")).unwrap(), Path::new("c"));
    assert!(
        !std::fs::symlink_metadata(root.join("b"))
            .unwrap()
            .is_symlink()
    );
    assert_eq!(std::fs::read(root.join("b")).unwrap(), b"file-b");
    assert_eq!(std::fs::read(root.join("c")).unwrap(), b"#!");
    assert_eq!(std::fs::read(root.join("script")).unwrap(), b"#!/bin/sh");
    let mode = |p: &str| {
        std::fs::symlink_metadata(root.join(p))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777
    };
    assert_eq!(mode("script"), 0o755);
    assert_eq!(mode("ro"), 0o555);
    assert_eq!(std::fs::read(root.join("ro/x")).unwrap(), b"x");
}

/// OCI-1: 中身のある下位ディレクトリを、上位レイヤーの通常ファイルが置き換える（image-spec の
/// Changeset over existing files。#1996 で実装済み、#2017 で公開 API 経由の結合試験を追加）。
#[test]
fn oci1_upper_file_replaces_lower_dir_with_contents() {
    let t = Tmp::new("dir2file");
    let l1 = layer_gz(&[
        E::Dir("d/", 0o755),
        E::File("d/x", 0o644, b"x"),
        E::File("d/sub/y", 0o644, b"y"),
        E::File("keep", 0o644, b"k"),
    ]);
    let l2 = layer_gz(&[E::File("d", 0o644, b"file-d")]);
    let b1 = t.blob("l1.tar.gz", &l1);
    let b2 = t.blob("l2.tar.gz", &l2);
    extract_layer_blobs(&[b1.as_path(), b2.as_path()], &t.root(), 1 << 20, limits()).unwrap();
    let root = t.root();
    assert_eq!(std::fs::read(root.join("d")).unwrap(), b"file-d");
    let expected: BTreeSet<String> = ["d", "keep"].iter().map(|s| (*s).to_string()).collect();
    assert_eq!(tree(&root), expected);
}

/// OCI-1: 下位ディレクトリを上位の symlink が置き換える。
#[cfg(unix)]
#[test]
fn oci1_upper_symlink_replaces_lower_dir() {
    let t = Tmp::new("dir2link");
    let l1 = layer_gz(&[E::File("d/x", 0o644, b"x"), E::File("keep", 0o644, b"k")]);
    let l2 = layer_gz(&[E::Symlink("d", "keep")]);
    let b1 = t.blob("l1.tar.gz", &l1);
    let b2 = t.blob("l2.tar.gz", &l2);
    extract_layer_blobs(&[b1.as_path(), b2.as_path()], &t.root(), 1 << 20, limits()).unwrap();
    assert_eq!(
        std::fs::read_link(t.root().join("d")).unwrap(),
        Path::new("keep")
    );
    let expected: BTreeSet<String> = ["d", "keep"].iter().map(|s| (*s).to_string()).collect();
    assert_eq!(tree(&t.root()), expected);
}

/// OCI-1: 下位の絶対 symlink を経由する置換も root の内側に閉じ、root の外は変わらない。
#[cfg(unix)]
#[test]
fn oci1_replacement_through_lower_symlink_stays_in_root() {
    let t = Tmp::new("repl-escape");
    let l1 = layer_gz(&[E::Symlink("out", "/"), E::File("d/x", 0o644, b"x")]);
    let l2 = layer_gz(&[E::File("out/d", 0o644, b"file-d")]);
    let b1 = t.blob("l1.tar.gz", &l1);
    let b2 = t.blob("l2.tar.gz", &l2);
    extract_layer_blobs(&[b1.as_path(), b2.as_path()], &t.root(), 1 << 20, limits()).unwrap();
    assert_eq!(std::fs::read(t.root().join("d")).unwrap(), b"file-d");
    let outside: BTreeSet<String> = std::fs::read_dir(&t.base)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    assert_eq!(
        outside,
        ["l1.tar.gz", "l2.tar.gz", "root"]
            .iter()
            .map(|s| (*s).to_string())
            .collect()
    );
}

/// OCI-1: 置換エントリが `..` で root の外を指すレイヤーは拒否され、下位の内容は残る。
#[test]
fn oci1_replacement_entry_with_parent_dir_is_rejected() {
    let t = Tmp::new("repl-dotdot");
    let l1 = layer_gz(&[E::File("d/x", 0o644, b"x")]);
    let b1 = t.blob("l1.tar.gz", &l1);
    // tar crate の builder は `..` を拒否するため、ヘッダを直接組む。
    let mut raw = vec![0u8; 512];
    raw[..4].copy_from_slice(b"../d");
    raw[100..107].copy_from_slice(b"0000644");
    raw[124..135].copy_from_slice(b"00000000000");
    raw[136..147].copy_from_slice(b"00000000000");
    raw[148..156].copy_from_slice(b"        ");
    raw[156] = b'0';
    raw[257..263].copy_from_slice(b"ustar\0");
    let sum: u32 = raw.iter().map(|b| u32::from(*b)).sum();
    raw[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    raw.extend_from_slice(&[0u8; 1024]);
    let mut z = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    z.write_all(&raw).unwrap();
    let b2 = t.blob("l2.tar.gz", &z.finish().unwrap());
    let e = extract_layer_blobs(&[b1.as_path(), b2.as_path()], &t.root(), 1 << 20, limits())
        .unwrap_err();
    assert_eq!(e.code(), OciErrorCode::PermissionDenied);
    assert_eq!(std::fs::read(t.root().join("d/x")).unwrap(), b"x");
}

/// OCI-1: 下位の symlink を経由してもルート外へは書けない（上位レイヤーの絶対 symlink 先もルートに閉じる）。
#[cfg(unix)]
#[test]
fn oci1_upper_layer_cannot_escape_through_lower_symlink() {
    let t = Tmp::new("escape");
    let l1 = layer_gz(&[E::Symlink("out", "/")]);
    let l2 = layer_gz(&[E::File("out/evil", 0o644, b"x")]);
    let b1 = t.blob("l1.tar.gz", &l1);
    let b2 = t.blob("l2.tar.gz", &l2);
    extract_layer_blobs(&[b1.as_path(), b2.as_path()], &t.root(), 1 << 20, limits()).unwrap();
    // chroot 意味論: `out` -> `/` は root 自身を指すので、書き込み先は root 配下になる。
    assert_eq!(std::fs::read(t.root().join("evil")).unwrap(), b"x");
    let outside: BTreeSet<String> = std::fs::read_dir(&t.base)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    assert_eq!(
        outside,
        ["l1.tar.gz", "l2.tar.gz", "root"]
            .iter()
            .map(|s| (*s).to_string())
            .collect()
    );
}
