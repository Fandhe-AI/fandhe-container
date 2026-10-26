//! 複数レイヤーの重ね合わせ展開の公開 API 結合試験（TASK-52.4・OCI-1・#410）。
//! digest 検証（TASK-52.1）→ gzip 展開（TASK-52.2）→ 下位から上位への重ね展開を、外向き通信なしで具体値で確認する。

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::io::Write;
use std::path::{Path, PathBuf};

use fandhe_container_oci::error::{OciError, OciErrorCode};
#[cfg(unix)]
use fandhe_container_oci::layer::VerifiedLayerBlob;
#[cfg(not(unix))]
use fandhe_container_oci::layer::decompress_layer_to_writer;
#[cfg(not(unix))]
use fandhe_container_oci::layer::extract::extract_layers;
use fandhe_container_oci::layer::extract::{ExtractLimits, ExtractedLayer};
#[cfg(unix)]
use fandhe_container_oci::layer::extract::{ImageLayer, extract_image_layers};
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

/// gzip の tar を gunzip する（blob の diff_id = 展開後 tar の sha256 を計算するため）。
#[cfg(unix)]
fn gunzip(gz: &[u8]) -> Vec<u8> {
    use std::io::Read as _;
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(gz)
        .read_to_end(&mut out)
        .unwrap();
    out
}

/// digest 検証済みの gzip blob を、下位から上位の順に `root` へ重ねて展開する（パスで開く旧入口の代わり。#2535・OCI-1）。
///
/// Unix（Linux・macOS）は本番と同じ検証済みハンドル版（`VerifiedLayerBlob` → `extract_image_layers`）を通す。
/// blob は 0600 にして umask に依らず信頼条件を満たす。Windows は `VerifiedLayerBlob` を作れない（`Unimplemented`）ため、
/// 検証 → gzip 展開 → ストリーム展開（`extract_layers`）の連結で代える。パスを開き直す展開入口は使わず、期待値は 3 OS 共通。
fn extract_blobs(
    blobs: &[&Path],
    root: &Path,
    max_uncompressed_bytes: u64,
    limits: ExtractLimits,
) -> Result<Vec<ExtractedLayer>, OciError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        let mut opened = Vec::new();
        for p in blobs {
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600)).unwrap();
            let gz = std::fs::read(p).unwrap();
            let owner = std::fs::metadata(p).unwrap().uid();
            let blob = VerifiedLayerBlob::open(p, &sha(&gz), gz.len() as u64, owner)?;
            opened.push((blob, sha(&gunzip(&gz))));
        }
        let layers: Vec<ImageLayer<'_>> = opened
            .iter()
            .map(|(b, d)| ImageLayer::new(b, "application/vnd.oci.image.layer.v1.tar+gzip", d))
            .collect();
        extract_image_layers(&layers, root, max_uncompressed_bytes, limits)
    }
    #[cfg(not(unix))]
    {
        let mut tars = Vec::new();
        for p in blobs {
            let gz = std::fs::read(p).unwrap();
            verify_blob_digest(p, &sha(&gz), gz.len() as u64)?;
            let mut tar = Vec::new();
            decompress_layer_to_writer(p, max_uncompressed_bytes, &mut tar)?;
            tars.push(std::io::Cursor::new(tar));
        }
        extract_layers(tars, root, limits)
    }
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
    let r = extract_blobs(&refs, &t.root(), 1 << 20, limits()).unwrap();

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
    extract_blobs(&refs, &t.root(), 1 << 20, limits()).unwrap();
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

/// OCI-1: ストリーム版の空の layer 列は InvalidArgument（ハンドル版の空は「レイヤー 0 のイメージ」で成功する。
/// layer_image.rs が確かめる）。
#[test]
fn oci1_empty_layer_list_is_rejected() {
    let t = Tmp::new("empty");
    let e = fandhe_container_oci::layer::extract::extract_layers(
        Vec::<std::io::Cursor<Vec<u8>>>::new(),
        &t.root(),
        limits(),
    )
    .unwrap_err();
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
    extract_blobs(&[b1.as_path(), b2.as_path()], &t.root(), 1 << 20, limits()).unwrap();
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
    extract_blobs(&[b1.as_path(), b2.as_path()], &t.root(), 1 << 20, limits()).unwrap();
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
    extract_blobs(&[b1.as_path(), b2.as_path()], &t.root(), 1 << 20, limits()).unwrap();
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
    extract_blobs(&[b1.as_path(), b2.as_path()], &t.root(), 1 << 20, limits()).unwrap();
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
    let e = extract_blobs(&[b1.as_path(), b2.as_path()], &t.root(), 1 << 20, limits()).unwrap_err();
    assert_eq!(e.code(), OciErrorCode::PermissionDenied);
    assert_eq!(std::fs::read(t.root().join("d/x")).unwrap(), b"x");
}

/// `base` の FS が `a` と `b` を同じ名前として解決するか（`a` を作って `b` で引く。後始末する）。
fn resolves_as_same(base: &Path, a: &str, b: &str) -> bool {
    std::fs::write(base.join(a), b"p").unwrap();
    let same = std::fs::symlink_metadata(base.join(b)).is_ok();
    std::fs::remove_file(base.join(a)).unwrap();
    same
}

/// `base` 直下の名前の集合（root の外が変わっていないことの照合用）。
fn names_at(base: &Path) -> BTreeSet<String> {
    std::fs::read_dir(base)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect()
}

/// IO-5・OCI-1・OCI-2: 上位レイヤーが別表記（大文字小文字・NFC / NFD）の名前のファイルで下位の中身のある
/// ディレクトリを置き換えようとする場合を、公開 API で実 FS に対して確かめる。ホスト FS で分岐する。
/// 別表記を同じ名前と解決する FS は拒否（`ALREADY_EXISTS`）され下位の木が残り、区別する FS は別名として
/// 並存する。区別しない FS の挙動はホストに依らない形で `extract.rs` の単体テスト（`folding_lstat`）が照合し、
/// ここは実 FS での確認（Linux の PR CI は区別する側だけ。macOS / Windows の側は main の 3 OS 実行と
/// `io5_default_host_fs_folds_spelling_variants` で固定する）。
#[test]
fn io5_oci1_upper_alias_file_over_lower_dir_follows_destination_fs() {
    for (case, lower, upper) in [("case", "d", "D"), ("nfd", "caf\u{e9}", "cafe\u{301}")] {
        let t = Tmp::new(&format!("alias-{case}"));
        let ld = format!("{lower}/");
        let lx = format!("{lower}/x");
        let ly = format!("{lower}/sub/y");
        let l1 = layer_gz(&[
            E::Dir(&ld, 0o755),
            E::File(&lx, 0o644, b"x"),
            E::File(&ly, 0o644, b"y"),
            E::File("keep", 0o644, b"k"),
        ]);
        let l2 = layer_gz(&[E::File(upper, 0o644, b"file-upper")]);
        let b1 = t.blob("l1.tar.gz", &l1);
        let b2 = t.blob("l2.tar.gz", &l2);
        let same = resolves_as_same(&t.base, lower, upper);
        let r = extract_blobs(&[b1.as_path(), b2.as_path()], &t.root(), 1 << 20, limits());
        let mut expect: BTreeSet<String> = [lower, &format!("{lower}/sub"), &ly, &lx, "keep"]
            .into_iter()
            .map(String::from)
            .collect();
        if same {
            let e = r.expect_err(case);
            assert_eq!(e.code(), OciErrorCode::AlreadyExists, "{case}");
            assert_eq!(e.code().as_str(), "ALREADY_EXISTS", "{case}");
            assert_eq!(
                e.message(),
                "entry name resolves to an existing entry with a different spelling \
                 (case or Unicode normalization) on the destination filesystem",
                "{case}"
            );
        } else {
            r.expect(case);
            expect.insert(upper.to_string());
            assert_eq!(
                std::fs::read(t.root().join(upper)).unwrap(),
                b"file-upper",
                "{case}"
            );
        }
        assert_eq!(tree(&t.root()), expect, "{case}");
        assert_eq!(std::fs::read(t.root().join(&lx)).unwrap(), b"x", "{case}");
        assert_eq!(std::fs::read(t.root().join(&ly)).unwrap(), b"y", "{case}");
        let outside: BTreeSet<String> = ["l1.tar.gz", "l2.tar.gz", "root"]
            .into_iter()
            .map(String::from)
            .collect();
        assert_eq!(names_at(&t.base), outside, "{case}");
    }
}

/// IO-5: macOS / Windows の既定の一時領域は別表記を同じ名前と解決する。上の試験が拒否の側を実際に通ることを
/// 固定する（大文字小文字は両 OS、NFC / NFD は macOS の APFS のみ）。
#[cfg(any(windows, target_os = "macos"))]
#[test]
fn io5_default_host_fs_folds_spelling_variants() {
    let t = Tmp::new("alias-host");
    assert!(resolves_as_same(&t.base, "d", "D"));
    #[cfg(target_os = "macos")]
    assert!(resolves_as_same(&t.base, "caf\u{e9}", "cafe\u{301}"));
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
    extract_blobs(&[b1.as_path(), b2.as_path()], &t.root(), 1 << 20, limits()).unwrap();
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
