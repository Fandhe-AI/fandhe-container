//! 複数レイヤー・whiteout 混在の公開 API 結合試験（TASK-53.3・OCI-2・MS-4・#414）。
//! digest 検証 → gzip 展開 → 下位から上位への重ね展開で whiteout・不透明ディレクトリを適用した最終 rootfs を具体値で確認する。

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
    /// hardlink（名前, 参照先）。
    Hardlink(&'a str, &'a str),
    /// FIFO（未対応の種別の拒否確認用）。
    Fifo(&'a str),
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
            E::Hardlink(name, target) => {
                h.set_entry_type(tar::EntryType::Link);
                h.set_size(0);
                h.set_mode(0o644);
                h.set_cksum();
                b.append_link(&mut h, name, target).unwrap();
            }
            E::Fifo(name) => {
                h.set_entry_type(tar::EntryType::Fifo);
                h.set_size(0);
                h.set_mode(0o644);
                h.set_cksum();
                b.append_data(&mut h, name, &b""[..]).unwrap();
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
            std::env::temp_dir().join(format!("fc-oci-whiteout-{tag}-{}", std::process::id()));
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

/// whiteout・不透明マーカー（中身の無い通常ファイル）。
fn marker(name: &str) -> E<'_> {
    E::File(name, 0o644, b"")
}

fn set(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(|s| (*s).to_string()).collect()
}

fn extract(t: &Tmp, layers: &[Vec<u8>]) -> Result<(), OciErrorCode> {
    let blobs: Vec<PathBuf> = layers
        .iter()
        .enumerate()
        .map(|(i, z)| t.blob(&format!("l{i}.tar.gz"), z))
        .collect();
    let refs: Vec<&Path> = blobs.iter().map(PathBuf::as_path).collect();
    extract_blobs(&refs, &t.root(), 1 << 20, limits())
        .map(|_| ())
        .map_err(|e| e.code())
}

/// OCI-2: 3 レイヤー（whiteout・不透明ディレクトリ・ディレクトリごとの whiteout と再作成）の最終 rootfs。
#[test]
fn oci2_three_layers_with_whiteouts_final_rootfs() {
    let t = Tmp::new("three");
    let layers = [
        layer_gz(&[
            E::File("etc/os-release", 0o644, b"ID=base\n"),
            E::File("etc/hostname", 0o644, b"base-host\n"),
            E::File("bin/sh", 0o755, b"base-sh"),
            E::File("var/cache/a", 0o644, b"A"),
            E::File("var/cache/b", 0o644, b"B"),
            E::File("opt/app/old", 0o644, b"old"),
        ]),
        layer_gz(&[
            marker("etc/.wh.os-release"),
            marker("var/cache/.wh..wh..opq"),
            E::File("var/cache/c", 0o644, b"C"),
            marker(".wh.opt"),
        ]),
        layer_gz(&[
            E::File("opt/app/new", 0o644, b"new"),
            E::File("etc/os-release", 0o644, b"ID=top\n"),
        ]),
    ];
    extract(&t, &layers).unwrap();
    let root = t.root();
    assert_eq!(
        tree(&root),
        set(&[
            "bin",
            "bin/sh",
            "etc",
            "etc/hostname",
            "etc/os-release",
            "opt",
            "opt/app",
            "opt/app/new",
            "var",
            "var/cache",
            "var/cache/c",
        ])
    );
    assert_eq!(
        std::fs::read(root.join("etc/os-release")).unwrap(),
        b"ID=top\n"
    );
    assert_eq!(
        std::fs::read(root.join("etc/hostname")).unwrap(),
        b"base-host\n"
    );
    assert_eq!(std::fs::read(root.join("var/cache/c")).unwrap(), b"C");
    assert_eq!(std::fs::read(root.join("opt/app/new")).unwrap(), b"new");
    assert!(tree(&root).iter().all(|p| !p.contains(".wh.")));
}

/// OCI-2: 同一レイヤー内では `foo` と `.wh.foo` の並びに依らず、上位の `foo` が残り下位の `foo` は置換される。
#[test]
fn oci2_same_layer_entry_order_does_not_matter() {
    for (tag, upper) in [
        (
            "before",
            layer_gz(&[E::File("d/foo", 0o644, b"upper"), marker("d/.wh.foo")]),
        ),
        (
            "after",
            layer_gz(&[marker("d/.wh.foo"), E::File("d/foo", 0o644, b"upper")]),
        ),
    ] {
        let t = Tmp::new(tag);
        let lower = layer_gz(&[
            E::File("d/foo", 0o644, b"lower"),
            E::File("d/bar", 0o644, b"bar"),
        ]);
        extract(&t, &[lower, upper]).unwrap();
        assert_eq!(std::fs::read(t.root().join("d/foo")).unwrap(), b"upper");
        assert_eq!(tree(&t.root()), set(&["d", "d/bar", "d/foo"]));
    }
}

/// OCI-2: 同一レイヤーの不透明マーカーは、前後どちらの同レイヤーの子も消さず、下位の子だけを消す。
#[test]
fn oci2_opaque_marker_keeps_same_layer_children() {
    let t = Tmp::new("opq");
    let lower = layer_gz(&[
        E::File("d/old", 0o644, b"o"),
        E::File("d/sub/x", 0o644, b"x"),
        E::File("other", 0o644, b"z"),
    ]);
    let upper = layer_gz(&[
        E::File("d/before", 0o644, b"b"),
        marker("d/.wh..wh..opq"),
        E::File("d/after", 0o644, b"a"),
    ]);
    extract(&t, &[lower, upper]).unwrap();
    assert_eq!(tree(&t.root()), set(&["d", "d/after", "d/before", "other"]));
}

/// OCI-2: マーカー名のディレクトリは拒否される。`.wh..wh.` の予約名は拒否せず読み飛ばす（#2183）。
#[test]
fn oci2_invalid_markers_are_rejected() {
    let t = Tmp::new("bad");
    let bad = layer_gz(&[E::Dir(".wh.foo", 0o755)]);
    assert_eq!(
        extract(&t, &[bad]).unwrap_err(),
        OciErrorCode::InvalidArgument
    );
    let t = Tmp::new("bad2");
    let aufs = layer_gz(&[marker(".wh..wh.plnk"), E::File("keep", 0o644, b"k")]);
    extract(&t, &[aufs]).unwrap();
    assert_eq!(tree(&t.root()), set(&["keep"]));
}

/// OCI-2: symlink への whiteout はリンク自体だけを消し、リンク先は残る。
#[cfg(unix)]
#[test]
fn oci2_whiteout_of_symlink_keeps_link_target() {
    let t = Tmp::new("sym");
    let lower = layer_gz(&[E::File("real/keep", 0o644, b"k"), E::Symlink("lnk", "real")]);
    let upper = layer_gz(&[marker(".wh.lnk")]);
    extract(&t, &[lower, upper]).unwrap();
    assert_eq!(tree(&t.root()), set(&["real", "real/keep"]));
    assert_eq!(std::fs::read(t.root().join("real/keep")).unwrap(), b"k");
}

/// OCI-2・#2312: AUFS 予約名を含む参照先への hardlink は `Unimplemented` で拒否し、下位レイヤーは変わらない。
#[test]
fn oci2_hardlink_into_aufs_metadata_is_unimplemented() {
    for target in [".wh..wh.plnk/123", "./.wh..wh.plnk/123", ".wh..wh.aufs"] {
        let t = Tmp::new("plnk");
        let lower = layer_gz(&[E::File("a", 0o644, b"a"), E::File("b", 0o644, b"b")]);
        let upper = layer_gz(&[
            marker(".wh.a"),
            E::File(".wh..wh.plnk/123", 0o644, b"x"),
            E::Hardlink("g", target),
        ]);
        assert_eq!(
            extract(&t, &[lower, upper]).unwrap_err(),
            OciErrorCode::Unimplemented,
            "{target}"
        );
        assert_eq!(tree(&t.root()), set(&["a", "b"]), "{target}");
        assert_eq!(std::fs::read(t.root().join("a")).unwrap(), b"a");
    }
}

/// OCI-2・#2312: 予約名配下の未対応の種別（FIFO）は `PermissionDenied` で拒否し、下位レイヤーは変わらない。
#[test]
fn oci2_aufs_reserved_unsupported_type_is_permission_denied() {
    for name in [".wh..wh.plnk/f", ".wh..wh.orph/f", "d/.wh..wh.aufs"] {
        let t = Tmp::new("fifo");
        let lower = layer_gz(&[E::File("a", 0o644, b"a")]);
        let upper = layer_gz(&[marker(".wh.a"), E::Fifo(name)]);
        assert_eq!(
            extract(&t, &[lower, upper]).unwrap_err(),
            OciErrorCode::PermissionDenied,
            "{name}"
        );
        assert_eq!(tree(&t.root()), set(&["a"]), "{name}");
    }
}
/// `base` の FS が `a` と `b` を同じ名前として解決するか（`a` を作って `b` で引く。後始末する）。
fn resolves_as_same(base: &Path, a: &str, b: &str) -> bool {
    std::fs::write(base.join(a), b"p").unwrap();
    let same = std::fs::symlink_metadata(base.join(b)).is_ok();
    std::fs::remove_file(base.join(a)).unwrap();
    same
}

/// IO-5・OCI-2: 上位レイヤーの whiteout・不透明ディレクトリが、対象または親を別表記（大文字小文字・NFC / NFD）の
/// 名前で指す場合を、公開 API で実 FS に対して確かめる。ホスト FS で分岐する。別表記を同じ名前と解決する FS は
/// `ALREADY_EXISTS` で拒否される（名前は書き換えない）。区別する FS では別の名前なので成功し、マーカーは存在しない
/// 対象に対して何もしない。どちらでも下位の木と内容は変わらず、マーカー名は書かれず、root の外も変わらない。
/// 区別しない FS の挙動はホストに依らない形で `extract.rs` の単体テスト（`folding_lstat`）が積み上げ全体で照合し、
/// ここは実 FS での確認（Linux の PR CI は区別する側だけ。macOS / Windows の側は main の 3 OS 実行と
/// `layer_overlay.rs` の `io5_default_host_fs_folds_spelling_variants` で固定する）。
#[test]
fn io5_oci2_alias_markers_follow_destination_fs() {
    // (case, 下位ディレクトリ名, 上位マーカー, 別表記かの判定に使う (下位, 別表記))
    let cases: [(&str, &str, &str, (&str, &str)); 5] = [
        ("case-wh", "d", ".wh.D", ("d", "D")),
        ("case-parent", "d", "D/.wh.x", ("d", "D")),
        ("case-opq", "d", "D/.wh..wh..opq", ("d", "D")),
        (
            "nfd-wh",
            "caf\u{e9}",
            ".wh.cafe\u{301}",
            ("caf\u{e9}", "cafe\u{301}"),
        ),
        (
            "nfd-opq",
            "caf\u{e9}",
            "cafe\u{301}/.wh..wh..opq",
            ("caf\u{e9}", "cafe\u{301}"),
        ),
    ];
    for (case, lower, upper_marker, (a, b)) in cases {
        let t = Tmp::new(&format!("alias-marker-{case}"));
        let ld = format!("{lower}/");
        let lx = format!("{lower}/x");
        let l1 = layer_gz(&[E::Dir(&ld, 0o755), E::File(&lx, 0o644, b"x")]);
        let l2 = layer_gz(&[marker(upper_marker)]);
        let b1 = t.blob("l1.tar.gz", &l1);
        let b2 = t.blob("l2.tar.gz", &l2);
        let same = resolves_as_same(&t.base, a, b);
        let r = extract_blobs(&[b1.as_path(), b2.as_path()], &t.root(), 1 << 20, limits());
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
        }
        // どちらの側でも下位の木・内容は変わらず、マーカー名は書かれない。
        assert_eq!(tree(&t.root()), set(&[lower, &lx]), "{case}");
        assert_eq!(std::fs::read(t.root().join(&lx)).unwrap(), b"x", "{case}");
        let outside = set(&["l1.tar.gz", "l2.tar.gz", "root"]);
        let names: BTreeSet<String> = std::fs::read_dir(&t.base)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        assert_eq!(names, outside, "{case}");
    }
}
