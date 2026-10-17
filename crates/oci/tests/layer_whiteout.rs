//! 複数レイヤー・whiteout 混在の公開 API 結合試験（TASK-53.3・OCI-2・MS-4・#414）。
//! digest 検証 → gzip 展開 → 下位から上位への重ね展開で whiteout・不透明ディレクトリを適用した最終 rootfs を具体値で確認する。

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
    extract_layer_blobs(&refs, &t.root(), 1 << 20, limits())
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

/// OCI-2: マーカー名のディレクトリや予約名は拒否される。
#[test]
fn oci2_invalid_markers_are_rejected() {
    let t = Tmp::new("bad");
    let bad = layer_gz(&[E::Dir(".wh.foo", 0o755)]);
    assert_eq!(
        extract(&t, &[bad]).unwrap_err(),
        OciErrorCode::InvalidArgument
    );
    let t = Tmp::new("bad2");
    let bad = layer_gz(&[marker(".wh..wh.plnk")]);
    assert_eq!(
        extract(&t, &[bad]).unwrap_err(),
        OciErrorCode::InvalidArgument
    );
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
