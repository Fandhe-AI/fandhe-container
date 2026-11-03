//! 共有の試験補助 `test_root_at` の排他作成の回帰試験（OCI-7・REPAIR-12・#3475）。
//!
//! 補助は core の `LegacyResidue` / `core1_issue1298_*` の試験と同じ方針で、既存の名前（ディレクトリ・
//! symlink・宛先の無い symlink）を消さず・辿らず・chmod せず、別名で作ることを照合する。
//! 残骸はすべて私有の親（`test_root` で排他作成）の下に置き、共有の `temp_dir()` に固定名を作らない。

use std::path::Path;

#[path = "support/test_root.rs"]
mod test_root;
use test_root::{create_unique_at, test_root, test_root_at};

#[cfg(unix)]
fn ino(p: &Path) -> (u64, u64) {
    use std::os::unix::fs::MetadataExt;
    let m = std::fs::symlink_metadata(p).unwrap();
    (m.dev(), m.ino())
}

#[cfg(not(unix))]
fn ino(_p: &Path) -> (u64, u64) {
    (0, 0)
}

/// 空いている名前はそのまま使われ、unix では作成時に 0700 になる。drop で消える。
#[test]
fn oci7_repair12_3475_free_name_is_created_at_p_with_mode_0700() {
    let parent = test_root("fc-oci-tr", "free");
    let p = parent.join("fresh");
    let root = test_root_at(p.clone());
    assert_eq!(&*root, p.as_path());
    assert_eq!(std::fs::read_dir(&*root).unwrap().count(), 0);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&*root).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }
    drop(root);
    assert_eq!(
        std::fs::metadata(&p).unwrap_err().kind(),
        std::io::ErrorKind::NotFound
    );
}

/// 同名のディレクトリは消されず、別名の空ディレクトリが同じ親の下に作られる。
#[test]
fn oci7_repair12_3475_existing_dir_is_kept_and_fresh_dir_is_used() {
    let parent = test_root("fc-oci-tr", "dir");
    let p = parent.join("stale");
    std::fs::create_dir_all(p.join("nested")).unwrap();
    std::fs::write(p.join("file"), b"stale").unwrap();
    let ino_before = ino(&p);

    let root = test_root_at(p.clone());
    let rp = root.to_path_buf();
    assert_ne!(rp, p);
    assert_eq!(rp.parent(), p.parent());
    assert!(
        rp.file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("stale-"),
        "unexpected name: {}",
        rp.display()
    );
    assert_eq!(std::fs::read_dir(&rp).unwrap().count(), 0);
    drop(root);

    assert!(!rp.exists());
    assert_eq!(std::fs::read(p.join("file")).unwrap(), b"stale");
    assert!(p.join("nested").is_dir());
    assert_eq!(ino(&p), ino_before);
}

/// 実在するディレクトリへの symlink と、宛先の無い symlink のどちらも辿られず、chmod もされない。
#[cfg(unix)]
#[test]
fn oci7_repair12_3475_preexisting_symlinks_are_not_followed() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let parent = test_root("fc-oci-tr", "link");

    let victim = parent.join("victim");
    std::fs::create_dir(&victim).unwrap();
    std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::write(victim.join("marker"), b"keep").unwrap();
    let to_dir = parent.join("to-dir");
    symlink(&victim, &to_dir).unwrap();

    let dangling_target = parent.join("nowhere");
    let dangling = parent.join("dangling");
    symlink(&dangling_target, &dangling).unwrap();

    for link in [&to_dir, &dangling] {
        let root = test_root_at(link.clone());
        let rp = root.to_path_buf();
        assert_ne!(&rp, link);
        assert!(
            !std::fs::symlink_metadata(&rp)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(std::fs::read_dir(&rp).unwrap().count(), 0);
        drop(root);
        assert!(
            std::fs::symlink_metadata(link)
                .unwrap()
                .file_type()
                .is_symlink(),
            "symlink must remain: {}",
            link.display()
        );
    }
    assert_eq!(
        std::fs::metadata(&victim).unwrap().permissions().mode() & 0o777,
        0o755
    );
    assert_eq!(std::fs::read_dir(&victim).unwrap().count(), 1);
    assert_eq!(std::fs::read(victim.join("marker")).unwrap(), b"keep");
    assert!(!dangling_target.exists());
}

/// 再試行は上限で諦め、既存のディレクトリには触れない。
#[test]
fn oci7_repair12_3475_retry_is_bounded() {
    let parent = test_root("fc-oci-tr", "bounded");
    let taken = parent.join("taken");
    std::fs::create_dir(&taken).unwrap();
    std::fs::write(taken.join("f"), b"x").unwrap();
    let names = std::iter::repeat_with(|| std::ffi::OsString::from("taken"));
    let err = match create_unique_at(&parent, names, 3) {
        Ok(_) => panic!("must give up"),
        Err(e) => e,
    };
    assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
    assert_eq!(std::fs::read(taken.join("f")).unwrap(), b"x");
}

/// 同じ `p` で 2 回呼ぶと 2 つ目は別のパスになる。
#[test]
fn oci7_repair12_3475_same_p_twice_yields_distinct_paths() {
    let parent = test_root("fc-oci-tr", "twice");
    let p = parent.join("same");
    let a = test_root_at(p.clone());
    let b = test_root_at(p.clone());
    assert_eq!(&*a, p.as_path());
    assert_ne!(&*a, &*b);
    assert!(a.is_dir() && b.is_dir());
}
