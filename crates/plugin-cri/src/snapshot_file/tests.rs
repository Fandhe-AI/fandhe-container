//! `snapshot_file` の単体試験（#4335・CRI-6・REPAIR-4・SEC-1）。実 FS 試験は Linux のみ。

use super::*;

fn limit(n: usize) -> SnapshotLimit {
    SnapshotLimit::for_blocks(NonZeroUsize::new(n).unwrap()).unwrap()
}

fn assert_send<T: Send>() {}

#[test]
fn cri6_4335_target_is_send() {
    assert_send::<SnapshotTarget>();
}

#[test]
fn cri6_4335_limit_values() {
    assert_eq!(limit(1).max_bytes(), 65536);
    assert_eq!(limit(2).max_bytes(), 131072);
    assert_eq!(
        SnapshotLimit::for_blocks(NonZeroUsize::new(65).unwrap()),
        Err(SnapshotError::LimitOutOfRange)
    );
}

#[test]
fn sec4_4335_error_text_is_fixed_vocabulary() {
    let all = [
        SnapshotError::Unsupported,
        SnapshotError::RelativePath,
        SnapshotError::InvalidPath,
        SnapshotError::UntrustedProcess,
        SnapshotError::UntrustedDirectory,
        SnapshotError::TooLarge,
        SnapshotError::LimitOutOfRange,
        SnapshotError::CreateFailed,
        SnapshotError::WriteFailed,
        SnapshotError::SyncFailed,
        SnapshotError::TargetNotRegular,
        SnapshotError::RenameFailed,
    ];
    for e in all {
        let s = format!("{e} {}", e.code());
        assert!(!s.contains('/') && !s.contains("os error"), "{s}");
        assert!(e.code().chars().all(|c| c.is_ascii_lowercase() || c == '_'));
    }
    assert_eq!(
        SnapshotError::UntrustedDirectory.code(),
        "untrusted_directory"
    );
}

#[cfg(not(target_os = "linux"))]
#[test]
fn cri6_4335_non_linux_is_unsupported() {
    let r = SnapshotTarget::open(Path::new("/tmp/x.json"), limit(1));
    assert_eq!(r.unwrap_err(), SnapshotError::Unsupported);
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use crate::snapshot_file::imp;
    use crate::test_root::TestRoot;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::path::PathBuf;

    fn root(tag: &str) -> TestRoot {
        let r = crate::test_root::test_root("snapfile", tag);
        std::fs::set_permissions(&*r, std::fs::Permissions::from_mode(0o700)).unwrap();
        r
    }

    fn euid() -> u32 {
        imp::unelevated_euid().unwrap()
    }

    fn open(p: &Path, n: usize) -> Result<SnapshotTarget, SnapshotError> {
        SnapshotTarget::open(p, limit(n))
    }

    fn leftovers(dir: &Path) -> Vec<String> {
        std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains(".tmp."))
            .collect()
    }

    #[test]
    fn sec1_4335_rejects_relative_and_malformed_paths() {
        for p in ["stats.json", "dir/stats.json"] {
            assert_eq!(
                open(Path::new(p), 1).unwrap_err(),
                SnapshotError::RelativePath
            );
        }
        let r = root("malformed");
        for p in [
            r.join("..").join("x"),
            r.join(".").join("x"),
            PathBuf::from(format!("{}/", r.display())),
            r.join("a".repeat(201)),
        ] {
            assert_eq!(
                open(&p, 1).unwrap_err(),
                SnapshotError::InvalidPath,
                "{p:?}"
            );
        }
    }

    #[test]
    fn sec1_4335_rejects_symlink_directory() {
        let r = root("symdir");
        std::fs::create_dir(r.join("real")).unwrap();
        std::os::unix::fs::symlink(r.join("real"), r.join("link")).unwrap();
        let e = open(&r.join("link").join("s.json"), 1).unwrap_err();
        assert_eq!(e, SnapshotError::UntrustedDirectory);
    }

    #[test]
    fn sec1_4335_rejects_group_or_other_writable_directory() {
        let r = root("gow");
        for mode in [0o775, 0o757, 0o777, 0o1777] {
            std::fs::set_permissions(&*r, std::fs::Permissions::from_mode(mode)).unwrap();
            let e = open(&r.join("s.json"), 1).unwrap_err();
            assert_eq!(e, SnapshotError::UntrustedDirectory, "mode {mode:o}");
        }
    }

    #[test]
    fn sec1_4335_rejects_other_uid_owner() {
        let r = root("owner");
        let e = imp::open_with_euid(&r.join("s.json"), limit(1), euid() + 1).unwrap_err();
        assert_eq!(e, SnapshotError::UntrustedDirectory);
        assert_eq!(
            imp::check_dir_meta(true, 1001, 0o40700, 1000),
            Err(SnapshotError::UntrustedDirectory)
        );
        assert_eq!(imp::check_dir_meta(true, 1000, 0o40700, 1000), Ok(()));
        assert_eq!(
            imp::check_dir_meta(false, 1000, 0o100600, 1000),
            Err(SnapshotError::UntrustedDirectory)
        );
    }

    #[test]
    fn sec1_4335_unelevated_requires_matching_ids() {
        let ok = "Uid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\nGroups:\t\nCapInh:\t0000000000000000\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\nCapBnd:\t0000000000000000\nCapAmb:\t0000000000000000\nNoNewPrivs:\t0\n";
        assert_eq!(imp::check_unelevated(ok), Ok(1000));
        let bad_uid = ok.replace("Uid:\t1000\t1000\t1000\t1000", "Uid:\t1000\t0\t1000\t1000");
        assert_eq!(
            imp::check_unelevated(&bad_uid),
            Err(SnapshotError::UntrustedProcess)
        );
        let bad_gid = ok.replace("Gid:\t1000\t1000\t1000\t1000", "Gid:\t1000\t1000\t1000\t0");
        assert_eq!(
            imp::check_unelevated(&bad_gid),
            Err(SnapshotError::UntrustedProcess)
        );
        assert_eq!(
            imp::check_unelevated("garbage"),
            Err(SnapshotError::UntrustedProcess)
        );
    }

    #[test]
    fn cri6_4335_replace_creates_and_replaces_with_mode_0600() {
        let r = root("basic");
        let p = r.join("s.json");
        let t = open(&p, 1).unwrap();
        assert_eq!(t.replace(b"first").unwrap(), SnapshotWritten { bytes: 5 });
        assert_eq!(std::fs::read(&p).unwrap(), b"first");
        assert_eq!(std::fs::metadata(&p).unwrap().mode() & 0o777, 0o600);
        assert_eq!(t.replace(b"second!").unwrap().bytes, 7);
        assert_eq!(std::fs::read(&p).unwrap(), b"second!");
        assert_eq!(std::fs::metadata(&p).unwrap().mode() & 0o777, 0o600);
        assert!(leftovers(&r).is_empty());
        assert!(!format!("{t:?}").contains(r.to_str().unwrap()));
    }

    #[test]
    fn sec1_4335_final_symlink_is_not_replaced() {
        let r = root("finalsym");
        std::fs::write(r.join("victim"), b"keep").unwrap();
        let p = r.join("s.json");
        std::os::unix::fs::symlink(r.join("victim"), &p).unwrap();
        let t = open(&p, 1).unwrap();
        assert_eq!(
            t.replace(b"new").unwrap_err(),
            SnapshotError::TargetNotRegular
        );
        assert_eq!(std::fs::read_link(&p).unwrap(), r.join("victim"));
        assert_eq!(std::fs::read(r.join("victim")).unwrap(), b"keep");
        assert!(leftovers(&r).is_empty());
    }

    #[test]
    fn sec1_4335_final_directory_is_not_replaced() {
        let r = root("finaldir");
        let p = r.join("s.json");
        std::fs::create_dir(&p).unwrap();
        let t = open(&p, 1).unwrap();
        assert_eq!(
            t.replace(b"new").unwrap_err(),
            SnapshotError::TargetNotRegular
        );
        assert!(p.is_dir());
        assert!(leftovers(&r).is_empty());
    }

    #[test]
    fn repair4_4335_over_limit_writes_nothing() {
        let r = root("limit");
        let p = r.join("s.json");
        std::fs::write(&p, b"old").unwrap();
        let t = open(&p, 1).unwrap();
        assert_eq!(
            t.replace(&vec![b'x'; 65537]).unwrap_err(),
            SnapshotError::TooLarge
        );
        assert_eq!(std::fs::read(&p).unwrap(), b"old");
        assert!(leftovers(&r).is_empty());
        assert_eq!(t.replace(&vec![b'x'; 65536]).unwrap().bytes, 65536);
        assert_eq!(std::fs::metadata(&p).unwrap().len(), 65536);
    }

    #[test]
    fn repair4_4335_readers_never_see_partial_content() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};
        let r = root("atomic");
        let p = r.join("s.json");
        let a = vec![b'a'; 48 * 1024];
        let b = vec![b'b'; 40 * 1024];
        let t = open(&p, 1).unwrap();
        t.replace(&a).unwrap();
        let done = Arc::new(AtomicBool::new(false));
        let reader = {
            let (p, a, b, done) = (p.clone(), a.clone(), b.clone(), done.clone());
            std::thread::spawn(move || {
                let mut seen = 0usize;
                while !done.load(Ordering::Relaxed) {
                    let got = std::fs::read(&p).unwrap();
                    assert!(got == a || got == b, "partial content len {}", got.len());
                    seen += 1;
                }
                seen
            })
        };
        for i in 0..500 {
            t.replace(if i % 2 == 0 { &b } else { &a }).unwrap();
        }
        done.store(true, Ordering::Relaxed);
        assert!(reader.join().unwrap() >= 1);
        assert!(leftovers(&r).is_empty());
    }

    /// #4340: 起動時の最終名の検査。不在・通常ファイルは通し、symlink（ダングリング含む）・ディレクトリ・FIFO は拒否する。
    #[test]
    fn sec1_4340_check_target_accepts_absent_and_regular() {
        let r = root("chkok");
        let p = r.join("s.json");
        assert_eq!(open(&p, 1).unwrap().check_target(), Ok(()));
        std::fs::write(&p, b"x").unwrap();
        assert_eq!(open(&p, 1).unwrap().check_target(), Ok(()));
    }

    #[test]
    fn sec1_4340_check_target_rejects_non_regular() {
        let r = root("chkbad");
        // 実在の先への symlink。
        std::fs::write(r.join("victim"), b"keep").unwrap();
        let live = r.join("live.json");
        std::os::unix::fs::symlink(r.join("victim"), &live).unwrap();
        // ダングリング symlink。
        let dangling = r.join("dangling.json");
        std::os::unix::fs::symlink(r.join("nowhere"), &dangling).unwrap();
        // ディレクトリ。
        let dir = r.join("dir.json");
        std::fs::create_dir(&dir).unwrap();
        // FIFO。
        let fifo = r.join("fifo.json");
        let st = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap();
        assert!(st.success());
        for p in [live, dangling, dir, fifo] {
            assert_eq!(
                open(&p, 1).unwrap().check_target(),
                Err(SnapshotError::TargetNotRegular),
                "{p:?}"
            );
        }
        assert!(leftovers(&r).is_empty());
    }
}
