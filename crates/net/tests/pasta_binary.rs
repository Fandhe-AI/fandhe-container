//! pasta のバイナリの検証の結合試験（NET-9・PLUG-11・ERR-1・REPAIR-5・#1936。root 不要・3 OS の既定集合）。
//!
//! 自身の実行ファイルを「偽の pasta」としてコピーして実行する（引数がちょうど `--version` のときだけ偽の pasta
//! として振る舞い、モードはコピー先の親ディレクトリ名で選ぶ）ため `harness = false`。パスの表は
//! `verify_pasta_binary_below`（feature `pasta-test-support`。`/tmp` が 1777 のため anchor より上の所有者・権限
//! の検査を省く試験専用の入口）で照合する。実際の pasta での確認（AppArmor・`argv[0]` のモード）は #1941 の担当。
//! 非 Linux では `Unimplemented` だけを照合する。

#[cfg(target_os = "linux")]
fn main() {
    linux::main();
}

#[cfg(not(target_os = "linux"))]
fn main() {
    use fandhe_container_net::error::NetErrorCode;
    use fandhe_container_net::pasta::binary::{MSG_UNSUPPORTED_OS, verify_pasta_binary};
    let e = verify_pasta_binary(std::path::Path::new("/usr/bin/pasta")).unwrap_err();
    assert_eq!(e.code(), NetErrorCode::Unimplemented);
    assert_eq!(e.message(), MSG_UNSUPPORTED_OS);
    println!("pasta_binary: verification table passed (NET-9)");
}

#[cfg(target_os = "linux")]
mod linux {
    use std::ffi::OsString;
    use std::io::{Read as _, Write as _};
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink};
    use std::path::{Path, PathBuf};
    use std::time::{Duration, Instant};

    use fandhe_container_net::error::{NetError, NetErrorCode};
    use fandhe_container_net::pasta::binary::{
        MSG_NOT_DIR, MSG_NOT_EXECUTABLE, MSG_NOT_FOUND, MSG_NOT_IN_PATH, MSG_NOT_REGULAR,
        MSG_PATH_INVALID, MSG_SETID, MSG_SYMLINK_DIR, MSG_SYMLINK_LOOP, MSG_UNTRUSTED,
        MSG_VERSION_TIMEOUT, MSG_VERSION_TOO_LONG, PastaBinary, search_pasta_in_path_below,
        verify_pasta_binary_below,
    };
    use fandhe_container_net::pasta::version::{
        MSG_VERSION_EXIT, MSG_VERSION_TOO_OLD, MSG_VERSION_UNPARSABLE,
    };

    const GOOD: &str = "pasta 0.0~git20260120.386b5f5-1\nCopyright Red Hat\n";

    /// 偽の pasta 本体。`--version` だけを受け、モード（親ディレクトリ名）ごとに出力を変える。
    fn fake_pasta(mode: &str) -> ! {
        let mut out = std::io::stdout();
        let line = |s: &str| {
            let _ = std::io::stdout().write_all(s.as_bytes());
        };
        match mode {
            "ok" => line(GOOD),
            "old" => line("pasta 0.0~git20260119.386b5f5-1\n"),
            "empty" => {}
            "huge" => line(&"x".repeat(5000)),
            "nonutf8" => {
                let _ = out.write_all(b"pasta \xff\n");
            }
            "passt" => line("passt 0.0~git20260120.386b5f5-1\n"),
            "exit1" => {
                line(GOOD);
                let _ = out.flush();
                std::process::exit(1);
            }
            "hang" => std::thread::sleep(Duration::from_secs(30)),
            "envcheck" => {
                let mut stdin_bytes = Vec::new();
                let _ = std::io::stdin().read_to_end(&mut stdin_bytes);
                let ok = std::env::vars_os().count() == 0
                    && stdin_bytes.is_empty()
                    && std::env::current_dir().is_ok_and(|d| d == Path::new("/"))
                    && std::env::args_os().next().is_some_and(|a| a == "pasta");
                line(if ok { GOOD } else { "bad-env\n" });
            }
            _ => line("unknown-mode\n"),
        }
        let _ = out.flush();
        std::process::exit(0);
    }

    fn expect_err(r: Result<PastaBinary, NetError>, code: NetErrorCode, msg: &str, what: &str) {
        match r {
            Ok(_) => panic!("{what}: expected {code:?} but verification passed"),
            Err(e) => {
                assert_eq!(e.code(), code, "{what}: code ({})", e.message());
                assert_eq!(e.message(), msg, "{what}: message");
            }
        }
    }

    pub fn main() {
        let args: Vec<OsString> = std::env::args_os().skip(1).collect();
        if args.len() == 1 && args[0] == "--version" {
            let exe = std::env::current_exe().expect("current_exe");
            let mode = exe
                .parent()
                .and_then(|p| p.file_name())
                .and_then(|n| n.to_str())
                .unwrap_or("")
                .to_owned();
            fake_pasta(&mode);
        }

        let anchor = std::fs::canonicalize(env!("CARGO_TARGET_TMPDIR")).expect("anchor");
        let base = anchor.join(format!("pasta-binary-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).expect("base");
        let result = std::panic::catch_unwind(|| run(&anchor, &base));
        let _ = std::fs::remove_dir_all(&base);
        if let Err(p) = result {
            std::panic::resume_unwind(p);
        }
        println!("pasta_binary: verification table passed (NET-9)");
    }

    fn mkdir(base: &Path, name: &str, mode: u32) -> PathBuf {
        let d = base.join(name);
        std::fs::create_dir_all(&d).expect("mkdir");
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(mode)).expect("chmod dir");
        d
    }

    /// 現在の実行ファイル（偽の pasta）を `<base>/<dir>/pasta` にコピーして `mode` にする。
    fn place_exe(base: &Path, dir: &str, mode: u32) -> PathBuf {
        let d = mkdir(base, dir, 0o755);
        let f = d.join("pasta");
        std::fs::copy(std::env::current_exe().expect("exe"), &f).expect("copy");
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(mode)).expect("chmod");
        f
    }

    /// 実行しない（検証で落ちる）ファイル。
    fn place_stub(base: &Path, dir: &str, dir_mode: u32, file_mode: u32) -> PathBuf {
        let d = mkdir(base, dir, dir_mode);
        let f = d.join("pasta");
        std::fs::write(&f, b"#!/bin/true\n").expect("write");
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(file_mode)).expect("chmod");
        f
    }

    fn run(anchor: &Path, base: &Path) {
        std::fs::set_permissions(base, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        let verify = |p: &Path| verify_pasta_binary_below(anchor, p);
        use NetErrorCode as C;

        // --version の振る舞い（偽の pasta を子として実行する）。
        let ok = place_exe(base, "ok", 0o755);
        let b = verify(&ok).expect("ok");
        assert_eq!(b.version().as_yyyymmdd(), 20260120);
        assert_eq!(b.path(), ok.as_path());
        assert_eq!(b.requested_path(), ok.as_path());
        assert_eq!(
            b.identity().ino(),
            std::fs::metadata(&ok).expect("md").ino()
        );
        assert_eq!(b.identity().mode(), 0o755);

        let env_ok = place_exe(base, "envcheck", 0o755);
        verify(&env_ok).expect("env_clear / stdin null / cwd / arg0 を満たす");

        let table: [(&str, C, &str); 7] = [
            ("old", C::FailedPrecondition, MSG_VERSION_TOO_OLD),
            ("empty", C::FailedPrecondition, MSG_VERSION_UNPARSABLE),
            ("huge", C::FailedPrecondition, MSG_VERSION_TOO_LONG),
            ("nonutf8", C::FailedPrecondition, MSG_VERSION_UNPARSABLE),
            ("passt", C::FailedPrecondition, MSG_VERSION_UNPARSABLE),
            ("exit1", C::FailedPrecondition, MSG_VERSION_EXIT),
            ("hang", C::Timeout, MSG_VERSION_TIMEOUT),
        ];
        for (mode, code, msg) in table {
            let p = place_exe(base, mode, 0o755);
            let t = Instant::now();
            expect_err(verify(&p), code, msg, mode);
            if mode == "hang" {
                let el = t.elapsed();
                assert!(
                    el >= Duration::from_secs(2) && el < Duration::from_secs(6),
                    "hang: elapsed {el:?}"
                );
            }
        }

        // パスの表。
        expect_err(
            verify(Path::new("relative/pasta")),
            C::InvalidArgument,
            MSG_PATH_INVALID,
            "relative",
        );
        expect_err(
            verify(&base.join("ok/none")),
            C::NotFound,
            MSG_NOT_FOUND,
            "missing",
        );
        let w = place_stub(base, "file775", 0o755, 0o775);
        expect_err(verify(&w), C::PermissionDenied, MSG_UNTRUSTED, "file 0775");
        let d775 = place_stub(base, "dir775", 0o775, 0o755);
        expect_err(
            verify(&d775),
            C::PermissionDenied,
            MSG_UNTRUSTED,
            "dir 0775",
        );
        let sticky = place_stub(base, "sticky", 0o1777, 0o755);
        expect_err(
            verify(&sticky),
            C::PermissionDenied,
            MSG_UNTRUSTED,
            "sticky",
        );
        let p644 = place_stub(base, "mode644", 0o755, 0o644);
        expect_err(
            verify(&p644),
            C::FailedPrecondition,
            MSG_NOT_EXECUTABLE,
            "0644",
        );
        let p4755 = place_stub(base, "mode4755", 0o755, 0o4755);
        expect_err(verify(&p4755), C::FailedPrecondition, MSG_SETID, "4755");
        mkdir(base, "isdir", 0o755);
        let isdir = mkdir(base, "isdir/pasta", 0o755);
        expect_err(
            verify(&isdir),
            C::FailedPrecondition,
            MSG_NOT_REGULAR,
            "directory",
        );
        let notdir = base.join("mode644/pasta/x");
        expect_err(
            verify(&notdir),
            C::FailedPrecondition,
            MSG_NOT_DIR,
            "file as dir",
        );

        // symlink: 祖先は拒否、最終要素は実体まで検証して実体のパスを返す。
        symlink(base.join("ok"), base.join("linkdir")).expect("symlink");
        expect_err(
            verify(&base.join("linkdir/pasta")),
            C::FailedPrecondition,
            MSG_SYMLINK_DIR,
            "symlinked ancestor",
        );
        let lnk = mkdir(base, "lnk-ok", 0o755).join("pasta");
        symlink(&ok, &lnk).expect("symlink");
        let b = verify(&lnk).expect("symlink to good file");
        assert_eq!(b.path(), ok.as_path());
        assert_eq!(b.requested_path(), lnk.as_path());
        let lnk_bad = mkdir(base, "lnk-bad", 0o755).join("pasta");
        symlink(&d775, &lnk_bad).expect("symlink");
        expect_err(
            verify(&lnk_bad),
            C::PermissionDenied,
            MSG_UNTRUSTED,
            "symlink into 0775 dir",
        );
        let loops = mkdir(base, "loops", 0o755);
        symlink(loops.join("l2"), loops.join("l1")).expect("symlink");
        symlink(loops.join("l1"), loops.join("l2")).expect("symlink");
        expect_err(
            verify(&loops.join("l1")),
            C::FailedPrecondition,
            MSG_SYMLINK_LOOP,
            "symlink loop",
        );

        // opt-in の PATH 探索。
        let search = |env: Option<&std::ffi::OsStr>| search_pasta_in_path_below(anchor, env);
        for env in [None, Some(std::ffi::OsStr::new(""))] {
            let e = search(env).unwrap_err();
            assert_eq!((e.code(), e.message()), (C::NotFound, MSG_NOT_IN_PATH));
        }
        let empty = mkdir(base, "emptydir", 0o755);
        let env = std::env::join_paths([
            PathBuf::from("rel"),
            PathBuf::from("/nonexistent-pasta-dir"),
            empty,
            base.join("ok"),
        ])
        .expect("join");
        let (bin, warn) = search(Some(&env)).expect("search");
        assert_eq!(bin.path(), ok.as_path());
        assert_eq!(warn.path(), ok.as_path());
        let env = std::env::join_paths([base.join("dir775"), base.join("ok")]).expect("join");
        let e = search(Some(&env)).map(|_| ()).unwrap_err();
        assert_eq!(
            (e.code(), e.message()),
            (C::PermissionDenied, MSG_UNTRUSTED),
            "最初の候補の失敗で止まり後ろへ進まない"
        );
    }
}
