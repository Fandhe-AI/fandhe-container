//! secrets / configs 注入（`fandhe_container_core::exec::inject_files`）の結合試験（SUP-12・TASK-169.4.2・MS-9）。
//!
//! `harness = false` の単一スレッド `main` で動かす理由・流れは `tmpfs_mount.rs` と同じ（`Cargo.toml` の
//! `[[test]]`）。非 Linux では `exec` モジュール自体がビルド対象外。
//!
//! # 流れ
//! - 親: `proc/`・`dev/`・`outside/` と symlink `link -> outside` を持つ rootfs を作る → 分離（root は
//!   rootful、非 root は rootless）→ 自身を `--child <rootfs>` で起動（新しい PID namespace の PID 1）
//!   → タイムアウト付きで終了コード 0 を待つ（REPAIR-5）→ 子の終了後（mount namespace が消えた後）に
//!   ホスト側の rootfs を走査し、注入先が空で内容を含むファイルが 1 つも無いことを照合する → 成功行を出力する
//! - 子: `establish` → `prepare_rootfs` の後、同じ分離の中で次を順に照合する
//!   1. **失敗時の後始末**: `/rb/one`（自動作成）→ `/link/x`（symlink で拒否）の 2 ディレクトリを適用し、
//!      `path_symlink_or_not_directory` で失敗すること、1 件目の tmpfs が mountinfo から消えていること、
//!      自動作成した `rb` が rootfs に残らないこと、symlink の先に何も作られないことを照合する
//!   2. **成功経路**: 2 ディレクトリ・3 ファイル（モード 0444 と 0400）を注入 → `pivot_root` の後、内容が
//!      一致し、`stat` のモードが指定どおりで、mountinfo で当該マウントが fstype `tmpfs` かつ
//!      `ro,nosuid,nodev,noexec` であることを具体値で照合する
//!   3. **書き込み拒否**: 既存ファイルを書き込みで開く・新規ファイルの作成・削除・`chmod` が、いずれも
//!      `EROFS`（errno 30）で失敗することを具体値で照合する
//!
//! 内容はダミー値のみ。rootless でも tmpfs は user namespace 内で作れるため両経路とも成功を要求する。
//!
//! # 実機前提テストとしての分離
//! root もしくは非特権 user namespace を許可するホストが必要で、GitHub ホステッド runner では
//! 保証できないため `-- --ignored` 指定時のみ実行する（ci.md「実機前提テスト」）。CI では
//! `integration-test` ジョブ（ubuntu-latest）が AppArmor の制限を緩和した後に rootless 経路で実行し、
//! 成功行 `inject_files: content, read-only and rollback verified (root=false)` を照合する。rootful 経路
//! （root）の実行は root 権限コマンドのため明示指示のもとで行い、結果を PR に記録する。

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("inject_files: Linux only, not applicable on this OS");
}

#[cfg(target_os = "linux")]
fn main() {
    // `-- --ignored` を付けたときだけ実行する。子は `--child <rootfs>` で再入する。
    if std::env::args().any(|a| a == "--ignored" || a == "--child") {
        linux::run();
    } else {
        println!(
            "inject_files: ignored (real-machine test; run with `-- --ignored`, see AGENTS.md)"
        );
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    use fandhe_container_core::exec::{
        IsolationConfig, IsolationStage, MountIsolation, Namespace, NamespaceSet, PreparedRootfs,
        ViolationReason, inject_files, isolate, isolate_rootful_host_root, pivot_root, plan,
        plan_rootful_host_root, prepare_rootfs,
    };
    use fandhe_container_core::injected_files::{
        InjectedContent, InjectedFileMode, InjectedFileSet, InjectedFileSpec,
    };

    /// 注入するダミーの内容（実際の秘密情報ではない）。ホストへ出ていないことの照合に使う。
    const SENTINEL: &str = "FANDHE-INJECT-SENTINEL-DUMMY-VALUE";
    const EROFS: i32 = 30;

    fn is_root() -> bool {
        std::fs::read_to_string("/proc/self/status")
            .expect("read status")
            .lines()
            .find(|l| l.starts_with("Uid:"))
            .and_then(|l| l.split_whitespace().nth(2).map(str::to_string))
            .as_deref()
            == Some("0")
    }

    fn timeout() -> Duration {
        let secs = std::env::var("FANDHE_CONTAINER_TEST_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|s| (1..=600).contains(s))
            .unwrap_or(10);
        Duration::from_secs(secs)
    }

    pub fn run() {
        let args: Vec<String> = std::env::args().collect();
        match args.iter().position(|a| a == "--child") {
            Some(i) => {
                let rootfs = args.get(i + 1).expect("rootfs path after --child");
                child(Path::new(rootfs));
            }
            None => parent(),
        }
    }

    /// 一時 rootfs（drop で削除）。
    struct Rootfs(PathBuf);

    impl Drop for Rootfs {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn make_rootfs() -> Rootfs {
        let base = std::fs::canonicalize(std::env::temp_dir())
            .expect("canonicalize temp_dir")
            .join(format!("fandhe-inject-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join("proc")).expect("create rootfs/proc");
        std::fs::create_dir_all(base.join("dev")).expect("create rootfs/dev");
        // 失敗シナリオ用: rootfs 内の symlink（辿らずに拒否されること）とその先。
        std::fs::create_dir_all(base.join("outside")).expect("create rootfs/outside");
        std::os::unix::fs::symlink("outside", base.join("link")).expect("create rootfs/link");
        Rootfs(base)
    }

    fn parent() {
        let rootfs = make_rootfs();
        let root = is_root();
        // euid 0 での自 ID 写像は SEC-5 で拒否されるため、root では User を除く rootful 構成にする。
        let mut namespaces = NamespaceSet::empty()
            .with(Namespace::Pid)
            .with(Namespace::Mount)
            .with(Namespace::Uts)
            .with(Namespace::Ipc);
        if !root {
            namespaces = namespaces.with(Namespace::User);
        }
        let config = IsolationConfig {
            namespaces,
            hostname: None,
        };
        let result = if root {
            plan_rootful_host_root(&config).and_then(|p| isolate_rootful_host_root(&p))
        } else {
            plan(&config).and_then(|p| isolate(&p))
        };
        match result {
            Ok(_) => {
                run_child(&rootfs.0);
                assert_nothing_leaked_to_host(&rootfs.0);
                println!("inject_files: content, read-only and rollback verified (root={root})");
            }
            Err(err) => panic!("isolate failed: {err}"),
        }
    }

    /// 自身を `--child <rootfs>` で起動する。分離後の最初の子なので新しい PID namespace の PID 1 になる。
    fn run_child(rootfs: &Path) {
        let exe = std::env::current_exe().expect("current_exe");
        let mut child = Command::new(exe)
            .arg("--child")
            .arg(rootfs)
            .stdin(Stdio::null())
            .spawn()
            .expect("spawn child");
        let deadline = Instant::now() + timeout();
        loop {
            match child.try_wait().expect("try_wait") {
                Some(status) => {
                    assert_eq!(status.code(), Some(0), "child must exit with 0");
                    return;
                }
                None if Instant::now() >= deadline => {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!("child did not exit within {:?}", timeout());
                }
                None => std::thread::sleep(Duration::from_millis(20)),
            }
        }
    }

    /// 内容がホストのディスクへ出ていないこと（SUP-12・TASK-169.4.2。内容は tmpfs のメモリ上にのみ置く）。
    /// 子の終了で mount namespace が消えた後の rootfs を走査し、注入先ディレクトリが空であり、番兵を含む
    /// ファイルが 1 つも無いことを確かめる。
    fn assert_nothing_leaked_to_host(rootfs: &Path) {
        for dir in ["run/secrets", "etc/app"] {
            let entries: Vec<_> = std::fs::read_dir(rootfs.join(dir))
                .unwrap_or_else(|e| panic!("read_dir {dir}: {e}"))
                .collect();
            assert_eq!(entries.len(), 0, "{dir} on the host must stay empty");
        }
        fn walk(dir: &Path) {
            for entry in std::fs::read_dir(dir).expect("read_dir") {
                let entry = entry.expect("entry");
                let ty = entry.file_type().expect("file_type");
                if ty.is_dir() {
                    walk(&entry.path());
                } else if ty.is_file() {
                    let body = std::fs::read(entry.path()).expect("read");
                    assert!(
                        !String::from_utf8_lossy(&body).contains(SENTINEL),
                        "the content must not reach the host disk: {}",
                        entry.path().display()
                    );
                }
            }
        }
        walk(rootfs);
    }

    /// `/proc/self/mountinfo` の 1 行から `(mount_point, mount_options, fstype)` を取り出す。
    fn parse_line(line: &str) -> Option<(String, String, String)> {
        let fields: Vec<&str> = line.split(' ').collect();
        let sep = fields.iter().position(|f| *f == "-")?;
        Some((
            (*fields.get(4)?).to_owned(),
            (*fields.get(5)?).to_owned(),
            (*fields.get(sep + 1)?).to_owned(),
        ))
    }

    fn set(files: &[(&str, &str, u32)]) -> InjectedFileSet {
        let mut s = InjectedFileSet::new();
        for (dest, body, mode) in files {
            s.push(
                InjectedFileSpec::new(
                    dest,
                    InjectedContent::from_bytes(body.as_bytes().to_vec()).expect("content"),
                    InjectedFileMode::new(*mode).expect("mode"),
                )
                .expect("spec"),
            )
            .expect("push");
        }
        s
    }

    /// 失敗時の後始末: 2 件目が symlink で拒否されたら、1 件目の tmpfs が mountinfo から消え、
    /// 自動作成したディレクトリも rootfs に残らない。
    fn rollback_scenario(isolation: &MountIsolation, prepared: &PreparedRootfs, rootfs: &Path) {
        let s = set(&[
            ("/rb/one/f", SENTINEL, 0o444),
            ("/link/x/f", SENTINEL, 0o444),
        ]);
        let err = inject_files(isolation, prepared, &s).expect_err("symlink must be rejected");
        assert_eq!(err.stage, IsolationStage::InjectFiles);
        assert_eq!(
            err.violation.as_ref().map(|v| v.reason),
            Some(ViolationReason::PathSymlinkOrNotDirectory)
        );
        assert!(!err.message.contains(SENTINEL));
        // pivot 前なので、呼び出しスレッドの mount namespace を元の procfs 経由で読む。
        let info = std::fs::read_to_string("/proc/thread-self/mountinfo").expect("mountinfo");
        let leftover: Vec<String> = info
            .lines()
            .filter_map(parse_line)
            .map(|l| l.0)
            .filter(|point| point.ends_with("/rb/one") || point.ends_with("/rb"))
            .collect();
        assert_eq!(leftover, Vec::<String>::new(), "tmpfs must be unmounted");
        assert_eq!(
            std::fs::symlink_metadata(rootfs.join("rb"))
                .map(|m| m.is_dir())
                .map_err(|e| e.kind()),
            Err(std::io::ErrorKind::NotFound),
            "auto-created directories must be removed"
        );
        assert_eq!(
            std::fs::read_dir(rootfs.join("outside"))
                .expect("read outside")
                .count(),
            0,
            "nothing must be created behind the symlink"
        );
    }

    fn assert_erofs<T: std::fmt::Debug>(what: &str, r: std::io::Result<T>) {
        let e = r.expect_err(what);
        assert_eq!(e.raw_os_error(), Some(EROFS), "{what}: {e}");
    }

    fn child(rootfs: &Path) {
        assert_eq!(
            std::process::id(),
            1,
            "child must be PID 1 of the new PID namespace"
        );
        let isolation = MountIsolation::establish().expect("establish mount isolation");
        let prepared = prepare_rootfs(&isolation, rootfs).expect("prepare rootfs");
        rollback_scenario(&isolation, &prepared, rootfs);

        let s = set(&[
            ("/run/secrets/db_password", SENTINEL, 0o400),
            ("/etc/app/app.conf", "key=value", 0o444),
            ("/run/secrets/api_token", "dummy-token", 0o444),
        ]);
        let report = inject_files(&isolation, &prepared, &s).expect("inject files");
        type Applied<'a> = (&'a str, Vec<(&'a str, u32)>, bool);
        let applied: Vec<Applied<'_>> = report
            .directories
            .iter()
            .map(|d| {
                (
                    d.destination.as_str(),
                    d.files.iter().map(|f| (f.name.as_str(), f.mode)).collect(),
                    d.read_only,
                )
            })
            .collect();
        assert_eq!(
            applied,
            vec![
                (
                    "/run/secrets",
                    vec![("db_password", 0o400), ("api_token", 0o444)],
                    true
                ),
                ("/etc/app", vec![("app.conf", 0o444)], true),
            ]
        );

        pivot_root(&isolation, prepared).expect("pivot_root");

        let info = std::fs::read_to_string("/proc/self/mountinfo").expect("mountinfo");
        for point in ["/run/secrets", "/etc/app"] {
            let (_, opts, fstype) = info
                .lines()
                .filter_map(parse_line)
                .find(|l| l.0 == point)
                .unwrap_or_else(|| panic!("{point} must be mounted:\n{info}"));
            assert_eq!(fstype, "tmpfs", "{point} fstype");
            let opts: Vec<&str> = opts.split(',').collect();
            for want in ["ro", "nosuid", "nodev", "noexec"] {
                assert!(opts.contains(&want), "{point} must be {want}: {opts:?}");
            }
        }

        for (path, body, mode) in [
            ("/run/secrets/db_password", SENTINEL, 0o400),
            ("/run/secrets/api_token", "dummy-token", 0o444),
            ("/etc/app/app.conf", "key=value", 0o444),
        ] {
            assert_eq!(std::fs::read_to_string(path).expect(path), body, "{path}");
            let m = std::fs::metadata(path).expect(path).permissions().mode() & 0o7777;
            assert_eq!(m, mode, "{path} mode");
        }

        // コンテナ内からの書き込み・作成・削除・chmod はすべて EROFS で拒否される。
        let target = "/run/secrets/db_password";
        assert_erofs(
            "open for write",
            std::fs::OpenOptions::new().write(true).open(target),
        );
        assert_erofs("create", std::fs::File::create("/run/secrets/new"));
        assert_erofs("remove", std::fs::remove_file(target));
        assert_erofs(
            "chmod",
            std::fs::set_permissions(target, std::fs::Permissions::from_mode(0o777)),
        );
        assert_eq!(std::fs::read_to_string(target).expect("reread"), SENTINEL);
    }
}
