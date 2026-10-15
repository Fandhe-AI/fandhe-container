//! 読み取り専用にするパスの固定集合（`/proc` 配下の 5 件と `/sys`）の結合試験
//! （SEC-2・CORE-1・CORE-5・SEC-5・TASK-29 追補・#1850。ESC-04・ESC-05 の前提）。
//!
//! `harness = false` の単一スレッド `main` で動かす理由は `default_devices.rs` と同じ（`Cargo.toml` の `[[test]]`）。
//! 非 Linux では `exec` モジュール自体がビルド対象外。
//!
//! # 流れ
//! - 親: `proc/` と、利用者所有のフィクスチャ `sys/fs/cgroup/release_agent`（空の通常ファイル・0644）を持つ rootfs を
//!   作る。分離（root は rootful、非 root は rootless）→ `spawn_container_probe`（`setup` なしの最小構成。
//!   `run_pre_pivot` が `readonly_paths` を常に走らせる）→ 子をタイムアウト付きで待つ（REPAIR-5）。
//! - 子（pivot 後。新しい PID namespace の PID 1）: 観測値を pipe へ `key=value` の行で書く。
//!   `/proc/self/mountinfo` の対象 6 件のマウントポイントの `ro`、書き込み用 `open(2)` の errno（1 バイトも書かない）、
//!   読み取りが従来どおり成功すること。
//! - 親は、子の終了後に観測値を具体値で照合し、ホスト側 rootfs に副作用が無い（フィクスチャの内容・モード不変、
//!   `proc` が空）ことを確かめる。
//!
//! # 期待値
//! - 存在する対象はすべて mountinfo に `ro` で現れる（`/sys` はフィクスチャがあるので含む）
//! - rootful: `/proc/sys/kernel/core_pattern` と `/proc/sysrq-trigger` の書き込み open は `EROFS`（30）
//! - rootfs の `/sys` 配下の利用者所有フィクスチャの書き込み open は、rootless・rootful とも `EROFS`
//! - rootless の `/proc` 配下: 対象はホストの root 所有で、読み取り専用マウントの検査より先にパーミッション検査で
//!   `EACCES`（13）になる可能性が高い。`EROFS` か `EACCES` のどちらかであることを要求し、観測値を出力する
//!   （mountinfo の `ro` が主な保証。判定は弱めず、実機結果で期待を確定する）
//!
//! # 実機前提テストとしての分離
//! Linux 5.12 以降（`mount_setattr`）で、root もしくは非特権 user namespace を許可するホストが必要。GitHub ホステッド
//! runner では保証できないため `-- --ignored` 指定時のみ実行する（ci.md「実機前提テスト」）。rootful 経路（root）の
//! 実行は root 権限コマンドのため明示指示のもとで行い、結果を #1621 へ記録する。

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("readonly_paths: Linux only, not applicable on this OS");
}

#[cfg(target_os = "linux")]
fn main() {
    if std::env::args().any(|a| a == "--ignored") {
        linux::run();
    } else {
        println!(
            "readonly_paths: ignored (real-machine test; run with `-- --ignored`, see AGENTS.md)"
        );
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::io::{Read as _, Write as _};
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    use fandhe_container_core::exec::{
        ChildExit, IsolationConfig, Namespace, NamespaceSet, StagePipeline, isolate,
        isolate_rootful_host_root, plan, plan_rootful_host_root, spawn_container_probe,
    };
    use fandhe_container_core::path_masks::{READONLY_PROC_PATHS, READONLY_SYS_PATH};

    /// `EROFS`・`EACCES`（x86_64・aarch64 とも同値）。
    const EROFS: i32 = 30;
    const EACCES: i32 = 13;

    /// フィクスチャ（rootfs からの相対パス）。ESC-04 の `release_agent` の代役。
    const FIXTURE_REL: [&str; 4] = ["sys", "fs", "cgroup", "release_agent"];

    fn timeout() -> Duration {
        let secs = std::env::var("FANDHE_CONTAINER_TEST_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|s| (1..=600).contains(s))
            .unwrap_or(10);
        Duration::from_secs(secs)
    }

    fn is_root() -> bool {
        std::fs::read_to_string("/proc/self/status")
            .expect("read status")
            .lines()
            .find(|l| l.starts_with("Uid:"))
            .and_then(|l| l.split_whitespace().nth(2).map(str::to_string))
            .as_deref()
            == Some("0")
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
            .join(format!("fandhe-readonly-paths-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join("proc")).expect("create rootfs/proc");
        let fixture = FIXTURE_REL.iter().fold(base.clone(), |p, c| p.join(c));
        std::fs::create_dir_all(fixture.parent().expect("parent")).expect("create sys/fs/cgroup");
        std::fs::write(&fixture, b"").expect("create fixture");
        std::fs::set_permissions(&fixture, std::fs::Permissions::from_mode(0o644))
            .expect("chmod fixture");
        Rootfs(base)
    }

    /// 書き込み用に開くだけで書かない（制限が欠けてもホストへ作用させないため）。失敗時の errno か `0`（開けた）。
    fn open_for_write_errno(path: &str) -> i32 {
        match std::fs::OpenOptions::new().write(true).open(path) {
            Ok(_) => 0,
            Err(e) => e.raw_os_error().unwrap_or(-1),
        }
    }

    /// 子（コンテナ内）の観測。結果は `writer` へ 1 行ずつ書く。
    fn observe(mut writer: std::io::PipeWriter) {
        let mountinfo = std::fs::read_to_string("/proc/self/mountinfo").expect("mountinfo");
        let mut targets: Vec<&str> = READONLY_PROC_PATHS.to_vec();
        targets.push(READONLY_SYS_PATH);
        for t in &targets {
            let exists = std::fs::symlink_metadata(t).is_ok();
            let ro = mountinfo.lines().find_map(|l| {
                let f: Vec<&str> = l.split(' ').collect();
                (f.get(4) == Some(t))
                    .then(|| f.get(5).is_some_and(|o| o.split(',').any(|x| x == "ro")))
            });
            writeln!(writer, "exists:{t}={exists}").expect("write");
            writeln!(writer, "mount_ro:{t}={ro:?}").expect("write");
        }
        let fixture = format!("/{}", FIXTURE_REL.join("/"));
        for p in [
            "/proc/sys/kernel/core_pattern",
            "/proc/sysrq-trigger",
            &fixture,
        ] {
            writeln!(writer, "open_w_errno:{p}={}", open_for_write_errno(p)).expect("write");
        }
        let hostname = std::fs::read_to_string("/proc/sys/kernel/hostname").is_ok();
        writeln!(writer, "read_ok:/proc/sys/kernel/hostname={hostname}").expect("write");
    }

    pub fn run() {
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
        result.unwrap_or_else(|err| panic!("isolate failed: {err}"));

        let (mut reader, writer) = std::io::pipe().expect("create pipe");
        // `setup` なしの最小構成。`readonly_paths` 段は常に走る（#1850）。
        let child = spawn_container_probe(&rootfs.0, StagePipeline::new(), move || observe(writer))
            .unwrap_or_else(|e| panic!("spawn: {e}"));
        let exit = child.wait_timeout(timeout()).unwrap_or_else(|e| {
            let _ = child.kill_and_reap(Duration::from_secs(5));
            panic!("wait: {e}")
        });
        assert!(
            matches!(exit, ChildExit::Exited(0)),
            "child must exit with 0, got {exit:?}"
        );
        let mut text = String::new();
        reader
            .by_ref()
            .take(64 * 1024)
            .read_to_string(&mut text)
            .expect("read observations");
        verify(&text, root);
        verify_host_untouched(&rootfs.0);
        println!(
            "readonly_paths: /proc bus,fs,irq,sys,sysrq-trigger and /sys mounted read-only, writes refused, reads allowed (root={root})"
        );
    }

    fn lookup<'a>(text: &'a str, key: &str) -> &'a str {
        text.lines()
            .find_map(|l| l.strip_prefix(&format!("{key}=")))
            .unwrap_or_else(|| panic!("missing observation {key}:\n{text}"))
    }

    fn verify(text: &str, root: bool) {
        let mut verified = 0usize;
        let mut targets: Vec<&str> = READONLY_PROC_PATHS.to_vec();
        targets.push(READONLY_SYS_PATH);
        for t in &targets {
            let exists = lookup(text, &format!("exists:{t}")) == "true";
            if *t == READONLY_SYS_PATH {
                assert!(exists, "the /sys fixture must exist");
            }
            if exists {
                assert_eq!(
                    lookup(text, &format!("mount_ro:{t}")),
                    "Some(true)",
                    "{t} must be a read-only mount point"
                );
                verified += 1;
            }
        }
        // `/sys` と、この環境に実在する `/proc` 配下の対象の件数（最低でも `/sys` + `/proc/sys`）。
        assert!(verified >= 2, "too few read-only targets: {verified}");
        println!("readonly_paths: observed {verified} read-only mount point(s)");

        assert_eq!(
            lookup(text, "read_ok:/proc/sys/kernel/hostname"),
            "true",
            "reads must keep working"
        );
        let fixture = format!("/{}", FIXTURE_REL.join("/"));
        assert_eq!(
            lookup(text, &format!("open_w_errno:{fixture}")),
            EROFS.to_string(),
            "a user-owned file under /sys must be refused with EROFS"
        );
        for p in ["/proc/sys/kernel/core_pattern", "/proc/sysrq-trigger"] {
            let errno: i32 = lookup(text, &format!("open_w_errno:{p}"))
                .parse()
                .expect("errno");
            println!("readonly_paths: open(O_WRONLY) {p} -> errno {errno}");
            if root {
                assert_eq!(errno, EROFS, "{p} must be refused with EROFS (rootful)");
            } else {
                assert!(
                    errno == EROFS || errno == EACCES,
                    "{p} must be refused with EROFS or EACCES (rootless), got {errno}"
                );
            }
        }
    }

    fn verify_host_untouched(rootfs: &Path) {
        let fixture = FIXTURE_REL
            .iter()
            .fold(rootfs.to_path_buf(), |p, c| p.join(c));
        assert_eq!(std::fs::read(&fixture).expect("read fixture"), b"");
        let mode = std::fs::metadata(&fixture)
            .expect("stat")
            .permissions()
            .mode()
            & 0o7777;
        assert_eq!(mode, 0o644);
        assert_eq!(
            std::fs::read_dir(rootfs.join("proc"))
                .expect("read proc")
                .count(),
            0,
            "host-side proc must stay empty"
        );
    }
}
