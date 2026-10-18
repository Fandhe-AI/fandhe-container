//! `mounts[]` の sysfs を受けて `/sys` を読み取り専用で供給する段（`mount_sysfs`）の結合試験
//! （SEC-2・OCI-4・CORE-1・CORE-5・TASK-29 追補・#2020。受け入れ条件 A1）。
//!
//! `harness = false` の単一スレッド `main` で動かす理由は `default_devices.rs` と同じ（`Cargo.toml` の `[[test]]`）。
//! 非 Linux では `exec` モジュール自体がビルド対象外。
//!
//! # 流れ
//! - 親: `proc/` と `sys/` を持つ rootfs を作る。分離（root は rootful、非 root は rootless）→
//!   `spawn_container_probe_with_sysfs`（`verify_pinned` の直後に `mount_sysfs`、続いて `readonly_paths`・`masked_paths`・
//!   `pivot_root` を本番と同じ順序で適用）→ 子をタイムアウト付きで待つ（REPAIR-5）。
//! - 子（pivot 後。新しい PID namespace の PID 1）: `/proc/self/mountinfo` と書き込み用 `open(2)` の errno を
//!   `key=value` の行で pipe へ書く（1 バイトも書かない）。
//! - 親は具体値で照合し、ホスト側 rootfs に副作用が無い（`sys` が空のまま）ことを確かめる。
//!
//! # 期待値
//! - `/sys` の最上位のマウントの fstype は `sysfs`、per-mount options に `ro`・`nosuid`・`nodev`・`noexec` がある
//! - `/sys` 配下のすべてのマウントも同じ 4 つを持つ（rootless はホストの `/sys` の再帰 bind のため、`/sys/fs/cgroup` 等が
//!   あればその行も含めて照合する）。rootful（新しい sysfs）では `/sys` 配下に子マウントが無い
//! - `/sys/kernel/uevent_helper` 等の既存ファイルへの書き込み `open` は `EROFS`（30）。rootless はホストの root 所有の
//!   ファイルでパーミッション検査が先に `EACCES`（13）になり得るため `EROFS` か `EACCES` を要求し、観測値を出力する
//!   （mountinfo の `ro` が主な保証。`readonly_paths` と同じ流儀）
//! - `/sys/fs/cgroup/cgroup.procs` があれば、書き込み `open` は拒否される（`exec::setns` の前提の裏付け）
//!
//! # 判定ロジックの自己照合（REPAIR-12）
//! mountinfo の判定（`sys_tree_violations`）は特権なしの純関数で、合成 fixture による自己照合を `--ignored` 指定の有無に
//! かかわらず毎回実行する（CI の `cargo test --workspace` で走る）。
//!
//! # 実機前提テストとしての分離
//! Linux 5.12 以降（`open_tree`・`move_mount`・`mount_setattr`）で、root もしくは非特権 user namespace を許可する
//! ホストが必要。GitHub ホステッド runner では保証できないため `-- --ignored` 指定時のみ実行する（ci.md「実機前提テスト」）。
//! rootful 経路（root）の実行は root 権限コマンドのため明示指示のもとで行い、結果を #1621 へ記録する。

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("sysfs_mount: Linux only, not applicable on this OS");
}

#[cfg(target_os = "linux")]
fn main() {
    linux::self_check();
    if std::env::args().any(|a| a == "--ignored") {
        linux::run();
    } else {
        println!(
            "sysfs_mount: ignored (real-machine test; run with `-- --ignored`, see AGENTS.md)"
        );
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::io::{Read as _, Write as _};
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    use fandhe_container_core::exec::{
        ChildExit, DevptsGidSource, IsolationConfig, Namespace, NamespaceSet, StagePipeline,
        isolate, isolate_rootful_host_root, plan, plan_rootful_host_root,
        spawn_container_probe_with_sysfs,
    };
    use fandhe_container_core::oci_runtime::{SysfsMountSpec, parse_config_bytes};
    use fandhe_container_core::rootless::single_id_mapping;

    /// `EROFS`・`EACCES`（x86_64・aarch64 とも同値）。
    const EROFS: i32 = 30;
    const EACCES: i32 = 13;

    /// 書き込み用 open の対象候補（存在するものだけを観測する）。
    const WRITE_TARGETS: [&str; 3] = [
        "/sys/kernel/uevent_helper",
        "/sys/kernel/mm/transparent_hugepage/enabled",
        "/sys/class/net/lo/mtu",
    ];

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
            .join(format!("fandhe-sysfs-mount-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join("proc")).expect("create rootfs/proc");
        std::fs::create_dir_all(base.join("sys")).expect("create rootfs/sys");
        Rootfs(base)
    }

    /// 書き込み用に開くだけで書かない（制限が欠けてもホストへ作用させないため）。失敗時の errno か `0`（開けた）。
    fn open_for_write_errno(path: &str) -> i32 {
        match std::fs::OpenOptions::new().write(true).open(path) {
            Ok(_) => 0,
            Err(e) => e.raw_os_error().unwrap_or(-1),
        }
    }

    /// mountinfo を解析した 1 行（判定に使う欄のみ）。
    struct Mnt {
        mountpoint: String,
        opts: Vec<String>,
        fstype: String,
    }

    /// mountinfo を解析する。カーネル応答（外部入力）として `get()` で扱い、壊れた行は `Err`（fail-closed）。
    fn parse_mountinfo(text: &str) -> Result<Vec<Mnt>, String> {
        text.lines()
            .filter(|l| !l.is_empty())
            .map(|l| {
                let bad = || format!("malformed mountinfo line: {l}");
                let f: Vec<&str> = l.split(' ').collect();
                let dash = f.iter().position(|x| *x == "-").ok_or_else(bad)?;
                Ok(Mnt {
                    mountpoint: f.get(4).ok_or_else(bad)?.to_string(),
                    opts: f
                        .get(5)
                        .ok_or_else(bad)?
                        .split(',')
                        .map(str::to_string)
                        .collect(),
                    fstype: f.get(dash + 1).ok_or_else(bad)?.to_string(),
                })
            })
            .collect()
    }

    /// `/sys` とその配下のマウントの違反一覧（空なら合格）と、`/sys` 配下の子マウント数。壊れた mountinfo は `Err`。
    ///
    /// 最上位の `/sys` が sysfs であること、`/sys` とその配下のすべてのマウントが `ro,nosuid,nodev,noexec` を持つこと。
    fn sys_tree_violations(mountinfo: &str) -> Result<(Vec<String>, usize), String> {
        let mnts = parse_mountinfo(mountinfo)?;
        let mut violations = Vec::new();
        // 同じマウントポイントに重なる行のうち、最後の行が見えている最上位（mountinfo は作成順）。
        match mnts.iter().rev().find(|m| m.mountpoint == "/sys") {
            None => violations.push("/sys has no mount".to_string()),
            Some(top) if top.fstype != "sysfs" => {
                violations.push("the top mount of /sys is not sysfs".to_string());
            }
            Some(_) => {}
        }
        let mut children = 0;
        for m in &mnts {
            let is_top = m.mountpoint == "/sys";
            if !is_top && !m.mountpoint.starts_with("/sys/") {
                continue;
            }
            if !is_top {
                children += 1;
            }
            for flag in ["ro", "nosuid", "nodev", "noexec"] {
                if !m.opts.iter().any(|o| o == flag) {
                    violations.push(format!("{} lacks {flag}", m.mountpoint));
                }
            }
        }
        Ok((violations, children))
    }

    /// `sys_tree_violations` の合成 fixture による自己照合（特権不要。毎回実行する）。
    pub fn self_check() {
        let good = "10 1 0:5 / /proc rw - proc proc rw\n\
                    11 1 0:6 / /sys ro,nosuid,nodev,noexec - sysfs sysfs rw\n\
                    12 11 0:7 / /sys/fs/cgroup ro,nosuid,nodev,noexec - cgroup2 cgroup2 rw\n\
                    13 1 0:8 / /sysx rw - tmpfs tmpfs rw\n";
        assert_eq!(sys_tree_violations(good), Ok((vec![], 1)));
        let child_rw = good.replace(
            "12 11 0:7 / /sys/fs/cgroup ro,",
            "12 11 0:7 / /sys/fs/cgroup rw,",
        );
        assert_eq!(
            sys_tree_violations(&child_rw),
            Ok((vec!["/sys/fs/cgroup lacks ro".to_string()], 1))
        );
        let top_rw = good.replace("/sys ro,nosuid", "/sys rw,nosuid");
        assert_eq!(
            sys_tree_violations(&top_rw),
            Ok((vec!["/sys lacks ro".to_string()], 1))
        );
        let not_sysfs = good.replace("sysfs sysfs rw", "tmpfs tmpfs rw");
        assert_eq!(
            sys_tree_violations(&not_sysfs),
            Ok((vec!["the top mount of /sys is not sysfs".to_string()], 1))
        );
        assert_eq!(
            sys_tree_violations("10 1 0:5 / /proc rw - proc proc rw\n"),
            Ok((vec!["/sys has no mount".to_string()], 0))
        );
        assert!(sys_tree_violations("10 1 0:5 / /sys rw\n").is_err());
        println!("sysfs_mount: mountinfo judgement self-check passed");
    }

    /// 子（コンテナ内）の観測。結果は `writer` へ 1 行ずつ書く。
    fn observe(mut writer: std::io::PipeWriter) {
        let mountinfo = std::fs::read_to_string("/proc/self/mountinfo").expect("mountinfo");
        let (violations, children) = sys_tree_violations(&mountinfo)
            .unwrap_or_else(|e| (vec![format!("malformed: {e}")], 0));
        writeln!(writer, "violations={}", violations.len()).expect("write");
        for (i, msg) in violations.iter().enumerate() {
            writeln!(writer, "violation:{i}={msg}").expect("write");
        }
        writeln!(writer, "children={children}").expect("write");
        let top_fstype = parse_mountinfo(&mountinfo).ok().and_then(|m| {
            m.iter()
                .rev()
                .find(|x| x.mountpoint == "/sys")
                .map(|x| x.fstype.clone())
        });
        writeln!(writer, "top_fstype={top_fstype:?}").expect("write");
        for p in WRITE_TARGETS {
            let exists = std::fs::symlink_metadata(p).is_ok();
            writeln!(writer, "exists:{p}={exists}").expect("write");
            if exists {
                writeln!(writer, "open_w_errno:{p}={}", open_for_write_errno(p)).expect("write");
            }
        }
        let cgroup_procs = "/sys/fs/cgroup/cgroup.procs";
        let exists = std::fs::symlink_metadata(cgroup_procs).is_ok();
        writeln!(writer, "exists:{cgroup_procs}={exists}").expect("write");
        if exists {
            writeln!(
                writer,
                "open_w_errno:{cgroup_procs}={}",
                open_for_write_errno(cgroup_procs)
            )
            .expect("write");
        }
        let readable = std::fs::read_dir("/sys/kernel").is_ok();
        writeln!(writer, "read_ok:/sys/kernel={readable}").expect("write");
    }

    pub fn run() {
        let rootfs = make_rootfs();
        let root = is_root();
        // 親（user namespace に入る前）の実効 gid。rootless の devpts の `gid=` 決定に使う。
        let egid: u32 = std::fs::read_to_string("/proc/self/status")
            .expect("read status")
            .lines()
            .find(|l| l.starts_with("Gid:"))
            .and_then(|l| l.split_whitespace().nth(2).map(str::to_string))
            .and_then(|v| v.parse().ok())
            .expect("parse egid");
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

        let spec = sysfs_spec();
        let gid_map;
        let devices = if root {
            DevptsGidSource::Rootful
        } else {
            gid_map = single_id_mapping(egid).expect("single id mapping");
            DevptsGidSource::Rootless(&gid_map)
        };
        let (mut reader, writer) = std::io::pipe().expect("create pipe");
        let child = spawn_container_probe_with_sysfs(
            &rootfs.0,
            StagePipeline::new(),
            devices,
            &spec,
            move || observe(writer),
        )
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
            "sysfs_mount: /sys is a read-only sysfs (nosuid,nodev,noexec), writes refused, reads allowed (root={root})"
        );
    }

    /// OCI 既定の sysfs の指定（`start` が検証するのと同じ変換）。
    fn sysfs_spec() -> SysfsMountSpec {
        let v = serde_json::json!({
            "ociVersion": "1.2.0",
            "root": {"path": "rootfs"},
            "mounts": [{
                "destination": "/sys", "type": "sysfs", "source": "sysfs",
                "options": ["nosuid", "noexec", "nodev", "ro"],
            }],
        });
        let cfg = parse_config_bytes(v.to_string().as_bytes()).expect("valid config");
        SysfsMountSpec::from_mounts(cfg.mounts())
            .expect("valid sysfs")
            .expect("sysfs present")
    }

    fn lookup<'a>(text: &'a str, key: &str) -> &'a str {
        text.lines()
            .find_map(|l| l.strip_prefix(&format!("{key}=")))
            .unwrap_or_else(|| panic!("missing observation {key}:\n{text}"))
    }

    fn verify(text: &str, root: bool) {
        assert_eq!(
            lookup(text, "violations"),
            "0",
            "every mount under /sys must be a read-only sysfs tree:\n{text}"
        );
        assert_eq!(
            lookup(text, "top_fstype"),
            "Some(\"sysfs\")",
            "the visible /sys must be sysfs"
        );
        let children = lookup(text, "children");
        println!("sysfs_mount: {children} child mount(s) under /sys (root={root})");
        if root {
            assert_eq!(children, "0", "a fresh sysfs has no child mounts");
        }
        assert_eq!(
            lookup(text, "read_ok:/sys/kernel"),
            "true",
            "reads must work"
        );
        let mut observed = 0usize;
        for p in WRITE_TARGETS {
            if lookup(text, &format!("exists:{p}")) != "true" {
                continue;
            }
            let errno: i32 = lookup(text, &format!("open_w_errno:{p}"))
                .parse()
                .expect("errno");
            println!("sysfs_mount: open(O_WRONLY) {p} -> errno {errno}");
            if root {
                assert_eq!(errno, EROFS, "{p} must be refused with EROFS (rootful)");
            } else {
                assert!(
                    errno == EROFS || errno == EACCES,
                    "{p} must be refused with EROFS or EACCES (rootless), got {errno}"
                );
            }
            observed += 1;
        }
        assert!(observed >= 1, "no writable-looking sysfs file was observed");
        let cgroup_procs = "/sys/fs/cgroup/cgroup.procs";
        if lookup(text, &format!("exists:{cgroup_procs}")) == "true" {
            let errno: i32 = lookup(text, &format!("open_w_errno:{cgroup_procs}"))
                .parse()
                .expect("errno");
            println!("sysfs_mount: open(O_WRONLY) {cgroup_procs} -> errno {errno}");
            assert_ne!(errno, 0, "cgroupfs must not be writable from the container");
        }
    }

    fn verify_host_untouched(rootfs: &Path) {
        assert_eq!(
            std::fs::read_dir(rootfs.join("sys"))
                .expect("read sys")
                .count(),
            0,
            "host-side sys must stay empty"
        );
        assert_eq!(
            std::fs::read_dir(rootfs.join("proc"))
                .expect("read proc")
                .count(),
            0,
            "host-side proc must stay empty"
        );
    }
}
