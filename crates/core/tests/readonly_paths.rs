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
//!   読み取りが従来どおり成功すること。あわせて、各マウントポイントの「見えている（最上位の）マウント」が実 procfs の上に
//!   載っていること（#2005）を構造化して判定し、違反を `stack_violations=N` で出す。
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
//! - `/proc` の最上位のマウントは fstype `proc`。存在する `/proc/*` の対象は、最上位のマウントが `ro` で、fstype が
//!   `proc` で、親が `/proc` の最上位のマウントであること。保護の後に `/proc` へ新しい procfs が載ると、隠れた古い
//!   `/proc/sys` の行は `ro` のまま残るが、親が最上位の procfs と食い違うため検出できる（#2005・SEC-2。pivot 前に
//!   procfs をマウントし、保護をその上に載せる順序は `run_pre_pivot` で固定）
//! - `/sys` は最上位のマウントが `ro`。本試験は `setup` なしの最小構成で動き `exec::mount_sysfs` の段を通らないため、`/sys` は
//!   rootfs 上のディレクトリで fstype は `sysfs` ではない（観測値として出力のみ）。sysfs を供給した後の fstype と `ro` は
//!   `tests/sysfs_mount.rs` が照合する（#2020。依存注記への回答として、本試験の `/sys` の
//!   fstype は観測値の出力のみとする）
//! - `/sys` の最上位とその配下のマウントに `ro` の無いものは 0 件（`sys_rw_submounts=0`）。利用者指定の tmpfs・注入ファイルは
//!   型の段で `/sys` 配下を拒否される（#2233・SEC-2）ため、本試験は pivot 後にその状態を観測する
//!
//! # 判定ロジックの自己照合（REPAIR-12）
//! mountinfo の積み方の判定（`stacking_violations`）は特権なしの純関数で、合成 fixture による自己照合を `--ignored`
//! 指定の有無にかかわらず毎回実行する（CI の `cargo test --workspace` で走る）。
//!
//! # 実機前提テストとしての分離
//! Linux 5.12 以降（`mount_setattr`）で、root もしくは非特権 user namespace を許可するホストが必要。GitHub ホステッド
//! runner では保証できないため `-- --ignored` 指定時のみ実行する（ci.md「実機前提テスト」）。rootful 経路（root）の
//! 実行は root 権限コマンドのため明示指示のもとで行い、結果を #1621 へ記録する。
//!
//! # fork 子で観測する理由（#2630・CORE-5・REPAIR-3）
//! `spawn_container_probe` を使い続け、exec 後のエントリポイント内の観測へはまだ移さない。観測するのは mountinfo の
//! `ro` と書き込み用 `open` の errno で、マウントの状態は execve をまたいで変わらないため移せる見込みはある。ただし
//! exec 経路は Landlock が必須で、書き込み用 `open` の errno（`EROFS` / `EACCES`）への影響を `platform-ci` の
//! `--ignored` で確かめる必要がある（手元では setgroups の拒否で `--ignored` を実行できない）。期待値を緩めずに
//! 移すため、確認できる環境での後続変更とする。

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("readonly_paths: Linux only, not applicable on this OS");
}

#[cfg(target_os = "linux")]
fn main() {
    linux::self_check();
    if std::env::args().any(|a| a == "--ignored") {
        linux::run();
    } else {
        println!(
            "readonly_paths: ignored (real-machine test; run with `-- --ignored`, see AGENTS.md)"
        );
    }
}

#[cfg(target_os = "linux")]
#[path = "support/temp_rootfs.rs"]
mod temp_rootfs;

#[cfg(target_os = "linux")]
mod linux {
    use crate::temp_rootfs;
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
        // 共有 /tmp 上の推測可能なパスを削除・再利用すると、競合で置かれた symlink を root が辿りうる。
        // 一意名で排他作成し、既存パスは削除も採用もせず、配下も 1 階層ずつ作る（#2324・SEC-2・CORE-5）。
        let base = temp_rootfs::exclusive_temp_dir("fandhe-readonly-paths", 0o755);
        temp_rootfs::create_dir_chain(&base, &["proc"]);
        let fixture = FIXTURE_REL.iter().fold(base.clone(), |p, c| p.join(c));
        temp_rootfs::create_dir_chain(&base, &FIXTURE_REL[..FIXTURE_REL.len() - 1]);
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

    /// mountinfo の 1 行（判定に使う欄のみ）。
    struct Mnt {
        id: u32,
        parent: u32,
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
                    id: f.first().and_then(|x| x.parse().ok()).ok_or_else(bad)?,
                    parent: f.get(1).and_then(|x| x.parse().ok()).ok_or_else(bad)?,
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

    /// `mountpoint` で見えている（最上位の）マウント。同じマウントポイントの他の行から親 ID として参照されて
    /// いない行で、行の順序には頼らない。
    fn top_mount<'a>(mnts: &'a [Mnt], mountpoint: &str) -> Option<&'a Mnt> {
        mnts.iter()
            .filter(|m| m.mountpoint == mountpoint)
            .find(|m| {
                !mnts
                    .iter()
                    .any(|o| o.mountpoint == mountpoint && o.parent == m.id)
            })
    }

    /// 保護（読み取り専用化）が見えている procfs の上に載っているかの違反一覧（空なら合格）。
    /// 壊れた mountinfo は `Err`。
    fn stacking_violations(mountinfo: &str, targets: &[&str]) -> Result<Vec<String>, String> {
        let mnts = parse_mountinfo(mountinfo)?;
        let mut v = Vec::new();
        let proc_top = top_mount(&mnts, "/proc");
        if proc_top.is_none_or(|p| p.fstype != "proc") {
            v.push("the top mount of /proc is not procfs".to_string());
        }
        for t in targets {
            let Some(m) = top_mount(&mnts, t) else {
                if *t == READONLY_SYS_PATH {
                    v.push(format!("{t} has no mount"));
                }
                continue;
            };
            if !m.opts.iter().any(|o| o == "ro") {
                v.push(format!("the top mount of {t} is not read-only"));
            }
            if t.starts_with("/proc/") {
                if m.fstype != "proc" {
                    v.push(format!("the top mount of {t} is not procfs"));
                }
                if proc_top.map(|p| p.id) != Some(m.parent) {
                    v.push(format!("{t} is hidden or not on the top procfs"));
                }
            }
        }
        Ok(v)
    }

    /// `/sys` の最上位のマウントと `/sys/` 配下のマウントのうち `ro` の無いものの数（SEC-2・#2233）。
    /// 前方一致だけの兄弟（`/sysx`）は数えない。壊れた mountinfo は `Err`。
    fn sys_rw_submounts(mountinfo: &str) -> Result<usize, String> {
        let mnts = parse_mountinfo(mountinfo)?;
        let top_id = top_mount(&mnts, READONLY_SYS_PATH).map(|m| m.id);
        Ok(mnts
            .iter()
            .filter(|m| Some(m.id) == top_id || m.mountpoint.starts_with("/sys/"))
            .filter(|m| !m.opts.iter().any(|o| o == "ro"))
            .count())
    }

    /// `stacking_violations` の合成 fixture による自己照合（特権不要。毎回実行する）。
    pub fn self_check() {
        let t = ["/proc/sys", "/sys"];
        let good = "10 1 0:5 / /proc rw - proc proc rw\n\
                    11 10 0:5 /sys /proc/sys ro,nosuid - proc proc rw\n\
                    12 1 0:6 /sys /sys ro - ext4 /dev/x rw\n";
        assert_eq!(stacking_violations(good, &t), Ok(vec![]));
        // 保護の後に新しい procfs が `/proc` へ載り、古い `/proc/sys` の `ro` 行が隠れた。
        let hidden = format!("{good}13 10 0:7 / /proc rw - proc proc rw\n");
        let v = stacking_violations(&hidden, &t).expect("parse");
        assert_eq!(v, vec!["/proc/sys is hidden or not on the top procfs"]);
        let rw = good.replace("ro,nosuid", "rw,nosuid");
        let v = stacking_violations(&rw, &t).expect("parse");
        assert_eq!(v, vec!["the top mount of /proc/sys is not read-only"]);
        let not_proc = good.replace("nosuid - proc proc rw\n12", "nosuid - tmpfs x rw\n12");
        let v = stacking_violations(&not_proc, &t).expect("parse");
        assert_eq!(v, vec!["the top mount of /proc/sys is not procfs"]);
        assert!(stacking_violations("10 1 0:5 / /proc rw\n", &t).is_err());
        // `/sys` 部分木の rw 数: 全部 ro は 0、rw の子 1 件は 1、`/sysx` は数えない。
        assert_eq!(sys_rw_submounts(good), Ok(0));
        let rw_child = format!("{good}14 12 0:8 / /sys/x rw,nosuid - tmpfs t rw\n");
        assert_eq!(sys_rw_submounts(&rw_child), Ok(1));
        let sibling = format!("{good}15 1 0:9 / /sysx rw - tmpfs t rw\n");
        assert_eq!(sys_rw_submounts(&sibling), Ok(0));
        assert!(sys_rw_submounts("garbage\n").is_err());
        println!("readonly_paths: mountinfo stacking self-check passed");
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
        let violations = stacking_violations(&mountinfo, &targets)
            .unwrap_or_else(|e| vec![format!("malformed: {e}")]);
        writeln!(writer, "stack_violations={}", violations.len()).expect("write");
        for (i, msg) in violations.iter().enumerate() {
            writeln!(writer, "stack_violation:{i}={msg}").expect("write");
        }
        let rw_subs = sys_rw_submounts(&mountinfo)
            .map_or_else(|e| format!("malformed: {e}"), |n| n.to_string());
        writeln!(writer, "sys_rw_submounts={rw_subs}").expect("write");
        let fstype_of = |mp: &str| {
            parse_mountinfo(&mountinfo)
                .ok()
                .and_then(|m| top_mount(&m, mp).map(|t| t.fstype.clone()))
        };
        writeln!(writer, "top_fstype:/proc={:?}", fstype_of("/proc")).expect("write");
        writeln!(writer, "top_fstype:/sys={:?}", fstype_of("/sys")).expect("write");
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
            lookup(text, "stack_violations"),
            "0",
            "protections must sit on the visible procfs:\n{text}"
        );
        assert_eq!(
            lookup(text, "top_fstype:/proc"),
            "Some(\"proc\")",
            "the visible /proc must be procfs"
        );
        assert_eq!(
            lookup(text, "sys_rw_submounts"),
            "0",
            "no writable mount may remain at or under /sys:\n{text}"
        );
        println!("readonly_paths: no writable mount under /sys (sys_rw_submounts=0)");
        println!(
            "readonly_paths: top mounts verified (/proc fstype {}, /sys fstype {})",
            lookup(text, "top_fstype:/proc"),
            lookup(text, "top_fstype:/sys")
        );

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
