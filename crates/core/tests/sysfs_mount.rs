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
//!   あればその行も含めて照合する）
//! - 覆い（#2014）: `/sys/firmware`・`/sys/devices/virtual/powercap`・`/sys/devices/system/cpu/cpuN/thermal_throttle` の
//!   うち存在するものはすべて、そのパスが `tmpfs` かつ `ro,nosuid,nodev,noexec` のマウントポイントで、`read_dir` が空。
//!   存在しない対象は飛ばされる。rootful（新しい sysfs）では `/sys` 配下の子マウントは覆いの tmpfs だけ
//! - 存在する覆いの tmpfs の直下への新規作成（`O_CREAT|O_EXCL`）は、rootful・rootless とも `EROFS`（`/sys` 配下に書き込み可能な
//!   tmpfs が残らないことの確認。#2233・SEC-2）
//! - `/sys/kernel/uevent_helper` 等の既存ファイルへの書き込み `open` は `EROFS`（30）。rootless はホストの root 所有の
//!   ファイルでパーミッション検査が先に `EACCES`（13）になり得るため `EROFS` か `EACCES` を要求し、観測値を出力する
//!   （mountinfo の `ro` が主な保証。`readonly_paths` と同じ流儀）
//! - `/sys/fs/cgroup/cgroup.procs` があれば、書き込み `open` は拒否される（`exec::setns` の前提の裏付け）
//!
//! # シナリオ（`--ignored` 時は dispatcher が順に再 exec する。#2305）
//! mount 属性を変える試行は同じ子の観測を壊すため、シナリオごとに別プロセスで動かす（`escape_suite.rs` の `--scenario` に倣う）。
//! - `default`: 上の流れと期待値（従来の試験）
//! - `ro-clear`: rootless の `/sys` の rbind の最上位の ro を、user namespace の root が `mount_setattr` で外せるかの測定
//!   （SEC-2・SEC-1・#2305 の P2-1。root では「該当なし」を出力する: 問いは rbind 経路にしか無く、skip で通しているのではない）。
//!   - 防御なしの測定: `StageKind::CgroupJoin` のフック（pivot 後・capability 削減前。全 capability あり・seccomp なし）で試し、
//!     `ro_clear_errno=0|<errno>|unsupported|failed|precondition` を記録する。**値は測定対象そのもので未知のため、
//!     どの errno でも assert しない**（0 なら外せた、`EPERM` ならロックされている）。測定が行われなかった
//!     `precondition`・`unsupported`・`failed` は測定不成立として失敗にする（false-green を避ける）。
//!     外せた場合は書き込みを一切せず、mountinfo の読み直しと書き込み用 `open(2)` の errno だけを観測する
//!   - 防御ありの測定: 組み込みの制限段（capability 削減・seccomp）通過後のクロージャで同じ試行をし、
//!     `ro_clear_defended_errno=1`（`EPERM`）を要求する。これは本番の防御（SEC-1・CORE-5）の性質なので assert する
//!   - 手順と結果の記録先: `docs/verification/rootless-sysfs-readonly.md`・#2305
//!
//! # 判定ロジックの自己照合（REPAIR-12）
//! mountinfo の判定（`sys_tree_violations`）は特権なしの純関数で、合成 fixture による自己照合を `--ignored` 指定の有無に
//! かかわらず毎回実行する（CI の `cargo test --workspace` で走る）。`ro-clear` の判定（`ro_clear_verdict`）も同様。
//!
//! # 実機前提テストとしての分離
//! Linux 5.12 以降（`open_tree`・`move_mount`・`mount_setattr`）で、root もしくは非特権 user namespace を許可する
//! ホストが必要。GitHub ホステッド runner では保証できないため `-- --ignored` 指定時のみ実行する（ci.md「実機前提テスト」）。
//! rootful 経路（root）の実行は root 権限コマンドのため明示指示のもとで行い、結果を #1621 へ記録する。
//!
//! # fork 子で観測する理由（#2630・CORE-5・REPAIR-3）
//! `spawn_container_probe` 系を使い続け、exec 後のエントリポイント内の観測へは移さない。
//! - 識別性: 観測するのは mountinfo の最上位のマウント・fstype・`ro` などのフラグ・覆ったファイルの内容・書き込み用
//!   `open` の errno で、いずれもマウントの状態で決まる。マウントの状態は execve をまたいで変わらないため、fork 子で
//!   観測しても exec 後の PID 1 と同じ結果になる。exec 経路は Landlock が必須で `EACCES` の発生源が増えるため、
//!   Landlock を載せない fork 子のほうが拒否の理由を識別しやすい
//! - 移せない事情: exec 経路の試験用入口（`spawn_container_with_stages_and_devices`）は `devices` しか渡せず、
//!   `config_paths` / `sysfs` を受け取らない。本試験は #2533 で `platform-ci`（ubuntu）の `--ignored` 対象に
//!   登録済みで、fork 子での観測は CI で継続して確かめられる
//! - 移す条件（後続）: `config_paths` / `sysfs` を受け取る exec 経路の入口を足すときは、`platform-ci` の成功行の照合も同じ変更で更新する

#[path = "support/reap.rs"]
mod reap;

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("sysfs_mount: Linux only, not applicable on this OS");
}

#[cfg(target_os = "linux")]
fn main() {
    // シナリオ再入時は常に走る自己照合を繰り返さない（dispatcher が 1 回走らせている）。
    let args: Vec<String> = std::env::args().collect();
    if let Some(i) = args.iter().position(|a| a == "--scenario") {
        let id = args.get(i + 1).expect("scenario id after --scenario");
        linux::scenario(id);
        return;
    }
    linux::self_check();
    if args.iter().any(|a| a == "--ignored") {
        linux::dispatch();
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
    use std::time::{Duration, Instant};

    use fandhe_container_core::exec::{
        ChildExit, DevptsGidSource, IsolationConfig, Namespace, NamespaceSet, ProbeOutcome,
        StageKind, StagePipeline, isolate, isolate_rootful_host_root, plan, plan_rootful_host_root,
        probe_clear_sysfs_readonly_for_test, spawn_container_probe_with_sysfs,
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
        // 共有 /tmp 上の推測可能なパスを削除・再利用すると、競合で置かれた symlink を root が辿りうる。
        // PID と時刻由来の名前を付けて 0700 の `create_dir` で排他的に作り、既存パスは削除も採用もしない。
        // 配下も `create_dir`（`create_dir_all` ではない）で 1 階層ずつ作り、途中の symlink を辿らせない（SEC-2）。
        use std::os::unix::fs::DirBuilderExt;
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        let base = std::fs::canonicalize(std::env::temp_dir())
            .expect("canonicalize temp_dir")
            .join(format!("fandhe-sysfs-mount-{}-{nanos}", std::process::id()));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&base)
            .expect("exclusively create rootfs dir");
        let rootfs = Rootfs(base.clone());
        std::fs::create_dir(base.join("proc")).expect("create rootfs/proc");
        std::fs::create_dir(base.join("sys")).expect("create rootfs/sys");
        rootfs
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

    /// 覆いの照合結果（`sys_mask_check`）。
    #[derive(Debug, PartialEq, Eq)]
    struct MaskCheck {
        /// 存在する対象が覆われていない等の違反（空なら合格）。
        violations: Vec<String>,
        /// 覆いの対象ではない `/sys` 配下のマウントポイント（rootful では空でなければならない）。
        unexpected_children: Vec<String>,
    }

    /// `present`（pivot 後に存在した覆い対象のパス）が、それぞれ最上位で `tmpfs` かつ `ro,nosuid,nodev,noexec` の
    /// マウントポイントであることと、覆いの対象でない `/sys` 配下のマウントを数える（特権不要の純関数）。
    fn sys_mask_check(mountinfo: &str, present: &[String]) -> Result<MaskCheck, String> {
        let mnts = parse_mountinfo(mountinfo)?;
        let mut violations = Vec::new();
        for target in present {
            match mnts.iter().rev().find(|m| &m.mountpoint == target) {
                None => violations.push(format!("{target} has no mount")),
                Some(m) => {
                    if m.fstype != "tmpfs" {
                        violations.push(format!("{target} is not masked by tmpfs"));
                    }
                    for flag in ["ro", "nosuid", "nodev", "noexec"] {
                        if !m.opts.iter().any(|o| o == flag) {
                            violations.push(format!("{target} lacks {flag}"));
                        }
                    }
                }
            }
        }
        let mut unexpected_children = Vec::new();
        for m in &mnts {
            if m.mountpoint.starts_with("/sys/") && !present.contains(&m.mountpoint) {
                unexpected_children.push(m.mountpoint.clone());
            }
        }
        Ok(MaskCheck {
            violations,
            unexpected_children,
        })
    }

    /// `cpu` ディレクトリの 1 件の名前が `cpu<10 進数>` か。
    fn is_cpu_dir_name(name: &str) -> bool {
        name.strip_prefix("cpu")
            .is_some_and(|d| !d.is_empty() && d.bytes().all(|b| b.is_ascii_digit()))
    }

    /// 覆い対象のうち pivot 後の `/sys` に存在するもの（`cpu*` の走査は 8192 件で打ち切り、超えたら `Err`）。
    fn present_mask_targets() -> Result<Vec<String>, String> {
        const MAX_CPUS: usize = 8192;
        let mut out = Vec::new();
        for p in ["/sys/devices/virtual/powercap", "/sys/firmware"] {
            if std::fs::symlink_metadata(p).is_ok() {
                out.push(p.to_string());
            }
        }
        let Ok(rd) = std::fs::read_dir("/sys/devices/system/cpu") else {
            return Ok(out);
        };
        let mut names = Vec::new();
        for e in rd {
            let name = e
                .map_err(|e| format!("read_dir(cpu): {e}"))?
                .file_name()
                .to_string_lossy()
                .into_owned();
            if is_cpu_dir_name(&name) {
                names.push(name);
                if names.len() > MAX_CPUS {
                    return Err("too many cpu directories".to_string());
                }
            }
        }
        names.sort();
        for n in names {
            let p = format!("/sys/devices/system/cpu/{n}/thermal_throttle");
            if std::fs::symlink_metadata(&p).is_ok() {
                out.push(p);
            }
        }
        Ok(out)
    }

    /// `sys_tree_violations` と `sys_mask_check` の合成 fixture による自己照合（特権不要。毎回実行する）。
    pub fn self_check() {
        let masks = "20 11 0:20 / /sys/firmware ro,nosuid,nodev,noexec - tmpfs tmpfs ro\n\
                     21 11 0:21 / /sys/devices/system/cpu/cpu0/thermal_throttle ro,nosuid,nodev,noexec - tmpfs tmpfs ro\n";
        let present = vec![
            "/sys/firmware".to_string(),
            "/sys/devices/system/cpu/cpu0/thermal_throttle".to_string(),
        ];
        assert_eq!(
            sys_mask_check(masks, &present),
            Ok(MaskCheck {
                violations: vec![],
                unexpected_children: vec![]
            })
        );
        let unmasked = "20 11 0:20 / /sys/firmware ro,nosuid,nodev,noexec - tmpfs tmpfs ro\n";
        assert_eq!(
            sys_mask_check(unmasked, &present).map(|c| c.violations),
            Ok(vec![
                "/sys/devices/system/cpu/cpu0/thermal_throttle has no mount".to_string()
            ])
        );
        let rw = masks.replace("/sys/firmware ro,", "/sys/firmware rw,");
        assert_eq!(
            sys_mask_check(&rw, &present).map(|c| c.violations),
            Ok(vec!["/sys/firmware lacks ro".to_string()])
        );
        let not_tmpfs = masks.replace("tmpfs tmpfs ro\n21", "sysfs sysfs ro\n21");
        assert_eq!(
            sys_mask_check(&not_tmpfs, &present).map(|c| c.violations),
            Ok(vec!["/sys/firmware is not masked by tmpfs".to_string()])
        );
        let extra = format!(
            "{masks}22 11 0:22 / /sys/fs/cgroup ro,nosuid,nodev,noexec - cgroup2 cgroup2 rw\n"
        );
        assert_eq!(
            sys_mask_check(&extra, &present).map(|c| c.unexpected_children),
            Ok(vec!["/sys/fs/cgroup".to_string()])
        );
        assert!(sys_mask_check("bad\n", &present).is_err());
        assert!(is_cpu_dir_name("cpu0") && is_cpu_dir_name("cpu127"));
        for bad in ["cpu", "cpufreq", "cpuidle", "cpu0x", "possible"] {
            assert!(!is_cpu_dir_name(bad), "{bad}");
        }

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
        // ro-clear の判定（#2305）。防御ありは EPERM のみ、防御なしは測定対象のため語彙内なら errno を問わない。
        let base = "sys_stack=2\ntop_opts=\"ro,nosuid\"\nro_clear_defended_errno=1\n";
        let verdict = |u: &str| ro_clear_verdict(&format!("{base}ro_clear_errno={u}\n"));
        assert_eq!(
            verdict("1"),
            Ok(RoClearVerdict {
                undefended: "1".to_string(),
                stack: 2
            })
        );
        assert_eq!(
            verdict("13").map(|v| v.undefended),
            Ok("13".to_string()),
            "any errno is a valid measurement"
        );
        assert!(verdict("0").is_err(), "0 needs the follow-up observations");
        let cleared = format!(
            "{base}ro_clear_errno=0\ntop_ro_after_clear=false\nchildren_ro_after_clear=true\n"
        );
        assert_eq!(
            ro_clear_verdict(&cleared).map(|v| v.undefended),
            Ok("0".to_string())
        );
        for bad in ["precondition", "unsupported", "failed", "eperm", ""] {
            assert!(
                verdict(bad).is_err(),
                "{bad:?} must not be a valid measurement"
            );
        }
        let defended_open = base.replace("defended_errno=1", "defended_errno=0");
        assert!(
            ro_clear_verdict(&format!("{defended_open}ro_clear_errno=1\n")).is_err(),
            "a defended success must fail"
        );
        assert!(ro_clear_verdict("sys_stack=1\nro_clear_errno=1\n").is_err());
        let two =
            "11 1 0:6 / /sys rw - sysfs sysfs rw\n12 1 0:7 / /sys ro,nosuid - sysfs sysfs rw\n";
        assert_eq!(
            sys_stack_and_top(two),
            Ok((2, Some(vec!["ro".to_string(), "nosuid".to_string()])))
        );
        assert_eq!(host_sys_read_only(two), Some(true));
        assert_eq!(
            host_sys_read_only("10 1 0:5 / /proc rw - proc proc rw\n"),
            None
        );
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
        observe_masks(&mut writer, &mountinfo);
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

    /// 覆い（#2014）の観測。存在する対象のマウントと中身が空であることを照合し、結果を `key=value` で書く。
    fn observe_masks(writer: &mut std::io::PipeWriter, mountinfo: &str) {
        let (present, mut violations, unexpected) = match present_mask_targets() {
            Ok(present) => match sys_mask_check(mountinfo, &present) {
                Ok(c) => (present, c.violations, c.unexpected_children),
                Err(e) => (present, vec![format!("malformed: {e}")], Vec::new()),
            },
            Err(e) => (Vec::new(), vec![e], Vec::new()),
        };
        for t in &present {
            match std::fs::read_dir(t) {
                Ok(mut rd) => {
                    if rd.next().is_some() {
                        violations.push(format!("{t} is not empty"));
                    }
                }
                Err(e) => violations.push(format!("read_dir({t}): {e}")),
            }
        }
        writeln!(writer, "mask_violations={}", violations.len()).expect("write");
        for (i, msg) in violations.iter().enumerate() {
            writeln!(writer, "mask_violation:{i}={msg}").expect("write");
        }
        writeln!(writer, "mask_unexpected_children={}", unexpected.len()).expect("write");
        for (i, msg) in unexpected.iter().enumerate() {
            writeln!(writer, "mask_unexpected:{i}={msg}").expect("write");
        }
        // 覆いの tmpfs への新規作成の errno（SEC-2・#2233。作れてしまったら 0 で、消してから失敗として扱わせる）。
        for t in &present {
            let probe = format!("{t}/.fandhe-probe");
            let errno = match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&probe)
            {
                Ok(_) => {
                    let _ = std::fs::remove_file(&probe);
                    0
                }
                Err(e) => e.raw_os_error().unwrap_or(-1),
            };
            writeln!(writer, "mask_create_errno:{t}={errno}").expect("write");
        }
        let has = |p: &str| present.iter().any(|x| x == p);
        let thermal = present
            .iter()
            .filter(|p| p.ends_with("/thermal_throttle"))
            .count();
        writeln!(writer, "mask_present={}", present.len()).expect("write");
        writeln!(writer, "mask_firmware={}", has("/sys/firmware")).expect("write");
        writeln!(
            writer,
            "mask_powercap={}",
            has("/sys/devices/virtual/powercap")
        )
        .expect("write");
        writeln!(writer, "mask_thermal_throttle={thermal}").expect("write");
    }

    /// 試験プロセスを分離する（root は rootful、非 root は rootless）。`(root かどうか, 分離前の実効 gid)`。
    fn isolate_self() -> (bool, u32) {
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
        (root, egid)
    }

    /// 従来の試験（シナリオ `default`）。
    fn run() {
        let rootfs = make_rootfs();
        let (root, egid) = isolate_self();

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
        println!(
            "sysfs_mount: {} /sys entries masked (firmware={}, powercap={}, thermal_throttle={}) (root={root})",
            lookup(&text, "mask_present"),
            lookup(&text, "mask_firmware"),
            lookup(&text, "mask_powercap"),
            lookup(&text, "mask_thermal_throttle"),
        );
    }

    /// `ro-clear` の防御なし側で、数値の errno 以外に許す語彙（測定不成立のものを含む。判定は `ro_clear_verdict`）。
    const UNDEFENDED_WORDS: [&str; 4] = ["unsupported", "failed", "precondition", "0"];

    /// 試行の結果を記録用の語彙へ写す（`0`・errno の数値・`unsupported`・`failed`・`precondition`）。
    fn render_clear_outcome<E>(r: &Result<ProbeOutcome, E>) -> String {
        match r {
            Ok(ProbeOutcome::Ok) => "0".to_string(),
            Ok(ProbeOutcome::Errno(n)) => n.to_string(),
            Ok(ProbeOutcome::Unsupported) => "unsupported".to_string(),
            Ok(ProbeOutcome::Failed) => "failed".to_string(),
            Err(_) => "precondition".to_string(),
        }
    }

    /// mountinfo の `/sys` の行数（mountpoint がちょうど `/sys`）と、最上位（最後の行）の per-mount options。
    fn sys_stack_and_top(mountinfo: &str) -> Result<(usize, Option<Vec<String>>), String> {
        let mnts = parse_mountinfo(mountinfo)?;
        let stack = mnts.iter().filter(|m| m.mountpoint == "/sys").count();
        let top = mnts
            .iter()
            .rev()
            .find(|m| m.mountpoint == "/sys")
            .map(|m| m.opts.clone());
        Ok((stack, top))
    }

    /// `/sys` の最上位が ro か（読めなければ `None`）。ホスト側で ro なら、rbind に後から付けた ro が外せなくても
    /// 仮説（ロックされない）とは別の理由であり、結果の解釈が変わる。
    fn host_sys_read_only(mountinfo: &str) -> Option<bool> {
        let (_, top) = sys_stack_and_top(mountinfo).ok()?;
        top.map(|o| o.iter().any(|x| x == "ro"))
    }

    /// `ro-clear` の観測の判定結果（`ro_clear_verdict`）。
    #[derive(Debug, PartialEq, Eq)]
    struct RoClearVerdict {
        /// 防御なしの試行の語彙。
        undefended: String,
        /// `/sys` の行数。
        stack: usize,
    }

    /// 観測テキストを判定する（特権不要の純関数）。防御あり側は `EPERM`（1）を要求し、防御なし側は測定対象のため
    /// errno の値を問わない（ただし測定不成立の語彙と、語彙外の値は失敗）。
    fn ro_clear_verdict(text: &str) -> Result<RoClearVerdict, String> {
        let get = |k: &str| {
            text.lines()
                .find_map(|l| l.strip_prefix(&format!("{k}=")))
                .ok_or_else(|| format!("missing observation {k}"))
        };
        let stack: usize = get("sys_stack")?
            .parse()
            .map_err(|_| "sys_stack is not a number".to_string())?;
        let undefended = get("ro_clear_errno")?.to_string();
        let numeric = undefended.parse::<i32>().is_ok();
        if !numeric && !UNDEFENDED_WORDS.contains(&undefended.as_str()) {
            return Err(format!("unknown ro_clear_errno value {undefended:?}"));
        }
        if matches!(
            undefended.as_str(),
            "unsupported" | "failed" | "precondition"
        ) {
            return Err(format!(
                "the undefended measurement was not taken (ro_clear_errno={undefended})"
            ));
        }
        let defended = get("ro_clear_defended_errno")?;
        if defended != "1" {
            return Err(format!(
                "the defended attempt must fail with EPERM (1), got {defended:?}"
            ));
        }
        if undefended == "0" {
            for k in ["top_ro_after_clear", "children_ro_after_clear"] {
                get(k)?;
            }
        }
        Ok(RoClearVerdict { undefended, stack })
    }

    /// `ro-clear` の防御なしの測定（`CgroupJoin` のフックから呼ぶ）。書き込みは一切しない。
    fn observe_ro_clear_undefended(writer: &mut std::io::PipeWriter) {
        let mountinfo = std::fs::read_to_string("/proc/self/mountinfo").unwrap_or_default();
        match sys_stack_and_top(&mountinfo) {
            Ok((stack, top)) => {
                writeln!(writer, "sys_stack={stack}").expect("write");
                writeln!(writer, "top_opts={:?}", top.unwrap_or_default().join(","))
                    .expect("write");
            }
            Err(e) => writeln!(writer, "mountinfo_error={e}").expect("write"),
        }
        let outcome = probe_clear_sysfs_readonly_for_test();
        let word = render_clear_outcome(&outcome);
        writeln!(writer, "ro_clear_errno={word}").expect("write");
        if word != "0" {
            return;
        }
        // 外せた場合: mountinfo を読み直し、書き込み用 open の errno だけを観測する（書かない）。
        let after = std::fs::read_to_string("/proc/self/mountinfo").unwrap_or_default();
        let top_ro = host_sys_read_only(&after);
        writeln!(
            writer,
            "top_ro_after_clear={}",
            top_ro.map_or("unknown".to_string(), |b| b.to_string())
        )
        .expect("write");
        let children = parse_mountinfo(&after)
            .map(|m| {
                m.into_iter()
                    .filter(|x| x.mountpoint.starts_with("/sys/"))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let children_ro = children.iter().all(|m| m.opts.iter().any(|o| o == "ro"));
        writeln!(writer, "children_after_clear={}", children.len()).expect("write");
        writeln!(writer, "children_ro_after_clear={children_ro}").expect("write");
        for p in WRITE_TARGETS
            .iter()
            .copied()
            .chain(["/sys/fs/cgroup/cgroup.procs"])
        {
            if std::fs::symlink_metadata(p).is_ok() {
                writeln!(
                    writer,
                    "open_w_errno_after_clear:{p}={}",
                    open_for_write_errno(p)
                )
                .expect("write");
            }
        }
    }

    /// シナリオ `ro-clear`（SEC-2・SEC-1・#2305）。
    fn run_ro_clear() {
        let rootfs = make_rootfs();
        let (root, egid) = isolate_self();
        if root {
            println!(
                "sysfs_mount: ro-clear not applicable (fresh sysfs in the initial user namespace) (root={root})"
            );
            return;
        }
        let spec = sysfs_spec();
        let gid_map = single_id_mapping(egid).expect("single id mapping");
        let (mut reader, writer) = std::io::pipe().expect("create pipe");
        let mut hook_writer = writer.try_clone().expect("clone pipe writer");
        let stages = StagePipeline::new()
            .with_hook(StageKind::CgroupJoin, move || {
                observe_ro_clear_undefended(&mut hook_writer);
                Ok(())
            })
            .expect("register the undefended probe hook");
        let child = spawn_container_probe_with_sysfs(
            &rootfs.0,
            stages,
            DevptsGidSource::Rootless(&gid_map),
            &spec,
            move || {
                // 組み込みの制限段（capability 削減・seccomp）の通過後。本番と同じ防御の下での同じ試行。
                let mut w = writer;
                let word = render_clear_outcome(&probe_clear_sysfs_readonly_for_test());
                writeln!(w, "ro_clear_defended_errno={word}").expect("write");
            },
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
        for l in text.lines() {
            println!("sysfs_mount: ro-clear observation: {l}");
        }
        let verdict = ro_clear_verdict(&text).unwrap_or_else(|e| panic!("{e}:\n{text}"));
        verify_host_untouched(&rootfs.0);
        println!(
            "sysfs_mount: ro-clear on /sys top mount (stack={}): undefended={}, defended errno=1 (root={root})",
            verdict.stack, verdict.undefended
        );
    }

    /// 子プロセスを期限付きで待つ。期限超過なら kill して回収し `None`（REPAIR-5）。
    fn wait_deadline(
        child: &mut std::process::Child,
        limit: Duration,
    ) -> Option<std::process::ExitStatus> {
        let deadline = Instant::now() + limit;
        loop {
            match child.try_wait().expect("try_wait") {
                Some(status) => return Some(status),
                None if Instant::now() >= deadline => {
                    crate::reap::reap_or_report(child, crate::reap::reap_within());
                    return None;
                }
                None => std::thread::sleep(Duration::from_millis(20)),
            }
        }
    }

    /// `--ignored` 時の入口。ホストの `/sys` の状態を出力し、シナリオを別プロセスで順に実行する。
    /// 自身は分離しない（入れ子の user namespace で測ってしまうため）。
    pub fn dispatch() {
        let mountinfo = std::fs::read_to_string("/proc/self/mountinfo").expect("mountinfo");
        println!(
            "sysfs_mount: host /sys read-only={}",
            host_sys_read_only(&mountinfo).map_or("unknown".to_string(), |b| b.to_string())
        );
        let exe = std::env::current_exe().expect("current_exe");
        // シナリオ内の子待ち（`timeout()`）より長い期限にして、シナリオ側の失敗報告を優先させる。
        let limit = timeout() + Duration::from_secs(15);
        for id in ["default", "ro-clear"] {
            let mut child = std::process::Command::new(&exe)
                .args(["--scenario", id])
                .stdin(std::process::Stdio::null())
                .spawn()
                .expect("spawn scenario");
            let status = wait_deadline(&mut child, limit)
                .unwrap_or_else(|| panic!("scenario {id} timed out"));
            assert!(status.success(), "scenario {id} failed: {status:?}");
        }
    }

    /// シナリオ 1 つを実行する（再 exec された子から呼ばれる）。
    pub fn scenario(id: &str) {
        match id {
            "default" => run(),
            "ro-clear" => run_ro_clear(),
            other => panic!("unknown scenario {other:?}"),
        }
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
        assert_eq!(
            lookup(text, "mask_violations"),
            "0",
            "every existing masked /sys entry must be an empty read-only tmpfs:\n{text}"
        );
        if root {
            // 新しい sysfs の子マウントは、覆いの tmpfs だけ（#2014。覆いの前は 0 件だった）。
            assert_eq!(
                lookup(text, "mask_unexpected_children"),
                "0",
                "a fresh sysfs has no child mounts other than the masks:\n{text}"
            );
            assert_eq!(
                children,
                lookup(text, "mask_present"),
                "child mounts must be exactly the masks"
            );
        }
        // `/sys` 配下に実在する唯一の tmpfs（覆い）にも、新しいファイルは作れない（EROFS。SEC-2・#2233）。
        let mut create_checked = 0usize;
        for l in text.lines() {
            if let Some(rest) = l.strip_prefix("mask_create_errno:") {
                let (path, errno) = rest.rsplit_once('=').expect("key=value");
                assert_eq!(
                    errno,
                    EROFS.to_string(),
                    "creating a file under {path} must fail with EROFS"
                );
                create_checked += 1;
            }
        }
        assert_eq!(
            create_checked.to_string(),
            lookup(text, "mask_present"),
            "every masked entry must have a create probe"
        );
        println!(
            "sysfs_mount: creating a file under {create_checked} masked tmpfs refused with EROFS"
        );
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
