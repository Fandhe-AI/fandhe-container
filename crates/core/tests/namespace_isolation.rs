//! namespace 分離の実証テスト（CORE-1・TASK-28.1・#145）。
//!
//! TASK-27 で実装済みの分離フロー（`fandhe_container_core::exec` の `isolate` →
//! `MountIsolation::establish` → `prepare_rootfs` → `pivot_root`）を 1 つのコンテナプロセスで通しで実行し、
//! 分離後のコンテナ側から (a) ホストのプロセスが見えない・(b) hostname が独自・(c) rootfs が独自、の
//! 3 点を具体値で確認する。あわせて、コンテナの namespace がホストのものと別であることを
//! `/proc/self/ns/*` の識別子で照合し、ホスト側から見て hostname・ファイルシステムが無傷であることを事後確認する。
//! 個別検証の `unshare_isolation`（TASK-27.2。PID・hostname）・`pivot_root_isolation`（TASK-27.3。rootfs）とは
//! 別に、3 点をホスト視点の照合つきで通す統合の実証として置く（既存 2 本は変更しない）。
//!
//! # 3 段構成
//! - host 段（`--ignored`。分離しない）: 一時 rootfs を作り、ホストの hostname・namespace 識別子を記録して
//!   `--launcher` を起動する。終了後にホスト側の不変を照合する
//! - launcher 段（`--launcher`）: 分離（User 〔非 root のみ〕/ Pid / Mount / Uts / Ipc・hostname 設定）して
//!   `--container` を起動する。分離後の最初の子なので新しい PID namespace の PID 1 になる
//! - container 段（`--container`）: pivot_root 後に 3 点と namespace の独立を照合する
//!
//! すべての子待機にタイムアウトを設ける（REPAIR-5）。
//!
//! # 実機前提テストとしての分離
//! libtest はテストをスレッドで実行し、マルチスレッドからの `CLONE_NEWUSER` は `EINVAL` になるため
//! `harness = false` の単一スレッド `main` で動かす（`Cargo.toml` の `[[test]]`）。実行には root もしくは
//! 非特権 user namespace を許可するホストが必要（AppArmor の
//! `kernel.apparmor_restrict_unprivileged_userns=1` 等の環境では `PermissionDenied` になる）。
//! GitHub ホステッド runner で保証できないため、`-- --ignored` 指定時のみ実行して既定のテスト集合から
//! 分離している（ci.md「実機前提テスト」）。実行された場合は分離の拒否を含めあらゆる失敗を失敗として扱い、
//! 検証せずに成功終了する分岐は持たない。非 Linux では `exec` モジュール自体がビルド対象外
//! （OS 非該当であり skip ではない）。
//!
//! # 未実装（別 Issue）
//! 「コンテナ 0 個時点のデーモンレス確認」は #146（TASK-28.2・CORE-1）が本ファイルへ追加する予定で、
//! 現時点では未実装。追加時は `linux::run` から呼ぶシナリオ関数として並べる。

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("namespace_isolation: Linux only, not applicable on this OS");
}

#[cfg(target_os = "linux")]
fn main() {
    // `-- --ignored` を付けたときだけ実行する。子は `--launcher` / `--container` で再入する。
    if std::env::args().any(|a| a == "--ignored" || a == "--launcher" || a == "--container") {
        linux::run();
    } else {
        println!(
            "namespace_isolation: ignored (real-machine test; run with `-- --ignored`, see AGENTS.md)"
        );
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::collections::BTreeSet;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    use fandhe_container_core::exec::{
        Hostname, IsolationConfig, IsolationPrivilege, MountIsolation, Namespace, NamespaceSet,
        isolate, isolate_rootful_host_root, pivot_root, plan, plan_rootful_host_root,
        prepare_rootfs,
    };

    /// コンテナ側に設定する hostname（ホストの値とは異なる固定値）。
    const HOSTNAME: &str = "fandhe-nsiso";
    const MARKER: &str = "marker.txt";
    const MARKER_BODY: &[u8] = b"fandhe-nsiso-marker";
    /// 比較する namespace 種別（`/proc/self/ns/<name>`）。
    const NS_NAMES: [&str; 4] = ["pid", "mnt", "uts", "ipc"];

    fn timeout() -> Duration {
        let secs = std::env::var("FANDHE_CONTAINER_TEST_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|s| (1..=600).contains(s))
            .unwrap_or(10);
        Duration::from_secs(secs)
    }

    /// 実機前提の分離実証の入口。引数で host / launcher / container 段を切り替える。
    pub fn run() {
        let args: Vec<String> = std::env::args().collect();
        if let Some(i) = args.iter().position(|a| a == "--container") {
            container(args.get(i + 1..).expect("container args"));
        } else if let Some(i) = args.iter().position(|a| a == "--launcher") {
            launcher(args.get(i + 1..).expect("launcher args"));
        } else {
            unshare_isolation_scenario();
        }
    }

    fn read_hostname() -> String {
        std::fs::read_to_string("/proc/sys/kernel/hostname")
            .expect("read hostname")
            .trim()
            .to_string()
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

    /// 自プロセスの namespace 識別子（`/proc/self/ns/<name>` のリンク先）を `NS_NAMES` の順で返す。
    fn ns_ids() -> Vec<String> {
        NS_NAMES
            .iter()
            .map(|n| {
                std::fs::read_link(format!("/proc/self/ns/{n}"))
                    .expect("read ns link")
                    .to_string_lossy()
                    .into_owned()
            })
            .collect()
    }

    /// 一時 rootfs（drop で削除）。
    struct Rootfs(PathBuf);

    impl Drop for Rootfs {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn make_rootfs() -> Rootfs {
        use std::os::unix::fs::DirBuilderExt;

        let tmp = std::fs::canonicalize(std::env::temp_dir()).expect("canonicalize temp_dir");
        // 既存パスは削除せず、排他的な `mkdir`（`create_dir`。既存・symlink なら `AlreadyExists`）で
        // 作成する。衝突時は名前を変えて少数回だけ再試行し、尽きたら中断する（破壊的な事前削除をしない）。
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        let mut created = None;
        for attempt in 0..16u32 {
            let cand = tmp.join(format!(
                "fandhe-nsiso-{}-{nanos}-{attempt}",
                std::process::id()
            ));
            match std::fs::DirBuilder::new().mode(0o700).create(&cand) {
                Ok(()) => {
                    created = Some(cand);
                    break;
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => panic!("create rootfs dir {cand:?}: {e}"),
            }
        }
        let base = created.expect("exclusive rootfs dir creation exhausted retries");
        // 以降の失敗でも作成済みの自前ディレクトリは Drop で回収する。
        let rootfs = Rootfs(base.clone());
        std::fs::create_dir(base.join("proc")).expect("create rootfs/proc");
        std::fs::write(base.join(MARKER), MARKER_BODY).expect("write marker");
        rootfs
    }

    /// 外部コマンド `kill` を `-KILL` 付きで実行し、終了コード 0 を確認する。起動失敗・非ゼロ終了・
    /// 待機超過はすべて `Err`（成功扱いにしない）。待機にも上限を設ける（REPAIR-5）。
    fn run_kill(targets: &[String]) -> Result<(), String> {
        let mut killer = Command::new("kill")
            .args(["-KILL", "--"])
            .args(targets)
            .stdin(Stdio::null())
            .spawn()
            .map_err(|e| format!("spawn kill failed: {e}"))?;
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            match killer.try_wait() {
                Ok(Some(status)) if status.success() => return Ok(()),
                Ok(Some(status)) => return Err(format!("kill exited with {status}")),
                Ok(None) => std::thread::sleep(Duration::from_millis(10)),
                Err(e) => return Err(format!("wait kill failed: {e}")),
            }
        }
        let _ = killer.kill();
        let _ = killer.wait();
        Err("kill did not exit within 5s".to_string())
    }

    /// プロセスグループ `pgid` に属する生存プロセス（ゾンビを除く）の PID を `/proc` から列挙する。
    /// 新しい PID namespace 内のプロセスもホストの `/proc` からはホスト側 PID で見える。
    /// 列挙・読み取り・解析の失敗は「全員停止」と区別できないため `Err` で返す（fail-closed）。
    /// 列挙中に終了して消えたプロセス（`NotFound`）のみ生存者ではないとして無視する。
    fn group_members(pgid: u32) -> Result<Vec<u32>, String> {
        let entries =
            std::fs::read_dir("/proc").map_err(|e| format!("read_dir /proc failed: {e}"))?;
        let mut pids = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|e| format!("read /proc entry failed: {e}"))?;
            let Some(pid) = entry
                .file_name()
                .to_str()
                .and_then(|n| n.parse::<u32>().ok())
            else {
                continue;
            };
            let stat = match std::fs::read_to_string(entry.path().join("stat")) {
                Ok(stat) => stat,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(format!("read /proc/{pid}/stat failed: {e}")),
            };
            // 形式: `pid (comm) state ppid pgrp ...`。comm は括弧を含み得るため最後の `)` 以降を分解する。
            let rest = stat
                .rsplit_once(')')
                .map(|(_, r)| r)
                .ok_or_else(|| format!("malformed /proc/{pid}/stat: {stat:?}"))?;
            let mut fields = rest.split_whitespace();
            let state = fields.next();
            let _ppid = fields.next();
            let pgrp = fields
                .next()
                .and_then(|f| f.parse::<u32>().ok())
                .ok_or_else(|| format!("malformed /proc/{pid}/stat: {stat:?}"))?;
            if pgrp == pgid && state != Some("Z") && state != Some("X") {
                pids.push(pid);
            }
        }
        Ok(pids)
    }

    /// `pgid` のグループが空になるまで最大 `limit` 待つ。残存 PID を返す（空なら全員停止）。
    /// 列挙に失敗した場合は停止を確認できないため `Err` を返す。
    fn wait_group_gone(pgid: u32, limit: Duration) -> Result<Vec<u32>, String> {
        let deadline = Instant::now() + limit;
        loop {
            let members = group_members(pgid)?;
            if members.is_empty() || Instant::now() >= deadline {
                return Ok(members);
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// プロセスグループ `pgid` の全員へ SIGKILL を送り、全員が止まったことまで確認する（特権操作の後始末）。
    /// 新しい PID namespace の PID 1 も親 namespace からの SIGKILL は受け付けるため container 段も止まる。
    /// グループ送信に失敗した場合は残存プロセスへ個別に送るフォールバックを試み、それでも残る・
    /// プロセス一覧を取得できない場合は `Err` を返す（停止を確認できるまで成功としない）。
    fn kill_group(pgid: u32) -> Result<(), String> {
        let group_result = run_kill(&[format!("-{pgid}")]);
        let mut survivors = wait_group_gone(pgid, Duration::from_secs(2))?;
        if survivors.is_empty() {
            return Ok(());
        }
        // フォールバック: 残存 PID へ個別に SIGKILL を送る。
        let targets: Vec<String> = survivors.iter().map(u32::to_string).collect();
        let individual_result = run_kill(&targets);
        survivors = wait_group_gone(pgid, Duration::from_secs(5))?;
        if survivors.is_empty() {
            Ok(())
        } else {
            Err(format!(
                "processes remain in group {pgid}: {survivors:?} (group kill: {group_result:?}, individual kill: {individual_result:?})"
            ))
        }
    }

    /// 子を起動して終了コード 0 を待つ。超過時・終了後はグループ全体を止めて残存を確認する（REPAIR-5）。
    fn run_stage(flag: &str, rootfs: &Path, host_pid: u32, ns: &[String]) {
        use std::os::unix::process::CommandExt;

        let exe = std::env::current_exe().expect("current_exe");
        let mut cmd = Command::new(exe);
        cmd.arg(flag)
            .arg(rootfs)
            .arg(host_pid.to_string())
            .args(ns)
            .stdin(Stdio::null());
        // host 段が起動する launcher は新しいプロセスグループのリーダーにする。launcher が起動する
        // container 段は同グループを継承するため、タイムアウト時にグループ全体を kill して子孫を残さない。
        let own_group = flag == "--launcher";
        if own_group {
            cmd.process_group(0);
        }
        let mut child = cmd.spawn().expect("spawn stage");
        let deadline = Instant::now() + timeout();
        loop {
            match child.try_wait().expect("try_wait") {
                Some(status) => {
                    // 正常・異常どちらの終了でも、launcher が残した container 段を止めて残存なしを確認してから
                    // 判定する（signal 死等で container が生きたまま rootfs 削除へ進まないため）。
                    let cleanup = if own_group {
                        kill_group(child.id())
                    } else {
                        Ok(())
                    };
                    assert_eq!(
                        status.code(),
                        Some(0),
                        "{flag} stage must exit with 0 (status: {status:?}, cleanup: {cleanup:?})"
                    );
                    assert_eq!(cleanup, Ok(()), "{flag} stage left processes in its group");
                    return;
                }
                None if Instant::now() >= deadline => {
                    // グループ kill の失敗は握りつぶさず、直接の子の回収後に panic 文言へ含める。
                    let group_result = if own_group {
                        kill_group(child.id())
                    } else {
                        Ok(())
                    };
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!(
                        "{flag} stage did not exit within {:?} (cleanup: {group_result:?})",
                        timeout()
                    );
                }
                None => std::thread::sleep(Duration::from_millis(20)),
            }
        }
    }

    /// host 段。分離せずに基準値を記録し、launcher を走らせた後にホスト側の不変を照合する（CORE-1・TASK-28.1）。
    fn unshare_isolation_scenario() {
        let rootfs = make_rootfs();
        let host_hostname = read_hostname();
        let host_pid = std::process::id();
        let host_ns = ns_ids();
        assert_ne!(
            host_hostname, HOSTNAME,
            "host hostname must differ from the container one"
        );

        run_stage("--launcher", &rootfs.0, host_pid, &host_ns);

        // ホスト側は無傷: hostname 不変・namespace 不変・rootfs 内の marker が残存・ホストの `/` に marker が出ていない。
        assert_eq!(
            read_hostname(),
            host_hostname,
            "host hostname must be unchanged"
        );
        assert_eq!(ns_ids(), host_ns, "host namespaces must be unchanged");
        assert_eq!(
            std::fs::read(rootfs.0.join(MARKER)).expect("read marker from host"),
            MARKER_BODY
        );
        assert!(
            !Path::new("/").join(MARKER).exists(),
            "container rootfs must not leak into the host /"
        );
        println!(
            "namespace_isolation: unshare isolation verified (root={})",
            is_root()
        );
    }

    /// launcher 段。分離して container 段を起動する。
    fn launcher(args: &[String]) {
        let rootfs = args.first().expect("rootfs path");
        let host_pid: u32 = args
            .get(1)
            .expect("host pid")
            .parse()
            .expect("host pid number");
        let host_ns = args.get(2..).expect("host ns ids");

        // euid 0 での自 ID 写像は SEC-5 で拒否されるため、root では User を除く rootful 構成にする。
        let root = is_root();
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
            hostname: Some(Hostname::new(HOSTNAME).expect("valid hostname")),
        };
        let result = if root {
            plan_rootful_host_root(&config).and_then(|p| isolate_rootful_host_root(&p))
        } else {
            plan(&config).and_then(|p| isolate(&p))
        };
        let report = match result {
            Ok(r) => r,
            Err(err) => panic!("isolate failed: {err}"),
        };
        assert_eq!(report.namespaces, namespaces);
        let want = if root {
            IsolationPrivilege::RootfulHostRoot
        } else {
            IsolationPrivilege::RootlessSingleId
        };
        assert_eq!(report.privilege, want);
        assert_eq!(read_hostname(), HOSTNAME);

        run_stage("--container", Path::new(rootfs), host_pid, host_ns);
    }

    /// container 段（新しい PID namespace の PID 1）。pivot 後に 3 点と namespace の独立を照合する。
    fn container(args: &[String]) {
        let rootfs = Path::new(args.first().expect("rootfs path"));
        let host_pid: u32 = args
            .get(1)
            .expect("host pid")
            .parse()
            .expect("host pid number");
        let host_ns = args.get(2..).expect("host ns ids");

        assert_eq!(
            std::process::id(),
            1,
            "container must be PID 1 of the new PID namespace"
        );
        // pivot 後は元の実行ファイルのパスが見えなくなるため、先に取得しておく。
        let exe = std::env::current_exe().expect("current_exe");

        let isolation = MountIsolation::establish().expect("establish mount isolation");
        let prepared = prepare_rootfs(&isolation, rootfs).expect("prepare rootfs");
        let report = pivot_root(&isolation, prepared).expect("pivot_root");
        assert!(report.old_root_detached);
        assert!(report.proc_mounted);

        // (a) ホストのプロセスが見えない。
        let pids: BTreeSet<String> = std::fs::read_dir("/proc")
            .expect("read /proc")
            .filter_map(|e| e.ok())
            .filter_map(|e| e.file_name().into_string().ok())
            .filter(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
            .collect();
        let want: BTreeSet<String> = ["1".to_string()].into_iter().collect();
        assert_eq!(pids, want, "host processes must be invisible");
        assert_ne!(host_pid, 1, "host stage must not be PID 1");
        assert!(
            !Path::new(&format!("/proc/{host_pid}")).exists(),
            "host stage process must be invisible"
        );

        // (b) hostname が独自。
        assert_eq!(read_hostname(), HOSTNAME);

        // (c) rootfs が独自。
        let names: BTreeSet<String> = std::fs::read_dir("/")
            .expect("read /")
            .map(|e| {
                e.expect("dir entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        let want: BTreeSet<String> = ["proc", MARKER].iter().map(|s| s.to_string()).collect();
        assert_eq!(names, want, "/ must contain only the container rootfs");
        assert_eq!(
            std::fs::read("/marker.txt").expect("read marker"),
            MARKER_BODY
        );
        for host_path in [rootfs, exe.as_path()] {
            let err = std::fs::metadata(host_path).unwrap_err();
            assert_eq!(
                err.kind(),
                std::io::ErrorKind::NotFound,
                "{host_path:?} must be invisible"
            );
        }
        assert_eq!(std::env::current_dir().expect("cwd"), Path::new("/"));
        let mountinfo = std::fs::read_to_string("/proc/self/mountinfo").expect("mountinfo");
        let mount_points: BTreeSet<String> = mountinfo
            .lines()
            .map(|l| l.split(' ').nth(4).expect("mount point field").to_string())
            .collect();
        let want: BTreeSet<String> = ["/", "/proc"].iter().map(|s| s.to_string()).collect();
        assert_eq!(mount_points, want, "only / and /proc must be mounted");

        // namespace の独立: ホスト段の識別子とすべて異なる。
        let mine = ns_ids();
        assert_eq!(host_ns.len(), NS_NAMES.len(), "host ns ids must be passed");
        for ((name, theirs), ours) in NS_NAMES.iter().zip(host_ns).zip(&mine) {
            assert_ne!(ours, theirs, "{name} namespace must differ from the host");
        }
    }
}
