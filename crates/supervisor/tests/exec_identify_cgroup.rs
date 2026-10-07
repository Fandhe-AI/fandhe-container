//! 実 cgroup に対する `identify_pid1`（既定ビルドの公開入口）の成功経路と拒否経路の結合試験
//! （SUP-6・SEC-1・CORE-3・OCI-6・TASK-163 追補・#1464・REPAIR-12）。
//!
//! `exec_setns_join`（非特権・CI 実行）は、コンテナ用の cgroup を作れないため、期待 cgroup パスを呼び出し側が
//! 渡す試験専用の入口 `identify_pid1_in` を使う。本番の `identify_pid1` は、状態記録の配置（委譲スコープ +
//! instance）から期待パス `<scope>/fc-<id>@<instance>` を core 側で導いて照合する（pid 再利用対策。SEC-1）。
//! 本試験はその成功経路を、実 `DelegatedCgroup::prepare` が作った実 cgroup と実 `FileStateStore` の記録で通す
//! （`exec-test-support` の入口は使わない。既定の公開 API の照合が目的のため）。具体値で確かめる内容:
//!
//! - 記録の配置から導いた名前（`fc-<id>@<instance>`）の子 cgroup を作り、pid1 を入れると、`/proc/<pid1>/cgroup` が
//!   `0::<scope>/fc-<id>@<instance>` と完全一致し、その記録から `identify_pid1` が成功する。続けて
//!   `enter_namespaces` の後の namespace 識別子が pid1 のものと一致する
//! - 同じ ID を削除・再作成した別 instance の記録では、pid1 が旧 instance の cgroup に居続けるため、違反
//!   `exec_target_cgroup_mismatch` で拒否される
//! - 特定の後に pid1 を別の cgroup へ移すと、参加の直前の再確認により `enter_namespaces` が拒否され、
//!   何の namespace にも参加しない
//!
//! # joiner が状態ストアを直接開かない理由
//! joiner は pid1 の user namespace へ `nsenter` で先に入る（user namespace への参加は未実装。`exec_setns_join`
//! と同じ構成）。その中からは `FileStateStore::open` が通らない（祖先ディレクトリの所有者がホストの root として
//! 見えず、overflow uid になるため、祖先検証が fail-closed で拒否する）。そのため、ストアの読み書きは orchestrator
//! （初期 user namespace）が行い、読み戻した配置（scope・instance）と pid を引数で joiner へ渡し、joiner が
//! `StateRecord` を再構成して `identify_pid1` へ渡す（`tests/exec.rs` の `make_record` と同じ方式）。
//!
//! # 単一スレッドの独自 main（harness = false）
//! `setns(CLONE_NEWNS)` は複数スレッドのプロセスから拒否され、`DelegatedCgroup::prepare` は自プロセスを退避
//! リーフへ移すため 1 プロセス 1 回しか呼べない。libtest ではなく独自 `main` で動かす。非 Linux では対象外
//! （OS 非該当であり skip ではない）。
//!
//! # 実機前提テストとしての分離
//! 非特権ユーザーに委譲された cgroup v2 サブツリー（GitHub ホステッド runner では保証できない）と、非特権
//! user namespace で `uid_map` を書けるホスト（AppArmor の `kernel.apparmor_restrict_unprivileged_userns=1`
//! がない環境）・`unshare` / `nsenter`（util-linux）が必要なため、`-- --ignored` 指定時のみ実行する
//! （AGENTS.md「実機前提テスト」）。`cargo` を経由せず、ビルド済みのバイナリを委譲スコープの中で直接実行する
//! （root 不要）:
//!
//! ```text
//! cargo test -p fandhe-container-supervisor --test exec_identify_cgroup --no-run
//! timeout 120 systemd-run --user --scope -p Delegate=yes <target/debug/deps/exec_identify_cgroup-XXXX> --ignored
//! ```
//!
//! 外側の `timeout` は、試験内の各待機の上限（REPAIR-5）が万一効かない場合の最終的な打ち切り。
//!
//! 実行された場合は、環境不備を含むあらゆる失敗を失敗として扱う（検証せずに成功する分岐を持たない）。

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("exec_identify_cgroup: Linux only, not applicable on this OS");
}

#[cfg(target_os = "linux")]
fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some(linux::JOINER_OK) => linux::joiner_ok(&args),
        Some(linux::JOINER_RECREATED) => linux::joiner_recreated(&args),
        Some(linux::JOINER_MOVED) => linux::joiner_moved(&args),
        _ if args.iter().any(|a| a == "--ignored") => linux::orchestrate(),
        _ => println!(
            "exec_identify_cgroup: ignored (real-machine test; run with `-- --ignored`, see AGENTS.md)"
        ),
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::fs;
    use std::num::NonZeroU32;
    use std::os::unix::fs::DirBuilderExt as _;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};

    use fandhe_container_core::cgroups::{CgroupName, ContainerCgroup, DelegatedCgroup};
    use fandhe_container_core::exec::JoinNamespace;
    use fandhe_container_core::oci_runtime::ContainerCgroupRemover as _;
    use fandhe_container_core::state_store::{FileStateStore, StateRoot};
    use fandhe_container_core::traits::{
        CgroupPlacement, CgroupScope, ContainerId, ContainerStatus, CreateStateRequest, ErrorCode,
        GetStateRequest, StateRecord, StateRevision, StateStore as _,
    };
    use fandhe_container_supervisor::exec::{enter_namespaces, identify_pid1};

    /// 成功経路の joiner の再入フラグ。
    pub const JOINER_OK: &str = "--joiner-ok";
    /// 別 instance の記録の拒否経路の joiner の再入フラグ。
    pub const JOINER_RECREATED: &str = "--joiner-recreated";
    /// 特定後に pid1 が別 cgroup へ移された場合の拒否経路の joiner の再入フラグ。
    pub const JOINER_MOVED: &str = "--joiner-moved";

    /// 試験で作るコンテナの ID（`fc-exec-identify@<instance>` が cgroup 名になる）。
    const CONTAINER_ID: &str = "exec-identify";
    /// 参加で切り替わる namespace の `/proc/<..>/ns/` エントリ名（pid は参加後 `pid_for_children` に現れる）。
    const NS_ENTRIES: [&str; 4] = ["mnt", "uts", "ipc", "net"];
    /// joiner が特定を終えた合図・orchestrator が pid1 を移し終えた合図のファイル名。
    const IDENTIFIED: &str = "identified";
    const MOVED: &str = "moved";
    /// 本番の拒否メッセージ（`from_exec_error`。`exec_setns_join` と同じ文字列）。
    const CGROUP_MISMATCH: &str = "exec stage SetNs: the exec target does not belong to the \
         recorded container cgroup (violation: exec_target/exec_target_cgroup_mismatch, SEC-1)";

    fn timeout() -> Duration {
        let secs = std::env::var("FANDHE_CONTAINER_TEST_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|s| (1..=600).contains(s))
            .unwrap_or(10);
        Duration::from_secs(secs)
    }

    /// 条件が成立するまで待つ。上限（REPAIR-5）を超えたら panic する。
    fn wait_until(what: &str, mut cond: impl FnMut() -> bool) {
        let deadline = Instant::now() + timeout();
        while !cond() {
            assert!(Instant::now() < deadline, "timed out waiting for {what}");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn link(path: &str) -> String {
        fs::read_link(path)
            .unwrap_or_else(|e| panic!("read_link {path}: {e}"))
            .to_string_lossy()
            .into_owned()
    }

    /// `/proc/<pid>/cgroup` の v2 行（`0::<path>\n`）をそのまま返す。
    fn proc_cgroup(pid: u32) -> String {
        fs::read_to_string(format!("/proc/{pid}/cgroup"))
            .unwrap_or_else(|e| panic!("read /proc/{pid}/cgroup: {e}"))
    }

    /// 0700 の一時ディレクトリ（祖先に symlink を含まない一意な場所へ排他作成。drop で削除）。
    struct TempDir(PathBuf);

    impl TempDir {
        fn create(tag: &str) -> Self {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.subsec_nanos());
            let dir = fs::canonicalize(std::env::temp_dir())
                .expect("canonicalize temp_dir")
                .join(format!(
                    "fandhe-identify-{tag}-{}-{nanos}",
                    std::process::id()
                ));
            fs::DirBuilder::new()
                .mode(0o700)
                .create(&dir)
                .expect("exclusively create the temp dir");
            Self(dir)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// 後始末をまとめて担う。検証の panic で巻き戻る場合も drop で実行する（成否に関わらず）。
    ///
    /// pid1 は `unshare --kill-child` が親（`Child` で保持する `unshare`）の死に連動して落とす。数値 PID への
    /// `kill` は PID 再利用で無関係なプロセスを殺し得る（SEC-1）ため行わない。子 cgroup は pid1 が消えて空に
    /// なってから、保持したハンドル経由（同一性確認つき）で削除する。退避リーフは自プロセスがいるため残す
    /// （transient scope ごと systemd が回収する。`cgroup_join` と同じ）。
    struct Cleanup {
        unshare: Option<Child>,
        delegated: DelegatedCgroup,
        container: ContainerCgroup,
        procs: PathBuf,
        finished: bool,
    }

    /// 子プロセスを強制終了し、有限の猶予（`timeout()`）内に回収する（REPAIR-5）。
    ///
    /// `Child::wait()` は無期限に待ち得る（kill の送信失敗・割り込み不能状態）ため使わず、`try_wait` で
    /// 上限まで確認する。kill の送信失敗と回収期限超過は、どちらも明示的な `Err` にする。
    fn kill_and_reap(child: &mut Child, what: &str) -> Result<(), String> {
        if let Err(e) = child.kill() {
            // 既に終了済みなら try_wait が即座に回収できるため、送信失敗はその確認後に失敗として扱う。
            if !matches!(child.try_wait(), Ok(Some(_))) {
                return Err(format!("failed to kill {what}: {e}"));
            }
            return Ok(());
        }
        let deadline = Instant::now() + timeout();
        loop {
            match child.try_wait() {
                Ok(Some(_)) => return Ok(()),
                Ok(None) => {}
                Err(e) => return Err(format!("try_wait on {what} failed: {e}")),
            }
            if Instant::now() >= deadline {
                return Err(format!("{what} was not reaped within {:?}", timeout()));
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    impl Cleanup {
        /// 後始末を実行し、失敗（回収期限超過・cgroup が空にならない・削除失敗）を `Err` で返す。
        /// 通常経路はこれを呼んで失敗を非ゼロ終了へ反映する。2 回目以降は何もしない。
        fn finish(&mut self) -> Result<(), String> {
            if self.finished {
                return Ok(());
            }
            self.finished = true;
            let mut errors = Vec::new();
            if let Some(mut unshare) = self.unshare.take()
                && let Err(e) = kill_and_reap(&mut unshare, "unshare")
            {
                errors.push(e);
            }
            let deadline = Instant::now() + timeout();
            let mut emptied = false;
            while Instant::now() < deadline {
                if fs::read_to_string(&self.procs).is_ok_and(|s| s.trim().is_empty()) {
                    emptied = true;
                    break;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            if !emptied {
                errors.push(format!(
                    "the container cgroup did not become empty within {:?}",
                    timeout()
                ));
            }
            if let Err(e) = self.delegated.remove_child(&self.container) {
                errors.push(format!("cleanup of the container cgroup failed: {e}"));
            }
            if errors.is_empty() {
                Ok(())
            } else {
                Err(errors.join("; "))
            }
        }
    }

    impl Drop for Cleanup {
        /// 検証の panic による巻き戻し時の回収用。失敗は表示のみ（通常経路は `finish` で失敗を返す）。
        fn drop(&mut self) {
            if let Err(e) = self.finish() {
                eprintln!("exec_identify_cgroup: cleanup failed: {e}");
            }
        }
    }

    pub fn orchestrate() {
        // 1. 委譲スコープと状態ストア。ストアの読み書きは初期 user namespace のここで行う。
        let delegated = DelegatedCgroup::detect().expect("detect delegated cgroup");
        let scope = delegated.scope().expect("delegated scope");
        let state_dir = TempDir::create("state");
        let store = FileStateStore::open(
            StateRoot::from_override(state_dir.0.clone()).expect("state root"),
        )
        .expect("open store");
        let id = ContainerId::new(CONTAINER_ID).expect("container id");
        let bundle = state_dir.0.join("bundle");
        let create = |store: &FileStateStore| {
            store
                .create(
                    &CreateStateRequest::new(
                        ContainerStatus::created(id.clone(), None),
                        bundle.clone(),
                    )
                    .expect("create request")
                    .with_cgroup_scope(scope.clone()),
                )
                .expect("create record")
        };
        let record = create(&store);
        // 本番 launcher の契約どおり、cgroup を作る前にスコープを記録し、返された instance の名前で作る。
        let placement = record.cgroup().expect("recorded placement").clone();
        assert_eq!(placement.scope().as_str(), delegated.path());
        let instance = placement.instance();
        assert_eq!(
            store
                .get(&GetStateRequest::new(id.clone()))
                .expect("read back")
                .cgroup(),
            Some(&placement),
            "the placement must survive a read back unchanged (OCI-6)"
        );

        // 2. 記録の instance から導いた名前の実 cgroup を作る。以後に生まれる子は退避リーフ側にいる。
        let name = CgroupName::for_instance(&id, instance).expect("cgroup name");
        let expected_name = format!("fc-{CONTAINER_ID}@{}", instance.value());
        assert_eq!(name.as_str(), expected_name);
        let (container, _evacuated) = delegated.prepare(&name).expect("prepare container cgroup");
        let scope_dir =
            PathBuf::from("/sys/fs/cgroup").join(delegated.path().trim_start_matches('/'));
        let procs = scope_dir.join(name.as_str()).join("cgroup.procs");
        // 退避リーフ（自プロセスの現在の cgroup。移動先として使う）。
        let own = proc_cgroup(std::process::id());
        let leaf_path = own
            .trim_end()
            .strip_prefix("0::")
            .expect("cgroup v2 line")
            .to_owned();
        assert_ne!(leaf_path, format!("{}/{expected_name}", delegated.path()));
        let leaf_procs = PathBuf::from("/sys/fs/cgroup")
            .join(leaf_path.trim_start_matches('/'))
            .join("cgroup.procs");
        let mut cleanup = Cleanup {
            unshare: None,
            delegated,
            container,
            procs: procs.clone(),
            finished: false,
        };

        // 3. pid1 を作って子 cgroup へ入れる。
        let unshare = Command::new("unshare")
            .args([
                "--user",
                "--map-root-user",
                "--pid",
                "--fork",
                "--kill-child",
            ])
            .args(["--mount", "--uts", "--ipc", "--net", "sleep", "60"])
            .stdin(Stdio::null())
            .spawn()
            .expect("spawn unshare");
        let unshare_pid = unshare.id();
        cleanup.unshare = Some(unshare);
        let mut pid1 = None;
        wait_until("pid1 to appear", || {
            pid1 = nested_pid1_child(unshare_pid);
            pid1.is_some()
        });
        let pid1 = pid1.expect("pid1");
        let want_cgroup = format!("0::{}/{expected_name}\n", cleanup.delegated.path());
        move_to(&procs, pid1);
        assert_eq!(proc_cgroup(pid1), want_cgroup);
        assert!(
            fs::read_to_string(&procs)
                .expect("read cgroup.procs")
                .split_whitespace()
                .any(|p| p == pid1.to_string()),
            "pid1 must be listed in the container cgroup"
        );

        let scope_str = placement.scope().as_str().to_owned();

        // (a) 成功: 記録の配置から導いた期待パスで identify_pid1 が成功し、参加後の識別子が一致する。
        run_joiner(
            pid1,
            JOINER_OK,
            &[&scope_str, &instance.value().to_string()],
        );
        println!("exec_identify_cgroup: identify_pid1 succeeded from the recorded placement");

        // (b) 特定後に pid1 が別 cgroup へ移されると、参加が拒否される。
        let handshake = TempDir::create("handshake");
        let mut joiner = spawn_joiner(
            pid1,
            JOINER_MOVED,
            &[
                &scope_str,
                &instance.value().to_string(),
                handshake.0.to_str().expect("utf-8 temp path"),
            ],
        );
        wait_until("the joiner to identify pid1", || {
            handshake.0.join(IDENTIFIED).exists()
        });
        move_to(&leaf_procs, pid1);
        assert_eq!(proc_cgroup(pid1), format!("0::{leaf_path}\n"));
        publish(&handshake.0, MOVED);
        wait_exit(&mut joiner, JOINER_MOVED);
        // pid1 を子 cgroup へ戻し、以降のシナリオの前提を保つ。
        move_to(&procs, pid1);
        assert_eq!(proc_cgroup(pid1), want_cgroup);
        println!("exec_identify_cgroup: join rejected after pid1 moved to another cgroup");

        // (c) 同じ ID を削除・再作成した別 instance の記録は、旧 instance の cgroup にいる pid1 を拒否する。
        let current = store
            .get(&GetStateRequest::new(id.clone()))
            .expect("read before delete");
        store
            .delete(&fandhe_container_core::traits::DeleteStateRequest::new(
                id.clone(),
                current.revision(),
            ))
            .expect("delete record");
        let recreated = create(&store);
        let new_instance = recreated.cgroup().expect("recreated placement").instance();
        assert_ne!(
            new_instance, instance,
            "a re-created ID must get a new instance"
        );
        run_joiner(
            pid1,
            JOINER_RECREATED,
            &[&scope_str, &new_instance.value().to_string()],
        );
        println!(
            "exec_identify_cgroup: recreated instance rejected with exec_target_cgroup_mismatch"
        );

        // 後始末は drop で行う（pid1 を止め、子 cgroup が空になってから削除する）。
        // 失敗（回収期限超過・cgroup が空にならない・削除失敗）は panic で非ゼロ終了にする。
        if let Err(e) = cleanup.finish() {
            panic!("cleanup failed: {e}");
        }
        println!("exec_identify_cgroup: identify_pid1 against a real container cgroup verified");
    }

    /// `procs`（`cgroup.procs`）へ pid を書いて cgroup を移す。
    fn move_to(procs: &Path, pid: u32) {
        fs::write(procs, pid.to_string())
            .unwrap_or_else(|e| panic!("move pid {pid} via {}: {e}", procs.display()));
    }

    /// 合図ファイルを一時名から rename で公開する（書きかけを見せない）。
    fn publish(dir: &Path, name: &str) {
        let tmp = dir.join(format!("{name}.tmp"));
        fs::write(&tmp, name).expect("write marker");
        fs::rename(&tmp, dir.join(name)).expect("publish marker");
    }

    /// joiner を pid1 の user namespace へ入れて起動する。引数は `<flag> <pid1> <extra...>`。
    fn spawn_joiner(pid1: u32, flag: &str, extra: &[&str]) -> Child {
        let exe = std::env::current_exe().expect("current_exe");
        Command::new("nsenter")
            // `--map-root-user` の user namespace は setgroups が deny のため、既定の setgroups(0) が
            // EPERM になる。資格情報を維持して参加する。
            .arg("--preserve-credentials")
            .arg(format!("--user=/proc/{pid1}/ns/user"))
            .arg(exe)
            .arg(flag)
            .arg(pid1.to_string())
            .args(extra)
            .stdin(Stdio::null())
            .spawn()
            .expect("spawn joiner")
    }

    fn run_joiner(pid1: u32, flag: &str, extra: &[&str]) {
        let mut joiner = spawn_joiner(pid1, flag, extra);
        wait_exit(&mut joiner, flag);
    }

    /// joiner が期限内に終了コード 0 で終わることを確かめる（超過は kill して panic）。
    fn wait_exit(joiner: &mut Child, flag: &str) {
        let deadline = Instant::now() + timeout();
        let status = loop {
            if let Some(s) = joiner.try_wait().expect("try_wait") {
                break s;
            }
            if Instant::now() >= deadline {
                let reaped = kill_and_reap(joiner, "joiner");
                panic!(
                    "joiner {flag} did not exit within {:?} (reap: {reaped:?})",
                    timeout()
                );
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        assert_eq!(status.code(), Some(0), "joiner {flag} must exit with 0");
    }

    /// `unshare_pid` の子のうち、入れ子の PID namespace の PID 1（`NSpid` が 2 要素以上で末尾 1）のものを返す。
    fn nested_pid1_child(unshare_pid: u32) -> Option<u32> {
        let children =
            fs::read_to_string(format!("/proc/{unshare_pid}/task/{unshare_pid}/children")).ok()?;
        children
            .split_whitespace()
            .filter_map(|t| t.parse::<u32>().ok())
            .find(|pid| {
                let Ok(status) = fs::read_to_string(format!("/proc/{pid}/status")) else {
                    return false;
                };
                let Some(rest) = status.lines().find_map(|l| l.strip_prefix("NSpid:")) else {
                    return false;
                };
                let toks: Vec<&str> = rest.split_whitespace().collect();
                toks.len() >= 2 && toks.last() == Some(&"1")
            })
    }

    /// joiner の引数（`<flag> <pid1> <scope> <instance> ...`）から Running の記録を再構成する。
    fn record_from_args(args: &[String]) -> (u32, StateRecord) {
        let pid: u32 = args
            .get(2)
            .and_then(|v| v.parse().ok())
            .expect("pid1 argument");
        let scope = CgroupScope::new(args.get(3).expect("scope argument")).expect("scope");
        let instance: u64 = args
            .get(4)
            .and_then(|v| v.parse().ok())
            .expect("instance argument");
        let status = ContainerStatus::running(
            ContainerId::new(CONTAINER_ID).expect("id"),
            NonZeroU32::new(pid),
        );
        let record = StateRecord::new(
            status,
            std::env::temp_dir().join("bundle"),
            StateRevision::from_raw(instance),
        )
        .expect("record")
        .with_cgroup(CgroupPlacement::new(
            scope,
            StateRevision::from_raw(instance),
        ));
        (pid, record)
    }

    /// 自分（現スレッド）の 4 種の namespace と `pid_for_children` のリンク先。
    fn own_namespaces() -> Vec<String> {
        NS_ENTRIES
            .iter()
            .chain(["pid_for_children"].iter())
            .map(|n| link(&format!("/proc/thread-self/ns/{n}")))
            .collect()
    }

    /// 成功経路: 記録から identify_pid1 が成功し、参加後の識別子が pid1 のものと一致する（AC1・AC2）。
    pub fn joiner_ok(args: &[String]) {
        let (pid, record) = record_from_args(args);
        let want: Vec<String> = NS_ENTRIES
            .iter()
            .map(|n| link(&format!("/proc/{pid}/ns/{n}")))
            .chain([link(&format!("/proc/{pid}/ns/pid"))])
            .collect();
        let before = own_namespaces();
        for (i, name) in NS_ENTRIES.iter().enumerate() {
            assert_ne!(
                before[i], want[i],
                "{name} namespace must differ before join"
            );
        }
        assert_ne!(
            before[4], want[4],
            "pid_for_children must differ before join"
        );

        let target = identify_pid1(&record).expect("identify pid1 from the recorded placement");
        assert_eq!(target.pid1().pid().get(), pid);
        assert_eq!(target.id().as_str(), CONTAINER_ID);
        let report = enter_namespaces(&target).expect("enter namespaces");
        assert_eq!(report.target_pid.get(), pid);
        assert_eq!(report.joined, JoinNamespace::SUP6_SET.to_vec());
        assert_eq!(own_namespaces(), want);
    }

    /// 別 instance の記録は、旧 instance の cgroup にいる pid1 を違反 `exec_target_cgroup_mismatch` で拒否する（AC3）。
    pub fn joiner_recreated(args: &[String]) {
        let (_pid, record) = record_from_args(args);
        let err = identify_pid1(&record).expect_err("a recreated instance must be rejected");
        assert_eq!(err.code(), ErrorCode::FailedPrecondition);
        assert_eq!(err.message(), CGROUP_MISMATCH);
    }

    /// 特定の後に pid1 が別 cgroup へ移されると、`enter_namespaces` が何にも参加せず拒否する（AC4）。
    pub fn joiner_moved(args: &[String]) {
        let dir = PathBuf::from(args.get(5).expect("handshake dir argument"));
        let (_pid, record) = record_from_args(args);
        let target = identify_pid1(&record).expect("identify pid1 before the move");
        let before = own_namespaces();
        publish(&dir, IDENTIFIED);
        wait_until("the cgroup move", || dir.join(MOVED).exists());
        let err = enter_namespaces(&target).expect_err("the join must be rejected after the move");
        assert_eq!(err.code(), ErrorCode::FailedPrecondition);
        assert_eq!(err.message(), CGROUP_MISMATCH);
        assert_eq!(own_namespaces(), before, "nothing may be joined");
    }
}
