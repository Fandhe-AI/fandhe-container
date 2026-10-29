//! `@lock` の取り直しで別プロセスが飢えないことの 2 プロセス競合試験（#2229・SUP-1・REPAIR-5・
//! TASK-157.9・OCI-5）。
//!
//! 連続側（子プロセス。CLI が間を空けず操作し続ける役）が自分の ID の `update` を sleep なしで回し続け、
//! 待ち側（親。supervisor の役）が別の ID の `update` を一定間隔で行う。待ち側の各操作の所要時間と
//! `TIMEOUT` 件数を測り、`--no-capture` で読める形で stderr に出す。判定は百分位ではなく緩い上限
//! （全操作成功・最大待ちが `STATE_LOCK_TIMEOUT` の半分未満）に留め、間欠失敗を避ける（#2214 の轍）。
//!
//! 別プロセスはこのテストバイナリ自身を `--exact` で再実行して用意する（追加依存なし）。子の待機には
//! 上限を設け、超えたら kill して出力を失敗メッセージに含める（REPAIR-5・#2001）。
//! `FileStateStore` は Linux 限定のため、全体を Linux 限定にする（他 OS の `open` は `Unimplemented`。
//! `state_store` のモジュール doc「対応プラットフォーム」）。root 不要で既定のテスト集合で動く。
//! 計測結果は `docs/design/measurements/state-lock-contention.md` に記録する。

#[path = "support/reap.rs"]
mod reap;

#[cfg(target_os = "linux")]
#[path = "support/scratch_root.rs"]
mod scratch_root;

#[cfg(target_os = "linux")]
mod linux {
    use std::fs;
    use std::io::Read;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    use fandhe_container_core::state_store::{FileStateStore, STATE_LOCK_TIMEOUT, StateRoot};
    use fandhe_container_core::traits::{
        ContainerId, ContainerStatus, CreateStateRequest, ErrorCode, GetStateRequest, StateStore,
        UpdateStateRequest,
    };

    const ROOT_ENV: &str = "FANDHE_LOCK_FAIR_ROOT";
    const GO_ENV: &str = "FANDHE_LOCK_FAIR_GO";
    const STOP_ENV: &str = "FANDHE_LOCK_FAIR_STOP";
    const COUNT_ENV: &str = "FANDHE_LOCK_FAIR_COUNT";
    const CHILD_TEST: &str = "linux::child_tight_loop_writer";
    /// 待ち側の操作回数と間隔。
    const WAITER_OPS: u32 = 20;
    const WAITER_INTERVAL: Duration = Duration::from_millis(50);
    /// 子の連続運転の上限（親の stop 合図が来なければここで止まる。REPAIR-5）。
    const CHILD_MAX_RUN: Duration = Duration::from_secs(30);
    const CHILD_DEADLINE: Duration = Duration::from_secs(60);

    fn cid(s: &str) -> ContainerId {
        ContainerId::new(s).unwrap()
    }

    fn open(root: &Path) -> FileStateStore {
        FileStateStore::open(StateRoot::from_override(root.to_path_buf()).unwrap()).unwrap()
    }

    fn create(store: &FileStateStore, id: &str) {
        let bundle = std::env::temp_dir().join("fandhe-lock-fair-bundle");
        store
            .create(
                &CreateStateRequest::new(ContainerStatus::created(cid(id), None), bundle).unwrap(),
            )
            .unwrap();
    }

    /// 1 回の `get` + `update`（どちらも `@lock` を取る）。成功なら Ok、失敗はエラーコードを返す。
    fn touch(store: &FileStateStore, id: &ContainerId) -> Result<(), ErrorCode> {
        let cur = store
            .get(&GetStateRequest::new(id.clone()))
            .map_err(|e| e.code())?;
        store
            .update(&UpdateStateRequest::new(
                cur.status().clone(),
                cur.revision(),
            ))
            .map(|_| ())
            .map_err(|e| e.code())
    }

    fn wait_for_marker(path: &Path) {
        let deadline = Instant::now() + CHILD_DEADLINE;
        while !path.exists() {
            assert!(Instant::now() < deadline, "timed out waiting for marker");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// 子プロセス側（連続側）。`ROOT_ENV` があるときだけ動く。stop 合図まで sleep なしで回し続け、
    /// 成功件数を `COUNT_ENV` のファイルへ書く。
    #[test]
    fn child_tight_loop_writer() {
        let Some(root) = std::env::var_os(ROOT_ENV) else {
            return;
        };
        let store = open(Path::new(&root));
        let go = PathBuf::from(std::env::var_os(GO_ENV).unwrap());
        let stop = PathBuf::from(std::env::var_os(STOP_ENV).unwrap());
        wait_for_marker(&go);
        let id = cid("hammer");
        let started = Instant::now();
        let mut ok = 0u64;
        while !stop.exists() && started.elapsed() < CHILD_MAX_RUN {
            // 連続側の TIMEOUT はこの試験の判定対象ではない（待ち側が主）。失敗は数えない。
            if touch(&store, &id).is_ok() {
                ok += 1;
            }
        }
        fs::write(std::env::var_os(COUNT_ENV).unwrap(), ok.to_string()).unwrap();
    }

    /// SUP-1・REPAIR-5・#2229: 連続して取り直す別プロセスがいても、待ち側の操作はすべて成功し
    /// （`TIMEOUT` 0 件）、最大待ちが `STATE_LOCK_TIMEOUT` の半分未満に収まる。連続側も進む。
    #[test]
    fn sup1_repair5_2229_tight_loop_writer_does_not_starve_other_process() {
        // pid だけの名前を先に消さず、排他作成の `ScratchDir`（0700）を使う。状態ルートはその子 `state`
        // （親は共有 flock を持つため親を渡さない）。#3434・REPAIR-12。
        let scratch =
            crate::scratch_root::ScratchDir::new("fandhe-lock-fair", Duration::from_secs(10));
        let dir = scratch.path().to_path_buf();
        let root = dir.join("state");
        fs::create_dir(&root).unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let go = dir.join("go");
        let stop = dir.join("stop");
        let count = dir.join("count");
        let log = dir.join("child.log");

        let store = open(&root);
        create(&store, "hammer");
        create(&store, "web");

        let out = fs::File::create(&log).unwrap();
        let err = out.try_clone().unwrap();
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", CHILD_TEST, "--test-threads=1", "--no-capture"])
            .env(ROOT_ENV, &root)
            .env(GO_ENV, &go)
            .env(STOP_ENV, &stop)
            .env(COUNT_ENV, &count)
            .stdout(Stdio::from(out))
            .stderr(Stdio::from(err))
            .spawn()
            .unwrap();

        fs::write(&go, b"go").unwrap();
        let web = cid("web");
        let mut latencies = Vec::new();
        let mut timeouts = 0u32;
        let mut other_failures = Vec::new();
        for _ in 0..WAITER_OPS {
            let t = Instant::now();
            let r = touch(&store, &web);
            latencies.push(t.elapsed());
            match r {
                Ok(()) => {}
                Err(ErrorCode::Timeout) => timeouts += 1,
                Err(c) => other_failures.push(c.as_str()),
            }
            std::thread::sleep(WAITER_INTERVAL);
        }
        fs::write(&stop, b"stop").unwrap();

        // 子を上限つきで待つ（REPAIR-5）。
        let deadline = Instant::now() + CHILD_DEADLINE;
        let status = loop {
            if let Some(s) = child.try_wait().unwrap() {
                break s;
            }
            if Instant::now() >= deadline {
                crate::reap::reap_or_report(&mut child, crate::reap::REAP_WITHIN);
                let mut buf = String::new();
                let _ = fs::File::open(&log)
                    .unwrap()
                    .take(64 * 1024)
                    .read_to_string(&mut buf);
                panic!("child did not finish within the deadline; child output:\n{buf}");
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        let mut buf = String::new();
        let _ = fs::File::open(&log)
            .unwrap()
            .take(64 * 1024)
            .read_to_string(&mut buf);
        assert!(
            status.success(),
            "child exited with {status}; output:\n{buf}"
        );
        let hammer_ok: u64 = fs::read_to_string(&count).unwrap().trim().parse().unwrap();

        latencies.sort();
        let pct = |p: usize| latencies[(latencies.len() * p / 100).min(latencies.len() - 1)];
        let max = *latencies.last().unwrap();
        eprintln!(
            "lock_fairness: waiter ops={WAITER_OPS} timeouts={timeouts} p50={:?} p99={:?} max={max:?} \
             hammer_ok={hammer_ok}",
            pct(50),
            pct(99)
        );

        assert!(
            other_failures.is_empty(),
            "unexpected errors: {other_failures:?}"
        );
        assert_eq!(timeouts, 0, "waiter must not hit the lock timeout");
        assert!(
            max < STATE_LOCK_TIMEOUT / 2,
            "waiter starved: max wait {max:?}"
        );
        assert!(hammer_ok >= 1, "tight-loop writer made no progress");
    }
}
