//! ファイルベース `StateStore` の結合試験（TASK-31.3・OCI-5・CRI-7。TASK-157.9・SUP-1・REPAIR-5）。
//!
//! 公開 API（`FileStateStore`・`StateRoot`・`StateStore`）だけを crate の外から呼び、
//! 別プロセスとの状態共有・ファイルロックによる排他・再起動（再 open）後の永続性・破損回復を
//! 具体値で確かめる。別プロセスはこのテストバイナリ自身を `--exact` で再実行して用意する
//! （追加依存なし）。子プロセスの待機には上限時間を設ける（REPAIR-5）。root 不要で既定の
//! テスト集合で動く。
//!
//! `FileStateStore` は Linux 限定（他 OS の `open` は `Unimplemented`。`state_store` のモジュール doc
//! 「対応プラットフォーム」）のため、ストアを使う試験は `linux` モジュールに置き、macOS / Windows では
//! fail-closed の挙動（何も作らずに `Unimplemented`）を `oci5_open_is_unimplemented_outside_linux` で
//! 照合する（CLI-1）。
//!
//! TASK-157.9（#1069）: CLI 役（親）と supervisor 役（子プロセス）が同じ ID の `state.json` へ同時に
//! 書いても破損・lost update がないこと、別プロセスが `@lock` を保持している間の書き込みが期限で
//! `TIMEOUT` になることを照合する。
//!
//! #2001（OCI-5・REPAIR-5）: 子プロセスの stderr はファイルへ捕捉し、子が失敗・期限超過したときは
//! 親の失敗メッセージへ含める（CI で子の panic 理由が読めず間欠失敗の原因が追えなかったため）。
//! 複数プロセスが競う試験では、書き込みの間で短く譲る。ロック取得は 5ms 間隔の期限付きポーリングで
//! 待ち順の公平性がなく、間を空けず取り直す側がいると他プロセスが `STATE_LOCK_TIMEOUT` まで飢えうる。
//!
//! #2214（OCI-5・SUP-1・REPAIR-5）: 同一 ID 試験の「親が子の途中値を観測する」重なりは、sleep の長さでなく
//! 段階的な同期で必ず作る。子は途中の `SAME_ID_CHECKPOINT` 回で止まり、親が途中値を観測して
//! resume マーカーを書いてから残りを再開する。

#[path = "support/reap.rs"]
mod reap;

/// OCI-5・SEC-4・CLI-1（#2247）: macOS では `open` が通り、状態ルートが 0700 で作られる。
#[cfg(target_os = "macos")]
#[test]
fn oci5_open_works_on_macos() {
    use fandhe_container_core::state_store::{FileStateStore, StateRoot};
    use std::os::unix::fs::PermissionsExt as _;
    let root = std::fs::canonicalize(std::env::temp_dir())
        .unwrap()
        .join(format!("fandhe-state-it-macos-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    FileStateStore::open(StateRoot::from_override(root.clone()).unwrap()).unwrap();
    assert_eq!(
        std::fs::metadata(&root).unwrap().permissions().mode() & 0o777,
        0o700
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// OCI-5・CLI-1: Linux・macOS 以外（Windows）では状態ルートを作らずに `Unimplemented` を返す。
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
#[test]
fn oci5_open_is_unimplemented_outside_linux() {
    use fandhe_container_core::state_store::{FileStateStore, StateRoot};
    use fandhe_container_core::traits::ErrorCode;
    let root = std::env::temp_dir().join(format!("fandhe-state-it-nolinux-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let e = FileStateStore::open(StateRoot::from_override(root.clone()).unwrap()).unwrap_err();
    assert_eq!(e.code(), ErrorCode::Unimplemented);
    assert_eq!(
        e.message(),
        "file state store requires Linux or macOS to verify the state root"
    );
    assert!(!root.exists());
}

/// ストアを使う試験（Linux 限定）。
#[cfg(target_os = "linux")]
mod linux {
    use std::fs;
    use std::io::Read;
    use std::num::NonZeroU32;
    use std::ops::{Deref, DerefMut};
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Stdio};
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::{Duration, Instant};

    use fandhe_container_core::state_store::{
        FileStateStore, LOCK_FILE_NAME, STATE_FILE_NAME, STATE_LOCK_TIMEOUT, StateRoot,
    };
    use fandhe_container_core::traits::{
        ContainerId, ContainerStatus, CreateStateRequest, DeleteStateRequest, ErrorCode,
        GetStateRequest, HealthStatus, ListStateRequest, StateStore, SupervisionState,
        UpdateStateRequest,
    };

    const ROOT_ENV: &str = "FANDHE_STATE_IT_ROOT";
    const PREFIX_ENV: &str = "FANDHE_STATE_IT_PREFIX";
    /// 子プロセスで再実行するテストの完全修飾名（`--exact` で照合する）。
    const CHILD_TEST: &str = "linux::child_worker_creates_records";
    const CHILDREN: u32 = 3;
    const PER_CHILD: u32 = 8;
    /// 複数プロセスが競う試験で、書き込みの間に譲る時間。ロック待ちは 5ms 間隔のポーリングで公平性がなく、
    /// 譲らないと解放直後に自分で取り直し、他プロセスが `STATE_LOCK_TIMEOUT`（5 秒）まで待たされうる（#2001）。
    const WRITE_YIELD: Duration = Duration::from_millis(3);
    const CHILD_DEADLINE: Duration = Duration::from_secs(60);

    /// 失敗メッセージへ含める子の出力の上限バイト数。
    const CHILD_LOG_LIMIT: u64 = 64 * 1024;

    static COUNTER: AtomicU32 = AtomicU32::new(0);

    /// テスト用一時ディレクトリ（drop で削除）。
    struct TmpDir(PathBuf);

    impl TmpDir {
        fn new(tag: &str) -> Self {
            let n = COUNTER.fetch_add(1, Ordering::SeqCst);
            let p = std::env::temp_dir()
                .join(format!("fandhe-state-it-{tag}-{}-{n}", std::process::id()));
            let _ = fs::remove_dir_all(&p);
            fs::create_dir_all(&p).unwrap();
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).unwrap();
            }
            Self(p)
        }
        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TmpDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// 子プロセスと、その stdout / stderr の捕捉先ファイル（drop で削除）。
    ///
    /// パイプだと親が `try_wait` で待つ間に子が詰まりうるため、ファイルへ逃がして終了後・kill 後に読む。
    /// `Child` へ `Deref` するので `kill` / `wait` はそのまま呼べる。
    struct Worker {
        child: Child,
        log: PathBuf,
    }

    impl Deref for Worker {
        type Target = Child;
        fn deref(&self) -> &Child {
            &self.child
        }
    }

    impl DerefMut for Worker {
        fn deref_mut(&mut self) -> &mut Child {
            &mut self.child
        }
    }

    impl Worker {
        /// `cmd` を stdout / stderr をログファイルへ向けて起動する。
        fn start(mut cmd: Command) -> Self {
            use std::os::unix::fs::OpenOptionsExt;
            let n = COUNTER.fetch_add(1, Ordering::SeqCst);
            let log = std::env::temp_dir().join(format!(
                "fandhe-state-it-log-{}-{n}.txt",
                std::process::id()
            ));
            let _ = fs::remove_file(&log);
            let out = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&log)
                .unwrap();
            let err = out.try_clone().unwrap();
            let child = cmd
                .stdout(Stdio::from(out))
                .stderr(Stdio::from(err))
                .spawn()
                .unwrap();
            Self { child, log }
        }

        /// 子の出力を上限つきで読む（超過分は切り捨てる）。
        fn output(&self) -> String {
            let Ok(f) = fs::File::open(&self.log) else {
                return String::from("<child output unavailable>");
            };
            let mut buf = Vec::new();
            let _ = f.take(CHILD_LOG_LIMIT).read_to_end(&mut buf);
            if buf.is_empty() {
                String::from("<child output empty>")
            } else {
                String::from_utf8_lossy(&buf).into_owned()
            }
        }

        /// kill して回収し、出力を返す。
        fn kill_and_output(&mut self) -> String {
            crate::reap::reap_or_report(&mut self.child, crate::reap::REAP_WITHIN);
            self.output()
        }
    }

    impl Drop for Worker {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.log);
        }
    }

    fn open(root: &Path) -> FileStateStore {
        FileStateStore::open(StateRoot::from_override(root.to_path_buf()).unwrap()).unwrap()
    }

    fn cid(s: &str) -> ContainerId {
        ContainerId::new(s).unwrap()
    }

    fn bundle() -> PathBuf {
        std::env::temp_dir().join("fandhe-it-bundle")
    }

    fn create_req(id: &str) -> CreateStateRequest {
        CreateStateRequest::new(ContainerStatus::created(cid(id), None), bundle()).unwrap()
    }

    fn list_req(n: u32) -> ListStateRequest {
        ListStateRequest::new(NonZeroU32::new(n).unwrap()).unwrap()
    }

    /// 子プロセス側の本体。親が `ROOT_ENV` を渡したときだけ動き、単独実行では何もしない。
    #[test]
    fn child_worker_creates_records() {
        let Some(root) = std::env::var_os(ROOT_ENV) else {
            return;
        };
        let prefix = std::env::var(PREFIX_ENV).unwrap();
        let store = open(Path::new(&root));
        let started = Instant::now();
        // 失敗した操作・件数・経過時間・エラーコードを stderr へ出して panic する（親が失敗メッセージへ含める）。
        let fail = |op: &str, i: u32, e: fandhe_container_core::traits::TraitError| -> ! {
            eprintln!(
                "child {prefix}: {op} #{i} failed after {:?}: {}: {}",
                started.elapsed(),
                e.code().as_str(),
                e.message()
            );
            panic!("child {prefix}: {op} #{i} failed");
        };
        for i in 0..PER_CHILD {
            let id = format!("{prefix}-{i}");
            let rec = match store.create(&create_req(&id)) {
                Ok(r) => r,
                Err(e) => fail("create", i, e),
            };
            // 状態遷移も行い、ロック下の read-modify-write を別プロセス間で競合させる。
            if let Err(e) = store.update(&UpdateStateRequest::new(
                ContainerStatus::creating(cid(&id)),
                rec.revision(),
            )) {
                fail("update", i, e);
            }
            // 解放直後の取り直しで他プロセスを飢えさせない（親と同じ間隔。SUP-1 の試験の前例）。
            std::thread::sleep(WRITE_YIELD);
        }
    }

    fn spawn_child(root: &Path, prefix: &str) -> Worker {
        let mut cmd = Command::new(std::env::current_exe().unwrap());
        cmd.args(["--exact", CHILD_TEST, "--test-threads=1", "--nocapture"])
            .env(ROOT_ENV, root)
            .env(PREFIX_ENV, prefix);
        Worker::start(cmd)
    }

    /// 子プロセスを上限時間つきで待つ。超過したら kill して失敗させる（ハング検出。REPAIR-5）。
    /// 失敗時は子の出力（panic の理由）を親の失敗メッセージへ含める（#2001）。
    fn wait_with_deadline(mut child: Worker) {
        let deadline = Instant::now() + CHILD_DEADLINE;
        loop {
            match child.try_wait().unwrap() {
                Some(status) => {
                    assert!(
                        status.success(),
                        "child exited with {status}; child output:\n{}",
                        child.output()
                    );
                    return;
                }
                None if Instant::now() >= deadline => {
                    let out = child.kill_and_output();
                    panic!("child did not finish within the deadline; child output:\n{out}");
                }
                None => std::thread::sleep(Duration::from_millis(20)),
            }
        }
    }

    /// OCI-5: 複数の別プロセスが同じ状態ルートへ同時に書いても、ロックで直列化されて
    /// 全レコードが残り、revision はストア全体で重複しない。
    #[test]
    fn oci5_processes_share_state_with_exclusive_locking() {
        let t = TmpDir::new("share");
        // 親が先に open して `@revision` を初期化しておく。
        let parent = open(t.path());
        let children: Vec<Worker> = (0..CHILDREN)
            .map(|n| spawn_child(t.path(), &format!("c{n}")))
            .collect();
        // 親も同時に書く。
        for i in 0..PER_CHILD {
            parent.create(&create_req(&format!("p-{i}"))).unwrap();
            // 子と交互にロックを取れるよう、連続した取り直しを避ける。見積もり: ロック下の操作は
            // 親 8 回 + 子 3 × 16 回 = 56 回。1 回 100ms の悲観値でも、譲れば 1 回の待ちは他 3 プロセスの
            // 1 操作ずつ程度で、STATE_LOCK_TIMEOUT（5 秒）を大きく下回る。
            std::thread::sleep(WRITE_YIELD);
        }
        for child in children {
            wait_with_deadline(child);
        }
        let page = parent.list(&list_req(1000)).unwrap();
        let total = (CHILDREN + 1) * PER_CHILD;
        assert_eq!(page.records().len() as u32, total);
        assert!(page.next_cursor().is_none());
        let mut revisions: Vec<u64> = page
            .records()
            .iter()
            .map(|r| r.revision().value())
            .collect();
        revisions.sort_unstable();
        revisions.dedup();
        assert_eq!(revisions.len() as u32, total, "revisions must be unique");
        // 子が更新した結果（creating）が親から見える。
        let rec = parent.get(&GetStateRequest::new(cid("c0-0"))).unwrap();
        assert_eq!(rec.status().state().as_str(), "creating");
    }

    const SAMEID_ROOT_ENV: &str = "FANDHE_STATE_IT_SAMEID_ROOT";
    /// 子が準備完了（`@lock` 越しに開ける状態）を親へ知らせるマーカーのパス。
    const SAMEID_READY_ENV: &str = "FANDHE_STATE_IT_SAMEID_READY";
    /// 親が開始合図を出すマーカーのパス。子はこれが現れるまで更新を始めない。
    const SAMEID_GO_ENV: &str = "FANDHE_STATE_IT_SAMEID_GO";
    /// 親が再開合図を出すマーカーのパス。子は `SAME_ID_CHECKPOINT` 回書いた後これが現れるまで止まる（#2214）。
    const SAMEID_RESUME_ENV: &str = "FANDHE_STATE_IT_SAMEID_RESUME";
    const SAMEID_CHILD_TEST: &str = "linux::child_supervisor_updates_same_id";
    const HOLD_ROOT_ENV: &str = "FANDHE_STATE_IT_HOLD_ROOT";
    const HOLD_READY_ENV: &str = "FANDHE_STATE_IT_HOLD_READY";
    const HOLD_CHILD_TEST: &str = "linux::child_holds_state_lock";
    /// 同一 ID への書き込み回数（親子それぞれ）。
    const SAME_ID_WRITES: u32 = 30;
    /// 子がいったん止まる書き込み回数（#2214）。親は止まった子の途中値（この値）を必ず観測できる。
    const SAME_ID_CHECKPOINT: u32 = SAME_ID_WRITES / 2;
    const _: () = assert!(SAME_ID_CHECKPOINT > 0 && SAME_ID_CHECKPOINT < SAME_ID_WRITES);
    /// `FAILED_PRECONDITION`（後着負け）での取り直し再試行の上限（REPAIR-5: 無限ループにしない）。
    const MAX_RETRIES_PER_WRITE: u32 = 1000;

    fn spawn_worker(test: &str, envs: &[(&str, &Path)]) -> Worker {
        let mut cmd = Command::new(std::env::current_exe().unwrap());
        cmd.args(["--exact", test, "--test-threads=1", "--nocapture"]);
        for (k, v) in envs {
            cmd.env(k, v);
        }
        Worker::start(cmd)
    }

    /// 後着負け（`FAILED_PRECONDITION`）のときだけ `get` からやり直して 1 回書く。
    /// 成功した revision と、後着負けで取り直した回数を返す。
    fn write_with_retry(
        store: &FileStateStore,
        id: &ContainerId,
        build: &dyn Fn(&fandhe_container_core::traits::StateRecord) -> UpdateStateRequest,
    ) -> (u64, u32) {
        for retries in 0..MAX_RETRIES_PER_WRITE {
            let cur = store.get(&GetStateRequest::new(id.clone())).unwrap();
            match store.update(&build(&cur)) {
                Ok(rec) => return (rec.revision().value(), retries),
                Err(e) if e.code() == ErrorCode::FailedPrecondition => continue,
                Err(e) => panic!("unexpected update error: {e:?}"),
            }
        }
        panic!("update kept losing the revision race");
    }

    /// マーカーファイルが現れるまで期限付きで待つ（REPAIR-5: 無限待ちにしない）。
    fn wait_for_marker(path: &Path, what: &str) {
        let deadline = Instant::now() + CHILD_DEADLINE;
        while !path.exists() {
            assert!(Instant::now() < deadline, "timed out waiting for {what}");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// 子プロセス側（supervisor 役）。`SAMEID_ROOT_ENV` があるときだけ動く。
    #[test]
    fn child_supervisor_updates_same_id() {
        let Some(root) = std::env::var_os(SAMEID_ROOT_ENV) else {
            return;
        };
        let store = open(Path::new(&root));
        let id = cid("web");
        let pid = NonZeroU32::new(std::process::id()).unwrap();
        // 準備完了を知らせ、親の開始合図まで待つ（親子の更新開始を揃えて競合を保証する）。
        fs::write(std::env::var_os(SAMEID_READY_ENV).unwrap(), b"ready").unwrap();
        let go = std::path::PathBuf::from(std::env::var_os(SAMEID_GO_ENV).unwrap());
        wait_for_marker(&go, "go marker");
        let resume = std::path::PathBuf::from(std::env::var_os(SAMEID_RESUME_ENV).unwrap());
        for i in 1..=SAME_ID_WRITES {
            write_with_retry(&store, &id, &|cur| {
                UpdateStateRequest::new(cur.status().clone(), cur.revision()).with_supervision(
                    SupervisionState::new(Some(pid), Some(HealthStatus::Healthy), i),
                )
            });
            // supervisor の監視ループ間隔を模して短く譲り、親の更新と時間的に重ねる。
            std::thread::sleep(WRITE_YIELD);
            // 途中値で止まり、親が観測して再開合図を出すまで待つ。重なりを時間でなく合図で作る（#2214）。
            if i == SAME_ID_CHECKPOINT {
                wait_for_marker(&resume, "resume marker");
            }
        }
    }

    /// SUP-1・OCI-5・TASK-157.9: CLI 役（親）と supervisor 役（子プロセス）が同じ ID へ同時に書いても、
    /// `@lock` で直列化され、部分書き込み・lost update・一時ファイルの残骸がない。
    /// 重なりは合図で作る（#2214）: 子は `SAME_ID_CHECKPOINT` 回で止まり、親が途中値を観測して
    /// resume を書くと再開する。
    #[test]
    fn sup1_task157_9_cli_and_supervisor_writes_to_same_id_are_serialized() {
        let t = TmpDir::new("sameid");
        let parent = open(t.path());
        let id = cid("web");
        parent.create(&create_req("web")).unwrap();
        let marker_dir = TmpDir::new("sameid-marker");
        let ready = marker_dir.path().join("ready");
        let go = marker_dir.path().join("go");
        let resume = marker_dir.path().join("resume");
        let mut child = spawn_worker(
            SAMEID_CHILD_TEST,
            &[
                (SAMEID_ROOT_ENV, t.path()),
                (SAMEID_READY_ENV, &ready),
                (SAMEID_GO_ENV, &go),
                (SAMEID_RESUME_ENV, &resume),
            ],
        );
        // 子の準備完了を待ってから開始合図を出し、双方が同時に更新を始める。
        let deadline = Instant::now() + CHILD_DEADLINE;
        while !ready.exists() {
            if Instant::now() >= deadline {
                let out = child.kill_and_output();
                panic!("child did not become ready within the deadline; child output:\n{out}");
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        fs::write(&go, b"go").unwrap();
        // CLI 役: supervision 未指定で status だけを往復させる（既存の supervision は引き継がれる）。
        let mut last_status;
        let mut observed = Vec::new();
        let mut child_progress = Vec::new();
        let write_deadline = Instant::now() + CHILD_DEADLINE;
        // 最低 N 回、かつ子が N 回書き終えたと観測するまで書き続ける。親が子の開始前に終わって
        // 直列実行になるのを防ぐ（子が進行中の値を親が観測できる = 同時書き込みの証拠）。
        let mut i = 0u32;
        let mut resumed = false;
        loop {
            let creating = i.is_multiple_of(2);
            let (rev, _retries) = write_with_retry(&parent, &id, &|cur| {
                let status = if creating {
                    ContainerStatus::creating(cid("web"))
                } else {
                    ContainerStatus::created(cid("web"), None)
                };
                UpdateStateRequest::new(status, cur.revision())
            });
            last_status = if creating { "creating" } else { "created" };
            observed.push(rev);
            // 競合中も常に完全なレコードが読める。
            let seen = parent.get(&GetStateRequest::new(id.clone())).unwrap();
            assert_eq!(seen.id().as_str(), "web");
            child_progress.push(seen.restart_count());
            // 子の途中値を観測したら再開合図を 1 回だけ出す（子は途中で止まっているので必ず観測できる）。
            if !resumed && seen.restart_count() > 0 && seen.restart_count() < SAME_ID_WRITES {
                fs::write(&resume, b"resume").unwrap();
                resumed = true;
            }
            i += 1;
            // ロック取得は期限付きのポーリングのため、親が連続して取り直すと子が割り込めない。
            // 実際の CLI 操作間隔を模して短く譲り、双方が交互にロックを取れるようにする。
            std::thread::sleep(Duration::from_millis(2));
            if i >= SAME_ID_WRITES && seen.restart_count() >= SAME_ID_WRITES {
                break;
            }
            if Instant::now() >= write_deadline {
                let out = child.kill_and_output();
                panic!(
                    "child did not finish its writes in time: {child_progress:?}; child output:\n{out}"
                );
            }
        }
        wait_with_deadline(child);
        assert!(
            resumed,
            "parent never observed the child mid-run: {child_progress:?}"
        );
        assert!(
            observed.windows(2).all(|w| w[0] < w[1]),
            "parent revisions must be strictly increasing: {observed:?}"
        );
        // 競合の発生を確認する: 親が更新を続けている最中に、子の進行が途中値（0 < n < N）で観測された。
        // 親子の更新が時間的に重なっていなければ、同一 ID への同時書き込みを検証できていない。
        assert!(
            child_progress.iter().any(|&c| c > 0 && c < SAME_ID_WRITES),
            "parent never observed the child mid-run (writes were serialized by timing): {child_progress:?}"
        );
        let fin = parent.get(&GetStateRequest::new(id.clone())).unwrap();
        assert_eq!(fin.status().state().as_str(), last_status);
        assert_eq!(fin.restart_count(), SAME_ID_WRITES);
        assert_eq!(fin.health(), Some(HealthStatus::Healthy));
        assert!(fin.supervisor_pid().is_some());
        // create が revision 0、その後に親子の成功した更新が（親 observed.len() + 子 N）回（lost update なし）。
        assert_eq!(
            fin.revision().value(),
            observed.len() as u64 + u64::from(SAME_ID_WRITES)
        );
        assert_eq!(parent.find_corrupted().unwrap(), Vec::<ContainerId>::new());
        let entries: Vec<String> = fs::read_dir(t.path().join("web"))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(entries, vec![STATE_FILE_NAME.to_owned()]);
        let raw = fs::read(t.path().join("web").join(STATE_FILE_NAME)).unwrap();
        let json: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        assert_eq!(json["id"], "web");
    }

    /// 子プロセス側。`@lock` を保持して準備完了マーカーを書き、有限時間だけ寝て終了する。
    #[test]
    fn child_holds_state_lock() {
        let Some(root) = std::env::var_os(HOLD_ROOT_ENV) else {
            return;
        };
        let ready = std::env::var_os(HOLD_READY_ENV).unwrap();
        let lock = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(Path::new(&root).join(LOCK_FILE_NAME))
            .unwrap();
        lock.lock().unwrap();
        fs::write(&ready, b"ready").unwrap();
        std::thread::sleep(STATE_LOCK_TIMEOUT + Duration::from_secs(3));
        drop(lock);
    }

    /// REPAIR-5・TASK-157.9: 別プロセスが `@lock` を保持している間の書き込みは、期限で `TIMEOUT` になり、
    /// 失敗した更新は反映されない。保持プロセスが終われば書ける。
    #[test]
    fn repair5_task157_9_lock_held_by_another_process_times_out() {
        let t = TmpDir::new("holdlock");
        let marker_dir = TmpDir::new("holdlock-marker");
        let ready = marker_dir.path().join("ready");
        let store = open(t.path());
        let rec = store.create(&create_req("web")).unwrap();
        let mut child = spawn_worker(
            HOLD_CHILD_TEST,
            &[(HOLD_ROOT_ENV, t.path()), (HOLD_READY_ENV, &ready)],
        );
        let deadline = Instant::now() + CHILD_DEADLINE;
        while !ready.exists() {
            if Instant::now() >= deadline {
                let out = child.kill_and_output();
                panic!("child did not take the lock within the deadline; child output:\n{out}");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let started = Instant::now();
        let e = store
            .update(&UpdateStateRequest::new(
                ContainerStatus::creating(cid("web")),
                rec.revision(),
            ))
            .unwrap_err();
        let elapsed = started.elapsed();
        assert_eq!(e.code(), ErrorCode::Timeout);
        assert_eq!(e.code().as_str(), "TIMEOUT");
        assert_eq!(e.message(), "timed out waiting for the state lock");
        assert!(elapsed >= STATE_LOCK_TIMEOUT, "{elapsed:?}");
        assert!(elapsed < STATE_LOCK_TIMEOUT + Duration::from_secs(5));
        // 保持側を終わらせると（OS がロックを解放）書ける。失敗した更新は反映されていない。
        crate::reap::reap_or_report(&mut child, crate::reap::REAP_WITHIN);
        let cur = store.get(&GetStateRequest::new(cid("web"))).unwrap();
        assert_eq!(cur, rec);
        let next = store
            .update(&UpdateStateRequest::new(
                ContainerStatus::creating(cid("web")),
                rec.revision(),
            ))
            .unwrap();
        assert_eq!(next.revision().value(), rec.revision().value() + 1);
    }

    /// OCI-5: ストアを閉じて開き直して（再起動相当）も状態が残り、削除済みの revision を再発行しない。
    #[test]
    fn oci5_state_survives_reopen_and_revision_is_not_reused() {
        let t = TmpDir::new("reopen");
        let first = {
            let store = open(t.path());
            let a = store.create(&create_req("a")).unwrap();
            store.create(&create_req("b")).unwrap();
            a
        };
        let store = open(t.path());
        let got = store.get(&GetStateRequest::new(cid("a"))).unwrap();
        assert_eq!(got, first);
        let b_rev = store
            .get(&GetStateRequest::new(cid("b")))
            .unwrap()
            .revision();
        store
            .delete(&DeleteStateRequest::new(cid("b"), b_rev))
            .unwrap();
        drop(store);
        let store = open(t.path());
        let c = store.create(&create_req("c")).unwrap();
        // a=0, b=1 を払い出し済み。b 削除・再 open 後も c は 2 になる。
        assert_eq!(c.revision().value(), 2);
        let ids: Vec<String> = store
            .list(&list_req(10))
            .unwrap()
            .records()
            .iter()
            .map(|r| r.id().as_str().to_owned())
            .collect();
        assert_eq!(ids, vec!["a".to_owned(), "c".to_owned()]);
    }

    /// OCI-5・CRI-7: 同じルートを開いた別インスタンス間で状態が見え、楽観的排他が効く
    /// （古い revision での update は FAILED_PRECONDITION）。
    #[test]
    fn oci5_optimistic_concurrency_across_instances() {
        let t = TmpDir::new("occ");
        let a = open(t.path());
        let b = open(t.path());
        let rec = a.create(&create_req("web")).unwrap();
        let seen = b.get(&GetStateRequest::new(cid("web"))).unwrap();
        assert_eq!(seen, rec);
        let next = a
            .update(&UpdateStateRequest::new(
                ContainerStatus::running(cid("web"), None),
                rec.revision(),
            ))
            .unwrap();
        let stale = b.update(&UpdateStateRequest::new(
            ContainerStatus::creating(cid("web")),
            rec.revision(),
        ));
        assert_eq!(stale.unwrap_err().code(), ErrorCode::FailedPrecondition);
        assert_eq!(
            b.get(&GetStateRequest::new(cid("web"))).unwrap().revision(),
            next.revision()
        );
    }

    /// OCI-5: 破損レコードは find / purge で回復でき、健全なレコードと revision 採番に影響しない。
    #[test]
    fn oci5_corrupted_record_recovery_across_reopen() {
        let t = TmpDir::new("recover");
        {
            let store = open(t.path());
            store.create(&create_req("a")).unwrap();
            store.create(&create_req("b")).unwrap();
        }
        fs::write(t.path().join("a").join("state.json"), b"{broken").unwrap();
        let store = open(t.path());
        assert_eq!(
            store.list(&list_req(10)).unwrap_err().code(),
            ErrorCode::Internal
        );
        assert_eq!(store.find_corrupted().unwrap(), vec![cid("a")]);
        store.purge_corrupted(&cid("a")).unwrap();
        let page = store.list(&list_req(10)).unwrap();
        assert_eq!(page.records().len(), 1);
        assert_eq!(
            store.create(&create_req("c")).unwrap().revision().value(),
            2
        );
    }

    /// OCI-5: 権限不備のレコードは破損扱いせず、回復操作でも消さない（fail-closed）。
    #[test]
    fn oci5_permission_error_record_is_never_purged() {
        use std::os::unix::fs::PermissionsExt;
        let t = TmpDir::new("permission");
        let store = open(t.path());
        store.create(&create_req("a")).unwrap();
        let dir = t.path().join("a");
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            store.list(&list_req(10)).unwrap_err().code(),
            ErrorCode::PermissionDenied
        );
        assert_eq!(
            store.find_corrupted().unwrap_err().code(),
            ErrorCode::PermissionDenied
        );
        assert_eq!(
            store.purge_corrupted(&cid("a")).unwrap_err().code(),
            ErrorCode::PermissionDenied
        );
        assert!(dir.join("state.json").is_file());
    }
}
