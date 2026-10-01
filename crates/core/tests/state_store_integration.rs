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

/// OCI-5・CLI-1: Linux 以外では状態ルートを作らずに `Unimplemented` を返す。
#[cfg(not(target_os = "linux"))]
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
        "file state store requires Linux to verify the state root"
    );
    assert!(!root.exists());
}

/// ストアを使う試験（Linux 限定）。
#[cfg(target_os = "linux")]
mod linux {
    use std::fs;
    use std::num::NonZeroU32;
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
    const CHILD_DEADLINE: Duration = Duration::from_secs(60);

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
        for i in 0..PER_CHILD {
            let id = format!("{prefix}-{i}");
            let rec = store.create(&create_req(&id)).unwrap();
            // 状態遷移も行い、ロック下の read-modify-write を別プロセス間で競合させる。
            store
                .update(&UpdateStateRequest::new(
                    ContainerStatus::creating(cid(&id)),
                    rec.revision(),
                ))
                .unwrap();
        }
    }

    fn spawn_child(root: &Path, prefix: &str) -> Child {
        Command::new(std::env::current_exe().unwrap())
            .args(["--exact", CHILD_TEST, "--test-threads=1", "--nocapture"])
            .env(ROOT_ENV, root)
            .env(PREFIX_ENV, prefix)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap()
    }

    /// 子プロセスを上限時間つきで待つ。超過したら kill して失敗させる（ハング検出。REPAIR-5）。
    fn wait_with_deadline(mut child: Child) {
        let deadline = Instant::now() + CHILD_DEADLINE;
        loop {
            match child.try_wait().unwrap() {
                Some(status) => {
                    assert!(status.success(), "child exited with {status}");
                    return;
                }
                None if Instant::now() >= deadline => {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!("child did not finish within the deadline");
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
        let children: Vec<Child> = (0..CHILDREN)
            .map(|n| spawn_child(t.path(), &format!("c{n}")))
            .collect();
        // 親も同時に書く。
        for i in 0..PER_CHILD {
            parent.create(&create_req(&format!("p-{i}"))).unwrap();
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
    const SAMEID_CHILD_TEST: &str = "linux::child_supervisor_updates_same_id";
    const HOLD_ROOT_ENV: &str = "FANDHE_STATE_IT_HOLD_ROOT";
    const HOLD_READY_ENV: &str = "FANDHE_STATE_IT_HOLD_READY";
    const HOLD_CHILD_TEST: &str = "linux::child_holds_state_lock";
    /// 同一 ID への書き込み回数（親子それぞれ）。
    const SAME_ID_WRITES: u32 = 30;
    /// `FAILED_PRECONDITION`（後着負け）での取り直し再試行の上限（REPAIR-5: 無限ループにしない）。
    const MAX_RETRIES_PER_WRITE: u32 = 1000;

    fn spawn_worker(test: &str, envs: &[(&str, &Path)]) -> Child {
        let mut cmd = Command::new(std::env::current_exe().unwrap());
        cmd.args(["--exact", test, "--test-threads=1", "--nocapture"])
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        for (k, v) in envs {
            cmd.env(k, v);
        }
        cmd.spawn().unwrap()
    }

    /// 後着負け（`FAILED_PRECONDITION`）のときだけ `get` からやり直して 1 回書く。成功した revision を返す。
    fn write_with_retry(
        store: &FileStateStore,
        id: &ContainerId,
        build: &dyn Fn(&fandhe_container_core::traits::StateRecord) -> UpdateStateRequest,
    ) -> u64 {
        for _ in 0..MAX_RETRIES_PER_WRITE {
            let cur = store.get(&GetStateRequest::new(id.clone())).unwrap();
            match store.update(&build(&cur)) {
                Ok(rec) => return rec.revision().value(),
                Err(e) if e.code() == ErrorCode::FailedPrecondition => continue,
                Err(e) => panic!("unexpected update error: {e:?}"),
            }
        }
        panic!("update kept losing the revision race");
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
        for i in 1..=SAME_ID_WRITES {
            write_with_retry(&store, &id, &|cur| {
                UpdateStateRequest::new(cur.status().clone(), cur.revision()).with_supervision(
                    SupervisionState::new(Some(pid), Some(HealthStatus::Healthy), i),
                )
            });
        }
    }

    /// SUP-1・OCI-5・TASK-157.9: CLI 役（親）と supervisor 役（子プロセス）が同じ ID へ同時に書いても、
    /// `@lock` で直列化され、部分書き込み・lost update・一時ファイルの残骸がない。
    #[test]
    fn sup1_task157_9_cli_and_supervisor_writes_to_same_id_are_serialized() {
        let t = TmpDir::new("sameid");
        let parent = open(t.path());
        let id = cid("web");
        parent.create(&create_req("web")).unwrap();
        let child = spawn_worker(SAMEID_CHILD_TEST, &[(SAMEID_ROOT_ENV, t.path())]);
        // CLI 役: supervision 未指定で status だけを往復させる（既存の supervision は引き継がれる）。
        let mut last_status = "created";
        let mut observed = Vec::new();
        for i in 0..SAME_ID_WRITES {
            let creating = i % 2 == 0;
            let rev = write_with_retry(&parent, &id, &|cur| {
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
            assert_eq!(
                parent
                    .get(&GetStateRequest::new(id.clone()))
                    .unwrap()
                    .id()
                    .as_str(),
                "web"
            );
        }
        wait_with_deadline(child);
        assert!(
            observed.windows(2).all(|w| w[0] < w[1]),
            "parent revisions must be strictly increasing: {observed:?}"
        );
        let fin = parent.get(&GetStateRequest::new(id.clone())).unwrap();
        assert_eq!(fin.status().state().as_str(), last_status);
        assert_eq!(fin.restart_count(), SAME_ID_WRITES);
        assert_eq!(fin.health(), Some(HealthStatus::Healthy));
        assert!(fin.supervisor_pid().is_some());
        // create が revision 0、その後に親子の成功した更新が 2N 回（lost update なし）。
        assert_eq!(fin.revision().value(), 2 * u64::from(SAME_ID_WRITES));
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
                let _ = child.kill();
                let _ = child.wait();
                panic!("child did not take the lock within the deadline");
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
        let _ = child.kill();
        let _ = child.wait();
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
