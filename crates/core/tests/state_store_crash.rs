//! 書き込み中の強制終了に対する `state.json` の耐性試験（TASK-31.2・OCI-5・REPAIR-5）。
//!
//! `FileStateStore` の書き込みは一意名の一時ファイルへ書いて fsync してから `rename` するため、
//! 書き込み中のプロセスを SIGKILL で止めても既存の `state.json` は壊れず、読み手は旧値か新値だけを
//! 見る（トレイト契約 4）。本試験は公開 API だけを使い、このテストバイナリ自身を子プロセスとして
//! 再実行し（追加依存なし）、更新ループの途中で kill して、再 open 後の状態を具体値で照合する。
//!
//! kill のタイミングは確率的で、write と rename の間で止まる状況を毎回再現できるわけではない。
//! その状況（途中までの一時ファイルが残った状態）の決定的な再現と掃除は、`state_store` のユニット
//! テスト `oci5_temp_residue_does_not_affect_reads_and_is_swept_on_update` が担う。
//! 子プロセスの待機には上限時間を設ける（REPAIR-5）。root 不要で既定のテスト集合で動く。
//!
//! 観測側は `@lock` を取らず `state.json` を直接読んで revision の前進を確認する（#1400）。子は
//! sleep なしで `get`→`update` を繰り返し、`update` は fsync と rename を含めて `@lock` を保持する
//! ため、`try_lock` の再試行（5ms 間隔・非公平）で待つ観測側は CI の fsync が遅いと取得に飢える。
//! 一時ファイル→fsync→rename の書き方により、ロックなしの読み手も旧値か新値の完全な JSON だけを
//! 見る（トレイト契約 4）ので、直接読みはロック非依存で契約 4 自体の検証にもなる。
//!
//! 失敗時の切り分け: 子の stderr は一時ログ（`child-<i>.log`）へ残し、期限切れ時は診断文字列に
//! 子の終了状態・ログ末尾・観測回数を含める。(a) 子が終了済みでログに失敗理由がある、(b) 子が前進して
//! いる（kill 後の `get` の revision が `last_seen` より大きい）のに直接読みで見えない、(c) 子は実行中で
//! `child: started` はあるが前進が無い、または開始マーカーすら無い（runner 負荷での起動遅延）。
//!
//! `FileStateStore` は Linux 限定（他 OS の `open` は `Unimplemented`。非 Linux の fail-closed は
//! `state_store_integration` の `oci5_open_is_unimplemented_outside_linux` で照合済み）のため、
//! 本試験は Linux のみで実行する。

#[cfg(target_os = "linux")]
mod linux {
    use std::fs::{self, File};
    use std::io::{Read, Seek, SeekFrom};
    use std::num::NonZeroU32;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};

    use fandhe_container_core::state_store::{FileStateStore, MAX_STATE_FILE_BYTES, StateRoot};
    use fandhe_container_core::traits::{
        ContainerId, ContainerStatus, CreateStateRequest, GetStateRequest, StateStore,
        UpdateStateRequest,
    };

    const ROOT_ENV: &str = "FANDHE_STATE_CRASH_ROOT";
    /// 子プロセスで再実行するテストの完全修飾名（`--exact` で照合する）。
    const CHILD_TEST: &str = "linux::child_updates_until_killed";
    /// 子が自力で止まる上限時間（親が異常終了しても孤児化しない）。
    const CHILD_LIFETIME: Duration = Duration::from_secs(30);
    const ITERATIONS: u64 = 15;
    const WAIT_DEADLINE: Duration = Duration::from_secs(20);
    const ID: &str = "crash-target";

    fn cid(s: &str) -> ContainerId {
        ContainerId::new(s).unwrap()
    }

    fn open(root: &Path) -> FileStateStore {
        FileStateStore::open(StateRoot::from_override(root.to_path_buf()).unwrap()).unwrap()
    }

    /// テスト用一時ディレクトリ（drop で削除。0700）。
    struct TmpDir(PathBuf);

    impl TmpDir {
        fn new() -> Self {
            Self::named("fandhe-state-crash")
        }

        fn named(prefix: &str) -> Self {
            let p = std::env::temp_dir().join(format!("{prefix}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&p);
            fs::create_dir_all(&p).unwrap();
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).unwrap();
            }
            Self(p)
        }
    }

    impl Drop for TmpDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// 子プロセス側の本体。親が `ROOT_ENV` を渡したときだけ動き、単独実行では何もしない。
    /// 既存レコードを上限時間まで更新し続ける（pid を変えて書き込みサイズを揺らす）。
    #[test]
    fn child_updates_until_killed() {
        let Some(root) = std::env::var_os(ROOT_ENV) else {
            return;
        };
        // 親が stderr をログへ向けているので、開始・初回成功・失敗理由がそこへ残る（#1400 の切り分け用）。
        eprintln!("child: started pid={}", std::process::id());
        let store = open(Path::new(&root));
        let begin = Instant::now();
        let deadline = begin + CHILD_LIFETIME;
        let mut n: u32 = 1;
        while Instant::now() < deadline {
            let cur = match store.get(&GetStateRequest::new(cid(ID))) {
                Ok(cur) => cur,
                Err(e) => panic!("child get failed after {} updates: {e:?}", n - 1),
            };
            let status = ContainerStatus::running(cid(ID), NonZeroU32::new(n));
            let updated = match store.update(&UpdateStateRequest::new(status, cur.revision())) {
                Ok(u) => u,
                Err(e) => panic!("child update failed after {} updates: {e:?}", n - 1),
            };
            if n == 1 {
                eprintln!(
                    "child: first update ok revision={} elapsed_ms={}",
                    updated.revision().value(),
                    begin.elapsed().as_millis()
                );
            }
            n = n.wrapping_add(1).max(1);
        }
    }

    /// 子の stderr をログファイルへ向けて起動する（パイプと違い詰まらず、SIGKILL 後も読める）。
    fn spawn_child(root: &Path, log: &Path) -> Child {
        let log_file = File::create(log).unwrap();
        Command::new(std::env::current_exe().unwrap())
            .args(["--exact", CHILD_TEST, "--test-threads=1", "--nocapture"])
            .env(ROOT_ENV, root)
            .stdout(Stdio::null())
            .stderr(log_file)
            .spawn()
            .unwrap()
    }

    /// 子プロセスを上限時間つきで回収する。超過したら失敗させる（REPAIR-5）。
    fn reap(child: &mut Child) -> std::process::ExitStatus {
        let deadline = Instant::now() + WAIT_DEADLINE;
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                return status;
            }
            assert!(Instant::now() < deadline, "child did not exit after kill");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// `state.json` を `@lock` なしで直接読み、revision を返す。ファイル無しは `None`。
    /// 一時ファイル→rename の書き方により、読めた内容は常に完全な JSON でなければならない
    /// （トレイト契約 4）ので、壊れていたら契約違反として panic する。
    fn read_revision_lock_free(root: &Path) -> Option<u64> {
        let path = root.join(ID).join("state.json");
        let mut f = File::open(&path).ok()?;
        let len = f.metadata().unwrap().len();
        assert!(len <= MAX_STATE_FILE_BYTES, "state.json too large: {len}");
        let mut buf = Vec::new();
        f.by_ref()
            .take(MAX_STATE_FILE_BYTES)
            .read_to_end(&mut buf)
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&buf)
            .unwrap_or_else(|e| panic!("state.json unreadable by lock-free reader: {e}"));
        assert_eq!(json["id"], ID, "state.json id mismatch");
        Some(
            json["revision"]
                .as_u64()
                .expect("state.json revision is not u64"),
        )
    }

    /// ログ末尾（最大 4 KiB）。診断用で、読めなければ理由を返す。
    fn log_tail(log: &Path) -> String {
        const TAIL: u64 = 4096;
        let Ok(mut f) = File::open(log) else {
            return "<log unavailable>".to_string();
        };
        let len = f.metadata().map(|m| m.len()).unwrap_or(0);
        let _ = f.seek(SeekFrom::Start(len.saturating_sub(TAIL)));
        let mut buf = Vec::new();
        let _ = f.take(TAIL).read_to_end(&mut buf);
        String::from_utf8_lossy(&buf).into_owned()
    }

    /// `dir` 直下で名前に `.tmp` を含むエントリ数。
    fn tmp_count(dir: &Path) -> usize {
        fs::read_dir(dir)
            .unwrap()
            .filter(|e| {
                e.as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .contains(".tmp")
            })
            .count()
    }

    /// OCI-5・REPAIR-5・TASK-31.2: 更新ループ中のプロセスを SIGKILL しても `state.json` は壊れず、
    /// revision は後退せず、再 open 後の更新が成功し、一時ファイルの残骸が残らない。
    #[test]
    fn oci5_state_json_survives_sigkill_during_writes() {
        let t = TmpDir::new();
        let root = t.0.clone();
        let store = open(&root);
        let created = store
            .create(
                &CreateStateRequest::new(
                    ContainerStatus::created(cid(ID), None),
                    std::env::temp_dir().join("fandhe-crash-bundle"),
                )
                .unwrap(),
            )
            .unwrap();
        let mut last_seen = created.revision().value();
        drop(store);
        // 子のログは状態ルートの外に置く（`tmp_count` 等の走査に影響させない）。
        let logs = TmpDir::named("fandhe-state-crash-logs");

        for i in 0..ITERATIONS {
            let log = logs.0.join(format!("child-{i}.log"));
            let mut child = spawn_child(&root, &log);
            // 子が書き込みを始めた（revision が前進した）ことを、`@lock` を取らない直接読みで
            // 上限時間つきで確認する。子が先に終了していたら待たずに失敗させる。
            let started = Instant::now();
            let (mut stale, mut missing) = (0u64, 0u64);
            let observed = loop {
                match read_revision_lock_free(&root) {
                    Some(r) if r > last_seen => break r,
                    Some(_) => stale += 1,
                    None => missing += 1,
                }
                let exited = child.try_wait().unwrap();
                if exited.is_some() || started.elapsed() >= WAIT_DEADLINE {
                    let _ = child.kill();
                    let _ = reap(&mut child);
                    let actual = open(&root).get(&GetStateRequest::new(cid(ID)));
                    panic!(
                        "child made no progress: iteration={i} elapsed_ms={} last_seen={last_seen} \
                         stale_reads={stale} missing_reads={missing} child_exit_before_kill={exited:?} \
                         locked_get_after_kill={:?}\n--- child log tail ---\n{}",
                        started.elapsed().as_millis(),
                        actual.map(|r| r.revision().value()),
                        log_tail(&log)
                    );
                }
                std::thread::sleep(Duration::from_millis(2));
            };
            // 可変オフセットで待ってから kill する（書き込みの様々な局面を狙う）。
            std::thread::sleep(Duration::from_millis((i * 3) % 17));
            // 子は無限に更新を続けるため、kill 時点で稼働中でなければならない（先に終了していたら
            // 試験の前提が崩れているので失敗させる）。
            assert!(
                child.try_wait().unwrap().is_none(),
                "child exited before kill: log:\n{}",
                log_tail(&log)
            );
            child.kill().unwrap();
            let status = reap(&mut child);
            assert_eq!(
                std::os::unix::process::ExitStatusExt::signal(&status),
                Some(9),
                "child was not terminated by SIGKILL: {status:?}"
            );

            // 再 open（新しいインスタンス）して照合する。
            let reopened = open(&root);
            let rec = reopened.get(&GetStateRequest::new(cid(ID))).unwrap();
            assert_eq!(rec.id().as_str(), ID);
            assert!(rec.revision().value() >= observed);
            let raw = fs::read(root.join(ID).join("state.json")).unwrap();
            let json: serde_json::Value = serde_json::from_slice(&raw).unwrap();
            assert_eq!(json["id"], ID);
            last_seen = rec.revision().value();

            // flock が解放され、`@revision` が先行していて、続く更新が成功する。
            let status = ContainerStatus::created(cid(ID), None);
            let updated = reopened
                .update(&UpdateStateRequest::new(status, rec.revision()))
                .unwrap();
            assert!(updated.revision().value() > last_seen);
            last_seen = updated.revision().value();
            // 書き込み後は残骸が掃除されている。
            assert_eq!(tmp_count(&root.join(ID)), 0);
            assert_eq!(tmp_count(&root), 0);
        }
    }
}
