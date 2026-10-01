//! コンテナ 0 個時点でのデーモンレス確認テスト（TASK-28.2・#146・CORE-1・D-19・SUP-1・MS-2・REPAIR-12）。
//!
//! CORE-1 は D-19 により「中央の常駐デーモンを持たない」と読み替えられている。本ファイルは、コンテナの
//! 作成前・作成後（`created` で存在している間）・削除後のいずれでも、fandhe-container 由来の常駐プロセスが
//! プロセス一覧（`/proc` の全走査）に現れないことを具体値で照合する。supervisor 側（コンテナ稼働中の
//! 監視プロセスがコンテナ終了で消えること）は `crates/supervisor/tests/daemonless.rs` が担当する。
//!
//! 判定方法: テストごとに一意な nonce を環境変数 `FANDHE_DAEMONLESS_PROBE` として役割プロセスに与える。
//! 環境変数は fork / exec / `setsid` / double fork を越えて子孫へ継承されるため、`/proc/<pid>/environ` を
//! 全走査すれば、親が持つ `Child` ハンドルで追えない常駐プロセスも検出できる。プロセス名（`comm`）では
//! 並列に走る他のテストバイナリを拾うため使わない。陰性対照（nonce つき生存プロセスを実際に検出できること）
//! を別テストで照合し、空振り合格を防ぐ（REPAIR-12）。
//!
//! 検証範囲と非範囲（REPAIR-3）: 本番の CLI・core の本番 `ProcessLauncher` は未提供のため、「CLI 役」は
//! テストバイナリ自身の再実行で `FileStateStore::open` → `oci_runtime::create` / `StateStore::delete` という
//! 将来の入口と同じ呼び出し順を模した代役である。本番バイナリでの n=0 確認と SUP-1 の実機計測は
//! TASK-45・47・49 の担当で、本テストは保証しない。root・namespace 不要で既定のテスト集合で動く。
//! 同等の走査補助は別 crate のテストと共有できないため `supervisor/tests/daemonless.rs` にも複製してある。

/// `environ`（NUL 区切りの `KEY=VALUE` 列）に `KEY=nonce` が完全一致で含まれるかを判定する。OS 非依存。
fn environ_has_marker(environ: &[u8], key: &str, nonce: &str) -> bool {
    let want = format!("{key}={nonce}");
    environ.split(|b| *b == 0).any(|e| e == want.as_bytes())
}

/// CORE-1・D-19: マーカー判定は完全一致のみ（前方一致・別キー・空入力は不一致）。
#[test]
fn core1_task28_2_environ_marker_matching_is_exact() {
    let key = "FANDHE_DAEMONLESS_PROBE";
    assert!(environ_has_marker(
        b"A=1\0FANDHE_DAEMONLESS_PROBE=n1\0B=2\0",
        key,
        "n1"
    ));
    assert!(environ_has_marker(b"FANDHE_DAEMONLESS_PROBE=n1", key, "n1"));
    assert!(!environ_has_marker(
        b"FANDHE_DAEMONLESS_PROBE=n1x\0",
        key,
        "n1"
    ));
    assert!(!environ_has_marker(
        b"XFANDHE_DAEMONLESS_PROBE=n1\0",
        key,
        "n1"
    ));
    assert!(!environ_has_marker(b"OTHER=n1\0", key, "n1"));
    assert!(!environ_has_marker(b"", key, "n1"));
}

#[cfg(target_os = "linux")]
mod linux {
    use super::environ_has_marker;

    use std::fs;
    use std::io::Read;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Stdio};
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::{Duration, Instant};

    use fandhe_container_core::observability::OpRecorder;
    use fandhe_container_core::oci_runtime::create;
    use fandhe_container_core::state_store::{FileStateStore, StateRoot};
    use fandhe_container_core::traits::{
        ContainerId, ContainerState, CreateRequest, DeleteStateRequest, GetStateRequest,
        ListStateRequest, StateStore,
    };
    use serde_json::json;

    const PROBE: &str = "FANDHE_DAEMONLESS_PROBE";
    const ENV_OP: &str = "FANDHE_DAEMONLESS_OP";
    const ENV_ROOT: &str = "FANDHE_DAEMONLESS_ROOT";
    const ENV_BUNDLE: &str = "FANDHE_DAEMONLESS_BUNDLE";
    const ENV_ID: &str = "FANDHE_DAEMONLESS_ID";
    const ENV_GO: &str = "FANDHE_DAEMONLESS_GO";

    /// 期限つき待機の上限（REPAIR-5）。
    const DEADLINE: Duration = Duration::from_secs(10);
    const POLL: Duration = Duration::from_millis(10);
    /// 居残り役がマーカー待ちを諦める上限（自滅して孤児を残さない）。
    const RESIDENT_LIFETIME: Duration = Duration::from_secs(8);
    /// `environ` 1 件あたりの読み取り上限（無制限確保をしない）。
    const ENVIRON_LIMIT: u64 = 1 << 20;

    static COUNTER: AtomicU32 = AtomicU32::new(0);

    fn unique(tag: &str) -> String {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        format!("{tag}-{}-{n}-{t}", std::process::id())
    }

    /// `/proc` を全走査し、nonce つきの環境を持つ pid を昇順で返す。
    ///
    /// 走査中に消えたプロセス（NotFound・ESRCH）・他ユーザーのプロセス（PermissionDenied）は対象外として
    /// 読み飛ばす。それ以外の I/O エラーは握りつぶさず panic する。出力へ環境内容は含めない。
    fn scan_marked(nonce: &str) -> Vec<u32> {
        let mut pids = Vec::new();
        for ent in fs::read_dir("/proc").expect("read /proc") {
            let ent = ent.expect("read /proc entry");
            let Some(pid) = ent.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) else {
                continue;
            };
            let f = match fs::File::open(ent.path().join("environ")) {
                Ok(f) => f,
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied
                    ) =>
                {
                    continue;
                }
                Err(e) => panic!("open environ of pid {pid}: {e}"),
            };
            let mut buf = Vec::new();
            match f.take(ENVIRON_LIMIT).read_to_end(&mut buf) {
                Ok(_) => {}
                Err(e) if e.raw_os_error() == Some(3) => continue, // ESRCH
                Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => continue,
                Err(e) => panic!("read environ of pid {pid}: {e}"),
            }
            if environ_has_marker(&buf, PROBE, nonce) {
                pids.push(pid);
            }
        }
        pids.sort_unstable();
        pids
    }

    /// 期限つきで `scan_marked` が空になるのを待つ（ゾンビ回収の揺らぎを吸収。REPAIR-5）。
    fn wait_no_marked(nonce: &str) {
        let end = Instant::now() + DEADLINE;
        loop {
            let found = scan_marked(nonce);
            if found.is_empty() {
                return;
            }
            assert!(Instant::now() < end, "marked processes remain: {found:?}");
            std::thread::sleep(POLL);
        }
    }

    /// drop で kill + 回収する子プロセス（失敗時にもプロセスを残さない）。
    struct Role(Child);

    impl Role {
        fn pid(&self) -> u32 {
            self.0.id()
        }

        /// 期限つきで終了を待ち、終了コードを返す。
        fn wait_exit(&mut self) -> i32 {
            let end = Instant::now() + DEADLINE;
            loop {
                if let Some(s) = self.0.try_wait().expect("try_wait") {
                    return s.code().unwrap_or(-1);
                }
                assert!(Instant::now() < end, "role process did not exit in time");
                std::thread::sleep(POLL);
            }
        }
    }

    impl Drop for Role {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    /// テスト用一時ディレクトリ（0700。drop で削除）。
    struct Tmp(PathBuf);

    impl Tmp {
        fn new(tag: &str) -> Self {
            use std::os::unix::fs::PermissionsExt;
            let p = std::env::temp_dir().join(format!("fandhe-daemonless-{}", unique(tag)));
            fs::create_dir_all(p.join("state")).expect("mkdir state");
            fs::create_dir_all(p.join("bundle").join("rootfs")).expect("mkdir bundle");
            fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).expect("chmod");
            fs::set_permissions(p.join("state"), fs::Permissions::from_mode(0o700)).expect("chmod");
            let cfg = json!({
                "ociVersion": "1.2.0",
                "root": {"path": "rootfs"},
                "process": {"user": {"uid": 0, "gid": 0}, "args": ["/bin/true"], "cwd": "/"}
            });
            fs::write(
                p.join("bundle").join("config.json"),
                serde_json::to_vec(&cfg).expect("serialize"),
            )
            .expect("write config");
            Self(p)
        }
        fn state(&self) -> PathBuf {
            self.0.join("state")
        }
        fn bundle(&self) -> PathBuf {
            self.0.join("bundle")
        }
        fn go(&self) -> PathBuf {
            self.0.join("go")
        }
    }

    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn cid(s: &str) -> ContainerId {
        ContainerId::new(s).expect("container id")
    }

    fn open(root: &Path) -> FileStateStore {
        FileStateStore::open(StateRoot::from_override(root.to_path_buf()).expect("state root"))
            .expect("open state store")
    }

    fn role_command(nonce: &str, test: &str) -> Command {
        let mut cmd = Command::new(std::env::current_exe().expect("current_exe"));
        cmd.args(["--exact", test, "--test-threads=1", "--nocapture"])
            .env(PROBE, nonce)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        cmd
    }

    /// 居残り役。環境変数が無ければ no-op。マーカーが現れるか上限時間で終了する。
    #[test]
    fn child_resident_role() {
        let Ok(go) = std::env::var(ENV_GO) else {
            return;
        };
        let end = Instant::now() + RESIDENT_LIFETIME;
        while !Path::new(&go).exists() && Instant::now() < end {
            std::thread::sleep(POLL);
        }
    }

    /// CLI 役。`ENV_OP` が `create` なら状態を作り、`delete` なら削除する。環境変数が無ければ no-op。
    #[test]
    fn child_cli_role() {
        let (Ok(op), Ok(root), Ok(id)) = (
            std::env::var(ENV_OP),
            std::env::var(ENV_ROOT),
            std::env::var(ENV_ID),
        ) else {
            return;
        };
        let store = open(Path::new(&root));
        match op.as_str() {
            "create" => {
                let bundle = PathBuf::from(std::env::var(ENV_BUNDLE).expect("bundle env"));
                let req = CreateRequest::new(cid(&id), bundle).expect("create request");
                create(&store, &OpRecorder::new(), &req).expect("create succeeds");
            }
            "delete" => {
                let rec = store
                    .get(&GetStateRequest::new(cid(&id)))
                    .expect("record exists");
                store
                    .delete(&DeleteStateRequest::new(cid(&id), rec.revision()))
                    .expect("delete succeeds");
            }
            other => panic!("unknown op: {other}"),
        }
    }

    fn run_cli(nonce: &str, t: &Tmp, op: &str, id: &str) {
        let mut cmd = role_command(nonce, "linux::child_cli_role");
        cmd.env(ENV_OP, op)
            .env(ENV_ROOT, t.state())
            .env(ENV_BUNDLE, t.bundle())
            .env(ENV_ID, id);
        let mut role = Role(cmd.spawn().expect("spawn cli role"));
        assert_eq!(role.wait_exit(), 0, "cli role `{op}` must exit with 0");
    }

    fn count_records(root: &Path) -> usize {
        let req = ListStateRequest::new(std::num::NonZeroU32::new(100).expect("nonzero"))
            .expect("list request");
        open(root).list(&req).expect("list").records().len()
    }

    /// 陰性対照（REPAIR-12）: nonce つき生存プロセスを走査が実際に検出し、終了後は 0 件になる。
    #[test]
    fn core1_task28_2_scanner_detects_marked_resident_process() {
        let t = Tmp::new("neg");
        let nonce = unique("neg");
        assert_eq!(scan_marked(&nonce), Vec::<u32>::new());

        let mut resident = Role(
            role_command(&nonce, "linux::child_resident_role")
                .env(ENV_GO, t.go())
                .spawn()
                .expect("spawn resident role"),
        );
        let pid = resident.pid();
        let end = Instant::now() + DEADLINE;
        while scan_marked(&nonce) != vec![pid] {
            assert!(
                Instant::now() < end,
                "scanner did not detect the resident role (pid {pid}); /proc/<pid>/environ unreadable?"
            );
            std::thread::sleep(POLL);
        }

        fs::write(t.go(), b"").expect("release");
        assert_eq!(resident.wait_exit(), 0);
        wait_no_marked(&nonce);
    }

    /// CORE-1・D-19・SUP-1: 作成前・`created` 存在中・削除後のすべてで常駐プロセスが 0 個。
    ///
    /// 削除は `oci_runtime::delete`（cgroup 後始末の代役が必要）ではなく `StateStore::delete` で行う。
    #[test]
    fn core1_task28_2_no_resident_process_before_and_after_create() {
        let t = Tmp::new("main");
        let nonce = unique("main");
        let id = "c1";

        assert_eq!(scan_marked(&nonce), Vec::<u32>::new(), "before create");

        run_cli(&nonce, &t, "create", id);
        let rec = open(&t.state())
            .get(&GetStateRequest::new(cid(id)))
            .expect("record exists after create");
        assert_eq!(rec.status().state(), ContainerState::Created);
        assert_eq!(count_records(&t.state()), 1);
        wait_no_marked(&nonce);

        run_cli(&nonce, &t, "delete", id);
        assert_eq!(count_records(&t.state()), 0);
        wait_no_marked(&nonce);
    }
}
