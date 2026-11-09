//! shim v2 起動バイナリの delete action の配線の結合試験（CRI-5・CRI-7・TASK-62.6・REPAIR-3・REPAIR-12・#4152）。
//!
//! 実バイナリ（`containerd-shim-fandhe-container-v2`）を containerd の呼び方（`-namespace`・`-address`・`-id`・`-bundle`・`delete`）で
//! 起動し、CLI → `production_delete` → 状態ルートの回収 → stdout の `DeleteResponse`（protobuf）の通しを具体値で照合する。
//! 状態ルートは `XDG_RUNTIME_DIR` 配下の既定の場所（非 root）に、本番と同じ `<base>-shim-state/<address のハッシュ>/<namespace>` の
//! 配置で記録を事前に作る。root・cgroup・実プロセスは要らず、既定のテスト集合で動く（Running の実プロセスの停止は
//! `reclaim_tests` の偽の実行層と実機前提の試験の範囲）。
#![cfg(target_os = "linux")]

use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::Duration;

use fandhe_container_core::state_store::{FileStateStore, StateRoot};
use fandhe_container_core::traits::{
    ContainerId, ContainerStatus, CreateStateRequest, ExitTime, GetStateRequest, ListStateRequest,
    StateStore,
};

const BIN: &str = env!("CARGO_BIN_EXE_containerd-shim-fandhe-container-v2");
const ADDRESS: &str = "/run/containerd/containerd.sock";
/// 回収済み・記録なしの冪等な応答の終了コード（`DELETE_EXIT_STATUS`）。
const IDEMPOTENT_EXIT: u64 = 137;

#[path = "support/mini_json.rs"]
mod mini_json;
#[path = "../../core/tests/support/reap.rs"]
mod reap;
#[path = "support/shim_wire.rs"]
mod shim_wire;
#[path = "../../oci/tests/support/test_root.rs"]
mod test_root;

/// 試験用の XDG_RUNTIME_DIR（短い /tmp 直下・0700。Drop で消す）。
struct Scratch {
    guard: test_root::TestRoot,
    root: PathBuf,
}

impl Scratch {
    fn new() -> Self {
        static SEQ: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let guard =
            test_root::test_root_at(PathBuf::from(format!("/tmp/fcd{}-{n}", std::process::id())));
        let root = guard.to_path_buf();
        Self { guard, root }
    }

    /// containerd の bundle の形（`<root>/b/default/<id>`）の実ディレクトリ。
    fn bundle(&self, id: &str) -> PathBuf {
        let b = self.root.join("b").join("default").join(id);
        std::fs::create_dir_all(&b).unwrap();
        b
    }

    /// 本番（`scoped_root_path`）と同じ式の状態ルート `<xdg>/fandhe-container-shim-state/<fnv1a(address)>/default`。
    fn scoped_root(&self) -> PathBuf {
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for b in ADDRESS.as_bytes() {
            h ^= u64::from(*b);
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
        self.guard
            .join("fandhe-container-shim-state")
            .join(format!("{h:016x}"))
            .join("default")
    }

    /// 記録用のストアを開く（階層は 0700 で 1 つずつ作る）。
    fn store(&self) -> FileStateStore {
        let path = self.scoped_root();
        let mut cur = self.root.clone();
        for part in path.strip_prefix(&self.root).unwrap().components() {
            cur.push(part);
            let _ = std::fs::DirBuilder::new().mode(0o700).create(&cur);
        }
        FileStateStore::open(StateRoot::from_override(path).unwrap()).unwrap()
    }

    fn seed(&self, store: &FileStateStore, status: ContainerStatus) {
        let bundle = self.bundle(status.id().as_str());
        store
            .create(&CreateStateRequest::new(status, bundle).unwrap())
            .unwrap();
    }

    /// delete を実バイナリで実行する（期限つき）。
    fn delete(&self, id: &str) -> Output {
        self.delete_at(id, &self.bundle(id))
    }

    /// `-bundle` を指定して delete を実バイナリで実行する（期限つき）。
    fn delete_at(&self, id: &str, bundle: &Path) -> Output {
        let mut cmd = Command::new(BIN);
        cmd.args(["-namespace", "default", "-address", ADDRESS])
            .args(["-publish-binary", BIN, "-id", id, "-bundle"])
            .arg(bundle)
            .arg("delete")
            .env("XDG_RUNTIME_DIR", &self.root)
            .env("FANDHE_CONTAINER_SHIM_SOCKET_DIR", self.root.join("s"))
            .current_dir(&self.root)
            .stdin(Stdio::null());
        reap::output_within(&mut cmd, Duration::from_secs(30))
            .expect("shim delete must exit within the limit")
    }

    /// bin の `start` を実行し、デーモンの socket のパスを返す（期限つき）。
    fn start(&self, id: &str) -> PathBuf {
        let mut cmd = Command::new(BIN);
        cmd.args(["-namespace", "default", "-address", ADDRESS])
            .args(["-publish-binary", BIN, "-id", id, "start"])
            .env("XDG_RUNTIME_DIR", &self.root)
            .env("FANDHE_CONTAINER_SHIM_SOCKET_DIR", self.root.join("s"))
            .current_dir(&self.root)
            .stdin(Stdio::null());
        let out = reap::output_within(&mut cmd, Duration::from_secs(30))
            .expect("shim start must exit within the limit");
        assert!(out.status.success(), "{out:?}");
        let addr = String::from_utf8(out.stdout).expect("utf8 address");
        PathBuf::from(
            addr.trim_end()
                .strip_prefix("unix://")
                .expect("unix:// address"),
        )
    }

    /// Create に渡せる最小の bundle（`<root>/b/default/<id>` に rootfs と config.json を作る）。
    fn make_bundle(&self, id: &str) -> PathBuf {
        let b = self.bundle(id);
        std::fs::create_dir_all(b.join("rootfs")).unwrap();
        std::fs::write(
            b.join("config.json"),
            r#"{"ociVersion":"1.2.0","root":{"path":"rootfs"},"process":{"user":{"uid":0,"gid":0},"args":["/bin/true"],"cwd":"/"},"linux":{"namespaces":[{"type":"pid"},{"type":"mount"},{"type":"user"},{"type":"uts"},{"type":"ipc"}]}}"#,
        )
        .unwrap();
        b
    }
}

/// `-id <id>` を持つ shim バイナリのプロセス（デーモンと fork した監査 helper）の PID を `/proc` から集める。
/// 記録の pid ではなく cmdline の一致だけで絞る（無関係なプロセスへ送らない。SEC-1）。
fn daemon_pids(id: &str) -> Vec<u32> {
    let needle = format!("-id\0{id}\0");
    let Ok(rd) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };
    rd.flatten()
        .filter_map(|e| {
            let pid: u32 = e.file_name().to_str()?.parse().ok()?;
            let c = std::fs::read(e.path().join("cmdline")).ok()?;
            let s = String::from_utf8_lossy(&c).into_owned();
            (s.contains(BIN) && s.contains(&needle)).then_some(pid)
        })
        .collect()
}

/// デーモンを SIGKILL で止め（containerd の「shim が死んだ」に最も近い）、期限内に消えたことを確かめる。
fn kill_daemon(id: &str) {
    let pids = daemon_pids(id);
    assert!(!pids.is_empty(), "daemon for {id} must be running");
    for pid in &pids {
        let mut cmd = Command::new("kill");
        cmd.args(["-s", "KILL", &pid.to_string()])
            .stderr(Stdio::null());
        let _ = reap::run_within(&mut cmd, Duration::from_secs(10));
    }
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while !daemon_pids(id).is_empty() && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(daemon_pids(id).is_empty(), "daemon for {id} must be gone");
}

fn cid(s: &str) -> ContainerId {
    ContainerId::new(s).unwrap()
}

fn recorded(store: &FileStateStore, id: &str) -> bool {
    store.get(&GetStateRequest::new(cid(id))).is_ok()
}

/// 状態ルートの記録の id の一覧。
fn ids(store: &FileStateStore) -> Vec<String> {
    let mut v: Vec<String> = store
        .list(&ListStateRequest::new(std::num::NonZeroU32::new(100).unwrap()).unwrap())
        .unwrap()
        .records()
        .iter()
        .map(|r| r.status().id().as_str().to_owned())
        .collect();
    v.sort();
    v
}

/// protobuf の varint を 1 つ読む。
fn varint(b: &[u8], i: &mut usize) -> u64 {
    let (mut v, mut shift) = (0u64, 0);
    loop {
        let byte = b[*i];
        *i += 1;
        v |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return v;
        }
        shift += 7;
    }
}

/// `DeleteResponse { pid = 1; exit_status = 2; exited_at = 3(Timestamp { seconds = 1; nanos = 2 }) }` の復号結果。
#[derive(Debug, PartialEq)]
struct Decoded {
    pid: u64,
    exit_status: u64,
    exited_at: Option<(u64, u64)>,
}

fn decode(buf: &[u8]) -> Decoded {
    let mut d = Decoded {
        pid: 0,
        exit_status: 0,
        exited_at: None,
    };
    let mut i = 0;
    while i < buf.len() {
        let tag = varint(buf, &mut i);
        match tag {
            0x08 => d.pid = varint(buf, &mut i),
            0x10 => d.exit_status = varint(buf, &mut i),
            0x1a => {
                let len = varint(buf, &mut i) as usize;
                let inner = &buf[i..i + len];
                i += len;
                let (mut j, mut secs, mut nanos) = (0, 0, 0);
                while j < inner.len() {
                    match varint(inner, &mut j) {
                        0x08 => secs = varint(inner, &mut j),
                        0x10 => nanos = varint(inner, &mut j),
                        t => panic!("unexpected timestamp tag {t:#x}"),
                    }
                }
                d.exited_at = Some((secs, nanos));
            }
            t => panic!("unexpected tag {t:#x}"),
        }
    }
    d
}

/// 成功の条件は終了コード 0 と stdout の protobuf。stderr は後始末の警告（`container_delete_cleanup`・
/// `shim_delete_warnings_unflushed`。いずれも 1 行の JSON で `"level":"warn"`）だけを許し、それ以外の行があれば失敗にする
/// （delete の契約は後始末の警告を stderr に許容する。REPAIR-4）。
fn assert_success(out: &Output) {
    assert!(out.status.success(), "{out:?}");
    let stderr = String::from_utf8(out.stderr.clone()).expect("stderr must be UTF-8");
    for line in stderr.lines() {
        let allowed = line
            .starts_with("{\"level\":\"warn\",\"event\":\"container_delete_cleanup\",")
            || line
                .starts_with("{\"level\":\"warn\",\"event\":\"shim_delete_warnings_unflushed\",");
        assert!(allowed, "unexpected stderr line: {line:?}");
    }
}

/// CRI-5・TASK-62.6・#4152: Stopped で記録された終了コード・`exited_at` が stdout の DeleteResponse と一致し、
/// 記録が消え、他のコンテナの記録には触れない。再実行は固定の冪等な応答（137）で、記録は増減しない。
#[test]
fn cri5_4152_bin_delete_reclaims_stopped_record_with_recorded_exit_state() {
    let sc = Scratch::new();
    let store = sc.store();
    let at = ExitTime::from_unix_nanos(1_700_000_000_123_456_789).unwrap();
    sc.seed(
        &store,
        ContainerStatus::stopped_at(cid("stopped1"), Some(7), Some(at)),
    );
    sc.seed(&store, ContainerStatus::created(cid("other"), None));

    let out = sc.delete("stopped1");
    assert_success(&out);
    assert_eq!(
        decode(&out.stdout),
        Decoded {
            pid: 0,
            exit_status: 7,
            exited_at: Some((1_700_000_000, 123_456_789)),
        }
    );
    assert!(!recorded(&store, "stopped1"));
    assert_eq!(ids(&store), vec!["other".to_owned()]);

    // 再実行（回収済み）は固定の応答。終了状態は記録に依らず 137・exited_at あり。他の記録は残る。
    let again = sc.delete("stopped1");
    assert_success(&again);
    let d = decode(&again.stdout);
    assert_eq!((d.pid, d.exit_status), (0, IDEMPOTENT_EXIT));
    assert!(d.exited_at.is_some());
    assert_eq!(ids(&store), vec!["other".to_owned()]);
}

/// CRI-5・TASK-62.6・#4152: PID の無い Created は停止せず回収され、終了コード 0。2 回目は冪等な 137。
#[test]
fn cri5_4152_bin_delete_reclaims_pidless_created_then_is_idempotent() {
    let sc = Scratch::new();
    let store = sc.store();
    sc.seed(&store, ContainerStatus::created(cid("created1"), None));

    let out = sc.delete("created1");
    assert_success(&out);
    let d = decode(&out.stdout);
    assert_eq!((d.pid, d.exit_status), (0, 0));
    assert!(!recorded(&store, "created1"));
    assert_eq!(ids(&store), Vec::<String>::new());

    for _ in 0..2 {
        let again = sc.delete("created1");
        assert_success(&again);
        let d = decode(&again.stdout);
        assert_eq!((d.pid, d.exit_status), (0, IDEMPOTENT_EXIT));
    }
}

/// CRI-5・#4152: 状態ルートが無い（記録が一度も作られていない）delete も成功し、固定の 137 を返して状態ルートを作らない。
#[test]
fn cri5_4152_bin_delete_without_state_root_is_idempotent_and_creates_nothing() {
    let sc = Scratch::new();
    let out = sc.delete("nothing");
    assert_success(&out);
    let d = decode(&out.stdout);
    assert_eq!((d.pid, d.exit_status), (0, IDEMPOTENT_EXIT));
    assert!(!Path::new(&sc.scoped_root()).exists());
    // 記録なし（NotRecorded）は副作用 0 回: 状態ルートの基底も作らず、後始末の警告も出さない（#4279）。
    assert!(!sc.guard.join("fandhe-container-shim-state").exists());
    assert_eq!(out.stderr, Vec::<u8>::new());
}

/// 状態ルート配下のエントリ名（相対パス）を再帰で集める（残骸の有無の照合に使う）。
fn tree(root: &Path) -> Vec<String> {
    fn walk(dir: &Path, root: &Path, out: &mut Vec<String>) {
        let Ok(rd) = std::fs::read_dir(dir) else {
            return;
        };
        for e in rd {
            let e = e.unwrap();
            out.push(
                e.path()
                    .strip_prefix(root)
                    .unwrap()
                    .to_string_lossy()
                    .into_owned(),
            );
            if e.file_type().unwrap().is_dir() {
                walk(&e.path(), root, out);
            }
        }
    }
    let mut v = Vec::new();
    walk(root, root, &mut v);
    v.sort();
    v
}

/// 起動オプション文書を置く（残骸の 1 種。作成世代つき）。
fn put_options(root: &Path, id: &str) {
    use fandhe_container_supervisor::container_options::document::ContainerOptionsDocument;
    let doc = ContainerOptionsDocument::new(
        vec!["nofile=1024:2048".into()],
        vec!["A=1".into()],
        None,
        None,
        vec![],
    )
    .unwrap()
    .with_generation("g1".to_owned())
    .unwrap();
    fandhe_container_supervisor::container_options::store::write_new(root, &cid(id), &doc).unwrap();
}

/// コンテナログの sink を開いて 1 行書く（drop するとファイルが残骸になる）。
fn open_container_sink(
    root: &Path,
    id: &str,
) -> fandhe_container_supervisor::logs::RotatingFileSink {
    use fandhe_container_supervisor::logs::{
        LogSink as _, RotatingFileSink, StreamKind, container_log_dir,
        container_log_rotation_config,
    };
    let dir = container_log_dir(root);
    let _ = std::fs::DirBuilder::new().mode(0o700).create(&dir);
    let sink = RotatingFileSink::open(&dir, &cid(id), container_log_rotation_config()).unwrap();
    sink.append(StreamKind::Stdout, b"x").unwrap();
    sink.flush().unwrap();
    sink
}

/// `id` の名前（`<id>` そのもの、または `<id>.` 始まり）を含むエントリ。
fn of_id(entries: &[String], id: &str) -> Vec<String> {
    let dotted = format!("{id}.");
    entries
        .iter()
        .filter(|e| {
            let leaf = e.rsplit('/').next().unwrap();
            leaf == id || leaf.starts_with(&dotted)
        })
        .cloned()
        .collect()
}

/// CRI-5・REPAIR-4・REPAIR-5・OCI-7・SUP-7・SUP-12・#4279: 後始末（ログ・起動オプション文書）が中断した delete の次の delete
/// （`AlreadyReclaimed`）で、その ID の残骸 3 種が消える。固定の応答（137）のまま、別 ID の記録・残骸には触れず、
/// 3 回目は状態ルートの木を変えない。
#[test]
fn cri5_4279_bin_delete_reclaims_leftovers_after_interrupted_cleanup() {
    use fandhe_container_supervisor::container_options::store as options_store;
    let sc = Scratch::new();
    let store = sc.store();
    let root = sc.scoped_root();
    let at = ExitTime::from_unix_nanos(1_700_000_000_123_456_789).unwrap();
    sc.seed(
        &store,
        ContainerStatus::stopped_at(cid("abc"), Some(7), Some(at)),
    );
    sc.seed(&store, ContainerStatus::created(cid("abcd"), None));
    // 別 ID（前方一致）の残骸。
    drop(fandhe_container_supervisor::supervisor_log::open(&root, &cid("abcd")).unwrap());
    drop(open_container_sink(&root, "abcd"));
    put_options(&root, "abcd");
    // abc の 3 種のロックを試験プロセスが保持し、1 回目の後始末を中断させる（待ちの期限まで解放されない）。
    let sup = fandhe_container_supervisor::supervisor_log::open(&root, &cid("abc")).unwrap();
    let sink = open_container_sink(&root, "abc");
    put_options(&root, "abc");
    let lock = options_store::acquire_lock(&root, &cid("abc"), Duration::from_secs(5)).unwrap();

    let first = sc.delete("abc");
    assert_success(&first);
    let d = decode(&first.stdout);
    assert_eq!((d.pid, d.exit_status), (0, 7));
    assert!(!recorded(&store, "abc"));
    assert!(recorded(&store, "abcd"));
    let after_first = tree(&root);
    assert!(
        !of_id(&after_first, "abc").is_empty(),
        "leftovers must remain: {after_first:?}"
    );
    drop((sup, sink, lock));

    // 2 回目（回収済み）: 固定の応答で、abc の残骸 3 種だけが消える。警告は出ない。
    let second = sc.delete("abc");
    assert_success(&second);
    let d = decode(&second.stdout);
    assert_eq!((d.pid, d.exit_status), (0, IDEMPOTENT_EXIT));
    assert!(d.exited_at.is_some());
    assert_eq!(second.stderr, Vec::<u8>::new());
    let after_second = tree(&root);
    assert_eq!(of_id(&after_second, "abc"), Vec::<String>::new());
    assert!(of_id(&after_second, "abcd").len() >= 4, "{after_second:?}");
    assert_eq!(ids(&store), vec!["abcd".to_owned()]);

    // 3 回目: 固定の応答で、状態ルートの木は変わらない。
    let third = sc.delete("abc");
    assert_success(&third);
    assert_eq!(decode(&third.stdout).exit_status, IDEMPOTENT_EXIT);
    assert_eq!(tree(&root), after_second);
}

/// SUP-7・REPAIR-4・#4279: 生きている sink のログは `AlreadyReclaimed` でも消さない（待たずに警告行を 1 件出す）。
/// 他の 2 種は消える。
#[test]
fn sup7_cri5_4279_bin_delete_keeps_leftovers_of_live_sink() {
    let sc = Scratch::new();
    let store = sc.store();
    let root = sc.scoped_root();
    sc.seed(&store, ContainerStatus::created(cid("other"), None));
    let sup = fandhe_container_supervisor::supervisor_log::open(&root, &cid("abc")).unwrap();
    drop(open_container_sink(&root, "abc"));
    put_options(&root, "abc");

    let out = sc.delete("abc");
    assert_success(&out);
    assert_eq!(decode(&out.stdout).exit_status, IDEMPOTENT_EXIT);
    let t = tree(&root);
    assert!(t.contains(&"@supervisor-logs/abc.log".to_owned()), "{t:?}");
    assert_eq!(
        of_id(&t, "abc")
            .iter()
            .filter(|e| !e.starts_with("@supervisor-logs/"))
            .count(),
        0,
        "{t:?}"
    );
    let stderr = String::from_utf8(out.stderr).unwrap();
    let hits: Vec<&str> = stderr
        .lines()
        .filter(|l| {
            l.contains("\"target\":\"supervisor_log\",\"code\":\"FAILED_PRECONDITION\",\"reason\":\"sink_open_after_wait\"")
        })
        .collect();
    assert_eq!(hits.len(), 1, "{stderr}");
    drop(sup);
}

/// 失敗の契約: 非ゼロ終了・stdout は空・stderr は JSON 1 行で `code` と空でない `message`。
fn assert_failed(out: &Output, code: &str) {
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    assert_eq!(out.stdout, b"");
    let err = String::from_utf8(out.stderr.clone()).unwrap();
    assert_eq!(err.lines().count(), 1, "{err}");
    let v = mini_json::parse(err.trim_end()).unwrap_or_else(|| panic!("invalid JSON: {err}"));
    assert_eq!(v.get("code").and_then(|x| x.as_str()), Some(code), "{err}");
    assert!(
        v.get("message")
            .and_then(|x| x.as_str())
            .is_some_and(|m| !m.is_empty()),
        "{err}"
    );
}

/// CRI-5・TASK-62.6・#4153: 本物の `start` と ttrpc の `Create` で作った Created のコンテナについて、
/// デーモンが居なくなった後の `delete`（containerd が shim の死後に呼ぶ形）が実行層まで回収し、
/// 終了コード 0・pid 0・終了状態 0 を返して状態ルートの `<id>` を消し、残った socket も消す。
/// 2 回目は終了コード 0 の固定の応答（137・exited_at あり）で、状態ルートが無い場合の応答と欄が一致する。
/// 記録の bundle と食い違う `-bundle`・不正な id は、記録に触れず構造化エラーで拒否する（SEC-1）。
#[test]
fn cri5_4153_bin_delete_after_daemon_death_reclaims_created_container() {
    for (n, svc) in ["containerd.task.v2.Task", "containerd.task.v3.Task"]
        .iter()
        .enumerate()
    {
        let sc = Scratch::new();
        let id = format!("d4153x{}n{n}", std::process::id());
        let sock = sc.start(&id);
        let bundle = sc.make_bundle(&id);
        let b = bundle.to_str().expect("utf8 bundle");
        let create =
            shim_wire::call_method(&sock, svc, "Create", &shim_wire::create_request(&id, b))
                .expect("Create must succeed");
        assert_eq!(create.status, None, "{svc}");
        let st = shim_wire::call_method(&sock, svc, "State", &shim_wire::id_request(&id))
            .expect("State must succeed");
        let f = shim_wire::decode_state_response(&st.payload).expect("StateResponse");
        assert_eq!(
            (f.id.as_str(), f.status, f.pid),
            (id.as_str(), 1, 0),
            "{svc}"
        );
        let record_dir = sc.scoped_root().join(&id);
        assert!(record_dir.join("state.json").is_file(), "{svc}");

        kill_daemon(&id);
        assert!(sock.exists(), "SIGKILL leaves the stale socket behind");

        // 記録の bundle と違う実在の bundle・不正な id は拒否し、記録は残る。
        let other = sc.root.join("b2").join("default").join(&id);
        std::fs::create_dir_all(&other).unwrap();
        assert_failed(&sc.delete_at(&id, &other), "FAILED_PRECONDITION");
        assert!(
            record_dir.join("state.json").is_file(),
            "mismatch must not reclaim"
        );
        let bad = sc.root.join("b").join("default").join("a");
        std::fs::create_dir_all(&bad).unwrap();
        let mut cmd = Command::new(BIN);
        cmd.args(["-namespace", "default", "-address", ADDRESS])
            .args(["-publish-binary", BIN, "-id", "a/b", "-bundle"])
            .arg(&bad)
            .arg("delete")
            .env("XDG_RUNTIME_DIR", &sc.root)
            .env("FANDHE_CONTAINER_SHIM_SOCKET_DIR", sc.root.join("s"))
            .current_dir(&sc.root)
            .stdin(Stdio::null());
        let out = reap::output_within(&mut cmd, Duration::from_secs(30)).expect("exit");
        assert_failed(&out, "INVALID_ARGUMENT");
        assert!(
            record_dir.join("state.json").is_file(),
            "invalid id must not reclaim"
        );

        let out = sc.delete_at(&id, &bundle);
        assert_success(&out);
        let first = decode(&out.stdout);
        assert_eq!(
            first,
            Decoded {
                pid: 0,
                exit_status: 0,
                exited_at: None,
            },
            "{svc}"
        );
        assert!(!record_dir.exists(), "{svc}: record dir must be removed");
        assert!(!sock.exists(), "{svc}: stale socket must be removed");

        // 2 回目: 終了コード 0 の固定の応答。`exited_at` は「今」の時刻で毎回違うため値ではなく欄の有無で比べる。
        let again = sc.delete_at(&id, &bundle);
        assert_success(&again);
        let second = decode(&again.stdout);
        assert_eq!(
            (second.pid, second.exit_status, second.exited_at.is_some()),
            (0, IDEMPOTENT_EXIT, true),
            "{svc}"
        );

        // 状態ルートが一度も作られていない場合の応答と、欄ごとに同じ形になる。
        let fresh = Scratch::new();
        let baseline = fresh.delete(&id);
        assert_success(&baseline);
        let base = decode(&baseline.stdout);
        assert_eq!(
            (base.pid, base.exit_status, base.exited_at.is_some()),
            (second.pid, second.exit_status, second.exited_at.is_some()),
            "{svc}"
        );
    }
}

/// CRI-5・SUP-7・REPAIR-4・REPAIR-5・#4280: serve の起動時の走査で、記録の無い ID の閉じたコンテナログだけが消える。
/// 記録のある ID と生きている sink のログは残り、`daemon.log` の要約行にパス・ID は含まれない。
#[test]
fn cri5_sup7_4280_bin_serve_sweeps_unrecorded_container_logs() {
    use fandhe_container_supervisor::logs::container_log_dir;
    let sc = Scratch::new();
    let store = sc.store();
    let root = sc.scoped_root();
    sc.seed(&store, ContainerStatus::created(cid("present1"), None));
    drop(open_container_sink(&root, "present1"));
    drop(open_container_sink(&root, "closed1"));
    drop(open_container_sink(&root, "closed2"));
    let _live = open_container_sink(&root, "live1");

    let id = format!("sw{}", std::process::id());
    let _sock = sc.start(&id);

    // 要約行を期限つきで待つ。
    let log = sc.root.join("s").join("daemon.log");
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let mut text = String::new();
    while std::time::Instant::now() < deadline {
        text = std::fs::read_to_string(&log).unwrap_or_default();
        if text.contains(r#""event":"op_stats_meta""#) {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let lines: Vec<&str> = text
        .lines()
        .filter(|l| l.contains(r#""event":"container_log_sweep""#))
        .collect();
    assert_eq!(lines.len(), 1, "{text}");
    assert!(lines[0].contains(r#""reclaimed_ids":2"#), "{}", lines[0]);
    assert!(lines[0].contains(r#""skipped_live":1"#), "{}", lines[0]);
    assert!(lines[0].contains(r#""skipped_present":1"#), "{}", lines[0]);
    assert!(!lines[0].contains("closed1"), "{}", lines[0]);
    assert!(
        !lines[0].contains(sc.root.to_str().unwrap()),
        "{}",
        lines[0]
    );

    // 書き出された記録器の計数（#4319）。ID・パスは含まない。
    let stats: Vec<&str> = text
        .lines()
        .filter(|l| l.contains(r#""op":"container_log_reclaim""#))
        .collect();
    assert_eq!(stats.len(), 1, "{text}");
    assert!(
        stats[0].contains(r#""success":2,"failure":0,"count":2"#),
        "{}",
        stats[0]
    );
    assert!(!stats[0].contains("closed"), "{}", stats[0]);
    assert!(
        !stats[0].contains(sc.root.to_str().unwrap()),
        "{}",
        stats[0]
    );
    assert!(text.contains(r#""event":"op_stats_meta""#), "{text}");

    let mut left: Vec<String> = std::fs::read_dir(container_log_dir(&root))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    left.sort();
    assert_eq!(left, ["live1.log", "live1.log.lock", "present1.log"]);

    kill_daemon(&id);
}
