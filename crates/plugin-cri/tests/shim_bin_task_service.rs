//! 配布する shim バイナリ（`containerd-shim-fandhe-container-v2`）が本番の `TaskService` を登録していることの結合試験
//! （CRI-5・CRI-7・PLUG-1・TASK-62.6・#3684）。
//!
//! bin を `start` で起動し、stdout のアドレスへ ttrpc で接続して v2・v3 の State・Kill・Create・Delete・Shutdown が
//! 実行層まで届くことを具体値で照合する。以前の bin は `EmptyTaskService`（Shutdown 以外は `UNIMPLEMENTED`=12）だけを
//! 登録していたため、`NOT_FOUND`(5) や `CREATED` が返ること自体が配線の証拠になる。Linux 限定・root 不要・supervisor 不要
//! （Start は呼ばない。実コンテナの通しは実機前提の `shim_v2_containerd_real`）で、既定のテスト集合に入る。
//! exec の起動役の配線（#4149）も照合する（存在しないコンテナへの Exec が `NOT_FOUND`、Created への Exec が `FAILED_PRECONDITION`。
//! 起動役が無ければ `UNIMPLEMENTED`=12）。
//! ttrpc の手組みは `support/shim_wire.rs`（prost を plugin-cri の依存に足さない）。

#![cfg(target_os = "linux")]

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use shim_wire::{
    Resp, call_method, create_request, decode_delete_response, decode_state_response,
    exec_id_request, exec_request, id_request, kill_request, shutdown_request,
};

#[path = "../../core/tests/support/reap.rs"]
mod reap;
#[path = "support/shim_wire.rs"]
mod shim_wire;
#[path = "../../oci/tests/support/test_root.rs"]
mod test_root;

const BIN: &str = env!("CARGO_BIN_EXE_containerd-shim-fandhe-container-v2");
const NOT_FOUND: i32 = 5;
const FAILED_PRECONDITION: i32 = 9;
const MIN_SPEC: &str = r#"{"cwd":"/","args":["/bin/true"]}"#;
const STATUS_CREATED: u32 = 1;
const SERVICES: [&str; 2] = ["containerd.task.v2.Task", "containerd.task.v3.Task"];
/// 子の実行・待ちの期限（REPAIR-5）。
const LIMIT: Duration = Duration::from_secs(30);

/// 試験用ディレクトリ（sun_path の制約のため短い /tmp 直下に 0700 で排他作成する）。Drop で消す。
struct Scratch {
    guard: test_root::TestRoot,
}

impl Scratch {
    fn new(tag: &str) -> Self {
        Self {
            guard: test_root::test_root_at(PathBuf::from(format!(
                "/tmp/fcb{}-{tag}",
                std::process::id()
            ))),
        }
    }
    fn sock_dir(&self) -> PathBuf {
        self.guard.join("s")
    }
}

/// `-publish-binary` を差し替えられる `run`（#4222。既定は bin 自身で、検査を通すだけの値）。
fn run_with_publish(
    sc: &Scratch,
    id: &str,
    action: &str,
    extra: &[&str],
    publish_binary: &str,
) -> std::process::Output {
    let mut cmd = Command::new(BIN);
    cmd.args([
        "-namespace",
        "default",
        "-address",
        "/run/containerd/containerd.sock",
        "-publish-binary",
        publish_binary,
        "-id",
        id,
    ])
    .args(extra)
    .arg(action)
    .env("FANDHE_CONTAINER_SHIM_SOCKET_DIR", sc.sock_dir())
    // 状態ルートを試験ごとに隔離する（`StateRoot::resolve(None)` が XDG_RUNTIME_DIR 配下を使う）。
    .env("XDG_RUNTIME_DIR", &*sc.guard)
    .current_dir(&*sc.guard)
    .stdin(Stdio::null());
    reap::output_within(&mut cmd, LIMIT).expect("shim child must exit within the limit")
}

fn start(sc: &Scratch, id: &str) -> PathBuf {
    start_with_publish(sc, id, BIN)
}

fn start_with_publish(sc: &Scratch, id: &str, publish_binary: &str) -> PathBuf {
    let out = run_with_publish(sc, id, "start", &[], publish_binary);
    assert!(out.status.success(), "{out:?}");
    let addr = String::from_utf8(out.stdout).expect("utf8 address");
    PathBuf::from(addr.strip_prefix("unix://").expect("unix:// address"))
}

fn make_bundle(sc: &Scratch) -> PathBuf {
    let bundle = sc.guard.join("bundle");
    std::fs::create_dir(&bundle).expect("bundle");
    std::fs::create_dir(bundle.join("rootfs")).expect("rootfs");
    std::fs::write(
        bundle.join("config.json"),
        r#"{"ociVersion":"1.2.0","root":{"path":"rootfs"},"process":{"user":{"uid":0,"gid":0},"args":["/bin/true"],"cwd":"/"},"linux":{"namespaces":[{"type":"pid"},{"type":"mount"},{"type":"user"},{"type":"uts"},{"type":"ipc"}]}}"#,
    )
    .expect("config");
    bundle
}

fn ok(r: Result<Resp, String>, what: &str) -> Resp {
    let r = r.unwrap_or_else(|e| panic!("{what}: {e}"));
    assert!(r.status.is_none(), "{what}: {:?}", r.status);
    r
}

fn code(r: Result<Resp, String>, what: &str) -> i32 {
    r.unwrap_or_else(|e| panic!("{what}: {e}"))
        .status
        .unwrap_or_else(|| panic!("{what}: expected an error status"))
        .0
}

/// CRI-5・CRI-7・#3684: 配布する bin 経由で、未知の id の State と Kill が実行層まで届いて `NOT_FOUND` になる
/// （以前の `EmptyTaskService` なら `UNIMPLEMENTED`）。
#[test]
fn cri5_3684_bin_reaches_state_and_kill() {
    let sc = Scratch::new("sk");
    let id = format!("sk{}", std::process::id());
    let sock = start(&sc, &id);
    for svc in SERVICES {
        assert_eq!(
            code(
                call_method(&sock, svc, "State", &id_request("nope")),
                "State"
            ),
            NOT_FOUND,
            "{svc}"
        );
        assert_eq!(
            code(
                call_method(&sock, svc, "Kill", &kill_request("nope", 9, true)),
                "Kill"
            ),
            NOT_FOUND,
            "{svc}"
        );
    }
    shutdown_and_wait(&sock, &id);
}

/// CRI-5・CRI-7・#3684: Create が実行層へ届き、続く State が `CREATED` で pid 0、Delete 後は `NOT_FOUND`。
/// Shutdown でデーモンが終わり socket が消える。
#[test]
fn cri5_3684_bin_create_state_delete_shutdown() {
    let sc = Scratch::new("cd");
    let id = format!("cd{}", std::process::id());
    let sock = start(&sc, &id);
    let bundle = make_bundle(&sc);
    let bundle = bundle.to_str().expect("utf8 bundle");
    for (i, svc) in SERVICES.iter().enumerate() {
        // v2 と v3 は同じ実行層・同じ状態ルートを共有するので、1 つ目で作って消してから 2 つ目で同じ id を作る。
        let create = ok(
            call_method(&sock, svc, "Create", &create_request(&id, bundle)),
            "Create",
        );
        let _ = create;
        let st = ok(
            call_method(&sock, svc, "State", &id_request(&id)),
            "State after create",
        );
        let f = decode_state_response(&st.payload).expect("StateResponse");
        assert_eq!(
            (f.id.as_str(), f.status, f.pid),
            (id.as_str(), STATUS_CREATED, 0),
            "{svc}"
        );
        let del = ok(
            call_method(&sock, svc, "Delete", &id_request(&id)),
            "Delete",
        );
        assert!(decode_delete_response(&del.payload).is_some(), "{svc} #{i}");
        assert_eq!(
            code(call_method(&sock, svc, "State", &id_request(&id)), "State"),
            NOT_FOUND,
            "{svc} after delete"
        );
    }
    shutdown_and_wait(&sock, &id);
}

/// CRI-5・CRI-1・#4149: bin の v2・v3 に exec の起動役が配線され、存在しないコンテナへの Exec・Start(exec_id)・State(exec_id) が
/// `NOT_FOUND`(5) になる（起動役が無ければ Exec は `UNIMPLEMENTED`=12）。
#[test]
fn cri5_4149_bin_exec_reaches_launcher() {
    let sc = Scratch::new("ex");
    let id = format!("ex{}", std::process::id());
    let sock = start(&sc, &id);
    for svc in SERVICES {
        assert_eq!(
            code(
                call_method(&sock, svc, "Exec", &exec_request("nope", "e1", MIN_SPEC)),
                "Exec"
            ),
            NOT_FOUND,
            "{svc} Exec"
        );
        assert_eq!(
            code(
                call_method(&sock, svc, "Start", &exec_id_request("nope", "e1")),
                "Start"
            ),
            NOT_FOUND,
            "{svc} Start"
        );
        assert_eq!(
            code(
                call_method(&sock, svc, "State", &exec_id_request("nope", "e1")),
                "State"
            ),
            NOT_FOUND,
            "{svc} State"
        );
    }
    shutdown_and_wait(&sock, &id);
}

/// CRI-5・CRI-1・#4149: Created のコンテナへの Exec は `FAILED_PRECONDITION`(9) "container is not running"。
#[test]
fn cri5_4149_bin_exec_on_created_container_is_failed_precondition() {
    let sc = Scratch::new("ec");
    let id = format!("ec{}", std::process::id());
    let sock = start(&sc, &id);
    let bundle = make_bundle(&sc);
    let bundle = bundle.to_str().expect("utf8 bundle");
    for svc in SERVICES {
        ok(
            call_method(&sock, svc, "Create", &create_request(&id, bundle)),
            "Create",
        );
        let r = call_method(&sock, svc, "Exec", &exec_request(&id, "e1", MIN_SPEC))
            .unwrap_or_else(|e| panic!("Exec: {e}"));
        assert_eq!(
            r.status,
            Some((FAILED_PRECONDITION, "container is not running".to_owned())),
            "{svc}"
        );
        ok(
            call_method(&sock, svc, "Delete", &id_request(&id)),
            "Delete",
        );
    }
    shutdown_and_wait(&sock, &id);
}

/// Shutdown RPC を送り、期限内に socket が消える（デーモンが終わる）ことを確かめる。
fn shutdown_and_wait(sock: &std::path::Path, id: &str) {
    let r = ok(
        call_method(sock, SERVICES[0], "Shutdown", &shutdown_request(id, false)),
        "Shutdown",
    );
    assert!(r.payload.is_empty());
    let deadline = Instant::now() + LIMIT;
    while sock.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(!sock.exists(), "socket must be removed after shutdown");
}

/// CRI-5・TASK-62.6・REPAIR-5・#4222: bin の Shutdown の後、キューに残った TaskDelete が排出されて publish バイナリへ届く。
/// 偽の publish バイナリは `/tasks/create` だけ 1 秒眠るため、Delete と Shutdown の時点で TaskDelete は未送信のキューにある。
/// 排出が無ければ、デーモンは応答の猶予の後に終わり、TaskDelete の子は一度も起動しない。
/// `daemon.log` に排出の 1 行（`complete`・捨てた件数 0）が残る。
#[test]
fn cri5_4222_bin_shutdown_drains_queued_task_delete() {
    let sc = Scratch::new("dr");
    let id = format!("dr{}", std::process::id());
    let out = sc.guard.join("calls");
    std::fs::create_dir(&out).expect("calls dir");
    let body = format!(
        "#!/bin/sh\ncase \"$*\" in *tasks/create*) /bin/sleep 1;; esac\nn=$(( $(/bin/ls \"{o}\" | /usr/bin/wc -l) ))\nd=\"{o}/call$n\"\n/bin/mkdir \"$d\"\nprintf '%s\\n' \"$@\" > \"$d/argv\"\n/bin/cat > \"$d/stdin\"\n",
        o = out.display()
    );
    let script = sc.guard.join("fake-publish");
    // ETXTBSY を避けるため、書き込みと chmod は子プロセスで行う。
    let st = Command::new("/bin/sh")
        .arg("-c")
        .arg(r#"printf '%s' "$1" > "$2" && chmod 755 "$2""#)
        .arg("sh")
        .arg(&body)
        .arg(&script)
        .status()
        .expect("run sh");
    assert!(st.success());
    let script = script.to_str().expect("utf8 script").to_owned();

    let sock = start_with_publish(&sc, &id, &script);
    let bundle = make_bundle(&sc);
    let bundle = bundle.to_str().expect("utf8 bundle");
    ok(
        call_method(&sock, SERVICES[0], "Create", &create_request(&id, bundle)),
        "Create",
    );
    ok(
        call_method(&sock, SERVICES[0], "Delete", &id_request(&id)),
        "Delete",
    );
    shutdown_and_wait(&sock, &id);

    // 排出の 1 行（排出の完了の後に書かれる）を待ち、その時点で TaskDelete が届いていること。
    let log = sc.sock_dir().join("daemon.log");
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut text = String::new();
    while Instant::now() < deadline {
        text = std::fs::read_to_string(&log).unwrap_or_default();
        if text.contains("task_event_publish_drain") {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let lines: Vec<&str> = text
        .lines()
        .filter(|l| l.contains(r#""event":"task_event_publish_drain""#))
        .collect();
    assert_eq!(lines.len(), 1, "{text}");
    assert!(lines[0].contains(r#""outcome":"complete""#), "{}", lines[0]);
    assert!(lines[0].contains(r#""dropped":0"#), "{}", lines[0]);
    let topics: Vec<String> = std::fs::read_dir(&out)
        .expect("calls")
        .map(|e| {
            let argv = std::fs::read_to_string(e.expect("entry").path().join("argv"))
                .expect("argv of a completed call");
            argv.lines().last().unwrap_or_default().to_owned()
        })
        .collect();
    let mut sorted = topics.clone();
    sorted.sort();
    assert_eq!(sorted, ["/tasks/create", "/tasks/delete"], "{topics:?}");
}

/// `op_stats` の行から時間の欄（`min_us` 以降）を除いた前半を返す（時間は実行ごとに揺れるため照合しない）。
fn op_stats_head(line: &str) -> &str {
    line.split(r#","min_us""#).next().unwrap_or(line)
}

/// CRI-5・REPAIR-4・REPAIR-5・#4408: serve の終了（Shutdown RPC）の後、`daemon.log` に共有記録器の操作統計が `op_stats` 行と
/// `op_stats_meta` 行の組で 1 回だけ出る。本番の bootstrap・`TtrpcServer` が終了後に登録簿の参照を解放し、プロセスの終了前に
/// 書き出す接続の契約を、配布する bin で照合する（unit 試験は登録簿を直接 drop するため確かめない）。
/// 起動時の走査は回収が 0 件のとき何も出さないので、Shutdown の前に `op_stats` 行は無く、出た行はすべて終了時のもの。
#[test]
fn cri5_4408_bin_shutdown_writes_final_op_stats_once() {
    let sc = Scratch::new("os");
    let id = format!("os{}", std::process::id());
    let sock = start(&sc, &id);
    let log = sc.sock_dir().join("daemon.log");
    let bundle = make_bundle(&sc);
    let bundle = bundle.to_str().expect("utf8 bundle");
    ok(
        call_method(&sock, SERVICES[0], "Create", &create_request(&id, bundle)),
        "Create",
    );
    ok(
        call_method(&sock, SERVICES[0], "Delete", &id_request(&id)),
        "Delete",
    );
    // Shutdown の前には統計の行が無い（書き出しは終了時の 1 回だけ）。
    let before = std::fs::read_to_string(&log).unwrap_or_default();
    assert!(!before.contains(r#""event":"op_stats"#), "{before}");
    shutdown_and_wait(&sock, &id);

    // 書き出しは登録簿の解放（socket の消失の後、プロセスの終了前）に行われる。meta 行を待つ。
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut text = String::new();
    while Instant::now() < deadline {
        text = std::fs::read_to_string(&log).unwrap_or_default();
        if text.contains(r#""event":"op_stats_meta""#) {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let stats: Vec<&str> = text
        .lines()
        .filter(|l| l.contains(r#""event":"op_stats""#))
        .map(op_stats_head)
        .collect();
    assert_eq!(
        stats,
        [
            r#"{"event":"op_stats","op":"container_log_remove","success":1,"failure":0,"count":1"#,
            r#"{"event":"op_stats","op":"create","success":1,"failure":0,"count":1"#,
            r#"{"event":"op_stats","op":"delete","success":1,"failure":0,"count":1"#,
            r#"{"event":"op_stats","op":"supervisor_log_remove","success":1,"failure":0,"count":1"#,
        ],
        "{text}"
    );
    let metas: Vec<&str> = text
        .lines()
        .filter(|l| l.contains(r#""event":"op_stats_meta""#))
        .collect();
    assert_eq!(
        metas,
        [r#"{"event":"op_stats_meta","ops":4,"dropped_records":0}"#],
        "{text}"
    );
}
