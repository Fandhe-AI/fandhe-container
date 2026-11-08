//! 配布する shim バイナリ（`containerd-shim-fandhe-container-v2`）が本番の `TaskService` を登録していることの結合試験
//! （CRI-5・CRI-7・PLUG-1・TASK-62.6・#3684）。
//!
//! bin を `start` で起動し、stdout のアドレスへ ttrpc で接続して v2・v3 の State・Kill・Create・Delete・Shutdown が
//! 実行層まで届くことを具体値で照合する。以前の bin は `EmptyTaskService`（Shutdown 以外は `UNIMPLEMENTED`=12）だけを
//! 登録していたため、`NOT_FOUND`(5) や `CREATED` が返ること自体が配線の証拠になる。Linux 限定・root 不要・supervisor 不要
//! （Start は呼ばない。実コンテナの通しは実機前提の `shim_v2_containerd_real`）で、既定のテスト集合に入る。
//! ttrpc の手組みは `support/shim_wire.rs`（prost を plugin-cri の依存に足さない）。

#![cfg(target_os = "linux")]

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use shim_wire::{
    Resp, call_method, create_request, decode_delete_response, decode_state_response, id_request,
    kill_request, shutdown_request,
};

#[path = "../../core/tests/support/reap.rs"]
mod reap;
#[path = "support/shim_wire.rs"]
mod shim_wire;
#[path = "../../oci/tests/support/test_root.rs"]
mod test_root;

const BIN: &str = env!("CARGO_BIN_EXE_containerd-shim-fandhe-container-v2");
const NOT_FOUND: i32 = 5;
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

fn run(sc: &Scratch, id: &str, action: &str, extra: &[&str]) -> std::process::Output {
    let mut cmd = Command::new(BIN);
    cmd.args([
        "-namespace",
        "default",
        "-address",
        "/run/containerd/containerd.sock",
        "-publish-binary",
        BIN,
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
    let out = run(sc, id, "start", &[]);
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
