//! shim v2 起動バイナリ（`containerd-shim-fandhe-container-v2`）の結合試験（CRI-5・TASK-62.7.1・MS-7・#872）。
//!
//! containerd の start / delete の呼び出しを再現し、stdout のアドレス・stderr が空であること・権限・
//! ttrpc の疎通・冪等性・fail-closed を具体値で照合する。root や特殊な環境は要らない。
#![cfg(unix)]

use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::Duration;
#[cfg(target_os = "linux")]
use std::time::Instant;

use fandhe_container_cri::shim_v2::{
    DeleteResponse, FrameHeader, HEADER_LEN, MessageType, TtrpcRequest, TtrpcResponse,
};
use prost::Message;

const BIN: &str = env!("CARGO_BIN_EXE_containerd-shim-fandhe-container-v2");
const UNIMPL: i32 = 12;

#[path = "support/bounded.rs"]
mod bounded;
#[path = "../../oci/tests/support/test_root.rs"]
mod test_root;

/// 試験用ディレクトリ（sun_path の制約のため短い /tmp 直下に 0700 で排他作成する）。Drop で消す。
struct Scratch {
    guard: test_root::TestRoot,
    root: PathBuf,
}

impl Scratch {
    fn new() -> Self {
        let guard = test_root::test_root("fcs", "b");
        let root = guard.to_path_buf();
        Self { guard, root }
    }
    fn sock_dir(&self) -> PathBuf {
        self.guard.join("s")
    }
}

/// 期限つきで子を回収して出力を得る。
fn run(sc: &Scratch, id: &str, action: &str, extra: &[&str]) -> Output {
    let mut cmd = Command::new(BIN);
    cmd.args([
        "-namespace",
        "default",
        "-address",
        "/run/containerd/containerd.sock",
        "-publish-binary",
        "/usr/bin/containerd",
        "-id",
        id,
    ])
    .args(extra)
    .arg(action)
    .env("FANDHE_CONTAINER_SHIM_SOCKET_DIR", sc.sock_dir())
    .current_dir(&sc.root)
    .stdin(Stdio::null());
    bounded::output_within(cmd, Duration::from_secs(30))
}

fn start_ok(sc: &Scratch, id: &str) -> String {
    let out = run(sc, id, "start", &[]);
    assert!(out.status.success(), "{:?}", out);
    assert_eq!(out.stderr, b"", "start must not write to stderr");
    String::from_utf8(out.stdout).unwrap()
}

fn sock_of(address: &str) -> PathBuf {
    PathBuf::from(address.strip_prefix("unix://").unwrap())
}

fn call(path: &Path, service: &str) -> TtrpcResponse {
    let mut s = UnixStream::connect(path).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let body = TtrpcRequest {
        service: service.into(),
        method: "Create".into(),
        ..Default::default()
    }
    .encode_to_vec();
    let h = FrameHeader::new(body.len() as u32, 1, MessageType::Request, 0).unwrap();
    s.write_all(&h.to_bytes()).unwrap();
    s.write_all(&body).unwrap();
    let mut hb = [0u8; HEADER_LEN];
    s.read_exact(&mut hb).unwrap();
    let h = FrameHeader::from_bytes(&hb).unwrap();
    let mut b = vec![0u8; h.length() as usize];
    s.read_exact(&mut b).unwrap();
    TtrpcResponse::decode(&b[..]).unwrap()
}

/// `/proc/*/cmdline` に id を含むデーモンが残っているか（Linux のみ）。
#[cfg(target_os = "linux")]
fn daemon_alive(id: &str) -> bool {
    let needle = format!("-id\0{id}\0");
    let Ok(rd) = std::fs::read_dir("/proc") else {
        return false;
    };
    rd.flatten().any(|e| {
        std::fs::read(e.path().join("cmdline"))
            .map(|c| {
                let s = String::from_utf8_lossy(&c).into_owned();
                s.contains(BIN) && s.contains(&needle)
            })
            .unwrap_or(false)
    })
}

/// CRI-5・#872: start がアドレスだけを stdout に出し、stderr が空、権限が 0700 / 0600、ttrpc が疎通する。
#[test]
fn cri5_872_start_prints_address_and_serves_ttrpc() {
    let sc = Scratch::new();
    let addr = start_ok(&sc, "c1");
    let prefix = format!("unix://{}/", sc.sock_dir().display());
    assert!(addr.starts_with(&prefix), "{addr}");
    let name = &addr[prefix.len()..];
    assert_eq!(name.len(), 64);
    assert!(name.bytes().all(|b| b.is_ascii_hexdigit()));
    let sock = sock_of(&addr);
    assert_eq!(std::fs::metadata(&sock).unwrap().mode() & 0o777, 0o600);
    assert_eq!(
        std::fs::metadata(sc.sock_dir()).unwrap().mode() & 0o777,
        0o700
    );
    for svc in ["containerd.task.v2.Task", "containerd.task.v3.Task"] {
        let r = call(&sock, svc);
        assert_eq!(r.status.unwrap().code, UNIMPL, "{svc}");
    }
    // 同じフラグでもう一度 start すると、生きている socket を再利用して同じアドレスを返す。
    assert_eq!(start_ok(&sc, "c1"), addr);
    let del = run(&sc, "c1", "delete", &["-bundle", "/tmp/b"]);
    assert!(del.status.success());
}

/// CRI-5・#872: delete は DeleteResponse を返し、socket を消し、デーモンが終わる。
#[test]
fn cri5_872_delete_cleans_up_and_daemon_exits() {
    let sc = Scratch::new();
    let id = format!("d{}", std::process::id());
    let addr = start_ok(&sc, &id);
    let sock = sock_of(&addr);
    assert!(sock.exists());
    let del = run(&sc, &id, "delete", &["-bundle", "/tmp/b"]);
    assert!(del.status.success(), "{:?}", del);
    let r = DeleteResponse::decode(&del.stdout[..]).unwrap();
    assert_eq!((r.pid, r.exit_status), (0, 137));
    assert!(r.exited_at.is_some());
    assert!(!sock.exists());
    // 冪等
    assert!(
        run(&sc, &id, "delete", &["-bundle", "/tmp/b"])
            .status
            .success()
    );
    #[cfg(target_os = "linux")]
    {
        let deadline = Instant::now() + Duration::from_secs(10);
        while daemon_alive(&id) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(100));
        }
        assert!(!daemon_alive(&id), "daemon must exit after delete");
    }
}

/// CRI-5・#872: 残骸の socket があっても start は置き換えて成功する。
#[test]
fn cri5_872_start_replaces_stale_socket() {
    let sc = Scratch::new();
    // アドレスを得るため一度 start して delete 相当で片付け、同じパスに残骸を作る。
    let addr = start_ok(&sc, "stale");
    let sock = sock_of(&addr);
    assert!(
        run(&sc, "stale", "delete", &["-bundle", "/tmp/b"])
            .status
            .success()
    );
    drop(UnixListener::bind(&sock).unwrap());
    assert!(sock.exists());
    assert_eq!(start_ok(&sc, "stale"), addr);
    let r = call(&sock, "containerd.task.v2.Task");
    assert_eq!(r.status.unwrap().code, UNIMPL);
    assert!(
        run(&sc, "stale", "delete", &["-bundle", "/tmp/b"])
            .status
            .success()
    );
}

fn assert_failed(out: &Output, code: &str) {
    assert!(!out.status.success());
    assert_eq!(out.stdout, b"");
    let err = String::from_utf8(out.stderr.clone()).unwrap();
    assert_eq!(err.lines().count(), 1, "{err}");
    let v: serde_json::Value = serde_json::from_str(&err).unwrap();
    assert_eq!(v["code"], code, "{err}");
    assert!(
        v["message"].as_str().is_some_and(|m| !m.is_empty()),
        "{err}"
    );
}

/// CRI-5・#872: socket パスに通常ファイルがあれば拒否し、内容を変えない。権限の緩いディレクトリも拒否する。
#[test]
fn cri5_872_start_rejects_unsafe_paths() {
    let sc = Scratch::new();
    let addr = start_ok(&sc, "x");
    let sock = sock_of(&addr);
    assert!(
        run(&sc, "x", "delete", &["-bundle", "/tmp/b"])
            .status
            .success()
    );
    std::fs::write(&sock, b"keep").unwrap();
    let out = run(&sc, "x", "start", &[]);
    assert_failed(&out, "FAILED_PRECONDITION");
    assert_eq!(std::fs::read(&sock).unwrap(), b"keep");
    std::fs::remove_file(&sock).unwrap();
    std::fs::set_permissions(sc.sock_dir(), std::fs::Permissions::from_mode(0o755)).unwrap();
    assert_failed(&run(&sc, "x", "start", &[]), "FAILED_PRECONDITION");
}

/// CRI-5・#872: 必須フラグの欠落と未知のフラグは INVALID_ARGUMENT で、stdout は空。
#[test]
fn cri5_872_invalid_arguments_fail_closed() {
    let sc = Scratch::new();
    let mut cmd = Command::new(BIN);
    cmd.args(["-namespace", "default", "-address", "/a.sock", "start"])
        .current_dir(&sc.root);
    let out = bounded::output_within(cmd, bounded::LIMIT);
    assert_failed(&out, "INVALID_ARGUMENT");
    let out = run(&sc, "i", "start", &["-bogus"]);
    assert_failed(&out, "INVALID_ARGUMENT");
}

/// CRI-5・#872: serve を stdin が socket でない状態で起動すると失敗する（fail-closed）。
#[test]
fn cri5_872_serve_rejects_non_socket_stdin() {
    let sc = Scratch::new();
    let mut cmd = Command::new(BIN);
    cmd.args(["-namespace", "default", "-address", "/a.sock", "-id", "s"])
        .env("FANDHE_CONTAINER_SHIM_SOCKET_DIR", sc.sock_dir())
        .current_dir(&sc.root)
        .stdin(Stdio::null());
    let out = bounded::output_within(cmd, bounded::LIMIT);
    assert_failed(&out, "FAILED_PRECONDITION");
}
