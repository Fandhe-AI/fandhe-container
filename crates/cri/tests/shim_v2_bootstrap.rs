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

/// 子の実行の期限（REPAIR-5）。
#[allow(dead_code)]
const LIMIT: Duration = Duration::from_secs(30);
const BIN: &str = env!("CARGO_BIN_EXE_containerd-shim-fandhe-container-v2");
const UNIMPL: i32 = 12;

#[path = "../../core/tests/support/reap.rs"]
mod reap;
#[path = "../../oci/tests/support/test_root.rs"]
mod test_root;

/// 試験用ディレクトリ（sun_path の制約のため短い /tmp 直下に 0700 で排他作成する）。Drop で消す。
struct Scratch {
    guard: test_root::TestRoot,
    root: PathBuf,
}

impl Scratch {
    fn new() -> Self {
        // sun_path（macOS は 103 バイト）の制約のため、`temp_dir()`（macOS では長い /var/folders/...）ではなく
        // 短い /tmp 直下に作る（socket 名 64 桁 hex を足しても収まる）。
        static SEQ: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let guard =
            test_root::test_root_at(PathBuf::from(format!("/tmp/fcs{}-{n}", std::process::id())));
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
    .env("XDG_RUNTIME_DIR", &sc.root)
    .current_dir(&sc.root)
    .stdin(Stdio::null());
    reap::output_within(&mut cmd, Duration::from_secs(30))
        .expect("shim child must exit within the limit")
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
    let out = reap::output_within(&mut cmd, LIMIT).expect("shim child must exit within the limit");
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
        .env("XDG_RUNTIME_DIR", &sc.root)
        .current_dir(&sc.root)
        .stdin(Stdio::null());
    let out = reap::output_within(&mut cmd, LIMIT).expect("shim child must exit within the limit");
    assert_failed(&out, "FAILED_PRECONDITION");
}

/// `/proc/<pid>/stat` の親 PID（Linux）。コマンド名に `)` が入っても末尾の `)` から読む。
#[cfg(target_os = "linux")]
fn ppid_of(pid: u32) -> Option<u32> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let rest = &stat[stat.rfind(')')? + 1..];
    rest.split_whitespace().nth(1)?.parse().ok()
}

/// `/proc/*/cmdline` に id を含むデーモン（と fork した子）の PID 一覧（Linux）。
#[cfg(target_os = "linux")]
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

/// `/proc/<pid>/fd` が指す `socket:[inode]` の一覧（Linux）。
#[cfg(target_os = "linux")]
fn socket_inodes(pid: u32) -> Vec<u64> {
    let Ok(rd) = std::fs::read_dir(format!("/proc/{pid}/fd")) else {
        return Vec::new();
    };
    rd.flatten()
        .filter_map(|e| {
            let t = std::fs::read_link(e.path()).ok()?;
            let t = t.to_str()?;
            t.strip_prefix("socket:[")?.strip_suffix(']')?.parse().ok()
        })
        .collect()
}

/// `/proc/net/unix` から、パスが `sock` の socket の inode を探す（Linux）。
#[cfg(target_os = "linux")]
fn inode_of_socket_path(sock: &Path) -> Option<u64> {
    let text = std::fs::read_to_string("/proc/net/unix").ok()?;
    text.lines().find_map(|l| {
        let cols: Vec<&str> = l.split_whitespace().collect();
        (cols.len() >= 8 && cols.last() == Some(&sock.to_str()?))
            .then(|| cols[6].parse().ok())
            .flatten()
    })
}

/// SEC-4・PLUG-12・#3663: 監査 relay の helper は listen socket を持たない（デーモンが死んでも LISTEN を保たず、
/// `start` が死んだアドレスを生きていると判定し続けない）。デーモンの stdin は /dev/null になっている。
#[cfg(target_os = "linux")]
#[test]
fn plug12_3663_audit_helper_does_not_hold_listener() {
    let sc = Scratch::new();
    let id = format!("h{}", std::process::id());
    let addr = start_ok(&sc, &id);
    let sock = sock_of(&addr);
    let ino = inode_of_socket_path(&sock).expect("listener inode must be listed in /proc/net/unix");
    let pids = daemon_pids(&id);
    assert_eq!(pids.len(), 2, "daemon and its audit helper: {pids:?}");
    let daemon = *pids
        .iter()
        .find(|p| ppid_of(**p).is_some_and(|pp| !pids.contains(&pp)))
        .expect("daemon (parent outside the pair) must exist");
    let helper = *pids.iter().find(|p| **p != daemon).unwrap();
    assert_eq!(ppid_of(helper), Some(daemon));
    assert!(
        socket_inodes(daemon).contains(&ino),
        "the daemon must hold the listener"
    );
    assert!(
        !socket_inodes(helper).contains(&ino),
        "the audit helper must not hold the listener"
    );
    assert_eq!(
        std::fs::read_link(format!("/proc/{daemon}/fd/0")).unwrap(),
        Path::new("/dev/null")
    );
    let del = run(&sc, &id, "delete", &["-bundle", "/tmp/b"]);
    assert!(del.status.success(), "{del:?}");
}

/// SEC-4・#3663: 監査の記録先を確保できないデーモンは起動に失敗し（置き場所の上書きでも縮退しない）、
/// その理由はデーモンの stderr の記録先 `daemon.log`（0600）に残る。
#[cfg(target_os = "linux")]
#[test]
fn sec4_3663_audit_open_failure_is_fatal_and_logged() {
    let sc = Scratch::new();
    let mut cmd = Command::new(BIN);
    cmd.args([
        "-namespace",
        "default",
        "-address",
        "/run/containerd/containerd.sock",
        "-publish-binary",
        "/usr/bin/containerd",
        "-id",
        "noaudit",
        "start",
    ])
    .env("FANDHE_CONTAINER_SHIM_SOCKET_DIR", sc.sock_dir())
    // 相対パスの XDG_RUNTIME_DIR は状態ルートとして拒否される（root では既定の /run/fandhe-container が使われるため対象外）。
    .env("XDG_RUNTIME_DIR", "relative-runtime-dir")
    .current_dir(&sc.root)
    .stdin(Stdio::null());
    let out = reap::output_within(&mut cmd, LIMIT).expect("shim child must exit within the limit");
    let log = sc.sock_dir().join("daemon.log");
    if std::fs::metadata(&sc.root).unwrap().uid() == 0 {
        return;
    }
    assert!(!out.status.success(), "{out:?}");
    let text = std::fs::read_to_string(&log).unwrap();
    assert!(text.contains("cannot open audit log"), "{text}");
    assert_eq!(std::fs::metadata(&log).unwrap().mode() & 0o777, 0o600);
}

/// SEC-4・PLUG-12・#3663: 非 Linux には監査の記録先が無く（`open_audit_sink` は `None`。#2430 の判断待ち）、
/// 状態ルートが使えなくても起動は成功する。stderr の記録先 `daemon.log` は 0600 で作られる。
/// 拒否の通知（`audit_unavailable`）は別 UID の接続があって初めて出るため、ここでは確かめない。
#[cfg(all(unix, not(target_os = "linux")))]
#[test]
fn sec4_3663_non_linux_starts_without_audit_sink() {
    let sc = Scratch::new();
    let shim = |extra: &[&str], action: &str| {
        let mut cmd = Command::new(BIN);
        cmd.args([
            "-namespace",
            "default",
            "-address",
            "/run/containerd/containerd.sock",
            "-publish-binary",
            "/usr/bin/containerd",
            "-id",
            "noaudit",
        ])
        .args(extra)
        .arg(action)
        .env("FANDHE_CONTAINER_SHIM_SOCKET_DIR", sc.sock_dir())
        .env("XDG_RUNTIME_DIR", "relative-runtime-dir")
        .current_dir(&sc.root)
        .stdin(Stdio::null());
        reap::output_within(&mut cmd, LIMIT).expect("shim child must exit within the limit")
    };
    let out = shim(&[], "start");
    assert!(out.status.success(), "{out:?}");
    let addr = String::from_utf8(out.stdout).unwrap();
    assert!(addr.starts_with("unix://"), "{addr}");
    let log = sc.sock_dir().join("daemon.log");
    assert_eq!(std::fs::metadata(&log).unwrap().mode() & 0o777, 0o600);
    let del = shim(&["-bundle", "/tmp/b"], "delete");
    assert!(del.status.success(), "{del:?}");
}
