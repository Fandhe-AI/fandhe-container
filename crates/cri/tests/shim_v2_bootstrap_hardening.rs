//! shim v2 起動バイナリの排他・計測の結合試験（REPAIR-4・REPAIR-5・PLUG-12・CRI-5・TASK-62.7.1・#872）。
#![cfg(unix)]

use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::time::Duration;

const BIN: &str = env!("CARGO_BIN_EXE_containerd-shim-fandhe-container-v2");

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
        let guard = test_root::test_root("fch", "h");
        let root = guard.to_path_buf();
        Self { guard, root }
    }
    fn sock_dir(&self) -> PathBuf {
        self.guard.join("s")
    }
}

fn run(sc: &Scratch, id: &str, action: &str) -> Output {
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
    .args(if action == "delete" {
        vec!["-bundle", "/tmp/b"]
    } else {
        vec![]
    })
    .arg(action)
    .env("FANDHE_CONTAINER_SHIM_SOCKET_DIR", sc.sock_dir())
    .current_dir(&sc.root)
    .stdin(Stdio::null());
    bounded::output_within(cmd, Duration::from_secs(30))
}

fn start_ok(sc: &Scratch, id: &str) -> String {
    let out = run(sc, id, "start");
    assert!(out.status.success(), "{out:?}");
    assert_eq!(out.stderr, b"");
    String::from_utf8(out.stdout).unwrap()
}

/// REPAIR-5・#872: 同一 id の start を同時に走らせても、全員が同じ address を返す。
#[test]
fn repair5_872_concurrent_starts_agree() {
    let sc = Scratch::new();
    let scr = &sc;
    let addrs: Vec<String> = std::thread::scope(|s| {
        let hs: Vec<_> = (0..4).map(|_| s.spawn(|| start_ok(scr, "race"))).collect();
        hs.into_iter().map(|h| h.join().unwrap()).collect()
    });
    assert!(addrs.iter().all(|a| a == &addrs[0]), "{addrs:?}");
    assert!(run(&sc, "race", "delete").status.success());
}

/// REPAIR-4・#872: start / delete の結果が ops.log に JSON Lines で残り、stderr は汚れない。
#[test]
fn repair4_872_ops_log_records_start_and_delete() {
    let sc = Scratch::new();
    start_ok(&sc, "log1");
    let del = run(&sc, "log1", "delete");
    assert!(del.status.success());
    assert_eq!(del.stderr, b"");
    let log = sc.sock_dir().join("ops.log");
    assert_eq!(std::fs::metadata(&log).unwrap().mode() & 0o777, 0o600);
    let text = std::fs::read_to_string(&log).unwrap();
    for op in ["cri.shim_v2.start", "cri.shim_v2.delete"] {
        let line = text
            .lines()
            .find(|l| l.contains(op))
            .unwrap_or_else(|| panic!("{op} missing: {text}"));
        let v: serde_json::Value = serde_json::from_str(line).unwrap();
        assert_eq!(v["outcome"], "success", "{line}");
        assert_eq!(v["code"], "Ok", "{line}");
        assert!(v["latency_us"].is_u64(), "{line}");
    }
}

/// PLUG-12・#872: 実行ユーザーが所有する socket dir と socket は受け入れられる（所有者の照合の通常経路）。
/// 他 uid の所有は root 以外では作れないため、拒否側は単体の検査（fail-closed）に委ねる。
#[test]
fn plug12_872_owned_socket_dir_is_accepted() {
    let sc = Scratch::new();
    let addr = start_ok(&sc, "own");
    let sock = PathBuf::from(addr.strip_prefix("unix://").unwrap());
    assert_eq!(
        std::fs::metadata(sc.sock_dir()).unwrap().uid(),
        std::fs::metadata(&sock).unwrap().uid()
    );
    assert!(run(&sc, "own", "delete").status.success());
}

/// PLUG-12・REPAIR-4・#872: socket dir が symlink のとき start / delete は失敗し、symlink の先へ ops.log を書かない。
#[test]
fn plug12_872_symlinked_socket_dir_gets_no_ops_log() {
    let sc = Scratch::new();
    let target = sc.root.join("target");
    std::fs::create_dir(&target).unwrap();
    std::os::unix::fs::symlink(&target, sc.sock_dir()).unwrap();
    assert!(!run(&sc, "sl", "start").status.success());
    assert!(!run(&sc, "sl", "delete").status.success());
    assert!(!target.join("ops.log").exists());
}
