//! shim v2 起動バイナリの排他・計測の結合試験（REPAIR-4・REPAIR-5・PLUG-12・CRI-5・TASK-62.7.1・#872）。
#![cfg(unix)]

use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::time::Duration;

/// 子の実行の期限（REPAIR-5）。
#[allow(dead_code)]
const LIMIT: Duration = Duration::from_secs(30);
const BIN: &str = env!("CARGO_BIN_EXE_containerd-shim-fandhe-container-v2");

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
            test_root::test_root_at(PathBuf::from(format!("/tmp/fch{}-{n}", std::process::id())));
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
    reap::output_within(&mut cmd, Duration::from_secs(30))
        .expect("shim child must exit within the limit")
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

/// PLUG-12・#872: 上書き値が symlink への末尾スラッシュ付きでも拒否し、参照先へ socket・ログを作らない。
#[test]
fn plug12_872_trailing_slash_symlink_override_is_rejected() {
    use std::os::unix::fs::DirBuilderExt;
    let sc = Scratch::new();
    let target = sc.root.join("real");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&target)
        .unwrap();
    let link = sc.root.join("link");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    let mut dir = link.into_os_string();
    dir.push("/");
    for action in ["start", "delete"] {
        let mut cmd = Command::new(BIN);
        cmd.args([
            "-namespace",
            "default",
            "-address",
            "/run/containerd/containerd.sock",
            "-id",
            "tl",
        ])
        .args(if action == "delete" {
            vec!["-bundle", "/tmp/b"]
        } else {
            vec![]
        })
        .arg(action)
        .env("FANDHE_CONTAINER_SHIM_SOCKET_DIR", &dir)
        .current_dir(&sc.root)
        .stdin(Stdio::null());
        let out = reap::output_within(&mut cmd, LIMIT).expect("shim child must exit");
        assert!(!out.status.success(), "{action}: {out:?}");
    }
    assert_eq!(std::fs::read_dir(&target).unwrap().count(), 0);
}

/// REPAIR-4・#872: 並行する start / delete が共有の ops.log を壊さず、全操作の行が残る。
#[test]
fn repair4_872_concurrent_ops_log_keeps_every_line() {
    let sc = Scratch::new();
    let scr = &sc;
    std::thread::scope(|s| {
        let hs: Vec<_> = (0..4)
            .map(|i| {
                s.spawn(move || {
                    let id = format!("log{i}");
                    start_ok(scr, &id);
                    assert!(run(scr, &id, "delete").status.success());
                })
            })
            .collect();
        for h in hs {
            h.join().unwrap();
        }
    });
    let log = std::fs::read_to_string(sc.sock_dir().join("ops.log")).unwrap();
    assert_eq!(log.lines().count(), 8, "{log}");
    assert!(log.lines().all(|l| l.starts_with('{') && l.ends_with('}')));
}
