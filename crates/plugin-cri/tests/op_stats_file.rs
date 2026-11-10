//! `--op-stats-file` の本番バイナリ越しの結合試験（#4340・CRI-6・REPAIR-4・REPAIR-5・SEC-1）。
//!
//! 実バイナリを `env_clear()` で起動し、(A) 周期の後に 0600 のスナップショットができること、(B) 停止（SIGTERM・SIGINT）時の最後の
//! 書き出しだけでスナップショットができること、(C) 不正な置き先で固定文言のまま起動を断ること、(D) 指定なしでは何も開かないことを
//! 具体値で照合する。周期は試験用 feature `op-stats-test-support` の環境変数で短くする（dev-dependency の自己参照で既定の集合に入る）。
//! 子の待ちはすべて期限つき（REPAIR-5）。子の stderr はパイプではなく一時ディレクトリのファイルへ書く（長い試験でパイプが詰まらないように）。

#![cfg(target_os = "linux")]

#[path = "../../core/tests/support/reap.rs"]
mod reap;

#[path = "../../net/tests/support/exclusive_dir.rs"]
mod exclusive_dir;

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use fandhe_container_plugin_cri::shutdown::SHUTDOWN_TOTAL_BOUND;

const BIN: &str = env!("CARGO_BIN_EXE_fandhe-container-plugin-cri");
/// 起動して socket が現れるまでの期限（dev ビルドの起動と状態ルートの準備を含む）。
const STARTUP_WAIT: Duration = Duration::from_secs(30);
/// 周期の書き出しが現れるまでの期限（周期 300 ms に対して十分大きい値）。
const PERIODIC_WAIT: Duration = Duration::from_secs(10);
/// 書き込み thread の名前（`cri-op-stats-file`）を `/proc/<pid>/task/*/comm`（15 字に切り詰め）で見たときの値。
const THREAD_COMM: &str = "cri-op-stats-fi";
const META: &str = "\"event\":\"op_stats_meta\"";

/// 0700 の一時ディレクトリ（Drop で自分の分だけ消す）。
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        Self(exclusive_dir::create(&format!("fcpc-opstats-{tag}")).expect("create temp dir"))
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// 起動した plugin。Drop で kill して期限つきで回収する。
struct Server {
    child: Child,
    _xdg: TempDir,
    xdg_path: PathBuf,
    socks: TempDir,
    stats: TempDir,
    stderr_path: PathBuf,
    stdout_path: PathBuf,
}

impl Drop for Server {
    fn drop(&mut self) {
        reap::reap_on_drop(&mut self.child);
    }
}

impl Server {
    fn sock(&self) -> PathBuf {
        self.socks.0.join("s.sock")
    }

    fn stderr(&self) -> String {
        std::fs::read_to_string(&self.stderr_path).expect("read stderr")
    }

    /// 親ディレクトリの用意（`prepare` が置き先のパスを返す）から起動する。`interval_ms` は試験用の周期。
    fn start(
        tag: &str,
        interval_ms: Option<u32>,
        prepare: impl FnOnce(&Path) -> Option<PathBuf>,
    ) -> Self {
        let xdg = TempDir::new(&format!("{tag}-xdg"));
        let socks = TempDir::new(&format!("{tag}-sock"));
        let stats = TempDir::new(&format!("{tag}-stats"));
        let target = prepare(&stats.0);
        let stderr_path = socks.0.join("stderr.log");
        let stdout_path = socks.0.join("stdout.log");
        let mut cmd = Command::new(BIN);
        cmd.arg("--socket").arg(socks.0.join("s.sock"));
        if let Some(t) = &target {
            cmd.arg("--op-stats-file").arg(t);
        }
        cmd.env_clear().env("XDG_RUNTIME_DIR", &xdg.0);
        if let Some(ms) = interval_ms {
            cmd.env("FANDHE_CONTAINER_TEST_OP_STATS_INTERVAL_MS", ms.to_string());
        }
        let child = cmd
            .stdin(Stdio::null())
            .stdout(Stdio::from(
                std::fs::File::create(&stdout_path).expect("stdout file"),
            ))
            .stderr(Stdio::from(
                std::fs::File::create(&stderr_path).expect("stderr file"),
            ))
            .spawn()
            .expect("spawn plugin binary");
        let xdg_path = xdg.0.clone();
        Self {
            child,
            _xdg: xdg,
            xdg_path,
            socks,
            stats,
            stderr_path,
            stdout_path,
        }
    }

    /// socket が現れるまで待つ。先に子が終わったら（起動の失敗）その stderr つきで失敗させる。
    fn wait_ready(&mut self) {
        let start = Instant::now();
        while !self.sock().exists() {
            if let Some(st) = self.child.try_wait().expect("try_wait") {
                panic!("plugin exited early ({st}): {}", self.stderr());
            }
            assert!(
                start.elapsed() < STARTUP_WAIT,
                "socket did not appear: {}",
                self.stderr()
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// 書き込み thread の有無（`/proc/<pid>/task/*/comm`）。
    fn has_writer_thread(&self) -> bool {
        let dir = format!("/proc/{}/task", self.child.id());
        std::fs::read_dir(dir)
            .expect("read task dir")
            .filter_map(Result::ok)
            .filter_map(|e| std::fs::read_to_string(e.path().join("comm")).ok())
            .any(|c| c.trim() == THREAD_COMM)
    }

    fn signal(&self, sig: &str) {
        let mut kill = Command::new("kill");
        kill.args(["-s", sig, "--"])
            .arg(self.child.id().to_string());
        let st = reap::run_within(&mut kill, reap::reap_within()).expect("kill");
        assert!(st.success(), "kill -s {sig} failed");
    }

    /// 停止の全体の上限 + 余裕まで待って終了コードを返す。
    fn wait_exit(&mut self) -> Option<i32> {
        let limit = SHUTDOWN_TOTAL_BOUND + Duration::from_secs(10);
        reap::wait_within(&mut self.child, limit)
            .expect("plugin did not stop in time")
            .code()
    }
}

fn read_snapshot(path: &Path) -> (String, std::fs::Metadata) {
    let meta = std::fs::symlink_metadata(path).expect("snapshot metadata");
    (std::fs::read_to_string(path).expect("snapshot"), meta)
}

fn assert_three_blocks(body: &str) {
    assert_eq!(body.matches(META).count(), 3, "{body}");
    assert!(body.lines().last().expect("lines").contains(META), "{body}");
}

fn dir_entries(dir: &Path) -> Vec<String> {
    std::fs::read_dir(dir)
        .expect("read_dir")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .collect()
}

/// CRI-6・REPAIR-4・#4340: 周期（300 ms）の後に 0600 のスナップショットができ、周期ごとに置き換わる（inode が変わる）。
/// 停止後は一時ファイルが残らず、失敗の行も無い。
#[test]
fn cri6_4340_periodic_snapshot_appears_with_0600() {
    let mut s = Server::start("periodic", Some(300), |d| Some(d.join("stats.jsonl")));
    s.wait_ready();
    assert!(
        s.has_writer_thread(),
        "writer thread must exist when opted in"
    );
    let path = s.stats.0.join("stats.jsonl");
    let start = Instant::now();
    while !path.exists() {
        assert!(
            start.elapsed() < PERIODIC_WAIT,
            "no periodic snapshot: {}",
            s.stderr()
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    let (body, meta) = read_snapshot(&path);
    assert!(meta.file_type().is_file());
    assert_eq!(meta.mode() & 0o777, 0o600);
    let own_uid = std::fs::metadata(&s.stats.0).expect("dir meta").uid();
    assert_eq!(meta.uid(), own_uid);
    assert_three_blocks(&body);
    // 次の周期で rename により置き換わる。
    let first_ino = meta.ino();
    let start = Instant::now();
    loop {
        let now = std::fs::symlink_metadata(&path).expect("meta").ino();
        if now != first_ino {
            break;
        }
        assert!(
            start.elapsed() < PERIODIC_WAIT,
            "snapshot was not replaced by a later cycle"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    s.signal("TERM");
    assert_eq!(s.wait_exit(), Some(0));
    let err = s.stderr();
    assert!(
        err.contains("cri plugin shutdown: signal=SIGTERM stage=serve"),
        "{err}"
    );
    assert!(!err.contains("op_stats_file_failed"), "{err}");
    assert_eq!(dir_entries(&s.stats.0), ["stats.jsonl"]);
}

/// 周期が 60 秒の既定のまま、停止時の最後の書き出しだけでスナップショットができることを確かめる。
fn final_snapshot_on(sig: &str, sig_name: &str, tag: &str) {
    let mut s = Server::start(tag, None, |d| Some(d.join("stats.jsonl")));
    s.wait_ready();
    // 陽性対照: 書き込み thread が居る（居なければ「ファイルが無い」が自明になる）。
    assert!(
        s.has_writer_thread(),
        "writer thread must exist when opted in"
    );
    let path = s.stats.0.join("stats.jsonl");
    assert!(!path.exists(), "no snapshot before the first period");
    s.signal(sig);
    assert_eq!(s.wait_exit(), Some(0), "{}", s.stderr());
    let (body, meta) = read_snapshot(&path);
    assert!(meta.file_type().is_file());
    assert_eq!(meta.mode() & 0o777, 0o600);
    assert_three_blocks(&body);
    let err = s.stderr();
    assert!(
        err.contains(&format!(
            "cri plugin shutdown: signal={sig_name} stage=serve"
        )),
        "{err}"
    );
    assert!(!err.contains("op_stats_file_failed"), "{err}");
    assert_eq!(dir_entries(&s.stats.0), ["stats.jsonl"]);
}

/// CRI-6・REPAIR-5・#4340: SIGTERM の停止時に最後のスナップショットが書かれる。
#[test]
fn cri6_4340_final_snapshot_written_on_sigterm() {
    final_snapshot_on("TERM", "SIGTERM", "finalterm");
}

/// CRI-6・REPAIR-5・#4340: SIGINT でも同じ。
#[test]
fn cri6_4340_final_snapshot_written_on_sigint() {
    final_snapshot_on("INT", "SIGINT", "finalint");
}

/// SEC-1・SEC-4・REPAIR-4・#4340: 信頼できない置き先は固定文言で起動を断る。状態ルートにも socket にも触らない。
#[test]
fn cri6_4340_untrusted_target_fails_startup() {
    type Prepare = fn(&Path) -> PathBuf;
    let cases: [(&str, &str, Prepare); 5] = [
        ("symlinkdir", "untrusted_directory", |d| {
            let real = d.join("real");
            std::fs::create_dir(&real).expect("mkdir");
            std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o700)).expect("chmod");
            std::os::unix::fs::symlink(&real, d.join("link")).expect("symlink");
            d.join("link").join("s.jsonl")
        }),
        ("gwrite", "untrusted_directory", |d| {
            std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o775)).expect("chmod");
            d.join("s.jsonl")
        }),
        ("owrite", "untrusted_directory", |d| {
            std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o757)).expect("chmod");
            d.join("s.jsonl")
        }),
        ("finalsym", "target_not_regular", |d| {
            std::fs::write(d.join("victim"), b"keep").expect("write");
            std::os::unix::fs::symlink(d.join("victim"), d.join("s.jsonl")).expect("symlink");
            d.join("s.jsonl")
        }),
        ("finaldir", "target_not_regular", |d| {
            std::fs::create_dir(d.join("s.jsonl")).expect("mkdir");
            d.join("s.jsonl")
        }),
    ];
    for (tag, reason, prepare) in cases {
        let mut s = Server::start(tag, None, |d| Some(prepare(d)));
        let code = reap::wait_within(&mut s.child, Duration::from_secs(20))
            .unwrap_or_else(|e| panic!("{tag}: {e}"))
            .code();
        assert_eq!(code, Some(1), "{tag}: {}", s.stderr());
        assert_eq!(
            s.stderr(),
            format!(
                "error: PERMISSION_DENIED: failed to open the op-stats snapshot file: {reason}\n"
            ),
            "{tag}"
        );
        assert_eq!(
            std::fs::read_to_string(&s.stdout_path).expect("stdout"),
            "",
            "{tag}"
        );
        assert!(!s.sock().exists(), "{tag}: socket must not be created");
        assert!(
            dir_entries(&s.xdg_path).is_empty(),
            "{tag}: state root must not be touched"
        );
        // 値（ディレクトリ名のタグ）をエコーしない。
        assert!(!s.stderr().contains(tag), "{tag}");
    }
}

/// CRI-6・REPAIR-3・#4340: 指定なしでは書き込み thread を作らず、何も書かない（従来どおり stderr のみ）。
#[test]
fn cri6_4340_no_flag_opens_nothing() {
    let mut s = Server::start("noflag", Some(300), |_| None);
    s.wait_ready();
    // 周期（300 ms）が何度か回る間待っても、ファイル sink は存在しない。
    std::thread::sleep(Duration::from_millis(1_000));
    assert!(!s.has_writer_thread(), "no writer thread without the flag");
    s.signal("TERM");
    assert_eq!(s.wait_exit(), Some(0), "{}", s.stderr());
    let err = s.stderr();
    assert!(!err.contains("op_stats_file"), "{err}");
    assert!(
        err.contains("cri plugin shutdown: signal=SIGTERM stage=serve"),
        "{err}"
    );
    assert!(dir_entries(&s.stats.0).is_empty());
}
