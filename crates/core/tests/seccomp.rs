//! 起動したコンテナプロセスの中で禁止 syscall が遮断されることの結合試験（CORE-5・TASK-38.4・#179。
//! REPAIR-12 の機械照合）。
//!
//! `seccomp_enforcement`（#178）は使い捨ての子で適用経路を呼ぶ検証にとどまる。本試験は
//! `spawn_container_seccomp_probe` が fork した実際のコンテナプロセス（新しい PID namespace の PID 1・
//! pivot_root 後・capability 削減・`NO_NEW_PRIVS` 設定済み）の中で、ステージ列の**組み込み `Seccomp` 段**が
//! 載せたフィルタが禁止 syscall を `EPERM` で拒否することを、子が pivot 後の `/seccomp-probe` へ書いた
//! 記録（`SeccompProbeRecord`）の具体値で照合する。exec は証跡が無い間は常に拒否される（fail-closed。
//! REPAIR-3）ため、プローブ用 API は exec の代わりに終端でプローブを実行する。
//!
//! # 識別的な検査と網羅確認
//! - 識別的（capability 不足ではなく seccomp が拒否したことを示せる）: `unshare(0)`（フィルタが無ければ
//!   成功）・`ptrace`（フィルタが無ければ `ESRCH`）・`/proc/thread-self/status` の `Seccomp: 2`。
//!   禁止対象外の対照（`/proc` の読み出し）が動くことも確認する
//! - 網羅確認: `mount`・`pivot_root`・`umount2`・`kexec_load` が `EPERM`。capability 不足でも
//!   `EPERM` になり得るため、識別的な根拠とは扱わない
//!
//! 受け入れ基準の「シグナル」側（x32 番号の `SECCOMP_RET_KILL_PROCESS` → `SIGSYS`）は、本試験では
//! 扱わない（errno による遮断の照合のみ）。
//!
//! # 構成
//! - 常に走る部分（3 OS 共通・既定のテスト集合）: プローブ対象が `DeniedSyscall::ALL` に含まれること、
//!   記録の解析の自己テスト
//! - 実機前提部分（Linux x86_64 / aarch64。`-- --ignored` 指定時のみ）: ディスパッチャが自身を
//!   `--scenario seccomp <rootfs>` で再起動する（`unshare(CLONE_NEWPID)` の後に PID 1 になれるのは最初の
//!   子だけのため）。
//!
//! # 実機前提テストとしての分離
//! root もしくは非特権 user namespace を許可するホストが必要（`capabilities` と同じ）。GitHub ホステッド
//! runner で保証できないため `-- --ignored` 指定時のみ実行する（ci.md「実機前提テスト」）。プローブの
//! 引数は、フィルタが欠けていてもホストへ副作用が出ないもの（attach を伴わない ptrace・segment 数超過の
//! kexec_load・コンテナの mount namespace に閉じる mount 系）に固定している。実行された場合は分離の拒否・
//! 事前条件の不成立を含めあらゆる失敗を失敗として扱い、検証せずに成功する分岐は持たない。

use fandhe_container_core::exec::{ProbeOutcome, SeccompProbeRecord};
use fandhe_container_core::seccomp::DeniedSyscall;

/// 結合試験が errno を照合する禁止 syscall の論理名（`DeniedSyscall::ALL` に含まれる必要がある）。
const PROBED: [&str; 6] = [
    "unshare",
    "ptrace",
    "mount",
    "pivot_root",
    "umount2",
    "kexec_load",
];

/// REPAIR-12: プローブ対象の論理名が禁止 syscall の一覧（CORE-5）に実在する。
fn core5_probed_names_are_in_deny_table() {
    let names: Vec<&str> = DeniedSyscall::ALL.iter().map(|d| d.name()).collect();
    for probed in PROBED.iter() {
        assert!(
            names.contains(probed),
            "CORE-5: probed syscall {probed} must be in DeniedSyscall::ALL"
        );
    }
}

/// 記録の解析を固定文字列で自己検証する（具体値・欠落・重複・未知キー・不正値の検出）。
fn core5_record_parser_selftest() {
    let ok = "unshare=errno=1\nptrace=errno=1\nseccomp_mode=2\ncontrol=ok\nmount=errno=1\n\
              pivot_root=errno=1\numount2=errno=1\nkexec_load=errno=1\n";
    let rec = SeccompProbeRecord::parse(ok).expect("well-formed record");
    assert_eq!(rec.unshare, ProbeOutcome::Errno(1));
    assert_eq!(rec.seccomp_mode, "2");
    assert_eq!(rec.control, ProbeOutcome::Ok);
    assert_eq!(rec.render(), ok, "render must round-trip");
    let missing = ok.replace("kexec_load=errno=1\n", "");
    assert_eq!(
        SeccompProbeRecord::parse(&missing),
        Err("missing key \"kexec_load\"".to_string())
    );
    let dup = format!("{ok}mount=ok\n");
    assert_eq!(
        SeccompProbeRecord::parse(&dup),
        Err("duplicate key \"mount\"".to_string())
    );
    let unknown = format!("{ok}extra=1\n");
    assert_eq!(
        SeccompProbeRecord::parse(&unknown),
        Err("unknown key \"extra\"".to_string())
    );
    let bad = ok.replace("ptrace=errno=1", "ptrace=errno=x");
    assert_eq!(
        SeccompProbeRecord::parse(&bad),
        Err("invalid outcome \"errno=x\"".to_string())
    );
}

fn always() {
    core5_probed_names_are_in_deny_table();
    core5_record_parser_selftest();
    println!("seccomp: CORE-5 probe table and record parser verified");
}

#[cfg(not(target_os = "linux"))]
fn main() {
    always();
    println!("seccomp: real-process part is Linux only, not applicable on this OS");
}

#[cfg(all(
    target_os = "linux",
    not(any(target_arch = "x86_64", target_arch = "aarch64"))
))]
fn main() {
    always();
    println!(
        "seccomp: real-process part is x86_64/aarch64 only, not applicable on this architecture"
    );
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn main() {
    // シナリオ再入時は常に走る部分を繰り返さない。
    if std::env::args().any(|a| a == "--scenario") {
        linux::run();
        return;
    }
    always();
    if std::env::args().any(|a| a == "--ignored") {
        linux::run();
    } else {
        println!("seccomp: ignored (real-machine test; run with `-- --ignored`, see AGENTS.md)");
    }
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod linux {
    use std::io::Read as _;
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::{Path, PathBuf};
    use std::process::{Command, ExitStatus, Stdio};
    use std::time::{Duration, Instant};

    use fandhe_container_core::exec::{
        ChildExit, IsolationConfig, Namespace, NamespaceSet, ProbeOutcome, SeccompProbeRecord,
        StagePipeline, isolate, isolate_rootful_host_root, plan, plan_rootful_host_root,
        spawn_container_seccomp_probe,
    };

    /// Linux の `EPERM`（x86_64・aarch64 共通で 1）。
    const EPERM: i32 = 1;
    /// 子が pivot 後の `/` に書く記録（親からは `<rootfs>/seccomp-probe`）。
    const RECORD: &str = "seccomp-probe";

    fn timeout() -> Duration {
        let secs = std::env::var("FANDHE_CONTAINER_TEST_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|s| (1..=600).contains(s))
            .unwrap_or(10);
        Duration::from_secs(secs)
    }

    pub fn run() {
        let args: Vec<String> = std::env::args().collect();
        match args.iter().position(|a| a == "--scenario") {
            Some(i) => {
                let rootfs = args
                    .get(i + 2)
                    .expect("rootfs path after the scenario name");
                scenario(Path::new(rootfs));
            }
            None => dispatcher(),
        }
    }

    /// 一時 rootfs（drop で削除）。
    struct Rootfs(PathBuf);

    impl Drop for Rootfs {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// `proc/` だけを持つ rootfs を排他的に作る（推測されにくい名前・`mkdir` は既存なら失敗）。
    fn make_rootfs() -> Rootfs {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        let base = std::fs::canonicalize(std::env::temp_dir())
            .expect("canonicalize temp_dir")
            .join(format!("fandhe-seccomp-{}-{nanos}", std::process::id()));
        std::fs::create_dir(&base).expect("exclusively create rootfs dir");
        let rootfs = Rootfs(base);
        std::fs::set_permissions(&rootfs.0, std::fs::Permissions::from_mode(0o755))
            .expect("chmod rootfs dir");
        std::fs::create_dir(rootfs.0.join("proc")).expect("create rootfs/proc");
        rootfs
    }

    /// 子を期限付きで待つ。期限超過なら kill して回収し `None`（REPAIR-5）。
    fn wait_deadline(child: &mut std::process::Child, limit: Duration) -> Option<ExitStatus> {
        let deadline = Instant::now() + limit;
        loop {
            match child.try_wait().expect("try_wait") {
                Some(status) => return Some(status),
                None if Instant::now() >= deadline => {
                    let _ = child.kill();
                    let reap_deadline = Instant::now() + Duration::from_secs(5);
                    while child.try_wait().expect("try_wait").is_none() {
                        assert!(
                            Instant::now() < reap_deadline,
                            "the child was not reaped after SIGKILL"
                        );
                        std::thread::sleep(Duration::from_millis(20));
                    }
                    return None;
                }
                None => std::thread::sleep(Duration::from_millis(20)),
            }
        }
    }

    fn is_root() -> bool {
        std::fs::read_to_string("/proc/self/status")
            .expect("read status")
            .lines()
            .find(|l| l.starts_with("Uid:"))
            .and_then(|l| l.split_whitespace().nth(2).map(str::to_string))
            .as_deref()
            == Some("0")
    }

    fn dispatcher() {
        let exe = std::env::current_exe().expect("current_exe");
        let rootfs = make_rootfs();
        let mut child = Command::new(&exe)
            .args(["--scenario", "seccomp"])
            .arg(&rootfs.0)
            .stdin(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn scenario");
        let status = wait_deadline(&mut child, timeout())
            .unwrap_or_else(|| panic!("scenario did not exit within {:?}", timeout()));
        let mut stderr = String::new();
        child
            .stderr
            .take()
            .expect("piped stderr")
            .read_to_string(&mut stderr)
            .expect("read scenario stderr");
        assert_eq!(
            status.code(),
            Some(0),
            "seccomp scenario must exit with 0; stderr:\n{stderr}"
        );
        println!(
            "seccomp: CORE-5 denied syscalls blocked inside the container (root={})",
            is_root()
        );
    }

    /// 分離 → fork したコンテナ内でプローブ → 記録を具体値で照合する。
    fn scenario(rootfs: &Path) {
        let is_root = is_root();
        let mut namespaces = NamespaceSet::empty()
            .with(Namespace::Pid)
            .with(Namespace::Mount)
            .with(Namespace::Uts)
            .with(Namespace::Ipc);
        if !is_root {
            namespaces = namespaces.with(Namespace::User);
        }
        let config = IsolationConfig {
            namespaces,
            hostname: None,
        };
        let result = if is_root {
            plan_rootful_host_root(&config).and_then(|p| isolate_rootful_host_root(&p))
        } else {
            plan(&config).and_then(|p| isolate(&p))
        };
        result.unwrap_or_else(|err| panic!("isolate failed: {err}"));

        let child = spawn_container_seccomp_probe(rootfs, StagePipeline::new())
            .unwrap_or_else(|e| panic!("spawn: {e}"));
        let exit = child.wait_timeout(timeout()).unwrap_or_else(|e| {
            let _ = child.kill_and_reap(Duration::from_secs(5));
            panic!("wait: {e}")
        });
        assert_eq!(exit, ChildExit::Exited(0), "probe child must exit with 0");

        let text = std::fs::read_to_string(rootfs.join(RECORD))
            .unwrap_or_else(|e| panic!("read probe record: {e}"));
        let rec = SeccompProbeRecord::parse(&text).unwrap_or_else(|e| panic!("parse record: {e}"));

        // 識別的な検査（フィルタが無ければ unshare は成功・ptrace は ESRCH になる）。
        assert_eq!(rec.seccomp_mode, "2", "SECCOMP_MODE_FILTER");
        assert_eq!(rec.unshare, ProbeOutcome::Errno(EPERM), "unshare blocked");
        assert_eq!(rec.ptrace, ProbeOutcome::Errno(EPERM), "ptrace blocked");
        // 対照: 禁止対象外の操作は引き続き動く。
        assert_eq!(rec.control, ProbeOutcome::Ok, "control read of /proc");
        // 網羅確認（capability 不足でも EPERM になり得るため識別的な根拠ではない）。
        assert_eq!(rec.mount, ProbeOutcome::Errno(EPERM), "mount blocked");
        assert_eq!(
            rec.pivot_root,
            ProbeOutcome::Errno(EPERM),
            "pivot_root blocked"
        );
        assert_eq!(rec.umount2, ProbeOutcome::Errno(EPERM), "umount2 blocked");
        assert_eq!(
            rec.kexec_load,
            ProbeOutcome::Errno(EPERM),
            "kexec_load blocked"
        );
    }
}
