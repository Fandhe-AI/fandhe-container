//! 起動したコンテナプロセスの中で禁止 syscall が遮断されることの結合試験（CORE-5・TASK-38.4・#179。
//! REPAIR-12 の機械照合）。
//!
//! `seccomp_enforcement`（#178）は使い捨ての子で適用経路を呼ぶ検証にとどまる。本試験は、
//! `with_landlock` を載せたステージ列で試験バイナリ自身を `/entry` として exec した実際のコンテナプロセス
//! （新しい PID namespace の PID 1・pivot_root 後・capability 削減・`NO_NEW_PRIVS` 設定済み。
//! `tests/support/real_entry.rs`。#2386・REPAIR-3）の**エントリポイントの中**で、ステージ列の**組み込み
//! `Seccomp` 段**が載せたフィルタが禁止 syscall を拒否することを照合する。`ERRNO(EPERM)` の syscall は、
//! エントリポイントが `probe_denied_syscalls_for_test` で観測して pivot 後の `/seccomp-probe` へ書いた記録
//! （`SeccompProbeRecord`）の具体値で照合する。`KILL_PROCESS` の
//! `unshare`・`ptrace`・`kexec_load`（ESC-06。`DeniedSyscall::deny_action`）は戻らず記録を書けないため、
//! 1 件ずつ別のコンテナで、エントリポイント（`/entry --entry kill-<名前>`）の中から発行し、親が終了シグナル
//! SIGSYS（31）を照合する（#2543・REPAIR-3）。`production_launcher` の
//! シナリオ J・K は本番 launcher 経由の exec 後の拒否を照合する（#2012）。
//!
//! # 識別的な検査と網羅確認
//! - 識別的（capability 不足ではなく seccomp が拒否したことを示せる）: `kcmp(自 pid, 自 pid, KCMP_VM)`
//!   （フィルタが無ければ成功）・`/proc/thread-self/status` の `Seccomp: 2`。
//!   禁止対象外の対照（`/proc` の読み出し）が動くことも確認する。適用前の対照として、組み込み段を載せる前に
//!   `kcmp(自 pid, 自 pid)` が成功することも要求する（`Seccomp: 0` の検査では見分けられない、seccomp 以外の理由で
//!   kcmp が通らない環境〔kcmp 非対応のカーネル・LSM〕と外側の拒否を検出する。満たさなければ skip せず前提欠如として失敗。#2234）
//! - 網羅確認: `mount`・`pivot_root`・`umount2` が `EPERM`。capability 不足でも
//!   `EPERM` になり得るため、識別的な根拠とは扱わない
//! - 強制終了: `unshare`・`ptrace`・`kexec_load` は別のコンテナのエントリポイントで SIGSYS 終了
//!   （`ChildExit::Signaled(31)`）。プローブが戻って終了コード 0 で終われば（フィルタ欠落）失敗
//!
//! x32 番号の `SECCOMP_RET_KILL_PROCESS` は本試験では扱わない（BPF の単体テストが照合する）。
//!
//! # 構成
//! - 常に走る部分（3 OS 共通・既定のテスト集合）: プローブ対象が `DeniedSyscall::ALL` に含まれること、
//!   記録の解析の自己テスト
//! - 実機前提部分（Linux x86_64 / aarch64。`-- --ignored` 指定時のみ）: ディスパッチャが自身を
//!   `--scenario seccomp <rootfs>` で再起動する（`unshare(CLONE_NEWPID)` の後に PID 1 になれるのは最初の
//!   子だけのため）。
//!
//! # 実機前提テストとしての分離
//! root もしくは非特権 user namespace を許可するホストと、Landlock ABI 6 以上（Linux 6.12 以上）が必要
//! （`with_landlock` を載せて exec まで到達させるため。満たさなければ検出の失敗で panic）。GitHub ホステッド
//! runner で保証できないため `-- --ignored` 指定時のみ実行する（ci.md「実機前提テスト」）。プローブの
//! 引数は、フィルタが欠けていてもホストへ副作用が出ないもの（attach を伴わない ptrace・segment 数超過の
//! kexec_load・コンテナの mount namespace に閉じる mount 系）に固定している。実行された場合は分離の拒否・
//! 事前条件の不成立を含めあらゆる失敗を失敗として扱い、検証せずに成功する分岐は持たない。

#[cfg(target_os = "linux")]
use fandhe_container_core::exec::{ProbeOutcome, SeccompProbeRecord};
use fandhe_container_core::seccomp::DeniedSyscall;

#[cfg(all(
    target_os = "linux",
    all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
#[path = "support/real_entry.rs"]
mod real_entry;

/// 結合試験が errno を照合する禁止 syscall の論理名（`DeniedSyscall::ALL` に含まれる必要がある）。
const PROBED: [&str; 7] = [
    "kcmp",
    "mount",
    "pivot_root",
    "umount2",
    "unshare",
    "ptrace",
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

/// 記録の解析を固定文字列で自己検証する（`exec` は Linux 限定のため Linux のみ）（具体値・欠落・重複・未知キー・不正値の検出）。
#[cfg(target_os = "linux")]
fn core5_record_parser_selftest() {
    let ok = "kcmp=errno=1\nseccomp_mode=2\ncontrol=ok\nmount=errno=1\n\
              pivot_root=errno=1\numount2=errno=1\n";
    let rec = SeccompProbeRecord::parse(ok).expect("well-formed record");
    assert_eq!(rec.kcmp, ProbeOutcome::Errno(1));
    assert_eq!(rec.seccomp_mode, "2");
    assert_eq!(rec.control, ProbeOutcome::Ok);
    assert_eq!(rec.render(), ok, "render must round-trip");
    let missing = ok.replace("umount2=errno=1\n", "");
    assert_eq!(
        SeccompProbeRecord::parse(&missing),
        Err("missing key \"umount2\"".to_string())
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
    let bad = ok.replace("kcmp=errno=1", "kcmp=errno=x");
    assert_eq!(
        SeccompProbeRecord::parse(&bad),
        Err("invalid outcome \"errno=x\"".to_string())
    );
}

fn always() {
    core5_probed_names_are_in_deny_table();
    #[cfg(target_os = "linux")]
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
    not(all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))
))]
fn main() {
    always();
    println!(
        "seccomp: real-process part is x86_64/aarch64 only, not applicable on this architecture"
    );
}

#[cfg(all(
    target_os = "linux",
    all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
fn main() {
    // exec 後のエントリポイント（`/entry --entry seccomp-probe`）は他のどの判定よりも先に分ける。
    // 後ろに置くとコンテナ内のプロセスが "ignored" を出して 0 で終わり、親が記録の欠落で失敗する。
    if std::env::args().any(|a| a == "--entry") {
        linux::entry_main();
    }
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
    all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
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
    };
    use fandhe_container_core::exec::{
        DevptsGidSource, EscapeSyscallProbe, probe_denied_syscalls_for_test, probe_escape_syscall,
        probe_kcmp_self_for_test, spawn_container_with_stages_and_devices,
    };
    use fandhe_container_core::rootless::single_id_mapping;

    use super::real_entry;

    /// Linux の `EPERM`（x86_64・aarch64 共通で 1）。
    const EPERM: i32 = 1;
    /// Linux の `SIGSYS`（x86_64・aarch64 共通で 31）。
    const SIGSYS: i32 = 31;
    /// 強制終了（`KILL_PROCESS`）の対象と、そのシナリオ名（ESC-06）。エントリポイントのモードは `kill-<名前>`。
    const KILLED: [(&str, EscapeSyscallProbe); 3] = [
        ("unshare", EscapeSyscallProbe::Unshare),
        ("ptrace", EscapeSyscallProbe::Ptrace),
        ("kexec_load", EscapeSyscallProbe::KexecLoad),
    ];
    /// 子が pivot 後の `/` に書く記録（親からは `<rootfs>/seccomp-probe`）。
    const RECORD: &str = "seccomp-probe";
    /// kill 系のエントリポイントで発行が戻ってきた（フィルタ欠落）ときに書く印（親からは `<rootfs>/seccomp-kill-returned`）。
    const KILL_RETURNED: &str = "seccomp-kill-returned";

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
                let name = args.get(i + 1).expect("scenario name");
                let rootfs = args
                    .get(i + 2)
                    .expect("rootfs path after the scenario name");
                match name.as_str() {
                    "seccomp" => scenario(Path::new(rootfs)),
                    other => {
                        let (n, _) = KILLED
                            .iter()
                            .find(|(n, _)| other.strip_prefix("kill-") == Some(n))
                            .unwrap_or_else(|| panic!("unknown scenario {other}"));
                        scenario_kill(Path::new(rootfs), n);
                    }
                }
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

    /// 自プロセスの `Seccomp:` 行の値（`/proc/self/status`）。
    fn seccomp_mode_of_self() -> String {
        std::fs::read_to_string("/proc/self/status")
            .expect("read status")
            .lines()
            .find_map(|l| l.strip_prefix("Seccomp:").map(|v| v.trim().to_string()))
            .expect("Seccomp line in /proc/self/status")
    }

    /// シナリオを自身の再実行で起動し、期限付きで待つ。終了状態と stderr を返す。
    fn run_scenario(name: &str) -> (ExitStatus, String) {
        let exe = std::env::current_exe().expect("current_exe");
        let rootfs = make_rootfs();
        let mut child = Command::new(&exe)
            .args(["--scenario", name])
            .arg(&rootfs.0)
            .stdin(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn scenario");
        let status = wait_deadline(&mut child, timeout())
            .unwrap_or_else(|| panic!("scenario {name} did not exit within {:?}", timeout()));
        let mut stderr = String::new();
        child
            .stderr
            .take()
            .expect("piped stderr")
            .read_to_string(&mut stderr)
            .expect("read scenario stderr");
        (status, stderr)
    }

    fn dispatcher() {
        let (status, stderr) = run_scenario("seccomp");
        assert_eq!(
            status.code(),
            Some(0),
            "seccomp scenario must exit with 0; stderr:\n{stderr}"
        );
        // 強制終了対象は戻らないため、シナリオ（親）は子の SIGSYS 終了を確認して 0 で終わる。
        for (name, _) in KILLED {
            let (status, stderr) = run_scenario(&format!("kill-{name}"));
            assert_eq!(
                status.code(),
                Some(0),
                "kill-{name} scenario must exit with 0; stderr:\n{stderr}"
            );
        }
        println!(
            "seccomp: CORE-5 denied syscalls blocked inside the container (root={})",
            is_root()
        );
    }

    /// シナリオ共通の分離（このプロセスを PID 1 の namespace 内へ入れる）。
    fn isolate_scenario() {
        let is_root = is_root();
        // 適用前の対照観測: このシナリオ自身（= 組み込み段を載せる前）に seccomp フィルタが無いこと。
        // 継承したフィルタ（コンテナ・サンドボックス上のテストランナー等）が既にあると、後段の
        // `Seccomp: 2` や `EPERM` は組み込みフィルタの成果と区別できないため、失敗として扱う（CORE-5・REPAIR-12）。
        // 適用前の kcmp 対照: 組み込み段の前で kcmp が成功すること。外側の拒否（seccomp・LSM・kcmp 非対応）は
        // `Seccomp: 0` の検査では見分けられないため、skip せず前提欠如として失敗させる（CORE-5・ESC-06・#2234）。
        let kcmp_before = probe_kcmp_self_for_test();
        assert_eq!(
            kcmp_before,
            ProbeOutcome::Ok,
            "precondition failed: kcmp(self, self) must succeed before the built-in seccomp stage (got {kcmp_before:?}, Seccomp: {}); the outer environment already denies kcmp (e.g. Docker's default seccomp profile, a kernel without kcmp, or an LSM), so EPERM inside the container cannot be attributed to the built-in filter",
            seccomp_mode_of_self()
        );
        assert_eq!(
            seccomp_mode_of_self(),
            "0",
            "precondition: the test process must not inherit a seccomp filter (cannot attribute the denial to the built-in stage)"
        );
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
    }

    /// 強制終了対象の syscall をエントリポイント内で 1 件発行させ、SIGSYS で終了したことを照合する
    /// （ESC-06・CORE-5・SEC-2・#2543）。
    fn scenario_kill(rootfs: &Path, name: &str) {
        let child = spawn_entry(rootfs, &format!("kill-{name}"));
        let exit = child.wait_timeout(timeout()).unwrap_or_else(|e| {
            let _ = child.kill_and_reap(Duration::from_secs(5));
            panic!("wait: {e}")
        });
        if exit == ChildExit::Exited(0) {
            // 発行が戻った（フィルタ欠落）。エントリポイントが残した印を、外部入力として上限つきで添える。
            let mut mark = String::new();
            if let Ok(f) = std::fs::File::open(rootfs.join(KILL_RETURNED)) {
                let _ = f.take(4096).read_to_string(&mut mark);
            }
            panic!(
                "kill-{name} returned instead of being killed (filter missing); entrypoint reported: {mark:?}"
            );
        }
        assert_eq!(
            exit,
            ChildExit::Signaled(SIGSYS),
            "kill-{name} must kill the process with SIGSYS (KILL_PROCESS)"
        );
    }

    /// 分離 → `with_landlock` を載せて `/entry --entry <mode>` を exec したコンテナを起動する
    /// （`scenario` と `scenario_kill` の共通部分）。
    fn spawn_entry(rootfs: &Path, mode: &str) -> fandhe_container_core::exec::ContainerChild {
        let is_root = is_root();
        // 分離（user namespace）の前に読む。入ると gid が 0 に見えるため。
        let egid = host_egid();
        isolate_scenario();

        let ld = real_entry::install_entry(rootfs);
        let entry =
            real_entry::entrypoint_from(&real_entry::entry_args(mode), &real_entry::entry_env(&ld));
        let stages = StagePipeline::new()
            .with_landlock(real_entry::landlock_ruleset())
            .unwrap_or_else(|e| panic!("register landlock: {e}"));
        // root は gid 0 を写せない（`single_id_mapping` は SEC-5 で host_id == 0 を拒否する）ため `Rootful`。
        if is_root {
            spawn_container_with_stages_and_devices(
                rootfs,
                &entry,
                stages,
                DevptsGidSource::Rootful,
            )
        } else {
            let gid_map = single_id_mapping(egid).expect("single id mapping");
            spawn_container_with_stages_and_devices(
                rootfs,
                &entry,
                stages,
                DevptsGidSource::Rootless(&gid_map),
            )
        }
        .unwrap_or_else(|e| panic!("spawn: {e}"))
    }

    /// 分離の前の実効 gid（`/proc/self/status` の `Gid:` の 2 列目。user namespace に入ると 0 に見えるため、
    /// rootless の devpts の gid 判定に分離前の値を使う）。
    fn host_egid() -> u32 {
        std::fs::read_to_string("/proc/self/status")
            .expect("read status")
            .lines()
            .find(|l| l.starts_with("Gid:"))
            .and_then(|l| l.split_whitespace().nth(2).map(str::to_string))
            .and_then(|v| v.parse().ok())
            .expect("parse egid")
    }

    /// 印を `create_new` で書く（失敗しても呼び出し側は非 0 で終わるだけ）。
    fn write_new(name: &str, body: &str) -> bool {
        use std::io::Write as _;
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(Path::new("/").join(name))
            .and_then(|mut f| {
                f.write_all(body.as_bytes())?;
                f.sync_all()
            })
            .is_ok()
    }

    /// exec 後のエントリポイント（コンテナ内の PID 1。標準入出力は `/dev/null`）。モードは `--entry` の次の引数。
    /// - `seccomp-probe`: 禁止 syscall を観測して `/seccomp-probe` へ書く。失敗は何も書かずに非 0 で終わる。
    /// - `kill-<名前>`: `KILL_PROCESS` の syscall を発行する。戻れば（フィルタ欠落）印を書いて 0 で終わり、
    ///   親が失敗にする。
    /// - 未知・欠落: ファイルシステムに触れず非 0 で終わる。
    pub fn entry_main() -> ! {
        let args: Vec<String> = std::env::args().collect();
        let mode = args
            .iter()
            .position(|a| a == "--entry")
            .and_then(|i| args.get(i + 1))
            .map(String::as_str);
        match mode {
            Some("seccomp-probe") => {
                let Ok(rec) = probe_denied_syscalls_for_test() else {
                    std::process::exit(3);
                };
                std::process::exit(if write_new(RECORD, &rec.render()) {
                    0
                } else {
                    4
                });
            }
            Some(m) => {
                let Some((_, which)) = KILLED
                    .iter()
                    .find(|(n, _)| m.strip_prefix("kill-") == Some(n))
                else {
                    std::process::exit(5);
                };
                // コアダンプによる遅延は `probe_escape_syscall` が RLIMIT_CORE を 0 にして避ける。
                let outcome = probe_escape_syscall(*which);
                write_new(KILL_RETURNED, &format!("{outcome:?}\n"));
                std::process::exit(0);
            }
            None => std::process::exit(5),
        }
    }

    /// 分離 → `with_landlock` を載せて `/entry` を exec → エントリポイント内の観測の記録を具体値で照合する。
    fn scenario(rootfs: &Path) {
        let child = spawn_entry(rootfs, "seccomp-probe");
        let exit = child.wait_timeout(timeout()).unwrap_or_else(|e| {
            let _ = child.kill_and_reap(Duration::from_secs(5));
            panic!("wait: {e}")
        });
        assert_eq!(exit, ChildExit::Exited(0), "entrypoint must exit with 0");

        // 記録はコンテナが書いた外部入力として、上限つきで読む。
        let mut text = String::new();
        std::fs::File::open(rootfs.join(RECORD))
            .unwrap_or_else(|e| panic!("open probe record: {e}"))
            .take(4096)
            .read_to_string(&mut text)
            .unwrap_or_else(|e| panic!("read probe record: {e}"));
        let rec = SeccompProbeRecord::parse(&text).unwrap_or_else(|e| panic!("parse record: {e}"));

        // 識別的な検査（フィルタが無ければ kcmp は成功する）。
        assert_eq!(rec.seccomp_mode, "2", "SECCOMP_MODE_FILTER");
        assert_eq!(
            rec.kcmp,
            ProbeOutcome::Errno(EPERM),
            "kcmp blocked by the built-in filter (the pre-stage control succeeded)"
        );
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
    }
}
