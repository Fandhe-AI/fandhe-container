//! `SECCOMP_RET_KILL_PROCESS` で終了した 3 件（`unshare`・`ptrace`・`kexec_load`）が、カーネル監査の
//! `AUDIT_SECCOMP` 記録として残ることの実機試験（SEC-4・ESC-06・CORE-5・TASK-41 追補・#2004）。
//!
//! # 位置づけ
//!
//! 強制終了したプロセスは自分では記録を書けない。正の記録（syscall・arch・pid）はカーネル自身が出す
//! `AUDIT_SECCOMP` で、`seccomp_data` の `actions_logged` に `kill_process` がある限り記録される
//! （`SECCOMP_FILTER_FLAG_LOG` は不要。`docs/design/audit-delivery.md`）。fandhe は読み手を持たず、
//! 本試験は auditd の `ausearch` で記録を読んで照合する。コンテナ経由の補助レコード（層 `exit_signal`）の
//! 実機確認は未整備（`oci_runtime::launch` の単体テストのみ）。本試験の子は本番の seccomp フィルタを適用した非コンテナの
//! プロセスである（rootful の本番 launcher 起動が SEC-5 で拒否されるため）。
//!
//! # 実行モード
//!
//! - 既定（`--ignored` なし）: 実機不要。`ausearch` の出力を照合する純関数を fixture で確かめるだけ。
//!   実機部分は動かないため、成功行は `seccomp_kill_audit: unit ok` で区別する
//! - `--ignored`（実機前提）: root で auditd が動いていることが必要。`/var/log/audit` は root しか読めず、
//!   GitHub ホステッド runner では保証できないため既定の集合から分離している。前提（root・`ausearch`・
//!   `actions_logged` の `kill_process`）を満たさなければ失敗にする（検証せず成功する分岐は持たない）。
//!   `harness = false` の単一スレッド `main` で動かす（seccomp の適用が不可逆のため）

#[cfg(target_os = "linux")]
#[path = "support/proc_status.rs"]
mod proc_status;

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("seccomp_kill_audit: Linux only, not applicable on this OS");
}

#[cfg(all(
    target_os = "linux",
    not(all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))
))]
fn main() {
    println!("seccomp_kill_audit: x86_64/aarch64 only, not applicable on this architecture");
}

#[cfg(all(
    target_os = "linux",
    all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
/// `msg=audit(<秒>.<ミリ秒>:<連番>)` の秒部分を取り出す。
fn audit_epoch_secs(line: &str) -> Option<u64> {
    let rest = line.split("msg=audit(").nth(1)?;
    let secs = rest.split('.').next()?;
    secs.parse().ok()
}

#[cfg(all(
    target_os = "linux",
    all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
/// `ausearch --raw` の出力から、`pid`・`sig=31`・`code=0x80000000`・`arch`・`syscall` が
/// すべて空白区切りのフィールドとして完全一致し、かつ記録時刻が `min_epoch_secs` 以上の
/// `type=SECCOMP` 行の件数を数える（部分一致はしない。`comm`・`exe` はコンテナが操作できるため解釈しない）。
/// `min_epoch_secs` は子の起動前に取った時刻で、PID 再利用による過去の記録を除く（SEC-4・REPAIR-12）。
fn count_matching_seccomp_records(
    raw: &str,
    pid: u32,
    arch: &str,
    syscall: u32,
    min_epoch_secs: u64,
) -> usize {
    let want = [
        format!("pid={pid}"),
        "sig=31".to_string(),
        "code=0x80000000".to_string(),
        format!("arch={arch}"),
        format!("syscall={syscall}"),
    ];
    raw.lines()
        .filter(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            fields.contains(&"type=SECCOMP")
                && want.iter().all(|w| fields.contains(&w.as_str()))
                && audit_epoch_secs(line).is_some_and(|t| t >= min_epoch_secs)
        })
        .count()
}

#[cfg(all(
    target_os = "linux",
    all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
/// `actions_logged`（空白区切りの許可リスト）に `kill_process` があるか。
fn actions_logged_has_kill_process(actions: &str) -> bool {
    actions.split_whitespace().any(|a| a == "kill_process")
}

#[cfg(all(
    target_os = "linux",
    all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
fn main() {
    use std::io::Read as _;
    use std::os::unix::process::ExitStatusExt as _;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    use fandhe_container_core::exec::{KilledSyscall, observe_default_seccomp_kill};

    /// `(名前, 種別, x86_64 の番号, aarch64 の番号)`。番号は各アーキの syscall 表の値。
    const KILLED: [(&str, KilledSyscall, u32, u32); 3] = [
        ("unshare", KilledSyscall::Unshare, 272, 97),
        ("ptrace", KilledSyscall::Ptrace, 101, 117),
        ("kexec_load", KilledSyscall::KexecLoad, 246, 104),
    ];
    #[cfg(target_arch = "x86_64")]
    const ARCH: &str = "c000003e";
    #[cfg(target_arch = "aarch64")]
    const ARCH: &str = "c00000b7";
    const AUSEARCH: &str = "/usr/sbin/ausearch";
    const ACTIONS_LOGGED: &str = "/proc/sys/kernel/seccomp/actions_logged";

    /// kill 後に有限の猶予（2 秒）で子を回収する。回収できなければ false（REPAIR-5）。
    fn reap_bounded(child: &mut std::process::Child) -> bool {
        let _ = child.kill();
        let limit = Instant::now() + Duration::from_secs(2);
        while Instant::now() < limit {
            match child.try_wait() {
                Ok(Some(_)) => return true,
                Ok(None) => std::thread::sleep(Duration::from_millis(10)),
                Err(_) => return false,
            }
        }
        false
    }

    /// `ausearch` を spawn し、1 回あたり 10 秒で打ち切る（REPAIR-5）。
    /// 期限超過は kill して有限の猶予で回収し、出力が途中で切れている可能性があるため
    /// 全量として扱わず panic で失敗にする。stdout は別スレッドで読み、完了待ちにも期限を設ける。
    /// PATH 探索はせず絶対パスで実行する。
    fn run_ausearch_bounded(pid: &str) -> String {
        let mut child = Command::new(AUSEARCH)
            .args(["-m", "SECCOMP", "-p", pid, "--raw"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("run ausearch (root and auditd required)");
        let mut stdout = child.stdout.take().expect("ausearch stdout");
        let (tx, rx) = std::sync::mpsc::channel::<Vec<u8>>();
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = stdout.read_to_end(&mut buf);
            let _ = tx.send(buf);
        });
        let limit = Instant::now() + Duration::from_secs(10);
        loop {
            match child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) => {}
                Err(e) => {
                    let reaped = reap_bounded(&mut child);
                    panic!("try_wait ausearch failed: {e} (reaped={reaped})");
                }
            }
            if Instant::now() >= limit {
                let reaped = reap_bounded(&mut child);
                panic!("ausearch exceeded 10s; output may be truncated (reaped={reaped})");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        match rx.recv_timeout(Duration::from_secs(3)) {
            Ok(buf) => String::from_utf8_lossy(&buf).into_owned(),
            Err(_) => panic!("ausearch stdout reader did not finish within 3s"),
        }
    }

    let args: Vec<String> = std::env::args().collect();
    if let Some(i) = args.iter().position(|a| a == "--child-kill") {
        let name = args.get(i + 1).expect("syscall name after --child-kill");
        let (_, which, _, _) = KILLED
            .iter()
            .find(|(n, ..)| n == name)
            .unwrap_or_else(|| panic!("unknown syscall {name}"));
        // 正常ならここで SIGSYS により終了して戻らない。
        let r = observe_default_seccomp_kill(*which);
        println!("seccomp_kill_audit child-kill: returned {r:?}");
        std::process::exit(1);
    }

    // 純関数の具体値照合（実機不要）。
    let fixture = format!(
        "type=SECCOMP msg=audit(1.1:5): auid=1000 uid=1000 pid=4242 comm=\"x\" exe=\"/x\" sig=31 arch={ARCH} syscall=272 compat=0 ip=0x1 code=0x80000000\n\
         type=SECCOMP msg=audit(1.2:6): pid=4243 sig=31 arch={ARCH} syscall=272 code=0x80000000\n\
         type=SECCOMP msg=audit(1.3:7): pid=42421 sig=31 arch={ARCH} syscall=272 code=0x80000000\n\
         type=SECCOMP msg=audit(1.4:8): pid=4242 sig=31 arch={ARCH} syscall=101 code=0x80000000\n"
    );
    assert_eq!(
        count_matching_seccomp_records(&fixture, 4242, ARCH, 272, 1),
        1,
        "exact field match only"
    );
    assert_eq!(
        count_matching_seccomp_records(&fixture, 4242, ARCH, 999, 1),
        0
    );
    // 境界より前の記録（PID 再利用で残る過去分）は数えない。
    assert_eq!(
        count_matching_seccomp_records(&fixture, 4242, ARCH, 272, 2),
        0,
        "records before the boundary are ignored"
    );
    assert!(actions_logged_has_kill_process(
        "kill_process kill_thread trap errno user_notif trace log"
    ));
    assert!(!actions_logged_has_kill_process("kill_thread trap errno"));

    if !args.iter().any(|a| a == "--ignored") {
        println!("seccomp_kill_audit: unit ok (real-machine part needs --ignored)");
        return;
    }

    // 実機前提: root・ausearch・actions_logged。満たさなければ失敗にする。
    let actions = std::fs::read_to_string(ACTIONS_LOGGED).expect("read actions_logged");
    assert!(
        actions_logged_has_kill_process(&actions),
        "actions_logged must contain kill_process: {actions}"
    );
    let exe = std::env::current_exe().expect("current_exe");
    for (name, _, x86_nr, arm_nr) in KILLED {
        let nr = if cfg!(target_arch = "x86_64") {
            x86_nr
        } else {
            arm_nr
        };
        // 子の起動前に境界時刻を取る（監査の記録時刻は同じ実時間。1 秒の丸めに備え切り捨てる）。
        let start_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_secs();
        let mut child = Command::new(&exe)
            .args(["--child-kill", name])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn child");
        let pid = child.id();
        let deadline = Instant::now() + Duration::from_secs(30);
        let status = loop {
            match child.try_wait() {
                Ok(Some(s)) => break s,
                Ok(None) => {}
                Err(e) => {
                    let reaped = reap_bounded(&mut child);
                    panic!("try_wait child {name} failed: {e} (reaped={reaped})");
                }
            }
            if Instant::now() >= deadline {
                let diag = crate::proc_status::excerpt(pid);
                let reaped = reap_bounded(&mut child);
                panic!("child {name} timed out (reaped={reaped}; {diag})");
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        assert_eq!(status.signal(), Some(31), "{name} must die with SIGSYS");

        // 記録の反映を最大 5 秒ポーリングする（REPAIR-5）。PATH 探索はせず絶対パスで実行する。
        let until = Instant::now() + Duration::from_secs(5);
        let count = loop {
            let raw = run_ausearch_bounded(&pid.to_string());
            let n = count_matching_seccomp_records(&raw, pid, ARCH, nr, start_secs);
            if n > 0 || Instant::now() >= until {
                break n;
            }
            std::thread::sleep(Duration::from_millis(200));
        };
        assert_eq!(
            count, 1,
            "{name}: exactly one AUDIT_SECCOMP record (pid={pid} arch={ARCH} syscall={nr})"
        );
    }
    println!("seccomp_kill_audit: ok");
}
