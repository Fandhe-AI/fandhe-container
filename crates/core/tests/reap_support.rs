//! 試験共有補助 `support/reap.rs`（全 crate の正本。#3410）の期限切れ経路の照合（REPAIR-5・REPAIR-12・#3302・#3409）。
//! 全 crate の試験が使う期限つき回収・期限つき実行（`run_within`・`output_within`）が、止まった子に対して無期限に待たず、具体的な
//! メッセージの `Err` で失敗を表に出すことを固定する。libtest ハーネス・全 OS で動く。

#[path = "support/reap.rs"]
mod reap;

#[cfg(unix)]
use std::os::unix::process::ExitStatusExt as _;
use std::process::{Child, Command};
use std::time::Duration;

const CHILD_ENV: &str = "FANDHE_CONTAINER_REAP_SUPPORT_CHILD";

/// 子の役。環境変数があるときだけ上限つきで眠る（通常実行では即座に返る no-op）。
#[test]
fn reap_support_child_blocks() {
    match std::env::var(CHILD_ENV).as_deref() {
        Ok("1") => std::thread::sleep(Duration::from_secs(30)),
        // 出力先を保持した孫の役。数秒眠り、試験プロセスの終了を待たずに自分で終わる。
        Ok("short") => std::thread::sleep(Duration::from_secs(10)),
        _ => {}
    }
}

/// 子の役。標準出力に固定の印を出して終わる。
#[test]
fn reap_support_child_prints() {
    if std::env::var(CHILD_ENV).as_deref() == Ok("print") {
        println!("REAP_MARK_STDOUT");
        eprintln!("REAP_MARK_STDERR");
    }
}

/// 子の役。役が `flood:<N>` なら標準出力へ N バイトを書いて終わり、`flood_forever` なら終了まで書き続ける。
#[test]
fn reap_support_child_floods() {
    use std::io::Write as _;
    let Ok(role) = std::env::var(CHILD_ENV) else {
        return;
    };
    let chunk = [b'x'; 4096];
    let mut out = std::io::stdout();
    if let Some(n) = role.strip_prefix("flood:") {
        let mut left: usize = n.parse().expect("flood size");
        while left > 0 {
            let k = left.min(chunk.len());
            out.write_all(&chunk[..k]).expect("write");
            left -= k;
        }
        out.flush().expect("flush");
    } else if role == "flood_forever" {
        // 親に kill されるまで書き続ける（上限で打ち切られることの確認用。念のため 60 秒で自分も止まる）。
        let until = std::time::Instant::now() + Duration::from_secs(60);
        while std::time::Instant::now() < until {
            if out.write_all(&chunk).is_err() {
                break;
            }
        }
    }
}

/// 子の役。出力先を継承した孫を起こして、自身は待たずに終了する。
#[test]
fn reap_support_child_leaves_holder() {
    if std::env::var(CHILD_ENV).as_deref() == Ok("holder") {
        let exe = std::env::current_exe().expect("current_exe");
        // 孫は待たずに残すのが目的（子が終了した後も出力先を保持させる）。
        #[allow(clippy::zombie_processes, reason = "孫を意図して待たずに残す")]
        Command::new(exe)
            .args(["--exact", "reap_support_child_blocks", "--test-threads=1"])
            .env(CHILD_ENV, "short")
            .spawn()
            .expect("spawn holder grandchild");
    }
}

/// 子の役。出力先を継承した孫（`flood_forever`）を起こし、`holder_flood` は自身も眠って待つ。
#[test]
fn reap_support_child_leaves_flooder() {
    if std::env::var(CHILD_ENV).as_deref() == Ok("holder_flood") {
        let exe = std::env::current_exe().expect("current_exe");
        // 孫は待たずに残すのが目的（子の終了後も書き続けさせる）。
        #[allow(clippy::zombie_processes, reason = "孫を意図して待たずに残す")]
        Command::new(exe)
            .args(["--exact", "reap_support_child_floods", "--test-threads=1"])
            .env(CHILD_ENV, "flood_forever")
            .spawn()
            .expect("spawn flooding grandchild");
    }
}

fn self_cmd(test: &str, role: &str) -> Command {
    let exe = std::env::current_exe().expect("current_exe");
    let mut cmd = Command::new(exe);
    cmd.args(["--exact", test, "--nocapture", "--test-threads=1"])
        .env(CHILD_ENV, role);
    cmd
}

/// 試験が途中で panic しても子を残さないためのガード。
struct Guard(Child);

impl Drop for Guard {
    fn drop(&mut self) {
        reap::reap_on_drop(&mut self.0);
    }
}

fn spawn_self(blocks: bool) -> Guard {
    let exe = std::env::current_exe().expect("current_exe");
    let mut cmd = Command::new(exe);
    cmd.args(["--exact", "reap_support_child_blocks", "--test-threads=1"]);
    if blocks {
        cmd.env(CHILD_ENV, "1");
    }
    Guard(cmd.spawn().expect("spawn self as child"))
}

#[test]
fn repair5_wait_within_reports_expiry() {
    let mut g = spawn_self(true);
    let pid = g.0.id();
    let err = reap::wait_within(&mut g.0, Duration::from_millis(200)).expect_err("must expire");
    assert_eq!(err, format!("child {pid} did not exit within 200ms"));
    reap::reap(&mut g.0, Duration::from_secs(10)).expect("reap after kill");
    assert!(g.0.try_wait().expect("try_wait").is_some());
    #[cfg(unix)]
    assert_eq!(
        g.0.try_wait().expect("try_wait").expect("reaped").signal(),
        Some(9)
    );
}

#[test]
fn repair5_reap_is_ok_for_already_reaped_child() {
    let mut g = spawn_self(false);
    reap::wait_within(&mut g.0, Duration::from_secs(10)).expect("child exits by itself");
    reap::reap(&mut g.0, Duration::from_secs(10)).expect("reaping a reaped child is Ok");
}

#[test]
fn repair5_run_within_reports_expiry_and_reaps() {
    let mut cmd = self_cmd("reap_support_child_blocks", "1");
    let program = cmd.get_program().to_string_lossy().into_owned();
    let err = reap::run_within(&mut cmd, Duration::from_millis(200)).expect_err("must expire");
    assert_eq!(err, format!("{program} did not finish within 200ms"));
}

#[test]
fn repair5_run_within_returns_success_status() {
    let mut cmd = self_cmd("reap_support_child_blocks", "none");
    let st = reap::run_within(&mut cmd, Duration::from_secs(30)).expect("child exits by itself");
    assert!(st.success(), "status: {st}");
}

#[test]
fn repair5_output_within_returns_stdout_and_stderr() {
    let mut cmd = self_cmd("reap_support_child_prints", "print");
    let out = reap::output_within(&mut cmd, Duration::from_secs(30)).expect("output");
    assert!(out.status.success(), "status: {}", out.status);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stdout.contains("REAP_MARK_STDOUT"), "stdout: {stdout}");
    assert!(stderr.contains("REAP_MARK_STDERR"), "stderr: {stderr}");
}

#[test]
fn repair5_output_within_reports_expiry() {
    let mut cmd = self_cmd("reap_support_child_blocks", "1");
    let program = cmd.get_program().to_string_lossy().into_owned();
    let err = reap::output_within(&mut cmd, Duration::from_millis(300)).expect_err("must expire");
    assert_eq!(err, format!("{program} did not finish within 300ms"));
}

/// 受け入れ条件 2: 子の終了後に孫が出力先を持ち続けても、pipe の EOF を待たずに戻る
/// （`wait_with_output()` ならこの孫が眠る間ずっと戻らない）。
#[test]
fn repair5_output_within_returns_when_descendant_holds_output() {
    let mut cmd = self_cmd("reap_support_child_leaves_holder", "holder");
    let start = std::time::Instant::now();
    let out = reap::output_within(&mut cmd, Duration::from_secs(30)).expect("output");
    assert!(out.status.success(), "status: {}", out.status);
    assert!(
        start.elapsed() < Duration::from_secs(5),
        "returned late: {:?}",
        start.elapsed()
    );
}

#[test]
fn repair5_run_within_reports_spawn_failure() {
    let missing = std::env::temp_dir().join("fandhe-container-reap-support-no-such-program");
    let program = missing.to_string_lossy().into_owned();
    let mut cmd = Command::new(&missing);
    let err = reap::run_within(&mut cmd, Duration::from_secs(10)).expect_err("spawn must fail");
    assert!(
        err.starts_with(&format!("spawn {program} failed: ")),
        "unexpected message: {err}"
    );
}

const FLOOD_TEST: &str = "reap_support_child_floods";

/// 上限以下の出力は完全に返る。
#[test]
fn repair5_repair12_output_under_cap_is_returned_in_full() {
    let mut cmd = self_cmd(FLOOD_TEST, "flood:1000");
    // 子はテストハーネスの出力（"running 1 test" 等）も stdout に出すため、上限は十分大きく取る。
    let out = reap::output_within_capped(&mut cmd, Duration::from_secs(30), 1 << 20)
        .expect("small output");
    let n = out.stdout.iter().filter(|b| **b == b'x').count();
    assert_eq!(n, 1000);
}

/// 指摘 1: 上限を超えた出力は先頭だけを返さず `Err`（後続のパス漏れ等を見逃さない）。
#[test]
fn repair5_repair12_output_over_cap_is_err() {
    let mut cmd = self_cmd(FLOOD_TEST, "flood:100000");
    let program = cmd.get_program().to_string_lossy().into_owned();
    let err = reap::output_within_capped(&mut cmd, Duration::from_secs(30), 4096)
        .expect_err("over cap must fail");
    assert!(
        err == format!("{program} stdout exceeded the 4096 byte capture cap")
            || err == format!("{program}: stdout: output exceeded the 4096 byte capture cap"),
        "unexpected message: {err}"
    );
}

/// 指摘 3: 書き続ける子は上限で打ち切られ、保存量が上限付近で止まり、期限まで待たない。
#[test]
fn repair5_repair12_endless_output_is_cut_at_cap() {
    let mut cmd = self_cmd(FLOOD_TEST, "flood_forever");
    let program = cmd.get_program().to_string_lossy().into_owned();
    let start = std::time::Instant::now();
    let err = reap::output_within_capped(&mut cmd, Duration::from_secs(40), 64 * 1024)
        .expect_err("endless output must fail");
    assert_eq!(
        err,
        format!("{program} stdout exceeded the 65536 byte capture cap")
    );
    assert!(
        start.elapsed() < Duration::from_secs(20),
        "not cut early: {:?}",
        start.elapsed()
    );
}

/// 指摘 3: 上限超過で捨てた後、一時ファイルは残らない（spawn_captured 経路でも finish が Err）。
#[test]
fn repair5_repair12_captured_finish_rejects_over_cap_and_removes_files() {
    let mut cmd = self_cmd(FLOOD_TEST, "flood:50000");
    let (mut child, captured) =
        reap::spawn_captured_capped(&mut cmd, 1024).expect("spawn captured");
    let st = reap::wait_within(&mut child, Duration::from_secs(30)).expect("exit");
    let out_path = captured.out_path.clone();
    let err = captured.finish(st).expect_err("over cap");
    assert_eq!(err, "stdout: output exceeded the 1024 byte capture cap");
    assert!(!out_path.exists(), "temp file left: {}", out_path.display());
}

/// 指摘 2: 読み取りの失敗（存在しない・読めない）は空出力にせず `Err`。
#[test]
fn repair5_repair12_drain_reports_open_and_read_failure() {
    let dir = std::env::temp_dir();
    let missing = dir.join(format!("fc-reap-test-missing-{}", std::process::id()));
    let err = reap::drain_output_file(&missing, 1024).expect_err("missing file");
    assert!(
        err.starts_with(&format!("open output file {}: ", missing.display())),
        "unexpected message: {err}"
    );
    // ディレクトリは Unix では open が成功して read が失敗し、Windows では open が失敗する。どちらも `Err`。
    let sub = dir.join(format!("fc-reap-test-dir-{}", std::process::id()));
    std::fs::create_dir_all(&sub).expect("mkdir");
    let err = reap::drain_output_file(&sub, 1024);
    let _ = std::fs::remove_dir(&sub);
    let err = err.expect_err("directory is not readable as a file");
    assert!(
        err.starts_with(&format!("open output file {}: ", sub.display()))
            || err.starts_with(&format!("read output file {}: ", sub.display())),
        "unexpected message: {err}"
    );
}

/// P1: 子が終了した後も出力先へ書き続ける孫は、`finish` の前にグループごと止められる。
/// 孫の書き込み先は同じ inode のため、止まらなければ削除後も増え続ける。止めたことは、`finish` の後に孫の
/// プロセスが居なくなること（`/proc` で pid が消える）で確かめる。
#[cfg(target_os = "linux")]
#[test]
fn repair5_repair12_finish_kills_descendant_that_keeps_writing() {
    let mut cmd = self_cmd("reap_support_child_leaves_flooder", "holder_flood");
    let (mut child, captured) =
        reap::spawn_captured_capped(&mut cmd, 1 << 30).expect("spawn captured");
    let pgid = child.id();
    let st = reap::wait_within(&mut child, Duration::from_secs(30)).expect("child exit");
    // 孫が同じグループに居る（子の pid を pgid とするメンバーが残っている）ことを確認する。
    assert!(
        group_members(pgid) >= 1,
        "no flooding grandchild in group {pgid}"
    );
    let out_path = captured.out_path.clone();
    let _ = captured.finish(st);
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while group_members(pgid) > 0 && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(group_members(pgid), 0, "grandchild survived finish");
    assert!(!out_path.exists());
}

/// プロセスグループ `pgid` のメンバー数（/proc/<pid>/stat の第 5 フィールド pgrp で数える。ゾンビは除く）。
#[cfg(target_os = "linux")]
fn group_members(pgid: u32) -> usize {
    let mut n = 0;
    for e in std::fs::read_dir("/proc").expect("read /proc").flatten() {
        let Ok(stat) = std::fs::read_to_string(e.path().join("stat")) else {
            continue;
        };
        // comm は括弧で囲まれ空白を含みうるため、最後の ')' の後ろから数える: state ppid pgrp ...
        let Some(rest) = stat.rsplit_once(')').map(|(_, r)| r) else {
            continue;
        };
        let f: Vec<&str> = rest.split_whitespace().collect();
        if f.first() != Some(&"Z") && f.get(2).and_then(|v| v.parse::<u32>().ok()) == Some(pgid) {
            n += 1;
        }
    }
    n
}

/// P2: `spawn_captured` の待機（`Captured::wait_within`）でも保存量を監視し、書き続ける子を期限前に `Err` にする。
#[test]
fn repair5_repair12_captured_wait_cuts_endless_output_before_deadline() {
    let mut cmd = self_cmd(FLOOD_TEST, "flood_forever");
    let (mut child, captured) =
        reap::spawn_captured_capped(&mut cmd, 64 * 1024).expect("spawn captured");
    let start = std::time::Instant::now();
    let err = captured
        .wait_within(&mut child, Duration::from_secs(40))
        .expect_err("endless output must fail");
    assert_eq!(err, "stdout exceeded the 65536 byte capture cap");
    assert!(
        start.elapsed() < Duration::from_secs(20),
        "not cut early: {:?}",
        start.elapsed()
    );
    assert!(
        child.try_wait().expect("try_wait").is_some(),
        "child not reaped"
    );
    let out_path = captured.out_path.clone();
    captured.discard();
    assert!(!out_path.exists());
}
