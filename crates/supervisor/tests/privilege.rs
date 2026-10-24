//! sudo（pty の保持者）を SIGKILL しても、切り離した子孫が動き続けることの結合試験
//! （SUP-14・TASK-171.3・#538・MS-9。PoC-17 の発見事項 1）。
//!
//! 背景: `sudo`（`use_pty`）は子を fork して pty 越しに中継する。この `sudo` を `SIGKILL` すると pty の master が
//! 閉じ、同じセッションの子孫（supervisor・ランタイム・コンテナ本体）が SIGHUP で巻き添えになる。対策の要素 (B) が
//! `privilege::detach_session`（TASK-171.2・#537。ランチャーの入口で `elevate` より前に呼ぶ）で、本試験はその
//! 効果を実カーネルで確かめる。
//!
//! 模擬の根拠: root と sudoers が要る実 `sudo` の代わりに、util-linux の `script` を中継プロセスに使う。`script` も
//! pty の master を握り、子に新しいセッションと制御端末を与えて動かす点が `sudo`（`use_pty`）と同じ構造である。
//! 実 `sudo` と実ランチャーでの通し確認は人間担当の #539、子での ambient の取りこぼしは TASK-161.2 の healthcheck exec（#2441）・#539。
//!
//! 対照プロセス（`role-attached`）: 切り離さずに同じ pty セッションに置くプロセスが `script` の SIGKILL で
//! 実際に消えることを必須にする。消えなければこの環境ではハングアップが起きておらず、試験が空振りで通るため失敗にする。
//!
//! 前提: Linux・util-linux の `script`・`/dev/pts` が使えること。前提が無いときは skip せず失敗する。
//! `harness = false`: `setsid` がプロセス全体に効くため、切り離す役は別プロセスとして自己再実行する。
//! 待機はすべて期限付き（REPAIR-5）。root・新規の unsafe・新規の依存は使わない。

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("privilege: Linux only, not applicable on this OS");
}

#[cfg(target_os = "linux")]
fn main() {
    linux::main();
}

#[cfg(target_os = "linux")]
mod linux {
    use fandhe_container_core::traits::ErrorCode;
    use fandhe_container_supervisor::privilege::{self, PrivilegeErrorReason};
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};

    const ENV_DIR: &str = "FANDHE_T538_DIR";
    const ENV_SELF: &str = "FANDHE_T538_SELF";
    /// 役の寿命の上限。試験が異常終了しても孤児が残らないようにする。
    const ROLE_LIFETIME: Duration = Duration::from_secs(30);
    const READY_TIMEOUT: Duration = Duration::from_secs(10);
    const GONE_TIMEOUT: Duration = Duration::from_secs(5);
    const MAX_STAT_READ: u64 = 4096;

    pub fn main() {
        let args: Vec<String> = std::env::args().collect();
        match args.get(1).map(String::as_str) {
            Some("role-detached") => role_detached(),
            Some("role-workload") => role_simple("workload"),
            Some("role-attached") => role_simple("attached"),
            Some("role-detach-on-pty") => role_detach_on_pty(),
            _ => {
                // 各シナリオは Result を返し、Work を破棄（後始末）した後にここで非ゼロ終了する。
                let result = check_script_available()
                    .and_then(|()| detached_descendants_survive_sigkill_of_pty_holder())
                    .and_then(|()| pty_stdio_is_refused_inside_pty_session());
                match result {
                    Ok(()) => println!("privilege: all scenarios passed"),
                    Err(msg) => {
                        eprintln!("privilege: FAILED: {msg}");
                        std::process::exit(1);
                    }
                }
            }
        }
    }

    type Res<T = ()> = Result<T, String>;

    fn check(ok: bool, msg: &str) -> Res {
        if ok { Ok(()) } else { Err(msg.to_string()) }
    }

    // ---- 共通の小関数 ----

    #[derive(Debug, Clone, Copy)]
    struct ProcInfo {
        state: char,
        starttime: u64,
    }

    fn read_proc(pid: u32) -> Option<ProcInfo> {
        use std::io::Read;
        let mut text = String::new();
        fs::File::open(format!("/proc/{pid}/stat"))
            .ok()?
            .take(MAX_STAT_READ)
            .read_to_string(&mut text)
            .ok()?;
        let rest = text.get(text.rfind(')')? + 1..)?;
        let mut it = rest.split_whitespace();
        let state = it.next()?.chars().next()?;
        // state の次から数えて 19 個目の後ろが starttime（stat の 22 番目のフィールド）。
        let starttime = it.nth(18)?.parse::<u64>().ok()?;
        Some(ProcInfo { state, starttime })
    }

    fn is_alive(pid: u32, starttime: u64) -> bool {
        matches!(read_proc(pid), Some(p) if p.starttime == starttime && matches!(p.state, 'R' | 'S' | 'D'))
    }

    fn write_atomic(path: &Path, text: &str) {
        let tmp = path.with_extension("tmp");
        let ok = fs::write(&tmp, text).is_ok() && fs::rename(&tmp, path).is_ok();
        if !ok {
            std::process::exit(2);
        }
    }

    fn wait_until(deadline: Duration, mut f: impl FnMut() -> bool) -> bool {
        let end = Instant::now() + deadline;
        loop {
            if f() {
                return true;
            }
            if Instant::now() >= end {
                return false;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn dir_from_env() -> PathBuf {
        PathBuf::from(std::env::var(ENV_DIR).unwrap_or_else(|_| std::process::exit(2)))
    }

    /// 自分の情報を `<name>.ready` に書く。形式: `pid session pgrp tty_nr starttime sighup_ignored`。
    fn write_ready(dir: &Path, name: &str) {
        let pid = std::process::id();
        let text = fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default();
        let (Ok(snap), Some(me)) = (privilege::parse_proc_stat(&text), read_proc(pid)) else {
            std::process::exit(2)
        };
        let sigign = fs::read_to_string("/proc/self/status")
            .unwrap_or_default()
            .lines()
            .find_map(|l| l.strip_prefix("SigIgn:"))
            .and_then(|v| u64::from_str_radix(v.trim(), 16).ok())
            .unwrap_or(0);
        write_atomic(
            &dir.join(format!("{name}.ready")),
            &format!(
                "{} {} {} {} {} {}",
                pid,
                snap.session,
                snap.pgrp,
                snap.tty_nr,
                me.starttime,
                sigign & 1
            ),
        );
    }

    /// stop ファイルか寿命の上限まで heartbeat を書き続ける。
    fn heartbeat_loop(dir: &Path, name: &str) {
        let start = Instant::now();
        let mut n: u64 = 0;
        while !dir.join("stop").exists() && start.elapsed() < ROLE_LIFETIME {
            n += 1;
            write_atomic(&dir.join(format!("{name}.hb")), &n.to_string());
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    // ---- 役 ----

    /// supervisor の代役。入口で切り離し、ランタイム・コンテナ本体の代役を子として起動する。
    fn role_detached() {
        let dir = dir_from_env();
        if let Err(e) = privilege::detach_session() {
            write_atomic(
                &dir.join("detached.ready"),
                &format!("error {:?} {:?} {}", e.code, e.reason, e.message),
            );
            std::process::exit(1);
        }
        write_ready(&dir, "detached");
        let Ok(me) = std::env::current_exe() else {
            std::process::exit(2)
        };
        let Ok(mut child) = Command::new(me)
            .arg("role-workload")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        else {
            std::process::exit(2)
        };
        heartbeat_loop(&dir, "detached");
        if wait_child(&mut child, GONE_TIMEOUT).is_err() {
            std::process::exit(2);
        }
    }

    /// 子の終了を期限付きで待つ。期限内に終わらなければ強制終了し、回収も有限時間で打ち切る（REPAIR-5）。
    /// 回収できなかった・kill に失敗した場合は Err を返す。
    fn wait_child(child: &mut Child, limit: Duration) -> Res {
        if wait_until(limit, || matches!(child.try_wait(), Ok(Some(_)))) {
            return Ok(());
        }
        kill_and_reap(child)
    }

    /// 子を SIGKILL して、有限時間で回収する。すでに終了済みの子は成功として扱う。
    fn kill_and_reap(child: &mut Child) -> Res {
        if let Err(e) = child.kill() {
            // 終了済みなら kill は InvalidInput を返す。回収できるなら問題にしない。
            if !matches!(child.try_wait(), Ok(Some(_))) {
                return Err(format!("cannot kill child: {e}"));
            }
        }
        if wait_until(GONE_TIMEOUT, || matches!(child.try_wait(), Ok(Some(_)))) {
            Ok(())
        } else {
            Err("child was not reaped after SIGKILL within the timeout".to_string())
        }
    }

    /// コンテナ本体の代役（切り離し済みセッションの子）または対照（切り離さない）。
    fn role_simple(name: &str) {
        let dir = dir_from_env();
        write_ready(&dir, name);
        heartbeat_loop(&dir, name);
    }

    fn role_detach_on_pty() {
        let dir = dir_from_env();
        let text = match privilege::detach_session() {
            Err(e) => format!("error {:?} {:?} {}", e.code, e.reason, e.message),
            Ok(_) => "ok".to_string(),
        };
        write_atomic(&dir.join("pty.result"), &text);
    }

    // ---- 試験側 ----

    fn check_script_available() -> Res {
        // `status()` は期限なしで待つため、spawn と期限付き try_wait で確かめる。
        let ok = match Command::new("script")
            .arg("--version")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        {
            Ok(mut c) => {
                let mut success = false;
                let done = wait_until(READY_TIMEOUT, || match c.try_wait() {
                    Ok(Some(st)) => {
                        success = st.success();
                        true
                    }
                    Ok(None) => false,
                    Err(_) => true,
                });
                if !done {
                    kill_and_reap(&mut c)?;
                }
                success
            }
            Err(_) => false,
        };
        check(
            ok,
            "util-linux `script` is required (the test needs a pty holder to kill)",
        )
    }

    /// 作業ディレクトリ。Drop で stop を作って役を止め、ディレクトリを消す。
    struct Work {
        dir: PathBuf,
        child: Option<Child>,
        _stdin: Option<std::process::ChildStdin>,
    }

    impl Work {
        fn new(tag: &str) -> Res<Self> {
            use std::os::unix::fs::PermissionsExt;
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            let dir = std::env::temp_dir()
                .join(format!("fandhe-t538-{tag}-{}-{nanos}", std::process::id()));
            fs::create_dir(&dir).map_err(|e| format!("cannot create work dir: {e}"))?;
            let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));
            Ok(Work {
                dir,
                child: None,
                _stdin: None,
            })
        }

        fn start_script(&mut self, inner: &str) -> Res {
            let me = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;
            let mut child = Command::new("script")
                .args(["-qec", inner, "/dev/null"])
                .env("SHELL", "/bin/sh")
                .env(ENV_DIR, &self.dir)
                .env(ENV_SELF, &me)
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .map_err(|e| format!("cannot spawn script: {e}"))?;
            // stdin を保持して EOF による script の早期終了を防ぐ。
            self._stdin = child.stdin.take();
            self.child = Some(child);
            Ok(())
        }

        fn read_ready(&self, name: &str) -> Res<Vec<i64>> {
            let path = self.dir.join(format!("{name}.ready"));
            if !wait_until(READY_TIMEOUT, || path.exists()) {
                return Err(format!("{name}.ready did not appear"));
            }
            let text = fs::read_to_string(&path).unwrap_or_default();
            if text.starts_with("error") {
                return Err(format!("{name} reported: {text}"));
            }
            let v: Vec<i64> = text
                .split_whitespace()
                .filter_map(|s| s.parse().ok())
                .collect();
            check(v.len() == 6, &format!("{name}.ready malformed: {text:?}"))?;
            Ok(v)
        }

        fn hb(&self, name: &str) -> u64 {
            fs::read_to_string(self.dir.join(format!("{name}.hb")))
                .ok()
                .and_then(|s| s.trim().parse().ok())
                .unwrap_or(0)
        }
    }

    impl Drop for Work {
        fn drop(&mut self) {
            let _ = fs::write(self.dir.join("stop"), "");
            if let Some(c) = self.child.as_mut()
                && let Err(e) = wait_child(c, GONE_TIMEOUT)
            {
                eprintln!("privilege: cleanup: {e}");
            }
            // 役が stop を見て終わるのを待ってから消す。
            std::thread::sleep(Duration::from_millis(200));
            let _ = fs::remove_dir_all(&self.dir);
        }
    }

    /// SUP-14・TASK-171.3: pty の保持者を SIGKILL しても、切り離した子孫は動き続ける（切り離さない対照は消える）。
    fn detached_descendants_survive_sigkill_of_pty_holder() -> Res {
        let mut w = Work::new("a")?;
        // exec は使わない（代役がセッションリーダーになり tty_nr != 0 で拒否されるため）。
        w.start_script(
            "\"$FANDHE_T538_SELF\" role-attached & \
             \"$FANDHE_T538_SELF\" role-detached </dev/null >/dev/null 2>&1 & wait",
        )?;
        let att = w.read_ready("attached")?;
        let det = w.read_ready("detached")?;
        let wl = w.read_ready("workload")?;
        // [pid, session, pgrp, tty_nr, starttime, sighup_ignored]
        check(
            att.get(3).copied().unwrap_or(0) != 0,
            "attached has no controlling tty",
        )?;
        check(
            att.get(5).copied() == Some(0),
            "SIGHUP is ignored; the negative control is invalid",
        )?;
        check(
            det.first() == det.get(1) && det.first() == det.get(2) && det.get(3) == Some(&0),
            "detached is not a session leader without a tty",
        )?;
        check(det.get(1) != att.get(1), "detached shares the pty session")?;
        check(
            wl.get(1) == det.first() && wl.get(3) == Some(&0),
            "workload is not in the detached session",
        )?;

        if let Some(c) = w.child.as_mut() {
            kill_and_reap(c)?;
        }

        let (ap, at) = (att[0] as u32, att[4] as u64);
        check(
            wait_until(GONE_TIMEOUT, || !is_alive(ap, at)),
            "negative control survived: pty hangup did not propagate",
        )?;

        let (d0, w0) = (w.hb("detached"), w.hb("workload"));
        std::thread::sleep(Duration::from_millis(500));
        check(
            w.hb("detached") > d0,
            "detached stopped after SIGKILL of the pty holder",
        )?;
        check(
            w.hb("workload") > w0,
            "workload stopped after SIGKILL of the pty holder",
        )?;
        check(
            is_alive(det[0] as u32, det[4] as u64),
            "detached is not alive in /proc",
        )?;
        check(
            is_alive(wl[0] as u32, wl[4] as u64),
            "workload is not alive in /proc",
        )?;
        Ok(())
    }

    /// SUP-14・#537: pty 経由の標準入出力は昇格前に拒否される（sudo の use_pty 起動は設計どおり弾く）。
    fn pty_stdio_is_refused_inside_pty_session() -> Res {
        let mut w = Work::new("b")?;
        w.start_script("\"$FANDHE_T538_SELF\" role-detach-on-pty")?;
        let path = w.dir.join("pty.result");
        check(
            wait_until(READY_TIMEOUT, || path.exists()),
            "pty.result did not appear",
        )?;
        let text = fs::read_to_string(&path).unwrap_or_default();
        let want = format!(
            "error {:?} {:?} stdin, stdout and stderr must not be terminals",
            ErrorCode::FailedPrecondition,
            PrivilegeErrorReason::StdioIsTerminal
        );
        check(
            text.starts_with(&want),
            &format!("unexpected result: {text:?}"),
        )
    }
}
