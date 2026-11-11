//! `netns-dial` helper の実プロセス経路の非特権結合試験（CRI-6・NET-3・SEC-1・REPAIR-5・REPAIR-12・#4479。Linux のみ）。
//!
//! 自身の実行ファイルを helper として再実行する（第 1 引数 `netns-dial` なら `run_netns_dial_main`）ため
//! `harness = false`。公開入口 `run_netns_dial_main` を通し、argv の検査・stdin の素性確認・peer 検証・継承 fd の整理・
//! 受信の期限・要求の検証・前検査・参加の失敗を、終了コードと固定語彙の応答 frame の具体値で照合する。
//! 実際の namespace への参加・capability の破棄・connect の成功と接続済み fd の返送は非特権 user namespace を要するため
//! `netns_dial_userns`（`--ignored`）が担う。root も user namespace も不要で、3 OS の既定集合で実行する。
//! 待ちはすべて `FANDHE_CONTAINER_TEST_TIMEOUT_SECS`（既定 10 秒）で期限を切る（REPAIR-5）。

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("netns_dial_process: Linux only, not applicable on this OS");
}

#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    let mut args = std::env::args_os();
    let _exe = args.next();
    match args.next() {
        Some(a) if a == fandhe_container_net::netns_dial::NETNS_DIAL_SUBCOMMAND => {
            fandhe_container_net::netns_dial::run_netns_dial_main(args)
        }
        _ => linux::run(),
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::fs::File;
    use std::io::Read as _;
    use std::num::NonZeroU16;
    use std::os::fd::{AsFd as _, OwnedFd};
    use std::process::{Child, Command, ExitCode, Stdio};
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    use fandhe_container_net::netns_dial::test_support::{recv_raw, send_raw, seqpacket_pair};
    use fandhe_container_net::netns_dial::{
        ConnectTimeout, DialErrorCode, DialRequest, DialRequestFrame, DialResponse,
        DialResponseFrame, REQUEST_RECV_TIMEOUT,
    };

    const OK_LINE: &str = "netns_dial_process: argv, stdin identity, peer check, fd cleanup, deadline and fixed-vocabulary responses passed (SEC-1)";

    fn limit() -> Duration {
        let secs = std::env::var("FANDHE_CONTAINER_TEST_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|s| (1..=600).contains(s))
            .unwrap_or(10);
        Duration::from_secs(secs)
    }

    fn check(cond: bool, msg: impl FnOnce() -> String) -> Result<(), String> {
        if cond { Ok(()) } else { Err(msg()) }
    }

    fn exe() -> std::path::PathBuf {
        std::env::current_exe().expect("current_exe")
    }

    /// 起動した helper。stderr は契約どおり null のはずなので pipe にして空であることも照合する。
    struct Helper {
        child: Child,
        parent: OwnedFd,
        stderr: mpsc::Receiver<String>,
    }

    fn drain(child: &mut Child) -> mpsc::Receiver<String> {
        let mut stderr = child.stderr.take().expect("stderr piped");
        let (tx, rx) = mpsc::channel::<String>();
        std::thread::spawn(move || {
            let mut s = String::new();
            let _ = stderr.read_to_string(&mut s);
            let _ = tx.send(s);
        });
        rx
    }

    /// `cmd` を stdin = seqpacket 対の子の端、stdout = null、stderr = pipe で起動する。
    fn spawn_with(mut cmd: Command) -> Result<Helper, String> {
        let (parent, child_end) = seqpacket_pair().map_err(|e| e.to_string())?;
        let mut child = cmd
            .env_clear()
            .stdin(Stdio::from(child_end))
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("spawn helper: {e}"))?;
        let stderr = drain(&mut child);
        Ok(Helper {
            child,
            parent,
            stderr,
        })
    }

    fn spawn_helper(extra: &[&str]) -> Result<Helper, String> {
        let mut cmd = Command::new(exe());
        cmd.arg("netns-dial").args(extra);
        spawn_with(cmd)
    }

    impl Helper {
        /// 終了を待ち、終了コードを返す。期限切れは kill して失敗にする。stderr は空でなければ失敗。
        fn wait_code(&mut self) -> Result<i32, String> {
            let started = Instant::now();
            loop {
                if let Some(st) = self.child.try_wait().map_err(|e| e.to_string())? {
                    let text = self
                        .stderr
                        .recv_timeout(Duration::from_secs(5))
                        .unwrap_or_default();
                    check(text.is_empty(), || format!("unexpected stderr {text:?}"))?;
                    return st.code().ok_or_else(|| format!("no exit code: {st}"));
                }
                if started.elapsed() > limit() {
                    let _ = self.child.kill();
                    let _ = self.child.wait();
                    return Err("helper did not exit in time".into());
                }
                std::thread::sleep(Duration::from_millis(5));
            }
        }

        /// 応答 frame を 1 通受けて復号する。`None` は応答なしの EOF。
        fn response(&mut self) -> Result<Option<(DialResponse, usize)>, String> {
            let got = recv_raw(self.parent.as_fd(), limit()).map_err(|e| e.to_string())?;
            let Some((bytes, fds)) = got else {
                return Err("no response and no EOF within the limit".into());
            };
            if bytes.is_empty() {
                return Ok(None);
            }
            let r = DialResponseFrame::decode(&bytes).map_err(|e| format!("decode: {e:?}"))?;
            Ok(Some((r, fds.len())))
        }

        fn send(&self, bytes: &[u8], fds: &[&File]) -> Result<(), String> {
            let borrowed: Vec<_> = fds.iter().map(|f| f.as_fd()).collect();
            send_raw(self.parent.as_fd(), bytes, &borrowed).map_err(|e| e.to_string())
        }
    }

    fn request_bytes() -> Vec<u8> {
        let req = DialRequest::new(
            NonZeroU16::new(9).expect("nonzero"),
            ConnectTimeout::new(1000).expect("range"),
        );
        DialRequestFrame::encode(req).as_bytes().to_vec()
    }

    fn open(path: &str) -> Result<File, String> {
        File::open(path).map_err(|e| format!("open {path}: {e}"))
    }

    /// 要求を送って「応答 = `Error(code)`・fd 0 本・終了コード 1」を確かめる。
    fn expect_error(
        label: &str,
        bytes: &[u8],
        fds: &[&File],
        code: DialErrorCode,
    ) -> Result<(), String> {
        let mut h = spawn_helper(&[])?;
        h.send(bytes, fds)?;
        let r = h.response()?;
        check(r == Some((DialResponse::Error(code), 0)), || {
            format!("{label}: response {r:?}, want Error({})", code.as_str())
        })?;
        let exit = h.wait_code()?;
        check(exit == 1, || format!("{label}: exit code {exit}, want 1"))
    }

    fn scenario() -> Result<(), String> {
        // argv: 非空は応答なしで終了コード 2（副作用の前に検査する）。
        let mut h = spawn_helper(&["--extra"])?;
        let exit = h.wait_code()?;
        check(exit == 2, || format!("extra argv exit {exit}, want 2"))?;
        check(h.response()?.is_none(), || {
            "extra argv: unexpected response".into()
        })?;

        // stdin が seqpacket でない（pipe）: 応答せず終了コード 1。
        let mut child = Command::new(exe())
            .arg("netns-dial")
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("spawn: {e}"))?;
        let rx = drain(&mut child);
        let st = wait_child(&mut child)?;
        check(st == 1, || format!("pipe stdin exit {st}, want 1"))?;
        check(
            rx.recv_timeout(Duration::from_secs(5))
                .unwrap_or_default()
                .is_empty(),
            || "pipe stdin: unexpected stderr".into(),
        )?;

        // peer 検証: socketpair の作成者（本プロセス）が helper の親でない（sh が親）なら応答せず終了コード 1。
        let mut cmd = Command::new("sh");
        cmd.args(["-c", "\"$0\" netns-dial; exit $?"]).arg(exe());
        let mut h = spawn_with(cmd)?;
        check(h.response()?.is_none(), || {
            "peer mismatch: unexpected response".into()
        })?;
        let exit = h.wait_code()?;
        check(exit == 1, || format!("peer mismatch exit {exit}, want 1"))?;

        // 継承 fd の整理: fd 3 に stdout の pipe の書き込み端を継承させる。要求を待つ間（期限 2 秒）に整理済みなら
        // 読み側が EOF になる（整理していなければ helper が生きている間は EOF にならない）。
        let (parent, child_end) = seqpacket_pair().map_err(|e| e.to_string())?;
        let mut child = Command::new("sh")
            .args(["-c", "exec \"$0\" netns-dial 3>&1 1>/dev/null"])
            .arg(exe())
            .env_clear()
            .stdin(Stdio::from(child_end))
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("spawn: {e}"))?;
        let rx = drain(&mut child);
        let mut out = child.stdout.take().ok_or("stdout")?;
        let (tx, eof) = mpsc::channel::<usize>();
        std::thread::spawn(move || {
            let mut s = Vec::new();
            let _ = out.read_to_end(&mut s);
            let _ = tx.send(s.len());
        });
        let got = eof.recv_timeout(REQUEST_RECV_TIMEOUT.saturating_sub(Duration::from_millis(500)));
        let alive = child.try_wait().map_err(|e| e.to_string())?.is_none();
        let outcome = check(got == Ok(0) && alive, || {
            format!("fd 3 was not closed while waiting (eof {got:?}, alive {alive})")
        });
        drop(parent);
        let _ = wait_child(&mut child);
        let _ = rx.recv_timeout(Duration::from_secs(5));
        outcome?;

        // 受信の期限: 何も送らなければ REQUEST_RECV_TIMEOUT 付近で InvalidRequest（TimedOut ではない）。
        let started = Instant::now();
        let mut h = spawn_helper(&[])?;
        let r = h.response()?;
        let elapsed = started.elapsed();
        check(
            r == Some((DialResponse::Error(DialErrorCode::InvalidRequest), 0)),
            || format!("deadline: response {r:?}, want Error(InvalidRequest)"),
        )?;
        check(
            elapsed >= REQUEST_RECV_TIMEOUT.saturating_sub(Duration::from_millis(300))
                && elapsed < REQUEST_RECV_TIMEOUT + limit(),
            || format!("deadline: responded after {elapsed:?}"),
        )?;
        let exit = h.wait_code()?;
        check(exit == 1, || format!("deadline exit {exit}, want 1"))?;

        // 要求の検証と前検査（いずれも InvalidRequest。参加はしない）。
        let user = open("/proc/self/ns/user")?;
        let net = open("/proc/self/ns/net")?;
        let net2 = open("/proc/self/ns/net")?;
        let req = request_bytes();
        let bad = DialErrorCode::InvalidRequest;
        expect_error("fd 0 本", &req, &[], bad)?;
        expect_error("fd 1 本", &req, &[&user], bad)?;
        expect_error("fd 3 本", &req, &[&user, &net, &net2], bad)?;
        expect_error("短い frame", &req[..8], &[&user, &net], bad)?;
        expect_error("同一 ns の 2 本", &req, &[&net, &net2], bad)?;

        // 参加の失敗: 別々の ns だが setns(user) が拒否される（自分の user namespace へは参加できない）→ JoinFailed。
        expect_error(
            "setns 拒否",
            &req,
            &[&user, &net],
            DialErrorCode::JoinFailed,
        )
    }

    fn wait_child(child: &mut Child) -> Result<i32, String> {
        let started = Instant::now();
        loop {
            if let Some(st) = child.try_wait().map_err(|e| e.to_string())? {
                return st.code().ok_or_else(|| format!("no exit code: {st}"));
            }
            if started.elapsed() > limit() {
                let _ = child.kill();
                let _ = child.wait();
                return Err("child did not exit in time".into());
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    pub fn run() -> ExitCode {
        match scenario() {
            Ok(()) => {
                println!("{OK_LINE}");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("netns_dial_process: FAILED: {e}");
                ExitCode::from(1)
            }
        }
    }
}
