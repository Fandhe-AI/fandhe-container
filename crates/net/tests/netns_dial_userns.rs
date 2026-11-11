//! netns-dial helper が非特権の user + network namespace へ実際に参加し、その namespace の中から connect することを
//! 照合する実機前提テスト（CRI-6・NET-3・SEC-1・REPAIR-5・REPAIR-12・#4479）。
//!
//! # 流れ
//! - 親（`-- --ignored`）: `unshare --user --map-root-user --net sleep` で対象の namespace を作り、その
//!   `/proc/<pid>/ns/{user,net}` を helper（自身を `netns-dial` で再実行）へ送る。同じ番号の TCP port を、親（init の
//!   network namespace）の `127.0.0.1` で listen しておく。
//! - 照合（具体値）: helper は `JoinFailed` / `IdentityMismatch` を返さず参加と特権の破棄まで進み、対象 namespace の
//!   中から connect する。対象の `lo` は down で listener も無いため `Unreachable` か `Refused` が返り、fd は添わず、終了コードは 1、
//!   stderr は空。親の listener は接続を 1 本も受けない（helper が init の network namespace から connect していない証拠）。
//!
//! 接続が成功して接続済み fd が返る経路と、参加後の capability の破棄・non-dumpable の個別の確認は、`Joiner` を差し替えた
//! `helper` のユニットテストと本試験の参加の成否で担保する（本試験は参加後の helper の状態を外から読まない。
//! 読むには helper を生かしたままにする必要があり、固定語彙の応答と終了コードの契約を変えるため）。
//!
//! # 前提
//! 非特権 user namespace（AppArmor の `kernel.apparmor_restrict_unprivileged_userns=1` がない環境）と util-linux の
//! `unshare` が要る。root は不要。前提を満たさない場合は skip せず失敗する。`harness = false` で `--ignored` が
//! 渡らなくても exit 0 になるため、CI は成功行を照合して false-green を防ぐ（AGENTS.md「実機前提テスト」）。
//! 待ちはすべて `FANDHE_CONTAINER_TEST_TIMEOUT_SECS`（既定 10 秒）で期限を切る（REPAIR-5）。Linux のみ。

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("netns_dial_userns: Linux only, not applicable on this OS");
}

#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    let mut args = std::env::args_os();
    let _exe = args.next();
    match args.next() {
        Some(a) if a == fandhe_container_net::netns_dial::NETNS_DIAL_SUBCOMMAND => {
            fandhe_container_net::netns_dial::run_netns_dial_main(args)
        }
        Some(a) if a == "--ignored" => linux::run(),
        _ => {
            println!(
                "netns_dial_userns: ignored (real-machine test; run with `-- --ignored`, see AGENTS.md)"
            );
            std::process::ExitCode::SUCCESS
        }
    }
}

#[cfg(target_os = "linux")]
#[path = "../../core/tests/support/reap.rs"]
mod reap;

#[cfg(target_os = "linux")]
mod linux {
    use super::reap;
    use std::fs::File;
    use std::io::Read as _;
    use std::net::{Ipv4Addr, TcpListener};
    use std::num::NonZeroU16;
    use std::os::fd::AsFd as _;
    use std::os::unix::fs::MetadataExt as _;
    use std::process::{Child, Command, ExitCode, Stdio};
    use std::time::{Duration, Instant};

    use fandhe_container_net::netns_dial::test_support::{recv_raw, send_raw, seqpacket_pair};
    use fandhe_container_net::netns_dial::{
        ConnectTimeout, DialErrorCode, DialRequest, DialRequestFrame, DialResponse,
        DialResponseFrame,
    };

    const OK_LINE: &str = "netns_dial_userns: helper joined the target user+net namespaces and dialed from inside them";

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

    fn ns_identity(path: &str) -> Result<(u64, u64), String> {
        let m = std::fs::metadata(path).map_err(|e| format!("stat {path}: {e}"))?;
        Ok((m.dev(), m.ino()))
    }

    /// 対象: 新しい user + network namespace に入った `sleep`（`netns_holder_userns` と同じ待ち方）。
    fn spawn_target() -> Result<Child, String> {
        let own_user = ns_identity("/proc/self/ns/user")?;
        let mut child = Command::new("unshare")
            .args(["--user", "--map-root-user", "--net", "sleep", "60"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| {
                format!("cannot spawn `unshare` (util-linux missing or not permitted): {e}")
            })?;
        let pid = child.id();
        let started = Instant::now();
        loop {
            let comm = std::fs::read_to_string(format!("/proc/{pid}/comm")).unwrap_or_default();
            let user = ns_identity(&format!("/proc/{pid}/ns/user"));
            if comm.trim() == "sleep" && user.as_ref().is_ok_and(|u| *u != own_user) {
                return Ok(child);
            }
            if let Some(st) = child.try_wait().map_err(|e| e.to_string())? {
                return Err(format!(
                    "`unshare` exited early with {st} (unprivileged user namespaces unavailable?)"
                ));
            }
            if started.elapsed() > limit() {
                reap::reap(&mut child, limit())?;
                return Err("target namespaces were not created in time".into());
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn scenario(target_pid: u32) -> Result<(), String> {
        // 親の network namespace の 127.0.0.1 で待ち受ける。helper が対象の namespace へ参加していなければここへ繋がる。
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).map_err(|e| e.to_string())?;
        listener.set_nonblocking(true).map_err(|e| e.to_string())?;
        let port = listener.local_addr().map_err(|e| e.to_string())?.port();

        let user = File::open(format!("/proc/{target_pid}/ns/user")).map_err(|e| e.to_string())?;
        let net = File::open(format!("/proc/{target_pid}/ns/net")).map_err(|e| e.to_string())?;
        let (parent, child_end) = seqpacket_pair().map_err(|e| e.to_string())?;
        let mut child = Command::new(std::env::current_exe().map_err(|e| e.to_string())?)
            .arg("netns-dial")
            .env_clear()
            .stdin(Stdio::from(child_end))
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("spawn helper: {e}"))?;
        let mut stderr = child.stderr.take().ok_or("stderr")?;
        let req = DialRequest::new(
            NonZeroU16::new(port).ok_or("port 0")?,
            ConnectTimeout::new(3000).map_err(|e| format!("{e:?}"))?,
        );
        let bytes = DialRequestFrame::encode(req);
        send_raw(
            parent.as_fd(),
            bytes.as_bytes(),
            &[user.as_fd(), net.as_fd()],
        )
        .map_err(|e| e.to_string())?;
        let got = recv_raw(parent.as_fd(), limit()).map_err(|e| e.to_string())?;
        let started = Instant::now();
        let status = loop {
            if let Some(st) = child.try_wait().map_err(|e| e.to_string())? {
                break st;
            }
            if started.elapsed() > limit() {
                reap::reap(&mut child, limit())?;
                return Err("helper did not exit in time".into());
            }
            std::thread::sleep(Duration::from_millis(5));
        };
        let mut text = String::new();
        let _ = stderr.read_to_string(&mut text);
        check(text.is_empty(), || {
            format!("unexpected helper stderr {text:?}")
        })?;
        let Some((resp, fds)) = got else {
            return Err("no response from the helper".into());
        };
        let r = DialResponseFrame::decode(&resp).map_err(|e| format!("decode: {e:?}"))?;
        // 参加と特権の破棄に成功し、対象の中（lo は down・listener 無し）から connect して失敗した。
        check(
            matches!(
                r,
                DialResponse::Error(DialErrorCode::Unreachable | DialErrorCode::Refused)
            ),
            || format!("response {r:?}, want Error(Unreachable or Refused)"),
        )?;
        check(fds.is_empty(), || format!("{} fd(s) attached", fds.len()))?;
        check(status.code() == Some(1), || {
            format!("helper exit {status}, want code 1")
        })?;
        // 親の listener は接続を受けていない（init の network namespace から connect していない）。
        match listener.accept() {
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(()),
            other => Err(format!("parent listener saw a connection: {other:?}")),
        }
    }

    pub fn run() -> ExitCode {
        let mut target = match spawn_target() {
            Ok(t) => t,
            Err(e) => {
                eprintln!("netns_dial_userns: FAILED: {e}");
                return ExitCode::from(1);
            }
        };
        let result = scenario(target.id());
        let reaped = reap::reap(&mut target, limit());
        match result.and(reaped) {
            Ok(()) => {
                println!("{OK_LINE}");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("netns_dial_userns: FAILED: {e}");
                ExitCode::from(1)
            }
        }
    }
}
