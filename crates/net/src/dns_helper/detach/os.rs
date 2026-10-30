//! `detach` の Linux 実装（切り離し起動・pidfd 経由の停止・起動窓の回収。NET-5・NET-7・REPAIR-5・SEC-1・#3070）。
//!
//! 手順と契約は親モジュール `detach` の doc を参照。ここは `sys::process`（pidfd・setsid・waitid の薄いラッパー）と
//! `identity`（照合）と `network_store` の記録の読み書きを組み合わせる。`unsafe` は持たない。
//!
//! # 安全性
//! - 停止は pidfd 経由だけで、pid 番号へシグナルを送らない。pidfd を取った後で開始時刻と boot id を照合する
//! - 起動は絶対パス・`env_clear`・シェルを通さない。段 2 は `/proc/self/exe` で、`PATH` を探索しない
//! - ヘルパーの出力（識別行 128 バイト・準備完了行 64 バイト）と `/proc` の読み込み（4 KiB）は上限を検証する
//! - 待ちはすべて期限つき（REPAIR-5）。後始末に失敗したら記録を残して報告し、黙って捨てない
//! - エラー文言に pid・ネットワーク名・アドレスを含めない

use std::net::SocketAddrV4;
use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::time::{Duration, Instant};

use super::{
    ACK, ARG_DETACH, ARG_NETWORK, ARG_NONCE, ARG_STAGE2, ARG_STATE_ROOT, DNS_HELPER_ACK_TIMEOUT,
    DNS_HELPER_KILL_REAP_TIMEOUT, DNS_HELPER_RECOVER_TIMEOUT, DNS_HELPER_STAGE1_EXIT_TIMEOUT,
    DNS_HELPER_STOP_GRACE, DnsHelperStopRequest, HelperProcessOps, IDENT_LINE_MAX, IDENT_PREFIX,
    MAX_RECOVERY_CANDIDATES, RequestOutcome, SPAWN_PREFIX, StopOutcome, StopStage,
    run_stop_sequence,
};
use crate::dns_helper::identity::{
    self, BootId, ProcessIdentity, Verify, read_boot_id, read_identity, read_limited,
    verify_pidfd_target,
};
use crate::dns_helper::record::{DnsHelperIntent, DnsHelperRecord, HelperNonce};
use crate::dns_helper::{
    DnsListenAddr, READY_LINE_MAX, check_timeout, kill_reap_or_detach, map_io, parse_ready,
    write_atomic, write_stdout_line_atomic,
};
use crate::error::{NetError, NetErrorCode};
use crate::instrument::{NetOpKind, NetOpRecorder, record_net_op};
use crate::network::NetworkName;
use crate::network_store::NetworkLockGuard;
use crate::sys::{self, Deadline, Readiness, SysError, process};

// 識別行の上限は、原子的な 1 回の書き込みの範囲（改行込み）に収まる。
const _: () = assert!(IDENT_LINE_MAX < crate::dns_helper::PIPE_ATOMIC_MAX);

/// `/proc/<pid>/cmdline` の読み込み上限。
const CMDLINE_MAX_BYTES: usize = 4096;

fn err(code: NetErrorCode, msg: &'static str) -> NetError {
    NetError::new(code, msg)
}

/// 失敗の説明に後始末の結果を追記する（元の分類は保つ）。
fn with_note(e: NetError, note: &str) -> NetError {
    NetError::new(e.code(), format!("{}; {note}", e.message()))
}

/// 切り離して起動したヘルパー。プロセスは起動元から切り離されており、このハンドルを捨てても止まらない
/// （停止は記録を使う [`stop_recorded_dns_helper`]）。
#[derive(Debug, Clone)]
pub struct DetachedDnsHelper {
    /// 起動時に確定した同一性（記録と同じ値）。
    pub identity: ProcessIdentity,
    /// ヘルパーが報告した待受アドレス。
    pub listen: SocketAddrV4,
}

fn open_pidfd(pid: u32) -> Result<OwnedFd, NetError> {
    match process::pidfd_open(pid) {
        Ok(fd) => Ok(fd),
        Err(SysError::Os(e)) if e == process::ESRCH => Err(err(
            NetErrorCode::NotFound,
            "dns helper process does not exist",
        )),
        Err(SysError::Os(e)) if e == process::ENOSYS => Err(err(
            NetErrorCode::Unimplemented,
            "pidfd_open is not supported by this kernel",
        )),
        Err(SysError::Unsupported) => Err(err(
            NetErrorCode::Unimplemented,
            "pidfd_open is not supported on this architecture",
        )),
        Err(_) => Err(err(NetErrorCode::Internal, "pidfd_open failed")),
    }
}

/// pidfd が可読（プロセスが終了）になるのを `timeout` まで待つ。
fn wait_exit(pidfd: BorrowedFd<'_>, timeout: Duration) -> Result<bool, NetError> {
    match sys::wait_readable(pidfd, &Deadline::after(timeout)) {
        Ok(Readiness::Readable) => Ok(true),
        Ok(Readiness::TimedOut) => Ok(false),
        Ok(Readiness::Exceptional) | Err(_) => Err(err(
            NetErrorCode::Internal,
            "cannot poll process descriptor",
        )),
    }
}

fn kill_via_pidfd(pidfd: BorrowedFd<'_>) -> Result<(), NetError> {
    match process::pidfd_send_sigkill(pidfd) {
        Ok(()) => Ok(()),
        // 既に終了している。
        Err(SysError::Os(e)) if e == process::ESRCH => Ok(()),
        Err(_) => Err(err(NetErrorCode::Internal, "pidfd_send_signal failed")),
    }
}

/// SIGKILL を送り、終了を期限つきで確かめて回収する。終了を確認できたら true。
fn kill_and_confirm(pidfd: BorrowedFd<'_>) -> bool {
    if kill_via_pidfd(pidfd).is_err() {
        return false;
    }
    let dead = matches!(wait_exit(pidfd, DNS_HELPER_KILL_REAP_TIMEOUT), Ok(true));
    if dead {
        let _ = process::reap_pidfd_nohang(pidfd);
    }
    dead
}

struct PidfdOps<'a> {
    pidfd: OwnedFd,
    request: &'a dyn DnsHelperStopRequest,
    record: &'a DnsHelperRecord,
}

impl HelperProcessOps for PidfdOps<'_> {
    fn request(&mut self) -> RequestOutcome {
        self.request.request(self.record)
    }
    fn wait_exit(&mut self, timeout: Duration) -> Result<bool, NetError> {
        wait_exit(self.pidfd.as_fd(), timeout)
    }
    fn kill(&mut self) -> Result<(), NetError> {
        kill_via_pidfd(self.pidfd.as_fd())
    }
}

/// 記録のヘルパーを停止する（ネットワークの排他ロックを持って呼ぶ）。
///
/// 記録の pid から pidfd を先に取り、開始時刻と boot id を照合する。別のプロセスなら何も送らず記録を古いものとして
/// 消す（制御 socket は終了を確認できないので保持する。[`StopOutcome::StaleRecord`]）。同一なら停止要求 → 猶予 → pidfd へ SIGKILL の順に進める。SIGKILL の後も
/// 終了しなければ `Timeout` を返して記録を残す（次の操作で再試行できる）。`pidfd_open` が使えないカーネルでは
/// 記録を残して `Unimplemented`。
pub fn stop_recorded_dns_helper(
    guard: &NetworkLockGuard<'_>,
    request: &dyn DnsHelperStopRequest,
    recorder: &dyn NetOpRecorder,
) -> Result<StopOutcome, NetError> {
    record_net_op(recorder, NetOpKind::DnsHelperStop, || {
        stop_inner(guard, request)
    })
}

fn stop_inner(
    guard: &NetworkLockGuard<'_>,
    request: &dyn DnsHelperStopRequest,
) -> Result<StopOutcome, NetError> {
    // 副作用（停止要求・SIGKILL）の前に排他ロックを確かめる（共有ロックの下で止めてから記録の削除で失敗しない）。
    guard.require_exclusive()?;
    guard.discard_stale_temps()?;
    let Some(record) = guard.read_dns_helper()? else {
        return Ok(StopOutcome::NoRecord);
    };
    let pidfd = match open_pidfd(record.identity().pid) {
        Ok(fd) => fd,
        Err(e) if e.code() == NetErrorCode::NotFound => {
            // 死んだヘルパーの制御ソケットは、記録を消す前に片付ける（記録が先に消えると socket だけが残る）。
            guard.remove_dns_control_socket()?;
            guard.remove_dns_helper()?;
            return Ok(StopOutcome::AlreadyGone);
        }
        Err(e) => return Err(e),
    };
    match verify_pidfd_target(pidfd.as_fd(), record.identity())? {
        Verify::Same => {}
        Verify::Different => {
            // pid が別のプロセスに再利用されている。ただし同一性の不一致は記録の古さしか示さず、元のヘルパーの
            // listener が死んだ根拠にならない（開始時刻の違う記録を渡されただけで生きたヘルパーの socket を
            // 消すと Reload / Stop が届かなくなる）。終了を確認できないので制御 socket は消さず保持する。
            guard.remove_dns_helper()?;
            return Ok(StopOutcome::StaleRecord);
        }
        Verify::Gone => {
            // subreaper の下では終了済みでもゾンビとして pidfd が開ける。記録を消す前に pidfd 経由で回収する。
            let _ = process::reap_pidfd_nohang(pidfd.as_fd());
            guard.remove_dns_control_socket()?;
            guard.remove_dns_helper()?;
            return Ok(StopOutcome::AlreadyGone);
        }
    }
    let mut ops = PidfdOps {
        pidfd,
        request,
        record: &record,
    };
    let stage = run_stop_sequence(
        &mut ops,
        DNS_HELPER_STOP_GRACE,
        DNS_HELPER_KILL_REAP_TIMEOUT,
    )?;
    let _ = process::reap_pidfd_nohang(ops.pidfd.as_fd());
    // 終了を確認できた後で、制御ソケットと記録を消す（`Timeout` で上の `?` が返ったときは両方残す）。
    guard.remove_dns_control_socket()?;
    guard.remove_dns_helper()?;
    Ok(match stage {
        StopStage::StoppedOnRequest => StopOutcome::StoppedOnRequest,
        StopStage::Killed => StopOutcome::Killed,
    })
}

/// 識別行 `IDENT <pid> <start> <boot> <nonce>` を解析する（nonce の一致を要する）。
fn parse_ident(line: &str, nonce: &HelperNonce) -> Result<ProcessIdentity, NetError> {
    let bad = || err(NetErrorCode::FailedPrecondition, "malformed identity line");
    let rest = line.strip_prefix(IDENT_PREFIX).ok_or_else(bad)?;
    let mut it = rest.split(' ');
    let pid: u32 = it.next().and_then(|s| s.parse().ok()).ok_or_else(bad)?;
    let start: u64 = it.next().and_then(|s| s.parse().ok()).ok_or_else(bad)?;
    let boot = BootId::new(it.next().ok_or_else(bad)?).map_err(|_| bad())?;
    if it.next() != Some(nonce.as_str()) || it.next().is_some() || pid == 0 {
        return Err(bad());
    }
    Ok(ProcessIdentity {
        pid,
        start_time_ticks: start,
        boot_id: boot,
    })
}

/// 段 1 の終了を期限つきで待つ。期限切れ・異常終了は失敗。
fn wait_stage1(mut child: Child) -> Result<(), NetError> {
    let deadline = Instant::now() + DNS_HELPER_STAGE1_EXIT_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(st)) if st.success() => return Ok(()),
            Ok(Some(_)) => {
                return Err(err(
                    NetErrorCode::FailedPrecondition,
                    "dns helper stage 1 failed",
                ));
            }
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(5)),
            Ok(None) => {
                let _ = kill_reap_or_detach(child, DNS_HELPER_KILL_REAP_TIMEOUT);
                return Err(err(
                    NetErrorCode::Timeout,
                    "dns helper stage 1 did not exit before the deadline",
                ));
            }
            Err(_) => {
                let _ = kill_reap_or_detach(child, DNS_HELPER_KILL_REAP_TIMEOUT);
                return Err(err(
                    NetErrorCode::Internal,
                    "cannot wait for dns helper stage 1",
                ));
            }
        }
    }
}

/// ヘルパーを親から切り離して起動する（ネットワークの排他ロックを持って呼ぶ）。
///
/// 手順は親モジュールの doc を参照。`program` は絶対パスに限る。`dns-helper` か `dns-helper.intent` が既にあれば
/// `AlreadyExists`（二重起動しない。古い記録は [`stop_recorded_dns_helper`] か [`recover_dns_helper_intent`] で
/// 片付けてから起動する）。失敗時は、起動窓の記録（意図記録・`dns-helper`）を、子が存在しない（`spawn` 自体の失敗）か
/// プロセスの終了を確認できたときだけ消す。段 1 の起動後に終了を確認できない失敗（識別行のタイムアウト・
/// reader スレッドの生成失敗等）は意図記録を残して報告し、次の操作で [`recover_dns_helper_intent`] が回収する。
pub fn spawn_detached_dns_helper(
    guard: &NetworkLockGuard<'_>,
    program: &Path,
    listen: DnsListenAddr,
    ready_timeout: Duration,
    recorder: &dyn NetOpRecorder,
) -> Result<DetachedDnsHelper, NetError> {
    record_net_op(recorder, NetOpKind::DnsHelperStart, || {
        spawn_inner(guard, program, listen, ready_timeout)
    })
}

fn spawn_inner(
    guard: &NetworkLockGuard<'_>,
    program: &Path,
    listen: DnsListenAddr,
    ready_timeout: Duration,
) -> Result<DetachedDnsHelper, NetError> {
    check_timeout(ready_timeout)?;
    if !program.is_absolute() {
        return Err(err(
            NetErrorCode::InvalidArgument,
            "helper program path must be absolute",
        ));
    }
    guard.discard_stale_temps()?;
    if guard.read_dns_helper()?.is_some() || guard.read_dns_helper_intent()?.is_some() {
        return Err(err(
            NetErrorCode::AlreadyExists,
            "dns helper record already exists",
        ));
    }
    // 記録も意図記録も無くても、`StaleRecord` の停止は記録だけを消して生きたヘルパーの socket を残す。listener の
    // 不在を確認できたときだけ残骸として消す（生存・判定不能なら起動を拒否。socket でない・他の所有者のものも
    // 消さずに失敗にする）。
    guard.remove_dns_control_socket_if_no_listener()?;
    let state_root = guard.state_root()?;
    let nonce = HelperNonce::generate()?;
    guard.write_dns_helper_intent(&DnsHelperIntent::new(
        guard.network().clone(),
        nonce.clone(),
        listen,
    ))?;

    let mut cmd = Command::new(program);
    cmd.arg(ARG_DETACH)
        .arg("--listen")
        .arg(listen.to_string())
        .arg(ARG_NONCE)
        .arg(nonce.as_str())
        .arg(ARG_STATE_ROOT)
        .arg(state_root)
        .arg(ARG_NETWORK)
        .arg(guard.network().as_str())
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut stage1 = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            return Err(fail_spawn(guard, map_io("spawn dns helper", &e)));
        }
    };
    let stdin = stage1.stdin.take();
    let Some(stdout) = stage1.stdout.take() else {
        let _ = kill_reap_or_detach(stage1, DNS_HELPER_KILL_REAP_TIMEOUT);
        return Err(fail_child_may_exist(
            stdin,
            err(NetErrorCode::Internal, "helper stdout unavailable"),
        ));
    };
    if let Err(e) = wait_stage1(stage1) {
        return Err(fail_child_may_exist(stdin, e));
    }

    // 識別行と準備完了行を同じ pipe から、poll と絶対期限つきで順に読む（読み手のスレッドを作らない。REPAIR-5）。
    // 段 1 が書く `SPAWN <pid>` 行は段 2 の識別行と前後しうるため、識別行が得られるまで高々 2 行を読む。
    let mut stdout = stdout;
    let ident_deadline = Deadline::after(DNS_HELPER_ACK_TIMEOUT);
    // `SPAWN` が識別行より先に届いたときは、識別行を待つ前に照合済みの同一性を意図記録へ残す（#3414）。
    // 識別行が届く前に呼び出し元が止まっても、回収が記録で帰属できる。
    let mut spawn_adopt: Option<SpawnAdopt> = None;
    let mut spawn_recorded: Option<ProcessIdentity> = None;
    let pre = read_pre_ack_lines(&mut stdout, &ident_deadline, &mut |rest| {
        let adopt = adopt_spawned(rest, &nonce);
        let recorded = match adopt.as_ref() {
            Some(a) => record_spawn_identity(guard, &nonce, listen, a),
            None => Ok(None),
        };
        spawn_adopt = adopt;
        spawn_recorded = recorded?;
        Ok(())
    });
    if !pre.spawn_first {
        // 識別行が先: 続く `SPAWN` は失敗時の回収用の pidfd を取るだけ（識別行の直後に記録する）。
        spawn_adopt = pre
            .spawn
            .as_deref()
            .and_then(|rest| adopt_spawned(rest, &nonce));
    }
    let early: Option<OwnedFd> = spawn_adopt.map(|a| a.pidfd);
    let ident_line = match pre.ident {
        Ok(l) => l,
        Err(e) => return Err(fail_before_ack_any(guard, stdin, early.as_ref(), e)),
    };
    let (identity, pidfd) = match confirm_identity(&ident_line, &nonce) {
        Ok(v) => v,
        Err(f) => {
            // 照合の途中で終了していた場合は、その pidfd で回収してから意図記録を消す。
            let fd = f.pidfd.as_ref().or(early.as_ref());
            return Err(fail_before_ack_any(guard, stdin, fd, f.error));
        }
    };
    let mut early = early;
    if let Some(extra) = early.take_if(|fd| !same_pidfd_pid(fd.as_fd(), identity.pid)) {
        // 識別行と別の pid を名乗った SPAWN 行の相手は止めておく。
        let stopped = kill_and_confirm(extra.as_fd());
        if !stopped && spawn_recorded.is_some() {
            // 意図記録は SPAWN 側の同一性を持つ。止めたと確認できないまま識別行側の同一性で上書きすると、
            // 帰属を失う。識別行側だけを止め、意図記録を残して失敗にする。
            return Err(fail_keep_intent(
                stdin,
                pidfd.as_fd(),
                err(
                    NetErrorCode::FailedPrecondition,
                    "dns helper reported a different pid than the spawn line",
                ),
            ));
        }
    }
    // 確定記録の前に、意図記録へ同一性を原子的に追記する（#3344）。回収前に段 2 が終了してゾンビになっても
    // （cmdline が空・cgroup.procs にも現れない）、回収はこの同一性で pidfd を取って帰属できる。
    // ack の期限（段 2 が識別行を書いた時点から数える）の中で fsync が 1 組増える。
    // SPAWN の時点で同じ同一性を記録済みなら、二重の fsync を避けて置き換えを飛ばす（#3414）。
    let upgraded = if spawn_recorded.as_ref() == Some(&identity) {
        Ok(())
    } else {
        DnsHelperIntent::new(guard.network().clone(), nonce.clone(), listen)
            .with_identity(identity.clone())
            .and_then(|i| guard.replace_dns_helper_intent(&i))
    };
    if let Err(e) = upgraded {
        return Err(fail_before_ack_reap(guard, stdin, pidfd.as_fd(), e));
    }
    let record = match DnsHelperRecord::new(identity.clone(), nonce, listen) {
        Ok(r) => r,
        Err(e) => return Err(fail_before_ack_reap(guard, stdin, pidfd.as_fd(), e)),
    };
    if let Err(e) = guard.write_dns_helper(&record) {
        return Err(fail_before_ack_reap(guard, stdin, pidfd.as_fd(), e));
    }

    // 記録を確定した後で ack を返す。ここから先の失敗は、プロセスを pidfd 経由で止めて確認してから記録を消す。
    let acked = match stdin {
        Some(mut s) => write_atomic(&mut s, ACK).is_ok(),
        None => false,
    };
    let result = if acked {
        match read_line_deadline(&mut stdout, READY_LINE_MAX, &Deadline::after(ready_timeout)) {
            Ok(line) => parse_ready(&line, listen.socket_addr()),
            Err(e) if e.code() == NetErrorCode::Timeout => Err(err(
                NetErrorCode::Timeout,
                "dns helper was not ready before the deadline",
            )),
            Err(e) => Err(e),
        }
    } else {
        Err(err(NetErrorCode::Internal, "cannot send ack to dns helper"))
    };
    let addr = match result {
        Ok(a) => a,
        Err(e) => return Err(fail_after_record(guard, pidfd.as_fd(), e)),
    };
    if let Err(e) = guard.remove_dns_helper_intent() {
        return Err(fail_after_record(guard, pidfd.as_fd(), e));
    }
    Ok(DetachedDnsHelper {
        identity,
        listen: addr,
    })
}

/// 識別行を解析し、boot id・pidfd 上の開始時刻で照合する。pidfd を返す。
fn confirm_identity(
    line: &str,
    nonce: &HelperNonce,
) -> Result<(ProcessIdentity, OwnedFd), ConfirmFailure> {
    let plain = |error| ConfirmFailure { error, pidfd: None };
    let identity = parse_ident(line, nonce).map_err(plain)?;
    if identity.boot_id != read_boot_id().map_err(plain)? {
        return Err(plain(err(
            NetErrorCode::FailedPrecondition,
            "dns helper reported a different boot id",
        )));
    }
    let pidfd = match open_pidfd(identity.pid) {
        Ok(fd) => fd,
        Err(e) if e.code() == NetErrorCode::NotFound => {
            return Err(plain(err(
                NetErrorCode::FailedPrecondition,
                "dns helper exited before its identity was confirmed",
            )));
        }
        Err(e) => return Err(plain(e)),
    };
    match verify_pidfd_target(pidfd.as_fd(), &identity).map_err(plain)? {
        Verify::Same => Ok((identity, pidfd)),
        // pidfd を持っている間は pid が再利用されないので、`Gone` は「この pidfd の子が終了した」。
        // 呼び出し側が pidfd で回収できるよう返す。
        Verify::Gone => Err(ConfirmFailure {
            error: err(
                NetErrorCode::FailedPrecondition,
                "dns helper exited before its identity was confirmed",
            ),
            pidfd: Some(pidfd),
        }),
        Verify::Different => Err(plain(err(
            NetErrorCode::FailedPrecondition,
            "dns helper identity did not match the process",
        ))),
    }
}

/// [`confirm_identity`] の失敗。照合の途中で子が終了していた場合だけ、回収用の pidfd を持つ。
struct ConfirmFailure {
    error: NetError,
    pidfd: Option<OwnedFd>,
}

/// stdout から 1 行（最大 `max` バイト）を、poll と絶対期限つきで読む。1 バイトずつ読むため続く行を食べない。
/// poll が可読を返した後の 1 バイト読みはブロックしない（pipe に 1 バイト以上ある、または EOF）。
fn read_line_deadline(
    out: &mut (impl std::io::Read + std::os::fd::AsFd),
    max: usize,
    deadline: &Deadline,
) -> Result<String, NetError> {
    let mut line = Vec::with_capacity(max);
    let mut byte = [0u8; 1];
    loop {
        match sys::wait_readable(out.as_fd(), deadline) {
            Ok(Readiness::Readable) => {}
            Ok(Readiness::TimedOut) => {
                return Err(err(
                    NetErrorCode::Timeout,
                    "dns helper did not report before the deadline",
                ));
            }
            // POLLHUP のみ: 書き手が全員閉じた (EOF)。
            Ok(Readiness::Exceptional) => {
                return Err(err(
                    NetErrorCode::FailedPrecondition,
                    "helper exited before readiness",
                ));
            }
            Err(_) => {
                return Err(err(NetErrorCode::Internal, "cannot poll helper output"));
            }
        }
        match out.read(&mut byte) {
            Ok(0) => {
                return Err(err(
                    NetErrorCode::FailedPrecondition,
                    "helper exited before readiness",
                ));
            }
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => {
                return Err(err(
                    NetErrorCode::FailedPrecondition,
                    "cannot read readiness line",
                ));
            }
        }
        match byte.first().copied() {
            Some(b'\n') => break,
            Some(b) if line.len() < max => line.push(b),
            _ => {
                return Err(err(
                    NetErrorCode::FailedPrecondition,
                    "readiness line too long",
                ));
            }
        }
    }
    String::from_utf8(line).map_err(|_| {
        err(
            NetErrorCode::FailedPrecondition,
            "readiness line is not UTF-8",
        )
    })
}

/// ack 前に読んだ行。`spawn` は `SPAWN` 行の `<pid>` 部分（無ければ `None`）。
struct PreAck {
    spawn: Option<String>,
    /// `SPAWN` 行が識別行より先に届き、フックを呼んだか。
    spawn_first: bool,
    ident: Result<String, NetError>,
}

/// ack の前に pipe にありうる 2 行（段 1 の `SPAWN <pid>`・段 2 の `IDENT ...`）を、順序によらず読み切る。
///
/// 2 行は別々のプロセスが同じ pipe へ書くため、どちらが先に届くか決まっていない。段 1 の終了を確認してから
/// 読むので `SPAWN` は（書かれていれば）既に pipe にあり、段 2 は ack まで識別行以外を書かない。したがって
/// 識別行を先に読んだ場合は、続きを期限 0 で確認して `SPAWN` を取り切る。`SPAWN` が残ったまま ack を返すと、
/// 準備完了行の読み取りが `SPAWN` を受けてしまう。
fn read_pre_ack_lines(
    out: &mut (impl std::io::Read + std::os::fd::AsFd),
    deadline: &Deadline,
    on_spawn_first: &mut dyn FnMut(&str) -> Result<(), NetError>,
) -> PreAck {
    let malformed = || err(NetErrorCode::FailedPrecondition, "malformed identity line");
    let first = match read_line_deadline(out, IDENT_LINE_MAX, deadline) {
        Ok(l) => l,
        Err(e) => {
            return PreAck {
                spawn: None,
                spawn_first: false,
                ident: Err(e),
            };
        }
    };
    if let Some(rest) = first.strip_prefix(SPAWN_PREFIX) {
        // 識別行を読む前に呼ぶ。失敗したら識別行は読まずに、そのエラーを返す（pipe に残す）。
        if let Err(e) = on_spawn_first(rest) {
            return PreAck {
                spawn: Some(rest.to_owned()),
                spawn_first: true,
                ident: Err(e),
            };
        }
        let ident = match read_line_deadline(out, IDENT_LINE_MAX, deadline) {
            Ok(l) if l.starts_with(SPAWN_PREFIX) => Err(malformed()),
            other => other,
        };
        return PreAck {
            spawn: Some(rest.to_owned()),
            spawn_first: true,
            ident,
        };
    }
    // 識別行が先。続きがあれば `SPAWN` でなければならない（期限 0 の確認。無ければ段 1 は書かなかった）。
    let spawn = match read_line_deadline(out, IDENT_LINE_MAX, &Deadline::after(Duration::ZERO)) {
        Ok(l) => match l.strip_prefix(SPAWN_PREFIX) {
            Some(rest) => Some(rest.to_owned()),
            None => {
                return PreAck {
                    spawn: None,
                    spawn_first: false,
                    ident: Err(malformed()),
                };
            }
        },
        Err(_) => None,
    };
    PreAck {
        spawn,
        spawn_first: false,
        ident: Ok(first),
    }
}

/// 段 1 が報告した段 2 の pid（`SPAWN <pid>` 行）から、失敗時の回収に使う pidfd を取る。
///
/// 段 2 が識別行を出す前に止まっても（SIGSTOP 等）、この pidfd で SIGKILL と `waitid` による回収ができる。
/// 生存中なら cmdline の nonce で別のプロセスでないことを確かめる。既に終了していれば（ゾンビは cmdline が
/// 空）、pid は回収まで再利用されないため、その pidfd を回収に使う。取れなければ `None`（呼び出し側は
/// 意図記録を残す）。
fn adopt_spawned(rest: &str, nonce: &HelperNonce) -> Option<SpawnAdopt> {
    let pid: u32 = rest.parse().ok().filter(|p| *p != 0)?;
    let pidfd = open_pidfd(pid).ok()?;
    let exited = matches!(wait_exit(pidfd.as_fd(), Duration::ZERO), Ok(true));
    if exited {
        return Some(SpawnAdopt {
            pidfd,
            identity: None,
        });
    }
    if !cmdline_has_nonce(pid, nonce).ok()? {
        return None;
    }
    // 生存中で nonce を持つときだけ同一性を読み、pidfd の指す先と照合して初めて記録の候補にする（SEC-1）。
    // 読み取りと照合の間に終了した場合は同一性なし（pidfd は回収用に返す）。
    let identity = read_identity(pid)
        .ok()
        .filter(|id| matches!(verify_pidfd_target(pidfd.as_fd(), id), Ok(Verify::Same)));
    Some(SpawnAdopt { pidfd, identity })
}

/// [`adopt_spawned`] の結果。`identity` は pidfd・nonce・開始時刻・boot id を照合済みのときだけ `Some`。
struct SpawnAdopt {
    pidfd: OwnedFd,
    identity: Option<ProcessIdentity>,
}

/// 照合済みの `SPAWN` 相手の同一性を意図記録へ原子的に追記し、記録した同一性を返す（無ければ `None`）。
///
/// 識別行が届く前に呼び出し元が止まっても、回収が同一性で pidfd を取って帰属できる（#3414・#3344）。
/// ack の期限の中で fsync が 1 組動くが、識別行の時点の置き換えはこの記録と同値なら飛ばすので、
/// 成功した起動の `NetworkStoreDnsHelperWrite` の回数は変わらない。
fn record_spawn_identity(
    guard: &NetworkLockGuard<'_>,
    nonce: &HelperNonce,
    listen: DnsListenAddr,
    adopt: &SpawnAdopt,
) -> Result<Option<ProcessIdentity>, NetError> {
    let Some(id) = adopt.identity.as_ref() else {
        return Ok(None);
    };
    let intent = DnsHelperIntent::new(guard.network().clone(), nonce.clone(), listen)
        .with_identity(id.clone())?;
    guard.replace_dns_helper_intent(&intent)?;
    Ok(Some(id.clone()))
}

/// 意図記録（帰属に要る同一性）を残したまま、`pidfd` の相手だけを止めて失敗にする。
fn fail_keep_intent(stdin: Option<ChildStdin>, pidfd: BorrowedFd<'_>, e: NetError) -> NetError {
    drop(stdin);
    let _ = kill_and_confirm(pidfd);
    with_note(e, "intent record kept")
}

/// pidfd の指す pid が `pid` と一致するか（`/proc/self/fdinfo` を読まず、pidfd を取った pid を使う代わりに
/// 開き直して比べる）。
fn same_pidfd_pid(pidfd: BorrowedFd<'_>, pid: u32) -> bool {
    read_pidfd_pid(pidfd) == Some(pid)
}

/// `/proc/self/fdinfo/<fd>` の `Pid:` 行。
fn read_pidfd_pid(pidfd: BorrowedFd<'_>) -> Option<u32> {
    use std::os::fd::AsRawFd as _;
    let raw = read_limited(
        PathBuf::from(format!("/proc/self/fdinfo/{}", pidfd.as_raw_fd())),
        CMDLINE_MAX_BYTES,
    )
    .ok()?;
    let text = String::from_utf8(raw).ok()?;
    text.lines()
        .find_map(|l| l.strip_prefix("Pid:"))
        .and_then(|v| v.trim().parse().ok())
}

/// 段 2 の pidfd を持つなら止めて回収して意図記録を消し、持たないなら意図記録を残す（ack 前の失敗）。
fn fail_before_ack_any(
    guard: &NetworkLockGuard<'_>,
    stdin: Option<ChildStdin>,
    pidfd: Option<&OwnedFd>,
    e: NetError,
) -> NetError {
    match pidfd {
        Some(fd) => fail_before_ack_reap(guard, stdin, fd.as_fd(), e),
        None => fail_child_may_exist(stdin, e),
    }
}

/// 段 1 の `spawn` 自体が失敗した経路（NET-5・REPAIR-5）。子プロセスは存在しないので、意図記録を消してよい。
/// 消せなければ記録を残したことを失敗に添える。
fn fail_spawn(guard: &NetworkLockGuard<'_>, e: NetError) -> NetError {
    match guard.remove_dns_helper_intent() {
        Ok(()) => e,
        Err(r) => with_note(e, &format!("intent record kept: {}", r.message())),
    }
}

/// 段 1 の起動に成功した後、段 2 の終了を確認できないまま失敗した経路（NET-5・REPAIR-5）。
///
/// 識別行のタイムアウト・不正、reader スレッドの生成失敗、段 1 の異常終了などでは、段 2 が生存している
/// かもしれない（停止中の子は EOF でも終了しない）。stdin を閉じて EOF での自発終了に任せるが、意図記録は
/// 消さずに残し、後続の `recover_dns_helper_intent` が nonce で再試行できるようにする。残った記録は
/// 次の `spawn_detached_dns_helper` を `AlreadyExists` にするので、呼び出し側は先に回収を行う。
fn fail_child_may_exist(stdin: Option<ChildStdin>, e: NetError) -> NetError {
    drop(stdin);
    with_note(
        e,
        "dns helper could not be confirmed stopped; intent record kept",
    )
}

/// ack を返す前の失敗のうち、段 2 の pidfd を確保済みの経路（NET-5・REPAIR-5）。
///
/// stdin を閉じて段 2 の自発終了（EOF）を期限つきで待ち、終了しなければ pidfd 経由で SIGKILL する。
/// child subreaper の呼び出し元では終了後もゾンビが残るため、pidfd 経由で回収する。終了を確認できないときは
/// 復旧用の意図記録を消さずに残す（後続の回収が nonce で再試行できる）。
fn fail_before_ack_reap(
    guard: &NetworkLockGuard<'_>,
    stdin: Option<ChildStdin>,
    pidfd: BorrowedFd<'_>,
    e: NetError,
) -> NetError {
    drop(stdin);
    let exited = if matches!(wait_exit(pidfd, DNS_HELPER_KILL_REAP_TIMEOUT), Ok(true)) {
        let _ = process::reap_pidfd_nohang(pidfd);
        true
    } else {
        kill_and_confirm(pidfd)
    };
    if !exited {
        return with_note(
            e,
            "dns helper could not be confirmed stopped; intent record kept",
        );
    }
    match guard.remove_dns_helper_intent() {
        Ok(()) => e,
        Err(r) => with_note(e, &format!("intent record kept: {}", r.message())),
    }
}

/// 記録を書いた後の失敗。pidfd 経由で止めて終了を確認できたら記録を消す。確認できなければ記録を残す。
fn fail_after_record(guard: &NetworkLockGuard<'_>, pidfd: BorrowedFd<'_>, e: NetError) -> NetError {
    if !kill_and_confirm(pidfd) {
        return with_note(e, "dns helper could not be confirmed stopped; records kept");
    }
    let removed = guard
        .remove_dns_control_socket()
        .map(|_| ())
        .and_then(|()| guard.remove_dns_helper())
        .and_then(|()| guard.remove_dns_helper_intent());
    match removed {
        Ok(()) => e,
        Err(r) => with_note(e, &format!("records kept: {}", r.message())),
    }
}

/// 起動窓の回収の結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum IntentRecovery {
    /// 意図記録が無かった。
    NoIntent,
    /// `dns-helper` の記録が確定していた（記録が正）ため、意図記録だけを消した。
    IntentDiscarded,
    /// 記録が無く、候補のうち nonce を持つプロセスを停止した（0 件なら、子は ack の期限で自分から終了していた）。
    /// 意図記録は消した。
    Recovered {
        /// 停止したプロセス数。
        stopped: usize,
    },
}

/// 意図記録が残っているときの回収（D14 (iv)。次の特権操作の先頭で、ネットワークの排他ロックを持って呼ぶ）。
///
/// `dns-helper` の記録があれば記録が正なので意図記録だけを消す。無ければ、`candidates`（`net-helpers` の cgroup に
/// 居るプロセスの pid。列挙は呼び出し側。#3074）のうち、`/proc/<pid>/cmdline` に意図記録の nonce を持つものを、
/// pidfd 取得後に開始時刻を再確認して pidfd 経由で停止し、意図記録を消す。停止を確認できなければ意図記録を
/// 残して `Timeout`。候補は [`MAX_RECOVERY_CANDIDATES`] 件まで調べ、残りがあれば意図記録を残して
/// `ResourceExhausted`。消滅を確認できない失敗（権限・fd 枯渇等）も意図記録を残して失敗にする。排他ロックでなければ
/// 副作用の前に `FailedPrecondition`。
pub fn recover_dns_helper_intent(
    guard: &NetworkLockGuard<'_>,
    candidates: &mut dyn Iterator<Item = u32>,
    recorder: &dyn NetOpRecorder,
) -> Result<IntentRecovery, NetError> {
    record_net_op(recorder, NetOpKind::DnsHelperRecover, || {
        recover_inner(guard, candidates)
    })
}

fn recover_inner(
    guard: &NetworkLockGuard<'_>,
    candidates: &mut dyn Iterator<Item = u32>,
) -> Result<IntentRecovery, NetError> {
    guard.require_exclusive()?;
    guard.discard_stale_temps()?;
    let Some(intent) = guard.read_dns_helper_intent()? else {
        return Ok(IntentRecovery::NoIntent);
    };
    // 確定記録の nonce が意図記録と同じときだけ「記録が正」。違えば別の起動の意図記録なので、記録の
    // ヘルパーには触れずに、意図記録の nonce を持つ子を探す。
    if guard
        .read_dns_helper()?
        .is_some_and(|r| r.nonce() == intent.nonce())
    {
        guard.remove_dns_helper_intent()?;
        return Ok(IntentRecovery::IntentDiscarded);
    }
    let deadline = Instant::now() + DNS_HELPER_RECOVER_TIMEOUT;
    let mut stopped = 0usize;
    let mut seen = 0usize;
    // 追記済みの同一性があれば、候補の列挙に依らず先に帰属して片付ける（#3344。ゾンビは cgroup.procs に現れない）。
    let recorded_pid = intent.identity().map(|i| i.pid);
    if let Some(id) = intent.identity()
        && settle_recorded_identity(id)?
    {
        stopped += 1;
    }
    for pid in (&mut *candidates).take(MAX_RECOVERY_CANDIDATES) {
        seen += 1;
        if Some(pid) == recorded_pid {
            continue;
        }
        if Instant::now() >= deadline {
            return Err(err(
                NetErrorCode::Timeout,
                "dns helper recovery exceeded its deadline; intent record kept",
            ));
        }
        // 消滅（NotFound）を確認できたものだけ読み飛ばす。確認できないエラーは意図記録（再試行に要る nonce）を
        // 残したまま失敗にする。
        if pid == 0 {
            continue;
        }
        if !cmdline_has_nonce(pid, intent.nonce())? {
            // nonce で帰属できない候補（終了済みで cmdline が空のものを含む）には触れない。`waitid` もしない
            // （同じ呼び出し元の別の子の終了状態を奪うため。#3414）。帰属できるゾンビは記録済みの同一性が扱う。
            continue;
        }
        let pidfd = match open_pidfd(pid) {
            Ok(fd) => fd,
            Err(e) if e.code() == NetErrorCode::NotFound => continue,
            Err(e) => return Err(with_note(e, "intent record kept")),
        };
        if settle_candidate(pidfd.as_fd(), pid, intent.nonce())? {
            stopped += 1;
        }
    }
    // 上限に達したのに候補が残っていれば、走査を終えていない。意図記録を消すと生存したヘルパーの nonce を失う。
    if seen >= MAX_RECOVERY_CANDIDATES && candidates.next().is_some() {
        return Err(err(
            NetErrorCode::ResourceExhausted,
            "too many recovery candidates; intent record kept",
        ));
    }
    // 起動途中で止めたヘルパー（`stopped > 0`）が bind していた制御ソケットを片付ける。何も止めていないとき
    // （子は ack の期限で bind せずに終了済み、または nonce が合わない別のプロセス）は触れない。`dns-helper` の
    // 記録が別にあるときの socket はその生きたヘルパーのものなので消さない。bind 前に死んだ子の socket が
    // 残っても、次の起動と `network rm` が消す。
    if stopped > 0 && guard.read_dns_helper()?.is_none() {
        guard.remove_dns_control_socket()?;
    }
    guard.remove_dns_helper_intent()?;
    Ok(IntentRecovery::Recovered { stopped })
}

/// 意図記録に追記された同一性（#3344）で pidfd を取って照合し、片付ける（止めた・回収したなら true）。
///
/// 生存していれば pidfd へ SIGKILL して終了を確認し、終了済み（subreaper の下のゾンビ。`/proc/<pid>/stat` の
/// 開始時刻は残るので照合できる）なら pidfd の `waitid` で回収する（自分の子でなければ回収は親の仕事で成功扱い）。
/// pid が再利用されている（開始時刻・boot id が違う）なら何も送らない。プロセスが無ければ回収済みで何もしない。
/// 確認できないエラーは意図記録を残して失敗にする。
fn settle_recorded_identity(identity: &ProcessIdentity) -> Result<bool, NetError> {
    let pidfd = match open_pidfd(identity.pid) {
        Ok(fd) => fd,
        Err(e) if e.code() == NetErrorCode::NotFound => return Ok(false),
        Err(e) => return Err(with_note(e, "intent record kept")),
    };
    match verify_pidfd_target(pidfd.as_fd(), identity)? {
        Verify::Different => Ok(false),
        Verify::Gone => {
            let _ = process::reap_pidfd_nohang(pidfd.as_fd());
            Ok(true)
        }
        Verify::Same => {
            if !kill_and_confirm(pidfd.as_fd()) {
                return Err(err(
                    NetErrorCode::Timeout,
                    "dns helper did not exit before the deadline; intent record kept",
                ));
            }
            Ok(true)
        }
    }
}

/// nonce の一致を確認して pidfd を取った候補を片付ける（止めた・回収したなら true）。
///
/// pidfd を持つ間は pid が再利用されないので、`/proc/<pid>` の消滅（`NotFound`）や空の cmdline（ゾンビ）は
/// 別のプロセスではなく「この pidfd の子が終了した」と扱い、pidfd で `waitid` して回収する。
fn settle_candidate(
    pidfd: BorrowedFd<'_>,
    pid: u32,
    nonce: &HelperNonce,
) -> Result<bool, NetError> {
    match read_identity(pid) {
        Ok(identity) => stop_confirmed_candidate(pidfd, &identity, nonce),
        Err(e) if e.code() == NetErrorCode::NotFound => {
            let _ = process::reap_pidfd_nohang(pidfd);
            Ok(true)
        }
        Err(e) => Err(with_note(e, "intent record kept")),
    }
}

/// pidfd の子が終了していれば（ゾンビの cmdline は空）、別のプロセスではなく子の終了として回収して true。
/// 生存中なら何もせず false。
fn reap_if_exited(pidfd: BorrowedFd<'_>) -> bool {
    if matches!(wait_exit(pidfd, Duration::ZERO), Ok(true)) {
        let _ = process::reap_pidfd_nohang(pidfd);
        true
    } else {
        false
    }
}

/// nonce の一致を確認して pidfd を取った候補を、同一性を再確認したうえで止める（止めた・回収したなら true）。
///
/// nonce の確認後に既に終了していた（`Verify::Gone`）場合も、この pidfd で `waitid` して回収する。
/// 終了後のゾンビは `/proc/<pid>/cmdline` が空で nonce を再検査できないため、確認済みの pidfd・同一性で扱う
/// （呼び出し元が child subreaper のとき、回収しないとゾンビが残る。自分の子でなければ回収は親の仕事）。
/// 開始時刻が違う（別のプロセス）か、生存したまま nonce が無い場合は何もしない。
fn stop_confirmed_candidate(
    pidfd: BorrowedFd<'_>,
    identity: &ProcessIdentity,
    nonce: &HelperNonce,
) -> Result<bool, NetError> {
    match verify_pidfd_target(pidfd, identity)? {
        Verify::Different => Ok(false),
        Verify::Gone => {
            let _ = process::reap_pidfd_nohang(pidfd);
            Ok(true)
        }
        Verify::Same => {
            if !cmdline_has_nonce(identity.pid, nonce)? {
                return Ok(reap_if_exited(pidfd));
            }
            if !kill_and_confirm(pidfd) {
                return Err(err(
                    NetErrorCode::Timeout,
                    "dns helper did not exit before the deadline; intent record kept",
                ));
            }
            Ok(true)
        }
    }
}

/// `/proc/<pid>/cmdline` が `--nonce <nonce>` を持つか。プロセスが無い（消滅）・上限超過（ヘルパーの
/// 引数列ではない）は `false`。それ以外の読み取り失敗（権限・fd 枯渇等）は確認不能として `Err`。
fn cmdline_has_nonce(pid: u32, nonce: &HelperNonce) -> Result<bool, NetError> {
    let raw = match read_limited(
        PathBuf::from(format!("/proc/{pid}/cmdline")),
        CMDLINE_MAX_BYTES,
    ) {
        Ok(r) => r,
        Err(e) if matches!(e.code(), NetErrorCode::NotFound | NetErrorCode::DataLoss) => {
            return Ok(false);
        }
        Err(e) => return Err(e),
    };
    let args: Vec<&[u8]> = raw.split(|&b| b == 0).collect();
    Ok(args.windows(2).any(|w| {
        w.first().copied() == Some(ARG_NONCE.as_bytes())
            && w.get(1).copied() == Some(nonce.as_str().as_bytes())
    }))
}

/// 段 1（`--dns-helper-detach`）の本体: 新しいセッションを作り、段 2 を起動して待たずに戻る。
/// `setsid` に失敗したら（切り離せない）起動を続けず失敗にする（fail-closed）。段 2 は stdin・stdout を継承し、
/// stderr を捨てる。
pub(crate) fn run_stage1(
    listen: DnsListenAddr,
    nonce: &HelperNonce,
    state_root: &Path,
    network: &NetworkName,
) -> Result<(), NetError> {
    process::setsid().map_err(|_| err(NetErrorCode::Internal, "setsid failed"))?;
    let child = Command::new("/proc/self/exe")
        .arg(ARG_STAGE2)
        .arg("--listen")
        .arg(listen.to_string())
        .arg(ARG_NONCE)
        .arg(nonce.as_str())
        .arg(ARG_STATE_ROOT)
        .arg(state_root)
        .arg(ARG_NETWORK)
        .arg(network.as_str())
        .env_clear()
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| map_io("spawn dns helper stage 2", &e))?;
    // 段 2 の pid を起動元へ知らせる（識別行の前に段 2 が止まっても、起動元が pidfd で回収できる）。
    // 書けなくても起動は続ける（起動元は識別行の期限で失敗にし、意図記録を残す）。
    let _ = write_stdout_line_atomic(&format!("{SPAWN_PREFIX}{}", child.id()));
    // 段 2 は待たない。段 1 の終了で init か subreaper の子になり、そこで回収される（二重 fork と同じ形）。
    #[allow(clippy::zombie_processes)]
    drop(child);
    Ok(())
}

/// 段 2（`--dns-helper-stage2`）の握手: 識別行を stdout へ送り、stdin の `ACK` を [`DNS_HELPER_ACK_TIMEOUT`] まで待つ。
/// 期限切れ・EOF・不一致は失敗（呼び出し元は bind せずに終了する。D14 (ii)）。
pub(crate) fn run_stage2_handshake(nonce: &HelperNonce) -> Result<(), NetError> {
    let me = identity::read_self_identity()?;
    let line = format!(
        "{IDENT_PREFIX}{} {} {} {}",
        me.pid, me.start_time_ticks, me.boot_id, nonce
    );
    if line.len() > IDENT_LINE_MAX {
        return Err(err(NetErrorCode::Internal, "identity line is too long"));
    }
    write_stdout_line_atomic(&line)
        .map_err(|_| err(NetErrorCode::Internal, "cannot write identity line"))?;
    let stdin = std::io::stdin();
    read_ack_within(&mut stdin.lock(), &Deadline::after(DNS_HELPER_ACK_TIMEOUT))
}

/// `ACK`（4 バイト）を共有の絶対期限 `deadline` までに読み切る（REPAIR-5）。
/// 部分読みのたびに残り時間で再び待つため、先頭だけ送って止まる相手でも期限で `Timeout` になる。
fn read_ack_within<R: std::io::Read + std::os::fd::AsFd>(
    r: &mut R,
    deadline: &Deadline,
) -> Result<(), NetError> {
    let mut buf = [0u8; 4];
    let mut filled = 0usize;
    while filled < buf.len() {
        match sys::wait_readable(r.as_fd(), deadline) {
            Ok(Readiness::Readable) => {}
            Ok(Readiness::TimedOut) => {
                return Err(err(
                    NetErrorCode::Timeout,
                    "ack was not received before the deadline",
                ));
            }
            Ok(Readiness::Exceptional) | Err(_) => {
                return Err(err(NetErrorCode::FailedPrecondition, "ack channel closed"));
            }
        }
        let Some(rest) = buf.get_mut(filled..) else {
            break;
        };
        match r.read(rest) {
            Ok(0) => {
                return Err(err(
                    NetErrorCode::FailedPrecondition,
                    "ack was not received",
                ));
            }
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => {
                return Err(err(
                    NetErrorCode::FailedPrecondition,
                    "ack was not received",
                ));
            }
        }
    }
    if &buf == ACK {
        Ok(())
    } else {
        Err(err(
            NetErrorCode::FailedPrecondition,
            "ack was not received",
        ))
    }
}

#[cfg(test)]
mod ack_tests {
    use super::*;
    use std::io::Write as _;
    use std::os::unix::net::UnixStream;

    /// REPAIR-5: ACK の一部だけ届いて止まっても期限で Timeout になる。
    #[test]
    fn net5_3070_partial_ack_times_out() {
        let (mut tx, mut rx) = UnixStream::pair().expect("pair");
        tx.write_all(b"A").expect("write");
        let started = std::time::Instant::now();
        let e = read_ack_within(&mut rx, &Deadline::after(Duration::from_millis(200)))
            .expect_err("timeout");
        assert_eq!(e.code(), NetErrorCode::Timeout);
        assert!(started.elapsed() < Duration::from_secs(5));
        drop(tx);
    }

    /// 分割して届いた完全な ACK は受理される。
    #[test]
    fn net5_3070_split_ack_is_accepted() {
        let (mut tx, mut rx) = UnixStream::pair().expect("pair");
        tx.write_all(&ACK[..2]).expect("write");
        let h = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            tx.write_all(&ACK[2..]).expect("write");
            tx
        });
        read_ack_within(&mut rx, &Deadline::after(Duration::from_secs(5))).expect("ack");
        drop(h.join());
    }

    fn spawn_sleeper() -> Child {
        Command::new("sleep")
            .arg("30")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn sleep")
    }

    /// REPAIR-5・NET-5: nonce 確認後に終了してゾンビ化した子も、確認済みの pidfd・同一性で回収される
    /// （`/proc/<pid>/cmdline` が空でも）。
    #[test]
    // 子は pidfd 経由で回収する（`Child::wait` を呼ぶと回収の検証にならない）。
    #[allow(clippy::zombie_processes)]
    fn net5_3070_exited_candidate_is_reaped_via_pidfd() {
        let mut child = spawn_sleeper();
        let pid = child.id();
        let pidfd = open_pidfd(pid).expect("pidfd");
        let identity = read_identity(pid).expect("identity");
        child.kill().expect("kill");
        assert!(wait_exit(pidfd.as_fd(), Duration::from_secs(5)).expect("wait"));
        assert!(
            std::path::Path::new(&format!("/proc/{pid}/stat")).exists(),
            "an unreaped child stays as a zombie"
        );
        let nonce = HelperNonce::generate().expect("nonce");
        assert!(stop_confirmed_candidate(pidfd.as_fd(), &identity, &nonce).expect("stop"));
        assert!(
            !std::path::Path::new(&format!("/proc/{pid}/stat")).exists(),
            "the zombie must be reaped"
        );
    }

    /// 開始時刻が違う（別のプロセス）なら何も送らない。
    #[test]
    fn net5_3070_different_identity_is_left_alone() {
        let mut child = spawn_sleeper();
        let pidfd = open_pidfd(child.id()).expect("pidfd");
        let mut identity = read_identity(child.id()).expect("identity");
        identity.start_time_ticks += 1;
        let nonce = HelperNonce::generate().expect("nonce");
        assert!(!stop_confirmed_candidate(pidfd.as_fd(), &identity, &nonce).expect("stop"));
        assert!(child.try_wait().expect("try_wait").is_none());
        child.kill().expect("kill");
        child.wait().expect("wait");
    }

    fn pipe_with(data: &[u8]) -> UnixStream {
        let (mut tx, rx) = UnixStream::pair().expect("pair");
        tx.write_all(data).expect("write");
        // 書き手を閉じる (EOF)。読み側のデータは残る。
        drop(tx);
        rx
    }

    /// 段 1 の `SPAWN` と段 2 の `IDENT` はどちらが先でも、両方を読み切って ack 後の読み取りに残さない。
    #[test]
    fn net5_3070_spawn_then_ident_order() {
        let mut rx = pipe_with(b"SPAWN 4242\nIDENT 1 2 b n\n");
        let pre = read_pre_ack_lines(
            &mut rx,
            &Deadline::after(Duration::from_secs(2)),
            &mut |_| Ok(()),
        );
        assert_eq!(pre.spawn.as_deref(), Some("4242"));
        assert_eq!(pre.ident.expect("ident"), "IDENT 1 2 b n");
    }

    #[test]
    fn net5_3070_ident_then_spawn_order() {
        let mut rx = pipe_with(b"IDENT 1 2 b n\nSPAWN 4242\n");
        let pre = read_pre_ack_lines(
            &mut rx,
            &Deadline::after(Duration::from_secs(2)),
            &mut |_| Ok(()),
        );
        assert_eq!(pre.spawn.as_deref(), Some("4242"));
        assert_eq!(pre.ident.expect("ident"), "IDENT 1 2 b n");
        // 何も残っていない (後続の準備完了行の読み取りに SPAWN が混ざらない)。
        let rest = read_line_deadline(&mut rx, 64, &Deadline::after(Duration::from_millis(50)));
        assert!(rest.is_err());
    }

    /// `SPAWN` が書かれなかった場合 (識別行のみ) は待たずに戻る。
    #[test]
    fn net5_3070_ident_without_spawn() {
        let (mut tx, mut rx) = UnixStream::pair().expect("pair");
        tx.write_all(b"IDENT 1 2 b n\n").expect("write");
        let t = Instant::now();
        let pre = read_pre_ack_lines(
            &mut rx,
            &Deadline::after(Duration::from_secs(5)),
            &mut |_| Ok(()),
        );
        assert_eq!(pre.spawn, None);
        assert_eq!(pre.ident.expect("ident"), "IDENT 1 2 b n");
        assert!(t.elapsed() < Duration::from_secs(1));
        drop(tx);
    }

    /// 識別行の後に SPAWN 以外の行があれば不正。
    #[test]
    fn net5_3070_extra_line_after_ident_is_malformed() {
        let mut rx = pipe_with(b"IDENT 1 2 b n\nREADY x\n");
        let pre = read_pre_ack_lines(
            &mut rx,
            &Deadline::after(Duration::from_secs(2)),
            &mut |_| Ok(()),
        );
        assert_eq!(
            pre.ident.expect_err("malformed").code(),
            NetErrorCode::FailedPrecondition
        );
    }

    /// REPAIR-5・NET-5: 照合（`Verify::Same`）の後に終了して cmdline が空になった窓でも、別のプロセス扱いにせず
    /// pidfd で回収する。`stop_confirmed_candidate` は終了後のゾンビを `Gone` で回収する経路と、
    /// `settle_candidate` は `/proc/<pid>` の消滅（`NotFound`）を回収済みとして扱う経路を固定する。
    #[test]
    #[allow(clippy::zombie_processes)]
    fn net5_3070_settle_treats_vanished_candidate_as_exited() {
        let mut child = spawn_sleeper();
        let pid = child.id();
        let pidfd = open_pidfd(pid).expect("pidfd");
        child.kill().expect("kill");
        child.wait().expect("wait");
        // 既に回収済みで /proc/<pid> が無い。
        let nonce = HelperNonce::generate().expect("nonce");
        assert!(settle_candidate(pidfd.as_fd(), pid, &nonce).expect("settle"));
    }

    /// 照合中に終了していた識別行は、`Different` ではなく回収用の pidfd つきの失敗になり、その pidfd で
    /// ゾンビを回収できる。
    #[test]
    #[allow(clippy::zombie_processes)]
    fn net5_3070_confirm_identity_gone_returns_pidfd_for_reaping() {
        let mut child = spawn_sleeper();
        let pid = child.id();
        let id = read_identity(pid).expect("identity");
        let nonce = HelperNonce::generate().expect("nonce");
        let line = format!(
            "{IDENT_PREFIX}{pid} {} {} {}",
            id.start_time_ticks, id.boot_id, nonce
        );
        child.kill().expect("kill");
        let proc_stat = format!("/proc/{pid}/stat");
        // 終了してゾンビになるまで待つ。
        let t = Instant::now();
        while std::fs::read_to_string(&proc_stat).is_ok_and(|s| {
            !s.rsplit_once(')')
                .is_some_and(|(_, r)| r.trim_start().starts_with('Z'))
        }) {
            assert!(t.elapsed() < Duration::from_secs(5));
            std::thread::sleep(Duration::from_millis(10));
        }
        let Err(f) = confirm_identity(&line, &nonce) else {
            panic!("a dead process must not be confirmed");
        };
        assert_eq!(f.error.code(), NetErrorCode::FailedPrecondition);
        let fd = f.pidfd.expect("pidfd for reaping");
        assert!(process::reap_pidfd_nohang(fd.as_fd()).expect("reap"));
        assert!(!std::path::Path::new(&proc_stat).exists(), "zombie reaped");
    }

    /// 照合の後に終了して cmdline が空になった窓: 終了していれば回収して true、生存中なら触れず false。
    #[test]
    #[allow(clippy::zombie_processes)]
    fn net5_3070_reap_if_exited_distinguishes_exit_from_alive() {
        let mut child = spawn_sleeper();
        let pid = child.id();
        let pidfd = open_pidfd(pid).expect("pidfd");
        assert!(!reap_if_exited(pidfd.as_fd()));
        assert!(child.try_wait().expect("try_wait").is_none());
        child.kill().expect("kill");
        assert!(wait_exit(pidfd.as_fd(), Duration::from_secs(5)).expect("wait"));
        let proc_stat = format!("/proc/{pid}/stat");
        assert!(std::path::Path::new(&proc_stat).exists(), "zombie before");
        assert!(reap_if_exited(pidfd.as_fd()));
        assert!(!std::path::Path::new(&proc_stat).exists(), "reaped");
    }

    /// REPAIR-2・NET-5: 段 2 が送る識別行は読み側の上限に収まり、原子的に書ける長さである。
    #[test]
    fn net5_3070_identity_line_fits_atomic_write() {
        let me = identity::read_self_identity().expect("identity");
        let nonce = HelperNonce::generate().expect("nonce");
        let line = format!(
            "{IDENT_PREFIX}{} {} {} {}",
            me.pid, me.start_time_ticks, me.boot_id, nonce
        );
        assert!(line.len() <= IDENT_LINE_MAX, "{}", line.len());
        assert!(line.len() < crate::dns_helper::PIPE_ATOMIC_MAX);
    }

    /// 指定の nonce を `--nonce` に持つ生存中の子（`sh -c 'sleep 30' sh --nonce N`）。
    fn spawn_nonce_sleeper(nonce: &HelperNonce) -> Child {
        Command::new("sh")
            .args(["-c", "kill -STOP $$", "sh", ARG_NONCE])
            .arg(nonce.as_str())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn sh")
    }

    /// 子が exec 済みで cmdline に nonce が現れ、かつ停止（`T`）するまで待つ（上限 5 秒。REPAIR-5・#3414）。
    fn wait_nonce_sleeper_stopped(pid: u32, nonce: &HelperNonce) {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let has = cmdline_has_nonce(pid, nonce).unwrap_or(false);
            let stopped = std::fs::read_to_string(format!("/proc/{pid}/stat"))
                .ok()
                .and_then(|s| {
                    s.rsplit_once(')')
                        .map(|(_, r)| r.trim_start().starts_with('T'))
                })
                .unwrap_or(false);
            if has && stopped {
                return;
            }
            assert!(Instant::now() < deadline, "sleeper not ready: pid {pid}");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// NET-5・SEC-1・REPAIR-4・#3414: `SPAWN` 行の時点で、照合済みの同一性が意図記録へ残り、識別行が届かずに
    /// 呼び出し元が止まっても（pidfd を捨てる）、候補なしの回収が帰属して止める。
    #[test]
    #[allow(clippy::zombie_processes)]
    fn net5_3414_spawn_identity_recorded_then_recovered_without_ident() {
        let (dir, st) = scratch_store();
        let name = crate::network::NetworkName::new("web").expect("name");
        let g = st.lock_global_exclusive().expect("global");
        let n = g.lock_network(&name).expect("net");
        let nonce = HelperNonce::generate().expect("nonce");
        let listen = DnsListenAddr::new(std::net::Ipv4Addr::LOCALHOST, 5353).expect("listen");
        n.write_dns_helper_intent(&DnsHelperIntent::new(name.clone(), nonce.clone(), listen))
            .expect("intent");
        let child = spawn_nonce_sleeper(&nonce);
        let pid = child.id();
        wait_nonce_sleeper_stopped(pid, &nonce);
        let adopt = adopt_spawned(&pid.to_string(), &nonce).expect("adopt");
        let expected = read_identity(pid).expect("identity");
        assert_eq!(adopt.identity.as_ref(), Some(&expected));
        let recorded = record_spawn_identity(&n, &nonce, listen, &adopt).expect("record");
        assert_eq!(recorded.as_ref(), Some(&expected));
        let intent = n.read_dns_helper_intent().expect("read").expect("intent");
        let got = intent.identity().expect("identity recorded");
        assert_eq!(got.pid, pid);
        assert_eq!(got.start_time_ticks, expected.start_time_ticks);
        assert_eq!(got.boot_id, expected.boot_id);
        // 起動元が止まった状態（pidfd を失う）。
        drop(adopt);
        let r = recover_dns_helper_intent(
            &n,
            &mut std::iter::empty(),
            &crate::instrument::NoopNetOpRecorder,
        )
        .expect("recover");
        assert_eq!(r, IntentRecovery::Recovered { stopped: 1 });
        assert!(n.read_dns_helper_intent().expect("read").is_none());
        assert!(!std::path::Path::new(&format!("/proc/{pid}/stat")).exists());
        drop(n);
        drop(g);
        let _ = std::fs::remove_dir_all(dir);
    }

    /// SEC-1・#3414: nonce を持たない生存中のプロセスの同一性は記録しない（意図記録は不変・相手は生存）。
    #[test]
    fn net5_3414_spawn_without_nonce_is_not_recorded() {
        let mut child = spawn_sleeper();
        let nonce = HelperNonce::generate().expect("nonce");
        assert!(adopt_spawned(&child.id().to_string(), &nonce).is_none());
        assert!(child.try_wait().expect("try_wait").is_none());
        child.kill().expect("kill");
        child.wait().expect("wait");
    }

    /// #3414: 終了済み（ゾンビ）の相手は回収用の pidfd だけを返し、同一性は記録しない。
    #[test]
    #[allow(clippy::zombie_processes)]
    fn net5_3414_spawn_exited_has_no_identity() {
        let child = spawn_sleeper();
        let pid = child.id();
        let pidfd = open_pidfd(pid).expect("pidfd");
        kill_via_pidfd(pidfd.as_fd()).expect("kill");
        assert!(wait_exit(pidfd.as_fd(), Duration::from_secs(5)).expect("wait"));
        let nonce = HelperNonce::generate().expect("nonce");
        let adopt = adopt_spawned(&pid.to_string(), &nonce).expect("adopt");
        assert!(adopt.identity.is_none());
        assert!(process::reap_pidfd_nohang(adopt.pidfd.as_fd()).expect("reap"));
    }

    /// #3414: `SPAWN` が先ならフックが識別行の前に 1 回だけ呼ばれ、識別行が先なら呼ばれない。
    /// フックが失敗したら識別行は読まずに戻る（pipe に残る）。
    #[test]
    fn net5_3414_spawn_hook_order_and_failure() {
        let mut calls = Vec::new();
        let mut rx = pipe_with(b"SPAWN 4242\nIDENT 1 2 b n\n");
        let pre = read_pre_ack_lines(
            &mut rx,
            &Deadline::after(Duration::from_secs(2)),
            &mut |r| {
                calls.push(r.to_owned());
                Ok(())
            },
        );
        assert_eq!(calls, vec!["4242".to_owned()]);
        assert!(pre.spawn_first);

        let mut calls = 0;
        let mut rx = pipe_with(b"IDENT 1 2 b n\nSPAWN 4242\n");
        let pre = read_pre_ack_lines(
            &mut rx,
            &Deadline::after(Duration::from_secs(2)),
            &mut |_| {
                calls += 1;
                Ok(())
            },
        );
        assert_eq!(calls, 0);
        assert!(!pre.spawn_first);

        let mut rx = pipe_with(b"SPAWN 4242\nIDENT 1 2 b n\n");
        let pre = read_pre_ack_lines(
            &mut rx,
            &Deadline::after(Duration::from_secs(2)),
            &mut |_| Err(err(NetErrorCode::Internal, "hook failed")),
        );
        assert_eq!(
            pre.ident.expect_err("hook error").code(),
            NetErrorCode::Internal
        );
        let rest = read_line_deadline(&mut rx, 64, &Deadline::after(Duration::from_secs(2)));
        assert_eq!(rest.expect("ident left in pipe"), "IDENT 1 2 b n");
    }

    fn scratch_store() -> (std::path::PathBuf, crate::network_store::NetworkStore) {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = std::env::temp_dir().join(format!(
            "fandhe-dnsh-rec-{}-{}",
            std::process::id(),
            HelperNonce::generate().expect("nonce")
        ));
        std::fs::create_dir_all(&dir).expect("mkdir");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        let st = crate::network_store::NetworkStore::open(&dir).expect("open");
        st.create(&crate::network_store::NetworkDefinition::pasta("web").expect("def"))
            .expect("create");
        (dir, st)
    }

    /// 同一性つき（`id` が `Some`）または無しの意図記録を書いて、候補なしで回収した結果を返す。
    fn recover_with(id: Option<ProcessIdentity>) -> (IntentRecovery, bool) {
        let (dir, st) = scratch_store();
        let name = crate::network::NetworkName::new("web").expect("name");
        let g = st.lock_global_exclusive().expect("global");
        let n = g.lock_network(&name).expect("net");
        let mut intent = DnsHelperIntent::new(
            name.clone(),
            HelperNonce::generate().expect("nonce"),
            DnsListenAddr::new(std::net::Ipv4Addr::LOCALHOST, 5353).expect("listen"),
        );
        if let Some(id) = id {
            intent = intent.with_identity(id).expect("identity");
        }
        n.write_dns_helper_intent(&intent).expect("intent");
        let r = recover_dns_helper_intent(
            &n,
            &mut std::iter::empty(),
            &crate::instrument::NoopNetOpRecorder,
        )
        .expect("recover");
        let kept = n.read_dns_helper_intent().expect("read").is_some();
        drop(n);
        drop(g);
        let _ = std::fs::remove_dir_all(dir);
        (r, kept)
    }

    /// NET-5・REPAIR-5・#3344: 回収前に終了してゾンビになった子は、候補なしでも意図記録の同一性で帰属して回収される。
    #[test]
    #[allow(clippy::zombie_processes)]
    fn net5_3344_recover_reaps_zombie_by_recorded_identity() {
        let child = spawn_sleeper();
        let pid = child.id();
        let pidfd = open_pidfd(pid).expect("pidfd");
        let identity = read_identity(pid).expect("identity");
        kill_via_pidfd(pidfd.as_fd()).expect("kill");
        assert!(wait_exit(pidfd.as_fd(), Duration::from_secs(5)).expect("wait"));
        let stat = format!("/proc/{pid}/stat");
        assert!(std::path::Path::new(&stat).exists(), "zombie before");
        let (r, kept) = recover_with(Some(identity));
        assert_eq!(r, IntentRecovery::Recovered { stopped: 1 });
        assert!(!kept, "intent record is removed");
        assert!(!std::path::Path::new(&stat).exists(), "zombie reaped");
    }

    /// NET-5・#3344: 生存中のヘルパーも候補なしで同一性により止まり、回収される。
    #[test]
    #[allow(clippy::zombie_processes)]
    fn net5_3344_recover_kills_live_process_by_recorded_identity() {
        let child = spawn_sleeper();
        let pid = child.id();
        let identity = read_identity(pid).expect("identity");
        let (r, kept) = recover_with(Some(identity));
        assert_eq!(r, IntentRecovery::Recovered { stopped: 1 });
        assert!(!kept);
        assert!(!std::path::Path::new(&format!("/proc/{pid}/stat")).exists());
    }

    /// NET-5・SEC-1・#3344: 開始時刻が違う（pid の再利用）なら何も送らない。意図記録は消える。
    #[test]
    fn net5_3344_recover_ignores_reused_pid() {
        let mut child = spawn_sleeper();
        let mut identity = read_identity(child.id()).expect("identity");
        identity.start_time_ticks += 1;
        let (r, kept) = recover_with(Some(identity));
        assert_eq!(r, IntentRecovery::Recovered { stopped: 0 });
        assert!(!kept);
        assert!(child.try_wait().expect("try_wait").is_none(), "left alone");
        child.kill().expect("kill");
        child.wait().expect("wait");
    }

    /// NET-5・#3344: 同一性の無い旧形式の意図記録は従来どおり（候補なしなら 0 件で消える）。
    #[test]
    fn net5_3344_recover_without_identity_is_unchanged() {
        let (r, kept) = recover_with(None);
        assert_eq!(r, IntentRecovery::Recovered { stopped: 0 });
        assert!(!kept);
    }
}
