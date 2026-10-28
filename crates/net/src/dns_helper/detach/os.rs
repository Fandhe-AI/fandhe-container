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

use std::io::Write as _;
use std::net::SocketAddrV4;
use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use super::{
    ACK, ARG_DETACH, ARG_NONCE, ARG_STAGE2, DNS_HELPER_ACK_TIMEOUT, DNS_HELPER_KILL_REAP_TIMEOUT,
    DNS_HELPER_STAGE1_EXIT_TIMEOUT, DNS_HELPER_STOP_GRACE, DnsHelperStopRequest, HelperProcessOps,
    IDENT_LINE_MAX, IDENT_PREFIX, MAX_RECOVERY_CANDIDATES, RequestOutcome, StopOutcome, StopStage,
    run_stop_sequence,
};
use crate::dns_helper::identity::{
    self, BootId, ProcessIdentity, Verify, read_boot_id, read_identity, read_limited,
    verify_pidfd_target,
};
use crate::dns_helper::record::{DnsHelperIntent, DnsHelperRecord, HelperNonce};
use crate::dns_helper::{
    DnsListenAddr, READY_LINE_MAX, check_timeout, kill_reap_or_detach, map_io, parse_ready,
    read_line_limited,
};
use crate::error::{NetError, NetErrorCode};
use crate::instrument::{NetOpKind, NetOpRecorder, record_net_op};
use crate::network_store::NetworkLockGuard;
use crate::sys::{self, Deadline, Readiness, SysError, process};

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
/// 消す（[`StopOutcome::StaleRecord`]）。同一なら停止要求 → 猶予 → pidfd へ SIGKILL の順に進める。SIGKILL の後も
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
    let Some(record) = guard.read_dns_helper()? else {
        return Ok(StopOutcome::NoRecord);
    };
    let pidfd = match open_pidfd(record.identity().pid) {
        Ok(fd) => fd,
        Err(e) if e.code() == NetErrorCode::NotFound => {
            guard.remove_dns_helper()?;
            return Ok(StopOutcome::AlreadyGone);
        }
        Err(e) => return Err(e),
    };
    match verify_pidfd_target(pidfd.as_fd(), record.identity())? {
        Verify::Same => {}
        Verify::Different => {
            guard.remove_dns_helper()?;
            return Ok(StopOutcome::StaleRecord);
        }
        Verify::Gone => {
            // subreaper の下では終了済みでもゾンビとして pidfd が開ける。記録を消す前に pidfd 経由で回収する。
            let _ = process::reap_pidfd_nohang(pidfd.as_fd());
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
/// 片付けてから起動する）。失敗時は、起動窓の記録（意図記録・`dns-helper`）を、プロセスの終了を確認できたときだけ消す。
/// 確認できなければ記録を残して報告する（次の操作で回収する）。
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
    if guard.read_dns_helper()?.is_some() || guard.read_dns_helper_intent()?.is_some() {
        return Err(err(
            NetErrorCode::AlreadyExists,
            "dns helper record already exists",
        ));
    }
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
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut stage1 = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            return Err(fail_before_ack(guard, None, map_io("spawn dns helper", &e)));
        }
    };
    let stdin = stage1.stdin.take();
    let Some(stdout) = stage1.stdout.take() else {
        let _ = kill_reap_or_detach(stage1, DNS_HELPER_KILL_REAP_TIMEOUT);
        return Err(fail_before_ack(
            guard,
            stdin,
            err(NetErrorCode::Internal, "helper stdout unavailable"),
        ));
    };
    if let Err(e) = wait_stage1(stage1) {
        return Err(fail_before_ack(guard, stdin, e));
    }

    // 識別行と準備完了行を同じ pipe から順に読む。読み手のスレッドは pipe が閉じれば（ヘルパーの終了で）戻る。
    let (tx, rx) = mpsc::channel::<Result<String, &'static str>>();
    // OS がスレッドの生成を拒否しても（pids.max 等）panic せず、起動前の後始末をして失敗にする。
    let reader = std::thread::Builder::new()
        .name("dns-helper-reader".to_owned())
        .spawn(move || {
            let mut out = stdout;
            let first = read_line_limited(&mut out, IDENT_LINE_MAX);
            let failed = first.is_err();
            let _ = tx.send(first);
            if !failed {
                let _ = tx.send(read_line_limited(&mut out, READY_LINE_MAX));
            }
        });
    if let Err(e) = reader {
        return Err(fail_before_ack(
            guard,
            stdin,
            map_io("spawn dns helper reader thread", &e),
        ));
    }

    let ident_line = match rx.recv_timeout(DNS_HELPER_ACK_TIMEOUT) {
        Ok(Ok(l)) => l,
        Ok(Err(msg)) => {
            return Err(fail_before_ack(
                guard,
                stdin,
                err(NetErrorCode::FailedPrecondition, msg),
            ));
        }
        Err(_) => {
            return Err(fail_before_ack(
                guard,
                stdin,
                err(
                    NetErrorCode::Timeout,
                    "dns helper did not report its identity before the deadline",
                ),
            ));
        }
    };
    let (identity, pidfd) = match confirm_identity(&ident_line, &nonce) {
        Ok(v) => v,
        Err(e) => return Err(fail_before_ack(guard, stdin, e)),
    };
    let record = match DnsHelperRecord::new(identity.clone(), nonce, listen) {
        Ok(r) => r,
        Err(e) => return Err(fail_before_ack(guard, stdin, e)),
    };
    if let Err(e) = guard.write_dns_helper(&record) {
        return Err(fail_before_ack(guard, stdin, e));
    }

    // 記録を確定した後で ack を返す。ここから先の失敗は、プロセスを pidfd 経由で止めて確認してから記録を消す。
    let acked = match stdin {
        Some(mut s) => s.write_all(ACK).and_then(|()| s.flush()).is_ok(),
        None => false,
    };
    let result = if acked {
        match rx.recv_timeout(ready_timeout) {
            Ok(Ok(line)) => parse_ready(&line, listen.socket_addr()),
            Ok(Err(msg)) => Err(err(NetErrorCode::FailedPrecondition, msg)),
            Err(_) => Err(err(
                NetErrorCode::Timeout,
                "dns helper was not ready before the deadline",
            )),
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
) -> Result<(ProcessIdentity, OwnedFd), NetError> {
    let identity = parse_ident(line, nonce)?;
    if identity.boot_id != read_boot_id()? {
        return Err(err(
            NetErrorCode::FailedPrecondition,
            "dns helper reported a different boot id",
        ));
    }
    let pidfd = match open_pidfd(identity.pid) {
        Ok(fd) => fd,
        Err(e) if e.code() == NetErrorCode::NotFound => {
            return Err(err(
                NetErrorCode::FailedPrecondition,
                "dns helper exited before its identity was confirmed",
            ));
        }
        Err(e) => return Err(e),
    };
    if verify_pidfd_target(pidfd.as_fd(), &identity)? != Verify::Same {
        return Err(err(
            NetErrorCode::FailedPrecondition,
            "dns helper identity did not match the process",
        ));
    }
    Ok((identity, pidfd))
}

/// ack を返す前の失敗。stdin を閉じて（段 2 は EOF で終了し bind しない）意図記録を消す。
fn fail_before_ack(
    guard: &NetworkLockGuard<'_>,
    stdin: Option<ChildStdin>,
    e: NetError,
) -> NetError {
    drop(stdin);
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
        .remove_dns_helper()
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
) -> Result<IntentRecovery, NetError> {
    guard.require_exclusive()?;
    let Some(intent) = guard.read_dns_helper_intent()? else {
        return Ok(IntentRecovery::NoIntent);
    };
    if guard.read_dns_helper()?.is_some() {
        guard.remove_dns_helper_intent()?;
        return Ok(IntentRecovery::IntentDiscarded);
    }
    let mut stopped = 0usize;
    let mut seen = 0usize;
    for pid in (&mut *candidates).take(MAX_RECOVERY_CANDIDATES) {
        seen += 1;
        // 消滅（NotFound）を確認できたものだけ読み飛ばす。確認できないエラーは意図記録（再試行に要る nonce）を
        // 残したまま失敗にする。
        if pid == 0 || !cmdline_has_nonce(pid, intent.nonce())? {
            continue;
        }
        let pidfd = match open_pidfd(pid) {
            Ok(fd) => fd,
            Err(e) if e.code() == NetErrorCode::NotFound => continue,
            Err(e) => return Err(with_note(e, "intent record kept")),
        };
        let identity = match read_identity(pid) {
            Ok(i) => i,
            Err(e) if e.code() == NetErrorCode::NotFound => continue,
            Err(e) => return Err(with_note(e, "intent record kept")),
        };
        // pidfd 取得後の再確認: 同じ nonce を持ち、開始時刻が変わっておらず、まだ終了していない。
        if !cmdline_has_nonce(pid, intent.nonce())?
            || verify_pidfd_target(pidfd.as_fd(), &identity)? != Verify::Same
        {
            continue;
        }
        if !kill_and_confirm(pidfd.as_fd()) {
            return Err(err(
                NetErrorCode::Timeout,
                "dns helper did not exit before the deadline; intent record kept",
            ));
        }
        stopped += 1;
    }
    // 上限に達したのに候補が残っていれば、走査を終えていない。意図記録を消すと生存したヘルパーの nonce を失う。
    if seen >= MAX_RECOVERY_CANDIDATES && candidates.next().is_some() {
        return Err(err(
            NetErrorCode::ResourceExhausted,
            "too many recovery candidates; intent record kept",
        ));
    }
    guard.remove_dns_helper_intent()?;
    Ok(IntentRecovery::Recovered { stopped })
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
pub(crate) fn run_stage1(listen: DnsListenAddr, nonce: &HelperNonce) -> Result<(), NetError> {
    process::setsid().map_err(|_| err(NetErrorCode::Internal, "setsid failed"))?;
    let child = Command::new("/proc/self/exe")
        .arg(ARG_STAGE2)
        .arg("--listen")
        .arg(listen.to_string())
        .arg(ARG_NONCE)
        .arg(nonce.as_str())
        .env_clear()
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| map_io("spawn dns helper stage 2", &e))?;
    // 段 2 は待たない。段 1 の終了で init か subreaper の子になり、そこで回収される（二重 fork と同じ形）。
    #[allow(clippy::zombie_processes)]
    drop(child);
    Ok(())
}

/// 段 2（`--dns-helper-stage2`）の握手: 識別行を stdout へ送り、stdin の `ACK` を [`DNS_HELPER_ACK_TIMEOUT`] まで待つ。
/// 期限切れ・EOF・不一致は失敗（呼び出し元は bind せずに終了する。D14 (ii)）。
pub(crate) fn run_stage2_handshake(nonce: &HelperNonce) -> Result<(), NetError> {
    use std::io::Read as _;
    let me = identity::read_self_identity()?;
    let mut stdout = std::io::stdout();
    writeln!(
        stdout,
        "{IDENT_PREFIX}{} {} {} {}",
        me.pid, me.start_time_ticks, me.boot_id, nonce
    )
    .and_then(|()| stdout.flush())
    .map_err(|_| err(NetErrorCode::Internal, "cannot write identity line"))?;
    let stdin = std::io::stdin();
    match sys::wait_readable(stdin.as_fd(), &Deadline::after(DNS_HELPER_ACK_TIMEOUT)) {
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
    let mut buf = [0u8; 4];
    // 部分読み・EINTR で有効な ACK を取り逃さないよう read_exact（EINTR は再試行される）で読む。
    match stdin.lock().read_exact(&mut buf) {
        Ok(()) if &buf == ACK => Ok(()),
        _ => Err(err(
            NetErrorCode::FailedPrecondition,
            "ack was not received",
        )),
    }
}
