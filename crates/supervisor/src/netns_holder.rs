//! netns holder の起動・待ち・停止・回収（supervisor 側。NET-9・CORE-1・CORE-6・SUP-12・REPAIR-4・REPAIR-5・#3198。
//! `docs/design/rootless-network.md` 12.2・12.9・12.10・12.14）。
//!
//! rootless の pasta 構成では pasta の対象を専用の holder にする。holder は supervisor 自身の実行ファイル
//! （`/proc/self/exe`）を `netns-holder` で exec し直したプロセスで、本体は
//! `fandhe_container_net::netns_holder::run_netns_holder_main`（bin の main が [`is_holder_invocation`] で振り分ける）、
//! 通信路と READY の検証は `fandhe_container_net::netns_holder::NetnsHolderChannel`（net crate）が持つ。
//! 本モジュールはその上に「プロセスとして起動し、期限つきで待ち、段階を上げて止め、必ず回収する」層を足す。
//!
//! # 呼び出し元（REPAIR-3）
//! `crate::pasta_attach` の `PastaAttachHook` が、core の exec 直前の同期点（#1939）から呼ぶ（#1940）。起動途中の失敗での
//! 逆順の停止・PID 1 の回収後の pasta → holder の停止・途中死の検知もそちらが行う。pidfd による監視は採らず、本モジュールの
//! 生存確認は未回収の `Child` の `try_wait` で行う（std の `create_pidfd` は unstable で、`sys` に `pidfd_open` も無い。
//! unsafe を足さない）。restart で作り直す経路は、再 launch 自体は #2043 で成立したが、holder を含む構成での restart は未確認（#341・#3331）。

//! # 起動の制約（12.10・fail-closed）
//! - **main スレッドから呼ぶ**: holder の `PR_SET_PDEATHSIG` は spawn したスレッドの終了でも届く。start の手順 8
//!   （launch を含む）は入口の main スレッドが直接行うため同じ寿命になる。main でなければ拒否する
//! - **capability を持たない supervisor からだけ起動する**: 実効・許可・ambient が 0 でなければ拒否する（rootless でない
//!   構成での誤用を防ぐ。holder 自身も capset で落とす）
//! - **単一スレッド区間でスレッドを作らない**: 手順 8 は単一スレッド前提の区間のため、spawn・待ち・停止の中でスレッドを
//!   作らず、`stderr_sink` も呼ばない。構造化ログ（`netns_holder_ready` / `netns_holder_exit`）の材料
//!   （[`HolderReady`]・[`HolderStopOutcome`]）を返すだけで、出力は呼び出し側が区間を抜けた後に行う
//!
//! # 回収の保証（12.9・12.10）
//! - 起動の途中の失敗: SIGKILL と回収（[`REAP_TIMEOUT`]）をしてから失敗を返す。holder を残さない
//! - 停止: [`NetnsHolderProcess::stop`] は STOP を送り [`STOP_GRACE`] 待ち、超えたら SIGKILL して [`REAP_TIMEOUT`]
//!   以内に回収する。回収後の pid へシグナルを送らない（pid の再利用を避ける。#2545）
//! - [`Drop`]: 端を閉じて EOF を伝え、SIGKILL と回収を試みる。回収できなければ zombie のまま残す（回収用のスレッドを
//!   単一スレッド区間で作らないため。zombie の間は pid が再利用されず、supervisor の終了で init が回収する）
//! - delete: holder はディスクに何も残さないので、すること自体が無い（`@pasta/<id>` の後始末は pasta 側。#1938・#1940）
//! - supervisor の異常終了: holder 自身の PDEATHSIG と socket の EOF で終わる。本モジュールに処理は無い
//!   （`tests/netns_holder_launch_userns.rs` で照合する）

use std::ffi::OsStr;
use std::io::Read as _;
use std::os::unix::process::{CommandExt as _, ExitStatusExt as _};
use std::process::{Child, ChildStderr, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use fandhe_container_core::traits::types::{ErrorCode, TraitError};
use fandhe_container_net::error::{NetError, NetErrorCode};
pub use fandhe_container_net::netns_holder::HolderReady;
use fandhe_container_net::netns_holder::{
    NETNS_HOLDER_SUBCOMMAND, NetnsHolderChannel, NetnsHolderFds, READY_TIMEOUT, REAP_TIMEOUT,
    STOP_GRACE,
};

/// holder の stderr を材料へ載せる上限（エスケープ後。12.9）。
pub const STDERR_CAP: usize = 4096;

/// holder の `argv[0]`（固定。`/proc/self/exe` のパス文字列を使わない）。
const HOLDER_ARG0: &str = "fandhe-container-supervisor";

/// 起動の失敗（Timeout 以外）で、holder が自分で終わるのを待つ短い猶予（stderr の材料を取り逃さないため）。
const FAILURE_EXIT_GRACE: Duration = Duration::from_millis(200);

/// 回収待ちのポーリング間隔の上限。
const POLL_STEP: Duration = Duration::from_millis(5);

/// bin の main が holder へ振り分ける呼び出しか（第 1 引数が `netns-holder`）。`run_main` より前に判定する。
pub fn is_holder_invocation(first: Option<&OsStr>) -> bool {
    first == Some(OsStr::new(NETNS_HOLDER_SUBCOMMAND))
}

/// `NetErrorCode` を `ErrorCode` へ写す（コードを潰さない。写像の実体は `net_error::net_code_to_trait`）。
pub fn trait_code(code: NetErrorCode) -> ErrorCode {
    crate::net_error::net_code_to_trait(code)
}

/// 起動の失敗。コードを保ったまま [`TraitError`] へ写せ、holder の stderr（エスケープ済み）を材料として持つ。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetnsHolderSpawnError {
    code: ErrorCode,
    message: String,
    /// 回収できた holder の stderr（エスケープ済み・[`STDERR_CAP`] 以下）。message には入れない（12.9）。
    pub holder_stderr: String,
    /// holder を回収できなかったか（回収の期限切れ。zombie が残り得る）。
    pub unreaped: bool,
}

impl NetnsHolderSpawnError {
    fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            holder_stderr: String::new(),
            unreaped: false,
        }
    }

    fn from_net(e: &NetError) -> Self {
        Self::new(trait_code(e.code()), e.message())
    }

    /// 機械可読な分類。
    pub fn code(&self) -> ErrorCode {
        self.code
    }

    /// 固定の英文メッセージ。
    pub fn message(&self) -> &str {
        &self.message
    }

    /// 呼び出し元のエラー型へ写す。
    pub fn trait_error(&self) -> TraitError {
        TraitError::new(self.code, self.message.clone())
    }
}

/// holder の終了の材料（`netns_holder_exit`。REPAIR-4）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HolderExit {
    /// 終了コード（シグナルで終わったら `None`）。
    pub code: Option<i32>,
    /// 終わらせたシグナル（正常終了なら `None`）。
    pub signal: Option<i32>,
    /// holder の stderr（エスケープ済み・[`STDERR_CAP`] 以下）。
    pub stderr: String,
}

/// 停止の経路。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopPath {
    /// STOP（または既に終了していた）で [`STOP_GRACE`] 内に終わった。
    Stopped,
    /// 猶予を超えて SIGKILL し、回収した。
    Killed,
    /// SIGKILL の後も [`REAP_TIMEOUT`] 内に回収できなかった（`unreaped` に未回収の子が戻る）。
    ReapTimedOut,
}

/// [`NetnsHolderProcess::stop`] の結果（`netns_holder_exit` の材料）。
#[derive(Debug)]
pub struct HolderStopOutcome {
    /// 停止の経路。
    pub path: StopPath,
    /// 回収できたときの終了の材料。既に [`NetnsHolderProcess::try_exit`] で回収済み・未回収なら `None`。
    pub exit: Option<HolderExit>,
    /// `stop` の開始から終わりまでの時間。
    pub elapsed: Duration,
    /// [`StopPath::ReapTimedOut`] のときの未回収の子（呼び出し側が再試行できるよう戻す）。
    pub unreaped: Option<Child>,
}

/// 起動して READY を受けた holder のハンドル。drop で EOF と SIGKILL・回収を試みる（上の「回収の保証」）。
#[derive(Debug)]
pub struct NetnsHolderProcess {
    child: Option<Child>,
    chan: Option<NetnsHolderChannel>,
    stderr: Option<ChildStderr>,
    pid: u32,
    ready: HolderReady,
}

/// `/proc/thread-self` の readlink（`<tgid>/task/<tid>`）から main スレッドか判定する純関数。
fn parse_is_main_thread(link: &str) -> Result<bool, &'static str> {
    const BAD: &str = "unexpected /proc/thread-self format";
    let mut it = link.split('/');
    let tgid = it.next().filter(|s| !s.is_empty());
    let task = it.next();
    let tid = it.next().filter(|s| !s.is_empty());
    if it.next().is_some() || task != Some("task") {
        return Err(BAD);
    }
    match (tgid, tid) {
        (Some(a), Some(b))
            if a.bytes().all(|c| c.is_ascii_digit()) && b.bytes().all(|c| c.is_ascii_digit()) =>
        {
            Ok(a == b)
        }
        _ => Err(BAD),
    }
}

/// `/proc/<..>/status` から `CapPrm`・`CapEff`・`CapAmb` がすべて 0 かを判定する純関数（欄の欠落・壊れた値は `Err`）。
fn parse_caps_all_zero(status: &str) -> Result<bool, &'static str> {
    let mut seen = 0u8;
    let mut zero = true;
    for line in status.lines() {
        let (value, bit) = match line.split_once(':') {
            Some(("CapPrm", v)) => (v, 1u8),
            Some(("CapEff", v)) => (v, 2u8),
            Some(("CapAmb", v)) => (v, 4u8),
            _ => continue,
        };
        let v = value.trim();
        if v.is_empty() || !v.bytes().all(|c| c.is_ascii_hexdigit()) {
            return Err("malformed capability field");
        }
        seen |= bit;
        zero &= v.bytes().all(|c| c == b'0');
    }
    if seen != 7 {
        return Err("missing capability field");
    }
    Ok(zero)
}

/// 呼び出しスレッドが main スレッドか（`/proc/thread-self` の readlink。pasta の起動の前提確認も使う。#1940）。
pub(crate) fn is_main_thread() -> Result<bool, TraitError> {
    let internal = |m: &'static str| TraitError::new(ErrorCode::Internal, m);
    let link = std::fs::read_link("/proc/thread-self")
        .map_err(|_| internal("cannot read /proc/thread-self"))?;
    parse_is_main_thread(&link.to_string_lossy()).map_err(internal)
}

/// 起動できる状況か（main スレッド・capability 0）を確かめる。
fn check_preconditions() -> Result<(), NetnsHolderSpawnError> {
    let internal = |m: &'static str| NetnsHolderSpawnError::new(ErrorCode::Internal, m);
    let fail = |m: &'static str| NetnsHolderSpawnError::new(ErrorCode::FailedPrecondition, m);
    let link = std::fs::read_link("/proc/thread-self")
        .map_err(|_| internal("cannot read /proc/thread-self"))?;
    let main = parse_is_main_thread(&link.to_string_lossy()).map_err(internal)?;
    if !main {
        return Err(fail(
            "the netns holder must be spawned from the main thread (PDEATHSIG follows the spawning thread)",
        ));
    }
    let status = std::fs::read_to_string("/proc/thread-self/status")
        .map_err(|_| internal("cannot read /proc/thread-self/status"))?;
    match parse_caps_all_zero(&status) {
        Ok(true) => Ok(()),
        Ok(false) => Err(fail(
            "the netns holder must be spawned from a process without capabilities",
        )),
        Err(m) => Err(internal(m)),
    }
}

/// 非印字文字・`"`・`\` をエスケープし、結果が `cap` バイトを超えない手前で切る純関数。
fn escape_capped(raw: &[u8], cap: usize) -> String {
    let mut out = String::new();
    for &b in raw {
        let piece = match b {
            b'"' => "\\\"".to_owned(),
            b'\\' => "\\\\".to_owned(),
            b'\n' => "\\n".to_owned(),
            0x20..=0x7e => (b as char).to_string(),
            _ => format!("\\x{b:02x}"),
        };
        if out.len() + piece.len() > cap {
            break;
        }
        out.push_str(&piece);
    }
    out
}

/// 回収済み holder の stderr を読む（書き込み端は holder の終了で閉じる。holder は fork しないので EOF で止まる）。
fn drain_stderr(stderr: &mut Option<ChildStderr>) -> String {
    let Some(mut s) = stderr.take() else {
        return String::new();
    };
    let mut raw = Vec::new();
    let _ = (&mut s).take(STDERR_CAP as u64).read_to_end(&mut raw);
    escape_capped(&raw, STDERR_CAP)
}

/// `limit` まで `try_wait` で待つ。`Ok(None)` は期限切れ。
fn wait_until(child: &mut Child, limit: Duration) -> std::io::Result<Option<ExitStatus>> {
    let end = Instant::now() + limit;
    loop {
        if let Some(st) = child.try_wait()? {
            return Ok(Some(st));
        }
        let now = Instant::now();
        if now >= end {
            return Ok(None);
        }
        std::thread::sleep(POLL_STEP.min(end - now));
    }
}

fn exit_of(status: ExitStatus, stderr: String) -> HolderExit {
    HolderExit {
        code: status.code(),
        signal: status.signal(),
        stderr,
    }
}

/// SIGKILL して [`REAP_TIMEOUT`] 内に回収する。回収できたら終了の材料、できなければ `None`。
fn kill_and_reap(child: &mut Child, stderr: &mut Option<ChildStderr>) -> Option<HolderExit> {
    // 既に回収済みなら std は何も送らない（回収後の pid へシグナルを送らない。#2545）。
    let _ = child.kill();
    match wait_until(child, REAP_TIMEOUT) {
        Ok(Some(st)) => Some(exit_of(st, drain_stderr(stderr))),
        _ => None,
    }
}

/// holder を起動し、`fds` を送り、READY を `deadline` までに受ける。
///
/// 手順の順序は固定: 期限の確認 → 前提の確認（main スレッド・capability 0）→ socketpair → exec し直しの spawn →
/// fd の送出 → READY の待ち（`min(READY_TIMEOUT, 残り)`）。READY までの失敗は SIGKILL と回収をしてから返す。
pub fn spawn_netns_holder(
    fds: NetnsHolderFds,
    deadline: Instant,
) -> Result<NetnsHolderProcess, NetnsHolderSpawnError> {
    spawn_inner(fds, deadline, &[NETNS_HOLDER_SUBCOMMAND], true)
}

fn spawn_inner(
    fds: NetnsHolderFds,
    deadline: Instant,
    args: &[&str],
    wait_for_ready: bool,
) -> Result<NetnsHolderProcess, NetnsHolderSpawnError> {
    let remaining = |d: Instant| d.saturating_duration_since(Instant::now());
    if remaining(deadline).is_zero() {
        return Err(NetnsHolderSpawnError::new(
            ErrorCode::Timeout,
            "no time left to spawn the netns holder",
        ));
    }
    check_preconditions()?;
    let (chan, child_end) =
        NetnsHolderChannel::pair().map_err(|e| NetnsHolderSpawnError::from_net(&e))?;
    let mut child = Command::new("/proc/self/exe")
        .arg0(HOLDER_ARG0)
        .args(args)
        .env_clear()
        .current_dir("/")
        .stdin(Stdio::from(child_end))
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| {
            let code = if e.kind() == std::io::ErrorKind::PermissionDenied {
                ErrorCode::PermissionDenied
            } else {
                ErrorCode::Internal
            };
            NetnsHolderSpawnError::new(code, "cannot spawn the netns holder")
        })?;
    let mut stderr = child.stderr.take();
    let pid = child.id();
    let started = Instant::now();
    let outcome = (|| {
        let sent = chan
            .send_namespaces(fds)
            .map_err(|e| NetnsHolderSpawnError::from_net(&e))?;
        if !wait_for_ready {
            return Ok(HolderReady {
                identity: sent.identity(),
                elapsed: started.elapsed(),
            });
        }
        let budget = READY_TIMEOUT.min(remaining(deadline));
        if budget.is_zero() {
            return Err(NetnsHolderSpawnError::new(
                ErrorCode::Timeout,
                "no time left to wait for the netns holder READY",
            ));
        }
        chan.wait_ready(&sent, budget)
            .map_err(|e| NetnsHolderSpawnError::from_net(&e))
    })();
    match outcome {
        Ok(ready) => Ok(NetnsHolderProcess {
            child: Some(child),
            chan: Some(chan),
            stderr,
            pid,
            ready,
        }),
        Err(mut e) => {
            drop(chan);
            if e.code != ErrorCode::Timeout {
                // holder は自分で失敗を報告して終わるのが普通のため、stderr の 1 行を書き終えるのを短く待ってから kill する。
                let _ = wait_until(&mut child, FAILURE_EXIT_GRACE);
            }
            match kill_and_reap(&mut child, &mut stderr) {
                Some(exit) => e.holder_stderr = exit.stderr,
                None => {
                    // 回収できなかった子は zombie のまま残す（Drop と同じ扱い。スレッドを作らない）。
                    e.unreaped = true;
                }
            }
            Err(e)
        }
    }
}

impl NetnsHolderProcess {
    /// holder の pid（pasta の対象。回収前だけ有効）。
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// READY の検証結果（`netns_holder_ready` の材料）。
    pub fn ready(&self) -> &HolderReady {
        &self.ready
    }

    /// 生存確認（待たない）。終了していれば回収して材料を返す（以後 [`Self::stop`] の `exit` は `None`）。
    pub fn try_exit(&mut self) -> Result<Option<HolderExit>, TraitError> {
        let Some(child) = self.child.as_mut() else {
            return Ok(None);
        };
        match child.try_wait() {
            Ok(None) => Ok(None),
            Ok(Some(st)) => {
                self.child = None;
                self.chan = None;
                Ok(Some(exit_of(st, drain_stderr(&mut self.stderr))))
            }
            Err(_) => Err(TraitError::new(
                ErrorCode::Internal,
                "cannot poll the netns holder",
            )),
        }
    }

    /// 段階を上げて止める: STOP → [`STOP_GRACE`] → SIGKILL → [`REAP_TIMEOUT`]（12.9）。
    pub fn stop(mut self) -> HolderStopOutcome {
        let started = Instant::now();
        let Some(mut child) = self.child.take() else {
            return HolderStopOutcome {
                path: StopPath::Stopped,
                exit: None,
                elapsed: started.elapsed(),
                unreaped: None,
            };
        };
        if let Some(chan) = self.chan.take() {
            // 送れなくても、端を閉じる EOF と後続の SIGKILL があるため先へ進む。
            let _ = chan.send_stop();
            drop(chan);
        }
        if let Ok(Some(st)) = wait_until(&mut child, STOP_GRACE) {
            return HolderStopOutcome {
                path: StopPath::Stopped,
                exit: Some(exit_of(st, drain_stderr(&mut self.stderr))),
                elapsed: started.elapsed(),
                unreaped: None,
            };
        }
        match kill_and_reap(&mut child, &mut self.stderr) {
            Some(exit) => HolderStopOutcome {
                path: StopPath::Killed,
                exit: Some(exit),
                elapsed: started.elapsed(),
                unreaped: None,
            },
            None => HolderStopOutcome {
                path: StopPath::ReapTimedOut,
                exit: None,
                elapsed: started.elapsed(),
                unreaped: Some(child),
            },
        }
    }
}

impl Drop for NetnsHolderProcess {
    fn drop(&mut self) {
        // 端を閉じて EOF を伝え、SIGKILL と回収を試みる。回収できなければ zombie のまま残す（モジュール doc）。
        self.chan = None;
        if let Some(mut child) = self.child.take() {
            let _ = kill_and_reap(&mut child, &mut self.stderr);
        }
    }
}

/// 試験専用: 引数を差し替えて起動する（応答しない・READY の前に終わる holder を作る）。
/// リリースビルドでは `exec-test-support` ごとコンパイルを止める（`lib.rs`）。
#[cfg(feature = "exec-test-support")]
#[doc(hidden)]
pub fn spawn_netns_holder_with_args_for_test(
    fds: NetnsHolderFds,
    deadline: Instant,
    args: &[&str],
) -> Result<NetnsHolderProcess, NetnsHolderSpawnError> {
    spawn_inner(fds, deadline, args, true)
}

/// 試験専用: READY を待たずに返す（STOP を無視する holder へ `stop` の段階を試すため）。`ready` の識別は送った fd のもの。
#[cfg(feature = "exec-test-support")]
#[doc(hidden)]
pub fn spawn_netns_holder_unready_for_test(
    fds: NetnsHolderFds,
    deadline: Instant,
    args: &[&str],
) -> Result<NetnsHolderProcess, NetnsHolderSpawnError> {
    spawn_inner(fds, deadline, args, false)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// NET-9・ERR-1: 全コードの写像を具体値で固定する（`Timeout` が `Internal` に潰れない）。
    #[test]
    fn trait_code_maps_every_net_code() {
        let cases = [
            (NetErrorCode::InvalidArgument, ErrorCode::InvalidArgument),
            (NetErrorCode::Timeout, ErrorCode::Timeout),
            (NetErrorCode::PermissionDenied, ErrorCode::PermissionDenied),
            (NetErrorCode::Unimplemented, ErrorCode::Unimplemented),
            (
                NetErrorCode::ResourceExhausted,
                ErrorCode::ResourceExhausted,
            ),
            (NetErrorCode::NotFound, ErrorCode::NotFound),
            (NetErrorCode::AlreadyExists, ErrorCode::AlreadyExists),
            (
                NetErrorCode::FailedPrecondition,
                ErrorCode::FailedPrecondition,
            ),
            (NetErrorCode::Internal, ErrorCode::Internal),
            (NetErrorCode::DataLoss, ErrorCode::Internal),
        ];
        assert_eq!(cases.len(), NetErrorCode::ALL.len());
        for (n, t) in cases {
            assert_eq!(trait_code(n), t, "{n:?}");
        }
    }

    /// NET-9・CORE-1: `/proc/thread-self` の解析。
    #[test]
    fn thread_self_parsing() {
        assert_eq!(parse_is_main_thread("123/task/123"), Ok(true));
        assert_eq!(parse_is_main_thread("123/task/124"), Ok(false));
        for bad in [
            "",
            "123",
            "123/task",
            "123/foo/123",
            "a/task/1",
            "1/task/",
            "/task/1",
            "1/task/1/x",
        ] {
            assert!(parse_is_main_thread(bad).is_err(), "{bad:?}");
        }
    }

    /// NET-9・SEC-1: capability 欄の解析（0・非 0・欄の欠落・壊れた値）。
    #[test]
    fn capability_parsing() {
        let zero = "CapInh:\t0000000000000000\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\nCapBnd:\t000001ffffffffff\nCapAmb:\t0000000000000000\n";
        assert_eq!(parse_caps_all_zero(zero), Ok(true));
        let eff = zero.replace("CapEff:\t0000000000000000", "CapEff:\t0000000000000001");
        assert_eq!(parse_caps_all_zero(&eff), Ok(false));
        let amb = zero.replace("CapAmb:\t0000000000000000", "CapAmb:\t0000000000200000");
        assert_eq!(parse_caps_all_zero(&amb), Ok(false));
        let prm = zero.replace("CapPrm:\t0000000000000000", "CapPrm:\t000001ffffffffff");
        assert_eq!(parse_caps_all_zero(&prm), Ok(false));
        assert!(parse_caps_all_zero("CapPrm:\t0\nCapEff:\t0\n").is_err());
        assert!(parse_caps_all_zero("CapPrm:\t0\nCapEff:\tzz\nCapAmb:\t0\n").is_err());
        assert!(parse_caps_all_zero("").is_err());
    }

    /// REPAIR-4: stderr のエスケープと 4 KiB の境界。
    #[test]
    fn stderr_escape_and_cap() {
        assert_eq!(escape_capped(b"ok line", 64), "ok line");
        assert_eq!(
            escape_capped(b"a\"b\\c\nd\x01\xff", 64),
            "a\\\"b\\\\c\\nd\\x01\\xff"
        );
        assert_eq!(escape_capped(b"abc", 2), "ab");
        assert_eq!(escape_capped(b"a\x01", 3), "a");
        assert_eq!(escape_capped(b"a\x01", 5), "a\\x01");
        let big = vec![b'x'; STDERR_CAP * 2];
        assert_eq!(escape_capped(&big, STDERR_CAP).len(), STDERR_CAP);
        let ctl = vec![0x01u8; STDERR_CAP];
        assert!(escape_capped(&ctl, STDERR_CAP).len() <= STDERR_CAP);
    }

    /// NET-9: 振り分けの判定。
    #[test]
    fn dispatch_decision() {
        assert!(is_holder_invocation(Some(OsStr::new("netns-holder"))));
        for other in ["start", "", "netns-holder2", "NETNS-HOLDER"] {
            assert!(!is_holder_invocation(Some(OsStr::new(other))), "{other:?}");
        }
        assert!(!is_holder_invocation(None));
    }

    /// REPAIR-5: 残りが 0 の期限は spawn せず `Timeout`。
    #[test]
    fn exhausted_deadline_is_timeout_without_spawning() {
        use std::os::fd::OwnedFd;
        let open = |p: &str| OwnedFd::from(std::fs::File::open(p).expect(p));
        let fds = NetnsHolderFds::new(open("/proc/self/ns/user"), open("/proc/self/ns/net"))
            .expect("distinct own namespaces");
        let e = spawn_netns_holder(fds, Instant::now()).expect_err("no time left");
        assert_eq!(e.code(), ErrorCode::Timeout);
        assert_eq!(e.trait_error().code(), ErrorCode::Timeout);
        assert!(!e.unreaped);
    }
}
