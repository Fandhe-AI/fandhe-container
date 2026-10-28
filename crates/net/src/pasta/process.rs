//! pasta の起動・準備完了の待ち・途中死の検出・段階を上げた停止と回収（NET-9・REPAIR-5・ERR-1・SEC-4・REPAIR-4・#1938。
//! `docs/design/rootless-network.md` 12.7〜12.10）。
//!
//! - 呼び出し元: supervisor の launch 手順 8（#1940）。検証済みの [`super::binary::PastaBinary`]（#1936）、
//!   ポート公開の検証済みの型 [`super::port_forward::PastaPortForwards`]（#1937）、置き場所
//!   [`super::run_dir::PastaRunDir`]、対象の netns を保持する holder の pid（#3197・#3198）を受けて [`spawn_pasta`] を呼ぶ。
//!   実行中は `is_alive`（定期の呼び出しは #1940 の監視の責務）、終了時は `stop` を呼ぶ。
//! - 起動: `argv[0]` は常に `pasta`、env は空、cwd は `/`、stdin / stdout は null、stderr は pipe。argv は
//!   [`pasta_argv`] の固定の並びで、シェルを介さない。pre_exec で `PR_SET_PDEATHSIG=SIGKILL` を設定し、
//!   親が `getppid` と一致することを確かめる（12.10 の (1)。`sys::pasta`）。
//! - 準備完了: pasta は `-f -P <pid>` で、初期化が終わった後に自分の PID をファイルへ書く（`man pasta` の `-P`・`-f`）。
//!   よって `pid` の中身が spawn した子の PID と 10 進で完全一致したときを準備完了とする（ファイルが現れただけでは
//!   判定しない。書き込みの途中の部分読みは「まだ」）。事前に古い `pid` は `PastaRunDir::prepare` が消している。
//!   並行して `try_wait` で子の生存を見て、準備完了前の終了は `FailedPrecondition`、期限切れは `Timeout`。
//!   失敗時は必ず kill して期限つきで回収してから返す。
//! - 停止: SIGTERM → [`PASTA_STOP_GRACE`] → SIGKILL → [`PASTA_REAP_TIMEOUT`]。回収済みの pid にはシグナルを送らない。
//! - スレッド: 作らない。supervisor の launch の手順 8 は「main スレッド・単一スレッドの区間」であり、PDEATHSIG は
//!   spawn したスレッドの寿命に紐づくため。回収スレッドへ移す [`PastaProcess::detach_reaper`] は呼び出し側が
//!   単一スレッドの区間の外から明示的に呼ぶ opt-in。
//! - stderr: pipe で受け、先頭の [`PASTA_STDERR_CAP`] バイト分をエスケープして保持し、以降は読み捨てる。
//!   読み出しは準備完了の待ちの間と `is_alive` / `stop*` の呼び出しのたびに行う（REPAIR-3: 長時間呼ばれないと
//!   pipe〔64 KiB〕が満ちて pasta の書き込みが止まりうる。定期呼び出しは #1940 の責務）。
//! - エラーの message は固定の英文で、パス・argv・pasta の出力を含まない（ERR-1）。診断の材料は
//!   [`PastaDiagnostics`] として返し、構造化ログ（`pasta_ready` / `pasta_exit`）と監査（SEC-4）への記録は呼び出し側が行う。
//! - Linux 以外では [`spawn_pasta`] は `Unimplemented`（置き場所の型を作れないため実際には到達しない。CLI-1）。

use std::ffi::OsString;
use std::net::Ipv4Addr;
use std::path::Path;
use std::process::{Child, ChildStderr};
use std::time::{Duration, Instant};

use super::binary::PastaBinary;
use super::port_forward::PastaPortForwards;
use super::run_dir::PastaRunDir;
use crate::error::{NetError, NetErrorCode};
use crate::instrument::{NetOpKind, NetOpRecorder, record_net_op};

/// pasta に渡す namespace 内のインタフェース名（12.7）。
pub const PASTA_IFNAME: &str = "eth0";
/// コンテナ内の DNS 転送先アドレス（`--dns-forward`。12.7）。
pub const PASTA_DNS_FORWARD: Ipv4Addr = Ipv4Addr::new(169, 254, 1, 1);
/// 準備完了の待ちの既定。
pub const PASTA_READY_TIMEOUT_DEFAULT: Duration = Duration::from_secs(5);
/// 準備完了の待ちの上限。
pub const PASTA_READY_TIMEOUT_MAX: Duration = Duration::from_secs(10);
/// SIGTERM の後、SIGKILL までの待ち。
pub const PASTA_STOP_GRACE: Duration = Duration::from_secs(2);
/// SIGKILL の後、回収までの待ち。
pub const PASTA_REAP_TIMEOUT: Duration = Duration::from_secs(1);
/// 回収スレッドが SIGKILL の後に回収を試みる上限（超えたら子のハンドルを手放す）。
pub const PASTA_DETACHED_REAP_DEADLINE: Duration = Duration::from_secs(30);
/// 保持する stderr の上限バイト数（エスケープ後）。
pub const PASTA_STDERR_CAP: usize = 4096;
/// PID ファイルとして受ける最大バイト数（10 進 + 改行 1 個）。
pub const PASTA_PID_FILE_MAX: usize = 32;
/// 準備完了の待ちの 1 回の刻み。
#[cfg_attr(
    not(target_os = "linux"),
    allow(dead_code, reason = "Linux 以外では起動経路が無い")
)]
const READY_POLL: Duration = Duration::from_millis(5);
/// 回収待ちの刻み。
const REAP_POLL: Duration = Duration::from_millis(10);

/// 準備完了の待ちの値が不正。
pub const MSG_PASTA_TIMEOUT_RANGE: &str =
    "pasta ready timeout must be greater than 0 and at most 10 seconds";
/// 対象 PID が不正（0・1・自分自身）。
pub const MSG_PASTA_TARGET: &str = "pasta target pid must not be 0, 1, or the current process";
/// 起動の許可なし。
pub const MSG_PASTA_SPAWN_DENIED: &str = "permission denied while starting pasta";
/// 起動時の資源枯渇。
pub const MSG_PASTA_SPAWN_RESOURCE: &str = "resource exhausted while starting pasta";
/// 親の死亡を検出した（pre_exec の getppid 不一致）。
pub const MSG_PASTA_PARENT_GONE: &str = "parent process changed while starting pasta";
/// 起動の失敗。
pub const MSG_PASTA_SPAWN_FAILED: &str = "pasta could not be started";
/// 準備完了前の終了。
pub const MSG_PASTA_EXITED_EARLY: &str = "pasta exited before it became ready";
/// 準備完了の期限切れ。
pub const MSG_PASTA_READY_TIMEOUT: &str = "pasta did not become ready before the deadline";
/// PID ファイルが基準外（種別・所有者・リンク数・長さ・文字）。
pub const MSG_PASTA_PID_FILE: &str =
    "pasta pid file is not a trusted regular file with a decimal pid";
/// 子の状態を得られない。
pub const MSG_PASTA_WAIT: &str = "pasta process state could not be determined";
/// 停止が期限内に終わらない。
pub const MSG_PASTA_STOP_TIMEOUT: &str = "pasta did not stop before the deadline";
/// 回収スレッドを作れない。
pub const MSG_PASTA_REAPER_SPAWN: &str = "pasta reaper thread could not be started";
/// 既に停止済み。
pub const MSG_PASTA_STOPPED: &str = "pasta has already been stopped";
/// Linux 以外では使えない。
pub const MSG_PASTA_UNSUPPORTED_OS: &str = super::binary::MSG_UNSUPPORTED_OS;

fn err(code: NetErrorCode, msg: &'static str) -> NetError {
    NetError::new(code, msg)
}

/// pasta が参加する対象のプロセス（holder）の PID（12.2）。
///
/// 0・1・自分自身は拒否する（pid 1 や自分を対象にするとホストの netns を対象にしてしまうため）。呼び出し側は
/// holder の未回収の `Child` の pid を渡すこと。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PastaTarget(u32);

impl PastaTarget {
    /// PID から作る。
    pub fn from_pid(pid: u32) -> Result<Self, NetError> {
        if pid <= 1 || pid == std::process::id() {
            return Err(err(NetErrorCode::InvalidArgument, MSG_PASTA_TARGET));
        }
        Ok(Self(pid))
    }

    /// PID。
    pub fn pid(self) -> u32 {
        self.0
    }
}

/// pasta の argv（`argv[0]` を含まない）の固定の並び（12.7）。
///
/// `-f --quiet -P <pid_file> --config-net -4 -I eth0 --map-host-loopback none --map-guest-addr none
/// --dns-forward 169.254.1.1 <ポート公開の引数…> <対象 PID>`。`--host-lo-to-ns-lo` は付けない。OS 非依存の純関数。
pub fn pasta_argv(
    pid_file: &Path,
    forwards: &PastaPortForwards,
    target: PastaTarget,
) -> Vec<OsString> {
    let mut v: Vec<OsString> = ["-f", "--quiet", "-P"].map(OsString::from).to_vec();
    v.push(pid_file.as_os_str().to_owned());
    for a in [
        "--config-net",
        "-4",
        "-I",
        PASTA_IFNAME,
        "--map-host-loopback",
        "none",
        "--map-guest-addr",
        "none",
        "--dns-forward",
    ] {
        v.push(OsString::from(a));
    }
    v.push(OsString::from(PASTA_DNS_FORWARD.to_string()));
    v.extend(forwards.pasta_args());
    v.push(OsString::from(target.0.to_string()));
    v
}

/// 準備完了の待ちの値の検査（0 と上限超えは `InvalidArgument`）。
pub fn check_ready_timeout(t: Duration) -> Result<(), NetError> {
    if t.is_zero() || t > PASTA_READY_TIMEOUT_MAX {
        return Err(err(NetErrorCode::InvalidArgument, MSG_PASTA_TIMEOUT_RANGE));
    }
    Ok(())
}

/// PID ファイルの中身の判定結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(
    not(target_os = "linux"),
    allow(dead_code, reason = "Linux 以外では起動経路が無く、試験だけが使う")
)]
pub(crate) enum PidFileState {
    /// まだ準備ができていない（空・書き込み途中・別の値）。
    NotYet,
    /// 対象の PID と一致した。
    Matches,
    /// 形が不正（長すぎる・10 進以外の文字）。
    Invalid,
}

/// PID ファイルの中身（最大 `PASTA_PID_FILE_MAX + 1` バイトまで読んだもの）を判定する。OS 非依存の純関数。
#[cfg_attr(
    not(target_os = "linux"),
    allow(dead_code, reason = "Linux 以外では起動経路が無く、試験だけが使う")
)]
pub(crate) fn parse_pid_file(bytes: &[u8], child_pid: u32) -> PidFileState {
    if bytes.len() > PASTA_PID_FILE_MAX {
        return PidFileState::Invalid;
    }
    if bytes.is_empty() {
        return PidFileState::NotYet;
    }
    let body = bytes.strip_suffix(b"\n").unwrap_or(bytes);
    if body.is_empty() || !body.iter().all(u8::is_ascii_digit) {
        return PidFileState::Invalid;
    }
    if body == child_pid.to_string().as_bytes() {
        PidFileState::Matches
    } else {
        PidFileState::NotYet
    }
}

/// 失敗した段階。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PastaStage {
    /// 引数の検査。
    Prepare,
    /// プロセスの起動。
    Spawn,
    /// 準備完了の待ち。
    Ready,
    /// 実行中。
    Running,
    /// 停止。
    Stop,
}

/// 子の終了状態（終了コードまたは終了シグナル）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct PastaExit {
    /// 終了コード。
    pub code: Option<i32>,
    /// 終了シグナル。
    pub signal: Option<i32>,
}

/// 失敗・停止の診断の材料（構造化ログと監査は呼び出し側。ERR-1 のため message には入れない）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct PastaDiagnostics {
    /// 失敗した段階。
    pub stage: PastaStage,
    /// 子の終了状態（回収できたとき）。
    pub exit: PastaExit,
    /// 開始からの経過時間。
    pub elapsed: Duration,
    /// stderr の先頭（エスケープ済み・[`PASTA_STDERR_CAP`] バイト以下）。
    pub stderr_excerpt: String,
}

/// 準備完了の結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PastaReady {
    pid: u32,
    elapsed: Duration,
}

impl PastaReady {
    /// pasta の PID。
    pub fn pid(&self) -> u32 {
        self.pid
    }
    /// spawn から準備完了までの時間。
    pub fn elapsed(&self) -> Duration {
        self.elapsed
    }
}

/// 停止の経路。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PastaStopPath {
    /// SIGTERM で終わった。
    Term,
    /// SIGKILL まで要した。
    Kill,
    /// 停止の要求の前に終わっていた。
    AlreadyExited,
}

/// 停止の結果。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct PastaStopOutcome {
    /// 終わらせた経路。
    pub path: PastaStopPath,
    /// 終了状態。
    pub exit: PastaExit,
    /// stderr の先頭（エスケープ済み）。
    pub stderr_excerpt: String,
}

/// 起動の失敗。未回収の子が残るときは [`Self::take_unreaped`] で回収権を受け取る。
#[derive(Debug)]
pub struct PastaSpawnError {
    error: NetError,
    diagnostics: PastaDiagnostics,
    unreaped: Option<PastaProcess>,
}

impl PastaSpawnError {
    /// 機械可読な分類。
    pub fn code(&self) -> NetErrorCode {
        self.error.code()
    }
    /// 固定の英文のメッセージ。
    pub fn message(&self) -> &str {
        self.error.message()
    }
    /// 診断の材料。
    pub fn diagnostics(&self) -> &PastaDiagnostics {
        &self.diagnostics
    }
    /// 回収できなかった子（あれば）。呼び出し側が再度停止を試みる。
    pub fn take_unreaped(&mut self) -> Option<PastaProcess> {
        self.unreaped.take()
    }
    /// 共通のエラー型へ。
    pub fn into_net_error(self) -> NetError {
        self.error
    }
}

impl std::fmt::Display for PastaSpawnError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.error.fmt(f)
    }
}

impl std::error::Error for PastaSpawnError {}

/// 停止の失敗。回収できなかった子は `unreaped` に残る。
#[derive(Debug)]
pub struct PastaStopError {
    /// 失敗の分類。
    pub error: NetError,
    /// 回収できなかった子（再試行用）。
    pub unreaped: Option<Box<PastaProcess>>,
}

impl std::fmt::Display for PastaStopError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.error.fmt(f)
    }
}

impl std::error::Error for PastaStopError {}

/// stderr の先頭を、非印字文字をエスケープして上限まで保持する。
#[derive(Debug, Default)]
struct StderrExcerpt {
    text: String,
}

impl StderrExcerpt {
    #[cfg_attr(
        not(target_os = "linux"),
        allow(dead_code, reason = "Linux 以外では起動経路が無い")
    )]
    fn push(&mut self, bytes: &[u8]) {
        for &b in bytes {
            let (piece, len): (String, usize) = match b {
                b'\\' => ("\\\\".to_owned(), 2),
                b'\n' => ("\\n".to_owned(), 2),
                b'\t' => ("\\t".to_owned(), 2),
                b'\r' => ("\\r".to_owned(), 2),
                0x20..=0x7e => ((b as char).to_string(), 1),
                _ => (format!("\\x{b:02x}"), 4),
            };
            if self.text.len() + len > PASTA_STDERR_CAP {
                return;
            }
            self.text.push_str(&piece);
        }
    }
}

/// 起動した pasta（未回収の子と stderr の読み口を持つ）。
///
/// `Drop` は SIGKILL を送り [`PASTA_REAP_TIMEOUT`] だけ回収を試みる。回収できなければ zombie のまま残す
/// （zombie の間は pid が再利用されず、プロセスの終了で init が回収する）。スレッドは作らない。
#[derive(Debug)]
pub struct PastaProcess {
    pid: u32,
    child: Option<Child>,
    stderr: Option<ChildStderr>,
    excerpt: StderrExcerpt,
}

/// 期限つきで子の終了を待つ（待つだけで kill しない）。
fn wait_exit(child: &mut Child, timeout: Duration) -> Option<std::process::ExitStatus> {
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(st)) => return Some(st),
            Ok(None) => {}
            Err(_) => return None,
        }
        let left = timeout.saturating_sub(started.elapsed());
        if left.is_zero() {
            return None;
        }
        std::thread::sleep(left.min(REAP_POLL));
    }
}

impl PastaProcess {
    /// pasta の PID。
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// 子がまだ動いているか。終了していれば `Ok(false)`（終了状態は保持され、後の `stop*` が返す）。
    /// 状態を得られないときは `Err`（生死不明を「死んでいる」と誤認しない）。stderr も読めるだけ読む。
    pub fn is_alive(&mut self) -> Result<bool, NetError> {
        imp::drain(&mut self.stderr, &mut self.excerpt, Duration::ZERO);
        match self.child.as_mut() {
            None => Ok(false),
            Some(c) => match c.try_wait() {
                Ok(None) => Ok(true),
                Ok(Some(_)) => Ok(false),
                Err(_) => Err(err(NetErrorCode::Internal, MSG_PASTA_WAIT)),
            },
        }
    }

    /// kill して期限内に回収する。回収できたら終了状態を返し、子を手放す。
    #[cfg_attr(
        not(target_os = "linux"),
        allow(dead_code, reason = "Linux 以外では起動経路が無い")
    )]
    fn kill_reap(&mut self, timeout: Duration) -> Option<std::process::ExitStatus> {
        let child = self.child.as_mut()?;
        let _ = child.kill();
        let st = wait_exit(child, timeout)?;
        self.child = None;
        Some(st)
    }

    /// 停止して回収する。期限を超えたら `Timeout` を返し、子は `self` に残す（再試行できる）。
    ///
    /// 手順は SIGTERM → [`PASTA_STOP_GRACE`] → SIGKILL → [`PASTA_REAP_TIMEOUT`]。回収済みの pid にはシグナルを送らない。
    pub fn stop_checked(&mut self) -> Result<PastaStopOutcome, NetError> {
        imp::drain(&mut self.stderr, &mut self.excerpt, Duration::ZERO);
        let Some(child) = self.child.as_mut() else {
            return Err(err(NetErrorCode::FailedPrecondition, MSG_PASTA_STOPPED));
        };
        let (path, status) = match child.try_wait() {
            Err(_) => return Err(err(NetErrorCode::Internal, MSG_PASTA_WAIT)),
            Ok(Some(st)) => (PastaStopPath::AlreadyExited, st),
            Ok(None) => {
                let sent = imp::send_term(child)?;
                match wait_exit(
                    child,
                    if sent {
                        PASTA_STOP_GRACE
                    } else {
                        PASTA_REAP_TIMEOUT
                    },
                ) {
                    Some(st) => {
                        let p = if sent {
                            PastaStopPath::Term
                        } else {
                            PastaStopPath::AlreadyExited
                        };
                        (p, st)
                    }
                    None => {
                        let _ = child.kill();
                        match wait_exit(child, PASTA_REAP_TIMEOUT) {
                            Some(st) => (PastaStopPath::Kill, st),
                            None => {
                                return Err(err(NetErrorCode::Timeout, MSG_PASTA_STOP_TIMEOUT));
                            }
                        }
                    }
                }
            }
        };
        self.child = None;
        imp::drain(&mut self.stderr, &mut self.excerpt, Duration::ZERO);
        self.stderr = None;
        Ok(PastaStopOutcome {
            path,
            exit: imp::exit_of(status),
            stderr_excerpt: std::mem::take(&mut self.excerpt.text),
        })
    }

    /// [`Self::stop_checked`] の消費版。期限超過のときは未回収のハンドルをエラーに入れて返す。
    pub fn stop(mut self) -> Result<PastaStopOutcome, PastaStopError> {
        match self.stop_checked() {
            Ok(o) => Ok(o),
            Err(error) => {
                let unreaped = self.child.is_some().then(|| Box::new(self));
                Err(PastaStopError { error, unreaped })
            }
        }
    }

    /// [`Self::stop`] を `PastaStop` として計装する（REPAIR-4）。
    pub fn stop_with_recorder(
        self,
        recorder: &dyn NetOpRecorder,
    ) -> Result<PastaStopOutcome, PastaStopError> {
        record_net_op(recorder, NetOpKind::PastaStop, || self.stop())
    }

    /// kill して回収を専用スレッドへ移す。**単一スレッドの区間の外から明示的に呼ぶこと**（暗黙には使わない）。
    /// 期限内に回収できなかった子を zombie にしないための最終手段。
    ///
    /// スレッドの生成に失敗したときは子の所有権を `self` へ戻して `unreaped` に入れて返す（呼び出し側が
    /// 再試行でき、捨てれば `Drop` が kill と回収を試みる。panic しない）。回収スレッドは SIGKILL の後
    /// [`PASTA_DETACHED_REAP_DEADLINE`] まで有限時間だけ回収を試み、超えたら子のハンドルを手放して終わる
    /// （zombie のまま残り、プロセスの終了で init が回収する。REPAIR-5）。
    pub fn detach_reaper(mut self) -> Result<(), PastaStopError> {
        let Some(child) = self.child.take() else {
            return Ok(());
        };
        let slot = std::sync::Arc::new(std::sync::Mutex::new(Some(child)));
        let thread_slot = std::sync::Arc::clone(&slot);
        let spawned = std::thread::Builder::new()
            .name("pasta-reaper".to_string())
            .spawn(move || {
                let taken = thread_slot.lock().ok().and_then(|mut g| g.take());
                if let Some(mut child) = taken {
                    let _ = child.kill();
                    let _ = wait_exit(&mut child, PASTA_DETACHED_REAP_DEADLINE);
                }
            });
        match spawned {
            Ok(_) => Ok(()),
            Err(_) => {
                // 生成失敗: スレッドは動いていないので子を取り戻す（毒化していても中身は取り出す）。
                let back = match slot.lock() {
                    Ok(mut g) => g.take(),
                    Err(p) => p.into_inner().take(),
                };
                self.child = back;
                let unreaped = self.child.is_some().then(|| Box::new(self));
                Err(PastaStopError {
                    error: err(NetErrorCode::Internal, MSG_PASTA_REAPER_SPAWN),
                    unreaped,
                })
            }
        }
    }
}

impl Drop for PastaProcess {
    fn drop(&mut self) {
        if let Some(child) = self.child.as_mut() {
            let _ = child.kill();
            let _ = wait_exit(child, PASTA_REAP_TIMEOUT);
        }
    }
}

/// pasta を起動し、準備完了まで期限つきで待つ。
///
/// 手順: 期限の検査 → argv の組み立て → spawn（pre_exec で PDEATHSIG）→ `pid` の中身が子の PID と一致するまで
/// ポーリング（子の終了と stderr も見る）。失敗時は kill して期限つきで回収してから返す。
/// **main スレッドから呼ぶこと**（PDEATHSIG は spawn したスレッドの終了でも届く。12.10。呼び出し側の責務）。
pub fn spawn_pasta(
    binary: &PastaBinary,
    run_dir: &PastaRunDir,
    forwards: &PastaPortForwards,
    target: PastaTarget,
    ready_timeout: Duration,
) -> Result<(PastaProcess, PastaReady), Box<PastaSpawnError>> {
    imp::spawn(binary, run_dir, forwards, target, ready_timeout)
}

/// [`spawn_pasta`] を `PastaStart` として計装する（REPAIR-4）。
pub fn spawn_pasta_with_recorder(
    binary: &PastaBinary,
    run_dir: &PastaRunDir,
    forwards: &PastaPortForwards,
    target: PastaTarget,
    ready_timeout: Duration,
    recorder: &dyn NetOpRecorder,
) -> Result<(PastaProcess, PastaReady), Box<PastaSpawnError>> {
    record_net_op(recorder, NetOpKind::PastaStart, || {
        spawn_pasta(binary, run_dir, forwards, target, ready_timeout)
    })
}

#[cfg(not(target_os = "linux"))]
mod imp {
    use super::*;

    pub(super) fn spawn(
        _binary: &PastaBinary,
        _run_dir: &PastaRunDir,
        _forwards: &PastaPortForwards,
        _target: PastaTarget,
        _ready_timeout: Duration,
    ) -> Result<(PastaProcess, PastaReady), Box<PastaSpawnError>> {
        Err(Box::new(PastaSpawnError {
            error: err(NetErrorCode::Unimplemented, MSG_PASTA_UNSUPPORTED_OS),
            diagnostics: PastaDiagnostics {
                stage: PastaStage::Prepare,
                exit: PastaExit::default(),
                elapsed: Duration::ZERO,
                stderr_excerpt: String::new(),
            },
            unreaped: None,
        }))
    }

    pub(super) fn drain(_s: &mut Option<ChildStderr>, _e: &mut StderrExcerpt, _wait: Duration) {}

    pub(super) fn send_term(_child: &mut Child) -> Result<bool, NetError> {
        Ok(false)
    }

    pub(super) fn exit_of(st: std::process::ExitStatus) -> PastaExit {
        PastaExit {
            code: st.code(),
            signal: None,
        }
    }
}

#[cfg(target_os = "linux")]
mod imp {
    use super::*;
    use crate::sys::{self, Deadline, Readiness, SysError};
    use std::fs::OpenOptions;
    use std::io::Read as _;
    use std::os::fd::AsFd as _;
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
    use std::os::unix::process::{CommandExt as _, ExitStatusExt as _};
    use std::process::{Command, Stdio};

    pub(super) fn exit_of(st: std::process::ExitStatus) -> PastaExit {
        PastaExit {
            code: st.code(),
            signal: st.signal(),
        }
    }

    pub(super) fn send_term(child: &mut Child) -> Result<bool, NetError> {
        sys::pasta::send_sigterm_unreaped(child).map_err(|e| match e {
            SysError::Unsupported => err(NetErrorCode::Unimplemented, MSG_PASTA_UNSUPPORTED_OS),
            SysError::Os(x) if x == sys::EPERM => {
                err(NetErrorCode::PermissionDenied, MSG_PASTA_SPAWN_DENIED)
            }
            _ => err(NetErrorCode::Internal, MSG_PASTA_WAIT),
        })
    }

    /// stderr を読めるだけ読む。最初の 1 回だけ `wait` まで待ち、以降は待たない。EOF・読み取り失敗で閉じる。
    pub(super) fn drain(stderr: &mut Option<ChildStderr>, ex: &mut StderrExcerpt, wait: Duration) {
        let mut w = wait;
        for _ in 0..64 {
            let Some(s) = stderr.as_mut() else { return };
            match sys::wait_readable(s.as_fd(), &Deadline::after(w)) {
                Ok(Readiness::TimedOut) => return,
                Ok(_) => {}
                Err(_) => {
                    *stderr = None;
                    return;
                }
            }
            w = Duration::ZERO;
            let mut buf = [0u8; 1024];
            match s.read(&mut buf) {
                Ok(0) => {
                    *stderr = None;
                    return;
                }
                Ok(n) => ex.push(buf.get(..n).unwrap_or(&[])),
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => {
                    *stderr = None;
                    return;
                }
            }
        }
    }

    fn map_spawn_error(e: &std::io::Error) -> NetError {
        if sys::pasta::is_parent_gone(e) {
            return err(NetErrorCode::FailedPrecondition, MSG_PASTA_PARENT_GONE);
        }
        match e.raw_os_error() {
            Some(x) if x == sys::EACCES || x == sys::EPERM => {
                err(NetErrorCode::PermissionDenied, MSG_PASTA_SPAWN_DENIED)
            }
            Some(x) if x == sys::EMFILE || x == sys::ENFILE || x == sys::ENOMEM => {
                err(NetErrorCode::ResourceExhausted, MSG_PASTA_SPAWN_RESOURCE)
            }
            _ => err(NetErrorCode::Internal, MSG_PASTA_SPAWN_FAILED),
        }
    }

    enum PidCheck {
        NotYet,
        Ready,
    }

    /// `pid` を O_NOFOLLOW・O_NONBLOCK で開き、通常ファイル・所有者 euid・nlink 1 を確かめてから中身を判定する。
    fn check_pid_file(path: &Path, child_pid: u32, euid: u32) -> Result<PidCheck, NetError> {
        let bad = || err(NetErrorCode::FailedPrecondition, MSG_PASTA_PID_FILE);
        let file = match OpenOptions::new()
            .read(true)
            .custom_flags(sys::O_NOFOLLOW | sys::O_NONBLOCK)
            .open(path)
        {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(PidCheck::NotYet),
            Err(_) => return Err(bad()),
        };
        let m = file.metadata().map_err(|_| bad())?;
        if !m.is_file() || m.uid() != euid || m.nlink() != 1 {
            return Err(bad());
        }
        let mut buf = Vec::with_capacity(PASTA_PID_FILE_MAX + 1);
        file.take(PASTA_PID_FILE_MAX as u64 + 1)
            .read_to_end(&mut buf)
            .map_err(|_| bad())?;
        match parse_pid_file(&buf, child_pid) {
            PidFileState::Matches => Ok(PidCheck::Ready),
            PidFileState::NotYet => Ok(PidCheck::NotYet),
            PidFileState::Invalid => Err(bad()),
        }
    }

    fn fail(
        mut proc: PastaProcess,
        error: NetError,
        stage: PastaStage,
        started: Instant,
        known: Option<PastaExit>,
    ) -> PastaSpawnError {
        drain(&mut proc.stderr, &mut proc.excerpt, Duration::ZERO);
        let exit = match known {
            Some(e) => e,
            None => proc
                .kill_reap(PASTA_REAP_TIMEOUT)
                .map(exit_of)
                .unwrap_or_default(),
        };
        drain(&mut proc.stderr, &mut proc.excerpt, Duration::ZERO);
        let diagnostics = PastaDiagnostics {
            stage,
            exit,
            elapsed: started.elapsed(),
            stderr_excerpt: proc.excerpt.text.clone(),
        };
        let unreaped = proc.child.is_some().then_some(proc);
        PastaSpawnError {
            error,
            diagnostics,
            unreaped,
        }
    }

    pub(super) fn spawn(
        binary: &PastaBinary,
        run_dir: &PastaRunDir,
        forwards: &PastaPortForwards,
        target: PastaTarget,
        ready_timeout: Duration,
    ) -> Result<(PastaProcess, PastaReady), Box<PastaSpawnError>> {
        let started = Instant::now();
        let early = |error: NetError, stage: PastaStage| {
            Box::new(PastaSpawnError {
                error,
                diagnostics: PastaDiagnostics {
                    stage,
                    exit: PastaExit::default(),
                    elapsed: started.elapsed(),
                    stderr_excerpt: String::new(),
                },
                unreaped: None,
            })
        };
        check_ready_timeout(ready_timeout).map_err(|e| early(e, PastaStage::Prepare))?;

        let argv = pasta_argv(run_dir.pid_path(), forwards, target);
        let mut cmd = Command::new(binary.path());
        cmd.arg0(super::super::binary::PASTA_ARGV0)
            .args(&argv)
            .env_clear()
            .current_dir("/")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        sys::pasta::set_pdeathsig_on_spawn(&mut cmd, std::process::id());
        let mut child = cmd
            .spawn()
            .map_err(|e| early(map_spawn_error(&e), PastaStage::Spawn))?;
        let stderr = child.stderr.take();
        let mut proc = PastaProcess {
            pid: child.id(),
            child: Some(child),
            stderr,
            excerpt: StderrExcerpt::default(),
        };

        let pid_open = run_dir.pid_open_path();
        let euid = sys::effective_uid();
        let deadline = Deadline::after(ready_timeout);
        loop {
            let st = match proc.child.as_mut() {
                Some(c) => c.try_wait(),
                None => Ok(None),
            };
            match st {
                Ok(Some(st)) => {
                    proc.child = None;
                    let e = err(NetErrorCode::FailedPrecondition, MSG_PASTA_EXITED_EARLY);
                    return Err(Box::new(fail(
                        proc,
                        e,
                        PastaStage::Ready,
                        started,
                        Some(exit_of(st)),
                    )));
                }
                Ok(None) => {}
                Err(_) => {
                    let e = err(NetErrorCode::Internal, MSG_PASTA_WAIT);
                    return Err(Box::new(fail(proc, e, PastaStage::Ready, started, None)));
                }
            }
            match check_pid_file(&pid_open, proc.pid, euid) {
                Ok(PidCheck::Ready) => break,
                Ok(PidCheck::NotYet) => {}
                Err(e) => return Err(Box::new(fail(proc, e, PastaStage::Ready, started, None))),
            }
            let remaining = deadline.remaining();
            if remaining.is_zero() {
                let e = err(NetErrorCode::Timeout, MSG_PASTA_READY_TIMEOUT);
                return Err(Box::new(fail(proc, e, PastaStage::Ready, started, None)));
            }
            let step = remaining.min(READY_POLL);
            if proc.stderr.is_some() {
                drain(&mut proc.stderr, &mut proc.excerpt, step);
            } else {
                std::thread::sleep(step);
            }
        }
        let ready = PastaReady {
            pid: proc.pid,
            elapsed: started.elapsed(),
        };
        Ok((proc, ready))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fwd(specs: &[&str]) -> PastaPortForwards {
        PastaPortForwards::parse_all(specs.iter().copied()).expect("forwards")
    }

    fn s(v: &[OsString]) -> Vec<String> {
        v.iter().map(|a| a.to_string_lossy().into_owned()).collect()
    }

    #[test]
    fn argv_exact_without_forwards() {
        let t = PastaTarget::from_pid(4242).expect("target");
        let a = s(&pasta_argv(Path::new("/run/u/@pasta/c/pid"), &fwd(&[]), t));
        let expect = [
            "-f",
            "--quiet",
            "-P",
            "/run/u/@pasta/c/pid",
            "--config-net",
            "-4",
            "-I",
            "eth0",
            "--map-host-loopback",
            "none",
            "--map-guest-addr",
            "none",
            "--dns-forward",
            "169.254.1.1",
            "-t",
            "none",
            "-u",
            "none",
            "-T",
            "none",
            "-U",
            "none",
            "4242",
        ];
        assert_eq!(a, expect);
        assert!(!a.iter().any(|x| x == "--host-lo-to-ns-lo"));
    }

    #[test]
    fn argv_includes_forwards_before_target() {
        let t = PastaTarget::from_pid(77).expect("target");
        let f = fwd(&["127.0.0.1:8080:80", "9090:90/udp"]);
        let a = s(&pasta_argv(Path::new("/p"), &f, t));
        let fixed = 14;
        let tail: Vec<String> = s(&f.pasta_args());
        assert_eq!(a.get(fixed..fixed + tail.len()), Some(tail.as_slice()));
        assert_eq!(a.last().map(String::as_str), Some("77"));
    }

    #[test]
    fn target_rejects_pid_0_1_and_self() {
        for pid in [0, 1, std::process::id()] {
            let e = PastaTarget::from_pid(pid).expect_err("rejected");
            assert_eq!(e.code(), NetErrorCode::InvalidArgument);
            assert_eq!(e.message(), MSG_PASTA_TARGET);
        }
        assert_eq!(PastaTarget::from_pid(2).expect("ok").pid(), 2);
    }

    #[test]
    fn ready_timeout_table() {
        for ok in [
            Duration::from_nanos(1),
            Duration::from_secs(5),
            Duration::from_secs(10),
        ] {
            check_ready_timeout(ok).expect("ok");
        }
        for bad in [
            Duration::ZERO,
            Duration::from_secs(10) + Duration::from_nanos(1),
        ] {
            let e = check_ready_timeout(bad).expect_err("bad");
            assert_eq!(e.code(), NetErrorCode::InvalidArgument);
            assert_eq!(e.message(), MSG_PASTA_TIMEOUT_RANGE);
        }
    }

    #[test]
    fn pid_file_content_table() {
        use PidFileState::*;
        let long = [b'1'; 33];
        let ok32 = [b'1'; 32];
        let cases: [(&[u8], PidFileState); 11] = [
            (b"", NotYet),
            (b"12", NotYet),
            (b"1234", Matches),
            (b"1234\n", Matches),
            (b"12345\n", NotYet),
            (b"1234\n\n", Invalid),
            (b"12a4", Invalid),
            (b" 1234", Invalid),
            (b"\n", Invalid),
            (&long, Invalid),
            (&ok32, NotYet),
        ];
        for (bytes, want) in cases {
            assert_eq!(parse_pid_file(bytes, 1234), want, "{bytes:?}");
        }
    }

    #[test]
    fn stderr_excerpt_escapes_and_caps() {
        let mut ex = StderrExcerpt::default();
        ex.push(b"a\x01\\\n\xff");
        assert_eq!(ex.text, "a\\x01\\\\\\n\\xff");
        ex.push(&[b'A'; 10_000]);
        assert!(ex.text.len() <= PASTA_STDERR_CAP);
        assert_eq!(ex.text.len(), PASTA_STDERR_CAP);
    }

    #[test]
    fn messages_are_fixed_english() {
        for m in [
            MSG_PASTA_TIMEOUT_RANGE,
            MSG_PASTA_TARGET,
            MSG_PASTA_EXITED_EARLY,
            MSG_PASTA_READY_TIMEOUT,
            MSG_PASTA_PID_FILE,
            MSG_PASTA_STOP_TIMEOUT,
        ] {
            assert!(m.is_ascii() && !m.contains('/'), "{m}");
        }
    }
}
