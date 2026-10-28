//! rootless の pasta 構成を supervisor の起動経路へ結線し、コンテナの寿命に連動させる層
//! （NET-9・NET-6・CORE-1・ERR-1・REPAIR-4・REPAIR-5・SEC-4・#1940。方式は `docs/design/rootless-network.md` 12.2・12.10）。
//!
//! # 役割と呼び出し文脈
//!
//! - start の手順 7（`ProductionStartDeps::build_launcher`）が、起動オプションの network が `Attachable`
//!   （ユーザー定義名。rootless）のときだけ、本モジュールの [`PastaAttachHook`] を core の
//!   `ProductionLauncherBuilder::netns_attach_hook` へ渡し、できた launcher を [`PastaAttachingLauncher`] で包む。
//! - core の launcher は PID 1 の exec の直前の同期点で netns と user namespace の fd 2 本を渡し、
//!   [`PastaAttachHook::attach`] を呼ぶ。フックは **holder の起動 → pasta の起動と準備完了の待ち** の順で行い、
//!   成功したときだけ core が PID 1 へ合図する（12.2 の (2)〜(6)）。pasta の準備が整う前に entrypoint は動かない。
//! - launch が成功すれば [`PastaAttachingLauncher::launch`] が起動済みの holder と pasta を
//!   [`PastaGuardedProcess`] に載せて返す。以後は supervisor の監視（`wait`）が、途中死の検出・PID 1 の回収後の
//!   pasta → holder の停止・`@pasta/<id>` の削除を行う（12.10）。
//!
//! # 後始末の保証（逆順の巻き戻し）
//!
//! - フックの途中の失敗: 起動済みのものを逆順（pasta → run dir → holder）に止めてから `Err` を返す
//! - launch が `Ok` の後で失敗: [`PastaAttachingLauncher::launch`] が受け渡し口に残った分を同じ順序で止める
//! - PID 1 の回収後・`terminate`・ハンドルの drop: pasta を止め、holder を止め、`@pasta/<id>` を消す（1 回だけ）
//! - 途中死: pasta か holder が先に死んだら **分離を緩めず** コンテナへ SIGTERM を送り、[`TERM_GRACE`] を超えたら
//!   SIGKILL する（ネットワーク無しで続けない。公開ポートが黙って消えない）。終了は通常の経路で restart policy に流れる
//!
//! # 単一スレッドの区間
//!
//! フックは core の launch の単一スレッドの区間から呼ばれる。スレッドを作らず、`stderr_sink` も呼ばない。この区間で
//! 出すログは [`PastaLogBuffer`] に積み、start の報告の後に `StartDeps::flush_deferred_logs` が出す。
//!
//! # 将来仕様・残余（REPAIR-3）
//!
//! - **pidfd での監視は採らない**: `pidfd_open` は `sys` の新しい `unsafe` になるため、生存確認は未回収の `Child` の
//!   `try_wait`（`wait` の周期ごと。pasta の stderr を読む責務も兼ねる）で行う。検出の遅れは `POLL_INTERVAL` 程度
//! - **restart の再 launch**: 同じ launcher とフックを通る形（起動の経路を 1 つ）だが、本番 launcher の再 launch は
//!   #2043 まで `FailedPrecondition` で拒否される。restart で動くことは本モジュールの時点では保証しない
//! - SEC-4 の監査への記録（識別の不一致）は #3330、CLI の `--network` の受け口と start での D10 の再照合は #3329、
//!   実機の通し確認は #3331
//!
//! Linux 専用（`lib.rs` で cfg）。エラーと構造化ログは固定語彙で、パス・argv・入力値を含めない（ERR-1）。

use std::os::fd::{AsFd as _, OwnedFd};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use fandhe_container_core::oci_runtime::{
    AttachableNamespaces, ContainerOutput, LaunchSpec, LaunchedProcess, NetnsAttachHook,
    ProcessExit, ProcessLauncher,
};
use fandhe_container_core::traits::{ContainerId, ErrorCode, Signal, TraitError};
use fandhe_container_net::netns_holder::NetnsHolderFds;
use fandhe_container_net::pasta::binary::PastaBinary;
use fandhe_container_net::pasta::process::{
    PASTA_READY_TIMEOUT_DEFAULT, PastaExit, PastaStopPath, check_ready_timeout,
};
use fandhe_container_net::pasta::run_dir::{remove_pasta_run_dir, validate_container_id};
use fandhe_container_net::pasta::{
    PastaPortForwards, PastaProcess, PastaRunDir, PastaTarget, spawn_pasta,
};

use crate::netns_holder::{
    HolderExit, NetnsHolderProcess, StopPath, spawn_netns_holder, trait_code,
};

/// pasta の準備完了の待ちの既定(net の `PASTA_READY_TIMEOUT_DEFAULT`)。
pub const READY_TIMEOUT_DEFAULT: Duration = PASTA_READY_TIMEOUT_DEFAULT;

/// 途中死を検出してコンテナへ SIGTERM を送ってから、SIGKILL へ上げるまでの猶予。
pub const TERM_GRACE: Duration = Duration::from_secs(10);

/// 途中死の検出で `signal` に渡す期限（送信直前の確認用）。
const SIGNAL_DEADLINE: Duration = Duration::from_secs(1);

/// `terminate` の後始末に使う、PID 1 を回収できなかったときの待ち。
const MISSING_ATTACHMENT_TERMINATE: Duration = Duration::from_secs(1);

// ---------------------------------------------------------------------------------------------
// 構造化ログ
// ---------------------------------------------------------------------------------------------

/// 構造化ログの値。`Text` は helper の stderr など任意の文字列で、JSON の文字列として必ずエンコードして出す。
///
/// helper の stderr は net の `StderrExcerpt` が診断用に整形したもの(二重引用符・バックスラッシュをそのまま保持し、
/// 非 ASCII バイトは `\xNN` の文字列にする)で、JSON のエスケープ済みではない。直接挿入すると行が壊れるため
/// [`push_json_string`] で値ごとにエンコードする(REPAIR-4)。
enum Val {
    U(u64),
    S(&'static str),
    Text(String),
}

/// `s` を JSON の文字列リテラル(両端の二重引用符を除く本体)として `out` へ足す。
/// `"`・`\`・制御文字(U+0000〜U+001F)をエスケープする。
fn push_json_string(out: &mut String, s: &str) {
    use std::fmt::Write as _;
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if u32::from(c) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c => out.push(c),
        }
    }
}

/// 1 行の構造化ログを組む（`component` / `event` / `container` と固定語彙の項目。REPAIR-4）。
fn json_line(event: &str, container: &str, fields: &[(&str, Val)]) -> String {
    let mut line = format!(
        "{{\"component\":\"supervisor\",\"event\":\"{event}\",\"container\":\"{container}\""
    );
    for (key, val) in fields {
        match val {
            Val::U(n) => line.push_str(&format!(",\"{key}\":{n}")),
            Val::S(s) => line.push_str(&format!(",\"{key}\":\"{s}\"")),
            Val::Text(s) => {
                line.push_str(&format!(",\"{key}\":\""));
                push_json_string(&mut line, s);
                line.push('"');
            }
        }
    }
    line.push_str("}\n");
    line
}

/// 単一スレッドの区間で出すログの遅延バッファ（start の報告の後に [`Self::flush`] が出す）。
#[derive(Debug, Default)]
pub struct PastaLogBuffer {
    lines: Mutex<Vec<String>>,
    /// 手順 2c の再検証が見つけた改ざんの疑い(作業スレッドが置き、単一スレッドの入口が取り出して監査へ配送する。
    /// SEC-4・#3330。作業スレッドは監査の `FileAuditSink`〔fork 隔離〕を使えないため、記録は入口に任せる)。
    tamper: Mutex<Option<fandhe_container_core::audit_log::PastaVerifyRejection>>,
}

impl PastaLogBuffer {
    /// 空のバッファ。
    pub fn new() -> Self {
        Self::default()
    }

    /// 1 行を積む（上限 64 行。超えた分は捨てる。無制限確保を避ける）。
    pub fn push(&self, line: String) {
        let mut g = self.lines.lock().unwrap_or_else(PoisonError::into_inner);
        if g.len() < 64 {
            g.push(line);
        }
    }

    /// 再検証が見つけた改ざんの疑いを置く(最初の 1 件を残す)。
    pub fn set_tamper(&self, rejection: fandhe_container_core::audit_log::PastaVerifyRejection) {
        let mut g = self.tamper.lock().unwrap_or_else(PoisonError::into_inner);
        g.get_or_insert(rejection);
    }

    /// 置かれた改ざんの疑いを取り出す。
    pub fn take_tamper(&self) -> Option<fandhe_container_core::audit_log::PastaVerifyRejection> {
        self.tamper
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
    }

    /// 積んだ行を取り出す（試験と flush が使う）。
    pub fn take(&self) -> Vec<String> {
        std::mem::take(&mut *self.lines.lock().unwrap_or_else(PoisonError::into_inner))
    }

    /// 積んだ行を supervisor の出力口へ待たずに流す（キュー満杯なら捨てる。REPAIR-5）。
    pub fn flush(&self) {
        for line in self.take() {
            emit_now(line);
        }
    }
}

/// 出力口へ待たずに 1 行を入れる。
fn emit_now(line: String) {
    let _ = crate::stderr_sink::stderr().emit(line.into_bytes());
}

/// 出力の宛先（単一スレッドの区間では遅延、監視の段階では直接）。
#[derive(Clone)]
struct Logger {
    container: Arc<str>,
    buffer: Arc<PastaLogBuffer>,
}

impl Logger {
    fn log(&self, deferred: bool, event: &str, fields: &[(&str, Val)]) {
        let line = json_line(event, &self.container, fields);
        if deferred {
            self.buffer.push(line);
        } else {
            emit_now(line);
        }
    }
}

/// start の手順 2c の再検証の結果を `pasta_verify` として遅延バッファへ積む(NET-9・REPAIR-4)。
///
/// `Ok(日付)` は検証に通った版の日付(`YYYYMMDD`)、`Err((code, tamper))` は拒否の分類と改ざんの疑いの有無。
/// パス・出力は載せない(ERR-1)。SEC-4 の監査への記録は入口が `PastaLogBuffer::take_tamper` を配送する(#3330)。
pub(crate) fn log_pasta_verify(
    buffer: &PastaLogBuffer,
    container: &str,
    outcome: Result<u32, (ErrorCode, bool)>,
    elapsed: Duration,
) {
    let mut f = vec![("elapsed_ms", Val::U(millis(elapsed)))];
    match outcome {
        Ok(date) => {
            f.push(("result", Val::S("ok")));
            f.push(("version_date", Val::U(u64::from(date))));
        }
        Err((code, tamper)) => {
            f.push(("result", Val::S("rejected")));
            f.push(("code", Val::S(code.as_str())));
            f.push((
                "tamper_suspected",
                Val::S(if tamper { "true" } else { "false" }),
            ));
        }
    }
    buffer.push(json_line("pasta_verify", container, &f));
}

/// 改ざんの疑いを監査の記録先へ書けなかったことを `pasta_audit_unavailable` として遅延バッファへ積む(SEC-4・#3330)。
/// 起動の拒否は覆らない(fail-closed)。パス・出力は載せない(ERR-1)。
pub(crate) fn log_pasta_audit_unavailable(
    buffer: &PastaLogBuffer,
    container: &str,
    code: ErrorCode,
) {
    buffer.push(json_line(
        "pasta_audit_unavailable",
        container,
        &[("code", Val::S(code.as_str()))],
    ));
}

// ---------------------------------------------------------------------------------------------
// helper の抽象（試験のための差し替え点）
// ---------------------------------------------------------------------------------------------

/// helper（holder・pasta）の終了の材料。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExitInfo {
    /// 終了コード。
    pub code: Option<i32>,
    /// 終了シグナル。
    pub signal: Option<i32>,
    /// stderr（診断用に整形済み・4 KiB 以下。JSON のエスケープはログの出力時に `Val::Text` が行う）。
    pub stderr: String,
}

/// 停止の経路。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopKind {
    /// 要求で終わった。
    Stopped,
    /// 猶予を超えて SIGKILL した。
    Killed,
    /// 要求の前に終わっていた。
    AlreadyExited,
    /// 回収できなかった（zombie が残り得る）。
    Unreaped,
}

impl StopKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Stopped => "stopped",
            Self::Killed => "killed",
            Self::AlreadyExited => "already_exited",
            Self::Unreaped => "unreaped",
        }
    }
}

/// 停止の結果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StopReport {
    /// 停止の経路。
    pub kind: StopKind,
    /// 終了の材料。
    pub exit: ExitInfo,
    /// 停止に要した時間。
    pub elapsed: Duration,
}

/// 起動済みの helper のハンドル。
pub trait HelperHandle: Send {
    /// helper の pid（回収前だけ有効）。
    fn pid(&self) -> u32;
    /// 生きているか。状態を得られないときは `Err`（死んでいると誤認しない）。
    fn is_alive(&mut self) -> Result<bool, TraitError>;
    /// 止めて回収する。`detach_ok` が偽なら回収用のスレッドを作らない（単一スレッドの区間）。
    fn stop(&mut self, detach_ok: bool) -> StopReport;
}

/// 起動した helper と、起動から準備完了までの時間。
pub struct Spawned {
    /// ハンドル。
    pub handle: Box<dyn HelperHandle>,
    /// 準備完了までの時間（ミリ秒）。
    pub ready_ms: u64,
}

/// holder と pasta を実際に起動する層（本番は [`ProductionBackend`]、試験はフェイク）。
pub trait PastaAttachBackend: Send + Sync {
    /// fd 2 本を渡して holder を起動し、READY を `deadline` までに受ける。
    fn spawn_holder(
        &self,
        user: OwnedFd,
        net: OwnedFd,
        deadline: Instant,
    ) -> Result<Spawned, TraitError>;

    /// holder の pid を対象に pasta を起動し、準備完了を `deadline` までに待つ。
    fn spawn_pasta(&self, holder_pid: u32, deadline: Instant) -> Result<Spawned, TraitError>;

    /// `@pasta/<id>/` を消す（無ければ成功）。
    fn remove_run_dir(&self) -> Result<(), TraitError>;
}

// ---------------------------------------------------------------------------------------------
// 本番の backend
// ---------------------------------------------------------------------------------------------

/// 本番の構成値（検証済みのバイナリ・ポート公開・状態ルートの fd・コンテナ ID・準備完了の待ち）。
pub struct PastaAttachConfig {
    /// 起動時の再検証を通ったバイナリ（exec に使えるのはこれだけ）。
    pub binary: PastaBinary,
    /// 検証済みのポート公開。
    pub forwards: PastaPortForwards,
    /// 状態ルートのディレクトリ fd（`O_DIRECTORY | O_NOFOLLOW` で開いたもの）。
    pub state_root: OwnedFd,
    /// コンテナ ID。
    pub container: ContainerId,
    /// 準備完了の待ち（既定は [`PASTA_READY_TIMEOUT_DEFAULT`]）。
    pub ready_timeout: Duration,
}

/// 状態ルートを `O_DIRECTORY | O_NOFOLLOW` で開く（symlink を辿らない。fd 起点の操作の土台。SEC-1）。
pub fn open_state_root(root: &Path) -> Result<OwnedFd, TraitError> {
    use std::os::unix::fs::OpenOptionsExt as _;
    let flags = crate::sys::open_dir_nofollow_flags()
        .map_err(|_| TraitError::new(ErrorCode::Unimplemented, "unsupported architecture"))?;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(flags)
        .open(root)
        .map_err(|_| {
            TraitError::new(
                ErrorCode::FailedPrecondition,
                "the state root cannot be opened",
            )
        })?;
    Ok(OwnedFd::from(file))
}

/// CLI の delete が呼ぶ入口。`@pasta/<id>/` の残骸を消す（無ければ成功。記録の pid でのプロセス操作はしない。12.10）。
pub fn remove_pasta_leftovers(state_root: &Path, id: &ContainerId) -> Result<(), TraitError> {
    let fd = open_state_root(state_root)?;
    remove_pasta_run_dir(fd.as_fd(), id.as_str())
        .map_err(|e| TraitError::new(trait_code(e.code()), e.message().to_owned()))
}

/// 本番の backend。holder は [`spawn_netns_holder`]、pasta は net の `spawn_pasta` を呼ぶ。
pub struct ProductionBackend {
    config: PastaAttachConfig,
    logger: Logger,
}

impl ProductionBackend {
    fn new(config: PastaAttachConfig, logger: Logger) -> Self {
        Self { config, logger }
    }
}

fn net_to_trait(e: &fandhe_container_net::error::NetError) -> TraitError {
    TraitError::new(trait_code(e.code()), e.message().to_owned())
}

/// main スレッドから呼ばれていること（pasta の `PR_SET_PDEATHSIG` は spawn したスレッドの終了でも届く。12.10）。
fn require_main_thread() -> Result<(), TraitError> {
    if crate::netns_holder::is_main_thread()? {
        Ok(())
    } else {
        Err(TraitError::new(
            ErrorCode::FailedPrecondition,
            "pasta must be spawned from the main thread",
        ))
    }
}

impl PastaAttachBackend for ProductionBackend {
    fn spawn_holder(
        &self,
        user: OwnedFd,
        net: OwnedFd,
        deadline: Instant,
    ) -> Result<Spawned, TraitError> {
        let fds = NetnsHolderFds::new(user, net).map_err(|e| net_to_trait(&e))?;
        let started = Instant::now();
        match spawn_netns_holder(fds, deadline) {
            Ok(p) => {
                let pid = p.pid();
                Ok(Spawned {
                    handle: Box::new(HolderAdapter {
                        proc: Some(p),
                        pid,
                        exited: None,
                    }),
                    ready_ms: millis(started.elapsed()),
                })
            }
            Err(e) => {
                if !e.holder_stderr.is_empty() {
                    self.logger.log(
                        true,
                        "netns_holder_failed",
                        &[
                            ("code", Val::S(e.code().as_str())),
                            ("stderr", Val::Text(e.holder_stderr.clone())),
                        ],
                    );
                }
                Err(e.trait_error())
            }
        }
    }

    fn spawn_pasta(&self, holder_pid: u32, deadline: Instant) -> Result<Spawned, TraitError> {
        require_main_thread()?;
        let remaining = deadline.saturating_duration_since(Instant::now());
        let timeout = self.config.ready_timeout.min(remaining);
        if timeout.is_zero() {
            return Err(TraitError::new(
                ErrorCode::Timeout,
                "the attach deadline was exceeded before pasta started",
            ));
        }
        check_ready_timeout(timeout).map_err(|e| net_to_trait(&e))?;
        let run_dir = PastaRunDir::prepare(
            self.config.state_root.as_fd(),
            self.config.container.as_str(),
        )
        .map_err(|e| net_to_trait(&e))?;
        let target = PastaTarget::from_pid(holder_pid).map_err(|e| net_to_trait(&e))?;
        match spawn_pasta(
            &self.config.binary,
            &run_dir,
            &self.config.forwards,
            target,
            timeout,
        ) {
            Ok((proc, ready)) => {
                let pid = proc.pid();
                Ok(Spawned {
                    handle: Box::new(PastaAdapter {
                        proc: Some(proc),
                        pid,
                    }),
                    ready_ms: millis(ready.elapsed()),
                })
            }
            Err(mut e) => {
                let d = e.diagnostics().clone();
                self.logger.log(
                    true,
                    "pasta_failed",
                    &[
                        ("code", Val::S(trait_code(e.code()).as_str())),
                        ("elapsed_ms", Val::U(millis(d.elapsed))),
                        ("stderr", Val::Text(d.stderr_excerpt)),
                    ],
                );
                // 未回収の子は drop が kill と回収を試みる（単一スレッドの区間なので回収スレッドは作らない）。
                drop(e.take_unreaped());
                Err(net_to_trait(&e.into_net_error()))
            }
        }
    }

    fn remove_run_dir(&self) -> Result<(), TraitError> {
        remove_pasta_run_dir(
            self.config.state_root.as_fd(),
            self.config.container.as_str(),
        )
        .map_err(|e| net_to_trait(&e))
    }
}

fn millis(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

/// holder のハンドルの本番アダプタ。
struct HolderAdapter {
    proc: Option<NetnsHolderProcess>,
    pid: u32,
    exited: Option<HolderExit>,
}

fn exit_of_holder(e: &HolderExit) -> ExitInfo {
    ExitInfo {
        code: e.code,
        signal: e.signal,
        stderr: e.stderr.clone(),
    }
}

impl HelperHandle for HolderAdapter {
    fn pid(&self) -> u32 {
        self.pid
    }

    fn is_alive(&mut self) -> Result<bool, TraitError> {
        let Some(p) = self.proc.as_mut() else {
            return Ok(false);
        };
        match p.try_exit()? {
            None => Ok(true),
            Some(e) => {
                self.exited = Some(e);
                self.proc = None;
                Ok(false)
            }
        }
    }

    fn stop(&mut self, _detach_ok: bool) -> StopReport {
        let Some(p) = self.proc.take() else {
            return StopReport {
                kind: StopKind::AlreadyExited,
                exit: self.exited.as_ref().map(exit_of_holder).unwrap_or_default(),
                elapsed: Duration::ZERO,
            };
        };
        let out = p.stop();
        let kind = match out.path {
            StopPath::Stopped => StopKind::Stopped,
            StopPath::Killed => StopKind::Killed,
            StopPath::ReapTimedOut => StopKind::Unreaped,
        };
        // 回収できなかった子は手放す（zombie は監視プロセスの終了で init が回収する。回収スレッドは作らない）。
        drop(out.unreaped);
        StopReport {
            kind,
            exit: out.exit.as_ref().map(exit_of_holder).unwrap_or_default(),
            elapsed: out.elapsed,
        }
    }
}

/// pasta のハンドルの本番アダプタ。
struct PastaAdapter {
    proc: Option<PastaProcess>,
    pid: u32,
}

fn exit_of_pasta(e: PastaExit, stderr: String) -> ExitInfo {
    ExitInfo {
        code: e.code,
        signal: e.signal,
        stderr,
    }
}

impl HelperHandle for PastaAdapter {
    fn pid(&self) -> u32 {
        self.pid
    }

    fn is_alive(&mut self) -> Result<bool, TraitError> {
        let Some(p) = self.proc.as_mut() else {
            return Ok(false);
        };
        p.is_alive().map_err(|e| net_to_trait(&e))
    }

    fn stop(&mut self, detach_ok: bool) -> StopReport {
        let started = Instant::now();
        let Some(p) = self.proc.as_mut() else {
            return StopReport {
                kind: StopKind::AlreadyExited,
                exit: ExitInfo::default(),
                elapsed: Duration::ZERO,
            };
        };
        match p.stop_checked() {
            Ok(o) => {
                self.proc = None;
                let kind = match o.path {
                    PastaStopPath::Term => StopKind::Stopped,
                    PastaStopPath::Kill => StopKind::Killed,
                    _ => StopKind::AlreadyExited,
                };
                StopReport {
                    kind,
                    exit: exit_of_pasta(o.exit, o.stderr_excerpt),
                    elapsed: started.elapsed(),
                }
            }
            Err(_) => {
                // 期限内に回収できなかった。監視の段階では回収を専用スレッドへ移す。単一スレッドの区間では
                // 子を持ったまま呼び出し元が drop し、drop が kill と回収を試みる。
                if detach_ok && let Some(p) = self.proc.take() {
                    let _ = p.detach_reaper();
                }
                StopReport {
                    kind: StopKind::Unreaped,
                    exit: ExitInfo::default(),
                    elapsed: started.elapsed(),
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------
// 起動中の組（Attachment）
// ---------------------------------------------------------------------------------------------

/// 起動済みの holder と pasta の組と、それらを止めるのに要るもの。
struct Attachment {
    holder: Box<dyn HelperHandle>,
    pasta: Box<dyn HelperHandle>,
    backend: Arc<dyn PastaAttachBackend>,
    logger: Logger,
}

impl Attachment {
    /// どちらかが死んでいれば、その名前（`pasta` / `netns_holder`）を返す。状態不明は死んでいるとみなさない。
    fn dead_helper(&mut self) -> Option<&'static str> {
        if matches!(self.pasta.is_alive(), Ok(false)) {
            return Some("pasta");
        }
        if matches!(self.holder.is_alive(), Ok(false)) {
            return Some("netns_holder");
        }
        None
    }

    /// 逆順に止める: pasta → holder → `@pasta/<id>` の削除。1 回で消費する。
    fn teardown(mut self, reason: &'static str, detach_ok: bool, deferred: bool) {
        let rep = self.pasta.stop(detach_ok);
        self.log_exit("pasta_exit", reason, &rep, deferred);
        let rep = self.holder.stop(detach_ok);
        self.log_exit("netns_holder_exit", reason, &rep, deferred);
        if let Err(e) = self.backend.remove_run_dir() {
            self.logger.log(
                deferred,
                "pasta_run_dir_remove_failed",
                &[("code", Val::S(e.code().as_str()))],
            );
        }
    }

    fn log_exit(&self, event: &str, reason: &'static str, rep: &StopReport, deferred: bool) {
        let mut f = vec![
            ("reason", Val::S(reason)),
            ("stop", Val::S(rep.kind.as_str())),
            ("elapsed_ms", Val::U(millis(rep.elapsed))),
        ];
        if let Some(c) = rep.exit.code.and_then(|c| u64::try_from(c).ok()) {
            f.push(("status", Val::U(c)));
        }
        if let Some(s) = rep.exit.signal.and_then(|s| u64::try_from(s).ok()) {
            f.push(("signal", Val::U(s)));
        }
        if !rep.exit.stderr.is_empty() {
            f.push(("stderr", Val::Text(rep.exit.stderr.clone())));
        }
        self.logger.log(deferred, event, &f);
    }
}

/// フックから launcher へ attachment を渡す口。
type Slot = Arc<Mutex<Option<Attachment>>>;

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

// ---------------------------------------------------------------------------------------------
// フックと launcher の包み
// ---------------------------------------------------------------------------------------------

/// pasta 構成の組み立て一式。フックと launcher の包みは同じ受け渡し口とログを共有する。
pub struct PastaWiring {
    hook: Arc<PastaAttachHook>,
    slot: Slot,
    backend: Arc<dyn PastaAttachBackend>,
    logger: Logger,
}

impl PastaWiring {
    /// 本番の構成から作る。`container` は `validate_container_id` を通す。
    pub fn production(
        config: PastaAttachConfig,
        buffer: Arc<PastaLogBuffer>,
    ) -> Result<Self, TraitError> {
        validate_container_id(config.container.as_str()).map_err(|e| net_to_trait(&e))?;
        check_ready_timeout(config.ready_timeout).map_err(|e| net_to_trait(&e))?;
        let logger = Logger {
            container: Arc::from(config.container.as_str()),
            buffer,
        };
        let backend: Arc<dyn PastaAttachBackend> =
            Arc::new(ProductionBackend::new(config, logger.clone()));
        Ok(Self::with_backend(backend, logger))
    }

    /// 任意の backend から作る（試験用）。
    fn with_backend(backend: Arc<dyn PastaAttachBackend>, logger: Logger) -> Self {
        let slot: Slot = Arc::new(Mutex::new(None));
        let hook = Arc::new(PastaAttachHook {
            backend: Arc::clone(&backend),
            slot: Arc::clone(&slot),
            logger: logger.clone(),
        });
        Self {
            hook,
            slot,
            backend,
            logger,
        }
    }

    /// core の launcher 構築器へ渡すフック。
    pub fn hook(&self) -> Arc<dyn NetnsAttachHook> {
        Arc::clone(&self.hook) as Arc<dyn NetnsAttachHook>
    }

    /// `inner`（フックを渡した core の launcher）を包んだ launcher。
    pub fn wrap(&self, inner: Arc<dyn ProcessLauncher>) -> Arc<dyn ProcessLauncher> {
        Arc::new(PastaAttachingLauncher {
            inner,
            slot: Arc::clone(&self.slot),
            _backend: Arc::clone(&self.backend),
            logger: self.logger.clone(),
        })
    }
}

/// `NetnsAttachHook` の実装。順序は holder → pasta（12.2 の (2)〜(4)）。
pub struct PastaAttachHook {
    backend: Arc<dyn PastaAttachBackend>,
    slot: Slot,
    logger: Logger,
}

impl PastaAttachHook {
    /// fd を取り出した後の本体（試験が直接呼べるよう分ける。core の `AttachableNamespaces` は crate 外で作れない）。
    pub fn attach_fds(
        &self,
        user: OwnedFd,
        net: OwnedFd,
        deadline: Instant,
    ) -> Result<(), TraitError> {
        if lock(&self.slot).is_some() {
            // 前回の attachment が回収されていない。二重の attach を許さない（fail-closed）。
            return Err(TraitError::new(
                ErrorCode::Internal,
                "a previous pasta attachment was not collected",
            ));
        }
        if Instant::now() >= deadline {
            return Err(TraitError::new(
                ErrorCode::Timeout,
                "the attach deadline was exceeded",
            ));
        }
        let mut holder = match self.backend.spawn_holder(user, net, deadline) {
            Ok(h) => h,
            Err(e) => {
                self.logger.log(
                    true,
                    "netns_holder_failed",
                    &[("code", Val::S(e.code().as_str()))],
                );
                return Err(e);
            }
        };
        let pasta = match self.backend.spawn_pasta(holder.handle.pid(), deadline) {
            Ok(p) => p,
            Err(e) => {
                // 逆順の巻き戻し: pasta は自分で片付けて戻る。run dir を消してから holder を止める。
                if let Err(re) = self.backend.remove_run_dir() {
                    self.logger.log(
                        true,
                        "pasta_run_dir_remove_failed",
                        &[("code", Val::S(re.code().as_str()))],
                    );
                }
                let rep = holder.handle.stop(false);
                self.logger.log(
                    true,
                    "netns_holder_exit",
                    &[
                        ("reason", Val::S("attach_failed")),
                        ("stop", Val::S(rep.kind.as_str())),
                        ("elapsed_ms", Val::U(millis(rep.elapsed))),
                    ],
                );
                return Err(e);
            }
        };
        self.logger.log(
            true,
            "netns_holder_ready",
            &[("elapsed_ms", Val::U(holder.ready_ms))],
        );
        self.logger.log(
            true,
            "pasta_ready",
            &[("elapsed_ms", Val::U(pasta.ready_ms))],
        );
        *lock(&self.slot) = Some(Attachment {
            holder: holder.handle,
            pasta: pasta.handle,
            backend: Arc::clone(&self.backend),
            logger: self.logger.clone(),
        });
        Ok(())
    }
}

impl NetnsAttachHook for PastaAttachHook {
    fn attach(
        &self,
        namespaces: AttachableNamespaces,
        deadline: Instant,
    ) -> Result<(), TraitError> {
        let (user, net) = namespaces.into_parts();
        self.attach_fds(user, net, deadline)
    }
}

/// `ProcessLauncher` の包み。内側の launch が成功したら受け渡し口の attachment を [`PastaGuardedProcess`] に載せ、
/// 失敗したら残った分を逆順に止める。他のメソッドはすべて内側へ転送する（転送の漏れは降格・監査の欠落になる）。
pub struct PastaAttachingLauncher {
    inner: Arc<dyn ProcessLauncher>,
    slot: Slot,
    _backend: Arc<dyn PastaAttachBackend>,
    logger: Logger,
}

impl PastaAttachingLauncher {
    /// 内側の launch の結果に、フックが残した attachment を結びつける(`LaunchSpec` を作れない試験のため分けた本体)。
    ///
    /// - `Ok`: attachment を [`PastaGuardedProcess`] に載せる。無ければ(フックが走っていない)プロセスを止めて `Err`
    /// - `Err`: フックが `Ok` を返した後の launch の失敗(合図の失敗など)。残った分を逆順に止める(core の契約)
    fn adopt(
        &self,
        result: Result<Box<dyn LaunchedProcess>, TraitError>,
    ) -> Result<Box<dyn LaunchedProcess>, TraitError> {
        match result {
            Ok(process) => {
                let taken = lock(&self.slot).take();
                match taken {
                    Some(attachment) => Ok(Box::new(PastaGuardedProcess::new(
                        process,
                        attachment,
                        self.logger.clone(),
                    ))),
                    None => {
                        // フックが走らなかった(network のモードとフックの組が崩れた)。ネットワーク無しで走らせない。
                        let _ = process.terminate(MISSING_ATTACHMENT_TERMINATE);
                        Err(TraitError::new(
                            ErrorCode::Internal,
                            "the pasta attachment is missing after launch",
                        ))
                    }
                }
            }
            Err(e) => {
                // 単一スレッドの区間なのでスレッドは作らない。
                if let Some(a) = lock(&self.slot).take() {
                    a.teardown("launch_failed", false, true);
                }
                Err(e)
            }
        }
    }
}

impl ProcessLauncher for PastaAttachingLauncher {
    fn launch_mode(&self) -> fandhe_container_core::oci_runtime::LaunchMode {
        self.inner.launch_mode()
    }

    fn rejection_audit_sink(&self) -> Option<&dyn fandhe_container_core::audit_log::AuditSink> {
        self.inner.rejection_audit_sink()
    }

    fn network_mode(&self) -> fandhe_container_core::oci_runtime::LaunchNetworkMode {
        self.inner.network_mode()
    }

    fn last_launch_may_have_left_process(&self) -> bool {
        self.inner.last_launch_may_have_left_process()
    }

    fn launch(
        &self,
        spec: &LaunchSpec,
        timeout: Duration,
    ) -> Result<Box<dyn LaunchedProcess>, TraitError> {
        self.adopt(self.inner.launch(spec, timeout))
    }

    fn confirm_no_process(&self, id: &ContainerId, timeout: Duration) -> Result<(), TraitError> {
        self.inner.confirm_no_process(id, timeout)
    }

    fn confirm_no_process_recorded(
        &self,
        id: &ContainerId,
        recorded: Option<&fandhe_container_core::traits::CgroupPlacement>,
        timeout: Duration,
    ) -> Result<(), TraitError> {
        self.inner
            .confirm_no_process_recorded(id, recorded, timeout)
    }
}

/// 起動済みの PID 1 と helper をまとめて持つハンドル。PID 1 の回収後に helper を止め、途中死でコンテナを止める。
pub struct PastaGuardedProcess {
    inner: Box<dyn LaunchedProcess>,
    attachment: Mutex<Option<Attachment>>,
    /// SIGTERM を送った時刻（途中死の検出後）。
    term_sent_at: Mutex<Option<Instant>>,
    killed: AtomicBool,
    unexpected: AtomicBool,
    /// SIGTERM から SIGKILL へ上げるまでの猶予(既定 [`TERM_GRACE`]。試験が縮める)。
    term_grace: Duration,
    logger: Logger,
}

impl PastaGuardedProcess {
    fn new(inner: Box<dyn LaunchedProcess>, attachment: Attachment, logger: Logger) -> Self {
        Self {
            inner,
            attachment: Mutex::new(Some(attachment)),
            term_sent_at: Mutex::new(None),
            killed: AtomicBool::new(false),
            unexpected: AtomicBool::new(false),
            term_grace: TERM_GRACE,
            logger,
        }
    }

    /// helper を 1 回だけ止める。
    fn teardown(&self, reason: &'static str, detach_ok: bool) {
        let taken = lock(&self.attachment).take();
        if let Some(a) = taken {
            let reason = if self.unexpected.load(Ordering::SeqCst) {
                "unexpected"
            } else {
                reason
            };
            a.teardown(reason, detach_ok, false);
        }
    }

    /// PID 1 がまだ動いている間の helper の生死確認。死んでいたらコンテナを止める（分離は緩めない）。
    fn check_helpers(&self) {
        let dead = {
            let mut g = lock(&self.attachment);
            match g.as_mut() {
                Some(a) => a.dead_helper(),
                None => return,
            }
        };
        let Some(which) = dead else { return };
        if !self.unexpected.swap(true, Ordering::SeqCst) {
            self.logger
                .log(false, "pasta_helper_died", &[("helper", Val::S(which))]);
        }
        let mut sent = lock(&self.term_sent_at);
        let deadline = Instant::now() + SIGNAL_DEADLINE;
        match *sent {
            None => {
                let _ = self.inner.signal(Signal::SIGTERM, deadline);
                *sent = Some(Instant::now());
            }
            Some(at)
                if at.elapsed() >= self.term_grace && !self.killed.swap(true, Ordering::SeqCst) =>
            {
                let _ = self.inner.signal(Signal::SIGKILL, deadline);
            }
            Some(_) => {}
        }
    }
}

impl Drop for PastaGuardedProcess {
    fn drop(&mut self) {
        // 回収前に手放された場合も helper を残さない（単一スレッドの区間かもしれないので回収スレッドは作らない）。
        self.teardown("drop", false);
    }
}

impl LaunchedProcess for PastaGuardedProcess {
    fn pid(&self) -> std::num::NonZeroU32 {
        self.inner.pid()
    }

    fn wait(&self, timeout: Duration) -> Result<Option<ProcessExit>, TraitError> {
        let result = self.inner.wait(timeout)?;
        match result {
            Some(_) => self.teardown("container_exit", true),
            None => self.check_helpers(),
        }
        Ok(result)
    }

    fn terminate(&self, timeout: Duration) -> Result<(), TraitError> {
        let result = self.inner.terminate(timeout);
        self.teardown("terminate", true);
        result
    }

    fn signal(&self, signal: Signal, deadline: Instant) -> Result<(), TraitError> {
        self.inner.signal(signal, deadline)
    }

    fn launch_pidfd(&self) -> Option<std::os::fd::BorrowedFd<'_>> {
        self.inner.launch_pidfd()
    }

    fn take_output(&self) -> Option<ContainerOutput> {
        self.inner.take_output()
    }

    fn take_seccomp_listener(&self) -> Option<fandhe_container_core::exec::SeccompListener> {
        self.inner.take_seccomp_listener()
    }

    fn launch_isolation(
        &self,
    ) -> Option<&fandhe_container_core::launch_isolation::LaunchIsolationRecord> {
        self.inner.launch_isolation()
    }

    fn launch_rlimits(&self) -> Option<&fandhe_container_core::rlimits::Rlimits> {
        self.inner.launch_rlimits()
    }
}

#[cfg(test)]
mod tests;
