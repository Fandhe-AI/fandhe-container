//! healthcheck コマンドを exec 専用 helper で実行する `HealthProbe` の本番アダプタ（SUP-4・SUP-6・SEC-1・SEC-4・REPAIR-5・#2441）。
//!
//! # 役割と呼び出し文脈
//! 周期実行エンジン [`run_periodic`](super::run_periodic) の `HealthProbe::probe` として、probe のたびに
//! `/proc/self/exe healthcheck-exec ...`（本体は [`super::exec_helper`]）を単一スレッドの別プロセスとして起動する。
//! helper は exec 共通関数（`exec::run_command_with_pidfd_output`。TASK-163・SUP-6）で healthcheck コマンドを
//! 稼働中コンテナの中で実行し、結果を 1 行（[`super::exec_wire`]）で返す。本アダプタは結果を `Healthy` / `Unhealthy` に
//! 写す（`health_from_exec_exit`）。`probe` は `ProbeRunner` が作る一時スレッドの上で呼ばれるため、supervisor 本体は
//! 多スレッドのまま、setns を伴う exec だけが `Threads: 1` の helper で動く（判断記録は
//! `docs/design/healthcheck-exec-helper.md`）。
//!
//! # 結線の範囲（REPAIR-3）
//! 本モジュールは判定の実装まで。monitor / supervisor 入口への `run_periodic` の結線、restart の quiesce の参加者への
//! 登録、restart での付け替え（アダプタは 1 起動世代につき 1 つ作り、restart で作り直す前提）は #2953 が担う。
//! `argv[0]` の PATH 解決と timeout 上限の見直しは #2439（オーナー判断待ち）で、それまでは `argv[0]` を絶対パスに限り、
//! 60 秒超の timeout は既存の拒否のまま。
//!
//! # 出力の扱い（stdout / stderr）
//! コマンドの stdout / stderr は結合した 1 本で、先頭 [`OUTPUT_CAP`] バイトだけを [`HealthExecReport::output`] に保持し、
//! 超えた分は読み捨てて合計バイト数と `truncated` を数える。`state.json`（`health` は列挙のまま）にも構造化ログ
//! （`healthcheck_exec`）にも **本文は載せない**（秘密情報・ログ注入・command の中身を出さない方針）。ログに出すのは
//! バイト数と `truncated` だけ。本文は [`ExecHealthProbe::last_report`] 経由で後続（inspect・#2953）が読み、
//! 表示する場合は [`HealthExecReport::output_escaped`] を使う。`TraitError` のメッセージには本文を入れない。
//!
//! # タイムアウトの層（REPAIR-5）
//! `probe(T)` に対し helper へ渡す exec の期限は `T - min(T/5, 2s)`（[`exec_budget`]）。通常は core が期限切れの
//! コマンドを `cgroup.kill` して `Timeout` を返し、`T` より前に終わる。`T` を過ぎても helper が終わらなければ、
//! helper の作成通知（`FCHC1`）で確認できた exec 子 cgroup だけを supervisor が `cgroup.kill` して削除し、
//! helper が自分で終わるのを [`REAP_TIMEOUT`] だけ待って `Timeout` を返す（cancel も同じ）。**helper へシグナルは
//! 送らない**（再親付けされる子孫を作らないため）。終わらない helper の `Child` は保持し、終わるまで次の probe を
//! `Unavailable` にする。1 回の読み取りは [`PUMP_BYTES_MAX`] で打ち切り、
//! 大量出力でも期限・cancel の確認へ戻る。残った `exec-*` の子 cgroup は次の exec 開始時の掃除と delete 前の掃除で消える（残余）。終わらなければ
//! `helper_reaped = false` で報告する。`cancel` はフラグを立てるだけで、probe のループが自分で止める。

use std::io::Read as _;
use std::num::NonZeroU32;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt as _;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use fandhe_container_core::exec::{ExecCgroupName, remove_exec_child_cgroup};
use fandhe_container_core::oci_runtime::LaunchedProcess;
use fandhe_container_core::traits::{
    ContainerId, ErrorCode, GetStateRequest, HealthStatus, StateRecord, TraitError,
};

use super::HealthcheckDefinition;
use super::exec_helper::{HEALTH_EXEC_ARG0, HEALTH_EXEC_SUBCOMMAND, HealthExecArgs};
use super::exec_wire::{HealthExecLine, LINE_MAX};
use crate::health::{HealthProbe, ProbeCancel};
use crate::run::MAX_POLL_INTERVAL;

/// 保持するコマンド出力の上限（Docker の Output の上限に倣った本実装の判断）。
pub const OUTPUT_CAP: usize = 4096;
/// 結果ストリームの読み取りの上限。超えたら helper の異常として扱う。
pub const RESULT_STREAM_CAP: usize = 32 * 1024;
/// helper の診断行として転送する 1 行の最大バイト数。
pub const DIAG_LINE_MAX: usize = 1024;
/// 転送する診断行の最大本数。
pub const DIAG_LINES_MAX: u32 = 16;
/// helper の終了後に出力・結果の EOF を待つ猶予（子孫が書き込み端を持ち続けても待ち続けない）。
pub const DRAIN_GRACE: Duration = Duration::from_millis(100);
/// 期限切れ・cancel の後、exec 子 cgroup を止めてから helper が自分で終わるのを待つ上限。
pub const REAP_TIMEOUT: Duration = Duration::from_secs(1);
/// 強制終了した helper の exec 子 cgroup を `cgroup.kill` して空になるまで待つ上限。
const CGROUP_KILL_TIMEOUT: Duration = Duration::from_secs(1);
/// probe ループの刻み（cancel・期限・終了の確認間隔）。
const POLL_STEP: Duration = Duration::from_millis(5);

/// healthcheck の exec 先（対象コンテナの識別と、起動時の pidfd の複製）。
///
/// restart で pid1 が変わるたびに作り直す（旧世代の pidfd は旧 pid1 を指す）。helper は記録 pid と pidfd の一致を
/// core が照合し、不一致は違反として拒否する（SEC-1）。
#[derive(Debug)]
pub struct HealthExecTarget {
    state_root: PathBuf,
    id: ContainerId,
    pid: NonZeroU32,
    pidfd: OwnedFd,
}

impl HealthExecTarget {
    /// 明示の値から作る。
    pub fn new(state_root: PathBuf, id: ContainerId, pid: NonZeroU32, pidfd: OwnedFd) -> Self {
        Self {
            state_root,
            id,
            pid,
            pidfd,
        }
    }

    /// 起動ハンドルから作る。pidfd を持たない実装（未対応カーネル・seccomp・起動ハンドルなし）は
    /// `FailedPrecondition` で拒否する（記録 pid への縮退はしない。fail-closed）。
    pub fn from_launched(
        state_root: PathBuf,
        id: ContainerId,
        process: &dyn LaunchedProcess,
    ) -> Result<Self, TraitError> {
        let pidfd = process
            .launch_pidfd()
            .ok_or_else(|| {
                TraitError::new(
                    ErrorCode::FailedPrecondition,
                    "the launched process has no pidfd; cannot run healthcheck exec",
                )
            })?
            .try_clone_to_owned()
            .map_err(|_| {
                TraitError::new(
                    ErrorCode::Internal,
                    "failed to duplicate the launch pidfd for healthcheck exec",
                )
            })?;
        Ok(Self::new(state_root, id, process.pid(), pidfd))
    }
}

/// 1 回の probe の分類（構造化ログの `result`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum HealthExecOutcome {
    /// 終了コード 0。
    Healthy,
    /// 終了コード非 0 またはシグナル終了。
    Unhealthy,
    /// コマンドが起動しなかった（`SetupFailed`）。
    NotStarted,
    /// exec の通しが拒否・失敗した。
    Failed,
    /// helper の前提検査の不一致。
    Stale,
    /// 期限切れ（exec の期限または supervisor 側の絶対期限）。
    Timeout,
    /// `cancel` により打ち切った。
    Cancelled,
    /// helper の起動失敗・結果行の欠落や不正・異常終了。
    HelperError,
}

impl HealthExecOutcome {
    /// 構造化ログの固定語彙。
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Unhealthy => "unhealthy",
            Self::NotStarted => "not_started",
            Self::Failed => "failed",
            Self::Stale => "stale",
            Self::Timeout => "timeout",
            Self::Cancelled => "cancelled",
            Self::HelperError => "helper_error",
        }
    }
}

/// 1 回の probe の報告（`ExecHealthProbe::last_report` と observer が読む）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct HealthExecReport {
    /// 分類。
    pub outcome: HealthExecOutcome,
    /// helper の結果行（復号できたとき）。
    pub line: Option<HealthExecLine>,
    /// コマンド出力の先頭 [`OUTPUT_CAP`] バイトまで。**untrusted**（表示は [`Self::output_escaped`]）。
    pub output: Vec<u8>,
    /// コマンド出力の合計バイト数（読み捨てた分を含む）。
    pub output_total_bytes: u64,
    /// 出力が上限を超えて読み捨てられたか。
    pub output_truncated: bool,
    /// probe の所要時間。
    pub elapsed: Duration,
    /// helper を回収できたか（`false` は zombie が残っている）。
    pub helper_reaped: bool,
    /// 強制停止が必要だった exec 子 cgroup の停止に失敗したか（`true` は子孫が残り得る。次回の掃除が回収する）。
    pub cgroup_stop_failed: bool,
    /// stderr sink へ転送した helper の診断行数。
    pub diag_forwarded: u32,
    /// 捨てた診断行・不正な行の数。
    pub diag_dropped: u32,
}

impl HealthExecReport {
    /// 制御文字と非 ASCII をエスケープした表示用の文字列（ログ注入を防ぐ。バイト単位で `\xNN`）。
    pub fn output_escaped(&self) -> String {
        let mut out = String::with_capacity(self.output.len());
        for &b in &self.output {
            match b {
                b'\n' => out.push_str("\\n"),
                b'\t' => out.push_str("\\t"),
                b'\\' => out.push_str("\\\\"),
                0x20..=0x7e => out.push(char::from(b)),
                _ => out.push_str(&format!("\\x{b:02x}")),
            }
        }
        out
    }
}

/// probe の報告の通知先（構造化ログ。REPAIR-4）。
pub trait HealthExecObserver: Send + Sync {
    /// probe ごとに 1 回、結果を返す直前に呼ばれる。
    fn observe(&self, container: &ContainerId, report: &HealthExecReport);
}

/// 既定の observer: `healthcheck_exec` の JSON 1 行を stderr sink へ待たずに出す。固定キーだけで、コマンド・
/// 出力の本文・パスは載せない（バイト数と `truncated` のみ）。
#[derive(Debug, Clone, Copy, Default)]
pub struct StderrHealthExecObserver;

impl HealthExecObserver for StderrHealthExecObserver {
    fn observe(&self, container: &ContainerId, report: &HealthExecReport) {
        let _ = crate::stderr_sink::stderr().emit(log_line(container, report).into_bytes());
    }
}

/// `healthcheck_exec` の JSON 1 行（改行つき）。
pub fn log_line(container: &ContainerId, report: &HealthExecReport) -> String {
    let mut line = format!(
        "{{\"component\":\"supervisor.healthcheck\",\"operation\":\"healthcheck_exec\",\"container\":\"{}\",\"result\":\"{}\"",
        escape_json(container.as_str()),
        report.outcome.as_str()
    );
    match report.line {
        Some(HealthExecLine::Exited {
            code,
            audit,
            exit_audit,
            ..
        }) => {
            line.push_str(&format!(
                ",\"exit_code\":{code},\"audit\":\"{}\",\"exit_audit\":\"{}\"",
                audit.as_str(),
                exit_audit.as_str()
            ));
        }
        Some(HealthExecLine::Signaled {
            signal,
            audit,
            exit_audit,
        }) => {
            line.push_str(&format!(
                ",\"signal\":{signal},\"audit\":\"{}\",\"exit_audit\":\"{}\"",
                audit.as_str(),
                exit_audit.as_str()
            ));
        }
        Some(HealthExecLine::NotStarted {
            step, code, audit, ..
        }) => {
            line.push_str(&format!(
                ",\"step\":\"{}\",\"code\":\"{}\",\"audit\":\"{}\"",
                step.map_or("-", fandhe_container_core::exec::ExecChildStep::as_str),
                code.as_str(),
                audit.as_str()
            ));
        }
        Some(HealthExecLine::Failed { code, audit }) => {
            line.push_str(&format!(
                ",\"code\":\"{}\",\"audit\":\"{}\"",
                code.as_str(),
                audit.as_str()
            ));
        }
        Some(HealthExecLine::Stale) | Some(HealthExecLine::Invalid) | None => {}
    }
    line.push_str(&format!(
        ",\"output_bytes\":{},\"output_truncated\":{},\"elapsed_ms\":{},\"helper_reaped\":{},\"cgroup_stop_failed\":{},\"diag_forwarded\":{},\"diag_dropped\":{}}}\n",
        report.output_total_bytes,
        report.output_truncated,
        report.elapsed.as_millis(),
        report.helper_reaped,
        report.cgroup_stop_failed,
        report.diag_forwarded,
        report.diag_dropped
    ));
    line
}

fn escape_json(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// helper へ渡す exec の期限: `T - min(T/5, 2s)`（下限 1ms、上限 [`MAX_POLL_INTERVAL`]。ミリ秒に丸める）。
///
/// 通常の期限切れは core が `T` より前に `Timeout` で返せるよう、supervisor 側の絶対期限 `T` より早く設定する
/// （本実装の判断。REPAIR-5）。
pub fn exec_budget(timeout: Duration) -> Duration {
    let margin = (timeout / 5).min(Duration::from_secs(2));
    let budget = timeout.saturating_sub(margin);
    let ms = budget.as_millis().clamp(1, MAX_POLL_INTERVAL.as_millis());
    Duration::from_millis(u64::try_from(ms).unwrap_or(1))
}

/// 結果行を `HealthProbe::probe` の戻り値と分類へ写す（純関数。写像表は `docs/design/healthcheck-exec-helper.md`）。
///
/// コマンドの失敗に `FailedPrecondition` を使わない（`periodic` はそれをループの停止条件として扱う）。例外は
/// `stale`（記録が `Running` でない・所有者の不一致）で、SUP-1 の意味どおり loop を正しく止める。
pub fn map_line(line: HealthExecLine) -> (Result<HealthStatus, TraitError>, HealthExecOutcome) {
    match line {
        HealthExecLine::Exited { healthy: true, .. } => {
            (Ok(HealthStatus::Healthy), HealthExecOutcome::Healthy)
        }
        HealthExecLine::Exited { .. } | HealthExecLine::Signaled { .. } => {
            (Ok(HealthStatus::Unhealthy), HealthExecOutcome::Unhealthy)
        }
        HealthExecLine::NotStarted { step, .. } => {
            let message = match step {
                Some(step) => format!("healthcheck command did not start: {}", step.message()),
                None => "healthcheck command did not start".to_string(),
            };
            (
                Err(TraitError::new(ErrorCode::Internal, message)),
                HealthExecOutcome::NotStarted,
            )
        }
        HealthExecLine::Failed {
            code: ErrorCode::Timeout,
            ..
        } => (
            Err(TraitError::new(
                ErrorCode::Timeout,
                "healthcheck exec timed out",
            )),
            HealthExecOutcome::Timeout,
        ),
        HealthExecLine::Failed { code, .. } => {
            // 実行基盤の前提不成立（rlimit・分離の記録なし・多スレッド等）は、コマンドの失敗ではなく Internal。
            let mapped = if code == ErrorCode::FailedPrecondition {
                ErrorCode::Internal
            } else {
                code
            };
            (
                Err(TraitError::new(
                    mapped,
                    format!("healthcheck exec failed ({})", code.as_str()),
                )),
                HealthExecOutcome::Failed,
            )
        }
        HealthExecLine::Stale => (
            Err(TraitError::new(
                ErrorCode::FailedPrecondition,
                "the healthcheck target is stale",
            )),
            HealthExecOutcome::Stale,
        ),
        HealthExecLine::Invalid => (
            Err(TraitError::new(
                ErrorCode::Internal,
                "the healthcheck exec helper rejected its arguments",
            )),
            HealthExecOutcome::HelperError,
        ),
    }
}

/// 出力の保持（先頭 [`OUTPUT_CAP`] バイトと合計・切り捨ての記録）。
#[derive(Debug, Default)]
struct OutputSink {
    kept: Vec<u8>,
    total: u64,
    truncated: bool,
}

impl OutputSink {
    fn push(&mut self, chunk: &[u8]) {
        self.total = self.total.saturating_add(chunk.len() as u64);
        let room = OUTPUT_CAP.saturating_sub(self.kept.len());
        let take = room.min(chunk.len());
        if let Some(head) = chunk.get(..take) {
            self.kept.extend_from_slice(head);
        }
        if take < chunk.len() {
            self.truncated = true;
        }
    }
}

/// 結果ストリームの保持（上限つき）。
#[derive(Debug, Default)]
struct ResultSink {
    bytes: Vec<u8>,
    overflow: bool,
}

/// 1 回の `pump` で読む最大バイト数。コマンドが並列に大量出力しても `WouldBlock` に届かず期限・cancel の
/// 確認へ戻れなくなることを防ぐ（REPAIR-5）。
pub const PUMP_BYTES_MAX: usize = 64 * 1024;

/// 非ブロッキングの読み取りを EOF・`WouldBlock`・[`PUMP_BYTES_MAX`] のいずれかまで行う。EOF なら `true`。
/// 上限で打ち切った場合は `false` で戻り、呼び出し側のループが期限・cancel を確認してから再度呼ぶ。
fn pump(stream: &mut UnixStream, mut sink: impl FnMut(&[u8])) -> bool {
    let mut buf = [0u8; 2048];
    let mut total = 0usize;
    loop {
        if total >= PUMP_BYTES_MAX {
            return false;
        }
        match stream.read(&mut buf) {
            Ok(0) => return true,
            Ok(n) => {
                total = total.saturating_add(n);
                sink(buf.get(..n).unwrap_or(&[]));
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return false,
            // 読み取りの失敗は EOF 相当（これ以上読めない）。
            Err(_) => return true,
        }
    }
}

/// 結果ストリームを行に分け、結果行と診断行を仕分ける。
struct ParsedStream {
    result: Result<HealthExecLine, ()>,
    forwarded: u32,
    dropped: u32,
}

fn parse_result_stream(sink: &ResultSink) -> ParsedStream {
    let mut forwarded = 0u32;
    let mut dropped = 0u32;
    let mut results: Vec<&[u8]> = Vec::new();
    let mut rest: &[u8] = &sink.bytes;
    while !rest.is_empty() {
        let (line, next, complete) = match rest.iter().position(|&b| b == b'\n') {
            Some(i) => (
                rest.get(..i).unwrap_or(&[]),
                rest.get(i + 1..).unwrap_or(&[]),
                true,
            ),
            None => (rest, &[][..], false),
        };
        rest = next;
        if !complete {
            // 改行で終わらない末尾は、途中で切れた行として捨てる。
            dropped = dropped.saturating_add(1);
            continue;
        }
        if line.starts_with(super::exec_wire::CGROUP_TAG.as_bytes()) {
            // 作成通知行は `owned_exec_cgroup` が読む。結果行でも診断行でもないので数えない。
            continue;
        }
        if line.starts_with(super::exec_wire::WIRE_TAG.as_bytes()) {
            results.push(line);
        } else if line.starts_with(b"{\"") && line.len() <= DIAG_LINE_MAX {
            if forwarded < DIAG_LINES_MAX {
                let mut bytes = line.to_vec();
                bytes.push(b'\n');
                let _ = crate::stderr_sink::stderr().emit(bytes);
                forwarded += 1;
            } else {
                dropped = dropped.saturating_add(1);
            }
        } else {
            dropped = dropped.saturating_add(1);
        }
    }
    let result = match results.as_slice() {
        [one] if one.len() <= LINE_MAX && !sink.overflow => {
            HealthExecLine::decode(one).map_err(|_| ())
        }
        _ => Err(()),
    };
    ParsedStream {
        result,
        forwarded,
        dropped,
    }
}

/// 結果ストリームから、helper が排他作成に成功したと通知した exec 子 cgroup の名前を取り出す。
///
/// 通知（`FCHC1 <name>\n`。[`super::exec_wire::CGROUP_TAG`]）が無い・名前が不正・名前の pid が `helper_pid` と
/// 食い違う場合は `None`（所有を確定できないので止めない）。helper の pid から名前を推定しない理由: 再利用された
/// pid の以前の exec が残した populated な同名 cgroup を誤停止し得るため（SUP-6・REPAIR-5）。
fn owned_exec_cgroup(bytes: &[u8], helper_pid: u32) -> Option<ExecCgroupName> {
    let prefix = format!("{} ", super::exec_wire::CGROUP_TAG);
    let owner = format!("exec-{helper_pid}-");
    bytes
        .split(|&b| b == b'\n')
        // 改行で終わらない末尾（途中で切れた行）は採らない。
        .take(bytes.iter().filter(|&&b| b == b'\n').count())
        .filter_map(|line| {
            std::str::from_utf8(line)
                .ok()?
                .strip_prefix(prefix.as_str())
        })
        .find_map(|name| {
            let name = ExecCgroupName::new(name).ok()?;
            name.as_str().starts_with(&owner).then_some(name)
        })
}

/// 期限切れ・cancel 後の止め方: 所有を確定した exec 子 cgroup だけを `stop`（`cgroup.kill` と削除）で止め、
/// helper が自分で終わるのを `wait` まで待つ。戻り値は `(stop の成否, helper が終わったか)`。
///
/// **helper へはシグナルを送らない**。SIGKILL すると helper の子孫（`FileAuditSink` が fork した子、worker）が
/// subreaper の supervisor へ再親付けされ、回収の責任と特定の手段が増え続けるため。cgroup を止めれば worker が
/// 結果を返して helper が終わる。待ちきれなければ呼び出し側が `Child` を保持する（REPAIR-5）。
fn stop_cgroup_then_wait(
    child: &mut Child,
    owned: Option<&ExecCgroupName>,
    stop: impl FnOnce(&ExecCgroupName) -> bool,
    wait: Duration,
) -> (bool, bool) {
    let stop_ok = stop_if_owned(owned, stop);
    let until = Instant::now() + wait;
    loop {
        if matches!(child.try_wait(), Ok(Some(_))) {
            return (stop_ok, true);
        }
        if Instant::now() >= until {
            return (stop_ok, false);
        }
        std::thread::sleep(POLL_STEP);
    }
}

/// 所有を確定した cgroup `owned` があるときだけ `stop` で止める。無ければ何もせず `true`（止める対象が無い）。
fn stop_if_owned(
    owned: Option<&ExecCgroupName>,
    stop: impl FnOnce(&ExecCgroupName) -> bool,
) -> bool {
    match owned {
        Some(name) => stop(name),
        None => true,
    }
}

/// 保持先が抱える未回収 helper の上限。到達している間は、どの adapter の probe も helper を作らずに `Unavailable`。
///
/// 根拠: 1 件は「同期 I/O で固まった helper」1 プロセス分で、supervisor はコンテナごと（restart の世代ごとに
/// adapter を作り直す）なので同時に多くは要らない。固まる原因（ストレージの停止）は共通で、複数世代で重なれば
/// 新しい helper を作っても同じ所で固まるだけなので、小さな定数（4。`FileAuditSink` の `MAX_UNREAPED` と同じ桁）で
/// 塞ぐ。adapter 自身が保持する 1 件（`unreaped`）は別枠で、保持先の件数は「上限 + 同時に走る adapter 数」を超えない
/// （上限到達中は誰も新しい helper を作らないため。SUP-4・REPAIR-5）。
pub const MAX_HELD_HELPERS: usize = 4;

/// drop された adapter から引き継いだ未回収 helper の保持先（プロセス全体で 1 つ。supervisor の寿命）。
///
/// `std::process::Child` の drop は終了を待たず、後で終わっても回収する経路が無い。restart で adapter を作り直しても
/// 回収の責任を失わないよう、drop 時に生きている helper をここへ移し、probe の開始時に `try_wait` で掃除する。
pub struct HeldHelpers(Mutex<Vec<Child>>);

impl HeldHelpers {
    const fn new() -> Self {
        Self(Mutex::new(Vec::new()))
    }

    /// 終わった helper を回収して外し、まだ残っている件数を返す（待たない）。
    fn sweep(&self) -> usize {
        let mut list = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        list.retain_mut(|child| matches!(child.try_wait(), Ok(None)));
        list.len()
    }

    /// 生きている helper を引き継ぐ。
    fn hold(&self, child: Child) {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(child);
    }
}

static GLOBAL_HELD: HeldHelpers = HeldHelpers::new();

/// healthcheck コマンドを exec 専用 helper で実行する `HealthProbe` の本番アダプタ。
///
/// 1 起動世代につき 1 つ作り、restart で作り直す（pidfd・記録 pid が世代に紐づく）。同時に走る probe は 1 本で、
/// 2 本目は `Unavailable`（`ProbeRunner` の排他に加えた多層防御）。
pub struct ExecHealthProbe {
    target: HealthExecTarget,
    command: Vec<String>,
    observer: Arc<dyn HealthExecObserver>,
    last: Mutex<Option<HealthExecReport>>,
    /// 直接 `probe` を呼んだ試行の旗（`cancel` の宛先）。`ProbeRunner` 経由の試行は試行ごとの旗を使う。
    current: Mutex<ProbeCancel>,
    busy: AtomicBool,
    /// 配置取得スレッド（`hc-resolve`）が生きている間 true。状態ストアの I/O が止まったときに切り離した
    /// スレッドと複製した pidfd が probe ごとに積み上がらないよう、同時に 1 本までに抑える（REPAIR-5）。
    resolver_busy: Arc<AtomicBool>,
    /// 期限切れ・cancel の後、`REAP_TIMEOUT` 内に自分で終わらなかった helper の `Child`（最大 1 個）。次の probe の開始時・
    /// `cancel`・drop で `try_wait` し、回収できるまで新しい helper を作らない（未回収 helper の蓄積を防ぐ。
    /// SUP-4・REPAIR-5）。
    unreaped: Mutex<Option<Child>>,
    /// adapter の drop で手放された未回収 helper の、プロセス全体で 1 つの保持先（通常は [`GLOBAL_HELD`]）。
    held: &'static HeldHelpers,
}

impl std::fmt::Debug for ExecHealthProbe {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // コマンドの中身は出さない（秘密情報の漏えい防止）。
        f.debug_struct("ExecHealthProbe")
            .field("id", &self.target.id)
            .finish_non_exhaustive()
    }
}

/// probe の終了時に `busy` を下ろす。cancel の旗は試行ごとに別のため、ここでは戻さない（SUP-4・REPAIR-5）。
struct BusyGuard<'a> {
    busy: &'a AtomicBool,
}

/// spawn 前に打ち切る理由。
enum PreSpawn {
    Timeout,
    Cancelled,
    /// 強制停止に要る cgroup の配置を得られない（取得失敗・配置なし・取得スレッドが未終了）。起動しない。
    Unavailable,
}

impl Drop for BusyGuard<'_> {
    fn drop(&mut self) {
        self.busy.store(false, Ordering::SeqCst);
    }
}

impl ExecHealthProbe {
    /// 検証済みの定義と対象から作る。`argv[0]` が絶対パスでなければ `InvalidArgument`（PATH 探索はしない。#2439 の
    /// 判断まで現行の拒否を保つ）。メッセージは固定で、コマンドの中身を出さない。
    pub fn new(
        definition: &HealthcheckDefinition,
        target: HealthExecTarget,
    ) -> Result<Self, TraitError> {
        let command = definition.command().to_vec();
        // helper と同じ規則で事前に確かめる（絶対パス・件数・サイズ・NUL）。
        HealthExecArgs::new(
            target.state_root.clone(),
            target.id.clone(),
            target.pid,
            Duration::from_secs(1),
            command.clone(),
        )?;
        Ok(Self {
            target,
            command,
            observer: Arc::new(StderrHealthExecObserver),
            last: Mutex::new(None),
            current: Mutex::new(ProbeCancel::new()),
            busy: AtomicBool::new(false),
            resolver_busy: Arc::new(AtomicBool::new(false)),
            unreaped: Mutex::new(None),
            held: &GLOBAL_HELD,
        })
    }

    /// 結果の通知先を差し替える（既定は [`StderrHealthExecObserver`]）。
    pub fn with_observer(mut self, observer: Arc<dyn HealthExecObserver>) -> Self {
        self.observer = observer;
        self
    }

    /// 直近の probe の報告（コマンド出力の上限つきの本文を含む）。
    pub fn last_report(&self) -> Option<HealthExecReport> {
        self.last
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    fn spawn_helper(
        &self,
        args: &HealthExecArgs,
        stdin: OwnedFd,
        stdout: OwnedFd,
        stderr: OwnedFd,
    ) -> std::io::Result<Child> {
        let mut command = Command::new("/proc/self/exe");
        command
            .arg0(HEALTH_EXEC_ARG0)
            .arg(HEALTH_EXEC_SUBCOMMAND)
            .args(args.to_args())
            .env_clear()
            .current_dir("/")
            .stdin(Stdio::from(stdin))
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr));
        // `Command` を drop して、子側の端の複製をこちらに残さない（EOF を受け取るため）。
        command.spawn()
    }

    /// 起動前に記録からコンテナ cgroup の配置を取り出して保持する（強制停止で状態ストアを再取得しないため。
    /// ロック競合で停止が省かれたり 1 秒の後始末上限を超えたりしない。SUP-6・REPAIR-5）。
    fn resolve_record(target: &HealthExecTarget) -> Result<StateRecord, TraitError> {
        let unavailable = || {
            TraitError::new(
                ErrorCode::Unavailable,
                "failed to resolve the container cgroup for the healthcheck",
            )
        };
        let store = crate::state::open_default_store(Some(target.state_root.clone()))
            .map_err(|_| unavailable())?;
        store
            .get(&GetStateRequest::new(target.id.clone()))
            .map_err(|_| unavailable())
    }

    /// [`Self::resolve_record`] を別スレッドで走らせ、`deadline` と cancel を確かめながら待つ。
    ///
    /// 配置（cgroup）を得られなければ `Err(PreSpawn::Unavailable)`（helper を起動しない）。helper が異常終了
    /// したときに親死亡シグナルを解除したコマンドと子孫を止める手段が無いまま起動しないため（SUP-4・SUP-6・
    /// REPAIR-5）。前回の取得スレッドが未終了のときも新しく作らず `Unavailable`（in-flight は最大 1 本）。
    /// 期限切れ・cancel は `Err`（helper を起動しない）。
    fn resolve_record_bounded(
        &self,
        deadline: Instant,
        cancel: &ProbeCancel,
    ) -> Result<StateRecord, PreSpawn> {
        /// スレッドの終了時（panic を含む）に `resolver_busy` を下ろす。
        struct ResolverGuard(Arc<AtomicBool>);
        impl Drop for ResolverGuard {
            fn drop(&mut self) {
                self.0.store(false, Ordering::SeqCst);
            }
        }

        if self.resolver_busy.swap(true, Ordering::SeqCst) {
            return Err(PreSpawn::Unavailable);
        }
        let guard = ResolverGuard(Arc::clone(&self.resolver_busy));
        let (tx, rx) = std::sync::mpsc::channel();
        let target = HealthExecTarget {
            state_root: self.target.state_root.clone(),
            id: self.target.id.clone(),
            pid: self.target.pid,
            pidfd: self
                .target
                .pidfd
                .try_clone()
                .map_err(|_| PreSpawn::Unavailable)?,
        };
        // 失敗時は guard が drop されて busy を下ろす。
        std::thread::Builder::new()
            .name("hc-resolve".into())
            .spawn(move || {
                let _guard = guard;
                let _ = tx.send(Self::resolve_record(&target));
            })
            .map_err(|_| PreSpawn::Unavailable)?;
        loop {
            if cancel.is_cancelled() {
                return Err(PreSpawn::Cancelled);
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(PreSpawn::Timeout);
            }
            match rx.recv_timeout(POLL_STEP.min(deadline - now)) {
                Ok(Ok(record)) if record.cgroup().is_some() => return Ok(record),
                Ok(_) | Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    return Err(PreSpawn::Unavailable);
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            }
        }
    }

    /// helper が **排他作成に成功したと通知した** exec 子 cgroup `owned`（[`owned_exec_cgroup`]）を、起動前に保持した
    /// 配置の直下で `cgroup.kill` して削除する。通知が無ければ何も止めない。
    ///
    /// 方式の選択: helper の pid から `exec-<pid>-0` を推定すると、再利用された pid の以前の exec が残した populated な
    /// 同名 cgroup を誤停止し得る（作成前に期限切れになった場合）。そのため core の既存の排他作成（同名は `EEXIST` で
    /// 失敗）の成功を helper が通知し、受けた名前だけを止める。残る窓: 作成の完了から通知の書き込み・読み取りまでの間に
    /// helper が殺されると名前を知れず止められない（空でなければ次回の exec 開始時の掃除・delete 前の掃除に任せる。
    /// 空の cgroup は掃除が回収する）。状態ストアは読まない。失敗は `false`。待機は `CGROUP_KILL_TIMEOUT` まで。
    fn kill_exec_cgroup(&self, record: &StateRecord, owned: Option<&ExecCgroupName>) -> bool {
        stop_if_owned(owned, |name| {
            let Some(placement) = record.cgroup() else {
                return false;
            };
            remove_exec_child_cgroup(&self.target.id, placement, name, CGROUP_KILL_TIMEOUT).is_ok()
        })
    }

    fn run(&self, timeout: Duration, cancel: &ProbeCancel) -> Result<HealthStatus, TraitError> {
        let start = Instant::now();
        let deadline = start + timeout;
        let mut report = HealthExecReport {
            outcome: HealthExecOutcome::HelperError,
            line: None,
            output: Vec::new(),
            output_total_bytes: 0,
            output_truncated: false,
            elapsed: Duration::ZERO,
            helper_reaped: true,
            cgroup_stop_failed: false,
            diag_forwarded: 0,
            diag_dropped: 0,
        };
        let finish = |mut report: HealthExecReport,
                      result: Result<HealthStatus, TraitError>|
         -> Result<HealthStatus, TraitError> {
            report.elapsed = start.elapsed();
            self.observer.observe(&self.target.id, &report);
            *self
                .last
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(report);
            result
        };
        let helper_args = HealthExecArgs::new(
            self.target.state_root.clone(),
            self.target.id.clone(),
            self.target.pid,
            exec_budget(timeout),
            self.command.clone(),
        );
        let helper_args = match helper_args {
            Ok(args) => args,
            Err(e) => return finish(report, Err(e)),
        };
        let pair = |what: &'static str| {
            UnixStream::pair().map_err(|_| {
                TraitError::new(
                    ErrorCode::Internal,
                    format!("failed to create the healthcheck {what} channel"),
                )
            })
        };
        let (mut out_parent, out_child) = match pair("output") {
            Ok(p) => p,
            Err(e) => return finish(report, Err(e)),
        };
        let (mut res_parent, res_child) = match pair("result") {
            Ok(p) => p,
            Err(e) => return finish(report, Err(e)),
        };
        if out_parent.set_nonblocking(true).is_err() || res_parent.set_nonblocking(true).is_err() {
            return finish(
                report,
                Err(TraitError::new(
                    ErrorCode::Internal,
                    "failed to configure the healthcheck channels",
                )),
            );
        }
        // 強制停止に使う cgroup の配置を起動前に取得する。得られなければ起動しない（fail-closed）。取得は別スレッドで
        // 残り予算内に限り待ち、待つ間も cancel と期限を確かめる。期限切れ・cancel の後も起動しない（REPAIR-5）。
        let record = match self.resolve_record_bounded(deadline, cancel) {
            Ok(record) => record,
            Err(PreSpawn::Timeout) => {
                report.outcome = HealthExecOutcome::Timeout;
                return finish(
                    report,
                    Err(TraitError::new(
                        ErrorCode::Timeout,
                        "healthcheck probe timed out",
                    )),
                );
            }
            Err(PreSpawn::Unavailable) => {
                return finish(
                    report,
                    Err(TraitError::new(
                        ErrorCode::Unavailable,
                        "failed to resolve the container cgroup for the healthcheck",
                    )),
                );
            }
            Err(PreSpawn::Cancelled) => {
                report.outcome = HealthExecOutcome::Cancelled;
                return finish(
                    report,
                    Err(TraitError::new(
                        ErrorCode::Timeout,
                        "healthcheck probe was cancelled",
                    )),
                );
            }
        };
        let pidfd = match self.target.pidfd.try_clone() {
            Ok(fd) => fd,
            Err(_) => {
                return finish(
                    report,
                    Err(TraitError::new(
                        ErrorCode::Internal,
                        "failed to duplicate the launch pidfd",
                    )),
                );
            }
        };
        if cancel.is_cancelled() {
            report.outcome = HealthExecOutcome::Cancelled;
            return finish(
                report,
                Err(TraitError::new(
                    ErrorCode::Timeout,
                    "healthcheck probe was cancelled",
                )),
            );
        }
        if Instant::now() >= deadline {
            report.outcome = HealthExecOutcome::Timeout;
            return finish(
                report,
                Err(TraitError::new(
                    ErrorCode::Timeout,
                    "healthcheck probe timed out",
                )),
            );
        }
        let mut child = match self.spawn_helper(
            &helper_args,
            pidfd,
            OwnedFd::from(out_child),
            OwnedFd::from(res_child),
        ) {
            Ok(child) => child,
            Err(e) => {
                let code = if e.kind() == std::io::ErrorKind::PermissionDenied {
                    ErrorCode::PermissionDenied
                } else {
                    ErrorCode::Internal
                };
                return finish(
                    report,
                    Err(TraitError::new(
                        code,
                        "failed to start the healthcheck exec helper",
                    )),
                );
            }
        };

        let helper_pid = child.id();
        let mut output = OutputSink::default();
        let mut results = ResultSink::default();
        let mut out_eof = false;
        let mut res_eof = false;
        let read_all = |out_eof: &mut bool,
                        res_eof: &mut bool,
                        output: &mut OutputSink,
                        results: &mut ResultSink,
                        out_parent: &mut UnixStream,
                        res_parent: &mut UnixStream| {
            if !*out_eof {
                *out_eof = pump(out_parent, |c| output.push(c));
            }
            if !*res_eof && !results.overflow {
                *res_eof = pump(res_parent, |c| {
                    let room = RESULT_STREAM_CAP.saturating_sub(results.bytes.len());
                    let take = room.min(c.len());
                    if let Some(head) = c.get(..take) {
                        results.bytes.extend_from_slice(head);
                    }
                    if take < c.len() {
                        results.overflow = true;
                    }
                });
            }
        };

        enum Ended {
            /// 値は helper の終了が正常（終了コード 0）だったか。
            Exited(bool),
            Timeout,
            Cancelled,
            WaitFailed,
        }
        let ended = loop {
            read_all(
                &mut out_eof,
                &mut res_eof,
                &mut output,
                &mut results,
                &mut out_parent,
                &mut res_parent,
            );
            match child.try_wait() {
                Ok(Some(status)) => break Ended::Exited(status.success()),
                Ok(None) => {}
                Err(_) => break Ended::WaitFailed,
            }
            if cancel.is_cancelled() {
                break Ended::Cancelled;
            }
            if Instant::now() >= deadline {
                break Ended::Timeout;
            }
            std::thread::sleep(POLL_STEP);
        };

        let mut cgroup_stop_failed = false;
        let mut reaped = matches!(ended, Ended::Exited(_));
        // helper が SIGKILL・OOM 等で異常終了したときは結果行を残せず、exec 子 cgroup の後始末が走っていない
        // 可能性があるため、正常終了以外は所有を確認した cgroup を止める（SUP-4・SUP-6）。
        // 止める対象は、helper の作成通知を受けた cgroup だけ（読み取り直後に確認する）。
        let mut stopped = false;
        if matches!(ended, Ended::Exited(false)) {
            read_all(
                &mut out_eof,
                &mut res_eof,
                &mut output,
                &mut results,
                &mut out_parent,
                &mut res_parent,
            );
            let owned = owned_exec_cgroup(&results.bytes, helper_pid);
            if owned.is_some() {
                stopped = true;
            }
            if !self.kill_exec_cgroup(&record, owned.as_ref()) {
                cgroup_stop_failed = true;
            }
        }
        if !reaped {
            // 期限切れ・cancel でも helper へシグナルは送らない（SIGKILL も SIGTERM も）。止めるのは、作成通知で
            // 今回の作成を確認できた exec 子 cgroup の `cgroup.kill` だけで、worker は結果を返して helper が
            // 自分で終わる。helper が SIGKILL されないので、helper の子孫（監査 sink の fork した子を含む）は
            // 親の helper が自分で回収し、supervisor へ再親付けされない（SUP-4・SUP-6・REPAIR-5）。
            read_all(
                &mut out_eof,
                &mut res_eof,
                &mut output,
                &mut results,
                &mut out_parent,
                &mut res_parent,
            );
            let owned = owned_exec_cgroup(&results.bytes, helper_pid);
            if owned.is_some() {
                stopped = true;
            }
            let (stop_ok, exited) = stop_cgroup_then_wait(
                &mut child,
                owned.as_ref(),
                |name| self.kill_exec_cgroup(&record, Some(name)),
                REAP_TIMEOUT,
            );
            if !stop_ok {
                cgroup_stop_failed = true;
            }
            reaped = exited;
            if !reaped {
                // 終わらない helper（同期 I/O で固まった等）の `Child` は手放さず保持する。後続の probe の開始時・
                // cancel・drop が `try_wait` し、終わるまで新しい helper を作らない（保持は 1 個まで。REPAIR-5）。
                *self
                    .unreaped
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(child);
            }
        }
        // helper が終わった後、出力と結果の EOF を短い猶予だけ待つ（孤児の子孫が端を持ち続けても待たない）。
        let drain_until = Instant::now() + DRAIN_GRACE;
        loop {
            read_all(
                &mut out_eof,
                &mut res_eof,
                &mut output,
                &mut results,
                &mut out_parent,
                &mut res_parent,
            );
            if (out_eof && res_eof) || Instant::now() >= drain_until {
                break;
            }
            std::thread::sleep(POLL_STEP);
        }

        // helper の終了後に届いた作成通知（作成の直後に期限切れで殺され、通知が読み取りに間に合わなかった場合）も、
        // ソケットに残った分を読んだ結果で拾って止める（SUP-6・REPAIR-5）。
        if !stopped && !matches!(ended, Ended::Exited(true)) {
            let owned = owned_exec_cgroup(&results.bytes, helper_pid);
            if !self.kill_exec_cgroup(&record, owned.as_ref()) {
                cgroup_stop_failed = true;
            }
        }
        report.helper_reaped = reaped;
        report.cgroup_stop_failed = cgroup_stop_failed;
        report.output = output.kept;
        report.output_total_bytes = output.total;
        report.output_truncated = output.truncated;

        match ended {
            Ended::Timeout => {
                report.outcome = HealthExecOutcome::Timeout;
                finish(
                    report,
                    Err(TraitError::new(
                        ErrorCode::Timeout,
                        "healthcheck probe timed out",
                    )),
                )
            }
            Ended::Cancelled => {
                report.outcome = HealthExecOutcome::Cancelled;
                finish(
                    report,
                    Err(TraitError::new(
                        ErrorCode::Timeout,
                        "healthcheck probe was cancelled",
                    )),
                )
            }
            Ended::WaitFailed => {
                report.outcome = HealthExecOutcome::HelperError;
                finish(
                    report,
                    Err(TraitError::new(
                        ErrorCode::Internal,
                        "failed to wait for the healthcheck exec helper",
                    )),
                )
            }
            Ended::Exited(false) => {
                // 結果行が残っていても、helper が異常終了したなら採用しない。
                report.outcome = HealthExecOutcome::HelperError;
                finish(
                    report,
                    Err(TraitError::new(
                        ErrorCode::Internal,
                        "the healthcheck exec helper exited abnormally",
                    )),
                )
            }
            Ended::Exited(true) => {
                let parsed = parse_result_stream(&results);
                report.diag_forwarded = parsed.forwarded;
                report.diag_dropped = parsed.dropped;
                match parsed.result {
                    Ok(line) => {
                        let (result, outcome) = map_line(line);
                        report.line = Some(line);
                        report.outcome = outcome;
                        finish(report, result)
                    }
                    Err(()) => {
                        report.outcome = HealthExecOutcome::HelperError;
                        finish(
                            report,
                            Err(TraitError::new(
                                ErrorCode::Internal,
                                "the healthcheck exec helper returned no valid result",
                            )),
                        )
                    }
                }
            }
        }
    }
}

impl ExecHealthProbe {
    /// 保持している未回収の helper を `try_wait` する（待たない）。まだ残っていれば `true`。
    ///
    /// シグナルは送らない（helper は自分で終わるのを待つ）。ロックは待たず、取れなければ「残っている」とみなす（SUP-4・REPAIR-5）。
    fn reap_unreaped(&self) -> bool {
        let mut slot = match self.unreaped.try_lock() {
            Ok(slot) => slot,
            Err(std::sync::TryLockError::Poisoned(p)) => p.into_inner(),
            Err(std::sync::TryLockError::WouldBlock) => return true,
        };
        let Some(child) = slot.as_mut() else {
            return false;
        };
        match child.try_wait() {
            Ok(None) => true,
            // 回収できた、または待ちが失敗した（もう回収の見込みが無い）なら手放す。
            Ok(Some(_)) | Err(_) => {
                *slot = None;
                false
            }
        }
    }

    /// 排他を取って `cancel`（この試行の旗）で 1 回実行する。
    fn probe_with(
        &self,
        timeout: Duration,
        cancel: &ProbeCancel,
    ) -> Result<HealthStatus, TraitError> {
        if self.busy.swap(true, Ordering::SeqCst) {
            return Err(TraitError::new(
                ErrorCode::Unavailable,
                "a healthcheck probe is already running",
            ));
        }
        let _guard = BusyGuard { busy: &self.busy };
        // 前回の未回収の helper が残っていれば、回収できるまで新しい helper を作らない（決定的に `Unavailable`）。
        if self.reap_unreaped() {
            return Err(TraitError::new(
                ErrorCode::Unavailable,
                "a previous healthcheck exec helper has not been reaped",
            ));
        }
        // 手放された helper の保持先が上限なら、どの adapter も新しい helper を作らない。
        if self.held.sweep() >= MAX_HELD_HELPERS {
            return Err(TraitError::new(
                ErrorCode::Unavailable,
                "too many unreaped healthcheck exec helpers",
            ));
        }
        // 排他を取れた試行だけが `cancel` の宛先を登録する。拒否された試行は `current` に触れないので、
        // 実行中の試行への `cancel()` が失われない。区間を抜けても消さない（次の試行が排他の中で置き換える。
        // 終わった試行の旗が立っても無害。SUP-4・REPAIR-5）。
        *self
            .current
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = cancel.clone();
        // 旗は試行ごとに別なので、開始時に消さない。遅れた前の回の cancel は前の回の旗にだけ立ち、
        // 今回の旗に先に立った cancel も失われない（SUP-4・REPAIR-5）。
        self.run(timeout, cancel)
    }
}

impl HealthProbe for ExecHealthProbe {
    fn probe(&self, timeout: Duration) -> Result<HealthStatus, TraitError> {
        // 直接呼び出しでは新しい旗を作る。`cancel` の宛先への登録は排他を取れた後に `probe_with` が行う。
        self.probe_with(timeout, &ProbeCancel::new())
    }

    fn probe_cancellable(
        &self,
        timeout: Duration,
        cancel: &ProbeCancel,
    ) -> Result<HealthStatus, TraitError> {
        self.probe_with(timeout, cancel)
    }

    fn cancel(&self) {
        // 旗を立てるだけ（すぐ戻る）。kill と回収は probe のループが自分で行う。
        self.current
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .cancel();
        // 未回収の helper が居れば、待たずに回収を試みる。
        let _ = self.reap_unreaped();
    }
}

impl Drop for ExecHealthProbe {
    fn drop(&mut self) {
        // 未回収の helper が生きていれば、プロセス全体の保持先へ移す（`Child` を drop しても回収されないため）。
        // シグナルは送らない。
        let child = self
            .unreaped
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some(mut child) = child
            && matches!(child.try_wait(), Ok(None))
        {
            self.held.hold(child);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fandhe_container_core::exec::ExecChildStep;
    use std::os::fd::AsFd as _;

    /// REPAIR-5（#2441）: exec の期限は `T - min(T/5, 2s)`。
    #[test]
    fn sup4_2441_exec_budget_table() {
        assert_eq!(
            exec_budget(Duration::from_secs(30)),
            Duration::from_millis(28_000)
        );
        assert_eq!(
            exec_budget(Duration::from_secs(5)),
            Duration::from_millis(4_000)
        );
        assert_eq!(
            exec_budget(Duration::from_secs(1)),
            Duration::from_millis(800)
        );
        assert_eq!(
            exec_budget(Duration::from_millis(1)),
            Duration::from_millis(1)
        );
        assert_eq!(exec_budget(Duration::ZERO), Duration::from_millis(1));
        assert_eq!(exec_budget(Duration::from_secs(600)), MAX_POLL_INTERVAL);
    }

    fn mapped(
        line: HealthExecLine,
    ) -> (Result<HealthStatus, (ErrorCode, String)>, HealthExecOutcome) {
        let (result, outcome) = map_line(line);
        (
            result.map_err(|e| (e.code(), e.message().to_string())),
            outcome,
        )
    }

    /// SUP-4（#2441）: 結果行から戻り値への写像表の全行。
    #[test]
    fn sup4_2441_map_line_table() {
        use super::super::exec_wire::AuditToken::Na;
        assert_eq!(
            mapped(HealthExecLine::Exited {
                code: 0,
                healthy: true,
                audit: Na,
                exit_audit: Na
            }),
            (Ok(HealthStatus::Healthy), HealthExecOutcome::Healthy)
        );
        assert_eq!(
            mapped(HealthExecLine::Exited {
                code: 3,
                healthy: false,
                audit: Na,
                exit_audit: Na
            }),
            (Ok(HealthStatus::Unhealthy), HealthExecOutcome::Unhealthy)
        );
        assert_eq!(
            mapped(HealthExecLine::Signaled {
                signal: 9,
                audit: Na,
                exit_audit: Na
            }),
            (Ok(HealthStatus::Unhealthy), HealthExecOutcome::Unhealthy)
        );
        assert_eq!(
            mapped(HealthExecLine::NotStarted {
                step: Some(ExecChildStep::OpenEntrypoint),
                code: ErrorCode::NotFound,
                violation: false,
                audit: Na
            }),
            (
                Err((
                    ErrorCode::Internal,
                    format!(
                        "healthcheck command did not start: {}",
                        ExecChildStep::OpenEntrypoint.message()
                    )
                )),
                HealthExecOutcome::NotStarted
            )
        );
        assert_eq!(
            mapped(HealthExecLine::NotStarted {
                step: None,
                code: ErrorCode::Internal,
                violation: false,
                audit: Na
            }),
            (
                Err((
                    ErrorCode::Internal,
                    "healthcheck command did not start".into()
                )),
                HealthExecOutcome::NotStarted
            )
        );
        assert_eq!(
            mapped(HealthExecLine::Failed {
                code: ErrorCode::Timeout,
                audit: Na
            }),
            (
                Err((ErrorCode::Timeout, "healthcheck exec timed out".into())),
                HealthExecOutcome::Timeout
            )
        );
        assert_eq!(
            mapped(HealthExecLine::Failed {
                code: ErrorCode::FailedPrecondition,
                audit: Na
            }),
            (
                Err((
                    ErrorCode::Internal,
                    "healthcheck exec failed (FAILED_PRECONDITION)".into()
                )),
                HealthExecOutcome::Failed
            )
        );
        assert_eq!(
            mapped(HealthExecLine::Failed {
                code: ErrorCode::PermissionDenied,
                audit: Na
            }),
            (
                Err((
                    ErrorCode::PermissionDenied,
                    "healthcheck exec failed (PERMISSION_DENIED)".into()
                )),
                HealthExecOutcome::Failed
            )
        );
        assert_eq!(
            mapped(HealthExecLine::Stale),
            (
                Err((
                    ErrorCode::FailedPrecondition,
                    "the healthcheck target is stale".into()
                )),
                HealthExecOutcome::Stale
            )
        );
        assert_eq!(
            mapped(HealthExecLine::Invalid),
            (
                Err((
                    ErrorCode::Internal,
                    "the healthcheck exec helper rejected its arguments".into()
                )),
                HealthExecOutcome::HelperError
            )
        );
    }

    fn report(output: &[u8]) -> HealthExecReport {
        HealthExecReport {
            outcome: HealthExecOutcome::Healthy,
            line: Some(HealthExecLine::Exited {
                code: 0,
                healthy: true,
                audit: super::super::exec_wire::AuditToken::Na,
                exit_audit: super::super::exec_wire::AuditToken::Na,
            }),
            output: output.to_vec(),
            output_total_bytes: 12_345,
            output_truncated: true,
            elapsed: Duration::from_millis(42),
            helper_reaped: true,
            cgroup_stop_failed: false,
            diag_forwarded: 1,
            diag_dropped: 2,
        }
    }

    /// REPAIR-4・SEC-1（#2441）: 構造化ログは固定キーだけで、コマンド出力の本文を含まない。
    #[test]
    fn sup4_2441_log_line_has_fixed_keys_and_never_the_output_body() {
        let id = ContainerId::new("web1").unwrap();
        let secret = b"SECRET-TOKEN\n\"quote\"";
        let line = log_line(&id, &report(secret));
        assert_eq!(
            line,
            "{\"component\":\"supervisor.healthcheck\",\"operation\":\"healthcheck_exec\",\"container\":\"web1\",\"result\":\"healthy\",\"exit_code\":0,\"audit\":\"na\",\"exit_audit\":\"na\",\"output_bytes\":12345,\"output_truncated\":true,\"elapsed_ms\":42,\"helper_reaped\":true,\"cgroup_stop_failed\":false,\"diag_forwarded\":1,\"diag_dropped\":2}\n"
        );
        assert!(!line.contains("SECRET"));
    }

    /// REPAIR-4（#2441）: 表示用の本文は制御文字・引用符・非 ASCII をエスケープする。
    #[test]
    fn sup4_2441_output_escaped_neutralizes_control_bytes() {
        assert_eq!(
            report(b"ok\n\x1b[31m\\\xff").output_escaped(),
            "ok\\n\\x1b[31m\\\\\\xff"
        );
    }

    /// REPAIR-5（#2441）: 出力は先頭 4096 バイトだけを保持し、合計と切り捨てを数える。
    #[test]
    fn sup4_2441_output_sink_caps_and_counts() {
        let mut sink = OutputSink::default();
        sink.push(&[b'a'; 3000]);
        assert!(!sink.truncated);
        sink.push(&[b'b'; 3000]);
        assert_eq!(sink.kept.len(), OUTPUT_CAP);
        assert_eq!(sink.total, 6000);
        assert!(sink.truncated);
        assert_eq!(sink.kept.get(2999), Some(&b'a'));
        assert_eq!(sink.kept.get(3000), Some(&b'b'));
    }

    fn sink_of(text: &str) -> ResultSink {
        ResultSink {
            bytes: text.as_bytes().to_vec(),
            overflow: false,
        }
    }

    /// SEC-1（#2441）: 結果行がちょうど 1 本で復号できるときだけ採用し、0 本・2 本・不正・上限超過は拒否する。
    /// 診断行は JSON 形のものだけを転送し、それ以外は捨てて数える。
    #[test]
    fn sup4_2441_result_stream_parsing() {
        let ok = parse_result_stream(&sink_of(
            "{\"component\":\"x\"}\nnoise\nFCHX1 exited 0 healthy na na\n",
        ));
        assert!(matches!(
            ok.result,
            Ok(HealthExecLine::Exited { code: 0, .. })
        ));
        assert_eq!((ok.forwarded, ok.dropped), (1, 1));
        let none = parse_result_stream(&sink_of("{\"a\":1}\n"));
        assert!(none.result.is_err());
        let two = parse_result_stream(&sink_of(
            "FCHX1 exited 0 healthy na na\nFCHX1 exited 0 healthy na na\n",
        ));
        assert!(two.result.is_err());
        let bad = parse_result_stream(&sink_of("FCHX1 exited 0 unhealthy na na\n"));
        assert!(bad.result.is_err());
        let partial = parse_result_stream(&sink_of("FCHX1 exited 0 healthy na na"));
        assert!(partial.result.is_err());
        let mut overflow = sink_of("FCHX1 exited 0 healthy na na\n");
        overflow.overflow = true;
        assert!(parse_result_stream(&overflow).result.is_err());
        let many: String =
            (0..20).map(|_| "{\"k\":1}\n").collect::<String>() + "FCHX1 exited 0 healthy na na\n";
        let noisy = parse_result_stream(&sink_of(&many));
        assert!(noisy.result.is_ok());
        assert_eq!((noisy.forwarded, noisy.dropped), (16, 4));
    }

    fn definition(command: &[&str]) -> HealthcheckDefinition {
        HealthcheckDefinition::parse(&super::super::RawHealthcheck {
            command: command.iter().map(|s| (*s).to_string()).collect(),
            ..Default::default()
        })
        .unwrap()
    }

    fn target() -> HealthExecTarget {
        let devnull = std::fs::File::open("/dev/null").unwrap();
        HealthExecTarget::new(
            PathBuf::from("/run/fandhe-test"),
            ContainerId::new("web1").unwrap(),
            NonZeroU32::new(4242).unwrap(),
            OwnedFd::from(devnull),
        )
    }

    /// SEC-1（#2441）: 相対の argv[0] は固定メッセージで拒否し、コマンドの中身を含めない。
    #[test]
    fn sup4_2441_relative_argv0_is_rejected_without_leaking_the_command() {
        let err = ExecHealthProbe::new(
            &definition(&["relative-secret-cmd", "--token=abc"]),
            target(),
        )
        .unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        assert!(!err.message().contains("secret"));
        assert!(!err.message().contains("abc"));
        assert!(ExecHealthProbe::new(&definition(&["/bin/true"]), target()).is_ok());
    }

    /// REPAIR-5（#2441）: 同時実行の 2 本目は `Unavailable`、`cancel` は即座に戻り直近の試行の旗を立てる。
    #[test]
    fn sup4_2441_second_concurrent_probe_is_unavailable_and_cancel_returns() {
        let probe = ExecHealthProbe::new(&definition(&["/bin/true"]), target()).unwrap();
        // 試行 A が排他を保持して実行中の状態（A の旗を登録済み）。
        let running = ProbeCancel::new();
        *probe.current.lock().unwrap() = running.clone();
        probe.busy.store(true, Ordering::SeqCst);
        // 拒否された B は `current` に触れない。
        let err = probe.probe(Duration::from_secs(1)).unwrap_err();
        assert_eq!(err.code(), ErrorCode::Unavailable);
        let err = probe
            .probe_cancellable(Duration::from_secs(1), &ProbeCancel::new())
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::Unavailable);
        assert!(!running.is_cancelled());
        // その後の `cancel()` は実行中の A の旗を立てる。
        probe.cancel();
        assert!(running.is_cancelled());
        probe.busy.store(false, Ordering::SeqCst);
        // A が打ち切られるのを実経路でも確認する: 排他を取った試行は自分の旗を登録し、cancel で Cancelled になる。
        let real = ProbeCancel::new();
        real.cancel();
        let err = probe
            .probe_cancellable(Duration::from_secs(5), &real)
            .unwrap_err();
        assert_eq!(err.message(), "healthcheck probe was cancelled");
    }

    /// REPAIR-5・SUP-4（#2441）: 前の回の試行の旗に遅れて届いた cancel は、次の回の旗を汚さず `Cancelled` にしない。
    #[test]
    fn repair5_2441_late_cancel_of_previous_attempt_does_not_poison_the_next_probe() {
        let probe = ExecHealthProbe::new(&definition(&["/bin/true"]), target()).unwrap();
        let previous = ProbeCancel::new();
        let next = ProbeCancel::new();
        // 次の回が始まった後に、前の回の cancel が着地する（開始後の遅延）。
        let _ = probe.probe_cancellable(Duration::from_secs(5), &next);
        previous.cancel();
        assert!(previous.is_cancelled());
        assert!(!next.is_cancelled());
        let outcome = probe.last_report().map(|r| r.outcome);
        assert_ne!(outcome, Some(HealthExecOutcome::Cancelled));
        assert!(!probe.busy.load(Ordering::SeqCst));
    }

    /// REPAIR-5・SUP-4（#2441）: 今回の試行に開始前に出た cancel は開始時に消えず、`Cancelled` で打ち切る。
    #[test]
    fn repair5_2441_cancel_issued_before_start_is_not_cleared() {
        let probe = ExecHealthProbe::new(&definition(&["/bin/true"]), target()).unwrap();
        let attempt = ProbeCancel::new();
        attempt.cancel();
        let err = probe
            .probe_cancellable(Duration::from_secs(5), &attempt)
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::Timeout);
        assert_eq!(err.message(), "healthcheck probe was cancelled");
        assert_eq!(
            probe.last_report().map(|r| r.outcome),
            Some(HealthExecOutcome::Cancelled)
        );
        assert!(attempt.is_cancelled());
        assert!(!probe.busy.load(Ordering::SeqCst));
    }

    /// SUP-6・REPAIR-5（#2441）: 作成通知が無ければ所有を確定できず何も止めない。同名の populated な cgroup が
    /// 既にあっても（pid の再利用）停止も削除もしない。
    #[test]
    fn sup6_2441_stale_same_name_cgroup_is_not_stopped_without_creation_notice() {
        let root = std::env::temp_dir().join(format!(
            "fandhe-hc-stale-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let helper_pid = 4242u32;
        let stale = root.join(format!("exec-{helper_pid}-0"));
        std::fs::create_dir_all(&stale).unwrap();
        std::fs::write(stale.join("cgroup.procs"), b"777\n").unwrap();

        // 結果行と診断行だけで、作成通知が無い。
        let stream = b"{\"diag\":1}\nFCHX1 stale\n";
        let owned = owned_exec_cgroup(stream, helper_pid);
        assert_eq!(owned, None);
        let mut called = false;
        assert!(stop_if_owned(owned.as_ref(), |_| {
            called = true;
            true
        }));
        assert!(!called);
        assert_eq!(
            std::fs::read(stale.join("cgroup.procs")).unwrap(),
            b"777\n".to_vec()
        );
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// SUP-6（#2441）: 作成通知を受けた名前だけを止める。pid の食い違い・不正な名前・途中で切れた行は採らない。
    #[test]
    fn sup6_2441_only_the_notified_cgroup_of_this_helper_is_owned() {
        let ok = owned_exec_cgroup(b"FCHC1 exec-4242-0\nFCHX1 stale\n", 4242).unwrap();
        assert_eq!(ok.as_str(), "exec-4242-0");
        let mut stopped = Vec::new();
        assert!(stop_if_owned(Some(&ok), |n| {
            stopped.push(n.as_str().to_owned());
            true
        }));
        assert_eq!(stopped, vec!["exec-4242-0".to_owned()]);
        // 別 pid の名前（偽造・古い通知）。
        assert_eq!(owned_exec_cgroup(b"FCHC1 exec-1-0\n", 4242), None);
        // 不正な名前。
        assert_eq!(owned_exec_cgroup(b"FCHC1 ../exec-4242-0\n", 4242), None);
        // 改行で終わらない途中の行。
        assert_eq!(owned_exec_cgroup(b"FCHC1 exec-4242-0", 4242), None);
        // 停止の失敗は false で返る。
        assert!(!stop_if_owned(Some(&ok), |_| false));
    }

    /// SUP-4（#2441）: 作成通知行は結果行の数にも診断行の破棄数にも入らない。
    #[test]
    fn sup4_2441_cgroup_notice_line_does_not_disturb_result_parsing() {
        let sink = ResultSink {
            bytes: b"FCHC1 exec-4242-0\nFCHX1 stale\n".to_vec(),
            overflow: false,
        };
        let parsed = parse_result_stream(&sink);
        assert_eq!(parsed.result, Ok(HealthExecLine::Stale));
        assert_eq!(parsed.dropped, 0);
    }

    /// SUP-4・REPAIR-5（#2441）: 期限切れでは作成通知を受けた exec 子 cgroup だけを止め、helper へシグナルは送らない。
    /// helper（の代役）は cgroup が止まったことを見て自分で終わり、シグナルによる終了ではない。
    #[test]
    fn sup4_2441_expiry_stops_only_the_owned_cgroup_and_never_signals_the_helper() {
        use std::os::unix::process::ExitStatusExt as _;
        let flag = std::env::temp_dir().join(format!("fandhe-hc-flag-{}", std::process::id()));
        std::fs::write(&flag, b"1").unwrap();
        // helper の代役: フラグ（= exec 子 cgroup の中身の代役）が消えるまで動き、消えたら自分で終わる。
        let mut helper = Command::new("/bin/sh")
            .arg("-c")
            .arg(format!(
                "while [ -e '{}' ]; do sleep 0.02; done",
                flag.display()
            ))
            .spawn()
            .unwrap();
        let name = ExecCgroupName::new("exec-4242-0").unwrap();
        let stopped = std::cell::RefCell::new(Vec::new());
        let (stop_ok, exited) = stop_cgroup_then_wait(
            &mut helper,
            Some(&name),
            |n| {
                stopped.borrow_mut().push(n.as_str().to_owned());
                std::fs::remove_file(&flag).is_ok()
            },
            Duration::from_secs(10),
        );
        assert!(stop_ok);
        assert!(exited);
        assert_eq!(*stopped.borrow(), vec!["exec-4242-0".to_owned()]);
        // 自分で終わった: 終了コード 0 で、シグナルによる終了ではない。
        let status = helper.wait().unwrap();
        assert_eq!(status.code(), Some(0));
        assert_eq!(status.signal(), None);
    }

    /// SUP-4・REPAIR-5（#2441）: 作成通知が無ければ何も止めず、終わらない helper は待ちきった後も生きたまま
    /// （シグナルを送らない）で、`exited = false` を返す。
    #[test]
    fn sup4_2441_expiry_without_notice_stops_nothing_and_leaves_helper_alive() {
        let mut helper = Command::new("/bin/sleep").arg("30").spawn().unwrap();
        let (stop_ok, exited) = stop_cgroup_then_wait(
            &mut helper,
            None,
            |_| panic!("nothing owned must not be stopped"),
            Duration::from_millis(100),
        );
        assert!(stop_ok);
        assert!(!exited);
        assert!(matches!(helper.try_wait(), Ok(None)));
        helper.kill().unwrap();
        helper.wait().unwrap();
    }

    /// SUP-4・REPAIR-5（#2441）: 終わらない helper が残っている間は、次の probe は helper を作らずに `Unavailable` で
    /// 戻り（シグナルも送らない）、終わった後は先へ進む。
    #[test]
    fn repair5_2441_unreaped_helper_blocks_new_probe_until_it_exits() {
        let probe = ExecHealthProbe::new(&definition(&["/bin/true"]), target()).unwrap();
        let stuck = Command::new("/bin/sleep").arg("30").spawn().unwrap();
        *probe.unreaped.lock().unwrap() = Some(stuck);
        for _ in 0..5 {
            let err = probe.probe(Duration::from_secs(1)).unwrap_err();
            assert_eq!(err.code(), ErrorCode::Unavailable);
            assert_eq!(
                err.message(),
                "a previous healthcheck exec helper has not been reaped"
            );
            assert!(probe.last_report().is_none());
            // シグナルを送っていないので、まだ生きている。
            assert!(matches!(
                probe.unreaped.lock().unwrap().as_mut().unwrap().try_wait(),
                Ok(None)
            ));
        }
        // helper が終わる（ここでは試験が終わらせる）。有界に待って、先へ進むことを確かめる。
        probe
            .unreaped
            .lock()
            .unwrap()
            .as_mut()
            .unwrap()
            .kill()
            .unwrap();
        let until = Instant::now() + Duration::from_secs(10);
        loop {
            let blocked = matches!(
                probe.probe(Duration::from_secs(1)),
                Err(e) if e.message() == "a previous healthcheck exec helper has not been reaped"
            );
            if !blocked {
                break;
            }
            assert!(Instant::now() < until, "the exited helper was never reaped");
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(probe.unreaped.lock().unwrap().is_none());
        assert!(!probe.busy.load(Ordering::SeqCst));
    }

    /// SUP-4・REPAIR-5（#2441）: adapter を drop すると、生きている未回収 helper は保持先へ移り（シグナルは送らない）、
    /// 保持先が上限の間はどの adapter の probe も `Unavailable`、helper が終わって掃除された後は進む。
    #[test]
    fn repair5_2441_dropped_adapter_hands_unreaped_helper_to_the_process_wide_holder() {
        let held: &'static HeldHelpers = Box::leak(Box::new(HeldHelpers::new()));
        let mut probe = ExecHealthProbe::new(&definition(&["/bin/true"]), target()).unwrap();
        probe.held = held;
        let stuck = Command::new("/bin/sleep").arg("30").spawn().unwrap();
        *probe.unreaped.lock().unwrap() = Some(stuck);
        drop(probe);
        // 引き継がれ、まだ生きている（シグナルを送っていない）。
        assert_eq!(held.sweep(), 1);
        // 上限まで埋める。
        for _ in 1..MAX_HELD_HELPERS {
            held.hold(Command::new("/bin/sleep").arg("30").spawn().unwrap());
        }
        assert_eq!(held.sweep(), MAX_HELD_HELPERS);
        // 別の adapter でも、上限の間は helper を作らず Unavailable。
        let mut other = ExecHealthProbe::new(&definition(&["/bin/true"]), target()).unwrap();
        other.held = held;
        let err = other.probe(Duration::from_secs(1)).unwrap_err();
        assert_eq!(err.code(), ErrorCode::Unavailable);
        assert_eq!(err.message(), "too many unreaped healthcheck exec helpers");
        assert!(other.last_report().is_none());
        // helper が終わる（試験が終わらせる）と掃除されて進む。有界に待つ。
        for child in held.0.lock().unwrap().iter_mut() {
            child.kill().unwrap();
        }
        let until = Instant::now() + Duration::from_secs(10);
        while held.sweep() > 0 {
            assert!(Instant::now() < until, "held helpers were never reaped");
            std::thread::sleep(Duration::from_millis(10));
        }
        let after = other.probe(Duration::from_secs(1));
        assert!(
            !matches!(&after, Err(e) if e.message() == "too many unreaped healthcheck exec helpers")
        );
    }

    /// REPAIR-5（#2441）: 前回の `hc-resolve` が未終了なら新しい取得スレッドを作らず `Unavailable`（in-flight は 1 本）。
    #[test]
    fn repair5_2441_unfinished_resolver_blocks_a_new_one() {
        let probe = ExecHealthProbe::new(&definition(&["/bin/true"]), target()).unwrap();
        probe.resolver_busy.store(true, Ordering::SeqCst);
        let err = probe.probe(Duration::from_secs(1)).unwrap_err();
        assert_eq!(err.code(), ErrorCode::Unavailable);
        assert!(
            probe.resolver_busy.load(Ordering::SeqCst),
            "must not be cleared by a refused probe"
        );
    }

    /// `as_fd` が使えること（未使用 import の警告を避ける最小の確認ではなく、target が pidfd を所有していること）。
    #[test]
    fn repair5_2441_pump_stops_at_byte_cap_without_eof() {
        use std::io::Write as _;
        let (mut tx, mut rx) = UnixStream::pair().unwrap();
        rx.set_nonblocking(true).unwrap();
        tx.set_nonblocking(true).unwrap();
        // 読み手が追い付かない大量出力を作る（送信側が詰まるまで書く）。
        let chunk = [b'x'; 4096];
        while tx.write(&chunk).is_ok() {}
        let mut got = 0usize;
        let eof = pump(&mut rx, |c| got += c.len());
        assert!(!eof);
        assert!(got >= PUMP_BYTES_MAX, "got {got}");
        assert!(got < PUMP_BYTES_MAX + 2048 + 1, "got {got}");
    }

    #[test]
    fn sup4_2441_target_owns_its_pidfd() {
        let t = target();
        assert!(t.pidfd.as_fd().try_clone_to_owned().is_ok());
    }
}
