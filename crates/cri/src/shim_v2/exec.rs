//! shim v2 Task API の Exec 用の型・検証・登録簿（CRI-5・TASK-62.4・MS-7）。
//!
//! containerd の意味論では `Exec` は exec プロセスを登録するだけで、起動は続く `Start`（`exec_id` つき）が
//! 行う。[`super::task_service::TaskService`] が `Exec` で [`parse_process_spec`] と [`ExecRegistry`] を使い、
//! `Start(exec_id)` で [`TaskExecLauncher`] を呼ぶ。
//!
//! 起動役 [`TaskExecLauncher`] は本モジュールでトレイトとして定義するだけで、実装は持たない。`ContainerRuntime`
//! （core）に exec は無く、本番の入口は supervisor の `run_command_with_pidfd` にあるが cri は依存しない
//! （PLUG-1 の境界を保つ）。本番の実装は plugin-cri の `task_exec::ShimExecLauncher`（Linux のみ。#4148）で、shim バイナリの
//! 登録簿が v2・v3 の `TaskService` へ差し込む（#4149。TASK-62.7）。
//! 差し込まれない既定の `TaskService` は `Exec` / `Start(exec_id)` と、`exec_id` つきの `State` / `Kill` / `Wait` /
//! `Delete` を `UNIMPLEMENTED` で拒否する（fail-closed）。
//!
//! 起動した exec は [`TaskExecProcess`]（起動したそのプロセスだけを指すハンドル）として登録簿が保持し、
//! `State` / `Kill` / `Wait` / `Delete`（`exec_id` つき。#3681）が [`ExecRegistry::snapshot`] 経由で引く。
//!
//! 外部入力（`Any` の JSON）は untrusted として検証する。受け付けない欄は黙って捨てず `UNIMPLEMENTED`、
//! 未知の欄は `INVALID_ARGUMENT`。エラーは固定の英語文のみで、spec の中身や環境変数の値は返さない。
//!
//! 出典: type URL は containerd の `core/runtime/typeurl.go`（`typeurl.Register(&specs.Process{}, "types.containerd.io",
//! "opencontainers/runtime-spec", major, "Process")`、major は 1）。欄は OCI runtime-spec v1.2 `config.md` の Process 節。

use std::collections::BTreeMap;
use std::num::NonZeroU32;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use fandhe_container_core::traits::{ContainerId, Signal};
use serde::Deserialize;
use serde::de::IgnoredAny;

use super::task_api::Any;
use crate::bundle::spec::{
    MAX_ADDITIONAL_GIDS, MAX_ARGS, MAX_CONFIG_BYTES, MAX_ENV, check_abs_path, check_string,
};
use crate::error::CriError;

/// `Any.type_url` として受け付ける runtime-spec の `Process`（containerd の typeurl 登録）。
pub const PROCESS_TYPE_URL: &str = "types.containerd.io/opencontainers/runtime-spec/1/Process";
/// `Any.value`（JSON）の最大バイト数。復号の前に検査する。
pub const MAX_EXEC_SPEC_BYTES: usize = 1 << 20;
/// 1 コンテナあたりに登録できる exec の最大数。`Delete(exec_id)` による除去は実装済みで、上限は無制限確保を防ぐために残す。
pub const MAX_EXECS_PER_CONTAINER: usize = 64;
/// 全コンテナ合計で登録できる exec の最大数。
///
/// 外で消えたコンテナの登録がこの枠を塞ぎ続けないよう、`TaskService` が回収する（#4058・CRI-5・REPAIR-5）。
/// 契機は shim の Create の成功・Exec / Start(exec_id) / Delete で実行層が `NOT_FOUND` を返したとき・
/// この上限に達した Exec の掃除（登録のある別コンテナを照会し `NOT_FOUND` のものだけ除去）。
/// 上限そのものは弱めない。
pub const MAX_EXECS_TOTAL: usize = 1024;

const _: () = assert!(MAX_EXEC_SPEC_BYTES <= MAX_CONFIG_BYTES);

/// 検証済みの exec ID（`ContainerId` と同じ規則）。
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ExecId(String);

impl ExecId {
    /// 検証して作る。空・`.`・`..`・255 バイト超・`[A-Za-z0-9._-]` 以外は `INVALID_ARGUMENT`。
    pub fn new(s: &str) -> Result<Self, CriError> {
        let id = ContainerId::new(s).map_err(|e| CriError::from(&e))?;
        Ok(Self(id.as_str().to_owned()))
    }

    /// 文字列表現。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// exec プロセスの実行ユーザー。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecUser {
    /// uid。
    pub uid: u32,
    /// gid。
    pub gid: u32,
    /// 補助 gid（件数は検証済み）。
    pub additional_gids: Vec<u32>,
}

/// 検証済みの exec プロセス仕様。[`parse_process_spec`] でしか作れない。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecProcessSpec {
    args: Vec<String>,
    env: Vec<String>,
    cwd: String,
    user: Option<ExecUser>,
}

impl ExecProcessSpec {
    /// argv。1 要素以上で `args[0]` は空でない。
    pub fn args(&self) -> &[String] {
        &self.args
    }

    /// `KEY=VALUE` 形式の環境変数。
    pub fn env(&self) -> &[String] {
        &self.env
    }

    /// コンテナ内の絶対パスの作業ディレクトリ。
    pub fn cwd(&self) -> &str {
        &self.cwd
    }

    /// 実行ユーザー。`None` は起動役が決める（コンテナの init と同じユーザーにすること）。
    pub fn user(&self) -> Option<&ExecUser> {
        self.user.as_ref()
    }
}

/// 起動済みの exec プロセスのハンドル（`State` / `Kill` / `Wait` / `Delete` が使う。CRI-5・CRI-1・REPAIR-5）。
///
/// [`TaskExecLauncher::launch`] が返し、登録簿が `Started` の間だけ保持する。
///
/// 契約:
/// - 起動したそのプロセスだけを指す。PID の再利用で別プロセスへシグナルを送らない（本番の実装は pidfd 等を使う。SEC-1）。
/// - 各メソッドは有界で、panic しない。
/// - 終了後の [`Self::signal`] は `NOT_FOUND` を返す。
/// - [`Self::wait_exit`] は期限で `Timeout`、取り消しで `Unavailable` を返し、有界の刻みで確認する（REPAIR-5）。
/// - drop は資源の解放だけを行い、プロセスの停止は要求しない（コンテナ削除の purge で drop される）。
///
/// 本番の実装は plugin-cri の `task_exec` の `ShimExecProcess`（Linux のみ。#4148）。
pub trait TaskExecProcess: Send + Sync {
    /// 起動したプロセスの PID（不明なら `None`）。
    fn pid(&self) -> Option<NonZeroU32>;

    /// 現在の状態を照会する。失敗は `Err`（呼び出し側は fail-closed で扱う）。
    fn status(&self) -> Result<ExecProcessStatus, CriError>;

    /// シグナルを送る。終了済みは `NOT_FOUND`。
    fn signal(&self, signal: Signal) -> Result<(), CriError>;

    /// 終了するまで `timeout` を上限に待ち、終了コード（不明なら `None`）を返す。
    ///
    /// 簡易実装（REPAIR-3）: 既定の本体は [`Self::status`] を `poll_interval` ごとに照会するだけで、
    /// 終了通知は使わない。pidfd 等を持つ実装は上書きしてイベント駆動にしてよい（期限と取り消しは有界の刻みで守る）。
    fn wait_exit(
        &self,
        timeout: Duration,
        poll_interval: Duration,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<Option<i32>, CriError> {
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or_else(|| CriError::internal("wait deadline overflow"))?;
        loop {
            if cancelled() {
                return Err(CriError::unavailable("wait cancelled"));
            }
            if let ExecProcessStatus::Exited { code } = self.status()? {
                return Ok(code);
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(CriError::timeout("wait exceeded its deadline"));
            }
            let until = now + poll_interval.min(deadline - now);
            if !sleep_until(until, cancelled) {
                return Err(CriError::unavailable("wait cancelled"));
            }
        }
    }
}

/// [`TaskExecProcess::status`] の結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecProcessStatus {
    /// 実行中。
    Running,
    /// 終了済み。`code` は終了コード（不明なら `None`）。
    Exited {
        /// 終了コード。
        code: Option<i32>,
    },
}

/// `until` まで有界の刻み（10 ミリ秒）で眠る。取り消されたら `false`。
pub(super) fn sleep_until(until: Instant, cancelled: &dyn Fn() -> bool) -> bool {
    const CANCEL_SLICE: Duration = Duration::from_millis(10);
    loop {
        if cancelled() {
            return false;
        }
        let now = Instant::now();
        if now >= until {
            return true;
        }
        std::thread::sleep(CANCEL_SLICE.min(until - now));
    }
}

/// コンテナ内で exec プロセスを起動する役（`Start(exec_id)` から呼ばれる）。
///
/// 契約:
/// - 期限は実装側が持つ（REPAIR-5。`ContainerRuntime` と同じ。shim は期限を足さない）。
/// - プロセスはコンテナの namespace・cgroup・seccomp・capability を継承する（SEC-1）。広げない。
/// - `spec.user()` が `None` のときはコンテナの init と同じユーザーで動かす。
/// - 戻り値は起動したプロセスのハンドル [`TaskExecProcess`]。
/// - shim は `Start` の直前にコンテナが Running かを再確認するが、確認から起動までの間に停止しうる。
///   停止済みコンテナへの起動は実装側が拒否する（`FAILED_PRECONDITION`）。
/// - `expected_instance` は登録時に実行層が報告したインスタンス識別子。実装は**起動対象（pid）を決める状態読み取りと
///   同じ読み取り**で [`crate::adapter::instance_matches`] により照合し、不一致（値が違う・片側だけ `None`）なら
///   起動せず `FAILED_PRECONDITION`（`MSG_EXEC_INSTANCE_CHANGED`）を返す。shim の `purge_mismatched` は別の読み取りで
///   行うため、その後の作り直し（TOCTOU）は起動役の照合だけが塞ぐ（#4323・CRI-5・SEC-1）。
/// - panic しないこと。panic すると登録簿の状態が `Starting` のまま残り、コンテナのゲートも毒される
///   （以後そのストライプは `INTERNAL`）。
///
/// 本番の実装は plugin-cri の `task_exec::ShimExecLauncher`（Linux のみ。#4148。shim バイナリの登録簿が差し込む。#4149）。
/// 非 Linux と、起動役を差さない `TaskService`（試験を含む）は `UNIMPLEMENTED` のまま（REPAIR-3）。
pub trait TaskExecLauncher: Send + Sync {
    /// exec プロセスを起動する。
    fn launch(
        &self,
        container: &ContainerId,
        exec_id: &ExecId,
        spec: &ExecProcessSpec,
        expected_instance: Option<u64>,
    ) -> Result<Arc<dyn TaskExecProcess>, CriError>;
}

fn invalid(msg: &'static str) -> CriError {
    CriError::invalid_argument(msg)
}

fn unsupported(msg: &'static str) -> CriError {
    CriError::unimplemented(msg)
}

/// runtime-spec の `Process` の欄。受け付けない欄は `IgnoredAny` で存在だけ見る。
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawProcess {
    terminal: Option<bool>,
    cwd: Option<String>,
    env: Option<Vec<String>>,
    args: Option<Vec<String>>,
    user: Option<RawUser>,
    console_size: Option<IgnoredAny>,
    command_line: Option<IgnoredAny>,
    rlimits: Option<IgnoredAny>,
    apparmor_profile: Option<IgnoredAny>,
    capabilities: Option<IgnoredAny>,
    no_new_privileges: Option<IgnoredAny>,
    oom_score_adj: Option<IgnoredAny>,
    scheduler: Option<IgnoredAny>,
    selinux_label: Option<IgnoredAny>,
    io_priority: Option<IgnoredAny>,
    #[serde(rename = "execCPUAffinity")]
    exec_cpu_affinity: Option<IgnoredAny>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawUser {
    uid: Option<u32>,
    gid: Option<u32>,
    additional_gids: Option<Vec<u32>>,
    umask: Option<IgnoredAny>,
    username: Option<IgnoredAny>,
}

/// `Exec` の `spec`（`Any`）を検証して [`ExecProcessSpec`] にする。
///
/// 検査順: type URL → 長さ上限 → JSON 復号 → 受け付けない欄 → args → env → cwd → user。
pub fn parse_process_spec(any: &Any) -> Result<ExecProcessSpec, CriError> {
    if any.type_url != PROCESS_TYPE_URL {
        return Err(invalid("unexpected exec spec type"));
    }
    if any.value.len() > MAX_EXEC_SPEC_BYTES {
        return Err(invalid("exec spec is too large"));
    }
    let raw: RawProcess =
        serde_json::from_slice(&any.value).map_err(|_| invalid("malformed exec process spec"))?;
    let unsupported_fields: [(bool, &'static str); 11] = [
        (raw.terminal == Some(true), "terminal is not supported"),
        (raw.console_size.is_some(), "consoleSize is not supported"),
        (raw.command_line.is_some(), "commandLine is not supported"),
        (raw.rlimits.is_some(), "rlimits is not supported"),
        (
            raw.apparmor_profile.is_some(),
            "apparmorProfile is not supported",
        ),
        (raw.capabilities.is_some(), "capabilities is not supported"),
        (
            raw.no_new_privileges.is_some(),
            "noNewPrivileges is not supported",
        ),
        (raw.oom_score_adj.is_some(), "oomScoreAdj is not supported"),
        (raw.scheduler.is_some(), "scheduler is not supported"),
        (raw.selinux_label.is_some(), "selinuxLabel is not supported"),
        (
            raw.io_priority.is_some() || raw.exec_cpu_affinity.is_some(),
            "ioPriority and execCPUAffinity are not supported",
        ),
    ];
    if let Some((_, msg)) = unsupported_fields.iter().find(|(hit, _)| *hit) {
        return Err(unsupported(msg));
    }
    if let Some(u) = &raw.user {
        if u.umask.is_some() {
            return Err(unsupported("user.umask is not supported"));
        }
        if u.username.is_some() {
            return Err(unsupported("user.username is not supported"));
        }
    }

    let args = raw.args.unwrap_or_default();
    if args.is_empty() || args.len() > MAX_ARGS {
        return Err(invalid("args is invalid"));
    }
    for a in &args {
        check_string("args", a).map_err(|_| invalid("args is invalid"))?;
    }
    if args.first().is_none_or(|a| a.is_empty()) {
        return Err(invalid("args is invalid"));
    }

    let env = raw.env.unwrap_or_default();
    if env.len() > MAX_ENV {
        return Err(invalid("env is invalid"));
    }
    for e in &env {
        check_string("env", e).map_err(|_| invalid("env is invalid"))?;
        match e.split_once('=') {
            Some((k, _)) if !k.is_empty() => {}
            _ => return Err(invalid("env is invalid")),
        }
    }

    let cwd = raw.cwd.ok_or_else(|| invalid("cwd is invalid"))?;
    check_abs_path("cwd", &cwd).map_err(|_| invalid("cwd is invalid"))?;

    let user = match raw.user {
        None => None,
        Some(u) => {
            let additional_gids = u.additional_gids.unwrap_or_default();
            if additional_gids.len() > MAX_ADDITIONAL_GIDS {
                return Err(invalid("user.additionalGids is invalid"));
            }
            Some(ExecUser {
                uid: u.uid.unwrap_or(0),
                gid: u.gid.unwrap_or(0),
                additional_gids,
            })
        }
    };
    Ok(ExecProcessSpec {
        args,
        env,
        cwd,
        user,
    })
}

#[derive(Clone)]
enum ExecState {
    Created,
    Starting,
    Started(Arc<dyn TaskExecProcess>),
}

/// ハンドルの中身は出さない（状態名だけ）。
impl std::fmt::Debug for ExecState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Created => "Created",
            Self::Starting => "Starting",
            Self::Started(_) => "Started",
        })
    }
}

/// 登録簿の exec の段階（[`ExecRegistry::snapshot`] の結果）。
#[derive(Clone)]
pub enum ExecPhase {
    /// 登録済みで未起動。
    Created,
    /// 起動役を呼び出し中。
    Starting,
    /// 起動済み。
    Started {
        /// 起動したプロセスのハンドル。
        process: Arc<dyn TaskExecProcess>,
    },
}

impl std::fmt::Debug for ExecPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Created => "Created",
            Self::Starting => "Starting",
            Self::Started { .. } => "Started",
        })
    }
}

/// ある時点の exec の段階と、登録固有のトークン（再登録の検出に使う）。
#[derive(Debug, Clone)]
pub struct ExecSnapshot {
    /// 段階。
    pub phase: ExecPhase,
    token: u64,
}

impl ExecSnapshot {
    /// 同じ登録の snapshot か（削除・再作成で別の登録になっていないか）。
    pub fn is_same_registration(&self, other: &ExecSnapshot) -> bool {
        self.token == other.token
    }
}

#[derive(Debug, Clone)]
struct ExecEntry {
    spec: ExecProcessSpec,
    state: ExecState,
    /// この登録に固有のトークン。`begin_start` が発行し、`finish_start` が照合する
    /// （削除・再作成で同じ ID の別登録に旧 launch の結果を書かないため）。
    token: u64,
    /// 登録時のコンテナのインスタンス識別子（#4220）。現在の値と違えば別インスタンスの登録とみなす。
    instance: Option<u64>,
}

/// `Start(exec_id)` の起動開始時に得る、検証済み仕様と登録固有のトークン。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartTicket {
    /// 起動する exec の仕様。
    pub spec: ExecProcessSpec,
    /// 登録時にコンテナが報告したインスタンス識別子（#4323）。起動役が自分の状態読み取りと照合する。
    pub instance: Option<u64>,
    token: u64,
}

/// コンテナ単位の排他に使うロックの本数（コンテナ ID のハッシュで選ぶ。増え続けない）。
const GATE_STRIPES: usize = 64;

/// 登録済みの exec の一覧（コンテナ ID と exec ID の組で引く）。
///
/// 起動中は内部ロックを保持しない: [`Self::begin_start`] が `Starting` にして解放し、
/// 起動役の結果を [`Self::finish_start`] で反映する。
///
/// 同じコンテナの「削除（remove から purge まで）」「状態確認から登録・起動の完了まで」は、
/// [`Self::lock_container`] のゲートで互いに排他する（CRI-5）。
#[derive(Debug)]
pub struct ExecRegistry {
    inner: Mutex<RegistryInner>,
    gates: Vec<Mutex<()>>,
}

#[derive(Debug, Default)]
struct RegistryInner {
    map: BTreeMap<(String, String), ExecEntry>,
    /// 登録ごとのトークンの採番。
    next_token: u64,
}

impl Default for ExecRegistry {
    fn default() -> Self {
        Self {
            inner: Mutex::default(),
            gates: (0..GATE_STRIPES).map(|_| Mutex::new(())).collect(),
        }
    }
}

fn poisoned() -> CriError {
    CriError::internal("exec registry is unavailable")
}

fn key(container: &ContainerId, exec_id: &ExecId) -> (String, String) {
    (container.as_str().to_owned(), exec_id.as_str().to_owned())
}

impl ExecRegistry {
    /// 空の登録簿を作る。
    pub fn new() -> Self {
        Self::default()
    }

    /// コンテナ単位のゲートを取る。Delete（remove から purge まで）と、Exec / Start の
    /// 「状態確認から登録・起動の完了まで」はこのゲートを保持して互いに排他する。
    /// Start(exec_id) は起動役の完了までこのゲートを保持する。同じ呼び出しで 2 つ以上取らない（デッドロック防止）。
    pub fn lock_container(
        &self,
        container: &ContainerId,
    ) -> Result<std::sync::MutexGuard<'_, ()>, CriError> {
        self.gate_of(container)?.lock().map_err(|_| poisoned())
    }

    /// ゲートを待たずに取る。他者が保持していれば `Ok(None)`（毒されていれば内部エラー）。
    ///
    /// 全体上限での掃除（#4058）が、別コンテナの Exec / Start の完了を待たずに飛ばすために使う。
    pub fn try_lock_container(
        &self,
        container: &ContainerId,
    ) -> Result<Option<std::sync::MutexGuard<'_, ()>>, CriError> {
        match self.gate_of(container)?.try_lock() {
            Ok(g) => Ok(Some(g)),
            Err(std::sync::TryLockError::WouldBlock) => Ok(None),
            Err(std::sync::TryLockError::Poisoned(_)) => Err(poisoned()),
        }
    }

    fn gate_of(&self, container: &ContainerId) -> Result<&Mutex<()>, CriError> {
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        container.as_str().hash(&mut h);
        let idx = (h.finish() % GATE_STRIPES as u64) as usize;
        self.gates.get(idx).ok_or_else(poisoned)
    }

    /// 登録のあるコンテナの一覧（重複なし。件数は [`MAX_EXECS_TOTAL`] 以下）。
    /// 内部ロックの中で複製してすぐ放す。全体上限での掃除（#4058・CRI-5・REPAIR-5）が使う。
    pub fn containers(&self) -> Result<Vec<ContainerId>, CriError> {
        let inner = self.inner.lock().map_err(|_| poisoned())?;
        let mut names: Vec<&str> = inner.map.keys().map(|(c, _)| c.as_str()).collect();
        names.dedup();
        Ok(names
            .into_iter()
            .filter_map(|c| ContainerId::new(c).ok())
            .collect())
    }

    /// 全体の登録数が [`MAX_EXECS_TOTAL`] に達しているか。
    pub fn is_total_full(&self) -> Result<bool, CriError> {
        let inner = self.inner.lock().map_err(|_| poisoned())?;
        Ok(inner.map.len() >= MAX_EXECS_TOTAL)
    }

    /// コンテナ単位の登録数が [`MAX_EXECS_PER_CONTAINER`] に達しているか。
    /// 達していれば全体掃除をしても空きは生まれないため、掃除を省く判定に使う（#4058・REPAIR-5）。
    pub fn is_container_full(&self, container: &ContainerId) -> Result<bool, CriError> {
        let inner = self.inner.lock().map_err(|_| poisoned())?;
        let n = inner
            .map
            .keys()
            .filter(|(c, _)| c == container.as_str())
            .count();
        Ok(n >= MAX_EXECS_PER_CONTAINER)
    }

    /// コンテナの exec 登録をすべて除去する（Delete 成功後、ゲート保持中に呼ぶ。CRI-5）。
    pub fn purge_container(&self, container: &ContainerId) -> Result<(), CriError> {
        let mut inner = self.inner.lock().map_err(|_| poisoned())?;
        inner.map.retain(|(c, _), _| c != container.as_str());
        Ok(())
    }

    /// コンテナの登録のうち、登録時のインスタンス識別子が `current` と異なるものを除去し、件数を返す
    /// （ゲート保持中に、`state` が返した識別子で呼ぶ。#4220・CRI-5・SEC-1・CORE-1）。
    ///
    /// shim の外で同じ ID のコンテナが削除・再作成されると `state` は `NOT_FOUND` を返さないため、旧い登録
    /// （argv・env・user）が新しいコンテナで起動されうる。それを塞ぐ照合で、素朴な不等号の比較にする:
    /// `None` 同士は残す（識別子を報告しない実装・旧い記録では判定できない）、`Some` が違うものと片側だけ
    /// `None` のものは除去する（fail-closed）。
    pub fn purge_mismatched(
        &self,
        container: &ContainerId,
        current: Option<u64>,
    ) -> Result<usize, CriError> {
        let mut inner = self.inner.lock().map_err(|_| poisoned())?;
        let before = inner.map.len();
        inner.map.retain(|(c, _), e| {
            c != container.as_str() || crate::adapter::instance_matches(e.instance, current)
        });
        Ok(before - inner.map.len())
    }

    /// 登録する。重複は `ALREADY_EXISTS`、上限超過は `RESOURCE_EXHAUSTED`。
    ///
    /// `instance` は登録時点のコンテナのインスタンス識別子（実行層が報告した値。`None` は報告なし）。
    /// [`Self::purge_mismatched`] が現在の値と照合する（#4220・CRI-5・SEC-1）。
    pub fn register(
        &self,
        container: &ContainerId,
        exec_id: &ExecId,
        spec: ExecProcessSpec,
        instance: Option<u64>,
    ) -> Result<(), CriError> {
        let mut inner = self.inner.lock().map_err(|_| poisoned())?;
        let k = key(container, exec_id);
        if inner.map.contains_key(&k) {
            return Err(CriError::already_exists("exec already exists"));
        }
        let per_container = inner.map.keys().filter(|(c, _)| *c == k.0).count();
        if per_container >= MAX_EXECS_PER_CONTAINER || inner.map.len() >= MAX_EXECS_TOTAL {
            return Err(CriError::resource_exhausted("too many execs"));
        }
        inner.next_token = inner.next_token.wrapping_add(1);
        let token = inner.next_token;
        inner.map.insert(
            k,
            ExecEntry {
                spec,
                state: ExecState::Created,
                token,
                instance,
            },
        );
        Ok(())
    }

    /// `Created` を `Starting` にして仕様の複製とトークンを返す。未登録は `NOT_FOUND`、起動済み・起動中は `FAILED_PRECONDITION`。
    pub fn begin_start(
        &self,
        container: &ContainerId,
        exec_id: &ExecId,
    ) -> Result<StartTicket, CriError> {
        let mut inner = self.inner.lock().map_err(|_| poisoned())?;
        let entry = inner
            .map
            .get_mut(&key(container, exec_id))
            .ok_or_else(|| CriError::not_found("exec not found"))?;
        match entry.state {
            ExecState::Created => {
                entry.state = ExecState::Starting;
                Ok(StartTicket {
                    spec: entry.spec.clone(),
                    instance: entry.instance,
                    token: entry.token,
                })
            }
            ExecState::Starting | ExecState::Started(_) => {
                Err(CriError::failed_precondition("exec already started"))
            }
        }
    }

    /// 起動の結果を反映する。ハンドルがあれば `Started`、`None`（失敗）は `Created` へ戻して再試行できるようにする。
    /// トークンが現在の登録と一致しなければ（削除・再作成で別の登録になった）何も書かない。
    pub fn finish_start(
        &self,
        container: &ContainerId,
        exec_id: &ExecId,
        ticket: &StartTicket,
        process: Option<Arc<dyn TaskExecProcess>>,
    ) -> Result<(), CriError> {
        let mut inner = self.inner.lock().map_err(|_| poisoned())?;
        if let Some(entry) = inner.map.get_mut(&key(container, exec_id))
            && entry.token == ticket.token
        {
            entry.state = match process {
                Some(p) => ExecState::Started(p),
                None => ExecState::Created,
            };
        }
        Ok(())
    }

    /// 登録の段階を複製して返す（ロックを持ったままハンドルを呼ばせないため）。未登録は `NOT_FOUND`。
    pub fn snapshot(
        &self,
        container: &ContainerId,
        exec_id: &ExecId,
    ) -> Result<ExecSnapshot, CriError> {
        let inner = self.inner.lock().map_err(|_| poisoned())?;
        let entry = inner
            .map
            .get(&key(container, exec_id))
            .ok_or_else(|| CriError::not_found("exec not found"))?;
        let phase = match &entry.state {
            ExecState::Created => ExecPhase::Created,
            ExecState::Starting => ExecPhase::Starting,
            ExecState::Started(p) => ExecPhase::Started {
                process: Arc::clone(p),
            },
        };
        Ok(ExecSnapshot {
            phase,
            token: entry.token,
        })
    }

    /// 登録を除去する（`Delete(exec_id)` が、コンテナのゲート保持中に呼ぶ）。未登録は `NOT_FOUND`。
    pub fn remove(&self, container: &ContainerId, exec_id: &ExecId) -> Result<(), CriError> {
        let mut inner = self.inner.lock().map_err(|_| poisoned())?;
        inner
            .map
            .remove(&key(container, exec_id))
            .map(|_| ())
            .ok_or_else(|| CriError::not_found("exec not found"))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::CriErrorCode;

    /// 状態を外から差し替えられる試験用ハンドル。
    struct TestProc(Mutex<ExecProcessStatus>);

    impl TestProc {
        fn running() -> Arc<Self> {
            Arc::new(Self(Mutex::new(ExecProcessStatus::Running)))
        }
    }

    impl TaskExecProcess for TestProc {
        fn pid(&self) -> Option<NonZeroU32> {
            NonZeroU32::new(42)
        }
        fn status(&self) -> Result<ExecProcessStatus, CriError> {
            Ok(*self.0.lock().unwrap())
        }
        fn signal(&self, _: Signal) -> Result<(), CriError> {
            Ok(())
        }
    }

    fn some(p: &Arc<TestProc>) -> Option<Arc<dyn TaskExecProcess>> {
        let p: Arc<dyn TaskExecProcess> = Arc::clone(p) as Arc<dyn TaskExecProcess>;
        Some(p)
    }

    fn any(json: &str) -> Any {
        Any {
            type_url: PROCESS_TYPE_URL.into(),
            value: json.as_bytes().to_vec(),
        }
    }

    const OK: &str = r#"{"cwd":"/","args":["/bin/sh","-c","id"],"env":["A=b","PATH=/bin"],"user":{"uid":1000,"gid":1001,"additionalGids":[2000,3000]}}"#;

    /// CRI-5: 正常な spec が具体値で復号される。
    #[test]
    fn cri5_parse_ok() {
        let s = parse_process_spec(&any(OK)).unwrap();
        assert_eq!(s.args(), ["/bin/sh", "-c", "id"]);
        assert_eq!(s.env(), ["A=b", "PATH=/bin"]);
        assert_eq!(s.cwd(), "/");
        assert_eq!(
            s.user(),
            Some(&ExecUser {
                uid: 1000,
                gid: 1001,
                additional_gids: vec![2000, 3000]
            })
        );
        let s =
            parse_process_spec(&any(r#"{"cwd":"/a/b","args":["x"],"terminal":false}"#)).unwrap();
        assert_eq!(s.user(), None);
        assert!(s.env().is_empty());
    }

    /// CRI-5: 不正な入力は INVALID_ARGUMENT。
    #[test]
    fn cri5_parse_invalid() {
        let bad = [
            r#"{"cwd":"/"}"#,
            r#"{"cwd":"/","args":[]}"#,
            r#"{"cwd":"/","args":[""]}"#,
            r#"{"cwd":"/","args":["a\u0000b"]}"#,
            r#"{"cwd":"/","args":["a"],"env":["NOEQ"]}"#,
            r#"{"cwd":"/","args":["a"],"env":["=v"]}"#,
            r#"{"args":["a"]}"#,
            r#"{"cwd":"rel","args":["a"]}"#,
            r#"{"cwd":"/a/../b","args":["a"]}"#,
            r#"{"cwd":"/","args":["a"],"bogus":1}"#,
            r#"{"cwd":"/","args":["a"],"user":{"uid":-1}}"#,
            r#"{"cwd":"/","args":["a"],"user":{"nope":1}}"#,
            "not json",
            "",
        ];
        for j in bad {
            let e = parse_process_spec(&any(j)).unwrap_err();
            assert_eq!(e.code(), CriErrorCode::InvalidArgument, "{j}");
        }
        let many = format!(
            r#"{{"cwd":"/","args":[{}]}}"#,
            vec!["\"a\""; MAX_ARGS + 1].join(",")
        );
        assert!(parse_process_spec(&any(&many)).is_err());
        let mut a = any(OK);
        a.type_url = "x".into();
        assert_eq!(
            parse_process_spec(&a).unwrap_err().message(),
            "unexpected exec spec type"
        );
        let mut a = any(OK);
        a.value = vec![b' '; MAX_EXEC_SPEC_BYTES + 1];
        assert_eq!(
            parse_process_spec(&a).unwrap_err().message(),
            "exec spec is too large"
        );
        let e =
            parse_process_spec(&any(r#"{"cwd":"/","args":["a"],"env":["SECRET"]}"#)).unwrap_err();
        assert!(!e.message().contains("SECRET"));
    }

    /// SEC-1: 受け付けない欄は UNIMPLEMENTED。
    #[test]
    fn cri5_parse_unsupported() {
        let cases = [
            (r#""terminal":true"#, "terminal is not supported"),
            (
                r#""capabilities":{"bounding":["CAP_SYS_ADMIN"]}"#,
                "capabilities is not supported",
            ),
            (r#""rlimits":[]"#, "rlimits is not supported"),
            (
                r#""noNewPrivileges":false"#,
                "noNewPrivileges is not supported",
            ),
            (
                r#""apparmorProfile":"x""#,
                "apparmorProfile is not supported",
            ),
            (r#""selinuxLabel":"x""#, "selinuxLabel is not supported"),
            (r#""oomScoreAdj":1"#, "oomScoreAdj is not supported"),
            (
                r#""consoleSize":{"height":1,"width":1}"#,
                "consoleSize is not supported",
            ),
            (r#""commandLine":"x""#, "commandLine is not supported"),
            (r#""scheduler":{}"#, "scheduler is not supported"),
            (
                r#""ioPriority":{}"#,
                "ioPriority and execCPUAffinity are not supported",
            ),
            (
                r#""execCPUAffinity":{}"#,
                "ioPriority and execCPUAffinity are not supported",
            ),
            (
                r#""user":{"username":"root"}"#,
                "user.username is not supported",
            ),
            (r#""user":{"umask":18}"#, "user.umask is not supported"),
        ];
        for (frag, msg) in cases {
            let j = format!(r#"{{"cwd":"/","args":["a"],{frag}}}"#);
            let e = parse_process_spec(&any(&j)).unwrap_err();
            assert_eq!(e.code(), CriErrorCode::Unimplemented, "{frag}");
            assert_eq!(e.message(), msg);
        }
    }

    #[test]
    fn cri5_exec_id_rules() {
        assert!(ExecId::new("e-1.x_2").is_ok());
        for bad in ["", ".", "..", "bad id!", &"a".repeat(256)] {
            assert!(ExecId::new(bad).is_err(), "{bad:?}");
        }
    }

    /// CRI-5: 登録簿の状態遷移と上限。
    #[test]
    fn cri5_registry_lifecycle_and_limits() {
        let r = ExecRegistry::new();
        let c = ContainerId::new("c1").unwrap();
        let e = ExecId::new("e1").unwrap();
        let spec = parse_process_spec(&any(OK)).unwrap();
        assert_eq!(
            r.begin_start(&c, &e).unwrap_err().message(),
            "exec not found"
        );
        r.register(&c, &e, spec.clone(), None).unwrap();
        assert_eq!(
            r.register(&c, &e, spec.clone(), None).unwrap_err().code(),
            CriErrorCode::AlreadyExists
        );
        let t = r.begin_start(&c, &e).unwrap();
        assert_eq!(t.spec, spec);
        assert_eq!(
            r.begin_start(&c, &e).unwrap_err().code(),
            CriErrorCode::FailedPrecondition
        );
        r.finish_start(&c, &e, &t, None).unwrap();
        let t = r.begin_start(&c, &e).unwrap();
        r.finish_start(&c, &e, &t, some(&TestProc::running()))
            .unwrap();
        assert!(r.begin_start(&c, &e).is_err());
        for i in 1..MAX_EXECS_PER_CONTAINER {
            r.register(
                &c,
                &ExecId::new(&format!("x{i}")).unwrap(),
                spec.clone(),
                None,
            )
            .unwrap();
        }
        assert_eq!(
            r.register(&c, &ExecId::new("over").unwrap(), spec.clone(), None)
                .unwrap_err()
                .code(),
            CriErrorCode::ResourceExhausted
        );
        // 別コンテナは per-container 上限の影響を受けない。
        let c2 = ContainerId::new("c2").unwrap();
        r.register(&c2, &e, spec, None).unwrap();
    }

    /// #4220・CRI-5・SEC-1: purge_mismatched は識別子が違うもの・片側だけ None のものだけを除去する。
    #[test]
    fn cri5_4220_registry_purge_mismatched() {
        let r = ExecRegistry::new();
        let spec = parse_process_spec(&any(OK)).unwrap();
        let (c, other) = (
            ContainerId::new("c1").unwrap(),
            ContainerId::new("c2").unwrap(),
        );
        let id = |s: &str| ExecId::new(s).unwrap();
        for i in 0..3 {
            r.register(&c, &id(&format!("a{i}")), spec.clone(), Some(1))
                .unwrap();
        }
        r.register(&c, &id("n"), spec.clone(), None).unwrap();
        r.register(&other, &id("o"), spec.clone(), Some(1)).unwrap();
        // 同じ識別子は残し、None だけ除去する。
        assert_eq!(r.purge_mismatched(&c, Some(1)).unwrap(), 1);
        // 違う識別子は全件除去する。別コンテナには触れない。
        assert_eq!(r.purge_mismatched(&c, Some(2)).unwrap(), 3);
        assert_eq!(r.purge_mismatched(&c, Some(2)).unwrap(), 0);
        assert!(r.begin_start(&other, &id("o")).is_ok());
        // None 同士は残す。
        r.register(&c, &id("n"), spec, None).unwrap();
        assert_eq!(r.purge_mismatched(&c, None).unwrap(), 0);
        assert!(r.begin_start(&c, &id("n")).is_ok());
    }

    /// #4058・CRI-5: containers は重複なしの一覧、is_total_full は上限の境界、try_lock は保持中なら None。
    #[test]
    fn cri5_4058_registry_containers_total_and_try_lock() {
        let r = ExecRegistry::new();
        let spec = parse_process_spec(&any(OK)).unwrap();
        let (c1, c2) = (
            ContainerId::new("c1").unwrap(),
            ContainerId::new("c2").unwrap(),
        );
        for i in 0..3 {
            r.register(
                &c1,
                &ExecId::new(&format!("e{i}")).unwrap(),
                spec.clone(),
                None,
            )
            .unwrap();
        }
        r.register(&c2, &ExecId::new("e0").unwrap(), spec.clone(), None)
            .unwrap();
        let names: Vec<String> = r
            .containers()
            .unwrap()
            .iter()
            .map(|c| c.as_str().to_owned())
            .collect();
        assert_eq!(names, vec!["c1".to_owned(), "c2".to_owned()]);
        assert!(!r.is_total_full().unwrap());
        let mut n = 4;
        let mut cid = 0;
        while n < MAX_EXECS_TOTAL - 1 {
            let c = ContainerId::new(format!("f{cid}")).unwrap();
            for i in 0..MAX_EXECS_PER_CONTAINER.min(MAX_EXECS_TOTAL - 1 - n) {
                r.register(
                    &c,
                    &ExecId::new(&format!("e{i}")).unwrap(),
                    spec.clone(),
                    None,
                )
                .unwrap();
                n += 1;
            }
            cid += 1;
        }
        assert!(!r.is_total_full().unwrap());
        r.register(&c2, &ExecId::new("last").unwrap(), spec, None)
            .unwrap();
        assert!(r.is_total_full().unwrap());
        let g = r.lock_container(&c1).unwrap();
        assert!(r.try_lock_container(&c1).unwrap().is_none());
        drop(g);
        assert!(r.try_lock_container(&c1).unwrap().is_some());
    }

    /// CRI-5: purge は当該コンテナの登録だけを除去し、旧登録の launch 結果は再登録に反映されない。
    #[test]
    fn cri5_registry_purge_and_stale_finish() {
        let r = ExecRegistry::new();
        let (c, c2) = (
            ContainerId::new("c1").unwrap(),
            ContainerId::new("c2").unwrap(),
        );
        let e = ExecId::new("e1").unwrap();
        let spec = parse_process_spec(&any(OK)).unwrap();
        r.register(&c, &e, spec.clone(), None).unwrap();
        r.register(&c2, &e, spec.clone(), None).unwrap();
        let old = r.begin_start(&c, &e).unwrap();
        assert_eq!(old.instance, None);
        r.purge_container(&c).unwrap();
        assert_eq!(
            r.begin_start(&c, &e).unwrap_err().code(),
            CriErrorCode::NotFound
        );
        // 同じ ID で再登録した新しい登録へ、旧 launch の結果（成功・失敗とも）は書かれない。
        r.register(&c, &e, spec.clone(), None).unwrap();
        r.finish_start(&c, &e, &old, some(&TestProc::running()))
            .unwrap();
        let fresh = r.begin_start(&c, &e).unwrap();
        r.finish_start(&c, &e, &old, None).unwrap();
        assert_eq!(
            r.begin_start(&c, &e).unwrap_err().code(),
            CriErrorCode::FailedPrecondition,
            "stale failure must not reset Starting"
        );
        r.finish_start(&c, &e, &fresh, some(&TestProc::running()))
            .unwrap();
        // 別コンテナの登録は purge の影響を受けない。
        assert_eq!(r.begin_start(&c2, &e).unwrap().spec, spec);
    }

    /// CRI-5: コンテナのゲートは解放後に再取得できる。
    #[test]
    fn cri5_registry_container_gate() {
        let r = ExecRegistry::new();
        let c = ContainerId::new("c1").unwrap();
        drop(r.lock_container(&c).unwrap());
        drop(r.lock_container(&c).unwrap());
    }

    /// CRI-5: snapshot は段階を返し、remove は除去して NOT_FOUND に戻す。再登録は別トークン。
    #[test]
    fn cri5_3681_registry_snapshot_and_remove() {
        let r = ExecRegistry::new();
        let c = ContainerId::new("c1").unwrap();
        let e = ExecId::new("e1").unwrap();
        let spec = parse_process_spec(&any(OK)).unwrap();
        assert_eq!(
            r.snapshot(&c, &e).unwrap_err().code(),
            CriErrorCode::NotFound
        );
        assert_eq!(r.remove(&c, &e).unwrap_err().message(), "exec not found");
        r.register(&c, &e, spec.clone(), None).unwrap();
        let s0 = r.snapshot(&c, &e).unwrap();
        assert!(matches!(s0.phase, ExecPhase::Created));
        let t = r.begin_start(&c, &e).unwrap();
        assert!(matches!(
            r.snapshot(&c, &e).unwrap().phase,
            ExecPhase::Starting
        ));
        let p = TestProc::running();
        r.finish_start(&c, &e, &t, some(&p)).unwrap();
        let s1 = r.snapshot(&c, &e).unwrap();
        assert!(s1.is_same_registration(&s0));
        let ExecPhase::Started { process } = s1.phase else {
            panic!("expected Started");
        };
        assert_eq!(process.pid(), NonZeroU32::new(42));
        r.remove(&c, &e).unwrap();
        assert_eq!(
            r.snapshot(&c, &e).unwrap_err().code(),
            CriErrorCode::NotFound
        );
        r.register(&c, &e, spec, None).unwrap();
        assert!(!r.snapshot(&c, &e).unwrap().is_same_registration(&s0));
    }

    /// REPAIR-5: 既定の wait_exit は終了コード・期限・取り消しを具体値で返す。
    #[test]
    fn cri5_3681_process_wait_exit_default() {
        let p = TestProc::running();
        let ms = Duration::from_millis(5);
        let e = p
            .wait_exit(Duration::from_millis(40), ms, &|| false)
            .unwrap_err();
        assert_eq!(
            (e.code(), e.message()),
            (CriErrorCode::Timeout, "wait exceeded its deadline")
        );
        let e = p
            .wait_exit(Duration::from_secs(10), ms, &|| true)
            .unwrap_err();
        assert_eq!(
            (e.code(), e.message()),
            (CriErrorCode::Unavailable, "wait cancelled")
        );
        *p.0.lock().unwrap() = ExecProcessStatus::Exited { code: Some(6) };
        assert_eq!(
            p.wait_exit(Duration::from_secs(10), ms, &|| false).unwrap(),
            Some(6)
        );
        *p.0.lock().unwrap() = ExecProcessStatus::Exited { code: None };
        assert_eq!(p.wait_exit(Duration::ZERO, ms, &|| false).unwrap(), None);
    }
}
