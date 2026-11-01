//! shim v2 Task API の Exec 用の型・検証・登録簿（CRI-5・TASK-62.4・MS-7）。
//!
//! containerd の意味論では `Exec` は exec プロセスを登録するだけで、起動は続く `Start`（`exec_id` つき）が
//! 行う。[`super::task_service::TaskService`] が `Exec` で [`parse_process_spec`] と [`ExecRegistry`] を使い、
//! `Start(exec_id)` で [`TaskExecLauncher`] を呼ぶ。
//!
//! 起動役 [`TaskExecLauncher`] は本モジュールで定義するだけで、本番の実装は無い（REPAIR-3）。`ContainerRuntime`
//! （core）に exec は無く、本番の入口は supervisor の `run_command_with_pidfd` にあるが cri は依存しない
//! （PLUG-1 の境界を保つ）。supervisor への橋渡しと配線は #803（TASK-62.7）で扱う（TASK-62.5 の #675 は ContainerRuntime 境界の接続までで、exec の起動役は含まない）。
//! 差し込まれない既定の `TaskService` は `Exec` / `Start(exec_id)` を `UNIMPLEMENTED` で拒否する（fail-closed）。
//!
//! 外部入力（`Any` の JSON）は untrusted として検証する。受け付けない欄は黙って捨てず `UNIMPLEMENTED`、
//! 未知の欄は `INVALID_ARGUMENT`。エラーは固定の英語文のみで、spec の中身や環境変数の値は返さない。
//!
//! 出典: type URL は containerd の `core/runtime/typeurl.go`（`typeurl.Register(&specs.Process{}, "types.containerd.io",
//! "opencontainers/runtime-spec", major, "Process")`、major は 1）。欄は OCI runtime-spec v1.2 `config.md` の Process 節。

use std::collections::BTreeMap;
use std::num::NonZeroU32;
use std::sync::Mutex;

use fandhe_container_core::traits::ContainerId;
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
/// 1 コンテナあたりに登録できる exec の最大数。`Delete(exec_id)` による除去（#870）が入るまでの歯止め。
pub const MAX_EXECS_PER_CONTAINER: usize = 64;
/// 全コンテナ合計で登録できる exec の最大数。
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

/// コンテナ内で exec プロセスを起動する役（`Start(exec_id)` から呼ばれる）。
///
/// 契約:
/// - 期限は実装側が持つ（REPAIR-5。`ContainerRuntime` と同じ。shim は期限を足さない）。
/// - プロセスはコンテナの namespace・cgroup・seccomp・capability を継承する（SEC-1）。広げない。
/// - `spec.user()` が `None` のときはコンテナの init と同じユーザーで動かす。
/// - 戻り値は PID（不明なら `None`）。
/// - shim は `Start` の直前にコンテナが Running かを再確認するが、確認から起動までの間に停止しうる。
///   停止済みコンテナへの起動は実装側が拒否する（`FAILED_PRECONDITION`。#803）。
/// - panic しないこと。panic すると登録簿の状態が `Starting` のまま残る（除去は #870 で `Delete(exec_id)`
///   とあわせて扱う。コンテナ削除・exec 終了時の登録の除去も #870 の必須事項）。
///
/// 本番の実装は無い（REPAIR-3。#803）。
pub trait TaskExecLauncher: Send + Sync {
    /// exec プロセスを起動する。
    fn launch(
        &self,
        container: &ContainerId,
        exec_id: &ExecId,
        spec: &ExecProcessSpec,
    ) -> Result<Option<NonZeroU32>, CriError>;
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

#[derive(Debug, Clone)]
enum ExecState {
    Created,
    Starting,
    Started,
}

#[derive(Debug, Clone)]
struct ExecEntry {
    spec: ExecProcessSpec,
    state: ExecState,
    /// この登録に固有のトークン。`begin_start` が発行し、`finish_start` が照合する
    /// （削除・再作成で同じ ID の別登録に旧 launch の結果を書かないため）。
    token: u64,
}

/// `Start(exec_id)` の起動開始時に得る、検証済み仕様と登録固有のトークン。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartTicket {
    /// 起動する exec の仕様。
    pub spec: ExecProcessSpec,
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
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        container.as_str().hash(&mut h);
        let idx = (h.finish() % GATE_STRIPES as u64) as usize;
        self.gates
            .get(idx)
            .ok_or_else(poisoned)?
            .lock()
            .map_err(|_| poisoned())
    }

    /// コンテナの exec 登録をすべて除去する（Delete 成功後、ゲート保持中に呼ぶ。CRI-5）。
    pub fn purge_container(&self, container: &ContainerId) -> Result<(), CriError> {
        let mut inner = self.inner.lock().map_err(|_| poisoned())?;
        inner.map.retain(|(c, _), _| c != container.as_str());
        Ok(())
    }

    /// 登録する。重複は `ALREADY_EXISTS`、上限超過は `RESOURCE_EXHAUSTED`。
    pub fn register(
        &self,
        container: &ContainerId,
        exec_id: &ExecId,
        spec: ExecProcessSpec,
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
                    token: entry.token,
                })
            }
            ExecState::Starting | ExecState::Started => {
                Err(CriError::failed_precondition("exec already started"))
            }
        }
    }

    /// 起動の結果を反映する。成功は `Started`、失敗は `Created` へ戻して再試行できるようにする。
    /// トークンが現在の登録と一致しなければ（削除・再作成で別の登録になった）何も書かない。
    pub fn finish_start(
        &self,
        container: &ContainerId,
        exec_id: &ExecId,
        ticket: &StartTicket,
        ok: bool,
    ) -> Result<(), CriError> {
        let mut inner = self.inner.lock().map_err(|_| poisoned())?;
        if let Some(entry) = inner.map.get_mut(&key(container, exec_id))
            && entry.token == ticket.token
        {
            entry.state = if ok {
                ExecState::Started
            } else {
                ExecState::Created
            };
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::CriErrorCode;

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
        r.register(&c, &e, spec.clone()).unwrap();
        assert_eq!(
            r.register(&c, &e, spec.clone()).unwrap_err().code(),
            CriErrorCode::AlreadyExists
        );
        let t = r.begin_start(&c, &e).unwrap();
        assert_eq!(t.spec, spec);
        assert_eq!(
            r.begin_start(&c, &e).unwrap_err().code(),
            CriErrorCode::FailedPrecondition
        );
        r.finish_start(&c, &e, &t, false).unwrap();
        let t = r.begin_start(&c, &e).unwrap();
        r.finish_start(&c, &e, &t, true).unwrap();
        assert!(r.begin_start(&c, &e).is_err());
        for i in 1..MAX_EXECS_PER_CONTAINER {
            r.register(&c, &ExecId::new(&format!("x{i}")).unwrap(), spec.clone())
                .unwrap();
        }
        assert_eq!(
            r.register(&c, &ExecId::new("over").unwrap(), spec.clone())
                .unwrap_err()
                .code(),
            CriErrorCode::ResourceExhausted
        );
        // 別コンテナは per-container 上限の影響を受けない。
        let c2 = ContainerId::new("c2").unwrap();
        r.register(&c2, &e, spec).unwrap();
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
        r.register(&c, &e, spec.clone()).unwrap();
        r.register(&c2, &e, spec.clone()).unwrap();
        let old = r.begin_start(&c, &e).unwrap();
        r.purge_container(&c).unwrap();
        assert_eq!(
            r.begin_start(&c, &e).unwrap_err().code(),
            CriErrorCode::NotFound
        );
        // 同じ ID で再登録した新しい登録へ、旧 launch の結果（成功・失敗とも）は書かれない。
        r.register(&c, &e, spec.clone()).unwrap();
        r.finish_start(&c, &e, &old, true).unwrap();
        let fresh = r.begin_start(&c, &e).unwrap();
        r.finish_start(&c, &e, &old, false).unwrap();
        assert_eq!(
            r.begin_start(&c, &e).unwrap_err().code(),
            CriErrorCode::FailedPrecondition,
            "stale failure must not reset Starting"
        );
        r.finish_start(&c, &e, &fresh, true).unwrap();
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
}
