//! OCI Runtime の `start`（`process.args` の起動と Running への遷移。TASK-29.3・CORE-2・OCI-4）。
//!
//! # 役割と呼び出し元
//!
//! create（`create.rs`）が作った「Created・pid なし」の状態を入力に、bundle の `config.json` を
//! 再検証して [`LaunchSpec`] を組み立て、[`ProcessLauncher`] に起動を委ね、[`StateStore`] を
//! Running（pid 付き）へ更新する。将来の plugin 側 `ContainerRuntime::start` 実装・CLI が呼び出し元。
//! `ContainerRuntime` の実装は plugin 側に置く（PLUG-1）ため、`StateStore` と launcher は依存注入する。
//!
//! # 処理順（固定）
//!
//! 1. 状態取得（不在は `NotFound`。launcher は呼ばない）
//! 2. `Created` 以外は `FailedPrecondition`（`ContainerRuntime::start` の契約）
//! 3. `config.json` を再読込・再検証（create 後の書き換え = TOCTOU 対策。ダイジェスト保持は
//!    `StateRecord` の拡張〔TASK-31・TASK-157.2 の領域〕を要するため採らない）
//! 4. 適用できない指定の fail-closed 拒否・args / env の上限検証・rootfs ハンドルの取得（下記）
//! 5. 起動権の予約: `StateStore::update` を revision 照合つきで呼び、Created を Running（pid なし）へ
//!    原子的に遷移させる。別プロセスの同時 start はここで revision 不一致（`FailedPrecondition`）に
//!    なり launch へ進めない（CORE-2）
//! 6. launcher 起動。失敗時は予約を Created へ戻す（戻せない場合は `Internal` で伝える）
//! 7. Running（pid 付き）へ状態更新。更新に失敗した場合は起動済みプロセスを上限時間つきで終了し、
//!    予約を Created へ戻してから、元のエラーを返す。終了にも失敗した場合（`Timeout` 等）は、
//!    未記録プロセスが残り得ることを示す `Internal` を返し、元のエラーで隠さない（REPAIR-5）
//!
//! start のプロセスが手順 5〜7 の間に異常終了すると Running・pid なしの予約だけが残る。この状態は
//! `FailedPrecondition`（`start was interrupted` を含むメッセージ）で識別でき、
//! [`recover_interrupted_start`] で Created へ戻せる（CORE-2）。ただし launch 後・pid 記録前の中断では
//! 生きたプロセスが残り得るため、回復は launcher が生存プロセス無しを確認できた場合に限る（SEC-1）。
//!
//! 手順 1〜7 は同一 ID につきプロセス内でも排他する（並行 start の早期拒否。CORE-2）。プロセス間の
//! 排他は手順 5 の revision 照合（`StateStore` 実装が更新を原子的に照合する契約）に依存する。
//!
//! # fail-closed の拒否（SEC-1・SEC-5・CORE-5・REPAIR-3）
//!
//! config パーサが解釈済みとする指定のうち、start 経路が現時点で適用できないものは黙って無視せず
//! `Unimplemented` で拒否する（指定より強い権限・弱い分離での起動を防ぐ）。後続タスクが適用を
//! 実装した時点で該当検査を外す。
//!
//! - `process.cwd` が `/` 以外（exec フローが cwd 未対応）
//! - `process.user` が uid 0・gid 0・追加 gid なし以外（ユーザー切替は未実装）
//! - `process.terminal` が true（端末受け渡し未実装）
//! - `mounts` が非空（mount 適用未実装）
//! - `linux.namespaces[].path` の指定（既存 namespace への join 未実装）
//! - `network`・`cgroup`・`time` namespace（exec の対応は PID/Mount/UTS/IPC/User のみ）
//! - `linux.namespaces` に user namespace が無い（`process.user` は root 必須のため、ホスト root での
//!   起動になる。`PermissionDenied`。SEC-5）
//! - `linux.namespaces` に IPC namespace が無い（ホストの IPC を共有する起動を防ぐ。共有の明示許可は
//!   未実装のため必須。`InvalidArgument`。SEC-1）
//! - `linux.namespaces` に PID・mount namespace が無い、または hostname 指定があるのに UTS namespace が
//!   無い（`exec::plan` の共通検証と同じ。ホストのプロセス・マウントが見える起動を防ぐ。`InvalidArgument`）
//! - `linux.uidMappings` / `gidMappings` が非空（config 指定の写像は subuid 範囲写像とともに
//!   TASK-40・CORE-6 で対応する。SEC-5 の「コンテナ内 root をホストの非特権 UID へ写す」写像は
//!   launcher の契約で、`exec::isolate` が呼び出しプロセスの euid / egid へ写す。`ProcessLauncher` 参照）
//! - `root.readonly` が true（読み取り専用 rootfs 未実装）
//!
//! `process.args` / `process.env` は `exec::Entrypoint::new` と同じ上限（件数 4096・1 要素 131072 バイト・
//! 合計 1 MiB。NUL 禁止・env は `KEY=VALUE`）を `LaunchSpec` 構築前に検証し、違反は `InvalidArgument`。
//! `exec` は Linux 限定のため、値は本ファイルに複製し Linux では一致をテストで固定する。
//!
//! rootfs は検査直後にディレクトリを開いて実体の同一性を確認し、ハンドルを `LaunchSpec` に載せる
//! （検査から使用までの差し替え = TOCTOU を閉じる。SEC-1。`RootfsDir` 参照）。
//!
//! `process.args[0]` がコンテナ内の絶対パス（先頭 `/`）でない場合は `InvalidArgument`（PATH 探索は未実装）。
//! コンテナパスはホスト OS 非依存に文字列で判定する（Windows でも `/bin/echo` を受理する。3 OS 一級対応）。
//!
//! # 到達範囲（REPAIR-3）
//!
//! 本 crate に本番 [`ProcessLauncher`] は無く、exec の制限ステージ（TASK-37〜39）も未実装のため
//! 実プロセスの起動は行われない。`process.args` 等がそのまま launcher へ渡り、launcher の返した
//! pid で Running へ遷移するところまでが本関数の責務である。
//!
//! エラーメッセージは固定文言と静的なフィールドパスのみで、config の値や OS 依存の I/O エラー
//! 文字列を含めない。

use std::collections::HashSet;
use std::path::Path;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use super::config::{NamespaceKind, OciConfig};
use super::create::validate_bundle;
use super::launch::{LaunchSpec, ProcessLauncher, RootfsDir};
use crate::observability::{OpName, OpRecorder};
use crate::traits::{
    ContainerId, ContainerState, ContainerStatus, ErrorCode, GetStateRequest, StartRequest,
    StateRecord, StateStore, TraitError, UpdateStateRequest,
};

/// [`OpRecorder`] に記録する操作名（REPAIR-4）。
const START_OP_NAME: &str = "start";

/// 状態更新に失敗したときの起動済みプロセス終了の待ち上限（REPAIR-5）。
const TERMINATE_TIMEOUT: Duration = Duration::from_secs(5);

/// Created 状態のコンテナのプロセスを起動し、Running（pid 付き）へ遷移させる。
///
/// 戻り値は更新後の [`StateRecord`]。未 create の ID は [`ErrorCode::NotFound`]、Created 以外は
/// [`ErrorCode::FailedPrecondition`]。成功・失敗の件数と所要時間は `recorder` へ操作名 `start` で
/// 記録する（全終了経路。REPAIR-4）。
pub fn start(
    store: &dyn StateStore,
    recorder: &OpRecorder,
    launcher: &dyn ProcessLauncher,
    req: &StartRequest,
) -> Result<StateRecord, TraitError> {
    let name = OpName::new(START_OP_NAME)?;
    recorder.record_op(&name, || start_inner(store, launcher, req))
}

/// プロセス内で start 実行中の ID 集合（同一 ID の並行 start による二重 launch を防ぐ予約表）。
fn in_flight() -> &'static Mutex<HashSet<ContainerId>> {
    static IN_FLIGHT: OnceLock<Mutex<HashSet<ContainerId>>> = OnceLock::new();
    IN_FLIGHT.get_or_init(|| Mutex::new(HashSet::new()))
}

/// ID の予約。Drop で解放する（全終了経路・panic でも残さない）。
struct StartReservation(ContainerId);

impl StartReservation {
    fn acquire(id: &ContainerId) -> Result<Self, TraitError> {
        let mut set = in_flight().lock().unwrap_or_else(|e| e.into_inner());
        if !set.insert(id.clone()) {
            return Err(TraitError::new(
                ErrorCode::FailedPrecondition,
                "container start is already in progress",
            ));
        }
        Ok(Self(id.clone()))
    }
}

impl Drop for StartReservation {
    fn drop(&mut self) {
        let mut set = in_flight().lock().unwrap_or_else(|e| e.into_inner());
        set.remove(&self.0);
    }
}

/// 中断された start の起動権予約（Running・pid なし）を Created へ戻す（CORE-2）。
///
/// start は launch 前に状態を Running・pid なしへ更新して起動権を予約する。プロセスが launch 中に
/// 異常終了すると予約だけが残り、次の start は `FailedPrecondition` で拒否される。本関数はその状態を
/// revision 照合つきで Created へ戻す。呼び出し元は、対象コンテナの start が実行中でないこと
/// （前回の start プロセスが終了済みであること）を確認してから呼ぶ。同一プロセス内の start とは
/// 排他する。Running・pid なし以外の状態は `FailedPrecondition`、不在は `NotFound`。
///
/// launch 後・pid 記録前の中断では生きたプロセスが残り得るため、Created へ戻す前に
/// [`ProcessLauncher::confirm_no_process`] で生存プロセスが無いことを確認する。確認できない場合
/// （既定実装を含む）はそのエラーを返して予約を残す（二重起動の防止。SEC-1・CORE-2）。
pub fn recover_interrupted_start(
    store: &dyn StateStore,
    launcher: &dyn ProcessLauncher,
    id: &ContainerId,
) -> Result<StateRecord, TraitError> {
    let _reservation = StartReservation::acquire(id)?;
    let record = store.get(&GetStateRequest::new(id.clone()))?;
    if record.status().state() != ContainerState::Running || record.status().pid().is_some() {
        return Err(TraitError::new(
            ErrorCode::FailedPrecondition,
            "no interrupted start reservation to recover",
        ));
    }
    launcher.confirm_no_process(id)?;
    store.update(&UpdateStateRequest::new(
        ContainerStatus::created(id.clone(), None),
        record.revision(),
    ))
}

fn start_inner(
    store: &dyn StateStore,
    launcher: &dyn ProcessLauncher,
    req: &StartRequest,
) -> Result<StateRecord, TraitError> {
    let _reservation = StartReservation::acquire(req.id())?;
    let record = store.get(&GetStateRequest::new(req.id().clone()))?;
    if record.status().state() != ContainerState::Created {
        // Running・pid なしは start の起動権予約が残った状態（中断・クラッシュ後）。識別できる
        // メッセージで返し、`recover_interrupted_start` での回復を促す（CORE-2）。
        let interrupted =
            record.status().state() == ContainerState::Running && record.status().pid().is_none();
        return Err(TraitError::new(
            ErrorCode::FailedPrecondition,
            if interrupted {
                "container start was interrupted; recover the start reservation"
            } else {
                "container is not in created state"
            },
        ));
    }

    let spec = build_spec(record.bundle())?;

    // 起動権の予約。revision 照合つき更新は別プロセスの同時 start と排他になる（CORE-2）。
    let claimed = store.update(&UpdateStateRequest::new(
        ContainerStatus::running(req.id().clone(), None),
        record.revision(),
    ))?;

    let process = match launcher.launch(&spec) {
        Ok(p) => p,
        Err(err) => return Err(release_claim(store, req.id(), &claimed, err)),
    };

    let running = ContainerStatus::running(req.id().clone(), Some(process.pid()));
    match store.update(&UpdateStateRequest::new(running, claimed.revision())) {
        Ok(updated) => Ok(updated),
        Err(err) => {
            // 状態を記録できないまま生きたプロセスを残さない。終了できなかった場合は
            // 未記録プロセスが残り得ることを呼び出し元へ伝える（元のエラーで隠さない）。
            match process.terminate(TERMINATE_TIMEOUT) {
                Ok(()) => Err(release_claim(store, req.id(), &claimed, err)),
                Err(_) => Err(TraitError::new(
                    ErrorCode::Internal,
                    "failed to record running state and failed to terminate the launched process",
                )),
            }
        }
    }
}

/// 予約（Running・pid なし）を Created へ戻す。戻せない場合は状態が残り得ることを `Internal` で伝える。
fn release_claim(
    store: &dyn StateStore,
    id: &ContainerId,
    claimed: &StateRecord,
    original: TraitError,
) -> TraitError {
    let created = ContainerStatus::created(id.clone(), None);
    match store.update(&UpdateStateRequest::new(created, claimed.revision())) {
        Ok(_) => original,
        Err(_) => TraitError::new(
            ErrorCode::Internal,
            "start failed and the start reservation could not be released",
        ),
    }
}

/// bundle を再検証し、start が適用できない指定を拒否したうえで [`LaunchSpec`] を組み立てる。
fn build_spec(bundle: &Path) -> Result<LaunchSpec, TraitError> {
    let (config, rootfs) = validate_bundle(bundle)?;
    let process = config.process().ok_or_else(|| {
        TraitError::new(
            ErrorCode::InvalidArgument,
            "config.json: process is required",
        )
    })?;

    let first_is_absolute = process.args().first().is_some_and(|a| a.starts_with('/'));
    if !first_is_absolute {
        return Err(TraitError::new(
            ErrorCode::InvalidArgument,
            "process.args[0] must be an absolute path",
        ));
    }
    validate_entrypoint_limits(process.args(), process.env())?;
    let user = process.user();
    if process.cwd() != Path::new("/") {
        return Err(unsupported("process.cwd other than /"));
    }
    if user.uid() != 0 || user.gid() != 0 || !user.additional_gids().is_empty() {
        return Err(unsupported("process.user other than root"));
    }
    if process.terminal() {
        return Err(unsupported("process.terminal"));
    }
    reject_unsupported_linux(&config)?;
    // process.user は root 必須のため、user namespace が無いとホスト root で起動してしまう（SEC-5）。
    if !config
        .namespaces()
        .iter()
        .any(|n| n.kind() == NamespaceKind::User)
    {
        return Err(TraitError::new(
            ErrorCode::PermissionDenied,
            "a user namespace is required to run as root",
        ));
    }

    let namespaces: Vec<NamespaceKind> = config.namespaces().iter().map(|n| n.kind()).collect();
    // exec::plan の共通検証と同じ組合せ（Pid には Mount、hostname には Uts）に加え、Pid・Mount を必須とする。
    let has = |k: NamespaceKind| namespaces.contains(&k);
    if !has(NamespaceKind::Pid) || !has(NamespaceKind::Mount) {
        return Err(TraitError::new(
            ErrorCode::InvalidArgument,
            "the PID and mount namespaces are required",
        ));
    }
    // IPC namespace が無いとホストの IPC（SysV IPC・POSIX メッセージキュー）を共有する。共有を明示許可する
    // 仕組みが無いため fail-closed で必須とする（SEC-1）。
    if !has(NamespaceKind::Ipc) {
        return Err(TraitError::new(
            ErrorCode::InvalidArgument,
            "the IPC namespace is required",
        ));
    }
    if config.hostname().is_some() && !has(NamespaceKind::Uts) {
        return Err(TraitError::new(
            ErrorCode::InvalidArgument,
            "hostname requires the UTS namespace",
        ));
    }
    // 検査済みパスの実体をハンドルで固定し、検査から使用までの差し替えを閉じる（SEC-1）。
    // ハンドル取得後にもう一度検査し、取得までの間に祖先が symlink 化された場合を拒否する。
    let rootfs_dir = RootfsDir::open_checked(&rootfs)?;
    let (_, rechecked) = validate_bundle(bundle)?;
    // 文字列比較だけでは、ハンドル取得後に rootfs や祖先が別実体へ差し替えられても通ってしまうため、
    // 再検証したパスの実体（dev・ino）が保持ハンドルと同一であることも確認する。
    if rechecked != rootfs || !rootfs_dir.is_same_entry(&rechecked) {
        return Err(TraitError::new(
            ErrorCode::PermissionDenied,
            "rootfs changed after validation",
        ));
    }
    Ok(LaunchSpec::new(
        rootfs,
        rootfs_dir,
        process.args().to_vec(),
        process.env().to_vec(),
        config.hostname().map(str::to_owned),
        namespaces,
    ))
}

fn reject_unsupported_linux(config: &OciConfig) -> Result<(), TraitError> {
    if config.root().readonly() {
        return Err(unsupported("root.readonly"));
    }
    if !config.mounts().is_empty() {
        return Err(unsupported("mounts"));
    }
    if !config.uid_mappings().is_empty() || !config.gid_mappings().is_empty() {
        return Err(unsupported("linux.uidMappings / linux.gidMappings"));
    }
    for ns in config.namespaces() {
        if ns.path().is_some() {
            return Err(unsupported("linux.namespaces[].path"));
        }
        if matches!(
            ns.kind(),
            NamespaceKind::Network | NamespaceKind::Cgroup | NamespaceKind::Time
        ) {
            return Err(unsupported("network / cgroup / time namespace"));
        }
    }
    Ok(())
}

/// `exec::ENTRYPOINT_MAX_ARGS`（`exec` は Linux 限定のため複製。Linux ではテストで一致を確認する）。
const ARGS_MAX: usize = 4096;
/// `exec::ENTRYPOINT_MAX_ENV`。
const ENV_MAX: usize = 4096;
/// `exec::ENTRYPOINT_MAX_STRING_BYTES`（NUL を含む 1 要素の上限）。
const STRING_MAX_BYTES: usize = 131_072;
/// `exec::ENTRYPOINT_MAX_TOTAL_BYTES`（path・argv・env の NUL 込み合計。path は `args[0]`）。
const TOTAL_MAX_BYTES: usize = 1 << 20;

/// `exec::Entrypoint::new` 相当の上限・形式検証を `LaunchSpec` 構築前に行う（DoS 防止・REPAIR-2）。
///
/// 上限の検証は要素を走査する前の件数で先に行い、以後は加算のみで確保しない。
fn validate_entrypoint_limits(args: &[String], env: &[String]) -> Result<(), TraitError> {
    let invalid = |msg: &'static str| TraitError::new(ErrorCode::InvalidArgument, msg);
    if args.is_empty() || args.len() > ARGS_MAX || env.len() > ENV_MAX {
        return Err(invalid(
            "process.args / process.env exceed the count limits",
        ));
    }
    // path（args[0]）は argv とは別に数えられるため、合計に 2 回加算される。
    let mut total = args.first().map_or(0, |a| a.len().saturating_add(1));
    for item in args.iter().chain(env.iter()) {
        let size = item.len().saturating_add(1);
        if size > STRING_MAX_BYTES {
            return Err(invalid("a process.args / process.env element is too large"));
        }
        if item.contains('\0') {
            return Err(invalid("process.args / process.env must not contain NUL"));
        }
        total = total.saturating_add(size);
        if total > TOTAL_MAX_BYTES {
            return Err(invalid(
                "process.args / process.env exceed the total size limit",
            ));
        }
    }
    for entry in env {
        if !matches!(entry.find('='), Some(i) if i > 0) {
            return Err(invalid("each process.env element must be KEY=VALUE"));
        }
    }
    Ok(())
}

/// 静的なフィールド名だけを含む `Unimplemented` を作る（config の値は含めない）。
fn unsupported(field: &'static str) -> TraitError {
    TraitError::new(
        ErrorCode::Unimplemented,
        format!("start does not support yet: {field}"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oci_runtime::{LaunchedProcess, create};
    use crate::traits::{
        ContainerId, CreateRequest, CreateStateRequest, DeleteStateRequest, DeleteStateResponse,
        ListStateRequest, StateList, StateRevision,
    };
    use serde_json::{Value, json};
    use std::collections::HashMap;
    use std::num::NonZeroU32;
    use std::path::PathBuf;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// テスト専用のインメモリ `StateStore`。`update` は revision を照合し、失敗注入もできる。
    struct MemStateStore {
        records: Mutex<HashMap<ContainerId, StateRecord>>,
        /// `update` の n 回目（0 始まり）の呼び出しだけ失敗させる。
        fail_update_at: Option<usize>,
        update_calls: AtomicUsize,
    }

    impl MemStateStore {
        fn new(fail_update_at: Option<usize>) -> Self {
            Self {
                records: Mutex::new(HashMap::new()),
                fail_update_at,
                update_calls: AtomicUsize::new(0),
            }
        }
    }

    impl StateStore for MemStateStore {
        fn create(&self, req: &CreateStateRequest) -> Result<StateRecord, TraitError> {
            let mut records = self.records.lock().unwrap_or_else(|e| e.into_inner());
            if records.contains_key(req.id()) {
                return Err(TraitError::new(ErrorCode::AlreadyExists, "exists"));
            }
            let record = StateRecord::new(
                req.status().clone(),
                req.bundle().to_path_buf(),
                StateRevision::from_raw(1),
            )?;
            records.insert(req.id().clone(), record.clone());
            Ok(record)
        }

        fn update(&self, req: &UpdateStateRequest) -> Result<StateRecord, TraitError> {
            let n = self.update_calls.fetch_add(1, Ordering::SeqCst);
            if self.fail_update_at == Some(n) {
                return Err(TraitError::new(ErrorCode::FailedPrecondition, "conflict"));
            }
            let mut records = self.records.lock().unwrap_or_else(|e| e.into_inner());
            let cur = records
                .get(req.status().id())
                .ok_or_else(|| TraitError::new(ErrorCode::NotFound, "not found"))?;
            if cur.revision() != req.expected_revision() {
                return Err(TraitError::new(ErrorCode::FailedPrecondition, "stale"));
            }
            let next = StateRecord::new(
                req.status().clone(),
                cur.bundle().to_path_buf(),
                cur.revision().next()?,
            )?;
            records.insert(req.status().id().clone(), next.clone());
            Ok(next)
        }

        fn get(&self, req: &GetStateRequest) -> Result<StateRecord, TraitError> {
            let records = self.records.lock().unwrap_or_else(|e| e.into_inner());
            records
                .get(req.id())
                .cloned()
                .ok_or_else(|| TraitError::new(ErrorCode::NotFound, "not found"))
        }

        fn list(&self, _req: &ListStateRequest) -> Result<StateList, TraitError> {
            Err(TraitError::new(ErrorCode::Unimplemented, "unused"))
        }

        fn delete(&self, _req: &DeleteStateRequest) -> Result<DeleteStateResponse, TraitError> {
            Err(TraitError::new(ErrorCode::Unimplemented, "unused"))
        }
    }

    /// 受け取った `LaunchSpec` を記録し、固定 pid を返す launcher。
    struct RecordingLauncher {
        specs: Mutex<Vec<LaunchSpec>>,
        terminated: std::sync::Arc<AtomicUsize>,
        fail: bool,
        fail_terminate: bool,
        /// `confirm_no_process` が生存プロセス無しを確認できるか。
        confirms_no_process: bool,
    }

    impl RecordingLauncher {
        fn new(fail: bool) -> Self {
            Self {
                specs: Mutex::new(Vec::new()),
                terminated: std::sync::Arc::new(AtomicUsize::new(0)),
                fail,
                fail_terminate: false,
                confirms_no_process: false,
            }
        }

        fn calls(&self) -> usize {
            self.specs.lock().unwrap_or_else(|e| e.into_inner()).len()
        }

        fn terminations(&self) -> usize {
            self.terminated.load(Ordering::SeqCst)
        }
    }

    struct FakeProcess(std::sync::Arc<AtomicUsize>, bool);

    impl LaunchedProcess for FakeProcess {
        fn pid(&self) -> NonZeroU32 {
            NonZeroU32::new(4242).expect("nonzero")
        }

        fn terminate(&self, _timeout: Duration) -> Result<(), TraitError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            if self.1 {
                return Err(TraitError::new(ErrorCode::Timeout, "terminate timed out"));
            }
            Ok(())
        }
    }

    impl ProcessLauncher for RecordingLauncher {
        fn confirm_no_process(&self, _id: &ContainerId) -> Result<(), TraitError> {
            if self.confirms_no_process {
                Ok(())
            } else {
                Err(TraitError::new(ErrorCode::Unimplemented, "cannot confirm"))
            }
        }

        fn launch(&self, spec: &LaunchSpec) -> Result<Box<dyn LaunchedProcess>, TraitError> {
            self.specs
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(spec.clone());
            if self.fail {
                return Err(TraitError::new(ErrorCode::Internal, "launch failed"));
            }
            Ok(Box::new(FakeProcess(
                self.terminated.clone(),
                self.fail_terminate,
            )))
        }
    }

    /// テストごとに一意な bundle ディレクトリ（終了時に削除）。
    struct Bundle {
        dir: PathBuf,
    }

    impl Bundle {
        fn new(name: &str) -> Self {
            let dir = std::env::temp_dir()
                .join(format!("fandhe-oci-start-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).expect("create bundle dir");
            Self { dir }
        }

        fn write_config(&self, v: &Value) {
            std::fs::write(
                self.dir.join("config.json"),
                serde_json::to_vec(v).expect("serialize"),
            )
            .expect("write config");
        }

        fn create_req(&self, id: &str) -> CreateRequest {
            CreateRequest::new(ContainerId::new(id).expect("id"), self.dir.clone())
                .expect("absolute bundle")
        }
    }

    impl Drop for Bundle {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn valid_config() -> Value {
        json!({
            "ociVersion": "1.2.0",
            "root": {"path": "rootfs"},
            "hostname": "box",
            "process": {
                "user": {"uid": 0, "gid": 0},
                "args": ["/bin/echo", "hello"],
                "env": ["PATH=/bin", "K=V"],
                "cwd": "/"
            },
            "linux": {"namespaces": [
                {"type": "pid"}, {"type": "mount"}, {"type": "user"}, {"type": "uts"},
                {"type": "ipc"}
            ]}
        })
    }

    /// 拒否ケース名と config 変更関数の組。
    type Case = (&'static str, Box<dyn Fn(&mut Value)>);

    fn sid(id: &str) -> StartRequest {
        StartRequest::new(ContainerId::new(id).expect("id"))
    }

    /// create 済みの bundle・ストアを用意する。
    fn created(name: &str) -> (Bundle, MemStateStore) {
        let b = Bundle::new(name);
        b.write_config(&valid_config());
        std::fs::create_dir(b.dir.join("rootfs")).expect("rootfs");
        let store = MemStateStore::new(None);
        create(&store, &OpRecorder::new(), &b.create_req(name)).expect("create");
        (b, store)
    }

    /// create 後に config を差し替えて start し、エラーを返す（状態は Created のまま・launcher 0 回を確認）。
    fn start_rejected_after_rewrite(name: &str, cfg: &Value) -> TraitError {
        let (b, store) = created(name);
        b.write_config(cfg);
        let launcher = RecordingLauncher::new(false);
        let err = start(&store, &OpRecorder::new(), &launcher, &sid(name)).expect_err("must fail");
        assert_eq!(launcher.calls(), 0);
        let got = store
            .get(&GetStateRequest::new(ContainerId::new(name).expect("id")))
            .expect("stored");
        assert_eq!(got.status().state(), ContainerState::Created);
        err
    }

    /// OCI-4: start で `process.args` 等がそのまま launcher に渡り、Running・pid 付きへ遷移する。
    #[test]
    fn oci4_start_launches_process_args_and_transitions_to_running() {
        let (b, store) = created("ok");
        let before = store
            .get(&GetStateRequest::new(ContainerId::new("ok").expect("id")))
            .expect("get");
        let launcher = RecordingLauncher::new(false);
        let record = start(&store, &OpRecorder::new(), &launcher, &sid("ok")).expect("start");
        assert_eq!(record.status().state(), ContainerState::Running);
        assert_eq!(record.status().pid(), NonZeroU32::new(4242));
        assert!(record.revision() > before.revision());
        assert_eq!(launcher.calls(), 1);
        let specs = launcher.specs.lock().expect("lock");
        let spec = specs.first().expect("spec");
        assert_eq!(spec.args(), ["/bin/echo", "hello"]);
        assert_eq!(spec.env(), ["PATH=/bin", "K=V"]);
        assert_eq!(spec.hostname(), Some("box"));
        assert_eq!(spec.rootfs(), b.dir.join("rootfs"));
        assert_eq!(
            spec.namespaces(),
            [
                NamespaceKind::Pid,
                NamespaceKind::Mount,
                NamespaceKind::User,
                NamespaceKind::Uts,
                NamespaceKind::Ipc
            ]
        );
    }

    /// CORE-2: create されていない ID の start は NotFound で、launcher は呼ばれない。
    #[test]
    fn core2_start_unknown_id_returns_not_found() {
        let store = MemStateStore::new(None);
        let launcher = RecordingLauncher::new(false);
        let err = start(&store, &OpRecorder::new(), &launcher, &sid("nope")).expect_err("fail");
        assert_eq!(err.code(), ErrorCode::NotFound);
        assert_eq!(launcher.calls(), 0);
    }

    /// CORE-2: Running への再 start は FailedPrecondition で、launcher は 1 回のまま。
    #[test]
    fn core2_start_twice_returns_failed_precondition() {
        let (_b, store) = created("twice");
        let launcher = RecordingLauncher::new(false);
        start(&store, &OpRecorder::new(), &launcher, &sid("twice")).expect("first");
        let err = start(&store, &OpRecorder::new(), &launcher, &sid("twice")).expect_err("second");
        assert_eq!(err.code(), ErrorCode::FailedPrecondition);
        assert_eq!(launcher.calls(), 1);
    }

    /// SEC-1: create 後に壊れた JSON へ書き換えられた config は start で拒否される（TOCTOU）。
    #[test]
    fn sec1_start_revalidates_malformed_config_after_create() {
        let (b, store) = created("rewrite-bad");
        std::fs::write(b.dir.join("config.json"), b"{ not json").expect("write");
        let launcher = RecordingLauncher::new(false);
        let err =
            start(&store, &OpRecorder::new(), &launcher, &sid("rewrite-bad")).expect_err("fail");
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        assert_eq!(launcher.calls(), 0);
    }

    /// SEC-1: create 後に seccomp 等の未解釈フィールドが加わった config は Unimplemented。
    #[test]
    fn sec1_start_rejects_unapplied_field_added_after_create() {
        let mut cfg = valid_config();
        cfg["linux"]["seccomp"] = json!({"defaultAction": "SCMP_ACT_ALLOW"});
        let err = start_rejected_after_rewrite("rewrite-seccomp", &cfg);
        assert_eq!(err.code(), ErrorCode::Unimplemented);
    }

    /// SEC-1: create 後に rootfs が symlink へ差し替えられたら拒否する。
    #[cfg(unix)]
    #[test]
    fn sec1_start_rejects_symlinked_rootfs_after_create() {
        let (b, store) = created("swap-rootfs");
        std::fs::remove_dir(b.dir.join("rootfs")).expect("rm");
        std::fs::create_dir(b.dir.join("real")).expect("real");
        std::os::unix::fs::symlink(b.dir.join("real"), b.dir.join("rootfs")).expect("symlink");
        let launcher = RecordingLauncher::new(false);
        let err =
            start(&store, &OpRecorder::new(), &launcher, &sid("swap-rootfs")).expect_err("fail");
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        assert_eq!(launcher.calls(), 0);
    }

    /// SEC-1: args[0] が相対パス（PATH 探索は未実装）なら InvalidArgument。
    #[test]
    fn sec1_start_rejects_relative_entrypoint() {
        let mut cfg = valid_config();
        cfg["process"]["args"] = json!(["echo", "hi"]);
        let err = start_rejected_after_rewrite("relarg", &cfg);
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        assert_eq!(err.message(), "process.args[0] must be an absolute path");
    }

    /// SEC-1・SEC-5・CORE-5: start が適用できない指定は黙って無視せず Unimplemented で拒否する。
    #[test]
    fn sec1_start_rejects_unsupported_fields() {
        let cases: Vec<Case> = vec![
            ("cwd", Box::new(|c| c["process"]["cwd"] = json!("/work"))),
            (
                "uid",
                Box::new(|c| c["process"]["user"]["uid"] = json!(1000)),
            ),
            (
                "gid",
                Box::new(|c| c["process"]["user"]["gid"] = json!(1000)),
            ),
            (
                "addgid",
                Box::new(|c| c["process"]["user"]["additionalGids"] = json!([5])),
            ),
            ("tty", Box::new(|c| c["process"]["terminal"] = json!(true))),
            (
                "mounts",
                Box::new(|c| {
                    c["mounts"] =
                        json!([{"destination": "/proc", "type": "proc", "source": "proc"}])
                }),
            ),
            (
                "nspath",
                Box::new(|c| {
                    c["linux"]["namespaces"] = json!([{"type": "pid", "path": "/proc/1/ns/pid"}])
                }),
            ),
            (
                "netns",
                Box::new(|c| c["linux"]["namespaces"] = json!([{"type": "network"}])),
            ),
            (
                "uidmap",
                Box::new(|c| {
                    c["linux"]["uidMappings"] =
                        json!([{"containerID": 0, "hostID": 1000, "size": 1}])
                }),
            ),
            ("ro", Box::new(|c| c["root"]["readonly"] = json!(true))),
        ];
        for (name, mutate) in cases {
            let mut cfg = valid_config();
            mutate(&mut cfg);
            let err = start_rejected_after_rewrite(&format!("rej-{name}"), &cfg);
            assert_eq!(err.code(), ErrorCode::Unimplemented, "case {name}");
            assert!(
                err.message().starts_with("start does not support yet: "),
                "case {name}: {}",
                err.message()
            );
        }
    }

    /// REPAIR-5: 状態更新に失敗したら起動済みプロセスをちょうど 1 回 terminate し、元のエラーを返す。
    #[test]
    fn repair5_start_terminates_process_when_state_update_fails() {
        let b = Bundle::new("upd-fail");
        b.write_config(&valid_config());
        std::fs::create_dir(b.dir.join("rootfs")).expect("rootfs");
        let store = MemStateStore::new(Some(1));
        create(&store, &OpRecorder::new(), &b.create_req("upd-fail")).expect("create");
        let launcher = RecordingLauncher::new(false);
        let err = start(&store, &OpRecorder::new(), &launcher, &sid("upd-fail")).expect_err("fail");
        assert_eq!(err.code(), ErrorCode::FailedPrecondition);
        assert_eq!(launcher.calls(), 1);
        assert_eq!(launcher.terminations(), 1);
    }

    /// SEC-5: user namespace が無い config（ホスト root での起動になる）は PermissionDenied で拒否する。
    #[test]
    fn sec5_start_rejects_missing_user_namespace() {
        let mut cfg = valid_config();
        cfg["linux"]["namespaces"] = json!([{"type": "pid"}, {"type": "mount"}]);
        let err = start_rejected_after_rewrite("no-userns", &cfg);
        assert_eq!(err.code(), ErrorCode::PermissionDenied);
        assert_eq!(err.message(), "a user namespace is required to run as root");
    }

    /// CORE-2: 同一 ID の start が進行中なら二重に launch せず FailedPrecondition を返す。
    #[test]
    fn core2_start_rejects_concurrent_start_of_same_id() {
        let (_b, store) = created("concurrent");
        let launcher = RecordingLauncher::new(false);
        let id = ContainerId::new("concurrent").expect("id");
        let guard = StartReservation::acquire(&id).expect("reserve");
        let err =
            start(&store, &OpRecorder::new(), &launcher, &sid("concurrent")).expect_err("busy");
        assert_eq!(err.code(), ErrorCode::FailedPrecondition);
        assert_eq!(launcher.calls(), 0);
        drop(guard);
        start(&store, &OpRecorder::new(), &launcher, &sid("concurrent")).expect("after release");
        assert_eq!(launcher.calls(), 1);
    }

    /// REPAIR-5: 状態更新と terminate の両方に失敗したら、終了失敗を Internal で伝える。
    #[test]
    fn repair5_start_reports_terminate_failure() {
        let b = Bundle::new("term-fail");
        b.write_config(&valid_config());
        std::fs::create_dir(b.dir.join("rootfs")).expect("rootfs");
        let store = MemStateStore::new(Some(1));
        create(&store, &OpRecorder::new(), &b.create_req("term-fail")).expect("create");
        let mut launcher = RecordingLauncher::new(false);
        launcher.fail_terminate = true;
        let err =
            start(&store, &OpRecorder::new(), &launcher, &sid("term-fail")).expect_err("fail");
        assert_eq!(err.code(), ErrorCode::Internal);
        assert_eq!(launcher.terminations(), 1);
    }

    /// OCI-4: launcher 失敗はそのまま返り、状態は Created のまま。
    #[test]
    fn oci4_start_propagates_launcher_error_without_state_change() {
        let (_b, store) = created("launch-fail");
        let launcher = RecordingLauncher::new(true);
        let err =
            start(&store, &OpRecorder::new(), &launcher, &sid("launch-fail")).expect_err("fail");
        assert_eq!(err.code(), ErrorCode::Internal);
        let got = store
            .get(&GetStateRequest::new(
                ContainerId::new("launch-fail").expect("id"),
            ))
            .expect("stored");
        assert_eq!(got.status().state(), ContainerState::Created);
        assert_eq!(launcher.terminations(), 0);
    }

    /// REPAIR-4: 成功・失敗が `start` 操作名で 1 件ずつ記録される。
    #[test]
    fn repair4_start_records_success_and_failure() {
        let (_b, store) = created("rec");
        let launcher = RecordingLauncher::new(false);
        let rec = OpRecorder::new();
        start(&store, &rec, &launcher, &sid("rec")).expect("first");
        start(&store, &rec, &launcher, &sid("rec")).expect_err("second");
        let stats = rec
            .snapshot_op(&OpName::new("start").expect("name"))
            .expect("recorded");
        assert_eq!(stats.success(), 1);
        assert_eq!(stats.failure(), 1);
        assert!(stats.latency().is_some());
    }

    /// SEC-1・SEC-5: PID / mount namespace が欠けた、または hostname に UTS が無い config は拒否する。
    #[test]
    fn sec1_start_rejects_incomplete_namespace_sets() {
        let cases: Vec<(&str, Value, &str)> = vec![
            (
                "userns-only",
                json!([{"type": "user"}, {"type": "uts"}, {"type": "ipc"}]),
                "the PID and mount namespaces are required",
            ),
            (
                "no-mount",
                json!([{"type": "pid"}, {"type": "user"}, {"type": "uts"}, {"type": "ipc"}]),
                "the PID and mount namespaces are required",
            ),
            (
                "no-uts",
                json!([{"type": "pid"}, {"type": "mount"}, {"type": "user"}, {"type": "ipc"}]),
                "hostname requires the UTS namespace",
            ),
            (
                "no-ipc",
                json!([{"type": "pid"}, {"type": "mount"}, {"type": "user"}, {"type": "uts"}]),
                "the IPC namespace is required",
            ),
        ];
        for (name, namespaces, message) in cases {
            let mut cfg = valid_config();
            cfg["linux"]["namespaces"] = namespaces;
            let err = start_rejected_after_rewrite(&format!("ns-{name}"), &cfg);
            assert_eq!(err.code(), ErrorCode::InvalidArgument, "case {name}");
            assert_eq!(err.message(), message, "case {name}");
        }
    }

    /// CORE-2: 中断された予約（Running・pid なし）は識別でき、回復後に start できる。
    #[test]
    fn core2_interrupted_reservation_is_recoverable() {
        let (b, store) = created("recover");
        let id = ContainerId::new("recover").expect("id");
        let rec = store.get(&GetStateRequest::new(id.clone())).expect("get");
        store
            .update(&UpdateStateRequest::new(
                ContainerStatus::running(id.clone(), None),
                rec.revision(),
            ))
            .expect("claim");
        let mut launcher = RecordingLauncher::new(false);
        let err = start(&store, &OpRecorder::new(), &launcher, &sid("recover")).expect_err("stuck");
        assert_eq!(err.code(), ErrorCode::FailedPrecondition);
        assert_eq!(
            err.message(),
            "container start was interrupted; recover the start reservation"
        );
        // 生存プロセス無しを確認できない launcher では予約を残す（二重起動防止。SEC-1）。
        let err = recover_interrupted_start(&store, &launcher, &id).expect_err("unconfirmed");
        assert_eq!(err.code(), ErrorCode::Unimplemented);
        let rec = store.get(&GetStateRequest::new(id.clone())).expect("get");
        assert_eq!(rec.status().state(), ContainerState::Running);
        launcher.confirms_no_process = true;
        let got = recover_interrupted_start(&store, &launcher, &id).expect("recover");
        assert_eq!(got.status().state(), ContainerState::Created);
        let err = recover_interrupted_start(&store, &launcher, &id).expect_err("not stuck");
        assert_eq!(err.code(), ErrorCode::FailedPrecondition);
        start(&store, &OpRecorder::new(), &launcher, &sid("recover")).expect("start");
        drop(b);
    }

    /// SEC-1: 絶対指定の `root.path` でホストの `/` を rootfs にする起動は拒否する。
    #[test]
    fn sec1_start_rejects_host_root_as_rootfs() {
        let mut cfg = valid_config();
        cfg["root"]["path"] = json!("/");
        let err = start_rejected_after_rewrite("hostroot", &cfg);
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        assert_eq!(err.message(), "rootfs must not be the filesystem root");
    }

    /// REPAIR-2: args / env の件数・サイズ・形式の違反は launcher に渡る前に InvalidArgument で拒否する。
    #[test]
    fn repair2_start_rejects_oversized_or_malformed_entrypoint() {
        let big = "a".repeat(STRING_MAX_BYTES);
        let many: Vec<String> = (0..=ARGS_MAX).map(|i| format!("/x{i}")).collect();
        let cases: Vec<(&str, Value, Value)> = vec![
            ("bigarg", json!(["/bin/echo", big]), json!(["K=V"])),
            ("manyargs", json!(many), json!(["K=V"])),
            (
                "total",
                json!(["/bin/echo", "a".repeat(100_000), "a".repeat(100_000)]),
                Value::Array(
                    (0..10)
                        .map(|i| json!(format!("K{i}={}", "v".repeat(100_000))))
                        .collect(),
                ),
            ),
            ("badenv", json!(["/bin/echo"]), json!(["NOEQUALS"])),
            ("emptykey", json!(["/bin/echo"]), json!(["=V"])),
        ];
        for (name, args, env) in cases {
            let mut cfg = valid_config();
            cfg["process"]["args"] = args;
            cfg["process"]["env"] = env;
            let err = start_rejected_after_rewrite(&format!("lim-{name}"), &cfg);
            assert_eq!(err.code(), ErrorCode::InvalidArgument, "case {name}");
        }
    }

    /// REPAIR-2: 複製した上限値が `exec::Entrypoint` の定数と一致する（Linux）。
    #[cfg(target_os = "linux")]
    #[test]
    fn repair2_entrypoint_limits_match_exec() {
        use crate::exec;
        assert_eq!(ARGS_MAX, exec::ENTRYPOINT_MAX_ARGS);
        assert_eq!(ENV_MAX, exec::ENTRYPOINT_MAX_ENV);
        assert_eq!(STRING_MAX_BYTES, exec::ENTRYPOINT_MAX_STRING_BYTES);
        assert_eq!(TOTAL_MAX_BYTES, exec::ENTRYPOINT_MAX_TOTAL_BYTES);
    }

    /// CORE-2: 起動権の予約（Created から Running への revision 照合つき更新）に負けたら launch しない。
    #[test]
    fn core2_start_does_not_launch_when_claim_is_lost() {
        let b = Bundle::new("claim-lost");
        b.write_config(&valid_config());
        std::fs::create_dir(b.dir.join("rootfs")).expect("rootfs");
        let store = MemStateStore::new(Some(0));
        create(&store, &OpRecorder::new(), &b.create_req("claim-lost")).expect("create");
        let launcher = RecordingLauncher::new(false);
        let err =
            start(&store, &OpRecorder::new(), &launcher, &sid("claim-lost")).expect_err("lost");
        assert_eq!(err.code(), ErrorCode::FailedPrecondition);
        assert_eq!(launcher.calls(), 0);
    }

    /// SEC-1: 再検証パスの実体が保持ハンドルと異なる場合（祖先・rootfs の差し替え）は同一と判定しない。
    #[cfg(unix)]
    #[test]
    fn sec1_rootfs_handle_rejects_swapped_entry() {
        let (b, _store) = created("swap");
        let rootfs = b.dir.join("rootfs");
        let handle = RootfsDir::open_checked(&rootfs).expect("open");
        assert!(handle.is_same_entry(&rootfs));
        let other = b.dir.join("other");
        std::fs::create_dir(&other).expect("mkdir");
        assert!(!handle.is_same_entry(&other));
        std::fs::rename(&rootfs, b.dir.join("moved")).expect("rename");
        std::fs::create_dir(&rootfs).expect("mkdir");
        assert!(!handle.is_same_entry(&rootfs));
    }

    /// SEC-1: 成功時の LaunchSpec は検査済み rootfs のハンドルを持つ（Unix）。
    #[cfg(unix)]
    #[test]
    fn sec1_launch_spec_carries_rootfs_handle() {
        use std::os::unix::fs::MetadataExt;
        let (b, store) = created("handle");
        let launcher = RecordingLauncher::new(false);
        start(&store, &OpRecorder::new(), &launcher, &sid("handle")).expect("start");
        let specs = launcher.specs.lock().expect("lock");
        let spec = specs.first().expect("spec");
        let handle = spec.rootfs_dir().file().metadata().expect("meta");
        let named = std::fs::metadata(b.dir.join("rootfs")).expect("meta");
        assert_eq!((handle.dev(), handle.ino()), (named.dev(), named.ino()));
    }
}
