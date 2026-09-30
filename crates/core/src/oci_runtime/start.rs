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
//! 4. 適用できない指定の fail-closed 拒否（下記）
//! 5. launcher 起動（失敗時はストア無変更）
//! 6. Running へ状態更新。更新に失敗した場合は起動済みプロセスを上限時間つきで終了してから、
//!    元のエラーを返す（`terminate` の失敗より元のエラーを優先する。孤児プロセスを残さない）
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
//! - `linux.uidMappings` / `gidMappings` が非空（subuid 範囲写像は TASK-40・CORE-6）
//! - `root.readonly` が true（読み取り専用 rootfs 未実装）
//!
//! `process.args[0]` が絶対パスでない場合は `InvalidArgument`（PATH 探索は未実装）。
//!
//! # 到達範囲（REPAIR-3）
//!
//! 本 crate に本番 [`ProcessLauncher`] は無く、exec の制限ステージ（TASK-37〜39）も未実装のため
//! 実プロセスの起動は行われない。`process.args` 等がそのまま launcher へ渡り、launcher の返した
//! pid で Running へ遷移するところまでが本関数の責務である。
//!
//! エラーメッセージは固定文言と静的なフィールドパスのみで、config の値や OS 依存の I/O エラー
//! 文字列を含めない。

use std::path::Path;
use std::time::Duration;

use super::config::{NamespaceKind, OciConfig};
use super::create::validate_bundle;
use super::launch::{LaunchSpec, ProcessLauncher};
use crate::observability::{OpName, OpRecorder};
use crate::traits::{
    ContainerState, ContainerStatus, ErrorCode, GetStateRequest, StartRequest, StateRecord,
    StateStore, TraitError, UpdateStateRequest,
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

fn start_inner(
    store: &dyn StateStore,
    launcher: &dyn ProcessLauncher,
    req: &StartRequest,
) -> Result<StateRecord, TraitError> {
    let record = store.get(&GetStateRequest::new(req.id().clone()))?;
    if record.status().state() != ContainerState::Created {
        return Err(TraitError::new(
            ErrorCode::FailedPrecondition,
            "container is not in created state",
        ));
    }

    let spec = build_spec(record.bundle())?;
    let process = launcher.launch(&spec)?;

    let running = ContainerStatus::running(req.id().clone(), Some(process.pid()));
    match store.update(&UpdateStateRequest::new(running, record.revision())) {
        Ok(updated) => Ok(updated),
        Err(err) => {
            // 状態を記録できないまま生きたプロセスを残さない。terminate の失敗より元のエラーを返す。
            let _ = process.terminate(TERMINATE_TIMEOUT);
            Err(err)
        }
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

    let first_is_absolute = process
        .args()
        .first()
        .is_some_and(|a| Path::new(a).is_absolute());
    if !first_is_absolute {
        return Err(TraitError::new(
            ErrorCode::InvalidArgument,
            "process.args[0] must be an absolute path",
        ));
    }
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

    let namespaces: Vec<NamespaceKind> = config.namespaces().iter().map(|n| n.kind()).collect();
    Ok(LaunchSpec::new(
        rootfs,
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
        fail_update: bool,
    }

    impl MemStateStore {
        fn new(fail_update: bool) -> Self {
            Self {
                records: Mutex::new(HashMap::new()),
                fail_update,
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
            if self.fail_update {
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
    }

    impl RecordingLauncher {
        fn new(fail: bool) -> Self {
            Self {
                specs: Mutex::new(Vec::new()),
                terminated: std::sync::Arc::new(AtomicUsize::new(0)),
                fail,
            }
        }

        fn calls(&self) -> usize {
            self.specs.lock().unwrap_or_else(|e| e.into_inner()).len()
        }

        fn terminations(&self) -> usize {
            self.terminated.load(Ordering::SeqCst)
        }
    }

    struct FakeProcess(std::sync::Arc<AtomicUsize>);

    impl LaunchedProcess for FakeProcess {
        fn pid(&self) -> NonZeroU32 {
            NonZeroU32::new(4242).expect("nonzero")
        }

        fn terminate(&self, _timeout: Duration) -> Result<(), TraitError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    impl ProcessLauncher for RecordingLauncher {
        fn launch(&self, spec: &LaunchSpec) -> Result<Box<dyn LaunchedProcess>, TraitError> {
            self.specs
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(spec.clone());
            if self.fail {
                return Err(TraitError::new(ErrorCode::Internal, "launch failed"));
            }
            Ok(Box::new(FakeProcess(self.terminated.clone())))
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
            "linux": {"namespaces": [{"type": "pid"}, {"type": "mount"}]}
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
        let store = MemStateStore::new(false);
        create(&store, &OpRecorder::new(), &b.create_req("c1")).expect("create");
        (b, store)
    }

    /// create 後に config を差し替えて start し、エラーを返す（状態は Created のまま・launcher 0 回を確認）。
    fn start_rejected_after_rewrite(name: &str, cfg: &Value) -> TraitError {
        let (b, store) = created(name);
        b.write_config(cfg);
        let launcher = RecordingLauncher::new(false);
        let err = start(&store, &OpRecorder::new(), &launcher, &sid("c1")).expect_err("must fail");
        assert_eq!(launcher.calls(), 0);
        let got = store
            .get(&GetStateRequest::new(ContainerId::new("c1").expect("id")))
            .expect("stored");
        assert_eq!(got.status().state(), ContainerState::Created);
        err
    }

    /// OCI-4: start で `process.args` 等がそのまま launcher に渡り、Running・pid 付きへ遷移する。
    #[test]
    fn oci4_start_launches_process_args_and_transitions_to_running() {
        let (b, store) = created("ok");
        let before = store
            .get(&GetStateRequest::new(ContainerId::new("c1").expect("id")))
            .expect("get");
        let launcher = RecordingLauncher::new(false);
        let record = start(&store, &OpRecorder::new(), &launcher, &sid("c1")).expect("start");
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
            [NamespaceKind::Pid, NamespaceKind::Mount]
        );
    }

    /// CORE-2: create されていない ID の start は NotFound で、launcher は呼ばれない。
    #[test]
    fn core2_start_unknown_id_returns_not_found() {
        let store = MemStateStore::new(false);
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
        start(&store, &OpRecorder::new(), &launcher, &sid("c1")).expect("first");
        let err = start(&store, &OpRecorder::new(), &launcher, &sid("c1")).expect_err("second");
        assert_eq!(err.code(), ErrorCode::FailedPrecondition);
        assert_eq!(launcher.calls(), 1);
    }

    /// SEC-1: create 後に壊れた JSON へ書き換えられた config は start で拒否される（TOCTOU）。
    #[test]
    fn sec1_start_revalidates_malformed_config_after_create() {
        let (b, store) = created("rewrite-bad");
        std::fs::write(b.dir.join("config.json"), b"{ not json").expect("write");
        let launcher = RecordingLauncher::new(false);
        let err = start(&store, &OpRecorder::new(), &launcher, &sid("c1")).expect_err("fail");
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
        let err = start(&store, &OpRecorder::new(), &launcher, &sid("c1")).expect_err("fail");
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
        let store = MemStateStore::new(true);
        create(&store, &OpRecorder::new(), &b.create_req("c1")).expect("create");
        let launcher = RecordingLauncher::new(false);
        let err = start(&store, &OpRecorder::new(), &launcher, &sid("c1")).expect_err("fail");
        assert_eq!(err.code(), ErrorCode::FailedPrecondition);
        assert_eq!(launcher.calls(), 1);
        assert_eq!(launcher.terminations(), 1);
    }

    /// OCI-4: launcher 失敗はそのまま返り、状態は Created のまま。
    #[test]
    fn oci4_start_propagates_launcher_error_without_state_change() {
        let (_b, store) = created("launch-fail");
        let launcher = RecordingLauncher::new(true);
        let err = start(&store, &OpRecorder::new(), &launcher, &sid("c1")).expect_err("fail");
        assert_eq!(err.code(), ErrorCode::Internal);
        let got = store
            .get(&GetStateRequest::new(ContainerId::new("c1").expect("id")))
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
        start(&store, &rec, &launcher, &sid("c1")).expect("first");
        start(&store, &rec, &launcher, &sid("c1")).expect_err("second");
        let stats = rec
            .snapshot_op(&OpName::new("start").expect("name"))
            .expect("recorded");
        assert_eq!(stats.success(), 1);
        assert_eq!(stats.failure(), 1);
        assert!(stats.latency().is_some());
    }
}
