//! shim v2 バイナリ（`containerd-shim-fandhe-container-v2`）が登録するサービスの組み立て（CRI-5・CRI-7・PLUG-1・TASK-62.6・#3684）。
//!
//! 呼び出し元: `src/bin/containerd_shim_v2.rs` の main が [`production_registry`] を
//! `fandhe_container_cri::shim_v2::bootstrap::run_cli_with_context` の注入口として渡す。serve（常駐デーモン）のときだけ呼ばれる。
//! 本番の `ContainerRuntime`（[`crate::adapter::CoreLifecycleRuntime`]）は plugin-cri にしか無く、cri から plugin-cri への依存は
//! `crates/cri/tests/dependency_direction.rs` が禁じているため、bin の置き場所をここにした
//! （判断は `docs/design/shim-v2-production-binary.md`）。辺の向きは plugin-cri → cri・core の一方向のままで、core は変わらない（PLUG-4）。
//!
//! 組み立て（Linux）: 既定の状態ルート（`StateRoot::resolve(None)`。外部入力から受けない）の `FileStateStore` の上に
//! `CoreLifecycleRuntime` を作り、`RuntimeAdapter` で包んで `TaskService`（v2・v3。`with_shared_created` で共有）を登録する。
//! デーモンの監査の記録先（`ServeContext::audit_sink`）を `with_create_audit_sink` に渡し、create の `mounts[].destination` の拒否を
//! peer UID の拒否と同じ `@audit.log` へ残す（SEC-4）。
//!
//! インスタンスロック（`.cri/@instance.lock`）は取らない。shim は pod（コンテナ）ごとに 1 プロセスあり、plugin-cri とも状態ルートを
//! 共有するため、取ると 2 つ目の shim と plugin-cri を締め出す。shim は回収記録・CRI 記録・在庫を持たないのでロックが守る対象も無い。
//! 並行の制御は core の `StateStore` の `@lock` に任せる（CLI と同じ前提）。
//!
//! 前提: rootless のみ。uid 0（rootful の containerd と、rootlesskit 配下で euid が 0 になる shim）の `start` は plugin-cri の
//! `supervised` と同じく `UNIMPLEMENTED`（#2442・#2241）。supervisor は shim の実体と同じディレクトリの固定名から解決する。
//!
//! 未実装（REPAIR-3）: 非 Linux（macOS は既定の状態ルートが未決定で #2431、`start`・`kill`・`stop` も `Unimplemented`）は Shutdown だけの
//! `EmptyTaskService` を登録する。exec の起動役（`TaskExecLauncher`）の本番実装は無く exec は `UNIMPLEMENTED`。`delete` action での
//! 実行層の後始末と `-publish-binary` のイベント publish も未実装。

use fandhe_container_cri::error::CriError;
use fandhe_container_cri::shim_v2::ServiceRegistry;
use fandhe_container_cri::shim_v2::bootstrap::ServeContext;

/// 本番の登録簿を作る。失敗は固定語彙の `CriError` で返す（パスや状態の中身は含めない。REPAIR-4）。
pub fn production_registry(ctx: ServeContext) -> Result<ServiceRegistry, CriError> {
    #[cfg(target_os = "linux")]
    {
        let root = fandhe_container_core::state_store::StateRoot::resolve(None)
            .map_err(|_| CriError::internal("cannot resolve the state root"))?;
        registry_in(root, ctx)
    }
    #[cfg(not(target_os = "linux"))]
    {
        empty_registry(ctx)
    }
}

/// 状態ルートを引数で受ける内側の関数（試験が一時ディレクトリの状態ルートで呼ぶ）。
#[cfg(target_os = "linux")]
pub(crate) fn registry_in(
    root: fandhe_container_core::state_store::StateRoot,
    ctx: ServeContext,
) -> Result<ServiceRegistry, CriError> {
    use std::sync::Arc;

    use fandhe_container_core::observability::OpRecorder;
    use fandhe_container_core::state_store::FileStateStore;
    use fandhe_container_core::traits::StateStore;
    use fandhe_container_cri::adapter::RuntimeAdapter;
    use fandhe_container_cri::shim_v2::{TaskApiVersion, TaskService};

    use crate::adapter::CoreLifecycleRuntime;

    let state: Arc<dyn StateStore> = Arc::new(
        FileStateStore::open(root)
            .map_err(|_| CriError::internal("cannot open the state store"))?,
    );
    let mut runtime = CoreLifecycleRuntime::with_recorder(state, Arc::new(OpRecorder::new()));
    if let Some(sink) = ctx.audit_sink() {
        runtime = runtime.with_create_audit_sink(sink);
    }
    let adapter = RuntimeAdapter::new(Arc::new(runtime));
    let v2 =
        TaskService::new(TaskApiVersion::V2, adapter.clone()).with_shutdown(ctx.shutdown().clone());
    let v3 = TaskService::new(TaskApiVersion::V3, adapter)
        .with_shutdown(ctx.shutdown().clone())
        .with_shared_created(&v2);
    let mut reg = ServiceRegistry::new();
    for svc in [Arc::new(v2), Arc::new(v3)] {
        reg.register(svc)
            .map_err(|_| CriError::internal("cannot register task service"))?;
    }
    Ok(reg)
}

/// Shutdown だけを処理する登録簿（非 Linux の縮退。REPAIR-3）。
#[cfg(not(target_os = "linux"))]
fn empty_registry(ctx: ServeContext) -> Result<ServiceRegistry, CriError> {
    use std::sync::Arc;

    use fandhe_container_cri::shim_v2::{EmptyTaskService, TaskApiVersion};

    let mut reg = ServiceRegistry::new();
    for v in [TaskApiVersion::V2, TaskApiVersion::V3] {
        reg.register(Arc::new(
            EmptyTaskService::new(v).with_shutdown(ctx.shutdown().clone()),
        ))
        .map_err(|_| CriError::internal("cannot register task service"))?;
    }
    Ok(reg)
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use fandhe_container_core::state_store::StateRoot;
    use fandhe_container_cri::shim_v2::{ShutdownSignal, TtrpcRequest};

    use crate::test_root;

    const NOT_FOUND: i32 = 5;
    const SERVICES: [&str; 2] = ["containerd.task.v2.Task", "containerd.task.v3.Task"];

    fn request(service: &str, method: &str, payload: Vec<u8>) -> TtrpcRequest {
        TtrpcRequest {
            service: service.into(),
            method: method.into(),
            payload,
            ..Default::default()
        }
    }

    /// `{ string id = 1; }` を手で組む（State・Kill の要求の先頭欄）。
    fn id_payload(id: &str) -> Vec<u8> {
        let mut b = vec![0x0a, id.len() as u8];
        b.extend_from_slice(id.as_bytes());
        b
    }

    fn registry(dir: &std::path::Path) -> (ServiceRegistry, ShutdownSignal) {
        let root = StateRoot::resolve(Some(dir.to_path_buf())).expect("state root");
        let signal = ShutdownSignal::new();
        let reg = registry_in(root, ServeContext::new(signal.clone(), None)).expect("registry");
        (reg, signal)
    }

    /// CRI-5・CRI-7・#3684: 登録簿は `EmptyTaskService`（State が UNIMPLEMENTED=12）ではなく本番の `TaskService` で、
    /// 未知の id の State と Kill は NOT_FOUND(5) になる。
    #[test]
    fn cri5_3684_registry_reaches_state_and_kill() {
        let guard = test_root::test_root("shim", "registry");
        let (reg, _signal) = registry(&guard.join("state"));
        for svc in SERVICES {
            for method in ["State", "Kill"] {
                let mut payload = id_payload("nope");
                if method == "Kill" {
                    // signal = 9（0 は InvalidArgument で NOT_FOUND に届かない）。
                    payload.extend_from_slice(&[0x18, 0x09]);
                }
                let resp = reg.dispatch(&request(svc, method, payload));
                let status = resp.status.expect("status must be set");
                assert_eq!(status.code, NOT_FOUND, "{svc} {method}");
            }
        }
    }

    /// CRI-5・TASK-62.7.2・#3684: コンテナが無い状態の Shutdown は終了要求を立てる。
    #[test]
    fn cri5_3684_shutdown_requests_exit() {
        let guard = test_root::test_root("shim", "shutdown");
        let (reg, signal) = registry(&guard.join("state"));
        let resp = reg.dispatch(&request(SERVICES[0], "Shutdown", id_payload("nope")));
        assert!(resp.status.is_none(), "{:?}", resp.status);
        assert!(signal.wait_timeout(std::time::Duration::from_secs(5)));
    }
}
