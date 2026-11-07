//! shim v2 バイナリ（`containerd-shim-fandhe-container-v2`）が登録するサービスの組み立て（CRI-5・CRI-7・PLUG-1・TASK-62.6・#3684）。
//!
//! 呼び出し元: `src/bin/containerd_shim_v2.rs` の main が [`production_registry`] を
//! `fandhe_container_cri::shim_v2::bootstrap::run_cli_with_context` の注入口として渡す。serve（常駐デーモン）のときだけ呼ばれる。
//! 本番の `ContainerRuntime`（[`crate::adapter::CoreLifecycleRuntime`]）は plugin-cri にしか無く、cri から plugin-cri への依存は
//! `crates/cri/tests/dependency_direction.rs` が禁じているため、bin の置き場所をここにした
//! （判断は `docs/design/shim-v2-production-binary.md`）。辺の向きは plugin-cri → cri・core の一方向のままで、core は変わらない（PLUG-4）。
//!
//! 組み立て（Linux）: 既定の状態ルート（`StateRoot::resolve(None)`。外部入力から受けない）の下を containerd の address・namespace ごとに分けた（`scoped_root`。状態ルートの兄弟に置く） `FileStateStore` の上に
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
        let base = fandhe_container_core::state_store::StateRoot::resolve(None)
            .map_err(|_| CriError::internal("cannot resolve the state root"))?;
        let root = scoped_root(base.path(), &ctx)?;
        registry_in(root, ctx)
    }
    #[cfg(not(target_os = "linux"))]
    {
        empty_registry(ctx)
    }
}

/// containerd の address と namespace ごとに分けた状態ルートを返す（CRI-5・#3684）。
///
/// bootstrap の socket は address・namespace・ID ごとに分かれるため、状態も同じ粒度で分ける。分けないと、同一ユーザーが
/// 別 namespace で同じ ID を作ったときに状態が衝突し、別 shim の State・Kill・Delete が同じ記録を参照できてしまう。
/// 置き場所は既定の状態ルート `base` の中ではなく兄弟（`<base>-shim/<address のハッシュ>/<namespace>`）にする。`base` 直下に
/// 置くと途中の要素が有効な `ContainerId` と衝突し、`FileStateStore::list` が fail-closed で失敗して CLI・plugin-cri が
/// `base` を開けなくなるため。途中の各階層は 1 つずつ 0700 で作り、既存の階層も symlink でなく他者が触れない権限であることを確かめる。
/// namespace は検証済みの identifier（英数字と `._-`）なのでパス要素として安全で、address は FNV-1a の 16 桁 16 進に潰す。
/// namespace が無い（containerd 以外の起動）ときは分けない。
#[cfg(target_os = "linux")]
pub(crate) fn scoped_root(
    base: &std::path::Path,
    ctx: &ServeContext,
) -> Result<fandhe_container_core::state_store::StateRoot, CriError> {
    use std::os::unix::ffi::OsStrExt;

    let Some(ns) = ctx.namespace() else {
        return fandhe_container_core::state_store::StateRoot::from_override(base.to_path_buf())
            .map_err(|_| CriError::internal("cannot resolve the state root"));
    };
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    if let Some(a) = ctx.address() {
        for b in a.as_os_str().as_bytes() {
            h ^= u64::from(*b);
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
    }
    let (Some(parent), Some(name)) = (base.parent(), base.file_name()) else {
        return Err(CriError::internal("cannot resolve the state root"));
    };
    let mut sibling = name.to_os_string();
    sibling.push("-shim");
    let hashed = parent.join(sibling).join(format!("{h:016x}"));
    // `FileStateStore::open` は最後の 1 階層しか作らないため、親をここで 1 階層ずつ 0700 で作る。最後の要素はストアの検査が確かめる。
    for dir in [hashed.parent().unwrap_or(parent), hashed.as_path()] {
        ensure_private_dir(dir)?;
    }
    fandhe_container_core::state_store::StateRoot::from_override(hashed.join(ns.as_str()))
        .map_err(|_| CriError::internal("cannot resolve the state root"))
}

/// `dir` を 0700 で作る（既存ならそのまま）。symlink・非ディレクトリ・グループ / その他に開いた権限は拒否する（SEC-1）。
#[cfg(target_os = "linux")]
fn ensure_private_dir(dir: &std::path::Path) -> Result<(), CriError> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

    match std::fs::DirBuilder::new().mode(0o700).create(dir) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(_) => return Err(CriError::internal("cannot create the state root")),
    }
    let md = std::fs::symlink_metadata(dir)
        .map_err(|_| CriError::internal("cannot create the state root"))?;
    if !md.is_dir() || md.permissions().mode() & 0o077 != 0 {
        return Err(CriError::internal("state root directory is not private"));
    }
    Ok(())
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

    /// CRI-5・#3684: namespace が違えば状態ルートが分かれ、同じ ID の State が互いに見えない。
    #[test]
    fn cri5_3684_namespaces_have_separate_state_roots() {
        let guard = test_root::test_root("shim", "ns-roots");
        let base = guard.join("state");
        let mk = |ns: &str, addr: &str| {
            ServeContext::new(ShutdownSignal::new(), None).with_origin(
                Some(fandhe_container_cri::shim_v2::bootstrap::ShimIdentifier::parse(ns).unwrap()),
                Some(std::path::PathBuf::from(addr)),
            )
        };
        let a = scoped_root(&base, &mk("ns-a", "/run/c.sock")).unwrap();
        let b = scoped_root(&base, &mk("ns-b", "/run/c.sock")).unwrap();
        let c = scoped_root(&base, &mk("ns-a", "/run/d.sock")).unwrap();
        assert_ne!(a.path(), b.path());
        assert_ne!(a.path(), c.path());
        assert!(a.path().starts_with(guard.join("state-shim")));
        // 既定の状態ルート（base）の中に何も作らない（途中要素が ContainerId と衝突しない）。
        assert!(!base.exists());
        let mode = |p: &std::path::Path| {
            use std::os::unix::fs::PermissionsExt;
            std::fs::metadata(p).unwrap().permissions().mode() & 0o777
        };
        assert_eq!(mode(&guard.join("state-shim")), 0o700);
        assert_eq!(mode(a.path().parent().unwrap()), 0o700);
        assert!(a.path().ends_with("ns-a"));
    }

    /// CRI-5・#3684: 分けた状態ルート（親ディレクトリが未作成）でも登録簿が開ける。
    #[test]
    fn cri5_3684_scoped_root_opens_registry() {
        let guard = test_root::test_root("shim", "scoped");
        let ctx = ServeContext::new(ShutdownSignal::new(), None).with_origin(
            Some(fandhe_container_cri::shim_v2::bootstrap::ShimIdentifier::parse("ns1").unwrap()),
            Some(std::path::PathBuf::from("/run/c.sock")),
        );
        let root = scoped_root(&guard.join("state"), &ctx).unwrap();
        let reg = registry_in(root, ctx).expect("registry");
        let resp = reg.dispatch(&request(SERVICES[0], "State", id_payload("nope")));
        assert_eq!(resp.status.expect("status").code, NOT_FOUND);
    }
}
