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
//! delete action の前段（#4151・CRI-5・SEC-1・REPAIR-3・REPAIR-4）: [`production_delete_preflight`] を bootstrap の注入口
//! （`run_cli_with_hooks`）へ渡し、`-id`・`-bundle` の検証（[`validate_delete_invocation`]）と、serve が使う状態ルートの記録との照合
//! （`delete_preflight_in`・[`match_delete_record`]）を行う。照合は読み取りだけで、状態ルートの作成・書き込み・シグナル・
//! プロセス起動をしない。結果は [`DeleteRecordMatch`]（記録なし・記録あり・回収済み）で、停止・回収（#4152）が受け取って使う。
//! 本 PR の bin は結果を捨てる（検証と照合の失敗だけが delete を止める）。判断は `docs/design/shim-v2-production-binary.md` D5。
//!
//! 未実装（REPAIR-3）: 非 Linux（macOS は既定の状態ルートが未決定で #2431、`start`・`kill`・`stop` も `Unimplemented`）は Shutdown だけの
//! `EmptyTaskService` を登録する。exec の起動役（`TaskExecLauncher`）の本番実装は無く exec は `UNIMPLEMENTED`。`delete` action での
//! 実行層の後始末（停止・回収・終了状態の応答。#4152）も未実装。`-publish-binary` による TaskCreate・TaskStart・TaskDelete・TaskExit の publish は実装済み（#4155・#4156）。非 Linux の delete は
//! 引数の検証だけで、記録の照合はしない（既定の状態ルートが未決定で #2431）。

use std::path::{Path, PathBuf};

use fandhe_container_core::traits::{
    ContainerId, ErrorCode, GetStateRequest, StateRecord, StateStore,
};
use fandhe_container_cri::error::CriError;
use fandhe_container_cri::shim_v2::ServiceRegistry;
use fandhe_container_cri::shim_v2::bootstrap::{ServeContext, ShimInvocation};

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
/// 置き場所は既定の状態ルート `base` の中ではなく兄弟（`<base>-shim-state/<address のハッシュ>/<namespace>`）にする。bootstrap の socket ディレクトリ（`<base>-shim`。`SOCKET_DIR_NAME`）とは別名にし、状態が ttrpc socket・`.lock`・ログと同居しないようにする。`base` 直下に
/// 置くと途中の要素が有効な `ContainerId` と衝突し、`FileStateStore::list` が fail-closed で失敗して CLI・plugin-cri が
/// `base` を開けなくなるため。途中の各階層は 1 つずつ 0700 で作り、既存の階層も symlink でなく他者が触れない権限であることを確かめる。
/// namespace は検証済みの identifier（英数字と `._-`）なのでパス要素として安全で、address は FNV-1a の 16 桁 16 進に潰す。
/// namespace が無い（containerd 以外の起動）ときは分けない。
#[cfg(target_os = "linux")]
pub(crate) fn scoped_root(
    base: &std::path::Path,
    ctx: &ServeContext,
) -> Result<fandhe_container_core::state_store::StateRoot, CriError> {
    let path = scoped_root_path(base, ctx.namespace(), ctx.address())?;
    if ctx.namespace().is_some() {
        // `FileStateStore::open` は最後の 1 階層しか作らないため、親をここで 1 階層ずつ 0700 で作る。最後の要素はストアの検査が確かめる。
        let hashed = path.parent();
        let sibling = hashed.and_then(std::path::Path::parent);
        for dir in [sibling, hashed].into_iter().flatten() {
            ensure_private_dir(dir)?;
        }
    }
    fandhe_container_core::state_store::StateRoot::from_override(path)
        .map_err(|_| CriError::internal("cannot resolve the state root"))
}

/// [`scoped_root`] の場所の計算だけ（何も作らない純粋関数。#4151）。
///
/// serve は [`scoped_root`] で作りながら使い、delete の前段は同じ式でこの関数が返す場所を読み取りだけで開く。
/// 計算を 1 か所に置くのは、2 つの経路で場所がずれて別の記録を見ないようにするため（CRI-5）。
/// `namespace` が無いときは `base` をそのまま返す。
#[cfg(target_os = "linux")]
pub(crate) fn scoped_root_path(
    base: &Path,
    namespace: Option<&fandhe_container_cri::shim_v2::bootstrap::ShimIdentifier>,
    address: Option<&Path>,
) -> Result<PathBuf, CriError> {
    use std::os::unix::ffi::OsStrExt;

    let Some(ns) = namespace else {
        return Ok(base.to_path_buf());
    };
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    if let Some(a) = address {
        for b in a.as_os_str().as_bytes() {
            h ^= u64::from(*b);
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
    }
    let (Some(parent), Some(name)) = (base.parent(), base.file_name()) else {
        return Err(CriError::internal("cannot resolve the state root"));
    };
    let mut sibling = name.to_os_string();
    sibling.push("-shim-state");
    Ok(parent
        .join(sibling)
        .join(format!("{h:016x}"))
        .join(ns.as_str()))
}

/// `dir` を 0700 で作る（既存ならそのまま）。symlink・非ディレクトリ・グループ / その他に開いた権限は拒否する（SEC-1）。
#[cfg(target_os = "linux")]
fn ensure_private_dir(dir: &Path) -> Result<(), CriError> {
    use std::os::unix::fs::DirBuilderExt;

    match std::fs::DirBuilder::new().mode(0o700).create(dir) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(_) => return Err(CriError::internal("cannot create the state root")),
    }
    let md = std::fs::symlink_metadata(dir)
        .map_err(|_| CriError::internal("cannot create the state root"))?;
    check_private_dir(&md)
}

/// 状態ルートの階層の基準（ディレクトリである・symlink でない・group / other に権限が無い）。
/// serve の作成（[`ensure_private_dir`]）と delete の読み取り専用の検査が共有する（SEC-1・#4151）。
#[cfg(target_os = "linux")]
fn check_private_dir(md: &std::fs::Metadata) -> Result<(), CriError> {
    use std::os::unix::fs::PermissionsExt;

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
    // イベント 4 種の送り先（`-publish-binary` が無ければ `None`。cri 側が `disabled` を記録する。CRI-5・#4155・#4156）。
    let publisher = fandhe_container_cri::shim_v2::publish::exec_publisher_for(&ctx);
    let mut v2 =
        TaskService::new(TaskApiVersion::V2, adapter.clone()).with_shutdown(ctx.shutdown().clone());
    let mut v3 = TaskService::new(TaskApiVersion::V3, adapter)
        .with_shutdown(ctx.shutdown().clone())
        .with_shared_created(&v2);
    if let Some(p) = publisher {
        v2 = v2.with_event_publisher(Arc::clone(&p));
        v3 = v3.with_event_publisher(p);
    }
    let mut reg = ServiceRegistry::new();
    for svc in [Arc::new(v2), Arc::new(v3)] {
        reg.register(svc)
            .map_err(|_| CriError::internal("cannot register task service"))?;
    }
    Ok(reg)
}

/// delete action の入口で検証済みの対象（CRI-5・SEC-1・#4151）。
///
/// [`validate_delete_invocation`] だけが作る。`bundle` は区切りの重複や末尾の区切りを畳んだ値で、`.`・`..` の要素と symlink
/// （末尾の要素）を含まないことと、末尾の要素が `id` と一致することを確かめてある。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeleteTarget {
    id: ContainerId,
    bundle: PathBuf,
}

impl DeleteTarget {
    /// 検証済みのコンテナ ID。
    pub fn id(&self) -> &ContainerId {
        &self.id
    }

    /// 検証済みの bundle の絶対パス。
    pub fn bundle(&self) -> &Path {
        &self.bundle
    }
}

/// delete の対象と状態ルートの記録との照合結果（副作用なしで得る。REPAIR-4・#4151）。
///
/// 停止・回収（#4152）がこの値を受け取り、`Recorded` のときだけ実行層に触れる。`NotRecorded` と `AlreadyReclaimed` は
/// どちらも副作用 0 回で成功させる想定で、挙動は変わらない。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DeleteRecordMatch {
    /// 記録なし: この (address, namespace) の状態ルートが無い、または一度もロックつきの操作が行われていない。
    NotRecorded,
    /// 記録あり: 状態（Creating・Created・Running・Stopped のいずれか）・pid・終了情報・revision・cgroup 配置を持つ記録そのもの。
    /// id と bundle は対象と一致することを確かめてある。止める・消すの判断は呼び出し側が記録の状態で行う。
    Recorded(Box<StateRecord>),
    /// 回収済み: 状態ルートとストアはあるが、この id の記録が無い。
    ///
    /// `StateStore` に tombstone は無く、`get` は「一度も作られなかった」と「削除済み」を共に `NotFound` で返すため、
    /// 両者を区別できない（区別できるように装わない。REPAIR-3）。
    AlreadyReclaimed,
}

/// 検証失敗の文言は固定の英語で、パスや記録の中身を含めない（REPAIR-4・SEC-1）。
fn bad_bundle(msg: &'static str) -> CriError {
    CriError::invalid_argument(msg)
}

/// 区切りで分けた要素のどれかが `.` か `..` か。`Path::components` は途中の `.` を畳むため、字面で見る。
fn has_dot_segment(p: &Path) -> bool {
    p.as_os_str()
        .as_encoded_bytes()
        .split(|b| *b == b'/' || (cfg!(windows) && *b == b'\\'))
        .any(|seg| seg == b"." || seg == b"..")
}

/// delete の `-id`・`-bundle` を検証する（副作用は `lstat` だけ。全 OS 共通。CRI-5・SEC-1・#4151）。
///
/// 呼び出し元は [`production_delete_preflight`]。`-id` は core の `ContainerId` に通す（`parse_args` の identifier 規則より緩い
/// ので多層防御）。`-bundle` は containerd v2.1.4 の `core/runtime/v2/bundle.go` が `<state>/<namespace>/<id>` で組むため、
/// 絶対パスで、`.`・`..` を含まず、末尾の要素が id と一致し、末尾の要素が実在するディレクトリ（symlink でない）であることを求める。
/// 親の namespace との一致は見ない（記録の bundle との照合の方が強く、state の配置が変わったときに正当な呼び出しを拒否する危険を増やすだけ）。
/// 祖先の symlink は許す（macOS の `/tmp` など）。bundle の中身は読まない。
pub fn validate_delete_invocation(inv: &ShimInvocation) -> Result<DeleteTarget, CriError> {
    let id = inv
        .id
        .as_ref()
        .ok_or_else(|| CriError::invalid_argument("id is required for delete"))?;
    let id = ContainerId::new(id.as_str())
        .map_err(|_| CriError::invalid_argument("id is not a valid container id"))?;
    let raw = inv
        .bundle
        .as_deref()
        .ok_or_else(|| bad_bundle("bundle is required for delete"))?;
    if !raw.is_absolute() {
        return Err(bad_bundle("bundle must be an absolute path"));
    }
    if has_dot_segment(raw) {
        return Err(bad_bundle("bundle must not contain dot segments"));
    }
    // 区切りの重複と末尾の区切りを畳む（`link/` が `lstat` で symlink を辿るのを避ける）。
    let bundle: PathBuf = raw.components().collect();
    if bundle.file_name() != Some(std::ffi::OsStr::new(id.as_str())) {
        return Err(bad_bundle("bundle must end with the container id"));
    }
    match std::fs::symlink_metadata(&bundle) {
        Ok(md) if md.file_type().is_symlink() => {
            return Err(bad_bundle("bundle must not be a symlink"));
        }
        Ok(md) if !md.is_dir() => return Err(bad_bundle("bundle must be a directory")),
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(bad_bundle("bundle does not exist"));
        }
        Err(_) => return Err(CriError::internal("cannot stat bundle")),
    }
    Ok(DeleteTarget { id, bundle })
}

/// 状態ストアの記録を `get` だけで引き、対象と照合して分類する（書き込み・シグナル・プロセス起動をしない。#4151）。
///
/// 記録の id が対象と食い違えばストアの不整合として `INTERNAL`、記録の bundle が `-bundle` と食い違えば別のコンテナの記録を
/// 回収しないよう `FAILED_PRECONDITION` で拒否する（`Path` の比較は区切りの重複・末尾の区切りを無視する）。
/// 読み取りの期限切れは `DEADLINE_EXCEEDED`、その他の失敗は固定文言の `INTERNAL`（fail-closed。黙って成功扱いにしない）。
pub fn match_delete_record(
    store: &dyn StateStore,
    target: &DeleteTarget,
) -> Result<DeleteRecordMatch, CriError> {
    match store.get(&GetStateRequest::new(target.id.clone())) {
        Ok(rec) => {
            if rec.status().id() != &target.id {
                return Err(CriError::internal("state store is inconsistent"));
            }
            if rec.bundle() != target.bundle {
                return Err(CriError::failed_precondition(
                    "bundle does not match the recorded container",
                ));
            }
            Ok(DeleteRecordMatch::Recorded(Box::new(rec)))
        }
        Err(e) => match e.code() {
            ErrorCode::NotFound => Ok(DeleteRecordMatch::AlreadyReclaimed),
            ErrorCode::Timeout => Err(CriError::timeout("timed out reading the state store")),
            _ => Err(CriError::internal("cannot read the state record")),
        },
    }
}

/// serve が使う状態ルートを、何も作らず書かずに開く（delete の前段用。Linux のみ。#4151）。
///
/// `Ok(None)` は記録が存在しえないこと: 階層のどれかが無い、または `@lock` が無くコンテナのエントリも無い（ストアで一度も
/// ロックつきの操作が行われていない）。階層が symlink・非ディレクトリ・group / other に開いた権限なら拒否する（SEC-1）。
/// `@lock` が無いのにコンテナのエントリがあるのは不整合として拒否する。`@lock` があるときは `FileStateStore::open` を使うが、
/// 既にエントリがあるルートでは作成も初期化もせず、`get` は既存の `@lock` を flock するだけ（試験で木が変わらないことを照合）。
#[cfg(target_os = "linux")]
fn open_scoped_store_read_only(
    base: &Path,
    namespace: &fandhe_container_cri::shim_v2::bootstrap::ShimIdentifier,
    address: &Path,
) -> Result<Option<fandhe_container_core::state_store::FileStateStore>, CriError> {
    use fandhe_container_core::state_store::{FileStateStore, StateRoot};

    let root = scoped_root_path(base, Some(namespace), Some(address))?;
    let hashed = root.parent();
    let sibling = hashed.and_then(Path::parent);
    for dir in [sibling, hashed, Some(root.as_path())]
        .into_iter()
        .flatten()
    {
        match std::fs::symlink_metadata(dir) {
            Ok(md) => check_private_dir(&md)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(CriError::internal("cannot stat the state root")),
        }
    }
    match std::fs::symlink_metadata(root.join("@lock")) {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let entries = std::fs::read_dir(&root)
                .map_err(|_| CriError::internal("cannot read the state root"))?;
            for entry in entries {
                let entry = entry.map_err(|_| CriError::internal("cannot read the state root"))?;
                if !entry.file_name().to_string_lossy().starts_with('@') {
                    return Err(CriError::internal("state store is inconsistent"));
                }
            }
            return Ok(None);
        }
        Err(_) => return Err(CriError::internal("cannot stat the state root")),
    }
    let root = StateRoot::from_override(root)
        .map_err(|_| CriError::internal("cannot resolve the state root"))?;
    FileStateStore::open(root)
        .map(Some)
        .map_err(|_| CriError::internal("cannot open the state store"))
}

/// delete の前段の本体を、状態ルートの基底（`StateRoot::resolve(None)` の結果）を引数で受けて行う（試験が一時ディレクトリで呼ぶ。#4151）。
///
/// 引数の検証 → 状態ルートの記録の照合の順で、副作用は無い。`-namespace`・`-address` は `parse_args` が delete に必須としている。
#[cfg(target_os = "linux")]
pub(crate) fn delete_preflight_in(
    inv: &ShimInvocation,
    base: &Path,
) -> Result<DeleteRecordMatch, CriError> {
    let target = validate_delete_invocation(inv)?;
    let (Some(ns), Some(addr)) = (inv.namespace.as_ref(), inv.address.as_deref()) else {
        return Err(CriError::invalid_argument(
            "namespace and address are required for delete",
        ));
    };
    match open_scoped_store_read_only(base, ns, addr)? {
        None => Ok(DeleteRecordMatch::NotRecorded),
        Some(store) => match_delete_record(&store, &target),
    }
}

/// bootstrap の delete の前段（`run_cli_with_hooks` の `before_delete`）として渡す本番の実装（CRI-5・SEC-1・#4151）。
///
/// Linux は既定の状態ルート（`StateRoot::resolve(None)`。外部入力から受けない）で、引数の検証の後に記録を照合する。
/// 結果の [`DeleteRecordMatch`] は本 PR では使わず捨てる（停止・回収は #4152。REPAIR-3）。非 Linux は引数の検証だけで、
/// 既定の状態ルートが未決定（#2431）のため照合は縮退する。
pub fn production_delete_preflight(inv: &ShimInvocation) -> Result<(), CriError> {
    #[cfg(target_os = "linux")]
    {
        let base = fandhe_container_core::state_store::StateRoot::resolve(None)
            .map_err(|_| CriError::internal("cannot resolve the state root"))?;
        delete_preflight_in(inv, base.path()).map(drop)
    }
    #[cfg(not(target_os = "linux"))]
    {
        validate_delete_invocation(inv).map(drop)
    }
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
        assert!(a.path().starts_with(guard.join("state-shim-state")));
        // 既定の状態ルート（base）の中に何も作らない（途中要素が ContainerId と衝突しない）。
        assert!(!base.exists());
        let mode = |p: &std::path::Path| {
            use std::os::unix::fs::PermissionsExt;
            std::fs::metadata(p).unwrap().permissions().mode() & 0o777
        };
        assert_eq!(mode(&guard.join("state-shim-state")), 0o700);
        assert_eq!(mode(a.path().parent().unwrap()), 0o700);
        assert!(a.path().ends_with("ns-a"));
    }

    /// CRI-5・#3684: 既定の状態ルート名 `fandhe-container` でも、状態の置き場所が bootstrap の socket ディレクトリと
    /// 同一にならず、一方が他方の配下にもならない。
    #[test]
    fn cri5_3684_scoped_root_distinct_from_socket_dir() {
        use fandhe_container_cri::shim_v2::bootstrap::SOCKET_DIR_NAME;
        let guard = test_root::test_root("shim", "sockdir");
        let base = guard.join("fandhe-container");
        let ctx = ServeContext::new(ShutdownSignal::new(), None).with_origin(
            Some(fandhe_container_cri::shim_v2::bootstrap::ShimIdentifier::parse("ns1").unwrap()),
            Some(std::path::PathBuf::from("/run/c.sock")),
        );
        let root = scoped_root(&base, &ctx).unwrap();
        let sock_dir = guard.join(SOCKET_DIR_NAME);
        assert_ne!(root.path(), sock_dir.as_path());
        assert!(!root.path().starts_with(&sock_dir));
        assert!(!sock_dir.starts_with(root.path()));
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

#[cfg(all(test, target_os = "linux"))]
mod delete_tests;
