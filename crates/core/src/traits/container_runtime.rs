//! `ContainerRuntime` 拡張点トレイト（TASK-4.1・CRI-7・PLUG-1）。
//!
//! CRI サーバー層（`fandhe-container-cri`）・将来の containerd shim v2（CRI-5）は、
//! この内部トレイトを呼ぶアダプタとなる想定（PoC-7 の原案）。実装は本 crate には置かず、
//! 別プロセス plugin（`fandhe-container-plugin-cri` 等。TASK-114）が担い、core 側の
//! proxy（G8・TASK-107/114）が UDS＋長さ接頭辞フレームの RPC へ変換して
//! `Box<dyn ContainerRuntime>` として呼び出し側へ渡す（PLUG-1）。
//!
//! シグネチャは人間のアーキテクチャレビュー（#19・TASK-4.h1）前の暫定版であり、
//! 「確認済み」の確定仕様ではない。

use std::num::{NonZeroU8, NonZeroU32};
use std::path::{Path, PathBuf};
use std::time::Duration;

use super::types::{ContainerId, ErrorCode, TraitError};

/// コンテナのライフサイクル（create/start/kill/stop/delete/state）を抽象化する拡張点。
///
/// # 契約
/// 1. 実装は panic せず、すべての結果を `Result` で返す（coding-rust.md）。
/// 2. 相手の応答を待つ処理（plugin RPC・子プロセスの起動確認等）は無期限に待たず、
///    上限時間を超えたら [`ErrorCode::Timeout`] を返す（REPAIR-5）。既定タイムアウト値の
///    決定は proxy 実装（G8・TASK-107/114）の責務であり、本トレイトは契約のみを定める。
/// 3. `Send + Sync` を要求する。呼び出し側は `Arc<dyn ContainerRuntime>` として複数スレッド
///    から共有できることを前提にしてよい。
/// 4. 本 crate（core）にはこのトレイトの実装を置かない。実装は plugin 側にある
///    （PLUG-1・TASK-114）。「実装済みを装わない」という REPAIR-3 の方針に基づく。
/// 5. plugin の信頼境界（UDS の所有者・権限検証、別 UID からの接続切断等。PLUG-11・PLUG-12）
///    はこのトレイトの外側、境界機構（`fandhe-container-plugin`）の責務であり、
///    `ContainerRuntime` の呼び出し側はそれらが検証済みであることを前提にしてよい。
///
/// メソッドは同期（`&self`、`async fn` を使わない）にし、ジェネリクスも持たない。
/// CRI-7 の呼び出し側はトレイト境界だけを通って `Box<dyn ContainerRuntime>` を扱うため、
/// dyn 互換（object safety）を保つ必要がある。async ランタイムへの依存を追加しない
/// （依存最小方針。dependency-policy.md）。
pub trait ContainerRuntime: Send + Sync {
    /// OCI bundle からコンテナを作成する（状態は [`ContainerState::Created`] になる）。
    ///
    /// 前提: 同じ [`ContainerId`] のコンテナが存在しないこと。存在する場合は
    /// [`ErrorCode::AlreadyExists`] を返す。対応: CORE-2・ERR-2。
    fn create(&self, req: &CreateRequest) -> Result<ContainerStatus, TraitError>;

    /// `created` 状態のコンテナでユーザープロセスを開始する（状態は `Running` になる）。
    ///
    /// 前提: 対象コンテナが `created` 状態であること。そうでなければ
    /// [`ErrorCode::FailedPrecondition`] を返す。対応: CORE-2・ERR-2。
    fn start(&self, req: &StartRequest) -> Result<ContainerStatus, TraitError>;

    /// 実行中のコンテナへシグナルを送る。プロセスの終了は待たない。
    ///
    /// 前提: 対象コンテナが存在すること。存在しなければ [`ErrorCode::NotFound`] を返す。
    /// 対応: CORE-2・ERR-2。
    fn kill(&self, req: &KillRequest) -> Result<ContainerStatus, TraitError>;

    /// SIGTERM を送り、猶予時間（[`StopRequest::grace`]）を過ぎたら SIGKILL で強制停止する。
    ///
    /// CLI の `stop` サブコマンド（CLI-1）と CRI `StopContainer` に対応する。
    /// 猶予は呼び出し側が明示し、無期限には待たない（REPAIR-5）。
    fn stop(&self, req: &StopRequest) -> Result<ContainerStatus, TraitError>;

    /// 停止済みコンテナの資源を解放する。`force` 指定時は実行中でも停止してから削除する。
    ///
    /// 前提: `force` が false の場合、対象コンテナが停止済みであること。実行中であれば
    /// [`ErrorCode::FailedPrecondition`] を返す。対応: CORE-2・ERR-2。
    fn delete(&self, req: &DeleteRequest) -> Result<DeleteResponse, TraitError>;

    /// コンテナの現在状態を照会する。
    ///
    /// 前提: 対象コンテナが存在すること。存在しなければ [`ErrorCode::NotFound`] を返す。
    /// 対応: CORE-2・ERR-2。
    fn state(&self, req: &StateRequest) -> Result<ContainerStatus, TraitError>;
}

/// Linux のシグナル番号（`kill`/`stop` で使う）。
///
/// Linux の番号体系をそのまま使う。macOS / Windows ホストでも、コンテナ本体はゲストの
/// Linux VM 内で動作する前提のため（OCI-5 の (4)）、シグナル番号は OS 分岐を持たない。
/// `SIGTERM`（15）・`SIGKILL`（9）は x86_64 / aarch64 で共通の値である。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Signal(NonZeroU8);

impl Signal {
    /// プロセスの正常終了を要求するシグナル（15）。
    pub const SIGTERM: Signal = Signal(NonZeroU8::new(15).expect("15 is nonzero"));
    /// プロセスを即座に強制終了させるシグナル（9）。
    pub const SIGKILL: Signal = Signal(NonZeroU8::new(9).expect("9 is nonzero"));

    /// シグナル番号を検証して作る。`0` および Linux の実時間シグナル上限を超える
    /// `65` 以上の値は [`ErrorCode::InvalidArgument`] で拒否する。
    pub fn new(value: u8) -> Result<Self, TraitError> {
        if value == 0 || value > 64 {
            return Err(TraitError::new(
                ErrorCode::InvalidArgument,
                "signal number must be in 1..=64",
            ));
        }
        // 直前の範囲検査により 1..=64 であることが保証されるため NonZeroU8 化は必ず成功する。
        Ok(Self(NonZeroU8::new(value).unwrap_or(NonZeroU8::MIN)))
    }

    /// シグナル番号を `u8` として返す。
    pub fn as_u8(&self) -> u8 {
        self.0.get()
    }
}

/// [`ContainerRuntime::create`] の要求。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CreateRequest {
    id: ContainerId,
    bundle: PathBuf,
}

impl CreateRequest {
    /// コンテナ ID と OCI bundle の絶対パスから要求を作る。
    ///
    /// `bundle` が絶対パスでない場合は [`ErrorCode::InvalidArgument`] を返す。plugin
    /// プロセスは呼び出し元と作業ディレクトリが異なるため、相対パスは解決先が曖昧になる
    /// （fail-closed）。rootfs の外を指していないか等の詳しい検証は実装側（TASK-114・G3）の
    /// 責務であり、本トレイトは形式検証のみを行う。
    pub fn new(id: ContainerId, bundle: PathBuf) -> Result<Self, TraitError> {
        if !bundle.is_absolute() {
            return Err(TraitError::new(
                ErrorCode::InvalidArgument,
                "bundle path must be absolute",
            ));
        }
        Ok(Self { id, bundle })
    }

    /// 対象コンテナの ID を返す。
    pub fn id(&self) -> &ContainerId {
        &self.id
    }

    /// OCI bundle の絶対パスを返す。
    pub fn bundle(&self) -> &Path {
        &self.bundle
    }
}

/// [`ContainerRuntime::start`] の要求。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct StartRequest {
    id: ContainerId,
}

impl StartRequest {
    /// 対象コンテナの ID から要求を作る。
    pub fn new(id: ContainerId) -> Self {
        Self { id }
    }

    /// 対象コンテナの ID を返す。
    pub fn id(&self) -> &ContainerId {
        &self.id
    }
}

/// [`ContainerRuntime::state`] の要求。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct StateRequest {
    id: ContainerId,
}

impl StateRequest {
    /// 対象コンテナの ID から要求を作る。
    pub fn new(id: ContainerId) -> Self {
        Self { id }
    }

    /// 対象コンテナの ID を返す。
    pub fn id(&self) -> &ContainerId {
        &self.id
    }
}

/// [`ContainerRuntime::kill`] の要求。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct KillRequest {
    id: ContainerId,
    signal: Signal,
}

impl KillRequest {
    /// 対象コンテナの ID と送るシグナルから要求を作る。
    pub fn new(id: ContainerId, signal: Signal) -> Self {
        Self { id, signal }
    }

    /// 対象コンテナの ID を返す。
    pub fn id(&self) -> &ContainerId {
        &self.id
    }

    /// 送るシグナルを返す。
    pub fn signal(&self) -> Signal {
        self.signal
    }
}

/// [`ContainerRuntime::stop`] の要求。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct StopRequest {
    id: ContainerId,
    grace: Duration,
}

impl StopRequest {
    /// 対象コンテナの ID と SIGKILL までの猶予時間から要求を作る。
    ///
    /// 猶予は呼び出し側が明示する必要があり（無期限を許さない。REPAIR-5）、
    /// 実装は猶予経過後に SIGKILL へ切り替える。
    pub fn new(id: ContainerId, grace: Duration) -> Self {
        Self { id, grace }
    }

    /// 対象コンテナの ID を返す。
    pub fn id(&self) -> &ContainerId {
        &self.id
    }

    /// SIGKILL までの猶予時間を返す。
    pub fn grace(&self) -> Duration {
        self.grace
    }
}

/// [`ContainerRuntime::delete`] の要求。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct DeleteRequest {
    id: ContainerId,
    force: bool,
}

impl DeleteRequest {
    /// 対象コンテナの ID から要求を作る（`force` は既定で false）。
    pub fn new(id: ContainerId) -> Self {
        Self { id, force: false }
    }

    /// `force` を指定したビルダ。true の場合、実行中でも停止してから削除する。
    pub fn with_force(mut self, force: bool) -> Self {
        self.force = force;
        self
    }

    /// 対象コンテナの ID を返す。
    pub fn id(&self) -> &ContainerId {
        &self.id
    }

    /// 強制削除が指定されているかを返す。
    pub fn force(&self) -> bool {
        self.force
    }
}

/// コンテナの状態（OCI Runtime Spec の state 文字列に対応）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ContainerState {
    /// 作成処理の途中。
    Creating,
    /// 作成済みでまだユーザープロセスを開始していない。
    Created,
    /// ユーザープロセスが実行中。
    Running,
    /// ユーザープロセスが終了済み。
    Stopped,
}

impl ContainerState {
    /// OCI Runtime Spec の state 文字列（小文字）を返す。
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Creating => "creating",
            Self::Created => "created",
            Self::Running => "running",
            Self::Stopped => "stopped",
        }
    }
}

/// コンテナの状態照会結果。真偽値やフラットな文字列ではなく、将来の拡張
/// （リソース使用量等）に備えて構造化された型にする（coding-rust.md）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ContainerStatus {
    id: ContainerId,
    state: ContainerState,
    pid: Option<NonZeroU32>,
    exit_code: Option<i32>,
}

impl ContainerStatus {
    /// ID と状態から作る（`pid`・`exit_code` は未設定）。
    pub fn new(id: ContainerId, state: ContainerState) -> Self {
        Self {
            id,
            state,
            pid: None,
            exit_code: None,
        }
    }

    /// 実行中プロセスの PID を設定したビルダ。
    pub fn with_pid(mut self, pid: NonZeroU32) -> Self {
        self.pid = Some(pid);
        self
    }

    /// 終了コードを設定したビルダ。
    pub fn with_exit_code(mut self, exit_code: i32) -> Self {
        self.exit_code = Some(exit_code);
        self
    }

    /// コンテナ ID を返す。
    pub fn id(&self) -> &ContainerId {
        &self.id
    }

    /// 現在の状態を返す。
    pub fn state(&self) -> ContainerState {
        self.state
    }

    /// 実行中プロセスの PID（未設定なら `None`）を返す。
    pub fn pid(&self) -> Option<NonZeroU32> {
        self.pid
    }

    /// 終了コード（未設定なら `None`）を返す。
    pub fn exit_code(&self) -> Option<i32> {
        self.exit_code
    }
}

/// [`ContainerRuntime::delete`] の応答。当面は空だが、将来の拡張
/// （解放した資源の情報等）に備えて構造体にする。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct DeleteResponse {}

impl DeleteResponse {
    /// 空の応答を作る。
    pub fn new() -> Self {
        Self {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    /// テスト用のスタブ実装。dyn 互換性と各メソッドの戻り値を確認するためのみに使う。
    struct StubRuntime;

    impl ContainerRuntime for StubRuntime {
        fn create(&self, req: &CreateRequest) -> Result<ContainerStatus, TraitError> {
            Ok(ContainerStatus::new(
                req.id().clone(),
                ContainerState::Created,
            ))
        }

        fn start(&self, req: &StartRequest) -> Result<ContainerStatus, TraitError> {
            Ok(
                ContainerStatus::new(req.id().clone(), ContainerState::Running)
                    .with_pid(NonZeroU32::new(42).expect("42 is nonzero")),
            )
        }

        fn kill(&self, req: &KillRequest) -> Result<ContainerStatus, TraitError> {
            Ok(ContainerStatus::new(
                req.id().clone(),
                ContainerState::Running,
            ))
        }

        fn stop(&self, req: &StopRequest) -> Result<ContainerStatus, TraitError> {
            Ok(ContainerStatus::new(req.id().clone(), ContainerState::Stopped).with_exit_code(0))
        }

        fn delete(&self, req: &DeleteRequest) -> Result<DeleteResponse, TraitError> {
            if !req.force() {
                return Err(TraitError::new(
                    ErrorCode::FailedPrecondition,
                    "container is still running",
                ));
            }
            Ok(DeleteResponse::new())
        }

        fn state(&self, req: &StateRequest) -> Result<ContainerStatus, TraitError> {
            Ok(ContainerStatus::new(
                req.id().clone(),
                ContainerState::Running,
            ))
        }
    }

    fn sample_id() -> ContainerId {
        ContainerId::new("sample-container").expect("valid id")
    }

    #[cfg(unix)]
    fn sample_bundle() -> PathBuf {
        PathBuf::from("/run/x")
    }

    #[cfg(windows)]
    fn sample_bundle() -> PathBuf {
        PathBuf::from(r"C:\x")
    }

    /// CRI-7: `ContainerRuntime` は dyn 互換で、`Box`/`Arc` に収めて各メソッドを呼べる。
    #[test]
    fn cri7_container_runtime_is_dyn_compatible() {
        let boxed: Box<dyn ContainerRuntime> = Box::new(StubRuntime);
        let req = CreateRequest::new(sample_id(), sample_bundle()).expect("absolute bundle");
        let status = boxed.create(&req).expect("create succeeds");
        assert_eq!(status.state(), ContainerState::Created);

        let shared: Arc<dyn ContainerRuntime> = Arc::new(StubRuntime);
        let start_status = shared
            .start(&StartRequest::new(sample_id()))
            .expect("start succeeds");
        assert_eq!(start_status.state(), ContainerState::Running);
        assert_eq!(start_status.pid().map(NonZeroU32::get), Some(42));
    }

    /// CRI-7: スタブの `state` が `ContainerState::Running` を返し、`as_str()` が "running"。
    #[test]
    fn cri7_state_as_str_is_running() {
        let runtime = StubRuntime;
        let status = runtime
            .state(&StateRequest::new(sample_id()))
            .expect("state succeeds");
        assert_eq!(status.state().as_str(), "running");
    }

    /// CRI-7: `CreateRequest::new` は相対パスを拒否し、絶対パスは受理する。
    #[test]
    fn cri7_create_request_rejects_relative_bundle() {
        let err = CreateRequest::new(sample_id(), PathBuf::from("bundle"))
            .expect_err("relative path must be rejected");
        assert_eq!(err.code().as_str(), "INVALID_ARGUMENT");

        assert!(CreateRequest::new(sample_id(), sample_bundle()).is_ok());
    }

    /// CRI-7: `Signal::new` は 0 と 65 以上を拒否し、`SIGTERM`/`SIGKILL` の値が正しい。
    #[test]
    fn cri7_signal_new_validates_range() {
        assert!(Signal::new(0).is_err());
        assert!(Signal::new(65).is_err());
        assert_eq!(Signal::new(15).unwrap(), Signal::SIGTERM);
        assert_eq!(Signal::SIGKILL.as_u8(), 9);
    }

    /// CRI-7: 前提条件違反時に返るエラーコードが具体文字列と一致する。
    #[test]
    fn cri7_delete_without_force_returns_failed_precondition() {
        let runtime = StubRuntime;
        let err = runtime
            .delete(&DeleteRequest::new(sample_id()))
            .expect_err("must fail without force");
        assert_eq!(err.code().as_str(), "FAILED_PRECONDITION");

        let ok = runtime.delete(&DeleteRequest::new(sample_id()).with_force(true));
        assert!(ok.is_ok());
    }
}
