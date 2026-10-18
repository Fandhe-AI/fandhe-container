//! CRI サーバー層から `ContainerRuntime` トレイト境界を呼ぶアダプタ（TASK-59.1・#437・CRI-2・CRI-7・MS-4）。
//!
//! `runtime_service` の RPC ハンドラ（`CreateContainer`・`StartContainer` 等）が、実行層の具象型を
//! 一切知らずにコンテナのライフサイクルを操作するための薄い変換層である。参照してよい core の
//! 項目は `fandhe_container_core::traits` のみで、`oci_runtime`・`exec`・`cgroups` 等の具象モジュールへ
//! 依存しない（CRI-7。依存の向きは cri → core の一方向で、core 側は cri に依存しない）。
//!
//! CRI の語彙（ID 文字列・秒・bool）を受け、`ContainerRuntime` の検証つき要求型へ変換して呼び、
//! 結果のエラーを ERR-3 の gRPC ステータスへ写す。core の型は公開 API へ漏らさず、
//! [`RuntimeContainerStatus`] へ写して返す。
//!
//! **同期 API**: `ContainerRuntime` は同期トレイトで、plugin 越しの実装は REPAIR-5 のタイムアウトを持つ
//! RPC になり得る。async ハンドラからは `tokio::task::spawn_blocking` 上で呼ぶこと（`image_pull` の前例）。
//!
//! **未実装・簡易実装（REPAIR-3）**: 本モジュールは呼び出し境界だけを提供する。RPC ハンドラへの接続は
//! create・start が TASK-59.2（#438。`CriRuntimeService::with_runtime` で注入したときだけ有効）、
//! stop・delete が TASK-59.3（#439。接続済み）、結合試験は TASK-59.4（#440）で行い、
//! `ContainerRuntime` の実装（plugin 側。TASK-114）と OCI bundle の生成の本体も本モジュールの範囲外である
//! （bundle の供給は [`BundleProvider`] の注入点だけを定義する）。

use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use fandhe_container_core::traits::{
    ContainerId, ContainerRuntime, ContainerState, ContainerStatus, CreateRequest, DeleteRequest,
    DeleteResponse, ErrorCode, KillRequest, Signal, StartRequest, StateRequest, StopRequest,
    TraitError,
};
use tonic::{Code, Status};

use crate::runtime::v1::ContainerConfig;
use crate::runtime::v1::ContainerState as CriContainerState;

/// エラーメッセージとして返す最大バイト数。plugin 由来の untrusted な文字列のため cri 側でも上限を掛ける。
const STATUS_MESSAGE_MAX_BYTES: usize = 4096;

/// 実行層が報告した生の状態（CRI の外向き状態へ写す前の区別。CRI-2・REPAIR-5）。
///
/// CRI の `ContainerCreated` は実行層の Creating と Created を区別しない。しかし作成完了の検査や
/// 「未起動と確定できるか」の判定では、Creating（作成途中で結果が不確定）を Created と同一視してはならない。
/// 判定は [`RuntimeContainerStatus::lifecycle`] のこの値で行う。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RuntimeLifecycle {
    /// 作成途中（完了未確定）。
    Creating,
    /// 作成完了・未起動。
    Created,
    /// 実行中。
    Running,
    /// 停止済み。
    Stopped,
    /// 未知の状態（将来追加される状態を含む）。
    Unknown,
}

/// `ContainerRuntime` の状態照会結果を CRI 側の語彙へ写した値（CRI-2）。
///
/// core の型を cri の公開 API へ漏らさないための型。将来の拡張に備えて `#[non_exhaustive]` とする。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RuntimeContainerStatus {
    /// コンテナ ID。
    pub id: String,
    /// CRI の状態。Creating・Created は `ContainerCreated`、Running は `ContainerRunning`、
    /// Stopped は `ContainerExited`、将来追加される未知の状態は `ContainerUnknown` に写す。
    pub state: CriContainerState,
    /// 実行層が報告した生の状態。完了・未起動の厳密な判定はこちらで行う（`state` は Creating を Created に写す）。
    pub lifecycle: RuntimeLifecycle,
    /// init プロセスの PID（判明していれば）。
    pub pid: Option<u32>,
    /// 終了コード（Stopped で判明していれば）。
    pub exit_code: Option<i32>,
}

impl From<&ContainerStatus> for RuntimeContainerStatus {
    fn from(s: &ContainerStatus) -> Self {
        let (state, lifecycle) = match s.state() {
            ContainerState::Creating => (
                CriContainerState::ContainerCreated,
                RuntimeLifecycle::Creating,
            ),
            ContainerState::Created => (
                CriContainerState::ContainerCreated,
                RuntimeLifecycle::Created,
            ),
            ContainerState::Running => (
                CriContainerState::ContainerRunning,
                RuntimeLifecycle::Running,
            ),
            ContainerState::Stopped => (
                CriContainerState::ContainerExited,
                RuntimeLifecycle::Stopped,
            ),
            _ => (
                CriContainerState::ContainerUnknown,
                RuntimeLifecycle::Unknown,
            ),
        };
        Self {
            id: s.id().as_str().to_owned(),
            state,
            lifecycle,
            pid: s.pid().map(|p| p.get()),
            exit_code: s.exit_code(),
        }
    }
}

/// `ContainerRuntime::delete` の結果を CRI 側の語彙へ写した値（CRI-2）。
///
/// core の `DeleteResponse` を公開 API へ漏らさず、将来の拡張（解放した資源の情報等）に備えて
/// `#[non_exhaustive]` とする。当面は core 側の応答が空のためフィールドを持たない。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct RuntimeDeleteResult {}

impl From<&DeleteResponse> for RuntimeDeleteResult {
    fn from(_: &DeleteResponse) -> Self {
        Self {}
    }
}

/// `ContainerRuntime` のエラーを ERR-3 の gRPC ステータスへ写す。
///
/// 未知のコード（`#[non_exhaustive]`）は `Internal` にする。メッセージは plugin 由来のため上限を再確認して詰める。
pub fn trait_error_to_status(err: &TraitError) -> Status {
    let code = match err.code() {
        ErrorCode::InvalidArgument => Code::InvalidArgument,
        ErrorCode::NotFound => Code::NotFound,
        ErrorCode::AlreadyExists => Code::AlreadyExists,
        ErrorCode::FailedPrecondition => Code::FailedPrecondition,
        ErrorCode::Unimplemented => Code::Unimplemented,
        ErrorCode::PermissionDenied => Code::PermissionDenied,
        ErrorCode::Timeout => Code::DeadlineExceeded,
        ErrorCode::Unavailable => Code::Unavailable,
        _ => Code::Internal,
    };
    let mut msg = err.message().to_owned();
    if msg.len() > STATUS_MESSAGE_MAX_BYTES {
        let mut end = STATUS_MESSAGE_MAX_BYTES;
        while !msg.is_char_boundary(end) {
            end -= 1;
        }
        msg.truncate(end);
    }
    Status::new(code, msg)
}

/// CRI の `ContainerConfig` から OCI bundle（rootfs と `config.json`）を用意する注入点（TASK-59.2・#438・CRI-2）。
///
/// `CreateContainer` ハンドラが `ContainerRuntime::create` を呼ぶ直前に呼ぶ。CRI の要求は bundle の
/// パスを持たないため、image の展開と `ContainerConfig` から `config.json` への変換は本トレイトの実装側の
/// 責務とする。同期 API で、ハンドラは tokio の blocking pool を使わず専用スレッド（worker）上から呼ぶ。
///
/// **未実装（REPAIR-3）**: 本番の実装（image 展開・config 変換・パスの検証）は未提供で、本リポでは
/// テスト用の実装だけがある。`config` の内容（envs 等の秘密値を含みうる）をエラー文言へ含めないこと。
pub trait BundleProvider: Send + Sync {
    /// コンテナ用の bundle を用意し、その絶対パスを返す。失敗は ERR-3 の gRPC ステータスで返す。
    fn prepare(
        &self,
        container_id: &str,
        sandbox_id: &str,
        config: &ContainerConfig,
    ) -> Result<PathBuf, Status>;

    /// `prepare` で用意した資源を解放する（`create` 失敗時の後始末。stop・delete は TASK-59.3 で接続済み）。
    ///
    /// 削除・解除に失敗したら `Err` を返す。呼び出し側は `Err` のとき資源が残っているとみなし、
    /// コンテナの記録と件数枠を保持して追跡を失わない（fail-closed）。不在は `Ok` としてよい。
    fn release(&self, container_id: &str) -> Result<(), Status>;
}

/// RPC ハンドラから `ContainerRuntime` を呼ぶアダプタ（CRI-2・CRI-7）。
///
/// トレイトオブジェクト（[`RuntimeAdapter::new`]）とジェネリクス（[`RuntimeAdapter::from_runtime`]）の
/// 両方で受けられ、core の具象実装に依存しない。`Clone` は `Arc` の複製で安価。
#[derive(Clone)]
pub struct RuntimeAdapter {
    runtime: Arc<dyn ContainerRuntime>,
}

impl fmt::Debug for RuntimeAdapter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RuntimeAdapter").finish_non_exhaustive()
    }
}

impl RuntimeAdapter {
    /// トレイトオブジェクトからアダプタを作る（plugin proxy 等を `Arc<dyn ContainerRuntime>` で渡す経路）。
    pub fn new(runtime: Arc<dyn ContainerRuntime>) -> Self {
        Self { runtime }
    }

    /// 具象型（ジェネリクス）からアダプタを作る。
    pub fn from_runtime<R: ContainerRuntime + 'static>(runtime: R) -> Self {
        Self::new(Arc::new(runtime))
    }

    /// CRI 由来の ID 文字列を検証して [`ContainerId`] にする（不正は `INVALID_ARGUMENT`）。
    fn id(id: &str) -> Result<ContainerId, Status> {
        ContainerId::new(id).map_err(|e| trait_error_to_status(&e))
    }

    /// OCI bundle（絶対パス）からコンテナを作成する。
    pub fn create(&self, id: &str, bundle: PathBuf) -> Result<RuntimeContainerStatus, Status> {
        let req =
            CreateRequest::new(Self::id(id)?, bundle).map_err(|e| trait_error_to_status(&e))?;
        Self::finish(id, self.runtime.create(&req))
    }

    /// `created` 状態のコンテナを開始する。
    pub fn start(&self, id: &str) -> Result<RuntimeContainerStatus, Status> {
        let req = StartRequest::new(Self::id(id)?);
        Self::finish(id, self.runtime.start(&req))
    }

    /// SIGTERM 後 `timeout_secs` 秒で SIGKILL へ切り替えて停止する。
    ///
    /// 負値は 0（即時 SIGKILL）に丸める。上限（24 時間。REPAIR-5）超過は `INVALID_ARGUMENT`。
    pub fn stop(&self, id: &str, timeout_secs: i64) -> Result<RuntimeContainerStatus, Status> {
        let grace = Duration::from_secs(u64::try_from(timeout_secs).unwrap_or(0));
        let req = StopRequest::new(Self::id(id)?, grace).map_err(|e| trait_error_to_status(&e))?;
        Self::finish(id, self.runtime.stop(&req))
    }

    /// コンテナの資源を解放する（`ContainerRuntime::delete`）。`force` は実行中でも停止してから削除する。
    pub fn remove(&self, id: &str, force: bool) -> Result<RuntimeDeleteResult, Status> {
        let req = DeleteRequest::new(Self::id(id)?).with_force(force);
        self.runtime
            .delete(&req)
            .as_ref()
            .map(RuntimeDeleteResult::from)
            .map_err(trait_error_to_status)
    }

    /// シグナル番号（1..=64）を送る。範囲外は `INVALID_ARGUMENT`。
    pub fn kill(&self, id: &str, signal: u8) -> Result<RuntimeContainerStatus, Status> {
        let signal = Signal::new(signal).map_err(|e| trait_error_to_status(&e))?;
        let req = KillRequest::new(Self::id(id)?, signal);
        Self::finish(id, self.runtime.kill(&req))
    }

    /// コンテナの現在状態を照会する。
    pub fn state(&self, id: &str) -> Result<RuntimeContainerStatus, Status> {
        let req = StateRequest::new(Self::id(id)?);
        Self::finish(id, self.runtime.state(&req))
    }

    /// 実行層の応答を CRI の語彙へ写す。応答の ID が要求の ID と異なれば plugin の不正な応答として
    /// `INTERNAL`（結果不明）で拒否する（plugin 入力は untrusted。別コンテナの状態を受理しない）。
    fn finish(
        expected_id: &str,
        r: Result<ContainerStatus, TraitError>,
    ) -> Result<RuntimeContainerStatus, Status> {
        let status = r.as_ref().map_err(trait_error_to_status)?;
        if status.id().as_str() != expected_id {
            return Err(Status::internal(
                "runtime returned a status for a different container id",
            ));
        }
        Ok(RuntimeContainerStatus::from(status))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::num::NonZeroU32;

    fn cid(s: &str) -> ContainerId {
        ContainerId::new(s).unwrap()
    }

    /// CRI-2: core の状態を CRI の状態へ具体値で写す。
    #[test]
    fn cri2_state_mapping() {
        let pid = NonZeroU32::new(42);
        let cases = [
            (
                ContainerStatus::creating(cid("a")),
                CriContainerState::ContainerCreated,
                None,
                None,
            ),
            (
                ContainerStatus::created(cid("a"), pid),
                CriContainerState::ContainerCreated,
                Some(42),
                None,
            ),
            (
                ContainerStatus::running(cid("a"), pid),
                CriContainerState::ContainerRunning,
                Some(42),
                None,
            ),
            (
                ContainerStatus::stopped(cid("a"), Some(137)),
                CriContainerState::ContainerExited,
                None,
                Some(137),
            ),
        ];
        let lifecycles = [
            RuntimeLifecycle::Creating,
            RuntimeLifecycle::Created,
            RuntimeLifecycle::Running,
            RuntimeLifecycle::Stopped,
        ];
        for ((src, state, pid, code), lifecycle) in cases.into_iter().zip(lifecycles) {
            let got = RuntimeContainerStatus::from(&src);
            assert_eq!(got.lifecycle, lifecycle);
            assert_eq!(got.id, "a");
            assert_eq!(got.state, state);
            assert_eq!(got.pid, pid);
            assert_eq!(got.exit_code, code);
        }
    }

    /// CRI-2: 応答の ID が要求と異なれば拒否する。
    #[test]
    fn cri2_finish_rejects_mismatched_id() {
        let ok = RuntimeAdapter::finish("a", Ok(ContainerStatus::creating(cid("a"))));
        assert_eq!(ok.unwrap().id, "a");
        let err = RuntimeAdapter::finish("a", Ok(ContainerStatus::created(cid("b"), None)))
            .expect_err("mismatch");
        assert_eq!(err.code(), Code::Internal);
    }

    /// CRI-2: 削除応答を CRI 側の型へ写す。
    #[test]
    fn cri2_delete_result_mapping() {
        assert_eq!(
            RuntimeDeleteResult::from(&DeleteResponse::new()),
            RuntimeDeleteResult::default()
        );
    }

    /// ERR-3: ErrorCode を gRPC コードへ具体値で写す。
    #[test]
    fn err3_error_code_mapping() {
        let cases = [
            (ErrorCode::InvalidArgument, Code::InvalidArgument),
            (ErrorCode::NotFound, Code::NotFound),
            (ErrorCode::AlreadyExists, Code::AlreadyExists),
            (ErrorCode::FailedPrecondition, Code::FailedPrecondition),
            (ErrorCode::Unimplemented, Code::Unimplemented),
            (ErrorCode::PermissionDenied, Code::PermissionDenied),
            (ErrorCode::Timeout, Code::DeadlineExceeded),
            (ErrorCode::Unavailable, Code::Unavailable),
        ];
        for (ec, code) in cases {
            let st = trait_error_to_status(&TraitError::new(ec, "msg"));
            assert_eq!(st.code(), code);
            assert_eq!(st.message(), "msg");
        }
    }

    /// ERR-3: 長いメッセージは文字境界で 4096 バイト以下に切る。
    #[test]
    fn err3_message_truncated_on_char_boundary() {
        let long = "あ".repeat(2000);
        let st = trait_error_to_status(&TraitError::new(ErrorCode::NotFound, long));
        assert!(st.message().len() <= STATUS_MESSAGE_MAX_BYTES);
        assert_eq!(st.message().len(), 4095);
    }
}
