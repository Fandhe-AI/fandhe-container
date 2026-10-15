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
//! TASK-59.2（#438。create・start）・TASK-59.3（#439。stop・delete）、結合試験は TASK-59.4（#440）で行い、
//! `ContainerRuntime` の実装（plugin 側。TASK-114）と OCI bundle の生成も本モジュールの範囲外である。

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

use crate::runtime::v1::ContainerState as CriContainerState;

/// エラーメッセージとして返す最大バイト数。plugin 由来の untrusted な文字列のため cri 側でも上限を掛ける。
const STATUS_MESSAGE_MAX_BYTES: usize = 4096;

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
    /// init プロセスの PID（判明していれば）。
    pub pid: Option<u32>,
    /// 終了コード（Stopped で判明していれば）。
    pub exit_code: Option<i32>,
}

impl From<&ContainerStatus> for RuntimeContainerStatus {
    fn from(s: &ContainerStatus) -> Self {
        let state = match s.state() {
            ContainerState::Creating | ContainerState::Created => {
                CriContainerState::ContainerCreated
            }
            ContainerState::Running => CriContainerState::ContainerRunning,
            ContainerState::Stopped => CriContainerState::ContainerExited,
            _ => CriContainerState::ContainerUnknown,
        };
        Self {
            id: s.id().as_str().to_owned(),
            state,
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
        Self::finish(self.runtime.create(&req))
    }

    /// `created` 状態のコンテナを開始する。
    pub fn start(&self, id: &str) -> Result<RuntimeContainerStatus, Status> {
        let req = StartRequest::new(Self::id(id)?);
        Self::finish(self.runtime.start(&req))
    }

    /// SIGTERM 後 `timeout_secs` 秒で SIGKILL へ切り替えて停止する。
    ///
    /// 負値は 0（即時 SIGKILL）に丸める。上限（24 時間。REPAIR-5）超過は `INVALID_ARGUMENT`。
    pub fn stop(&self, id: &str, timeout_secs: i64) -> Result<RuntimeContainerStatus, Status> {
        let grace = Duration::from_secs(u64::try_from(timeout_secs).unwrap_or(0));
        let req = StopRequest::new(Self::id(id)?, grace).map_err(|e| trait_error_to_status(&e))?;
        Self::finish(self.runtime.stop(&req))
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
        Self::finish(self.runtime.kill(&req))
    }

    /// コンテナの現在状態を照会する。
    pub fn state(&self, id: &str) -> Result<RuntimeContainerStatus, Status> {
        let req = StateRequest::new(Self::id(id)?);
        Self::finish(self.runtime.state(&req))
    }

    fn finish(r: Result<ContainerStatus, TraitError>) -> Result<RuntimeContainerStatus, Status> {
        r.as_ref()
            .map(RuntimeContainerStatus::from)
            .map_err(trait_error_to_status)
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
        for (src, state, pid, code) in cases {
            let got = RuntimeContainerStatus::from(&src);
            assert_eq!(got.id, "a");
            assert_eq!(got.state, state);
            assert_eq!(got.pid, pid);
            assert_eq!(got.exit_code, code);
        }
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
