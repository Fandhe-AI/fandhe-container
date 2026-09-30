//! `PR_SET_NO_NEW_PRIVS` の固定ステージ（CORE-1・TASK-27.4.3・#833・MS-2）。
//!
//! # 役割と呼び出し文脈
//!
//! ステージ列（`exec/stages.rs` の `StagePipeline`）の第 3 段。`StagePipeline::run_then` が
//! capability 削減の後・Landlock の前に 1 回だけ [`apply_no_new_privs`] を呼ぶ。他の段と違い
//! `StageHook` として差し替えられない組み込み処理で、フックを登録しなくても（空のパイプラインでも）
//! 必ず実行される。非特権の Landlock / seccomp は `NO_NEW_PRIVS` を前提にするため、これを
//! それらより前に固定することが fail-closed の前提になる。
//!
//! # 契約
//!
//! - `sys::set_no_new_privs` の後に `sys::no_new_privs_enabled` で立っていることを確認し、確認できな
//!   ければ `Internal` で失敗する（exec に進ませない）
//! - `NO_NEW_PRIVS` はタスク（スレッド）単位のフラグで、fork・clone・execve を越えて継承され解除
//!   できない。子は `fork_single_threaded` によりシングルスレッドなので 1 回の呼び出しで
//!   プロセス全体を覆う
//! - **制限適用の証跡にはしない**（REPAIR-3）。`process.rs::require_restriction_evidence` は
//!   capability 削減・seccomp・Landlock が揃うまで、本ステージの成否によらず exec を拒否する
//!
//! `cfg(test)` では本物の `prctl` を呼ばず、thread_local の偽物に差し替える（テストの外へ
//! フラグが残るのを防ぐ。本物の syscall は `sys.rs` のテストで確認する）。

use super::{ExecError, IsolationStage};
use crate::traits::types::ErrorCode;

#[cfg(not(test))]
use crate::sys::{no_new_privs_enabled, set_no_new_privs};
#[cfg(test)]
use testing::{no_new_privs_enabled, set_no_new_privs};

/// `NO_NEW_PRIVS` を有効にし、立っていることを確認する。
pub(super) fn apply_no_new_privs() -> Result<(), ExecError> {
    let stage = IsolationStage::NoNewPrivs;
    set_no_new_privs().map_err(|e| ExecError::from_sys(e, stage, "prctl(PR_SET_NO_NEW_PRIVS)"))?;
    let enabled = no_new_privs_enabled()
        .map_err(|e| ExecError::from_sys(e, stage, "prctl(PR_GET_NO_NEW_PRIVS)"))?;
    if !enabled {
        return Err(ExecError::new(
            ErrorCode::Internal,
            stage,
            "no_new_privs is not set after prctl",
        ));
    }
    Ok(())
}

/// テスト用の偽 syscall と、`stages.rs` のテストと共有する呼び出し記録器。
#[cfg(test)]
pub(super) mod testing {
    use std::cell::{Cell, RefCell};

    use crate::sys::SysError;

    thread_local! {
        static CALLS: RefCell<Vec<&'static str>> = const { RefCell::new(Vec::new()) };
        static SET_RESULT: Cell<Result<(), SysError>> = const { Cell::new(Ok(())) };
        static GET_RESULT: Cell<Result<bool, SysError>> = const { Cell::new(Ok(true)) };
    }

    pub(in crate::exec) fn rec(name: &'static str) {
        CALLS.with(|c| c.borrow_mut().push(name));
    }

    /// 記録を取り出し、偽物の結果を既定（set 成功・GET が true）へ戻す。
    pub(in crate::exec) fn take() -> Vec<&'static str> {
        SET_RESULT.with(|c| c.set(Ok(())));
        GET_RESULT.with(|c| c.set(Ok(true)));
        CALLS.with(|c| std::mem::take(&mut *c.borrow_mut()))
    }

    pub(in crate::exec) fn fake(set: Result<(), SysError>, get: Result<bool, SysError>) {
        SET_RESULT.with(|c| c.set(set));
        GET_RESULT.with(|c| c.set(get));
    }

    pub(super) fn set_no_new_privs() -> Result<(), SysError> {
        rec("no_new_privs");
        SET_RESULT.with(Cell::get)
    }

    pub(super) fn no_new_privs_enabled() -> Result<bool, SysError> {
        GET_RESULT.with(Cell::get)
    }
}

#[cfg(test)]
mod tests {
    use super::testing::{fake, take};
    use super::*;
    use crate::sys::{self, SysError};

    /// CORE-1・TASK-27.4.3: 既定（成功）で Ok、set を 1 回呼ぶ。
    #[test]
    fn core1_apply_no_new_privs_succeeds() {
        take();
        assert!(apply_no_new_privs().is_ok());
        assert_eq!(take(), ["no_new_privs"]);
    }

    /// CORE-1・TASK-27.4.3: EPERM は PermissionDenied（違反ではなくシステムエラー）。
    #[test]
    fn core1_apply_no_new_privs_maps_eperm() {
        take();
        fake(Err(SysError::Os(sys::EPERM)), Ok(true));
        let e = apply_no_new_privs().unwrap_err();
        assert_eq!(e.code, ErrorCode::PermissionDenied);
        assert_eq!(e.stage, IsolationStage::NoNewPrivs);
        assert_eq!(e.violation, None);
        take();
    }

    /// CORE-1・TASK-27.4.3: EINVAL は FailedPrecondition、Unsupported は Unimplemented。
    #[test]
    fn core1_apply_no_new_privs_maps_einval_and_unsupported() {
        take();
        fake(Err(SysError::Os(sys::EINVAL)), Ok(true));
        assert_eq!(
            apply_no_new_privs().unwrap_err().code,
            ErrorCode::FailedPrecondition
        );
        fake(Err(SysError::Unsupported), Ok(true));
        assert_eq!(
            apply_no_new_privs().unwrap_err().code,
            ErrorCode::Unimplemented
        );
        take();
    }

    /// CORE-1・TASK-27.4.3: set が Ok でも GET が false なら fail-closed（Internal）。
    #[test]
    fn core1_apply_no_new_privs_fails_when_flag_not_visible() {
        take();
        fake(Ok(()), Ok(false));
        let e = apply_no_new_privs().unwrap_err();
        assert_eq!(e.code, ErrorCode::Internal);
        assert_eq!(e.stage, IsolationStage::NoNewPrivs);
        take();
    }
}
