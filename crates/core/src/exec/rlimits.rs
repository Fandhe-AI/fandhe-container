//! rlimit 適用の組み込みステージ（SUP-12・TASK-169.1・#526・MS-9）。
//!
//! # 役割と呼び出し文脈
//!
//! ステージ列（`exec/stages.rs` の `StagePipeline`）の第 2 段。`StagePipeline::run_then` が
//! cgroup 参加の後・capability 削減の前に、`StagePipeline::with_rlimits` で渡された
//! [`Rlimits`] を [`apply_rlimits`] で適用する。他の段と違い `StageHook` では差し替えられない
//! 組み込み処理で、集合が未設定・空のときは syscall を呼ばず `Skipped` のままにする。
//!
//! # 順序の根拠
//!
//! - capability 削減より前: OCI 既定の capability マスクに `CAP_SYS_RESOURCE` は含まれず、
//!   削減後は hard limit の引き上げが常に `EPERM` になる
//! - seccomp より前: 既定 allowlist（CORE-5）に `prlimit64` を足さずに済む
//!
//! # 契約（fail-closed）
//!
//! - 各 rlimit を `prlimit(2)` で設定した直後に読み戻し、soft / hard が指定値と一致することを
//!   確認する。不一致は `Internal`。**黙ってクランプしない**
//! - 最初の失敗で打ち切り、後続の種別・後続段・exec に進ませない
//! - rootless（user namespace 内）では hard の引き下げと範囲内の soft 変更は成功し、継承値を超える
//!   hard の引き上げは `EPERM`（`PermissionDenied`）で起動拒否になる
//! - `RLIMIT_NOFILE` 等を極端に下げると後続段（Landlock のパス open・exec）が失敗して起動拒否に
//!   なり得る。これも fail-closed の範囲内の挙動
//! - **制限適用の証跡にはしない**（REPAIR-3）。`process.rs::require_restriction_evidence` は本ステージの
//!   成否によらず従来どおり判定する
//!
//! `cfg(test)` では本物の `prlimit` を呼ばず thread_local の偽物に差し替える（テストプロセス自身の
//! 制限を変えないため。本物の syscall は `sys.rs` のテストで別プロセスに対して確認する）。

use super::{ExecError, IsolationStage};
use crate::rlimits::Rlimits;
use crate::traits::types::ErrorCode;

#[cfg(not(test))]
use crate::sys::{get_rlimit_self, set_rlimit_self};
#[cfg(test)]
use testing::{get_rlimit_self, set_rlimit_self};

/// 集合の各 rlimit を設定し、読み戻して指定値との一致を確認する。
pub(super) fn apply_rlimits(set: &Rlimits) -> Result<(), ExecError> {
    let stage = IsolationStage::Rlimits;
    for r in set.iter() {
        let what = format!("prlimit({})", r.kind().as_oci_name());
        set_rlimit_self(r.kind(), r.soft(), r.hard())
            .map_err(|e| ExecError::from_sys(e, stage, &what))?;
        let (soft, hard) =
            get_rlimit_self(r.kind()).map_err(|e| ExecError::from_sys(e, stage, &what))?;
        if (soft, hard) != (r.soft(), r.hard()) {
            return Err(ExecError::new(
                ErrorCode::Internal,
                stage,
                format!("{what} did not take effect"),
            ));
        }
    }
    Ok(())
}

/// テスト用の偽 syscall。呼び出し記録は `no_new_privs::testing` の記録器と共有する。
#[cfg(test)]
pub(super) mod testing {
    use std::cell::{Cell, RefCell};

    use crate::rlimits::RlimitKind;
    use crate::sys::SysError;

    thread_local! {
        static SET_RESULT: Cell<Result<(), SysError>> = const { Cell::new(Ok(())) };
        static LAST: Cell<(u64, u64)> = const { Cell::new((0, 0)) };
        static GET_OVERRIDE: Cell<Option<(u64, u64)>> = const { Cell::new(None) };
        static SETS: RefCell<Vec<(RlimitKind, u64, u64)>> = const { RefCell::new(Vec::new()) };
    }

    /// 設定の記録を取り出し、偽物を既定（成功・読み戻しは直前の設定値）へ戻す。
    pub(in crate::exec) fn take_sets() -> Vec<(RlimitKind, u64, u64)> {
        SET_RESULT.with(|c| c.set(Ok(())));
        GET_OVERRIDE.with(|c| c.set(None));
        SETS.with(|c| std::mem::take(&mut *c.borrow_mut()))
    }

    /// 設定の結果と、読み戻しの上書き値を指定する。
    pub(in crate::exec) fn fake(set: Result<(), SysError>, get: Option<(u64, u64)>) {
        SET_RESULT.with(|c| c.set(set));
        GET_OVERRIDE.with(|c| c.set(get));
    }

    pub(super) fn set_rlimit_self(kind: RlimitKind, soft: u64, hard: u64) -> Result<(), SysError> {
        super::super::no_new_privs::testing::rec("rlimits");
        SETS.with(|c| c.borrow_mut().push((kind, soft, hard)));
        let r = SET_RESULT.with(Cell::get);
        if r.is_ok() {
            LAST.with(|c| c.set((soft, hard)));
        }
        r
    }

    pub(super) fn get_rlimit_self(_kind: RlimitKind) -> Result<(u64, u64), SysError> {
        Ok(GET_OVERRIDE
            .with(Cell::get)
            .unwrap_or_else(|| LAST.with(Cell::get)))
    }
}

#[cfg(test)]
mod tests {
    use super::testing::{fake, take_sets};
    use super::*;
    use crate::exec::no_new_privs::testing::take;
    use crate::rlimits::{Rlimit, RlimitKind};
    use crate::sys::{self, SysError};

    fn set_of(items: &[(RlimitKind, u64, u64)]) -> Rlimits {
        Rlimits::new(
            items
                .iter()
                .map(|&(k, s, h)| Rlimit::new(k, s, h).unwrap())
                .collect(),
        )
        .unwrap()
    }

    /// SUP-12・TASK-169.1: 種別ごとに 1 回ずつ、指定順・指定値で設定される。
    #[test]
    fn sup12_apply_rlimits_sets_each_kind_once_in_order() {
        take();
        take_sets();
        let set = set_of(&[(RlimitKind::Nofile, 256, 512), (RlimitKind::Core, 0, 0)]);
        apply_rlimits(&set).unwrap();
        assert_eq!(
            take_sets(),
            [(RlimitKind::Nofile, 256, 512), (RlimitKind::Core, 0, 0)]
        );
        assert_eq!(take(), ["rlimits", "rlimits"]);
    }

    /// SUP-12・TASK-169.1: errno の写像（EPERM → PermissionDenied、EINVAL → FailedPrecondition、
    /// Unsupported → Unimplemented）と、段が Rlimits であること。
    #[test]
    fn sup12_apply_rlimits_maps_errors() {
        let set = set_of(&[(RlimitKind::Nofile, 1, 2)]);
        for (err, code) in [
            (SysError::Os(sys::EPERM), ErrorCode::PermissionDenied),
            (SysError::Os(sys::EINVAL), ErrorCode::FailedPrecondition),
            (SysError::Unsupported, ErrorCode::Unimplemented),
        ] {
            take();
            take_sets();
            fake(Err(err), None);
            let e = apply_rlimits(&set).unwrap_err();
            assert_eq!(e.code, code);
            assert_eq!(e.stage, IsolationStage::Rlimits);
            assert_eq!(e.violation, None);
        }
        take();
        take_sets();
    }

    /// SUP-12・TASK-169.1: 読み戻しが指定値と違えば Internal（黙ってクランプしない）。
    #[test]
    fn sup12_apply_rlimits_fails_on_readback_mismatch() {
        take();
        take_sets();
        fake(Ok(()), Some((100, 512)));
        let e = apply_rlimits(&set_of(&[(RlimitKind::Nofile, 256, 512)])).unwrap_err();
        assert_eq!(e.code, ErrorCode::Internal);
        assert_eq!(e.stage, IsolationStage::Rlimits);
        take();
        take_sets();
    }

    /// SUP-12・TASK-169.1: 途中の失敗で後続の種別を呼ばない。
    #[test]
    fn sup12_apply_rlimits_stops_at_first_failure() {
        take();
        take_sets();
        fake(Err(SysError::Os(sys::EPERM)), None);
        let set = set_of(&[(RlimitKind::Nofile, 1, 2), (RlimitKind::Core, 0, 0)]);
        assert!(apply_rlimits(&set).is_err());
        assert_eq!(take_sets(), [(RlimitKind::Nofile, 1, 2)]);
        take();
    }
}
