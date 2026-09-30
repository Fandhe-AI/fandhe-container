//! seccomp フィルタの適用（CORE-5・TASK-38.2・#177・MS-2）。
//!
//! # 役割と呼び出し文脈
//!
//! ステージ列（`exec/stages.rs`）第 5 段「seccomp」の実体。`crate::seccomp::build_deny_filter`
//! （TASK-38.1）が作る [`SeccompProgram`] を `prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER)` で呼び出し
//! スレッドへ適用する。ステージ列（`StagePipeline`）へは TASK-38.3（#178）で組み込み済みで、
//! `stages.rs` の組み込み段が [`apply_default_seccomp`] を exec 直前に必ず呼ぶ（差し替え不可）。
//! 最終的な制限適用の証跡型は TASK-38・TASK-39 で決めるため、[`SeccompReport`] は証跡ではなく、
//! `process.rs::require_restriction_evidence` は本関数の成否によらず exec を拒否し続ける（REPAIR-3）。
//!
//! # 契約
//!
//! - `fork_single_threaded` による単一スレッドの子で、`NO_NEW_PRIVS`（固定ステージ。#833）の後・
//!   exec の直前に呼ぶ。適用は不可逆で、呼び出したスレッドにしか効かない。`Threads:` が 1 で
//!   あることを適用の前後で実行時に確認し、事前に満たさなければ何も変更せず `FailedPrecondition`、
//!   適用中に増えたときは `Internal` で失敗する（fail-closed）
//! - `NO_NEW_PRIVS` が未設定なら適用 syscall を呼ばず `FailedPrecondition` で失敗する。カーネルは
//!   `CAP_SYS_ADMIN` を持つ呼び出しでは未設定でも適用を許すため、カーネルの `EACCES` には頼らず
//!   自前で検証する（execve 後の権限昇格で seccomp を回避されない前提を崩さない）
//! - 適用後に `PR_GET_SECCOMP` で filter モード（2）を読み戻す。これは読み戻しの fail-closed 検査で、
//!   既に filter モードの環境では適用前から 2 のため「このフィルタが載った」証明ではない
//!
//! 本物の syscall は [`RealKernel`]（`sys` のラッパー）だけが呼ぶ。テストは偽の `SeccompKernel` で
//! 呼び出し順・エラー写像を再現し、実 syscall は使い捨てスレッドで確認する。

use super::{ExecError, IsolationStage};
use crate::seccomp::SeccompProgram;
use crate::sys::{self, SysError};
use crate::traits::types::ErrorCode;

/// `PR_GET_SECCOMP` が返す filter モードの値（`SECCOMP_MODE_FILTER`）。
const MODE_FILTER: u32 = 2;

/// カーネルへの seccomp 操作の境界。本番は [`RealKernel`]、テストは偽物を差し込む。
trait SeccompKernel {
    /// 呼び出したプロセスのスレッド数（`/proc/self/status` の `Threads:`）。読めない場合は `None`。
    fn thread_count(&mut self) -> Option<u64>;
    fn no_new_privs_enabled(&mut self) -> Result<bool, SysError>;
    fn set_filter(&mut self, program: &SeccompProgram) -> Result<(), SysError>;
    fn mode(&mut self) -> Result<u32, SysError>;
}

/// 本物の syscall を呼ぶ実装。
struct RealKernel;

impl SeccompKernel for RealKernel {
    fn thread_count(&mut self) -> Option<u64> {
        let status = std::fs::read_to_string("/proc/self/status").ok()?;
        super::status_threads(&status)
    }
    fn no_new_privs_enabled(&mut self) -> Result<bool, SysError> {
        sys::no_new_privs_enabled()
    }
    fn set_filter(&mut self, program: &SeccompProgram) -> Result<(), SysError> {
        sys::seccomp_set_filter(program)
    }
    fn mode(&mut self) -> Result<u32, SysError> {
        sys::seccomp_mode()
    }
}

/// seccomp の適用結果。最終的な証跡型は TASK-38・TASK-39 で確定するため `non_exhaustive`。
/// 制限適用の証跡としては扱わない（REPAIR-3）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SeccompReport {
    /// 適用した BPF 命令数。
    pub instructions: usize,
}

/// 呼び出したスレッドへ seccomp フィルタを適用する（CORE-5）。
///
/// **crate 内限定**（`pub(crate)`）。`sys::fork_single_threaded` の子で、`NO_NEW_PRIVS` の後に呼ぶ。
/// 本番の入口は [`apply_default_seccomp`]（ステージ列の組み込み段から呼ばれる）。
// テストでは `stages.rs` が偽物（`testing`）へ差し替えるため、本物は未使用になる。
#[cfg_attr(test, allow(dead_code))]
pub(crate) fn apply_seccomp_filter(program: &SeccompProgram) -> Result<SeccompReport, ExecError> {
    apply_single_threaded(program, &mut RealKernel)
}

/// ビルド対象アーキの既定 deny フィルタを構築して適用する（CORE-5・TASK-38.3・#178）。
///
/// `stages.rs` の組み込み `Seccomp` 段が exec 直前に呼ぶ本番の入口。`fork_single_threaded` の
/// 子（単一スレッド）の中で BPF を構築する。構築失敗は fail-closed で exec を止める:
/// 対応外アーキは `Unimplemented`、命令数超過は `Internal`（段はいずれも `Seccomp`）。
///
/// # 将来仕様（記録のみ）
///
/// 構築を親で事前に行い、呼び出し元へ構造化エラーを返す改善は未実施（REPAIR-3）。
// テストでは `stages.rs` が偽物（`testing`）へ差し替えるため、本物は未使用になる。
#[cfg_attr(test, allow(dead_code))]
pub(crate) fn apply_default_seccomp() -> Result<SeccompReport, ExecError> {
    let program = crate::seccomp::build_filter_for_target_arch().map_err(|e| {
        let code = match e {
            crate::seccomp::SeccompBuildError::UnsupportedArch => ErrorCode::Unimplemented,
            _ => ErrorCode::Internal,
        };
        ExecError::new(code, IsolationStage::Seccomp, e.to_string())
    })?;
    apply_seccomp_filter(&program)
}

/// 単一スレッド条件を適用の前後で検査して [`apply_filter`] を呼ぶ。事前検査は副作用の前に行う。
fn apply_single_threaded(
    program: &SeccompProgram,
    kernel: &mut impl SeccompKernel,
) -> Result<SeccompReport, ExecError> {
    if kernel.thread_count() != Some(1) {
        return Err(ExecError::new(
            ErrorCode::FailedPrecondition,
            IsolationStage::Seccomp,
            "seccomp filter requires a single-threaded process (Threads: 1)",
        ));
    }
    let report = apply_filter(program, kernel)?;
    if kernel.thread_count() != Some(1) {
        return Err(ExecError::new(
            ErrorCode::Internal,
            IsolationStage::Seccomp,
            "process became multi-threaded while applying seccomp filter",
        ));
    }
    Ok(report)
}

/// `NO_NEW_PRIVS` 検証 → 適用 → モード読み戻し。スレッド数検査は呼び出し側が行う。
fn apply_filter(
    program: &SeccompProgram,
    kernel: &mut impl SeccompKernel,
) -> Result<SeccompReport, ExecError> {
    let stage = IsolationStage::Seccomp;
    let nnp = kernel
        .no_new_privs_enabled()
        .map_err(|e| ExecError::from_sys(e, stage, "PR_GET_NO_NEW_PRIVS"))?;
    if !nnp {
        return Err(ExecError::new(
            ErrorCode::FailedPrecondition,
            stage,
            "seccomp filter requires no_new_privs to be set beforehand",
        ));
    }
    kernel
        .set_filter(program)
        .map_err(|e| ExecError::from_sys(e, stage, "PR_SET_SECCOMP"))?;
    let mode = kernel
        .mode()
        .map_err(|e| ExecError::from_sys(e, stage, "PR_GET_SECCOMP"))?;
    if mode != MODE_FILTER {
        return Err(ExecError::new(
            ErrorCode::Internal,
            stage,
            "seccomp mode is not filter after prctl",
        ));
    }
    Ok(SeccompReport {
        instructions: program.len(),
    })
}

#[cfg(all(test, any(target_arch = "x86_64", target_arch = "aarch64")))]
mod tests {
    use super::*;
    use crate::seccomp::build_filter_for_target_arch;
    use crate::sys::{EACCES, EINVAL};

    #[derive(Default)]
    struct Fake {
        threads: Vec<Option<u64>>,
        nnp: Option<Result<bool, SysError>>,
        set: Option<Result<(), SysError>>,
        mode: Option<Result<u32, SysError>>,
        calls: Vec<&'static str>,
    }

    impl Fake {
        fn ok() -> Self {
            Fake {
                threads: vec![Some(1), Some(1)],
                nnp: Some(Ok(true)),
                set: Some(Ok(())),
                mode: Some(Ok(2)),
                calls: vec![],
            }
        }
    }

    impl SeccompKernel for Fake {
        fn thread_count(&mut self) -> Option<u64> {
            self.calls.push("threads");
            if self.threads.is_empty() {
                None
            } else {
                self.threads.remove(0)
            }
        }
        fn no_new_privs_enabled(&mut self) -> Result<bool, SysError> {
            self.calls.push("nnp");
            self.nnp.unwrap()
        }
        fn set_filter(&mut self, _p: &SeccompProgram) -> Result<(), SysError> {
            self.calls.push("set");
            self.set.unwrap()
        }
        fn mode(&mut self) -> Result<u32, SysError> {
            self.calls.push("mode");
            self.mode.unwrap()
        }
    }

    fn program() -> SeccompProgram {
        build_filter_for_target_arch().unwrap()
    }

    /// CORE-5: NO_NEW_PRIVS 未設定なら適用 syscall を呼ばずに FailedPrecondition。
    #[test]
    fn core5_apply_seccomp_rejects_without_no_new_privs() {
        let mut k = Fake::ok();
        k.nnp = Some(Ok(false));
        let e = apply_single_threaded(&program(), &mut k).unwrap_err();
        assert_eq!(e.code, ErrorCode::FailedPrecondition);
        assert_eq!(e.stage, IsolationStage::Seccomp);
        assert_eq!(e.violation, None);
        assert_eq!(k.calls, vec!["threads", "nnp"]);
    }

    /// CORE-5: NNP 取得失敗の写像と、その場合も適用 syscall を呼ばない。
    #[test]
    fn core5_apply_seccomp_maps_nnp_query_errors() {
        for (err, code) in [
            (SysError::Unsupported, ErrorCode::Unimplemented),
            (SysError::Os(EINVAL), ErrorCode::FailedPrecondition),
        ] {
            let mut k = Fake::ok();
            k.nnp = Some(Err(err));
            let e = apply_single_threaded(&program(), &mut k).unwrap_err();
            assert_eq!(e.code, code);
            assert!(!k.calls.contains(&"set"));
        }
    }

    /// CORE-5: 正常系の呼び出し順と報告。
    #[test]
    fn core5_apply_seccomp_succeeds_in_order() {
        let p = program();
        let mut k = Fake::ok();
        let r = apply_single_threaded(&p, &mut k).unwrap();
        assert_eq!(r.instructions, p.len());
        assert_eq!(k.calls, vec!["threads", "nnp", "set", "mode", "threads"]);
    }

    /// CORE-5: 適用失敗の errno 写像。
    #[test]
    fn core5_apply_seccomp_maps_set_filter_errors() {
        for (err, code) in [
            (SysError::Os(EACCES), ErrorCode::PermissionDenied),
            (SysError::Os(EINVAL), ErrorCode::FailedPrecondition),
            (SysError::Unsupported, ErrorCode::Unimplemented),
        ] {
            let mut k = Fake::ok();
            k.set = Some(Err(err));
            let e = apply_single_threaded(&program(), &mut k).unwrap_err();
            assert_eq!(e.code, code);
            assert_eq!(e.stage, IsolationStage::Seccomp);
            assert!(!k.calls.contains(&"mode"));
        }
    }

    /// CORE-5: 読み戻しが filter モードでなければ Internal（fail-closed）。
    #[test]
    fn core5_apply_seccomp_fails_when_mode_not_filter() {
        let mut k = Fake::ok();
        k.mode = Some(Ok(0));
        let e = apply_single_threaded(&program(), &mut k).unwrap_err();
        assert_eq!(e.code, ErrorCode::Internal);
    }

    /// CORE-5: スレッド数の事前・事後検査。
    #[test]
    fn core5_apply_seccomp_requires_single_thread() {
        for threads in [vec![Some(2)], vec![None]] {
            let mut k = Fake::ok();
            k.threads = threads;
            let e = apply_single_threaded(&program(), &mut k).unwrap_err();
            assert_eq!(e.code, ErrorCode::FailedPrecondition);
            assert_eq!(k.calls, vec!["threads"]);
        }
        let mut k = Fake::ok();
        k.threads = vec![Some(1), Some(2)];
        let e = apply_single_threaded(&program(), &mut k).unwrap_err();
        assert_eq!(e.code, ErrorCode::Internal);
    }

    fn thread_status_field(field: &str) -> String {
        let status = std::fs::read_to_string("/proc/thread-self/status").unwrap();
        status
            .lines()
            .find_map(|l| l.strip_prefix(field))
            .unwrap_or_else(|| panic!("{field} missing"))
            .trim()
            .to_string()
    }

    /// CORE-5: 実 syscall（使い捨てスレッド。適用は不可逆・スレッド単位）。事後状態のみを照合する。
    #[test]
    fn core5_apply_seccomp_filter_real_thread() {
        std::thread::spawn(|| {
            let p = program();
            assert_eq!(sys::set_no_new_privs(), Ok(()));
            let report = apply_filter(&p, &mut RealKernel).unwrap();
            assert_eq!(report.instructions, p.len());
            assert_eq!(thread_status_field("Seccomp:"), "2");
            // 通常は成功する unshare(0) が、禁止 syscall として EPERM になる。
            assert_eq!(sys::unshare_namespaces(&[]), Err(SysError::Os(sys::EPERM)));
            // 禁止対象外の syscall は動作し続ける。
            let _ = sys::effective_uid();
        })
        .join()
        .unwrap();
    }

    /// CORE-5: NNP 未設定の実スレッドでは適用が FailedPrecondition。NNP が環境から継承済み（sandbox 等）
    /// の場合は前提検証を再現できないため照合しない。決定的なカバレッジは偽カーネルテストが担う。
    #[test]
    fn core5_apply_seccomp_without_nnp_real_thread() {
        std::thread::spawn(|| {
            if thread_status_field("NoNewPrivs:") == "0" {
                let e = apply_filter(&program(), &mut RealKernel).unwrap_err();
                assert_eq!(e.code, ErrorCode::FailedPrecondition);
                assert_eq!(e.stage, IsolationStage::Seccomp);
            }
        })
        .join()
        .unwrap();
    }
}

/// テスト用の偽物。本物の BPF 構築・syscall は呼ばない（libtest のスレッドへ不可逆のフィルタを載せないため）。
#[cfg(test)]
pub(super) mod testing {
    use std::cell::Cell;

    use super::{ExecError, SeccompReport};

    thread_local! {
        static SECCOMP_ERR: Cell<Option<ExecError>> = const { Cell::new(None) };
    }

    /// 次の 1 回だけ、`apply_default_seccomp` の偽物を失敗させる（使うと既定へ戻る）。
    pub(in crate::exec) fn fake_seccomp_err(e: ExecError) {
        SECCOMP_ERR.with(|c| c.set(Some(e)));
    }

    /// `stages.rs` の組み込み段が `cfg(test)` で呼ぶ偽物。
    pub(in crate::exec) fn apply_default_seccomp() -> Result<SeccompReport, ExecError> {
        crate::exec::no_new_privs::testing::rec("seccomp");
        match SECCOMP_ERR.with(Cell::take) {
            Some(e) => Err(e),
            None => Ok(SeccompReport { instructions: 0 }),
        }
    }
}
