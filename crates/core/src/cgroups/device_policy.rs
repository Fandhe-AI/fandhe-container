//! コンテナ用 cgroup への既定のデバイス許可プログラムの適用と、rootless では適用しない結果の返却
//! （TASK-32 追補・MS-2・#1680・SEC-1・CORE-1・CORE-4。関連: CORE-6・SEC-5・GPU-4・REPAIR-3・REPAIR-4）。
//!
//! # 役割
//! [`ContainerCgroup::apply_default_device_policy`] が入口。OCI default devices と pty だけを許可する
//! `BPF_PROG_TYPE_CGROUP_DEVICE` のプログラム（`device` サブモジュールの `DeviceProgram`。#1678）を、
//! `sys::bpf`（#1679）のラッパーでロード・アタッチし、`BPF_PROG_QUERY` で付いたことを照合する。
//! GPU 以外のコンテナでも許可リスト外のデバイスノードを開けなくするための層（SEC-1）。
//!
//! # 呼び出し文脈・契約
//! - 呼び出し元: 起動フロー。`IsolationPrivilege` から [`DevicePolicyMode`] を決める配線と launcher への結線は
//!   #1314（本 issue では未結線。REPAIR-3）。GPU の `deviceNodes` を足したプログラムでの再利用（#562）は、
//!   内部の `apply_device_policy_at` に別の `DeviceProgram` を渡す形で行う
//! - コンテナのプロセスが cgroup に入る（`CgroupJoin` 段）**前**に、cgroup を作った runtime 側のプロセスから
//!   呼ぶ。コンテナ側の seccomp は `bpf` を拒否するため、子プロセスからは呼べない
//! - 付けたプログラムは子孫の cgroup（exec 用の `exec-*`）にも効く。attach flags は 0 固定のため、子孫で
//!   上書きも追加もできない（子孫へのアタッチは `EPERM`）
//! - 1 つの cgroup につき 1 回だけ呼ぶ。同じ cgroup に flags 0 のプログラムがあるとアタッチは黙って置き換える
//!   ため、アタッチ前に問い合わせてプログラム数が 0 でなければ `FailedPrecondition` で拒否する
//!   （`open_child` が既存の cgroup を開き直す経路でも置き換えを検出するため。付けた後の問い合わせは
//!   置き換え後もどちらも数 1 を返し検出できない）
//! - `target_fd` には [`ContainerCgroup::as_fd`]（O_PATH）をそのまま渡す。`cgroup_get_from_fd` が `fdget_raw`
//!   を使うため通る（`sys::bpf` の一次情報）。開き直しや同一性の再確認はしない
//! - verifier ログ（PR #1705 事後監査 P3-4）: `message` と `Display` には入れず、1 行に整えた上限つきの
//!   写しを [`CgroupError::verifier_log`] に持たせる。呼び出し側は構造化ログへ 1 フィールドとして出し、
//!   CRI / MCP 等の外部応答には出さない
//! - 失敗は fail-closed で `Err`。途中で失敗しても付いたプログラムを外す後始末はしない（外すには
//!   `BPF_PROG_DETACH` の `sys` ラッパーが要り範囲外）。呼び出し側は `Err` を受けたらコンテナを起動せず
//!   cgroup を削除する（削除で外れる）。待機を伴わない同期 syscall のみのためタイムアウトは設けない
//! - `unsafe` は持たない（`sys::bpf` の安全な API だけを使う）
//!
//! # rootful / rootless
//! 経路は呼び出し元の申告 [`DevicePolicyMode`] で決め、`EPERM` を見て切り替えない（`exec` の
//! `DevptsGidSource` と同じ考え方）。rootful で `EPERM` が出たら `PermissionDenied` で失敗し、rootless
//! 扱いに縮退しない。ただし `DevptsGidSource` と違い、rootful なのに誤って `Rootless` を申告すると
//! デバイス cgroup が付かないまま root のコンテナが動き制限が緩む。#1314 の配線では、検証済みの権限モデル
//! （rootful の計画は euid 0 を要求し、rootless の計画は euid 0 を拒否する）からモードを決めること。
//! 整合ガードとして、`Rootless` を申告したのに euid が 0 なら何も呼ばず `FailedPrecondition` を返す。
//! BPF token を使わないため user namespace 内の capability ではロードできず、rootless では適用できない
//! （`sys::bpf` の一次情報）。
//!
//! # テスト
//! `cfg(test)` では `bpf(2)` を呼ばず、3 つの差し込み点（`device_prog_query` / `device_prog_load` /
//! `device_prog_attach`）が呼び出しを記録して差し込み値を返す。root で単体テストを走らせてもホストの
//! cgroup には届かない。このため lib の試験バイナリでは入口の本番経路（実際の `bpf(2)`）は通らず、
//! 入口の結合試験は `crates/core/tests/cgroup_device_policy_rootless.rs` / `cgroup_device_policy_rootful.rs`
//! （委譲 cgroup・root を要するため `#[ignore]` の実機前提テスト）に置く。

use std::os::fd::BorrowedFd;

use super::{
    CgroupError, CgroupStep, ContainerCgroup, DeviceAllowList, DeviceProgram, record_cgroup_op,
};
use crate::observability::OpRecorder;
use crate::sys::{self, SysError, bpf};
use crate::traits::ErrorCode;

/// [`OpRecorder`] に記録する操作名（REPAIR-4）。
const APPLY_DEFAULT_DEVICE_POLICY_OP_NAME: &str = "cgroup.apply_default_device_policy";

/// デバイス許可プログラムの適用経路。呼び出し元の申告で決まり、`EPERM` で切り替わらない。
///
/// 誤って `Rootless` を申告すると制限が緩む点に注意（モジュール doc の「rootful / rootless」）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DevicePolicyMode {
    /// init user namespace の root（`CAP_BPF`+`CAP_NET_ADMIN` か `CAP_SYS_ADMIN`）。ロード・アタッチする。
    Rootful,
    /// rootless。何も試さず [`DevicePolicyNotApplied::Rootless`] を返す。
    Rootless,
}

/// 適用結果。真偽値にせず、適用しなかった理由を型で返す（REPAIR-3）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DevicePolicyOutcome {
    /// ロード・アタッチし、事後検証（数 1・attach flags 0）に通った。
    Applied(AppliedDevicePolicy),
    /// 適用しなかった（失敗ではない）。
    NotApplied(DevicePolicyNotApplied),
}

/// 適用済みのプログラムの情報。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AppliedDevicePolicy {
    prog_id: u32,
    attach_flags: u32,
}

impl AppliedDevicePolicy {
    /// 事後問い合わせが返したプログラム ID（実機照合・ログ用）。
    pub fn prog_id(&self) -> u32 {
        self.prog_id
    }

    /// 事後問い合わせが返した attach flags（検証済みで常に 0）。
    pub fn attach_flags(&self) -> u32 {
        self.attach_flags
    }
}

/// 適用しなかった理由。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DevicePolicyNotApplied {
    /// rootless のため適用しない（user namespace 内の capability では `bpf(2)` のロードができない。SEC-5）。
    Rootless,
}

impl ContainerCgroup {
    /// コンテナ用 cgroup に既定のデバイス許可プログラム（OCI default devices と pty のみ許可）を付ける。
    ///
    /// `Rootful` ではアタッチ前の問い合わせ（既存プログラムがあれば拒否）→ ロード → アタッチ（flags 0）→
    /// 事後問い合わせの照合を行う。`Rootless` では何も呼ばず `Ok(NotApplied(Rootless))` を返す（記録上は
    /// 成功）。`Rootless` なのに euid が 0 なら `FailedPrecondition`。契約と失敗時の扱いはモジュール doc。
    ///
    /// どの段で失敗しても成否と所要時間を `recorder` へ操作名 `cgroup.apply_default_device_policy` で
    /// 記録する（REPAIR-4。`set_pids_max` と同じ形）。
    pub fn apply_default_device_policy(
        &self,
        recorder: &OpRecorder,
        mode: DevicePolicyMode,
    ) -> Result<DevicePolicyOutcome, CgroupError> {
        apply_device_policy_recorded(self.as_fd(), recorder, mode, sys::effective_uid())
    }
}

/// [`apply_device_policy_at`] を計測つきで実行する（テスト可能な実体。euid を差し込める）。
fn apply_device_policy_recorded(
    dir: BorrowedFd<'_>,
    recorder: &OpRecorder,
    mode: DevicePolicyMode,
    euid: u32,
) -> Result<DevicePolicyOutcome, CgroupError> {
    record_cgroup_op(
        recorder,
        APPLY_DEFAULT_DEVICE_POLICY_OP_NAME,
        CgroupStep::DeviceCgroupPolicy,
        || {
            // rootless は命令列を組み立てずに返す（何も呼ばない）。
            if mode == DevicePolicyMode::Rootless {
                return rootless_outcome(euid);
            }
            let program = DeviceProgram::from_allow_list(&DeviceAllowList::oci_default())?;
            apply_device_policy_at(dir, mode, euid, &program)
        },
    )
}

/// rootless の結果。euid 0 は申告の誤りなので拒否する（モジュール doc の整合ガード）。
fn rootless_outcome(euid: u32) -> Result<DevicePolicyOutcome, CgroupError> {
    if euid == 0 {
        return Err(CgroupError::precondition(
            CgroupStep::DeviceCgroupPolicy,
            "rootless device policy was requested but the effective uid is 0 (mode/privilege mismatch)",
        ));
    }
    Ok(DevicePolicyOutcome::NotApplied(
        DevicePolicyNotApplied::Rootless,
    ))
}

/// `program` を `cgroup` に付ける本体。#562（GPU の許可リスト追加）が別の `DeviceProgram` を渡して再利用する。
fn apply_device_policy_at(
    cgroup: BorrowedFd<'_>,
    mode: DevicePolicyMode,
    euid: u32,
    program: &DeviceProgram,
) -> Result<DevicePolicyOutcome, CgroupError> {
    if mode == DevicePolicyMode::Rootless {
        return rootless_outcome(euid);
    }
    let pre = device_prog_query(cgroup).map_err(|e| {
        bpf_sys_error(
            CgroupStep::QueryDeviceProgram,
            "BPF_PROG_QUERY (pre-attach)",
            e,
            QUERY_EPERM_HINT,
        )
    })?;
    verify_pre_attach(&pre)?;
    let prog = device_prog_load(program).map_err(|e| bpf_load_error(&e))?;
    device_prog_attach(cgroup, &prog).map_err(|e| {
        bpf_sys_error(
            CgroupStep::AttachDeviceProgram,
            "BPF_PROG_ATTACH",
            e,
            ATTACH_EPERM_HINT,
        )
    })?;
    // cgroup 側が参照を持つため、prog fd を閉じても外れない。
    drop(prog);
    let post = device_prog_query(cgroup).map_err(|e| {
        bpf_sys_error(
            CgroupStep::VerifyDeviceProgram,
            "BPF_PROG_QUERY (post-attach)",
            e,
            QUERY_EPERM_HINT,
        )
    })?;
    verify_post_attach(&post).map(DevicePolicyOutcome::Applied)
}

const QUERY_EPERM_HINT: &str =
    " (missing CAP_NET_ADMIN or CAP_SYS_ADMIN in the init user namespace)";
const ATTACH_EPERM_HINT: &str =
    " (missing capability, or an ancestor cgroup already holds a flags-0 device program)";

/// アタッチ前の照合: 既存プログラムがあれば拒否する（黙って置き換えない）。
fn verify_pre_attach(q: &bpf::CgroupDeviceQuery) -> Result<(), CgroupError> {
    if q.prog_count() != 0 {
        return Err(CgroupError::precondition(
            CgroupStep::QueryDeviceProgram,
            format!(
                "the cgroup already has {} device program(s) (attach flags {}); refusing to replace",
                q.prog_count(),
                q.attach_flags()
            ),
        ));
    }
    Ok(())
}

/// アタッチ後の照合: プログラム数 1・attach flags 0 でなければ `FailedPrecondition`。
fn verify_post_attach(q: &bpf::CgroupDeviceQuery) -> Result<AppliedDevicePolicy, CgroupError> {
    let step = CgroupStep::VerifyDeviceProgram;
    if q.prog_count() != 1 || q.attach_flags() != bpf::DEVICE_ATTACH_FLAGS {
        return Err(CgroupError::precondition(
            step,
            format!(
                "unexpected device program state after attach: count {} (want 1), attach flags {} (want {})",
                q.prog_count(),
                q.attach_flags(),
                bpf::DEVICE_ATTACH_FLAGS
            ),
        ));
    }
    let prog_id = q.prog_ids().first().copied().ok_or_else(|| {
        CgroupError::precondition(step, "BPF_PROG_QUERY returned no program id after attach")
    })?;
    Ok(AppliedDevicePolicy {
        prog_id,
        attach_flags: q.attach_flags(),
    })
}

/// `bpf(2)` の errno を `CgroupError` へ写す（既存の `sys_error` は `EINVAL`・`ENOSYS` を `Internal` に
/// 写すため使わない）。`EINVAL`・`ENOSYS` は「カーネルが対応していない」ので `Unimplemented`。
fn bpf_sys_error(step: CgroupStep, what: &str, err: SysError, eperm_hint: &str) -> CgroupError {
    let (code, message) = match err {
        SysError::Unsupported => (
            ErrorCode::Unimplemented,
            format!("{what}: unsupported architecture"),
        ),
        SysError::MultiThreaded => (
            ErrorCode::FailedPrecondition,
            format!("{what}: multi-threaded process"),
        ),
        SysError::Os(e) if e == sys::ENOSYS || e == sys::EINVAL => (
            ErrorCode::Unimplemented,
            format!(
                "{what}: errno {e} (bpf(2), CONFIG_CGROUP_BPF or this program type is not supported)"
            ),
        ),
        SysError::Os(e) if e == sys::EPERM => (
            ErrorCode::PermissionDenied,
            format!("{what}: errno {e}{eperm_hint}"),
        ),
        SysError::Os(e) if e == sys::EACCES => {
            (ErrorCode::PermissionDenied, format!("{what}: errno {e}"))
        }
        SysError::Os(e) if e == sys::ENOSPC => (
            ErrorCode::FailedPrecondition,
            format!("{what}: errno {e} (too many programs attached)"),
        ),
        SysError::Os(e) => (ErrorCode::Internal, format!("{what}: errno {e}")),
    };
    CgroupError::new(code, step, message)
}

/// `BPF_PROG_LOAD` の失敗を写す。verifier がログつきで拒否した場合は本リポの命令列の不具合（`Internal`）。
/// ログは `message` に入れず [`CgroupError::verifier_log`] に持たせる（モジュール doc の「verifier ログ」）。
fn bpf_load_error(e: &bpf::BpfProgLoadError) -> CgroupError {
    let step = CgroupStep::LoadDeviceProgram;
    if let (SysError::Os(errno), Some(log)) = (e.cause, e.verifier_log.as_deref())
        && (errno == sys::EINVAL || errno == sys::EACCES)
    {
        return CgroupError::new(
            ErrorCode::Internal,
            step,
            format!(
                "BPF_PROG_LOAD: errno {errno}: the verifier rejected the device program \
                 (verifier log withheld from this message)"
            ),
        )
        .with_verifier_log(log);
    }
    bpf_sys_error(step, "BPF_PROG_LOAD", e.cause, QUERY_EPERM_HINT)
}

// ---------------------------------------------------------------------------------------------
// 差し込み点（本番は sys::bpf を呼ぶ。cfg(test) では記録して差し込み値を返す）
// ---------------------------------------------------------------------------------------------

#[cfg(not(test))]
fn device_prog_query(cgroup: BorrowedFd<'_>) -> Result<bpf::CgroupDeviceQuery, SysError> {
    bpf::bpf_prog_query_cgroup_device(cgroup)
}

#[cfg(not(test))]
fn device_prog_load(
    program: &DeviceProgram,
) -> Result<bpf::CgroupDeviceProgFd, bpf::BpfProgLoadError> {
    bpf::bpf_prog_load_cgroup_device(program)
}

#[cfg(not(test))]
fn device_prog_attach(
    cgroup: BorrowedFd<'_>,
    prog: &bpf::CgroupDeviceProgFd,
) -> Result<(), SysError> {
    bpf::bpf_prog_attach_cgroup_device(cgroup, prog)
}

#[cfg(test)]
fn device_prog_query(cgroup: BorrowedFd<'_>) -> Result<bpf::CgroupDeviceQuery, SysError> {
    dry_run::query(cgroup)
}

#[cfg(test)]
fn device_prog_load(
    program: &DeviceProgram,
) -> Result<bpf::CgroupDeviceProgFd, bpf::BpfProgLoadError> {
    dry_run::load(program)
}

#[cfg(test)]
fn device_prog_attach(
    cgroup: BorrowedFd<'_>,
    prog: &bpf::CgroupDeviceProgFd,
) -> Result<(), SysError> {
    dry_run::attach(cgroup, prog)
}

/// 試験専用の dry-run。呼び出しをスレッドローカルへ記録し、差し込み値（`BpfScript`）を返す。
#[cfg(test)]
mod dry_run {
    use super::*;
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::os::fd::{AsRawFd as _, OwnedFd, RawFd};

    /// 記録する呼び出し。`prog_type` 等は `sys::bpf` の中で固定された定数で、配線の確認に使う。
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(super) enum BpfCall {
        Query {
            target_fd: RawFd,
            attach_type: u32,
        },
        Load {
            prog_type: u32,
            expected_attach_type: u32,
            insn_cnt: usize,
        },
        Attach {
            target_fd: RawFd,
            attach_type: u32,
            attach_flags: u32,
        },
    }

    /// 呼び出しごとに返す値。既定はすべて成功（事前問い合わせは数 0、事後は数 1・flags 0・ID 42）。
    #[derive(Debug, Clone)]
    pub(super) struct BpfScript {
        pub(super) queries: VecDeque<Result<bpf::CgroupDeviceQuery, SysError>>,
        pub(super) load: Result<(), bpf::BpfProgLoadError>,
        pub(super) attach: Result<(), SysError>,
    }

    impl Default for BpfScript {
        fn default() -> Self {
            Self {
                queries: VecDeque::from([
                    Ok(bpf::CgroupDeviceQuery::new_for_test(0, 0, &[])),
                    Ok(bpf::CgroupDeviceQuery::new_for_test(0, 1, &[42])),
                ]),
                load: Ok(()),
                attach: Ok(()),
            }
        }
    }

    thread_local! {
        static CALLS: RefCell<Vec<BpfCall>> = const { RefCell::new(Vec::new()) };
        static SCRIPT: RefCell<Option<BpfScript>> = const { RefCell::new(None) };
    }

    /// 差し込み値を保持するガード。drop（panic の巻き戻しを含む）で記録と差し込みを空に戻し、
    /// 再利用されるテストスレッドへ前の試験の値を残さない。
    #[must_use = "the script is cleared when the guard is dropped"]
    pub(super) struct ScriptGuard(());

    impl Drop for ScriptGuard {
        fn drop(&mut self) {
            CALLS.with(|c| c.borrow_mut().clear());
            SCRIPT.with(|s| *s.borrow_mut() = None);
        }
    }

    pub(super) fn install(script: BpfScript) -> ScriptGuard {
        CALLS.with(|c| c.borrow_mut().clear());
        SCRIPT.with(|s| *s.borrow_mut() = Some(script));
        ScriptGuard(())
    }

    /// 記録を取り出して消す。
    pub(super) fn take_calls() -> Vec<BpfCall> {
        CALLS.with(|c| std::mem::take(&mut *c.borrow_mut()))
    }

    fn record(call: BpfCall) {
        CALLS.with(|c| c.borrow_mut().push(call));
    }

    fn with_script<T>(f: impl FnOnce(&mut BpfScript) -> T) -> T {
        SCRIPT.with(|s| {
            let mut guard = s.borrow_mut();
            f(guard.get_or_insert_with(BpfScript::default))
        })
    }

    pub(super) fn query(cgroup: BorrowedFd<'_>) -> Result<bpf::CgroupDeviceQuery, SysError> {
        record(BpfCall::Query {
            target_fd: cgroup.as_raw_fd(),
            attach_type: bpf::DEVICE_ATTACH_TYPE,
        });
        with_script(|s| {
            s.queries
                .pop_front()
                .unwrap_or(Err(SysError::Os(sys::EINVAL)))
        })
    }

    pub(super) fn load(
        program: &DeviceProgram,
    ) -> Result<bpf::CgroupDeviceProgFd, bpf::BpfProgLoadError> {
        record(BpfCall::Load {
            prog_type: bpf::DEVICE_PROG_TYPE,
            expected_attach_type: bpf::DEVICE_ATTACH_TYPE,
            insn_cnt: program.len(),
        });
        with_script(|s| s.load.clone())?;
        let fd = std::fs::File::open("/dev/null")
            .map(OwnedFd::from)
            .map_err(|_| bpf::BpfProgLoadError {
                cause: SysError::Os(sys::EINVAL),
                verifier_log: None,
            })?;
        Ok(bpf::CgroupDeviceProgFd::from_fd_for_test(fd))
    }

    pub(super) fn attach(
        cgroup: BorrowedFd<'_>,
        _prog: &bpf::CgroupDeviceProgFd,
    ) -> Result<(), SysError> {
        record(BpfCall::Attach {
            target_fd: cgroup.as_raw_fd(),
            attach_type: bpf::DEVICE_ATTACH_TYPE,
            attach_flags: bpf::DEVICE_ATTACH_FLAGS,
        });
        with_script(|s| s.attach)
    }
}

#[cfg(all(test, any(target_arch = "x86_64", target_arch = "aarch64")))]
mod tests {
    use super::dry_run::{BpfCall, BpfScript, install, take_calls};
    use super::*;
    use crate::cgroups::CgroupName;
    use crate::observability::OpName;
    use crate::traits::ContainerId;
    use std::collections::VecDeque;
    use std::fs::File;
    use std::os::fd::{AsFd as _, AsRawFd as _, OwnedFd};

    type Q = Result<bpf::CgroupDeviceQuery, SysError>;
    /// (ラベル, 差し込み値, モード, euid, 期待する (成功, 失敗) 件数)
    type RecordedCase = (&'static str, BpfScript, DevicePolicyMode, u32, (u64, u64));

    fn q(flags: u32, count: u32, ids: &[u32]) -> Q {
        Ok(bpf::CgroupDeviceQuery::new_for_test(flags, count, ids))
    }

    fn script_with_post(post: Q) -> BpfScript {
        BpfScript {
            queries: VecDeque::from([q(0, 0, &[]), post]),
            ..BpfScript::default()
        }
    }

    fn dir() -> File {
        File::open(std::env::temp_dir()).unwrap()
    }

    fn insn_count() -> usize {
        DeviceProgram::from_allow_list(&DeviceAllowList::oci_default())
            .unwrap()
            .len()
    }

    fn run(mode: DevicePolicyMode, euid: u32) -> (Result<DevicePolicyOutcome, CgroupError>, i32) {
        let d = dir();
        let fd = d.as_raw_fd();
        let r = apply_device_policy_recorded(d.as_fd(), &OpRecorder::new(), mode, euid);
        (r, fd)
    }

    fn err_of(r: Result<DevicePolicyOutcome, CgroupError>) -> (ErrorCode, CgroupStep) {
        let e = r.unwrap_err();
        (e.code, e.step)
    }

    /// SEC-1・CORE-4・TASK-32: rootful の呼び出し列と結果の完全一致。先頭の事前問い合わせは「既存プログラムを
    /// 黙って置き換えない」ための追加（#1680 の設計判断）で、ロード・アタッチ・事後問い合わせは要求どおりの順。
    /// 15・6・0 は `sys::bpf` 側で固定された値の配線確認（値そのものは bpf.rs の試験で照合済み）。
    #[test]
    fn sec1_core4_task32_rootful_call_sequence_is_exact() {
        let _g = install(BpfScript::default());
        let (r, fd) = run(DevicePolicyMode::Rootful, 0);
        assert_eq!(
            take_calls(),
            vec![
                BpfCall::Query {
                    target_fd: fd,
                    attach_type: 6
                },
                BpfCall::Load {
                    prog_type: 15,
                    expected_attach_type: 6,
                    insn_cnt: insn_count()
                },
                BpfCall::Attach {
                    target_fd: fd,
                    attach_type: 6,
                    attach_flags: 0
                },
                BpfCall::Query {
                    target_fd: fd,
                    attach_type: 6
                },
            ]
        );
        let Ok(DevicePolicyOutcome::Applied(applied)) = r else {
            panic!("expected Applied, got {r:?}");
        };
        assert_eq!((applied.prog_id(), applied.attach_flags()), (42, 0));
    }

    /// SEC-1・TASK-32: 事後問い合わせが想定外なら成功扱いにしない。
    #[test]
    fn sec1_task32_post_query_mismatch_fails_closed() {
        for post in [
            q(0, 0, &[]),
            q(0, 2, &[1, 2]),
            q(2, 1, &[42]),
            q(1, 1, &[42]),
        ] {
            let _g = install(script_with_post(post.clone()));
            let (r, _) = run(DevicePolicyMode::Rootful, 0);
            assert_eq!(
                err_of(r),
                (
                    ErrorCode::FailedPrecondition,
                    CgroupStep::VerifyDeviceProgram
                ),
                "{post:?}"
            );
        }
    }

    /// SEC-1・TASK-32: 既存プログラムがあれば置き換えず、ロードもしない。
    #[test]
    fn sec1_task32_preexisting_program_is_rejected() {
        let _g = install(BpfScript {
            queries: VecDeque::from([q(0, 1, &[7])]),
            ..BpfScript::default()
        });
        let (r, fd) = run(DevicePolicyMode::Rootful, 0);
        assert_eq!(
            err_of(r),
            (
                ErrorCode::FailedPrecondition,
                CgroupStep::QueryDeviceProgram
            )
        );
        assert_eq!(
            take_calls(),
            vec![BpfCall::Query {
                target_fd: fd,
                attach_type: 6
            }]
        );
    }

    /// SEC-1・CORE-6・TASK-32: rootless は何も呼ばず `NotApplied(Rootless)`。
    #[test]
    fn sec1_core6_task32_rootless_is_not_applied() {
        let _g = install(BpfScript::default());
        let (r, _) = run(DevicePolicyMode::Rootless, 1000);
        assert_eq!(
            r,
            Ok(DevicePolicyOutcome::NotApplied(
                DevicePolicyNotApplied::Rootless
            ))
        );
        assert_eq!(take_calls(), vec![]);
    }

    /// SEC-1・SEC-5・TASK-32: rootless と申告したのに euid 0 は申告の誤りとして拒否する。
    #[test]
    fn sec1_sec5_task32_rootless_with_euid0_is_rejected() {
        let _g = install(BpfScript::default());
        let (r, _) = run(DevicePolicyMode::Rootless, 0);
        assert_eq!(
            err_of(r),
            (
                ErrorCode::FailedPrecondition,
                CgroupStep::DeviceCgroupPolicy
            )
        );
        assert_eq!(take_calls(), vec![]);
    }

    /// SEC-1・TASK-32: rootful のロードの `EPERM` は rootless 扱いに縮退せず `PermissionDenied`。
    #[test]
    fn sec1_task32_rootful_load_eperm_is_permission_denied() {
        let _g = install(BpfScript {
            load: Err(bpf::BpfProgLoadError {
                cause: SysError::Os(sys::EPERM),
                verifier_log: None,
            }),
            ..BpfScript::default()
        });
        let (r, fd) = run(DevicePolicyMode::Rootful, 1000);
        assert_eq!(
            err_of(r),
            (ErrorCode::PermissionDenied, CgroupStep::LoadDeviceProgram)
        );
        let calls = take_calls();
        assert_eq!(calls.len(), 2);
        assert_eq!(
            calls.first(),
            Some(&BpfCall::Query {
                target_fd: fd,
                attach_type: 6
            })
        );
    }

    /// SEC-1・TASK-32: ロードの errno の写像（verifier ログの有無で `Internal` / `Unimplemented`）。
    #[test]
    fn sec1_task32_load_enosys_einval_unsupported_are_unimplemented() {
        for cause in [
            SysError::Os(sys::ENOSYS),
            SysError::Os(sys::EINVAL),
            SysError::Unsupported,
        ] {
            let _g = install(BpfScript {
                load: Err(bpf::BpfProgLoadError {
                    cause,
                    verifier_log: None,
                }),
                ..BpfScript::default()
            });
            let (r, _) = run(DevicePolicyMode::Rootful, 0);
            assert_eq!(
                err_of(r),
                (ErrorCode::Unimplemented, CgroupStep::LoadDeviceProgram),
                "{cause:?}"
            );
        }
        let _g = install(BpfScript {
            load: Err(bpf::BpfProgLoadError {
                cause: SysError::Os(sys::EINVAL),
                verifier_log: Some("R0 !read_ok".to_owned()),
            }),
            ..BpfScript::default()
        });
        let (r, _) = run(DevicePolicyMode::Rootful, 0);
        let e = r.unwrap_err();
        assert_eq!(
            (e.code, e.step),
            (ErrorCode::Internal, CgroupStep::LoadDeviceProgram)
        );
        // verifier ログは外部応答に出しうる message へ入れず、別の口で持つ（PR #1705 事後監査 P3-4）。
        assert_eq!(
            e.message,
            "BPF_PROG_LOAD: errno 22: the verifier rejected the device program \
             (verifier log withheld from this message)"
        );
        assert_eq!(e.verifier_log(), Some("R0 !read_ok"));
        assert!(!e.to_string().contains("R0 !read_ok"), "{e}");
    }

    /// SEC-1・TASK-32: アタッチ・問い合わせの errno の写像。
    #[test]
    fn sec1_task32_attach_and_query_errno_mapping() {
        let cases: [(BpfScript, ErrorCode, CgroupStep); 4] = [
            (
                BpfScript {
                    attach: Err(SysError::Os(sys::EPERM)),
                    ..BpfScript::default()
                },
                ErrorCode::PermissionDenied,
                CgroupStep::AttachDeviceProgram,
            ),
            (
                BpfScript {
                    attach: Err(SysError::Os(sys::EINVAL)),
                    ..BpfScript::default()
                },
                ErrorCode::Unimplemented,
                CgroupStep::AttachDeviceProgram,
            ),
            (
                BpfScript {
                    queries: VecDeque::from([Err(SysError::Os(sys::EPERM))]),
                    ..BpfScript::default()
                },
                ErrorCode::PermissionDenied,
                CgroupStep::QueryDeviceProgram,
            ),
            (
                script_with_post(Err(SysError::Os(sys::ENOSPC))),
                ErrorCode::FailedPrecondition,
                CgroupStep::VerifyDeviceProgram,
            ),
        ];
        for (script, code, step) in cases {
            let _g = install(script);
            let (r, _) = run(DevicePolicyMode::Rootful, 0);
            assert_eq!(err_of(r), (code, step));
        }
    }

    /// REPAIR-4・TASK-32: 全経路が `cgroup.apply_default_device_policy` へ成否つきで記録される。
    #[test]
    fn repair4_task32_device_policy_operations_are_recorded() {
        let name = OpName::new("cgroup.apply_default_device_policy").unwrap();
        let scripts: Vec<RecordedCase> = vec![
            (
                "ok",
                BpfScript::default(),
                DevicePolicyMode::Rootful,
                0,
                (1, 0),
            ),
            (
                "rootless",
                BpfScript::default(),
                DevicePolicyMode::Rootless,
                1000,
                (1, 0),
            ),
            (
                "load eperm",
                BpfScript {
                    load: Err(bpf::BpfProgLoadError {
                        cause: SysError::Os(sys::EPERM),
                        verifier_log: None,
                    }),
                    ..BpfScript::default()
                },
                DevicePolicyMode::Rootful,
                0,
                (0, 1),
            ),
            (
                "post mismatch",
                script_with_post(q(0, 0, &[])),
                DevicePolicyMode::Rootful,
                0,
                (0, 1),
            ),
            (
                "preexisting",
                BpfScript {
                    queries: VecDeque::from([q(0, 1, &[7])]),
                    ..BpfScript::default()
                },
                DevicePolicyMode::Rootful,
                0,
                (0, 1),
            ),
            (
                "rootless euid0",
                BpfScript::default(),
                DevicePolicyMode::Rootless,
                0,
                (0, 1),
            ),
        ];
        for (label, script, mode, euid, want) in scripts {
            let _g = install(script);
            let rec = OpRecorder::new();
            let d = dir();
            drop(apply_device_policy_recorded(d.as_fd(), &rec, mode, euid));
            let stats = rec.snapshot_op(&name).expect("recorded");
            assert_eq!((stats.success(), stats.failure()), want, "{label}");
            assert!(
                rec.snapshot_op(&OpName::new("cgroup.set_pids_max").unwrap())
                    .is_none(),
                "{label}"
            );
        }
    }

    /// SEC-1・TASK-32: 公開入口は euid に関わらず dry-run に届く（ホストの cgroup に `bpf(2)` は届かない）。
    #[test]
    fn sec1_task32_public_entry_uses_dry_run() {
        let _g = install(BpfScript::default());
        let d = File::open(std::env::temp_dir()).unwrap();
        let fd = d.as_raw_fd();
        let cg = ContainerCgroup::from_dir_for_test(
            CgroupName::new(&ContainerId::new("t").unwrap()).unwrap(),
            OwnedFd::from(d),
        );
        let r = cg.apply_default_device_policy(&OpRecorder::new(), DevicePolicyMode::Rootful);
        assert!(matches!(r, Ok(DevicePolicyOutcome::Applied(_))), "{r:?}");
        assert_eq!(take_calls().len(), 4);
        assert_eq!(cg.as_fd().as_raw_fd(), fd);
    }
}
