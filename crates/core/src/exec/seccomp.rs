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

/// [`observe_default_seccomp_enforcement`] の観測結果。errno は `Err(SysError::Os(n))` の `n`、成功は `None`。
#[doc(hidden)]
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SeccompEnforcementObservation {
    /// 適用前の `unshare(0)`（対照。フラグなしのため通常は成功し `None`）。
    pub unshare_before: Option<i32>,
    /// 適用した BPF 命令数。
    pub instructions: usize,
    /// 適用後の `/proc/thread-self/status` の `Seccomp:` 値（filter モードは `2`）。
    pub seccomp_mode: String,
    /// 適用後の `unshare(0)` の errno（禁止 syscall のため `EPERM`）。
    pub unshare_after: Option<i32>,
    /// 適用後の `mount` 系（`mount(MS_REC|MS_PRIVATE)`）の errno。
    pub mount_after: Option<i32>,
    /// 適用後の `pivot_root` の errno。
    pub pivot_root_after: Option<i32>,
    /// 適用後の `umount2` の errno。
    pub umount_after: Option<i32>,
}

/// 本番の適用経路（[`apply_default_seccomp`]）を呼び出しスレッドへ適用し、禁止 syscall の遮断を観測する
/// （CORE-5・TASK-38.3・#178。結合試験専用）。
///
/// 適用は不可逆・呼び出しスレッド単位で、単一スレッド（`Threads: 1`）を要するため、結合試験
/// `tests/seccomp_enforcement.rs`（`harness = false` の単一スレッド `main`）から、使い捨ての子プロセス
/// の中で呼ぶ。`unsafe` を `sys` の外へ出さないため、syscall の発行はこの関数が肩代わりする。
/// 通常の利用者は呼ばない（起動フローは組み込み段 `StageKind::Seccomp` が適用する）。
/// `NO_NEW_PRIVS` の設定に失敗、または適用に失敗したら `Err`。
#[doc(hidden)]
pub fn observe_default_seccomp_enforcement() -> Result<SeccompEnforcementObservation, ExecError> {
    fn errno(r: Result<(), SysError>) -> Option<i32> {
        match r {
            Ok(()) => None,
            Err(SysError::Os(n)) => Some(n),
            Err(_) => Some(-1),
        }
    }
    let fail =
        |m: &str| ExecError::new(ErrorCode::Internal, IsolationStage::Seccomp, m.to_string());
    sys::set_no_new_privs().map_err(|_| fail("failed to set no_new_privs"))?;
    let unshare_before = errno(sys::unshare_namespaces(&[]));
    let report = apply_default_seccomp()?;
    let status = std::fs::read_to_string("/proc/thread-self/status")
        .map_err(|_| fail("failed to read thread status"))?;
    let seccomp_mode = status
        .lines()
        .find_map(|l| l.strip_prefix("Seccomp:"))
        .map(|v| v.trim().to_string())
        .ok_or_else(|| fail("Seccomp field missing"))?;
    Ok(SeccompEnforcementObservation {
        unshare_before,
        instructions: report.instructions,
        seccomp_mode,
        unshare_after: errno(sys::unshare_namespaces(&[])),
        mount_after: errno(sys::mount_root_private_recursive()),
        pivot_root_after: errno(sys::pivot_root_dot()),
        umount_after: errno(sys::umount_cwd_detach()),
    })
}

/// コンテナ内プローブの 1 syscall 分の結果。成功は [`ProbeOutcome::Ok`]、失敗は errno。
#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeOutcome {
    /// syscall が成功した（遮断されていない）。
    Ok,
    /// syscall が errno で失敗した（`EPERM` = 1 なら seccomp の遮断、または capability 不足）。
    Errno(i32),
    /// 対応外アーキテクチャで syscall を発行できなかった（[`SysError::Unsupported`]）。
    Unsupported,
    /// errno を伴わない失敗（プローブ自体の読み出し失敗など）。遮断とは区別する。
    Failed,
}

impl ProbeOutcome {
    fn from_result(r: Result<(), SysError>) -> Self {
        match r {
            Ok(()) => ProbeOutcome::Ok,
            Err(SysError::Os(n)) => ProbeOutcome::Errno(n),
            Err(SysError::Unsupported) => ProbeOutcome::Unsupported,
            Err(_) => ProbeOutcome::Failed,
        }
    }

    fn render(self) -> String {
        match self {
            ProbeOutcome::Ok => "ok".to_string(),
            ProbeOutcome::Errno(n) => format!("errno={n}"),
            ProbeOutcome::Unsupported => "unsupported".to_string(),
            ProbeOutcome::Failed => "failed".to_string(),
        }
    }

    fn parse(v: &str) -> Result<Self, String> {
        match v {
            "ok" => return Ok(ProbeOutcome::Ok),
            "unsupported" => return Ok(ProbeOutcome::Unsupported),
            "failed" => return Ok(ProbeOutcome::Failed),
            _ => {}
        }
        v.strip_prefix("errno=")
            .and_then(|n| n.parse::<i32>().ok())
            .map(ProbeOutcome::Errno)
            .ok_or_else(|| format!("invalid outcome {v:?}"))
    }
}

/// コンテナ内（組み込み `Seccomp` 段の通過後）で観測した禁止 syscall の遮断記録（CORE-5・TASK-38.4・#179）。
///
/// [`spawn_container_seccomp_probe`](super::spawn_container_seccomp_probe) の子が `probe_denied_syscalls`
/// で作り、pivot 後の `/seccomp-probe` へ `key=value` 行で書く。親（結合試験 `tests/seccomp.rs`）が
/// [`SeccompProbeRecord::parse`] で読む。識別的な検査は `unshare`・`ptrace`・`seccomp_mode`、網羅確認は
/// `mount`・`pivot_root`・`umount2`・`kexec_load`（capability 不足でも `EPERM` になり得る）。
#[doc(hidden)]
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SeccompProbeRecord {
    /// `unshare(0)`。フィルタが無ければ成功、有れば `EPERM`（識別的）。
    pub unshare: ProbeOutcome,
    /// `ptrace(PTRACE_CONT, 自 pid)`。フィルタが無ければ `ESRCH`、有れば `EPERM`（識別的）。
    pub ptrace: ProbeOutcome,
    /// `/proc/thread-self/status` の `Seccomp:` 値（filter モードは `2`）。
    pub seccomp_mode: String,
    /// 禁止対象外の対照。`/proc/thread-self/status` を読めること（`openat`・`read` が動く）。
    pub control: ProbeOutcome,
    /// `mount(MS_REC|MS_PRIVATE)`（網羅確認）。
    pub mount: ProbeOutcome,
    /// `pivot_root(".", ".")`（網羅確認）。
    pub pivot_root: ProbeOutcome,
    /// `umount2(".", MNT_DETACH)`（網羅確認）。
    pub umount2: ProbeOutcome,
    /// 無効引数の `kexec_load`（網羅確認）。
    pub kexec_load: ProbeOutcome,
}

/// 記録のキー（直列化・解析で共通。増減時は [`SeccompProbeRecord`] と同時に直す）。
const PROBE_KEYS: [&str; 8] = [
    "unshare",
    "ptrace",
    "seccomp_mode",
    "control",
    "mount",
    "pivot_root",
    "umount2",
    "kexec_load",
];

impl SeccompProbeRecord {
    /// 英語の `key=value` 行（改行区切り）へ直列化する。
    pub fn render(&self) -> String {
        format!(
            "unshare={}\nptrace={}\nseccomp_mode={}\ncontrol={}\nmount={}\npivot_root={}\numount2={}\nkexec_load={}\n",
            self.unshare.render(),
            self.ptrace.render(),
            self.seccomp_mode,
            self.control.render(),
            self.mount.render(),
            self.pivot_root.render(),
            self.umount2.render(),
            self.kexec_load.render(),
        )
    }

    /// [`render`](Self::render) の出力を解析する。外部入力として扱い、未知キー・重複キー・欠落・
    /// 不正値はすべて `Err`（パニックしない）。
    pub fn parse(text: &str) -> Result<Self, String> {
        let mut map: std::collections::BTreeMap<&str, &str> = std::collections::BTreeMap::new();
        for line in text.lines() {
            let (k, v) = line
                .split_once('=')
                .ok_or_else(|| format!("malformed line {line:?}"))?;
            if !PROBE_KEYS.contains(&k) {
                return Err(format!("unknown key {k:?}"));
            }
            if map.insert(k, v).is_some() {
                return Err(format!("duplicate key {k:?}"));
            }
        }
        let get = |k: &str| -> Result<&str, String> {
            map.get(k)
                .copied()
                .ok_or_else(|| format!("missing key {k:?}"))
        };
        let seccomp_mode = get("seccomp_mode")?;
        if seccomp_mode.is_empty() || !seccomp_mode.bytes().all(|b| b.is_ascii_digit()) {
            return Err(format!("invalid seccomp_mode {seccomp_mode:?}"));
        }
        Ok(SeccompProbeRecord {
            unshare: ProbeOutcome::parse(get("unshare")?)?,
            ptrace: ProbeOutcome::parse(get("ptrace")?)?,
            seccomp_mode: seccomp_mode.to_string(),
            control: ProbeOutcome::parse(get("control")?)?,
            mount: ProbeOutcome::parse(get("mount")?)?,
            pivot_root: ProbeOutcome::parse(get("pivot_root")?)?,
            umount2: ProbeOutcome::parse(get("umount2")?)?,
            kexec_load: ProbeOutcome::parse(get("kexec_load")?)?,
        })
    }
}

/// 組み込み `Seccomp` 段の通過後に禁止 syscall を呼んで遮断を記録する（CORE-5・TASK-38.4・#179）。
///
/// `process.rs::spawn_container_seccomp_probe` の子（コンテナの PID 1・pivot 済み）が、ステージ列の
/// 終端として exec の代わりに呼ぶ。引数はいずれも副作用が出ないものに固定している（`sys` の各プローブの
/// `// SAFETY:` 参照）。`seccomp_mode` を読めない場合は `Err`（fail-closed）。
///
/// # 将来仕様（記録のみ）
///
/// exec が許可されたら（TASK-39.4・#184）、エントリポイント側のプローブ実行へ置き換える（REPAIR-3）。
pub(crate) fn probe_denied_syscalls() -> Result<SeccompProbeRecord, ExecError> {
    let fail =
        |m: &str| ExecError::new(ErrorCode::Internal, IsolationStage::Seccomp, m.to_string());
    let read_status = || std::fs::read_to_string("/proc/thread-self/status");
    let status = read_status().map_err(|_| fail("failed to read thread status"))?;
    let seccomp_mode = status
        .lines()
        .find_map(|l| l.strip_prefix("Seccomp:"))
        .map(|v| v.trim().to_string())
        .ok_or_else(|| fail("Seccomp field missing"))?;
    // 対照: 禁止対象外の読み出しが成功すること。失敗は errno を伴わないので `Failed`。
    let control = match read_status() {
        Ok(_) => ProbeOutcome::Ok,
        Err(_) => ProbeOutcome::Failed,
    };
    Ok(SeccompProbeRecord {
        unshare: ProbeOutcome::from_result(sys::unshare_namespaces(&[])),
        ptrace: ProbeOutcome::from_result(sys::ptrace_cont_probe(std::process::id())),
        seccomp_mode,
        control,
        mount: ProbeOutcome::from_result(sys::mount_root_private_recursive()),
        pivot_root: ProbeOutcome::from_result(sys::pivot_root_dot()),
        umount2: ProbeOutcome::from_result(sys::umount_cwd_detach()),
        kexec_load: ProbeOutcome::from_result(sys::kexec_load_invalid_probe()),
    })
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
