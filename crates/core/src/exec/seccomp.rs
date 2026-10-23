//! seccomp フィルタの適用（CORE-5・TASK-38.2・#177・MS-2）。
//!
//! # 役割と呼び出し文脈
//!
//! ステージ列（`exec/stages.rs`）第 5 段「seccomp」の実体。`crate::seccomp::build_deny_filter`
//! （TASK-38.1）が作る [`SeccompProgram`] を `prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER)` で呼び出し
//! スレッドへ適用する。ステージ列（`StagePipeline`）へは TASK-38.3（#178）で組み込み済みで、
//! `stages.rs` の組み込み段が [`apply_default_seccomp`] を exec 直前に必ず呼ぶ（差し替え不可）。
//! [`SeccompReport`] は証跡ではない。制限適用の証跡は `run_then` が本関数の成功後に作る `LaunchReady`（#1714）。
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

use super::seccomp_listener::ListenerSender;
use super::{ExecError, IsolationStage, ThreadCountSource};
use crate::seccomp::SeccompProgram;
use crate::sys::{self, SysError};
use crate::traits::types::ErrorCode;
use std::os::fd::OwnedFd;

/// `PR_GET_SECCOMP` が返す filter モードの値（`SECCOMP_MODE_FILTER`）。
const MODE_FILTER: u32 = 2;

/// カーネルへの seccomp 操作の境界。本番は [`RealKernel`]、テストは偽物を差し込む。
trait SeccompKernel {
    /// 呼び出したプロセスのスレッド数（`/proc/self/status` の `Threads:`）。読めない場合は `None`。
    fn thread_count(&mut self) -> Option<u64>;
    fn no_new_privs_enabled(&mut self) -> Result<bool, SysError>;
    fn set_filter(&mut self, program: &SeccompProgram) -> Result<(), SysError>;
    /// `NEW_LISTENER` 付きの適用（listener fd を得る。SEC-4・#2024）。
    fn set_filter_listener(&mut self, program: &SeccompProgram) -> Result<OwnedFd, SysError>;
    fn mode(&mut self) -> Result<u32, SysError>;
}

/// 本物の syscall を呼ぶ実装。スレッド数の取得元だけ差し替えられる（SUP-6・TASK-163.3）。
struct RealKernel<'a> {
    threads: &'a mut ThreadCountSource,
}

impl SeccompKernel for RealKernel<'_> {
    fn thread_count(&mut self) -> Option<u64> {
        self.threads.count()
    }
    fn no_new_privs_enabled(&mut self) -> Result<bool, SysError> {
        sys::no_new_privs_enabled()
    }
    fn set_filter(&mut self, program: &SeccompProgram) -> Result<(), SysError> {
        sys::seccomp_set_filter(program)
    }
    fn set_filter_listener(&mut self, program: &SeccompProgram) -> Result<OwnedFd, SysError> {
        sys::seccomp_notify::seccomp_set_filter_new_listener(program)
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
    apply_seccomp_filter_with(program, &mut ThreadCountSource::ProcSelf)
}

/// [`apply_seccomp_filter`] のスレッド数取得元を差し替える版（SUP-6・TASK-163.3・#502）。
///
/// exec の再適用（`exec/reapply.rs`）が、`setns` の前に開いた status fd を渡すために使う。
/// 適用前後の `Threads: 1` 検査・`NO_NEW_PRIVS` 検証は [`apply_seccomp_filter`] と同一。
#[cfg_attr(test, allow(dead_code))]
pub(crate) fn apply_seccomp_filter_with(
    program: &SeccompProgram,
    threads: &mut ThreadCountSource,
) -> Result<SeccompReport, ExecError> {
    apply_single_threaded(program, &mut RealKernel { threads })
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
    apply_seccomp_filter(&build_default_program()?)
}

/// 既定 deny フィルタを `NEW_LISTENER` 付きで適用し、得た listener fd を `sender` で C へ渡して ACK を待つ
/// （SEC-4・TASK-41 追補・#2024。`stages.rs` の組み込み `Seccomp` 段が、送り手が付いているときに呼ぶ）。
///
/// 適用・事後検査が済んだ後に、送信 → 手元の listener を閉じる → ACK 待ちの順で行う。**filter は ERRNO 版のまま**
/// （`USER_NOTIF` を返さないため通知は生じず、挙動は [`apply_default_seccomp`] と同じ。応答側は #2025）。
/// 失敗（`EBUSY`・送信・ACK の不着）は段 `Seccomp` で、exec に進ませない。
#[cfg_attr(test, allow(dead_code))]
pub(crate) fn apply_default_seccomp_with_listener(
    sender: ListenerSender,
) -> Result<SeccompReport, ExecError> {
    apply_default_seccomp_with_listener_threads(
        sender,
        super::seccomp_listener::ACK_TIMEOUT,
        &mut ThreadCountSource::ProcSelf,
    )
}

/// [`apply_default_seccomp_with_listener`] のスレッド数取得元を差し替える版（exec の再適用用。SUP-6）。
#[cfg_attr(test, allow(dead_code))]
///
/// `ack_timeout` は C の ACK を待つ上限（exec は全体の期限と `ACK_TIMEOUT` の短い方を渡す。REPAIR-5・#2385）。
pub(crate) fn apply_default_seccomp_with_listener_threads(
    sender: ListenerSender,
    ack_timeout: std::time::Duration,
    threads: &mut ThreadCountSource,
) -> Result<SeccompReport, ExecError> {
    let program = match build_default_program_with(sender.delivery()) {
        Ok(p) => p,
        Err(e) => {
            sender.report_failure(&e);
            return Err(e);
        }
    };
    // 送り手は受け渡しの closure が取り出す。適用が先に失敗して残っていたら、失敗を C へ知らせる(EOF 由来の
    // `Internal` に潰さない。SEC-4・#2024)。
    let slot = std::cell::RefCell::new(Some(sender));
    let result =
        apply_single_threaded_with_listener(&program, &mut RealKernel { threads }, |fd| match slot
            .borrow_mut()
            .take()
        {
            Some(sender) => sender.hand_over(fd, ack_timeout),
            None => Err(ExecError::new(
                ErrorCode::Internal,
                IsolationStage::Seccomp,
                "the listener sender was already consumed",
            )),
        });
    if let (Err(e), Some(sender)) = (&result, slot.borrow().as_ref()) {
        sender.report_failure(e);
    }
    result
}

/// [`apply_default_seccomp`] のスレッド数取得元を差し替える版（SUP-6・TASK-163.3・#502）。
#[cfg_attr(test, allow(dead_code))]
pub(crate) fn apply_default_seccomp_with(
    threads: &mut ThreadCountSource,
) -> Result<SeccompReport, ExecError> {
    apply_seccomp_filter_with(&build_default_program()?, threads)
}

/// ビルド対象アーキの既定 deny フィルタを構築する（構築失敗は段 `Seccomp` の `ExecError`）。
fn build_default_program() -> Result<SeccompProgram, ExecError> {
    build_default_program_with(crate::seccomp::ErrnoDelivery::Errno)
}

/// [`build_default_program`] の届け方指定版(listener 付きの適用だけが `UserNotif` を指定し得る。SEC-4・#2025)。
fn build_default_program_with(
    delivery: crate::seccomp::ErrnoDelivery,
) -> Result<SeccompProgram, ExecError> {
    crate::seccomp::build_filter_for_target_arch_with(delivery).map_err(|e| {
        let code = match e {
            crate::seccomp::SeccompBuildError::UnsupportedArch => ErrorCode::Unimplemented,
            _ => ErrorCode::Internal,
        };
        ExecError::new(code, IsolationStage::Seccomp, e.to_string())
    })
}

/// [`observe_default_seccomp_enforcement`] の観測結果。errno は `Err(SysError::Os(n))` の `n`、成功は `None`。
#[doc(hidden)]
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SeccompEnforcementObservation {
    /// 適用前の `kcmp(自 pid, 自 pid, KCMP_VM)`（対照。通常は成功し `None`。外側の seccomp が `kcmp` を拒否する環境では `EPERM` になり対照として働かないため、試験は前提欠如として失敗させる。ESC-06・#2006）。
    pub kcmp_before: Option<i32>,
    /// 適用した BPF 命令数。
    pub instructions: usize,
    /// 適用後の `/proc/thread-self/status` の `Seccomp:` 値（filter モードは `2`）。
    pub seccomp_mode: String,
    /// 適用後の `kcmp` の errno（`ERRNO(EPERM)` の禁止 syscall のため `EPERM`）。
    ///
    /// `unshare`・`ptrace`・`kexec_load` は `KILL_PROCESS` で戻らないため errno では観測できない
    /// （[`observe_default_seccomp_kill`]）。
    pub kcmp_after: Option<i32>,
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
    let kcmp_before = errno(sys::kcmp_self_probe());
    let report = apply_default_seccomp()?;
    let status = std::fs::read_to_string("/proc/thread-self/status")
        .map_err(|_| fail("failed to read thread status"))?;
    let seccomp_mode = status
        .lines()
        .find_map(|l| l.strip_prefix("Seccomp:"))
        .map(|v| v.trim().to_string())
        .ok_or_else(|| fail("Seccomp field missing"))?;
    Ok(SeccompEnforcementObservation {
        kcmp_before,
        instructions: report.instructions,
        seccomp_mode,
        kcmp_after: errno(sys::kcmp_self_probe()),
        mount_after: errno(sys::mount_root_private_recursive()),
        pivot_root_after: errno(sys::pivot_root_dot()),
        umount_after: errno(sys::umount_cwd_detach()),
    })
}

/// SIGSYS で死ぬ試験専用の入口が、違反 syscall の直前に core dump を作らない状態へする（SEC-4・CORE-5・REPAIR-12・#2629）。
///
/// `observe_default_seccomp_kill` と `probe_escape_syscall` から呼ぶ。`PR_SET_DUMPABLE` を 0 にするのが主で、
/// `core_pattern` がパイプ形式（apport 等）のとき、`RLIMIT_CORE` を 0 にしても helper が起動され、
/// 終わるまで親が子を回収できない（並列の試験の `wait` が期限切れになる。#2538）。`execve` は dumpable を
/// 1 に戻すため、exec 後の最後のプロセスの中で呼ぶこと。non-dumpable の後は `/proc/<pid>` の所有者が
/// 変わるので、親による ID 写像の書き込み等が済んだ後に限る。`RLIMIT_CORE` は file 形式のホストで
/// core ファイルを残さないための補助。
fn suppress_core_dump_before_sigsys() -> Result<(), sys::SysError> {
    sys::set_non_dumpable()?;
    if sys::is_dumpable()? {
        return Err(sys::SysError::Unsupported);
    }
    sys::set_rlimit_self(crate::rlimits::RlimitKind::Core, 0, 0)
}

/// 強制終了（`SECCOMP_RET_KILL_PROCESS`）対象の禁止 syscall（ESC-06・CORE-5・SEC-2。`DeniedSyscall::deny_action`）。
#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KilledSyscall {
    /// `unshare(0)`。
    Unshare,
    /// `ptrace(PTRACE_CONT, 自 pid)`（attach を伴わない）。
    Ptrace,
    /// segment 数が上限超過の `kexec_load`（ロードに至らない）。
    KexecLoad,
}

/// 本番の適用経路を適用したあと、強制終了対象の syscall を 1 件発行する（CORE-5・SEC-2・ESC-06・#1834。結合試験専用）。
///
/// 正常な挙動では syscall が SIGSYS で子プロセスを終了させるため、本関数は戻らない。戻った場合は
/// 強制終了になっていない（フィルタの欠落）ので `Err` を返す。`tests/seccomp_enforcement.rs` の
/// 使い捨ての子（`--child-kill`）から呼び、親が終了シグナル（SIGSYS = 31）を照合する。
/// SIGSYS の既定動作はコアダンプのため、発行前に non-dumpable にする（`suppress_core_dump_before_sigsys`。
/// パイプ形式の `core_pattern` の helper 待ちによる間欠失敗の回避。#2538・#2629）。
#[doc(hidden)]
pub fn observe_default_seccomp_kill(which: KilledSyscall) -> Result<(), ExecError> {
    let fail =
        |m: &str| ExecError::new(ErrorCode::Internal, IsolationStage::Seccomp, m.to_string());
    sys::set_no_new_privs().map_err(|_| fail("failed to set no_new_privs"))?;
    suppress_core_dump_before_sigsys()
        .map_err(|_| fail("failed to suppress core dump (PR_SET_DUMPABLE / RLIMIT_CORE)"))?;
    apply_default_seccomp()?;
    let r = match which {
        KilledSyscall::Unshare => sys::unshare_namespaces(&[]),
        KilledSyscall::Ptrace => sys::ptrace_cont_probe(std::process::id()),
        KilledSyscall::KexecLoad => sys::kexec_load_invalid_probe(),
    };
    Err(ExecError::new(
        ErrorCode::FailedPrecondition,
        IsolationStage::Seccomp,
        format!("{which:?} returned {r:?} instead of being killed by SIGSYS"),
    ))
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
    /// 試験用プローブの入口が `SysError` の結果を `ProbeOutcome` へ写す関数（CORE-5・REPAIR-7・#2550）。
    ///
    /// 呼び出し元（`probe_escape_syscall`・`escape_probe_mount`・`probe_kcmp_self_for_test`・
    /// `probe_denied_syscalls_for_test`・`sysfs.rs` の試験用プローブ）の feature の和集合に cfg を揃える。
    /// `allow(dead_code)` にしないのは、test 用 feature 無効の `-p` 単独 clippy を通すため。
    #[cfg(any(feature = "escape-probe", feature = "exec-test-support"))]
    pub(super) fn from_result(r: Result<(), SysError>) -> Self {
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
/// exec 後のエントリポイント（`tests/seccomp.rs` の `/entry`）が `probe_denied_syscalls_for_test`
/// で作り、pivot 後の `/seccomp-probe` へ `key=value` 行で書く。親（結合試験 `tests/seccomp.rs`）が
/// [`SeccompProbeRecord::parse`] で読む。識別的な検査は `kcmp`・`seccomp_mode`、網羅確認は
/// `mount`・`pivot_root`・`umount2`（capability 不足でも `EPERM` になり得る）。強制終了対象の
/// `unshare`・`ptrace`・`kexec_load` は戻らないため記録せず、別のコンテナのエントリポイントで終了シグナルを確認する。
#[doc(hidden)]
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SeccompProbeRecord {
    /// `kcmp(自 pid, 自 pid, KCMP_VM)`。フィルタが無ければ成功、有れば `EPERM`（識別的）。
    ///
    /// `unshare`・`ptrace`・`kexec_load` は `KILL_PROCESS` で戻らず記録できないため、`ERRNO(EPERM)` の
    /// 禁止 syscall である `kcmp` で遮断を識別する（強制終了は別の子で確認する。#1834）。
    pub kcmp: ProbeOutcome,
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
}

/// 記録のキー（直列化・解析で共通。増減時は [`SeccompProbeRecord`] と同時に直す）。
const PROBE_KEYS: [&str; 6] = [
    "kcmp",
    "seccomp_mode",
    "control",
    "mount",
    "pivot_root",
    "umount2",
];

impl SeccompProbeRecord {
    /// 英語の `key=value` 行（改行区切り）へ直列化する。
    pub fn render(&self) -> String {
        format!(
            "kcmp={}\nseccomp_mode={}\ncontrol={}\nmount={}\npivot_root={}\numount2={}\n",
            self.kcmp.render(),
            self.seccomp_mode,
            self.control.render(),
            self.mount.render(),
            self.pivot_root.render(),
            self.umount2.render(),
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
            kcmp: ProbeOutcome::parse(get("kcmp")?)?,
            seccomp_mode: seccomp_mode.to_string(),
            control: ProbeOutcome::parse(get("control")?)?,
            mount: ProbeOutcome::parse(get("mount")?)?,
            pivot_root: ProbeOutcome::parse(get("pivot_root")?)?,
            umount2: ProbeOutcome::parse(get("umount2")?)?,
        })
    }
}

/// ESC-06 の攻撃クロージャが発行する禁止 syscall の種別（SEC-2・TASK-42.3・#201）。
///
/// 各バリアントは [`probe_escape_syscall`] が呼ぶ既存 `sys` プローブに 1 対 1 で対応する。
#[cfg(feature = "escape-probe")]
#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EscapeSyscallProbe {
    /// `unshare(0)`。
    Unshare,
    /// `ptrace(PTRACE_CONT, 自 pid)`（attach を伴わない）。
    Ptrace,
    /// segment 数が上限超過の `kexec_load`（ロードに至らない）。
    KexecLoad,
}

/// 結合試験 `tests/escape_suite.rs` の ESC-06 から呼ぶ、禁止 syscall の安全な入口（SEC-2・TASK-42.3・#201）。
///
/// 組み込み Seccomp 段の通過後に呼ばれる。呼び出し元は、exec 後のエントリポイント（`tests/seccomp.rs` の
/// `/entry --entry kill-<名前>`・`production_launcher` のシナリオ K）と、`spawn_container_probe` の fork 子
/// （`escape_suite` の ESC-06）。ESC-06 を fork 子のまま残してよい根拠: seccomp フィルタ・`NO_NEW_PRIVS`・Landlock のドメイン・マウントの状態は execve をまたいで変わらないため、
/// 組み込み `Seccomp` 段を通った後の fork 子で観測した `EPERM` や SIGSYS は、exec 後の PID 1 で観測したものと
/// 同じフィルタによる。capability は execve で再計算されうるため例外で、exec 後の値は `production_launcher` の
/// シナリオ J が照合する。
/// `unsafe` を `sys` の外へ出さないための薄い入口で、引数は副作用のない値に固定している（根拠は各 `sys` プローブの `// SAFETY:`）。
///
/// # 将来仕様（REPAIR-3）
///
/// 現行フィルタは本 3 件を `SECCOMP_RET_KILL_PROCESS` で拒否するため、本関数は戻らず子が SIGSYS で
/// 終了する（ESC-06 の期待。CORE-5・SEC-2。#1834）。戻るのはフィルタが欠落した場合だけ。
/// 終了するプロセス自身は監査記録を書けない（SEC-4。正の記録はカーネルの `AUDIT_SECCOMP`、補助は
/// 親の回収点が出す `exit_signal` レコード。#2004）。
#[cfg(feature = "escape-probe")]
#[doc(hidden)]
pub fn probe_escape_syscall(which: EscapeSyscallProbe) -> ProbeOutcome {
    // SIGSYS の既定動作はコアダンプのため、発行前に non-dumpable にして抑止する（失敗しても観測は続ける。
    // ベストエフォート。`prctl` は組み込みフィルタの必須許可。#2629）。
    let _ = suppress_core_dump_before_sigsys();
    let result = match which {
        EscapeSyscallProbe::Unshare => sys::unshare_namespaces(&[]),
        EscapeSyscallProbe::Ptrace => sys::ptrace_cont_probe(std::process::id()),
        EscapeSyscallProbe::KexecLoad => sys::kexec_load_invalid_probe(),
    };
    ProbeOutcome::from_result(result)
}

/// 攻撃テスト ESC-03 用: コンテナ内（PID 1・pivot 済み）から `mount(2)` を 1 回試行して結果を返す（SEC-2・TASK-42.2・#200）。
///
/// `tests/escape_suite.rs` の攻撃クロージャ（`spawn_container_probe` の子）から呼ばれる。テスト側は
/// `unsafe` を書けず raw syscall を発行できないため、既存の `sys::mount_root_private_recursive`
/// （`mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL)`。propagation の変更のみで新たなマウントは作らない）を
/// 薄く包む。新規 `unsafe`・新規 `sys` ラッパーは追加しない。
///
/// 誤用の封じ込め（fail-closed）: 次をすべて満たさない場合は syscall を発行せず `FailedPrecondition` を返す
/// （ホストの `/` の propagation を変えない）。
/// - PID 1 であること
/// - `/proc/self/status` の `Seccomp` が 2（filter 適用済み）。組み込み filter は `mount` を `ERRNO(EPERM)` で
///   拒否するため、filter 適用前の（ホスト側の）プロセスでは syscall を発行しない
///
/// 呼び出し元は escape_suite の ESC-03 と、supervisor の `supervisor_bin_real` のシナリオ E（本番の
/// `SeccompNotifyHub` をコンテナ経由で通す照合。SEC-4・#2482）。`escape-probe` または `exec-test-support` の
/// feature はテスト専用で、通常ビルドには含まれない（dev-dependency の自己参照でのみ有効化）。
///
/// # 残す理由（#2543・REPAIR-3）
///
/// 本関数は `unsafe` を書けない試験のための安全な入口で、exec 後のエントリポイント（`production_launcher` の
/// シナリオ J・`supervisor_bin_real` のシナリオ E）がすでに呼んでいるため、廃止しない。fork 子から呼ぶのは
/// ESC-03 だけで、`spawn_container_probe_with_seccomp_listener`（USER_NOTIF の listener の受け渡し）に結びついて
/// いる。ここをエントリポイント内へ移さない根拠: seccomp フィルタ・`NO_NEW_PRIVS`・Landlock のドメイン・マウントの状態は execve をまたいで変わらないため、
/// 組み込み `Seccomp` 段を通った後の fork 子で観測した `EPERM` や SIGSYS は、exec 後の PID 1 で観測したものと
/// 同じフィルタによる。capability は execve で再計算されうるため例外で、exec 後の値は `production_launcher` の
/// シナリオ J が照合する。ESC-03 の移行は未着手。
#[cfg(any(feature = "escape-probe", feature = "exec-test-support"))]
#[doc(hidden)]
pub fn escape_probe_mount() -> Result<ProbeOutcome, ExecError> {
    if std::process::id() != 1 || !probe_context_is_isolated() {
        return Err(ExecError::new(
            ErrorCode::FailedPrecondition,
            IsolationStage::Seccomp,
            "escape_probe_mount must run as PID 1 with the seccomp filter active".to_string(),
        ));
    }
    Ok(ProbeOutcome::from_result(
        sys::mount_root_private_recursive(),
    ))
}

/// [`escape_probe_mount`] の前提検査: seccomp filter 適用済みか（読めなければ false）。
#[cfg(any(feature = "escape-probe", feature = "exec-test-support"))]
fn probe_context_is_isolated() -> bool {
    use std::io::Read;
    // /proc/self/status は小さい（数 KiB）。上限を設けて読む。
    let mut text = String::new();
    let Ok(file) = std::fs::File::open("/proc/self/status") else {
        return false;
    };
    if file.take(64 * 1024).read_to_string(&mut text).is_err() {
        return false;
    }
    text.lines()
        .find_map(|l| l.strip_prefix("Seccomp:"))
        .and_then(|v| v.trim().parse::<u32>().ok())
        == Some(2)
}

/// seccomp 段を載せる前の対照として `kcmp(自 pid, 自 pid, KCMP_VM)` の結果を返す（CORE-5・ESC-06・SEC-1・#2234）。
///
/// `tests/seccomp.rs`・`tests/production_launcher.rs` の試験プロセス（組み込みフィルタを載せる前）が呼び、
/// `kcmp` が成功することを前提として要求する。外側の seccomp・LSM・kcmp 非対応のカーネルでは `EPERM` / `ENOSYS`
/// になり、コンテナ内の `EPERM` を組み込みフィルタの成果と見なせないため、試験側が前提欠如として失敗させる。
/// `kcmp` は比較のみで副作用が無いため、PID・seccomp の前提検査は付けない。
///
/// # 残す理由（#2543・REPAIR-3）
///
/// 組み込み段を載せる**前**の親での対照であり、フィルタの無い状態での観測が役割のため、エントリポイント内へは
/// 移せない。コンテナ内の `kcmp` は [`probe_denied_syscalls_for_test`] が担う。
#[cfg(feature = "escape-probe")]
#[doc(hidden)]
pub fn probe_kcmp_self_for_test() -> ProbeOutcome {
    ProbeOutcome::from_result(sys::kcmp_self_probe())
}

/// exec 後のコンテナ PID 1（エントリポイント）から禁止 syscall を呼んで遮断を記録する test 限定の入口
/// （CORE-5・ESC-06・SEC-1・REPAIR-3・#2234・#2386）。
///
/// `tests/seccomp.rs` の `/entry`・`tests/production_launcher.rs` のシナリオ J のプローブ（exec 後の PID 1）が呼び、
/// `kcmp` の `EPERM`・`Seccomp: 2`・対照の読み出し・`mount`・`pivot_root`・`umount2` の結果を
/// [`SeccompProbeRecord`] にして返す。引数はいずれも副作用が出ないものに固定している（`sys` の各プローブの
/// `// SAFETY:` 参照）。試験側は `unsafe` を書けないため、この安全な入口が exec 後のエントリポイントの
/// プローブ本体になる。`mount`・`pivot_root`・`umount2` を発行するため、[`escape_probe_mount`] と同じ前提検査で
/// fail-closed にする。PID 1 かつ `Seccomp: 2` でなければ syscall を発行せず `FailedPrecondition` を返す
/// （ホストの `/` の propagation を変えない）。`Seccomp` 欄を読めない場合も `Err`。新規 `unsafe`・新規 `sys` 宣言は無い。
#[cfg(feature = "escape-probe")]
#[doc(hidden)]
pub fn probe_denied_syscalls_for_test() -> Result<SeccompProbeRecord, ExecError> {
    if std::process::id() != 1 || !probe_context_is_isolated() {
        return Err(ExecError::new(
            ErrorCode::FailedPrecondition,
            IsolationStage::Seccomp,
            "probe_denied_syscalls_for_test must run as PID 1 with the seccomp filter active"
                .to_string(),
        ));
    }
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
        kcmp: ProbeOutcome::from_result(sys::kcmp_self_probe()),
        seccomp_mode,
        control,
        mount: ProbeOutcome::from_result(sys::mount_root_private_recursive()),
        pivot_root: ProbeOutcome::from_result(sys::pivot_root_dot()),
        umount2: ProbeOutcome::from_result(sys::umount_cwd_detach()),
    })
}

/// 単一スレッド条件を適用の前後で検査して [`apply_filter`] を呼ぶ。事前検査は副作用の前に行う。
fn apply_single_threaded(
    program: &SeccompProgram,
    kernel: &mut impl SeccompKernel,
) -> Result<SeccompReport, ExecError> {
    apply_single_threaded_mode(program, kernel, false).map(|(report, _)| report)
}

/// [`apply_single_threaded`] の listener 版（SEC-4・#2024）。`handover` が listener を受けて C へ渡す
/// （適用・事後検査がすべて済んだ後に呼ぶ）。渡せなければ失敗にする（listener 無しで進まない。fail-closed）。
fn apply_single_threaded_with_listener(
    program: &SeccompProgram,
    kernel: &mut impl SeccompKernel,
    handover: impl FnOnce(OwnedFd) -> Result<(), ExecError>,
) -> Result<SeccompReport, ExecError> {
    let (report, listener) = apply_single_threaded_mode(program, kernel, true)?;
    let Some(listener) = listener else {
        return Err(ExecError::new(
            ErrorCode::Internal,
            IsolationStage::Seccomp,
            "no seccomp listener was produced",
        ));
    };
    handover(listener)?;
    Ok(report)
}

/// 共通の本体。`want_listener` が真なら `NEW_LISTENER` 付きで適用して fd を返す（渡し方は呼び出し側）。
fn apply_single_threaded_mode(
    program: &SeccompProgram,
    kernel: &mut impl SeccompKernel,
    want_listener: bool,
) -> Result<(SeccompReport, Option<OwnedFd>), ExecError> {
    if kernel.thread_count() != Some(1) {
        return Err(ExecError::new(
            ErrorCode::FailedPrecondition,
            IsolationStage::Seccomp,
            "seccomp filter requires a single-threaded process (Threads: 1)",
        ));
    }
    let (report, fd) = apply_filter_mode(program, kernel, want_listener)?;
    if kernel.thread_count() != Some(1) {
        return Err(ExecError::new(
            ErrorCode::Internal,
            IsolationStage::Seccomp,
            "process became multi-threaded while applying seccomp filter",
        ));
    }
    Ok((report, fd))
}

/// `NO_NEW_PRIVS` 検証 → 適用 → モード読み戻し。スレッド数検査は呼び出し側が行う。
#[cfg(test)]
fn apply_filter(
    program: &SeccompProgram,
    kernel: &mut impl SeccompKernel,
) -> Result<SeccompReport, ExecError> {
    apply_filter_mode(program, kernel, false).map(|(report, _)| report)
}

fn apply_filter_mode(
    program: &SeccompProgram,
    kernel: &mut impl SeccompKernel,
    want_listener: bool,
) -> Result<(SeccompReport, Option<OwnedFd>), ExecError> {
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
    let listener = if want_listener {
        match kernel.set_filter_listener(program) {
            Ok(fd) => Some(fd),
            // 祖先の filter が既に listener を持つ（カーネルは listener を 1 つに制限する）。
            Err(SysError::Os(e)) if e == sys::EBUSY => {
                return Err(ExecError::new(
                    ErrorCode::FailedPrecondition,
                    stage,
                    "seccomp listener unavailable: an ancestor filter already has a listener",
                ));
            }
            Err(e) => return Err(ExecError::from_sys(e, stage, "seccomp(NEW_LISTENER)")),
        }
    } else {
        kernel
            .set_filter(program)
            .map_err(|e| ExecError::from_sys(e, stage, "PR_SET_SECCOMP"))?;
        None
    };
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
    Ok((
        SeccompReport {
            instructions: program.len(),
        },
        listener,
    ))
}

#[cfg(all(
    test,
    all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
mod tests {
    use super::*;
    use crate::seccomp::build_filter_for_target_arch;
    use crate::sys::{EACCES, EINVAL};

    #[derive(Default)]
    struct Fake {
        threads: Vec<Option<u64>>,
        nnp: Option<Result<bool, SysError>>,
        set: Option<Result<(), SysError>>,
        listener: Option<Result<(), SysError>>,
        mode: Option<Result<u32, SysError>>,
        calls: Vec<&'static str>,
    }

    impl Fake {
        fn ok() -> Self {
            Fake {
                threads: vec![Some(1), Some(1)],
                nnp: Some(Ok(true)),
                set: Some(Ok(())),
                listener: Some(Ok(())),
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
        fn set_filter_listener(&mut self, _p: &SeccompProgram) -> Result<OwnedFd, SysError> {
            self.calls.push("set_listener");
            self.listener.unwrap()?;
            let (r, _w) = std::io::pipe().unwrap();
            Ok(OwnedFd::from(r))
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

    /// CORE-5・#2234: 試験プロセス（PID 1 ではない）からは syscall を発行せず `FailedPrecondition`（fail-closed）。
    #[cfg(feature = "escape-probe")]
    #[test]
    fn core5_probe_denied_syscalls_for_test_refuses_outside_container() {
        let e = probe_denied_syscalls_for_test().unwrap_err();
        assert_eq!(e.code, ErrorCode::FailedPrecondition);
    }

    /// CORE-5・#2234: 適用前の対照は `sys` のプローブ結果と一致する。
    #[cfg(feature = "escape-probe")]
    #[test]
    fn core5_probe_kcmp_self_for_test_matches_sys_probe() {
        assert_eq!(
            probe_kcmp_self_for_test(),
            ProbeOutcome::from_result(sys::kcmp_self_probe())
        );
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

    /// SEC-4（#2024）: listener 版の呼び出し順は 適用 → 読み戻し → 事後のスレッド検査 → 受け渡し。
    #[test]
    fn sec4_listener_apply_hands_over_after_all_checks() {
        let p = program();
        let mut k = Fake::ok();
        let mut handed = 0;
        let r = apply_single_threaded_with_listener(&p, &mut k, |_fd| {
            handed += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!(r.instructions, p.len());
        assert_eq!(handed, 1);
        assert_eq!(
            k.calls,
            vec!["threads", "nnp", "set_listener", "mode", "threads"]
        );
    }

    /// SEC-4: 受け渡しの失敗はそのまま失敗になる（listener 無しで進まない）。
    #[test]
    fn sec4_listener_handover_failure_is_propagated() {
        let mut k = Fake::ok();
        let e = apply_single_threaded_with_listener(&program(), &mut k, |_fd| {
            Err(ExecError::new(
                ErrorCode::Timeout,
                IsolationStage::Seccomp,
                "ack",
            ))
        })
        .unwrap_err();
        assert_eq!(e.code, ErrorCode::Timeout);
    }

    /// SEC-4: 受け渡しの前に失敗したら受け渡しを呼ばない。`EBUSY` は固定文言の `FailedPrecondition`。
    #[test]
    fn sec4_listener_apply_failures_never_hand_over() {
        for (err, code) in [
            (SysError::Os(sys::EBUSY), ErrorCode::FailedPrecondition),
            (SysError::Os(EACCES), ErrorCode::PermissionDenied),
            (SysError::Unsupported, ErrorCode::Unimplemented),
        ] {
            let mut k = Fake::ok();
            k.listener = Some(Err(err));
            let e = apply_single_threaded_with_listener(&program(), &mut k, |_fd| {
                panic!("handover must not run")
            })
            .unwrap_err();
            assert_eq!(e.code, code);
            assert_eq!(e.stage, IsolationStage::Seccomp);
            if err == SysError::Os(sys::EBUSY) {
                assert_eq!(
                    e.message,
                    "seccomp listener unavailable: an ancestor filter already has a listener"
                );
            }
        }
        let mut k = Fake::ok();
        k.mode = Some(Ok(0));
        let e = apply_single_threaded_with_listener(&program(), &mut k, |_fd| {
            panic!("handover must not run")
        })
        .unwrap_err();
        assert_eq!(e.code, ErrorCode::Internal);
        let mut k = Fake::ok();
        k.nnp = Some(Ok(false));
        assert!(
            apply_single_threaded_with_listener(&program(), &mut k, |_fd| {
                panic!("handover must not run")
            })
            .is_err()
        );
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
            let report = apply_filter(
                &p,
                &mut RealKernel {
                    threads: &mut ThreadCountSource::ProcSelf,
                },
            )
            .unwrap();
            assert_eq!(report.instructions, p.len());
            assert_eq!(thread_status_field("Seccomp:"), "2");
            // 自プロセス同士の kcmp は通常成功するが、ERRNO の禁止 syscall として EPERM になる。
            // （unshare・ptrace・kexec_load は KILL_PROCESS で戻らないため、libtest のプロセスでは呼ばない）
            assert_eq!(sys::kcmp_self_probe(), Err(SysError::Os(sys::EPERM)));
            // 禁止対象外の syscall は動作し続ける。
            let _ = sys::effective_uid();
        })
        .join()
        .unwrap();
    }

    /// SEC-4（#2023）: listener 無し（`NEW_LISTENER` を付けない通常の適用）で USER_NOTIF 版を載せると、
    /// ERRNO 側の禁止 syscall はカーネルが `ENOSYS` で拒否し、実行されない（拒否は維持される）。
    /// `EPERM` ではないため、listener の配線（#2024・#2025）前は本番に載せない。
    ///
    /// 適用前の対照として kcmp が通ることを要求する。外側の seccomp（開発コンテナの既定プロファイル等）が
    /// kcmp を拒否する環境では、skip せず前提不成立として失敗させる。
    #[test]
    fn sec4_user_notif_without_listener_returns_enosys_real_thread() {
        std::thread::spawn(|| {
            assert_eq!(
                sys::kcmp_self_probe(),
                Ok(()),
                "outer seccomp rejects kcmp; no valid control for this test"
            );
            let p = crate::seccomp::build_filter_for_target_arch_with(
                crate::seccomp::ErrnoDelivery::UserNotif,
            )
            .unwrap();
            assert_eq!(sys::set_no_new_privs(), Ok(()));
            apply_filter(
                &p,
                &mut RealKernel {
                    threads: &mut ThreadCountSource::ProcSelf,
                },
            )
            .unwrap();
            assert_eq!(thread_status_field("Seccomp:"), "2");
            assert_eq!(sys::kcmp_self_probe(), Err(SysError::Os(sys::ENOSYS)));
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
                let e = apply_filter(
                    &program(),
                    &mut RealKernel {
                        threads: &mut ThreadCountSource::ProcSelf,
                    },
                )
                .unwrap_err();
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

    use super::{ExecError, SeccompReport, ThreadCountSource};

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

    /// `stages.rs` の組み込み段が `cfg(test)` で、送り手つきのときに呼ぶ偽物。送り手は使わず閉じるだけ。
    pub(in crate::exec) fn apply_default_seccomp_with_listener(
        _sender: crate::exec::seccomp_listener::ListenerSender,
    ) -> Result<SeccompReport, ExecError> {
        apply_default_seccomp()
    }

    /// `exec/reapply.rs` が `cfg(test)` で呼ぶ偽物（取得元は読まない）。
    pub(in crate::exec) fn apply_default_seccomp_with(
        _threads: &mut ThreadCountSource,
    ) -> Result<SeccompReport, ExecError> {
        apply_default_seccomp()
    }

    /// `exec/reapply.rs` が `cfg(test)` で、送り手つきのときに呼ぶ偽物。送り手は使わず閉じるだけ（呼び出しは
    /// `apply_default_seccomp_with` と同じ記録・失敗注入に従う）。
    pub(in crate::exec) fn apply_default_seccomp_with_listener_threads(
        _sender: crate::exec::seccomp_listener::ListenerSender,
        _ack_timeout: std::time::Duration,
        _threads: &mut ThreadCountSource,
    ) -> Result<SeccompReport, ExecError> {
        apply_default_seccomp()
    }
}
