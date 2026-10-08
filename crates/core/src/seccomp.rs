//! 禁止 syscall の一覧とアーキテクチャ別 syscall 番号テーブル（CORE-5・TASK-38.1.1・#837・MS-2）。
//!
//! # 役割と呼び出し文脈
//!
//! コンテナ内から拒否すべき syscall（`unshare`・`mount`・`ptrace`・`kexec_load` 等）を論理名
//! [`DeniedSyscall`] で列挙し、x86_64 / aarch64 それぞれの番号を [`ArchSyscallTable`] として
//! 提供するデータ層である。capability 最小化（SEC-1・TASK-37）とは独立に効く多層防御の土台で、
//! CAP を持っていても、あるいは誤って付与しても、これらの syscall による脱出経路を塞ぐ。
//!
//! 本モジュールは syscall を発行しない純粋関数・データで、[`build_deny_filter`] が
//! テーブルから BPF プログラム（`seccomp_data.arch` 検査・x32 拒否を含む。TASK-38.1.2・#838）を構築する。
//! 適用関数は `crate::exec` の `apply_seccomp_filter`（TASK-38.2・#177）に実装済みだが、
//! 起動フロー（`exec/stages.rs`）の組み込み段が exec 直前に適用する（TASK-38.3・#178）。
//! 禁止 syscall の遮断を起動したコンテナの中で確かめる結合テストは `tests/seccomp.rs`（TASK-38.4・#179）。
//!
//! # 契約
//!
//! - **fail-closed**: 対応外アーキでは空テーブルを返さず [`SeccompTableError::UnsupportedArch`] を返す。
//!   呼び出し側（#838 以降）はフィルタ構築を失敗させ、`ErrorCode::Unimplemented` 相当へ写すこと
//! - **存在しない syscall と対応外アーキの区別**: `iopl`・`ioperm` のようにそのアーキに無い syscall は
//!   [`SyscallLookup::AbsentOnArch`] で表す。ダミー番号（0 等。0 は x86_64 の `read`・aarch64 の
//!   `io_setup`）で埋めない
//! - **ランタイム自身が使う syscall を含めない**: seccomp 段は `execveat` の前に適用される予定
//!   （TASK-38.3）のため、`execve`・`execveat`・`prctl`・`capget`・`capset`・`close_range`・
//!   `exit`・`exit_group`・`pidfd_open`・`pidfd_send_signal`・`rt_sigreturn` と、封印した複製からの
//!   実行（TASK-163 追補・#1530・SUP-6）が使う `memfd_create`・`fcntl` は禁止対象にしない
//!   （テストで機械照合）。適用前に完了する `unshare`・`mount`・`pivot_root`・`umount2` は禁止してよい
//! - **x32 ABI は BPF 構築側（[`build_deny_filter`]）が明示的に拒否する**: x86_64 の `AUDIT_ARCH_X86_64` は x32 ABI の
//!   syscall でも同じ値になり、`arch` の照合だけでは x32 を区別できない。x32 の syscall 番号には
//!   `0x4000_0000`（`__X32_SYSCALL_BIT`）が付くため、本テーブルの番号との単純比較では
//!   `unshare` 等を遮断できない。BPF 構築は、x86_64 で
//!   `nr & 0x4000_0000 != 0` の呼び出しを（テーブル照合の前に）無条件に拒否する（実装済み）。
//!   本テーブルは x32 番号を含まず、この拒否は構築側の責務である（CORE-5）
//! - 各アーキの番号は `mod nr` に個別定義し、値が同じでも他アーキの定数を流用しない
//!   （`sys.rs` の `consts` と同じ流儀。アーキ差の取り違えは誤遮断・遮断漏れに直結する）
//!
//! # cfg の方針
//!
//! 値は Linux カーネル ABI の番号だが、syscall を発行しないデータであり、3 OS の CI
//! （macOS arm64 runner が aarch64 テーブルを検証する）で固定値テストを走らせるため、
//! `target_os` では分岐せず `target_arch` のみで分ける。適用（`prctl(PR_SET_SECCOMP)`）は
//! Linux 限定の `exec` / `sys` 側に置く（TASK-38.2・#177）。
//!
//! # 範囲外
//!
//! 引数ベースのフィルタ（`clone`・`clone3` の `CLONE_NEW*`、`personality` 等）、moby 既定プロファイルの
//! 許可リスト方式への発展（TASK-128・GPU-3）は扱わない。
//! 監査ログ連携のうち拒否報告からレコードを作るフックは `audit_log`（TASK-41.2・SEC-4）にある。
//! ただし現行の `ERRNO(EPERM)` はユーザー空間へ報告しないため、配送経路は未実装。
//! 本一覧は拒否リストの土台である。将来 `config.json` の `linux.seccomp` を解釈する場合は
//! 外部入力として別途検証が必要。

use std::fmt;

/// 禁止 syscall の論理名。各 variant の doc に syscall 名と遮断理由を記す。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DeniedSyscall {
    /// `unshare`: 新しい namespace の作成（コンテナ外への分離回避）。
    Unshare,
    /// `setns`: 既存 namespace への参加（ホスト namespace への侵入）。
    Setns,
    /// `mount`: マウントの追加（rootfs 外のファイルシステム露出）。
    Mount,
    /// `umount2`: マウントの取り外し。
    Umount2,
    /// `pivot_root`: ルートの切り替え（起動時に完了済みのため以後は不要）。
    PivotRoot,
    /// `open_tree`: 新マウント API（mount の代替経路）。
    OpenTree,
    /// `move_mount`: 新マウント API（mount の代替経路）。
    MoveMount,
    /// `fsopen`: 新マウント API（mount の代替経路）。
    Fsopen,
    /// `fsconfig`: 新マウント API（mount の代替経路）。
    Fsconfig,
    /// `fsmount`: 新マウント API（mount の代替経路）。
    Fsmount,
    /// `fspick`: 新マウント API（mount の代替経路）。
    Fspick,
    /// `mount_setattr`: マウント属性の変更。
    MountSetattr,
    /// `ptrace`: 他プロセスの観察・改変。
    Ptrace,
    /// `process_vm_readv`: 他プロセスのメモリ読み取り。
    ProcessVmReadv,
    /// `process_vm_writev`: 他プロセスのメモリ書き込み。
    ProcessVmWritev,
    /// `kcmp`: プロセス間のカーネル資源比較（情報漏えい経路）。
    Kcmp,
    /// `kexec_load`: ホストカーネルの置換。
    KexecLoad,
    /// `kexec_file_load`: ホストカーネルの置換。
    KexecFileLoad,
    /// `init_module`: カーネルモジュールのロード。
    InitModule,
    /// `finit_module`: カーネルモジュールのロード。
    FinitModule,
    /// `delete_module`: カーネルモジュールのアンロード。
    DeleteModule,
    /// `reboot`: ホストの再起動・停止。
    Reboot,
    /// `swapon`: ホストのスワップ操作。
    Swapon,
    /// `swapoff`: ホストのスワップ操作。
    Swapoff,
    /// `acct`: ホストのプロセスアカウンティング操作。
    Acct,
    /// `quotactl`: ホストのディスククォータ操作。
    Quotactl,
    /// `quotactl_fd`: `quotactl` と同じクォータ操作を fd 指定で行う（Linux 5.14 以降。`quotactl` だけでは遮断漏れになる）。
    QuotactlFd,
    /// `vhangup`: 制御端末の強制ハングアップ。
    Vhangup,
    /// `settimeofday`: ホスト時刻の変更。
    Settimeofday,
    /// `clock_settime`: ホスト時刻の変更。
    ClockSettime,
    /// `clock_adjtime`: ホスト時刻の調整。
    ClockAdjtime,
    /// `adjtimex`: ホスト時刻の調整。
    Adjtimex,
    /// `syslog`: カーネルリングバッファの読み取り。
    Syslog,
    /// `lookup_dcookie`: カーネル内部情報の取得（Linux 6.8 で削除済み。番号は予約として残るため遮断しても無害）。
    LookupDcookie,
    /// `bpf`: eBPF プログラムのロード。
    Bpf,
    /// `perf_event_open`: 性能計測経由のカーネル情報取得。
    PerfEventOpen,
    /// `userfaultfd`: カーネル脆弱性の悪用補助。
    Userfaultfd,
    /// `add_key`: カーネル keyring の操作。
    AddKey,
    /// `request_key`: カーネル keyring の操作。
    RequestKey,
    /// `keyctl`: カーネル keyring の操作。
    Keyctl,
    /// `open_by_handle_at`: ファイルハンドルからの rootfs 外アクセス。
    OpenByHandleAt,
    /// `iopl`: I/O 特権レベルの変更（x86 固有。aarch64 には存在しない）。
    Iopl,
    /// `ioperm`: I/O ポートアクセス許可（x86 固有。aarch64 には存在しない）。
    Ioperm,
}

impl DeniedSyscall {
    /// 全 variant（テーブルの網羅性検査と #838 の走査に使う）。
    pub const ALL: [DeniedSyscall; 43] = [
        DeniedSyscall::Unshare,
        DeniedSyscall::Setns,
        DeniedSyscall::Mount,
        DeniedSyscall::Umount2,
        DeniedSyscall::PivotRoot,
        DeniedSyscall::OpenTree,
        DeniedSyscall::MoveMount,
        DeniedSyscall::Fsopen,
        DeniedSyscall::Fsconfig,
        DeniedSyscall::Fsmount,
        DeniedSyscall::Fspick,
        DeniedSyscall::MountSetattr,
        DeniedSyscall::Ptrace,
        DeniedSyscall::ProcessVmReadv,
        DeniedSyscall::ProcessVmWritev,
        DeniedSyscall::Kcmp,
        DeniedSyscall::KexecLoad,
        DeniedSyscall::KexecFileLoad,
        DeniedSyscall::InitModule,
        DeniedSyscall::FinitModule,
        DeniedSyscall::DeleteModule,
        DeniedSyscall::Reboot,
        DeniedSyscall::Swapon,
        DeniedSyscall::Swapoff,
        DeniedSyscall::Acct,
        DeniedSyscall::Quotactl,
        DeniedSyscall::QuotactlFd,
        DeniedSyscall::Vhangup,
        DeniedSyscall::Settimeofday,
        DeniedSyscall::ClockSettime,
        DeniedSyscall::ClockAdjtime,
        DeniedSyscall::Adjtimex,
        DeniedSyscall::Syslog,
        DeniedSyscall::LookupDcookie,
        DeniedSyscall::Bpf,
        DeniedSyscall::PerfEventOpen,
        DeniedSyscall::Userfaultfd,
        DeniedSyscall::AddKey,
        DeniedSyscall::RequestKey,
        DeniedSyscall::Keyctl,
        DeniedSyscall::OpenByHandleAt,
        DeniedSyscall::Iopl,
        DeniedSyscall::Ioperm,
    ];

    /// syscall 名（監査ログ SEC-4・TASK-41 とエラー表示用）。
    pub const fn name(self) -> &'static str {
        match self {
            DeniedSyscall::Unshare => "unshare",
            DeniedSyscall::Setns => "setns",
            DeniedSyscall::Mount => "mount",
            DeniedSyscall::Umount2 => "umount2",
            DeniedSyscall::PivotRoot => "pivot_root",
            DeniedSyscall::OpenTree => "open_tree",
            DeniedSyscall::MoveMount => "move_mount",
            DeniedSyscall::Fsopen => "fsopen",
            DeniedSyscall::Fsconfig => "fsconfig",
            DeniedSyscall::Fsmount => "fsmount",
            DeniedSyscall::Fspick => "fspick",
            DeniedSyscall::MountSetattr => "mount_setattr",
            DeniedSyscall::Ptrace => "ptrace",
            DeniedSyscall::ProcessVmReadv => "process_vm_readv",
            DeniedSyscall::ProcessVmWritev => "process_vm_writev",
            DeniedSyscall::Kcmp => "kcmp",
            DeniedSyscall::KexecLoad => "kexec_load",
            DeniedSyscall::KexecFileLoad => "kexec_file_load",
            DeniedSyscall::InitModule => "init_module",
            DeniedSyscall::FinitModule => "finit_module",
            DeniedSyscall::DeleteModule => "delete_module",
            DeniedSyscall::Reboot => "reboot",
            DeniedSyscall::Swapon => "swapon",
            DeniedSyscall::Swapoff => "swapoff",
            DeniedSyscall::Acct => "acct",
            DeniedSyscall::Quotactl => "quotactl",
            DeniedSyscall::QuotactlFd => "quotactl_fd",
            DeniedSyscall::Vhangup => "vhangup",
            DeniedSyscall::Settimeofday => "settimeofday",
            DeniedSyscall::ClockSettime => "clock_settime",
            DeniedSyscall::ClockAdjtime => "clock_adjtime",
            DeniedSyscall::Adjtimex => "adjtimex",
            DeniedSyscall::Syslog => "syslog",
            DeniedSyscall::LookupDcookie => "lookup_dcookie",
            DeniedSyscall::Bpf => "bpf",
            DeniedSyscall::PerfEventOpen => "perf_event_open",
            DeniedSyscall::Userfaultfd => "userfaultfd",
            DeniedSyscall::AddKey => "add_key",
            DeniedSyscall::RequestKey => "request_key",
            DeniedSyscall::Keyctl => "keyctl",
            DeniedSyscall::OpenByHandleAt => "open_by_handle_at",
            DeniedSyscall::Iopl => "iopl",
            DeniedSyscall::Ioperm => "ioperm",
        }
    }
}

/// syscall 番号の newtype。生の整数を公開 API に出さない。
///
/// 幅を `u32` にするのは、#838 の BPF 命令 `sock_filter.k`（`u32`）と `seccomp_data.nr` の
/// 32 bit 比較に合わせるため。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyscallNr(u32);

impl SyscallNr {
    /// 本モジュールのテーブル定義専用の構築子。
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    const fn new(nr: u32) -> Self {
        SyscallNr(nr)
    }

    /// 番号を返す。
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// `seccomp_data.arch` と比較する `AUDIT_ARCH_*` 値の newtype（`include/uapi/linux/audit.h`）。
///
/// #838 の BPF 先頭で検査し、別アーキの呼び出し（compat 等）を素通りさせないために使う。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AuditArch(u32);

impl AuditArch {
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    const fn new(v: u32) -> Self {
        AuditArch(v)
    }

    /// `AUDIT_ARCH_*` の値を返す。
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// 番号の引き当て結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyscallLookup {
    /// このアーキでの syscall 番号。
    Present(SyscallNr),
    /// この syscall はこのアーキに存在しない（遮断不要）。対応外アーキとは別物。
    AbsentOnArch,
}

/// 1 アーキ分の禁止 syscall 番号テーブル。
#[derive(Debug, PartialEq, Eq)]
pub struct ArchSyscallTable {
    audit_arch: AuditArch,
    entries: &'static [(DeniedSyscall, SyscallNr)],
    absent: &'static [DeniedSyscall],
}

impl ArchSyscallTable {
    /// `seccomp_data.arch` と比較する値。
    pub const fn audit_arch(&self) -> AuditArch {
        self.audit_arch
    }

    /// このアーキで遮断対象となる `(論理名, 番号)` の一覧。
    pub const fn entries(&self) -> &'static [(DeniedSyscall, SyscallNr)] {
        self.entries
    }

    /// このアーキに存在しない禁止 syscall。
    pub const fn absent(&self) -> &'static [DeniedSyscall] {
        self.absent
    }

    /// 論理名から番号を引く。
    pub fn number_of(&self, syscall: DeniedSyscall) -> SyscallLookup {
        for (name, nr) in self.entries {
            if *name == syscall {
                return SyscallLookup::Present(*nr);
            }
        }
        SyscallLookup::AbsentOnArch
    }
}

/// テーブル取得エラー。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeccompTableError {
    /// 対応外アーキ（x86_64・aarch64 以外）。フィルタ構築を失敗させること（fail-closed）。
    UnsupportedArch,
}

impl fmt::Display for SeccompTableError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SeccompTableError::UnsupportedArch => {
                write!(
                    f,
                    "seccomp syscall table is not available for this architecture"
                )
            }
        }
    }
}

impl std::error::Error for SeccompTableError {}

/// ビルド対象アーキのテーブルを返す。対応外アーキでは `Err`（fail-closed）。
pub fn table_for_target_arch() -> Result<&'static ArchSyscallTable, SeccompTableError> {
    nr::TABLE.ok_or(SeccompTableError::UnsupportedArch)
}

// ---- BPF フィルタ構築（TASK-38.1.2・#838） ----
//
// 定数はカーネル UAPI ヘッダの値（libc を使わず自前定義。本モジュールは OS 非依存のため
// `sys::EPERM` 等の Linux 限定定義は使えない）。

/// `BPF_LD`（`include/uapi/linux/bpf_common.h`）。
const BPF_LD: u16 = 0x00;
/// `BPF_W`（同上）。
const BPF_W: u16 = 0x00;
/// `BPF_ABS`（同上）。
const BPF_ABS: u16 = 0x20;
/// `BPF_JMP`（同上）。
const BPF_JMP: u16 = 0x05;
/// `BPF_JEQ`（同上）。
const BPF_JEQ: u16 = 0x10;
/// `BPF_JSET`（同上）。
const BPF_JSET: u16 = 0x40;
/// `BPF_K`（同上）。
const BPF_K: u16 = 0x00;
/// `BPF_RET`（同上）。
const BPF_RET: u16 = 0x06;
/// `BPF_MAXINSNS`（同上）。カーネルが受け付ける命令数の上限。
const BPF_MAXINSNS: usize = 4096;

/// `SECCOMP_RET_KILL_PROCESS`（`include/uapi/linux/seccomp.h`。Linux 4.14 以降）。
const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
/// `SECCOMP_RET_ERRNO`（同上）。
const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
/// `SECCOMP_RET_ALLOW`（同上）。
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
/// `SECCOMP_RET_DATA`（同上）。
const SECCOMP_RET_DATA: u32 = 0x0000_ffff;
/// `EPERM`（`include/uapi/asm-generic/errno-base.h`。全 Linux アーキ共通）。
const EPERM: u32 = 1;

/// `struct seccomp_data` の `nr` オフセット（アーキ非依存レイアウト）。
const SECCOMP_DATA_NR_OFFSET: u32 = 0;
/// `struct seccomp_data` の `arch` オフセット。
const SECCOMP_DATA_ARCH_OFFSET: u32 = 4;

/// x32 ABI の syscall 番号ビット（`arch/x86/include/uapi/asm/unistd.h` の `__X32_SYSCALL_BIT`）。
const X32_SYSCALL_BIT: u32 = 0x4000_0000;
/// x86_64 の `AUDIT_ARCH_X86_64`。x32 規則を x86_64 テーブルにだけ適用する判定に使う
/// （`cfg(target_arch)` ではなく値で判定し、どのホストでも両レイアウトをテストできるようにする）。
const AUDIT_ARCH_X86_64_VALUE: u32 = 0xC000_003E;

/// classic BPF 命令 1 個（`struct sock_filter` と同一レイアウト）。
///
/// `repr(C)` なのは、適用側（`exec::apply_seccomp_filter`。TASK-38.2・#177）が `sock_fprog.filter` へ `as_ptr()` を
/// コピーなしで渡すため。フィールドは非公開で、任意命令はこのモジュールの構築子からしか作れない
/// （壊れた値を表現できない型。REPAIR-2）。
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BpfInstruction {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

impl BpfInstruction {
    const fn stmt(code: u16, k: u32) -> Self {
        BpfInstruction {
            code,
            jt: 0,
            jf: 0,
            k,
        }
    }

    const fn jump(code: u16, k: u32, jt: u8, jf: u8) -> Self {
        BpfInstruction { code, jt, jf, k }
    }

    /// オペコード。
    pub const fn code(&self) -> u16 {
        self.code
    }

    /// 条件成立時のジャンプ量。
    pub const fn jt(&self) -> u8 {
        self.jt
    }

    /// 条件不成立時のジャンプ量。
    pub const fn jf(&self) -> u8 {
        self.jf
    }

    /// 即値・オフセット・戻り値。
    pub const fn k(&self) -> u32 {
        self.k
    }
}

/// 検証済みの seccomp BPF プログラム（1 以上 `BPF_MAXINSNS` 以下の命令列）。
///
/// [`build_deny_filter`] が唯一の生成経路。適用関数は `exec::apply_seccomp_filter`（TASK-38.2・#177）で、起動フローの
/// 組み込み段（TASK-38.3・#178）が exec 直前に適用する。遮断の結合テストは `tests/seccomp.rs`（TASK-38.4・#179）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeccompProgram(Vec<BpfInstruction>);

impl SeccompProgram {
    /// 空・上限超過を拒否して包む。
    fn new(insns: Vec<BpfInstruction>) -> Result<Self, SeccompBuildError> {
        if insns.is_empty() || insns.len() > BPF_MAXINSNS {
            return Err(SeccompBuildError::TooManyInstructions { len: insns.len() });
        }
        Ok(SeccompProgram(insns))
    }

    /// 命令列（`sock_filter` 配列として読める）。
    pub fn instructions(&self) -> &[BpfInstruction] {
        &self.0
    }

    /// 命令数（`sock_fprog.len` 用。検証により `u16` に収まる）。
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// 命令が無いか（構築検証により常に false）。
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// BPF 構築エラー。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeccompBuildError {
    /// 対応外アーキ（fail-closed。空・全許可プログラムは返さない）。
    UnsupportedArch,
    /// 命令数が `BPF_MAXINSNS` を超える（`len` は必要だった命令数）。
    TooManyInstructions {
        /// 必要だった命令数。
        len: usize,
    },
}

impl From<SeccompTableError> for SeccompBuildError {
    fn from(e: SeccompTableError) -> Self {
        match e {
            SeccompTableError::UnsupportedArch => SeccompBuildError::UnsupportedArch,
        }
    }
}

impl fmt::Display for SeccompBuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SeccompBuildError::UnsupportedArch => {
                write!(f, "seccomp filter is not available for this architecture")
            }
            SeccompBuildError::TooManyInstructions { len } => {
                write!(
                    f,
                    "seccomp filter needs {len} instructions, exceeding the limit of {BPF_MAXINSNS}"
                )
            }
        }
    }
}

impl std::error::Error for SeccompBuildError {}

/// 禁止 syscall テーブルから deny-list 型の seccomp BPF プログラムを構築する純粋関数（CORE-5・TASK-38.1.2）。
///
/// 生成する形は次のとおり。適用は実装済み（TASK-38.2・#177）、起動フローの組み込み段（TASK-38.3・#178）が exec 直前に呼ぶ。
///
/// 1. `seccomp_data.arch` が `table.audit_arch()` と違えば `KILL_PROCESS`（compat 経由の回避を防ぐ。
///    スレッド単位の `KILL` ではなくプロセス単位）
/// 2. x86_64 のみ、`nr & 0x4000_0000 != 0`（x32 ABI）を表照合より前に `KILL_PROCESS`。
///    ptrace のトレーサが syscall を skip させるために書く `nr = 0xFFFF_FFFF` もこれに該当する
///    （deny-list 型のため、トレース下の挙動は範囲外）
/// 3. `entries()` の各番号は `ERRNO(EPERM)`（`absent()` は命令を出さない）
/// 4. それ以外は `ALLOW`（許可リスト方式への発展は TASK-128・GPU-3 で範囲外）
///
/// 命令数は checked 演算で事前計算し、上限検証してから確保する。
pub fn build_deny_filter(table: &ArchSyscallTable) -> Result<SeccompProgram, SeccompBuildError> {
    let audit_arch = table.audit_arch().get();
    let is_x86_64 = audit_arch == AUDIT_ARCH_X86_64_VALUE;
    let entries = table.entries();

    let fixed: usize = if is_x86_64 { 4 + 2 + 1 } else { 4 + 1 };
    let total = entries
        .len()
        .checked_mul(2)
        .and_then(|n| n.checked_add(fixed))
        .unwrap_or(usize::MAX);
    if total > BPF_MAXINSNS {
        return Err(SeccompBuildError::TooManyInstructions { len: total });
    }

    let mut p = Vec::with_capacity(total);
    p.push(BpfInstruction::stmt(
        BPF_LD | BPF_W | BPF_ABS,
        SECCOMP_DATA_ARCH_OFFSET,
    ));
    p.push(BpfInstruction::jump(
        BPF_JMP | BPF_JEQ | BPF_K,
        audit_arch,
        1,
        0,
    ));
    p.push(BpfInstruction::stmt(
        BPF_RET | BPF_K,
        SECCOMP_RET_KILL_PROCESS,
    ));
    p.push(BpfInstruction::stmt(
        BPF_LD | BPF_W | BPF_ABS,
        SECCOMP_DATA_NR_OFFSET,
    ));
    if is_x86_64 {
        p.push(BpfInstruction::jump(
            BPF_JMP | BPF_JSET | BPF_K,
            X32_SYSCALL_BIT,
            0,
            1,
        ));
        p.push(BpfInstruction::stmt(
            BPF_RET | BPF_K,
            SECCOMP_RET_KILL_PROCESS,
        ));
    }
    for (_, nr) in entries {
        p.push(BpfInstruction::jump(
            BPF_JMP | BPF_JEQ | BPF_K,
            nr.get(),
            0,
            1,
        ));
        p.push(BpfInstruction::stmt(
            BPF_RET | BPF_K,
            SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA),
        ));
    }
    p.push(BpfInstruction::stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
    SeccompProgram::new(p)
}

/// ビルド対象アーキのテーブルから BPF を構築する。対応外アーキは `Err(UnsupportedArch)`（fail-closed）。
pub fn build_filter_for_target_arch() -> Result<SeccompProgram, SeccompBuildError> {
    build_deny_filter(table_for_target_arch()?)
}

/// x86_64 の番号（出典: `arch/x86/entry/syscalls/syscall_64.tbl`。`AUDIT_ARCH_X86_64` = EM_X86_64(62) | 64BIT | LE）。
#[cfg(target_arch = "x86_64")]
mod nr {
    use super::{ArchSyscallTable, AuditArch, DeniedSyscall as D, SyscallNr as N};

    const AUDIT_ARCH: AuditArch = AuditArch::new(0xC000_003E);

    static ENTRIES: [(D, N); 43] = [
        (D::Unshare, N::new(272)),
        (D::Setns, N::new(308)),
        (D::Mount, N::new(165)),
        (D::Umount2, N::new(166)),
        (D::PivotRoot, N::new(155)),
        (D::OpenTree, N::new(428)),
        (D::MoveMount, N::new(429)),
        (D::Fsopen, N::new(430)),
        (D::Fsconfig, N::new(431)),
        (D::Fsmount, N::new(432)),
        (D::Fspick, N::new(433)),
        (D::MountSetattr, N::new(442)),
        (D::Ptrace, N::new(101)),
        (D::ProcessVmReadv, N::new(310)),
        (D::ProcessVmWritev, N::new(311)),
        (D::Kcmp, N::new(312)),
        (D::KexecLoad, N::new(246)),
        (D::KexecFileLoad, N::new(320)),
        (D::InitModule, N::new(175)),
        (D::FinitModule, N::new(313)),
        (D::DeleteModule, N::new(176)),
        (D::Reboot, N::new(169)),
        (D::Swapon, N::new(167)),
        (D::Swapoff, N::new(168)),
        (D::Acct, N::new(163)),
        (D::Quotactl, N::new(179)),
        (D::QuotactlFd, N::new(443)),
        (D::Vhangup, N::new(153)),
        (D::Settimeofday, N::new(164)),
        (D::ClockSettime, N::new(227)),
        (D::ClockAdjtime, N::new(305)),
        (D::Adjtimex, N::new(159)),
        (D::Syslog, N::new(103)),
        (D::LookupDcookie, N::new(212)),
        (D::Bpf, N::new(321)),
        (D::PerfEventOpen, N::new(298)),
        (D::Userfaultfd, N::new(323)),
        (D::AddKey, N::new(248)),
        (D::RequestKey, N::new(249)),
        (D::Keyctl, N::new(250)),
        (D::OpenByHandleAt, N::new(304)),
        (D::Iopl, N::new(172)),
        (D::Ioperm, N::new(173)),
    ];

    static ABSENT: [D; 0] = [];

    static ARCH_TABLE: ArchSyscallTable = ArchSyscallTable {
        audit_arch: AUDIT_ARCH,
        entries: &ENTRIES,
        absent: &ABSENT,
    };

    pub(super) const TABLE: Option<&'static ArchSyscallTable> = Some(&ARCH_TABLE);
}

/// aarch64 の番号（出典: `include/uapi/asm-generic/unistd.h`（arm64 は汎用テーブル）。`AUDIT_ARCH_AARCH64` = EM_AARCH64(183) | 64BIT | LE）。
#[cfg(target_arch = "aarch64")]
mod nr {
    use super::{ArchSyscallTable, AuditArch, DeniedSyscall as D, SyscallNr as N};

    const AUDIT_ARCH: AuditArch = AuditArch::new(0xC000_00B7);

    static ENTRIES: [(D, N); 41] = [
        (D::Unshare, N::new(97)),
        (D::Setns, N::new(268)),
        (D::Mount, N::new(40)),
        (D::Umount2, N::new(39)),
        (D::PivotRoot, N::new(41)),
        (D::OpenTree, N::new(428)),
        (D::MoveMount, N::new(429)),
        (D::Fsopen, N::new(430)),
        (D::Fsconfig, N::new(431)),
        (D::Fsmount, N::new(432)),
        (D::Fspick, N::new(433)),
        (D::MountSetattr, N::new(442)),
        (D::Ptrace, N::new(117)),
        (D::ProcessVmReadv, N::new(270)),
        (D::ProcessVmWritev, N::new(271)),
        (D::Kcmp, N::new(272)),
        (D::KexecLoad, N::new(104)),
        (D::KexecFileLoad, N::new(294)),
        (D::InitModule, N::new(105)),
        (D::FinitModule, N::new(273)),
        (D::DeleteModule, N::new(106)),
        (D::Reboot, N::new(142)),
        (D::Swapon, N::new(224)),
        (D::Swapoff, N::new(225)),
        (D::Acct, N::new(89)),
        (D::Quotactl, N::new(60)),
        (D::QuotactlFd, N::new(443)),
        (D::Vhangup, N::new(58)),
        (D::Settimeofday, N::new(170)),
        (D::ClockSettime, N::new(112)),
        (D::ClockAdjtime, N::new(266)),
        (D::Adjtimex, N::new(171)),
        (D::Syslog, N::new(116)),
        (D::LookupDcookie, N::new(18)),
        (D::Bpf, N::new(280)),
        (D::PerfEventOpen, N::new(241)),
        (D::Userfaultfd, N::new(282)),
        (D::AddKey, N::new(217)),
        (D::RequestKey, N::new(218)),
        (D::Keyctl, N::new(219)),
        (D::OpenByHandleAt, N::new(265)),
    ];

    static ABSENT: [D; 2] = [D::Iopl, D::Ioperm];

    static ARCH_TABLE: ArchSyscallTable = ArchSyscallTable {
        audit_arch: AUDIT_ARCH,
        entries: &ENTRIES,
        absent: &ABSENT,
    };

    pub(super) const TABLE: Option<&'static ArchSyscallTable> = Some(&ARCH_TABLE);
}

/// 対応外アーキ（fail-closed。空テーブルで全許可にしない）。
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
mod nr {
    use super::ArchSyscallTable;

    pub(super) const TABLE: Option<&'static ArchSyscallTable> = None;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ネイティブアーキのテーブル（対応アーキのテストでのみ使用）。
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    fn native() -> &'static ArchSyscallTable {
        table_for_target_arch().expect("supported arch")
    }

    #[cfg(target_arch = "x86_64")]
    const EXPECTED: &[(DeniedSyscall, u32)] = &[
        (DeniedSyscall::Unshare, 272),
        (DeniedSyscall::Setns, 308),
        (DeniedSyscall::Mount, 165),
        (DeniedSyscall::Umount2, 166),
        (DeniedSyscall::PivotRoot, 155),
        (DeniedSyscall::OpenTree, 428),
        (DeniedSyscall::MoveMount, 429),
        (DeniedSyscall::Fsopen, 430),
        (DeniedSyscall::Fsconfig, 431),
        (DeniedSyscall::Fsmount, 432),
        (DeniedSyscall::Fspick, 433),
        (DeniedSyscall::MountSetattr, 442),
        (DeniedSyscall::Ptrace, 101),
        (DeniedSyscall::ProcessVmReadv, 310),
        (DeniedSyscall::ProcessVmWritev, 311),
        (DeniedSyscall::Kcmp, 312),
        (DeniedSyscall::KexecLoad, 246),
        (DeniedSyscall::KexecFileLoad, 320),
        (DeniedSyscall::InitModule, 175),
        (DeniedSyscall::FinitModule, 313),
        (DeniedSyscall::DeleteModule, 176),
        (DeniedSyscall::Reboot, 169),
        (DeniedSyscall::Swapon, 167),
        (DeniedSyscall::Swapoff, 168),
        (DeniedSyscall::Acct, 163),
        (DeniedSyscall::Quotactl, 179),
        (DeniedSyscall::QuotactlFd, 443),
        (DeniedSyscall::Vhangup, 153),
        (DeniedSyscall::Settimeofday, 164),
        (DeniedSyscall::ClockSettime, 227),
        (DeniedSyscall::ClockAdjtime, 305),
        (DeniedSyscall::Adjtimex, 159),
        (DeniedSyscall::Syslog, 103),
        (DeniedSyscall::LookupDcookie, 212),
        (DeniedSyscall::Bpf, 321),
        (DeniedSyscall::PerfEventOpen, 298),
        (DeniedSyscall::Userfaultfd, 323),
        (DeniedSyscall::AddKey, 248),
        (DeniedSyscall::RequestKey, 249),
        (DeniedSyscall::Keyctl, 250),
        (DeniedSyscall::OpenByHandleAt, 304),
        (DeniedSyscall::Iopl, 172),
        (DeniedSyscall::Ioperm, 173),
    ];

    #[cfg(target_arch = "aarch64")]
    const EXPECTED: &[(DeniedSyscall, u32)] = &[
        (DeniedSyscall::Unshare, 97),
        (DeniedSyscall::Setns, 268),
        (DeniedSyscall::Mount, 40),
        (DeniedSyscall::Umount2, 39),
        (DeniedSyscall::PivotRoot, 41),
        (DeniedSyscall::OpenTree, 428),
        (DeniedSyscall::MoveMount, 429),
        (DeniedSyscall::Fsopen, 430),
        (DeniedSyscall::Fsconfig, 431),
        (DeniedSyscall::Fsmount, 432),
        (DeniedSyscall::Fspick, 433),
        (DeniedSyscall::MountSetattr, 442),
        (DeniedSyscall::Ptrace, 117),
        (DeniedSyscall::ProcessVmReadv, 270),
        (DeniedSyscall::ProcessVmWritev, 271),
        (DeniedSyscall::Kcmp, 272),
        (DeniedSyscall::KexecLoad, 104),
        (DeniedSyscall::KexecFileLoad, 294),
        (DeniedSyscall::InitModule, 105),
        (DeniedSyscall::FinitModule, 273),
        (DeniedSyscall::DeleteModule, 106),
        (DeniedSyscall::Reboot, 142),
        (DeniedSyscall::Swapon, 224),
        (DeniedSyscall::Swapoff, 225),
        (DeniedSyscall::Acct, 89),
        (DeniedSyscall::Quotactl, 60),
        (DeniedSyscall::QuotactlFd, 443),
        (DeniedSyscall::Vhangup, 58),
        (DeniedSyscall::Settimeofday, 170),
        (DeniedSyscall::ClockSettime, 112),
        (DeniedSyscall::ClockAdjtime, 266),
        (DeniedSyscall::Adjtimex, 171),
        (DeniedSyscall::Syslog, 116),
        (DeniedSyscall::LookupDcookie, 18),
        (DeniedSyscall::Bpf, 280),
        (DeniedSyscall::PerfEventOpen, 241),
        (DeniedSyscall::Userfaultfd, 282),
        (DeniedSyscall::AddKey, 217),
        (DeniedSyscall::RequestKey, 218),
        (DeniedSyscall::Keyctl, 219),
        (DeniedSyscall::OpenByHandleAt, 265),
    ];

    /// CORE-5・TASK-38.1.1: 全エントリの番号と AUDIT_ARCH を具体値で照合する。
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    fn core5_task38_1_1_native_table_numbers() {
        let t = native();
        let got: Vec<(DeniedSyscall, u32)> =
            t.entries().iter().map(|(d, n)| (*d, n.get())).collect();
        assert_eq!(got, EXPECTED.to_vec());
        #[cfg(target_arch = "x86_64")]
        assert_eq!(t.audit_arch().get(), 0xC000_003E);
        #[cfg(target_arch = "aarch64")]
        assert_eq!(t.audit_arch().get(), 0xC000_00B7);
    }

    /// 各 variant が entries と absent のちょうど一方に現れる。
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    fn core5_task38_1_1_table_is_complete() {
        let t = native();
        for d in DeniedSyscall::ALL {
            let in_entries = t.entries().iter().filter(|(e, _)| *e == d).count();
            let in_absent = t.absent().iter().filter(|e| **e == d).count();
            assert_eq!(in_entries + in_absent, 1, "{}", d.name());
        }
        assert_eq!(
            t.entries().len() + t.absent().len(),
            DeniedSyscall::ALL.len()
        );
    }

    /// 番号の重複が無い。
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    fn core5_task38_1_1_no_duplicate_numbers() {
        let t = native();
        let mut nrs: Vec<u32> = t.entries().iter().map(|(_, n)| n.get()).collect();
        nrs.sort_unstable();
        let before = nrs.len();
        nrs.dedup();
        assert_eq!(nrs.len(), before);
    }

    /// ランタイム自身が seccomp 適用後に使う syscall を禁止していない（契約）。
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    fn core5_task38_1_1_runtime_required_syscalls_not_denied() {
        // execve・execveat・prctl・capget・capset・close_range・exit・exit_group・
        // pidfd_open・pidfd_send_signal・rt_sigreturn・memfd_create・fcntl
        // （memfd_create・fcntl は封印した複製からの実行。TASK-163 追補・#1530・SUP-6）、
        // faccessat2・pread64・pwrite64（複製の前の実行権限の照合と複製の読み書き。TASK-163 追補・#1531・SEC-1）
        #[cfg(target_arch = "x86_64")]
        let required: [u32; 16] = [
            59, 322, 157, 125, 126, 436, 60, 231, 434, 424, 15, 319, 72, 439, 17, 18,
        ];
        #[cfg(target_arch = "aarch64")]
        let required: [u32; 16] = [
            221, 281, 167, 90, 91, 436, 93, 94, 434, 424, 139, 279, 25, 439, 67, 68,
        ];
        let t = native();
        for (d, n) in t.entries() {
            assert!(!required.contains(&n.get()), "{} is required", d.name());
        }
    }

    /// iopl / ioperm は x86_64 にのみ存在する。
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    fn core5_task38_1_1_absent_on_arch() {
        let t = native();
        #[cfg(target_arch = "x86_64")]
        {
            assert_eq!(
                t.number_of(DeniedSyscall::Iopl),
                SyscallLookup::Present(SyscallNr::new(172))
            );
            assert_eq!(
                t.number_of(DeniedSyscall::Ioperm),
                SyscallLookup::Present(SyscallNr::new(173))
            );
        }
        #[cfg(target_arch = "aarch64")]
        {
            assert_eq!(
                t.number_of(DeniedSyscall::Iopl),
                SyscallLookup::AbsentOnArch
            );
            assert_eq!(
                t.number_of(DeniedSyscall::Ioperm),
                SyscallLookup::AbsentOnArch
            );
        }
    }

    /// 対応外アーキは fail-closed。
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    #[test]
    fn core5_task38_1_1_unsupported_arch_is_fail_closed() {
        assert_eq!(
            table_for_target_arch().unwrap_err(),
            SeccompTableError::UnsupportedArch
        );
    }

    /// 名前の具体値と件数。
    #[test]
    fn core5_task38_1_1_names() {
        assert_eq!(DeniedSyscall::KexecLoad.name(), "kexec_load");
        assert_eq!(DeniedSyscall::Unshare.name(), "unshare");
        assert_eq!(DeniedSyscall::OpenByHandleAt.name(), "open_by_handle_at");
        assert_eq!(DeniedSyscall::ALL.len(), 43);
        assert_eq!(
            SeccompTableError::UnsupportedArch.to_string(),
            "seccomp syscall table is not available for this architecture"
        );
    }
}

/// BPF 構築（TASK-38.1.2・#838）のテスト。両アーキのテーブルをリテラルで組み、ホストに依存せず検証する。
#[cfg(test)]
mod bpf_tests {
    use super::*;

    const X86_NRS: [u32; 43] = [
        272, 308, 165, 166, 155, 428, 429, 430, 431, 432, 433, 442, 101, 310, 311, 312, 246, 320,
        175, 313, 176, 169, 167, 168, 163, 179, 443, 153, 164, 227, 305, 159, 103, 212, 321, 298,
        323, 248, 249, 250, 304, 172, 173,
    ];
    const AARCH_NRS: [u32; 41] = [
        97, 268, 40, 39, 41, 428, 429, 430, 431, 432, 433, 442, 117, 270, 271, 272, 104, 294, 105,
        273, 106, 142, 224, 225, 89, 60, 443, 58, 170, 112, 266, 171, 116, 18, 280, 241, 282, 217,
        218, 219, 265,
    ];
    /// ランタイム自身が使う 11 syscall（x86_64）。
    const X86_RUNTIME: [u32; 11] = [59, 322, 157, 125, 126, 436, 60, 231, 434, 424, 15];
    /// 同（aarch64）。
    const AARCH_RUNTIME: [u32; 11] = [221, 281, 167, 90, 91, 436, 93, 94, 434, 424, 139];

    const KILL: u32 = 0x8000_0000;
    const ERRNO_EPERM: u32 = 0x0005_0001;
    const ALLOW: u32 = 0x7fff_0000;

    fn leak_table(audit: u32, nrs: &[u32]) -> &'static ArchSyscallTable {
        let entries: Vec<(DeniedSyscall, SyscallNr)> = nrs
            .iter()
            .enumerate()
            .map(|(i, n)| {
                let d = DeniedSyscall::ALL[i % DeniedSyscall::ALL.len()];
                (d, SyscallNr(*n))
            })
            .collect();
        let absent: &'static [DeniedSyscall] = Box::leak(Vec::new().into_boxed_slice());
        Box::leak(Box::new(ArchSyscallTable {
            audit_arch: AuditArch(audit),
            entries: Box::leak(entries.into_boxed_slice()),
            absent,
        }))
    }

    fn x86() -> &'static ArchSyscallTable {
        leak_table(0xC000_003E, &X86_NRS)
    }

    fn aarch() -> &'static ArchSyscallTable {
        leak_table(0xC000_00B7, &AARCH_NRS)
    }

    /// テスト専用の cBPF 評価器（LD W ABS・JEQ K・JSET K・RET K のみ）。
    fn eval(p: &SeccompProgram, nr: u32, arch: u32) -> u32 {
        let insns = p.instructions();
        let (mut pc, mut a) = (0usize, 0u32);
        loop {
            let i = insns.get(pc).expect("pc in range");
            match i.code() {
                0x20 => {
                    a = match i.k() {
                        0 => nr,
                        4 => arch,
                        k => panic!("bad offset {k}"),
                    };
                    pc += 1;
                }
                0x15 => pc += 1 + usize::from(if a == i.k() { i.jt() } else { i.jf() }),
                0x45 => pc += 1 + usize::from(if a & i.k() != 0 { i.jt() } else { i.jf() }),
                0x06 => return i.k(),
                c => panic!("bad opcode {c:#x}"),
            }
        }
    }

    #[test]
    fn core5_task38_1_2_layout() {
        assert_eq!(std::mem::size_of::<BpfInstruction>(), 8);
        assert_eq!(std::mem::align_of::<BpfInstruction>(), 4);
    }

    #[test]
    fn core5_task38_1_2_x86_64_shape() {
        let p = build_deny_filter(x86()).unwrap();
        assert_eq!(p.len(), 93);
        assert!(!p.is_empty());
        let i = p.instructions();
        let t = |x: &BpfInstruction| (x.code(), x.jt(), x.jf(), x.k());
        assert_eq!(t(&i[0]), (0x20, 0, 0, 4));
        assert_eq!(t(&i[1]), (0x15, 1, 0, 0xC000_003E));
        assert_eq!(t(&i[2]), (0x06, 0, 0, 0x8000_0000));
        assert_eq!(t(&i[3]), (0x20, 0, 0, 0));
        assert_eq!(t(&i[4]), (0x45, 0, 1, 0x4000_0000));
        assert_eq!(t(&i[5]), (0x06, 0, 0, 0x8000_0000));
        assert_eq!(t(&i[6]), (0x15, 0, 1, 272));
        assert_eq!(t(&i[7]), (0x06, 0, 0, ERRNO_EPERM));
        assert_eq!(t(&i[92]), (0x06, 0, 0, 0x7fff_0000));
    }

    #[test]
    fn core5_task38_1_2_aarch64_shape() {
        let p = build_deny_filter(aarch()).unwrap();
        assert_eq!(p.len(), 87);
        assert!(p.instructions().iter().all(|i| i.code() != 0x45));
        assert!(
            !p.instructions()
                .iter()
                .any(|i| { i.code() == 0x15 && (i.k() == 172 || i.k() == 173) })
        );
        let last = p.instructions().last().unwrap();
        assert_eq!((last.code(), last.k()), (0x06, 0x7fff_0000));
    }

    #[test]
    fn core5_task38_1_2_jumps_in_range() {
        for t in [x86(), aarch()] {
            let p = build_deny_filter(t).unwrap();
            for (idx, i) in p.instructions().iter().enumerate() {
                if i.code() == 0x15 || i.code() == 0x45 {
                    assert!(idx + 1 + usize::from(i.jt()) < p.len());
                    assert!(idx + 1 + usize::from(i.jf()) < p.len());
                }
            }
        }
    }

    #[test]
    fn core5_task38_1_2_evaluation() {
        let px = build_deny_filter(x86()).unwrap();
        for n in X86_NRS {
            assert_eq!(eval(&px, n, 0xC000_003E), ERRNO_EPERM, "nr {n}");
        }
        for n in X86_RUNTIME {
            assert_eq!(eval(&px, n, 0xC000_003E), ALLOW, "nr {n}");
        }
        assert_eq!(eval(&px, 272, 0xC000_00B7), KILL);
        assert_eq!(eval(&px, 3, 0x4000_0003), KILL);
        assert_eq!(eval(&px, 0x4000_0000 | 272, 0xC000_003E), KILL);
        assert_eq!(eval(&px, 0x4000_0000, 0xC000_003E), KILL);
        assert_eq!(eval(&px, 0xFFFF_FFFF, 0xC000_003E), KILL);

        let pa = build_deny_filter(aarch()).unwrap();
        for n in AARCH_NRS {
            assert_eq!(eval(&pa, n, 0xC000_00B7), ERRNO_EPERM, "nr {n}");
        }
        for n in AARCH_RUNTIME {
            assert_eq!(eval(&pa, n, 0xC000_00B7), ALLOW, "nr {n}");
        }
        assert_eq!(eval(&pa, 97, 0xC000_003E), KILL);
        assert_eq!(eval(&pa, 0x4000_0000 | 97, 0xC000_00B7), ALLOW);
    }

    #[test]
    fn core5_task38_1_2_too_many_instructions() {
        let nrs: Vec<u32> = (0..2100).collect();
        let t = leak_table(0xC000_00B7, &nrs);
        assert_eq!(
            build_deny_filter(t).unwrap_err(),
            SeccompBuildError::TooManyInstructions { len: 4205 }
        );
        assert_eq!(
            SeccompBuildError::TooManyInstructions { len: 4205 }.to_string(),
            "seccomp filter needs 4205 instructions, exceeding the limit of 4096"
        );
    }

    #[test]
    fn core5_task38_1_2_errors() {
        assert_eq!(
            SeccompBuildError::from(SeccompTableError::UnsupportedArch),
            SeccompBuildError::UnsupportedArch
        );
        assert_eq!(
            SeccompBuildError::UnsupportedArch.to_string(),
            "seccomp filter is not available for this architecture"
        );
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn core5_task38_1_2_native_x86_64() {
        assert_eq!(build_filter_for_target_arch().unwrap().len(), 93);
    }

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn core5_task38_1_2_native_aarch64() {
        assert_eq!(build_filter_for_target_arch().unwrap().len(), 87);
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    #[test]
    fn core5_task38_1_2_unsupported_arch_is_fail_closed() {
        assert_eq!(
            build_filter_for_target_arch().unwrap_err(),
            SeccompBuildError::UnsupportedArch
        );
    }
}
