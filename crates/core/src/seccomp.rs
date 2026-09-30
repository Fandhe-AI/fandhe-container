//! 禁止 syscall の一覧とアーキテクチャ別 syscall 番号テーブル（CORE-5・TASK-38.1.1・#837・MS-2）。
//!
//! # 役割と呼び出し文脈
//!
//! コンテナ内から拒否すべき syscall（`unshare`・`mount`・`ptrace`・`kexec_load` 等）を論理名
//! [`DeniedSyscall`] で列挙し、x86_64 / aarch64 それぞれの番号を [`ArchSyscallTable`] として
//! 提供するデータ層である。capability 最小化（SEC-1・TASK-37）とは独立に効く多層防御の土台で、
//! CAP を持っていても、あるいは誤って付与しても、これらの syscall による脱出経路を塞ぐ。
//!
//! 本モジュールは syscall を発行しない純粋なデータで、BPF プログラムの構築（`seccomp_data.arch`
//! 検査を含む。#838・TASK-38.1.2）が [`table_for_target_arch`] を使う予定である。
//! **フィルタの構築・適用・起動フローへの組み込みは未実装**（適用は TASK-38.2・#177、
//! `exec/stages.rs` への組み込みは TASK-38.3・#178）。本モジュール単体ではコンテナを保護しない
//! （REPAIR-3）。
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
//!   `exit`・`exit_group`・`pidfd_open`・`pidfd_send_signal`・`rt_sigreturn` は禁止対象にしない
//!   （テストで機械照合）。適用前に完了する `unshare`・`mount`・`pivot_root`・`umount2` は禁止してよい
//! - **x32 ABI は BPF 構築側が明示的に拒否する**: x86_64 の `AUDIT_ARCH_X86_64` は x32 ABI の
//!   syscall でも同じ値になり、`arch` の照合だけでは x32 を区別できない。x32 の syscall 番号には
//!   `0x4000_0000`（`__X32_SYSCALL_BIT`）が付くため、本テーブルの番号との単純比較では
//!   `unshare` 等を遮断できない。#838（TASK-38.1.2）の BPF 構築は、x86_64 で
//!   `nr & 0x4000_0000 != 0` の呼び出しを（テーブル照合の前に）無条件に拒否しなければならない。
//!   本テーブルは x32 番号を含まず、この拒否は呼び出し側の責務である（CORE-5）
//! - 各アーキの番号は `mod nr` に個別定義し、値が同じでも他アーキの定数を流用しない
//!   （`sys.rs` の `consts` と同じ流儀。アーキ差の取り違えは誤遮断・遮断漏れに直結する）
//!
//! # cfg の方針
//!
//! 値は Linux カーネル ABI の番号だが、syscall を発行しないデータであり、3 OS の CI
//! （macOS arm64 runner が aarch64 テーブルを検証する）で固定値テストを走らせるため、
//! `target_os` では分岐せず `target_arch` のみで分ける。適用（`seccomp(2)`・
//! `prctl(PR_SET_SECCOMP)`）は TASK-38.2 で Linux 限定の `exec` / `sys` 側に置く。
//!
//! # 範囲外
//!
//! 引数ベースのフィルタ（`clone`・`clone3` の `CLONE_NEW*`、`personality` 等）、moby 既定プロファイルの
//! 許可リスト方式への発展（TASK-128・GPU-3）、監査ログ連携（TASK-41・SEC-4）は扱わない。
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
        // pidfd_open・pidfd_send_signal・rt_sigreturn
        #[cfg(target_arch = "x86_64")]
        let required: [u32; 11] = [59, 322, 157, 125, 126, 436, 60, 231, 434, 424, 15];
        #[cfg(target_arch = "aarch64")]
        let required: [u32; 11] = [221, 281, 167, 90, 91, 436, 93, 94, 434, 424, 139];
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
