//! コンテナへ付与する capability 集合の型（SEC-1・TASK-37.1・#172・MS-2）。
//!
//! # 役割と呼び出し文脈
//!
//! OCI 既定の最小セット（moby の既定 14 個。`daemon/pkg/oci/caps/defaults.go`）を表す
//! OS 非依存のデータ型。適用処理（`capset(2)`・`prctl(2)`）は Linux 限定の
//! `exec/capabilities.rs` の `apply_default_capabilities` が担い、本モジュールの
//! [`CapabilitySet::oci_default`] を許可集合として使う。組み込みのステージ（`StagePipeline::run_then`）から呼ばれる（#173・TASK-37.2）。
//! 将来 `config.json` の `process.capabilities` を解釈する際の型としても使える
//! （現状は `UnappliedField::ProcessCapabilities` として記録するのみ）。
//!
//! # 契約
//!
//! - [`Capability`] はカーネルの `include/uapi/linux/capability.h` の 0〜40 を列挙する
//! - [`CapabilitySet`] は生のビット値を公開しない。カーネルが知るが本 enum が知らない番号
//!   （新しいカーネルの capability）は `contains_index` が常に `false` を返し、
//!   適用側が fail-closed に drop 対象として扱える
//! - `CAP_SYS_ADMIN`・`CAP_SYS_MODULE`・`CAP_SYS_PTRACE` 等は既定集合に含めない（SEC-1）

/// Linux capability（`include/uapi/linux/capability.h` の 0〜40）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Capability {
    /// `CAP_CHOWN`（0）。
    Chown = 0,
    /// `CAP_DAC_OVERRIDE`（1）。
    DacOverride = 1,
    /// `CAP_DAC_READ_SEARCH`（2）。
    DacReadSearch = 2,
    /// `CAP_FOWNER`（3）。
    Fowner = 3,
    /// `CAP_FSETID`（4）。
    Fsetid = 4,
    /// `CAP_KILL`（5）。
    Kill = 5,
    /// `CAP_SETGID`（6）。
    Setgid = 6,
    /// `CAP_SETUID`（7）。
    Setuid = 7,
    /// `CAP_SETPCAP`（8）。
    Setpcap = 8,
    /// `CAP_LINUX_IMMUTABLE`（9）。
    LinuxImmutable = 9,
    /// `CAP_NET_BIND_SERVICE`（10）。
    NetBindService = 10,
    /// `CAP_NET_BROADCAST`（11）。
    NetBroadcast = 11,
    /// `CAP_NET_ADMIN`（12）。
    NetAdmin = 12,
    /// `CAP_NET_RAW`（13）。
    NetRaw = 13,
    /// `CAP_IPC_LOCK`（14）。
    IpcLock = 14,
    /// `CAP_IPC_OWNER`（15）。
    IpcOwner = 15,
    /// `CAP_SYS_MODULE`（16）。
    SysModule = 16,
    /// `CAP_SYS_RAWIO`（17）。
    SysRawio = 17,
    /// `CAP_SYS_CHROOT`（18）。
    SysChroot = 18,
    /// `CAP_SYS_PTRACE`（19）。
    SysPtrace = 19,
    /// `CAP_SYS_PACCT`（20）。
    SysPacct = 20,
    /// `CAP_SYS_ADMIN`（21）。
    SysAdmin = 21,
    /// `CAP_SYS_BOOT`（22）。
    SysBoot = 22,
    /// `CAP_SYS_NICE`（23）。
    SysNice = 23,
    /// `CAP_SYS_RESOURCE`（24）。
    SysResource = 24,
    /// `CAP_SYS_TIME`（25）。
    SysTime = 25,
    /// `CAP_SYS_TTY_CONFIG`（26）。
    SysTtyConfig = 26,
    /// `CAP_MKNOD`（27）。
    Mknod = 27,
    /// `CAP_LEASE`（28）。
    Lease = 28,
    /// `CAP_AUDIT_WRITE`（29）。
    AuditWrite = 29,
    /// `CAP_AUDIT_CONTROL`（30）。
    AuditControl = 30,
    /// `CAP_SETFCAP`（31）。
    Setfcap = 31,
    /// `CAP_MAC_OVERRIDE`（32）。
    MacOverride = 32,
    /// `CAP_MAC_ADMIN`（33）。
    MacAdmin = 33,
    /// `CAP_SYSLOG`（34）。
    Syslog = 34,
    /// `CAP_WAKE_ALARM`（35）。
    WakeAlarm = 35,
    /// `CAP_BLOCK_SUSPEND`（36）。
    BlockSuspend = 36,
    /// `CAP_AUDIT_READ`（37）。
    AuditRead = 37,
    /// `CAP_PERFMON`（38）。
    Perfmon = 38,
    /// `CAP_BPF`（39）。
    Bpf = 39,
    /// `CAP_CHECKPOINT_RESTORE`（40）。
    CheckpointRestore = 40,
}

impl Capability {
    /// カーネルの番号順の全 capability。
    pub const ALL: [Capability; 41] = [
        Self::Chown,
        Self::DacOverride,
        Self::DacReadSearch,
        Self::Fowner,
        Self::Fsetid,
        Self::Kill,
        Self::Setgid,
        Self::Setuid,
        Self::Setpcap,
        Self::LinuxImmutable,
        Self::NetBindService,
        Self::NetBroadcast,
        Self::NetAdmin,
        Self::NetRaw,
        Self::IpcLock,
        Self::IpcOwner,
        Self::SysModule,
        Self::SysRawio,
        Self::SysChroot,
        Self::SysPtrace,
        Self::SysPacct,
        Self::SysAdmin,
        Self::SysBoot,
        Self::SysNice,
        Self::SysResource,
        Self::SysTime,
        Self::SysTtyConfig,
        Self::Mknod,
        Self::Lease,
        Self::AuditWrite,
        Self::AuditControl,
        Self::Setfcap,
        Self::MacOverride,
        Self::MacAdmin,
        Self::Syslog,
        Self::WakeAlarm,
        Self::BlockSuspend,
        Self::AuditRead,
        Self::Perfmon,
        Self::Bpf,
        Self::CheckpointRestore,
    ];

    /// カーネルの capability 番号（ビット位置）。
    pub fn index(self) -> u8 {
        match self {
            Self::Chown => 0,
            Self::DacOverride => 1,
            Self::DacReadSearch => 2,
            Self::Fowner => 3,
            Self::Fsetid => 4,
            Self::Kill => 5,
            Self::Setgid => 6,
            Self::Setuid => 7,
            Self::Setpcap => 8,
            Self::LinuxImmutable => 9,
            Self::NetBindService => 10,
            Self::NetBroadcast => 11,
            Self::NetAdmin => 12,
            Self::NetRaw => 13,
            Self::IpcLock => 14,
            Self::IpcOwner => 15,
            Self::SysModule => 16,
            Self::SysRawio => 17,
            Self::SysChroot => 18,
            Self::SysPtrace => 19,
            Self::SysPacct => 20,
            Self::SysAdmin => 21,
            Self::SysBoot => 22,
            Self::SysNice => 23,
            Self::SysResource => 24,
            Self::SysTime => 25,
            Self::SysTtyConfig => 26,
            Self::Mknod => 27,
            Self::Lease => 28,
            Self::AuditWrite => 29,
            Self::AuditControl => 30,
            Self::Setfcap => 31,
            Self::MacOverride => 32,
            Self::MacAdmin => 33,
            Self::Syslog => 34,
            Self::WakeAlarm => 35,
            Self::BlockSuspend => 36,
            Self::AuditRead => 37,
            Self::Perfmon => 38,
            Self::Bpf => 39,
            Self::CheckpointRestore => 40,
        }
    }

    /// `CAP_CHOWN` 形式の機械可読な識別子。
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Chown => "CAP_CHOWN",
            Self::DacOverride => "CAP_DAC_OVERRIDE",
            Self::DacReadSearch => "CAP_DAC_READ_SEARCH",
            Self::Fowner => "CAP_FOWNER",
            Self::Fsetid => "CAP_FSETID",
            Self::Kill => "CAP_KILL",
            Self::Setgid => "CAP_SETGID",
            Self::Setuid => "CAP_SETUID",
            Self::Setpcap => "CAP_SETPCAP",
            Self::LinuxImmutable => "CAP_LINUX_IMMUTABLE",
            Self::NetBindService => "CAP_NET_BIND_SERVICE",
            Self::NetBroadcast => "CAP_NET_BROADCAST",
            Self::NetAdmin => "CAP_NET_ADMIN",
            Self::NetRaw => "CAP_NET_RAW",
            Self::IpcLock => "CAP_IPC_LOCK",
            Self::IpcOwner => "CAP_IPC_OWNER",
            Self::SysModule => "CAP_SYS_MODULE",
            Self::SysRawio => "CAP_SYS_RAWIO",
            Self::SysChroot => "CAP_SYS_CHROOT",
            Self::SysPtrace => "CAP_SYS_PTRACE",
            Self::SysPacct => "CAP_SYS_PACCT",
            Self::SysAdmin => "CAP_SYS_ADMIN",
            Self::SysBoot => "CAP_SYS_BOOT",
            Self::SysNice => "CAP_SYS_NICE",
            Self::SysResource => "CAP_SYS_RESOURCE",
            Self::SysTime => "CAP_SYS_TIME",
            Self::SysTtyConfig => "CAP_SYS_TTY_CONFIG",
            Self::Mknod => "CAP_MKNOD",
            Self::Lease => "CAP_LEASE",
            Self::AuditWrite => "CAP_AUDIT_WRITE",
            Self::AuditControl => "CAP_AUDIT_CONTROL",
            Self::Setfcap => "CAP_SETFCAP",
            Self::MacOverride => "CAP_MAC_OVERRIDE",
            Self::MacAdmin => "CAP_MAC_ADMIN",
            Self::Syslog => "CAP_SYSLOG",
            Self::WakeAlarm => "CAP_WAKE_ALARM",
            Self::BlockSuspend => "CAP_BLOCK_SUSPEND",
            Self::AuditRead => "CAP_AUDIT_READ",
            Self::Perfmon => "CAP_PERFMON",
            Self::Bpf => "CAP_BPF",
            Self::CheckpointRestore => "CAP_CHECKPOINT_RESTORE",
        }
    }
}

/// OCI 既定の capability（SEC-1。moby の既定 14 個。Docker の root コンテナの `CapEff`
/// `00000000a80425fb` に対応する）。
pub const OCI_DEFAULT_CAPABILITIES: [Capability; 14] = [
    Capability::Chown,
    Capability::DacOverride,
    Capability::Fsetid,
    Capability::Fowner,
    Capability::Mknod,
    Capability::NetRaw,
    Capability::Setgid,
    Capability::Setuid,
    Capability::Setfcap,
    Capability::Setpcap,
    Capability::NetBindService,
    Capability::SysChroot,
    Capability::Kill,
    Capability::AuditWrite,
];

/// capability の集合（ビット位置はカーネルの capability 番号）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CapabilitySet(u64);

impl CapabilitySet {
    /// 本 enum が知る最後の capability 番号（`CAP_CHECKPOINT_RESTORE`）。
    const LAST_KNOWN: u8 = 40;

    /// 空集合。
    pub const fn empty() -> Self {
        Self(0)
    }

    /// OCI 既定集合（[`OCI_DEFAULT_CAPABILITIES`]）。
    pub fn oci_default() -> Self {
        OCI_DEFAULT_CAPABILITIES
            .iter()
            .fold(Self::empty(), |set, cap| set.with(*cap))
    }

    /// `cap` を加えた集合を返す。
    #[must_use]
    pub fn with(self, cap: Capability) -> Self {
        Self(self.0 | (1u64 << cap.index()))
    }

    /// `cap` を含むか。
    pub fn contains(self, cap: Capability) -> bool {
        self.contains_index(cap.index())
    }

    /// カーネルの番号（0〜63）で判定する。範囲外・本 enum が知らない番号は常に `false`。
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn contains_index(self, index: u8) -> bool {
        index <= Self::LAST_KNOWN && self.0 & (1u64 << index) != 0
    }

    /// 含む capability を番号順に返す。
    pub fn iter(self) -> impl Iterator<Item = Capability> {
        Capability::ALL
            .into_iter()
            .filter(move |c| self.contains(*c))
    }

    /// 要素数。
    pub fn len(self) -> usize {
        self.iter().count()
    }

    /// 空か。
    pub fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// 積集合。
    #[must_use]
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn intersect(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }

    /// `capset(2)`（`_LINUX_CAPABILITY_U32S_3`）の 2 語形式へ変換する。
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn to_cap_words(self) -> [u32; 2] {
        [self.0 as u32, (self.0 >> 32) as u32]
    }

    /// `capget(2)` の 2 語形式から作る。本 enum が知らないビットは落とす
    /// （許可側の集合として使うため、未知は含めない）。
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn from_cap_words(words: [u32; 2]) -> Self {
        let raw = u64::from(words[0]) | (u64::from(words[1]) << 32);
        Self(raw & ((1u64 << (Self::LAST_KNOWN + 1)) - 1))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SEC-1: 既定集合は Docker の root コンテナの `CapEff`（`a80425fb`）と一致する。
    #[test]
    fn sec1_oci_default_mask_matches_docker_capeff() {
        let set = CapabilitySet::oci_default();
        assert_eq!(set.to_cap_words(), [0xA804_25FB, 0]);
        assert_eq!(set.len(), 14);
    }

    /// SEC-1: 危険な capability を既定集合に含めない。
    #[test]
    fn sec1_oci_default_excludes_dangerous_caps() {
        let set = CapabilitySet::oci_default();
        for cap in [
            Capability::SysAdmin,
            Capability::SysModule,
            Capability::SysPtrace,
            Capability::NetAdmin,
            Capability::SysRawio,
            Capability::DacReadSearch,
            Capability::Bpf,
            Capability::Perfmon,
        ] {
            assert!(!set.contains(cap), "{}", cap.as_str());
        }
        assert!(set.contains(Capability::Chown));
    }

    /// SEC-1: 番号の具体値と、`ALL` が 0..=40 を重複・欠落なく並べること。
    #[test]
    fn sec1_capability_indices_are_exact() {
        assert_eq!(Capability::Chown.index(), 0);
        assert_eq!(Capability::Setpcap.index(), 8);
        assert_eq!(Capability::SysModule.index(), 16);
        assert_eq!(Capability::SysPtrace.index(), 19);
        assert_eq!(Capability::SysAdmin.index(), 21);
        assert_eq!(Capability::AuditWrite.index(), 29);
        assert_eq!(Capability::Setfcap.index(), 31);
        assert_eq!(Capability::CheckpointRestore.index(), 40);
        assert_eq!(Capability::SysAdmin.as_str(), "CAP_SYS_ADMIN");
        for (i, cap) in Capability::ALL.iter().enumerate() {
            assert_eq!(usize::from(cap.index()), i);
        }
    }

    /// SEC-1: 本 enum が知らない番号は許可されない（fail-closed）。
    #[test]
    fn sec1_unknown_index_is_not_allowed() {
        let set = CapabilitySet::oci_default();
        for i in 41..64u8 {
            assert!(!set.contains_index(i), "{i}");
        }
        assert!(set.contains_index(0));
    }

    /// SEC-1: 2 語形式の往復（具体値）。
    #[test]
    fn sec1_cap_words_round_trip() {
        let set = CapabilitySet::empty()
            .with(Capability::Chown)
            .with(Capability::CheckpointRestore);
        assert_eq!(set.to_cap_words(), [1, 0x100]);
        assert_eq!(CapabilitySet::from_cap_words([1, 0x100]), set);
        assert_eq!(
            CapabilitySet::from_cap_words([0, 0xFFFF_FFFF]).to_cap_words(),
            [0, 0x1FF]
        );
    }
}
