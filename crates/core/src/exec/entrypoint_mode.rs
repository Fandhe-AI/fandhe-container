//! 稼働中コンテナへの exec のエントリポイントの実行方式と、その判定結果の型（SUP-6・SEC-1・REPAIR-4・TASK-163 追補・
//! #1531。オーナー判断 2026-10-09「条件付き切り替え」）。
//!
//! # 役割と呼び出し文脈
//!
//! `sealed_copy::SealPolicy::probe` が `prepare_exec_restrictions`（`setns` の前）でホストの環境を判定し、
//! [`EntrypointExecMode`] を決める。exec の子（`process::prepare_exec_child`）はこの方式に従って、封印した複製
//! （`sealed_copy.rs`）か、照合した元の fd をそのまま実行する現行方式（O_PATH での固定 + inode 照合。#1478）のどちらかで
//! 実行する。supervisor（`fandhe-container-supervisor` の `exec::run_command`）は判定結果を
//! [`crate::exec::ExecRestrictions::entrypoint_mode`] で受け取り、構造化ログ（1 行 1 JSON）と `ExecOutcome` に残す。
//!
//! # 契約
//!
//! - 方式の切り替えは黙って行わない: 現行方式を選んだときは、封印した複製を使わなかった理由を
//!   [`SealedCopyUnavailable`] の機械可読なコード（[`SealedCopyUnavailable::as_str`]）で必ず持つ。真偽値や自由文字列で
//!   方式を表さない（REPAIR-2・REPAIR-4）
//! - 理由コードの全体: `kernel_too_old`・`exec_check_probe_failed`・`lsm_list_unreadable`・`lsm_apparmor`・`lsm_tomoyo`・
//!   `lsm_smack`・`lsm_bpf`・`lsm_ipe`・`lsm_selinux`・`lsm_unrecognized`・`lsm_ima`・`lsm_evm`・`lsm_integrity`
//!   （[`SealedCopyUnavailable::ALL`]）。判定の順序はカーネル（`AT_EXECVE_CHECK`）→ LSM 一覧の妥当性 → LSM 一覧の順で
//!   最初に見つかった許可リスト外の LSM
//! - コードは固定の語彙（英小文字・数字・`_`）で、ホスト側の入力（LSM 名の生文字列・パス）を含めない。未知の LSM は
//!   名前を載せず [`SealedCopyUnavailable::UnrecognizedLsm`]（`lsm_unrecognized`）にまとめる
//! - どちらの方式でも、元のファイルのマウントの `noexec` は `fstatfs` で判定して違反 `entrypoint_on_noexec_mount` で
//!   拒否する（`process.rs`・`sealed_copy.rs`）

/// エントリポイントの実行方式（判定結果）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EntrypointExecMode {
    /// 照合した本体を封印した memfd に複製して実行する（`sealed_copy.rs`）。照合と実行の間の書き換え（TOCTOU）を閉じる。
    SealedCopy,
    /// 照合した元の fd をそのまま `execveat` する現行方式（O_PATH での固定 + inode 照合。#1478）。封印した複製を
    /// 使えない環境で選ぶ。照合の後・`execveat` の前に元のファイルの内容やインタープリタのパスを書き換える競合は
    /// 残る（#1458 の論点。`interpreter.rs` の「限界」）。
    PinnedInode {
        /// 封印した複製を使わなかった理由。
        reason: SealedCopyUnavailable,
    },
}

impl EntrypointExecMode {
    /// 方式の機械可読な名前（構造化ログ・worker の結果の行に使う）。
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SealedCopy => "sealed_copy",
            Self::PinnedInode { .. } => "pinned_inode",
        }
    }

    /// 現行方式を選んだ理由（封印した複製なら `None`）。
    pub fn fallback_reason(self) -> Option<SealedCopyUnavailable> {
        match self {
            Self::SealedCopy => None,
            Self::PinnedInode { reason } => Some(reason),
        }
    }

    /// [`Self::as_str`] と [`SealedCopyUnavailable::as_str`]（封印した複製は `-`）の組から引き直す（worker の結果の
    /// 復号用）。組み合わせが不正なら `None`。
    pub fn from_tokens(mode: &str, reason: &str) -> Option<Self> {
        match (mode, reason) {
            ("sealed_copy", "-") => Some(Self::SealedCopy),
            ("pinned_inode", reason) => {
                SealedCopyUnavailable::from_token(reason).map(|reason| Self::PinnedInode { reason })
            }
            _ => None,
        }
    }
}

/// パス・ラベルに結び付いた exec 時の判定を持ち、封印した複製では再現できない既知の LSM。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PathBoundLsm {
    /// AppArmor。
    AppArmor,
    /// TOMOYO。
    Tomoyo,
    /// Smack。
    Smack,
    /// BPF LSM。
    Bpf,
    /// IPE。
    Ipe,
}

impl PathBoundLsm {
    /// 全値（`/sys/kernel/security/lsm` の名前との対応表に使う）。
    pub const ALL: [Self; 5] = [
        Self::AppArmor,
        Self::Tomoyo,
        Self::Smack,
        Self::Bpf,
        Self::Ipe,
    ];

    /// `/sys/kernel/security/lsm` に現れる名前。
    pub fn lsm_name(self) -> &'static str {
        match self {
            Self::AppArmor => "apparmor",
            Self::Tomoyo => "tomoyo",
            Self::Smack => "smack",
            Self::Bpf => "bpf",
            Self::Ipe => "ipe",
        }
    }
}

/// 完全性検査（integrity）系の LSM。実行したファイルについて計測・appraisal（`evm` は security xattr の検証）を行うが、
/// memfd の複製では元のファイルの inode・パス・xattr について働かない、または元のパスで記録されないおそれがある
/// （#1579 の独立監査 P2-1）。一次情報（`security/integrity/ima`・`evm`）で memfd からの実行時の挙動と
/// `AT_EXECVE_CHECK` での評価を確かめられれば、計測専用の環境などは将来緩められる。それまでは有効なら封印した複製を
/// 使わない（fail-closed）。`evm`・`integrity` は IMA の appraisal と組で働く層（`integrity` は IMA・EVM の共通基盤）で、
/// 単独で載っていても元の inode の xattr に依る検査を持つため、`ima` と同じく扱う。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum IntegrityLsm {
    /// IMA。
    Ima,
    /// EVM。
    Evm,
    /// integrity（IMA・EVM の共通基盤）。
    Integrity,
}

impl IntegrityLsm {
    /// 全値。
    pub const ALL: [Self; 3] = [Self::Ima, Self::Evm, Self::Integrity];

    /// `/sys/kernel/security/lsm` に現れる名前。
    pub fn lsm_name(self) -> &'static str {
        match self {
            Self::Ima => "ima",
            Self::Evm => "evm",
            Self::Integrity => "integrity",
        }
    }
}

/// 封印した複製を使わなかった理由（[`EntrypointExecMode::PinnedInode`] の値）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SealedCopyUnavailable {
    /// カーネルが `AT_EXECVE_CHECK`（Linux 6.14+）を知らない。
    KernelTooOld,
    /// `AT_EXECVE_CHECK` の有無を判定できなかった（判定用の問い合わせが想定外の結果を返した）。
    ExecCheckProbeFailed,
    /// 有効な LSM の一覧（`/sys/kernel/security/lsm`）を読めなかった・securityfs 上に無い・空・`capability` を含まない
    /// （一覧として信用できない）。
    LsmListUnreadable,
    /// パス結び付きの LSM が有効。
    PathBoundLsm(PathBoundLsm),
    /// SELinux が有効。
    Selinux,
    /// 許可リストに無い LSM が有効。
    UnrecognizedLsm,
    /// 完全性検査系の LSM（IMA・EVM・integrity）が有効。
    IntegrityLsm(IntegrityLsm),
}

impl SealedCopyUnavailable {
    /// 機械可読な理由コード（固定の語彙）。
    pub fn as_str(self) -> &'static str {
        match self {
            Self::KernelTooOld => "kernel_too_old",
            Self::ExecCheckProbeFailed => "exec_check_probe_failed",
            Self::LsmListUnreadable => "lsm_list_unreadable",
            Self::PathBoundLsm(PathBoundLsm::AppArmor) => "lsm_apparmor",
            Self::PathBoundLsm(PathBoundLsm::Tomoyo) => "lsm_tomoyo",
            Self::PathBoundLsm(PathBoundLsm::Smack) => "lsm_smack",
            Self::PathBoundLsm(PathBoundLsm::Bpf) => "lsm_bpf",
            Self::PathBoundLsm(PathBoundLsm::Ipe) => "lsm_ipe",
            Self::Selinux => "lsm_selinux",
            Self::UnrecognizedLsm => "lsm_unrecognized",
            Self::IntegrityLsm(IntegrityLsm::Ima) => "lsm_ima",
            Self::IntegrityLsm(IntegrityLsm::Evm) => "lsm_evm",
            Self::IntegrityLsm(IntegrityLsm::Integrity) => "lsm_integrity",
        }
    }

    /// 英語の説明（診断用）。
    pub fn message(self) -> &'static str {
        match self {
            Self::KernelTooOld => {
                "AT_EXECVE_CHECK is unavailable (Linux 6.14 or later is required); the original file cannot be checked before copying it"
            }
            Self::ExecCheckProbeFailed => {
                "whether AT_EXECVE_CHECK is available could not be determined"
            }
            Self::LsmListUnreadable => {
                "the active security modules could not be read or did not form a valid list"
            }
            Self::PathBoundLsm(_) => {
                "a path-bound security module is active; its exec-time checks cannot be reproduced for a sealed copy"
            }
            Self::Selinux => {
                "SELinux is active; the exec-time permission and transition for the original file label cannot be reproduced for a sealed copy"
            }
            Self::UnrecognizedLsm => {
                "an unrecognized security module is active; its exec-time checks cannot be ruled out for a sealed copy"
            }
            Self::IntegrityLsm(_) => {
                "an integrity security module (IMA/EVM) is active; its measurement and appraisal of the original file cannot be guaranteed for a sealed copy"
            }
        }
    }

    /// 全値（復号と単体テストの対応表）。
    pub const ALL: [Self; 13] = [
        Self::KernelTooOld,
        Self::ExecCheckProbeFailed,
        Self::LsmListUnreadable,
        Self::PathBoundLsm(PathBoundLsm::AppArmor),
        Self::PathBoundLsm(PathBoundLsm::Tomoyo),
        Self::PathBoundLsm(PathBoundLsm::Smack),
        Self::PathBoundLsm(PathBoundLsm::Bpf),
        Self::PathBoundLsm(PathBoundLsm::Ipe),
        Self::Selinux,
        Self::UnrecognizedLsm,
        Self::IntegrityLsm(IntegrityLsm::Ima),
        Self::IntegrityLsm(IntegrityLsm::Evm),
        Self::IntegrityLsm(IntegrityLsm::Integrity),
    ];

    /// [`Self::as_str`] の逆変換。未知のコードは `None`。
    pub fn from_token(token: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|r| r.as_str() == token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SUP-6・REPAIR-4・#1531: 理由コードと方式名の具体値。コードは重複せず、固定の語彙（英小文字・数字・`_`）で、
    /// 往復できる。
    #[test]
    fn sup6_repair4_mode_and_reason_codes_are_exact() {
        let codes: Vec<&str> = SealedCopyUnavailable::ALL
            .iter()
            .map(|r| r.as_str())
            .collect();
        assert_eq!(
            codes,
            [
                "kernel_too_old",
                "exec_check_probe_failed",
                "lsm_list_unreadable",
                "lsm_apparmor",
                "lsm_tomoyo",
                "lsm_smack",
                "lsm_bpf",
                "lsm_ipe",
                "lsm_selinux",
                "lsm_unrecognized",
                "lsm_ima",
                "lsm_evm",
                "lsm_integrity",
            ]
        );
        for r in SealedCopyUnavailable::ALL {
            assert!(
                r.as_str()
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'),
                "{r:?}"
            );
            assert_eq!(SealedCopyUnavailable::from_token(r.as_str()), Some(r));
            let mode = EntrypointExecMode::PinnedInode { reason: r };
            assert_eq!(mode.as_str(), "pinned_inode");
            assert_eq!(mode.fallback_reason(), Some(r));
            assert_eq!(
                EntrypointExecMode::from_tokens("pinned_inode", r.as_str()),
                Some(mode)
            );
        }
        assert_eq!(EntrypointExecMode::SealedCopy.as_str(), "sealed_copy");
        assert_eq!(EntrypointExecMode::SealedCopy.fallback_reason(), None);
        assert_eq!(
            EntrypointExecMode::from_tokens("sealed_copy", "-"),
            Some(EntrypointExecMode::SealedCopy)
        );
        for (mode, reason) in [
            ("sealed_copy", "kernel_too_old"),
            ("pinned_inode", "-"),
            ("pinned_inode", "lsm_mystery"),
            ("other", "-"),
        ] {
            assert_eq!(EntrypointExecMode::from_tokens(mode, reason), None);
        }
        assert_eq!(SealedCopyUnavailable::from_token("unknown"), None);
        let names: Vec<&str> = PathBoundLsm::ALL.iter().map(|l| l.lsm_name()).collect();
        assert_eq!(names, ["apparmor", "tomoyo", "smack", "bpf", "ipe"]);
        let names: Vec<&str> = IntegrityLsm::ALL.iter().map(|l| l.lsm_name()).collect();
        assert_eq!(names, ["ima", "evm", "integrity"]);
    }
}
