//! 分離違反の試行を拒否したときの構造化された違反記録（SEC-4 の記録経路。TASK-27.2・#134）。
//!
//! # 役割と範囲
//!
//! `crate::exec` の各拒否経路（`plan` / `plan_rootful_host_root` / `isolate` 系の前提、
//! `MountIsolation::establish` の前提、`mount_proc` の証跡不一致・パス検証・shared 伝播）は、
//! 拒否時に [`IsolationViolation`] を `ExecError::violation` に載せて呼び出し側へ返す。
//!
//! **本モジュールは記録の経路のみを提供する。** 違反記録の永続化・3 レイヤー（実行層・
//! supervisor・CLI）への集約・ログの出力先は TASK-41（#191。SEC-4）で扱い、ここでは
//! 実装していない（REPAIR-3: 実装済みを装わない）。
//!
//! # 違反とシステムエラーの区別
//!
//! - **違反**: 呼び出し側の構成・呼び出し文脈・パスが分離の前提を満たさず、fail-closed で
//!   拒否したもの（例: User なしの既定計画、PID 1 でない呼び出し、rootfs 外のマウント先、
//!   shared 伝播上のマウント先）。`ExecError::violation` は `Some`
//! - **システムエラー**: 前提は満たしているが、カーネル・procfs の応答が得られない・解釈
//!   できない、または syscall が失敗したもの（例: `ENOMEM`・`/proc` の読み取り失敗・
//!   mountinfo の書式不正・`unshare` の `EPERM`）。`ExecError::violation` は `None`
//! - hostname の書式不正（`Hostname::new`）は入力値の書式エラーであり、分離違反の試行では
//!   ないため違反記録を付けない
//!
//! # 秘匿
//!
//! 違反記録には namespace の識別子（`mnt:[inode]` 等）や正規化後のホスト側実パスを含めない。
//! 対象（[`ViolationSubject`]）は呼び出し側が渡したパスだけで、長さを上限で切り詰め、
//! 制御文字とバックスラッシュをエスケープして保持する。

use std::path::Path;

use crate::traits::types::ErrorCode;

use super::IsolationStage;

/// 違反の種別（どの検査で拒否したか）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ViolationKind {
    /// 分離計画（`plan` / `plan_rootful_host_root`）または `isolate` 系の実行前検証。
    PlanRejected,
    /// `MountIsolation::establish` の前提（PID 1・入れ子・シングルスレッド・新しい mount ns）。
    EstablishPrecondition,
    /// `mount_proc` 直前の証跡の再検証（PID 1・mount ns・PID ns の不一致）。
    EvidenceMismatch,
    /// `mount_proc` のマウント先パスの検証（rootfs 境界・symlink・`..` 等）。
    MountTarget,
    /// `mount_proc` のマウント先が shared propagation 上にある。
    SharedPropagation,
}

impl ViolationKind {
    /// 機械可読な種別名（snake_case）。
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PlanRejected => "plan_rejected",
            Self::EstablishPrecondition => "establish_precondition",
            Self::EvidenceMismatch => "evidence_mismatch",
            Self::MountTarget => "mount_target",
            Self::SharedPropagation => "shared_propagation",
        }
    }
}

/// 違反の理由コード。種別・ビヘイビア ID・`ErrorCode`・段・英語メッセージは理由から一意に
/// 決まる（拒否経路ごとに文字列を手で組まない）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ViolationReason {
    /// namespace が 1 つも選ばれていない。
    NoNamespaces,
    /// hostname 指定があるのに UTS namespace が無い（ホストの hostname を書き換え得る）。
    HostnameWithoutUts,
    /// PID namespace があるのに mount namespace が無い。
    PidWithoutMount,
    /// 既定計画に user namespace が無い（SEC-5）。
    UserNamespaceRequired,
    /// 既定計画で euid / egid 0 をそのまま写そうとした（SEC-5）。
    HostRootIdentityMapping,
    /// rootful 計画に user namespace が含まれる。
    RootfulWithUserNamespace,
    /// rootful 計画 / 実行が euid 0 でない。
    RootfulRequiresRoot,
    /// 既定計画の作成後に実効 uid / gid が変わった（SEC-5）。
    IdentityChanged,
    /// establish の呼び出し元が PID 1 でない。
    EstablishNotPid1,
    /// establish 時の `NSpid` 末尾が 1 でない。
    EstablishNspidNotPid1,
    /// establish 時に入れ子の PID namespace にいない。
    EstablishNotNestedPidNamespace,
    /// establish 時にマルチスレッドである。
    EstablishMultiThreaded,
    /// `unshare(CLONE_NEWNS)` の前後で mount namespace が変わらなかった。
    EstablishMountNamespaceNotFresh,
    /// `mount_proc` の呼び出し元が PID 1 でない（`getpid`）。
    EvidenceCallerNotPid1,
    /// `mount_proc` 呼び出し時の `NSpid` 末尾が 1 でない。
    EvidenceNspidNotPid1,
    /// 呼び出しスレッドの mount namespace が証跡と異なる。
    EvidenceMountNamespaceMismatch,
    /// 呼び出しスレッドの PID namespace が証跡と異なる。
    EvidencePidNamespaceMismatch,
    /// rootfs / マウント先が絶対パスでない。
    PathNotAbsolute,
    /// rootfs / マウント先が NUL を含む。
    PathContainsNul,
    /// rootfs / マウント先が `..` を含む。
    PathParentComponent,
    /// マウント先が rootfs 配下でない。
    TargetOutsideRootfs,
    /// rootfs が存在しない。
    RootfsMissing,
    /// rootfs 自体または祖先に symlink がある（正規化した実パスと一致しない）。
    RootfsNotCanonical,
    /// マウント先が rootfs そのもの。
    TargetIsRootfs,
    /// 経路上に symlink または非ディレクトリがある。
    PathSymlinkOrNotDirectory,
    /// 経路上の要素が存在しない。
    PathMissing,
    /// マウント先が shared propagation 上にある。
    TargetOnSharedMount,
}

impl ViolationReason {
    /// 機械可読な理由コード（snake_case）。
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NoNamespaces => "no_namespaces",
            Self::HostnameWithoutUts => "hostname_without_uts",
            Self::PidWithoutMount => "pid_without_mount",
            Self::UserNamespaceRequired => "user_namespace_required",
            Self::HostRootIdentityMapping => "host_root_identity_mapping",
            Self::RootfulWithUserNamespace => "rootful_with_user_namespace",
            Self::RootfulRequiresRoot => "rootful_requires_root",
            Self::IdentityChanged => "identity_changed",
            Self::EstablishNotPid1 => "establish_not_pid1",
            Self::EstablishNspidNotPid1 => "establish_nspid_not_pid1",
            Self::EstablishNotNestedPidNamespace => "establish_not_nested_pid_namespace",
            Self::EstablishMultiThreaded => "establish_multi_threaded",
            Self::EstablishMountNamespaceNotFresh => "establish_mount_namespace_not_fresh",
            Self::EvidenceCallerNotPid1 => "evidence_caller_not_pid1",
            Self::EvidenceNspidNotPid1 => "evidence_nspid_not_pid1",
            Self::EvidenceMountNamespaceMismatch => "evidence_mount_namespace_mismatch",
            Self::EvidencePidNamespaceMismatch => "evidence_pid_namespace_mismatch",
            Self::PathNotAbsolute => "path_not_absolute",
            Self::PathContainsNul => "path_contains_nul",
            Self::PathParentComponent => "path_parent_component",
            Self::TargetOutsideRootfs => "target_outside_rootfs",
            Self::RootfsMissing => "rootfs_missing",
            Self::RootfsNotCanonical => "rootfs_not_canonical",
            Self::TargetIsRootfs => "target_is_rootfs",
            Self::PathSymlinkOrNotDirectory => "path_symlink_or_not_directory",
            Self::PathMissing => "path_missing",
            Self::TargetOnSharedMount => "target_on_shared_mount",
        }
    }

    /// 違反の種別。
    pub fn kind(self) -> ViolationKind {
        match self {
            Self::NoNamespaces
            | Self::HostnameWithoutUts
            | Self::PidWithoutMount
            | Self::UserNamespaceRequired
            | Self::HostRootIdentityMapping
            | Self::RootfulWithUserNamespace
            | Self::RootfulRequiresRoot
            | Self::IdentityChanged => ViolationKind::PlanRejected,
            Self::EstablishNotPid1
            | Self::EstablishNspidNotPid1
            | Self::EstablishNotNestedPidNamespace
            | Self::EstablishMultiThreaded
            | Self::EstablishMountNamespaceNotFresh => ViolationKind::EstablishPrecondition,
            Self::EvidenceCallerNotPid1
            | Self::EvidenceNspidNotPid1
            | Self::EvidenceMountNamespaceMismatch
            | Self::EvidencePidNamespaceMismatch => ViolationKind::EvidenceMismatch,
            Self::PathNotAbsolute
            | Self::PathContainsNul
            | Self::PathParentComponent
            | Self::TargetOutsideRootfs
            | Self::RootfsMissing
            | Self::RootfsNotCanonical
            | Self::TargetIsRootfs
            | Self::PathSymlinkOrNotDirectory
            | Self::PathMissing => ViolationKind::MountTarget,
            Self::TargetOnSharedMount => ViolationKind::SharedPropagation,
        }
    }

    /// 違反した前提のビヘイビア ID（SSOT: spec `04-behavior/`）。
    pub fn behavior_id(self) -> &'static str {
        match self {
            Self::UserNamespaceRequired | Self::HostRootIdentityMapping | Self::IdentityChanged => {
                "SEC-5"
            }
            _ => "CORE-1",
        }
    }

    /// 呼び出し側へ返す `ErrorCode`（構成・パスの不正は `InvalidArgument`、実行文脈・権限の
    /// 前提違反は `FailedPrecondition`）。
    pub fn error_code(self) -> ErrorCode {
        match self {
            Self::NoNamespaces
            | Self::HostnameWithoutUts
            | Self::PidWithoutMount
            | Self::UserNamespaceRequired
            | Self::RootfulWithUserNamespace
            | Self::PathNotAbsolute
            | Self::PathContainsNul
            | Self::PathParentComponent
            | Self::TargetOutsideRootfs
            | Self::RootfsMissing
            | Self::RootfsNotCanonical
            | Self::TargetIsRootfs
            | Self::PathSymlinkOrNotDirectory
            | Self::PathMissing => ErrorCode::InvalidArgument,
            Self::HostRootIdentityMapping
            | Self::RootfulRequiresRoot
            | Self::IdentityChanged
            | Self::EstablishNotPid1
            | Self::EstablishNspidNotPid1
            | Self::EstablishNotNestedPidNamespace
            | Self::EstablishMultiThreaded
            | Self::EstablishMountNamespaceNotFresh
            | Self::EvidenceCallerNotPid1
            | Self::EvidenceNspidNotPid1
            | Self::EvidenceMountNamespaceMismatch
            | Self::EvidencePidNamespaceMismatch
            | Self::TargetOnSharedMount => ErrorCode::FailedPrecondition,
        }
    }

    /// 拒否した段（計画は `Validate`、それ以外は `MountProc`）。
    pub(super) fn stage(self) -> IsolationStage {
        match self.kind() {
            ViolationKind::PlanRejected => IsolationStage::Validate,
            _ => IsolationStage::MountProc,
        }
    }

    /// 英語のメッセージ（`ExecError::message`）。
    pub fn message(self) -> &'static str {
        match self {
            Self::NoNamespaces => "at least one namespace must be selected",
            Self::HostnameWithoutUts => "hostname requires the UTS namespace",
            Self::PidWithoutMount => "the PID namespace requires the mount namespace",
            Self::UserNamespaceRequired => {
                "the user namespace is required to map container root to an unprivileged host ID"
            }
            Self::HostRootIdentityMapping => {
                "refusing identity mapping of host root into the user namespace \
                 (map a subordinate ID range from /etc/subuid and /etc/subgid instead; \
                 subordinate ID mapping is not implemented yet, see TASK-40)"
            }
            Self::RootfulWithUserNamespace => {
                "the rootful host-root plan must not include the user namespace"
            }
            Self::RootfulRequiresRoot => "the rootful host-root plan requires euid 0",
            Self::IdentityChanged => "effective uid/gid changed after the plan was created",
            Self::EstablishNotPid1 => {
                "not PID 1; call from the first child created after unshare(CLONE_NEWPID)"
            }
            Self::EstablishNspidNotPid1 | Self::EvidenceNspidNotPid1 => {
                "NSpid does not end with 1; not PID 1 of the innermost PID namespace"
            }
            Self::EstablishNotNestedPidNamespace => {
                "not in a nested PID namespace; isolate with Namespace::Pid first"
            }
            Self::EstablishMultiThreaded => {
                "the process must be single-threaded before establishing mount isolation"
            }
            Self::EstablishMountNamespaceNotFresh => {
                "unshare(CLONE_NEWNS) did not move the thread to a new mount namespace"
            }
            Self::EvidenceCallerNotPid1 => {
                "mount_proc must be called by PID 1 of the isolated PID namespace"
            }
            Self::EvidenceMountNamespaceMismatch => {
                "isolation evidence does not belong to the current mount namespace"
            }
            Self::EvidencePidNamespaceMismatch => {
                "isolation evidence does not belong to the current PID namespace"
            }
            Self::PathNotAbsolute => "rootfs and proc mount target must be absolute paths",
            Self::PathContainsNul => "rootfs and proc mount target must not contain NUL",
            Self::PathParentComponent => "rootfs and proc mount target must not contain '..'",
            Self::TargetOutsideRootfs => "proc mount target must be under rootfs",
            Self::RootfsMissing => "rootfs must exist",
            Self::RootfsNotCanonical => {
                "rootfs must be a canonical path without symlinks in itself or its ancestors"
            }
            Self::TargetIsRootfs => {
                "proc mount target must be a dedicated directory below rootfs, not rootfs itself"
            }
            Self::PathSymlinkOrNotDirectory => {
                "proc mount target path components must be directories, not symlinks"
            }
            Self::PathMissing => "proc mount target path must exist",
            Self::TargetOnSharedMount => {
                "proc mount target is on a shared mount; isolate the mount namespace first"
            }
        }
    }
}

/// 違反記録の対象として保持する文字列の上限（文字数。超過分は切り詰める）。
pub const VIOLATION_SUBJECT_MAX_CHARS: usize = 256;

/// 違反の対象（呼び出し側が渡したパス）。制御文字とバックスラッシュはエスケープ済みで、
/// 長さは [`VIOLATION_SUBJECT_MAX_CHARS`] 文字以下（ログ注入・無制限確保を防ぐ）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ViolationSubject {
    text: String,
    truncated: bool,
}

impl ViolationSubject {
    /// パスから作る。非 UTF-8 のバイトは U+FFFD に置き換え、制御文字（改行・ESC 等）と
    /// `\` は `char::escape_default` 形式でエスケープする。
    pub(super) fn from_path(path: &Path) -> Self {
        let lossy = path.to_string_lossy();
        let mut text = String::new();
        let mut count = 0usize;
        let mut truncated = false;
        for c in lossy.chars() {
            let escaped: String = if c.is_control() || c == '\\' {
                c.escape_default().collect()
            } else {
                c.to_string()
            };
            let len = escaped.chars().count();
            if count + len > VIOLATION_SUBJECT_MAX_CHARS {
                truncated = true;
                break;
            }
            count += len;
            text.push_str(&escaped);
        }
        Self { text, truncated }
    }

    /// エスケープ・切り詰め済みの文字列。
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// 上限で切り詰めたか。
    pub fn is_truncated(&self) -> bool {
        self.truncated
    }
}

/// 分離違反の試行を拒否したときの構造化された記録（SEC-4 の記録経路。保存は TASK-41）。
///
/// `ExecError::violation` から取り出す。生成は `crate::exec` の拒否経路のみ。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct IsolationViolation {
    /// 種別。
    pub kind: ViolationKind,
    /// 理由コード。
    pub reason: ViolationReason,
    /// 違反した前提のビヘイビア ID（例: `"CORE-1"`・`"SEC-5"`）。
    pub behavior_id: &'static str,
    /// 対象（パスの検証で拒否した場合のみ）。
    pub subject: Option<ViolationSubject>,
}

impl IsolationViolation {
    /// 理由から作る（種別・ビヘイビア ID は理由から決まる）。
    pub(super) fn new(reason: ViolationReason, subject: Option<&Path>) -> Self {
        Self {
            kind: reason.kind(),
            reason,
            behavior_id: reason.behavior_id(),
            subject: subject.map(ViolationSubject::from_path),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 制御文字・バックスラッシュはエスケープし、通常の文字はそのまま保持する。
    #[test]
    fn subject_escapes_control_chars() {
        let s = ViolationSubject::from_path(Path::new("/a\nb\u{1b}[31m\\c/日本"));
        assert_eq!(s.as_str(), "/a\\nb\\u{1b}[31m\\\\c/日本");
        assert!(!s.is_truncated());
    }

    /// 上限を超えるパスは上限の文字数で切り詰め、切り詰めたことを記録する。
    #[test]
    fn subject_is_bounded() {
        let long = format!("/{}", "a".repeat(1000));
        let s = ViolationSubject::from_path(Path::new(&long));
        assert_eq!(s.as_str().chars().count(), VIOLATION_SUBJECT_MAX_CHARS);
        assert!(s.is_truncated());
        // エスケープ列の途中では切らない（上限 256 に対して "\n" 1 個は 2 文字）。
        let edge = format!("/{}\n", "a".repeat(VIOLATION_SUBJECT_MAX_CHARS - 2));
        let s = ViolationSubject::from_path(Path::new(&edge));
        assert_eq!(s.as_str().chars().count(), VIOLATION_SUBJECT_MAX_CHARS - 1);
        assert!(s.is_truncated());
    }

    /// 理由コード・種別・ビヘイビア ID の具体値。
    #[test]
    fn reason_metadata_is_exact() {
        let r = ViolationReason::HostRootIdentityMapping;
        assert_eq!(r.as_str(), "host_root_identity_mapping");
        assert_eq!(r.kind(), ViolationKind::PlanRejected);
        assert_eq!(r.behavior_id(), "SEC-5");
        assert_eq!(r.error_code(), ErrorCode::FailedPrecondition);
        let r = ViolationReason::TargetOnSharedMount;
        assert_eq!(r.kind().as_str(), "shared_propagation");
        assert_eq!(r.behavior_id(), "CORE-1");
        assert_eq!(r.stage(), IsolationStage::MountProc);
    }
}
