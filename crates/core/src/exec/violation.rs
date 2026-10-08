//! 分離違反の試行を拒否したときの構造化された違反記録（SEC-4 の記録経路。TASK-27.2・#134）。
//!
//! # 役割と範囲
//!
//! `crate::exec` の各拒否経路（`plan` / `plan_rootful_host_root` / `isolate` 系の前提、
//! `MountIsolation::establish` の前提、`mount_proc` の証跡不一致・パス検証・shared 伝播、
//! `prepare_rootfs` / `pivot_root` の証跡不一致・rootfs パス検証・shared 伝播。TASK-27.3・#135、
//! `setns` 参加前の exec の対象の検証〔種別 `exec_target`。入れ子の PID 1 でない・cgroup 不一致・呼び出し側と
//! 同じ pid / mnt namespace。SUP-6・SEC-1・TASK-163.1・#500〕、`setns` 参加後の root の照合〔同種別。参加後の
//! `/` が記録したコンテナの rootfs でない。SUP-6・SEC-1・TASK-163.3・#502〕）は、
//! 拒否時に [`IsolationViolation`] を `ExecError::violation` に載せて呼び出し側へ返す。
//!
//! **本モジュールは記録の経路のみを提供する。** マウント層の違反から `Mount` 監査イベントへの
//! 写像は [`IsolationViolation::mount_audit_event`]（TASK-41.4・#195）、exec の対象の拒否から `ExecTarget`
//! 監査イベントへの写像は [`IsolationViolation::exec_audit_event`]（SUP-6・TASK-163 追補・#1465）で実装済み。
//! ファイルへの永続化（TASK-41.5.1・#839）とカーネル監査フォールバック（#840）も `audit_log` に実装済みで、
//! 本モジュールの記録を実際の sink へ流す本番経路（launcher・CLI への配線）は未実装
//! （REPAIR-3: 実装済みを装わない）。
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
//! Cc・Cf・Zl・Zp の文字とバックスラッシュをエスケープして保持する。
//!
//! exec 対象の監査イベントは理由コード（静的トークン）だけを持ち、対象パス（期待 cgroup パス等）も
//! 載せない（`AuditEvent::ExecTarget` がパスのフィールドを持たない型で保証する。#1465）。

use std::path::Path;

use crate::audit_log::{AuditEvent, AuditPath, AuditReason};
use crate::sanitize::is_display_unsafe_char;
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
    /// `mount_proc` のマウント先または `prepare_rootfs` の rootfs が shared propagation 上にある。
    SharedPropagation,
    /// `prepare_rootfs` の rootfs 指定そのものの拒否（ホスト root の指定・固定後の移動。TASK-27.3）。
    RootfsPivot,
    /// exec 直前のエントリポイントの検証（ランタイム自身のホスト側バイナリの指定等。TASK-27.4.1）。
    Entrypoint,
    /// 稼働中コンテナへの exec の対象（pid1）の検証（`setns` 参加前の対象の検証と、参加後の root の照合。
    /// SUP-6・SEC-1・TASK-163.1・TASK-163.3）。
    ExecTarget,
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
            Self::RootfsPivot => "rootfs_pivot",
            Self::Entrypoint => "entrypoint",
            Self::ExecTarget => "exec_target",
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
    /// rootfs 自体または祖先に symlink・非ディレクトリがある。
    RootfsSymlinkOrNotDirectory,
    /// マウント先が rootfs そのもの。
    TargetIsRootfs,
    /// 経路上に symlink または非ディレクトリがある。
    PathSymlinkOrNotDirectory,
    /// 経路上の要素が存在しない。
    PathMissing,
    /// マウント先が shared propagation 上にある。
    TargetOnSharedMount,
    /// fd で固定した後にマウント先が改名・移動・削除された。
    TargetMoved,
    /// rootfs が `/`（ホスト root）そのもの。ホスト root への pivot は無意味かつ危険なため拒否する。
    RootfsIsHostRoot,
    /// rootfs が shared propagation 上にある（pivot_root は EINVAL になり、bind もホストへ伝播し得る）。
    RootfsOnSharedMount,
    /// fd で固定した後に rootfs が改名・移動・削除された。
    RootfsMoved,
    /// rootfs の bind mount が rootfs 配下の既存マウント（サブマウント）を複製した。許可リストは
    /// 空のため 1 つでもあれば拒否する（ホスト領域への bind mount 経由の脱出を防ぐ）。
    RootfsHasSubmounts,
    /// rootfs 内のファイルが rootfs の外にもハードリンクを持つ（外部 inode を共有する）。pivot 後の
    /// 書き込みが rootfs 外のファイルを書き換えるため拒否する。
    RootfsHasExternalHardlink,
    /// エントリポイントがランタイム自身の実行ファイル（`/proc/self/exe`）と同一の inode
    /// （CVE-2019-5736 型の多層防御。TASK-27.4.1）。
    EntrypointIsRuntimeBinary,
    /// 新 root の `/dev/null` が文字デバイス 1:3 でない（symlink・通常ファイル・別のデバイスノードへ差し替え
    /// られている。SUP-6・SEC-1・TASK-163 追補・#1459）。コンテナは `CAP_MKNOD` で自分の `/dev/null` を差し替え
    /// られるため、標準入出力の置換先として開く前に検証し、差し替え先を開かずに拒否する。
    StdioNullNotNullDevice,
    /// エントリポイントのインタープリタ（シェバンの連鎖・ELF の `PT_INTERP`）が、ランタイム自身の実行ファイルと
    /// 同一の inode に解決される（`#!/proc/self/exe` 等。CVE-2019-5736 型。SUP-6・SEC-1・CORE-5・TASK-163 追補・
    /// #1458）。カーネルはインタープリタを exec するプロセス自身の文脈で開くため、本体の照合
    /// （[`Self::EntrypointIsRuntimeBinary`]）だけでは通ってしまう。
    EntrypointInterpreterIsRuntimeBinary,
    /// 新 root の `/dev` が実ディレクトリでない（symlink・通常ファイル等へ差し替えられている。SUP-6・SEC-1・
    /// SEC-4・TASK-163 追補・#1459）。`/dev/null` を別の木から引かせないため、symlink を辿らずに拒否する。
    ExecDevNotDirectory,
    /// 新 root の `/proc` が procfs でない（symlink・非ディレクトリ・別のファイルシステムが置かれている。SUP-6・
    /// SEC-1・SEC-4・TASK-163 追補・#1459）。ランタイムの同一性の基準と、検証済みの fd の開き直しの起点を
    /// すり替えさせないために拒否する。
    ExecProcNotProcfs,
    /// exec の対象が入れ子の PID namespace の PID 1 でない（`NSpid` が 2 要素・末尾 1 でない。SUP-6）。
    ExecTargetNotNestedPid1,
    /// exec の対象の所属 cgroup が、記録から導いた期待パスと一致しない（pid 再利用・移動。SEC-1）。
    ExecTargetCgroupMismatch,
    /// exec の対象が呼び出し側と同じ PID namespace にいる（参加しても分離境界を越えない対象。SUP-6）。
    ExecTargetSharesPidNamespace,
    /// exec の対象が呼び出し側と同じ mount namespace にいる（同上）。
    ExecTargetSharesMountNamespace,
    /// exec の対象が呼び出し側と別の user namespace にいる（SUP-6・SEC-5・TASK-163.4）。user namespace への
    /// 参加は未実装のため、参加すると exec したコマンドは呼び出し側の user namespace の資格情報のまま対象の
    /// mount / PID namespace で動く。呼び出し側がホスト root なら、capability が自分の user namespace に閉じた
    /// コンテナ内プロセスより強い権限を持つことになるため、`setns` が成功する場合でも参加の前に拒否する。
    ExecTargetInOtherUserNamespace,
    /// `setns` 参加後の呼び出しプロセスの `/` が、記録（bundle の `config.json`）から固定したコンテナの
    /// rootfs と同じディレクトリでない（pivot していない対象・`/` へ別のマウントが重ねられた対象。この状態で
    /// 制限を適用するとルールが別の木に付き、コマンドも rootfs の外で動く。SEC-1・TASK-163.3）。
    ExecRootNotContainerRootfs,
    /// `setns` 参加後の呼び出しプロセスの mount namespace が、制限を準備した時点の exec の対象（pid1）の
    /// mount namespace と一致しない（A 用に準備した制限を、同じ rootfs を共有する別コンテナ B へ参加した
    /// プロセスへ適用させない。rootfs のディレクトリ照合だけでは取り違えを検出できない。SEC-1・TASK-163.4）。
    ExecJoinedNamespaceMismatch,
    /// `setns` 参加後に子が入る PID namespace（`ns/pid_for_children`）が、制限を準備した時点の exec の対象
    /// （pid1）の PID namespace と一致しない（同じ mount namespace を共有する別の参加先へ、準備済みの制限を
    /// 適用させない。SEC-1・TASK-163.4）。
    ExecJoinedPidNamespaceMismatch,
    /// cgroup 参加後の呼び出しプロセスの所属 cgroup が、制限を準備した時点の exec の対象のコンテナ cgroup と
    /// 一致しない（同上。SEC-1・TASK-163.4）。
    ExecJoinedCgroupMismatch,
    /// 起動時から保持する pidfd の指すプロセスが、記録した pid と一致しない（pidfd の取り違え・記録の
    /// 古さ。cgroup の所属に依らない同一性の照合。SUP-6・SEC-1・TASK-163 追補・#1461）。
    ExecTargetPidfdMismatch,
}

impl ViolationReason {
    /// 種別 [`ViolationKind::ExecTarget`] の理由の全一覧（exec の対象の拒否。SUP-6・SEC-1）。
    ///
    /// supervisor の worker が返す理由コードを許可リストとして引き直すための SSOT（#1465）。
    pub const EXEC_TARGET_REASONS: [ViolationReason; 10] = [
        Self::ExecTargetNotNestedPid1,
        Self::ExecTargetCgroupMismatch,
        Self::ExecTargetSharesPidNamespace,
        Self::ExecTargetSharesMountNamespace,
        Self::ExecTargetInOtherUserNamespace,
        Self::ExecRootNotContainerRootfs,
        Self::ExecJoinedNamespaceMismatch,
        Self::ExecJoinedPidNamespaceMismatch,
        Self::ExecJoinedCgroupMismatch,
        Self::ExecTargetPidfdMismatch,
    ];

    /// exec 対象の理由コード文字列から理由を引き直す（許可リスト照合。未知の文字列は `None`）。
    ///
    /// 外部（worker の結果行）から届いた文字列を、監査レコードへ入る静的トークンへ変換する唯一の入口。
    pub fn from_exec_target_token(token: &str) -> Option<Self> {
        Self::EXEC_TARGET_REASONS
            .into_iter()
            .find(|r| r.as_str() == token)
    }

    /// exec 対象の理由なら `ExecTarget` 監査イベントを返す（それ以外は `None`）。パスは持たない。
    pub fn exec_target_audit_event(self) -> Option<AuditEvent> {
        (self.kind() == ViolationKind::ExecTarget).then(|| AuditEvent::ExecTarget {
            reason: AuditReason::new(self.as_str()),
        })
    }

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
            Self::RootfsSymlinkOrNotDirectory => "rootfs_symlink_or_not_directory",
            Self::TargetIsRootfs => "target_is_rootfs",
            Self::PathSymlinkOrNotDirectory => "path_symlink_or_not_directory",
            Self::PathMissing => "path_missing",
            Self::TargetOnSharedMount => "target_on_shared_mount",
            Self::TargetMoved => "target_moved",
            Self::RootfsIsHostRoot => "rootfs_is_host_root",
            Self::RootfsOnSharedMount => "rootfs_on_shared_mount",
            Self::RootfsMoved => "rootfs_moved",
            Self::RootfsHasSubmounts => "rootfs_has_submounts",
            Self::RootfsHasExternalHardlink => "rootfs_has_external_hardlink",
            Self::EntrypointIsRuntimeBinary => "entrypoint_is_runtime_binary",
            Self::StdioNullNotNullDevice => "stdio_null_not_null_device",
            Self::EntrypointInterpreterIsRuntimeBinary => {
                "entrypoint_interpreter_is_runtime_binary"
            }
            Self::ExecDevNotDirectory => "exec_dev_not_directory",
            Self::ExecProcNotProcfs => "exec_proc_not_procfs",
            Self::ExecTargetNotNestedPid1 => "exec_target_not_nested_pid1",
            Self::ExecTargetCgroupMismatch => "exec_target_cgroup_mismatch",
            Self::ExecTargetSharesPidNamespace => "exec_target_shares_pid_namespace",
            Self::ExecTargetSharesMountNamespace => "exec_target_shares_mount_namespace",
            Self::ExecTargetInOtherUserNamespace => "exec_target_in_other_user_namespace",
            Self::ExecRootNotContainerRootfs => "exec_root_not_container_rootfs",
            Self::ExecJoinedNamespaceMismatch => "exec_joined_namespace_mismatch",
            Self::ExecJoinedPidNamespaceMismatch => "exec_joined_pid_namespace_mismatch",
            Self::ExecJoinedCgroupMismatch => "exec_joined_cgroup_mismatch",
            Self::ExecTargetPidfdMismatch => "exec_target_pidfd_mismatch",
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
            | Self::RootfsSymlinkOrNotDirectory
            | Self::TargetIsRootfs
            | Self::PathSymlinkOrNotDirectory
            | Self::PathMissing
            | Self::TargetMoved => ViolationKind::MountTarget,
            Self::TargetOnSharedMount | Self::RootfsOnSharedMount => {
                ViolationKind::SharedPropagation
            }
            Self::RootfsIsHostRoot
            | Self::RootfsMoved
            | Self::RootfsHasSubmounts
            | Self::RootfsHasExternalHardlink => ViolationKind::RootfsPivot,
            Self::EntrypointIsRuntimeBinary
            | Self::StdioNullNotNullDevice
            | Self::EntrypointInterpreterIsRuntimeBinary
            | Self::ExecDevNotDirectory
            | Self::ExecProcNotProcfs => ViolationKind::Entrypoint,
            Self::ExecTargetNotNestedPid1
            | Self::ExecTargetCgroupMismatch
            | Self::ExecTargetSharesPidNamespace
            | Self::ExecTargetSharesMountNamespace
            | Self::ExecTargetInOtherUserNamespace
            | Self::ExecRootNotContainerRootfs
            | Self::ExecJoinedNamespaceMismatch
            | Self::ExecJoinedPidNamespaceMismatch
            | Self::ExecJoinedCgroupMismatch
            | Self::ExecTargetPidfdMismatch => ViolationKind::ExecTarget,
        }
    }

    /// 違反した前提のビヘイビア ID（SSOT: spec `04-behavior/`）。
    pub fn behavior_id(self) -> &'static str {
        match self {
            Self::UserNamespaceRequired | Self::HostRootIdentityMapping | Self::IdentityChanged => {
                "SEC-5"
            }
            Self::ExecTargetCgroupMismatch
            | Self::StdioNullNotNullDevice
            | Self::EntrypointInterpreterIsRuntimeBinary
            | Self::ExecDevNotDirectory
            | Self::ExecProcNotProcfs
            | Self::ExecRootNotContainerRootfs
            | Self::ExecJoinedNamespaceMismatch
            | Self::ExecJoinedPidNamespaceMismatch
            | Self::ExecJoinedCgroupMismatch => "SEC-1",
            Self::ExecTargetNotNestedPid1
            | Self::ExecTargetSharesPidNamespace
            | Self::ExecTargetSharesMountNamespace
            | Self::ExecTargetInOtherUserNamespace
            | Self::ExecTargetPidfdMismatch => "SUP-6",
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
            | Self::RootfsSymlinkOrNotDirectory
            | Self::TargetIsRootfs
            | Self::PathSymlinkOrNotDirectory
            | Self::PathMissing
            | Self::RootfsIsHostRoot => ErrorCode::InvalidArgument,
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
            | Self::TargetOnSharedMount
            | Self::TargetMoved
            | Self::RootfsOnSharedMount
            | Self::RootfsMoved
            | Self::RootfsHasSubmounts
            | Self::RootfsHasExternalHardlink
            | Self::ExecTargetNotNestedPid1
            | Self::ExecTargetCgroupMismatch
            | Self::ExecTargetSharesPidNamespace
            | Self::ExecTargetSharesMountNamespace
            | Self::ExecTargetInOtherUserNamespace
            | Self::ExecRootNotContainerRootfs
            | Self::ExecJoinedNamespaceMismatch
            | Self::ExecJoinedPidNamespaceMismatch
            | Self::ExecJoinedCgroupMismatch
            | Self::ExecTargetPidfdMismatch
            | Self::ExecDevNotDirectory
            | Self::ExecProcNotProcfs => ErrorCode::FailedPrecondition,
            Self::EntrypointIsRuntimeBinary
            | Self::StdioNullNotNullDevice
            | Self::EntrypointInterpreterIsRuntimeBinary => ErrorCode::PermissionDenied,
        }
    }

    /// 拒否した段の既定（計画は `Validate`、rootfs 指定は `PrepareRootfs`、エントリポイントは `Exec`、
    /// exec の対象は `SetNs`、それ以外は `MountProc`）。
    /// `prepare_rootfs` / `pivot_root` が共通のパス理由を返すときは、呼び出した段を
    /// `ExecError::from_violation_at` で明示する。
    pub(super) fn stage(self) -> IsolationStage {
        match self.kind() {
            ViolationKind::PlanRejected => IsolationStage::Validate,
            ViolationKind::RootfsPivot => IsolationStage::PrepareRootfs,
            ViolationKind::Entrypoint => IsolationStage::Exec,
            ViolationKind::ExecTarget => IsolationStage::SetNs,
            _ => IsolationStage::MountProc,
        }
    }

    /// 英語のメッセージ（`ExecError::message`）。マウント先に関する文言は procfs（`mount_proc`）と tmpfs
    /// （`mount_tmpfs`。SUP-12・TASK-169.2）の両方の段が使うため、種別を含めない中立な表現にする。
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
            Self::PathNotAbsolute => "rootfs and mount target must be absolute paths",
            Self::PathContainsNul => "rootfs and mount target must not contain NUL",
            Self::PathParentComponent => "rootfs and mount target must not contain '..'",
            Self::TargetOutsideRootfs => "mount target must be under rootfs",
            Self::RootfsMissing => "rootfs must exist",
            Self::RootfsSymlinkOrNotDirectory => {
                "rootfs and its ancestors must be directories, not symlinks"
            }
            Self::TargetIsRootfs => {
                "mount target must be a dedicated directory below rootfs, not rootfs itself"
            }
            Self::PathSymlinkOrNotDirectory => {
                "mount target path components must be directories, not symlinks"
            }
            Self::PathMissing => "mount target path must exist",
            Self::TargetOnSharedMount => {
                "mount target is on a shared mount; isolate the mount namespace first"
            }
            Self::TargetMoved => "mount target was moved or removed after validation",
            Self::RootfsIsHostRoot => "rootfs must not be the host root '/'",
            Self::RootfsOnSharedMount => {
                "rootfs is on a shared mount; isolate the mount namespace first"
            }
            Self::RootfsMoved => "rootfs was moved or removed after validation",
            Self::RootfsHasSubmounts => {
                "rootfs contains existing mounts; unknown submounts are not allowed"
            }
            Self::RootfsHasExternalHardlink => {
                "rootfs contains a file hard-linked to an inode outside the rootfs"
            }
            Self::EntrypointIsRuntimeBinary => {
                "the entrypoint is the runtime's own executable; refusing to exec it"
            }
            Self::EntrypointInterpreterIsRuntimeBinary => {
                "the interpreter of the entrypoint resolves to the runtime's own executable; \
                 refusing to exec it"
            }
            Self::ExecDevNotDirectory => "/dev in the new root is not a directory",
            Self::ExecProcNotProcfs => {
                "/proc in the new root is not procfs; cannot reopen a verified file"
            }
            Self::StdioNullNotNullDevice => {
                "/dev/null in the new root is not the null device (1:3); refusing to open it"
            }
            Self::ExecTargetNotNestedPid1 => {
                "the exec target is not PID 1 of a directly nested PID namespace"
            }
            Self::ExecTargetCgroupMismatch => {
                "the exec target does not belong to the recorded container cgroup"
            }
            Self::ExecTargetSharesPidNamespace => {
                "the exec target shares the PID namespace with the caller; refusing to join"
            }
            Self::ExecTargetSharesMountNamespace => {
                "the exec target shares the mount namespace with the caller; refusing to join"
            }
            Self::ExecTargetInOtherUserNamespace => {
                "the exec target is in another user namespace than the caller; refusing to join"
            }
            Self::ExecRootNotContainerRootfs => {
                "the root directory after joining is not the recorded container rootfs"
            }
            Self::ExecJoinedNamespaceMismatch => {
                "the mount namespace after joining is not the one of the prepared exec target"
            }
            Self::ExecJoinedPidNamespaceMismatch => {
                "the PID namespace after joining is not the one of the prepared exec target"
            }
            Self::ExecJoinedCgroupMismatch => {
                "the cgroup after joining is not the one of the prepared exec target"
            }
            Self::ExecTargetPidfdMismatch => {
                "the process held by the launch pidfd is not the recorded exec target"
            }
        }
    }
}

/// 違反記録の対象として保持する文字列の上限（文字数。超過分は切り詰める）。
pub const VIOLATION_SUBJECT_MAX_CHARS: usize = 256;

/// 違反の対象（呼び出し側が渡したパス。exec の対象の cgroup 不一致では、記録から導いた期待 cgroup パス）。Cc・Cf・Zl・Zp の文字とバックスラッシュはエスケープ済みで、
/// 長さは [`VIOLATION_SUBJECT_MAX_CHARS`] 文字以下（ログ注入・無制限確保を防ぐ）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ViolationSubject {
    text: String,
    truncated: bool,
}

impl ViolationSubject {
    /// パスから作る。非 UTF-8 のバイトは U+FFFD に置き換え、Unicode 一般カテゴリ Cc・Cf・Zl・Zp の文字（改行・ESC・双方向制御等。判定は `crate::sanitize`）と
    /// `\` は `char::escape_default` 形式でエスケープする。
    pub(super) fn from_path(path: &Path) -> Self {
        let lossy = path.to_string_lossy();
        let mut text = String::new();
        let mut count = 0usize;
        let mut truncated = false;
        for c in lossy.chars() {
            let escaped: String = if is_display_unsafe_char(c) || c == '\\' {
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

/// 分離違反の試行を拒否したときの構造化された記録（SEC-4 の記録経路。マウント層の写像は TASK-41.4、exec 対象の写像は #1465）。
///
/// `ExecError::violation` から取り出す。生成は `crate::exec` の拒否経路のみ。
///
/// - **記録の経路のみ**: ファイルへの永続化は `audit_log` に実装済みだが、本番経路への sink の
///   配線は未実装（REPAIR-3）。呼び出し側は受け取った記録を必要に応じて自分で扱う
/// - **違反**（構成・呼び出し文脈・パスが分離の前提を満たさず fail-closed で拒否したもの）
///   にだけ付く。**システムエラー**（syscall 失敗・procfs の読み取り失敗・mountinfo の書式
///   不正・権限不足）と hostname の書式エラーには付かない
/// - namespace の識別子や正規化後のホスト側実パスは含めない
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
    /// 監査レコード用の生パス（エスケープ・切り詰め前。`AuditPath` が 4096 バイトで切り詰める）。
    audit_path: Option<AuditPath>,
}

impl IsolationViolation {
    /// 理由から作る（種別・ビヘイビア ID は理由から決まる）。
    pub(super) fn new(reason: ViolationReason, subject: Option<&Path>) -> Self {
        Self {
            kind: reason.kind(),
            reason,
            behavior_id: reason.behavior_id(),
            subject: subject.map(ViolationSubject::from_path),
            audit_path: subject.map(AuditPath::new),
        }
    }

    /// 監査用の生パス（SEC-4・TASK-41.4）。エスケープは書き込み側（TASK-41.5 系）の責務で、
    /// `subject` のエスケープ済み文字列は流用しない（二重エスケープ・表記ずれを避ける）。
    pub fn audit_path(&self) -> Option<&AuditPath> {
        self.audit_path.as_ref()
    }

    /// exec の対象の違反（種別 `ExecTarget`）なら `ExecTarget` 監査イベントを返す（SEC-4・SUP-6・#1465）。
    ///
    /// 理由コードだけを載せ、`audit_path`（期待 cgroup パス等）は使わない。
    pub fn exec_audit_event(&self) -> Option<AuditEvent> {
        self.reason.exec_target_audit_event()
    }

    /// マウント検証層の違反なら `Mount` 監査イベントを返す（SEC-4・TASK-41.4）。
    ///
    /// 対象は `MountTarget`・`SharedPropagation`・`RootfsPivot`。計画・establish 前提・証跡不一致・
    /// エントリポイントはマウント層の拒否ではないため `None`。exec の対象の拒否は [`Self::exec_audit_event`]。
    pub fn mount_audit_event(&self) -> Option<AuditEvent> {
        match self.kind {
            ViolationKind::MountTarget
            | ViolationKind::SharedPropagation
            | ViolationKind::RootfsPivot => Some(AuditEvent::Mount {
                path: self.audit_path.clone(),
            }),
            ViolationKind::PlanRejected
            | ViolationKind::EstablishPrecondition
            | ViolationKind::EvidenceMismatch
            | ViolationKind::Entrypoint
            | ViolationKind::ExecTarget => None,
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

    /// SEC-4: Cf（双方向制御・WORD JOINER）と Zl・Zp も `escape_default` 形式でエスケープする。
    #[test]
    fn sec4_subject_escapes_format_and_separator_chars() {
        let s = ViolationSubject::from_path(Path::new("/a\u{202E}b\u{2060}c\u{2028}d\u{2029}e"));
        assert_eq!(s.as_str(), "/a\\u{202e}b\\u{2060}c\\u{2028}d\\u{2029}e");
        assert!(!s.is_truncated());
    }

    /// SEC-4: Cf のエスケープ列（8 文字）でも上限 256 文字を超えず、途中で切らない。
    #[test]
    fn sec4_subject_bound_holds_with_format_char_escapes() {
        // 1 個 8 文字のエスケープ列が 32 個でちょうど 256 文字（33 個目で切り詰め）。
        let many = "\u{202E}".repeat(33);
        let s = ViolationSubject::from_path(Path::new(&many));
        assert_eq!(s.as_str().chars().count(), 256);
        assert!(s.is_truncated());
        let fit = format!("/{}\u{202E}", "a".repeat(247));
        let s = ViolationSubject::from_path(Path::new(&fit));
        assert_eq!(s.as_str().chars().count(), 256);
        assert!(!s.is_truncated());
        let over = format!("/{}\u{202E}", "a".repeat(248));
        let s = ViolationSubject::from_path(Path::new(&over));
        assert_eq!(s.as_str().chars().count(), 249);
        assert!(s.is_truncated());
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

    /// CORE-1（TASK-27.3）: rootfs 切替の理由コード・種別・`ErrorCode`・段の具体値。
    #[test]
    fn core1_rootfs_reason_metadata_is_exact() {
        let r = ViolationReason::RootfsIsHostRoot;
        assert_eq!(r.as_str(), "rootfs_is_host_root");
        assert_eq!(r.kind().as_str(), "rootfs_pivot");
        assert_eq!(r.behavior_id(), "CORE-1");
        assert_eq!(r.error_code(), ErrorCode::InvalidArgument);
        assert_eq!(r.stage(), IsolationStage::PrepareRootfs);
        assert_eq!(r.message(), "rootfs must not be the host root '/'");
        let r = ViolationReason::RootfsOnSharedMount;
        assert_eq!(r.as_str(), "rootfs_on_shared_mount");
        assert_eq!(r.kind().as_str(), "shared_propagation");
        assert_eq!(r.error_code(), ErrorCode::FailedPrecondition);
        let r = ViolationReason::RootfsMoved;
        assert_eq!(r.as_str(), "rootfs_moved");
        assert_eq!(r.kind().as_str(), "rootfs_pivot");
        assert_eq!(r.error_code(), ErrorCode::FailedPrecondition);
        let r = ViolationReason::RootfsHasSubmounts;
        assert_eq!(r.as_str(), "rootfs_has_submounts");
        assert_eq!(r.kind().as_str(), "rootfs_pivot");
        assert_eq!(r.behavior_id(), "CORE-1");
        assert_eq!(r.error_code(), ErrorCode::FailedPrecondition);
        assert_eq!(r.stage(), IsolationStage::PrepareRootfs);
        let r = ViolationReason::RootfsHasExternalHardlink;
        assert_eq!(r.as_str(), "rootfs_has_external_hardlink");
        assert_eq!(r.kind().as_str(), "rootfs_pivot");
        assert_eq!(r.behavior_id(), "CORE-1");
        assert_eq!(r.error_code(), ErrorCode::FailedPrecondition);
        assert_eq!(r.stage(), IsolationStage::PrepareRootfs);
    }

    /// CORE-1（TASK-27.4.1）: エントリポイント検証の理由コード・種別・`ErrorCode`・段の具体値。
    #[test]
    fn core1_entrypoint_reason_metadata_is_exact() {
        let r = ViolationReason::EntrypointIsRuntimeBinary;
        assert_eq!(r.as_str(), "entrypoint_is_runtime_binary");
        assert_eq!(r.kind().as_str(), "entrypoint");
        assert_eq!(r.behavior_id(), "CORE-1");
        assert_eq!(r.error_code(), ErrorCode::PermissionDenied);
        assert_eq!(r.stage(), IsolationStage::Exec);
    }

    /// SUP-6・SEC-1・SEC-4（TASK-163 追補・#1458）: インタープリタ経由の拒否の理由コード・種別・ビヘイビア ID・
    /// `ErrorCode`・段・メッセージの具体値。
    #[test]
    fn sec4_sup6_task163_interpreter_reason_metadata_is_exact() {
        let r = ViolationReason::EntrypointInterpreterIsRuntimeBinary;
        assert_eq!(r.as_str(), "entrypoint_interpreter_is_runtime_binary");
        assert_eq!(r.kind().as_str(), "entrypoint");
        assert_eq!(r.behavior_id(), "SEC-1");
        assert_eq!(r.error_code(), ErrorCode::PermissionDenied);
        assert_eq!(r.stage(), IsolationStage::Exec);
        assert_eq!(
            r.message(),
            "the interpreter of the entrypoint resolves to the runtime's own executable; \
             refusing to exec it"
        );
        let v = IsolationViolation::new(r, Some(Path::new("/script")));
        assert_eq!(v.mount_audit_event(), None);
    }

    /// SUP-6・SEC-1・SEC-4（TASK-163 追補・#1459）: `/dev`・`/proc` の差し替えの理由コード・種別・ビヘイビア ID・
    /// `ErrorCode`・段・メッセージの具体値。
    #[test]
    fn sec4_sup6_task163_dev_and_proc_reason_metadata_is_exact() {
        for (r, code, message) in [
            (
                ViolationReason::ExecDevNotDirectory,
                "exec_dev_not_directory",
                "/dev in the new root is not a directory",
            ),
            (
                ViolationReason::ExecProcNotProcfs,
                "exec_proc_not_procfs",
                "/proc in the new root is not procfs; cannot reopen a verified file",
            ),
        ] {
            assert_eq!(r.as_str(), code);
            assert_eq!(r.kind().as_str(), "entrypoint");
            assert_eq!(r.behavior_id(), "SEC-1");
            assert_eq!(r.error_code(), ErrorCode::FailedPrecondition);
            assert_eq!(r.stage(), IsolationStage::Exec);
            assert_eq!(r.message(), message);
            assert_eq!(IsolationViolation::new(r, None).mount_audit_event(), None);
        }
    }

    /// SUP-6・SEC-1・SEC-4（TASK-163 追補・#1459）: `/dev/null` 差し替えの理由コード・種別・ビヘイビア ID・
    /// `ErrorCode`・段・メッセージの具体値。マウント層の違反ではないため `Mount` 監査イベントへは写らない。
    #[test]
    fn sec4_sup6_task163_stdio_null_reason_metadata_is_exact() {
        let r = ViolationReason::StdioNullNotNullDevice;
        assert_eq!(r.as_str(), "stdio_null_not_null_device");
        assert_eq!(r.kind().as_str(), "entrypoint");
        assert_eq!(r.behavior_id(), "SEC-1");
        assert_eq!(r.error_code(), ErrorCode::PermissionDenied);
        assert_eq!(r.stage(), IsolationStage::Exec);
        assert_eq!(
            r.message(),
            "/dev/null in the new root is not the null device (1:3); refusing to open it"
        );
        let v = IsolationViolation::new(r, Some(Path::new("/dev/null")));
        assert_eq!(v.mount_audit_event(), None);
    }

    /// SEC-4・SEC-1・SUP-6（TASK-163.1）: exec の対象の検証の理由コード・種別・ビヘイビア ID・`ErrorCode`・
    /// 段・メッセージの具体値。マウント層の違反ではないため `Mount` 監査イベントへは写らない。
    #[test]
    fn sec4_sup6_exec_target_reason_metadata_is_exact() {
        let cases = [
            (
                ViolationReason::ExecTargetNotNestedPid1,
                "exec_target_not_nested_pid1",
                "SUP-6",
                "the exec target is not PID 1 of a directly nested PID namespace",
            ),
            (
                ViolationReason::ExecTargetCgroupMismatch,
                "exec_target_cgroup_mismatch",
                "SEC-1",
                "the exec target does not belong to the recorded container cgroup",
            ),
            (
                ViolationReason::ExecTargetSharesPidNamespace,
                "exec_target_shares_pid_namespace",
                "SUP-6",
                "the exec target shares the PID namespace with the caller; refusing to join",
            ),
            (
                ViolationReason::ExecTargetSharesMountNamespace,
                "exec_target_shares_mount_namespace",
                "SUP-6",
                "the exec target shares the mount namespace with the caller; refusing to join",
            ),
            (
                ViolationReason::ExecTargetInOtherUserNamespace,
                "exec_target_in_other_user_namespace",
                "SUP-6",
                "the exec target is in another user namespace than the caller; refusing to join",
            ),
            (
                ViolationReason::ExecRootNotContainerRootfs,
                "exec_root_not_container_rootfs",
                "SEC-1",
                "the root directory after joining is not the recorded container rootfs",
            ),
            (
                ViolationReason::ExecJoinedNamespaceMismatch,
                "exec_joined_namespace_mismatch",
                "SEC-1",
                "the mount namespace after joining is not the one of the prepared exec target",
            ),
            (
                ViolationReason::ExecJoinedPidNamespaceMismatch,
                "exec_joined_pid_namespace_mismatch",
                "SEC-1",
                "the PID namespace after joining is not the one of the prepared exec target",
            ),
            (
                ViolationReason::ExecJoinedCgroupMismatch,
                "exec_joined_cgroup_mismatch",
                "SEC-1",
                "the cgroup after joining is not the one of the prepared exec target",
            ),
            (
                ViolationReason::ExecTargetPidfdMismatch,
                "exec_target_pidfd_mismatch",
                "SUP-6",
                "the process held by the launch pidfd is not the recorded exec target",
            ),
        ];
        for (r, code, behavior, message) in cases {
            assert_eq!(r.as_str(), code);
            assert_eq!(r.kind(), ViolationKind::ExecTarget);
            assert_eq!(r.kind().as_str(), "exec_target");
            assert_eq!(r.behavior_id(), behavior);
            assert_eq!(r.error_code(), ErrorCode::FailedPrecondition);
            assert_eq!(r.stage(), IsolationStage::SetNs);
            assert_eq!(r.message(), message);
            let v = IsolationViolation::new(r, None);
            assert_eq!(v.mount_audit_event(), None);
        }
    }

    /// SEC-4・TASK-41.4: 理由ごとの Mount 写像の有無を具体値で照合し、生パスを保持する。
    #[test]
    fn sec4_task41_4_mount_audit_event_mapping() {
        let mapped = [
            (ViolationReason::PathParentComponent, true),
            (ViolationReason::TargetOutsideRootfs, true),
            (ViolationReason::TargetOnSharedMount, true),
            (ViolationReason::RootfsIsHostRoot, true),
            (ViolationReason::RootfsHasExternalHardlink, true),
            (ViolationReason::NoNamespaces, false),
            (ViolationReason::EstablishNotPid1, false),
            (ViolationReason::EvidenceCallerNotPid1, false),
            (ViolationReason::EntrypointIsRuntimeBinary, false),
        ];
        for (reason, expect) in mapped {
            let v = IsolationViolation::new(reason, Some(Path::new("/x")));
            assert_eq!(v.mount_audit_event().is_some(), expect, "{reason:?}");
        }
        let raw = Path::new("/a\nb\\c");
        let v = IsolationViolation::new(ViolationReason::PathParentComponent, Some(raw));
        assert_eq!(v.audit_path().map(|p| p.as_path()), Some(raw));
        let v = IsolationViolation::new(ViolationReason::RootfsMissing, None);
        assert_eq!(
            v.mount_audit_event(),
            Some(AuditEvent::Mount { path: None })
        );
    }

    /// SEC-4・SUP-6・TASK-163 追補: exec 対象の 10 理由は許可リスト往復でき、対象外・未知は引けない。
    #[test]
    fn sec4_sup6_task163_exec_target_token_allowlist() {
        assert_eq!(ViolationReason::EXEC_TARGET_REASONS.len(), 10);
        for r in ViolationReason::EXEC_TARGET_REASONS {
            assert_eq!(r.kind(), ViolationKind::ExecTarget);
            assert_eq!(ViolationReason::from_exec_target_token(r.as_str()), Some(r));
        }
        for t in [
            "target_moved",
            "entrypoint_is_runtime_binary",
            "",
            "unknown",
            "exec_target",
        ] {
            assert_eq!(ViolationReason::from_exec_target_token(t), None, "{t}");
        }
        assert_eq!(
            ViolationReason::EntrypointIsRuntimeBinary.exec_target_audit_event(),
            None
        );
    }

    /// SEC-4・SUP-6・TASK-163 追補: 期待 cgroup パスを subject に持つ違反でもレコードにパスは載らない。
    #[test]
    fn sec4_sup6_task163_exec_audit_event_has_no_path() {
        let v = IsolationViolation::new(
            ViolationReason::ExecTargetCgroupMismatch,
            Some(Path::new("/sys/fs/cgroup/fandhe/c1")),
        );
        assert!(v.audit_path().is_some());
        let ev = v.exec_audit_event();
        assert_eq!(
            ev,
            Some(AuditEvent::ExecTarget {
                reason: AuditReason::new("exec_target_cgroup_mismatch")
            })
        );
        assert_eq!(v.mount_audit_event(), None);
    }

    /// SEC-4・TASK-41.4: audit_mount_violation は違反のみ記録し、エラーを変えない。
    #[test]
    fn sec4_task41_4_audit_mount_violation_records_once() {
        use crate::audit_log::mount::tests::VecSink;
        use crate::audit_log::{AuditDelivery, AuditLayer};
        use crate::exec::{ExecError, audit_mount_violation};

        let sink = VecSink::new(false);
        let err = ExecError::from_violation_at(
            ViolationReason::PathParentComponent,
            Some(Path::new("/tmp/a/../b")),
            IsolationStage::PrepareRootfs,
        );
        let r = audit_mount_violation(err, &sink);
        assert_eq!(r.delivery, AuditDelivery::Recorded);
        assert_eq!(
            r.error.violation.as_ref().map(|v| v.reason),
            Some(ViolationReason::PathParentComponent)
        );
        let recs = sink.snapshot();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].layer(), AuditLayer::Mount);
        assert_eq!(recs[0].path(), Some(Path::new("/tmp/a/../b")));

        let sys = ExecError::new(ErrorCode::Internal, IsolationStage::MountProc, "sys");
        let r = audit_mount_violation(sys, &sink);
        assert_eq!(r.delivery, AuditDelivery::NotApplicable);
        assert_eq!(sink.snapshot().len(), 1);
    }
}
