//! 実行層の最小実行フロー（CORE-1・TASK-27・MS-2）を担うモジュール。
//!
//! 現状は namespace 分離（[`isolate`]・[`mount_proc`]。#134・TASK-27.2）と、`pivot_root` による
//! rootfs 切替（[`prepare_rootfs`]・[`pivot_root`]。#135・TASK-27.3）、基本デバイスノード作成
//! （[`create_default_devices`]。#834・TASK-27.6）、fork / exec による子プロセス
//! 起動（[`spawn_container`]・[`exec_entrypoint`]。#831・TASK-27.4.1）と、順序固定のステージ列の枠
//! （[`StagePipeline`]。#832・TASK-27.4.2。`exec/stages.rs`）まで実装済み。各段の実体
//! のうち `PR_SET_NO_NEW_PRIVS` は組み込みの固定ステージとして実装済み（#833・TASK-27.4.3。
//! `exec/no_new_privs.rs`）、capability 削減（#173）と seccomp（#178・TASK-38.3）も同様に組み込み済み。
//! cgroup 参加は `cgroups::CgroupJoin`（TASK-32.4・#161）が `StageHook` として実装済み（登録は呼び出し側）。
//! exec 経路（SUP-6）の制限の再適用は [`prepare_exec_restrictions`] / [`reapply_restrictions`]
//! （TASK-163.3・TASK-163.4・#502・#503。`exec/reapply.rs`。`setns` の後に使えるよう status fd と rootfs の固定を事前に保持する二段階 API。参加後の対象束縛と `/` を照合してから、rlimit・capability 削減・`NO_NEW_PRIVS`・Landlock・seccomp を launch と同じ順で適用する）。稼働中コンテナでのコマンド実行は、再適用の完了の証跡 [`ExecReady`] だけを受け取る [`spawn_exec_command`]（`exec/exec_command.rs`。fork → `close_range` → `execveat`。TASK-163.4・#503）が担う。launch 経路の制限適用の証跡は未実装（Landlock は `StagePipeline::with_landlock` で差し込み可能。#184）で、後続の sub-issue（#137、TASK-39・40）が追記する（REPAIR-3: 実装済みを装わない）。
//!
//! # 目指すフロー（Linux 専用）
//!
//! 1. namespace 分離（PID / mount / UTS / IPC / user。#134・TASK-27.2。**実装済み**）
//! 2. `pivot_root` による rootfs 切替と旧 root の後始末（#135・TASK-27.3。**実装済み**。
//!    [`prepare_rootfs`]〔自己 bind と rootfs 配下への `/proc` マウント〕→ [`pivot_root`]）
//! 3. rootfs の `dev` への専用 tmpfs のマウント（#1653）と、その上への基本デバイスノード 6 種・
//!    default symlink 4 本・`/dev/pts` の独立した devpts・`/dev/ptmx`（`pts/ptmx` への symlink）の作成
//!    （#834・TASK-27.6・#1656。**実装済み**。[`create_default_devices`] を
//!    [`prepare_rootfs`] の後・[`pivot_root`] の前に呼ぶ。rootful は `mknod`、rootless はホストの
//!    `/dev/<名前>` の bind で基本デバイスを供給する〔#1660〕）
//! 4. 順序固定のステージ列: cgroup 参加 → capability 削減 → `PR_SET_NO_NEW_PRIVS`
//!    → Landlock → seccomp（#136・#832・#833。**枠・`NO_NEW_PRIVS`・capability 削減・seccomp は実装済み**: [`StagePipeline`] が
//!    [`StageKind::ORDER`] の固定順でフックを呼び、`NO_NEW_PRIVS` は差し替え不可の組み込み段として
//!    常に適用する。capability の絞り込み処理 `apply_default_capabilities`（crate 内限定。SEC-1・TASK-37.1・#172）
//!    も #173（TASK-37.2）で同じく差し替え不可の組み込み段になった。seccomp の適用処理 `apply_default_seccomp`
//!    （crate 内限定。CORE-5・TASK-38.2・#177）も #178（TASK-38.3）で同じく差し替え不可の組み込み段になり、
//!    exec 直前に必ず適用される。最終的な制限の証跡は未実装（Landlock は `StagePipeline::with_landlock` で差し込み可能。
//!    組み込み段ではない）のため exec は引き続き拒否される。cgroup 参加は `cgroups::CgroupJoin` を呼び出し側が登録して使う。
//!    他の段の実体は未実装で、後続の TASK-39・40 が [`StageHook`] として
//!    差し込む）。
//!    `NO_NEW_PRIVS` を Landlock / seccomp より前に固定する順序は fail-closed の前提で、
//!    後続実装はこの順序を崩さない
//! 5. `fork` / `exec`（#831・TASK-27.4.1。**最小構成のみ実装済み**。[`spawn_container`] が分離済みの
//!    親から子を fork し、子が `establish` → [`prepare_rootfs`] → [`pivot_root`] →
//!    [`exec_entrypoint`] を行う。上の第 3・4 段〔デバイスノード・ステージ列・`NO_NEW_PRIVS`〕のうち
//!    制限適用の証跡配線が未実装のため**この最小構成は exec を許可せず、[`exec_entrypoint`] は
//!    制限の適用証跡が無い限り rootful・rootless を問わず `PermissionDenied` で exec を拒否する**
//!    （SEC-1・CORE-5。fail-closed）。親子間の同期・構造化エラーパイプも未実装で、子の失敗は
//!    終了コードと stderr で伝える〔TASK-29/30 で扱う〕）
//!
//! # 前提・契約
//!
//! - 本モジュールは `#[cfg(target_os = "linux")]` でモジュールごとビルド対象から外れる。
//!   macOS / Windows ではコンテナはゲスト VM（Linux）内で実行されるため、ホスト側から
//!   直接呼ぶ経路は存在しない（非 Linux ビルドの確認は #137・TASK-27.5）
//! - syscall を呼ぶ `unsafe` は `crate::sys` に閉じ込め、本ファイルには置かない
//! - 呼び出し元は TASK-29 の `oci_runtime`（`create` / `start`）と supervisor（TASK-157）を想定し、fork 段は
//!   [`spawn_container`]（#831）が担う
//! - 常駐デーモンを前提にしない（CORE-1・D-19）
//! - 分離違反の試行を拒否したエラーは `ExecError::violation` に構造化された違反記録
//!   （[`IsolationViolation`]: 種別・理由コード・ビヘイビア ID・対象）を持つ。**記録の経路のみ**で、
//!   マウント層の監査レコード化は [`audit_mount_violation`]（TASK-41.4）、exec の対象の拒否の監査レコード化
//!   （層 `exec_target`）は [`audit_exec_violation`]・[`record_exec_target_rejection`]（#1465）、
//!   エントリポイント検証の拒否（層 `entrypoint`）は [`audit_entrypoint_violation`]・
//!   [`record_entrypoint_rejection`]（#1595）、supervisor の exec の worker の経路の拒否（層 `exec_target`、
//!   または種別 `rootfs_pivot` の `rootfs_is_host_root` を層 `mount` のパスなし）は [`record_exec_worker_rejection`] が担う。
//!   ファイルへの保存は `audit_log::AuditFileWriter`（#839）で実装済みで、本番経路への sink の配線は未実装
//!   （REPAIR-3）。システムエラーには付かない
//!
//! # namespace 分離の契約（[`isolate`]・[`isolate_rootful_host_root`]）
//!
//! - 分離は検証済みの計画を型で受け取る。既定は [`plan`] → [`isolate`]（user namespace 必須・
//!   非 root 起動。SEC-5）。ホスト root のまま動く rootful 分離は [`plan_rootful_host_root`] →
//!   [`isolate_rootful_host_root`] という別経路で、計画の型（[`IsolationPlan`] /
//!   [`RootfulHostRootPlan`]）が異なるため既定経路が rootful へ暗黙に落ちることはない
//! - シングルスレッドのプロセスから呼ぶこと（マルチスレッドからの `CLONE_NEWUSER` は
//!   `EINVAL` になり、`FailedPrecondition` で返す）
//! - `unshare(CLONE_NEWPID)` は呼び出し元自身を移動させず、**次に生成する子が PID 1** になる。
//!   その PID 1 側で [`MountIsolation::establish`]（PID 1・入れ子の PID namespace の実行時
//!   検証と、PID 1 自身による新しい mount namespace の作成）を通し、[`mount_proc`] を呼んで
//!   初めて `/proc` からホストのプロセスが見えなくなる。証跡は呼び出し側の申告に依存しない
//!   （fail-closed）
//! - 途中で失敗しても namespace を元へ戻す手段はない。呼び出し元はそのプロセスを破棄する
//!   （長寿命のホストプロセスで呼ばない）。`pivot_root` 段（[`prepare_rootfs`]・[`pivot_root`]）も同じ
//! - rootfs の切替は `establish` → [`prepare_rootfs`] → [`pivot_root`] の順で、`/proc` は
//!   **pivot 前に rootfs 配下へマウントする**（[`PreparedRootfs`] がその証。詳細は `rootfs` の doc）
//! - 既定経路（[`isolate`]）の user namespace は自 euid / egid を コンテナ内 0 へ写す単一 ID 写像のみ。
//!   euid 0 での自 ID 写像はコンテナ root がホスト root に写るため拒否する（SEC-5）
//! - subuid 範囲の写像は別経路 [`plan_rootless_subordinate`] → [`isolate_rootless_subordinate`]
//!   （TASK-40.2・CORE-6。**実装済み**）が担う。呼び出したプロセス自身を分離する契約は [`isolate`]
//!   と同じで、写像だけを fork した mapper（外側の user namespace に残る）が
//!   [`crate::rootless`] で書く。rootless 経路で root 権限を要する操作をどう回避・代替するかの対応表は
//!   [`crate::rootless`] のモジュール doc を参照。`mknod` によるデバイスノード作成は代替せず、
//!   [`create_default_devices`] がホストの `/dev/<名前>` を fd 起点で bind して供給する（#1660）

use std::ffi::{CString, OsStr};
use std::fmt;
use std::io::Write as _;
use std::os::fd::{AsFd as _, AsRawFd as _, OwnedFd};
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Component, Path};
use std::time::Duration;

use crate::rootless::{
    self, IdMapReport, IdMapSet, IdMapWriter, MapperReply, RootlessError, WriterKind,
};
use crate::sys::{self, NsFlag, SysError};
use crate::traits::types::ErrorCode;

mod capabilities;
mod cgroup_join;
mod container_env;
mod devices;
mod entrypoint_mode;
mod exec_command;
mod inject;
mod interpreter;
mod landlock;
mod no_new_privs;
mod process;
mod reapply;
mod rlimits;
mod rootfs;
mod sealed_copy;
mod seccomp;
mod setns;
mod stages;
mod tmpfs;
mod violation;
#[cfg(test)]
mod violation_scan;

/// 結合試験 `tests/exec_child_setup.rs`・supervisor の `tests/exec_setns_join.rs` 専用の再公開
/// （SUP-6・TASK-163 追補・#1457。通常の利用者は呼ばない。詳細は定義側）。
#[cfg(all(feature = "exec-test-support", not(test)))]
#[doc(hidden)]
pub use capabilities::clear_supplementary_groups_for_test;
pub use capabilities::{CapabilityReport, SupplementaryGroups};
pub use cgroup_join::{
    ExecCgroupJoin, ExecCgroupJoinReport, ExecCgroupName, ExecCgroupRemoval, ExecCgroupSweep,
    ExecChildCgroup, join_cgroup, prepare_cgroup_join, remove_exec_child_cgroup,
    sweep_stale_exec_child_cgroups,
};
#[cfg(feature = "exec-test-support")]
pub use cgroup_join::{remove_exec_child_cgroup_in, sweep_stale_exec_child_cgroups_in};
pub use container_env::{ContainerEnv, ExecCommand};
pub use devices::{
    DeviceLinkOutcome, DeviceLinkStatus, DeviceNodeOutcome, DeviceNodeStatus, DeviceReport,
    DevptsDirStatus, DevptsGidSource, DevptsOutcome, create_default_devices,
};
/// 封印した複製の上限（結合試験が上限超過を再現するための再公開。TASK-163 追補・#1531）。
pub use entrypoint_mode::{EntrypointExecMode, IntegrityLsm, PathBoundLsm, SealedCopyUnavailable};
pub use exec_command::{ExecChild, ExecWorkerProof, spawn_exec_command, spawn_exec_worker};
pub use inject::{InjectReport, InjectedDirectoryOutcome, InjectedFileOutcome, inject_files};
/// 結合試験 `tests/landlock.rs` 専用の再公開（CORE-5・TASK-39.5・#185。通常の利用者は呼ばない。詳細は定義側）。
#[doc(hidden)]
pub use landlock::{
    LANDLOCK_PROBE_CONTENT_MISMATCH, LandlockAccessKind, LandlockAccessObservation,
    LandlockAccessProbe, observe_landlock_path_access,
};
/// supervisor の `SETUP_VIOLATIONS` との突き合わせ試験専用の再公開（SEC-4・SUP-6・#1579。通常の利用者は呼ばない）。
#[doc(hidden)]
pub use process::exec_child_violation_reasons;
/// 結合試験 `tests/escape_suite.rs` 専用の再公開（SEC-2・TASK-42.1・#199。通常の利用者は呼ばない。詳細は定義側）。
#[cfg(feature = "escape-probe")]
#[doc(hidden)]
pub use process::spawn_container_probe;
/// 結合試験 `tests/seccomp.rs` 専用の再公開（CORE-5・TASK-38.4・#179。通常の利用者は呼ばない。詳細は定義側）。
#[doc(hidden)]
pub use process::spawn_container_seccomp_probe;
pub use process::{
    ChildExit, ContainerChild, ENTRYPOINT_MAX_ARGS, ENTRYPOINT_MAX_ENV,
    ENTRYPOINT_MAX_STRING_BYTES, ENTRYPOINT_MAX_TOTAL_BYTES, EXIT_EXEC_NOT_EXECUTABLE,
    EXIT_EXEC_NOT_FOUND, EXIT_SETUP_FAILED, Entrypoint, ExecExit, SignalDelivery, exec_entrypoint,
    spawn_container, spawn_container_with_stages,
};
/// 結合試験 `tests/exec_child_setup.rs` 専用の再公開（SUP-6・TASK-163 追補・#1456。通常の利用者は呼ばない。詳細は定義側）。
#[cfg(all(feature = "exec-test-support", not(test)))]
#[doc(hidden)]
pub use process::{
    EXEC_FD_HEAD_BYTES, ExecChildSetupObservation, ExecChildSetupReport, ExecFdReport,
    observe_exec_child_setup, observe_exec_child_setup_pinned, observe_exec_child_setup_with,
    observe_exec_child_setup_with_fsize,
};
/// 結合試験 `tests/exec_child_setup.rs`・`tests/fork_exec_isolation.rs` 専用の再公開（SEC-1・CORE-1・TASK-27.4.1・#1299。
/// 通常の利用者は呼ばない。詳細は定義側）。
#[cfg(all(feature = "exec-test-support", not(test)))]
#[doc(hidden)]
pub use process::{StandardFd, close_standard_fds_for_test};
/// supervisor の結合試験 `tests/exec_audit.rs` 専用の再公開（SEC-4・SEC-1・#1614 の事後監査。通常の利用者は
/// 呼ばない。詳細は定義側）。`exec-test-support` feature を付けたビルドにだけ存在する。
#[cfg(feature = "exec-test-support")]
#[doc(hidden)]
pub use reapply::reject_own_root_for_test;
pub use reapply::{
    ExecReady, ExecRestrictionReport, ExecRestrictions, UnappliedExecRestriction,
    prepare_exec_restrictions, reapply_restrictions,
};
/// 結合試験 `tests/exec_restrictions_reapply.rs` 専用の再公開（SUP-6・TASK-163.3・#502。通常の利用者は呼ばない。詳細は定義側）。
/// `exec-test-support` feature を付けたビルドにだけ存在する（TASK-163 追補・#1460）。
#[cfg(feature = "exec-test-support")]
#[doc(hidden)]
pub use reapply::{ExecReapplyObservation, observe_exec_restriction_reapply};
pub use rootfs::{PivotReport, PreparedRootfs, pivot_root, prepare_rootfs};
pub use sealed_copy::MAX_SEALED_COPY_BYTES;
pub use seccomp::SeccompReport;
/// 結合試験 `tests/escape_suite.rs` の ESC-03 専用の再公開（SEC-2・TASK-42.2・#200。通常の利用者は呼ばない。詳細は定義側）。
#[cfg(feature = "escape-probe")]
#[doc(hidden)]
pub use seccomp::escape_probe_mount;
/// 結合試験 `tests/escape_suite.rs` 専用の再公開（SEC-2・TASK-42.3・#201。通常の利用者は呼ばない。詳細は定義側）。
#[cfg(feature = "escape-probe")]
#[doc(hidden)]
pub use seccomp::{EscapeSyscallProbe, probe_escape_syscall};
#[doc(hidden)]
pub use seccomp::{ProbeOutcome, SeccompProbeRecord};
/// 結合試験 `tests/seccomp_enforcement.rs` 専用の再公開（通常の利用者は呼ばない。詳細は定義側）。`unsafe` を `sys` の外へ出さないための観測専用の入口。
#[doc(hidden)]
pub use seccomp::{SeccompEnforcementObservation, observe_default_seccomp_enforcement};
pub use setns::{JoinNamespace, NamespaceJoinReport, Pid1Target, join_namespaces};
pub use stages::{StageHook, StageKind, StagePipeline, StageReport, StageStatus};
pub use tmpfs::{TmpfsMountOutcome, TmpfsReport, mount_tmpfs};
/// 結合試験 `tests/tmpfs_mount.rs` 専用の再公開（SUP-12・TASK-169 追補・#1472・#1669 事後監査 P2。通常の利用者は呼ばない。
/// 詳細は定義側）。
/// `exec-test-support` feature を付けたビルドにだけ存在する。
#[cfg(feature = "exec-test-support")]
#[doc(hidden)]
pub use tmpfs::{mount_tmpfs_over_bare_dev_for_test, mount_tmpfs_with_attach_hook};

/// 結合試験 `tests/sanitize_integration.rs` 専用の入口: パス検証の拒否（対象パス付きの違反記録）を
/// 作る（SEC-4・TASK-96.1・REPAIR-12。通常の利用者は呼ばない）。
///
/// 実際の拒否は `mount_proc` 等が特権（mount namespace の分離）を要する経路でしか得られないため、
/// それらが拒否時に通るのと同じ `ExecError::from_violation` を公開する。`exec-test-support` feature
/// を付けたビルドにだけ存在する。
#[cfg(feature = "exec-test-support")]
#[doc(hidden)]
pub fn path_violation_error_for_test(reason: ViolationReason, subject: &Path) -> ExecError {
    ExecError::from_violation(reason, Some(subject))
}

pub use violation::{
    IsolationViolation, VIOLATION_SUBJECT_MAX_CHARS, ViolationKind, ViolationReason,
    ViolationSubject,
};

/// マウント層の分離違反を監査レコードとして記録する（SEC-4・CORE-1・TASK-41.4・#195）。
///
/// `err.violation` が `MountTarget` / `SharedPropagation` / `RootfsPivot` のときだけ `Mount`
/// レコードを 1 件 `sink` へ渡す（時刻・PID は呼び出し時点）。システムエラー・それ以外の種別は
/// 記録せず `NotApplicable`。`err` は常にそのまま返り、記録の失敗で拒否は覆らない（fail-closed）。
///
/// 本番の `spawn_container` 子プロセス・launcher への配線は未実装（`AuditSink` を fork 後へ渡す設計が
/// 未決定。TASK-29 / TASK-157 系。REPAIR-3）。ファイル永続化は `audit_log::AuditFileWriter`（#839）で実装済み。
///
/// 移行（#1618）: 引数 `container` を `sink` の直前に追加した。記録の `container_id` に載せる検証済みの
/// コンテナ ID で、ID が無い呼び出し側は `None` を渡す（ワイヤーでは null）。記録の `pid` は記録を行った
/// プロセスのもので、違反したプロセスや pid1 ではない。
pub fn audit_mount_violation(
    err: ExecError,
    container: Option<&crate::traits::ContainerId>,
    sink: &dyn crate::audit_log::AuditSink,
) -> crate::audit_log::AuditedRejection<ExecError> {
    let event = err
        .violation
        .as_ref()
        .and_then(IsolationViolation::mount_audit_event);
    match event {
        Some(event) => {
            let delivery = crate::audit_log::mount::deliver(event, container, sink);
            crate::audit_log::AuditedRejection {
                error: err,
                delivery,
            }
        }
        None => crate::audit_log::AuditedRejection::not_applicable(err),
    }
}

/// exec の対象の違反を `ExecTarget` 監査レコードとして記録する（SEC-4・SUP-6・TASK-163 追補・#1465）。
///
/// `err.violation` が種別 `ExecTarget` のときだけ 1 件 `sink` へ渡す。それ以外（マウント層の違反・
/// システムエラー）は `NotApplicable`。`err` は常にそのまま返り、記録の失敗で拒否は覆らない（fail-closed）。
/// プロセス内で `ExecError` を直接扱う呼び出し側向けで、supervisor の通しの入口は
/// [`record_exec_worker_rejection`] を使う。
///
/// 移行（#1618）: 引数 `container` を `sink` の直前に追加した。記録の `container_id` に載せる検証済みの
/// コンテナ ID で、ID が無い呼び出し側は `None` を渡す（ワイヤーでは null）。記録の `pid` は記録を行った
/// プロセスのもので、違反したプロセスや pid1 ではない。
pub fn audit_exec_violation(
    err: ExecError,
    container: Option<&crate::traits::ContainerId>,
    sink: &dyn crate::audit_log::AuditSink,
) -> crate::audit_log::AuditedRejection<ExecError> {
    let event = err
        .violation
        .as_ref()
        .and_then(IsolationViolation::exec_audit_event);
    match event {
        Some(event) => {
            let delivery = crate::audit_log::mount::deliver(event, container, sink);
            crate::audit_log::AuditedRejection {
                error: err,
                delivery,
            }
        }
        None => crate::audit_log::AuditedRejection::not_applicable(err),
    }
}

/// 理由コードだけを持つ呼び出し側（supervisor が worker の結果行を復号した親プロセス）向けに、
/// exec の対象の拒否 `error` を 1 件記録して返す（SEC-4・SUP-6・TASK-163 追補・#1465）。
///
/// `reason` が exec 対象の理由でなければ記録せず `NotApplicable`。時刻と PID は呼び出したプロセスのもの。
/// 記録の成否で `error` は変わらない（fail-closed）。
///
/// 移行（#1618）: 引数 `container` を `sink` の直前に追加した。記録の `container_id` に載せる検証済みの
/// コンテナ ID で、ID が無い呼び出し側は `None` を渡す（ワイヤーでは null）。記録の `pid` は記録を行った
/// プロセスのもので、違反したプロセスや pid1 ではない。
pub fn record_exec_target_rejection<E>(
    error: E,
    reason: ViolationReason,
    container: Option<&crate::traits::ContainerId>,
    sink: &dyn crate::audit_log::AuditSink,
) -> crate::audit_log::AuditedRejection<E> {
    match reason.exec_target_audit_event() {
        Some(event) => {
            let delivery = crate::audit_log::mount::deliver(event, container, sink);
            crate::audit_log::AuditedRejection { error, delivery }
        }
        None => crate::audit_log::AuditedRejection::not_applicable(error),
    }
}

/// 理由コードだけを持つ呼び出し側（supervisor が worker の `err` 行を復号した親プロセス）向けに、worker の経路の
/// 拒否 `error` を 1 件記録して返す（SEC-4・SUP-6・SEC-1）。
///
/// `reason` は `ViolationReason::EXEC_WORKER_REASONS` で引き直した値を渡す。種別 `exec_target` は層 `exec_target`
/// （[`record_exec_target_rejection`] と同じレコード）、種別 `rootfs_pivot`（`rootfs_is_host_root`）は
/// [`audit_mount_violation`] と同じ写像で層 `mount` のパスなしのレコードにする（`ViolationReason::exec_worker_audit_event`）。
/// 一覧外の理由は記録せず `NotApplicable`。時刻と PID は呼び出したプロセスのもの。記録の成否で `error` は
/// 変わらない（fail-closed）。
///
/// 移行（#1618）: 引数 `container` を `sink` の直前に追加した。記録の `container_id` に載せる検証済みの
/// コンテナ ID で、ID が無い呼び出し側は `None` を渡す（ワイヤーでは null）。記録の `pid` は記録を行った
/// プロセスのもので、違反したプロセスや pid1 ではない。
pub fn record_exec_worker_rejection<E>(
    error: E,
    reason: ViolationReason,
    container: Option<&crate::traits::ContainerId>,
    sink: &dyn crate::audit_log::AuditSink,
) -> crate::audit_log::AuditedRejection<E> {
    match reason.exec_worker_audit_event() {
        Some(event) => {
            let delivery = crate::audit_log::mount::deliver(event, container, sink);
            crate::audit_log::AuditedRejection { error, delivery }
        }
        None => crate::audit_log::AuditedRejection::not_applicable(error),
    }
}

/// エントリポイント検証の違反を `Entrypoint` 監査レコードとして記録する（SEC-4・SUP-6・SEC-1・TASK-163 追補・#1595）。
///
/// `err.violation` が種別 `Entrypoint` のときだけ 1 件 `sink` へ渡す。それ以外（マウント層・exec 対象の違反・
/// システムエラー）は `NotApplicable`。`err` は常にそのまま返り、記録の失敗で拒否は覆らない（fail-closed）。
/// `ExecError` を直接扱う launch 側の入口で、理由コードだけを持つ supervisor の親プロセスは
/// [`record_entrypoint_rejection`] を使う。launch 経路（`spawn_container` の子・launcher）への配線は
/// 未実装（#1314。TASK-29 / TASK-157 系。REPAIR-3）。
///
/// 移行（#1618）: 引数 `container` を `sink` の直前に追加した。記録の `container_id` に載せる検証済みの
/// コンテナ ID で、ID が無い呼び出し側は `None` を渡す（ワイヤーでは null）。記録の `pid` は記録を行った
/// プロセスのもので、違反したプロセスや pid1 ではない。
pub fn audit_entrypoint_violation(
    err: ExecError,
    container: Option<&crate::traits::ContainerId>,
    sink: &dyn crate::audit_log::AuditSink,
) -> crate::audit_log::AuditedRejection<ExecError> {
    let event = err
        .violation
        .as_ref()
        .and_then(IsolationViolation::entrypoint_audit_event);
    match event {
        Some(event) => {
            let delivery = crate::audit_log::mount::deliver(event, container, sink);
            crate::audit_log::AuditedRejection {
                error: err,
                delivery,
            }
        }
        None => crate::audit_log::AuditedRejection::not_applicable(err),
    }
}

/// 理由コードだけを持つ呼び出し側（supervisor が worker の結果行を復号した親プロセス）向けに、
/// エントリポイント検証の拒否 `error` を 1 件記録して返す（SEC-4・SUP-6・SEC-1・TASK-163 追補・#1595）。
///
/// `reason` がエントリポイント検証の理由でなければ記録せず `NotApplicable`。時刻と PID は呼び出した
/// プロセスのもの。記録の成否で `error` は変わらない（fail-closed）。
///
/// 移行（#1618）: 引数 `container` を `sink` の直前に追加した。記録の `container_id` に載せる検証済みの
/// コンテナ ID で、ID が無い呼び出し側は `None` を渡す（ワイヤーでは null）。記録の `pid` は記録を行った
/// プロセスのもので、違反したプロセスや pid1 ではない。
pub fn record_entrypoint_rejection<E>(
    error: E,
    reason: ViolationReason,
    container: Option<&crate::traits::ContainerId>,
    sink: &dyn crate::audit_log::AuditSink,
) -> crate::audit_log::AuditedRejection<E> {
    match reason.entrypoint_audit_event() {
        Some(event) => {
            let delivery = crate::audit_log::mount::deliver(event, container, sink);
            crate::audit_log::AuditedRejection { error, delivery }
        }
        None => crate::audit_log::AuditedRejection::not_applicable(error),
    }
}

/// 分離対象の namespace 種別。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Namespace {
    /// PID namespace（次に生成する子が PID 1 になる）。
    Pid,
    /// mount namespace。
    Mount,
    /// UTS namespace（hostname）。
    Uts,
    /// IPC namespace。
    Ipc,
    /// user namespace。
    User,
}

impl Namespace {
    const ALL: [Namespace; 5] = [
        Namespace::Pid,
        Namespace::Mount,
        Namespace::Uts,
        Namespace::Ipc,
        Namespace::User,
    ];

    fn flag(self) -> NsFlag {
        match self {
            Self::Pid => NsFlag::Pid,
            Self::Mount => NsFlag::Mount,
            Self::Uts => NsFlag::Uts,
            Self::Ipc => NsFlag::Ipc,
            Self::User => NsFlag::User,
        }
    }

    fn index(self) -> u8 {
        match self {
            Self::Pid => 0,
            Self::Mount => 1,
            Self::Uts => 2,
            Self::Ipc => 3,
            Self::User => 4,
        }
    }
}

/// [`Namespace`] の集合（生のビット値は公開しない）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NamespaceSet(u8);

impl NamespaceSet {
    /// 空集合。
    pub fn empty() -> Self {
        Self(0)
    }

    /// 5 種すべて。
    pub fn all() -> Self {
        Namespace::ALL
            .iter()
            .fold(Self::empty(), |s, ns| s.with(*ns))
    }

    /// `ns` を加えた集合を返す。
    pub fn with(mut self, ns: Namespace) -> Self {
        self.0 |= 1 << ns.index();
        self
    }

    /// `ns` を除いた集合を返す（[`Self::with`] の対）。
    pub fn without(mut self, ns: Namespace) -> Self {
        self.0 &= !(1 << ns.index());
        self
    }

    /// `ns` を含むか。
    pub fn contains(&self, ns: Namespace) -> bool {
        self.0 & (1 << ns.index()) != 0
    }

    /// 空か。
    pub fn is_empty(&self) -> bool {
        self.0 == 0
    }

    fn flags(&self) -> Vec<NsFlag> {
        Namespace::ALL
            .iter()
            .filter(|ns| self.contains(**ns))
            .map(|ns| ns.flag())
            .collect()
    }
}

/// `HOST_NAME_MAX`（Linux は 64 バイト）。
const HOSTNAME_MAX_LEN: usize = 64;
/// DNS ラベル長の上限。
const HOSTNAME_LABEL_MAX_LEN: usize = 63;

/// 検証済みの hostname。外部入力（将来の OCI `config.json`）由来を想定し、生成は
/// [`Hostname::new`] のみ。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hostname(String);

impl Hostname {
    /// 検証して作る。拒否条件（`InvalidArgument`）: 空・64 バイト超・`[A-Za-z0-9-.]` 以外
    /// （NUL 含む）・空ラベル・63 バイト超ラベル・先頭 / 末尾ハイフンのラベル。
    pub fn new(value: impl Into<String>) -> Result<Self, ExecError> {
        let value = value.into();
        let bad = |msg: &str| {
            ExecError::new(
                ErrorCode::InvalidArgument,
                IsolationStage::Validate,
                format!("invalid hostname: {msg}"),
            )
        };
        if value.is_empty() {
            return Err(bad("must not be empty"));
        }
        if value.len() > HOSTNAME_MAX_LEN {
            return Err(bad("must be at most 64 bytes"));
        }
        if !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
        {
            return Err(bad("must match [A-Za-z0-9-.]"));
        }
        for label in value.split('.') {
            if label.is_empty() || label.len() > HOSTNAME_LABEL_MAX_LEN {
                return Err(bad("labels must be 1 to 63 bytes"));
            }
            if label.starts_with('-') || label.ends_with('-') {
                return Err(bad("labels must not start or end with '-'"));
            }
        }
        Ok(Self(value))
    }

    /// 検証済み文字列。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// `uid_map` / `gid_map` の 1 行（`container_id host_id count`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdMapping {
    /// コンテナ内の先頭 ID。
    pub container_id: u32,
    /// ホスト側の先頭 ID。
    pub host_id: u32,
    /// 写像する ID 数。
    pub count: u32,
}

impl IdMapping {
    /// カーネルが受け付ける書式（改行終端の 1 行）。
    pub fn to_map_line(&self) -> String {
        format!("{} {} {}\n", self.container_id, self.host_id, self.count)
    }

    /// 自 ID をコンテナ内 0 へ写す単一 ID 写像。
    fn single(host_id: u32) -> Self {
        Self {
            container_id: 0,
            host_id,
            count: 1,
        }
    }
}

/// 分離の設定。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IsolationConfig {
    /// 分離する namespace。
    pub namespaces: NamespaceSet,
    /// コンテナの hostname（指定時は `Uts` が必須）。
    pub hostname: Option<Hostname>,
}

/// 失敗した段（ERR-1 の機械可読な文脈）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum IsolationStage {
    /// 設定・前提の検証。
    Validate,
    /// `unshare(2)`。
    Unshare,
    /// `/proc/self/setgroups` への `deny` 書き込み。
    SetGroups,
    /// `/proc/self/uid_map` への書き込み。
    UidMap,
    /// `/proc/self/gid_map` への書き込み。
    GidMap,
    /// `/` の propagation を private にする `mount(2)`。
    MountPrivate,
    /// `sethostname(2)`。
    SetHostname,
    /// procfs のマウント。
    MountProc,
    /// pivot_root の準備（rootfs の検証・自己 bind・rootfs 配下への procfs マウント）。
    PrepareRootfs,
    /// `pivot_root(2)` による rootfs 切替と旧 root の切り離し。
    PivotRoot,
    /// 子プロセスの `fork(2)`。
    Spawn,
    /// rootless の UID/GID 写像の設定（mapper との同期・書き込み・読み戻し。TASK-40.2）。
    UserNamespaceMap,
    /// exec 直前の検証（証跡・エントリポイント・fd・シグナル状態）と `execve(2)`。
    Exec,
    /// 子の終了待ち（`waitpid(2)`）と、期限超過時の `kill(2)`。
    Wait,
    /// rootfs 配下の `dev` への専用 tmpfs のマウントと、基本デバイスノード・default symlink の作成
    /// （`mknodat(2)`・`symlink(2)`。#1653）、`/dev/pts` の devpts のマウントと `/dev/ptmx` の symlink の作成（#1656）。
    CreateDevices,
    /// cgroup 参加ステージ（TASK-32。#832 のステージ列の第 1 段）。
    CgroupJoin,
    /// rlimit 適用ステージ（SUP-12・TASK-169.1・#526。ステージ列の第 2 段。組み込み段）。
    Rlimits,
    /// capability 削減ステージ（TASK-37。#832 のステージ列の第 3 段）。
    CapabilityDrop,
    /// `PR_SET_NO_NEW_PRIVS` ステージ（#833。#832 のステージ列の第 4 段）。
    NoNewPrivs,
    /// Landlock ステージ（TASK-39。#832 のステージ列の第 5 段）。
    Landlock,
    /// seccomp ステージ（TASK-38。#832 のステージ列の第 6 段。#178 で組み込み段）。
    Seccomp,
    /// 稼働中コンテナの pid1 の特定と `setns(2)` による namespace 参加（SUP-6・TASK-163.1）。
    SetNs,
    /// rootfs 配下への tmpfs マウント（SUP-12・TASK-169.2。`--shm-size` / `--tmpfs`）。
    MountTmpfs,
    /// secrets / configs の注入（専用 tmpfs への書き込みと read-only 再マウント。SUP-12・TASK-169.4.2）。
    InjectFiles,
}

/// 実行層の構造化エラー（`code` は `traits::types::ErrorCode` を再利用）。
///
/// 分離違反の試行を拒否した場合は `violation` に構造化された違反記録が入り、システム
/// エラー（syscall 失敗・procfs の読み取り失敗等）では `None`。区別の定義と、記録の保存経路の
/// 現状（ファイル書き込みは実装済み・本番経路への配線は未実装）は [`IsolationViolation`] を参照（SEC-4）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ExecError {
    /// 機械可読な分類。
    pub code: ErrorCode,
    /// 失敗した段。
    pub stage: IsolationStage,
    /// 英語のメッセージ。
    pub message: String,
    /// 分離違反の記録（違反による拒否のときだけ `Some`）。
    pub violation: Option<IsolationViolation>,
}

impl ExecError {
    /// 違反ではない失敗（システムエラー・入力書式エラー）を作る。
    fn new(code: ErrorCode, stage: IsolationStage, message: impl Into<String>) -> Self {
        Self {
            code,
            stage,
            message: message.into(),
            violation: None,
        }
    }

    /// 分離違反の拒否を作る。`code`・`stage`・`message` は理由から決まり、`subject` は
    /// 呼び出し側が渡したパス（パス検証の拒否のときだけ）。
    fn from_violation(reason: ViolationReason, subject: Option<&Path>) -> Self {
        Self {
            code: reason.error_code(),
            stage: reason.stage(),
            message: reason.message().to_string(),
            violation: Some(IsolationViolation::new(reason, subject)),
        }
    }

    /// [`Self::from_violation`] の段を明示する版。理由から決まる段（`ViolationReason::stage`。
    /// 共通のパス理由は `MountProc` に写る）ではなく、呼び出した段（rootfs 切替など）を記録する。
    fn from_violation_at(
        reason: ViolationReason,
        subject: Option<&Path>,
        stage: IsolationStage,
    ) -> Self {
        Self {
            stage,
            ..Self::from_violation(reason, subject)
        }
    }

    /// 失敗した段だけを差し替える（共有ヘルパが返した `MountProc` 段のエラーを、呼び出した段へ
    /// 付け替えるために使う。ERR-1 の段情報を呼び出し元の文脈に合わせる）。
    fn at_stage(mut self, stage: IsolationStage) -> Self {
        self.stage = stage;
        self
    }

    fn from_sys(err: SysError, stage: IsolationStage, what: &str) -> Self {
        let code = errno_to_code(err);
        Self::new(code, stage, format!("{what} failed: {}", describe(err)))
    }

    /// rootless 側のエラーを写す。`code` は保ち、段は `UserNamespaceMap`、message に rootless 側の
    /// 段名を含める（ERR-1 の機械可読な文脈を失わない）。
    fn from_rootless(err: RootlessError) -> Self {
        Self::new(
            err.code,
            IsolationStage::UserNamespaceMap,
            format!("{}: {}", err.stage.as_str(), err.message),
        )
    }

    /// cgroup 参加の失敗（`CgroupError`）を変換する。`code` を保持し、段は `CgroupJoin`、
    /// message に失敗した `CgroupStep` を載せる（TASK-32.4。`stages.rs` の `CgroupJoin` 実装から呼ぶ）。
    fn from_cgroup(err: crate::cgroups::CgroupError) -> Self {
        Self::new(
            err.code,
            IsolationStage::CgroupJoin,
            format!("{:?}: {}", err.step, err.message),
        )
    }

    fn from_io(err: &std::io::Error, stage: IsolationStage, what: &str) -> Self {
        let sys_err = SysError::Os(err.raw_os_error().unwrap_or(0));
        let code = errno_to_code(sys_err);
        Self::new(code, stage, format!("{what} failed: {err}"))
    }
}

impl fmt::Display for ExecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} at {:?}: {}",
            self.code.as_str(),
            self.stage,
            self.message
        )?;
        if let Some(v) = &self.violation {
            write!(
                f,
                " (violation: {}/{}, {})",
                v.kind.as_str(),
                v.reason.as_str(),
                v.behavior_id
            )?;
        }
        Ok(())
    }
}

impl std::error::Error for ExecError {}

fn describe(err: SysError) -> String {
    match err {
        SysError::Unsupported => {
            "not supported by the kernel or the target architecture".to_string()
        }
        SysError::MultiThreaded => {
            "the process is multi-threaded or its thread count is unknown; refusing to fork"
                .to_string()
        }
        SysError::Os(errno) => std::io::Error::from_raw_os_error(errno).to_string(),
    }
}

/// errno を `ErrorCode` に写す。`EPERM`/`EACCES` → `PermissionDenied`、
/// `EINVAL`（例: マルチスレッドからの `CLONE_NEWUSER`）→ `FailedPrecondition`、
/// 対応外 arch → `Unimplemented`、その他 → `Internal`。
fn errno_to_code(err: SysError) -> ErrorCode {
    match err {
        SysError::Unsupported => ErrorCode::Unimplemented,
        SysError::MultiThreaded => ErrorCode::FailedPrecondition,
        SysError::Os(e) if e == sys::EPERM || e == sys::EACCES => ErrorCode::PermissionDenied,
        SysError::Os(e) if e == sys::EINVAL => ErrorCode::FailedPrecondition,
        SysError::Os(_) => ErrorCode::Internal,
    }
}

/// 分離がどの権限モデルで行われたか（[`IsolationReport::privilege`]）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum IsolationPrivilege {
    /// 既定経路（[`isolate`]）。非 root の自 ID をコンテナ内 0 へ写す user namespace 付き。
    RootlessSingleId,
    /// rootful 経路（[`isolate_rootful_host_root`]）。user namespace なしでホスト root 権限を
    /// 保ったまま分離した。
    RootfulHostRoot,
    /// [`isolate_rootless_subordinate`]。非 root の起動ユーザーで、コンテナ root を自 ID、残りを
    /// subuid / subgid 範囲へ写す user namespace 付き（CORE-6・SEC-5）。
    RootlessSubordinateIds,
}

/// [`isolate`] / [`isolate_rootful_host_root`] の成功結果（将来拡張できる構造化された戻り値）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IsolationReport {
    /// どの権限モデルで分離したか。
    pub privilege: IsolationPrivilege,
    /// 分離した namespace。
    pub namespaces: NamespaceSet,
    /// 設定した hostname。
    pub hostname: Option<Hostname>,
    /// 書き込んだ uid 写像（`User` を含む場合のみ）。
    pub uid_mapping: Option<IdMapping>,
    /// 書き込んだ gid 写像（`User` を含む場合のみ）。
    pub gid_mapping: Option<IdMapping>,
}

/// [`mount_proc`] を呼べる状態（新しい PID namespace の PID 1 で、そのスレッドだけが属する
/// 新しい mount namespace にいる）を、PID 1 自身が作って確かめた証跡（CORE-1）。前提を
/// 満たさない呼び出しは fail-closed で拒否し、`ExecError::violation` に違反記録を載せる
/// （SEC-4 の記録経路。ファイル保存は実装済み、本番経路への sink の配線は未実装。REPAIR-3）。
///
/// 生成は [`MountIsolation::establish`] のみで、呼び出し側の申告では作れない。証跡は作成時の
/// mount namespace・PID namespace に束縛され、[`mount_proc`] は呼び出し直前に「PID 1 である
/// こと」「呼び出しスレッドの両 namespace が証跡と一致すること」を再検証する。
///
/// 持ち出し対策として `Clone` を実装せず、`!Send` にしている（mount namespace は
/// `unshare(CLONE_NEWNS)` を呼んだスレッドだけが移るため、別スレッドへ渡すと前提が崩れる）。
/// 別スレッドへは渡せない:
///
/// 下の `compile_fail` doctest は「コンパイルに失敗すること」しか確かめないため、`!Send` 以外の
/// 理由（名前の誤り・モジュールが無い等）のエラーでも通ってしまう。また `exec` モジュールは
/// Linux 限定のため、非 Linux では型が存在せず常に失敗し、この doctest は常に通る
/// （`!Send` の実質的な確認は Linux のみ）。
///
/// ```compile_fail
/// fn assert_send<T: Send>() {}
/// assert_send::<fandhe_container_core::exec::MountIsolation>();
/// ```
///
/// procfs を再マウントした後は `/proc/thread-self` が新しい procfs を指すが、namespace の
/// 識別子（`mnt:[inode]` 等）は procfs に依存しないため、[`prepare_rootfs`]（rootfs 配下への
/// procfs マウント）と [`pivot_root`] は同じ証跡を使い回す。pivot 後の `/proc` は、pivot 前に
/// rootfs 配下へマウント済みのものがそのまま `/proc` になる（pivot 後に新規マウントはしない。
/// rootless では旧 root を切り離した後に完全に見える procfs が無く、新規マウントが拒否されるため）。
#[derive(Debug, PartialEq, Eq)]
pub struct MountIsolation {
    /// 作成した mount namespace（`/proc/thread-self/ns/mnt` のリンク先 `mnt:[inode]`）。
    mnt_ns: String,
    /// 作成時の PID namespace（`/proc/thread-self/ns/pid`）。procfs はマウントした
    /// プロセス自身の PID namespace（`ns/pid`）を映すため、子向けの `pid_for_children`
    /// ではなくこちらを束縛する。
    pid_ns: String,
    /// `!Send`・`!Sync` にするための印（生ポインタは Send / Sync でない）。
    _not_send: std::marker::PhantomData<*const ()>,
}

/// 初期 PID namespace の inode 番号（`include/uapi/linux/nsfs.h` の `enum init_ns_ino` の
/// `PID_NS_INIT_INO`）。初期 namespace の inode は uapi で予約された固定値で、アーキテクチャに
/// 依存しない。
const PID_NS_INIT_INO: u64 = 0xEFFF_FFFC;

/// `/proc/thread-self/ns/pid` のリンク先（`pid:[inode]`）の inode 番号。書式に反すれば `None`。
fn parse_pid_ns_inode(link: &str) -> Option<u64> {
    link.strip_prefix("pid:[")?.strip_suffix(']')?.parse().ok()
}

/// `/proc/self/status` の `NSpid:` 行の末尾要素（最も内側の PID namespace での PID）。
fn nspid_innermost(status: &str) -> Option<u32> {
    status
        .lines()
        .find_map(|l| l.strip_prefix("NSpid:"))
        .and_then(|rest| rest.split_whitespace().last())
        .and_then(|v| v.parse().ok())
}

/// `/proc/self/status` の `Threads:` 行（スレッドグループのスレッド数）。
pub(crate) fn status_threads(status: &str) -> Option<u64> {
    status
        .lines()
        .find_map(|l| l.strip_prefix("Threads:"))
        .and_then(|v| v.trim().parse().ok())
}

/// 適用前後の単一スレッド検査（`Threads: 1`）が読む `status` の取得元（SUP-6・TASK-163.3・#502）。
///
/// 通常は呼び出しプロセスの `/proc/self/status`（[`ProcSelf`](Self::ProcSelf)）。exec 経路では
/// `setns(CLONE_NEWNS)` の後に `/proc` がコンテナ側の procfs になり、自プロセスを `/proc/self` で
/// 解決できないため、`setns` の前に開いた fd を保持して読む（[`PreOpened`](Self::PreOpened)。
/// `cgroups::ExecJoinFds` が `/proc/self/cgroup` を事前に開くのと同じ理由）。
/// 取得元を替えても「適用の前後で `Threads: 1`」という検査自体は弱めない。
#[derive(Debug)]
pub(crate) enum ThreadCountSource {
    /// `/proc/self/status` をそのつど開く（launch 経路。挙動は従来どおり）。
    ProcSelf,
    /// 事前に開いた `/proc/self/status` の fd。開いたプロセス自身のスレッド数を返す。
    PreOpened(std::fs::File),
}

/// `status` 1 回分の読み取り上限（本物は数 KiB。無制限確保を避ける。REPAIR-5 の入力上限方針）。
/// 超過は切り詰めずに読み取り失敗として扱う（`setns::read_bounded_from`）。
const STATUS_READ_LIMIT: u64 = 64 * 1024;

impl ThreadCountSource {
    /// 現在のスレッド数。読めない・パースできない場合は `None`（呼び出し側は適用を拒否する）。
    pub(crate) fn count(&mut self) -> Option<u64> {
        use std::io::{Seek as _, SeekFrom};
        match self {
            ThreadCountSource::ProcSelf => {
                let status = std::fs::read_to_string("/proc/self/status").ok()?;
                status_threads(&status)
            }
            ThreadCountSource::PreOpened(file) => {
                // procfs のファイルは read のたびに再生成される。先頭へ戻して読み直す。
                // 上限を超える内容は切り詰めずに失敗させる（途中で切れた内容から判定しない。fail-closed）。
                file.seek(SeekFrom::Start(0)).ok()?;
                let status =
                    setns::read_bounded_from(std::io::Read::by_ref(file), STATUS_READ_LIMIT)
                        .ok()?;
                status_threads(&status)
            }
        }
    }
}

/// [`MountIsolation::establish`] の前提（副作用の前に判定するテスト可能な純関数）。
/// `pid` は `getpid()`、`status` は `/proc/self/status` の内容、`pid_ns_inode` は呼び出し
/// スレッドの PID namespace の inode 番号。
///
/// - PID が 1 で、`NSpid` の末尾要素も 1
/// - PID namespace が初期 namespace でない（inode が `PID_NS_INIT_INO` でない）。`NSpid` の
///   要素数は参照している procfs の PID namespace を起点にした表示で、その PID namespace 内で
///   マウントされた procfs を見ると入れ子でも 1 段になるため、入れ子の判定には使わない
///   （Codex 指摘）。初期 PID namespace でなければ、その PID 1 がマウントする procfs には
///   その namespace と子孫のプロセスしか見えない
/// - `Threads:` が 1（シングルスレッド）。`unshare(CLONE_NEWNS)` は呼んだスレッドだけを移すため、
///   他のスレッドが古い mount namespace に残り、後続の `pivot_root`・exec（#135・#831）が別
///   スレッドで行われるとホストの procfs・ファイルシステムが見えてしまう
fn check_establish_preconditions(
    pid: u32,
    status: &str,
    pid_ns_inode: u64,
) -> Result<(), ViolationReason> {
    if pid != 1 {
        return Err(ViolationReason::EstablishNotPid1);
    }
    if nspid_innermost(status) != Some(1) {
        return Err(ViolationReason::EstablishNspidNotPid1);
    }
    if pid_ns_inode == PID_NS_INIT_INO {
        return Err(ViolationReason::EstablishNotNestedPidNamespace);
    }
    if status_threads(status) != Some(1) {
        return Err(ViolationReason::EstablishMultiThreaded);
    }
    Ok(())
}

/// 呼び出しスレッドの namespace リンク（`/proc/thread-self/ns/<kind>`）を読む。
///
/// `unshare(CLONE_NEWNS)` はマルチスレッドのプロセスでは呼んだスレッドだけを移すため、
/// スレッドグループの代表を指す `/proc/self` ではなく `/proc/thread-self` を使う。
fn thread_ns_link(kind: &str) -> std::io::Result<String> {
    std::fs::read_link(Path::new("/proc/thread-self/ns").join(kind))
        .map(|l| l.to_string_lossy().into_owned())
}

/// [`MountIsolation::establish`] の mount namespace 判定（テスト可能な純関数）。
/// `unshare(CLONE_NEWNS)` の前後でリンク先が変わっていなければ拒否する。
fn check_fresh_mount_ns(before: &str, after: &str) -> Result<(), ViolationReason> {
    if before == after {
        return Err(ViolationReason::EstablishMountNamespaceNotFresh);
    }
    Ok(())
}

/// [`mount_proc`] 直前の証跡の再検証（テスト可能な純関数）。`pid` は `getpid()`、
/// `mnt_ns` / `pid_ns` は呼び出しスレッドの現在のリンク先。
fn check_evidence(
    evidence: &MountIsolation,
    pid: u32,
    mnt_ns: &str,
    pid_ns: &str,
) -> Result<(), ViolationReason> {
    if pid != 1 {
        return Err(ViolationReason::EvidenceCallerNotPid1);
    }
    if mnt_ns != evidence.mnt_ns {
        return Err(ViolationReason::EvidenceMountNamespaceMismatch);
    }
    if pid_ns != evidence.pid_ns {
        return Err(ViolationReason::EvidencePidNamespaceMismatch);
    }
    Ok(())
}

impl MountIsolation {
    /// 新しい PID namespace の PID 1 が、自分だけの mount namespace を作って証跡を得る。
    ///
    /// 手順（前提検証はすべて副作用の前に行う）:
    ///
    /// 1. PID が 1（`getpid()` と `NSpid` の末尾要素の両方）で、PID namespace が初期
    ///    namespace でなく（`ns/pid` の inode で判定）、かつシングルスレッド（`Threads: 1`）。
    ///    満たさなければ副作用なしで `FailedPrecondition`
    ///    （判定は `check_establish_preconditions`）
    /// 2. 呼び出しスレッドを `unshare(CLONE_NEWNS)` で新しい mount namespace へ移し、`/` を
    ///    再帰 private にする（コピーされたマウントの shared peer から切り離し、以後のマウントを
    ///    外へ伝播させない）
    /// 3. `unshare` の前後で `/proc/thread-self/ns/mnt` が変わったことを確かめ、作成直後の
    ///    mount namespace と PID namespace を証跡に記録する
    ///
    /// この mount namespace の所属は作成直後は呼び出しスレッドだけであり、他プロセスとの
    /// 共有がないことを他プロセスの情報（`/proc/1/ns/mnt` 等）を読まずに自分で保証する。
    /// rootless でも user namespace 内の CAP_SYS_ADMIN で実行でき、比較を省く分岐は持たない。
    ///
    /// 手順 2 以降の失敗は namespace を戻せない（モジュール doc の「失敗時はプロセスを破棄」の
    /// 契約に従う）。
    ///
    /// **スレッド数の確認に競合がない理由**: `Threads: 1` のとき、プロセス内のスレッドは
    /// establish を実行中の呼び出しスレッドだけであり、スレッドを生成できる主体は他に
    /// 存在しない（スレッドは同じプロセスのスレッドからしか生成されない）。したがって確認から
    /// `unshare(CLONE_NEWNS)` までの間に古い mount namespace に残るスレッドは生じず、以後に
    /// 生成するスレッドは新しい mount namespace を引き継ぐ。
    ///
    /// **同一スレッドの契約**: 返った証跡は同じスレッドで [`mount_proc`] に渡し、以後の
    /// [`prepare_rootfs`]・[`pivot_root`]（#135）・exec（#831）も同じスレッドで行う。新しい mount namespace に
    /// 移るのは呼んだスレッドだけのため、前提としてシングルスレッドであることを確かめている
    /// （establish 後に作ったスレッドは新しい mount namespace を引き継ぐ）。
    pub fn establish() -> Result<Self, ExecError> {
        let fail = |msg: &str| {
            ExecError::new(
                ErrorCode::FailedPrecondition,
                IsolationStage::MountProc,
                msg,
            )
        };
        let violation = |r: ViolationReason| ExecError::from_violation(r, None);
        let pid = std::process::id();
        if pid != 1 {
            // /proc を読む前に拒否する（PID 1 でないことは getpid だけで確定する）。
            return Err(violation(ViolationReason::EstablishNotPid1));
        }
        let status = std::fs::read_to_string("/proc/self/status")
            .map_err(|_| fail("cannot read /proc/self/status to verify the PID namespace"))?;
        let pid_ns_inode = thread_ns_link("pid")
            .ok()
            .as_deref()
            .and_then(parse_pid_ns_inode)
            .ok_or_else(|| fail("cannot read or parse /proc/thread-self/ns/pid"))?;
        check_establish_preconditions(pid, &status, pid_ns_inode).map_err(violation)?;
        let before =
            thread_ns_link("mnt").map_err(|_| fail("cannot read /proc/thread-self/ns/mnt"))?;
        sys::unshare_namespaces(&[NsFlag::Mount])
            .map_err(|e| ExecError::from_sys(e, IsolationStage::Unshare, "unshare(CLONE_NEWNS)"))?;
        sys::mount_root_private_recursive().map_err(|e| {
            ExecError::from_sys(e, IsolationStage::MountPrivate, "mount(MS_PRIVATE)")
        })?;
        let mnt_ns =
            thread_ns_link("mnt").map_err(|_| fail("cannot read /proc/thread-self/ns/mnt"))?;
        check_fresh_mount_ns(&before, &mnt_ns).map_err(violation)?;
        let pid_ns =
            thread_ns_link("pid").map_err(|_| fail("cannot read /proc/thread-self/ns/pid"))?;
        Ok(Self {
            mnt_ns,
            pid_ns,
            _not_send: std::marker::PhantomData,
        })
    }

    /// 呼び出し元の現在の状態（PID・スレッドの mount / PID namespace）が証跡と一致するか。
    ///
    /// `stage` は失敗を記録する段（`mount_proc` は `MountProc`、rootfs 切替は `PrepareRootfs` /
    /// `PivotRoot`）。
    fn verify_caller(&self, stage: IsolationStage) -> Result<(), ExecError> {
        let fail = |msg: &str| ExecError::new(ErrorCode::FailedPrecondition, stage, msg);
        let mnt_ns =
            thread_ns_link("mnt").map_err(|_| fail("cannot read /proc/thread-self/ns/mnt"))?;
        let pid_ns =
            thread_ns_link("pid").map_err(|_| fail("cannot read /proc/thread-self/ns/pid"))?;
        check_evidence(self, std::process::id(), &mnt_ns, &pid_ns)
            .map_err(|r| ExecError::from_violation_at(r, None, stage))?;
        // getpid に加え、procfs 側の NSpid 末尾も 1 であることを確かめる（procfs を再マウント
        // した後も NSpid の末尾は最も内側の namespace の PID）。
        let status = std::fs::read_to_string("/proc/self/status")
            .map_err(|_| fail("cannot read /proc/self/status to verify the PID"))?;
        if nspid_innermost(&status) != Some(1) {
            return Err(ExecError::from_violation_at(
                ViolationReason::EvidenceNspidNotPid1,
                None,
                stage,
            ));
        }
        Ok(())
    }
}

/// 既定経路（rootless）の検証済み計画。[`plan`] だけが作り、[`isolate`] だけが受け取る。
///
/// user namespace を必ず含み、非 root の自 euid / egid をコンテナ内 0 へ写す単一 ID 写像を
/// 持つ（SEC-5。subuid 範囲の写像は [`plan_rootless_subordinate`]〔TASK-40.2〕が扱う）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IsolationPlan {
    namespaces: NamespaceSet,
    hostname: Option<Hostname>,
    uid_mapping: IdMapping,
    gid_mapping: IdMapping,
}

/// rootful 経路の検証済み計画。[`plan_rootful_host_root`] だけが作り、
/// [`isolate_rootful_host_root`] だけが受け取る。
///
/// **権限条件**: sudo 等で euid 0 として起動し、user namespace を作らずに**ホストの root 権限を
/// 保ったまま**分離する。コンテナ内 root はホスト root そのものであり、SEC-5（非 root 起動時に
/// コンテナ内 root をホストの非特権 UID へ写す）の保護は受けない。
///
/// **用途**: CORE-7・CORE-9 の rootful 分離（spec 上、dev-box02 の PoC-14・15・17 で実機実証済みの
/// 構成）。root 起動でもコンテナ内 root を非特権 UID へ写す構成は未実装（TASK-40.2 の
/// [`plan_rootless_subordinate`] は非 root 起動に限る）で、それまでの暫定経路ではなく明示的に選ぶ別経路として分けている。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootfulHostRootPlan {
    namespaces: NamespaceSet,
    hostname: Option<Hostname>,
}

/// 既定・rootful に共通する設定の検証（副作用なしの純関数）。
///
/// - namespace が空、または hostname 指定なのに `Uts` が無い場合は `InvalidArgument`
///   （ホストの hostname を書き換える経路を作らない）
/// - `Pid` を含み `Mount` を含まない場合は `InvalidArgument`（PID 1 が外側と mount
///   namespace を共有した状態から始まる構成を作らない。[`MountIsolation::establish`] が
///   PID 1 自身で mount namespace を分けることとの二重の防御）
fn validate_common(config: &IsolationConfig) -> Result<(), ExecError> {
    let violation = |r: ViolationReason| Err(ExecError::from_violation(r, None));
    if config.namespaces.is_empty() {
        return violation(ViolationReason::NoNamespaces);
    }
    if config.hostname.is_some() && !config.namespaces.contains(Namespace::Uts) {
        return violation(ViolationReason::HostnameWithoutUts);
    }
    if config.namespaces.contains(Namespace::Pid) && !config.namespaces.contains(Namespace::Mount) {
        return violation(ViolationReason::PidWithoutMount);
    }
    Ok(())
}

/// [`plan`] の本体（euid / egid を引数に取りテスト可能にした純関数）。
fn plan_for(config: &IsolationConfig, euid: u32, egid: u32) -> Result<IsolationPlan, ExecError> {
    validate_common(config)?;
    if !config.namespaces.contains(Namespace::User) {
        return Err(ExecError::from_violation(
            ViolationReason::UserNamespaceRequired,
            None,
        ));
    }
    if euid == 0 || egid == 0 {
        return Err(ExecError::from_violation(
            ViolationReason::HostRootIdentityMapping,
            None,
        ));
    }
    Ok(IsolationPlan {
        namespaces: config.namespaces,
        hostname: config.hostname.clone(),
        uid_mapping: IdMapping::single(euid),
        gid_mapping: IdMapping::single(egid),
    })
}

/// [`plan_rootful_host_root`] の本体（euid を引数に取りテスト可能にした純関数）。
fn plan_rootful_for(config: &IsolationConfig, euid: u32) -> Result<RootfulHostRootPlan, ExecError> {
    validate_common(config)?;
    if config.namespaces.contains(Namespace::User) {
        return Err(ExecError::from_violation(
            ViolationReason::RootfulWithUserNamespace,
            None,
        ));
    }
    if euid != 0 {
        return Err(ExecError::from_violation(
            ViolationReason::RootfulRequiresRoot,
            None,
        ));
    }
    Ok(RootfulHostRootPlan {
        namespaces: config.namespaces,
        hostname: config.hostname.clone(),
    })
}

/// 既定経路の計画を作る（副作用なし）。拒否条件は共通検証（空・hostname に Uts なし・Pid に
/// Mount なし）に加え、`User` を含まない場合は `InvalidArgument`、euid / egid が 0 の場合は
/// `FailedPrecondition`（SEC-5）。
pub fn plan(config: &IsolationConfig) -> Result<IsolationPlan, ExecError> {
    plan_for(config, sys::effective_uid(), sys::effective_gid())
}

/// rootful 経路の計画を作る（副作用なし）。用途と権限条件は [`RootfulHostRootPlan`] を参照。
/// 共通検証に加え、`User` を含む場合は `InvalidArgument`、euid が 0 でない場合は
/// `FailedPrecondition`。
pub fn plan_rootful_host_root(config: &IsolationConfig) -> Result<RootfulHostRootPlan, ExecError> {
    plan_rootful_for(config, sys::effective_uid())
}

/// `/proc/self/<name>` へ内容を 1 回の write で書く（カーネルは map を 1 回しか受け付けない）。
fn write_proc_self(name: &str, content: &str, stage: IsolationStage) -> Result<(), ExecError> {
    let path = Path::new("/proc/self").join(name);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .map_err(|e| ExecError::from_io(&e, stage, name))?;
    file.write_all(content.as_bytes())
        .map_err(|e| ExecError::from_io(&e, stage, name))
}

/// 既定経路の計画に従い、呼び出しプロセスを namespace 分離する（CORE-1・SEC-5）。
///
/// 処理順: 実行 ID の再検証 → `unshare` を全フラグで 1 回 → `setgroups` deny・`uid_map`・
/// `gid_map` → （`Mount`）`/` を再帰 private 化 → （`Uts` かつ hostname）`sethostname`。
/// 契約はモジュール doc（シングルスレッド・PID 1 は次の子・失敗時はプロセス破棄）を参照。
pub fn isolate(plan: &IsolationPlan) -> Result<IsolationReport, ExecError> {
    // unshare 後の euid / egid は overflow id になるため、先に取得する。計画作成後に
    // setuid 等で ID が変わっていれば写像がずれるため、副作用の前に拒否する。
    let (euid, egid) = (sys::effective_uid(), sys::effective_gid());
    if euid != plan.uid_mapping.host_id || egid != plan.gid_mapping.host_id {
        return Err(ExecError::from_violation(
            ViolationReason::IdentityChanged,
            None,
        ));
    }
    unshare_and_configure(
        plan.namespaces,
        plan.hostname.as_ref(),
        Some((plan.uid_mapping, plan.gid_mapping)),
    )?;
    Ok(IsolationReport {
        privilege: IsolationPrivilege::RootlessSingleId,
        namespaces: plan.namespaces,
        hostname: plan.hostname.clone(),
        uid_mapping: Some(plan.uid_mapping),
        gid_mapping: Some(plan.gid_mapping),
    })
}

/// rootful 経路の計画に従い、ホスト root 権限を保ったまま namespace 分離する（CORE-1・
/// CORE-7・CORE-9）。用途と権限条件は [`RootfulHostRootPlan`] を参照。
///
/// 処理順: euid 0 の再検証 → `unshare` を全フラグで 1 回 → （`Mount`）`/` を再帰 private 化
/// → （`Uts` かつ hostname）`sethostname`。user namespace は作らない。
pub fn isolate_rootful_host_root(plan: &RootfulHostRootPlan) -> Result<IsolationReport, ExecError> {
    if sys::effective_uid() != 0 {
        return Err(ExecError::from_violation(
            ViolationReason::RootfulRequiresRoot,
            None,
        ));
    }
    unshare_and_configure(plan.namespaces, plan.hostname.as_ref(), None)?;
    Ok(IsolationReport {
        privilege: IsolationPrivilege::RootfulHostRoot,
        namespaces: plan.namespaces,
        hostname: plan.hostname.clone(),
        uid_mapping: None,
        gid_mapping: None,
    })
}

/// 範囲写像付き rootless 経路の検証済み計画。[`plan_rootless_subordinate`] だけが作り、
/// [`isolate_rootless_subordinate`] だけが受け取る（CORE-6・SEC-5・TASK-40.2）。
///
/// user namespace を必ず含み、非 root の起動ユーザー（euid / egid）がコンテナ内 0 に写る
/// `/etc/subuid`・`/etc/subgid` 由来の範囲写像を持つ。ホスト root 起動・コンテナ 0 が起動ユーザー以外へ
/// 写る構成は計画の段階で拒否する。フィールドは非公開（検証を経ない組み立てを防ぐ）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubordinateIsolationPlan {
    namespaces: NamespaceSet,
    hostname: Option<Hostname>,
    uid: IdMapSet,
    gid: IdMapSet,
    writer: IdMapWriter,
    timeout: Duration,
    euid: u32,
    egid: u32,
}

/// [`isolate_rootless_subordinate`] の成功結果。[`IsolationReport`] は拡張できない型のため、
/// 別の型で包む（既存 API を壊さない）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootlessIsolationReport {
    /// 分離の結果（`privilege` は `RootlessSubordinateIds`。`uid_mapping` / `gid_mapping` はコンテナ 0 の行）。
    pub isolation: IsolationReport,
    /// 書き込み・読み戻し検証が済んだ UID/GID 写像の全体。
    pub id_maps: IdMapReport,
}

/// mapper の終了を待つ上限（応答受領後なので短い。REPAIR-5）。
const MAPPER_REAP_TIMEOUT: Duration = Duration::from_secs(5);

/// [`plan_rootless_subordinate`] の本体（euid / egid を引数に取りテスト可能にした純関数）。
///
/// 拒否条件: 共通検証（[`validate_common`]）・`User` 無し（`UserNamespaceRequired`）・euid / egid が 0
/// （`HostRootIdentityMapping`）・コンテナ 0 が起動ユーザー以外へ写る（`InvalidArgument`。
/// `rootless_mapping` の形に限る fail-closed）・`timeout` が `1..=60` 秒の外（`InvalidArgument`）。
fn plan_subordinate_for(
    config: &IsolationConfig,
    uid: IdMapSet,
    gid: IdMapSet,
    writer: IdMapWriter,
    timeout: Duration,
    euid: u32,
    egid: u32,
) -> Result<SubordinateIsolationPlan, ExecError> {
    validate_common(config)?;
    if !config.namespaces.contains(Namespace::User) {
        return Err(ExecError::from_violation(
            ViolationReason::UserNamespaceRequired,
            None,
        ));
    }
    if euid == 0 || egid == 0 {
        return Err(ExecError::from_violation(
            ViolationReason::HostRootIdentityMapping,
            None,
        ));
    }
    let invalid =
        |msg: &str| ExecError::new(ErrorCode::InvalidArgument, IsolationStage::Validate, msg);
    if uid.host_id_of(0) != Some(euid) || gid.host_id_of(0) != Some(egid) {
        return Err(invalid(
            "container root must map to the launching user's euid/egid",
        ));
    }
    if timeout < Duration::from_secs(1) || timeout > Duration::from_secs(60) {
        return Err(invalid("id map timeout must be within 1..=60 seconds"));
    }
    // 非特権（euid != 0。上で保証済み）の Direct は自 euid/egid への単一行のみ書ける。
    // 違反を mapper 側の拒否（CLONE_NEWUSER 実行後）まで持ち越さず、副作用前に弾く。
    if matches!(writer, IdMapWriter::Direct)
        && crate::rootless::check_direct_allowed(&uid, &gid, euid, egid).is_err()
    {
        return Err(invalid(
            "direct id map writer allows only a single mapping to the caller's own euid/egid; use the helper writer",
        ));
    }
    Ok(SubordinateIsolationPlan {
        namespaces: config.namespaces,
        hostname: config.hostname.clone(),
        uid,
        gid,
        writer,
        timeout,
        euid,
        egid,
    })
}

/// 範囲写像付き rootless 経路の計画を作る（副作用なし。CORE-6・SEC-5・TASK-40.2）。
///
/// `uid` / `gid` は [`crate::rootless::rootless_mapping`] 等で作った検証済み写像、`writer` は
/// [`IdMapWriter::Direct`]（自 ID の単一行のみ）か [`IdMapWriter::Helper`]（範囲写像）。
/// 拒否条件: 共通検証・`User` 必須・非 root 起動・コンテナ 0 は起動ユーザーへ写すこと・
/// `timeout` は `1..=60` 秒。
pub fn plan_rootless_subordinate(
    config: &IsolationConfig,
    uid: IdMapSet,
    gid: IdMapSet,
    writer: IdMapWriter,
    timeout: Duration,
) -> Result<SubordinateIsolationPlan, ExecError> {
    plan_subordinate_for(
        config,
        uid,
        gid,
        writer,
        timeout,
        sys::effective_uid(),
        sys::effective_gid(),
    )
}

/// 同期チャネルの入出力エラーを写す（タイムアウトは `Timeout`、その他は `Internal`）。
fn sync_io_error(e: &std::io::Error, what: &str) -> ExecError {
    let code = match e.kind() {
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => ErrorCode::Timeout,
        _ => ErrorCode::Internal,
    };
    ExecError::new(
        code,
        IsolationStage::UserNamespaceMap,
        format!("{what} failed: {e}"),
    )
}

/// 範囲写像付き rootless 経路の計画に従い、呼び出しプロセスを namespace 分離する（CORE-6・SEC-5）。
///
/// 処理順: 実行 ID の再検証 → 同期チャネルと mapper の fork（外側の user namespace に残る）→
/// 呼び出し元が `CLONE_NEWUSER` → mapper へ go → mapper が親 pid の `uid_map` / `gid_map` を書く
/// （`newuidmap` / `newgidmap` 経由は setuid ヘルパーで root 権限を代替）→ 応答（固定 3 バイト）を
/// 上限付き・タイムアウト付きで受領 → 自プロセスの写像を読み戻して計画と照合 → user namespace 内で
/// uid / gid が 0 であることを確認 → 残りの namespace を分離（[`isolate`] と同じ `MS_PRIVATE`・hostname）。
///
/// 契約:
/// - シングルスレッドから呼ぶこと（mapper の fork と `CLONE_NEWUSER` の制約。マルチスレッドは
///   副作用なしで `FailedPrecondition`）
/// - 失敗したプロセスは破棄すること（写像は write-once で戻せない。[`isolate`] と同じ）。mapper は
///   どの失敗経路でも kill して回収する（ゾンビを残さない）
/// - mapper は親の死を EOF で検知できない（fork で fd が複製され、子側から安全に閉じられない）ため、
///   go の待ちは read タイムアウト（`timeout`）と `parent_id()` の再確認で止める（REPAIR-5）
/// - pidfd は採らない（書き込み先は応答待ちでブロックしている親で、pid は解放されない。
///   詳細は [`crate::rootless`] の doc）
pub fn isolate_rootless_subordinate(
    plan: &SubordinateIsolationPlan,
) -> Result<RootlessIsolationReport, ExecError> {
    let (euid, egid) = (sys::effective_uid(), sys::effective_gid());
    if euid != plan.euid || egid != plan.egid {
        return Err(ExecError::from_violation(
            ViolationReason::IdentityChanged,
            None,
        ));
    }
    let (mut parent_sock, mapper_sock) = std::os::unix::net::UnixStream::pair()
        .map_err(|e| ExecError::from_io(&e, IsolationStage::UserNamespaceMap, "socketpair"))?;
    let parent_pid = std::process::id();
    let (uid, gid, writer, timeout) = (
        plan.uid.clone(),
        plan.gid.clone(),
        plan.writer.clone(),
        plan.timeout,
    );
    let mapper_pid = sys::fork_single_threaded(
        move || rootless::run_id_map_mapper(parent_pid, mapper_sock, &uid, &gid, &writer, timeout),
        EXIT_SETUP_FAILED,
    )
    .map_err(|e| ExecError::from_sys(e, IsolationStage::Spawn, "fork"))?;
    let mapper = ContainerChild::new(mapper_pid);

    let handshake = rootless_handshake(&mut parent_sock, plan);
    drop(parent_sock);
    match handshake {
        Ok(()) => {
            mapper.wait_timeout(MAPPER_REAP_TIMEOUT)?;
        }
        Err(e) => {
            // 失敗しても mapper を必ず回収する。回収自体の失敗は元のエラーを優先する。
            let _ = mapper.kill_and_reap(MAPPER_REAP_TIMEOUT);
            return Err(e);
        }
    }

    let rest = plan.namespaces.without(Namespace::User);
    if !rest.is_empty() {
        unshare_and_configure(rest, plan.hostname.as_ref(), None)?;
    }
    let container_root = |host_id| IdMapping {
        container_id: 0,
        host_id,
        count: 1,
    };
    Ok(RootlessIsolationReport {
        isolation: IsolationReport {
            privilege: IsolationPrivilege::RootlessSubordinateIds,
            namespaces: plan.namespaces,
            hostname: plan.hostname.clone(),
            uid_mapping: Some(container_root(plan.euid)),
            gid_mapping: Some(container_root(plan.egid)),
        },
        id_maps: IdMapReport {
            uid: plan.uid.clone(),
            gid: plan.gid.clone(),
            writer: match plan.writer {
                IdMapWriter::Direct => WriterKind::Direct,
                IdMapWriter::Helper(_) => WriterKind::Helper,
            },
        },
    })
}

/// [`isolate_rootless_subordinate`] の親側（`unshare` → go → 応答 → 自己検証）。
/// 失敗時の mapper 回収は呼び出し元が行う。
fn rootless_handshake(
    sock: &mut std::os::unix::net::UnixStream,
    plan: &SubordinateIsolationPlan,
) -> Result<(), ExecError> {
    use std::io::Read as _;

    rootless::unshare_user_namespace().map_err(ExecError::from_rootless)?;
    sock.set_write_timeout(Some(plan.timeout))
        .map_err(|e| sync_io_error(&e, "set write timeout"))?;
    sock.write_all(&[rootless::MAPPER_GO])
        .map_err(|e| sync_io_error(&e, "send go signal to the id map mapper"))?;
    // Helper は uid / gid で 2 回実行するため、応答待ちの上限は 2 × timeout + 1s。
    sock.set_read_timeout(Some(plan.timeout * 2 + Duration::from_secs(1)))
        .map_err(|e| sync_io_error(&e, "set read timeout"))?;
    let mut buf = [0u8; rootless::MAPPER_REPLY_LEN];
    sock.read_exact(&mut buf)
        .map_err(|e| sync_io_error(&e, "read the id map mapper reply"))?;
    match MapperReply::decode(&buf).map_err(ExecError::from_rootless)? {
        MapperReply::Ok => {}
        MapperReply::Failed { code, stage } => {
            return Err(ExecError::new(
                code,
                IsolationStage::UserNamespaceMap,
                format!("id map mapper failed at {}", stage.as_str()),
            ));
        }
    }
    // 写像の照合は mapper 側（親の user namespace の外側）が `apply_id_maps_to` の読み戻しで済ませ、
    // Ok 応答はその検証通過を意味する。分離先の namespace から /proc/self/{uid,gid}_map を読むと
    // lower ID が読み手基準（opener の user namespace）で表示され、外側の ID と直接比較できない
    // ため、ここでは比較せず、namespace 内で uid / gid が 0 になったことだけを確かめる。
    if sys::effective_uid() != 0 || sys::effective_gid() != 0 {
        return Err(ExecError::new(
            ErrorCode::Internal,
            IsolationStage::UserNamespaceMap,
            "uid/gid inside the user namespace is not 0 after mapping",
        ));
    }
    Ok(())
}

/// 両経路に共通する副作用部（検証済みの計画からだけ呼ぶ）。
fn unshare_and_configure(
    namespaces: NamespaceSet,
    hostname: Option<&Hostname>,
    mappings: Option<(IdMapping, IdMapping)>,
) -> Result<(), ExecError> {
    sys::unshare_namespaces(&namespaces.flags())
        .map_err(|e| ExecError::from_sys(e, IsolationStage::Unshare, "unshare"))?;

    if let Some((uid, gid)) = mappings {
        // 非特権の gid_map 書き込みには setgroups の deny が先に必要。
        write_proc_self("setgroups", "deny", IsolationStage::SetGroups)?;
        write_proc_self("uid_map", &uid.to_map_line(), IsolationStage::UidMap)?;
        write_proc_self("gid_map", &gid.to_map_line(), IsolationStage::GidMap)?;
    }

    if namespaces.contains(Namespace::Mount) {
        sys::mount_root_private_recursive().map_err(|e| {
            ExecError::from_sys(e, IsolationStage::MountPrivate, "mount(MS_PRIVATE)")
        })?;
    }

    if let Some(hostname) = hostname {
        sys::set_hostname(hostname.as_str().as_bytes())
            .map_err(|e| ExecError::from_sys(e, IsolationStage::SetHostname, "sethostname"))?;
    }
    Ok(())
}

/// `rootfs` 配下の `target` に procfs をマウントする。新しい PID namespace の PID 1 側で呼ぶ。
///
/// pivot_root を行う場合は、pivot 前に [`prepare_rootfs`] が rootfs 配下へ procfs をマウントする
/// ため、通常は本関数を pivot の前後で追加に呼ぶ必要はない（pivot 後に `mount_proc(&iso, "/",
/// "/proc")` を呼ぶことは、pivot 前に rootfs/proc をマウント済みなら可能だが、rootless では
/// 旧 root を切り離した後の新規 procfs マウントは拒否され得る）。
///
/// マウント前に次をすべて検証し、1 つでも満たさなければ副作用なしで拒否する（fail-closed。
/// security.md「rootfs の外へ書き込める経路を作らない」）。
///
/// - 呼び出し側が [`MountIsolation::establish`] で得た証跡を提示し、呼び出し直前の状態が
///   証跡と一致する（PID 1 であること・呼び出しスレッドの mount / PID namespace が作成時と
///   同じこと）。証跡を受け取った親・PID 1 が fork した子・別スレッドからの呼び出しは拒否する
/// - `rootfs` / `target` は絶対パスで NUL・`..` を含まず、`target` は `rootfs` より下の専用ディレクトリ
///   （`target == rootfs` は拒否）
/// - `/` から `rootfs` までを `openat(O_PATH|O_DIRECTORY|O_NOFOLLOW)` で 1 要素ずつ辿って rootfs を
///   fd で固定し（rootfs 自体・祖先に symlink・非ディレクトリがあれば拒否）、続けて**その rootfs の
///   fd を起点に** `target` の残りの要素を同様に辿る（`open_dir_beneath`）。パスを別の操作で
///   解決し直さないため、検証後に祖先を改名・差し替えられても、固定した rootfs の外へは出ない
///   （TOCTOU の防止）。マウントは `/proc/thread-self/fd/N` 経由で同じ実体に対して行う。
///   O_PATH のため祖先に要るのは search（実行）権限だけで、user namespace 内から読み取り不可・
///   実行可のホスト側ディレクトリを辿れる
/// - 固定した fd が属するマウント（`/proc/thread-self/fdinfo/N` の `mnt_id`）の propagation が
///   `shared` でない（mount namespace 分離済みで `MS_PRIVATE` 化されていること。shared の
///   ままではマウントがホストへ伝播する）。パス文字列ではなく fd で判定し、検証と実マウント
///   の対象を一致させる
pub fn mount_proc(
    isolation: &MountIsolation,
    rootfs: &Path,
    target: &Path,
) -> Result<(), ExecError> {
    isolation.verify_caller(IsolationStage::MountProc)?;
    mount_proc_verified(rootfs, target)
}

/// [`mount_proc`] の証跡検証後の本体（パス検証 → fd 固定 → propagation 検査 → マウント）。
/// 証跡を取らないため、単体テストは証跡を偽造せずにパス検証を直接確かめられる（最終段の
/// `mount(2)` はテストビルドでは dry-run）。
fn mount_proc_verified(rootfs: &Path, target: &Path) -> Result<(), ExecError> {
    let violation = |r: ViolationReason, p: &Path| ExecError::from_violation(r, Some(p));
    for p in [rootfs, target] {
        if !p.is_absolute() {
            return Err(violation(ViolationReason::PathNotAbsolute, p));
        }
        if p.as_os_str().as_bytes().contains(&0) {
            return Err(violation(ViolationReason::PathContainsNul, p));
        }
        if p.components().any(|c| matches!(c, Component::ParentDir)) {
            return Err(violation(ViolationReason::PathParentComponent, p));
        }
    }
    let rel = target
        .strip_prefix(rootfs)
        .map_err(|_| violation(ViolationReason::TargetOutsideRootfs, target))?;
    // rootfs 自体をマウント先にすると rootfs 全体を procfs で覆えるため、専用の下位ディレクトリを要求する。
    let names: Vec<&OsStr> = rel
        .components()
        .filter_map(|c| match c {
            Component::Normal(n) => Some(n),
            _ => None,
        })
        .collect();
    if names.is_empty() {
        return Err(violation(ViolationReason::TargetIsRootfs, target));
    }
    // `/` から rootfs まで 1 要素ずつ開いて rootfs を fd で固定し、その fd を起点に target を
    // 辿る（検証と使用を同じ解決で行い、別の操作でパスを解決し直さない = TOCTOU の防止）。
    // 以後の判定・マウントはこの fd 経由でのみ行う。
    let dir = open_dir_beneath(rootfs, &names)?;
    mount_proc_at_dir(&dir, target, IsolationStage::MountProc)
}

/// 固定済みの `dir`（マウント先ディレクトリの O_PATH fd）へ procfs をマウントする共通の後半
/// （propagation 検査 → 移動検査 → `/proc/thread-self/fd/N` 経由のマウント）。
///
/// [`mount_proc_verified`] と `rootfs` の `prepare_rootfs`（新しい mount top 起点で開いた
/// `rootfs/proc`）が共有する。`target` は fd が今指しているはずのパス（移動検査と違反記録の
/// 対象。呼び出し側が渡したパスのみ）、`stage` は失敗を記録する段。
fn mount_proc_at_dir(dir: &OwnedFd, target: &Path, stage: IsolationStage) -> Result<(), ExecError> {
    let violation = |r: ViolationReason, p: &Path| ExecError::from_violation_at(r, Some(p), stage);
    if mount_is_shared(dir, stage)? {
        return Err(violation(ViolationReason::TargetOnSharedMount, target));
    }
    // fd 固定後に別プロセスがマウント先（または祖先）を改名・移動していないかを、マウント
    // 直前に fd の現在の位置で確かめる（Codex 指摘）。移動・削除されていれば拒否する。
    // 残る窓（この確認から mount(2) まで）で移動された場合も、マウントは establish が作った
    // 呼び出しスレッド専用の mount namespace（shared でないことを上で確認済み）に閉じ、
    // ホストや外側の namespace へは伝播しない。rootfs の外に残るマウントは #135 の
    // pivot_root で旧ルートごと切り離される。
    if !fd_still_at(dir, target) {
        return Err(violation(ViolationReason::TargetMoved, target));
    }
    // fd が指す実体へマウントする（`/proc/thread-self/fd/N` は fd の dentry へ解決される）。
    // `establish` は呼び出しスレッドだけを新しい mount namespace へ移すため、パス解決・
    // mountinfo の参照はスレッドグループの代表（`/proc/self`）ではなく呼び出しスレッドで行う。
    // 数値だけから組む文字列のため NUL は含まれ得ない（失敗は内部エラー扱い）。
    let c_target =
        CString::new(format!("/proc/thread-self/fd/{}", dir.as_raw_fd())).map_err(|_| {
            ExecError::new(
                ErrorCode::Internal,
                stage,
                "failed to build the fd path of the proc mount target",
            )
        })?;
    mount_proc_syscall(&c_target).map_err(|e| ExecError::from_sys(e, stage, "mount(proc)"))
}

/// [`mount_proc`] の最終段（`mount(2)`）。本番ビルドでは [`sys::mount_proc_at`] を呼ぶ。
#[cfg(not(test))]
fn mount_proc_syscall(target: &std::ffi::CStr) -> Result<(), SysError> {
    sys::mount_proc_at(target)
}

/// テストビルドの dry-run 差し込み点。`mount(2)` を呼ばず、渡されたマウント先をスレッド
/// ローカルに記録するだけにする。単体テストは証跡の検証を経ない `mount_proc_verified` を
/// 直接呼ぶため、将来パス検証が後退しても root 実行のテストからホストへ `mount(2)` が
/// 届かないことを cfg で構造的に保証する。
#[cfg(test)]
fn mount_proc_syscall(target: &std::ffi::CStr) -> Result<(), SysError> {
    tests::DRY_RUN_MOUNTS.with(|m| m.borrow_mut().push(target.to_string_lossy().into_owned()));
    Ok(())
}

/// `/` から `rootfs`（絶対パス）の各要素を 1 要素ずつ `O_PATH|O_DIRECTORY|O_NOFOLLOW` で開いて
/// rootfs を fd で固定し、続けてその fd を起点に `names` を同様に開き、最後の要素の fd を返す
/// （副作用なし）。
///
/// [`mount_proc`] のマウント先固定と、`oci_runtime` の start が bundle 配下の rootfs を固定する
/// `RootfsDir::pin`（TASK-29.3。`rootfs` に bundle、`names` に bundle から rootfs までの要素を渡す）に
/// 使う。各要素は直前の fd を起点に開くため、途中の要素を
/// symlink へ差し替えても、祖先を改名しても、辿る実体は固定した rootfs の中に留まる。O_PATH は
/// 読み取り権限を要求しないため、実行権限のみの祖先（`CLONE_NEWUSER` 後のホスト所有
/// ディレクトリ等）も辿れる。
///
/// 拒否は違反記録付きの `InvalidArgument`:
/// - rootfs 側（対象は `rootfs`）: symlink・非ディレクトリ → `RootfsSymlinkOrNotDirectory`、
///   不在 → `RootfsMissing`
/// - rootfs より下（対象は `rootfs` と `names` を連結したマウント先）: symlink・非ディレクトリ
///   → `PathSymlinkOrNotDirectory`、不在 → `PathMissing`、NUL → `PathContainsNul`
///
/// search 権限不足（`PermissionDenied`）等のその他の errno はシステムエラー（違反記録なし）。
pub(crate) fn open_dir_beneath(rootfs: &Path, names: &[&OsStr]) -> Result<OwnedFd, ExecError> {
    let mut cur = pin_rootfs(rootfs)?.dir;
    // 2 段目: 固定した rootfs の fd を起点にマウント先を辿る。
    for name in names {
        let c = c_name(rootfs, names, name, true)?;
        cur = sys::open_dir_path_nofollow(Some(cur.as_fd()), &c)
            .map_err(|e| open_error(e, true, rootfs, names))?;
    }
    Ok(cur)
}

/// [`pin_rootfs`] の結果。
struct PinnedRootfs {
    /// rootfs の親ディレクトリの fd（rootfs が `/` のときは `None`）。bind mount 後に同じ
    /// 親・同じ名前から開き直して新しい mount top を得るために保持する。
    parent: Option<OwnedFd>,
    /// rootfs の末尾要素名（`parent` があるときだけ `Some`）。
    leaf: Option<CString>,
    /// 固定した rootfs 自体の fd。
    dir: OwnedFd,
}

/// `/` から `rootfs` までを 1 要素ずつ開いて固定する（[`open_dir_beneath`] の 1 段目）。
/// 親 fd と末尾要素名も返す（`prepare_rootfs` が bind 後の開き直しに使う）。拒否の分類は
/// [`open_dir_beneath`] の rootfs 側と同じ。
fn pin_rootfs(rootfs: &Path) -> Result<PinnedRootfs, ExecError> {
    let mut cur =
        sys::open_dir_path_nofollow(None, c"/").map_err(|e| open_error(e, false, rootfs, &[]))?;
    let mut parent = None;
    let mut leaf = None;
    for c in rootfs.components() {
        let name = match c {
            Component::Normal(n) => n,
            Component::RootDir | Component::CurDir => continue,
            // 呼び出し側で `..`・相対パスを拒否済み。ここへ来たら構成の誤りとして拒否する。
            Component::ParentDir | Component::Prefix(_) => {
                return Err(ExecError::from_violation(
                    ViolationReason::PathParentComponent,
                    Some(rootfs),
                ));
            }
        };
        let c = c_name(rootfs, &[], name, false)?;
        let next = sys::open_dir_path_nofollow(Some(cur.as_fd()), &c)
            .map_err(|e| open_error(e, false, rootfs, &[]))?;
        parent = Some(std::mem::replace(&mut cur, next));
        leaf = Some(c);
    }
    Ok(PinnedRootfs {
        parent,
        leaf,
        dir: cur,
    })
}

/// `openat` の失敗を違反記録付きの拒否（またはシステムエラー）へ写す。`below_rootfs` は
/// rootfs より下の要素の失敗か。対象は rootfs 側なら `rootfs`、下なら `rootfs` に `names` を
/// 連結したパス。
fn open_error(e: SysError, below_rootfs: bool, rootfs: &Path, names: &[&OsStr]) -> ExecError {
    let (not_dir, missing) = if below_rootfs {
        (
            ViolationReason::PathSymlinkOrNotDirectory,
            ViolationReason::PathMissing,
        )
    } else {
        (
            ViolationReason::RootfsSymlinkOrNotDirectory,
            ViolationReason::RootfsMissing,
        )
    };
    let violation = |r: ViolationReason| {
        let subject = subject_path(rootfs, names, below_rootfs);
        ExecError::from_violation(r, Some(&subject))
    };
    match e {
        // O_DIRECTORY|O_NOFOLLOW では symlink も ENOTDIR になる。ELOOP は念のため残す。
        SysError::Os(sys::ELOOP) | SysError::Os(sys::ENOTDIR) => violation(not_dir),
        SysError::Os(sys::ENOENT) => violation(missing),
        other => ExecError::from_sys(other, IsolationStage::MountProc, "openat"),
    }
}

/// 違反記録の対象パス（rootfs 側の失敗は `rootfs`、下の失敗は `rootfs` に `names` を連結したもの）。
fn subject_path(rootfs: &Path, names: &[&OsStr], below_rootfs: bool) -> std::path::PathBuf {
    if below_rootfs {
        names.iter().fold(rootfs.to_path_buf(), |p, n| p.join(n))
    } else {
        rootfs.to_path_buf()
    }
}

/// 要素名を NUL 終端文字列にする。NUL を含めば違反記録付きで拒否する。
fn c_name(
    rootfs: &Path,
    names: &[&OsStr],
    name: &OsStr,
    below_rootfs: bool,
) -> Result<CString, ExecError> {
    CString::new(name.as_bytes()).map_err(|_| {
        let subject = subject_path(rootfs, names, below_rootfs);
        ExecError::from_violation(ViolationReason::PathContainsNul, Some(&subject))
    })
}

/// `dir` の現在の位置（`/proc/thread-self/fd/N` のリンク先）が `expected` と要素単位で一致
/// するか。移動・削除（リンク先に ` (deleted)` が付く）・読み取り失敗はいずれも不一致とする。
fn fd_still_at(dir: &OwnedFd, expected: &Path) -> bool {
    std::fs::read_link(format!("/proc/thread-self/fd/{}", dir.as_raw_fd()))
        .is_ok_and(|now| now.components().eq(expected.components()))
}

/// `/proc/thread-self/fdinfo/<fd>` の `mnt_id:` 行（fd が属するマウントの ID）を取り出す。
fn parse_fdinfo_mnt_id(fdinfo: &str) -> Option<u64> {
    fdinfo
        .lines()
        .find_map(|l| l.strip_prefix("mnt_id:"))
        .and_then(|v| v.trim().parse().ok())
}

/// `dir` が属するマウントが shared propagation か判定する。fdinfo の `mnt_id` と
/// 呼び出しスレッドの `/proc/thread-self/mountinfo` の先頭フィールド（mount ID）を
/// 突き合わせる（`/proc/self/mountinfo` はスレッドグループの代表の mount namespace を映し、
/// `establish` 後の別スレッドでは一致しないため）。読み取り・解析
/// できない場合は安全側（エラー）に倒す。
/// 失敗は `stage` の段として返す（proc マウントは `MountProc`、rootfs 切替は `PrepareRootfs`）。
///
/// `cfg(test)` では `tests::DRY_RUN_SHARED` に値があればそれを返す（既定の `None` は実際に読む）。実行環境
/// （CI の ubuntu は shared）に依らず `rootfs::prepare_rootfs` の bind 以降の経路を照合するため（#1676）。
fn mount_is_shared(dir: &OwnedFd, stage: IsolationStage) -> Result<bool, ExecError> {
    #[cfg(test)]
    if let Some(shared) = tests::DRY_RUN_SHARED.with(std::cell::Cell::get) {
        return Ok(shared);
    }
    let mnt_id = fd_mount_id(dir, stage)?;
    let info = read_thread_mountinfo(stage)?;
    mount_is_shared_in(&info, mnt_id).map_err(|e| e.at_stage(stage))
}

/// `dir` が属するマウントの ID（`/proc/thread-self/fdinfo/N` の `mnt_id`）。読めなければ
/// システムエラー（fail-closed）。
fn fd_mount_id(dir: &OwnedFd, stage: IsolationStage) -> Result<u64, ExecError> {
    let err = |msg: &str| mountinfo_error(msg).at_stage(stage);
    let fdinfo = std::fs::read_to_string(format!("/proc/thread-self/fdinfo/{}", dir.as_raw_fd()))
        .map_err(|_| err("cannot read fdinfo of the pinned directory"))?;
    parse_fdinfo_mnt_id(&fdinfo).ok_or_else(|| err("no mnt_id in fdinfo of the pinned directory"))
}

/// 呼び出しスレッドの mount namespace の mountinfo（`/proc/self/mountinfo` はスレッドグループの
/// 代表の namespace を映すため使わない）。
fn read_thread_mountinfo(stage: IsolationStage) -> Result<String, ExecError> {
    std::fs::read_to_string("/proc/thread-self/mountinfo").map_err(|_| {
        mountinfo_error("cannot read /proc/thread-self/mountinfo to verify mount propagation")
            .at_stage(stage)
    })
}

fn mountinfo_error(msg: &str) -> ExecError {
    ExecError::new(
        ErrorCode::FailedPrecondition,
        IsolationStage::MountProc,
        msg,
    )
}

/// mountinfo の 1 行に必須の固定フィールド数（`id parent major:minor root mount_point options`）。
const MOUNTINFO_FIXED_FIELDS: usize = 6;
/// 区切り `-` の後ろの必須フィールド数（`fstype source super_options`）。
const MOUNTINFO_TAIL_FIELDS: usize = 3;

/// `mnt_id` のマウントが read-only（mountinfo の per-mount options に `ro`）か判定する純関数。
/// `inject_files` が read-only 再マウントの事後検証に使う（SUP-12・TASK-169.4.2）。書式に反する行・
/// 該当行なし・複数行はエラー（fail-closed。`mount_is_shared_in` と同じ姿勢）。
fn mount_is_read_only_in(info: &str, mnt_id: u64) -> Result<bool, ExecError> {
    let malformed = || mountinfo_error("malformed line in /proc/thread-self/mountinfo");
    let mut found: Option<bool> = None;
    for line in info.lines() {
        let fields: Vec<&str> = line.split(' ').collect();
        let id: u64 = fields
            .first()
            .and_then(|f| f.parse().ok())
            .ok_or_else(malformed)?;
        if id != mnt_id {
            continue;
        }
        if found.is_some() {
            return Err(mountinfo_error(
                "duplicate mount ID in /proc/thread-self/mountinfo",
            ));
        }
        let options = fields.get(5).ok_or_else(malformed)?;
        found = Some(options.split(',').any(|o| o == "ro"));
    }
    found.ok_or_else(|| mountinfo_error("no mount entry found for the injected files mount"))
}

/// [`mount_is_shared`] の解析部（テスト可能な純関数）。先頭フィールド（mount ID）が
/// `mnt_id` の行の optional fields に `shared:` があるかを返す。書式に反する行は 1 行でも
/// あれば候補行かどうかに関わらずエラーにする（fail-closed。壊れた行を黙って飛ばして
/// 非 shared と誤判定しない）。該当行が無い・同じ mount ID の行が複数ある場合もエラー。
fn mount_is_shared_in(info: &str, mnt_id: u64) -> Result<bool, ExecError> {
    let malformed = || mountinfo_error("malformed line in /proc/thread-self/mountinfo");
    let mut found: Option<bool> = None;
    for line in info.lines() {
        let fields: Vec<&str> = line.split(' ').collect();
        // optional fields（0 個以上）の終端 `-` を、固定フィールドの後ろから探す。
        let sep = fields
            .iter()
            .skip(MOUNTINFO_FIXED_FIELDS)
            .position(|f| *f == "-")
            .map(|i| i + MOUNTINFO_FIXED_FIELDS)
            .ok_or_else(malformed)?;
        if fields.len() < sep + 1 + MOUNTINFO_TAIL_FIELDS {
            return Err(malformed());
        }
        let id: u64 = fields
            .first()
            .and_then(|f| f.parse().ok())
            .ok_or_else(malformed)?;
        if id != mnt_id {
            continue;
        }
        if found.is_some() {
            return Err(mountinfo_error(
                "duplicate mount ID in /proc/thread-self/mountinfo",
            ));
        }
        let shared = fields
            .get(MOUNTINFO_FIXED_FIELDS..sep)
            .ok_or_else(malformed)?
            .iter()
            .any(|f| f.starts_with("shared:"));
        found = Some(shared);
    }
    found.ok_or_else(|| mountinfo_error("no mount entry found for proc mount target"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn cfg(namespaces: NamespaceSet, hostname: Option<&str>) -> IsolationConfig {
        IsolationConfig {
            namespaces,
            hostname: hostname.map(|h| Hostname::new(h).unwrap()),
        }
    }

    /// CORE-1: 5 種の集合と単体の所属判定。
    #[test]
    fn core1_namespace_set_membership() {
        let all = NamespaceSet::all();
        assert!(Namespace::ALL.iter().all(|ns| all.contains(*ns)));
        let only_uts = NamespaceSet::empty().with(Namespace::Uts);
        assert!(only_uts.contains(Namespace::Uts));
        assert!(!only_uts.contains(Namespace::Pid));
        assert!(NamespaceSet::empty().is_empty());
        // 単体フラグの合成値（sys の具体値と一致）
        let bits = all.flags().iter().fold(0i32, |a, f| a | f.bits());
        assert_eq!(bits, 0x3C02_0000);
    }

    /// CORE-1: hostname の受理例。
    #[test]
    fn core1_hostname_accepts_valid() {
        assert_eq!(
            Hostname::new("fandhe-probe").unwrap().as_str(),
            "fandhe-probe"
        );
        assert_eq!(Hostname::new("a.b-c").unwrap().as_str(), "a.b-c");
        assert!(Hostname::new("a".repeat(63)).is_ok());
    }

    /// CORE-1: hostname の拒否例はすべて `InvalidArgument`。
    #[test]
    fn core1_hostname_rejects_invalid() {
        let too_long = "a".repeat(65);
        let long_label = "a".repeat(64);
        for bad in [
            "",
            "a_b",
            "-a",
            "a-",
            "a..b",
            "a.",
            ".a",
            "a\0b",
            too_long.as_str(),
            long_label.as_str(),
            "日本",
        ] {
            let err = Hostname::new(bad).unwrap_err();
            assert_eq!(err.code, ErrorCode::InvalidArgument, "input: {bad:?}");
            assert_eq!(err.stage, IsolationStage::Validate);
        }
    }

    /// CORE-1: uid_map / gid_map の書式。
    #[test]
    fn core1_id_mapping_line_format() {
        assert_eq!(IdMapping::single(1000).to_map_line(), "0 1000 1\n");
    }

    /// CORE-1: 空集合は拒否。
    #[test]
    fn core1_plan_rejects_empty_namespaces() {
        let err = plan_for(&cfg(NamespaceSet::empty(), None), 1000, 1000).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidArgument);
        let err = plan_rootful_for(&cfg(NamespaceSet::empty(), None), 0).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidArgument);
    }

    /// CORE-1: UTS 無しの hostname はホストの hostname を書き換え得るため拒否。
    #[test]
    fn core1_plan_rejects_hostname_without_uts() {
        let ns = NamespaceSet::empty()
            .with(Namespace::Pid)
            .with(Namespace::Mount);
        let err = plan_for(&cfg(ns.with(Namespace::User), Some("x")), 1000, 1000).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidArgument);
        assert_eq!(err.stage, IsolationStage::Validate);
        assert_eq!(err.message, "hostname requires the UTS namespace");
        let err = plan_rootful_for(&cfg(ns, Some("x")), 0).unwrap_err();
        assert_eq!(err.message, "hostname requires the UTS namespace");
    }

    /// SEC-5: root（euid 0 / egid 0）の自 ID 写像は拒否。
    #[test]
    fn sec5_plan_rejects_root_identity_mapping() {
        for (u, g) in [(0, 1000), (1000, 0), (0, 0)] {
            let err = plan_for(&cfg(NamespaceSet::all(), None), u, g).unwrap_err();
            assert_eq!(err.code, ErrorCode::FailedPrecondition, "({u},{g})");
        }
    }

    /// 監査 P1-1: Pid あり・Mount なしは両経路とも拒否し、Mount を加えれば通る。
    #[test]
    fn core1_plan_rejects_pid_without_mount() {
        let pid_only = NamespaceSet::empty()
            .with(Namespace::Pid)
            .with(Namespace::Uts);
        let err = plan_rootful_for(&cfg(pid_only, None), 0).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidArgument);
        assert_eq!(err.stage, IsolationStage::Validate);
        assert_eq!(
            err.message,
            "the PID namespace requires the mount namespace"
        );
        let err = plan_for(&cfg(pid_only.with(Namespace::User), None), 1000, 1000).unwrap_err();
        assert_eq!(
            err.message,
            "the PID namespace requires the mount namespace"
        );
        assert!(plan_rootful_for(&cfg(pid_only.with(Namespace::Mount), None), 0).is_ok());
    }

    /// SEC-5（監査 P2-4）: 拒否文言は弱い分離ではなく subuid / subgid 写像へ案内する。
    #[test]
    fn sec5_rejection_message_points_to_subordinate_ids() {
        let err = plan_for(&cfg(NamespaceSet::all(), None), 0, 0).unwrap_err();
        assert!(err.message.contains("/etc/subuid"), "{}", err.message);
        assert!(err.message.contains("TASK-40"), "{}", err.message);
        assert!(!err.message.contains("rootful"), "{}", err.message);
    }

    /// SEC-5: 既定経路は非 root の自 ID を 0 へ写す単一写像を計画する。
    #[test]
    fn sec5_plan_maps_unprivileged_ids_to_zero() {
        let p = plan_for(&cfg(NamespaceSet::all(), Some("h")), 1000, 1001).unwrap();
        assert_eq!(p.uid_mapping.to_map_line(), "0 1000 1\n");
        assert_eq!(p.gid_mapping.to_map_line(), "0 1001 1\n");
        assert_eq!(p.namespaces, NamespaceSet::all());
        assert_eq!(p.hostname.as_ref().map(Hostname::as_str), Some("h"));
    }

    /// CORE-7・CORE-9: rootful 経路は euid 0 で User なしの構成を計画する。
    #[test]
    fn rootful_plan_accepts_root_without_user() {
        let rootful = NamespaceSet::empty()
            .with(Namespace::Pid)
            .with(Namespace::Mount)
            .with(Namespace::Uts)
            .with(Namespace::Ipc);
        let p = plan_rootful_for(&cfg(rootful, Some("h")), 0).unwrap();
        assert_eq!(
            p,
            RootfulHostRootPlan {
                namespaces: rootful,
                hostname: Some(Hostname::new("h").unwrap()),
            }
        );
    }

    /// Codex P0: 既定経路は User を含まない構成を拒否する（root でも非 root でも）。
    #[test]
    fn default_plan_requires_user_namespace() {
        let no_user = NamespaceSet::empty()
            .with(Namespace::Pid)
            .with(Namespace::Mount)
            .with(Namespace::Uts)
            .with(Namespace::Ipc);
        for (u, g) in [(1000, 1000), (0, 0)] {
            let err = plan_for(&cfg(no_user, None), u, g).unwrap_err();
            assert_eq!(err.code, ErrorCode::InvalidArgument, "({u},{g})");
            assert_eq!(err.stage, IsolationStage::Validate);
            assert_eq!(
                err.message,
                "the user namespace is required to map container root to an unprivileged host ID"
            );
        }
    }

    /// Codex P0: rootful 経路は euid が 0 でなければ拒否する。
    #[test]
    fn rootful_plan_requires_euid_zero() {
        let rootful = NamespaceSet::empty()
            .with(Namespace::Pid)
            .with(Namespace::Mount);
        for euid in [1, 1000, u32::MAX] {
            let err = plan_rootful_for(&cfg(rootful, None), euid).unwrap_err();
            assert_eq!(err.code, ErrorCode::FailedPrecondition, "euid {euid}");
            assert_eq!(err.stage, IsolationStage::Validate);
            assert_eq!(err.message, "the rootful host-root plan requires euid 0");
        }
    }

    /// Codex P0: rootful 経路は User を含められない（euid 0 でも拒否）。
    #[test]
    fn rootful_plan_rejects_user_namespace() {
        let err = plan_rootful_for(&cfg(NamespaceSet::all(), None), 0).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidArgument);
        assert_eq!(err.stage, IsolationStage::Validate);
        assert_eq!(
            err.message,
            "the rootful host-root plan must not include the user namespace"
        );
    }

    /// 既定経路の isolate は、計画作成時と実行 ID が変わっていれば副作用なしで拒否する。
    #[test]
    fn isolate_rejects_plan_for_other_ids() {
        let (euid, egid) = (sys::effective_uid(), sys::effective_gid());
        let other = |id: u32| if id == 4242 { 4243 } else { 4242 };
        let p = plan_for(&cfg(NamespaceSet::all(), None), other(euid), other(egid)).unwrap();
        let err = isolate(&p).unwrap_err();
        assert_eq!(err.code, ErrorCode::FailedPrecondition);
        assert_eq!(err.stage, IsolationStage::Validate);
        assert_eq!(
            err.message,
            "effective uid/gid changed after the plan was created"
        );
    }

    const STATUS_PID1: &str = "Name:\tx\nNSpid:\t4321\t1\nThreads:\t1\n";

    /// 再監査 P2-2・P2-3: establish の前提（PID 1・NSpid 末尾 1・入れ子・シングルスレッド）。
    #[test]
    fn establish_preconditions() {
        const NESTED: u64 = 4_026_532_001;
        assert_eq!(
            check_establish_preconditions(1, STATUS_PID1, NESTED),
            Ok(())
        );
        // PID namespace 内でマウントした procfs を見ていて NSpid が 1 段でも、初期 PID
        // namespace でなければ受け付ける（NSpid の要素数に依存しない。Codex 指摘）。
        assert_eq!(
            check_establish_preconditions(1, "NSpid:\t1\nThreads:\t1\n", NESTED),
            Ok(())
        );
        let cases: [(u32, &str, u64, ViolationReason); 5] = [
            (7, STATUS_PID1, NESTED, ViolationReason::EstablishNotPid1),
            (
                1,
                "NSpid:\t4321\t7\nThreads:\t1\n",
                NESTED,
                ViolationReason::EstablishNspidNotPid1,
            ),
            // 初期 PID namespace の PID 1（ホストの init）。
            (
                1,
                "NSpid:\t1\nThreads:\t1\n",
                PID_NS_INIT_INO,
                ViolationReason::EstablishNotNestedPidNamespace,
            ),
            (
                1,
                "NSpid:\t4321\t1\nThreads:\t2\n",
                NESTED,
                ViolationReason::EstablishMultiThreaded,
            ),
            (
                1,
                "NSpid:\t4321\t1\n",
                NESTED,
                ViolationReason::EstablishMultiThreaded,
            ),
        ];
        for (pid, status, ino, want) in cases {
            assert_eq!(
                check_establish_preconditions(pid, status, ino),
                Err(want),
                "{status:?} {ino}"
            );
        }
    }

    /// `Threads:`・`NSpid` 末尾の解析。
    #[test]
    fn status_fields_parsing() {
        assert_eq!(status_threads("Threads:\t12\n"), Some(12));
        assert_eq!(status_threads("Threads:\tx\n"), None);
        assert_eq!(status_threads("Name:\tx\n"), None);
        assert_eq!(nspid_innermost("NSpid:\t4321\t55\t1\n"), Some(1));
        assert_eq!(nspid_innermost("NSpid:\t4321\n"), Some(4321));
        assert_eq!(nspid_innermost("NSpid:\n"), None);
        // 実プロセスの status でも取れる（libtest はマルチスレッド）。
        let status = std::fs::read_to_string("/proc/self/status").unwrap();
        assert!(status_threads(&status).is_some_and(|n| n >= 1));
        assert_eq!(
            nspid_innermost(&status),
            Some(std::process::id()),
            "innermost NSpid equals getpid"
        );
    }

    /// errno 写像の具体値。
    #[test]
    fn errno_maps_to_error_code() {
        assert_eq!(
            errno_to_code(SysError::Os(sys::EPERM)),
            ErrorCode::PermissionDenied
        );
        assert_eq!(
            errno_to_code(SysError::Os(sys::EACCES)),
            ErrorCode::PermissionDenied
        );
        assert_eq!(
            errno_to_code(SysError::Os(sys::EINVAL)),
            ErrorCode::FailedPrecondition
        );
        assert_eq!(errno_to_code(SysError::Os(2)), ErrorCode::Internal);
        assert_eq!(
            errno_to_code(SysError::Unsupported),
            ErrorCode::Unimplemented
        );
    }

    thread_local! {
        /// dry-run の `mount_proc_syscall` が記録したマウント先（テストスレッドごと）。
        pub(super) static DRY_RUN_MOUNTS: std::cell::RefCell<Vec<String>> =
            const { std::cell::RefCell::new(Vec::new()) };
        /// `mount_is_shared` に返させる値（テストスレッドごと。`None` は実際の propagation を読む）。
        pub(super) static DRY_RUN_SHARED: std::cell::Cell<Option<bool>> =
            const { std::cell::Cell::new(None) };
    }

    /// dry-run の記録を取り出して空にする。libtest のワーカースレッドが再利用されても、
    /// 前のテストの記録が後続のテストへ漏れないよう、照合は必ずこの関数で取り出して行う。
    pub(super) fn take_dry_run_mounts() -> Vec<String> {
        DRY_RUN_MOUNTS.with(|m| std::mem::take(&mut *m.borrow_mut()))
    }

    /// dry-run の記録を消費せずに件数だけ返す（`rootfs` の nodev の順序照合用。#1676）。
    pub(super) fn peek_dry_run_mounts_len() -> usize {
        DRY_RUN_MOUNTS.with(|m| m.borrow().len())
    }

    /// パス検証は相対パス・NUL を副作用なしで拒否する。
    #[test]
    fn mount_proc_rejects_bad_targets() {
        let rel = mount_proc_verified(Path::new("/"), Path::new("proc")).unwrap_err();
        assert_eq!(rel.code, ErrorCode::InvalidArgument);
        assert_eq!(rel.stage, IsolationStage::MountProc);
        let nul = mount_proc_verified(Path::new("/"), Path::new("/pr\0oc")).unwrap_err();
        assert_eq!(nul.code, ErrorCode::InvalidArgument);
    }

    /// テストプロセスは PID 1 ではないため、証跡の作成は副作用なしで拒否される
    /// （CORE-1・fail-closed）。
    #[test]
    fn establish_rejects_non_pid1() {
        let before = thread_ns_link("mnt").unwrap();
        let err = MountIsolation::establish().unwrap_err();
        assert_eq!(err.code, ErrorCode::FailedPrecondition);
        assert_eq!(err.stage, IsolationStage::MountProc);
        assert!(err.message.starts_with("not PID 1"), "{}", err.message);
        // unshare 前に拒否しており、スレッドの mount namespace は変わらない。
        assert_eq!(thread_ns_link("mnt").unwrap(), before);
    }

    fn evidence(mnt_ns: &str, pid_ns: &str) -> MountIsolation {
        MountIsolation {
            mnt_ns: mnt_ns.to_string(),
            pid_ns: pid_ns.to_string(),
            _not_send: std::marker::PhantomData,
        }
    }

    /// CORE-1（Codex P0）: 証跡の再検証は PID 1・mount ns・PID ns のすべての一致を要求する。
    #[test]
    fn check_evidence_requires_pid1_and_both_namespaces() {
        let e = evidence("mnt:[10]", "pid:[20]");
        assert_eq!(check_evidence(&e, 1, "mnt:[10]", "pid:[20]"), Ok(()));
        // 証跡を受け取った親や PID 1 が fork した子（PID が 1 でない）。
        assert_eq!(
            check_evidence(&e, 42, "mnt:[10]", "pid:[20]"),
            Err(ViolationReason::EvidenceCallerNotPid1)
        );
        // 別の mount namespace（別スレッド・親）。
        assert_eq!(
            check_evidence(&e, 1, "mnt:[11]", "pid:[20]"),
            Err(ViolationReason::EvidenceMountNamespaceMismatch)
        );
        // 同じ mount namespace だが別の PID namespace（procfs が別の PID 集合を映す）。
        assert_eq!(
            check_evidence(&e, 1, "mnt:[10]", "pid:[21]"),
            Err(ViolationReason::EvidencePidNamespaceMismatch)
        );
    }

    /// CORE-1（Codex P0・監査 P1-1）: unshare の前後で mount ns が変わらなければ拒否する。
    #[test]
    fn check_fresh_mount_ns_rejects_unchanged_namespace() {
        assert_eq!(check_fresh_mount_ns("mnt:[1]", "mnt:[2]"), Ok(()));
        assert_eq!(
            check_fresh_mount_ns("mnt:[1]", "mnt:[1]"),
            Err(ViolationReason::EstablishMountNamespaceNotFresh)
        );
    }

    /// 現在のスレッドの値で作った証跡でも、PID 1 でなければ mount_proc は副作用なしで拒否し、
    /// dry-run の mount にも到達しない。
    #[test]
    fn mount_proc_rejects_caller_that_is_not_pid1() {
        take_dry_run_mounts();
        let e = evidence(
            &thread_ns_link("mnt").unwrap(),
            &thread_ns_link("pid").unwrap(),
        );
        let err = mount_proc(&e, Path::new("/"), Path::new("/proc")).unwrap_err();
        assert_eq!(err.code, ErrorCode::FailedPrecondition);
        assert_eq!(err.stage, IsolationStage::MountProc);
        assert_eq!(
            err.message,
            "mount_proc must be called by PID 1 of the isolated PID namespace"
        );
        assert_eq!(take_dry_run_mounts(), Vec::<String>::new());
    }

    /// `ns/pid` の inode の解析と、初期 PID namespace の inode の具体値。
    #[test]
    fn pid_ns_inode_parsing() {
        assert_eq!(PID_NS_INIT_INO, 4_026_531_836);
        assert_eq!(
            parse_pid_ns_inode("pid:[4026531836]"),
            Some(PID_NS_INIT_INO)
        );
        assert_eq!(parse_pid_ns_inode("pid:[4026532001]"), Some(4_026_532_001));
        for bad in ["mnt:[4026531836]", "pid:[x]", "pid:4026531836", ""] {
            assert_eq!(parse_pid_ns_inode(bad), None, "{bad:?}");
        }
        // 実プロセスのリンクも解析できる。
        assert!(parse_pid_ns_inode(&thread_ns_link("pid").unwrap()).is_some());
    }

    const MI_SHARED: &str = "22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw\n";
    const MI_PRIVATE: &str = "30 22 0:5 / /proc rw - proc proc rw\n";

    /// mountinfo の shared 判定は mount ID で行い、パスの前後関係に依存しない。
    #[test]
    fn mountinfo_detects_shared_and_private_by_mount_id() {
        let both = format!("{MI_SHARED}{MI_PRIVATE}");
        assert!(mount_is_shared_in(&both, 22).unwrap());
        assert!(!mount_is_shared_in(&both, 30).unwrap());
        // optional fields が複数（master: 等）でも shared: を見つける。
        let multi = "40 22 0:6 / /x rw master:3 shared:7 - tmpfs t rw\n";
        assert!(mount_is_shared_in(multi, 40).unwrap());
    }

    /// 書式に反する行（区切り `-` 欠落・フィールド不足・末尾欠落・数値でない ID）・
    /// 該当なし・ID 重複はエラー。
    #[test]
    fn mountinfo_rejects_malformed_lines() {
        for bad in [
            "22 1 8:1 / / rw,relatime\n",
            "22 1 8:1 /\n",
            "22 1 8:1 / / rw,relatime shared:1 - ext4\n",
            "22 1 8:1 / / rw,relatime -\n",
            "\n",
            "x 1 8:1 / / rw - ext4 /dev/sda1 rw\n",
            // 候補でない行が壊れていても黙って飛ばさない。
            "23 1 8:1 / /other rw\n22 1 8:1 / / rw - ext4 /dev/sda1 rw\n",
            // 該当する mount ID が無い。
            "23 1 8:1 / /other rw - ext4 /dev/sda1 rw\n",
            // 同じ mount ID が 2 行。
            "22 1 8:1 / / rw - ext4 a rw\n22 1 8:1 / /b rw - ext4 b rw\n",
        ] {
            let err = mount_is_shared_in(bad, 22).unwrap_err();
            assert_eq!(err.code, ErrorCode::FailedPrecondition, "input: {bad:?}");
            assert_eq!(err.stage, IsolationStage::MountProc);
        }
    }

    /// テスト用の一時ディレクトリ（`chmod` で絞ったディレクトリを戻してから削除する）。
    /// `TMPDIR` に symlink があると rootfs の正規化検査が先に失敗して各ケースが意図と
    /// 違う理由で通るため、正規化したパスを起点にする。
    struct TempTree {
        base: std::path::PathBuf,
        restore: Vec<std::path::PathBuf>,
    }

    impl TempTree {
        fn new(label: &str) -> Self {
            let base = std::fs::canonicalize(std::env::temp_dir())
                .unwrap()
                .join(format!("fandhe-exec-{label}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&base);
            std::fs::create_dir_all(&base).unwrap();
            Self {
                base,
                restore: Vec::new(),
            }
        }
    }

    impl Drop for TempTree {
        fn drop(&mut self) {
            use std::os::unix::fs::PermissionsExt as _;
            for p in &self.restore {
                let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o700));
            }
            let _ = std::fs::remove_dir_all(&self.base);
        }
    }

    /// `..`・rootfs 外・symlink・非ディレクトリのターゲットは、それぞれ意図した理由で
    /// 副作用なしに拒否する（mount(2) へは到達しない）。
    #[test]
    fn mount_proc_rejects_escape_paths() {
        take_dry_run_mounts();
        let t = TempTree::new("escape");
        let root = t.base.join("root");
        std::fs::create_dir_all(root.join("real")).unwrap();
        std::fs::write(root.join("file"), b"").unwrap();
        std::os::unix::fs::symlink("/", root.join("link")).unwrap();
        std::os::unix::fs::symlink(root.join("real"), root.join("dirlink")).unwrap();
        let not_dir = "must be directories, not symlinks";
        let cases = [
            (root.join("real/../real"), "must not contain '..'"),
            (t.base.join("outside"), "must be under rootfs"),
            (root.join("link"), not_dir),
            (root.join("dirlink"), not_dir),
            (root.join("link/proc"), not_dir),
            (root.join("file"), not_dir),
            (root.join("missing"), "must exist"),
            (root.clone(), "not rootfs itself"),
        ];
        for (target, want) in &cases {
            let err = mount_proc_verified(&root, target).unwrap_err();
            assert_eq!(err.code, ErrorCode::InvalidArgument, "{target:?}");
            assert_eq!(err.stage, IsolationStage::MountProc, "{target:?}");
            assert!(err.message.contains(want), "{target:?}: {}", err.message);
        }
        assert_eq!(take_dry_run_mounts(), Vec::<String>::new());
        // rootfs 自体が symlink（実体は base/root）の場合は拒否する。
        let alias = t.base.join("alias");
        std::os::unix::fs::symlink(&root, &alias).unwrap();
        let err = mount_proc_verified(&alias, &alias.join("real")).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidArgument, "rootfs symlink");
        assert!(
            err.message
                .contains("rootfs and its ancestors must be directories"),
            "{}",
            err.message
        );
    }

    /// CORE-1（Cursor Bugbot 指摘の回帰）: rootfs の祖先に実行権限のみ（読み取り不可）の
    /// ディレクトリがあっても、マウント先まで辿って fd を固定できる。mount(2) を呼ばない
    /// 走査部だけを検証する（root で実行されてもホストにマウントしないため）。root では DAC を
    /// 迂回するため判別力はないが失敗もしない。
    #[test]
    fn open_dir_beneath_traverses_execute_only_ancestor() {
        use std::os::unix::fs::PermissionsExt as _;
        let mut t = TempTree::new("xonly");
        let xonly = t.base.join("xonly");
        let root = xonly.join("root");
        std::fs::create_dir_all(root.join("proc")).unwrap();
        std::fs::set_permissions(&xonly, std::fs::Permissions::from_mode(0o100)).unwrap();
        t.restore.push(xonly.clone());
        if sys::effective_uid() != 0 {
            // 前提の確認: 読み取りで開く方式ではこの祖先を開けない（修正前の失敗条件）。
            let err = std::fs::read_dir(&xonly).unwrap_err();
            assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
        }
        let fd = open_dir_beneath(&root, &[OsStr::new("proc")]).unwrap();
        assert_eq!(
            std::fs::read_link(format!("/proc/thread-self/fd/{}", fd.as_raw_fd())).unwrap(),
            root.join("proc")
        );
    }

    /// 走査の途中に symlink があれば、実体がディレクトリでも拒否する（パス差し替え対策）。
    #[test]
    fn open_dir_beneath_rejects_symlink_component() {
        let t = TempTree::new("beneath-link");
        let root = t.base.join("root");
        std::fs::create_dir_all(root.join("real/proc")).unwrap();
        std::os::unix::fs::symlink(root.join("real"), root.join("link")).unwrap();
        let err = open_dir_beneath(&root, &[OsStr::new("link"), OsStr::new("proc")]).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidArgument);
        assert_eq!(err.stage, IsolationStage::MountProc);
    }

    /// fdinfo の `mnt_id:` を取り出す（無い・数値でない場合は None）。
    #[test]
    fn fdinfo_mnt_id_parsing() {
        assert_eq!(
            parse_fdinfo_mnt_id("pos:\t0\nflags:\t012600000\nmnt_id:\t52\nino:\t1\n"),
            Some(52)
        );
        assert_eq!(parse_fdinfo_mnt_id("pos:\t0\nflags:\t0\n"), None);
        assert_eq!(parse_fdinfo_mnt_id("mnt_id:\tx\n"), None);
    }

    /// 走査で固定した `/` の fd の mnt_id は、mountinfo で最後に現れる（最上位の）
    /// マウントポイント `/` の mount ID と一致し、その行の shared 判定を返す。
    #[test]
    fn sup12_task169_4_2_mount_is_read_only_in_parses_per_mount_options() {
        let info = "30 20 0:25 / /a ro,nosuid,nodev,noexec - tmpfs tmpfs rw,size=64k\n\
                    31 20 0:26 / /b rw,nosuid,nodev,noexec shared:3 - tmpfs tmpfs ro\n";
        assert!(mount_is_read_only_in(info, 30).expect("30"));
        // super block 側の `ro`（末尾）ではなく per-mount options を見る。
        assert!(!mount_is_read_only_in(info, 31).expect("31"));
        assert!(mount_is_read_only_in(info, 99).is_err());
        assert!(mount_is_read_only_in("x y z\n", 30).is_err());
        assert!(mount_is_read_only_in("30 20 0:25 / /a\n", 30).is_err());
        assert!(
            mount_is_read_only_in(
                "30 20 0:25 / /a ro - tmpfs t r\n30 1 0:1 / /b rw - tmpfs t r\n",
                30
            )
            .is_err()
        );
    }

    #[test]
    fn mount_is_shared_uses_mount_id_of_fd() {
        let fd = open_dir_beneath(Path::new("/"), &[]).unwrap();
        let fdinfo =
            std::fs::read_to_string(format!("/proc/thread-self/fdinfo/{}", fd.as_raw_fd()))
                .unwrap();
        let mnt_id = parse_fdinfo_mnt_id(&fdinfo).unwrap();
        let info = std::fs::read_to_string("/proc/thread-self/mountinfo").unwrap();
        let root_line = info
            .lines()
            .rev()
            .find(|l| l.split(' ').nth(4) == Some("/"))
            .unwrap();
        let id: u64 = root_line.split(' ').next().unwrap().parse().unwrap();
        assert_eq!(mnt_id, id);
        let want = root_line
            .split(" - ")
            .next()
            .unwrap()
            .split(' ')
            .skip(6)
            .any(|f| f.starts_with("shared:"));
        assert_eq!(
            mount_is_shared(&fd, IsolationStage::MountProc).unwrap(),
            want
        );
    }

    /// 違反記録の中身を具体値で取り出す（種別名・理由コード・ビヘイビア ID・対象）。
    fn violation_of(err: &ExecError) -> (&'static str, &'static str, &'static str, Option<String>) {
        let v = err.violation.as_ref().expect("violation record");
        (
            v.kind.as_str(),
            v.reason.as_str(),
            v.behavior_id,
            v.subject.as_ref().map(|s| s.as_str().to_string()),
        )
    }

    /// SEC-4（記録経路）: plan / plan_rootful_host_root / isolate の各拒否に違反記録が付く。
    #[test]
    fn sec4_plan_rejections_carry_violation_records() {
        let pm = NamespaceSet::empty()
            .with(Namespace::Pid)
            .with(Namespace::Mount);
        let pid_only = NamespaceSet::empty().with(Namespace::Pid);
        let cases: [(Result<(), ExecError>, &str, &str); 7] = [
            (
                plan_for(&cfg(NamespaceSet::empty(), None), 1000, 1000).map(drop),
                "no_namespaces",
                "CORE-1",
            ),
            (
                plan_for(&cfg(pm.with(Namespace::User), Some("h")), 1000, 1000).map(drop),
                "hostname_without_uts",
                "CORE-1",
            ),
            (
                plan_rootful_for(&cfg(pid_only, None), 0).map(drop),
                "pid_without_mount",
                "CORE-1",
            ),
            (
                plan_for(&cfg(pm, None), 1000, 1000).map(drop),
                "user_namespace_required",
                "SEC-5",
            ),
            (
                plan_for(&cfg(NamespaceSet::all(), None), 0, 1000).map(drop),
                "host_root_identity_mapping",
                "SEC-5",
            ),
            (
                plan_rootful_for(&cfg(NamespaceSet::all(), None), 0).map(drop),
                "rootful_with_user_namespace",
                "CORE-1",
            ),
            (
                plan_rootful_for(&cfg(pm, None), 1000).map(drop),
                "rootful_requires_root",
                "CORE-1",
            ),
        ];
        for (result, reason, id) in cases {
            let err = result.unwrap_err();
            assert_eq!(err.stage, IsolationStage::Validate, "{reason}");
            assert_eq!(
                violation_of(&err),
                ("plan_rejected", reason, id, None),
                "{reason}"
            );
        }
        // isolate の実行 ID 再検証（unshare 前に拒否）。
        let (euid, egid) = (sys::effective_uid(), sys::effective_gid());
        let other = |id: u32| if id == 4242 { 4243 } else { 4242 };
        let p = plan_for(&cfg(NamespaceSet::all(), None), other(euid), other(egid)).unwrap();
        let err = isolate(&p).unwrap_err();
        assert_eq!(
            violation_of(&err),
            ("plan_rejected", "identity_changed", "SEC-5", None)
        );
        assert!(
            err.to_string()
                .ends_with("(violation: plan_rejected/identity_changed, SEC-5)")
        );
    }

    /// SEC-4（記録経路）: establish の前提違反と証跡不一致に違反記録が付く（対象なし。
    /// namespace の識別子は記録しない）。
    #[test]
    fn sec4_establish_and_evidence_rejections_carry_violation_records() {
        let err = MountIsolation::establish().unwrap_err();
        assert_eq!(
            violation_of(&err),
            (
                "establish_precondition",
                "establish_not_pid1",
                "CORE-1",
                None
            )
        );
        let e = evidence(
            &thread_ns_link("mnt").unwrap(),
            &thread_ns_link("pid").unwrap(),
        );
        let err = mount_proc(&e, Path::new("/"), Path::new("/proc")).unwrap_err();
        assert_eq!(
            violation_of(&err),
            (
                "evidence_mismatch",
                "evidence_caller_not_pid1",
                "CORE-1",
                None
            )
        );
        assert!(!err.to_string().contains("mnt:["), "{err}");
    }

    /// SEC-4（記録経路）: mount_proc のパス検証の各拒否に、理由コードと対象パスが付く。
    #[test]
    fn sec4_mount_path_rejections_carry_violation_records() {
        take_dry_run_mounts();
        let t = TempTree::new("sec4-path");
        let root = t.base.join("root");
        std::fs::create_dir_all(root.join("real")).unwrap();
        std::fs::write(root.join("file"), b"").unwrap();
        std::os::unix::fs::symlink("/", root.join("link")).unwrap();
        let alias = t.base.join("alias");
        std::os::unix::fs::symlink(&root, &alias).unwrap();
        let s = |p: &Path| Some(p.to_str().unwrap().to_string());
        let dotdot = root.join("real/../real");
        let cases = [
            (
                root.clone(),
                dotdot.clone(),
                "path_parent_component",
                s(&dotdot),
            ),
            (
                root.clone(),
                t.base.join("outside"),
                "target_outside_rootfs",
                s(&t.base.join("outside")),
            ),
            (
                root.clone(),
                root.join("link/proc"),
                "path_symlink_or_not_directory",
                s(&root.join("link/proc")),
            ),
            (
                root.clone(),
                root.join("file"),
                "path_symlink_or_not_directory",
                s(&root.join("file")),
            ),
            (
                root.clone(),
                root.join("missing"),
                "path_missing",
                s(&root.join("missing")),
            ),
            (root.clone(), root.clone(), "target_is_rootfs", s(&root)),
            (
                alias.clone(),
                alias.join("real"),
                "rootfs_symlink_or_not_directory",
                s(&alias),
            ),
            (
                t.base.join("nope"),
                t.base.join("nope/proc"),
                "rootfs_missing",
                s(&t.base.join("nope")),
            ),
            (
                PathBuf::from("/"),
                PathBuf::from("proc"),
                "path_not_absolute",
                Some("proc".to_string()),
            ),
            (
                PathBuf::from("/"),
                PathBuf::from("/pr\0oc"),
                "path_contains_nul",
                Some("/pr\\u{0}oc".to_string()),
            ),
        ];
        for (rootfs, target, reason, subject) in cases {
            let err = mount_proc_verified(&rootfs, &target).unwrap_err();
            assert_eq!(err.code, ErrorCode::InvalidArgument, "{reason}");
            assert_eq!(
                violation_of(&err),
                ("mount_target", reason, "CORE-1", subject),
                "{reason}"
            );
        }
        assert_eq!(take_dry_run_mounts(), Vec::<String>::new());
    }

    /// SEC-4（記録経路）: shared 伝播上のマウント先は違反記録付きで拒否し、shared でなければ
    /// dry-run の mount まで進む（実行環境の propagation に応じてどちらかを具体値で照合する）。
    #[test]
    fn sec4_shared_propagation_carries_violation_record() {
        take_dry_run_mounts();
        let t = TempTree::new("sec4-shared");
        let root = t.base.join("root");
        std::fs::create_dir_all(root.join("proc")).unwrap();
        let target = root.join("proc");
        let dir = open_dir_beneath(&root, &[OsStr::new("proc")]).unwrap();
        let shared = mount_is_shared(&dir, IsolationStage::MountProc).unwrap();
        drop(dir);
        let result = mount_proc_verified(&root, &target);
        if shared {
            let err = result.unwrap_err();
            assert_eq!(err.code, ErrorCode::FailedPrecondition);
            assert_eq!(
                violation_of(&err),
                (
                    "shared_propagation",
                    "target_on_shared_mount",
                    "CORE-1",
                    Some(target.to_str().unwrap().to_string())
                )
            );
            assert_eq!(take_dry_run_mounts(), Vec::<String>::new());
        } else {
            assert_eq!(result, Ok(()));
            let m = take_dry_run_mounts();
            assert_eq!(m.len(), 1);
            assert!(
                m.first()
                    .is_some_and(|t| t.starts_with("/proc/thread-self/fd/")),
                "{m:?}"
            );
        }
    }

    /// SEC-4: システムエラー（syscall 失敗・mountinfo の書式不正・権限不足）と hostname の
    /// 書式エラーには違反記録を付けない。
    #[test]
    fn sec4_system_errors_have_no_violation_record() {
        let enomem = ExecError::from_sys(SysError::Os(12), IsolationStage::Unshare, "unshare");
        assert_eq!(enomem.code, ErrorCode::Internal);
        assert_eq!(enomem.violation, None);
        let err = mount_is_shared_in("22 1 8:1 / / rw\n", 22).unwrap_err();
        assert_eq!(err.violation, None);
        assert_eq!(Hostname::new("a_b").unwrap_err().violation, None);
        if sys::effective_uid() != 0 {
            // search 権限の無い祖先: 走査・rootfs の正規化とも権限不足のシステムエラー。
            use std::os::unix::fs::PermissionsExt as _;
            let mut t = TempTree::new("sec4-eacces");
            let locked = t.base.join("locked");
            std::fs::create_dir_all(locked.join("root/proc")).unwrap();
            std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
            t.restore.push(locked.clone());
            let err = open_dir_beneath(&locked.join("root"), &[OsStr::new("proc")]).unwrap_err();
            assert_eq!(err.code, ErrorCode::PermissionDenied);
            assert_eq!(err.violation, None);
            let err =
                mount_proc_verified(&locked.join("root"), &locked.join("root/proc")).unwrap_err();
            assert_eq!(err.code, ErrorCode::PermissionDenied);
            assert_eq!(err.violation, None);
        }
    }

    /// Codex P0（rootfs の検証後の差し替え）: rootfs 自体・祖先の symlink や非ディレクトリは
    /// rootfs を fd で固定する段で拒否し、対象は rootfs のパスになる。rootfs より下の拒否とは
    /// 理由コードで区別する。
    #[test]
    fn open_dir_beneath_pins_rootfs_before_target() {
        let t = TempTree::new("pin-rootfs");
        let root = t.base.join("root");
        std::fs::create_dir_all(root.join("proc")).unwrap();
        std::fs::write(t.base.join("file"), b"").unwrap();
        std::os::unix::fs::symlink(&t.base, t.base.join("up")).unwrap();
        let s = |p: &Path| Some(p.to_str().unwrap().to_string());
        let proc = [OsStr::new("proc")];
        for (rootfs, reason) in [
            // rootfs の祖先が symlink（実体は同じ root）。
            (t.base.join("up/root"), "rootfs_symlink_or_not_directory"),
            // rootfs が通常ファイル。
            (t.base.join("file"), "rootfs_symlink_or_not_directory"),
            (t.base.join("absent"), "rootfs_missing"),
        ] {
            let err = open_dir_beneath(&rootfs, &proc).unwrap_err();
            assert_eq!(err.code, ErrorCode::InvalidArgument, "{rootfs:?}");
            assert_eq!(
                violation_of(&err),
                ("mount_target", reason, "CORE-1", s(&rootfs)),
                "{rootfs:?}"
            );
        }
        // 固定した fd は rootfs を改名しても同じ実体（改名後の rootfs 配下）を指し続ける。
        let fd = open_dir_beneath(&root, &proc).unwrap();
        let moved = t.base.join("moved");
        std::fs::rename(&root, &moved).unwrap();
        assert_eq!(
            std::fs::read_link(format!("/proc/thread-self/fd/{}", fd.as_raw_fd())).unwrap(),
            moved.join("proc")
        );
    }

    /// Codex P0（固定後のマウント先の移動）: fd の現在の位置が target と一致するときだけ
    /// 真で、改名・移動・削除の後は偽になる。
    #[test]
    fn fd_still_at_detects_moved_or_removed_target() {
        let t = TempTree::new("moved-target");
        let root = t.base.join("root");
        std::fs::create_dir_all(root.join("proc")).unwrap();
        std::fs::create_dir_all(root.join("gone")).unwrap();
        let proc = root.join("proc");
        let fd = open_dir_beneath(&root, &[OsStr::new("proc")]).unwrap();
        assert!(fd_still_at(&fd, &proc));
        // `.` を含む表記でも同じ位置と判定する（`Path::components` は先頭以外の `.` を
        // 正規化で取り除くため、絶対パスでは `.` による誤検出はない。Cursor Bugbot 指摘の確認）。
        assert!(fd_still_at(&fd, &root.join("./proc/.")));
        assert!(fd_still_at(&fd, &t.base.join("./root/./proc")));
        // rootfs の外へ移動。
        let outside = t.base.join("outside");
        std::fs::rename(&proc, &outside).unwrap();
        assert!(!fd_still_at(&fd, &proc));
        assert!(fd_still_at(&fd, &outside));
        // 削除（リンク先に " (deleted)" が付く）。
        let gone = root.join("gone");
        let fd = open_dir_beneath(&root, &[OsStr::new("gone")]).unwrap();
        std::fs::remove_dir(&gone).unwrap();
        assert!(!fd_still_at(&fd, &gone));
    }

    /// SEC-4（記録経路）: 移動の拒否に付く違反記録の具体値。
    #[test]
    fn target_moved_violation_metadata() {
        let err = ExecError::from_violation(ViolationReason::TargetMoved, Some(Path::new("/r/p")));
        assert_eq!(err.code, ErrorCode::FailedPrecondition);
        assert_eq!(err.stage, IsolationStage::MountProc);
        assert_eq!(
            err.message,
            "mount target was moved or removed after validation"
        );
        assert_eq!(
            violation_of(&err),
            (
                "mount_target",
                "target_moved",
                "CORE-1",
                Some("/r/p".to_string())
            )
        );
    }

    fn sub_maps(euid: u32, egid: u32) -> (IdMapSet, IdMapSet) {
        let r = rootless::SubordinateRange::new(100_000, 65_536).unwrap();
        (
            rootless::rootless_mapping(euid, &[r]).unwrap(),
            rootless::rootless_mapping(egid, &[r]).unwrap(),
        )
    }

    /// `Direct` writer が許す形（自 ID への単一行）の写像。
    fn single_maps(euid: u32, egid: u32) -> (IdMapSet, IdMapSet) {
        (
            rootless::single_id_mapping(euid).unwrap(),
            rootless::single_id_mapping(egid).unwrap(),
        )
    }

    /// CORE-6・SEC-5（TASK-40.2）: 非特権の `Direct` writer と範囲写像（複数行）の組み合わせは、
    /// 副作用の前に計画段階で `InvalidArgument` として拒否する。
    #[test]
    fn core6_sec5_subordinate_plan_rejects_direct_with_range_mapping() {
        let (u, g) = sub_maps(1000, 1000);
        let err = plan_subordinate_for(
            &cfg(NamespaceSet::all(), None),
            u,
            g,
            IdMapWriter::Direct,
            Duration::from_secs(5),
            1000,
            1000,
        )
        .unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidArgument);
        assert_eq!(err.stage, IsolationStage::Validate);
    }

    fn sub_plan(
        ns: NamespaceSet,
        euid: u32,
        egid: u32,
        timeout_secs: u64,
    ) -> Result<SubordinateIsolationPlan, ExecError> {
        let (u, g) = single_maps(1000, 1000);
        plan_subordinate_for(
            &cfg(ns, None),
            u,
            g,
            IdMapWriter::Direct,
            Duration::from_secs(timeout_secs),
            euid,
            egid,
        )
    }

    /// CORE-6・SEC-5（TASK-40.2）: 正常系は計画の各値がそのまま保たれる。
    #[test]
    fn core6_sec5_subordinate_plan_keeps_values() {
        let plan = sub_plan(NamespaceSet::all(), 1000, 1000, 5).unwrap();
        let (u, g) = single_maps(1000, 1000);
        assert_eq!(plan.namespaces, NamespaceSet::all());
        assert_eq!((plan.euid, plan.egid), (1000, 1000));
        assert_eq!(plan.uid, u);
        assert_eq!(plan.gid, g);
        assert_eq!(plan.timeout, Duration::from_secs(5));
        assert_eq!(plan.writer, IdMapWriter::Direct);
        assert!(sub_plan(NamespaceSet::all(), 1000, 1000, 1).is_ok());
        assert!(sub_plan(NamespaceSet::all(), 1000, 1000, 60).is_ok());
    }

    /// CORE-6・SEC-5（TASK-40.2）: user namespace 無しは違反記録付きで拒否する。
    #[test]
    fn core6_sec5_subordinate_plan_requires_user_namespace() {
        let ns = NamespaceSet::empty()
            .with(Namespace::Pid)
            .with(Namespace::Mount);
        let err = sub_plan(ns, 1000, 1000, 5).unwrap_err();
        assert_eq!(violation_of(&err).1, "user_namespace_required", "{err}");
    }

    /// CORE-6・SEC-5（TASK-40.2）: euid / egid が 0 の起動は拒否する。
    #[test]
    fn core6_sec5_subordinate_plan_rejects_host_root() {
        for (u, g) in [(0, 1000), (1000, 0), (0, 0)] {
            let err = sub_plan(NamespaceSet::all(), u, g, 5).unwrap_err();
            assert_eq!(violation_of(&err).1, "host_root_identity_mapping");
        }
    }

    /// CORE-6・SEC-5（TASK-40.2）: コンテナ 0 が起動ユーザー以外へ写る構成は `InvalidArgument`。
    #[test]
    fn core6_sec5_subordinate_plan_rejects_foreign_container_root() {
        let err = sub_plan(NamespaceSet::all(), 1001, 1000, 5).unwrap_err();
        assert_eq!(
            (err.code, err.stage),
            (ErrorCode::InvalidArgument, IsolationStage::Validate)
        );
        let err = sub_plan(NamespaceSet::all(), 1000, 1001, 5).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidArgument);
    }

    /// CORE-6（TASK-40.2）: timeout は 1..=60 秒の外を副作用の前に拒否する。
    #[test]
    fn core6_subordinate_plan_rejects_timeout_out_of_range() {
        for secs in [0, 61] {
            let err = sub_plan(NamespaceSet::all(), 1000, 1000, secs).unwrap_err();
            assert_eq!(err.code, ErrorCode::InvalidArgument, "{secs}s");
        }
    }

    /// CORE-6（TASK-40.2）: `without` は対象だけを除く。
    #[test]
    fn core6_namespace_set_without_removes_only_target() {
        let s = NamespaceSet::all().without(Namespace::User);
        assert!(!s.contains(Namespace::User));
        for ns in [
            Namespace::Pid,
            Namespace::Mount,
            Namespace::Uts,
            Namespace::Ipc,
        ] {
            assert!(s.contains(ns));
        }
        assert_eq!(
            NamespaceSet::empty()
                .with(Namespace::User)
                .without(Namespace::User),
            NamespaceSet::empty()
        );
    }

    /// CORE-3（TASK-32.4）: cgroup 参加の失敗は `code` を保ち、段は `CgroupJoin`、message に
    /// cgroup 側の段名を含む。
    #[test]
    fn core3_task32_4_exec_error_from_cgroup_keeps_code_and_names_stage() {
        use crate::cgroups::{CgroupError, CgroupStep};
        let e = ExecError::from_cgroup(CgroupError {
            code: ErrorCode::PermissionDenied,
            step: CgroupStep::JoinContainer,
            message: "denied".to_string(),
        });
        assert_eq!(e.code, ErrorCode::PermissionDenied);
        assert_eq!(e.stage, IsolationStage::CgroupJoin);
        assert_eq!(e.message, "JoinContainer: denied");
        assert!(e.violation.is_none());
    }

    /// CORE-6（TASK-40.2）: rootless の失敗は `code` を保ち、段は `UserNamespaceMap`、message に
    /// rootless 側の段名を含む。
    #[test]
    fn core6_exec_error_from_rootless_keeps_code_and_names_stage() {
        let e = ExecError::from_rootless(RootlessError {
            code: ErrorCode::PermissionDenied,
            stage: rootless::RootlessStage::UidMap,
            message: "denied".to_string(),
        });
        assert_eq!(e.code, ErrorCode::PermissionDenied);
        assert_eq!(e.stage, IsolationStage::UserNamespaceMap);
        assert_eq!(e.message, "uid_map: denied");
        assert!(e.violation.is_none());
    }

    /// CORE-6（TASK-40.2）: 計画作成後に実行 ID が変わっていれば副作用の前に拒否する
    /// （現在の euid と異なる値を持つ計画を直接作る）。libtest はマルチスレッドだが、ID 再検証は
    /// fork より前なので fork 段まで進まない。
    #[test]
    fn core6_isolate_subordinate_rejects_changed_identity() {
        let other = sys::effective_uid().wrapping_add(1).max(1);
        let (u, g) = single_maps(other, other);
        let mut plan = plan_subordinate_for(
            &cfg(NamespaceSet::all(), None),
            u,
            g,
            IdMapWriter::Direct,
            Duration::from_secs(1),
            other,
            other,
        )
        .unwrap();
        plan.egid = other;
        let err = isolate_rootless_subordinate(&plan).unwrap_err();
        assert_eq!(violation_of(&err).1, "identity_changed");
    }

    /// CORE-6（TASK-40.2）: マルチスレッドからは fork 段で副作用なしに `FailedPrecondition` で拒否される
    /// （handshake の実動作は結合試験 `rootless_launch` で確認する）。保護用のスレッドを明示的に立て、
    /// 単一スレッド実行でも実際に fork / unshare へ進まないようにする。root（euid 0）では計画の段階で
    /// `host_root_identity_mapping` で拒否されることを照合する。
    #[test]
    fn core6_isolate_subordinate_refuses_multithreaded_caller() {
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        let guard = std::thread::spawn(move || {
            let _ = rx.recv();
        });
        let (euid, egid) = (sys::effective_uid(), sys::effective_gid());
        let (u, g) = single_maps(euid, egid);
        let planned = plan_subordinate_for(
            &cfg(NamespaceSet::all(), None),
            u,
            g,
            IdMapWriter::Direct,
            Duration::from_secs(1),
            euid,
            egid,
        );
        if euid == 0 || egid == 0 {
            let err = planned.unwrap_err();
            assert_eq!(violation_of(&err).1, "host_root_identity_mapping");
        } else {
            let err = isolate_rootless_subordinate(&planned.unwrap()).unwrap_err();
            assert_eq!(
                (err.code, err.stage),
                (ErrorCode::FailedPrecondition, IsolationStage::Spawn)
            );
        }
        tx.send(()).unwrap();
        guard.join().unwrap();
    }
}
