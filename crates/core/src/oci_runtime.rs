//! OCI Runtime ライフサイクル（TASK-29・CORE-2・OCI-4）の置き場。
//!
//! bundle の `config.json` を型として読み込む `config`（TASK-29.1.1）と、
//! `mounts[].destination` の正規化・トラバーサル拒否 `mount_destination`（TASK-29.1.2）、
//! プロセス未起動の状態初期化 `create`（TASK-29.2）が実装済み。
//! `start`（TASK-29.3）も実装済みで、起動は依存注入する `ProcessLauncher` に委ねる。本番 launcher
//! `ProductionLauncher`（`launcher.rs`。Linux。#1816）は実装済みで、`confirm_no_process`（#1817）は launcher 自身が
//! 起動した範囲の確認まで実装済み（別プロセスで起動した残存の確認は未対応）。supervisor の呼び出しスレッドの再構成（#1819）は未実装である（REPAIR-3）。
//! 実プロセスで通す実機前提の結合試験は `tests/production_launcher.rs`（#1818。`-- --ignored`。実機での実行結果の記録は #1621）。
//! `kill`（TASK-30.1。送信は依存注入する `ProcessSignaler` に委ね、本番実装は supervisor〔TASK-157〕待ち）
//! も実装済み。`delete`（TASK-30.2・TASK-30.3）は cgroup（依存注入する `ContainerCgroupRemover`。Linux の
//! 本番実装は `cgroups::DelegatedCgroup`）と `StateStore` のレコード（状態ファイル）を削除する。OCI-7 の
//! 参照登録・解除は `create_with_image` / `delete_releasing_image_ref`（TASK-183.8.1。依存注入する
//! `ContainerImageRefs` 経由）が担い、本番のアダプタは cli の `StoreImageRefs`（#2315）で CLI から配線済み、plugin 経由の配線は未実装である
//! （REPAIR-3: 実装済みを装わない）。イメージのレイヤーを rootfs へ展開する依存注入口 `ImageRootfsUnpacker`
//! （#2342）も同様で、`create_with_image` が展開先の作成・展開・失敗時の後始末を担い、作った rootfs は状態に記録して delete が状態削除の後に消す（#2378）。本番の展開器は未実装である。モジュールは
//! `cfg(target_os)` を付けず 3 OS でビルドされる（CLI-1）。
//! create / start / kill / delete は依存注入された `OpRecorder` へ固定の操作名（`create`・`start`・`kill`・
//! `delete`）で成功 / 失敗と所要時間を記録する（REPAIR-4・TASK-84.4。delete は TASK-30.2 で同じ
//! `record_op` パターンにより計装）。
//! 失敗を表すエラー型 `OciRuntimeError` と終了コード対応表 `exit_code_for`（ERR-2・TASK-96.1）は定義済み。
//! create / start / kill / delete の失敗は `OciRuntimeError` で返し、標準エラー向け 1 行 JSON は `write_json_line` で
//! 出せる（TASK-96.2・TASK-96.3）。実 stderr への書き出しとプロセス終了は CLI 側（TASK-79・TASK-95）の
//! 責務で未結線である（REPAIR-3）。
//! launcher が fork 前に cgroup 要件を検査する関数 `require_cgroup_join`（#1814・CORE-3）も置く。
//! `mounts[]` の bind mount の指定を検証済みの型へ変換する `bind_mounts`（#1911）は型と検証で、適用の段は `exec` に実装済み
//! （#1912〜#1914）、`start` と本番 launcher へも結線済み（#1915。検証済みの集合は `LaunchSpec::bind_mounts` で渡る）。
//! bind 以外の種類の `mounts[]` は未対応で `start` が拒否する（REPAIR-3）。
//! 例外は start の rootfs 固定（`RootfsDir::pin`。`exec::open_dir_beneath` を使う。検証後の差し替えの違反は
//! `RootfsPinError` で運び、exec の経路が監査ログの層 `mount` へ記録する。start の経路は `build_spec` が launcher の拒否の記録先へ記録する。#2623・#1702）と
//! `ContainerChildProcess` で、`launch.rs` 内に `cfg(target_os = "linux")` で局所化している。Linux 以外の
//! start は rootfs を固定できないため、起動前に `Unimplemented` で拒否する（fail-closed）。

mod bind_mounts;
mod cgroup_requirement;
mod config;
mod create;
mod delete;
mod error;
mod image_refs;
mod image_rootfs;
mod kill;
mod launch;
mod launch_options;
mod launcher;
mod mount_destination;
pub(crate) mod mountinfo_identity;
mod resources;
mod start;
mod sysfs_mount;
mod working_dir;

#[cfg(target_os = "linux")]
pub(crate) use bind_mounts::ProtectedFsRoot;
pub use bind_mounts::{
    BindMountError, BindMountErrorKind, BindMountSet, BindMountSpec, audit_bind_mount_error,
};
pub use cgroup_requirement::{
    CgroupJoinMeans, CgroupRequirement, launch_after_cgroup_check, require_cgroup_join,
};
pub use config::{
    CONFIG_MAX_ADDITIONAL_GIDS, CONFIG_MAX_ARGS, CONFIG_MAX_BYTES, CONFIG_MAX_ENV,
    CONFIG_MAX_HOSTNAME_BYTES, CONFIG_MAX_ID_MAPPINGS, CONFIG_MAX_MASKED_PATHS,
    CONFIG_MAX_MOUNT_OPTIONS, CONFIG_MAX_MOUNTS, CONFIG_MAX_NAMESPACES,
    CONFIG_MAX_OCI_VERSION_BYTES, CONFIG_MAX_PATH_BYTES, CONFIG_MAX_READONLY_PATHS,
    CONFIG_MAX_STRING_BYTES, CONFIG_MAX_THROTTLE_DEVICES, NamespaceKind, OciConfig, OciConfigError,
    OciConfigErrorKind, OciIdMapping, OciMount, OciNamespace, OciProcess, OciRoot, OciUser,
    OciVersion, UnappliedField, load_config, parse_config_bytes,
};
pub use create::{
    create, create_audited, create_with_image, create_with_image_audited, load_resource_limits,
    load_resource_limits_audited,
};
pub use delete::{
    CgroupRemoval, ContainerCgroupRemover, DeleteOptions, delete, delete_releasing_image_ref,
    delete_releasing_image_ref_with_options, delete_with_options,
};
pub use error::{
    LifecycleOp, OCI_ERROR_MESSAGE_MAX_BYTES, OCI_EXIT_ALREADY_EXISTS,
    OCI_EXIT_FAILED_PRECONDITION, OCI_EXIT_INTERNAL, OCI_EXIT_INVALID_ARGUMENT, OCI_EXIT_NOT_FOUND,
    OCI_EXIT_PERMISSION_DENIED, OCI_EXIT_TIMEOUT, OCI_EXIT_UNAVAILABLE, OCI_EXIT_UNIMPLEMENTED,
    OciRuntimeError, exit_code_for,
};
pub use image_refs::{
    ContainerImage, ContainerImageRefs, ImageManifestDigest, ImageRefGeneration,
    ImageRefRegistration, ImageRefRelease,
};
pub use image_rootfs::{
    ImageRootfsPrivilege, ImageRootfsUnpacked, ImageRootfsUnpacker, ReapOptions,
    StagingReclamation, UnverifiedReason, reap_stale_unpacks, reap_stale_unpacks_with,
};
pub use kill::{KillTimeout, ProcessSignaler, kill};
#[cfg(target_os = "linux")]
pub use launch::ContainerChildProcess;
#[cfg(feature = "exec-test-support")]
#[doc(hidden)]
pub use launch::pin_bundle_rootfs_with_swap_for_test;
pub use launch::{
    ContainerOutput, LaunchMode, LaunchSpec, LaunchedProcess, ProcessExit, ProcessLauncher,
    RootfsDir, RootfsPinError, START_TIMEOUT_MAX, StartTimeouts, pin_bundle_rootfs,
    pin_bundle_rootfs_audited,
};
pub use launch_options::{LaunchIpcMode, LaunchOptions};
pub use launcher::{ProductionLauncher, ProductionLauncherBuilder};
#[cfg(target_os = "linux")]
pub use launcher::{SubordinateIdMaps, SubordinateIdSource};
pub use mount_destination::{MountDestination, audit_mount_config_error};
pub use resources::{ByteLimit, CgroupsPath, IoThrottle, LinuxResourceLimits};
#[cfg(feature = "exec-test-support")]
#[doc(hidden)]
pub use start::claim_start_with_pin_swap_for_test;
pub use start::{
    ClaimedStart, LAUNCHER_REPLY_GRACE, StartedContainer, claim_start, launch_claimed,
    recover_interrupted_start, start, take_unreaped_processes,
};
#[cfg(target_os = "linux")]
pub(crate) use sysfs_mount::OciMountKind;
pub use sysfs_mount::{
    SysfsMountError, SysfsMountErrorKind, SysfsMountSpec, audit_sysfs_mount_error,
};
pub use working_dir::ContainerWorkingDir;
