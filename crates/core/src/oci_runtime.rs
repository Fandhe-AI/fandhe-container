//! OCI Runtime ライフサイクル（TASK-29・CORE-2・OCI-4）の置き場。
//!
//! bundle の `config.json` を型として読み込む `config`（TASK-29.1.1）と、
//! `mounts[].destination` の正規化・トラバーサル拒否 `mount_destination`（TASK-29.1.2）、
//! プロセス未起動の状態初期化 `create`（TASK-29.2）が実装済み。
//! `start`（TASK-29.3）も実装済みだが、起動は依存注入する `ProcessLauncher` に委ねており、本番
//! launcher と実プロセスの exec は未提供（制限ステージ TASK-37〜39 待ちで fail-closed）。
//! `kill`（TASK-30.1。送信は依存注入する `ProcessSignaler` に委ね、本番実装は supervisor〔TASK-157〕待ち）
//! も実装済み。`delete`（TASK-30.2・TASK-30.3）は cgroup（依存注入する `ContainerCgroupRemover`。Linux の
//! 本番実装は `cgroups::DelegatedCgroup`）と `StateStore` のレコード（状態ファイル）を削除する。OCI-7 の
//! 参照解除は TASK-183 で未実装である（REPAIR-3: 実装済みを装わない）。モジュールは
//! `cfg(target_os)` を付けず 3 OS でビルドされる（CLI-1）。
//! create / start / kill / delete は依存注入された `OpRecorder` へ固定の操作名（`create`・`start`・`kill`・
//! `delete`）で成功 / 失敗と所要時間を記録する（REPAIR-4・TASK-84.4。delete は TASK-30.2 で同じ
//! `record_op` パターンにより計装）。
//! 失敗を表すエラー型 `OciRuntimeError` と終了コード対応表 `exit_code_for`（ERR-2・TASK-96.1）は定義済み。
//! create / start / kill / delete の失敗は `OciRuntimeError` で返し、標準エラー向け 1 行 JSON は `write_json_line` で
//! 出せる（TASK-96.2・TASK-96.3）。実 stderr への書き出しとプロセス終了は CLI 側（TASK-79・TASK-95）の
//! 責務で未結線である（REPAIR-3）。
//! 例外は start の rootfs 固定（`RootfsDir::pin`。`exec::open_dir_beneath` を使う）と
//! `ContainerChildProcess` で、`launch.rs` 内に `cfg(target_os = "linux")` で局所化している。Linux 以外の
//! start は rootfs を固定できないため、起動前に `Unimplemented` で拒否する（fail-closed）。

mod config;
mod create;
mod delete;
mod error;
mod kill;
mod launch;
mod mount_destination;
mod start;

pub use config::{
    CONFIG_MAX_ADDITIONAL_GIDS, CONFIG_MAX_ARGS, CONFIG_MAX_BYTES, CONFIG_MAX_ENV,
    CONFIG_MAX_HOSTNAME_BYTES, CONFIG_MAX_ID_MAPPINGS, CONFIG_MAX_MOUNT_OPTIONS, CONFIG_MAX_MOUNTS,
    CONFIG_MAX_NAMESPACES, CONFIG_MAX_OCI_VERSION_BYTES, CONFIG_MAX_PATH_BYTES,
    CONFIG_MAX_STRING_BYTES, NamespaceKind, OciConfig, OciConfigError, OciConfigErrorKind,
    OciIdMapping, OciMount, OciNamespace, OciProcess, OciRoot, OciUser, OciVersion, UnappliedField,
    load_config, parse_config_bytes,
};
pub use create::create;
pub use delete::{CgroupRemoval, ContainerCgroupRemover, delete};
pub use error::{
    LifecycleOp, OCI_ERROR_MESSAGE_MAX_BYTES, OCI_EXIT_ALREADY_EXISTS,
    OCI_EXIT_FAILED_PRECONDITION, OCI_EXIT_INTERNAL, OCI_EXIT_INVALID_ARGUMENT, OCI_EXIT_NOT_FOUND,
    OCI_EXIT_PERMISSION_DENIED, OCI_EXIT_TIMEOUT, OCI_EXIT_UNAVAILABLE, OCI_EXIT_UNIMPLEMENTED,
    OciRuntimeError, exit_code_for,
};
pub use kill::{KillTimeout, ProcessSignaler, kill};
#[cfg(target_os = "linux")]
pub use launch::ContainerChildProcess;
pub use launch::{
    LaunchSpec, LaunchedProcess, ProcessExit, ProcessLauncher, RootfsDir, START_TIMEOUT_MAX,
    StartTimeouts, pin_bundle_rootfs,
};
pub use mount_destination::{MountDestination, audit_mount_config_error};
pub use start::{
    LAUNCHER_REPLY_GRACE, StartedContainer, recover_interrupted_start, start,
    take_unreaped_processes,
};
