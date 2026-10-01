//! OCI Runtime ライフサイクル（TASK-29・CORE-2・OCI-4）の置き場。
//!
//! bundle の `config.json` を型として読み込む `config`（TASK-29.1.1）と、
//! `mounts[].destination` の正規化・トラバーサル拒否 `mount_destination`（TASK-29.1.2）、
//! プロセス未起動の状態初期化 `create`（TASK-29.2）が実装済み。
//! `start`（TASK-29.3）も実装済みだが、起動は依存注入する `ProcessLauncher` に委ねており、本番
//! launcher と実プロセスの exec は未提供（制限ステージ TASK-37〜39 待ちで fail-closed）。
//! `kill`（TASK-30.1。送信は依存注入する `ProcessSignaler` に委ね、本番実装は supervisor〔TASK-157〕待ち）
//! も実装済み。`delete`（TASK-30.2）は `StateStore` のレコード削除までで、状態ファイル・cgroup の
//! 削除は TASK-30.3 で追加する予定で未実装である（REPAIR-3: 実装済みを装わない）。モジュールは
//! `cfg(target_os)` を付けず 3 OS でビルドされる（CLI-1）。
//! create / start / kill / delete は依存注入された `OpRecorder` へ固定の操作名（`create`・`start`・`kill`・
//! `delete`）で成功 / 失敗と所要時間を記録する（REPAIR-4・TASK-84.4。delete は TASK-30.2 で同じ
//! `record_op` パターンにより計装）。
//! 例外は start の rootfs 固定（`RootfsDir::pin`。`exec::open_dir_beneath` を使う）と
//! `ContainerChildProcess` で、`launch.rs` 内に `cfg(target_os = "linux")` で局所化している。Linux 以外の
//! start は rootfs を固定できないため、起動前に `Unimplemented` で拒否する（fail-closed）。

mod config;
mod create;
mod delete;
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
pub use delete::delete;
pub use kill::{KillTimeout, ProcessSignaler, kill};
#[cfg(target_os = "linux")]
pub use launch::ContainerChildProcess;
pub use launch::{
    LaunchSpec, LaunchedProcess, ProcessExit, ProcessLauncher, RootfsDir, START_TIMEOUT_MAX,
    StartTimeouts,
};
pub use mount_destination::{MountDestination, audit_mount_config_error};
pub use start::{
    LAUNCHER_REPLY_GRACE, StartedContainer, recover_interrupted_start, start,
    take_unreaped_processes,
};
