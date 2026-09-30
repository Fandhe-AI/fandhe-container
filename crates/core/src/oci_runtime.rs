//! OCI Runtime ライフサイクル（TASK-29・CORE-2・OCI-4）の置き場。
//!
//! bundle の `config.json` を型として読み込む `config`（TASK-29.1.1）と、
//! `mounts[].destination` の正規化・トラバーサル拒否 `mount_destination`（TASK-29.1.2）、
//! プロセス未起動の状態初期化 `create`（TASK-29.2）が実装済み。
//! `start`（TASK-29.3）も実装済みだが、起動は依存注入する `ProcessLauncher` に委ねており、本番
//! launcher と実プロセスの exec は未提供（制限ステージ TASK-37〜39 待ちで fail-closed）。
//! kill / delete は TASK-30 で追加する予定で、現時点では未実装である
//! （REPAIR-3: 実装済みを装わない）。純粋なデータ処理のため `cfg(target_os)` を付けず 3 OS で
//! ビルドされる（CLI-1）。

mod config;
mod create;
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
pub use launch::{LaunchSpec, LaunchedProcess, ProcessLauncher};
pub use mount_destination::MountDestination;
pub use start::start;
