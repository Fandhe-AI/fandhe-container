//! OCI Runtime ライフサイクル（TASK-29・CORE-2・OCI-4）の置き場。
//!
//! 現状は bundle の `config.json` を型として読み込む `config` のみ実装済み（TASK-29.1.1）。
//! create / start / kill / delete は TASK-29.2・29.3・30 で追加する予定で、現時点では未実装である
//! （REPAIR-3: 実装済みを装わない）。純粋なデータ処理のため `cfg(target_os)` を付けず 3 OS で
//! ビルドされる（CLI-1）。

mod config;

pub use config::{
    CONFIG_MAX_ADDITIONAL_GIDS, CONFIG_MAX_ARGS, CONFIG_MAX_BYTES, CONFIG_MAX_ENV,
    CONFIG_MAX_HOSTNAME_BYTES, CONFIG_MAX_ID_MAPPINGS, CONFIG_MAX_MOUNT_OPTIONS, CONFIG_MAX_MOUNTS,
    CONFIG_MAX_NAMESPACES, CONFIG_MAX_OCI_VERSION_BYTES, CONFIG_MAX_PATH_BYTES,
    CONFIG_MAX_STRING_BYTES, NamespaceKind, OciConfig, OciConfigError, OciConfigErrorKind,
    OciIdMapping, OciMount, OciNamespace, OciProcess, OciRoot, OciUser, OciVersion, load_config,
    parse_config_bytes,
};
