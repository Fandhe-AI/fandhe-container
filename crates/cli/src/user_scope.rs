//! `systemd-run` の探索と信頼判定、実行ユーザーの判定の再エクスポート（CORE-3・CORE-4・PLUG-11・CLI-1・#2133）。
//!
//! 実体は `fandhe_container_supervisor::systemd_run` にある（plugin-cri の `start` と判定を共有するため移設した。
//! #2434・REPAIR-1）。CLI の `doctor`（`doctor::user_scope_check`・`doctor::id_mapping_check`）が従来の
//! `crate::user_scope` の名前のまま使えるよう、ここで再エクスポートする。探索と信頼の基準・既知の限界（NixOS）は
//! 移設先の module doc を参照する。

pub(crate) use fandhe_container_supervisor::systemd_run::{
    Identity, SYSTEMD_RUN_NAME, SystemdRunRejection, identity_from_status, read_self_status,
    resolve_systemd_run, systemd_run_candidates,
};
