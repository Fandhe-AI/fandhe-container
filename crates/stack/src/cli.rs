//! プロジェクト単位 CLI（`up` / `down` / `ps` / `logs`）の stack 側ロジック（STACK-8・TASK-155・MS-12）。
//!
//! 本体はサブモジュールに置き、兄弟 issue が同じファイルを奪い合わないようにする。
//! 現状は `up`（TASK-155.1・#618、ネットワーク接続の計画と注入ポート TASK-155.2・#619）・
//! `down`（TASK-155.3・#620）・`ps`（TASK-155.4・#621）・`logs`（TASK-155.5・#622）。
//! 本番アダプタと CLI のサブコマンドへの結線は #3639 で追う。

pub mod down;
pub mod logs;
pub mod ps;
pub mod up;

pub use down::{
    DownError, DownFailure, DownReport, DownStepReport, ServiceStopper, StopError, StopOutcome,
    down,
};
pub use logs::{
    LogSourceError, LogsClock, LogsError, LogsEvent, LogsObserver, LogsOutcome, LogsReport,
    NoopLogsObserver, ServiceLogSource, SystemLogsClock, logs, logs_observed,
};
pub use ps::{
    MAX_PS_NAME_BYTES, MAX_PS_OUTPUT_BYTES, MAX_PS_SERVICES, PsError, PsLimit, PsReport, PsRow,
    ServiceStatus, ServiceStatusSource, ps,
};
pub use up::{
    LaunchError, LaunchRequest, LaunchedService, NetworkAttachment, NetworkDriver, NetworkPlan,
    NetworkPlanError, NetworkProvisionError, NetworkProvisioner, NetworkRequest, ProvisionOutcome,
    ProvisionedNetwork, ServiceLauncher, UpClock, UpError, UpFailure, UpPolicy, UpProject,
    UpReport, UpStepReport, plan_networks, up,
};
