//! プロジェクト単位 CLI（`up` / `down` / `ps` / `logs`）の stack 側ロジック（STACK-8・TASK-155・MS-12）。
//!
//! 本体はサブモジュールに置き、兄弟 issue が同じファイルを奪い合わないようにする。
//! 現状は `up`（TASK-155.1・#618）・`down`（TASK-155.3・#620）・`ps`（TASK-155.4・#621）。
//! ネットワーク接続は #619、`logs` は #622 で追加する予定（未実装。実装済みを装わない。REPAIR-3）。
//! 本番アダプタと CLI のサブコマンドへの結線は #3639 で追う。

pub mod down;
pub mod ps;
pub mod up;

pub use down::{
    DownError, DownFailure, DownReport, DownStepReport, ServiceStopper, StopError, StopOutcome,
    down,
};
pub use ps::{
    MAX_PS_NAME_BYTES, MAX_PS_OUTPUT_BYTES, MAX_PS_SERVICES, PsError, PsLimit, PsReport, PsRow,
    ServiceStatus, ServiceStatusSource, ps,
};

pub use up::{
    LaunchError, LaunchedService, ServiceLauncher, UpClock, UpError, UpFailure, UpPolicy, UpReport,
    UpStepReport, up,
};
