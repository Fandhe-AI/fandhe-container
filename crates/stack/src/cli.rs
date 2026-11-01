//! プロジェクト単位 CLI（`up` / `down` / `ps` / `logs`）の stack 側ロジック（STACK-8・TASK-155・MS-12）。
//!
//! 本体はサブモジュールに置き、兄弟 issue が同じファイルを奪い合わないようにする。
//! 現状は `up`（TASK-155.1・#618、ネットワーク接続の計画と注入ポート TASK-155.2・#619）のみ。
//! `down` / `ps` / `logs` は #620〜#622 で追加する予定（未実装。実装済みを装わない。REPAIR-3）。
//! 本番アダプタと CLI のサブコマンドへの結線は #3639 で追う。

pub mod up;

pub use up::{
    LaunchError, LaunchRequest, LaunchedService, NetworkAttachment, NetworkDriver, NetworkPlan,
    NetworkPlanError, NetworkProvisionError, NetworkProvisioner, NetworkRequest, ProvisionOutcome,
    ProvisionedNetwork, ServiceLauncher, UpClock, UpError, UpFailure, UpPolicy, UpProject,
    UpReport, UpStepReport, plan_networks, up,
};
