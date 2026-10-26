//! CDI の containerEdits を実行層へ渡せる形へ変換する適用層の入口（TASK-127・GPU-2・MS-10）。
//!
//! `cdi_edits` が集計した [`crate::cdi_edits::AggregatedEdits`] を、core が受理する形へ純粋関数で
//! 変換する。実際の mount・mknod・hook 実行は core 側の既存経路が担い（docs/architecture.md の境界表）、
//! 本層は FS に触れない。
//!
//! 実装範囲（REPAIR-3）:
//! - [`mounts`]: `mounts`（bind mount の指定への変換。TASK-127.2・#548）。実装済み
//! - `deviceNodes`（TASK-127.1・#547）・`hooks`（TASK-127.3・#549）・`env`（TASK-127.4・#550）・
//!   `netDevices` の適用は未実装で、本モジュールには存在しない。各タスクが `cdi_apply/<関心事>.rs` を足す

pub mod mounts;
