//! fandhe-container-gpu: GPU CDI spec 解析・edits 適用・Landlock/seccomp・cgroup device・読み取り専用 rootfs。
//!
//! 現状は CDI spec の読み込み基盤（`cdi_spec`。TASK-126.1・GPU-1）と containerEdits の集計（`cdi_edits`。
//! TASK-126.2・GPU-1）・usr-merge のパス正規化（`cdi_paths`。TASK-126.3・GPU-1・MS-10）のみ実装済みで、edits 適用・Landlock/seccomp・cgroup device 等は未実装（REPAIR-3）。残りは G9（TASK-126〜135）で実装する。macOS Venus（GPU-6）は対象・実装機構が異なる別枠で、
//! 成果物は `fandhe-container-plugin-macos` 側に置かれる。PLUG-1 区分は core（推奨。crate-naming.md 注 1）。

pub mod cdi_edits;
pub mod cdi_paths;
pub mod cdi_spec;
