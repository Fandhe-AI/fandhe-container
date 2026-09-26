//! fandhe-container-gpu: GPU CDI spec 解析・edits 適用・Landlock/seccomp・cgroup device・読み取り専用 rootfs。
//!
//! 現状は雛形のみで、実装はない（TASK-1.3・REPAIR-1。スタブの明示は REPAIR-3）。
//! 本体は G9（TASK-126〜135）で実装する。macOS Venus（GPU-6）は対象・実装機構が異なる別枠で、
//! 成果物は `fandhe-container-plugin-macos` 側に置かれる。PLUG-1 区分は core（推奨。crate-naming.md 注 1）。
