//! fandhe-container-plugin-microvm: microVM 制御 plugin バイナリ（`fandhe-container-microvm` の実装を別プロセス化）。
//!
//! 現状は雛形のみで、実装はない（TASK-1.3・REPAIR-1。スタブの明示は REPAIR-3）。
//! 本体は G8（TASK-117）で実装する。`fandhe-container-plugin`（境界機構）の UDS フレームを介して
//! core と通信し、`fandhe-container-microvm` の KVM 制御を実行する。PLUG-1 区分は plugin（crate-naming.md）。
//! rust-vmm 系クレートへの依存は禁止（MVM-4・.claude/rules/dependency-policy.md）。
