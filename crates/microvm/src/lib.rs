//! fandhe-container-microvm: KVM 直接制御・最小 virtio デバイスモデル（Linux オプション）。
//!
//! 実装済み（TASK-74.1.1・MVM-1。Linux のみ）: `/dev/kvm` のオープン・API 版数 12 の確認・`KVM_CREATE_VM` による
//! VM fd の取得（`error` は OS 非依存、`device` は Linux 限定）。未実装: vCPU・ゲストメモリ・virtio・実行ループ
//! （TASK-74.1.2〜TASK-75。REPAIR-3）。実行時は `fandhe-container-plugin-microvm`（TASK-117）が
//! 本 crate を別プロセスとして動かす。PLUG-1 区分は plugin 境界の外側（バックエンド実装ライブラリ。crate-naming.md）。
//! `unsafe` は `src/sys.rs` に限る。rust-vmm 系クレートへの依存は禁止（MVM-4・.claude/rules/dependency-policy.md）。

#[cfg(target_os = "linux")]
pub mod device;
pub mod error;
#[cfg(target_os = "linux")]
mod sys;
