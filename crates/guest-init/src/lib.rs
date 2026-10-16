//! macOS ゲスト VM の initrd に入れる Rust 製 PID 1（MAC-1・MAC-2・TASK-64 追補・#1875・MS-5）。
//!
//! # 役割
//!
//! `fandhe-container-platform-macos` の `Vm::launch` が起動したゲストカーネルが最初に実行する。
//! 責務は次の 3 点に限る（4 は試験専用の追加）。
//!
//! 1. `/proc`・`/sys`・`/dev` を mount する。
//! 2. カーネルコマンドラインの `fandhe.virtiofs=<tag>:<mountpoint>:<ro|rw>` を untrusted として復号し、
//!    virtiofs を mount して共有ごとに 1 行を hvc0 へ報告する（[`process::process_directives`]）。
//! 3. 起動完了マーカー [`READY_MARKER`] を出し、以後は終了しない。
//! 4. （試験専用）予約キー `fandhe.guest-test=virtiofs-io` があり、`fandhe-io` の RW mount が成功したときだけ、
//!    ready の後に共有の read / readdir / write のプローブ行を出す（[`probe`]。MAC-1・IO-5・#1876）。
//!    キーはホストの `reject_reserved_keys` により利用者指定では注入できず、本番の起動では走らない。
//!
//! # ホストとの契約
//!
//! SSOT はホスト側の `fandhe_container_platform_macos::guest_mount`（指示の書式・報告の書式・定数）。
//! 本 crate は静的なゲストバイナリへバックエンドを入れないため、規則を同じ内容で持ち直し
//! （[`directive`]・[`report`]）、`tests/contract.rs` が dev-dependency 経由で定数・復号結果・報告行の
//! 一致を機械照合する。契約を変えるときはホスト側と本 crate を同時に直す。
//!
//! # 失敗時の方針（fail-closed）
//!
//! 指示に 1 件でも不正があれば 1 件も mount しない。致命的な初期化失敗では [`READY_MARKER`] を出さない。
//! PID 1 が終了するとカーネルが panic するため、どの経路でも終了せず待機する。
//!
//! # 未実装（REPAIR-3）
//!
//! - 協調停止: `reboot(2)` 等は呼ばない。VM の停止はホストの VZ の強制停止に任せる（TASK-115）。
//! - 子プロセスの回収（`waitpid`）: 現状は子を作らない。ゲスト内でコンテナを実行する際に実装する。
//! - 静的リンクの実ビルド・initrd への梱包は #1878、symlink・ハードリンクの観測モードは #1877、実機起動は #1628。

pub mod cmdline;
pub mod directive;
pub mod probe;
pub mod process;
pub mod report;

#[cfg(target_os = "linux")]
mod init;
#[cfg(target_os = "linux")]
mod sys;

#[cfg(target_os = "linux")]
pub use init::run;

/// 起動完了マーカー（初期化に成功し、指示の処理を終えた後に 1 行だけ出す）。
///
/// ホストの `vm_boot` では `FANDHE_CONTAINER_MACOS_VM_READY_MARKER` にこの文字列を指定する。
/// 既定のブートマーカー `Linux version`・報告行の接頭辞・`virtiofs_io` のプローブ接頭辞のいずれとも
/// 一致・包含の関係にない（単体テストで照合）。
pub const READY_MARKER: &str = "fandhe-guest: init ready v1";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac1_ready_marker_does_not_collide() {
        assert_eq!(READY_MARKER, "fandhe-guest: init ready v1");
        // vm_boot の既定ブートマーカーと一致・包含の関係にない（validate_marker_pair が panic するため）。
        assert!(!READY_MARKER.contains("Linux version"));
        assert!(!"Linux version".contains(READY_MARKER));
        assert!(!READY_MARKER.starts_with(report::REPORT_PREFIX));
        assert!(!READY_MARKER.starts_with(report::PROBE_NAMESPACE));
    }
}
