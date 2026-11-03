//! fandhe-container-gpu: GPU CDI spec 解析・edits 適用・Landlock/seccomp・cgroup device・読み取り専用 rootfs。
//!
//! 現状は CDI spec の読み込み基盤（`cdi_spec`。TASK-126.1・GPU-1）と containerEdits の集計（`cdi_edits`。
//! TASK-126.2・GPU-1）・usr-merge のパス正規化（`cdi_paths`。TASK-126.3・GPU-1・MS-10）と、edits 適用のうち createContainer フックの実行と順序強制（`cdi_apply::hooks`。TASK-127.3・GPU-2）・ `deviceNodes` の作成（`cdi_apply`。TASK-127.1・GPU-2。core の実行フローへの配線は未実装）・mounts の bind 指定への変換（`cdi_apply::mounts`。TASK-127.2・GPU-2）、コンテナプロセス env の合成（`cdi_apply::env`。TASK-127.4・GPU-2。core への配線は未実装）が実装済みで、Landlock/seccomp・cgroup device 等は未実装（REPAIR-3）。CDI v1.1.0 の `netDevices` は解析・集計までで、適用は未実装のため `Unimplemented` で拒否する（#2445・GPU-1）。残りは G9（TASK-126〜135）で実装する。macOS Venus（GPU-6）は対象・実装機構が異なる別枠で、
//! 成果物は `fandhe-container-plugin-macos` 側に置かれる。PLUG-1 区分は core（推奨。crate-naming.md 注 1）。

pub mod cdi_apply;
pub mod cdi_edits;
pub mod cdi_paths;
pub mod cdi_spec;

#[cfg(target_os = "linux")]
mod sys;

// pid だけの名前の一時ディレクトリを残骸に強くする共有部品（oci の結合試験の補助を取り込む。
// REPAIR-12・#3375）。試験専用で製品・rlib に影響しない。
#[cfg(test)]
#[path = "../../oci/tests/support/test_root.rs"]
mod test_root;

// 予測できる名前を消さずに排他作成する補助（net の試験補助を取り込む。REPAIR-12・#3479）。
#[cfg(test)]
#[path = "../../net/tests/support/exclusive_dir.rs"]
mod exclusive_dir;
