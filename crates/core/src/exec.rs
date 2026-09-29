//! 実行層の最小実行フロー（CORE-1・TASK-27・MS-2）を担うモジュール。
//!
//! 現状は未実装のスタブであり、関数・型は置かない（REPAIR-3: 実装済みを装わない）。
//! 後続の sub-issue（#134〜#137・#831〜#834）が本モジュールへ追記する土台である。
//!
//! # 目指すフロー（Linux 専用）
//!
//! 1. namespace 分離（PID / mount / UTS / IPC / user。#134・TASK-27.2）
//! 2. `pivot_root` による rootfs 切替と旧 root の後始末（#135・TASK-27.3）
//! 3. 基本デバイスノード 6 種の作成（#834・TASK-27.6。実体は別モジュール `devices` の予定）
//! 4. 順序固定のステージ列: cgroup 参加 → capability 削減 → `PR_SET_NO_NEW_PRIVS`
//!    → Landlock → seccomp（#136・#832・#833。後続の TASK-32・37・38・39・40 が差し込む）。
//!    `NO_NEW_PRIVS` を Landlock / seccomp より前に固定する順序は fail-closed の前提で、
//!    後続実装はこの順序を崩さない
//! 5. `fork` / `exec`（#831・TASK-27.4）
//!
//! # 前提・契約
//!
//! - 本モジュールは `#[cfg(target_os = "linux")]` でモジュールごとビルド対象から外れる。
//!   macOS / Windows ではコンテナはゲスト VM（Linux）内で実行されるため、ホスト側から
//!   直接呼ぶ経路は存在しない（非 Linux ビルドの確認は #137・TASK-27.5）
//! - syscall を呼ぶ `unsafe` は将来の `sys` モジュールに閉じ込め、本ファイルには置かない
//! - 呼び出し元は TASK-29 の `oci_runtime`（`create` / `start`）を想定する
//! - 常駐デーモンを前提にしない（CORE-1・D-19）
