//! fandhe-container-supervisor: コンテナごとの軽量監視プロセス（restart・healthcheck・exec・logs・stats）。
//!
//! 常駐デーモンを持たない設計（CORE-1・D-19）の実装主体で、コンテナ 1 つにつき 1 プロセスで監視する（SUP-1）。
//! PLUG-1 区分は core（plugin 境界〔PLUG-2〕を経由せず実行層コアの一部。crate-naming.md）。
//!
//! 現状は状態配線（[`state`]。TASK-157.3）・監視ループ基本（[`run`]。TASK-157.4）・restart の土台（TASK-157.5。`restart_count` の加算は TASK-159.3 で再 launch 成功時へ移設）・healthcheck フック（[`health`]。TASK-157.6。コマンド実行は未実装）・logs 捕捉の土台（[`logs`]。TASK-157.7。永続化・ローテーションは SUP-7・TASK-164 で未実装）が実装済みで、終了分類と restart ポリシー評価（[`restart`]。TASK-159.1・#487／TASK-159.2・#488。呼び出し側への配線は未実装）と、再起動ループ（バックオフ・注入式の再 launch・`restart_count` 管理・state.json 反映。#489・TASK-159.3）も実装済みで、本番 launcher による再 launch・明示的 stop の検知（SUP-9）等は未実装（TASK-1.3・TASK-157.1〔#235〕・REPAIR-1。スタブの明示は REPAIR-3）。
//! inspect 相当の機械可読出力（[`inspect`]。TASK-168.1・#523・SUP-11）も実装済みで、出力をパースして型・値域・キー順・値を照合する結合テスト（TASK-168.2・#524。メモリ上のフェイクは 3 OS、実ストアは Linux）（`tests/inspect_output.rs`）も併置済み（CLI 配線は未実装）。
//! cgroup 統計の読み取り・パース（[`stats`]。SUP-10・TASK-167.1・#520）と機械可読形式（JSON Lines）での出力（TASK-167.2・#521）も実装済みで、`stats` の CLI 配線は未実装。
//! `--shm-size` / `--tmpfs` の解析と core の仕様型への変換（[`container_options`]。SUP-12・TASK-169.2・#527）も実装済みで、launcher・CLI 配線は未実装。
//! 本体は G12（TASK-157〜171）で、次の分割に沿って実装する。
//!
//! | issue | TASK | 内容 |
//! | ----- | ---- | ---- |
//! | #236 | TASK-157.2 | core への状態型追加 |
//! | #237 | TASK-157.3 | core の `StateStore` 配線（supervisor から使う） |
//! | #238 | TASK-157.4 | 監視ループ基本（実装済み） |
//! | #239 | TASK-157.5 | restart の土台（実装済み。ポリシーと加算は #487〜#489 で実装） |
//! | #240 | TASK-157.6 | healthcheck フックの土台（実装済み。コマンド実行・周期実行は TASK-161） |
//! | #493 | TASK-161.1 | healthcheck 定義パース（[`healthcheck`]。実装済み。実行・周期は #495、`health` 反映は #496 で未実装） |
//! | #241 | TASK-157.7 | logs 捕捉の土台（実装済み。永続化・ローテーションは SUP-7・TASK-164 で未実装） |
//! | #505 | TASK-164.1 | 行単位捕捉（実装は #241。バッファ境界跨ぎを検証済み。永続化・ローテーションは #506 以降で未実装） |
//! | #242 | TASK-157.8 | 結合テスト |
//! | #500 | TASK-163.1 | exec: pid1 特定・setns（`exec`。実装済み。コマンド実行は未実装） |
//! | #501〜#503 | TASK-163.2〜163.4 | exec: cgroup join・seccomp / Landlock 再適用・execve と統合テスト（未実装） |
//! | #1069 | TASK-157.9 | state.json 書き込み排他 |
//! | #487 | TASK-159.1 | 終了検知・終了コード分類（実装済み） |
//! | #526 | TASK-169.1 | ulimit の指定モデル（[`container_options`]。適用は core の exec ステージ `Rlimits`。launcher 未結線のため消費者は無い。REPAIR-3） |
//! | #528 | TASK-169.3 | `--ipc`（host / shareable）の指定モデル（[`container_options::ipc`]。Linux では core の `NamespaceSet` へ反映。他コンテナからの join は未実装。REPAIR-3） |
//! | #529 | TASK-169.4 | env / env ファイル（[`container_options::env`]。実装済み。secrets / configs 注入は tmpfs 機構〔#527〕のマージ待ちで未実装。REPAIR-3） |
//! | #488 | TASK-159.2 | restart ポリシー評価（実装済み） |
//! | #858 | TASK-171.1.2 | 権限昇格の必要最小集合と検証ロジック（[`privilege`]。実装済み。昇格 syscall 経路・setuid・fd 検証付き exec は方式承認待ちで未実装。REPAIR-3） |
//! | #489 | TASK-159.3 | restart_count 管理・state.json 反映・結合テスト（実装済み。本番 launcher は未実装） |
//! | #523 | TASK-168.1 | state.json 読み取り・inspect 出力フォーマット（実装済み） |
//! | #524 | TASK-168.2 | inspect 出力のパース検証結合テスト（`tests/inspect_output.rs`。#523 で先行追加し、#524 でキー順・型・値域・列挙値の照合を追加。実装済み） |
//!
//! supervisor から `fandhe-container-core` への一方向依存は導入済み（TASK-157.3・#237）。
//! `StateStore` は core の既定実装を使い、2 つ目の実装は持たない（決定 6）。

pub mod container_options;
#[cfg(target_os = "linux")]
pub mod exec;
pub mod health;
pub mod healthcheck;
pub mod inspect;
pub mod logs;
pub mod privilege;
pub mod restart;
pub mod run;
pub mod state;
pub mod stats;
