//! fandhe-container-supervisor: コンテナごとの軽量監視プロセス（restart・healthcheck・exec・logs・stats）。
//!
//! 常駐デーモンを持たない設計（CORE-1・D-19）の実装主体で、コンテナ 1 つにつき 1 プロセスで監視する（SUP-1）。
//! PLUG-1 区分は core（plugin 境界〔PLUG-2〕を経由せず実行層コアの一部。crate-naming.md）。
//!
//! 現状は状態配線（[`state`]。TASK-157.3）・監視ループ基本（[`run`]。TASK-157.4）・restart の土台（TASK-157.5。`restart_count` の加算は TASK-159.3 で再 launch 成功時へ移設）・healthcheck フック（[`health`]。TASK-157.6。コマンド実行は未実装）・logs 捕捉の土台（[`logs`]。TASK-157.7。ファイルへのローテーション書き込みは TASK-164.2・#506 で実装済み、フラッシュ制御・大規模検証は SUP-7・TASK-164.3/4 で未実装）が実装済みで、終了分類と restart ポリシー評価（[`restart`]。TASK-159.1・#487／TASK-159.2・#488。呼び出し側への配線は未実装）と、再起動ループ（バックオフ・注入式の再 launch・`restart_count` 管理・state.json 反映。#489・TASK-159.3）も実装済みで、本番 launcher による再 launch の実機での成立（#2043）・明示的 stop の検知（SUP-9）等は未実装（TASK-1.3・TASK-157.1〔#235〕・REPAIR-1。スタブの明示は REPAIR-3）。
//! inspect 相当の機械可読出力（[`inspect`]。TASK-168.1・#523・SUP-11）も実装済みで、出力をパースして型・値域・キー順・値を照合する結合テスト（TASK-168.2・#524。メモリ上のフェイクは 3 OS、実ストアは Linux）（`tests/inspect_output.rs`）も併置済み（CLI 配線は未実装）。
//! cgroup 統計の読み取り・パース（[`stats`]。SUP-10・TASK-167.1・#520）と機械可読形式（JSON Lines）での出力（TASK-167.2・#521）も実装済みで、`stats` の CLI 配線は未実装。
//! `--shm-size` / `--tmpfs` の解析と core の仕様型への変換（[`container_options`]。SUP-12・TASK-169.2・#527）と secrets / configs の指定モデル（TASK-169.4.2・#1473）も実装済みで、launcher・CLI 配線は未実装。
//! 本体は G12（TASK-157〜171）で、次の分割に沿って実装する。
//!
//! | issue | TASK | 内容 |
//! | ----- | ---- | ---- |
//! | #236 | TASK-157.2 | core への状態型追加 |
//! | #237 | TASK-157.3 | core の `StateStore` 配線（supervisor から使う） |
//! | #238 | TASK-157.4 | 監視ループ基本（実装済み） |
//! | #239 | TASK-157.5 | restart の土台（実装済み。ポリシーと加算は #487〜#489 で実装） |
//! | #240 | TASK-157.6 | healthcheck フックの土台（実装済み。コマンド実行・周期実行は TASK-161） |
//! | #493 | TASK-161.1 | healthcheck 定義パース（[`healthcheck`]。実装済み） |
//! | #495 | TASK-161.2 | healthcheck 周期実行エンジン（[`healthcheck::run_periodic`]。実装済み。exec を呼ぶ判定の実装・`monitor` ループへの組み込みは未実装で #2441 が担う。REPAIR-3） |
//! | #496 | TASK-161.3 | `health` の state.json 反映（[`healthcheck::HealthAggregator`]・[`health::probe_aggregate_and_record`]。retries・start_period・`Starting`。実装済み。SUP-4） |
//! | #241 | TASK-157.7 | logs 捕捉の土台（実装済み。永続化・ローテーションは #506 で実装） |
//! | #505 | TASK-164.1 | 行単位捕捉（実装は #241。バッファ境界跨ぎを検証済み。ローテーション書き込みは #506） |
//! | #506 | TASK-164.2 | ローテーションログ書き込み（[`logs::rotating`]。実装済み。Windows の世代 rename の共有違反は有界再試行・ロックのファイル ID 照合・読み出し入口 `open_for_read` は #1470 で追補。フラッシュ制御は #507、100 万行規模の欠落 0・重複 0 検証は #508 で `tests/log_rotation.rs` に実装済み。ロックファイルの掃除は #1469 で `remove_all`・`open` 失敗時の削除を追加。`logs` 読み出しは #1543 で `logs::read_container_log` を実装済み・実パイプ取得も未実装） |
//! | #242 | TASK-157.8 | 結合テスト |
//! | #500 | TASK-163.1 | exec: pid1 特定・setns（`exec`。実装済み。コマンド実行は未実装） |
//! | #501 | TASK-163.2 | exec: cgroup join（`exec`。実装済み。コマンド実行は未実装） |
//! | #502 | TASK-163.3 | exec: seccomp / Landlock 再適用（`exec`。実装済み。コマンド実行は未実装） |
//! | #503 | TASK-163.4 | exec: fork・execve と統合テスト（未実装） |
//! | #1069 | TASK-157.9 | state.json 書き込み排他 |
//! | #487 | TASK-159.1 | 終了検知・終了コード分類（実装済み） |
//! | #526 | TASK-169.1 | ulimit の指定モデル（[`container_options`]。適用は core の exec ステージ `Rlimits`。launcher 未結線のため消費者は無い。REPAIR-3） |
//! | #528 | TASK-169.3 | `--ipc`（host / shareable）の指定モデル（[`container_options::ipc`]。Linux では core の `NamespaceSet` へ反映。他コンテナからの join は未実装。REPAIR-3） |
//! | #529 | TASK-169.4 | env / env ファイル（[`container_options::env`]。実装済み。secrets / configs 注入は #1473 で実装） |
//! | #1473 | TASK-169.4.2 | secrets / configs の指定モデル（[`container_options::secrets`]。`ContainerOptions::injected_files` で core の注入仕様型へ変換し、core の `exec::inject_files` が専用 tmpfs へ書き込み後に read-only 化する。launcher・CLI・stack 未結線。REPAIR-3） |
//! | #855 | TASK-169.5.1 | label（`--label`。[`container_options::labels`]。core の `StateRecord::annotations` 経由で state.json へ反映。CLI・launcher 未結線。REPAIR-3） |
//! | #856 | TASK-169.5.2 | 全オプション同時指定の結合テスト（`tests/container_options.rs`）。`--ipc=host` と `--shm-size` の併用は `ContainerOptions::tmpfs_set` が拒否 |
//! | #488 | TASK-159.2 | restart ポリシー評価（実装済み） |
//! | #858 | TASK-171.1.2 | 権限昇格の必要最小集合と検証ロジック（[`privilege`]。実装済み） |
//! | #1717 | TASK-157 追補 | bin の入口（`src/main.rs`・[`start_entry`]）と CLI との起動の契約（[`start_contract`]）。|
//! | #1819 | TASK-157 追補 | `ProductionStartDeps` を core の本番 launcher（`ProductionLauncher`）へ結線（手順 8 は入口スレッドが直接行う）。restart の再 launch は単一スレッドの要求を満たせず fail-closed（#2043）。実機前提の通し試験は `tests/supervisor_bin_real.rs`。REPAIR-3 |
//! | #1475 | TASK-171.1.3 | 権限昇格の実体 `privilege::elevate`（承認済みの方式〔#1454〕。縮退の syscall 適用と読み戻し検証は実装済み。fd 検証付き exec・入口検証・ランチャー bin は #1719 で実装） |
//! | #1719 | TASK-171 追補 | 特権ランチャー bin `fandhe-container-launcher`（[`launcher`]。入口検証 → `elevate` → 検証済み fd の `execveat`。hash / 署名照合・ambient の子での解除〔healthcheck exec。#2441〕・実機検証〔#538・#539〕は未実装。REPAIR-3） |
//! | #1543 | TASK-79 追補 | `logs` でコンテナログの内容を読み出す（[`logs::reader`]。ディレクトリは `<root>/@container-logs`。CLI-1・SUP-7） |
//! | #2067 | TASK-79 追補 | supervisor の構造化ログ（stderr）の保存先（[`supervisor_log`]。`<root>/@supervisor-logs/<id>.log*`。REPAIR-4） |
//! | #2446 | TASK-164 追補 | CLI の `delete` と plugin-cri の `RemoveContainer`（#2593・CRI-2）でコンテナログ（`<root>/@container-logs/<id>.log*`）を消す入口（[`logs::remove_container_logs`]・期限つきは [`logs::remove_container_logs_bounded`]。SUP-7・CLI-1） |
//! | #2133 | CORE-3・CORE-4 | systemd user マネージャへの到達検査（`user_scope`。Linux のみ。CLI の start・doctor とベンチが共有） |
//! | #2243 | TASK-157 追補 | rootless の ID 写像モデルの選択（`RootlessSingleId` か範囲写像 `RootlessSubordinateIds` か。条件と所有者名の取得は `id_model`、結線は `ProductionStartDeps`）。CORE-6・SEC-5。実機での確認は #1621 |
//! | #2058 | TASK-157 追補 | CLI からのシグナル送信を受ける制御チャネル（[`control`]。コンテナごとの UDS。サーバ・クライアント入口〔`ControlSignaler`〕は実装済み。CLI の `stop` への結線は済み〔#2059〕、`kill` への結線〔#1902〕・stop の意図の伝達〔SUP-9〕は未実装。REPAIR-3） |
//! | #489 | TASK-159.3 | restart_count 管理・state.json 反映・結合テスト（実装済み。本番 launcher での再 launch の成立は #2043） |
//! | #523 | TASK-168.1 | state.json 読み取り・inspect 出力フォーマット（実装済み） |
//! | #524 | TASK-168.2 | inspect 出力のパース検証結合テスト（`tests/inspect_output.rs`。#523 で先行追加し、#524 でキー順・型・値域・列挙値の照合を追加。実装済み） |
//!
//! supervisor から `fandhe-container-core` への一方向依存は導入済み（TASK-157.3・#237）。
//! `StateStore` は core の既定実装を使い、2 つ目の実装は持たない（決定 6）。

// `exec-test-support` は試験専用の入口（期待 cgroup パスを呼び出し側から受け取る対象特定・`execveat` を伴わない
// 観測・worker 機構の直接呼び出し）を公開する feature で、リリースビルドで有効にすると SEC-1 の同一性照合を
// 迂回できる。最適化ビルド（`debug_assertions` が無効）で有効になっていたらコンパイルを止める
// （SUP-6・SEC-1・REPAIR-3・TASK-163 追補・#1460。テスト・clippy は dev プロファイルのため影響しない）。
#[cfg(all(feature = "exec-test-support", not(debug_assertions)))]
compile_error!(
    "the `exec-test-support` feature exposes test-only exec entry points and must not be enabled in release builds"
);

pub mod cgroup_remover;
pub mod container_options;
pub mod control;
mod deadline_store;
#[cfg(target_os = "linux")]
pub mod exec;
pub mod health;
pub mod healthcheck;
#[cfg(any(target_os = "linux", test))]
pub mod id_model;
pub mod inspect;
pub mod launcher;
#[cfg(any(target_os = "linux", test))]
pub mod launcher_probe;
pub mod log_pipeline;
pub mod logs;
pub mod privilege;
pub mod restart;
pub mod run;
pub mod seccomp_notify;
#[cfg(target_os = "linux")]
pub mod start_client;
pub mod start_contract;
pub mod start_entry;
pub mod state;
pub mod stats;
pub mod stderr_sink;
pub mod supervisor_log;
#[cfg(any(windows, target_os = "linux"))]
mod sys;
#[cfg(target_os = "linux")]
pub mod systemd_run;
pub mod user_db;
#[cfg(target_os = "linux")]
pub mod user_scope;
