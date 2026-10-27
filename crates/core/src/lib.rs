//! fandhe-container-core: 実行層（namespace・cgroups v2・seccomp/Landlock・rootless・ログ・状態管理）。
//!
//! # 役割
//!
//! コンテナを起動・分離する実行層（CORE-1・TASK-27）と、拡張点トレイト定義
//! （`traits`。TASK-4・CRI-7・MS-0）を担う。`StateStore` トレイトとファイルベースの
//! 既定実装も本 crate に置く（TASK-31・OCI-5・決定 6）。PLUG-1 区分は core
//! （crate-naming.md）。中央の常駐デーモンは持たない（CORE-1・D-19）。
//!
//! # 責務境界・依存方向
//!
//! - `core` は `io` に依存する想定（`VolumeProvider` のデータパス）。`io` は core に依存しない
//! - `supervisor` は core に依存する（`StateStore` 既定実装を core に一本化。決定 6）
//! - `ContainerRuntime`・`NetworkPlugin` の実装は別プロセス＋UDS の plugin 側に置く（PLUG-1）。
//!   plugin の追加で core を変更しない（PLUG-4）
//! - `plugin` feature 有効時のみ `fandhe-container-plugin`（境界基盤）に依存する（既定で有効。PLUG-3・
//!   TASK-111.1）。無効化は `--no-default-features`
//! - `cri`・`platform-*`・`microvm`・`plugin-*` には依存しない
//!
//! # モジュール構成
//!
//! - `traits`: 拡張点トレイト（実装済み。TASK-4 系）
//! - `sanitize`: 表示を乱す文字（Cc・Cf・Zl・Zp）の判定と有界追記の共通実装（公開 API `sanitize_display_bounded` は cli も利用。ERR-2・SEC-4・TASK-96.1）
//! - `exec`: 最小実行フロー（Linux 限定。稼働中コンテナへの exec〔SUP-6・TASK-163.1〜163.4。pid1 特定と `setns(2)` 参加は `exec/setns.rs`、cgroup join は `exec/cgroup_join.rs`、制限の再適用は `exec/reapply.rs`、fork・`close_range`・`execveat` は `exec/exec_command.rs`。user namespace への参加は未実装で、対象が別の user namespace にいれば拒否する。実コンテナへの通し試験は実機前提で、CI では実行していない〕も持つ。`mounts[]` の sysfs を読み取り専用で `/sys` に供給する段〔`exec/sysfs.rs`・#2020・SEC-2〕も持つ。namespace 分離〔TASK-27.2〕と `pivot_root` による
//!   rootfs 切替〔TASK-27.3〕、基本デバイスノード作成〔TASK-27.6。`exec/devices.rs`。
//!   Issue 表記の `src/devices.rs` ではなく `exec` 配下に置く: 段の型 `ExecError`・`MountIsolation`
//!   の検証が `exec` の非公開項目のため〕、fork / exec による子プロセス起動〔TASK-27.4.1。最小構成でフック無し〕、順序固定のステージ列の枠〔TASK-27.4.2。`exec/stages.rs`。`NO_NEW_PRIVS`〔TASK-27.4.3〕と capability 削減〔TASK-37.2〕のみ固定ステージとして実装済み〕が
//!   実装済みで、Landlock は `with_landlock` で差し込み可能・cgroup 参加は未実装（seccomp は #178 で組み込み済み）。非 Linux ではビルド対象外のため本 doc からは
//!   リンクしない）
//! - `audit_log`: 分離違反の監査レコード型 `AuditRecord` 等（SEC-4・TASK-41.1・#192。OS 非依存で
//!   型定義・マウント検証/API の記録ヘルパ〔TASK-41.4〕・seccomp フック〔TASK-41.2・#193。拒否報告→レコード→`AuditSink`〕・ローカルファイル書き込み主経路〔TASK-41.5.1・#839〕・exec の対象の拒否の記録ヘルパ〔`exec::audit_exec_violation`・
//!   `exec::record_exec_target_rejection`。層 `exec_target`。#1465〕は実装済み。Landlock のフック〔TASK-41.3・#194。`landlock_denial_record` / `landlock_denial_record_now` と
//!   `exec::observe_landlock_path_access` による適用後プローブの拒否記録〕も実装済み。配送経路〔TRAP / USER_NOTIF /
//!   カーネル監査〕・ワークロードプロセスが受けた Landlock 拒否の捕捉は未実装。主経路失敗時のカーネル監査フォールバック〔#840 `KernelAuditFallback`〕と両者を束ねる本番 sink〔#1594 `FileAuditSink`〕は実装済み・supervisor の exec への構築入口あり・その他の本番経路への配線は未実装）
//! - `capabilities`: capability 集合の型 `Capability`・`CapabilitySet`・OCI 既定集合（SEC-1・
//!   TASK-37.1）。OS 非依存で syscall を持たない。適用関数 `apply_default_capabilities` は
//!   `exec/capabilities.rs`（Linux 限定）に置く: 段の型 `ExecError` の非公開コンストラクタと
//!   errno 分類を再利用するため（`exec/devices.rs` と同じ判断）。ステージ列へは #173（TASK-37.2）で組み込み済み
//! - `observability`: メトリクス集計型 `OpStats` 等（TASK-84.1）と記録 API `OpRecorder`
//!   （TASK-84.2）は実装済み（REPAIR-4）。JSON Lines 出力（TASK-84.3）も実装済み。create / start / kill の計装は実装済み（TASK-84.4）、delete も TASK-30.2 で同じパターンにより計装済み。io 向け連携点は io 側に定義済み（TASK-84.5）
//! - `landlock`: Landlock ABI 検出（TASK-39.1・#181）とパスルール生成（TASK-39.2・#182）と ruleset 適用（TASK-39.3・#183）を実装済み（Linux 限定。CORE-5）。ステージ列への組み込み口（`StagePipeline::with_landlock`・TASK-39.4・#184）は実装済みで、制限適用の証跡は `LaunchReady`（#1714）で配線済み。本番 launcher（`oci_runtime::ProductionLauncher`）からの呼び出しは実装済み（#1816。実プロセスでの確認は `tests/production_launcher.rs`・#1818）。
//! - `legacy_tiocsti`: 起動時に `dev.tty.legacy_tiocsti` を読み、`1` のときだけ警告の構造化ログを 1 行出す（観測のみで起動は止めない。CORE-5・SEC-1・REPAIR-4・#1658 の案 A・#1739。OS 非依存。呼び出し元は `exec::spawn_container_with_stages`〔結合試験専用・`exec-test-support`〕と本番 launcher の入口 `exec::spawn_container_via_intermediate`〔#2008〕）
//! - `logging`: JSON Lines 共通ログ型 `LogLine` 等と書き出し口（TASK-98.1・ERR-4。OS 非依存）。監査ログ（#3115）と `observability` の op_stats（#3116）は移行済み。その他の既存出力の移行は TASK-98.2（#653）で未実装（REPAIR-3）
//! - `rlimits`: rlimit（`process.rlimits`・`--ulimit`）の検証済み型 `Rlimit`・`Rlimits`（SUP-12・TASK-169.1・#526。OS 非依存）。適用は `exec::StagePipeline::with_rlimits`（Linux 限定）で、OCI config からの結線は未実装（REPAIR-3）
//! - `rootless`: user namespace の UID/GID 写像の設定・読み戻し検証（Linux 限定。CORE-6・SEC-5・
//!   TASK-40.1）。検証済み写像型・subuid/subgid 解析・`Direct` / `newuidmap` 経由の書き込みが実装済みで、
//!   `exec::isolate_rootless_subordinate` による起動フローへの組み込みも実装済み（TASK-40.2）。
//!   本番 launcher（`oci_runtime::ProductionLauncher`）経由の流れ（#2009）: 構築時に `SubordinateIdSource` から
//!   subuid / subgid の範囲と `newuidmap` / `newgidmap` の絶対パスを解決・検証し（ホスト ID 0 を含む構成と
//!   helper 欠落は fork 前に拒否）、起動ごとにまず mapper を fork し、その後に中間プロセスが user namespace を unshare する。
//!   mapper は外側の user namespace に残り、helper で写像を書いて読み戻し、応答後に中間プロセスが PID 1 を fork する。
//!   責務境界は、`rootless` が写像の検証・書き込み・読み戻し、`exec` が計画・unshare・mapper の fork と失敗時の回収、
//!   launcher が権限モデルの検査と構築時の解決。supervisor が `RootlessSubordinateIds` を選ぶ経路は未結線（#2243）、
//!   `RootfulHostRoot` は未実装（`Unimplemented`。#2241）。詳細は `oci_runtime` の launcher と `rootless` のモジュール doc を参照。
//!   config 指定の `linux.uidMappings` は start が拒否（受けるかは #2240 で判断待ち。`docs/design/config-id-mappings.md`）、ファイル所有者検証（TASK-40.3）は未実装
//! - `seccomp`: 禁止 syscall の一覧 `DeniedSyscall` と x86_64 / aarch64 別の番号テーブル（CORE-5・
//!   TASK-38.1.1・#837。OS 非依存で syscall を持たない）。テーブルと BPF 構築
//!   （TASK-38.1.2・#838）は実装済み。フィルタ適用（TASK-38.2）と起動フローへの組み込み（TASK-38.3）も実装済み
//! - `container_usage`: `system df` 向けのコンテナ（bundle・rootfs）使用容量の読み取り専用計測（OCI-7・TASK-183・#2222。OS 非依存で `std` のみ。oci へは依存せず呼び出し側が合成する）
//! - `sys`: syscall・FFI の薄いラッパー（Linux 限定・非公開。`unsafe` の事前承認範囲）
//! - `oci_runtime`: OCI Runtime のライフサイクル。`config.json` の型・パーサ
//!   （TASK-29.1.1）と create（プロセス未起動の状態初期化。TASK-29.2）は実装済み・OS 非依存。
//!   start（TASK-29.3）の起動は `ProcessLauncher` の依存注入で、本番 launcher（`ProductionLauncher`・Linux。#1816）は実装済み。supervisor の start 経路は呼び出しスレッドでの直接 launch へ再構成済み（#1819）。restart の再 launch は未対応（#2043）。
//!   kill（TASK-30.1）も実装済みで、送信は `ProcessSignaler` の依存注入（本番実装は supervisor 待ち）。delete（TASK-30.2・TASK-30.3）は cgroup（`ContainerCgroupRemover` の依存注入）と `StateStore` のレコードの削除を実装済みで、OCI-7 の参照解除は TASK-183 で未実装。
//!   失敗のエラー型 `OciRuntimeError`（ERR-2・TASK-96.1）は定義済みで、4 操作（create / start / kill / delete）は結線済み・`write_json_line` で stderr 向け 1 行を出せる（TASK-96.2・TASK-96.3）。実 stderr 出力・終了は CLI 側で未実装
//! - `tmpfs`: tmpfs マウントの検証済み仕様型（`--shm-size` / `--tmpfs`。SUP-12・TASK-169.2）。OS 非依存で、
//!   Linux 限定の適用は `exec::mount_tmpfs`。暗黙の既定 `/dev/shm`（64 MiB）は `TmpfsMountSet::ensure_default_dev_shm`（#1654）。launcher・CLI への配線は未実装（REPAIR-3）
//! - `injected_files`: secrets / configs 注入の検証済み仕様型（SUP-12・TASK-169.4.2）。OS 非依存で、
//!   Linux 限定の適用は `exec::inject_files`（専用 tmpfs へ書き込み後に read-only 化）。配線は未実装（REPAIR-3）
//! - `state_store`: ファイルベース `StateStore`（TASK-31.1・OCI-5）は実装済み。3 OS でコンパイルされるが
//!   使えるのは Linux のみで、他 OS の `FileStateStore::open` は状態ルートの信頼境界（所有者・ACL）を
//!   検査できないため `Unimplemented`（fail-closed。start の `BundleLock` と同じ扱い）。
//!   fsync・残骸掃除の強化は TASK-31.2（#156）、結合テスト（ライフサイクル経由の `state.json` 照合）は TASK-31.3（#157）で実装済み。CLI と supervisor の書き込み排他（`@lock`＋期限つき `try_lock`＋revision による楽観的排他）の検証・明文化は TASK-157.9（#1069）
//! - `cgroups`: 委譲 cgroup v2 の検出・コンテナ用子 cgroup 作成・自プロセス退避の検証・controller
//!   有効化・`memory.max` / `memory.swap.max` 設定・`cpu.max` 設定（Linux 限定。TASK-32.1・TASK-32.2・
//!   TASK-32.3・CORE-3 は実装済み。TASK-32.4 は fork 後の子の `cgroup.procs` 参加フック `CgroupJoin` まで実装済みで、本番 launcher 側の受け口（`ProductionLauncher` の `cgroup_join_source`。#1816）も実装済み。start 経路の supervisor からの供給の結線は #1717。デバイス cgroup の eBPF 命令列の組み立て〔#1678〕まで実装済みで、ロード・アタッチは未実装）
//! - `plugin`: `plugin` feature 配下の境界基盤型の再エクスポートと、照合済み fd から起動対象を作る変換
//!   `HashVerifiedPluginFile::into_launch_target`（PLUG-3・TASK-111.1・#262・PLUG-11・#1857）。
//!   発見・登録・起動の本番配線は未実装
//! - `plugin_discovery`: 管理ディレクトリ（system / user）からの plugin 候補探索（TASK-109.1・PLUG-4・PLUG-11）と `PATH` 探索の opt-in・警告ログ（TASK-109.2）、同名重複を解決する候補レジストリ（TASK-109.3。登録は未検証）は実装済み・OS 非依存。
//!   候補は未検証。opt-in の CLI フラグ配線（TASK-79）・信頼性検証（TASK-122）は未実装
//! - `plugin_trust`: plugin 候補の所有者・モード・symlink 実体解決・sha256 許可済みハッシュ検証・検証方式の切替点（TASK-122.1〜122.4・PLUG-11。既定はハッシュ一覧、署名検証は未実装で指定時は拒否）。fd 経由の fstat・ハッシュ計算で判定し検証済み fd を返す。macOS は実装済み（拡張 ACL を含む。#1865）、Windows は常に拒否。拒否の構造化エラー（code / reason / message）と `PluginTrust` 監査レコード化は TASK-122.5 で実装済み。レジストリ・本番 sink（実装済み `FileAuditSink`）への配線は未実装
//!
//! # プラットフォーム対応（TASK-27.5・CORE-1）
//!
//! - `exec`・`sys`（`sys.rs`）は `lib.rs` の `#[cfg(target_os = "linux")]` でビルド対象から外れ、
//!   `sys.rs` も内側の `#![cfg]` で二重に隔離している。macOS には別ファイル `sys/macos.rs`
//!   （実効 UID・`O_NOFOLLOW | O_NONBLOCK`・拡張 ACL の検出〔`state_store` 用。#2247・OCI-5〕と、
//!   plugin 検証向けの symlink 非追従の fd 相対 open・fd の実体パス取得・fd の拡張 ACL 検出〔`plugin_fs`。
//!   呼び出し元は `plugin_trust`〔#1865〕。#1864・PLUG-11〕のみ）を
//!   `#[cfg(target_os = "macos")]` で取り込み、Linux の宣言は macOS に漏らさない。`traits` は OS 非依存で 3 OS に公開される
//! - `sys` の `extern "C"` 宣言と `unsafe` は glibc / musl の型幅・syscall 番号を前提とするため、
//!   前提の成り立たない macOS / Windows でコンパイル・リンクさせない（安全上の理由での隔離）
//! - 新しい Linux 専用コードは `exec` / `sys` 配下に置く。それ以外に置く場合は
//!   `cfg(target_os = "linux")` で局所化する（CLI-1）
//! - 非 Linux ビルドの保証は CI の macOS / Windows ネイティブ runner での
//!   ビルド・clippy `-D warnings` が担う（3 OS 一級対応）
//!
//! 実行層本体（namespace・cgroups v2・seccomp/Landlock・rootless 等）は G3（TASK-27〜50）で
//! 実装する未実装のままである（REPAIR-3: 実装済みを装わず、未実装であることも隠さない）。

// `exec-test-support` は試験専用の入口（期待 cgroup パスを呼び出し側から受け取る対象特定・`execveat` を伴わない
// 観測・worker 機構の直接呼び出し）を公開する feature で、リリースビルドで有効にすると SEC-1 の同一性照合を
// 迂回できる。最適化ビルド（`debug_assertions` が無効）で有効になっていたらコンパイルを止める
// （SUP-6・SEC-1・REPAIR-3・TASK-163 追補・#1460。テスト・clippy は dev プロファイルのため影響しない）。
#[cfg(all(feature = "exec-test-support", not(debug_assertions)))]
compile_error!(
    "the `exec-test-support` feature exposes test-only exec entry points and must not be enabled in release builds"
);

pub mod audit_log;
pub mod capabilities;
#[cfg(target_os = "linux")]
pub mod cgroups;
pub mod container_usage;
pub mod dev_mounts;
#[cfg(target_os = "linux")]
pub mod exec;
pub mod injected_files;
#[cfg(target_os = "linux")]
pub mod landlock;
pub mod launch_isolation;
pub mod legacy_tiocsti;
pub mod logging;
pub mod observability;
pub mod oci_runtime;
pub mod open_flags;
pub mod path_masks;
#[cfg(feature = "plugin")]
pub mod plugin;
pub mod plugin_discovery;
pub mod plugin_trust;
pub mod rlimits;
#[cfg(target_os = "linux")]
pub mod rootless;
pub mod sanitize;
pub mod seccomp;
pub mod state_store;
#[cfg(target_os = "linux")]
mod sys;
pub mod sysctl;
// macOS 向けの `sys` は別ファイル（Linux の宣言を macOS へ漏らさない。#2247・OCI-5）。
#[cfg(target_os = "macos")]
#[path = "sys/macos.rs"]
mod sys;
#[cfg(test)]
mod test_support;
pub mod tmpfs;
pub mod traits;

/// 非 Linux ビルドの確認（CORE-1・TASK-27.5）。
///
/// 本当のガードは macOS / Windows runner でのコンパイル（clippy `-D warnings`）そのものである。
/// 本テストは OS 非依存の公開面（`traits`）が 3 OS で到達可能であることを具体値で照合した記録。
#[cfg(test)]
mod platform_tests {
    use crate::traits::{ContainerId, ErrorCode};

    #[test]
    fn core1_task27_5_traits_surface_is_os_neutral() {
        let id = ContainerId::new("abc").expect("valid container id");
        assert_eq!(id.as_str(), "abc");
        assert_eq!(ErrorCode::Unimplemented.as_str(), "UNIMPLEMENTED");
    }
}
