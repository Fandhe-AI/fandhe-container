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
//! - `cri`・`platform-*`・`microvm`・`plugin-*` には依存しない
//!
//! # モジュール構成
//!
//! - `traits`: 拡張点トレイト（実装済み。TASK-4 系）
//! - `exec`: 最小実行フロー（Linux 限定。namespace 分離〔TASK-27.2〕と `pivot_root` による
//!   rootfs 切替〔TASK-27.3〕、基本デバイスノード作成〔TASK-27.6。`exec/devices.rs`。
//!   Issue 表記の `src/devices.rs` ではなく `exec` 配下に置く: 段の型 `ExecError`・`MountIsolation`
//!   の検証が `exec` の非公開項目のため〕、fork / exec による子プロセス起動〔TASK-27.4.1。最小構成でフック無し〕、順序固定のステージ列の枠〔TASK-27.4.2。`exec/stages.rs`。`NO_NEW_PRIVS`〔TASK-27.4.3〕と capability 削減〔TASK-37.2〕のみ固定ステージとして実装済み〕が
//!   実装済みで、Landlock は `with_landlock` で差し込み可能・cgroup 参加は未実装（seccomp は #178 で組み込み済み）。非 Linux ではビルド対象外のため本 doc からは
//!   リンクしない）
//! - `audit_log`: 分離違反の監査レコード型 `AuditRecord` 等（SEC-4・TASK-41.1・#192。OS 非依存で
//!   型定義・マウント検証/API の記録ヘルパ〔TASK-41.4〕・seccomp フック〔TASK-41.2・#193。拒否報告→レコード→`AuditSink`〕・ローカルファイル書き込み主経路〔TASK-41.5.1・#839〕は実装済み。Landlock のフック〔TASK-41.3・#194。`landlock_denial_record` / `landlock_denial_record_now` と
//!   `exec::observe_landlock_path_access` による適用後プローブの拒否記録〕も実装済み。配送経路〔TRAP / USER_NOTIF /
//!   カーネル監査〕・ワークロードプロセスが受けた Landlock 拒否の捕捉は未実装。主経路失敗時のカーネル監査フォールバック〔#840 `KernelAuditFallback`〕は実装済み・本番経路への配線は未実装）
//! - `capabilities`: capability 集合の型 `Capability`・`CapabilitySet`・OCI 既定集合（SEC-1・
//!   TASK-37.1）。OS 非依存で syscall を持たない。適用関数 `apply_default_capabilities` は
//!   `exec/capabilities.rs`（Linux 限定）に置く: 段の型 `ExecError` の非公開コンストラクタと
//!   errno 分類を再利用するため（`exec/devices.rs` と同じ判断）。ステージ列へは #173（TASK-37.2）で組み込み済み
//! - `observability`: メトリクス集計型 `OpStats` 等（TASK-84.1）と記録 API `OpRecorder`
//!   （TASK-84.2）は実装済み（REPAIR-4）。JSON Lines 出力（TASK-84.3）も実装済み。create / start / kill の計装は実装済み（TASK-84.4）、delete も TASK-30.2 で同じパターンにより計装済み。io 向け連携点は io 側に定義済み（TASK-84.5）
//! - `landlock`: Landlock ABI 検出（TASK-39.1・#181）とパスルール生成（TASK-39.2・#182）と ruleset 適用（TASK-39.3・#183）を実装済み（Linux 限定。CORE-5）。ステージ列への組み込み口（`StagePipeline::with_landlock`・TASK-39.4・#184）は実装済みで、本番 launcher からの呼び出しと制限適用の証跡配線は後続作業。
//! - `rootless`: user namespace の UID/GID 写像の設定・読み戻し検証（Linux 限定。CORE-6・SEC-5・
//!   TASK-40.1）。検証済み写像型・subuid/subgid 解析・`Direct` / `newuidmap` 経由の書き込みが実装済みで、
//!   `exec::isolate_rootless_subordinate` による起動フローへの組み込みも実装済み（TASK-40.2）。
//!   `linux.uidMappings` の受理は後続、ファイル所有者検証（TASK-40.3）は未実装
//! - `seccomp`: 禁止 syscall の一覧 `DeniedSyscall` と x86_64 / aarch64 別の番号テーブル（CORE-5・
//!   TASK-38.1.1・#837。OS 非依存で syscall を持たない）。テーブルと BPF 構築
//!   （TASK-38.1.2・#838）は実装済み。フィルタ適用（TASK-38.2）と起動フローへの組み込み（TASK-38.3）も実装済み
//! - `sys`: syscall・FFI の薄いラッパー（Linux 限定・非公開。`unsafe` の事前承認範囲）
//! - `oci_runtime`: OCI Runtime のライフサイクル。`config.json` の型・パーサ
//!   （TASK-29.1.1）と create（プロセス未起動の状態初期化。TASK-29.2）は実装済み・OS 非依存。
//!   start（TASK-29.3）は実装済みだが起動は `ProcessLauncher` の依存注入で、本番 launcher と実 exec は未提供。
//!   kill（TASK-30.1）も実装済みで、送信は `ProcessSignaler` の依存注入（本番実装は supervisor 待ち）。delete（TASK-30.2・TASK-30.3）は cgroup（`ContainerCgroupRemover` の依存注入）と `StateStore` のレコードの削除を実装済みで、OCI-7 の参照解除は TASK-183 で未実装。
//!   失敗のエラー型 `OciRuntimeError`（ERR-2・TASK-96.1）は定義済みで、4 操作（create / start / kill / delete）は結線済み・`write_json_line` で stderr 向け 1 行を出せる（TASK-96.2・TASK-96.3）。実 stderr 出力・終了は CLI 側で未実装
//! - `state_store`: ファイルベース `StateStore`（TASK-31.1・OCI-5）は実装済み。3 OS でコンパイルされるが
//!   使えるのは Linux のみで、他 OS の `FileStateStore::open` は状態ルートの信頼境界（所有者・ACL）を
//!   検査できないため `Unimplemented`（fail-closed。start の `BundleLock` と同じ扱い）。
//!   fsync・残骸掃除の強化は TASK-31.2（#156）、結合テスト（ライフサイクル経由の `state.json` 照合）は TASK-31.3（#157）で実装済み。CLI と supervisor の書き込み排他（`@lock`＋期限つき `try_lock`＋revision による楽観的排他）の検証・明文化は TASK-157.9（#1069）
//! - `cgroups`: 委譲 cgroup v2 の検出・コンテナ用子 cgroup 作成・自プロセス退避の検証・controller
//!   有効化・`memory.max` / `memory.swap.max` 設定・`cpu.max` 設定（Linux 限定。TASK-32.1・TASK-32.2・
//!   TASK-32.3・CORE-3 は実装済み。TASK-32.4 は fork 後の子の `cgroup.procs` 参加フック `CgroupJoin` まで実装済み。本番 launcher からの結線は未実装）
//! - `plugin_discovery`: 管理ディレクトリ（system / user）からの plugin 候補探索（TASK-109.1・PLUG-4・PLUG-11）と `PATH` 探索の opt-in・警告ログ（TASK-109.2）は実装済み・OS 非依存。
//!   候補は未検証。opt-in の CLI フラグ配線（TASK-79）・レジストリ（TASK-109.3）・信頼性検証（TASK-122）は未実装
//!
//! # プラットフォーム対応（TASK-27.5・CORE-1）
//!
//! - `exec`・`sys` は `lib.rs` の `#[cfg(target_os = "linux")]` でビルド対象から外れ、
//!   `sys.rs` も内側の `#![cfg]` で二重に隔離している。`traits` は OS 非依存で 3 OS に公開される
//! - `sys` の `extern "C"` 宣言と `unsafe` は glibc / musl の型幅・syscall 番号を前提とするため、
//!   前提の成り立たない macOS / Windows でコンパイル・リンクさせない（安全上の理由での隔離）
//! - 新しい Linux 専用コードは `exec` / `sys` 配下に置く。それ以外に置く場合は
//!   `cfg(target_os = "linux")` で局所化する（CLI-1）
//! - 非 Linux ビルドの保証は CI の macOS / Windows ネイティブ runner での
//!   ビルド・clippy `-D warnings` が担う（3 OS 一級対応）
//!
//! 実行層本体（namespace・cgroups v2・seccomp/Landlock・rootless 等）は G3（TASK-27〜50）で
//! 実装する未実装のままである（REPAIR-3: 実装済みを装わず、未実装であることも隠さない）。

pub mod audit_log;
pub mod capabilities;
#[cfg(target_os = "linux")]
pub mod cgroups;
#[cfg(target_os = "linux")]
pub mod exec;
#[cfg(target_os = "linux")]
pub mod landlock;
pub mod observability;
pub mod oci_runtime;
pub mod plugin_discovery;
#[cfg(target_os = "linux")]
pub mod rootless;
pub mod seccomp;
pub mod state_store;
#[cfg(target_os = "linux")]
mod sys;
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
