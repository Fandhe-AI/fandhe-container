//! fandhe-container-plugin-cri: CRI サーバー plugin バイナリ（`fandhe-container-cri` の実装を別プロセス化）。
//!
//! バイナリの入口（起動引数の解析と終了コードの規則。[`startup`]）と、実装の組み立て口（[`adapter`]。TASK-114.2・#458）、
//! `--socket <PATH>` の UDS 上で `RuntimeService` を gRPC サーブする `server`（unix のみ。TASK-114.3.1・#849・PLUG-1・PLUG-2）がある。
//! core との接続の向きは `docs/design/plugin-backend-wiring.md` 4.9（#1869。承認と実装 issue の起票は #2232）に従い、plugin-cri が gRPC サーバー、
//! core 側（kubelet / crictl 相当）が `fandhe-container-plugin` の `connect_uds_channel` で接続するクライアントである。
//! `ImageService` は同じ UDS・同じ listener でサーブする（`PullImage` の登録先の在庫を `CreateContainer` のタグ解決と共有する。#2592・CRI-3）。
//! 在庫はプロセス内だけで、再起動でタグの対応は失われる（キャッシュは残る）。
//! 未実装（REPAIR-3）: 既定の socket パスの解決と lifecycle からの起動（#459。配線の設計は #1869、承認と実装 issue の起票は #2232）、
//! 在庫の永続化（TASK-183・#2315・#2380）。start / kill / stop と cgroup remover は supervisor 経由で本番結線済み
//! （`supervised`。Linux のみ。#2434）。本番の `BundleProvider`（#2433）も結線済みで、タグ・digest・image ID で `CreateContainer` を受ける。
//! crictl の通し（#442）の pod.json はホストの network namespace（NODE）を指定する（core が pod の network namespace の join を受けるまで。
//! `docs/verification/crictl-smoke.md`）。
//! Container 系 4 RPC の UDS＋gRPC 境界越しの到達と、注入したフェイクでの一連の成功は `tests/container_grpc.rs` で照合済み（#850）。
//! PLUG-12 の別 UID 拒否（実機前提）と正規クライアントの一連は `tests/integration.rs` で照合する（#461）。
//! 状態ルートのインスタンス排他は [`instance_lock`]（`<状態ルート>/.cri/@instance.lock`。起動時に取りプロセスの間持つ。#2931・CRI-2・CORE-1）。
//! SIGTERM・SIGINT による正常停止（受付の停止・実行中の RPC の期限つき待ち・socket の削除・ロックの解放）は `shutdown`・`sys` と `main.rs`（#3226・CRI-1・REPAIR-5。
//! 停止の契約は `docs/design/cri-record-readoption.md`「停止の契約」）。SIGHUP は対象外。
//! ストリーミングサーバー（`Exec`・`Attach`・`PortForward` の URL の先）の loopback 起動と `with_streaming` の注入、停止シグナルでの待ち受けの閉鎖は `streaming`
//! （#3754・CRI-6・REPAIR-5。結線済みは Attach〔Linux は kind 9 の tap と fd の完全版 backend `streaming::supervisor_attach`〔#4077。stdin・tty を受ける。#4078。実機の通しは `tests/cri_attach_real.rs`（#4079）〕、非 Linux は読み取り専用の回転ログの follow の `streaming::log_attach`〔#3763〕〕・PortForward の NODE の pod・Exec〔Linux のみ。supervisor の helper 経由の `streaming::exec_launcher`。tty と相対 `argv[0]` は断る。#3761〕で、POD の PortForward は Linux・非 root で保持役を注入した構成だけ結線済み〔`streaming::ProductionPortForward::pod_network`。#4486〕、それ以外は `UNIMPLEMENTED`。REPAIR-3）。
//! shim v2 バイナリ `containerd-shim-fandhe-container-v2`（`src/bin/containerd_shim_v2.rs`）も本 crate が持つ（#3684・CRI-5・CRI-7・TASK-62.6）。
//! 本番の `ContainerRuntime` が本 crate にしか無く cri から本 crate への依存は禁止のため。登録簿の組み立ては [`shim`]。
//! op-stats のスナップショットファイルを安全に開いて原子的に置き換える部品は [`snapshot_file`]（#4335・CRI-6・REPAIR-4・SEC-1。`telemetry::OpStatsFileSink`〔#4337〕が使う。`main.rs` へ `--op-stats-file` として結線済み〔#4340〕）。
//! user namespace の中で展開・削除する再 exec helper の入口は [`userns_helper`]（隠し引数 `__extract-in-userns`。入口の振り分け・親側の起動部品・
//! namespace への参加・結果の返却のみで、展開〔H2〕・削除〔H3〕の本体は未実装。SEC-5・OCI-1・CORE-6・REPAIR-5。#4795。設計は `docs/design/userns-extract-helper.md`）。
//! PLUG-1 区分は plugin（crate-naming.md）。

// `op-stats-test-support` は op-stats の書き出し周期を環境変数で短くする試験専用の入口を有効にする feature で、製品のバイナリに
// 含める理由がない。最適化ビルドで有効になっていたらコンパイルを止める（#4340・CRI-6・REPAIR-3。cli の `logs-test-support` と同じ方式）。
#[cfg(all(feature = "op-stats-test-support", not(debug_assertions)))]
compile_error!(
    "the `op-stats-test-support` feature lets the op-stats export interval be overridden by an environment variable and must not be enabled in release builds"
);

// `pod-holder-test-support` は保持役 provider の実行ファイルを差し替える試験専用の入口と、既定の集合の試験が保持役の注入を
// 止める環境変数 `FANDHE_CONTAINER_TEST_POD_HOLDER=off` を有効にする feature で、製品のバイナリに含める理由がない。
// 最適化ビルドで有効になっていたらコンパイルを止める（H6・#2877・CRI-2・REPAIR-3。`op-stats-test-support` と同じ方式）。
#[cfg(all(feature = "pod-holder-test-support", not(debug_assertions)))]
compile_error!(
    "the `pod-holder-test-support` feature lets the pod holder injection and executable be overridden and must not be enabled in release builds"
);

// `userns-helper-test-support` は userns helper が試験専用の `--no-join` を受ける口と、起動役の実行ファイル差し替えを有効にする
// feature で、製品のバイナリに含める理由がない。最適化ビルドで有効になっていたらコンパイルを止める
// （#4795・SEC-5・REPAIR-3。`pod-holder-test-support` と同じ方式）。
#[cfg(all(feature = "userns-helper-test-support", not(debug_assertions)))]
compile_error!(
    "the `userns-helper-test-support` feature lets the userns helper skip joining and its executable be overridden and must not be enabled in release builds"
);

pub mod adapter;
#[cfg(target_os = "linux")]
pub mod audit_relay;
#[cfg(unix)]
pub mod extract_identity;
mod flock_release;
#[cfg(unix)]
pub mod image_inventory;
#[cfg(unix)]
pub(crate) mod image_refs;
pub mod instance_lock;
pub mod netsetup;
#[cfg(unix)]
pub mod orphan_bundles;
#[cfg(target_os = "linux")]
pub mod pod_holder;
pub mod pod_network;
#[cfg(unix)]
pub mod record_readoption;
#[cfg(unix)]
pub mod server;
pub mod shim;
#[cfg(unix)]
pub mod shutdown;
pub mod snapshot_file;
pub mod startup;
#[cfg(unix)]
pub mod streaming;
#[cfg(target_os = "linux")]
pub mod supervised;
#[cfg(unix)]
pub mod sys;
pub mod task_exec;
pub mod telemetry;
pub mod userns_helper;

// pid と連番だけの名前の一時ディレクトリを残骸に強くする共有部品（oci の結合試験の補助を取り込む。
// REPAIR-12・#3435）。試験専用で製品・rlib に影響しない。
#[cfg(test)]
#[path = "../../oci/tests/support/test_root.rs"]
mod test_root;
// flock_release の複製間で本体の振る舞いを同じ試験ケースで照合する共有部品（REPAIR-1・OCI-5・CORE-2・#4566・#4532）。
// 試験専用で製品・rlib に影響しない。flock の OFD 単位の意味論を見るため unix に限る。
#[cfg(all(test, unix))]
#[path = "../../core/tests/support/flock_release_cases.rs"]
mod flock_release_cases;
#[cfg(all(test, unix))]
#[path = "../../core/tests/support/flock_release_with_cases.rs"]
mod flock_release_with_cases;
