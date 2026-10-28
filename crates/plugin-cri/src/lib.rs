//! fandhe-container-plugin-cri: CRI サーバー plugin バイナリ（`fandhe-container-cri` の実装を別プロセス化）。
//!
//! バイナリの入口（起動引数の解析と終了コードの規則。[`startup`]）と、実装の組み立て口（[`adapter`]。TASK-114.2・#458）、
//! `--socket <PATH>` の UDS 上で `RuntimeService` を gRPC サーブする `server`（unix のみ。TASK-114.3.1・#849・PLUG-1・PLUG-2）がある。
//! core との接続の向きは `docs/design/plugin-backend-wiring.md` 4.9（#1869。承認待ち）に従い、plugin-cri が gRPC サーバー、
//! core 側（kubelet / crictl 相当）が `fandhe-container-plugin` の `connect_uds_channel` で接続するクライアントである。
//! `ImageService` は同じ UDS・同じ listener でサーブする（`PullImage` の登録先の在庫を `CreateContainer` のタグ解決と共有する。#2592・CRI-3）。
//! 在庫はプロセス内だけで、再起動でタグの対応は失われる（キャッシュは残る）。
//! 未実装（REPAIR-3）: 既定の socket パスの解決と lifecycle からの起動（#459・#1869）、
//! 在庫の永続化（TASK-183・#2315・#2380）。start / kill / stop と cgroup remover は supervisor 経由で本番結線済み
//! （`supervised`。Linux のみ。#2434）。本番の `BundleProvider`（#2433）も結線済みで、タグ・digest・image ID で `CreateContainer` を受ける。
//! crictl の通し（#442）の pod.json はホストの network namespace（NODE）を指定する（core が pod の network namespace の join を受けるまで。
//! `docs/verification/crictl-smoke.md`）。
//! Container 系 4 RPC の UDS＋gRPC 境界越しの到達と、注入したフェイクでの一連の成功は `tests/container_grpc.rs` で照合済み（#850）。
//! PLUG-12 の別 UID 拒否（実機前提）と正規クライアントの一連は `tests/integration.rs` で照合する（#461）。
//! 状態ルートのインスタンス排他は [`instance_lock`]（`<状態ルート>/.cri/@instance.lock`。起動時に取りプロセスの間持つ。#2931・CRI-2・CORE-1）。
//! SIGTERM・SIGINT による正常停止（受付の停止・実行中の RPC の期限つき待ち・socket の削除・ロックの解放）は `shutdown`・`sys` と `main.rs`（#3226・CRI-1・REPAIR-5。
//! 停止の契約は `docs/design/cri-record-readoption.md`「停止の契約」）。SIGHUP は対象外。
//! PLUG-1 区分は plugin（crate-naming.md）。

pub mod adapter;
pub mod instance_lock;
pub mod netsetup;
#[cfg(unix)]
pub mod orphan_bundles;
pub mod pod_network;
#[cfg(unix)]
pub mod record_readoption;
#[cfg(unix)]
pub mod server;
#[cfg(unix)]
pub mod shutdown;
pub mod startup;
#[cfg(target_os = "linux")]
pub mod supervised;
#[cfg(unix)]
pub mod sys;
pub mod telemetry;
