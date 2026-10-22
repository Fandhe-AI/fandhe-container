//! fandhe-container-plugin-cri: CRI サーバー plugin バイナリ（`fandhe-container-cri` の実装を別プロセス化）。
//!
//! バイナリの入口（起動引数の解析と終了コードの規則。[`startup`]）と、実装の組み立て口（[`adapter`]。TASK-114.2・#458）、
//! `--socket <PATH>` の UDS 上で `RuntimeService` を gRPC サーブする `server`（unix のみ。TASK-114.3.1・#849・PLUG-1・PLUG-2）がある。
//! core との接続の向きは `docs/design/plugin-backend-wiring.md` 4.9（#1869。承認待ち）に従い、plugin-cri が gRPC サーバー、
//! core 側（kubelet / crictl 相当）が `fandhe-container-plugin` の `connect_uds_channel` で接続するクライアントである。
//! 未実装（REPAIR-3）: 既定の socket パスの解決と lifecycle からの起動（#459・#1869）、`ImageService` の UDS サーブ、
//! SIGTERM の正常停止。start / kill / stop と cgroup remover は supervisor 経由で本番結線済み（`supervised`。Linux のみ。#2434）。本番の `BundleProvider`（#2433）は結線済みだが、
//! `ImageService` をサーブしていないためタグは解決できず、`CreateContainer` は image ID（`sha256:<hex>`）で受ける
//! （タグ解決とイメージ取り込みの結線は別途。crictl の通し〔#442〕は `container.json` がタグのため、それまで通らない）。
//! Container 系 4 RPC の UDS＋gRPC 境界越しの到達と、注入したフェイクでの一連の成功は `tests/container_grpc.rs` で照合済み（#850）。
//! PLUG-12 の別 UID 拒否（実機前提）と正規クライアントの一連は `tests/integration.rs` で照合する（#461）。
//! PLUG-1 区分は plugin（crate-naming.md）。

pub mod adapter;
pub mod netsetup;
pub mod pod_network;
#[cfg(unix)]
pub mod server;
pub mod startup;
#[cfg(target_os = "linux")]
pub mod supervised;
pub mod telemetry;
