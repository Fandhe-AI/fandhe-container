//! fandhe-container-plugin-macos: macOS バックエンド plugin バイナリ（`fandhe-container-platform-macos` の実装を別プロセス化）。
//!
//! 実装済み: 起動引数の解析と socket パスの解決（[`startup`]。TASK-115.1・#385・MAC-1・PLUG-1）、
//! UDS 上の長さ接頭辞フレーム送受信ループ（[`frame_loop`]。TASK-115.2・#386）、
//! create / start / stop を platform-macos へ委譲するアダプタ（[`adapter`]。TASK-115.3・#387）、
//! SIGTERM でのグレースフルシャットダウン（[`sys`]・[`frame_loop::serve_until`]）と `ping` ヘルスチェック（[`adapter`]。
//! TASK-115.5・#389。SIGKILL・非対応 OS では VM 残留の余地が残る。REPAIR-3）。
//! 未実装（実装済みを装わない。REPAIR-3）: 型つき本体と core の `ContainerRuntime` への接続（TASK-114）・
//! 永続的な監査ログへの配線（core 側 TASK-114）・macOS Venus（GPU-6、TASK-172〜181）の大半。
//! virtio-gpu デバイスモデル等は `src/gpu/` 配下に置く定義（crate-naming.md）。実装済みは
//! venus wire のパース骨格のみ（[`gpu::venus`]。TASK-172.2・#723。コマンド引数のパース・ディスパッチは未実装）と capset 応答の最小実装（TASK-172.3・#724。配線なし）。
//!
//! 接続方向の現行契約: socket は core 側が bind し、plugin が接続する（`fandhe-container-plugin` の
//! `lifecycle` 冒頭「契約」）。TASK-115.4（#388）で、plugin 側 bind は導入せず connect 側を維持すると
//! 確定した（PLUG-12。オーナー未承認の暫定判断で、bind 側を必須とするなら接続契約の変更設計が先に必要）。
//! 接続経路は peer 認証つき `UdsStream::connect` のみで、server の UID が不一致なら 1 バイトも送らず切断する。
//! 迂回する起動フラグ・環境変数は設けない。bind 側の保護（0700 配置ディレクトリ・stale 判定・accept 時の
//! peer 検証）は core 側 `UdsListener` が担う。discovery 登録はバイナリ名（`fandhe-container-plugin-*`。
//! PLUG-4・PLUG-11）で満たし、UDS 上の登録 RPC は spec 未規定のため設けない。
//! `fandhe-container-plugin`（境界機構）の UDS フレームを介して core と通信する。PLUG-1 区分は plugin。

pub mod adapter;
pub mod frame_loop;
pub mod gpu;
pub mod isolate;
pub mod startup;
pub mod sys;
