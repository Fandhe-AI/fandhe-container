//! fandhe-container-platform-windows: Windows WSL2 経由（virtiofs opt-in）の実装。
//!
//! Windows で Linux コンテナを動かす主経路は WSL2 経由とし（WIN-1）、`.wslconfig` の
//! `virtiofs=true` を opt-in として既定運用に含める（WIN-2）。
//!
//! 実装状況:
//! - `error`（構造化エラー型）・`wslconfig`（`.wslconfig` の読み書き）・`instrument`（操作の成否と所要時間の
//!   記録先。REPAIR-4）は TASK-67.2（#373）で実装済み。
//! - `wsl2` の WSL2 検出・バージョン確認（TASK-67.3・#374）は実装済み。virtiofs 共有マウントと起動前の検証
//!   シーケンス（TASK-67.4・#375。ゲスト内ランタイムの常駐起動は TASK-116）も実装済み。virtiofs が使えない
//!   環境での 9P フォールバックと警告・エラー型の統合（TASK-67.5・#376。WIN-2・ERR-1）も実装済み。実機での
//!   fstype・オプション確認は TASK-67.6（#377）。
//! - `sys` は `unsafe` を閉じ込める FFI の薄いラッパー。Windows は `wsl2` の `wsl.exe` パス解決・Job Object と
//!   `wslconfig` 置換時のアクセス制御の複製・検査に、unix は `wslconfig` 置換時の拡張 ACL の検出に使う。
//!
//! cfg 方針: `wsl2` は解析器と実行器を 3 OS の CI でテストできるよう全 OS でビルドし、`wsl.exe` の
//! パス解決（Windows 以外では `UNIMPLEMENTED` を返す）と子孫プロセスをまとめる Job Object（`wsl2::run`）
//! だけを `cfg(windows)` で分岐する。Win32 API の呼び出しは `sys` に閉じる。
//! OS 非依存のロジック（`.wslconfig` のテキスト処理・エラー型）も全 OS でビルドする。
//!
//! 実行時は `fandhe-container-plugin-windows`（TASK-116）が本 crate を別プロセスとして動かす。
//! PLUG-1 区分は plugin 境界の外側（バックエンド実装ライブラリ。crate-naming.md）。

pub mod error;
pub mod instrument;
#[cfg(any(unix, windows))]
mod sys;
pub mod wsl2;
pub mod wslconfig;
