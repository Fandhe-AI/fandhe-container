//! fandhe-container-platform-windows: Windows WSL2 経由（virtiofs opt-in）の実装。
//!
//! Windows で Linux コンテナを動かす主経路は WSL2 経由とし（WIN-1）、`.wslconfig` の
//! `virtiofs=true` を opt-in として既定運用に含める（WIN-2）。
//!
//! 実装状況: `wsl2` の WSL2 検出・バージョン確認（TASK-67.3・#374）は実装済み。`.wslconfig` の
//! 処理（TASK-67.2）・virtiofs マウント・起動（TASK-67.4）・9P フォールバック（TASK-67.5）は
//! 未実装またはスタブ（REPAIR-3）。
//!
//! cfg 方針: `wsl2` は解析器と実行器を 3 OS の CI でテストできるよう全 OS でビルドし、`wsl.exe` の
//! パス解決（Windows 以外では `UNIMPLEMENTED` を返す）と子孫プロセスをまとめる Job Object（`wsl2::run`）
//! だけを `cfg(windows)` で分岐する。Win32 API の呼び出しは `sys` に閉じる。
//! OS 非依存のロジック（`.wslconfig` のテキスト処理・エラー型）も全 OS でビルドする。
//!
//! 実行時は `fandhe-container-plugin-windows`（TASK-116）が本 crate を別プロセスとして動かす。
//! PLUG-1 区分は plugin 境界の外側（バックエンド実装ライブラリ。crate-naming.md）。

pub mod error;
#[cfg(windows)]
mod sys;
pub mod wsl2;
pub mod wslconfig;
