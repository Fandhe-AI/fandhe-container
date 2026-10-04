//! fandhe-container-platform-windows: Windows WSL2 経由（virtiofs opt-in）の実装。
//!
//! Windows で Linux コンテナを動かす主経路は WSL2 経由とし（WIN-1）、`.wslconfig` の
//! `virtiofs=true` を opt-in として既定運用に含める（WIN-2）。
//!
//! 実装状況: `error`（構造化エラー型）と `wslconfig`（`.wslconfig` の読み書き）は TASK-67.2（#373）で
//! 実装済み。`sys` は `unsafe` を閉じ込める FFI の薄いラッパーで、`.wslconfig` 置換時のアクセス制御の
//! 複製・検査（Windows の DACL 等・unix の拡張 ACL の検出）に使う。`wsl2`（WSL2 検出・virtiofs マウント・9P フォールバック）は引き続きスタブで、
//! TASK-67.3〜67.5（#374〜#376）で実装する（REPAIR-3）。
//!
//! cfg 方針: Windows 固有の振る舞い（`wsl.exe` 起動・Win32 API）を持つ `wsl2` のみ
//! `cfg(target_os = "windows")` でビルドする。OS 非依存のロジック（`.wslconfig` のテキスト処理・
//! エラー型）は 3 OS の CI でテストできるよう全 OS でビルドする。親 issue の「Windows 上でのみ
//! ビルド対象」は「Windows 固有の振る舞いは Windows でのみビルドされる」の意味で解釈する。
//!
//! 実行時は `fandhe-container-plugin-windows`（TASK-116）が本 crate を別プロセスとして動かす。
//! PLUG-1 区分は plugin 境界の外側（バックエンド実装ライブラリ。crate-naming.md）。

pub mod error;
#[cfg(any(unix, windows))]
mod sys;
#[cfg(target_os = "windows")]
pub mod wsl2;
pub mod wslconfig;
