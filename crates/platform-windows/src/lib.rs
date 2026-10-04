//! fandhe-container-platform-windows: Windows WSL2 経由（virtiofs opt-in）の実装。
//!
//! Windows で Linux コンテナを動かす主経路は WSL2 経由とし（WIN-1）、`.wslconfig` の
//! `virtiofs=true` を opt-in として既定運用に含める（WIN-2）。
//!
//! 実装状況: TASK-67.1（#372）でモジュールの骨格と cfg ガードだけを置いた。各モジュールは
//! スタブで、本体は TASK-67.2〜67.5 で実装する（REPAIR-3）。
//!
//! cfg 方針: Windows 固有の振る舞い（`wsl.exe` 起動・Win32 API）を持つ `wsl2` のみ
//! `cfg(target_os = "windows")` でビルドする。OS 非依存のロジック（`.wslconfig` のテキスト処理・
//! エラー型）は 3 OS の CI でテストできるよう全 OS でビルドする。親 issue の「Windows 上でのみ
//! ビルド対象」は「Windows 固有の振る舞いは Windows でのみビルドされる」の意味で解釈する。
//!
//! 実行時は `fandhe-container-plugin-windows`（TASK-116）が本 crate を別プロセスとして動かす。
//! PLUG-1 区分は plugin 境界の外側（バックエンド実装ライブラリ。crate-naming.md）。

pub mod error;
#[cfg(target_os = "windows")]
pub mod wsl2;
pub mod wslconfig;
