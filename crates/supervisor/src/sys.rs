//! OS ごとの `unsafe` FFI / syscall 薄ラッパーの入口（`unsafe` 事前承認の範囲。coding-rust.md「unsafe・FFI・syscall」節・
//! オーナー決定 2026-09-27〔[#4](https://github.com/Fandhe-AI/fandhe-container/issues/4#issuecomment-5856057084)・
//! [範囲限定](https://github.com/Fandhe-AI/fandhe-container/issues/4#issuecomment-5856167174)〕）。
//!
//! OS ごとの子モジュールへ振り分け、公開は `pub(crate)` の安全な関数だけにする（`unsafe fn` を外へ出さない）。
//! - `windows`: ローテーション sink のロックファイル同一性照合（`logs::rotating`。SUP-7・TASK-164 追補・#1470）
//! - `linux`: 権限昇格の縮退に使う capability / credential の syscall ラッパー
//!   （`privilege::elevate`。SUP-14・TASK-171.1.3・#1475。方式は #1454 のオーナー判断 2026-10-10）。特権ランチャー
//!   （`launcher`。#1719）向けに、検証済み fd の `execveat`・継承 fd の整理（`close_range`）・fd 開閉の確認・
//!   `PR_SET_DUMPABLE`・セッションの切り離し（`setsid`。#537）も持つ。制御チャネル（`control`。SUP-1・SEC-1・#2058）向けに、接続相手の資格情報の取得
//!   （`getsockopt(SO_PEERCRED)`）、ディレクトリを symlink 越しに開かないための `open(2)` フラグ、期限つきクライアント用の non-blocking `connect(2)` と `CLOCK_MONOTONIC` の取得、exec 用 pidfd の受け渡し（`sendmsg` / `recvmsg` の `SCM_RIGHTS` で fd 1 本。#2626・SUP-6）も持つ
//!
//! macOS は本モジュールを持たない（`unsafe` を要する機能が無い）。

#[cfg(target_os = "linux")]
mod linux;
#[cfg(windows)]
mod windows;

#[cfg(target_os = "linux")]
pub(crate) use linux::*;
#[cfg(windows)]
pub(crate) use windows::*;
