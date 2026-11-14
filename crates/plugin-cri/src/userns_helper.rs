//! user namespace の中で展開・削除するための再 exec helper の入口（SEC-5・OCI-1・CORE-6・REPAIR-5。#4795。親 issue #4777 の H1）。
//!
//! マルチスレッドの plugin-cri プロセスは core の `isolate_rootless_subordinate`（単一スレッド必須）を呼べず、範囲写像の
//! user namespace に入れない。そこで plugin-cri 自身（`/proc/self/exe`）を固定の隠し引数 [`USERNS_HELPER_ARG`] で再 exec した
//! 単一スレッドの helper を作る。本モジュールが提供するのは次の 4 点で、展開（H2）・削除（H3）の本体は含まない:
//!
//! - 入口の振り分け: `main.rs` の先頭で第 1 引数が [`USERNS_HELPER_ARG`] なら [`run_helper_main`] へ渡す（tokio を起動しない）
//! - 親側の起動部品: `launcher`（Linux のみ。同期のブロッキング API。期限・kill・回収つき）
//! - namespace への参加: `helper`（Linux のみ。dumpable を落とし、fd を閉じ、`Threads: 1` を確かめて参加する）
//! - 結果の返却: [`wire`]（OS 非依存の固定長 frame。上限検査・固定語彙のエラー）
//!
//! 未実装（REPAIR-3）: Extract（H2。OCI-1・OCI-2・SEC-5）と Remove（H3。OCI-7・SEC-5）のモードは予約だけで、受けると
//! `unimplemented` を返す。`extract_identity` の対応表の切り替え（H6）と CI への組み込み（H7）も未。設計は
//! `docs/design/userns-extract-helper.md`。

pub mod wire;

#[cfg(target_os = "linux")]
mod helper;
#[cfg(target_os = "linux")]
pub mod launcher;

/// helper を起動する隠しの第 1 引数（固定。パスや設定を引数で受けない）。
pub const USERNS_HELPER_ARG: &str = "__extract-in-userns";

#[cfg(target_os = "linux")]
pub use helper::run_helper_main;
#[cfg(target_os = "linux")]
pub use launcher::{JOIN_BUDGET, UsernsHelperError, UsernsHelperLauncher, WorkBudget};

/// 非 Linux では helper を提供しない。終了コード 1 で終える（実装済みを装わない。REPAIR-3）。
#[cfg(not(target_os = "linux"))]
pub fn run_helper_main(_args: Vec<std::ffi::OsString>) -> std::process::ExitCode {
    std::process::ExitCode::from(1)
}
