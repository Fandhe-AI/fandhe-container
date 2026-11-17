//! user namespace の中で展開・削除するための再 exec helper の入口（SEC-5・OCI-1・CORE-6・REPAIR-5。#4795・#4800・#4847。親 issue #4777）。
//!
//! マルチスレッドの plugin-cri プロセスは core の `isolate_rootless_subordinate`（単一スレッド必須）を呼べず、範囲写像の
//! user namespace に入れない。そこで plugin-cri 自身（`/proc/self/exe`）を固定の隠し引数 [`USERNS_HELPER_ARG`] で再 exec した
//! 単一スレッドの helper を作る。本モジュールが提供するのは次の 6 点:
//!
//! - 入口の振り分け: `main.rs` の先頭で第 1 引数が [`USERNS_HELPER_ARG`] なら [`run_helper_main`] へ渡す（tokio を起動しない）
//! - 親側の起動部品: `launcher`（Linux のみ。同期のブロッキング API。期限・kill・回収つき）
//! - namespace への参加: `helper`（Linux のみ。dumpable を落とし、fd を閉じ、`Threads: 1` を確かめて参加する）
//! - 結果の返却: [`wire`]（OS 非依存の固定長 frame。上限検査・固定語彙のエラー）
//! - 削除モード（H3。#4800）: `helper` が親ディレクトリ fd の直下の固定名の木を名前空間の中で消し、`remover`
//!   （Linux x86_64 / aarch64）が cri の注入点 `SubordinateTreeRemover` の本番実装として上限・期限・回収を持つ
//!
//! - 展開モード（#4847。OCI-1・OCI-2）: `launcher` の `run_extract_bounded` が展開要求の frame の後に blob の fd を `SCM_RIGHTS`
//!   で送り、`helper` が参加の後に blob を再検証して oci の `extract_image_layers_bounded_in` で展開する
//!
//! - 展開器（#4848）: `extractor` が cri の注入点 `SubordinateLayerExtractor` の本番実装として、blob と展開先を fd で渡して
//!   `run_extract_bounded` を呼ぶ（枠・期限・回収は `slots` で削除器と共通の処理を別インスタンスで持つ）
//!
//! 未配線（REPAIR-3）: CI への組み込み（H7・#4802）と特殊ビットの保持（#4849）は未。対応表の切り替えは H6（#4801）で有効化済み
//! （範囲写像の行は `ChownInUserNamespace` + `Strip`。削除・展開は cri の pull・create へ配線済み）。
//! 設計は `docs/design/userns-extract-helper.md`。

pub mod wire;

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
pub mod extractor;
#[cfg(target_os = "linux")]
mod helper;
#[cfg(target_os = "linux")]
pub mod launcher;
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
pub mod remover;
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod slots;

/// helper を起動する隠しの第 1 引数（固定。パスや設定を引数で受けない）。
pub const USERNS_HELPER_ARG: &str = "__extract-in-userns";

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
pub use extractor::UsernsLayerExtractor;
#[cfg(target_os = "linux")]
pub use helper::run_helper_main;
#[cfg(target_os = "linux")]
pub use launcher::{JOIN_BUDGET, UsernsHelperError, UsernsHelperLauncher, WorkBudget};
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
pub use remover::UsernsTreeRemover;

/// 試験専用: 生の socket へ fd を送る（helper の fd 検査〔本数・token〕を実バイナリへ直接当てる試験のため。feature 限定）。
#[cfg(all(target_os = "linux", feature = "userns-helper-test-support"))]
pub fn send_fds_for_test(
    sock: std::os::fd::BorrowedFd<'_>,
    token: u8,
    fds: &[std::os::fd::BorrowedFd<'_>],
) -> std::io::Result<()> {
    crate::sys::fd_passing::send_fds(sock, token, fds)
}

/// 非 Linux では helper を提供しない。終了コード 1 で終える（実装済みを装わない。REPAIR-3）。
#[cfg(not(target_os = "linux"))]
pub fn run_helper_main(_args: Vec<std::ffi::OsString>) -> std::process::ExitCode {
    std::process::ExitCode::from(1)
}
