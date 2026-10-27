//! 実機前提試験の「試験環境の前提欠如」を、回帰と 1 行目で見分けられる形にする共有部品の cli 側アダプタ
//! （#2957・#3028・CLI-1・CORE-6・REPAIR-1・REPAIR-12）。
//!
//! # 役割と呼び出し元
//! `start_stop_delete_real`・`delete_cgroup_real`・`start_recover_real` が、委譲 cgroup・Landlock の前提が
//! 欠けたとき、`<試験名>: FAILED: ...` ではなく
//! `<試験名>: PRECONDITION FAILED (test environment, not a <X> regression): ...` の 1 行目で失敗させる。
//! `AGENTS.md`「実機前提テスト」の見分け方と一致する。
//!
//! # 正本との関係
//! 分類・文言・`Failure` は `crates/core/tests/support/precondition.rs` の正本を `#[path]` で取り込んで再公開する
//! （複製しない。分類や文言を変えるときは正本の 1 か所だけを直す）。cli の試験は panic ではなく `Result` で失敗を
//! 返し `main` が `FAILED:` 行へ流すため、このアダプタは正本の `try_*`（`Result` 層）を公開名で包むだけである。
//! `#[path]` で取り込むので `CARGO_CRATE_NAME` は取り込んだ試験の名前になる。
//!
//! # 取り込み方
//! 各試験が `#[path = "support/precondition.rs"] mod precondition;` で直接取り込む。

#[path = "../../../core/tests/support/precondition.rs"]
mod shared;

#[allow(unused_imports)] // 取り込み元によって使う項目が異なる
pub use shared::{
    Failure, Kind, classify_detect, classify_landlock, classify_subid_code, message, self_check,
};

/// 委譲 cgroup の検出結果を返す。前提欠如なら `Failure::Precondition`、そうでなければ `Failure::Other`。
#[allow(dead_code)] // 取り込み元によっては使わない
pub fn delegated_cgroup() -> Result<fandhe_container_core::cgroups::DelegatedCgroup, Failure> {
    shared::try_delegated_cgroup()
}

/// Landlock ABI 6 以上を検出する。前提欠如なら `Failure::Precondition`、そうでなければ `Failure::Other`。
#[allow(dead_code)] // 取り込み元によっては使わない
pub fn landlock_support() -> Result<fandhe_container_core::landlock::LandlockSupport, Failure> {
    shared::try_landlock_support()
}
