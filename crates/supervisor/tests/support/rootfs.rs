//! 実機前提の結合試験が使う最小 rootfs の組み立て部品（SEC-5・CORE-6・SUP-1・REPAIR-1・REPAIR-12。#2835・#2889）。
//!
//! 利用元は `exec_subordinate_e2e`・`supervisor_bin_real` の 2 本で、どちらも
//! `#[path = "support/rootfs.rs"] mod rootfs;` で取り込む（`tests/support/` には `main.rs` が無く cargo の自動検出の
//! 対象にならない）。試験バイナリ自身を rootfs の `/probe`（別 inode のコピー。ランタイム自身のバイナリを exec
//! させない）へ置き、動的ローダ（ELF の `PT_INTERP`）と読み込み済みの共有ライブラリを同じ絶対パスへコピーする。
//!
//! 置き場所の判断: 利用元が同じ crate なので `crates/supervisor/tests/support/` に置き、crate はまたがない。
//! core の `tests/support/real_entry.rs`・`tests/production_launcher.rs`、cli の `tests/start_stop_delete_real.rs`、
//! `benches/src/startup_latency/bundle.rs` に似た部品があるが、契約（`Result` を返すか panic か・symlink を辿らない
//! `mkdir`・`/entry` の命名・core の API への依存）が違うため今回はまとめない（別 issue で扱う）。
//!
//! 契約: 失敗はすべて panic。ELF の読み取り（外部入力）は共有部品が `get()` と checked 演算で検査する。

use std::path::Path;

#[path = "../../../core/tests/support/minimal_rootfs.rs"]
mod minimal_rootfs;

/// rootfs に `proc/` を作るか。`Omit` は `supervisor_bin_real` のシナリオ B（pre-pivot 段の失敗注入）用。
#[derive(Clone, Copy)]
pub enum ProcDir {
    Create,
    #[allow(dead_code)]
    // exec_subordinate_e2e は使わない（supervisor_bin_real のシナリオ B が使う）
    Omit,
}

/// 最小 rootfs を作る（`proc`〔`Create` のとき〕・`dev`・`tmp`・`etc` と `/probe`・ローダ・共有ライブラリ）。戻り値はプローブが使う
/// `LD_LIBRARY_PATH` の値。
pub fn make_rootfs(rootfs: &Path, proc_dir: ProcDir) -> String {
    let dirs: &[&str] = match proc_dir {
        ProcDir::Create => &["proc", "dev", "tmp", "etc"],
        ProcDir::Omit => &["dev", "tmp", "etc"],
    };
    minimal_rootfs::install_binary_at(rootfs, "probe", dirs).unwrap_or_else(|e| panic!("{e}"))
}
