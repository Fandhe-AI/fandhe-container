//! POSIX syscall の薄いラッパー（`sys` モジュールの unix 共通部。`unsafe` 事前承認の範囲。
//! coding-rust.md「unsafe・FFI・syscall」節・オーナー決定 2026-09-27
//! 〔[#4](https://github.com/Fandhe-AI/fandhe-container/issues/4#issuecomment-5856057084)・
//! [範囲限定](https://github.com/Fandhe-AI/fandhe-container/issues/4#issuecomment-5856167174)〕）。
//!
//! 呼び出し文脈: `config` のコンソールログ open が、open 済み fd の所有者を自プロセスの実効 uid と
//! 照合する（他ユーザーが事前作成したファイルへの追記を拒否する。MAC-1・TASK-64.3）。Virtualization.framework
//! 層（macOS 限定）と違い OS 非依存の検証ロジックから使うため、macOS 以外の unix でもビルドし、3 OS CI の
//! Linux でも所有者検査を実行できるようにする。`libc` / `nix` は製品の依存に入れない（dependency-policy。`libc` は dev-dependencies で照合にだけ使う。#1318）ため、
//! `crates/plugin/src/sys.rs` と同じ流儀で必要最小限の `extern "C"` 宣言を自前で持つ。`libc` との機械照合は子 `libc_abi` で行う（#1844）。
//!
//! 不変条件: `unsafe fn` を公開しない。公開するのは安全な [`effective_uid`]（`pub(crate)`）のみ。

unsafe extern "C" {
    // SAFETY（宣言そのものの妥当性）: POSIX の `uid_t geteuid(void)` と同じ戻り値の型・幅
    // （`uid_t` は Linux・macOS とも `u32`）。引数を取らず、エラー条件を持たない。
    fn geteuid() -> u32;
}

/// 自プロセスの実効 uid を返す（`geteuid(2)`。エラーを返さない）。
pub(crate) fn effective_uid() -> u32 {
    // SAFETY: 引数を取らず、POSIX の規定上エラー条件を持たない。グローバル状態を書き換えない。
    unsafe { geteuid() }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// MAC-1・TASK-64.3: 実効 uid は自分が新規作成したファイルの所有者と一致する。
    #[test]
    fn effective_uid_matches_owner_of_created_file() {
        use std::os::unix::fs::MetadataExt;
        let path =
            std::env::temp_dir().join(format!("fandhe-macos-sys-euid-{}", std::process::id()));
        std::fs::write(&path, b"x").expect("write fixture");
        let owner = std::fs::metadata(&path).expect("stat fixture").uid();
        let _ = std::fs::remove_file(&path);
        assert_eq!(effective_uid(), owner);
    }
}

#[cfg(test)]
mod libc_abi {
    //! `geteuid` の宣言を `libc` 0.2.189 と型で照合する（#1844・MAC-1・MVM-4・REPAIR-12）。関数は呼ばない。
    //! macOS と Linux の両方でコンパイルされるため、PR の ubuntu CI でもネイティブに評価される。
    use super::*;

    const _: unsafe extern "C" fn() -> libc::uid_t = geteuid;
    const _: unsafe extern "C" fn() -> libc::uid_t = libc::geteuid;
}
