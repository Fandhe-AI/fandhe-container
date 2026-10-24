//! syscall の薄いラッパー（`unsafe` 事前承認の範囲。coding-rust.md「unsafe・FFI・syscall」節・
//! オーナー決定 2026-09-27
//! 〔[#4](https://github.com/Fandhe-AI/fandhe-container/issues/4#issuecomment-5856057084)・
//! [範囲限定](https://github.com/Fandhe-AI/fandhe-container/issues/4#issuecomment-5856167174)〕）。
//!
//! # 呼び出し文脈
//! `image_management::store` の `ImageStore::open` / `with_table` が、イメージストア root と祖先ディレクトリの
//! 所有者を現在プロセスの実効 uid と照合するために使う（OCI-7・SEC-1・#2381）。依存追加は禁止
//! （dependency-policy）のため、他 crate の `sys` と同じ流儀で `extern "C"` 宣言を自前で持つ。
//! Linux の x86_64 / aarch64 では `at`（`openat2` 系）を `layer::anchored` と `image_management::root_handle`
//! （root 配下の永続化操作を検査済み root の fd 起点にする。#2638）が使う。
//!
//! # libc との照合（#2590）
//! `geteuid` の型は子 `libc_abi`、`at.rs` の番号・フラグ・`OpenHow` のレイアウト・関数の型は `at::libc_abi` で、
//! `libc`（dev-dependencies のみ。#1318・#1837）と `const` 評価で照合する（方式は `docs/design/ffi-libc-check.md`。
//! 承認は #2590 のオーナーコメント 2026-10-23）。
//!
//! # macOS の拡張 ACL を宣言しない理由（#2547）
//! macOS では本番経路が `ImageStore::open` に届かず（cli は `non_linux_failure` で先に fail-closed）、
//! ACL の FFI と `unsafe` を足す根拠が無い。判断は `docs/design/image-store-root-trust.md`。
//!
//! # 契約
//! - `unsafe fn` はこのモジュールの外へ公開しない（公開するのは安全な関数のみ）
//! - `unsafe` ブロック・`unsafe extern "C"` 宣言に `// SAFETY:` で理由と不変条件を明記する
//! - unix 限定。非 unix では本モジュール自体をコンパイルしない（呼び出し側も `cfg(unix)`）

unsafe extern "C" {
    // SAFETY（宣言そのものの妥当性）: POSIX の `uid_t geteuid(void)` と同じ戻り値の型・幅
    // （`uid_t` は `u32`）。引数を取らず、エラー条件を持たない。
    fn geteuid() -> u32;
}

/// 自プロセスの実効 uid を返す（`geteuid(2)`。エラーを返さない）。
pub(crate) fn effective_uid() -> u32 {
    // SAFETY: 引数を取らず、POSIX の規定上エラー条件を持たない。
    unsafe { geteuid() }
}

// ディレクトリ fd 起点の操作（`openat2` 系。#2437・OCI-1・SEC-5）。Linux の x86_64 / aarch64 限定。
// 他のアーキテクチャ・OS ではコンパイルせず、呼び出し側（`layer::anchored`）が fail-closed にし、
// `image_management::root_handle` はパス起点の実装に切り替える（#2638）。
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
pub(crate) mod at;

/// `geteuid` の型を `libc` と照合する（#2590・OCI-7・REPAIR-12）。関数は呼ばない。
/// 対象外: `effective_uid` は FFI ではなく安全なラッパー。
#[cfg(test)]
mod libc_abi {
    const _: unsafe extern "C" fn() -> libc::uid_t = super::geteuid;
    const _: unsafe extern "C" fn() -> libc::uid_t = libc::geteuid;
}
