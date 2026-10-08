//! syscall・FFI の薄いラッパー（`crates/cli` の `sys` モジュール。`unsafe` 事前承認の範囲。
//! coding-rust.md「unsafe・FFI・syscall」節・オーナー決定 2026-09-27
//! 〔[#4](https://github.com/Fandhe-AI/fandhe-container/issues/4#issuecomment-5856057084)・
//! [範囲限定](https://github.com/Fandhe-AI/fandhe-container/issues/4#issuecomment-5856167174)〕）。
//!
//! # 呼び出し文脈
//! `crate::signals` が、バイナリ `fandhe-container` の起動時に SIGINT・SIGTERM・SIGHUP のハンドラを
//! 登録し（`install_handler`）、ハンドラ内で plugin へ転送した後に既定動作へ戻して自分へ再送する
//! （`raise_signal`）ために呼ぶ（#1513・PLUG-7・#1403 判断 2）。`libc` は依存追加が禁止（dependency-policy）の
//! ため、`crates/plugin/src/sys.rs` と同じ流儀で必要最小限の `extern "C"` 宣言と構造体を自前で持つ。
//!
//! # 構造体レイアウトと定数（一次情報）
//! - Linux（glibc。x86_64 / aarch64 とも同一）: `bits/sigaction.h` の `struct sigaction` は
//!   `{ sa_handler(8), sa_mask(__sigset_t = unsigned long[16] = 128), sa_flags(int, 後ろに 4 パディング), sa_restorer(8) }`
//!   で 152 バイト。`SA_RESTART` = 0x10000000・`SA_RESETHAND` = 0x80000000（`asm-generic/signal-defs.h`）。
//! - macOS: xnu の `sys/signal.h` の `struct sigaction` は `{ __sigaction_u(8), sa_mask(sigset_t = u32), sa_flags(int) }`
//!   で 16 バイト。`SA_RESTART` = 0x0002・`SA_RESETHAND` = 0x0004。
//! - `SIG_IGN` = 1（いずれの OS も）。
//! - 上記以外の OS・アーキテクチャは構造体を持たず `Unsupported` を返す（他 OS の値を流用しない。fail-closed）。
//!
//! # 契約
//! - `unsafe fn` は公開しない。公開するのは安全な [`install_handler`]・[`raise_signal`]（`pub(crate)`）のみ
//! - ハンドラとして渡す関数は async-signal-safe であること（割り当て・ロック・panic をしない）は呼び出し側の責務

#![cfg(unix)]

/// 既存のシグナル設定を尊重したかどうか。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // 構造体レイアウト未確認の OS では構築されない（fail-closed の `Unsupported` 経路）
pub(crate) enum Disposition {
    /// ハンドラを登録した。
    Installed,
    /// 起動時から `SIG_IGN` だったため上書きしなかった（nohup・バックグラウンドジョブの慣行を壊さない）。
    KeptIgnored,
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod layout {
    /// glibc の `struct sigaction`（x86_64 / aarch64 共通。152 バイト）。
    #[repr(C)]
    pub(super) struct SigAction {
        pub(super) handler: usize,
        pub(super) mask: [u64; 16],
        pub(super) flags: i32,
        pub(super) restorer: usize,
    }
    const _: () = assert!(std::mem::size_of::<SigAction>() == 152);

    pub(super) const SA_RESTART: i32 = 0x1000_0000;
    // 0x80000000 は i32 では最上位ビットのみ（ビットパターンが同じ）。
    pub(super) const SA_RESETHAND: i32 = i32::MIN;

    pub(super) fn empty() -> SigAction {
        SigAction {
            handler: 0,
            mask: [0; 16],
            flags: 0,
            restorer: 0,
        }
    }
}

#[cfg(target_os = "macos")]
mod layout {
    /// macOS の `struct sigaction`（16 バイト）。
    #[repr(C)]
    pub(super) struct SigAction {
        pub(super) handler: usize,
        pub(super) mask: u32,
        pub(super) flags: i32,
    }
    const _: () = assert!(std::mem::size_of::<SigAction>() == 16);

    pub(super) const SA_RESTART: i32 = 0x0002;
    pub(super) const SA_RESETHAND: i32 = 0x0004;

    pub(super) fn empty() -> SigAction {
        SigAction {
            handler: 0,
            mask: 0,
            flags: 0,
        }
    }
}

#[cfg(any(
    target_os = "macos",
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
mod imp {
    use super::{Disposition, layout};
    use std::io;

    const SIG_IGN: usize = 1;

    unsafe extern "C" {
        // SAFETY（宣言そのものの妥当性）: POSIX の `int sigaction(int, const struct sigaction *, struct sigaction *)`。
        // `layout::SigAction` は上記ヘッダのレイアウトと同一（サイズは const assert で固定）。
        fn sigaction(sig: i32, act: *const layout::SigAction, old: *mut layout::SigAction) -> i32;
        // SAFETY（宣言そのものの妥当性）: POSIX の `int raise(int)`。
        fn raise(sig: i32) -> i32;
    }

    /// `sig` に `handler` を登録する。起動時に `SIG_IGN` なら上書きしない。登録は `SA_RESETHAND`
    /// （ハンドラ進入時に既定動作へ戻す）と `SA_RESTART`・空のマスク。
    pub(crate) fn install_handler(
        sig: i32,
        handler: extern "C" fn(i32),
    ) -> io::Result<Disposition> {
        let mut old = layout::empty();
        // SAFETY: `act` は NULL（取得のみ）、`old` は呼び出し中有効なスタック上の書き込み可能な領域。
        if unsafe { sigaction(sig, std::ptr::null(), &mut old) } != 0 {
            return Err(io::Error::last_os_error());
        }
        if old.handler == SIG_IGN {
            return Ok(Disposition::KeptIgnored);
        }
        let mut act = layout::empty();
        act.handler = handler as usize;
        act.flags = layout::SA_RESETHAND | layout::SA_RESTART;
        // SAFETY: `act` は初期化済みで呼び出し中有効、`old` の取得は不要なため NULL。`handler` は
        // `extern "C" fn(i32)` で、シグナルハンドラの ABI と一致する。
        if unsafe { sigaction(sig, &act, std::ptr::null_mut()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Disposition::Installed)
    }

    /// 自プロセス（呼び出しスレッド）へ `sig` を送る。ハンドラ内から呼べる（`raise` は async-signal-safe）。
    pub(crate) fn raise_signal(sig: i32) {
        // SAFETY: 値渡しの整数のみでメモリ安全上の前提を持たない。戻り値は使わない
        // （終了に向かう経路で、失敗しても呼び出し側にできることがない）。
        let _ = unsafe { raise(sig) };
    }
}

#[cfg(not(any(
    target_os = "macos",
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
)))]
mod imp {
    use super::Disposition;
    use std::io;

    /// 構造体レイアウトを確認していない OS・アーキテクチャでは登録しない（fail-closed）。
    pub(crate) fn install_handler(
        _sig: i32,
        _handler: extern "C" fn(i32),
    ) -> io::Result<Disposition> {
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }

    pub(crate) fn raise_signal(_sig: i32) {}
}

pub(crate) use imp::{install_handler, raise_signal};

#[cfg(all(
    test,
    any(
        target_os = "macos",
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    )
))]
mod tests {
    use super::*;

    extern "C" fn noop(_sig: i32) {}

    /// 範囲外のシグナル番号は OS のエラー（EINVAL）で失敗する。
    #[test]
    fn install_handler_rejects_invalid_signal_number() {
        assert!(install_handler(100_000, noop).is_err());
    }
}
