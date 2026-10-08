//! syscall・FFI の薄いラッパー（`crates/cli` の `sys` モジュール。`unsafe` 事前承認の範囲。
//! coding-rust.md「unsafe・FFI・syscall」節・オーナー決定 2026-09-27
//! 〔[#4](https://github.com/Fandhe-AI/fandhe-container/issues/4#issuecomment-5856057084)・
//! [範囲限定](https://github.com/Fandhe-AI/fandhe-container/issues/4#issuecomment-5856167174)〕）。
//!
//! # 呼び出し文脈
//! `crate::signals` が、バイナリ `fandhe-container` の起動時に SIGINT・SIGTERM・SIGHUP のハンドラを
//! 登録するために呼ぶ（[`install_forwarding_handler`]。#1513・PLUG-7・#1403 判断 2）。ハンドラ本体
//! （plugin へ転送した後、既定動作へ戻った同じシグナルを自分へ再送する `forward_and_reraise`）は
//! 本モジュールが持つ。`libc` は依存追加が禁止（dependency-policy）の
//! ため、`crates/plugin/src/sys.rs` と同じ流儀で必要最小限の `extern "C"` 宣言と構造体を自前で持つ。
//!
//! # 構造体レイアウトと定数（一次情報）
//! - Linux（`target_env = "gnu"` の glibc のみ。x86_64 / aarch64 とも同一）: `bits/sigaction.h` の `struct sigaction` は
//!   `{ sa_handler(8), sa_mask(__sigset_t = unsigned long[16] = 128), sa_flags(int, 後ろに 4 パディング), sa_restorer(8) }`
//!   で 152 バイト。`SA_RESTART` = 0x10000000・`SA_RESETHAND` = 0x80000000（`asm-generic/signal-defs.h`）。
//! - macOS: xnu の `sys/signal.h` の `struct sigaction` は `{ __sigaction_u(8), sa_mask(sigset_t = u32), sa_flags(int) }`
//!   で 16 バイト。`SA_RESTART` = 0x0002・`SA_RESETHAND` = 0x0004。
//! - `SIG_IGN` = 1（いずれの OS も）。
//! - musl は `struct sigaction` の並びが異なる（handler・flags・restorer・mask の順）ため対象外。
//! - 上記以外の OS・アーキテクチャ・libc は構造体を持たず `Unsupported` を返す（他 OS の値を流用しない。fail-closed）。
//!
//! # 契約
//! - `unsafe fn` も、任意の関数ポインタをハンドラとして受け取る API も公開しない（PR #1572 事後監査の P2）。
//!   登録できるハンドラは本モジュール内の固定の `extern "C" fn` に限り、その本体が async-signal-safe
//!   （割り当て・ロック・panic・添字アクセスをしない）であることを本モジュールで保証する:
//!   - `forward_and_reraise`: `fandhe_container_plugin::forward_to_running_plugins`（同 crate の契約で
//!     atomic の load と `kill(2)` のみ）と `raise(3)` だけを呼ぶ
//!   - `record_for_test`（feature `signal-test-support` のときだけ存在する。結合試験の plugin 役用）:
//!     受信番号を `AtomicI32` へ store するだけ
//! - 公開するのは安全な `pub(crate)` の [`install_forwarding_handler`] と、feature `signal-test-support` の
//!   ときだけの `install_recording_handler`・`recorded_signal` のみ

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
    target_env = "gnu",
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
        target_env = "gnu",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
mod imp {
    use super::{Disposition, layout};
    use fandhe_container_plugin::{ForwardSignal, forward_to_running_plugins};
    use std::io;

    const SIG_IGN: usize = 1;

    unsafe extern "C" {
        // SAFETY（宣言そのものの妥当性）: POSIX の `int sigaction(int, const struct sigaction *, struct sigaction *)`。
        // `layout::SigAction` は上記ヘッダのレイアウトと同一（サイズは const assert で固定）。
        fn sigaction(sig: i32, act: *const layout::SigAction, old: *mut layout::SigAction) -> i32;
        // SAFETY（宣言そのものの妥当性）: POSIX の `int raise(int)`。
        fn raise(sig: i32) -> i32;
    }

    /// 受けたシグナルを plugin へ転送し、既定動作へ戻った同じシグナルを自分へ再送する固定ハンドラ
    /// （#1513・PLUG-7）。`SA_RESETHAND` で進入時に既定動作へ戻っており、ハンドラ中は当該シグナルが
    /// ブロックされるため、再送は保留され、戻った時点で配送されて既定動作（終了）になる。errno は
    /// 再送で終了するため退避しない。async-signal-safe な操作（atomic・`kill`・`raise`）だけを行う。
    extern "C" fn forward_and_reraise(sig: i32) {
        if let Some(forward) = ForwardSignal::from_raw(sig) {
            let _ = forward_to_running_plugins(forward);
        }
        // SAFETY: 値渡しの整数のみでメモリ安全上の前提を持たない。`raise` は async-signal-safe。戻り値は
        // 使わない（終了に向かう経路で、失敗しても呼び出し側にできることがない）。
        let _ = unsafe { raise(sig) };
    }

    /// 固定の記録ハンドラが受信番号を残す先（feature `signal-test-support`。結合試験の plugin 役用）。
    #[cfg(feature = "signal-test-support")]
    static RECORDED: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);

    /// 受信したシグナル番号を [`RECORDED`] へ store するだけの固定ハンドラ（async-signal-safe）。
    #[cfg(feature = "signal-test-support")]
    extern "C" fn record_for_test(sig: i32) {
        RECORDED.store(sig, std::sync::atomic::Ordering::SeqCst);
    }

    /// `sig` に転送用の固定ハンドラ（`forward_and_reraise`）を登録する（[`install`] の規則に従う）。
    pub(crate) fn install_forwarding_handler(sig: i32) -> io::Result<Disposition> {
        install(sig, forward_and_reraise)
    }

    /// `sig` に記録用の固定ハンドラ（`record_for_test`）を登録する（[`install`] の規則に従う）。
    #[cfg(feature = "signal-test-support")]
    pub(crate) fn install_recording_handler(sig: i32) -> io::Result<Disposition> {
        install(sig, record_for_test)
    }

    /// 記録用ハンドラが最後に受けたシグナル番号（未受信は 0）。
    #[cfg(feature = "signal-test-support")]
    pub(crate) fn recorded_signal() -> i32 {
        RECORDED.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// `sig` に `handler` を登録する。起動時に `SIG_IGN` なら上書きしない。登録は `SA_RESETHAND`
    /// （ハンドラ進入時に既定動作へ戻す）と `SA_RESTART`・空のマスク。`handler` は本モジュール内の固定
    /// ハンドラに限る（非公開。外から任意の関数を渡せないようにする）。
    fn install(sig: i32, handler: extern "C" fn(i32)) -> io::Result<Disposition> {
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
        // `extern "C" fn(i32)` で、シグナルハンドラの ABI と一致する。登録したハンドラは任意の時点で
        // 任意のスレッドに割り込んで実行されるため、async-signal-safe であることが不変条件になる。
        // `handler` は非公開の本関数へ本モジュール内から渡す固定の関数（`forward_and_reraise`・
        // `record_for_test`）に限られ、いずれも割り当て・ロック・panic・添字アクセスをせず、atomic・
        // `kill`・`raise` だけを使う（モジュール冒頭の契約）。固定ハンドラを追加・変更するときは
        // この条件を保つこと。
        if unsafe { sigaction(sig, &act, std::ptr::null_mut()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Disposition::Installed)
    }
}

#[cfg(not(any(
    target_os = "macos",
    all(
        target_os = "linux",
        target_env = "gnu",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
)))]
mod imp {
    use super::Disposition;
    use std::io;

    /// 構造体レイアウトを確認していない OS・アーキテクチャでは登録しない（fail-closed）。
    pub(crate) fn install_forwarding_handler(_sig: i32) -> io::Result<Disposition> {
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }

    /// 構造体レイアウトを確認していない OS・アーキテクチャでは登録しない（fail-closed）。
    #[cfg(feature = "signal-test-support")]
    pub(crate) fn install_recording_handler(_sig: i32) -> io::Result<Disposition> {
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }

    /// 登録できないため常に 0（未受信）。
    #[cfg(feature = "signal-test-support")]
    pub(crate) fn recorded_signal() -> i32 {
        0
    }
}

pub(crate) use imp::install_forwarding_handler;
#[cfg(feature = "signal-test-support")]
pub(crate) use imp::{install_recording_handler, recorded_signal};

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

    /// 範囲外のシグナル番号は OS のエラー（EINVAL）で失敗する。
    #[test]
    fn install_handler_rejects_invalid_signal_number() {
        assert!(install_forwarding_handler(100_000).is_err());
    }
}
