//! syscall・FFI の薄いラッパー（`crates/cli` の `sys` モジュール。`unsafe` 事前承認の範囲。
//! coding-rust.md「unsafe・FFI・syscall」節・オーナー決定 2026-09-27
//! 〔[#4](https://github.com/Fandhe-AI/fandhe-container/issues/4#issuecomment-5856057084)・
//! [範囲限定](https://github.com/Fandhe-AI/fandhe-container/issues/4#issuecomment-5856167174)〕）。
//!
//! # 呼び出し文脈
//! `crate::signals` が、バイナリ `fandhe-container` の起動時に SIGINT・SIGTERM・SIGHUP のハンドラを
//! 登録するために呼ぶ（[`install_forwarding_handler`]。#1513・PLUG-7・#1403 判断 2）。ハンドラ本体
//! （plugin へ転送した後、既定動作へ戻った同じシグナルを自分へ再送する `forward_and_reraise`）は
//! 本モジュールが持つ。同じ起動時に、継承した `SIGCHLD` の `SIG_IGN` を `SIG_DFL` へ戻す
//! （[`reset_child_signal_if_ignored`]。plugin の子が自動回収されて pid が再利用され、転送が無関係な
//! プロセスへ届く窓を閉じる。#1513・PLUG-7・PR #1572 事後監査の P2）。`libc` は依存追加が禁止（dependency-policy）の
//! ため、`crates/plugin/src/sys.rs` と同じ流儀で必要最小限の `extern "C"` 宣言と構造体を自前で持つ。
//!
//! # 構造体レイアウトと定数（一次情報）
//! - Linux（`target_env = "gnu"` の glibc のみ。x86_64 / aarch64 とも同一）: `bits/sigaction.h` の `struct sigaction` は
//!   `{ sa_handler(8), sa_mask(__sigset_t = unsigned long[16] = 128), sa_flags(int, 後ろに 4 パディング), sa_restorer(8) }`
//!   で 152 バイト。`SA_RESTART` = 0x10000000・`SA_RESETHAND` = 0x80000000（`asm-generic/signal-defs.h`）。
//! - macOS: xnu の `sys/signal.h` の `struct sigaction` は `{ __sigaction_u(8), sa_mask(sigset_t = u32), sa_flags(int) }`
//!   で 16 バイト。`SA_RESTART` = 0x0002・`SA_RESETHAND` = 0x0004。
//! - `SIG_IGN` = 1・`SIG_DFL` = 0（いずれの OS も）。
//! - `sa_mask` のビット規則（転送対象 SIGHUP=1・SIGINT=2・SIGTERM=15 は両 OS で 0x4003）: glibc は
//!   `__sigmask(sig) = 1UL << ((sig - 1) % 64)`・`__sigword(sig) = (sig - 1) / 64`（`bits/sigsetops.h`）で、
//!   3 つとも word 0 の bit 0・1・14。xnu は `sigmask(m) = 1 << ((m) - 1)`（`bsd/sys/signal.h`）。
//!   読み戻しは Linux の `do_sigaction`（`kernel/signal.c`）が SIGKILL・SIGSTOP だけを除き、xnu の
//!   `sigaction`（`bsd/kern/kern_sig.c` の `ps_catchmask`）は保存した値をそのまま返す。
//!   なお Linux のカーネルは `sa_mask` の先頭 8 バイトだけを読み書きし、glibc の読み戻しは残りの word に未初期化の値を
//!   入れ得るため、読み戻しの照合は word 0 に限る。
//! - `SA_NOCLDWAIT`: Linux 0x2（`asm-generic/signal-defs.h`）・macOS 0x20（xnu `bsd/sys/signal.h`）。
//! - musl（対象外）: 公開 `struct sigaction`（musl `include/signal.h`。handler の union・`sa_mask`・`sa_flags`・
//!   `sa_restorer` の順）は glibc と同じ並びで、「handler・flags・restorer・mask の順」なのは libc が
//!   カーネルへ渡す内部の `struct k_sigaction`（musl `src/internal/ksigaction.h`）である。したがって
//!   並びの差は除外理由ではない。除外するのは、musl ターゲットを CI でビルド・試験しておらず、構造体
//!   レイアウトと定数を実機で確認していないため（3 OS 一級対応は glibc の Linux と macOS の範囲。fail-closed）。
//!   出典: musl v1.2.5 タグの上記 2 ファイル（`struct k_sigaction` は handler・flags・restorer・mask の順）。
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
//! - `forward_and_reraise` は登録したプロセス自身（`OWNER_PID`）でだけ転送する。fork した子は exec 前なら
//!   親の登録表のコピーを持ち、`setpgid` 前の窓で端末の Ctrl-C を受け得るため、誤配送を避けて再送だけを
//!   行う（#1605）。pid の取得は `std::process::id()`（unix では `getpid(2)` の直接呼び出しで、割り当て・ロックを
//!   伴わず async-signal-safe。glibc 2.25 以降は pid をキャッシュせず syscall で取得するため fork 後の子でも正しい）。
//! - ハンドラの `sa_mask` に転送対象の 3 シグナルを入れ、実行中に別の転送対象が割り込んで二重に転送・再送
//!   しないようにする（#1605）。
//! - 公開するのは安全な `pub(crate)` の [`install_forwarding_handler`]・[`reset_child_signal_if_ignored`] と、
//!   feature `signal-test-support` のときだけの `install_recording_handler`・`recorded_signal`・
//!   `ignore_child_signal_for_test`（SIGCHLD を `SIG_IGN` にする。ハンドラ関数は登録しない）のみ

#![cfg(unix)]

/// 転送対象のシグナル番号（SIGHUP・SIGINT・SIGTERM。Linux・macOS 共通）。`signals` と `sa_mask` の共通の源。
pub(crate) const FORWARDED_SIGNALS: [i32; 3] = [1, 2, 15];

/// [`reset_child_signal_if_ignored`] の結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // 構造体レイアウト未確認の OS では構築されない（fail-closed の `Unsupported` 経路）
pub(crate) enum ChildSignal {
    /// 起動時に `SIG_IGN` だったため `SIG_DFL` へ戻した。
    ResetFromIgnored,
    /// 起動時に `SA_NOCLDWAIT` が残っていた（macOS は exec で `P_NOCLDWAIT` が消えない）ため `SIG_DFL`・
    /// フラグ 0 へ戻した。
    ResetFromNoCldWait,
    /// `SIG_IGN` でも `SA_NOCLDWAIT` でもなかったため変更しなかった。
    Kept,
}

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
    /// `SA_NOCLDWAIT`（`asm-generic/signal-defs.h`。x86_64 / aarch64 とも 2）。
    pub(super) const SA_NOCLDWAIT: i32 = 0x2;
    // 0x80000000 は i32 では最上位ビットのみ（ビットパターンが同じ）。
    pub(super) const SA_RESETHAND: i32 = i32::MIN;
    /// `SIGCHLD`（x86_64 / aarch64 とも 17。`asm-generic/signal.h`・`arch/x86/include/uapi/asm/signal.h`）。
    pub(super) const SIGCHLD: i32 = 17;

    pub(super) fn empty() -> SigAction {
        SigAction {
            handler: 0,
            mask: [0; 16],
            flags: 0,
            restorer: 0,
        }
    }

    /// `sigs` を `sa_mask` に立てる。`__sigmask`・`__sigword`（`bits/sigsetops.h`）と同じ規則。範囲外は None。
    pub(super) fn mask_of(sigs: &[i32]) -> Option<[u64; 16]> {
        let mut mask = [0u64; 16];
        for &sig in sigs {
            let bit = usize::try_from(sig.checked_sub(1)?).ok()?;
            *mask.get_mut(bit / 64)? |= 1u64 << (bit % 64);
        }
        Some(mask)
    }

    /// 読み戻し照合用: `sa_mask` の先頭 word だけ。Linux のカーネルは 8 バイト（`_NSIG` = 64 ビット）しか
    /// 読み書きせず、glibc の読み戻しは word 1 以降を未初期化にし得るため、初期化が保証された先頭だけを返す。
    #[cfg(test)]
    pub(super) fn mask_first_word(a: &SigAction) -> u64 {
        a.mask[0]
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
    /// `SA_NOCLDWAIT`（xnu `bsd/sys/signal.h` で 0x0020）。
    pub(super) const SA_NOCLDWAIT: i32 = 0x0020;
    /// `SIGCHLD`（xnu の `sys/signal.h` で 20）。
    pub(super) const SIGCHLD: i32 = 20;

    pub(super) fn empty() -> SigAction {
        SigAction {
            handler: 0,
            mask: 0,
            flags: 0,
        }
    }

    /// `sigs` を `sa_mask` に立てる。xnu の `sigmask(m) = 1 << ((m) - 1)` と同じ規則。範囲外は None。
    pub(super) fn mask_of(sigs: &[i32]) -> Option<u32> {
        let mut mask = 0u32;
        for &sig in sigs {
            let bit = u32::try_from(sig.checked_sub(1)?).ok()?;
            mask |= 1u32.checked_shl(bit)?;
        }
        Some(mask)
    }

    /// 読み戻し照合用: `sa_mask`（1 word）。
    #[cfg(test)]
    pub(super) fn mask_first_word(a: &SigAction) -> u64 {
        u64::from(a.mask)
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
    use super::{ChildSignal, Disposition, FORWARDED_SIGNALS, layout};
    use fandhe_container_plugin::{ForwardSignal, forward_to_running_plugins};
    use std::io;
    use std::sync::atomic::{AtomicU32, Ordering};

    const SIG_IGN: usize = 1;
    const SIG_DFL: usize = 0;

    unsafe extern "C" {
        // SAFETY（宣言そのものの妥当性）: POSIX の `int sigaction(int, const struct sigaction *, struct sigaction *)`。
        // `layout::SigAction` は上記ヘッダのレイアウトと同一（サイズは const assert で固定）。
        fn sigaction(sig: i32, act: *const layout::SigAction, old: *mut layout::SigAction) -> i32;
        // SAFETY（宣言そのものの妥当性）: POSIX の `int raise(int)`。
        fn raise(sig: i32) -> i32;
    }

    // 試験専用の fork ラッパー用宣言（feature `signal-test-support` のときだけ）。POSIX の
    // `pid_t fork(void)`・`void _exit(int)`・`pid_t waitpid(pid_t, int *, int)`・`int kill(pid_t, int)`。
    // `pid_t` は Linux・macOS とも `int`（32 ビット）。
    #[cfg(feature = "signal-test-support")]
    unsafe extern "C" {
        fn fork() -> i32;
        fn _exit(code: i32) -> !;
        fn waitpid(pid: i32, status: *mut i32, options: i32) -> i32;
        fn kill(pid: i32, sig: i32) -> i32;
    }

    /// 転送ハンドラを登録したプロセスの pid（未登録は 0）。fork した子が親の登録表のコピーで plugin へ
    /// 誤転送しないよう、ハンドラが自分の pid と照合する（#1605・PLUG-7）。
    static OWNER_PID: AtomicU32 = AtomicU32::new(0);

    /// 登録したプロセス自身のときだけ転送してよいか。未登録（0）は転送しない側に倒す（fail-closed）。
    fn is_owner(owner: u32, current: u32) -> bool {
        owner != 0 && owner == current
    }

    /// 受けたシグナルを plugin へ転送し、既定動作へ戻った同じシグナルを自分へ再送する固定ハンドラ
    /// （#1513・PLUG-7）。`SA_RESETHAND` で進入時に既定動作へ戻っており、ハンドラ中は当該シグナルが
    /// ブロックされるため、再送は保留され、戻った時点で配送されて既定動作（終了）になる。errno は
    /// 再送で終了するため退避しない。async-signal-safe な操作（atomic・`kill`・`raise`）だけを行う。
    ///
    /// 登録したプロセス自身（[`OWNER_PID`]）でだけ転送する。fork した子（exec 前）は親の登録表のコピーを
    /// 持つため、転送せずに再送だけを行う。`sa_mask` に転送対象の 3 シグナルを入れてあるため、実行中に別の
    /// 転送対象が割り込むことはない（保留されて復帰後に既定動作で配送される）。
    extern "C" fn forward_and_reraise(sig: i32) {
        // `std::process::id()` は `getpid(2)` の直接呼び出しで async-signal-safe（割り当て・ロックなし）。
        if is_owner(OWNER_PID.load(Ordering::SeqCst), std::process::id())
            && let Some(forward) = ForwardSignal::from_raw(sig)
        {
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
        // ハンドラが動き得るようになる前に所有者を記録する（照合が常に「所有者あり」で始まるように）。
        OWNER_PID.store(std::process::id(), Ordering::SeqCst);
        install(sig, forward_and_reraise, true)
    }

    /// `sig` に記録用の固定ハンドラ（`record_for_test`）を登録する（[`install`] の規則に従う）。
    #[cfg(feature = "signal-test-support")]
    pub(crate) fn install_recording_handler(sig: i32) -> io::Result<Disposition> {
        install(sig, record_for_test, true)
    }

    /// 試験専用: 継承した `SIG_IGN` を上書きして記録用ハンドラを登録する（plugin 役が `SIG_IGN` を継承しても
    /// 転送された SIGHUP を観測できるようにする。#1605）。
    #[cfg(feature = "signal-test-support")]
    pub(crate) fn install_recording_handler_overriding_ignore(sig: i32) -> io::Result<Disposition> {
        install(sig, record_for_test, false)
    }

    /// 記録用ハンドラが最後に受けたシグナル番号（未受信は 0）。
    #[cfg(feature = "signal-test-support")]
    pub(crate) fn recorded_signal() -> i32 {
        RECORDED.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// `sig` に `handler` を登録する。起動時に `SIG_IGN` なら上書きしない。登録は `SA_RESETHAND`
    /// （ハンドラ進入時に既定動作へ戻す）と `SA_RESTART`・空のマスク。`handler` は本モジュール内の固定
    /// ハンドラに限る（非公開。外から任意の関数を渡せないようにする）。
    ///
    /// `respect_ignored` が false のときは継承した `SIG_IGN` も上書きする（試験専用の登録だけが使う）。
    /// `sa_mask` には転送対象の 3 シグナルを入れる（記録ハンドラにも同じマスクが入るが害はない）。
    fn install(
        sig: i32,
        handler: extern "C" fn(i32),
        respect_ignored: bool,
    ) -> io::Result<Disposition> {
        let mask = layout::mask_of(&FORWARDED_SIGNALS)
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
        let mut old = layout::empty();
        // SAFETY: `act` は NULL（取得のみ）、`old` は呼び出し中有効なスタック上の書き込み可能な領域。
        if unsafe { sigaction(sig, std::ptr::null(), &mut old) } != 0 {
            return Err(io::Error::last_os_error());
        }
        if respect_ignored && old.handler == SIG_IGN {
            return Ok(Disposition::KeptIgnored);
        }
        let mut act = layout::empty();
        act.handler = handler as usize;
        act.mask = mask;
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

    /// 継承した `SIGCHLD` の `SIG_IGN`・`SA_NOCLDWAIT` を `SIG_DFL` へ戻す（どちらでもなければ変更しない）。
    ///
    /// `SIGCHLD` が `SIG_IGN` または `SA_NOCLDWAIT` だとカーネルが子を自動回収し、plugin の登録表に残った
    /// pid が回収後に再利用され得る（`fandhe_container_plugin` の `signal_forward` の「制限」）。
    /// Linux は execve で全シグナルの `sa_flags` を 0 にする（`flush_signal_handlers`、`kernel/signal.c`）ため
    /// `SA_NOCLDWAIT` は継承されず、継承し得るのは `SIG_IGN` だけである。一方 macOS の xnu は `execsigs`
    /// （`bsd/kern/kern_sig.c`）でも exec 経路（`kern_exec.c`）でも `P_NOCLDWAIT` を消さず、`sigaction` の
    /// 読み戻しは `P_NOCLDWAIT` から `SA_NOCLDWAIT` を再構成する（同ファイル）ため、ハンドラが `SIG_DFL` でも
    /// 自動回収が残り得る。照合しきれない OS 差は戻す側に倒す（fail-closed）ため、`SA_NOCLDWAIT` も戻す。
    /// 出典: apple-oss-distributions/xnu タグ xnu-11215.1.10。
    pub(crate) fn reset_child_signal_if_ignored() -> io::Result<ChildSignal> {
        reset_if_ignored(layout::SIGCHLD)
    }

    /// 継承した設定のうち、自動回収につながるもの（`SIG_IGN`・`SA_NOCLDWAIT`）か。どちらでもなければ None。
    fn child_reset_reason(handler: usize, flags: i32) -> Option<ChildSignal> {
        if handler == SIG_IGN {
            Some(ChildSignal::ResetFromIgnored)
        } else if flags & layout::SA_NOCLDWAIT != 0 {
            Some(ChildSignal::ResetFromNoCldWait)
        } else {
            None
        }
    }

    /// `sig` が `SIG_IGN` または `SA_NOCLDWAIT` なら `SIG_DFL`（フラグ 0・空のマスク）へ戻す。
    fn reset_if_ignored(sig: i32) -> io::Result<ChildSignal> {
        let mut old = layout::empty();
        // SAFETY: `act` は NULL（取得のみ）、`old` は呼び出し中有効なスタック上の書き込み可能な領域。
        if unsafe { sigaction(sig, std::ptr::null(), &mut old) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let Some(reason) = child_reset_reason(old.handler, old.flags) else {
            return Ok(ChildSignal::Kept);
        };
        let mut act = layout::empty();
        act.handler = SIG_DFL;
        // SAFETY: `act` は初期化済み（`SIG_DFL`・フラグ 0・空のマスク）で呼び出し中有効、`old` の取得は
        // 不要なため NULL。ハンドラ関数を登録しないため async-signal-safety の前提を持たない。
        if unsafe { sigaction(sig, &act, std::ptr::null_mut()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(reason)
    }

    /// テスト専用: `sig` を `SIG_IGN` にする（[`reset_if_ignored`] の照合用と、feature `signal-test-support` の
    /// 結合試験で隔離した子プロセスの SIGCHLD を無視にするため。ユニットテストからは SIGCHLD に使わない）。
    #[cfg(any(test, feature = "signal-test-support"))]
    pub(super) fn set_ignored_for_test(sig: i32) -> io::Result<()> {
        let mut act = layout::empty();
        act.handler = SIG_IGN;
        // SAFETY: `act` は初期化済みで呼び出し中有効、`old` の取得は不要なため NULL。ハンドラ関数を
        // 登録しない。
        if unsafe { sigaction(sig, &act, std::ptr::null_mut()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// テスト専用: [`reset_if_ignored`] を任意のシグナルで呼ぶ（プロセス全体の SIGCHLD を変えずに照合する）。
    #[cfg(test)]
    pub(super) fn reset_if_ignored_for_test(sig: i32) -> io::Result<ChildSignal> {
        reset_if_ignored(sig)
    }

    /// テスト専用: `sig` の現在の設定（ハンドラ値・フラグ）を読み出す（登録内容の読み戻し照合用）。
    #[cfg(test)]
    pub(super) fn current(sig: i32) -> io::Result<(usize, i32)> {
        let mut old = layout::empty();
        // SAFETY: `act` は NULL（取得のみ）、`old` は呼び出し中有効なスタック上の書き込み可能な領域。
        if unsafe { sigaction(sig, std::ptr::null(), &mut old) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok((old.handler, old.flags))
    }

    /// テスト専用: `sig` の `sa_mask` の先頭 word（読み戻し照合用）。
    #[cfg(test)]
    pub(super) fn current_mask(sig: i32) -> io::Result<u64> {
        let mut old = layout::empty();
        // SAFETY: `act` は NULL（取得のみ）、`old` は呼び出し中有効なスタック上の書き込み可能な領域。
        if unsafe { sigaction(sig, std::ptr::null(), &mut old) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(layout::mask_first_word(&old))
    }

    /// テスト専用: 所有者 pid と照合の判定（ユニットテスト用）。
    #[cfg(test)]
    pub(super) fn owner_pid_for_test() -> u32 {
        OWNER_PID.load(Ordering::SeqCst)
    }

    #[cfg(test)]
    pub(super) fn is_owner_for_test(owner: u32, current: u32) -> bool {
        is_owner(owner, current)
    }

    #[cfg(test)]
    pub(super) fn child_reset_reason_for_test(handler: usize, flags: i32) -> Option<ChildSignal> {
        child_reset_reason(handler, flags)
    }

    /// テスト専用: 転送用の固定ハンドラの値（読み戻し照合の期待値）。
    #[cfg(test)]
    pub(super) fn forwarding_handler_value() -> usize {
        forward_and_reraise as extern "C" fn(i32) as usize
    }

    /// 結合試験専用（feature `signal-test-support`）: 自プロセスの SIGCHLD を `SIG_IGN` にする（継承した
    /// `SIG_IGN` の再現。隔離した子プロセスの役からだけ呼ぶ）。
    #[cfg(feature = "signal-test-support")]
    pub(crate) fn ignore_child_signal_for_test() -> io::Result<()> {
        set_ignored_for_test(layout::SIGCHLD)
    }

    /// `waitpid` の `WNOHANG`（Linux・macOS とも 1。`sys/wait.h`）。
    #[cfg(feature = "signal-test-support")]
    const WNOHANG: i32 = 1;
    /// `SIGKILL`（Linux・macOS とも 9）。
    #[cfg(feature = "signal-test-support")]
    const SIGKILL: i32 = 9;
    /// `EINTR`（Linux・macOS とも 4）。
    #[cfg(feature = "signal-test-support")]
    const EINTR: i32 = 4;
    /// SIGKILL 後の回収を待つ上限（REPAIR-5）。
    #[cfg(feature = "signal-test-support")]
    const REAP_LIMIT: std::time::Duration = std::time::Duration::from_secs(5);

    /// 結合試験専用（feature `signal-test-support`）: fork した子で `sig` を自分へ送り、子の終了を `limit` まで
    /// 待って、シグナル終了ならその番号（`Some`）、通常終了なら `None` を返す（#1605・PLUG-7）。
    ///
    /// fork した子は exec 前に親の転送ハンドラと登録表のコピーを持つ。その子がシグナルを受けても plugin へ
    /// 転送せず、再送だけで終了することを親役の試験で確かめるために使う。期限（REPAIR-5）を超えたら子を
    /// SIGKILL して回収し、`TimedOut` を返す。
    #[cfg(feature = "signal-test-support")]
    pub(crate) fn fork_and_raise_for_test(
        sig: i32,
        limit: std::time::Duration,
    ) -> io::Result<Option<i32>> {
        use std::os::unix::process::ExitStatusExt;
        // SAFETY: `fork` は引数を取らない。多スレッドのプロセスで呼ぶため、子は fork 直後に
        // async-signal-safe な関数（`raise`・`_exit`）だけを呼び、割り当て・ロック・アンワインドを伴う
        // Rust のコードへ戻らない（`_exit` は戻らない）。親は戻り値の pid だけを使う。
        let pid = unsafe { fork() };
        if pid < 0 {
            return Err(io::Error::last_os_error());
        }
        if pid == 0 {
            // SAFETY: 値渡しの整数のみ。シグナルで終了する想定で、戻った場合も `_exit` で Rust ランタイムを
            // 経由せず終了する（終了コード 97 は「シグナルで終了しなかった」ことを示す）。
            unsafe {
                let _ = raise(sig);
                _exit(97)
            }
        }
        let start = std::time::Instant::now();
        let mut status = 0i32;
        loop {
            // SAFETY: `status` は呼び出し中有効なスタック上の書き込み可能な領域。`pid` は本関数が fork した
            // 子で、未回収の間は再利用されない。
            let r = unsafe { waitpid(pid, &mut status, WNOHANG) };
            if r == pid {
                return Ok(std::process::ExitStatus::from_raw(status).signal());
            }
            if r < 0 {
                let e = io::Error::last_os_error();
                if e.raw_os_error() != Some(EINTR) {
                    return Err(e);
                }
            }
            if start.elapsed() >= limit {
                // SAFETY: 未回収の自分の子（pid は再利用されない）への SIGKILL。
                let killed = unsafe { kill(pid, SIGKILL) };
                let kill_err = (killed != 0).then(io::Error::last_os_error);
                // 強制終了後の回収も期限つき（REPAIR-5）。無期限の `waitpid` にしない。
                let reap_start = std::time::Instant::now();
                loop {
                    // SAFETY: `status` は呼び出し中有効なスタック上の書き込み可能な領域。`pid` は未回収の自分の子。
                    let r = unsafe { waitpid(pid, &mut status, WNOHANG) };
                    if r == pid {
                        break;
                    }
                    if r < 0 && io::Error::last_os_error().raw_os_error() != Some(EINTR) {
                        break;
                    }
                    if reap_start.elapsed() >= REAP_LIMIT {
                        return Err(io::Error::other(format!(
                            "child {pid} not reaped within {REAP_LIMIT:?} after SIGKILL"
                        )));
                    }
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                return Err(match kill_err {
                    Some(e) => io::Error::other(format!("SIGKILL to child {pid} failed: {e}")),
                    None => io::Error::from(io::ErrorKind::TimedOut),
                });
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
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
    use super::{ChildSignal, Disposition};
    use std::io;

    /// 構造体レイアウトを確認していない OS・アーキテクチャでは変更しない（fail-closed）。
    pub(crate) fn reset_child_signal_if_ignored() -> io::Result<ChildSignal> {
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }

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

    /// 構造体レイアウトを確認していない OS・アーキテクチャでは変更しない（fail-closed）。
    #[cfg(feature = "signal-test-support")]
    pub(crate) fn ignore_child_signal_for_test() -> io::Result<()> {
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }

    /// 登録できないため常に失敗（fail-closed）。
    #[cfg(feature = "signal-test-support")]
    pub(crate) fn install_recording_handler_overriding_ignore(
        _sig: i32,
    ) -> io::Result<Disposition> {
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }

    /// fork を試さず常に失敗（fail-closed）。
    #[cfg(feature = "signal-test-support")]
    pub(crate) fn fork_and_raise_for_test(
        _sig: i32,
        _limit: std::time::Duration,
    ) -> io::Result<Option<i32>> {
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }
}

#[cfg(feature = "signal-test-support")]
pub(crate) use imp::{
    fork_and_raise_for_test, ignore_child_signal_for_test, install_recording_handler,
    install_recording_handler_overriding_ignore, recorded_signal,
};
pub(crate) use imp::{install_forwarding_handler, reset_child_signal_if_ignored};

// 対象は構造体レイアウトを確認済みの `imp`（実装側）と同じ cfg に揃える（musl 等の fail-closed 側を
// 実装側の試験で検証したことにしない。PR #1572 事後監査の P3）。
#[cfg(all(
    test,
    any(
        target_os = "macos",
        all(
            target_os = "linux",
            target_env = "gnu",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    )
))]
mod tests {
    use super::*;

    /// EINVAL は Linux（asm-generic/errno-base.h）・macOS（sys/errno.h）とも 22。
    const EINVAL: i32 = 22;
    /// SIGWINCH は Linux・macOS とも 28。既定動作は無視で、テストハーネスの動作を乱さない。
    const SIGWINCH: i32 = 28;
    /// SIGURG（Linux 23・macOS 16）。既定動作は無視。プロセス全体の SIGCHLD を変えずに戻しの照合に使う。
    #[cfg(target_os = "linux")]
    const SIGURG: i32 = 23;
    #[cfg(target_os = "macos")]
    const SIGURG: i32 = 16;

    /// 範囲外のシグナル番号は OS のエラー（EINVAL）で失敗する。
    #[test]
    fn install_handler_rejects_invalid_signal_number() {
        let e = install_forwarding_handler(100_000).unwrap_err();
        assert_eq!(e.raw_os_error(), Some(EINVAL));
    }

    /// PLUG-7・#1513: 登録したハンドラ値とフラグ（`SA_RESETHAND | SA_RESTART`）を OS から読み戻して照合する
    /// （構造体レイアウト・定数の取り違えを検出する）。Linux はカーネルが `SA_RESTORER` を加えて返すため、
    /// 期待するビットをマスクして照合する（macOS の差は本文のコメント）。
    #[test]
    fn plug7_installed_handler_reads_back_with_expected_flags() {
        let (before, _) = imp::current(SIGWINCH).unwrap();
        assert_eq!(before, 0, "SIGWINCH must start as SIG_DFL");
        assert_eq!(
            install_forwarding_handler(SIGWINCH).unwrap(),
            Disposition::Installed
        );
        let (handler, flags) = imp::current(SIGWINCH).unwrap();
        assert_eq!(handler, imp::forwarding_handler_value());
        // macOS（xnu）は読み戻しの `sa_flags` に `SA_RESETHAND` を含めない（`SA_RESTART` 等だけを再構成する）
        // ため、macOS では `SA_RESTART` だけを照合する。`SA_RESETHAND` が効くこと（ハンドラ後に既定動作で
        // 終了すること）は結合試験 `tests/signal_forward.rs` の親のシグナル終了で確かめている。
        #[cfg(target_os = "linux")]
        let want = layout::SA_RESETHAND | layout::SA_RESTART;
        #[cfg(target_os = "macos")]
        let want = layout::SA_RESTART;
        assert_eq!(flags & want, want);
    }

    /// PLUG-7・#1605: 登録後に読み戻した `sa_mask` に転送対象 3 シグナル（SIGHUP・SIGINT・SIGTERM）だけが
    /// 入っている。両 OS とも 0x4003（bit 0・1・14）。
    #[test]
    fn plug7_installed_handler_reads_back_with_forwarded_signal_mask() {
        const SIGPROF: i32 = 27;
        install_forwarding_handler(SIGPROF).unwrap();
        // 先頭 word だけを照合する（残りの word は読み戻し API が返さない）。
        let word = imp::current_mask(SIGPROF).unwrap();
        assert_eq!(word, 0x4003);
        // 自分自身（SIGPROF = 27）は含まない（sa_mask は追加で止めるシグナルだけ）。
        assert_eq!(word & (1 << (SIGPROF - 1)), 0);
        // 範囲外の番号は立てられない。
        assert!(layout::mask_of(&[0]).is_none());
        assert!(layout::mask_of(&[-1]).is_none());
        assert!(layout::mask_of(&[100_000]).is_none());
    }

    /// PLUG-7・#1605: 登録後の所有者 pid は自プロセスで、照合は所有者のときだけ真（0 は偽）。
    #[test]
    fn plug7_forwarding_is_limited_to_the_registering_process() {
        // SIGVTALRM（Linux・macOS とも 26）。他の試験が読み戻しの前提にする SIGWINCH とは分ける。
        install_forwarding_handler(26).unwrap();
        assert_eq!(imp::owner_pid_for_test(), std::process::id());
        assert!(imp::is_owner_for_test(5, 5));
        assert!(!imp::is_owner_for_test(5, 6));
        assert!(!imp::is_owner_for_test(0, 0));
        assert!(!imp::is_owner_for_test(0, 5));
    }

    /// PLUG-7・#1605: SIGCHLD を戻す条件は `SIG_IGN` または `SA_NOCLDWAIT`（macOS は exec で
    /// `P_NOCLDWAIT` が消えないため）。それ以外は変更しない。
    #[test]
    fn plug7_child_reset_reason_covers_ignore_and_nocldwait() {
        assert_eq!(
            imp::child_reset_reason_for_test(1, 0),
            Some(ChildSignal::ResetFromIgnored)
        );
        assert_eq!(
            imp::child_reset_reason_for_test(0, layout::SA_NOCLDWAIT),
            Some(ChildSignal::ResetFromNoCldWait)
        );
        assert_eq!(
            imp::child_reset_reason_for_test(0, layout::SA_RESTART),
            None
        );
        #[cfg(target_os = "linux")]
        assert_eq!(layout::SA_NOCLDWAIT, 2);
        #[cfg(target_os = "macos")]
        assert_eq!(layout::SA_NOCLDWAIT, 0x20);
    }

    /// PLUG-7・#1605: 転送対象は SIGHUP・SIGINT・SIGTERM（Linux・macOS 共通の番号）。
    #[test]
    fn plug7_forwarded_signals_are_hup_int_term() {
        assert_eq!(FORWARDED_SIGNALS, [1, 2, 15]);
    }

    /// PLUG-7・#1513: `SIG_IGN` のシグナルだけを `SIG_DFL`（フラグ 0）へ戻し、それ以外は変更しない。
    /// SIGCHLD そのものはテストプロセスの他の試験の子の回収に影響するため、同じ処理を SIGURG で照合する。
    #[test]
    fn plug7_reset_if_ignored_restores_default_only_when_ignored() {
        imp::set_ignored_for_test(SIGURG).unwrap();
        // フラグは Linux で `SA_RESTORER` が加わるため照合しない（ハンドラ値 `SIG_IGN` = 1 のみ）。
        assert_eq!(imp::current(SIGURG).unwrap().0, 1);
        assert_eq!(
            imp::reset_if_ignored_for_test(SIGURG).unwrap(),
            ChildSignal::ResetFromIgnored
        );
        let (handler, flags) = imp::current(SIGURG).unwrap();
        assert_eq!(handler, 0);
        assert_eq!(flags & (layout::SA_RESETHAND | layout::SA_RESTART), 0);
        assert_eq!(
            imp::reset_if_ignored_for_test(SIGURG).unwrap(),
            ChildSignal::Kept
        );
        // 範囲外の番号は OS のエラー（EINVAL）。
        let e = imp::reset_if_ignored_for_test(100_000).unwrap_err();
        assert_eq!(e.raw_os_error(), Some(EINVAL));
    }

    /// SIGCHLD の番号は OS ごとの一次情報の値（Linux 17・macOS 20）。
    #[test]
    fn plug7_sigchld_number_matches_platform() {
        #[cfg(target_os = "linux")]
        assert_eq!(layout::SIGCHLD, 17);
        #[cfg(target_os = "macos")]
        assert_eq!(layout::SIGCHLD, 20);
    }
}
