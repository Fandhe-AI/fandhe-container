//! SIGTERM 受信フラグの登録（`unsafe` 事前承認の範囲。#3746。PLUG-1・REPAIR-3・REPAIR-5。
//! coding-rust.md「unsafe・FFI・syscall」節・オーナー決定 2026-09-27
//! 〔[#4](https://github.com/Fandhe-AI/fandhe-container/issues/4#issuecomment-5856057084)・
//! [範囲限定](https://github.com/Fandhe-AI/fandhe-container/issues/4#issuecomment-5856167174)〕）。
//! 方式は `fandhe-container-plugin-macos` の `sys.rs`（TASK-115.5・#389）を写したもの。
//!
//! # 呼び出し文脈
//! `main.rs` が接続前に [`install_sigterm_flag`] を 1 回呼び、得たフラグを `frame_loop::serve_until` へ渡す
//! （#3747）。フラグが立つと受付をやめ、`stop_all` で起動中の VM を止めてから終了する。
//! core 自身の終了要求は SIGTERM ではなく接続切断（EOF）で伝わる。
//!
//! 製品の依存に `libc` は入れず、`nix` は不採用（dependency-policy）で、std にシグナル API が無いため、
//! 最小限の `extern "C"` 宣言を自前で持つ。`struct sigaction` は OS・アーキテクチャでレイアウトが異なるため
//! 使わず、番号とハンドラのアドレスだけを取る `signal(3)`（glibc・musl・macOS とも BSD セマンティクスで、
//! ハンドラは解除されず再設定も不要）を使う。
//!
//! # SIGUSR2 との非衝突
//! SIGTERM（15）と、`fandhe-container-microvm` の vCPU 実行が使う SIGUSR2（12）は、プロセス全体の別々の
//! disposition の枠である。ここの `signal(15, ..)` は SIGUSR2 の disposition もスレッドのマスクも変えない。
//! microvm の `install_kick_handler` は SIGUSR2 の枠だけを照会・導入し SIGTERM の枠には触れないため、
//! 登録の順序に関わらず互いの導入が `EBUSY` 等で失敗することはない。
//! SIGTERM は process-directed なので、vCPU スレッドが `KVM_RUN` 中に受けることもある。その場合 `KVM_RUN` は
//! EINTR で戻り、microvm の `device.rs` が `VcpuExit::Interrupted` に分類して再実行する（`stats.interrupted` が
//! 増えるだけ）。ハンドラは atomic store のみなので、どのスレッドで走っても安全である。
//! 呼び出し側の規約として、本 crate を組み込むプロセスは SIGUSR2 を他の用途に使わない（`lib.rs` の注意と同じ）。
//!
//! # 契約
//! - `unsafe fn` は公開しない。公開するのは安全な [`install_sigterm_flag`] のみ。
//! - ハンドラは `static AtomicBool` への `store` だけを行う（async-signal-safe。確保・ロック・I/O をしない）。
//! - 登録するのは `SIGTERM` の番号を確認済みの組（Linux の x86_64 / aarch64・macOS）だけ。
//! - Linux の他アーキテクチャは番号が未確認のため登録を試みず、`UNIMPLEMENTED` を返す（fail-closed）。
//! - Linux・macOS 以外（Windows・他の unix）は何も登録せず、決して立たないフラグを `Ok` で返す
//!   （実装済みを装わない。REPAIR-3）。Windows には SIGTERM 経路が無く（コンソール制御ハンドラ等は未実装）、
//!   他の unix では SIGTERM が既定動作のまま届き、後始末を経ずに即終了して VM は止まらない。
//! - 返したフラグを立てるのはハンドラだけ、というのは呼び出し側の規約である。戻り値は
//!   `&'static AtomicBool` で `store` を呼べるため、型では強制していない。
//! - 現状の本 crate と microvm には fork / exec の呼び出しが無く、捕捉中のハンドラの子への継承は問題にならない
//!   （exec した子では SIG_DFL に戻る）。fork を足すときは plugin-cri の検討（#3300）を参照する。
//!
//! # 限界（残存リスク）
//! SIGKILL は捕捉できない。`stop_all` が送信側の猶予内に終わらず SIGKILL された場合、VM は残留しうる
//! （#3722 の範囲）。SIGINT / SIGHUP は対象外。
//!
//! # libc との機械照合（未導入）
//! 本 crate は dev-dependencies に `libc` を持たないため照合は入れていない。dev-dependency の追加は crate ごとの
//! オーナー承認事項で、#1837 の子として扱う（判断のまとめは #3290。`docs/design/ffi-libc-check.md`「適用状況」）。
//! 代わりに番号を具体値で固定する試験を置く。番号の出典は Linux `include/uapi/asm-generic/signal.h`
//! （SIGTERM=15。x86_64・aarch64 とも同じ）と macOS `sys/signal.h`（同値）、`SIG_ERR` は `(sighandler_t)-1`
//! で、手作業で突き合わせた値である。

use std::sync::atomic::AtomicBool;

use fandhe_container_plugin::PluginError;

/// SIGTERM 受信で立つフラグ。本モジュール内で立てるのはハンドラだけ。[`install_sigterm_flag`] が
/// `&'static AtomicBool` として外へ渡すため、呼び出し側が立てないことは規約であり型では強制していない。
static SIGTERM_RECEIVED: AtomicBool = AtomicBool::new(false);

// `SIGTERM` の番号を確認済みの組だけで有効にする。Linux の他アーキテクチャは実行時に `UNIMPLEMENTED` で
// 拒否する（ビルドは通すが起動は拒否。plugin-macos と同じ判断）。
#[cfg(any(
    target_os = "macos",
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
mod imp {
    use std::sync::atomic::Ordering;

    use super::SIGTERM_RECEIVED;

    // SIGTERM は Linux（x86_64 / aarch64）・macOS とも 15 だが、アーキテクチャ差の流用を避けるため個別に定義する。
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    pub(super) const SIGTERM: i32 = 15;
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    pub(super) const SIGTERM: i32 = 15;
    #[cfg(target_os = "macos")]
    pub(super) const SIGTERM: i32 = 15;

    /// `signal(3)` の失敗値 `SIG_ERR`（`(sighandler_t)-1`）。
    const SIG_ERR: usize = usize::MAX;

    unsafe extern "C" {
        // SAFETY（宣言そのものの妥当性）: POSIX の `sighandler_t signal(int, sighandler_t)`。
        // 前提は、本モジュールが有効になる組で `sighandler_t`（関数ポインタ）と `usize` が同じ幅で、
        // 整数レジスタで同じように受け渡されること。幅は直下の const assert がコンパイル時に確かめる。
        fn signal(signum: i32, handler: usize) -> usize;
    }

    // 上の宣言の前提（関数ポインタと `usize` が同幅）をコンパイル時に確かめる。
    const _: () = assert!(size_of::<extern "C" fn(i32)>() == size_of::<usize>());

    /// SIGTERM ハンドラ。atomic store のみ（async-signal-safe）。
    extern "C" fn on_sigterm(_signum: i32) {
        SIGTERM_RECEIVED.store(true, Ordering::SeqCst);
    }

    /// ハンドラを登録する。成功なら `true`。
    pub(super) fn install() -> bool {
        let handler: extern "C" fn(i32) = on_sigterm;
        // SAFETY: ハンドラは `'static` な関数で、単一の `static AtomicBool` 以外に触れない。
        // シグナルはどのスレッドにも配送され得るが、atomic store のみのため安全。BSD セマンティクスで
        // ハンドラは解除されないため、2 回目以降の SIGTERM もフラグを再度立てるだけでプロセスを殺さない。
        let prev = unsafe { signal(SIGTERM, handler as usize) };
        prev != SIG_ERR
    }
}

/// SIGTERM 受信フラグを登録して返す。接続前に 1 回だけ呼ぶ。
///
/// 登録失敗は `INTERNAL`、Linux の未確認アーキテクチャは `UNIMPLEMENTED`（どちらも固定文言）。
/// VM を安全に止められない状態で動かさないため、呼び出し側は fail-closed で終了する。
/// Linux・macOS 以外（Windows・他の unix）では登録せず、決して立たないフラグを `Ok` で返す
/// （SIGTERM での後始末は効かない。モジュール doc「契約」参照。REPAIR-3）。
pub fn install_sigterm_flag() -> Result<&'static AtomicBool, PluginError> {
    register()?;
    Ok(&SIGTERM_RECEIVED)
}

/// 対応済みの組: ハンドラを登録する。失敗は `INTERNAL`。
#[cfg(any(
    target_os = "macos",
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
fn register() -> Result<(), PluginError> {
    if imp::install() {
        Ok(())
    } else {
        Err(PluginError::new(
            fandhe_container_plugin::PluginErrorCode::Internal,
            "failed to install SIGTERM handler",
        ))
    }
}

/// Linux の未確認アーキテクチャ: `SIGTERM` の番号を持たないため登録を試みず拒否する（fail-closed）。
#[cfg(all(
    target_os = "linux",
    not(any(target_arch = "x86_64", target_arch = "aarch64"))
))]
fn register() -> Result<(), PluginError> {
    Err(PluginError::new(
        fandhe_container_plugin::PluginErrorCode::Unimplemented,
        "SIGTERM handler is not supported on this architecture",
    ))
}

/// Linux・macOS 以外: 何も登録しない（決して立たないフラグを返す側。REPAIR-3）。
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn register() -> Result<(), PluginError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 対応済みの組の番号を具体値で固定する（libc 照合の代わり。PLUG-1）。
    #[cfg(any(
        target_os = "macos",
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    ))]
    #[test]
    fn plug1_sigterm_number_is_15() {
        assert_eq!(imp::SIGTERM, 15);
    }

    /// 自プロセスへ SIGTERM を送るとフラグが立ち、プロセスは落ちず、2 回目でも立ったままである
    /// （PLUG-1・REPAIR-5）。送信は `kill` コマンドで行い、unsafe の面を `signal` 1 箇所に保つ。
    /// 静的なフラグを共有するため、立つことの確認は本試験 1 件にまとめる。
    #[cfg(any(
        target_os = "macos",
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    ))]
    #[test]
    fn task117_plug1_repair5_sigterm_to_self_sets_flag() {
        use std::sync::atomic::Ordering;
        use std::time::{Duration, Instant};

        fn send_term() {
            let status = std::process::Command::new("kill")
                .args(["-TERM", &std::process::id().to_string()])
                .status()
                .expect("spawn kill");
            assert!(status.success(), "kill -TERM failed: {status:?}");
        }

        assert!(!SIGTERM_RECEIVED.load(Ordering::SeqCst));
        let flag = install_sigterm_flag().expect("install");
        assert!(std::ptr::eq(flag, &SIGTERM_RECEIVED));
        assert!(!flag.load(Ordering::SeqCst));

        send_term();
        let deadline = Instant::now() + Duration::from_secs(5);
        while !flag.load(Ordering::SeqCst) {
            assert!(
                Instant::now() < deadline,
                "SIGTERM flag not set within 5s of kill -TERM"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(flag.load(Ordering::SeqCst));

        // BSD セマンティクスでハンドラが残ること: 2 回目でもプロセスが生きていて、フラグは立ったまま。
        send_term();
        std::thread::sleep(Duration::from_millis(50));
        assert!(flag.load(Ordering::SeqCst));
    }

    /// Linux の未確認アーキテクチャは `UNIMPLEMENTED` で拒否し、フラグは立たない。
    #[cfg(all(
        target_os = "linux",
        not(any(target_arch = "x86_64", target_arch = "aarch64"))
    ))]
    #[test]
    fn plug1_unknown_linux_arch_is_unimplemented() {
        use std::sync::atomic::Ordering;
        let e = install_sigterm_flag().expect_err("must be rejected");
        assert_eq!(
            e.code(),
            fandhe_container_plugin::PluginErrorCode::Unimplemented
        );
        assert_eq!(
            e.message(),
            "SIGTERM handler is not supported on this architecture"
        );
        assert!(!SIGTERM_RECEIVED.load(Ordering::SeqCst));
    }

    /// Windows・他の unix は何も登録せず、決して立たないフラグを `Ok` で返す（REPAIR-3）。
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    #[test]
    fn repair3_unsupported_os_returns_never_set_flag() {
        use std::sync::atomic::Ordering;
        let flag = install_sigterm_flag().expect("ok");
        assert!(!flag.load(Ordering::SeqCst));
    }
}
