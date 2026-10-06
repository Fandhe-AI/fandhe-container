//! SIGTERM 受信フラグの登録（`unsafe` 事前承認の範囲。TASK-115.5・#389。MAC-1・PLUG-1・REPAIR-3・REPAIR-5。
//! coding-rust.md「unsafe・FFI・syscall」節・オーナー決定 2026-09-27
//! 〔[#4](https://github.com/Fandhe-AI/fandhe-container/issues/4#issuecomment-5856057084)・
//! [範囲限定](https://github.com/Fandhe-AI/fandhe-container/issues/4#issuecomment-5856167174)〕）。
//!
//! # 呼び出し文脈
//! `main.rs` が接続前に [`install_sigterm_flag`] を 1 回呼び、得たフラグを
//! `frame_loop::serve_until` へ渡す。SIGTERM は core 以外（運用者・OS・launchd 等）から届く経路で、
//! フラグが立つとフレームループが次の受信境界で抜け、`stop_all` で起動中の VM を停止してから終了する。
//! core 自身の終了要求は SIGTERM を使わず接続切断（EOF）で伝わる（`ResidentPlugin::shutdown`）。
//!
//! `libc` / `nix` は依存追加が承認制（dependency-policy）で std にシグナル API が無いため、
//! `crates/plugin/src/sys.rs` と同じ流儀で最小限の `extern "C"` 宣言を自前で持つ。`struct sigaction` は
//! OS・アーキテクチャでレイアウトが異なるため使わず、番号とハンドラのアドレスだけを取る `signal(3)`
//! （glibc・musl・macOS とも BSD セマンティクスで、ハンドラは解除されず再設定も不要）を使う。
//!
//! # 契約
//! - `unsafe fn` は公開しない。公開するのは安全な [`install_sigterm_flag`] のみ。
//! - ハンドラは `static AtomicBool` への `store` だけを行う（async-signal-safe。確保・ロック・I/O をしない）。
//! - 登録するのは `SIGTERM` の番号を確認済みの組（Linux の x86_64 / aarch64・macOS）だけ。
//! - Linux の他アーキテクチャは番号が未確認のため登録を試みず、`UNIMPLEMENTED` を返す（呼び出し側は
//!   fail-closed で終了する。SIGTERM の既定動作で後始末を経ずに終了する状態では起動させない）。
//! - Linux 以外の非対応 OS（Windows・FreeBSD 等の他の unix）は何も登録せず、決して立たないフラグを `Ok` で
//!   返す（実装済みを装わない。REPAIR-3）。Windows には SIGTERM 経路が無い。他の unix では SIGTERM が
//!   既定動作のまま届き、後始末を経ずに即終了する。
//! - 返したフラグを立てるのはハンドラだけ、というのは呼び出し側の規約である。戻り値は
//!   `&'static AtomicBool` で `store` を呼べるため、型では強制していない。
//!
//! # 限界（残存リスク）
//! SIGKILL は捕捉できない。SIGTERM 送信側の猶予内に `stop_all`（最大 `SHUTDOWN_BUDGET` 4 秒）が終わらず
//! SIGKILL された場合、VM は残留しうる。SIGINT / SIGHUP は本モジュールの対象外（#389 の受入基準は SIGTERM のみ）。
//! 何も登録しない OS（契約の項を参照）では、SIGTERM は既定動作で即終了するか（他の unix）
//! そもそも届かず（Windows）、VM は停止されない。

use std::sync::atomic::AtomicBool;

use fandhe_container_plugin::PluginError;

/// SIGTERM 受信で立つフラグ。本モジュール内で立てるのはハンドラだけ。[`install_sigterm_flag`] が
/// `&'static AtomicBool` として外へ渡すため、呼び出し側が立てないことは規約であり型では強制していない。
static SIGTERM_RECEIVED: AtomicBool = AtomicBool::new(false);

// `SIGTERM` の番号を定義した組だけで有効にする。Linux の他アーキテクチャは [`install_sigterm_flag`] が
// 実行時に `UNIMPLEMENTED` で拒否する。`crates/plugin/src/sys.rs` の流儀に合わせた選択で、同ファイルは
// 未確認のアーキテクチャを `compile_error!` でなく実行時のエラー（`Unsupported`。fail-closed）で扱い、
// `compile_error!` は構造体レイアウトの取り違えが未定義動作になる箇所に限っている。番号とハンドラの
// アドレスしか渡さない `signal(3)` にその危険は無く、ビルドを拒否すると workspace 全体がそのターゲットで
// ビルドできなくなる。OS だけで分岐していた従来は Linux の他アーキテクチャで定数未定義のコンパイル
// エラーになっていた。ビルドは通すが起動は拒否するため、後始末なしで動く構成は増やさない。
// 対応済みの組と Linux 以外の OS の挙動は変えていない。
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
        // 前提は、本モジュールが有効になる組（外側の cfg）で `sighandler_t`（関数ポインタ）と `usize` が
        // 同じ幅で、整数レジスタで同じように受け渡されること。ポインタ幅が 64 ビットであることには頼らない。
        // 幅は直下の const assert がコンパイル時に確かめる。
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
/// Linux 以外の非対応 OS（Windows・他の unix）では登録せず、決して立たないフラグを `Ok` で返す
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

/// Linux 以外の非対応 OS: 何も登録しない（決して立たないフラグを返す側。REPAIR-3）。
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn register() -> Result<(), PluginError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;

    use super::*;

    /// TASK-115.5・MAC-1: 登録に成功し（Linux 以外の非対応 OS では何もせず `Ok`）、初期値は偽。
    #[cfg(not(all(
        target_os = "linux",
        not(any(target_arch = "x86_64", target_arch = "aarch64"))
    )))]
    #[test]
    fn task115_5_mac1_install_succeeds_and_flag_starts_false() {
        let flag = install_sigterm_flag().expect("install");
        assert!(!flag.load(Ordering::SeqCst));
    }

    /// TASK-115.5・MAC-1・REPAIR-3: Linux の未確認アーキテクチャは登録せず `UNIMPLEMENTED` で拒否する（fail-closed）。
    #[cfg(all(
        target_os = "linux",
        not(any(target_arch = "x86_64", target_arch = "aarch64"))
    ))]
    #[test]
    fn task115_5_mac1_unverified_linux_arch_is_rejected() {
        let err = install_sigterm_flag().expect_err("must reject");
        assert_eq!(
            err.code(),
            fandhe_container_plugin::PluginErrorCode::Unimplemented
        );
        assert_eq!(
            err.message(),
            "SIGTERM handler is not supported on this architecture"
        );
        assert!(!SIGTERM_RECEIVED.load(Ordering::SeqCst));
    }

    #[cfg(any(
        target_os = "macos",
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    ))]
    #[test]
    fn task115_5_mac1_sigterm_number_is_15() {
        assert_eq!(imp::SIGTERM, 15);
    }
}
