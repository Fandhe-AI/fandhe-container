//! SIGTERM 受信フラグの登録（`unsafe` 事前承認の範囲。TASK-116.5・#396。WIN-1・PLUG-1・REPAIR-3・REPAIR-5。
//! coding-rust.md「unsafe・FFI・syscall」節・オーナー決定 2026-09-27
//! 〔[#4](https://github.com/Fandhe-AI/fandhe-container/issues/4#issuecomment-5856057084)・
//! [範囲限定](https://github.com/Fandhe-AI/fandhe-container/issues/4#issuecomment-5856167174)〕）。
//!
//! # 呼び出し文脈
//! `main.rs` が接続前に [`install_sigterm_flag`] を 1 回呼び、得たフラグを
//! `frame_loop::serve_until` へ渡す。SIGTERM は core 以外（運用者・OS・launchd 等）から届く経路で、
//! フラグが立つとフレームループが次の受信境界で抜け、`release_all` で保持中の共有マウントを解除してから終了する。
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
//! - 対応 OS は Linux・macOS。それ以外（Windows 等）は何も登録せず、決して立たないフラグを返す
//!   （SIGTERM 経路なし。実装済みを装わない。REPAIR-3）。
//!
//! # 限界（残存リスク）
//! SIGKILL は捕捉できない。SIGTERM 送信側の猶予内に `release_all`（最大 `RELEASE_ALL_BUDGET` 4 秒）が終わらず
//! SIGKILL された場合、共有マウントは残留しうる（回収は #1412）。Windows ホスト上のビルドではシグナル経路が無くフラグは立たない
//! （コンソール制御ハンドラ等は未実装。REPAIR-3）。SIGINT / SIGHUP は本モジュールの対象外（#396 の受入基準は SIGTERM のみ）。

use std::sync::atomic::AtomicBool;

use fandhe_container_plugin::PluginError;

/// SIGTERM 受信で立つフラグ。ハンドラ以外から立てない。
static SIGTERM_RECEIVED: AtomicBool = AtomicBool::new(false);

#[cfg(any(target_os = "linux", target_os = "macos"))]
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
        // 対象ターゲット（Linux・macOS の 64 ビット）では関数ポインタ・`sighandler_t` が `usize` と同じ幅。
        fn signal(signum: i32, handler: usize) -> usize;
    }

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
/// 登録失敗は `INTERNAL`（固定文言）。共有マウントを安全に解除できない状態で動かさないため、呼び出し側は
/// fail-closed で終了する。非対応 OS では登録せず、決して立たないフラグを返す。
pub fn install_sigterm_flag() -> Result<&'static AtomicBool, PluginError> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        if !imp::install() {
            return Err(PluginError::new(
                fandhe_container_plugin::PluginErrorCode::Internal,
                "failed to install SIGTERM handler",
            ));
        }
    }
    Ok(&SIGTERM_RECEIVED)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;

    use super::*;

    /// TASK-116.5・WIN-1: 登録に成功し、初期値は偽。
    #[test]
    fn task116_5_win1_install_succeeds_and_flag_starts_false() {
        let flag = install_sigterm_flag().expect("install");
        assert!(!flag.load(Ordering::SeqCst));
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn task116_5_win1_sigterm_number_is_15() {
        assert_eq!(imp::SIGTERM, 15);
    }
}
