//! holder の期限切れ後始末の結合試験(CORE-6・SEC-5・REPAIR-5・#2551)。
//!
//! 本番の holder(`unshare(CLONE_NEWUSER)` 済み)、`setsid` 済みの mapper、止められた helper、呼び出し元(中間プロセス I)
//! を実プロセスで起動し、呼び出し元が消え helper が SIGSTOP で止まったまま期限が来る状況を再現する。具体値で照合する。
//!
//! - 期限前: holder は生きており、helper は停止(`T`)のまま(holder は pid を解放していない)
//! - 期限後: 別 user namespace の holder が mapper のセッションへ送った SIGKILL で、mapper と helper が SIGKILL(9) で終わる
//! - holder は mapper と helper が終わった後に、終了コード 1(期限切れで kill した)で終わる(EOF を確かめてから)
//! - holder の生存は `release_wait + drain_wait` 内に収まる(REPAIR-5)
//!
//! 単一スレッドの fork が要るため `harness = false`。非 Linux では対象外。`-- --ignored` 指定時のみ実行する実機前提
//! テスト(非特権 user namespace を許可するホスト・`setsid` コマンドが必要。AGENTS.md)。成功行は
//! `rootless_holder_expiry: holder outlived the stopped helper until expiry, then killed its session (...)`。

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("rootless_holder_expiry: Linux only, not applicable on this OS");
}

#[cfg(target_os = "linux")]
fn main() {
    if std::env::args().any(|a| a == "--ignored") {
        linux::run();
    } else {
        println!(
            "rootless_holder_expiry: ignored (real-machine test; run with `-- --ignored`, see AGENTS.md)"
        );
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::time::Duration;

    use fandhe_container_core::rootless::observe_holder_expiry;

    /// `waitpid` の生の status が SIGKILL による終了か。
    fn killed_by_sigkill(status: i32) -> bool {
        status & 0x7f == 9
    }

    pub fn run() {
        let release = Duration::from_secs(4);
        let drain = Duration::from_secs(5);
        let o = observe_holder_expiry(release, drain).expect("observe holder expiry");
        assert!(
            o.holder_alive_at_midpoint,
            "holder exited before the release wait ended: {o:?}"
        );
        assert_eq!(
            o.helper_state_at_midpoint,
            Some('T'),
            "helper must still be stopped while the holder is alive: {o:?}"
        );
        assert_eq!(
            o.holder_status >> 8 & 0xff,
            1,
            "holder must exit with code 1 after an expiry kill: {o:?}"
        );
        assert_eq!(
            o.holder_status & 0x7f,
            0,
            "holder must exit normally: {o:?}"
        );
        assert!(
            o.mapper_status.is_some_and(killed_by_sigkill),
            "mapper must be ended by SIGKILL before the holder exits: {o:?}"
        );
        assert!(
            o.helper_status.is_some_and(killed_by_sigkill),
            "helper must be ended by SIGKILL before the holder exits: {o:?}"
        );
        assert!(
            o.holder_exit_after_caller_exit <= release + drain,
            "holder outlived release_wait + drain_wait: {o:?}"
        );
        println!(
            "rootless_holder_expiry: holder outlived the stopped helper until expiry, then killed its session (holder exit after {} ms)",
            o.holder_exit_after_caller_exit.as_millis()
        );
    }
}
