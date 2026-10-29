//! SIGTERM / SIGINT の受信記録（`unsafe` 事前承認の範囲。#3226・CRI-1・CORE-1・REPAIR-3・REPAIR-5。
//! coding-rust.md「unsafe・FFI・syscall」節・オーナー決定 2026-09-27
//! 〔[#4](https://github.com/Fandhe-AI/fandhe-container/issues/4#issuecomment-5856057084)・
//! [範囲限定](https://github.com/Fandhe-AI/fandhe-container/issues/4#issuecomment-5856167174)〕）。
//!
//! # 呼び出し文脈
//! `main.rs` が受付の前に [`install_shutdown_signals`] を 1 回呼び、受信は [`received`] で見る
//! （`shutdown` モジュールの待ち future と、起動段の境界での確認）。受け取ったら新しい接続と RPC を止め、
//! 実行中の RPC を期限つきで待って終了する（停止の契約は `docs/design/cri-record-readoption.md`「停止の契約」）。
//!
//! # シグナルの受け方の判断（#3226 の A3）
//! - 採用: 最小限の `extern "C"` 宣言を自前で持つ（`crates/plugin-macos/src/sys.rs` と同じ流儀）。`signal(3)` は
//!   glibc・musl・macOS とも BSD セマンティクスでハンドラが解除されず、`struct sigaction` のレイアウト差も踏まない。
//! - 不採用: tokio の `signal` feature（workspace 依存の feature 変更で承認が要る。Cargo.toml の方針で使わない）。
//!   `signalfd` + `sigprocmask`（ブロックしたマスクが exec 後の子〔supervisor・getent 等〕へ引き継がれる）。
//!   self-pipe + `AsyncFd`（FFI の宣言が増える。検知遅延が数百 ms 許されるので atomic のポーリングで足りる）。
//! - 継承した `SIG_IGN` も上書きする。常駐サーバーで SIGTERM が無視されると止める手段が SIGKILL だけになるため。
//!
//! libc との機械照合: plugin-cri は dev-dependencies に `libc` を持たないため未導入（依存の追加は承認事項。
//! 番号の出典は Linux `include/uapi/asm-generic/signal.h`〔SIGINT=2・SIGTERM=15。x86_64・aarch64 とも同じ〕と
//! macOS `sys/signal.h`〔同値〕）。導入は後続（#1837 の子として起票候補）。
//!
//! # fork した子への継承（#3300）
//! 登録したハンドラは exec しない `fork` の子へ引き継がれ、そうした子は停止シグナルでは死なない（atomic を立てるだけ）。
//! 前提と帰結:
//! - exec した子（`std::process::Command` 経由の supervisor・systemd-run・getent 等）は、`execve` で捕捉中のハンドラが
//!   `SIG_DFL` に戻る（`SIG_IGN` は引き継がれる）ため問題にならない。
//! - exec しない fork の原始は core の `fork_single_threaded*`（`sys` の `fork` 宣言）だけで、plugin-cri の依存に
//!   `fandhe-container-cli`（もう 1 つの `fork` 宣言）は無い。可否は **fork の瞬間の `Threads: 1`** で決まる（join 済み・
//!   終了済みのスレッドは数えない）。だから窓は「ハンドラの登録から常駐スレッド（`LineSink`・forwarder・tokio の
//!   blocking pool）ができるまでの間に、**メインスレッドが直接**呼ぶ処理」であり、スレッドで包んだ呼び出しの最中は
//!   メインが待っていて `Threads >= 2` になるため `MultiThreaded` で拒否される。
//! - 起動段の調査結果（#3415。調べた時点は main の 81577bce、静的な読解による）。窓の中でメインが直接呼ぶ処理は
//!   fork に到達しない:
//!
//!   | 段 | 主な呼び出し | fork の呼び出し点への到達 |
//!   | -- | ------------ | ------------------------- |
//!   | backends の構築 | `StateRoot::resolve`・`FileStateStore::open`・インスタンスロック（sleep の再試行のみ）・`LinuxNetsetup::with_recorder`・`ReclaimStore::open`・`NetsetupNetwork::with_reclaim_store`・`CoreLifecycleRuntime::with_recorder` | 無し（ファイル操作と構築のみ。構築時に回収・netns 操作は走らない） |
//!   | bundle・記録ストア・image service | `production_bundle_provider`（`bundle_provider_with`）・`production_record_store`・`image_service`（`OciRegistryClient::new`） | 無し（ディレクトリの作成・検証と設定の組み立てのみ） |
//!   | pull の回収 | `recover_stale_image_pulls` | worker スレッドで包む（メインは待ち）。fork は `MultiThreaded` で拒否 |
//!   | 記録の再採用 | `readopt_records`（core の呼び出しは cri の `call_with_deadline`、孤児 bundle は `orphan_bundles::with_deadline`） | 呼び出しはすべてスレッドで包まれ、メインは直接 core を呼ばない |
//!   | ランタイム・forwarder | tokio の current_thread ランタイム・`PeerAuditForwarder::spawn` | 無し（以後は常駐スレッドができる） |
//!
//!   fork の呼び出し点（`audit_log` の隔離の子・launch の中間プロセス・mapper・exec・seccomp listener・image rootfs の
//!   userns の子）は、CRI の RPC 経路（常駐スレッドの後）か、上のスレッドで包んだ経路からしか呼ばれない。よって届く経路は
//!   見つかっていない。万一届いても、子が継承するのは捕捉中のハンドラ（atomic を立てるだけ）で停止シグナルでは死なず、
//!   親の待ちは各段の期限と SIGKILL で回収される。常駐スレッドの後に image rootfs の userns の fork が `MultiThreaded`
//!   で拒否される点は別件（#2315）で、ここでは扱わない。
//! - 監査 relay の helper は fork の直後に自分で SIGTERM・SIGINT を `SIG_IGN` にする
//!   （`ControlAuditRelay::spawn_ignoring_stop_signals`）。継承に頼らない。
//!
//! 固定する試験: 結合試験 `shutdown_audit_helper`（登録後に exec した子の `SigCgt` にビットが無いこと、helper の
//! `SigIgn` にビットがあること）。
//!
//! # 契約
//! - `unsafe fn` は公開しない。公開するのは安全な [`install_shutdown_signals`] と [`received`] のみ。
//! - ハンドラは `static AtomicI32` への compare_exchange だけを行う（async-signal-safe。確保・ロック・I/O・panic なし）。
//!   最初に届いた 1 つだけを記録し、2 回目以降のシグナルは何もしない（停止の途中で再度届いても全体の上限は変わらない）。
//! - 登録するのは番号を確認済みの組（Linux の x86_64 / aarch64・macOS）だけ。Linux の他アーキテクチャは
//!   登録を試みず `UNIMPLEMENTED` を返す（呼び出し側は fail-closed で起動しない）。
//! - 上記以外の unix は何も登録せず `Ok` を返し、[`received`] は常に `None`（実装済みを装わない。REPAIR-3。
//!   SIGTERM は既定動作のまま届き、後始末を経ずに終了する）。SIGHUP は対象外（既定動作）。

use std::sync::atomic::{AtomicI32, Ordering};

use fandhe_container_plugin::PluginError;

/// 受け取った停止シグナル。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShutdownSignal {
    /// SIGTERM。
    Term,
    /// SIGINT。
    Int,
}

impl ShutdownSignal {
    /// 固定語彙のシグナル名（stderr の 1 行に使う。REPAIR-4）。
    pub fn as_str(self) -> &'static str {
        match self {
            ShutdownSignal::Term => "SIGTERM",
            ShutdownSignal::Int => "SIGINT",
        }
    }
}

/// 最初に受け取ったシグナルの符号（0 = 未受信、1 = SIGTERM、2 = SIGINT）。立てるのはハンドラだけ。
static RECEIVED: AtomicI32 = AtomicI32::new(0);
const CODE_TERM: i32 = 1;
const CODE_INT: i32 = 2;

/// 最初に受け取った停止シグナル。未受信（と、何も登録しない OS）では `None`。
pub fn received() -> Option<ShutdownSignal> {
    match RECEIVED.load(Ordering::SeqCst) {
        CODE_TERM => Some(ShutdownSignal::Term),
        CODE_INT => Some(ShutdownSignal::Int),
        _ => None,
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
    use std::sync::atomic::Ordering;

    use super::{CODE_INT, CODE_TERM, RECEIVED};

    // 番号はどの組でも同じだが、アーキテクチャ差の流用を避けるため腕ごとに個別に定義する。
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    pub(super) const SIGINT: i32 = 2;
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    pub(super) const SIGTERM: i32 = 15;
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    pub(super) const SIGINT: i32 = 2;
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    pub(super) const SIGTERM: i32 = 15;
    #[cfg(target_os = "macos")]
    pub(super) const SIGINT: i32 = 2;
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

    /// 停止シグナルのハンドラ。atomic の compare_exchange のみ（async-signal-safe）。最初の 1 つだけを記録する。
    pub(super) extern "C" fn on_signal(signum: i32) {
        let code = if signum == SIGTERM {
            CODE_TERM
        } else if signum == SIGINT {
            CODE_INT
        } else {
            return;
        };
        let _ = RECEIVED.compare_exchange(0, code, Ordering::SeqCst, Ordering::SeqCst);
    }

    /// SIGTERM と SIGINT のハンドラを登録する。両方成功なら `true`。
    pub(super) fn install() -> bool {
        let handler: extern "C" fn(i32) = on_signal;
        // SAFETY: ハンドラは `'static` な関数で、単一の `static AtomicI32` 以外に触れない。
        // シグナルはどのスレッドにも配送され得るが、atomic の操作のみのため安全。BSD セマンティクスで
        // ハンドラは解除されないため、再設定は要らない。
        let term = unsafe { signal(SIGTERM, handler as usize) };
        // SAFETY: 同上（番号だけが異なる）。
        let int = unsafe { signal(SIGINT, handler as usize) };
        term != SIG_ERR && int != SIG_ERR
    }
}

/// 停止シグナル（SIGTERM・SIGINT）の受信記録を登録する。受付の前に 1 回だけ呼ぶ。
///
/// 登録失敗は `INTERNAL`、Linux の未確認アーキテクチャは `UNIMPLEMENTED`（どちらも固定文言）。
/// 後始末を経ずに死ぬ状態で動かさないため、呼び出し側は fail-closed で起動しない。
/// 上記以外の非対応 unix では登録せず `Ok` を返す（モジュール doc「契約」。REPAIR-3）。
pub fn install_shutdown_signals() -> Result<(), PluginError> {
    register()
}

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
            "failed to install the shutdown signal handler",
        ))
    }
}

/// Linux の未確認アーキテクチャ: 番号を持たないため登録を試みず拒否する（fail-closed）。
#[cfg(all(
    target_os = "linux",
    not(any(target_arch = "x86_64", target_arch = "aarch64"))
))]
fn register() -> Result<(), PluginError> {
    Err(PluginError::new(
        fandhe_container_plugin::PluginErrorCode::Unimplemented,
        "the shutdown signal handler is not supported on this architecture",
    ))
}

/// Linux・macOS 以外の unix: 何も登録しない（決して立たない。REPAIR-3）。
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn register() -> Result<(), PluginError> {
    Ok(())
}

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

    /// 静的状態を共有するため 1 件にまとめる（CRI-1・REPAIR-5）。ハンドラは直接呼ぶ（自プロセスへ raise しない）。
    /// `install_shutdown_signals()` は呼ばない: libtest のプロセスで SIGINT・SIGTERM が効かなくなり Ctrl-C で
    /// 止まらなくなるため（#3300）。登録の成功は本番バイナリの試験（`container_grpc` の停止の段）と、別プロセスで
    /// 登録する結合試験 `shutdown_audit_helper` が担う。
    #[test]
    fn handler_records_only_the_first_signal() {
        assert_eq!(received(), None);
        imp::on_signal(imp::SIGINT);
        assert_eq!(received(), Some(ShutdownSignal::Int));
        imp::on_signal(imp::SIGTERM);
        assert_eq!(received(), Some(ShutdownSignal::Int));
        imp::on_signal(1234);
        assert_eq!(received(), Some(ShutdownSignal::Int));
        assert_eq!(ShutdownSignal::Int.as_str(), "SIGINT");
        assert_eq!(ShutdownSignal::Term.as_str(), "SIGTERM");
    }
}
