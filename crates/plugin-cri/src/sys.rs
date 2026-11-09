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

/// [`poll_writable`] の結果（REPAIR-5・CRI-6・#4077）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WritePoll {
    /// 1 バイト以上書ける（パイプは `PIPE_BUF` まで、pty は空きがある）。
    Ready,
    /// 期限内に書けるようにならなかった（または `EINTR`）。
    NotReady,
    /// 相手が閉じた・エラー・無効な fd（`POLLERR`・`POLLHUP`・`POLLNVAL`）。
    Closed,
}

/// `fd` が書き込み可能になるまで最大 `timeout_ms` ミリ秒待つ（`poll(2)`。`fd` の記述のフラグは変えない）。
///
/// 呼び出し元は `supervisor_attach` の入力スレッド。blocking の `write` の前に呼び、取り消しを見ながら
/// 有限の刻みで待つことで、コンテナが stdin を読まなくても回収できるようにする（REPAIR-5）。
/// 失敗（`poll` の `EINTR` 以外のエラー）は `Err`。非対応の組では常に `Err(Unsupported)`
/// （呼び出し側は書き込みを諦め、警告を一度だけ出す。REPAIR-4・#4135）。
///
/// `timeout_ms` は `u16`（最大 65535 ms）。`0` はすぐに返る。`poll` に負の値を渡すと無期限に待つため、負の期限は
/// 型で表現できないようにしてある（REPAIR-5・#4135）。
pub fn poll_writable(
    fd: std::os::fd::BorrowedFd<'_>,
    timeout_ms: u16,
) -> std::io::Result<WritePoll> {
    poll_imp::poll_writable(fd, timeout_ms)
}

/// `open(2)` の `O_NONBLOCK`（CRI-6・REPAIR-5・#4287）。`/proc/self/fd/N` の開き直し（Linux のみ）で使う。
/// 値は Linux の `include/uapi/asm-generic/fcntl.h`（x86_64・aarch64 とも 0o4000）。他の組は `None`
/// （開き直さず従来の共有記述の経路を使う）。`libc` の機械照合は plugin-cri には未導入。
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
pub const O_NONBLOCK: Option<i32> = Some(0o4000);
/// 非対応の組では開き直さない。
#[cfg(not(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
)))]
pub const O_NONBLOCK: Option<i32> = None;

#[cfg(any(
    target_os = "macos",
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
mod poll_imp {
    use std::os::fd::{AsRawFd as _, BorrowedFd};

    use super::WritePoll;

    // 値は Linux の `include/uapi/asm-generic/poll.h`（x86_64・aarch64 とも同じ）と macOS の `sys/poll.h` で同じ。
    const POLLOUT: i16 = 0x0004;
    const POLLERR: i16 = 0x0008;
    const POLLHUP: i16 = 0x0010;
    const POLLNVAL: i16 = 0x0020;

    /// `struct pollfd`（`int fd; short events; short revents;`。Linux・macOS 共通のレイアウト）。
    #[repr(C)]
    struct PollFd {
        fd: i32,
        events: i16,
        revents: i16,
    }

    /// `nfds_t`: Linux は `unsigned long`、macOS は `unsigned int`。
    #[cfg(target_os = "linux")]
    type NfdsT = std::ffi::c_ulong;
    #[cfg(target_os = "macos")]
    type NfdsT = std::ffi::c_uint;

    unsafe extern "C" {
        // SAFETY（宣言そのものの妥当性）: POSIX の `int poll(struct pollfd *fds, nfds_t nfds, int timeout)`。
        // `PollFd` は上のとおり `struct pollfd` と同じレイアウト。
        fn poll(fds: *mut PollFd, nfds: NfdsT, timeout: i32) -> i32;
    }

    pub(super) fn poll_writable(fd: BorrowedFd<'_>, timeout_ms: u16) -> std::io::Result<WritePoll> {
        let mut pfd = PollFd {
            fd: fd.as_raw_fd(),
            events: POLLOUT,
            revents: 0,
        };
        // SAFETY: `pfd` は 1 要素の有効な `struct pollfd` で、`nfds` は 1。呼び出しの間 `fd`（BorrowedFd）は開いたまま。
        // `poll` は `revents` だけを書き、保持しない。
        // 期限は `u16` から変換するので常に 0 以上で、無期限の待ち（負の値）は表現できない。
        let rc = unsafe { poll(&raw mut pfd, 1, i32::from(timeout_ms)) };
        if rc < 0 {
            let e = std::io::Error::last_os_error();
            return if e.kind() == std::io::ErrorKind::Interrupted {
                Ok(WritePoll::NotReady)
            } else {
                Err(e)
            };
        }
        if rc == 0 {
            return Ok(WritePoll::NotReady);
        }
        if pfd.revents & POLLOUT != 0 {
            Ok(WritePoll::Ready)
        } else if pfd.revents & (POLLERR | POLLHUP | POLLNVAL) != 0 {
            Ok(WritePoll::Closed)
        } else {
            Ok(WritePoll::NotReady)
        }
    }
}

#[cfg(not(any(
    target_os = "macos",
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
)))]
mod poll_imp {
    use std::os::fd::BorrowedFd;

    use super::WritePoll;

    pub(super) fn poll_writable(
        _fd: BorrowedFd<'_>,
        _timeout_ms: u16,
    ) -> std::io::Result<WritePoll> {
        Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
    }
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

    type Pair = (
        std::os::unix::net::UnixStream,
        std::os::unix::net::UnixStream,
    );

    /// 書き込み側を満杯にした socketpair（`WouldBlock` まで書く）。
    fn full_socket() -> Pair {
        use std::io::Write as _;
        let (mut a, b) = std::os::unix::net::UnixStream::pair().expect("pair");
        a.set_nonblocking(true).expect("nonblocking");
        let buf = [0u8; 4096];
        loop {
            match a.write(&buf) {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => panic!("fill failed: {e}"),
            }
        }
        (a, b)
    }

    /// 期限の型は負にならず、`poll` へ渡す値は常に 0 以上（無期限の待ちにならない。REPAIR-5・CRI-6・#4135）。
    #[test]
    fn cri6_repair5_4135_timeout_converts_without_going_negative() {
        use std::os::fd::AsFd as _;
        assert_eq!(i32::from(u16::MIN), 0);
        assert_eq!(i32::from(u16::MAX), 65_535);
        let (a, _b) = full_socket();
        let t = std::time::Instant::now();
        assert_eq!(
            poll_writable(a.as_fd(), 0).expect("poll"),
            WritePoll::NotReady
        );
        assert!(t.elapsed() < std::time::Duration::from_secs(1));
    }

    /// 有限の期限が効く（満杯の fd で 10 ms 待って `NotReady`）。
    #[test]
    fn cri6_repair5_4135_finite_timeout_expires() {
        use std::os::fd::AsFd as _;
        let (a, _b) = full_socket();
        let t = std::time::Instant::now();
        assert_eq!(
            poll_writable(a.as_fd(), 10).expect("poll"),
            WritePoll::NotReady
        );
        let e = t.elapsed();
        assert!(e >= std::time::Duration::from_millis(9), "{e:?}");
        assert!(e < std::time::Duration::from_secs(5), "{e:?}");
    }

    /// 陽性対照: 空きのある socket は `Ready`。
    #[test]
    fn cri6_repair5_4135_writable_socket_is_ready() {
        use std::os::fd::AsFd as _;
        let (a, _b) = std::os::unix::net::UnixStream::pair().expect("pair");
        assert_eq!(poll_writable(a.as_fd(), 0).expect("poll"), WritePoll::Ready);
    }
}
