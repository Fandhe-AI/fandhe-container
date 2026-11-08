//! 完全版 Attach の入出力を、起動直後の `LaunchedProcess` から取り出して捕捉と世代の保持へ振り分ける包み
//! （SUP-7・SUP-3・CRI-6・SEC-1・REPAIR-5・#4074。設計は `docs/design/cri-streaming-server.md` の D3・D8・D9）。
//!
//! # 役割
//! core の `LaunchedProcess` は `take_output`（stdout / stderr の pipe）・`take_stdin`（stdin の書き込み端）・
//! `take_pty_master`（tty の master）を各 1 回だけ返す。tty のコンテナでは出力が master 1 本に載るため、
//! 「master をログの捕捉（`LogCapture`）の stdout 1 本として渡す」と「attach 用に master の複製を世代の保持先
//! （[`crate::control::target::SignalSlot`] の `Active`）へ渡す」を、取り出しの順序に依存せず両立させる必要がある。
//! [`AttachIoProcess::wrap`] が構築の時点でそれを分ける。
//!
//! # 呼び出し文脈（ここが唯一の適用点）
//! - 起動: `start_entry::launch_prepared` が `launch_claimed` の戻りのプロセスを包む（`ControlledProcess::new`〔`install`〕より前）
//! - 再起動: `restart::LauncherRelauncher::relaunch` が launch 直後に包む（捕捉の `take_output` より前）
//!
//! 包んだ後は、`ControlledProcess::new` が `take_stdin` / `take_pty_master` をスロットへ移し、捕捉が `take_output` で
//! master の読み取り側（tty）または core の pipe（非 tty）を受け取る。この順序の逆転（起動と再起動で `take_output` と
//! `ControlledProcess::new` の順が逆）が、`ControlledProcess::new` だけで分けられない理由である。
//!
//! # 契約
//! - tty（`take_pty_master` が `Some`）: 元の master を [`PtyOutputReader`] に包んで `ContainerOutput.stdout` の 1 本として返し
//!   （`stderr` は `None`。tty は stdout と stderr が混ざる）、`as_fd().try_clone_to_owned()`（`F_DUPFD_CLOEXEC`）の複製を
//!   `PtyMaster::from_received` で検証し直して `take_pty_master` で返す。複製できなければログの捕捉を優先し、attach の口だけを
//!   閉じる（C6 は `NoHandle`）。core の stdout / stderr の pipe は取り出して閉じる（init が pty の slave で fd 1 / 2 を置き換えた後で、
//!   `launch` は master を受け取ってから戻るため、書き込み端は誰にも残らない。core の `attach_launch_pty` を参照）
//! - 非 tty: `take_output` は内側へ転送し、`take_stdin` は構築時に取り出して保持した書き込み端を 1 回だけ返す
//! - fail-closed（D8。要求より弱いコンテナを動かさない）: 端末を期待したのに master が届かない、stdin を期待した非 tty で書き込み端が
//!   届かない場合は `Err`。呼び出し側がプロセスを回収して失敗にする
//! - そのほかのメソッドはすべて内側へ転送する（転送漏れは restart 後の exec 拒否・seccomp 応答者の欠落などになる）
//!
//! `unsafe` は書かない。Linux 限定（pty と stdin の pipe は Linux の launcher だけが渡す）。

use std::io::{self, Read};
use std::num::NonZeroU32;
use std::os::fd::OwnedFd;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use fandhe_container_core::exec::{PtyMaster, SeccompListener};
use fandhe_container_core::oci_runtime::{
    ContainerOutput, ContainerStdin, LaunchedProcess, ProcessExit,
};
use fandhe_container_core::traits::{ErrorCode, Signal, TraitError};

use crate::sys;

/// 起動（または再起動）したコンテナについて、呼び出し側が期待する入出力（D8 の fail-closed の根拠）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AttachExpectation {
    /// `process.terminal: true`（`LaunchSpec::terminal()`）。真なら master が届かない起動は失敗にする。
    pub terminal: bool,
    /// `--stdin` の指定（core へ `LaunchStdinMode::Pipe` を渡した）。真かつ非 tty なら書き込み端が届かない起動は失敗にする。
    pub stdin: bool,
}

/// pty の master を読む `Read`。slave の全 fd が閉じたとき `read(2)` が返す `EIO` を EOF（`Ok(0)`）とみなす。
///
/// `LogCapture` は `Interrupted` 以外のエラーを `Internal` として捕捉を打ち切るため、tty の正常終了（コンテナの終了で
/// slave が閉じる）をエラーにしないよう、ここで変換する（`LogCapture` 側は変えない）。`EIO` 以外のエラーはそのまま返す。
pub struct PtyOutputReader<R> {
    inner: R,
}

impl<R: Read> PtyOutputReader<R> {
    /// `inner`（pty の master を読む `Read`）を包む。
    pub fn new(inner: R) -> Self {
        Self { inner }
    }
}

impl<R: Read> Read for PtyOutputReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.inner.read(buf) {
            Err(e) if e.raw_os_error() == Some(sys::EIO) => Ok(0),
            other => other,
        }
    }
}

/// [`AttachExpectation`] に従って入出力を振り分けた `LaunchedProcess`（モジュール doc）。
pub struct AttachIoProcess {
    inner: Box<dyn LaunchedProcess>,
    /// tty のとき master の読み取り側（`take_output` で 1 回だけ返す）。非 tty は `None`（内側へ転送する）。
    tty_output: Mutex<Option<ContainerOutput>>,
    /// tty の master を捕捉と分けた複製（`take_pty_master` で 1 回だけ返す）。
    master_dup: Mutex<Option<PtyMaster>>,
    /// 非 tty の stdin の書き込み端（構築時に内側から取り出した分。`take_stdin` で 1 回だけ返す）。
    stdin: Mutex<Option<ContainerStdin>>,
    /// tty なら真（`take_output` を内側へ転送しない）。
    tty: bool,
}

impl AttachIoProcess {
    /// `inner` の入出力を振り分けて包む。期待した入出力が届かなければ、プロセスを `Err` と一緒に返す
    /// （呼び出し側が回収する。包みの中で terminate はしない）。
    pub fn wrap(
        inner: Box<dyn LaunchedProcess>,
        expect: AttachExpectation,
    ) -> Result<Box<dyn LaunchedProcess>, (Box<dyn LaunchedProcess>, TraitError)> {
        if let Some(master) = inner.take_pty_master() {
            return Ok(Box::new(Self::wrap_tty(inner, master)));
        }
        if expect.terminal {
            return Err((
                inner,
                TraitError::new(ErrorCode::Internal, "the pty master was not delivered"),
            ));
        }
        let stdin = inner.take_stdin();
        if expect.stdin && stdin.is_none() {
            return Err((
                inner,
                TraitError::new(ErrorCode::Internal, "the stdin pipe was not delivered"),
            ));
        }
        Ok(Box::new(Self {
            inner,
            tty_output: Mutex::new(None),
            master_dup: Mutex::new(None),
            stdin: Mutex::new(stdin),
            tty: false,
        }))
    }

    fn wrap_tty(inner: Box<dyn LaunchedProcess>, master: PtyMaster) -> Self {
        // core の pipe は使わない（init は pty の slave で fd 1 / 2 を置き換え済み）。取り出して閉じる。
        drop(inner.take_output());
        drop(inner.take_stdin());
        let dup = master
            .as_fd()
            .try_clone_to_owned()
            .map_err(|_| ())
            .and_then(|fd: OwnedFd| PtyMaster::from_received(fd).map_err(|_| ()));
        let dup = match dup {
            Ok(m) => Some(m),
            Err(()) => {
                // ログの捕捉を優先し、attach の口だけを閉じる（C6 は `NoHandle` を返す）。
                crate::control::log_control_event("pty_master_dup_failed", Some("clone_failed"));
                None
            }
        };
        let reader = PtyOutputReader::new(std::fs::File::from(master.into_owned_fd()));
        Self {
            inner,
            tty_output: Mutex::new(Some(ContainerOutput {
                stdout: Some(Box::new(reader)),
                stderr: None,
            })),
            master_dup: Mutex::new(dup),
            stdin: Mutex::new(None),
            tty: true,
        }
    }
}

impl LaunchedProcess for AttachIoProcess {
    fn pid(&self) -> NonZeroU32 {
        self.inner.pid()
    }

    fn wait(&self, timeout: Duration) -> Result<Option<ProcessExit>, TraitError> {
        self.inner.wait(timeout)
    }

    fn terminate(&self, timeout: Duration) -> Result<(), TraitError> {
        self.inner.terminate(timeout)
    }

    fn signal(&self, signal: Signal, deadline: Instant) -> Result<(), TraitError> {
        self.inner.signal(signal, deadline)
    }

    fn launch_pidfd(&self) -> Option<std::os::fd::BorrowedFd<'_>> {
        self.inner.launch_pidfd()
    }

    /// tty なら master の読み取り側（stdout の 1 本）を 1 回だけ、非 tty なら内側の出力を転送する。
    fn take_output(&self) -> Option<ContainerOutput> {
        if self.tty {
            self.tty_output
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .take()
        } else {
            self.inner.take_output()
        }
    }

    fn take_stdin(&self) -> Option<ContainerStdin> {
        self.stdin
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
    }

    fn take_seccomp_listener(&self) -> Option<SeccompListener> {
        self.inner.take_seccomp_listener()
    }

    fn take_pty_master(&self) -> Option<PtyMaster> {
        self.master_dup
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
    }

    fn launch_isolation(
        &self,
    ) -> Option<&fandhe_container_core::launch_isolation::LaunchIsolationRecord> {
        self.inner.launch_isolation()
    }

    fn launch_rlimits(&self) -> Option<&fandhe_container_core::rlimits::Rlimits> {
        self.inner.launch_rlimits()
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::os::fd::{AsFd, AsRawFd};
    use std::os::unix::fs::MetadataExt;

    use fandhe_container_core::exec::{WindowSize, open_host_pty_for_test};

    use super::*;

    /// 入出力の取り出しだけを答える偽のプロセス。
    struct Fake {
        pid: NonZeroU32,
        stdin: Mutex<Option<ContainerStdin>>,
        master: Mutex<Option<PtyMaster>>,
        output: Mutex<Option<ContainerOutput>>,
    }

    impl Fake {
        fn new() -> Self {
            Self {
                pid: NonZeroU32::new(4242).expect("nonzero"),
                stdin: Mutex::new(None),
                master: Mutex::new(None),
                output: Mutex::new(None),
            }
        }
    }

    impl LaunchedProcess for Fake {
        fn pid(&self) -> NonZeroU32 {
            self.pid
        }
        fn wait(&self, _: Duration) -> Result<Option<ProcessExit>, TraitError> {
            Ok(None)
        }
        fn terminate(&self, _: Duration) -> Result<(), TraitError> {
            Ok(())
        }
        fn take_output(&self) -> Option<ContainerOutput> {
            self.output.lock().expect("lock").take()
        }
        fn take_stdin(&self) -> Option<ContainerStdin> {
            self.stdin.lock().expect("lock").take()
        }
        fn take_pty_master(&self) -> Option<PtyMaster> {
            self.master.lock().expect("lock").take()
        }
    }

    /// 偽の Read（固定の結果を 1 回返す）。
    struct Once(Option<io::Result<usize>>);

    impl Read for Once {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            self.0.take().unwrap_or(Ok(0))
        }
    }

    /// SUP-7・CRI-6・#4074: `EIO` は EOF、`EINTR` は `Interrupted` のまま、`EBADF` はそのまま返る。
    #[test]
    fn sup7_4074_pty_reader_maps_eio_to_eof() {
        let mut eio = PtyOutputReader::new(Once(Some(Err(io::Error::from_raw_os_error(5)))));
        assert_eq!(eio.read(&mut [0u8; 4]).expect("eio is eof"), 0);
        let mut intr = PtyOutputReader::new(Once(Some(Err(io::Error::from_raw_os_error(4)))));
        let e = intr.read(&mut [0u8; 4]).expect_err("eintr kept");
        assert_eq!(e.kind(), io::ErrorKind::Interrupted);
        let mut badf = PtyOutputReader::new(Once(Some(Err(io::Error::from_raw_os_error(9)))));
        let e = badf.read(&mut [0u8; 4]).expect_err("ebadf kept");
        assert_eq!(e.raw_os_error(), Some(9));
        let mut data = PtyOutputReader::new(Once(Some(Ok(3))));
        assert_eq!(data.read(&mut [0u8; 4]).expect("data"), 3);
    }

    /// SUP-7・CRI-6・#4074: 実 pty の master を読むと、master への書き込みのエコーが読め、slave を閉じると EOF になる。
    #[test]
    fn sup7_4074_pty_reader_reads_echo_then_eof_after_slave_close() {
        let (master, slave) = open_host_pty_for_test(WindowSize::new(24, 80)).expect("pty");
        let mut file = std::fs::File::from(master.into_owned_fd());
        // line discipline のエコー（ECHO は既定で有効）で、master への書き込みが master から読める。
        file.write_all(b"hi\n").expect("write");
        let mut reader = PtyOutputReader::new(file);
        let mut buf = [0u8; 16];
        let n = reader.read(&mut buf).expect("echo");
        assert_eq!(buf.get(..n), Some(&b"hi\r\n"[..]));
        drop(slave);
        assert_eq!(reader.read(&mut buf).expect("eof after slave close"), 0);
    }

    fn pipe_stdin() -> (std::io::PipeReader, ContainerStdin) {
        let (r, w) = std::io::pipe().expect("pipe");
        (r, ContainerStdin::from_pipe_writer_for_test(w))
    }

    /// CRI-6・#4074: tty は master を stdout の 1 本として返し（stderr なし・2 回目は None）、複製が同じ master を指して 1 回だけ返る。
    #[test]
    fn cri6_4074_terminal_output_is_master_stdout_only() {
        let (master, slave) = open_host_pty_for_test(WindowSize::new(24, 80)).expect("pty");
        let original = std::fs::File::from(master.as_fd().try_clone_to_owned().expect("dup"))
            .metadata()
            .expect("meta");
        let fake = Fake::new();
        *fake.master.lock().expect("lock") = Some(master);
        // core の pipe は閉じられる（出力が Some でも捕捉へは渡らない）。
        let (pipe_r, pipe_w) = std::io::pipe().expect("pipe");
        *fake.output.lock().expect("lock") = Some(ContainerOutput {
            stdout: Some(Box::new(pipe_r)),
            stderr: None,
        });
        let wrapped = AttachIoProcess::wrap(
            Box::new(fake),
            AttachExpectation {
                terminal: true,
                stdin: false,
            },
        )
        .ok()
        .expect("wrap");
        assert_eq!(wrapped.pid().get(), 4242);
        let out = wrapped.take_output().expect("first take");
        assert!(out.stdout.is_some());
        assert!(out.stderr.is_none());
        assert!(wrapped.take_output().is_none());
        // core の pipe は読み取り側が閉じられた（書き込みが EPIPE）。
        let mut w = pipe_w;
        assert_eq!(
            w.write(b"x").expect_err("reader closed").kind(),
            io::ErrorKind::BrokenPipe
        );
        let dup = wrapped.take_pty_master().expect("dup");
        assert!(wrapped.take_pty_master().is_none());
        let dup_meta = std::fs::File::from(dup.into_owned_fd())
            .metadata()
            .expect("meta");
        assert_eq!(dup_meta.rdev(), original.rdev());
        assert!(wrapped.take_stdin().is_none());
        drop(slave);
    }

    /// CRI-6・#4074: 非 tty は出力と stdin を内側の値のまま返す（stdin は 1 回だけ）。
    #[test]
    fn cri6_4074_non_terminal_forwards_output_and_stdin() {
        let fake = Fake::new();
        let (reader, stdin) = pipe_stdin();
        let raw = stdin.as_fd().as_raw_fd();
        *fake.stdin.lock().expect("lock") = Some(stdin);
        let (out_r, _out_w) = std::io::pipe().expect("pipe");
        *fake.output.lock().expect("lock") = Some(ContainerOutput {
            stdout: Some(Box::new(out_r)),
            stderr: None,
        });
        let wrapped = AttachIoProcess::wrap(
            Box::new(fake),
            AttachExpectation {
                terminal: false,
                stdin: true,
            },
        )
        .ok()
        .expect("wrap");
        assert!(wrapped.take_output().expect("output").stdout.is_some());
        let mut got = wrapped.take_stdin().expect("stdin");
        assert_eq!(got.as_fd().as_raw_fd(), raw);
        assert!(wrapped.take_stdin().is_none());
        assert!(wrapped.take_pty_master().is_none());
        got.write_all(b"in").expect("write");
        drop(got);
        let mut buf = String::new();
        let mut reader = reader;
        reader.read_to_string(&mut buf).expect("read");
        assert_eq!(buf, "in");
    }

    /// D8・#4074: 端末を期待して master が無い、stdin を期待して書き込み端が無い起動は Err で、プロセスを返す。
    #[test]
    fn cri6_4074_fail_closed_when_expected_io_is_missing() {
        let Err((p, e)) = AttachIoProcess::wrap(
            Box::new(Fake::new()),
            AttachExpectation {
                terminal: true,
                stdin: false,
            },
        ) else {
            panic!("must fail");
        };
        assert_eq!(e.code(), ErrorCode::Internal);
        assert_eq!(e.message(), "the pty master was not delivered");
        assert_eq!(p.pid().get(), 4242);
        let Err((p, e)) = AttachIoProcess::wrap(
            Box::new(Fake::new()),
            AttachExpectation {
                terminal: false,
                stdin: true,
            },
        ) else {
            panic!("must fail");
        };
        assert_eq!(e.code(), ErrorCode::Internal);
        assert_eq!(e.message(), "the stdin pipe was not delivered");
        assert_eq!(p.pid().get(), 4242);
        // 何も期待しなければ成功し、何も返さない。
        let ok = AttachIoProcess::wrap(Box::new(Fake::new()), AttachExpectation::default())
            .ok()
            .expect("plain wrap");
        assert!(ok.take_stdin().is_none());
        assert!(ok.take_pty_master().is_none());
        assert!(ok.take_output().is_none());
    }
}
