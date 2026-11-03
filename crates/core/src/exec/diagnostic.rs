//! 診断ログ 1 行を「止まった出力先でも待たずに」出す経路（#1697・REPAIR-5・REPAIR-4）。
//!
//! 役割: core が出す診断用の構造化ログ（`create_default_devices` の devpts の `gid=` 省略〔TASK-29 追補・#1656〕、
//! 起動時の `pidfd_open` 失敗の縮退理由〔`LaunchPidfdUnavailable::log_line`。TASK-163 追補・#1617・SUP-6〕）の出力口。
//! 旧来の `writeln!(std::io::stderr(), ..)` は、stderr の先が読み手の止まった満杯の pipe だと無期限に止まる
//! （spawn から `wait_timeout` までの経路で止まるとハンドル返却と期限管理が効かない。PR #1683 の P0）。
//! そのため `crate::sys::send_nonblocking_unix`（`MSG_DONTWAIT | MSG_NOSIGNAL` の `send(2)` 1 回）で、待たないと
//! 保証できる出力先にだけ書き、それ以外は書かずに捨てる（fail-closed）。方式は plugin の `write_nonblocking`
//! （#1605）と揃えた。出力先を広げる課題は #1673（plugin 側の方針）と同じ判断に従う。
//!
//! 呼び出し元: `devices.rs` の `emit_devpts_gid_omitted`（fork した子の `create_default_devices`）、
//! `process.rs` の `ContainerChild::spawned`（fork 直後の親）。supervisor の `log_entrypoint_mode` の載せ替えは
//! `supervisor` の exec の `log_entrypoint_mode` がこの公開関数を使う（#1698）。
//!
//! # 出力先の種別ごとの扱い（fd 2 の実体）
//!
//! | 出力先 | 扱い | 戻り値 |
//! | ------ | ---- | ------ |
//! | AF_UNIX の stream socket（journald の stream 等） | `send` を 1 回。満杯でも待たない | `Sent` / `Partial` / `Dropped(WouldBlock)` |
//! | AF_UNIX の datagram・seqpacket socket | 同上（1 データグラム） | `Sent` / `Dropped(WouldBlock)` |
//! | 相手が閉じた AF_UNIX socket | `SIGPIPE` を出さず失敗 | `Dropped(Os("EPIPE"))` |
//! | pipe・FIFO（`\| tee` を含む） | 書かない | `Dropped(NotUnixSocket)` |
//! | 通常ファイル（`2>file`） | 書かない | `Dropped(NotUnixSocket)` |
//! | 端末・キャラクタデバイス（pty・`/dev/null`） | 書かない | `Dropped(NotUnixSocket)` |
//! | AF_UNIX 以外の socket（TCP・UDP 等） | 書かない | `Dropped(NotUnixSocket)` |
//! | Linux の x86_64・aarch64 以外 | 書かない | `Dropped(NotUnixSocket)` |
//!
//! 後退の明記: 従来は止まり得る代わりに `2>file`・`| tee` の先にも出ていた行が、pipe・ファイル・端末では出なく
//! なる。ブロックしないことを保証できる経路が AF_UNIX の socket に限られるため（通常ファイルの write は応答しない
//! FUSE / NFS・FS freeze で止まり得る。pipe は共有 open file description を変えずに非ブロッキング化できず、
//! 読み手が閉じた直後の write は `SIGPIPE` になる。TCP は socket ロックで待ち得る）。捨てた事実は戻り値で観測でき、
//! 省略した事実そのものは別の経路でも観測できる（devpts は `DevptsOutcome::gid` が `None`、pidfd は
//! `ContainerChild::pidfd_unavailable`）。
//!
//! # 契約
//! - 呼び出し側は固定語彙と数値だけの 1 行を渡す（利用者由来の値・パス・資格情報を含めない。ログ注入を避ける）
//! - 改行（`\n`・`\r`）を含む行と [`MAX_DIAGNOSTIC_LINE`] を超える行は送らない（1 行であることを保つ）
//! - ヒープを確保せず、再試行も待機もしない。送信の失敗でコンテナの起動・exec の可否は変えない（最善努力）
//! - 判定と送信の間に別スレッドが fd 番号を AF_UNIX 以外の socket へ差し替える窓は残る（`sys::send_nonblocking_unix` の doc）

use std::os::fd::{AsFd as _, BorrowedFd};

use crate::sys::{self, SysError};

/// 1 行の最大バイト数（末尾の改行を含む）。スタック上の固定長バッファに組むための上限で、診断ログ（固定語彙のみ）には
/// 十分大きい。超える行は送らず捨てる。
pub const MAX_DIAGNOSTIC_LINE: usize = 1024;

/// 診断 1 行の送信結果。真偽値にせず、将来の状態を足せる形にする（`#[non_exhaustive]`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DiagnosticDelivery {
    /// 改行を含む 1 行をすべて送った。
    Sent,
    /// 一部だけ送れた（stream socket の送信バッファが途中で満杯）。送れたバイト数を返す。残りは送らない。
    Partial {
        /// 送れたバイト数（改行を含めた行全体の長さ未満）。
        written: usize,
    },
    /// 送らずに捨てた。理由は [`DiagnosticDropReason`]。
    Dropped(DiagnosticDropReason),
}

/// 診断 1 行を捨てた理由（固定語彙。カーネル由来の自由文字列を持たない）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DiagnosticDropReason {
    /// 出力先が AF_UNIX の socket ではない、または対応外のアーキテクチャ（待たないことを保証できないため書かない）。
    NotUnixSocket,
    /// 送信バッファが満杯（`EAGAIN`）。待たずに捨てた。
    WouldBlock,
    /// 行が [`MAX_DIAGNOSTIC_LINE`]（改行を含む）を超える。
    LineTooLong,
    /// 行に改行（`\n`・`\r`）を含む。1 行であることを保てないため送らない。
    InvalidLine,
    /// 送信が errno で失敗した。値は固定語彙（`EPIPE`・`ECONNREFUSED`・`other`）。
    Os(&'static str),
}

/// errno を固定語彙名へ写す（一覧外は `"other"`）。
fn errno_name(errno: i32) -> &'static str {
    match errno {
        e if e == sys::EPIPE => "EPIPE",
        e if e == sys::ECONNREFUSED => "ECONNREFUSED",
        _ => "other",
    }
}

/// `out` が AF_UNIX の socket のときに限り、`line` と改行を `send(2)` 1 回で出す。待たず、再試行しない。
///
/// 出力先ごとの扱いは本モジュールの表のとおり。試験では socket pair を `out` に渡して届いたバイト列を照合する。
pub fn emit_diagnostic_line_to(out: BorrowedFd<'_>, line: &str) -> DiagnosticDelivery {
    if line.bytes().any(|b| b == b'\n' || b == b'\r') {
        return DiagnosticDelivery::Dropped(DiagnosticDropReason::InvalidLine);
    }
    let bytes = line.as_bytes();
    // 長さを上限検証してから組む（改行 1 バイトを含めて上限以内）。
    let total = bytes.len().saturating_add(1);
    if total > MAX_DIAGNOSTIC_LINE {
        return DiagnosticDelivery::Dropped(DiagnosticDropReason::LineTooLong);
    }
    let mut buf = [0u8; MAX_DIAGNOSTIC_LINE];
    let Some((nl, head)) = buf.get_mut(..total).and_then(<[u8]>::split_last_mut) else {
        return DiagnosticDelivery::Dropped(DiagnosticDropReason::LineTooLong);
    };
    head.copy_from_slice(bytes);
    *nl = b'\n';
    let Some(msg) = buf.get(..total) else {
        return DiagnosticDelivery::Dropped(DiagnosticDropReason::LineTooLong);
    };
    match sys::send_nonblocking_unix(out, msg) {
        Ok(n) if n >= total => DiagnosticDelivery::Sent,
        Ok(n) => DiagnosticDelivery::Partial { written: n },
        Err(SysError::Os(e)) if e == sys::EAGAIN => {
            DiagnosticDelivery::Dropped(DiagnosticDropReason::WouldBlock)
        }
        Err(SysError::Os(e)) => {
            DiagnosticDelivery::Dropped(DiagnosticDropReason::Os(errno_name(e)))
        }
        Err(SysError::Unsupported | SysError::MultiThreaded) => {
            DiagnosticDelivery::Dropped(DiagnosticDropReason::NotUnixSocket)
        }
    }
}

/// 標準エラー（fd 2）へ診断 1 行を出す。stderr のロックは取らない（別スレッドが stderr への書き込みで止まって
/// いてもロック待ちで巻き込まれない）。出力先ごとの扱いは本モジュールの表のとおり。
///
/// 呼び出し側は固定語彙と数値だけの行を渡す（利用者由来の値・パスを含めない）。
pub fn emit_diagnostic_line(line: &str) -> DiagnosticDelivery {
    emit_diagnostic_line_to(std::io::stderr().as_fd(), line)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read as _;
    use std::os::unix::net::{UnixDatagram, UnixStream};
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    /// devpts の gid 省略ログと同じ固定語彙の 1 行（`devices.rs` の関数の戻り値と一致することも別途照合する）。
    const DEVPTS_LINE: &str =
        r#"{"event":"devpts_gid_omitted","container_gid":5,"reason":"rootless_gid_unmapped"}"#;

    /// 読み手側を非ブロッキングにして、届いているバイト列をすべて読む。
    fn drain(stream: &UnixStream) -> Vec<u8> {
        stream.set_nonblocking(true).unwrap();
        let mut out = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            match (&*stream).read(&mut buf) {
                Ok(0) => break,
                Ok(n) => out.extend_from_slice(&buf[..n]),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => panic!("read: {e}"),
            }
        }
        out
    }

    /// REPAIR-5・REPAIR-4・#1697: devpts の gid 省略ログの語彙は `devices.rs` と一致する。
    #[test]
    fn rep5_1697_devpts_line_matches_devices_vocabulary() {
        assert_eq!(
            super::super::devices::devpts_gid_omitted_log_line(),
            DEVPTS_LINE
        );
    }

    /// REPAIR-4・REPAIR-5・#1697: AF_UNIX の stream socket には固定語彙の 1 行がちょうど 1 回、バイト一致で届く。
    #[test]
    fn rep5_1697_diagnostic_line_reaches_unix_stream_exactly_once() {
        for line in [
            DEVPTS_LINE,
            r#"{"component":"core.exec","operation":"launch_pidfd","outcome":"unavailable","reason":"failed","errno":"EMFILE"}"#,
        ] {
            let (tx, rx) = UnixStream::pair().unwrap();
            assert_eq!(
                emit_diagnostic_line_to(tx.as_fd(), line),
                DiagnosticDelivery::Sent
            );
            assert_eq!(drain(&rx), format!("{line}\n").into_bytes());
            assert_eq!(drain(&rx), Vec::<u8>::new());
        }
    }

    /// REPAIR-4・REPAIR-5・#1697: AF_UNIX の datagram socket には 1 データグラムが届き、2 つ目は無い。
    #[test]
    fn rep5_1697_diagnostic_line_reaches_unix_datagram_exactly_once() {
        let (tx, rx) = UnixDatagram::pair().unwrap();
        assert_eq!(
            emit_diagnostic_line_to(tx.as_fd(), DEVPTS_LINE),
            DiagnosticDelivery::Sent
        );
        rx.set_nonblocking(true).unwrap();
        let mut buf = [0u8; 512];
        let n = rx.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], format!("{DEVPTS_LINE}\n").as_bytes());
        assert_eq!(
            rx.recv(&mut buf).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }

    /// REPAIR-5・#1697: pipe・通常ファイル・pty の master・`/dev/null` へは書かず `NotUnixSocket` で捨てる
    /// （読み手側・ファイルの中身は 0 バイト）。`/dev/ptmx` が開けない環境では失敗させる（skip しない）。
    #[test]
    fn rep5_1697_diagnostic_line_dropped_for_pipe_file_tty() {
        use std::os::unix::fs::OpenOptionsExt as _;
        let dropped = DiagnosticDelivery::Dropped(DiagnosticDropReason::NotUnixSocket);

        let (mut r, w) = std::io::pipe().unwrap();
        assert_eq!(emit_diagnostic_line_to(w.as_fd(), DEVPTS_LINE), dropped);
        drop(w);
        let mut got = Vec::new();
        r.read_to_end(&mut got).unwrap();
        assert_eq!(got, Vec::<u8>::new());

        let scratch = crate::scratch_root::ScratchDir::new(
            "fandhe-diag-1697",
            std::time::Duration::from_secs(10),
        );
        let path = scratch.path().join("stderr.log");
        let file = std::fs::File::create(&path).unwrap();
        assert_eq!(emit_diagnostic_line_to(file.as_fd(), DEVPTS_LINE), dropped);
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 0);
        drop(file);

        // `O_NOCTTY`（Linux の x86_64・aarch64 とも 0o400）で制御端末を取得しない。
        let ptmx = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(0o400)
            .open("/dev/ptmx")
            .expect("/dev/ptmx must be openable");
        assert_eq!(emit_diagnostic_line_to(ptmx.as_fd(), DEVPTS_LINE), dropped);

        let null = std::fs::OpenOptions::new()
            .write(true)
            .open("/dev/null")
            .unwrap();
        assert_eq!(emit_diagnostic_line_to(null.as_fd(), DEVPTS_LINE), dropped);
    }

    /// REPAIR-5・#1697: AF_UNIX 以外の socket（TCP・UDP）へも書かず捨てる。
    #[test]
    fn rep5_1697_diagnostic_line_dropped_for_inet_sockets() {
        let dropped = DiagnosticDelivery::Dropped(DiagnosticDropReason::NotUnixSocket);
        let tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        assert_eq!(emit_diagnostic_line_to(tcp.as_fd(), DEVPTS_LINE), dropped);
        let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        assert_eq!(emit_diagnostic_line_to(udp.as_fd(), DEVPTS_LINE), dropped);
    }

    /// REPAIR-5・#1697: 送信バッファが満杯の AF_UNIX stream socket でも、ブロッキングの fd のまま 1 秒未満で
    /// `Dropped(WouldBlock)` が返る。
    #[test]
    fn rep5_1697_diagnostic_line_full_unix_socket_returns_would_block() {
        use std::io::Write as _;
        let (mut tx, rx) = UnixStream::pair().unwrap();
        tx.set_nonblocking(true).unwrap();
        let chunk = [b'x'; 4096];
        loop {
            match tx.write(&chunk) {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => panic!("fill: {e}"),
            }
        }
        // 共有している open file description をブロッキングに戻してから呼ぶ（`O_NONBLOCK` に頼らないことの照合）。
        tx.set_nonblocking(false).unwrap();
        let start = Instant::now();
        let delivery = emit_diagnostic_line_to(tx.as_fd(), DEVPTS_LINE);
        assert!(
            start.elapsed() < Duration::from_secs(1),
            "{:?}",
            start.elapsed()
        );
        assert_eq!(
            delivery,
            DiagnosticDelivery::Dropped(DiagnosticDropReason::WouldBlock)
        );
        drop(rx);
    }

    /// REPAIR-5・#1697: 改行を含む行・上限超えの行は送らない（1 行であることを保つ）。上限ちょうどは送れる。
    #[test]
    fn rep5_1697_diagnostic_line_rejects_newline_and_oversize() {
        let (tx, rx) = UnixStream::pair().unwrap();
        assert_eq!(
            emit_diagnostic_line_to(tx.as_fd(), "a\nb"),
            DiagnosticDelivery::Dropped(DiagnosticDropReason::InvalidLine)
        );
        assert_eq!(
            emit_diagnostic_line_to(tx.as_fd(), "a\rb"),
            DiagnosticDelivery::Dropped(DiagnosticDropReason::InvalidLine)
        );
        let too_long = "x".repeat(MAX_DIAGNOSTIC_LINE);
        assert_eq!(
            emit_diagnostic_line_to(tx.as_fd(), &too_long),
            DiagnosticDelivery::Dropped(DiagnosticDropReason::LineTooLong)
        );
        assert_eq!(drain(&rx), Vec::<u8>::new());
        let max = "x".repeat(MAX_DIAGNOSTIC_LINE - 1);
        assert_eq!(
            emit_diagnostic_line_to(tx.as_fd(), &max),
            DiagnosticDelivery::Sent
        );
        assert_eq!(drain(&rx).len(), MAX_DIAGNOSTIC_LINE);
    }

    /// 子役を選ぶ環境変数（SIGPIPE の試験。値は任意）。
    const SIGPIPE_CHILD_ENV: &str = "FANDHE_TEST_1697_SIGPIPE_CHILD";

    /// REPAIR-5・#1697: `SIGPIPE` が `SIG_DFL` でも、相手が閉じた AF_UNIX socket への送信はシグナルで落ちず
    /// `Dropped(Os("EPIPE"))` で戻る（`MSG_NOSIGNAL` が外れると子がシグナル 13 で終わり落ちる）。
    /// Rust ランタイムは起動時に `SIGPIPE` を無視するため、テストバイナリを再実行した子役で `SIG_DFL` に戻して送る。
    #[test]
    fn rep5_1697_diagnostic_send_to_closed_peer_has_no_sigpipe() {
        use std::os::unix::process::ExitStatusExt as _;
        if std::env::var_os(SIGPIPE_CHILD_ENV).is_some() {
            let (tx, rx) = UnixStream::pair().unwrap();
            drop(rx);
            crate::sys::reset_sigpipe_default().unwrap();
            let delivery = emit_diagnostic_line_to(tx.as_fd(), DEVPTS_LINE);
            let expected = DiagnosticDelivery::Dropped(DiagnosticDropReason::Os("EPIPE"));
            std::process::exit(if delivery == expected { 0 } else { 2 });
        }
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "exec::diagnostic::tests::rep5_1697_diagnostic_send_to_closed_peer_has_no_sigpipe",
                "--test-threads=1",
            ])
            .env(SIGPIPE_CHILD_ENV, "1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("child did not finish within 10s (REPAIR-5)");
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        assert_eq!((status.code(), status.signal()), (Some(0), None));
    }
}
