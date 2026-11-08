//! stream-exec の channel の期限つき送受信（socketpair 上の frame と `SCM_RIGHTS` の fd。SUP-6・REPAIR-2・REPAIR-5・#3759）。
//!
//! [`super::wire`] の frame を、fd とともに送受信する安全な公開 API。`sys::send_with_fds`・`sys::recv_with_fds` を
//! 呼ぶだけで `unsafe` を持たない。helper（#3760。受信は [`recv_stdio_handover`]、送信は `send_started` ほか）と
//! plugin-cri（#3761。送信は [`send_stdio_handover`]、受信は [`recv_from_helper`]）が呼ぶ。
//!
//! # 信頼境界
//!
//! channel はパスを持たない socketpair で、第三者は接続できない（`docs/design/cri-streaming-server.md` の SEC-1 の節）。
//! `SO_PEERCRED` は socketpair の作成者の資格情報になり相手の確認にならないため照合しない。受信内容は untrusted として、
//! ヘッダ（magic・version・kind・長さ）を payload を読む前に、fd の本数・向き・mask・pty master を受信後に検証する
//! （`PtyMaster` は core の `PtyMaster::from_received`。文字デバイス `5:2` かつ `TIOCGPTN` の成功。#4100・SEC-1）。
//! 拒否の全経路で、受け取った fd は drop で閉じる。
//!
//! # 受信失敗後の扱い（REPAIR-5・SEC-1・#4100）
//!
//! 受信（[`recv_stdio_handover`]・[`recv_from_helper`]）が失敗した channel からは、二度と受信しない。frame の境界も残りの fd も
//! 保証できず、後続の frame・fd を取り違えうるため。呼び出し側は channel を閉じる。socketpair の送信方向は受信の失敗で崩れないので、
//! 失敗を相手へ伝える最後の送信（helper の `Result`）を 1 回だけ行ってから閉じることは許す。受信に成功した後に限り、
//! `try_clone` で別スレッドへ渡してよい。plugin-cri の `launch` は `Err` で戻ると channel を drop し、複製は成功後だけに作る。
//!
//! # 期限（REPAIR-5）
//!
//! 送受信は呼び出し側の絶対期限 [`Instant`] を受け、読み書きのたびに残り時間をソケットのタイムアウトに設定し直す
//! （期限の値は #3760・#3761 が決める。本モジュールに既定値は置かない）。

use std::io;
use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use fandhe_container_core::exec::PtyMaster;
use fandhe_container_core::traits::ErrorCode;

use super::wire::{
    EncodeError, Frame, HEADER_LEN, Kind, MAX_FRAME_LEN, StdioMask, StreamExecOutcome, WireError,
    parse_header,
};
use crate::sys;

/// channel の失敗（固定語彙。入力値・パス・errno の文字列を載せない）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelError {
    /// 期限を超えた。
    Timeout,
    /// 相手が閉じた（frame の途中の EOF を含む）。
    Closed,
    /// frame が壊れている。
    Malformed(WireError),
    /// 添えられた fd の本数が frame の要求と合わない。
    FdCountMismatch,
    /// 制御データが切り詰められた（`MSG_CTRUNC`）。
    ControlTruncated,
    /// 最初の読み取り以外に fd が付いていた。
    FdOnContinuation,
    /// `StdioHandover` の mask が期待と違う。
    MaskMismatch,
    /// `PtyMaster` の fd が pty master でない（`5:2` の文字デバイスでない、または `TIOCGPTN` が失敗。#4100）。
    NotPtyMaster,
    /// 番号表に無い値のため符号化できない。
    Unencodable(EncodeError),
    /// その他の入出力の失敗。
    Io(io::ErrorKind),
}

impl ChannelError {
    /// 機械可読な分類へ写す。期限は `Timeout`、切断・入出力は `Unavailable`、受信内容の不正は `InvalidArgument`、
    /// 符号化できない値（自プロセスの不整合）は `Internal`。
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::Timeout => ErrorCode::Timeout,
            Self::Closed | Self::Io(_) => ErrorCode::Unavailable,
            Self::Unencodable(_) => ErrorCode::Internal,
            Self::Malformed(_)
            | Self::FdCountMismatch
            | Self::ControlTruncated
            | Self::FdOnContinuation
            | Self::MaskMismatch
            | Self::NotPtyMaster => ErrorCode::InvalidArgument,
        }
    }
}

/// 送る stdio の fd（有無から mask を導くため、mask と fd の不一致を作れない）。
#[derive(Debug, Clone, Copy, Default)]
pub struct StdioSend<'a> {
    /// stdin の端。
    pub stdin: Option<BorrowedFd<'a>>,
    /// stdout の端。
    pub stdout: Option<BorrowedFd<'a>>,
    /// stderr の端。
    pub stderr: Option<BorrowedFd<'a>>,
}

/// 受け取った stdio の fd。
#[derive(Debug, Default)]
pub struct StdioFds {
    /// stdin の端。
    pub stdin: Option<OwnedFd>,
    /// stdout の端。
    pub stdout: Option<OwnedFd>,
    /// stderr の端。
    pub stderr: Option<OwnedFd>,
}

/// helper から plugin-cri への受信結果。
#[derive(Debug)]
pub enum HelperMessage {
    /// exec の開始。
    Started,
    /// pty master（`PtyMaster::from_received` で検証済み）。
    PtyMaster(PtyMaster),
    /// 終了の結果。
    Result(StreamExecOutcome),
}

fn remaining(deadline: Instant) -> Result<Duration, ChannelError> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
        .ok_or(ChannelError::Timeout)
}

fn map_io(e: &io::Error) -> ChannelError {
    match e.kind() {
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => ChannelError::Timeout,
        io::ErrorKind::BrokenPipe
        | io::ErrorKind::ConnectionReset
        | io::ErrorKind::UnexpectedEof => ChannelError::Closed,
        k => ChannelError::Io(k),
    }
}

/// `bytes` 全体を送る。fd は最初に送れたバイトにだけ付け、残りは fd なしで送る（`MSG_NOSIGNAL`）。
fn send_all(
    stream: &UnixStream,
    bytes: &[u8],
    fds: &[BorrowedFd<'_>],
    deadline: Instant,
) -> Result<(), ChannelError> {
    let mut sent = 0usize;
    while sent < bytes.len() {
        stream
            .set_write_timeout(Some(remaining(deadline)?))
            .map_err(|e| map_io(&e))?;
        let tail = bytes.get(sent..).unwrap_or(&[]);
        let attach = if sent == 0 { fds } else { &[] };
        match sys::send_with_fds(stream.as_fd(), tail, attach) {
            Ok(0) => return Err(ChannelError::Closed),
            Ok(n) => sent = sent.saturating_add(n),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(map_io(&e)),
        }
    }
    Ok(())
}

fn send_frame(
    stream: &UnixStream,
    frame: &Frame,
    fds: &[BorrowedFd<'_>],
    deadline: Instant,
) -> Result<(), ChannelError> {
    let enc = frame.encode().map_err(ChannelError::Unencodable)?;
    send_all(stream, enc.as_bytes(), fds, deadline)
}

/// plugin-cri → helper: stdio の fd を渡す。mask は `stdio` の有無から導き、fd はビット昇順（stdin → stdout → stderr）。
/// 3 本とも `None` なら mask 0 で fd を付けない。
pub fn send_stdio_handover(
    stream: &UnixStream,
    stdio: &StdioSend<'_>,
    deadline: Instant,
) -> Result<(), ChannelError> {
    let mask = StdioMask::from_presence(
        stdio.stdin.is_some(),
        stdio.stdout.is_some(),
        stdio.stderr.is_some(),
    );
    let fds: Vec<BorrowedFd<'_>> = [stdio.stdin, stdio.stdout, stdio.stderr]
        .into_iter()
        .flatten()
        .collect();
    send_frame(stream, &Frame::StdioHandover(mask), &fds, deadline)
}

/// helper → plugin-cri: exec の開始を知らせる。
pub fn send_started(stream: &UnixStream, deadline: Instant) -> Result<(), ChannelError> {
    send_frame(stream, &Frame::Started, &[], deadline)
}

/// helper → plugin-cri: pty master の fd を渡す。
pub fn send_pty_master(
    stream: &UnixStream,
    master: BorrowedFd<'_>,
    deadline: Instant,
) -> Result<(), ChannelError> {
    send_frame(stream, &Frame::PtyMaster, &[master], deadline)
}

/// helper → plugin-cri: 終了の結果を返す。
pub fn send_result(
    stream: &UnixStream,
    outcome: &StreamExecOutcome,
    deadline: Instant,
) -> Result<(), ChannelError> {
    send_frame(stream, &Frame::Result(*outcome), &[], deadline)
}

/// `buf` を満たすまで受ける。fd は frame 全体の最初の `recvmsg`（`first`）で受けたものだけを `fds` に集め、
/// 後続の読み取りに付いていたら拒否する。通常の `read` は fd を黙って捨てるため使わない。
fn recv_exact(
    stream: &UnixStream,
    buf: &mut [u8],
    first: &mut bool,
    fds: &mut Vec<OwnedFd>,
    deadline: Instant,
) -> Result<(), ChannelError> {
    let mut filled = 0usize;
    while filled < buf.len() {
        stream
            .set_read_timeout(Some(remaining(deadline)?))
            .map_err(|e| map_io(&e))?;
        let tail = buf.get_mut(filled..).ok_or(ChannelError::Closed)?;
        let got = match sys::recv_with_fds(stream.as_fd(), tail) {
            Ok(g) => g,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(map_io(&e)),
        };
        // 以降の拒否でも、`got.fds` は drop で閉じる。
        if got.truncated {
            return Err(ChannelError::ControlTruncated);
        }
        if !got.fds.is_empty() {
            if !*first {
                return Err(ChannelError::FdOnContinuation);
            }
            fds.extend(got.fds);
        }
        *first = false;
        if got.len == 0 {
            return Err(ChannelError::Closed);
        }
        filled = filled.saturating_add(got.len);
    }
    Ok(())
}

/// 1 frame を受ける。向きの逆の kind（`accept` が偽）は payload を読む前に拒否する。
fn recv_frame(
    stream: &UnixStream,
    accept: fn(Kind) -> bool,
    deadline: Instant,
) -> Result<(Frame, Vec<OwnedFd>), ChannelError> {
    let mut fds = Vec::new();
    let mut first = true;
    let mut head = [0u8; HEADER_LEN];
    recv_exact(stream, &mut head, &mut first, &mut fds, deadline)?;
    let header = parse_header(&head).map_err(ChannelError::Malformed)?;
    if !accept(header.kind) {
        return Err(ChannelError::Malformed(WireError::UnknownKind));
    }
    let mut payload_buf = [0u8; MAX_FRAME_LEN - HEADER_LEN];
    let payload = payload_buf
        .get_mut(..header.payload_len)
        .ok_or(ChannelError::Malformed(WireError::PayloadTooLarge))?;
    recv_exact(stream, payload, &mut first, &mut fds, deadline)?;
    let frame = Frame::decode(header.kind, payload).map_err(ChannelError::Malformed)?;
    Ok((frame, fds))
}

/// helper 側: plugin-cri からの `StdioHandover` を受け、期待 mask と fd の本数を照合して返す。
/// 向きの逆の kind・本数の不一致・期待と違う mask は拒否する（受け取った fd は閉じる）。
pub fn recv_stdio_handover(
    stream: &UnixStream,
    expected: StdioMask,
    deadline: Instant,
) -> Result<StdioFds, ChannelError> {
    let (frame, fds) = recv_frame(stream, Kind::is_to_helper, deadline)?;
    let Frame::StdioHandover(mask) = frame else {
        return Err(ChannelError::Malformed(WireError::UnknownKind));
    };
    if fds.len() != mask.count() {
        return Err(ChannelError::FdCountMismatch);
    }
    if mask != expected {
        return Err(ChannelError::MaskMismatch);
    }
    let mut it = fds.into_iter();
    let mut take = |present: bool| if present { it.next() } else { None };
    Ok(StdioFds {
        stdin: take(mask.stdin()),
        stdout: take(mask.stdout()),
        stderr: take(mask.stderr()),
    })
}

/// plugin-cri 側: helper からの frame（`Started`・`PtyMaster`・`Result`）を 1 つ受ける。`PtyMaster` の fd は
/// pty master であることを確かめ、違えば fd を閉じて `NotPtyMaster` で拒否する（#4100）。失敗後は channel を再利用しない。
pub fn recv_from_helper(
    stream: &UnixStream,
    deadline: Instant,
) -> Result<HelperMessage, ChannelError> {
    let (frame, fds) = recv_frame(stream, Kind::is_from_helper, deadline)?;
    let expected_fds = usize::from(matches!(frame, Frame::PtyMaster));
    if fds.len() != expected_fds {
        return Err(ChannelError::FdCountMismatch);
    }
    match frame {
        Frame::Started => Ok(HelperMessage::Started),
        Frame::Result(o) => Ok(HelperMessage::Result(o)),
        Frame::PtyMaster => {
            let fd = fds
                .into_iter()
                .next()
                .ok_or(ChannelError::FdCountMismatch)?;
            let master = PtyMaster::from_received(fd).map_err(|_| ChannelError::NotPtyMaster)?;
            Ok(HelperMessage::PtyMaster(master))
        }
        Frame::StdioHandover(_) => Err(ChannelError::Malformed(WireError::UnknownKind)),
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::Read as _;
    use std::os::fd::AsRawFd as _;
    use std::os::unix::fs::MetadataExt as _;

    use super::*;
    use crate::stream_exec::wire::{ChildStatus, ExitSignal};

    fn far() -> Instant {
        Instant::now() + Duration::from_secs(10)
    }

    fn pair() -> (UnixStream, UnixStream) {
        UnixStream::pair().unwrap()
    }

    fn temp_files(n: usize) -> (std::path::PathBuf, Vec<File>) {
        let dir = std::env::temp_dir().join(format!(
            "fcx-channel-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let files = (0..n)
            .map(|i| File::create(dir.join(format!("f{i}"))).unwrap())
            .collect();
        (dir, files)
    }

    fn same(a: &OwnedFd, b: &File) -> bool {
        let fa = File::from(a.try_clone().unwrap()).metadata().unwrap();
        let fb = b.metadata().unwrap();
        (fa.dev(), fa.ino()) == (fb.dev(), fb.ino())
    }

    #[test]
    fn sup6_fds_keep_identity_across_socketpair() {
        let (a, b) = pair();
        let (dir, files) = temp_files(3);
        let [f0, f1, f2] = <[File; 3]>::try_from(files).unwrap();
        send_stdio_handover(
            &a,
            &StdioSend {
                stdin: Some(f0.as_fd()),
                stdout: Some(f1.as_fd()),
                stderr: Some(f2.as_fd()),
            },
            far(),
        )
        .unwrap();
        let got = recv_stdio_handover(&b, StdioMask::new(0b111).unwrap(), far()).unwrap();
        assert!(same(got.stdin.as_ref().unwrap(), &f0));
        assert!(same(got.stdout.as_ref().unwrap(), &f1));
        assert!(same(got.stderr.as_ref().unwrap(), &f2));

        send_stdio_handover(
            &a,
            &StdioSend {
                stdin: Some(f0.as_fd()),
                stdout: None,
                stderr: Some(f2.as_fd()),
            },
            far(),
        )
        .unwrap();
        let got = recv_stdio_handover(&b, StdioMask::new(0b101).unwrap(), far()).unwrap();
        assert!(same(got.stdin.as_ref().unwrap(), &f0));
        assert!(got.stdout.is_none());
        assert!(same(got.stderr.as_ref().unwrap(), &f2));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn sup6_empty_mask_sends_no_fds() {
        let (a, b) = pair();
        send_stdio_handover(&a, &StdioSend::default(), far()).unwrap();
        let got = recv_stdio_handover(&b, StdioMask::new(0).unwrap(), far()).unwrap();
        assert!(got.stdin.is_none() && got.stdout.is_none() && got.stderr.is_none());
    }

    #[test]
    fn sup6_helper_messages_roundtrip() {
        let (a, b) = pair();
        send_started(&a, far()).unwrap();
        assert!(matches!(
            recv_from_helper(&b, far()).unwrap(),
            HelperMessage::Started
        ));
        let outcome = StreamExecOutcome::NotStarted {
            exit: ChildStatus::Signaled(ExitSignal::new(9).unwrap()),
            step: None,
            code: ErrorCode::Internal,
        };
        send_result(&a, &outcome, far()).unwrap();
        match recv_from_helper(&b, far()).unwrap() {
            HelperMessage::Result(o) => assert_eq!(o, outcome),
            other => panic!("unexpected {other:?}"),
        }
    }

    fn open_ptmx() -> File {
        File::options()
            .read(true)
            .write(true)
            .open("/dev/ptmx")
            .unwrap()
    }

    /// `/dev/null` と通常ファイルは拒否し、本物の pty master は受理する（SUP-6・SEC-1・#4100）。
    #[test]
    fn sup6_pty_master_must_be_a_pty_master() {
        let (a, b) = pair();
        let null = File::open("/dev/null").unwrap();
        send_pty_master(&a, null.as_fd(), far()).unwrap();
        assert_eq!(
            recv_from_helper(&b, far()).unwrap_err(),
            ChannelError::NotPtyMaster
        );
        let (dir, files) = temp_files(1);
        send_pty_master(&a, files[0].as_fd(), far()).unwrap();
        assert_eq!(
            recv_from_helper(&b, far()).unwrap_err(),
            ChannelError::NotPtyMaster
        );
        let _ = std::fs::remove_dir_all(dir);

        let ptmx = open_ptmx();
        send_pty_master(&a, ptmx.as_fd(), far()).unwrap();
        match recv_from_helper(&b, far()).unwrap() {
            HelperMessage::PtyMaster(m) => {
                let got = File::from(m.into_owned_fd()).metadata().unwrap();
                let sent = ptmx.metadata().unwrap();
                assert_eq!((got.dev(), got.ino()), (sent.dev(), sent.ino()));
                assert_eq!(got.rdev(), (5 << 8) | 2);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    /// 拒否した `/dev/null` の fd は受け側で閉じられ、`/proc/self/fd` の `/dev/null` の数が増えたままにならない。
    #[test]
    fn sup6_rejected_pty_master_fd_is_closed() {
        fn null_links() -> usize {
            std::fs::read_dir("/proc/self/fd")
                .unwrap()
                .filter_map(Result::ok)
                .filter(|e| {
                    std::fs::read_link(e.path())
                        .is_ok_and(|p| p == std::path::Path::new("/dev/null"))
                })
                .count()
        }
        let (a, b) = pair();
        let null = File::open("/dev/null").unwrap();
        let before = null_links();
        send_pty_master(&a, null.as_fd(), far()).unwrap();
        assert_eq!(
            recv_from_helper(&b, far()).unwrap_err(),
            ChannelError::NotPtyMaster
        );
        assert_eq!(null_links(), before);
    }

    #[test]
    fn sup6_fd_count_and_mask_mismatch_rejected() {
        let (a, b) = pair();
        let null = File::open("/dev/null").unwrap();
        let two = [null.as_fd(), null.as_fd()];
        let one = [null.as_fd()];
        let frame = |kind: u8, plen: u8, payload: &[u8], fds: &[BorrowedFd<'_>]| {
            let mut v = vec![b'F', b'C', b'S', b'X', 1, kind, 0, plen];
            v.extend_from_slice(payload);
            sys::send_with_fds(a.as_fd(), &v, fds).unwrap();
        };
        // mask 0b011 に fd 1 本。
        frame(1, 1, &[0b011], &one);
        assert_eq!(
            recv_stdio_handover(&b, StdioMask::new(0b011).unwrap(), far()).unwrap_err(),
            ChannelError::FdCountMismatch
        );
        // mask 0 に fd 1 本。
        frame(1, 1, &[0], &one);
        assert_eq!(
            recv_stdio_handover(&b, StdioMask::new(0).unwrap(), far()).unwrap_err(),
            ChannelError::FdCountMismatch
        );
        // Started に fd 1 本。
        frame(2, 0, &[], &one);
        assert_eq!(
            recv_from_helper(&b, far()).unwrap_err(),
            ChannelError::FdCountMismatch
        );
        // PtyMaster に fd 2 本。
        frame(3, 0, &[], &two);
        assert_eq!(
            recv_from_helper(&b, far()).unwrap_err(),
            ChannelError::FdCountMismatch
        );
        // 期待と違う mask（本数は一致）。
        frame(1, 1, &[0b001], &one);
        assert_eq!(
            recv_stdio_handover(&b, StdioMask::new(0b010).unwrap(), far()).unwrap_err(),
            ChannelError::MaskMismatch
        );
    }

    #[test]
    fn sup6_fd_on_continuation_rejected() {
        let (a, b) = pair();
        let null = File::open("/dev/null").unwrap();
        let head = [b'F', b'C', b'S', b'X', 1, 1, 0, 1];
        sys::send_with_fds(a.as_fd(), &head, &[]).unwrap();
        sys::send_with_fds(a.as_fd(), &[0b001], &[null.as_fd()]).unwrap();
        assert_eq!(
            recv_stdio_handover(&b, StdioMask::new(0b001).unwrap(), far()).unwrap_err(),
            ChannelError::FdOnContinuation
        );
    }

    #[test]
    fn sup6_rejected_fd_is_closed() {
        let (a, b) = pair();
        let (mut r, w) = std::io::pipe().unwrap();
        // 不正な magic の frame に pipe の書き込み端を添える。
        let bad = [b'X', b'C', b'S', b'X', 1, 2, 0, 0];
        sys::send_with_fds(a.as_fd(), &bad, &[w.as_fd()]).unwrap();
        assert_eq!(
            recv_from_helper(&b, far()).unwrap_err(),
            ChannelError::Malformed(WireError::BadMagic)
        );
        drop(w);
        // 受け側が閉じていれば、全ての書き込み端が無くなり読み端は EOF になる。
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut buf = [0u8; 1];
            let _ = tx.send(r.read(&mut buf));
        });
        assert_eq!(rx.recv_timeout(Duration::from_secs(5)).unwrap().unwrap(), 0);
    }

    #[test]
    fn sup6_oversized_header_rejected_without_payload() {
        let (a, b) = pair();
        let head = [b'F', b'C', b'S', b'X', 1, 4, 0xFF, 0xFF];
        sys::send_with_fds(a.as_fd(), &head, &[]).unwrap();
        let t = Instant::now();
        let err = recv_from_helper(&b, Instant::now() + Duration::from_secs(5)).unwrap_err();
        assert_eq!(err, ChannelError::Malformed(WireError::PayloadTooLarge));
        assert!(t.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn sup6_unknown_and_reverse_direction_kinds_rejected() {
        let (a, b) = pair();
        let unknown = [b'F', b'C', b'S', b'X', 1, 9, 0, 0];
        sys::send_with_fds(a.as_fd(), &unknown, &[]).unwrap();
        assert_eq!(
            recv_from_helper(&b, far()).unwrap_err(),
            ChannelError::Malformed(WireError::UnknownKind)
        );
        // helper 側で Started を受ける。
        send_started(&a, far()).unwrap();
        assert_eq!(
            recv_stdio_handover(&b, StdioMask::new(0).unwrap(), far()).unwrap_err(),
            ChannelError::Malformed(WireError::UnknownKind)
        );
        // plugin-cri 側で StdioHandover を受ける。
        send_stdio_handover(&a, &StdioSend::default(), far()).unwrap();
        assert_eq!(
            recv_from_helper(&b, far()).unwrap_err(),
            ChannelError::Malformed(WireError::UnknownKind)
        );
    }

    #[test]
    fn sup6_recv_times_out_and_detects_close() {
        let (a, b) = pair();
        let t = Instant::now();
        let err = recv_from_helper(&b, Instant::now() + Duration::from_millis(50)).unwrap_err();
        assert_eq!(err, ChannelError::Timeout);
        assert!(t.elapsed() < Duration::from_secs(2));
        // frame の途中で閉じる。
        sys::send_with_fds(a.as_fd(), b"FC", &[]).unwrap();
        drop(a);
        assert_eq!(
            recv_from_helper(&b, far()).unwrap_err(),
            ChannelError::Closed
        );
    }

    #[test]
    fn sup6_send_times_out_when_peer_never_reads() {
        let (a, _b) = pair();
        let chunk = [0u8; 4096];
        let deadline = Instant::now() + Duration::from_millis(200);
        let t = Instant::now();
        let err = loop {
            match send_all(&a, &chunk, &[], deadline) {
                Ok(()) => {}
                Err(e) => break e,
            }
            assert!(t.elapsed() < Duration::from_secs(5), "send never blocked");
        };
        assert_eq!(err, ChannelError::Timeout);
    }

    #[test]
    fn sup6_error_codes_map_to_machine_readable_classes() {
        assert_eq!(ChannelError::Timeout.code(), ErrorCode::Timeout);
        assert_eq!(ChannelError::Closed.code(), ErrorCode::Unavailable);
        assert_eq!(
            ChannelError::Io(io::ErrorKind::Other).code(),
            ErrorCode::Unavailable
        );
        assert_eq!(
            ChannelError::MaskMismatch.code(),
            ErrorCode::InvalidArgument
        );
        assert_eq!(
            ChannelError::NotPtyMaster.code(),
            ErrorCode::InvalidArgument
        );
        assert_eq!(
            ChannelError::Unencodable(EncodeError::UnmappedCode).code(),
            ErrorCode::Internal
        );
        let _ = File::open("/dev/null").unwrap().as_raw_fd();
    }
}
