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

use fandhe_container_core::exec::{ExecCgroupName, PtyMaster};
use fandhe_container_core::traits::ErrorCode;

use super::wire::{
    EncodeError, ExecSignal, Frame, HEADER_LEN, Kind, MAX_FRAME_LEN, SignalAckCode, StdioMask,
    StreamExecOutcome, WireCgroupName, WireError, parse_header,
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
    /// その他の入出力の失敗（OS の errno があれば保持する。診断行の errno 用。#4284）。
    Io {
        /// 失敗の種別。
        kind: io::ErrorKind,
        /// OS の errno（OS 由来でない入出力の失敗は `None`）。
        errno: Option<i32>,
    },
}

impl ChannelError {
    /// 機械可読な分類へ写す。期限は `Timeout`、切断・入出力は `Unavailable`、受信内容の不正は `InvalidArgument`、
    /// 符号化できない値（自プロセスの不整合）は `Internal`。
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::Timeout => ErrorCode::Timeout,
            Self::Closed | Self::Io { .. } => ErrorCode::Unavailable,
            Self::Unencodable(_) => ErrorCode::Internal,
            Self::Malformed(_)
            | Self::FdCountMismatch
            | Self::ControlTruncated
            | Self::FdOnContinuation
            | Self::MaskMismatch
            | Self::NotPtyMaster => ErrorCode::InvalidArgument,
        }
    }

    /// OS の errno（[`Self::Io`] のときだけ。診断行用。#4284）。
    pub fn errno(&self) -> Option<i32> {
        match self {
            Self::Io { errno, .. } => *errno,
            _ => None,
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
    /// exec の開始（helper が作った exec 子 cgroup の名前。検証済み。#4221）。
    Started(ExecCgroupName),
    /// pty master（`PtyMaster::from_received` で検証済み）。
    PtyMaster(PtyMaster),
    /// 終了の結果。
    Result(StreamExecOutcome),
    /// `Signal` の結果（要求の番号と結果。検証済み。#4282）。
    SignalAck {
        /// 要求されたシグナル。
        signal: ExecSignal,
        /// 結果。
        code: SignalAckCode,
    },
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
        kind => ChannelError::Io {
            kind,
            errno: e.raw_os_error(),
        },
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

/// helper → plugin-cri: exec の開始と、作った exec 子 cgroup の名前を知らせる（#4221。名前は plugin-cri が消滅確認に使う）。
pub fn send_started(
    stream: &UnixStream,
    name: &ExecCgroupName,
    deadline: Instant,
) -> Result<(), ChannelError> {
    let wire = WireCgroupName::from_name(name).map_err(ChannelError::Unencodable)?;
    send_frame(stream, &Frame::Started(wire), &[], deadline)
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

/// plugin-cri → helper: exec のコマンドへ SIGKILL 以外のシグナルを送る要求（#4282・SUP-6）。番号は許可リストの [`ExecSignal`]
/// でしか作れない。fd は付けない。
pub fn send_signal(
    stream: &UnixStream,
    signal: ExecSignal,
    deadline: Instant,
) -> Result<(), ChannelError> {
    send_frame(stream, &Frame::Signal(signal), &[], deadline)
}

/// helper → plugin-cri: `Signal` の結果を返す（#4282。要求の番号を折り返す）。
pub fn send_signal_ack(
    stream: &UnixStream,
    signal: ExecSignal,
    code: SignalAckCode,
    deadline: Instant,
) -> Result<(), ChannelError> {
    send_frame(stream, &Frame::SignalAck { signal, code }, &[], deadline)
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

/// `try_recv_signal` が 1 frame の受信に割り当てる上限（`POLLIN` を見てからの受信なので通常は即座に終わる。REPAIR-5）。
pub const SIGNAL_RECV_BUDGET: Duration = Duration::from_millis(200);

/// helper 側: plugin-cri からの `Signal` を、読めるデータがあるときだけ 1 つ受ける（#4282・SUP-6・SEC-1・REPAIR-5）。
///
/// `poll(timeout = 0)` で `POLLIN` が立っていなければ何も読まず `Ok(None)`（待たない。判定の失敗も `Ok(None)`）。立っていれば
/// [`SIGNAL_RECV_BUDGET`] の期限つきで 1 frame を受け、`Signal` 以外（`StdioHandover` を含む）・fd が付いた frame・許可外の番号・
/// 壊れた frame は `Err`（受け取った fd は閉じる）。`Err` の後は channel から二度と受信しないこと（frame の境界を信頼できない。
/// モジュール doc「受信失敗後の扱い」）。切断（`POLLIN` と EOF）は `Closed`。
pub fn try_recv_signal(stream: &UnixStream) -> Result<Option<ExecSignal>, ChannelError> {
    match sys::poll_revents_now(stream.as_fd(), sys::POLL_IN) {
        Ok(revents) if revents & sys::POLL_IN != 0 => {}
        _ => return Ok(None),
    }
    let (frame, fds) = recv_frame(
        stream,
        Kind::is_to_helper,
        Instant::now() + SIGNAL_RECV_BUDGET,
    )?;
    if !fds.is_empty() {
        return Err(ChannelError::FdCountMismatch);
    }
    match frame {
        Frame::Signal(signal) => Ok(Some(signal)),
        _ => Err(ChannelError::Malformed(WireError::UnknownKind)),
    }
}

/// plugin-cri 側: helper からの frame（`Started`・`PtyMaster`・`Result`・`SignalAck`）を 1 つ受ける。`PtyMaster` の fd は
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
        Frame::Started(name) => name
            .to_name()
            .map(HelperMessage::Started)
            .map_err(ChannelError::Malformed),
        Frame::Result(o) => Ok(HelperMessage::Result(o)),
        Frame::PtyMaster => {
            let fd = fds
                .into_iter()
                .next()
                .ok_or(ChannelError::FdCountMismatch)?;
            let master = PtyMaster::from_received(fd).map_err(|_| ChannelError::NotPtyMaster)?;
            Ok(HelperMessage::PtyMaster(master))
        }
        Frame::SignalAck { signal, code } => Ok(HelperMessage::SignalAck { signal, code }),
        Frame::StdioHandover(_) | Frame::Signal(_) => {
            Err(ChannelError::Malformed(WireError::UnknownKind))
        }
    }
}

/// `poll` の `revents`（失敗なら `Err`）から、要求元の消滅を判定する純関数（[`requester_gone`] の本体）。
/// `POLLIN` だけは消滅としない。`poll` の失敗は「消滅と言えない」ので偽（取り消さない側。REPAIR-5）。
fn gone_from(revents: io::Result<i16>) -> bool {
    matches!(revents, Ok(r) if r & sys::POLL_GONE_MASK != 0)
}

/// 要求元（plugin-cri）が channel を閉じた・異常終了した（接続が切れた）かを、読まずに 1 回だけ確かめる
/// （`poll(timeout = 0)` で `POLLHUP`・`POLLERR`・`POLLRDHUP`・`POLLNVAL`。データ・fd は消費しない。#4166・SUP-6・REPAIR-5）。
///
/// helper が exec の間に呼ぶ取り消し判定の実体で、真なら exec のコマンドを止めて回収してから終わる
/// （`docs/design/cri-streaming-server.md`「要求元の異常終了の検知」の方式 A）。判定に失敗した（`EINTR` 等）・非対応の
/// ターゲットは偽（取り消さない）で、従来の期限と `hold_grace` で終わる。
///
/// 要求元側の契約: 続けたい間は channel を閉じず、`shutdown` もせず、自分の端を他プロセスへ渡さない
/// （渡すと要求元が死んでも相手が端を持ち続け、検知できない。その場合は従来の上限で終わる）。
/// 再評価条件: 要求元が channel を意図して半閉じする設計に変わるとき（誤検知になる）。
pub fn requester_gone(channel: &UnixStream) -> bool {
    gone_from(sys::poll_revents_now(
        channel.as_fd(),
        sys::POLL_IN | sys::POLL_RDHUP,
    ))
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
        send_started(&a, &ExecCgroupName::new("exec-4242-0").unwrap(), far()).unwrap();
        match recv_from_helper(&b, far()).unwrap() {
            HelperMessage::Started(n) => assert_eq!(n.as_str(), "exec-4242-0"),
            other => panic!("unexpected {other:?}"),
        }
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

    /// 拒否した fd は受け側で閉じられ、専用の一時ファイルを指す fd の数が増えたままにならない。
    /// 並列に走る他の試験の `/dev/null` の開閉の影響を受けないよう、この試験だけが開く一時ファイルで数える。
    #[test]
    fn sup6_rejected_pty_master_fd_is_closed() {
        let path = std::env::temp_dir().join(format!(
            "fandhe-sup6-rejected-fd-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let file = File::create(&path).unwrap();
        let links = |p: &std::path::Path| -> usize {
            std::fs::read_dir("/proc/self/fd")
                .unwrap()
                .filter_map(Result::ok)
                .filter(|e| std::fs::read_link(e.path()).is_ok_and(|l| l == p))
                .count()
        };
        let (a, b) = pair();
        let before = links(&path);
        assert_eq!(before, 1);
        send_pty_master(&a, file.as_fd(), far()).unwrap();
        let result = recv_from_helper(&b, far());
        let after = links(&path);
        let _ = std::fs::remove_file(&path);
        assert_eq!(result.unwrap_err(), ChannelError::NotPtyMaster);
        assert_eq!(after, before);
    }

    #[test]
    fn sup6_fd_count_and_mask_mismatch_rejected() {
        let (a, b) = pair();
        let null = File::open("/dev/null").unwrap();
        let two = [null.as_fd(), null.as_fd()];
        let one = [null.as_fd()];
        let frame = |kind: u8, plen: u8, payload: &[u8], fds: &[BorrowedFd<'_>]| {
            let mut v = vec![b'F', b'C', b'S', b'X', 3, kind, 0, plen];
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
        let mut started = [0u8; 65];
        started[0] = 11;
        started[1..12].copy_from_slice(b"exec-4242-0");
        frame(2, 65, &started, &one);
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
        let head = [b'F', b'C', b'S', b'X', 3, 1, 0, 1];
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
        let bad = [b'X', b'C', b'S', b'X', 3, 2, 0, 0];
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
        let head = [b'F', b'C', b'S', b'X', 3, 4, 0xFF, 0xFF];
        sys::send_with_fds(a.as_fd(), &head, &[]).unwrap();
        let t = Instant::now();
        let err = recv_from_helper(&b, Instant::now() + Duration::from_secs(5)).unwrap_err();
        assert_eq!(err, ChannelError::Malformed(WireError::PayloadTooLarge));
        assert!(t.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn sup6_unknown_and_reverse_direction_kinds_rejected() {
        let (a, b) = pair();
        let unknown = [b'F', b'C', b'S', b'X', 3, 9, 0, 0];
        sys::send_with_fds(a.as_fd(), &unknown, &[]).unwrap();
        assert_eq!(
            recv_from_helper(&b, far()).unwrap_err(),
            ChannelError::Malformed(WireError::UnknownKind)
        );
        // helper 側で Started を受ける。
        send_started(&a, &ExecCgroupName::new("exec-4242-0").unwrap(), far()).unwrap();
        assert_eq!(
            recv_stdio_handover(&b, StdioMask::new(0).unwrap(), far()).unwrap_err(),
            ChannelError::Malformed(WireError::UnknownKind)
        );
        // plugin-cri 側で StdioHandover を受ける（向きの違う frame は拒否後に channel を再利用しないので、組を取り直す。
        // `Started` の payload が未読のまま残るため、同じ組では続きの frame を読めない）。
        let (a, b) = pair();
        send_stdio_handover(&a, &StdioSend::default(), far()).unwrap();
        assert_eq!(
            recv_from_helper(&b, far()).unwrap_err(),
            ChannelError::Malformed(WireError::UnknownKind)
        );
    }

    /// SUP-6・SEC-1・#4282: `Signal` の往復と、データが無いときの `Ok(None)`（待たない）。`SignalAck` は plugin-cri 側で受ける。
    #[test]
    fn sup6_4282_signal_roundtrip_and_ack() {
        let (plugin, helper) = pair();
        let t = Instant::now();
        assert_eq!(try_recv_signal(&helper), Ok(None));
        assert!(t.elapsed() < Duration::from_millis(500));
        let term = ExecSignal::new(15).unwrap();
        send_signal(&plugin, term, far()).unwrap();
        assert_eq!(try_recv_signal(&helper), Ok(Some(term)));
        assert_eq!(try_recv_signal(&helper), Ok(None));
        send_signal_ack(&helper, term, SignalAckCode::Delivered, far()).unwrap();
        match recv_from_helper(&plugin, far()).unwrap() {
            HelperMessage::SignalAck { signal, code } => {
                assert_eq!(signal, term);
                assert_eq!(code, SignalAckCode::Delivered);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    /// SUP-6・SEC-1・REPAIR-2・#4282: 許可外の番号・旧い版・fd 付き・向きの違う frame は `try_recv_signal` が拒否する。
    #[test]
    fn sup6_4282_try_recv_signal_rejections() {
        let hdr = |ver: u8, kind: u8, plen: u8| vec![b'F', b'C', b'S', b'X', ver, kind, 0, plen];
        let send = |a: &UnixStream, bytes: &[u8], fds: &[BorrowedFd<'_>]| {
            sys::send_with_fds(a.as_fd(), bytes, fds).unwrap();
        };
        // SIGKILL(9) は許可外。
        let (a, b) = pair();
        let mut v = hdr(3, 5, 1);
        v.push(9);
        send(&a, &v, &[]);
        assert_eq!(
            try_recv_signal(&b),
            Err(ChannelError::Malformed(WireError::SignalNotAllowed))
        );
        // 0 と 65 は範囲外。
        for n in [0u8, 65] {
            let (a, b) = pair();
            let mut v = hdr(3, 5, 1);
            v.push(n);
            send(&a, &v, &[]);
            assert_eq!(
                try_recv_signal(&b),
                Err(ChannelError::Malformed(WireError::SignalOutOfRange))
            );
        }
        // 旧い版（v2）。
        let (a, b) = pair();
        let mut v = hdr(2, 5, 1);
        v.push(15);
        send(&a, &v, &[]);
        assert_eq!(
            try_recv_signal(&b),
            Err(ChannelError::Malformed(WireError::BadVersion))
        );
        // fd 付きの Signal は拒否し、受け取った fd は閉じる。
        let (a, b) = pair();
        let null = File::open("/dev/null").unwrap();
        let mut v = hdr(3, 5, 1);
        v.push(15);
        send(&a, &v, &[null.as_fd()]);
        assert_eq!(try_recv_signal(&b), Err(ChannelError::FdCountMismatch));
        // 向きの違う frame（helper → plugin-cri の SignalAck・Started）。
        let (a, b) = pair();
        let mut v = hdr(3, 6, 2);
        v.extend_from_slice(&[15, 1]);
        send(&a, &v, &[]);
        assert_eq!(
            try_recv_signal(&b),
            Err(ChannelError::Malformed(WireError::UnknownKind))
        );
        // StdioHandover は向きは合うが Signal ではない。
        let (a, b) = pair();
        send_stdio_handover(&a, &StdioSend::default(), far()).unwrap();
        assert_eq!(
            try_recv_signal(&b),
            Err(ChannelError::Malformed(WireError::UnknownKind))
        );
        // 切断は Closed。
        let (a, b) = pair();
        drop(a);
        assert_eq!(try_recv_signal(&b), Err(ChannelError::Closed));
        // plugin-cri 側は Signal を受けない。
        let (a, b) = pair();
        send_signal(&a, ExecSignal::new(15).unwrap(), far()).unwrap();
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

    /// SUP-6・REPAIR-4（#4284）: OS の errno は `Io` に保持され、timeout・切断・OS 由来でない失敗は errno を持たない。
    #[test]
    fn sup6_4284_map_io_keeps_the_os_errno() {
        let ebadf = map_io(&io::Error::from_raw_os_error(9));
        assert_eq!(ebadf.errno(), Some(9));
        assert_eq!(ebadf.code(), ErrorCode::Unavailable);
        assert_eq!(map_io(&io::Error::from(io::ErrorKind::Other)).errno(), None);
        assert_eq!(
            map_io(&io::Error::from_raw_os_error(32)),
            ChannelError::Closed
        );
        assert_eq!(ChannelError::Closed.errno(), None);
    }

    #[test]
    fn sup6_error_codes_map_to_machine_readable_classes() {
        assert_eq!(ChannelError::Timeout.code(), ErrorCode::Timeout);
        assert_eq!(ChannelError::Closed.code(), ErrorCode::Unavailable);
        assert_eq!(
            ChannelError::Io {
                kind: io::ErrorKind::Other,
                errno: None
            }
            .code(),
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

    /// SUP-6・REPAIR-5・#4166: 要求元の消滅の判定（開いている・データだけ・半閉じ・閉じた・判定の失敗）。
    #[cfg(any(
        all(target_arch = "x86_64", target_pointer_width = "64"),
        all(target_arch = "aarch64", target_pointer_width = "64")
    ))]
    #[test]
    fn sup6_4166_requester_gone_follows_the_peer_state() {
        let (helper, plugin) = pair();
        assert!(!requester_gone(&helper), "open peer");
        std::io::Write::write_all(&mut &plugin, b"x").unwrap();
        assert!(!requester_gone(&helper), "data only is not gone");
        plugin.shutdown(std::net::Shutdown::Write).unwrap();
        assert!(requester_gone(&helper), "half-closed peer");
        let (helper, plugin) = pair();
        drop(plugin);
        assert!(requester_gone(&helper), "closed peer");
    }

    /// SUP-6・REPAIR-5・#4166: revents の各ビットと判定の失敗の写し。
    #[test]
    fn sup6_4166_gone_from_maps_bits_and_errors() {
        assert!(!gone_from(Ok(0)));
        assert!(!gone_from(Ok(sys::POLL_IN)));
        for bit in [0x8, 0x10, 0x20, 0x2000] {
            assert!(gone_from(Ok(bit)), "{bit:#x}");
        }
        assert!(gone_from(Ok(sys::POLL_IN | 0x10)));
        assert!(!gone_from(Err(io::ErrorKind::Interrupted.into())));
        assert!(!gone_from(Err(io::ErrorKind::Unsupported.into())));
    }
}
