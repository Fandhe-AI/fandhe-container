//! stream-exec の channel の frame codec（固定長・big-endian。SUP-6・REPAIR-2・CRI-6・#3759）。
//!
//! 生の `Vec<u8>` を手で組まず、壊れた値を表現できない型（[`StdioMask`]・[`ExitSignal`]・[`StreamExecOutcome`]）から
//! 固定長配列を作り、復号は `get`・配列パターンだけで読む（添字アクセス・`unwrap` なし）。
//! 呼び出し元は [`super::channel`]（socketpair 上の期限つき送受信）で、その先の helper（#3760）と plugin-cri
//! （#3761）が本モジュールの語彙を使う。**本モジュールの doc を語彙の正**とする。
//!
//! # ヘッダ（8 バイト）
//!
//! | オフセット | 長さ | 内容 |
//! | --- | --- | --- |
//! | 0 | 4 | magic `FCSX`（制御チャネルの `FCSC` と別。取り違えを検出する） |
//! | 4 | 1 | version `u8` = 1 |
//! | 5 | 1 | kind `u8` |
//! | 6 | 2 | payload_len `u16`（big-endian） |
//!
//! [`MAX_PAYLOAD`] を超える payload_len は payload を読まずにヘッダだけで拒否する。各 kind の payload 長は固定で、
//! 一致しなければ同様に payload を読まずに拒否する。
//!
//! # frame
//!
//! | kind | frame | 向き | payload | 全長 | 添える fd |
//! | --- | --- | --- | --- | --- | --- |
//! | 1 | `StdioHandover` | plugin-cri → helper | mask `u8` | 9 | mask の popcount 本ちょうど（0〜3） |
//! | 2 | `Started` | helper → plugin-cri | なし | 8 | 0 |
//! | 3 | `PtyMaster` | helper → plugin-cri | なし | 8 | 1（文字デバイス） |
//! | 4 | `Result` | helper → plugin-cri | 5 バイト | 13 | 0 |
//!
//! mask: bit0 = stdin、bit1 = stdout、bit2 = stderr。bit3〜7 は 0 でなければ拒否。fd の並びはビット昇順。
//!
//! # `Result` の payload（5 バイト）
//!
//! `[outcome, status_kind, status_value, step, code]`
//!
//! | outcome | 意味 | status_kind / value | step | code |
//! | --- | --- | --- | --- | --- |
//! | 1 | exited | 1 / exit code | 0 | 0 |
//! | 2 | signaled | 2 / signal（1〜64） | 0 | 0 |
//! | 3 | not_started | 1 または 2（子の終了状態。写像に使う） | 0〜15 | 1〜10 |
//! | 4 | failed | 0 / 0 | 0 | 1〜10 |
//!
//! step: 0 = なし、1〜15 = `ExecChildStep` を宣言順に 1 から。code: 1〜10 = `ErrorCode` を宣言順に 1 から。
//! 番号は `ALL` の添字からではなく明示の `match` で固定し、core の並び替えで動かさない。未知の番号は frame 全体を拒否する。

use fandhe_container_core::exec::ExecChildStep;
use fandhe_container_core::traits::ErrorCode;

/// 先頭の識別子（制御チャネルの `FCSC` と別）。
pub const MAGIC: [u8; 4] = *b"FCSX";
/// 語彙の版。
pub const VERSION: u8 = 1;
/// ヘッダの長さ。
pub const HEADER_LEN: usize = 8;
/// payload の上限（`Result` の 5 バイトに余裕を足した値）。これを超えるヘッダは payload を読まずに拒否する。
pub const MAX_PAYLOAD: u16 = 8;
/// frame 全体の上限（受信バッファを固定長配列にするため）。
pub const MAX_FRAME_LEN: usize = HEADER_LEN + MAX_PAYLOAD as usize;
/// `Result` の payload 長。
pub const RESULT_PAYLOAD_LEN: usize = 5;

/// 復号の失敗（固定語彙。入力値を載せない）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireError {
    /// magic が `FCSX` でない。
    BadMagic,
    /// version が未対応。
    BadVersion,
    /// kind が未知。
    UnknownKind,
    /// payload_len が [`MAX_PAYLOAD`] を超える。
    PayloadTooLarge,
    /// payload_len が kind の固定長と一致しない（または payload の長さが足りない）。
    LengthMismatch,
    /// mask の予約ビット（bit3〜7）が立っている。
    ReservedMaskBits,
    /// `Result` の outcome が未知。
    UnknownOutcome,
    /// `Result` の status・step・code の組が outcome の制約を満たさない。
    InvalidResult,
    /// step の番号が未知。
    UnknownStep,
    /// code の番号が未知。
    UnknownCode,
}

/// 符号化の失敗（core に値が増えて番号表に無いとき。既知の値へ黙って置き換えない）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncodeError {
    /// `ErrorCode` の番号が未割り当て。
    UnmappedCode,
    /// `ExecChildStep` の番号が未割り当て。
    UnmappedStep,
}

/// frame の種別。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// plugin-cri → helper。stdio の fd の受け渡し。
    StdioHandover,
    /// helper → plugin-cri。exec の開始。
    Started,
    /// helper → plugin-cri。pty master の fd。
    PtyMaster,
    /// helper → plugin-cri。終了の結果。
    Result,
}

impl Kind {
    fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::StdioHandover),
            2 => Some(Self::Started),
            3 => Some(Self::PtyMaster),
            4 => Some(Self::Result),
            _ => None,
        }
    }

    fn as_u8(self) -> u8 {
        match self {
            Self::StdioHandover => 1,
            Self::Started => 2,
            Self::PtyMaster => 3,
            Self::Result => 4,
        }
    }

    /// この kind の payload 長（固定）。
    pub fn payload_len(self) -> u16 {
        match self {
            Self::StdioHandover => 1,
            Self::Started | Self::PtyMaster => 0,
            Self::Result => 5,
        }
    }

    /// helper が受けてよい kind（plugin-cri → helper の向き）。
    pub fn is_to_helper(self) -> bool {
        matches!(self, Self::StdioHandover)
    }

    /// plugin-cri が受けてよい kind（helper → plugin-cri の向き）。
    pub fn is_from_helper(self) -> bool {
        !self.is_to_helper()
    }
}

/// 復号済みのヘッダ。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// frame の種別。
    pub kind: Kind,
    /// payload の長さ（kind の固定長と一致済み）。
    pub payload_len: usize,
}

/// ヘッダ 8 バイトを検査して復号する。payload を読む前に呼び、magic・version・kind・長さを確かめる。
pub fn parse_header(bytes: &[u8; HEADER_LEN]) -> Result<Header, WireError> {
    let [m0, m1, m2, m3, version, kind, l0, l1] = *bytes;
    if [m0, m1, m2, m3] != MAGIC {
        return Err(WireError::BadMagic);
    }
    if version != VERSION {
        return Err(WireError::BadVersion);
    }
    let kind = Kind::from_u8(kind).ok_or(WireError::UnknownKind)?;
    let len = u16::from_be_bytes([l0, l1]);
    if len > MAX_PAYLOAD {
        return Err(WireError::PayloadTooLarge);
    }
    if len != kind.payload_len() {
        return Err(WireError::LengthMismatch);
    }
    Ok(Header {
        kind,
        payload_len: usize::from(len),
    })
}

/// stdio の mask（bit0 = stdin、bit1 = stdout、bit2 = stderr。予約ビットは作れない）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StdioMask(u8);

impl StdioMask {
    /// 予約ビット（bit3〜7）が立っていれば `None`。
    pub fn new(bits: u8) -> Option<Self> {
        (bits & !0b111 == 0).then_some(Self(bits))
    }

    /// 各 stdio の有無から作る。
    pub fn from_presence(stdin: bool, stdout: bool, stderr: bool) -> Self {
        Self(u8::from(stdin) | (u8::from(stdout) << 1) | (u8::from(stderr) << 2))
    }

    /// ビット値。
    pub fn bits(self) -> u8 {
        self.0
    }

    /// stdin を含むか。
    pub fn stdin(self) -> bool {
        self.0 & 0b001 != 0
    }

    /// stdout を含むか。
    pub fn stdout(self) -> bool {
        self.0 & 0b010 != 0
    }

    /// stderr を含むか。
    pub fn stderr(self) -> bool {
        self.0 & 0b100 != 0
    }

    /// 添える fd の本数（popcount。0〜3）。
    pub fn count(self) -> usize {
        usize::try_from(self.0.count_ones()).unwrap_or(usize::MAX)
    }
}

/// シグナル番号（1〜64）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExitSignal(u8);

impl ExitSignal {
    /// 1〜64 以外は `None`。
    pub fn new(n: u8) -> Option<Self> {
        (1..=64).contains(&n).then_some(Self(n))
    }

    /// シグナル番号。
    pub fn get(self) -> u8 {
        self.0
    }
}

/// 子プロセスの終了状態。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChildStatus {
    /// 終了コードで終了。
    Exited(u8),
    /// シグナルで終了。
    Signaled(ExitSignal),
}

/// helper が plugin-cri へ返す終了の結果（`Result` frame）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamExecOutcome {
    /// コマンドが終了コードで終了した。
    Exited(u8),
    /// コマンドがシグナルで終了した。
    Signaled(ExitSignal),
    /// 子の準備に失敗してコマンドを実行できなかった。`exit` は子の終了状態（通常 125 / 126 / 127）。
    NotStarted {
        /// 子の終了状態。
        exit: ChildStatus,
        /// 失敗した段（不明なら `None`）。
        step: Option<ExecChildStep>,
        /// 失敗の分類。
        code: ErrorCode,
    },
    /// helper 自身の失敗（子を起動できなかった等）。
    Failed(ErrorCode),
}

/// 復号済みの frame（fd は含まない。fd は [`super::channel`] が別に運ぶ）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Frame {
    /// stdio の受け渡し（mask の fd を伴う）。
    StdioHandover(StdioMask),
    /// exec の開始。
    Started,
    /// pty master（fd 1 本を伴う）。
    PtyMaster,
    /// 終了の結果。
    Result(StreamExecOutcome),
}

/// 符号化済みの frame（固定長の入れ物）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncodedFrame {
    buf: [u8; MAX_FRAME_LEN],
    len: usize,
}

impl EncodedFrame {
    /// 送るバイト列。
    pub fn as_bytes(&self) -> &[u8] {
        self.buf.get(..self.len).unwrap_or(&[])
    }
}

fn build(kind: Kind, payload: &[u8]) -> EncodedFrame {
    let mut buf = [0u8; MAX_FRAME_LEN];
    let plen_usize = payload.len().min(usize::from(MAX_PAYLOAD));
    let plen = u16::try_from(plen_usize).unwrap_or(0).to_be_bytes();
    let head = [
        MAGIC[0],
        MAGIC[1],
        MAGIC[2],
        MAGIC[3],
        VERSION,
        kind.as_u8(),
        plen[0],
        plen[1],
    ];
    for (dst, src) in buf
        .iter_mut()
        .zip(head.iter().chain(payload.iter().take(plen_usize)))
    {
        *dst = *src;
    }
    EncodedFrame {
        buf,
        len: HEADER_LEN + plen_usize,
    }
}

impl Frame {
    /// frame の種別。
    pub fn kind(&self) -> Kind {
        match self {
            Self::StdioHandover(_) => Kind::StdioHandover,
            Self::Started => Kind::Started,
            Self::PtyMaster => Kind::PtyMaster,
            Self::Result(_) => Kind::Result,
        }
    }

    /// 固定長配列へ符号化する。番号表に無い `ErrorCode`・`ExecChildStep` は `Err`（黙って置き換えない）。
    pub fn encode(&self) -> Result<EncodedFrame, EncodeError> {
        Ok(match self {
            Self::StdioHandover(mask) => build(Kind::StdioHandover, &[mask.bits()]),
            Self::Started => build(Kind::Started, &[]),
            Self::PtyMaster => build(Kind::PtyMaster, &[]),
            Self::Result(outcome) => build(Kind::Result, &encode_outcome(outcome)?),
        })
    }

    /// 検証済みヘッダの kind に対する payload を復号する。長さが kind の固定長と違えば `LengthMismatch`。
    pub fn decode(kind: Kind, payload: &[u8]) -> Result<Self, WireError> {
        if payload.len() != usize::from(kind.payload_len()) {
            return Err(WireError::LengthMismatch);
        }
        match kind {
            Kind::StdioHandover => {
                let [bits] =
                    *<&[u8; 1]>::try_from(payload).map_err(|_| WireError::LengthMismatch)?;
                StdioMask::new(bits)
                    .map(Self::StdioHandover)
                    .ok_or(WireError::ReservedMaskBits)
            }
            Kind::Started => Ok(Self::Started),
            Kind::PtyMaster => Ok(Self::PtyMaster),
            Kind::Result => {
                let arr = <&[u8; RESULT_PAYLOAD_LEN]>::try_from(payload)
                    .map_err(|_| WireError::LengthMismatch)?;
                decode_outcome(arr).map(Self::Result)
            }
        }
    }
}

/// `ErrorCode` の番号（1〜10）。未割り当てなら `None`。
pub fn error_code_to_u8(code: ErrorCode) -> Option<u8> {
    match code {
        ErrorCode::InvalidArgument => Some(1),
        ErrorCode::NotFound => Some(2),
        ErrorCode::AlreadyExists => Some(3),
        ErrorCode::FailedPrecondition => Some(4),
        ErrorCode::Unimplemented => Some(5),
        ErrorCode::Internal => Some(6),
        ErrorCode::PermissionDenied => Some(7),
        ErrorCode::Timeout => Some(8),
        ErrorCode::Unavailable => Some(9),
        ErrorCode::ResourceExhausted => Some(10),
        _ => None,
    }
}

/// 番号から `ErrorCode` を引く（未知は `None`）。
pub fn error_code_from_u8(v: u8) -> Option<ErrorCode> {
    match v {
        1 => Some(ErrorCode::InvalidArgument),
        2 => Some(ErrorCode::NotFound),
        3 => Some(ErrorCode::AlreadyExists),
        4 => Some(ErrorCode::FailedPrecondition),
        5 => Some(ErrorCode::Unimplemented),
        6 => Some(ErrorCode::Internal),
        7 => Some(ErrorCode::PermissionDenied),
        8 => Some(ErrorCode::Timeout),
        9 => Some(ErrorCode::Unavailable),
        10 => Some(ErrorCode::ResourceExhausted),
        _ => None,
    }
}

/// `ExecChildStep` の番号（1〜15）。未割り当てなら `None`。
pub fn step_to_u8(step: ExecChildStep) -> Option<u8> {
    match step {
        ExecChildStep::ParentLifetime => Some(1),
        ExecChildStep::CgroupJoin => Some(2),
        ExecChildStep::CloseFds => Some(3),
        ExecChildStep::Setsid => Some(4),
        ExecChildStep::OpenRoot => Some(5),
        ExecChildStep::OpenEntrypoint => Some(6),
        ExecChildStep::RuntimeIdentity => Some(7),
        ExecChildStep::SelectExecutable => Some(8),
        ExecChildStep::DeferredRlimit => Some(9),
        ExecChildStep::Interpreter => Some(10),
        ExecChildStep::ScriptFd => Some(11),
        ExecChildStep::PrepareFds => Some(12),
        ExecChildStep::StdioNull => Some(13),
        ExecChildStep::ReportReady => Some(14),
        ExecChildStep::Execveat => Some(15),
        _ => None,
    }
}

/// 番号から `ExecChildStep` を引く（未知は `None`）。
pub fn step_from_u8(v: u8) -> Option<ExecChildStep> {
    match v {
        1 => Some(ExecChildStep::ParentLifetime),
        2 => Some(ExecChildStep::CgroupJoin),
        3 => Some(ExecChildStep::CloseFds),
        4 => Some(ExecChildStep::Setsid),
        5 => Some(ExecChildStep::OpenRoot),
        6 => Some(ExecChildStep::OpenEntrypoint),
        7 => Some(ExecChildStep::RuntimeIdentity),
        8 => Some(ExecChildStep::SelectExecutable),
        9 => Some(ExecChildStep::DeferredRlimit),
        10 => Some(ExecChildStep::Interpreter),
        11 => Some(ExecChildStep::ScriptFd),
        12 => Some(ExecChildStep::PrepareFds),
        13 => Some(ExecChildStep::StdioNull),
        14 => Some(ExecChildStep::ReportReady),
        15 => Some(ExecChildStep::Execveat),
        _ => None,
    }
}

fn status_bytes(status: ChildStatus) -> [u8; 2] {
    match status {
        ChildStatus::Exited(c) => [1, c],
        ChildStatus::Signaled(s) => [2, s.get()],
    }
}

fn encode_outcome(o: &StreamExecOutcome) -> Result<[u8; RESULT_PAYLOAD_LEN], EncodeError> {
    Ok(match *o {
        StreamExecOutcome::Exited(c) => [1, 1, c, 0, 0],
        StreamExecOutcome::Signaled(s) => [2, 2, s.get(), 0, 0],
        StreamExecOutcome::NotStarted { exit, step, code } => {
            let [k, v] = status_bytes(exit);
            let step = match step {
                Some(s) => step_to_u8(s).ok_or(EncodeError::UnmappedStep)?,
                None => 0,
            };
            let code = error_code_to_u8(code).ok_or(EncodeError::UnmappedCode)?;
            [3, k, v, step, code]
        }
        StreamExecOutcome::Failed(code) => [
            4,
            0,
            0,
            0,
            error_code_to_u8(code).ok_or(EncodeError::UnmappedCode)?,
        ],
    })
}

fn decode_outcome(p: &[u8; RESULT_PAYLOAD_LEN]) -> Result<StreamExecOutcome, WireError> {
    let [outcome, kind, value, step, code] = *p;
    let status = match kind {
        1 => Some(ChildStatus::Exited(value)),
        2 => ExitSignal::new(value).map(ChildStatus::Signaled),
        _ => None,
    };
    match outcome {
        1 => match (status, step, code) {
            (Some(ChildStatus::Exited(c)), 0, 0) => Ok(StreamExecOutcome::Exited(c)),
            _ => Err(WireError::InvalidResult),
        },
        2 => match (status, step, code) {
            (Some(ChildStatus::Signaled(s)), 0, 0) => Ok(StreamExecOutcome::Signaled(s)),
            _ => Err(WireError::InvalidResult),
        },
        3 => {
            let exit = status.ok_or(WireError::InvalidResult)?;
            let step = match step {
                0 => None,
                n => Some(step_from_u8(n).ok_or(WireError::UnknownStep)?),
            };
            if code == 0 {
                return Err(WireError::InvalidResult);
            }
            let code = error_code_from_u8(code).ok_or(WireError::UnknownCode)?;
            Ok(StreamExecOutcome::NotStarted { exit, step, code })
        }
        4 => {
            if kind != 0 || value != 0 || step != 0 || code == 0 {
                return Err(WireError::InvalidResult);
            }
            let code = error_code_from_u8(code).ok_or(WireError::UnknownCode)?;
            Ok(StreamExecOutcome::Failed(code))
        }
        _ => Err(WireError::UnknownOutcome),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hdr(kind: u8, len: u16) -> [u8; 8] {
        let l = len.to_be_bytes();
        [b'F', b'C', b'S', b'X', 1, kind, l[0], l[1]]
    }

    fn roundtrip(frame: Frame) -> Vec<u8> {
        let enc = frame.encode().unwrap();
        let bytes = enc.as_bytes().to_vec();
        let (head, payload) = bytes.split_first_chunk::<HEADER_LEN>().unwrap();
        let h = parse_header(head).unwrap();
        assert_eq!(h.kind, frame.kind());
        assert_eq!(h.payload_len, payload.len());
        assert_eq!(Frame::decode(h.kind, payload).unwrap(), frame);
        bytes
    }

    #[test]
    fn sup6_stdio_handover_roundtrip_all_masks() {
        for bits in 0..=7u8 {
            let m = StdioMask::new(bits).unwrap();
            let bytes = roundtrip(Frame::StdioHandover(m));
            assert_eq!(bytes.len(), 9);
            assert_eq!(bytes.last(), Some(&bits));
        }
        assert_eq!(
            roundtrip(Frame::StdioHandover(StdioMask::new(0b101).unwrap())),
            vec![0x46, 0x43, 0x53, 0x58, 1, 1, 0, 1, 0x05]
        );
    }

    #[test]
    fn sup6_simple_frames_concrete_bytes() {
        assert_eq!(
            roundtrip(Frame::Started),
            vec![0x46, 0x43, 0x53, 0x58, 1, 2, 0, 0]
        );
        assert_eq!(
            roundtrip(Frame::PtyMaster),
            vec![0x46, 0x43, 0x53, 0x58, 1, 3, 0, 0]
        );
    }

    #[test]
    fn sup6_result_roundtrip_and_concrete_payload() {
        let sig = ExitSignal::new(9).unwrap();
        let cases = [
            StreamExecOutcome::Exited(0),
            StreamExecOutcome::Exited(255),
            StreamExecOutcome::Signaled(sig),
            StreamExecOutcome::NotStarted {
                exit: ChildStatus::Exited(127),
                step: Some(ExecChildStep::Execveat),
                code: ErrorCode::NotFound,
            },
            StreamExecOutcome::NotStarted {
                exit: ChildStatus::Signaled(sig),
                step: None,
                code: ErrorCode::Internal,
            },
            StreamExecOutcome::Failed(ErrorCode::Timeout),
        ];
        for c in cases {
            roundtrip(Frame::Result(c));
        }
        let bytes = roundtrip(Frame::Result(StreamExecOutcome::NotStarted {
            exit: ChildStatus::Exited(127),
            step: Some(ExecChildStep::Execveat),
            code: ErrorCode::NotFound,
        }));
        assert_eq!(bytes.get(8..), Some(&[3u8, 1, 127, 15, 2][..]));
        assert_eq!(bytes.len(), 13);
    }

    #[test]
    fn sup6_header_rejections() {
        let mut bad = hdr(2, 0);
        bad[0] = b'X';
        assert_eq!(parse_header(&bad), Err(WireError::BadMagic));
        let mut v2 = hdr(2, 0);
        v2[4] = 2;
        assert_eq!(parse_header(&v2), Err(WireError::BadVersion));
        for k in [0u8, 5, 255] {
            assert_eq!(parse_header(&hdr(k, 0)), Err(WireError::UnknownKind));
        }
        assert_eq!(
            parse_header(&hdr(2, 0xFFFF)),
            Err(WireError::PayloadTooLarge)
        );
        assert_eq!(parse_header(&hdr(2, 1)), Err(WireError::LengthMismatch));
        assert_eq!(parse_header(&hdr(1, 0)), Err(WireError::LengthMismatch));
        assert_eq!(parse_header(&hdr(4, 4)), Err(WireError::LengthMismatch));
    }

    #[test]
    fn sup6_payload_rejections() {
        assert_eq!(
            Frame::decode(Kind::StdioHandover, &[0b1000]),
            Err(WireError::ReservedMaskBits)
        );
        assert_eq!(
            Frame::decode(Kind::Started, &[1]),
            Err(WireError::LengthMismatch)
        );
        let r = |p: [u8; 5]| Frame::decode(Kind::Result, &p);
        assert_eq!(r([0, 1, 0, 0, 0]), Err(WireError::UnknownOutcome));
        assert_eq!(r([5, 1, 0, 0, 0]), Err(WireError::UnknownOutcome));
        assert_eq!(r([1, 1, 0, 1, 0]), Err(WireError::InvalidResult));
        assert_eq!(r([1, 1, 0, 0, 1]), Err(WireError::InvalidResult));
        assert_eq!(r([1, 2, 9, 0, 0]), Err(WireError::InvalidResult));
        assert_eq!(r([2, 2, 0, 0, 0]), Err(WireError::InvalidResult));
        assert_eq!(r([2, 2, 65, 0, 0]), Err(WireError::InvalidResult));
        assert_eq!(r([3, 1, 127, 15, 0]), Err(WireError::InvalidResult));
        assert_eq!(r([3, 0, 0, 15, 2]), Err(WireError::InvalidResult));
        assert_eq!(r([3, 1, 127, 16, 2]), Err(WireError::UnknownStep));
        assert_eq!(r([3, 1, 127, 15, 11]), Err(WireError::UnknownCode));
        assert_eq!(r([4, 1, 0, 0, 2]), Err(WireError::InvalidResult));
        assert_eq!(r([4, 0, 0, 1, 2]), Err(WireError::InvalidResult));
        assert_eq!(r([4, 0, 0, 0, 0]), Err(WireError::InvalidResult));
        assert_eq!(r([4, 0, 0, 0, 11]), Err(WireError::UnknownCode));
    }

    #[test]
    fn sup6_number_tables_cover_every_core_variant() {
        let mut seen = std::collections::HashSet::new();
        for c in ErrorCode::ALL {
            let n = error_code_to_u8(c).expect("every ErrorCode has a number");
            assert!(seen.insert(n));
            assert_eq!(error_code_from_u8(n), Some(c));
        }
        assert_eq!(seen.len(), 10);
        let mut seen = std::collections::HashSet::new();
        for s in ExecChildStep::ALL {
            let n = step_to_u8(s).expect("every ExecChildStep has a number");
            assert!(seen.insert(n));
            assert_eq!(step_from_u8(n), Some(s));
        }
        assert_eq!(seen.len(), 15);
        assert_eq!(error_code_from_u8(0), None);
        assert_eq!(step_from_u8(0), None);
    }

    #[test]
    fn sup6_mask_accessors() {
        let m = StdioMask::from_presence(true, false, true);
        assert_eq!(m.bits(), 0b101);
        assert!(m.stdin() && !m.stdout() && m.stderr());
        assert_eq!(m.count(), 2);
        assert!(StdioMask::new(0b1000).is_none());
        assert!(ExitSignal::new(0).is_none() && ExitSignal::new(65).is_none());
    }
}
