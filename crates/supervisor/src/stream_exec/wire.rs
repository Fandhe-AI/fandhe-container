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
//! | 4 | 1 | version `u8` = 3（#4221 で `Started` に exec 子 cgroup の名前を載せるため 1 から 2 へ、#4282 で `Signal`・`SignalAck` を足すため 3 へ上げた。旧い相手とは混在させない） |
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
//! | 2 | `Started` | helper → plugin-cri | 65 バイト（exec 子 cgroup の名前） | 73 | 0 |
//! | 3 | `PtyMaster` | helper → plugin-cri | なし | 8 | 1（文字デバイス） |
//! | 4 | `Result` | helper → plugin-cri | 5 バイト | 13 | 0 |
//! | 5 | `Signal` | plugin-cri → helper | signal `u8` | 9 | 0 |
//! | 6 | `SignalAck` | helper → plugin-cri | `[signal, code]` 2 バイト | 10 | 0 |
//!
//! mask: bit0 = stdin、bit1 = stdout、bit2 = stderr。bit3〜7 は 0 でなければ拒否。fd の並びはビット昇順。
//!
//! # `Signal` と `SignalAck`（#4282・SUP-6・CRI-5・SEC-1）
//!
//! `Signal` は exec のコマンド（本体の 1 プロセス。子孫へは送らない）へ SIGKILL 以外のシグナルを届ける要求。番号は許可リスト
//! [`ExecSignal`]（SIGHUP 1・SIGINT 2・SIGQUIT 3・SIGUSR1 10・SIGUSR2 12・SIGTERM 15。x86_64 と aarch64 で同じ）だけで、
//! 0 と 65 以上は `SignalOutOfRange`、1〜64 の許可外（SIGKILL は既存の cgroup ごとの停止のほうが強い・STOP 系と CONT は exec を止める・
//! WINCH は tty 未対応・実時間シグナルは glibc の予約を含む）は `SignalNotAllowed` で frame ごと拒否する。
//! `SignalAck` は helper がその結果を 1 つ返す（要求 1 件につき高々 1 件）。code: 1 = delivered、2 = not_started（コマンドの
//! pidfd がまだ届いていない。猶予を過ぎた）、3 = exited（既に終わっていた）、4 = unavailable（送れなかった）。未知の code は
//! `UnknownSignalAck` で frame ごと拒否する。
//!
//! # `Started` の payload（65 バイト。#4221）
//!
//! `[name_len: u8][name: 64 バイト（NUL で埋める）]`。名前は helper が作った exec 子 cgroup の名前（`exec-<pid>-<連番>`）で、
//! plugin-cri が kill・期限切れの後に「その cgroup が無いこと」を読み取り専用で確かめる材料になる（CRI-5・SEC-1）。
//! `name_len` が 0 か 64 超・埋めに 0 でないバイトがある・`ExecCgroupName::new` が拒否する名前は frame 全体を拒否する。
//!
//! # `Result` の payload（5 バイト）
//!
//! `[outcome, status_kind, status_value, step, code]`
//!
//! | outcome | 意味 | status_kind / value | step | code |
//! | --- | --- | --- | --- | --- |
//! | 1 | exited | 1 / exit code | 0 | 0 |
//! | 2 | signaled | 2 / signal（1〜64） | 0 | 0 |
//! | 3 | not_started | 1 または 2（子の終了状態。写像に使う） | 0〜16 | 1〜10 |
//! | 4 | failed | 0 / 0 | 0 | 1〜10 |
//!
//! step: 0 = なし、1〜16 = `ExecChildStep`。1〜15 は宣言順（`ControllingTty` を除く）、後から足した `ControllingTty`（#3758）は既存番号を動かさないため末尾の 16。code: 1〜10 = `ErrorCode` を宣言順に 1 から。
//! 番号は `ALL` の添字からではなく明示の `match` で固定し、core の並び替えで動かさない。未知の番号は frame 全体を拒否する。

use std::num::NonZeroU8;

use fandhe_container_core::exec::{ExecCgroupName, ExecChildStep};
use fandhe_container_core::traits::ErrorCode;

/// 先頭の識別子（制御チャネルの `FCSC` と別）。
pub const MAGIC: [u8; 4] = *b"FCSX";
/// 語彙の版。
pub const VERSION: u8 = 3;
/// ヘッダの長さ。
pub const HEADER_LEN: usize = 8;
/// payload の上限（`Started` の 65 バイト）。これを超えるヘッダは payload を読まずに拒否する。
pub const MAX_PAYLOAD: u16 = (1 + CGROUP_NAME_FIELD_LEN) as u16;
/// frame 全体の上限（受信バッファを固定長配列にするため）。
pub const MAX_FRAME_LEN: usize = HEADER_LEN + MAX_PAYLOAD as usize;
/// `Started` の名前欄の長さ（core の `ExecCgroupName::MAX_LEN`）。
pub const CGROUP_NAME_FIELD_LEN: usize = ExecCgroupName::MAX_LEN;
/// `Started` の payload 長（長さ 1 バイト + 名前欄）。
pub const STARTED_PAYLOAD_LEN: usize = 1 + CGROUP_NAME_FIELD_LEN;
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
    /// `Started` の名前欄が不正（長さ 0・上限超・埋めが 0 でない・名前の検証に失敗）。
    InvalidCgroupName,
    /// `Signal` の番号が範囲外（0 と 65 以上。#4282）。
    SignalOutOfRange,
    /// `Signal` の番号が 1〜64 だが許可リストに無い（#4282）。
    SignalNotAllowed,
    /// `SignalAck` の code が未知（#4282）。
    UnknownSignalAck,
}

/// 符号化の失敗（core に値が増えて番号表に無いとき。既知の値へ黙って置き換えない）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncodeError {
    /// `ErrorCode` の番号が未割り当て。
    UnmappedCode,
    /// `ExecChildStep` の番号が未割り当て。
    UnmappedStep,
    /// exec 子 cgroup の名前が名前欄に収まらない（黙って切り詰めない）。
    CgroupNameTooLong,
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
    /// plugin-cri → helper。exec のコマンドへ SIGKILL 以外のシグナルを送る要求（#4282）。
    Signal,
    /// helper → plugin-cri。`Signal` の結果（#4282）。
    SignalAck,
}

impl Kind {
    fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::StdioHandover),
            2 => Some(Self::Started),
            3 => Some(Self::PtyMaster),
            4 => Some(Self::Result),
            5 => Some(Self::Signal),
            6 => Some(Self::SignalAck),
            _ => None,
        }
    }

    fn as_u8(self) -> u8 {
        match self {
            Self::StdioHandover => 1,
            Self::Started => 2,
            Self::PtyMaster => 3,
            Self::Result => 4,
            Self::Signal => 5,
            Self::SignalAck => 6,
        }
    }

    /// この kind の payload 長（固定）。
    pub fn payload_len(self) -> u16 {
        match self {
            Self::StdioHandover | Self::Signal => 1,
            Self::PtyMaster => 0,
            Self::Started => STARTED_PAYLOAD_LEN as u16,
            Self::Result => 5,
            Self::SignalAck => 2,
        }
    }

    /// helper が受けてよい kind（plugin-cri → helper の向き）。
    pub fn is_to_helper(self) -> bool {
        matches!(self, Self::StdioHandover | Self::Signal)
    }

    /// plugin-cri が受けてよい kind（helper → plugin-cri の向き）。向きは明示の集合で持ち、kind を足したとき
    /// 「`is_to_helper` でなければ helper 発」と黙って決まらないようにする（#4282）。
    pub fn is_from_helper(self) -> bool {
        matches!(
            self,
            Self::Started | Self::PtyMaster | Self::Result | Self::SignalAck
        )
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

/// `Started` が運ぶ exec 子 cgroup の名前（固定長 64 バイト + 長さ。壊れた値は作れない）。
///
/// `ExecCgroupName`（`String` を持ち `Copy` でない）の代わりに `Frame`・`EncodedFrame` の `Copy` を保つための型。
/// 作れるのは [`Self::from_name`]（検証済みの名前）と復号だけで、復号は `ExecCgroupName::new` を通った値だけを受ける。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WireCgroupName {
    len: u8,
    bytes: [u8; CGROUP_NAME_FIELD_LEN],
}

impl WireCgroupName {
    /// 検証済みの名前から作る。名前欄（64 バイト）に収まらなければ `CgroupNameTooLong`（切り詰めない）。
    pub fn from_name(name: &ExecCgroupName) -> Result<Self, EncodeError> {
        let src = name.as_str().as_bytes();
        let len = u8::try_from(src.len()).map_err(|_| EncodeError::CgroupNameTooLong)?;
        let mut bytes = [0u8; CGROUP_NAME_FIELD_LEN];
        let dst = bytes
            .get_mut(..src.len())
            .ok_or(EncodeError::CgroupNameTooLong)?;
        dst.copy_from_slice(src);
        Ok(Self { len, bytes })
    }

    /// 名前の文字列（検証済みの ASCII。異常時は空文字）。
    pub fn as_str(&self) -> &str {
        self.bytes
            .get(..usize::from(self.len))
            .and_then(|b| std::str::from_utf8(b).ok())
            .unwrap_or("")
    }

    /// `ExecCgroupName` へ戻す（検証を通す）。
    pub fn to_name(&self) -> Result<ExecCgroupName, WireError> {
        ExecCgroupName::new(self.as_str()).map_err(|_| WireError::InvalidCgroupName)
    }

    fn encode_payload(&self) -> [u8; STARTED_PAYLOAD_LEN] {
        let mut out = [0u8; STARTED_PAYLOAD_LEN];
        for (dst, src) in out
            .iter_mut()
            .zip(std::iter::once(&self.len).chain(self.bytes.iter()))
        {
            *dst = *src;
        }
        out
    }

    fn decode_payload(p: &[u8; STARTED_PAYLOAD_LEN]) -> Result<Self, WireError> {
        let (len, rest) = p.split_first().ok_or(WireError::LengthMismatch)?;
        let bytes =
            <[u8; CGROUP_NAME_FIELD_LEN]>::try_from(rest).map_err(|_| WireError::LengthMismatch)?;
        let n = usize::from(*len);
        if n == 0 || n > CGROUP_NAME_FIELD_LEN {
            return Err(WireError::InvalidCgroupName);
        }
        // 埋めの部分は 0 でなければならない。
        if bytes.get(n..).is_none_or(|pad| pad.iter().any(|b| *b != 0)) {
            return Err(WireError::InvalidCgroupName);
        }
        let me = Self { len: *len, bytes };
        me.to_name()?;
        Ok(me)
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

/// `ExecSignal::new` の拒否の理由（#4282。固定語彙）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignalRejection {
    /// 0 または 65 以上。
    OutOfRange,
    /// 1〜64 だが許可リストに無い。
    NotAllowed,
}

/// `Signal` frame で送れるシグナル番号（許可リストの newtype。許可外の値は作れない。#4282・SUP-6・SEC-1）。
///
/// 許可: SIGHUP 1・SIGINT 2・SIGQUIT 3・SIGUSR1 10・SIGUSR2 12・SIGTERM 15（x86_64 と aarch64 の asm-generic で同じ番号）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecSignal(NonZeroU8);

impl ExecSignal {
    /// 許可する番号（昇順）。
    pub const ALLOWED: [u8; 6] = [1, 2, 3, 10, 12, 15];

    /// 検証して作る。0 と 65 以上は `OutOfRange`、1〜64 の許可外は `NotAllowed`。
    pub fn new(n: u8) -> Result<Self, SignalRejection> {
        let nz = NonZeroU8::new(n).ok_or(SignalRejection::OutOfRange)?;
        if n > 64 {
            return Err(SignalRejection::OutOfRange);
        }
        if !Self::ALLOWED.contains(&n) {
            return Err(SignalRejection::NotAllowed);
        }
        Ok(Self(nz))
    }

    /// シグナル番号。
    pub fn get(self) -> u8 {
        self.0.get()
    }

    /// 番号（`NonZeroU8`。core の送信口へ渡す）。
    pub fn number(self) -> NonZeroU8 {
        self.0
    }
}

impl From<SignalRejection> for WireError {
    fn from(r: SignalRejection) -> Self {
        match r {
            SignalRejection::OutOfRange => Self::SignalOutOfRange,
            SignalRejection::NotAllowed => Self::SignalNotAllowed,
        }
    }
}

/// `SignalAck` の code（#4282）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignalAckCode {
    /// シグナルをコマンドへ送れた（1）。
    Delivered,
    /// コマンドの pidfd がまだ届いておらず、猶予を過ぎた（2）。
    NotStarted,
    /// コマンドは既に終わっていた（3）。
    Exited,
    /// 送れなかった（pidfd を使えない・送信の失敗。4）。
    Unavailable,
}

impl SignalAckCode {
    fn as_u8(self) -> u8 {
        match self {
            Self::Delivered => 1,
            Self::NotStarted => 2,
            Self::Exited => 3,
            Self::Unavailable => 4,
        }
    }

    fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Delivered),
            2 => Some(Self::NotStarted),
            3 => Some(Self::Exited),
            4 => Some(Self::Unavailable),
            _ => None,
        }
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
    /// exec の開始（exec 子 cgroup の名前を運ぶ。#4221）。
    Started(WireCgroupName),
    /// pty master（fd 1 本を伴う）。
    PtyMaster,
    /// 終了の結果。
    Result(StreamExecOutcome),
    /// コマンドへのシグナルの要求（plugin-cri → helper。#4282）。
    Signal(ExecSignal),
    /// `Signal` の結果（helper → plugin-cri。要求の番号を折り返す。#4282）。
    SignalAck {
        /// 要求されたシグナル。
        signal: ExecSignal,
        /// 結果。
        code: SignalAckCode,
    },
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
            Self::Started(_) => Kind::Started,
            Self::PtyMaster => Kind::PtyMaster,
            Self::Result(_) => Kind::Result,
            Self::Signal(_) => Kind::Signal,
            Self::SignalAck { .. } => Kind::SignalAck,
        }
    }

    /// 固定長配列へ符号化する。番号表に無い `ErrorCode`・`ExecChildStep` は `Err`（黙って置き換えない）。
    pub fn encode(&self) -> Result<EncodedFrame, EncodeError> {
        Ok(match self {
            Self::StdioHandover(mask) => build(Kind::StdioHandover, &[mask.bits()]),
            Self::Started(name) => build(Kind::Started, &name.encode_payload()),
            Self::PtyMaster => build(Kind::PtyMaster, &[]),
            Self::Result(outcome) => build(Kind::Result, &encode_outcome(outcome)?),
            Self::Signal(signal) => build(Kind::Signal, &[signal.get()]),
            Self::SignalAck { signal, code } => {
                build(Kind::SignalAck, &[signal.get(), code.as_u8()])
            }
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
            Kind::Started => {
                let arr = <&[u8; STARTED_PAYLOAD_LEN]>::try_from(payload)
                    .map_err(|_| WireError::LengthMismatch)?;
                WireCgroupName::decode_payload(arr).map(Self::Started)
            }
            Kind::PtyMaster => Ok(Self::PtyMaster),
            Kind::Result => {
                let arr = <&[u8; RESULT_PAYLOAD_LEN]>::try_from(payload)
                    .map_err(|_| WireError::LengthMismatch)?;
                decode_outcome(arr).map(Self::Result)
            }
            Kind::Signal => {
                let [n] = *<&[u8; 1]>::try_from(payload).map_err(|_| WireError::LengthMismatch)?;
                ExecSignal::new(n)
                    .map(Self::Signal)
                    .map_err(WireError::from)
            }
            Kind::SignalAck => {
                let [n, c] =
                    *<&[u8; 2]>::try_from(payload).map_err(|_| WireError::LengthMismatch)?;
                let signal = ExecSignal::new(n).map_err(WireError::from)?;
                let code = SignalAckCode::from_u8(c).ok_or(WireError::UnknownSignalAck)?;
                Ok(Self::SignalAck { signal, code })
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

/// `ExecChildStep` の番号（1〜16）。未割り当てなら `None`。
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
        ExecChildStep::ControllingTty => Some(16),
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
        16 => Some(ExecChildStep::ControllingTty),
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
        [b'F', b'C', b'S', b'X', 3, kind, l[0], l[1]]
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
            vec![0x46, 0x43, 0x53, 0x58, 3, 1, 0, 1, 0x05]
        );
    }

    fn started(name: &str) -> Frame {
        let n = ExecCgroupName::new(name).unwrap();
        Frame::Started(WireCgroupName::from_name(&n).unwrap())
    }

    #[test]
    fn sup6_simple_frames_concrete_bytes() {
        assert_eq!(
            roundtrip(Frame::PtyMaster),
            vec![0x46, 0x43, 0x53, 0x58, 3, 3, 0, 0]
        );
    }

    /// SUP-6・CRI-5・REPAIR-2・#4221: `Started` は名前を固定長 65 バイトで運び、往復で値が一致する。
    #[test]
    fn sup6_4221_started_roundtrip_concrete_bytes() {
        let bytes = roundtrip(started("exec-4242-0"));
        assert_eq!(bytes.len(), 73);
        assert_eq!(
            bytes.get(..8),
            Some(&[0x46, 0x43, 0x53, 0x58, 3, 2, 0, 65][..])
        );
        assert_eq!(bytes.get(8), Some(&11u8));
        assert_eq!(bytes.get(9..20), Some(&b"exec-4242-0"[..]));
        assert!(bytes.get(20..).unwrap().iter().all(|b| *b == 0));
        // 実際に作られる名前と、名前欄ちょうどの 64 バイトの名前。
        roundtrip(Frame::Started(
            WireCgroupName::from_name(&ExecCgroupName::unique()).unwrap(),
        ));
        let max = format!("exec-{}", "1".repeat(ExecCgroupName::MAX_LEN - 5));
        let f = started(&max);
        let bytes = roundtrip(f);
        assert_eq!(bytes.get(8), Some(&64u8));
        let Frame::Started(w) = f else { panic!() };
        assert_eq!(w.to_name().unwrap().as_str(), max);
    }

    /// REPAIR-2・#4221: 名前欄に収まらない名前は符号化で拒否する（黙って切り詰めない。`ExecCgroupName::new` が長さ上限で拒否するため
    /// 65 バイト以上の名前はそもそも作れず、`MAX_LEN` が欄の大きさと一致することを固定する）。
    #[test]
    fn repair2_4221_started_name_field_matches_core_limit() {
        assert_eq!(CGROUP_NAME_FIELD_LEN, 64);
        assert_eq!(MAX_PAYLOAD, 65);
        assert_eq!(MAX_FRAME_LEN, 73);
        let long = format!("exec-{}", "1".repeat(ExecCgroupName::MAX_LEN));
        assert!(ExecCgroupName::new(&long).is_err());
    }

    /// SUP-6・REPAIR-2・#4221: 旧い version 1 のヘッダは `BadVersion`（旧い相手の `Started` を確認済みとして扱わない）。
    #[test]
    fn sup6_4221_v1_header_is_rejected() {
        let mut v1 = hdr(2, 65);
        v1[4] = 1;
        assert_eq!(parse_header(&v1), Err(WireError::BadVersion));
        let mut v1_old_started = hdr(2, 0);
        v1_old_started[4] = 1;
        assert_eq!(parse_header(&v1_old_started), Err(WireError::BadVersion));
    }

    /// SUP-6・SEC-1・REPAIR-2・#4282: 旧い version 2 のヘッダは `BadVersion`（旧い相手に `Signal` を送らず、旧い相手の `Started` も確認済みにしない）。
    #[test]
    fn sup6_4282_v2_header_is_rejected() {
        for (kind, len) in [(1u8, 1u16), (2, 65), (3, 0), (4, 5), (5, 1), (6, 2)] {
            let mut v2 = hdr(kind, len);
            v2[4] = 2;
            assert_eq!(parse_header(&v2), Err(WireError::BadVersion), "kind {kind}");
        }
        assert_eq!(VERSION, 3);
    }

    /// SUP-6・REPAIR-2・#4282: `Signal` / `SignalAck` の具体バイトの往復。
    #[test]
    fn sup6_4282_signal_frames_concrete_bytes() {
        let term = ExecSignal::new(15).unwrap();
        assert_eq!(
            roundtrip(Frame::Signal(term)),
            vec![0x46, 0x43, 0x53, 0x58, 3, 5, 0, 1, 0x0F]
        );
        for code in [
            SignalAckCode::Delivered,
            SignalAckCode::NotStarted,
            SignalAckCode::Exited,
            SignalAckCode::Unavailable,
        ] {
            roundtrip(Frame::SignalAck { signal: term, code });
        }
        assert_eq!(
            roundtrip(Frame::SignalAck {
                signal: term,
                code: SignalAckCode::Delivered
            }),
            vec![0x46, 0x43, 0x53, 0x58, 3, 6, 0, 2, 0x0F, 1]
        );
        assert_eq!(
            roundtrip(Frame::SignalAck {
                signal: ExecSignal::new(1).unwrap(),
                code: SignalAckCode::Unavailable
            })
            .get(8..),
            Some(&[1u8, 4][..])
        );
    }

    /// SUP-6・SEC-1・#4282: 許可リストはちょうど {1, 2, 3, 10, 12, 15}。範囲外と許可外は別の固定語彙で拒否する。
    #[test]
    fn sup6_4282_signal_allow_list_is_exact() {
        let allowed: Vec<u8> = (0..=255u8)
            .filter(|n| ExecSignal::new(*n).is_ok())
            .collect();
        assert_eq!(allowed, vec![1, 2, 3, 10, 12, 15]);
        assert_eq!(ExecSignal::ALLOWED.to_vec(), allowed);
        for n in [9u8, 19, 18, 34, 20, 21, 22, 28, 17, 64, 32, 33] {
            assert_eq!(ExecSignal::new(n), Err(SignalRejection::NotAllowed), "{n}");
            assert_eq!(
                Frame::decode(Kind::Signal, &[n]),
                Err(WireError::SignalNotAllowed),
                "{n}"
            );
        }
        for n in [0u8, 65, 255] {
            assert_eq!(ExecSignal::new(n), Err(SignalRejection::OutOfRange), "{n}");
            assert_eq!(
                Frame::decode(Kind::Signal, &[n]),
                Err(WireError::SignalOutOfRange),
                "{n}"
            );
        }
    }

    /// SUP-6・REPAIR-2・#4282: `SignalAck` の不正（未知の code・許可外の番号）と長さの不一致・向きの集合。
    #[test]
    fn sup6_4282_signal_ack_rejections_and_directions() {
        for code in [0u8, 5, 255] {
            assert_eq!(
                Frame::decode(Kind::SignalAck, &[15, code]),
                Err(WireError::UnknownSignalAck)
            );
        }
        assert_eq!(
            Frame::decode(Kind::SignalAck, &[9, 1]),
            Err(WireError::SignalNotAllowed)
        );
        assert_eq!(
            Frame::decode(Kind::SignalAck, &[15]),
            Err(WireError::LengthMismatch)
        );
        assert_eq!(
            Frame::decode(Kind::Signal, &[15, 1]),
            Err(WireError::LengthMismatch)
        );
        assert_eq!(parse_header(&hdr(5, 2)), Err(WireError::LengthMismatch));
        assert_eq!(parse_header(&hdr(6, 1)), Err(WireError::LengthMismatch));
        for (kind, to_helper, from_helper) in [
            (Kind::StdioHandover, true, false),
            (Kind::Signal, true, false),
            (Kind::Started, false, true),
            (Kind::PtyMaster, false, true),
            (Kind::Result, false, true),
            (Kind::SignalAck, false, true),
        ] {
            assert_eq!(kind.is_to_helper(), to_helper, "{kind:?}");
            assert_eq!(kind.is_from_helper(), from_helper, "{kind:?}");
        }
    }

    /// REPAIR-12・#4282: 許可リストの番号は `libc` の定義と一致する（Linux。x86_64 と aarch64 で同じ値）。
    #[cfg(target_os = "linux")]
    #[test]
    fn sup6_4282_allow_list_matches_libc() {
        let expected = [
            libc::SIGHUP,
            libc::SIGINT,
            libc::SIGQUIT,
            libc::SIGUSR1,
            libc::SIGUSR2,
            libc::SIGTERM,
        ];
        let got: Vec<i32> = ExecSignal::ALLOWED.iter().map(|n| i32::from(*n)).collect();
        assert_eq!(got, expected.to_vec());
    }

    /// REPAIR-2・SEC-1・#4221: `Started` の名前欄の不正は frame 全体を拒否する。
    #[test]
    fn repair2_4221_started_payload_rejections() {
        let mk = |len: u8, name: &[u8]| {
            let mut p = [0u8; STARTED_PAYLOAD_LEN];
            p[0] = len;
            p[1..1 + name.len()].copy_from_slice(name);
            p
        };
        let d = |p: [u8; STARTED_PAYLOAD_LEN]| Frame::decode(Kind::Started, &p);
        assert!(d(mk(11, b"exec-4242-0")).is_ok());
        assert_eq!(d(mk(0, b"")), Err(WireError::InvalidCgroupName));
        assert_eq!(d(mk(65, &[b'a'; 64])), Err(WireError::InvalidCgroupName));
        // 埋めに 0 でないバイト。
        let mut pad = mk(11, b"exec-4242-0");
        pad[40] = b'x';
        assert_eq!(d(pad), Err(WireError::InvalidCgroupName));
        for bad in [
            &b"exec-A"[..],
            b"exec-1/2",
            b"exec-..",
            b"fc-c1@7",
            b"exec-",
        ] {
            assert_eq!(
                d(mk(u8::try_from(bad.len()).unwrap(), bad)),
                Err(WireError::InvalidCgroupName),
                "{bad:?}"
            );
        }
        assert_eq!(
            Frame::decode(Kind::Started, &[1u8; 64]),
            Err(WireError::LengthMismatch)
        );
        assert_eq!(
            Frame::decode(Kind::Started, &[]),
            Err(WireError::LengthMismatch)
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
        let mut bad = hdr(2, 65);
        bad[0] = b'X';
        assert_eq!(parse_header(&bad), Err(WireError::BadMagic));
        let mut v4 = hdr(2, 65);
        v4[4] = 4;
        assert_eq!(parse_header(&v4), Err(WireError::BadVersion));
        for k in [0u8, 7, 255] {
            assert_eq!(parse_header(&hdr(k, 0)), Err(WireError::UnknownKind));
        }
        assert_eq!(
            parse_header(&hdr(2, 0xFFFF)),
            Err(WireError::PayloadTooLarge)
        );
        assert_eq!(parse_header(&hdr(2, 66)), Err(WireError::PayloadTooLarge));
        assert_eq!(parse_header(&hdr(2, 1)), Err(WireError::LengthMismatch));
        assert_eq!(parse_header(&hdr(2, 0)), Err(WireError::LengthMismatch));
        assert_eq!(parse_header(&hdr(1, 0)), Err(WireError::LengthMismatch));
        assert_eq!(parse_header(&hdr(4, 4)), Err(WireError::LengthMismatch));
    }

    #[test]
    fn sup6_payload_rejections() {
        assert_eq!(
            Frame::decode(Kind::StdioHandover, &[0b1000]),
            Err(WireError::ReservedMaskBits)
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
        assert_eq!(r([3, 1, 127, 17, 2]), Err(WireError::UnknownStep));
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
        assert_eq!(seen.len(), 16);
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
