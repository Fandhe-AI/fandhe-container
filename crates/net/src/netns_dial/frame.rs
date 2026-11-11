//! plugin-cri と `netns-dial` helper の間の固定長 frame（CRI-6・NET-3・SEC-1・REPAIR-2・#4477）。
//!
//! 生の `Vec<u8>` を手で組まず、型付きの [`DialRequest`] / [`DialResponse`] から 16 バイトの newtype
//! （[`DialRequestFrame`] / [`DialResponseFrame`]）を作り、受信側は `decode` で全項目を検証する。
//! 要求と応答は別の型で、方向の取り違え（応答のバイト列を要求として読む等）は decode が拒否する。
//! 宛先は helper が `127.0.0.1` 固定で書くため、アドレス欄は持たない（channel を越える可変値は port と期限だけ）。
//! OS 非依存の純関数だけで、送受信は後続（#4478〜#4480）が担う。
//!
//! # レイアウト（16 バイト・整数は LE）
//! | offset | 長さ | 内容 |
//! | ------ | ---- | ---- |
//! | 0 | 4 | magic `b"FCND"` |
//! | 4 | 1 | version（`1`） |
//! | 5 | 1 | kind（1 = Request、2 = Connected、3 = Error） |
//! | 6 | 2 | reserved（0 でなければ拒否） |
//! | 8 | 2 | port（Request のみ。0 は拒否。他は 0） |
//! | 10 | 2 | reserved（0 でなければ拒否） |
//! | 12 | 4 | Request は connect の期限 ms（1..=10000）、Error はエラーコード（1..=6）、Connected は 0 |
//!
//! # fd の対応（frame の外の契約。本数の検査は送受信側が行う）
//! Request は `SCM_RIGHTS` の fd 2 本（順は user、net）、Connected は接続済み fd 1 本、Error は fd 0 本。

use std::num::NonZeroU16;
use std::time::Duration;

use crate::error::{NetError, NetErrorCode};

/// frame の長さ（固定）。
pub const FRAME_LEN: usize = 16;
/// connect の期限の下限（ms）。
pub const MIN_CONNECT_TIMEOUT_MS: u32 = 1;
/// connect の期限の上限（ms）。上限の無い待ちを frame から作らせない（REPAIR-5）。
pub const MAX_CONNECT_TIMEOUT_MS: u32 = 10_000;

const MAGIC: [u8; 4] = *b"FCND";
const VERSION: u8 = 1;

const KIND_REQUEST: u8 = 1;
const KIND_CONNECTED: u8 = 2;
const KIND_ERROR: u8 = 3;

fn bad(message: &'static str) -> NetError {
    NetError::new(NetErrorCode::FailedPrecondition, message)
}

/// connect の期限。1..=10000 ms の外を表現できない。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectTimeout(u32);

impl ConnectTimeout {
    /// ms から作る。範囲外は `InvalidArgument`。
    pub fn new(ms: u32) -> Result<Self, NetError> {
        if (MIN_CONNECT_TIMEOUT_MS..=MAX_CONNECT_TIMEOUT_MS).contains(&ms) {
            Ok(Self(ms))
        } else {
            Err(NetError::new(
                NetErrorCode::InvalidArgument,
                "connect timeout is out of range",
            ))
        }
    }

    /// `Duration` から作る（ms へ切り捨てた後に範囲検査する）。
    pub fn from_duration(d: Duration) -> Result<Self, NetError> {
        let ms = u32::try_from(d.as_millis()).map_err(|_| {
            NetError::new(
                NetErrorCode::InvalidArgument,
                "connect timeout is out of range",
            )
        })?;
        Self::new(ms)
    }

    /// ms。
    pub fn as_millis(self) -> u32 {
        self.0
    }

    /// `Duration`。
    pub fn as_duration(self) -> Duration {
        Duration::from_millis(u64::from(self.0))
    }
}

/// plugin-cri → helper の dial 要求。port は 0 を表現できない。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DialRequest {
    port: NonZeroU16,
    connect_timeout: ConnectTimeout,
}

impl DialRequest {
    /// 要求を作る。
    pub fn new(port: NonZeroU16, connect_timeout: ConnectTimeout) -> Self {
        Self {
            port,
            connect_timeout,
        }
    }

    /// 接続先の port（宛先アドレスは helper が `127.0.0.1` 固定）。
    pub fn port(&self) -> NonZeroU16 {
        self.port
    }

    /// connect の期限。
    pub fn connect_timeout(&self) -> ConnectTimeout {
        self.connect_timeout
    }
}

/// helper が返す失敗の分類（固定語彙 6 種。ワイヤー値は 1..=6 で並びに依存しない）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DialErrorCode {
    /// 接続拒否。
    Refused,
    /// connect の期限切れ。
    TimedOut,
    /// 到達不能。
    Unreachable,
    /// namespace への参加の失敗。
    JoinFailed,
    /// 参加先の識別（inode 等）の不一致。
    IdentityMismatch,
    /// 要求が不正。
    InvalidRequest,
}

impl DialErrorCode {
    /// 全 variant。
    pub const ALL: [DialErrorCode; 6] = [
        Self::Refused,
        Self::TimedOut,
        Self::Unreachable,
        Self::JoinFailed,
        Self::IdentityMismatch,
        Self::InvalidRequest,
    ];

    /// 固定語彙の名前。
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Refused => "refused",
            Self::TimedOut => "timed_out",
            Self::Unreachable => "unreachable",
            Self::JoinFailed => "join_failed",
            Self::IdentityMismatch => "identity_mismatch",
            Self::InvalidRequest => "invalid_request",
        }
    }

    fn to_wire(self) -> u32 {
        match self {
            Self::Refused => 1,
            Self::TimedOut => 2,
            Self::Unreachable => 3,
            Self::JoinFailed => 4,
            Self::IdentityMismatch => 5,
            Self::InvalidRequest => 6,
        }
    }

    fn from_wire(v: u32) -> Option<Self> {
        Some(match v {
            1 => Self::Refused,
            2 => Self::TimedOut,
            3 => Self::Unreachable,
            4 => Self::JoinFailed,
            5 => Self::IdentityMismatch,
            6 => Self::InvalidRequest,
            _ => return None,
        })
    }
}

/// helper → plugin-cri の応答。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DialResponse {
    /// 接続済み fd 1 本を `SCM_RIGHTS` で添える。
    Connected,
    /// 失敗（fd なし）。
    Error(DialErrorCode),
}

/// 共通の組み立て。固定長配列へ逐次書き込む（添字アクセスを使わない）。
fn build(kind: u8, port: u16, tail: u32) -> [u8; FRAME_LEN] {
    let mut buf = [0u8; FRAME_LEN];
    let mut at = 0usize;
    for chunk in [
        &MAGIC[..],
        &[VERSION, kind, 0, 0],
        &port.to_le_bytes(),
        &[0, 0],
        &tail.to_le_bytes(),
    ] {
        if let Some(dst) = buf.get_mut(at..at + chunk.len()) {
            dst.copy_from_slice(chunk);
        }
        at += chunk.len();
    }
    buf
}

/// 共通の検証（長さ・magic・version・予約欄）。`(kind, port, tail)` を返す。
fn parse(bytes: &[u8]) -> Result<(u8, u16, u32), NetError> {
    let Ok(buf) = <&[u8; FRAME_LEN]>::try_from(bytes) else {
        return Err(bad("netns dial frame has an unexpected length"));
    };
    if buf.get(0..4) != Some(&MAGIC[..]) {
        return Err(bad("netns dial frame has a bad magic"));
    }
    if buf.get(4) != Some(&VERSION) {
        return Err(bad("netns dial frame has an unsupported version"));
    }
    if buf.get(6..8) != Some(&[0u8, 0u8][..]) || buf.get(10..12) != Some(&[0u8, 0u8][..]) {
        return Err(bad("netns dial frame has a nonzero reserved field"));
    }
    let kind = buf.get(5).copied();
    let port = buf
        .get(8..10)
        .and_then(|s| <[u8; 2]>::try_from(s).ok())
        .map(u16::from_le_bytes);
    let tail = buf
        .get(12..16)
        .and_then(|s| <[u8; 4]>::try_from(s).ok())
        .map(u32::from_le_bytes);
    match (kind, port, tail) {
        (Some(k), Some(p), Some(t)) => Ok((k, p, t)),
        _ => Err(bad("netns dial frame is truncated")),
    }
}

/// エンコード済みの要求 frame（16 バイト）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DialRequestFrame([u8; FRAME_LEN]);

impl DialRequestFrame {
    /// 要求から frame を作る。
    pub fn encode(req: DialRequest) -> Self {
        Self(build(
            KIND_REQUEST,
            req.port.get(),
            req.connect_timeout.as_millis(),
        ))
    }

    /// 送信するバイト列。
    pub fn as_bytes(&self) -> &[u8; FRAME_LEN] {
        &self.0
    }

    /// 受信バイト列を検証して要求へ戻す。外れたものは `FailedPrecondition`（固定の英文。受信値を含めない）。
    pub fn decode(bytes: &[u8]) -> Result<DialRequest, NetError> {
        let (kind, port, tail) = parse(bytes)?;
        match kind {
            KIND_REQUEST => {}
            KIND_CONNECTED | KIND_ERROR => {
                return Err(bad("netns dial request frame has a response kind"));
            }
            _ => return Err(bad("netns dial frame has an unknown kind")),
        }
        let port = NonZeroU16::new(port).ok_or_else(|| bad("netns dial frame has a zero port"))?;
        let timeout = ConnectTimeout::new(tail)
            .map_err(|_| bad("netns dial frame has a connect timeout out of range"))?;
        Ok(DialRequest::new(port, timeout))
    }
}

/// エンコード済みの応答 frame（16 バイト）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DialResponseFrame([u8; FRAME_LEN]);

impl DialResponseFrame {
    /// 応答から frame を作る。
    pub fn encode(resp: DialResponse) -> Self {
        Self(match resp {
            DialResponse::Connected => build(KIND_CONNECTED, 0, 0),
            DialResponse::Error(code) => build(KIND_ERROR, 0, code.to_wire()),
        })
    }

    /// 送信するバイト列。
    pub fn as_bytes(&self) -> &[u8; FRAME_LEN] {
        &self.0
    }

    /// 受信バイト列を検証して応答へ戻す。外れたものは `FailedPrecondition`（固定の英文。受信値を含めない）。
    pub fn decode(bytes: &[u8]) -> Result<DialResponse, NetError> {
        let (kind, port, tail) = parse(bytes)?;
        match kind {
            KIND_REQUEST => Err(bad("netns dial response frame has a request kind")),
            KIND_CONNECTED | KIND_ERROR if port != 0 => {
                Err(bad("netns dial frame has a nonzero unused field"))
            }
            KIND_CONNECTED if tail == 0 => Ok(DialResponse::Connected),
            KIND_CONNECTED => Err(bad("netns dial frame has a nonzero unused field")),
            KIND_ERROR => DialErrorCode::from_wire(tail)
                .map(DialResponse::Error)
                .ok_or_else(|| bad("netns dial frame has an unknown error code")),
            _ => Err(bad("netns dial frame has an unknown kind")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(port: u16, ms: u32) -> DialRequest {
        DialRequest::new(
            NonZeroU16::new(port).expect("port"),
            ConnectTimeout::new(ms).expect("ms"),
        )
    }

    fn code_of<T: std::fmt::Debug>(r: Result<T, NetError>) -> (NetErrorCode, String) {
        let e = r.expect_err("must be rejected");
        (e.code(), e.message().to_string())
    }

    /// CRI-6・REPAIR-2・#4477: 要求の往復と全バイトの固定値。
    #[test]
    fn cri6_4477_request_roundtrip_and_wire_layout() {
        let f = DialRequestFrame::encode(req(8080, 2500));
        let mut want = [0u8; FRAME_LEN];
        want[..4].copy_from_slice(b"FCND");
        want[4] = 1;
        want[5] = 1;
        want[8..10].copy_from_slice(&8080u16.to_le_bytes());
        want[12..16].copy_from_slice(&2500u32.to_le_bytes());
        assert_eq!(f.as_bytes(), &want);
        assert_eq!(
            DialRequestFrame::decode(f.as_bytes()).expect("d"),
            req(8080, 2500)
        );
    }

    /// CRI-6・REPAIR-2・#4477: 応答の往復と固定値。
    #[test]
    fn cri6_4477_response_roundtrip_and_wire_layout() {
        let c = DialResponseFrame::encode(DialResponse::Connected);
        assert_eq!(
            c.as_bytes(),
            &[b'F', b'C', b'N', b'D', 1, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(
            DialResponseFrame::decode(c.as_bytes()).expect("d"),
            DialResponse::Connected
        );
        for (i, code) in DialErrorCode::ALL.iter().enumerate() {
            let f = DialResponseFrame::encode(DialResponse::Error(*code));
            let want_code = u8::try_from(i + 1).expect("small");
            assert_eq!(
                f.as_bytes(),
                &[
                    b'F', b'C', b'N', b'D', 1, 3, 0, 0, 0, 0, 0, 0, want_code, 0, 0, 0
                ]
            );
            assert_eq!(
                DialResponseFrame::decode(f.as_bytes()).expect("d"),
                DialResponse::Error(*code)
            );
        }
    }

    #[test]
    fn every_dial_error_code_has_fixed_name() {
        let names: Vec<&str> = DialErrorCode::ALL.iter().map(|c| c.as_str()).collect();
        assert_eq!(
            names,
            [
                "refused",
                "timed_out",
                "unreachable",
                "join_failed",
                "identity_mismatch",
                "invalid_request"
            ]
        );
    }

    #[test]
    fn connect_timeout_boundaries() {
        assert!(ConnectTimeout::new(1).is_ok());
        assert!(ConnectTimeout::new(10_000).is_ok());
        for ms in [0, 10_001, u32::MAX] {
            assert_eq!(
                code_of(ConnectTimeout::new(ms)).0,
                NetErrorCode::InvalidArgument
            );
        }
        assert_eq!(
            ConnectTimeout::from_duration(Duration::from_millis(1))
                .expect("1")
                .as_millis(),
            1
        );
        assert_eq!(
            ConnectTimeout::from_duration(Duration::from_secs(10))
                .expect("10s")
                .as_duration(),
            Duration::from_secs(10)
        );
        for d in [
            Duration::from_millis(0),
            Duration::from_micros(999),
            Duration::from_millis(10_001),
            Duration::MAX,
        ] {
            assert!(ConnectTimeout::from_duration(d).is_err(), "{d:?}");
        }
    }

    #[test]
    fn request_decode_rejects_out_of_range_values() {
        let ok = *DialRequestFrame::encode(req(80, 100)).as_bytes();
        let mut zero_port = ok;
        zero_port[8] = 0;
        zero_port[9] = 0;
        assert_eq!(
            code_of(DialRequestFrame::decode(&zero_port)),
            (
                NetErrorCode::FailedPrecondition,
                "netns dial frame has a zero port".into()
            )
        );
        for ms in [0u32, 10_001, u32::MAX] {
            let mut b = ok;
            b[12..16].copy_from_slice(&ms.to_le_bytes());
            assert_eq!(
                code_of(DialRequestFrame::decode(&b)),
                (
                    NetErrorCode::FailedPrecondition,
                    "netns dial frame has a connect timeout out of range".into()
                ),
                "{ms}"
            );
        }
        for ms in [1u32, 10_000] {
            let mut b = ok;
            b[12..16].copy_from_slice(&ms.to_le_bytes());
            assert!(DialRequestFrame::decode(&b).is_ok());
        }
    }

    #[test]
    fn unknown_kind_and_code_are_rejected() {
        let req_ok = *DialRequestFrame::encode(req(80, 100)).as_bytes();
        for k in [0u8, 4, 255] {
            let mut b = req_ok;
            b[5] = k;
            assert_eq!(
                code_of(DialRequestFrame::decode(&b)).1,
                "netns dial frame has an unknown kind"
            );
            assert_eq!(
                code_of(DialResponseFrame::decode(&b)).1,
                "netns dial frame has an unknown kind"
            );
        }
        let err =
            *DialResponseFrame::encode(DialResponse::Error(DialErrorCode::Refused)).as_bytes();
        for c in [0u32, 7, u32::MAX] {
            let mut b = err;
            b[12..16].copy_from_slice(&c.to_le_bytes());
            assert_eq!(
                code_of(DialResponseFrame::decode(&b)),
                (
                    NetErrorCode::FailedPrecondition,
                    "netns dial frame has an unknown error code".into()
                ),
                "{c}"
            );
        }
    }

    #[test]
    fn wrong_direction_is_rejected() {
        let rq = DialRequestFrame::encode(req(80, 100));
        let cn = DialResponseFrame::encode(DialResponse::Connected);
        let er = DialResponseFrame::encode(DialResponse::Error(DialErrorCode::TimedOut));
        assert_eq!(
            code_of(DialResponseFrame::decode(rq.as_bytes())).1,
            "netns dial response frame has a request kind"
        );
        for f in [cn, er] {
            assert_eq!(
                code_of(DialRequestFrame::decode(f.as_bytes())).1,
                "netns dial request frame has a response kind"
            );
        }
    }

    #[test]
    fn wrong_length_is_rejected() {
        for n in [0usize, 15, 17, 32] {
            let v = vec![0u8; n];
            assert_eq!(
                code_of(DialRequestFrame::decode(&v)),
                (
                    NetErrorCode::FailedPrecondition,
                    "netns dial frame has an unexpected length".into()
                )
            );
            assert_eq!(
                code_of(DialResponseFrame::decode(&v)).1,
                "netns dial frame has an unexpected length"
            );
        }
    }

    #[test]
    fn corrupted_header_and_unused_fields_are_rejected() {
        let rq = *DialRequestFrame::encode(req(80, 100)).as_bytes();
        let cn = *DialResponseFrame::encode(DialResponse::Connected).as_bytes();
        let er = *DialResponseFrame::encode(DialResponse::Error(DialErrorCode::Refused)).as_bytes();
        for i in 0..4 {
            let mut b = rq;
            b[i] ^= 0xff;
            assert_eq!(
                code_of(DialRequestFrame::decode(&b)).1,
                "netns dial frame has a bad magic"
            );
        }
        for v in [0u8, 2] {
            let mut b = rq;
            b[4] = v;
            assert_eq!(
                code_of(DialRequestFrame::decode(&b)).1,
                "netns dial frame has an unsupported version"
            );
        }
        for i in [6usize, 7, 10, 11] {
            let mut b = rq;
            b[i] = 1;
            assert_eq!(
                code_of(DialRequestFrame::decode(&b)),
                (
                    NetErrorCode::FailedPrecondition,
                    "netns dial frame has a nonzero reserved field".into()
                ),
                "{i}"
            );
        }
        for i in [8usize, 9, 12, 13, 14, 15] {
            let mut b = cn;
            b[i] = 1;
            assert_eq!(
                code_of(DialResponseFrame::decode(&b)).1,
                "netns dial frame has a nonzero unused field",
                "{i}"
            );
        }
        for i in [8usize, 9] {
            let mut b = er;
            b[i] = 1;
            assert_eq!(
                code_of(DialResponseFrame::decode(&b)).1,
                "netns dial frame has a nonzero unused field"
            );
        }
    }

    #[test]
    fn error_message_does_not_echo_input() {
        let mut b = *DialRequestFrame::encode(req(4242, 100)).as_bytes();
        b[0] = 0;
        assert!(!code_of(DialRequestFrame::decode(&b)).1.contains("4242"));
        let mut z = *DialRequestFrame::encode(req(4242, 100)).as_bytes();
        z[12..16].copy_from_slice(&0u32.to_le_bytes());
        assert!(!code_of(DialRequestFrame::decode(&z)).1.contains("4242"));
    }
}
