//! 制御チャネルのワイヤー形式（固定長・big-endian。REPAIR-2・SUP-1・SEC-1・#2058）。
//!
//! CLI（クライアント。[`super::client`]）と supervisor（サーバ。`control::server`）が UDS 上で交わす 3 種類の
//! frame を、壊れた値を表現できない型で組み立てる。生の `Vec<u8>` を手で組まず、encode は固定長の配列を返し、
//! decode は `get`・`from_be_bytes`・配列パターンだけで読む（添字アクセスをしない。外部入力の経路）。
//!
//! # frame
//!
//! 先頭は 8 バイトのヘッダ: magic `FCSC`（4）・version `u8`（現在 1）・kind `u8`・payload_len `u16`。
//!
//! | frame | 向き | kind | payload | 全長 |
//! | ----- | ---- | ---- | ------- | ---- |
//! | Hello | サーバ → クライアント | 1 | なし | 8 |
//! | SignalRequest | クライアント → サーバ | 2 | pid `u32`・signal `u8`・deadline_ns `u64` | 21 |
//! | Response | サーバ → クライアント | 3 | reason `u8` | 9 |
//!
//! 1 接続 1 要求。Hello はサーバが接続元の uid を検証した後に送る。クライアントは Hello を受けてから
//! 「自分の期限 − 余裕」を `CLOCK_MONOTONIC` のナノ秒（同一ホストの別プロセスと比較できる絶対時刻）で要求に載せ、
//! サーバは受信の遅れを含めてその絶対期限を送信期限にする（サーバの処理が遅れても期限は延びず、クライアントが
//! `Timeout` を返した後にシグナルを届けない。REPAIR-5）。
//!
//! 応答は理由コード（[`ControlReason`]）だけを返す。文言はクライアントの固定表が決め、入力値は反射しない。
//!
//! 将来拡張: kind の値域は、明示的な stop の意図の伝達（SUP-9。別 issue）等の追加に備えて残してある（未実装。REPAIR-3）。

use std::num::NonZeroU32;
use std::time::Duration;

use fandhe_container_core::traits::{ErrorCode, Signal, TraitError};

/// ヘッダの magic。
pub const MAGIC: [u8; 4] = *b"FCSC";
/// プロトコルの版。
pub const VERSION: u8 = 1;
/// ヘッダの長さ（バイト）。
pub const HEADER_LEN: usize = 8;
/// 受け付ける payload の最大長。これを超えるヘッダは payload を読まずに拒否する（無制限確保の防止）。
pub const MAX_PAYLOAD: u16 = 64;
/// SignalRequest の payload 長。
pub const SIGNAL_REQUEST_PAYLOAD_LEN: usize = 13;
/// SignalRequest の全長。
pub const SIGNAL_REQUEST_LEN: usize = HEADER_LEN + SIGNAL_REQUEST_PAYLOAD_LEN;
/// Response の payload 長。
pub const RESPONSE_PAYLOAD_LEN: usize = 1;
/// Response の全長。
pub const RESPONSE_LEN: usize = HEADER_LEN + RESPONSE_PAYLOAD_LEN;
/// 要求が指定できる送信期限の、サーバが見た時点からの残り時間の上限。
pub const MAX_SIGNAL_BUDGET: Duration = Duration::from_secs(10);

const KIND_HELLO: u8 = 1;
const KIND_SIGNAL_REQUEST: u8 = 2;
const KIND_RESPONSE: u8 = 3;

/// 応答の理由コード。サーバは値だけを返し、クライアントが固定文言へ写す（[`ControlReason::to_error`]）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[non_exhaustive]
pub enum ControlReason {
    /// シグナルを送った。
    Ok = 0,
    /// 起動ハンドルを保持していない。
    NoHandle = 1,
    /// 要求の pid が起動ハンドルの pid と一致しない。
    PidMismatch = 2,
    /// コンテナのプロセスはすでに終了している。
    ContainerExited = 3,
    /// 期限内に送信を完了できなかった（期限後にシグナルは届かない）。
    Timeout = 4,
    /// 受け付け口が埋まっている。
    Busy = 5,
    /// 要求が不正（magic・kind・長さ・値域）。
    Malformed = 6,
    /// payload_len が上限を超えた。
    TooLarge = 7,
    /// プロトコルの版が合わない。
    UnsupportedVersion = 8,
    /// シグナルの送信が失敗した。
    SignalFailed = 9,
    /// supervisor の内部エラー。
    Internal = 10,
}

impl ControlReason {
    /// ワイヤー上の値から復元する。未知の値は `None`（クライアントは `Internal` 扱いにする）。
    pub fn from_u8(value: u8) -> Option<Self> {
        Some(match value {
            0 => Self::Ok,
            1 => Self::NoHandle,
            2 => Self::PidMismatch,
            3 => Self::ContainerExited,
            4 => Self::Timeout,
            5 => Self::Busy,
            6 => Self::Malformed,
            7 => Self::TooLarge,
            8 => Self::UnsupportedVersion,
            9 => Self::SignalFailed,
            10 => Self::Internal,
            _ => return None,
        })
    }

    /// 構造化ログ用の固定語彙。
    pub fn name(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::NoHandle => "no_handle",
            Self::PidMismatch => "pid_mismatch",
            Self::ContainerExited => "container_exited",
            Self::Timeout => "timeout",
            Self::Busy => "busy",
            Self::Malformed => "malformed",
            Self::TooLarge => "too_large",
            Self::UnsupportedVersion => "unsupported_version",
            Self::SignalFailed => "signal_failed",
            Self::Internal => "internal",
        }
    }

    /// クライアント側の固定表: 理由コードを機械可読な構造化エラーへ写す。`Ok` は `None`。
    /// 文言はここだけで決まり、サーバが送った値や要求の内容は含めない。
    pub fn to_error(self) -> Option<TraitError> {
        let (code, message) = match self {
            Self::Ok => return None,
            Self::NoHandle => (
                ErrorCode::FailedPrecondition,
                "the supervisor holds no launched process",
            ),
            Self::PidMismatch => (
                ErrorCode::FailedPrecondition,
                "the process id does not match the launched process",
            ),
            Self::ContainerExited => (
                ErrorCode::FailedPrecondition,
                "the container process has already exited",
            ),
            Self::Timeout => (
                ErrorCode::Timeout,
                "the signal delivery did not complete within the timeout",
            ),
            Self::Busy => (
                ErrorCode::Unavailable,
                "the supervisor control channel is busy",
            ),
            Self::Malformed | Self::TooLarge => (
                ErrorCode::InvalidArgument,
                "the supervisor rejected the control request",
            ),
            Self::UnsupportedVersion => (
                ErrorCode::FailedPrecondition,
                "the supervisor control protocol version does not match",
            ),
            Self::SignalFailed | Self::Internal => (
                ErrorCode::Internal,
                "the supervisor failed to deliver the signal",
            ),
        };
        Some(TraitError::new(code, message))
    }
}

/// 送信期限。`CLOCK_MONOTONIC` のナノ秒による絶対時刻（0 は表現できない）。
///
/// 同一ホストの別プロセス（CLI と supervisor）が同じ時計を読むので、サーバは受信の遅れを含めて残り時間を
/// 求められる（相対値だと遅れの分だけ送信期限が延びる。REPAIR-5）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignalDeadline(u64);

impl SignalDeadline {
    /// 絶対時刻（ナノ秒）から作る。0 は `Malformed`。
    pub fn from_nanos(ns: u64) -> Result<Self, ControlReason> {
        if ns == 0 {
            return Err(ControlReason::Malformed);
        }
        Ok(Self(ns))
    }

    /// ナノ秒（`CLOCK_MONOTONIC`）。
    pub fn as_nanos(self) -> u64 {
        self.0
    }

    /// 現在時刻 `now_ns`（同じ時計）から見た残り時間。すでに過ぎていれば `Timeout`、
    /// [`MAX_SIGNAL_BUDGET`] を超える先なら `Malformed`（無制限に長い期限を受けない）。
    pub fn remaining_from(self, now_ns: u64) -> Result<Duration, ControlReason> {
        let Some(rest) = self.0.checked_sub(now_ns).filter(|r| *r > 0) else {
            return Err(ControlReason::Timeout);
        };
        let remaining = Duration::from_nanos(rest);
        if remaining > MAX_SIGNAL_BUDGET {
            return Err(ControlReason::Malformed);
        }
        Ok(remaining)
    }
}

/// ヘッダ（kind と payload_len。magic・version は decode で検証済み）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameHeader {
    kind: u8,
    payload_len: u16,
}

impl FrameHeader {
    fn encode(kind: u8, payload_len: u16) -> [u8; HEADER_LEN] {
        let [m0, m1, m2, m3] = MAGIC;
        let [l0, l1] = payload_len.to_be_bytes();
        [m0, m1, m2, m3, VERSION, kind, l0, l1]
    }

    /// 受信した 8 バイトを検証して読む。magic 違いは `Malformed`、版違いは `UnsupportedVersion`、
    /// payload_len が [`MAX_PAYLOAD`] 超は `TooLarge`（payload は読まない）。
    pub fn decode(bytes: &[u8; HEADER_LEN]) -> Result<Self, ControlReason> {
        let [m0, m1, m2, m3, version, kind, l0, l1] = *bytes;
        if [m0, m1, m2, m3] != MAGIC {
            return Err(ControlReason::Malformed);
        }
        if version != VERSION {
            return Err(ControlReason::UnsupportedVersion);
        }
        let payload_len = u16::from_be_bytes([l0, l1]);
        if payload_len > MAX_PAYLOAD {
            return Err(ControlReason::TooLarge);
        }
        Ok(Self { kind, payload_len })
    }

    /// 期待する kind と payload 長に一致するか確かめる（不一致は `Malformed`）。
    fn expect(self, kind: u8, payload_len: usize) -> Result<(), ControlReason> {
        if self.kind != kind || usize::from(self.payload_len) != payload_len {
            return Err(ControlReason::Malformed);
        }
        Ok(())
    }

    /// SignalRequest のヘッダとして正しいか確かめる（サーバが payload を読む前に呼ぶ）。
    pub fn expect_signal_request(self) -> Result<(), ControlReason> {
        self.expect(KIND_SIGNAL_REQUEST, SIGNAL_REQUEST_PAYLOAD_LEN)
    }

    /// Hello のヘッダとして正しいか確かめる。
    pub fn expect_hello(self) -> Result<(), ControlReason> {
        self.expect(KIND_HELLO, 0)
    }

    /// Response のヘッダとして正しいか確かめる。
    pub fn expect_response(self) -> Result<(), ControlReason> {
        self.expect(KIND_RESPONSE, RESPONSE_PAYLOAD_LEN)
    }
}

/// Hello frame（payload なし）を encode する。
pub fn encode_hello() -> [u8; HEADER_LEN] {
    FrameHeader::encode(KIND_HELLO, 0)
}

/// SignalRequest frame。pid・signal・deadline の値域は型が保証する。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignalRequestFrame {
    /// 対象の pid（起動ハンドルの pid と一致したときだけ送る）。
    pub pid: NonZeroU32,
    /// 送るシグナル（1..=64）。
    pub signal: Signal,
    /// 送信期限（`CLOCK_MONOTONIC` の絶対時刻）。
    pub deadline: SignalDeadline,
}

impl SignalRequestFrame {
    /// 21 バイトに encode する。
    pub fn encode(&self) -> [u8; SIGNAL_REQUEST_LEN] {
        let [h0, h1, h2, h3, h4, h5, h6, h7] =
            FrameHeader::encode(KIND_SIGNAL_REQUEST, SIGNAL_REQUEST_PAYLOAD_LEN as u16);
        let [p0, p1, p2, p3] = self.pid.get().to_be_bytes();
        let [b0, b1, b2, b3, b4, b5, b6, b7] = self.deadline.as_nanos().to_be_bytes();
        [
            h0,
            h1,
            h2,
            h3,
            h4,
            h5,
            h6,
            h7,
            p0,
            p1,
            p2,
            p3,
            self.signal.as_u8(),
            b0,
            b1,
            b2,
            b3,
            b4,
            b5,
            b6,
            b7,
        ]
    }

    /// 検証済みヘッダの後ろの payload 13 バイトを読む。pid 0・signal 範囲外・deadline 0 は `Malformed`。
    pub fn decode_payload(
        payload: &[u8; SIGNAL_REQUEST_PAYLOAD_LEN],
    ) -> Result<Self, ControlReason> {
        let [p0, p1, p2, p3, signal, b0, b1, b2, b3, b4, b5, b6, b7] = *payload;
        let pid = NonZeroU32::new(u32::from_be_bytes([p0, p1, p2, p3]))
            .ok_or(ControlReason::Malformed)?;
        let signal = Signal::new(signal).map_err(|_| ControlReason::Malformed)?;
        let deadline =
            SignalDeadline::from_nanos(u64::from_be_bytes([b0, b1, b2, b3, b4, b5, b6, b7]))?;
        Ok(Self {
            pid,
            signal,
            deadline,
        })
    }
}

/// Response frame。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResponseFrame {
    /// 理由コード（成功は [`ControlReason::Ok`]）。
    pub reason: ControlReason,
}

impl ResponseFrame {
    /// 9 バイトに encode する。
    pub fn encode(&self) -> [u8; RESPONSE_LEN] {
        let [h0, h1, h2, h3, h4, h5, h6, h7] =
            FrameHeader::encode(KIND_RESPONSE, RESPONSE_PAYLOAD_LEN as u16);
        [h0, h1, h2, h3, h4, h5, h6, h7, self.reason as u8]
    }

    /// 検証済みヘッダの後ろの payload 1 バイトを読む。未知の理由は `Internal` に倒す。
    pub fn decode_payload(payload: &[u8; RESPONSE_PAYLOAD_LEN]) -> Self {
        let [reason] = *payload;
        Self {
            reason: ControlReason::from_u8(reason).unwrap_or(ControlReason::Internal),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> SignalRequestFrame {
        SignalRequestFrame {
            pid: NonZeroU32::new(4242).unwrap(),
            signal: Signal::new(15).unwrap(),
            deadline: SignalDeadline::from_nanos(1_500_000_000).unwrap(),
        }
    }

    /// REPAIR-2・SUP-1: 要求の encode は具体的な 21 バイトに一致し、decode で元に戻る。
    #[test]
    fn repair2_sup1_request_roundtrip_concrete_bytes() {
        let bytes = request().encode();
        assert_eq!(
            bytes,
            [
                b'F', b'C', b'S', b'C', 1, 2, 0, 13, // ヘッダ
                0, 0, 0x10, 0x92, // pid 4242
                15,   // signal
                0, 0, 0, 0, 0x59, 0x68, 0x2f, 0x00, // deadline 1_500_000_000ns
            ]
        );
        let (head, payload) = bytes.split_first_chunk::<HEADER_LEN>().unwrap();
        let header = FrameHeader::decode(head).unwrap();
        header.expect_signal_request().unwrap();
        let payload: [u8; SIGNAL_REQUEST_PAYLOAD_LEN] = payload.try_into().unwrap();
        assert_eq!(
            SignalRequestFrame::decode_payload(&payload).unwrap(),
            request()
        );
    }

    #[test]
    fn repair2_sup1_hello_and_response_concrete_bytes() {
        assert_eq!(encode_hello(), [b'F', b'C', b'S', b'C', 1, 1, 0, 0]);
        let resp = ResponseFrame {
            reason: ControlReason::PidMismatch,
        };
        assert_eq!(resp.encode(), [b'F', b'C', b'S', b'C', 1, 3, 0, 1, 2]);
        assert_eq!(ResponseFrame::decode_payload(&[2]), resp);
        // 未知の理由は Internal に倒す。
        assert_eq!(
            ResponseFrame::decode_payload(&[200]).reason,
            ControlReason::Internal
        );
    }

    /// SEC-1・REPAIR-2: ヘッダの拒否（magic・version・長さ上限・kind・長さ不一致）。
    #[test]
    fn sec1_repair2_header_rejections() {
        let good = request().encode();
        let mut head: [u8; HEADER_LEN] = good.first_chunk::<HEADER_LEN>().copied().unwrap();
        assert!(FrameHeader::decode(&head).is_ok());

        let mut bad = head;
        bad[0] = b'X';
        assert_eq!(FrameHeader::decode(&bad), Err(ControlReason::Malformed));

        let mut bad = head;
        bad[4] = 2;
        assert_eq!(
            FrameHeader::decode(&bad),
            Err(ControlReason::UnsupportedVersion)
        );

        // payload_len = 4096 は payload を読まずに TooLarge。
        let mut bad = head;
        bad[6] = 0x10;
        bad[7] = 0x00;
        assert_eq!(FrameHeader::decode(&bad), Err(ControlReason::TooLarge));

        // 上限ちょうど（64）は通るが、SignalRequest の 9 とは一致しない。
        let mut edge = head;
        edge[6] = 0;
        edge[7] = 64;
        assert!(
            FrameHeader::decode(&edge)
                .unwrap()
                .expect_signal_request()
                .is_err()
        );

        // len = 8 は Malformed。
        head[7] = 8;
        assert_eq!(
            FrameHeader::decode(&head).unwrap().expect_signal_request(),
            Err(ControlReason::Malformed)
        );

        // kind 違い（Hello を要求として受けた）。
        let hello = encode_hello();
        assert_eq!(
            FrameHeader::decode(&hello).unwrap().expect_signal_request(),
            Err(ControlReason::Malformed)
        );
        FrameHeader::decode(&hello).unwrap().expect_hello().unwrap();
    }

    /// SEC-1・REPAIR-2: payload の値域（pid 0・signal 0 / 65・deadline 0）は型で表現できない。
    #[test]
    fn sec1_repair2_payload_range_rejections() {
        let p = |pid: u32, sig: u8, ns: u64| {
            let [a, b, c, d] = pid.to_be_bytes();
            let [e, f, g, h, i, j, k, l] = ns.to_be_bytes();
            [a, b, c, d, sig, e, f, g, h, i, j, k, l]
        };
        assert!(SignalRequestFrame::decode_payload(&p(1, 9, 1)).is_ok());
        assert!(SignalRequestFrame::decode_payload(&p(1, 64, u64::MAX)).is_ok());
        for bad in [p(0, 9, 100), p(1, 0, 100), p(1, 65, 100), p(1, 9, 0)] {
            assert_eq!(
                SignalRequestFrame::decode_payload(&bad),
                Err(ControlReason::Malformed)
            );
        }
        assert!(SignalDeadline::from_nanos(0).is_err());
    }

    /// REPAIR-5: 残り時間は絶対期限から受信側の現在時刻で数える（受信の遅れの分だけ縮む）。
    /// 過去・現在は Timeout、上限超は Malformed。
    #[test]
    fn repair5_deadline_remaining_shrinks_with_receive_delay() {
        let d = SignalDeadline::from_nanos(1_000_000_000 + 80_000_000).unwrap();
        // 受信が遅れず 1_000_000_000ns 時点なら 80ms。
        assert_eq!(
            d.remaining_from(1_000_000_000),
            Ok(Duration::from_millis(80))
        );
        // 100ms 遅れて 1_100_000_000ns 時点で読めば期限切れ（延長されない）。
        assert_eq!(d.remaining_from(1_100_000_000), Err(ControlReason::Timeout));
        assert_eq!(d.remaining_from(1_080_000_000), Err(ControlReason::Timeout));
        let far = SignalDeadline::from_nanos(11_000_000_001).unwrap();
        assert_eq!(far.remaining_from(1), Err(ControlReason::Malformed));
        assert_eq!(far.remaining_from(1_000_000_001), Ok(MAX_SIGNAL_BUDGET));
    }

    /// SUP-1・SEC-1: 理由コード → 構造化エラーの固定表（文言は入力に依存しない）。
    #[test]
    fn sup1_sec1_reason_to_error_table() {
        assert!(ControlReason::Ok.to_error().is_none());
        let e = ControlReason::PidMismatch.to_error().unwrap();
        assert_eq!(e.code(), ErrorCode::FailedPrecondition);
        assert_eq!(
            e.message(),
            "the process id does not match the launched process"
        );
        assert_eq!(
            ControlReason::Timeout.to_error().unwrap().code(),
            ErrorCode::Timeout
        );
        assert_eq!(
            ControlReason::TooLarge.to_error().unwrap().code(),
            ErrorCode::InvalidArgument
        );
        assert_eq!(
            ControlReason::Busy.to_error().unwrap().code(),
            ErrorCode::Unavailable
        );
        assert_eq!(
            ControlReason::SignalFailed.to_error().unwrap().code(),
            ErrorCode::Internal
        );
    }
}
