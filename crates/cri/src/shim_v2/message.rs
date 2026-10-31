//! ttrpc の封筒メッセージ（CRI-5・TASK-62.1・MS-7）。
//!
//! containerd/ttrpc の `request.proto` のフィールド番号を prost の derive で手書きする
//! （`.proto` は持ち込まない。#670）。`google.rpc.Status.details` は定義せず、受信時は
//! prost が未知フィールドとして読み飛ばし、送信では出さない。
//! `timeout_nano`・`metadata` は復号するだけで使わない（REPAIR-3。使うのは #672 以降）。

use crate::error::CriErrorCode;

/// 受け付ける `metadata` の最大件数。prost は空の `KeyValue`（2 バイト）を件数分確保するため、
/// フレーム上限だけでは展開量を抑えられない（件数を確保前に検証する規約）。
pub const MAX_METADATA_ENTRIES: usize = 64;

/// 復号前にワイヤー形式を走査し、`metadata`（フィールド 5）の件数が上限以内かを返す。
/// 走査できない（切れた・未知のワイヤー型）場合も `false`（確保しない側に倒す）。
pub fn metadata_within_limit(buf: &[u8]) -> bool {
    fn varint(buf: &[u8], pos: &mut usize) -> Option<u64> {
        let mut v: u64 = 0;
        for i in 0..10u32 {
            let b = *buf.get(*pos)?;
            *pos += 1;
            v |= u64::from(b & 0x7f).checked_shl(7 * i)?;
            if b & 0x80 == 0 {
                return Some(v);
            }
        }
        None
    }
    let mut pos = 0usize;
    let mut count = 0usize;
    while pos < buf.len() {
        let Some(tag) = varint(buf, &mut pos) else {
            return false;
        };
        let skip = match tag & 7 {
            0 => varint(buf, &mut pos).map(|_| 0usize),
            1 => Some(8),
            5 => Some(4),
            2 => {
                if tag >> 3 == 5 {
                    count += 1;
                    if count > MAX_METADATA_ENTRIES {
                        return false;
                    }
                }
                varint(buf, &mut pos).and_then(|l| usize::try_from(l).ok())
            }
            _ => None,
        };
        let Some(n) = skip else {
            return false;
        };
        match pos.checked_add(n) {
            Some(end) if end <= buf.len() => pos = end,
            _ => return false,
        }
    }
    true
}

/// `KeyValue { string key = 1; string value = 2; }`。
#[derive(Clone, PartialEq, prost::Message)]
pub struct KeyValue {
    /// キー。
    #[prost(string, tag = "1")]
    pub key: String,
    /// 値。
    #[prost(string, tag = "2")]
    pub value: String,
}

/// ttrpc の `Request`。
#[derive(Clone, PartialEq, prost::Message)]
pub struct TtrpcRequest {
    /// サービス名（例: `containerd.task.v2.Task`）。
    #[prost(string, tag = "1")]
    pub service: String,
    /// メソッド名。
    #[prost(string, tag = "2")]
    pub method: String,
    /// メソッド引数の符号化済みバイト列。
    #[prost(bytes = "vec", tag = "3")]
    pub payload: Vec<u8>,
    /// 期限（ナノ秒）。現状は読むだけで使わない。
    #[prost(int64, tag = "4")]
    pub timeout_nano: i64,
    /// メタデータ。現状は読むだけで使わない。
    #[prost(message, repeated, tag = "5")]
    pub metadata: Vec<KeyValue>,
}

/// `google.rpc.Status` 相当（code・message のみ）。
#[derive(Clone, PartialEq, prost::Message)]
pub struct RpcStatus {
    /// gRPC のコード値。
    #[prost(int32, tag = "1")]
    pub code: i32,
    /// 説明（英語。要求のサービス名・メソッド名を長さ上限つきでエコーすることがある）。
    #[prost(string, tag = "2")]
    pub message: String,
}

impl RpcStatus {
    /// CRI のエラー区分から作る。gRPC コードへの写像は `error.rs` に一本化する（ERR-3）。
    pub fn from_code(code: CriErrorCode, message: impl Into<String>) -> Self {
        Self {
            code: code.grpc_code() as i32,
            message: message.into(),
        }
    }
}

/// ttrpc の `Response`。
#[derive(Clone, PartialEq, prost::Message)]
pub struct TtrpcResponse {
    /// 結果。成功時は省略。
    #[prost(message, optional, tag = "1")]
    pub status: Option<RpcStatus>,
    /// 戻り値の符号化済みバイト列。
    #[prost(bytes = "vec", tag = "2")]
    pub payload: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message;

    /// CRI-5: フィールド番号の固定バイト列。
    #[test]
    fn cri5_request_wire_bytes() {
        let r = TtrpcRequest {
            service: "a".into(),
            method: "b".into(),
            payload: vec![9],
            ..Default::default()
        };
        assert_eq!(
            r.encode_to_vec(),
            [0x0a, 1, b'a', 0x12, 1, b'b', 0x1a, 1, 9]
        );
        assert_eq!(TtrpcRequest::decode(&r.encode_to_vec()[..]).unwrap(), r);
    }

    /// CRI-5: metadata の件数は復号前に数えて上限で拒否する（0x2a 0x00 の繰り返しを含む）。
    #[test]
    fn cri5_metadata_count_limit_before_decode() {
        let ok = TtrpcRequest {
            service: "a".into(),
            metadata: vec![KeyValue::default(); MAX_METADATA_ENTRIES],
            ..Default::default()
        };
        assert!(metadata_within_limit(&ok.encode_to_vec()));
        let bad = [0x2a, 0x00].repeat(MAX_METADATA_ENTRIES + 1);
        assert!(!metadata_within_limit(&bad));
        let huge = [0x2a, 0x00].repeat(100_000);
        assert!(!metadata_within_limit(&huge));
        // 切れた長さ・未知のワイヤー型は拒否。
        assert!(!metadata_within_limit(&[0x0a, 5, 1]));
        assert!(!metadata_within_limit(&[0x0b]));
        assert!(metadata_within_limit(&[]));
    }

    /// CRI-5: Response の往復と gRPC コード値（Unimplemented = 12）。
    #[test]
    fn cri5_response_roundtrip() {
        let st = RpcStatus::from_code(CriErrorCode::Unimplemented, "x");
        assert_eq!(st.code, 12);
        let r = TtrpcResponse {
            status: Some(st),
            payload: vec![],
        };
        assert_eq!(r.encode_to_vec(), [0x0a, 5, 0x08, 12, 0x12, 1, b'x']);
        assert_eq!(TtrpcResponse::decode(&r.encode_to_vec()[..]).unwrap(), r);
    }
}
