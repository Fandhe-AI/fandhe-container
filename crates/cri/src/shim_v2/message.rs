//! ttrpc の封筒メッセージ（CRI-5・TASK-62.1）。
//!
//! containerd/ttrpc の `request.proto` のフィールド番号を prost の derive で手書きする
//! （`.proto` は持ち込まない。#670）。`google.rpc.Status.details` は定義せず、受信時は
//! prost が未知フィールドとして読み飛ばし、送信では出さない。
//! `timeout_nano`・`metadata` は復号するだけで使わない（REPAIR-3。使うのは #672 以降）。

use crate::error::CriErrorCode;

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
