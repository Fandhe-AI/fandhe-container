//! 制御面メッセージの serde_json 符号化・復号（TASK-107.3・PLUG-2・PLUG-5・REPAIR-1・MS-3・#247）。
//!
//! core 側 proxy（`ContainerRuntime` 等の plugin 実装へ要求を送る側。TASK-114）と plugin
//! バイナリ（受ける側）の双方が、[`Frame`] のペイロードへ載せる JSON を作る・読むための層。
//! ペイロード方式は serde_json（#246 の決定。bincode は RUSTSEC-2025-0141 のため不採用）。
//! 個々の RPC の型対応は core 側の責務で、本モジュールは汎用エンベロープ [`ControlMessage<T>`] と
//! エラーのワイヤー表現だけを持つ。I/O は行わない（3 OS 共通の純粋関数）。
//!
//! # ワイヤー形（externally tagged・snake_case。操作種別は本体型 `T` 側のタグで表す）
//!
//! ```text
//! {"request":{"id":7,"body":{...}}}
//! {"response":{"id":7,"body":{...}}}
//! {"error":{"id":7,"error":{"code":"NOT_FOUND","message":"..."}}}
//! ```
//!
//! internally tagged は serde が全体を中間バッファへ溜めるため使わない（PLUG-5 の往復コスト）。
//! 項目を足す場合は旧実装が未知フィールドとして拒否するため
//! [`PROTOCOL_VERSION`](crate::frame::PROTOCOL_VERSION) を上げる。
//!
//! # 信頼境界・資源上限（REPAIR-1・security.md）
//!
//! - 復号の入力は検証済みの [`Frame`] のみ。長さ上限・チェックサム検証を通ったペイロードしか
//!   渡せないため、JSON 解析時の確保は上限（`MAX_PAYLOAD_LEN`）で頭打ちになる。
//! - 符号化は上限つきシンクへ直接書き、超過時点で打ち切る（出力全体を作ってから検査しない）。
//! - 未知フィールド・未知 variant・配列形・未知のエラー code は拒否する（fail-closed）。
//! - ネスト深さは serde_json 既定の再帰上限に任せる。`T` に `serde_json::Value` を選ぶと JSON
//!   サイズの数倍のメモリを使いうるため、型つき struct を推奨する（上限値の見直しは TASK-113）。
//! - 解析エラーの `message` には入力由来の断片を載せない（固定文言・分類・位置のみ）。
//!
//! # 未実装（REPAIR-3）
//!
//! ACK 種別・RPC タイムアウト（#250・#251）、ストリームからの読み書き（共通関数。#250・#251 で扱いを決める）、
//! gRPC 境界（TASK-108）は別 sub で実装する。

use std::fmt;
use std::io;
use std::marker::PhantomData;

use serde::de::{self, DeserializeOwned, MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};

use crate::error::{PluginError, PluginErrorCode};
use crate::frame::{Frame, MAX_PAYLOAD_LEN};

/// 要求と応答を対応づける ID。ワイヤー上は整数そのもの。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct MessageId(u64);

impl MessageId {
    /// ID を生成する。
    pub fn new(id: u64) -> Self {
        Self(id)
    }

    /// ID の値を返す。
    pub fn get(&self) -> u64 {
        self.0
    }
}

/// 制御面メッセージのエンベロープ。`T` は要求・応答の本体型（core 側が定義。TASK-114）。
///
/// `#[non_exhaustive]` のため、呼び出し側の `match` は `_` 分岐を持つこと。
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ControlMessage<T> {
    /// 要求。
    Request {
        /// 対応づけ用 ID。
        id: MessageId,
        /// 本体。
        body: T,
    },
    /// 正常応答。
    Response {
        /// 対応する要求の ID。
        id: MessageId,
        /// 本体。
        body: T,
    },
    /// 失敗応答。
    Error {
        /// 対応する要求の ID。
        id: MessageId,
        /// 構造化エラー。
        error: PluginError,
    },
}

// 本体は秘密情報を含みうるため、`Debug` では種別と ID のみ出す（`Frame` と同じ方針）。
impl<T> fmt::Debug for ControlMessage<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (kind, id) = match self {
            Self::Request { id, .. } => ("Request", id),
            Self::Response { id, .. } => ("Response", id),
            Self::Error { id, .. } => ("Error", id),
        };
        f.debug_struct(kind)
            .field("id", &id.get())
            .finish_non_exhaustive()
    }
}

// ---- 符号化側（借用 DTO。struct の Serialize は JSON では常に object になる） ----

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum WireOut<'a, T> {
    Request(EntryOut<'a, T>),
    Response(EntryOut<'a, T>),
    Error(ErrorEntryOut<'a>),
}

#[derive(Serialize)]
struct EntryOut<'a, T> {
    id: MessageId,
    body: &'a T,
}

#[derive(Serialize)]
struct ErrorEntryOut<'a> {
    id: MessageId,
    error: ErrorDtoOut<'a>,
}

#[derive(Serialize)]
struct ErrorDtoOut<'a> {
    code: &'static str,
    message: &'a str,
}

/// 上限つきの書き込み先。上限を超える書き込みは追記前に拒否する（AC2: 上限検証より前に
/// 出力サイズへ比例した確保をしない。保持バッファ長は上限を超えない）。
struct LimitedSink {
    buf: Vec<u8>,
    limit: usize,
    exceeded: bool,
}

impl LimitedSink {
    fn new(limit: usize) -> Self {
        Self {
            buf: Vec::new(),
            limit,
            exceeded: false,
        }
    }
}

impl io::Write for LimitedSink {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let fits = self
            .buf
            .len()
            .checked_add(data.len())
            .is_some_and(|total| total <= self.limit);
        if !fits {
            self.exceeded = true;
            return Err(io::Error::new(io::ErrorKind::WriteZero, "payload limit"));
        }
        self.buf.extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// 制御メッセージを JSON 化して [`Frame`] に載せる。
///
/// 出力が `MAX_PAYLOAD_LEN` を超える場合は `InvalidArgument`、それ以外の符号化失敗
/// （非文字列キーの map 等）は `Internal`。
pub fn encode_message<T: Serialize>(msg: &ControlMessage<T>) -> Result<Frame, PluginError> {
    let mut sink = LimitedSink::new(MAX_PAYLOAD_LEN as usize);
    let result = match msg {
        ControlMessage::Request { id, body } => {
            serde_json::to_writer(&mut sink, &WireOut::Request(EntryOut { id: *id, body }))
        }
        ControlMessage::Response { id, body } => {
            serde_json::to_writer(&mut sink, &WireOut::Response(EntryOut { id: *id, body }))
        }
        ControlMessage::Error { id, error } => serde_json::to_writer(
            &mut sink,
            &WireOut::<()>::Error(ErrorEntryOut {
                id: *id,
                error: ErrorDtoOut {
                    code: error.code().as_str(),
                    message: error.message(),
                },
            }),
        ),
    };
    if result.is_err() {
        return Err(if sink.exceeded {
            PluginError::new(
                PluginErrorCode::InvalidArgument,
                "encoded control message exceeds the maximum payload length",
            )
        } else {
            PluginError::new(
                PluginErrorCode::Internal,
                "failed to encode control message",
            )
        });
    }
    // `Frame::new` の長さ検査は二重の保険（上限はシンクが先に守る）。
    Frame::new(sink.buf)
}

// ---- 復号側（JSON object のみ受理する手書き Deserialize） ----
//
// serde の derive は struct を配列形でも受理する。plugin 入力は untrusted なので、
// `deserialize_map` だけを使い object 以外を拒否する（core の `Obj<T>` と同じ考え方）。

enum WireIn<T> {
    Request(EntryIn<T>),
    Response(EntryIn<T>),
    Error(ErrorEntryIn),
}

struct EntryIn<T> {
    id: MessageId,
    body: T,
}

struct ErrorEntryIn {
    id: MessageId,
    error: ErrorDtoIn,
}

struct ErrorDtoIn {
    code: String,
    message: String,
}

/// 値を 1 つだけ受け取るスロットへ格納する（重複フィールドは拒否）。
fn put<V, E: de::Error>(slot: &mut Option<V>, value: V, name: &'static str) -> Result<(), E> {
    if slot.is_some() {
        return Err(E::duplicate_field(name));
    }
    *slot = Some(value);
    Ok(())
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for EntryIn<T> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V<T>(PhantomData<T>);
        impl<'de, T: Deserialize<'de>> Visitor<'de> for V<T> {
            type Value = EntryIn<T>;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("an object with id and body")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut m: A) -> Result<Self::Value, A::Error> {
                let (mut id, mut body) = (None, None);
                while let Some(key) = m.next_key::<String>()? {
                    match key.as_str() {
                        "id" => put(&mut id, m.next_value::<MessageId>()?, "id")?,
                        "body" => put(&mut body, m.next_value::<T>()?, "body")?,
                        _ => return Err(de::Error::custom("unknown field")),
                    }
                }
                Ok(EntryIn {
                    id: id.ok_or_else(|| de::Error::missing_field("id"))?,
                    body: body.ok_or_else(|| de::Error::missing_field("body"))?,
                })
            }
        }
        d.deserialize_map(V(PhantomData))
    }
}

impl<'de> Deserialize<'de> for ErrorEntryIn {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = ErrorEntryIn;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("an object with id and error")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut m: A) -> Result<Self::Value, A::Error> {
                let (mut id, mut error) = (None, None);
                while let Some(key) = m.next_key::<String>()? {
                    match key.as_str() {
                        "id" => put(&mut id, m.next_value::<MessageId>()?, "id")?,
                        "error" => put(&mut error, m.next_value::<ErrorDtoIn>()?, "error")?,
                        _ => return Err(de::Error::custom("unknown field")),
                    }
                }
                Ok(ErrorEntryIn {
                    id: id.ok_or_else(|| de::Error::missing_field("id"))?,
                    error: error.ok_or_else(|| de::Error::missing_field("error"))?,
                })
            }
        }
        d.deserialize_map(V)
    }
}

impl<'de> Deserialize<'de> for ErrorDtoIn {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = ErrorDtoIn;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("an object with code and message")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut m: A) -> Result<Self::Value, A::Error> {
                let (mut code, mut message) = (None, None);
                while let Some(key) = m.next_key::<String>()? {
                    match key.as_str() {
                        "code" => put(&mut code, m.next_value::<String>()?, "code")?,
                        "message" => put(&mut message, m.next_value::<String>()?, "message")?,
                        _ => return Err(de::Error::custom("unknown field")),
                    }
                }
                Ok(ErrorDtoIn {
                    code: code.ok_or_else(|| de::Error::missing_field("code"))?,
                    message: message.ok_or_else(|| de::Error::missing_field("message"))?,
                })
            }
        }
        d.deserialize_map(V)
    }
}

// externally tagged のエンベロープ。variant 名は snake_case、未知 variant・複数 variant は拒否する。
impl<'de, T: Deserialize<'de>> Deserialize<'de> for WireIn<T> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V<T>(PhantomData<T>);
        impl<'de, T: Deserialize<'de>> Visitor<'de> for V<T> {
            type Value = WireIn<T>;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("an object with exactly one of request, response, error")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut m: A) -> Result<Self::Value, A::Error> {
                let key = m
                    .next_key::<String>()?
                    .ok_or_else(|| de::Error::custom("empty envelope"))?;
                let wire = match key.as_str() {
                    "request" => WireIn::Request(m.next_value()?),
                    "response" => WireIn::Response(m.next_value()?),
                    "error" => WireIn::Error(m.next_value()?),
                    _ => return Err(de::Error::custom("unknown variant")),
                };
                if m.next_key::<String>()?.is_some() {
                    return Err(de::Error::custom("multiple variants"));
                }
                Ok(wire)
            }
        }
        d.deserialize_map(V(PhantomData))
    }
}

/// 検証済み [`Frame`] のペイロードを制御メッセージへ復号する。
///
/// 入力を `&Frame` に限るのは、長さ上限・チェックサム検証済みのペイロードだけを解析対象にして
/// 解析時の確保を上限で頭打ちにするため（生バイト列を受ける公開関数は設けない）。
/// 構文・型・未知フィールド・未知 variant・未知のエラー code・末尾の余剰データ・再帰上限超過は
/// すべて `InvalidArgument`（`DataLoss` はチェックサム専用）。エラー文言に入力断片は載せない。
pub fn decode_message<T: DeserializeOwned>(
    frame: &Frame,
) -> Result<ControlMessage<T>, PluginError> {
    let wire: WireIn<T> = serde_json::from_slice(frame.payload()).map_err(|e| {
        PluginError::new(
            PluginErrorCode::InvalidArgument,
            format!(
                "malformed control message ({:?} error at line {} column {})",
                e.classify(),
                e.line(),
                e.column()
            ),
        )
    })?;
    Ok(match wire {
        WireIn::Request(e) => ControlMessage::Request {
            id: e.id,
            body: e.body,
        },
        WireIn::Response(e) => ControlMessage::Response {
            id: e.id,
            body: e.body,
        },
        WireIn::Error(e) => {
            // 未知の code は fail-closed。受信文字列はメッセージへ載せない。
            let code = PluginErrorCode::from_code_str(&e.error.code).ok_or_else(|| {
                PluginError::new(
                    PluginErrorCode::InvalidArgument,
                    "unknown error code in control message",
                )
            })?;
            ControlMessage::Error {
                id: e.id,
                error: PluginError::new(code, e.error.message),
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::PLUGIN_ERROR_MESSAGE_MAX_BYTES;
    use io::Write;
    use serde_json::{Value, json};

    /// PoC-13 相当の代表操作を模した本体型。
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    enum Body {
        Create { name: String, args: Vec<String> },
        ListImages,
        Images { names: Vec<String> },
    }

    fn frame_of(json: &str) -> Frame {
        Frame::new(json.as_bytes().to_vec()).expect("frame")
    }

    fn decode_err(json: &str) -> PluginError {
        decode_message::<Body>(&frame_of(json)).expect_err("must fail")
    }

    fn roundtrip(msg: ControlMessage<Body>) {
        let frame = encode_message(&msg).expect("encode");
        assert_eq!(decode_message::<Body>(&frame).expect("decode"), msg);
    }

    #[test]
    fn plug2_request_roundtrip() {
        roundtrip(ControlMessage::Request {
            id: MessageId::new(u64::MAX),
            body: Body::Create {
                name: "web \"quoted\" \\ あ\n\u{1F600}".to_string(),
                args: vec!["--rm".to_string(), String::new()],
            },
        });
        roundtrip(ControlMessage::Request {
            id: MessageId::new(0),
            body: Body::ListImages,
        });
    }

    #[test]
    fn plug2_response_roundtrip() {
        for names in [vec![], vec!["a".to_string(), "b".to_string()]] {
            roundtrip(ControlMessage::Response {
                id: MessageId::new(7),
                body: Body::Images { names },
            });
        }
    }

    #[test]
    fn plug2_error_roundtrip() {
        for (code, message) in [
            (PluginErrorCode::NotFound, "no such container"),
            (PluginErrorCode::DataLoss, ""),
        ] {
            roundtrip(ControlMessage::Error {
                id: MessageId::new(3),
                error: PluginError::new(code, message),
            });
        }
    }

    #[test]
    fn plug2_request_wire_json_is_exact() {
        let frame = encode_message(&ControlMessage::Request {
            id: MessageId::new(7),
            body: Body::Create {
                name: "w".to_string(),
                args: vec!["x".to_string()],
            },
        })
        .expect("encode");
        assert_eq!(
            std::str::from_utf8(frame.payload()).expect("utf8"),
            r#"{"request":{"id":7,"body":{"create":{"name":"w","args":["x"]}}}}"#
        );
        let frame = encode_message::<Body>(&ControlMessage::Error {
            id: MessageId::new(7),
            error: PluginError::new(PluginErrorCode::NotFound, "gone"),
        })
        .expect("encode");
        assert_eq!(
            std::str::from_utf8(frame.payload()).expect("utf8"),
            r#"{"error":{"id":7,"error":{"code":"NOT_FOUND","message":"gone"}}}"#
        );
    }

    #[test]
    fn repair2_encode_rejects_payload_over_max() {
        let big = "a".repeat(MAX_PAYLOAD_LEN as usize);
        let e = encode_message(&ControlMessage::Request {
            id: MessageId::new(1),
            body: big,
        })
        .expect_err("must fail");
        assert_eq!(e.code(), PluginErrorCode::InvalidArgument);
    }

    #[test]
    fn repair2_limited_sink_never_holds_more_than_limit() {
        let mut sink = LimitedSink::new(8);
        assert_eq!(sink.write(b"12345678").expect("fits"), 8);
        assert!(sink.write(b"9").is_err());
        assert!(sink.exceeded);
        assert_eq!(sink.buf.len(), 8);

        let mut sink = LimitedSink::new(8);
        assert!(sink.write(b"123456789").is_err());
        assert!(sink.buf.is_empty());
    }

    #[test]
    fn plug2_decode_rejects_malformed_inputs() {
        let cases = [
            "",
            "{",
            "not json",
            r#"{"request":{"id":1,"body":"list_images"}} x"#,
            r#"{"request":{"id":1,"body":"list_images"}}{}"#,
            r#"{"unknown":{"id":1,"body":"list_images"}}"#,
            r#"{"request":{"id":1,"body":"list_images","extra":1}}"#,
            r#"{"request":[1,"list_images"]}"#,
            r#"[{"request":{"id":1,"body":"list_images"}}]"#,
            r#"{"request":{"id":"1","body":"list_images"}}"#,
            r#"{"request":{"id":1}}"#,
            r#"{"request":{"id":1,"id":2,"body":"list_images"}}"#,
            r#"{"request":{"id":1,"body":"nope"}}"#,
            r#"{"request":{"id":1,"body":"list_images"},"response":{"id":1,"body":"list_images"}}"#,
            r#"{}"#,
            r#"{"error":{"id":1,"error":{"code":"WHATEVER","message":"m"}}}"#,
            r#"{"error":{"id":1,"error":["NOT_FOUND","m"]}}"#,
            r#"{"error":{"id":1,"error":{"code":"NOT_FOUND","message":"m","x":1}}}"#,
        ];
        for c in cases {
            assert_eq!(
                decode_err(c).code(),
                PluginErrorCode::InvalidArgument,
                "input: {c}"
            );
        }
    }

    #[test]
    fn plug2_decode_rejects_deep_nesting() {
        let depth = 200;
        let json = format!(
            r#"{{"request":{{"id":1,"body":{}0{}}}}}"#,
            "[".repeat(depth),
            "]".repeat(depth)
        );
        let e = decode_message::<Value>(&frame_of(&json)).expect_err("must fail");
        assert_eq!(e.code(), PluginErrorCode::InvalidArgument);
    }

    #[test]
    fn plug2_decode_error_message_omits_payload() {
        let e = decode_err(r#"{"request":{"id":1,"body":"s3cr3t-token","s3cr3t-field":1}}"#);
        assert!(!e.message().contains("s3cr3t"), "{}", e.message());
        let e = decode_err(r#"{"error":{"id":1,"error":{"code":"s3cr3t","message":"m"}}}"#);
        assert!(!e.message().contains("s3cr3t"), "{}", e.message());
        let e = decode_err(r#"{"s3cr3t":{"id":1,"body":"list_images"}}"#);
        assert!(!e.message().contains("s3cr3t"), "{}", e.message());
    }

    #[test]
    fn plug2_decoded_error_message_is_truncated() {
        let long = "a".repeat(PLUGIN_ERROR_MESSAGE_MAX_BYTES + 100);
        let json = json!({"error": {"id": 1, "error": {"code": "INTERNAL", "message": long}}});
        let msg = decode_message::<Body>(&frame_of(&json.to_string())).expect("decode");
        match msg {
            ControlMessage::Error { error, .. } => {
                assert_eq!(error.message().len(), 4096);
                assert_eq!(error.code(), PluginErrorCode::Internal);
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn plug2_control_message_debug_omits_body() {
        let msg = ControlMessage::Request {
            id: MessageId::new(9),
            body: "s3cr3t".to_string(),
        };
        let dbg = format!("{msg:?}");
        assert!(!dbg.contains("s3cr3t"), "{dbg}");
        assert!(dbg.contains("Request") && dbg.contains('9'), "{dbg}");
    }
}
