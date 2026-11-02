//! k8s の remotecommand サブプロトコル（`*.channel.k8s.io`）の交渉と、ストリームの割り当て（CRI-6・TASK-63.3・#681）。
//!
//! kubelet / crictl は `Attach`・`Exec` の URL へ `Upgrade: SPDY/3.1` と `X-Stream-Protocol-Version` を付けて
//! 接続し、101 の後に SPDY のストリームを `streamtype` ヘッダで error / stdin / stdout / stderr / resize として
//! 開く。本モジュールは HTTP 層の交渉（[`negotiate`]・[`upgrade_response`]）、ストリームの種別
//! （[`StreamType`]）、error ストリームへ書く `metav1.Status` の JSON（[`status_success`]・[`status_failure`]）、
//! resize の JSON の読み取り（[`ResizeParser`]）を持つ純粋な部品で、IO は持たない。呼び出し元は
//! `streaming::attach`（Attach）と、将来の Exec（#680）。SPDY のフレームは `streaming::spdy` が扱う。
//!
//! ## 対応するサブプロトコル
//!
//! `v4.channel.k8s.io`（error ストリームが JSON の `metav1.Status`）・`v3.channel.k8s.io`（resize を足す。
//! error ストリームは失敗時のメッセージのみ）・`v2.channel.k8s.io`（resize なし）。無改変の v1
//! （`channel.k8s.io`。既知の不具合つき）と WebSocket（`v5.channel.k8s.io` 等）は扱わない（#678 の判断）。
//! 一次情報: kubernetes/kubernetes の `staging/src/k8s.io/apimachinery/pkg/util/remotecommand/constants.go`・
//! `cri-streaming/pkg/streaming/remotecommand/httpstream.go`・`apimachinery/.../httpstream/httpstream.go`
//! （2026-11-02 に master を確認）。

use std::time::Duration;

use hyper::header::{CONNECTION, HeaderMap, HeaderName, HeaderValue, UPGRADE};
use hyper::{Response, StatusCode};
use serde::Deserialize;

use super::{StreamBody, plain_response};
use crate::error::{CriError, CriErrorCode};

/// 対応する Upgrade 先（SPDY/3.1）。
pub const UPGRADE_SPDY: &str = "SPDY/3.1";
/// クライアントが提示するサブプロトコル一覧のヘッダ名。
const HEADER_PROTOCOL_VERSION: &str = "x-stream-protocol-version";
/// 合意できなかったときに対応版を知らせるヘッダ名。
const HEADER_ACCEPTED_VERSIONS: &str = "x-accepted-stream-protocol-versions";
/// ストリームの種別を載せる SPDY ヘッダ名（小文字化済み。k8s では `streamType`）。
pub const HEADER_STREAM_TYPE: &str = "streamtype";
/// `X-Stream-Protocol-Version` の値の最大件数（提示の列挙を無制限に走査しない）。
const MAX_OFFERED_PROTOCOLS: usize = 32;
/// resize の JSON を溜める最大バイト数。
const MAX_RESIZE_BUFFER: usize = 4 * 1024;

/// `stream_creation_timeout` の上限。
pub const MAX_STREAM_CREATION_TIMEOUT: Duration = Duration::from_secs(300);
/// `stream_idle_timeout` の上限。
pub const MAX_STREAM_IDLE_TIMEOUT: Duration = Duration::from_secs(24 * 60 * 60);

/// `backend_timeout`・`drain_timeout`・`close_timeout` の上限。`Instant` への加算のオーバーフローも防ぐ。
pub const MAX_SESSION_STEP_TIMEOUT: Duration = Duration::from_secs(10 * 60);

/// Upgrade 後のセッションの期限（REPAIR-5）。`StreamingConfig` が既定値と検証を持ち、ハンドラへ渡す。
///
/// Attach は長時間 idle になり得る（シェルを開いたまま放置する）ため、idle の既定は kubelet と同じ 4 時間とする。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionLimits {
    /// 必要なストリームが揃うまでの期限。既定は 30 秒（kubelet の `DefaultStreamCreationTimeout`）。
    pub stream_creation_timeout: Duration,
    /// どちら向きにもフレームが流れない期間の上限。既定は 4 時間（kubelet の `StreamIdleTimeout`）。
    pub stream_idle_timeout: Duration,
    /// バックエンドへの接続（`AttachBackend::attach`）の期限。既定は 10 秒。
    pub backend_timeout: Duration,
    /// コンテナ終了後に残りの出力を流し切る期限。既定は 5 秒。
    pub drain_timeout: Duration,
    /// 終了時の最後の送出（Status・GOAWAY）の期限。既定は 5 秒。
    pub close_timeout: Duration,
}

impl Default for SessionLimits {
    fn default() -> Self {
        Self {
            stream_creation_timeout: Duration::from_secs(30),
            stream_idle_timeout: Duration::from_secs(4 * 60 * 60),
            backend_timeout: Duration::from_secs(10),
            drain_timeout: Duration::from_secs(5),
            close_timeout: Duration::from_secs(5),
        }
    }
}

impl SessionLimits {
    /// 期限を検証する（0 と過大な値は拒否。fail-closed）。
    pub fn validate(&self) -> Result<(), CriError> {
        if self.stream_creation_timeout.is_zero()
            || self.stream_creation_timeout > MAX_STREAM_CREATION_TIMEOUT
        {
            return Err(CriError::invalid_argument(
                "streaming stream_creation_timeout must be between 1ns and 300s",
            ));
        }
        if self.stream_idle_timeout.is_zero() || self.stream_idle_timeout > MAX_STREAM_IDLE_TIMEOUT
        {
            return Err(CriError::invalid_argument(
                "streaming stream_idle_timeout must be between 1ns and 24h",
            ));
        }
        if self.backend_timeout.is_zero()
            || self.drain_timeout.is_zero()
            || self.close_timeout.is_zero()
            || self.backend_timeout > MAX_SESSION_STEP_TIMEOUT
            || self.drain_timeout > MAX_SESSION_STEP_TIMEOUT
            || self.close_timeout > MAX_SESSION_STEP_TIMEOUT
        {
            return Err(CriError::invalid_argument(
                "streaming backend, drain and close timeouts must be between 1ns and 600s",
            ));
        }
        Ok(())
    }
}

/// remotecommand のサブプロトコルの版。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    /// `v4.channel.k8s.io`。error ストリームは JSON の `metav1.Status`。
    V4,
    /// `v3.channel.k8s.io`。resize に対応。error ストリームは失敗時のメッセージのみ。
    V3,
    /// `v2.channel.k8s.io`。resize なし。
    V2,
}

impl Protocol {
    /// サーバーの優先順（kubelet の `SupportedStreamingProtocols` と同じく新しい版が先）。
    pub const SUPPORTED: [Protocol; 3] = [Protocol::V4, Protocol::V3, Protocol::V2];

    /// ヘッダに載せる名前。
    pub fn name(self) -> &'static str {
        match self {
            Protocol::V4 => "v4.channel.k8s.io",
            Protocol::V3 => "v3.channel.k8s.io",
            Protocol::V2 => "v2.channel.k8s.io",
        }
    }

    /// resize ストリームに対応する版か。
    pub fn supports_resize(self) -> bool {
        matches!(self, Protocol::V4 | Protocol::V3)
    }

    fn from_name(name: &str) -> Option<Self> {
        Self::SUPPORTED.into_iter().find(|p| p.name() == name)
    }
}

/// 交渉の失敗。HTTP の応答に変換する（[`Self::into_response`]）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeError {
    /// `X-Stream-Protocol-Version` が無い・空（400）。
    MissingProtocolVersion,
    /// 提示された版にサーバーが対応するものが無い（403。対応版を知らせる）。
    NoCommonProtocol,
    /// `Connection: Upgrade` と `Upgrade: SPDY/3.1` が揃っていない（400）。
    MissingUpgradeHeaders,
}

impl HandshakeError {
    /// 失敗に対応する HTTP 応答。本文は固定の英語で、入力値を含めない。
    pub fn into_response(self) -> Response<StreamBody> {
        match self {
            HandshakeError::MissingProtocolVersion => plain_response(
                StatusCode::BAD_REQUEST,
                "unable to upgrade: missing stream protocol version",
            ),
            HandshakeError::MissingUpgradeHeaders => plain_response(
                StatusCode::BAD_REQUEST,
                "unable to upgrade: missing upgrade headers",
            ),
            HandshakeError::NoCommonProtocol => {
                let mut response = plain_response(
                    StatusCode::FORBIDDEN,
                    "unable to upgrade: unable to negotiate protocol",
                );
                let name = HeaderName::from_static(HEADER_ACCEPTED_VERSIONS);
                for protocol in Protocol::SUPPORTED {
                    response
                        .headers_mut()
                        .append(name.clone(), HeaderValue::from_static(protocol.name()));
                }
                response
            }
        }
    }
}

fn header_has_token(headers: &HeaderMap, name: HeaderName, token: &str) -> bool {
    headers
        .get_all(name)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .any(|v| v.to_ascii_lowercase().contains(token))
}

/// クライアントの要求ヘッダからサブプロトコルを選ぶ（kubelet の `Handshake` → `UpgradeResponse` の順に合わせる）。
///
/// 1. `X-Stream-Protocol-Version` が無い・空なら 400。クライアントの提示順に、サーバーが対応する最初の版を選ぶ
/// 2. 合う版が無ければ 403 と `X-Accepted-Stream-Protocol-Versions`
/// 3. `Connection` に `upgrade`、`Upgrade` に `spdy/3.1` が無ければ 400
pub fn negotiate(headers: &HeaderMap) -> Result<Protocol, HandshakeError> {
    let name = HeaderName::from_static(HEADER_PROTOCOL_VERSION);
    let offered: Vec<&str> = headers
        .get_all(&name)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .take(MAX_OFFERED_PROTOCOLS)
        .collect();
    if offered.is_empty() {
        return Err(HandshakeError::MissingProtocolVersion);
    }
    let protocol = offered
        .iter()
        .find_map(|offer| Protocol::from_name(offer))
        .ok_or(HandshakeError::NoCommonProtocol)?;
    if !header_has_token(headers, CONNECTION, "upgrade")
        || !header_has_token(headers, UPGRADE, "spdy/3.1")
    {
        return Err(HandshakeError::MissingUpgradeHeaders);
    }
    Ok(protocol)
}

/// 交渉に成功したときの `101 Switching Protocols`。選んだ版をエコーする。
pub fn upgrade_response(protocol: Protocol) -> Response<StreamBody> {
    let mut response = Response::new(StreamBody::empty());
    *response.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
    let headers = response.headers_mut();
    headers.insert(CONNECTION, HeaderValue::from_static("Upgrade"));
    headers.insert(UPGRADE, HeaderValue::from_static(UPGRADE_SPDY));
    headers.insert(
        HeaderName::from_static(HEADER_PROTOCOL_VERSION),
        HeaderValue::from_static(protocol.name()),
    );
    response
}

/// SPDY ストリームの用途（`streamtype` ヘッダの値）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StreamType {
    /// `error`。終了時に Status を書く。
    Error,
    /// `stdin`。クライアントからコンテナへ。
    Stdin,
    /// `stdout`。
    Stdout,
    /// `stderr`。
    Stderr,
    /// `resize`（tty のとき、v3 以降）。
    Resize,
}

impl StreamType {
    /// `streamtype` ヘッダの値から。未知の値は `None`。
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "error" => Some(StreamType::Error),
            "stdin" => Some(StreamType::Stdin),
            "stdout" => Some(StreamType::Stdout),
            "stderr" => Some(StreamType::Stderr),
            "resize" => Some(StreamType::Resize),
            _ => None,
        }
    }
}

/// Attach / Exec が要求するストリームの組。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamOptions {
    /// stdin を流すか。
    pub stdin: bool,
    /// stdout を流すか。
    pub stdout: bool,
    /// stderr を流すか（tty のときは常に false に正規化済み。kubelet の `NewOptions` と同じ）。
    pub stderr: bool,
    /// tty か。
    pub tty: bool,
}

impl StreamOptions {
    /// 要求の値から作る。tty のとき stderr は stdout に合流するため false にする。
    pub fn new(stdin: bool, stdout: bool, stderr: bool, tty: bool) -> Self {
        Self {
            stdin,
            stdout,
            stderr: stderr && !tty,
            tty,
        }
    }

    /// この版で、クライアントが開くべき種別（error は常に必要）。
    pub fn expected(&self, protocol: Protocol) -> Vec<StreamType> {
        let mut out = vec![StreamType::Error];
        if self.stdin {
            out.push(StreamType::Stdin);
        }
        if self.stdout {
            out.push(StreamType::Stdout);
        }
        if self.stderr {
            out.push(StreamType::Stderr);
        }
        if self.tty && protocol.supports_resize() {
            out.push(StreamType::Resize);
        }
        out
    }
}

/// resize の寸法（kubelet の `TerminalSize`。JSON のキーは `Width`・`Height`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub struct TerminalSize {
    /// 桁数。
    #[serde(rename = "Width")]
    pub width: u16,
    /// 行数。
    #[serde(rename = "Height")]
    pub height: u16,
}

/// resize ストリームの JSON（連続した値）を、フレーム境界に依らず読み取る。
#[derive(Debug, Default)]
pub struct ResizeParser {
    buf: Vec<u8>,
}

/// resize の読み取りの失敗（不正な JSON・過大な滞留）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResizeError;

impl ResizeParser {
    /// 空の読み取り器。
    pub fn new() -> Self {
        Self::default()
    }

    /// バイトを足し、完成した値を順に返す。未完の末尾は次回へ持ち越す。
    pub fn push(&mut self, data: &[u8]) -> Result<Vec<TerminalSize>, ResizeError> {
        if self.buf.len().saturating_add(data.len()) > MAX_RESIZE_BUFFER {
            return Err(ResizeError);
        }
        self.buf.extend_from_slice(data);
        let mut sizes = Vec::new();
        let consumed = {
            let mut stream =
                serde_json::Deserializer::from_slice(&self.buf).into_iter::<TerminalSize>();
            loop {
                match stream.next() {
                    Some(Ok(size)) => sizes.push(size),
                    // 未完の末尾。次の push で続きを読む。
                    Some(Err(e)) if e.is_eof() => break,
                    Some(Err(_)) => return Err(ResizeError),
                    None => break,
                }
            }
            stream.byte_offset()
        };
        self.buf.drain(..consumed.min(self.buf.len()));
        Ok(sizes)
    }
}

/// error ストリームへ書く、成功の Status。v4 は JSON、v3・v2 は成功時に何も書かない（kubelet と同じ）。
pub fn status_success(protocol: Protocol) -> Option<Vec<u8>> {
    match protocol {
        Protocol::V4 => Some(br#"{"metadata":{},"status":"Success"}"#.to_vec()),
        Protocol::V3 | Protocol::V2 => None,
    }
}

/// 失敗の Status の固定メッセージ。入力 ID・内部パスを含めない（コード別の固定文）。
fn failure_parts(code: CriErrorCode) -> (&'static str, &'static str, u16) {
    match code {
        CriErrorCode::InvalidArgument => (
            "error attaching to container: invalid argument",
            "BadRequest",
            400,
        ),
        CriErrorCode::NotFound => (
            "error attaching to container: container not found",
            "NotFound",
            404,
        ),
        CriErrorCode::FailedPrecondition => (
            "error attaching to container: container is not running",
            "Conflict",
            409,
        ),
        CriErrorCode::AlreadyExists => (
            "error attaching to container: already exists",
            "AlreadyExists",
            409,
        ),
        CriErrorCode::PermissionDenied => (
            "error attaching to container: permission denied",
            "Forbidden",
            403,
        ),
        CriErrorCode::ResourceExhausted => (
            "error attaching to container: resource exhausted",
            "TooManyRequests",
            429,
        ),
        CriErrorCode::Unavailable => (
            "error attaching to container: service unavailable",
            "ServiceUnavailable",
            503,
        ),
        CriErrorCode::Timeout => ("error attaching to container: timed out", "Timeout", 504),
        CriErrorCode::Unimplemented | CriErrorCode::DataLoss | CriErrorCode::Internal => (
            "error attaching to container: internal error",
            "InternalError",
            500,
        ),
    }
}

/// error ストリームへ書く、失敗の Status。v4 は JSON、v3・v2 はメッセージのテキスト。
pub fn status_failure(protocol: Protocol, error: &CriError) -> Vec<u8> {
    let (message, reason, code) = failure_parts(error.code());
    match protocol {
        Protocol::V4 => serde_json::json!({
            "metadata": {},
            "status": "Failure",
            "message": message,
            "reason": reason,
            "code": code,
        })
        .to_string()
        .into_bytes(),
        Protocol::V3 | Protocol::V2 => message.as_bytes().to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (n, v) in pairs {
            h.append(HeaderName::from_static(n), HeaderValue::from_static(v));
        }
        h
    }

    fn upgrade_headers(offer: &'static str) -> HeaderMap {
        headers(&[
            ("connection", "Upgrade"),
            ("upgrade", "SPDY/3.1"),
            ("x-stream-protocol-version", offer),
        ])
    }

    #[test]
    fn cri6_remotecommand_prefers_clients_first_supported_protocol() {
        let h = upgrade_headers("v4.channel.k8s.io, v3.channel.k8s.io, v2.channel.k8s.io");
        assert_eq!(negotiate(&h), Ok(Protocol::V4));
        let h = upgrade_headers("channel.k8s.io, v3.channel.k8s.io");
        assert_eq!(negotiate(&h), Ok(Protocol::V3));
        let h = upgrade_headers("v2.channel.k8s.io,v4.channel.k8s.io");
        assert_eq!(negotiate(&h), Ok(Protocol::V2));
    }

    #[test]
    fn cri6_remotecommand_rejects_unmatched_protocols_with_403_and_supported_list() {
        let h = upgrade_headers("channel.k8s.io, v5.channel.k8s.io");
        assert_eq!(negotiate(&h), Err(HandshakeError::NoCommonProtocol));
        let response = HandshakeError::NoCommonProtocol.into_response();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let accepted: Vec<&str> = response
            .headers()
            .get_all(HEADER_ACCEPTED_VERSIONS)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .collect();
        assert_eq!(
            accepted,
            [
                "v4.channel.k8s.io",
                "v3.channel.k8s.io",
                "v2.channel.k8s.io"
            ]
        );
    }

    #[test]
    fn cri6_remotecommand_rejects_missing_headers_with_400() {
        let h = headers(&[("connection", "Upgrade"), ("upgrade", "SPDY/3.1")]);
        assert_eq!(negotiate(&h), Err(HandshakeError::MissingProtocolVersion));
        let h = headers(&[("x-stream-protocol-version", "v4.channel.k8s.io")]);
        assert_eq!(negotiate(&h), Err(HandshakeError::MissingUpgradeHeaders));
        let h = headers(&[
            ("connection", "keep-alive"),
            ("upgrade", "SPDY/3.1"),
            ("x-stream-protocol-version", "v4.channel.k8s.io"),
        ]);
        assert_eq!(negotiate(&h), Err(HandshakeError::MissingUpgradeHeaders));
        let h = headers(&[
            ("connection", "Upgrade"),
            ("upgrade", "websocket"),
            ("x-stream-protocol-version", "v4.channel.k8s.io"),
        ]);
        assert_eq!(negotiate(&h), Err(HandshakeError::MissingUpgradeHeaders));
        assert_eq!(
            HandshakeError::MissingProtocolVersion
                .into_response()
                .status(),
            StatusCode::BAD_REQUEST
        );
    }

    #[test]
    fn cri6_remotecommand_upgrade_response_echoes_protocol() {
        let r = upgrade_response(Protocol::V3);
        assert_eq!(r.status(), StatusCode::SWITCHING_PROTOCOLS);
        assert_eq!(
            r.headers().get("upgrade").map(HeaderValue::as_bytes),
            Some(&b"SPDY/3.1"[..])
        );
        assert_eq!(
            r.headers()
                .get("x-stream-protocol-version")
                .map(HeaderValue::as_bytes),
            Some(&b"v3.channel.k8s.io"[..])
        );
    }

    #[test]
    fn cri6_remotecommand_expected_streams_follow_options_and_version() {
        let o = StreamOptions::new(true, true, true, false);
        assert_eq!(
            o.expected(Protocol::V4),
            [
                StreamType::Error,
                StreamType::Stdin,
                StreamType::Stdout,
                StreamType::Stderr
            ]
        );
        // tty では stderr を要求しない。resize は v3 以降だけ。
        let o = StreamOptions::new(true, true, true, true);
        assert!(!o.stderr);
        assert_eq!(
            o.expected(Protocol::V4),
            [
                StreamType::Error,
                StreamType::Stdin,
                StreamType::Stdout,
                StreamType::Resize
            ]
        );
        assert_eq!(
            o.expected(Protocol::V2),
            [StreamType::Error, StreamType::Stdin, StreamType::Stdout]
        );
    }

    #[test]
    fn cri6_remotecommand_stream_type_parse() {
        assert_eq!(StreamType::parse("resize"), Some(StreamType::Resize));
        assert_eq!(StreamType::parse("Stdout"), None);
        assert_eq!(StreamType::parse(""), None);
    }

    #[test]
    fn cri6_remotecommand_status_json_exact() {
        assert_eq!(
            status_success(Protocol::V4).as_deref(),
            Some(&br#"{"metadata":{},"status":"Success"}"#[..])
        );
        assert_eq!(status_success(Protocol::V3), None);
        let err = CriError::failed_precondition("container secret-id is not running");
        let v4 = String::from_utf8(status_failure(Protocol::V4, &err)).expect("utf8");
        let value: serde_json::Value = serde_json::from_str(&v4).expect("json");
        assert_eq!(
            value,
            serde_json::json!({
                "metadata": {},
                "status": "Failure",
                "message": "error attaching to container: container is not running",
                "reason": "Conflict",
                "code": 409,
            })
        );
        assert!(!v4.contains("secret-id"));
        assert_eq!(
            status_failure(Protocol::V3, &err),
            b"error attaching to container: container is not running"
        );
    }

    #[test]
    fn cri6_remotecommand_resize_parser_handles_split_and_batched_values() {
        let mut p = ResizeParser::new();
        assert_eq!(p.push(br#"{"Width":80,"He"#), Ok(vec![]));
        assert_eq!(
            p.push(br#"ight":24}{"Width":132,"Height":43}"#),
            Ok(vec![
                TerminalSize {
                    width: 80,
                    height: 24
                },
                TerminalSize {
                    width: 132,
                    height: 43
                }
            ])
        );
        assert_eq!(p.push(b""), Ok(vec![]));
    }

    #[test]
    fn cri6_remotecommand_resize_parser_rejects_garbage_and_overflow() {
        assert_eq!(ResizeParser::new().push(b"not json"), Err(ResizeError));
        assert_eq!(
            ResizeParser::new().push(br#"{"Width":70000,"Height":1}"#),
            Err(ResizeError)
        );
        let mut p = ResizeParser::new();
        assert_eq!(p.push(&vec![b' '; MAX_RESIZE_BUFFER + 1]), Err(ResizeError));
    }

    /// CRI-6: backend・drain・close の期限は上限を超えると拒否する（`Duration::MAX` での加算 panic を防ぐ）。
    #[test]
    fn cri6_session_limits_reject_oversized_step_timeouts() {
        let base = SessionLimits::default();
        base.validate().expect("default");
        for limits in [
            SessionLimits {
                backend_timeout: Duration::MAX,
                ..base
            },
            SessionLimits {
                drain_timeout: Duration::MAX,
                ..base
            },
            SessionLimits {
                close_timeout: MAX_SESSION_STEP_TIMEOUT + Duration::from_nanos(1),
                ..base
            },
        ] {
            assert!(limits.validate().is_err());
        }
        SessionLimits {
            drain_timeout: MAX_SESSION_STEP_TIMEOUT,
            ..base
        }
        .validate()
        .expect("boundary");
    }
}
