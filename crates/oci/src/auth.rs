//! 匿名トークン取得の純粋な部分: `WWW-Authenticate` の解析・`realm` の検証・トークン応答のパース
//! （TASK-51.2・OCI-1）。
//!
//! 通信は行わない。`registry` モジュールの `RegistryClient::authenticate_anonymous` が 401 チャレンジの
//! ヘッダ値と、トークンエンドポイントの応答本文をここへ渡し、得た `RegistryAuth` を後続の manifest 取得
//! （#402）・blob 取得（#403）が `Authorization` ヘッダに載せる。判定を純関数へ寄せているのは、ネットワーク
//! なしで具体値のテストを書けるようにするため（REPAIR-12）。
//!
//! 入力はすべて非信頼（レジストリ応答）として扱う。長さ・件数を先に上限検証し、`unwrap` や添字アクセスを
//! 使わない（coding-rust.md）。`realm` は接続先を決めるため SSRF の入口になる。`TokenRealm` に検証を閉じ
//! 込め、不正な値を表現できないようにする（REPAIR-2）。
//!
//! 未実装（将来仕様）: Basic / OAuth2 など資格情報つき認証（OCI-3）、トークンのキャッシュと失効時の再取得。
//! 本モジュールは資格情報を一切扱わない。

use crate::error::{OciError, OciErrorCode};
use crate::reference::RegistryHost;
use serde::Deserialize;
use std::fmt;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// `WWW-Authenticate` ヘッダ値 1 件の最大バイト数。
const CHALLENGE_HEADER_MAX_BYTES: usize = 4096;
/// `WWW-Authenticate` ヘッダ値（全件）の合計最大バイト数。
const CHALLENGE_TOTAL_MAX_BYTES: usize = 8192;
/// 解析する `WWW-Authenticate` ヘッダ値の最大件数。
const CHALLENGE_MAX_HEADERS: usize = 8;
/// 1 チャレンジあたりのパラメータ最大数。
const CHALLENGE_MAX_PARAMS: usize = 16;
/// 1 ヘッダ値内のチャレンジ最大数。
const CHALLENGE_MAX_PER_HEADER: usize = 8;
/// `realm` URL の最大バイト数。
const REALM_MAX_BYTES: usize = 2048;
/// `service` の最大バイト数。
const SERVICE_MAX_BYTES: usize = 256;
/// トークン文字列の最大バイト数。
const TOKEN_MAX_BYTES: usize = 16 * 1024;
/// `expires_in` 省略時の有効秒数（Distribution Token spec の既定）。
const DEFAULT_EXPIRES_SECS: u64 = 60;
/// `expires_in` の上限秒数（巨大値を丸める）。
const MAX_EXPIRES_SECS: u64 = 3600;

fn data_loss(message: &str) -> OciError {
    OciError::new(OciErrorCode::DataLoss, message)
}

/// トークンエンドポイントの URL（`https://host[:port]/path`。query・fragment を持たない）。
///
/// レジストリ応答由来の非信頼値のため、生成時に次を検証する: `https://` 固定・userinfo / IPv6 リテラル
/// 不可（`RegistryHost::parse`）・IP リテラルと単一ラベル名（`localhost` 等）の拒否・path の文字種制限
/// （`..` 成分・`?`・`#`・`%` 不可）。ただし接続先レジストリ自身のホストと一致する場合は許可する。
/// **名前ベースの最小防御**であり、DNS 解決後にプライベート IP を指すホスト名は防げない（ureq の範囲外。
/// 接続先 IP の検査は将来課題）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TokenRealm(String);

impl TokenRealm {
    /// `realm` を検証して作る。`registry` はこの realm を提示したレジストリのホスト。
    pub(crate) fn parse(realm: &str, registry: &RegistryHost) -> Result<Self, OciError> {
        let bad = |m: &str| data_loss(m);
        if realm.is_empty() || realm.len() > REALM_MAX_BYTES {
            return Err(bad("invalid token realm length"));
        }
        let rest = realm
            .strip_prefix("https://")
            .ok_or_else(|| bad("token realm must use https"))?;
        let (authority, path) = match rest.find('/') {
            Some(i) => (rest.get(..i).unwrap_or(""), rest.get(i..).unwrap_or("")),
            None => (rest, ""),
        };
        let host = RegistryHost::parse(authority).map_err(|_| bad("invalid token realm host"))?;
        if host != *registry {
            let last_label = host.host().rsplit('.').next().unwrap_or("");
            let numeric_tail =
                !last_label.is_empty() && last_label.bytes().all(|b| b.is_ascii_digit());
            if numeric_tail || !host.host().contains('.') || host.host().ends_with(".localhost") {
                return Err(bad("token realm host is not allowed"));
            }
        }
        if !path.is_empty() {
            let allowed =
                |b: u8| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'~' | b'/' | b'-');
            if !path.bytes().all(allowed) {
                return Err(bad("invalid token realm path"));
            }
            // 先頭の '/' の後ろの成分。`.` / `..` と空成分（`//`）は拒否する。
            let comps = path.get(1..).unwrap_or("");
            if comps.split('/').any(|c| c == "." || c == "..") || path.contains("//") {
                return Err(bad("invalid token realm path"));
            }
        }
        Ok(Self(format!("https://{}{}", host.authority(), path)))
    }

    /// 検証済みの URL 文字列。
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

/// 解析済みの Bearer チャレンジ。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BearerChallenge {
    pub(crate) realm: TokenRealm,
    pub(crate) service: Option<String>,
}

struct RawChallenge {
    scheme: String,
    params: Vec<(String, String)>,
}

fn is_token_byte(b: u8) -> bool {
    b.is_ascii_graphic() && !matches!(b, b'=' | b',' | b'"')
}

/// 1 ヘッダ値を `auth-scheme #auth-param` の列へ分解する（RFC 7235）。
fn split_challenges(value: &str) -> Result<Vec<RawChallenge>, OciError> {
    if value.len() > CHALLENGE_HEADER_MAX_BYTES {
        return Err(OciError::new(
            OciErrorCode::ResourceExhausted,
            "www-authenticate header is too long",
        ));
    }
    if !value
        .bytes()
        .all(|b| b == b' ' || b == b'\t' || b.is_ascii_graphic())
    {
        return Err(data_loss("invalid characters in www-authenticate"));
    }
    let b = value.as_bytes();
    let mut i = 0usize;
    let mut out: Vec<RawChallenge> = Vec::new();
    loop {
        while matches!(b.get(i), Some(b' ' | b'\t' | b',')) {
            i += 1;
        }
        if i >= b.len() {
            break;
        }
        let start = i;
        while b.get(i).copied().is_some_and(is_token_byte) {
            i += 1;
        }
        if i == start {
            return Err(data_loss("malformed www-authenticate"));
        }
        let token = value.get(start..i).unwrap_or("").to_string();
        while matches!(b.get(i), Some(b' ' | b'\t')) {
            i += 1;
        }
        if b.get(i) != Some(&b'=') {
            if out.len() >= CHALLENGE_MAX_PER_HEADER {
                return Err(OciError::new(
                    OciErrorCode::ResourceExhausted,
                    "too many authentication challenges",
                ));
            }
            out.push(RawChallenge {
                scheme: token,
                params: Vec::new(),
            });
            continue;
        }
        i += 1;
        while matches!(b.get(i), Some(b' ' | b'\t')) {
            i += 1;
        }
        let mut val = Vec::new();
        if b.get(i) == Some(&b'"') {
            i += 1;
            loop {
                match b.get(i) {
                    None => return Err(data_loss("unterminated quoted string")),
                    Some(b'"') => {
                        i += 1;
                        break;
                    }
                    Some(b'\\') => {
                        let Some(&n) = b.get(i + 1) else {
                            return Err(data_loss("unterminated quoted string"));
                        };
                        val.push(n);
                        i += 2;
                    }
                    Some(&c) => {
                        val.push(c);
                        i += 1;
                    }
                }
            }
        } else {
            while let Some(&c) = b.get(i) {
                if !is_token_byte(c) {
                    break;
                }
                val.push(c);
                i += 1;
            }
        }
        let val = String::from_utf8(val).map_err(|_| data_loss("invalid www-authenticate"))?;
        let Some(cur) = out.last_mut() else {
            return Err(data_loss("authentication parameter without scheme"));
        };
        if cur.params.len() >= CHALLENGE_MAX_PARAMS {
            return Err(OciError::new(
                OciErrorCode::ResourceExhausted,
                "too many authentication parameters",
            ));
        }
        cur.params.push((token.to_ascii_lowercase(), val));
    }
    Ok(out)
}

/// 401 応答の `WWW-Authenticate` ヘッダ値群から、最初の Bearer チャレンジを取り出す（OCI-1）。
///
/// Bearer が無く Basic のみなら `Unimplemented`（資格情報つき認証は OCI-3 で未実装）。チャレンジの
/// `scope` は無視する（スコープは検証済み `Repository` から呼び出し側が組み立てる）。
pub(crate) fn parse_www_authenticate(
    values: &[&str],
    registry: &RegistryHost,
) -> Result<BearerChallenge, OciError> {
    if values.len() > CHALLENGE_MAX_HEADERS
        || values.iter().map(|v| v.len()).sum::<usize>() > CHALLENGE_TOTAL_MAX_BYTES
    {
        return Err(OciError::new(
            OciErrorCode::ResourceExhausted,
            "www-authenticate headers are too large",
        ));
    }
    let mut saw_other = false;
    for v in values {
        for ch in split_challenges(v)? {
            if !ch.scheme.eq_ignore_ascii_case("bearer") {
                saw_other = true;
                continue;
            }
            let get = |k: &str| {
                ch.params
                    .iter()
                    .find(|(n, _)| n == k)
                    .map(|(_, v)| v.as_str())
            };
            let Some(realm) = get("realm").filter(|r| !r.is_empty()) else {
                return Err(data_loss("bearer challenge has no realm"));
            };
            let realm = TokenRealm::parse(realm, registry)?;
            let service = match get("service") {
                None | Some("") => None,
                Some(s) => {
                    if s.len() > SERVICE_MAX_BYTES {
                        return Err(data_loss("token service is too long"));
                    }
                    Some(s.to_string())
                }
            };
            return Ok(BearerChallenge { realm, service });
        }
    }
    if saw_other {
        Err(OciError::new(
            OciErrorCode::Unimplemented,
            "basic authentication is not supported yet (OCI-3)",
        ))
    } else {
        Err(data_loss("no authentication challenge in 401 response"))
    }
}

/// 取得した Bearer トークン。値は `Debug` に出さず、`Display` も持たない（security.md）。
#[derive(Clone)]
pub struct BearerToken {
    value: String,
    expires_at: Instant,
}

impl BearerToken {
    /// `Authorization` ヘッダ値（`Bearer <token>`）。#402 / #403 が使う。
    #[allow(dead_code)]
    pub(crate) fn authorization_header_value(&self) -> String {
        format!("Bearer {}", self.value)
    }

    /// 有効期限を過ぎていれば true。
    pub fn is_expired(&self, now: Instant) -> bool {
        now >= self.expires_at
    }
}

impl fmt::Debug for BearerToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BearerToken(<redacted>)")
    }
}

/// レジストリへの認証状態（OCI-1）。将来 Basic / OAuth2 の変種を足すため `non_exhaustive`（OCI-3）。
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum RegistryAuth {
    /// 認証不要（`/v2/` が 200 を返した）。
    None,
    /// 匿名 Bearer トークン。
    Bearer(BearerToken),
}

#[derive(Deserialize)]
struct TokenResponse {
    token: Option<String>,
    access_token: Option<String>,
    expires_in: Option<u64>,
    issued_at: Option<String>,
}

/// RFC 3339 の日時（`2026-01-02T03:04:05[.frac](Z|±HH:MM)`）を UNIX 秒へ変換する。
/// 形式が不正・1970 年より前・範囲外なら `None`（非信頼値のため寛容に解釈せず、失敗は呼び出し側で保守側へ倒す）。
fn parse_rfc3339_unix_secs(s: &str) -> Option<u64> {
    let b = s.as_bytes();
    if b.len() < 20 || b.len() > 40 {
        return None;
    }
    let num = |from: usize, to: usize| -> Option<i64> {
        let part = b.get(from..to)?;
        if !part.iter().all(u8::is_ascii_digit) {
            return None;
        }
        std::str::from_utf8(part).ok()?.parse().ok()
    };
    let sep = |i: usize, c: u8| b.get(i).copied() == Some(c);
    if !(sep(4, b'-')
        && sep(7, b'-')
        && (sep(10, b'T') || sep(10, b't'))
        && sep(13, b':')
        && sep(16, b':'))
    {
        return None;
    }
    let (y, mo, d) = (num(0, 4)?, num(5, 7)?, num(8, 10)?);
    let (h, mi, sec) = (num(11, 13)?, num(14, 16)?, num(17, 19)?);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || sec > 60 {
        return None;
    }
    let mut i = 19;
    if sep(i, b'.') {
        i += 1;
        let start = i;
        while b.get(i).is_some_and(u8::is_ascii_digit) {
            i += 1;
        }
        if i == start {
            return None;
        }
    }
    let offset_secs: i64 = match b.get(i).copied()? {
        b'Z' | b'z' if i + 1 == b.len() => 0,
        sign @ (b'+' | b'-') if i + 6 == b.len() && sep(i + 3, b':') => {
            let oh = num(i + 1, i + 3)?;
            let om = num(i + 4, i + 6)?;
            if oh > 23 || om > 59 {
                return None;
            }
            let v = oh * 3600 + om * 60;
            if sign == b'+' { v } else { -v }
        }
        _ => return None,
    };
    // 民法日（proleptic Gregorian）→ 1970-01-01 からの日数。
    let yy = if mo <= 2 { y - 1 } else { y };
    let era = yy.div_euclid(400);
    let yoe = yy - era * 400;
    let mp = (mo + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let total = days * 86_400 + h * 3600 + mi * 60 + sec - offset_secs;
    u64::try_from(total).ok()
}

/// トークンエンドポイントの応答本文を `BearerToken` へ変換する。
///
/// 有効期限は `now`（受信後の単調時刻）から `expires_in`（既定 60 秒・上限 3600 秒）の**残存分**とする。
/// `issued_at`（RFC 3339）が読めれば `wall_now` との差（発行からの経過）を、読めない・省略なら
/// `request_elapsed`（トークン要求開始からの経過）を差し引く。両方あるときは大きい方を引く（保守側。
/// 時計ずれで発行時刻が未来でも要求経過分は引く）。残りが 0 以下なら即失効扱いにする。
pub(crate) fn parse_token_response(
    body: &[u8],
    now: Instant,
    wall_now: SystemTime,
    request_elapsed: Duration,
) -> Result<BearerToken, OciError> {
    let resp: TokenResponse =
        serde_json::from_slice(body).map_err(|_| data_loss("invalid token response"))?;
    let value = [resp.token, resp.access_token]
        .into_iter()
        .flatten()
        .find(|t| !t.is_empty())
        .ok_or_else(|| data_loss("token response has no token"))?;
    if value.len() > TOKEN_MAX_BYTES {
        return Err(OciError::new(
            OciErrorCode::ResourceExhausted,
            "token is too long",
        ));
    }
    if !value.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
        return Err(data_loss("token contains invalid characters"));
    }
    let secs = match resp.expires_in {
        None | Some(0) => DEFAULT_EXPIRES_SECS,
        Some(n) => n.min(MAX_EXPIRES_SECS),
    };
    let wall_age = resp
        .issued_at
        .as_deref()
        .and_then(parse_rfc3339_unix_secs)
        .and_then(|issued| {
            let wall = wall_now.duration_since(UNIX_EPOCH).ok()?.as_secs();
            Some(Duration::from_secs(wall.saturating_sub(issued)))
        })
        .unwrap_or(Duration::ZERO);
    let age = wall_age.max(request_elapsed);
    let remaining = Duration::from_secs(secs).saturating_sub(age);
    let expires_at = now.checked_add(remaining).unwrap_or(now);
    Ok(BearerToken { value, expires_at })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reg() -> RegistryHost {
        RegistryHost::parse("registry-1.docker.io").expect("host")
    }

    fn parse(v: &str) -> Result<BearerChallenge, OciError> {
        parse_www_authenticate(&[v], &reg())
    }

    /// OCI-1: Docker Hub 実形式のチャレンジ。
    #[test]
    fn docker_hub_challenge() {
        let c =
            parse(r#"Bearer realm="https://auth.docker.io/token",service="registry.docker.io""#)
                .expect("parse");
        assert_eq!(c.realm.as_str(), "https://auth.docker.io/token");
        assert_eq!(c.service.as_deref(), Some("registry.docker.io"));
    }

    /// OCI-1: ghcr 形式（scope つき・スキーム大小混在・複数チャレンジ・エスケープ）。
    #[test]
    fn other_forms() {
        let c = parse(
            r#"bEaReR realm="https://ghcr.io/token",service="ghcr.io",scope="repository:a/b:pull""#,
        )
        .expect("ghcr");
        assert_eq!(c.realm.as_str(), "https://ghcr.io/token");
        let c =
            parse(r#"Basic realm="x", Bearer realm="https://auth.example.com/t", service="a\"b""#)
                .expect("multi");
        assert_eq!(c.service.as_deref(), Some("a\"b"));
        let c = parse_www_authenticate(
            &[
                r#"Basic realm="x""#,
                r#"Bearer realm="https://auth.example.com/t""#,
            ],
            &reg(),
        )
        .expect("two headers");
        assert_eq!(c.service, None);
    }

    /// OCI-1・OCI-3: Basic のみは Unimplemented。
    #[test]
    fn basic_only_is_unimplemented() {
        let e = parse(r#"Basic realm="registry""#).expect_err("basic");
        assert_eq!(e.code(), OciErrorCode::Unimplemented);
        assert_eq!(
            e.message(),
            "basic authentication is not supported yet (OCI-3)"
        );
    }

    /// OCI-1・SEC: 異常入力はすべてエラー（具体的な分類つき）。
    #[test]
    fn malformed_challenges() {
        let data_loss_cases = [
            r#"Bearer service="x""#,
            r#"Bearer realm="""#,
            r#"Bearer realm="https://auth.example.com/t"#,
            r#"Bearer realm="http://auth.example.com/t""#,
            r#"Bearer realm="https://user@auth.example.com/t""#,
            r#"Bearer realm="https://[::1]/t""#,
            r#"Bearer realm="https://127.0.0.1/t""#,
            r#"Bearer realm="https://localhost/t""#,
            r#"Bearer realm="https://169.254.169.254/latest""#,
            r#"Bearer realm="https://auth.example.com/a/../t""#,
            r#"Bearer realm="https://auth.example.com/t?x=1""#,
            r#"Bearer realm="https://auth.example.com/t#f""#,
            r#"Bearer realm="https://auth.example.com/t%2e""#,
            "Bearer realm=\"https://auth.example.com/t\u{1}\"",
            "",
        ];
        for c in data_loss_cases {
            let e = parse(c).expect_err(c);
            assert_eq!(e.code(), OciErrorCode::DataLoss, "{c:?}");
        }
        let long = format!(
            r#"Bearer realm="https://a.example.com/{}""#,
            "a".repeat(5000)
        );
        assert_eq!(
            parse(&long).expect_err("long").code(),
            OciErrorCode::ResourceExhausted
        );
        let many: String = (0..17).map(|i| format!("k{i}=v,")).collect();
        let e = parse(&format!("Bearer {many}")).expect_err("params");
        assert_eq!(e.code(), OciErrorCode::ResourceExhausted);
    }

    /// OCI-1: 接続先レジストリ自身のホストは realm に使える（単一ラベル・ポート付きでも）。
    #[test]
    fn realm_same_as_registry_is_allowed() {
        let host = RegistryHost::parse("localhost:5000").expect("host");
        let c = parse_www_authenticate(&[r#"Bearer realm="https://localhost:5000/token""#], &host)
            .expect("same host");
        assert_eq!(c.realm.as_str(), "https://localhost:5000/token");
    }

    fn token(json: &str) -> Result<BearerToken, OciError> {
        parse_token_response(
            json.as_bytes(),
            Instant::now(),
            SystemTime::now(),
            Duration::ZERO,
        )
    }

    /// OCI-1: token / access_token の選択とヘッダ値。
    #[test]
    fn token_fields() {
        let t = token(r#"{"token":"abc.def","expires_in":300,"issued_at":"x"}"#).expect("t");
        assert_eq!(t.authorization_header_value(), "Bearer abc.def");
        let t = token(r#"{"access_token":"zzz"}"#).expect("a");
        assert_eq!(t.authorization_header_value(), "Bearer zzz");
        let t = token(r#"{"token":"","access_token":"zzz"}"#).expect("both");
        assert_eq!(t.authorization_header_value(), "Bearer zzz");
        for bad in [
            r#"{"token":""}"#,
            r#"{}"#,
            "not json",
            r#"{"token":"a b"}"#,
            "{\"token\":\"a\\nb\"}",
        ] {
            assert_eq!(
                token(bad).expect_err(bad).code(),
                OciErrorCode::DataLoss,
                "{bad}"
            );
        }
        let big = format!(r#"{{"token":"{}"}}"#, "a".repeat(TOKEN_MAX_BYTES + 1));
        assert_eq!(
            token(&big).expect_err("big").code(),
            OciErrorCode::ResourceExhausted
        );
    }

    /// OCI-1: 有効期限（省略 60 秒・0 は既定・巨大値は 3600 秒）。
    #[test]
    fn token_expiry() {
        let now = Instant::now();
        let at = |s: u64| now + Duration::from_secs(s);
        let t = parse_token_response(br#"{"token":"a"}"#, now, SystemTime::now(), Duration::ZERO)
            .expect("t");
        assert!(!t.is_expired(at(59)));
        assert!(t.is_expired(at(60)));
        let t = parse_token_response(
            br#"{"token":"a","expires_in":0}"#,
            now,
            SystemTime::now(),
            Duration::ZERO,
        )
        .expect("t");
        assert!(t.is_expired(at(60)));
        let t = parse_token_response(
            br#"{"token":"a","expires_in":999999999999}"#,
            now,
            SystemTime::now(),
            Duration::ZERO,
        )
        .expect("t");
        assert!(!t.is_expired(at(3599)));
        assert!(t.is_expired(at(3600)));
    }

    /// RFC 3339 の変換（具体値）。
    #[test]
    fn rfc3339_parsing() {
        assert_eq!(parse_rfc3339_unix_secs("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(
            parse_rfc3339_unix_secs("2026-10-11T12:34:56.789Z"),
            Some(1_791_722_096)
        );
        assert_eq!(
            parse_rfc3339_unix_secs("2026-10-11T21:34:56+09:00"),
            Some(1_791_722_096)
        );
        assert_eq!(
            parse_rfc3339_unix_secs("2024-02-29T00:00:00Z"),
            Some(1_709_164_800)
        );
        for bad in [
            "x",
            "",
            "2026-10-11 12:34:56Z",
            "2026-13-11T12:34:56Z",
            "2026-10-11T12:34:56",
            "1969-12-31T23:59:59Z",
        ] {
            assert_eq!(parse_rfc3339_unix_secs(bad), None, "{bad}");
        }
    }

    /// OCI-1: issued_at が古ければ残存期間だけ有効、失効済みなら即失効。省略時は要求経過を差し引く。
    #[test]
    fn token_expiry_accounts_for_issue_time() {
        let now = Instant::now();
        let at = |s: u64| now + Duration::from_secs(s);
        let wall = UNIX_EPOCH + Duration::from_secs(1_791_722_096);
        let body = br#"{"token":"a","expires_in":300,"issued_at":"2026-10-11T12:30:56Z"}"#;
        // 発行から 240 秒経過 → 残り 60 秒。
        let t = parse_token_response(body, now, wall, Duration::ZERO).expect("t");
        assert!(!t.is_expired(at(59)));
        assert!(t.is_expired(at(60)));
        // 発行から 300 秒以上経過 → 即失効。
        let old = br#"{"token":"a","expires_in":300,"issued_at":"2026-10-11T12:00:00Z"}"#;
        let t = parse_token_response(old, now, wall, Duration::ZERO).expect("t");
        assert!(t.is_expired(now));
        // issued_at 省略 → 要求経過 100 秒を差し引く。
        let t = parse_token_response(
            br#"{"token":"a","expires_in":300}"#,
            now,
            wall,
            Duration::from_secs(100),
        )
        .expect("t");
        assert!(!t.is_expired(at(199)));
        assert!(t.is_expired(at(200)));
        // issued_at が未来でも要求経過は引く。
        let fut = br#"{"token":"a","expires_in":300,"issued_at":"2030-01-01T00:00:00Z"}"#;
        let t = parse_token_response(fut, now, wall, Duration::from_secs(100)).expect("t");
        assert!(t.is_expired(at(200)));
        assert!(!t.is_expired(at(199)));
    }

    /// security.md: Debug にトークン値を出さない。
    #[test]
    fn debug_redacts_token() {
        let t = token(r#"{"token":"SECRET-VALUE"}"#).expect("t");
        assert_eq!(format!("{t:?}"), "BearerToken(<redacted>)");
        let a = format!("{:?}", RegistryAuth::Bearer(t));
        assert!(!a.contains("SECRET-VALUE"));
    }
}
