//! 匿名トークン取得の純粋な部分: `WWW-Authenticate` の解析・`realm` の検証・トークン応答のパース
//! （TASK-51.2・OCI-1・MS-4）。
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
//! 実装済み: Basic 認証の資格情報型 `BasicCredentials` とチャレンジ判定（TASK-54.1・OCI-3・MS-4・#416）。
//! 資格情報は生成時に検証し（REPAIR-2）、`Authorization` ヘッダ値は `Debug` / エラーに出さない。
//!
//! 実装済み: 資格情報つき Bearer トークン交換（Basic 認証付きで realm へ GET する Docker token 認証。
//! TASK-54.2・OCI-3・MS-4・#417）。realm は非信頼 URL のため、`realm_may_receive_credentials` が許可した
//! ホストにだけ資格情報を送る（fail-closed）。
//!
//! 実装済み: `registry` への統一入口 `RegistryClient::authenticate`（チャレンジに応じた Basic / Bearer の
//! 自動選択。TASK-54.3・OCI-3・#418）。
//!
//! 未実装（将来仕様）: OAuth2 の POST フロー（`grant_type=password` / `refresh_token`・OCI-3）、
//! トークンのキャッシュと失効時の再取得。
//! 資格情報の保管（docker config・credential helper）も範囲外。

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
/// **名前ベースの防御**であり、DNS 解決後にプライベート IP を指すホスト名は本型では防げない。そのため
/// 接続先レジストリと別ホストの realm へは、解決済み IP を検査して公開アドレスだけへ接続するリゾルバを
/// 持つ別 `Agent` で通信する（`registry` モジュールの `PublicOnlyResolver`。解決と接続が同じ結果を使うため
/// DNS rebinding の隙間がない）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TokenRealm {
    url: String,
    host: RegistryHost,
    same_as_registry: bool,
}

/// 資格情報の送出先として組み込みで許可する (レジストリ, realm) の対。Docker Hub は
/// `registry-1.docker.io` が `auth.docker.io` をトークンエンドポイントとして提示する実在の構成（OCI-3）。
const BUILTIN_REALM_PAIRS: &[(&str, &str)] = &[("registry-1.docker.io", "auth.docker.io")];

/// 資格情報を `realm` へ送ってよいか判定する（TASK-54.2・OCI-3）。
///
/// realm はレジストリ応答由来の非信頼 URL のため、無条件に資格情報を送ると悪意あるレジストリや
/// 中間者に資格情報を持ち出される。許可は次の 3 つだけ（fail-closed）: (1) 接続先レジストリと同一
/// エンドポイント、(2) 呼び出し側が明示した `trusted`（ホストとポートが一致）、(3) 組み込みの既知対。
pub(crate) fn realm_may_receive_credentials(
    realm: &TokenRealm,
    registry: &RegistryHost,
    trusted: &[RegistryHost],
) -> bool {
    if realm.is_registry_host() {
        return true;
    }
    let h = realm.host();
    if trusted.iter().any(|t| same_endpoint(t, h)) {
        return true;
    }
    h.port().unwrap_or(443) == 443
        && registry.port().unwrap_or(443) == 443
        && BUILTIN_REALM_PAIRS
            .iter()
            .any(|(r, a)| registry.host() == *r && h.host() == *a)
}

/// 既定ポート（https の 443）を補ってホストとポートが同じか判定する。
/// `harbor.internal` と `harbor.internal:443` は同じ接続先なので同一視する（`RegistryHost` の
/// `PartialEq` はポートの有無を区別するため使わない）。
fn same_endpoint(a: &RegistryHost, b: &RegistryHost) -> bool {
    a.host() == b.host() && a.port().unwrap_or(443) == b.port().unwrap_or(443)
}

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
        let same = same_endpoint(&host, registry);
        if !same {
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
        Ok(Self {
            url: format!("https://{}{}", host.authority(), path),
            host,
            same_as_registry: same,
        })
    }

    /// 接続先レジストリ自身のホストなら true。false のとき呼び出し側は公開 IP のみへ接続する
    /// 経路で通信する（SSRF 対策）。
    pub(crate) fn is_registry_host(&self) -> bool {
        self.same_as_registry
    }

    /// 検証済みの realm ホスト（資格情報の送出可否判定に使う）。
    pub(crate) fn host(&self) -> &RegistryHost {
        &self.host
    }

    /// 検証済みの URL 文字列。
    pub(crate) fn as_str(&self) -> &str {
        &self.url
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

/// `WWW-Authenticate` ヘッダ値群の件数・合計バイト数を検査する（匿名経路と Basic 判定で共有）。
fn check_challenge_limits(values: &[&str]) -> Result<(), OciError> {
    if values.len() > CHALLENGE_MAX_HEADERS
        || values.iter().map(|v| v.len()).sum::<usize>() > CHALLENGE_TOTAL_MAX_BYTES
    {
        return Err(OciError::new(
            OciErrorCode::ResourceExhausted,
            "www-authenticate headers are too large",
        ));
    }
    Ok(())
}

/// 401 応答の `WWW-Authenticate` ヘッダ値群が Basic チャレンジを含むか判定する（OCI-3・#416）。
///
/// Basic の `realm` は表示用で接続先を決めないため読み捨てる（資格情報の送出先は常に検証済みの
/// `RegistryEndpoint` であり、応答由来の URL ではない）。件数・長さの上限は匿名経路と共通。
pub(crate) fn challenge_offers_basic(values: &[&str]) -> Result<bool, OciError> {
    check_challenge_limits(values)?;
    for v in values {
        if split_challenges(v)?
            .iter()
            .any(|ch| ch.scheme.eq_ignore_ascii_case("basic"))
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// 401 応答の `WWW-Authenticate` ヘッダ値群から、最初の Bearer チャレンジを取り出す（OCI-1）。
///
/// Bearer が無く Basic のみなら `Unimplemented`（匿名取得では満たせない。資格情報つきは
/// `RegistryClient::authenticate_basic`）。チャレンジの
/// `scope` は無視する（スコープは検証済み `Repository` から呼び出し側が組み立てる）。
pub(crate) fn parse_www_authenticate(
    values: &[&str],
    registry: &RegistryHost,
) -> Result<BearerChallenge, OciError> {
    check_challenge_limits(values)?;
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
            "registry requires credentials; anonymous access is not enough (OCI-3)",
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

/// ユーザー名の最大バイト数。
const BASIC_USERNAME_MAX_BYTES: usize = 256;
/// パスワードの最大バイト数（レジストリのトークン型パスワードを許容する大きさ）。
const BASIC_PASSWORD_MAX_BYTES: usize = 4096;

/// 標準 base64（RFC 4648 §4、パディングあり）。依存を増やさないための最小実装。
fn base64_encode(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let sym = |v: u32| char::from(ALPHABET.get((v & 0x3f) as usize).copied().unwrap_or(b'A'));
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = u32::from(chunk.first().copied().unwrap_or(0));
        let b1 = u32::from(chunk.get(1).copied().unwrap_or(0));
        let b2 = u32::from(chunk.get(2).copied().unwrap_or(0));
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(sym(n >> 18));
        out.push(sym(n >> 12));
        out.push(if chunk.len() > 1 { sym(n >> 6) } else { '=' });
        out.push(if chunk.len() > 2 { sym(n) } else { '=' });
    }
    out
}

/// Basic 認証の資格情報（RFC 7617。OCI-3・TASK-54.1・#416）。
///
/// 生成時に検証し（REPAIR-2）、ヘッダインジェクション（制御文字）と RFC 7617 違反（ユーザー名の `:`）を
/// 表現できなくする。保持するのは組み立て済みの `Authorization` ヘッダ値のみで、`Debug` は値を出さず
/// `Display` は持たない（security.md）。ユーザー名・パスワードを含む中間 `String` は組み立て後すぐ
/// drop するが、zeroize 用の依存は未導入のため、解放後のメモリ上の残存までは消さない。
#[derive(Clone)]
pub struct BasicCredentials {
    header_value: String,
}

impl BasicCredentials {
    /// 資格情報を検証して作る。違反は `InvalidArgument`（message は固定文で、入力値を載せない）。
    ///
    /// ユーザー名は 1〜256 バイトで `:` を含まない。パスワードは 1〜4096 バイト。どちらも ASCII 制御文字
    /// （0x00-0x1f・0x7f）を含まない。UTF-8 は許可する。
    pub fn new(username: &str, password: &str) -> Result<Self, OciError> {
        let bad = |m: &str| OciError::new(OciErrorCode::InvalidArgument, m);
        if username.is_empty() || username.len() > BASIC_USERNAME_MAX_BYTES {
            return Err(bad("invalid basic auth username length"));
        }
        if password.is_empty() || password.len() > BASIC_PASSWORD_MAX_BYTES {
            return Err(bad("invalid basic auth password length"));
        }
        if username.contains(':') {
            return Err(bad("basic auth username must not contain a colon"));
        }
        if username.chars().any(char::is_control) || password.chars().any(char::is_control) {
            return Err(bad("basic auth credentials contain control characters"));
        }
        let mut raw = String::with_capacity(username.len() + 1 + password.len());
        raw.push_str(username);
        raw.push(':');
        raw.push_str(password);
        let header_value = format!("Basic {}", base64_encode(raw.as_bytes()));
        drop(raw);
        Ok(Self { header_value })
    }

    /// `Authorization` ヘッダ値（`Basic <base64>`）。
    pub(crate) fn authorization_header_value(&self) -> &str {
        &self.header_value
    }
}

impl fmt::Debug for BasicCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BasicCredentials(<redacted>)")
    }
}

/// レジストリへの認証状態（OCI-1・OCI-3）。OAuth2 などの変種を足すため `non_exhaustive`。
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum RegistryAuth {
    /// 認証不要（`/v2/` が 200 を返した）。
    None,
    /// 匿名 Bearer トークン。
    Bearer(BearerToken),
    /// Basic 認証の資格情報（`RegistryClient::authenticate_basic` が検証済み。期限は持たない）。
    Basic(BasicCredentials),
}

impl RegistryAuth {
    /// 接続先レジストリへ送る `Authorization` ヘッダ値。認証不要なら `None`。
    ///
    /// 期限切れの Bearer は通信させず `PermissionDenied`（再取得は呼び出し側）。manifest 取得と
    /// blob 取得が共有する。
    pub(crate) fn authorization_header(&self, now: Instant) -> Result<Option<String>, OciError> {
        match self {
            RegistryAuth::None => Ok(None),
            RegistryAuth::Bearer(t) if t.is_expired(now) => Err(OciError::new(
                OciErrorCode::PermissionDenied,
                "registry token has expired",
            )),
            RegistryAuth::Bearer(t) => Ok(Some(t.authorization_header_value())),
            RegistryAuth::Basic(c) => Ok(Some(c.authorization_header_value().to_string())),
        }
    }
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
    if !(1..=12).contains(&mo) || h > 23 || mi > 59 || sec > 60 {
        return None;
    }
    // 月ごとの日数と閏年を検証する（2026-02-31 のような存在しない日付は別の日付へ化けるため拒否）。
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let days_in_month = match mo {
        2 if leap => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    };
    if !(1..=days_in_month).contains(&d) {
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
            "registry requires credentials; anonymous access is not enough (OCI-3)"
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

    /// OCI-1: 既定ポート 443 の明示有無は同一ホストとして扱い、別ポートは別ホストのまま。
    #[test]
    fn realm_default_port_is_normalized() {
        for (reg, realm) in [
            ("harbor.internal", "https://harbor.internal:443/token"),
            ("harbor.internal:443", "https://harbor.internal/token"),
        ] {
            let host = RegistryHost::parse(reg).expect("host");
            let c = parse_www_authenticate(&[&format!(r#"Bearer realm="{realm}""#)], &host)
                .expect("same host");
            assert!(c.realm.is_registry_host(), "{reg} {realm}");
        }
        let host = RegistryHost::parse("harbor.internal").expect("host");
        let c = parse_www_authenticate(
            &[r#"Bearer realm="https://harbor.internal:8443/token""#],
            &host,
        )
        .expect("other port is a separate host");
        // 別ポートはレジストリ自身ではないため公開 IP のみの経路になる。
        assert!(!c.realm.is_registry_host());
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
        // 400 で割り切れる年は閏年。
        assert_eq!(
            parse_rfc3339_unix_secs("2000-02-29T00:00:00Z"),
            Some(951_782_400)
        );
        for bad in [
            "x",
            "",
            "2026-10-11 12:34:56Z",
            "2026-13-11T12:34:56Z",
            "2026-10-11T12:34:56",
            "1969-12-31T23:59:59Z",
            "2026-02-31T00:00:00Z",
            "2026-04-31T00:00:00Z",
            "2026-02-29T00:00:00Z",
            "2100-02-29T00:00:00Z",
            "2026-10-00T00:00:00Z",
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

    /// OCI-3: base64 の RFC 4648 テストベクタ。
    #[test]
    fn base64_rfc4648_vectors() {
        for (i, o) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64_encode(i.as_bytes()), o, "{i}");
        }
    }

    /// OCI-3: RFC 7617 の例と UTF-8 の資格情報のヘッダ値。
    #[test]
    fn basic_header_values() {
        let c = BasicCredentials::new("Aladdin", "open sesame").expect("c");
        assert_eq!(
            c.authorization_header_value(),
            "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=="
        );
        let c = BasicCredentials::new("ユーザー", "パス").expect("utf8");
        assert_eq!(
            c.authorization_header_value(),
            "Basic 44Om44O844K244O8OuODkeOCuQ=="
        );
    }

    /// OCI-3・SEC: 不正な資格情報は InvalidArgument で拒否し、message に入力値を載せない。
    #[test]
    fn basic_rejects_invalid_credentials() {
        let long_user = "u".repeat(BASIC_USERNAME_MAX_BYTES + 1);
        let long_pw = "p".repeat(BASIC_PASSWORD_MAX_BYTES + 1);
        let cases: [(&str, &str); 8] = [
            ("", "pw"),
            ("us:er", "SECRET-PW"),
            ("us\ner", "SECRET-PW"),
            ("user", "SECRET\r\nX: y"),
            ("user", "SECRET\u{7f}"),
            (&long_user, "pw"),
            ("user", ""),
            ("user", &long_pw),
        ];
        for (u, p) in cases {
            let e = BasicCredentials::new(u, p).expect_err(u);
            assert_eq!(e.code(), OciErrorCode::InvalidArgument);
            assert!(!e.message().contains("SECRET"));
        }
        assert!(BasicCredentials::new(&"u".repeat(BASIC_USERNAME_MAX_BYTES), "pw").is_ok());
        assert!(BasicCredentials::new("u", &"p".repeat(BASIC_PASSWORD_MAX_BYTES)).is_ok());
    }

    /// OCI-3・security.md: Debug に資格情報を出さない。
    #[test]
    fn basic_debug_redacts() {
        let c = BasicCredentials::new("alice", "SECRET-PW").expect("c");
        assert_eq!(format!("{c:?}"), "BasicCredentials(<redacted>)");
        let a = format!("{:?}", RegistryAuth::Basic(c));
        assert!(!a.contains("SECRET-PW") && !a.contains("alice") && !a.contains("QWxp"));
    }

    /// OCI-3: Basic チャレンジの判定と上限。
    #[test]
    fn challenge_offers_basic_cases() {
        assert!(challenge_offers_basic(&[r#"Basic realm="x""#]).expect("a"));
        assert!(challenge_offers_basic(&[r#"basic realm="x""#]).expect("b"));
        assert!(
            challenge_offers_basic(&[r#"Bearer realm="https://a.example.com/t", Basic realm="x""#])
                .expect("c")
        );
        assert!(
            !challenge_offers_basic(&[r#"Bearer realm="https://a.example.com/t""#]).expect("d")
        );
        assert!(!challenge_offers_basic(&[]).expect("e"));
        let many = ["Basic"; 9];
        assert_eq!(
            challenge_offers_basic(&many).expect_err("n").code(),
            OciErrorCode::ResourceExhausted
        );
    }

    /// OCI-3: Authorization ヘッダ値の共通生成（None / Bearer 有効・期限切れ / Basic）。
    #[test]
    fn authorization_header_by_variant() {
        let now = Instant::now();
        assert_eq!(
            RegistryAuth::None.authorization_header(now).expect("n"),
            None
        );
        let tok = parse_token_response(
            br#"{"token":"tok","expires_in":300}"#,
            now,
            SystemTime::now(),
            Duration::ZERO,
        )
        .expect("t");
        let bearer = RegistryAuth::Bearer(tok);
        assert_eq!(
            bearer.authorization_header(now).expect("b").as_deref(),
            Some("Bearer tok")
        );
        let e = bearer
            .authorization_header(now + Duration::from_secs(301))
            .expect_err("expired");
        assert_eq!(e.code(), OciErrorCode::PermissionDenied);
        let basic =
            RegistryAuth::Basic(BasicCredentials::new("Aladdin", "open sesame").expect("c"));
        assert_eq!(
            basic.authorization_header(now).expect("basic").as_deref(),
            Some("Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==")
        );
    }

    /// OCI-3・TASK-54.2: 資格情報の送出可否は同一ホスト・明示した信頼ホスト・既知対だけ許可する。
    #[test]
    fn realm_credentials_policy() {
        let parse = |r: &str, h: &str| {
            let host = RegistryHost::parse(h).expect("host");
            (TokenRealm::parse(r, &host).expect("realm"), host)
        };
        let trusted = [RegistryHost::parse("auth.corp.example:8443").expect("t")];
        let (r, h) = parse("https://harbor.internal/token", "harbor.internal:443");
        assert!(realm_may_receive_credentials(&r, &h, &[]));
        let (r, h) = parse("https://auth.docker.io/token", "registry-1.docker.io");
        assert!(realm_may_receive_credentials(&r, &h, &[]));
        let (r, h) = parse("https://auth.docker.io/token", "other.example");
        assert!(!realm_may_receive_credentials(&r, &h, &[]));
        let (r, h) = parse("https://auth.corp.example:8443/t", "reg.example");
        assert!(realm_may_receive_credentials(&r, &h, &trusted));
        assert!(!realm_may_receive_credentials(&r, &h, &[]));
        let (r, h) = parse("https://auth.corp.example/t", "reg.example");
        assert!(!realm_may_receive_credentials(&r, &h, &trusted));
        let (r, h) = parse("https://evil.example/t", "registry-1.docker.io");
        assert!(!realm_may_receive_credentials(&r, &h, &[]));
    }
}
