//! 記録ファイル共通の長さ接頭辞テキストの部品（NET-1・NET-6・REPAIR-2・#3067）。
//!
//! 役割: `member`・`realized` の各記録（FCMEM1・FCMIN1・FCREA1・FCRIN1）が共有する
//! `MAGIC\n` + `kind <len>\n<値>\n` の組み立てと読み取りを 1 か所に置く。FCNET1（`definition`）と同じ規則
//! （`len` は 10 進で先頭の 0 と `+` を拒否し最大 4 桁・末尾のごみ / 順序違い / 欠落は `DataLoss`）で、
//! 呼び出し元は各記録の型の `encode` / `decode` だけ。OS 非依存でファイルには触れない。
//! FCNET1 の部品は `definition` 内に閉じており、メッセージ文言が定義専用のため本モジュールで別に持つ。

use std::net::{IpAddr, Ipv4Addr};

use crate::error::{NetError, NetErrorCode};
use crate::netlink_route::IpPrefix;

/// 記録 1 件の最大バイト数。解析の前にサイズで拒否する（無制限確保の防止）。
pub const RECORD_MAX_BYTES: usize = 4096;

pub(super) fn bad(msg: &'static str) -> NetError {
    NetError::new(NetErrorCode::DataLoss, msg)
}

/// `kind <len>\n<値>\n` を追記する。
pub(super) fn push_field(out: &mut String, kind: &str, value: &str) {
    out.push_str(kind);
    out.push(' ');
    out.push_str(&value.len().to_string());
    out.push('\n');
    out.push_str(value);
    out.push('\n');
}

/// 先頭の `magic` を確認して、本文を返す。サイズ超過・非 UTF-8・magic 違いは `DataLoss`。
pub(super) fn open<'a>(bytes: &'a [u8], magic: &str) -> Result<&'a str, NetError> {
    if bytes.len() > RECORD_MAX_BYTES {
        return Err(bad("network record exceeds the size limit"));
    }
    let text = std::str::from_utf8(bytes).map_err(|_| bad("network record is not UTF-8"))?;
    text.strip_prefix(magic)
        .ok_or_else(|| bad("network record magic mismatch"))
}

/// `kind <len>\n<値>\n` を 1 つ読み、値を返して `rest` を進める。
pub(super) fn take_field<'a>(rest: &mut &'a str, kind: &str) -> Result<&'a str, NetError> {
    let after_kind = rest
        .strip_prefix(kind)
        .and_then(|r| r.strip_prefix(' '))
        .ok_or_else(|| bad("network record field is missing or out of order"))?;
    let (len_str, body) = after_kind
        .split_once('\n')
        .ok_or_else(|| bad("network record length line is unterminated"))?;
    let canonical = !len_str.is_empty()
        && len_str.len() <= 4
        && len_str.bytes().all(|b| b.is_ascii_digit())
        && (len_str == "0" || !len_str.starts_with('0'));
    if !canonical {
        return Err(bad("network record length is not canonical"));
    }
    let len: usize = len_str
        .parse()
        .map_err(|_| bad("network record length is not canonical"))?;
    let value = body
        .get(..len)
        .ok_or_else(|| bad("network record length exceeds the remaining data"))?;
    let after_value = body
        .get(len..)
        .and_then(|r| r.strip_prefix('\n'))
        .ok_or_else(|| bad("network record value is not newline terminated"))?;
    *rest = after_value;
    Ok(value)
}

/// 次の項目が `kind` なら読む（任意の繰り返し項目用）。
pub(super) fn take_optional<'a>(
    rest: &mut &'a str,
    kind: &str,
) -> Result<Option<&'a str>, NetError> {
    let present = rest.strip_prefix(kind).is_some_and(|r| r.starts_with(' '));
    if present {
        take_field(rest, kind).map(Some)
    } else {
        Ok(None)
    }
}

/// 本文を読み切ったことを確認する。
pub(super) fn finish(rest: &str) -> Result<(), NetError> {
    if rest.is_empty() {
        Ok(())
    } else {
        Err(bad("network record has trailing data"))
    }
}

/// `a.b.c.d/nn` の正準形だけを受ける IPv4 プレフィックス。
pub(super) fn parse_prefix(s: &str) -> Result<IpPrefix, NetError> {
    let malformed = || bad("network record prefix is malformed");
    let (addr, len) = s.split_once('/').ok_or_else(malformed)?;
    let addr: Ipv4Addr = addr.parse().map_err(|_| malformed())?;
    if len.is_empty() || len.len() > 2 || !len.bytes().all(|b| b.is_ascii_digit()) {
        return Err(malformed());
    }
    let len: u8 = len.parse().map_err(|_| malformed())?;
    let prefix = IpPrefix::new(IpAddr::V4(addr), len).map_err(|_| malformed())?;
    if format_prefix(&prefix) != s {
        return Err(malformed());
    }
    Ok(prefix)
}

pub(super) fn format_prefix(p: &IpPrefix) -> String {
    format!("{}/{}", p.addr(), p.prefix_len())
}

/// `dev:ino` の正準形（10 進・先頭 0 なし）を読む。
pub(super) fn parse_dir_id(s: &str) -> Result<(u64, u64), NetError> {
    let malformed = || bad("network record directory id is malformed");
    let (dev, ino) = s.split_once(':').ok_or_else(malformed)?;
    let dev: u64 = dev.parse().map_err(|_| malformed())?;
    let ino: u64 = ino.parse().map_err(|_| malformed())?;
    if format!("{dev}:{ino}") != s {
        return Err(malformed());
    }
    Ok((dev, ino))
}

/// 所有トークンとして許す文字列か（ASCII の図形文字のみ・256 バイト以下）。
pub(super) fn token_is_sane(t: &str) -> bool {
    !t.is_empty() && t.len() <= 256 && t.bytes().all(|b| b.is_ascii_graphic())
}
