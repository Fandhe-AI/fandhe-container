//! 構造化ログ 1 行の整形と照合器（GPU-6・TASK-172.4）。
//!
//! ログは数値と固定語彙だけを出し、ゲストのバイト列や文字列をエコーしない（ログ注入の防止）。
//! 照合器は実機前提テスト（`tests/real_machine_capset_log.rs`）が使い、入力の行長・行数・総量に上限を設ける。

/// ログ全体の上限（バイト）。
pub const MAX_LOG_BYTES: usize = 4 * 1024 * 1024;
/// 1 行の上限（バイト）。超えた行は壊れた行として数える。
pub const MAX_LINE_BYTES: usize = 512;
/// 行数の上限。
pub const MAX_LINES: usize = 100_000;

/// ctrl 応答の結果語彙（capset クエリ・display info・ctx 操作で共用）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryResult {
    /// 成功。
    Ok,
    /// パラメータ不正（`ERR_INVALID_PARAMETER`）。
    InvalidParameter,
    /// 未対応コマンド（`ERR_UNSPEC`）。
    Unspec,
    /// ctx_id が 0・重複・未作成（`ERR_INVALID_CONTEXT_ID`）。
    InvalidContextId,
    /// ctx 表が上限（`ERR_OUT_OF_MEMORY`）。
    OutOfMemory,
}

impl QueryResult {
    fn word(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::InvalidParameter => "invalid_parameter",
            Self::Unspec => "unspec",
            Self::InvalidContextId => "invalid_context_id",
            Self::OutOfMemory => "out_of_memory",
        }
    }
}

/// `GET_CAPSET_INFO` のログ行。復号できなかった値は -1 で表す。
pub fn info_line(index: Option<u32>, result: QueryResult, max_size: u32) -> String {
    format!(
        "venus_jig event=capset_query cmd=GET_CAPSET_INFO capset_index={} result={} max_size={max_size}",
        index.map_or(-1, i64::from),
        result.word()
    )
}

/// `GET_CAPSET` のログ行。復号できなかった値は -1 で表す。
pub fn query_line(id: Option<u32>, version: u32, result: QueryResult, max_size: u32) -> String {
    format!(
        "venus_jig event=capset_query cmd=GET_CAPSET capset_id={} version={version} result={} max_size={max_size}",
        id.map_or(-1, i64::from),
        result.word()
    )
}

/// `GET_DISPLAY_INFO` のログ行（scanout なし構成のため `num_scanouts=0` 固定）。
pub fn display_info_line(result: QueryResult) -> String {
    format!(
        "venus_jig event=display_info cmd=GET_DISPLAY_INFO num_scanouts=0 result={}",
        result.word()
    )
}

/// `CTX_CREATE` のログ行。復号できなかった値は -1。debug_name は出さず `nlen` の数値のみ出す（ログ注入の防止）。
pub fn ctx_create_line(
    ctx_id: u32,
    capset_id: Option<u8>,
    nlen: Option<u32>,
    result: QueryResult,
) -> String {
    format!(
        "venus_jig event=ctx cmd=CTX_CREATE ctx_id={ctx_id} capset_id={} nlen={} result={}",
        capset_id.map_or(-1, i64::from),
        nlen.map_or(-1, i64::from),
        result.word()
    )
}

/// `CTX_DESTROY` のログ行。
pub fn ctx_destroy_line(ctx_id: u32, result: QueryResult) -> String {
    format!(
        "venus_jig event=ctx cmd=CTX_DESTROY ctx_id={ctx_id} result={}",
        result.word()
    )
}

/// 拒否した ctrl 要求のログ行（種別は数値のみ）。
pub fn rejected_line(cmd_type: Option<u32>, result: QueryResult) -> String {
    format!(
        "venus_jig event=ctrl_rejected cmd_type={} result={}",
        cmd_type.map_or(-1, i64::from),
        result.word()
    )
}

/// 照合結果。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CapsetLogReport {
    /// `GET_CAPSET` で `capset_id=4` が `result=ok` の行数（受入基準 2 の判定対象）。
    pub venus_get_capset_ok: usize,
    /// `GET_CAPSET_INFO` で `result=ok` の行数。
    pub info_ok: usize,
    /// 解釈できなかった行・上限超過行の数（空行は数えない）。
    pub malformed_lines: usize,
}

/// 照合の失敗。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogError {
    /// ログが `MAX_LOG_BYTES` を超えた。
    TooLarge,
    /// 行数が `MAX_LINES` を超えた。
    TooManyLines,
}

/// ログ全体を走査して capset クエリの成功行を数える。
pub fn find_capset_queries(log: &str) -> Result<CapsetLogReport, LogError> {
    if log.len() > MAX_LOG_BYTES {
        return Err(LogError::TooLarge);
    }
    let mut report = CapsetLogReport::default();
    for (n, line) in log.lines().enumerate() {
        if n >= MAX_LINES {
            return Err(LogError::TooManyLines);
        }
        if line.trim().is_empty() {
            continue;
        }
        match classify(line) {
            Some(Class::VenusGetCapsetOk) => report.venus_get_capset_ok += 1,
            Some(Class::InfoOk) => report.info_ok += 1,
            Some(Class::Other) => {}
            None => report.malformed_lines += 1,
        }
    }
    Ok(report)
}

enum Class {
    VenusGetCapsetOk,
    InfoOk,
    Other,
}

fn classify(line: &str) -> Option<Class> {
    if line.len() > MAX_LINE_BYTES {
        return None;
    }
    let mut tokens = line.split_whitespace();
    if tokens.next()? != "venus_jig" {
        return None;
    }
    let (mut event, mut cmd, mut id, mut result) = (None, None, None, None);
    let (mut version, mut max_size) = (None, None);
    let mut seen: Vec<&str> = Vec::new();
    for t in tokens {
        let (k, v) = t.split_once('=')?;
        // 重複キーは矛盾行（例: result=invalid_parameter result=ok）を成功扱いしないため壊れた行として拒否する。
        if seen.contains(&k) {
            return None;
        }
        seen.push(k);
        match k {
            "event" => event = Some(v),
            "cmd" => cmd = Some(v),
            "capset_id" => id = Some(v),
            "version" => version = Some(v),
            "max_size" => max_size = Some(v),
            "result" => result = Some(v),
            _ => {}
        }
    }
    if event? != "capset_query" {
        return Some(Class::Other);
    }
    let ok = result? == "ok";
    // 成功行の出力契約: max_size は正の u32、GET_CAPSET の version は対応版の 0。
    let size_ok = max_size
        .and_then(|v| v.parse::<u32>().ok())
        .is_some_and(|n| n > 0);
    match cmd? {
        "GET_CAPSET" if ok => {
            if size_ok && version == Some("0") && id.is_some_and(|v| v.parse::<u32>().is_ok()) {
                if id == Some("4") {
                    Some(Class::VenusGetCapsetOk)
                } else {
                    Some(Class::Other)
                }
            } else {
                None
            }
        }
        "GET_CAPSET_INFO" if ok => {
            if size_ok {
                Some(Class::InfoOk)
            } else {
                None
            }
        }
        "GET_CAPSET" | "GET_CAPSET_INFO" => Some(Class::Other),
        _ => None,
    }
}
