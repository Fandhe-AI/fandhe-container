//! 構造化ログ 1 行の整形と照合器（GPU-6・TASK-172.4）。
//!
//! ログは数値と固定語彙だけを出し、ゲストのバイト列や文字列をエコーしない（ログ注入の防止）。
//! 照合器は実機前提テスト（`tests/real_machine_capset_log.rs`）が使い、入力の行長・行数・総量に上限を設ける。
//!
//! 書き出し側の [`LogSink`] は起動 bin（`launch`。#1598）が使い、照合器の上限に収まるよう総量・行長・行数を抑える（REPAIR-5）。
//! 読み取り側の [`read_log_file`] は通常ファイル以外を open 前に拒否する（FIFO で open が止まるのを防ぐ。事後監査 #1528 D2）。

use std::fs;
use std::io::{self, Read, Write};
use std::path::Path;

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

/// セッションがエラーで終了したときのログ行。code は固定語彙、要求 ID は数値（無ければ -1）だけを出す。
pub fn session_error_line(code: &str, request: Option<u32>) -> String {
    format!(
        "venus_jig event=session_error code={code} request={}",
        request.map_or(-1, i64::from)
    )
}

/// `NEED_REPLY` が付いた `SET_*` に応答しなかった（REPLY_ACK を広告していない）ことを示すログ行。
pub fn need_reply_ignored_line(request: u32) -> String {
    format!("venus_jig event=need_reply_ignored request={request}")
}

/// writable の容量が応答に足りず、応答を書かずに len=0 で返したことを示すログ行。
pub fn response_dropped_line() -> String {
    "venus_jig event=response_dropped reason=writable_too_small".to_string()
}

/// セッションが正常終了（frontend がメッセージ境界で切断）したときのログ行。
pub fn session_end_line() -> String {
    "venus_jig event=session_end result=peer_closed".to_string()
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

/// 上限に達してログの書き込みを止めたことを示す行。照合器では `Other` に分類され、壊れた行に数えられない。
pub fn log_truncated_line() -> String {
    "venus_jig event=log_truncated reason=limit".to_string()
}

/// 上限つきのログ書き出し先（GPU-6・REPAIR-5・#1598）。1 行ずつ `write_all` し、バッファリングしない。
///
/// 総量が [`MAX_LOG_BYTES`]・行数が [`MAX_LINES`]・1 行が [`MAX_LINE_BYTES`] を超える行は書かず、打ち切り行
/// （[`log_truncated_line`]）を 1 回だけ書いて以降は捨てる。打ち切り行の分は常に予約するので、書いたログ全体が
/// 照合器（[`find_capset_queries`]）の上限に収まる。`session::run` の sink は `Result` を返さないため、最初の書き込み
/// エラーはここに保持して以降の書き込みを止め、呼び出し側が [`LogSink::into_inner`] で取り出す。
#[derive(Debug)]
pub struct LogSink<W: Write> {
    out: W,
    bytes: usize,
    lines: usize,
    truncated: bool,
    error: Option<io::ErrorKind>,
}

impl<W: Write> LogSink<W> {
    /// 空のログとして `out` を包む。
    pub fn new(out: W) -> Self {
        Self {
            out,
            bytes: 0,
            lines: 0,
            truncated: false,
            error: None,
        }
    }

    /// 1 行を書く（末尾の改行は付与する）。上限を超える場合は打ち切り行を 1 回だけ書いて以降を捨てる。
    pub fn write_line(&mut self, line: &str) {
        if self.truncated || self.error.is_some() {
            return;
        }
        let reserve = log_truncated_line().len() + 1;
        let need = line.len() + 1;
        let fits = line.len() <= MAX_LINE_BYTES
            && !line.contains(['\n', '\r'])
            && self.bytes + need + reserve <= MAX_LOG_BYTES
            && self.lines + 2 <= MAX_LINES;
        if fits {
            self.put(line, need);
        } else {
            self.truncated = true;
            let t = log_truncated_line();
            let n = t.len() + 1;
            self.put(&t, n);
        }
    }

    fn put(&mut self, line: &str, need: usize) {
        let mut buf = String::with_capacity(need);
        buf.push_str(line);
        buf.push('\n');
        match self.out.write_all(buf.as_bytes()) {
            Ok(()) => {
                self.bytes += need;
                self.lines += 1;
            }
            Err(e) => self.error = Some(e.kind()),
        }
    }

    /// 打ち切りが起きたか。
    pub fn truncated(&self) -> bool {
        self.truncated
    }

    /// 書き出し先と、保持した最初の書き込みエラーを返す。
    pub fn into_inner(self) -> (W, Option<io::ErrorKind>) {
        (self.out, self.error)
    }
}

/// [`read_log_file`] の失敗。固定語彙のみ。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFileError {
    /// 通常ファイルでない（symlink・FIFO・ディレクトリ等）。open する前に拒否する。
    NotRegularFile,
    /// 状態の取得または open に失敗した。
    Open,
    /// 読み取りに失敗した。
    Read,
    /// `MAX_LOG_BYTES` を超えている。
    TooLarge,
    /// UTF-8 でない。
    NotUtf8,
}

/// 治具のログファイルを上限つきで読む（事後監査 #1528 D2。実機前提テストが使う）。
///
/// 手順: (1) `symlink_metadata` で通常ファイル以外を open 前に拒否する（FIFO は書き手が現れるまで open が止まるため）。
/// (2) open する。(3) 開いた fd の `metadata` で通常ファイルとサイズ上限を確かめ直す。(4) `MAX_LOG_BYTES + 1` で打ち切って読む。
/// 限界: (1) と (2) の間に FIFO へ差し替えられる競合は残る（`O_NONBLOCK` / `O_NOFOLLOW` の値はアーキごとに異なり、
/// ここでは扱わない）。呼び出し側は読み取りを期限つきで待つこと（REPAIR-5）。
pub fn read_log_file(path: &Path) -> Result<String, LogFileError> {
    let before = fs::symlink_metadata(path).map_err(|_| LogFileError::Open)?;
    if !before.file_type().is_file() {
        return Err(LogFileError::NotRegularFile);
    }
    let file = fs::File::open(path).map_err(|_| LogFileError::Open)?;
    let meta = file.metadata().map_err(|_| LogFileError::Open)?;
    if !meta.file_type().is_file() {
        return Err(LogFileError::NotRegularFile);
    }
    if meta.len() > MAX_LOG_BYTES as u64 {
        return Err(LogFileError::TooLarge);
    }
    let mut bytes = Vec::new();
    file.take(MAX_LOG_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| LogFileError::Read)?;
    if bytes.len() > MAX_LOG_BYTES {
        return Err(LogFileError::TooLarge);
    }
    String::from_utf8(bytes).map_err(|_| LogFileError::NotUtf8)
}
