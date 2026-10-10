//! 構造化ログ 1 行の整形と照合器（GPU-6・TASK-172.4）。
//!
//! ログは数値と固定語彙だけを出し、ゲストのバイト列や文字列をエコーしない（ログ注入の防止）。
//! 照合器は実機前提テスト（`tests/real_machine_capset_log.rs`）が使い、入力の行長・行数・総量に上限を設ける。
//!
//! 書き出し側の [`LogSink`] は起動 bin（`launch`。#1598）が使い、照合器の上限に収まるよう総量・行長・行数を抑える（REPAIR-5）。
//! 読み取り側の [`read_log_file`] は通常ファイル以外を open 前に拒否する（FIFO で open が止まるのを防ぐ。事後監査 #1528 D2）。
//! Unix では open 後に `dev` / `ino` を open 前の値と比べ、間に別のファイルへ差し替えられたものを拒否する（事後監査 PR #1611）。

use std::fs;
use std::io::{self, Read, Write};
use std::path::Path;

use crate::recording::{RecordSummary, StopReason};

/// ログ全体の上限（バイト）。
pub const MAX_LOG_BYTES: usize = 4 * 1024 * 1024;
/// 1 行の上限（バイト）。超えた行は壊れた行として数える。
pub const MAX_LINE_BYTES: usize = 512;
/// 行数の上限。
pub const MAX_LINES: usize = 100_000;
/// 優先行（[`LogSink::write_priority`]）のために通常行から取り置くバイト数。
pub const PRIORITY_RESERVE_BYTES: usize = 2048;
/// 優先行のために通常行から取り置く行数。
pub const PRIORITY_RESERVE_LINES: usize = 8;

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
    /// 資源表または ctx 表が上限（`ERR_OUT_OF_MEMORY`）。
    OutOfMemory,
    /// resource_id が 0・重複・未作成（`ERR_INVALID_RESOURCE_ID`）。
    InvalidResourceId,
}

impl QueryResult {
    fn word(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::InvalidParameter => "invalid_parameter",
            Self::Unspec => "unspec",
            Self::InvalidContextId => "invalid_context_id",
            Self::OutOfMemory => "out_of_memory",
            Self::InvalidResourceId => "invalid_resource_id",
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

/// `RESOURCE_CREATE_BLOB` のログ行。復号できなかった値は -1。`blob_id` は出さない。
pub fn resource_create_blob_line(
    ctx_id: u32,
    req: Option<&crate::ctrl::ResourceCreateBlob>,
    result: QueryResult,
) -> String {
    format!(
        "venus_jig event=resource cmd=RESOURCE_CREATE_BLOB ctx_id={ctx_id} res_id={} blob_mem={} blob_flags={} size={} result={}",
        req.map_or(-1, |c| i128::from(c.res_id)),
        req.map_or(-1, |c| i128::from(c.blob_mem)),
        req.map_or(-1, |c| i128::from(c.blob_flags)),
        req.map_or(-1, |c| i128::from(c.size)),
        result.word()
    )
}

/// `CTX_ATTACH_RESOURCE` / `CTX_DETACH_RESOURCE` のログ行（`cmd` は呼び出し側の固定語彙）。
pub fn ctx_resource_line(
    cmd: &'static str,
    ctx_id: u32,
    res_id: Option<u32>,
    result: QueryResult,
) -> String {
    format!(
        "venus_jig event=resource cmd={cmd} ctx_id={ctx_id} res_id={} result={}",
        res_id.map_or(-1, i64::from),
        result.word()
    )
}

/// `RESOURCE_UNREF` のログ行。
pub fn resource_unref_line(res_id: Option<u32>, result: QueryResult) -> String {
    format!(
        "venus_jig event=resource cmd=RESOURCE_UNREF res_id={} result={}",
        res_id.map_or(-1, i64::from),
        result.word()
    )
}

/// `RESOURCE_MAP_BLOB` のログ行（F5.2b.4a・#1643）。数値と固定語彙のみ。復号できなかった値と、成功以外の `map_info` は -1 で出す。
pub fn resource_map_blob_line(
    res_id: Option<u32>,
    offset: Option<u64>,
    size: Option<u64>,
    map_info: Option<u32>,
    result: QueryResult,
) -> String {
    format!(
        "venus_jig event=resource cmd=RESOURCE_MAP_BLOB res_id={} offset={} size={} map_info={} result={}",
        res_id.map_or(-1, i128::from),
        offset.map_or(-1, i128::from),
        size.map_or(-1, i128::from),
        map_info.map_or(-1, i128::from),
        result.word()
    )
}

/// `RESOURCE_UNMAP_BLOB` のログ行（[`resource_map_blob_line`] から `map_info` を除いた形）。
pub fn resource_unmap_blob_line(
    res_id: Option<u32>,
    offset: Option<u64>,
    size: Option<u64>,
    result: QueryResult,
) -> String {
    format!(
        "venus_jig event=resource cmd=RESOURCE_UNMAP_BLOB res_id={} offset={} size={} result={}",
        res_id.map_or(-1, i128::from),
        offset.map_or(-1, i128::from),
        size.map_or(-1, i128::from),
        result.word()
    )
}

/// `SUBMIT_3D` のログ行の材料。本体のバイト列は含めない（数値と固定語彙のみ）。
#[derive(Debug, Clone, Copy)]
pub struct Submit3dLog {
    /// ヘッダの ctx_id。
    pub ctx_id: u32,
    /// `INFO_RING_IDX` が立つときだけ入る ring_idx（無ければ -1 で出す）。
    pub ring_idx: Option<u8>,
    /// `size` フィールド（復号できなければ -1）。
    pub size: Option<u32>,
    /// 本体先頭の venus コマンド種別の生値（解析できなければ -1）。
    pub venus_cmd: Option<u32>,
    /// 本体ヘッダ検査の結果の固定語彙（`ok` / `empty` / `none` / `venus_wire.*`）。
    pub wire: &'static str,
    /// 応答の結果。
    pub result: QueryResult,
}

/// `SUBMIT_3D` のログ行。
pub fn submit_3d_line(l: &Submit3dLog) -> String {
    format!(
        "venus_jig event=submit_3d cmd=SUBMIT_3D ctx_id={} ring_idx={} size={} venus_cmd={} wire={} result={}",
        l.ctx_id,
        l.ring_idx.map_or(-1, i64::from),
        l.size.map_or(-1, i64::from),
        l.venus_cmd.map_or(-1, i64::from),
        l.wire,
        l.result.word()
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

/// セッション終了時の blob の片づけの集計行（#1645）。数値だけを出す（ゲスト・frontend 由来のバイト列や fd 番号は出さない）。
/// `mapped` は片づけ前の map 中の件数、`unmapped` は frontend が 0 を返した `SHMEM_UNMAP` の件数、`memfds` は閉じた memfd の数。
/// 照合器（`find_capset_queries`）では `Other` に分類され、壊れた行に数えられない。
pub fn blob_release_line(mapped: usize, unmapped: usize, memfds: usize) -> String {
    format!("venus_jig event=blob_release mapped={mapped} unmapped={unmapped} memfds={memfds}")
}

/// REPLY_ACK 確定後に、NEED_REPLY が付いた要求へ ack を返したことを示すログ行（#1639）。固定語彙と要求 ID だけを出す。
pub fn need_reply_ack_line(request: u32, ok: bool) -> String {
    let result = if ok { "ok" } else { "err" };
    format!("venus_jig event=need_reply_ack request={request} result={result}")
}

/// `NEED_REPLY` が付いた `SET_*` に応答しなかった（REPLY_ACK が確定していないセッション）ことを示すログ行。
pub fn need_reply_ignored_line(request: u32) -> String {
    format!("venus_jig event=need_reply_ignored request={request}")
}

/// `GET_SHMEM_CONFIG` に答えたことを示すログ行（#1641）。固定語彙と数値だけを出す。
pub fn shmem_config_line(nregions: u32, shmid: u8, size: u64) -> String {
    format!("venus_jig event=shmem_config request=44 nregions={nregions} shmid={shmid} size={size}")
}

/// `SET_BACKEND_REQ_FD` を受理した（UDS を保持した）ことを示すログ行（#1641）。fd 番号は出さない。
pub fn backend_req_line() -> String {
    "venus_jig event=backend_req request=21 result=accepted".to_string()
}

/// backend 要求（`SHMEM_MAP` / `SHMEM_UNMAP`）の結果（#1642）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendReqOutcome<'a> {
    /// frontend が 0 を返した。
    Ok,
    /// frontend が非 0 を返した（u64 を 10 進で出す。`-errno as u64` もそのまま）。
    Status(u64),
    /// 治具側の失敗（固定語彙の code。`TIMEOUT` など）。
    Code(&'a str),
}

/// backend 要求を送った結果のログ行（#1642）。固定語彙と数値だけを出し、fd 番号・frontend 由来のバイト列は出さない。
/// `backend_req_line`（`request=21`。frontend 要求 `SET_BACKEND_REQ_FD` の受理）とはキー（`cmd=`）で区別する。
pub fn backend_req_result_line(
    cmd: &str,
    shmid: u8,
    shm_offset: u64,
    len: u64,
    outcome: BackendReqOutcome<'_>,
) -> String {
    let tail = match outcome {
        BackendReqOutcome::Ok => "result=ok status=0".to_string(),
        BackendReqOutcome::Status(v) => format!("result=err status={v}"),
        BackendReqOutcome::Code(c) => format!("result=err code={c}"),
    };
    format!(
        "venus_jig event=backend_req cmd={cmd} shmid={shmid} shm_offset={shm_offset} len={len} {tail}"
    )
}

/// セッション終了時の host-visible 共有メモリの成立状況（#1641）。`status` は固定語彙（`ready` ほか）。
pub fn host_visible_line(status: &str) -> String {
    format!("venus_jig event=host_visible status={status}")
}

/// writable の容量が応答に足りず、応答を書かずに len=0 で返したことを示すログ行。
pub fn response_dropped_line() -> String {
    "venus_jig event=response_dropped reason=writable_too_small".to_string()
}

/// セッションが正常終了（frontend がメッセージ境界で切断）したときのログ行。
pub fn session_end_line() -> String {
    "venus_jig event=session_end result=peer_closed".to_string()
}

/// 記録（`--record`）が上限で止まったことを示すログ行。理由は固定語彙、件数は数値だけを出す（パスは出さない）。
/// 照合器（`find_capset_queries`）では `Other` に分類され、壊れた行に数えられない。停止ごとに 1 回だけ出る。
pub fn record_stopped_line(reason: StopReason, records: u32) -> String {
    format!(
        "venus_jig event=record_stopped reason={} records={records}",
        reason.as_str()
    )
}

/// 打ち切り後も [`LogSink::write_priority`] で書く行か（記録の停止通知・集計・起動エラー）。`event=` の値が固定語彙と
/// 完全一致するときだけ真（`record_stopped_x` のような接頭辞一致は優先しない）。
pub fn is_priority_line(line: &str) -> bool {
    let Some(rest) = line.strip_prefix("venus_jig event=") else {
        return false;
    };
    let event = rest.split(' ').next().unwrap_or_default();
    matches!(event, "record_stopped" | "record_summary" | "launch_error")
}

/// 終了時の記録の集計行。`write_ok` が偽なら `result=write_failed`（書き出しの失敗を成功と装わない）。
/// 照合器では `Other` に分類される。
pub fn record_summary_line(summary: &RecordSummary, write_ok: bool) -> String {
    format!(
        "venus_jig event=record_summary records={} skipped={} stopped={} result={}",
        summary.records,
        summary.skipped,
        summary.stopped.map_or("none", StopReason::as_str),
        if write_ok { "ok" } else { "write_failed" }
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
            && self.bytes + need + reserve + PRIORITY_RESERVE_BYTES <= MAX_LOG_BYTES
            && self.lines + 2 + PRIORITY_RESERVE_LINES <= MAX_LINES;
        if fits {
            self.put(line, need);
        } else {
            self.truncated = true;
            let t = log_truncated_line();
            let n = t.len() + 1;
            self.put(&t, n);
        }
    }

    /// 打ち切り後も届く優先行（記録の停止通知・集計・起動エラー）を書く。通常行が取り置いた領域だけを使い、
    /// 領域も尽きたとき・不正な行（長すぎる・改行を含む）は捨てる（REPAIR-4）。
    pub fn write_priority(&mut self, line: &str) {
        let need = line.len() + 1;
        let fits = self.error.is_none()
            && line.len() <= MAX_LINE_BYTES
            && !line.contains(['\n', '\r'])
            && self.bytes + need <= MAX_LOG_BYTES
            && self.lines < MAX_LINES;
        if fits {
            self.put(line, need);
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
    /// open 前に確かめたファイルと open したファイルが違う（`dev` / `ino` の不一致。間に rename や symlink で
    /// 差し替えられた。Unix のみ検出する）。
    Replaced,
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
/// (2) open する。(3) 開いた fd の `metadata` で通常ファイルであることと、Unix では `dev` / `ino` が (1) と同じであること
/// （間に別のファイルへ rename・symlink で差し替えられていないこと。不一致は `Replaced`）を確かめ、サイズ上限を見る。
/// (4) `MAX_LOG_BYTES + 1` で打ち切って読む。
/// 限界: (1) と (2) の間に FIFO へ差し替えられると (2) の open が止まり、(3) の照合まで進まない（`O_NONBLOCK` /
/// `O_NOFOLLOW` の値はアーキごとに異なり、ここでは扱わない）。呼び出し側は読み取りを期限つきで待つこと（REPAIR-5）。
/// Unix 以外は std の stable API にファイルの同一性（`dev` / `ino` 相当）が無いため (3) の同一性の照合をしない。
pub fn read_log_file(path: &Path) -> Result<String, LogFileError> {
    read_log_file_with(path, || {})
}

/// [`read_log_file`] の本体。`between` は (1) と (2) の間に呼ばれ、差し替えの試験だけが中身を渡す（本番は空）。
pub(crate) fn read_log_file_with(
    path: &Path,
    between: impl FnOnce(),
) -> Result<String, LogFileError> {
    let before = fs::symlink_metadata(path).map_err(|_| LogFileError::Open)?;
    if !before.file_type().is_file() {
        return Err(LogFileError::NotRegularFile);
    }
    between();
    let file = fs::File::open(path).map_err(|_| LogFileError::Open)?;
    let meta = file.metadata().map_err(|_| LogFileError::Open)?;
    if !meta.file_type().is_file() {
        return Err(LogFileError::NotRegularFile);
    }
    if !same_file(&before, &meta) {
        return Err(LogFileError::Replaced);
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

/// open 前（`symlink_metadata`）と open 後（fd の `metadata`）が同じファイルか（`dev` と `ino` の一致）。
#[cfg(unix)]
fn same_file(before: &fs::Metadata, after: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    before.dev() == after.dev() && before.ino() == after.ino()
}

/// Unix 以外は同一性を確かめる stable API が無いので照合しない（[`read_log_file`] の限界。実装済みを装わない）。
#[cfg(not(unix))]
fn same_file(_before: &fs::Metadata, _after: &fs::Metadata) -> bool {
    true
}
