//! stream-exec helper の fd 2（診断の受け口）を上限つきで読み、固定語彙の構造化ログへ転送する（CRI-6・SUP-6・SEC-1・
//! REPAIR-4・REPAIR-5・#4171）。
//!
//! 役割: 本番の helper 起動口（`ProductionHelperSpawner`）が helper の stderr に渡した socketpair の plugin 側の端を、
//! helper 1 本につき 1 本の読み手スレッドで読む。helper・supervisor・core が fd 2 へ出す診断の構造化行
//! （起動失敗の段名・errno の縮退理由など）を、後から原因を追えるように plugin-cri の構造化ログ
//! （`telemetry::LineSink`。共有の stderr sink）へ出す。呼び出し元は `exec_launcher::SupervisorExecLauncher`
//! の起動処理と、終了時の `wait_diagnostics_idle`（`main.rs`）。
//!
//! # 「pipe」ではなく AF_UNIX の socketpair を使う理由
//! core の診断出力 `emit_diagnostic_line_to` は、書き込み先が AF_UNIX の socket のときだけ `send(MSG_DONTWAIT)` し、
//! pipe・FIFO・ファイル・端末へは書かない（`exec/diagnostic.rs` の表。#1697）。fd 2 を pipe にすると、本機能が拾いたい
//! core・supervisor の行がすべて捨てられる。そのため issue 本文の「pipe」は socketpair（`UnixStream::pair`。CLOEXEC）で
//! 実現した。副次効果として core は読み手が遅くても待たずに捨てる。
//!
//! # 上限（定数）
//! 1 行 [`DIAG_MAX_LINE_BYTES`]（改行を含む）・解析対象 [`DIAG_MAX_LINES`] 行・総 [`DIAG_MAX_TOTAL_BYTES`]。超えた分は読み捨て
//! （読むのはやめない。やめると socket の送信側が埋まり helper の同期書き込みが止まるため）、捨てた行数・バイト数を数える。
//! メモリは固定長（行バッファ 1 つ + 読み取り chunk）で入力量に比例しない。
//!
//! # 転送の規則（SEC-1）
//! 出力へ写すのは、閉じた語彙（core の `ExecChildStep`・`IsolationStage`・`ErrorCode`・errno 名の表など）で引き直した
//! `&'static str` と整数だけ。helper 由来のバイト列は出力へ写さない（ログ注入・argv・トークン・コンテナ ID・入出力の
//! 漏えいは構造上起きない）。解釈できない行は内容を出さず件数だけ数える。失敗の欄（stage・errno・code）を持たない
//! 語彙内の行（毎回の exec で出る `entrypoint_mode` など）は出さずに件数だけ数える。
//!
//! # 停止（REPAIR-5）
//! 読み手は `read_timeout`（[`DIAG_POLL`]）刻みで停止フラグと絶対期限を確かめる。helper の kill・セッションの drop・
//! `shutdown_all` は `HelperGuard::kill` が停止フラグを立てる。EOF に頼らない（fork した exec の worker は書き込み端を
//! 継承しうるため、helper を kill しても EOF にならないことがある）。停止後は [`DIAG_STOP_DRAIN`] だけ残りを読んで終える。
//!
//! # 残余（REPAIR-3）
//! - 現状、`stage=… errno=N` の形（本ファイルが受け入れる文法）を fd 2 へ出す生成側は supervisor・core には無い。
//!   子の段の失敗は `Result` frame の `NotStarted` で返る。#4172 で確認した結果、helper が fd 2 へ書くのは
//!   「fd 0 が socket でない」「要求元の消滅で取り消した」の 2 行（`code` と `message` だけ）で、状態の不一致・kind 6 の
//!   失敗・stdio の受け取りの失敗は `Failed(code)` の `Result` frame だけで返り、errno はどこにも運ばれない。この現状を
//!   `tests/exec_helper_failure_diag.rs` が実 helper のコードで具体値に固定している（生成側が入ったら期待値を直す）。
//!   生成側の追加（制御クライアントへの errno の受け渡し・helper の段の語彙・本ファイルの分類語彙の拡張）は後続 issue で扱う。
//! - seccomp の集計行（`event` つき）は語彙を公開していないため、解釈できない行（unparsed）として数える。
//! - 停止後の drain 上限を超えて残った診断は失う（要約の `end` は `stopped`）。

use std::io::Read as _;
use std::os::unix::net::UnixStream as StdUnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::time::{Duration, Instant};

use fandhe_container_core::exec::SealedCopyUnavailable;
use fandhe_container_core::exec::{EntrypointExecMode, ExecChildStep, IsolationStage};
use fandhe_container_core::traits::ErrorCode;

use crate::telemetry::LineSink;

/// 1 行の上限（末尾の改行を含むバイト数）。
pub const DIAG_MAX_LINE_BYTES: usize = 512;

/// helper 1 本あたり、解析の対象にする行数の上限。
pub const DIAG_MAX_LINES: usize = 32;

/// helper 1 本あたり、解析の対象にする行の総バイト数（改行を含む）の上限。
pub const DIAG_MAX_TOTAL_BYTES: usize = 8 * 1024;

/// 停止フラグと期限を確かめる刻み（`set_read_timeout` の値）。
pub const DIAG_POLL: Duration = Duration::from_millis(100);

/// 停止を見た後、socket のバッファに残った分を読む上限。
pub const DIAG_STOP_DRAIN: Duration = Duration::from_millis(50);

/// 終了時に読み手の完了を待つ上限（`main.rs` が `wait_diagnostics_idle` に渡す）。
pub const DIAG_JOIN_BUDGET: Duration = Duration::from_millis(500);

/// 読み取りの chunk（スタック上の固定長）。
const READ_CHUNK: usize = 4096;

/// 受け入れる要素数の上限（1 行あたり）。
const MAX_PAIRS: usize = 12;

/// 転送する errno の名前の表（core の `pidfd_errno_name` と diagnostic の `errno_name` を含む閉じた集合）。
const ERRNO_NAMES: [&str; 24] = [
    "EPERM",
    "ENOENT",
    "ESRCH",
    "EINTR",
    "EIO",
    "EBADF",
    "ENOMEM",
    "EACCES",
    "EFAULT",
    "EBUSY",
    "EEXIST",
    "ENOTDIR",
    "EINVAL",
    "ENFILE",
    "EMFILE",
    "ENOSPC",
    "EPIPE",
    "ERANGE",
    "ENOSYS",
    "ELOOP",
    "ENAMETOOLONG",
    "EAGAIN",
    "ECONNREFUSED",
    "other",
];

const COMPONENTS: [&str; 3] = ["core.exec", "supervisor.exec", "supervisor"];
const OPERATIONS: [&str; 2] = ["launch_pidfd", "entrypoint_mode"];
const OUTCOMES: [&str; 1] = ["unavailable"];
const PIDFD_REASONS: [&str; 3] = ["denied", "failed", "unsupported"];
const MODES: [&str; 2] = ["sealed_copy", "pinned_inode"];

/// errno の値（数値か固定語彙名）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Errno {
    Num(u16),
    Name(&'static str),
}

/// 解釈できた欄（すべて静的な値か整数）。
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct Fields {
    component: Option<&'static str>,
    operation: Option<&'static str>,
    outcome: Option<&'static str>,
    reason: Option<&'static str>,
    mode: Option<&'static str>,
    code: Option<&'static str>,
    stage: Option<&'static str>,
    errno: Option<Errno>,
}

/// 1 行の分類結果。
#[derive(Debug, Clone, PartialEq, Eq)]
enum Classified {
    /// 組み直した 1 行を出す。
    Forwarded(String),
    /// 語彙内だが失敗の欄を持たない。出さずに数える。
    Ignored,
    /// 解釈できない。内容を出さずに数える。
    Unparsed,
}

/// 値の種別（JSON の数値か、文字列か）。
#[derive(Clone, Copy)]
enum Raw<'a> {
    Str(&'a str),
    Num(u64),
}

fn is_text_value_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-')
}

/// 平坦な JSON オブジェクト（エスケープ無しの文字列か符号なし整数の値だけ）を要素の列へ分解する。
fn split_json(body: &str) -> Option<Vec<(&str, Raw<'_>)>> {
    let b = body.as_bytes();
    let mut i = 0usize;
    let skip_ws = |i: &mut usize| {
        while b.get(*i) == Some(&b' ') {
            *i += 1;
        }
    };
    let mut out = Vec::new();
    skip_ws(&mut i);
    if b.get(i) != Some(&b'{') {
        return None;
    }
    i += 1;
    loop {
        skip_ws(&mut i);
        if b.get(i) == Some(&b'}') {
            i += 1;
            break;
        }
        if !out.is_empty() {
            if b.get(i) != Some(&b',') {
                return None;
            }
            i += 1;
            skip_ws(&mut i);
        }
        if out.len() >= MAX_PAIRS || b.get(i) != Some(&b'"') {
            return None;
        }
        i += 1;
        let ks = i;
        while b
            .get(i)
            .is_some_and(|c| c.is_ascii_alphanumeric() || *c == b'_')
        {
            i += 1;
        }
        let key = body.get(ks..i)?;
        if key.is_empty() || b.get(i) != Some(&b'"') {
            return None;
        }
        i += 1;
        skip_ws(&mut i);
        if b.get(i) != Some(&b':') {
            return None;
        }
        i += 1;
        skip_ws(&mut i);
        let value = if b.get(i) == Some(&b'"') {
            i += 1;
            let vs = i;
            while b.get(i).is_some_and(|c| *c != b'"') {
                i += 1;
            }
            if b.get(i) != Some(&b'"') {
                return None;
            }
            let v = body.get(vs..i)?;
            i += 1;
            Raw::Str(v)
        } else {
            let vs = i;
            while b.get(i).is_some_and(u8::is_ascii_digit) {
                i += 1;
            }
            let digits = body.get(vs..i)?;
            if digits.is_empty() || digits.len() > 10 {
                return None;
            }
            Raw::Num(digits.parse().ok()?)
        };
        out.push((key, value));
    }
    skip_ws(&mut i);
    if i != b.len() {
        return None;
    }
    Some(out)
}

/// 空白区切りの `key=value`（値は `[A-Za-z0-9_.-]+`）を要素の列へ分解する。
fn split_text(line: &str) -> Option<Vec<(&str, Raw<'_>)>> {
    let mut out = Vec::new();
    for tok in line.split_ascii_whitespace() {
        let (k, v) = tok.split_once('=')?;
        if out.len() >= MAX_PAIRS
            || k.is_empty()
            || !k.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_')
            || v.is_empty()
            || !v.bytes().all(is_text_value_char)
        {
            return None;
        }
        out.push((k, Raw::Str(v)));
    }
    Some(out)
}

/// 正規形（大文字・`_` 区切り）と受信トークン（大文字 `_` 表記、または小文字 `-` 表記）の一致判定。
fn code_token_eq(canonical: &str, token: &str) -> bool {
    let upper = canonical == token;
    let lower_hyphen = canonical.len() == token.len()
        && canonical.bytes().zip(token.bytes()).all(|(c, t)| {
            if c == b'_' {
                t == b'-'
            } else {
                t == c.to_ascii_lowercase()
            }
        });
    upper || lower_hyphen
}

fn pick(set: &[&'static str], v: &str) -> Option<&'static str> {
    set.iter().copied().find(|s| *s == v)
}

fn parse_errno(raw: Raw<'_>) -> Option<Errno> {
    let num = |n: u64| u16::try_from(n).ok().filter(|n| (1..=4095).contains(n));
    match raw {
        Raw::Num(n) => num(n).map(Errno::Num),
        Raw::Str(s) if !s.is_empty() && s.bytes().all(|c| c.is_ascii_digit()) => {
            if s.len() > 5 {
                return None;
            }
            num(s.parse().ok()?).map(Errno::Num)
        }
        Raw::Str(s) => pick(&ERRNO_NAMES, s).map(Errno::Name),
    }
}

fn parse_reason(v: &str) -> Option<&'static str> {
    if let Some(r) = pick(&PIDFD_REASONS, v) {
        return Some(r);
    }
    SealedCopyUnavailable::ALL
        .iter()
        .map(|r| r.as_str())
        .find(|s| *s == v)
}

/// 1 行（改行を除く）を分類する。純関数。
fn classify(line: &[u8]) -> Classified {
    if line.is_empty() || !line.iter().all(|b| b.is_ascii_graphic() || *b == b' ') {
        return Classified::Unparsed;
    }
    let Ok(text) = std::str::from_utf8(line) else {
        return Classified::Unparsed;
    };
    let pairs = if text.trim_start().starts_with('{') {
        // JSON の値のバックスラッシュ（エスケープ）は受けない。
        if text.contains('\\') {
            return Classified::Unparsed;
        }
        split_json(text)
    } else {
        split_text(text)
    };
    let Some(pairs) = pairs else {
        return Classified::Unparsed;
    };
    if pairs.is_empty() {
        return Classified::Unparsed;
    }
    let mut f = Fields::default();
    let mut seen: Vec<&str> = Vec::new();
    for (k, v) in pairs {
        if seen.contains(&k) {
            return Classified::Unparsed;
        }
        seen.push(k);
        let s = match v {
            Raw::Str(s) => Some(s),
            Raw::Num(_) => None,
        };
        let ok = match k {
            "stage" => s
                .and_then(|s| {
                    ExecChildStep::from_token(s)
                        .map(ExecChildStep::as_str)
                        .or_else(|| IsolationStage::from_token(s).map(IsolationStage::as_str))
                })
                .map(|v| f.stage = Some(v))
                .is_some(),
            "errno" => parse_errno(v).map(|e| f.errno = Some(e)).is_some(),
            "code" => s
                .and_then(|s| {
                    // 大文字の `ErrorCode::as_str()` 表記と、helper の `diagnose()` が出す小文字ハイフン表記の両方を受け、
                    // 閉じた語彙（`ErrorCode::ALL`）の正規形へ引き直す。
                    ErrorCode::ALL
                        .iter()
                        .map(|c| c.as_str())
                        .find(|n| code_token_eq(n, s))
                })
                .map(|v| f.code = Some(v))
                .is_some(),
            "component" => s
                .and_then(|s| pick(&COMPONENTS, s))
                .map(|v| f.component = Some(v))
                .is_some(),
            "operation" => s
                .and_then(|s| pick(&OPERATIONS, s))
                .map(|v| f.operation = Some(v))
                .is_some(),
            "outcome" => s
                .and_then(|s| pick(&OUTCOMES, s))
                .map(|v| f.outcome = Some(v))
                .is_some(),
            "reason" => s
                .and_then(|s| {
                    if s.is_empty() || s == "-" {
                        Some("")
                    } else {
                        parse_reason(s)
                    }
                })
                .map(|v| f.reason = Some(v))
                .is_some(),
            "mode" => s
                .and_then(|s| pick(&MODES, s))
                .map(|v| f.mode = Some(v))
                .is_some(),
            // helper の `diagnose()` の形（`code` と `message`）を受けるため、文字列のときだけ受けて値は捨てる。
            "message" => s.is_some(),
            _ => false,
        };
        if !ok {
            return Classified::Unparsed;
        }
    }
    // 方式と理由の組は core の復号で検証する（`sealed_copy` の理由は空）。
    if let Some(mode) = f.mode {
        let reason = f.reason.unwrap_or("");
        let token = if reason.is_empty() { "-" } else { reason };
        if EntrypointExecMode::from_tokens(mode, token).is_none() {
            return Classified::Unparsed;
        }
    }
    if f.stage.is_none() && f.errno.is_none() && f.code.is_none() {
        return Classified::Ignored;
    }
    Classified::Forwarded(render(&f))
}

/// 欄を固定順で 1 行にする。`&'static str` と整数だけで組む（ログ注入不可）。
fn render(f: &Fields) -> String {
    let mut s = String::from("{\"event\":\"cri_exec_helper_diagnostic\"");
    let strs = [
        ("component", f.component),
        ("operation", f.operation),
        ("outcome", f.outcome),
        ("reason", f.reason.filter(|r| !r.is_empty())),
        ("mode", f.mode),
        ("code", f.code),
        ("stage", f.stage),
    ];
    for (k, v) in strs {
        if let Some(v) = v {
            s.push_str(&format!(",\"{k}\":\"{v}\""));
        }
    }
    match f.errno {
        Some(Errno::Num(n)) => s.push_str(&format!(",\"errno\":{n}")),
        Some(Errno::Name(n)) => s.push_str(&format!(",\"errno\":\"{n}\"")),
        None => {}
    }
    s.push('}');
    s
}

/// 読み取りの件数（解析・転送・捨てた分）。
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct DiagStats {
    /// 転送した行数。
    pub forwarded: u64,
    /// 語彙内で失敗の欄が無く、出さずに数えた行数。
    pub ignored: u64,
    /// 解釈できず、内容を出さずに数えた行数。
    pub unparsed: u64,
    /// 上限超過で読み捨てた行数。
    pub dropped_lines: u64,
    /// 上限超過で読み捨てたバイト数（改行を含む）。
    pub dropped_bytes: u64,
}

/// 到着順に chunk を受けて行へ区切り、上限と分類を適用する状態機械（I/O を持たない）。
pub struct DiagCounter {
    line: Vec<u8>,
    skipping: bool,
    lines_used: usize,
    bytes_used: usize,
    stats: DiagStats,
}

impl Default for DiagCounter {
    fn default() -> Self {
        Self::new()
    }
}

impl DiagCounter {
    /// 空の状態で作る。行バッファは [`DIAG_MAX_LINE_BYTES`] を 1 回だけ確保する。
    pub fn new() -> Self {
        Self {
            line: Vec::with_capacity(DIAG_MAX_LINE_BYTES),
            skipping: false,
            lines_used: 0,
            bytes_used: 0,
            stats: DiagStats::default(),
        }
    }

    /// chunk を渡す。転送する行ができるたびに `emit` を呼ぶ。chunk の境界をまたぐ行も扱う。
    pub fn feed(&mut self, chunk: &[u8], emit: &mut dyn FnMut(String)) {
        for &b in chunk {
            if self.skipping {
                self.stats.dropped_bytes = self.stats.dropped_bytes.saturating_add(1);
                if b == b'\n' {
                    self.stats.dropped_lines = self.stats.dropped_lines.saturating_add(1);
                    self.skipping = false;
                }
                continue;
            }
            if b == b'\n' {
                let n = self.line.len() + 1;
                self.complete(n, emit);
                self.line.clear();
            } else if self.line.len() + 1 >= DIAG_MAX_LINE_BYTES {
                // 改行を含めて上限を超える。ここまでの分と今の 1 バイトを数え、改行まで読み飛ばす。
                self.stats.dropped_bytes = self
                    .stats
                    .dropped_bytes
                    .saturating_add(self.line.len() as u64 + 1);
                self.line.clear();
                self.skipping = true;
            } else {
                self.line.push(b);
            }
        }
    }

    fn complete(&mut self, n: usize, emit: &mut dyn FnMut(String)) {
        if self.lines_used >= DIAG_MAX_LINES || self.bytes_used + n > DIAG_MAX_TOTAL_BYTES {
            self.stats.dropped_lines = self.stats.dropped_lines.saturating_add(1);
            self.stats.dropped_bytes = self.stats.dropped_bytes.saturating_add(n as u64);
            return;
        }
        self.lines_used += 1;
        self.bytes_used += n;
        match classify(&self.line) {
            Classified::Forwarded(l) => {
                self.stats.forwarded = self.stats.forwarded.saturating_add(1);
                emit(l);
            }
            Classified::Ignored => self.stats.ignored = self.stats.ignored.saturating_add(1),
            Classified::Unparsed => self.stats.unparsed = self.stats.unparsed.saturating_add(1),
        }
    }

    /// 入力の終わり。改行の無い末尾の断片を数えて件数を返す。
    pub fn finish(&mut self) -> DiagStats {
        if self.skipping {
            self.stats.dropped_lines = self.stats.dropped_lines.saturating_add(1);
            self.skipping = false;
        } else if !self.line.is_empty() {
            self.stats.unparsed = self.stats.unparsed.saturating_add(1);
        }
        self.line.clear();
        self.stats
    }
}

/// 読み手が終わった理由。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiagEnd {
    /// helper 側の全ての書き込み端が閉じた。
    Eof,
    /// 停止フラグ（helper の kill・セッションの終了・`shutdown_all`）で止めた。
    Stopped,
    /// 絶対期限に達した。
    Deadline,
    /// 読み取りが errno で失敗した。
    ReadError,
}

impl DiagEnd {
    fn as_str(self) -> &'static str {
        match self {
            Self::Eof => "eof",
            Self::Stopped => "stopped",
            Self::Deadline => "deadline",
            Self::ReadError => "read_error",
        }
    }
}

/// 終了時の要約行。出すのは、解釈できない行・捨てた行があるとき、または期限切れ・読み取り失敗のときだけ。
fn summary_line(end: DiagEnd, s: &DiagStats) -> Option<String> {
    let abnormal = matches!(end, DiagEnd::Deadline | DiagEnd::ReadError);
    if s.unparsed == 0 && s.dropped_lines == 0 && !abnormal {
        return None;
    }
    Some(format!(
        "{{\"event\":\"cri_exec_helper_diagnostics\",\"outcome\":\"error\",\"end\":\"{}\",\"forwarded\":{},\"ignored\":{},\"unparsed\":{},\"dropped_lines\":{},\"dropped_bytes\":{}}}",
        end.as_str(),
        s.forwarded,
        s.ignored,
        s.unparsed,
        s.dropped_lines,
        s.dropped_bytes
    ))
}

/// 読み手を作れなかったときの 1 行（観測は最善努力で、exec は失敗にしない）。
pub fn reader_unavailable_line() -> String {
    "{\"event\":\"cri_exec_helper_diagnostics\",\"outcome\":\"error\",\"reason\":\"reader_unavailable\"}"
        .to_string()
}

/// 動いている読み手の数。終了時に上限つきで完了を待つ（REPAIR-5）。
#[derive(Default)]
pub struct DiagTracker {
    active: Mutex<usize>,
    idle: Condvar,
}

struct DiagGuard(Arc<DiagTracker>);

impl Drop for DiagGuard {
    fn drop(&mut self) {
        let mut n = self.0.active.lock().unwrap_or_else(PoisonError::into_inner);
        *n = n.saturating_sub(1);
        self.0.idle.notify_all();
    }
}

impl DiagTracker {
    fn enter(self: &Arc<Self>) -> DiagGuard {
        let mut n = self.active.lock().unwrap_or_else(PoisonError::into_inner);
        *n += 1;
        DiagGuard(Arc::clone(self))
    }

    /// 全ての読み手が終わるまで最大 `timeout` 待ち、残った数を返す。
    pub fn wait_idle(&self, timeout: Duration) -> usize {
        let deadline = Instant::now() + timeout;
        let mut n = self.active.lock().unwrap_or_else(PoisonError::into_inner);
        while *n > 0 {
            let now = Instant::now();
            if now >= deadline {
                break;
            }
            let (g, _) = self
                .idle
                .wait_timeout(n, deadline - now)
                .unwrap_or_else(PoisonError::into_inner);
            n = g;
        }
        *n
    }
}

/// 読み手スレッドを 1 本起動する。作れなければ `Err`（`sock` は閉じる）。
pub fn spawn_reader(
    sock: StdUnixStream,
    stop: Arc<AtomicBool>,
    deadline: Instant,
    sink: LineSink,
    tracker: &Arc<DiagTracker>,
) -> std::io::Result<()> {
    let _ = sock.shutdown(std::net::Shutdown::Write);
    sock.set_read_timeout(Some(DIAG_POLL))?;
    let guard = tracker.enter();
    std::thread::Builder::new()
        .name("exec-diag".to_string())
        .spawn(move || {
            let _guard = guard;
            run_reader(sock, &stop, deadline, &sink);
        })
        .map(|_| ())
}

fn run_reader(mut sock: StdUnixStream, stop: &AtomicBool, deadline: Instant, sink: &LineSink) {
    let mut counter = DiagCounter::new();
    let mut buf = [0u8; READ_CHUNK];
    let mut end: Option<DiagEnd> = None;
    let mut drain_until: Option<Instant> = None;
    let mut emit = |line: String| {
        let _ = sink.submit(line);
    };
    let end = loop {
        let now = Instant::now();
        if drain_until.is_none() {
            if stop.load(Ordering::SeqCst) {
                end = Some(DiagEnd::Stopped);
                drain_until = Some(now + DIAG_STOP_DRAIN);
            } else if now >= deadline {
                end = Some(DiagEnd::Deadline);
                drain_until = Some(now + DIAG_STOP_DRAIN);
            }
        }
        if drain_until.is_some_and(|d| now >= d) {
            break end.unwrap_or(DiagEnd::Stopped);
        }
        match sock.read(&mut buf) {
            Ok(0) => break end.unwrap_or(DiagEnd::Eof),
            Ok(n) => {
                if let Some(chunk) = buf.get(..n) {
                    counter.feed(chunk, &mut emit);
                }
            }
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::Interrupted
                ) =>
            {
                if drain_until.is_some() {
                    break end.unwrap_or(DiagEnd::Stopped);
                }
            }
            Err(_) => break end.unwrap_or(DiagEnd::ReadError),
        }
    };
    let stats = counter.finish();
    if let Some(l) = summary_line(end, &stats) {
        let _ = sink.submit(l);
    }
}

#[cfg(test)]
mod tests;
