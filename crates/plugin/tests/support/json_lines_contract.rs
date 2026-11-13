//! 「1 行 1 JSON」契約の共有検査器（ERR-4・#3122・TASK-98 の受け入れ条件 2〔#653〕・#3114 の判断 (f)）。
//!
//! 監査（SEC-4）・可観測性（REPAIR-4）・警告・エラーの各書き出し口が、journald / syslog へ
//! 行単位で転送できる形式（LF 区切りの 1 行 1 JSON オブジェクト）で出していることを、実際の
//! 書き出し口がバッファへ書いた行に対して横断して照合する。core・cli・io・plugin の
//! `#[cfg(test)]` モジュールと cli の結合試験が `#[path]` で取り込む。
//!
//! # 置き場所の理由
//!
//! io・plugin は core より下の層で core へ依存できない（#3114 (f)）。形式を保つ手段として
//! 「契約試験の検査器を共有する」方式を採る。ライセンスが `MIT OR Apache-2.0` の plugin 配下に
//! 置くことで、Apache-2.0 単独の crate からも、plugin の試験からも取り込める。
//! cli・io は `serde_json` を持たない（依存の追加は承認事項）ため、解析器は std のみで書く。
//! 解析器自身の正しさは core の試験が `serde_json` との差分照合で確かめる。
//!
//! # 契約
//!
//! 各行は LF で終わり、LF / CR を中に持たず、`max_line` バイト以下の UTF-8 で、前後に何も
//! 無い単一の JSON オブジェクトとして読め、キーが重複せず、`event` を持つ。キー順は
//! `event` が先頭、または `level` → `event`。

/// core の `logging::MAX_LOG_LINE_BYTES` の写し（一致は core の試験で照合する）。
#[allow(dead_code)] // #[path] で取り込む利用側ごとに使う項目が異なる（共有検査器）
pub const SHARED_MAX_LOG_LINE_BYTES: usize = 32 * 1024;
/// journald の `LineMax` の既定値。超えた行は分割され 1 行 1 JSON が壊れる。
#[allow(dead_code)] // #[path] で取り込む利用側ごとに使う項目が異なる（共有検査器）
pub const JOURNALD_LINE_MAX_DEFAULT: usize = 48 * 1024;

/// 表示を乱す文字・制御文字・エスケープが要る文字をまとめた敵対的な入力。
#[allow(dead_code)] // #[path] で取り込む利用側ごとに使う項目が異なる（共有検査器）
pub const HOSTILE_TEXT: &str = "a\nb\rc\u{0}d\u{7}e\u{1b}[31mf\u{7f}g\u{85}h\u{2028}i\u{2029}j\u{202e}k\u{200b}l\u{feff}m\"n\\o\u{3042}";

/// 契約違反の種類。`usize` は 0 始まりの行番号。
#[allow(dead_code)] // #[path] で取り込む利用側ごとに使う項目が異なる（共有検査器）
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Violation {
    Empty,
    MissingTrailingLf,
    EmptyLine(usize),
    CarriageReturn(usize),
    TooLong { line: usize, len: usize },
    NotUtf8(usize),
    NotJson { line: usize, offset: usize },
    NotObject(usize),
    TrailingData(usize),
    DuplicateKey(usize),
    MissingEvent(usize),
    EventNotString(usize),
    BadEventName(usize),
    BadLevel(usize),
    BadKeyOrder(usize),
    EmbeddedLf,
}

/// 1 行から取り出した事実。
#[allow(dead_code)] // #[path] で取り込む利用側ごとに使う項目が異なる（共有検査器）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LineFacts {
    pub level: Option<String>,
    pub event: String,
    /// トップレベルのキー順。
    pub keys: Vec<String>,
    /// トップレベルの文字列値（デコード済み）。
    pub strings: Vec<(String, String)>,
    pub bools: Vec<(String, bool)>,
}

#[allow(dead_code)] // #[path] で取り込む利用側ごとに使う項目が異なる（共有検査器）
impl LineFacts {
    pub fn str_of(&self, key: &str) -> Option<&str> {
        self.strings
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }
    pub fn bool_of(&self, key: &str) -> Option<bool> {
        self.bools.iter().find(|(k, _)| k == key).map(|(_, v)| *v)
    }
    pub fn keys_vec(&self) -> Vec<&str> {
        self.keys.iter().map(String::as_str).collect()
    }
}

/// LF 区切りのバイト列全体（出力の全量）を検査する。
#[allow(dead_code)] // #[path] で取り込む利用側ごとに使う項目が異なる（共有検査器）
pub fn check_stream(bytes: &[u8], max_line: usize) -> Result<Vec<LineFacts>, Violation> {
    if bytes.is_empty() {
        return Err(Violation::Empty);
    }
    if bytes.last() != Some(&b'\n') {
        return Err(Violation::MissingTrailingLf);
    }
    let body = bytes.get(..bytes.len() - 1).unwrap_or(&[]);
    let mut out = Vec::new();
    for (i, line) in body.split(|&b| b == b'\n').enumerate() {
        out.push(check_line(i, line, max_line)?);
    }
    Ok(out)
}

/// LF を含まない 1 行分の本体（`drain_lines` の戻り値等）を検査する。
#[allow(dead_code)] // #[path] で取り込む利用側ごとに使う項目が異なる（共有検査器）
pub fn check_body(body: &str, max_line: usize) -> Result<LineFacts, Violation> {
    if body.contains('\n') {
        return Err(Violation::EmbeddedLf);
    }
    check_line(0, body.as_bytes(), max_line)
}

fn check_line(idx: usize, line: &[u8], max_line: usize) -> Result<LineFacts, Violation> {
    if line.is_empty() {
        return Err(Violation::EmptyLine(idx));
    }
    if line.contains(&b'\r') {
        return Err(Violation::CarriageReturn(idx));
    }
    if line.len() > max_line {
        return Err(Violation::TooLong {
            line: idx,
            len: line.len(),
        });
    }
    let text = std::str::from_utf8(line).map_err(|_| Violation::NotUtf8(idx))?;
    let mut p = Parser {
        b: text.as_bytes(),
        pos: 0,
        line: idx,
    };
    if p.peek() != Some(b'{') {
        // 値として読めるかを先に見て、読めるならオブジェクトでないと報告する。
        p.value(0)?;
        return Err(if p.pos < p.b.len() {
            Violation::TrailingData(idx)
        } else {
            Violation::NotObject(idx)
        });
    }
    let facts = p.object_top()?;
    if p.pos < p.b.len() {
        return Err(Violation::TrailingData(idx));
    }
    finish(idx, facts)
}

fn finish(idx: usize, f: Raw) -> Result<LineFacts, Violation> {
    let pos = f
        .keys
        .iter()
        .position(|k| k == "event")
        .ok_or(Violation::MissingEvent(idx))?;
    let event = f
        .strings
        .iter()
        .find(|(k, _)| k == "event")
        .map(|(_, v)| v.clone())
        .ok_or(Violation::EventNotString(idx))?;
    let ok_name = !event.is_empty()
        && event.len() <= 64
        && event
            .bytes()
            .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_'));
    if !ok_name {
        return Err(Violation::BadEventName(idx));
    }
    let level_present = f.keys.iter().any(|k| k == "level");
    let level = f
        .strings
        .iter()
        .find(|(k, _)| k == "level")
        .map(|(_, v)| v.clone());
    // level キーがあるのに文字列でない値（1・null 等）は level なしとして通さない。
    if level_present && level.is_none() {
        return Err(Violation::BadLevel(idx));
    }
    match (&level, pos) {
        (None, 0) => {}
        (Some(l), 1) => {
            if f.keys.first().map(String::as_str) != Some("level") {
                return Err(Violation::BadKeyOrder(idx));
            }
            if !matches!(l.as_str(), "error" | "warn" | "info" | "debug") {
                return Err(Violation::BadLevel(idx));
            }
        }
        _ => return Err(Violation::BadKeyOrder(idx)),
    }
    Ok(LineFacts {
        level,
        event,
        keys: f.keys,
        strings: f.strings,
        bools: f.bools,
    })
}

struct Raw {
    keys: Vec<String>,
    strings: Vec<(String, String)>,
    bools: Vec<(String, bool)>,
}

const MAX_DEPTH: usize = 32;

/// RFC 8259 の厳密な再帰下降の解析器（panic せず、添字でなく `get()` を使う）。
struct Parser<'a> {
    b: &'a [u8],
    pos: usize,
    line: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.b.get(self.pos).copied()
    }
    fn err(&self) -> Violation {
        Violation::NotJson {
            line: self.line,
            offset: self.pos,
        }
    }
    fn eat(&mut self, c: u8) -> Result<(), Violation> {
        if self.peek() == Some(c) {
            self.pos += 1;
            Ok(())
        } else {
            Err(self.err())
        }
    }
    fn lit(&mut self, s: &str) -> Result<(), Violation> {
        for c in s.bytes() {
            self.eat(c)?;
        }
        Ok(())
    }

    /// トップレベルのオブジェクト。キー順・文字列値・真偽値を集める。
    fn object_top(&mut self) -> Result<Raw, Violation> {
        let mut raw = Raw {
            keys: Vec::new(),
            strings: Vec::new(),
            bools: Vec::new(),
        };
        self.eat(b'{')?;
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(raw);
        }
        loop {
            let key = self.string()?;
            if raw.keys.contains(&key) {
                return Err(Violation::DuplicateKey(self.line));
            }
            self.eat(b':')?;
            match self.peek() {
                Some(b'"') => {
                    let v = self.string()?;
                    raw.strings.push((key.clone(), v));
                }
                Some(b't') => {
                    self.lit("true")?;
                    raw.bools.push((key.clone(), true));
                }
                Some(b'f') => {
                    self.lit("false")?;
                    raw.bools.push((key.clone(), false));
                }
                _ => self.value(1)?,
            }
            raw.keys.push(key);
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(raw);
                }
                _ => return Err(self.err()),
            }
        }
    }

    fn value(&mut self, depth: usize) -> Result<(), Violation> {
        if depth > MAX_DEPTH {
            return Err(self.err());
        }
        match self.peek() {
            Some(b'{') => {
                self.pos += 1;
                if self.peek() == Some(b'}') {
                    self.pos += 1;
                    return Ok(());
                }
                let mut seen: Vec<String> = Vec::new();
                loop {
                    let k = self.string()?;
                    if seen.contains(&k) {
                        return Err(Violation::DuplicateKey(self.line));
                    }
                    seen.push(k);
                    self.eat(b':')?;
                    self.value(depth + 1)?;
                    match self.peek() {
                        Some(b',') => self.pos += 1,
                        Some(b'}') => {
                            self.pos += 1;
                            return Ok(());
                        }
                        _ => return Err(self.err()),
                    }
                }
            }
            Some(b'[') => {
                self.pos += 1;
                if self.peek() == Some(b']') {
                    self.pos += 1;
                    return Ok(());
                }
                loop {
                    self.value(depth + 1)?;
                    match self.peek() {
                        Some(b',') => self.pos += 1,
                        Some(b']') => {
                            self.pos += 1;
                            return Ok(());
                        }
                        _ => return Err(self.err()),
                    }
                }
            }
            Some(b'"') => self.string().map(|_| ()),
            Some(b't') => self.lit("true"),
            Some(b'f') => self.lit("false"),
            Some(b'n') => self.lit("null"),
            Some(b'-' | b'0'..=b'9') => self.number(),
            _ => Err(self.err()),
        }
    }

    fn number(&mut self) -> Result<(), Violation> {
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        match self.peek() {
            Some(b'0') => self.pos += 1,
            Some(b'1'..=b'9') => self.digits(),
            _ => return Err(self.err()),
        }
        if self.peek() == Some(b'.') {
            self.pos += 1;
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(self.err());
            }
            self.digits();
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.pos += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.pos += 1;
            }
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(self.err());
            }
            self.digits();
        }
        Ok(())
    }

    fn digits(&mut self) {
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.pos += 1;
        }
    }

    fn hex4(&mut self) -> Result<u32, Violation> {
        let mut v = 0u32;
        for _ in 0..4 {
            let d = match self.peek() {
                Some(c @ b'0'..=b'9') => u32::from(c - b'0'),
                Some(c @ b'a'..=b'f') => u32::from(c - b'a') + 10,
                Some(c @ b'A'..=b'F') => u32::from(c - b'A') + 10,
                _ => return Err(self.err()),
            };
            v = v * 16 + d;
            self.pos += 1;
        }
        Ok(v)
    }

    fn string(&mut self) -> Result<String, Violation> {
        self.eat(b'"')?;
        let mut out: Vec<u8> = Vec::new();
        loop {
            let c = self.peek().ok_or_else(|| self.err())?;
            match c {
                b'"' => {
                    self.pos += 1;
                    return String::from_utf8(out).map_err(|_| Violation::NotUtf8(self.line));
                }
                0..=0x1f => return Err(self.err()),
                b'\\' => {
                    self.pos += 1;
                    let e = self.peek().ok_or_else(|| self.err())?;
                    self.pos += 1;
                    let ch = match e {
                        b'"' => '"',
                        b'\\' => '\\',
                        b'/' => '/',
                        b'b' => '\u{8}',
                        b'f' => '\u{c}',
                        b'n' => '\n',
                        b'r' => '\r',
                        b't' => '\t',
                        b'u' => {
                            let hi = self.hex4()?;
                            let cp = if (0xD800..0xDC00).contains(&hi) {
                                self.eat(b'\\')?;
                                self.eat(b'u')?;
                                let lo = self.hex4()?;
                                if !(0xDC00..0xE000).contains(&lo) {
                                    return Err(self.err());
                                }
                                0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00)
                            } else if (0xDC00..0xE000).contains(&hi) {
                                return Err(self.err());
                            } else {
                                hi
                            };
                            char::from_u32(cp).ok_or_else(|| self.err())?
                        }
                        _ => return Err(self.err()),
                    };
                    let mut buf = [0u8; 4];
                    out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                }
                _ => {
                    out.push(c);
                    self.pos += 1;
                }
            }
        }
    }
}
