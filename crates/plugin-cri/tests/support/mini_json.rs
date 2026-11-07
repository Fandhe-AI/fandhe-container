//! 結合試験用の最小の JSON 構文検査と値の読み取り（CRI-5・REPAIR-12・#3684）。
//!
//! 呼び出し元: shim バイナリの試験（`shim_bin_bootstrap*.rs`）が `#[path]` で共有する。serde_json を plugin-cri の依存に
//! 足さない（依存は承認制）ため、移設前の `serde_json::from_str` 相当（構文・不正エスケープ・末尾の余り・欄の型）を
//! 試験側で最小限に再現する。数値は非負整数かどうかを区別できれば足りる（それ以外の数値は `Number`）。

#[derive(Debug, Clone, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    /// 符号・小数・指数を持たない非負整数（u64 に収まるもの）。
    UInt(u64),
    /// 上記以外の数値。
    Number,
    Str(String),
    Array(Vec<Json>),
    Object(Vec<(String, Json)>),
}

impl Json {
    #[allow(dead_code, reason = "取り込み元の試験によっては使わない共有補助")]
    pub fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Object(v) => v.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }
    #[allow(dead_code, reason = "取り込み元の試験によっては使わない共有補助")]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Json::Str(s) => Some(s),
            _ => None,
        }
    }
    #[allow(dead_code, reason = "取り込み元の試験によっては使わない共有補助")]
    pub fn is_u64(&self) -> bool {
        matches!(self, Json::UInt(_))
    }
}

/// 全体が 1 つの JSON 値であることを検査して読む。違反は `None`。
#[allow(dead_code, reason = "取り込み元の試験によっては使わない共有補助")]
pub fn parse(text: &str) -> Option<Json> {
    let mut p = P {
        b: text.as_bytes(),
        i: 0,
        depth: 0,
    };
    p.ws();
    let v = p.value()?;
    p.ws();
    (p.i == p.b.len()).then_some(v)
}

struct P<'a> {
    b: &'a [u8],
    i: usize,
    depth: usize,
}

impl P<'_> {
    fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }
    fn ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.i += 1;
        }
    }
    fn lit(&mut self, s: &str, v: Json) -> Option<Json> {
        let end = self.i.checked_add(s.len())?;
        if self.b.get(self.i..end)? == s.as_bytes() {
            self.i = end;
            Some(v)
        } else {
            None
        }
    }
    fn value(&mut self) -> Option<Json> {
        match self.peek()? {
            b'n' => self.lit("null", Json::Null),
            b't' => self.lit("true", Json::Bool(true)),
            b'f' => self.lit("false", Json::Bool(false)),
            b'"' => self.string().map(Json::Str),
            b'[' | b'{' => {
                self.depth += 1;
                if self.depth > 64 {
                    return None;
                }
                let r = if self.peek()? == b'[' {
                    self.array()
                } else {
                    self.object()
                };
                self.depth -= 1;
                r
            }
            b'-' | b'0'..=b'9' => self.number(),
            _ => None,
        }
    }
    fn digits(&mut self) -> usize {
        let s = self.i;
        while self.peek().is_some_and(|c| c.is_ascii_digit()) {
            self.i += 1;
        }
        self.i - s
    }
    fn number(&mut self) -> Option<Json> {
        let negative = self.peek()? == b'-';
        if negative {
            self.i += 1;
        }
        let int_start = self.i;
        match self.peek()? {
            b'0' => self.i += 1,
            b'1'..=b'9' => {
                self.digits();
            }
            _ => return None,
        }
        let int_end = self.i;
        let mut plain = !negative;
        if self.peek() == Some(b'.') {
            plain = false;
            self.i += 1;
            if self.digits() == 0 {
                return None;
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            plain = false;
            self.i += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.i += 1;
            }
            if self.digits() == 0 {
                return None;
            }
        }
        if plain {
            let text = std::str::from_utf8(self.b.get(int_start..int_end)?).ok()?;
            if let Ok(n) = text.parse::<u64>() {
                return Some(Json::UInt(n));
            }
        }
        Some(Json::Number)
    }
    fn hex4(&mut self) -> Option<u32> {
        let end = self.i.checked_add(4)?;
        let s = std::str::from_utf8(self.b.get(self.i..end)?).ok()?;
        if !s.bytes().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }
        self.i = end;
        u32::from_str_radix(s, 16).ok()
    }
    fn string(&mut self) -> Option<String> {
        self.i += 1; // 開き引用符
        let mut out: Vec<u8> = Vec::new();
        loop {
            let c = self.peek()?;
            self.i += 1;
            match c {
                b'"' => return String::from_utf8(out).ok(),
                0..=0x1f => return None,
                b'\\' => {
                    let e = self.peek()?;
                    self.i += 1;
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
                            if (0xd800..0xdc00).contains(&hi) {
                                if self.peek()? != b'\\' || self.b.get(self.i + 1) != Some(&b'u') {
                                    return None;
                                }
                                self.i += 2;
                                let lo = self.hex4()?;
                                if !(0xdc00..0xe000).contains(&lo) {
                                    return None;
                                }
                                char::from_u32(0x10000 + ((hi - 0xd800) << 10) + (lo - 0xdc00))?
                            } else {
                                char::from_u32(hi)?
                            }
                        }
                        _ => return None,
                    };
                    let mut buf = [0u8; 4];
                    out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                }
                _ => out.push(c),
            }
        }
    }
    fn array(&mut self) -> Option<Json> {
        self.i += 1;
        let mut v = Vec::new();
        self.ws();
        if self.peek()? == b']' {
            self.i += 1;
            return Some(Json::Array(v));
        }
        loop {
            self.ws();
            v.push(self.value()?);
            self.ws();
            match self.peek()? {
                b',' => self.i += 1,
                b']' => {
                    self.i += 1;
                    return Some(Json::Array(v));
                }
                _ => return None,
            }
        }
    }
    fn object(&mut self) -> Option<Json> {
        self.i += 1;
        let mut v = Vec::new();
        self.ws();
        if self.peek()? == b'}' {
            self.i += 1;
            return Some(Json::Object(v));
        }
        loop {
            self.ws();
            if self.peek()? != b'"' {
                return None;
            }
            let k = self.string()?;
            self.ws();
            if self.peek()? != b':' {
                return None;
            }
            self.i += 1;
            self.ws();
            v.push((k, self.value()?));
            self.ws();
            match self.peek()? {
                b',' => self.i += 1,
                b'}' => {
                    self.i += 1;
                    return Some(Json::Object(v));
                }
                _ => return None,
            }
        }
    }
}
