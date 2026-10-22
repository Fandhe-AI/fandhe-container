//! コンテナログのレコード走査（ストリームの絞り込み・末尾 N 件の読み飛ばし・エスケープ表示。CLI-1・SUP-7）。
//!
//! [`super`]（読み出しの入口）が、オプション（`--tail` / `--stream` / `--escape` / `--follow`）を指定された
//! 読み出しで、ファイルのバイト列を [`Scanner::feed`] へ流す。書き手 [`crate::logs::RotatingFileSink`] の
//! レコード形式（`<stream 名> ` + 行 + LF。行は [`MAX_LINE_BYTES`] 以下）を 1 バイトずつ追う状態機械で、
//! ファイル全体を溜めずに固定長の状態（タグ 7 バイト + 数個の整数）だけで動く（メモリ O(1)。REPAIR-5）。
//!
//! # 契約
//! - タグが `stdout ` / `stderr ` の接頭辞でなくなった時点、または 1 行が [`MAX_LINE_BYTES`] を超えた時点で
//!   [`ScanError::Malformed`]（ファイルの破損。呼び出し側が `Internal` へ写す）。
//! - レコードはファイルをまたがない契約（ローテーションはレコード境界で行われる）ため、ファイルの境目で
//!   [`Scanner::end_file`] を呼んで状態を初期化する。LF の無い切れた末尾（書き込み失敗の sink が残すもの）は
//!   ストリームの絞り込みが無いときだけそのまま出し、絞り込みの指定時にタグが不完全なら捨てる。
//! - エスケープは `cat -v` と同じ表で、レコード本体（タグの後から LF の手前まで）だけに適用する。
//!   タグと区切りの LF は変えない。1 バイトあたり最大 4 バイトに伸びる。

use std::io::Write;

use super::super::{MAX_LINE_BYTES, StreamKind};

/// タグ（`stdout ` / `stderr `）の長さ。
const TAG_BYTES: usize = 7;

/// 走査の失敗。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ScanError {
    /// レコード形式に合わない（未知のタグ・行の上限超過）。
    Malformed,
    /// 出力先への書き込みの失敗。
    Output,
}

/// レコードの走査の状態機械。
#[derive(Debug)]
pub(super) struct Scanner {
    filter: Option<[u8; TAG_BYTES]>,
    escape: bool,
    skip_remaining: u64,
    matched: u64,
    in_body: bool,
    tag: [u8; TAG_BYTES],
    tag_len: usize,
    body_len: usize,
    emit_record: bool,
    /// 1 回の `feed` で作る出力（入力 8 KiB なら最大 32 KiB 強。呼び出しごとに空へ戻す）。
    outbuf: Vec<u8>,
}

/// `stream` に対応するタグ（`"stdout "` 等）。
fn tag_of(stream: StreamKind) -> [u8; TAG_BYTES] {
    let mut tag = [b' '; TAG_BYTES];
    for (dst, src) in tag.iter_mut().zip(stream.as_str().bytes()) {
        *dst = src;
    }
    tag
}

/// `prefix` が既知のタグのどちらかの接頭辞か。
fn is_known_prefix(prefix: &[u8]) -> bool {
    [StreamKind::Stdout, StreamKind::Stderr]
        .iter()
        .any(|k| tag_of(*k).starts_with(prefix))
}

/// `cat -v` と同じ 1 バイトの表示（TAB は変えない。LF は呼び出し側が区切りとして扱うため来ない）。
pub(super) fn escape_byte(b: u8, out: &mut Vec<u8>) {
    let mut low = b;
    if b >= 0x80 {
        out.extend_from_slice(b"M-");
        low = b & 0x7f;
    }
    match low {
        b'\t' => out.push(low),
        0x00..=0x1f => {
            out.push(b'^');
            out.push(low + 0x40);
        }
        0x7f => out.extend_from_slice(b"^?"),
        _ => out.push(low),
    }
}

impl Scanner {
    /// `stream` が `Some` ならそのタグのレコードだけを対象にする。`escape` は本体のエスケープ。
    pub(super) fn new(stream: Option<StreamKind>, escape: bool) -> Self {
        Self {
            filter: stream.map(tag_of),
            escape,
            skip_remaining: 0,
            matched: 0,
            in_body: false,
            tag: [0; TAG_BYTES],
            tag_len: 0,
            body_len: 0,
            emit_record: false,
            outbuf: Vec::new(),
        }
    }

    /// 対象レコードの先頭から `n` 件を出力せず読み飛ばす（`--tail` の 2 パス目）。
    pub(super) fn set_skip(&mut self, n: u64) {
        self.skip_remaining = n;
    }

    /// これまでに見た対象レコードの数（切れた末尾を含む）。
    pub(super) fn matched(&self) -> u64 {
        self.matched
    }

    /// 1 レコードの開始（タグの確定）を数え、出力するかを決める。
    fn start_record(&mut self, matches: bool) -> bool {
        if !matches {
            return false;
        }
        self.matched = self.matched.saturating_add(1);
        if self.skip_remaining > 0 {
            self.skip_remaining -= 1;
            return false;
        }
        true
    }

    fn put_body(&mut self, body: &[u8]) {
        if !self.emit_record {
            return;
        }
        if self.escape {
            for b in body {
                escape_byte(*b, &mut self.outbuf);
            }
        } else {
            self.outbuf.extend_from_slice(body);
        }
    }

    /// `chunk` を走査し、出力対象を `out` へ書く（`out` が `None` なら数えるだけ）。
    pub(super) fn feed(
        &mut self,
        chunk: &[u8],
        out: Option<&mut dyn Write>,
    ) -> Result<(), ScanError> {
        let r = self.feed_inner(chunk);
        self.flush_to(out, r)
    }

    fn feed_inner(&mut self, chunk: &[u8]) -> Result<(), ScanError> {
        let mut rest = chunk;
        while !rest.is_empty() {
            if !self.in_body {
                let take = (TAG_BYTES - self.tag_len).min(rest.len());
                let (head, tail) = rest.split_at(take);
                let Some(dst) = self.tag.get_mut(self.tag_len..self.tag_len + take) else {
                    return Err(ScanError::Malformed);
                };
                dst.copy_from_slice(head);
                self.tag_len += take;
                rest = tail;
                let Some(prefix) = self.tag.get(..self.tag_len) else {
                    return Err(ScanError::Malformed);
                };
                if !is_known_prefix(prefix) {
                    return Err(ScanError::Malformed);
                }
                if self.tag_len == TAG_BYTES {
                    let matches = self.filter.is_none_or(|f| f == self.tag);
                    self.emit_record = self.start_record(matches);
                    if self.emit_record {
                        let tag = self.tag;
                        self.outbuf.extend_from_slice(&tag);
                    }
                    self.in_body = true;
                    self.body_len = 0;
                }
                continue;
            }
            match rest.iter().position(|b| *b == b'\n') {
                Some(p) => {
                    let (body, tail) = rest.split_at(p);
                    if self.body_len.saturating_add(body.len()) > MAX_LINE_BYTES {
                        return Err(ScanError::Malformed);
                    }
                    self.put_body(body);
                    if self.emit_record {
                        self.outbuf.push(b'\n');
                    }
                    rest = tail.get(1..).unwrap_or(&[]);
                    self.in_body = false;
                    self.tag_len = 0;
                    self.body_len = 0;
                    self.emit_record = false;
                }
                None => {
                    if self.body_len.saturating_add(rest.len()) > MAX_LINE_BYTES {
                        return Err(ScanError::Malformed);
                    }
                    self.put_body(rest);
                    self.body_len += rest.len();
                    rest = &[];
                }
            }
        }
        Ok(())
    }

    /// ファイルの境目。LF の無い切れた末尾を扱い、状態を初期化する。
    pub(super) fn end_file(&mut self, out: Option<&mut dyn Write>) -> Result<(), ScanError> {
        // タグの途中で切れている場合だけ、ここで 1 件として数える（タグが揃った切れは開始時に数え済み）。
        if !self.in_body && self.tag_len > 0 && self.filter.is_none() && self.start_record(true) {
            let n = self.tag_len;
            let partial: Vec<u8> = self.tag.get(..n).unwrap_or(&[]).to_vec();
            self.outbuf.extend_from_slice(&partial);
        }
        self.in_body = false;
        self.tag_len = 0;
        self.body_len = 0;
        self.emit_record = false;
        self.flush_to(out, Ok(()))
    }

    fn flush_to(
        &mut self,
        out: Option<&mut dyn Write>,
        result: Result<(), ScanError>,
    ) -> Result<(), ScanError> {
        let written = match out {
            Some(w) if !self.outbuf.is_empty() => {
                w.write_all(&self.outbuf).map_err(|_| ScanError::Output)
            }
            _ => Ok(()),
        };
        self.outbuf.clear();
        result.and(written)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(sc: &mut Scanner, data: &[u8], chunk: usize) -> Result<Vec<u8>, ScanError> {
        let mut out = Vec::new();
        for c in data.chunks(chunk.max(1)) {
            sc.feed(c, Some(&mut out))?;
        }
        Ok(out)
    }

    /// CLI-1: エスケープの表は `cat -v` と同じ。
    #[test]
    fn cli1_escape_table_matches_cat_v() {
        let cases: [(&[u8], &[u8]); 7] = [
            (b"\x1b[0m", b"^[[0m"),
            (b"\r", b"^M"),
            (b"\t", b"\t"),
            (b"\x7f", b"^?"),
            (b"\x9b", b"M-^["),
            (b"\xe3", b"M-c"),
            (b"\x00\x80\xff", b"^@M-^@M-^?"),
        ];
        for (input, expect) in cases {
            let mut out = Vec::new();
            for b in input {
                escape_byte(*b, &mut out);
            }
            assert_eq!(out, expect, "input {input:?}");
        }
    }

    /// CLI-1: エスケープはレコード本体だけに掛かり、タグと LF は変わらない。
    #[test]
    fn cli1_escape_keeps_tag_and_lf() {
        let mut sc = Scanner::new(None, true);
        let out = run(&mut sc, b"stderr a\x1b[1m\nstdout b\r\n", 4).expect("ok");
        assert_eq!(out, b"stderr a^[[1m\nstdout b^M\n");
    }

    /// CLI-1: ストリームの絞り込みはタグを残したまま対象のレコードだけを出す。
    #[test]
    fn cli1_stream_filter_keeps_tags() {
        let mut sc = Scanner::new(Some(StreamKind::Stderr), false);
        let out = run(&mut sc, b"stdout a\nstderr b\nstdout c\nstderr d\n", 5).expect("ok");
        assert_eq!(out, b"stderr b\nstderr d\n");
        assert_eq!(sc.matched(), 2);
    }

    /// SUP-7: 1 行が上限を超えたら破損。
    #[test]
    fn sup7_record_over_limit_is_malformed() {
        let mut sc = Scanner::new(None, false);
        let mut data = b"stdout ".to_vec();
        data.extend(std::iter::repeat_n(b'x', MAX_LINE_BYTES));
        data.push(b'\n');
        run(&mut sc, &data, 8192).expect("exactly the limit is fine");
        let mut sc = Scanner::new(None, false);
        let mut data = b"stdout ".to_vec();
        data.extend(std::iter::repeat_n(b'x', MAX_LINE_BYTES + 1));
        data.push(b'\n');
        assert_eq!(run(&mut sc, &data, 8192), Err(ScanError::Malformed));
    }

    /// SUP-7: 未知のタグは破損（タグの途中でも接頭辞でなくなれば止まる）。
    #[test]
    fn sup7_unknown_tag_is_malformed() {
        for bad in [&b"stdin x\n"[..], b"stdoutx\n", b"std\nxx", b"xx"] {
            let mut sc = Scanner::new(None, false);
            assert_eq!(run(&mut sc, bad, 3), Err(ScanError::Malformed), "{bad:?}");
        }
    }

    /// SUP-7: 切れた末尾は絞り込み無しならそのまま出し、絞り込み指定時にタグが不完全なら捨てる。
    #[test]
    fn sup7_torn_tail_passthrough_and_filter_drop() {
        let mut sc = Scanner::new(None, false);
        let mut out = run(&mut sc, b"stdout a\nstd", 100).expect("ok");
        let mut tail = Vec::new();
        sc.end_file(Some(&mut tail)).expect("end");
        out.extend(tail);
        assert_eq!(out, b"stdout a\nstd");
        assert_eq!(sc.matched(), 2);

        let mut sc = Scanner::new(Some(StreamKind::Stdout), false);
        let mut out = run(&mut sc, b"stdout a\nstd", 100).expect("ok");
        let mut tail = Vec::new();
        sc.end_file(Some(&mut tail)).expect("end");
        out.extend(tail);
        assert_eq!(out, b"stdout a\n");
        assert_eq!(sc.matched(), 1);

        // タグが揃った切れた本体は、絞り込みの対象ならそのまま出る。
        let mut sc = Scanner::new(Some(StreamKind::Stdout), false);
        let out = run(&mut sc, b"stdout partial", 100).expect("ok");
        sc.end_file(None).expect("end");
        assert_eq!(out, b"stdout partial");
    }

    /// SUP-7: チャンク境界がどこでも出力は同じ（タグの途中・LF の直前直後を含む）。
    #[test]
    fn sup7_tag_split_across_chunks() {
        let data = b"stdout one\nstderr two\x1b\nstdout \nstderr z\n";
        let mut whole = Scanner::new(None, true);
        let expect = run(&mut whole, data, data.len()).expect("ok");
        for chunk in [1usize, 3, 6, 7, 8] {
            let mut sc = Scanner::new(None, true);
            assert_eq!(run(&mut sc, data, chunk).expect("ok"), expect, "{chunk}");
        }
    }

    /// CLI-1: 先頭 n 件の読み飛ばしは対象レコードだけを数える。
    #[test]
    fn cli1_skip_counts_matching_records_only() {
        let mut sc = Scanner::new(Some(StreamKind::Stdout), false);
        sc.set_skip(1);
        let out = run(&mut sc, b"stdout a\nstderr x\nstdout b\nstdout c\n", 6).expect("ok");
        assert_eq!(out, b"stdout b\nstdout c\n");
        assert_eq!(sc.matched(), 3);
    }
}
