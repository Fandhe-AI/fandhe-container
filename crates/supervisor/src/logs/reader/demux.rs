//! 追従の出力（`stdout ` / `stderr ` のタグつきレコード）を、タグを外して 2 本の `Write` へ分ける（CRI-6・SUP-7・#3763）。
//!
//! plugin-cri の attach が [`super::read_container_log_with_cancel`] の出力（ストリームの絞り込みなし）を
//! stdout / stderr の 2 本の読み口へ振り分けるために使う。レコード形式（タグ 7 バイト + 本体 + LF）は supervisor の
//! 持ち物のため、解釈もここに置く（形式が変わっても直すのが 1 crate で済む。REPAIR-1）。
//!
//! # 契約
//! - 本体と LF は加工せず、対応する側へ渡す。要求していない側（`None`）のレコードは捨てる。
//! - 入力は任意の位置で分割されてよい（状態を持つ）。固定長の状態だけで動き、メモリは O(1)。
//! - 未知のタグ・1 行が [`MAX_LINE_BYTES`] を超える入力は `InvalidData` で失敗する（破損を黙って流さない。REPAIR-5）。
//! - LF の無い切れた末尾は、タグが揃っていれば本体だけをその時点で出す（LF は付けない）。不完全なタグは出さない。
//!   [`RecordDemux::finish`] は状態を初期化するだけで、追加の出力はしない。

use std::io::{self, ErrorKind, Write};

use super::super::{MAX_LINE_BYTES, StreamKind};

const TAG_BYTES: usize = 7;

fn tag_of(kind: StreamKind) -> [u8; TAG_BYTES] {
    let mut tag = [b' '; TAG_BYTES];
    for (dst, src) in tag.iter_mut().zip(kind.as_str().bytes()) {
        *dst = src;
    }
    tag
}

fn invalid() -> io::Error {
    io::Error::new(ErrorKind::InvalidData, "container log record is malformed")
}

/// レコードをストリーム別に振り分ける `Write`。
pub struct RecordDemux<'a> {
    stdout: Option<&'a mut dyn Write>,
    stderr: Option<&'a mut dyn Write>,
    tag: [u8; TAG_BYTES],
    tag_len: usize,
    /// タグ確定後の振り分け先。
    current: Option<StreamKind>,
    in_body: bool,
    body_len: usize,
}

impl<'a> RecordDemux<'a> {
    /// 振り分け先を指定する。`None` の側のレコードは捨てる。
    pub fn new(stdout: Option<&'a mut dyn Write>, stderr: Option<&'a mut dyn Write>) -> Self {
        Self {
            stdout,
            stderr,
            tag: [0; TAG_BYTES],
            tag_len: 0,
            current: None,
            in_body: false,
            body_len: 0,
        }
    }

    fn put(&mut self, bytes: &[u8]) -> io::Result<()> {
        let w = match self.current {
            Some(StreamKind::Stdout) => self.stdout.as_deref_mut(),
            Some(StreamKind::Stderr) => self.stderr.as_deref_mut(),
            None => None,
        };
        match w {
            Some(w) => w.write_all(bytes),
            None => Ok(()),
        }
    }

    fn reset(&mut self) {
        self.tag_len = 0;
        self.current = None;
        self.in_body = false;
        self.body_len = 0;
    }

    /// 入力の終わり。LF の無い切れた末尾の状態を捨てて初期化する（本体は到着時に出し済み）。
    pub fn finish(&mut self) -> io::Result<()> {
        self.reset();
        self.flush()
    }

    fn feed(&mut self, chunk: &[u8]) -> io::Result<()> {
        let mut rest = chunk;
        while !rest.is_empty() {
            if !self.in_body {
                let take = (TAG_BYTES - self.tag_len).min(rest.len());
                let (head, tail) = rest.split_at(take);
                let dst = self
                    .tag
                    .get_mut(self.tag_len..self.tag_len + take)
                    .ok_or_else(invalid)?;
                dst.copy_from_slice(head);
                self.tag_len += take;
                rest = tail;
                let prefix = self.tag.get(..self.tag_len).ok_or_else(invalid)?;
                let known = [StreamKind::Stdout, StreamKind::Stderr]
                    .into_iter()
                    .find(|k| tag_of(*k).starts_with(prefix));
                let Some(kind) = known else {
                    return Err(invalid());
                };
                if self.tag_len == TAG_BYTES {
                    self.current = Some(kind);
                    self.in_body = true;
                    self.body_len = 0;
                }
                continue;
            }
            match rest.iter().position(|b| *b == b'\n') {
                Some(p) => {
                    let (body, tail) = rest.split_at(p);
                    if self.body_len.saturating_add(body.len()) > MAX_LINE_BYTES {
                        return Err(invalid());
                    }
                    self.put(body)?;
                    self.put(b"\n")?;
                    rest = tail.get(1..).unwrap_or(&[]);
                    self.reset();
                }
                None => {
                    if self.body_len.saturating_add(rest.len()) > MAX_LINE_BYTES {
                        return Err(invalid());
                    }
                    self.put(rest)?;
                    self.body_len += rest.len();
                    rest = &[];
                }
            }
        }
        Ok(())
    }
}

impl Write for RecordDemux<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.feed(buf)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        if let Some(w) = self.stdout.as_deref_mut() {
            w.flush()?;
        }
        if let Some(w) = self.stderr.as_deref_mut() {
            w.flush()?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(chunks: &[&[u8]], out: bool, err: bool) -> (io::Result<()>, Vec<u8>, Vec<u8>) {
        let mut o = Vec::new();
        let mut e = Vec::new();
        let r = {
            let mut d = RecordDemux::new(
                if out {
                    Some(&mut o as &mut dyn Write)
                } else {
                    None
                },
                if err {
                    Some(&mut e as &mut dyn Write)
                } else {
                    None
                },
            );
            let mut r = Ok(());
            for c in chunks {
                if let Err(x) = d.write_all(c) {
                    r = Err(x);
                    break;
                }
            }
            if r.is_ok() {
                r = d.finish();
            }
            r
        };
        (r, o, e)
    }

    /// SUP-7・CRI-6・#3763: 分割されたチャンクでもタグを外して振り分け、本体と LF を保つ。
    #[test]
    fn sup7_demux_splits_streams_across_chunk_boundaries() {
        let (r, o, e) = run(
            &[b"std", b"out hel", b"lo\nstderr oo", b"ps\nstdout \n"],
            true,
            true,
        );
        assert!(r.is_ok());
        assert_eq!(o, b"hello\n\n");
        assert_eq!(e, b"oops\n");
    }

    /// 要求していない側のレコードは捨てる。
    #[test]
    fn sup7_demux_drops_unrequested_stream() {
        let (r, o, e) = run(&[b"stdout a\nstderr b\n"], true, false);
        assert!(r.is_ok());
        assert_eq!(o, b"a\n");
        assert!(e.is_empty());
    }

    /// 未知のタグは `InvalidData`。
    #[test]
    fn repair5_demux_rejects_unknown_tag() {
        let (r, o, _) = run(&[b"stdxyz a\n"], true, true);
        assert_eq!(r.expect_err("malformed").kind(), ErrorKind::InvalidData);
        assert!(o.is_empty());
    }

    /// 1 行が上限を超えたら `InvalidData`（確保の前に検証する）。
    #[test]
    fn repair5_demux_rejects_line_over_limit() {
        let mut data = b"stdout ".to_vec();
        data.extend(std::iter::repeat_n(b'x', MAX_LINE_BYTES + 1));
        let (r, _, _) = run(&[&data], true, true);
        assert_eq!(r.expect_err("too long").kind(), ErrorKind::InvalidData);
    }

    /// LF の無い切れた末尾: タグが揃っていれば本体だけ（LF なし）、不完全なタグは出さない。
    #[test]
    fn sup7_demux_torn_tail_emits_body_only_or_drops() {
        let (r, o, _) = run(&[b"stdout a\nstdout par"], true, true);
        assert!(r.is_ok());
        assert_eq!(o, b"a\npar");
        let (r, o, e) = run(&[b"stdout a\nstde"], true, true);
        assert!(r.is_ok());
        assert_eq!(o, b"a\n");
        assert!(e.is_empty());
    }
}
