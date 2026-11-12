//! 行の断片化（`LogSink::append_part`・`LineSplitter`）の照合試験（SUP-7・CRI-2・REPAIR-12。#4580）。
//!
//! `pump` を Cursor ベースのリーダーで直接呼び、断片列（`index`・`end`・長さ）を具体値で見る。
//! 親モジュール `logs` の私的な `pump`・`CancelGate` を使うため子モジュールとして置く。

use std::io::{Cursor, Read};
use std::sync::Mutex;

use fandhe_container_core::traits::{ErrorCode, TraitError};

use super::{
    CancelGate, LinePart, LogSink, MAX_LINE_BYTES, MemoryLogSink, PartEnd, READ_CHUNK_BYTES,
    StreamKind, StreamSummary, pump,
};

const K: usize = MAX_LINE_BYTES;

type Call = (u64, PartEnd, Vec<u8>, Vec<u8>);

/// 受け取った断片を記録する sink。`fail_at` 番目（0 始まり）の呼び出しで失敗する。
#[derive(Default)]
struct PartRecorder {
    calls: Mutex<Vec<Call>>,
    fail_at: Option<usize>,
}

impl LogSink for PartRecorder {
    fn append(&self, _: StreamKind, _: &[u8]) -> Result<(), TraitError> {
        Ok(())
    }
    fn append_part(
        &self,
        _: StreamKind,
        bytes: &[u8],
        part: LinePart<'_>,
    ) -> Result<(), TraitError> {
        let mut c = self.calls.lock().unwrap();
        let n = c.len();
        c.push((part.index, part.end, bytes.to_vec(), part.head.to_vec()));
        if self.fail_at == Some(n) {
            return Err(TraitError::new(ErrorCode::Unavailable, "injected"));
        }
        Ok(())
    }
}

struct StepRead {
    data: Cursor<Vec<u8>>,
    step: usize,
}
impl Read for StepRead {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = buf.len().min(self.step);
        let head = buf.get_mut(..n).unwrap_or(&mut []);
        self.data.read(head)
    }
}

/// `data` を返し切った後に読み取りエラーを返す。
struct FailingRead(Cursor<Vec<u8>>);
impl Read for FailingRead {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self.0.read(buf)? {
            0 => Err(std::io::Error::other("fake read failure")),
            n => Ok(n),
        }
    }
}

/// LF を含まない決定的なバイト列。
fn body(n: usize) -> Vec<u8> {
    (0..n).map(|i| b'a' + (i % 23) as u8).collect()
}

type Shape = Vec<(u64, PartEnd, usize)>;

fn run_with(stream: Box<dyn Read + Send>, sink: &dyn LogSink) -> StreamSummary {
    pump(
        stream,
        StreamKind::Stdout,
        sink,
        &CancelGate::default(),
        None,
    )
}

fn shape_of(rec: &PartRecorder) -> Shape {
    rec.calls
        .lock()
        .unwrap()
        .iter()
        .map(|(i, e, b, _)| (*i, *e, b.len()))
        .collect()
}

fn cases() -> Vec<(&'static str, Vec<u8>, Shape)> {
    use PartEnd::{Continued as C, Eof, Lf};
    let with_lf = |mut v: Vec<u8>| {
        v.push(b'\n');
        v
    };
    vec![
        ("exact+lf", with_lf(body(K)), vec![(0, Lf, K)]),
        (
            "over1+lf",
            with_lf(body(K + 1)),
            vec![(0, C, K), (1, Lf, 1)],
        ),
        ("2k+lf", with_lf(body(2 * K)), vec![(0, C, K), (1, Lf, K)]),
        (
            "3k5+lf",
            with_lf(body(3 * K + 5)),
            vec![(0, C, K), (1, C, K), (2, C, K), (3, Lf, 5)],
        ),
        ("eof exact", body(K), vec![(0, Eof, K)]),
        ("eof over1", body(K + 1), vec![(0, C, K), (1, Eof, 1)]),
        (
            "eof 2k3",
            body(2 * K + 3),
            vec![(0, C, K), (1, C, K), (2, Eof, 3)],
        ),
        ("eof tail", b"tail".to_vec(), vec![(0, Eof, 4)]),
    ]
}

/// 断片列を具体値で照合する（SUP-7・CRI-2・#4580）。
#[test]
fn sup7_cri2_4580_fragment_sequences_are_exact() {
    for (name, input, want) in cases() {
        let rec = PartRecorder::default();
        let sum = run_with(Box::new(Cursor::new(input.clone())), &rec);
        assert_eq!(shape_of(&rec), want, "{name}");
        let calls = rec.calls.lock().unwrap();
        let mut joined = Vec::new();
        for (i, _, b, head) in calls.iter() {
            assert!(b.len() <= MAX_LINE_BYTES, "{name}");
            if *i > 0 {
                assert_eq!(head, &calls[0].2, "{name}: head");
            } else {
                assert!(head.is_empty(), "{name}");
            }
            joined.extend_from_slice(b);
        }
        let expect: Vec<u8> = input.iter().copied().filter(|b| *b != b'\n').collect();
        assert_eq!(joined, expect, "{name}: concat");
        assert_eq!(sum.lines(), 1, "{name}");
        assert_eq!(sum.truncated_lines(), u64::from(want.len() > 1), "{name}");
        assert_eq!(sum.discarded_lines(), 0, "{name}");
        assert_eq!(sum.error_code(), None, "{name}");
    }
}

/// 断片列は read の戻りサイズ・チャンク境界に依らない。
#[test]
fn sup7_cri2_4580_fragments_independent_of_read_boundaries() {
    for (name, input, want) in cases() {
        for step in [7, 1000, READ_CHUNK_BYTES - 1, READ_CHUNK_BYTES] {
            let rec = PartRecorder::default();
            let sum = run_with(
                Box::new(StepRead {
                    data: Cursor::new(input.clone()),
                    step,
                }),
                &rec,
            );
            assert_eq!(shape_of(&rec), want, "{name} step={step}");
            assert_eq!(sum.lines(), 1, "{name} step={step}");
        }
    }
    // 64 KiB 境界・LF の位置をまたぐ読み取りサイズでも同じ断片列になる。
    let mut input = body(K + 10);
    input.push(b'\n');
    input.extend_from_slice(b"next\n");
    for step in [K - 1, K, K + 10, K + 11, 4096] {
        let rec = PartRecorder::default();
        let r = StepRead {
            data: Cursor::new(input.clone()),
            step: step.min(READ_CHUNK_BYTES),
        };
        run_with(Box::new(r), &rec);
        use PartEnd::{Continued as C, Lf};
        assert_eq!(
            shape_of(&rec),
            vec![(0, C, K), (1, Lf, 10), (0, Lf, 4)],
            "step={step}"
        );
    }
}

/// 既定の `append_part` は現行の切り詰めと同じ記録（先頭 64 KiB だけ。続く行は無傷）。
#[test]
fn sup7_cri2_4580_default_impl_records_same_as_truncation() {
    let sink = MemoryLogSink::default();
    let mut input = body(2 * K + 5);
    input.extend_from_slice(b"\nnext\n");
    let sum = run_with(Box::new(Cursor::new(input)), &sink);
    let got: Vec<Vec<u8>> = sink
        .snapshot()
        .unwrap()
        .into_iter()
        .map(|l| l.bytes)
        .collect();
    assert_eq!(got, vec![body(K), b"next".to_vec()]);
    assert_eq!(sum.lines(), 2);
    assert_eq!(sum.truncated_lines(), 1);
    assert_eq!(sum.discarded_lines(), 0);
}

/// 既定実装の単体: `Continued` では何もせず、終端で `bytes` か先頭断片を `append` する。
#[test]
fn sup7_cri2_4580_default_append_part_unit() {
    #[derive(Default)]
    struct OnlyAppend(Mutex<Vec<Vec<u8>>>);
    impl LogSink for OnlyAppend {
        fn append(&self, _: StreamKind, line: &[u8]) -> Result<(), TraitError> {
            self.0.lock().unwrap().push(line.to_vec());
            Ok(())
        }
    }
    let s = OnlyAppend::default();
    let k = StreamKind::Stdout;
    let p = |index, end, head| LinePart { index, end, head };
    s.append_part(k, b"x", p(0, PartEnd::Continued, b""))
        .unwrap();
    s.append_part(k, b"x", p(2, PartEnd::Continued, b"H"))
        .unwrap();
    assert!(s.0.lock().unwrap().is_empty());
    s.append_part(k, b"b0", p(0, PartEnd::Lf, b"")).unwrap();
    s.append_part(k, b"b1", p(0, PartEnd::Eof, b"")).unwrap();
    s.append_part(k, b"zz", p(2, PartEnd::Lf, b"HEAD")).unwrap();
    s.append_part(k, b"zz", p(1, PartEnd::Eof, b"HEAD2"))
        .unwrap();
    let want: Vec<Vec<u8>> = ["b0", "b1", "HEAD", "HEAD2"]
        .iter()
        .map(|s| s.as_bytes().to_vec())
        .collect();
    assert_eq!(*s.0.lock().unwrap(), want);
}

/// Continued の後に読み取りエラー: 終端は来ず、既定の sink には何も残らない。
#[test]
fn sup7_cri2_4580_read_error_after_continued_records_nothing() {
    let rec = PartRecorder::default();
    let sum = run_with(Box::new(FailingRead(Cursor::new(body(K + 10)))), &rec);
    assert_eq!(shape_of(&rec), vec![(0, PartEnd::Continued, K)]);
    assert_eq!(sum.lines(), 1);
    assert_eq!(sum.discarded_lines(), 1);
    assert_eq!(sum.truncated_lines(), 1);
    assert_eq!(sum.error_code(), Some(ErrorCode::Internal));

    let sink = MemoryLogSink::default();
    run_with(Box::new(FailingRead(Cursor::new(body(K + 10)))), &sink);
    assert!(sink.snapshot().unwrap().is_empty());
}

/// 行の途中（index 1 の Continued）で sink が失敗しても、その行は 1 回だけ数え、以後 sink を呼ばない。
#[test]
fn sup7_cri2_4580_sink_failure_mid_line_counts_once() {
    let rec = PartRecorder {
        fail_at: Some(1),
        ..Default::default()
    };
    let mut input = body(3 * K + 5);
    input.extend_from_slice(b"\nnext\n");
    let sum = run_with(Box::new(Cursor::new(input)), &rec);
    assert_eq!(rec.calls.lock().unwrap().len(), 2);
    assert_eq!(sum.lines(), 2);
    assert_eq!(sum.discarded_lines(), 2);
    assert_eq!(sum.truncated_lines(), 1);
    assert_eq!(sum.error_code(), Some(ErrorCode::Unavailable));
}
