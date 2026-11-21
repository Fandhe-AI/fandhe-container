//! CRI ログの書き手が断片を `P` / `F` で書くことの照合試験（CRI-2・SUP-7・REPAIR-12。#4582）。
//!
//! `pump`（捕捉リーダー）→ [`TeeLogSink`]（`@container-logs` 相当の [`MemoryLogSink`] + 本物の [`CriFileSink`]）を通し、
//! CRI ログを kubelet と同じ規則（`P` は内容だけ、`F` は内容 + LF）で連結した結果が入力と一致することを具体値で見る。
//! 親の `logs` の私的な `pump`・`CancelGate` を使うため子孫モジュールとして置く。

use std::io::{Cursor, Read};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use fandhe_container_core::traits::{ContainerLogPath, ErrorCode, TraitError};

use super::super::{
    CancelGate, LinePart, LogSink, MAX_LINE_BYTES, MemoryLogSink, PartEnd, StreamKind,
    StreamSummary, pump,
};
use super::{
    CRI_LOG_CHUNK_BYTES, CRI_LOG_MAX_BYTES, CRI_TIMESTAMP_LEN, CriFileSink, TeeLogSink,
    encode_part_records, format_timestamp,
};

const K: usize = MAX_LINE_BYTES;
/// 16 KiB チャンクのレコード 1 件の大きさ（30 + " stdout P "(10) + 16384 + LF）。
const CHUNK_RECORD: u64 = 30 + 10 + 16384 + 1;

/// LF を含まない決定的なバイト列。
fn body(n: usize) -> Vec<u8> {
    (0..n).map(|i| b'a' + (i % 23) as u8).collect()
}

/// 残骸を消して作る一時ディレクトリ（Drop で後始末）。
struct Tmp(PathBuf, #[allow(dead_code)] crate::test_root::TestRoot);

impl Tmp {
    fn new(tag: &str) -> Self {
        use std::os::unix::fs::PermissionsExt as _;
        static SEQ: AtomicUsize = AtomicUsize::new(0);
        let n = SEQ.fetch_add(1, Ordering::SeqCst);
        let p = std::env::temp_dir().join(format!("fc-cripart-{tag}-{}-{n}", std::process::id()));
        let root = crate::test_root::test_root_at(p);
        let p = root.to_path_buf();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o750)).expect("chmod");
        Self(std::fs::canonicalize(&p).expect("canon"), root)
    }

    fn log(&self) -> ContainerLogPath {
        ContainerLogPath::new(format!("{}/0.log", self.0.display())).expect("log path")
    }
}

/// kubelet の規則で CRI ログを連結する。形式外の行は panic で失敗させる。
/// 戻り値は (タグ列, 内容長の列, stdout の連結, stderr の連結)。
fn restore(file: &[u8]) -> (Vec<u8>, Vec<usize>, Vec<u8>, Vec<u8>) {
    let mut tags = Vec::new();
    let mut lens = Vec::new();
    let (mut out, mut err) = (Vec::new(), Vec::new());
    if file.is_empty() {
        return (tags, lens, out, err);
    }
    assert_eq!(file.last(), Some(&b'\n'), "file must end with LF");
    let text = &file[..file.len() - 1];
    for rec in text.split(|b| *b == b'\n') {
        assert!(rec.len() > CRI_TIMESTAMP_LEN + 6, "short record");
        assert_eq!(rec[CRI_TIMESTAMP_LEN], b' ');
        let rest = &rec[CRI_TIMESTAMP_LEN + 1..];
        let (stream, rest) = if let Some(r) = rest.strip_prefix(b"stdout ") {
            (&mut out, r)
        } else if let Some(r) = rest.strip_prefix(b"stderr ") {
            (&mut err, r)
        } else {
            panic!("unknown stream");
        };
        let tag = rest[0];
        assert!(tag == b'P' || tag == b'F', "unknown tag");
        assert_eq!(rest[1], b' ');
        let content = &rest[2..];
        tags.push(tag);
        lens.push(content.len());
        stream.extend_from_slice(content);
        if tag == b'F' {
            stream.push(b'\n');
        }
    }
    (tags, lens, out, err)
}

fn tag_str(tags: &[u8]) -> String {
    String::from_utf8(tags.to_vec()).expect("ascii")
}

fn flush_and_read(sink: &TeeLogSink, path: &ContainerLogPath) -> Vec<u8> {
    sink.flush().expect("flush");
    std::fs::read(path.as_str()).expect("read")
}

struct Rig {
    _tmp: Tmp,
    path: ContainerLogPath,
    mem: Arc<MemoryLogSink>,
    tee: TeeLogSink,
}

fn rig(tag: &str, limit: u64) -> Rig {
    let tmp = Tmp::new(tag);
    let path = tmp.log();
    let cri = Arc::new(CriFileSink::open_with_limit(&path, limit).expect("open"));
    let mem = Arc::new(MemoryLogSink::default());
    let tee = TeeLogSink::new(mem.clone(), cri);
    Rig {
        _tmp: tmp,
        path,
        mem,
        tee,
    }
}

fn run(input: Vec<u8>, sink: &dyn LogSink) -> StreamSummary {
    pump(
        Box::new(Cursor::new(input)),
        StreamKind::Stdout,
        sink,
        &CancelGate::default(),
        None,
    )
}

fn primary_lines(mem: &MemoryLogSink) -> Vec<Vec<u8>> {
    mem.snapshot()
        .expect("snapshot")
        .into_iter()
        .map(|l| l.bytes)
        .collect()
}

fn with_lf(mut v: Vec<u8>) -> Vec<u8> {
    v.push(b'\n');
    v
}

/// 連結器自身の照合（誤った連結器で偽の緑にならないように）。
#[test]
fn cri2_sup7_4582_restore_helper_follows_kubelet_rule() {
    let t = "1970-01-01T00:00:00.000000000Z";
    let file = format!("{t} stdout P ab\n{t} stdout F c\n{t} stderr P x\n").into_bytes();
    let (tags, lens, out, err) = restore(&file);
    assert_eq!(tag_str(&tags), "PFP");
    assert_eq!(lens, vec![2, 1, 1]);
    assert_eq!(out, b"abc\n".to_vec());
    assert_eq!(err, b"x".to_vec());
}

#[test]
#[should_panic(expected = "unknown tag")]
fn cri2_sup7_4582_restore_helper_rejects_unknown_tag() {
    let t = "1970-01-01T00:00:00.000000000Z";
    restore(format!("{t} stdout X ab\n").as_bytes());
}

/// 64 KiB + 1 の行が元のバイト列に戻る。主（`@container-logs`）は切り詰めのまま。
#[test]
fn cri2_sup7_4582_long_line_over1_restores_bytes() {
    let r = rig("over1", CRI_LOG_MAX_BYTES);
    let input = with_lf(body(K + 1));
    let summary = run(input.clone(), &r.tee);
    let (tags, lens, out, _) = restore(&flush_and_read(&r.tee, &r.path));
    assert_eq!(tag_str(&tags), "PPPPF");
    assert_eq!(
        lens,
        vec![
            CRI_LOG_CHUNK_BYTES,
            CRI_LOG_CHUNK_BYTES,
            CRI_LOG_CHUNK_BYTES,
            CRI_LOG_CHUNK_BYTES,
            1
        ]
    );
    assert_eq!(out, input);
    assert_eq!(primary_lines(&r.mem), vec![body(K)]);
    assert_eq!(summary.truncated_lines(), 1);
}

/// 3 × 64 KiB + 5 の行が元のバイト列に戻る。
#[test]
fn cri2_sup7_4582_long_line_3k5_restores_bytes() {
    let r = rig("3k5", CRI_LOG_MAX_BYTES);
    let input = with_lf(body(3 * K + 5));
    run(input.clone(), &r.tee);
    let (tags, lens, out, _) = restore(&flush_and_read(&r.tee, &r.path));
    assert_eq!(tag_str(&tags), format!("{}F", "P".repeat(12)));
    assert_eq!(lens.len(), 13);
    assert_eq!(lens[11], CRI_LOG_CHUNK_BYTES);
    assert_eq!(lens[12], 5);
    assert_eq!(out, input);
    assert_eq!(primary_lines(&r.mem), vec![body(K)]);
}

/// LF の無い EOF の末尾は全部 `P`（`F` が無い）で、連結結果が入力と一致する。
#[test]
fn cri2_sup7_4582_eof_tail_without_lf_is_partial() {
    let r = rig("eof-tail", CRI_LOG_MAX_BYTES);
    run(b"tail".to_vec(), &r.tee);
    let (tags, _, out, _) = restore(&flush_and_read(&r.tee, &r.path));
    assert_eq!(tag_str(&tags), "P");
    assert_eq!(out, b"tail".to_vec());
    assert_eq!(primary_lines(&r.mem), vec![b"tail".to_vec()]);

    let r = rig("eof-2k3", CRI_LOG_MAX_BYTES);
    let input = body(2 * K + 3);
    run(input.clone(), &r.tee);
    let (tags, _, out, _) = restore(&flush_and_read(&r.tee, &r.path));
    assert_eq!(tag_str(&tags), "P".repeat(9));
    assert_eq!(out, input);
    assert_eq!(primary_lines(&r.mem), vec![body(K)]);
}

/// 通常の行・空行・長い行・EOF の末尾を混ぜた入力が順序どおり完全に戻る。
#[test]
fn cri2_sup7_4582_mixed_lines_restore_in_order() {
    let r = rig("mixed", CRI_LOG_MAX_BYTES);
    let mut input = b"a\n\n".to_vec();
    input.extend(with_lf(body(K + 1)));
    input.extend_from_slice(b"z");
    run(input.clone(), &r.tee);
    let (_, _, out, _) = restore(&flush_and_read(&r.tee, &r.path));
    assert_eq!(out, input);
    assert_eq!(
        primary_lines(&r.mem),
        vec![b"a".to_vec(), Vec::new(), body(K), b"z".to_vec()]
    );
}

/// 総量の上限は断片でも変わらない: 上限に達した断片は 1 バイトも書かず、以後も止まる。主は継続する。
#[test]
fn cri2_4582_size_limit_unchanged_for_parts() {
    assert_eq!(CRI_LOG_MAX_BYTES, 50 * 1024 * 1024);
    // 64 KiB の `Continued` 断片 1 つ分（4 レコード）だけ許す。
    let r = rig("limit", 4 * CHUNK_RECORD);
    let mut input = with_lf(body(3 * K + 5));
    input.extend_from_slice(b"next\n");
    run(input, &r.tee);
    let file = flush_and_read(&r.tee, &r.path);
    assert_eq!(file.len() as u64, 4 * CHUNK_RECORD);
    let (tags, _, _, _) = restore(&file);
    assert_eq!(tag_str(&tags), "PPPP");
    assert_eq!(
        r.tee.failed_codes(),
        [None, Some(ErrorCode::ResourceExhausted)]
    );
    assert_eq!(primary_lines(&r.mem), vec![body(K), b"next".to_vec()]);
}

/// 副が行の途中で失敗しても主は記録を続け、副は以後呼ばれない。
#[test]
fn cri2_4582_tee_cri_failure_mid_line_keeps_primary() {
    #[derive(Default)]
    struct FailFirst(Mutex<usize>);
    impl LogSink for FailFirst {
        fn append(&self, _: StreamKind, _: &[u8]) -> Result<(), TraitError> {
            Ok(())
        }
        fn append_part(&self, _: StreamKind, _: &[u8], _: LinePart<'_>) -> Result<(), TraitError> {
            *self.0.lock().unwrap() += 1;
            Err(TraitError::new(ErrorCode::Unavailable, "injected"))
        }
    }
    let mem = Arc::new(MemoryLogSink::default());
    let fail = Arc::new(FailFirst::default());
    let tee = TeeLogSink::new(mem.clone(), fail.clone());
    let mut input = with_lf(body(K + 1));
    input.extend_from_slice(b"next\n");
    run(input, &tee);
    assert_eq!(*fail.0.lock().unwrap(), 1);
    assert_eq!(primary_lines(&mem), vec![body(K), b"next".to_vec()]);
}

/// 直接呼び出しの契約違反（LF・長さ超過）は固定文言で拒否し、何も書かない（ERR-1）。
#[test]
fn cri2_4582_append_part_rejects_lf_and_oversize() {
    let tmp = Tmp::new("reject");
    let path = tmp.log();
    let sink = CriFileSink::open(&path).expect("open");
    let part = |end| LinePart {
        index: 0,
        end,
        head: &[],
    };
    let e = sink
        .append_part(StreamKind::Stdout, b"SECRETab\ncd", part(PartEnd::Lf))
        .expect_err("lf");
    assert_eq!(e.code(), ErrorCode::InvalidArgument);
    assert_eq!(e.message(), "log line must not contain a line feed");
    let big = vec![b'S'; MAX_LINE_BYTES + 1];
    let e = sink
        .append_part(StreamKind::Stdout, &big, part(PartEnd::Continued))
        .expect_err("oversize");
    assert_eq!(e.code(), ErrorCode::InvalidArgument);
    assert_eq!(e.message(), "log line part exceeds the maximum length");
    assert!(!e.message().contains("SECRET"));
    sink.flush().expect("flush");
    assert_eq!(
        std::fs::read(path.as_str()).expect("read"),
        Vec::<u8>::new()
    );
}

/// 読み取りエラーで終わった未完了の末尾は CRI ログへ書かない（先頭の `Continued` の分だけ残る）。主には何も残らない。
#[test]
fn cri2_sup7_4582_read_error_tail_is_not_written() {
    struct FailingRead(Cursor<Vec<u8>>);
    impl Read for FailingRead {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            match self.0.read(buf)? {
                0 => Err(std::io::Error::other("fake read failure")),
                n => Ok(n),
            }
        }
    }
    let r = rig("read-err", CRI_LOG_MAX_BYTES);
    pump(
        Box::new(FailingRead(Cursor::new(body(K + 10)))),
        StreamKind::Stdout,
        &r.tee,
        &CancelGate::default(),
        None,
    );
    let (tags, _, out, _) = restore(&flush_and_read(&r.tee, &r.path));
    assert_eq!(tag_str(&tags), "PPPP");
    assert_eq!(out, body(K));
    assert_eq!(primary_lines(&r.mem), Vec::<Vec<u8>>::new());
}

/// 純関数の符号化: `Lf` は最後だけ `F`、`Continued` / `Eof` は全 `P`、空の扱い、`encode_records` と一致。
#[test]
fn cri2_sup7_4582_encode_part_records_tags() {
    let ts = format_timestamp(std::time::Duration::ZERO);
    let enc = |bytes: &[u8], end| {
        let mut out = Vec::new();
        encode_part_records(StreamKind::Stdout, bytes, end, &ts, &mut out);
        restore(&out)
    };
    let (tags, lens, _, _) = enc(&body(CRI_LOG_CHUNK_BYTES + 1), PartEnd::Lf);
    assert_eq!(tag_str(&tags), "PF");
    assert_eq!(lens, vec![CRI_LOG_CHUNK_BYTES, 1]);
    let (tags, _, _, _) = enc(&body(K), PartEnd::Continued);
    assert_eq!(tag_str(&tags), "PPPP");
    let (tags, _, _, _) = enc(b"tail", PartEnd::Eof);
    assert_eq!(tag_str(&tags), "P");
    let (tags, lens, _, _) = enc(b"", PartEnd::Lf);
    assert_eq!((tag_str(&tags), lens), ("F".to_string(), vec![0]));
    let (tags, _, _, _) = enc(b"", PartEnd::Continued);
    assert!(tags.is_empty());
    let (tags, _, _, _) = enc(b"", PartEnd::Eof);
    assert!(tags.is_empty());
}
