//! 記録ファイル検証モード `venus-jig --verify-record` の結合試験（GPU-6・REPAIR-2・REPAIR-12・TASK-172.5 後続・#1885。3 OS・既定集合）。
//!
//! 合成の記録ファイル（`RecordingWriter` で 3 件。実機のストリームは使わない）を bin に渡し、終了コードと stdout の 1 行を
//! 具体値で照合する。出力にパスと payload が含まれないことも全ケースで確かめる。

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU32, Ordering};

use fandhe_container_plugin_macos::gpu::venus::replay::{MAX_RECORDING_LEN, RecordingWriter};

const BIN: &str = env!("CARGO_BIN_EXE_venus-jig");
const PATH_MARK: &str = "fcvnsrec-secret-path";
const PAYLOAD_MARK: &[u8] = b"PAYLOADMARK";
/// 20（ファイルヘッダ）+ (12+4+4) + (12+8+4) + (12+0+4)。
const GOOD_LEN: u64 = 80;

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        static N: AtomicU32 = AtomicU32::new(0);
        let n = N.fetch_add(1, Ordering::SeqCst);
        let p = std::env::temp_dir().join(format!("{PATH_MARK}-{}-{n}", std::process::id()));
        fs::create_dir(&p).expect("scratch dir");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).expect("chmod");
        }
        Self(p)
    }
    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn good_bytes() -> Vec<u8> {
    let mut w = RecordingWriter::new(Vec::new());
    w.append(&PAYLOAD_MARK[..4]).expect("append 1");
    w.append(&PAYLOAD_MARK[..8]).expect("append 2");
    w.append(&[]).expect("append 3");
    w.finish().expect("finish")
}

fn run(args: &[&Path]) -> Output {
    Command::new(BIN)
        .args(args)
        .output()
        .expect("run venus-jig")
}

fn stdout_of(o: &Output) -> String {
    String::from_utf8(o.stdout.clone()).expect("utf8 stdout")
}

fn assert_no_leak(o: &Output) {
    for stream in [&o.stdout, &o.stderr] {
        let s = String::from_utf8_lossy(stream);
        assert!(!s.contains(PATH_MARK), "path leaked: {s}");
        assert!(!s.contains("PAYLOAD"), "payload leaked: {s}");
    }
}

fn expect_line(o: &Output, code: i32, line: &str) {
    assert_eq!(o.status.code(), Some(code), "stderr={:?}", o.stderr);
    assert_eq!(stdout_of(o), format!("{line}\n"));
    assert!(o.stderr.is_empty(), "stderr={:?}", o.stderr);
    assert_no_leak(o);
}

fn write_and_verify(s: &Scratch, bytes: &[u8]) -> Output {
    let p = s.path("rec.bin");
    fs::write(&p, bytes).expect("write");
    run(&[Path::new("--verify-record"), &p])
}

#[test]
fn gpu6_repair2_1885_verify_mode_reports_ok_count_and_bytes() {
    let s = Scratch::new();
    let bytes = good_bytes();
    assert_eq!(bytes.len() as u64, GOOD_LEN);
    let o = write_and_verify(&s, &bytes);
    expect_line(&o, 0, "{\"result\":\"ok\",\"records\":3,\"bytes\":80}");
}

#[test]
fn gpu6_repair2_1885_verify_mode_rejects_corruptions_with_exact_codes() {
    let s = Scratch::new();

    let mut b = good_bytes();
    b[32] ^= 0xff; // 1 件目の payload の 1 バイト
    let o = write_and_verify(&s, &b);
    expect_line(
        &o,
        1,
        "{\"result\":\"venus_replay.record_checksum\",\"records\":null,\"bytes\":80}",
    );

    let mut b = good_bytes();
    b[44] = 2; // 2 件目の seqno（CRC より先に検査される）
    let o = write_and_verify(&s, &b);
    expect_line(
        &o,
        1,
        "{\"result\":\"venus_replay.sequence_mismatch\",\"records\":null,\"bytes\":80}",
    );

    let mut b = good_bytes();
    b.push(0);
    let o = write_and_verify(&s, &b);
    expect_line(
        &o,
        1,
        "{\"result\":\"venus_replay.trailing_bytes\",\"records\":null,\"bytes\":81}",
    );

    let mut b = good_bytes();
    b[0] ^= 0xff;
    let o = write_and_verify(&s, &b);
    expect_line(
        &o,
        1,
        "{\"result\":\"venus_replay.bad_magic\",\"records\":null,\"bytes\":80}",
    );
}

#[test]
fn gpu6_repair2_1885_verify_mode_rejects_non_regular_and_missing_files() {
    let s = Scratch::new();
    let flag = Path::new("--verify-record");

    let o = run(&[flag, &s.0]);
    expect_line(
        &o,
        1,
        "{\"result\":\"venus_replay.not_regular_file\",\"records\":null,\"bytes\":null}",
    );

    let o = run(&[flag, &s.path("missing.bin")]);
    expect_line(
        &o,
        1,
        "{\"result\":\"venus_replay.io\",\"records\":null,\"bytes\":null}",
    );

    let big = s.path("big.bin");
    let f = fs::File::create(&big).expect("create");
    f.set_len(MAX_RECORDING_LEN + 1).expect("sparse");
    drop(f);
    let o = run(&[flag, &big]);
    expect_line(
        &o,
        1,
        "{\"result\":\"venus_replay.recording_too_large\",\"records\":null,\"bytes\":null}",
    );
}

#[cfg(unix)]
#[test]
fn gpu6_repair2_1885_verify_mode_rejects_symlink_and_fifo_without_blocking() {
    let s = Scratch::new();
    let flag = Path::new("--verify-record");
    let target = s.path("rec.bin");
    fs::write(&target, good_bytes()).expect("write");
    let link = s.path("link.bin");
    std::os::unix::fs::symlink(&target, &link).expect("symlink");
    let o = run(&[flag, &link]);
    expect_line(
        &o,
        1,
        "{\"result\":\"venus_replay.not_regular_file\",\"records\":null,\"bytes\":null}",
    );

    let fifo = s.path("fifo.bin");
    let made = Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .map(|st| st.success())
        .unwrap_or(false);
    if made {
        // open がブロックすれば timeout（60 秒）まで返らない。通常は即時に拒否される。
        let o = run(&[flag, &fifo]);
        expect_line(
            &o,
            1,
            "{\"result\":\"venus_replay.not_regular_file\",\"records\":null,\"bytes\":null}",
        );
    }
}

#[test]
fn gpu6_repair2_1885_verify_mode_argument_errors() {
    let o = run(&[
        Path::new("--verify-record"),
        Path::new("rel/fcvnsrec-secret-path"),
    ]);
    assert_eq!(o.status.code(), Some(2));
    assert!(o.stdout.is_empty());
    assert_eq!(
        String::from_utf8(o.stderr.clone()).expect("utf8"),
        "{\"code\":\"PATH_NOT_ABSOLUTE\",\"message\":\"recording path must be absolute\"}\n"
    );
    assert_no_leak(&o);

    for args in [
        vec![Path::new("--verify-record")],
        vec![
            Path::new("--verify-record"),
            Path::new("/x"),
            Path::new("extra"),
        ],
    ] {
        let o = run(&args);
        assert_eq!(o.status.code(), Some(2));
        assert!(o.stdout.is_empty());
        assert_eq!(
            String::from_utf8(o.stderr.clone()).expect("utf8"),
            "{\"code\":\"INVALID_ARGUMENT\",\"message\":\"usage: --verify-record <absolute-path> (no other arguments)\"}\n"
        );
    }
}
