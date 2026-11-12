//! 記録ファイル検証モード `venus-jig --verify-record` の結合試験（GPU-6・REPAIR-2・REPAIR-12・TASK-172.5 後続・#1885。3 OS・既定集合）。
//!
//! 合成の記録ファイル（`RecordingWriter` で 3 件。実機のストリームは使わない）を bin に渡し、終了コードと stdout の 1 行を
//! 具体値で照合する。出力にパスと payload が含まれないことも全ケースで確かめる。

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::thread;
use std::time::{Duration, Instant};

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

/// 親側の期限（子の 60 秒制限より長い。REPAIR-5）。超過したら子を kill・wait で回収して試験を失敗させる。
const PARENT_DEADLINE: Duration = Duration::from_secs(90);

/// 子を起動し、出力は別スレッドで読み（pipe の詰まりによる停止を防ぐ）、期限つきで終了を待つ。
fn output_with_deadline(mut cmd: Command) -> Output {
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn child");
    let mut out = child.stdout.take().expect("stdout pipe");
    let mut err = child.stderr.take().expect("stderr pipe");
    let t_out = thread::spawn(move || {
        let mut v = Vec::new();
        let _ = out.read_to_end(&mut v);
        v
    });
    let t_err = thread::spawn(move || {
        let mut v = Vec::new();
        let _ = err.read_to_end(&mut v);
        v
    });
    let start = Instant::now();
    let status = loop {
        match child.try_wait().expect("try_wait") {
            Some(st) => break st,
            None if start.elapsed() >= PARENT_DEADLINE => {
                let _ = child.kill();
                let _ = child.wait();
                // 子孫が pipe を持ち続けても読み手の join で待たない（スレッドは切り離す）。
                panic!("deadline_exceeded: child did not exit within {PARENT_DEADLINE:?}");
            }
            None => thread::sleep(Duration::from_millis(20)),
        }
    };
    // 子が終了済みなら EOF は即時に来る。孫が書き込み端を持つ場合に備え期限内で待つ。
    let join = |t: thread::JoinHandle<Vec<u8>>| {
        let limit = Instant::now() + Duration::from_secs(10);
        while !t.is_finished() {
            assert!(
                Instant::now() < limit,
                "deadline_exceeded: output pipe not closed"
            );
            thread::sleep(Duration::from_millis(10));
        }
        t.join().expect("reader thread")
    };
    Output {
        status,
        stdout: join(t_out),
        stderr: join(t_err),
    }
}

fn run(args: &[&Path]) -> Output {
    let mut cmd = Command::new(BIN);
    cmd.args(args);
    output_with_deadline(cmd)
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
    // stderr は構造化ログ 1 行（所要時間つき。REPAIR-4）。
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(
        err.starts_with("{\"event\":\"venus_verify\"") && err.contains("\"elapsed_ms\":"),
        "stderr={err:?}"
    );
    assert_eq!(err.lines().count(), 1, "stderr={err:?}");
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
    // FIFO の作成成功を必須とする（作れないまま検証を省略して成功させない）。
    // この試験は cfg(unix) 限定で、Windows は対象外（FIFO の概念が無い）。
    let mut mk = Command::new("mkfifo");
    mk.arg(&fifo);
    let mko = output_with_deadline(mk);
    assert!(mko.status.success(), "mkfifo failed: {:?}", mko.status);
    {
        use std::os::unix::fs::FileTypeExt;
        let ft = fs::symlink_metadata(&fifo).expect("stat fifo").file_type();
        assert!(ft.is_fifo(), "created path is not a FIFO");
    }
    // open がブロックすれば timeout（60 秒）まで返らない。通常は即時に拒否される。
    let o = run(&[flag, &fifo]);
    expect_line(
        &o,
        1,
        "{\"result\":\"venus_replay.not_regular_file\",\"records\":null,\"bytes\":null}",
    );
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
