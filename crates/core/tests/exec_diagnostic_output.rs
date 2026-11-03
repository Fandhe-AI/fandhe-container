//! 診断ログ出力の公開 API `emit_diagnostic_line_to` を外部クレートとして呼ぶ結合試験
//! （#1697・REPAIR-5・REPAIR-4・REPAIR-10・REPAIR-12）。
//!
//! `src/exec/diagnostic.rs` 内の単体試験と併置し、公開 API 越しに次の 3 点を具体値で確かめる。
//! - AF_UNIX の stream socket へ固定語彙の 1 行がちょうど 1 回、バイト一致で届く
//! - 送信バッファが満杯でも、ブロッキングの fd のまま有限時間内に `Dropped(WouldBlock)` で返る
//! - 非 socket（pipe・通常ファイル・`/dev/null`）には何も書かず `Dropped(NotUnixSocket)` を返す

#![cfg(target_os = "linux")]

use std::io::{Read as _, Write as _};
use std::os::fd::AsFd as _;
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

#[path = "support/scratch_root.rs"]
mod scratch_root;

use fandhe_container_core::exec::{
    DiagnosticDelivery, DiagnosticDropReason, emit_diagnostic_line_to,
};

/// 起動時 `pidfd_open` 失敗の縮退理由と同じ形の固定語彙 1 行（SUP-6）。
const LINE: &str = r#"{"component":"core.exec","operation":"launch_pidfd","outcome":"unavailable","reason":"failed","errno":"EMFILE"}"#;

/// REPAIR-4・#1697: AF_UNIX の stream socket へ 1 行が改行付きでちょうど 1 回届く。
#[test]
fn diagnostic_line_is_delivered_to_unix_stream_once() {
    let (tx, mut rx) = UnixStream::pair().unwrap();
    assert_eq!(
        emit_diagnostic_line_to(tx.as_fd(), LINE),
        DiagnosticDelivery::Sent
    );
    drop(tx);
    let mut got = Vec::new();
    rx.read_to_end(&mut got).unwrap();
    assert_eq!(got, format!("{LINE}\n").into_bytes());
}

/// REPAIR-5・#1697: 送信先が満杯でも 1 秒未満で `Dropped(WouldBlock)` が返る（`O_NONBLOCK` に頼らない）。
#[test]
fn diagnostic_line_returns_in_bounded_time_when_peer_is_full() {
    let (mut tx, rx) = UnixStream::pair().unwrap();
    tx.set_nonblocking(true).unwrap();
    let chunk = [b'x'; 4096];
    loop {
        match tx.write(&chunk) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(e) => panic!("fill: {e}"),
        }
    }
    tx.set_nonblocking(false).unwrap();
    let start = Instant::now();
    let delivery = emit_diagnostic_line_to(tx.as_fd(), LINE);
    assert!(
        start.elapsed() < Duration::from_secs(1),
        "{:?}",
        start.elapsed()
    );
    assert_eq!(
        delivery,
        DiagnosticDelivery::Dropped(DiagnosticDropReason::WouldBlock)
    );
    drop(rx);
}

/// REPAIR-5・#1697: pipe・通常ファイル・`/dev/null` には書かず `NotUnixSocket` で捨てる（中身は 0 バイト）。
#[test]
fn diagnostic_line_is_not_written_to_non_sockets() {
    let dropped = DiagnosticDelivery::Dropped(DiagnosticDropReason::NotUnixSocket);

    let (mut r, w) = std::io::pipe().unwrap();
    assert_eq!(emit_diagnostic_line_to(w.as_fd(), LINE), dropped);
    drop(w);
    let mut got = Vec::new();
    r.read_to_end(&mut got).unwrap();
    assert_eq!(got, Vec::<u8>::new());

    let scratch = scratch_root::ScratchDir::new("fandhe-diag-it-1697", Duration::from_secs(10));
    let path = scratch.path().join("stderr.log");
    let file = std::fs::File::create(&path).unwrap();
    assert_eq!(emit_diagnostic_line_to(file.as_fd(), LINE), dropped);
    assert_eq!(std::fs::metadata(&path).unwrap().len(), 0);
    drop(file);

    let null = std::fs::OpenOptions::new()
        .write(true)
        .open("/dev/null")
        .unwrap();
    assert_eq!(emit_diagnostic_line_to(null.as_fd(), LINE), dropped);
}
