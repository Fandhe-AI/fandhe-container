//! stream-exec の channel（公開 API）の結合試験（SUP-6・REPAIR-2・REPAIR-5・#3759）。
//!
//! 実際の socketpair の上で、plugin-cri 側（`send_stdio_handover`・`recv_from_helper`）と helper 側
//! （`recv_stdio_handover`・`send_started`・`send_pty_master`・`send_result`）の公開 API だけを通す。
//! helper の本番入口（#3760）は未実装のため、双方を同じプロセスの 2 端で模擬する。root・実コンテナは不要で、
//! 既定のテスト集合で動く。期待値は具体値で照合する。

#![cfg(target_os = "linux")]

use std::fs::File;
use std::io::{Read as _, Write as _};
use std::os::fd::{AsFd as _, OwnedFd};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use fandhe_container_core::exec::ExecCgroupName;
use fandhe_container_core::traits::ErrorCode;
use fandhe_container_supervisor::stream_exec::channel::{
    ChannelError, HelperMessage, StdioSend, recv_from_helper, recv_stdio_handover, send_pty_master,
    send_result, send_started, send_stdio_handover,
};
use fandhe_container_supervisor::stream_exec::wire::{
    ExitSignal, StdioMask, StreamExecOutcome, WireError,
};

fn far() -> Instant {
    Instant::now() + Duration::from_secs(10)
}

fn pair() -> (UnixStream, UnixStream) {
    UnixStream::pair().expect("socketpair")
}

/// stdio の通し: fd が相手側で実際に読み書きでき、helper の応答 3 種が順に届く。
#[test]
fn sup6_stdio_handover_and_helper_replies_roundtrip() {
    let (plugin, helper) = pair();

    // plugin 側が保持する端: stdin へ書く端・stdout を読む端。helper へ渡す端は反対側。
    let (stdin_r, stdin_w) = std::io::pipe().expect("pipe");
    let (stdout_r, stdout_w) = std::io::pipe().expect("pipe");
    let stdin_r = OwnedFd::from(stdin_r);
    let stdout_w = OwnedFd::from(stdout_w);

    send_stdio_handover(
        &plugin,
        &StdioSend {
            stdin: Some(stdin_r.as_fd()),
            stdout: Some(stdout_w.as_fd()),
            stderr: None,
        },
        far(),
    )
    .expect("send handover");
    // 送り側の複製は閉じる（helper が持つ端だけが読み取り端 / 書き込み端として残る）。
    drop(stdin_r);
    drop(stdout_w);

    let expected = StdioMask::from_presence(true, true, false);
    let got = recv_stdio_handover(&helper, expected, far()).expect("recv handover");
    assert!(got.stderr.is_none());
    let mut h_stdin = File::from(got.stdin.expect("stdin fd"));
    let mut h_stdout = File::from(got.stdout.expect("stdout fd"));

    let mut stdin_w = File::from(OwnedFd::from(stdin_w));
    stdin_w.write_all(b"ping").expect("write stdin");
    drop(stdin_w);
    let mut buf = Vec::new();
    h_stdin.read_to_end(&mut buf).expect("helper reads stdin");
    assert_eq!(buf, b"ping");

    h_stdout.write_all(b"pong").expect("helper writes stdout");
    drop(h_stdout);
    let mut out = Vec::new();
    File::from(OwnedFd::from(stdout_r))
        .read_to_end(&mut out)
        .expect("plugin reads stdout");
    assert_eq!(out, b"pong");

    // helper → plugin-cri: Started → PtyMaster（pty master）→ Result。
    send_started(
        &helper,
        &ExecCgroupName::new("exec-4242-0").expect("name"),
        far(),
    )
    .expect("send started");
    let ptmx = File::options()
        .read(true)
        .write(true)
        .open("/dev/ptmx")
        .expect("open /dev/ptmx");
    send_pty_master(&helper, ptmx.as_fd(), far()).expect("send pty master");
    let outcome = StreamExecOutcome::Signaled(ExitSignal::new(9).expect("signal 9"));
    send_result(&helper, &outcome, far()).expect("send result");

    match recv_from_helper(&plugin, far()).expect("started") {
        HelperMessage::Started(name) => assert_eq!(name.as_str(), "exec-4242-0"),
        other => panic!("expected Started, got {other:?}"),
    }
    match recv_from_helper(&plugin, far()).expect("pty") {
        HelperMessage::PtyMaster(m) => {
            let meta = File::from(m.into_owned_fd()).metadata().expect("stat");
            assert_eq!(std::os::unix::fs::MetadataExt::rdev(&meta), (5 << 8) | 2);
        }
        other => panic!("unexpected message: {other:?}"),
    }
    match recv_from_helper(&plugin, far()).expect("result") {
        HelperMessage::Result(o) => assert_eq!(o, outcome),
        other => panic!("unexpected message: {other:?}"),
    }
}

/// pty master でない fd（`/dev/null`）は `NotPtyMaster`・`InvalidArgument` で拒否する（SUP-6・SEC-1・#4100）。
#[test]
fn sup6_non_pty_master_is_rejected() {
    let (plugin, helper) = pair();
    let dev_null = File::open("/dev/null").expect("open /dev/null");
    send_pty_master(&helper, dev_null.as_fd(), far()).expect("send");
    let err = recv_from_helper(&plugin, far()).expect_err("must reject");
    assert_eq!(err, ChannelError::NotPtyMaster);
    assert_eq!(err.code(), ErrorCode::InvalidArgument);
}

/// 期待と違う mask は拒否し、分類は `InvalidArgument`。
#[test]
fn sup6_mask_mismatch_is_rejected() {
    let (plugin, helper) = pair();
    let dev_null = File::open("/dev/null").expect("open");
    send_stdio_handover(
        &plugin,
        &StdioSend {
            stdin: Some(dev_null.as_fd()),
            ..StdioSend::default()
        },
        far(),
    )
    .expect("send");
    let err = recv_stdio_handover(&helper, StdioMask::from_presence(true, true, true), far())
        .expect_err("mask mismatch");
    assert_eq!(err, ChannelError::MaskMismatch);
    assert_eq!(err.code(), ErrorCode::InvalidArgument);
}

/// 壊れたヘッダ（magic 違い）は payload を読まずに拒否する。
#[test]
fn sup6_bad_magic_is_rejected_as_malformed() {
    let (mut plugin, helper) = pair();
    plugin.write_all(b"XXXX\x01\x01\x00\x00").expect("write");
    let err = recv_from_helper(&helper, far()).expect_err("bad magic");
    assert!(
        matches!(err, ChannelError::Malformed(WireError::BadMagic)),
        "{err:?}"
    );
}

/// 相手の切断は `Closed`（`Unavailable`）、相手が送らないときの期限超過は `Timeout`。
#[test]
fn sup6_peer_close_and_deadline_are_reported() {
    let (plugin, helper) = pair();
    drop(helper);
    let err = recv_from_helper(&plugin, far()).expect_err("closed");
    assert_eq!(err, ChannelError::Closed);
    assert_eq!(err.code(), ErrorCode::Unavailable);

    let (plugin, _helper) = pair();
    let started = Instant::now();
    let err = recv_from_helper(&plugin, Instant::now() + Duration::from_millis(100))
        .expect_err("timeout");
    assert_eq!(err, ChannelError::Timeout);
    assert_eq!(err.code(), ErrorCode::Timeout);
    assert!(started.elapsed() < Duration::from_secs(5));

    // 期限が過去なら送信も即 `Timeout`。
    let (plugin, _helper) = pair();
    let err = send_started(
        &plugin,
        &ExecCgroupName::new("exec-4242-0").expect("name"),
        Instant::now(),
    )
    .expect_err("expired");
    assert_eq!(err, ChannelError::Timeout);
}
