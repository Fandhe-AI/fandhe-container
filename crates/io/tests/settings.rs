//! `--batch-size` 相当の設定 API（[`fandhe_container_io::WritebackSettings`]・
//! [`fandhe_container_io::parse_batch_size`]）の結合試験（TASK-13.3・IO-1・#78）。
//!
//! 3 OS 共通のテストは公開 API を通じた値の受理・拒否を確認する。Linux /
//! macOS 限定のテストは `tests/writeback.rs` と同じ UDS 経由の構成で、設定
//! した件数でバッチが実際に発火することを確認する（R1）。Windows では
//! `UdsServer::bind` が `Unimplemented` を返すことのみを確認し、3 OS すべてで
//! テストが空にならないようにする（`tests/writeback.rs` と同じ方針）。

use fandhe_container_io::{
    IoErrorCode, MAX_BATCH_SIZE_ARG_LEN, ReceiveLimits, WritebackSettings, parse_batch_size,
};

/// IO-1・TASK-13.3・R1: `"1"`（下限境界）を受理する。
#[test]
fn io1_settings_parse_accepts_one() {
    let config = parse_batch_size("1").expect("1 must be accepted");
    assert_eq!(config.batch_size(), 1);
}

/// IO-1・TASK-13.3・R1: `MAX_BATCH_SIZE`（上限境界）を受理する。
#[test]
fn io1_settings_parse_accepts_max() {
    let input = fandhe_container_io::MAX_BATCH_SIZE.to_string();
    let config = parse_batch_size(&input).expect("MAX_BATCH_SIZE must be accepted");
    assert_eq!(config.batch_size(), fandhe_container_io::MAX_BATCH_SIZE);
}

/// IO-1・TASK-13.3・R3: `WritebackSettings::default()` の既定値は 64 のまま。
#[test]
fn io1_settings_default_is_64() {
    assert_eq!(
        WritebackSettings::default().batch_size(),
        fandhe_container_io::DEFAULT_BATCH_SIZE
    );
}

/// IO-1・TASK-13.3・R2: 0・負数は `InvalidArgument` で拒否する。
#[test]
fn io1_settings_rejects_zero_and_negative() {
    for input in ["0", "-1", "-0", "+8"] {
        match parse_batch_size(input) {
            Ok(_) => panic!("{input:?} must be rejected"),
            Err(err) => assert_eq!(err.code(), IoErrorCode::InvalidArgument, "input={input:?}"),
        }
    }
}

/// IO-1・TASK-13.3・R2: 非数値・範囲外・桁あふれの指定は `InvalidArgument` で
/// 拒否する。
#[test]
fn io1_settings_rejects_non_numeric_and_out_of_range() {
    let overlong = "1".repeat(MAX_BATCH_SIZE_ARG_LEN + 1);
    let overflow_20_digits = "9".repeat(MAX_BATCH_SIZE_ARG_LEN);
    let out_of_range = (fandhe_container_io::MAX_BATCH_SIZE + 1).to_string();
    let inputs: Vec<&str> = vec![
        "",
        " 8",
        "8 ",
        "abc",
        "8a",
        "４",
        &out_of_range,
        &overflow_20_digits,
        &overlong,
    ];
    for input in inputs {
        match parse_batch_size(input) {
            Ok(_) => panic!("{input:?} must be rejected"),
            Err(err) => assert_eq!(err.code(), IoErrorCode::InvalidArgument, "input={input:?}"),
        }
    }
}

/// IO-1・TASK-13.3: エラーメッセージに入力文字列そのものをエコーしない
/// （security.md「情報漏えい」観点）。
#[test]
fn io1_settings_error_does_not_echo_input() {
    let sensitive_looking_input = "9".repeat(MAX_BATCH_SIZE_ARG_LEN);
    let err =
        parse_batch_size(&sensitive_looking_input).expect_err("overflowing input must be rejected");
    assert!(!err.to_string().contains(&sensitive_looking_input));
}

/// IO-1・TASK-13.3・R4: `receive_limits()` は `batch_config()` から
/// `ReceiveLimits::for_batch` で導いたものと一致する。
#[test]
fn io1_settings_receive_limits_match_batch_config() {
    let settings =
        WritebackSettings::from_batch_size_arg("8").expect("8 must be a valid batch size");
    assert_eq!(
        settings.receive_limits(),
        ReceiveLimits::for_batch(&settings.batch_config())
    );
}

/// Linux / macOS 限定: `WritebackSettings` から得た設定で UDS 経由の
/// バッチ write-back を動かし、設定した件数でバッチが発火することを確認する
/// （R1。`tests/writeback.rs` と同じ TempSocketDir・送受信ヘルパー構成）。
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod unix {
    use std::io::{Read, Write};
    use std::os::unix::fs::DirBuilderExt;
    use std::os::unix::net::UnixStream;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::{Duration, Instant};

    use fandhe_container_io::{
        AppendFileSink, Frame, FrameHeader, FrameKind, IoTimeout, NoopServerObserver,
        WritebackSettings, WritebackTimeouts,
    };

    struct TempSocketDir {
        path: PathBuf,
    }

    impl TempSocketDir {
        fn new() -> Self {
            static COUNTER: AtomicU32 = AtomicU32::new(0);
            let n = COUNTER.fetch_add(1, Ordering::Relaxed);
            let pid = std::process::id();
            let dir = std::env::temp_dir().join(format!("fcio-settings-{pid}-{n}"));
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&dir)
                .expect("must be able to create a temp dir for the socket");
            Self { path: dir }
        }

        fn socket_path(&self) -> PathBuf {
            self.path.join("s.sock")
        }

        fn output_path(&self) -> PathBuf {
            self.path.join("out.bin")
        }
    }

    impl Drop for TempSocketDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    fn test_timeout() -> IoTimeout {
        IoTimeout::new(Duration::from_secs(5)).expect("5s must be a valid IoTimeout")
    }

    fn writeback_timeouts() -> WritebackTimeouts {
        WritebackTimeouts {
            recv: test_timeout(),
            send: test_timeout(),
        }
    }

    fn send_write(stream: &mut UnixStream, id: u64, body: &[u8]) {
        let mut payload = Vec::with_capacity(8 + body.len());
        payload.extend_from_slice(&id.to_le_bytes());
        payload.extend_from_slice(body);
        let frame = Frame::new(FrameKind::Write, payload).expect("write frame must construct");
        stream
            .write_all(&frame.encode())
            .expect("client write must succeed");
    }

    fn recv_frame(stream: &mut UnixStream) -> Frame {
        let mut header = [0u8; fandhe_container_io::FRAME_HEADER_LEN];
        stream
            .read_exact(&mut header)
            .expect("client must read the response header");
        let parsed_header = FrameHeader::from_bytes(header).expect("response header must be valid");
        let mut body = vec![0u8; parsed_header.body_len()];
        stream
            .read_exact(&mut body)
            .expect("client must read the response body");
        Frame::decode_body(parsed_header, &body).expect("response frame must decode")
    }

    fn ack_id(frame: &Frame) -> u64 {
        let ack = fandhe_container_io::decode_ack(frame).expect("frame must be a valid ack");
        assert_eq!(ack.kind(), FrameKind::Ack);
        ack.id().get()
    }

    fn connect(path: &std::path::Path) -> UnixStream {
        let deadline = Instant::now() + Duration::from_secs(5);
        let stream = loop {
            match UnixStream::connect(path) {
                Ok(stream) => break stream,
                Err(_) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(err) => panic!("client failed to connect: {err}"),
            }
        };
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("must be able to set a read timeout on the client stream");
        stream
    }

    /// `WritebackSettings::from_batch_size_arg(batch_size)` を
    /// [`WritebackSettings::bind`] → [`BoundWriteback::accept`] →
    /// [`BoundConnection::serve`] という経路で呼び、`batch_size` 件ごとに
    /// ACK がバッチとして届くことを確認する（R1・REPAIR-2・#78・#1115 codex
    /// レビュー指摘対応。`bind` 側の `ReceiveLimits` と `serve` 側の
    /// `BatchConfig` を個別に取り出して別々に渡すのではなく、同じ
    /// `settings` から生まれた `BoundWriteback` / `BoundConnection` を経由する
    /// 実際の呼び出し経路を検証する。`BoundConnection::serve` は
    /// `BatchConfig` を引数に取らないため、別の設定値を混ぜる経路自体が
    /// 無い）。
    fn run_batch_size_case(batch_size: usize, batches: usize) {
        let dir = TempSocketDir::new();
        let socket_path = dir.socket_path();
        let output_path = dir.output_path();

        let settings = WritebackSettings::from_batch_size_arg(&batch_size.to_string())
            .expect("batch_size must be a valid setting");

        let mut server = settings
            .bind(&socket_path, NoopServerObserver)
            .expect("bind must succeed on a private, empty path");

        let total: u64 = (batch_size * batches) as u64;
        let connect_path = socket_path.clone();
        let client_thread = std::thread::spawn(move || {
            let mut stream = connect(&connect_path);
            for id in 0..total {
                send_write(&mut stream, id, &id.to_le_bytes());
            }
            let mut acked_ids = Vec::with_capacity(total as usize);
            for _ in 0..total {
                let frame = recv_frame(&mut stream);
                acked_ids.push(ack_id(&frame));
            }
            acked_ids
        });

        let mut connection = server
            .accept(test_timeout(), NoopServerObserver)
            .expect("server must accept the client connection within the timeout");

        let file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&output_path)
            .expect("must open output file");
        let mut sink = AppendFileSink::new(file).expect("seek to end must succeed");

        let server_thread =
            std::thread::spawn(move || connection.serve(&mut sink, writeback_timeouts()));

        let acked_ids = client_thread.join().expect("client thread must not panic");
        assert_eq!(acked_ids, (0..total).collect::<Vec<_>>());

        let contents = std::fs::read(&output_path).expect("must read output file");
        let expected: Vec<u8> = (0..total).flat_map(|id| id.to_le_bytes()).collect();
        assert_eq!(contents, expected);

        let report = server_thread.join().expect("server thread must not panic");
        assert_eq!(report.stats.acks_sent, total);
        assert_eq!(report.stats.batches_written, batches as u64);
        assert_eq!(report.stats.discarded_pending_frames, 0);
    }

    /// IO-1・TASK-13.3・R1: `batch_size = 1`（下限境界）で 3 バッチぶん送ると、
    /// 1 件ごとにバッチが発火する。
    #[test]
    fn io1_settings_batch_size_1_via_uds_fires_at_configured_count() {
        run_batch_size_case(1, 3);
    }

    /// IO-1・TASK-13.3・R1: `batch_size = 5`（任意件数）で 2 バッチぶん送ると、
    /// 5 件ごとにバッチが発火する。
    #[test]
    fn io1_settings_batch_size_5_via_uds_fires_at_configured_count() {
        run_batch_size_case(5, 2);
    }

    /// IO-1・TASK-13.3・R1・R3: `batch_size = 64`（既定値）で 1 バッチぶん
    /// 送ると、64 件で発火する。
    #[test]
    fn io1_settings_batch_size_64_via_uds_fires_at_configured_count() {
        run_batch_size_case(64, 1);
    }

    /// IO-1・TASK-13.3・#1115 Bugbot レビュー指摘対応: `WritebackSettings::bind`
    /// が返す [`fandhe_container_io::BoundWriteback`] は、渡した `observer` を
    /// ラッパーの中へ隠さず `observer()` / `observer_mut()` 経由で取り出せる。
    /// `JsonLinesServerObserver` を bind に渡した場合、`accept` が発火させる
    /// Accept イベントが `observer_mut().drain_lines()` で実際に取り出せる
    /// ことを、素の `NoopServerObserver` ではなく `JsonLinesServerObserver` を
    /// 使った実接続で確認する（推奨経路〔bind/accept〕にこの観測フックを渡すと
    /// Accept / 接続イベントを収集できなくなっていた、という指摘の再現条件を
    /// そのまま実行する）。
    #[test]
    fn io1_settings_bound_writeback_observer_forwards_accept_events() {
        use fandhe_container_io::JsonLinesServerObserver;

        let dir = TempSocketDir::new();
        let socket_path = dir.socket_path();

        let settings =
            WritebackSettings::from_batch_size_arg("1").expect("1 must be a valid batch size");

        let mut server = settings
            .bind(&socket_path, JsonLinesServerObserver::new())
            .expect("bind must succeed on a private, empty path");

        assert!(
            server.observer().is_empty(),
            "no Accept event must have been recorded before any client connects"
        );

        let connect_path = socket_path.clone();
        let client_thread = std::thread::spawn(move || {
            // 接続を確立するだけでよく、フレームの送受信までは不要
            // （`accept` が Accept イベントを記録することの確認が目的）。
            let _stream = connect(&connect_path);
        });

        let connection = server
            .accept(test_timeout(), fandhe_container_io::NoopServerObserver)
            .expect("server must accept the client connection within the timeout");
        drop(connection);
        client_thread.join().expect("client thread must not panic");

        let lines = server.observer_mut().drain_lines();
        assert!(
            !lines.is_empty(),
            "BoundWriteback::observer_mut() must forward accept's Accept event to the \
             JsonLinesServerObserver passed to WritebackSettings::bind"
        );
    }
}

/// 非対応 OS（Windows）では `UdsServer::bind` が常に `Unimplemented` を返す
/// ことを確認する（`tests/writeback.rs` の同名テストと同じ方針。3 OS すべてで
/// テストを空にしないため）。
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
#[test]
fn io1_settings_uds_bind_is_unimplemented_on_unsupported_os() {
    use fandhe_container_io::{IoErrorCode, NoopServerObserver, WritebackSettings};

    let settings =
        WritebackSettings::from_batch_size_arg("8").expect("8 must be a valid batch size");
    let path = std::env::temp_dir().join("fcio-settings-unsupported.sock");
    let err = settings
        .bind(&path, NoopServerObserver)
        .expect_err("bind must be unimplemented on unsupported OS");
    assert_eq!(err.code(), IoErrorCode::Unimplemented);
}
