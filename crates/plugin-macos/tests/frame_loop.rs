//! 生成バイナリを core 役のテストから駆動するフレーム送受信の結合試験（TASK-115.2・#386。REPAIR-12）。
//!
//! テスト側が `UdsListener` を bind して子（plugin-macos）を spawn し、子が connect してくる
//! 既存契約（core が bind・plugin が connect）どおりに往復させる。待ちはすべて期限つきで、超過時は
//! kill して失敗にする（REPAIR-5）。UDS 実体が unix のみ（非 unix の `UdsListener::bind` は `Unimplemented`）のため unix に限定する。
//! 対応 ID: TASK-115・PLUG-1・PLUG-12・MAC-1・REPAIR-5。
#![cfg(unix)]

use std::io::{Read, Write};
use std::os::unix::fs::DirBuilderExt;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use fandhe_container_plugin::{
    ControlMessage, FRAME_HEADER_LEN, Frame, FrameHeader, JsonLinesPeerAuthObserver,
    MAX_PAYLOAD_LEN, MessageId, PLUGIN_SOCKET_ENV, PluginErrorCode, RpcTimeout, UdsListener,
    UdsStream, decode_message, encode_message,
};

const BIN: &str = env!("CARGO_BIN_EXE_fandhe-container-plugin-macos");
const WAIT: Duration = Duration::from_secs(30);

struct Harness {
    child: Child,
    stream: Option<UdsStream>,
    dir: PathBuf,
    sock: String,
}

impl Harness {
    fn start() -> Self {
        let dir = create_unique_dir();
        let sock = dir.join("p.sock").to_str().expect("utf8").to_string();
        let listener = UdsListener::bind(std::path::Path::new(&sock)).expect("bind");
        let child = Command::new(BIN)
            .env_clear()
            .env(PLUGIN_SOCKET_ENV, &sock)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn");
        let mut h = Self {
            child,
            stream: None,
            dir,
            sock,
        };
        let mut obs = JsonLinesPeerAuthObserver::new();
        h.stream = Some(
            listener
                .accept(Duration::from_secs(20), &mut obs)
                .expect("accept"),
        );
        h
    }

    fn stream(&mut self) -> &mut UdsStream {
        self.stream.as_mut().expect("stream")
    }

    /// 要求を送り、応答 1 件を受ける。
    fn call(&mut self, id: u64, body: &[&str]) -> ControlMessage<Vec<String>> {
        let f = request(id, body);
        self.stream()
            .write_frame(&f, RpcTimeout::default())
            .expect("write");
        let r = self
            .stream()
            .read_frame(RpcTimeout::default())
            .expect("read");
        decode_message(&r).expect("decode")
    }

    /// 接続を閉じて子の終了を待ち、(終了コード, stderr) を返す。
    fn finish(self) -> (i32, String) {
        self.finish_with(true)
    }

    /// `close` が偽なら接続を開いたまま子の自発的な終了を待つ（期限切れによる切断の検証用）。
    fn finish_with(mut self, close: bool) -> (i32, String) {
        if close {
            self.stream = None;
        }
        let start = Instant::now();
        let status = loop {
            if let Some(s) = self.child.try_wait().expect("try_wait") {
                break s;
            }
            if start.elapsed() > WAIT {
                let _ = self.child.kill();
                let _ = self.child.wait();
                panic!("plugin binary did not exit within deadline");
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        let mut err = String::new();
        if let Some(mut s) = self.child.stderr.take() {
            let _ = s.read_to_string(&mut err);
        }
        assert!(!err.contains(&self.sock), "stderr leaks socket path: {err}");
        (status.code().expect("exit code"), err)
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir); // 排他作成した自前のディレクトリのみ
    }
}

fn create_unique_dir() -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    for n in 0..100u32 {
        let p = PathBuf::from("/tmp").join(format!("fc-pmf-{}-{nanos:x}-{n}", std::process::id()));
        match std::fs::DirBuilder::new().mode(0o700).create(&p) {
            Ok(()) => return p,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => panic!("create test dir: {e}"),
        }
    }
    panic!("could not create a unique test dir");
}

fn request(id: u64, body: &[&str]) -> Frame {
    encode_message(&ControlMessage::Request {
        id: MessageId::new(id),
        body: body.iter().map(|s| s.to_string()).collect::<Vec<String>>(),
    })
    .expect("encode")
}

fn expect_unimplemented(msg: ControlMessage<Vec<String>>, want_id: u64) {
    match msg {
        ControlMessage::Error { id, error } => {
            assert_eq!(id.get(), want_id);
            assert_eq!(error.code(), PluginErrorCode::Unimplemented);
            assert_eq!(error.message(), "operation is not implemented");
        }
        other => panic!("unexpected {other:?}"),
    }
}

/// 切断後に読み取りが EOF（`Unavailable`）になることを確かめる。
fn expect_disconnected(h: &mut Harness) {
    let e = h
        .stream()
        .read_frame(RpcTimeout::default())
        .expect_err("connection must be closed");
    assert_eq!(e.code(), PluginErrorCode::Unavailable);
}

#[test]
fn task115_2_plug1_sequential_requests_keep_connection_and_exit_0_on_close() {
    let mut h = Harness::start();
    expect_unimplemented(h.call(1, &["kill", "a"]), 1);
    expect_unimplemented(h.call(2, &["list"]), 2);
    let (code, err) = h.finish();
    assert_eq!(code, 0, "{err}");
    assert_eq!(err, "");
}

#[test]
fn task115_2_plug1_idle_longer_than_poll_still_served() {
    let mut h = Harness::start();
    std::thread::sleep(Duration::from_millis(2500));
    expect_unimplemented(h.call(10, &["op"]), 10);
    let (code, err) = h.finish();
    assert_eq!(code, 0, "{err}");
}

#[test]
fn task115_2_plug1_empty_body_gets_invalid_argument_and_continues() {
    let mut h = Harness::start();
    match h.call(4, &[]) {
        ControlMessage::Error { id, error } => {
            assert_eq!(id.get(), 4);
            assert_eq!(error.code(), PluginErrorCode::InvalidArgument);
        }
        other => panic!("unexpected {other:?}"),
    }
    expect_unimplemented(h.call(5, &["op"]), 5);
    let (code, _) = h.finish();
    assert_eq!(code, 0);
}

#[test]
fn task115_2_plug1_corrupt_header_disconnects_with_code_4() {
    let mut h = Harness::start();
    expect_unimplemented(h.call(1, &["op"]), 1);
    let mut hdr = FrameHeader::new(0).expect("hdr").to_bytes();
    if let Some(b) = hdr.get_mut(FRAME_HEADER_LEN - 1) {
        *b ^= 0xff;
    }
    h.stream().write_all(&hdr).expect("write header");
    expect_disconnected(&mut h);
    let (code, err) = h.finish();
    assert_eq!(code, 4, "{err}");
    assert!(err.starts_with("error: DATA_LOSS: "), "{err}");
}

/// テスト用の CRC-32C（ヘッダ CRC を正しく作るため。共有 crate の実装は非公開）。
fn crc32c(bytes: &[u8]) -> u32 {
    let mut c = !0u32;
    for b in bytes {
        c ^= u32::from(*b);
        for _ in 0..8 {
            c = if c & 1 == 1 {
                (c >> 1) ^ 0x82F6_3B78
            } else {
                c >> 1
            };
        }
    }
    !c
}

fn raw_header(payload_len: u32) -> [u8; FRAME_HEADER_LEN] {
    let l = payload_len.to_le_bytes();
    let p = [1u8, l[0], l[1], l[2], l[3]];
    let c = crc32c(&p).to_le_bytes();
    [p[0], p[1], p[2], p[3], p[4], c[0], c[1], c[2], c[3]]
}

#[test]
fn task115_2_plug1_test_crc_matches_shared_header_encoding() {
    assert_eq!(raw_header(5), FrameHeader::new(5).expect("hdr").to_bytes());
}

#[test]
fn task115_2_plug1_oversized_length_disconnects_without_body() {
    let mut h = Harness::start();
    h.stream()
        .write_all(&raw_header(MAX_PAYLOAD_LEN + 1))
        .expect("write header");
    expect_disconnected(&mut h);
    let (code, err) = h.finish();
    assert_eq!(code, 4, "{err}");
    assert!(err.starts_with("error: INVALID_ARGUMENT: "), "{err}");
}

#[test]
fn task115_2_plug1_checksum_mismatch_disconnects_with_code_4() {
    let mut h = Harness::start();
    let mut bytes = request(1, &["op"]).encode();
    if let Some(b) = bytes.last_mut() {
        *b ^= 0x01;
    }
    h.stream().write_all(&bytes).expect("write");
    expect_disconnected(&mut h);
    let (code, err) = h.finish();
    assert_eq!(code, 4, "{err}");
    assert!(err.starts_with("error: DATA_LOSS: "), "{err}");
}

#[test]
fn task115_2_plug1_response_envelope_is_protocol_violation() {
    let mut h = Harness::start();
    let f = encode_message(&ControlMessage::Response {
        id: MessageId::new(1),
        body: vec!["x".to_string()],
    })
    .expect("encode");
    h.stream()
        .write_frame(&f, RpcTimeout::default())
        .expect("write");
    expect_disconnected(&mut h);
    let (code, err) = h.finish();
    assert_eq!(code, 4, "{err}");
    assert!(err.starts_with("error: INVALID_ARGUMENT: "), "{err}");
}

#[test]
fn task115_2_plug1_stalled_partial_frame_times_out() {
    let mut h = Harness::start();
    let hdr = FrameHeader::new(0).expect("hdr").to_bytes();
    h.stream()
        .write_all(hdr.get(..3).expect("slice"))
        .expect("write");
    // 合計期限（10 秒）を超えて黙る。子は接続を開いたまま期限後に自発的に終了する。
    let (code, err) = h.finish_with(false);
    assert_eq!(code, 4, "{err}");
    assert!(err.starts_with("error: TIMEOUT: "), "{err}");
}

/// 応答が Error のとき (code, message) を返す。
fn expect_error(msg: ControlMessage<Vec<String>>, want_id: u64) -> (PluginErrorCode, String) {
    match msg {
        ControlMessage::Error { id, error } => {
            assert_eq!(id.get(), want_id);
            (error.code(), error.message().to_string())
        }
        other => panic!("unexpected {other:?}"),
    }
}

/// 3 OS 共通の検証経路（TASK-115.3・#387）: 存在しない kernel と不正 id は固定文言の INVALID_ARGUMENT。
#[test]
fn task115_3_plug1_adapter_rejects_invalid_create_with_fixed_messages() {
    let mut h = Harness::start();
    let r = expect_error(
        h.call(1, &["create", "a", "/nonexistent/SECRET", "", ""]),
        1,
    );
    assert_eq!(
        r,
        (
            PluginErrorCode::InvalidArgument,
            "config.path_not_found: VM configuration was rejected".to_string()
        )
    );
    let r = expect_error(h.call(2, &["create", "..", "/k", "", ""]), 2);
    assert_eq!(
        r,
        (
            PluginErrorCode::InvalidArgument,
            "invalid container id".to_string()
        )
    );
    expect_unimplemented(h.call(3, &["kill", "a"]), 3);
    let (code, err) = h.finish();
    assert_eq!(code, 0, "{err}");
    // 計測は create の 2 回分のみ（未実装操作は対象外）。入力値は含まれない（REPAIR-4）。
    let lines: Vec<&str> = err.lines().collect();
    assert_eq!(lines.len(), 2, "{err}");
    assert!(lines.iter().all(|l| l.starts_with("{\"event\":\"plugin.op\",\"op\":\"create\",\"result\":\"err\"")), "{err}");
    assert!(!err.contains("SECRET"), "{err}");
}

/// create 成功後の start は、非 macOS では UNIMPLEMENTED、macOS では entitlement なしの VZ 失敗（Error）になる。
/// いずれも接続は継続し、後続要求に応答する。起動失敗 VM は停止未確認として終了コード 5 で終わる。
#[test]
fn task115_3_mac1_start_returns_error_frame_and_keeps_connection() {
    let mut h = Harness::start();
    let kernel = h.dir.join("kernel");
    std::fs::write(&kernel, b"k").expect("write kernel");
    let k = kernel.to_str().expect("utf8").to_string();
    match h.call(1, &["create", "a", &k, "", ""]) {
        ControlMessage::Response { id, body } => {
            assert_eq!(id.get(), 1);
            assert_eq!(body, vec!["created".to_string()]);
        }
        other => panic!("unexpected {other:?}"),
    }
    let (code, message) = expect_error(h.call(2, &["start", "a"]), 2);
    #[cfg(not(target_os = "macos"))]
    {
        assert_eq!(code, PluginErrorCode::Unimplemented);
        assert_eq!(
            message,
            "Virtualization.framework is only available on macOS"
        );
    }
    #[cfg(target_os = "macos")]
    {
        let _ = (code, message);
    }
    expect_unimplemented(h.call(3, &["delete", "a"]), 3);
    let (code, err) = h.finish();
    // 起動に失敗した VM は停止を確認できないため、成功終了にせず終了コード 5 で報告する（REPAIR-3）。
    assert_eq!(code, 5, "{err}");
    assert!(
        err.contains("\"event\":\"plugin.cleanup\",\"stopped\":0,\"remaining\":1"),
        "{err}"
    );
    assert!(err.contains("\"op\":\"start\",\"result\":\"err\""), "{err}");
}
