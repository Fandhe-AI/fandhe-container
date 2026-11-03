//! 生成バイナリを core 役のテストから駆動するフレーム送受信の結合試験（TASK-117.1・#710。REPAIR-12）。
//!
//! テスト側が `UdsListener` を bind して子（plugin-microvm）を spawn し、子が connect してくる
//! 既存契約（core が bind・plugin が connect）どおりに往復させる。待ちはすべて期限つきで、超過時は
//! kill して失敗にする（REPAIR-5）。UDS 実体が unix のみ（非 unix の `UdsListener::bind` は `Unimplemented`）のため unix に限定する。
//! 対応 ID: TASK-117・PLUG-1・PLUG-12・MVM-1・REPAIR-5。
#![cfg(unix)]

#[path = "../../core/tests/support/reap.rs"]
mod reap;

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

const BIN: &str = env!("CARGO_BIN_EXE_fandhe-container-plugin-microvm");
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

    /// 接続を開いたまま子の自発的な終了を期限つきで待ち、終了コードを返す（stderr は `take_stderr` で読む）。
    fn wait_exit(&mut self) -> i32 {
        let start = Instant::now();
        loop {
            if let Some(s) = self.child.try_wait().expect("try_wait") {
                return s.code().expect("exit code");
            }
            if start.elapsed() > WAIT {
                let _ = self.child.kill();
                crate::reap::reap_or_report(&mut self.child, crate::reap::reap_within());
                panic!("plugin binary did not exit within deadline");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// 終了済みの子の stderr を読み切る。
    fn take_stderr(&mut self) -> String {
        let mut err = String::new();
        if let Some(mut s) = self.child.stderr.take() {
            let _ = s.read_to_string(&mut err);
        }
        assert!(!err.contains(&self.sock), "stderr leaks socket path: {err}");
        err
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
                crate::reap::reap_or_report(&mut self.child, crate::reap::reap_within());
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
        crate::reap::reap_on_drop(&mut self.child);
        let _ = std::fs::remove_dir_all(&self.dir); // 排他作成した自前のディレクトリのみ
    }
}

/// `sun_path`（約 104〜108 バイト）に収めるため、`temp_dir()`（macOS では `/var/folders/...`）ではなく
/// `/tmp` 直下に mode 0700 で排他作成する。
fn create_unique_dir() -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    for n in 0..100u32 {
        let p = PathBuf::from("/tmp").join(format!("fc-pmv-{}-{nanos:x}-{n}", std::process::id()));
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

fn expect_error(
    msg: ControlMessage<Vec<String>>,
    want_id: u64,
    want_code: PluginErrorCode,
    want_msg: &str,
) {
    match msg {
        ControlMessage::Error { id, error } => {
            assert_eq!(id.get(), want_id);
            assert_eq!(error.code(), want_code);
            assert_eq!(error.message(), want_msg);
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
fn task117_1_plug1_sequential_requests_keep_connection_and_exit_0_on_close() {
    let mut h = Harness::start();
    expect_unimplemented(h.call(1, &["kill", "a"]), 1);
    expect_unimplemented(h.call(2, &["list"]), 2);
    let (code, err) = h.finish();
    assert_eq!(code, 0, "{err}");
    assert_eq!(err, "");
}

#[test]
fn task117_1_plug1_idle_longer_than_poll_still_served() {
    let mut h = Harness::start();
    std::thread::sleep(Duration::from_millis(2500));
    expect_unimplemented(h.call(10, &["op"]), 10);
    let (code, err) = h.finish();
    assert_eq!(code, 0, "{err}");
}

#[test]
fn task117_1_plug1_empty_body_gets_invalid_argument_and_continues() {
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
fn task117_1_plug1_corrupt_header_disconnects_with_code_4() {
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
fn task117_1_plug1_test_crc_matches_shared_header_encoding() {
    assert_eq!(raw_header(5), FrameHeader::new(5).expect("hdr").to_bytes());
}

#[test]
fn task117_1_plug1_oversized_length_disconnects_without_body() {
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
fn task117_1_plug1_checksum_mismatch_disconnects_with_code_4() {
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
fn task117_1_plug1_response_envelope_is_protocol_violation() {
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
fn task117_1_plug1_stalled_partial_frame_times_out() {
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

/// MVM-1・PLUG-1: ping は pong を同じ MessageId で返し、接続は維持される。
#[test]
fn task117_1_mvm1_ping_roundtrip_keeps_connection() {
    let mut h = Harness::start();
    match h.call(11, &["ping"]) {
        ControlMessage::Response { id, body } => {
            assert_eq!(id.get(), 11);
            assert_eq!(body, vec!["pong".to_string()]);
        }
        other => panic!("unexpected {other:?}"),
    }
    // start は引数不足で INVALID_ARGUMENT（TASK-117.2）。接続は継続する。
    expect_error(
        h.call(12, &["start", "a"]),
        12,
        PluginErrorCode::InvalidArgument,
        "malformed request",
    );
    let (code, err) = h.finish();
    assert_eq!(code, 0, "{err}");
    // start は構造化ログ 1 行を stderr に出す（id・パスは載せない。REPAIR-4）。
    assert_eq!(err.lines().count(), 1, "{err}");
    assert!(
        err.contains("op=plugin.microvm.start outcome=error code=INVALID_ARGUMENT"),
        "{err}"
    );
}

/// TASK-117.2・MVM-1: 存在しない kernel の start は NOT_FOUND、相対パスは INVALID_ARGUMENT、
/// 未登録 id の stop は NOT_FOUND。KVM には触れず、接続は継続して終了コード 0 になる。
#[test]
fn task117_2_mvm1_start_stop_errors_keep_connection() {
    let mut h = Harness::start();
    expect_error(
        h.call(
            1,
            &["start", "vm1", "/nonexistent/fc-kernel", "", "", "1", "64"],
        ),
        1,
        PluginErrorCode::NotFound,
        "kernel image not found",
    );
    expect_error(
        h.call(2, &["start", "vm1", "relative/kernel", "", "", "1", "64"]),
        2,
        PluginErrorCode::InvalidArgument,
        "invalid image path",
    );
    expect_error(
        h.call(3, &["stop", "vm1"]),
        3,
        PluginErrorCode::NotFound,
        "microVM not found",
    );
    let (code, _) = h.finish();
    assert_eq!(code, 0);
}

/// 余分な要素つきの ping は固定文言の INVALID_ARGUMENT で、接続は継続する。
#[test]
fn task117_1_plug1_ping_with_extra_is_invalid_argument() {
    let mut h = Harness::start();
    match h.call(3, &["ping", "SECRETARG"]) {
        ControlMessage::Error { id, error } => {
            assert_eq!(id.get(), 3);
            assert_eq!(error.code(), PluginErrorCode::InvalidArgument);
            assert_eq!(error.message(), "malformed request");
        }
        other => panic!("unexpected {other:?}"),
    }
    let (code, _) = h.finish();
    assert_eq!(code, 0);
}

/// listener 不在・相対パスの起動失敗を期限つきで実行し、(終了コード, stderr) を返す。
fn run_startup_failure(args: &[&str], env_socket: Option<&str>) -> (i32, String) {
    let mut cmd = Command::new(BIN);
    cmd.env_clear().args(args);
    if let Some(v) = env_socket {
        cmd.env(PLUGIN_SOCKET_ENV, v);
    }
    cmd.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("spawn");
    let start = Instant::now();
    let status = loop {
        if let Some(s) = child.try_wait().expect("try_wait") {
            break s;
        }
        if start.elapsed() > WAIT {
            let _ = child.kill();
            crate::reap::reap_or_report(&mut child, crate::reap::reap_within());
            panic!("plugin binary did not exit within deadline");
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let mut err = String::new();
    if let Some(mut s) = child.stderr.take() {
        let _ = s.read_to_string(&mut err);
    }
    (status.code().expect("exit code"), err)
}

/// 存在しない socket への接続は終了コード 3。stderr に socket パスを含めない。
#[test]
fn task117_1_plug12_missing_socket_exits_3_without_path() {
    let dir = create_unique_dir();
    let sock = dir.join("absent-SECRETNAME.sock");
    let sock_s = sock.to_str().expect("utf8").to_string();
    let (code, err) = run_startup_failure(&[], Some(&sock_s));
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(code, 3, "{err}");
    assert!(err.starts_with("error: "), "{err}");
    assert!(
        !err.contains("SECRETNAME") && !err.contains(&sock_s),
        "{err}"
    );
}

/// 相対パスの socket は起動設定の検証で拒否され、終了コード 2。入力値は出力に反射しない。
#[test]
fn task117_1_plug12_relative_socket_exits_2_without_value() {
    let (code, err) = run_startup_failure(&["--socket", "rel/SECRETREL.sock"], None);
    assert_eq!(code, 2, "{err}");
    assert_eq!(
        err,
        "error: INVALID_ARGUMENT: socket path must be absolute\n"
    );
    let (code, err) = run_startup_failure(&[], Some("rel/SECRETREL.sock"));
    assert_eq!(code, 2, "{err}");
    assert!(!err.contains("SECRETREL"), "{err}");
}

/// 子へ SIGTERM を送る（テスト側に FFI・依存を足さないため `kill` コマンドを使う。引数は pid の数値のみ）。
fn sigterm(h: &Harness) {
    let mut cmd = Command::new("kill");
    cmd.args(["-TERM", &h.child.id().to_string()]);
    let st = crate::reap::run_within(&mut cmd, crate::reap::reap_within())
        .unwrap_or_else(|e| panic!("sigterm to plugin child: {e}"));
    assert!(st.success());
}

/// SIGTERM 後の終了コード 0・shutdown 行・VM 無しの結果行・時間の上限を照合する。
fn expect_clean_sigterm_exit(mut h: Harness, sent: Instant) {
    let code = h.wait_exit();
    let elapsed = sent.elapsed();
    let err = h.take_stderr();
    assert_eq!(code, 0, "{err}");
    // IDLE_POLL(1s) + STOP_ALL_BUDGET(4s) + 余裕。
    assert!(elapsed < Duration::from_secs(10), "took {elapsed:?}");
    let lines: Vec<&str> = err.lines().collect();
    assert!(
        lines.contains(&"level=info op=plugin.microvm.shutdown reason=signal"),
        "{err}"
    );
    assert!(
        lines.contains(
            &"level=info op=plugin.microvm.stop_all stopped=0 failed=0 remaining=0 detached=0"
        ),
        "{err}"
    );
}

/// PLUG-1・REPAIR-5: アイドル中の SIGTERM で受付をやめ、VM が無くても結果行を出して終了コード 0 で終わる。
#[test]
fn task117_plug1_repair5_sigterm_idle_exits_zero_with_stop_all_line() {
    let h = Harness::start();
    let sent = Instant::now();
    sigterm(&h);
    expect_clean_sigterm_exit(h, sent);
}

/// PLUG-1・REPAIR-5: 要求を 1 往復した後の SIGTERM でも同じ。
#[test]
fn task117_plug1_repair5_sigterm_after_request_exits_zero() {
    let mut h = Harness::start();
    match h.call(1, &["ping"]) {
        ControlMessage::Response { id, body } => {
            assert_eq!(id.get(), 1);
            assert_eq!(body, vec!["pong".to_string()]);
        }
        other => panic!("unexpected {other:?}"),
    }
    let sent = Instant::now();
    sigterm(&h);
    expect_clean_sigterm_exit(h, sent);
}

/// PLUG-1・REPAIR-5: SIGTERM を続けて 2 回送ってもプロセスは殺されず、終了コード 0 で終わる。
#[test]
fn task117_plug1_repair5_double_sigterm_exits_zero() {
    let h = Harness::start();
    let sent = Instant::now();
    sigterm(&h);
    sigterm(&h);
    expect_clean_sigterm_exit(h, sent);
}

/// PLUG-1・REPAIR-5: SIGTERM 後に届いた要求は処理されない（応答も Error も返らず、start は実行されない）。
#[test]
fn task117_plug1_repair5_request_after_sigterm_is_not_processed() {
    let mut h = Harness::start();
    sigterm(&h);
    // 接続を開いたまま子の終了を待つ（待ちは期限つき）。
    let code = h.wait_exit();
    let f = request(2, &["start", "vm1", "/nonexistent", "", "", "1", "64"]);
    let wrote = h.stream().write_frame(&f, RpcTimeout::default());
    if wrote.is_ok() {
        let e = h
            .stream()
            .read_frame(RpcTimeout::new(Duration::from_secs(2)).expect("timeout"))
            .expect_err("no response may arrive after SIGTERM");
        assert_eq!(e.code(), PluginErrorCode::Unavailable);
    }
    let err = h.take_stderr();
    assert_eq!(code, 0, "{err}");
    assert!(!err.contains("op=plugin.microvm.start"), "{err}");
}
