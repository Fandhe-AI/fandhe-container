//! バイナリ `fandhe-container-plugin-mcp` の UDS（PLUG-12 準拠）経由の起動・疎通の結合試験
//! （TASK-118.4・#467。MCP-1・MCP-2・PLUG-12・REPAIR-5・REPAIR-12）。
//!
//! 接続方向は既存契約（core = ハーネスが `UdsListener` で bind、plugin が `FANDHE_CONTAINER_PLUGIN_SOCKET`
//! の socket へ `UdsStream::connect` で接続）。UDS 上のフレーミングは改行区切りの JSON-RPC 2.0
//! （暫定契約。確定は別 issue で行う。#1869 で設計した plugin-backend-wiring.md 4.9 では入口の対象外で、追跡 issue は未起票。起票の要否は #3417 のコメントでユーザーに諮った）。既定集合のテストは同一 UID で `initialize` → `tools/list` →
//! `tools/call` の 3 要求の応答を具体値で照合する。
//!
//! 別 UID の listener の拒否は root なしに用意できないため `#[ignore]` の実機前提テスト（準備手順は
//! `AGENTS.md`「実機前提テスト」節）。ハーネス側 listener による別 UID connector の拒否は
//! `crates/plugin/tests/peer_auth.rs` が検証済みで、本ファイルでは重複させない。
//! 待ちはすべて期限つきで、超過時は kill して失敗にする（REPAIR-5）。

use std::io::Read;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use fandhe_container_plugin::PLUGIN_SOCKET_ENV;

const BIN: &str = env!("CARGO_BIN_EXE_fandhe-container-plugin-mcp");
/// 子プロセスの終了・応答 1 行を待つ上限。
const WAIT: Duration = Duration::from_secs(30);
/// kill 後の子の回収を待つ猶予。超過しても待ち続けず失敗にする。
const REAP_GRACE: Duration = Duration::from_secs(5);

/// 子の終了を期限内に待ち、(終了コード, stdout, stderr) を返す。超過時は kill して失敗にする。
fn wait_exit(mut child: Child) -> (i32, String, String) {
    let out_rx = spawn_reader(child.stdout.take());
    let err_rx = spawn_reader(child.stderr.take());
    let start = Instant::now();
    let status = loop {
        if let Some(s) = child.try_wait().expect("try_wait") {
            break s;
        }
        if start.elapsed() > WAIT {
            let kill_result = child.kill();
            // 回収も有限の猶予で行う（期限なしの wait は割り込み不能な待ちで無期限に止まる。REPAIR-5）。
            let reap_start = Instant::now();
            let mut reaped = false;
            while reap_start.elapsed() < REAP_GRACE {
                if matches!(child.try_wait(), Ok(Some(_))) {
                    reaped = true;
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            panic!(
                "plugin binary did not exit within deadline (kill: {kill_result:?}, reaped: {reaped})"
            );
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let out = out_rx.recv_timeout(WAIT).expect("stdout not collected");
    let err = err_rx.recv_timeout(WAIT).expect("stderr not collected");
    (status.code().expect("exit code"), out, err)
}

fn spawn_reader<R: Read + Send + 'static>(pipe: Option<R>) -> mpsc::Receiver<String> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut buf = String::new();
        if let Some(mut p) = pipe {
            let _ = p.read_to_string(&mut buf);
        }
        let _ = tx.send(buf);
    });
    rx
}

/// 環境を空にして socket 環境変数だけを渡して起動する（stdin は null、stdout/stderr は収集）。
fn spawn_with(sock: &std::ffi::OsStr, runtime_dir: Option<&std::path::Path>) -> Child {
    let mut cmd = Command::new(BIN);
    cmd.env_clear().env(PLUGIN_SOCKET_ENV, sock);
    if let Some(dir) = runtime_dir {
        cmd.env("XDG_RUNTIME_DIR", dir);
    }
    if let Some(root) = std::env::var_os("SystemRoot") {
        cmd.env("SystemRoot", root);
    }
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn fandhe-container-plugin-mcp")
}

#[cfg(unix)]
mod uds {
    use super::*;
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt};
    use std::path::{Path, PathBuf};

    use fandhe_container_plugin::{JsonLinesPeerAuthObserver, UdsListener};
    use serde_json::{Value, json};

    /// 一時ディレクトリ（0700）。macOS の `temp_dir` は `sun_path` に収まらないことがあるため /tmp 直下に作る。
    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0);
            for n in 0..100u32 {
                let p = PathBuf::from("/tmp")
                    .join(format!("fc-mcp-{}-{nanos:x}-{n}", std::process::id()));
                match std::fs::DirBuilder::new().mode(0o700).create(&p) {
                    Ok(()) => return Self(p),
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(e) => panic!("create test dir: {e}"),
                }
            }
            panic!("could not create a unique test dir");
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0); // 排他作成した自前のディレクトリのみ
        }
    }

    /// root で実行すると状態ルートが `/run/fandhe-container` に解決され実環境へ触れるため、失敗させる（skip しない）。
    fn assert_non_root(dir: &TempDir) {
        let uid = std::fs::metadata(&dir.0).expect("meta").uid();
        assert_ne!(
            uid, 0,
            "this test must run as a non-root user (state root would be /run)"
        );
    }

    /// 応答 1 行の最大バイト数（無制限確保を避ける。REPAIR-5）。
    const MAX_REPLY_BYTES: usize = 64 * 1024;

    /// テスト失敗（panic）時にも子を kill して有限の猶予で回収するガード。
    struct ChildGuard(Option<Child>);

    impl ChildGuard {
        /// 正常系で子を取り出す（以降は `wait_exit` が回収する）。
        fn into_inner(mut self) -> Child {
            self.0.take().expect("child present")
        }
    }

    impl Drop for ChildGuard {
        fn drop(&mut self) {
            if let Some(mut c) = self.0.take() {
                let _ = c.kill();
                let start = Instant::now();
                while start.elapsed() < REAP_GRACE {
                    if matches!(c.try_wait(), Ok(Some(_))) {
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
        }
    }

    /// 応答 1 行を絶対期限（`WAIT`）と受信サイズ上限つきで読む。
    /// チャンクごとに期限とサイズを確認するため、改行なしのデータを送り続けられても戻る（REPAIR-5）。
    fn read_reply(reader: &mut BufReader<fandhe_container_plugin::UdsStream>) -> Value {
        let mut line: Vec<u8> = Vec::new();
        let deadline = Instant::now() + WAIT;
        loop {
            assert!(Instant::now() < deadline, "no reply within deadline");
            let (used, done) = match reader.fill_buf() {
                Ok([]) => panic!("connection closed before a reply: {} bytes", line.len()),
                Ok(buf) => match buf.iter().position(|&b| b == b'\n') {
                    Some(i) => {
                        line.extend_from_slice(&buf[..i]);
                        (i + 1, true)
                    }
                    None => {
                        line.extend_from_slice(buf);
                        (buf.len(), false)
                    }
                },
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock
                            | std::io::ErrorKind::TimedOut
                            | std::io::ErrorKind::Interrupted
                    ) =>
                {
                    continue;
                }
                Err(e) => panic!("read reply: {e}"),
            };
            reader.consume(used);
            assert!(line.len() <= MAX_REPLY_BYTES, "reply exceeds size limit");
            if done {
                break;
            }
        }
        serde_json::from_slice(&line).expect("reply is JSON")
    }

    /// MCP-1・MCP-2・PLUG-12 / TASK-118.4: 同一 UID の UDS 上で 3 要求が正常に応答する。拒否イベントは 0 件。
    #[test]
    fn mcp1_mcp2_plug12_three_requests_over_uds_same_uid() {
        let dir = TempDir::new();
        assert_non_root(&dir);
        let runtime = dir.0.join("run");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&runtime)
            .unwrap();
        let sock = dir.0.join("p.sock");
        let listener = UdsListener::bind(&sock).expect("bind");
        let child = ChildGuard(Some(spawn_with(
            listener.path().as_os_str(),
            Some(&runtime),
        )));
        let mut obs = JsonLinesPeerAuthObserver::new();
        let stream = listener
            .accept(Duration::from_secs(20), &mut obs)
            .expect("accept");
        assert_eq!(obs.len(), 0);
        stream
            .set_io_timeout(Duration::from_secs(1))
            .expect("set timeout");
        let mut reader = BufReader::new(stream);

        let send = |reader: &mut BufReader<fandhe_container_plugin::UdsStream>, v: Value| {
            let mut text = v.to_string();
            text.push('\n');
            reader
                .get_mut()
                .write_all(text.as_bytes())
                .expect("write request");
        };

        send(
            &mut reader,
            json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
                "protocolVersion":"2025-06-18","capabilities":{},
                "clientInfo":{"name":"harness","version":"0"}}}),
        );
        let init = read_reply(&mut reader);
        assert_eq!(init["id"], json!(1));
        assert_eq!(init["result"]["protocolVersion"], json!("2025-06-18"));
        assert!(init.get("error").is_none(), "{init}");

        send(
            &mut reader,
            json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
        );
        send(
            &mut reader,
            json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}),
        );
        let list = read_reply(&mut reader);
        assert_eq!(list["id"], json!(2));
        let names: Vec<&str> = list["result"]["tools"]
            .as_array()
            .expect("tools array")
            .iter()
            .filter_map(|t| t["name"].as_str())
            .collect();
        assert_eq!(names, ["list_containers", "start_container"]);

        send(
            &mut reader,
            json!({"jsonrpc":"2.0","id":3,"method":"tools/call",
                   "params":{"name":"list_containers","arguments":{}}}),
        );
        let call = read_reply(&mut reader);
        assert_eq!(call["id"], json!(3));
        assert!(call.get("error").is_none(), "{call}");
        #[cfg(target_os = "linux")]
        {
            assert_eq!(call["result"]["isError"], json!(false), "{call}");
            assert_eq!(
                call["result"]["structuredContent"]["containers"],
                json!([]),
                "{call}"
            );
        }
        #[cfg(not(target_os = "linux"))]
        {
            // Linux 以外は core の状態ストアが状態ルートを検査できず UNIMPLEMENTED を返す（fail-closed）。
            // 業務エラーの result は `structuredContent` を持たず、`{code, message}` を
            // `content[0].text` の JSON 文字列に載せる（server.rs の `tool_error_result`）。
            assert_eq!(call["result"]["isError"], json!(true), "{call}");
            let text = call["result"]["content"][0]["text"]
                .as_str()
                .unwrap_or_else(|| panic!("content[0].text is a string: {call}"));
            let body: Value = serde_json::from_str(text).expect("content[0].text is JSON");
            assert_eq!(
                body,
                json!({"code": "UNIMPLEMENTED", "message": "Not implemented"}),
                "{call}"
            );
        }

        drop(reader);
        let (code, out, err) = wait_exit(child.into_inner());
        assert_eq!(code, 0, "{err}");
        assert_eq!(out, "", "stdout must stay empty in UDS mode");
        let ops: Vec<String> = err
            .lines()
            .filter_map(|l| serde_json::from_str::<Value>(l).ok())
            .filter(|v| v["event"] == "mcp.request")
            .map(|v| v["op"].as_str().unwrap_or("").to_owned())
            .collect();
        assert_eq!(
            ops,
            ["initialize", "notification", "tools/list", "tools/call"]
        );
        assert!(!err.contains("PERMISSION_DENIED"), "{err}");
        assert!(!err.contains(sock.to_str().expect("utf8")), "{err}");
    }

    /// MCP-1・REPAIR-5 / TASK-118.4: 要求を送ってすぐ切断した相手でも、受信済みの要求を処理してから
    /// EOF で正常終了する（終了コード 0）。macOS では相手切断後の socket 期限の設定が EINVAL に
    /// なるため、境界基盤の non-blocking 1 回読みで残りデータと EOF を受け取れることを照合する。
    #[test]
    fn mcp1_repair5_peer_close_right_after_request_exits_zero() {
        let dir = TempDir::new();
        assert_non_root(&dir);
        let runtime = dir.0.join("run");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&runtime)
            .unwrap();
        let sock = dir.0.join("p.sock");
        let listener = UdsListener::bind(&sock).expect("bind");
        let child = ChildGuard(Some(spawn_with(
            listener.path().as_os_str(),
            Some(&runtime),
        )));
        let mut obs = JsonLinesPeerAuthObserver::new();
        let mut stream = listener
            .accept(Duration::from_secs(20), &mut obs)
            .expect("accept");
        stream
            .write_all(b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n")
            .expect("write notification");
        drop(stream);
        let (code, out, err) = wait_exit(child.into_inner());
        assert_eq!(code, 0, "{err}");
        assert_eq!(out, "", "stdout must stay empty in UDS mode");
        let ops: Vec<String> = err
            .lines()
            .filter_map(|l| serde_json::from_str::<Value>(l).ok())
            .filter(|v| v["event"] == "mcp.request")
            .map(|v| v["op"].as_str().unwrap_or("").to_owned())
            .collect();
        assert_eq!(ops, ["notification"], "{err}");
        assert!(!err.contains("mcp.transport"), "{err}");
    }

    /// PLUG-12 / TASK-118.4: 相対パス・`..` 含みの socket 指定は終了コード 2 で拒否し、入力値を出力へ反射しない。
    #[test]
    fn plug12_uds_mode_rejects_invalid_socket_env_without_echo() {
        for bad in ["relative/secret-name.sock", "/tmp/../secret-name.sock", ""] {
            let (code, out, err) = wait_exit(spawn_with(std::ffi::OsStr::new(bad), None));
            assert_eq!(code, 2, "{bad}: {err}");
            assert_eq!(out, "");
            assert_eq!(
                err,
                "{\"code\":\"INVALID_ARGUMENT\",\"message\":\"invalid socket path\"}\n"
            );
        }
    }

    /// PLUG-12 / TASK-118.4: 存在しない socket は終了コード 3 で、パスを出力へ反射しない。
    #[test]
    fn plug12_uds_mode_reports_missing_socket_without_echo() {
        let dir = TempDir::new();
        let sock = dir.0.join("secret-missing.sock");
        let (code, out, err) = wait_exit(spawn_with(sock.as_os_str(), None));
        assert_eq!(code, 3, "{err}");
        assert_eq!(out, "");
        let v: Value = serde_json::from_str(err.trim_end()).expect("one JSON line");
        assert_eq!(v["code"], json!("NOT_FOUND"), "{err}");
        assert!(!err.contains("secret-missing"), "{err}");
    }

    /// PLUG-12 / TASK-118.4（実機前提）: 別 UID が listen 中の socket への接続を plugin-mcp が拒否し fail-closed する。
    ///
    /// 別 UID が listen 中で実行ユーザーから接続できる socket と、その listener が受信したバイトを
    /// 書き出す空の記録ファイルを人間が用意する。fixture は読み取りと connect のみで、削除・chmod しない。
    /// 確認は終了コード 3・固定の stderr に加え、listener 側の受信バイト数が 0 であること
    /// （認証前にデータを送らない。PLUG-12・REPAIR-12）。テスト自身は sudo もシェルも呼ばない。
    #[test]
    #[ignore = "requires a listening socket owned by another UID prepared by a human; PLUG-12"]
    fn plug12_rejects_other_uid_listener() {
        let raw = std::env::var_os("FANDHE_CONTAINER_TEST_OTHER_UID_SOCKET").expect(
            "FANDHE_CONTAINER_TEST_OTHER_UID_SOCKET must be set to an absolute path (see AGENTS.md)",
        );
        let recv_raw = std::env::var_os("FANDHE_CONTAINER_TEST_OTHER_UID_RECEIVED_FILE").expect(
            "FANDHE_CONTAINER_TEST_OTHER_UID_RECEIVED_FILE must be set to an absolute path (see AGENTS.md)",
        );
        let recv_path = PathBuf::from(recv_raw);
        assert!(
            recv_path.is_absolute(),
            "received file must be an absolute path"
        );
        let path = PathBuf::from(raw);
        assert!(path.is_absolute(), "fixture must be an absolute path");
        let meta = std::fs::symlink_metadata(&path).expect("fixture socket must exist");
        assert!(meta.file_type().is_socket(), "fixture must be a socket");
        let dir = TempDir::new();
        let me = std::fs::metadata(&dir.0).expect("meta").uid();
        assert_ne!(me, 0, "test must run as a non-root user");
        assert_ne!(meta.uid(), me, "fixture must be owned by a different UID");

        let (code, out, err) = wait_exit(spawn_with(path.as_os_str(), None));
        assert_eq!(code, 3, "{err}");
        assert_eq!(out, "");
        // 先頭は socket パスを含まない拒否イベント（SEC-4）、末尾は固定の診断行。
        let lines: Vec<&str> = err.lines().collect();
        assert_eq!(lines.len(), 2, "{err}");
        let ev: Value = serde_json::from_str(lines[0]).expect("event line is JSON");
        assert_eq!(ev["event"], json!("plugin_peer_auth"), "{err}");
        assert_eq!(ev["op"], json!("connect"), "{err}");
        assert_eq!(ev["code"], json!("PERMISSION_DENIED"), "{err}");
        assert!(ev.get("socket_path").is_none(), "{err}");
        assert_eq!(
            lines[1],
            "{\"code\":\"PERMISSION_DENIED\",\"message\":\"peer credential does not match the current user\"}"
        );
        assert!(!err.contains(path.to_str().expect("utf8")), "{err}");

        // listener が受信したバイト数は 0 でなければならない。終了後も決定的な猶予の間監視する。
        assert!(
            std::fs::metadata(&recv_path)
                .expect("received-bytes file must exist")
                .is_file(),
            "received-bytes file must be a regular file"
        );
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(2) {
            let len = std::fs::metadata(&recv_path).expect("exists").len();
            assert_eq!(len, 0, "listener of another UID must receive 0 bytes");
            std::thread::sleep(Duration::from_millis(20));
        }
        let _: &Path = &path;
    }
}

/// 非 unix では UDS が未実装のため、UDS モードは `UNIMPLEMENTED`・終了コード 3 で fail-closed する（PLUG-12）。
#[cfg(not(unix))]
#[test]
fn plug12_uds_mode_is_unimplemented_on_non_unix() {
    let sock = std::env::temp_dir().join("fc-mcp-none.sock");
    let (code, out, err) = wait_exit(spawn_with(sock.as_os_str(), None));
    assert_eq!(code, 3, "{err}");
    assert_eq!(out, "");
    assert!(err.contains("UNIMPLEMENTED"), "{err}");
}
