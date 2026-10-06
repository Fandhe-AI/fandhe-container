//! 生成バイナリの起動が peer 認証済み UDS 接続になることの結合試験（TASK-115.4・#388。PLUG-12・PLUG-1・MAC-1・REPAIR-5・REPAIR-12）。
//!
//! 接続方向は既存契約（core が bind・plugin が connect）のまま、plugin の接続経路が
//! `UdsStream::connect`（server の peer UID 照合つき）のみであることを固定する。
//! 別 UID の listener の拒否は root なしに用意できないため `#[ignore]` の実機前提テスト（準備手順は
//! `AGENTS.md`「実機前提テスト」節）。待ちはすべて期限つきで、超過時は kill して失敗にする（REPAIR-5）。
//! 実行環境は unix のみ（非 unix では UDS 実体がないため中身は空でコンパイルされる）。
#![cfg(unix)]

use std::io::Read;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use fandhe_container_plugin::{
    ControlMessage, JsonLinesPeerAuthObserver, MessageId, PLUGIN_SOCKET_ENV, PluginErrorCode,
    RpcTimeout, UdsListener, decode_message, encode_message,
};

const BIN: &str = env!("CARGO_BIN_EXE_fandhe-container-plugin-macos");
const WAIT: Duration = Duration::from_secs(30);
/// peer 不一致の拒否で返る固定メッセージ（共有 crate 側の契約と同値。UID 値を含めない）。
const MISMATCH_MESSAGE: &str = "peer credential does not match the current user";

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        for n in 0..100u32 {
            let p =
                PathBuf::from("/tmp").join(format!("fc-pma-{}-{nanos:x}-{n}", std::process::id()));
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

fn spawn(sock: &Path) -> Child {
    Command::new(BIN)
        .env_clear()
        .env(PLUGIN_SOCKET_ENV, sock)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn")
}

/// 期限内に子の終了を待ち、(終了コード, stderr) を返す。超過時は kill して失敗にする。
fn wait_exit(mut child: Child) -> (i32, String) {
    let start = Instant::now();
    let status = loop {
        if let Some(s) = child.try_wait().expect("try_wait") {
            break s;
        }
        if start.elapsed() > WAIT {
            let _ = child.kill();
            let _ = child.wait();
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

/// PLUG-12 / TASK-115.4: 同一 UID の listener へは peer 認証を通って接続が成立し、拒否は 0 件。
#[test]
fn task115_4_plug12_same_uid_listener_is_accepted_without_rejection() {
    let dir = TempDir::new();
    let sock = dir.0.join("p.sock");
    let listener = UdsListener::bind(&sock).expect("bind");
    let child = spawn(&sock);
    let mut obs = JsonLinesPeerAuthObserver::new();
    let mut stream = listener
        .accept(Duration::from_secs(20), &mut obs)
        .expect("accept");
    assert_eq!(obs.len(), 0);

    let req = encode_message(&ControlMessage::Request {
        id: MessageId::new(7),
        body: vec!["list".to_string()],
    })
    .expect("encode");
    stream
        .write_frame(&req, RpcTimeout::default())
        .expect("write");
    let r = stream.read_frame(RpcTimeout::default()).expect("read");
    match decode_message::<Vec<String>>(&r).expect("decode") {
        ControlMessage::Error { id, error } => {
            assert_eq!(id.get(), 7);
            assert_eq!(error.code(), PluginErrorCode::Unimplemented);
        }
        other => panic!("unexpected {other:?}"),
    }
    drop(stream);

    let (code, err) = wait_exit(child);
    assert_eq!(code, 0, "{err}");
    assert!(!err.contains("PERMISSION_DENIED"), "{err}");
    assert!(!err.contains(sock.to_str().expect("utf8")), "{err}");
}

/// PLUG-12 / TASK-115.4（実機前提）: 別 UID が listen 中の socket への接続を plugin が拒否し fail-closed する。
///
/// 別 UID が listen 中で実行ユーザーから接続できる socket と、その listener が受信したバイトを
/// 書き出す空の記録ファイルを人間が用意する。fixture は読み取りと connect のみで、削除・chmod しない。
/// 拒否の確認は終了コード・stderr に加え、listener 側の受信バイト数が 0 であること（認証前に
/// データを送らない。PLUG-12・REPAIR-12）で行う。テスト自身は sudo を呼ばず、シェルも介さない。
#[test]
#[ignore = "requires a listening socket owned by another UID prepared by a human; PLUG-12"]
fn task115_4_plug12_rejects_other_uid_listener() {
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

    let (code, err) = wait_exit(spawn(&path));
    assert_eq!(code, 3, "{err}");
    assert!(
        err.starts_with(&format!("error: PERMISSION_DENIED: {MISMATCH_MESSAGE}")),
        "{err}"
    );
    assert!(!err.contains(path.to_str().expect("utf8")), "{err}");

    // 認証前にデータを送る回帰の検出: listener が受信したバイト数は 0 でなければならない。
    let received = std::fs::metadata(&recv_path).expect("received-bytes file must exist");
    assert!(
        received.is_file(),
        "received-bytes file must be a regular file"
    );
    assert_eq!(
        received.len(),
        0,
        "listener of another UID must receive 0 bytes before peer authentication"
    );
}
