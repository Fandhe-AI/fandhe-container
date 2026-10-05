//! UDS の peer credential 認証の結合試験（PLUG-12。TASK-124.4・#295）。
//!
//! TASK-124.6（#1389）: 拒否時に先送りフレームを読まない・送らない順序の照合は cfg(test) の入口が
//! 必要なため、crate 内ユニットテスト（`transport::tests::plug12_order`）で行う。本ファイルは
//! 公開 API で、accept 前に届いたフレームが accept で消費されないことだけを確認する。
//!
//! 公開 API（`UdsListener::accept`・`UdsStream::connect`）を通して、同一 UID は受理・別 UID は拒否
//! されることを確認する。検証本体は `uds_security::verify_peer`（Linux は SO_PEERCRED、macOS は
//! getpeereid。TASK-124.1・TASK-124.2）で、accept / connect の直後に呼ばれる。
//!
//! - 既定集合: 同一 UID の受理（`plug12_accepts_same_uid_connection`）、非 unix の fail-closed。
//! - 取得失敗時の fail-closed は公開 API から注入できないため、crate 内ユニットテスト
//!   `uds_security::tests::plug12_fail_closed_on_peercred_error` で照合する。
//! - 実機前提（`#[ignore]`）: 別 UID の接続拒否。別 UID のプロセスは root 権限なしに用意できないため
//!   既定集合から分離している（CI 通過のための弱体化ではない）。準備手順と実行コマンドは `AGENTS.md`
//!   「実機前提テスト」節。テスト自身は sudo を呼ばず、前提不備は skip せず panic する。
//!
//! listener 側の拒否に別 UID の非 root は使えない（0700 の配置ディレクトリで connect 前に遮断され、
//! peer 検証へ届かない）ため、connector は root が必要。client 側は親ディレクトリを検証しないので、
//! 別 UID が listen 中の socket であれば root でなくてもよい。

#[cfg(not(unix))]
#[test]
fn plug12_peer_auth_is_unimplemented_on_non_unix() {
    use fandhe_container_plugin::{PluginErrorCode, UdsListener, UdsStream};
    let err = UdsListener::bind(std::path::Path::new("s.sock")).unwrap_err();
    assert_eq!(err.code(), PluginErrorCode::Unimplemented);
    let err = UdsStream::connect(
        std::path::Path::new("s.sock"),
        std::time::Duration::from_secs(1),
    )
    .unwrap_err();
    assert_eq!(err.code(), PluginErrorCode::Unimplemented);
}

// peer credential の取得が実装済みの OS・アーキテクチャに限定する（他は Unimplemented を返す）。
#[cfg(all(
    unix,
    any(
        target_os = "macos",
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    )
))]
mod unix {
    use fandhe_container_plugin::{
        ControlMessage, MessageId, PluginErrorCode, RpcTimeout, UdsListener, UdsStream,
        decode_message, encode_message,
    };
    use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::{Duration, Instant};

    const WAIT: Duration = Duration::from_secs(5);

    /// peer 不一致の拒否で返る固定メッセージ（UID 値を含めない契約）。
    const MISMATCH_MESSAGE: &str = "peer credential does not match the current user";

    type Msg = ControlMessage<String>;

    /// 0700 の一時ディレクトリ（socket の配置先。drop で削除）。
    struct TempDir(PathBuf);
    impl TempDir {
        fn new() -> Self {
            static N: AtomicU32 = AtomicU32::new(0);
            let p = std::env::temp_dir().join(format!(
                "fcpa-{}-{}",
                std::process::id(),
                N.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::DirBuilder::new().mode(0o700).create(&p).unwrap();
            Self(p)
        }
        fn sock(&self) -> PathBuf {
            self.0.join("s.sock")
        }
        /// テスト実行ユーザーの UID（自分が作ったディレクトリの所有者）。
        fn owner_uid(&self) -> u32 {
            std::fs::metadata(&self.0).unwrap().uid()
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn msg(id: u64, response: bool, body: &str) -> Msg {
        let (id, body) = (MessageId::new(id), body.to_string());
        if response {
            ControlMessage::Response { id, body }
        } else {
            ControlMessage::Request { id, body }
        }
    }

    /// 同一 UID の connect → accept を 1 組成立させ、受理後にフレームを往復できることを確認する。
    fn assert_same_uid_roundtrip(l: &UdsListener) {
        let rpc = RpcTimeout::new(WAIT).unwrap();
        let path = l.path().to_path_buf();
        let h = std::thread::spawn(move || {
            let mut c = UdsStream::connect(&path, WAIT).unwrap();
            c.write_frame(&encode_message(&msg(1, false, "ping")).unwrap(), rpc)
                .unwrap();
            decode_message::<String>(&c.read_frame(rpc).unwrap()).unwrap()
        });
        let mut s = l.accept(WAIT).unwrap();
        let req = decode_message::<String>(&s.read_frame(rpc).unwrap()).unwrap();
        assert_eq!(req, msg(1, false, "ping"));
        s.write_frame(&encode_message(&msg(1, true, "pong")).unwrap(), rpc)
            .unwrap();
        assert_eq!(h.join().unwrap(), msg(1, true, "pong"));
    }

    /// PLUG-12: 同一 UID の接続は受理され、受理後のフレーム往復が成立する。
    #[test]
    fn plug12_accepts_same_uid_connection() {
        let dir = TempDir::new();
        let l = UdsListener::bind(&dir.sock()).unwrap();
        assert_same_uid_roundtrip(&l);
    }

    /// PLUG-12・TASK-124.6: accept より前に client が送ったフレームは、検証経路で消費されず
    /// 受理後の最初のフレームとして読める。
    #[test]
    fn plug12_accept_does_not_consume_frame_sent_before_accept() {
        let dir = TempDir::new();
        let l = UdsListener::bind(&dir.sock()).unwrap();
        let rpc = RpcTimeout::new(WAIT).unwrap();
        let path = l.path().to_path_buf();
        let (tx, rx) = std::sync::mpsc::channel();
        let h = std::thread::spawn(move || {
            let mut c = UdsStream::connect(&path, WAIT).unwrap();
            c.write_frame(&encode_message(&msg(1, false, "early")).unwrap(), rpc)
                .unwrap();
            tx.send(()).unwrap();
            c
        });
        rx.recv_timeout(WAIT).unwrap();
        let mut s = l.accept(WAIT).unwrap();
        let req = decode_message::<String>(&s.read_frame(rpc).unwrap()).unwrap();
        assert_eq!(req, msg(1, false, "early"));
        drop(h.join().unwrap());
    }

    /// 実機前提テストの fixture パスを環境変数から取る。未設定・相対パスは skip せず panic する。
    fn fixture_path(var: &str) -> PathBuf {
        let raw = std::env::var_os(var)
            .unwrap_or_else(|| panic!("{var} must be set to an absolute path (see AGENTS.md)"));
        let p = PathBuf::from(raw);
        assert!(p.is_absolute(), "{var} must be an absolute path: {p:?}");
        p
    }

    /// PLUG-12 / TASK-124.4（実機前提）: 別 UID の connector からの接続を accept が拒否する。
    ///
    /// 非 root の別 UID は 0700 の配置ディレクトリで connect(2) 前に EACCES となり peer 検証へ
    /// 届かないため、connector は root で動かす必要がある。connector は人間が用意した実行ファイルで、
    /// socket パスを第 1 引数に受けて接続し、受信内容を stdout へ出す。テスト自身は sudo を呼ばず、
    /// シェルも介さない。準備手順は `AGENTS.md`「実機前提テスト」節。
    #[test]
    #[ignore = "requires a connector running as another UID (root) prepared by a human; PLUG-12"]
    fn plug12_rejects_other_uid_connection() {
        use std::io::Read;
        use std::process::{Command, Stdio};

        let cmd = fixture_path("FANDHE_CONTAINER_TEST_OTHER_UID_CONNECT_CMD");
        let meta = std::fs::metadata(&cmd).expect("connector command must exist");
        assert!(meta.is_file(), "connector command must be a regular file");

        let dir = TempDir::new();
        assert_ne!(
            dir.owner_uid(),
            0,
            "this test must run as a non-root user (otherwise the other UID is meaningless)"
        );
        let l = UdsListener::bind(&dir.sock()).unwrap();

        let mut child = Command::new(&cmd)
            .arg(l.path())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .spawn()
            .expect("failed to spawn the connector command");
        let mut stdout = child.stdout.take().unwrap();
        // 孫プロセスが stdout を保持すると read_to_end が戻らないため、join ではなく
        // 期限付き recv で結果を受け取る（REPAIR-5）。
        let (tx, rx) = std::sync::mpsc::channel::<Vec<u8>>();
        let _reader = std::thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = stdout.read_to_end(&mut buf);
            let _ = tx.send(buf);
        });

        match l.accept(Duration::from_secs(10)) {
            Ok(_) => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("accept succeeded: the connector ran as the same UID as the test");
            }
            Err(e) => {
                assert_eq!(e.code(), PluginErrorCode::PermissionDenied);
                assert_eq!(e.message(), MISMATCH_MESSAGE);
            }
        }

        // connector の終了を有限時間で待つ（REPAIR-5）。超過時は kill して失敗にする。
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut exited = false;
        while Instant::now() < deadline {
            if child.try_wait().unwrap().is_some() {
                exited = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        if !exited {
            let _ = child.kill();
            let _ = child.wait();
            panic!("connector did not exit after the connection was rejected");
        }
        // 読み取り側にも期限を設ける。超過時は reader を待たずに失敗させる（reader は孫が
        // パイプを閉じるか test プロセス終了で回収される）。
        let received = match rx.recv_timeout(Duration::from_secs(10)) {
            Ok(buf) => buf,
            Err(e) => panic!("stdout reader did not finish in time: {e}"),
        };
        assert!(
            received.is_empty(),
            "no bytes must reach the rejected peer: {} bytes",
            received.len()
        );

        // 拒否後も listener は同一 UID の接続を受け付け続ける。
        assert_same_uid_roundtrip(&l);
    }

    /// PLUG-12 / TASK-124.4（実機前提）: client の connect が別 UID の listener を拒否する（偽 listener 対策）。
    ///
    /// 別 UID（root でも非 root でもよい）が listen 中で、実行ユーザーから接続できる socket を
    /// 人間が用意する。fixture は読み取りと connect のみで、削除・chmod しない。
    /// connect 自体の EACCES は別メッセージ（`permission denied while connecting to socket`）なので、
    /// 完全一致で peer 検証由来の拒否であることを区別する。
    #[test]
    #[ignore = "requires a listening socket owned by another UID prepared by a human; PLUG-12"]
    fn plug12_connect_rejects_other_uid_listener() {
        let path = fixture_path("FANDHE_CONTAINER_TEST_OTHER_UID_SOCKET");
        let meta = std::fs::symlink_metadata(&path).expect("fixture socket must exist");
        assert!(
            meta.file_type().is_socket(),
            "fixture must be a socket: {path:?}"
        );
        let dir = TempDir::new();
        assert_ne!(
            meta.uid(),
            dir.owner_uid(),
            "fixture socket must be owned by a different UID than the test user"
        );

        let err = UdsStream::connect(Path::new(&path), WAIT).unwrap_err();
        assert_eq!(err.code(), PluginErrorCode::PermissionDenied);
        assert_eq!(err.message(), MISMATCH_MESSAGE);
    }
}
