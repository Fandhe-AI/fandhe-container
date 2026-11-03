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
//!
//! 実機前提の観測（macOS のみ・`#[ignore]`）: `plug12_macos_peer_uid_after_client_close_probe` は、
//! client が connect 直後に close した接続の peer UID 取得結果を JSON 行で出す（accept の結果・監査 reason と getpeereid の errno。UID は含まない）（#2252 P2-2。
//! 結果の判断は人間担当の #2405）。手順は `AGENTS.md`「実機前提テスト」節。

// 残骸・PID 再利用と衝突しない排他作成の補助（REPAIR-12・#3435）。root や別 UID の `#[ignore]` の場面を
// 持つ試験ファイルがあるため、予測できる名前を消す補助は使わず排他作成で連番を進める。
#[cfg(unix)]
#[path = "../../net/tests/support/exclusive_dir.rs"]
mod exclusive_dir;

#[path = "../../core/tests/support/reap.rs"]
mod reap;

#[cfg(not(unix))]
#[test]
fn plug12_peer_auth_is_unimplemented_on_non_unix() {
    use fandhe_container_plugin::{PluginErrorCode, UdsListener, UdsStream};
    let err = UdsListener::bind(std::path::Path::new("s.sock")).unwrap_err();
    assert_eq!(err.code(), PluginErrorCode::Unimplemented);
    let err = UdsStream::connect(
        std::path::Path::new("s.sock"),
        std::time::Duration::from_secs(1),
        &mut fandhe_container_plugin::JsonLinesPeerAuthObserver::new(),
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
            all(
                target_pointer_width = "64",
                any(target_arch = "x86_64", target_arch = "aarch64")
            )
        )
    )
))]
mod unix {
    use fandhe_container_plugin::{
        ControlMessage, MessageId, PluginErrorCode, RpcTimeout, UdsListener, UdsStream,
        decode_message, encode_message,
    };
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    use std::path::{Path, PathBuf};
    use std::time::{Duration, Instant};

    const WAIT: Duration = Duration::from_secs(5);

    /// peer 不一致の拒否で返る固定メッセージ（UID 値を含めない契約）。
    const MISMATCH_MESSAGE: &str = "peer credential does not match the current user";

    type Msg = ControlMessage<String>;

    /// 0700 の一時ディレクトリ（socket の配置先。drop で削除）。
    struct TempDir(PathBuf);
    impl TempDir {
        fn new() -> Self {
            // 残骸・PID 再利用との衝突を避ける排他作成（既存のパスは消さず連番を進める。REPAIR-12・#3435）。
            let p = crate::exclusive_dir::create("fcpa").unwrap();
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
    /// 受理した経路では監査イベントが 0 件であることも照合する（PLUG-12・SEC-4・TASK-124.5）。
    fn assert_same_uid_roundtrip(l: &UdsListener) {
        let rpc = RpcTimeout::new(WAIT).unwrap();
        let path = l.path().to_path_buf();
        let h = std::thread::spawn(move || {
            let mut audit = fandhe_container_plugin::JsonLinesPeerAuthObserver::new();
            let mut c = UdsStream::connect(&path, WAIT, &mut audit).unwrap();
            assert_eq!(audit.drain_lines(), Vec::<String>::new());
            c.write_frame(&encode_message(&msg(1, false, "ping")).unwrap(), rpc)
                .unwrap();
            decode_message::<String>(&c.read_frame(rpc).unwrap()).unwrap()
        });
        let mut audit = fandhe_container_plugin::JsonLinesPeerAuthObserver::new();
        let mut s = l.accept(WAIT, &mut audit).unwrap();
        assert_eq!(audit.drain_lines(), Vec::<String>::new());
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
            let mut c = UdsStream::connect(
                &path,
                WAIT,
                &mut fandhe_container_plugin::JsonLinesPeerAuthObserver::new(),
            )
            .unwrap();
            c.write_frame(&encode_message(&msg(1, false, "early")).unwrap(), rpc)
                .unwrap();
            tx.send(()).unwrap();
            c
        });
        rx.recv_timeout(WAIT).unwrap();
        let mut s = l
            .accept(
                WAIT,
                &mut fandhe_container_plugin::JsonLinesPeerAuthObserver::new(),
            )
            .unwrap();
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

        match l.accept(
            Duration::from_secs(10),
            &mut fandhe_container_plugin::JsonLinesPeerAuthObserver::new(),
        ) {
            Ok(_) => {
                let _ = child.kill();
                crate::reap::reap_or_report(&mut child, crate::reap::reap_within());
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
            crate::reap::reap_or_report(&mut child, crate::reap::reap_within());
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

        let err = UdsStream::connect(
            Path::new(&path),
            WAIT,
            &mut fandhe_container_plugin::JsonLinesPeerAuthObserver::new(),
        )
        .unwrap_err();
        assert_eq!(err.code(), PluginErrorCode::PermissionDenied);
        assert_eq!(err.message(), MISMATCH_MESSAGE);
    }

    /// PLUG-12 / SEC-4（実機前提・観測用。#2252 P2-2・人間担当は #2405）: macOS で client が connect 直後に
    /// close した接続に対し、listener 側の peer UID 取得（`getpeereid`）が成功するか失敗するかを観測する。
    ///
    /// 結果の解釈（`ENOTCONN` で失敗するか。失敗するなら少数回の許容を設けるか）は人間が行う。
    /// 現状の挙動（取得失敗は即エラー・fail-closed）は変えない。assert はどちらの結果でも成り立つ
    /// 不変条件（受理なら監査 0 件）に限り、失敗は panic せず観測として記録する。
    /// 出力は code・監査 reason・errno だけで、UID 値は載せない。
    #[test]
    #[cfg(target_os = "macos")]
    #[ignore = "observation on a real macOS host; the result is judged by a human; PLUG-12 #2252 P2-2"]
    fn plug12_macos_peer_uid_after_client_close_probe() {
        let dir = TempDir::new();
        let l = UdsListener::bind(&dir.sock()).unwrap();
        let mut connect_audit = fandhe_container_plugin::JsonLinesPeerAuthObserver::new();
        let c = UdsStream::connect(l.path(), WAIT, &mut connect_audit).unwrap();
        drop(c);
        std::thread::sleep(Duration::from_millis(50));

        let mut audit = fandhe_container_plugin::JsonLinesPeerAuthObserver::new();
        let result = l.accept(Duration::from_secs(2), &mut audit);
        let lines = audit.drain_lines();
        // 観測専用: 結果は panic せずそのまま JSON に記録する（Internal で監査なし〔set_io_timeout 由来〕・
        // Timeout 等も観測対象。#2252 P2-1/P2-2）。assert は「受理なら監査 0 件」だけに限る。
        let reasons: Vec<&str> = lines
            .iter()
            .map(|l| {
                if l.contains("\"reason\":\"peer_uid_unavailable\"") {
                    "peer_uid_unavailable"
                } else {
                    "other"
                }
            })
            .collect();
        let (outcome, code) = match &result {
            Ok(_) => {
                assert!(lines.is_empty(), "accepted connection must not be audited");
                ("ok", String::new())
            }
            Err(err) => ("error", format!("{:?}", err.code())),
        };
        println!(
            "{{\"probe\":\"peer_uid_after_close\",\"outcome\":\"{outcome}\",\"code\":\"{code}\",\"audit_count\":{},\"audit_reasons\":{:?}}}",
            lines.len(),
            reasons
        );

        // getpeereid の失敗 errno を、UID を含めず別の接続で観測する（ENOTCONN 等の区別用。#2405 の判断材料）。
        let sl_dir = TempDir::new();
        let std_l = std::os::unix::net::UnixListener::bind(sl_dir.sock()).unwrap();
        let client = std::os::unix::net::UnixStream::connect(sl_dir.sock()).unwrap();
        drop(client);
        std::thread::sleep(Duration::from_millis(50));
        let (accepted, _) = std_l.accept().unwrap();
        let errno = fandhe_container_plugin::observe_peer_uid_errno(&accepted);
        match errno {
            Some(e) => println!(
                "{{\"probe\":\"peer_uid_errno_after_close\",\"outcome\":\"error\",\"errno\":{e}}}"
            ),
            None => println!("{{\"probe\":\"peer_uid_errno_after_close\",\"outcome\":\"ok\"}}"),
        }
    }
}
