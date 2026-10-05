//! ACK を返さない相手に対する往復待ちのタイムアウト保護結合試験
//! （PLUG-2・PLUG-5・REPAIR-5。TASK-107.7・#251）。
//! root・特権不要。待ちはすべて有限の期限付きで、CI の既定テスト集合
//! （`make test`・`integration-test` ジョブ）で実行される。
//!
//! 本 crate での「ACK / RPC 応答待ち」は `UdsStream::read_frame` を指す
//! （ACK 専用のワイヤー種別は無い）。単体の期限・接続の poisoning は
//! `transport_frame_io.rs` が担い、本ファイルは「要求を送ったのに応答が来ない」
//! 往復シナリオと、待機処理が無期限ブロックへ退行した場合でもテスト自身が
//! ハングせず失敗するためのウォッチドッグを担う。

#[cfg(not(unix))]
#[test]
fn plug5_ack_timeout_requires_unix_transport() {
    use fandhe_container_plugin::{PluginErrorCode, UdsStream};
    let err = UdsStream::connect(
        std::path::Path::new("s.sock"),
        std::time::Duration::from_secs(1),
        &mut fandhe_container_plugin::JsonLinesPeerAuthObserver::new(),
    )
    .unwrap_err();
    assert_eq!(err.code(), PluginErrorCode::Unimplemented);
}

#[cfg(unix)]
mod unix {
    use fandhe_container_plugin::{
        ControlMessage, MessageId, PluginErrorCode, RpcTimeout, UdsListener, UdsStream,
        decode_message, encode_message,
    };
    use std::io::Write;
    use std::os::unix::fs::DirBuilderExt;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    /// ウォッチドッグの上限。RpcTimeout（300ms）より十分長く、CI ステップの timeout より短い。
    const WAIT: Duration = Duration::from_secs(5);

    struct TempDir(PathBuf);
    impl TempDir {
        fn new() -> Self {
            static N: AtomicU32 = AtomicU32::new(0);
            let p = std::env::temp_dir().join(format!(
                "fcpt-{}-{}",
                std::process::id(),
                N.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::DirBuilder::new().mode(0o700).create(&p).unwrap();
            Self(p)
        }
        fn sock(&self) -> PathBuf {
            self.0.join("s.sock")
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    type Msg = ControlMessage<String>;

    fn rpc(ms: u64) -> RpcTimeout {
        RpcTimeout::new(Duration::from_millis(ms)).unwrap()
    }

    fn request(id: u64, body: &str) -> Msg {
        ControlMessage::Request {
            id: MessageId::new(id),
            body: body.to_string(),
        }
    }

    /// `f` を別スレッドで実行し、`WAIT` 以内に結果が返らなければ失敗させる。
    /// 期限切れ時は実行スレッドを join しない（join すると再びハングするため）。
    fn with_watchdog<T: Send + 'static>(what: &str, f: impl FnOnce() -> T + Send + 'static) -> T {
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(f());
        });
        match rx.recv_timeout(WAIT) {
            Ok(v) => v,
            Err(_) => panic!("{what} hung: no result within {WAIT:?}"),
        }
    }

    /// server 側の振る舞い。要求を受信したら `act` を実行し、完了を `acted` へ通知した後、
    /// 解放通知（release の sender drop）まで接続を開いたまま沈黙する。
    /// client は `acted` を待ってから読み取り期限を開始する（部分応答の送信完了を保証し、
    /// server の遅延で「部分応答なしの Timeout」になる偽陽性を防ぐ）。
    fn run_silent_server(
        mut server: UdsStream,
        act: impl FnOnce(&mut UdsStream) + Send + 'static,
    ) -> (mpsc::Sender<()>, mpsc::Receiver<()>, mpsc::Receiver<Msg>) {
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let (acted_tx, acted_rx) = mpsc::channel::<()>();
        let (done_tx, done_rx) = mpsc::channel::<Msg>();
        // join は無期限に待つため使わない。完了は done チャネルで期限付きに受け取る。
        std::thread::spawn(move || {
            let got = server.read_frame(rpc(2000)).unwrap();
            let msg = decode_message::<String>(&got).unwrap();
            act(&mut server);
            let _ = acted_tx.send(());
            let _ = release_rx.recv_timeout(WAIT);
            let _ = done_tx.send(msg);
        });
        (release_tx, acted_rx, done_rx)
    }

    /// 要求送信成功 -> 応答なし -> client の read_frame が有限時間で Timeout になる。
    fn assert_client_times_out(act: impl FnOnce(&mut UdsStream) + Send + 'static) {
        let dir = TempDir::new();
        let l = UdsListener::bind(&dir.sock()).unwrap();
        let mut client = UdsStream::connect(
            l.path(),
            WAIT,
            &mut fandhe_container_plugin::JsonLinesPeerAuthObserver::new(),
        )
        .unwrap();
        let server = l
            .accept(
                WAIT,
                &mut fandhe_container_plugin::JsonLinesPeerAuthObserver::new(),
            )
            .unwrap();
        let (release, acted, done) = run_silent_server(server, act);

        let frame = encode_message(&request(42, "ping")).unwrap();
        client.write_frame(&frame, rpc(1000)).unwrap();

        // server の act（部分応答の送信等）完了後に client の期限を開始する。
        // 失敗時も server を解放できるよう、結果は後で検証する。
        let acted_ok = acted.recv_timeout(WAIT).is_ok();

        let (err, elapsed) = with_watchdog("client read_frame", move || {
            let start = Instant::now();
            let e = client.read_frame(rpc(300)).unwrap_err();
            (e, start.elapsed())
        });

        // 先に server を解放する。server の停止時は join せずに失敗させる（REPAIR-5）。
        drop(release);
        assert!(acted_ok, "server did not finish its action within {WAIT:?}");
        let received = done
            .recv_timeout(WAIT)
            .expect("server thread did not complete within the deadline");
        assert_eq!(received, request(42, "ping"));

        assert_eq!(err.code(), PluginErrorCode::Timeout);
        assert_eq!(err.code().as_str(), "TIMEOUT");
        assert_eq!(err.message(), "timed out waiting for a frame");
        assert!(elapsed >= Duration::from_millis(250), "{elapsed:?}");
        assert!(elapsed < WAIT, "{elapsed:?}");
    }

    /// ACK（応答）を一切返さない相手でも、待ち側はハングせず Timeout で終了する。
    #[test]
    fn plug5_ack_timeout_does_not_hang() {
        assert_client_times_out(|_| {});
    }

    /// 応答の先頭数バイトだけ送って沈黙する相手でも、フレーム全体の期限で打ち切る。
    #[test]
    fn plug5_partial_ack_then_silence_times_out() {
        assert_client_times_out(|server| {
            let bytes = encode_message(&request(42, "pong")).unwrap().encode();
            let head = bytes.get(..3).unwrap();
            server.write_all(head).unwrap();
            server.flush().unwrap();
        });
    }
}
