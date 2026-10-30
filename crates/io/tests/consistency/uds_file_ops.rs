//! UDS 越しのファイル操作（v2 の `Create`・`WriteFile`・`Close`・`Flush`・`Nack`）の整合性ケース
//! （TASK-14 追補・#3166・IO-4・IO-1・IO-5・REPAIR-6。設計は `docs/design/io-protocol.md` の F14）。
//!
//! [`super::uds_concurrent`] は単一 sink モード（v1 の `Write`）を std の `UnixStream` で手組みして
//! 確かめる。本モジュールは v2 のファイル操作モードを、本番の経路そのもので確かめる。
//! クライアントは `UdsClientConnection::connect` ＋ `PipelineClient`、サーバーは
//! `UdsServer::bind` → `accept` → `serve_file_connection_with_limit` で、生の
//! `UnixListener` / `UnixStream` では迂回しない（ソケットの親ディレクトリ検査と peer uid 照合を
//! 通常どおり通す）。
//!
//! # 範囲と制約
//! - 型つき API では表現できない入力（`..` を含むパス、request id の逆戻り）だけ、
//!   `UdsClientConnection` の `send_frame` で生フレームを送る。型つきエンコーダを迂回して不正入力を
//!   作るのは試験コードに限る（REPAIR-2 の例外。製品コードに同じ経路は無い）。
//! - Nack はパスを返さず code と reason だけを返す（型の上で保証されている）。
//! - 実行中の `recv_ack` の失敗はクライアントを失効させる（P1-3）ため、「まだ届かない」ことの確認に
//!   短い期限の受信の空振りは使わない。順序はバッチの実行回数など、サーバーの統計で裏づける。
//! - 実行中のバッチが接続全体の失敗になったとき、実行済みの Create の結果は不定（F10）であり、
//!   ファイルの有無は assert しない。
//! - `Flush` を待つケースは、永続化に未対応の環境（Linux 5.8 未満等）では FlushAck を偽装せず
//!   `Unimplemented` で終わることを assert する（skip にしない）。
//! - 待ちはすべて期限つき（`IoTimeout`・チャネルの `recv_timeout`）で、`sleep` で同期しない（REPAIR-5）。
//! - `UdsClientConnection` は Linux / macOS 限定。Windows では
//!   `io4_uds_file_ops_connect_is_unimplemented_on_unsupported_os` が未対応を明示する。

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod unix {
    use std::path::{Path, PathBuf};
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    use fandhe_container_io::{
        AckReceipt, BatchConfig, FileHandle, FileServeLimits, FileServeReport, Frame, FrameKind,
        FrameReceiver, FrameSender, GuestFileCreator, GuestPath, InFlightLimit, IoErrorCode,
        IoTimeout, MaxOpenFiles, NackCode, NackReason, NoopSendObserver, NoopServerObserver,
        PipelineClient, ReceiveLimits, UdsClientConnection, UdsServer, UdsServerPolicy,
        UnflushedLimit, WritebackTimeouts, decode_ack, decode_nack,
        serve_file_connection_with_limit,
    };

    type Client = PipelineClient<UdsClientConnection<NoopServerObserver>, NoopSendObserver>;

    /// ソケット・共有ルート・外側ディレクトリを置く 0700 の一時ディレクトリ
    /// （macOS の `sun_path` 104 バイト上限に収まるよう prefix は短くする）。
    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new() -> Self {
            let path = crate::exclusive_dir::create("fcio-ufo")
                .expect("must be able to create a temp dir for the socket and share root");
            Self { path }
        }

        fn socket_path(&self) -> PathBuf {
            self.path.join("s.sock")
        }

        fn share_root(&self) -> PathBuf {
            self.path.join("share")
        }

        fn outside(&self) -> PathBuf {
            self.path.join("outside")
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    fn secs(n: u64) -> IoTimeout {
        IoTimeout::new(Duration::from_secs(n)).expect("valid timeout")
    }

    fn timeouts() -> WritebackTimeouts {
        WritebackTimeouts {
            recv: secs(5),
            send: secs(5),
        }
    }

    fn gp(path: &str) -> GuestPath {
        GuestPath::parse(path).expect("test path must be a valid guest path")
    }

    /// サーバー（別スレッドで accept → serve）の結果を受ける。
    struct Session {
        rx: mpsc::Receiver<FileServeReport>,
    }

    impl Session {
        /// 終了報告を待つ（REPAIR-5: 期限つき）。
        fn finish(self) -> FileServeReport {
            self.rx
                .recv_timeout(Duration::from_secs(15))
                .expect("server thread must finish in time")
        }
    }

    /// bind して共有ルートを作り、accept → serve を別スレッドで始める。
    fn start(dir: &TempDir, batch: usize, limits: FileServeLimits) -> Session {
        let mut server = UdsServer::bind(
            &dir.socket_path(),
            ReceiveLimits::default(),
            NoopServerObserver,
        )
        .expect("bind must succeed on a private, empty path");
        std::fs::create_dir(dir.share_root()).expect("share root");
        let creator = GuestFileCreator::new(dir.share_root()).expect("creator");
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let mut conn = server
                .accept(secs(10), NoopServerObserver)
                .expect("server must accept the client within the timeout");
            let report = serve_file_connection_with_limit(
                &mut conn,
                BatchConfig::new(batch).expect("batch size"),
                limits,
                &creator,
                timeouts(),
            );
            let _ = tx.send(report);
        });
        Session { rx }
    }

    fn default_limits() -> FileServeLimits {
        FileServeLimits::new(MaxOpenFiles::default(), UnflushedLimit::default())
    }

    fn raw_client(path: &Path) -> UdsClientConnection<NoopServerObserver> {
        UdsClientConnection::connect(
            path,
            secs(5),
            UdsServerPolicy::same_effective_uid(),
            ReceiveLimits::default(),
            NoopServerObserver,
        )
        .expect("client must connect")
    }

    fn client(path: &Path) -> Client {
        PipelineClient::new(
            raw_client(path),
            InFlightLimit::new(64).expect("limit"),
            NoopSendObserver,
        )
    }

    fn supported() -> bool {
        fandhe_container_io::persist_support().is_supported()
    }

    /// `n` 件の ACK（Write か Rejected）を FIFO で受け取る。順序違反は `recv_ack` 自体が `Err` にする。
    fn drain(pc: &mut Client, n: usize) -> Vec<AckReceipt> {
        (0..n)
            .map(|_| pc.recv_ack(secs(5)).expect("ack must arrive in time"))
            .collect()
    }

    fn is_write(r: &AckReceipt) -> bool {
        matches!(r, AckReceipt::Write(_))
    }

    fn rejected(r: &AckReceipt) -> (NackCode, NackReason) {
        match r {
            AckReceipt::Rejected(x) => (x.code(), x.reason()),
            other => panic!("expected a rejection, got {other:?}"),
        }
    }

    /// 決定的な 32 B のチャンク（ファイル番号とチャンク番号から導く）。
    fn chunk(file: usize, c: usize) -> Vec<u8> {
        (0..32)
            .map(|k| u8::try_from((file * 31 + c * 7 + k) % 251).expect("fits"))
            .collect()
    }

    fn expected_body(file: usize, chunks: usize) -> Vec<u8> {
        (0..chunks).flat_map(|c| chunk(file, c)).collect()
    }

    fn names(dir: &Path) -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(dir)
            .expect("read_dir")
            .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
            .collect();
        v.sort();
        v
    }

    fn raw_create(conn: &mut UdsClientConnection<NoopServerObserver>, id: u64, path: &str) {
        let mut payload = id.to_le_bytes().to_vec();
        payload.extend_from_slice(&u16::try_from(path.len()).expect("len").to_le_bytes());
        payload.extend_from_slice(path.as_bytes());
        conn.send_frame(
            &Frame::new(FrameKind::Create, payload).expect("frame"),
            secs(5),
        )
        .expect("send create");
    }

    fn raw_handle_op(
        conn: &mut UdsClientConnection<NoopServerObserver>,
        kind: FrameKind,
        id: u64,
        handle: u64,
        body: &[u8],
    ) {
        let mut payload = id.to_le_bytes().to_vec();
        payload.extend_from_slice(&handle.to_le_bytes());
        payload.extend_from_slice(body);
        conn.send_frame(&Frame::new(kind, payload).expect("frame"), secs(5))
            .expect("send handle op");
    }

    /// IO-4・IO-2: N ファイルへ交互に書いて close → flush した後、新しいハンドルで開くと
    /// 内容がバイト単位で一致する（close-to-open）。
    #[test]
    fn io4_uds_file_ops_n_files_flush_then_close_to_open_matches() {
        const FILES: usize = 8;
        const CHUNKS: usize = 4;
        let dir = TempDir::new();
        let session = start(&dir, 16, default_limits());
        let mut pc = client(&dir.socket_path());
        let handles: Vec<FileHandle> = (0..FILES)
            .map(|i| {
                pc.create(&gp(&format!("d{}/f{i}", i % 2)), secs(5))
                    .expect("create")
            })
            .collect();
        for c in 0..CHUNKS {
            for (i, h) in handles.iter().enumerate() {
                pc.write_file(*h, &chunk(i, c), secs(5)).expect("write");
            }
        }
        for h in &handles {
            pc.close(*h, secs(5)).expect("close");
        }
        let barrier = pc.flush(secs(5)).expect("flush");
        let writes = FILES + FILES * CHUNKS + FILES;
        let receipts = drain(&mut pc, writes);
        assert!(receipts.iter().all(is_write), "{receipts:?}");
        if supported() {
            match pc.recv_ack(secs(5)).expect("flush ack") {
                AckReceipt::Flush(ack) => assert_eq!(ack.barrier(), barrier),
                other => panic!("expected a flush ack, got {other:?}"),
            }
        } else {
            pc.recv_ack(secs(5))
                .expect_err("no flush ack without persist support");
        }
        drop(pc);
        let report = session.finish();
        assert_eq!(
            report.end.code(),
            if supported() {
                IoErrorCode::Unavailable
            } else {
                IoErrorCode::Unimplemented
            }
        );
        for i in 0..FILES {
            let got = std::fs::read(dir.share_root().join(format!("d{}/f{i}", i % 2)))
                .expect("file must exist");
            assert_eq!(got, expected_body(i, CHUNKS), "file {i} content");
        }
        let s = &report.stats;
        assert_eq!(s.creates_succeeded, 8);
        assert_eq!(s.write_files_succeeded, 32);
        assert_eq!(s.closes_succeeded, 8);
        assert_eq!(s.nacks_sent, 0);
        assert_eq!(s.flush_acks_sent, u64::from(supported()));
    }

    /// IO-1・F6: `WriteFile` は Create の Ack を待たずに送れる。Create と WriteFile が同じバッチで
    /// 実行される（バッチ数 1）ことで、WriteFile が Create の Ack の送出より前にサーバーへ届いていたと
    /// 裏づける。
    #[test]
    fn io1_uds_file_ops_write_file_pipelined_before_create_ack() {
        let dir = TempDir::new();
        let session = start(&dir, 64, default_limits());
        let mut pc = client(&dir.socket_path());
        let h = pc.create(&gp("p/q"), secs(5)).expect("create");
        pc.write_file(h, b"one-", secs(5)).expect("write 1");
        pc.write_file(h, b"two", secs(5)).expect("write 2");
        pc.close(h, secs(5)).expect("close");
        let _barrier = pc.flush(secs(5)).expect("flush");
        let receipts = drain(&mut pc, 4);
        assert!(receipts.iter().all(is_write), "{receipts:?}");
        if supported() {
            assert!(matches!(
                pc.recv_ack(secs(5)).expect("flush ack"),
                AckReceipt::Flush(_)
            ));
        }
        drop(pc);
        let report = session.finish();
        assert_eq!(report.stats.batches_executed, 1);
        assert_eq!(report.stats.creates_succeeded, 1);
        assert_eq!(report.stats.write_files_succeeded, 2);
        assert_eq!(
            std::fs::read(dir.share_root().join("p/q")).expect("read"),
            b"one-two"
        );
    }

    /// IO-5: 大文字小文字だけが違う Create は Nack（AlreadyExists / CaseCollision）になり、
    /// 他のファイルは影響を受けない。衝突した名前のファイルは作られない。
    #[test]
    fn io5_uds_file_ops_case_collision_nacked_others_unaffected() {
        let dir = TempDir::new();
        let session = start(&dir, 7, default_limits());
        let mut pc = client(&dir.socket_path());
        let upper = pc.create(&gp("Foo"), secs(5)).expect("create Foo");
        let _lower = pc.create(&gp("foo"), secs(5)).expect("create foo");
        let bar = pc.create(&gp("bar"), secs(5)).expect("create bar");
        pc.write_file(upper, b"UPPER", secs(5)).expect("write");
        pc.write_file(bar, b"bar!", secs(5)).expect("write");
        pc.close(upper, secs(5)).expect("close");
        pc.close(bar, secs(5)).expect("close");
        let receipts = drain(&mut pc, 7);
        assert!(is_write(&receipts[0]));
        assert_eq!(
            rejected(&receipts[1]),
            (NackCode::AlreadyExists, NackReason::CaseCollision)
        );
        assert!(
            receipts
                .iter()
                .enumerate()
                .all(|(i, r)| i == 1 || is_write(r)),
            "{receipts:?}"
        );
        drop(pc);
        let report = session.finish();
        assert_eq!(
            report.stats.nacks_by_reason.get(NackReason::CaseCollision),
            1
        );
        assert_eq!(report.stats.nacks_sent, 1);
        assert_eq!(names(&dir.share_root()), vec!["Foo", "bar"]);
        assert_eq!(
            std::fs::read(dir.share_root().join("Foo")).expect("read"),
            b"UPPER"
        );
        assert_eq!(
            std::fs::read(dir.share_root().join("bar")).expect("read"),
            b"bar!"
        );
    }

    /// IO-1・F6: 失敗した Create のハンドルへの WriteFile / Close は要求単位の Nack
    /// （InvalidArgument / UnknownHandle）になり、接続は続いて後続の操作は Ack になる。
    #[test]
    fn io1_uds_file_ops_write_to_failed_handle_is_unknown_handle() {
        let dir = TempDir::new();
        let session = start(&dir, 7, default_limits());
        let mut pc = client(&dir.socket_path());
        let _a = pc.create(&gp("a"), secs(5)).expect("create a");
        let failed = pc.create(&gp("A"), secs(5)).expect("create A");
        pc.write_file(failed, b"x", secs(5)).expect("write");
        pc.close(failed, secs(5)).expect("close");
        let b = pc.create(&gp("b"), secs(5)).expect("create b");
        pc.write_file(b, b"after", secs(5)).expect("write b");
        pc.close(b, secs(5)).expect("close b");
        let receipts = drain(&mut pc, 7);
        assert!(is_write(&receipts[0]));
        assert_eq!(
            rejected(&receipts[1]),
            (NackCode::AlreadyExists, NackReason::CaseCollision)
        );
        for r in &receipts[2..4] {
            assert_eq!(
                rejected(r),
                (NackCode::InvalidArgument, NackReason::UnknownHandle)
            );
        }
        assert!(receipts[4..].iter().all(is_write), "{receipts:?}");
        drop(pc);
        let report = session.finish();
        assert_eq!(report.end.code(), IoErrorCode::Unavailable);
        assert_eq!(
            std::fs::read(dir.share_root().join("b")).expect("read"),
            b"after"
        );
    }

    /// IO-4・IO-2・F7: 複数ファイルにまたがるバッチで、K ファイルごとの Flush を挟んでも
    /// Ack と FlushAck の順序が保たれ、全ファイルの内容が一致する。
    #[test]
    fn io4_uds_file_ops_flush_every_k_files_preserves_order() {
        const GROUPS: usize = 3;
        const PER_GROUP: usize = 3;
        let dir = TempDir::new();
        let session = start(&dir, 3, default_limits());
        let mut pc = client(&dir.socket_path());
        let mut completed = 0usize;
        for g in 0..GROUPS {
            let handles: Vec<FileHandle> = (0..PER_GROUP)
                .map(|j| {
                    pc.create(&gp(&format!("g{g}/f{j}")), secs(5))
                        .expect("create")
                })
                .collect();
            for c in 0..2 {
                for (j, h) in handles.iter().enumerate() {
                    pc.write_file(*h, &chunk(g * PER_GROUP + j, c), secs(5))
                        .expect("write");
                }
            }
            for h in &handles {
                pc.close(*h, secs(5)).expect("close");
            }
            let barrier = pc.flush(secs(5)).expect("flush");
            let receipts = drain(&mut pc, PER_GROUP * 4);
            assert!(receipts.iter().all(is_write), "{receipts:?}");
            if !supported() {
                pc.recv_ack(secs(5))
                    .expect_err("no flush ack without persist support");
                break;
            }
            match pc.recv_ack(secs(5)).expect("flush ack") {
                AckReceipt::Flush(ack) => assert_eq!(ack.barrier(), barrier),
                other => panic!("expected a flush ack, got {other:?}"),
            }
            completed += 1;
        }
        drop(pc);
        let report = session.finish();
        if supported() {
            assert_eq!(completed, GROUPS);
            assert_eq!(report.stats.flush_acks_sent, 3);
            assert_eq!(report.end.code(), IoErrorCode::Unavailable);
        } else {
            assert_eq!(report.end.code(), IoErrorCode::Unimplemented);
        }
        assert!(report.stats.batches_executed >= 2);
        let groups_written = if supported() { GROUPS } else { 1 };
        for g in 0..groups_written {
            for j in 0..PER_GROUP {
                let got = std::fs::read(dir.share_root().join(format!("g{g}/f{j}")))
                    .expect("file must exist");
                assert_eq!(got, expected_body(g * PER_GROUP + j, 2), "g{g}/f{j}");
            }
        }
    }

    /// IO-1・F6・F10: 開いているファイル数の上限に達した Create は ResourceExhausted /
    /// OpenFilesLimit の Nack（葉を作らない）。Close で空きができれば同じ名前を作れる。
    #[test]
    fn io1_uds_file_ops_open_files_limit_then_close_allows_create() {
        let dir = TempDir::new();
        let limits = FileServeLimits::new(
            MaxOpenFiles::new(2).expect("limit"),
            UnflushedLimit::default(),
        );
        let session = start(&dir, 8, limits);
        let mut pc = client(&dir.socket_path());
        let a = pc.create(&gp("a"), secs(5)).expect("create a");
        let b = pc.create(&gp("b"), secs(5)).expect("create b");
        let _c = pc.create(&gp("c"), secs(5)).expect("create c (over limit)");
        pc.close(a, secs(5)).expect("close a");
        let c2 = pc.create(&gp("c"), secs(5)).expect("create c again");
        pc.write_file(c2, b"fits", secs(5)).expect("write c");
        pc.close(c2, secs(5)).expect("close c");
        pc.close(b, secs(5)).expect("close b");
        let receipts = drain(&mut pc, 8);
        assert_eq!(
            rejected(&receipts[2]),
            (NackCode::ResourceExhausted, NackReason::OpenFilesLimit)
        );
        assert!(
            receipts
                .iter()
                .enumerate()
                .all(|(i, r)| i == 2 || is_write(r)),
            "{receipts:?}"
        );
        drop(pc);
        let report = session.finish();
        assert_eq!(report.stats.max_open_handles, 2);
        assert_eq!(
            report.stats.nacks_by_reason.get(NackReason::OpenFilesLimit),
            1
        );
        assert_eq!(
            std::fs::read(dir.share_root().join("c")).expect("read"),
            b"fits"
        );
    }

    /// IO-5: パストラバーサルは 3 層で拒否され、共有ルートの外に何も作られない。
    /// (a) クライアント側の `GuestPath` が送信前に拒否する、(b) 生フレームで送ってもサーバーが
    /// PathSyntax の Nack にする（接続は続く）、(c) symlink の祖先は EscapesRoot、
    /// ディレクトリでない祖先は NotADirectory。
    #[test]
    fn io5_uds_file_ops_path_traversal_nacked_and_contained() {
        let bad = ["../x", "a/../../x", "/abs", "a\\b", "c:x"];
        // (a) 型つき API ではワイヤーへ出せない。
        for p in bad {
            assert!(GuestPath::parse(p).is_err(), "{p} must be rejected");
        }

        // (b) 生フレームでもサーバーが拒否する。
        let dir = TempDir::new();
        std::fs::create_dir(dir.outside()).expect("outside");
        let session = start(&dir, bad.len() + 1, default_limits());
        let mut raw = raw_client(&dir.socket_path());
        for (i, p) in bad.iter().enumerate() {
            raw_create(&mut raw, u64::try_from(i + 1).expect("id"), p);
        }
        raw_create(&mut raw, 6, "ok");
        for i in 0..bad.len() {
            let frame = raw.recv_frame(secs(5)).expect("nack frame");
            assert_eq!(frame.kind(), FrameKind::Nack);
            let n = decode_nack(&frame).expect("nack");
            assert_eq!(n.id().get(), u64::try_from(i + 1).expect("id"));
            assert_eq!(
                (n.code(), n.reason()),
                (NackCode::InvalidArgument, NackReason::PathSyntax)
            );
        }
        let frame = raw.recv_frame(secs(5)).expect("ack frame");
        assert_eq!(decode_ack(&frame).expect("ack").id().get(), 6);
        drop(raw);
        let report = session.finish();
        assert_eq!(report.stats.nacks_by_reason.get(NackReason::PathSyntax), 5);
        assert_eq!(names(&dir.share_root()), vec!["ok"]);
        assert!(names(&dir.outside()).is_empty());

        // (c) symlink の祖先とディレクトリでない祖先。
        let dir2 = TempDir::new();
        std::fs::create_dir(dir2.outside()).expect("outside");
        let session = start(&dir2, 2, default_limits());
        std::os::unix::fs::symlink(dir2.outside(), dir2.share_root().join("link"))
            .expect("symlink");
        std::fs::write(dir2.share_root().join("plain"), b"p").expect("plain file");
        let mut pc = client(&dir2.socket_path());
        pc.create(&gp("link/x"), secs(5)).expect("create link/x");
        pc.create(&gp("plain/x"), secs(5)).expect("create plain/x");
        let receipts = drain(&mut pc, 2);
        assert_eq!(
            rejected(&receipts[0]),
            (NackCode::InvalidArgument, NackReason::EscapesRoot)
        );
        assert_eq!(
            rejected(&receipts[1]),
            (NackCode::InvalidArgument, NackReason::NotADirectory)
        );
        drop(pc);
        let _ = session.finish();
        assert!(names(&dir2.outside()).is_empty());
        assert_eq!(names(&dir2.share_root()), vec!["link", "plain"]);
    }

    /// IO-4・F10: バッチの実行中に接続全体の失敗（request id の逆戻り）が起きると、そのバッチの
    /// 応答は 1 件も送られず、クライアントは EOF（Unavailable）を見る。実行済みの Create の結果は
    /// 不定なので、ファイルの有無は assert しない。
    #[test]
    fn io4_uds_file_ops_connection_failure_mid_batch_sends_no_response() {
        let dir = TempDir::new();
        let session = start(&dir, 3, default_limits());
        let mut raw = raw_client(&dir.socket_path());
        raw_create(&mut raw, 1, "a");
        raw_handle_op(&mut raw, FrameKind::WriteFile, 2, 1, b"x");
        raw_handle_op(&mut raw, FrameKind::Close, 2, 1, b"");
        let err = raw
            .recv_frame(secs(5))
            .expect_err("no response may be sent for a failed batch");
        assert_eq!(err.code(), IoErrorCode::Unavailable);
        let report = session.finish();
        assert_eq!(report.end.code(), IoErrorCode::InvalidArgument);
        assert_eq!(report.stats.acks_sent, 0);
        assert_eq!(report.stats.nacks_sent, 0);
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
mod unsupported {
    use std::time::Duration;

    use fandhe_container_io::{
        IoErrorCode, IoTimeout, NoopServerObserver, ReceiveLimits, UdsClientConnection,
        UdsServerPolicy,
    };

    /// IO-1・IO-4: UDS 非対応の OS では connect が `Unimplemented` を返す（黙って 0 件にしない）。
    #[test]
    fn io4_uds_file_ops_connect_is_unimplemented_on_unsupported_os() {
        let path = std::env::temp_dir().join("fcio-ufo-unsupported.sock");
        let timeout = IoTimeout::new(Duration::from_secs(1)).expect("timeout");
        let err = UdsClientConnection::connect(
            &path,
            timeout,
            UdsServerPolicy::same_effective_uid(),
            ReceiveLimits::default(),
            NoopServerObserver,
        )
        .expect_err("connect must fail on an unsupported OS");
        assert_eq!(err.code(), IoErrorCode::Unimplemented);
    }
}
