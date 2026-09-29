//! グレースフルシャットダウン経路の close-to-open 検証ケース
//! （TASK-14.3・IO-4・REPAIR-6・#82）。
//!
//! [`super::harness`] の部品（[`harness::DuplexEnd`]・[`harness::TempDir`]・
//! [`harness::body_for`]・[`harness::SharedSink`] 等）を再利用し、
//! 「グレースフルシャットダウン」「close」「open」「close-to-open 整合性違反」
//! を次のように定義して検証する（#82 実装計画に基づく）。
//!
//! # 用語の定義
//!
//! - **グレースフルシャットダウン**: 次のどちらか。
//!   - (a) クライアントが write の後に `Flush` を送る。サーバーは
//!     [`fandhe_container_io::writeback::serve_connection`] の
//!     [`fandhe_container_io::batch::BatchBuffer::take_pending`] で残りを
//!     書き込み、ACK を返してから [`IoErrorCode::Unimplemented`] で終わる
//!     （D4。FlushAck と syncfs は TASK-15.2.2・#824 の担当で、本ケースの
//!     着手時点では未マージ）。
//!   - (b) 送った write の ACK をすべて受け取ってから切断する（EOF →
//!     `Unavailable`・`discarded_pending_frames == 0`）。
//! - **非グレースフル**: ACK していない端数を残したまま切断すること。D5 に
//!   より端数は破棄される。本ファイルでは比較対象としてだけ扱う（G3）。
//! - **close**: `serve_connection` が戻り、sink（[`std::fs::File`]）が drop
//!   された状態。sink は [`harness::spawn_server`] のクロージャへ move
//!   されているため、[`harness::join_within`] から戻った時点で close が保証
//!   される。[`harness::SharedSink`] の場合は、最後の clone（テストが持つ
//!   元の値を含む）が drop された時点。
//! - **open**: close の後に、新しいハンドルで [`read_fresh`] すること。
//! - **close-to-open 整合性違反**: 次のいずれか。
//!   - fresh open で読んだ内容が、ACK 済みの期待バイト列（[`records`] の
//!     連結）と完全一致しない（欠落・余剰・重複・部分レコード・ゼロ埋めの穴）
//!   - `metadata().len()` が期待長、またはサーバーの `stats.bytes_written`
//!     の累計と一致しない
//! - **対象外**: クラッシュ時・電源断時の永続化（fsync / syncfs。IO-2・IO-3・
//!   TASK-15）と、並行する読み手の可視性（OS の性質）。
//!
//! # PoC との差（`03-poc/io-layer-redesign`）
//!
//! PoC は EOF を受けたときに残りのバッチを flush する前提だったが、現行の
//! `serve_connection` は D5 に従い EOF の時点で ACK していない保留分を破棄
//! する。本スイートはこの現行実装を基準に「グレースフルシャットダウン」を
//! 上記 (a)・(b) として定義し直す（spec 側の変更は不要と判断。IO-4 の
//! 「グレースフルシャットダウン」はこの 2 経路で満たせる）。
//!
//! # 既存 19 件（#80・#81）にない観点
//!
//! - G1: 同じファイルへ続けて開くセッションで、境界（Flush 終了・clean 切断・
//!   再度 Flush 終了）ごとに close-to-open を確認する（rename_truncate.rs の
//!   `run_session` は毎回サーバー切断のみで、境界ごとの再オープン確認はない）
//! - G2: 残りのない（`take_pending` が `None` を返す） Flush での close-to-open
//! - G3: 非グレースフルな切断（未 ACK 分の破棄）の後、未 ACK 分を再送して
//!   Flush で閉じても、破棄されたレコードが重複も欠落もなく厳密に 1 回だけ
//!   現れること（D5 の「破棄が再送時の重複を防ぐ」の直接確認）
//! - G4: [`harness::SharedSink`] を共有する全クライアントが同時に Flush で
//!   閉じ、最後の close の後に fresh open すること
//! - G5: 別ファイルの複数接続で、片方の close がもう片方の未 close 状態に
//!   影響しないこと（close の独立性）
//!
//! `sleep` によるタイミング同期は使わない。待ち合わせには必ず期限を付ける
//! （[`harness::join_within`]・[`harness::barrier_wait_within`]・
//! [`harness::timeout`]。REPAIR-5）。

use std::path::Path;
use std::sync::{Arc, Barrier, mpsc};
use std::time::Duration;

use fandhe_container_io::{
    AppendFileSink, BatchConfig, Frame, FrameKind, FrameReceiver, FrameSender, InFlightLimit,
    IoError, IoErrorCode, IoTimeout, NoopSendObserver, PipelineClient, WritebackReport,
    WritebackTimeouts, serve_connection,
};

use super::harness::{
    self, DuplexEnd, SharedSink, TempDir, barrier_wait_within, body_for, decompose_records,
    drain_acks, join_within, record_client, record_seq, send_all_writes, spawn_server, timeout,
};

/// [`harness::join_within`] / [`harness::barrier_wait_within`] に渡す上限時間
/// （兄弟ファイル `concurrent_write.rs` / `rename_truncate.rs` と同じ 20 秒。
/// REPAIR-5）。
fn join_deadline() -> Duration {
    Duration::from_secs(20)
}

fn writeback_timeouts() -> WritebackTimeouts {
    WritebackTimeouts {
        recv: timeout(),
        send: timeout(),
    }
}

/// `path` に新規ファイルを作り（既存があれば切り詰め）、末尾へ位置合わせした
/// [`AppendFileSink`] を返す（`rename_truncate.rs` の `create_sink` と同じ方針）。
fn create_sink(path: &Path) -> AppendFileSink {
    let file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)
        .expect("must be able to create the test output file");
    AppendFileSink::new(file).expect("seek to end must succeed on a freshly created file")
}

/// 既存の `path` を書き込みモード（切り詰めなし）で開き、末尾へ位置合わせした
/// [`AppendFileSink`] を返す（前セッションが閉じた（close 済み）ファイルの末尾
/// から追記を再開するケースで使う）。
fn reopen_sink(path: &Path) -> AppendFileSink {
    std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .map(|file| AppendFileSink::new(file).expect("seek to end must succeed on reopen"))
        .expect("must be able to reopen the existing test output file")
}

/// close の後に、新しいハンドルでファイル全体を読む（close-to-open の
/// 「open」。`std::fs::read` は呼び出しのたびに新しい `File` を開いて読み切って
/// から閉じるため、直前の書き込みハンドルとは独立に「今のディスク上の内容」を
/// 確認できる）。
fn read_fresh(path: &Path) -> Vec<u8> {
    std::fs::read(path).expect("fresh open after close must succeed")
}

/// [`harness::body_for`]（`client` 固定）を `seqs` の範囲で連結した期待
/// バイト列を作る（`rename_truncate.rs` の `records` と同じ方針）。
fn records(client: u16, seqs: std::ops::Range<u32>, body_len: usize) -> Vec<u8> {
    seqs.flat_map(|seq| body_for(client, seq, body_len))
        .collect()
}

/// 1 接続分のライブセッション（[`PipelineClient`] + `serve_connection` を
/// 動かすサーバースレッド）を保持する。[`Self::write_and_ack`] で ACK 済みの
/// 静止点を作り、[`Self::send_writes`]（ACK を待たない）で未 ACK の端数
/// （`unacked`）を積み、3 種類の閉じ方
/// （[`Self::shutdown_with_flush`]・[`Self::shutdown_clean`]・[`Self::abort`]）
/// のいずれかでセッションを終える。
struct Session {
    client: PipelineClient<DuplexEnd, NoopSendObserver>,
    server: std::thread::JoinHandle<WritebackReport>,
    /// 送信済みだが ACK をまだ受け取っていないフレーム数。
    unacked: usize,
}

impl Session {
    /// `sink` を使うサーバーをスレッドで起動し、対応するクライアントを持つ
    /// セッションを作る。`in_flight` には「このセッションで送る write の総数 +
    /// 1」以上を渡すこと（`send(Flush, ..)` も [`fandhe_container_io::client::SendQueue`]
    /// に登録されるため）。
    fn start(sink: AppendFileSink, config: BatchConfig, in_flight: usize) -> Self {
        let (client_end, server_end) = harness::duplex();
        let server = spawn_server(server_end, config, sink, writeback_timeouts());
        let client = PipelineClient::new(
            client_end,
            InFlightLimit::new(in_flight).expect("valid in-flight limit"),
            NoopSendObserver,
        );
        Self {
            client,
            server,
            unacked: 0,
        }
    }

    /// `bodies` を送信し、対応する ACK をすべて受け取るまで待つ（静止点。
    /// この呼び出しが戻った時点でファイル状態が確定する。`writeback.rs` D3）。
    fn write_and_ack(&mut self, bodies: &[Vec<u8>]) {
        send_all_writes(&mut self.client, bodies, timeout());
        drain_acks(&mut self.client, bodies.len(), timeout());
    }

    /// `bodies` を送信するが ACK は待たず、`unacked` へ加算する（非グレース
    /// フルな切断・部分 ACK 後の abort（G3）や、Flush で一括確定するケース
    /// （G1・G2・G4）で使う）。
    fn send_writes(&mut self, bodies: &[Vec<u8>]) {
        send_all_writes(&mut self.client, bodies, timeout());
        self.unacked += bodies.len();
    }

    /// `count` 件だけ ACK を受け取り、`unacked` から差し引く（G3: 送った
    /// うち一部だけ ACK を受け取ってから abort するケースで使う）。
    fn drain_some_acks(&mut self, count: usize) {
        drain_acks(&mut self.client, count, timeout());
        self.unacked = self
            .unacked
            .checked_sub(count)
            .expect("drain_some_acks: count must not exceed the outstanding unacked frames");
    }

    /// `Flush` を送り、`unacked` 件の Write ACK だけを受け取ってからクライアント
    /// を drop し、サーバーの終了を待つ（グレースフルシャットダウン (a)。D4 の
    /// とおり FlushAck は来ない — #824〔TASK-15.2.2〕がマージされ FlushAck が
    /// 実装されたら、ここでの FlushAck 受信と [`assert_flush_terminated`] の
    /// 期待コードだけを直せばよい構造にしてある）。
    fn shutdown_with_flush(mut self) -> WritebackReport {
        self.client
            .send(FrameKind::Flush, &[], timeout())
            .expect("flush send must succeed against an unbounded in-memory transport");
        let unacked = self.unacked;
        drain_acks(&mut self.client, unacked, timeout());
        drop(self.client);
        join_within(self.server, join_deadline())
    }

    /// 未 ACK 分が残っていないことを確認してから切断する（グレースフル
    /// シャットダウン (b)。EOF は `Unavailable`・`discarded_pending_frames == 0`
    /// になる）。
    fn shutdown_clean(self) -> WritebackReport {
        assert_eq!(
            self.unacked, 0,
            "shutdown_clean requires every sent write to be acked first (graceful path (b))"
        );
        drop(self.client);
        join_within(self.server, join_deadline())
    }

    /// 未 ACK 分を残したまま切断する（非グレースフル。D5 の破棄を発生させる
    /// 比較用の経路。G3 でのみ使う）。
    fn abort(self) -> WritebackReport {
        drop(self.client);
        join_within(self.server, join_deadline())
    }
}

/// サーバー側の [`DuplexEnd`] を包み、`recv_frame` が呼ばれるたびにその通算
/// 回数を通知するラッパー（G5 の同期点。`sleep` を使わずに「サーバーがここまでの
/// フレームを取り込み終えた」ことを確認するために使う）。
///
/// `serve_connection` は 1 フレームを `recv_frame` で受け取り、`BatchBuffer` へ
/// 積む・ACK を返すまでを終えてから次の `recv_frame` を呼ぶ。したがって
/// `n + 1` 回目の `recv_frame` 呼び出しの通知は「先頭 `n` フレームの処理完了」
/// を意味する（`send_writes` の mpsc 送信完了ではサーバーの取り込みを保証
/// できない。codex レビュー #82 PRRT_kwDOUq78ts6m6sCi・PRRT_kwDOUq78ts6m60UW
/// 指摘への対応。REPAIR-12）。
struct RecvCountingEnd {
    inner: DuplexEnd,
    calls: u64,
    notify: mpsc::Sender<u64>,
}

impl FrameSender for RecvCountingEnd {
    type Frame = Frame;

    fn send_frame(&mut self, frame: &Frame, timeout: IoTimeout) -> Result<(), IoError> {
        self.inner.send_frame(frame, timeout)
    }
}

impl FrameReceiver for RecvCountingEnd {
    type Frame = Frame;

    fn recv_frame(&mut self, timeout: IoTimeout) -> Result<Frame, IoError> {
        self.calls += 1;
        // 受信側（テスト）が既に drop されていても、サーバーの動作は変えない。
        let _ = self.notify.send(self.calls);
        self.inner.recv_frame(timeout)
    }
}

/// [`Session::start`] と同じだが、サーバーの `recv_frame` 呼び出し回数を通知する
/// チャネルも返す（[`wait_until_server_handled`] で同期点として使う）。
fn start_observed_session(
    sink: AppendFileSink,
    config: BatchConfig,
    in_flight: usize,
) -> (Session, mpsc::Receiver<u64>) {
    let (client_end, server_end) = harness::duplex();
    let (notify, calls) = mpsc::channel();
    let server = std::thread::spawn(move || {
        let mut conn = RecvCountingEnd {
            inner: server_end,
            calls: 0,
            notify,
        };
        let mut sink = sink;
        serve_connection(&mut conn, config, &mut sink, writeback_timeouts())
    });
    let client = PipelineClient::new(
        client_end,
        InFlightLimit::new(in_flight).expect("valid in-flight limit"),
        NoopSendObserver,
    );
    (
        Session {
            client,
            server,
            unacked: 0,
        },
        calls,
    )
}

/// サーバーが先頭 `handled` フレームの処理を終えるまで（= `handled + 1` 回目の
/// `recv_frame` 呼び出しの通知が来るまで）期限付きで待つ。期限切れは panic
/// （REPAIR-5）。
fn wait_until_server_handled(calls: &mpsc::Receiver<u64>, handled: u64) {
    let deadline = std::time::Instant::now() + join_deadline();
    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        let n = calls
            .recv_timeout(remaining)
            .expect("server must reach the next recv_frame within the deadline");
        if n > handled {
            return;
        }
    }
}

/// [`Session::shutdown_with_flush`] が返した [`WritebackReport`] の終了コードが
/// 期待値（現状 `Unimplemented`）であることを確認する（この 1 か所に集約する
/// ことで、#824〔TASK-15.2.2〕マージ後の追随を最小にする。`writeback.rs`
/// モジュール doc「FLUSH フレームの扱い（D4）」参照）。
fn assert_flush_terminated(report: &WritebackReport) {
    assert_eq!(
        report.end.code(),
        IoErrorCode::Unimplemented,
        "flush-terminated sessions must currently end with Unimplemented (D4; \
         FlushAck return is TASK-15.2.2 / #824)"
    );
}

/// IO-4・REPAIR-6・TASK-14.3（G1）: 同じファイルへ続けて開く 3 つのセッション
/// （Flush 終了 → clean 切断 → Flush 終了）で、境界ごとに close-to-open を
/// 確認する。各境界で fresh read がその時点までの全レコードと完全一致し、
/// ファイル長も累積 `bytes_written` と一致することを確認する。
#[test]
fn io4_graceful_shutdown_successive_sessions_close_to_open_at_each_boundary() {
    const BODY_LEN: usize = 16;
    const BATCH_SIZE: usize = 4;
    let config = BatchConfig::new(BATCH_SIZE).expect("valid batch size");

    let dir = TempDir::new("graceful-shutdown-successive-sessions");
    let path = dir.file_path("data.bin");

    // S1: 5 件 + Flush で閉じる。
    let bodies1: Vec<Vec<u8>> = (0..5u32).map(|seq| body_for(0, seq, BODY_LEN)).collect();
    let mut session1 = Session::start(create_sink(&path), config, bodies1.len() + 1);
    session1.send_writes(&bodies1);
    let report1 = session1.shutdown_with_flush();
    assert_flush_terminated(&report1);
    assert_eq!(report1.stats.acks_sent, 5);
    assert_eq!(report1.stats.batches_written, 2);
    assert_eq!(report1.stats.discarded_pending_frames, 0);

    let after1 = read_fresh(&path);
    assert_eq!(after1, records(0, 0..5, BODY_LEN));
    assert_eq!(
        std::fs::metadata(&path).expect("metadata").len(),
        report1.stats.bytes_written
    );

    // S2: 8 件を全 ACK してから clean 切断する（グレースフル (b)）。
    let bodies2: Vec<Vec<u8>> = (0..8u32)
        .map(|seq| body_for(0, 5 + seq, BODY_LEN))
        .collect();
    let mut session2 = Session::start(reopen_sink(&path), config, bodies2.len() + 1);
    session2.write_and_ack(&bodies2);
    let report2 = session2.shutdown_clean();
    assert_eq!(report2.end.code(), IoErrorCode::Unavailable);
    assert_eq!(report2.stats.acks_sent, 8);
    assert_eq!(report2.stats.discarded_pending_frames, 0);

    let after2 = read_fresh(&path);
    assert_eq!(after2, records(0, 0..13, BODY_LEN));
    assert_eq!(
        std::fs::metadata(&path).expect("metadata").len(),
        u64::from(13u32) * BODY_LEN as u64
    );

    // S3: 3 件 + Flush で閉じる。
    let bodies3: Vec<Vec<u8>> = (0..3u32)
        .map(|seq| body_for(0, 13 + seq, BODY_LEN))
        .collect();
    let mut session3 = Session::start(reopen_sink(&path), config, bodies3.len() + 1);
    session3.send_writes(&bodies3);
    let report3 = session3.shutdown_with_flush();
    assert_flush_terminated(&report3);
    assert_eq!(report3.stats.acks_sent, 3);

    let after3 = read_fresh(&path);
    assert_eq!(after3, records(0, 0..16, BODY_LEN));
    assert_eq!(
        std::fs::metadata(&path).expect("metadata").len(),
        u64::from(16u32) * BODY_LEN as u64
    );
}

/// IO-4・REPAIR-6・TASK-14.3（G2）: `batch_size` の倍数だけ送ってから Flush する
/// （`take_pending` が `None` を返す分岐。既存にない「残りのない Flush」の
/// close-to-open 確認）。
#[test]
fn io4_graceful_shutdown_flush_with_empty_pending_closes_cleanly() {
    const BODY_LEN: usize = 16;
    const BATCH_SIZE: usize = 4;
    const N: u32 = 8;
    let config = BatchConfig::new(BATCH_SIZE).expect("valid batch size");

    let dir = TempDir::new("graceful-shutdown-flush-empty-pending");
    let path = dir.file_path("data.bin");

    let bodies: Vec<Vec<u8>> = (0..N).map(|seq| body_for(0, seq, BODY_LEN)).collect();
    let mut session = Session::start(create_sink(&path), config, bodies.len() + 1);
    session.send_writes(&bodies);
    let report = session.shutdown_with_flush();

    assert_flush_terminated(&report);
    assert_eq!(report.stats.frames_received, u64::from(N) + 1);
    assert_eq!(report.stats.batches_written, 2);
    assert_eq!(report.stats.acks_sent, u64::from(N));
    assert_eq!(report.stats.discarded_pending_frames, 0);

    let actual = read_fresh(&path);
    let expected = records(0, 0..N, BODY_LEN);
    assert_eq!(actual, expected);
    assert_eq!(
        std::fs::metadata(&path).expect("metadata").len(),
        u64::from(N) * BODY_LEN as u64
    );
}

/// IO-4・REPAIR-6・TASK-14.3（G3。D5 の直接確認）: 非グレースフルな切断
/// （未 ACK 分の破棄）の後、破棄された分を再送して Flush で閉じても、各
/// レコードが重複も欠落もなくちょうど 1 回だけ現れることを確認する。
#[test]
fn io4_graceful_shutdown_resend_after_abort_yields_each_record_exactly_once() {
    const BODY_LEN: usize = 16;
    const BATCH_SIZE: usize = 4;
    let config = BatchConfig::new(BATCH_SIZE).expect("valid batch size");

    let dir = TempDir::new("graceful-shutdown-resend-after-abort");
    let path = dir.file_path("data.bin");

    // S1: 7 件送り、最初のバッチ（4 件）分の ACK だけ受け取って非グレースフル
    // に abort する。残り 3 件（seq 4..7）は書き込まれずに破棄される（D5）。
    let bodies1: Vec<Vec<u8>> = (0..7u32).map(|seq| body_for(0, seq, BODY_LEN)).collect();
    let mut session1 = Session::start(create_sink(&path), config, bodies1.len() + 1);
    session1.send_writes(&bodies1);
    session1.drain_some_acks(4);
    let report1 = session1.abort();

    assert_eq!(report1.end.code(), IoErrorCode::Unavailable);
    assert_eq!(report1.stats.acks_sent, 4);
    assert_eq!(report1.stats.discarded_pending_frames, 3);

    let after1 = read_fresh(&path);
    assert_eq!(
        after1,
        records(0, 0..4, BODY_LEN),
        "abort must leave exactly the acked prefix, no partial trailing record"
    );

    // S2: 破棄された seq 4..7 を再送し、続けて新規の seq 7..9 を送って Flush で
    // 閉じる。
    let bodies2: Vec<Vec<u8>> = (4..9u32).map(|seq| body_for(0, seq, BODY_LEN)).collect();
    let mut session2 = Session::start(reopen_sink(&path), config, bodies2.len() + 1);
    session2.send_writes(&bodies2);
    let report2 = session2.shutdown_with_flush();

    assert_flush_terminated(&report2);
    assert_eq!(report2.stats.acks_sent, 5);

    let final_bytes = read_fresh(&path);
    assert_eq!(
        final_bytes,
        records(0, 0..9, BODY_LEN),
        "resend after abort must produce each record exactly once, in order"
    );
    let decomposed = decompose_records(&final_bytes);
    let seqs: Vec<u32> = decomposed.iter().map(|r| record_seq(r)).collect();
    assert_eq!(
        seqs,
        (0..9u32).collect::<Vec<_>>(),
        "each seq 0..9 must appear exactly once, in ascending order"
    );
}

/// IO-4・REPAIR-6・TASK-14.3（G4）: [`harness::SharedSink`] を共有する 4
/// クライアントが、それぞれ異なる端数の write を送ってから同時に Flush で
/// 閉じる。全サーバースレッドの join・テストが保持する元の [`SharedSink`] の
/// drop（= 最後の `Arc` 参照の解放）の後に fresh open し、総件数・クライアント
/// ごとの昇順・バイト内容の完全一致を確認する。
#[test]
fn io4_graceful_shutdown_shared_file_all_clients_flush_concurrently() {
    const BODY_LEN: usize = 16;
    const BATCH_SIZE: usize = 4;
    const CLIENT_COUNTS: [u32; 4] = [5, 6, 7, 8];
    let config = BatchConfig::new(BATCH_SIZE).expect("valid batch size");

    let dir = TempDir::new("graceful-shutdown-shared-flush");
    let path = dir.file_path("shared.bin");

    let shared = SharedSink::new(create_sink(&path));
    let barrier = Arc::new(Barrier::new(CLIENT_COUNTS.len() + 1));
    // 全クライアントが write 送信を終えた時点で揃える 2 つ目の同期点。
    // これがないと 1 接続が Flush まで完走してから次の接続が始まり得て、
    // Flush の並行実行（狙った競合）を通らずに成功する（REPAIR-12）。
    let pre_flush_barrier = Arc::new(Barrier::new(CLIENT_COUNTS.len() + 1));

    let mut server_handles = Vec::new();
    let mut client_handles = Vec::new();
    for (i, &n) in CLIENT_COUNTS.iter().enumerate() {
        let (client_end, server_end) = harness::duplex();
        server_handles.push(spawn_server(
            server_end,
            config,
            shared.clone(),
            writeback_timeouts(),
        ));

        let barrier = Arc::clone(&barrier);
        let pre_flush_barrier = Arc::clone(&pre_flush_barrier);
        let client_id = i as u16;
        client_handles.push(std::thread::spawn(move || {
            let mut client = PipelineClient::new(
                client_end,
                InFlightLimit::new(n as usize + 1).expect("valid in-flight limit"),
                NoopSendObserver,
            );
            barrier_wait_within(&barrier, join_deadline());

            let bodies: Vec<Vec<u8>> = (0..n)
                .map(|seq| body_for(client_id, seq, BODY_LEN))
                .collect();
            send_all_writes(&mut client, &bodies, timeout());
            // 全クライアントの write 送信完了を待ってから Flush を送る。
            barrier_wait_within(&pre_flush_barrier, join_deadline());
            client
                .send(FrameKind::Flush, &[], timeout())
                .expect("flush send must succeed against an unbounded in-memory transport");
            drain_acks(&mut client, bodies.len(), timeout());
            drop(client);
        }));
    }
    barrier_wait_within(&barrier, join_deadline());
    barrier_wait_within(&pre_flush_barrier, join_deadline());

    for handle in client_handles {
        join_within(handle, join_deadline());
    }
    let reports: Vec<WritebackReport> = server_handles
        .into_iter()
        .map(|handle| join_within(handle, join_deadline()))
        .collect();

    // 各サーバースレッド内の `SharedSink` clone は、上の join でスレッドが
    // 終わった時点で既に drop されている。テストが持つ元の `shared` を
    // ここで drop することで、最後の `Arc` 参照を解放し close を成立させる
    // （モジュール doc「close」の定義参照）。
    drop(shared);

    let total: u32 = CLIENT_COUNTS.iter().sum();
    for (i, report) in reports.iter().enumerate() {
        assert_flush_terminated(report);
        assert_eq!(report.stats.discarded_pending_frames, 0, "client {i}");
        assert_eq!(
            report.stats.acks_sent,
            u64::from(CLIENT_COUNTS[i]),
            "client {i}"
        );
    }

    let contents = read_fresh(&path);
    let decomposed = decompose_records(&contents);
    assert_eq!(decomposed.len(), total as usize);

    let mut seen_by_client: [Vec<u32>; 4] = Default::default();
    for record in &decomposed {
        let client_id = record_client(record);
        let seq = record_seq(record);
        let expected = body_for(client_id, seq, BODY_LEN);
        assert_eq!(
            record, &expected,
            "record bytes must exactly match body_for(client={client_id}, seq={seq})"
        );
        let bucket = seen_by_client
            .get_mut(client_id as usize)
            .expect("client id must be within CLIENT_COUNTS range");
        bucket.push(seq);
    }
    for (i, &n) in CLIENT_COUNTS.iter().enumerate() {
        let expected_seqs: Vec<u32> = (0..n).collect();
        assert_eq!(
            seen_by_client[i], expected_seqs,
            "client {i}'s records must appear in ascending seq order 0..{n}"
        );
    }
    assert_eq!(
        std::fs::metadata(&path).expect("metadata").len(),
        u64::from(total) * BODY_LEN as u64
    );
}

/// IO-4・REPAIR-6・TASK-14.3（G5）: 別ファイルの 2 セッション（A・B）で、B に
/// 未 ACK の端数を残したまま A が Flush で閉じても B の内容・保留分には影響
/// せず、B を fresh open した結果も A の close 前後で変化しないことを確認する
/// （close の独立性）。
#[test]
fn io4_graceful_shutdown_one_connection_closed_while_other_stays_live() {
    const BODY_LEN: usize = 16;
    const BATCH_SIZE: usize = 4;
    let config = BatchConfig::new(BATCH_SIZE).expect("valid batch size");

    let dir = TempDir::new("graceful-shutdown-independent-close");
    let a_path = dir.file_path("a.bin");
    let b_path = dir.file_path("b.bin");

    // B をまず 4 件 ACK 済みまで進めて静止点を作る（write_and_ack が戻った
    // 時点でファイル状態が確定する。Session::write_and_ack のコメント参照）。
    // その後さらに 2 件を ACK を待たずに送り、B に未 ACK の端数
    // （`unacked`）を残したまま A の close を迎えさせる（codex レビュー #82
    // PRRT_kwDOUq78ts6m6iBl 指摘への対応。B が全件 ACK 済みで保留中の書き込み
    // が無い状態だと、A の close が B の未 ACK 分に干渉する回帰
    // （誤って書き込む・破棄する等）を検出できないため）。
    let bodies_b1: Vec<Vec<u8>> = (0..4u32).map(|seq| body_for(1, seq, BODY_LEN)).collect();
    let (mut session_b, b_recv_calls) = start_observed_session(create_sink(&b_path), config, 10);
    session_b.write_and_ack(&bodies_b1);

    let bodies_b_pending: Vec<Vec<u8>> = (0..2u32)
        .map(|seq| body_for(1, 4 + seq, BODY_LEN))
        .collect();
    session_b.send_writes(&bodies_b_pending);

    // 同期点: B のサーバーが保留 2 件を含む先頭 6 フレーム（ACK 済み 4 + 保留
    // 2）を取り込み終える（7 回目の recv_frame に入る）まで待つ。`send_writes`
    // は mpsc への送信完了しか保証しないため、この待ち合わせが無いと A の
    // close 時点で B の保留分が未取り込みのままになり得る。
    wait_until_server_handled(
        &b_recv_calls,
        (bodies_b1.len() + bodies_b_pending.len()) as u64,
    );

    // B の session はまだ live（close していない）。未 ACK の 2 件を抱えた
    // 状態で fresh open した内容を基準値として確保しておく（BATCH_SIZE 未満
    // のためまだディスクへ書き出されておらず、ACK 済みの 4 件のみが見える
    // はず）。A の close が B に影響しないことを、後続の「A close 直後」の
    // 再読み取りと突き合わせて確認するための対照点。
    let b_before_a_closed = read_fresh(&b_path);
    assert_eq!(b_before_a_closed, records(1, 0..4, BODY_LEN));

    // A は 6 件 + Flush で閉じる。B には一切触れていない。
    let bodies_a: Vec<Vec<u8>> = (0..6u32).map(|seq| body_for(0, seq, BODY_LEN)).collect();
    let mut session_a = Session::start(create_sink(&a_path), config, bodies_a.len() + 1);
    session_a.send_writes(&bodies_a);
    let report_a = session_a.shutdown_with_flush();
    assert_flush_terminated(&report_a);
    assert_eq!(report_a.stats.acks_sent, 6);

    // B はまだ開いている状態で、A を fresh open して独立性を確認する。
    let a_after_a_closed = read_fresh(&a_path);
    assert_eq!(a_after_a_closed, records(0, 0..6, BODY_LEN));

    // A の close 直後、B へまだ追加の書き込み・close を一切行っていない時点で
    // B を fresh open し、A の close 前に取った基準値と比較する。B 自身の
    // 追加書き込み・close が起きる前に比較することで、A の close が B の
    // 未 close・未 ACK 状態（一時的な変化・誤った書き込みを含む）に影響しない
    // ことを検出できる。
    let b_after_a_closed = read_fresh(&b_path);
    assert_eq!(
        b_after_a_closed, b_before_a_closed,
        "closing A must not affect B's not-yet-closed content"
    );

    // B へさらに 3 件を追加して Flush で閉じる（先の未 ACK 2 件と合わせて
    // 4 + 2 + 3 = 9 件）。A の close 前後で保留にしていた 2 件を含め、
    // discarded_pending_frames == 0・acks_sent == 9 まで正常に完了することを
    // 確認し、A の close が B の保留分を破棄していないことも検証する。
    let bodies_b2: Vec<Vec<u8>> = (0..3u32)
        .map(|seq| body_for(1, 6 + seq, BODY_LEN))
        .collect();
    session_b.send_writes(&bodies_b2);
    let report_b = session_b.shutdown_with_flush();
    assert_flush_terminated(&report_b);
    assert_eq!(report_b.stats.acks_sent, 9);
    assert_eq!(report_b.stats.discarded_pending_frames, 0);

    // A を再度 fresh open し、B の close 後も変化していないことを確認する。
    let a_after_b_closed = read_fresh(&a_path);
    assert_eq!(
        a_after_b_closed, a_after_a_closed,
        "closing B must not affect A's already-closed content"
    );

    let b_final = read_fresh(&b_path);
    assert_eq!(b_final, records(1, 0..9, BODY_LEN));
}
