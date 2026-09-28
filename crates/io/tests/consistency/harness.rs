//! 整合性テストスイート（[`super`]。TASK-14・IO-4・REPAIR-6）の共通ハーネス。
//!
//! [`concurrent_write`](super::concurrent_write) をはじめ、兄弟 sub-issue
//! （#81 の rename/truncate・#82 の close-to-open）が同じ入口
//! （`tests/consistency.rs`）から再利用できる形で、次の部品を提供する。
//!
//! - [`DuplexEnd`]: `std::sync::mpsc` によるメモリ内の二方向トランスポート
//!   （3 OS で動く。[`fandhe_container_io::FrameSender`] /
//!   [`fandhe_container_io::FrameReceiver`] を実装する）
//! - [`TempDir`]: テストごとに一意な一時ディレクトリ（`Drop` で削除）
//! - [`body_for`]: 決定的な合成 body（自己記述ヘッダつき）を作る
//! - [`decompose_records`]: 複数クライアントが 1 ファイルを共有した場合に、
//!   [`body_for`] のヘッダを使ってレコード単位へ分解する
//! - [`SharedSink`]: 複数接続から 1 つの [`fandhe_container_io::AppendFileSink`]
//!   を直列化して共有する [`fandhe_container_io::BatchSink`] 実装
//! - [`spawn_server`] / [`join_within`]: `serve_connection` を別スレッドで
//!   動かし、期限付きで合流する（REPAIR-5）
//! - [`barrier_wait_within`]: `std::sync::Barrier::wait` を期限付きで待つ
//!   （REPAIR-5）

use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Barrier, Mutex};
use std::time::Duration;

use fandhe_container_io::{
    AppendFileSink, Batch, BatchSink, Frame, FrameReceiver, FrameSender, IoError, IoErrorCode,
    IoTimeout, SinkWriteReport,
};

/// 相手の応答を待つ処理の既定タイムアウト（REPAIR-5。既存の結合試験
/// （`tests/writeback.rs`）と同じ 5 秒）。
pub fn timeout() -> IoTimeout {
    IoTimeout::new(Duration::from_secs(5)).expect("5s must be a valid IoTimeout")
}

/// [`DuplexEnd::recv_frame`] が Err を返した後、接続を「poison 済み」として
/// 扱うためのエラー（P1-3。`crate::transport` モジュールの契約と同じ意味論）。
fn unavailable(message: &'static str) -> IoError {
    IoError::new(IoErrorCode::Unavailable, message)
}

/// `std::sync::mpsc` による二方向トランスポート（TASK-14.1・IO-4。3 OS で
/// 動くメモリ内の [`FrameSender`] + [`FrameReceiver`] 実装）。
///
/// [`fandhe_container_io::UdsServer`] は Linux / macOS 限定のため、並行 write
/// の主ケースはこの型で構成する（`tests/consistency.rs` モジュール doc「実行
/// する OS の方針」参照）。[`duplex`] が返すペアは互いの送信先・受信元が
/// 入れ替わった対称な 2 つの端点で、一方をクライアント役・他方をサーバー役
/// （[`spawn_server`] へ渡す）として別スレッドへ渡す想定。
///
/// # poison 契約（P1-3・REPAIR-5・REPAIR-6）
/// [`FrameSender::send_frame`] / [`FrameReceiver::recv_frame`] のいずれかが
/// 一度でも `Err` を返すと、以後は両メソッドとも下位のチャネルに触れず
/// [`IoErrorCode::Unavailable`] を返し続ける（`crate::transport` モジュールの
/// 契約と同じ）。[`mpsc::Receiver::recv_timeout`] のタイムアウトも
/// [`IoErrorCode::Timeout`] として一度返した後は poison する（無期限の
/// ポーリング再試行を許さない）。
pub struct DuplexEnd {
    tx: mpsc::Sender<Frame>,
    rx: mpsc::Receiver<Frame>,
    poisoned: bool,
}

/// 対称な [`DuplexEnd`] のペアを作る（`a` の送信は `b` の受信へ、`b` の送信は
/// `a` の受信へ届く）。
pub fn duplex() -> (DuplexEnd, DuplexEnd) {
    let (tx_a, rx_a) = mpsc::channel();
    let (tx_b, rx_b) = mpsc::channel();
    (
        DuplexEnd {
            tx: tx_a,
            rx: rx_b,
            poisoned: false,
        },
        DuplexEnd {
            tx: tx_b,
            rx: rx_a,
            poisoned: false,
        },
    )
}

impl FrameSender for DuplexEnd {
    type Frame = Frame;

    fn send_frame(&mut self, frame: &Frame, _timeout: IoTimeout) -> Result<(), IoError> {
        if self.poisoned {
            return Err(unavailable(
                "duplex end is poisoned by a previous error and must be reconnected",
            ));
        }
        match self.tx.send(frame.clone()) {
            Ok(()) => Ok(()),
            Err(_) => {
                self.poisoned = true;
                Err(unavailable("duplex peer has disconnected"))
            }
        }
    }
}

impl FrameReceiver for DuplexEnd {
    type Frame = Frame;

    fn recv_frame(&mut self, timeout: IoTimeout) -> Result<Frame, IoError> {
        if self.poisoned {
            return Err(unavailable(
                "duplex end is poisoned by a previous error and must be reconnected",
            ));
        }
        match self.rx.recv_timeout(timeout.as_duration()) {
            Ok(frame) => Ok(frame),
            Err(mpsc::RecvTimeoutError::Timeout) => {
                self.poisoned = true;
                Err(IoError::new(IoErrorCode::Timeout, "duplex recv timed out"))
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                self.poisoned = true;
                Err(unavailable("duplex peer has disconnected"))
            }
        }
    }
}

/// テストごとに一意な一時ディレクトリ（`Drop` で再帰削除。`tests/writeback.rs`
/// の `TempSocketDir` と同じ方針）。
pub struct TempDir {
    path: PathBuf,
}

impl TempDir {
    /// `tag`（テスト名相当の短い識別子）・pid・連番からディレクトリを作る。
    pub fn new(tag: &str) -> Self {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        let dir = std::env::temp_dir().join(format!("fcio-consistency-{tag}-{pid}-{n}"));
        std::fs::create_dir_all(&dir).expect("must be able to create a temp dir for test output");
        Self { path: dir }
    }

    /// `name` をこのディレクトリの下のパスへ解決する（`Path::join` で組み立て、
    /// 文字列連結はしない。coding-rust「クロスプラットフォーム」節）。
    pub fn file_path(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// [`body_for`] が組み立てる自己記述ヘッダのバイト数
/// （`client: u16 LE` + `seq: u32 LE` + `len: u32 LE`）。
pub const BODY_HEADER_LEN: usize = 2 + 4 + 4;

/// 決定的な合成 body を作る（[`concurrent_write`](super::concurrent_write) の
/// 期待値生成と、[`decompose_records`] によるレコード分解の両方が使う）。
///
/// 先頭 [`BODY_HEADER_LEN`] バイトに `client`・`seq`・`len` 自身を LE で
/// 埋め込み、残りを `(client * 31 + seq + i) as u8` の決定的パターンで
/// 埋める。`len` は [`BODY_HEADER_LEN`] 以上でなければならない。
pub fn body_for(client: u16, seq: u32, len: usize) -> Vec<u8> {
    assert!(
        len >= BODY_HEADER_LEN,
        "body_for: len ({len}) must be at least BODY_HEADER_LEN ({BODY_HEADER_LEN})"
    );
    let len_u32 = u32::try_from(len).expect("body_for: len must fit in u32 for test fixtures");
    let mut body = Vec::with_capacity(len);
    body.extend_from_slice(&client.to_le_bytes());
    body.extend_from_slice(&seq.to_le_bytes());
    body.extend_from_slice(&len_u32.to_le_bytes());
    for i in 0..(len - BODY_HEADER_LEN) {
        let filler = (u32::from(client))
            .wrapping_mul(31)
            .wrapping_add(seq)
            .wrapping_add(i as u32);
        body.push(filler as u8);
    }
    body
}

/// [`body_for`] で作ったレコードが連結されたバイト列を、レコード単位へ
/// 分解する（複数クライアントが 1 ファイル（[`SharedSink`]）を共有した場合の
/// 検証に使う）。各レコードの先頭 [`BODY_HEADER_LEN`] バイトの `len`
/// フィールドを読み、その長さぶんを 1 レコードとして切り出す。
///
/// `data` はテストが自ら書き込ませた出力ファイルの内容であり untrusted な
/// 外部入力ではないが、レコード境界の不整合（実装バグによる破損）を
/// 添字パニックではなく分かりやすいメッセージで検出できるよう `get(..)` で
/// 読む（coding-rust「外部入力の経路」の作法をここでも踏襲する）。
pub fn decompose_records(data: &[u8]) -> Vec<Vec<u8>> {
    let mut records = Vec::new();
    let mut rest = data;
    while !rest.is_empty() {
        let header = rest.get(..BODY_HEADER_LEN).unwrap_or_else(|| {
            panic!(
                "decompose_records: {} byte(s) remain, shorter than a record header \
                 ({BODY_HEADER_LEN} bytes) — output is corrupted or truncated",
                rest.len()
            )
        });
        let len_bytes: [u8; 4] = header[6..10]
            .try_into()
            .expect("header slice is exactly 4 bytes");
        let len = u32::from_le_bytes(len_bytes) as usize;
        // `len` はヘッダ自身を含む値であり、`BODY_HEADER_LEN` 未満だと
        // `rest.get(..len)` が空スライス（`len == 0`）や不完全なヘッダを
        // 誤って 1 レコードとして受理し、`rest` が一切縮まないまま次周の
        // `while !rest.is_empty()` に戻って無限ループする（データ破損を
        // ハングとして見逃す。REPAIR-5 違反）。ここで即座に失敗させる。
        assert!(
            len >= BODY_HEADER_LEN,
            "decompose_records: declared record length {len} is shorter than a record header \
             ({BODY_HEADER_LEN} bytes) — output is corrupted or truncated"
        );
        let record = rest.get(..len).unwrap_or_else(|| {
            panic!(
                "decompose_records: declared record length {len} exceeds the {} byte(s) \
                 remaining — output is corrupted or truncated",
                rest.len()
            )
        });
        records.push(record.to_vec());
        rest = &rest[len..];
    }
    records
}

/// [`decompose_records`] が返すレコードから `client` フィールドを読む。
pub fn record_client(record: &[u8]) -> u16 {
    let bytes: [u8; 2] = record
        .get(0..2)
        .and_then(|s| s.try_into().ok())
        .expect("record must have at least a 2-byte client field");
    u16::from_le_bytes(bytes)
}

/// [`decompose_records`] が返すレコードから `seq` フィールドを読む。
pub fn record_seq(record: &[u8]) -> u32 {
    let bytes: [u8; 4] = record
        .get(2..6)
        .and_then(|s| s.try_into().ok())
        .expect("record must have at least a 4-byte seq field at offset 2");
    u32::from_le_bytes(bytes)
}

/// 複数の [`fandhe_container_io::writeback::serve_connection`] 呼び出し
/// （＝複数の並行接続）から 1 つの [`AppendFileSink`] を直列化して共有する
/// [`BatchSink`] 実装（TASK-14.1・IO-4）。
///
/// `write_batch` はロックを取った上で内側の [`AppendFileSink::write_batch`]
/// に委譲するだけで、OS の `O_APPEND` の原子性（3 OS 間で差がある）に頼らず
/// バッチ単位の直列化で「同じファイルへの並行書き込みでもレコードが交錯しない
/// こと」を保証する。`Clone` は内部の `Arc` を複製するだけで、複製後もすべて
/// 同じ [`AppendFileSink`]（＝同じ出力ファイル）を指す。
#[derive(Clone)]
pub struct SharedSink {
    inner: Arc<Mutex<AppendFileSink>>,
}

impl SharedSink {
    /// 既に末尾へ位置合わせ済みの [`AppendFileSink`] から作る。
    pub fn new(sink: AppendFileSink) -> Self {
        Self {
            inner: Arc::new(Mutex::new(sink)),
        }
    }
}

impl BatchSink for SharedSink {
    fn write_batch(&mut self, batch: &Batch) -> Result<SinkWriteReport, IoError> {
        // テストのみで使う型のため、他スレッドの panic によるロック汚染は
        // `expect` で即座に検出する（本番コードの `sys`/外部入力経路には
        // 置かない。coding-rust「ライブラリコードでは panic させない」は
        // 本番コードに対する規約であり、本ファイルはテストハーネス）。
        let mut guard = self
            .inner
            .lock()
            .expect("SharedSink mutex must not be poisoned during a test run");
        guard.write_batch(batch)
    }
}

/// `serve_connection` を別スレッドで動かす（呼び出し元がバッチ集約設定・
/// sink・タイムアウトを渡し、そのまま
/// [`fandhe_container_io::writeback::serve_connection`] へ委譲する）。
pub fn spawn_server<W>(
    mut conn: DuplexEnd,
    config: fandhe_container_io::BatchConfig,
    mut sink: W,
    timeouts: fandhe_container_io::WritebackTimeouts,
) -> std::thread::JoinHandle<fandhe_container_io::WritebackReport>
where
    W: BatchSink + Send + 'static,
{
    std::thread::spawn(move || {
        fandhe_container_io::serve_connection(&mut conn, config, &mut sink, timeouts)
    })
}

/// [`std::thread::JoinHandle::join`] を無期限に待たず、`deadline` 以内に
/// 終わらなければ panic する（REPAIR-5: スレッドの join にも期限を設ける。
/// ACK 未送信等の実装バグによるハングを、テストのタイムアウトではなく
/// 明示的なメッセージで検出できるようにする）。
///
/// 監視用の別スレッドを立てて `handle.join()` を行わせ、その結果をチャネル
/// 経由で `recv_timeout` により期限付きで待つ。期限切れの場合、対象スレッドは
/// バックグラウンドに残る（テストプロセス自体は panic で終了するため実害は
/// ない）。
pub fn join_within<T>(handle: std::thread::JoinHandle<T>, deadline: Duration) -> T
where
    T: Send + 'static,
{
    let (tx, rx) = mpsc::channel();
    let _watcher = std::thread::spawn(move || {
        let result = handle.join();
        let _ = tx.send(result);
    });
    match rx.recv_timeout(deadline) {
        Ok(Ok(value)) => value,
        Ok(Err(_)) => panic!("join_within: joined thread panicked"),
        Err(_) => panic!(
            "join_within: thread did not finish within {deadline:?} \
             (REPAIR-5: bounded join — likely an unsent ACK or other hang)"
        ),
    }
}

/// [`std::sync::Barrier::wait`] を無期限に待たず、`deadline` 以内に全参加者が
/// 揃わなければ panic する（REPAIR-5: [`concurrent_write`](super::concurrent_write)
/// の各ケースが開始同期に使う `Barrier` にも期限を設ける。参加予定のクライアント
/// スレッドが `barrier.wait()` へ到達する前に panic 等で脱落すると、残りの
/// 参加者・呼び出し元スレッドは本来なら [`Barrier`] の性質上永久に揃わない）。
///
/// [`join_within`] と同じ構成（監視用の別スレッドへ実際のブロッキング呼び出し
/// `barrier.wait()` を委譲し、呼び出し元は `recv_timeout` で期限付きに待つ）を
/// 取る。`Barrier::wait` はどの OS スレッドから呼んでも参加カウントに数えられる
/// ため、監視スレッド経由でも待ち合わせの意味は変わらない。期限切れの場合、
/// 監視スレッドはバックグラウンドに残る（テストプロセス自体は panic で終了する
/// ため実害はない）。
pub fn barrier_wait_within(barrier: &Arc<Barrier>, deadline: Duration) {
    let barrier = Arc::clone(barrier);
    let (tx, rx) = mpsc::channel();
    let _watcher = std::thread::spawn(move || {
        barrier.wait();
        let _ = tx.send(());
    });
    if rx.recv_timeout(deadline).is_err() {
        panic!(
            "barrier_wait_within: barrier did not release within {deadline:?} \
             (REPAIR-5: bounded barrier wait — a participant likely failed before \
             reaching barrier.wait())"
        );
    }
}

/// クライアント役の [`fandhe_container_io::PipelineClient`] へ、`bodies` を
/// 順に `Write` フレームとして送る（ACK は待たない。`DuplexEnd` の
/// [`mpsc::Sender`] は無制限にバッファできるため、送信側は ACK を待たずに
/// 送り切ってよい。呼び出し元は送信後に [`drain_acks`] で ACK をまとめて
/// 受け取る）。
pub fn send_all_writes(
    client: &mut fandhe_container_io::PipelineClient<
        DuplexEnd,
        fandhe_container_io::NoopSendObserver,
    >,
    bodies: &[Vec<u8>],
    timeout: IoTimeout,
) {
    for body in bodies {
        client
            .send(fandhe_container_io::FrameKind::Write, body, timeout)
            .expect("write send must succeed against an unbounded in-memory transport");
    }
}

/// [`fandhe_container_io::PipelineClient::recv_ack`] を `count` 回呼び、
/// 送信順の ACK をすべて受け取る。
pub fn drain_acks(
    client: &mut fandhe_container_io::PipelineClient<
        DuplexEnd,
        fandhe_container_io::NoopSendObserver,
    >,
    count: usize,
    timeout: IoTimeout,
) {
    for _ in 0..count {
        client
            .recv_ack(timeout)
            .expect("recv_ack must succeed while draining expected acks");
    }
}
