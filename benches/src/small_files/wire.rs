//! 小ファイル多数の files/s を「ワイヤー経路」（UDS 越しの I/O 共有層のフレーム）で測る 1 試行
//! （TASK-189 追補・#2074・IO-1・IO-2・IO-6・REPAIR-5・REPAIR-8。設計は #1886 の F6〜F9）。
//!
//! `small_files::run_trial`（`--route wire`）から呼ばれる。サーバー側の API を直接呼ぶ経路
//! （`small_files::run_trial_server_api`）との差は、フレームの符号化と復号・UDS の往復・
//! ACK の待ちが区間に入ることだけで、計測する仕事（作成 → 固定長の write 1 回 → FLUSH）は同じ。
//!
//! # 構成
//!
//! - server: `UdsServer::bind` した後、スレッドで `accept` し `serve_file_connection_with_limit`
//!   を動かす。作成口は試行ごとの作業ディレクトリ `GuestFileCreator`
//! - client: `UdsClientConnection::connect`（接続先 uid の照合つき）の上の `PipelineClient`
//! - ソケットは `--root` ではなく `std::env::temp_dir()` の下の専用の短いディレクトリ（0700）に置く
//!   （`--root` が深いと `sun_path` の上限を超えるため）
//!
//! # 区間
//!
//! 最初の `create` の送信直前から最後の `FlushAck` の受信まで。client の符号化・UDS の往復・
//! server の復号と実行と応答をすべて含む。接続・サーバーの起動・body の用意・後始末・report の
//! 照合は区間に入れない。
//!
//! # デッドロックしない不変条件
//!
//! server は受信順に同期で実行し、バッチ（[`WIRE_SERVER_BATCH`] フレーム）が埋まるたびと
//! `Flush` でだけ応答を送る。IO-10 と保持表の上限を io crate の最大まで広げ、K を
//! `MAX_MAX_RETAINED_DIRTY_FILES - 1` 以下に絞っているので、`FlushAck` を伴わない自動フラッシュは
//! 起きない（`auto_flushes == 0` を report で照合する）。client は [`WIRE_SERVER_BATCH`] フレームを
//! 送るたびと `Flush` のたびに、その分の応答をすべて受ける。このため未読の応答は常に高々
//! [`WIRE_SERVER_BATCH`] 件で、UDS のバッファに収まる。前提が崩れても `recv_ack` の期限で
//! `timeout` になり、ハングしない（REPAIR-5）。
//!
//! # 既知の限界
//!
//! - 1 回の FLUSH は io crate の上限 `MAX_IO_TIMEOUT`（10 秒）で切れる。遅い媒体で K が大きいと
//!   値を出さずに失敗する
//! - Linux では保持する `Close` 済みファイルが K 個の fd を持つ。`RLIMIT_NOFILE` が K に足りない
//!   と server が失敗し、値を出さずに失敗する
//! - server スレッドは強制停止できない。client の切断後に終わらなければプロセスの終了に任せる
//!
//! 結果の `io2_guaranteed` は every-k で `false`（#1886 の spec 確認事項 (b) の回答待ち）。

use super::{Plan, SmallFilesError, WorkDir, flush_timeout, from_io, guest_path, merge_cleanup};
use fandhe_container_io::{
    AckReceipt, BatchConfig, DEFAULT_BATCH_SIZE, DEFAULT_MAX_OPEN_FILES, FileServeLimits,
    FileServeReport, GuestFileCreator, GuestPath, InFlightLimit, IoTimeout, MAX_IO_TIMEOUT,
    MAX_MAX_RETAINED_DIRTY_FILES, MAX_UNFLUSHED_MAX_BYTES, MAX_UNFLUSHED_MAX_FRAMES, MaxOpenFiles,
    MaxRetainedDirtyFiles, NoopSendObserver, NoopServerObserver, PersistSupport, PipelineClient,
    ReceiveLimits, UdsClientConnection, UdsServer, UdsServerPolicy, UnflushedLimit,
    WritebackTimeouts, persist_support, serve_file_connection_with_limit,
};
use std::path::Path;
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// server のバッチ（応答を返す単位）のフレーム数。`fandhe_container_io::DEFAULT_BATCH_SIZE`。
pub const WIRE_SERVER_BATCH: usize = DEFAULT_BATCH_SIZE;
/// wire 経路で受け付ける `--batch-size`（K）の上限。保持表の上限に達すると明示 Flush の直前に
/// 自動フラッシュが入り、「K ごと」の意味が崩れるため、上限より 1 小さい値までにする。
pub const WIRE_MAX_BATCH_SIZE: u64 = (MAX_MAX_RETAINED_DIRTY_FILES as u64) - 1;
/// `sun_path` に収める社内上限（Linux 108・macOS 104 から終端分を引いた余裕を含む）。
const MAX_SOCKET_PATH_BYTES: usize = 100;

/// wire 経路を動かせる OS か（UDS が使える Linux と macOS）。
pub const fn route_supported() -> bool {
    cfg!(any(target_os = "linux", target_os = "macos"))
}

/// 副作用の前の環境検査（経路の対応 OS と、server の FLUSH が使えるか）。
pub fn check_environment() -> Result<(), SmallFilesError> {
    if !route_supported() {
        return Err(SmallFilesError::new(
            "unsupported-route",
            "the wire route requires UDS (Linux or macOS)",
        ));
    }
    let support = persist_support();
    if !support.is_supported() {
        return Err(SmallFilesError::new(
            "persist-unsupported",
            "persist is not supported on this host",
        ));
    }
    // Linux の server の FLUSH は syncfs（5.8 以上）が前提。満たさなければ Unimplemented になる。
    if cfg!(target_os = "linux") && support != PersistSupport::Supported {
        return Err(SmallFilesError::new(
            "persist-unsupported",
            "the wire route requires syncfs support (Linux 5.8 or later)",
        ));
    }
    Ok(())
}

/// 1 試行（計測区間）を実行して所要時間を返す。ソケットは `std::env::temp_dir()` の下に置く。
pub fn run_trial(
    trial_root: &Path,
    plan: &Plan,
    trial_deadline: Instant,
    overall_deadline: Instant,
) -> Result<Duration, SmallFilesError> {
    run_trial_in(
        &std::env::temp_dir(),
        trial_root,
        plan,
        trial_deadline,
        overall_deadline,
    )
}

/// [`run_trial`] のソケットの親ディレクトリ `socket_parent` を明示する版（試験用）。
pub fn run_trial_in(
    socket_parent: &Path,
    trial_root: &Path,
    plan: &Plan,
    trial_deadline: Instant,
    overall_deadline: Instant,
) -> Result<Duration, SmallFilesError> {
    plan.validate()?;
    check_environment()?;
    let mut sock_dir = WorkDir::create_with_prefix(socket_parent, "fcsf")?;
    let result = run_with_socket_dir(
        &sock_dir.path,
        trial_root,
        plan,
        trial_deadline.min(overall_deadline),
    );
    let cleanup = sock_dir.cleanup();
    merge_cleanup(result, cleanup)
}

fn run_with_socket_dir(
    sock_dir: &Path,
    trial_root: &Path,
    plan: &Plan,
    deadline: Instant,
) -> Result<Duration, SmallFilesError> {
    let socket = sock_dir.join("s.sock");
    if socket.as_os_str().len() > MAX_SOCKET_PATH_BYTES {
        return Err(SmallFilesError::new(
            "socket-path-too-long",
            "the socket path exceeds the sun_path limit; set a shorter TMPDIR",
        ));
    }
    let io_max = || IoTimeout::new(MAX_IO_TIMEOUT).map_err(|e| from_io(&e));

    // 区間の外: server の起動と接続、body の用意。
    let creator = GuestFileCreator::new(trial_root.to_path_buf()).map_err(|e| from_io(&e))?;
    let mut server = UdsServer::bind(&socket, ReceiveLimits::default(), NoopServerObserver)
        .map_err(|e| from_io(&e))?;
    let accept_timeout = io_max()?;
    let batch = BatchConfig::new(WIRE_SERVER_BATCH).map_err(|e| from_io(&e))?;
    let limits = FileServeLimits::new(
        MaxOpenFiles::new(DEFAULT_MAX_OPEN_FILES).map_err(|e| from_io(&e))?,
        UnflushedLimit::new(MAX_UNFLUSHED_MAX_FRAMES, MAX_UNFLUSHED_MAX_BYTES)
            .map_err(|e| from_io(&e))?,
    )
    .with_max_retained_dirty_files(
        MaxRetainedDirtyFiles::new(MAX_MAX_RETAINED_DIRTY_FILES).map_err(|e| from_io(&e))?,
    )
    .with_flush_timeout(io_max()?);
    let timeouts = WritebackTimeouts {
        recv: io_max()?,
        send: io_max()?,
    };
    let (tx, rx) = mpsc::channel::<Result<FileServeReport, SmallFilesError>>();
    let handle = std::thread::Builder::new()
        .name("sf-wire-server".into())
        .spawn(move || {
            let outcome = match server.accept(accept_timeout, NoopServerObserver) {
                Ok(mut conn) => Ok(serve_file_connection_with_limit(
                    &mut conn, batch, limits, &creator, timeouts,
                )),
                Err(e) => Err(from_io(&e)),
            };
            // ソケットファイルを先に片付けてから結果を返す。
            // Windows では UdsServer が Drop を持たない（UDS の wire 経路は Linux / macOS のみ実行）ため lint を許す。
            #[allow(clippy::drop_non_drop)]
            drop(server);
            let _ = tx.send(outcome);
        })
        .map_err(|_| SmallFilesError::new("io-error", "failed to spawn the server thread"))?;

    let body = vec![
        b'f';
        usize::try_from(plan.file_size).map_err(|_| {
            SmallFilesError::new("invalid-args", "file size is out of range")
        })?
    ];
    let connect_timeout = flush_timeout(deadline)?;
    let conn = UdsClientConnection::connect(
        &socket,
        connect_timeout,
        UdsServerPolicy::same_effective_uid(),
        ReceiveLimits::default(),
        NoopServerObserver,
    )
    .map_err(|e| from_io(&e))?;
    let limit = InFlightLimit::new(2 * WIRE_SERVER_BATCH).map_err(|e| from_io(&e))?;
    let mut pc = PipelineClient::new(conn, limit, NoopSendObserver);

    // 計測区間。
    let start = Instant::now();
    let mut buffered: usize = 0;
    for i in 0..plan.count {
        if Instant::now() >= deadline {
            return Err(SmallFilesError::new("timeout", "deadline exceeded"));
        }
        let path = GuestPath::parse(&guest_path(plan.layout, i))
            .map_err(|_| SmallFilesError::new("io-error", "synthetic guest path was rejected"))?;
        let handle_id = pc
            .create(&path, flush_timeout(deadline)?)
            .map_err(|e| from_io(&e))?;
        count_sent(&mut pc, &mut buffered, deadline)?;
        pc.write_file(handle_id, &body, flush_timeout(deadline)?)
            .map_err(|e| from_io(&e))?;
        count_sent(&mut pc, &mut buffered, deadline)?;
        pc.close(handle_id, flush_timeout(deadline)?)
            .map_err(|e| from_io(&e))?;
        count_sent(&mut pc, &mut buffered, deadline)?;

        // i + 1 は count <= 50,000 のため溢れない。
        if (i + 1) % plan.batch_size == 0 || i + 1 == plan.count {
            pc.flush(flush_timeout(deadline)?)
                .map_err(|e| from_io(&e))?;
            while buffered > 0 {
                expect_write_ack(&mut pc, deadline)?;
                buffered -= 1;
            }
            match pc
                .recv_ack(flush_timeout(deadline)?)
                .map_err(|e| from_io(&e))?
            {
                AckReceipt::Flush(_) => {}
                _ => return Err(unexpected_ack()),
            }
        }
    }
    let elapsed = start.elapsed();

    // 区間の後: 切断して server の report を照合する。
    drop(pc);
    let report = rx
        .recv_timeout(MAX_IO_TIMEOUT + Duration::from_secs(5))
        .map_err(|_| SmallFilesError::new("timeout", "the server did not finish in time"))??;
    let _ = handle.join();
    verify_report(&report, plan)?;
    Ok(elapsed)
}

/// 1 フレーム送ったことを数え、server のバッチが埋まったらその分の応答を受ける。
fn count_sent(
    pc: &mut PipelineClient<UdsClientConnection<NoopServerObserver>, NoopSendObserver>,
    buffered: &mut usize,
    deadline: Instant,
) -> Result<(), SmallFilesError> {
    *buffered += 1;
    if *buffered == WIRE_SERVER_BATCH {
        while *buffered > 0 {
            expect_write_ack(pc, deadline)?;
            *buffered -= 1;
        }
    }
    Ok(())
}

fn expect_write_ack(
    pc: &mut PipelineClient<UdsClientConnection<NoopServerObserver>, NoopSendObserver>,
    deadline: Instant,
) -> Result<(), SmallFilesError> {
    match pc
        .recv_ack(flush_timeout(deadline)?)
        .map_err(|e| from_io(&e))?
    {
        AckReceipt::Write(_) => Ok(()),
        AckReceipt::Rejected(r) => Err(SmallFilesError::new(
            "nack-received",
            format!(
                "the server rejected a request ({})",
                r.code().io_error_code().as_str()
            ),
        )),
        _ => Err(unexpected_ack()),
    }
}

fn unexpected_ack() -> SmallFilesError {
    SmallFilesError::new("unexpected-ack", "received an unexpected kind of response")
}

/// server の report が計画どおりであることを確かめる（fail-closed。合わなければ値を出さない）。
fn verify_report(report: &FileServeReport, plan: &Plan) -> Result<(), SmallFilesError> {
    let s = &report.stats;
    let flushes = plan.count.div_ceil(plan.batch_size);
    let ok = s.creates_succeeded == plan.count
        && s.write_files_succeeded == plan.count
        && s.closes_succeeded == plan.count
        && s.bytes_written == plan.count.saturating_mul(plan.file_size)
        && s.nacks_sent == 0
        && s.auto_flushes == 0
        && s.flush_acks_sent == flushes
        && s.discarded_pending_frames == 0
        && s.persist_failed == 0;
    if ok {
        Ok(())
    } else {
        Err(SmallFilesError::new(
            "server-report-mismatch",
            "the server report does not match the plan",
        ))
    }
}
