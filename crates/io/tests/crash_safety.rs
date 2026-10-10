//! SIGKILL 耐性テスト（IO-3・TASK-18）の結合試験とハーネス（TASK-18.1.1・#825、TASK-18.1.2・#826）。
//!
//! `tests/bin/crash_test_server.rs`（専用 feature `crash-test-server` でのみビルドされる
//! テスト用サーバー）を子プロセスとして起動し、SIGKILL で強制終了できることを確かめる（#825）。
//! さらに #826 で、クライアント側の ACK 観測・kill 位置の制御（`unix::KillPoint`）・
//! 有効 / 無効試行の判定（`trial` モジュール）・有効試行を集める試行ループを追加した。
//! 判定ロジックは OS 非依存の `trial` に置き 3 OS でユニットテストする。
//!
//! #95（TASK-18.2）で、kill 後に `data.bin` を読んで seq 0..n と照合する損失計測と、
//! 2 つの対照ケースを追加した。
//! - フラッシュ済み（`io3_flushed_data_survives_10_valid_sigkills`）: 有効 10/10 で損失 0 を検証する。
//!   保証範囲は「プロセス強制終了（SIGKILL）後に、FLUSH ACK 済みデータが OS 経由の再読込で
//!   欠落・重複なく見えること」に限る。再読込はページキャッシュ経由のため、電源断・カーネル
//!   クラッシュ後の媒体上の永続化（IO-2 の fsync 等価の保証）はこの試験では検証しない。
//! - 未フラッシュ対照（`io3_unflushed_control_records_loss_without_asserting`）: 損失件数は
//!   記録するだけで、件数ではテストを失敗させない。
//!
//! CI 回帰への組み込みは実装済み（#827）: `platform-ci`（PR は ubuntu・main は 3 OS）と `rust-ci`（`--all-features`）で
//! 実行し、実機前提テストとしては分離しない。`platform-ci` は存在確認ステップで無言除外を検出する。
//!
//! 未実装（TASK-18 の人間担当）: 実測結果レポートと対照としての妥当性の判断。
//! ここの小さい目標数の結合試験（`io3_harness_*`）は試行ループの挙動だけを確かめる（REPAIR-3）。
//! Windows など UDS 未対応 OS では、未対応終了コード 5 を返すことだけを確かめる。

#[path = "crash_safety/trial.rs"]
mod trial;

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod unix {
    use std::io::Write as _;
    use std::io::{BufRead, BufReader, Read};
    use std::os::unix::fs::DirBuilderExt;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixStream;
    use std::os::unix::process::ExitStatusExt;
    use std::path::PathBuf;
    use std::process::{Child, Command, ExitStatus, Stdio};
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    use fandhe_container_io::{
        AckReceipt, FRAME_HEADER_LEN, Frame, FrameHeader, FrameKind, FrameReceiver, FrameSender,
        InFlightLimit, IoError, IoErrorCode, IoTimeout, NoopSendObserver, PipelineClient,
        persist_support,
    };

    use crate::trial::{
        DiskObservation, InvalidReason, MAX_ATTEMPTS, RECORD_LEN, ServerExit, TARGET_VALID_TRIALS,
        TrialLedger, TrialObservation, TrialSummary, TrialVerdict, check_disk_records,
        classify_trial, loss_summary, run_until_valid,
    };

    const READY_WAIT: Duration = Duration::from_secs(10);
    const EXIT_WAIT: Duration = Duration::from_secs(15);

    /// 短いパスの 0700 一時ディレクトリ（macOS の sun_path 上限 104 バイト対策。`tests/server.rs` と同方針）。
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            // 並行テスト・複数試行で同じ tag が重なっても衝突しないよう連番を足す
            static COUNTER: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
            let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let dir =
                std::env::temp_dir().join(format!("fcio-cs-{}-{tag}-{n}", std::process::id()));
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&dir)
                .expect("must be able to create a temp dir");
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
                .expect("must be able to force mode 0700 regardless of umask");
            Self(dir)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// 失敗時も孤児を残さないよう Drop で kill + wait する。
    struct ChildGuard(Child);

    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    /// `batch_size` を `Some` にすると `--batch-size` を渡す（通常 ACK はバッチ書き込み後に返るため、
    /// 「n 件の Write に n 件の ACK が返る」試行では n をバッチサイズに合わせる）。
    fn spawn_server(dir: &TempDir, batch_size: Option<u64>) -> ChildGuard {
        let mut command = Command::new(env!("CARGO_BIN_EXE_crash_test_server"));
        if let Some(n) = batch_size {
            command.arg("--batch-size").arg(n.to_string());
        }
        let child = command
            .arg("--socket")
            .arg(dir.0.join("s.sock"))
            .arg("--data-dir")
            .arg(&dir.0)
            .arg("--file")
            .arg("data.bin")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("crash_test_server must spawn");
        ChildGuard(child)
    }

    /// stdout の `READY` 行を期限付きで待つ。
    fn wait_ready(child: &mut ChildGuard) {
        let stdout = child.0.stdout.take().expect("stdout must be piped");
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let mut line = String::new();
            let _ = BufReader::new(stdout).read_line(&mut line);
            let _ = tx.send(line);
        });
        let line = rx
            .recv_timeout(READY_WAIT)
            .expect("READY line must arrive within the deadline");
        assert_eq!(line.trim_end(), "READY");
    }

    fn wait_exit(child: &mut ChildGuard) -> ExitStatus {
        let deadline = Instant::now() + EXIT_WAIT;
        loop {
            if let Some(status) = child.0.try_wait().expect("try_wait must succeed") {
                return status;
            }
            assert!(Instant::now() < deadline, "child must exit within deadline");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// IO-3・TASK-18.1.1: 子プロセスとして起動でき、接続して切断すると終了コード 0 で終わる。
    #[test]
    fn io3_crash_test_server_spawns_and_accepts() {
        let dir = TempDir::new("ok");
        let mut child = spawn_server(&dir, None);
        wait_ready(&mut child);
        // 接続直後に閉じると、サーバーが accept する前に切断が listen キューへ届く競合が
        // 起こり得る。accept を済ませて recv 待ちに入る猶予を与えてから閉じる。
        let stream = UnixStream::connect(dir.0.join("s.sock")).expect("connect must succeed");
        std::thread::sleep(Duration::from_millis(300));
        drop(stream);
        let status = wait_exit(&mut child);
        let mut stderr = String::new();
        child
            .0
            .stderr
            .take()
            .expect("stderr must be piped")
            .read_to_string(&mut stderr)
            .expect("stderr must be readable");
        assert_eq!(status.code(), Some(0), "stderr: {stderr}");
        assert!(
            stderr.contains("\"code\":\"UNAVAILABLE\""),
            "stderr: {stderr}"
        );
    }

    /// IO-3・TASK-18.1.1: READY 後に SIGKILL で強制終了できる（シグナル 9）。
    #[test]
    fn io3_crash_test_server_can_be_sigkilled() {
        let dir = TempDir::new("kill");
        let mut child = spawn_server(&dir, None);
        wait_ready(&mut child);
        child.0.kill().expect("kill (SIGKILL) must succeed");
        let status = wait_exit(&mut child);
        assert_eq!(status.signal(), Some(9));
    }

    /// テスト用の UDS クライアント端点（`FrameSender` + `FrameReceiver`）。
    ///
    /// `src/` には UDS のクライアント側具象実装がないため（`client.rs` の doc 参照）、
    /// 本テストで `PipelineClient` を使えるよう std の `UnixStream` を包む。ACK の順序・種別の
    /// 検証は `PipelineClient::recv_ack` に任せ、ここでは観測数を水増ししない。
    /// 一度でも `Err` を返したら以後は `Unavailable` を返す（transport の poison 契約と同じ）。
    struct UnixClientEnd {
        stream: UnixStream,
        poisoned: bool,
    }

    impl UnixClientEnd {
        fn new(stream: UnixStream) -> Self {
            Self {
                stream,
                poisoned: false,
            }
        }

        fn fail(&mut self, e: &std::io::Error) -> IoError {
            self.poisoned = true;
            let code = match e.kind() {
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => {
                    IoErrorCode::Timeout
                }
                _ => IoErrorCode::Unavailable,
            };
            IoError::new(code, format!("unix client io failed: {e}"))
        }

        fn poisoned_error() -> IoError {
            IoError::new(
                IoErrorCode::Unavailable,
                "unix client end is poisoned by a previous error",
            )
        }
    }

    impl FrameSender for UnixClientEnd {
        type Frame = Frame;

        fn send_frame(&mut self, frame: &Frame, timeout: IoTimeout) -> Result<(), IoError> {
            if self.poisoned {
                return Err(Self::poisoned_error());
            }
            let result = self
                .stream
                .set_write_timeout(Some(timeout.as_duration()))
                .and_then(|()| self.stream.write_all(&frame.encode()));
            result.map_err(|e| self.fail(&e))
        }
    }

    impl FrameReceiver for UnixClientEnd {
        type Frame = Frame;

        fn recv_frame(&mut self, timeout: IoTimeout) -> Result<Frame, IoError> {
            if self.poisoned {
                return Err(Self::poisoned_error());
            }
            let mut header_bytes = [0u8; FRAME_HEADER_LEN];
            if let Err(e) = self
                .stream
                .set_read_timeout(Some(timeout.as_duration()))
                .and_then(|()| self.stream.read_exact(&mut header_bytes))
            {
                return Err(self.fail(&e));
            }
            let header = match FrameHeader::from_bytes(header_bytes) {
                Ok(h) => h,
                Err(e) => {
                    self.poisoned = true;
                    return Err(e);
                }
            };
            // body 長は検証済みの FrameHeader（MAX_FRAME_LEN 以内）の値だけを使う
            let mut body = vec![0u8; header.body_len()];
            if let Err(e) = self.stream.read_exact(&mut body) {
                return Err(self.fail(&e));
            }
            match Frame::decode_body(header, &body) {
                Ok(frame) => Ok(frame),
                Err(e) => {
                    self.poisoned = true;
                    Err(e)
                }
            }
        }
    }

    /// SIGKILL を打つ位置（IO-3・TASK-18.1.2）。
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum KillPoint {
        /// `n` 件の Write を送り、通常 ACK を `n` 件観測した直後に kill する（未フラッシュ状態。
        /// サーバーのバッチサイズを `n` に合わせ、ACK が確実に返るようにする）。
        AfterWriteAcks(u64),
        /// `writes`（バッチサイズ未満）件の Write と Flush を送り、通常 ACK `writes` 件と
        /// FLUSH ACK を観測した直後に kill する。FLUSH ACK 非対応環境（Linux 5.8 未満等）では
        /// サーバーが接続を閉じるため、無効試行として分類される。
        AfterFlushAck { writes: u64 },
        /// 何も送らずに切断し、サーバーが自然終了した後に kill する（サーバー早期終了の
        /// 無効試行の再現用。除外ロジックの検証専用）。
        DisconnectBeforeKill,
    }

    impl KillPoint {
        fn label(self) -> &'static str {
            match self {
                Self::AfterWriteAcks(_) => "w",
                Self::AfterFlushAck { .. } => "f",
                Self::DisconnectBeforeKill => "d",
            }
        }
    }

    fn server_exit(status: ExitStatus) -> ServerExit {
        ServerExit {
            code: status.code(),
            signal: status.signal(),
        }
    }

    fn io_timeout(secs: u64) -> IoTimeout {
        IoTimeout::new(Duration::from_secs(secs)).expect("timeout must be within the IoTimeout cap")
    }

    /// 期限付きで子プロセスの終了を待ち、回収できた状態を返す（REPAIR-5）。
    fn try_reap(child: &mut ChildGuard, wait: Duration) -> Option<ServerExit> {
        let deadline = Instant::now() + wait;
        loop {
            if let Ok(Some(status)) = child.0.try_wait() {
                return Some(server_exit(status));
            }
            if Instant::now() >= deadline {
                return None;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// クライアントの送受信部分。ACK 観測数などを `obs` へ逐次書き込み、失敗コードを返す。
    /// 各 ACK 待ちは期限付き（REPAIR-5。FLUSH ACK は syncfs のため上限の 10 秒）。
    /// 成功時は kill まで接続を生かすため client を返す（先に閉じるとサーバーが正常終了してしまう）。
    fn drive_client(
        stream: UnixStream,
        kill_point: KillPoint,
        obs: &mut TrialObservation,
    ) -> Result<PipelineClient<UnixClientEnd, NoopSendObserver>, IoErrorCode> {
        let (writes, flush) = match kill_point {
            KillPoint::AfterWriteAcks(n) => (n, false),
            KillPoint::AfterFlushAck { writes } => (writes, true),
            KillPoint::DisconnectBeforeKill => return Err(IoErrorCode::InvalidArgument),
        };
        let limit =
            InFlightLimit::new(usize::try_from(writes).unwrap_or(0) + 2).map_err(|e| e.code())?;
        let mut client = PipelineClient::new(UnixClientEnd::new(stream), limit, NoopSendObserver);
        let send_timeout = io_timeout(5);
        for seq in 0..writes {
            client
                .send(FrameKind::Write, &seq.to_le_bytes(), send_timeout)
                .map_err(|e| e.code())?;
        }
        if flush {
            client
                .send(FrameKind::Flush, &[], send_timeout)
                .map_err(|e| e.code())?;
        }
        for _ in 0..writes {
            client.recv_ack(io_timeout(5)).map_err(|e| e.code())?;
            obs.acks_observed += 1;
        }
        if flush {
            match client.recv_ack(io_timeout(10)) {
                Ok(AckReceipt::Flush(_)) => obs.flush_ack_observed = true,
                Ok(_) => return Err(IoErrorCode::Internal),
                Err(e) => return Err(e.code()),
            }
        }
        Ok(client)
    }

    /// 1 試行を実行して観測値を返す（判定は [`classify_trial`] が行う）。
    /// 試行ごとに新しいパスを使う（SIGKILL 後はソケットが残るため。`crash_test_server` の doc 参照）。
    fn run_trial(index: usize, kill_point: KillPoint) -> TrialObservation {
        let (ack_target, flush_required, batch_size) = match kill_point {
            KillPoint::AfterWriteAcks(n) => (n, false, Some(n)),
            KillPoint::AfterFlushAck { writes } => (writes, true, None),
            KillPoint::DisconnectBeforeKill => (0, false, None),
        };
        let mut obs = TrialObservation {
            acks_observed: 0,
            ack_target,
            flush_ack_required: flush_required,
            flush_ack_observed: false,
            server_exited_before_kill: None,
            client_error: None,
            final_exit: None,
            server_persist_failed: false,
            disk: None,
        };
        let dir = TempDir::new(&format!("{}{index}", kill_point.label()));
        let mut child = spawn_server(&dir, batch_size);
        wait_ready(&mut child);
        let stream = UnixStream::connect(dir.0.join("s.sock")).expect("connect must succeed");

        let _client = if kill_point == KillPoint::DisconnectBeforeKill {
            // accept 済みで recv 待ちに入る猶予を与えてから切断し、サーバーの自然終了を待つ
            std::thread::sleep(Duration::from_millis(300));
            drop(stream);
            obs.server_exited_before_kill = try_reap(&mut child, EXIT_WAIT);
            None
        } else {
            match drive_client(stream, kill_point, &mut obs) {
                Ok(client) => Some(client),
                Err(code) => {
                    obs.client_error = Some(code);
                    None
                }
            }
        };

        if obs.server_exited_before_kill.is_none() {
            // kill 直前の状態確認（待たない）
            obs.server_exited_before_kill = try_reap(&mut child, Duration::ZERO);
        }
        if obs.server_exited_before_kill.is_none()
            && obs.flush_ack_required
            && !obs.flush_ack_observed
        {
            // 永続化失敗ならサーバーは自ら終了レポートを出して終わる。kill で終了レポートを
            // 失わないよう、FLUSH ACK 未観測の試行に限り短く終了を待つ（REPAIR-5・REPAIR-12）。
            obs.server_exited_before_kill = try_reap(&mut child, Duration::from_secs(3));
        }
        // 失敗しても後段の判定（NotKilledBySigkill）と ChildGuard の Drop が後始末する
        let _ = child.0.kill();
        obs.final_exit = try_reap(&mut child, EXIT_WAIT);
        if obs.final_exit.is_some() {
            // 子は回収済み（stderr は EOF 済み）なので読み取りでブロックしない。上限付き。
            obs.server_persist_failed = child
                .0
                .stderr
                .take()
                .is_some_and(|mut e| stderr_reports_persist_failure(&mut e));
        }
        // TempDir を破棄する前にディスク上の状態を照合する（IO-3・TASK-18.2）。
        // サーバーは回収済み（または kill 済み）なので、以降ファイルは変化しない。
        if kill_point != KillPoint::DisconnectBeforeKill {
            obs.disk = Some(observe_disk(&dir, ack_target));
        }
        obs
    }

    /// `data.bin` を上限付きで読み、seq 0..expected と照合する。
    /// 上限は期待サイズ + 余裕。超過ファイルは読まずに `TooLarge` にして無制限確保を避ける。
    fn observe_disk(dir: &TempDir, expected: u64) -> DiskObservation {
        const SLACK: u64 = 4096;
        let cap = expected
            .saturating_mul(RECORD_LEN as u64)
            .saturating_add(SLACK);
        let path = dir.0.join("data.bin");
        let file = match std::fs::File::open(&path) {
            Ok(f) => f,
            Err(e) => return DiskObservation::ReadFailed(format!("{:?}", e.kind())),
        };
        match file.metadata() {
            Ok(m) if m.len() > cap => {
                return DiskObservation::TooLarge { len: m.len(), cap };
            }
            Ok(_) => {}
            Err(e) => return DiskObservation::ReadFailed(format!("{:?}", e.kind())),
        }
        let mut bytes = Vec::new();
        match file.take(cap.saturating_add(1)).read_to_end(&mut bytes) {
            Ok(_) if bytes.len() as u64 > cap => DiskObservation::TooLarge {
                len: bytes.len() as u64,
                cap,
            },
            Ok(_) => DiskObservation::Checked(check_disk_records(&bytes, expected)),
            Err(e) => DiskObservation::ReadFailed(format!("{:?}", e.kind())),
        }
    }

    /// サーバーの標準エラーを上限付きで読み、終了レポート行（`"event":"exit"`）の統計に
    /// `persist_failed >= 1` があるかを返す。読み取り失敗は `false`（fail-closed）。
    fn stderr_reports_persist_failure(stderr: &mut impl Read) -> bool {
        const CAP: u64 = 64 * 1024;
        let mut text = String::new();
        if stderr.take(CAP).read_to_string(&mut text).is_err() {
            return false;
        }
        text_reports_persist_failure(&text)
    }

    /// 終了レポート行から `"persist_failed":N` を取り出して `N >= 1` を判定する（純粋関数）。
    fn text_reports_persist_failure(text: &str) -> bool {
        const KEY: &str = "\"persist_failed\":";
        text.lines()
            .filter(|l| l.contains("\"event\":\"exit\""))
            .filter_map(|l| l.split_once(KEY))
            .filter_map(|(_, rest)| {
                let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
                digits.parse::<u64>().ok()
            })
            .any(|n| n >= 1)
    }

    /// crash_test_server が `serve` を正常切断以外で終了したときの終了コード
    /// （`tests/bin/crash_test_server.rs` の `EXIT_SERVE`）。永続化失敗はこの経路で終了する。
    const SERVER_EXIT_SERVE: i32 = 4;

    /// 永続化（FLUSH）非対応環境で許容する無効理由。通常 ACK は全件届いた前提で、
    /// FLUSH ACK 待ちの失敗（未観測・接続断・タイムアウト）またはその失敗に伴うサーバー終了に限り、
    /// かつサーバーの構造化された終了レポートが `persist_failed >= 1` を示していることを必須とする。
    /// `SERVER_EXIT_SERVE`（4）は書き込み失敗など別の serve 異常終了にも使われるため、終了コードだけでは
    /// 永続化非対応と判定しない（REPAIR-12）。サーバー終了はコード 4・シグナルなしのみ許容する。
    fn is_persist_unsupported_reason(obs: &TrialObservation, verdict: &TrialVerdict) -> bool {
        if !obs.server_persist_failed {
            return false;
        }
        match verdict {
            TrialVerdict::Invalid(InvalidReason::ServerExitedEarly(exit)) => {
                exit.code == Some(SERVER_EXIT_SERVE) && exit.signal.is_none()
            }
            TrialVerdict::Invalid(
                InvalidReason::FlushAckMissing
                | InvalidReason::ClientFailed(IoErrorCode::Unavailable | IoErrorCode::Timeout),
            ) => true,
            _ => false,
        }
    }

    /// 構造化ログ用のディスク照合フィールド（件数のみ。データ本体・パスは出さない）。
    fn disk_log_fields(disk: &Option<DiskObservation>) -> String {
        match disk {
            Some(DiskObservation::Checked(c)) => format!(
                "\"disk\":\"checked\",\"lost\":{},\"found\":{},\"unexpected\":{},\"trailing_partial_bytes\":{}",
                c.lost(),
                c.found.len(),
                c.unexpected.len(),
                c.trailing_partial_bytes
            ),
            Some(DiskObservation::ReadFailed(kind)) => {
                format!("\"disk\":\"read_failed\",\"error_kind\":\"{kind}\"")
            }
            Some(DiskObservation::TooLarge { len, cap }) => {
                format!("\"disk\":\"too_large\",\"len\":{len},\"cap\":{cap}")
            }
            None => "\"disk\":\"none\"".to_string(),
        }
    }

    /// ケースごとのサマリー行（実測結果レポートの材料。REPAIR-4）。
    fn log_case_summary(case: &str, ledger: &TrialLedger, summary: &TrialSummary) {
        let loss = loss_summary(ledger);
        eprintln!(
            "{{\"event\":\"crash_summary\",\"case\":\"{case}\",\"attempts\":{},\"valid\":{},\"invalid\":{},\"aborted\":{},\"checked\":{},\"total_lost\":{},\"max_lost\":{},\"trials_with_loss\":{},\"unexact\":{}}}",
            summary.attempts,
            summary.valid,
            summary.invalid,
            summary.aborted,
            loss.checked_trials,
            loss.total_lost,
            loss.max_lost,
            loss.trials_with_loss,
            loss.unexact_trials
        );
    }

    /// 試行ループ。結果を JSON 1 行の構造化ログとして stderr へ出す（REPAIR-4）。
    fn run_trials(
        kill_point: KillPoint,
        target_valid: usize,
        max_attempts: usize,
    ) -> (TrialLedger, TrialSummary) {
        let mut ledger = TrialLedger::new(target_valid, max_attempts);
        let summary = run_until_valid(&mut ledger, |index| {
            let obs = run_trial(index, kill_point);
            eprintln!(
                "{{\"event\":\"crash_trial\",\"index\":{index},\"kill_point\":\"{kill_point:?}\",\"acks_observed\":{},\"verdict\":\"{:?}\",{}}}",
                obs.acks_observed,
                classify_trial(&obs),
                disk_log_fields(&obs.disk)
            );
            obs
        });
        (ledger, summary)
    }

    /// IO-3・TASK-18.1.2: 通常 ACK を 30 件観測した直後に SIGKILL した試行は有効になる。
    #[test]
    fn io3_trial_after_write_acks_is_valid() {
        let obs = run_trial(0, KillPoint::AfterWriteAcks(30));
        assert_eq!(obs.acks_observed, 30);
        assert_eq!(
            obs.final_exit,
            Some(ServerExit {
                code: None,
                signal: Some(9)
            })
        );
        assert_eq!(
            classify_trial(&obs),
            TrialVerdict::Valid { acks_observed: 30 }
        );
    }

    /// IO-3・TASK-18.1.2: FLUSH ACK 対応環境では有効、非対応環境ではハングせず無効に分類される。
    #[test]
    fn io3_trial_after_flush_ack_is_classified_by_persist_support() {
        let obs = run_trial(0, KillPoint::AfterFlushAck { writes: 5 });
        let verdict = classify_trial(&obs);
        if persist_support().is_supported() {
            assert!(obs.flush_ack_observed);
            assert_eq!(verdict, TrialVerdict::Valid { acks_observed: 5 });
        } else {
            assert!(!obs.flush_ack_observed);
            // 通常 ACK は全件届き、FLUSH ACK 待ちだけが失敗した経路であることを確認する
            // （接続失敗・通常 ACK 未達・SIGKILL 不成立による無効化を除外。REPAIR-12）。
            // 永続化失敗でサーバーが通常 ACK 送出後に終了し、kill 直前の回収で観測された場合は
            // ServerExitedEarly（serve 異常終了の終了コード 4）になるため、これも同経路として許容する。
            assert_eq!(obs.acks_observed, 5);
            assert!(
                is_persist_unsupported_reason(&obs, &verdict),
                "unsupported persist must be excluded by the FLUSH ACK path, got {verdict:?}"
            );
        }
    }

    /// IO-3・TASK-18.1.2: kill 前にサーバーが終了していた試行は ServerExitedEarly で除外される。
    #[test]
    fn io3_invalid_when_server_exits_before_kill() {
        let obs = run_trial(0, KillPoint::DisconnectBeforeKill);
        assert_eq!(
            classify_trial(&obs),
            TrialVerdict::Invalid(InvalidReason::ServerExitedEarly(ServerExit {
                code: Some(0),
                signal: None
            }))
        );
    }

    /// REPAIR-12: 永続化非対応の許容は persist_failed を示す終了レポートを必須とし、
    /// 終了コード 4 だけ・無関係な早期終了は拒否する。
    #[test]
    fn persist_unsupported_reason_requires_structured_persist_failure() {
        let exit = |code, signal| {
            TrialVerdict::Invalid(InvalidReason::ServerExitedEarly(ServerExit {
                code,
                signal,
            }))
        };
        let obs = |persist_failed| TrialObservation {
            acks_observed: 30,
            ack_target: 30,
            flush_ack_required: true,
            flush_ack_observed: false,
            server_exited_before_kill: None,
            client_error: None,
            final_exit: None,
            server_persist_failed: persist_failed,
            disk: None,
        };
        assert!(is_persist_unsupported_reason(
            &obs(true),
            &exit(Some(4), None)
        ));
        // 終了コード 4 でも persist_failed の根拠がなければ別障害として拒否する
        assert!(!is_persist_unsupported_reason(
            &obs(false),
            &exit(Some(4), None)
        ));
        assert!(!is_persist_unsupported_reason(
            &obs(false),
            &TrialVerdict::Invalid(InvalidReason::FlushAckMissing)
        ));
        assert!(!is_persist_unsupported_reason(
            &obs(true),
            &exit(Some(0), None)
        ));
        assert!(!is_persist_unsupported_reason(
            &obs(true),
            &exit(Some(3), None)
        ));
        assert!(!is_persist_unsupported_reason(
            &obs(true),
            &exit(None, Some(9))
        ));
    }

    /// REPAIR-12: 終了レポートの persist_failed だけを根拠にする（書き込み失敗等は対象外）。
    #[test]
    fn text_reports_persist_failure_parses_exit_report_only() {
        let base = |n: u64| {
            format!(
                "{{\"event\":\"exit\",\"code\":\"INTERNAL\",\"message\":\"x\",\"stats\":{{\"persist_succeeded\":0,\"persist_failed\":{n},\"auto_flushes\":0}}}}\n"
            )
        };
        assert!(text_reports_persist_failure(&base(1)));
        assert!(!text_reports_persist_failure(&base(0)));
        assert!(!text_reports_persist_failure(""));
        assert!(!text_reports_persist_failure(
            "{\"event\":\"other\",\"persist_failed\":3}\n"
        ));
    }

    /// IO-3・TASK-18.1.2: 試行ループが有効試行を目標数（ここでは 2）まで集める。
    /// 本番の目標（有効 10・上限 30）は #95 の対照ケースで使う。
    #[test]
    fn io3_harness_collects_valid_trials_until_target() {
        let (ledger, summary) = run_trials(KillPoint::AfterWriteAcks(30), 2, 6);
        assert_eq!(summary.valid, 2);
        assert!(!summary.aborted);
        assert_eq!(ledger.valid_trials().count(), 2);
    }

    /// IO-3・TASK-18.2: フラッシュ済みケース。保証範囲は SIGKILL 後の可視性（ページキャッシュ経由の
    /// 再読込）に限り、電源断後の媒体永続化は検証しない。バッチ未満の 30 件を書いて Flush し、FLUSH ACK を
    /// 観測した直後に SIGKILL する試行を有効 10 回集め、すべてで 30 件が欠落・重複なく並ぶこと
    /// （損失 0）を検証する。FLUSH ACK を返せない環境（Linux 5.8 未満等）では有効試行が
    /// 成立しないため、全試行が FLUSH ACK 経路で無効になることを確認する。これは CI を通すための
    /// 弱体化ではなく、ACK 自体が存在しない環境の契約確認である（対応環境では必ず 10/10・損失 0）。
    #[test]
    fn io3_flushed_data_survives_10_valid_sigkills() {
        let (ledger, summary) = run_trials(
            KillPoint::AfterFlushAck { writes: 30 },
            TARGET_VALID_TRIALS,
            MAX_ATTEMPTS,
        );
        let loss = loss_summary(&ledger);
        log_case_summary("flushed", &ledger, &summary);
        if persist_support().is_supported() {
            assert!(!summary.aborted, "summary: {summary:?}");
            assert_eq!(summary.valid, 10);
            let expected: Vec<u64> = (0..30).collect();
            for rec in ledger.valid_trials() {
                match &rec.observation.disk {
                    Some(DiskObservation::Checked(c)) => {
                        assert_eq!(c.found, expected, "trial {}", rec.index);
                        assert!(c.missing.is_empty(), "trial {}", rec.index);
                        assert!(c.unexpected.is_empty(), "trial {}", rec.index);
                        assert_eq!(c.trailing_partial_bytes, 0, "trial {}", rec.index);
                    }
                    other => panic!("trial {} must be disk-checked, got {other:?}", rec.index),
                }
            }
            assert_eq!(loss.checked_trials, 10);
            assert_eq!(loss.total_lost, 0);
            assert_eq!(loss.trials_with_loss, 0);
            assert_eq!(loss.unexact_trials, 0);
        } else {
            assert!(summary.aborted);
            assert_eq!(summary.valid, 0);
            assert!(summary.invalid > 0, "summary: {summary:?}");
            for rec in ledger.invalid_trials() {
                // 通常 ACK 30 件を全件観測した上で FLUSH ACK だけが得られなかった試行に限る
                // （接続失敗・ACK 未達を「永続化非対応」に紛れ込ませない。REPAIR-12）。
                assert_eq!(rec.observation.acks_observed, 30, "trial {}", rec.index);
                assert!(!rec.observation.flush_ack_observed, "trial {}", rec.index);
                assert!(
                    is_persist_unsupported_reason(&rec.observation, &rec.verdict),
                    "trial {}: {:?}",
                    rec.index,
                    rec.verdict
                );
            }
            eprintln!(
                "{{\"event\":\"crash_summary\",\"case\":\"flushed\",\"persist_supported\":false}}"
            );
        }
    }

    /// IO-3・TASK-18.2: 未フラッシュ対照ケース。ACK 30 件を観測した直後（Flush なし）に SIGKILL
    /// する試行を有効 10 回集め、ディスク上の損失件数を記録・報告する。**損失件数ではテストを
    /// 失敗させない**（対照データの記録とレポートが目的。アサートするのは計測が成立したことだけ）。
    ///
    /// 本実装は通常 ACK を `write()` 完了後に返し、SIGKILL ではページキャッシュが失われないため、
    /// ACK 済みデータの損失はほぼ 0 と予想される。spec の PoC で見られた損失は ACK を書き込みより
    /// 先に返す実装によるもので、本実装にその状態は無い。電源断相当の耐久性はこの試験の範囲外。
    /// 対照として十分かどうかの判断は TASK-18 の人間担当に委ねる。
    #[test]
    fn io3_unflushed_control_records_loss_without_asserting() {
        let (ledger, summary) = run_trials(
            KillPoint::AfterWriteAcks(30),
            TARGET_VALID_TRIALS,
            MAX_ATTEMPTS,
        );
        log_case_summary("unflushed_control", &ledger, &summary);
        assert!(!summary.aborted, "summary: {summary:?}");
        assert_eq!(summary.valid, 10);
        for rec in ledger.valid_trials() {
            assert!(
                matches!(rec.observation.disk, Some(DiskObservation::Checked(_))),
                "trial {} must be disk-checked, got {:?}",
                rec.index,
                rec.observation.disk
            );
        }
    }

    /// IO-3・TASK-18.1.2: 無効試行しか得られない場合は上限で打ち切られ、有効数は 0 のまま。
    #[test]
    fn io3_harness_aborts_when_every_trial_is_invalid() {
        let (ledger, summary) = run_trials(KillPoint::DisconnectBeforeKill, 2, 3);
        assert_eq!(summary.attempts, 3);
        assert_eq!(summary.valid, 0);
        assert_eq!(summary.invalid, 3);
        assert!(summary.aborted);
        assert_eq!(ledger.valid_trials().count(), 0);
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
mod other {
    use std::io::Read;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    /// 子プロセス終了の待機上限（REPAIR-5: 相手の応答を待つ処理には期限を設ける）。
    const EXIT_WAIT: Duration = Duration::from_secs(15);

    /// IO-3・TASK-18.1.1: UDS 未対応 OS では終了コード 5 と UNIMPLEMENTED を返す。
    #[test]
    fn io3_crash_test_server_reports_unsupported_platform() {
        let mut child = Command::new(env!("CARGO_BIN_EXE_crash_test_server"))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("crash_test_server must spawn");
        // 期限付きの try_wait ループ。超過時は kill + wait して孤児とハングを防ぐ
        let deadline = Instant::now() + EXIT_WAIT;
        let status = loop {
            if let Some(status) = child.try_wait().expect("try_wait must succeed") {
                break status;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("crash_test_server must exit within the deadline");
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        let mut stderr = String::new();
        child
            .stderr
            .take()
            .expect("stderr must be piped")
            .read_to_string(&mut stderr)
            .expect("stderr must be readable");
        assert_eq!(status.code(), Some(5), "stderr: {stderr}");
        assert!(stderr.contains("UNIMPLEMENTED"), "stderr: {stderr}");
    }
}
