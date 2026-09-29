//! rename / truncate の整合性ケース（TASK-14.2・IO-4・REPAIR-6・#81）。
//!
//! [`super::harness`] の部品（[`harness::DuplexEnd`]・[`harness::TempDir`]・
//! [`harness::body_for`] 等）を再利用し、`tests/consistency.rs` モジュール doc
//! 「「rename / truncate」の定義（TASK-14.2・#81 の範囲）」で定めた操作
//! （[`fandhe_container_io::AppendFileSink`] が書き込む先のファイルに対する
//! `std::fs::rename` / `File::set_len`）を検証する。すべてのケースでファイル
//! 内容を [`harness::body_for`] が生成する期待バイト列との完全一致で確認する
//! （IO-4・REPAIR-6・#81 受入基準）。
//!
//! セッション境界の操作は「`serve_connection` の join 後」（[`run_session`]）、
//! ライブセッション中の操作は「`drain_acks` 完了直後」（[`LiveSession`]）の
//! いずれかの静止点でのみ行う（モジュール doc 参照。`Flush` はセッション終了に
//! しか使わない。D3・D4）。

use std::path::Path;
use std::sync::{Arc, Barrier};
use std::time::Duration;

use fandhe_container_io::{
    AppendFileSink, BatchConfig, InFlightLimit, IoErrorCode, NoopSendObserver, PipelineClient,
    WritebackReport, WritebackTimeouts,
};

use super::harness::{
    self, DuplexEnd, TempDir, barrier_wait_within, body_for, drain_acks, join_within,
    send_all_writes, spawn_server, timeout,
};

/// [`harness::join_within`] / [`harness::barrier_wait_within`] に渡す上限時間
/// （`concurrent_write.rs` と同じ 20 秒。REPAIR-5）。
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
/// [`AppendFileSink`] を返す（`concurrent_write.rs` の `new_sink` と同じ方針）。
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
/// [`AppendFileSink`] を返す。前セッションが書いた内容・外部からの
/// rename / truncate の結果の末尾から追記を再開するケースで使う。
fn reopen_sink(path: &Path) -> AppendFileSink {
    let file = std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .expect("must be able to reopen the existing test output file");
    AppendFileSink::new(file).expect("seek to end must succeed on reopen")
}

/// `path` を `OpenOptions::append(true)` で開いた [`AppendFileSink`] を返す
/// （T4 専用）。`append(true)` では各 `write_all` が OS レベルで常に現在の
/// EOF に着地する。通常モード（`create_sink`。非 `O_APPEND`）でも
/// [`AppendFileSink`] の `write_batch` がバッチごとに現在の EOF へ位置合わせ
/// するため、バッチの合間の外部 truncate 後に穴はできない（T5 で検証）。
/// T4 と T5 は、開き方によらず truncate 後の書き込みが新しい EOF に着地する
/// ことを対で確認する。
fn append_mode_sink(path: &Path) -> AppendFileSink {
    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .expect("must be able to open the test output file in append mode");
    AppendFileSink::new(file).expect("seek to end must succeed in append mode")
}

/// ライブセッション（1 接続の `serve_connection` と、それに対応する 1 つの
/// [`PipelineClient`]）を保持する。[`Self::write_and_ack`] は「送信 → 全 ACK
/// 受信」までを行い、この呼び出しが戻った時点でだけファイル状態が確定する
/// （ACK はバッチ書き込みの後に返るため。`writeback.rs` D3 参照）。外部からの
/// rename / truncate はこの戻り値を受け取った後にのみ行うこと。
struct LiveSession {
    client: PipelineClient<DuplexEnd, NoopSendObserver>,
    server: std::thread::JoinHandle<WritebackReport>,
}

impl LiveSession {
    /// `sink` を使うサーバーをスレッドで起動し、対応するクライアントを持つ
    /// セッションを作る。`in_flight` はこのセッションで送る最大の未 ACK 件数
    /// 以上を指定する。
    fn start(sink: AppendFileSink, config: BatchConfig, in_flight: usize) -> Self {
        let (client_end, server_end) = harness::duplex();
        let server = spawn_server(server_end, config, sink, writeback_timeouts());
        let client = PipelineClient::new(
            client_end,
            InFlightLimit::new(in_flight).expect("valid in-flight limit"),
            NoopSendObserver,
        );
        Self { client, server }
    }

    /// `bodies` を送信し、対応する ACK をすべて受け取るまで待つ（静止点）。
    fn write_and_ack(&mut self, bodies: &[Vec<u8>]) {
        send_all_writes(&mut self.client, bodies, timeout());
        drain_acks(&mut self.client, bodies.len(), timeout());
    }

    /// クライアントを切断してセッションを終える（`Flush` は使わない。`Flush` は
    /// persist 非対応環境〔Linux 5.8 未満・非 Linux〕ではサーバーを
    /// `Unimplemented` で終了させ、以後の write_and_ack ができなくなるため、
    /// セッションの最終確定にのみ使う。IO-2・TASK-15.2.2）。
    /// 内部の [`AppendFileSink`] が閉じるのはこの呼び出しが戻った後
    /// （[`join_within`] がサーバースレッドの終了を待つため）。
    fn finish(self) -> WritebackReport {
        drop(self.client);
        join_within(self.server, join_deadline())
    }
}

/// 1 セッションを最後まで（送信 → ACK 受信 → 切断・join）流し、結果の
/// [`WritebackReport`] を返す。セッション境界での rename / truncate は、この
/// 呼び出しが戻った後にのみ行うこと（内部の [`AppendFileSink`] が確実に
/// 閉じているのはここで初めて保証される）。
fn run_session(sink: AppendFileSink, config: BatchConfig, bodies: &[Vec<u8>]) -> WritebackReport {
    let mut session = LiveSession::start(sink, config, bodies.len() + 1);
    session.write_and_ack(bodies);
    session.finish()
}

/// [`harness::body_for`]（`client` 固定）を `seqs` の範囲で連結した期待
/// バイト列を作る。
fn records(client: u16, seqs: std::ops::Range<u32>, body_len: usize) -> Vec<u8> {
    seqs.flat_map(|seq| body_for(client, seq, body_len))
        .collect()
}

// ---------------------------------------------------------------------
// rename ケース（R1〜R5）
// ---------------------------------------------------------------------

/// IO-4・REPAIR-6・TASK-14.2（R1）: セッション終了後に `rename(a → b)` し、次の
/// セッションで `b` へ追記する。`b` が旧セッション分＋新セッション分の
/// 全件と完全一致し、`a` が存在しないことを確認する。
#[test]
fn io4_rename_between_sessions_appends_to_renamed_file() {
    const BODY_LEN: usize = 16;
    const BATCH_SIZE: usize = 4;
    const N: u32 = 8;
    const M: u32 = 4;
    let config = BatchConfig::new(BATCH_SIZE).expect("valid batch size");

    let dir = TempDir::new("rename-between-sessions");
    let a_path = dir.file_path("a.bin");
    let b_path = dir.file_path("b.bin");

    let bodies_n: Vec<Vec<u8>> = (0..N).map(|seq| body_for(0, seq, BODY_LEN)).collect();
    let report1 = run_session(create_sink(&a_path), config, &bodies_n);
    assert_eq!(report1.stats.acks_sent, u64::from(N));
    assert_eq!(report1.end.code(), IoErrorCode::Unavailable);

    std::fs::rename(&a_path, &b_path).expect("rename after session end must succeed");
    assert!(!a_path.exists(), "old path must not exist after rename");

    let bodies_m: Vec<Vec<u8>> = (0..M).map(|seq| body_for(0, N + seq, BODY_LEN)).collect();
    let report2 = run_session(reopen_sink(&b_path), config, &bodies_m);
    assert_eq!(report2.stats.acks_sent, u64::from(M));

    let expected = records(0, 0..N + M, BODY_LEN);
    let actual = std::fs::read(&b_path).expect("must read renamed file");
    assert_eq!(
        actual, expected,
        "renamed file must contain all records in order"
    );
    assert_eq!(
        std::fs::metadata(&b_path).expect("metadata").len(),
        u64::from(N + M) * BODY_LEN as u64
    );
    assert!(!a_path.exists());
}

/// IO-4・REPAIR-6・TASK-14.2（R2）: ライブセッション中に、開いているファイルを
/// 移動元として `rename(a → b)` する（Rust std の既定 `share_mode` は
/// `FILE_SHARE_DELETE` を含むため Windows でも成功する見込み。`tests/
/// consistency.rs`「実行する OS の方針」参照）。書き込みはパスではなく開いた
/// ハンドルについていくため、rename 後に送った分も `b` に着地することを
/// 確認する。
#[test]
fn io4_rename_live_session_writes_follow_open_handle() {
    const BODY_LEN: usize = 16;
    const BATCH_SIZE: usize = 4;
    const N: u32 = 4;
    const M: u32 = 4;
    let config = BatchConfig::new(BATCH_SIZE).expect("valid batch size");

    let dir = TempDir::new("rename-live-session");
    let a_path = dir.file_path("a.bin");
    let b_path = dir.file_path("b.bin");

    let mut session = LiveSession::start(create_sink(&a_path), config, (N + M) as usize + 1);
    let bodies_n: Vec<Vec<u8>> = (0..N).map(|seq| body_for(0, seq, BODY_LEN)).collect();
    session.write_and_ack(&bodies_n);

    std::fs::rename(&a_path, &b_path).expect("rename of an open file's path must succeed");
    assert!(!a_path.exists());

    let bodies_m: Vec<Vec<u8>> = (0..M).map(|seq| body_for(0, N + seq, BODY_LEN)).collect();
    session.write_and_ack(&bodies_m);

    let report = session.finish();
    assert_eq!(report.stats.acks_sent, u64::from(N + M));
    assert_eq!(report.end.code(), IoErrorCode::Unavailable);

    let expected = records(0, 0..N + M, BODY_LEN);
    let actual = std::fs::read(&b_path).expect("must read file at new path");
    assert_eq!(
        actual, expected,
        "writes issued after the mid-session rename must follow the open handle to the new path"
    );
    assert!(!a_path.exists());
}

/// IO-4・REPAIR-6・TASK-14.2（R3）: write-back が書き終えて閉じた一時ファイル
/// （`target.tmp`）を、既存ファイル（`target.bin`。別のバイト列・別の長さで
/// 事前作成）へ上書きで rename する（一時ファイル経由の置換パターンの手順）。
/// 置換後の `target` がセッションで書いたレコード列とバイト単位で完全一致し
/// （旧バイト列が 1 バイトも残らない）、`target.tmp` が存在しないことを
/// 確認する。
///
/// 検証するのは置換後の最終状態だけである。置換の原子性（置換と並行する
/// 読み手が旧内容・新内容のどちらかだけを観測すること）は OS の rename が
/// 担う性質で、本 crate（[`AppendFileSink`]・write-back 経路）の保証範囲では
/// ないため対象外とする（#81 の受入基準は「操作後のファイル状態を具体値で
/// 検証する」）。Windows では開いているファイルへの上書き rename は失敗
/// しうるため、移動先を閉じた状態でだけ実行する（`tests/consistency.rs`
/// 「実行する OS の方針」参照）。
#[test]
fn io4_rename_over_existing_target_leaves_only_new_content() {
    const BODY_LEN: usize = 16;
    const BATCH_SIZE: usize = 4;
    const N: u32 = 8;
    let config = BatchConfig::new(BATCH_SIZE).expect("valid batch size");

    let dir = TempDir::new("rename-over-existing-target");
    let tmp_path = dir.file_path("target.tmp");
    let target_path = dir.file_path("target.bin");

    // 事前に別内容（0xAA の連続。長さも新内容と異なる）で target を作る。
    let old_bytes = vec![0xAAu8; 5 * BODY_LEN];
    std::fs::write(&target_path, &old_bytes).expect("must write pre-existing target");

    let bodies: Vec<Vec<u8>> = (0..N).map(|seq| body_for(0, seq, BODY_LEN)).collect();
    let report = run_session(create_sink(&tmp_path), config, &bodies);
    assert_eq!(report.stats.acks_sent, u64::from(N));

    std::fs::rename(&tmp_path, &target_path)
        .expect("rename over an existing closed target must succeed");
    assert!(
        !tmp_path.exists(),
        "tmp path must not exist after replacing the target"
    );

    let expected = records(0, 0..N, BODY_LEN);
    let actual = std::fs::read(&target_path).expect("must read replaced target");
    assert_eq!(
        actual, expected,
        "target must contain exactly the new content, none of the old bytes"
    );
}

/// IO-4・REPAIR-6・TASK-14.2（R4）: ライブセッション中に `rename(a → b)` した後、
/// 元のパス `a` を無関係な内容で再作成する。サーバーの書き込みが `b` から
/// 漏れて `a` に混ざらないこと・`a` が無関係なバイト列だけであることを確認
/// する。
#[test]
fn io4_rename_then_recreate_original_path_no_leak() {
    const BODY_LEN: usize = 16;
    const BATCH_SIZE: usize = 4;
    const N: u32 = 4;
    const M: u32 = 4;
    let config = BatchConfig::new(BATCH_SIZE).expect("valid batch size");

    let dir = TempDir::new("rename-then-recreate");
    let a_path = dir.file_path("a.bin");
    let b_path = dir.file_path("b.bin");

    let mut session = LiveSession::start(create_sink(&a_path), config, (N + M) as usize + 1);
    let bodies_n: Vec<Vec<u8>> = (0..N).map(|seq| body_for(0, seq, BODY_LEN)).collect();
    session.write_and_ack(&bodies_n);

    std::fs::rename(&a_path, &b_path).expect("rename must succeed");

    let unrelated: Vec<u8> = b"unrelated-bytes-not-from-server".to_vec();
    std::fs::write(&a_path, &unrelated).expect("must recreate the original path");

    let bodies_m: Vec<Vec<u8>> = (0..M).map(|seq| body_for(0, N + seq, BODY_LEN)).collect();
    session.write_and_ack(&bodies_m);
    let report = session.finish();
    assert_eq!(report.stats.acks_sent, u64::from(N + M));

    let expected_b = records(0, 0..N + M, BODY_LEN);
    let actual_b = std::fs::read(&b_path).expect("must read renamed file");
    assert_eq!(
        actual_b, expected_b,
        "server writes must not leak from the renamed file"
    );

    let actual_a = std::fs::read(&a_path).expect("must read recreated original path");
    assert_eq!(
        actual_a, unrelated,
        "the recreated original path must contain only the unrelated bytes we wrote"
    );
}

/// IO-4・REPAIR-6・TASK-14.2（R5）: 4 クライアントがそれぞれ自分のファイルへ書き、
/// ACK の境界（静止点）で自分のファイルを rename してから、さらに書く。
/// rename 後の各ファイルが自クライアントの全件と完全一致し、他クライアントの
/// バイトが混ざらず、元のパスがすべて存在しないことを確認する。
#[test]
fn io4_rename_concurrent_clients_each_file_renamed_mid_session() {
    const CLIENTS: u16 = 4;
    const BATCH_SIZE: usize = 4;
    const N: u32 = 4;
    const M: u32 = 4;
    const BODY_LEN: usize = 16;
    let config = BatchConfig::new(BATCH_SIZE).expect("valid batch size");

    let dir = TempDir::new("rename-concurrent-clients");
    let mut old_paths = Vec::new();
    let mut new_paths = Vec::new();
    let mut client_ends = Vec::new();
    let mut server_handles = Vec::new();
    let barrier = Arc::new(Barrier::new(CLIENTS as usize + 1));

    for i in 0..CLIENTS {
        let old_path = dir.file_path(&format!("client-{i}-old.bin"));
        let (client_end, server_end) = harness::duplex();
        server_handles.push(spawn_server(
            server_end,
            config,
            create_sink(&old_path),
            writeback_timeouts(),
        ));
        client_ends.push(client_end);
        new_paths.push(dir.file_path(&format!("client-{i}-new.bin")));
        old_paths.push(old_path);
    }

    let mut client_handles = Vec::new();
    for (i, client_end) in client_ends.into_iter().enumerate() {
        let barrier = Arc::clone(&barrier);
        let old_path = old_paths[i].clone();
        let new_path = new_paths[i].clone();
        let client_id = i as u16;
        client_handles.push(std::thread::spawn(move || {
            let mut client = PipelineClient::new(
                client_end,
                InFlightLimit::new((N + M) as usize + 1).expect("valid in-flight limit"),
                NoopSendObserver,
            );
            barrier_wait_within(&barrier, join_deadline());

            let bodies_n: Vec<Vec<u8>> = (0..N)
                .map(|seq| body_for(client_id, seq, BODY_LEN))
                .collect();
            send_all_writes(&mut client, &bodies_n, timeout());
            drain_acks(&mut client, bodies_n.len(), timeout());

            std::fs::rename(&old_path, &new_path)
                .expect("each client's own-file rename must not depend on other clients");

            let bodies_m: Vec<Vec<u8>> = (0..M)
                .map(|seq| body_for(client_id, N + seq, BODY_LEN))
                .collect();
            send_all_writes(&mut client, &bodies_m, timeout());
            drain_acks(&mut client, bodies_m.len(), timeout());
        }));
    }
    barrier_wait_within(&barrier, join_deadline());

    for handle in client_handles {
        join_within(handle, join_deadline());
    }

    for (i, handle) in server_handles.into_iter().enumerate() {
        let report = join_within(handle, join_deadline());
        let client_id = i as u16;
        assert_eq!(report.stats.acks_sent, u64::from(N + M));

        assert!(
            !old_paths[i].exists(),
            "client {i}'s old path must not exist"
        );
        let expected = records(client_id, 0..N + M, BODY_LEN);
        let actual = std::fs::read(&new_paths[i]).expect("must read client's renamed file");
        assert_eq!(
            actual, expected,
            "client {i}'s renamed file must contain exactly its own records, no cross-client bytes"
        );
    }
}

// ---------------------------------------------------------------------
// truncate ケース（T1〜T6）
// ---------------------------------------------------------------------

/// IO-4・REPAIR-6・TASK-14.2（T1）: セッション終了後に `set_len(0)` してから次の
/// セッションで書く。ファイルが新しいセッション分だけになることを確認する。
#[test]
fn io4_truncate_to_zero_between_sessions_keeps_only_new_records() {
    const BODY_LEN: usize = 16;
    const BATCH_SIZE: usize = 4;
    const N: u32 = 8;
    const M: u32 = 4;
    let config = BatchConfig::new(BATCH_SIZE).expect("valid batch size");

    let dir = TempDir::new("truncate-zero-between-sessions");
    let path = dir.file_path("data.bin");

    let bodies_n: Vec<Vec<u8>> = (0..N).map(|seq| body_for(0, seq, BODY_LEN)).collect();
    let report1 = run_session(create_sink(&path), config, &bodies_n);
    assert_eq!(report1.stats.acks_sent, u64::from(N));

    let file = std::fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .expect("must open for truncate");
    file.set_len(0).expect("truncate to zero must succeed");
    drop(file);

    let bodies_m: Vec<Vec<u8>> = (0..M).map(|seq| body_for(0, seq, BODY_LEN)).collect();
    let report2 = run_session(reopen_sink(&path), config, &bodies_m);
    assert_eq!(report2.stats.acks_sent, u64::from(M));

    let expected = records(0, 0..M, BODY_LEN);
    let actual = std::fs::read(&path).expect("must read file");
    assert_eq!(
        actual, expected,
        "file must contain only the post-truncate records"
    );
    assert_eq!(
        std::fs::metadata(&path).expect("metadata").len(),
        u64::from(M) * BODY_LEN as u64
    );
}

/// IO-4・REPAIR-6・TASK-14.2（T2）: セッション終了後にレコード境界（先頭 K 件分）で
/// `set_len` してから追記する。内容が「先頭 K 件＋新しい M 件」になり、
/// 再オープンした [`AppendFileSink`]（[`reopen_sink`]）が truncate 後の EOF
/// から追記することを確認する。
#[test]
fn io4_truncate_to_record_boundary_then_append() {
    const BODY_LEN: usize = 16;
    const BATCH_SIZE: usize = 4;
    const N: u32 = 8;
    const K: u32 = 5;
    const M: u32 = 4;
    let config = BatchConfig::new(BATCH_SIZE).expect("valid batch size");

    let dir = TempDir::new("truncate-record-boundary");
    let path = dir.file_path("data.bin");

    let bodies_n: Vec<Vec<u8>> = (0..N).map(|seq| body_for(0, seq, BODY_LEN)).collect();
    run_session(create_sink(&path), config, &bodies_n);

    let file = std::fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .expect("must open for truncate");
    file.set_len(u64::from(K) * BODY_LEN as u64)
        .expect("truncate to record boundary must succeed");
    drop(file);

    let bodies_m: Vec<Vec<u8>> = (0..M).map(|seq| body_for(0, K + seq, BODY_LEN)).collect();
    let report = run_session(reopen_sink(&path), config, &bodies_m);
    assert_eq!(report.stats.acks_sent, u64::from(M));

    let mut expected = records(0, 0..K, BODY_LEN);
    expected.extend(records(0, K..K + M, BODY_LEN));
    let actual = std::fs::read(&path).expect("must read file");
    assert_eq!(
        actual, expected,
        "reopened sink must append starting from the truncated EOF"
    );
}

/// IO-4・REPAIR-6・TASK-14.2（T3。REPAIR-6 の検出ケース）: 最後のレコードの
/// 途中で `set_len` した破損状態を [`harness::decompose_records`] へ渡し、
/// panic で検出されることを確認する（実際の I/O 実装から生じたファイルに
/// 対する破損検出。REPAIR-6「実際の I/O 実装へ適用され破損を検出できる」の
/// 直接的な確認）。続けて直前のレコード境界まで切り直して復旧できることも
/// 確認する。
#[test]
fn io4_truncate_mid_record_is_detected_then_recovered() {
    const BODY_LEN: usize = 16;
    const BATCH_SIZE: usize = 4;
    const N: u32 = 4;
    const M: u32 = 4;
    let config = BatchConfig::new(BATCH_SIZE).expect("valid batch size");

    let dir = TempDir::new("truncate-mid-record-detected");
    let path = dir.file_path("data.bin");

    let bodies_n: Vec<Vec<u8>> = (0..N).map(|seq| body_for(0, seq, BODY_LEN)).collect();
    run_session(create_sink(&path), config, &bodies_n);

    // 最後のレコード（16 バイト）の途中、BODY_HEADER_LEN（10 バイト）未満
    // しか残らない位置で切る。decompose_records は「残りバイト数がヘッダ長
    // 未満」を破損として panic する。
    let full_len = u64::from(N) * BODY_LEN as u64;
    let mid_cut_len = full_len - (BODY_LEN as u64) / 2;
    let file = std::fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .expect("must open for mid-record truncate");
    file.set_len(mid_cut_len)
        .expect("mid-record truncate must succeed");
    drop(file);

    let corrupted = std::fs::read(&path).expect("must read corrupted file");
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        harness::decompose_records(&corrupted)
    }));
    let payload =
        result.expect_err("decompose_records must panic on a mid-record truncation (REPAIR-6)");
    let message = payload
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| {
            payload
                .downcast_ref::<&'static str>()
                .map(|s| s.to_string())
        })
        .expect("panic payload must be a string message");
    assert!(
        message.contains("corrupted or truncated"),
        "panic message must explain the corruption, got: {message}"
    );

    // 直前のレコード境界（N-1 件目まで）へ切り直してから復旧する。
    let last_boundary_len = u64::from(N - 1) * BODY_LEN as u64;
    let file = std::fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .expect("must open for recovery truncate");
    file.set_len(last_boundary_len)
        .expect("truncate to last record boundary must succeed");
    drop(file);

    let bodies_m: Vec<Vec<u8>> = (0..M)
        .map(|seq| body_for(0, (N - 1) + seq, BODY_LEN))
        .collect();
    let report = run_session(reopen_sink(&path), config, &bodies_m);
    assert_eq!(report.stats.acks_sent, u64::from(M));

    let mut expected = records(0, 0..N - 1, BODY_LEN);
    expected.extend(records(0, N - 1..N - 1 + M, BODY_LEN));
    let actual = std::fs::read(&path).expect("must read recovered file");
    assert_eq!(
        actual, expected,
        "recovery session must produce byte-exact output"
    );
}

/// IO-4・REPAIR-6・TASK-14.2（T4）: `append(true)` で開いたライブセッション中に、
/// 別ハンドルで `set_len(0)` する。truncate 後の書き込みが新しい EOF（先頭）
/// に着地し、ゼロ埋めの穴ができないことをファイル全体の完全一致で確認する
/// （通常モードでの同じ操作は T5
/// `io4_truncate_live_session_normal_mode_lands_at_new_eof` で確認する）。
#[test]
fn io4_truncate_live_session_append_mode_lands_at_new_eof() {
    const BODY_LEN: usize = 16;
    const BATCH_SIZE: usize = 4;
    const N: u32 = 4;
    const M: u32 = 4;
    let config = BatchConfig::new(BATCH_SIZE).expect("valid batch size");

    let dir = TempDir::new("truncate-live-session-append-mode");
    let path = dir.file_path("data.bin");

    let mut session = LiveSession::start(append_mode_sink(&path), config, (N + M) as usize + 1);
    let bodies_n: Vec<Vec<u8>> = (0..N).map(|seq| body_for(0, seq, BODY_LEN)).collect();
    session.write_and_ack(&bodies_n);

    let external = std::fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .expect("must open for external truncate");
    external
        .set_len(0)
        .expect("external truncate must succeed while the append-mode sink stays open");
    drop(external);

    let bodies_m: Vec<Vec<u8>> = (0..M).map(|seq| body_for(0, seq, BODY_LEN)).collect();
    session.write_and_ack(&bodies_m);
    let report = session.finish();
    assert_eq!(report.stats.acks_sent, u64::from(N + M));

    let expected = records(0, 0..M, BODY_LEN);
    let actual = std::fs::read(&path).expect("must read file");
    assert_eq!(
        actual, expected,
        "append(true) must land post-truncate writes at the new EOF with no zero-fill hole"
    );
}

/// IO-4・REPAIR-6・TASK-14.2（T5。Codex #1125 レビュー指摘）: `create_sink`
/// （通常モード、非 `O_APPEND`）で開いたライブセッション中に、別ハンドルで
/// `set_len(0)` する。[`AppendFileSink`] の `write_batch` はバッチごとに現在の
/// EOF へ位置合わせするため、truncate 後の M 件は新しい EOF（先頭）から穴なしで
/// 書き込まれる。穴のない期待バイト列との完全一致だけを成功条件とする
/// （truncate 前のオフセット `N*BODY_LEN` へ書き続けて `[0, N*BODY_LEN)` を
/// ゼロ埋めの穴にする退行は失敗として検出する）。
#[test]
fn io4_truncate_live_session_normal_mode_lands_at_new_eof() {
    const BODY_LEN: usize = 16;
    const BATCH_SIZE: usize = 4;
    const N: u32 = 4;
    const M: u32 = 4;
    let config = BatchConfig::new(BATCH_SIZE).expect("valid batch size");

    let dir = TempDir::new("truncate-live-session-normal-mode");
    let path = dir.file_path("data.bin");

    let mut session = LiveSession::start(create_sink(&path), config, (N + M) as usize + 1);
    let bodies_n: Vec<Vec<u8>> = (0..N).map(|seq| body_for(0, seq, BODY_LEN)).collect();
    session.write_and_ack(&bodies_n);

    let external = std::fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .expect("must open for external truncate");
    external
        .set_len(0)
        .expect("external truncate must succeed while the normal-mode sink stays open");
    drop(external);

    let bodies_m: Vec<Vec<u8>> = (0..M).map(|seq| body_for(0, N + seq, BODY_LEN)).collect();
    session.write_and_ack(&bodies_m);
    let report = session.finish();
    assert_eq!(report.stats.acks_sent, u64::from(N + M));

    // 期待値: 外部 truncate で空になったファイルへ、truncate 後の M 件だけが
    // 穴なしで先頭から追記される（`AppendFileSink` は各バッチの書き込み前に
    // 現在の EOF へ位置合わせする。`AppendFileSink::write_batch` 参照）。
    let expected = records(0, N..N + M, BODY_LEN);
    let actual = std::fs::read(&path).expect("must read file");
    assert_eq!(
        actual, expected,
        "post-truncate writes must land at the new EOF with no zero-fill hole"
    );
}

/// IO-4・REPAIR-6・TASK-14.2（T6）: セッション終了後に `set_len` でファイルを拡張
/// （レコード境界を跨がない端数バイトぶん）してから追記する。拡張分が
/// ゼロ埋めされ、その後ろに新しいレコードが続くことを確認する（拡張時の
/// ゼロ埋めは POSIX（`ftruncate`）・Windows（`SetEndOfFile`）双方で決定的）。
#[test]
fn io4_truncate_extend_zero_fills_then_appends() {
    const BODY_LEN: usize = 16;
    const BATCH_SIZE: usize = 4;
    const N: u32 = 4;
    const PAD: usize = 7;
    const M: u32 = 4;
    let config = BatchConfig::new(BATCH_SIZE).expect("valid batch size");

    let dir = TempDir::new("truncate-extend-zero-fill");
    let path = dir.file_path("data.bin");

    let bodies_n: Vec<Vec<u8>> = (0..N).map(|seq| body_for(0, seq, BODY_LEN)).collect();
    run_session(create_sink(&path), config, &bodies_n);

    let extended_len = u64::from(N) * BODY_LEN as u64 + PAD as u64;
    let file = std::fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .expect("must open for extend");
    file.set_len(extended_len).expect("extend must succeed");
    drop(file);

    let bodies_m: Vec<Vec<u8>> = (0..M).map(|seq| body_for(0, N + seq, BODY_LEN)).collect();
    let report = run_session(reopen_sink(&path), config, &bodies_m);
    assert_eq!(report.stats.acks_sent, u64::from(M));

    let mut expected = records(0, 0..N, BODY_LEN);
    expected.extend(std::iter::repeat_n(0u8, PAD));
    expected.extend(records(0, N..N + M, BODY_LEN));
    let actual = std::fs::read(&path).expect("must read file");
    assert_eq!(
        actual, expected,
        "extend must zero-fill the padding and the reopened sink must append after it"
    );
}
