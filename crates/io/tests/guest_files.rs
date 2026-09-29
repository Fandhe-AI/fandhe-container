//! サーバーのファイル作成経路への大文字小文字衝突検出の結合試験
//! （TASK-19.2・IO-5・#100。3 OS 共通）。
//!
//! 大文字小文字だけが違う 2 つの作成要求を同時に出すと、サーバー側
//! （[`fandhe_container_io::GuestFileCreator`]）が構造化エラーを返すこと、および
//! 作成した sink が `serve_connection` の書き込み経路でそのまま使えることを
//! 確かめる。応答を待つ処理にはすべて期限を付ける（REPAIR-5）。

#[allow(dead_code)]
#[path = "consistency/harness.rs"]
mod harness;

use std::sync::{Arc, Barrier};
use std::time::Duration;

use fandhe_container_io::{
    BatchConfig, GuestFileCreator, InFlightLimit, IoError, IoErrorCode, NoopSendObserver,
    PipelineClient, WritebackTimeouts,
};
use harness::{
    TempDir, barrier_wait_within, drain_acks, duplex, join_within, send_all_writes, spawn_server,
    timeout,
};

fn deadline() -> Duration {
    Duration::from_secs(5)
}

fn creator_in(dir: &TempDir, name: &str) -> (Arc<GuestFileCreator>, std::path::PathBuf) {
    let root = dir.file_path(name);
    std::fs::create_dir_all(&root).expect("root must be creatable");
    (
        Arc::new(GuestFileCreator::new(root.clone()).expect("creator")),
        root,
    )
}

fn race(
    creator: &Arc<GuestFileCreator>,
    a: &'static str,
    b: &'static str,
) -> Vec<Result<(), IoError>> {
    let barrier = Arc::new(Barrier::new(3));
    let handles: Vec<_> = [a, b]
        .into_iter()
        .map(|path| {
            let creator = Arc::clone(creator);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier_wait_within(&barrier, deadline());
                creator.create_file(path).map(|_| ())
            })
        })
        .collect();
    barrier_wait_within(&barrier, deadline());
    handles
        .into_iter()
        .map(|h| join_within(h, deadline()))
        .collect()
}

/// IO-5・TASK-19.2: 大文字小文字だけが違う 2 つの作成要求を同時に出すと
/// 一方だけが成功し、他方は衝突の構造化エラーになる。
#[test]
fn io5_concurrent_case_only_creates_one_is_rejected() {
    let dir = TempDir::new("gf-race");
    for round in 0..20 {
        let (creator, root) = creator_in(&dir, &format!("root-{round}"));
        let results = race(&creator, "Report.txt", "report.txt");
        let oks = results.iter().filter(|r| r.is_ok()).count();
        assert_eq!(oks, 1, "exactly one create must succeed");
        let err = results
            .iter()
            .find_map(|r| r.as_ref().err())
            .expect("exactly one create must fail");
        assert_eq!(err.code().as_str(), "ALREADY_EXISTS");
        assert!(
            err.message().starts_with("case-insensitive path collision"),
            "message: {}",
            err.message()
        );
        assert!(err.message().contains("Report.txt"));
        assert!(err.message().contains("report.txt"));
        assert_eq!(std::fs::read_dir(&root).expect("read_dir").count(), 1);
    }
}

/// IO-5・TASK-19.2（Codex P1 指摘）: 同じ共有ルートに別々の
/// [`GuestFileCreator`] インスタンス（プロセス間の競合を模す。`Mutex` は共有
/// しない）から大文字小文字だけが違う作成を同時に出しても、大小違いの項目が
/// 両方とも残ることはなく、成功した件数と残った項目の件数が一致する（作成後の
/// 再検証と取り消し。両方が取り消して 0 件になることは許容する）。大文字小文字を
/// 区別する FS でのみ両方の作成が通りうるため Linux 限定。
#[cfg(target_os = "linux")]
#[test]
fn io5_separate_instances_never_leave_both_case_variants() {
    let dir = TempDir::new("gf-xinst");
    for round in 0..50 {
        let root = dir.file_path(&format!("root-{round}"));
        std::fs::create_dir_all(&root).expect("root must be creatable");
        let a = Arc::new(GuestFileCreator::new(root.clone()).expect("creator a"));
        let b = Arc::new(GuestFileCreator::new(root.clone()).expect("creator b"));
        let barrier = Arc::new(Barrier::new(3));
        let handles: Vec<_> = [(a, "Report.txt"), (b, "report.txt")]
            .into_iter()
            .map(|(creator, path)| {
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier_wait_within(&barrier, deadline());
                    creator.create_file(path).map(|_| ())
                })
            })
            .collect();
        barrier_wait_within(&barrier, deadline());
        let results: Vec<Result<(), IoError>> = handles
            .into_iter()
            .map(|h| join_within(h, deadline()))
            .collect();
        let oks = results.iter().filter(|r| r.is_ok()).count();
        for err in results.iter().filter_map(|r| r.as_ref().err()) {
            assert_eq!(err.code(), IoErrorCode::AlreadyExists, "{err:?}");
            assert!(
                err.message().starts_with("case-insensitive path collision"),
                "message: {}",
                err.message()
            );
        }
        let survivors = std::fs::read_dir(&root).expect("read_dir").count();
        assert!(
            survivors <= 1,
            "round {round}: {survivors} entries survived"
        );
        assert_eq!(oks, survivors, "round {round}: results {results:?}");
    }
}

/// IO-5・IO-1・TASK-19.2: 作成した sink を `serve_connection` へつなぎ、
/// 書き込みがファイルへ到着順に反映され ACK が返る。
#[test]
fn io5_io1_created_sink_serves_writeback() {
    let dir = TempDir::new("gf-serve");
    let (creator, root) = creator_in(&dir, "root");
    // Windows は祖先付き作成を未実装（fail-closed）のため、ルート直下の名前を使う。
    // 書き込み経路の検証内容はディレクトリ深さに依存しない。
    let (guest_path, host_rel): (&str, &[&str]) =
        if cfg!(any(target_os = "linux", target_os = "macos")) {
            ("sub/Data.bin", &["sub", "Data.bin"])
        } else {
            ("Data.bin", &["Data.bin"])
        };
    let sink = creator.create_file(guest_path).expect("create");
    let (client_end, server_end) = duplex();
    let timeouts = WritebackTimeouts {
        recv: timeout(),
        send: timeout(),
    };
    let server = spawn_server(
        server_end,
        BatchConfig::new(2).expect("cfg"),
        sink,
        timeouts,
    );

    let bodies = vec![b"hello ".to_vec(), b"world".to_vec()];
    let mut client = PipelineClient::new(
        client_end,
        InFlightLimit::new(4).expect("limit"),
        NoopSendObserver,
    );
    send_all_writes(&mut client, &bodies, timeout());
    drain_acks(&mut client, bodies.len(), timeout());
    drop(client);
    let report = join_within(server, deadline());
    assert_eq!(report.stats.acks_sent, 2);

    let host_path = host_rel.iter().fold(root.clone(), |p, c| p.join(c));
    let written = std::fs::read(host_path).expect("read back");
    assert_eq!(written, b"hello world".to_vec());
}

/// IO-5・TASK-19.2: 脱出を試みるパスは拒否され、索引にも FS にも痕跡を残さない。
#[test]
fn io5_creator_rejects_escape_and_does_not_pollute_index() {
    let dir = TempDir::new("gf-escape");
    let (creator, root) = creator_in(&dir, "root");
    for path in [
        "../escape",
        "a/../../escape",
        "a\\..\\escape",
        "C:escape",
        "/abs",
    ] {
        let err = creator.create_file(path).err().expect("must be rejected");
        assert_eq!(err.code(), IoErrorCode::InvalidArgument, "path {path:?}");
    }
    assert_eq!(creator.tracked_len().expect("len"), 0);
    assert_eq!(std::fs::read_dir(&root).expect("read_dir").count(), 0);
    let parent = root.parent().expect("parent");
    assert_eq!(std::fs::read_dir(parent).expect("read_dir").count(), 1);
}
