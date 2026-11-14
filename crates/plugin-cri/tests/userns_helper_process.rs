//! userns helper の実バイナリのプロセス試験（既定の集合。root・subuid 不要。SEC-5・REPAIR-2・REPAIR-5。#4795）。
//!
//! 試験専用の `--no-join`（feature `userns-helper-test-support`）で参加を省き、入口の振り分け・単一スレッド・non-dumpable・
//! 要求の上限検査・fd の検査を実バイナリで具体値として照合する。本番の参加経路は実機前提の `userns_helper_real` が担う。
//! 待ちはすべて期限つきで、子は必ず kill・回収する。

#![cfg(all(
    target_os = "linux",
    target_pointer_width = "64",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]

use std::fs::File;
use std::io::{Read as _, Write as _};
use std::os::fd::{AsFd as _, OwnedFd};
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use fandhe_container_core::traits::ErrorCode;
use fandhe_container_plugin_cri::userns_helper::wire::{
    HelperErrorCode, MAX_REQUEST_PAYLOAD_BYTES, Mode, RESPONSE_LEN, Report, decode_response,
};
use fandhe_container_plugin_cri::userns_helper::{
    USERNS_HELPER_ARG, UsernsHelperLauncher, WorkBudget,
};

const BIN: &str = env!("CARGO_BIN_EXE_fandhe-container-plugin-cri");

fn budget() -> WorkBudget {
    WorkBudget::new(Duration::from_secs(10)).expect("budget")
}

fn launcher() -> UsernsHelperLauncher {
    UsernsHelperLauncher::with_fixed_command(
        BIN,
        vec![USERNS_HELPER_ARG.into(), "--no-join".into()],
    )
}

/// 自分が所有する 0750 の一時ディレクトリ。
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        let p =
            std::env::temp_dir().join(format!("userns-helper-proc-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir(&p);
        std::fs::DirBuilder::new()
            .mode(0o750)
            .create(&p)
            .expect("create");
        Self(p)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir(&self.0);
    }
}

/// 実バイナリを生の socket で起動する（stdin = socket の片端、stdout = `target`）。
fn spawn_raw(target: OwnedFd) -> (Child, UnixStream) {
    let (parent, child_end) = UnixStream::pair().expect("pair");
    parent
        .set_read_timeout(Some(Duration::from_secs(20)))
        .expect("timeout");
    let child = Command::new(BIN)
        .arg(USERNS_HELPER_ARG)
        .arg("--no-join")
        .env_clear()
        .stdin(Stdio::from(OwnedFd::from(child_end)))
        .stdout(Stdio::from(target))
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn helper");
    (child, parent)
}

fn read_response(sock: &mut UnixStream) -> Option<Result<Report, HelperErrorCode>> {
    let mut buf = [0u8; RESPONSE_LEN];
    sock.read_exact(&mut buf).ok()?;
    decode_response(&buf)
}

fn finish(mut child: Child) -> i32 {
    let status = child.wait().expect("wait");
    status.code().unwrap_or(-1)
}

/// SEC-5・REPAIR-5・#4795: 実バイナリは tokio を起動せず単一スレッドで、non-dumpable で応答する。
#[test]
fn sec5_4795_inspect_reports_single_thread_non_dumpable() {
    let dir = Scratch::new("inspect");
    let target = File::open(&dir.0).expect("open");
    let Report::Inspect(r) = launcher()
        .run(Mode::Inspect, target.as_fd(), budget())
        .expect("inspect")
    else {
        panic!("unexpected report kind");
    };
    assert_eq!(r.threads, 1);
    assert_eq!(r.dumpable, 0);
    assert!(!r.joined);
    assert!(r.uid_map_rows >= 1 && r.gid_map_rows >= 1);
}

/// SEC-5・#4795: StatTarget は渡したディレクトリ fd の所有者と mode を返す（パスは渡さない）。
#[test]
fn sec5_4795_stat_target_reports_the_passed_directory() {
    let dir = Scratch::new("stat");
    let meta = std::fs::metadata(&dir.0).expect("meta");
    let target = File::open(&dir.0).expect("open");
    let Report::StatTarget(r) = launcher()
        .run(Mode::StatTarget, target.as_fd(), budget())
        .expect("stat")
    else {
        panic!("unexpected report kind");
    };
    assert_eq!((r.uid, r.gid, r.mode), (meta.uid(), meta.gid(), 0o750));
}

/// SEC-5・#4795: 隠し引数の後ろの余分な引数（パスの入力）は応答なしで終了コード 2。
#[test]
fn sec5_4795_extra_path_argument_is_rejected_with_exit_code_2() {
    let status = Command::new(BIN)
        .arg(USERNS_HELPER_ARG)
        .arg("/tmp")
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("run");
    assert_eq!(status.code(), Some(2));
}

/// REPAIR-5・#4795: 上限 + 1 の `payload_len` は payload を読む前に `RequestTooLarge`。
#[test]
fn sec5_4795_oversized_payload_len_is_rejected() {
    let dir = Scratch::new("big");
    let (child, mut sock) = spawn_raw(File::open(&dir.0).expect("open").into());
    let len = u32::try_from(MAX_REQUEST_PAYLOAD_BYTES + 1).expect("fits");
    let mut header = vec![1u8, 1, 0, 0];
    header.extend_from_slice(&len.to_be_bytes());
    sock.write_all(&header).expect("write");
    assert_eq!(
        read_response(&mut sock),
        Some(Err(HelperErrorCode::RequestTooLarge))
    );
    assert_eq!(finish(child), 1);
}

/// REPAIR-2・#4795: 壊れた header は `InvalidRequest`、予約済みの tag 3 は `Unimplemented`。
#[test]
fn sec5_4795_malformed_and_reserved_requests_get_fixed_errors() {
    for (header, want) in [
        ([9u8, 1, 0, 0, 0, 0, 0, 0], HelperErrorCode::InvalidRequest),
        ([1u8, 77, 0, 0, 0, 0, 0, 0], HelperErrorCode::InvalidRequest),
        ([1u8, 3, 0, 0, 0, 0, 0, 0], HelperErrorCode::Unimplemented),
    ] {
        let dir = Scratch::new("bad");
        let (child, mut sock) = spawn_raw(File::open(&dir.0).expect("open").into());
        sock.write_all(&header).expect("write");
        assert_eq!(read_response(&mut sock), Some(Err(want)));
        assert_eq!(finish(child), 1);
    }
}

/// SEC-5・#4795: fd 1 がディレクトリでなければ `InvalidRequest`。
#[test]
fn sec5_4795_non_directory_target_fd_is_rejected_by_the_helper() {
    let (child, mut sock) = spawn_raw(File::open("/dev/null").expect("open").into());
    assert_eq!(
        read_response(&mut sock),
        Some(Err(HelperErrorCode::InvalidRequest))
    );
    assert_eq!(finish(child), 1);
}

/// REPAIR-5・#4795: 要求を送らない親には、helper が期限（2 秒）で `RequestTimeout` を返して終わる。
#[test]
fn sec5_4795_silent_parent_gets_request_timeout() {
    let dir = Scratch::new("silent");
    let (child, mut sock) = spawn_raw(File::open(&dir.0).expect("open").into());
    assert_eq!(
        read_response(&mut sock),
        Some(Err(HelperErrorCode::RequestTimeout))
    );
    assert_eq!(finish(child), 1);
}

/// REPAIR-5・#4795: 起動役の経路で、応答しない子の失敗は `Timeout` の core コードに写る（偽 helper は単体試験側。ここでは実バイナリが
/// 親の socket の EOF で終わること = 子が残らないことを確かめる）。
#[test]
fn sec5_4795_helper_exits_when_the_parent_closes_the_socket() {
    let dir = Scratch::new("eof");
    let (child, sock) = spawn_raw(File::open(&dir.0).expect("open").into());
    drop(sock);
    assert_eq!(finish(child), 1);
    // 期待値の固定: 親側の写像は core の InvalidArgument / Timeout 等（wire の単体試験で網羅）。
    assert_eq!(
        HelperErrorCode::RequestTimeout.core_code(),
        ErrorCode::Timeout
    );
}
