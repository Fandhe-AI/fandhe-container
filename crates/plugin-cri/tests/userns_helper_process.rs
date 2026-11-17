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
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, PermissionsExt as _};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use fandhe_container_core::traits::ErrorCode;
use fandhe_container_plugin_cri::userns_helper::wire::{
    HelperErrorCode, MAX_REQUEST_PAYLOAD_BYTES, Mode, RESPONSE_LEN, RemoveTarget, Report,
    decode_response,
};
use fandhe_container_plugin_cri::userns_helper::{
    USERNS_HELPER_ARG, UsernsHelperLauncher, WorkBudget,
};

#[path = "../../core/tests/support/reap.rs"]
mod reap;

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
fn spawn_raw(target: OwnedFd) -> (ChildGuard, UnixStream) {
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
    (ChildGuard(child), parent)
}

/// panic・期限切れでも子を kill して回収するガード（REPAIR-5）。
struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        reap::reap_or_report(&mut self.0, reap::reap_within());
    }
}

fn read_response(sock: &mut UnixStream) -> Option<Result<Report, HelperErrorCode>> {
    let mut buf = [0u8; RESPONSE_LEN];
    sock.read_exact(&mut buf).ok()?;
    decode_response(&buf)
}

/// 期限つきで終了を待つ。期限切れは panic（子は Drop で回収）。
fn finish(mut child: ChildGuard) -> i32 {
    let status = reap::wait_within(&mut child.0, Duration::from_secs(30)).expect("helper exit");
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
    let status = reap::run_within(
        Command::new(BIN)
            .arg(USERNS_HELPER_ARG)
            .arg("/tmp")
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null()),
        Duration::from_secs(30),
    )
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

/// REPAIR-2・#4795・#4847: 壊れた header は `InvalidRequest`、長さ 0 の tag 3（展開要求の固定部が無い）も `InvalidRequest`。
#[test]
fn sec5_4795_malformed_and_reserved_requests_get_fixed_errors() {
    for (header, want) in [
        ([9u8, 1, 0, 0, 0, 0, 0, 0], HelperErrorCode::InvalidRequest),
        ([1u8, 77, 0, 0, 0, 0, 0, 0], HelperErrorCode::InvalidRequest),
        ([1u8, 3, 0, 0, 0, 0, 0, 0], HelperErrorCode::InvalidRequest),
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

/// 木ごと消せる一時ディレクトリ（0555・0000 を含む木を作るため、後始末で権限を戻す）。
struct Tree(PathBuf);

impl Tree {
    fn new(tag: &str) -> Self {
        let p = std::env::temp_dir().join(format!("userns-helper-rm-{tag}-{}", std::process::id()));
        Self::wipe(&p);
        std::fs::create_dir(&p).expect("create");
        Self(p)
    }

    fn wipe(p: &std::path::Path) {
        // 権限を戻してから消す（失敗しても試験の結果は変えない）。
        if std::fs::symlink_metadata(p).is_err() {
            return;
        }
        let _ = std::process::Command::new("chmod")
            .args(["-R", "u+rwx"])
            .arg(p)
            .status();
        let _ = std::fs::remove_dir_all(p);
    }
}

impl Drop for Tree {
    fn drop(&mut self) {
        Self::wipe(&self.0);
    }
}

fn open_dir(p: &std::path::Path) -> File {
    File::open(p).expect("open dir")
}

/// SEC-5・OCI-7・#4800: Remove は fd で渡した親の直下の `rootfs` だけを木ごと消す（0555・0000 のディレクトリを含む）。
/// 親と、兄弟（`keep`）は残る。
#[test]
fn sec5_4800_remove_deletes_only_the_named_child_tree() {
    let t = Tree::new("ok");
    let parent = t.0.join("parent");
    let deep = parent.join("rootfs/a/b");
    std::fs::create_dir_all(&deep).expect("mkdir");
    std::fs::write(deep.join("f"), b"x").expect("write");
    std::fs::create_dir(parent.join("rootfs/a/ro")).expect("mkdir");
    std::fs::write(parent.join("rootfs/a/ro/g"), b"y").expect("write");
    std::fs::set_permissions(
        parent.join("rootfs/a/ro"),
        std::fs::Permissions::from_mode(0o555),
    )
    .expect("chmod");
    std::fs::create_dir(parent.join("rootfs/a/none")).expect("mkdir");
    std::fs::set_permissions(
        parent.join("rootfs/a/none"),
        std::fs::Permissions::from_mode(0o000),
    )
    .expect("chmod");
    std::fs::create_dir(parent.join("keep")).expect("mkdir");

    let target = open_dir(&parent);
    let r = launcher()
        .run(
            Mode::Remove(RemoveTarget::BundleRootfs),
            target.as_fd(),
            budget(),
        )
        .expect("remove");
    assert_eq!(r, Report::Removed);
    assert!(!parent.join("rootfs").exists());
    assert!(parent.join("keep").is_dir());
    assert!(parent.is_dir());
}

/// SEC-5・#4800: 対象の子が無くても成功する（冪等。kill 後の再実行が続きから消せる）。
#[test]
fn sec5_4800_remove_of_a_missing_child_is_ok() {
    let t = Tree::new("missing");
    let target = open_dir(&t.0);
    let r = launcher()
        .run(
            Mode::Remove(RemoveTarget::PullUnpack),
            target.as_fd(),
            budget(),
        )
        .expect("remove");
    assert_eq!(r, Report::Removed);
}

/// SEC-5・SEC-1・#4800: 対象の名前が木の外を指す symlink でも辿らない。リンク自体を unlink するだけで、リンク先は消えない
/// （木の外を消さない）。
#[test]
fn sec5_4800_remove_never_follows_a_symlinked_child() {
    let t = Tree::new("symlink");
    let outside = t.0.join("outside");
    std::fs::create_dir(&outside).expect("mkdir");
    std::fs::write(outside.join("precious"), b"keep").expect("write");
    let parent = t.0.join("parent");
    std::fs::create_dir(&parent).expect("mkdir");
    std::os::unix::fs::symlink(&outside, parent.join("rootfs")).expect("symlink");

    let target = open_dir(&parent);
    let r = launcher()
        .run(
            Mode::Remove(RemoveTarget::BundleRootfs),
            target.as_fd(),
            budget(),
        )
        .expect("remove");
    assert_eq!(r, Report::Removed);
    assert!(std::fs::symlink_metadata(parent.join("rootfs")).is_err());
    assert_eq!(
        std::fs::read(outside.join("precious")).expect("link target kept"),
        b"keep"
    );
}

/// REPAIR-2・SEC-5・#4800: Remove の payload の不整合（未知の対象）は `InvalidRequest` で、何も消さない。
#[test]
fn sec5_4800_remove_with_an_unknown_target_is_invalid_and_deletes_nothing() {
    let t = Tree::new("unknown");
    let parent = t.0.join("parent");
    std::fs::create_dir_all(parent.join("rootfs")).expect("mkdir");
    let (child, mut sock) = spawn_raw(open_dir(&parent).into());
    sock.write_all(&[1, 4, 0, 0, 0, 0, 0, 4, 9, 0, 0, 0])
        .expect("write");
    assert_eq!(
        read_response(&mut sock),
        Some(Err(HelperErrorCode::InvalidRequest))
    );
    assert_eq!(finish(child), 1);
    assert!(parent.join("rootfs").is_dir());
}

/// SEC-5・OCI-7・REPAIR-5・#4800: 本番の削除器（`UsernsTreeRemover`）が実バイナリの helper で bundle の `rootfs` を消し、
/// cri の注入点（`SubordinateTreeRemover`）の契約どおり不在の再実行も成功する。
#[test]
fn sec5_4800_remover_removes_the_tree_through_the_real_helper() {
    use fandhe_container_cri::adapter::ReleaseBudget;
    use fandhe_container_cri::bundle::{RemovalTarget, SubordinateTreeRemover};
    use fandhe_container_plugin_cri::userns_helper::UsernsTreeRemover;

    let t = Tree::new("remover");
    let parent = t.0.join("bundle");
    std::fs::create_dir_all(parent.join("rootfs/usr/bin")).expect("mkdir");
    std::fs::write(parent.join("rootfs/usr/bin/sh"), b"#!").expect("write");
    std::fs::write(parent.join("config.json"), b"{}").expect("write");

    let remover = UsernsTreeRemover::with_launcher_and_limit(launcher(), 2);
    let budget = ReleaseBudget::new().with_deadline(
        std::time::Instant::now()
            + fandhe_container_plugin_cri::userns_helper::JOIN_BUDGET
            + Duration::from_secs(30),
    );
    let dir = open_dir(&parent);
    remover
        .remove_child_tree(dir.as_fd(), RemovalTarget::BundleRootfs, &budget)
        .expect("remove");
    assert!(!parent.join("rootfs").exists());
    assert!(parent.join("config.json").is_file());
    remover
        .remove_child_tree(dir.as_fd(), RemovalTarget::BundleRootfs, &budget)
        .expect("idempotent");
}
// ---- 展開モード（#4847。OCI-1・OCI-2・SEC-5・REPAIR-2・REPAIR-5）----

use fandhe_container_oci::error::OciErrorCode;
use fandhe_container_oci::layer::DEFAULT_MAX_UNCOMPRESSED_LAYER_BYTES;
use fandhe_container_oci::layer::extract::ExtractLimits;
use fandhe_container_oci::reference::Digest;
use fandhe_container_plugin_cri::userns_helper::send_fds_for_test;
use fandhe_container_plugin_cri::userns_helper::wire::{
    EXTRACT_FD_TOKEN, ExtractLayerSpec, ExtractReport, ExtractRequest, ExtractSpecialBits,
    encode_extract_request,
};

const TAR_MEDIA: &str = "application/vnd.oci.image.layer.v1.tar";

/// 最小の ustar 1 エントリ（`container_grpc.rs` と同型）。
fn tar_entry(name: &str, mode: u32, data: &[u8], dir: bool) -> Vec<u8> {
    let mut h = [0u8; 512];
    let mut put = |off: usize, bytes: &[u8]| h[off..off + bytes.len()].copy_from_slice(bytes);
    put(0, name.as_bytes());
    put(100, format!("{mode:07o}\0").as_bytes());
    put(108, b"0000000\0");
    put(116, b"0000000\0");
    put(124, format!("{:011o}\0", data.len()).as_bytes());
    put(136, b"00000000000\0");
    put(148, b"        ");
    put(156, if dir { b"5" } else { b"0" });
    put(257, b"ustar\0");
    put(263, b"00");
    let sum: u32 = h.iter().map(|b| u32::from(*b)).sum();
    h[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    let mut out = h.to_vec();
    out.extend_from_slice(data);
    out.resize(512 + data.len().div_ceil(512) * 512, 0);
    out
}

/// dir `d/` と file `d/f`（"hello"）の非圧縮 tar（終端ブロックつき）。
fn sample_tar() -> Vec<u8> {
    let mut t = tar_entry("d/", 0o755, b"", true);
    t.extend(tar_entry("d/f", 0o644, b"hello", false));
    t.extend([0u8; 1024]);
    t
}

/// 自分が所有する 0600・nlink 1 の blob ファイル（`VerifiedLayerBlob` の信頼条件を満たす）。
fn write_blob(dir: &std::path::Path, bytes: &[u8]) -> File {
    let p = dir.join("blob");
    std::fs::write(&p, bytes).expect("write blob");
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).expect("chmod");
    File::open(&p).expect("open blob")
}

fn extract_request(tar: &[u8], digest: Digest) -> ExtractRequest {
    let size = u64::try_from(tar.len()).expect("fits");
    let layer = ExtractLayerSpec::new(TAR_MEDIA, size, digest.clone(), digest).expect("layer");
    ExtractRequest::new(
        ExtractSpecialBits::Strip,
        ExtractLimits::default(),
        DEFAULT_MAX_UNCOMPRESSED_LAYER_BYTES,
        vec![layer],
    )
    .expect("request")
}

/// SEC-5・OCI-1・#4847: 展開要求が往復する。blob の fd と展開先の fd だけを渡し（パスなし）、helper が再検証して展開する。
#[test]
fn sec5_4847_extract_round_trips_through_the_real_helper() {
    let t = Tree::new("extract-ok");
    let tar = sample_tar();
    let blob = write_blob(&t.0, &tar);
    let dest_path = t.0.join("dest");
    std::fs::create_dir(&dest_path).expect("mkdir");
    let dest = open_dir(&dest_path);
    let req = extract_request(&tar, Digest::sha256_of(&tar));
    let r = launcher()
        .run_extract_bounded(
            &req,
            &[blob.as_fd()],
            dest.as_fd(),
            None,
            budget(),
            None,
            None,
        )
        .expect("extract");
    assert_eq!(
        r,
        ExtractReport {
            layers: 1,
            entries: 2
        }
    );
    assert_eq!(
        std::fs::read(dest_path.join("d/f")).expect("read"),
        b"hello"
    );
    assert!(dest_path.join("d").is_dir());
}

/// SEC-5・SEC-1・#4849: 閉じ込めの祖先の fd は blob の通の後に別の通で渡り、helper が受けて展開を続ける
/// （`Strip` は祖先を使わないので、受け渡しの成立だけを見る。保持は実機前提試験 `userns_helper_real`）。
#[test]
fn sec5_4849_ancestor_fd_is_received_by_the_real_helper() {
    let t = Tree::new("extract-ancestor");
    let tar = sample_tar();
    let blob = write_blob(&t.0, &tar);
    let dest_path = t.0.join("dest");
    std::fs::create_dir(&dest_path).expect("mkdir");
    let dest = open_dir(&dest_path);
    let ancestor = open_dir(&t.0);
    let req = extract_request(&tar, Digest::sha256_of(&tar));
    let r = launcher()
        .run_extract_bounded(
            &req,
            &[blob.as_fd()],
            dest.as_fd(),
            Some(ancestor.as_fd()),
            budget(),
            None,
            None,
        )
        .expect("extract with an ancestor");
    assert_eq!(
        r,
        ExtractReport {
            layers: 1,
            entries: 2
        }
    );
    assert_eq!(
        std::fs::read(dest_path.join("d/f")).expect("read"),
        b"hello"
    );
}

/// SEC-5・OCI-1・#4847: blob の digest が要求と違うと、helper は `ExtractFailed(DataLoss)` を返し、展開先に何も書かない。
#[test]
fn sec5_4847_digest_mismatch_is_data_loss_and_writes_nothing() {
    let t = Tree::new("extract-bad-digest");
    let tar = sample_tar();
    let blob = write_blob(&t.0, &tar);
    let dest_path = t.0.join("dest");
    std::fs::create_dir(&dest_path).expect("mkdir");
    let dest = open_dir(&dest_path);
    let req = extract_request(&tar, Digest::sha256_of(b"something else"));
    let err = launcher()
        .run_extract_bounded(
            &req,
            &[blob.as_fd()],
            dest.as_fd(),
            None,
            budget(),
            None,
            None,
        )
        .expect_err("digest mismatch");
    assert_eq!(
        err.helper_code(),
        Some(HelperErrorCode::ExtractFailed(OciErrorCode::DataLoss))
    );
    assert_eq!(err.code(), ErrorCode::Internal);
    assert_eq!(std::fs::read_dir(&dest_path).expect("ls").count(), 0);
}

/// SEC-5・REPAIR-5・#4847: 要求の後に fd を送らない親には、helper が期限（2 秒）で `RequestTimeout` を返して終わる。
#[test]
fn sec5_4847_missing_fds_get_request_timeout() {
    let t = Tree::new("extract-nofds");
    let tar = sample_tar();
    let req = extract_request(&tar, Digest::sha256_of(&tar));
    let (child, mut sock) = spawn_raw(open_dir(&t.0).into());
    sock.write_all(encode_extract_request(&req).as_bytes())
        .expect("write frame");
    assert_eq!(
        read_response(&mut sock),
        Some(Err(HelperErrorCode::RequestTimeout))
    );
    assert_eq!(finish(child), 1);
}

/// SEC-5・REPAIR-5・#4847: fd の本数・token が要求と合わない通信は `InvalidRequest`（余分な fd は閉じられ、何も展開しない）。
#[test]
fn sec5_4847_wrong_fd_count_or_token_is_invalid() {
    let t = Tree::new("extract-count");
    let tar = sample_tar();
    let blob = write_blob(&t.0, &tar);
    let req = extract_request(&tar, Digest::sha256_of(&tar));
    // (token, 送る本数): 2 本（要求は 1 本）・token 違い・fd なしの通常 1 バイト。
    for (token, n) in [(EXTRACT_FD_TOKEN, 2usize), (0x01, 1), (EXTRACT_FD_TOKEN, 0)] {
        let dest_path = t.0.join(format!("dest-{token}-{n}"));
        std::fs::create_dir(&dest_path).expect("mkdir");
        let (child, mut sock) = spawn_raw(open_dir(&dest_path).into());
        sock.write_all(encode_extract_request(&req).as_bytes())
            .expect("write frame");
        if n == 0 {
            sock.write_all(&[token]).expect("write token");
        } else {
            let fds = vec![blob.as_fd(); n];
            send_fds_for_test(sock.as_fd(), token, &fds).expect("send fds");
        }
        assert_eq!(
            read_response(&mut sock),
            Some(Err(HelperErrorCode::InvalidRequest)),
            "token {token:#x} n {n}"
        );
        assert_eq!(finish(child), 1);
        assert_eq!(std::fs::read_dir(&dest_path).expect("ls").count(), 0);
    }
}

/// REPAIR-2・SEC-5・#4847: 壊れた展開要求の payload（予約・未知の media・所有者の方針・制限値・work_ms）は `InvalidRequest`。
#[test]
fn sec5_4847_malformed_extract_payloads_get_invalid_request() {
    let t = Tree::new("extract-malformed");
    let tar = sample_tar();
    let good = encode_extract_request(&extract_request(&tar, Digest::sha256_of(&tar)))
        .as_bytes()
        .to_vec();
    // offset は header 8 バイトを含む frame 先頭から（固定部 112 バイトの直後にレイヤーが続く。wire.rs の単体テストと同じ表）。
    let mutations: [(&str, usize, Vec<u8>); 8] = [
        ("reserved", 121, vec![1]),
        ("media 0", 120, vec![0]),
        ("media 7", 120, vec![7]),
        ("ownership 2", 8, vec![2]),
        ("special 0", 9, vec![0]),
        ("limit 0", 16, 0u64.to_be_bytes().to_vec()),
        ("limit over default", 16, u64::MAX.to_be_bytes().to_vec()),
        ("work 0", 12, vec![0, 0, 0, 0]),
    ];
    for (name, at, bytes) in mutations {
        let mut b = good.clone();
        b[at..at + bytes.len()].copy_from_slice(&bytes);
        let (child, mut sock) = spawn_raw(open_dir(&t.0).into());
        sock.write_all(&b).expect("write frame");
        assert_eq!(
            read_response(&mut sock),
            Some(Err(HelperErrorCode::InvalidRequest)),
            "{name}"
        );
        assert_eq!(finish(child), 1);
    }
}

/// SEC-5・OCI-1・OCI-7・REPAIR-5・#4848: 本番の展開器（`UsernsLayerExtractor`）が、cri の注入点の呼び出し（検証済み blob・
/// 展開先の `ExtractRoot`・範囲写像の展開設定）を実バイナリの helper（`--no-join`）へ橋渡しして展開する。
/// 写像は送らない（helper が参加に使うもの）ため、展開設定の値は `ChownInUserNamespace` であることだけが要る。
#[test]
fn sec5_4848_extractor_extracts_through_the_real_helper() {
    use fandhe_container_cri::adapter::ReleaseBudget;
    use fandhe_container_cri::bundle::SubordinateLayerExtractor as _;
    use fandhe_container_oci::layer::VerifiedLayerBlob;
    use fandhe_container_oci::layer::extract::{
        ExtractOptions, ExtractRoot, IdMap, IdRange, ImageLayer, OwnershipPolicy,
    };
    use fandhe_container_plugin_cri::userns_helper::UsernsLayerExtractor;

    let t = Tree::new("extractor-real");
    let tar = sample_tar();
    let _ = write_blob(&t.0, &tar);
    let digest = Digest::sha256_of(&tar);
    let owner = std::fs::metadata(t.0.join("blob")).expect("meta").uid();
    let blob = VerifiedLayerBlob::from_file(
        File::open(t.0.join("blob")).expect("open"),
        &digest,
        u64::try_from(tar.len()).expect("len"),
        owner,
    )
    .expect("verified");
    let root = ExtractRoot::create_private_dir(&t.0.join("root")).expect("root");
    let map = IdMap::new(vec![IdRange {
        container_id: 0,
        host_id: 100_000,
        count: 65_536,
    }])
    .expect("map");
    let opts = ExtractOptions::new().with_ownership(OwnershipPolicy::ChownInUserNamespace {
        uid: map.clone(),
        gid: map,
    });
    let ex = UsernsLayerExtractor::with_launcher_and_limit(launcher(), 2);
    let layers = [ImageLayer::new(&blob, TAR_MEDIA, &digest)];
    ex.extract_layers(
        &layers,
        &root,
        None,
        DEFAULT_MAX_UNCOMPRESSED_LAYER_BYTES,
        ExtractLimits::default(),
        &opts,
        &ReleaseBudget::new(),
    )
    .expect("extract");
    assert_eq!(std::fs::read(t.0.join("root/d/f")).expect("read"), b"hello");

    // 要求と違う digest の diff_id でも blob の digest 検証は通るが、blob の中身が違えば helper が `DataLoss` で拒否する。
    let other = Digest::sha256_of(b"something else");
    let bad = VerifiedLayerBlob::from_file(
        File::open(t.0.join("blob")).expect("open"),
        &digest,
        u64::try_from(tar.len()).expect("len"),
        owner,
    )
    .expect("verified");
    let root2 = ExtractRoot::create_private_dir(&t.0.join("root2")).expect("root2");
    let layers = [ImageLayer::new(&bad, TAR_MEDIA, &other)];
    let e = ex
        .extract_layers(
            &layers,
            &root2,
            None,
            DEFAULT_MAX_UNCOMPRESSED_LAYER_BYTES,
            ExtractLimits::default(),
            &opts,
            &ReleaseBudget::new(),
        )
        .expect_err("diff_id mismatch");
    assert_eq!(e.code(), OciErrorCode::DataLoss);
    assert_eq!(std::fs::read_dir(t.0.join("root2")).expect("ls").count(), 0);
}
