//! `ProductionPodHolder` の単体試験（既定の集合。偽の保持役は `/bin/sh -c` の短いスクリプトで、root・userns・supervisor の
//! bin は要らない。本物の bin での照合は実機前提の `tests/pod_holder_provider_real.rs`）。CRI-2・REPAIR-5・SEC-5・#2877。

use std::os::unix::fs::PermissionsExt as _;
use std::process::{Command, Stdio};

use fandhe_container_core::traits::types::ErrorCode;
use fandhe_container_cri::error::CriErrorCode;
use fandhe_container_supervisor::pod_holder::{NsId, PodHolderFrame};

use super::*;

fn sh(script: &str, limit: usize) -> ProductionPodHolder {
    ProductionPodHolder::with_fixed_program(
        PathBuf::from("/bin/sh"),
        vec!["-c".into(), script.into(), "sh".into()],
        false,
        limit,
    )
}

fn octal(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("\\{b:03o}")).collect()
}

fn ready_frame(pid: u32) -> String {
    let ns = |i| NsId { dev: 4, ino: i };
    let r = PodHolderReady::new(pid, ns(10), ns(11), ns(12)).unwrap();
    format!("printf '{}'", octal(PodHolderFrame::ready(&r).as_bytes()))
}

fn config() -> fandhe_container_cri::runtime::v1::PodSandboxConfig {
    fandhe_container_cri::runtime::v1::PodSandboxConfig::default()
}

fn req<'a>(
    id: &'a str,
    cfg: &'a fandhe_container_cri::runtime::v1::PodSandboxConfig,
    ready_ms: u64,
) -> PodHolderRequest<'a> {
    PodHolderRequest::new(id, cfg, Duration::from_millis(ready_ms))
}

fn scratch(name: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("fc-podholder-{}-{name}", std::process::id()));
    let _ = std::fs::remove_file(&p);
    p
}

fn proc_gone(pid: u32) -> bool {
    !Path::new(&format!("/proc/{pid}")).exists()
}

fn read_pid(path: &Path) -> u32 {
    std::fs::read_to_string(path)
        .unwrap()
        .trim()
        .parse()
        .unwrap()
}

/// stdin をパイプにした子を表へ入れる。
fn insert_child(p: &ProductionPodHolder, id: &str, script: &str) -> u32 {
    let mut c = Command::new("sh")
        .args(["-c", script])
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    let pid = c.id();
    let stdin = c.stdin.take();
    p.insert_for_test(id, c, stdin);
    pid
}

/// 何も書かない偽: 期限で `Timeout`、子は回収され、表は空に戻る。
#[test]
fn cri2_repair5_silent_holder_times_out_and_is_reaped() {
    let pidfile = scratch("silent");
    let p = sh(&format!("echo $$ >{}; exec cat", pidfile.display()), 8);
    let cfg = config();
    let t = Instant::now();
    let e = p.spawn(&req("s1", &cfg, 1000)).unwrap_err();
    assert_eq!(e.code(), CriErrorCode::Timeout);
    assert!(t.elapsed() < Duration::from_secs(3), "{:?}", t.elapsed());
    assert!(proc_gone(read_pid(&pidfile)));
    let table = p.table.lock().unwrap();
    assert_eq!(
        (
            table.entries.len(),
            table.spawning.len(),
            table.orphans.len()
        ),
        (0, 0, 0)
    );
    let _ = std::fs::remove_file(&pidfile);
}

/// READY の前に終わる偽は `FAILED_PRECONDITION`。ERROR フレームはそのコードで失敗する。
#[test]
fn cri2_early_exit_and_error_frame_map_to_codes() {
    let cfg = config();
    let e = sh("exit 3", 8).spawn(&req("s2", &cfg, 5000)).unwrap_err();
    assert_eq!(e.code(), CriErrorCode::FailedPrecondition);

    let frame = octal(PodHolderFrame::error(ErrorCode::PermissionDenied).as_bytes());
    let e = sh(&format!("printf '{frame}'; exec cat >/dev/null"), 8)
        .spawn(&req("s3", &cfg, 5000))
        .unwrap_err();
    assert_eq!(e.code(), CriErrorCode::PermissionDenied);
}

/// READY の pid が子の pid と違えば拒否し、子を SIGKILL して回収する。
#[test]
fn cri2_sec5_ready_pid_mismatch_is_rejected_and_child_reaped() {
    let pidfile = scratch("mismatch");
    let script = format!(
        "echo $$ >{}; {}; exec cat >/dev/null",
        pidfile.display(),
        ready_frame(4242)
    );
    let p = sh(&script, 8);
    let cfg = config();
    let e = p.spawn(&req("s4", &cfg, 5000)).unwrap_err();
    assert_eq!(e.code(), CriErrorCode::FailedPrecondition);
    assert_eq!(e.message(), MSG_PID_MISMATCH);
    assert!(proc_gone(read_pid(&pidfile)));
    assert!(p.table.lock().unwrap().entries.is_empty());
    let _ = std::fs::remove_file(&pidfile);
}

/// bin の検査: 開いた fd に対し、通常ファイルで自分（か root）所有・group/other 書き込み不可・読み取り可だけを通す。
#[test]
fn cri2_plug11_executable_trust_checks() {
    let euid = current_euid().unwrap();
    let path = scratch("trust");
    std::fs::write(&path, b"#!/bin/sh\n").unwrap();
    let set =
        |mode: u32| std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
    set(0o755);
    assert!(open_trusted_executable(&path, euid).is_ok());
    set(0o775);
    assert_eq!(
        open_trusted_executable(&path, euid).unwrap_err().message(),
        MSG_UNTRUSTED_EXE
    );
    set(0o757);
    assert!(open_trusted_executable(&path, euid).is_err());
    // root は読み取り権限を無視できるため、読めない場合の拒否は非 root のときだけ確かめる。
    set(0o300);
    if euid != 0 {
        assert!(open_trusted_executable(&path, euid).is_err());
    }
    set(0o755);
    assert!(open_trusted_executable(Path::new("/nonexistent/fc-holder"), euid).is_err());
    assert!(open_trusted_executable(Path::new("/"), euid).is_err());
    let _ = std::fs::remove_file(&path);
}

/// 祖先ディレクトリの検査: 全祖先が自分（か root）所有で group/other 書き込み不可のときだけ通す（PLUG-11）。
#[test]
fn cri2_plug11_ancestor_directories_must_not_be_writable_by_others() {
    let euid = current_euid().unwrap();
    let mut dir = std::env::temp_dir();
    dir.push(format!("fc-podholder-anc-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("sub")).unwrap();
    let exe = dir.join("sub").join("holder");
    std::fs::write(&exe, b"x").unwrap();
    let set = |p: &Path, mode: u32| {
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).unwrap()
    };
    set(&dir, 0o755);
    set(&dir.join("sub"), 0o755);
    // /tmp 自体が他者書き込み可（sticky）の環境では祖先全体は通らないため、検査対象を自作の部分に限って確かめる。
    let tmp_ok = check_ancestors_trust(&exe, euid).is_ok();
    set(&dir, 0o775);
    assert_eq!(
        check_ancestors_trust(&exe, euid).unwrap_err().message(),
        MSG_UNTRUSTED_EXE
    );
    set(&dir, 0o755);
    set(&dir.join("sub"), 0o757);
    assert!(check_ancestors_trust(&exe, euid).is_err());
    set(&dir.join("sub"), 0o755);
    assert_eq!(check_ancestors_trust(&exe, euid).is_ok(), tmp_ok);
    let _ = std::fs::remove_dir_all(&dir);
}

/// 検証した fd は、パスが差し替わった後でも元の実体を指す（`/proc/self/fd/N` で exec する前提。PLUG-11）。
#[test]
fn cri2_plug11_verified_fd_survives_path_replacement() {
    let euid = current_euid().unwrap();
    let path = scratch("swap");
    std::fs::write(&path, b"original").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    let file = open_trusted_executable(&path, euid).unwrap();
    std::fs::remove_file(&path).unwrap();
    std::fs::write(&path, b"replaced").unwrap();
    let via_fd = std::fs::read(format!("/proc/self/fd/{}", file.as_raw_fd())).unwrap();
    assert_eq!(via_fd, b"original");
    let _ = std::fs::remove_file(&path);
}

/// 回収できなかった子は sandbox ID 付きで保持され、`release` が SIGKILL と回収を再試行して追跡から外す（REPAIR-5・SEC-5）。
#[test]
fn cri2_repair5_orphan_is_kept_by_id_and_reaped_by_release() {
    let p = sh("exit 0", 8);
    let c = Command::new("sleep")
        .arg("30")
        .stdin(Stdio::null())
        .spawn()
        .unwrap();
    let pid = c.id();
    p.table.lock().unwrap().orphans.insert("o1".to_owned(), c);
    // 同じ ID の起動は拒否される（残存する子を見失わない）。
    let cfg = config();
    assert_eq!(
        p.spawn(&req("o1", &cfg, 1000)).unwrap_err().code(),
        CriErrorCode::AlreadyExists
    );
    p.release("o1", Duration::from_secs(2)).unwrap();
    assert!(p.table.lock().unwrap().orphans.is_empty());
    assert!(proc_gone(pid));
    // 冪等。
    p.release("o1", Duration::from_secs(1)).unwrap();
}

/// 起動失敗の `Err` が資源残存の印を運ぶ（回収できなかった子があるときだけ）。
#[test]
fn cri2_repair5_retained_flag_follows_orphan_presence() {
    let p = sh("exit 3", 8);
    let cfg = config();
    let e = p.spawn(&req("r1", &cfg, 1000)).unwrap_err();
    assert!(!e.resource_retained());
}

/// 上限と重複: 上限に達した追跡があれば `RESOURCE_EXHAUSTED`、同じ ID は `ALREADY_EXISTS`。解放後は上限を外れる。
#[test]
fn cri2_repair5_limit_and_duplicate() {
    let p = sh("exit 3", 1);
    insert_child(&p, "a", "cat >/dev/null");
    let cfg = config();
    let e = p.spawn(&req("b", &cfg, 1000)).unwrap_err();
    assert_eq!(e.code(), CriErrorCode::ResourceExhausted);
    assert_eq!(e.message(), MSG_TOO_MANY);
    let e = p.spawn(&req("a", &cfg, 1000)).unwrap_err();
    assert_eq!(e.code(), CriErrorCode::AlreadyExists);
    p.release("a", Duration::from_secs(5)).unwrap();
    // 上限の外れた後は、上限ではなく偽の保持役の失敗（exit 3）で落ちる。
    let e = p.spawn(&req("b", &cfg, 5000)).unwrap_err();
    assert_eq!(e.code(), CriErrorCode::FailedPrecondition);
}

/// 解放: stdin の EOF で終わる子は `Ok` で回収される。stdin を読まない子は期限で SIGKILL されて `Ok`。
#[test]
fn cri2_repair5_release_eof_then_kill() {
    let p = sh("exit 3", 8);
    let eof_pid = insert_child(&p, "eof", "cat >/dev/null");
    let t = Instant::now();
    p.release("eof", Duration::from_secs(5)).unwrap();
    assert!(t.elapsed() < Duration::from_secs(3));
    assert!(proc_gone(eof_pid));

    let deaf_pid = insert_child(&p, "deaf", "exec sleep 600");
    let t = Instant::now();
    p.release("deaf", Duration::from_secs(2)).unwrap();
    assert!(t.elapsed() < Duration::from_secs(4), "{:?}", t.elapsed());
    assert!(proc_gone(deaf_pid));
    assert!(p.liveness("deaf").is_err());

    // 未知の ID の解放は冪等で `Ok`。
    p.release("unknown", Duration::from_millis(100)).unwrap();
}

/// 生存の判定は回収しない: 終了済みの子は `Exited` で、その後も `/proc/<pid>` が残る。未知の ID は `NOT_FOUND`。
#[test]
fn cri2_sec5_liveness_does_not_reap() {
    let p = sh("exit 3", 8);
    let pid = insert_child(&p, "done", "exit 0");
    let mut seen = false;
    for _ in 0..500 {
        if p.liveness("done").unwrap() == PodHolderLiveness::Exited {
            seen = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(seen);
    assert_eq!(p.liveness("done").unwrap(), PodHolderLiveness::Exited);
    assert!(!proc_gone(pid));
    p.release("done", Duration::from_secs(2)).unwrap();
    assert!(proc_gone(pid));

    insert_child(&p, "live", "cat >/dev/null");
    assert_eq!(p.liveness("live").unwrap(), PodHolderLiveness::Alive);
    assert_eq!(
        p.liveness("nope").unwrap_err().code(),
        CriErrorCode::NotFound
    );
    p.release("live", Duration::from_secs(2)).unwrap();
}

/// REPAIR-5: cri が渡す期限（`PLUGIN_RUNTIME_TIMEOUT`）から回収分を引いても、保持役の READY の契約上の上限に足りる。
#[test]
fn repair5_pod_holder_ready_budget_covers_holder_waits() {
    assert!(crate::adapter::PLUGIN_RUNTIME_TIMEOUT - POD_HOLDER_KILL_REAP_WAIT >= READY_TIMEOUT);
}

/// CRI-2: 注入は実効 uid が 0 と確定したときだけ止める。
#[test]
fn cri2_inject_decision() {
    assert!(!should_inject_pod_holder::<()>(Ok(0)));
    assert!(should_inject_pod_holder::<()>(Ok(1000)));
    assert!(should_inject_pod_holder(Err(())));
}
