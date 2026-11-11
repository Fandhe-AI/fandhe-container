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
    let ns = |i| NsId { dev: 4, ino: i };
    let ready = PodHolderReady::new(pid, ns(10), ns(11), ns(12)).unwrap();
    p.insert_for_test(id, c, stdin, ready);
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

/// bin が FIFO でも open がブロックせず拒否される（writer が居ない FIFO の blocking open は無期限。REPAIR-5）。
#[test]
fn cri2_repair5_fifo_executable_is_rejected_without_blocking() {
    let euid = current_euid().unwrap();
    let path = scratch("fifo");
    let _ = std::fs::remove_file(&path);
    let ok = Command::new("mkfifo")
        .arg(&path)
        .status()
        .unwrap()
        .success();
    assert!(ok);
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    let p2 = path.clone();
    std::thread::spawn(move || {
        let _ = tx.send(open_trusted_executable(&p2, euid).map(|_| ()));
    });
    let r = rx
        .recv_timeout(Duration::from_secs(10))
        .expect("open must not block on a FIFO");
    let err = r.unwrap_err();
    assert_eq!(err.code(), ErrorCode::FailedPrecondition);
    assert_eq!(err.message(), MSG_UNTRUSTED_EXE);
    let _ = std::fs::remove_file(&path);
}

/// `sys::O_NONBLOCK` が `None` の組では、FIFO でも通常ファイルでも open より前に固定文言で拒否される
/// （CRI-2・REPAIR-5・MVM-4・#4441）。`Some` の対照として通常ファイルは通る。
#[test]
fn cri2_repair5_mvm4_missing_o_nonblock_is_rejected_before_open() {
    let euid = current_euid().unwrap();
    let fifo = scratch("nonblock-fifo");
    let reg = scratch("nonblock-reg");
    let _ = std::fs::remove_file(&fifo);
    assert!(
        Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success()
    );
    std::fs::set_permissions(&fifo, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::write(&reg, b"x").unwrap();
    std::fs::set_permissions(&reg, std::fs::Permissions::from_mode(0o755)).unwrap();
    for path in [fifo.clone(), reg.clone()] {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(open_trusted_executable_with(&path, euid, None).map(|_| ()));
        });
        let err = rx
            .recv_timeout(Duration::from_secs(10))
            .expect("rejection must not block")
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::FailedPrecondition);
        assert_eq!(err.message(), MSG_NONBLOCK_UNSUPPORTED);
    }
    if let Some(flag) = crate::sys::O_NONBLOCK {
        assert!(open_trusted_executable_with(&reg, euid, Some(flag)).is_ok());
    }
    let _ = std::fs::remove_file(&fifo);
    let _ = std::fs::remove_file(&reg);
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
// ---- #4483: READY の保存と ns の fd を開く口（SEC-5・SEC-1・REPAIR-5・PLUG-11） ----

/// 偽の proc root の 1 pod 分の素材。`stage` の通常ファイルの (dev, ino) を READY の NsId にし、spawn 後に
/// `<root>/<pid>/ns/` へ rename（inode は保たれる）で置く。
struct Staged {
    stage: PathBuf,
    user: NsId,
    ipc: NsId,
    net: NsId,
}

fn nsid_of(path: &Path) -> NsId {
    let m = std::fs::metadata(path).unwrap();
    NsId {
        dev: m.dev(),
        ino: m.ino(),
    }
}

impl Staged {
    fn new(dir: &Path, tag: &str) -> Self {
        let stage = dir.join(format!("stage-{tag}"));
        std::fs::create_dir_all(&stage).unwrap();
        for n in ["user", "ipc", "net"] {
            std::fs::write(stage.join(n), tag).unwrap();
        }
        Self {
            user: nsid_of(&stage.join("user")),
            ipc: nsid_of(&stage.join("ipc")),
            net: nsid_of(&stage.join("net")),
            stage,
        }
    }

    /// 自分の pid を READY に入れる偽の保持役（`$$` を欄 A に出し、`tail` の後に stdin の EOF まで生きる）。
    fn script(&self, tail: &str) -> String {
        let f =
            PodHolderFrame::ready(&PodHolderReady::new(1, self.user, self.ipc, self.net).unwrap());
        let b = f.as_bytes();
        let (head, rest) = (octal(&b[..8]), octal(&b[16..]));
        format!(
            "printf '{head}'; p=$$; i=0; while [ $i -lt 8 ]; do printf \"\\\\$(printf '%03o' $(( (p >> (i*8)) & 255 )))\"; i=$((i+1)); done; printf '{rest}'; {tail}"
        )
    }

    fn provider(&self, tail: &str) -> ProductionPodHolder {
        sh(&self.script(tail), 8)
    }

    /// spawn 後の pid の ns ディレクトリへ stage を置く。
    fn place(&self, root: &Path, pid: u32) {
        let ns = root.join(pid.to_string()).join("ns");
        std::fs::create_dir_all(&ns).unwrap();
        for n in ["user", "ipc", "net"] {
            std::fs::rename(self.stage.join(n), ns.join(n)).unwrap();
        }
    }
}

fn spawn_at(p: &ProductionPodHolder, id: &str) -> u32 {
    let cfg = config();
    p.spawn(&req(id, &cfg, 5000)).unwrap().pid().get()
}

fn fd_id(fd: BorrowedFd<'_>) -> NsId {
    let f = File::from(fd.try_clone_to_owned().unwrap());
    let m = f.metadata().unwrap();
    NsId {
        dev: m.dev(),
        ino: m.ino(),
    }
}

fn unavail(e: &TraitError, msg: &str) {
    assert_eq!(e.code(), ErrorCode::Unavailable);
    assert_eq!(e.message(), msg);
}

/// 固定プログラムの保持役 2 つで、pod A と pod B の fd を取り違えない（受け入れ基準。SEC-5・SEC-1・#4483）。
#[test]
fn sec5_sec1_4483_two_fixed_holders_open_their_own_namespaces() {
    let root = scratch("4483-two");
    std::fs::create_dir_all(&root).unwrap();
    let (a, b) = (Staged::new(&root, "a"), Staged::new(&root, "b"));
    let (pa, pb) = (
        a.provider("exec cat >/dev/null"),
        b.provider("exec cat >/dev/null"),
    );
    let (ida, idb) = (spawn_at(&pa, "a"), spawn_at(&pb, "b"));
    a.place(&root, ida);
    b.place(&root, idb);
    assert_ne!(a.net, b.net);
    let fa = pa.open_pod_namespaces_at("a", &root).unwrap();
    assert_eq!((fa.user_id(), fa.net_id()), (a.user, a.net));
    assert_eq!((fd_id(fa.user()), fd_id(fa.net())), (a.user, a.net));
    let fb = pb.open_pod_namespaces_at("b", &root).unwrap();
    assert_eq!((fd_id(fb.user()), fd_id(fb.net())), (b.user, b.net));
    let (u, n) = fb.into_fds();
    assert_eq!(fd_id(u.as_fd()), b.user);
    assert_eq!(fd_id(n.as_fd()), b.net);
    pa.release("a", Duration::from_secs(2)).unwrap();
    pb.release("b", Duration::from_secs(2)).unwrap();
    let _ = std::fs::remove_dir_all(&root);
}

/// 別 pod の実体へ差し替えられた ns は (dev, ino) の不一致で拒否する。
#[test]
fn sec5_sec1_4483_swapped_namespace_is_rejected() {
    let root = scratch("4483-swap");
    std::fs::create_dir_all(&root).unwrap();
    let (a, b) = (Staged::new(&root, "a"), Staged::new(&root, "b"));
    let p = a.provider("exec cat >/dev/null");
    let pid = spawn_at(&p, "a");
    a.place(&root, pid);
    let ns = root.join(pid.to_string()).join("ns");
    std::fs::rename(b.stage.join("net"), ns.join("net")).unwrap();
    unavail(
        &p.open_pod_namespaces_at("a", &root).unwrap_err(),
        MSG_NS_IDENTITY_MISMATCH,
    );
    std::fs::rename(b.stage.join("user"), ns.join("user")).unwrap();
    unavail(
        &p.open_pod_namespaces_at("a", &root).unwrap_err(),
        MSG_NS_IDENTITY_MISMATCH,
    );
    p.release("a", Duration::from_secs(2)).unwrap();
    let _ = std::fs::remove_dir_all(&root);
}

/// ns のファイルが無ければ open の失敗で fail-closed。
#[test]
fn sec5_4483_missing_namespace_file_fails_closed() {
    let root = scratch("4483-missing");
    std::fs::create_dir_all(&root).unwrap();
    let a = Staged::new(&root, "a");
    let p = a.provider("exec cat >/dev/null");
    let pid = spawn_at(&p, "a");
    a.place(&root, pid);
    std::fs::remove_file(root.join(pid.to_string()).join("ns").join("net")).unwrap();
    unavail(
        &p.open_pod_namespaces_at("a", &root).unwrap_err(),
        MSG_NS_OPEN_FAILED,
    );
    p.release("a", Duration::from_secs(2)).unwrap();
    let _ = std::fs::remove_dir_all(&root);
}

/// 終了済みの保持役は、ファイルが残っていても拒否し、回収はしない（REPAIR-5・SEC-5）。
#[test]
fn sec5_repair5_4483_exited_holder_is_rejected_without_reaping() {
    let root = scratch("4483-exited");
    std::fs::create_dir_all(&root).unwrap();
    let a = Staged::new(&root, "a");
    let p = a.provider("exit 0");
    let pid = spawn_at(&p, "a");
    a.place(&root, pid);
    let mut seen = false;
    for _ in 0..500 {
        if p.liveness("a").unwrap() == PodHolderLiveness::Exited {
            seen = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(seen);
    unavail(
        &p.open_pod_namespaces_at("a", &root).unwrap_err(),
        MSG_NS_HOLDER_UNAVAILABLE,
    );
    assert!(!proc_gone(pid));
    p.release("a", Duration::from_secs(2)).unwrap();
    assert!(proc_gone(pid));
    let _ = std::fs::remove_dir_all(&root);
}

/// 未知・release 済み・解放中・orphans だけにある ID は不在扱い。
#[test]
fn sec5_4483_unknown_released_and_releasing_ids_fail_closed() {
    let root = scratch("4483-absent");
    std::fs::create_dir_all(&root).unwrap();
    let a = Staged::new(&root, "a");
    let p = a.provider("exec cat >/dev/null");
    unavail(
        &p.open_pod_namespaces_at("nope", &root).unwrap_err(),
        MSG_NS_HOLDER_UNAVAILABLE,
    );
    let pid = spawn_at(&p, "a");
    a.place(&root, pid);
    assert!(p.open_pod_namespaces_at("a", &root).is_ok());
    // 解放中（stdin を take 済み）を再現する。
    let taken = p
        .table
        .lock()
        .unwrap()
        .entries
        .get_mut("a")
        .unwrap()
        .stdin
        .take();
    drop(taken);
    unavail(
        &p.open_pod_namespaces_at("a", &root).unwrap_err(),
        MSG_NS_HOLDER_UNAVAILABLE,
    );
    p.release("a", Duration::from_secs(2)).unwrap();
    unavail(
        &p.open_pod_namespaces_at("a", &root).unwrap_err(),
        MSG_NS_HOLDER_UNAVAILABLE,
    );
    let orphan = Command::new("sh")
        .args(["-c", "exec sleep 600"])
        .spawn()
        .unwrap();
    p.table.lock().unwrap().orphans.insert("o".into(), orphan);
    unavail(
        &p.open_pod_namespaces_at("o", &root).unwrap_err(),
        MSG_NS_HOLDER_UNAVAILABLE,
    );
    let _ = p.release("o", Duration::from_secs(2));
    let _ = std::fs::remove_dir_all(&root);
}

/// 実 `/proc` の公開口: 自プロセスの ns の素性を READY に入れた偽の保持役（unshare しない子）で成功し、
/// 偽の NsId では不一致になる。
#[test]
fn sec5_4483_real_proc_open_matches_recorded_identity() {
    let own = |n: &str| nsid_of(Path::new(&format!("/proc/self/ns/{n}")));
    let (user, ipc, net) = (own("user"), own("ipc"), own("net"));
    let st = Staged {
        stage: PathBuf::new(),
        user,
        ipc,
        net,
    };
    let p = st.provider("exec cat >/dev/null");
    spawn_at(&p, "x");
    let f = p.open_pod_namespaces("x").unwrap();
    assert_eq!((f.user_id(), f.net_id()), (user, net));
    assert_eq!((fd_id(f.user()), fd_id(f.net())), (user, net));
    p.release("x", Duration::from_secs(2)).unwrap();

    let q = sh("exec cat >/dev/null", 8);
    insert_child(&q, "fake", "exec cat >/dev/null");
    unavail(
        &q.open_pod_namespaces("fake").unwrap_err(),
        MSG_NS_IDENTITY_MISMATCH,
    );
    q.release("fake", Duration::from_secs(2)).unwrap();
}

/// supervisor の bin の解決の共通口: 隣の固定名・0755 で成功し、0775・不在・親なしは拒否する（PLUG-11・#4483）。
#[test]
fn plug11_4483_supervisor_beside_resolution_is_shared() {
    let euid = current_euid().unwrap();
    let dir = scratch("4483-beside");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    let exe = dir.join("plugin");
    let sup = holder_executable_beside(&exe).unwrap();
    assert_eq!(
        open_supervisor_beside_at(&exe, euid)
            .err()
            .map(|e| e.code()),
        Some(ErrorCode::FailedPrecondition)
    );
    std::fs::write(&sup, b"#!/bin/sh\n").unwrap();
    std::fs::set_permissions(&sup, std::fs::Permissions::from_mode(0o755)).unwrap();
    // 祖先（temp_dir）が検査を通らない環境では成功を要求しない（環境依存の部分だけを分ける）。
    let tmp_ok = check_ancestors_trust(&sup, euid).is_ok();
    let r = open_supervisor_beside_at(&exe, euid);
    assert_eq!(r.is_ok(), tmp_ok);
    if let Ok(v) = r {
        let prog = v.command().get_program().to_string_lossy().into_owned();
        assert!(prog.starts_with("/proc/self/fd/"), "{prog}");
    }
    std::fs::set_permissions(&sup, std::fs::Permissions::from_mode(0o775)).unwrap();
    assert_eq!(
        open_supervisor_beside_at(&exe, euid)
            .err()
            .map(|e| e.message().to_owned()),
        Some(MSG_UNTRUSTED_EXE.to_owned())
    );
    assert!(open_supervisor_beside_at(Path::new("plugin"), euid).is_err());
    let _ = std::fs::remove_dir_all(&dir);
}
