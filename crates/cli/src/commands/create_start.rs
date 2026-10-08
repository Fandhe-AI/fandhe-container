//! `create` / `start` コマンド本体（Linux は plugin を介さず core を直接呼ぶ。TASK-79.2.1・CLI-1・MS-6）。
//!
//! `commands::run` が argv を解析した後に [`run_create`] / [`run_start`] を呼ぶ。実処理は core の
//! `oci_runtime::create` / `oci_runtime::start`（OCI-4・OCI-5・TASK-29）へ委ね、入力の意味検証
//! （ID の文字種・bundle の絶対パス・bundle / rootfs の symlink 検査）も core の型と関数を唯一の判定とする。
//! 依存（状態ストア・launcher・計測器）は [`Runtime`] で注入できるようにし、単体テストではフェイクを差せる。
//!
//! 未実装・簡易実装（REPAIR-3）:
//! - 本番の [`ProcessLauncher`] はリポジトリ内に存在しない。そのため本番入口の `start` は
//!   [`UnavailableLauncher`] により fail-closed で `UNIMPLEMENTED` を返す。将来は supervisor 経由の
//!   起動（TASK-157・TASK-37〜39・CORE-1）に差し替え、起動済みプロセスの監視・回収を supervisor へ引き渡す。
//! - macOS / Windows は plugin 発見機構経由（TASK-79.4・PLUG-4）。ここでは core を呼ぶだけで、
//!   非 Linux では core 側が `Unimplemented` を返す（fail-closed）。

use std::sync::Arc;
use std::time::{Duration, Instant};

use fandhe_container_core::observability::{OpName, OpOutcome, OpRecorder};
use fandhe_container_core::oci_runtime::{
    LaunchSpec, LaunchedProcess, LifecycleOp, OciRuntimeError, ProcessLauncher, StartTimeouts,
    StartedContainer, create, start,
};
use fandhe_container_core::state_store::{FileStateStore, StateRoot};
use fandhe_container_core::traits::{
    ContainerId, CreateRequest, ErrorCode, StartRequest, StateRecord, StateStore, TraitError,
};

use super::CliExit;
use super::args::{CreateArgs, GlobalArgs, StartArgs};

/// core の操作へ注入する依存の束。
pub(super) struct Runtime {
    pub(super) store: Box<dyn StateStore>,
    pub(super) launcher: Arc<dyn ProcessLauncher>,
    pub(super) recorder: OpRecorder,
    pub(super) timeouts: StartTimeouts,
}

/// 本番の launcher。プロセス起動の本番実装がまだ無いため、常に `Unimplemented` で失敗する（REPAIR-3）。
///
/// core の `start` は launch 失敗時に予約を Created へ戻すため、状態は壊れない。将来仕様: supervisor 経由で
/// コンテナプロセスを起動する実装（TASK-157・TASK-37〜39・CORE-1）に置き換える。
struct UnavailableLauncher;

impl ProcessLauncher for UnavailableLauncher {
    fn launch(
        &self,
        _spec: &LaunchSpec,
        _timeout: Duration,
    ) -> Result<Box<dyn LaunchedProcess>, TraitError> {
        Err(TraitError::new(
            ErrorCode::Unimplemented,
            "process launcher is not available yet",
        ))
    }
}

/// 構築済みの要求で core の `create` を呼ぶ。
pub(super) fn create_container(
    rt: &Runtime,
    req: &CreateRequest,
) -> Result<StateRecord, OciRuntimeError> {
    create(rt.store.as_ref(), &rt.recorder, req)
}

/// 構築済みの要求で core の `start` を呼ぶ。起動済みプロセスのハンドルは呼び出し元へ返す
/// （監視・回収は呼び出し元の責務。CORE-1）。
pub(super) fn start_container(
    rt: &Runtime,
    req: &StartRequest,
) -> Result<StartedContainer, OciRuntimeError> {
    start(
        rt.store.as_ref(),
        &rt.recorder,
        &rt.launcher,
        req,
        &rt.timeouts,
    )
}

/// ID の文字種と bundle の絶対パスを core の型で検証する（相対パスの解決・canonicalize はしない。SEC-1）。
fn build_create_request(args: &CreateArgs) -> Result<CreateRequest, TraitError> {
    let id = ContainerId::new(args.id.as_str())?;
    CreateRequest::new(id, args.bundle.clone())
}

fn build_start_request(args: &StartArgs) -> Result<StartRequest, TraitError> {
    Ok(StartRequest::new(ContainerId::new(args.id.as_str())?))
}

/// 要求を構築し、状態ルートを解決して本番の依存を組む。要求構築が先なので、不正な入力では状態ルートを作らない。
/// いずれかの失敗は core に到達していないため、ここで `op_name` の失敗として記録する（REPAIR-4）。
fn production_runtime<R>(
    global: &GlobalArgs,
    recorder: OpRecorder,
    op_name: &str,
    started: Instant,
    build: impl FnOnce() -> Result<R, TraitError>,
) -> Result<(Runtime, R), TraitError> {
    let prepared = build().and_then(|req| {
        let root = StateRoot::resolve(global.root.clone())?;
        let store = FileStateStore::open(root)?;
        Ok((req, store))
    });
    match prepared {
        Ok((req, store)) => Ok((
            Runtime {
                store: Box::new(store),
                launcher: Arc::new(UnavailableLauncher),
                recorder,
                timeouts: StartTimeouts::default(),
            },
            req,
        )),
        Err(e) => {
            record_pre_core_failure(&recorder, op_name, started);
            export_ops(&recorder, std::env::var_os(OP_LOG_ENV).as_deref());
            Err(e)
        }
    }
}

/// core に到達する前の失敗を操作名 `op_name` の失敗として記録する（REPAIR-4）。
/// core に到達した操作は core 自身が記録するため、ここで二重には記録しない。
fn record_pre_core_failure(recorder: &OpRecorder, op_name: &str, started: Instant) {
    if let Ok(name) = OpName::new(op_name) {
        let _ = recorder.record(&name, OpOutcome::Failure, started.elapsed());
    }
}

/// 計測（`OpRecorder`）の JSON Lines 出力先を指す環境変数（REPAIR-4）。
///
/// OCI の stdout 契約（create / start は成功時に何も出さない）と stderr の 1 行エラー JSON を保つため、
/// 計測は stdout / stderr へ混ぜず、この環境変数が指すファイルへ追記する。未設定なら出力しない。
pub(super) const OP_LOG_ENV: &str = "FANDHE_CONTAINER_OP_LOG";

/// 計測出力の open に付ける O_NONBLOCK（REPAIR-5）。読み手のいない FIFO の open が無期限に
/// ブロックして CLI が結果を返せなくなるのを防ぐ。libc 非依存のため値を直書きする（Linux 限定）。
#[cfg(target_os = "linux")]
const O_NONBLOCK: i32 = 0o4000;

/// 最終要素が symlink なら open を失敗させる O_NOFOLLOW（SEC-1）。値は ABI ごとに異なる
/// （Linux の arm / arm64 は 0o100000、他の Linux アーキは 0o400000）。
#[cfg(all(target_os = "linux", any(target_arch = "aarch64", target_arch = "arm")))]
const O_NOFOLLOW: i32 = 0o100_000;
#[cfg(all(
    target_os = "linux",
    not(any(target_arch = "aarch64", target_arch = "arm"))
))]
const O_NOFOLLOW: i32 = 0o400_000;

/// ディレクトリ open に付ける O_DIRECTORY（SEC-1）。値は ABI ごとに異なる
/// （Linux の arm / arm64 は 0o40000、他の Linux アーキは 0o200000）。
#[cfg(all(target_os = "linux", any(target_arch = "aarch64", target_arch = "arm")))]
const O_DIRECTORY: i32 = 0o40_000;
#[cfg(all(
    target_os = "linux",
    not(any(target_arch = "aarch64", target_arch = "arm"))
))]
const O_DIRECTORY: i32 = 0o200_000;

/// 呼び出しプロセスの実効 UID（`/proc/self` の所有者で代用し、取得できなければ None）。
/// None のときは呼び出し側が計測出力を拒否する（fail-closed。SEC-1）。
#[cfg(target_os = "linux")]
fn effective_uid() -> Option<u32> {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata("/proc/self").ok().map(|m| m.uid())
}

/// 開いた fd に対する要素 `name` の `/proc/self/fd/<fd>/<name>` 経路を作る。
/// この経路は親 fd が指すディレクトリ直下の 1 要素だけを解決するため、パス文字列の再解決で
/// 親が差し替えられる競合（TOCTOU）が起きない。`openat` 相当を unsafe なしで実現する（SEC-1）。
#[cfg(target_os = "linux")]
fn child_via_fd(parent: &std::fs::File, name: &std::ffi::OsStr) -> std::path::PathBuf {
    use std::os::fd::AsRawFd;
    std::path::PathBuf::from(format!("/proc/self/fd/{}", parent.as_raw_fd())).join(name)
}

/// 開いた fd のディレクトリが、他ユーザーに差し替えられない状態かを fd から検査する（SEC-1）。
/// ディレクトリであり、所有者が root か自分で、group / other 書き込み可なら sticky bit を要する。
#[cfg(target_os = "linux")]
fn dir_trusted(dir: &std::fs::File, euid: u32) -> bool {
    use std::os::unix::fs::MetadataExt;
    let Ok(m) = dir.metadata() else {
        return false;
    };
    let mode = m.mode();
    let writable_by_others = mode & 0o022 != 0;
    let sticky = mode & 0o1000 != 0;
    let owner_ok = m.uid() == 0 || m.uid() == euid;
    m.is_dir() && owner_ok && (!writable_by_others || sticky)
}

/// `dir` 直下の要素 `name` を O_NOFOLLOW でディレクトリとして開く（親 fd 経由。SEC-1）。
#[cfg(target_os = "linux")]
fn open_dir_at(dir: &std::fs::File, name: &std::ffi::OsStr) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(O_NONBLOCK | O_NOFOLLOW | O_DIRECTORY)
        .open(child_via_fd(dir, name))
}

/// symlink を辿る回数の上限（ループ・過大な展開の防止）。
#[cfg(target_os = "linux")]
const MAX_SYMLINK_HOPS: u32 = 8;

/// 親ディレクトリを、ルートから 1 要素ずつディレクトリ fd で固定しながら開く（SEC-1）。
///
/// 各要素は直前に開いた fd 経由で O_NOFOLLOW | O_DIRECTORY で開き、開いた fd ごとに所有者・権限を
/// 検査する。パス全体を再解決しないため、検査と open の間に親を symlink へ差し替えられない。
/// root 所有の symlink（システム標準の `/var/run` 等）のみ、その場で内容を読んで同じ手順で
/// 辿る（root 所有のため一般ユーザーは差し替えられない）。`..` を含む経路は拒否する。
#[cfg(target_os = "linux")]
fn open_trusted_parent(parent: &std::path::Path, euid: u32) -> Option<std::fs::File> {
    use std::collections::VecDeque;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    use std::path::Component;

    /// `path` の各要素を `queue` の先頭へ順序を保って積み、絶対パスだったかを返す。
    fn push_components(
        queue: &mut VecDeque<std::ffi::OsString>,
        path: &std::path::Path,
    ) -> Option<bool> {
        let mut absolute = false;
        let mut names = Vec::new();
        for c in path.components() {
            match c {
                Component::RootDir => absolute = true,
                Component::Normal(n) => names.push(n.to_os_string()),
                Component::CurDir => {}
                Component::ParentDir | Component::Prefix(_) => return None,
            }
        }
        for n in names.into_iter().rev() {
            queue.push_front(n);
        }
        Some(absolute)
    }

    let abs = if parent.is_absolute() {
        parent.to_path_buf()
    } else {
        std::env::current_dir().ok()?.join(parent)
    };
    let open_root = || -> Option<std::fs::File> {
        let f = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(O_NONBLOCK | O_NOFOLLOW | O_DIRECTORY)
            .open("/")
            .ok()?;
        dir_trusted(&f, euid).then_some(f)
    };
    let mut queue = VecDeque::new();
    push_components(&mut queue, &abs)?;
    let mut cur = open_root()?;
    let mut hops = 0;
    while let Some(name) = queue.pop_front() {
        match open_dir_at(&cur, &name) {
            Ok(next) => {
                if !dir_trusted(&next, euid) {
                    return None;
                }
                cur = next;
            }
            Err(_) => {
                // symlink だった場合のみ、root 所有に限って辿る。それ以外は拒否する。
                let link = child_via_fd(&cur, &name);
                let m = std::fs::symlink_metadata(&link).ok()?;
                if !m.file_type().is_symlink() || m.uid() != 0 {
                    return None;
                }
                hops += 1;
                if hops > MAX_SYMLINK_HOPS {
                    return None;
                }
                let target = std::fs::read_link(&link).ok()?;
                if push_components(&mut queue, &target)? {
                    cur = open_root()?;
                }
            }
        }
    }
    Some(cur)
}

/// 計測出力先を非ブロッキングで開く。通常ファイル以外（FIFO・デバイス等）は拒否する。
///
/// Linux では、親ディレクトリをルートから fd で固定しながら開き（[`open_trusted_parent`]）、
/// その親 fd 経由で最終要素を O_NOFOLLOW で開く。開いたファイルの種別・ハードリンク数
/// （1 のみ許可）・所有者を fd から検証する（root 実行時に別ファイルへ追記させる攻撃の防止。SEC-1）。
#[cfg(target_os = "linux")]
fn open_op_log(path: &std::ffi::OsStr) -> Option<std::fs::File> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let path = std::path::Path::new(path);
    let name = path.file_name()?;
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => std::path::Path::new("."),
    };
    let euid = effective_uid()?;
    let dir = open_trusted_parent(parent, euid)?;
    let mut opts = std::fs::OpenOptions::new();
    opts.create(true)
        .append(true)
        .custom_flags(O_NONBLOCK | O_NOFOLLOW);
    let f = opts.open(child_via_fd(&dir, name)).ok()?;
    // open 後のハンドルで検証する（パスの事前検査による TOCTOU を避ける）。
    let m = f.metadata().ok()?;
    if m.is_file() && m.nlink() == 1 && m.uid() == euid {
        Some(f)
    } else {
        None
    }
}

/// Linux 以外（macOS・Windows）は、実効 UID の取得・symlink / junction / reparse point の
/// 安全な検査が未実装のため計測のファイル出力を拒否する（fail-closed。SEC-1・REPAIR-4）。
/// 将来は各 OS の安全な open 実装を `sys` モジュールに追加して対応する。
#[cfg(not(target_os = "linux"))]
fn open_op_log(_path: &std::ffi::OsStr) -> Option<std::fs::File> {
    None
}

/// 計測を `path` の通常ファイルへ追記する（best effort。失敗しても終了コード・エラー出力は変えない）。
///
/// open は O_NONBLOCK で行い、通常ファイル以外は拒否して書き込まない（REPAIR-5: 読み手のいない
/// FIFO 等で CLI が無期限にブロックしない）。
pub(super) fn export_ops(recorder: &OpRecorder, path: Option<&std::ffi::OsStr>) {
    let Some(path) = path.filter(|p| !p.is_empty()) else {
        return;
    };
    let Some(mut f) = open_op_log(path) else {
        return;
    };
    let _ = recorder.export_json_lines(Some(&mut f));
}

/// 本番入口の `create`。成功時は何も出さない（OCI の create 互換）。
///
/// 要求構築・状態ストア初期化の失敗も操作名 `create` の失敗として計測する（REPAIR-4）。
pub(super) fn run_create(global: &GlobalArgs, args: &CreateArgs) -> CliExit {
    let started = Instant::now();
    let recorder = OpRecorder::new();
    let result = production_runtime(global, recorder, "create", started, || {
        build_create_request(args)
    })
    .map_err(|e| OciRuntimeError::from_trait_error(LifecycleOp::Create, e))
    .and_then(|(rt, req)| {
        let r = create_container(&rt, &req);
        export_ops(&rt.recorder, std::env::var_os(OP_LOG_ENV).as_deref());
        r
    });
    match result {
        Ok(_) => CliExit::Success,
        Err(e) => CliExit::Runtime(e),
    }
}

/// 本番入口の `start`。
pub(super) fn run_start(global: &GlobalArgs, args: &StartArgs) -> CliExit {
    let started = Instant::now();
    let recorder = OpRecorder::new();
    let prepared = production_runtime(global, recorder, "start", started, || {
        build_start_request(args)
    })
    .map_err(|e| OciRuntimeError::from_trait_error(LifecycleOp::Start, e));
    let (rt, req) = match prepared {
        Ok(v) => v,
        Err(e) => return CliExit::Runtime(e),
    };
    let result = start_container(&rt, &req);
    export_ops(&rt.recorder, std::env::var_os(OP_LOG_ENV).as_deref());
    match result {
        // 本番 launcher（UnavailableLauncher）では到達しない。将来 launcher が差し替わっても、
        // 監視者へ引き渡せないまま CLI が終了して孤児プロセスを残さないよう、止めてから失敗を返す
        // （fail-closed）。supervisor への引き渡しは TASK-157。
        Ok(started) => {
            let (_record, process) = started.into_parts();
            let _ = process.terminate(rt.timeouts.terminate());
            CliExit::Runtime(OciRuntimeError::new(
                LifecycleOp::Start,
                ErrorCode::Internal,
                "no supervisor is available to take over the started process",
            ))
        }
        Err(e) => CliExit::Runtime(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn create_args(bundle: &str, id: &str) -> CreateArgs {
        CreateArgs {
            bundle: PathBuf::from(bundle),
            id: id.to_string(),
        }
    }

    /// CLI-1・ERR-2: 相対 bundle は INVALID_ARGUMENT（終了コード 2・op=create）で、core へ到達する前に拒否される。
    #[test]
    fn err2_build_create_rejects_relative_bundle() {
        let e = build_create_request(&create_args("rel/b", "c1")).expect_err("relative");
        let e = OciRuntimeError::from_trait_error(LifecycleOp::Create, e);
        assert_eq!(e.code(), ErrorCode::InvalidArgument);
        assert_eq!(e.exit_code().get(), 2);
        assert_eq!(e.op(), LifecycleOp::Create);
    }

    /// CLI-1・ERR-2: 不正な ID 文字は INVALID_ARGUMENT。
    #[test]
    fn err2_build_requests_reject_invalid_id() {
        for id in ["a/b", "..", "", "a b"] {
            let e = build_create_request(&CreateArgs {
                bundle: std::env::temp_dir(),
                id: id.to_string(),
            })
            .expect_err("id");
            assert_eq!(e.code(), ErrorCode::InvalidArgument);
            let e = build_start_request(&StartArgs { id: id.to_string() }).expect_err("id");
            assert_eq!(e.code(), ErrorCode::InvalidArgument);
        }
    }

    /// CLI-1: 正常な引数は core の要求型へ値をそのまま写す。
    #[test]
    fn cli1_build_create_request_keeps_values() {
        // OS ごとに絶対パスの形が違う（Windows は `/abs/b` を絶対と見なさない）ため temp_dir 由来にする。
        let bundle = std::env::temp_dir().join("abs-b");
        let req = build_create_request(&CreateArgs {
            bundle: bundle.clone(),
            id: "c1".to_string(),
        })
        .expect("ok");
        assert_eq!(req.id().as_str(), "c1");
        assert_eq!(req.bundle(), bundle.as_path());
    }

    /// REPAIR-4: 計測は指定ファイルへ JSON Lines で追記され、未指定なら何も書かない。
    /// Linux 以外は計測のファイル出力を拒否するため対象外（SEC-1）。
    #[cfg(target_os = "linux")]
    #[test]
    fn repair4_export_ops_appends_json_lines() {
        use fandhe_container_core::observability::{OpName, OpOutcome};
        let rec = OpRecorder::new();
        rec.record(
            &OpName::new("create").expect("name"),
            OpOutcome::Success,
            Duration::from_millis(1),
        )
        .expect("record");
        let path = std::env::temp_dir().join(format!("fc-cli-oplog-{}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        export_ops(&rec, None);
        assert!(!path.exists());
        export_ops(&rec, Some(path.as_os_str()));
        let text = std::fs::read_to_string(&path).expect("read");
        let _ = std::fs::remove_file(&path);
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("\"op_stats\""));
        assert!(lines[1].contains("\"op_stats_meta\""));
    }

    /// REPAIR-5: 計測出力先が FIFO でも `export_ops` がブロックせず、何も書き込まない。
    /// 読み手がいない場合と、読み手が open しただけで読まない場合の両方を具体値で検証する。
    #[cfg(target_os = "linux")]
    #[test]
    fn repair5_export_ops_rejects_fifo_without_blocking() {
        use fandhe_container_core::observability::{OpName, OpOutcome};
        use std::os::unix::fs::OpenOptionsExt;
        let rec = Arc::new(OpRecorder::new());
        rec.record(
            &OpName::new("create").expect("name"),
            OpOutcome::Success,
            Duration::from_millis(1),
        )
        .expect("record");
        let run = |path: std::path::PathBuf| {
            let (tx, rx) = std::sync::mpsc::channel();
            let rec = Arc::clone(&rec);
            std::thread::spawn(move || {
                export_ops(&rec, Some(path.as_os_str()));
                let _ = tx.send(());
            });
            rx.recv_timeout(Duration::from_secs(5))
                .expect("export_ops must not block on a FIFO");
        };
        let mkfifo = |name: &str| {
            let p =
                std::env::temp_dir().join(format!("fc-cli-oplog-{name}-{}", std::process::id()));
            let _ = std::fs::remove_file(&p);
            let st = std::process::Command::new("mkfifo")
                .arg(&p)
                .status()
                .expect("mkfifo");
            assert!(st.success());
            p
        };
        // 読み手なし。
        let p1 = mkfifo("noreader");
        run(p1.clone());
        let _ = std::fs::remove_file(&p1);
        // 読み手あり（open のみで読まない）。何も書かれていないこと。
        let p2 = mkfifo("idlereader");
        let reader = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(O_NONBLOCK)
            .open(&p2)
            .expect("open reader");
        run(p2.clone());
        let mut buf = [0u8; 16];
        let n = match std::io::Read::read(&mut &reader, &mut buf) {
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => 0,
            Err(e) => panic!("read: {e}"),
        };
        assert_eq!(n, 0);
        let _ = std::fs::remove_file(&p2);
    }

    /// SEC-1: 最終要素が symlink なら辿らず拒否し、リンク先は書き換えない。
    #[cfg(target_os = "linux")]
    #[test]
    fn sec1_open_op_log_rejects_symlink_and_hardlink() {
        let dir = std::env::temp_dir().join(format!("fc-cli-oplog-sec-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir");
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        }
        let victim = dir.join("victim");
        std::fs::write(&victim, "keep").expect("victim");
        let link = dir.join("link");
        std::os::unix::fs::symlink(&victim, &link).expect("symlink");
        assert!(open_op_log(link.as_os_str()).is_none());
        let hard = dir.join("hard");
        std::fs::hard_link(&victim, &hard).expect("hardlink");
        assert!(open_op_log(hard.as_os_str()).is_none());
        assert_eq!(std::fs::read_to_string(&victim).expect("read"), "keep");
        let fresh = dir.join("fresh");
        assert!(open_op_log(fresh.as_os_str()).is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// SEC-1: 信頼できない（非 root 所有の）親 symlink は辿らず拒否し、リンク先へ書かない。
    #[cfg(target_os = "linux")]
    #[test]
    fn sec1_open_op_log_rejects_parent_symlink() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("fc-cli-oplog-psym-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let real = dir.join("real");
        std::fs::create_dir_all(&real).expect("mkdir");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        let link = dir.join("linkdir");
        std::os::unix::fs::symlink(&real, &link).expect("symlink");
        assert!(open_op_log(link.join("log").as_os_str()).is_none());
        assert!(!real.join("log").exists());
        assert!(open_op_log(real.join("log").as_os_str()).is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// SEC-1: Linux 以外は計測のファイル出力を拒否し、ファイルを作らない（fail-closed）。
    #[cfg(not(target_os = "linux"))]
    #[test]
    fn sec1_open_op_log_refused_on_non_linux() {
        let path = std::env::temp_dir().join(format!("fc-cli-oplog-nl-{}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        assert!(open_op_log(path.as_os_str()).is_none());
        assert!(!path.exists());
    }

    /// REPAIR-4: 不正 ID（core 到達前の失敗）も操作名 create の失敗として 1 件計測される。
    #[test]
    fn repair4_pre_core_failure_is_recorded_once() {
        let rec = OpRecorder::new();
        record_pre_core_failure(&rec, "create", Instant::now());
        let snap = rec
            .snapshot_op(&OpName::new("create").expect("name"))
            .expect("snap");
        assert_eq!(snap.failure(), 1);
        assert_eq!(snap.success(), 0);
    }

    #[cfg(target_os = "linux")]
    mod linux {
        use super::*;
        use fandhe_container_core::traits::ContainerState;
        use std::num::NonZeroU32;
        use std::sync::atomic::{AtomicUsize, Ordering};

        /// テスト用の一意な一時ディレクトリ（Drop で削除）。
        struct TmpDir(PathBuf);

        impl TmpDir {
            fn new(tag: &str) -> Self {
                static SEQ: AtomicUsize = AtomicUsize::new(0);
                let n = SEQ.fetch_add(1, Ordering::SeqCst);
                let p =
                    std::env::temp_dir().join(format!("fc-cli-{tag}-{}-{n}", std::process::id()));
                std::fs::create_dir_all(&p).expect("mkdir");
                // 状態ルートの祖先は group / other 書き込み不可でなければならない（umask に依存せず 0700 に固定）。
                {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700))
                        .expect("chmod");
                }
                Self(p)
            }
        }

        impl Drop for TmpDir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }

        /// 有効な bundle（config.json と rootfs/）を作る。
        fn make_bundle(base: &TmpDir) -> PathBuf {
            let b = base.0.join("bundle");
            std::fs::create_dir_all(b.join("rootfs")).expect("rootfs");
            std::fs::write(
                b.join("config.json"),
                r#"{"ociVersion":"1.2.0","root":{"path":"rootfs"},"process":{"user":{"uid":0,"gid":0},"args":["/bin/echo","it"],"cwd":"/"},"linux":{"namespaces":[{"type":"pid"},{"type":"mount"},{"type":"user"},{"type":"uts"},{"type":"ipc"}]}}"#,
            )
            .expect("config");
            b
        }

        fn runtime(base: &TmpDir, launcher: Arc<dyn ProcessLauncher>) -> Runtime {
            let root = StateRoot::from_override(base.0.join("state")).expect("root");
            Runtime {
                store: Box::new(FileStateStore::open(root).expect("open")),
                launcher,
                recorder: OpRecorder::new(),
                timeouts: StartTimeouts::default(),
            }
        }

        struct FakeProcess;

        impl LaunchedProcess for FakeProcess {
            fn pid(&self) -> NonZeroU32 {
                NonZeroU32::new(4242).expect("nonzero")
            }
            fn wait(
                &self,
                _timeout: Duration,
            ) -> Result<Option<fandhe_container_core::oci_runtime::ProcessExit>, TraitError>
            {
                Ok(None)
            }
            fn terminate(&self, _timeout: Duration) -> Result<(), TraitError> {
                Ok(())
            }
        }

        struct FakeLauncher(AtomicUsize);

        impl ProcessLauncher for FakeLauncher {
            fn launch(
                &self,
                _spec: &LaunchSpec,
                _timeout: Duration,
            ) -> Result<Box<dyn LaunchedProcess>, TraitError> {
                self.0.fetch_add(1, Ordering::SeqCst);
                Ok(Box::new(FakeProcess))
            }
        }

        /// CLI-1・OCI-4: create は core を呼び、Created（pid なし）を記録する。同一 ID の再 create は ALREADY_EXISTS（4）。
        #[test]
        fn cli1_create_calls_core_and_rejects_duplicate() {
            let base = TmpDir::new("create");
            let bundle = make_bundle(&base);
            let rt = runtime(&base, Arc::new(UnavailableLauncher));
            let args = CreateArgs {
                bundle: bundle.clone(),
                id: "c1".into(),
            };
            let rec =
                create_container(&rt, &build_create_request(&args).expect("req")).expect("create");
            assert_eq!(rec.status().state(), ContainerState::Created);
            assert_eq!(rec.status().pid(), None);
            let e =
                create_container(&rt, &build_create_request(&args).expect("req")).expect_err("dup");
            assert_eq!(e.code(), ErrorCode::AlreadyExists);
            assert_eq!(e.exit_code().get(), 4);
            assert_eq!(e.op(), LifecycleOp::Create);
        }

        /// ERR-2: 未 create の ID の start は NOT_FOUND（3）で launcher を呼ばない。
        #[test]
        fn err2_start_unknown_id_is_not_found() {
            let base = TmpDir::new("notfound");
            let launcher = Arc::new(FakeLauncher(AtomicUsize::new(0)));
            let rt = runtime(&base, launcher.clone());
            let e = start_container(
                &rt,
                &build_start_request(&StartArgs { id: "nope".into() }).expect("req"),
            )
            .expect_err("nf");
            assert_eq!(e.code(), ErrorCode::NotFound);
            assert_eq!(e.exit_code().get(), 3);
            assert_eq!(launcher.0.load(Ordering::SeqCst), 0);
        }

        /// CLI-1・CORE-1: create → start で Running・launcher の返した pid が記録され、ハンドルが呼び出し元へ渡る。
        #[test]
        fn cli1_start_calls_core_and_hands_over_process() {
            let base = TmpDir::new("start");
            let bundle = make_bundle(&base);
            let launcher = Arc::new(FakeLauncher(AtomicUsize::new(0)));
            let rt = runtime(&base, launcher.clone());
            create_container(
                &rt,
                &build_create_request(&CreateArgs {
                    bundle,
                    id: "start-ok".into(),
                })
                .expect("req"),
            )
            .expect("create");
            let started = start_container(
                &rt,
                &build_start_request(&StartArgs {
                    id: "start-ok".into(),
                })
                .expect("req"),
            )
            .expect("start");
            assert_eq!(started.record().status().state(), ContainerState::Running);
            assert_eq!(started.record().status().pid(), NonZeroU32::new(4242));
            assert_eq!(started.process().pid().get(), 4242);
            assert_eq!(launcher.0.load(Ordering::SeqCst), 1);
        }

        /// REPAIR-3: 本番 launcher では start が UNIMPLEMENTED（8）で、状態は Created に戻る。
        #[test]
        fn repair3_unavailable_launcher_keeps_created() {
            let base = TmpDir::new("unavail");
            let bundle = make_bundle(&base);
            let rt = runtime(&base, Arc::new(UnavailableLauncher));
            create_container(
                &rt,
                &build_create_request(&CreateArgs {
                    bundle,
                    id: "unavail".into(),
                })
                .expect("req"),
            )
            .expect("create");
            let e = start_container(
                &rt,
                &build_start_request(&StartArgs {
                    id: "unavail".into(),
                })
                .expect("req"),
            )
            .expect_err("unimpl");
            assert_eq!(e.code(), ErrorCode::Unimplemented);
            assert_eq!(e.exit_code().get(), 8);
            let id = ContainerId::new("unavail").expect("id");
            let got = rt
                .store
                .get(&fandhe_container_core::traits::GetStateRequest::new(id))
                .expect("get");
            assert_eq!(got.status().state(), ContainerState::Created);
        }
    }
}
