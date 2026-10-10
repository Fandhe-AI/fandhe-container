//! rootless 起動での OCI Runtime ライフサイクル（`create` → `start` → `kill`）の結合試験と、検証できない
//! 既知条件の記録（CORE-6・SEC-5・MS-2・TASK-40.4・#190）。
//!
//! 部品ごとの結合試験（`rootless_id_map`〔40.1〕・`rootless_launch`〔40.2〕・`rootless_file_owner`〔40.3〕）に
//! 対し、本ファイルは公開 API の `oci_runtime::{create, start, kill}` を非 root ユーザーから通し、
//! 起動されたコンテナプロセスを「ホスト視点」で検査する。`oci_lifecycle.rs` の launcher は模擬で実プロセスも
//! namespace 分離も使わないため、その不足を補う。
//!
//! libtest はマルチスレッドで、マルチスレッドからの `CLONE_NEWUSER`・fork は拒否されるため
//! `harness = false` の単一スレッド `main` で動かす（`rootless_launch` と同じ理由）。非 Linux では
//! OS 非該当（skip ではない）として成功終了する。
//!
//! # 受入基準の解釈（REPAIR-3）
//! - 「非 root で一連のライフサイクルが成功する」は、create → start → kill を実行し、各段の状態・revision・
//!   観測記録（REPAIR-4）と、起動したプロセスのホスト視点の写像（`/proc/<pid>/uid_map`・`gid_map`・
//!   `status`）で照合する。検証できるのは **create / start / kill と、kill 直後の delete の拒否まで**で、
//!   Running → Stopped の遷移と停止後の delete の成功は未検証（下記「既知課題」）
//! - 制限ステージ（seccomp: TASK-38.2/38.3、Landlock: TASK-39.3/39.4）が未適用の間、`exec_entrypoint` は
//!   fail-closed で `Exited(126)` を返す。そのため長く動き続ける「実行中コンテナ」になれるのは
//!   `isolate_rootless_subordinate` を通った中間プロセスだけで、これを init の代役として使う。中間プロセスは
//!   `spawn_container` が exec 段まで到達して 126 で終わることを自身で確かめた後、stdin の EOF まで
//!   生き続ける（ディスパッチャが panic しても孤児が残らない）
//!
//! # 流れ
//! - ディスパッチャ: 一時 bundle（`config.json`・`rootfs/`）を排他的に作り、`start` へ渡す
//!   `ProcessLauncher` の実装（`RootlessLauncher`）が自身を `--scenario container ...` で再起動して
//!   代役 init とする。kill は保持している起動ハンドルへ送る `ProcessSignaler`（`HandleSignaler`）で行い、
//!   状態に記録された pid へ生の kill を送らない（SEC-1）
//! - モード `direct`: `single_id_mapping` と `IdMapWriter::Direct`。`uid_map` は `0 <euid> 1`
//! - モード `helper`（`FANDHE_CONTAINER_TEST_ID_HELPER=1` の時だけ）: `/etc/subuid`・`/etc/subgid` の
//!   範囲写像を `newuidmap` / `newgidmap` 経由で書く
//! - root で実行された場合は、plan が `host_root_identity_mapping` で拒否されること（SEC-5）だけを照合する
//!
//! # 実機前提テストとしての分離
//! 非特権 user namespace を許可するホストが必要。`-- --ignored` 指定時のみ実行し、未指定時は「ignored」を
//! 出力して成功終了する（ci.md「実機前提テスト」。CI 通過のための弱体化ではない）。CI の
//! `platform-ci` への組み込みは別 PR（ci.yml は infra-builder 担当・AppArmor 緩和の
//! `sudo sysctl` は root 権限コマンド）。実行された場合は拒否を含むあらゆる失敗を失敗として扱い、検証せずに
//! 成功する分岐は持たない。
//!
//! # 既知課題・未検証の条件（ホスト設定などで本テストが検証できない、または未実装で検証しないもの）
//! - AppArmor の `kernel.apparmor_restrict_unprivileged_userns=1`（Ubuntu 23.10 以降・24.04 の既定）:
//!   非特権 user namespace での写像書き込みやマウントが拒否され、`PermissionDenied` で失敗する。緩和は
//!   sysctl を 0 にするか AppArmor プロファイルの付与（いずれも root 権限が必要）。CI が緩和しているのは
//!   `unshare_isolation` のみ
//! - `user.max_user_namespaces=0`・ディストリ固有の `kernel.unprivileged_userns_clone=0`:
//!   `CLONE_NEWUSER` が EPERM になる
//! - helper ケースの前提: `uidmap` パッケージ（setuid または file capability を持つ `newuidmap` /
//!   `newgidmap`）と、`/etc/subuid`・`/etc/subgid` の自ユーザー行。opt-in 時に無ければ失敗とする
//! - Docker コンテナ内（`make docker-ci` 等）: 既定の seccomp プロファイルが `CLONE_NEWUSER` を遮断し、
//!   マスクされた `/proc` で proc マウントも拒否されるため検証できない
//! - rootless の cgroup v2 委譲（systemd ユーザー slice の Delegate）: rootless 経路での cgroup 参加は
//!   未実装・未検証（TASK-32・CORE-3・CORE-4）
//! - 実エントリポイントの exec: 制限ステージ適用（TASK-38.2/38.3・TASK-39.3/39.4。Landlock は ABI 6+ =
//!   Linux 6.12+ が必要）まで拒否されるため代役 init を使う。適用後は、動き続ける実エントリポイントの pid を
//!   対象にするよう置き換える
//! - SIGKILL 以外のシグナル（SIGTERM 等）の配送: 本テストの起動ハンドルが std のみで作られており送れない。
//!   本番の `ProcessSignaler` は supervisor（TASK-157）が提供する
//! - Running → Stopped の遷移と停止後の delete の成功: Stopped への遷移は起動ハンドルの所有者である
//!   supervisor（TASK-157）の責務。`kill` が状態を更新しない契約と、その結果 kill 直後の delete
//!   （TASK-30.2・#152）が `FailedPrecondition` で拒否され状態が残ることだけを照合し、状態の書き換えに
//!   よる代用はしない（停止後の delete の成功は `oci_lifecycle.rs`・`oci_delete.rs` が状態を直接作って
//!   照合する）。supervisor の実装後に本テストへ追加する
//! - SEC-1 契約からの逸脱（テスト専用）: 固定した rootfs の fd は CLOEXEC で閉じられ、std だけでは子へ
//!   継承できない。そのため子の側で `spec.rootfs()` を stat し、渡された (dev, ino) と一致することを
//!   確かめてから使う。本番 launcher（TASK-29・TASK-157 系）は fd を渡す

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("rootless: Linux only, not applicable on this OS");
}

#[cfg(target_os = "linux")]
fn main() {
    if std::env::args().any(|a| a == "--ignored" || a == "--scenario") {
        linux::run();
    } else {
        println!("rootless: ignored (real-machine test; run with `-- --ignored`, see AGENTS.md)");
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::collections::HashMap;
    use std::io::{BufRead as _, Read as _, Write as _};
    use std::num::NonZeroU32;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    use std::os::unix::process::ExitStatusExt as _;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, ExitStatus, Stdio};
    use std::sync::mpsc;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use fandhe_container_core::exec::{
        ChildExit, Entrypoint, Hostname, IsolationConfig, IsolationPrivilege, Namespace,
        NamespaceSet, isolate_rootless_subordinate, plan_rootless_subordinate, spawn_container,
    };
    use fandhe_container_core::observability::{OpName, OpRecorder};
    use fandhe_container_core::oci_runtime::{
        CgroupRemoval, ContainerCgroupRemover, KillTimeout, LaunchSpec, LaunchedProcess,
        ProcessExit, ProcessLauncher, ProcessSignaler, StartTimeouts, create, delete, kill, start,
    };
    use fandhe_container_core::rootless::{
        DEFAULT_HELPER_TIMEOUT, HelperPaths, IdMapSet, IdMapWriter, SubIdOwner, WriterKind,
        load_subordinate_ids, rootless_mapping, single_id_mapping,
    };
    use fandhe_container_core::traits::{
        CgroupScope, ContainerId, ContainerState, CreateRequest, CreateStateRequest, DeleteRequest,
        DeleteStateRequest, DeleteStateResponse, ErrorCode, GetStateRequest, KillRequest,
        ListStateRequest, Signal, StartRequest, StateList, StateRecord, StateRevision, StateStore,
        TraitError, UpdateStateRequest,
    };

    const HOSTNAME: &str = "fandhe-rootless";
    const READY_LINE: &str = "READY exec=126";
    /// READY 行・stderr の読み取り上限（バイト）。無制限確保を避ける。
    const LINE_CAP: u64 = 256;
    const STDERR_CAP: u64 = 16 * 1024;

    /// 環境変数で受け付ける上限（秒）。start の全体上限 `DEFAULT_HELPER_TIMEOUT * 2 + t * 2` が
    /// `StartTimeouts::new` の 600 秒上限を超えないよう 295 秒で打ち切る。
    const MAX_TIMEOUT_SECS: u64 = 295;

    fn timeout() -> Duration {
        let secs = std::env::var("FANDHE_CONTAINER_TEST_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|s| (1..=MAX_TIMEOUT_SECS).contains(s))
            .unwrap_or(10);
        Duration::from_secs(secs)
    }

    fn own_ids() -> (u32, u32) {
        let id = |key: &str| -> u32 {
            std::fs::read_to_string("/proc/self/status")
                .expect("read status")
                .lines()
                .find(|l| l.starts_with(key))
                // 第 1 欄は real ID、第 2 欄が effective ID（兄弟テスト・plan_rootless_subordinate と同じ）。
                .and_then(|l| l.split_whitespace().nth(2))
                .and_then(|v| v.parse().ok())
                .expect("parse id")
        };
        (id("Uid:"), id("Gid:"))
    }

    fn helper_requested() -> bool {
        std::env::var("FANDHE_CONTAINER_TEST_ID_HELPER").as_deref() == Ok("1")
    }

    fn config() -> IsolationConfig {
        IsolationConfig {
            namespaces: NamespaceSet::empty()
                .with(Namespace::Pid)
                .with(Namespace::Mount)
                .with(Namespace::Uts)
                .with(Namespace::Ipc)
                .with(Namespace::User),
            hostname: Some(Hostname::new(HOSTNAME).expect("hostname")),
        }
    }

    fn helper_mappings(euid: u32, egid: u32) -> (IdMapSet, IdMapSet) {
        let name = std::env::var("USER").ok();
        let uowner = SubIdOwner::new(euid, name.clone()).expect("uid owner");
        let gowner = SubIdOwner::new(egid, name).expect("gid owner");
        let uranges =
            load_subordinate_ids(Path::new("/etc/subuid"), &uowner).expect("load /etc/subuid");
        let granges =
            load_subordinate_ids(Path::new("/etc/subgid"), &gowner).expect("load /etc/subgid");
        assert!(
            !uranges.is_empty() && !granges.is_empty(),
            "helper case requires subuid/subgid entries for the current user"
        );
        (
            rootless_mapping(euid, &uranges).expect("uid range mapping"),
            rootless_mapping(egid, &granges).expect("gid range mapping"),
        )
    }

    /// 経路（`direct` / `helper`）ごとの UID・GID 写像と書き込み経路。
    fn mappings_for(
        mode: &str,
        euid: u32,
        egid: u32,
    ) -> (IdMapSet, IdMapSet, IdMapWriter, WriterKind) {
        match mode {
            "direct" => (
                single_id_mapping(euid).expect("uid mapping"),
                single_id_mapping(egid).expect("gid mapping"),
                IdMapWriter::Direct,
                WriterKind::Direct,
            ),
            "helper" => {
                let (u, g) = helper_mappings(euid, egid);
                assert!(u.entries().len() >= 2 && g.entries().len() >= 2);
                let paths = HelperPaths::system_default().expect("newuidmap/newgidmap");
                (u, g, IdMapWriter::Helper(paths), WriterKind::Helper)
            }
            other => panic!("unknown mode {other}"),
        }
    }

    pub fn run() {
        let args: Vec<String> = std::env::args().collect();
        match args.iter().position(|a| a == "--scenario") {
            Some(i) => {
                let rest: Vec<&str> = args.iter().skip(i + 1).map(String::as_str).collect();
                container_scenario(&rest);
            }
            None => dispatcher(),
        }
    }

    // ---- シナリオ側（分離された代役 init） ----

    /// 引数: `container <rootfs> <hostname> <dev> <ino> <direct|helper>`。失敗はすべて panic
    /// （非 0 終了。launcher 側は READY 未着として `Err` にする）。
    fn container_scenario(args: &[&str]) {
        let [name, rootfs, hostname, dev, ino, mode] = args else {
            panic!("usage: container <rootfs> <hostname> <dev> <ino> <direct|helper>");
        };
        assert_eq!(*name, "container");
        let rootfs = Path::new(rootfs);
        let want_dev: u64 = dev.parse().expect("dev");
        let want_ino: u64 = ino.parse().expect("ino");
        let (euid, egid) = own_ids();
        let (uid, gid, writer, want_kind) = mappings_for(mode, euid, egid);

        let cfg = IsolationConfig {
            hostname: Some(Hostname::new(*hostname).expect("hostname")),
            ..config()
        };
        let plan = plan_rootless_subordinate(
            &cfg,
            uid.clone(),
            gid.clone(),
            writer,
            DEFAULT_HELPER_TIMEOUT,
        )
        .unwrap_or_else(|e| panic!("plan failed: {e}"));
        let report =
            isolate_rootless_subordinate(&plan).unwrap_or_else(|e| panic!("isolate failed: {e}"));
        assert_eq!(
            report.isolation.privilege,
            IsolationPrivilege::RootlessSubordinateIds
        );
        assert_eq!(report.id_maps.writer, want_kind);
        assert_eq!(report.id_maps.uid, uid);
        assert_eq!(report.id_maps.gid, gid);
        // namespace 内ではコンテナ root（uid 0・gid 0）に見える（SEC-5）。
        assert_eq!(own_ids(), (0, 0));

        // テスト専用の逸脱（冒頭の「既知課題」参照）: 固定 fd の代わりに (dev, ino) で同一性を確かめる。
        let meta = std::fs::metadata(rootfs).expect("stat rootfs");
        assert_eq!((meta.dev(), meta.ino()), (want_dev, want_ino));

        let entry = Entrypoint::new("/entry", ["/entry"], [] as [&str; 0]).expect("entrypoint");
        let child =
            spawn_container(rootfs, &entry).unwrap_or_else(|e| panic!("spawn_container: {e}"));
        let exit = child
            .wait_timeout(timeout())
            .unwrap_or_else(|e| panic!("wait: {e}"));
        // 制限ステージ未実装の間は exec だけが拒否される（126）。setup 失敗（125）ではない。
        assert_eq!(exit, ChildExit::Exited(126));

        let mut out = std::io::stdout();
        writeln!(out, "{READY_LINE}").expect("write READY");
        out.flush().expect("flush READY");

        // 代役 init: stdin が EOF になる（launcher・ディスパッチャが消える）まで生き続ける。
        let mut buf = [0u8; 64];
        let mut stdin = std::io::stdin();
        while stdin.read(&mut buf).map(|n| n > 0).unwrap_or(false) {}
    }

    // ---- launcher 側（ディスパッチャ内で start が呼ぶ） ----

    /// 代役 init の子プロセスのハンドル。回収済みかを自前で管理する（`Child::kill` は回収済みにも `Ok`
    /// を返すため pid 再利用対策の判定は自前で行う。SEC-1）。
    struct StandInProcess {
        pid: NonZeroU32,
        inner: Mutex<(Child, Option<ExitStatus>)>,
    }

    fn to_exit(status: ExitStatus) -> ProcessExit {
        match (status.code(), status.signal()) {
            (Some(code), _) => ProcessExit::Exited(code),
            (None, Some(sig)) => ProcessExit::Signaled(sig),
            (None, None) => ProcessExit::Exited(-1),
        }
    }

    impl StandInProcess {
        fn reap_until(&self, deadline: Instant) -> Result<Option<ExitStatus>, TraitError> {
            loop {
                {
                    let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
                    if let Some(st) = g.1 {
                        return Ok(Some(st));
                    }
                    match g.0.try_wait() {
                        Ok(Some(st)) => {
                            g.1 = Some(st);
                            return Ok(Some(st));
                        }
                        Ok(None) => {}
                        Err(_) => {
                            return Err(TraitError::new(
                                ErrorCode::Internal,
                                "failed to wait for the stand-in process",
                            ));
                        }
                    }
                }
                if Instant::now() >= deadline {
                    return Ok(None);
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    }

    impl LaunchedProcess for StandInProcess {
        fn pid(&self) -> NonZeroU32 {
            self.pid
        }

        fn wait(&self, timeout: Duration) -> Result<Option<ProcessExit>, TraitError> {
            Ok(self.reap_until(Instant::now() + timeout)?.map(to_exit))
        }

        fn terminate(&self, timeout: Duration) -> Result<(), TraitError> {
            {
                let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
                if g.1.is_none() {
                    let _ = g.0.kill();
                }
            }
            match self.reap_until(Instant::now() + timeout)? {
                Some(_) => Ok(()),
                None => Err(TraitError::new(
                    ErrorCode::Timeout,
                    "the stand-in process was not reaped within the timeout",
                )),
            }
        }

        fn signal(&self, signal: Signal, deadline: Instant) -> Result<(), TraitError> {
            let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            if Instant::now() >= deadline {
                return Err(TraitError::new(
                    ErrorCode::Timeout,
                    "the signal deadline has passed",
                ));
            }
            let gone = || {
                TraitError::new(
                    ErrorCode::FailedPrecondition,
                    "the container process has already exited",
                )
            };
            if g.1.is_some() {
                return Err(gone());
            }
            match g.0.try_wait() {
                Ok(Some(st)) => {
                    g.1 = Some(st);
                    return Err(gone());
                }
                Ok(None) => {}
                Err(_) => {
                    return Err(TraitError::new(
                        ErrorCode::Internal,
                        "failed to poll the stand-in process",
                    ));
                }
            }
            if signal != Signal::SIGKILL {
                return Err(TraitError::new(
                    ErrorCode::Unimplemented,
                    "only SIGKILL can be sent without libc",
                ));
            }
            g.0.kill().map_err(|_| {
                TraitError::new(ErrorCode::Internal, "failed to kill the stand-in process")
            })
        }
    }

    /// 自身を `--scenario container ...` で再起動し、代役 init を起動する launcher（テスト専用）。
    ///
    /// SEC-1 契約からの逸脱と理由は冒頭の「既知課題」を参照（rootfs は (dev, ino) の照合で代替）。
    struct RootlessLauncher {
        mode: &'static str,
    }

    fn launch_failed(child: &mut Child, code: ErrorCode, msg: &'static str) -> TraitError {
        // 契約: 失敗時にプロセスを残さない。
        let _ = child.kill();
        let _ = child.wait();
        TraitError::new(code, msg)
    }

    impl ProcessLauncher for RootlessLauncher {
        fn launch(
            &self,
            spec: &LaunchSpec,
            timeout: Duration,
        ) -> Result<Box<dyn LaunchedProcess>, TraitError> {
            let pinned =
                std::fs::File::from(spec.rootfs_dir().as_fd().try_clone_to_owned().map_err(
                    |_| TraitError::new(ErrorCode::Internal, "pinned rootfs fd is invalid"),
                )?)
                .metadata()
                .map_err(|_| TraitError::new(ErrorCode::Internal, "pinned rootfs fstat failed"))?;
            let hostname = spec
                .hostname()
                .ok_or_else(|| TraitError::new(ErrorCode::Internal, "hostname is required"))?;
            let exe = std::env::current_exe()
                .map_err(|_| TraitError::new(ErrorCode::Internal, "current_exe failed"))?;
            // 引数は配列で渡し、シェルを介さない。
            let mut child = Command::new(exe)
                .args(["--scenario", "container"])
                .arg(spec.rootfs())
                .arg(hostname)
                .arg(pinned.dev().to_string())
                .arg(pinned.ino().to_string())
                .arg(self.mode)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .map_err(|_| {
                    TraitError::new(ErrorCode::Internal, "failed to spawn the scenario")
                })?;
            let (Some(stdout), Some(stderr)) = (child.stdout.take(), child.stderr.take()) else {
                return Err(launch_failed(
                    &mut child,
                    ErrorCode::Internal,
                    "missing pipes",
                ));
            };
            // stderr は上限まで共有バッファへ蓄積し、以降は捨てる（パイプ詰まりで子が止まらないように）。
            // 蓄積分は READY 後に拒否理由（PERMISSION_DENIED）の照合に使う。
            let captured = std::sync::Arc::new(Mutex::new(Vec::<u8>::new()));
            let captured_writer = std::sync::Arc::clone(&captured);
            std::thread::spawn(move || {
                let mut r = stderr;
                let mut chunk = [0u8; 1024];
                while let Ok(n) = r.read(&mut chunk) {
                    if n == 0 {
                        break;
                    }
                    if let Ok(mut buf) = captured_writer.lock() {
                        let room = STDERR_CAP as usize - buf.len().min(STDERR_CAP as usize);
                        let take = n.min(room);
                        if let Some(part) = chunk.get(..take) {
                            buf.extend_from_slice(part);
                        }
                    }
                }
            });
            let (tx, rx) = mpsc::channel::<String>();
            std::thread::spawn(move || {
                let mut line = String::new();
                let mut r = std::io::BufReader::new(stdout.take(LINE_CAP));
                let _ = r.read_line(&mut line);
                let _ = tx.send(line);
            });
            match rx.recv_timeout(timeout) {
                Ok(line) if line.trim_end() == READY_LINE => {}
                Ok(_) => {
                    return Err(launch_failed(
                        &mut child,
                        ErrorCode::Internal,
                        "the scenario did not report readiness",
                    ));
                }
                Err(_) => {
                    return Err(launch_failed(
                        &mut child,
                        ErrorCode::Timeout,
                        "the scenario did not report readiness within the timeout",
                    ));
                }
            }
            // exec 拒否の理由まで照合する（SEC-1・CORE-5）。Exited(126) だけでは別の exec 失敗と区別できない。
            // 子の stderr 書き込みは READY より前だが、蓄積スレッドの読み取りは非同期のため期限付きで待つ。
            let deadline = Instant::now() + timeout;
            let denied = loop {
                let seen = captured
                    .lock()
                    .map(|b| String::from_utf8_lossy(&b).contains("PERMISSION_DENIED"))
                    .unwrap_or(false);
                if seen {
                    break true;
                }
                if Instant::now() >= deadline {
                    break false;
                }
                std::thread::sleep(Duration::from_millis(10));
            };
            if !denied {
                if let Ok(b) = captured.lock() {
                    eprintln!("[scenario stderr] {}", String::from_utf8_lossy(&b));
                }
                return Err(launch_failed(
                    &mut child,
                    ErrorCode::Internal,
                    "scenario stderr lacked PERMISSION_DENIED (exec stage not reached via fail-closed path)",
                ));
            }
            let Some(pid) = NonZeroU32::new(child.id()) else {
                return Err(launch_failed(
                    &mut child,
                    ErrorCode::Internal,
                    "pid is zero",
                ));
            };
            Ok(Box::new(StandInProcess {
                pid,
                inner: Mutex::new((child, None)),
            }))
        }
    }

    /// start が返した起動ハンドルを保持し、kill をそのハンドルへだけ委ねる signaler（テスト専用）。
    /// 状態に記録された pid へ生の kill は送らない（SEC-1）。本番は supervisor（TASK-157）が提供する。
    struct HandleSignaler {
        slot: Mutex<Option<(ContainerId, Box<dyn LaunchedProcess>)>>,
    }

    impl ProcessSignaler for HandleSignaler {
        fn signal(
            &self,
            id: &ContainerId,
            pid: NonZeroU32,
            signal: Signal,
            deadline: Instant,
        ) -> Result<(), TraitError> {
            let g = self.slot.lock().unwrap_or_else(|e| e.into_inner());
            match g.as_ref() {
                Some((hid, handle)) if hid == id && handle.pid() == pid => {
                    handle.signal(signal, deadline)
                }
                _ => Err(TraitError::new(
                    ErrorCode::FailedPrecondition,
                    "no matching launch handle",
                )),
            }
        }
    }

    /// テスト専用の `ContainerCgroupRemover`。cgroup は常に存在しない（`NotPresent`）として扱い、実 cgroup には
    /// 触れない（OS 非依存。cgroup 削除の結線は `oci_delete.rs`・`cgroup_delete.rs` が照合する。TASK-30.3）。
    /// `oci_runtime::create` は cgroup スコープを記録しないため、delete は本 fake を呼ばない。呼ばれた場合に
    /// 気付けるよう `scope` はエラーを返す（delete は照合できず失敗する）。
    struct NoCgroup;

    impl ContainerCgroupRemover for NoCgroup {
        fn scope(&self) -> Result<CgroupScope, TraitError> {
            Err(TraitError::new(
                ErrorCode::Internal,
                "no delegated cgroup in this test",
            ))
        }
        fn remove(
            &self,
            _id: &ContainerId,
            _instance: StateRevision,
        ) -> Result<CgroupRemoval, TraitError> {
            Ok(CgroupRemoval::NotPresent)
        }
    }

    // ---- 最小のインメモリ StateStore（`StateStore::delete` は本テストの経路で呼ばれないため未実装のまま。
    // delete〔TASK-30.2〕は Running のレコードを状態判定で拒否し、ここへ到達しない） ----

    struct MemStateStore {
        records: Mutex<HashMap<ContainerId, StateRecord>>,
    }

    impl StateStore for MemStateStore {
        fn create(&self, req: &CreateStateRequest) -> Result<StateRecord, TraitError> {
            let mut records = self.records.lock().unwrap_or_else(|e| e.into_inner());
            if records.contains_key(req.id()) {
                return Err(TraitError::new(ErrorCode::AlreadyExists, "exists"));
            }
            let record = StateRecord::new(
                req.status().clone(),
                req.bundle().to_path_buf(),
                StateRevision::from_raw(1),
            )?;
            records.insert(req.id().clone(), record.clone());
            Ok(record)
        }

        fn update(&self, req: &UpdateStateRequest) -> Result<StateRecord, TraitError> {
            let mut records = self.records.lock().unwrap_or_else(|e| e.into_inner());
            let cur = records
                .get(req.status().id())
                .ok_or_else(|| TraitError::new(ErrorCode::NotFound, "not found"))?;
            if cur.revision() != req.expected_revision() {
                return Err(TraitError::new(ErrorCode::FailedPrecondition, "stale"));
            }
            let next = StateRecord::new(
                req.status().clone(),
                cur.bundle().to_path_buf(),
                cur.revision().next()?,
            )?;
            records.insert(req.status().id().clone(), next.clone());
            Ok(next)
        }

        fn get(&self, req: &GetStateRequest) -> Result<StateRecord, TraitError> {
            let records = self.records.lock().unwrap_or_else(|e| e.into_inner());
            records
                .get(req.id())
                .cloned()
                .ok_or_else(|| TraitError::new(ErrorCode::NotFound, "not found"))
        }

        fn list(&self, _req: &ListStateRequest) -> Result<StateList, TraitError> {
            Err(TraitError::new(ErrorCode::Unimplemented, "unused"))
        }

        fn delete(&self, _req: &DeleteStateRequest) -> Result<DeleteStateResponse, TraitError> {
            Err(TraitError::new(ErrorCode::Unimplemented, "unused"))
        }
    }

    // ---- bundle ----

    /// 一時 bundle（drop で削除）。
    struct Bundle(PathBuf);

    impl Drop for Bundle {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// `config.json` と `rootfs/`（`proc/`・実行権限付き `entry`）を排他的に作る。`RootfsDir::pin` は
    /// symlink を含む祖先を拒否するため、temp は canonicalize する。
    fn make_bundle(label: &str) -> Bundle {
        use std::os::unix::fs::OpenOptionsExt as _;
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        let base = std::fs::canonicalize(std::env::temp_dir())
            .expect("canonicalize temp_dir")
            .join(format!(
                "fandhe-rootless-lifecycle-{label}-{}-{nanos}",
                std::process::id()
            ));
        std::fs::create_dir(&base).expect("exclusively create bundle dir");
        let bundle = Bundle(base);
        std::fs::set_permissions(&bundle.0, std::fs::Permissions::from_mode(0o700))
            .expect("chmod bundle");
        let rootfs = bundle.0.join("rootfs");
        std::fs::create_dir(&rootfs).expect("create rootfs");
        std::fs::set_permissions(&rootfs, std::fs::Permissions::from_mode(0o755))
            .expect("chmod rootfs");
        std::fs::create_dir(rootfs.join("proc")).expect("create rootfs/proc");
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o755)
            .open(rootfs.join("entry"))
            .expect("create entrypoint");
        // exec は制限の証跡が無く拒否されるため、中身は実行されない。
        f.write_all(b"#!/bin/true\n").expect("write entrypoint");
        drop(f);
        // linux.uidMappings は書かない（start が拒否する。写像は launcher 側の責務）。
        let config = serde_json::json!({
            "ociVersion": "1.2.0",
            "root": {"path": "rootfs"},
            "process": {
                "user": {"uid": 0, "gid": 0},
                "args": ["/entry"],
                "env": ["PATH=/usr/bin:/bin"],
                "cwd": "/"
            },
            "hostname": HOSTNAME,
            "linux": {"namespaces": [
                {"type": "pid"}, {"type": "mount"}, {"type": "user"}, {"type": "uts"}, {"type": "ipc"}
            ]}
        });
        let mut cf = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(bundle.0.join("config.json"))
            .expect("create config.json");
        cf.write_all(&serde_json::to_vec(&config).expect("serialize"))
            .expect("write config.json");
        bundle
    }

    // ---- ディスパッチャ ----

    fn dispatcher() {
        let (euid, egid) = own_ids();
        if euid == 0 || egid == 0 {
            // SEC-5: root 起動＋自 ID 写像（コンテナ root = ホスト root）は計画の段階で拒否される。
            let uid = single_id_mapping(1000).expect("uid mapping");
            let gid = single_id_mapping(1000).expect("gid mapping");
            let err =
                plan_rootless_subordinate(&config(), uid, gid, IdMapWriter::Direct, timeout())
                    .expect_err("root launch must be rejected");
            let v = err.violation.expect("violation record");
            assert_eq!(v.reason.as_str(), "host_root_identity_mapping");
            println!("rootless: host root launch rejected (SEC-5, root=true)");
            return;
        }
        let mut modes: Vec<&'static str> = vec!["direct"];
        if helper_requested() {
            modes.push("helper");
        } else {
            println!("rootless: helper case not requested (set FANDHE_CONTAINER_TEST_ID_HELPER=1)");
        }
        for mode in modes {
            lifecycle(mode, euid, egid);
        }
    }

    /// `/proc/<pid>/{uid_map,gid_map}` を (コンテナ内 ID, ホスト ID, 長さ) の列として読む。
    fn read_map(pid: u32, file: &str) -> Vec<(u32, u32, u32)> {
        let text = std::fs::read_to_string(format!("/proc/{pid}/{file}"))
            .unwrap_or_else(|e| panic!("read {file}: {e}"));
        let mut rows: Vec<(u32, u32, u32)> = text
            .lines()
            .map(|l| {
                let mut it = l
                    .split_whitespace()
                    .map(|v| v.parse::<u32>().expect("number"));
                let row = (
                    it.next().expect("inside"),
                    it.next().expect("outside"),
                    it.next().expect("count"),
                );
                assert!(it.next().is_none(), "map line has 3 columns");
                row
            })
            .collect();
        rows.sort_unstable();
        rows
    }

    fn expected_rows(set: &IdMapSet) -> Vec<(u32, u32, u32)> {
        let mut rows: Vec<_> = set
            .entries()
            .iter()
            .map(|e| (e.container_id, e.host_id, e.count))
            .collect();
        rows.sort_unstable();
        rows
    }

    /// `/proc/<pid>/status` の `Uid:` / `Gid:` 行の 4 つの ID（real・effective・saved・fs）。
    fn status_ids(pid: u32, key: &str) -> Vec<u32> {
        std::fs::read_to_string(format!("/proc/{pid}/status"))
            .expect("read status")
            .lines()
            .find(|l| l.starts_with(key))
            .map(|l| {
                l.split_whitespace()
                    .skip(1)
                    .map(|v| v.parse().expect("id"))
                    .collect()
            })
            .expect("status line")
    }

    fn op_stats(rec: &OpRecorder, name: &str) -> (u64, u64) {
        let s = rec
            .snapshot_op(&OpName::new(name).expect("name"))
            .expect("recorded");
        (s.success(), s.failure())
    }

    /// 1 経路分の create → start → ホスト視点検証 → kill → 後始末の照合。拒否を含むあらゆる失敗は panic。
    fn lifecycle(mode: &'static str, euid: u32, egid: u32) {
        let bundle = make_bundle(mode);
        let store = MemStateStore {
            records: Mutex::new(HashMap::new()),
        };
        let rec = OpRecorder::new();
        let launcher: Arc<dyn ProcessLauncher> = Arc::new(RootlessLauncher { mode });
        let signaler_impl = Arc::new(HandleSignaler {
            slot: Mutex::new(None),
        });
        let signaler: Arc<dyn ProcessSignaler> = signaler_impl.clone();
        let id_str = format!("rootless-{mode}");
        let id = ContainerId::new(&id_str).expect("id");

        // create: Created・pid なし・revision 1。
        let created = create(
            &store,
            &rec,
            &CreateRequest::new(id.clone(), bundle.0.clone()).expect("absolute bundle"),
        )
        .expect("create");
        assert_eq!(created.status().state(), ContainerState::Created);
        assert_eq!(created.status().pid(), None);
        assert_eq!(created.revision().value(), 1);

        // start: helper ケースは 2 回の helper 呼び出しが要るため、既定の上限では足りない。
        let limit = DEFAULT_HELPER_TIMEOUT * 2 + timeout() * 2;
        let timeouts = StartTimeouts::new(limit, timeout(), timeout()).expect("start timeouts");
        let started = start(
            &store,
            &rec,
            &launcher,
            &StartRequest::new(id.clone()),
            &timeouts,
        )
        .expect("start");
        let (record, handle) = started.into_parts();
        assert_eq!(record.status().state(), ContainerState::Running);
        assert_eq!(record.revision().value(), 3);
        let pid = handle.pid();
        assert_eq!(record.status().pid(), Some(pid));
        assert_eq!(
            store
                .get(&GetStateRequest::new(id.clone()))
                .expect("stored"),
            record
        );
        *signaler_impl.slot.lock().unwrap_or_else(|e| e.into_inner()) = Some((id.clone(), handle));

        // ホスト視点の rootless 検証（SEC-5・CORE-6）。
        let p = pid.get();
        let (uid_set, gid_set) = match mode {
            "direct" => (
                single_id_mapping(euid).expect("uid"),
                single_id_mapping(egid).expect("gid"),
            ),
            _ => helper_mappings(euid, egid),
        };
        assert_eq!(read_map(p, "uid_map"), expected_rows(&uid_set));
        assert_eq!(read_map(p, "gid_map"), expected_rows(&gid_set));
        if mode == "direct" {
            assert_eq!(read_map(p, "uid_map"), vec![(0, euid, 1)]);
            assert_eq!(read_map(p, "gid_map"), vec![(0, egid, 1)]);
        }
        assert_eq!(status_ids(p, "Uid:"), vec![euid; 4]);
        assert_eq!(status_ids(p, "Gid:"), vec![egid; 4]);
        assert_ne!(euid, 0);
        // 別の user namespace にいることは、初期 namespace の恒等写像ではない上の uid_map の完全一致で
        // 保証される（`/proc/<pid>/ns/user` の readlink は ptrace 権限検査を伴い環境差が大きいため使わない）。

        // kill: 戻り値は照合時点の状態（Running）で、状態は更新されない。
        let status = kill(
            &store,
            &rec,
            &signaler,
            &KillRequest::new(id.clone(), Signal::SIGKILL),
            &KillTimeout::default(),
        )
        .expect("kill");
        assert_eq!(status.state(), ContainerState::Running);

        // 終了の確認（起動ハンドルで回収）。
        let exit = signaler_impl
            .slot
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .expect("handle")
            .1
            .wait(timeout())
            .expect("wait");
        assert_eq!(exit, Some(ProcessExit::Signaled(9)));

        // kill 後も状態は Running のまま（Stopped への遷移は supervisor〔TASK-157〕の責務。書き換えない）。
        let after = store
            .get(&GetStateRequest::new(id.clone()))
            .expect("stored");
        assert_eq!(after.status().state(), ContainerState::Running);
        assert_eq!(after.status().pid(), Some(pid));

        // 2 回目の kill は回収済みのハンドルへ送らず FailedPrecondition（SEC-1）。
        let err = kill(
            &store,
            &rec,
            &signaler,
            &KillRequest::new(id.clone(), Signal::SIGKILL),
            &KillTimeout::default(),
        )
        .expect_err("second kill");
        assert_eq!(err.code(), ErrorCode::FailedPrecondition);

        // kill 直後の delete は Running・pid ありとして拒否され、状態・revision は残る（CORE-2・TASK-30.2）。
        let err = delete(&store, &rec, &NoCgroup, &DeleteRequest::new(id.clone()))
            .expect_err("delete running");
        assert_eq!(err.code(), ErrorCode::FailedPrecondition);
        assert_eq!(err.message(), "container is still running");
        assert_eq!(
            store
                .get(&GetStateRequest::new(id.clone()))
                .expect("stored"),
            after
        );

        // 観測記録（REPAIR-4）。
        assert_eq!(op_stats(&rec, "create"), (1, 0));
        assert_eq!(op_stats(&rec, "start"), (1, 0));
        assert_eq!(op_stats(&rec, "kill"), (1, 1));
        assert_eq!(op_stats(&rec, "delete"), (0, 1));

        println!(
            "rootless: scenario {mode} lifecycle verified (create/start/kill/delete-rejected; host uid={euid})"
        );
    }
}
