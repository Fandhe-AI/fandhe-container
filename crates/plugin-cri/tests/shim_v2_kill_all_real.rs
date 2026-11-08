//! 配布する shim バイナリの `Kill(all=true)` が、実 cgroup でコンテナ内の init 以外のプロセスも止めることを照合する
//! 実機前提の試験（CRI-5・CORE-4・REPAIR-5・REPAIR-12。#4055。実装は #3680・PR #4050）。
//!
//! # 感度の設計（なぜホストのプロセスを cgroup へ移すのか）
//! core は PID namespace を必須にしている。init を殺すだけでも、カーネルの pidns teardown でコンテナ内の子孫は
//! すべて死ぬ。そのため「コンテナ内の子が死んだ」だけでは、`cgroup.kill` が効いたのか init だけが kill されたのかを
//! 区別できない。区別できるのは「コンテナの cgroup に居るが、PID namespace の外に居るプロセス」だけである。
//! そこで試験が起動したホストのプロセス（sleeper）を init と同じ leaf cgroup の `cgroup.procs` へ移し、これを証拠にする。
//! - シーン A（`all=true`）: init・コンテナ内の子・移した sleeper がすべて止まる（sleeper の死因は SIGKILL）。
//! - シーン B（対照。`all=false`）: init とコンテナ内の子は止まるが、sleeper は生き残る。A に感度があることの証拠。
//! - 実 cgroup に対する `kill_recorded_container_cgroup` の直接呼び出し: 空の cgroup は `WasEmpty`、Delete 後は
//!   `AlreadyAbsent`（shim の RPC では到達できない。停止後の Kill は `TaskService::kill` が先に `NOT_FOUND` を返す）。
//!
//! 「配置の記録が無いときは `FAILED_PRECONDITION`」は実機では再現しない（状態記録の改ざんが要る）。core の
//! `cri5_kill_all_without_placement_is_failed_precondition`、plugin-cri の `lifecycle_supervisor.rs` の
//! `cri5_kill_all_processes_without_placement_is_failed_precondition`、shim の層の
//! `cri5_4055_kill_all_failed_precondition_maps_to_code_9`（`crates/cri/src/shim_v2/task_service.rs`）が照合する。
//!
//! containerd・ctr・レジストリからの pull は使わない（`shim_v2_containerd_real` は containerd 経由の確認で、人間担当 #3685）。
//! 配布する shim を `start` でデーモンとして起動し、ttrpc（`support/shim_wire.rs`）で Create -> Start -> State -> Kill ->
//! State -> Delete -> Shutdown を直接呼ぶ。
//!
//! # 必要環境
//! Linux 6.12 以上（Landlock ABI 6 以上）・cgroup v2（`cgroup.kill` は 5.14 以上）・非 root・非特権 user namespace・
//! `systemd-run --user`（user マネージャ）・委譲 scope・`XDG_RUNTIME_DIR`。前提が欠けたら skip ではなく 1 行目
//! `PRECONDITION FAILED` で失敗する。
//!
//! # 実機前提テストとしての分離
//! `--ignored` 指定時のみ実行する（ci.md「実機前提テスト」）。Agent はホストで実行しない（transient scope を作るため）。
//!
//! ```text
//! cargo build -p fandhe-container-supervisor --bin fandhe-container-supervisor
//! cargo test -p fandhe-container-plugin-cri --test shim_v2_kill_all_real --no-run
//! systemd-run --user --scope -p Delegate=yes <target/debug/deps/shim_v2_kill_all_real-XXXX> --ignored
//! ```
//!
//! 成功行（固定。3 行）は `LINE_ALL`・`LINE_CONTROL`・`LINE_RECORDED`。失敗は `shim_v2_kill_all_real: FAILED: ...`、
//! 全体の期限切れは `WATCHDOG EXPIRED` と終了コード 124。

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("shim_v2_kill_all_real: skipped (linux only)");
}

#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--container-probe") {
        linux::container_probe();
    }
    if args.iter().any(|a| a == "--container-child") {
        linux::idle(linux::PROBE_LIFETIME);
    }
    if args.iter().any(|a| a == "--host-sleeper") {
        linux::idle(linux::SLEEPER_LIFETIME);
    }
    linux::main()
}

#[cfg(target_os = "linux")]
#[path = "../../core/tests/support/minimal_rootfs.rs"]
mod minimal_rootfs;
#[cfg(target_os = "linux")]
#[path = "../../core/tests/support/reap.rs"]
mod reap;
#[cfg(target_os = "linux")]
#[path = "support/shim_wire.rs"]
mod shim_wire;
#[cfg(target_os = "linux")]
#[path = "../../oci/tests/support/test_root.rs"]
mod test_root;

#[cfg(target_os = "linux")]
mod linux {
    use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _, PermissionsExt as _};
    use std::os::unix::process::ExitStatusExt as _;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, ExitCode, Stdio};
    use std::sync::Mutex;
    use std::time::{Duration, Instant};

    use fandhe_container_core::cgroups::{RecordedCgroupKill, kill_recorded_container_cgroup};
    use fandhe_container_core::traits::{CgroupPlacement, CgroupScope, ContainerId, StateRevision};

    use super::shim_wire::{
        Resp, TaskFields, call_method, create_request, decode_state_response, id_request,
        kill_request, shutdown_request,
    };
    use super::{minimal_rootfs, reap, test_root};

    /// 全体の期限（REPAIR-5）。超えたら子を回収して `WATCHDOG EXPIRED` と終了コード 124 で終わる。
    const WATCHDOG: Duration = Duration::from_secs(300);
    /// コンテナ内のプロセスの寿命の上限。SIGKILL が届かなければ終了コード 8 で終わる（寿命切れを停止と取り違えない目印）。
    pub const PROBE_LIFETIME: Duration = Duration::from_secs(60);
    /// ホスト側の sleeper の寿命の上限（シーン A と B の両方より長い）。
    pub const SLEEPER_LIFETIME: Duration = Duration::from_secs(120);
    /// 個々の待ちの期限。
    const STEP: Duration = Duration::from_secs(30);
    const SERVICE: &str = "containerd.task.v2.Task";
    const STATUS_RUNNING: u32 = 2;
    const STATUS_STOPPED: u32 = 3;
    /// SIGKILL で止めた init の終了コード（128 + 9）。
    const EXIT_STATUS_KILLED: u32 = 137;
    const SHIM_SRC: &str = env!("CARGO_BIN_EXE_containerd-shim-fandhe-container-v2");
    const SHIM_NAME: &str = "containerd-shim-fandhe-container-v2";
    const SUPERVISOR_NAME: &str = "fandhe-container-supervisor";
    const CGROUP_ROOT: &str = "/sys/fs/cgroup";
    const LINE_ALL: &str = "shim_v2_kill_all_real: Kill all=true with SIGKILL stopped the init, the in-container descendant and the migrated host process through the production shim (exit_status=137)";
    const LINE_CONTROL: &str = "shim_v2_kill_all_real: Kill all=false with SIGKILL stopped the init and the in-container descendant but left the migrated host process alive (control)";
    const LINE_RECORDED: &str = "shim_v2_kill_all_real: kill_recorded_container_cgroup returned WasEmpty for the emptied container cgroup and AlreadyAbsent after Delete";

    /// 期限切れの後始末で止めるプロセス（sleeper・shim デーモン・supervisor）の pid。
    static PIDS: Mutex<Vec<u32>> = Mutex::new(Vec::new());

    fn track(pid: u32) {
        if let Ok(mut p) = PIDS.lock() {
            p.push(pid);
        }
    }

    fn untrack(pid: u32) {
        if let Ok(mut p) = PIDS.lock() {
            p.retain(|x| *x != pid);
        }
    }

    /// `limit` だけ待って終了コード 8 で終わる（コンテナ内の子・ホストの sleeper の本体）。
    pub fn idle(limit: Duration) -> ! {
        let until = Instant::now() + limit;
        while Instant::now() < until {
            std::thread::sleep(Duration::from_millis(100));
        }
        std::process::exit(8);
    }

    /// コンテナの init。init 以外の子孫を 1 つ作ってから待つ（子の spawn に失敗したら終了コード 9）。
    pub fn container_probe() -> ! {
        let spawned = Command::new("/probe")
            .arg("--container-child")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();
        if spawned.is_err() {
            std::process::exit(9);
        }
        idle(PROBE_LIFETIME)
    }

    fn precondition_failed(reason: &str) -> ! {
        // 前提欠如は回帰と 1 行目で見分ける（skip にしない）。メッセージはホストのパス・ID を含めない。
        println!(
            "shim_v2_kill_all_real: PRECONDITION FAILED (test environment, not a shim regression): {reason}"
        );
        std::process::exit(1);
    }

    fn kill_pid(sig: &str, pid: u32) {
        // `kill` の待ちにも期限を持つ（watchdog の中からも呼ばれる。止まっても exit(124) へ進めるため。REPAIR-5）。
        let _ = reap::run_within(
            Command::new("kill")
                .args([&format!("-{sig}"), &pid.to_string()])
                .stderr(Stdio::null()),
            Duration::from_secs(5),
        );
    }

    fn watchdog() {
        std::thread::spawn(|| {
            std::thread::sleep(WATCHDOG);
            eprintln!("shim_v2_kill_all_real: WATCHDOG EXPIRED after {WATCHDOG:?}");
            if let Ok(pids) = PIDS.lock() {
                for pid in pids.iter() {
                    kill_pid("KILL", *pid);
                }
            }
            std::process::exit(124);
        });
    }

    fn wait_until(limit: Duration, mut f: impl FnMut() -> bool) -> bool {
        let until = Instant::now() + limit;
        loop {
            if f() {
                return true;
            }
            if Instant::now() >= until {
                return false;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// 試験バイナリの隣（`target/<profile>/`）にある成果物を探す。
    fn sibling_artifact(name: &str) -> PathBuf {
        let exe = std::env::current_exe()
            .unwrap_or_else(|_| precondition_failed("cannot resolve the test executable path"));
        let found = exe
            .ancestors()
            .skip(1)
            .take(3)
            .map(|d| d.join(name))
            .find(|p| p.is_file());
        found.unwrap_or_else(|| {
            precondition_failed(&format!(
                "{name} is not built (run cargo build -p fandhe-container-supervisor --bin fandhe-container-supervisor first)"
            ))
        })
    }

    fn install_exe(src: &Path, dest: &Path) -> Result<(), String> {
        minimal_rootfs::file_copy::replace_with_copy(src, dest)
            .map_err(|e| format!("copy {}: {e}", src.display()))?;
        std::fs::set_permissions(dest, std::fs::Permissions::from_mode(0o755))
            .map_err(|e| format!("chmod {}: {e}", dest.display()))
    }

    // ---- /proc と cgroup の読み取り（外部入力。unwrap・添字を使わず Option で扱う） ----

    /// `/proc/<pid>/stat` の (状態, ppid, starttime)。comm は括弧内に空白や `)` を含みうるため最後の `)` で分ける。
    fn proc_stat(pid: u32) -> Option<(char, u32, u64)> {
        let text = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        let rest = text.get(text.rfind(')')? + 1..)?;
        let mut f = rest.split_whitespace();
        let state = f.next()?.chars().next()?;
        let ppid: u32 = f.next()?.parse().ok()?;
        // state(3) の次が ppid(4)。starttime は 22 番目 = state から数えて 20 個後。
        let start: u64 = f.nth(17)?.parse().ok()?;
        Some((state, ppid, start))
    }

    /// 記録した (pid, starttime) のプロセスが居なくなった（無い・別プロセスに再利用された・ゾンビ）か。
    fn is_gone(pid: u32, start: u64) -> bool {
        match proc_stat(pid) {
            None => true,
            Some((state, _, s)) => s != start || state == 'Z' || state == 'X',
        }
    }

    /// `/proc/<pid>/cgroup` の cgroup v2 の行（`0::<path>`）のパス。
    fn proc_cgroup(pid: u32) -> Option<String> {
        let text = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?;
        text.lines()
            .find_map(|l| l.strip_prefix("0::").map(str::to_owned))
    }

    fn cgroup_file(leaf: &str, name: &str) -> PathBuf {
        Path::new(CGROUP_ROOT)
            .join(leaf.trim_start_matches('/'))
            .join(name)
    }

    fn cgroup_procs(leaf: &str) -> Vec<u32> {
        std::fs::read_to_string(cgroup_file(leaf, "cgroup.procs"))
            .unwrap_or_default()
            .lines()
            .filter_map(|l| l.trim().parse().ok())
            .collect()
    }

    /// `cgroup.events` の `populated`。読めない（cgroup が無い）ときは `None`。
    fn populated(leaf: &str) -> Option<bool> {
        let text = std::fs::read_to_string(cgroup_file(leaf, "cgroup.events")).ok()?;
        text.lines().find_map(|l| match l.trim() {
            "populated 1" => Some(true),
            "populated 0" => Some(false),
            _ => None,
        })
    }

    /// init の cgroup パスから `fc-<id>@<instance>` の要素までを leaf、その親を scope とし、instance を取り出す。
    fn split_leaf(path: &str, id: &str) -> Result<(String, String, u64), String> {
        let prefix = format!("fc-{id}@");
        let comps: Vec<&str> = path.split('/').filter(|c| !c.is_empty()).collect();
        let idx = comps
            .iter()
            .position(|c| c.starts_with(&prefix))
            .ok_or_else(|| format!("init cgroup {path} has no fc-{id}@ component"))?;
        let instance: u64 = comps
            .get(idx)
            .and_then(|c| c.strip_prefix(prefix.as_str()))
            .and_then(|d| d.parse().ok())
            .ok_or_else(|| "container cgroup instance is not a decimal number".to_string())?;
        let leaf = format!("/{}", comps.get(..=idx).unwrap_or_default().join("/"));
        let scope = format!("/{}", comps.get(..idx).unwrap_or_default().join("/"));
        Ok((leaf, scope, instance))
    }

    // ---- shim の ttrpc 呼び出し ----

    fn rpc(sock: &Path, method: &str, payload: &[u8]) -> Result<Resp, String> {
        let r =
            call_method(sock, SERVICE, method, payload).map_err(|e| format!("{method}: {e}"))?;
        match &r.status {
            None => Ok(r),
            Some((code, msg)) => Err(format!("{method} failed: code={code} message={msg}")),
        }
    }

    fn state_of(sock: &Path, id: &str) -> Result<TaskFields, String> {
        let r = rpc(sock, "State", &id_request(id))?;
        decode_state_response(&r.payload).ok_or_else(|| "undecodable StateResponse".to_string())
    }

    fn wait_state(sock: &Path, id: &str, status: u32) -> Result<TaskFields, String> {
        let mut last = None;
        let ok = wait_until(STEP, || {
            last = state_of(sock, id).ok();
            last.as_ref().is_some_and(|f| f.status == status)
        });
        match (ok, last) {
            (true, Some(f)) => Ok(f),
            (_, other) => Err(format!(
                "State never reached status {status}; last={other:?}"
            )),
        }
    }

    // ---- 1 つのコンテナの場面 ----

    struct Scene {
        id: String,
        sock: PathBuf,
        init: u32,
        init_start: u64,
        child: u32,
        child_start: u64,
        leaf: String,
        scope: String,
        instance: u64,
    }

    fn write_bundle(dir: &Path, n: u32) -> Result<PathBuf, String> {
        let bundle = dir.join(format!("b{n}"));
        let rootfs = bundle.join("rootfs");
        let ld =
            minimal_rootfs::install_binary_at(&rootfs, "probe", &["proc", "dev", "tmp", "etc"])?;
        let spec = format!(
            r#"{{"ociVersion":"1.2.0","root":{{"path":"{}","readonly":false}},"hostname":"fandhe-shim",
"process":{{"user":{{"uid":0,"gid":0}},"args":["/probe","--container-probe"],
"env":["PATH=/","TERM=dumb","LD_LIBRARY_PATH={ld}"],"cwd":"/"}},
"linux":{{"namespaces":[{{"type":"pid"}},{{"type":"mount"}},{{"type":"uts"}},{{"type":"ipc"}},{{"type":"user"}}]}}}}"#,
            rootfs.display()
        );
        std::fs::write(bundle.join("config.json"), spec)
            .map_err(|e| format!("write config.json: {e}"))?;
        Ok(bundle)
    }

    /// shim を `start` で起動して socket を得る。
    fn start_shim(dir: &Path, namespace: &str, id: &str) -> Result<PathBuf, String> {
        let shim = dir.join("bin").join(SHIM_NAME);
        let mut cmd = Command::new(&shim);
        cmd.args(["-namespace", namespace])
            .arg("-address")
            .arg(dir.join("containerd.sock"))
            .args(["-publish-binary", "/usr/bin/containerd", "-id", id, "start"])
            // XDG_RUNTIME_DIR は上書きしない（supervisor の `systemd-run --user` に user マネージャが要る）。
            .env("FANDHE_CONTAINER_SHIM_SOCKET_DIR", dir.join("s"))
            .current_dir(dir)
            .stdin(Stdio::null());
        let out = reap::output_within(&mut cmd, STEP).map_err(|e| format!("shim start: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "shim start failed: {:?}; stderr: {}",
                out.status.code(),
                String::from_utf8_lossy(&out.stderr)
            ));
        }
        let addr = String::from_utf8_lossy(&out.stdout).trim().to_owned();
        addr.strip_prefix("unix://")
            .map(PathBuf::from)
            .ok_or_else(|| "shim start printed no unix:// address".to_string())
    }

    /// Create -> Start -> RUNNING を待ち、init・コンテナ内の子・コンテナ cgroup の識別情報を集める。
    fn launch(dir: &Path, namespace: &str, id: &str, n: u32) -> Result<Scene, String> {
        let sock = start_shim(dir, namespace, id)?;
        let bundle = write_bundle(dir, n)?;
        let bundle_s = bundle.to_string_lossy().into_owned();
        rpc(&sock, "Create", &create_request(id, &bundle_s))?;
        rpc(&sock, "Start", &id_request(id))?;
        let running = wait_state(&sock, id, STATUS_RUNNING)?;
        let init = running.pid;
        if init == 0 {
            return Err("State reported pid 0 for a RUNNING task".into());
        }
        let init_start = proc_stat(init)
            .ok_or_else(|| format!("init pid {init} does not exist"))?
            .2;
        let path = proc_cgroup(init).ok_or("cannot read the init cgroup")?;
        let (leaf, scope, instance) = split_leaf(&path, id)?;
        // init 以外の子孫（コンテナ内の子）が cgroup.procs に現れるまで待つ。
        let mut child = None;
        let found = wait_until(Duration::from_secs(10), || {
            child = cgroup_procs(&leaf).into_iter().find(|p| *p != init);
            child.is_some()
        });
        let child = match (found, child) {
            (true, Some(c)) => c,
            _ => return Err("no in-container descendant appeared in the container cgroup".into()),
        };
        let (_, ppid, child_start) =
            proc_stat(child).ok_or_else(|| format!("child pid {child} does not exist"))?;
        if ppid != init {
            return Err(format!("child {child} has ppid {ppid}, want init {init}"));
        }
        Ok(Scene {
            id: id.to_owned(),
            sock,
            init,
            init_start,
            child,
            child_start,
            leaf,
            scope,
            instance,
        })
    }

    /// pidns の外のホストのプロセスを起動し、コンテナ cgroup へ移す。移動後に `/proc/<pid>/cgroup` を読み戻して確かめる。
    fn spawn_migrated_sleeper(scene: &Scene) -> Result<Child, String> {
        let exe = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;
        let child = Command::new(exe)
            .arg("--host-sleeper")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("spawn sleeper: {e}"))?;
        track(child.id());
        let procs = cgroup_file(&scene.leaf, "cgroup.procs");
        match std::fs::write(&procs, child.id().to_string()) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                // 縮退（STOPPED だけの確認）にはしない。共通祖先の cgroup.procs への書き込み権が環境の前提。
                precondition_failed(
                    "cannot move a host process into the container cgroup (write access to cgroup.procs of the common ancestor is required)",
                );
            }
            Err(e) => return Err(format!("move sleeper into the container cgroup: {e}")),
        }
        if proc_cgroup(child.id()).as_deref() != Some(scene.leaf.as_str()) {
            return Err("sleeper is not in the container cgroup after the move".into());
        }
        Ok(child)
    }

    fn placement(scene: &Scene) -> Result<CgroupPlacement, String> {
        let scope = CgroupScope::new(&scene.scope).map_err(|e| format!("CgroupScope: {e:?}"))?;
        Ok(CgroupPlacement::new(
            scope,
            StateRevision::from_raw(scene.instance),
        ))
    }

    fn kill_recorded(scene: &Scene) -> Result<RecordedCgroupKill, String> {
        let id = ContainerId::new(scene.id.as_str()).map_err(|e| format!("ContainerId: {e:?}"))?;
        kill_recorded_container_cgroup(
            &id,
            &placement(scene)?,
            Instant::now() + Duration::from_secs(5),
        )
        .map_err(|e| format!("kill_recorded_container_cgroup: {e:?}"))
    }

    fn finish_scene(scene: &Scene) -> Result<(), String> {
        rpc(&scene.sock, "Delete", &id_request(&scene.id))?;
        rpc(&scene.sock, "Shutdown", &shutdown_request(&scene.id, false))?;
        Ok(())
    }

    /// シーン A: `Kill(all=true)` が init・コンテナ内の子・移したホストのプロセスをすべて止める。
    fn scene_all(dir: &Path, namespace: &str) -> Result<Scene, String> {
        let id = format!("kar{}", std::process::id());
        let scene = launch(dir, namespace, &id, 1)?;
        let mut sleeper = spawn_migrated_sleeper(&scene)?;
        rpc(&scene.sock, "Kill", &kill_request(&scene.id, 9, true))?;
        let status = reap::wait_within(&mut sleeper, STEP)
            .map_err(|e| format!("migrated host process survived Kill all=true: {e}"))?;
        untrack(sleeper.id());
        if status.signal() != Some(9) {
            return Err(format!(
                "migrated host process ended with {status:?}, want death by SIGKILL"
            ));
        }
        if !wait_until(STEP, || {
            is_gone(scene.init, scene.init_start) && is_gone(scene.child, scene.child_start)
        }) {
            return Err("init or the in-container descendant is still alive".into());
        }
        if !wait_until(STEP, || populated(&scene.leaf) == Some(false)) {
            return Err("container cgroup is still populated after Kill all=true".into());
        }
        let st = wait_state(&scene.sock, &scene.id, STATUS_STOPPED)?;
        if st.exit_status != EXIT_STATUS_KILLED {
            return Err(format!(
                "exit_status {} (want {EXIT_STATUS_KILLED})",
                st.exit_status
            ));
        }
        // 空の実 cgroup は何も書かずに WasEmpty（Delete の前）。
        match kill_recorded(&scene)? {
            RecordedCgroupKill::WasEmpty => {}
            other => return Err(format!("before Delete: got {other:?}, want WasEmpty")),
        }
        finish_scene(&scene)?;
        // Delete が cgroup を消した後は AlreadyAbsent（冪等に成功）。
        match kill_recorded(&scene)? {
            RecordedCgroupKill::AlreadyAbsent => {}
            other => return Err(format!("after Delete: got {other:?}, want AlreadyAbsent")),
        }
        Ok(scene)
    }

    /// シーン B（対照）: `Kill(all=false)` は init とコンテナ内の子を止めるが、移したホストのプロセスは止めない。
    fn scene_control(dir: &Path, namespace: &str) -> Result<Scene, String> {
        let id = format!("kbr{}", std::process::id());
        let scene = launch(dir, namespace, &id, 2)?;
        let mut sleeper = spawn_migrated_sleeper(&scene)?;
        rpc(&scene.sock, "Kill", &kill_request(&scene.id, 9, false))?;
        let st = wait_state(&scene.sock, &scene.id, STATUS_STOPPED)?;
        if st.exit_status != EXIT_STATUS_KILLED {
            return Err(format!(
                "control: exit_status {} (want {EXIT_STATUS_KILLED})",
                st.exit_status
            ));
        }
        if !wait_until(STEP, || {
            is_gone(scene.init, scene.init_start) && is_gone(scene.child, scene.child_start)
        }) {
            return Err("control: init or the in-container descendant is still alive".into());
        }
        // 感度の証拠: init だけを殺しても pidns の外の sleeper は cgroup に残って生きている。
        let alive = sleeper
            .try_wait()
            .map_err(|e| format!("control: try_wait: {e}"))?
            .is_none();
        if !alive
            || proc_cgroup(sleeper.id()).as_deref() != Some(scene.leaf.as_str())
            || populated(&scene.leaf) != Some(true)
        {
            return Err(
                "control: the migrated host process did not survive Kill all=false (the test has no sensitivity)"
                    .into(),
            );
        }
        // Delete は populated の間は FailedPrecondition で拒否されるため、sleeper を止めて cgroup が空になってから行う。
        let _ = sleeper.kill();
        reap::reap(&mut sleeper, Duration::from_secs(10))?;
        untrack(sleeper.id());
        if !wait_until(STEP, || populated(&scene.leaf) == Some(false)) {
            return Err("control: container cgroup did not become empty".into());
        }
        finish_scene(&scene)?;
        Ok(scene)
    }

    // ---- 残存プロセスの検出（`shim_v2_containerd_real` の最小版の複製。試験 crate 間では共有しない） ----

    /// 1 プロセスが「`bin_dir` から起動された `names` のどれかで、引数に `id` を持つ」かの判定（純関数）。
    /// 本番 supervisor は `PR_SET_DUMPABLE=0` のため `/proc/<pid>/exe` が読めない（`exe` が `None`）。その場合は
    /// `cmdline` の argv[0] で判定し、確認不能を「不存在」にしない（fail-closed。REPAIR-12）。
    fn belongs(
        exe: Option<&Path>,
        cmdline: &[u8],
        id: &str,
        bin_dir: &Path,
        names: &[&str],
    ) -> bool {
        let argv0 = cmdline
            .split(|b| *b == 0)
            .next()
            .map(|a| PathBuf::from(String::from_utf8_lossy(a).into_owned()));
        let (dir_ok, file) = match (exe, argv0.as_deref()) {
            (Some(e), _) => (e.parent() == Some(bin_dir), e.file_name()),
            (None, Some(a)) => (
                a.parent()
                    .is_none_or(|p| p.as_os_str().is_empty() || p == bin_dir),
                a.file_name(),
            ),
            (None, None) => return false,
        };
        if !dir_ok || !names.iter().any(|n| file.is_some_and(|f| f == *n)) {
            return false;
        }
        cmdline.split(|b| *b == 0).any(|arg| {
            let arg = String::from_utf8_lossy(arg);
            arg == id || arg.split('/').any(|part| part == id)
        })
    }

    fn processes_with(id: &str, bin_dir: &Path) -> Vec<u32> {
        let me = std::process::id();
        let Ok(rd) = std::fs::read_dir("/proc") else {
            return Vec::new();
        };
        rd.flatten()
            .filter_map(|e| {
                let pid: u32 = e.file_name().to_str()?.parse().ok()?;
                if pid == me {
                    return None;
                }
                let exe = std::fs::read_link(e.path().join("exe")).ok();
                let c = std::fs::read(e.path().join("cmdline")).ok()?;
                belongs(
                    exe.as_deref(),
                    &c,
                    id,
                    bin_dir,
                    &[SHIM_NAME, SUPERVISOR_NAME],
                )
                .then_some(pid)
            })
            .collect()
    }

    /// `belongs` の具体値による自己照合（REPAIR-12）。非 dumpable（exe 不明）の supervisor が検出され、別 ID・別
    /// ディレクトリが誤検出されないことを固定する。
    fn self_check_belongs() -> Result<(), String> {
        let bin = Path::new("/tmp/x/bin");
        let names = [SHIM_NAME, SUPERVISOR_NAME];
        let cmd = b"/tmp/x/bin/fandhe-container-supervisor\0--id\0ctr1\0";
        let cases: [(&str, bool, bool); 4] = [
            (
                "non-dumpable",
                belongs(None, cmd, "ctr1", bin, &names),
                true,
            ),
            ("other id", belongs(None, cmd, "ctr", bin, &names), false),
            (
                "other dir",
                belongs(
                    None,
                    b"/usr/bin/fandhe-container-supervisor\0ctr1\0",
                    "ctr1",
                    bin,
                    &names,
                ),
                false,
            ),
            ("no cmdline", belongs(None, b"", "ctr1", bin, &names), false),
        ];
        for (name, got, want) in cases {
            if got != want {
                return Err(format!(
                    "self-check belongs[{name}]: got {got}, want {want}"
                ));
            }
        }
        // split_leaf の具体値。
        let (leaf, scope, inst) = split_leaf("/user.slice/x.scope/fc-abc@7", "abc")?;
        if (leaf.as_str(), scope.as_str(), inst)
            != ("/user.slice/x.scope/fc-abc@7", "/user.slice/x.scope", 7)
        {
            return Err(format!("self-check split_leaf: {leaf} {scope} {inst}"));
        }
        if split_leaf("/user.slice/x.scope", "abc").is_ok() {
            return Err("self-check split_leaf: accepted a path without fc-<id>@".into());
        }
        Ok(())
    }

    pub fn main() -> ExitCode {
        if let Err(e) = self_check_belongs() {
            eprintln!("shim_v2_kill_all_real: FAILED: {e}");
            return ExitCode::from(1);
        }
        if !std::env::args().any(|a| a == "--ignored") {
            println!(
                "shim_v2_kill_all_real: ignored (run the test binary with --ignored in a delegated scope; see crates/plugin-cri/tests/shim_v2_kill_all_real.rs)"
            );
            return ExitCode::SUCCESS;
        }
        watchdog();
        match scenario() {
            Ok(()) => {
                println!("{LINE_ALL}");
                println!("{LINE_CONTROL}");
                println!("{LINE_RECORDED}");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("shim_v2_kill_all_real: FAILED: {e}");
                ExitCode::from(1)
            }
        }
    }

    /// 前提確認。欠けたら skip せず PRECONDITION FAILED。
    fn check_preconditions() {
        let uid = std::fs::metadata("/proc/self")
            .map(|m| m.uid())
            .unwrap_or(0);
        if uid == 0 {
            precondition_failed("must run as a non-root user (rootful start is UNIMPLEMENTED)");
        }
        if !Path::new("/sys/fs/cgroup/cgroup.controllers").is_file() {
            precondition_failed("cgroup v2 is required");
        }
        match std::env::var_os("XDG_RUNTIME_DIR") {
            Some(p) if Path::new(&p).is_absolute() => {}
            _ => precondition_failed("XDG_RUNTIME_DIR must be set to an absolute path"),
        }
        let own = proc_cgroup(std::process::id())
            .unwrap_or_else(|| precondition_failed("cannot read own cgroup"));
        for name in ["", "cgroup.procs"] {
            let owned = std::fs::metadata(cgroup_file(&own, name)).is_ok_and(|m| m.uid() == uid);
            if !owned {
                precondition_failed(
                    "own cgroup is not delegated (run under systemd-run --user --scope -p Delegate=yes)",
                );
            }
        }
        if !cgroup_file(&own, "cgroup.kill").is_file() {
            precondition_failed("cgroup.kill is required (Linux 5.14 or later)");
        }
    }

    fn scenario() -> Result<(), String> {
        check_preconditions();
        let sup_src = sibling_artifact(SUPERVISOR_NAME);

        // 作業ディレクトリ（sun_path の制約のため短い /tmp 直下）。shim と supervisor は同じ bin/ に置く（ランチャーは置かない）。
        let work =
            test_root::test_root_at(PathBuf::from(format!("/tmp/fsk{}", std::process::id())));
        let dir: PathBuf = (*work).to_path_buf();
        let bin = dir.join("bin");
        std::fs::create_dir(&bin).map_err(|e| format!("mkdir bin: {e}"))?;
        install_exe(Path::new(SHIM_SRC), &bin.join(SHIM_NAME))?;
        install_exe(&sup_src, &bin.join(SUPERVISOR_NAME))?;
        let namespace = format!("fckillall{}", std::process::id());

        let mut scenes: Vec<Scene> = Vec::new();
        let outcome = (|| -> Result<(), String> {
            scenes.push(scene_all(&dir, &namespace)?);
            scenes.push(scene_control(&dir, &namespace)?);
            Ok(())
        })();

        // 後始末（成否に関わらず）。残った sleeper・shim デーモン・supervisor を止める。
        if let Ok(pids) = PIDS.lock() {
            for pid in pids.iter() {
                kill_pid("KILL", *pid);
            }
        }
        let ids = [
            format!("kar{}", std::process::id()),
            format!("kbr{}", std::process::id()),
        ];
        if outcome.is_err() {
            for id in &ids {
                // 最後の手段の停止（途中で落ちた場面のコンテナを cgroup ごと止める。socket が無ければ何も起きない）。
                let sock = shim_socket(&dir);
                if let Some(sock) = sock {
                    let _ = call_method(&sock, SERVICE, "Kill", &kill_request(id, 9, true));
                }
            }
        }
        for id in &ids {
            for pid in processes_with(id, &bin) {
                kill_pid("KILL", pid);
            }
        }
        if let Err(e) = &outcome {
            let t = std::fs::read_to_string(dir.join("s/daemon.log")).unwrap_or_default();
            let tail: Vec<&str> = t.lines().rev().take(40).collect();
            eprintln!(
                "--- s/daemon.log (last lines) ---\n{}",
                tail.into_iter().rev().collect::<Vec<_>>().join("\n")
            );
            eprintln!("shim_v2_kill_all_real: diagnostics end: {e}");
        }
        outcome?;

        // 成功の経路: すべて片付いたことの照合。
        for scene in &scenes {
            check_clean(&dir, &bin, &namespace, &scene.id)?;
        }
        cleanup_state_dirs(&namespace);
        Ok(())
    }

    /// 作業ディレクトリ配下の shim の socket のうち最初の 1 つ（失敗時の最後の手段の停止用）。
    fn shim_socket(dir: &Path) -> Option<PathBuf> {
        std::fs::read_dir(dir.join("s"))
            .ok()?
            .flatten()
            .find(|e| e.file_type().is_ok_and(|t| t.is_socket()))
            .map(|e| e.path())
    }

    /// 1 つのコンテナが片付いたことの照合（デーモンと supervisor が残らない・socket が残らない・状態ルートに無い）。
    fn check_clean(dir: &Path, bin: &Path, namespace: &str, id: &str) -> Result<(), String> {
        if !wait_until(Duration::from_secs(15), || {
            processes_with(id, bin).is_empty()
        }) {
            return Err(format!("shim daemon or supervisor for {id} still alive"));
        }
        let socks = match std::fs::read_dir(dir.join("s")) {
            Ok(rd) => rd
                .flatten()
                .filter(|e| e.file_type().is_ok_and(|t| t.is_socket()))
                .count(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => 0,
            Err(e) => return Err(format!("read socket dir: {e}")),
        };
        if socks != 0 {
            return Err(format!("{socks} shim socket(s) remain"));
        }
        for p in state_dirs(namespace, Some(id))? {
            if p.symlink_metadata().is_ok() {
                return Err(format!("state directory for {id} remains: {}", p.display()));
            }
        }
        Ok(())
    }

    /// 状態ルート `<XDG>/fandhe-container-shim-state/<address のハッシュ>/<namespace>[/<id>]` の候補（全ハッシュを走査）。
    fn state_dirs(namespace: &str, id: Option<&str>) -> Result<Vec<PathBuf>, String> {
        let xdg = std::env::var_os("XDG_RUNTIME_DIR")
            .map(PathBuf::from)
            .ok_or("XDG_RUNTIME_DIR is not set")?;
        let mut out = Vec::new();
        match std::fs::read_dir(xdg.join("fandhe-container-shim-state")) {
            Ok(rd) => {
                for h in rd.flatten() {
                    let ns = h.path().join(namespace);
                    out.push(match id {
                        Some(id) => ns.join(id),
                        None => ns,
                    });
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(format!("read shim state dir: {e}")),
        }
        Ok(out)
    }

    /// 自分の namespace のディレクトリと、空になったハッシュのディレクトリだけを消す（他の状態には触れない）。
    fn cleanup_state_dirs(namespace: &str) {
        for ns in state_dirs(namespace, None).unwrap_or_default() {
            if std::fs::remove_dir(&ns).is_ok()
                && let Some(hash) = ns.parent()
            {
                let _ = std::fs::remove_dir(hash);
            }
        }
    }
}
