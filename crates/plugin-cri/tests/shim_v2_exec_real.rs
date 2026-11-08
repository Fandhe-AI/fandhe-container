//! 配布する shim バイナリ経由の `Exec` が、コンテナの init の namespace・cgroup・seccomp・capability を超えないことを
//! 実コンテナで照合する実機前提の試験（CRI-5・CRI-1・SEC-1・REPAIR-5・REPAIR-12・TASK-62.7。#4150。実装は #4148・#4149）。
//!
//! 呼び出し元は CI の `platform-ci`（ubuntu）と人間の実機確認。配布する shim を `start` でデーモンとして起動し、
//! ttrpc（`support/shim_wire.rs`）で Create -> Start -> Exec -> Start(exec_id) -> State(exec_id) -> Delete(exec_id) ->
//! Kill -> Delete -> Shutdown を直接呼ぶ。containerd・ctr・レジストリからの pull は使わない
//! （containerd 経由の確認は人間担当 #3685）。
//!
//! # 照合する項目（SEC-1。すべてホストの `/proc` から読む）
//! - capability・seccomp: init と exec のプロセスの `CapEff` がどちらも OCI 既定（`00000000a80425fb`）で、
//!   `CapEff`・`CapPrm`・`CapBnd` は exec が init を超えない。`CapInh`・`CapAmb` は 0。`Seccomp` は両方 `2`。
//! - namespace: `/proc/<pid>/ns/*` の 8 種（cgroup ipc mnt net pid time user uts）の inode が init と一致する。
//!   陰性対照として、config が新しく作る 5 種（ipc mnt pid user uts）は init の値が試験プロセスのものと異なる。
//! - cgroup: init の cgroup は `fc-<id>@<instance>` の leaf、exec のプロセスはその直下の `exec-*` 子 cgroup
//!   （supervisor の exec が作る。#1466・CORE-4）に居る。exit 後に子 cgroup が回収される。
//!
//! # Issue の文面と異なる点
//! - ハーネスは `harness = false`。shim の exec は stdio が `/dev/null` で pid も返さないため、試験バイナリ自身を
//!   rootfs の `/probe` として init と exec のコマンドの両方に使う独自 argv の再入が要る（兄弟の
//!   `shim_v2_kill_all_real` と同じ形）。`--ignored`・委譲 scope・全体期限・`PRECONDITION FAILED` の契約は保つ。
//! - cgroup は「init と同じ」ではなく「init の直下の `exec-*` 子 cgroup」で照合する（exec は init と同じ cgroup にならない）。
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
//! cargo test -p fandhe-container-plugin-cri --test shim_v2_exec_real --no-run
//! systemd-run --user --scope -p Delegate=yes <target/debug/deps/shim_v2_exec_real-XXXX> --ignored
//! ```
//!
//! 成功行（固定。4 行）は `LINE_CAPS`・`LINE_NS`・`LINE_CGROUP`・`LINE_EXIT`。失敗は `shim_v2_exec_real: FAILED: ...`、
//! 全体の期限切れは `WATCHDOG EXPIRED` と終了コード 124。

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("shim_v2_exec_real: skipped (linux only)");
}

#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--container-probe") {
        linux::container_probe();
    }
    if args.iter().any(|a| a == "--exec-probe") {
        linux::exec_probe();
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
    use std::path::{Path, PathBuf};
    use std::process::{Command, ExitCode, Stdio};
    use std::sync::Mutex;
    use std::time::{Duration, Instant};

    use super::shim_wire::{
        Resp, TaskFields, call_method, create_request, decode_delete_response,
        decode_state_response, exec_id_request, exec_request, id_request, kill_request,
        shutdown_request,
    };
    use super::{minimal_rootfs, reap, test_root};

    /// 全体の期限（REPAIR-5）。超えたら子を回収して `WATCHDOG EXPIRED` と終了コード 124 で終わる。
    const WATCHDOG: Duration = Duration::from_secs(300);
    /// コンテナ内のプロセス（init と exec のコマンド）の寿命の上限。超えたら終了コード 8（寿命切れを正常終了と取り違えない目印）。
    pub const PROBE_LIFETIME: Duration = Duration::from_secs(60);
    /// 個々の待ちの期限。
    const STEP: Duration = Duration::from_secs(30);
    const SERVICE: &str = "containerd.task.v2.Task";
    const STATUS_RUNNING: u32 = 2;
    const STATUS_STOPPED: u32 = 3;
    /// SIGKILL で止めた init の終了コード（128 + 9）。
    const EXIT_STATUS_KILLED: u32 = 137;
    /// `NOT_FOUND` の ttrpc / gRPC のコード。
    const CODE_NOT_FOUND: i32 = 5;
    /// OCI 既定の capability 集合（14 個）のビット列。`self_check` が core の定義と突き合わせる。
    const OCI_DEFAULT_MASK: u64 = 0x0000_0000_a804_25fb;
    const EXEC_ID: &str = "e1";
    /// exec の spec（env 空・cwd `/`・user なし・stdio なし。初版の受け入れの範囲。`docs/design/shim-v2-production-binary.md`）。
    const EXEC_SPEC: &str = r#"{"cwd":"/","args":["/probe","--exec-probe"]}"#;
    /// exec のコマンドの cmdline（argv を NUL で区切って末尾も NUL）。
    const EXEC_CMDLINE: &[u8] = b"/probe\0--exec-probe\0";
    /// 解放の合図。rootfs 直下に作ると exec のコマンドが終了コード 0 で終わる。
    const RELEASE_NAME: &str = "release";
    const NS_ALL: [&str; 8] = ["cgroup", "ipc", "mnt", "net", "pid", "time", "user", "uts"];
    /// config が新しく作る namespace（陰性対照。試験プロセスの値と異なるはず）。
    const NS_UNSHARED: [&str; 5] = ["ipc", "mnt", "pid", "user", "uts"];
    const SHIM_SRC: &str = env!("CARGO_BIN_EXE_containerd-shim-fandhe-container-v2");
    const SHIM_NAME: &str = "containerd-shim-fandhe-container-v2";
    const SUPERVISOR_NAME: &str = "fandhe-container-supervisor";
    const CGROUP_ROOT: &str = "/sys/fs/cgroup";
    const LINE_CAPS: &str = "shim_v2_exec_real: exec through the production shim kept CapEff=00000000a80425fb and Seccomp=2 equal to the container init without exceeding CapPrm/CapBnd (SEC-1)";
    const LINE_NS: &str = "shim_v2_exec_real: exec through the production shim shared all 8 namespaces (cgroup ipc mnt net pid time user uts) with the container init";
    const LINE_CGROUP: &str = "shim_v2_exec_real: exec through the production shim ran in an exec-* child cgroup directly under the container init cgroup and the child was removed after exit";
    const LINE_EXIT: &str = "shim_v2_exec_real: exec through the production shim reported STOPPED with exit_status=0 and Delete(exec_id) succeeded";

    /// コンテナの init。`PROBE_LIFETIME` まで待つだけ（子は作らない）。
    pub fn container_probe() -> ! {
        let until = Instant::now() + PROBE_LIFETIME;
        while Instant::now() < until {
            std::thread::sleep(Duration::from_millis(100));
        }
        std::process::exit(8);
    }

    /// exec のコマンド。rootfs 直下の解放の合図が現れたら終了コード 0、寿命が切れたら 8。
    pub fn exec_probe() -> ! {
        let until = Instant::now() + PROBE_LIFETIME;
        while Instant::now() < until {
            if std::fs::metadata(format!("/{RELEASE_NAME}")).is_ok() {
                std::process::exit(0);
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        std::process::exit(8);
    }

    /// 起動済みの資源がある地点で前提欠如を見つけたときの `Err` の接頭辞。`process::exit` せず上位へ返し、
    /// 回収の後で `main` が PRECONDITION FAILED を出す（REPAIR-5）。
    const PRECOND_PREFIX: &str = "precondition: ";

    fn print_precondition(reason: &str) {
        // 前提欠如は回帰と 1 行目で見分ける（skip にしない）。メッセージはホストのパス・ID を含めない。
        println!(
            "shim_v2_exec_real: PRECONDITION FAILED (test environment, not a shim regression): {reason}"
        );
    }

    fn precondition_failed(reason: &str) -> ! {
        print_precondition(reason);
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

    /// 回収に必要な作業ディレクトリと bin ディレクトリ（`scenario` が作ったら登録する。watchdog と通常の後始末が共有）。
    static WORK: Mutex<Option<(PathBuf, PathBuf)>> = Mutex::new(None);
    /// 期限切れの後始末で止めるプロセス（exec のコマンド）の pid。
    /// pid の再利用で無関係なプロセスを止めないよう、発見時の starttime（`/proc/<pid>/stat` の 22 番目）を併記する。
    static PIDS: Mutex<Vec<(u32, u64)>> = Mutex::new(Vec::new());

    /// `/proc/<pid>/stat` の starttime（clock ticks）。プロセスが無い・解析不能なら `None`。
    fn proc_starttime(pid: u32) -> Option<u64> {
        let text = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        // comm は括弧で囲まれ空白や `)` を含みうるため、最後の `)` の後ろから数える（3 番目の欄が先頭）。
        let rest = text.get(text.rfind(')')? + 1..)?;
        rest.split_whitespace().nth(19)?.parse().ok()
    }

    fn container_id() -> String {
        format!("xer{}", std::process::id())
    }

    /// 共通の回収処理（REPAIR-5）。追跡中の pid を止め、`kill_all_via_shim` なら shim の `Kill(all=true)` を期限つき
    /// （5 秒）で試し、別 systemd scope の supervisor と shim デーモンを id と bin ディレクトリで見つけて止める。
    /// watchdog の `process::exit(124)` の前にも呼ぶ（外側の scope 回収は別 scope の supervisor に届かないため）。
    fn emergency_cleanup(kill_all_via_shim: bool) {
        if let Ok(pids) = PIDS.lock() {
            for (pid, start) in pids.iter() {
                // 終了済み・pid 再利用（starttime 不一致）の対象には送らない。
                if proc_starttime(*pid) == Some(*start) {
                    kill_pid("KILL", *pid);
                }
            }
        }
        let ctx = WORK.lock().ok().and_then(|g| g.clone());
        let Some((dir, bin)) = ctx else {
            return;
        };
        let id = container_id();
        if kill_all_via_shim && let Some(sock) = shim_socket(&dir) {
            // 最後の手段の停止。応答が無くても 5 秒で先へ進む。
            let (tx, rx) = std::sync::mpsc::channel();
            let id2 = id.clone();
            std::thread::spawn(move || {
                let _ = call_method(&sock, SERVICE, "Kill", &kill_request(&id2, 9, true));
                let _ = tx.send(());
            });
            let _ = rx.recv_timeout(Duration::from_secs(5));
        }
        for pid in processes_with(&id, &bin) {
            kill_pid("KILL", pid);
        }
    }

    fn watchdog() {
        std::thread::spawn(|| {
            std::thread::sleep(WATCHDOG);
            eprintln!("shim_v2_exec_real: WATCHDOG EXPIRED after {WATCHDOG:?}");
            emergency_cleanup(true);
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

    fn cgroup_procs(dir: &str) -> Vec<u32> {
        std::fs::read_to_string(cgroup_file(dir, "cgroup.procs"))
            .unwrap_or_default()
            .lines()
            .filter_map(|l| l.trim().parse().ok())
            .collect()
    }

    /// `leaf` 直下の `exec-*` 子 cgroup のパス（`leaf` が無ければ空）。
    fn exec_children(leaf: &str) -> Vec<String> {
        let Ok(rd) = std::fs::read_dir(cgroup_file(leaf, "")) else {
            return Vec::new();
        };
        rd.flatten()
            .filter_map(|e| {
                let name = e.file_name().to_str()?.to_owned();
                (name.starts_with("exec-") && e.file_type().is_ok_and(|t| t.is_dir()))
                    .then(|| format!("{}/{name}", leaf.trim_end_matches('/')))
            })
            .collect()
    }

    /// init の cgroup パスから `fc-<id>@<instance>` の要素までを leaf として返す。
    fn split_leaf(path: &str, id: &str) -> Result<String, String> {
        let prefix = format!("fc-{id}@");
        let comps: Vec<&str> = path.split('/').filter(|c| !c.is_empty()).collect();
        let idx = comps
            .iter()
            .position(|c| c.starts_with(&prefix))
            .ok_or_else(|| format!("init cgroup {path} has no fc-{id}@ component"))?;
        let instance_ok = comps
            .get(idx)
            .and_then(|c| c.strip_prefix(prefix.as_str()))
            .is_some_and(|d| !d.is_empty() && d.bytes().all(|b| b.is_ascii_digit()));
        if !instance_ok {
            return Err("container cgroup instance is not a decimal number".to_string());
        }
        Ok(format!(
            "/{}",
            comps.get(..=idx).unwrap_or_default().join("/")
        ))
    }

    /// exec の cgroup パスが「`leaf` の直下の `exec-*` 子 cgroup 1 要素」か（純関数。等値・接頭辞だけの一致・孫は拒否）。
    fn exec_cgroup_ok(exec_path: &str, leaf: &str) -> bool {
        let Some(rest) = exec_path
            .strip_prefix(leaf)
            .and_then(|r| r.strip_prefix('/'))
        else {
            return false;
        };
        rest.starts_with("exec-") && rest.len() > "exec-".len() && !rest.contains('/')
    }

    /// `/proc/<pid>/status` から照合に使う欄（capability のビット列と `Seccomp`）。
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct Caps {
        eff: u64,
        prm: u64,
        bnd: u64,
        inh: u64,
        amb: u64,
        seccomp: String,
    }

    fn parse_caps(text: &str) -> Option<Caps> {
        let field = |key: &str| -> Option<&str> {
            text.lines()
                .find_map(|l| l.strip_prefix(key).and_then(|r| r.strip_prefix(':')))
                .map(str::trim)
        };
        let hex = |key: &str| -> Option<u64> { u64::from_str_radix(field(key)?, 16).ok() };
        Some(Caps {
            eff: hex("CapEff")?,
            prm: hex("CapPrm")?,
            bnd: hex("CapBnd")?,
            inh: hex("CapInh")?,
            amb: hex("CapAmb")?,
            seccomp: field("Seccomp")?.to_owned(),
        })
    }

    fn read_caps(pid: u32) -> Result<Caps, String> {
        let text = std::fs::read_to_string(format!("/proc/{pid}/status"))
            .map_err(|e| format!("read /proc/{pid}/status: {e}"))?;
        parse_caps(&text).ok_or_else(|| format!("cannot parse /proc/{pid}/status"))
    }

    /// `/proc/<pid>/ns/<name>` の readlink（`mnt:[4026531841]` の形）。
    fn ns_link(pid: &str, name: &str) -> Result<String, String> {
        std::fs::read_link(format!("/proc/{pid}/ns/{name}"))
            .map(|p| p.to_string_lossy().into_owned())
            .map_err(|e| format!("readlink /proc/{pid}/ns/{name}: {e}"))
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

    fn exec_state(sock: &Path, id: &str) -> Result<TaskFields, String> {
        let r = rpc(sock, "State", &exec_id_request(id, EXEC_ID))?;
        decode_state_response(&r.payload)
            .ok_or_else(|| "undecodable exec StateResponse".to_string())
    }

    fn wait_exec_state(sock: &Path, id: &str, status: u32) -> Result<TaskFields, String> {
        let mut last = None;
        let ok = wait_until(STEP, || {
            last = exec_state(sock, id).ok();
            last.as_ref().is_some_and(|f| f.status == status)
        });
        match (ok, last) {
            (true, Some(f)) => Ok(f),
            (_, other) => Err(format!(
                "exec State never reached status {status}; last={other:?}"
            )),
        }
    }

    // ---- コンテナの用意 ----

    fn write_bundle(dir: &Path) -> Result<PathBuf, String> {
        let bundle = dir.join("b1");
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
            .arg("-publish-binary")
            .arg(&shim)
            .args(["-id", id, "start"])
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

    /// exec のコマンドの pid を、`leaf` 直下の `exec-*` 子 cgroup から cmdline で特定する（ちょうど 1 つ）。
    /// 子 cgroup には fork 直後の worker なども居うるため、cmdline が `EXEC_CMDLINE` と完全一致するものに絞る。
    fn find_exec_pid(leaf: &str) -> Result<(u32, String), String> {
        let mut found: Vec<(u32, String)> = Vec::new();
        wait_until(STEP, || {
            found = exec_children(leaf)
                .into_iter()
                .flat_map(|dir| {
                    cgroup_procs(&dir)
                        .into_iter()
                        .filter(|pid| {
                            std::fs::read(format!("/proc/{pid}/cmdline"))
                                .is_ok_and(|c| c == EXEC_CMDLINE)
                        })
                        .map(|pid| (pid, dir.clone()))
                        .collect::<Vec<_>>()
                })
                .collect();
            !found.is_empty()
        });
        match found.as_slice() {
            [one] => Ok(one.clone()),
            other => Err(format!(
                "want exactly one exec command process in an exec-* cgroup, found {}",
                other.len()
            )),
        }
    }

    /// 本体のシナリオ。1 つのコンテナで exec を通し、4 項目を照合する。
    fn run_all(dir: &Path, namespace: &str, id: &str) -> Result<(), String> {
        let sock = start_shim(dir, namespace, id)?;
        let bundle = write_bundle(dir)?;
        let bundle_s = bundle.to_string_lossy().into_owned();
        rpc(&sock, "Create", &create_request(id, &bundle_s))?;
        rpc(&sock, "Start", &id_request(id))?;
        let running = wait_state(&sock, id, STATUS_RUNNING)?;
        let init = running.pid;
        if init == 0 {
            return Err("State reported pid 0 for a RUNNING task".into());
        }

        // init の観測。
        let init_path = proc_cgroup(init).ok_or("cannot read the init cgroup")?;
        let leaf = split_leaf(&init_path, id)?;
        if init_path != leaf {
            return Err(format!("init cgroup {init_path} is not the leaf {leaf}"));
        }
        let init_caps = read_caps(init)?;
        let init_pid = init.to_string();
        let mut init_ns = Vec::new();
        for name in NS_ALL {
            init_ns.push((name, ns_link(&init_pid, name)?));
        }
        // 陰性対照: 新しく作った namespace は試験プロセスのものと異なる（継承ではなく参加した証拠。照合が空でない証拠）。
        for name in NS_UNSHARED {
            let mine = ns_link("self", name)?;
            if init_ns.iter().any(|(n, v)| *n == name && *v == mine) {
                return Err(format!(
                    "init shares the {name} namespace with the test process (negative control failed)"
                ));
            }
        }

        // exec を通す（env 空・cwd `/`・user なし・stdio なし）。
        rpc(&sock, "Exec", &exec_request(id, EXEC_ID, EXEC_SPEC))?;
        rpc(&sock, "Start", &exec_id_request(id, EXEC_ID))?;
        let st = wait_exec_state(&sock, id, STATUS_RUNNING)?;
        if st.pid != 0 {
            return Err(format!(
                "exec State reported pid {} (the shim exec does not expose pids; want 0)",
                st.pid
            ));
        }
        let (exec_pid, exec_dir) = find_exec_pid(&leaf)?;
        if let (Ok(mut p), Some(start)) = (PIDS.lock(), proc_starttime(exec_pid)) {
            p.push((exec_pid, start));
        }

        // capability・seccomp。
        let exec_caps = read_caps(exec_pid)?;
        if init_caps.eff != OCI_DEFAULT_MASK || exec_caps.eff != OCI_DEFAULT_MASK {
            return Err(format!(
                "CapEff init={:#x} exec={:#x}, want {OCI_DEFAULT_MASK:#x} for both",
                init_caps.eff, exec_caps.eff
            ));
        }
        for (name, e, i) in [
            ("CapEff", exec_caps.eff, init_caps.eff),
            ("CapPrm", exec_caps.prm, init_caps.prm),
            ("CapBnd", exec_caps.bnd, init_caps.bnd),
        ] {
            if e & !i != 0 {
                return Err(format!("exec {name} {e:#x} exceeds init {i:#x}"));
            }
        }
        if exec_caps.inh != 0 || exec_caps.amb != 0 {
            return Err(format!(
                "exec CapInh={:#x} CapAmb={:#x}, want 0",
                exec_caps.inh, exec_caps.amb
            ));
        }
        if init_caps.seccomp != "2" || exec_caps.seccomp != "2" {
            return Err(format!(
                "Seccomp init={} exec={}, want 2 for both",
                init_caps.seccomp, exec_caps.seccomp
            ));
        }

        // namespace。
        let exec_pid_s = exec_pid.to_string();
        for (name, want) in &init_ns {
            let got = ns_link(&exec_pid_s, name)?;
            if got != *want {
                return Err(format!(
                    "exec {name} namespace {got} differs from init {want}"
                ));
            }
        }

        // cgroup: init の leaf 直下の exec-* 子 cgroup。試験プロセス自身の cgroup とは異なる。
        let exec_path = proc_cgroup(exec_pid).ok_or("cannot read the exec cgroup")?;
        if !exec_cgroup_ok(&exec_path, &leaf) || exec_path != exec_dir {
            return Err(format!(
                "exec cgroup {exec_path} is not a direct exec-* child of {leaf} (dir {exec_dir})"
            ));
        }
        if proc_cgroup(std::process::id()).as_deref() == Some(exec_path.as_str()) {
            return Err("exec cgroup equals the test process cgroup".into());
        }

        // 解放: 合図で自然に終わらせる（SIGKILL の経路は消滅の確認が無く Delete が拒否されるため使わない）。
        std::fs::write(bundle.join("rootfs").join(RELEASE_NAME), b"")
            .map_err(|e| format!("write release marker: {e}"))?;
        let stopped = wait_exec_state(&sock, id, STATUS_STOPPED)?;
        if stopped.exit_status != 0 {
            return Err(format!("exec exit_status {} (want 0)", stopped.exit_status));
        }
        let del = rpc(&sock, "Delete", &exec_id_request(id, EXEC_ID))?;
        let del = decode_delete_response(&del.payload)
            .ok_or_else(|| "undecodable exec DeleteResponse".to_string())?;
        if del.exit_status != 0 {
            return Err(format!(
                "Delete(exec_id) exit_status {} (want 0)",
                del.exit_status
            ));
        }
        let after = call_method(&sock, SERVICE, "State", &exec_id_request(id, EXEC_ID))
            .map_err(|e| format!("State after exec Delete: {e}"))?;
        if after.status.as_ref().map(|(c, _)| *c) != Some(CODE_NOT_FOUND) {
            return Err(format!(
                "State(exec_id) after Delete: {:?}, want NOT_FOUND",
                after.status
            ));
        }
        // exec 子 cgroup は呼び出し側が exit 後に回収する（CORE-4）。
        if !wait_until(STEP, || exec_children(&leaf).is_empty()) {
            return Err("exec-* child cgroup was not removed after the exec exited".into());
        }

        // コンテナの後始末。
        rpc(&sock, "Kill", &kill_request(id, 9, false))?;
        let st = wait_state(&sock, id, STATUS_STOPPED)?;
        if st.exit_status != EXIT_STATUS_KILLED {
            return Err(format!(
                "init exit_status {} (want {EXIT_STATUS_KILLED})",
                st.exit_status
            ));
        }
        rpc(&sock, "Delete", &id_request(id))?;
        rpc(&sock, "Shutdown", &shutdown_request(id, false))?;
        Ok(())
    }

    // ---- 残存プロセスの検出（`shim_v2_kill_all_real` の最小版の複製。試験 crate 間では共有しない） ----

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

    /// 既定の集合（`--ignored` なし）でも走る具体値の自己照合（REPAIR-12）。照合の部品が壊れていないことを固定する。
    fn self_check() -> Result<(), String> {
        use fandhe_container_core::capabilities::OCI_DEFAULT_CAPABILITIES;
        let derived = OCI_DEFAULT_CAPABILITIES
            .iter()
            .fold(0u64, |m, c| m | (1u64 << c.index()));
        if derived != OCI_DEFAULT_MASK {
            return Err(format!(
                "self-check: OCI_DEFAULT_MASK {OCI_DEFAULT_MASK:#x} != core {derived:#x}"
            ));
        }
        let text = "Name:\tprobe\nCapInh:\t0000000000000000\nCapPrm:\t00000000a80425fb\nCapEff:\t00000000a80425fb\nCapBnd:\t00000000a80425fb\nCapAmb:\t0000000000000000\nSeccomp:\t2\n";
        let want = Caps {
            eff: 0xa804_25fb,
            prm: 0xa804_25fb,
            bnd: 0xa804_25fb,
            inh: 0,
            amb: 0,
            seccomp: "2".into(),
        };
        if parse_caps(text).as_ref() != Some(&want) {
            return Err(format!("self-check parse_caps: {:?}", parse_caps(text)));
        }
        if parse_caps("CapEff:\tzz\n").is_some() {
            return Err("self-check parse_caps: accepted a non-hex value".into());
        }
        let leaf = "/a/fc-x@1";
        let cgroup_cases: [(&str, &str, bool); 6] = [
            ("/a/fc-x@1/exec-12-3", leaf, true),
            ("/a/fc-x@1", leaf, false),
            ("/a/fc-x@1/exec-1/x", leaf, false),
            ("/a/fc-x@10/exec-1", leaf, false),
            ("/b/exec-1", leaf, false),
            ("/a/fc-x@1/exec-", leaf, false),
        ];
        for (path, l, want) in cgroup_cases {
            if exec_cgroup_ok(path, l) != want {
                return Err(format!("self-check exec_cgroup_ok({path}): want {want}"));
            }
        }
        let cmd_cases: [(&[u8], bool); 3] = [
            (b"/probe\0--exec-probe\0", true),
            (b"/probe\0--container-probe\0", false),
            (b"", false),
        ];
        for (c, want) in cmd_cases {
            if (c == EXEC_CMDLINE) != want {
                return Err(format!("self-check cmdline {c:?}: want {want}"));
            }
        }
        let bin = Path::new("/tmp/x/bin");
        let names = [SHIM_NAME, SUPERVISOR_NAME];
        let cmd = b"/tmp/x/bin/fandhe-container-supervisor\0--id\0ctr1\0";
        let belongs_cases: [(bool, bool); 3] = [
            (belongs(None, cmd, "ctr1", bin, &names), true),
            (belongs(None, cmd, "ctr", bin, &names), false),
            (belongs(None, b"", "ctr1", bin, &names), false),
        ];
        for (i, (got, want)) in belongs_cases.into_iter().enumerate() {
            if got != want {
                return Err(format!("self-check belongs[{i}]: got {got}, want {want}"));
            }
        }
        match split_leaf("/user.slice/x.scope/fc-abc@7/exec-1-2", "abc") {
            Ok(l) if l == "/user.slice/x.scope/fc-abc@7" => {}
            other => return Err(format!("self-check split_leaf: {other:?}")),
        }
        if split_leaf("/user.slice/x.scope", "abc").is_ok()
            || split_leaf("/x/fc-abc@", "abc").is_ok()
        {
            return Err("self-check split_leaf: accepted an invalid path".into());
        }
        Ok(())
    }

    pub fn main() -> ExitCode {
        if let Err(e) = self_check() {
            eprintln!("shim_v2_exec_real: FAILED: {e}");
            return ExitCode::from(1);
        }
        if !std::env::args().any(|a| a == "--ignored") {
            println!(
                "shim_v2_exec_real: ignored (run the test binary with --ignored in a delegated scope; see crates/plugin-cri/tests/shim_v2_exec_real.rs)"
            );
            return ExitCode::SUCCESS;
        }
        watchdog();
        match scenario() {
            Ok(()) => {
                println!("{LINE_CAPS}");
                println!("{LINE_NS}");
                println!("{LINE_CGROUP}");
                println!("{LINE_EXIT}");
                ExitCode::SUCCESS
            }
            Err(e) => {
                // 回収は scenario 内で済んでいる。前提欠如は回帰と見分けられる行で非ゼロ終了にする。
                match e.strip_prefix(PRECOND_PREFIX) {
                    Some(reason) => print_precondition(reason),
                    None => eprintln!("shim_v2_exec_real: FAILED: {e}"),
                }
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
            test_root::test_root_at(PathBuf::from(format!("/tmp/fse{}", std::process::id())));
        let dir: PathBuf = (*work).to_path_buf();
        let bin = dir.join("bin");
        std::fs::create_dir(&bin).map_err(|e| format!("mkdir bin: {e}"))?;
        install_exe(Path::new(SHIM_SRC), &bin.join(SHIM_NAME))?;
        install_exe(&sup_src, &bin.join(SUPERVISOR_NAME))?;
        let namespace = format!("fcexec{}", std::process::id());
        if let Ok(mut w) = WORK.lock() {
            *w = Some((dir.clone(), bin.clone()));
        }

        let id = container_id();
        let outcome = run_all(&dir, &namespace, &id);

        // 成功の経路: 強制回収の前に、期限つきで自然終了したこと（残存なし）を照合する（REPAIR-12）。
        let clean: Result<(), String> = if outcome.is_ok() {
            check_clean(&dir, &bin, &namespace, &id)
        } else {
            Ok(())
        };

        // check_clean が成功した（exec のコマンドの終了を確認済み）なら追跡を外し、回収済み pid へは何も送らない。
        if outcome.is_ok()
            && clean.is_ok()
            && let Ok(mut p) = PIDS.lock()
        {
            p.clear();
        }

        // 後始末（成否に関わらず）。残った exec のコマンド・shim デーモン・supervisor を止める（watchdog と共通の処理）。
        emergency_cleanup(outcome.is_err());
        if let Err(e) = &outcome {
            let t = std::fs::read_to_string(dir.join("s/daemon.log")).unwrap_or_default();
            let tail: Vec<&str> = t.lines().rev().take(40).collect();
            eprintln!(
                "--- s/daemon.log (last lines) ---\n{}",
                tail.into_iter().rev().collect::<Vec<_>>().join("\n")
            );
            eprintln!("shim_v2_exec_real: diagnostics end: {e}");
        }
        outcome?;
        clean?;
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

    /// コンテナが片付いたことの照合（デーモンと supervisor が残らない・socket が残らない・状態ルートに無い）。
    fn check_clean(dir: &Path, bin: &Path, namespace: &str, id: &str) -> Result<(), String> {
        if !wait_until(Duration::from_secs(15), || {
            processes_with(id, bin).is_empty()
        }) {
            return Err(format!("shim daemon or supervisor for {id} still alive"));
        }
        // Shutdown の応答は socket の削除より先に返るため、socket の消滅も期限つきで待つ（REPAIR-5）。
        let count_socks = || -> Result<usize, String> {
            match std::fs::read_dir(dir.join("s")) {
                Ok(rd) => Ok(rd
                    .flatten()
                    .filter(|e| e.file_type().is_ok_and(|t| t.is_socket()))
                    .count()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(0),
                Err(e) => Err(format!("read socket dir: {e}")),
            }
        };
        let mut socks = count_socks()?;
        if socks != 0 {
            wait_until(Duration::from_secs(15), || {
                socks = count_socks().unwrap_or(usize::MAX);
                socks == 0
            });
        }
        if socks != 0 {
            return Err(format!("{socks} shim socket(s) remain for {id}"));
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
