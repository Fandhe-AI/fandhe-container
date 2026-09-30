//! fork / exec による子プロセス起動（`fandhe_container_core::exec::spawn_container` /
//! `exec_entrypoint`）の結合試験（CORE-1・TASK-27.4.1・#831）。
//!
//! libtest はテストをスレッドで実行し、マルチスレッドからの `CLONE_NEWUSER` は `EINVAL` に
//! なり、`spawn_container` もマルチスレッドでは fork を拒否するため、`harness = false` の
//! 単一スレッド `main` で動かす（`Cargo.toml` の `[[test]]`）。非 Linux では `exec` モジュール自体が
//! ビルド対象外（OS 非該当であり skip ではない）。
//!
//! # 流れ
//! `unshare(CLONE_NEWPID)` の後に最初に生成した子だけが PID 1 になり、それが終わると namespace は
//! 以後 fork できない。そのため各シナリオは、自身を `--scenario <name> <rootfs>` で再起動した新しい
//! プロセスの中で `isolate` → `spawn_container` → `wait_timeout` を行う（検証用のプロセスを spawn
//! するなら `isolate` より前の外側のディスパッチャで行う）。
//! - ディスパッチャ: 分離前に、手組みの静的 ELF プローブ（終了コード 42）をホスト上で直接実行して
//!   バイト列の正しさを自己検証する（バイト列の誤りをランタイムの不具合と取り違えないため）→
//!   シナリオごとに一時 rootfs を作り、タイムアウト付きで終了コード 0 を待つ（REPAIR-5）
//! - 制限（capability 削減・no_new_privs・seccomp）が未適用の間は root（rootful）・非 root（rootless）とも
//!   exec は拒否されるため、全シナリオが `Exited(126)`・stderr に `PERMISSION_DENIED`（SEC-1・CORE-5）。
//!   ステージ列（#832・#833）が適用されたら、下の想定を各シナリオ本来の値へ戻す
//! - シナリオ `ok`: プローブへ exec し `Exited(42)`
//! - シナリオ `missing`: 不在のエントリポイントで `Exited(127)`、stderr に `NOT_FOUND`
//! - シナリオ `not-executable`: 実行権限の無いファイルで `Exited(126)`、stderr に `PERMISSION_DENIED`
//! - シナリオ `stages-order`（#832・TASK-27.4.2、#833・TASK-27.4.3。`spawn_container_with_stages`）:
//!   逆順に登録した 3 段（cgroup 参加・capability 削減・Landlock）のフックが、子の pivot 後（`/` が
//!   新 rootfs）に固定順で実行されることをログファイルで照合する。各フックは自分の時点の
//!   `/proc/self/status` の `NoNewPrivs` を記録し、組み込みの固定ステージが capability 削減の後・
//!   Landlock の前に実際に適用されたこと（Landlock の時点で 1）を照合する。フックが全て成功しても
//!   証跡不在の exec は拒否される（`Exited(126)`・`PERMISSION_DENIED`）
//! - シナリオ `stage-fail`（同上）: 途中の段のフック失敗で後続段と exec に進まず `Exited(125)`
//!   （setup 失敗）、stderr に失敗した段（`at CapabilityDrop`）
//!
//! # 実機前提テストとしての分離
//! 実行には root もしくは非特権 user namespace を許可するホストが必要（AppArmor の
//! `kernel.apparmor_restrict_unprivileged_userns=1` 等の環境では `PermissionDenied` になる）。
//! GitHub ホステッド runner で保証できないため、`-- --ignored` 指定時のみ実行して既定のテスト集合
//! から分離している（ci.md「実機前提テスト」）。実行された場合は分離の拒否を含めあらゆる失敗を
//! 失敗として扱い、検証せずに成功終了する分岐は持たない。プローブは x86_64 / aarch64 の機械語のみ
//! 用意しており、それ以外のアーキテクチャは `sys` が `Unsupported` を返すため not applicable を出力する。

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("fork_exec_isolation: Linux only, not applicable on this OS");
}

#[cfg(all(
    target_os = "linux",
    not(any(target_arch = "x86_64", target_arch = "aarch64"))
))]
fn main() {
    println!("fork_exec_isolation: x86_64/aarch64 only, not applicable on this architecture");
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn main() {
    // `-- --ignored` を付けたときだけ実行する。シナリオは `--scenario <name> <rootfs>` で再入する。
    if std::env::args().any(|a| a == "--ignored" || a == "--scenario") {
        linux::run();
    } else {
        println!(
            "fork_exec_isolation: ignored (real-machine test; run with `-- --ignored`, see AGENTS.md)"
        );
    }
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod linux {
    use std::io::Read as _;
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::{Path, PathBuf};
    use std::process::{Command, ExitStatus, Stdio};
    use std::time::{Duration, Instant};

    use fandhe_container_core::exec::{
        ChildExit, Entrypoint, ExecError, Hostname, IsolationConfig, Namespace, NamespaceSet,
        StageKind, StagePipeline, isolate, isolate_rootful_host_root, plan, plan_rootful_host_root,
        spawn_container, spawn_container_with_stages,
    };

    const PROBE: &str = "fandhe-exec-probe";
    const PROBE_EXIT: i32 = 42;
    const NOT_EXEC: &str = "not-executable";
    /// 子が pivot 後の `/` に追記するステージ実行ログ（親からは `<rootfs>/stage-log`）。
    const STAGE_LOG: &str = "stage-log";
    /// (シナリオ名, stderr に含まれるべき文字列)。
    const SCENARIOS: [(&str, &str); 5] = [
        ("ok", "PERMISSION_DENIED"),
        ("missing", "PERMISSION_DENIED"),
        ("not-executable", "PERMISSION_DENIED"),
        ("stages-order", "PERMISSION_DENIED"),
        ("stage-fail", "at CapabilityDrop"),
    ];

    fn timeout() -> Duration {
        let secs = std::env::var("FANDHE_CONTAINER_TEST_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|s| (1..=600).contains(s))
            .unwrap_or(10);
        Duration::from_secs(secs)
    }

    pub fn run() {
        let args: Vec<String> = std::env::args().collect();
        match args.iter().position(|a| a == "--scenario") {
            Some(i) => {
                let name = args.get(i + 1).expect("scenario name after --scenario");
                let rootfs = args
                    .get(i + 2)
                    .expect("rootfs path after the scenario name");
                scenario(name, Path::new(rootfs));
            }
            None => dispatcher(),
        }
    }

    /// 動的ローダ不要の静的 ELF64 を組み立てる。終了コード 42 で `exit(2)` するだけ。
    /// ヘッダ 64 バイト + PT_LOAD 1 本（56 バイト）+ 機械語。
    fn probe_elf() -> Vec<u8> {
        #[cfg(target_arch = "x86_64")]
        let (machine, code): (u16, &[u8]) = (
            62,
            // mov edi, 42 ; mov eax, 60 (exit) ; syscall
            &[
                0xbf, 0x2a, 0x00, 0x00, 0x00, 0xb8, 0x3c, 0x00, 0x00, 0x00, 0x0f, 0x05,
            ],
        );
        #[cfg(target_arch = "aarch64")]
        let (machine, code): (u16, &[u8]) = (
            183,
            // movz x0, #42 ; movz x8, #93 (exit) ; svc #0
            &[
                0x40, 0x05, 0x80, 0xd2, 0xa8, 0x0b, 0x80, 0xd2, 0x01, 0x00, 0x00, 0xd4,
            ],
        );
        const BASE: u64 = 0x40_0000;
        const HEADERS: u64 = 64 + 56;
        let total = HEADERS + code.len() as u64;
        let mut b = Vec::new();
        // e_ident: ELF64・little endian・version 1・System V ABI。
        b.extend_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        b.extend_from_slice(&2u16.to_le_bytes()); // e_type = ET_EXEC
        b.extend_from_slice(&machine.to_le_bytes());
        b.extend_from_slice(&1u32.to_le_bytes()); // e_version
        b.extend_from_slice(&(BASE + HEADERS).to_le_bytes()); // e_entry
        b.extend_from_slice(&64u64.to_le_bytes()); // e_phoff
        b.extend_from_slice(&0u64.to_le_bytes()); // e_shoff
        b.extend_from_slice(&0u32.to_le_bytes()); // e_flags
        b.extend_from_slice(&64u16.to_le_bytes()); // e_ehsize
        b.extend_from_slice(&56u16.to_le_bytes()); // e_phentsize
        b.extend_from_slice(&1u16.to_le_bytes()); // e_phnum
        b.extend_from_slice(&0u16.to_le_bytes()); // e_shentsize
        b.extend_from_slice(&0u16.to_le_bytes()); // e_shnum
        b.extend_from_slice(&0u16.to_le_bytes()); // e_shstrndx
        assert_eq!(b.len(), 64);
        b.extend_from_slice(&1u32.to_le_bytes()); // p_type = PT_LOAD
        b.extend_from_slice(&5u32.to_le_bytes()); // p_flags = R + X
        b.extend_from_slice(&0u64.to_le_bytes()); // p_offset
        b.extend_from_slice(&BASE.to_le_bytes()); // p_vaddr
        b.extend_from_slice(&BASE.to_le_bytes()); // p_paddr
        b.extend_from_slice(&total.to_le_bytes()); // p_filesz
        b.extend_from_slice(&total.to_le_bytes()); // p_memsz
        b.extend_from_slice(&0x1000u64.to_le_bytes()); // p_align
        assert_eq!(b.len(), 120);
        b.extend_from_slice(code);
        b
    }

    /// 一時 rootfs（drop で削除）。
    struct Rootfs(PathBuf);

    impl Drop for Rootfs {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// `proc/`・実行可能なプローブ・実行権限の無いファイルを持つ rootfs を作る。
    ///
    /// 共有 temp 配下の予測可能な名前への事前配置（symlink 差し替え）を防ぐため、名前に時刻と連番を
    /// 混ぜ、ディレクトリは `mkdir`（既存なら失敗・リンクを辿らない）、ファイルは `O_EXCL`
    /// （`create_new`。リンクを辿らない）で排他的に作る。
    fn make_rootfs(label: &str) -> Rootfs {
        static SEQ: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let base = std::fs::canonicalize(std::env::temp_dir())
            .expect("canonicalize temp_dir")
            .join(format!(
                "fandhe-forkexec-{label}-{}-{nanos}-{seq}",
                std::process::id()
            ));
        std::fs::create_dir(&base).expect("exclusively create rootfs dir");
        // 以降の失敗でも残さないよう、作成直後に drop ガードへ渡す。
        let rootfs = Rootfs(base);
        std::fs::set_permissions(&rootfs.0, std::fs::Permissions::from_mode(0o755))
            .expect("chmod rootfs dir");
        std::fs::create_dir(rootfs.0.join("proc")).expect("create rootfs/proc");
        write_file(&rootfs.0.join(PROBE), &probe_elf(), 0o755);
        write_file(&rootfs.0.join(NOT_EXEC), &probe_elf(), 0o644);
        rootfs
    }

    /// `O_EXCL` で新規作成する（既存パス・symlink があれば失敗し、リンク先を上書きしない）。
    fn write_file(path: &Path, bytes: &[u8], mode: u32) {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt as _;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(path)
            .expect("exclusively create file");
        f.write_all(bytes).expect("write file");
        f.set_permissions(std::fs::Permissions::from_mode(mode))
            .expect("chmod");
    }

    /// 子を期限付きで待つ。期限超過なら kill して回収し `None`（REPAIR-5）。kill 後の回収にも
    /// 期限を設け、回収できなければ panic（失敗）にする。
    fn wait_deadline(child: &mut std::process::Child, limit: Duration) -> Option<ExitStatus> {
        let deadline = Instant::now() + limit;
        loop {
            match child.try_wait().expect("try_wait") {
                Some(status) => return Some(status),
                None if Instant::now() >= deadline => {
                    let _ = child.kill();
                    let reap_deadline = Instant::now() + Duration::from_secs(5);
                    while child.try_wait().expect("try_wait").is_none() {
                        assert!(
                            Instant::now() < reap_deadline,
                            "the child was not reaped after SIGKILL"
                        );
                        std::thread::sleep(Duration::from_millis(20));
                    }
                    return None;
                }
                None => std::thread::sleep(Duration::from_millis(20)),
            }
        }
    }

    /// 自己検証: 分離前にホスト上でプローブを直接実行し、終了コード 42 を確かめる（期限付き）。
    fn verify_probe_on_host() {
        let rootfs = make_rootfs("selfcheck");
        let mut child = Command::new(rootfs.0.join(PROBE))
            .stdin(Stdio::null())
            .spawn()
            .expect("run the probe directly on the host (is the temp dir mounted noexec?)");
        let status = wait_deadline(&mut child, timeout())
            .unwrap_or_else(|| panic!("host probe did not exit within {:?}", timeout()));
        assert_eq!(
            status.code(),
            Some(PROBE_EXIT),
            "the hand-made ELF probe is broken; this is a test bug, not a runtime bug"
        );
    }

    fn dispatcher() {
        verify_probe_on_host();
        let exe = std::env::current_exe().expect("current_exe");
        for (name, marker) in SCENARIOS {
            let rootfs = make_rootfs(name);
            let mut child = Command::new(&exe)
                .args(["--scenario", name])
                .arg(&rootfs.0)
                .stdin(Stdio::null())
                .stderr(Stdio::piped())
                .spawn()
                .expect("spawn scenario");
            let status = wait_deadline(&mut child, timeout())
                .unwrap_or_else(|| panic!("scenario {name} did not exit within {:?}", timeout()));
            let mut stderr = String::new();
            child
                .stderr
                .take()
                .expect("piped stderr")
                .read_to_string(&mut stderr)
                .expect("read scenario stderr");
            assert_eq!(
                status.code(),
                Some(0),
                "scenario {name} must exit with 0; stderr:\n{stderr}"
            );
            // SEC-1・CORE-5: 制限が未適用の間は exec が拒否される（`stage-fail` はフック失敗で
            // exec に到達しないため、失敗した段を照合する）。
            assert!(
                stderr.contains(marker),
                "stderr of scenario {name} must contain {marker}; got:\n{stderr}"
            );
        }
        let is_root = is_root();
        println!("fork_exec_isolation: fork/exec verified (root={is_root})");
    }

    fn is_root() -> bool {
        std::fs::read_to_string("/proc/self/status")
            .expect("read status")
            .lines()
            .find(|l| l.starts_with("Uid:"))
            .and_then(|l| l.split_whitespace().nth(2).map(str::to_string))
            .as_deref()
            == Some("0")
    }

    /// 分離（`pivot_root_isolation` と同じ分岐: root は rootful、非 root は rootless）→ fork/exec →
    /// 終了状態の照合。分離の拒否を含むあらゆる失敗は panic（失敗）にする。
    fn scenario(name: &str, rootfs: &Path) {
        let is_root = is_root();
        // 環境（docker 等）が既に NO_NEW_PRIVS=1 のことがあるため、適用前の値を記録して期待値にする。
        let inherited_nnp = no_new_privs_flag();
        let mut namespaces = NamespaceSet::empty()
            .with(Namespace::Pid)
            .with(Namespace::Mount)
            .with(Namespace::Uts)
            .with(Namespace::Ipc);
        if !is_root {
            namespaces = namespaces.with(Namespace::User);
        }
        let config = IsolationConfig {
            namespaces,
            hostname: None,
        };
        let result = if is_root {
            plan_rootful_host_root(&config).and_then(|p| isolate_rootful_host_root(&p))
        } else {
            plan(&config).and_then(|p| isolate(&p))
        };
        result.unwrap_or_else(|err| panic!("isolate failed: {err}"));

        let path = match name {
            "ok" => format!("/{PROBE}"),
            "missing" => "/no-such-entrypoint".to_string(),
            "not-executable" => format!("/{NOT_EXEC}"),
            "stages-order" | "stage-fail" => format!("/{PROBE}"),
            other => panic!("unknown scenario {other}"),
        };
        // SEC-1・CORE-5: capability 削減・no_new_privs・seccomp が未適用の間は、root / 非 root を問わず
        // exec が拒否される（終了コード 126・PERMISSION_DENIED）。適用後は "ok" が Exited(PROBE_EXIT)、
        // "missing" が Exited(127) に戻る。
        let mut want = ChildExit::Exited(126);
        let entry = Entrypoint::new(&path, [path.as_str()], [] as [&str; 0]).expect("entrypoint");
        let child = match name {
            "stages-order" => {
                // 逆順に登録しても固定順（cgroup_join → capability_drop → [組み込みの no_new_privs]
                // → landlock）で実行される。NO_NEW_PRIVS は組み込みのため登録しない。
                let stages = StagePipeline::new()
                    .with_hook(StageKind::Landlock, logging_hook(StageKind::Landlock))
                    .and_then(|p| {
                        p.with_hook(
                            StageKind::CapabilityDrop,
                            logging_hook(StageKind::CapabilityDrop),
                        )
                    })
                    .and_then(|p| {
                        p.with_hook(StageKind::CgroupJoin, logging_hook(StageKind::CgroupJoin))
                    })
                    .unwrap_or_else(|e| panic!("register hooks: {e}"));
                spawn_container_with_stages(rootfs, &entry, stages)
            }
            "stage-fail" => {
                // CapabilityDrop のフックが失敗する。後続の Landlock と exec は実行されない。
                let stages = StagePipeline::new()
                    .with_hook(StageKind::CgroupJoin, logging_hook(StageKind::CgroupJoin))
                    .and_then(|p| p.with_hook(StageKind::CapabilityDrop, failing_hook))
                    .and_then(|p| {
                        p.with_hook(StageKind::Landlock, logging_hook(StageKind::Landlock))
                    })
                    .unwrap_or_else(|e| panic!("register hooks: {e}"));
                want = ChildExit::Exited(125);
                spawn_container_with_stages(rootfs, &entry, stages)
            }
            _ => spawn_container(rootfs, &entry),
        }
        .unwrap_or_else(|e| panic!("spawn: {e}"));
        let exit = child
            .wait_timeout(timeout())
            .unwrap_or_else(|e| panic!("wait: {e}"));
        assert_eq!(exit, want, "scenario {name}");

        // 子（pivot 後の `/`）が書いたログを、親から rootfs 越しに読んで実行順・位置を照合する。
        let log = std::fs::read_to_string(rootfs.join(STAGE_LOG)).unwrap_or_default();
        match name {
            // 各フックは pivot 後の `/` にプローブが見えること（root=1）を記録する。ホスト側の `/` には
            // プローブは無いため、pivot 前に実行されていれば root=0 になる。
            "stages-order" => assert_eq!(
                log,
                format!(
                    "cgroup_join root=1 nnp={inherited_nnp}\ncapability_drop root=1 nnp={inherited_nnp}\nlandlock root=1 nnp=1\n"
                ),
                "hooks must run in fixed order after pivot_root, with NO_NEW_PRIVS applied before landlock"
            ),
            "stage-fail" => assert_eq!(
                log,
                format!("cgroup_join root=1 nnp={inherited_nnp}\n"),
                "no stage after the failed one may run"
            ),
            _ => assert_eq!(log, "", "no hook is registered"),
        }
    }

    /// 自プロセスの `/proc/self/status` の `NoNewPrivs:` の値（0 または 1）。
    fn no_new_privs_flag() -> u8 {
        let status = std::fs::read_to_string("/proc/self/status")
            .unwrap_or_else(|e| panic!("read /proc/self/status: {e}"));
        let line = status
            .lines()
            .find(|l| l.starts_with("NoNewPrivs:"))
            .unwrap_or_else(|| panic!("NoNewPrivs line missing"));
        match line.split_whitespace().nth(1) {
            Some("0") => 0,
            Some("1") => 1,
            other => panic!("unexpected NoNewPrivs value: {other:?}"),
        }
    }

    /// 子の pivot 後の `/` に自段名・「新 rootfs が見えているか」・その時点の `NoNewPrivs` を追記して
    /// 成功するフック。
    fn logging_hook(kind: StageKind) -> impl FnMut() -> Result<(), ExecError> + 'static {
        move || {
            use std::io::Write as _;
            let root = u8::from(Path::new(&format!("/{PROBE}")).exists());
            let mut f = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(format!("/{STAGE_LOG}"))
                .unwrap_or_else(|e| panic!("open stage log in the child: {e}"));
            let nnp = no_new_privs_flag();
            writeln!(f, "{} root={root} nnp={nnp}", kind.as_str())
                .unwrap_or_else(|e| panic!("write stage log in the child: {e}"));
            Ok(())
        }
    }

    /// 必ず失敗するフック（公開 API で作れる `ExecError` として不正なホスト名の検証エラーを流用する）。
    fn failing_hook() -> Result<(), ExecError> {
        Hostname::new("").map(|_| ())
    }
}
