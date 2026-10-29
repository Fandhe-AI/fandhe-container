//! config の `linux.maskedPaths` / `readonlyPaths` が暗黙の `/dev`・`/dev/pts`・`/dev/shm` と同じパスを指すとき、
//! exec 層（Landlock なし）のマウントがどうなるかを実機で観測する結合試験
//! （SEC-2・CORE-1・CORE-5・OCI-4・TASK-29 追補・#2015。暗黙マウントは #1609、Landlock 側の照合は #2071）。
//!
//! # 位置づけ（誤読の防止）
//! この試験が観測するのは **exec 層だけ**（Landlock を載せない probe）のマウントの結果である。本番の start は、
//! 同じ重なりを fork・予約より前に `InvalidArgument` で拒否する（`oci_runtime::start` の単体テスト
//! `sec2_oci4_start_rejects_protected_paths_over_implicit_dev_mounts`）。fork 後の Landlock 段の照合（#2071）が
//! その後ろ盾である。つまり本試験は「本番が `/dev` を覆ったまま起動する」ことを示すものではなく、拒否の根拠
//! （重なると最上位のマウントが入れ替わる）を実機で確かめるための観測である。
//!
//! `harness = false` の単一スレッド `main` で動かす理由は `config_paths.rs` と同じ（`Cargo.toml` の `[[test]]`）。
//! 非 Linux では `exec` モジュール自体がビルド対象外。
//!
//! # 流れ
//! シナリオごとに新しい rootfs と子を作る（1 件の失敗が他を隠さないため）。masked × {`/dev`, `/dev/pts`,
//! `/dev/shm`}、readonly × {同}。分離 -> `spawn_container_probe_with_tmpfs_and_config_paths`（既定の `/dev/shm` つき。
//! 本番と同じ順序で適用）-> 子をタイムアウト付きで待つ（REPAIR-5）。子（pivot 後）は観測値を `key=value` で pipe へ書き、
//! `ready` の後に親の解放を待つ。親は `/proc/<子の PID>/mountinfo` から対象の最上位のマウント（親 ID で選ぶ）を読む。
//!
//! # 期待値（アサートするもの）
//! - 6 件とも子は `ready` に達して終了コード 0（exec 層には重なりの拒否が無い）
//! - masked: 対象の最上位のマウントが `tmpfs` で `ro,nosuid,nodev,noexec`。対象直下の作成 `open` は `EROFS`
//! - readonly: 対象の最上位のマウントが `ro` で fstype は元のまま（`/dev`・`/dev/shm` は `tmpfs`、`/dev/pts` は `devpts`）
//! - ホスト側 rootfs は不変（`proc` は空のまま）
//!
//! `observed:` 行は断定せず出力するだけの観測値（覆いの下の `/dev/null` が見えるか・`/dev/ptmx` が開けるか等）。
//!
//! # 実機前提テストとしての分離
//! Linux 5.12 以降で root もしくは非特権 user namespace を許可するホストが必要。`-- --ignored` 指定時のみ実行する
//! （ci.md「実機前提テスト」。AGENTS.md）。rootful 経路（root）の実行は root 権限コマンドのため明示指示のもとで行う。
//!
//! # fork 子で観測する理由（#2630・CORE-5・REPAIR-3）
//! `spawn_container_probe_with_tmpfs_and_config_paths` を使い続け、exec 後のエントリポイント内の観測へは移さない。
//! 目的が「Landlock を載せない exec 層のマウントの結果」の観測にあるため。exec 経路は `LaunchReady` のために Landlock が
//! 必須で、本番は同じ重なりを start で拒否する（Landlock 段の照合は #2071）。移すと観測の対象そのものが変わる。

#[path = "support/reap.rs"]
mod reap;

#[cfg(target_os = "linux")]
#[path = "support/temp_rootfs.rs"]
mod temp_rootfs;

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("config_paths_implicit_dev: Linux only, not applicable on this OS");
}

#[cfg(target_os = "linux")]
fn main() {
    if std::env::args().any(|a| a == "--ignored") {
        linux::run();
    } else {
        println!(
            "config_paths_implicit_dev: ignored (real-machine test; run with `-- --ignored`, see AGENTS.md)"
        );
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use crate::temp_rootfs;
    use std::io::{Read as _, Write as _};
    use std::os::unix::fs::FileTypeExt as _;
    use std::path::PathBuf;
    use std::time::Duration;

    use fandhe_container_core::exec::{
        ChildExit, DevptsGidSource, IsolationConfig, Namespace, NamespaceSet, StagePipeline,
        isolate, isolate_rootful_host_root, plan, plan_rootful_host_root,
        spawn_container_probe_with_tmpfs_and_config_paths,
    };
    use fandhe_container_core::rootless::single_id_mapping;
    use fandhe_container_core::tmpfs::TmpfsMountSet;

    /// `EROFS`（x86_64・aarch64 とも同値）。
    const EROFS: i32 = 30;

    #[derive(Clone, Copy, PartialEq)]
    enum Kind {
        Masked,
        Readonly,
    }

    /// 重なりを試す対象と、その fstype（暗黙マウントの元の種別）。
    const TARGETS: [(&str, &str); 3] = [
        ("/dev", "tmpfs"),
        ("/dev/pts", "devpts"),
        ("/dev/shm", "tmpfs"),
    ];

    fn timeout() -> Duration {
        let secs = std::env::var("FANDHE_CONTAINER_TEST_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|s| (1..=600).contains(s))
            .unwrap_or(10);
        Duration::from_secs(secs)
    }

    fn status_field(name: &str) -> String {
        std::fs::read_to_string("/proc/self/status")
            .expect("read status")
            .lines()
            .find(|l| l.starts_with(name))
            .and_then(|l| l.split_whitespace().nth(2).map(str::to_string))
            .unwrap_or_else(|| panic!("no {name} in status"))
    }

    fn is_root() -> bool {
        status_field("Uid:") == "0"
    }

    /// 一時 rootfs（drop で削除）。
    struct Rootfs(PathBuf);

    impl Drop for Rootfs {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn make_rootfs(tag: &str) -> Rootfs {
        // 共有 /tmp 上の推測可能なパスを再利用しない。時刻由来の名前で `create_dir` して排他的に作る（SEC-2）。
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        let base = std::fs::canonicalize(std::env::temp_dir())
            .expect("canonicalize temp_dir")
            .join(format!(
                "fandhe-implicit-dev-{tag}-{}-{nanos}",
                std::process::id()
            ));
        std::fs::create_dir(&base).expect("exclusively create rootfs dir");
        let rootfs = Rootfs(base.clone());
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o755))
                .expect("chmod rootfs dir");
        }
        // `prepare_rootfs` は rootfs/proc の存在を必須とし自動作成しない。
        temp_rootfs::create_dir_chain(&base, &["proc"]);
        rootfs
    }

    /// mountinfo の 1 行（ID・親 ID・マウント先・per-mount options・fstype）。
    struct Entry {
        id: u64,
        parent: u64,
        mount_point: String,
        opts: Vec<String>,
        fstype: String,
    }

    fn parse_mountinfo(mountinfo: &str) -> Vec<Entry> {
        mountinfo
            .lines()
            .filter_map(|l| {
                let f: Vec<&str> = l.split(' ').collect();
                let dash = f.iter().position(|x| *x == "-")?;
                Some(Entry {
                    id: f.first()?.parse().ok()?,
                    parent: f.get(1)?.parse().ok()?,
                    mount_point: f.get(4)?.to_string(),
                    opts: f.get(5)?.split(',').map(str::to_string).collect(),
                    fstype: f.get(dash + 1)?.to_string(),
                })
            })
            .collect()
    }

    /// `target` に積み重なったマウントのうち最上位（同じマウント先の別行の親になっていないもの）。
    fn top_mount<'a>(entries: &'a [Entry], target: &str) -> Option<&'a Entry> {
        let same: Vec<&Entry> = entries.iter().filter(|e| e.mount_point == target).collect();
        same.iter()
            .copied()
            .find(|e| !same.iter().any(|o| o.parent == e.id))
    }

    fn create_errno(path: &str) -> i32 {
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .err()
            .and_then(|e| e.raw_os_error())
            .unwrap_or(0)
    }

    /// 子（コンテナ内）の観測。最後に `ready` を書いて、親が解放バイトを送るまで待つ。
    fn observe(target: &str, mut writer: std::io::PipeWriter, mut gate: std::io::PipeReader) {
        let null_is_char = std::fs::metadata("/dev/null").map(|m| m.file_type().is_char_device());
        writeln!(writer, "dev_null_is_char={null_is_char:?}").expect("write");
        let ptmx = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/ptmx")
            .err()
            .and_then(|e| e.raw_os_error())
            .unwrap_or(0);
        writeln!(writer, "ptmx_open_errno={ptmx}").expect("write");
        writeln!(
            writer,
            "dev_shm_create_errno={}",
            create_errno("/dev/shm/probe")
        )
        .expect("write");
        writeln!(writer, "dev_create_errno={}", create_errno("/dev/probe")).expect("write");
        writeln!(
            writer,
            "target_create_errno={}",
            create_errno(&format!("{target}/probe"))
        )
        .expect("write");
        writeln!(writer, "ready").expect("write");
        // fork で子にも親の書き込み端が複製されるため、EOF は当てにせず解放バイトを待つ。
        let mut release = [0u8; 1];
        let _ = gate.read_exact(&mut release);
    }

    /// 全シナリオを 1 件ずつ別プロセス（自分自身の再実行）で回す。`isolate` は呼び出しプロセスの namespace を
    /// 変える不可逆な操作のため、シナリオごとに新しいプロセスで分離する。
    pub fn run() {
        let args: Vec<String> = std::env::args().collect();
        if let Some(i) = args.iter().position(|a| a == "--scenario") {
            let kind = match args.get(i + 1).map(String::as_str) {
                Some("masked") => Kind::Masked,
                Some("readonly") => Kind::Readonly,
                other => panic!("unknown scenario kind: {other:?}"),
            };
            let (target, fstype) = TARGETS
                .iter()
                .copied()
                .find(|(t, _)| Some(*t) == args.get(i + 2).map(String::as_str))
                .expect("unknown scenario target");
            run_scenario(kind, target, fstype, is_root());
            return;
        }
        let root = is_root();
        let exe = std::env::current_exe().expect("current_exe");
        let mut count = 0;
        for kind in ["masked", "readonly"] {
            for (target, _) in TARGETS {
                let out = run_bounded(&exe, kind, target);
                print!("{}", out.stdout);
                eprint!("{}", out.stderr);
                assert!(
                    out.success,
                    "scenario {kind}:{target} failed: {}",
                    out.status_desc
                );
                count += 1;
            }
        }
        println!(
            "config_paths_implicit_dev: {count} overlaps with the implicit /dev mounts applied at the exec layer (no Landlock); start refuses them before fork (root={root})"
        );
    }

    /// シナリオ子プロセスの結果。
    struct Bounded {
        success: bool,
        status_desc: String,
        stdout: String,
        stderr: String,
    }

    /// シナリオを spawn し、全体の期限（wall clock）内で終了を待つ（REPAIR-5）。
    /// 期限超過時は子のプロセスグループを kill し、出力の収集も有限時間で打ち切る
    /// （孫が pipe を保持し続けても無期限に待たない）。
    fn run_bounded(exe: &std::path::Path, kind: &str, target: &str) -> Bounded {
        use std::os::unix::process::CommandExt as _;
        use std::process::Stdio;
        use std::time::Instant;

        let mut child = std::process::Command::new(exe)
            .args(["--ignored", "--scenario", kind, target])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0)
            .spawn()
            .expect("spawn the scenario process");
        let pgid = child.id();
        let spawn_reader = |mut r: Box<dyn std::io::Read + Send>| {
            let (tx, rx) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let mut buf = Vec::new();
                let _ = r.by_ref().take(1024 * 1024).read_to_end(&mut buf);
                let _ = tx.send(buf);
            });
            rx
        };
        let out_rx = spawn_reader(Box::new(child.stdout.take().expect("stdout pipe")));
        let err_rx = spawn_reader(Box::new(child.stderr.take().expect("stderr pipe")));

        let deadline = Instant::now() + timeout() * 4 + Duration::from_secs(30);
        let (success, status_desc) = loop {
            match child.try_wait() {
                Ok(Some(st)) => break (st.success(), format!("{st:?}")),
                Ok(None) if Instant::now() >= deadline => {
                    // 子孫ごと終了させる（プロセスグループ宛の SIGKILL）。
                    let _ = std::process::Command::new("kill")
                        .args(["-KILL", "--", &format!("-{pgid}")])
                        .status();
                    crate::reap::reap_or_report(&mut child, crate::reap::REAP_WITHIN);
                    break (false, "killed: scenario exceeded its deadline".to_string());
                }
                Ok(None) => std::thread::sleep(Duration::from_millis(50)),
                Err(e) => break (false, format!("try_wait failed: {e}")),
            }
        };
        let grace = Duration::from_secs(5);
        let collect = |rx: std::sync::mpsc::Receiver<Vec<u8>>| {
            rx.recv_timeout(grace)
                .map(|b| String::from_utf8_lossy(&b).into_owned())
                .unwrap_or_default()
        };
        Bounded {
            success,
            status_desc,
            stdout: collect(out_rx),
            stderr: collect(err_rx),
        }
    }

    fn lookup<'a>(text: &'a str, key: &str) -> &'a str {
        text.lines()
            .find_map(|l| l.strip_prefix(&format!("{key}=")))
            .unwrap_or_else(|| panic!("missing observation {key}:\n{text}"))
    }

    fn run_scenario(kind: Kind, target: &'static str, fstype: &str, root: bool) {
        let label = format!(
            "{}:{target}",
            if kind == Kind::Masked {
                "masked"
            } else {
                "readonly"
            }
        );
        let rootfs = make_rootfs(&label.replace([':', '/'], "_"));
        let egid: u32 = status_field("Gid:").parse().expect("parse egid");
        // euid 0 での自 ID 写像は SEC-5 で拒否されるため、root では User を除く rootful 構成にする。
        let mut namespaces = NamespaceSet::empty()
            .with(Namespace::Pid)
            .with(Namespace::Mount)
            .with(Namespace::Uts)
            .with(Namespace::Ipc);
        if !root {
            namespaces = namespaces.with(Namespace::User);
        }
        let config = IsolationConfig {
            namespaces,
            hostname: None,
        };
        let result = if root {
            plan_rootful_host_root(&config).and_then(|p| isolate_rootful_host_root(&p))
        } else {
            plan(&config).and_then(|p| isolate(&p))
        };
        result.unwrap_or_else(|err| panic!("[{label}] isolate failed: {err}"));

        let gid_map;
        let devices = if root {
            DevptsGidSource::Rootful
        } else {
            gid_map = single_id_mapping(egid).expect("single id mapping");
            DevptsGidSource::Rootless(&gid_map)
        };
        let mut tmpfs = TmpfsMountSet::new();
        tmpfs
            .ensure_default_dev_shm()
            .expect("default /dev/shm tmpfs");
        let (readonly, masked): (&[&str], &[&str]) = match kind {
            Kind::Masked => (&[], &[target]),
            Kind::Readonly => (&[target], &[]),
        };
        let (reader, writer) = std::io::pipe().expect("create pipe");
        let (gate_reader, gate_writer) = std::io::pipe().expect("create gate pipe");
        let child = spawn_container_probe_with_tmpfs_and_config_paths(
            &rootfs.0,
            StagePipeline::new(),
            devices,
            &tmpfs,
            readonly,
            masked,
            move || observe(target, writer, gate_reader),
        )
        .unwrap_or_else(|e| panic!("[{label}] spawn: {e}"));
        let kill = |why: &str| -> ! {
            let _ = child.kill_and_reap(Duration::from_secs(5));
            panic!("[{label}] {why}")
        };
        // 子の `ready` までを読む。unshare(CLONE_NEWPID) 後のこのプロセスは pid namespace が
        // 子孫用に切り替わっており、スレッド生成が EINVAL になるため別スレッドは使わない。
        // 子が前段で失敗すれば EOF で戻る。子のハングは親の run_bounded の全体期限
        // （プロセスグループ kill）が回収する（REPAIR-5）。
        let text = {
            let mut text = String::new();
            let mut limited = reader.take(64 * 1024);
            let mut buf = [0u8; 4096];
            loop {
                match limited.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        text.push_str(&String::from_utf8_lossy(&buf[..n]));
                        if text.lines().any(|l| l == "ready") {
                            break;
                        }
                    }
                }
            }
            text
        };
        if !text.lines().any(|l| l == "ready") {
            let exit = child.wait_timeout(timeout());
            panic!("[{label}] the child failed before ready: {exit:?}\n{text}");
        }
        let mountinfo = std::fs::read_to_string(format!("/proc/{}/mountinfo", child.pid()))
            .unwrap_or_else(|e| kill(&format!("read the child's mountinfo: {e}")));
        let mut gate_writer = gate_writer;
        gate_writer.write_all(&[1]).expect("release the child");
        drop(gate_writer);
        let exit = child.wait_timeout(timeout()).unwrap_or_else(|e| {
            let _ = child.kill_and_reap(Duration::from_secs(5));
            panic!("[{label}] wait: {e}")
        });
        assert!(
            matches!(exit, ChildExit::Exited(0)),
            "[{label}] child must exit with 0, got {exit:?}"
        );

        let entries = parse_mountinfo(&mountinfo);
        let top = top_mount(&entries, target)
            .unwrap_or_else(|| panic!("[{label}] {target} must be a mount point:\n{mountinfo}"));
        let opts: Vec<&str> = top.opts.iter().map(String::as_str).collect();
        // 観測値（断定しない）。
        for key in [
            "dev_null_is_char",
            "ptmx_open_errno",
            "dev_shm_create_errno",
            "dev_create_errno",
            "target_create_errno",
        ] {
            println!("observed: {label} {key}={}", lookup(&text, key));
        }
        println!(
            "observed: {label} top_mount fstype={} opts={}",
            top.fstype,
            opts.join(",")
        );
        match kind {
            Kind::Masked => {
                assert_eq!(
                    top.fstype,
                    "tmpfs",
                    "[{label}] {top_opts:?}",
                    top_opts = opts
                );
                for o in ["ro", "nosuid", "nodev", "noexec"] {
                    assert!(
                        opts.contains(&o),
                        "[{label}] top mount must have {o}: {opts:?}"
                    );
                }
                assert_eq!(
                    lookup(&text, "target_create_errno"),
                    EROFS.to_string(),
                    "[{label}] creating under the masked target must fail with EROFS"
                );
            }
            Kind::Readonly => {
                assert_eq!(top.fstype, fstype, "[{label}] fstype must stay as it was");
                assert!(
                    opts.contains(&"ro"),
                    "[{label}] top mount must be read-only: {opts:?}"
                );
            }
        }
        // ホスト側 rootfs は不変（proc は空のまま）。
        assert_eq!(
            std::fs::read_dir(rootfs.0.join("proc"))
                .expect("read proc")
                .count(),
            0,
            "[{label}] host rootfs proc must stay empty"
        );
    }
}
