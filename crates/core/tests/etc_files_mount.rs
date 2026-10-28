//! 管理ルートの `/etc/hosts`・`/etc/resolv.conf` を rootfs へ bind する段
//! （`fandhe_container_core::exec::mount_etc_files`）の結合試験（NET-12・NET-8・CORE-1・SEC-1・SEC-5・TASK-185 追補・#1872）。
//!
//! `harness = false` の単一スレッド `main` で動かす理由・流れは `inject_files.rs` と同じ（`Cargo.toml` の `[[test]]`）。
//! 非 Linux では `exec` モジュール自体がビルド対象外。
//!
//! # 流れ
//! 外側の `main` が、次の 3 つのモードをそれぞれ別プロセス（`--mode <m>`）で実行する（`isolate` の後の最初の子だけが
//! 新しい PID namespace の PID 1 になるため、モードごとに分離をやり直す）。各モードの親は、状態ルート（0700）に
//! `create_etc_files` で hosts と resolv.conf を作り、rootfs を用意して分離し、自身を `--child` で起動する
//! （子が PID 1）。子は `establish` → `prepare_rootfs` の後、同じ分離の中で次を具体値で照合する。
//!
//! - `rw`: (1) 先の `etc/resolv.conf` が symlink（`../outside/leak`。絶対パスと systemd-resolved 形の `../run/systemd/resolve/stub-resolv.conf` も同様。解決せず、`run/` も作らない）なら `InvalidArgument` で拒否し、先に成功していた
//!   hosts の bind も外れ、symlink の先（`outside`）に何も作られないこと（逆方向の脱出と後始末）。(2) symlink を消すと
//!   hosts（既存）と resolv.conf（無いので空ファイルを作成）が載り、`pivot_root` の後に `/etc/hosts` の内容が
//!   `INITIAL_HOSTS` と一致し、mountinfo で `rw,nosuid,nodev,noexec`、`st_ino` が元と一致し、コンテナ内からの書き込みが
//!   ホスト側の元ファイルへ反映されること
//! - `ro`: (1) 実効 `root.readonly=true` で先に `etc/resolv.conf` が無いと `FailedPrecondition` で拒否し、rootfs へ何も作らず、
//!   hosts の bind も外れること。(2) hosts だけを ro で載せ、mountinfo に `ro` が立ち、書き込みが `EROFS`（errno 30）になること
//! - `etc-symlink`: rootfs の `etc` が symlink なら `InvalidArgument` で拒否し、リンク先に何も作られないこと
//!
//! # 実機前提テストとしての分離
//! root もしくは非特権 user namespace を許可するホスト（Linux 5.12 以降）が必要で、GitHub ホステッド runner では
//! 保証できないため `-- --ignored` 指定時のみ実行する（ci.md「実機前提テスト」）。CI では `platform-ci`
//! （ubuntu-latest）が AppArmor の制限を緩和した後に rootless 経路で実行し、成功行を照合する。rootful 経路（root）は
//! root 権限コマンドのため明示指示のもとで行う（本番の起動経路は `RootfulHostRoot` を拒否しているため、この経路は
//! 段の単体の確認に限る。#2241・SEC-5）。

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("etc_files_mount: Linux only, not applicable on this OS");
}

#[cfg(target_os = "linux")]
fn main() {
    if std::env::args().any(|a| a == "--ignored" || a == "--child") {
        linux::run();
    } else {
        println!(
            "etc_files_mount: ignored (real-machine test; run with `-- --ignored`, see AGENTS.md)"
        );
    }
}

#[cfg(target_os = "linux")]
#[path = "support/temp_rootfs.rs"]
mod temp_rootfs;

#[cfg(target_os = "linux")]
mod linux {
    use crate::temp_rootfs;
    use std::os::unix::fs::MetadataExt as _;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    use fandhe_container_core::etc_files::{
        EtcFileKind, EtcFileSelection, INITIAL_HOSTS, create_etc_files, etc_file_path,
    };
    use fandhe_container_core::exec::{
        EtcFileMounts, IsolationConfig, IsolationStage, MountIsolation, Namespace, NamespaceSet,
        isolate, isolate_rootful_host_root, mount_etc_files, pivot_root, plan,
        plan_rootful_host_root, prepare_rootfs,
    };
    use fandhe_container_core::traits::{ContainerId, ErrorCode};

    const EROFS: i32 = 30;
    const MODES: [&str; 3] = ["rw", "ro", "etc-symlink"];
    const APPENDED: &str = "10.0.0.9\tweb\n";
    const IMAGE_HOSTS: &str = "image hosts\n";

    fn is_root() -> bool {
        std::fs::read_to_string("/proc/self/status")
            .expect("read status")
            .lines()
            .find(|l| l.starts_with("Uid:"))
            .and_then(|l| l.split_whitespace().nth(2).map(str::to_string))
            .as_deref()
            == Some("0")
    }

    fn timeout() -> Duration {
        let secs = std::env::var("FANDHE_CONTAINER_TEST_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|s| (1..=600).contains(s))
            .unwrap_or(10);
        Duration::from_secs(secs)
    }

    fn both() -> EtcFileSelection {
        EtcFileSelection::default()
            .with(EtcFileKind::Hosts)
            .with(EtcFileKind::ResolvConf)
    }

    fn container_id() -> ContainerId {
        ContainerId::new("etc-mount-test").expect("container id")
    }

    pub fn run() {
        let args: Vec<String> = std::env::args().collect();
        if let Some(i) = args.iter().position(|a| a == "--child") {
            let mode = args.get(i + 1).expect("mode after --child");
            let rootfs = args.get(i + 2).expect("rootfs after mode");
            let state = args.get(i + 3).expect("state root after rootfs");
            child(mode, Path::new(rootfs), Path::new(state));
        } else if let Some(i) = args.iter().position(|a| a == "--mode") {
            parent(args.get(i + 1).expect("mode after --mode"));
        } else {
            outer();
        }
    }

    /// モードごとに別プロセスで再実行し、すべて終了コード 0 なら成功行を出す。
    fn outer() {
        let exe = std::env::current_exe().expect("current_exe");
        for mode in MODES {
            let status = wait_with_timeout(
                Command::new(&exe)
                    .args(["--ignored", "--mode", mode])
                    .stdin(Stdio::null())
                    .spawn()
                    .expect("spawn mode"),
            );
            assert_eq!(status, Some(0), "mode {mode} must exit with 0");
        }
        let root = is_root();
        println!(
            "etc_files_mount: content, read-only, escape rejection and rollback verified (root={root})"
        );
    }

    /// 終了コードを返す（期限切れは kill して panic。REPAIR-5）。
    fn wait_with_timeout(mut child: std::process::Child) -> Option<i32> {
        let deadline = Instant::now() + timeout() * 3;
        loop {
            match child.try_wait().expect("try_wait") {
                Some(status) => return status.code(),
                None if Instant::now() >= deadline => {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!("child did not exit within the timeout");
                }
                None => std::thread::sleep(Duration::from_millis(20)),
            }
        }
    }

    struct Dir(PathBuf);

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// モードごとの rootfs。`proc/`・`dev/`・`outside/` は共通。
    fn make_rootfs(mode: &str) -> Dir {
        let base = temp_rootfs::exclusive_temp_dir("fandhe-etcmnt", 0o755);
        temp_rootfs::create_dir_chain(&base, &["proc"]);
        temp_rootfs::create_dir_chain(&base, &["dev"]);
        temp_rootfs::create_dir_chain(&base, &["outside"]);
        match mode {
            "rw" => {
                temp_rootfs::create_dir_chain(&base, &["etc"]);
                std::fs::write(base.join("etc/hosts"), IMAGE_HOSTS).expect("image hosts");
                std::os::unix::fs::symlink("../outside/leak", base.join("etc/resolv.conf"))
                    .expect("symlink resolv.conf");
            }
            "ro" => {
                temp_rootfs::create_dir_chain(&base, &["etc"]);
                std::fs::write(base.join("etc/hosts"), IMAGE_HOSTS).expect("image hosts");
            }
            "etc-symlink" => {
                std::os::unix::fs::symlink("outside", base.join("etc")).expect("symlink etc");
            }
            other => panic!("unknown mode {other}"),
        }
        Dir(base)
    }

    fn parent(mode: &str) {
        let rootfs = make_rootfs(mode);
        // 管理ルート(0700)に supervisor の役で生成する。
        let state = Dir(temp_rootfs::exclusive_temp_dir(
            "fandhe-etcmnt-state",
            0o700,
        ));
        create_etc_files(&state.0, &container_id(), both()).expect("create etc files");
        let root = is_root();
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
        if let Err(err) = result {
            panic!("isolate failed: {err}");
        }
        let exe = std::env::current_exe().expect("current_exe");
        let child = Command::new(exe)
            .arg("--child")
            .arg(mode)
            .arg(&rootfs.0)
            .arg(&state.0)
            .stdin(Stdio::null())
            .spawn()
            .expect("spawn child");
        assert_eq!(wait_with_timeout(child), Some(0), "child must exit with 0");
        assert_host_side(mode, &rootfs.0, &state.0);
    }

    /// 子の終了後(mount namespace が消えた後)のホスト側の照合。
    fn assert_host_side(mode: &str, rootfs: &Path, state: &Path) {
        let outside = std::fs::read_dir(rootfs.join("outside"))
            .expect("read outside")
            .count();
        assert_eq!(outside, 0, "nothing may be created behind a symlink");
        let hosts = std::fs::read(etc_file_path(state, &container_id(), EtcFileKind::Hosts))
            .expect("read source hosts");
        match mode {
            "rw" => {
                let mut want = INITIAL_HOSTS.to_vec();
                want.extend_from_slice(APPENDED.as_bytes());
                assert_eq!(hosts, want, "a write in the container reaches the source");
                // rootfs 側の実ファイルは元のまま(bind は上に載っただけ)。
                assert_eq!(
                    std::fs::read_to_string(rootfs.join("etc/hosts")).expect("rootfs hosts"),
                    IMAGE_HOSTS
                );
                // 無かった resolv.conf は空の通常ファイルとして作られ、残る。
                let m = std::fs::symlink_metadata(rootfs.join("etc/resolv.conf"))
                    .expect("created resolv.conf");
                assert!(m.file_type().is_file());
                assert_eq!(m.len(), 0);
            }
            "ro" => {
                assert_eq!(
                    hosts, INITIAL_HOSTS,
                    "a read-only mount leaves the source intact"
                );
                assert!(
                    !rootfs.join("etc/resolv.conf").exists(),
                    "a read-only rootfs must not gain a file"
                );
            }
            _ => assert_eq!(hosts, INITIAL_HOSTS),
        }
    }

    /// mountinfo の 1 行から `(mount_point, mount_options)`。
    fn parse_line(line: &str) -> Option<(String, String)> {
        let fields: Vec<&str> = line.split(' ').collect();
        Some(((*fields.get(4)?).to_owned(), (*fields.get(5)?).to_owned()))
    }

    fn mounts_ending_with(info: &str, suffix: &str) -> Vec<String> {
        info.lines()
            .filter_map(parse_line)
            .map(|l| l.0)
            .filter(|p| p.ends_with(suffix))
            .collect()
    }

    fn child(mode: &str, rootfs: &Path, state: &Path) {
        assert_eq!(
            std::process::id(),
            1,
            "child must be PID 1 of the new PID namespace"
        );
        let id = container_id();
        let isolation = MountIsolation::establish().expect("establish mount isolation");
        let prepared = prepare_rootfs(&isolation, rootfs).expect("prepare rootfs");
        match mode {
            "rw" => child_rw(&isolation, prepared, rootfs, state, &id),
            "ro" => child_ro(&isolation, prepared, rootfs, state, &id),
            "etc-symlink" => child_etc_symlink(&isolation, &prepared, rootfs, state, &id),
            other => panic!("unknown mode {other}"),
        }
    }

    fn child_rw(
        isolation: &MountIsolation,
        prepared: fandhe_container_core::exec::PreparedRootfs,
        rootfs: &Path,
        state: &Path,
        id: &ContainerId,
    ) {
        let mounts = EtcFileMounts::verify(state, id, both(), false).expect("verify");
        // (1) resolv.conf が symlink: 拒否され、先に載った hosts も外れる。
        let err = mount_etc_files(isolation, &prepared, &mounts).expect_err("symlink destination");
        assert_eq!(err.stage, IsolationStage::MountEtcFiles);
        assert_eq!(err.code, ErrorCode::InvalidArgument, "{}", err.message);
        assert!(
            !err.message.contains("cleanup failed"),
            "rollback must succeed on a real mount: {}",
            err.message
        );
        let info = std::fs::read_to_string("/proc/thread-self/mountinfo").expect("mountinfo");
        assert_eq!(
            mounts_ending_with(&info, "/etc/hosts"),
            Vec::<String>::new(),
            "the first mount must be rolled back"
        );
        assert_eq!(
            std::fs::read_to_string(rootfs.join("etc/hosts")).expect("rootfs hosts"),
            IMAGE_HOSTS
        );
        assert_eq!(
            std::fs::read_dir(rootfs.join("outside"))
                .expect("outside")
                .count(),
            0,
            "nothing may be created behind the symlink"
        );

        // (1b) 絶対パスの symlink と、systemd-resolved 形（rootfs に無い `run/` を指す）も解決せず拒否し、
        // 解決先の親ディレクトリを作らない（D9・#3210）。
        for link in ["/outside/leak", "../run/systemd/resolve/stub-resolv.conf"] {
            let dst = rootfs.join("etc/resolv.conf");
            std::fs::remove_file(&dst).expect("remove symlink");
            std::os::unix::fs::symlink(link, &dst).expect("symlink resolv.conf");
            let err = mount_etc_files(isolation, &prepared, &mounts).expect_err(link);
            assert_eq!(err.stage, IsolationStage::MountEtcFiles, "{link}");
            assert_eq!(
                err.code,
                ErrorCode::InvalidArgument,
                "{link}: {}",
                err.message
            );
            assert!(
                !err.message.contains("cleanup failed"),
                "{link}: {}",
                err.message
            );
            let info = std::fs::read_to_string("/proc/thread-self/mountinfo").expect("mountinfo");
            assert_eq!(
                mounts_ending_with(&info, "/etc/hosts"),
                Vec::<String>::new(),
                "{link}: the first mount must be rolled back"
            );
            assert!(
                !rootfs.join("run").exists(),
                "{link}: run/ must not be created"
            );
            assert_eq!(
                std::fs::read_dir(rootfs.join("outside"))
                    .expect("outside")
                    .count(),
                0,
                "{link}: nothing may be created behind the symlink"
            );
        }

        // (2) symlink を除くと、hosts は既存へ、resolv.conf は空ファイルを作って載る。
        std::fs::remove_file(rootfs.join("etc/resolv.conf")).expect("remove symlink");
        let report = mount_etc_files(isolation, &prepared, &mounts).expect("mount etc files");
        let got: Vec<(EtcFileKind, &str, bool, bool)> = report
            .mounts
            .iter()
            .map(|m| (m.kind, m.destination, m.read_only, m.created_target))
            .collect();
        assert_eq!(
            got,
            vec![
                (EtcFileKind::Hosts, "/etc/hosts", false, false),
                (EtcFileKind::ResolvConf, "/etc/resolv.conf", false, true),
            ]
        );
        let src_ino = std::fs::metadata(etc_file_path(state, id, EtcFileKind::Hosts))
            .expect("source")
            .ino();
        pivot_root(isolation, prepared).expect("pivot_root");

        assert_eq!(std::fs::read("/etc/hosts").expect("hosts"), INITIAL_HOSTS);
        assert_eq!(std::fs::read("/etc/resolv.conf").expect("resolv"), b"");
        assert_eq!(
            std::fs::metadata("/etc/hosts").expect("stat").ino(),
            src_ino
        );
        let info = std::fs::read_to_string("/proc/self/mountinfo").expect("mountinfo");
        for point in ["/etc/hosts", "/etc/resolv.conf"] {
            let (_, opts) = info
                .lines()
                .filter_map(parse_line)
                .find(|l| l.0 == point)
                .unwrap_or_else(|| panic!("{point} must be mounted:\n{info}"));
            let opts: Vec<&str> = opts.split(',').collect();
            for want in ["rw", "nosuid", "nodev", "noexec"] {
                assert!(opts.contains(&want), "{point} must be {want}: {opts:?}");
            }
            assert!(!opts.contains(&"ro"), "{point} must not be ro: {opts:?}");
        }
        // コンテナ内からの追記はホスト側の元ファイルへ届く(親が照合する)。
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open("/etc/hosts")
            .expect("open hosts for append");
        std::io::Write::write_all(&mut f, APPENDED.as_bytes()).expect("append");
    }

    fn child_ro(
        isolation: &MountIsolation,
        prepared: fandhe_container_core::exec::PreparedRootfs,
        rootfs: &Path,
        state: &Path,
        id: &ContainerId,
    ) {
        // (1) 読み取り専用の rootfs で先が無い: rootfs へ書かずに拒否し、先に載った hosts も外れる。
        let mounts = EtcFileMounts::verify(state, id, both(), true).expect("verify ro");
        let err = mount_etc_files(isolation, &prepared, &mounts).expect_err("missing under ro");
        assert_eq!(err.stage, IsolationStage::MountEtcFiles);
        assert_eq!(err.code, ErrorCode::FailedPrecondition, "{}", err.message);
        assert!(!rootfs.join("etc/resolv.conf").exists());
        let info = std::fs::read_to_string("/proc/thread-self/mountinfo").expect("mountinfo");
        assert_eq!(
            mounts_ending_with(&info, "/etc/hosts"),
            Vec::<String>::new(),
            "the first mount must be rolled back"
        );

        // (2) hosts だけを ro で載せる。
        let sel = EtcFileSelection::default().with(EtcFileKind::Hosts);
        let mounts = EtcFileMounts::verify(state, id, sel, true).expect("verify hosts only");
        let report = mount_etc_files(isolation, &prepared, &mounts).expect("mount ro");
        assert_eq!(report.mounts.len(), 1);
        assert!(
            report
                .mounts
                .iter()
                .all(|m| m.read_only && !m.created_target)
        );
        pivot_root(isolation, prepared).expect("pivot_root");
        assert_eq!(std::fs::read("/etc/hosts").expect("hosts"), INITIAL_HOSTS);
        let info = std::fs::read_to_string("/proc/self/mountinfo").expect("mountinfo");
        let (_, opts) = info
            .lines()
            .filter_map(parse_line)
            .find(|l| l.0 == "/etc/hosts")
            .unwrap_or_else(|| panic!("/etc/hosts must be mounted:\n{info}"));
        let opts: Vec<&str> = opts.split(',').collect();
        for want in ["ro", "nosuid", "nodev", "noexec"] {
            assert!(opts.contains(&want), "/etc/hosts must be {want}: {opts:?}");
        }
        let e = std::fs::OpenOptions::new()
            .write(true)
            .open("/etc/hosts")
            .expect_err("write to a read-only mount");
        assert_eq!(e.raw_os_error(), Some(EROFS), "{e}");
    }

    fn child_etc_symlink(
        isolation: &MountIsolation,
        prepared: &fandhe_container_core::exec::PreparedRootfs,
        _rootfs: &Path,
        state: &Path,
        id: &ContainerId,
    ) {
        let mounts = EtcFileMounts::verify(state, id, both(), false).expect("verify");
        let err = mount_etc_files(isolation, prepared, &mounts).expect_err("symlinked /etc");
        assert_eq!(err.stage, IsolationStage::MountEtcFiles);
        assert_eq!(err.code, ErrorCode::InvalidArgument, "{}", err.message);
        // `outside` に何も作られていないことは親が照合する(`assert_host_side`)。
    }
}
