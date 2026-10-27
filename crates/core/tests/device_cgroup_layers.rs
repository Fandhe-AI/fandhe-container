//! 既定のデバイス制限を層ごとに実機照合する結合試験（SEC-1・CORE-1・CORE-4・TASK-32 追補・MS-2・#1681。関連 CORE-5・REPAIR-7・REPAIR-12）。
//!
//! Landlock と seccomp を**適用しない**構成で、rootful のコンテナ用 cgroup に既定のデバイス許可プログラム
//! （`apply_default_device_policy`。#1680）を付け、デバイス cgroup の拒否（`EPERM`=1）と rootfs の自己 bind の
//! `nodev`（`prepare_rootfs`。#1676）の拒否（`EACCES`=13）を errno で区別して照合する。Landlock も `EACCES` を返す
//! ため、errno で層を区別できるのは Landlock を適用しない構成に限る（Landlock の層は `landlock_implicit_dev.rs`）。
//!
//! # 照合する内容（子の中。期待値はすべて具体値）
//! - 許可: `/dev/null` への書き込み・`/dev/zero` から読んだ 16 バイトがすべて 0・`/dev/urandom` から 16 バイト・
//!   `/dev/ptmx` を `O_NOCTTY` で開いて得た pty の slave（major 136）を開ける
//! - デバイス cgroup の層（nodev でない `/dev` の tmpfs の上）: 事前に作った c 120:0 の open が `EPERM`。c 120:1・
//!   c 10:200 の `mknodat` が `EPERM` でノードが残らない。許可リストにある c 1:3 の `mknodat` は成功する
//! - nodev の層（rootfs の `opt/`）: c 1:3（許可リストにある）も c 120:0（許可リストに無い）も open が `EACCES`
//!   （`EPERM` にならない。Linux の `may_open()` は `may_open_dev()`〔`MNT_NODEV`〕を `inode_permission()` 内の
//!   `devcgroup_inode_permission()` より先に評価するため）
//! - 継承: コンテナ用 cgroup の下の `exec-*` 子 cgroup に入れた別プロセスでも、c 120:0 の open が `EPERM`、
//!   `/dev/null` は開ける。`exec-*` 自身にはプログラムが付かない（祖先の実効集合で継承される）
//! - 問い合わせ: コンテナ用 cgroup の `BPF_PROG_QUERY` でプログラム数 1・attach flags 0
//! - 後始末: 試験の cgroup と一時 rootfs が消え、ホスト側の cgroup にプログラムが残らない
//!
//! # 試験用の major に 120 を使う理由
//! 当初想定の 240 は、カーネルの動的 major 割り当て（`fs/char_dev.c` の `find_dynamic_major()` は 254 から 234 へ向けて
//! 割り当てる）と重なり、開発ホストの `/proc/devices` にも `240 ttyDBC` が実在した。devices.txt で char 120-127 は
//! LOCAL/EXPERIMENTAL USE で動的割り当ての範囲（234-254・384-511）の外にある。親は `/proc/devices` に 120 が無いことを
//! 確かめ、あれば失敗する（拒否が効かなかった場合でも実在のドライバに届かない）。ドライバが無い 120:0 の open は
//! cgroup の外では `ENXIO`（6）になり、それを対照にする。
//!
//! # 流れ
//! - 親（root・委譲スコープ内。単一スレッド）: `DelegatedCgroup::prepare` → 既定のポリシーを付与 → `exec-*` 作成 →
//!   一時 rootfs（`opt/fake-null`・`opt/fake-local` を coreutils の `mknod` で作る）→ `isolate_rootful_host_root` →
//!   自身を `--child` で起動（新しい PID namespace の PID 1）→ タイムアウト付きで待つ → 後始末 → 照合
//! - 子: `establish` → `prepare_rootfs` → `create_default_devices`（Landlock・seccomp・capability の削減は呼ばない）→
//!   cgroup に入る前に c 120:0 を作る → コンテナ用 cgroup に入る → 照合 → 孫（`--grandchild`）を起動
//! - 孫: `exec-*` に入って継承を照合する
//!
//! `pivot_root` はしない。nodev も `/dev` の tmpfs も rootfs のパスに依らないため、`<rootfs>/...` の絶対パスで
//! 調べれば足り、`current_exe()` と `/sys/fs/cgroup` が子からも見えて孫を普通の `Command` で起動できる。
//!
//! # 実機前提テストとしての分離
//! root・cgroup v2 の委譲スコープ・`bpf(2)` の cgroup-device 対応カーネルが必要で、GitHub ホステッド runner では
//! 保証できないため `-- --ignored` 指定時のみ実行する（ci.md「実機前提テスト」・AGENTS.md）。非 root での
//! `--ignored` は skip で成功にせず失敗とする。root 権限コマンドのため実行は実機担当（人間）が行い、結果は #1621 に記録する。
//! `TMPDIR` は nodev でないマウントにする（nodev だと c 1:3 の自己検証で失敗する）。
//! `harness = false` の単一スレッド `main` で動かす理由は `landlock_implicit_dev.rs` と同じ（`Cargo.toml` の `[[test]]`）。

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("device_cgroup_layers: Linux only, not applicable on this OS");
}

#[cfg(all(
    target_os = "linux",
    not(all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))
))]
fn main() {
    println!("device_cgroup_layers: x86_64/aarch64 only, not applicable on this architecture");
}

#[cfg(all(
    target_os = "linux",
    all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
fn main() {
    // 分類の自己照合（既定のテスト集合でも常に走る。出力はしない）。
    precondition::self_check();
    // `-- --ignored` を付けたときだけ実行する。子・孫は `--child` / `--grandchild` で再入する。
    if std::env::args().any(|a| a == "--ignored" || a == "--child" || a == "--grandchild") {
        linux::run();
    } else {
        println!(
            "device_cgroup_layers: ignored (real-machine test; run with `-- --ignored`, see AGENTS.md)"
        );
    }
}

// 前提欠如を `PRECONDITION FAILED` の 1 行目で失敗させる共有部品（#2888・#2956・REPAIR-12）。
#[cfg(all(
    target_os = "linux",
    all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
#[path = "support/precondition.rs"]
mod precondition;

#[cfg(all(
    target_os = "linux",
    all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
mod linux {
    use std::fs::File;
    use std::io::{Read as _, Write as _};
    use std::os::fd::AsFd as _;
    use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _, OpenOptionsExt as _};
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};

    use fandhe_container_core::cgroups::{
        CgroupName, ContainerCgroup, DelegatedCgroup, DevicePolicyMode, DevicePolicyOutcome,
        query_device_programs_for_test,
    };
    use fandhe_container_core::exec::{
        DevptsGidSource, ExecCgroupName, ExecChildCgroup, IsolationConfig, MountIsolation,
        Namespace, NamespaceSet, create_default_devices, isolate_rootful_host_root,
        make_char_device_for_test, open_pty_slave_for_test, plan_rootful_host_root, prepare_rootfs,
        remove_exec_child_cgroup_in,
    };
    use fandhe_container_core::observability::OpRecorder;
    use fandhe_container_core::traits::ContainerId;

    /// Linux の errno（x86_64・aarch64 共通）。
    const EPERM: i32 = 1;
    const ENXIO: i32 = 6;
    const EACCES: i32 = 13;
    /// `O_NOCTTY`（asm-generic。x86_64・aarch64 とも 0o400）。
    const O_NOCTTY: i32 = 0o400;
    /// 試験用の char major（devices.txt の LOCAL/EXPERIMENTAL USE。モジュール doc）。
    const TEST_MAJOR: u32 = 120;
    const SUCCESS_LINE: &str = "device_cgroup_layers: device cgroup EPERM, rootfs nodev EACCES, exec child inheritance and cleanup verified (root=true)";

    fn timeout() -> Duration {
        let secs = std::env::var("FANDHE_CONTAINER_TEST_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|s| (1..=600).contains(s))
            .unwrap_or(30);
        Duration::from_secs(secs)
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

    pub fn run() {
        let args: Vec<String> = std::env::args().collect();
        let value = |flag: &str| -> Option<String> {
            args.iter()
                .position(|a| a == flag)
                .and_then(|i| args.get(i + 1))
                .cloned()
        };
        if let Some(rootfs) = value("--child") {
            child(
                Path::new(&rootfs),
                &value("--procs").expect("--procs"),
                &value("--exec-procs").expect("--exec-procs"),
            );
        } else if let Some(rootfs) = value("--grandchild") {
            grandchild(
                Path::new(&rootfs),
                &value("--exec-procs").expect("--exec-procs"),
            );
        } else {
            parent();
        }
    }

    // ---------------------------------------------------------------------------------------
    // 共通の道具
    // ---------------------------------------------------------------------------------------

    /// 子プロセスを期限つきで待ち、終了コードを返す。期限超過は kill して回収し、失敗にする（REPAIR-5）。
    fn wait_bounded(child: &mut Child, what: &str) -> Option<i32> {
        let deadline = Instant::now() + timeout();
        loop {
            match child.try_wait().expect("try_wait") {
                Some(status) => return status.code(),
                None if Instant::now() >= deadline => {
                    if let Err(e) = child.kill() {
                        panic!(
                            "{what} did not exit within {:?} and kill failed: {e}",
                            timeout()
                        );
                    }
                    let reap_deadline = Instant::now() + Duration::from_secs(10);
                    loop {
                        match child.try_wait() {
                            Ok(Some(_)) => break,
                            Ok(None) if Instant::now() < reap_deadline => {
                                std::thread::sleep(Duration::from_millis(20));
                            }
                            Ok(None) => panic!("{what} could not be reaped after kill"),
                            Err(e) => panic!("try_wait failed while reaping {what}: {e}"),
                        }
                    }
                    panic!("{what} did not exit within {:?}", timeout());
                }
                None => std::thread::sleep(Duration::from_millis(20)),
            }
        }
    }

    /// `path` を読み書きで開けるかの errno（成功は `None`）。`O_NOCTTY` で端末を制御端末にしない。
    fn open_errno(path: &Path, write: bool) -> Option<i32> {
        std::fs::OpenOptions::new()
            .read(!write)
            .write(write)
            .custom_flags(O_NOCTTY)
            .open(path)
            .err()
            .map(|e| e.raw_os_error().unwrap_or(-1))
    }

    /// coreutils の `mknod` で文字デバイスを作る（試験に `unsafe` を書かない）。待ちには期限を付ける。
    fn mknod_char(path: &Path, major: u32, minor: u32) {
        let mut child = Command::new("mknod")
            .arg("-m")
            .arg("0666")
            .arg(path)
            .arg("c")
            .arg(major.to_string())
            .arg(minor.to_string())
            .stdin(Stdio::null())
            .spawn()
            .expect("spawn mknod");
        assert_eq!(
            wait_bounded(&mut child, "mknod"),
            Some(0),
            "mknod must succeed"
        );
    }

    /// glibc の `gnu_dev_major` と同じ式。
    fn dev_major(rdev: u64) -> u64 {
        ((rdev >> 8) & 0xfff) | ((rdev >> 32) & !0xfff)
    }

    fn dev_minor(rdev: u64) -> u64 {
        (rdev & 0xff) | ((rdev >> 12) & !0xff)
    }

    /// `/proc/self/cgroup` の v2 行（`0::<path>`）の末尾の要素。
    fn own_cgroup_leaf() -> String {
        let text = std::fs::read_to_string("/proc/self/cgroup").expect("read /proc/self/cgroup");
        let path = text
            .lines()
            .find_map(|l| l.strip_prefix("0::"))
            .expect("cgroup v2 line");
        path.rsplit('/').next().expect("leaf").to_string()
    }

    // ---------------------------------------------------------------------------------------
    // 親
    // ---------------------------------------------------------------------------------------

    /// 親が作った資源の後始末（成否にかかわらず Drop でも走る）。
    struct Scope {
        delegated: DelegatedCgroup,
        container: Option<ContainerCgroup>,
        container_path: String,
        exec_name: Option<ExecCgroupName>,
        /// 排他的に確保した一時 rootfs（確保前は `None`）。後始末はこの領域だけを対象にする。
        rootfs: Option<PathBuf>,
        done: bool,
    }

    impl Scope {
        /// exec 子 cgroup → コンテナ用 cgroup → 一時 rootfs の順に消す。失敗は文字列で返す。
        fn cleanup(&mut self) -> Result<(), String> {
            self.done = true;
            let mut errors = Vec::new();
            if let Some(name) = self.exec_name.take()
                && let Err(e) = remove_exec_child_cgroup_in(
                    &self.container_path,
                    &name,
                    Duration::from_secs(10),
                )
            {
                errors.push(format!("remove exec child cgroup: {e}"));
            }
            if let Some(container) = self.container.take()
                && let Err(e) = self.delegated.remove_child(&container)
            {
                errors.push(format!("remove container cgroup: {e}"));
            }
            if let Some(rootfs) = self.rootfs.take()
                && let Err(e) = std::fs::remove_dir_all(&rootfs)
                && e.kind() != std::io::ErrorKind::NotFound
            {
                errors.push(format!("remove rootfs: {e}"));
            }
            if errors.is_empty() {
                Ok(())
            } else {
                Err(errors.join("; "))
            }
        }
    }

    impl Drop for Scope {
        fn drop(&mut self) {
            if !self.done
                && let Err(e) = self.cleanup()
            {
                eprintln!("cleanup on drop failed: {e}");
            }
        }
    }

    /// `/proc/devices` の Character devices 節に major `TEST_MAJOR` が無いことを確かめる（fail-closed）。
    fn assert_test_major_unregistered() {
        let text = std::fs::read_to_string("/proc/devices").expect("read /proc/devices");
        let chars = text
            .lines()
            .skip_while(|l| !l.starts_with("Character devices:"))
            .skip(1)
            .take_while(|l| !l.trim().is_empty());
        for line in chars {
            let major = line
                .split_whitespace()
                .next()
                .and_then(|m| m.parse::<u32>().ok());
            assert_ne!(
                major,
                Some(TEST_MAJOR),
                "char major {TEST_MAJOR} is registered on this host ({line}); pick another unused major"
            );
        }
    }

    /// root 用の一時 rootfs を排他的に作る。既存パスは削除も採用もしない。名前は PID・時刻・`/dev/urandom` の
    /// 乱数で推測困難にし、`DirBuilder` の mode 0700 で `create`（既存なら `AlreadyExists` で失敗）する。
    /// 共有の一時領域での削除→再作成の競合（他ユーザーの symlink 差し込みで root の `mknod` が領域外へ出る）を防ぐ。
    fn create_private_rootfs() -> PathBuf {
        use std::os::unix::fs::DirBuilderExt as _;
        let base = std::fs::canonicalize(std::env::temp_dir()).expect("canonicalize temp_dir");
        for _ in 0..16 {
            let mut rnd = [0u8; 8];
            File::open("/dev/urandom")
                .and_then(|mut f| f.read_exact(&mut rnd))
                .expect("read /dev/urandom");
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            let path = base.join(format!(
                "fandhe-devcg-{}-{nanos:x}-{:016x}",
                std::process::id(),
                u64::from_le_bytes(rnd)
            ));
            match std::fs::DirBuilder::new().mode(0o700).create(&path) {
                Ok(()) => return path,
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => panic!("create private rootfs {path:?}: {e}"),
            }
        }
        panic!("could not create a private rootfs after 16 attempts");
    }

    fn query_ids(fd: std::os::fd::BorrowedFd<'_>, what: &str) -> Vec<u32> {
        query_device_programs_for_test(fd)
            .unwrap_or_else(|e| panic!("query {what}: {e}"))
            .prog_ids
    }

    fn parent() {
        assert!(
            is_root(),
            "this test requires root (CAP_MKNOD/CAP_BPF); a skip would hide the layers"
        );
        assert_test_major_unregistered();

        // 1. 委譲 cgroup とコンテナ用 cgroup。
        let delegated = crate::precondition::delegated_cgroup();
        let delegated_path = delegated.path();
        let cgroup_base =
            PathBuf::from("/sys/fs/cgroup").join(delegated_path.trim_start_matches('/'));
        let id = ContainerId::new(format!("dl{}", std::process::id())).unwrap();
        let name = CgroupName::new(&id).unwrap();
        let (container, _proof) = delegated.prepare(&name).expect("prepare");
        let container_path = format!("{}/{}", delegated_path.trim_end_matches('/'), name.as_str());
        let container_dir = cgroup_base.join(name.as_str());
        // cgroup 作成の直後に回収ガードを作る。以降のどの失敗経路（panic）でも Drop が `remove_child` を呼ぶ。
        let mut scope = Scope {
            delegated,
            container: Some(container),
            container_path: container_path.clone(),
            exec_name: None,
            rootfs: None,
            done: false,
        };

        // 事前の問い合わせ（後始末の後にホストの cgroup へプログラムが残らないことの基準）。
        let runtime_leaf = File::open(cgroup_base.join("fc-runtime")).expect("open fc-runtime");
        let before_parent = query_ids(scope.delegated.as_fd(), "delegated parent (before)");
        let before_runtime = query_ids(runtime_leaf.as_fd(), "fc-runtime (before)");

        let rootfs = create_private_rootfs();
        scope.rootfs = Some(rootfs.clone());

        // 2. 既定のポリシーを付ける。
        let applied = {
            let container = scope.container.as_ref().expect("container");
            match container
                .apply_default_device_policy(&OpRecorder::new(), DevicePolicyMode::Rootful)
                .expect("apply default device policy")
            {
                DevicePolicyOutcome::Applied(a) => a,
                other => panic!("expected Applied, got {other:?}"),
            }
        };
        assert_eq!(applied.attach_flags(), 0);
        assert_ne!(applied.prog_id(), 0);
        let q = query_device_programs_for_test(scope.container.as_ref().expect("c").as_fd())
            .expect("query container");
        assert_eq!(q.prog_count, 1, "{q:?}");
        assert_eq!(q.attach_flags, 0, "{q:?}");
        assert_eq!(q.prog_ids, vec![applied.prog_id()], "{q:?}");

        // 3. exec-* 子 cgroup。自身にはプログラムが付かない（継承は祖先の実効集合による）。
        let exec_name = ExecCgroupName::unique();
        let exec = ExecChildCgroup::create_in_path_for_test(&container_path, &exec_name)
            .expect("create exec child cgroup");
        drop(exec);
        scope.exec_name = Some(exec_name.clone());
        let exec_dir = container_dir.join(exec_name.as_str());
        let exec_file = File::open(&exec_dir).expect("open exec cgroup dir");
        let exec_q = query_device_programs_for_test(exec_file.as_fd()).expect("query exec");
        assert_eq!(exec_q.prog_count, 0, "{exec_q:?}");
        drop(exec_file);

        // 4. 一時 rootfs とホスト側の自己検証。
        for d in ["proc", "opt", "dev"] {
            std::fs::create_dir(rootfs.join(d)).expect("create rootfs dir");
        }
        let fake_null = rootfs.join("opt/fake-null");
        let fake_local = rootfs.join("opt/fake-local");
        mknod_char(&fake_null, 1, 3);
        mknod_char(&fake_local, TEST_MAJOR, 0);
        assert!(
            std::fs::symlink_metadata(&fake_null)
                .expect("stat fake-null")
                .file_type()
                .is_char_device()
        );
        assert_eq!(
            open_errno(&fake_null, false),
            None,
            "TMPDIR must not be a nodev mount (host-side open of c 1:3 failed); set TMPDIR to e.g. /var/tmp"
        );
        assert_eq!(
            open_errno(&fake_local, false),
            Some(ENXIO),
            "c {TEST_MAJOR}:0 must have no driver outside the container cgroup"
        );

        // 5. rootful 分離（Landlock・seccomp なし）→ 子。
        let config = IsolationConfig {
            namespaces: NamespaceSet::empty()
                .with(Namespace::Pid)
                .with(Namespace::Mount)
                .with(Namespace::Uts)
                .with(Namespace::Ipc),
            hostname: None,
        };
        plan_rootful_host_root(&config)
            .and_then(|p| isolate_rootful_host_root(&p))
            .unwrap_or_else(|e| panic!("isolate failed: {e}"));
        let procs = container_dir.join("cgroup.procs");
        let exec_procs = exec_dir.join("cgroup.procs");
        let exe = std::env::current_exe().expect("current_exe");
        let mut child = Command::new(exe)
            .arg("--child")
            .arg(&rootfs)
            .arg("--procs")
            .arg(&procs)
            .arg("--exec-procs")
            .arg(&exec_procs)
            .stdin(Stdio::null())
            .spawn()
            .expect("spawn child");
        let child_code = wait_bounded(&mut child, "child");

        // 6. 後始末（子の結果を照合する前に必ず行う）。
        let host_dev_entries = std::fs::read_dir(rootfs.join("dev"))
            .expect("read host-side dev")
            .count();
        scope.cleanup().expect("cleanup");
        assert_eq!(
            child_code,
            Some(0),
            "child must exit with 0 (see its stderr for the failing check)"
        );
        assert_eq!(
            host_dev_entries, 0,
            "child tmpfs must not leak onto the host"
        );
        assert!(
            !container_dir.exists(),
            "container cgroup must be removed: {container_dir:?}"
        );
        assert!(!rootfs.exists(), "rootfs must be removed");
        let after_parent = query_ids(scope.delegated.as_fd(), "delegated parent (after)");
        let after_runtime = query_ids(runtime_leaf.as_fd(), "fc-runtime (after)");
        assert_eq!(after_parent, before_parent);
        assert_eq!(after_runtime, before_runtime);
        assert!(!after_parent.contains(&applied.prog_id()));
        println!("{SUCCESS_LINE}");
    }

    // ---------------------------------------------------------------------------------------
    // 子（PID 1）
    // ---------------------------------------------------------------------------------------

    fn child(rootfs: &Path, procs: &str, exec_procs: &str) {
        assert_eq!(
            std::process::id(),
            1,
            "child must be PID 1 of the new PID namespace"
        );
        let isolation = MountIsolation::establish().expect("establish mount isolation");
        let prepared = prepare_rootfs(&isolation, rootfs).expect("prepare rootfs");
        create_default_devices(&isolation, &prepared, DevptsGidSource::Rootful)
            .expect("create default devices");
        let dev = rootfs.join("dev");

        // cgroup に入る前: nodev でない tmpfs の上に c 120:0 を作り、ドライバが無いこと（ENXIO）を確かめる。
        let local = dev.join("devcg-local");
        assert_eq!(make_char_device_for_test(&local, TEST_MAJOR, 0), None);
        assert_eq!(open_errno(&local, false), Some(ENXIO));

        // コンテナ用 cgroup に入る。
        std::fs::write(procs, "0").expect("join container cgroup");
        assert!(
            own_cgroup_leaf().starts_with("fc-"),
            "must be in the container cgroup, got {}",
            own_cgroup_leaf()
        );

        // 許可リストにあるもの。
        let mut null = std::fs::OpenOptions::new()
            .write(true)
            .open(dev.join("null"))
            .expect("open /dev/null for write");
        null.write_all(b"x").expect("write /dev/null");
        let mut buf = [0xffu8; 16];
        File::open(dev.join("zero"))
            .expect("open /dev/zero")
            .read_exact(&mut buf)
            .expect("read /dev/zero");
        assert_eq!(buf, [0u8; 16]);
        let mut rnd = [0u8; 16];
        File::open(dev.join("urandom"))
            .expect("open /dev/urandom")
            .read_exact(&mut rnd)
            .expect("read /dev/urandom");
        let slave = open_pty_slave_for_test(&dev.join("ptmx")).expect("open pty slave");
        assert_eq!(dev_major(slave.rdev), 136, "{slave:?}");

        // デバイス cgroup の層: open は EPERM、許可外の mknod は EPERM でノードが残らない。
        assert_eq!(open_errno(&local, false), Some(EPERM));
        let mk_local = dev.join("devcg-mk-local");
        let mk_tun = dev.join("devcg-mk-tun");
        assert_eq!(
            make_char_device_for_test(&mk_local, TEST_MAJOR, 1),
            Some(EPERM)
        );
        assert_eq!(make_char_device_for_test(&mk_tun, 10, 200), Some(EPERM));
        for p in [&mk_local, &mk_tun] {
            assert_eq!(
                std::fs::symlink_metadata(p).err().map(|e| e.kind()),
                Some(std::io::ErrorKind::NotFound),
                "{p:?} must not be created"
            );
        }
        // 対照: 許可リストにある c 1:3 の mknod は成功する。
        let mk_null = dev.join("devcg-mk-null");
        assert_eq!(make_char_device_for_test(&mk_null, 1, 3), None);
        let meta = std::fs::symlink_metadata(&mk_null).expect("stat created node");
        assert!(meta.file_type().is_char_device());
        assert_eq!((dev_major(meta.rdev()), dev_minor(meta.rdev())), (1, 3));

        // nodev の層: 許可リストの内外を問わず EACCES（EPERM ではない）。
        assert_eq!(
            open_errno(&rootfs.join("opt/fake-null"), false),
            Some(EACCES)
        );
        assert_eq!(
            open_errno(&rootfs.join("opt/fake-local"), false),
            Some(EACCES)
        );

        // 継承: exec-* に入る別プロセス。
        let exe = std::env::current_exe().expect("current_exe");
        let mut grandchild = Command::new(exe)
            .arg("--grandchild")
            .arg(rootfs)
            .arg("--exec-procs")
            .arg(exec_procs)
            .stdin(Stdio::null())
            .spawn()
            .expect("spawn grandchild");
        assert_eq!(wait_bounded(&mut grandchild, "grandchild"), Some(0));
    }

    // ---------------------------------------------------------------------------------------
    // 孫
    // ---------------------------------------------------------------------------------------

    fn grandchild(rootfs: &Path, exec_procs: &str) {
        std::fs::write(exec_procs, "0").expect("join exec child cgroup");
        assert!(
            own_cgroup_leaf().starts_with("exec-"),
            "must be in the exec child cgroup, got {}",
            own_cgroup_leaf()
        );
        let dev = rootfs.join("dev");
        assert_eq!(open_errno(&dev.join("devcg-local"), false), Some(EPERM));
        assert_eq!(open_errno(&dev.join("null"), true), None);
    }
}
