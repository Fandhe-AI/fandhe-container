//! 実 pid1 の 5 種 namespace への `setns` 参加の結合試験（TASK-163.1・#500・SUP-6・REPAIR-12）。
//!
//! `identify_pid1` / `enter_namespaces`（`fandhe_container_supervisor::exec`）の成功経路を、実プロセスで
//! 検証する。`unshare` で新しい user / pid / mnt / uts / ipc / net namespace に pid1（`sleep`）を作り、
//! その user namespace に `nsenter` で入った単一スレッドの joiner（本バイナリの `--joiner` 再入）が
//! pid1 を特定して参加し、参加後の namespace 識別子（`/proc/thread-self/ns/*` のリンク先）が対象の
//! 値と具体値で一致することを照合する。参加前は対象と異なることも確認する。続けて、mount namespace を
//! 分離していない pid1（呼び出し側と同じ mnt namespace）が違反として拒否されることも照合する。
//!
//! TASK-163.4（#503）で次の 2 つを足した（どちらも非特権の user namespace に閉じ、root を要さない）。
//!
//! - **別の user namespace の対象の拒否（SEC-5・SEC-1）**: 対象の user namespace へ入っていない joiner からの
//!   特定は、違反 `exec_target_in_other_user_namespace` で拒否される（user namespace への参加は未実装のため、
//!   `setns` が成功し得る rootful の呼び出し側でも、参加の前に拒否する。`exec/setns.rs` のモジュール doc）
//! - **`pivot_root` 済みの対象へ参加した後の `/`（SEC-1）**: launcher と同じ手順（`establish` →
//!   `prepare_rootfs` → `pivot_root`。本バイナリの `--pid1-pivot` 再入）で rootfs へ切り替えた pid1 へ、本番の
//!   `enter_namespaces` で参加し、参加後の `/` と cwd が、参加前にホスト側のパスで調べた rootfs と **同じ
//!   ディレクトリ（`st_dev`・`st_ino`）** であることを具体値で照合する。`setns(CLONE_NEWNS)` が呼び出し
//!   プロセスの root と cwd を参加先 mount namespace のルートへ付け替える（カーネルの `mntns_install` /
//!   `commit_nsset`）ことの実測で、`exec/reapply.rs` の `/` の照合（`exec_root_not_container_rootfs`）が
//!   launcher 契約どおりの対象では通ることの根拠になる。制限の再適用以降は Landlock ABI 6 以上を要し、
//!   hosted runner では実行できないため、ここでは照合しない（`tests/exec.rs`。実機前提）
//!
//! # 試験専用の入口（`exec-test-support` feature）
//! 試験環境ではコンテナ用 cgroup（`<scope>/fc-<id>@<instance>`）を作れないため、期待 cgroup パスを
//! 呼び出し側から渡す `identify_pid1_in` を使う。この入口は `exec-test-support` feature を付けたビルドにだけ
//! 存在し、既定のビルドの公開 API は記録から期待値を導く `identify_pid1` だけである（SEC-1）。
//! feature なしのビルドでは本体をコンパイルせず、`-- --ignored` で実行を求められたら「検証していない」
//! ことを非ゼロ終了で知らせる（検証せずに成功しない。fail-closed）。`required-features` にしないのは、
//! `cargo test --workspace --test '*'`（`make test-integration`）が feature なしで本 target を選ぶと
//! エラーになるため。
//!
//! # 単一スレッドの独自 main（harness = false）
//! `setns(CLONE_NEWNS)` は複数スレッドのプロセスから拒否されるため、libtest ではなく独自 `main` で動かす。
//! 非 Linux では対象外（OS 非該当であり skip ではない）。
//!
//! # 実機前提テストとしての分離
//! 非特権 user namespace で `uid_map` を書けるホスト（AppArmor の
//! `kernel.apparmor_restrict_unprivileged_userns=1` がない環境）と `unshare` / `nsenter`（util-linux）が
//! 必要なため、`-- --ignored` 指定時のみ実行する（`crates/core/tests/unshare_isolation.rs` と同じ方式。
//! AGENTS.md「実機前提テスト」）。実行された場合は拒否を含むあらゆる失敗を失敗として扱う。

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("exec_setns_join: Linux only, not applicable on this OS");
}

#[cfg(all(target_os = "linux", not(feature = "exec-test-support")))]
fn main() {
    if std::env::args().any(|a| a == "--ignored" || a.starts_with("--joiner")) {
        eprintln!(
            "exec_setns_join: not verified; rebuild with `--features exec-test-support` (see AGENTS.md)"
        );
        std::process::exit(2);
    }
    println!(
        "exec_setns_join: ignored (real-machine test; run with `-- --ignored`, see AGENTS.md)"
    );
}

#[cfg(all(target_os = "linux", feature = "exec-test-support"))]
fn main() {
    let args: Vec<String> = std::env::args().collect();
    let pid_after = |flag: &str| -> Option<u32> {
        let i = args.iter().position(|a| a == flag)?;
        Some(
            args.get(i + 1)
                .and_then(|v| v.parse().ok())
                .expect("joiner requires a pid"),
        )
    };
    if let Some(pid) = pid_after(linux::JOINER) {
        linux::joiner(pid);
    } else if let Some(pid) = pid_after(linux::JOINER_SHARED_MNT) {
        linux::joiner_shared_mnt(pid);
    } else if let Some(pid) = pid_after(linux::JOINER_OTHER_USERNS) {
        linux::joiner_other_userns(pid);
    } else if let Some(pid) = pid_after(linux::JOINER_PIVOTED) {
        let i = args
            .iter()
            .position(|a| a == linux::JOINER_PIVOTED)
            .expect("flag position");
        let rootfs = args.get(i + 2).expect("joiner requires the rootfs path");
        linux::joiner_pivoted(pid, std::path::Path::new(rootfs));
    } else if let Some(i) = args.iter().position(|a| a == linux::PID1_PIVOT) {
        let rootfs = args.get(i + 1).expect("pid1 requires the rootfs path");
        linux::pid1_pivot(std::path::Path::new(rootfs));
    } else if args.iter().any(|a| a == "--ignored") {
        linux::orchestrate();
    } else {
        println!(
            "exec_setns_join: ignored (real-machine test; run with `-- --ignored`, see AGENTS.md)"
        );
    }
}

#[cfg(all(target_os = "linux", feature = "exec-test-support"))]
mod linux {
    use std::ffi::OsString;
    use std::fs;
    use std::num::NonZeroU32;
    use std::os::unix::fs::MetadataExt as _;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};

    use fandhe_container_core::exec::{JoinNamespace, MountIsolation, pivot_root, prepare_rootfs};
    use fandhe_container_core::traits::{
        ContainerId, ContainerStatus, ErrorCode, StateRecord, StateRevision,
    };
    use fandhe_container_supervisor::exec::{enter_namespaces, identify_pid1_in};

    /// 参加で切り替わる namespace の `/proc/<..>/ns/` エントリ名（pid は参加後 `pid_for_children` に現れる）。
    const NS_ENTRIES: [&str; 4] = ["mnt", "uts", "ipc", "net"];

    fn timeout() -> Duration {
        let secs = std::env::var("FANDHE_CONTAINER_TEST_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|s| (1..=600).contains(s))
            .unwrap_or(10);
        Duration::from_secs(secs)
    }

    fn link(path: &str) -> String {
        fs::read_link(path)
            .unwrap_or_else(|e| panic!("read_link {path}: {e}"))
            .to_string_lossy()
            .into_owned()
    }

    /// 終了時に `unshare` と pid1 を確実に止める。
    ///
    /// pid1 は `unshare --kill-child` が親（`Child` ハンドルで保持する `unshare`）の死に連動して
    /// 落とす。数値 PID への `kill` は pid1 が先に回収された場合の PID 再利用で無関係なプロセスを
    /// 殺し得る（SEC-1）ため行わない。
    struct Fixture {
        unshare: Child,
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = self.unshare.kill();
            let _ = self.unshare.wait();
        }
    }

    /// 成功経路の joiner の再入フラグ。
    pub const JOINER: &str = "--joiner";
    /// 「呼び出し側と同じ mount namespace」の拒否経路の joiner の再入フラグ。
    pub const JOINER_SHARED_MNT: &str = "--joiner-shared-mnt";
    /// 「呼び出し側と別の user namespace」の拒否経路の joiner の再入フラグ（`nsenter` を通さない）。
    pub const JOINER_OTHER_USERNS: &str = "--joiner-other-userns";
    /// `pivot_root` 済みの pid1 へ参加し、参加後の `/` を照合する joiner の再入フラグ（引数: pid・rootfs）。
    pub const JOINER_PIVOTED: &str = "--joiner-pivoted";
    /// launcher と同じ手順で `pivot_root` まで進んで待機する pid1 の再入フラグ（引数: rootfs）。
    pub const PID1_PIVOT: &str = "--pid1-pivot";
    /// pid1 が pivot の後に新しい `/` へ置く合図ファイルの名前と内容。
    const READY: &str = "ready";
    /// rootfs に置く目印ファイルの名前と内容（参加後の `/` から読めることを照合する）。
    const MARKER: &str = "marker";
    const MARKER_CONTENT: &[u8] = b"fandhe exec_setns_join rootfs";

    /// すべての namespace を分離する `unshare` の追加フラグ。
    const ALL_NS: [&str; 4] = ["--mount", "--uts", "--ipc", "--net"];

    pub fn orchestrate() {
        let sleep = || vec![OsString::from("sleep"), OsString::from("60")];
        // 成功経路: 5 種すべてを分離した pid1 へ参加する。
        run_scenario(&ALL_NS, sleep(), None, true, JOINER, &[]);
        // 拒否経路: mount namespace を分離していない pid1（呼び出し側と同じ mnt namespace）は、
        // 入れ子の PID 1 で cgroup が一致していても対象にしない（SUP-6・SEC-4）。
        run_scenario(
            &["--uts", "--ipc", "--net"],
            sleep(),
            None,
            true,
            JOINER_SHARED_MNT,
            &[],
        );
        // 拒否経路: 対象の user namespace へ入っていない呼び出し側は、5 種すべてを分離した pid1 でも対象に
        // しない（SEC-5・SEC-1・TASK-163.4。user namespace への参加は未実装）。
        run_scenario(&ALL_NS, sleep(), None, false, JOINER_OTHER_USERNS, &[]);
        println!("exec_setns_join: target in another user namespace rejected");
        // 成功経路: launcher と同じ手順で pivot_root した pid1 へ参加した後の `/` は、固定した rootfs と同じ
        // ディレクトリになる（SEC-1・TASK-163.4）。
        let rootfs = Rootfs::create();
        let exe = std::env::current_exe().expect("current_exe");
        let pid1 = vec![
            exe.into_os_string(),
            OsString::from(PID1_PIVOT),
            rootfs.dir.clone().into_os_string(),
        ];
        let rootfs_arg = rootfs.dir.to_str().expect("utf-8 rootfs path").to_owned();
        run_scenario(
            &ALL_NS,
            pid1,
            Some(&rootfs.dir.join(READY)),
            true,
            JOINER_PIVOTED,
            &[rootfs_arg],
        );
        println!("exec_setns_join: root after joining a pivoted target equals the pinned rootfs");
        println!("exec_setns_join: namespace join verified");
    }

    /// 使い捨ての rootfs（`proc/` と目印ファイル）。drop で削除する。
    struct Rootfs {
        dir: PathBuf,
    }

    impl Rootfs {
        /// 祖先に symlink を含まない一意なディレクトリへ作る（`prepare_rootfs` は祖先の symlink を拒否する）。
        fn create() -> Self {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.subsec_nanos());
            let dir = fs::canonicalize(std::env::temp_dir())
                .expect("canonicalize temp_dir")
                .join(format!("fandhe-setns-join-{}-{nanos}", std::process::id()));
            fs::create_dir(&dir).expect("exclusively create the rootfs");
            let rootfs = Self { dir };
            fs::create_dir(rootfs.dir.join("proc")).expect("mkdir rootfs/proc");
            fs::write(rootfs.dir.join(MARKER), MARKER_CONTENT).expect("write marker");
            rootfs
        }
    }

    impl Drop for Rootfs {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.dir);
        }
    }

    /// `unshare` で user / pid（と `extra_ns`）を分離した pid1（`pid1_command`）を作り、joiner（本バイナリの
    /// `joiner_flag` 再入。引数は pid1 の pid と `joiner_args`）が 0 で終わることを確かめる。
    ///
    /// `ready` があれば、そのファイルが現れるまで joiner の起動を待つ（pid1 の準備完了の合図）。
    /// `enter_user_ns` が真なら joiner を `nsenter` で対象の user namespace へ入れてから起動し、偽なら
    /// 呼び出し側の user namespace のまま起動する。
    fn run_scenario(
        extra_ns: &[&str],
        pid1_command: Vec<OsString>,
        ready: Option<&Path>,
        enter_user_ns: bool,
        joiner_flag: &str,
        joiner_args: &[String],
    ) {
        let unshare = Command::new("unshare")
            .args([
                "--user",
                "--map-root-user",
                "--pid",
                // `--kill-child` は `--fork` を含意する（util-linux）が、新しい PID namespace の PID 1 は
                // fork した子であることを引数の上でも明示する。
                "--fork",
                "--kill-child",
            ])
            .args(extra_ns)
            .args(pid1_command)
            .stdin(Stdio::null())
            .spawn()
            .expect("spawn unshare");
        let unshare_pid = unshare.id();
        let _fx = Fixture { unshare };

        // `--fork` した子（新 PID namespace の PID 1）が現れるまで待つ。
        let deadline = Instant::now() + timeout();
        let pid1 = loop {
            if let Some(pid) = nested_pid1_child(unshare_pid) {
                break pid;
            }
            assert!(Instant::now() < deadline, "pid1 did not appear in time");
            std::thread::sleep(Duration::from_millis(20));
        };

        if let Some(ready) = ready {
            let deadline = Instant::now() + timeout();
            while !ready.exists() {
                assert!(
                    Instant::now() < deadline,
                    "pid1 did not become ready in time"
                );
                std::thread::sleep(Duration::from_millis(20));
            }
        }

        let exe = std::env::current_exe().expect("current_exe");
        let mut command = if enter_user_ns {
            let mut nsenter = Command::new("nsenter");
            nsenter
                // `--map-root-user` の user namespace は setgroups が deny のため、nsenter 既定の
                // setgroups(0) が EPERM になる。資格情報を維持して参加する。
                .arg("--preserve-credentials")
                .arg(format!("--user=/proc/{pid1}/ns/user"))
                .arg(exe);
            nsenter
        } else {
            Command::new(exe)
        };
        let mut joiner = command
            .arg(joiner_flag)
            .arg(pid1.to_string())
            .args(joiner_args)
            .stdin(Stdio::null())
            .spawn()
            .expect("spawn joiner");
        let deadline = Instant::now() + timeout();
        let status = loop {
            if let Some(s) = joiner.try_wait().expect("try_wait") {
                break s;
            }
            if Instant::now() >= deadline {
                let _ = joiner.kill();
                let _ = joiner.wait();
                panic!("joiner {joiner_flag} did not exit within {:?}", timeout());
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        assert_eq!(
            status.code(),
            Some(0),
            "joiner {joiner_flag} must exit with 0"
        );
    }

    /// 試験用のレコード（Running・記録 pid あり）と、pid1 が実際に属する cgroup の絶対パス。
    fn record_and_cgroup_path(pid: u32) -> (StateRecord, String) {
        let status =
            ContainerStatus::running(ContainerId::new("c1").expect("id"), NonZeroU32::new(pid));
        let rec = StateRecord::new(
            status,
            std::env::temp_dir().join("b"),
            StateRevision::from_raw(1),
        )
        .expect("record");
        let cgroup = fs::read_to_string(format!("/proc/{pid}/cgroup")).expect("read cgroup");
        let path = cgroup
            .lines()
            .find_map(|l| l.strip_prefix("0::"))
            .expect("cgroup v2 path")
            .to_owned();
        assert!(
            path.starts_with('/') && path.len() > 1,
            "pid1 must be in a non-root cgroup: {path}"
        );
        (rec, path)
    }

    /// 対象の user namespace に入った単一スレッドで、mount namespace を共有する pid1 が拒否されることを
    /// 照合する（入れ子の PID 1・cgroup 一致・pid namespace は別、の条件で mnt の検査に届く）。
    pub fn joiner_shared_mnt(pid: u32) {
        assert_eq!(
            link("/proc/thread-self/ns/mnt"),
            link(&format!("/proc/{pid}/ns/mnt")),
            "the target must share the mount namespace with the joiner"
        );
        assert_ne!(
            link("/proc/thread-self/ns/pid"),
            link(&format!("/proc/{pid}/ns/pid")),
            "the target must be in another PID namespace"
        );
        let (rec, path) = record_and_cgroup_path(pid);
        let err = identify_pid1_in(&rec, &path).unwrap_err();
        assert_eq!(err.code(), ErrorCode::FailedPrecondition);
        assert_eq!(
            err.message(),
            "exec stage SetNs: the exec target shares the mount namespace with the caller; \
             refusing to join (violation: exec_target/exec_target_shares_mount_namespace, SUP-6)"
        );
    }

    /// 対象の user namespace へ入っていない単一スレッドで、5 種すべてを分離した pid1 が「別の user namespace」を
    /// 理由に拒否されることを照合する（入れ子の PID 1・cgroup 一致・pid / mnt namespace は別、の条件で user
    /// namespace の検査に届く。SEC-5・SEC-1・SEC-4・TASK-163.4）。
    pub fn joiner_other_userns(pid: u32) {
        assert_ne!(
            link("/proc/thread-self/ns/user"),
            link(&format!("/proc/{pid}/ns/user")),
            "the target must be in another user namespace"
        );
        for ns in ["mnt", "pid"] {
            assert_ne!(
                link(&format!("/proc/thread-self/ns/{ns}")),
                link(&format!("/proc/{pid}/ns/{ns}")),
                "the target must be in another {ns} namespace"
            );
        }
        let (rec, path) = record_and_cgroup_path(pid);
        let err = identify_pid1_in(&rec, &path).unwrap_err();
        assert_eq!(err.code(), ErrorCode::FailedPrecondition);
        assert_eq!(
            err.message(),
            "exec stage SetNs: the exec target is in another user namespace than the caller; \
             refusing to join (violation: exec_target/exec_target_in_other_user_namespace, SUP-6)"
        );
    }

    /// `--pid1-pivot`: 新しい PID namespace の PID 1 として、launcher と同じ手順（`establish` →
    /// `prepare_rootfs` → `pivot_root`。`exec/rootfs.rs` の契約）で rootfs へ切り替え、新しい `/` に合図
    /// ファイルを置いて待機する。デバイスノードの作成は rootless では `mknod` が拒否されるため行わない。
    pub fn pid1_pivot(rootfs: &Path) {
        assert_eq!(std::process::id(), 1, "must be PID 1 of the new namespace");
        let isolation = MountIsolation::establish().expect("establish mount isolation");
        let prepared = prepare_rootfs(&isolation, rootfs).expect("prepare rootfs");
        let report = pivot_root(&isolation, prepared).expect("pivot_root");
        assert!(report.old_root_detached, "the old root must be detached");
        // 合図は一時名から rename で公開する（書きかけを見せない）。
        fs::write(format!("/{READY}.tmp"), READY).expect("write ready marker");
        fs::rename(format!("/{READY}.tmp"), format!("/{READY}")).expect("publish ready marker");
        // `unshare --kill-child` が親の終了に連動して落とすまで待機する（上限つき。REPAIR-5）。
        let deadline = Instant::now() + Duration::from_secs(60);
        while Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    /// 対象の user namespace に入った単一スレッドで、`pivot_root` 済みの pid1 へ本番の入口で参加し、参加後の
    /// `/` と cwd が、参加前にホスト側のパスで調べた rootfs と同じディレクトリであることを照合する
    /// （SEC-1・SUP-6・TASK-163.4）。
    pub fn joiner_pivoted(pid: u32, rootfs: &Path) {
        let identity = |path: &Path| -> (u64, u64) {
            let m = fs::metadata(path).unwrap_or_else(|e| panic!("stat {}: {e}", path.display()));
            assert!(m.is_dir(), "{} must be a directory", path.display());
            (m.dev(), m.ino())
        };
        // 参加前: rootfs はホスト側のパスで見え、自分の `/` とは別のディレクトリ。
        let pinned = identity(rootfs);
        assert_ne!(
            identity(Path::new("/")),
            pinned,
            "the caller's root must differ from the container rootfs before joining"
        );
        assert_ne!(
            link("/proc/thread-self/ns/mnt"),
            link(&format!("/proc/{pid}/ns/mnt"))
        );

        let (rec, path) = record_and_cgroup_path(pid);
        let target = identify_pid1_in(&rec, &path).expect("identify pid1");
        let report = enter_namespaces(&target).expect("enter namespaces");
        assert_eq!(report.joined, JoinNamespace::SUP6_SET.to_vec());

        // 参加後: `/` と cwd は、固定した rootfs と同じディレクトリ（`st_dev`・`st_ino`）。`setns` は root と cwd を
        // 参加先 mount namespace のルートへ付け替えるため、明示的な chroot / chdir をしなくても一致する。
        assert_eq!(
            identity(Path::new("/")),
            pinned,
            "the root after joining must be the pinned container rootfs"
        );
        assert_eq!(
            identity(Path::new(".")),
            pinned,
            "the cwd after joining must be the pinned container rootfs"
        );
        // `/` の親も `/` 自身（rootfs の外へ出られない）。
        assert_eq!(identity(Path::new("/..")), pinned);
        // rootfs の中身が `/` 直下に見え、pid1 が pivot の後に置いた合図も読める。
        assert_eq!(
            fs::read(format!("/{MARKER}")).expect("read marker"),
            MARKER_CONTENT
        );
        assert_eq!(
            fs::read(format!("/{READY}")).expect("read ready marker"),
            READY.as_bytes()
        );
        // ホスト側のパスは参加後の root からは解決できない（旧 root は切り離されている）。
        assert_eq!(
            fs::metadata(rootfs)
                .expect_err("host path must not resolve")
                .kind(),
            std::io::ErrorKind::NotFound
        );
    }

    /// `unshare_pid` の子のうち、入れ子の PID namespace の PID 1（`NSpid` が 2 要素以上で末尾 1）のものを返す。
    fn nested_pid1_child(unshare_pid: u32) -> Option<u32> {
        let children =
            fs::read_to_string(format!("/proc/{unshare_pid}/task/{unshare_pid}/children")).ok()?;
        children
            .split_whitespace()
            .filter_map(|t| t.parse::<u32>().ok())
            .find(|pid| {
                let Ok(status) = fs::read_to_string(format!("/proc/{pid}/status")) else {
                    return false;
                };
                let Some(rest) = status.lines().find_map(|l| l.strip_prefix("NSpid:")) else {
                    return false;
                };
                let toks: Vec<&str> = rest.split_whitespace().collect();
                toks.len() >= 2 && toks.last() == Some(&"1")
            })
    }

    /// 対象の user namespace に入った単一スレッドで、pid1 を特定して 5 種へ参加し、識別子を照合する。
    pub fn joiner(pid: u32) {
        let target_ns = |name: &str| link(&format!("/proc/{pid}/ns/{name}"));
        let before: Vec<String> = NS_ENTRIES
            .iter()
            .map(|n| link(&format!("/proc/thread-self/ns/{n}")))
            .collect();
        let want: Vec<String> = NS_ENTRIES.iter().map(|n| target_ns(n)).collect();
        for (i, n) in NS_ENTRIES.iter().enumerate() {
            assert_ne!(before[i], want[i], "{n} namespace must differ before join");
        }
        let want_pid = target_ns("pid");
        assert_ne!(link("/proc/thread-self/ns/pid_for_children"), want_pid);

        // コンテナ用 cgroup は作れないため、pid1 が実際に属する cgroup の絶対パスを期待値にする
        // （本番は記録の配置から導く。`identify_pid1`）。別コンテナの cgroup・配下の子 cgroup・親 cgroup・
        // リーフ名だけの指定では、pid 再利用対策として拒否されることも確認する（SEC-1）。
        let (rec, path) = record_and_cgroup_path(pid);
        let (parent, leaf) = path.rsplit_once('/').expect("cgroup leaf");
        let mut rejected = vec![
            (
                format!("{parent}/fc-c1@999999"),
                ErrorCode::FailedPrecondition,
            ),
            (format!("{path}/{leaf}"), ErrorCode::FailedPrecondition),
            (leaf.to_owned(), ErrorCode::InvalidArgument),
        ];
        if !parent.is_empty() {
            rejected.push((parent.to_owned(), ErrorCode::FailedPrecondition));
        }
        for (bad, code) in rejected {
            let err = identify_pid1_in(&rec, &bad).unwrap_err();
            assert_eq!(err.code(), code, "{bad}");
            if code == ErrorCode::FailedPrecondition {
                assert_eq!(
                    err.message(),
                    "exec stage SetNs: the exec target does not belong to the recorded container \
                     cgroup (violation: exec_target/exec_target_cgroup_mismatch, SEC-1)",
                    "{bad}"
                );
            }
        }
        let target = identify_pid1_in(&rec, &path).expect("identify pid1");
        assert_eq!(target.pid1().pid().get(), pid);
        let report = enter_namespaces(&target).expect("enter namespaces");
        assert_eq!(report.target_pid.get(), pid);
        assert_eq!(report.joined, JoinNamespace::SUP6_SET.to_vec());

        for (i, n) in NS_ENTRIES.iter().enumerate() {
            assert_eq!(
                link(&format!("/proc/thread-self/ns/{n}")),
                want[i],
                "{n} namespace must equal the target after join"
            );
        }
        // PID namespace は以後に fork した子にだけ効くため、`pid_for_children` で照合する。
        assert_eq!(link("/proc/thread-self/ns/pid_for_children"), want_pid);
    }
}
