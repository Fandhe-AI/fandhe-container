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
//! - **別の user namespace の対象への参加（SEC-5・SEC-1・TASK-163.h2・#1462）**: 対象の user namespace へ入って
//!   いない（`nsenter` を通さない）joiner が、5 種に先立って対象の user namespace にも参加する（rootless の
//!   exec）。参加後の `ns/user` が対象と一致すること、`NamespaceJoinReport` が user namespace への参加を報告する
//!   こと、続く補助グループ・gid・uid の処理（`apply_join_credentials_for_test`）が参加先の namespace 内で
//!   `Uid:` / `Gid:` を 0 に揃え、`setgroups` が `deny` の補助グループを現状維持として記録することを具体値で
//!   照合する。`nsenter --user` で先に同じ user namespace へ入った joiner（rootful 相当）は user namespace へ
//!   参加せず、報告もそのとおりであることも照合する
//! - **`pivot_root` 済みの対象へ参加した後の `/`（SEC-1）**: launcher と同じ手順（`establish` →
//!   `prepare_rootfs` → `pivot_root`。本バイナリの `--pid1-pivot` 再入）で rootfs へ切り替えた pid1 へ、本番の
//!   `enter_namespaces` で参加し、参加後の `/` と cwd が、参加前にホスト側のパスで調べた rootfs と **同じ
//!   ディレクトリ（`st_dev`・`st_ino`）** であることを具体値で照合する。`setns(CLONE_NEWNS)` が呼び出し
//!   プロセスの root と cwd を参加先 mount namespace のルートへ付け替える（カーネルの `mntns_install` /
//!   `commit_nsset`）ことの実測で、`exec/reapply.rs` の `/` の照合（`exec_root_not_container_rootfs`）が
//!   launcher 契約どおりの対象では通ることの根拠になる。制限の再適用以降は Landlock ABI 6 以上を要し、
//!   hosted runner では実行できないため、ここでは照合しない（`tests/exec.rs`。実機前提）
//!
//! TASK-163 追補（#1468）で次を足した（同じく非特権の user namespace に閉じる）。
//!
//! - **rootfs を mount namespace の中で組み立てる構成での `/` の照合（SEC-1・SUP-6）**: pid1 が自分の mount
//!   namespace の中でだけ、rootfs ディレクトリへ tmpfs をマウントし（overlay の代わり。どちらも匿名の `st_dev` を持ち、
//!   ホスト側のディレクトリとは別の実体になる）、launcher と同じ手順で `pivot_root` する（`--pid1-pivot-tmpfs`）。pid1 が
//!   pivot 後の `/` の識別子を事前に開いたファイルへ書き、joiner はそれを launch 時の記録として本番の
//!   `enter_namespaces` で参加した後、本番と同じ照合（`verify_joined_root_for_test`）が通ること、ホスト側の bundle
//!   ディレクトリの識別子とは **一致しない** こと（ホスト側の bundle 起点の照合では拒否されていた構成）を具体値で照合する。
//!   記録は `launch_isolation` の `root` に載せる値で、exec の `/` の照合の基準になる
//!
//! TASK-163 追補（#1457）で次を足した（同じく非特権の user namespace に閉じる）。
//!
//! - **`setgroups` が `deny` の user namespace での補助グループ（SEC-5）**: launch・exec が共有する補助グループの
//!   消去を、`unshare --map-root-user` の user namespace（`setgroups` は `deny`）の中で実 syscall により通し、
//!   `CAP_SETGID` を持っていても消去できない場合に「現状維持の記録」（`KeptSetgroupsDenied`）になること・
//!   補助グループが実際に変わらないことを照合する
//!
//! #2770（SEC-5・CORE-6・SUP-6）で次を足した（`FANDHE_CONTAINER_TEST_ID_HELPER=1` の時だけ。`newuidmap` / `newgidmap` と
//! `/etc/subuid`・`/etc/subgid` の自ユーザー行を要する）。
//!
//! - **非 root の `process.user` と `additionalGids`（範囲写像）**: `unshare --map-users` / `--map-groups` で
//!   コンテナ内 0.. を subuid / subgid の範囲へ写した pid1 に対し、joiner が本番と同じ照合（実際の
//!   `uid_map`・`gid_map`・`setgroups` との照合）で 1000:1000・`additionalGids` [3000, 2000, 3000] を受け、写像の外
//!   （65536）を `InvalidArgument` で拒否し、参加後に補助グループ → gid → uid の順で適用して、`Uid:` / `Gid:` が
//!   1000、`Groups:` が `2000 3000` になることを具体値で照合する
//!
//! # 試験専用の入口（`exec-test-support` feature）
//! 試験環境ではコンテナ用 cgroup（`<scope>/fc-<id>@<instance>`）を作れないため、期待 cgroup パスを
//! 呼び出し側から渡す `identify_pid1_in` を使う。この入口は `exec-test-support` feature を付けたビルドにだけ
//! 存在し、既定のビルドの公開 API は記録から期待値を導く `identify_pid1` だけである（SEC-1）。
//! 既定の入口 `identify_pid1` の成功経路と拒否経路は、実 cgroup を作れる `tests/exec_identify_cgroup.rs`
//! （実機前提。TASK-163 追補・#1464）が別に照合する。
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
//! 範囲写像の helper ケース（`FANDHE_CONTAINER_TEST_ID_HELPER=1`）の前提欠如（`newuidmap` / `newgidmap`・
//! subuid / subgid）は、1 行目が `exec_setns_join: PRECONDITION FAILED (test environment, ...)` になる
//! （分類元は core の `tests/support/precondition.rs`。#2957・SUP-6・REPAIR-12）。

#[path = "../../core/tests/support/reap.rs"]
mod reap;

#[cfg(target_os = "linux")]
#[path = "../../core/tests/support/precondition.rs"]
mod precondition;

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("exec_setns_join: Linux only, not applicable on this OS");
}

#[cfg(all(target_os = "linux", not(feature = "exec-test-support")))]
fn main() {
    precondition::self_check();
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
    } else if let Some(pid) = pid_after(linux::JOINER_ROOTLESS) {
        linux::joiner_rootless(pid);
    } else if let Some(pid) = pid_after(linux::JOINER_PIVOTED) {
        let i = args
            .iter()
            .position(|a| a == linux::JOINER_PIVOTED)
            .expect("flag position");
        let rootfs = args.get(i + 2).expect("joiner requires the rootfs path");
        linux::joiner_pivoted(pid, std::path::Path::new(rootfs));
    } else if let Some(pid) = pid_after(linux::JOINER_TMPFS) {
        let i = args
            .iter()
            .position(|a| a == linux::JOINER_TMPFS)
            .expect("flag position");
        let rootfs = args.get(i + 2).expect("joiner requires the rootfs path");
        let identity = args.get(i + 3).expect("joiner requires the identity file");
        linux::joiner_tmpfs(
            pid,
            std::path::Path::new(rootfs),
            std::path::Path::new(identity),
        );
    } else if let Some(pid) = pid_after(linux::JOINER_USER) {
        linux::joiner_user(pid);
    } else if pid_after(linux::JOINER_GROUPS).is_some() {
        linux::joiner_groups();
    } else if let Some(i) = args.iter().position(|a| a == linux::PID1_PIVOT_TMPFS) {
        let rootfs = args.get(i + 1).expect("pid1 requires the rootfs path");
        let identity = args.get(i + 2).expect("pid1 requires the identity file");
        linux::pid1_pivot_tmpfs(std::path::Path::new(rootfs), std::path::Path::new(identity));
    } else if let Some(i) = args.iter().position(|a| a == linux::PID1_PIVOT) {
        let rootfs = args.get(i + 1).expect("pid1 requires the rootfs path");
        linux::pid1_pivot(std::path::Path::new(rootfs));
    } else if args.iter().any(|a| a == "--ignored") {
        precondition::self_check();
        linux::orchestrate();
    } else {
        precondition::self_check();
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

    use fandhe_container_core::exec::{
        JoinNamespace, MountIsolation, SupplementaryGroups, ViolationReason,
        apply_join_credentials_for_test, clear_supplementary_groups_for_test, pivot_root,
        prepare_rootfs, verify_joined_root_for_test,
    };
    use fandhe_container_core::launch_isolation::{
        LaunchIsolationRecord, RecordedLandlock, RecordedRule, RecordedTarget, RootIdentity,
    };
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
            crate::reap::reap_on_drop(&mut self.unshare);
        }
    }

    /// 成功経路の joiner の再入フラグ。
    pub const JOINER: &str = "--joiner";
    /// 「呼び出し側と同じ mount namespace」の拒否経路の joiner の再入フラグ。
    pub const JOINER_SHARED_MNT: &str = "--joiner-shared-mnt";
    /// 「呼び出し側と別の user namespace」の対象へ、user namespace にも参加する joiner の再入フラグ（`nsenter` を
    /// 通さない。rootless の exec。#1462）。
    pub const JOINER_ROOTLESS: &str = "--joiner-rootless";
    /// `pivot_root` 済みの pid1 へ参加し、参加後の `/` を照合する joiner の再入フラグ（引数: pid・rootfs）。
    pub const JOINER_PIVOTED: &str = "--joiner-pivoted";
    /// 範囲写像の対象へ、非 root の `process.user` と `additionalGids` を照合して適用する joiner の再入フラグ
    /// （引数: pid。#2770）。
    pub const JOINER_USER: &str = "--joiner-user";
    /// `setgroups` が `deny` の user namespace で補助グループの扱いを照合する joiner の再入フラグ（引数: pid。未使用）。
    pub const JOINER_GROUPS: &str = "--joiner-groups";
    /// launcher と同じ手順で `pivot_root` まで進んで待機する pid1 の再入フラグ（引数: rootfs）。
    pub const PID1_PIVOT: &str = "--pid1-pivot";
    /// rootfs へ tmpfs をマウントしてから `pivot_root` まで進んで待機する pid1 の再入フラグ（引数: rootfs・pivot 後の
    /// `/` の識別子の書き出し先。#1468）。
    pub const PID1_PIVOT_TMPFS: &str = "--pid1-pivot-tmpfs";
    /// tmpfs で組み立てた rootfs の pid1 へ参加する joiner の再入フラグ（引数: pid・rootfs・識別子ファイル。#1468）。
    pub const JOINER_TMPFS: &str = "--joiner-tmpfs";
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
        // 成功経路: 対象の user namespace へ入っていない（`nsenter` を通さない）呼び出し側は、5 種に先立って対象の
        // user namespace にも参加し、参加後の資格情報を名前空間内の root へ揃える（SEC-5・SEC-1・TASK-163.h2・#1462）。
        run_scenario(&ALL_NS, sleep(), None, false, JOINER_ROOTLESS, &[]);
        println!("exec_setns_join: rootless join into the target user namespace verified");
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
        // 成功経路（#1468）: rootfs を mount namespace の中で組み立てる構成（tmpfs。overlay の代わり）。参加後の `/` は
        // 記録した pivot 後の `/` と一致し、ホスト側の bundle ディレクトリとは一致しない。
        let tmpfs_rootfs = Rootfs::create();
        let identity_file = tmpfs_rootfs.dir.with_extension("identity");
        fs::write(&identity_file, b"").expect("create the identity file");
        let _identity_guard = FileGuard(identity_file.clone());
        let exe = std::env::current_exe().expect("current_exe");
        let pid1 = vec![
            exe.into_os_string(),
            OsString::from(PID1_PIVOT_TMPFS),
            tmpfs_rootfs.dir.clone().into_os_string(),
            identity_file.clone().into_os_string(),
        ];
        run_scenario(
            &ALL_NS,
            pid1,
            Some(&identity_file),
            true,
            JOINER_TMPFS,
            &[
                tmpfs_rootfs
                    .dir
                    .to_str()
                    .expect("utf-8 rootfs path")
                    .to_owned(),
                identity_file.to_str().expect("utf-8 path").to_owned(),
            ],
        );
        println!(
            "exec_setns_join: root after joining a mount-namespace-built rootfs equals the recorded root"
        );
        // TASK-163 追補（#1457）: `setgroups` が `deny` の user namespace（rootless。`--map-root-user`）では、
        // `CAP_SETGID` を持っていても補助グループを消去できない。launch・exec が共有する関数は拒否にも成功の偽装にも
        // せず、現状維持として記録する（SEC-5。rootless の launch を壊さない）。
        run_scenario(&ALL_NS, sleep(), None, true, JOINER_GROUPS, &[]);
        println!(
            "exec_setns_join: supplementary groups kept and recorded where setgroups is denied"
        );
        // #2770: 範囲写像の対象への非 root の `process.user` と `additionalGids`（実機前提の追加。前提が揃う時だけ）。
        if std::env::var("FANDHE_CONTAINER_TEST_ID_HELPER").as_deref() == Ok("1") {
            let uid = fs::metadata("/proc/self").expect("stat /proc/self").uid();
            crate::precondition::require_subordinate_ids(uid);
            let (uid_range, gid_range) = subordinate_ranges();
            let map_users = format!("--map-users=0:{}:{}", uid_range.0, uid_range.1);
            let map_groups = format!("--map-groups=0:{}:{}", gid_range.0, gid_range.1);
            run_scenario_mapped(
                &[map_users.as_str(), map_groups.as_str()],
                &ALL_NS,
                sleep(),
                None,
                false,
                JOINER_USER,
                &[],
            );
            println!(
                "exec_setns_join: exec user 1000:1000 with groups 2000,3000 applied via subordinate ids"
            );
        } else {
            println!(
                "exec_setns_join: subordinate id case not requested (set FANDHE_CONTAINER_TEST_ID_HELPER=1)"
            );
        }
        println!("exec_setns_join: namespace join verified");
    }

    /// 自ユーザーの subuid・subgid の最初の範囲 `(先頭, 件数)`（件数は 65536 まで）。前提欠如は呼び出し前の
    /// `require_subordinate_ids` が PRECONDITION FAILED で拒否済みで、ここでの失敗は事前検査後の回帰として扱う。
    fn subordinate_ranges() -> ((u32, u32), (u32, u32)) {
        use fandhe_container_core::rootless::{SubIdOwner, load_subordinate_ids};
        let uid = fs::metadata("/proc/self").expect("stat /proc/self").uid();
        let owner = SubIdOwner::new(uid, std::env::var("USER").ok()).expect("owner");
        let first = |file: &str| {
            let ranges = load_subordinate_ids(Path::new(file), &owner)
                .unwrap_or_else(|e| panic!("load {file}: {e}"));
            let r = ranges
                .first()
                .unwrap_or_else(|| panic!("{file} has no range for the current user"));
            (r.start(), r.count().min(65_536))
        };
        (first("/etc/subuid"), first("/etc/subgid"))
    }

    /// 使い捨てのファイル。drop で削除する。
    struct FileGuard(PathBuf);

    impl Drop for FileGuard {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
        }
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
        run_scenario_mapped(
            &["--map-root-user"],
            extra_ns,
            pid1_command,
            ready,
            enter_user_ns,
            joiner_flag,
            joiner_args,
        );
    }

    /// [`run_scenario`] の本体。`user_map` は `unshare` の user namespace の写像の指定（`--map-root-user` か、
    /// 範囲写像の `--map-users` / `--map-groups`。#2770）。
    fn run_scenario_mapped(
        user_map: &[&str],
        extra_ns: &[&str],
        pid1_command: Vec<OsString>,
        ready: Option<&Path>,
        enter_user_ns: bool,
        joiner_flag: &str,
        joiner_args: &[String],
    ) {
        let unshare = Command::new("unshare")
            .args(["--user"])
            .args(user_map)
            .args([
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
            while !fs::metadata(ready).is_ok_and(|m| m.len() > 0) {
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
                crate::reap::reap_or_report(&mut joiner, crate::reap::REAP_WITHIN);
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

    /// 全 16 種の launch 記録（`Nofile` は (700, 1500)、他は種別の添字から決める具体値。TASK-169 追補・#1467）。
    fn full_rlimits() -> fandhe_container_core::rlimits::Rlimits {
        use fandhe_container_core::rlimits::{Rlimit, RlimitKind, Rlimits};
        Rlimits::new(
            RlimitKind::ALL
                .into_iter()
                .enumerate()
                .map(|(i, k)| {
                    let (soft, hard) = if k == RlimitKind::Nofile {
                        (700, 1500)
                    } else {
                        (i as u64, 100 + i as u64)
                    };
                    Rlimit::new(k, soft, hard).expect("rlimit")
                })
                .collect(),
        )
        .expect("rlimits")
    }

    /// launch 時の分離の記録（`root` は参加後の `/` の照合の基準。ルールは rootfs だけ。#1468）。
    fn launch_isolation(root: RootIdentity) -> LaunchIsolationRecord {
        LaunchIsolationRecord::from_parts(
            root,
            RecordedLandlock::new(0xFFFF, vec![RecordedRule::new(RecordedTarget::Root, 0x7)])
                .expect("recorded landlock"),
        )
    }

    /// 試験用のレコード（Running・記録 pid あり）と、pid1 が実際に属する cgroup の絶対パス。
    /// `root` は記録する launch 時の `/` の識別子（`enter_namespaces` までの試験では照合しないので任意の値）。
    fn record_and_cgroup_path(pid: u32, root: RootIdentity) -> (StateRecord, String) {
        let status =
            ContainerStatus::running(ContainerId::new("c1").expect("id"), NonZeroU32::new(pid));
        let rec = StateRecord::new(
            status,
            std::env::temp_dir().join("b"),
            StateRevision::from_raw(1),
        )
        .expect("record")
        .with_rlimits(full_rlimits())
        .with_launch_isolation(launch_isolation(root));
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
        let (rec, path) = record_and_cgroup_path(pid, RootIdentity::new(44, 1234));
        let err = identify_pid1_in(&rec, &path).unwrap_err();
        assert_eq!(err.code(), ErrorCode::FailedPrecondition);
        assert_eq!(
            err.message(),
            "exec stage SetNs: the exec target shares the mount namespace with the caller; \
             refusing to join (violation: exec_target/exec_target_shares_mount_namespace, SUP-6)"
        );
    }

    /// 対象の user namespace へ入っていない（初期 user namespace の非特権ユーザー = 対象の所有者）単一スレッドで、
    /// 5 種すべてを分離した pid1 へ、user namespace を先頭に 1 回の `setns` で参加する（rootless の exec。
    /// SEC-5・SEC-1・TASK-163.h2・#1462）。
    ///
    /// 参加前は user / mnt / pid が対象と異なり、参加後は user を含む 5 種が対象と一致する。続けて本番と同じ関数・
    /// 実 syscall で補助グループ → gid・uid の処理を通し、補助グループが `setgroups` = `deny` のため現状維持として
    /// 記録されること（0 件なら `AlreadyEmpty`）と、`Uid:` / `Gid:` が名前空間内から見て 0 になることを照合する。
    pub fn joiner_rootless(pid: u32) {
        let status = || fs::read_to_string("/proc/thread-self/status").expect("read own status");
        let field = |status: &str, name: &str| {
            status
                .lines()
                .find_map(|l| l.strip_prefix(name))
                .unwrap_or_else(|| panic!("{name} missing in status"))
                .trim()
                .to_owned()
        };
        let entries = ["user", "mnt", "uts", "ipc", "net"];
        let want: Vec<String> = entries
            .iter()
            .map(|n| link(&format!("/proc/{pid}/ns/{n}")))
            .collect();
        let want_pid = link(&format!("/proc/{pid}/ns/pid"));
        for (i, n) in entries.iter().enumerate() {
            assert_ne!(
                link(&format!("/proc/thread-self/ns/{n}")),
                want[i],
                "{n} namespace must differ before join"
            );
        }
        let groups_before = field(&status(), "Groups:");
        let group_count = groups_before.split_whitespace().count();

        let (rec, path) = record_and_cgroup_path(pid, RootIdentity::new(44, 1234));
        let target =
            identify_pid1_in(&rec, &path).expect("identify pid1 in another user namespace");
        let report = enter_namespaces(&target).expect("enter namespaces including the user one");
        assert_eq!(report.target_pid.get(), pid);
        assert!(report.user_namespace_joined);
        let mut expected = vec![JoinNamespace::User];
        expected.extend(JoinNamespace::SUP6_SET);
        assert_eq!(report.joined, expected);

        for (i, n) in entries.iter().enumerate() {
            assert_eq!(
                link(&format!("/proc/thread-self/ns/{n}")),
                want[i],
                "{n} namespace must equal the target after join"
            );
        }
        assert_eq!(link("/proc/thread-self/ns/pid_for_children"), want_pid);

        // 参加後の処理（補助グループ → gid・uid）。参加先は `unshare --map-root-user` の namespace で、`setgroups` は
        // `deny`。呼び出し側の補助グループは消去できず、現状維持として記録される。
        assert_eq!(
            fs::read_to_string("/proc/thread-self/setgroups").expect("read setgroups"),
            "deny\n",
            "setgroups must be denied in the joined user namespace"
        );
        let want_groups = if group_count == 0 {
            SupplementaryGroups::AlreadyEmpty
        } else {
            SupplementaryGroups::KeptSetgroupsDenied { kept: group_count }
        };
        assert_eq!(
            apply_join_credentials_for_test(0, 0).expect("switch to the container root"),
            want_groups
        );
        let after = status();
        assert_eq!(field(&after, "Uid:"), "0\t0\t0\t0");
        assert_eq!(field(&after, "Gid:"), "0\t0\t0\t0");
    }

    /// 範囲写像の user namespace（コンテナ内 0.. を subuid / subgid の範囲へ写す。`setgroups` は `allow`）の pid1 へ、
    /// 対象の所有者として参加する単一スレッドで、非 root の `process.user` と `additionalGids` を本番と同じ照合
    /// （実際の写像との照合）で受け、参加後に補助グループ → gid → uid の順で適用する（SEC-5・CORE-6・SUP-6・#2770）。
    ///
    /// 参加前に、写像の外の uid・追加 gid が `InvalidArgument` で拒否されることも照合する（副作用の前）。適用後は
    /// 参加先の名前空間内から見た `Uid:` / `Gid:` が 1000、`Groups:` が昇順の `2000 3000` になる。
    pub fn joiner_user(pid: u32) {
        use fandhe_container_core::exec::{apply_join_user_for_test, exec_user_check_for_test};
        let config = |user: &str| {
            let json = format!(
                r#"{{"ociVersion":"1.2.0","root":{{"path":"rootfs","readonly":false}},"mounts":[],
                "process":{{"terminal":false,"user":{user},"args":["/bin/true"],"cwd":"/"}}}}"#
            );
            fandhe_container_core::oci_runtime::parse_config_bytes(json.as_bytes())
                .expect("parse config")
        };
        let (rec, path) = record_and_cgroup_path(pid, RootIdentity::new(44, 1234));
        let target =
            identify_pid1_in(&rec, &path).expect("identify pid1 in the subordinate user namespace");
        // 写像の内側は受け、補助グループは昇順・重複なしに正規化される。
        let accepted = exec_user_check_for_test(
            target.pid1(),
            &config(r#"{"uid":1000,"gid":1000,"additionalGids":[3000,2000,3000]}"#),
        )
        .expect("a mapped process.user must be accepted");
        assert_eq!(accepted, Some((1000, 1000, vec![2000, 3000])));
        // 写像の外（コンテナ内 65536 以上。写像は 0..65535）は副作用の前に拒否される。
        for user in [
            r#"{"uid":65536,"gid":1000}"#,
            r#"{"uid":1000,"gid":65536}"#,
            r#"{"uid":1000,"gid":1000,"additionalGids":[2000,65536]}"#,
        ] {
            let e = exec_user_check_for_test(target.pid1(), &config(user))
                .expect_err("an unmapped process.user must be refused");
            assert_eq!(e.code, ErrorCode::InvalidArgument, "{user}");
        }

        let report = enter_namespaces(&target).expect("enter namespaces including the user one");
        assert!(report.user_namespace_joined);
        assert_eq!(
            fs::read_to_string("/proc/thread-self/setgroups").expect("read setgroups"),
            "allow\n",
            "setgroups must be allowed in the subordinate user namespace"
        );
        assert_eq!(
            apply_join_user_for_test(1000, 1000, &[3000, 2000]).expect("apply the exec user"),
            SupplementaryGroups::Applied { count: 2 }
        );
        let status = fs::read_to_string("/proc/thread-self/status").expect("read own status");
        let field = |name: &str| {
            status
                .lines()
                .find_map(|l| l.strip_prefix(name))
                .unwrap_or_else(|| panic!("{name} missing in status"))
                .trim()
                .to_owned()
        };
        assert_eq!(field("Uid:"), "1000\t1000\t1000\t1000");
        assert_eq!(field("Gid:"), "1000\t1000\t1000\t1000");
        assert_eq!(field("Groups:"), "2000 3000");
    }

    /// 対象の user namespace（`unshare --map-root-user` が作る。`setgroups` は `deny`）に入った単一スレッドで、
    /// 本番と同じ関数・実 syscall により補助グループの消去を試み、「現状維持の記録」になることを具体値で照合する
    /// （SUP-6・SEC-5・TASK-163 追補・#1457）。
    ///
    /// この user namespace の中では uid 0 で全 capability（`CAP_SETGID` を含む）を持つが、`setgroups(2)` は
    /// `EPERM` になる。呼び出したユーザーの補助グループが写像されないまま残っていること（1 件以上）が前提。
    pub fn joiner_groups() {
        let status = || fs::read_to_string("/proc/self/status").expect("read own status");
        let field = |status: &str, name: &str| {
            status
                .lines()
                .find_map(|l| l.strip_prefix(name))
                .unwrap_or_else(|| panic!("{name} missing in status"))
                .trim()
                .to_owned()
        };
        let before = status();
        assert_eq!(
            fs::read_to_string("/proc/self/setgroups").expect("read setgroups"),
            "deny\n",
            "setgroups must be denied in this user namespace"
        );
        let effective = u64::from_str_radix(&field(&before, "CapEff:"), 16).expect("CapEff");
        assert_ne!(effective & (1 << 6), 0, "the joiner must hold CAP_SETGID");
        let groups = field(&before, "Groups:");
        let count = groups.split_whitespace().count();
        assert!(
            count > 0,
            "the joiner must carry supplementary groups for this scenario to be meaningful"
        );
        assert_eq!(
            clear_supplementary_groups_for_test().expect("handle supplementary groups"),
            SupplementaryGroups::KeptSetgroupsDenied { kept: count }
        );
        // 何も変わっていない（消去を装わない）。
        assert_eq!(field(&status(), "Groups:"), groups);
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

        // 記録する launch 時の `/` は、bind で自己 pivot する launcher の契約どおり、固定した rootfs の識別子。
        let (rec, path) = record_and_cgroup_path(pid, RootIdentity::new(pinned.0, pinned.1));
        let target = identify_pid1_in(&rec, &path).expect("identify pid1");
        let report = enter_namespaces(&target).expect("enter namespaces");
        assert_eq!(report.joined, JoinNamespace::SUP6_SET.to_vec());
        assert!(!report.user_namespace_joined);
        // 本番と同じ `/` の照合（記録した識別子との一致）が通る。
        verify_joined_root_for_test(RootIdentity::new(pinned.0, pinned.1))
            .expect("the joined root equals the recorded root");

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

    /// `--pid1-pivot-tmpfs`: 新しい PID namespace の PID 1 として、自分の mount namespace の中でだけ `rootfs` へ tmpfs を
    /// マウントし、launcher と同じ手順で `pivot_root` する（overlay のように rootfs を mount namespace の中で
    /// 組み立てる構成の代わり。#1468）。pivot 後の `/` の `st_dev`・`st_ino` を、pivot の前に開いておいた
    /// `identity_out` へ 1 回の書き込みで残して待機する（ホスト側のパスは pivot 後に解決できないため）。
    pub fn pid1_pivot_tmpfs(rootfs: &Path, identity_out: &Path) {
        use std::io::Write as _;
        assert_eq!(std::process::id(), 1, "must be PID 1 of the new namespace");
        let mut out = fs::OpenOptions::new()
            .write(true)
            .open(identity_out)
            .expect("open the identity file before pivoting");
        let isolation = MountIsolation::establish().expect("establish mount isolation");
        // 自分の mount namespace（`establish` が `/` を再帰 private にした後）の中でだけ tmpfs をマウントする。
        let mounted = Command::new("mount")
            .args(["-n", "-t", "tmpfs", "tmpfs"])
            .arg(rootfs)
            .status()
            .expect("run mount");
        assert!(mounted.success(), "mount tmpfs over the rootfs directory");
        fs::create_dir(rootfs.join("proc")).expect("mkdir proc in the tmpfs rootfs");
        let prepared = prepare_rootfs(&isolation, rootfs).expect("prepare rootfs");
        let report = pivot_root(&isolation, prepared).expect("pivot_root");
        assert!(report.old_root_detached, "the old root must be detached");
        let root = fs::metadata("/").expect("stat the new root");
        out.write_all(format!("{} {}\n", root.dev(), root.ino()).as_bytes())
            .expect("write the recorded root identity");
        out.sync_all().expect("sync the identity file");
        // `unshare --kill-child` が親の終了に連動して落とすまで待機する（上限つき。REPAIR-5）。
        let deadline = Instant::now() + Duration::from_secs(60);
        while Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    /// 対象の user namespace に入った単一スレッドで、tmpfs で組み立てた rootfs の pid1 へ参加し、参加後の `/` が
    /// 記録した pivot 後の `/` と一致すること、ホスト側の bundle ディレクトリの識別子とは一致しないことを照合する
    /// （SEC-1・SUP-6・TASK-163 追補・#1468）。
    pub fn joiner_tmpfs(pid: u32, rootfs: &Path, identity_file: &Path) {
        // 参加前（ホスト側のパスが見えるうち）に、記録の識別子とホスト側の rootfs の識別子を読む。
        let text = fs::read_to_string(identity_file).expect("read the recorded root identity");
        let mut fields = text.split_whitespace().map(|t| t.parse::<u64>());
        let recorded = RootIdentity::new(
            fields.next().expect("dev").expect("dev is a number"),
            fields.next().expect("ino").expect("ino is a number"),
        );
        let host = fs::metadata(rootfs).expect("stat the host-side rootfs directory");
        let host_identity = RootIdentity::new(host.dev(), host.ino());
        assert_ne!(
            recorded, host_identity,
            "a mount-namespace-built rootfs must differ from the host-side directory"
        );

        let (rec, path) = record_and_cgroup_path(pid, recorded);
        let target = identify_pid1_in(&rec, &path).expect("identify pid1");
        let report = enter_namespaces(&target).expect("enter namespaces");
        assert_eq!(report.joined, JoinNamespace::SUP6_SET.to_vec());

        // 本番と同じ照合: 記録した識別子とは一致し、ホスト側の bundle ディレクトリの識別子とは不一致（違反つき）。
        verify_joined_root_for_test(recorded).expect("the joined root equals the recorded root");
        let e = verify_joined_root_for_test(host_identity)
            .expect_err("the host-side directory is not the joined root");
        assert_eq!(
            e.violation.expect("violation recorded").reason,
            ViolationReason::ExecRootNotContainerRootfs
        );
        // 参加後の `/` を直接 stat しても記録と同じ。
        let joined = fs::metadata("/").expect("stat the joined root");
        assert_eq!(
            (joined.dev(), joined.ino()),
            (recorded.dev(), recorded.ino())
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
        let (rec, path) = record_and_cgroup_path(pid, RootIdentity::new(44, 1234));
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
        // 呼び出し側は `nsenter --user` で対象と同じ user namespace にいるため、user namespace には参加しない。
        assert_eq!(report.joined, JoinNamespace::SUP6_SET.to_vec());
        assert!(!report.user_namespace_joined);

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
