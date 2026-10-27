//! bind mount の適用の段（`fandhe_container_core::exec::mount_binds`）を実カーネルで照合する結合試験
//! （CORE-1・CORE-2・OCI-4・SEC-1・SEC-2・SEC-4・SEC-5・IO-8・REPAIR-12・TASK-29 追補・#1916）。
//!
//! 単体試験（`exec/bind_mounts.rs`）は新しいマウント API（`open_tree`・`mount_setattr`・`move_mount`）と
//! mountinfo を差し替えて検証している。属性が実際に付くこと、伝播が private であること、symlink や疑似 FS で
//! 外へ出られないこと、失敗時に巻き戻ることは、実カーネルでしか確かめられないため、本試験が実マウントで照合する。
//! 本番 launcher（#1816）には依存せず、`tmpfs_mount.rs` と同じ入口（`isolate` → `establish` → `prepare_rootfs`）を使う。
//! 既定の集合で走る API 試験は `tests/bind_mounts.rs`（#1911）。本試験は `bind_mounts_real`（名前の `_real` は実機前提）。
//!
//! # プロセス構成（3 段）
//! - T（dispatcher）: 分離しない。fixture を作り、ホストの mountinfo を事前に控え、P を起動して C の `READY` を
//!   期限つきで待つ。READY の後にホスト側の mountinfo（子の bind が現れない）とホスト側の元（rw の書き込みが
//!   現れる・ro に何も増えない）を照合し、`GO` を返す
//! - P（`--isolated-parent`）: 単一スレッドのまま `isolate`（rootless は user・pid・mount・uts・ipc、root は
//!   user を除く rootful 構成）し、C を起動して期限つきで待つ
//! - C（`--child`）: 新しい PID namespace の PID 1。`establish` → `prepare_rootfs` → 各シナリオ → `pivot_root`
//!   の後の観測 → `READY` を出して `GO` を待つ
//!
//! # 照合する内容（rootless）
//! 失敗した後も同じ分離を使い続けるのは後始末の照合のためで、本番の契約（失敗時はプロセスを破棄）とは別。
//! 1. 途中の件での失敗と巻き戻し（先に載せた分が mountinfo から消える・自動作成が残らない・symlink の先に何も
//!    作られない・違反記録が 1 件残る）
//! 2. 検査後の差し替え（`exec-test-support` の `mount_binds_with_attach_hook`。どちらの名前にもマウントが残らない）
//! 3. 元の拒否（symlink・ソケット・FIFO・起動した利用者が読めない元）
//! 4. 成功経路と `pivot_root` の後の観測（`nosuid`・`nodev`・private、`ro`・`noexec`、書き込みのホスト側への反映、
//!    ファイルの bind、`rbind` と非再帰の差、`nodev`）
//! 5. 疑似 FS（`/proc`・`/sys`・`/sys/fs/cgroup`・`/dev` の rbind）の拒否、非再帰で `/dev` を元にした拒否、
//!    自分の `ro` を元にした rw の bind の拒否、overlay を元にした bind の拒否（#2064・#2120・#2298）
//!
//! root（`root=true`）では user namespace を作れず、段は rootfs に触れる前に `user_namespace_required` で拒否する
//! （SEC-5）。この経路では「拒否されて何もマウント・作成されない」ことを照合する。
//!
//! # 範囲外（REPAIR-3）
//! 状態ルートの別名・改名・付け替え（#2066・#2104・#2129）は、`BindMountSet` の保護対象の設定口が crate 内に限られ
//! 段の公開 API から入れられないため本試験では扱わない（`production_launcher` のシナリオ E・H と人間担当の #1621）。
//! ホスト側でロックされた `ro` のマウントを元にする確認も、ホストの構成に依存するため扱わない。
//! `lowerdir` そのものを元にした場合の結果は assert せず、観測値を出力するだけにする（実装は付け替えた木が
//! overlay のときだけ拒否すると読めるため、期待と食い違う可能性がある。オーナー判断待ち）。
//!
//! # 実機前提テストとしての分離
//! 非特権 user namespace を許可するホスト（AppArmor の `kernel.apparmor_restrict_unprivileged_userns=1` では不可）
//! または root と、Linux 5.12 以降（新しいマウント API）、overlay の確認用に util-linux の `mount`・coreutils の
//! `mknod`・`mkfifo` が要る。一時ディレクトリが overlayfs の上にあると元がすべて拒否されるため、`TMPDIR` を
//! overlay 以外へ向ける。GitHub ホステッド runner では保証できないため `-- --ignored` 指定時のみ実行する。
//! 前提が欠けていれば skip せず panic する。実行: `cargo test -p fandhe-container-core --test bind_mounts_real -- --ignored`。
//! root は一般ユーザーで `--no-run` してから、生成されたバイナリを root で `--ignored` 付きで実行する
//! （root 権限コマンドは明示指示のもとで行い、結果は #1621 へ記録する）。期限は
//! `FANDHE_CONTAINER_TEST_TIMEOUT_SECS`（1..=600、既定 30）で変えられる（REPAIR-5）。
//!
//! 成功行（rootless）: `bind_mounts_real: binds applied with nosuid,nodev and private propagation; ro, noexec, nodev, rbind enforced; rejections rolled back; nothing propagated to the host (root=false)`
//! 成功行（root）: `bind_mounts_real: bind mounts refused without a user namespace; nothing mounted or created (root=true)`

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("bind_mounts_real: Linux only, not applicable on this OS");
}

#[cfg(target_os = "linux")]
fn main() {
    // mountinfo の解析と伝播判定の自己照合は、実機前提の実行でなくても毎回走らせる（REPAIR-12）。
    linux::self_check();
    let args: Vec<String> = std::env::args().collect();
    if args
        .iter()
        .any(|a| a == "--ignored" || a == "--child" || a == "--isolated-parent")
    {
        linux::run(&args);
    } else {
        println!(
            "bind_mounts_real: ignored (real-machine test; run with `-- --ignored`, see AGENTS.md)"
        );
    }
}

#[cfg(target_os = "linux")]
#[path = "support/temp_rootfs.rs"]
mod temp_rootfs;

#[cfg(target_os = "linux")]
mod linux {
    use crate::temp_rootfs;
    use std::io::{BufRead as _, Write as _};
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Stdio};
    use std::sync::Mutex;
    use std::time::{Duration, Instant};

    use fandhe_container_core::audit_log::{AuditDelivery, AuditLayer, AuditRecord, AuditSink};
    use fandhe_container_core::exec::{
        BindSourceType, ExecError, IsolationConfig, IsolationStage, MountIsolation, Namespace,
        NamespaceSet, PreparedRootfs, ViolationReason, audit_mount_violation, isolate,
        isolate_rootful_host_root, mount_binds, mount_binds_with_attach_hook, mount_tmpfs,
        pivot_root, plan, plan_rootful_host_root, prepare_rootfs,
    };
    use fandhe_container_core::oci_runtime::{BindMountSet, parse_config_bytes};
    use fandhe_container_core::tmpfs::{TmpfsMountSet, TmpfsMountSpec};
    use fandhe_container_core::traits::{ErrorCode, TraitError};

    /// 上限秒の既定。`mount` の子と C・P の待ちに使う。
    const DEFAULT_TIMEOUT_SECS: u64 = 30;
    /// 元の `prog` に書く内容。ELF でも通常の `#!` でもなく、存在しないインタプリタを指す。
    /// `noexec` でない bind では `ENOENT`、`noexec` では実行の前に `EACCES` になる（差が観測点）。
    const PROG_BYTES: &[u8] = b"#!/nonexistent-interpreter-for-bind-mounts-real\n";
    const WRITTEN_BYTES: &[u8] = b"written by the container\n";
    const FILE_BYTES: &[u8] = b"file bind content\n";
    const MARKER_BYTES: &[u8] = b"marker on the tmpfs submount\n";
    const ENV_UNREADABLE_DIR: &str = "FANDHE_CONTAINER_BINDS_REAL_UNREADABLE_DIR";
    const ENV_UNREADABLE_FILE: &str = "FANDHE_CONTAINER_BINDS_REAL_UNREADABLE_FILE";

    fn timeout() -> Duration {
        let secs = std::env::var("FANDHE_CONTAINER_TEST_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|s| (1..=600).contains(s))
            .unwrap_or(DEFAULT_TIMEOUT_SECS);
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

    // ---------------------------------------------------------------- mountinfo

    /// `/proc/*/mountinfo` の 1 行の必要な部分。
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Entry {
        pub point: String,
        /// per-mount options。
        pub opts: Vec<String>,
        /// optional fields（`shared:N`・`master:N`・`propagate_from:N`・`unbindable`）。
        pub optional: Vec<String>,
        pub fstype: String,
    }

    impl Entry {
        pub fn has_opt(&self, opt: &str) -> bool {
            self.opts.iter().any(|o| o == opt)
        }

        /// 伝播が private（`shared:`・`master:`・`propagate_from:` のいずれも無い）か。
        pub fn is_private(&self) -> bool {
            !self.optional.iter().any(|o| {
                o.starts_with("shared:")
                    || o.starts_with("master:")
                    || o.starts_with("propagate_from:")
            })
        }
    }

    /// mountinfo の `\040` 等の 8 進エスケープを戻す。
    fn unescape(s: &str) -> String {
        let bytes = s.as_bytes();
        let mut out = Vec::with_capacity(bytes.len());
        let mut i = 0;
        while let Some(&b) = bytes.get(i) {
            let oct = bytes
                .get(i + 1..i + 4)
                .filter(|_| b == b'\\')
                .and_then(|d| std::str::from_utf8(d).ok())
                .and_then(|d| u8::from_str_radix(d, 8).ok());
            match oct {
                Some(v) => {
                    out.push(v);
                    i += 4;
                }
                None => {
                    out.push(b);
                    i += 1;
                }
            }
        }
        String::from_utf8_lossy(&out).into_owned()
    }

    pub fn parse_line(line: &str) -> Option<Entry> {
        let f: Vec<&str> = line.split(' ').collect();
        let sep = f.iter().position(|x| *x == "-")?;
        if sep < 6 {
            return None;
        }
        Some(Entry {
            point: unescape(f.get(4)?),
            opts: f.get(5)?.split(',').map(str::to_owned).collect(),
            optional: f.get(6..sep)?.iter().map(|s| (*s).to_owned()).collect(),
            fstype: (*f.get(sep + 1)?).to_owned(),
        })
    }

    fn read_entries(path: &str) -> Vec<Entry> {
        std::fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("read {path}: {e}"))
            .lines()
            .filter_map(parse_line)
            .collect()
    }

    /// `path` を含む（マウントポイントが祖先で最長の）マウント。
    fn entry_covering<'a>(entries: &'a [Entry], path: &Path) -> Option<&'a Entry> {
        entries
            .iter()
            .filter(|e| path.starts_with(&e.point))
            .max_by_key(|e| e.point.len())
    }

    /// 呼び出しスレッドの mountinfo のマウントポイント一覧（pivot 前に使う）。
    fn thread_points() -> Vec<String> {
        read_entries("/proc/thread-self/mountinfo")
            .into_iter()
            .map(|e| e.point)
            .collect()
    }

    /// mountinfo の解析・伝播判定・最長一致の合成 fixture による自己照合（特権不要。毎回実行する）。
    pub fn self_check() {
        let shared = parse_line(
            "36 35 98:0 /mnt1 /mnt2 rw,noatime shared:1 master:2 - ext3 /dev/root rw,errors=continue",
        )
        .expect("parse shared line");
        assert_eq!(shared.point, "/mnt2");
        assert_eq!(shared.opts, vec!["rw", "noatime"]);
        assert_eq!(shared.optional, vec!["shared:1", "master:2"]);
        assert_eq!(shared.fstype, "ext3");
        assert!(!shared.is_private());

        let private = parse_line("20 11 0:20 / /with\\040space ro,nosuid,nodev - tmpfs tmpfs ro")
            .expect("parse private line");
        assert_eq!(private.point, "/with space");
        assert!(private.optional.is_empty());
        assert!(private.is_private());
        assert!(private.has_opt("nosuid") && !private.has_opt("noexec"));

        let unb = parse_line("21 11 0:21 / /u rw unbindable - tmpfs tmpfs rw").expect("parse");
        assert!(unb.is_private(), "unbindable is not shared / master");
        let slave = parse_line("22 11 0:22 / /s rw master:5 - tmpfs tmpfs rw").expect("parse");
        assert!(!slave.is_private());
        let from = parse_line("23 11 0:23 / /f rw propagate_from:5 - tmpfs tmpfs rw").expect("p");
        assert!(!from.is_private());

        assert_eq!(parse_line("garbage"), None);

        let entries = vec![
            parse_line("1 0 0:1 / / rw - overlay overlay rw").expect("root"),
            parse_line("2 1 0:2 / /tmp rw - tmpfs tmpfs rw").expect("tmp"),
        ];
        assert_eq!(
            entry_covering(&entries, Path::new("/tmp/a/b")).map(|e| e.fstype.as_str()),
            Some("tmpfs")
        );
        assert_eq!(
            entry_covering(&entries, Path::new("/var/a")).map(|e| e.fstype.as_str()),
            Some("overlay")
        );
        assert_eq!(
            entry_covering(&entries, Path::new("/tmpx")).map(|e| e.fstype.as_str()),
            Some("overlay"),
            "a prefix of the name is not an ancestor"
        );
    }

    // ---------------------------------------------------------------- 入口

    pub fn run(args: &[String]) {
        let value_after = |flag: &str| {
            args.iter()
                .position(|a| a == flag)
                .and_then(|i| args.get(i + 1))
                .map(PathBuf::from)
        };
        // user namespace 内では写像後の euid が 0 になり is_root() で判別できないため、
        // T が決めた rootful / rootless を引数で受け取る。
        let rootful = args.iter().any(|a| a == "--rootful");
        if let Some(base) = value_after("--child") {
            child(&base, rootful);
        } else if let Some(base) = value_after("--isolated-parent") {
            isolated_parent(&base, rootful);
        } else {
            dispatcher();
        }
    }

    // ---------------------------------------------------------------- T（dispatcher）

    /// 一時 base（drop で削除）。
    struct Base(PathBuf);

    impl Drop for Base {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// kill 後の回収を期限つきで行う（REPAIR-5）。期限内に回収できなければ警告だけ出す
    /// （`Drop` 中の panic による abort を避ける）。
    fn kill_and_reap(child: &mut Child) {
        let _ = child.kill();
        let deadline = Instant::now() + timeout();
        loop {
            match child.try_wait() {
                Ok(Some(_)) | Err(_) => return,
                Ok(None) if Instant::now() >= deadline => {
                    eprintln!("bind_mounts_real: warning: a child was not reaped after SIGKILL");
                    return;
                }
                Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            }
        }
    }

    /// 子の終了を期限つきで待つ。期限を超えたら kill して回収する（REPAIR-5）。
    /// `Drop` 中でも使うため panic しない。
    fn wait_or_reap(child: &mut Child) {
        let deadline = Instant::now() + timeout();
        loop {
            match child.try_wait() {
                Ok(Some(_)) | Err(_) => return,
                Ok(None) if Instant::now() >= deadline => {
                    kill_and_reap(child);
                    return;
                }
                Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            }
        }
    }

    /// `pid` の子の PID 一覧（`/proc/<pid>/task/<pid>/children`）。読めなければ空。
    fn children_of(pid: u32) -> Vec<u32> {
        std::fs::read_to_string(format!("/proc/{pid}/task/{pid}/children"))
            .map(|s| {
                s.split_whitespace()
                    .filter_map(|v| v.parse().ok())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// P の後始末。panic でも C に EOF を返し、P と、P の子の C（新しい PID namespace の PID 1）を
    /// kill して消えるまで期限つきで確認する。C が消えれば namespace 内の子孫とマウントも消える。
    /// fixture の削除（`Base` の drop）より前に走る（宣言順の逆に drop される）。
    struct ParentGuard(Child);

    impl Drop for ParentGuard {
        fn drop(&mut self) {
            drop(self.0.stdin.take());
            // P を kill する前に C の PID を控える（kill 後は C が孤児になり辿れない）。
            let kids = children_of(self.0.id());
            kill_and_reap(&mut self.0);
            for pid in kids {
                // 同じ UID の祖先 namespace からの SIGKILL は PID 1 にも届く。
                // kill コマンドの待機にも期限を設ける（REPAIR-5）。Drop 中は panic しない。
                match Command::new("kill")
                    .args(["-KILL", &pid.to_string()])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                {
                    Ok(mut killer) => wait_or_reap(&mut killer),
                    Err(e) => eprintln!("bind_mounts_real: warning: spawn kill failed: {e}"),
                }
                let gone = Instant::now() + timeout();
                while Path::new(&format!("/proc/{pid}")).exists() && Instant::now() < gone {
                    std::thread::sleep(Duration::from_millis(20));
                }
                if Path::new(&format!("/proc/{pid}")).exists() {
                    eprintln!("bind_mounts_real: warning: child {pid} still exists after SIGKILL");
                }
            }
        }
    }

    /// 期限つきで外部コマンドを実行する（REPAIR-5）。
    fn run_tool_with_deadline(tool: &str, args: &[&str]) {
        let mut child = Command::new(tool)
            .args(args)
            .stdout(Stdio::null())
            .spawn()
            .unwrap_or_else(|e| panic!("spawn {tool} (required for this test): {e}"));
        let deadline = Instant::now() + timeout();
        loop {
            match child.try_wait().expect("try_wait") {
                Some(status) => {
                    assert!(status.success(), "{tool} {args:?} failed: {status:?}");
                    return;
                }
                None if Instant::now() >= deadline => {
                    kill_and_reap(&mut child);
                    panic!("{tool} {args:?} did not finish within {:?}", timeout());
                }
                None => std::thread::sleep(Duration::from_millis(20)),
            }
        }
    }

    fn write_file(path: &Path, bytes: &[u8], mode: u32) {
        std::fs::write(path, bytes).unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
            .unwrap_or_else(|e| panic!("chmod {}: {e}", path.display()));
    }

    /// `/proc/sys/kernel/osrelease` の `(major, minor)`。
    fn kernel_version() -> (u32, u32) {
        let rel = std::fs::read_to_string("/proc/sys/kernel/osrelease").expect("osrelease");
        let mut it = rel.trim().split(['.', '-']);
        let major = it
            .next()
            .and_then(|v| v.parse().ok())
            .expect("kernel major");
        let minor = it
            .next()
            .and_then(|v| v.parse().ok())
            .expect("kernel minor");
        (major, minor)
    }

    fn make_fixture() -> Base {
        let base = temp_rootfs::exclusive_temp_dir("fandhe-binds-real", 0o755);
        let guard = Base(base.clone());
        let s = path_str(&base);
        assert!(
            !s.contains(['"', '\\']),
            "the temp directory path must not contain quotes or backslashes: {s}"
        );
        for chain in [
            &["rootfs", "proc"][..],
            &["rootfs", "outside"],
            &["rootfs", "swap"],
            &["rootfs", "data"],
            &["rootfs", "srcdir", "sub"],
            &["src", "data"],
            &["src", "noexec"],
            &["src", "ro"],
            &["src", "real"],
            &["ovl", "lower"],
            &["ovl", "upper"],
            &["ovl", "work"],
            &["ovl", "merged"],
        ] {
            temp_rootfs::create_dir_chain(&base, chain);
        }
        std::os::unix::fs::symlink("outside", base.join("rootfs/link")).expect("rootfs/link");
        std::os::unix::fs::symlink("real", base.join("src/lnk")).expect("src/lnk");
        write_file(&base.join("src/data/prog"), PROG_BYTES, 0o755);
        write_file(&base.join("src/noexec/prog"), PROG_BYTES, 0o755);
        write_file(&base.join("src/ro/existing.txt"), b"existing\n", 0o644);
        write_file(&base.join("src/file.txt"), FILE_BYTES, 0o644);
        write_file(&base.join("ovl/lower/lower.txt"), b"lower\n", 0o644);
        // whiteout（文字デバイス 0:0）。`nodev` の観測に使う。作れなければ前提の欠如。
        // 0:0 の文字デバイスは whiteout として扱われ、`CAP_MKNOD` が無くても作れる
        // （`vfs_mknod` の whiteout 例外）。一般の文字デバイスは使わない。
        run_tool_with_deadline(
            "mknod",
            &[path_str(&base.join("src/data/wh")), "c", "0", "0"],
        );
        run_tool_with_deadline("mkfifo", &[path_str(&base.join("src/fifo"))]);
        // listener を drop しても socket の inode は残る。
        drop(
            std::os::unix::net::UnixListener::bind(base.join("src/sock")).unwrap_or_else(|e| {
                panic!("bind a unix socket under the temp dir (path too long?): {e}")
            }),
        );
        guard
    }

    fn dispatcher() {
        let rootful = is_root();
        assert!(
            kernel_version() >= (5, 12),
            "Linux 5.12 or later is required for the new mount API (open_tree / mount_setattr)"
        );
        let base = make_fixture();
        let host_entries = read_entries("/proc/self/mountinfo");
        if let Some(e) = entry_covering(&host_entries, &base.0) {
            assert_ne!(
                e.fstype, "overlay",
                "the temp directory is on overlayfs; every bind source would be rejected. \
                 Point TMPDIR at a non-overlay filesystem (e.g. a tmpfs)"
            );
        }
        assert!(
            host_entries.iter().any(|e| e.point.starts_with("/dev/")),
            "the host must have mounts under /dev (devpts etc.) for the /dev rbind scenarios"
        );
        let base_str = path_str(&base.0).to_owned();
        let base_prefix = format!("{base_str}/");
        let under_base = |entries: &[Entry]| -> Vec<String> {
            entries
                .iter()
                .map(|e| e.point.clone())
                .filter(|p| *p == base_str || p.starts_with(&base_prefix))
                .collect()
        };
        let host_before = under_base(&host_entries);

        // 読めない元の候補（rootless のみ。中身は読まない・出さない）。
        let mut unreadable = None;
        if !rootful {
            let dir = ["/root", "/etc/ssl/private", "/var/lib/private"]
                .into_iter()
                .find(|p| {
                    matches!(std::fs::read_dir(p),
                        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied)
                });
            let file = ["/etc/shadow", "/etc/gshadow", "/etc/sudoers"]
                .into_iter()
                .find(|p| {
                    matches!(std::fs::File::open(p),
                        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied)
                });
            match (dir, file) {
                (Some(d), Some(f)) => unreadable = Some((d, f)),
                other => panic!(
                    "rootless needs a directory and a file the invoking user cannot read \
                     (e.g. /root and /etc/shadow): {other:?}"
                ),
            }
        }

        let exe = std::env::current_exe().expect("current_exe");
        let mut cmd = Command::new(exe);
        cmd.arg("--isolated-parent")
            .arg(&base.0)
            .arg(if rootful { "--rootful" } else { "--rootless" })
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        if let Some((d, f)) = unreadable {
            cmd.env(ENV_UNREADABLE_DIR, d).env(ENV_UNREADABLE_FILE, f);
        }
        let mut guard = ParentGuard(cmd.spawn().expect("spawn isolated parent"));
        let stdout = guard.0.stdout.take().expect("parent stdout");
        let (tx, rx) = std::sync::mpsc::channel::<String>();
        std::thread::spawn(move || {
            for line in std::io::BufReader::new(stdout)
                .lines()
                .map_while(Result::ok)
            {
                if tx.send(line).is_err() {
                    break;
                }
            }
        });

        // READY を期限つきで待つ。途中の観測行は転記する。
        let deadline = Instant::now() + timeout();
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match rx.recv_timeout(left) {
                Ok(line) if line == "READY" => break,
                Ok(line) => println!("{line}"),
                Err(e) => panic!(
                    "the container side did not reach READY ({e}; status {:?})",
                    guard.0.try_wait()
                ),
            }
        }

        // ホストの mount namespace に子の bind mount が現れていない（SEC-1）。
        let host_after = under_base(&read_entries("/proc/self/mountinfo"));
        assert_eq!(
            host_after, host_before,
            "bind mounts of the child must not appear in the host mountinfo"
        );

        if !rootful {
            // rw の bind での書き込みがホスト側の元に同じ内容で現れる。
            assert_eq!(
                std::fs::read(base.0.join("src/data/written.txt")).expect("host-side written.txt"),
                WRITTEN_BYTES
            );
            // ro の bind には何も増えない。
            let mut names: Vec<String> = std::fs::read_dir(base.0.join("src/ro"))
                .expect("read src/ro")
                .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
                .collect();
            names.sort();
            assert_eq!(names, vec!["existing.txt".to_owned()]);
            // 文字デバイス 0:0 は、ホストの元のマウントが nodev なら EACCES、そうでなければ ENXIO で開けない。
            let entries = read_entries("/proc/self/mountinfo");
            let nodev = entry_covering(&entries, &base.0).is_some_and(|e| e.has_opt("nodev"));
            let host_errno = std::fs::File::open(base.0.join("src/data/wh"))
                .expect_err("the whiteout device must not open on the host either")
                .raw_os_error();
            assert_eq!(
                host_errno,
                Some(if nodev { 13 } else { 6 }),
                "host nodev={nodev}"
            );
        }

        let mut stdin = guard.0.stdin.take().expect("parent stdin");
        stdin.write_all(b"GO\n").expect("write GO");
        drop(stdin);
        let exit_deadline = Instant::now() + timeout() + timeout();
        loop {
            match guard.0.try_wait().expect("try_wait") {
                Some(status) => {
                    assert_eq!(status.code(), Some(0), "isolated parent must exit with 0");
                    break;
                }
                None if Instant::now() >= exit_deadline => {
                    panic!("isolated parent did not exit within the deadline")
                }
                None => std::thread::sleep(Duration::from_millis(20)),
            }
        }
        while let Ok(line) = rx.try_recv() {
            println!("{line}");
        }
        if rootful {
            println!(
                "bind_mounts_real: bind mounts refused without a user namespace; nothing mounted or created (root=true)"
            );
        } else {
            println!(
                "bind_mounts_real: binds applied with nosuid,nodev and private propagation; ro, noexec, nodev, rbind enforced; rejections rolled back; nothing propagated to the host (root=false)"
            );
        }
    }

    // ---------------------------------------------------------------- P

    fn isolated_parent(base: &Path, rootful: bool) {
        let mut namespaces = NamespaceSet::empty()
            .with(Namespace::Pid)
            .with(Namespace::Mount)
            .with(Namespace::Uts)
            .with(Namespace::Ipc);
        if rootful {
            // root から user namespace を含む計画は、ホスト root の恒等写像として拒否される（SEC-5）。
            // root では bind を適用する経路が無いことの裏付け。
            let with_user = IsolationConfig {
                namespaces: namespaces.with(Namespace::User),
                hostname: None,
            };
            let err = plan(&with_user).expect_err("root with a user namespace must be refused");
            assert_eq!(
                err.violation.as_ref().map(|v| v.reason),
                Some(ViolationReason::HostRootIdentityMapping)
            );
        } else {
            namespaces = namespaces.with(Namespace::User);
        }
        let config = IsolationConfig {
            namespaces,
            hostname: None,
        };
        let result = if rootful {
            plan_rootful_host_root(&config).and_then(|p| isolate_rootful_host_root(&p))
        } else {
            plan(&config).and_then(|p| isolate(&p))
        };
        if let Err(err) = result {
            panic!("isolate failed: {err}");
        }
        let exe = std::env::current_exe().expect("current_exe");
        // stdin / stdout は T とつながるパイプのまま C へ引き継ぐ（READY・GO の受け渡し）。
        let mut c = Command::new(exe)
            .arg("--child")
            .arg(base)
            .arg(if rootful { "--rootful" } else { "--rootless" })
            .spawn()
            .expect("spawn child");
        let budget = timeout() + timeout();
        let deadline = Instant::now() + budget;
        loop {
            match c.try_wait().expect("try_wait") {
                Some(status) => {
                    assert_eq!(status.code(), Some(0), "child must exit with 0");
                    return;
                }
                None if Instant::now() >= deadline => {
                    kill_and_reap(&mut c);
                    panic!("child did not exit within {budget:?}");
                }
                None => std::thread::sleep(Duration::from_millis(20)),
            }
        }
    }

    // ---------------------------------------------------------------- C 共通

    struct VecSink(Mutex<Vec<AuditRecord>>);

    impl AuditSink for VecSink {
        fn record(&self, record: &AuditRecord) -> Result<(), TraitError> {
            self.0
                .lock()
                .map_err(|_| TraitError::new(ErrorCode::Internal, "poisoned"))?
                .push(record.clone());
            Ok(())
        }
    }

    /// `(元, 宛先, オプション)` から検証済みの bind の集合を作る。`bind` / `rbind` はオプションに含める。
    fn bind_set(entries: &[(&str, &str, &[&str])]) -> BindMountSet {
        let mounts: Vec<String> = entries
            .iter()
            .map(|(src, dst, opts)| {
                let o = opts
                    .iter()
                    .map(|x| format!("\"{x}\""))
                    .collect::<Vec<_>>()
                    .join(",");
                format!(
                    r#"{{"destination":"{dst}","type":"bind","source":"{src}","options":[{o}]}}"#
                )
            })
            .collect();
        let json = format!(
            r#"{{"ociVersion":"1.2.0","root":{{"path":"rootfs"}},"mounts":[{}],"linux":{{}}}}"#,
            mounts.join(",")
        );
        let config = parse_config_bytes(json.as_bytes()).expect("valid config");
        BindMountSet::from_mounts(config.mounts()).expect("accepted bind set")
    }

    fn path_str(p: &Path) -> &str {
        p.to_str().expect("utf8 path")
    }

    fn missing(p: &Path) -> bool {
        matches!(
            std::fs::symlink_metadata(p).map_err(|e| e.kind()),
            Err(std::io::ErrorKind::NotFound)
        )
    }

    struct Ctx<'a> {
        isolation: &'a MountIsolation,
        prepared: &'a PreparedRootfs,
        base: &'a Path,
    }

    impl Ctx<'_> {
        fn src(&self, rel: &str) -> String {
            path_str(&self.base.join(rel)).to_owned()
        }

        fn rootfs(&self, rel: &str) -> PathBuf {
            self.base.join("rootfs").join(rel)
        }

        /// 共通の拒否の照合: 段・code・違反の理由・message にホスト側のパスが無い・mountinfo が呼び出し前と同じ。
        fn expect_violation(
            &self,
            what: &str,
            set: &BindMountSet,
            reason: ViolationReason,
            code: ErrorCode,
        ) -> ExecError {
            let before = thread_points();
            let err = mount_binds(self.isolation, self.prepared, set)
                .expect_err(&format!("{what} must be rejected"));
            assert_eq!(err.stage, IsolationStage::MountBinds, "{what}");
            assert_eq!(err.code, code, "{what}: {}", err.message);
            assert_eq!(
                err.violation.as_ref().map(|v| v.reason),
                Some(reason),
                "{what}: {}",
                err.message
            );
            self.assert_no_host_path(what, &err);
            assert_eq!(
                thread_points(),
                before,
                "{what}: mountinfo must be unchanged"
            );
            err
        }

        /// 違反ではない前提不成立（FAILED_PRECONDITION）の照合。`needle` は固定文言の一部。
        fn expect_precondition(&self, what: &str, set: &BindMountSet, needle: &str) -> ExecError {
            let before = thread_points();
            let err = mount_binds(self.isolation, self.prepared, set)
                .expect_err(&format!("{what} must be rejected"));
            assert_eq!(err.stage, IsolationStage::MountBinds, "{what}");
            assert_eq!(
                err.code,
                ErrorCode::FailedPrecondition,
                "{what}: {}",
                err.message
            );
            assert!(err.message.contains(needle), "{what}: {}", err.message);
            self.assert_no_host_path(what, &err);
            assert_eq!(
                thread_points(),
                before,
                "{what}: mountinfo must be unchanged"
            );
            err
        }

        /// message にホスト側のパスを載せない（SEC-4）。
        fn assert_no_host_path(&self, what: &str, err: &ExecError) {
            assert!(
                !err.message.contains(path_str(self.base)),
                "{what}: the message must not carry host paths: {}",
                err.message
            );
        }
    }

    fn child(base: &Path, rootful: bool) {
        assert_eq!(
            std::process::id(),
            1,
            "child must be PID 1 of the new PID namespace"
        );
        let isolation = MountIsolation::establish().expect("establish mount isolation");
        let prepared = prepare_rootfs(&isolation, &base.join("rootfs")).expect("prepare rootfs");
        {
            let ctx = Ctx {
                isolation: &isolation,
                prepared: &prepared,
                base,
            };
            if rootful {
                rootful_refusal(&ctx);
            } else {
                rollback_scenario(&ctx);
                swap_scenario(&ctx);
                source_rejections(&ctx);
                success_path(&ctx);
                extra_scenarios(&ctx);
            }
        }
        if !rootful {
            pivot_root(&isolation, prepared).expect("pivot_root");
            observe_after_pivot();
        }
        ready_and_wait_go();
    }

    /// READY を T へ出し、`GO` を 1 行受けるまで待つ（EOF・別の行は失敗。T の期限と kill で回収される）。
    fn ready_and_wait_go() {
        // READY は GO を待つ前に必ず T へ届ける（明示 flush でバッファ滞留によるデッドロックを避ける）。
        println!("READY");
        {
            use std::io::Write;
            std::io::stdout().flush().expect("flush READY");
        }
        let mut line = String::new();
        std::io::stdin()
            .lock()
            .read_line(&mut line)
            .expect("read GO");
        assert_eq!(line, "GO\n", "expected GO from the dispatcher");
    }

    // ---------------------------------------------------------------- root

    /// root（user namespace なし）: 段は rootfs に触れる前に拒否し、何もマウント・作成しない（SEC-5）。
    fn rootful_refusal(ctx: &Ctx<'_>) {
        let set = bind_set(&[(&ctx.src("src/data"), "/data", &["bind"])]);
        let before = std::fs::read_to_string("/proc/thread-self/mountinfo").expect("mountinfo");
        let err = ctx.expect_violation(
            "bind without a user namespace",
            &set,
            ViolationReason::UserNamespaceRequired,
            ErrorCode::InvalidArgument,
        );
        assert_eq!(err.violation.as_ref().map(|v| v.behavior_id), Some("SEC-5"));
        assert_eq!(
            std::fs::read_to_string("/proc/thread-self/mountinfo").expect("mountinfo"),
            before,
            "mountinfo must be byte-identical"
        );
        // `rootfs/data` は fixture で作ってある空ディレクトリのまま（自動作成も、中身の追加も無い）。
        assert_eq!(
            std::fs::read_dir(ctx.rootfs("data"))
                .expect("read rootfs/data")
                .count(),
            0
        );
    }

    // ---------------------------------------------------------------- rootless のシナリオ

    /// 1. 途中の件での失敗と巻き戻し（#1913 の後始末。違反記録つき）。
    fn rollback_scenario(ctx: &Ctx<'_>) {
        let set = bind_set(&[
            (&ctx.src("src/file.txt"), "/roll/conf.txt", &["bind"]),
            (&ctx.src("src/data"), "/other/one", &["bind"]),
            (&ctx.src("src/real"), "/link/x", &["bind"]),
        ]);
        let err = ctx.expect_violation(
            "a destination behind a symlink",
            &set,
            ViolationReason::PathSymlinkOrNotDirectory,
            ErrorCode::InvalidArgument,
        );
        let points = thread_points();
        let leftover: Vec<&String> = points
            .iter()
            .filter(|p| p.ends_with("/roll/conf.txt") || p.ends_with("/other/one"))
            .collect();
        assert!(
            leftover.is_empty(),
            "earlier mounts must be unmounted: {leftover:?}"
        );
        assert!(
            missing(&ctx.rootfs("roll")),
            "auto-created roll must be removed"
        );
        assert!(
            missing(&ctx.rootfs("other")),
            "auto-created other must be removed"
        );
        assert_eq!(
            std::fs::read_dir(ctx.rootfs("outside"))
                .expect("read outside")
                .count(),
            0,
            "nothing must be created behind the symlink"
        );
        // 違反記録（SEC-4）: 1 件・Mount 層・コンテナ内の宛先だけでホスト側のパスを載せない。
        let sink = VecSink(Mutex::new(Vec::new()));
        let audited = audit_mount_violation(err, None, &sink);
        assert_eq!(audited.delivery, AuditDelivery::Recorded);
        let records = sink.0.lock().expect("sink");
        assert_eq!(records.len(), 1, "exactly one audit record");
        let record = records.first().expect("record");
        assert_eq!(record.layer(), AuditLayer::Mount);
        let path = record.path().map(|p| p.to_string_lossy().into_owned());
        println!("bind_mounts_real: observed audit record path={path:?}");
        assert!(
            path.as_deref()
                .is_some_and(|p| p.contains("link") && !p.contains(path_str(ctx.base))),
            "the audit path must be the container-side destination: {path:?}"
        );
    }

    /// 2. 検査の後・付け替えの前にマウント先を差し替える（`exec-test-support`）。
    fn swap_scenario(ctx: &Ctx<'_>) {
        let set = bind_set(&[(&ctx.src("src/data"), "/swap", &["bind"])]);
        let (from, to) = (ctx.rootfs("swap"), ctx.rootfs("swapped"));
        let err = mount_binds_with_attach_hook(ctx.isolation, ctx.prepared, &set, &|| {
            std::fs::rename(&from, &to).expect("rename swap");
            std::fs::create_dir(&from).expect("recreate swap");
        })
        .expect_err("a swapped target must be rejected");
        assert_eq!(err.stage, IsolationStage::MountBinds);
        assert_eq!(err.code, ErrorCode::FailedPrecondition, "{}", err.message);
        let points = thread_points();
        let leftover: Vec<&String> = points
            .iter()
            .filter(|p| p.ends_with("/swap") || p.ends_with("/swapped"))
            .collect();
        assert!(leftover.is_empty(), "no mount may remain: {leftover:?}");
        for name in ["swap", "swapped"] {
            assert_eq!(
                std::fs::read_dir(ctx.rootfs(name))
                    .unwrap_or_else(|e| panic!("{name} must remain a directory: {e}"))
                    .count(),
                0,
                "{name} must stay empty"
            );
        }
    }

    /// 3. 元の拒否（symlink・ソケット・FIFO・利用者が読めない元）。宛先は作られない。
    fn source_rejections(ctx: &Ctx<'_>) {
        let cases: [(&str, String, ViolationReason, ErrorCode); 3] = [
            (
                "a symlink source",
                ctx.src("src/lnk"),
                ViolationReason::BindSourceSymlink,
                ErrorCode::InvalidArgument,
            ),
            (
                "a socket source",
                ctx.src("src/sock"),
                ViolationReason::BindSourceUnsupportedType,
                ErrorCode::InvalidArgument,
            ),
            (
                "a FIFO source",
                ctx.src("src/fifo"),
                ViolationReason::BindSourceUnsupportedType,
                ErrorCode::InvalidArgument,
            ),
        ];
        for (what, source, reason, code) in cases {
            let set = bind_set(&[(&source, "/mnt/x", &["bind"])]);
            ctx.expect_violation(what, &set, reason, code);
            assert!(
                missing(&ctx.rootfs("mnt")),
                "{what}: no destination may be created"
            );
        }
        // 起動した利用者が読めない元（user namespace の CAP_DAC_OVERRIDE は写像されていない所有者の inode に効かない）。
        let dir = std::env::var(ENV_UNREADABLE_DIR).expect("unreadable dir from the dispatcher");
        let file = std::env::var(ENV_UNREADABLE_FILE).expect("unreadable file from the dispatcher");
        for (what, source) in [
            ("an unreadable directory", dir),
            ("an unreadable file", file),
        ] {
            let set = bind_set(&[(&source, "/mnt/x", &["bind"])]);
            ctx.expect_violation(
                what,
                &set,
                ViolationReason::BindSourceNotAccessible,
                ErrorCode::PermissionDenied,
            );
            assert!(
                missing(&ctx.rootfs("mnt")),
                "{what}: no destination may be created"
            );
        }
    }

    /// 4. 成功経路（pivot 前）。tmpfs の submount を持つ元を rbind / 非再帰の両方で載せる。
    fn success_path(ctx: &Ctx<'_>) {
        // 元の下に別マウントを作る（rootfs の配下は元にできる。#2063 案 B）。
        let mut tmpfs = TmpfsMountSet::new();
        tmpfs
            .push(TmpfsMountSpec::new("/srcdir/sub", None).expect("tmpfs spec"))
            .expect("push tmpfs");
        mount_tmpfs(ctx.isolation, ctx.prepared, None, &tmpfs).expect("mount the submount tmpfs");
        std::fs::write(ctx.rootfs("srcdir/sub/marker"), MARKER_BYTES).expect("write marker");

        let srcdir = ctx.src("rootfs/srcdir");
        let set = bind_set(&[
            (&ctx.src("src/data"), "/data", &["bind"]),
            (&ctx.src("src/noexec"), "/noexec", &["bind", "noexec"]),
            (&ctx.src("src/ro"), "/ro", &["bind", "ro"]),
            (&ctx.src("src/file.txt"), "/etc/conf.txt", &["bind"]),
            (&srcdir, "/rb", &["rbind", "ro", "noexec"]),
            (&srcdir, "/nr", &["bind"]),
        ]);
        let report = mount_binds(ctx.isolation, ctx.prepared, &set).expect("mount binds");
        let applied: Vec<(&str, BindSourceType, bool, bool, bool, bool)> = report
            .mounts
            .iter()
            .map(|m| {
                (
                    m.destination.as_str(),
                    m.source_kind,
                    m.read_only,
                    m.noexec,
                    m.recursive,
                    m.created_target,
                )
            })
            .collect();
        use BindSourceType::{Directory, RegularFile};
        assert_eq!(
            applied,
            vec![
                // `/data` は fixture で作ってある（作成なし）。他は宛先の末尾をこの呼び出しが作る。
                ("/data", Directory, false, false, false, false),
                ("/noexec", Directory, false, true, false, true),
                ("/ro", Directory, true, false, false, true),
                ("/etc/conf.txt", RegularFile, false, false, false, true),
                ("/rb", Directory, true, true, true, true),
                ("/nr", Directory, false, false, false, true),
            ]
        );
    }

    /// 呼び出しスレッドの mountinfo から `point` の fstype を引く。
    fn thread_fstype(point: &str) -> Option<String> {
        read_entries("/proc/thread-self/mountinfo")
            .into_iter()
            .find(|e| e.point == point)
            .map(|e| e.fstype)
    }

    /// 5. 疑似 FS・非再帰の submount・自分の ro を元にした rw・overlay の各拒否（#2064・#2120・#2298）。
    fn extra_scenarios(ctx: &Ctx<'_>) {
        // 疑似 FS は宛先を作る前に拒否される。
        for source in ["/proc", "/sys"] {
            let set = bind_set(&[(source, "/pfs/x", &["bind"])]);
            ctx.expect_violation(
                source,
                &set,
                ViolationReason::BindSourcePseudoFs,
                ErrorCode::InvalidArgument,
            );
            assert!(
                missing(&ctx.rootfs("pfs")),
                "{source}: no destination may be created"
            );
        }
        assert_eq!(
            thread_fstype("/sys/fs/cgroup").as_deref(),
            Some("cgroup2"),
            "/sys/fs/cgroup must be cgroup2 (cgroups v2 only: CORE-4)"
        );
        let set = bind_set(&[("/sys/fs/cgroup", "/pfs/x", &["bind"])]);
        ctx.expect_violation(
            "/sys/fs/cgroup",
            &set,
            ViolationReason::BindSourcePseudoFs,
            ErrorCode::InvalidArgument,
        );
        assert!(missing(&ctx.rootfs("pfs")));

        // `/dev` の rbind は、付け替えた木の中の疑似 FS（devtmpfs・devpts 等）で付け替えの後に拒否され、巻き戻る。
        let set = bind_set(&[("/dev", "/devx", &["rbind"])]);
        let err = ctx.expect_violation(
            "/dev rbind",
            &set,
            ViolationReason::BindSourcePseudoFs,
            ErrorCode::InvalidArgument,
        );
        println!(
            "bind_mounts_real: observed /dev rbind rejection: {}",
            err.message
        );
        assert!(
            missing(&ctx.rootfs("devx")),
            "the auto-created devx must be removed"
        );

        // `/dev` を非再帰で元にすると、ホストから引き継いだ配下のマウントがロックされており EINVAL になる（#2064 (a)）。
        let set = bind_set(&[("/dev", "/devx", &["bind"])]);
        ctx.expect_precondition("/dev non-recursive", &set, "use rbind");
        assert!(missing(&ctx.rootfs("devx")));

        // 自分が載せた ro のマウントを元に rw を指定すると、EPERM ではなく `specify ro` の前提不成立になる（#2064 (c)）。
        let set = bind_set(&[(&ctx.src("rootfs/ro"), "/rw_over_ro", &["bind"])]);
        ctx.expect_precondition("rw over a ro mount", &set, "specify ro");
        assert!(missing(&ctx.rootfs("rw_over_ro")));

        // overlay の merged を元にすると、層が元のディレクトリであることを確かめられず拒否される（#2298）。
        let ovl = ctx.base.join("ovl");
        let opts = format!(
            "userxattr,lowerdir={},upperdir={},workdir={}",
            path_str(&ovl.join("lower")),
            path_str(&ovl.join("upper")),
            path_str(&ovl.join("work"))
        );
        run_tool_with_deadline(
            "mount",
            &[
                "-t",
                "overlay",
                "overlay",
                "-o",
                &opts,
                path_str(&ovl.join("merged")),
            ],
        );
        let set = bind_set(&[(&ctx.src("ovl/merged"), "/ovl_merged", &["bind"])]);
        ctx.expect_precondition("an overlay merged directory", &set, "cannot be verified");
        assert!(missing(&ctx.rootfs("ovl_merged")));
        // lowerdir を元にした結果は assert しない（実装は付け替えた木が overlay のときだけ拒否すると読めるため）。
        // 観測値だけ出し、PR でオーナーの判断を仰ぐ。
        let set = bind_set(&[(&ctx.src("ovl/lower"), "/ovl_lower", &["bind"])]);
        match mount_binds(ctx.isolation, ctx.prepared, &set) {
            Ok(report) => println!(
                "bind_mounts_real: observed lowerdir bind accepted ({} mount)",
                report.mounts.len()
            ),
            Err(err) => println!(
                "bind_mounts_real: observed lowerdir bind rejected: {:?} {}",
                err.code, err.message
            ),
        }
    }

    // ---------------------------------------------------------------- pivot 後の観測

    /// `errno` を返す形で exec を試みる。実行できてしまったら失敗。標準入出力は pivot 前に開いた fd を
    /// 継承する（`Stdio::null()` は pivot 後の `/dev/null` を開こうとして、rootfs に無いと ENOENT になり、
    /// 対象ファイルの exec 由来の errno を隠すため）。
    fn exec_errno(path: &str) -> Option<i32> {
        match Command::new(path)
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
        {
            Ok(mut c) => {
                kill_and_reap(&mut c);
                panic!("{path} unexpectedly started");
            }
            Err(e) => e.raw_os_error(),
        }
    }

    /// `pivot_root` の後、コンテナ内の mountinfo と実際の操作で属性・伝播・実効を照合する。
    fn observe_after_pivot() {
        let entries = read_entries("/proc/self/mountinfo");
        let find = |point: &str| {
            entries
                .iter()
                .find(|e| e.point == point)
                .unwrap_or_else(|| panic!("{point} must be a mount point: {entries:?}"))
        };
        // (マウント先, ro か, noexec か)
        for (point, ro, noexec) in [
            ("/data", false, false),
            ("/noexec", false, true),
            ("/ro", true, false),
            ("/etc/conf.txt", false, false),
            ("/rb", true, true),
            ("/rb/sub", true, true),
            ("/nr", false, false),
        ] {
            let e = find(point);
            for want in ["nosuid", "nodev"] {
                assert!(e.has_opt(want), "{point} must be {want}: {:?}", e.opts);
            }
            assert_eq!(e.has_opt("ro"), ro, "{point} ro: {:?}", e.opts);
            assert_eq!(e.has_opt("rw"), !ro, "{point} rw: {:?}", e.opts);
            assert_eq!(e.has_opt("noexec"), noexec, "{point} noexec: {:?}", e.opts);
            assert!(e.is_private(), "{point} must be private: {:?}", e.optional);
        }
        assert!(
            entries.iter().all(|e| e.point != "/nr/sub"),
            "a non-recursive bind must not carry the submount"
        );

        // rw: コンテナ内で書いた内容は、T がホスト側の元に同じ内容で現れることを確かめる。
        std::fs::write("/data/written.txt", WRITTEN_BYTES).expect("write into the rw bind");
        // noexec: 同じバイト列の実行は EACCES、noexec でない bind では実行の前段を過ぎて ENOENT（インタプリタ無し）。
        assert_eq!(exec_errno("/noexec/prog"), Some(13), "noexec bind");
        assert_eq!(exec_errno("/data/prog"), Some(2), "plain bind control");
        // ro: 作成も既存への書き込み用の open も EROFS。
        assert_eq!(
            std::fs::File::create("/ro/new")
                .expect_err("create in ro")
                .raw_os_error(),
            Some(30)
        );
        assert_eq!(
            std::fs::OpenOptions::new()
                .append(true)
                .open("/ro/existing.txt")
                .expect_err("write open in ro")
                .raw_os_error(),
            Some(30)
        );
        // ファイルの bind。
        assert_eq!(
            std::fs::read("/etc/conf.txt").expect("read file bind"),
            FILE_BYTES
        );
        // rbind は配下の別マウントが見え、非再帰は空のディレクトリ。
        assert_eq!(
            std::fs::read("/rb/sub/marker").expect("read through rbind"),
            MARKER_BYTES
        );
        assert_eq!(
            std::fs::read_dir("/nr/sub").expect("read /nr/sub").count(),
            0
        );
        // nodev: 元に置いた文字デバイスは開けない。
        assert_eq!(
            std::fs::File::open("/data/wh")
                .expect_err("device node on nodev")
                .raw_os_error(),
            Some(13)
        );
    }
}
