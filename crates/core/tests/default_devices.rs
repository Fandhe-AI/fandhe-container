//! 基本デバイスノード作成（`fandhe_container_core::exec::create_default_devices`）の結合試験
//! （CORE-1・CORE-6・SEC-1・SEC-5・TASK-27.6・#834・#1660・#1676）。
//!
//! `harness = false` の単一スレッド `main` で動かす理由・流れは `pivot_root_isolation.rs` と同じ
//! （`Cargo.toml` の `[[test]]`）。非 Linux では `exec` モジュール自体がビルド対象外。
//!
//! # 流れ
//! - 親（root）: `proc/` と、偽ノードとして通常ファイル `dev/null` を持つ rootfs を作る。親（非 root）: `dev` を
//!   持たない rootfs（`proc/` のみ）を作る。分離（root は rootful、非 root は rootless）→ 自身を
//!   `--child <rootfs>` で起動（新しい PID namespace の PID 1）→ タイムアウト付きで終了コード 0 を待つ
//!   （REPAIR-5）。子の終了後、ホスト側の rootfs を照合する
//! - 子（root）: `establish` → `prepare_rootfs` → `create_default_devices`（1 回。`dev` に専用の tmpfs を載せて
//!   から 6 種と symlink 4 本を作る。#1653）→ `pivot_root` の後、`/dev` の mountinfo（tmpfs・`nosuid` あり・
//!   `nodev` なし）、6 種の種別・`rdev`・モード、symlink 4 本の参照先を具体値で照合する。親は、ホスト側の
//!   偽ノードが内容ごと不変で、`dev` に新エントリが増えていないことを照合する
//! - rootfs の自己 bind の `nodev`（#1676・SEC-1・CORE-1）: 親（root）は `dev` の外にも偽のデバイスノード
//!   `opt/fake-null`（c 1:3）・`root/fake-zero`（c 1:5）を `mknod` で置き、ホスト側で開けること（試験の前提。
//!   ホストの一時領域が `nodev` だと空振りするため開けなければ panic）を自己検証する。子（root）は `pivot_root` の後、
//!   この 2 個が `EACCES`（13）で開けないこと（Landlock は適用しないので `nodev` 由来）、`/dev/null` への書き込みと
//!   `/dev/zero` の 16 バイト読みが成功すること、mountinfo の `/` に `nodev` があり `/dev` に無いことを照合する。
//!   親は、子の終了後にホスト側の 2 個が同じ `rdev` の文字デバイスのまま残っていることを照合する
//! - 子（非 root）: 非特権 user namespace では文字デバイスの `mknod(2)` が `EPERM` になるため、ホストの
//!   `/dev/<名前>` を `open_tree(2)` + `move_mount(2)` で `dev` の tmpfs 上の空ファイルへ bind する
//!   （#1660。6 種すべてが `BoundFromHost`）。`pivot_root` の後、6 種の種別・`rdev`、`/dev/null` への書き込み、
//!   `/dev/zero` の 16 バイトの読み出し、mountinfo のマウントポイント 6 件、devpts に `gid=` が無いことを照合する。
//!   親は、ホスト側の `dev` が空のまま残っている（空ファイルは tmpfs 上にありホスト側には現れない）ことを照合する。
//!   rootful の `nodev`（#1676）が rootless に及ばないことは、mountinfo の `/` の `nodev` の有無が、親が
//!   ホスト側で rootfs を含むマウントについて読んだ値（`--host-nodev`）と同じであることで照合する
//!
//! # 実機前提テストとしての分離
//! root もしくは非特権 user namespace を許可するホストが必要で、GitHub ホステッド runner では
//! 保証できないため `-- --ignored` 指定時のみ実行する（ci.md「実機前提テスト」）。実行時は分離の
//! 拒否を含めあらゆる失敗を失敗として扱う。rootful 経路（root）の実行は root 権限コマンドのため
//! 明示指示のもとで行い、結果を PR に記録する。

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("default_devices: Linux only, not applicable on this OS");
}

#[cfg(target_os = "linux")]
fn main() {
    // `-- --ignored` を付けたときだけ実行する。子は `--child <rootfs>` で再入する。
    if std::env::args().any(|a| a == "--ignored" || a == "--child") {
        linux::run();
    } else {
        println!(
            "default_devices: ignored (real-machine test; run with `-- --ignored`, see AGENTS.md)"
        );
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    use fandhe_container_core::exec::{
        DeviceLinkStatus, DeviceNodeStatus, DevptsDirStatus, DevptsGidSource, IsolationConfig,
        MountIsolation, Namespace, NamespaceSet, create_default_devices, isolate,
        isolate_rootful_host_root, pivot_root, plan, plan_rootful_host_root, prepare_rootfs,
    };
    use fandhe_container_core::rootless::single_id_mapping;

    /// 期待する `(name, major, minor)`。OCI Runtime Spec の default devices（モードは全て 0666）。
    const EXPECTED: [(&str, u64, u64); 6] = [
        ("null", 1, 3),
        ("zero", 1, 5),
        ("full", 1, 7),
        ("random", 1, 8),
        ("urandom", 1, 9),
        ("tty", 5, 0),
    ];

    /// ホスト側 rootfs の `dev/null` に置く偽ノード（通常ファイル）の内容。
    const FAKE_NULL: &[u8] = b"fake-null";

    /// `dev` の外に置く偽のデバイスノード `(rootfs からの相対パス, major, minor)`（#1676）。
    const FAKE_DEVICES: [(&str, u64, u64); 2] = [("opt/fake-null", 1, 3), ("root/fake-zero", 1, 5)];

    /// coreutils の `mknod` で文字デバイスを作る（core のテストに `unsafe` を書かないため）。
    /// 子の待ちには期限を付ける（REPAIR-5）。
    fn mknod_char(path: &Path, major: u64, minor: u64) {
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
        let deadline = Instant::now() + timeout();
        loop {
            match child.try_wait().expect("try_wait") {
                Some(status) => {
                    assert_eq!(status.code(), Some(0), "mknod must succeed");
                    return;
                }
                None if Instant::now() >= deadline => {
                    kill_and_reap_bounded(&mut child);
                    panic!("mknod did not exit within {:?}", timeout());
                }
                None => std::thread::sleep(Duration::from_millis(20)),
            }
        }
    }

    /// glibc の `gnu_dev_makedev` と同じ配置（下位 8 ビットの minor と 8..20 ビットの major）。
    fn makedev(major: u64, minor: u64) -> u64 {
        (major << 8) | minor
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

    /// 親（user namespace に入る前）の実効 gid。user namespace の中では 0 に見えるため、親が子へ渡す。
    fn egid() -> u32 {
        std::fs::read_to_string("/proc/self/status")
            .expect("read status")
            .lines()
            .find(|l| l.starts_with("Gid:"))
            .and_then(|l| l.split_whitespace().nth(2).map(str::to_string))
            .and_then(|v| v.parse().ok())
            .expect("parse egid")
    }

    /// 期限超過した子を kill し、回収も有限の猶予で打ち切る（REPAIR-5）。
    /// SIGKILL は終了完了を保証せず（割り込み不能待機等）、無期限 `wait()` は
    /// 期限超過の報告に到達できなくなるため `try_wait()` をポーリングする。
    /// 回収できない場合は明示的に panic して失敗を報告する。
    fn kill_and_reap_bounded(child: &mut std::process::Child) {
        if let Err(e) = child.kill() {
            // 既に終了済みの場合などは回収確認へ進む。それ以外は回収の成否で判定する。
            eprintln!("kill failed: {e}");
        }
        let reap_deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match child.try_wait() {
                Ok(Some(_)) => return,
                Ok(None) if Instant::now() >= reap_deadline => {
                    panic!("child could not be reaped within 5s after kill");
                }
                Ok(None) => std::thread::sleep(Duration::from_millis(20)),
                Err(e) => panic!("try_wait after kill failed: {e}"),
            }
        }
    }

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
        match args.iter().position(|a| a == "--child") {
            Some(i) => {
                let rootfs = args.get(i + 1).expect("rootfs path after --child");
                // user namespace 内では写像後の euid が 0 になり is_root() で判別できないため、
                // 親が決めた rootful / rootless を引数で受け取る。
                let rootful = args.iter().any(|a| a == "--rootful");
                let egid = args
                    .iter()
                    .position(|a| a == "--egid")
                    .and_then(|j| args.get(j + 1))
                    .and_then(|v| v.parse::<u32>().ok());
                let host_nodev = args
                    .iter()
                    .position(|a| a == "--host-nodev")
                    .and_then(|j| args.get(j + 1))
                    .and_then(|v| match v.as_str() {
                        "1" => Some(true),
                        "0" => Some(false),
                        _ => None,
                    });
                child(Path::new(rootfs), rootful, egid, host_nodev);
            }
            None => parent(),
        }
    }

    /// 一時 rootfs（drop で削除）。
    struct Rootfs(PathBuf);

    impl Drop for Rootfs {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn make_rootfs() -> Rootfs {
        let base = std::fs::canonicalize(std::env::temp_dir())
            .expect("canonicalize temp_dir")
            .join(format!("fandhe-devices-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join("proc")).expect("create rootfs/proc");
        if is_root() {
            // イメージ同梱の偽ノード。tmpfs に覆い隠され、コンテナからは見えずホスト側は不変であること。
            std::fs::create_dir_all(base.join("dev")).expect("create rootfs/dev");
            std::fs::write(base.join("dev/null"), FAKE_NULL).expect("write fake node");
            // `dev` の外のデバイスノード（rootfs の自己 bind の `nodev` で開けなくなること。#1676）。
            for (rel, major, minor) in FAKE_DEVICES {
                let path = base.join(rel);
                std::fs::create_dir_all(path.parent().expect("parent")).expect("create parent");
                mknod_char(&path, major, minor);
                // 試験の前提: ホスト側（`nodev` でないマウント）では開ける。開けないなら空振りになる。
                if let Err(e) = std::fs::File::open(&path) {
                    panic!(
                        "host cannot open {}: {e}; set TMPDIR to a mount that is not nodev",
                        path.display()
                    );
                }
            }
        }
        Rootfs(base)
    }

    fn parent() {
        let rootfs = make_rootfs();
        let root = is_root();
        // user namespace に入る前にホスト側の実効 gid を控える（入った後は写像後の 0 に見える）。
        let host_egid = egid();
        // rootless の `/` の `nodev` の照合の基準（#1676）。分離の前にホストの mount namespace で読む。
        let host_nodev = host_mount_is_nodev(&rootfs.0);
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
        match result {
            Ok(_) => {
                run_child(&rootfs.0, root, host_egid, host_nodev);
                if root {
                    // 偽ノードは tmpfs に覆い隠されただけで、ホスト側は内容ごと不変・新エントリなし。
                    assert_eq!(
                        std::fs::read(rootfs.0.join("dev/null")).expect("read fake node"),
                        FAKE_NULL
                    );
                    let entries: Vec<_> = std::fs::read_dir(rootfs.0.join("dev"))
                        .expect("read host dev")
                        .map(|e| e.expect("entry").file_name())
                        .collect();
                    assert_eq!(entries, vec![std::ffi::OsString::from("null")]);
                    // ホスト側の `dev` 外のノードは変わらない。
                    for (rel, major, minor) in FAKE_DEVICES {
                        let meta =
                            std::fs::symlink_metadata(rootfs.0.join(rel)).expect("stat fake");
                        assert!(meta.file_type().is_char_device(), "{rel}");
                        assert_eq!(meta.rdev(), makedev(major, minor), "{rel} rdev");
                    }
                    println!(
                        "default_devices: /dev tmpfs, basic device nodes, default links, /dev/pts and /dev/ptmx verified; rootfs self-bind nodev verified (root=true)"
                    );
                } else {
                    // 空ファイルは子の mount namespace の tmpfs 上にあり、ホスト側の `dev` は空のまま残る。
                    let dev = rootfs.0.join("dev");
                    assert!(dev.is_dir(), "dev must exist on the host side");
                    assert_eq!(
                        std::fs::read_dir(&dev).expect("read host dev").count(),
                        0,
                        "host-side dev must stay empty"
                    );
                    println!(
                        "default_devices: rootless basic device nodes bound from host, default links, /dev/pts and /dev/ptmx verified; rootfs nodev unchanged (root=false)"
                    );
                }
            }
            Err(err) => panic!("isolate failed: {err}"),
        }
    }

    /// ホストの mount namespace で、`path` を含むマウント（mountinfo のマウントポイントが `path` の最長の
    /// 祖先。同じマウントポイントに重なるときは後の行）のマウント単位のオプションに `nodev` があるか（#1676）。
    /// mountinfo のマウントポイントは空白等を 8 進でエスケープするため戻してから比べる。
    fn host_mount_is_nodev(path: &Path) -> bool {
        let mountinfo = std::fs::read_to_string("/proc/self/mountinfo").expect("read mountinfo");
        let mut best: Option<(usize, bool)> = None;
        for line in mountinfo.lines() {
            let fields: Vec<_> = line.split_whitespace().collect();
            let (Some(point), Some(options)) = (fields.get(4), fields.get(5)) else {
                panic!("malformed mountinfo line: {line}");
            };
            let point = PathBuf::from(unescape_mountinfo(point));
            if !path.starts_with(&point) {
                continue;
            }
            let depth = point.components().count();
            if best.is_none_or(|(d, _)| depth >= d) {
                best = Some((depth, options.split(',').any(|o| o == "nodev")));
            }
        }
        best.expect("a mount containing the rootfs").1
    }

    /// mountinfo の 8 進エスケープ（`\040` 等）を戻す。
    fn unescape_mountinfo(field: &str) -> String {
        let bytes = field.as_bytes();
        let mut out = Vec::with_capacity(bytes.len());
        let mut i = 0;
        while i < bytes.len() {
            match (bytes.get(i), bytes.get(i + 1..i + 4)) {
                (Some(b'\\'), Some(oct)) if oct.iter().all(|b| (b'0'..=b'7').contains(b)) => {
                    let v = oct
                        .iter()
                        .fold(0u32, |acc, b| acc * 8 + u32::from(b - b'0'));
                    out.push(u8::try_from(v).expect("octal escape fits in a byte"));
                    i += 4;
                }
                (Some(&b), _) => {
                    out.push(b);
                    i += 1;
                }
                (None, _) => break,
            }
        }
        String::from_utf8(out).expect("utf-8 mount point")
    }

    /// 自身を `--child <rootfs>` で起動する。分離後の最初の子なので新しい PID namespace の PID 1 になる。
    fn run_child(rootfs: &Path, rootful: bool, host_egid: u32, host_nodev: bool) {
        let exe = std::env::current_exe().expect("current_exe");
        let mut child = Command::new(exe)
            .arg("--child")
            .arg(rootfs)
            .arg(if rootful { "--rootful" } else { "--rootless" })
            .arg("--egid")
            .arg(host_egid.to_string())
            .arg("--host-nodev")
            .arg(if host_nodev { "1" } else { "0" })
            .stdin(Stdio::null())
            .spawn()
            .expect("spawn child");
        let deadline = Instant::now() + timeout();
        loop {
            match child.try_wait().expect("try_wait") {
                Some(status) => {
                    assert_eq!(status.code(), Some(0), "child must exit with 0");
                    return;
                }
                None if Instant::now() >= deadline => {
                    kill_and_reap_bounded(&mut child);
                    panic!("child did not exit within {:?}", timeout());
                }
                None => std::thread::sleep(Duration::from_millis(20)),
            }
        }
    }

    fn child(rootfs: &Path, rootful: bool, egid: Option<u32>, host_nodev: Option<bool>) {
        assert_eq!(
            std::process::id(),
            1,
            "child must be PID 1 of the new PID namespace"
        );
        let isolation = MountIsolation::establish().expect("establish mount isolation");
        let prepared = prepare_rootfs(&isolation, rootfs).expect("prepare rootfs");

        // 単一 ID 経路の gid の写像（自 gid → コンテナ内 0）。コンテナ内 gid 5 は写像されない。
        let gid_map;
        let source = if rootful {
            DevptsGidSource::Rootful
        } else {
            gid_map = single_id_mapping(egid.expect("--egid for rootless child"))
                .expect("single id mapping");
            DevptsGidSource::Rootless(&gid_map)
        };
        // 1 回だけ呼ぶ（同じ PreparedRootfs への 2 回目は tmpfs が重なるため契約外）。
        let first = create_default_devices(&isolation, &prepared, source).expect("create devices");
        assert_eq!(first.nodes.len(), 6);
        let expected_status = if rootful {
            DeviceNodeStatus::Created
        } else {
            DeviceNodeStatus::BoundFromHost
        };
        for (n, (name, major, minor)) in first.nodes.iter().zip(EXPECTED) {
            assert_eq!(
                (n.name, u64::from(n.major), u64::from(n.minor), n.mode),
                (name, major, minor, 0o666)
            );
            assert_eq!(n.status, expected_status, "{name}");
        }
        assert_eq!(first.links.len(), 4);
        assert!(
            first
                .links
                .iter()
                .all(|l| l.status == DeviceLinkStatus::Created)
        );
        // gid 5 が写像されない rootless の devpts は `gid=` を渡さない（判断 3）。
        assert_eq!(first.devpts.gid, if rootful { Some(5) } else { None });
        assert_eq!(first.devpts.pts_dir, DevptsDirStatus::Created);
        assert_eq!(first.devpts.ptmx.status, DeviceLinkStatus::Created);

        pivot_root(&isolation, prepared).expect("pivot_root");

        // `/dev` は専用の tmpfs。rootful は `nosuid` あり・`nodev` なしまで照合する（rootless の user namespace
        // が載せたマウントのフラグはカーネルの扱いに依存するため、種別だけを照合する）。
        let mountinfo = std::fs::read_to_string("/proc/self/mountinfo").expect("read mountinfo");
        let dev_lines: Vec<_> = mountinfo
            .lines()
            .filter(|l| l.split_whitespace().nth(4) == Some("/dev"))
            .collect();
        assert_eq!(dev_lines.len(), 1, "exactly one mount at /dev");
        let fields: Vec<_> = dev_lines[0].split_whitespace().collect();
        let options: Vec<_> = fields[5].split(',').collect();
        let sep = fields.iter().position(|f| *f == "-").expect("separator");
        assert_eq!(fields[sep + 1], "tmpfs", "{}", dev_lines[0]);
        if rootful {
            assert!(options.contains(&"nosuid"), "{}", dev_lines[0]);
            assert!(!options.contains(&"nodev"), "{}", dev_lines[0]);
        }

        for (name, major, minor) in EXPECTED {
            let path = format!("/dev/{name}");
            let meta = std::fs::symlink_metadata(&path).expect("stat device node");
            assert!(
                meta.file_type().is_char_device(),
                "{path} must be a char device"
            );
            assert_eq!(meta.rdev(), makedev(major, minor), "{path} rdev");
            // bind したホストのノードの所有者ではないためモードは補正できず、ホスト側の値が見える。
            if rootful {
                assert_eq!(meta.mode() & 0o7777, 0o666, "{path} mode");
            }
        }
        if !rootful {
            verify_bound_nodes(&mountinfo);
        }
        for (name, target) in [
            ("fd", "/proc/self/fd"),
            ("stdin", "/proc/self/fd/0"),
            ("stdout", "/proc/self/fd/1"),
            ("stderr", "/proc/self/fd/2"),
        ] {
            let path = format!("/dev/{name}");
            assert_eq!(
                std::fs::read_link(&path).expect("readlink"),
                std::path::PathBuf::from(target),
                "{path} target"
            );
        }

        verify_devpts(rootful);
        if rootful {
            verify_rootfs_nodev();
        } else {
            verify_rootless_rootfs_nodev_unchanged(
                host_nodev.expect("--host-nodev for rootless child"),
            );
        }
    }

    /// `/dev/null` へ書き込めて、`/dev/zero` から読んだ 16 バイトがすべて 0 であること（rootful の作成・
    /// rootless の bind の双方で、`nodev` 相当で拒まれずにノードを実際に使えること。#1660・#1676）。
    fn verify_null_zero_usable() {
        use std::io::{Read as _, Write as _};

        std::fs::OpenOptions::new()
            .write(true)
            .open("/dev/null")
            .expect("open /dev/null for write")
            .write_all(b"discarded")
            .expect("write /dev/null");
        let mut zeros = [0xffu8; 16];
        std::fs::File::open("/dev/zero")
            .expect("open /dev/zero")
            .read_exact(&mut zeros)
            .expect("read /dev/zero");
        assert_eq!(zeros, [0u8; 16], "/dev/zero must read 16 zero bytes");
    }

    /// pivot 後のマウントポイント `target` のマウント単位のオプション（mountinfo の 6 列目）。ちょうど 1 件を要求する。
    fn mount_options_at(mountinfo: &str, target: &str) -> Vec<String> {
        let lines: Vec<_> = mountinfo
            .lines()
            .filter(|l| l.split_whitespace().nth(4) == Some(target))
            .collect();
        assert_eq!(lines.len(), 1, "exactly one mount at {target}");
        lines[0]
            .split_whitespace()
            .nth(5)
            .expect("options")
            .split(',')
            .map(str::to_string)
            .collect()
    }

    /// pivot 後の rootfs の `nodev`（#1676。SEC-1・CORE-1）。Landlock は適用していないため、`EACCES` は
    /// `nodev` 由来。`/dev` の既定ノードは専用の tmpfs 上にあるので使える。
    fn verify_rootfs_nodev() {
        const EACCES: i32 = 13;
        for (rel, _, _) in FAKE_DEVICES {
            let err = std::fs::File::open(format!("/{rel}")).expect_err("must not open on nodev");
            assert_eq!(err.raw_os_error(), Some(EACCES), "/{rel}");
        }
        verify_null_zero_usable();

        let mountinfo = std::fs::read_to_string("/proc/self/mountinfo").expect("read mountinfo");
        assert!(
            mount_options_at(&mountinfo, "/")
                .iter()
                .any(|o| o == "nodev"),
            "/ must be nodev"
        );
        assert!(
            !mount_options_at(&mountinfo, "/dev")
                .iter()
                .any(|o| o == "nodev"),
            "/dev must not be nodev"
        );
    }

    /// rootless では `prepare_rootfs` が `nodev` を足さない（#1676 は rootful 限定。CORE-6・SEC-5）。自己 bind は
    /// 元のマウントのフラグを引き継ぐため、`/` の `nodev` の有無はホスト側で rootfs を含むマウントと同じになる。
    fn verify_rootless_rootfs_nodev_unchanged(host_nodev: bool) {
        let mountinfo = std::fs::read_to_string("/proc/self/mountinfo").expect("read mountinfo");
        assert_eq!(
            mount_options_at(&mountinfo, "/")
                .iter()
                .any(|o| o == "nodev"),
            host_nodev,
            "rootless / must keep the nodev flag of the host-side mount"
        );
    }

    /// rootless の bind で供給したノードの実使用と、bind が 6 件ちょうどであることの照合（#1660。CORE-6・SEC-5）。
    fn verify_bound_nodes(mountinfo: &str) {
        // 書き込める（ホストの devtmpfs の superblock を保つため `nodev` 相当で拒まれない）。
        verify_null_zero_usable();
        // マウントポイントが基本デバイス 6 種の名前である行がちょうど 6 件（fs 種別はホスト依存のため照合しない）。
        let mut points: Vec<_> = mountinfo
            .lines()
            .filter_map(|l| l.split_whitespace().nth(4))
            .filter(|p| EXPECTED.iter().any(|(n, _, _)| *p == format!("/dev/{n}")))
            .collect();
        points.sort_unstable();
        let mut want: Vec<_> = EXPECTED
            .iter()
            .map(|(n, _, _)| format!("/dev/{n}"))
            .collect();
        want.sort_unstable();
        assert_eq!(points, want, "exactly one bind mount per basic device node");
    }

    /// pivot 後の `/dev/pts`（独立した devpts）と `/dev/ptmx` の照合（#1656。CORE-1・SEC-1）。
    fn verify_devpts(rootful: bool) {
        use std::os::unix::fs::OpenOptionsExt as _;

        let mountinfo = std::fs::read_to_string("/proc/self/mountinfo").expect("read mountinfo");
        let pts_lines: Vec<_> = mountinfo
            .lines()
            .filter(|l| l.split_whitespace().nth(4) == Some("/dev/pts"))
            .collect();
        assert_eq!(pts_lines.len(), 1, "exactly one mount at /dev/pts");
        let fields: Vec<_> = pts_lines[0].split_whitespace().collect();
        let options: Vec<_> = fields[5].split(',').collect();
        assert!(options.contains(&"nosuid"), "{}", pts_lines[0]);
        assert!(options.contains(&"noexec"), "{}", pts_lines[0]);
        // pty は文字デバイスのため nodev を付けない。
        assert!(!options.contains(&"nodev"), "{}", pts_lines[0]);
        let sep = fields.iter().position(|f| *f == "-").expect("separator");
        assert_eq!(fields[sep + 1], "devpts", "{}", pts_lines[0]);
        let super_options: Vec<_> = fields[sep + 3].split(',').collect();
        for want in ["mode=620", "ptmxmode=666"] {
            assert!(super_options.contains(&want), "{want}: {}", pts_lines[0]);
        }
        if rootful {
            assert!(super_options.contains(&"gid=5"), "{}", pts_lines[0]);
        } else {
            // gid 5 が写像されない rootless は `gid=` を渡さない（判断 3。#1656 の実機照合）。
            assert!(
                !super_options.iter().any(|o| o.starts_with("gid=")),
                "{}",
                pts_lines[0]
            );
        }

        // ホストの pty が見えない独立 instance なので、開く前のエントリは `ptmx` だけ。
        let entries: Vec<_> = std::fs::read_dir("/dev/pts")
            .expect("read /dev/pts")
            .map(|e| e.expect("entry").file_name())
            .collect();
        assert_eq!(entries, vec![std::ffi::OsString::from("ptmx")]);

        assert_eq!(
            std::fs::read_link("/dev/ptmx").expect("readlink /dev/ptmx"),
            std::path::PathBuf::from("pts/ptmx")
        );
        let meta = std::fs::metadata("/dev/pts/ptmx").expect("stat /dev/pts/ptmx");
        assert!(meta.file_type().is_char_device());
        assert_eq!(meta.rdev(), makedev(5, 2), "/dev/pts/ptmx rdev");

        // `O_NOCTTY`（0o400）で開けること（libc の依存を足さないため定数をここで定義する）。
        const O_NOCTTY: i32 = 0o400;
        let master = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(O_NOCTTY)
            .open("/dev/ptmx")
            .expect("open /dev/ptmx");
        drop(master);
    }
}
