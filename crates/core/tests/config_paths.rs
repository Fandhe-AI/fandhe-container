//! config の `linux.maskedPaths` / `readonlyPaths` が固定集合に追加されて適用されることの結合試験
//! （SEC-2・CORE-1・CORE-5・OCI-4・TASK-29 追補・#1852）。
//!
//! `harness = false` の単一スレッド `main` で動かす理由は `default_devices.rs` と同じ（`Cargo.toml` の `[[test]]`）。
//! 非 Linux では `exec` モジュール自体がビルド対象外。
//!
//! # 流れ
//! - 親: 利用者所有の rootfs に、`/data/secret.txt`（覆うファイル）・`/data/dir`（覆うディレクトリ。中にファイル）・
//!   `/rofile/file`（読み取り専用にするディレクトリ内のファイル）・`/rodir` を作る。`/proc` は実 procfs が載るため、
//!   config の指定は `/proc` 外のこれらに置く。存在しない `/absent` も指定し、飛ばされること（起動が止まらないこと）を
//!   確かめる。分離 -> `spawn_container_probe_with_config_paths`（`setup` 付き。固定集合 + config を本番と同じ順序で
//!   適用）-> 子をタイムアウト付きで待つ（REPAIR-5）。
//! - 子（pivot 後）: 読んだ長さ・`readdir` の件数・書き込み系 `open` の errno を pipe へ `key=value` で書き、`ready` を
//!   書いたら親が許すまで待つ。親は `/proc/<子の PID>/mountinfo` で種別と per-mount options を照合する。
//!
//! # 期待値
//! - 覆うファイル: 読むと 0 バイト。覆うディレクトリ: 空で `tmpfs`・`ro,nosuid,nodev,noexec`、作成 `open` は `EROFS`
//! - 読み取り専用にした `/rodir`: 作成 `open` は `EROFS`、mountinfo に `ro`。`/rofile` 内のファイルは読めるが
//!   書き込み `open` は `EROFS`
//! - 固定集合は引き続き適用される（`/proc/sys` が `ro` のマウントポイント）。`/absent` 等はマウントポイントにならない
//! - rootless は rootful と同じ期待を要求する（弱めない）
//!
//! # 実機前提テストとしての分離
//! Linux 5.12 以降で root もしくは非特権 user namespace を許可するホストが必要。`-- --ignored` 指定時のみ実行する
//! （ci.md「実機前提テスト」。AGENTS.md）。rootful 経路（root）の実行は root 権限コマンドのため明示指示のもとで行う。
//!
//! # fork 子で観測する理由（#2630・CORE-5・REPAIR-3）
//! `spawn_container_probe` 系を使い続け、exec 後のエントリポイント内の観測へは移さない。
//! - 識別性: 観測するのは mountinfo の最上位のマウント・fstype・`ro` などのフラグ・覆ったファイルの内容・書き込み用
//!   `open` の errno で、いずれもマウントの状態で決まる。マウントの状態は execve をまたいで変わらないため、fork 子で
//!   観測しても exec 後の PID 1 と同じ結果になる。exec 経路は Landlock が必須で `EACCES` の発生源が増えるため、
//!   Landlock を載せない fork 子のほうが拒否の理由を識別しやすい
//! - 移せない事情: exec 経路の試験用入口（`spawn_container_with_stages_and_devices`）は `devices` しか渡せず、
//!   `config_paths` / `sysfs` を受け取らない。本試験は `platform-ci` の `--ignored` 対象でもなく、移行後の観測を CI で
//!   確かめる手段が無い
//! - 移す条件（後続）: `config_paths` / `sysfs` を受け取る exec 経路の入口と `platform-ci` への登録を同じ変更で入れる

#[cfg(target_os = "linux")]
#[path = "support/temp_rootfs.rs"]
mod temp_rootfs;

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("config_paths: Linux only, not applicable on this OS");
}

#[cfg(target_os = "linux")]
fn main() {
    if std::env::args().any(|a| a == "--ignored") {
        linux::run();
    } else {
        println!(
            "config_paths: ignored (real-machine test; run with `-- --ignored`, see AGENTS.md)"
        );
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use crate::temp_rootfs;
    use std::io::{Read as _, Write as _};
    use std::path::PathBuf;
    use std::time::Duration;

    use fandhe_container_core::exec::{
        ChildExit, DevptsGidSource, IsolationConfig, Namespace, NamespaceSet, StagePipeline,
        isolate, isolate_rootful_host_root, plan, plan_rootful_host_root,
        spawn_container_probe_with_config_paths,
    };
    use fandhe_container_core::rootless::single_id_mapping;

    /// `EROFS`（x86_64・aarch64 とも同値）。
    const EROFS: i32 = 30;
    /// フィクスチャの中身（覆われれば読めない）。
    const SECRET: &[u8] = b"fandhe-config-secret";

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

    fn make_rootfs() -> Rootfs {
        // 共有 /tmp 上の推測可能なパスを再利用しない。時刻由来の名前で `create_dir` して排他的に作る（SEC-2）。
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        let base = std::fs::canonicalize(std::env::temp_dir())
            .expect("canonicalize temp_dir")
            .join(format!(
                "fandhe-config-paths-{}-{nanos}",
                std::process::id()
            ));
        std::fs::create_dir(&base).expect("exclusively create rootfs dir");
        let rootfs = Rootfs(base.clone());
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o755))
                .expect("chmod rootfs dir");
        }
        temp_rootfs::create_dir_chain(&base, &["data", "dir"]);
        std::fs::write(base.join("data/secret.txt"), SECRET).expect("create secret");
        std::fs::write(base.join("data/dir/inner"), SECRET).expect("create inner");
        temp_rootfs::create_dir_chain(&base, &["rofile"]);
        std::fs::write(base.join("rofile/file"), SECRET).expect("create rofile/file");
        temp_rootfs::create_dir_chain(&base, &["rodir"]);
        // `prepare_rootfs` は rootfs/proc の存在を必須とし自動作成しない（open_proc_dir が拒否する）ため用意する。
        temp_rootfs::create_dir_chain(&base, &["proc"]);
        rootfs
    }

    /// マウントポイント `target` の mountinfo 行の (per-mount options, fstype)。
    fn mount_entry(mountinfo: &str, target: &str) -> Option<(Vec<String>, String)> {
        mountinfo.lines().find_map(|l| {
            let f: Vec<&str> = l.split(' ').collect();
            if f.get(4) != Some(&target) {
                return None;
            }
            let opts = f.get(5)?.split(',').map(str::to_string).collect();
            let dash = f.iter().position(|x| *x == "-")?;
            Some((opts, f.get(dash + 1)?.to_string()))
        })
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
    fn observe(mut writer: std::io::PipeWriter, mut gate: std::io::PipeReader) {
        let len = std::fs::read("/data/secret.txt").map(|b| b.len().to_string());
        writeln!(writer, "secret_len={len:?}").expect("write");
        let n = std::fs::read_dir("/data/dir").map(|d| d.count().to_string());
        writeln!(writer, "dir_entries={n:?}").expect("write");
        writeln!(
            writer,
            "dir_create_errno={}",
            create_errno("/data/dir/probe")
        )
        .expect("write");
        writeln!(
            writer,
            "rodir_create_errno={}",
            create_errno("/rodir/probe")
        )
        .expect("write");
        let ro_read = std::fs::read("/rofile/file").map(|b| b == SECRET);
        writeln!(writer, "rofile_read={ro_read:?}").expect("write");
        let write_err = std::fs::OpenOptions::new()
            .write(true)
            .open("/rofile/file")
            .err()
            .and_then(|e| e.raw_os_error())
            .unwrap_or(0);
        writeln!(writer, "rofile_write_errno={write_err}").expect("write");
        writeln!(writer, "ready").expect("write");
        // fork で子にも親の書き込み端が複製されるため、EOF は当てにせず解放バイトを待つ。
        let mut release = [0u8; 1];
        let _ = gate.read_exact(&mut release);
    }

    pub fn run() {
        let rootfs = make_rootfs();
        let root = is_root();
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
        result.unwrap_or_else(|err| panic!("isolate failed: {err}"));

        let gid_map;
        let devices = if root {
            DevptsGidSource::Rootful
        } else {
            gid_map = single_id_mapping(egid).expect("single id mapping");
            DevptsGidSource::Rootless(&gid_map)
        };
        let (reader, writer) = std::io::pipe().expect("create pipe");
        let (gate_reader, gate_writer) = std::io::pipe().expect("create gate pipe");
        let child = spawn_container_probe_with_config_paths(
            &rootfs.0,
            StagePipeline::new(),
            devices,
            &["/rodir", "/rofile", "/absent-ro"],
            &["/data/secret.txt", "/data/dir", "/absent"],
            move || observe(writer, gate_reader),
        )
        .unwrap_or_else(|e| panic!("spawn: {e}"));
        let kill = |why: &str| -> ! {
            let _ = child.kill_and_reap(Duration::from_secs(5));
            panic!("{why}")
        };
        // 子の `ready` までを別スレッドで読み、期限付きで待つ（子が前段で失敗すれば EOF で戻る）。
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
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
            let _ = tx.send(text);
        });
        let text = rx
            .recv_timeout(timeout())
            .unwrap_or_else(|_| kill("the child did not report within the timeout"));
        if !text.lines().any(|l| l == "ready") {
            let exit = child.wait_timeout(timeout());
            panic!("the child failed before ready: {exit:?}\n{text}");
        }
        let mountinfo = std::fs::read_to_string(format!("/proc/{}/mountinfo", child.pid()))
            .unwrap_or_else(|e| kill(&format!("read the child's mountinfo: {e}")));
        let mut gate_writer = gate_writer;
        gate_writer.write_all(&[1]).expect("release the child");
        drop(gate_writer);
        let exit = child.wait_timeout(timeout()).unwrap_or_else(|e| {
            let _ = child.kill_and_reap(Duration::from_secs(5));
            panic!("wait: {e}")
        });
        assert!(
            matches!(exit, ChildExit::Exited(0)),
            "child must exit with 0, got {exit:?}"
        );
        verify(&text, &mountinfo);
        // ホスト側 rootfs の内容は不変。
        assert_eq!(
            std::fs::read(rootfs.0.join("data/secret.txt")).expect("read"),
            SECRET
        );
        assert_eq!(
            std::fs::read(rootfs.0.join("data/dir/inner")).expect("read"),
            SECRET
        );
        println!(
            "config_paths: config masked/readonly paths applied on top of the fixed set (root={root})"
        );
    }

    fn lookup<'a>(text: &'a str, key: &str) -> &'a str {
        text.lines()
            .find_map(|l| l.strip_prefix(&format!("{key}=")))
            .unwrap_or_else(|| panic!("missing observation {key}:\n{text}"))
    }

    fn opts_of(entry: &(Vec<String>, String)) -> Vec<&str> {
        entry.0.iter().map(String::as_str).collect()
    }

    fn verify(text: &str, mountinfo: &str) {
        assert_eq!(
            lookup(text, "secret_len"),
            "Ok(\"0\")",
            "masked file must read as 0 bytes"
        );
        assert_eq!(
            lookup(text, "dir_entries"),
            "Ok(\"0\")",
            "masked dir must be empty"
        );
        assert_eq!(lookup(text, "dir_create_errno"), EROFS.to_string());
        assert_eq!(lookup(text, "rodir_create_errno"), EROFS.to_string());
        assert_eq!(lookup(text, "rofile_read"), "Ok(true)");
        assert_eq!(lookup(text, "rofile_write_errno"), EROFS.to_string());

        let dir = mount_entry(mountinfo, "/data/dir")
            .unwrap_or_else(|| panic!("/data/dir must be a mount point:\n{mountinfo}"));
        assert_eq!(dir.1, "tmpfs");
        for o in ["ro", "nosuid", "nodev", "noexec"] {
            assert!(
                opts_of(&dir).contains(&o),
                "/data/dir must have {o}: {dir:?}"
            );
        }
        let file = mount_entry(mountinfo, "/data/secret.txt")
            .unwrap_or_else(|| panic!("/data/secret.txt must be a mount point:\n{mountinfo}"));
        assert!(!opts_of(&file).contains(&"nodev"), "{file:?}");
        let rodir = mount_entry(mountinfo, "/rodir")
            .unwrap_or_else(|| panic!("/rodir must be a mount point:\n{mountinfo}"));
        assert!(opts_of(&rodir).contains(&"ro"), "{rodir:?}");
        // 固定集合は引き続き適用される。存在しない指定は飛ばされる。
        let sys = mount_entry(mountinfo, "/proc/sys").map(|e| opts_of(&e).contains(&"ro"));
        assert_eq!(
            sys,
            Some(true),
            "/proc/sys must stay a read-only mount point"
        );
        for absent in ["/absent", "/absent-ro"] {
            assert!(mount_entry(mountinfo, absent).is_none(), "{absent}");
        }
    }
}
