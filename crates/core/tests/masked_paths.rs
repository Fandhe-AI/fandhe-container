//! 覆うパスの固定集合（`/proc` 配下の 10 件）の結合試験
//! （SEC-2・CORE-1・CORE-5・SEC-5・TASK-29 追補・#1851）。
//!
//! `harness = false` の単一スレッド `main` で動かす理由は `default_devices.rs` と同じ（`Cargo.toml` の `[[test]]`）。
//! 非 Linux では `exec` モジュール自体がビルド対象外。
//!
//! # 流れ
//! - 親: 利用者所有のフィクスチャを持つ rootfs を作る。`proc/` には対象 10 件に対応する中身つきのファイル（`secret`）と
//!   ディレクトリ（中にファイルを持つ）、読み取り専用化側の `proc/sys` を置く。ただし `spawn_container_probe_with_devices`
//!   は `prepare_rootfs` で `rootfs/proc` に実 procfs をマウントするため、子から見える対象は実カーネルの `/proc` で
//!   あり、フィクスチャは隠れる（ホスト側で不変かの確認にだけ使う）。対象の有無はカーネル依存（例: `timer_stats` が無い
//!   カーネルでは実装は正常に不在として飛ばす）なので、子が各対象の有無を観測し、存在する対象にだけ期待値を要求する。分離（root は rootful、非 root は rootless）→ `spawn_container_probe_with_devices`
//!   （`setup` 付き。`create_default_devices` → `readonly_paths` → `masked_paths` を本番と同じ順序で適用）→
//!   子をタイムアウト付きで待つ（REPAIR-5）。
//! - 子（pivot 後。新しい PID namespace の PID 1）: コンテナ内から確かめられる観測値（読んだ長さ・`readdir` の件数・
//!   作成 `open` の errno・対象の有無）を pipe へ `key=value` の行で書き、`ready` を書いたら親が許すまで待つ。
//!   子の `/proc` は覆いの後の状態で、子は mountinfo を読まない。
//! - 親は `ready` を受けたら `/proc/<子の PID>/mountinfo`（子の mount namespace・root から見た経路）を読んで
//!   マウントの種別・per-mount options を照合し、続けて子を解放して終了を待つ。ホスト側 rootfs に副作用が無い
//!   （フィクスチャの内容不変）ことも確かめる。
//!
//! # 期待値
//! 実 procfs 上で存在する対象にだけ次を要求し、不在の対象は mountinfo にマウントポイントが無いことだけを確かめる
//! （最低 1 件は存在して覆われていること）。
//! - ファイルの対象: 読むと 0 バイト。mountinfo にマウントポイントが現れ、`nodev` は付かない（付くと開けない）
//! - ディレクトリの対象: 空（`readdir` が 0 件）。mountinfo に `tmpfs` と `ro`・`nosuid`・`nodev`・`noexec` があり、
//!   中への作成 `open(O_CREAT|O_WRONLY)` は `EROFS`（30）で拒否される
//! - 読み取り専用化側（`proc/sys`）は引き続き `ro` のマウントポイント（順序の回帰検査）
//! - rootless は rootful と同じ期待を要求する（弱めない）。差が出た場合は実機結果を踏まえて理由を記録する
//!
//! # 実機前提テストとしての分離
//! Linux 5.12 以降（`open_tree`・`move_mount`・`mount_setattr`）で、root もしくは非特権 user namespace を許可する
//! ホストが必要。GitHub ホステッド runner では保証できないため `-- --ignored` 指定時のみ実行する
//! （ci.md「実機前提テスト」）。rootful 経路（root）の実行は root 権限コマンドのため明示指示のもとで行い、結果を
//! #1621 へ記録する。

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("masked_paths: Linux only, not applicable on this OS");
}

#[cfg(target_os = "linux")]
fn main() {
    if std::env::args().any(|a| a == "--ignored") {
        linux::run();
    } else {
        println!(
            "masked_paths: ignored (real-machine test; run with `-- --ignored`, see AGENTS.md)"
        );
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::io::{Read as _, Write as _};
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    use fandhe_container_core::exec::{
        ChildExit, DevptsGidSource, IsolationConfig, Namespace, NamespaceSet, StagePipeline,
        isolate, isolate_rootful_host_root, plan, plan_rootful_host_root,
        spawn_container_probe_with_devices,
    };
    use fandhe_container_core::path_masks::{
        MASKED_PROC_PATHS, MaskMethod, TargetKind, mask_method,
    };
    use fandhe_container_core::rootless::single_id_mapping;

    /// `EROFS`（x86_64・aarch64 とも同値）。
    const EROFS: i32 = 30;
    /// フィクスチャの中身（覆われれば読めない）。
    const SECRET: &[u8] = b"fandhe-masked-secret";

    /// ディレクトリとして用意する対象（それ以外はファイル）。実 `/proc` の種別と同じ。
    const DIR_TARGETS: [&str; 3] = ["/proc/acpi", "/proc/asound", "/proc/scsi"];

    fn is_dir_target(p: &str) -> bool {
        DIR_TARGETS.contains(&p)
    }

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
        let base = std::fs::canonicalize(std::env::temp_dir())
            .expect("canonicalize temp_dir")
            .join(format!("fandhe-masked-paths-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join("proc/sys")).expect("create rootfs/proc/sys");
        for t in MASKED_PROC_PATHS {
            let host = base.join(t.trim_start_matches('/'));
            if is_dir_target(t) {
                std::fs::create_dir_all(&host).expect("create dir target");
                std::fs::write(host.join("inner"), SECRET).expect("create inner file");
            } else {
                std::fs::write(&host, SECRET).expect("create file target");
            }
        }
        Rootfs(base)
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

    /// 子（コンテナ内）の観測。結果は `writer` へ 1 行ずつ書き、最後に `ready` を書いて `gate` が閉じられる（親が
    /// mountinfo を読み終えて解放バイトを送る）まで待つ。待ちは親の `wait_timeout` が上限になる（REPAIR-5）。
    fn observe(mut writer: std::io::PipeWriter, mut gate: std::io::PipeReader) {
        for t in MASKED_PROC_PATHS {
            // 実 procfs では対象の有無がカーネル依存。不在なら以降の観測を省く。
            let present = std::fs::symlink_metadata(t).is_ok();
            writeln!(writer, "present:{t}={present}").expect("write");
            if !present {
                continue;
            }
            if is_dir_target(t) {
                let count = std::fs::read_dir(t).map(|d| d.count().to_string());
                writeln!(writer, "dir_entries:{t}={count:?}").expect("write");
                // 作成の open（読み取り専用 tmpfs の上なのでホストへは作用しない）。
                let create = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(format!("{t}/probe"));
                let errno = create.err().and_then(|e| e.raw_os_error()).unwrap_or(0);
                writeln!(writer, "create_errno:{t}={errno}").expect("write");
            } else {
                let read = std::fs::read(t).map(|b| b.len().to_string());
                writeln!(writer, "file_len:{t}={read:?}").expect("write");
            }
        }
        writeln!(writer, "ready").expect("write");
        // 親が解放バイトを送るまで待つ。fork で子にも親の書き込み端が複製されるため、EOF は当てにしない。
        let mut release = [0u8; 1];
        let _ = gate.read_exact(&mut release);
    }

    pub fn run() {
        let rootfs = make_rootfs();
        let root = is_root();
        // 親（user namespace に入る前）の実効 gid。rootless の devpts の `gid=` 決定に使う。
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
        let child = spawn_container_probe_with_devices(
            &rootfs.0,
            StagePipeline::new(),
            devices,
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
        // 子を解放して終了を待つ。
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
        let (applied, absent) = verify(&text, &mountinfo);
        verify_host_untouched(&rootfs.0);
        println!(
            "masked_paths: {applied} /proc entries masked, {absent} absent on this kernel (files read as 0 bytes, dirs empty and EROFS on create) (root={root})"
        );
    }

    fn lookup<'a>(text: &'a str, key: &str) -> &'a str {
        text.lines()
            .find_map(|l| l.strip_prefix(&format!("{key}=")))
            .unwrap_or_else(|| panic!("missing observation {key}:\n{text}"))
    }

    /// 検証した（存在して覆われていた）対象の件数と、不在で飛ばした件数。
    fn verify(text: &str, mountinfo: &str) -> (usize, usize) {
        let (mut applied, mut absent) = (0, 0);
        for t in MASKED_PROC_PATHS {
            if lookup(text, &format!("present:{t}")) != "true" {
                assert!(
                    mount_entry(mountinfo, t).is_none(),
                    "{t} is absent on this kernel and must not become a mount point:\n{mountinfo}"
                );
                absent += 1;
                continue;
            }
            applied += 1;
            let kind = if is_dir_target(t) {
                TargetKind::Dir
            } else {
                TargetKind::File
            };
            let method = mask_method(kind).expect("mask method");
            let (opts, fstype) = mount_entry(mountinfo, t)
                .unwrap_or_else(|| panic!("{t} must be a mount point:\n{mountinfo}"));
            let opts: Vec<&str> = opts.iter().map(String::as_str).collect();
            match method {
                MaskMethod::BindDevNull => {
                    assert_eq!(
                        lookup(text, &format!("file_len:{t}")),
                        "Ok(\"0\")",
                        "{t} must read as 0 bytes"
                    );
                    assert!(
                        !opts.contains(&"nodev"),
                        "{t} must not be nodev (the device node must stay openable): {opts:?}"
                    );
                }
                MaskMethod::EmptyTmpfs => {
                    assert_eq!(
                        lookup(text, &format!("dir_entries:{t}")),
                        "Ok(\"0\")",
                        "{t} must be empty"
                    );
                    assert_eq!(fstype, "tmpfs", "{t}");
                    for o in ["ro", "nosuid", "nodev", "noexec"] {
                        assert!(opts.contains(&o), "{t} must have {o}: {opts:?}");
                    }
                    assert_eq!(
                        lookup(text, &format!("create_errno:{t}")),
                        EROFS.to_string(),
                        "creating a file under {t} must be refused with EROFS"
                    );
                }
                other => panic!("unexpected mask method {other:?}"),
            }
        }
        // 読み取り専用化側が引き続き効いている（順序の回帰検査）。
        let sys =
            mount_entry(mountinfo, "/proc/sys").map(|(opts, _)| opts.iter().any(|o| o == "ro"));
        assert_eq!(
            sys,
            Some(true),
            "/proc/sys must stay a read-only mount point"
        );
        assert!(
            applied > 0,
            "at least one masked target must exist:\n{text}"
        );
        (applied, absent)
    }

    fn verify_host_untouched(rootfs: &Path) {
        for t in MASKED_PROC_PATHS {
            let host = rootfs.join(t.trim_start_matches('/'));
            if is_dir_target(t) {
                assert_eq!(
                    std::fs::read(host.join("inner")).expect("read inner"),
                    SECRET,
                    "{t}"
                );
                assert_eq!(
                    std::fs::read_dir(&host).expect("read dir").count(),
                    1,
                    "{t}"
                );
            } else {
                assert_eq!(std::fs::read(&host).expect("read file"), SECRET, "{t}");
            }
        }
    }
}
