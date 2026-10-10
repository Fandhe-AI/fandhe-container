//! 暗黙の `/dev`・`/dev/pts`・`/dev/shm` を Landlock のルールに反映する結合試験
//! （CORE-5・TASK-29 追補・#1657）。
//!
//! 読み取り専用の root（`root.readonly=true`）・`mounts[]` が空の config でも、Landlock 適用後に
//! `/dev/null` への書き込みと `/dev/shm` でのファイル・ディレクトリ作成が通り、`/dev/ptmx` を `O_NOCTTY` で
//! 開け、許可外のパス（`/etc`・`/`）への作成は従来どおり `EACCES` で拒否されることを errno で照合する。
//! rootful では `CAP_MKNOD` があり `/dev` の tmpfs に `nodev` が無いため、`/dev`・`/dev/shm` での文字デバイスの
//! 作成（`mknodat(2)`）を止めるのは Landlock の `MAKE_CHAR` 不許可だけで、それが `EACCES` になることも通しで
//! 照合する（#1672 事後監査 P2）。拒否 4 件に対する監査レコード 4 件とパス一致も照合する（SEC-4）。
//!
//! # 流れ
//! - 親（root 必須）: `proc/`・`etc/` のみの一時 rootfs を作り、rootful 分離 → 自身を `--child <rootfs>` で
//!   起動（新しい PID namespace の PID 1）→ タイムアウト付きで終了コード 0 を待つ（REPAIR-5）
//! - 子: `establish` → `prepare_rootfs` → `create_default_devices` → 既定の `/dev/shm`
//!   （`TmpfsMountSet::ensure_default_dev_shm` → `mount_tmpfs`）→ `pivot_root` → `observe_landlock_path_access`
//!
//! # 実機前提テストとしての分離
//! root・Linux 6.12+（Landlock ABI 6+）が必要で、GitHub ホステッド runner では保証できないため
//! `-- --ignored` 指定時のみ実行する（ci.md「実機前提テスト」・AGENTS.md）。非 root は rootless では
//! `create_default_devices` が `mknod(2)` の `EPERM` で止まり照合まで進めない（#1660 の後に対応）ため、
//! 検証せずに成功せず失敗として扱う。root 権限コマンドのため実行は明示指示のもとで行い、結果を PR に記録する。
//! pty の ioctl（`IOCTL_DEV`）の実機照合は安全なラッパーが無く本試験の範囲外で、ルールのビット照合は
//! `landlock::rules` の単体テストが担う。
//!
//! `harness = false` の単一スレッド `main` で動かす理由は `landlock.rs` と同じ（`Cargo.toml` の `[[test]]`）。

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("landlock_implicit_dev: Linux only, not applicable on this OS");
}

#[cfg(all(
    target_os = "linux",
    not(any(target_arch = "x86_64", target_arch = "aarch64"))
))]
fn main() {
    println!("landlock_implicit_dev: x86_64/aarch64 only, not applicable on this architecture");
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn main() {
    // `-- --ignored` を付けたときだけ実行する。子は `--child <rootfs>` で再入する。
    if std::env::args().any(|a| a == "--ignored" || a == "--child") {
        linux::run();
    } else {
        println!(
            "landlock_implicit_dev: ignored (real-machine test; run with `-- --ignored`, see AGENTS.md)"
        );
    }
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod linux {
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    use fandhe_container_core::audit_log::AuditLayer;
    use fandhe_container_core::exec::{
        DevptsGidSource, IsolationConfig, LandlockAccessKind as K, LandlockAccessProbe,
        MountIsolation, Namespace, NamespaceSet, create_default_devices, isolate_rootful_host_root,
        mount_tmpfs, observe_landlock_path_access, pivot_root, plan_rootful_host_root,
        prepare_rootfs,
    };
    use fandhe_container_core::oci_runtime::parse_config_bytes;
    use fandhe_container_core::tmpfs::TmpfsMountSet;

    /// Linux の `EACCES`（x86_64・aarch64 共通で 13）。
    const EACCES: i32 = 13;

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
            .unwrap_or(30);
        Duration::from_secs(secs)
    }

    pub fn run() {
        let args: Vec<String> = std::env::args().collect();
        match args.iter().position(|a| a == "--child") {
            Some(i) => child(Path::new(
                args.get(i + 1).expect("rootfs path after --child"),
            )),
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
            .join(format!("fandhe-landlock-dev-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        for d in ["proc", "etc"] {
            std::fs::create_dir_all(base.join(d)).expect("create rootfs dir");
        }
        Rootfs(base)
    }

    fn parent() {
        assert!(
            is_root(),
            "landlock_implicit_dev is rootful only: run as root (rootless stops at mknod, see #1660)"
        );
        let rootfs = make_rootfs();
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
        run_child(&rootfs.0);
        println!(
            "landlock_implicit_dev: /dev/null write, /dev/shm create, /dev/ptmx open allowed; mknod and outside write denied (root=true)"
        );
    }

    /// 自身を `--child <rootfs>` で起動する。分離後の最初の子なので新しい PID namespace の PID 1 になる。
    fn run_child(rootfs: &Path) {
        let exe = std::env::current_exe().expect("current_exe");
        let mut child = Command::new(exe)
            .arg("--child")
            .arg(rootfs)
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
                    // kill 失敗は握りつぶさず明示的に失敗させ、回収にも有限の猶予を設ける（REPAIR-5）。
                    if let Err(e) = child.kill() {
                        panic!(
                            "child did not exit within {:?} and kill failed: {e}",
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
                            Ok(None) => panic!(
                                "child could not be reaped after kill (timeout {:?})",
                                timeout()
                            ),
                            Err(e) => panic!("try_wait failed while reaping child: {e}"),
                        }
                    }
                    panic!("child did not exit within {:?}", timeout());
                }
                None => std::thread::sleep(Duration::from_millis(20)),
            }
        }
    }

    fn probe(kind: K, path: &str) -> LandlockAccessProbe {
        LandlockAccessProbe {
            kind,
            path: PathBuf::from(path),
            expected_content: None,
        }
    }

    fn child(rootfs: &Path) {
        assert_eq!(
            std::process::id(),
            1,
            "child must be PID 1 of the new PID namespace"
        );
        let isolation = MountIsolation::establish().expect("establish mount isolation");
        let prepared = prepare_rootfs(&isolation, rootfs).expect("prepare rootfs");
        let devices = create_default_devices(&isolation, &prepared, DevptsGidSource::Rootful)
            .expect("create default devices");
        // 本番の順序: create_default_devices の後に既定の `/dev/shm`（#1654）。
        let mut tmpfs = TmpfsMountSet::new();
        tmpfs
            .ensure_default_dev_shm()
            .expect("default /dev/shm spec");
        mount_tmpfs(&isolation, &prepared, Some(&devices), &tmpfs).expect("mount default /dev/shm");
        pivot_root(&isolation, prepared).expect("pivot_root");

        // 読み取り専用 root・`mounts[]` が空。暗黙の `/dev` 系だけが書き込みを許す。
        let config = parse_config_bytes(
            br#"{"ociVersion":"1.2.0","root":{"path":"rootfs","readonly":true},"mounts":[]}"#,
        )
        .expect("valid config");
        let probes = vec![
            probe(K::WriteExisting, "/dev/null"),
            probe(K::CreateFile, "/dev/shm/landlock-probe"),
            probe(K::MakeDir, "/dev/shm/landlock-dir"),
            probe(K::OpenNoCtty, "/dev/ptmx"),
            probe(K::MakeCharDevice, "/dev/landlock-mknod"),
            probe(K::MakeCharDevice, "/dev/shm/landlock-mknod"),
            probe(K::CreateFile, "/etc/landlock-denied"),
            probe(K::CreateFile, "/landlock-denied"),
        ];
        let o = observe_landlock_path_access(&config, &probes).expect("observe");
        // 検出失敗（ABI 6 未満）も実機前提の不成立として失敗にする。
        assert!(o.ruleset_error.is_none(), "{:?}", o.ruleset_error);
        assert!(o.apply_error.is_none(), "{:?}", o.apply_error);
        assert!(o.applied);
        let got: Vec<Option<i32>> = o.results.iter().map(|(_, r)| *r).collect();
        assert_eq!(
            got,
            vec![
                None,
                None,
                None,
                None,
                Some(EACCES),
                Some(EACCES),
                Some(EACCES),
                Some(EACCES)
            ],
            "results: {:?}",
            o.results
        );
        // mknod の拒否でノードが作られていない（Landlock が `mknodat(2)` の前に止める）。
        for p in ["/dev/landlock-mknod", "/dev/shm/landlock-mknod"] {
            assert!(
                std::fs::symlink_metadata(p).is_err(),
                "{p} must not be created"
            );
        }
        // SEC-4: 拒否 4 件に対して監査レコードがちょうど 4 件・パス一致。
        assert!(o.audit_error.is_none(), "{:?}", o.audit_error);
        assert_eq!(o.audit_records.len(), 4, "{:?}", o.audit_records);
        let want = [
            Path::new("/dev/landlock-mknod"),
            Path::new("/dev/shm/landlock-mknod"),
            Path::new("/etc/landlock-denied"),
            Path::new("/landlock-denied"),
        ];
        for (rec, want) in o.audit_records.iter().zip(want) {
            assert_eq!(rec.layer(), AuditLayer::Landlock);
            assert_eq!(rec.path(), Some(want));
        }
    }
}
