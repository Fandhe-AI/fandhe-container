//! イメージストア root 配下の別マウント（実マウント）が `FailedPrecondition` で拒否されることの実機前提試験
//! （OCI-7・SEC-1・ERR-1・#2701）。
//!
//! `harness = false`（単一スレッドの独自 `main`）。`-- --ignored` を付けたときだけ実行し、付けなければ
//! 何もせず成功する（既定のテスト集合に実機前提を混ぜない。AGENTS.md「実機前提テスト」）。
//!
//! 構成: 外側（初期 user namespace・非 root）が `unshare --user --map-root-user --mount` で自分自身を
//! `--case all --dir <一時ディレクトリ>` つきで再起動する。子は新しい user / mount namespace の中で、
//!
//! 1. 一時ディレクトリに tmpfs を mount し、その中に `store-blobs`（`blobs/sha256` を bind mount で別マウントにした
//!    root）と `store-lock`（`@lock` を bind mount にした root）を作る。
//! 2. その tmpfs へ `chroot` する。user namespace の中ではホストの root 所有の祖先（`/`・`/tmp`）が overflow uid に
//!    見えて `ImageStore::open` の祖先検査を通らないため、祖先を namespace の root 所有の tmpfs だけにする。
//! 3. 公開 API の rm・prune・lock が `FailedPrecondition` と固定メッセージで止まり、テーブルも blob も
//!    ジャーナルも変わらないことを具体値で照合する。
//!
//! 前提: 非特権 user namespace を作れること・util-linux の `unshare` と `mount`・非 root での実行。満たさなければ
//! 成功を装わず失敗する。Linux の x86_64 / aarch64 以外は fd 起点の実装が無い（`Unimplemented` で拒否）ため
//! `not applicable` を出して成功する。

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[path = "support/reap.rs"]
mod reap;

#[cfg(not(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
)))]
fn main() {
    println!("image_store_xdev: not applicable on this OS or architecture");
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn main() {
    linux::main();
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod linux {
    use std::fs;
    use std::os::unix::fs::{PermissionsExt as _, chroot};
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    use fandhe_container_oci::error::{OciError, OciErrorCode};
    use fandhe_container_oci::image_management::{
        ImageRmOptions, ImageRmTarget, ImageStore, ManifestComposition, StoppedContainers, TagKey,
    };
    use fandhe_container_oci::reference::{Digest, RegistryHost, Repository, Tag};

    const CASE_TIMEOUT: Duration = Duration::from_secs(60);
    const MESSAGE: &str = "image store path crosses a mount point; unsupported (RESOLVE_NO_XDEV)";

    fn d(n: u8) -> Digest {
        Digest::parse(&format!("sha256:{}", format!("{n:02x}").repeat(32))).expect("digest")
    }

    fn tag() -> TagKey {
        TagKey::new(
            RegistryHost::parse("registry.example").expect("host"),
            Repository::parse("lib/app").expect("repo"),
            Tag::parse("v1").expect("tag"),
        )
    }

    fn hex(n: u8) -> String {
        format!("{n:02x}").repeat(32)
    }

    fn mount(args: &[&str]) -> Result<(), String> {
        let st = Command::new("mount")
            .args(args)
            .status()
            .map_err(|e| format!("spawn mount: {e}"))?;
        if st.success() {
            Ok(())
        } else {
            Err(format!("mount {args:?} failed: {st}"))
        }
    }

    fn expect_crossing(what: &str, e: &OciError) -> Result<(), String> {
        if e.code() == OciErrorCode::FailedPrecondition && e.message() == MESSAGE {
            Ok(())
        } else {
            Err(format!(
                "{what}: unexpected error {:?}: {}",
                e.code(),
                e.message()
            ))
        }
    }

    fn mkdir_private(p: &Path) -> Result<(), String> {
        fs::create_dir_all(p).map_err(|e| format!("mkdir {p:?}: {e}"))?;
        fs::set_permissions(p, fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("chmod {p:?}: {e}"))
    }

    /// 子（新しい user / mount namespace の中）。
    fn child(dir: &Path) -> Result<(), String> {
        mount(&["-t", "tmpfs", "tmpfs", &dir.to_string_lossy()])?;
        // 別マウントの実体と構成を、chroot の前に tmpfs の中へ作る。
        mkdir_private(&dir.join("other"))?;
        mkdir_private(&dir.join("store-blobs/blobs/sha256"))?;
        mkdir_private(&dir.join("store-lock"))?;
        fs::write(dir.join("lockfile"), b"").map_err(|e| format!("lockfile: {e}"))?;
        fs::write(dir.join("store-lock/@lock"), b"").map_err(|e| format!("@lock: {e}"))?;
        mount(&[
            "--bind",
            &dir.join("other").to_string_lossy(),
            &dir.join("store-blobs/blobs/sha256").to_string_lossy(),
        ])?;
        mount(&[
            "--bind",
            &dir.join("lockfile").to_string_lossy(),
            &dir.join("store-lock/@lock").to_string_lossy(),
        ])?;
        chroot(dir).map_err(|e| format!("chroot: {e}"))?;
        std::env::set_current_dir("/").map_err(|e| format!("chdir: {e}"))?;

        blobs_dir_is_a_mount()?;
        lock_file_is_a_mount()?;
        Ok(())
    }

    /// `blobs/sha256` が別マウント: lock は通り、rm・prune・（ジャーナルがある）lock は拒否される。
    fn blobs_dir_is_a_mount() -> Result<(), String> {
        let root = Path::new("/store-blobs");
        let store = ImageStore::open(root).map_err(|e| format!("open: {:?}", e.message()))?;
        let blob = root.join("blobs/sha256").join(hex(0x11));
        let mut g = store.lock().map_err(|e| format!("lock: {}", e.message()))?;
        g.register_manifest(
            d(0xa0),
            ManifestComposition::new(d(0xc1), vec![d(0x11)]).map_err(|e| e.message().to_owned())?,
        )
        .map_err(|e| format!("register: {}", e.message()))?;
        g.register_tag(tag(), &d(0xa0))
            .map_err(|e| format!("tag: {}", e.message()))?;
        fs::write(&blob, b"blob").map_err(|e| format!("blob: {e}"))?;

        let e = g
            .execute_image_rm(
                root,
                &ImageRmTarget::Tag(tag()),
                &ImageRmOptions::default(),
                &StoppedContainers::new(),
            )
            .err()
            .ok_or("rm unexpectedly succeeded")?;
        expect_crossing("rm", &e)?;
        if g.manifests().count() != 1 || g.tags().count() != 1 || !blob.is_file() {
            return Err("rm changed the table or removed the blob".into());
        }
        println!("ok: xdev_rm");

        // 参照を外してから prune を試す(タグを外すには rm が要るため、別の無参照 manifest を足す)。
        g.register_manifest(
            d(0xb0),
            ManifestComposition::new(d(0xc2), vec![d(0x12)]).map_err(|e| e.message().to_owned())?,
        )
        .map_err(|e| format!("register b: {}", e.message()))?;
        let e = g
            .execute_image_prune(root)
            .err()
            .ok_or("prune unexpectedly succeeded")?;
        expect_crossing("prune", &e)?;
        if g.manifests().count() != 2 || !blob.is_file() {
            return Err("prune changed the table or removed the blob".into());
        }
        if root.join("@gc-pending.json").exists() {
            return Err("a journal was written".into());
        }
        println!("ok: xdev_prune");
        drop(g);

        // ジャーナルが残る状態の lock は、ジャーナルに触れずに拒否される。
        let journal = root.join("@gc-pending.json");
        let body = format!(
            r#"{{"version":1,"manifests":[],"untag":[],"delete_blobs":["sha256:{}"],"attempts":0}}"#,
            hex(0x11)
        );
        fs::write(&journal, &body).map_err(|e| format!("journal: {e}"))?;
        fs::set_permissions(&journal, fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("chmod journal: {e}"))?;
        let e = store
            .lock()
            .err()
            .ok_or("lock with a journal unexpectedly succeeded")?;
        expect_crossing("lock", &e)?;
        let after = fs::read_to_string(&journal).map_err(|e| format!("journal read: {e}"))?;
        if after != body || !blob.is_file() {
            return Err("recovery touched the journal or the blob".into());
        }
        println!("ok: xdev_lock_pending_journal");
        Ok(())
    }

    /// `@lock` が bind mount: lock は拒否される。
    fn lock_file_is_a_mount() -> Result<(), String> {
        let store = ImageStore::open(Path::new("/store-lock"))
            .map_err(|e| format!("open: {}", e.message()))?;
        let e = store.lock().err().ok_or("lock unexpectedly succeeded")?;
        expect_crossing("lock file", &e)?;
        println!("ok: xdev_lock_file_bind");
        Ok(())
    }

    fn outer() -> Result<(), String> {
        let exe = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;
        let dir: PathBuf =
            std::env::temp_dir().join(format!("fc-oci-image-store-xdev-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).map_err(|e| format!("mkdir: {e}"))?;
        let result = run_child(&exe, &dir);
        // 子の mount は子の namespace と一緒に消えている。
        let _ = fs::remove_dir_all(&dir);
        result
    }

    fn run_child(exe: &Path, dir: &Path) -> Result<(), String> {
        let mut cmd = Command::new("unshare");
        cmd.args(["--user", "--map-root-user", "--mount", "--"])
            .arg(exe)
            .arg("--case")
            .arg("all")
            .arg("--dir")
            .arg(dir)
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        let mut child = cmd.spawn().map_err(|e| format!("spawn unshare: {e}"))?;
        let deadline = Instant::now() + CASE_TIMEOUT;
        loop {
            match child.try_wait().map_err(|e| format!("wait: {e}"))? {
                Some(_) => break,
                None if Instant::now() >= deadline => {
                    crate::reap::reap_or_report(&mut child, crate::reap::REAP_WITHIN);
                    return Err("child timed out".into());
                }
                None => std::thread::sleep(Duration::from_millis(50)),
            }
        }
        let out = child
            .wait_with_output()
            .map_err(|e| format!("output: {e}"))?;
        let stdout = String::from_utf8_lossy(&out.stdout);
        print!("{stdout}");
        if !out.status.success() {
            return Err(format!("child failed: {}", out.status));
        }
        for line in [
            "ok: xdev_rm",
            "ok: xdev_prune",
            "ok: xdev_lock_pending_journal",
            "ok: xdev_lock_file_bind",
        ] {
            if !stdout.lines().any(|l| l == line) {
                return Err(format!("missing success line: {line}"));
            }
        }
        Ok(())
    }

    pub fn main() {
        let args: Vec<String> = std::env::args().collect();
        if args.iter().any(|a| a == "--case") {
            let dir = args
                .iter()
                .position(|a| a == "--dir")
                .and_then(|p| args.get(p + 1));
            let Some(dir) = dir else {
                eprintln!("image_store_xdev: bad child arguments");
                std::process::exit(2);
            };
            if let Err(e) = child(Path::new(dir)) {
                eprintln!("FAIL: image_store_xdev: {e}");
                std::process::exit(1);
            }
            return;
        }
        if !args.iter().any(|a| a == "--ignored") {
            println!(
                "image_store_xdev: ignored (pass `-- --ignored` on a host that allows unprivileged user namespaces)"
            );
            return;
        }
        match outer() {
            Ok(()) => println!("test image_store_xdev ... ok"),
            Err(e) => {
                eprintln!("FAIL: image_store_xdev: {e}");
                std::process::exit(1);
            }
        }
    }
}
