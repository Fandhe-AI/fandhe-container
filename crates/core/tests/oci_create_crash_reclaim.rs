//! create の途中でプロセスが落ちて残った展開途中の rootfs の回収の結合試験（#2379・OCI-7・REPAIR-5）。
//!
//! 展開付きの `create_with_image` が非公開の名前（`.fandhe-unpack-<pid>-<seq>`）の木へ展開している最中に、
//! 子プロセス（このテストバイナリ自身を `--exact` で再実行。追加依存なし）を SIGKILL で止める。落ちた
//! プロセスの OS ロックは外れるので、同じ bundle で create をやり直すと、残った木が回収されて成功し、
//! 新しい rootfs が公開されることを具体値で確かめる。`state_store_crash` と同じ方式で、root 不要・
//! 既定のテスト集合で動く。子の待機には上限時間を設ける（REPAIR-5）。
//!
//! 展開途中の木の回収の判定（OS ロック・所有者・mode・同一性・symlink の非追従）の決定的な試験は
//! `oci_runtime::image_rootfs` のユニットテストが担う。`FileStateStore` は Linux 限定のため Linux のみで動く。

#[cfg(target_os = "linux")]
mod linux {
    use std::fs::{self, File};
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};

    use fandhe_container_core::observability::OpRecorder;
    use fandhe_container_core::oci_runtime::{
        ContainerImage, ContainerImageRefs, ImageManifestDigest, ImageRefGeneration,
        ImageRefRegistration, ImageRefRelease, ImageRootfsUnpacked, ImageRootfsUnpacker,
        create_with_image,
    };
    use fandhe_container_core::state_store::{FileStateStore, StateRoot};
    use fandhe_container_core::traits::{ContainerId, CreateRequest, StateStore, TraitError};

    const DIR_ENV: &str = "FANDHE_CREATE_CRASH_DIR";
    /// 子プロセスで再実行するテストの完全修飾名（`--exact` で照合する）。
    const CHILD_TEST: &str = "linux::child_unpacks_until_killed";
    /// 子が自力で止まる上限時間（親が異常終了しても孤児化しない）。
    const CHILD_LIFETIME: Duration = Duration::from_secs(60);
    const WAIT_DEADLINE: Duration = Duration::from_secs(30);
    const MANIFEST: &str =
        "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const MARKER: &str = "unpacking";

    /// 参照テーブルの代役（登録・確定・解除をすべて成功させるだけ）。
    struct NoopRefs;

    impl ContainerImageRefs for NoopRefs {
        fn register(
            &self,
            _id: &ContainerId,
            _manifest: &ImageManifestDigest,
        ) -> Result<ImageRefRegistration, TraitError> {
            Ok(ImageRefRegistration::Registered)
        }
        fn release(&self, _id: &ContainerId) -> Result<ImageRefRelease, TraitError> {
            Ok(ImageRefRelease::Released)
        }
        fn bind(&self, _id: &ContainerId) -> Result<ImageRefGeneration, TraitError> {
            Ok(ImageRefGeneration::from_raw(1))
        }
        fn registration(
            &self,
            _id: &ContainerId,
        ) -> Result<Option<ImageRefGeneration>, TraitError> {
            Ok(Some(ImageRefGeneration::from_raw(1)))
        }
        fn release_if(
            &self,
            _id: &ContainerId,
            _expected: ImageRefGeneration,
        ) -> Result<ImageRefRelease, TraitError> {
            Ok(ImageRefRelease::Released)
        }
    }

    /// 展開器: 途中のファイルを書き、`hang` なら目印を置いて止まり続ける（kill される）。
    struct Unpacker {
        hang_marker: Option<PathBuf>,
    }

    impl ImageRootfsUnpacker for Unpacker {
        fn unpack(
            &self,
            _manifest: &ImageManifestDigest,
            rootfs: &Path,
        ) -> Result<ImageRootfsUnpacked, TraitError> {
            if let Some(marker) = &self.hang_marker {
                fs::create_dir(rootfs.join("etc")).unwrap();
                fs::write(rootfs.join("etc/partial"), b"partial").unwrap();
                fs::write(marker, b"x").unwrap();
                let end = Instant::now() + CHILD_LIFETIME;
                while Instant::now() < end {
                    std::thread::sleep(Duration::from_millis(10));
                }
                return Ok(ImageRootfsUnpacked::default());
            }
            fs::write(rootfs.join("fresh"), b"fresh").unwrap();
            Ok(ImageRootfsUnpacked::default())
        }
    }

    /// テスト用一時ディレクトリ（drop で削除。0700）。
    struct TmpDir(PathBuf);

    impl TmpDir {
        fn new() -> Self {
            let p =
                std::env::temp_dir().join(format!("fandhe-create-crash-{}", std::process::id()));
            let _ = fs::remove_dir_all(&p);
            fs::create_dir_all(&p).unwrap();
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).unwrap();
            Self(p)
        }
    }

    impl Drop for TmpDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn open_store(dir: &Path) -> FileStateStore {
        let root = dir.join("state");
        fs::create_dir_all(&root).unwrap();
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        FileStateStore::open(StateRoot::from_override(root).unwrap()).unwrap()
    }

    fn request(dir: &Path) -> CreateRequest {
        CreateRequest::new(ContainerId::new("crash-c1").unwrap(), dir.join("bundle")).unwrap()
    }

    fn run_create(dir: &Path, unpacker: &Unpacker) {
        let store = open_store(dir);
        let manifest = ImageManifestDigest::new(MANIFEST).unwrap();
        let refs = NoopRefs;
        let image = ContainerImage::new(&refs, &manifest).with_unpacker(unpacker);
        create_with_image(&store, &OpRecorder::new(), image, &request(dir)).unwrap_or_else(|e| {
            panic!("create_with_image failed: {e:?}");
        });
        // 状態が作られていること。
        assert!(
            store
                .get(&fandhe_container_core::traits::GetStateRequest::new(
                    ContainerId::new("crash-c1").unwrap()
                ))
                .is_ok()
        );
    }

    fn write_bundle(dir: &Path) {
        let bundle = dir.join("bundle");
        fs::create_dir_all(&bundle).unwrap();
        fs::write(
            bundle.join("config.json"),
            br#"{"ociVersion":"1.2.0","root":{"path":"rootfs"},"process":{"user":{"uid":0,"gid":0},"args":["/bin/true"],"cwd":"/"}}"#,
        )
        .unwrap();
    }

    fn staging_names(bundle: &Path) -> Vec<String> {
        let mut v: Vec<String> = fs::read_dir(bundle)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with(".fandhe-unpack-"))
            .collect();
        v.sort();
        v
    }

    /// 子プロセス側の本体。親が `DIR_ENV` を渡したときだけ動く。展開の最中（目印を置いた後）に止まり続ける。
    #[test]
    fn child_unpacks_until_killed() {
        let Some(dir) = std::env::var_os(DIR_ENV) else {
            return;
        };
        let dir = PathBuf::from(dir);
        eprintln!("child: started pid={}", std::process::id());
        let marker = dir.join(MARKER);
        run_create(
            &dir,
            &Unpacker {
                hang_marker: Some(marker),
            },
        );
    }

    fn spawn_child(dir: &Path, log: &Path) -> Child {
        let log_file = File::create(log).unwrap();
        Command::new(std::env::current_exe().unwrap())
            .args(["--exact", CHILD_TEST, "--test-threads=1", "--nocapture"])
            .env(DIR_ENV, dir)
            .stdout(Stdio::null())
            .stderr(log_file)
            .spawn()
            .unwrap()
    }

    /// 子のログ末尾（診断用）。
    fn log_tail(log: &Path) -> String {
        let s = fs::read_to_string(log).unwrap_or_else(|_| "<log unavailable>".to_string());
        let start = s.len().saturating_sub(4096);
        s.get(start..).unwrap_or("").to_string()
    }

    /// OCI-7・#2379・REPAIR-5: 展開の最中に SIGKILL された create の残した展開途中の木は、同じ bundle の
    /// create のやり直しで回収され、やり直しは成功して新しい rootfs だけが公開される。
    #[test]
    fn oci7_create_after_sigkill_during_unpack_reclaims_staging() {
        let t = TmpDir::new();
        let dir = t.0.clone();
        write_bundle(&dir);
        let log = dir.join("child.log");
        let mut child = spawn_child(&dir, &log);

        // 展開が始まった目印を上限時間つきで待つ。
        let deadline = Instant::now() + WAIT_DEADLINE;
        while !dir.join(MARKER).exists() {
            if let Some(status) = child.try_wait().unwrap() {
                panic!(
                    "child exited before unpacking: {status:?}\n{}",
                    log_tail(&log)
                );
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let reap_end = Instant::now() + WAIT_DEADLINE;
                while child.try_wait().ok().flatten().is_none() && Instant::now() < reap_end {
                    std::thread::sleep(Duration::from_millis(5));
                }
                panic!("child did not start unpacking\n{}", log_tail(&log));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        child.kill().unwrap();
        let end = Instant::now() + WAIT_DEADLINE;
        loop {
            if child.try_wait().unwrap().is_some() {
                break;
            }
            assert!(Instant::now() < end, "child did not exit after kill");
            std::thread::sleep(Duration::from_millis(5));
        }

        let bundle = dir.join("bundle");
        let before = staging_names(&bundle);
        assert_eq!(before.len(), 1, "one leftover staging tree: {before:?}");
        assert!(
            bundle.join(&before[0]).join("rootfs/etc/partial").exists(),
            "partial content left by the killed create (wrapper/rootfs layout, #2635)"
        );
        assert!(!bundle.join("rootfs").exists());

        // やり直し: 残った木を回収して成功する。
        run_create(&dir, &Unpacker { hang_marker: None });
        assert_eq!(staging_names(&bundle), Vec::<String>::new());
        assert_eq!(fs::read(bundle.join("rootfs/fresh")).unwrap(), b"fresh");
        assert!(!bundle.join("rootfs/etc").exists());
    }
}
