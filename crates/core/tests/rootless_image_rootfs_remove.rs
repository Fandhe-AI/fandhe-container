//! rootless の userns 展開が作る subuid 所有の rootfs の木を、core が回収・削除できることの結合試験
//! （OCI-7・OCI-5・SEC-5・CORE-6・REPAIR-5・#2540）。
//!
//! 展開器の役の子プロセス（本試験バイナリを `--populate <dir>` で再実行）が、user namespace
//! （コンテナ 0 → 自 euid、1.. → subuid 範囲。`SubordinateIdSource` の写像を `newuidmap` 経由で書く）の中で
//! `chown(1, 1)`・mode 0555 の木を作る。この木はホストの実効 uid では `chmod`・`unlink` が `EPERM` になる。
//! 続けて本番の `create_with_image` / `delete_with_options` / `reap_stale_unpacks_with` が次の経路で木を
//! 消せることを、権限なし（`HostEffectiveIds`）で消せず・権限あり（`SubordinateIds`）で消せる対で確かめる。
//!
//! # シナリオ（成功時に `rootless_image_rootfs_remove: scenario <x> verified` を出す）
//! - `a`: 記録が subordinate の木は、権限なしの delete が木に触れず `image_rootfs_remove` の失敗を記録して残す
//! - `b`: 権限ありの delete が木を消す（`image_rootfs_remove` 成功 1 件）
//! - `c`: 公開済みで状態の無い subuid 所有の木（`a` の残り）を、次の `create_with_image` が userns の中で
//!   孤児として回収する（`image_rootfs_orphan_reap` 成功 1 件）
//! - `d`: 展開途中の subuid 所有の木は、権限なしの回収が失敗として残し、権限ありの回収が消す
//! - `d2`: 最上位自身が subuid 所有・mode 0700 の展開途中の木（ホストの uid ではロック用に開けない）を、
//!   権限なしは `LockError` で残し、権限ありは userns の中でロック・同一性確認・削除まで行って回収する
//! - `e`: 展開に失敗した create の後始末（`image_rootfs_cleanup`）が、権限ありなら subuid 所有の木を消す
//! - `f`: core 専有のラッパー（実効 uid 所有）の下の子が subuid 所有・mode 0700 の展開途中の木（#2635）。
//!   ラッパーの所有者が崩れないので `Unverified` にならず、権限なしは失敗として残し、権限ありは回収する。
//!   rootful でイメージが所有者を変える場合の実機確認〔root 版〕は CI で回さない（#1621）
//!
//! # 実機前提テストとしての分離
//! `harness = false` の単一スレッド `main`（fork と `CLONE_NEWUSER` の前提）。非特権 user namespace を許可する
//! ホストと、`uidmap`（setuid の `newuidmap` / `newgidmap`）・自分の subuid / subgid の行が要る。
//! `-- --ignored` 指定時のみ実行し、未指定時は「ignored」を出力して成功終了する（ci.md「実機前提テスト」）。
//! 実行された場合は前提の欠落を含むあらゆる失敗を失敗として扱う。root では実行しない。

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("rootless_image_rootfs_remove: Linux only, not applicable on this OS");
}

#[cfg(target_os = "linux")]
fn main() {
    let args: Vec<String> = std::env::args().collect();
    if let Some(i) = args.iter().position(|a| a == "--populate") {
        let dir = args.get(i + 1).expect("directory after --populate");
        linux::populate(dir, args.iter().any(|a| a == "--chown-root"));
    } else if args.iter().any(|a| a == "--ignored") {
        linux::run();
    } else {
        println!(
            "rootless_image_rootfs_remove: ignored (real-machine test; run with `-- --ignored`, see AGENTS.md)"
        );
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::os::fd::AsRawFd as _;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::time::{Duration, Instant};

    use fandhe_container_core::exec::{
        IsolationConfig, Namespace, NamespaceSet, isolate_rootless_subordinate,
        plan_rootless_subordinate,
    };
    use fandhe_container_core::observability::{OpName, OpRecorder};
    use fandhe_container_core::oci_runtime::{
        CgroupRemoval, ContainerCgroupRemover, ContainerImage, ContainerImageRefs, DeleteOptions,
        ImageManifestDigest, ImageRefGeneration, ImageRefRegistration, ImageRefRelease,
        ImageRootfsPrivilege, ImageRootfsUnpacked, ImageRootfsUnpacker, ReapOptions,
        SubordinateIdSource, create_with_image, delete_releasing_image_ref_with_options,
        reap_stale_unpacks_with,
    };
    use fandhe_container_core::state_store::{FileStateStore, StateRoot};
    use fandhe_container_core::traits::{
        CgroupScope, CleanupOutcome, ContainerId, CreateRequest, DeleteRequest, DeleteResponse,
        ErrorCode, ImageRootfsOwnership, StateRevision, StateStore, TraitError,
    };
    use serde_json::json;

    const MANIFEST: &str =
        "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const CHILD_DEADLINE: Duration = Duration::from_secs(60);

    fn owner_name() -> Option<String> {
        std::env::var("USER").ok()
    }

    fn source() -> SubordinateIdSource {
        SubordinateIdSource::system(owner_name()).expect("subordinate id source")
    }

    fn euid() -> u32 {
        std::fs::metadata("/proc/self")
            .expect("stat /proc/self")
            .uid()
    }

    /// 展開器の役の子: userns の中で subuid 所有の木を作る（`chown(1, 1)`・mode 0555）。
    /// `chown_root` なら、木の最上位 `dir` 自身も subuid 所有・mode 0700 にする（展開途中でクラッシュした
    /// 木の再現。ホストの実効 uid ではロック用に開き直せない）。
    pub fn populate(dir: &str, chown_root: bool) {
        // userns に入る前にディレクトリを開く（入った後は親の `/proc/<pid>/fd` に頼らない）。
        let root = std::fs::File::open(dir).expect("open target dir");
        let (euid, egid) = (euid(), std::fs::metadata("/proc/self").expect("stat").gid());
        let maps = source().resolve_id_maps(euid, egid).expect("id maps");
        let helper =
            fandhe_container_core::rootless::HelperPaths::system_default().expect("newuidmap");
        let config = IsolationConfig {
            namespaces: NamespaceSet::empty().with(Namespace::User),
            hostname: None,
        };
        let plan = plan_rootless_subordinate(
            &config,
            maps.uid().clone(),
            maps.gid().clone(),
            fandhe_container_core::rootless::IdMapWriter::Helper(helper),
            fandhe_container_core::rootless::DEFAULT_HELPER_TIMEOUT,
        )
        .expect("plan");
        isolate_rootless_subordinate(&plan).expect("enter user namespace");
        let base = PathBuf::from(format!("/proc/self/fd/{}", root.as_raw_fd()));
        let sub = base.join("sub");
        std::fs::create_dir(&sub).expect("mkdir sub");
        std::fs::write(sub.join("f"), b"owned by a subordinate id").expect("write f");
        std::fs::set_permissions(sub.join("f"), std::fs::Permissions::from_mode(0o444))
            .expect("chmod f");
        std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o555)).expect("chmod sub");
        std::os::unix::fs::chown(sub.join("f"), Some(1), Some(1)).expect("chown f");
        std::os::unix::fs::chown(&sub, Some(1), Some(1)).expect("chown sub");
        if chown_root {
            std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700))
                .expect("chmod root");
            std::os::unix::fs::chown(&base, Some(1), Some(1)).expect("chown root");
        }
    }

    /// 本試験バイナリを `--populate` で再実行して、`dir`（親のプロセスが保持する fd を指す経路でも可）に
    /// subuid 所有の木を作らせる。子の待ちは期限つきで、超えたら kill して失敗にする（REPAIR-5）。
    fn populate_via_child(dir: &Path) {
        populate_child(dir, false);
    }

    fn populate_child(dir: &Path, chown_root: bool) {
        // `/proc/self/fd/N` は子から見ると別のプロセスの fd なので、親の pid の経路へ読み替える。
        let text = dir.to_string_lossy();
        let path = match text.strip_prefix("/proc/self/") {
            Some(rest) => format!("/proc/{}/{rest}", std::process::id()),
            None => text.into_owned(),
        };
        let exe = std::env::current_exe().expect("current exe");
        let mut cmd = Command::new(exe);
        cmd.args(["--populate", &path]);
        if chown_root {
            cmd.arg("--chown-root");
        }
        let mut child = cmd.spawn().expect("spawn populate child");
        let deadline = Instant::now() + CHILD_DEADLINE;
        loop {
            match child.try_wait().expect("try_wait") {
                Some(status) => {
                    assert!(status.success(), "populate child failed: {status}");
                    return;
                }
                None if Instant::now() >= deadline => {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!("populate child timed out");
                }
                None => std::thread::sleep(Duration::from_millis(50)),
            }
        }
    }

    struct Populating {
        fail: bool,
    }

    impl ImageRootfsUnpacker for Populating {
        fn unpack(
            &self,
            _manifest: &ImageManifestDigest,
            rootfs: &Path,
        ) -> Result<ImageRootfsUnpacked, TraitError> {
            populate_via_child(rootfs);
            if self.fail {
                return Err(TraitError::new(ErrorCode::Internal, "unpack failed"));
            }
            Ok(ImageRootfsUnpacked::default())
        }
    }

    /// 呼び出しを受け流す参照テーブル。
    struct Refs;

    impl ContainerImageRefs for Refs {
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
            Ok(None)
        }
        fn release_if(
            &self,
            _id: &ContainerId,
            _expected: ImageRefGeneration,
        ) -> Result<ImageRefRelease, TraitError> {
            Ok(ImageRefRelease::NotRegistered)
        }
    }

    /// cgroup を記録しない create なので触れない `ContainerCgroupRemover`。
    struct NoCgroup;

    impl ContainerCgroupRemover for NoCgroup {
        fn scope(&self) -> Result<CgroupScope, TraitError> {
            CgroupScope::new("/user.slice/user-1000.slice/a.scope")
        }
        fn remove(
            &self,
            _id: &ContainerId,
            _instance: StateRevision,
        ) -> Result<CgroupRemoval, TraitError> {
            Err(TraitError::new(
                ErrorCode::Internal,
                "cgroup must not be touched",
            ))
        }
    }

    struct Sandbox {
        dir: PathBuf,
    }

    impl Sandbox {
        fn new(tag: &str) -> Self {
            let tmp = std::fs::canonicalize(std::env::temp_dir()).expect("tmp");
            let dir = tmp.join(format!(
                "fandhe-rootless-rootfs-remove-{tag}-{}",
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&dir);
            // 状態ルートの祖先は group / other 書き込み不可でなければならない（umask に依らず 0700 で作る）。
            for d in [dir.clone(), dir.join("bundle")] {
                std::os::unix::fs::DirBuilderExt::mode(&mut std::fs::DirBuilder::new(), 0o700)
                    .create(&d)
                    .expect("mkdir");
            }
            std::fs::write(
                dir.join("bundle/config.json"),
                serde_json::to_vec(&json!({
                    "ociVersion": "1.2.0",
                    "root": {"path": "rootfs"},
                    "process": {"user": {"uid": 0, "gid": 0}, "args": ["/bin/true"], "cwd": "/"}
                }))
                .expect("ser"),
            )
            .expect("config");
            Self { dir }
        }

        fn bundle(&self) -> PathBuf {
            self.dir.join("bundle")
        }

        fn rootfs(&self) -> PathBuf {
            self.bundle().join("rootfs")
        }

        fn store(&self) -> FileStateStore {
            FileStateStore::open(StateRoot::from_override(self.dir.join("state")).expect("root"))
                .expect("open store")
        }

        fn request(&self) -> CreateRequest {
            CreateRequest::new(ContainerId::new("c1").expect("id"), self.bundle()).expect("req")
        }
    }

    impl Drop for Sandbox {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn counts(rec: &OpRecorder, name: &str) -> (u64, u64) {
        rec.snapshot_op(&OpName::new(name).expect("name"))
            .map_or((0, 0), |s| (s.success(), s.failure()))
    }

    fn create(
        sb: &Sandbox,
        store: &dyn StateStore,
        rec: &OpRecorder,
        privilege: &ImageRootfsPrivilege,
        fail: bool,
    ) -> Result<(), fandhe_container_core::oci_runtime::OciRuntimeError> {
        let manifest = ImageManifestDigest::new(MANIFEST).expect("digest");
        let unpacker = Populating { fail };
        create_with_image(
            store,
            rec,
            ContainerImage::new(&Refs, &manifest)
                .with_unpacker(&unpacker)
                .with_rootfs_privilege(privilege),
            &sb.request(),
        )
        .map(|_| ())
    }

    fn delete(
        store: &dyn StateStore,
        rec: &OpRecorder,
        privilege: ImageRootfsPrivilege,
    ) -> Result<DeleteResponse, fandhe_container_core::oci_runtime::OciRuntimeError> {
        delete_releasing_image_ref_with_options(
            store,
            rec,
            &NoCgroup,
            &Refs,
            &DeleteRequest::new(ContainerId::new("c1").expect("id")),
            &DeleteOptions::new().with_rootfs_privilege(privilege),
        )
    }

    /// ホストの実効 uid ではこの木の中身を消せないこと（前提の確認）。
    fn assert_tree_is_subordinate_owned(rootfs: &Path) {
        let file = rootfs.join("sub/f");
        let meta = std::fs::metadata(&file).expect("stat sub/f");
        assert_ne!(
            meta.uid(),
            euid(),
            "sub/f must not be owned by the host euid"
        );
        // 前提の実測: 所有者が subuid の inode は、ホストの実効 uid では消せない。
        assert!(std::fs::remove_file(&file).is_err());
        assert!(file.is_file());
    }

    pub fn run() {
        let euid = euid();
        assert_ne!(euid, 0, "this test must run as a non-root user");
        let sub = ImageRootfsPrivilege::SubordinateIds(source());
        let host = ImageRootfsPrivilege::HostEffectiveIds;

        // a・c・b は同じ bundle を順に使う。
        let sb = Sandbox::new("abc");
        let store = sb.store();
        create(&sb, &store, &OpRecorder::new(), &sub, false).expect("create (subordinate)");
        let record = store
            .get(&fandhe_container_core::traits::GetStateRequest::new(
                ContainerId::new("c1").expect("id"),
            ))
            .expect("state");
        assert_eq!(
            record.image_rootfs().map(|r| r.ownership()),
            Some(ImageRootfsOwnership::SubordinateIds)
        );
        assert_tree_is_subordinate_owned(&sb.rootfs());

        // a: 権限なしの delete は木に触れず、失敗として記録する（状態は消える）。
        let rec = OpRecorder::new();
        let resp = delete(&store, &rec, host).expect("delete succeeds even if the tree is kept");
        assert!(
            matches!(resp.image_rootfs(), CleanupOutcome::Kept { .. }),
            "unprivileged delete must report the kept tree: {:?}",
            resp.image_rootfs()
        );
        assert_eq!(counts(&rec, "image_rootfs_remove"), (0, 1));
        assert!(sb.rootfs().join("sub/f").is_file());
        println!("rootless_image_rootfs_remove: scenario a verified");

        // c: 状態の無い subuid 所有の公開済みの木を、次の create が userns の中で孤児として回収する。
        let rec = OpRecorder::new();
        create(&sb, &store, &rec, &sub, false).expect("create reclaims the orphan");
        assert_eq!(counts(&rec, "image_rootfs_orphan_reap"), (1, 0));
        assert_tree_is_subordinate_owned(&sb.rootfs());
        println!("rootless_image_rootfs_remove: scenario c verified");

        // b: 権限ありの delete が木を消す。
        let rec = OpRecorder::new();
        let resp = delete(&store, &rec, sub.clone()).expect("delete");
        assert_eq!(resp.image_rootfs(), CleanupOutcome::Removed);
        assert_eq!(counts(&rec, "image_rootfs_remove"), (1, 0));
        assert!(!sb.rootfs().exists());
        println!("rootless_image_rootfs_remove: scenario b verified");
        drop(store);
        drop(sb);

        // d: 展開途中の subuid 所有の木。
        let sb = Sandbox::new("d");
        let staging = sb.bundle().join(".fandhe-unpack-1-1");
        std::fs::create_dir(&staging).expect("staging");
        std::fs::set_permissions(&staging, std::fs::Permissions::from_mode(0o700)).expect("mode");
        populate_via_child(&staging);
        let rec = OpRecorder::new();
        let r =
            reap_stale_unpacks_with(&sb.bundle(), Path::new("rootfs"), &ReapOptions::new(), &rec)
                .expect("reap (host)");
        assert!(r.reclaimed.is_empty());
        assert_eq!(r.failed.len(), 1, "{r:?}");
        assert_eq!(counts(&rec, "image_rootfs_reap_failed"), (0, 1));
        assert!(staging.join("sub").is_dir());
        let options = ReapOptions::new().with_privilege(sub.clone());
        let r = reap_stale_unpacks_with(&sb.bundle(), Path::new("rootfs"), &options, &rec)
            .expect("reap (subordinate)");
        assert_eq!(r.reclaimed.len(), 1, "{r:?}");
        assert!(!staging.exists());
        println!("rootless_image_rootfs_remove: scenario d verified");
        drop(sb);

        // d2: 最上位自身が subuid 所有・mode 0700 の展開途中の木（ホストの uid ではロック用に開けない）。
        // 権限なしは LockError で残し、権限ありは userns の中でロック・同一性確認・削除まで行う。
        let sb = Sandbox::new("d2");
        let staging = sb.bundle().join(".fandhe-unpack-2-1");
        std::fs::create_dir(&staging).expect("staging");
        std::fs::set_permissions(&staging, std::fs::Permissions::from_mode(0o700)).expect("mode");
        populate_child(&staging, true);
        let rec = OpRecorder::new();
        let r =
            reap_stale_unpacks_with(&sb.bundle(), Path::new("rootfs"), &ReapOptions::new(), &rec)
                .expect("reap (host)");
        assert!(r.reclaimed.is_empty(), "{r:?}");
        assert_eq!(r.kept_unverified.len(), 1, "{r:?}");
        assert!(staging.exists());
        let options = ReapOptions::new().with_privilege(sub.clone());
        let r = reap_stale_unpacks_with(&sb.bundle(), Path::new("rootfs"), &options, &rec)
            .expect("reap (subordinate)");
        assert_eq!(r.reclaimed.len(), 1, "{r:?}");
        assert!(!staging.exists());
        println!("rootless_image_rootfs_remove: scenario d2 verified");
        drop(sb);

        // f: core 専有のラッパー（実効 uid 所有・0700）の下の子が subuid 所有・mode 0700 の展開途中の木（#2635）。
        // ラッパーの所有者は崩れないので `Unverified` にならず、権限なしは削除の失敗として残し、権限ありは
        // 通常の経路（ホストでラッパーを開いてロックし、userns の中で消す）で回収する。
        let sb = Sandbox::new("f");
        let wrapper = sb.bundle().join(".fandhe-unpack-3-1");
        std::fs::create_dir(&wrapper).expect("wrapper");
        std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o700)).expect("mode");
        let child = wrapper.join("rootfs");
        std::fs::create_dir(&child).expect("child");
        std::fs::set_permissions(&child, std::fs::Permissions::from_mode(0o700)).expect("mode");
        populate_child(&child, true);
        let rec = OpRecorder::new();
        let r =
            reap_stale_unpacks_with(&sb.bundle(), Path::new("rootfs"), &ReapOptions::new(), &rec)
                .expect("reap (host)");
        assert!(r.reclaimed.is_empty(), "{r:?}");
        assert!(r.kept_unverified.is_empty(), "{r:?}");
        assert_eq!(r.failed.len(), 1, "{r:?}");
        assert_eq!(counts(&rec, "image_rootfs_reap_failed"), (0, 1));
        assert_eq!(counts(&rec, "image_rootfs_reap_kept_unverified"), (0, 0));
        assert!(wrapper.exists());
        let options = ReapOptions::new().with_privilege(sub.clone());
        let r = reap_stale_unpacks_with(&sb.bundle(), Path::new("rootfs"), &options, &rec)
            .expect("reap (subordinate)");
        assert_eq!(r.reclaimed.len(), 1, "{r:?}");
        assert!(r.kept_unverified.is_empty() && r.failed.is_empty(), "{r:?}");
        assert!(!wrapper.exists());
        println!("rootless_image_rootfs_remove: scenario f verified");
        drop(sb);

        // e: 展開に失敗した create の後始末。
        let sb = Sandbox::new("e");
        let store = sb.store();
        let rec = OpRecorder::new();
        let err = create(&sb, &store, &rec, &sub, true).expect_err("unpack fails");
        assert_eq!(err.code(), ErrorCode::Internal);
        assert_eq!(counts(&rec, "image_rootfs_cleanup"), (1, 0));
        let leftovers: Vec<_> = std::fs::read_dir(sb.bundle())
            .expect("read bundle")
            .map(|e| e.expect("entry").file_name())
            .collect();
        assert_eq!(leftovers, vec![std::ffi::OsString::from("config.json")]);
        println!("rootless_image_rootfs_remove: scenario e verified");
    }
}
