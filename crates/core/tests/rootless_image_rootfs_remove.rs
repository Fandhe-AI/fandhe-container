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
//! - `g`: イメージの `./` が subuid 所有・mode 0700（rootless の展開器が最上位を chown する）で、権限なし
//!   （`HostEffectiveIds`）の create は seal で明示エラーにして拒否する。後始末もホストでは消せず、残った
//!   ラッパーは権限ありの回収が消す（#2690。暗黙に userns へ昇格しない）
//! - `h`: 同じ構成で権限あり（`SubordinateIds`）の create は、印の書き込みと最終の名前への改名を userns の中で
//!   行って成功し、最上位の mode が元（0700）に戻っている。delete が木を消す（#2690）
//! - `i2`: 公開済みで状態の無い、最上位が subuid 所有・mode 0700 の木（公開後・状態作成前のクラッシュの跡を、
//!   状態の削除で再現）を、確かめられない場合は残して `AlreadyExists` で拒否する（#2769。fail-closed）。
//!   権限なし（`HostEffectiveIds`）は昇格せず残し、別の状態ルートのストアは `ForeignStateRoot` として残し、
//!   印の無い 0700・subuid 所有のディレクトリも残す
//! - `i`: 同じ残骸を、元のストアと権限あり（`SubordinateIds`）の次の create が userns の中で孤児と確かめて
//!   回収し、`AlreadyExists` で止まらずに新しい木を公開する（#2769。`image_rootfs_orphan_reap` 成功 1 件）
//! - `h2`: 同じ構成で最上位が mode 0555 のとき、mode が 0555 に戻り、ホストから読める印が実効 uid 所有・
//!   0400・nlink 1 で残る（孤児の回収の厳格照合と整合。#2690）
//!
//! # 実機前提テストとしての分離
//! `harness = false` の単一スレッド `main`（fork と `CLONE_NEWUSER` の前提）。非特権 user namespace を許可する
//! ホストと、`uidmap`（setuid の `newuidmap` / `newgidmap`）・自分の subuid / subgid の行が要る。
//! `-- --ignored` 指定時のみ実行し、未指定時は「ignored」を出力して成功終了する（ci.md「実機前提テスト」）。
//! 実行された場合は前提の欠落を含むあらゆる失敗を失敗として扱う。root では実行しない。

#[path = "support/reap.rs"]
mod reap;

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("rootless_image_rootfs_remove: Linux only, not applicable on this OS");
}

// 前提欠如を `PRECONDITION FAILED` の 1 行目で失敗させる共有部品（#2888・REPAIR-12）。
#[cfg(target_os = "linux")]
#[path = "support/precondition.rs"]
mod precondition;

#[cfg(target_os = "linux")]
fn main() {
    // 分類の自己照合（既定のテスト集合でも常に走る。出力はしない）。
    precondition::self_check();
    let args: Vec<String> = std::env::args().collect();
    if let Some(i) = args.iter().position(|a| a == "--populate") {
        let dir = args.get(i + 1).expect("directory after --populate");
        let root_mode = args.iter().position(|a| a == "--chown-root").map(|j| {
            args.get(j + 1)
                .and_then(|m| u32::from_str_radix(m, 8).ok())
                .expect("octal mode after --chown-root")
        });
        linux::populate(dir, root_mode);
    } else if let Some(i) = args.iter().position(|a| a == "--purge") {
        let dir = args.get(i + 1).expect("directory after --purge");
        linux::purge(dir);
    } else if args.iter().any(|a| a == "--ignored") {
        linux::run();
    } else {
        println!(
            "rootless_image_rootfs_remove: ignored (real-machine test; run with `-- --ignored`, see AGENTS.md)"
        );
    }
}

#[cfg(target_os = "linux")]
#[path = "support/scratch_root.rs"]
mod scratch_root;

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
        DeleteStateRequest, ErrorCode, GetStateRequest, ImageRootfsOwnership, StateRevision,
        StateStore, TraitError,
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
    /// `root_mode` が `Some` なら、木の最上位 `dir` 自身も subuid 所有・その mode にする（展開途中でクラッシュした
    /// 木や、イメージの `./` が root 以外の所有の再現。ホストの実効 uid ではロック用に開き直せない）。
    pub fn populate(dir: &str, root_mode: Option<u32>) {
        // userns に入る前にディレクトリを開く（入った後は親の `/proc/<pid>/fd` に頼らない）。
        let root = std::fs::File::open(dir).expect("open target dir");
        enter_userns();
        let base = PathBuf::from(format!("/proc/self/fd/{}", root.as_raw_fd()));
        let sub = base.join("sub");
        std::fs::create_dir(&sub).expect("mkdir sub");
        std::fs::write(sub.join("f"), b"owned by a subordinate id").expect("write f");
        std::fs::set_permissions(sub.join("f"), std::fs::Permissions::from_mode(0o444))
            .expect("chmod f");
        std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o555)).expect("chmod sub");
        std::os::unix::fs::chown(sub.join("f"), Some(1), Some(1)).expect("chown f");
        std::os::unix::fs::chown(&sub, Some(1), Some(1)).expect("chown sub");
        if let Some(mode) = root_mode {
            std::fs::set_permissions(&base, std::fs::Permissions::from_mode(mode))
                .expect("chmod root");
            std::os::unix::fs::chown(&base, Some(1), Some(1)).expect("chown root");
        }
    }

    /// 後始末の役の子: userns の中で `dir` を中身ごと消す（最上位が subuid 所有・0700 でホストからは開けないため）。
    /// 印の無い subuid 所有の木のように、core の回収が（意図して）消さない残骸の掃除に使う。
    pub fn purge(dir: &str) {
        // 最上位が subuid 所有・0700 のため、ホストの uid では開けない。userns に入ってから経路で開く。
        enter_userns();
        let base = PathBuf::from(dir);
        for entry in std::fs::read_dir(&base).expect("read dir") {
            let path = entry.expect("entry").path();
            if path.is_dir() {
                std::fs::remove_dir_all(&path).expect("remove dir");
            } else {
                std::fs::remove_file(&path).expect("remove file");
            }
        }
        // 親（bundle）はホストの実効 uid 所有で userns の中では uid 0 の所有なので、空の `dir` 自身も消せる。
        std::fs::remove_dir(&base).expect("remove dir itself");
    }

    /// 子の user namespace に入る（コンテナ 0 → 自 euid、1.. → subuid 範囲）。
    fn enter_userns() {
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
    }

    /// `--purge` の子を期限つきで実行し、`dir` の中身を userns の中で消す（REPAIR-5）。
    fn purge_via_child(dir: &Path) {
        let exe = std::env::current_exe().expect("current exe");
        let mut child = Command::new(exe)
            .arg("--purge")
            .arg(dir)
            .spawn()
            .expect("spawn purge child");
        let deadline = Instant::now() + CHILD_DEADLINE;
        loop {
            match child.try_wait().expect("try_wait") {
                Some(status) => {
                    assert!(status.success(), "purge child failed: {status}");
                    return;
                }
                None if Instant::now() >= deadline => {
                    crate::reap::reap_or_report(&mut child, crate::reap::REAP_WITHIN);
                    panic!("purge child timed out");
                }
                None => std::thread::sleep(Duration::from_millis(50)),
            }
        }
    }

    /// 公開後・状態作成前のクラッシュの跡を作る: 権限ありで最上位が subuid 所有・0700 の木を公開して状態を
    /// 作らせ、その状態だけを消す（木と v3 の印は残る）。残った木の (dev, ino) を返す。
    fn make_published_orphan(
        sb: &Sandbox,
        store: &dyn StateStore,
        sub: &ImageRootfsPrivilege,
    ) -> (u64, u64) {
        create_rooted(sb, store, &OpRecorder::new(), sub, false, Some(0o700))
            .expect("create (0700 top)");
        let id = ContainerId::new("c1").expect("id");
        let record = store.get(&GetStateRequest::new(id.clone())).expect("state");
        store
            .delete(&DeleteStateRequest::new(id, record.revision()))
            .expect("drop only the state record");
        let meta = std::fs::metadata(sb.rootfs()).expect("stat orphan");
        assert_ne!(meta.uid(), euid(), "orphan top must be subordinate-owned");
        assert_eq!(meta.permissions().mode() & 0o7777, 0o700);
        (meta.dev(), meta.ino())
    }

    /// 本試験バイナリを `--populate` で再実行して、`dir`（親のプロセスが保持する fd を指す経路でも可）に
    /// subuid 所有の木を作らせる。子の待ちは期限つきで、超えたら kill して失敗にする（REPAIR-5）。
    fn populate_via_child(dir: &Path) {
        populate_child(dir, None);
    }

    fn populate_child(dir: &Path, root_mode: Option<u32>) {
        // `/proc/self/fd/N` は子から見ると別のプロセスの fd なので、親の pid の経路へ読み替える。
        let text = dir.to_string_lossy();
        let path = match text.strip_prefix("/proc/self/") {
            Some(rest) => format!("/proc/{}/{rest}", std::process::id()),
            None => text.into_owned(),
        };
        let exe = std::env::current_exe().expect("current exe");
        let mut cmd = Command::new(exe);
        cmd.args(["--populate", &path]);
        if let Some(mode) = root_mode {
            cmd.args(["--chown-root", &format!("{mode:o}")]);
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
                    crate::reap::reap_or_report(&mut child, crate::reap::REAP_WITHIN);
                    panic!("populate child timed out");
                }
                None => std::thread::sleep(Duration::from_millis(50)),
            }
        }
    }

    struct Populating {
        fail: bool,
        /// `Some` なら最上位自身も subuid 所有にして、その mode にする（イメージの `./` が root 以外の所有）。
        root_mode: Option<u32>,
    }

    impl ImageRootfsUnpacker for Populating {
        fn unpack(
            &self,
            _manifest: &ImageManifestDigest,
            rootfs: &Path,
        ) -> Result<ImageRootfsUnpacked, TraitError> {
            populate_child(rootfs, self.root_mode);
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
            let tmp = super::scratch_root::scratch_root(
                "fandhe-rootless-rootfs-scratch",
                std::time::Duration::from_secs(10),
            );
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
        create_rooted(sb, store, rec, privilege, fail, None)
    }

    /// [`create`] に、最上位自身の所有・mode（`Some(mode)`）を指定したもの。
    fn create_rooted(
        sb: &Sandbox,
        store: &dyn StateStore,
        rec: &OpRecorder,
        privilege: &ImageRootfsPrivilege,
        fail: bool,
        root_mode: Option<u32>,
    ) -> Result<(), fandhe_container_core::oci_runtime::OciRuntimeError> {
        let manifest = ImageManifestDigest::new(MANIFEST).expect("digest");
        let unpacker = Populating { fail, root_mode };
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
        // 一時領域の親ディレクトリ（tmpfiles の掃除と flock 競合の回避）を panic でも消す（#2887）。
        let _scratch_cleanup = super::scratch_root::ScratchRootCleanup;
        let euid = euid();
        assert_ne!(euid, 0, "this test must run as a non-root user");
        // 前提（`USER`・`uidmap`・subuid / subgid の自ユーザー行）の欠如は回帰と見分けられる 1 行目で失敗させる（#2888）。
        crate::precondition::require_subordinate_ids(euid);
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
        let resp =
            delete(&store, &rec, host.clone()).expect("delete succeeds even if the tree is kept");
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
        populate_child(&staging, Some(0o700));
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
        populate_child(&child, Some(0o700));
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

        // g: イメージの `./` が subuid 所有・mode 0700。権限なしは seal で明示エラーにして拒否する（#2690）。
        let sb = Sandbox::new("g");
        let store = sb.store();
        let rec = OpRecorder::new();
        let err = create_rooted(&sb, &store, &rec, &host, false, Some(0o700))
            .expect_err("create without privilege must be rejected");
        assert_eq!(err.code(), ErrorCode::Internal, "{err:?}");
        assert!(
            err.message()
                .contains("cannot make unpacked root writable for rename"),
            "{}",
            err.message()
        );
        // ホストの ID では後始末もできない。最終の名前は無く、予約名のラッパーが残る。
        assert_eq!(counts(&rec, "image_rootfs_cleanup"), (0, 1));
        assert!(!sb.rootfs().exists());
        let wrappers: Vec<_> = std::fs::read_dir(sb.bundle())
            .expect("read bundle")
            .map(|e| e.expect("entry").file_name())
            .filter(|n| n.to_string_lossy().starts_with(".fandhe-unpack-"))
            .collect();
        assert_eq!(wrappers.len(), 1, "{wrappers:?}");
        let options = ReapOptions::new().with_privilege(sub.clone());
        let r = reap_stale_unpacks_with(&sb.bundle(), Path::new("rootfs"), &options, &rec)
            .expect("reap (subordinate)");
        assert_eq!(r.reclaimed.len(), 1, "{r:?}");
        let leftovers: Vec<_> = std::fs::read_dir(sb.bundle())
            .expect("read bundle")
            .map(|e| e.expect("entry").file_name())
            .collect();
        assert_eq!(leftovers, vec![std::ffi::OsString::from("config.json")]);
        println!("rootless_image_rootfs_remove: scenario g verified");
        drop(store);
        drop(sb);

        // h: 同じ構成で権限あり。印の書き込みと改名が userns の中で行われて成功する（#2690）。
        let sb = Sandbox::new("h");
        let store = sb.store();
        let rec = OpRecorder::new();
        create_rooted(&sb, &store, &rec, &sub, false, Some(0o700))
            .expect("create with subordinate privilege");
        let record = store
            .get(&fandhe_container_core::traits::GetStateRequest::new(
                ContainerId::new("c1").expect("id"),
            ))
            .expect("state");
        assert_eq!(
            record.image_rootfs().map(|r| r.ownership()),
            Some(ImageRootfsOwnership::SubordinateIds)
        );
        let meta = std::fs::metadata(sb.rootfs()).expect("stat rootfs");
        assert_ne!(meta.uid(), euid, "rootfs must stay subordinate-owned");
        assert_eq!(meta.permissions().mode() & 0o7777, 0o700);
        let wrappers = std::fs::read_dir(sb.bundle())
            .expect("read bundle")
            .filter(|e| {
                e.as_ref()
                    .expect("entry")
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".fandhe-unpack-")
            })
            .count();
        assert_eq!(wrappers, 0, "wrapper must be removed after publish");
        let rec = OpRecorder::new();
        let resp = delete(&store, &rec, sub.clone()).expect("delete");
        assert_eq!(resp.image_rootfs(), CleanupOutcome::Removed);
        assert_eq!(counts(&rec, "image_rootfs_remove"), (1, 0));
        assert!(!sb.rootfs().exists());
        println!("rootless_image_rootfs_remove: scenario h verified");
        drop(store);
        drop(sb);

        // h2: 最上位が mode 0555。mode が戻り、ホストから読める印が実効 uid 所有・0400・nlink 1 で残る。
        let sb = Sandbox::new("h2");
        let store = sb.store();
        let rec = OpRecorder::new();
        create_rooted(&sb, &store, &rec, &sub, false, Some(0o555))
            .expect("create with subordinate privilege (0555)");
        let meta = std::fs::metadata(sb.rootfs()).expect("stat rootfs");
        assert_ne!(meta.uid(), euid, "rootfs must stay subordinate-owned");
        assert_eq!(meta.permissions().mode() & 0o7777, 0o555);
        let marker = std::fs::metadata(sb.rootfs().join(".fandhe-container-rootfs-owner"))
            .expect("stat marker");
        assert_eq!(marker.uid(), euid);
        assert_eq!(marker.permissions().mode() & 0o7777, 0o400);
        assert_eq!(marker.nlink(), 1);
        let resp = delete(&store, &OpRecorder::new(), sub.clone()).expect("delete");
        assert_eq!(resp.image_rootfs(), CleanupOutcome::Removed);
        println!("rootless_image_rootfs_remove: scenario h2 verified");
        drop(store);
        drop(sb);

        // i2: 公開済みで状態の無い 0700・subuid 所有の木。確かめられないものは残して AlreadyExists で拒否する。
        let sb = Sandbox::new("i");
        let store = sb.store();
        let tree = make_published_orphan(&sb, &store, &sub);
        let same_tree = |tag: &str| {
            let m = std::fs::metadata(sb.rootfs()).expect("stat kept tree");
            assert_eq!((m.dev(), m.ino()), tree, "tree must be kept ({tag})");
        };
        // (1) 権限なしは userns へ昇格せず、残して拒否する。
        let rec = OpRecorder::new();
        let err = create_rooted(&sb, &store, &rec, &host, false, Some(0o700))
            .expect_err("host privilege must not reclaim");
        assert_eq!(err.code(), ErrorCode::AlreadyExists, "{err:?}");
        assert_eq!(counts(&rec, "image_rootfs_orphan_reap"), (0, 1));
        same_tree("host");
        // (2) 別の状態ルートのストアからは、印の状態ルートの識別子が合わず残す。
        let other =
            FileStateStore::open(StateRoot::from_override(sb.dir.join("state2")).expect("root2"))
                .expect("open store2");
        let rec = OpRecorder::new();
        let err = create_rooted(&sb, &other, &rec, &sub, false, Some(0o700))
            .expect_err("foreign state root must not reclaim");
        assert_eq!(err.code(), ErrorCode::AlreadyExists, "{err:?}");
        assert_eq!(counts(&rec, "image_rootfs_orphan_reap"), (0, 1));
        same_tree("foreign state root");
        // (3) 印の無い 0700・subuid 所有のディレクトリ（利用者のデータかもしれない）は残す。
        let sb2 = Sandbox::new("i2b");
        let store2 = sb2.store();
        std::fs::create_dir(sb2.rootfs()).expect("mkdir rootfs");
        std::fs::set_permissions(sb2.rootfs(), std::fs::Permissions::from_mode(0o700))
            .expect("mode");
        populate_child(&sb2.rootfs(), Some(0o700));
        let rec = OpRecorder::new();
        let err = create_rooted(&sb2, &store2, &rec, &sub, false, Some(0o700))
            .expect_err("markerless tree must not be reclaimed");
        assert_eq!(err.code(), ErrorCode::AlreadyExists, "{err:?}");
        assert_eq!(counts(&rec, "image_rootfs_orphan_reap"), (0, 1));
        assert!(
            std::fs::metadata(sb2.rootfs()).is_ok(),
            "markerless tree must be kept"
        );
        purge_via_child(&sb2.rootfs());
        drop(store2);
        drop(sb2);
        println!("rootless_image_rootfs_remove: scenario i2 verified");

        // i: 同じ残骸を、元のストアと権限ありの次の create が孤児と確かめて回収し、新しい木を公開する。
        let rec = OpRecorder::new();
        create_rooted(&sb, &store, &rec, &sub, false, Some(0o700))
            .expect("create reclaims the 0700 orphan");
        assert_eq!(counts(&rec, "image_rootfs_orphan_reap"), (1, 0));
        let meta = std::fs::metadata(sb.rootfs()).expect("stat new rootfs");
        assert_ne!(meta.uid(), euid, "new rootfs must stay subordinate-owned");
        assert_eq!(meta.permissions().mode() & 0o7777, 0o700);
        let resp = delete(&store, &OpRecorder::new(), sub.clone()).expect("delete");
        assert_eq!(resp.image_rootfs(), CleanupOutcome::Removed);
        assert!(!sb.rootfs().exists());
        println!("rootless_image_rootfs_remove: scenario i verified");
        drop(other);
        drop(store);
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
