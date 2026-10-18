//! イメージストア単位の排他区間（OCI-7・TASK-183.2・MS-4・#473）。
//!
//! `image rm` / `image prune` の GC は「排他取得 → 参照テーブルの数え直し → 削除 → 解放」を単一の
//! 排他区間で行い、その間に参照テーブルを変える操作（create の参照登録・delete の参照解除・
//! `image tag` のタグ登録・`image rm` の untag・pull のリース登録 / 公開 / 解放）を割り込ませない。
//! 本モジュールはその区間を `ImageStore::lock` の RAII ガードとして提供する。
//! 後続の #474・#475（pull）・#476（prune）・#479（tag）・#480 / #481（rm）・#853（create / delete）が使う。
//!
//! # 契約
//!
//! - `ReferenceTable` の変更メソッドはすべて `&mut self` のため、`ImageStore` 経由では
//!   ガード（排他区間）の内側でしか変更できない。読み取りも同じガード越しに行い、GC の数え直しを
//!   区間内に置く。テーブルを `ImageStore` の外へ取り出す API は置かない。
//! - 排他はスレッド間（プロセス内 `Mutex`）とプロセス間（root 直下の `@lock` ファイルへの OS ロック）
//!   の両方に効く。待機は両段で単一の期限を共有し、超過は `Timeout`（REPAIR-5）。
//!   OS ロックは保持プロセスが死ねば OS が解放する。
//! - プロセス内 `Mutex` が毒化していたら `Internal` で拒否する（fail-closed）。区間内で panic すると
//!   テーブルが半端な状態の可能性があり、それを GC が読んで削除を決めると誤削除になりうるため。
//!   OCI-7 の「余分に残す方向にのみ誤る」と整合させる。
//! - `ImageStore` は `Send + Sync`。ガードは `MutexGuard` を含むため `!Send`（取得したスレッドで解放する）。
//! - ガードを保持したまま `StateStore` の操作や start の `BundleLock` を取らない
//!   （create は「排他下で参照登録 → 解放 → レイヤー展開・StateStore 作成」の順。循環させない）。
//!
//! # 未実装・前提（実装済みを装わない。REPAIR-3）
//!
//! - 永続化（#853・#854・#851）が入るまで、テーブルはプロセスごとのメモリ上の別物である。
//!   プロセス間ロックは各プロセスの排他区間の順序を直列化するだけで、内容は同期しない。
//! - root の解決・作成・所有者 / 権限（0700）検査・祖先検査は永続化側の担当。`open` は存在する
//!   ディレクトリ（symlink でない）であることしか見ない。oci には `sys` モジュールが無く
//!   `O_NOFOLLOW` / `O_NONBLOCK` を使えないため、`@lock` の検査から open までの差し替えは
//!   「root は所有者専用」の前提で防ぐ（open 後に通常ファイルであることを再確認する）。

use std::fs::{self, File, OpenOptions, TryLockError};
use std::ops::{Deref, DerefMut};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, TryLockError as MutexTryLockError};
use std::thread;
use std::time::{Duration, Instant};

use super::ReferenceTable;
use crate::error::{OciError, OciErrorCode};
use crate::instrument::{NoopOciOpRecorder, OciOpKind, OciOpRecorder, record_oci_op};

/// ストア root 直下の排他用ロックファイル名。
pub const IMAGE_STORE_LOCK_FILE_NAME: &str = "@lock";

/// 排他区間の取得を待つ既定の上限（REPAIR-5）。
pub const IMAGE_STORE_LOCK_TIMEOUT: Duration = Duration::from_secs(5);

/// ロック取得の再試行間隔。
const LOCK_RETRY_INTERVAL: Duration = Duration::from_millis(5);

/// イメージストアの root と、プロセス内の参照テーブルを束ねる。
///
/// 参照テーブルへの唯一の入口が [`ImageStore::lock`] で、返るガードの生存期間が排他区間になる。
#[derive(Debug)]
pub struct ImageStore {
    root: PathBuf,
    table: Mutex<ReferenceTable>,
    timeout: Duration,
    recorder: Arc<dyn OciOpRecorder>,
}

impl ImageStore {
    /// 空の参照テーブルでストアを開く。root は存在するディレクトリ（symlink 不可）でなければならない。
    pub fn open(root: &Path) -> Result<Self, OciError> {
        Self::with_table(root, ReferenceTable::new())
    }

    /// 既存の参照テーブル（永続化からの読み込み結果。#853 等）でストアを開く。
    pub fn with_table(root: &Path, table: ReferenceTable) -> Result<Self, OciError> {
        // 末尾の区切りがあると symlink_metadata が symlink を辿るため、components で正規化してから判定する。
        let root: PathBuf = root.components().collect();
        if root.as_os_str().is_empty() {
            return Err(OciError::new(
                OciErrorCode::InvalidArgument,
                "image store root is empty",
            ));
        }
        let meta = fs::symlink_metadata(&root).map_err(|e| {
            let code = if e.kind() == std::io::ErrorKind::NotFound {
                OciErrorCode::NotFound
            } else {
                OciErrorCode::Internal
            };
            OciError::new(code, "image store root is not accessible")
        })?;
        if !meta.is_dir() {
            return Err(OciError::new(
                OciErrorCode::FailedPrecondition,
                "image store root is not a directory",
            ));
        }
        Ok(Self {
            root,
            table: Mutex::new(table),
            timeout: IMAGE_STORE_LOCK_TIMEOUT,
            recorder: Arc::new(NoopOciOpRecorder),
        })
    }

    /// 排他区間の取得を待つ上限を差し替える（呼び出し側の期限調整・試験用）。
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// 取得ごとの結果・エラー code・所要時間の記録先を差し替える（REPAIR-4）。既定は記録しない。
    pub fn with_recorder(mut self, recorder: Arc<dyn OciOpRecorder>) -> Self {
        self.recorder = recorder;
        self
    }

    /// ストア root。
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// 排他区間を取得する。スレッド間・プロセス間で他の保持者がいれば期限まで待ち、超過は `Timeout`。
    ///
    /// 取得ごとに成否・エラー code・所要時間を記録先へ渡す（REPAIR-4）。期限が `Instant` で表現できない
    /// ほど長い場合は `InvalidArgument`。
    pub fn lock(&self) -> Result<ImageStoreGuard<'_>, OciError> {
        record_oci_op(&*self.recorder, OciOpKind::AcquireImageStoreLock, || {
            self.lock_inner()
        })
    }

    fn lock_inner(&self) -> Result<ImageStoreGuard<'_>, OciError> {
        let deadline = Instant::now().checked_add(self.timeout).ok_or_else(|| {
            OciError::new(
                OciErrorCode::InvalidArgument,
                "image store lock timeout is too large",
            )
        })?;
        let table = self.lock_table_until(deadline)?;
        let file = open_lock_file(&self.root)?;
        lock_file_until(&file, deadline)?;
        Ok(ImageStoreGuard { _file: file, table })
    }

    fn lock_table_until(
        &self,
        deadline: Instant,
    ) -> Result<MutexGuard<'_, ReferenceTable>, OciError> {
        loop {
            match self.table.try_lock() {
                Ok(g) => return Ok(g),
                Err(MutexTryLockError::Poisoned(_)) => {
                    return Err(OciError::new(
                        OciErrorCode::Internal,
                        "image store lock poisoned",
                    ));
                }
                Err(MutexTryLockError::WouldBlock) => wait_or_timeout(deadline)?,
            }
        }
    }
}

/// 排他区間の RAII ガード。生存中だけ参照テーブルを読み書きでき、drop で区間が終わる。
///
/// フィールド順は drop 順を決める（OS ロック → プロセス内 `Mutex` の順で解放する。取得の逆順）。
#[derive(Debug)]
pub struct ImageStoreGuard<'a> {
    _file: File,
    table: MutexGuard<'a, ReferenceTable>,
}

impl Deref for ImageStoreGuard<'_> {
    type Target = ReferenceTable;

    fn deref(&self) -> &ReferenceTable {
        &self.table
    }
}

impl DerefMut for ImageStoreGuard<'_> {
    fn deref_mut(&mut self) -> &mut ReferenceTable {
        &mut self.table
    }
}

/// 期限内なら再試行間隔だけ待つ。超過は `Timeout`。
fn wait_or_timeout(deadline: Instant) -> Result<(), OciError> {
    if Instant::now() >= deadline {
        return Err(OciError::new(
            OciErrorCode::Timeout,
            "timed out waiting for the image store lock",
        ));
    }
    thread::sleep(LOCK_RETRY_INTERVAL);
    Ok(())
}

fn lock_file_error() -> OciError {
    OciError::new(
        OciErrorCode::Internal,
        "image store lock file is not a regular file",
    )
}

/// `@lock` を開く（無ければ 0600 で作る）。symlink・通常ファイル以外は拒否する。
fn open_lock_file(root: &Path) -> Result<File, OciError> {
    let path = root.join(IMAGE_STORE_LOCK_FILE_NAME);
    let pre = match fs::symlink_metadata(&path) {
        Ok(m) if m.is_file() => Some(m),
        Ok(_) => return Err(lock_file_error()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(_) => {
            return Err(OciError::new(
                OciErrorCode::Internal,
                "failed to inspect the image store lock file",
            ));
        }
    };
    let mut opts = OpenOptions::new();
    opts.create(true).truncate(false).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let file = opts.open(&path).map_err(|_| {
        OciError::new(
            OciErrorCode::Internal,
            "failed to open the image store lock file",
        )
    })?;
    let post = file.metadata().map_err(|_| lock_file_error())?;
    if !post.is_file() {
        return Err(lock_file_error());
    }
    #[cfg(unix)]
    if let Some(pre) = pre {
        use std::os::unix::fs::MetadataExt;
        if pre.dev() != post.dev() || pre.ino() != post.ino() {
            return Err(lock_file_error());
        }
    }
    #[cfg(not(unix))]
    let _ = pre;
    Ok(file)
}

/// OS ロックを期限まで再試行して取る。
fn lock_file_until(file: &File, deadline: Instant) -> Result<(), OciError> {
    loop {
        match file.try_lock() {
            Ok(()) => return Ok(()),
            Err(TryLockError::WouldBlock) => wait_or_timeout(deadline)?,
            Err(TryLockError::Error(_)) => {
                return Err(OciError::new(
                    OciErrorCode::Internal,
                    "failed to lock the image store lock file",
                ));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::image_management::{ContainerRefId, ManifestComposition, PullId, TagKey};
    use crate::reference::{Digest, RegistryHost, Repository, Tag};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};

    const SHORT: Duration = Duration::from_millis(200);

    fn d(n: u8) -> Digest {
        Digest::parse(&format!("sha256:{}", format!("{n:02x}").repeat(32))).expect("digest")
    }

    fn tag(t: &str) -> TagKey {
        TagKey::new(
            RegistryHost::parse("registry.example").expect("host"),
            Repository::parse("lib/app").expect("repo"),
            Tag::parse(t).expect("tag"),
        )
    }

    fn temp_root(label: &str) -> PathBuf {
        static SEQ: AtomicU32 = AtomicU32::new(0);
        let p = std::env::temp_dir().join(format!(
            "fc-oci-store-{}-{}-{label}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&p).expect("mkdir");
        p
    }

    fn seeded_store(label: &str, timeout: Duration) -> (PathBuf, Arc<ImageStore>) {
        let root = temp_root(label);
        let mut t = ReferenceTable::new();
        t.register_manifest(
            d(0xa0),
            ManifestComposition::new(d(0xc1), vec![d(0x10)]).expect("comp"),
        )
        .expect("manifest");
        t.register_tag(tag("keep"), &d(0xa0)).expect("tag");
        t.register_container(ContainerRefId::new("c1").expect("id"), &d(0xa0))
            .expect("container");
        let store = ImageStore::with_table(&root, t)
            .expect("open")
            .with_timeout(timeout);
        (root, Arc::new(store))
    }

    /// OCI-7: 排他区間の保持中、別スレッドの変更操作 6 種はすべて Timeout になり、テーブルは不変。
    #[test]
    fn oci7_lock_blocks_other_thread_reference_ops_until_timeout() {
        type Op = fn(&mut ReferenceTable);
        let ops: [(&str, Op); 6] = [
            ("register_container", |t| {
                let _ = t.register_container(ContainerRefId::new("c2").expect("id"), &d(0xa0));
            }),
            ("unregister_container", |t| {
                let _ = t.unregister_container(&ContainerRefId::new("c1").expect("id"));
            }),
            ("register_tag", |t| {
                let _ = t.register_tag(tag("new"), &d(0xa0));
            }),
            ("unregister_tag", |t| {
                let _ = t.unregister_tag(&tag("keep"));
            }),
            ("acquire_lease", |t| {
                t.acquire_lease(d(0x10), PullId::new("p1").expect("pull"));
            }),
            ("release_lease", |t| {
                let _ = t.release_lease(&d(0x10), &PullId::new("p1").expect("pull"));
            }),
        ];
        for (name, op) in ops {
            let (root, store) = seeded_store(name, SHORT);
            let guard = store.lock().expect("holder");
            let before = (*guard).clone();
            let s2 = Arc::clone(&store);
            let started = Instant::now();
            let waiter = thread::spawn(move || match s2.lock() {
                Ok(mut g) => {
                    op(&mut g);
                    None
                }
                Err(e) => Some((e.code(), started.elapsed())),
            });
            let (code, elapsed) = waiter
                .join()
                .expect("join")
                .unwrap_or_else(|| panic!("{name}: second lock must not succeed while held"));
            assert_eq!(code, OciErrorCode::Timeout, "{name}");
            assert!(
                elapsed >= SHORT && elapsed < Duration::from_secs(5),
                "{name}"
            );
            assert_eq!(*guard, before, "{name}: table must be unchanged");
            drop(guard);
            drop(store);
            let _ = fs::remove_dir_all(&root);
        }
    }

    /// OCI-7: 待機側は解放後に取得でき、先行区間の変更が見える（直列化の順序）。
    #[test]
    fn oci7_waiting_thread_acquires_after_release_and_sees_prior_changes() {
        let (root, store) = seeded_store("serial", Duration::from_secs(5));
        let mut guard = store.lock().expect("holder");
        guard.register_tag(tag("added"), &d(0xa0)).expect("tag");
        let s2 = Arc::clone(&store);
        let waiter = thread::spawn(move || {
            let mut g = s2.lock().expect("acquire after release");
            let seen = g.unregister_tag(&tag("added"));
            (seen, g.manifest_references(&d(0xa0)).count())
        });
        thread::sleep(Duration::from_millis(100));
        drop(guard);
        let (seen, count) = waiter.join().expect("join");
        assert_eq!(seen.expect("added tag visible"), d(0xa0));
        // 残りは keep タグとコンテナ c1 の 2 件。
        assert_eq!(count, 2);
        let _ = fs::remove_dir_all(&root);
    }

    /// OCI-7: 別ハンドル（別プロセス相当）が OS ロックを持つ間は Timeout、閉じれば取得できる。
    #[test]
    fn oci7_other_file_handle_holding_lock_times_out() {
        let (root, store) = seeded_store("handle", SHORT);
        let other = open_lock_file(&root).expect("open lock file");
        lock_file_until(&other, Instant::now() + SHORT).expect("external lock");
        let e = store.lock().expect_err("held elsewhere");
        assert_eq!(e.code(), OciErrorCode::Timeout);
        drop(other);
        store.lock().expect("acquire after external release");
        let _ = fs::remove_dir_all(&root);
    }

    /// OCI-7: 区間内で panic したストアは fail-closed で拒否する。
    #[test]
    fn oci7_poisoned_store_is_rejected() {
        let (root, store) = seeded_store("poison", SHORT);
        let s2 = Arc::clone(&store);
        let r = thread::spawn(move || {
            let _g = s2.lock().expect("lock");
            panic!("simulated failure inside the exclusive section");
        })
        .join();
        assert!(r.is_err());
        let e = store.lock().expect_err("poisoned");
        assert_eq!(e.code(), OciErrorCode::Internal);
        let _ = fs::remove_dir_all(&root);
    }

    /// OCI-7: root が不在・非ディレクトリなら開けない。
    #[test]
    fn oci7_open_rejects_missing_or_non_directory_root() {
        let root = temp_root("badroot");
        let missing = root.join("nope");
        assert_eq!(
            ImageStore::open(&missing).expect_err("missing").code(),
            OciErrorCode::NotFound
        );
        let file = root.join("file");
        fs::write(&file, b"x").expect("write");
        assert_eq!(
            ImageStore::open(&file).expect_err("file").code(),
            OciErrorCode::FailedPrecondition
        );
        let _ = fs::remove_dir_all(&root);
    }

    /// OCI-7: 表現不能な巨大 timeout は panic せず InvalidArgument。
    #[test]
    fn oci7_huge_timeout_is_invalid_argument() {
        let root = temp_root("huge");
        let store = ImageStore::open(&root)
            .expect("open")
            .with_timeout(Duration::MAX);
        assert_eq!(
            store.lock().expect_err("huge").code(),
            OciErrorCode::InvalidArgument
        );
        let _ = fs::remove_dir_all(&root);
    }

    /// REPAIR-4: 成功・Timeout が種別 oci.store.lock として記録される。
    #[test]
    fn oci7_lock_outcomes_are_recorded() {
        use crate::instrument::OciOpOutcome;
        use crate::instrument::testing::Collect;
        let (root, store) = seeded_store("rec", SHORT);
        let rec = Arc::new(Collect::default());
        let store = Arc::try_unwrap(store)
            .expect("unique")
            .with_recorder(rec.clone());
        let g = store.lock().expect("first");
        let e = store.lock().expect_err("timeout");
        assert_eq!(e.code(), OciErrorCode::Timeout);
        drop(g);
        let items = rec.items();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].kind(), OciOpKind::AcquireImageStoreLock);
        assert_eq!(items[0].outcome(), OciOpOutcome::Success);
        assert_eq!(items[1].outcome(), OciOpOutcome::Failure);
        assert_eq!(items[1].error_code(), Some(OciErrorCode::Timeout));
        assert!(items[1].latency() >= SHORT);
        let _ = fs::remove_dir_all(&root);
    }

    /// OCI-7: 末尾区切り付きの symlink root も拒否する。
    #[cfg(unix)]
    #[test]
    fn oci7_open_rejects_symlink_root_with_trailing_slash() {
        let base = temp_root("symroot");
        let real = base.join("real");
        fs::create_dir(&real).expect("mkdir");
        let link = base.join("link");
        std::os::unix::fs::symlink(&real, &link).expect("symlink");
        let slashed = PathBuf::from(format!("{}/", link.display()));
        assert_eq!(
            ImageStore::open(&slashed).expect_err("symlink").code(),
            OciErrorCode::FailedPrecondition
        );
        let _ = fs::remove_dir_all(&base);
    }

    /// OCI-7: `@lock` がディレクトリなら拒否する。
    #[test]
    fn oci7_lock_rejects_non_regular_lock_file() {
        let root = temp_root("lockdir");
        fs::create_dir(root.join(IMAGE_STORE_LOCK_FILE_NAME)).expect("mkdir");
        let store = ImageStore::open(&root).expect("open").with_timeout(SHORT);
        assert_eq!(
            store.lock().expect_err("dir").code(),
            OciErrorCode::Internal
        );
        let _ = fs::remove_dir_all(&root);
    }

    /// OCI-7: `@lock` が symlink なら拒否し、リンク先を作らない・変えない。
    #[cfg(unix)]
    #[test]
    fn oci7_lock_rejects_symlink_lock_file() {
        let root = temp_root("locklink");
        let target = root.join("target");
        fs::write(&target, b"keep").expect("write");
        std::os::unix::fs::symlink(&target, root.join(IMAGE_STORE_LOCK_FILE_NAME))
            .expect("symlink");
        let store = ImageStore::open(&root).expect("open").with_timeout(SHORT);
        assert_eq!(
            store.lock().expect_err("symlink").code(),
            OciErrorCode::Internal
        );
        assert_eq!(fs::read(&target).expect("read"), b"keep");
        let _ = fs::remove_dir_all(&root);
    }

    /// OCI-7: 作成された `@lock` は所有者専用（0600）。
    #[cfg(unix)]
    #[test]
    fn oci7_lock_file_is_created_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let root = temp_root("mode");
        let store = ImageStore::open(&root).expect("open");
        drop(store.lock().expect("lock"));
        let mode = fs::metadata(root.join(IMAGE_STORE_LOCK_FILE_NAME))
            .expect("meta")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        let _ = fs::remove_dir_all(&root);
    }
}
