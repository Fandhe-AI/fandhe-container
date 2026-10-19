//! pull 経路のリース登録とステージング領域の確保（OCI-7・TASK-183.9・MS-4・#474）。
//!
//! GC（`image rm` / `image prune`）が「参照あり」とみなす根拠は参照テーブルだけである。進行中の pull が
//! 使う blob を GC に消させないため、pull は次の 2 つを守る。
//!
//! - (A) 既存 blob の再利用: 使う前に、排他区間（[`ImageStore::lock`]）の下で自分の [`PullId`] の
//!   リースを登録する（[`PullSession::lease_existing_blob`]）。各 pull は自分の ID のリースだけに触れる。
//! - (B) 新規取得 blob: GC の走査対象外のステージング領域 `<root>/staging/<pull-id>/` へ書く
//!   （[`PullSession::staged_blob_path`]）。`blobs/sha256` には公開するまで何も置かないため、
//!   書き込み中のファイルは `image ls` にも参照テーブルの走査にも現れない。
//!
//! 呼び出し文脈: pull の全体処理（レジストリ取得 → 検証 → 公開）から使う想定である。
//! `RegistryClient::fetch_blob` の `dest` には [`PullSession::staged_blob_path`] の戻り値を渡す。
//! cri の `image_pull` からの配線は後続で扱う（本モジュールは oci 内で完結する）。
//!
//! ロックの規律: ガードを持ったままファイルの検査・digest 検証・通信をしない。順序は
//! 「リース登録 → 使う」に固定する。並行する prune はガードの内側でリースを数え直すため、
//! 登録後に blob が消されることはない（OCI-7 の「余分に残す方向にのみ誤る」）。
//!
//! 未実装（実装済みを装わない。REPAIR-3）:
//! - 公開（ステージングから `blobs/sha256` への移動・manifest とタグの登録・自分のリースの解放を
//!   不可分に行う）と、失敗・中断時のロールバック（リース解放とステージング削除）は #475。
//!   `PullSession` に `Drop` は実装しない。drop 後もリースとステージングは残る（余分に残す側）。
//! - クラッシュ後に残ったリース・ステージングの回収 GC は #852・#477。
//! - `system df` でのステージング容量の集計。永続化は #853・#854・#851。

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use super::{ImageStore, MAX_COMPOSITION_LAYERS, PullId};
use crate::error::{OciError, OciErrorCode};
use crate::instrument::{OciOpKind, OciOpRecorder, record_oci_op};
use crate::reference::Digest;

/// ストア root 直下のステージング領域名。GC・`image ls` の走査対象外。
const STAGING_DIR_NAME: &str = "staging";

/// 1 つの pull セッションが触れる blob 件数の上限（config 1 件 + layers）。
const MAX_SESSION_BLOBS: usize = MAX_COMPOSITION_LAYERS + 1;

static PULL_SEQ: AtomicU64 = AtomicU64::new(0);

/// セッション識別子の採番。トークンの発行元照合に使う（プロセス内で一意）。
static SESSION_SEQ: AtomicU64 = AtomicU64::new(1);

fn err(code: OciErrorCode, msg: &str) -> OciError {
    OciError::new(code, msg)
}

impl PullId {
    /// 新しい pull ID を作る。形式は `<pid>-<UNIX 時刻ナノ秒>-<プロセス内連番>`（数字と `-` だけ）。
    ///
    /// PID を含めるのは、クラッシュ回収（#852）が pull プロセスの不在確認の手がかりにできるため。
    /// PID の再利用への対処は #852 の判断に残す。
    pub fn generate() -> Result<Self, OciError> {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let seq = PULL_SEQ.fetch_add(1, Ordering::Relaxed);
        Self::new(&format!("{}-{nanos}-{seq}", std::process::id()))
    }
}

/// 既存 blob の再利用を試みた結果。
#[derive(Debug)]
#[non_exhaustive]
pub enum BlobReuse {
    /// リースを登録済みで、再利用候補のパスを持つ。内容の検証は呼び出し側の責務。
    Leased(LeasedBlob),
    /// キャッシュに無い（取得が必要）。リースは残していない。
    Absent,
    /// 通常ファイルでない（symlink 等。辿らない）。リースは残していない。
    NotRegularFile,
}

/// リース登録済みの既存 blob へのトークン。作れるのは [`PullSession::lease_existing_blob`] だけで、
/// 「使う前にリースを登録する」順序を型で強制する。「検証済み」は意味しない。
#[derive(Debug)]
pub struct LeasedBlob {
    digest: Digest,
    path: PathBuf,
    /// 発行元セッションの識別子。別セッション・別ストアのトークンによる解放を拒否するための照合用。
    session: u64,
}

impl LeasedBlob {
    /// blob の digest。
    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    /// `<root>/blobs/sha256/<hex>`。開くときは symlink を辿らず、digest を検証してから使う。
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// 進行中の pull 1 件。`PullId` のリース登録とステージング領域を束ねる。
#[derive(Debug)]
pub struct PullSession<'a> {
    store: &'a ImageStore,
    id: PullId,
    /// このセッション固有の識別子（`LeasedBlob` の発行元照合）。
    session: u64,
    staging_dir: PathBuf,
    touched: BTreeSet<Digest>,
    /// 現在リースを保持している digest。同一 digest の二重取得を拒否して、
    /// 1 リース = 1 トークンを保つ（片方の解放で他方のリースが消えないようにする）。
    leased: BTreeSet<Digest>,
}

fn hex_of(digest: &Digest) -> Result<&str, OciError> {
    digest
        .as_str()
        .strip_prefix("sha256:")
        .ok_or_else(|| err(OciErrorCode::Internal, "unsupported digest algorithm"))
}

fn io_err(e: &std::io::Error, msg: &str) -> OciError {
    let code = if e.kind() == std::io::ErrorKind::AlreadyExists {
        OciErrorCode::AlreadyExists
    } else {
        OciErrorCode::Internal
    };
    err(code, msg)
}

fn make_dir(path: &Path) -> std::io::Result<()> {
    #[cfg_attr(not(unix), allow(unused_mut))]
    let mut b = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(0o700);
    }
    b.create(path)
}

/// `staging` が symlink でない通常ディレクトリであることを確かめる。
fn check_staging_is_dir(staging: &Path) -> Result<(), OciError> {
    let m = fs::symlink_metadata(staging).map_err(|e| io_err(&e, "failed to stat staging"))?;
    if m.is_dir() {
        Ok(())
    } else {
        Err(err(
            OciErrorCode::FailedPrecondition,
            "staging is not a directory",
        ))
    }
}

impl ImageStore {
    /// 指定の ID で pull セッションを始め、`<root>/staging/<pull-id>/` を作る。
    ///
    /// 同じ ID のディレクトリが既にあれば `AlreadyExists`（二重利用させない）。`staging` が
    /// symlink・非ディレクトリなら `FailedPrecondition`。
    /// 記録先は [`ImageStore::with_recorder`] で設定したもの（REPAIR-4）。
    pub fn begin_pull(&self, id: PullId) -> Result<PullSession<'_>, OciError> {
        self.begin_pull_with(self.recorder(), id)
    }

    /// [`ImageStore::begin_pull`] の全体（重複 ID・非ディレクトリ・作成失敗を含む）を
    /// `OciOpKind::BeginPull` として `recorder` へ記録する（REPAIR-4）。
    pub fn begin_pull_with(
        &self,
        recorder: &dyn OciOpRecorder,
        id: PullId,
    ) -> Result<PullSession<'_>, OciError> {
        record_oci_op(recorder, OciOpKind::BeginPull, || self.begin_pull_inner(id))
    }

    fn begin_pull_inner(&self, id: PullId) -> Result<PullSession<'_>, OciError> {
        let staging = self.root().join(STAGING_DIR_NAME);
        match fs::symlink_metadata(&staging) {
            Ok(_) => check_staging_is_dir(&staging)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => match make_dir(&staging) {
                Ok(()) => {}
                // 並行する別 pull が先に作った場合は、作られたものを再検査する。
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    check_staging_is_dir(&staging)?
                }
                Err(e) => return Err(io_err(&e, "failed to create staging")),
            },
            Err(e) => return Err(io_err(&e, "failed to stat staging")),
        }
        let dir = staging.join(id.as_str());
        make_dir(&dir).map_err(|e| io_err(&e, "failed to create pull staging directory"))?;
        Ok(PullSession {
            store: self,
            id,
            session: SESSION_SEQ.fetch_add(1, Ordering::Relaxed),
            staging_dir: dir,
            touched: BTreeSet::new(),
            leased: BTreeSet::new(),
        })
    }

    /// ID を生成して [`ImageStore::begin_pull`] する。
    pub fn begin_pull_generated(&self) -> Result<PullSession<'_>, OciError> {
        self.begin_pull_generated_with(self.recorder())
    }

    /// ID を生成して [`ImageStore::begin_pull_with`] する。
    pub fn begin_pull_generated_with(
        &self,
        recorder: &dyn OciOpRecorder,
    ) -> Result<PullSession<'_>, OciError> {
        self.begin_pull_with(recorder, PullId::generate()?)
    }
}

impl PullSession<'_> {
    /// この pull の ID。
    pub fn id(&self) -> &PullId {
        &self.id
    }

    /// この pull のステージングディレクトリ。
    pub fn staging_dir(&self) -> &Path {
        &self.staging_dir
    }

    fn note_blob(&mut self, digest: &Digest) -> Result<(), OciError> {
        if !self.touched.contains(digest) && self.touched.len() >= MAX_SESSION_BLOBS {
            return Err(err(
                OciErrorCode::ResourceExhausted,
                "too many blobs in one pull",
            ));
        }
        self.touched.insert(digest.clone());
        Ok(())
    }

    /// 既存 blob を再利用する前に、自分の `PullId` のリースを排他下で登録する（OCI-7）。
    ///
    /// 登録後にキャッシュ上の実体を調べ、通常ファイルでなければ自分のリースだけを外して
    /// [`BlobReuse::Absent`] / [`BlobReuse::NotRegularFile`] を返す。
    ///
    /// 同じ digest のトークンが未解放のうちに再度呼ぶと `AlreadyExists`（1 リース = 1 トークン）。
    pub fn lease_existing_blob(&mut self, digest: &Digest) -> Result<BlobReuse, OciError> {
        let recorder = self.store.recorder();
        record_oci_op(recorder, OciOpKind::LeaseBlob, || {
            self.lease_existing_blob_inner(digest)
        })
    }

    fn lease_existing_blob_inner(&mut self, digest: &Digest) -> Result<BlobReuse, OciError> {
        self.note_blob(digest)?;
        if self.leased.contains(digest) {
            return Err(err(
                OciErrorCode::AlreadyExists,
                "blob is already leased by this pull",
            ));
        }
        let path = self
            .store
            .root()
            .join("blobs")
            .join("sha256")
            .join(hex_of(digest)?);
        {
            let mut guard = self.store.lock()?;
            guard.acquire_lease(digest.clone(), self.id.clone());
        }
        let miss = match fs::symlink_metadata(&path) {
            Ok(m) if m.is_file() => None,
            Ok(_) => Some(BlobReuse::NotRegularFile),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Some(BlobReuse::Absent),
            Err(e) => {
                self.release_own(digest)?;
                return Err(io_err(&e, "failed to stat cached blob"));
            }
        };
        match miss {
            None => {
                self.leased.insert(digest.clone());
                Ok(BlobReuse::Leased(LeasedBlob {
                    digest: digest.clone(),
                    path,
                    session: self.session,
                }))
            }
            Some(r) => {
                self.release_own(digest)?;
                Ok(r)
            }
        }
    }

    /// 検証失敗などで再利用をやめるとき、トークンを消費して自分のリースだけを外す。
    ///
    /// 別セッション・別ストアが発行したトークンは `PermissionDenied` で拒否し、テーブルを変えない。
    pub fn release_leased(&mut self, blob: LeasedBlob) -> Result<(), OciError> {
        let recorder = self.store.recorder();
        record_oci_op(recorder, OciOpKind::ReleaseBlobLease, || {
            self.release_leased_inner(blob)
        })
    }

    fn release_leased_inner(&mut self, blob: LeasedBlob) -> Result<(), OciError> {
        if blob.session != self.session || !self.leased.contains(&blob.digest) {
            return Err(err(
                OciErrorCode::PermissionDenied,
                "lease token does not belong to this pull",
            ));
        }
        // トークンは値で消費済みのため、解放が一時的に失敗（ロックの Timeout 等）しても `leased` に
        // digest を残すと再 lease も再解放もできず固着する。先に外して、テーブル側のリースが残った
        // 場合は `lease_existing_blob` の再呼び出し（登録は冪等）で新トークンを得て解放し直せる。
        self.leased.remove(&blob.digest);
        self.release_own(&blob.digest)
    }

    fn release_own(&self, digest: &Digest) -> Result<(), OciError> {
        let mut guard = self.store.lock()?;
        guard.release_lease(digest, &self.id)
    }

    /// 新規取得 blob の書き込み先 `<root>/staging/<pull-id>/<hex>` を返す。
    ///
    /// `RegistryClient::fetch_blob` の `dest` に渡す。参照テーブルには何も登録しない
    /// （GC の走査にも `image ls` にも出さない）。公開は #475。
    pub fn staged_blob_path(&mut self, digest: &Digest) -> Result<PathBuf, OciError> {
        self.note_blob(digest)?;
        Ok(self.staging_dir.join(hex_of(digest)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::image_management::{PULL_ID_MAX_BYTES, ReferenceTable};

    fn d(n: u8) -> Digest {
        Digest::parse(&format!("sha256:{}", format!("{n:02x}").repeat(32))).unwrap()
    }
    fn pid(s: &str) -> PullId {
        PullId::new(s).unwrap()
    }

    struct Root(PathBuf);
    impl Root {
        fn new(tag: &str) -> Self {
            let p = std::env::temp_dir().join(format!("fc-oci-pull-{tag}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&p);
            fs::create_dir_all(p.join("blobs").join("sha256")).unwrap();
            Root(p)
        }
        fn blob(&self, dg: &Digest) -> PathBuf {
            self.0
                .join("blobs")
                .join("sha256")
                .join(hex_of(dg).unwrap())
        }
        fn put(&self, dg: &Digest, len: usize) {
            fs::write(self.blob(dg), vec![0u8; len]).unwrap();
        }
    }
    impl Drop for Root {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn leases(store: &ImageStore, dg: &Digest) -> Vec<PullId> {
        store.lock().unwrap().blob_references(dg).leases
    }

    /// REPAIR-4: ストアに設定した記録先が begin_pull / begin_pull_generated で使われる。
    #[test]
    fn repair4_begin_pull_uses_store_recorder() {
        use crate::instrument::OciOpOutcome;
        use crate::instrument::testing::Collect;
        let root = Root::new("rec");
        let rec = std::sync::Arc::new(Collect::default());
        let store = ImageStore::open(&root.0)
            .unwrap()
            .with_recorder(rec.clone());
        let _s = store.begin_pull(pid("p1")).unwrap();
        let dup = store.begin_pull(pid("p1")).err().unwrap();
        let _g = store.begin_pull_generated().unwrap();
        let items = rec.items();
        assert_eq!(items.len(), 3);
        assert!(items.iter().all(|i| i.kind() == OciOpKind::BeginPull));
        assert_eq!(items[0].outcome(), OciOpOutcome::Success);
        assert_eq!(items[1].outcome(), OciOpOutcome::Failure);
        assert_eq!(items[1].error_code(), Some(dup.code()));
        assert_eq!(items[2].outcome(), OciOpOutcome::Success);
    }

    /// REPAIR-4: リースの登録・返却が操作単位で記録される（成功・AlreadyExists・PermissionDenied）。
    #[test]
    fn repair4_lease_and_release_are_recorded() {
        use crate::instrument::OciOpOutcome;
        use crate::instrument::testing::Collect;
        let root = Root::new("rec-lease");
        root.put(&d(1), 5);
        let rec = std::sync::Arc::new(Collect::default());
        let store = ImageStore::open(&root.0)
            .unwrap()
            .with_recorder(rec.clone());
        let mut s1 = store.begin_pull(pid("p1")).unwrap();
        let mut s2 = store.begin_pull(pid("p2")).unwrap();
        let BlobReuse::Leased(b1) = s1.lease_existing_blob(&d(1)).unwrap() else {
            panic!("expected Leased");
        };
        let dup = s1.lease_existing_blob(&d(1)).err().unwrap();
        assert_eq!(dup.code(), OciErrorCode::AlreadyExists);
        let denied = s2.release_leased(b1).err().unwrap();
        assert_eq!(denied.code(), OciErrorCode::PermissionDenied);
        let BlobReuse::Leased(b2) = s2.lease_existing_blob(&d(1)).unwrap() else {
            panic!("expected Leased");
        };
        s2.release_leased(b2).unwrap();
        let got: Vec<_> = rec
            .items()
            .iter()
            .filter(|i| matches!(i.kind(), OciOpKind::LeaseBlob | OciOpKind::ReleaseBlobLease))
            .map(|i| (i.kind(), i.outcome(), i.error_code()))
            .collect();
        assert_eq!(
            got,
            vec![
                (OciOpKind::LeaseBlob, OciOpOutcome::Success, None),
                (
                    OciOpKind::LeaseBlob,
                    OciOpOutcome::Failure,
                    Some(OciErrorCode::AlreadyExists)
                ),
                (
                    OciOpKind::ReleaseBlobLease,
                    OciOpOutcome::Failure,
                    Some(OciErrorCode::PermissionDenied)
                ),
                (OciOpKind::LeaseBlob, OciOpOutcome::Success, None),
                (OciOpKind::ReleaseBlobLease, OciOpOutcome::Success, None),
            ]
        );
    }

    /// OCI-7: 既存 blob の再利用は、使う前に自分の pull ID でリースを登録する。
    #[test]
    fn oci7_reuse_registers_own_pull_lease_before_use() {
        let root = Root::new("reuse");
        root.put(&d(1), 5);
        let store = ImageStore::open(&root.0).unwrap();
        let mut s = store.begin_pull(pid("p1")).unwrap();
        let BlobReuse::Leased(b) = s.lease_existing_blob(&d(1)).unwrap() else {
            panic!("expected Leased");
        };
        assert_eq!(leases(&store, &d(1)), vec![pid("p1")]);
        assert!(store.lock().unwrap().blob_references(&d(1)).is_referenced());
        assert_eq!(b.path(), root.blob(&d(1)));
        assert_eq!(b.digest(), &d(1));
    }

    /// OCI-7: 2 つの pull のリースは独立で、一方の解放が他方に影響しない。
    #[test]
    fn oci7_two_pulls_hold_independent_leases() {
        let root = Root::new("two");
        root.put(&d(1), 5);
        let store = ImageStore::open(&root.0).unwrap();
        let mut s1 = store.begin_pull(pid("p1")).unwrap();
        let mut s2 = store.begin_pull(pid("p2")).unwrap();
        let BlobReuse::Leased(b1) = s1.lease_existing_blob(&d(1)).unwrap() else {
            panic!("expected Leased");
        };
        assert!(matches!(
            s2.lease_existing_blob(&d(1)).unwrap(),
            BlobReuse::Leased(_)
        ));
        assert_eq!(leases(&store, &d(1)), vec![pid("p1"), pid("p2")]);
        s1.release_leased(b1).unwrap();
        assert_eq!(leases(&store, &d(1)), vec![pid("p2")]);
        assert!(store.lock().unwrap().blob_references(&d(1)).is_referenced());
    }

    /// OCI-7: 同一 digest の二重取得を拒否し、最初のトークンのリースは残る。
    #[test]
    fn oci7_duplicate_lease_of_same_digest_is_rejected() {
        let root = Root::new("duplease");
        root.put(&d(1), 5);
        let store = ImageStore::open(&root.0).unwrap();
        let mut s = store.begin_pull(pid("p1")).unwrap();
        let BlobReuse::Leased(b) = s.lease_existing_blob(&d(1)).unwrap() else {
            panic!("expected Leased");
        };
        assert_eq!(
            s.lease_existing_blob(&d(1)).unwrap_err().code(),
            OciErrorCode::AlreadyExists
        );
        assert_eq!(leases(&store, &d(1)), vec![pid("p1")]);
        s.release_leased(b).unwrap();
        assert_eq!(leases(&store, &d(1)), vec![]);
        // 解放後は再取得できる。
        assert!(matches!(
            s.lease_existing_blob(&d(1)).unwrap(),
            BlobReuse::Leased(_)
        ));
    }

    /// OCI-7: 別セッション・別ストアのトークンでは解放できず、テーブルは変わらない。
    #[test]
    fn oci7_release_rejects_foreign_token() {
        let root = Root::new("foreign");
        root.put(&d(1), 5);
        let store = ImageStore::open(&root.0).unwrap();
        let mut s1 = store.begin_pull(pid("p1")).unwrap();
        let mut s2 = store.begin_pull(pid("p2")).unwrap();
        let BlobReuse::Leased(b1) = s1.lease_existing_blob(&d(1)).unwrap() else {
            panic!("expected Leased");
        };
        let BlobReuse::Leased(b2) = s2.lease_existing_blob(&d(1)).unwrap() else {
            panic!("expected Leased");
        };
        assert_eq!(
            s2.release_leased(b1).unwrap_err().code(),
            OciErrorCode::PermissionDenied
        );
        assert_eq!(leases(&store, &d(1)), vec![pid("p1"), pid("p2")]);

        let root_b = Root::new("foreign-b");
        root_b.put(&d(1), 5);
        let store_b = ImageStore::open(&root_b.0).unwrap();
        let mut sb = store_b.begin_pull(pid("p1")).unwrap();
        assert_eq!(
            sb.release_leased(b2).unwrap_err().code(),
            OciErrorCode::PermissionDenied
        );
        assert_eq!(leases(&store, &d(1)), vec![pid("p1"), pid("p2")]);
        assert_eq!(leases(&store_b, &d(1)), vec![]);
    }

    /// OCI-7: 解放がロック Timeout で失敗しても、再 lease で新トークンを得て解放し直せる。
    #[test]
    fn oci7_release_failure_does_not_pin_lease() {
        let root = Root::new("release-fail");
        root.put(&d(1), 5);
        let store = ImageStore::open(&root.0)
            .unwrap()
            .with_timeout(std::time::Duration::from_millis(50));
        let mut s = store.begin_pull(pid("p1")).unwrap();
        let BlobReuse::Leased(b) = s.lease_existing_blob(&d(1)).unwrap() else {
            panic!("expected Leased");
        };
        let held = store.lock().unwrap();
        assert_eq!(
            s.release_leased(b).unwrap_err().code(),
            OciErrorCode::Timeout
        );
        drop(held);
        assert_eq!(leases(&store, &d(1)), vec![pid("p1")]);
        let BlobReuse::Leased(b2) = s.lease_existing_blob(&d(1)).unwrap() else {
            panic!("expected Leased");
        };
        s.release_leased(b2).unwrap();
        assert_eq!(leases(&store, &d(1)), vec![]);
    }

    /// REPAIR-4: begin_pull の成否・エラー code・種別が記録される。
    #[test]
    fn repair4_begin_pull_is_recorded() {
        use crate::instrument::OciOpOutcome;
        use crate::instrument::testing::Collect;
        let root = Root::new("record");
        let store = ImageStore::open(&root.0).unwrap();
        let rec = Collect::default();
        let _s = store.begin_pull_with(&rec, pid("p1")).unwrap();
        let e = store.begin_pull_with(&rec, pid("p1")).unwrap_err();
        assert_eq!(e.code(), OciErrorCode::AlreadyExists);
        let v = rec.0.lock().unwrap();
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].kind(), OciOpKind::BeginPull);
        assert_eq!(v[0].outcome(), OciOpOutcome::Success);
        assert_eq!(v[0].error_code(), None);
        assert_eq!(v[1].outcome(), OciOpOutcome::Failure);
        assert_eq!(v[1].error_code(), Some(OciErrorCode::AlreadyExists));
    }

    /// OCI-7: キャッシュに無い・通常ファイルでない blob はリースを残さない。
    #[test]
    fn oci7_missing_or_non_regular_cached_blob_leaves_no_lease() {
        let root = Root::new("miss");
        let store = ImageStore::open(&root.0).unwrap();
        let mut s = store.begin_pull(pid("p1")).unwrap();
        assert!(matches!(
            s.lease_existing_blob(&d(1)).unwrap(),
            BlobReuse::Absent
        ));
        assert_eq!(leases(&store, &d(1)), vec![]);
        fs::create_dir(root.blob(&d(2))).unwrap();
        assert!(matches!(
            s.lease_existing_blob(&d(2)).unwrap(),
            BlobReuse::NotRegularFile
        ));
        assert_eq!(leases(&store, &d(2)), vec![]);
        #[cfg(unix)]
        {
            let target = root.0.join("outside");
            fs::write(&target, b"x").unwrap();
            std::os::unix::fs::symlink(&target, root.blob(&d(3))).unwrap();
            assert!(matches!(
                s.lease_existing_blob(&d(3)).unwrap(),
                BlobReuse::NotRegularFile
            ));
            assert_eq!(leases(&store, &d(3)), vec![]);
            assert_eq!(fs::read(&target).unwrap(), b"x");
        }
    }

    /// OCI-7: ステージングへ書き込み中の blob は `image ls` にも GC 走査にも現れない。
    #[test]
    fn oci7_staged_blob_is_invisible_to_image_ls_and_gc_scan() {
        let root = Root::new("staged");
        root.put(&d(9), 7);
        let store = ImageStore::open(&root.0).unwrap();
        let mut s = store.begin_pull(pid("p1")).unwrap();
        let path = s.staged_blob_path(&d(1)).unwrap();
        fs::write(&path, vec![1u8; 100]).unwrap();
        fs::write(path.with_extension("part"), vec![1u8; 50]).unwrap();
        assert!(path.starts_with(root.0.join("staging").join("p1")));
        assert!(!path.starts_with(root.0.join("blobs")));
        let g = store.lock().unwrap();
        assert_eq!(g.list_images(&root.0).unwrap().entries, vec![]);
        let cache = g.disk_usage(&root.0).unwrap().cache;
        assert_eq!(cache.blob_count, 1);
        assert_eq!(cache.bytes, 7);
        assert_eq!(cache.unregistered_count, 1);
        let r = g.blob_references(&d(1));
        assert_eq!(r.referencing_manifests, vec![]);
        assert_eq!(r.leases, vec![]);
        assert!(!r.is_referenced());
        assert_eq!(g.manifests().count(), 0);
    }

    /// OCI-7: 同じ ID の二重開始と symlink の staging を拒否し、ディレクトリは 0700。
    #[test]
    fn oci7_begin_pull_rejects_duplicate_id_and_symlinked_staging() {
        let root = Root::new("dup");
        let store = ImageStore::open(&root.0).unwrap();
        let _s = store.begin_pull(pid("p1")).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(_s.staging_dir()).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o700);
        }
        assert_eq!(
            store.begin_pull(pid("p1")).unwrap_err().code(),
            OciErrorCode::AlreadyExists
        );
        #[cfg(unix)]
        {
            let root2 = Root::new("symlink");
            let outside = root2.0.join("outside");
            fs::create_dir(&outside).unwrap();
            std::os::unix::fs::symlink(&outside, root2.0.join("staging")).unwrap();
            let store2 = ImageStore::open(&root2.0).unwrap();
            assert_eq!(
                store2.begin_pull(pid("p1")).unwrap_err().code(),
                OciErrorCode::FailedPrecondition
            );
            assert_eq!(fs::read_dir(&outside).unwrap().count(), 0);
        }
    }

    /// OCI-7: 1 セッションの blob 件数に上限があり、超過してもテーブルは変わらない。
    #[test]
    fn oci7_session_caps_blob_count() {
        let root = Root::new("cap");
        let store = ImageStore::open(&root.0).unwrap();
        let mut s = store.begin_pull(pid("p1")).unwrap();
        for i in 0..MAX_SESSION_BLOBS {
            let dg = Digest::parse(&format!("sha256:{i:064x}")).unwrap();
            s.staged_blob_path(&dg).unwrap();
        }
        let extra = Digest::parse(&format!("sha256:{:064x}", MAX_SESSION_BLOBS)).unwrap();
        assert_eq!(
            s.lease_existing_blob(&extra).unwrap_err().code(),
            OciErrorCode::ResourceExhausted
        );
        let table = store.lock().unwrap().clone();
        assert_eq!(table, ReferenceTable::new());
    }

    /// OCI-7: 生成した pull ID は互いに異なり、検証を通り、先頭は PID。
    #[test]
    fn oci7_generated_pull_id_round_trips() {
        let a = PullId::generate().unwrap();
        let b = PullId::generate().unwrap();
        assert_ne!(a, b);
        assert!(a.as_str().len() <= PULL_ID_MAX_BYTES);
        assert_eq!(PullId::new(a.as_str()).unwrap(), a);
        let first = a.as_str().split('-').next().unwrap();
        assert_eq!(first, std::process::id().to_string());
    }
}
