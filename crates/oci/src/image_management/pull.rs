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
//! - (C) 公開: 取得と digest 検証が済んだら、排他区間の下で「ステージングから `blobs/sha256` への
//!   移動」「manifest（在庫と構成）とタグの登録」「自分のリースの解放」を行う（[`PullSession::publish`]）。
//!   公開が完了するまで当該イメージは `image ls` に現れない。失敗・中断時は自分のリースを解放し、
//!   ステージングを削除する（[`PullSession::abort`]。publish の失敗時にも内部で同じ手順を行う）。
//!
//! 呼び出し文脈: pull の全体処理（レジストリ取得 → 検証 → 公開）から使う想定である。
//! `RegistryClient::fetch_blob` の `dest` には [`PullSession::staged_blob_path`] の戻り値を渡し、
//! 取得後に [`PullSession::verify_staged_blob`] で検証してから [`PullSession::publish`] を呼ぶ。
//! cri の `image_pull` からの配線は後続で扱う（本モジュールは oci 内で完結する）。
//!
//! ロックの規律: ガードを持ったまま digest 検証（再ハッシュ）・通信をしない。公開直前の完全性は、
//! 検証時に控えたファイルの指紋（サイズ・時刻・inode 等）の照合で保つ。既存宛先の内容検証は
//! ガードの外で行い、ガード内では指紋の照合だけをする。ガードの中で行うファイル操作は、
//! 公開（OCI-7 (C) の「排他の下で移動」）の `hard_link` / `remove_file`（同一ファイルシステム内の
//! メタデータ操作）に限る。リース登録は「リース登録 → 使う」の順に固定する。並行する prune は
//! ガードの内側でリースを数え直すため、登録後に blob が消されることはない
//! （OCI-7 の「余分に残す方向にのみ誤る」）。
//!
//! 公開の移動は `hard_link` で宛先を置き換えずに作り、成功後にステージング側の名前を消す
//! （公開後のハードリンク数を 1 に保つ。cri の `check_blob_trust` の条件と整合）。宛先が既にある
//! 通常ファイル（並行 pull が先に公開した同 digest）は、ガードの外で内容を検証した実体と
//! 指紋が一致するときだけ受け入れ、それ以外は検証済みのステージングで置き換える。
//!
//! 未実装（実装済みを装わない。REPAIR-3）:
//! - `PullSession` に `Drop` は実装しない（ロック待ちの Timeout・panic 中の毒化があり、ロックを取る
//!   `Drop` は危険なため）。publish も abort もせずに drop すると、リースとステージングが残る
//!   （余分に残す側）。呼び出し側は失敗経路で [`PullSession::abort`] を呼ぶ契約である。
//! - クラッシュ後に残ったリース・ステージングの回収 GC は #852・#477。
//! - `system df` でのステージング容量の集計。永続化・fsync は #853・#854・#851。
//! - cri の `image_pull` からの配線。

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use super::tag::ImageTagChange;
use super::usage::{blob_path, check_blob_dirs};
use super::{ImageStore, MAX_COMPOSITION_LAYERS, ManifestComposition, PullId, TagKey};
use crate::error::{OciError, OciErrorCode};
use crate::instrument::{OciOpKind, OciOpRecorder, record_oci_op};
use crate::layer::{VerifiedBlob, verify_blob_digest, verify_blob_digest_with};
use crate::reference::Digest;

/// ストア root 直下のステージング領域名。GC・`image ls` の走査対象外。
const STAGING_DIR_NAME: &str = "staging";

/// 1 つの pull セッションが触れる blob 件数の上限（config 1 件 + layers）。
const MAX_SESSION_BLOBS: usize = MAX_COMPOSITION_LAYERS + 1;

/// 1 回の公開で付けるタグ件数の上限。
pub const MAX_PUBLISH_TAGS: usize = 16;

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
    /// このセッションのステージングで digest 検証に成功した digest（[`PullSession::verify_staged_blob`]）。
    /// 公開できる新規 blob はこの集合にあるものに限る。
    /// 値は検証で確定したサイズ。公開直前の再ハッシュの読み取り上限に使う。
    verified: BTreeMap<Digest, VerifiedEntry>,
}

/// 検証で確定したサイズと、検証した実体の同一性（[`FileIdent`]）。
#[derive(Debug, Clone)]
struct VerifiedEntry {
    size: u64,
    ident: FileIdent,
}

/// ファイルの同一性の指紋（サイズ・更新時刻、unix では dev / inode / ctime も）。
///
/// digest の再ハッシュを排他区間の外へ出す代わりに、検証した実体が公開直前まで同じであることを
/// 安価な stat の照合で確かめるために使う（OCI-1・OCI-7）。差し替え（別 inode）・サイズ変更・
/// 書き換え（mtime / ctime の変化）を検出する。
#[derive(Debug, Clone, PartialEq, Eq)]
struct FileIdent {
    len: u64,
    mtime: Option<SystemTime>,
    #[cfg(unix)]
    unix: (u64, u64, i64, i64),
}

impl FileIdent {
    fn of(m: &fs::Metadata) -> Self {
        #[cfg(unix)]
        let unix = {
            use std::os::unix::fs::MetadataExt;
            (m.dev(), m.ino(), m.ctime(), m.ctime_nsec())
        };
        Self {
            len: m.len(),
            mtime: m.modified().ok(),
            #[cfg(unix)]
            unix,
        }
    }

    /// symlink を辿らず、通常ファイルのときだけ指紋を返す。
    fn of_regular(path: &Path) -> std::io::Result<Option<Self>> {
        let m = fs::symlink_metadata(path)?;
        Ok(m.is_file().then(|| Self::of(&m)))
    }
}

/// 公開の要求（manifest・構成・付けるタグ）。TASK-183.10・OCI-7。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct PullPublishRequest {
    /// 登録する manifest の digest。
    pub manifest: Digest,
    /// manifest の blob 構成（config と layers）。
    pub composition: ManifestComposition,
    /// 付けるタグ（`MAX_PUBLISH_TAGS` 件まで）。
    pub tags: Vec<TagKey>,
}

impl PullPublishRequest {
    /// タグ無しの要求を作る。
    pub fn new(manifest: Digest, composition: ManifestComposition) -> Self {
        Self {
            manifest,
            composition,
            tags: Vec::new(),
        }
    }

    /// 付けるタグを足す。
    pub fn with_tag(mut self, tag: TagKey) -> Self {
        self.tags.push(tag);
        self
    }
}

/// ステージング削除の結果。コミット後の削除失敗は公開の失敗にしない（残置は無害で #852・#477 が回収する）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum StagingCleanup {
    /// 削除済み（元から無かった場合を含む）。
    Removed,
    /// 削除に失敗した（残置）。
    Failed {
        /// 失敗の分類。
        code: OciErrorCode,
    },
}

/// 公開の結果。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct PullPublishOutcome {
    /// 登録した manifest。
    pub manifest: Digest,
    /// タグごとの付与の区分（要求の並び）。
    pub tags: Vec<(TagKey, ImageTagChange)>,
    /// この呼び出しでステージングから `blobs/sha256` へ移した blob。
    pub moved_blobs: Vec<Digest>,
    /// 宛先が既にあり、受け入れた blob（並行 pull が先に公開したもの）。
    pub already_present_blobs: Vec<Digest>,
    /// リース済みの既存 blob をそのまま再利用したもの。
    pub reused_blobs: Vec<Digest>,
    /// 解放した自分のリースの件数。
    pub released_leases: usize,
    /// ステージング削除の結果。
    pub staging: StagingCleanup,
}

/// 中断（ロールバック）の結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct PullAbortOutcome {
    /// 解放した自分のリースの件数。
    pub released_leases: usize,
    /// ステージング削除の結果。
    pub staging: StagingCleanup,
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
            verified: BTreeMap::new(),
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
        // `blobs` / `blobs/sha256` が symlink・非ディレクトリなら、ストア外を指すため stat せず拒否する
        // （ls / df / prune / rm と同じ fail-closed）。リース登録の前に判定し、拒否時は何も残さない。
        let dirs_exist = check_blob_dirs(self.store.root())?;
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
            _ if !dirs_exist => Some(BlobReuse::Absent),
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
    /// （GC の走査にも `image ls` にも出さない）。公開は [`PullSession::publish`]。
    pub fn staged_blob_path(&mut self, digest: &Digest) -> Result<PathBuf, OciError> {
        self.note_blob(digest)?;
        Ok(self.staging_dir.join(hex_of(digest)?))
    }

    /// ステージング済みの blob の sha256 を検証し、成功したらこのセッションの「公開できる」集合へ入れる。
    ///
    /// 検証はこのセッションのステージングのパスに結びつく（別ファイルの検証結果を流用できない）。
    /// ガードは持たない。symlink・通常ファイルでないものは `FailedPrecondition`。
    pub fn verify_staged_blob(
        &mut self,
        digest: &Digest,
        max_bytes: u64,
    ) -> Result<VerifiedBlob, OciError> {
        self.note_blob(digest)?;
        let path = self.staging_dir.join(hex_of(digest)?);
        match fs::symlink_metadata(&path) {
            Ok(m) if m.is_file() => {}
            Ok(_) => {
                return Err(err(
                    OciErrorCode::FailedPrecondition,
                    "staged blob is not a regular file",
                ));
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(err(OciErrorCode::NotFound, "staged blob not found"));
            }
            Err(e) => return Err(io_err(&e, "failed to stat staged blob")),
        }
        // 再検証の開始時に以前の検証結果を無効化する（失敗した再検証の前の登録を残さない）。
        self.verified.remove(digest);
        // 検証の前後で指紋が一致することを確かめ、検証した実体を固定する（公開直前の再ハッシュの代わり）。
        let before = FileIdent::of_regular(&path)
            .map_err(|e| io_err(&e, "failed to stat staged blob"))?
            .ok_or_else(|| {
                err(
                    OciErrorCode::FailedPrecondition,
                    "staged blob is not a regular file",
                )
            })?;
        let v = verify_blob_digest_with(self.store.recorder(), &path, digest, max_bytes)?;
        let after =
            FileIdent::of_regular(&path).map_err(|e| io_err(&e, "failed to stat staged blob"))?;
        if after.as_ref() != Some(&before) {
            return Err(err(
                OciErrorCode::DataLoss,
                "staged blob changed during verification",
            ));
        }
        self.verified.insert(
            digest.clone(),
            VerifiedEntry {
                size: v.size,
                ident: before,
            },
        );
        Ok(v)
    }

    /// 公開する（OCI-7 (C)）。排他区間の下で、ステージングからの移動・manifest とタグの登録・
    /// 自分のリースの解放を不可分に行う。公開が完了するまで当該イメージは `image ls` に現れない。
    ///
    /// 構成の blob は「リース済み」か「このセッションで検証済み」のどちらかでなければ
    /// `FailedPrecondition`。同じ digest で別構成の manifest が登録済みなら `AlreadyExists`。
    /// `Err` を返すときは内部でロールバック（自分のリース解放とステージング削除。`AbortPull` として記録）
    /// を試みてから元のエラーを返す。セッションは消費される。
    pub fn publish(mut self, request: PullPublishRequest) -> Result<PullPublishOutcome, OciError> {
        let store = self.store;
        let r = record_oci_op(store.recorder(), OciOpKind::PublishPull, || {
            self.publish_inner(&request)
        });
        if r.is_err() {
            let _ = record_oci_op(store.recorder(), OciOpKind::AbortPull, || {
                self.abort_inner()
            });
        }
        r
    }

    /// 呼び出し側の明示的な中断。自分のリースを解放し、ステージングを削除する。
    ///
    /// ロックを取れない（Timeout・毒化）場合はリースが残り（余分に残す側。#852・#477 が回収）、
    /// ステージングは削除したうえでそのエラーを返す。
    pub fn abort(mut self) -> Result<PullAbortOutcome, OciError> {
        let store = self.store;
        record_oci_op(store.recorder(), OciOpKind::AbortPull, || {
            self.abort_inner()
        })
    }

    fn abort_inner(&mut self) -> Result<PullAbortOutcome, OciError> {
        let released = self
            .store
            .lock()
            .map(|mut g| g.release_all_leases(&self.id).len());
        self.leased.clear();
        self.verified.clear();
        let staging = self.remove_staging();
        released.map(|released_leases| PullAbortOutcome {
            released_leases,
            staging,
        })
    }

    /// 自分のステージングディレクトリを消す。親・自分が symlink なら辿らず失敗とする。
    fn remove_staging(&self) -> StagingCleanup {
        let failed = |code| StagingCleanup::Failed { code };
        let parent = self.store.root().join(STAGING_DIR_NAME);
        match fs::symlink_metadata(&parent) {
            Ok(m) if m.is_dir() => {}
            Ok(_) => return failed(OciErrorCode::FailedPrecondition),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return StagingCleanup::Removed,
            Err(_) => return failed(OciErrorCode::Internal),
        }
        match fs::symlink_metadata(&self.staging_dir) {
            Ok(m) if m.is_dir() => match fs::remove_dir_all(&self.staging_dir) {
                Ok(()) => StagingCleanup::Removed,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => StagingCleanup::Removed,
                Err(_) => failed(OciErrorCode::Internal),
            },
            Ok(_) => failed(OciErrorCode::FailedPrecondition),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => StagingCleanup::Removed,
            Err(_) => failed(OciErrorCode::Internal),
        }
    }

    fn publish_inner(&mut self, req: &PullPublishRequest) -> Result<PullPublishOutcome, OciError> {
        if req.tags.len() > MAX_PUBLISH_TAGS {
            return Err(err(
                OciErrorCode::ResourceExhausted,
                "too many tags in one publish",
            ));
        }
        // 事前検証（ガードの外）。blob を再利用・移動に分類し、移動元と宛先ディレクトリを確かめる。
        let mut reused = Vec::new();
        let mut to_move = Vec::new();
        for b in req.composition.blobs() {
            if self.leased.contains(b) {
                reused.push(b.clone());
            } else if self.verified.contains_key(b) {
                to_move.push(b.clone());
            } else {
                return Err(err(
                    OciErrorCode::FailedPrecondition,
                    "blob is neither leased nor verified by this pull",
                ));
            }
        }
        for b in &to_move {
            let src = self.staging_dir.join(hex_of(b)?);
            self.check_staged_ident(&src, b)?;
        }
        if !to_move.is_empty() {
            self.ensure_blob_dirs()?;
        }

        let root = self.store.root().to_path_buf();
        // 既存の宛先の内容検証（再ハッシュ）はガードの外で済ませ、検証した実体の指紋を控える。
        // 排他区間の中では指紋の照合だけを行う（大容量 blob でガード保持が期限を超えないように。
        // ロックの規律）。
        let mut dst_checked: BTreeMap<Digest, Option<FileIdent>> = BTreeMap::new();
        for b in &to_move {
            let dst = blob_path(&root, b)?;
            let size = self.verified.get(b).map_or(0, |v| v.size);
            let ident = match FileIdent::of_regular(&dst) {
                Ok(Some(before)) => match verify_blob_digest(&dst, b, size) {
                    Ok(_) => {
                        // 検証中に変わっていれば「未検証」として扱い、ガード内で置き換える。
                        match FileIdent::of_regular(&dst) {
                            Ok(Some(after)) if after == before => Some(after),
                            _ => None,
                        }
                    }
                    Err(e)
                        if matches!(
                            e.code(),
                            OciErrorCode::DataLoss | OciErrorCode::ResourceExhausted
                        ) =>
                    {
                        None
                    }
                    Err(e) => return Err(e),
                },
                // 不在・通常ファイルでないもの。ガード内の hard_link の結果で判定する。
                _ => None,
            };
            dst_checked.insert(b.clone(), ident);
        }
        let mut guard = self.store.lock()?;
        if guard
            .manifests()
            .any(|(d, c)| d == &req.manifest && c != &req.composition)
        {
            return Err(err(
                OciErrorCode::AlreadyExists,
                "manifest is already registered with a different composition",
            ));
        }
        // 移動。この呼び出しで作った宛先だけを記録し、失敗時はそれだけを消す。
        let mut created: Vec<PathBuf> = Vec::new();
        let mut moved = Vec::new();
        let mut present = Vec::new();
        let moves = (|| -> Result<(), OciError> {
            for b in &to_move {
                let src = self.staging_dir.join(hex_of(b)?);
                let dst = blob_path(&root, b)?;
                // 検証後にステージングのファイルが差し替わっても未検証の内容を公開しないよう、
                // 排他区間の下では再ハッシュせず、検証した実体の指紋を照合する（OCI-1・OCI-7）。
                self.check_staged_ident(&src, b)?;
                match fs::hard_link(&src, &dst) {
                    Ok(()) => {
                        created.push(dst);
                        moved.push(b.clone());
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                        match fs::symlink_metadata(&dst) {
                            Ok(m) if m.is_file() => {
                                // 既存の宛先は、ガードの外で検証した実体と指紋が一致するときだけ受け入れる。
                                // 壊れている・検証後に変わった・未検証のものは、検証済みのステージングで
                                // 原子的に置き換えて修復する。
                                let verified_dst = dst_checked.get(b).and_then(Option::as_ref);
                                if verified_dst.is_some()
                                    && FileIdent::of_regular(&dst).ok().flatten().as_ref()
                                        == verified_dst
                                {
                                    present.push(b.clone());
                                } else {
                                    fs::rename(&src, &dst).map_err(|_| {
                                        err(OciErrorCode::Internal, "failed to repair corrupt blob")
                                    })?;
                                    moved.push(b.clone());
                                    continue;
                                }
                            }
                            _ => {
                                return Err(err(
                                    OciErrorCode::FailedPrecondition,
                                    "blob destination is not a regular file",
                                ));
                            }
                        }
                    }
                    Err(_) => return Err(err(OciErrorCode::Internal, "failed to publish blob")),
                }
                // 公開後のハードリンク数を 1 に保つため、ステージング側の名前を消す。
                fs::remove_file(&src)
                    .map_err(|_| err(OciErrorCode::Internal, "failed to remove staged blob"))?;
            }
            Ok(())
        })();
        let result = moves.and_then(|()| {
            guard.register_manifest(req.manifest.clone(), req.composition.clone())?;
            let mut changes = Vec::with_capacity(req.tags.len());
            for tag in &req.tags {
                let change = match guard.register_tag(tag.clone(), &req.manifest)? {
                    None => ImageTagChange::Added,
                    Some(prev) if prev == req.manifest => ImageTagChange::Unchanged,
                    Some(from) => ImageTagChange::Moved { from },
                };
                changes.push((tag.clone(), change));
            }
            Ok(changes)
        });
        let changes = match result {
            Ok(c) => c,
            Err(e) => {
                for p in &created {
                    let _ = fs::remove_file(p);
                }
                return Err(e);
            }
        };
        let released_leases = guard.release_all_leases(&self.id).len();
        drop(guard);
        self.leased.clear();
        self.verified.clear();
        let staging = self.remove_staging();
        Ok(PullPublishOutcome {
            manifest: req.manifest.clone(),
            tags: changes,
            moved_blobs: moved,
            already_present_blobs: present,
            reused_blobs: reused,
            released_leases,
            staging,
        })
    }

    /// ステージングのファイルが検証時と同じ実体（指紋が一致）であることを確かめる。再ハッシュはしない。
    /// 通常ファイルでない・指紋が違う（差し替え・書き換え）なら `DataLoss`（通常ファイルでなければ
    /// `FailedPrecondition`）。
    fn check_staged_ident(&self, src: &Path, digest: &Digest) -> Result<(), OciError> {
        let Some(entry) = self.verified.get(digest) else {
            return Err(err(
                OciErrorCode::FailedPrecondition,
                "blob is neither leased nor verified by this pull",
            ));
        };
        match FileIdent::of_regular(src) {
            Ok(Some(now)) if now == entry.ident => Ok(()),
            Ok(Some(_)) => Err(err(
                OciErrorCode::DataLoss,
                "staged blob changed after verification",
            )),
            Ok(None) => Err(err(
                OciErrorCode::FailedPrecondition,
                "staged blob is not a regular file",
            )),
            Err(e) => Err(io_err(&e, "failed to stat staged blob")),
        }
    }

    /// `blobs` / `blobs/sha256` を（無ければ 0700 で）用意する。symlink・非ディレクトリは拒否。
    fn ensure_blob_dirs(&self) -> Result<(), OciError> {
        let root = self.store.root();
        if check_blob_dirs(root)? {
            return Ok(());
        }
        for dir in [root.join("blobs"), root.join("blobs").join("sha256")] {
            match make_dir(&dir) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(io_err(&e, "failed to create blob directory")),
            }
        }
        if check_blob_dirs(root)? {
            Ok(())
        } else {
            Err(err(
                OciErrorCode::FailedPrecondition,
                "blob directory is unavailable",
            ))
        }
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

    /// OCI-7・REPAIR-4: `blobs` / `blobs/sha256` が symlink なら lease は FailedPrecondition で拒否され、
    /// リースは残らず、失敗が記録に残る（ストア外のファイルをキャッシュヒットにしない）。
    #[cfg(unix)]
    #[test]
    fn oci7_lease_rejects_symlinked_blob_dirs() {
        use crate::instrument::OciOpOutcome;
        use crate::instrument::testing::Collect;
        for (tag, top) in [("symtop", true), ("symsha", false)] {
            let root = Root::new(tag);
            let outside = root.0.join("outside");
            fs::create_dir_all(&outside).unwrap();
            fs::write(outside.join(hex_of(&d(1)).unwrap()), b"x").unwrap();
            if top {
                fs::remove_dir_all(root.0.join("blobs")).unwrap();
                std::os::unix::fs::symlink(&outside, root.0.join("blobs")).unwrap();
            } else {
                fs::remove_dir(root.0.join("blobs").join("sha256")).unwrap();
                std::os::unix::fs::symlink(&outside, root.0.join("blobs").join("sha256")).unwrap();
            }
            let rec = std::sync::Arc::new(Collect::default());
            let store = ImageStore::open(&root.0)
                .unwrap()
                .with_recorder(rec.clone());
            let mut s = store.begin_pull(pid("p1")).unwrap();
            let e = s.lease_existing_blob(&d(1)).err().unwrap();
            assert_eq!(e.code(), OciErrorCode::FailedPrecondition);
            let items = rec.items();
            let last = items.last().unwrap();
            assert_eq!(last.kind(), OciOpKind::LeaseBlob);
            assert_eq!(last.outcome(), OciOpOutcome::Failure);
            assert_eq!(last.error_code(), Some(OciErrorCode::FailedPrecondition));
            assert_eq!(leases(&store, &d(1)), vec![]);
        }
    }

    /// OCI-7: blobs ディレクトリ自体が無いストアでは lease は Absent（リースを残さない）。
    #[test]
    fn oci7_lease_without_blob_dirs_is_absent() {
        let root = Root::new("nodirs");
        fs::remove_dir_all(root.0.join("blobs")).unwrap();
        let store = ImageStore::open(&root.0).unwrap();
        let mut s = store.begin_pull(pid("p1")).unwrap();
        assert!(matches!(
            s.lease_existing_blob(&d(1)).unwrap(),
            BlobReuse::Absent
        ));
        assert_eq!(leases(&store, &d(1)), vec![]);
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

    // ---- 公開とロールバック（OCI-7・TASK-183.10・#475） ----

    use crate::instrument::OciOpOutcome;
    use crate::instrument::testing::Collect;
    use crate::reference::{RegistryHost, Repository, Tag};
    use sha2::{Digest as _, Sha256};

    fn sha_of(data: &[u8]) -> Digest {
        let mut hex = String::new();
        for b in Sha256::digest(data) {
            hex.push_str(&format!("{b:02x}"));
        }
        Digest::parse(&format!("sha256:{hex}")).unwrap()
    }

    fn tag(name: &str) -> TagKey {
        TagKey::new(
            RegistryHost::parse("example.com").unwrap(),
            Repository::parse("lib/app").unwrap(),
            Tag::parse(name).unwrap(),
        )
    }

    /// ステージングへ書いて検証まで済ませ、digest を返す。
    fn stage(s: &mut PullSession<'_>, data: &[u8]) -> Digest {
        let dg = sha_of(data);
        let path = s.staged_blob_path(&dg).unwrap();
        fs::write(&path, data).unwrap();
        s.verify_staged_blob(&dg, 1 << 20).unwrap();
        dg
    }

    fn manifest_digest() -> Digest {
        sha_of(b"manifest-body")
    }

    fn all_leases(store: &ImageStore, dgs: &[&Digest]) -> Vec<Vec<PullId>> {
        dgs.iter().map(|d| leases(store, d)).collect()
    }

    /// 受け入れ条件 1: 公開が完了するまで `image ls` に現れず、完了後に現れる。
    #[test]
    fn oci7_image_is_invisible_until_publish_completes() {
        let root = Root::new("pub-ok");
        let cached = sha_of(b"cached-layer");
        fs::write(root.blob(&cached), b"cached-layer").unwrap();
        let store = ImageStore::open(&root.0).unwrap();
        let mut s = store.begin_pull(pid("p1")).unwrap();
        let BlobReuse::Leased(_tok) = s.lease_existing_blob(&cached).unwrap() else {
            panic!("expected Leased");
        };
        let cfg = stage(&mut s, b"config-body");
        let layer = stage(&mut s, b"layer-body");
        let staged = s.staging_dir().to_path_buf();

        // 公開前: ステージング済みでも一覧にもテーブルにも現れない。
        {
            let g = store.lock().unwrap();
            assert_eq!(g.list_images(&root.0).unwrap().entries, vec![]);
            assert_eq!(g.manifests().count(), 0);
        }
        let comp =
            ManifestComposition::new(cfg.clone(), vec![cached.clone(), layer.clone()]).unwrap();
        let m = manifest_digest();
        let out = s
            .publish(PullPublishRequest::new(m.clone(), comp).with_tag(tag("v1")))
            .unwrap();
        assert_eq!(out.moved_blobs.len(), 2);
        assert_eq!(out.reused_blobs, vec![cached.clone()]);
        assert_eq!(out.released_leases, 1);
        assert_eq!(out.staging, StagingCleanup::Removed);
        assert_eq!(out.tags, vec![(tag("v1"), ImageTagChange::Added)]);

        let g = store.lock().unwrap();
        let list = g.list_images(&root.0).unwrap();
        assert_eq!(list.entries.len(), 1);
        let e = &list.entries[0];
        assert_eq!(e.tag, Some(tag("v1")));
        assert_eq!(e.digest, m);
        assert_eq!(e.size_bytes, (12 + 11 + 10) as u64);
        assert_eq!(e.missing_blobs, vec![]);
        assert_eq!(g.blob_references(&cached).leases, vec![]);
        assert_eq!(g.disk_usage(&root.0).unwrap().cache.unregistered_count, 0);
        assert!(!staged.exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            assert_eq!(fs::metadata(root.blob(&cfg)).unwrap().nlink(), 1);
            assert_eq!(fs::read(root.blob(&layer)).unwrap(), b"layer-body");
        }
    }

    /// 受け入れ条件 2: 公開の途中で失敗すると、自分のリースが解放されステージングが消える。
    #[test]
    fn oci7_publish_failure_midway_releases_own_leases_and_removes_staging() {
        let root = Root::new("pub-fail");
        let cached = sha_of(b"cached-layer");
        fs::write(root.blob(&cached), b"cached-layer").unwrap();
        let store = ImageStore::open(&root.0).unwrap();
        let mut other = store.begin_pull(pid("other")).unwrap();
        let _o = other.lease_existing_blob(&cached).unwrap();
        let mut s = store.begin_pull(pid("p1")).unwrap();
        let _t = s.lease_existing_blob(&cached).unwrap();
        let a = stage(&mut s, b"blob-a");
        let b = stage(&mut s, b"blob-b");
        let staged = s.staging_dir().to_path_buf();
        // digest 昇順で 2 番目の宛先をディレクトリにして、1 件目の移動後に失敗させる。
        let (first, second) = if a < b { (&a, &b) } else { (&b, &a) };
        fs::create_dir(root.blob(second)).unwrap();
        let comp = ManifestComposition::new(a.clone(), vec![b.clone(), cached.clone()]).unwrap();
        let err = s
            .publish(PullPublishRequest::new(manifest_digest(), comp).with_tag(tag("v1")))
            .unwrap_err();
        assert_eq!(err.code(), OciErrorCode::FailedPrecondition);
        assert_eq!(leases(&store, &cached), vec![pid("other")]);
        assert!(!staged.exists());
        assert!(!root.blob(first).exists());
        assert!(root.blob(second).is_dir());
        let g = store.lock().unwrap();
        assert_eq!(g.list_images(&root.0).unwrap().entries, vec![]);
        assert_eq!(g.manifests().count(), 0);
        assert_eq!(g.tags().count(), 0);
    }

    /// 同じ digest で別構成の manifest が登録済みなら、ファイルに触れず AlreadyExists でロールバックする。
    #[test]
    fn oci7_publish_manifest_conflict_rolls_back_before_file_ops() {
        let root = Root::new("pub-conflict");
        let store = ImageStore::open(&root.0).unwrap();
        let m = manifest_digest();
        let other_cfg = sha_of(b"other-config");
        store
            .lock()
            .unwrap()
            .register_manifest(
                m.clone(),
                ManifestComposition::new(other_cfg, vec![]).unwrap(),
            )
            .unwrap();
        let mut s = store.begin_pull(pid("p1")).unwrap();
        let cfg = stage(&mut s, b"config-body");
        let staged = s.staging_dir().to_path_buf();
        let comp = ManifestComposition::new(cfg.clone(), vec![]).unwrap();
        let err = s.publish(PullPublishRequest::new(m, comp)).unwrap_err();
        assert_eq!(err.code(), OciErrorCode::AlreadyExists);
        assert!(!root.blob(&cfg).exists());
        assert!(!staged.exists());
        assert_eq!(all_leases(&store, &[&cfg]), vec![vec![]]);
    }

    /// 検証もリースも無い blob は公開できず、ロールバックされる。
    #[test]
    fn oci7_publish_rejects_unverified_or_unleased_blob() {
        let root = Root::new("pub-unverified");
        let store = ImageStore::open(&root.0).unwrap();
        let mut s = store.begin_pull(pid("p1")).unwrap();
        let dg = sha_of(b"never-verified");
        let path = s.staged_blob_path(&dg).unwrap();
        fs::write(&path, b"never-verified").unwrap();
        let staged = s.staging_dir().to_path_buf();
        let comp = ManifestComposition::new(dg.clone(), vec![]).unwrap();
        let err = s
            .publish(PullPublishRequest::new(manifest_digest(), comp))
            .unwrap_err();
        assert_eq!(err.code(), OciErrorCode::FailedPrecondition);
        assert!(!root.blob(&dg).exists());
        assert!(!staged.exists());
    }

    /// OCI-7 (v): 並行 pull が先に公開した同 digest の宛先は受け入れ、既存の内容を変えない。
    #[test]
    fn oci7_publish_accepts_blob_already_published_by_other_pull() {
        let root = Root::new("pub-present");
        let store = ImageStore::open(&root.0).unwrap();
        let mut s = store.begin_pull(pid("p1")).unwrap();
        let cfg = stage(&mut s, b"config-body");
        fs::write(root.blob(&cfg), b"config-body").unwrap();
        let comp = ManifestComposition::new(cfg.clone(), vec![]).unwrap();
        let out = s
            .publish(PullPublishRequest::new(manifest_digest(), comp))
            .unwrap();
        assert_eq!(out.already_present_blobs, vec![cfg.clone()]);
        assert_eq!(out.moved_blobs, vec![]);
        assert_eq!(fs::read(root.blob(&cfg)).unwrap(), b"config-body");
    }

    /// OCI-1・OCI-7: 検証後にステージングが差し替えられても、未検証の内容は公開されない。
    #[test]
    fn oci7_publish_rejects_staged_file_swapped_after_verify() {
        let root = Root::new("pub-swap");
        let store = ImageStore::open(&root.0).unwrap();
        let mut s = store.begin_pull(pid("p1")).unwrap();
        let cfg = stage(&mut s, b"config-body");
        let path = s.staged_blob_path(&cfg).unwrap();
        fs::write(&path, b"evil-body").unwrap();
        let comp = ManifestComposition::new(cfg.clone(), vec![]).unwrap();
        let err = s
            .publish(PullPublishRequest::new(manifest_digest(), comp))
            .unwrap_err();
        assert_eq!(err.code(), OciErrorCode::DataLoss);
        assert!(!root.blob(&cfg).exists());
    }

    /// OCI-1・OCI-7: 同じサイズの別ファイルへ差し替えられても（別 inode）、指紋の照合で拒否する。
    #[test]
    fn oci7_publish_rejects_same_size_replacement_after_verify() {
        let root = Root::new("pub-swap-same");
        let store = ImageStore::open(&root.0).unwrap();
        let mut s = store.begin_pull(pid("p1")).unwrap();
        let cfg = stage(&mut s, b"config-body");
        let path = s.staged_blob_path(&cfg).unwrap();
        let tmp = path.with_extension("evil");
        fs::write(&tmp, b"evil--body!").unwrap();
        fs::rename(&tmp, &path).unwrap();
        let comp = ManifestComposition::new(cfg.clone(), vec![]).unwrap();
        let err = s
            .publish(PullPublishRequest::new(manifest_digest(), comp))
            .unwrap_err();
        assert_eq!(err.code(), OciErrorCode::DataLoss);
        assert!(!root.blob(&cfg).exists());
    }

    /// OCI-7: 大容量 blob の公開でも、ガードの外で済ませる検証のため他操作のロック取得を妨げない。
    /// 公開（検証済み 64 MiB）の最中に別スレッドがロックを取れる。
    #[test]
    fn oci7_publish_of_large_blob_does_not_hold_guard_for_hashing() {
        let root = Root::new("pub-large");
        let store = ImageStore::open(&root.0).unwrap();
        let mut s = store.begin_pull(pid("p1")).unwrap();
        let data = vec![7u8; 64 << 20];
        let dg = sha_of(&data);
        fs::write(s.staged_blob_path(&dg).unwrap(), &data).unwrap();
        s.verify_staged_blob(&dg, 1 << 30).unwrap();
        // 既存の宛先にも同内容を置く（ガード外で検証され、ガード内では指紋照合のみ）。
        fs::write(root.blob(&dg), &data).unwrap();
        let comp = ManifestComposition::new(dg.clone(), vec![]).unwrap();
        let start = std::time::Instant::now();
        let hold = std::thread::scope(|sc| {
            let h = sc.spawn(|| {
                // 公開中に何度かロックを取り直し、最長の取得待ちを測る。
                let mut worst = std::time::Duration::ZERO;
                for _ in 0..200 {
                    let t = std::time::Instant::now();
                    drop(store.lock().unwrap());
                    worst = worst.max(t.elapsed());
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
                worst
            });
            let out = s
                .publish(PullPublishRequest::new(manifest_digest(), comp))
                .unwrap();
            assert_eq!(out.already_present_blobs, vec![dg.clone()]);
            h.join().unwrap()
        });
        assert!(
            hold < std::time::Duration::from_secs(1),
            "{hold:?} {:?}",
            start.elapsed()
        );
    }

    /// OCI-1・OCI-7: 再検証が失敗したら以前の検証結果は残らず、公開できない。
    #[test]
    fn oci7_failed_reverify_clears_verified_state() {
        let root = Root::new("pub-reverify");
        let store = ImageStore::open(&root.0).unwrap();
        let mut s = store.begin_pull(pid("p1")).unwrap();
        let cfg = stage(&mut s, b"config-body");
        let path = s.staged_blob_path(&cfg).unwrap();
        fs::write(&path, b"evil-body").unwrap();
        let e = s.verify_staged_blob(&cfg, 1 << 20).unwrap_err();
        assert_eq!(e.code(), OciErrorCode::DataLoss);
        let comp = ManifestComposition::new(cfg, vec![]).unwrap();
        let err = s
            .publish(PullPublishRequest::new(manifest_digest(), comp))
            .unwrap_err();
        assert_eq!(err.code(), OciErrorCode::FailedPrecondition);
    }

    /// OCI-7: 宛先に壊れた既存 blob があれば、検証済みのステージングで置き換えて修復する。
    #[test]
    fn oci7_publish_repairs_corrupt_existing_blob() {
        let root = Root::new("pub-corrupt");
        let store = ImageStore::open(&root.0).unwrap();
        let mut s = store.begin_pull(pid("p1")).unwrap();
        let cfg = stage(&mut s, b"config-body");
        fs::write(root.blob(&cfg), b"corrupt").unwrap();
        let comp = ManifestComposition::new(cfg.clone(), vec![]).unwrap();
        let out = s
            .publish(PullPublishRequest::new(manifest_digest(), comp))
            .unwrap();
        assert_eq!(out.moved_blobs, vec![cfg.clone()]);
        assert_eq!(out.already_present_blobs, vec![]);
        assert_eq!(fs::read(root.blob(&cfg)).unwrap(), b"config-body");
    }

    /// abort は自分のリースだけを外し、ステージングを消す。blobs は変えない。
    #[test]
    fn oci7_abort_releases_own_leases_and_removes_staging() {
        let root = Root::new("abort");
        let cached = sha_of(b"cached-layer");
        fs::write(root.blob(&cached), b"cached-layer").unwrap();
        let store = ImageStore::open(&root.0).unwrap();
        let mut other = store.begin_pull(pid("other")).unwrap();
        let _o = other.lease_existing_blob(&cached).unwrap();
        let mut s = store.begin_pull(pid("p1")).unwrap();
        let _t = s.lease_existing_blob(&cached).unwrap();
        let cfg = stage(&mut s, b"config-body");
        let staged = s.staging_dir().to_path_buf();
        let out = s.abort().unwrap();
        assert_eq!(out.released_leases, 1);
        assert_eq!(out.staging, StagingCleanup::Removed);
        assert_eq!(leases(&store, &cached), vec![pid("other")]);
        assert!(!staged.exists());
        assert!(!root.blob(&cfg).exists());
        assert_eq!(fs::read(root.blob(&cached)).unwrap(), b"cached-layer");
    }

    /// ステージング済みファイルが symlink なら検証・公開とも拒否し、リンク先を変えない。
    #[cfg(unix)]
    #[test]
    fn oci7_publish_rejects_symlinked_staged_file() {
        let root = Root::new("pub-symlink");
        let store = ImageStore::open(&root.0).unwrap();
        let mut s = store.begin_pull(pid("p1")).unwrap();
        let target = root.0.join("outside");
        fs::write(&target, b"config-body").unwrap();
        let dg = sha_of(b"config-body");
        let path = s.staged_blob_path(&dg).unwrap();
        std::os::unix::fs::symlink(&target, &path).unwrap();
        assert_eq!(
            s.verify_staged_blob(&dg, 1 << 20).unwrap_err().code(),
            OciErrorCode::FailedPrecondition
        );
        let staged = s.staging_dir().to_path_buf();
        let comp = ManifestComposition::new(dg.clone(), vec![]).unwrap();
        let err = s
            .publish(PullPublishRequest::new(manifest_digest(), comp))
            .unwrap_err();
        assert_eq!(err.code(), OciErrorCode::FailedPrecondition);
        assert_eq!(fs::read(&target).unwrap(), b"config-body");
        assert!(!staged.exists());
    }

    /// 既存タグの付け替えは Moved、同じ manifest なら Unchanged を返す。
    #[test]
    fn oci7_publish_retag_reports_moved() {
        let root = Root::new("pub-retag");
        let store = ImageStore::open(&root.0).unwrap();
        let old = sha_of(b"old-manifest");
        {
            let mut g = store.lock().unwrap();
            g.register_manifest(
                old.clone(),
                ManifestComposition::new(sha_of(b"old-config"), vec![]).unwrap(),
            )
            .unwrap();
            g.register_tag(tag("v1"), &old).unwrap();
        }
        let mut s = store.begin_pull(pid("p1")).unwrap();
        let cfg = stage(&mut s, b"config-body");
        let comp = ManifestComposition::new(cfg, vec![]).unwrap();
        let out = s
            .publish(PullPublishRequest::new(manifest_digest(), comp).with_tag(tag("v1")))
            .unwrap();
        assert_eq!(
            out.tags,
            vec![(tag("v1"), ImageTagChange::Moved { from: old })]
        );
    }

    /// タグ件数が上限を超える公開は ResourceExhausted でロールバックされる。
    #[test]
    fn oci7_publish_caps_tag_count() {
        let root = Root::new("pub-tagcap");
        let store = ImageStore::open(&root.0).unwrap();
        let mut s = store.begin_pull(pid("p1")).unwrap();
        let cfg = stage(&mut s, b"config-body");
        let mut req = PullPublishRequest::new(
            manifest_digest(),
            ManifestComposition::new(cfg, vec![]).unwrap(),
        );
        for i in 0..=MAX_PUBLISH_TAGS {
            req = req.with_tag(tag(&format!("t{i}")));
        }
        assert_eq!(
            s.publish(req).unwrap_err().code(),
            OciErrorCode::ResourceExhausted
        );
        assert_eq!(store.lock().unwrap().tags().count(), 0);
    }

    /// REPAIR-4: publish・abort が成否つきで記録される（失敗時は publish の後に abort も記録）。
    #[test]
    fn repair4_publish_and_abort_are_recorded() {
        let root = Root::new("pub-rec");
        let rec = std::sync::Arc::new(Collect::default());
        let store = ImageStore::open(&root.0)
            .unwrap()
            .with_recorder(rec.clone());
        let mut s = store.begin_pull(pid("p1")).unwrap();
        let cfg = stage(&mut s, b"config-body");
        s.publish(PullPublishRequest::new(
            manifest_digest(),
            ManifestComposition::new(cfg, vec![]).unwrap(),
        ))
        .unwrap();
        let s2 = store.begin_pull(pid("p2")).unwrap();
        let bad = ManifestComposition::new(sha_of(b"nope"), vec![]).unwrap();
        s2.publish(PullPublishRequest::new(sha_of(b"m2"), bad))
            .unwrap_err();
        let s3 = store.begin_pull(pid("p3")).unwrap();
        s3.abort().unwrap();
        let got: Vec<_> = rec
            .items()
            .iter()
            .filter(|i| matches!(i.kind(), OciOpKind::PublishPull | OciOpKind::AbortPull))
            .map(|i| (i.kind(), i.outcome(), i.error_code()))
            .collect();
        assert_eq!(
            got,
            vec![
                (OciOpKind::PublishPull, OciOpOutcome::Success, None),
                (
                    OciOpKind::PublishPull,
                    OciOpOutcome::Failure,
                    Some(OciErrorCode::FailedPrecondition)
                ),
                (OciOpKind::AbortPull, OciOpOutcome::Success, None),
                (OciOpKind::AbortPull, OciOpOutcome::Success, None),
            ]
        );
    }

    /// ロックを取れない abort は Timeout を返し、リースは残るがステージングは消える（余分に残す側）。
    #[test]
    fn oci7_abort_under_lock_timeout_keeps_lease_but_removes_staging() {
        let root = Root::new("abort-timeout");
        let cached = sha_of(b"cached-layer");
        fs::write(root.blob(&cached), b"cached-layer").unwrap();
        let store = ImageStore::open(&root.0)
            .unwrap()
            .with_timeout(std::time::Duration::from_millis(50));
        let mut s = store.begin_pull(pid("p1")).unwrap();
        let _t = s.lease_existing_blob(&cached).unwrap();
        let staged = s.staging_dir().to_path_buf();
        let held = store.lock().unwrap();
        assert_eq!(s.abort().unwrap_err().code(), OciErrorCode::Timeout);
        drop(held);
        assert_eq!(leases(&store, &cached), vec![pid("p1")]);
        assert!(!staged.exists());
    }
}
