//! 削除ジャーナルと、削除の永続化完了確認・再試行（OCI-7・TASK-183.11.1・MS-4・#851）。
//!
//! `image rm`（完全削除）と `image prune` は、テーブルを変える前に「消す blob の一覧」をジャーナル
//! （ストア root 直下の `@gc-pending.json`、0600）として永続化する（一時ファイル → fsync → rename →
//! root の fsync）。blob を unlink し終えたら `blobs/sha256` を fsync し、ジャーナルを削除して root を
//! fsync する。**この最後の fsync の成功が削除確定のコミット点**で、`api-io-share.md` IO-2 の
//! fsync 契約（`docs/api/io-barrier.md`）にならう。
//!
//! 途中でクラッシュしても、次に [`super::ImageStore::lock`] を取ったとき
//! （[`ReferenceTable::resume_pending_deletion`]）にジャーナルを読み、**参照を数え直してから**削除を
//! やり直す。ジャーナルが永続化される前の中断は「削除前」、後の中断は「削除後」の一貫した状態に
//! 収束する。数え直しで参照・リースが見つかった blob は消さない（余分に残す側にだけ誤る）。
//! ジャーナルの検証に失敗したら、ファイルに触らず fail-closed（lock 自体を失敗させる）。
//!
//! 永続的に消せない blob（symlink・非通常ファイル・`remove_file` が恒久的に失敗する等）で
//! 新しい削除が恒久的に拒否されないよう、消せなかった blob の再試行には上限
//! （[`MAX_GC_RETRY_ATTEMPTS`] 回）を設ける。上限に達したらその blob はジャーナルから外して
//! 孤児として残し（余分に残す側にだけ誤る）、[`DeletionDurability::Abandoned`] で報告する。
//! 残った孤児ファイルは運用者がストアの `blobs/sha256` から手動で確認・削除する。
//!
//! 信頼境界: ジャーナルの読み込みは種別・group/other の書き込み権限・サイズ・件数・未知フィールドを
//! 検査するが、所有者（uid）は検査しない。ストア root 自体の所有者・権限の検査は `store.rs` の
//! 永続化側の担当で、root が信頼できることを前提とする。
//! 書き込み中のクラッシュで残る一時ファイル `@gc-pending.json.tmp-*` は、lock 取得時に回収する。
//!
//! 呼び出し元: `remove`（`execute_image_rm`）・`prune`（`execute_image_prune`）・`store`（lock 時の再試行）。
//!
//! 未実装・保証範囲（実装済みを装わない。REPAIR-3）:
//! - 保証するのはジャーナルと blob ファイルの unlink の永続化だけである。manifest の在庫・タグ・
//!   pull リースのテーブル自体はまだメモリ上の別物で、テーブルの永続化は別 issue の担当。
//!   そのため再試行時の新しいプロセスのテーブルには、ジャーナルの manifest が既に無いことが多い。
//! - Windows ではディレクトリを std で開けないため、ディレクトリの fsync は行わない（no-op）。
//! - コンテナ参照テーブルの未解決（unresolved）参照の考慮は、その永続化が入ってから足す。

use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};

use super::usage::{blob_dir, blob_path, check_blob_dirs};
use super::{ReferenceTable, TagKey};
use crate::error::{OciError, OciErrorCode};
use crate::reference::{Digest, RegistryHost, Repository, Tag};

/// ストア root 直下の削除ジャーナルのファイル名。
pub const GC_JOURNAL_FILE_NAME: &str = "@gc-pending.json";

/// ジャーナルのファイルサイズの上限（読み込み・書き込みの両方で確かめる）。
pub const MAX_GC_JOURNAL_BYTES: u64 = 8 * 1024 * 1024;

/// ジャーナルの各配列の件数の上限。
pub const MAX_GC_JOURNAL_ENTRIES: usize = 65_536;

/// 消せなかった blob を再試行する回数の上限（初回の削除を 1 回目と数える）。到達したら断念する。
pub const MAX_GC_RETRY_ATTEMPTS: u32 = 5;

const JOURNAL_VERSION: u32 = 1;
const TMP_PREFIX: &str = "@gc-pending.json.tmp-";

fn err(code: OciErrorCode, msg: &str) -> OciError {
    OciError::new(code, msg)
}

/// 削除の永続化の状態。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum DeletionDurability {
    /// ジャーナルを使う削除ではない（消す blob が無い・untag だけ）。
    #[default]
    NotApplicable,
    /// blob の unlink とジャーナル削除の fsync まで成功した（削除確定）。
    Confirmed,
    /// fsync の失敗や消せなかった blob のためジャーナルが残っている。次の lock で再試行される。
    Pending,
    /// 再試行の上限に達しても消せない blob を孤児として残し、ジャーナルは片づけた。
    /// 残った blob は `undeleted_blobs` で報告され、運用者の手動確認が要る。
    Abandoned,
}

/// 永続化する削除の意図。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct GcJournal {
    /// 外す manifest（昇順）。
    pub manifests: Vec<Digest>,
    /// 外すタグと、そのタグが指していた manifest。
    pub untag: Vec<(TagKey, Digest)>,
    /// 消す blob（昇順）。
    pub delete_blobs: Vec<Digest>,
    /// 消せなかった blob を再試行した回数（0 なら初回）。
    pub attempts: u32,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawJournal {
    version: u32,
    manifests: Vec<String>,
    untag: Vec<RawTag>,
    delete_blobs: Vec<String>,
    #[serde(default)]
    attempts: u32,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTag {
    host: String,
    repository: String,
    tag: String,
    manifest: String,
}

fn journal_path(root: &Path) -> PathBuf {
    root.join(GC_JOURNAL_FILE_NAME)
}

/// ディレクトリの fsync（unix）。Windows では std で開けないため何もしない。
#[cfg(unix)]
fn sync_dir(dir: &Path) -> std::io::Result<()> {
    File::open(dir)?.sync_all()
}

#[cfg(not(unix))]
fn sync_dir(_dir: &Path) -> std::io::Result<()> {
    Ok(())
}

fn to_raw(j: &GcJournal) -> RawJournal {
    RawJournal {
        version: JOURNAL_VERSION,
        manifests: j.manifests.iter().map(|d| d.to_string()).collect(),
        untag: j
            .untag
            .iter()
            .map(|(k, m)| RawTag {
                host: k.host.to_string(),
                repository: k.repository.to_string(),
                tag: k.tag.to_string(),
                manifest: m.to_string(),
            })
            .collect(),
        delete_blobs: j.delete_blobs.iter().map(|d| d.to_string()).collect(),
        attempts: j.attempts,
    }
}

fn parse_digest(s: &str) -> Result<Digest, OciError> {
    Digest::parse(s).map_err(|_| err(OciErrorCode::DataLoss, "gc journal has an invalid digest"))
}

fn from_raw(raw: RawJournal) -> Result<GcJournal, OciError> {
    if raw.version != JOURNAL_VERSION {
        return Err(err(
            OciErrorCode::DataLoss,
            "gc journal has an unknown version",
        ));
    }
    if raw.manifests.len() > MAX_GC_JOURNAL_ENTRIES
        || raw.untag.len() > MAX_GC_JOURNAL_ENTRIES
        || raw.delete_blobs.len() > MAX_GC_JOURNAL_ENTRIES
    {
        return Err(err(
            OciErrorCode::ResourceExhausted,
            "gc journal has too many entries",
        ));
    }
    let bad_tag = || err(OciErrorCode::DataLoss, "gc journal has an invalid tag");
    let mut untag = Vec::with_capacity(raw.untag.len());
    for t in &raw.untag {
        let key = TagKey::new(
            RegistryHost::parse(&t.host).map_err(|_| bad_tag())?,
            Repository::parse(&t.repository).map_err(|_| bad_tag())?,
            Tag::parse(&t.tag).map_err(|_| bad_tag())?,
        );
        untag.push((key, parse_digest(&t.manifest)?));
    }
    Ok(GcJournal {
        manifests: raw
            .manifests
            .iter()
            .map(|s| parse_digest(s))
            .collect::<Result<_, _>>()?,
        untag,
        delete_blobs: raw
            .delete_blobs
            .iter()
            .map(|s| parse_digest(s))
            .collect::<Result<_, _>>()?,
        attempts: raw.attempts,
    })
}

/// ジャーナルが（種別を問わず）存在するか。
pub(super) fn journal_exists(root: &Path) -> bool {
    match fs::symlink_metadata(journal_path(root)) {
        Ok(_) => true,
        Err(e) => e.kind() != ErrorKind::NotFound,
    }
}

/// 片づいていないジャーナルがあれば `FailedPrecondition`。新しい削除を始める前に呼ぶ。
pub(super) fn ensure_no_pending_journal(root: &Path) -> Result<(), OciError> {
    if journal_exists(root) {
        return Err(err(
            OciErrorCode::FailedPrecondition,
            "a previous image deletion is still pending; retry after the store lock recovers it",
        ));
    }
    Ok(())
}

/// ジャーナルを永続化する（一時ファイル → fsync → rename → root の fsync）。
///
/// 失敗しても既存のジャーナルは壊さない。上限超過は `ResourceExhausted`。
pub(super) fn write_journal(root: &Path, journal: &GcJournal) -> Result<(), OciError> {
    if journal.manifests.len() > MAX_GC_JOURNAL_ENTRIES
        || journal.untag.len() > MAX_GC_JOURNAL_ENTRIES
        || journal.delete_blobs.len() > MAX_GC_JOURNAL_ENTRIES
    {
        return Err(err(
            OciErrorCode::ResourceExhausted,
            "gc journal has too many entries",
        ));
    }
    let bytes = serde_json::to_vec(&to_raw(journal))
        .map_err(|_| err(OciErrorCode::Internal, "failed to encode gc journal"))?;
    if bytes.len() as u64 > MAX_GC_JOURNAL_BYTES {
        return Err(err(
            OciErrorCode::ResourceExhausted,
            "gc journal is too large",
        ));
    }
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let tmp = root.join(format!(
        "{TMP_PREFIX}{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    let io = |_: std::io::Error| err(OciErrorCode::Internal, "failed to persist gc journal");
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let result = (|| {
        let mut f = opts.open(&tmp)?;
        f.write_all(&bytes)?;
        f.sync_all()?;
        drop(f);
        fs::rename(&tmp, journal_path(root))?;
        sync_dir(root)
    })();
    if let Err(e) = result {
        let _ = fs::remove_file(&tmp);
        return Err(io(e));
    }
    Ok(())
}

/// 書き込み中のクラッシュで残った一時ファイルを回収する（通常ファイルだけ。ストアの排他区間内で、`lock` が取得直後に呼ぶ）。
pub(super) fn reap_stale_tmp(root: &Path) {
    let Ok(rd) = fs::read_dir(root) else {
        return;
    };
    for ent in rd.flatten() {
        let name = ent.file_name();
        if !name.to_string_lossy().starts_with(TMP_PREFIX) {
            continue;
        }
        let path = ent.path();
        if fs::symlink_metadata(&path).is_ok_and(|m| m.is_file()) {
            let _ = fs::remove_file(&path);
        }
    }
}

/// ジャーナルを削除して root を fsync する。この成功が削除確定のコミット点。
pub(super) fn remove_journal(root: &Path) -> std::io::Result<()> {
    match fs::remove_file(journal_path(root)) {
        Ok(()) => {}
        Err(e) if e.kind() == ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    sync_dir(root)
}

fn untrusted(msg: &str) -> OciError {
    err(OciErrorCode::FailedPrecondition, msg)
}

/// ジャーナルを読む。無ければ `None`。信頼できない・壊れている場合はファイルに触らずエラー。
pub(super) fn read_journal(root: &Path) -> Result<Option<GcJournal>, OciError> {
    let path = journal_path(root);
    let pre = match fs::symlink_metadata(&path) {
        Ok(m) => m,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(err(OciErrorCode::Internal, "failed to stat gc journal")),
    };
    if !pre.is_file() {
        return Err(untrusted("gc journal is not a regular file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if pre.mode() & 0o022 != 0 {
            return Err(untrusted("gc journal is writable by group or others"));
        }
    }
    if pre.len() > MAX_GC_JOURNAL_BYTES {
        return Err(err(
            OciErrorCode::ResourceExhausted,
            "gc journal is too large",
        ));
    }
    let file =
        File::open(&path).map_err(|_| err(OciErrorCode::Internal, "failed to open gc journal"))?;
    let post = file
        .metadata()
        .map_err(|_| err(OciErrorCode::Internal, "failed to stat gc journal"))?;
    if !post.is_file() {
        return Err(untrusted("gc journal is not a regular file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if pre.dev() != post.dev() || pre.ino() != post.ino() {
            return Err(untrusted("gc journal changed while opening"));
        }
    }
    let mut buf = Vec::new();
    file.take(MAX_GC_JOURNAL_BYTES + 1)
        .read_to_end(&mut buf)
        .map_err(|_| err(OciErrorCode::Internal, "failed to read gc journal"))?;
    if buf.len() as u64 > MAX_GC_JOURNAL_BYTES {
        return Err(err(
            OciErrorCode::ResourceExhausted,
            "gc journal is too large",
        ));
    }
    let raw: RawJournal = serde_json::from_slice(&buf)
        .map_err(|_| err(OciErrorCode::DataLoss, "gc journal is corrupt"))?;
    from_raw(raw).map(Some)
}

/// blob ファイル 1 件の削除結果。
pub(super) enum BlobRemoval {
    Deleted(u64),
    Absent,
    Kept,
}

/// 通常ファイルだけを消す。symlink・その他は辿らず触らない（`Kept`）。
pub(super) fn remove_blob_durable(root: &Path, digest: &Digest) -> BlobRemoval {
    let Ok(path) = blob_path(root, digest) else {
        return BlobRemoval::Kept;
    };
    match fs::symlink_metadata(&path) {
        Ok(m) if m.is_file() => {
            let len = m.len();
            match fs::remove_file(&path) {
                Ok(()) => BlobRemoval::Deleted(len),
                Err(e) if e.kind() == ErrorKind::NotFound => BlobRemoval::Absent,
                Err(_) => BlobRemoval::Kept,
            }
        }
        Ok(_) => BlobRemoval::Kept,
        Err(e) if e.kind() == ErrorKind::NotFound => BlobRemoval::Absent,
        Err(_) => BlobRemoval::Kept,
    }
}

/// blob の一括削除の結果（いずれも入力順）。
#[derive(Debug, Default)]
pub(super) struct Sweep {
    pub deleted: Vec<(Digest, u64)>,
    pub absent: Vec<Digest>,
    pub undeleted: Vec<Digest>,
}

/// `blobs` を unlink する。`dirs_present` が偽ならディレクトリが無いので全件 `absent` とする。
pub(super) fn sweep_blobs(root: &Path, blobs: &[Digest], dirs_present: bool) -> Sweep {
    let mut s = Sweep::default();
    for b in blobs {
        if !dirs_present {
            s.absent.push(b.clone());
            continue;
        }
        match remove_blob_durable(root, b) {
            BlobRemoval::Deleted(n) => s.deleted.push((b.clone(), n)),
            BlobRemoval::Absent => s.absent.push(b.clone()),
            BlobRemoval::Kept => s.undeleted.push(b.clone()),
        }
    }
    s
}

/// unlink 後の永続化を確定させる。
///
/// 1 件でも unlink したら（`force_blob_dir_sync` が真なら件数に関わらず）`blobs/sha256` を fsync する。消せなかった blob があれば、その分でジャーナルを
/// 書き直して保持する。このとき fsync が失敗していたら、unlink 済みの blob（`deleted`）も書き直した
/// ジャーナルに残す（クラッシュで unlink が巻き戻っても次の再試行で消し直せるようにする）。
/// 書き直しに失敗したときは attempts を永続化できず上限に届かないため、ジャーナルを削除して
/// `Abandoned` にする（削除も失敗したら `Pending`）。
/// 全件片づいたらジャーナルを削除して root を fsync し、成功すれば `Confirmed`。
/// 消せない blob が `MAX_GC_RETRY_ATTEMPTS` 回目に達したらジャーナルを削除して `Abandoned`。
pub(super) fn settle(
    root: &Path,
    undeleted: &[Digest],
    deleted: &[Digest],
    prior_attempts: u32,
    force_blob_dir_sync: bool,
) -> DeletionDurability {
    // 復旧では今回の削除件数に依存せず fsync する（前回プロセスが unlink 後・fsync 前に落ちた場合に備える）。
    let blobs_synced =
        (deleted.is_empty() && !force_blob_dir_sync) || sync_dir(&blob_dir(root)).is_ok();
    if !undeleted.is_empty() {
        let attempts = prior_attempts.saturating_add(1);
        let abandon = || match remove_journal(root) {
            Ok(()) => DeletionDurability::Abandoned,
            Err(_) => DeletionDurability::Pending,
        };
        if attempts >= MAX_GC_RETRY_ATTEMPTS {
            // 断念: 消せない blob は孤児として残し、ジャーナルを片づけて新しい削除を再び通す。
            return abandon();
        }
        let mut keep = undeleted.to_vec();
        if !blobs_synced {
            keep.extend_from_slice(deleted);
        }
        keep.sort();
        keep.dedup();
        let rest = GcJournal {
            delete_blobs: keep,
            attempts,
            ..GcJournal::default()
        };
        if write_journal(root, &rest).is_err() {
            return abandon();
        }
        return DeletionDurability::Pending;
    }
    if !blobs_synced {
        return DeletionDurability::Pending;
    }
    match remove_journal(root) {
        Ok(()) => DeletionDurability::Confirmed,
        Err(_) => DeletionDurability::Pending,
    }
}

/// 再試行（ロールフォワード）の結果。配列はいずれも昇順で決定的。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct PendingDeletionRecovery {
    /// テーブルから外した manifest。
    pub removed_manifests: Vec<Digest>,
    /// 外したタグ。
    pub untagged: Vec<TagKey>,
    /// 消した blob。
    pub deleted_blobs: Vec<Digest>,
    /// 既に無かった blob。
    pub absent_blobs: Vec<Digest>,
    /// 数え直しで参照・リースが見つかったため残した blob。
    pub kept_blobs: Vec<Digest>,
    /// 消せなかった blob（ジャーナルに残り、次の lock で再試行される）。
    pub undeleted_blobs: Vec<Digest>,
    /// 参照が戻っていたため外さなかった manifest。
    pub conflicted_manifests: Vec<Digest>,
    /// 永続化の状態。
    pub durability: DeletionDurability,
}

impl ReferenceTable {
    /// manifest をテーブルから外した場合に消してよくなる blob（昇順）。副作用は無い。
    pub(super) fn blobs_deletable_after_removal(&self, manifest: &Digest) -> Vec<Digest> {
        // 構成が分からないコンテナ参照が残る間は blob を 1 つも削除候補にしない（#2341・OCI-7）。
        if self.has_unresolved_container_refs() {
            return Vec::new();
        }
        let Some(comp) = self.manifests.get(manifest) else {
            return Vec::new();
        };
        comp.blobs()
            .into_iter()
            .filter(|b| {
                let refs = self.blob_references(b);
                refs.leases.is_empty() && refs.referencing_manifests.iter().all(|m| m == manifest)
            })
            .cloned()
            .collect()
    }

    /// 残っている削除ジャーナルがあれば、参照を数え直してから削除をやり直す（OCI-7・#851）。
    ///
    /// ストアの排他区間の内側で呼ぶ（[`super::ImageStore::lock`] が取得直後に呼ぶ）。無ければ
    /// `Ok(None)`（費用は stat 1 回）。ジャーナルが信頼できない・壊れているときはファイルに触らず
    /// エラーを返す（fail-closed）。冪等で、片づいた後の 2 回目は `Ok(None)`。
    pub fn resume_pending_deletion(
        &mut self,
        root: &Path,
    ) -> Result<Option<PendingDeletionRecovery>, OciError> {
        let Some(journal) = read_journal(root)? else {
            return Ok(None);
        };
        let mut out = PendingDeletionRecovery::default();
        for (key, manifest) in &journal.untag {
            if self.tag_refs.get(key) == Some(manifest) {
                self.tag_refs.remove(key);
                out.untagged.push(key.clone());
            }
        }
        for m in &journal.manifests {
            if !self.manifests.contains_key(m) {
                continue;
            }
            if self.manifest_references(m).is_referenced() {
                out.conflicted_manifests.push(m.clone());
            } else {
                self.manifests.remove(m);
                out.removed_manifests.push(m.clone());
            }
        }
        // 数え直し: 構成に含む manifest かリースがある blob は残す。
        // 構成が分からないコンテナ参照が残る間は blob を消さない（#2341・OCI-7）。
        let unresolved = self.has_unresolved_container_refs();
        let mut to_sweep = Vec::new();
        for b in &journal.delete_blobs {
            let refs = self.blob_references(b);
            if !unresolved && refs.referencing_manifests.is_empty() && refs.leases.is_empty() {
                to_sweep.push(b.clone());
            } else {
                out.kept_blobs.push(b.clone());
            }
        }
        // ディレクトリ異常（symlink 等）なら何も消さず、全件を残してジャーナルを保持する。
        let mut force_sync = false;
        let sweep = match check_blob_dirs(root) {
            Ok(present) => {
                force_sync = present;
                sweep_blobs(root, &to_sweep, present)
            }
            Err(_) => Sweep {
                undeleted: to_sweep,
                ..Sweep::default()
            },
        };
        let deleted_digests: Vec<Digest> = sweep.deleted.iter().map(|(d, _)| d.clone()).collect();
        out.durability = settle(
            root,
            &sweep.undeleted,
            &deleted_digests,
            journal.attempts,
            force_sync,
        );
        out.deleted_blobs = sweep.deleted.into_iter().map(|(d, _)| d).collect();
        out.absent_blobs = sweep.absent;
        out.undeleted_blobs = sweep.undeleted;
        Ok(Some(out))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::image_management::{
        ContainerRefId, ImageRmKind, ImageRmOptions, ImageRmTarget, ImageStore,
        ManifestComposition, PullId, StoppedContainers,
    };
    use crate::instrument::testing::Collect;
    use crate::instrument::{OciOpKind, OciOpOutcome};
    use std::sync::Arc;

    static SEQ: AtomicU64 = AtomicU64::new(0);

    fn d(n: u8) -> Digest {
        Digest::parse(&format!("sha256:{}", format!("{n:02x}").repeat(32))).unwrap()
    }
    fn tk(t: &str) -> TagKey {
        TagKey::new(
            RegistryHost::parse("registry.example").unwrap(),
            Repository::parse("lib/app").unwrap(),
            Tag::parse(t).unwrap(),
        )
    }

    struct Root(PathBuf);
    impl Root {
        fn new() -> Self {
            let n = SEQ.fetch_add(1, Ordering::SeqCst);
            let p = std::env::temp_dir().join(format!("fc-oci-gcj-{}-{n}", std::process::id()));
            let _ = fs::remove_dir_all(&p);
            fs::create_dir_all(p.join("blobs").join("sha256")).unwrap();
            Root(p)
        }
        fn put(&self, dg: &Digest) {
            fs::write(blob_path(&self.0, dg).unwrap(), b"x").unwrap();
        }
        fn exists(&self, dg: &Digest) -> bool {
            fs::symlink_metadata(blob_path(&self.0, dg).unwrap()).is_ok()
        }
        fn journal(&self) -> bool {
            fs::symlink_metadata(self.0.join(GC_JOURNAL_FILE_NAME)).is_ok()
        }
    }
    impl Drop for Root {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    // A=0xa0 (config 0xc1, layers 0x10 0x11), B=0xb0 (config 0xc2, layers 0x10 0x12)。
    fn table() -> ReferenceTable {
        let mut t = ReferenceTable::new();
        t.register_manifest(
            d(0xa0),
            ManifestComposition::new(d(0xc1), vec![d(0x10), d(0x11)]).unwrap(),
        )
        .unwrap();
        t.register_manifest(
            d(0xb0),
            ManifestComposition::new(d(0xc2), vec![d(0x10), d(0x12)]).unwrap(),
        )
        .unwrap();
        t
    }
    fn files(root: &Root) {
        for n in [0xc1, 0x10, 0x11, 0xc2, 0x12] {
            root.put(&d(n));
        }
    }
    /// A を消す意図のジャーナル（0x10 は B と共有のため含めない）。
    fn journal_a() -> GcJournal {
        GcJournal {
            manifests: vec![d(0xa0)],
            untag: vec![(tk("v1"), d(0xa0))],
            delete_blobs: vec![d(0x11), d(0xc1)],
            attempts: 0,
        }
    }
    fn after_state(root: &Root, t: &ReferenceTable) {
        assert_eq!(
            t.manifests().map(|(x, _)| x.clone()).collect::<Vec<_>>(),
            vec![d(0xb0)]
        );
        assert_eq!(t.tags().count(), 0);
        for n in [0xc1, 0x11] {
            assert!(!root.exists(&d(n)));
        }
        for n in [0x10, 0xc2, 0x12] {
            assert!(root.exists(&d(n)));
        }
        assert!(!root.journal());
    }

    /// OCI-7: ジャーナルの前の中断は削除前のまま（ジャーナルも無く、何も消えていない）。
    #[test]
    fn oci7_interrupted_before_journal_converges_to_before() {
        let root = Root::new();
        files(&root);
        let store = ImageStore::with_table(&root.0, table()).unwrap();
        assert!(store.recover_pending_deletion().unwrap().is_none());
        for n in [0xc1, 0x10, 0x11, 0xc2, 0x12] {
            assert!(root.exists(&d(n)));
        }
        assert_eq!(store.lock().unwrap().manifests().count(), 2);
    }

    /// OCI-7: ジャーナル後・unlink 前の中断は、再起動で戻ったテーブルでも削除後に収束する。
    #[test]
    fn oci7_interrupted_after_journal_before_unlink_converges_to_after() {
        let root = Root::new();
        files(&root);
        write_journal(&root.0, &journal_a()).unwrap();
        let mut t = table();
        t.register_tag(tk("v1"), &d(0xa0)).unwrap();
        let store = ImageStore::with_table(&root.0, t).unwrap();
        let rec = store.recover_pending_deletion().unwrap().unwrap();
        assert_eq!(rec.removed_manifests, vec![d(0xa0)]);
        assert_eq!(rec.untagged, vec![tk("v1")]);
        assert_eq!(rec.deleted_blobs, vec![d(0x11), d(0xc1)]);
        assert_eq!(rec.durability, DeletionDurability::Confirmed);
        after_state(&root, &store.lock().unwrap());
    }

    /// OCI-7: k / n 件を unlink した後の中断は、k の全通りで同じ削除後に収束する。
    #[test]
    fn oci7_interrupted_midway_converges_to_after() {
        let blobs = [d(0x11), d(0xc1)];
        for k in 0..=blobs.len() {
            let root = Root::new();
            files(&root);
            write_journal(&root.0, &journal_a()).unwrap();
            for b in &blobs[..k] {
                fs::remove_file(blob_path(&root.0, b).unwrap()).unwrap();
            }
            let mut t = table();
            t.register_tag(tk("v1"), &d(0xa0)).unwrap();
            let store = ImageStore::with_table(&root.0, t).unwrap();
            let rec = store.recover_pending_deletion().unwrap().unwrap();
            assert_eq!(rec.deleted_blobs.len(), blobs.len() - k, "k={k}");
            assert_eq!(rec.absent_blobs.len(), k, "k={k}");
            after_state(&root, &store.lock().unwrap());
        }
    }

    /// OCI-7: 全件 unlink 後・ジャーナル削除前の中断は、ジャーナルだけを片づける。
    #[test]
    fn oci7_interrupted_after_all_unlinks_clears_journal() {
        let root = Root::new();
        files(&root);
        write_journal(&root.0, &journal_a()).unwrap();
        for n in [0x11, 0xc1] {
            fs::remove_file(blob_path(&root.0, &d(n)).unwrap()).unwrap();
        }
        let store = ImageStore::with_table(&root.0, table()).unwrap();
        let rec = store.recover_pending_deletion().unwrap().unwrap();
        assert_eq!(rec.absent_blobs, vec![d(0x11), d(0xc1)]);
        assert!(rec.deleted_blobs.is_empty());
        assert_eq!(rec.durability, DeletionDurability::Confirmed);
        assert!(!root.journal());
    }

    /// OCI-7: 再起動後のテーブルに別の manifest・リースが blob を参照していれば、その blob は残る。
    #[test]
    fn oci7_recovery_recounts_and_keeps_blob_referenced_after_restart() {
        let root = Root::new();
        files(&root);
        write_journal(&root.0, &journal_a()).unwrap();
        let mut t = table();
        // 0x11 は別の manifest C の構成に、0xc1 は pull リースに守られている。
        t.register_manifest(
            d(0xd0),
            ManifestComposition::new(d(0xc2), vec![d(0x11)]).unwrap(),
        )
        .unwrap();
        t.acquire_lease(d(0xc1), PullId::new("p1").unwrap());
        let store = ImageStore::with_table(&root.0, t).unwrap();
        let rec = store.recover_pending_deletion().unwrap().unwrap();
        assert_eq!(rec.kept_blobs, vec![d(0x11), d(0xc1)]);
        assert!(rec.deleted_blobs.is_empty());
        assert!(root.exists(&d(0x11)) && root.exists(&d(0xc1)));
        assert!(!root.journal());
    }

    /// OCI-7: ジャーナルの manifest にコンテナ参照が戻っていたら外さず、conflicted に載せる。
    #[test]
    fn oci7_recovery_keeps_manifest_that_regained_reference() {
        let root = Root::new();
        files(&root);
        write_journal(&root.0, &journal_a()).unwrap();
        let mut t = table();
        t.register_container(ContainerRefId::new("c1").unwrap(), &d(0xa0))
            .unwrap();
        let store = ImageStore::with_table(&root.0, t).unwrap();
        let rec = store.recover_pending_deletion().unwrap().unwrap();
        assert_eq!(rec.conflicted_manifests, vec![d(0xa0)]);
        assert!(rec.removed_manifests.is_empty());
        // manifest が在庫に残るので、その構成の blob も残る。
        assert_eq!(rec.kept_blobs, vec![d(0x11), d(0xc1)]);
        assert_eq!(store.lock().unwrap().manifests().count(), 2);
    }

    /// OCI-7: 再試行は冪等（2 回目は何もしない）。
    #[test]
    fn oci7_recovery_is_idempotent() {
        let root = Root::new();
        files(&root);
        write_journal(&root.0, &journal_a()).unwrap();
        let store = ImageStore::with_table(&root.0, table()).unwrap();
        assert!(store.recover_pending_deletion().unwrap().is_some());
        assert!(store.recover_pending_deletion().unwrap().is_none());
    }

    /// OCI-7: 正常系の rm・prune は Confirmed でジャーナルを残さない。untag だけなら作らない。
    #[test]
    fn oci7_rm_and_prune_report_confirmed_durability() {
        let root = Root::new();
        files(&root);
        let mut t = table();
        t.register_tag(tk("v1"), &d(0xa0)).unwrap();
        t.register_tag(tk("v2"), &d(0xa0)).unwrap();
        let stopped = StoppedContainers::new();
        let opts = ImageRmOptions::default();
        // タグが複数ある状態でタグ指定の rm は untag だけ。
        let out = t
            .execute_image_rm(&root.0, &ImageRmTarget::Tag(tk("v1")), &opts, &stopped)
            .unwrap();
        assert_eq!(out.kind, ImageRmKind::UntagOnly);
        assert_eq!(out.durability, DeletionDurability::NotApplicable);
        assert!(!root.journal());
        let out = t
            .execute_image_rm(&root.0, &ImageRmTarget::Tag(tk("v2")), &opts, &stopped)
            .unwrap();
        assert_eq!(out.kind, ImageRmKind::Deleted);
        assert_eq!(out.deleted_blobs, vec![d(0x11), d(0xc1)]);
        assert_eq!(out.durability, DeletionDurability::Confirmed);
        assert!(!root.journal());
        let out = t.execute_image_prune(&root.0).unwrap();
        assert_eq!(out.removed_manifests, vec![d(0xb0)]);
        assert_eq!(out.durability, DeletionDurability::Confirmed);
        assert!(!root.journal());
    }

    /// OCI-7: 消せなかった blob はジャーナルに残り、障害を取り除いた後の lock で片づく。
    #[cfg(unix)]
    #[test]
    fn oci7_undeleted_blob_keeps_journal_for_retry() {
        let root = Root::new();
        files(&root);
        let p = blob_path(&root.0, &d(0x11)).unwrap();
        fs::remove_file(&p).unwrap();
        fs::create_dir(&p).unwrap();
        let store = ImageStore::with_table(&root.0, table()).unwrap();
        let out = store.lock().unwrap().execute_image_prune(&root.0).unwrap();
        assert_eq!(out.undeleted_blobs, vec![d(0x11)]);
        assert_eq!(out.durability, DeletionDurability::Pending);
        let j = read_journal(&root.0).unwrap().unwrap();
        assert_eq!(j.delete_blobs, vec![d(0x11)]);
        // 障害が残る間は再試行も Pending のまま、新しい削除は拒否される。
        let rec = store.recover_pending_deletion().unwrap().unwrap();
        assert_eq!(rec.undeleted_blobs, vec![d(0x11)]);
        // 再試行後も片づかないのでジャーナルは残り、新しい削除は FailedPrecondition。
        let mut t2 = table();
        let e = t2.execute_image_prune(&root.0).unwrap_err();
        assert_eq!(e.code(), OciErrorCode::FailedPrecondition);
        fs::remove_dir(&p).unwrap();
        let rec = store.recover_pending_deletion().unwrap().unwrap();
        assert_eq!(rec.absent_blobs, vec![d(0x11)]);
        assert_eq!(rec.durability, DeletionDurability::Confirmed);
        assert!(!root.journal());
    }

    /// OCI-7: 永続的に消せない blob は再試行の上限で断念し、ジャーナルが片づいて新しい削除が通る。
    #[cfg(unix)]
    #[test]
    fn oci7_permanently_undeletable_blob_is_abandoned_after_retry_limit() {
        let root = Root::new();
        files(&root);
        let p = blob_path(&root.0, &d(0x11)).unwrap();
        fs::remove_file(&p).unwrap();
        fs::create_dir(&p).unwrap();
        let store = ImageStore::with_table(&root.0, table()).unwrap();
        let out = store.lock().unwrap().execute_image_prune(&root.0).unwrap();
        assert_eq!(out.durability, DeletionDurability::Pending);
        // 1 回目は prune、以降は lock 時の再試行。上限の手前までは Pending のまま残る。
        for _ in 2..MAX_GC_RETRY_ATTEMPTS {
            let rec = store.recover_pending_deletion().unwrap().unwrap();
            assert_eq!(rec.durability, DeletionDurability::Pending);
            assert!(root.journal());
        }
        let rec = store.recover_pending_deletion().unwrap().unwrap();
        assert_eq!(rec.durability, DeletionDurability::Abandoned);
        assert_eq!(rec.undeleted_blobs, vec![d(0x11)]);
        assert!(!root.journal());
        // 孤児として残り、新しい削除は拒否されない。
        assert!(fs::symlink_metadata(&p).is_ok());
        ensure_no_pending_journal(&root.0).unwrap();
        assert!(store.recover_pending_deletion().unwrap().is_none());
    }

    /// OCI-7: fsync が失敗し消せない blob もあるとき、unlink 済みの blob もジャーナルに残す。
    #[test]
    fn oci7_settle_keeps_deleted_blobs_when_blob_dir_fsync_fails() {
        let root = Root::new();
        // blobs/sha256 を消して fsync を失敗させる。
        fs::remove_dir(blob_dir(&root.0)).unwrap();
        let st = settle(&root.0, &[d(0x22)], &[d(0x11)], 0, false);
        assert_eq!(st, DeletionDurability::Pending);
        let j = read_journal(&root.0).unwrap().unwrap();
        assert_eq!(j.delete_blobs, vec![d(0x11), d(0x22)]);
        assert_eq!(j.attempts, 1);
    }

    /// OCI-7: ジャーナルの書き直しに失敗しても上限判定を諦めず、断念して片づける。
    #[cfg(unix)]
    #[test]
    fn oci7_settle_abandons_when_journal_rewrite_fails() {
        use std::os::unix::fs::PermissionsExt;
        let root = Root::new();
        // root を書き込み不可にして、一時ファイルの作成（書き直し）を失敗させる。
        fs::set_permissions(&root.0, fs::Permissions::from_mode(0o500)).unwrap();
        let writable = fs::File::create(root.0.join("probe")).is_ok();
        let st = settle(&root.0, &[d(0x22)], &[], 0, false);
        fs::set_permissions(&root.0, fs::Permissions::from_mode(0o700)).unwrap();
        // 特権で実行されて書き込めてしまう環境では前提が成り立たないので判定しない。
        if !writable {
            assert_eq!(st, DeletionDurability::Abandoned);
        }
    }

    /// OCI-7: 書き込み中のクラッシュで残った一時ファイルは lock 時に回収される。
    #[test]
    fn oci7_stale_journal_tmp_is_reaped_on_lock() {
        let root = Root::new();
        files(&root);
        let stale = root.0.join(format!("{TMP_PREFIX}99999-0"));
        fs::write(&stale, b"partial").unwrap();
        let other = root.0.join("unrelated.tmp");
        fs::write(&other, b"keep").unwrap();
        let store = ImageStore::with_table(&root.0, table()).unwrap();
        assert!(store.recover_pending_deletion().unwrap().is_none());
        assert!(fs::symlink_metadata(&stale).is_err());
        assert!(other.exists());
    }

    /// OCI-7: 片づかないジャーナルがある間、rm は FailedPrecondition でテーブルもファイルも変えない。
    #[test]
    fn oci7_new_gc_refused_while_journal_pending() {
        let root = Root::new();
        files(&root);
        write_journal(&root.0, &journal_a()).unwrap();
        let mut t = table();
        let snapshot = t.clone();
        let e = t
            .execute_image_rm(
                &root.0,
                &ImageRmTarget::Manifest(d(0xb0)),
                &ImageRmOptions::default(),
                &StoppedContainers::new(),
            )
            .unwrap_err();
        assert_eq!(e.code(), OciErrorCode::FailedPrecondition);
        assert_eq!(t, snapshot);
        assert!(root.exists(&d(0x12)));
    }

    /// 信頼性検査: 壊れた JSON・未知の version は DataLoss、ファイルには触らない。
    #[test]
    fn oci7_journal_corrupt_or_unknown_version_is_data_loss() {
        for body in [
            "not json".to_string(),
            r#"{"version":9,"manifests":[],"untag":[],"delete_blobs":[]}"#.to_string(),
            r#"{"version":1,"manifests":["bad"],"untag":[],"delete_blobs":[]}"#.to_string(),
        ] {
            let root = Root::new();
            files(&root);
            let path = root.0.join(GC_JOURNAL_FILE_NAME);
            fs::write(&path, &body).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            }
            let store = ImageStore::with_table(&root.0, table()).unwrap();
            let e = store.lock().unwrap_err();
            assert_eq!(e.code(), OciErrorCode::DataLoss, "{body}");
            assert_eq!(fs::read_to_string(&path).unwrap(), body);
            assert!(root.exists(&d(0x11)));
        }
    }

    /// 上限: 件数・サイズの超過は ResourceExhausted（書き込みも読み込みも）。
    #[test]
    fn oci7_journal_limits_are_enforced() {
        let root = Root::new();
        let big = GcJournal {
            delete_blobs: vec![d(1); MAX_GC_JOURNAL_ENTRIES + 1],
            ..GcJournal::default()
        };
        assert_eq!(
            write_journal(&root.0, &big).unwrap_err().code(),
            OciErrorCode::ResourceExhausted
        );
        assert!(!root.journal());
        let path = root.0.join(GC_JOURNAL_FILE_NAME);
        let f = File::create(&path).unwrap();
        f.set_len(MAX_GC_JOURNAL_BYTES + 1).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert_eq!(
            read_journal(&root.0).unwrap_err().code(),
            OciErrorCode::ResourceExhausted
        );
    }

    /// 信頼性検査: symlink・ディレクトリは拒否し、リンク先を変えない。group 書き込み可も拒否する。
    #[cfg(unix)]
    #[test]
    fn oci7_journal_rejects_symlink_dir_and_group_writable() {
        use std::os::unix::fs::PermissionsExt;
        let root = Root::new();
        let target = root.0.join("target");
        fs::write(&target, b"keep").unwrap();
        let path = root.0.join(GC_JOURNAL_FILE_NAME);
        std::os::unix::fs::symlink(&target, &path).unwrap();
        assert_eq!(
            read_journal(&root.0).unwrap_err().code(),
            OciErrorCode::FailedPrecondition
        );
        assert_eq!(fs::read(&target).unwrap(), b"keep");
        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();
        assert_eq!(
            read_journal(&root.0).unwrap_err().code(),
            OciErrorCode::FailedPrecondition
        );
        fs::remove_dir(&path).unwrap();
        write_journal(&root.0, &journal_a()).unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        fs::set_permissions(&path, fs::Permissions::from_mode(0o660)).unwrap();
        assert_eq!(
            read_journal(&root.0).unwrap_err().code(),
            OciErrorCode::FailedPrecondition
        );
    }

    /// 書き込んだジャーナルは同じ内容で読み戻せる。
    #[test]
    fn oci7_journal_roundtrip() {
        let root = Root::new();
        write_journal(&root.0, &journal_a()).unwrap();
        assert_eq!(read_journal(&root.0).unwrap(), Some(journal_a()));
    }

    /// REPAIR-4: ジャーナルがあったときだけ gc_recover が記録される。
    #[test]
    fn repair4_recovery_is_recorded_only_when_journal_exists() {
        let root = Root::new();
        files(&root);
        let rec = Arc::new(Collect::default());
        let store = ImageStore::with_table(&root.0, table())
            .unwrap()
            .with_recorder(rec.clone());
        drop(store.lock().unwrap());
        let n = |c: &Collect| {
            c.items()
                .iter()
                .filter(|s| s.kind() == OciOpKind::RecoverPendingDeletion)
                .count()
        };
        assert_eq!(n(&rec), 0);
        write_journal(&root.0, &journal_a()).unwrap();
        drop(store.lock().unwrap());
        let items = rec.items();
        let r: Vec<_> = items
            .iter()
            .filter(|s| s.kind() == OciOpKind::RecoverPendingDeletion)
            .collect();
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].outcome(), OciOpOutcome::Success);
        assert_eq!(r[0].kind().as_str(), "oci.image.gc_recover");
    }
}
