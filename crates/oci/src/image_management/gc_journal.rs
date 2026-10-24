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
//! 検査するが、所有者（uid）は検査しない。ストア root 自体の所有者・権限・祖先の検査は
//! `ImageStore::open` が行う（#2381。unix のみ）ため、ここでは root が信頼できることを前提とする。
//! 本モジュールの永続化操作（ジャーナル・一時ファイルの回収・blob の削除と fsync）は検査済み root の
//! ハンドル（`root_handle::RootHandle`）起点で、Linux の x86_64 / aarch64 では検査後に root が差し替えられても
//! 差し替え後のディレクトリへ届かない（#2638）。
//! 書き込み中のクラッシュで残る一時ファイル `@gc-pending.json.tmp-*` は、lock 取得時に回収する。
//!
//! 呼び出し元: `remove`（`execute_image_rm`）・`prune`（`execute_image_prune`）・`store`（lock 時の再試行）。
//!
//! 未実装・保証範囲（実装済みを装わない。REPAIR-3）:
//! - 保証するのはジャーナルと blob ファイルの unlink の永続化だけである。manifest の在庫・タグ・
//!   pull リースのテーブル自体はまだメモリ上の別物で、テーブルの永続化は別 issue の担当。
//!   そのため再試行時の新しいプロセスのテーブルには、ジャーナルの manifest が既に無いことが多い。
//! - Windows ではディレクトリを std で開けないため、ディレクトリの fsync は行わない（no-op）。
//!   そのため Windows では削除が完了しても [`DeletionDurability::Confirmed`] は返さず
//!   [`DeletionDurability::Unconfirmed`] を返す（永続化を確認できていない）。
//! - コンテナ参照テーブルの未解決（unresolved）参照の考慮は、その永続化が入ってから足す。

use std::io::{ErrorKind, Read, Write};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};

use super::container_ref_persist::CONTAINER_REFS_TMP_PREFIX;
use super::inventory_persist::IMAGE_INVENTORY_TMP_PREFIX;
use super::root_handle::{BlobDir, RootHandle};
#[cfg(test)]
use super::usage::blob_dir;
use super::{MAX_CACHE_SCAN_ENTRIES, ReferenceTable, TagKey};
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
    /// blob の unlink とジャーナル削除は完了したが、このプラットフォームではディレクトリの fsync が
    /// できないため永続化を確認できていない（Windows。ベストエフォート）。`Confirmed` と同等には扱わない。
    Unconfirmed,
}

/// ディレクトリの fsync でディレクトリエントリの永続化を確認できるプラットフォームか。
const DIR_SYNC_SUPPORTED: bool = cfg!(unix);

/// 全件片づいて最後の fsync まで成功したときの永続化状態。fsync できない環境では `Confirmed` を返さない。
fn success_durability(dir_sync_supported: bool) -> DeletionDurability {
    if dir_sync_supported {
        DeletionDurability::Confirmed
    } else {
        DeletionDurability::Unconfirmed
    }
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

impl GcJournal {
    /// 何も消さない空のジャーナル（削除確定の fsync が未了であることを示す墓標）か。
    #[cfg(test)]
    fn is_tombstone(&self) -> bool {
        self.manifests.is_empty() && self.untag.is_empty() && self.delete_blobs.is_empty()
    }
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

/// root ディレクトリの fsync（検査済み root の fd 起点）。Windows では std で開けないため何もしない。
fn sync_dir(root: &RootHandle) -> std::io::Result<()> {
    #[cfg(test)]
    if test_hook::should_fail(root.path()) {
        return Err(std::io::Error::other("injected directory fsync failure"));
    }
    root.sync()
}

/// `blobs/sha256` の fsync（root の fd から開き直す。ディレクトリが無ければ `NotFound`）。
fn sync_blob_dir(root: &RootHandle) -> std::io::Result<()> {
    #[cfg(test)]
    if test_hook::should_fail(&blob_dir(root.path())) {
        return Err(std::io::Error::other("injected directory fsync failure"));
    }
    match root.open_blob_dir() {
        Ok(Some(d)) => d.sync(),
        Ok(None) => Err(std::io::Error::new(
            ErrorKind::NotFound,
            "blob directory is missing",
        )),
        Err(e) => Err(std::io::Error::other(e.message().to_owned())),
    }
}

/// テスト専用: 指定ディレクトリの fsync を回数限定で失敗させる（OCI-7 の fsync 失敗経路の検証用）。
#[cfg(test)]
mod test_hook {
    use std::cell::{Cell, RefCell};
    use std::path::{Path, PathBuf};

    thread_local! {
        static FAIL: RefCell<Option<(PathBuf, u32)>> = const { RefCell::new(None) };
        static FAIL_UNLINK: Cell<u32> = const { Cell::new(0) };
        static FAIL_REWRITE: Cell<u32> = const { Cell::new(0) };
    }

    /// ジャーナルの unlink を `times` 回失敗させる。
    pub(super) fn fail_unlink(times: u32) {
        FAIL_UNLINK.with(|c| c.set(times));
    }

    /// 削除開始後のジャーナル書き直しを公開前に `times` 回失敗させる。
    pub(super) fn fail_rewrite(times: u32) {
        FAIL_REWRITE.with(|c| c.set(times));
    }

    fn take(c: &'static std::thread::LocalKey<Cell<u32>>) -> bool {
        c.with(|c| {
            let n = c.get();
            c.set(n.saturating_sub(1));
            n > 0
        })
    }

    pub(super) fn should_fail_unlink() -> bool {
        take(&FAIL_UNLINK)
    }

    pub(super) fn should_fail_rewrite() -> bool {
        take(&FAIL_REWRITE)
    }

    pub(super) fn fail_sync_of(dir: &Path, times: u32) {
        FAIL.with(|f| *f.borrow_mut() = Some((dir.to_path_buf(), times)));
    }

    pub(super) fn clear() {
        FAIL_UNLINK.with(|c| c.set(0));
        FAIL_REWRITE.with(|c| c.set(0));
        FAIL.with(|f| *f.borrow_mut() = None);
    }

    pub(super) fn should_fail(dir: &Path) -> bool {
        FAIL.with(|f| {
            let mut f = f.borrow_mut();
            match f.as_mut() {
                Some((p, n)) if p == dir && *n > 0 => {
                    *n -= 1;
                    true
                }
                _ => false,
            }
        })
    }
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

/// ジャーナルのパスにファイルが 1 つでも在る（墓標・壊れた・通常ファイル以外を含む）か。
///
/// 不変条件（OCI-7）。論証:
/// 1. **内容に依らない検査**: パスに何かが見えている間は、どのプロセスからも参照の追加（manifest・タグ・
///    コンテナ参照の登録、blob の公開・配置、pull リースの取得）と新しい削除の開始を拒否する。見えて
///    いることは永続化済みであることを意味しないので、root の fsync を確定させて消えるまで、墓標も
///    無害とはみなさない。stat に失敗した場合も存在とみなす（fail-closed）。
/// 2. **単調で fsync 確定済みの遷移**: 削除意図は縮む方向にしか動かない（テーブル操作入り → blob のみ →
///    墓標 → 消滅）。各段は rename → root の fsync で進め、削除意図を持つジャーナルを直接 unlink しない
///    （[`remove_journal`] は墓標への置換を fsync で確定してから、墓標だけを unlink する）。
///
/// したがって、クラッシュで復活し得るのは最後に fsync で確定した状態以下の削除意図だけで、消滅の直前に
/// 確定する状態は墓標（意図なし）である。消滅していない状態は(1)で参照の追加を拒否するので、ジャーナル
/// 作成後に追加された参照が、復活したジャーナルで消されることはない。別プロセスの復旧も、manifest・
/// タグ・リースは `@image-inventory.json`（`inventory_persist`・#2380）、コンテナ参照は
/// `@container-refs.json` に永続化されて排他取得ごとに読み直されるため、別プロセスのリースや再公開された
/// blob の参照を数え直しに含め、それらの blob を消さない。
pub(super) fn journal_exists(root: &RootHandle) -> bool {
    !matches!(root.stat_name(GC_JOURNAL_FILE_NAME), Ok(None))
}

pub(super) fn ensure_no_pending_journal(root: &RootHandle) -> Result<(), OciError> {
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
pub(super) fn write_journal(root: &RootHandle, journal: &GcJournal) -> Result<(), OciError> {
    persist_journal(root, journal, true)
}

/// 削除開始後にジャーナルを書き直す（`settle` 専用）。
///
/// 初回公開の [`write_journal`] と違い、rename 後に root の fsync だけが失敗しても取り消さない。
/// 取り消すと削除対象を持つジャーナルが消え、電源断で unlink が巻き戻っても再削除できなくなる（OCI-7）。
/// その場合は `Ok` を返す（書き直したジャーナルは見えており、永続化は未確定）。呼び出し側は
/// 常に `Pending` を返し、次の lock の復旧が再試行する。公開前の失敗は元のジャーナルが残る `Err`。
fn rewrite_journal(root: &RootHandle, journal: &GcJournal) -> Result<(), OciError> {
    #[cfg(test)]
    if test_hook::should_fail_rewrite() {
        return Err(err(OciErrorCode::Internal, "injected rewrite failure"));
    }
    persist_journal(root, journal, false)
}

fn persist_journal(
    root: &RootHandle,
    journal: &GcJournal,
    revoke_on_unsynced: bool,
) -> Result<(), OciError> {
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
    match publish_journal(root, &bytes) {
        Ok(()) => Ok(()),
        Err(PublishError::BeforePublish) => {
            Err(err(OciErrorCode::Internal, "failed to persist gc journal"))
        }
        Err(PublishError::AfterPublish) if !revoke_on_unsynced => Ok(()),
        Err(PublishError::AfterPublish) => {
            // rename 済みで root の fsync だけが失敗した。ジャーナルは見えているが、ディレクトリエントリの
            // 永続化は未確定である。読み戻せても永続化の証明にならないため、削除（テーブル更新・unlink）は
            // 始めずに必ず Err を返す。取り消しは直接 unlink せず、墓標への置換を確定してから行う
            // （`remove_journal`）。確定できなければ見えているジャーナルか墓標が残り、変更は拒否され続け、
            // 次の lock の復旧が片づける（blob は消えないので余分に残す側にだけ誤る）。
            let revoked = remove_journal(root).is_ok();
            let msg = if revoked {
                "failed to persist gc journal"
            } else {
                "failed to persist gc journal and could not revoke it; the next store lock recovers it"
            };
            Err(err(OciErrorCode::Internal, msg))
        }
    }
}

/// ジャーナルの公開（rename）より前に失敗したか、後に失敗したか。
enum PublishError {
    /// 公開前の失敗。一時ファイルは掃除済みで、既存のジャーナルは変わらない。
    BeforePublish,
    /// rename 後の root の fsync の失敗。ジャーナルは公開済みで、永続化だけが未確定。
    AfterPublish,
}

/// 一時ファイル → fsync → rename → root の fsync。失敗を公開の前後で区別して返す。
fn publish_journal(root: &RootHandle, bytes: &[u8]) -> Result<(), PublishError> {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let tmp = format!(
        "{TMP_PREFIX}{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    );
    let before = (|| {
        let mut f = root.create_new(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        drop(f);
        root.rename(&tmp, GC_JOURNAL_FILE_NAME)
    })();
    if before.is_err() {
        let _ = root.unlink(&tmp);
        return Err(PublishError::BeforePublish);
    }
    sync_dir(root).map_err(|_| PublishError::AfterPublish)
}

/// 書き込み中のクラッシュで残った一時ファイルを回収する（通常ファイルだけ。ストアの排他区間内で、`lock` が取得直後に呼ぶ）。
///
/// `prefixes` のいずれかで始まる root 直下の通常ファイルだけを消す（symlink・ディレクトリ・固定名の
/// 本体ファイルは触らない）。対象は GC ジャーナルの一時ファイル（`@gc-pending.json.tmp-*`）と
/// コンテナ参照テーブルの一時ファイル（`@container-refs.json.tmp-*`。#2379・OCI-7）と在庫ファイルの
/// 一時ファイル（`@image-inventory.json.tmp-*`。#2380）。いずれも書き手が
/// 排他区間の中でしか作らないため、排他を取った時点で残っているものは中断した書き込みの残骸で、PID の
/// 生存確認は要らない。走査は 1 回にまとめ、件数は `MAX_CACHE_SCAN_ENTRIES` で打ち切る。
pub(super) fn reap_stale_tmp(root: &RootHandle, prefixes: &[&str]) {
    let Ok(names) = root.list_names(MAX_CACHE_SCAN_ENTRIES) else {
        return;
    };
    for name in names {
        if !prefixes
            .iter()
            .any(|p| name.to_string_lossy().starts_with(p))
        {
            continue;
        }
        if root
            .stat_name(&name)
            .ok()
            .flatten()
            .is_some_and(|m| m.is_file())
        {
            let _ = root.unlink(&name);
        }
    }
}

/// `lock` が取得直後に回収する一時ファイルの接頭辞（GC ジャーナル・コンテナ参照テーブル・在庫ファイル）。
pub(super) const STALE_TMP_PREFIXES: &[&str] = &[
    TMP_PREFIX,
    CONTAINER_REFS_TMP_PREFIX,
    IMAGE_INVENTORY_TMP_PREFIX,
];

/// ジャーナルを消滅させる。この成功が削除確定のコミット点。
///
/// 削除意図を持つジャーナルを直接 unlink しない（unlink が永続化されずに古い意図が復活し、後の再登録に
/// 適用されるのを防ぐ。OCI-7）。手順は (1) 墓標（意図なし）へ rename → root の fsync で置換して確定、
/// (2) 墓標の unlink、(3) root の fsync。(1) か (2) が失敗したら `Err` で、見えているジャーナル
/// （古い内容か墓標）が残り、[`journal_exists`] により変更は拒否され続ける。(3) が失敗したら墓標を
/// 再公開して `Err`（再公開も失敗しても、復活し得るのは意図なしの墓標だけで無害）。
/// 次の lock の復旧が墓標を読み、何も消さずに `blobs/sha256` と root の fsync をやり直して片づける。
pub(super) fn remove_journal(root: &RootHandle) -> std::io::Result<()> {
    if journal_exists(root) {
        let tombstone = tombstone_bytes()?;
        // (1) 墓標へ置換して確定する。失敗したら unlink に進まない。
        publish_journal(root, &tombstone)
            .map_err(|_| std::io::Error::other("failed to confirm gc journal tombstone"))?;
        // (2) 確定した墓標だけを unlink する。
        #[cfg(test)]
        if test_hook::should_fail_unlink() {
            return Err(std::io::Error::other("injected journal unlink failure"));
        }
        match root.unlink(GC_JOURNAL_FILE_NAME) {
            Ok(()) => {}
            Err(e) if e.kind() == ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
    }
    // (3) unlink の永続化。
    let synced = sync_dir(root);
    if synced.is_err() {
        // 再公開が失敗しても、復活し得るのは意図なしの墓標だけで無害。呼び出し側は Pending として扱う。
        if let Ok(bytes) = tombstone_bytes() {
            let _ = publish_journal(root, &bytes);
        }
    }
    synced
}

/// 削除意図を持たない空のジャーナル（墓標）のバイト列。
fn tombstone_bytes() -> std::io::Result<Vec<u8>> {
    serde_json::to_vec(&to_raw(&GcJournal::default()))
        .map_err(|_| std::io::Error::other("failed to encode gc journal tombstone"))
}

fn untrusted(msg: &str) -> OciError {
    err(OciErrorCode::FailedPrecondition, msg)
}

/// ジャーナルを読む。無ければ `None`。信頼できない・壊れている場合はファイルに触らずエラー。
pub(super) fn read_journal(root: &RootHandle) -> Result<Option<GcJournal>, OciError> {
    let pre = match root.stat_name(GC_JOURNAL_FILE_NAME) {
        Ok(Some(m)) => m,
        Ok(None) => return Ok(None),
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
    let open_failed = || err(OciErrorCode::Internal, "failed to open gc journal");
    let file = root
        .open_read(GC_JOURNAL_FILE_NAME)
        .map_err(|_| open_failed())?
        .ok_or_else(open_failed)?;
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
///
/// `dir` は `blobs/sha256` を root の fd から開いたもの（差し替え後のディレクトリへは届かない。#2638）。
pub(super) fn remove_blob_durable(dir: &BlobDir, digest: &Digest) -> BlobRemoval {
    let Some(hex) = digest.as_str().strip_prefix("sha256:") else {
        return BlobRemoval::Kept;
    };
    match dir.stat(hex) {
        Ok(Some(m)) if m.is_file() => {
            let len = m.len();
            match dir.unlink(hex) {
                Ok(()) => BlobRemoval::Deleted(len),
                Err(e) if e.kind() == ErrorKind::NotFound => BlobRemoval::Absent,
                Err(_) => BlobRemoval::Kept,
            }
        }
        Ok(Some(_)) => BlobRemoval::Kept,
        Ok(None) => BlobRemoval::Absent,
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
pub(super) fn sweep_blobs(root: &RootHandle, blobs: &[Digest], dirs_present: bool) -> Sweep {
    let mut s = Sweep::default();
    // 判定後にディレクトリが消えた・差し替えられた場合も、開き直した結果に従う（消せなければ残す側）。
    let dir = dirs_present.then(|| root.open_blob_dir());
    for b in blobs {
        let dir = match &dir {
            None | Some(Ok(None)) => {
                s.absent.push(b.clone());
                continue;
            }
            Some(Err(_)) => {
                s.undeleted.push(b.clone());
                continue;
            }
            Some(Ok(Some(d))) => d,
        };
        match remove_blob_durable(dir, b) {
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
    root: &RootHandle,
    undeleted: &[Digest],
    deleted: &[Digest],
    prior_attempts: u32,
    force_blob_dir_sync: bool,
) -> DeletionDurability {
    // 復旧では今回の削除件数に依存せず fsync する（前回プロセスが unlink 後・fsync 前に落ちた場合に備える）。
    let blobs_synced = (deleted.is_empty() && !force_blob_dir_sync) || sync_blob_dir(root).is_ok();
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
        if rewrite_journal(root, &rest).is_err() {
            return abandon();
        }
        return DeletionDurability::Pending;
    }
    if !blobs_synced {
        // テーブル更新（タグ解除・manifest 除去）は済んでいるため、元のジャーナルを残すと
        // 再 pull で再登録された同じタグ・manifest を次の復旧が外してしまう（OCI-7）。
        // 段階を進めた「unlink 済み blob の fsync 待ち」だけのジャーナルへ原子的に置き換える。
        // 置換に失敗したら元のジャーナルのまま Pending にする（保持する以外に手段が無い）。
        let mut keep = deleted.to_vec();
        keep.sort();
        keep.dedup();
        let rest = GcJournal {
            delete_blobs: keep,
            attempts: prior_attempts,
            ..GcJournal::default()
        };
        let _ = rewrite_journal(root, &rest);
        return DeletionDurability::Pending;
    }
    match remove_journal(root) {
        Ok(()) => success_durability(DIR_SYNC_SUPPORTED),
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
    /// 検査用の root を設定する（`ImageStore::lock` が区間ごとに呼ぶ）。
    pub(super) fn set_root_handle(&mut self, root: Arc<RootHandle>) {
        self.journal_root = super::JournalRoot(Some(root));
    }

    /// 試験用: パスから検査なしでハンドルを開いて設定する。
    #[cfg(test)]
    pub(super) fn set_journal_root(&mut self, root: &Path) {
        let h = RootHandle::open_unchecked(root).expect("open root handle");
        self.set_root_handle(Arc::new(h));
    }

    /// 操作の起点にする root のハンドルを決める（公開 API が受け取るパスと排他区間の root の対応）。
    ///
    /// - 排他区間で設定済み: `root` が同じディレクトリならそのハンドル。違えば `InvalidArgument`（fail-closed）
    /// - 未設定の単体テーブル: `root` を検査なしで開く（従来どおり信頼検査をしない）
    pub(super) fn root_handle_for(&self, root: &Path) -> Result<Arc<RootHandle>, OciError> {
        match &self.journal_root.0 {
            Some(h) if h.matches(root) => Ok(Arc::clone(h)),
            Some(_) => Err(err(
                OciErrorCode::InvalidArgument,
                "root does not match the image store root of this exclusive section",
            )),
            None => RootHandle::open_unchecked(root).map(Arc::new),
        }
    }

    /// 削除ジャーナル（墓標を含む）がディスクに見えていれば
    /// `FailedPrecondition` で拒否する（OCI-7。論証は [`journal_exists`]）。
    ///
    /// 契約: 参照を増やす・blob を書く変更系の入口（リース取得を含む）は、先頭でこれを呼ぶこと。
    /// 取得済みのガードの中で rm / prune が Pending を返した後も、残ったジャーナルを復旧が再実行する
    /// ため、再登録・リース取得と両立しない。
    /// 変更系を新設するときは必ず付ける（rm / prune が自分のジャーナルを書いた後の実行用の
    /// `*_unchecked` を除く）。root が未設定の単体テーブルでは何もしない。
    pub(super) fn ensure_no_pending_deletion(&self) -> Result<(), OciError> {
        match &self.journal_root.0 {
            Some(root) if journal_exists(root) => Err(err(
                OciErrorCode::FailedPrecondition,
                "a pending image deletion has not been completed; the store is read-only until it is recovered",
            )),
            _ => Ok(()),
        }
    }

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
        let handle = self.root_handle_for(root)?;
        self.resume_pending_deletion_at(&handle)
    }

    /// [`Self::resume_pending_deletion`] の本体。検査済み root のハンドルを起点にする（#2638）。
    pub(super) fn resume_pending_deletion_at(
        &mut self,
        root: &RootHandle,
    ) -> Result<Option<PendingDeletionRecovery>, OciError> {
        let Some(journal) = read_journal(root)? else {
            return Ok(None);
        };
        // untag・manifest 除去を保存するための複製。保存に失敗したら戻し、ジャーナルを残して失敗させる。
        let before = self.inventory_portion();
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
        // untag・manifest 除去を blob の削除より前に永続化する。保存できなければ blob を消さず、ジャーナルを
        // 残したまま失敗とする（次の lock が同じ復旧をやり直す。fail-closed。#2380・OCI-7）。
        self.persist_inventory(before)?;
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
        let sweep = match root.check_blob_dirs() {
            Ok(present) => {
                force_sync = present;
                sweep_blobs(root, &to_sweep, present)
            }
            Err(_) => Sweep {
                undeleted: to_sweep,
                ..Sweep::default()
            },
        };
        // 既に不在の blob も「unlink 済み」に含める。前回プロセスが unlink 後・ディレクトリ fsync 前に
        // 落ちた blob で、fsync 失敗時に書き直すジャーナルから落ちると、電源断で unlink が巻き戻っても
        // 再削除できなくなるため（OCI-7）。ただし blob ディレクトリ自体が無いときは fsync する対象が
        // 無く、含めると存在しないディレクトリの fsync が失敗して回復が止まるため含めない（#851）。
        let absent_as_deleted = if force_sync { &sweep.absent[..] } else { &[] };
        let deleted_digests: Vec<Digest> = sweep
            .deleted
            .iter()
            .map(|(d, _)| d.clone())
            .chain(absent_as_deleted.iter().cloned())
            .collect();
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
    use crate::image_management::root_handle::rh;
    use crate::image_management::usage::blob_path;
    use crate::image_management::{
        ContainerRefId, ImageRmKind, ImageRmOptions, ImageRmTarget, ImageStore,
        ManifestComposition, PullId, StoppedContainers,
    };
    use crate::instrument::testing::Collect;
    use crate::instrument::{OciOpKind, OciOpOutcome};
    use std::fs::{self, File};
    use std::path::PathBuf;
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
            #[cfg(unix)]
            let p = {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).expect("chmod");
                // unix の `ImageStore::open` は root を `canonicalize` した正規パスで保持する（#2381）。
                // macOS の一時ディレクトリ（`/var` → `/private/var` の symlink 配下）では、非正規パスのままだと
                // 障害注入の照合キーやストアが返すパスとの比較が食い違うため、ストアと同じ正規パスに揃える（#2537）。
                fs::canonicalize(&p).expect("canonicalize")
            };
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
        write_journal(&rh(&root.0), &journal_a()).unwrap();
        let mut t = table();
        t.register_tag(tk("v1"), &d(0xa0)).unwrap();
        let store = ImageStore::with_table(&root.0, t).unwrap();
        let rec = store.recover_pending_deletion().unwrap().unwrap();
        assert_eq!(rec.removed_manifests, vec![d(0xa0)]);
        assert_eq!(rec.untagged, vec![tk("v1")]);
        assert_eq!(rec.deleted_blobs, vec![d(0x11), d(0xc1)]);
        assert_eq!(rec.durability, success_durability(DIR_SYNC_SUPPORTED));
        after_state(&root, &store.lock().unwrap());
    }

    /// OCI-7: k / n 件を unlink した後の中断は、k の全通りで同じ削除後に収束する。
    #[test]
    fn oci7_interrupted_midway_converges_to_after() {
        let blobs = [d(0x11), d(0xc1)];
        for k in 0..=blobs.len() {
            let root = Root::new();
            files(&root);
            write_journal(&rh(&root.0), &journal_a()).unwrap();
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
        write_journal(&rh(&root.0), &journal_a()).unwrap();
        for n in [0x11, 0xc1] {
            fs::remove_file(blob_path(&root.0, &d(n)).unwrap()).unwrap();
        }
        let store = ImageStore::with_table(&root.0, table()).unwrap();
        let rec = store.recover_pending_deletion().unwrap().unwrap();
        assert_eq!(rec.absent_blobs, vec![d(0x11), d(0xc1)]);
        assert!(rec.deleted_blobs.is_empty());
        assert_eq!(rec.durability, success_durability(DIR_SYNC_SUPPORTED));
        assert!(!root.journal());
    }

    /// OCI-7: 再起動後のテーブルに別の manifest・リースが blob を参照していれば、その blob は残る。
    #[test]
    fn oci7_recovery_recounts_and_keeps_blob_referenced_after_restart() {
        let root = Root::new();
        files(&root);
        write_journal(&rh(&root.0), &journal_a()).unwrap();
        let mut t = table();
        // 0x11 は別の manifest C の構成に、0xc1 は pull リースに守られている。
        t.register_manifest(
            d(0xd0),
            ManifestComposition::new(d(0xc2), vec![d(0x11)]).unwrap(),
        )
        .unwrap();
        t.acquire_lease(d(0xc1), PullId::new("p1").unwrap())
            .unwrap();
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
        write_journal(&rh(&root.0), &journal_a()).unwrap();
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
        write_journal(&rh(&root.0), &journal_a()).unwrap();
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
        assert_eq!(out.durability, success_durability(DIR_SYNC_SUPPORTED));
        assert!(!root.journal());
        let out = t.execute_image_prune(&root.0).unwrap();
        assert_eq!(out.removed_manifests, vec![d(0xb0)]);
        assert_eq!(out.durability, success_durability(DIR_SYNC_SUPPORTED));
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
        let j = read_journal(&rh(&root.0)).unwrap().unwrap();
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
        assert_eq!(rec.durability, success_durability(DIR_SYNC_SUPPORTED));
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
        ensure_no_pending_journal(&rh(&root.0)).unwrap();
        assert!(store.recover_pending_deletion().unwrap().is_none());
    }

    /// OCI-7: fsync が失敗し消せない blob もあるとき、unlink 済みの blob もジャーナルに残す。
    #[test]
    fn oci7_settle_keeps_deleted_blobs_when_blob_dir_fsync_fails() {
        let root = Root::new();
        // blobs/sha256 の fsync を注入で失敗させる（Windows の sync_dir_os は常に成功するため、
        // ディレクトリ削除ではなく test_hook で 3 OS 共通の障害条件にする）。
        test_hook::fail_sync_of(&blob_dir(&root.0), 8);
        let st = settle(&rh(&root.0), &[d(0x22)], &[d(0x11)], 0, false);
        test_hook::clear();
        assert_eq!(st, DeletionDurability::Pending);
        let j = read_journal(&rh(&root.0)).unwrap().unwrap();
        assert_eq!(j.delete_blobs, vec![d(0x11), d(0x22)]);
        assert_eq!(j.attempts, 1);
    }

    /// OCI-7: 復旧で fsync が失敗し消せない blob もあるとき、既に不在の blob も再試行一覧に残す。
    #[cfg(unix)]
    #[test]
    fn oci7_resume_keeps_absent_blobs_when_blob_dir_fsync_fails() {
        let root = Root::new();
        files(&root);
        write_journal(&rh(&root.0), &journal_a()).unwrap();
        // 0x11 は前回プロセスが unlink 済み（不在）、0xc1 は消せない（ディレクトリ）。
        fs::remove_file(blob_path(&root.0, &d(0x11)).unwrap()).unwrap();
        let p = blob_path(&root.0, &d(0xc1)).unwrap();
        fs::remove_file(&p).unwrap();
        fs::create_dir(&p).unwrap();
        let mut t = table();
        t.register_tag(tk("v1"), &d(0xa0)).unwrap();
        let store = ImageStore::with_table(&root.0, t).unwrap();
        test_hook::fail_sync_of(&blob_dir(&root.0), 8);
        let rec = store.recover_pending_deletion().unwrap().unwrap();
        test_hook::clear();
        assert_eq!(rec.durability, DeletionDurability::Pending);
        assert_eq!(rec.absent_blobs, vec![d(0x11)]);
        assert_eq!(rec.undeleted_blobs, vec![d(0xc1)]);
        let j = read_journal(&rh(&root.0)).unwrap().unwrap();
        assert_eq!(j.delete_blobs, vec![d(0x11), d(0xc1)]);
    }

    /// OCI-7・#851: blob ディレクトリが無いとき、全件を不在として回復を完了しジャーナルを消す。
    /// `blobs` ごと無い場合と `blobs/sha256` だけ無い場合の両方を、実際に取り除いて確かめる。
    #[test]
    fn oci7_resume_completes_when_blob_dirs_missing() {
        for remove_whole_blobs in [true, false] {
            let root = Root::new();
            write_journal(&rh(&root.0), &journal_a()).unwrap();
            let target = if remove_whole_blobs {
                root.0.join("blobs")
            } else {
                blob_dir(&root.0)
            };
            fs::remove_dir_all(&target).unwrap();
            assert!(!blob_dir(&root.0).exists());
            let mut t = table();
            t.register_tag(tk("v1"), &d(0xa0)).unwrap();
            let store = ImageStore::with_table(&root.0, t).unwrap();
            let rec = store.recover_pending_deletion().unwrap().unwrap();
            assert!(!rec.absent_blobs.is_empty());
            assert!(rec.undeleted_blobs.is_empty());
            assert_ne!(rec.durability, DeletionDurability::Pending);
            assert!(read_journal(&rh(&root.0)).unwrap().is_none());
        }
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
        let st = settle(&rh(&root.0), &[d(0x22)], &[], 0, false);
        fs::set_permissions(&root.0, fs::Permissions::from_mode(0o700)).unwrap();
        // 特権で実行されて書き込めてしまう環境では前提が成り立たないので判定しない。
        if !writable {
            assert_eq!(st, DeletionDurability::Abandoned);
        }
    }

    /// OCI-7: ジャーナルの rename 後に root の fsync が失敗しても、取り消せなければ
    /// ジャーナルは残り、操作は続行できる（次の lock のロールフォワードと整合する）。
    #[test]
    fn oci7_publish_then_root_fsync_failure_revokes_journal_when_possible() {
        let root = Root::new();
        files(&root);
        // 1 回目（公開後の fsync）だけ失敗、取り消しの fsync は成功 -> 削除前に収束して Err。
        test_hook::fail_sync_of(&root.0, 1);
        let e = write_journal(&rh(&root.0), &journal_a()).unwrap_err();
        test_hook::clear();
        assert_eq!(e.code(), OciErrorCode::Internal);
        assert!(!root.journal());
        // 一時ファイルも残さない。
        assert!(
            fs::read_dir(&root.0)
                .unwrap()
                .flatten()
                .all(|e| !e.file_name().to_string_lossy().starts_with(TMP_PREFIX))
        );
    }

    /// OCI-7: 公開後の fsync も取り消しの fsync も失敗したら、削除は始めず（Err）、
    /// 墓標（空のジャーナル）を残す。次の lock が何も消さずに片づける。
    #[test]
    fn oci7_publish_fsync_failure_and_revoke_fsync_failure_leaves_tombstone() {
        let root = Root::new();
        files(&root);
        test_hook::fail_sync_of(&root.0, 2);
        let e = write_journal(&rh(&root.0), &journal_a()).unwrap_err();
        test_hook::clear();
        assert_eq!(e.code(), OciErrorCode::Internal);
        let j = read_journal(&rh(&root.0)).unwrap().unwrap();
        assert!(j.is_tombstone());
        // 失敗した操作の blob は消えない。
        assert!(root.exists(&d(0x12)));
        let store = ImageStore::with_table(&root.0, table()).unwrap();
        let rec = store.recover_pending_deletion().unwrap().unwrap();
        assert_eq!(rec.durability, success_durability(DIR_SYNC_SUPPORTED));
        assert!(rec.deleted_blobs.is_empty());
        assert!(root.exists(&d(0x12)));
        assert!(!root.journal());
    }

    /// OCI-7: ジャーナル削除後の root の fsync が失敗したら Pending で、墓標が残り、
    /// 次の lock が復旧して再試行するまで新しい削除は拒否される。
    #[test]
    fn oci7_journal_removal_fsync_failure_keeps_pending_until_next_lock() {
        let root = Root::new();
        files(&root);
        write_journal(&rh(&root.0), &journal_a()).unwrap();
        for n in [0x10u8, 0x11, 0x12] {
            let _ = fs::remove_file(blob_path(&root.0, &d(n)).unwrap());
        }
        test_hook::fail_sync_of(&root.0, 1);
        let st = settle(&rh(&root.0), &[], &[d(0x10)], 0, false);
        test_hook::clear();
        assert_eq!(st, DeletionDurability::Pending);
        // 墓標が見えるので次の削除は拒否され、lock が復旧する。
        assert!(root.journal());
        let e = ensure_no_pending_journal(&rh(&root.0)).unwrap_err();
        assert_eq!(e.code(), OciErrorCode::FailedPrecondition);
        let store = ImageStore::with_table(&root.0, table()).unwrap();
        let rec = store.recover_pending_deletion().unwrap().unwrap();
        assert_eq!(rec.durability, success_durability(DIR_SYNC_SUPPORTED));
        assert!(!root.journal());
        ensure_no_pending_journal(&rh(&root.0)).unwrap();
    }

    /// OCI-7: 全 blob を unlink した後に blob ディレクトリの fsync が失敗して Pending のとき、
    /// 再 pull で同じ manifest・タグが再登録されても、次の復旧はそれらを外さず消さない。
    #[test]
    fn oci7_pending_after_table_update_does_not_remove_reregistered_tag() {
        let root = Root::new();
        files(&root);
        write_journal(&rh(&root.0), &journal_a()).unwrap();
        // 削除対象の blob を全部 unlink 済みにして、blob ディレクトリの fsync だけ失敗させる。
        for n in [0x11u8, 0xc1] {
            fs::remove_file(blob_path(&root.0, &d(n)).unwrap()).unwrap();
        }
        test_hook::fail_sync_of(&blob_dir(&root.0), 1);
        let st = settle(&rh(&root.0), &[], &[d(0x11), d(0xc1)], 0, false);
        test_hook::clear();
        assert_eq!(st, DeletionDurability::Pending);
        // 残ったジャーナルは unlink 済み blob の fsync 待ちだけで、manifest・untag を含まない。
        let j = read_journal(&rh(&root.0)).unwrap().unwrap();
        assert!(j.manifests.is_empty());
        assert!(j.untag.is_empty());
        assert_eq!(j.delete_blobs, vec![d(0x11), d(0xc1)]);
        // 同じ manifest・タグ・blob が再登録された状態で復旧する。
        root.put(&d(0x11));
        root.put(&d(0xc1));
        let mut t = table();
        t.register_tag(tk("v1"), &d(0xa0)).unwrap();
        let store = ImageStore::with_table(&root.0, t).unwrap();
        let rec = store.recover_pending_deletion().unwrap().unwrap();
        assert!(rec.untagged.is_empty());
        assert!(rec.removed_manifests.is_empty());
        assert_eq!(rec.kept_blobs, vec![d(0x11), d(0xc1)]);
        let g = store.lock().unwrap();
        assert_eq!(g.tags().count(), 1);
        assert_eq!(g.manifests().count(), 2);
        drop(g);
        assert!(root.exists(&d(0x11)));
        assert!(root.exists(&d(0xc1)));
        assert!(!root.journal());
    }

    /// OCI-7: 削除開始後のジャーナル書き直しで rename 後に root の fsync が失敗しても、
    /// ジャーナルを取り消さず Pending を返し、次の復旧が delete_blobs を消す。
    #[test]
    fn oci7_rewrite_root_fsync_failure_keeps_journal_and_recovers() {
        let root = Root::new();
        files(&root);
        write_journal(&rh(&root.0), &journal_a()).unwrap();
        // 0x11 は unlink 済み、0xc1 は今回は消せなかった扱い。書き直しの root fsync だけ失敗させる。
        fs::remove_file(blob_path(&root.0, &d(0x11)).unwrap()).unwrap();
        test_hook::fail_sync_of(&root.0, 1);
        let st = settle(&rh(&root.0), &[d(0xc1)], &[d(0x11)], 0, false);
        test_hook::clear();
        assert_eq!(st, DeletionDurability::Pending);
        let j = read_journal(&rh(&root.0)).unwrap().unwrap();
        assert_eq!(j.delete_blobs, vec![d(0xc1)]);
        assert_eq!(j.attempts, 1);
        // テーブル更新は済んでいる（A は無い）状態で復旧する。
        let store = ImageStore::with_table(&root.0, ReferenceTable::new()).unwrap();
        let rec = store.recover_pending_deletion().unwrap().unwrap();
        assert_eq!(rec.deleted_blobs, vec![d(0xc1)]);
        assert!(!root.exists(&d(0xc1)));
        assert!(!root.journal());
    }

    /// OCI-7: 削除完了時のジャーナル unlink が失敗してテーブル操作入りのジャーナルが残る間は、
    /// lock が FailedPrecondition で拒否され、障害を除くと復旧が完了して変更が通る。
    #[test]
    fn oci7_unlink_failure_blocks_lock_until_recovered() {
        let root = Root::new();
        files(&root);
        write_journal(&rh(&root.0), &journal_a()).unwrap();
        for n in [0x11u8, 0xc1] {
            fs::remove_file(blob_path(&root.0, &d(n)).unwrap()).unwrap();
        }
        test_hook::fail_unlink(100);
        let st = settle(&rh(&root.0), &[], &[d(0x11), d(0xc1)], 0, false);
        assert_eq!(st, DeletionDurability::Pending);
        assert!(root.journal());
        let store = ImageStore::with_table(&root.0, table()).unwrap();
        let e = store.lock().unwrap_err();
        assert_eq!(e.code(), OciErrorCode::FailedPrecondition);
        test_hook::clear();
        // 意図は墓標へ縮んでから確定済みのため、復旧は何も外さない。再登録（pull 相当）が通り、以後も外されない。
        let mut g = store.lock().unwrap();
        assert_eq!(g.manifests().count(), 2);
        g.register_manifest(
            d(0xa0),
            ManifestComposition::new(d(0xc1), vec![d(0x10), d(0x11)]).unwrap(),
        )
        .unwrap();
        g.register_tag(tk("v1"), &d(0xa0)).unwrap();
        assert_eq!(g.tags().count(), 1);
        drop(g);
        let g = store.lock().unwrap();
        assert_eq!(g.tags().count(), 1);
        assert_eq!(g.manifests().count(), 2);
        drop(g);
        assert!(!root.journal());
    }

    /// OCI-7: blobs だけへの書き直しが公開前に失敗して元のジャーナルが残る間も、lock は拒否される。
    #[test]
    fn oci7_rewrite_failure_blocks_lock_until_recovered() {
        let root = Root::new();
        files(&root);
        write_journal(&rh(&root.0), &journal_a()).unwrap();
        for n in [0x11u8, 0xc1] {
            fs::remove_file(blob_path(&root.0, &d(n)).unwrap()).unwrap();
        }
        test_hook::fail_sync_of(&blob_dir(&root.0), 100);
        test_hook::fail_rewrite(100);
        let st = settle(&rh(&root.0), &[], &[d(0x11), d(0xc1)], 0, false);
        assert_eq!(st, DeletionDurability::Pending);
        let j = read_journal(&rh(&root.0)).unwrap().unwrap();
        assert_eq!(j, journal_a());
        let store = ImageStore::with_table(&root.0, table()).unwrap();
        let e = store.lock().unwrap_err();
        assert_eq!(e.code(), OciErrorCode::FailedPrecondition);
        test_hook::clear();
        // 復旧は A を外し終えている。再登録（pull 相当）が通り、以後は外されない。
        let mut g = store.lock().unwrap();
        assert_eq!(g.manifests().count(), 1);
        // 公開（pull 相当）は変更を永続化する。ガード直接の変更は次の取得でディスクの内容に置き換わる（#2380）。
        let before = g.inventory_portion();
        g.register_manifest(
            d(0xa0),
            ManifestComposition::new(d(0xc1), vec![d(0x10), d(0x11)]).unwrap(),
        )
        .unwrap();
        g.register_tag(tk("v1"), &d(0xa0)).unwrap();
        g.persist_inventory(before).unwrap();
        assert_eq!(g.tags().count(), 1);
        drop(g);
        let g = store.lock().unwrap();
        assert_eq!(g.tags().count(), 1);
        assert_eq!(g.manifests().count(), 2);
        drop(g);
        assert!(!root.journal());
    }

    /// OCI-7: 取得済みのガードで rm が Pending（ジャーナル unlink 失敗）を返した後は、同じガードでの
    /// 変更系が FailedPrecondition になる。障害を除いて再 lock すると復旧が完了し登録が通る。
    #[test]
    fn oci7_rm_pending_blocks_mutations_in_same_guard() {
        let root = Root::new();
        files(&root);
        let mut t = table();
        t.register_tag(tk("v1"), &d(0xa0)).unwrap();
        let store = ImageStore::with_table(&root.0, t).unwrap();
        let mut g = store.lock().unwrap();
        test_hook::fail_unlink(1);
        let out = g
            .execute_image_rm(
                &root.0,
                &ImageRmTarget::Tag(tk("v1")),
                &ImageRmOptions::default(),
                &StoppedContainers::new(),
            )
            .unwrap();
        test_hook::clear();
        assert_eq!(out.durability, DeletionDurability::Pending);
        assert!(root.journal());
        let comp = ManifestComposition::new(d(0xc1), vec![d(0x10), d(0x11)]).unwrap();
        for code in [
            g.register_manifest(d(0xa0), comp.clone())
                .unwrap_err()
                .code(),
            g.register_tag(tk("v9"), &d(0xb0)).unwrap_err().code(),
            g.unregister_tag(&tk("v9")).unwrap_err().code(),
            g.remove_manifest(&d(0xb0)).unwrap_err().code(),
        ] {
            assert_eq!(code, OciErrorCode::FailedPrecondition);
        }
        assert_eq!(g.tags().count(), 0);
        drop(g);
        let mut g = store.lock().unwrap();
        assert!(!root.journal());
        g.register_manifest(d(0xa0), comp).unwrap();
        g.register_tag(tk("v1"), &d(0xa0)).unwrap();
        assert_eq!(g.tags().count(), 1);
    }

    /// OCI-7: prune が Pending を返した後も、同じガードでの変更系は FailedPrecondition になる。
    #[test]
    fn oci7_prune_pending_blocks_mutations_in_same_guard() {
        let root = Root::new();
        files(&root);
        let store = ImageStore::with_table(&root.0, table()).unwrap();
        let mut g = store.lock().unwrap();
        test_hook::fail_unlink(1);
        let out = g.execute_image_prune(&root.0).unwrap();
        test_hook::clear();
        assert_eq!(out.removed_manifests, vec![d(0xa0), d(0xb0)]);
        assert_eq!(out.durability, DeletionDurability::Pending);
        let comp = ManifestComposition::new(d(0xc2), vec![d(0x10), d(0x12)]).unwrap();
        let e = g.register_manifest(d(0xb0), comp.clone()).unwrap_err();
        assert_eq!(e.code(), OciErrorCode::FailedPrecondition);
        assert_eq!(g.manifests().count(), 0);
        drop(g);
        let mut g = store.lock().unwrap();
        assert!(!root.journal());
        g.register_manifest(d(0xb0), comp).unwrap();
        assert_eq!(g.manifests().count(), 1);
    }

    /// OCI-7: blob のみのジャーナルが Pending で残る間は、参照の追加（register_manifest・
    /// register_tag・acquire_lease）が FailedPrecondition になり、新しい lock も拒否される。
    /// 障害を除いて再 lock すると復旧が完了し、その後は通る。
    #[test]
    fn oci7_blob_only_pending_blocks_reference_additions() {
        let root = Root::new();
        files(&root);
        // 消せない blob（ディレクトリ）を残して blob のみのジャーナルを Pending にする。
        let victim = blob_path(&root.0, &d(0x11)).unwrap();
        fs::remove_file(&victim).unwrap();
        fs::create_dir(&victim).unwrap();
        let store = ImageStore::with_table(&root.0, table()).unwrap();
        let mut g = store.lock().unwrap();
        let out = g.execute_image_prune(&root.0).unwrap();
        assert_eq!(out.durability, DeletionDurability::Pending);
        let j = read_journal(&rh(&root.0)).unwrap().unwrap();
        assert!(j.manifests.is_empty() && j.untag.is_empty());
        assert_eq!(j.delete_blobs, vec![d(0x11)]);
        // 同じガード: 参照の追加はすべて拒否される。
        let comp = ManifestComposition::new(d(0xc1), vec![d(0x10), d(0x11)]).unwrap();
        let e = g.register_manifest(d(0xa0), comp.clone()).unwrap_err();
        assert_eq!(e.code(), OciErrorCode::FailedPrecondition);
        let e = g.register_tag(tk("v1"), &d(0xa0)).unwrap_err();
        assert_eq!(e.code(), OciErrorCode::FailedPrecondition);
        let pull = PullId::new("p1").unwrap();
        let e = g.acquire_lease(d(0x11), pull.clone()).unwrap_err();
        assert_eq!(e.code(), OciErrorCode::FailedPrecondition);
        drop(g);
        // 新しい lock も拒否される（復旧が試みられるが blob が消せない間）。
        let e = store.lock().unwrap_err();
        assert_eq!(e.code(), OciErrorCode::FailedPrecondition);
        assert!(root.journal());
        // 障害を除くと復旧が完了し、以後は通る。
        fs::remove_dir(&victim).unwrap();
        let mut g = store.lock().unwrap();
        assert!(!root.journal());
        g.register_manifest(d(0xa0), comp).unwrap();
        g.register_tag(tk("v1"), &d(0xa0)).unwrap();
        assert!(g.acquire_lease(d(0x11), pull).unwrap().newly_added);
    }

    /// OCI-7: 墓標の公開後に root の fsync が失敗しても、墓標が見えている間は lock と変更系が
    /// FailedPrecondition になる。障害を除くと復旧が完了して変更が通る。
    #[test]
    fn oci7_tombstone_visible_blocks_lock_and_mutations() {
        let root = Root::new();
        files(&root);
        write_journal(&rh(&root.0), &journal_a()).unwrap();
        for n in [0x11u8, 0xc1] {
            fs::remove_file(blob_path(&root.0, &d(n)).unwrap()).unwrap();
        }
        // root の fsync を全部失敗させる: 墓標への置換は rename されるが確定できない。
        test_hook::fail_sync_of(&root.0, 100);
        let st = settle(&rh(&root.0), &[], &[d(0x11), d(0xc1)], 0, false);
        assert_eq!(st, DeletionDurability::Pending);
        // 削除意図を持つジャーナルは unlink されず、見えているのは墓標。
        let j = read_journal(&rh(&root.0)).unwrap().unwrap();
        assert!(j.is_tombstone());
        let mut t = table();
        t.set_journal_root(&root.0);
        let e = t.register_tag(tk("v1"), &d(0xa0)).unwrap_err();
        assert_eq!(e.code(), OciErrorCode::FailedPrecondition);
        let store = ImageStore::with_table(&root.0, table()).unwrap();
        let e = store.lock().unwrap_err();
        assert_eq!(e.code(), OciErrorCode::FailedPrecondition);
        assert!(root.journal());
        test_hook::clear();
        let mut g = store.lock().unwrap();
        assert!(!root.journal());
        g.register_tag(tk("v1"), &d(0xa0)).unwrap();
        assert_eq!(g.tags().count(), 1);
    }

    /// OCI-7: 初回の write_journal の公開後に root の fsync が失敗しても、ジャーナルを直接 unlink せず
    /// 墓標へ置換する。確定できない間は見えている墓標で変更が拒否され、障害を除くと変更が通る。
    #[test]
    fn oci7_initial_publish_fsync_failure_tombstones_instead_of_unlink() {
        let root = Root::new();
        files(&root);
        test_hook::fail_sync_of(&root.0, 100);
        let e = write_journal(&rh(&root.0), &journal_a()).unwrap_err();
        assert_eq!(e.code(), OciErrorCode::Internal);
        // 取り消しの unlink は走らず、見えているのは（確定できていない）墓標。
        let j = read_journal(&rh(&root.0)).unwrap().unwrap();
        assert!(j.is_tombstone());
        let store = ImageStore::with_table(&root.0, table()).unwrap();
        let e = store.lock().unwrap_err();
        assert_eq!(e.code(), OciErrorCode::FailedPrecondition);
        test_hook::clear();
        let mut g = store.lock().unwrap();
        assert!(!root.journal());
        g.register_tag(tk("v1"), &d(0xa0)).unwrap();
        assert_eq!(g.tags().count(), 1);
    }

    /// OCI-7: 通常の lock 経路でも復旧結果（Abandoned と孤児 blob）が guard から取れる。
    #[test]
    fn oci7_lock_exposes_abandoned_recovery() {
        let root = Root::new();
        files(&root);
        // 消せない blob にする（通常ファイルをディレクトリに差し替える）。
        let victim = blob_path(&root.0, &d(0x11)).unwrap();
        fs::remove_file(&victim).unwrap();
        fs::create_dir(&victim).unwrap();
        let store = ImageStore::with_table(&root.0, table()).unwrap();
        let out = store.lock().unwrap().execute_image_prune(&root.0).unwrap();
        assert_eq!(out.durability, DeletionDurability::Pending);
        // 1 回目は prune、以降は lock 時の再試行。上限の手前までは Pending のため lock は拒否される（OCI-7）。
        for _ in 2..MAX_GC_RETRY_ATTEMPTS {
            let e = store.lock().unwrap_err();
            assert_eq!(e.code(), OciErrorCode::FailedPrecondition);
        }
        let g = store.lock().unwrap();
        let rec = g.recovery().expect("recovery must be reported");
        assert_eq!(rec.durability, DeletionDurability::Abandoned);
        assert_eq!(rec.undeleted_blobs, vec![d(0x11)]);
        drop(g);
        assert!(store.recover_pending_deletion().unwrap().is_none());
    }

    /// OCI-7: fsync できない環境では削除が完了しても Confirmed を返さない。
    #[test]
    fn oci7_success_without_dir_sync_is_unconfirmed() {
        assert_eq!(success_durability(true), DeletionDurability::Confirmed);
        assert_eq!(success_durability(false), DeletionDurability::Unconfirmed);
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
        write_journal(&rh(&root.0), &journal_a()).unwrap();
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
            write_journal(&rh(&root.0), &big).unwrap_err().code(),
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
            read_journal(&rh(&root.0)).unwrap_err().code(),
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
            read_journal(&rh(&root.0)).unwrap_err().code(),
            OciErrorCode::FailedPrecondition
        );
        assert_eq!(fs::read(&target).unwrap(), b"keep");
        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();
        assert_eq!(
            read_journal(&rh(&root.0)).unwrap_err().code(),
            OciErrorCode::FailedPrecondition
        );
        fs::remove_dir(&path).unwrap();
        write_journal(&rh(&root.0), &journal_a()).unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        fs::set_permissions(&path, fs::Permissions::from_mode(0o660)).unwrap();
        assert_eq!(
            read_journal(&rh(&root.0)).unwrap_err().code(),
            OciErrorCode::FailedPrecondition
        );
    }

    /// 書き込んだジャーナルは同じ内容で読み戻せる。
    #[test]
    fn oci7_journal_roundtrip() {
        let root = Root::new();
        write_journal(&rh(&root.0), &journal_a()).unwrap();
        assert_eq!(read_journal(&rh(&root.0)).unwrap(), Some(journal_a()));
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
        write_journal(&rh(&root.0), &journal_a()).unwrap();
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
