//! 記録ストアのファイル実装（unix のみ。CRI-1・OCI-7・REPAIR-5・SEC-1。#2932）。
//!
//! 置き場の作法は plugin-cri の `ReclaimStore`（`docs/design/network-reclaim-persistence.md`）に揃える:
//! 0700・symlink 拒否・所有者照合・`O_EXCL` の一時ファイル → fsync → rename → ディレクトリの fsync・
//! `.lock` の期限つき `try_lock`。契約の全体は親モジュール（`record_store`）を参照。
//!
//! 呼び出し元になる予定: R4〜R9（#2933〜#2938）。本単位では試験からのみ呼ばれる。

use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use super::{
    Failed, ListBudget, ListLimits, ListSink, ListedRecord, NoopRecordStoreOpRecorder, RecordId,
    RecordKind, RecordListing, RecordReadFailure, RecordStore, RecordStoreOp,
    RecordStoreOpRecorder, RecordStoreOpSample, RecordStoreOutcome, run_listing,
};
use crate::error::CriError;

const REC_EXT: &str = ".rec";
const LOCK_NAME: &str = ".lock";
const LOCK_TIMEOUT: Duration = Duration::from_secs(5);
const LOCK_POLL: Duration = Duration::from_millis(5);
/// 一時ファイル名の衝突時の再試行回数の上限。
const TMP_ATTEMPTS: u32 = 16;
/// 列挙で走査するエントリ数の上限に足す余裕（一時ファイル・`.lock`・無関係なファイル）。
const SCAN_SLACK: usize = 64;
/// ディレクトリ fd の fsync が拒否され得る errno（macOS の EINVAL・ENOTSUP）。それ以外は fail-closed。
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
const DIR_SYNC_UNSUPPORTED_ERRNOS: [i32; 2] = [22, 45];

/// 試験用: 1 件を読む前に呼ぶフック（期限の再現に使う）。
#[cfg(test)]
type ReadHook = std::sync::Arc<dyn Fn(&RecordId) + Send + Sync>;

/// `<状態ルート>/.cri/records` に記録を置くファイル実装。
pub struct FileRecordStore {
    sandboxes: PathBuf,
    containers: PathBuf,
    lock_path: PathBuf,
    lock_timeout: Duration,
    next_seq: AtomicU64,
    recorder: Arc<dyn RecordStoreOpRecorder>,
    #[cfg(test)]
    read_hook: Option<ReadHook>,
}

impl std::fmt::Debug for FileRecordStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // パスは出さない（REPAIR-4）。
        f.debug_struct("FileRecordStore").finish_non_exhaustive()
    }
}

impl FileRecordStore {
    /// 状態ルート配下に置き場を用意して開く。既存の置き場が危険なら消さずに拒否する（SEC-1）。
    pub fn open(state_root: &Path) -> Result<Self, CriError> {
        let owner = fs::metadata(state_root).map_err(|_| prepare_error())?.uid();
        Self::open_with_owner(state_root, owner)
    }

    fn open_with_owner(state_root: &Path, owner: u32) -> Result<Self, CriError> {
        let root_meta = fs::metadata(state_root).map_err(|_| prepare_error())?;
        if !root_meta.is_dir() {
            return Err(prepare_error());
        }
        let cri = state_root.join(".cri");
        let records = cri.join("records");
        let sandboxes = records.join(RecordKind::Sandbox.dir_name());
        let containers = records.join(RecordKind::Container.dir_name());
        for (dir, parent) in [
            (&cri, state_root),
            (&records, cri.as_path()),
            (&sandboxes, records.as_path()),
            (&containers, records.as_path()),
        ] {
            ensure_private_dir(dir, owner)?;
            sync_dir(parent).map_err(|_| prepare_error())?;
        }
        Ok(Self {
            lock_path: records.join(LOCK_NAME),
            sandboxes,
            containers,
            lock_timeout: LOCK_TIMEOUT,
            next_seq: AtomicU64::new(0),
            recorder: Arc::new(NoopRecordStoreOpRecorder),
            #[cfg(test)]
            read_hook: None,
        })
    }

    fn dir(&self, kind: RecordKind) -> &Path {
        match kind {
            RecordKind::Sandbox => &self.sandboxes,
            RecordKind::Container => &self.containers,
        }
    }

    /// ファイル名は検証済みの ID だけから作る。
    fn record_path(&self, kind: RecordKind, id: &RecordId) -> PathBuf {
        self.dir(kind).join(format!("{}{REC_EXT}", id.as_str()))
    }

    /// 操作の計測結果を受ける記録器を差し替える（既定は何も記録しない。REPAIR-4）。
    ///
    /// `put` / `remove` / `list` の全終了経路（成功・上限拒否・ロック取得失敗・列挙の期限切れ・I/O エラー）で、
    /// 操作名・種別・結果区分・所要時間だけを記録する。バイト列・ID・パスは渡さない。
    pub fn with_recorder(mut self, recorder: Arc<dyn RecordStoreOpRecorder>) -> Self {
        self.recorder = recorder;
        self
    }

    fn lock(&self) -> Result<File, Failed> {
        lock_file(&self.lock_path, self.lock_timeout)
    }

    /// `f` を計測して結果を記録し、呼び出し側へは `CriError` だけを返す。
    fn timed<T>(
        &self,
        op: RecordStoreOp,
        kind: RecordKind,
        f: impl FnOnce() -> Result<T, Failed>,
    ) -> Result<T, CriError> {
        let start = Instant::now();
        let result = f();
        let outcome = match &result {
            Ok(_) => RecordStoreOutcome::Ok,
            Err(e) => e.outcome,
        };
        self.recorder.record_store_op(&RecordStoreOpSample {
            op,
            kind,
            outcome,
            latency: start.elapsed(),
        });
        result.map_err(|e| e.err)
    }

    fn put_inner(&self, kind: RecordKind, id: &RecordId, bytes: &[u8]) -> Result<(), Failed> {
        if bytes.len() > kind.max_record_bytes() {
            return Err(Failed::new(
                RecordStoreOutcome::TooLong,
                CriError::internal("cri record is too long"),
            ));
        }
        let _guard = self.lock()?;
        let target = self.record_path(kind, id);
        match fs::symlink_metadata(&target) {
            Ok(m) if !m.file_type().is_file() => return Err(not_regular()),
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(persist_error()),
        }
        let dir = self.dir(kind);
        let (tmp, mut file) = self.create_tmp(dir)?;
        let result = (|| -> std::io::Result<()> {
            file.write_all(bytes)?;
            file.sync_all()?;
            drop(file);
            fs::rename(&tmp, &target)
        })();
        if result.is_err() {
            let _ = fs::remove_file(&tmp);
            return Err(persist_error());
        }
        sync_dir(dir).map_err(|_| persist_error())
    }

    fn remove_inner(&self, kind: RecordKind, id: &RecordId) -> Result<(), Failed> {
        let _guard = self.lock()?;
        let target = self.record_path(kind, id);
        match fs::symlink_metadata(&target) {
            Ok(m) if m.file_type().is_file() => {}
            Ok(_) => return Err(not_regular()),
            // 記録が既に無くても親ディレクトリの同期を成功条件にする。前回の再試行で unlink
            // 後の同期が失敗していた場合に、削除が永続化されないまま成功を返さないため（CRI-1）。
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return sync_dir(self.dir(kind)).map_err(|_| remove_error());
            }
            Err(_) => return Err(remove_error()),
        }
        fs::remove_file(&target).map_err(|_| remove_error())?;
        sync_dir(self.dir(kind)).map_err(|_| remove_error())
    }

    fn list_inner(
        &self,
        kind: RecordKind,
        budget: ListBudget,
        limits: ListLimits,
    ) -> Result<RecordListing, Failed> {
        // 呼び出し側が別種別の上限を渡しても、この種別の既定値を超えさせない。
        let limits = limits.clamp_to(kind);
        let dir = self.dir(kind).to_path_buf();
        let lock_path = self.lock_path.clone();
        let lock_timeout = self.lock_timeout;
        #[cfg(test)]
        let hook = self.read_hook.clone();
        run_listing(budget, move |sink| {
            let result = list_worker(
                &dir,
                &lock_path,
                lock_timeout,
                kind,
                limits,
                &sink,
                #[cfg(test)]
                hook,
            );
            sink.finish(result);
        })
    }

    /// `O_EXCL` の一時ファイルを作る。衝突したら連番を進めて最大 [`TMP_ATTEMPTS`] 回まで再試行する。
    fn create_tmp(&self, dir: &Path) -> Result<(PathBuf, File), Failed> {
        for _ in 0..TMP_ATTEMPTS {
            let seq = self.next_seq.fetch_add(1, Ordering::Relaxed);
            let path = dir.join(format!(".tmp-{}-{seq}", std::process::id()));
            let mut opts = OpenOptions::new();
            opts.write(true).create_new(true).mode(0o600);
            match opts.open(&path) {
                Ok(f) => return Ok((path, f)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(_) => return Err(persist_error()),
            }
        }
        Err(persist_error())
    }
}

impl RecordStore for FileRecordStore {
    fn put(&self, kind: RecordKind, id: &RecordId, bytes: &[u8]) -> Result<(), CriError> {
        self.timed(RecordStoreOp::Put, kind, || self.put_inner(kind, id, bytes))
    }

    fn remove(&self, kind: RecordKind, id: &RecordId) -> Result<(), CriError> {
        self.timed(RecordStoreOp::Remove, kind, || self.remove_inner(kind, id))
    }

    fn list(
        &self,
        kind: RecordKind,
        budget: ListBudget,
        limits: ListLimits,
    ) -> Result<RecordListing, CriError> {
        self.timed(RecordStoreOp::List, kind, || {
            self.list_inner(kind, budget, limits)
        })
    }
}

/// 列挙の本体（専用スレッドで動く）。ロック → 走査 → 昇順に 1 件ずつ読む。
fn list_worker(
    dir: &Path,
    lock_path: &Path,
    lock_timeout: Duration,
    kind: RecordKind,
    limits: ListLimits,
    sink: &ListSink,
    #[cfg(test)] hook: Option<ReadHook>,
) -> Result<usize, Failed> {
    // ガードは worker の終了（期限切れで切り離されても中止フラグで抜ける）で drop される。
    let _guard = lock_file(lock_path, lock_timeout)?;
    let too_many = || {
        Failed::new(
            RecordStoreOutcome::TooManyRecords,
            CriError::failed_precondition("cri record store holds too many records"),
        )
    };
    let max_entries = limits
        .max_records()
        .saturating_mul(2)
        .saturating_add(SCAN_SLACK);
    let mut ids: Vec<RecordId> = Vec::new();
    let mut unrecognized = 0usize;
    let mut scanned = 0usize;
    let entries = fs::read_dir(dir).map_err(|_| list_error())?;
    for entry in entries {
        if sink.is_cancelled() {
            return Ok(0);
        }
        let entry = entry.map_err(|_| list_error())?;
        scanned += 1;
        if scanned > max_entries {
            return Err(too_many());
        }
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            // 非 UTF-8 の名前は ID になり得ない。`.rec` で終わるものは不正名として数える。
            if std::os::unix::ffi::OsStrExt::as_bytes(name.as_os_str())
                .ends_with(REC_EXT.as_bytes())
            {
                unrecognized += 1;
            }
            continue;
        };
        let Some(stem) = name.strip_suffix(REC_EXT) else {
            continue;
        };
        match RecordId::new(stem) {
            Ok(id) => {
                if ids.len() >= limits.max_records() {
                    return Err(too_many());
                }
                ids.push(id);
            }
            Err(_) => unrecognized += 1,
        }
    }
    ids.sort();
    let mut total = 0usize;
    for id in ids {
        if sink.is_cancelled() {
            return Ok(unrecognized);
        }
        #[cfg(test)]
        if let Some(h) = &hook {
            h(&id);
        }
        let path = dir.join(format!("{}{REC_EXT}", id.as_str()));
        let outcome = read_one(
            &path,
            kind.max_record_bytes(),
            limits.max_total_bytes(),
            &mut total,
        )?;
        if !sink.record(ListedRecord { id, outcome }) {
            return Ok(unrecognized);
        }
    }
    Ok(unrecognized)
}

/// 1 件を読む。保持量の上限を超えるなら列挙全体の失敗（`Err`）、その他の失敗は `Ok(Err(..))`。
fn read_one(
    path: &Path,
    max: usize,
    max_total: usize,
    total: &mut usize,
) -> Result<Result<Vec<u8>, RecordReadFailure>, Failed> {
    let Ok(before) = fs::symlink_metadata(path) else {
        return Ok(Err(RecordReadFailure::Unreadable));
    };
    if !before.file_type().is_file() {
        return Ok(Err(RecordReadFailure::NotRegularFile));
    }
    let len = usize::try_from(before.len()).unwrap_or(usize::MAX);
    if len > max {
        return Ok(Err(RecordReadFailure::TooLong));
    }
    if total.checked_add(len).is_none_or(|t| t > max_total) {
        return Err(too_much_data());
    }
    let Ok(file) = File::open(path) else {
        return Ok(Err(RecordReadFailure::Unreadable));
    };
    let Ok(after) = file.metadata() else {
        return Ok(Err(RecordReadFailure::Unreadable));
    };
    if !after.file_type().is_file() || after.dev() != before.dev() || after.ino() != before.ino() {
        return Ok(Err(RecordReadFailure::Unreadable));
    }
    let mut buf = Vec::new();
    // 検査後の伸長に備え、種別の上限と残りの総量予算の小さい方 + 1 バイトまでしか読まない。
    let remaining = max_total.saturating_sub(*total);
    let limit = u64::try_from(max.min(remaining))
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    if file.take(limit).read_to_end(&mut buf).is_err() {
        return Ok(Err(RecordReadFailure::Unreadable));
    }
    if buf.len() > max {
        return Ok(Err(RecordReadFailure::TooLong));
    }
    // 実際に読んだバイト数で総量を検証・計上する（metadata の長さは信用しない）。
    let new_total = total
        .checked_add(buf.len())
        .filter(|t| *t <= max_total)
        .ok_or_else(too_much_data)?;
    *total = new_total;
    Ok(Ok(buf))
}

/// `.lock` を期限つきで取る。**決して unlink しない**（消えた inode をロックして二重取得になるのを防ぐ。
/// plugin-cri の `InstanceLock`・`ReclaimStore` と同じ）。
fn lock_file(path: &Path, timeout: Duration) -> Result<File, Failed> {
    if let Ok(m) = fs::symlink_metadata(path)
        && !m.file_type().is_file()
    {
        return Err(Failed::new(
            RecordStoreOutcome::NotRegularFile,
            CriError::internal("cri record store lock is not a regular file"),
        ));
    }
    let mut opts = OpenOptions::new();
    opts.read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600);
    let file = opts
        .open(path)
        .map_err(|_| lock_error("failed to open the cri record store lock"))?;
    let deadline = Instant::now() + timeout;
    loop {
        match file.try_lock() {
            Ok(()) => return Ok(file),
            Err(std::fs::TryLockError::WouldBlock) => {
                if Instant::now() >= deadline {
                    return Err(Failed::new(
                        RecordStoreOutcome::LockTimeout,
                        CriError::timeout("timed out waiting for the cri record store lock"),
                    ));
                }
                std::thread::sleep(LOCK_POLL);
            }
            Err(std::fs::TryLockError::Error(_)) => {
                return Err(lock_error("failed to lock the cri record store"));
            }
        }
    }
}

/// 置き場のディレクトリを作る（無ければ 0700）か、既存を検査する。違反は消さずに拒否する。
fn ensure_private_dir(path: &Path, owner: u32) -> Result<(), CriError> {
    match DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(_) => return Err(prepare_error()),
    }
    let m = fs::symlink_metadata(path).map_err(|_| prepare_error())?;
    if !m.file_type().is_dir() || m.uid() != owner || m.mode() & 0o077 != 0 {
        return Err(prepare_error());
    }
    Ok(())
}

fn prepare_error() -> CriError {
    CriError::failed_precondition("failed to prepare the cri record store")
}

fn persist_error() -> Failed {
    Failed::new(
        RecordStoreOutcome::Io,
        CriError::internal("failed to persist the cri record"),
    )
}

fn remove_error() -> Failed {
    Failed::new(
        RecordStoreOutcome::Io,
        CriError::internal("failed to remove the cri record"),
    )
}

fn list_error() -> Failed {
    Failed::new(
        RecordStoreOutcome::Io,
        CriError::internal("failed to list the cri records"),
    )
}

fn not_regular() -> Failed {
    Failed::new(
        RecordStoreOutcome::NotRegularFile,
        CriError::internal("cri record target is not a regular file"),
    )
}

fn too_much_data() -> Failed {
    Failed::new(
        RecordStoreOutcome::TooMuchData,
        CriError::failed_precondition("cri record store holds too much data"),
    )
}

fn lock_error(message: &'static str) -> Failed {
    Failed::new(RecordStoreOutcome::LockError, CriError::internal(message))
}

/// `result` が失敗でも、`tolerated` に含まれる errno のときだけ成功として扱う。
fn tolerate_errnos(result: std::io::Result<()>, tolerated: &[i32]) -> std::io::Result<()> {
    match result {
        Err(e) if e.raw_os_error().is_some_and(|n| tolerated.contains(&n)) => Ok(()),
        other => other,
    }
}

/// ディレクトリの内容（rename・unlink・作成）を永続化する。
fn sync_dir(dir: &Path) -> std::io::Result<()> {
    #[cfg(target_os = "macos")]
    let tolerated: &[i32] = &DIR_SYNC_UNSUPPORTED_ERRNOS;
    #[cfg(not(target_os = "macos"))]
    let tolerated: &[i32] = &[];
    File::open(dir).and_then(|d| tolerate_errnos(d.sync_all(), tolerated))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime_service::record::SandboxRecordData;
    use std::os::unix::fs::symlink;
    use std::sync::Arc;

    const ID_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const ID_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const ID_C: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

    fn temp_root(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "fandhe-cri-record-store-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        DirBuilder::new().mode(0o700).create(&p).unwrap();
        p
    }

    fn id(s: &str) -> RecordId {
        RecordId::new(s).unwrap()
    }

    fn mode_of(p: &Path) -> u32 {
        fs::symlink_metadata(p).unwrap().mode() & 0o7777
    }

    fn list_all(store: &FileRecordStore, kind: RecordKind) -> RecordListing {
        store
            .list(kind, ListBudget::default(), ListLimits::for_kind(kind))
            .unwrap()
    }

    #[test]
    fn cri1_record_store_open_creates_private_dirs() {
        let root = temp_root("create");
        let store = FileRecordStore::open(&root).unwrap();
        for sub in [
            root.join(".cri"),
            root.join(".cri/records"),
            root.join(".cri/records/sandboxes"),
            root.join(".cri/records/containers"),
        ] {
            assert_eq!(mode_of(&sub), 0o700, "{sub:?}");
        }
        assert!(format!("{store:?}").contains("FileRecordStore"));
        assert!(!format!("{store:?}").contains("fandhe-cri-record-store"));
        // 2 回目の open は既存を受ける。
        FileRecordStore::open(&root).unwrap();
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn sec1_record_store_open_rejects_loose_mode() {
        let root = temp_root("loose");
        FileRecordStore::open(&root).unwrap();
        let d = root.join(".cri/records/sandboxes");
        fs::set_permissions(&d, std::os::unix::fs::PermissionsExt::from_mode(0o750)).unwrap();
        let e = FileRecordStore::open(&root).unwrap_err();
        assert_eq!(e.code(), crate::error::CriErrorCode::FailedPrecondition);
        assert_eq!(e.message(), "failed to prepare the cri record store");
        assert_eq!(mode_of(&d), 0o750);
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn sec1_record_store_open_rejects_symlink() {
        let root = temp_root("symlink");
        let target = temp_root("symlink-target");
        symlink(&target, root.join(".cri")).unwrap();
        let e = FileRecordStore::open(&root).unwrap_err();
        assert_eq!(e.code(), crate::error::CriErrorCode::FailedPrecondition);
        assert!(
            fs::symlink_metadata(root.join(".cri"))
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(fs::read_dir(&target).unwrap().count(), 0);
        fs::remove_dir_all(&root).unwrap();
        fs::remove_dir_all(&target).unwrap();
    }

    #[test]
    fn sec1_record_store_open_rejects_regular_file() {
        let root = temp_root("regular");
        fs::write(root.join(".cri"), b"keep me").unwrap();
        let e = FileRecordStore::open(&root).unwrap_err();
        assert_eq!(e.code(), crate::error::CriErrorCode::FailedPrecondition);
        assert_eq!(fs::read(root.join(".cri")).unwrap(), b"keep me");
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn sec1_record_store_open_rejects_owner_mismatch() {
        let root = temp_root("owner");
        let me = fs::metadata(&root).unwrap().uid();
        let e = FileRecordStore::open_with_owner(&root, me.wrapping_add(1)).unwrap_err();
        assert_eq!(e.code(), crate::error::CriErrorCode::FailedPrecondition);
        assert!(root.join(".cri").is_dir());
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn cri1_record_id_rejects_malformed() {
        for bad in [
            "",
            &"a".repeat(63),
            &"a".repeat(65),
            &"A".repeat(64),
            &format!("../{}", "a".repeat(61)),
            &"g".repeat(64),
        ] {
            let e = RecordId::new(bad).unwrap_err();
            assert_eq!(e.code(), crate::error::CriErrorCode::InvalidArgument);
            assert_eq!(e.message(), "invalid record id");
        }
        assert_eq!(RecordId::new(ID_A).unwrap().as_str(), ID_A);
    }

    #[test]
    fn cri1_record_store_put_list_remove_roundtrip() {
        let root = temp_root("roundtrip");
        let store = FileRecordStore::open(&root).unwrap();
        store.put(RecordKind::Sandbox, &id(ID_B), b"two").unwrap();
        store.put(RecordKind::Sandbox, &id(ID_A), b"one").unwrap();
        store.put(RecordKind::Container, &id(ID_C), b"ctr").unwrap();
        store
            .put(RecordKind::Sandbox, &id(ID_A), b"one-v2")
            .unwrap();
        let file = root.join(format!(".cri/records/sandboxes/{ID_A}.rec"));
        assert_eq!(mode_of(&file), 0o600);

        let sb = list_all(&store, RecordKind::Sandbox);
        assert_eq!(sb.unrecognized, 0);
        let got: Vec<(&str, &[u8])> = sb
            .records
            .iter()
            .map(|r| (r.id.as_str(), r.outcome.as_deref().unwrap()))
            .collect();
        assert_eq!(got, vec![(ID_A, &b"one-v2"[..]), (ID_B, &b"two"[..])]);
        let ct = list_all(&store, RecordKind::Container);
        assert_eq!(ct.records.len(), 1);
        assert_eq!(ct.records[0].outcome.as_deref().unwrap(), b"ctr");

        store.remove(RecordKind::Sandbox, &id(ID_A)).unwrap();
        store.remove(RecordKind::Sandbox, &id(ID_A)).unwrap();
        assert_eq!(list_all(&store, RecordKind::Sandbox).records.len(), 1);
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn cri1_record_store_put_rejects_too_long() {
        let root = temp_root("toolong");
        let store = FileRecordStore::open(&root).unwrap();
        let max = RecordKind::Sandbox.max_record_bytes();
        let e = store
            .put(RecordKind::Sandbox, &id(ID_A), &vec![b'x'; max + 1])
            .unwrap_err();
        assert_eq!(e.code(), crate::error::CriErrorCode::Internal);
        assert!(
            !root
                .join(format!(".cri/records/sandboxes/{ID_A}.rec"))
                .exists()
        );
        store
            .put(RecordKind::Sandbox, &id(ID_A), &vec![b'x'; max])
            .unwrap();
        assert_eq!(
            fs::metadata(root.join(format!(".cri/records/sandboxes/{ID_A}.rec")))
                .unwrap()
                .len(),
            max as u64
        );
        fs::remove_dir_all(&root).unwrap();
    }

    /// 記録が既に無い再試行でも親ディレクトリの同期を行い、同期できなければ失敗を返す（CRI-1）。
    #[test]
    fn cri1_record_store_remove_of_absent_record_still_syncs_directory() {
        let root = temp_root("remove-absent-sync");
        let store = FileRecordStore::open(&root).unwrap();
        // 置き場を消すと同期（ディレクトリの open）が失敗する。NotFound 分岐でも成功扱いにならない。
        fs::remove_dir_all(root.join(".cri/records/sandboxes")).unwrap();
        let e = store.remove(RecordKind::Sandbox, &id(ID_A)).unwrap_err();
        assert_eq!(e.message(), "failed to remove the cri record");
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn cri1_record_store_put_and_remove_refuse_non_regular_target() {
        let root = temp_root("nonregular");
        let store = FileRecordStore::open(&root).unwrap();
        let target = root.join(format!(".cri/records/sandboxes/{ID_A}.rec"));
        fs::create_dir(&target).unwrap();
        let e = store.put(RecordKind::Sandbox, &id(ID_A), b"x").unwrap_err();
        assert_eq!(e.code(), crate::error::CriErrorCode::Internal);
        let e = store.remove(RecordKind::Sandbox, &id(ID_A)).unwrap_err();
        assert_eq!(e.code(), crate::error::CriErrorCode::Internal);
        assert!(target.is_dir());
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn oci7_record_store_list_reports_broken_without_deleting() {
        let root = temp_root("broken");
        let store = FileRecordStore::open(&root).unwrap();
        let dir = root.join(".cri/records/sandboxes");
        let max = RecordKind::Sandbox.max_record_bytes();
        fs::write(dir.join("not-an-id.rec"), b"x").unwrap();
        fs::write(dir.join(".tmp-1-0"), b"x").unwrap();
        fs::write(dir.join("foo.txt"), b"x").unwrap();
        fs::write(dir.join(format!("{ID_A}.rec")), vec![b'x'; max + 1]).unwrap();
        fs::create_dir(dir.join(format!("{ID_B}.rec"))).unwrap();
        let outside = root.join("outside");
        fs::write(&outside, b"secret").unwrap();
        symlink(&outside, dir.join(format!("{ID_C}.rec"))).unwrap();

        let l = list_all(&store, RecordKind::Sandbox);
        assert_eq!(l.unrecognized, 1);
        let got: Vec<_> = l
            .records
            .iter()
            .map(|r| (r.id.as_str(), r.outcome.clone()))
            .collect();
        assert_eq!(
            got,
            vec![
                (ID_A, Err(RecordReadFailure::TooLong)),
                (ID_B, Err(RecordReadFailure::NotRegularFile)),
                (ID_C, Err(RecordReadFailure::NotRegularFile)),
            ]
        );
        for n in ["not-an-id.rec", ".tmp-1-0", "foo.txt"] {
            assert!(dir.join(n).exists(), "{n}");
        }
        assert!(dir.join(format!("{ID_A}.rec")).exists());
        assert!(dir.join(format!("{ID_B}.rec")).is_dir());
        assert_eq!(fs::read(&outside).unwrap(), b"secret");
        fs::remove_dir_all(&root).unwrap();
    }

    /// OCI-7: 非 UTF-8 の `.rec` 名も不正名として数える（`.rec` で終わらない非 UTF-8 名は数えない）。
    #[test]
    fn oci7_record_store_list_counts_non_utf8_rec_name() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;
        let root = temp_root("nonutf8");
        let store = FileRecordStore::open(&root).unwrap();
        let dir = root.join(".cri/records/sandboxes");
        fs::write(dir.join(OsStr::from_bytes(b"\xff.rec")), b"x").unwrap();
        fs::write(dir.join(OsStr::from_bytes(b"\xff.txt")), b"x").unwrap();
        let l = list_all(&store, RecordKind::Sandbox);
        assert_eq!(l.unrecognized, 1);
        assert!(l.records.is_empty());
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn cri1_record_store_garbage_content_is_returned_and_kept() {
        let root = temp_root("garbage");
        let store = FileRecordStore::open(&root).unwrap();
        store
            .put(RecordKind::Sandbox, &id(ID_A), b"garbage")
            .unwrap();
        let l = list_all(&store, RecordKind::Sandbox);
        let bytes = l.records[0].outcome.clone().unwrap();
        assert_eq!(bytes, b"garbage");
        let e = SandboxRecordData::decode(&bytes, ID_A).unwrap_err();
        assert_eq!(e.code(), crate::error::CriErrorCode::InvalidArgument);
        assert!(
            root.join(format!(".cri/records/sandboxes/{ID_A}.rec"))
                .exists()
        );
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn repair5_record_store_list_rejects_too_many_records() {
        let root = temp_root("many");
        let store = FileRecordStore::open(&root).unwrap();
        let kind = RecordKind::Sandbox;
        let dir = root.join(".cri/records/sandboxes");
        for i in 0..4u8 {
            let name = format!("{:02x}{}", i, "0".repeat(62));
            fs::write(dir.join(format!("{name}.rec")), b"x").unwrap();
        }
        let limits = ListLimits::for_kind(kind).with_max_records(kind, 3);
        let e = store.list(kind, ListBudget::default(), limits).unwrap_err();
        assert_eq!(e.code(), crate::error::CriErrorCode::FailedPrecondition);
        assert_eq!(e.message(), "cri record store holds too many records");
        let ok = ListLimits::for_kind(kind).with_max_records(kind, 4);
        assert_eq!(
            store
                .list(kind, ListBudget::default(), ok)
                .unwrap()
                .records
                .len(),
            4
        );
        // 既定の上限（MAX_SANDBOXES）を超える絞りは丸められる。
        assert_eq!(
            ListLimits::for_kind(kind)
                .with_max_records(kind, usize::MAX)
                .max_records(),
            crate::runtime_service::MAX_SANDBOXES
        );
        // 既定の上限でも MAX_SANDBOXES + 1 件で失敗する。
        for i in 4..=(crate::runtime_service::MAX_SANDBOXES as u32) {
            let name = format!("{:08x}{}", i + 0x1000, "0".repeat(56));
            fs::write(dir.join(format!("{name}.rec")), b"x").unwrap();
        }
        let e = store
            .list(kind, ListBudget::default(), ListLimits::for_kind(kind))
            .unwrap_err();
        assert_eq!(e.code(), crate::error::CriErrorCode::FailedPrecondition);
        fs::remove_dir_all(&root).unwrap();
    }

    /// CRI-1・REPAIR-5: 別種別の上限を渡しても list の入口で種別の既定値に絞られる。
    #[test]
    fn repair5_record_store_list_clamps_foreign_kind_limits() {
        let root = temp_root("clamp");
        let store = FileRecordStore::open(&root).unwrap();
        let foreign = ListLimits::for_kind(RecordKind::Container);
        assert!(foreign.max_records() > RecordKind::Sandbox.max_records());
        let clamped = foreign.clamp_to(RecordKind::Sandbox);
        assert_eq!(clamped.max_records(), RecordKind::Sandbox.max_records());
        store.put(RecordKind::Sandbox, &id(ID_A), b"x").unwrap();
        let listing = store
            .list(RecordKind::Sandbox, ListBudget::default(), foreign)
            .unwrap();
        assert_eq!(listing.records.len(), 1);
    }

    #[test]
    fn repair5_record_store_list_rejects_total_bytes_over_limit() {
        let root = temp_root("bytes");
        let store = FileRecordStore::open(&root).unwrap();
        let kind = RecordKind::Container;
        store.put(kind, &id(ID_A), &[b'x'; 60]).unwrap();
        let limits = ListLimits::for_kind(kind).with_max_total_bytes(kind, 100);
        assert_eq!(
            store
                .list(kind, ListBudget::default(), limits)
                .unwrap()
                .records
                .len(),
            1
        );
        store.put(kind, &id(ID_B), &[b'x'; 60]).unwrap();
        let e = store.list(kind, ListBudget::default(), limits).unwrap_err();
        assert_eq!(e.code(), crate::error::CriErrorCode::FailedPrecondition);
        assert_eq!(e.message(), "cri record store holds too much data");
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn repair5_record_store_list_bounds_directory_scan() {
        let root = temp_root("scan");
        let store = FileRecordStore::open(&root).unwrap();
        let kind = RecordKind::Sandbox;
        let dir = root.join(".cri/records/sandboxes");
        let limits = ListLimits::for_kind(kind).with_max_records(kind, 2);
        for i in 0..(2 * 2 + SCAN_SLACK + 1) {
            fs::write(dir.join(format!("junk-{i}")), b"").unwrap();
        }
        let e = store.list(kind, ListBudget::default(), limits).unwrap_err();
        assert_eq!(e.code(), crate::error::CriErrorCode::FailedPrecondition);
        fs::remove_dir_all(&root).unwrap();
    }

    fn with_sleep_hook(store: &mut FileRecordStore, ms: u64) {
        store.read_hook = Some(Arc::new(move |_| {
            std::thread::sleep(Duration::from_millis(ms))
        }));
    }

    #[test]
    fn repair5_record_store_list_per_record_timeout() {
        let root = temp_root("perrec");
        let mut store = FileRecordStore::open(&root).unwrap();
        store.put(RecordKind::Sandbox, &id(ID_A), b"x").unwrap();
        with_sleep_hook(&mut store, 300);
        let budget = ListBudget {
            per_record: Duration::from_millis(50),
            total: Duration::from_secs(10),
        };
        let start = Instant::now();
        let e = store
            .list(
                RecordKind::Sandbox,
                budget,
                ListLimits::for_kind(RecordKind::Sandbox),
            )
            .unwrap_err();
        assert_eq!(e.code(), crate::error::CriErrorCode::Timeout);
        assert!(start.elapsed() < Duration::from_secs(1));
        std::thread::sleep(Duration::from_millis(400));
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn repair5_record_store_list_total_timeout() {
        let root = temp_root("total");
        let mut store = FileRecordStore::open(&root).unwrap();
        for c in ["a", "b", "c", "d", "e"] {
            store
                .put(RecordKind::Sandbox, &id(&c.repeat(64)), b"x")
                .unwrap();
        }
        with_sleep_hook(&mut store, 40);
        let budget = ListBudget {
            per_record: Duration::from_secs(1),
            total: Duration::from_millis(100),
        };
        let e = store
            .list(
                RecordKind::Sandbox,
                budget,
                ListLimits::for_kind(RecordKind::Sandbox),
            )
            .unwrap_err();
        assert_eq!(e.code(), crate::error::CriErrorCode::Timeout);
        // worker が中止フラグで抜けるとロックが解放され、短い lock 期限内に put が通る。
        store.lock_timeout = Duration::from_secs(2);
        store.put(RecordKind::Sandbox, &id(ID_A), b"y").unwrap();
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn repair5_record_store_lock_contention_times_out() {
        let root = temp_root("lock");
        let mut store = FileRecordStore::open(&root).unwrap();
        store.lock_timeout = Duration::from_millis(100);
        let held = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&store.lock_path)
            .unwrap();
        held.try_lock().unwrap();
        let e = store.put(RecordKind::Sandbox, &id(ID_A), b"x").unwrap_err();
        assert_eq!(e.code(), crate::error::CriErrorCode::Timeout);
        drop(held);
        store.put(RecordKind::Sandbox, &id(ID_A), b"x").unwrap();
        // .lock が symlink のときは拒否する（ロックファイルは消さない）。
        fs::remove_file(&store.lock_path).unwrap();
        let other = root.join("other-lock");
        fs::write(&other, b"").unwrap();
        symlink(&other, &store.lock_path).unwrap();
        let e = store.put(RecordKind::Sandbox, &id(ID_B), b"x").unwrap_err();
        assert_eq!(e.code(), crate::error::CriErrorCode::Internal);
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn cri1_record_store_put_survives_stale_tmp_collision() {
        let root = temp_root("tmpcollision");
        let store = FileRecordStore::open(&root).unwrap();
        let dir = root.join(".cri/records/sandboxes");
        let pid = std::process::id();
        fs::write(dir.join(format!(".tmp-{pid}-0")), b"stale").unwrap();
        fs::write(dir.join(format!(".tmp-{pid}-1")), b"stale").unwrap();
        store.put(RecordKind::Sandbox, &id(ID_A), b"fresh").unwrap();
        assert_eq!(store.next_seq.load(Ordering::Relaxed), 3);
        assert_eq!(fs::read(dir.join(format!("{ID_A}.rec"))).unwrap(), b"fresh");
        assert_eq!(
            fs::read(dir.join(format!(".tmp-{pid}-0"))).unwrap(),
            b"stale"
        );
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn cri1_record_store_tolerate_errnos_only_listed() {
        let err = |n| Err(std::io::Error::from_raw_os_error(n));
        assert!(tolerate_errnos(err(22), &DIR_SYNC_UNSUPPORTED_ERRNOS).is_ok());
        assert!(tolerate_errnos(err(45), &DIR_SYNC_UNSUPPORTED_ERRNOS).is_ok());
        assert_eq!(
            tolerate_errnos(err(5), &DIR_SYNC_UNSUPPORTED_ERRNOS)
                .unwrap_err()
                .raw_os_error(),
            Some(5)
        );
        assert!(tolerate_errnos(Ok(()), &[]).is_ok());
    }

    /// 記録器の呼び出しを控える試験用の実装。
    #[derive(Default)]
    struct Capture(std::sync::Mutex<Vec<RecordStoreOpSample>>);

    impl RecordStoreOpRecorder for Capture {
        fn record_store_op(&self, sample: &RecordStoreOpSample) {
            self.0.lock().unwrap().push(*sample);
        }
    }

    impl Capture {
        fn take(&self) -> Vec<RecordStoreOpSample> {
            std::mem::take(&mut *self.0.lock().unwrap())
        }

        /// 直近 1 件の (操作, 種別, 結果区分) を取り出して 1 件だけであることを確認する。
        fn one(&self) -> RecordStoreOpSample {
            let mut v = self.take();
            assert_eq!(v.len(), 1, "exactly one sample per operation: {v:?}");
            v.remove(0)
        }
    }

    fn captured_store(root: &Path) -> (FileRecordStore, Arc<Capture>) {
        let cap = Arc::new(Capture::default());
        let store = FileRecordStore::open(root)
            .unwrap()
            .with_recorder(Arc::clone(&cap) as Arc<dyn RecordStoreOpRecorder>);
        (store, cap)
    }

    fn expect(
        s: RecordStoreOpSample,
        op: RecordStoreOp,
        kind: RecordKind,
        outcome: RecordStoreOutcome,
    ) {
        assert_eq!((s.op, s.kind, s.outcome), (op, kind, outcome));
    }

    #[test]
    fn repair4_record_store_records_put_and_remove_outcomes() {
        let root = temp_root("rec-putrm");
        let (mut store, cap) = captured_store(&root);
        let k = RecordKind::Sandbox;
        // 成功。
        store.put(k, &id(ID_A), b"x").unwrap();
        expect(cap.one(), RecordStoreOp::Put, k, RecordStoreOutcome::Ok);
        // 上限拒否（何も書かない）。
        let big = vec![0u8; k.max_record_bytes() + 1];
        store.put(k, &id(ID_A), &big).unwrap_err();
        expect(
            cap.one(),
            RecordStoreOp::Put,
            k,
            RecordStoreOutcome::TooLong,
        );
        // 通常ファイルでない対象。
        let dir_target = store.record_path(k, &id(ID_B));
        fs::create_dir(&dir_target).unwrap();
        store.put(k, &id(ID_B), b"x").unwrap_err();
        expect(
            cap.one(),
            RecordStoreOp::Put,
            k,
            RecordStoreOutcome::NotRegularFile,
        );
        store.remove(k, &id(ID_B)).unwrap_err();
        expect(
            cap.one(),
            RecordStoreOp::Remove,
            k,
            RecordStoreOutcome::NotRegularFile,
        );
        fs::remove_dir(&dir_target).unwrap();
        // 削除の成功と、既に無い場合（冪等）。
        store.remove(k, &id(ID_A)).unwrap();
        expect(cap.one(), RecordStoreOp::Remove, k, RecordStoreOutcome::Ok);
        store.remove(k, &id(ID_A)).unwrap();
        expect(cap.one(), RecordStoreOp::Remove, k, RecordStoreOutcome::Ok);
        // ロック取得の期限切れ（所要時間に待ちが含まれる）。
        store.lock_timeout = Duration::from_millis(100);
        let held = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&store.lock_path)
            .unwrap();
        held.try_lock().unwrap();
        store.put(k, &id(ID_A), b"x").unwrap_err();
        let s = cap.one();
        expect(s, RecordStoreOp::Put, k, RecordStoreOutcome::LockTimeout);
        assert!(s.latency >= Duration::from_millis(100), "{:?}", s.latency);
        store.remove(k, &id(ID_A)).unwrap_err();
        expect(
            cap.one(),
            RecordStoreOp::Remove,
            k,
            RecordStoreOutcome::LockTimeout,
        );
        drop(held);
        // ロックファイルが symlink。
        fs::remove_file(&store.lock_path).unwrap();
        let other = root.join("other-lock");
        fs::write(&other, b"").unwrap();
        symlink(&other, &store.lock_path).unwrap();
        store.put(k, &id(ID_A), b"x").unwrap_err();
        expect(
            cap.one(),
            RecordStoreOp::Put,
            k,
            RecordStoreOutcome::NotRegularFile,
        );
        fs::remove_file(&store.lock_path).unwrap();
        // I/O エラー（置き場が消えた）。
        fs::remove_dir_all(store.dir(k)).unwrap();
        store.put(k, &id(ID_A), b"x").unwrap_err();
        expect(cap.one(), RecordStoreOp::Put, k, RecordStoreOutcome::Io);
        store.remove(k, &id(ID_A)).unwrap_err();
        expect(cap.one(), RecordStoreOp::Remove, k, RecordStoreOutcome::Io);
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn repair4_record_store_records_list_outcomes() {
        let root = temp_root("rec-list");
        let (mut store, cap) = captured_store(&root);
        let k = RecordKind::Container;
        store.put(k, &id(ID_A), &[b'x'; 60]).unwrap();
        store.put(k, &id(ID_B), &[b'x'; 60]).unwrap();
        cap.take();
        // 成功。
        store
            .list(k, ListBudget::default(), ListLimits::for_kind(k))
            .unwrap();
        expect(cap.one(), RecordStoreOp::List, k, RecordStoreOutcome::Ok);
        // 件数の上限。
        let e = store
            .list(
                k,
                ListBudget::default(),
                ListLimits::for_kind(k).with_max_records(k, 1),
            )
            .unwrap_err();
        assert_eq!(e.code(), crate::error::CriErrorCode::FailedPrecondition);
        expect(
            cap.one(),
            RecordStoreOp::List,
            k,
            RecordStoreOutcome::TooManyRecords,
        );
        // 保持量の上限。
        store
            .list(
                k,
                ListBudget::default(),
                ListLimits::for_kind(k).with_max_total_bytes(k, 100),
            )
            .unwrap_err();
        expect(
            cap.one(),
            RecordStoreOp::List,
            k,
            RecordStoreOutcome::TooMuchData,
        );
        // 列挙の期限切れ（所要時間に待ちが含まれる）。
        with_sleep_hook(&mut store, 300);
        let budget = ListBudget {
            per_record: Duration::from_millis(50),
            total: Duration::from_secs(10),
        };
        store.list(k, budget, ListLimits::for_kind(k)).unwrap_err();
        let s = cap.one();
        expect(s, RecordStoreOp::List, k, RecordStoreOutcome::ListTimeout);
        assert!(s.latency >= Duration::from_millis(50), "{:?}", s.latency);
        // worker が抜けるのを待ってから、ロック取得の期限切れ（worker 側）を確認する。
        std::thread::sleep(Duration::from_millis(800));
        store.read_hook = None;
        store.lock_timeout = Duration::from_millis(100);
        let held = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&store.lock_path)
            .unwrap();
        held.try_lock().unwrap();
        store
            .list(k, ListBudget::default(), ListLimits::for_kind(k))
            .unwrap_err();
        expect(
            cap.one(),
            RecordStoreOp::List,
            k,
            RecordStoreOutcome::LockTimeout,
        );
        drop(held);
        // I/O エラー（置き場が消えた）。
        fs::remove_dir_all(store.dir(k)).unwrap();
        store
            .list(k, ListBudget::default(), ListLimits::for_kind(k))
            .unwrap_err();
        expect(cap.one(), RecordStoreOp::List, k, RecordStoreOutcome::Io);
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn repair4_record_store_outcome_names_are_fixed() {
        // 記録先へ渡す語彙は固定。名前の変更は集計の互換性を壊すため具体値で固定する。
        assert_eq!(RecordStoreOp::Put.as_str(), "put");
        assert_eq!(RecordStoreOp::Remove.as_str(), "remove");
        assert_eq!(RecordStoreOp::List.as_str(), "list");
        assert_eq!(RecordStoreOutcome::Ok.as_str(), "ok");
        assert_eq!(RecordStoreOutcome::LockTimeout.as_str(), "lock_timeout");
        assert_eq!(RecordStoreOutcome::ListTimeout.as_str(), "list_timeout");
        assert_eq!(RecordStoreOutcome::TooLong.as_str(), "too_long");
    }
}
