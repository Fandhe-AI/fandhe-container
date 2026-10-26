//! イメージストア単位の排他区間（OCI-7・TASK-183.2・MS-4・#473）。
//!
//! `image rm` / `image prune` の GC は「排他取得 → 参照テーブルの数え直し → 削除 → 解放」を単一の
//! 排他区間で行い、その間に参照テーブルを変える操作（create の参照登録・delete の参照解除・
//! `image tag` のタグ登録・`image rm` の untag・pull のリース登録 / 公開 / 解放）を割り込ませない。
//! 本モジュールはその区間を `ImageStore::lock` の RAII ガードとして提供する。
//! 後続の #474・#475（pull）・#476（prune）・#479（tag）・#480 / #481（rm）・#853（create / delete。入口は `register_container_ref` / `release_container_ref`）が使う。
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
//! - コンテナ参照（エントリと世代カウンタ）は #2341 で root 直下の `@container-refs.json` へ、manifest の
//!   在庫・タグ・pull リースは #2380 で `@image-inventory.json`（`inventory_persist`）へ永続化済み。
//!   排他区間に入るたびにどちらもディスクから読み直し（ファイルが無ければメモリ上の内容を保つ）、読み込みに
//!   失敗したら `lock` 自体がエラーを返す。削除の永続化（削除ジャーナルと取得時の再試行。`gc_journal`・#851）も
//!   実装済み。保存はひとまとまりの操作の入口が排他の中で行い、ガードから下位メソッドを直接呼んだ変更は
//!   保存されない（試験と `with_table` の種入れ用の口。ファイルがあれば次の排他取得でディスクの内容になる）。
//!   在庫を埋める経路（pull → `ImageStore`）は cri の `OciImagePuller::pull` に配線済み（#2539）。本番の `PullImage` へは #2592 で到達済み。
//! - root の所有者・権限・祖先の検査は `open` / `with_table` で行う（#2381・SEC-1。unix のみ）。root は
//!   現在の実効 uid の所有で group / other に書き込めないこと（`0o022` が立っていない。0700 と 0755 は受理、
//!   0770・0757・1777 は拒否）、祖先は root か実効 uid の所有で、group / other に書き込めないこと
//!   （sticky bit 付きは許す）を、副作用（`@lock` の作成）より前に確かめ、違反は `PermissionDenied`。
//!   root は `canonicalize` した正規パスと open 時の dev / ino を保持し、`lock` と create ゲートの
//!   取得ごとに同じ検査を `@lock` / ゲートファイルの作成より前に再実行する（`reverify_root`・#2547）。
//!   権限の基準（厳密な 0700 か現行の `0o022` か）と root の所有者の基準はオーナー判断待ちで、現行を保つ
//!   （選択肢と影響は `docs/design/image-store-root-trust.md`・#2547）。残る制約: Windows は検査しない
//!   （ACL は #2428 の方式判断後）、macOS の拡張 ACL は見ない（根拠は同 doc）。
//! - 再検査から使用までの差し替え（TOCTOU）は、Linux の x86_64 / aarch64 では root を開いたまま持つ
//!   `RootHandle`（`root_handle`）の fd 起点の `openat2` / `*at` で閉じる（#2638）。入口の `reverify_root` が
//!   差し替えを検出して拒否し、区間内の永続化操作（`@lock`・参照・在庫・ジャーナル・blob の削除）は検査済みの
//!   実体にだけ届く。他の OS・アーキテクチャはパス起点＋入口の再検査のままで、「root と祖先は所有者専用」の
//!   前提で防ぐ。`usage` の読み取りと `pull` の staging・公開はパス起点のまま（根拠は同 doc の論点 3）。
//!   Linux 5.6 未満など `openat2` が使えない環境では `open` が `Unimplemented` で拒否する。

use std::fs::{self, File, TryLockError};
use std::ops::{Deref, DerefMut};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, TryLockError as MutexTryLockError};
use std::thread;
use std::time::{Duration, Instant};

use super::ReferenceTable;
use super::container_ref_persist::load_container_refs;
use super::gc_journal::{
    PendingDeletionRecovery, STALE_TMP_PREFIXES, journal_state, reap_stale_tmp,
};
use super::inventory_persist::load_image_inventory;
use super::root_handle::{RootHandle, map_root_io};
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
    /// open 時に検査した root を開いたまま持つ。永続化操作はここを起点にする（#2638）。
    handle: Arc<RootHandle>,
    table: Mutex<ReferenceTable>,
    timeout: Duration,
    recorder: Arc<dyn OciOpRecorder>,
}

impl ImageStore {
    /// 空の参照テーブルでストアを開く。root は存在するディレクトリ（symlink 不可）でなければならない。
    ///
    /// unix では root が実効 uid の所有で group / other に書き込めず、祖先も root か実効 uid の所有で
    /// 他者に書き込めない（sticky 付きを除く）ことを要求し、違反は `PermissionDenied`（OCI-7・SEC-1・#2381）。
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
        #[cfg(unix)]
        let handle = {
            let (canonical, id) = verify_root_trust(root, &meta)?;
            RootHandle::open_checked(canonical, id)?
        };
        #[cfg(not(unix))]
        let handle = RootHandle::open_checked(root)?;
        Ok(Self {
            handle: Arc::new(handle),
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

    /// 記録先。`tag` 等の同モジュール階層の操作入口が、ガード取得後の操作を計装するために使う。
    pub(super) fn recorder(&self) -> &dyn OciOpRecorder {
        &*self.recorder
    }

    /// ストア root。
    pub fn root(&self) -> &Path {
        self.handle.path()
    }

    /// 検査済み root のハンドル（永続化操作の起点。同モジュール階層の入口が使う）。
    pub(super) fn handle(&self) -> &Arc<RootHandle> {
        &self.handle
    }

    /// 排他区間の取得を待つ上限（`with_timeout` の値）。create ゲートが同じ期限を使う。
    pub(super) fn lock_timeout(&self) -> Duration {
        self.timeout
    }

    /// 排他区間を取得する。スレッド間・プロセス間で他の保持者がいれば期限まで待ち、超過は `Timeout`。
    ///
    /// 取得ごとに成否・エラー code・所要時間を記録先へ渡す（REPAIR-4）。期限が `Instant` で表現できない
    /// ほど長い場合は `InvalidArgument`。
    pub fn lock(&self) -> Result<ImageStoreGuard<'_>, OciError> {
        record_oci_op(&*self.recorder, OciOpKind::AcquireImageStoreLock, || {
            let guard = self.lock_inner()?;
            // 復旧後もジャーナル（墓標を含む）が見えているなら、変更を許さない（OCI-7）。
            // 古い untag・manifest 除去が再登録と両立しないため、障害が除かれて復旧が完了するまで拒否する。
            if journal_state(&self.handle)? {
                return Err(OciError::new(
                    OciErrorCode::FailedPrecondition,
                    "a pending image deletion could not be completed; retry after it is recovered",
                ));
            }
            Ok(guard)
        })
    }

    /// 排他区間を取得し、残っている削除ジャーナルがあれば参照を数え直して削除をやり直す
    /// （OCI-7・TASK-183.11.1・#851）。結果（無ければ `None`）を返して区間を閉じる。
    ///
    /// `lock` も取得時に同じ再試行を行うため、起動時に明示的に呼ぶのは結果を知りたい場合だけでよい。
    /// CLI / CRI からの配線は未実装（REPAIR-3）。
    pub fn recover_pending_deletion(&self) -> Result<Option<PendingDeletionRecovery>, OciError> {
        record_oci_op(&*self.recorder, OciOpKind::AcquireImageStoreLock, || {
            self.lock_inner().map(|mut g| g.recovered.take())
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
        // open 後の chmod / 差し替えを `@lock` の作成より前に fail-closed で拒否する（#2547・SEC-1）。
        self.reverify_root()?;
        #[cfg(test)]
        test_hook::run_after_reverify();
        let file = open_lock_file(&self.handle)?;
        lock_file_until(&file, deadline)?;
        let mut guard = ImageStoreGuard {
            _file: file,
            table,
            recovered: None,
        };
        guard.table.set_root_handle(Arc::clone(&self.handle));
        // 区間に入るたびにディスクのコンテナ参照を正とする（#2341）。壊れた参照表は fail-closed で拒否する。
        if let Some(persisted) = load_container_refs(&self.handle)? {
            guard.table.apply_persisted_container_refs(persisted);
        }
        // manifest の在庫・タグ・pull リースも同様にディスクを正とする（#2380）。ファイルが無ければメモリ上の
        // 内容を保つ。復旧と GC の数え直しが別プロセスのリース・タグを見られるよう、復旧より前に読む。
        if let Some(persisted) = load_image_inventory(&self.handle)? {
            guard.table.apply_persisted_inventory(persisted);
        }
        // 他の操作が割り込む前に、前回の中断した削除を片づける。ジャーナルがあったときだけ記録する。
        reap_stale_tmp(&self.handle, STALE_TMP_PREFIXES);
        let recovered = if journal_state(&self.handle)? {
            record_oci_op(&*self.recorder, OciOpKind::RecoverPendingDeletion, || {
                guard.table.resume_pending_deletion_at(&self.handle)
            })?
        } else {
            None
        };
        guard.recovered = recovered;
        Ok(guard)
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
    /// この取得時に行った中断削除の復旧結果（無ければ `None`）。`Abandoned` で孤児として残った blob
    /// （`undeleted_blobs`）や `Pending` の状態を、呼び出し側が構造化された形で受け取るために保持する
    /// （OCI-7・REPAIR-4。ジャーナルは片づいていても運用者の確認が要る情報を捨てない）。
    recovered: Option<PendingDeletionRecovery>,
}

impl ImageStoreGuard<'_> {
    /// この取得時に行った中断削除の復旧結果。ジャーナルが無かったときは `None`。
    pub fn recovery(&self) -> Option<&PendingDeletionRecovery> {
        self.recovered.as_ref()
    }
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
pub(super) fn wait_or_timeout(deadline: Instant) -> Result<(), OciError> {
    if Instant::now() >= deadline {
        return Err(OciError::new(
            OciErrorCode::Timeout,
            "timed out waiting for the image store lock",
        ));
    }
    thread::sleep(LOCK_RETRY_INTERVAL);
    Ok(())
}

impl ImageStore {
    /// root と祖先の信頼性を再検査する（`lock` / create ゲートの取得ごと。副作用より前に呼ぶ。#2547・SEC-1）。
    ///
    /// open 時の dev / ino と食い違えば差し替えとして `Internal`。非 unix は検査しない（Windows は #2428）。
    pub(super) fn reverify_root(&self) -> Result<(), OciError> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let meta = fs::symlink_metadata(self.handle.path()).map_err(|e| {
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
            if (meta.dev(), meta.ino()) != self.handle.id() {
                return Err(OciError::new(
                    OciErrorCode::Internal,
                    "image store root changed after open",
                ));
            }
            // 所有者・権限は開いている実体（fd）で見る。パスの差し替えに影響されない（#2638）。
            let held = self.handle.root_meta().map_err(|_| {
                OciError::new(OciErrorCode::Internal, "image store root is not accessible")
            })?;
            let euid = crate::sys::effective_uid();
            verify_root_meta(&held, euid)?;
            verify_ancestors(self.handle.path(), euid)?;
        }
        Ok(())
    }
}

fn lock_file_error() -> OciError {
    OciError::new(
        OciErrorCode::Internal,
        "image store lock file is not a regular file",
    )
}

/// root と祖先の信頼性を検査し、正規化したパスを返す（OCI-7・SEC-1・#2381）。`@lock` 作成等の副作用より前に呼ぶ。
#[cfg(unix)]
fn verify_root_trust(
    root: PathBuf,
    meta: &fs::Metadata,
) -> Result<(PathBuf, (u64, u64)), OciError> {
    let euid = crate::sys::effective_uid();
    verify_root_meta(meta, euid)?;
    let canonical = fs::canonicalize(&root)
        .map_err(|_| OciError::new(OciErrorCode::Internal, "image store root is not accessible"))?;
    // 検査した実体と正規化後の実体が同じことを確かめる（検査と正規化の間の差し替えを fail-closed に）。
    let after = fs::symlink_metadata(&canonical)
        .map_err(|_| OciError::new(OciErrorCode::Internal, "image store root is not accessible"))?;
    use std::os::unix::fs::MetadataExt;
    if after.dev() != meta.dev() || after.ino() != meta.ino() {
        return Err(OciError::new(
            OciErrorCode::Internal,
            "image store root changed while opening",
        ));
    }
    verify_ancestors(&canonical, euid)?;
    Ok((canonical, (after.dev(), after.ino())))
}

/// 祖先ディレクトリをすべて `verify_ancestor_meta` で検査する（open と再検査で共用）。
#[cfg(unix)]
fn verify_ancestors(canonical: &Path, euid: u32) -> Result<(), OciError> {
    for ancestor in canonical.ancestors().skip(1) {
        let m = fs::metadata(ancestor).map_err(|_| {
            OciError::new(
                OciErrorCode::Internal,
                "ancestor of the image store root is not accessible",
            )
        })?;
        verify_ancestor_meta(&m, euid)?;
    }
    Ok(())
}

/// root 自身の所有者・権限の判定（sticky の免除なし。1777 の root は攻撃そのもの）。
#[cfg(unix)]
fn verify_root_meta(meta: &fs::Metadata, euid: u32) -> Result<(), OciError> {
    use std::os::unix::fs::MetadataExt;
    if meta.mode() & 0o022 != 0 {
        return Err(OciError::new(
            OciErrorCode::PermissionDenied,
            "image store root must not be writable by group or others",
        ));
    }
    if meta.uid() != euid {
        return Err(OciError::new(
            OciErrorCode::PermissionDenied,
            "image store root must be owned by the current user",
        ));
    }
    Ok(())
}

/// 祖先ディレクトリの判定（root か実効 uid の所有。sticky 付きの group / other 書き込み可は許す。`/tmp` 等）。
#[cfg(unix)]
fn verify_ancestor_meta(meta: &fs::Metadata, euid: u32) -> Result<(), OciError> {
    use std::os::unix::fs::MetadataExt;
    let mode = meta.mode();
    if mode & 0o022 != 0 && mode & 0o1000 == 0 {
        return Err(OciError::new(
            OciErrorCode::PermissionDenied,
            "ancestor of the image store root must not be writable by group or others",
        ));
    }
    if meta.uid() != 0 && meta.uid() != euid {
        return Err(OciError::new(
            OciErrorCode::PermissionDenied,
            "ancestor of the image store root must be owned by root or the current user",
        ));
    }
    Ok(())
}

/// `@lock` を開く（無ければ 0600 で作る）。symlink・通常ファイル以外は拒否する。
fn open_lock_file(root: &RootHandle) -> Result<File, OciError> {
    open_named_lock_file(root, IMAGE_STORE_LOCK_FILE_NAME)
}

/// root 直下の固定名ロックファイルを開く（無ければ 0600 で作る）。symlink・通常ファイル以外は拒否する。
///
/// `name` は定数だけを渡す（外部入力からパスを組まない）。`@lock` と create ゲート（`create_gate.rs`）が共用する。
/// Linux の x86_64 / aarch64 では検査済み root の fd 起点で開く（`O_NOFOLLOW`。#2638）。
pub(super) fn open_named_lock_file(root: &RootHandle, name: &str) -> Result<File, OciError> {
    let pre = match root.stat_name(name) {
        Ok(Some(m)) if m.is_file() => Some(m),
        Ok(Some(_)) => return Err(lock_file_error()),
        Ok(None) => None,
        Err(e) => {
            return Err(map_root_io(&e, || {
                OciError::new(
                    OciErrorCode::Internal,
                    "failed to inspect the image store lock file",
                )
            }));
        }
    };
    let file = match root.open_lock(name) {
        Ok(f) => f,
        Err(e) => {
            // 検査後に symlink・ディレクトリへ差し替えられた場合（`O_NOFOLLOW` の拒否など）は通常ファイルでない扱い。
            // root 配下の別マウント（`@lock` の bind mount 等。EXDEV）は対応外として原因を示す（#2701）。
            return Err(match root.stat_name(name) {
                Ok(Some(m)) if !m.is_file() => lock_file_error(),
                _ => map_root_io(&e, || {
                    OciError::new(
                        OciErrorCode::Internal,
                        "failed to open the image store lock file",
                    )
                }),
            });
        }
    };
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

/// 試験用: `reverify_root` の直後（排他区間の中の最初の操作の前）に任意の処理を差し込む。
/// 検査後に root を差し替える競合を決定的に再現するために使う（OCI-7・SEC-1・#2638）。
#[cfg(test)]
pub(super) mod test_hook {
    use std::cell::RefCell;

    type Hook = Box<dyn FnOnce()>;

    thread_local! {
        static AFTER_REVERIFY: RefCell<Option<Hook>> = const { RefCell::new(None) };
    }

    /// 次の 1 回の `lock` の再検査直後に実行する処理を仕込む（このスレッドだけ・1 回限り）。
    #[cfg_attr(
        not(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )),
        allow(dead_code)
    )]
    pub(in crate::image_management) fn set_after_reverify(f: impl FnOnce() + 'static) {
        AFTER_REVERIFY.with(|h| *h.borrow_mut() = Some(Box::new(f)));
    }

    pub(super) fn run_after_reverify() {
        if let Some(f) = AFTER_REVERIFY.with(|h| h.borrow_mut().take()) {
            f();
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
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).expect("chmod");
        }
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
                t.acquire_lease(d(0x10), PullId::new("p1").expect("pull"))
                    .unwrap();
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
        let other = open_lock_file(&RootHandle::open_unchecked(&root).expect("handle"))
            .expect("open lock file");
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

    #[cfg(unix)]
    fn chmod(p: &Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(p, fs::Permissions::from_mode(mode)).expect("chmod");
    }

    /// OCI-7・SEC-1・#2381: 0700 と 0755 の root は受理する。
    #[cfg(unix)]
    #[test]
    fn oci7_open_accepts_0700_and_0755_roots() {
        let root = temp_root("m_ok");
        for mode in [0o700, 0o755] {
            chmod(&root, mode);
            ImageStore::open(&root).unwrap_or_else(|e| panic!("mode {mode:o}: {e:?}"));
        }
        let _ = fs::remove_dir_all(&root);
    }

    /// OCI-7・SEC-1・#2381: group / other に書き込める root は拒否し、`@lock` も作らない。
    #[cfg(unix)]
    #[test]
    fn oci7_open_rejects_group_or_other_writable_root() {
        let root = temp_root("m_bad");
        for mode in [0o770, 0o757, 0o1777] {
            chmod(&root, mode);
            let e = ImageStore::open(&root).expect_err("writable root");
            assert_eq!(e.code(), OciErrorCode::PermissionDenied, "mode {mode:o}");
            assert!(!root.join(IMAGE_STORE_LOCK_FILE_NAME).exists());
        }
        chmod(&root, 0o700);
        let _ = fs::remove_dir_all(&root);
    }

    /// OCI-7・SEC-1・#2381: 他者が書き込める祖先（sticky なし）は拒否し、sticky 付きは受理する。
    #[cfg(unix)]
    #[test]
    fn oci7_open_checks_ancestor_permissions() {
        let base = temp_root("anc");
        let root = base.join("store");
        fs::create_dir(&root).expect("mkdir");
        chmod(&root, 0o700);
        chmod(&base, 0o777);
        assert_eq!(
            ImageStore::open(&root).expect_err("ancestor").code(),
            OciErrorCode::PermissionDenied
        );
        chmod(&base, 0o1777);
        ImageStore::open(&root).expect("sticky ancestor is accepted");
        chmod(&base, 0o700);
        let _ = fs::remove_dir_all(&base);
    }

    /// OCI-7・SEC-1・#2547: open 後に root へ group / other の書き込みを付けると、`lock` は `@lock` を作らず拒否する。
    #[cfg(unix)]
    #[test]
    fn oci7_sec1_lock_rechecks_root_mode() {
        let root = temp_root("recheck-mode");
        let store = ImageStore::open(&root).expect("open");
        chmod(&root, 0o757);
        let Err(err) = store.lock() else {
            panic!("must be rejected")
        };
        assert_eq!(err.code(), OciErrorCode::PermissionDenied);
        assert!(!root.join(IMAGE_STORE_LOCK_FILE_NAME).exists());
        let err = store.recover_pending_deletion().expect_err("recover");
        assert_eq!(err.code(), OciErrorCode::PermissionDenied);
        chmod(&root, 0o700);
        store.lock().expect("accepted again");
        let _ = fs::remove_dir_all(&root);
    }

    /// OCI-7・SEC-1・#2547: open 後に root が別ディレクトリへ差し替わると `lock` は `Internal` で拒否する。
    #[cfg(unix)]
    #[test]
    fn oci7_sec1_lock_rejects_swapped_root() {
        let root = temp_root("recheck-swap");
        let store = ImageStore::open(&root).expect("open");
        let moved = root.with_extension("moved");
        fs::rename(&root, &moved).expect("rename");
        fs::create_dir(&root).expect("mkdir");
        chmod(&root, 0o700);
        let Err(err) = store.lock() else {
            panic!("must be rejected")
        };
        assert_eq!(err.code(), OciErrorCode::Internal);
        assert_eq!(err.message(), "image store root changed after open");
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&moved);
    }

    /// OCI-7・SEC-1・#2547: open 後に祖先が他者書き込み可（sticky なし）になると `lock` は拒否する。
    #[cfg(unix)]
    #[test]
    fn oci7_sec1_lock_rechecks_ancestor_mode() {
        let base = temp_root("recheck-anc");
        let root = base.join("store");
        fs::create_dir(&root).expect("mkdir");
        chmod(&root, 0o700);
        let store = ImageStore::open(&root).expect("open");
        chmod(&base, 0o777);
        let Err(err) = store.lock() else {
            panic!("must be rejected")
        };
        assert_eq!(err.code(), OciErrorCode::PermissionDenied);
        chmod(&base, 0o700);
        let _ = fs::remove_dir_all(&base);
    }

    /// OCI-7・SEC-1・#2547: create ゲートの入口も root を再検査する。
    #[cfg(unix)]
    #[test]
    fn oci7_sec1_create_gate_rechecks_root_mode() {
        let root = temp_root("recheck-gate");
        let store = ImageStore::open(&root).expect("open");
        chmod(&root, 0o757);
        let Err(err) = store.enter_container_create() else {
            panic!("must be rejected")
        };
        assert_eq!(err.code(), OciErrorCode::PermissionDenied);
        let Err(err) = store.quiesce_container_creates() else {
            panic!("must be rejected")
        };
        assert_eq!(err.code(), OciErrorCode::PermissionDenied);
        chmod(&root, 0o700);
        let _ = fs::remove_dir_all(&root);
    }

    /// OCI-7・SEC-1・#2381: 所有者の判定（chown は root 権限が要るため純関数で照合する）。
    #[cfg(unix)]
    #[test]
    fn oci7_owner_checks_use_effective_uid() {
        use std::os::unix::fs::MetadataExt;
        let root = temp_root("owner");
        let meta = fs::metadata(&root).expect("meta");
        let uid = meta.uid();
        assert!(verify_root_meta(&meta, uid).is_ok());
        assert_eq!(
            verify_root_meta(&meta, uid.wrapping_add(1))
                .expect_err("other owner")
                .code(),
            OciErrorCode::PermissionDenied
        );
        // 祖先は root か実効 uid の所有を受理する。自分の所有は uid 一致で受理、不一致（かつ非 root）は拒否。
        assert!(verify_ancestor_meta(&meta, uid).is_ok());
        if uid != 0 {
            assert_eq!(
                verify_ancestor_meta(&meta, uid.wrapping_add(1))
                    .expect_err("foreign ancestor")
                    .code(),
                OciErrorCode::PermissionDenied
            );
        }
        let _ = fs::remove_dir_all(&root);
    }

    /// OCI-7・SEC-1・#2381: 祖先側の symlink を経由しても、root は正規化したパスで保持する。
    #[cfg(unix)]
    #[test]
    fn oci7_open_stores_canonical_root() {
        let base = temp_root("canon");
        let real = base.join("real");
        fs::create_dir(&real).expect("mkdir");
        chmod(&real, 0o700);
        let store_dir = real.join("store");
        fs::create_dir(&store_dir).expect("mkdir");
        chmod(&store_dir, 0o700);
        std::os::unix::fs::symlink(&real, base.join("link")).expect("symlink");
        let store = ImageStore::open(&base.join("link").join("store")).expect("open");
        assert_eq!(
            store.root(),
            fs::canonicalize(&store_dir).expect("canon").as_path()
        );
        let _ = fs::remove_dir_all(&base);
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
