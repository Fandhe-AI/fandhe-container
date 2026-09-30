//! ファイルベースの `StateStore` 既定実装（TASK-31.1・OCI-5・CRI-7・PLUG-1）。
//!
//! # 役割と呼び出し元
//!
//! [`crate::traits::StateStore`] の core 側既定実装。常駐デーモンを持たない（CORE-1）ため、状態は
//! ファイルシステム上の `state.json` に置き、CLI・supervisor（TASK-157）など別プロセスが同じ
//! ディレクトリを直接読み書きする。`oci_runtime::create` / `start` は `&dyn StateStore` として
//! 本実装を受け取る想定。別実装（分散ストア等）は plugin として差し替えられる（PLUG-1）。
//!
//! # 配置（OCI-5。TASK-31.h1 の確定方針）
//!
//! ```text
//! <root>/                 0700。root 実行は /run/fandhe-container、rootless は
//!                         $XDG_RUNTIME_DIR/fandhe-container（未設定なら fail-closed）
//! ├── @lock               ストア全体の排他用ロックファイル
//! ├── @revision           次に払い出す revision（10 進 ASCII）
//! └── <id>/state.json     ContainerId をそのままパス要素に使う
//! ```
//!
//! メタデータ名は `ContainerId` の許容文字に含まれない `@` で始め、コンテナ ID と衝突させない。
//! 「レコードが存在する」とは `<id>/state.json` が通常ファイルとして存在することを指し、
//! `state.json` のない `<id>/` はクラッシュの残骸として存在しないものと扱う。
//!
//! # 排他・不可分性・信頼境界
//!
//! - 5 メソッドはすべて「プロセス内 `Mutex` → `@lock` の `try_lock`（上限 [`STATE_LOCK_TIMEOUT`]、
//!   超えたら `Timeout`。REPAIR-5）」を取ってから読み書きする
//! - revision は `@revision` のハイウォーターマークから払い出し、レコードより先に書く。
//!   クラッシュしても欠番になるだけで再利用しない。`@revision` は新規ストアの `open` が
//!   `@lock` より先に（hard_link で不可分に）初期化し、後から消えた場合は採番履歴を確認できないためレコードの有無によらず
//!   fail-closed（`Internal`）
//! - 破損レコード（JSON 破損・ociVersion 不正・ID 不一致・状態と PID の矛盾等に加え、`<id>` が
//!   ディレクトリでない・`state.json` が通常ファイルでない等のファイル種別の異常）は revision を
//!   照合できないため通常の `delete` では消せない。管理操作 `find_corrupted` /
//!   `purge_corrupted` で特定・回復する。破損・異常なレコードが 1 件でもあれば `list` はどのページでも
//!   失敗する（fail-closed）
//! - 書き込みは同じディレクトリの一時ファイルへ書いて fsync してから `rename` し、ディレクトリも
//!   fsync する。一時ファイル名の衝突回避・残骸掃除・強制終了テストは TASK-31.2（#156）、結合テストの
//!   拡充は TASK-31.3（#157）で行う
//! - 状態ルートは信頼境界として扱う（`bundle` のすり替えは `start` の起動先のすり替えになるため。
//!   SEC-1・PLUG-12 と同じ姿勢）。symlink・所有者不一致を拒否し、状態ルートと `<id>/` は既存の
//!   ものも 0700 に限る（group / other の権限ビットがあれば `PermissionDenied`）。祖先は group / other
//!   書き込み不可（sticky 付きは許可）を求める
//! - `@lock` は start の起動権の所有ロック（`oci_runtime` の `BundleLock`。bundle ディレクトリの
//!   `flock`。TASK-29.3・CORE-2）とは独立している。start は `BundleLock` を保持したまま `update` を
//!   呼び、`@lock` はその内側で取って解放する。本ストアは `BundleLock` を取らないため、ロック順序の
//!   逆転（デッドロック）は起きない
//! - エラーメッセージは固定の英語文言のみで、パス・errno を含めない
//!
//! # 対応プラットフォーム（Linux 限定。fail-closed）
//!
//! [`FileStateStore::open`] は Linux 以外では何も作らずに `Unimplemented` を返す。信頼境界の検査
//! （所有者 = 実効 UID・権限ビット）は Linux でしか完結しないため（Windows の ACL・所有者 SID の
//! 検査と保護 DACL での作成、macOS の実効 UID の取得には `sys` の FFI が要るが、`sys` は Linux 限定）。
//! macOS / Windows では状態ルートをゲスト VM 内の Linux パスに置く（OCI-5）ため、ホスト側で本実装を
//! 使う経路はない。start の所有ロック（`BundleLock::acquire`）が Linux 以外で `Unimplemented` を返すのと
//! 同じ扱いである（CLI-1）

use std::collections::BinaryHeap;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::traits::{
    ContainerId, ContainerStatus, CreateStateRequest, DeleteStateRequest, DeleteStateResponse,
    ErrorCode, GetStateRequest, ListStateRequest, StateList, StateListCursor, StateRecord,
    StateRevision, StateStore, TraitError, UpdateStateRequest,
};

/// 各コンテナの状態ファイル名（OCI-5）。
pub const STATE_FILE_NAME: &str = "state.json";

/// `state.json` として読み込む最大バイト数（無制限なメモリ確保の防止）。
pub const MAX_STATE_FILE_BYTES: u64 = 64 * 1024;

/// `bundle` の絶対パスとして受け付ける最大バイト数（Linux の `PATH_MAX`。TASK-31.1・OCI-5）。
///
/// シリアライズ前に検証し、`state.json` が [`MAX_STATE_FILE_BYTES`] を超えて書けても読めない
/// レコードになることを防ぐ（無制限確保の防止）。
pub const MAX_BUNDLE_PATH_BYTES: usize = 4096;

/// ファイルロックを待つ上限時間（REPAIR-5: 相手を無期限に待たない）。
pub const STATE_LOCK_TIMEOUT: Duration = Duration::from_secs(5);

/// ロック再試行の間隔。
const LOCK_RETRY_INTERVAL: Duration = Duration::from_millis(5);

/// `state.json` に書く OCI Runtime Spec のバージョン。
const OCI_VERSION: &str = "1.2.0";

/// `find_corrupted` が返す最大件数（無制限確保の防止）。
pub const MAX_CORRUPTED_REPORT: usize = 256;

const LOCK_FILE: &str = "@lock";
const REVISION_FILE: &str = "@revision";
/// `@revision` の初期化途中の一時ファイル名の接頭辞（新規ストア判定で無視する）。
const REVISION_INIT_PREFIX: &str = "@revision.init-";
/// `@revision` として読み込む最大バイト数（u64 の 10 進表現は 20 桁）。
const MAX_REVISION_FILE_BYTES: u64 = 32;

fn err(code: ErrorCode, msg: &'static str) -> TraitError {
    TraitError::new(code, msg)
}

fn internal(msg: &'static str) -> TraitError {
    err(ErrorCode::Internal, msg)
}

/// 検証済みの状態ルート（絶対パス）。
///
/// 既定値の解決規則は OCI-5（TASK-31.h1）に従う。呼び出し元は CLI の `--root` 相当の指定を
/// `resolve` へ渡す。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateRoot(PathBuf);

impl StateRoot {
    /// 明示指定（`--root` 相当）から作る。絶対パスでなければ `InvalidArgument`。
    pub fn from_override(path: PathBuf) -> Result<Self, TraitError> {
        if !path.is_absolute() {
            return Err(err(
                ErrorCode::InvalidArgument,
                "state root must be an absolute path",
            ));
        }
        Ok(Self(path))
    }

    /// 上書き指定があればそれを、なければ既定（root: `/run/fandhe-container`、rootless:
    /// `$XDG_RUNTIME_DIR/fandhe-container`）を使う。
    ///
    /// 既定の解決は Linux のみ（macOS / Windows ではゲスト VM 内の Linux パスとして同じ規則を
    /// 使う。OCI-5）。Linux 以外で上書き指定がなければ `Unimplemented`（fail-closed）。
    pub fn resolve(override_root: Option<PathBuf>) -> Result<Self, TraitError> {
        if let Some(path) = override_root {
            return Self::from_override(path);
        }
        #[cfg(target_os = "linux")]
        {
            let is_root = crate::sys::effective_uid() == 0;
            let xdg = std::env::var_os("XDG_RUNTIME_DIR");
            resolve_default(is_root, xdg).map(Self)
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(err(
                ErrorCode::Unimplemented,
                "default state root is defined only inside a Linux guest",
            ))
        }
    }

    /// 状態ルートのパスを返す。
    pub fn path(&self) -> &Path {
        &self.0
    }
}

/// 既定の状態ルートを OS 状態に依存せず決める純粋関数（3 OS でテストできるよう分離）。
///
/// `XDG_RUNTIME_DIR` が未設定・空・相対パスの rootless は `/tmp` 等へ落とさず
/// `FailedPrecondition` にする（fail-closed。ERR-2）。
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn resolve_default(
    is_root: bool,
    xdg_runtime_dir: Option<OsString>,
) -> Result<PathBuf, TraitError> {
    if is_root {
        return Ok(PathBuf::from("/run/fandhe-container"));
    }
    match xdg_runtime_dir.map(PathBuf::from) {
        Some(dir) if dir.is_absolute() => Ok(dir.join("fandhe-container")),
        _ => Err(err(
            ErrorCode::FailedPrecondition,
            "XDG_RUNTIME_DIR must be set to an absolute path for rootless state",
        )),
    }
}

/// `<id>/state.json` の検査結果（内容の破損と、権限・I/O エラーを区別する）。
enum RecordHealth {
    /// レコードがない（残骸ディレクトリのみも含む）。
    Absent,
    /// 読めて内容も整合している。
    Healthy(StateRecord),
    /// 内容が使えない（JSON 破損・サイズ超過・ociVersion 不正・ID 不一致・状態と PID の矛盾）、
    /// またはファイル種別が異常（`<id>` がディレクトリでない・`state.json` が通常ファイルでない）。
    Corrupted(TraitError),
}

/// `list` の有界選択用に、レコードを ID の辞書順で比較するラッパー（同じルート内で ID は一意）。
struct ById(StateRecord);

impl PartialEq for ById {
    fn eq(&self, other: &Self) -> bool {
        self.0.id() == other.0.id()
    }
}

impl Eq for ById {}

impl PartialOrd for ById {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ById {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.id().as_str().cmp(other.0.id().as_str())
    }
}

/// `<id>/state.json` の場所の検査結果（`record_file`）。
enum RecordEntry {
    /// レコードがない（`<id>` がない、または残骸ディレクトリのみ）。
    Absent,
    /// `state.json` が通常ファイルとして存在する。
    File(PathBuf),
    /// ファイル種別の異常（`<id>` がディレクトリでない・`state.json` が通常ファイルでない）。
    /// 保持するエラーは get・list が返すもの。
    Malformed(TraitError),
}

/// ファイルベースの [`StateStore`] 実装。
#[derive(Debug)]
pub struct FileStateStore {
    root: PathBuf,
    /// プロセス内の排他と、その下で読み書きするインスタンス固有の状態。プロセス間は `@lock` の
    /// ファイルロックが担う。
    process_lock: Mutex<LockedState>,
}

/// プロセス内ミューテックスで守る、インスタンス固有の状態。
#[derive(Debug, Default)]
struct LockedState {
    /// `@revision` として受け入れる最小値（巻き戻り検出の下限）。`None` は未確定で、次の採番で
    /// 全レコードを走査して確定する。以降は払い出しのたびに引き上げる（`allocate_revision`）。
    revision_floor: Option<u64>,
}

/// ロックの RAII ガード。drop でファイルロックとミューテックスが解放される。
struct StoreGuard<'a> {
    process: MutexGuard<'a, LockedState>,
    _file: File,
}

impl FileStateStore {
    /// 状態ルートを用意して検証する。
    ///
    /// ルートがなければ 0700 で作る。親ディレクトリは作らない（`/run` や
    /// `$XDG_RUNTIME_DIR` がなければ `NotFound`）。symlink・ディレクトリでないもの・
    /// 他ユーザー所有・group / other に権限ビットのある（0700 でない）ルートは `PermissionDenied`。
    /// Linux 以外では何も作らずに `Unimplemented`（信頼境界を検査できないため。fail-closed。
    /// モジュール doc「対応プラットフォーム」）。
    pub fn open(root: StateRoot) -> Result<Self, TraitError> {
        // 副作用（ルートの作成）より前に拒否する。
        ensure_supported_platform()?;
        let path = root.0;
        match private_dir_builder().create(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(err(
                    ErrorCode::NotFound,
                    "parent of the state root does not exist",
                ));
            }
            Err(_) => return Err(internal("failed to create the state root")),
        }
        verify_root(&path)?;
        // 親パスの symlink を一度だけ解決して固定し、以降はその正規パスで操作する。
        // 祖先ディレクトリの書き込み権限も検査する（親すり替え対策。詳細は verify_ancestors）。
        let root = canonical_root(&path)?;
        verify_ancestors(&root)?;
        // 新規ストア（初期化途中の残骸 `@revision.init-*` 以外のエントリがない）だけ `@revision` を
        // 初期化する。`@lock` を作る前に `@revision` を確定させるため、初期化の途中失敗で
        // `@lock` だけが残って「空でない・高水位マークなし」の永久 fail-closed になることはない。
        // `@revision` が後から失われた場合は採番履歴を確認できないため、`allocate_revision` が
        // fail-closed にする（revision 再発行の防止。OCI-5）。
        let mut fresh = true;
        for entry in fs::read_dir(&root).map_err(|_| internal("failed to read the state root"))? {
            let entry = entry.map_err(|_| internal("failed to read the state root"))?;
            if !entry
                .file_name()
                .to_str()
                .is_some_and(|n| n.starts_with(REVISION_INIT_PREFIX))
            {
                fresh = false;
                break;
            }
        }
        if fresh {
            init_revision_file(&root)?;
        }
        Ok(Self {
            root,
            process_lock: Mutex::new(LockedState::default()),
        })
    }

    fn lock(&self) -> Result<StoreGuard<'_>, TraitError> {
        let deadline = Instant::now() + STATE_LOCK_TIMEOUT;
        // プロセス内ミューテックスも有限時間で打ち切る（REPAIR-5）。毒化は状態がファイル側に
        // あるため無視して続行する。
        let process = loop {
            match self.process_lock.try_lock() {
                Ok(g) => break g,
                Err(std::sync::TryLockError::Poisoned(e)) => break e.into_inner(),
                Err(std::sync::TryLockError::WouldBlock) => {
                    if Instant::now() >= deadline {
                        return Err(err(
                            ErrorCode::Timeout,
                            "timed out waiting for the state lock",
                        ));
                    }
                    std::thread::sleep(LOCK_RETRY_INTERVAL);
                }
            }
        };
        let path = self.root.join(LOCK_FILE);
        reject_symlink(&path)?;
        let mut opts = OpenOptions::new();
        opts.create(true).truncate(false).write(true);
        // state.json・@revision と同じ 0600 で作る（他ユーザーによるロック占有 DoS の防止）。
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let file = opts
            .open(&path)
            .map_err(|_| internal("failed to open the state lock file"))?;
        loop {
            match file.try_lock() {
                Ok(()) => {
                    return Ok(StoreGuard {
                        process,
                        _file: file,
                    });
                }
                Err(std::fs::TryLockError::WouldBlock) => {
                    if Instant::now() >= deadline {
                        return Err(err(
                            ErrorCode::Timeout,
                            "timed out waiting for the state lock",
                        ));
                    }
                    std::thread::sleep(LOCK_RETRY_INTERVAL);
                }
                Err(std::fs::TryLockError::Error(_)) => {
                    return Err(internal("failed to lock the state store"));
                }
            }
        }
    }

    fn record_dir(&self, id: &ContainerId) -> PathBuf {
        self.root.join(id.as_str())
    }

    /// `<id>/state.json` の場所をファイル種別で検査する（symlink は辿らない）。
    ///
    /// `<id>` がディレクトリでない（symlink・通常ファイル等）・`state.json` が通常ファイルでない
    /// （symlink・ディレクトリ等）は `Malformed`（get・list は失敗し、回復操作で消せる）。
    /// `<id>` の権限不備・所有者不一致と、検査自体の I/O エラーは `Err`（回復操作でも消さない。
    /// fail-closed）。
    fn record_file(&self, id: &ContainerId) -> Result<RecordEntry, TraitError> {
        let dir = self.record_dir(id);
        match fs::symlink_metadata(&dir) {
            Ok(m) if m.is_dir() => verify_record_dir(&m)?,
            Ok(_) => {
                return Ok(RecordEntry::Malformed(err(
                    ErrorCode::PermissionDenied,
                    "state entry is not a directory",
                )));
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(RecordEntry::Absent),
            Err(_) => return Err(internal("failed to inspect the state directory")),
        }
        let file_path = dir.join(STATE_FILE_NAME);
        match fs::symlink_metadata(&file_path) {
            Ok(m) if m.is_file() => Ok(RecordEntry::File(file_path)),
            Ok(_) => Ok(RecordEntry::Malformed(internal(
                "state file is not a regular file",
            ))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(RecordEntry::Absent),
            Err(_) => Err(internal("failed to inspect the state file")),
        }
    }

    /// レコードを検査する。内容の不整合（JSON 破損・サイズ超過・ociVersion 不正・ID 不一致・
    /// 状態と PID の矛盾等）とファイル種別の異常（`record_file` の `Malformed`）は `Corrupted`、
    /// 権限・I/O 等の失敗は `Err`（破損とは区別する。権限・I/O エラーのレコードを回復操作で
    /// 消さないため）。
    fn inspect_record(&self, id: &ContainerId) -> Result<RecordHealth, TraitError> {
        let file_path = match self.record_file(id)? {
            RecordEntry::Absent => return Ok(RecordHealth::Absent),
            RecordEntry::Malformed(e) => return Ok(RecordHealth::Corrupted(e)),
            RecordEntry::File(path) => path,
        };
        let Some(bytes) = read_limited(&file_path, MAX_STATE_FILE_BYTES)? else {
            return Ok(RecordHealth::Corrupted(internal(
                "state file exceeds the size limit",
            )));
        };
        let Ok(dto) = serde_json::from_slice::<StateDto>(&bytes) else {
            return Ok(RecordHealth::Corrupted(internal("state file is corrupted")));
        };
        match dto.into_record(id) {
            Ok(record) => Ok(RecordHealth::Healthy(record)),
            Err(e) => Ok(RecordHealth::Corrupted(e)),
        }
    }

    /// `<id>/state.json` を読む。存在しなければ `None`。内容が破損していれば `Internal`。
    fn read_record(&self, id: &ContainerId) -> Result<Option<StateRecord>, TraitError> {
        match self.inspect_record(id)? {
            RecordHealth::Absent => Ok(None),
            RecordHealth::Healthy(record) => Ok(Some(record)),
            RecordHealth::Corrupted(e) => Err(e),
        }
    }

    /// `<id>/state.json` を削除し、空になれば `<id>/` も削除する（ロック保持下で呼ぶこと）。
    ///
    /// ファイル種別の異常（`record_file` の `Malformed`。`purge_corrupted` からのみ到達）も消せる。
    /// symlink はリンク自体を消し、リンク先は辿らない。`<id>` がディレクトリでなければ `<id>` の
    /// エントリだけを消し、`state.json` がディレクトリなら `remove_dir_all`（std の実装は symlink を
    /// 辿らない）で消す。いずれも 0700・所有者検査済みの状態ルート配下のエントリに限る。
    fn remove_record(&self, id: &ContainerId) -> Result<(), TraitError> {
        let dir = self.record_dir(id);
        let dir_meta = fs::symlink_metadata(&dir)
            .map_err(|_| internal("failed to inspect the state directory"))?;
        if !dir_meta.is_dir() {
            fs::remove_file(&dir).map_err(|_| internal("failed to remove the state entry"))?;
            return sync_dir(&self.root);
        }
        let file = dir.join(STATE_FILE_NAME);
        let file_is_dir = fs::symlink_metadata(&file)
            .map_err(|_| internal("failed to inspect the state file"))?
            .is_dir();
        let removed = if file_is_dir {
            fs::remove_dir_all(&file)
        } else {
            fs::remove_file(&file)
        };
        removed.map_err(|_| internal("failed to remove the state file"))?;
        // 削除（unlink）の永続化のため <id>/ を fsync する。ディレクトリ自体を消した場合は
        // その dirent の消失を永続化するため状態ルートも fsync する。
        sync_dir(&dir)?;
        match fs::remove_dir(&dir) {
            Ok(()) => sync_dir(&self.root)?,
            // 他の部品（PLUG-12 の UDS 等）がファイルを置いている場合は残す。レコードの
            // 有無は state.json で判定するため整合する。
            Err(e) if e.kind() == std::io::ErrorKind::DirectoryNotEmpty => {}
            Err(_) => return Err(internal("failed to remove the state directory")),
        }
        Ok(())
    }

    /// 内容が破損しているレコードの ID を返す（管理操作。最大 [`MAX_CORRUPTED_REPORT`] 件）。
    ///
    /// 破損レコードが 1 件でもあると `list` は（どのページでも）fail-closed で失敗するため、
    /// 回復対象の特定に使う。回復は [`FileStateStore::purge_corrupted`]（OCI-5）。上限を超える
    /// 場合は走査順で打ち切るため、回復後に再度呼んで残りを得る。
    pub fn find_corrupted(&self) -> Result<Vec<ContainerId>, TraitError> {
        let _guard = self.lock()?;
        let entries =
            fs::read_dir(&self.root).map_err(|_| internal("failed to read the state root"))?;
        let mut found = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|_| internal("failed to read the state root"))?;
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            let Ok(id) = ContainerId::new(&name) else {
                continue;
            };
            // 権限・I/O エラーのエントリは破損として列挙せず、エラーで返す（fail-closed）。
            if matches!(self.inspect_record(&id)?, RecordHealth::Corrupted(_)) {
                found.push(id);
                if found.len() >= MAX_CORRUPTED_REPORT {
                    break;
                }
            }
        }
        found.sort_by(|a, b| a.as_str().cmp(b.as_str()));
        Ok(found)
    }

    /// 内容が破損した、またはファイル種別が異常なレコードを削除して回復する管理操作（OCI-5）。
    ///
    /// 破損レコードは revision を検証できないため、楽観的排他を持つ通常の
    /// `StateStore::delete` とは分離している。健全なレコードには使えず
    /// （`FailedPrecondition`）、存在しなければ `NotFound`。権限不備（`<id>` の 0700 以外・所有者
    /// 不一致）や I/O エラーで検査できないものは削除せず元のエラーを返す（fail-closed）。
    /// symlink はリンク自体だけを消す（`remove_record`）。
    pub fn purge_corrupted(&self, id: &ContainerId) -> Result<DeleteStateResponse, TraitError> {
        let _guard = self.lock()?;
        match self.inspect_record(id)? {
            RecordHealth::Healthy(_) => {
                return Err(err(
                    ErrorCode::FailedPrecondition,
                    "state record is not corrupted",
                ));
            }
            RecordHealth::Absent => {
                return Err(err(ErrorCode::NotFound, "container state not found"));
            }
            RecordHealth::Corrupted(_) => {}
        }
        self.remove_record(id)?;
        Ok(DeleteStateResponse::new())
    }

    fn write_record(&self, record: &StateRecord) -> Result<(), TraitError> {
        let dto = StateDto::from_record(record)?;
        let bytes =
            serde_json::to_vec(&dto).map_err(|_| internal("failed to serialize the state"))?;
        if bytes.len() as u64 > MAX_STATE_FILE_BYTES {
            return Err(err(
                ErrorCode::InvalidArgument,
                "state file exceeds the size limit",
            ));
        }
        write_file_replacing(&self.record_dir(record.id()), STATE_FILE_NAME, &bytes)
    }

    /// revision を 1 つ払い出し、上限値を先に永続化する（`guard` はこのストアのロック）。
    ///
    /// `existing` は更新対象の既存レコード。ハイウォーターマークがその revision 以下なら
    /// （巻き戻り等で `@revision` が古い）revision の再発行になるため fail-closed
    /// （`Internal`）にする。`@revision` はレコードより先に fsync 済みで置き換える
    /// （`write_file_replacing`）ため、クラッシュでは巻き戻らない。
    ///
    /// ストア全体の巻き戻り検出（全レコードの revision が `@revision` 未満であること）は、
    /// インスタンスごとの初回の採番でだけ全レコードを走査して下限（`revision_floor`）を確定し、
    /// 以降は下限との比較で行う（採番ごとの全件走査で連続作成が O(N²) になり、ロック保持時間が
    /// 伸びるのを避ける）。下限は自インスタンスが払い出した値で引き上げる。他インスタンスが
    /// 進めた範囲への巻き戻り（状態ルートの所有者による外部改変でしか起きない）は、次に開いた
    /// インスタンスの初回走査と、更新対象レコードとの比較（`existing`）で検出する。
    fn allocate_revision(
        &self,
        guard: &mut StoreGuard<'_>,
        existing: Option<&StateRecord>,
    ) -> Result<StateRevision, TraitError> {
        let path = self.root.join(REVISION_FILE);
        let current = match fs::symlink_metadata(&path) {
            Ok(m) if m.is_file() => {
                let bytes = read_limited(&path, MAX_REVISION_FILE_BYTES)?
                    .ok_or_else(|| internal("revision file is corrupted"))?;
                let text = std::str::from_utf8(&bytes)
                    .map_err(|_| internal("revision file is corrupted"))?;
                let value: u64 = text
                    .trim()
                    .parse()
                    .map_err(|_| internal("revision file is corrupted"))?;
                StateRevision::from_raw(value)
            }
            Ok(_) => return Err(internal("revision file is not a regular file")),
            // 新規ストアの `@revision` は `open` が初期化する。ここで無ければ採番履歴が
            // 失われているため、レコードの有無によらず fail-closed（過去の revision の
            // 再発行を防ぐ）。
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(internal("revision high-water mark is missing"));
            }
            Err(_) => return Err(internal("failed to inspect the revision file")),
        };
        if let Some(rec) = existing
            && rec.revision().value() >= current.value()
        {
            return Err(internal("revision high-water mark is behind the record"));
        }
        // ストア全体で単調採番する契約のため、更新・新規作成を問わず `@revision` が下限
        // （全レコードの revision の最大値 + 1 と、自インスタンスが払い出した値）以上であることを
        // 確認する（`@revision` の巻き戻りで使用済み revision を別コンテナへ払い出さない。fail-closed）。
        let floor = match guard.process.revision_floor {
            Some(floor) => floor,
            None => {
                let floor = match self.max_record_revision()? {
                    Some(max) => max
                        .checked_add(1)
                        .ok_or_else(|| internal("state revision overflowed"))?,
                    None => StateRevision::INITIAL.value(),
                };
                guard.process.revision_floor = Some(floor);
                floor
            }
        };
        if current.value() < floor {
            return Err(internal("revision high-water mark is behind the records"));
        }
        let next = current.next()?;
        write_file_replacing(
            &self.root,
            REVISION_FILE,
            next.value().to_string().as_bytes(),
        )?;
        guard.process.revision_floor = Some(next.value());
        Ok(current)
    }

    /// 全レコードの revision の最大値（レコードが無ければ `None`）。ロック保持下で呼ぶこと。
    fn max_record_revision(&self) -> Result<Option<u64>, TraitError> {
        let entries =
            fs::read_dir(&self.root).map_err(|_| internal("failed to read the state root"))?;
        let mut max: Option<u64> = None;
        for entry in entries {
            let entry = entry.map_err(|_| internal("failed to read the state root"))?;
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            let Ok(id) = ContainerId::new(&name) else {
                continue;
            };
            // 読めないレコード（緩んだ権限・破損 state.json）は revision を採れないため走査から
            // 除外する。1 件の問題レコードが他コンテナの create / update を止めないようにし
            // （可用性）、単調性は `@revision` のハイウォーターマークで担保する。問題レコード
            // 自体は get / list / delete 側で検出・回復する。
            if let Ok(Some(rec)) = self.read_record(&id) {
                let v = rec.revision().value();
                max = Some(max.map_or(v, |m| m.max(v)));
            }
        }
        Ok(max)
    }
}

impl StateStore for FileStateStore {
    fn create(&self, req: &CreateStateRequest) -> Result<StateRecord, TraitError> {
        check_bundle_len(req.bundle())?;
        let mut guard = self.lock()?;
        if self.read_record(req.id())?.is_some() {
            return Err(err(
                ErrorCode::AlreadyExists,
                "container state already exists",
            ));
        }
        let dir = self.record_dir(req.id());
        match private_dir_builder().create(&dir) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                // 残骸ディレクトリの再利用。symlink などは read_record が拒否済みだが、
                // 種別を再確認してから書く（多重防御）。
                match fs::symlink_metadata(&dir) {
                    Ok(m) if m.is_dir() => verify_record_dir(&m)?,
                    _ => {
                        return Err(err(
                            ErrorCode::PermissionDenied,
                            "state entry is not a directory",
                        ));
                    }
                }
            }
            Err(_) => return Err(internal("failed to create the state directory")),
        }
        let revision = self.allocate_revision(&mut guard, None)?;
        let record = StateRecord::new(req.status().clone(), req.bundle().to_path_buf(), revision)?;
        self.write_record(&record)?;
        Ok(record)
    }

    fn update(&self, req: &UpdateStateRequest) -> Result<StateRecord, TraitError> {
        let mut guard = self.lock()?;
        let existing = self
            .read_record(req.id())?
            .ok_or_else(|| err(ErrorCode::NotFound, "container state not found"))?;
        if existing.revision() != req.expected_revision() {
            return Err(err(
                ErrorCode::FailedPrecondition,
                "state revision does not match",
            ));
        }
        let revision = self.allocate_revision(&mut guard, Some(&existing))?;
        let record = StateRecord::new(
            req.status().clone(),
            existing.bundle().to_path_buf(),
            revision,
        )?;
        self.write_record(&record)?;
        Ok(record)
    }

    fn get(&self, req: &GetStateRequest) -> Result<StateRecord, TraitError> {
        let _guard = self.lock()?;
        self.read_record(req.id())?
            .ok_or_else(|| err(ErrorCode::NotFound, "container state not found"))
    }

    /// カーソルは「この ID より後」を表すキーセット方式。ページの間にカーソルの ID が
    /// 削除されても一覧が壊れないよう、その ID の存在は確認しない。
    ///
    /// fail-closed（OCI-5）: ページの内外・カーソルの前後を問わず、ストア内に異常なエントリ
    /// （symlink 化・権限不備・`state.json` が通常ファイルでない）や内容が破損したレコードが 1 件でも
    /// あれば、ページを返さず `get` と同じエラーを返す（回復は [`FileStateStore::find_corrupted`] /
    /// [`FileStateStore::purge_corrupted`]）。そのため全レコードを読んで検証するが、保持するのは
    /// page + 1 件に限る（ストア全体の件数に比例したメモリを確保しない）。
    fn list(&self, req: &ListStateRequest) -> Result<StateList, TraitError> {
        let after = match req.cursor() {
            Some(c) => Some(ContainerId::new(c.as_str())?),
            None => None,
        };
        let _guard = self.lock()?;
        let page = req.page_size().get() as usize;
        let mut smallest: BinaryHeap<ById> = BinaryHeap::with_capacity(page.saturating_add(1));
        let entries =
            fs::read_dir(&self.root).map_err(|_| internal("failed to read the state root"))?;
        for entry in entries {
            let entry = entry.map_err(|_| internal("failed to read the state root"))?;
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            let Ok(id) = ContainerId::new(name.as_str()) else {
                continue;
            };
            // 内容まで検証してから（カーソルより前のレコードも含む）ページ対象かを判定する。
            let Some(record) = self.read_record(&id)? else {
                continue;
            };
            if let Some(a) = &after
                && id.as_str() <= a.as_str()
            {
                continue;
            }
            smallest.push(ById(record));
            if smallest.len() > page.saturating_add(1) {
                smallest.pop();
            }
        }
        let mut selected: Vec<ById> = smallest.into_vec();
        selected.sort();
        // 上の有界選択は「小さい方から page + 1 件」を残すため、超過分は最後の 1 件。
        let has_more = selected.len() > page;
        selected.truncate(page);
        let records: Vec<StateRecord> = selected.into_iter().map(|r| r.0).collect();
        let next_cursor = match (has_more, records.last()) {
            (true, Some(l)) => Some(StateListCursor::from_raw(l.id().as_str().to_owned())?),
            _ => None,
        };
        Ok(StateList::new(records, next_cursor))
    }

    /// 楽観的排他付きの削除。revision を照合できない破損レコードは削除せず元のエラーを返す
    /// （回復は管理操作 [`FileStateStore::purge_corrupted`]）。
    fn delete(&self, req: &DeleteStateRequest) -> Result<DeleteStateResponse, TraitError> {
        let _guard = self.lock()?;
        let existing = self
            .read_record(req.id())?
            .ok_or_else(|| err(ErrorCode::NotFound, "container state not found"))?;
        if existing.revision() != req.expected_revision() {
            return Err(err(
                ErrorCode::FailedPrecondition,
                "state revision does not match",
            ));
        }
        self.remove_record(req.id())?;
        Ok(DeleteStateResponse::new())
    }
}

/// 本実装を使えるプラットフォームか確かめる（Linux のみ。モジュール doc「対応プラットフォーム」）。
///
/// `open` の先頭で呼ぶ。実行時の `?` で拒否するため、以降のコードは 3 OS でコンパイル・型検査される。
#[cfg(target_os = "linux")]
fn ensure_supported_platform() -> Result<(), TraitError> {
    Ok(())
}

/// Linux 以外では状態ルートの信頼境界（所有者・ACL）を検査できないため拒否する（fail-closed）。
#[cfg(not(target_os = "linux"))]
fn ensure_supported_platform() -> Result<(), TraitError> {
    Err(err(
        ErrorCode::Unimplemented,
        "file state store requires Linux to verify the state root",
    ))
}

/// 0700（unix）でディレクトリを作る builder。`let mut` が OS ごとに不要になる警告を避けるため
/// 関数に切り出している。
fn private_dir_builder() -> fs::DirBuilder {
    #[cfg_attr(not(unix), allow(unused_mut))]
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
}

/// 最終要素を除く親パスを正規化して結合し直す（最終要素は symlink でないこと検査済み）。
fn canonical_root(path: &Path) -> Result<PathBuf, TraitError> {
    let (Some(parent), Some(name)) = (path.parent(), path.file_name()) else {
        return Err(err(
            ErrorCode::InvalidArgument,
            "state root must have a parent directory",
        ));
    };
    let parent = fs::canonicalize(parent)
        .map_err(|_| internal("failed to resolve the state root parent"))?;
    Ok(parent.join(name))
}

/// 祖先ディレクトリが第三者にすり替えられないか検査する。
///
/// 各祖先は、group / other 書き込み不可（sticky ビット付きは許可。`/tmp` 等）であり、
/// root か現在のユーザーの所有でなければ `PermissionDenied`。Linux 以外は `open` が先に拒否する
/// ため本検査に到達しない（`#[cfg(unix)]` の枝は macOS でも型検査のためにコンパイルされる）。
///
/// 制約（未実装。REPAIR-3）: 検査と使用の間の TOCTOU を閉じるには、ディレクトリ fd を基点に
/// `openat` 系で操作する必要がある。std には無く `sys` の unsafe ラッパーが要るため、
/// 別タスクで扱う。現状は「正規パスの固定＋祖先の権限検査」による緩和にとどまる。
fn verify_ancestors(root: &Path) -> Result<(), TraitError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        for ancestor in root.ancestors().skip(1) {
            let meta = fs::metadata(ancestor)
                .map_err(|_| internal("failed to inspect an ancestor of the state root"))?;
            let mode = meta.mode();
            if mode & 0o022 != 0 && mode & 0o1000 == 0 {
                return Err(err(
                    ErrorCode::PermissionDenied,
                    "ancestor of the state root must not be writable by group or others",
                ));
            }
            #[cfg(target_os = "linux")]
            if meta.uid() != 0 && meta.uid() != crate::sys::effective_uid() {
                return Err(err(
                    ErrorCode::PermissionDenied,
                    "ancestor of the state root must be owned by root or the current user",
                ));
            }
        }
    }
    #[cfg(not(unix))]
    let _ = root;
    Ok(())
}

/// 状態ルートが信頼できるか検査する（symlink・種別・所有者・権限ビット）。
///
/// 既存のルートも新規作成時と同じ 0700 に限る（group / other の権限ビットが 1 つでもあれば拒否）。
/// 読み取り・実行ビットだけでも、他ユーザーがコンテナ ID を列挙できてしまうため（OCI-5 の配置）。
fn verify_root(path: &Path) -> Result<(), TraitError> {
    let meta =
        fs::symlink_metadata(path).map_err(|_| internal("failed to inspect the state root"))?;
    if meta.file_type().is_symlink() || !meta.is_dir() {
        return Err(err(
            ErrorCode::PermissionDenied,
            "state root must be a directory and not a symlink",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if meta.mode() & 0o077 != 0 {
            return Err(err(
                ErrorCode::PermissionDenied,
                "state root must not be accessible by group or others",
            ));
        }
        // 所有者検査は euid を取れる Linux のみ。他 OS は `open` が先に拒否する。
        #[cfg(target_os = "linux")]
        if meta.uid() != crate::sys::effective_uid() {
            return Err(err(
                ErrorCode::PermissionDenied,
                "state root must be owned by the current user",
            ));
        }
    }
    Ok(())
}

/// レコードディレクトリ `<id>/` が第三者に改変されないか検査する。
///
/// group / other の権限ビットが 1 つでもあれば（0700 限定）、または所有者が現在のユーザーで
/// なければ `PermissionDenied`（残存ディレクトリの再利用・読み取り前に呼ぶ。`state.json` 改変・
/// bundle すり替えの防止。OCI-5）。Linux 以外は `open` が先に拒否するため本検査に到達しない。
fn verify_record_dir(meta: &fs::Metadata) -> Result<(), TraitError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if meta.mode() & 0o077 != 0 {
            return Err(err(
                ErrorCode::PermissionDenied,
                "state directory must not be accessible by group or others",
            ));
        }
        #[cfg(target_os = "linux")]
        if meta.uid() != crate::sys::effective_uid() {
            return Err(err(
                ErrorCode::PermissionDenied,
                "state directory must be owned by the current user",
            ));
        }
    }
    #[cfg(not(unix))]
    let _ = meta;
    Ok(())
}

fn reject_symlink(path: &Path) -> Result<(), TraitError> {
    match fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_symlink() => Err(err(
            ErrorCode::PermissionDenied,
            "state entry must not be a symlink",
        )),
        _ => Ok(()),
    }
}

/// `bundle` のバイト長を上限検証する（シリアライズ前。UTF-8 でなければ別途拒否される）。
fn check_bundle_len(bundle: &Path) -> Result<(), TraitError> {
    if bundle.as_os_str().len() > MAX_BUNDLE_PATH_BYTES {
        return Err(err(
            ErrorCode::InvalidArgument,
            "bundle path exceeds the length limit",
        ));
    }
    Ok(())
}

/// 通常ファイルを上限つきで読む。上限を超えたら `Ok(None)`（無制限確保の防止）。
/// 開く・読むの失敗（権限・I/O）は `Err`（内容の問題とは区別する）。
fn read_limited(path: &Path, max: u64) -> Result<Option<Vec<u8>>, TraitError> {
    let file = File::open(path).map_err(|_| internal("failed to open the state file"))?;
    let mut buf = Vec::new();
    file.take(max.saturating_add(1))
        .read_to_end(&mut buf)
        .map_err(|_| internal("failed to read the state file"))?;
    if buf.len() as u64 > max {
        return Ok(None);
    }
    Ok(Some(buf))
}

/// `@revision` を初期値で新規作成する（既にあれば何もしない）。
///
/// 一時ファイルへ内容を書いて fsync し、`hard_link` で `@revision` として公開する。
/// `hard_link` は既存の宛先を上書きしないため、複数プロセスの同時 `open` が競合しても
/// 先に作った側の内容が残り、途中まで書かれた `@revision` が現れることもない。
fn init_revision_file(root: &Path) -> Result<(), TraitError> {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let tmp = root.join(format!(
        "{REVISION_INIT_PREFIX}{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    let dest = root.join(REVISION_FILE);
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts
        .open(&tmp)
        .map_err(|_| internal("failed to create the revision file"))?;
    let written = file
        .write_all(StateRevision::INITIAL.value().to_string().as_bytes())
        .and_then(|()| file.sync_all());
    drop(file);
    let linked = match written {
        Ok(()) => match fs::hard_link(&tmp, &dest) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
            Err(_) => Err(internal("failed to publish the revision file")),
        },
        Err(_) => Err(internal("failed to write the revision file")),
    };
    let _ = fs::remove_file(&tmp);
    linked?;
    sync_dir(root)
}

/// 同じディレクトリの `<name>.tmp` へ書いて `rename` する（トレイト契約 4 の不可分な書き込み）。
///
/// 全書き込みの唯一の経路。一時ファイルを `sync_all` してから `rename` し、unix では親
/// ディレクトリも fsync して置き換えを永続化する（クラッシュ後の revision 再発行防止）。
/// 一時ファイル名の衝突回避と残骸掃除は TASK-31.2（#156）で強化する予定で、現状は未実装
/// （REPAIR-3）。
fn write_file_replacing(dir: &Path, name: &str, bytes: &[u8]) -> Result<(), TraitError> {
    let tmp = dir.join(format!("{name}.tmp"));
    let dest = dir.join(name);
    match fs::remove_file(&tmp) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(internal("failed to prepare the temporary file")),
    }
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts
        .open(&tmp)
        .map_err(|_| internal("failed to create the temporary file"))?;
    file.write_all(bytes)
        .map_err(|_| internal("failed to write the temporary file"))?;
    file.sync_all()
        .map_err(|_| internal("failed to sync the temporary file"))?;
    drop(file);
    reject_symlink(&dest)?;
    fs::rename(&tmp, &dest).map_err(|_| internal("failed to replace the state file"))?;
    sync_dir(dir)
}

/// ディレクトリを fsync して dirent の変更（作成・rename・unlink）を永続化する。
/// Linux 以外は `open` が先に拒否するため、非 unix の枝は型検査のためだけに残す。
fn sync_dir(dir: &Path) -> Result<(), TraitError> {
    #[cfg(unix)]
    File::open(dir)
        .and_then(|d| d.sync_all())
        .map_err(|_| internal("failed to sync the state directory"))?;
    #[cfg(not(unix))]
    let _ = dir;
    Ok(())
}

/// `state.json` の JSON 表現（OCI Runtime Spec の state 形式。`ociVersion`・`id`・`status`・
/// `pid`・`bundle`）に、ストア独自の `revision`・`exitCode` を加えたもの。
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StateDto {
    oci_version: String,
    id: String,
    status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pid: Option<u32>,
    bundle: String,
    revision: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    exit_code: Option<i32>,
}

impl StateDto {
    fn from_record(record: &StateRecord) -> Result<Self, TraitError> {
        check_bundle_len(record.bundle())?;
        let status = record.status();
        let bundle = record
            .bundle()
            .to_str()
            .ok_or_else(|| {
                err(
                    ErrorCode::InvalidArgument,
                    "bundle path must be valid UTF-8",
                )
            })?
            .to_owned();
        Ok(Self {
            oci_version: OCI_VERSION.to_owned(),
            id: status.id().as_str().to_owned(),
            status: status.state().as_str().to_owned(),
            pid: status.pid().map(NonZeroU32::get),
            bundle,
            revision: record.revision().value(),
            exit_code: status.exit_code(),
        })
    }

    /// 公開コンストラクタで組み直し、矛盾があれば `Internal`（壊れた値を表現させない）。
    ///
    /// 書き込み側（`from_record`）が拒否する値は読み込み側でも破損として拒否する（読めても
    /// `update` で書き戻せないレコードを健全扱いにしないため。回復は `purge_corrupted`）。
    fn into_record(self, dir_id: &ContainerId) -> Result<StateRecord, TraitError> {
        let corrupted = || internal("state file is inconsistent");
        if self.oci_version != OCI_VERSION {
            return Err(internal("state file has an unsupported ociVersion"));
        }
        if check_bundle_len(Path::new(&self.bundle)).is_err() {
            return Err(corrupted());
        }
        let id = ContainerId::new(self.id).map_err(|_| corrupted())?;
        if id != *dir_id {
            return Err(corrupted());
        }
        let pid = match self.pid {
            Some(p) => Some(NonZeroU32::new(p).ok_or_else(corrupted)?),
            None => None,
        };
        let status = match (self.status.as_str(), pid, self.exit_code) {
            ("creating", None, None) => ContainerStatus::creating(id),
            ("created", p, None) => ContainerStatus::created(id, p),
            ("running", p, None) => ContainerStatus::running(id, p),
            ("stopped", None, code) => ContainerStatus::stopped(id, code),
            _ => return Err(corrupted()),
        };
        StateRecord::new(
            status,
            PathBuf::from(self.bundle),
            StateRevision::from_raw(self.revision),
        )
        .map_err(|_| corrupted())
    }
}

/// 3 OS 共通の試験（状態ルートの解決規則と、Linux 以外での fail-closed。OCI-5・CLI-1）。
#[cfg(test)]
mod platform_tests {
    use super::*;

    fn code<T: std::fmt::Debug>(r: Result<T, TraitError>) -> &'static str {
        r.unwrap_err().code().as_str()
    }

    #[test]
    fn oci5_root_path_resolution() {
        assert_eq!(
            resolve_default(true, None).unwrap(),
            PathBuf::from("/run/fandhe-container")
        );
        // Windows では "/run/user/1000" が絶対パスでないため、OS ごとの絶対パスを使う。
        let xdg = std::env::temp_dir();
        assert_eq!(
            resolve_default(false, Some(xdg.clone().into_os_string())).unwrap(),
            xdg.join("fandhe-container")
        );
        for bad in [
            None,
            Some(OsString::new()),
            Some(OsString::from("run/user")),
        ] {
            assert_eq!(code(resolve_default(false, bad)), "FAILED_PRECONDITION");
        }
    }

    #[test]
    fn oci5_override_must_be_absolute() {
        assert_eq!(
            code(StateRoot::from_override(PathBuf::from("relative/root"))),
            "INVALID_ARGUMENT"
        );
        assert_eq!(
            code(StateRoot::resolve(Some(PathBuf::from("x")))),
            "INVALID_ARGUMENT"
        );
    }

    /// OCI-5・CLI-1: Linux 以外では状態ルートを作らずに `Unimplemented` を返す（信頼境界を
    /// 検査できないため。start の `BundleLock::acquire` と同じ扱い）。
    #[cfg(not(target_os = "linux"))]
    #[test]
    fn oci5_open_is_unimplemented_outside_linux() {
        let root =
            std::env::temp_dir().join(format!("fandhe-state-store-nolinux-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let e = FileStateStore::open(StateRoot::from_override(root.clone()).unwrap()).unwrap_err();
        assert_eq!(e.code(), ErrorCode::Unimplemented);
        assert_eq!(
            e.message(),
            "file state store requires Linux to verify the state root"
        );
        assert!(!root.exists());
    }
}

/// ストアを開く試験（Linux 限定。他 OS では `open` が `Unimplemented` を返し、その挙動は
/// `platform_tests` が照合する。モジュール doc「対応プラットフォーム」）。
#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use crate::traits::ContainerState;
    use std::num::NonZeroU32;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};

    static COUNTER: AtomicU32 = AtomicU32::new(0);

    /// テスト用一時ディレクトリ（drop で削除）。`tempfile` は依存に追加しない。
    struct TmpDir(PathBuf);

    impl TmpDir {
        fn new(tag: &str) -> Self {
            let n = COUNTER.fetch_add(1, Ordering::SeqCst);
            let p = std::env::temp_dir().join(format!(
                "fandhe-state-store-{tag}-{}-{n}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&p);
            fs::create_dir_all(&p).unwrap();
            // umask に依存せず、状態ルートとして信頼できるモード（0700）に固定する。
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).unwrap();
            }
            Self(p)
        }
        fn path(&self) -> &Path {
            &self.0
        }
        fn open(&self) -> FileStateStore {
            FileStateStore::open(StateRoot::from_override(self.0.clone()).unwrap()).unwrap()
        }
    }

    impl Drop for TmpDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn cid(s: &str) -> ContainerId {
        ContainerId::new(s).unwrap()
    }

    fn bundle() -> PathBuf {
        std::env::temp_dir().join("fandhe-bundle")
    }

    fn create(store: &FileStateStore, id: &str) -> StateRecord {
        let req =
            CreateStateRequest::new(ContainerStatus::created(cid(id), None), bundle()).unwrap();
        store.create(&req).unwrap()
    }

    fn code<T: std::fmt::Debug>(r: Result<T, TraitError>) -> &'static str {
        r.unwrap_err().code().as_str()
    }

    fn list_req(n: u32) -> ListStateRequest {
        ListStateRequest::new(NonZeroU32::new(n).unwrap()).unwrap()
    }

    #[test]
    fn oci5_create_rejects_overlong_bundle_path() {
        let t = TmpDir::new("longbundle");
        let store = t.open();
        let long = std::env::temp_dir().join("a".repeat(MAX_BUNDLE_PATH_BYTES + 1));
        let req = CreateStateRequest::new(ContainerStatus::creating(cid("big")), long).unwrap();
        assert_eq!(code(store.create(&req)), "INVALID_ARGUMENT");
        // 拒否時は revision もレコードも消費しない。
        assert!(!t.path().join("big").exists());
        assert_eq!(fs::read_to_string(t.path().join("@revision")).unwrap(), "0");
    }

    #[test]
    fn oci5_update_fails_closed_when_revision_high_water_mark_is_behind() {
        let t = TmpDir::new("hwm");
        let store = t.open();
        let rec = create(&store, "web");
        // @revision が巻き戻った状態（fsync 欠落クラッシュ相当）を再現する。
        fs::write(t.path().join("@revision"), b"0").unwrap();
        let req =
            UpdateStateRequest::new(ContainerStatus::running(cid("web"), None), rec.revision());
        assert_eq!(code(store.update(&req)), "INTERNAL");
    }

    #[test]
    fn oci5_create_writes_state_json_at_expected_path() {
        let t = TmpDir::new("create");
        let store = t.open();
        let rec = create(&store, "web");
        assert_eq!(rec.revision(), StateRevision::INITIAL);
        let text = fs::read_to_string(t.path().join("web").join("state.json")).unwrap();
        let v: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(v["ociVersion"], "1.2.0");
        assert_eq!(v["id"], "web");
        assert_eq!(v["status"], "created");
        assert_eq!(v["revision"], 0);
        assert_eq!(v["bundle"], bundle().to_str().unwrap());
        assert!(v.get("pid").is_none());
    }

    #[test]
    fn cri7_file_state_store_is_dyn_compatible() {
        let t = TmpDir::new("dyn");
        let boxed: Box<dyn StateStore> = Box::new(t.open());
        let req = CreateStateRequest::new(ContainerStatus::creating(cid("a")), bundle()).unwrap();
        boxed.create(&req).unwrap();
        let got = boxed.get(&GetStateRequest::new(cid("a"))).unwrap();
        assert_eq!(got.status().state(), ContainerState::Creating);
        let shared: Arc<dyn StateStore> = Arc::new(t.open());
        assert_eq!(
            shared
                .get(&GetStateRequest::new(cid("a")))
                .unwrap()
                .id()
                .as_str(),
            "a"
        );
    }

    #[test]
    fn oci5_contract_errors() {
        let t = TmpDir::new("contract");
        let store = t.open();
        let rec = create(&store, "a");
        let dup =
            CreateStateRequest::new(ContainerStatus::created(cid("a"), None), bundle()).unwrap();
        assert_eq!(code(store.create(&dup)), "ALREADY_EXISTS");
        assert_eq!(
            code(store.get(&GetStateRequest::new(cid("zz")))),
            "NOT_FOUND"
        );
        assert_eq!(
            code(store.delete(&DeleteStateRequest::new(cid("zz"), StateRevision::INITIAL))),
            "NOT_FOUND"
        );
        let stale = StateRevision::from_raw(999);
        let up = UpdateStateRequest::new(ContainerStatus::running(cid("a"), None), stale);
        assert_eq!(code(store.update(&up)), "FAILED_PRECONDITION");
        assert_eq!(
            code(store.delete(&DeleteStateRequest::new(cid("a"), stale))),
            "FAILED_PRECONDITION"
        );
        // 失敗後もレコードが残る。
        assert_eq!(store.get(&GetStateRequest::new(cid("a"))).unwrap(), rec);
        let up = UpdateStateRequest::new(
            ContainerStatus::running(cid("a"), NonZeroU32::new(42)),
            rec.revision(),
        );
        let updated = store.update(&up).unwrap();
        assert_eq!(updated.revision().value(), 1);
        assert_eq!(updated.bundle(), bundle());
        assert_eq!(updated.status().pid(), NonZeroU32::new(42));
    }

    #[test]
    fn oci5_revision_never_reused_across_delete_and_reopen() {
        let t = TmpDir::new("rev");
        let store = t.open();
        let first = create(&store, "a");
        store
            .delete(&DeleteStateRequest::new(cid("a"), first.revision()))
            .unwrap();
        drop(store);
        let store = t.open();
        let second = create(&store, "a");
        assert_eq!(first.revision().value(), 0);
        assert_eq!(second.revision().value(), 1);
    }

    #[test]
    fn oci5_missing_revision_file_with_records_fails_closed() {
        let t = TmpDir::new("revmiss");
        let store = t.open();
        create(&store, "a");
        fs::remove_file(t.path().join("@revision")).unwrap();
        let req =
            CreateStateRequest::new(ContainerStatus::created(cid("b"), None), bundle()).unwrap();
        assert_eq!(code(store.create(&req)), "INTERNAL");
    }

    #[test]
    fn oci5_list_pagination() {
        let t = TmpDir::new("list");
        let store = t.open();
        for id in ["c", "a", "b"] {
            create(&store, id);
        }
        let residue = t.path().join("residue");
        fs::create_dir(&residue).unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&residue, fs::Permissions::from_mode(0o700)).unwrap();
        }
        fs::write(t.path().join("bad name"), b"x").unwrap();
        let p1 = store.list(&list_req(2)).unwrap();
        let ids: Vec<&str> = p1.records().iter().map(|r| r.id().as_str()).collect();
        assert_eq!(ids, ["a", "b"]);
        let cursor = p1.next_cursor().unwrap().clone();
        assert_eq!(cursor.as_str(), "b");
        let p2 = store.list(&list_req(2).with_cursor(cursor)).unwrap();
        let ids: Vec<&str> = p2.records().iter().map(|r| r.id().as_str()).collect();
        assert_eq!(ids, ["c"]);
        assert!(p2.next_cursor().is_none());
        let bad = StateListCursor::from_raw("a/b".to_owned()).unwrap();
        assert_eq!(
            code(store.list(&list_req(2).with_cursor(bad))),
            "INVALID_ARGUMENT"
        );
    }

    /// OCI-5: 破損レコードが対象ページの外（後ろ）にあっても list は fail-closed で失敗する。
    #[test]
    fn oci5_list_detects_corruption_outside_the_page() {
        let t = TmpDir::new("listoutside");
        let store = t.open();
        create(&store, "a");
        create(&store, "z");
        fs::write(t.path().join("z").join("state.json"), b"{not json").unwrap();
        let e = store.list(&list_req(1)).unwrap_err();
        assert_eq!(e.code().as_str(), "INTERNAL");
        assert_eq!(e.message(), "state file is corrupted");
        // 回復すれば同じ要求が成功し、健全なレコードだけが返る。
        store.purge_corrupted(&cid("z")).unwrap();
        let page = store.list(&list_req(1)).unwrap();
        let ids: Vec<&str> = page.records().iter().map(|r| r.id().as_str()).collect();
        assert_eq!(ids, ["a"]);
        assert!(page.next_cursor().is_none());
    }

    /// OCI-5: カーソルより前にある破損レコードも検出する（後続ページの取得でも fail-closed）。
    #[test]
    fn oci5_list_detects_corruption_before_the_cursor() {
        let t = TmpDir::new("listbefore");
        let store = t.open();
        for id in ["a", "b", "c"] {
            create(&store, id);
        }
        let first = store.list(&list_req(2)).unwrap();
        let cursor = first.next_cursor().unwrap().clone();
        assert_eq!(cursor.as_str(), "b");
        let bad =
            r#"{"ociVersion":"1.2.0","id":"z","status":"created","bundle":"/b","revision":1}"#;
        fs::write(t.path().join("b").join("state.json"), bad).unwrap();
        let e = store.list(&list_req(2).with_cursor(cursor)).unwrap_err();
        assert_eq!(e.code().as_str(), "INTERNAL");
        assert_eq!(e.message(), "state file is inconsistent");
    }

    #[test]
    fn oci5_delete_removes_state_file_and_dir() {
        let t = TmpDir::new("del");
        let store = t.open();
        let a = create(&store, "a");
        store
            .delete(&DeleteStateRequest::new(cid("a"), a.revision()))
            .unwrap();
        assert!(!t.path().join("a").exists());
        let b = create(&store, "b");
        fs::write(t.path().join("b").join("extra"), b"x").unwrap();
        store
            .delete(&DeleteStateRequest::new(cid("b"), b.revision()))
            .unwrap();
        assert!(t.path().join("b").join("extra").exists());
        assert!(!t.path().join("b").join("state.json").exists());
        assert_eq!(
            code(store.get(&GetStateRequest::new(cid("b")))),
            "NOT_FOUND"
        );
    }

    #[test]
    fn oci5_create_ignores_residual_dir_without_state_json() {
        let t = TmpDir::new("resid");
        let store = t.open();
        let resid = t.path().join("a");
        fs::create_dir(&resid).unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&resid, fs::Permissions::from_mode(0o700)).unwrap();
        }
        assert_eq!(create(&store, "a").id().as_str(), "a");
    }

    /// OCI-5: 他ユーザーがアクセスできる残存ディレクトリは再利用・読み取りとも拒否する。
    #[test]
    fn oci5_create_rejects_group_accessible_residual_dir() {
        use std::os::unix::fs::PermissionsExt;
        let t = TmpDir::new("residperm");
        let store = t.open();
        let resid = t.path().join("a");
        fs::create_dir(&resid).unwrap();
        fs::set_permissions(&resid, fs::Permissions::from_mode(0o755)).unwrap();
        let req = CreateStateRequest::new(ContainerStatus::creating(cid("a")), bundle()).unwrap();
        assert_eq!(code(store.create(&req)), "PERMISSION_DENIED");
        assert!(!resid.join("state.json").exists());
        // 既存レコードのディレクトリが緩められた場合は get も拒否する。
        let rec = create(&store, "b");
        fs::set_permissions(t.path().join("b"), fs::Permissions::from_mode(0o770)).unwrap();
        assert_eq!(
            code(store.get(&GetStateRequest::new(cid("b")))),
            "PERMISSION_DENIED"
        );
        let _ = rec;
    }

    /// OCI-5: `@revision` が巻き戻った状態で新規作成しても使用済み revision を払い出さない。
    #[test]
    fn oci5_create_fails_closed_when_revision_high_water_mark_is_behind() {
        let t = TmpDir::new("hwmcreate");
        let store = t.open();
        create(&store, "a");
        create(&store, "b");
        fs::write(t.path().join("@revision"), b"0").unwrap();
        let req = CreateStateRequest::new(ContainerStatus::creating(cid("c")), bundle()).unwrap();
        assert_eq!(code(store.create(&req)), "INTERNAL");
        assert!(!t.path().join("c").join("state.json").exists());
    }

    /// OCI-5: 巻き戻り検出の全レコード走査はインスタンスごとの初回の採番だけで行い、以降は下限
    /// （払い出し済みの値）との比較で検出する。新しいインスタンスは初回に全件を走査する。
    #[test]
    fn oci5_revision_floor_is_scanned_once_per_instance() {
        let t = TmpDir::new("floor");
        let store = t.open();
        create(&store, "a");
        create(&store, "b");
        // レコード側の revision を @revision（2）より大きく書き換える（外部改変相当）。
        let b = r#"{"ociVersion":"1.2.0","id":"b","status":"created","bundle":"/b","revision":50}"#;
        fs::write(t.path().join("b").join("state.json"), b).unwrap();
        // 同じインスタンスは全件を読み直さないため、下限（2）との比較だけで払い出す。
        assert_eq!(create(&store, "c").revision().value(), 2);
        // 新しいインスタンスは初回の採番で全件を走査し、巻き戻りとして拒否する。
        let fresh = t.open();
        let req = CreateStateRequest::new(ContainerStatus::creating(cid("d")), bundle()).unwrap();
        let e = fresh.create(&req).unwrap_err();
        assert_eq!(e.code().as_str(), "INTERNAL");
        assert_eq!(
            e.message(),
            "revision high-water mark is behind the records"
        );
        assert!(!t.path().join("d").join("state.json").exists());
        // 同じインスタンスでも、払い出し済みの値より @revision が小さくなれば拒否する。
        fs::write(t.path().join("@revision"), b"1").unwrap();
        let req = CreateStateRequest::new(ContainerStatus::creating(cid("e")), bundle()).unwrap();
        let e = store.create(&req).unwrap_err();
        assert_eq!(
            e.message(),
            "revision high-water mark is behind the records"
        );
    }

    #[test]
    fn oci5_corrupted_state_json_returns_internal() {
        let t = TmpDir::new("corrupt");
        let store = t.open();
        create(&store, "a");
        let file = t.path().join("a").join("state.json");
        let get = || store.get(&GetStateRequest::new(cid("a")));
        fs::write(&file, b"{not json").unwrap();
        assert_eq!(code(get()), "INTERNAL");
        fs::write(&file, vec![b' '; (MAX_STATE_FILE_BYTES + 1) as usize]).unwrap();
        assert_eq!(code(get()), "INTERNAL");
        let stopped_with_pid = r#"{"ociVersion":"1.2.0","id":"a","status":"stopped","pid":5,"bundle":"/b","revision":0}"#;
        fs::write(&file, stopped_with_pid).unwrap();
        assert_eq!(code(get()), "INTERNAL");
        let other_id =
            r#"{"ociVersion":"1.2.0","id":"z","status":"created","bundle":"/b","revision":0}"#;
        fs::write(&file, other_id).unwrap();
        assert_eq!(code(get()), "INTERNAL");
    }

    /// OCI-5: 破損レコード 1 件が他コンテナの create / update を止めず、delete で回復できる。
    #[test]
    fn oci5_corrupted_record_does_not_block_others_and_is_deletable() {
        let t = TmpDir::new("corruptrecover");
        let store = t.open();
        create(&store, "a");
        let rec_b = create(&store, "b");
        fs::write(t.path().join("a").join("state.json"), b"{not json").unwrap();
        // 他コンテナの update・create は成功する。
        let updated = store
            .update(&UpdateStateRequest::new(
                ContainerStatus::creating(cid("b")),
                rec_b.revision(),
            ))
            .unwrap();
        assert!(updated.revision().value() > rec_b.revision().value());
        let req = CreateStateRequest::new(ContainerStatus::creating(cid("c")), bundle()).unwrap();
        store.create(&req).unwrap();
        // 通常の delete は revision を照合できないため拒否し、管理操作で回復する。
        assert_eq!(
            code(store.delete(&DeleteStateRequest::new(cid("a"), StateRevision::INITIAL))),
            "INTERNAL"
        );
        assert!(t.path().join("a").join("state.json").exists());
        assert_eq!(store.find_corrupted().unwrap(), vec![cid("a")]);
        // 健全なレコードには purge_corrupted を使えない。
        assert_eq!(
            code(store.purge_corrupted(&cid("b"))),
            "FAILED_PRECONDITION"
        );
        store.purge_corrupted(&cid("a")).unwrap();
        assert!(!t.path().join("a").exists());
        assert_eq!(code(store.purge_corrupted(&cid("a"))), "NOT_FOUND");
    }

    /// OCI-5: 構造上の不整合（ociVersion 不正・ID 不一致・状態と PID の矛盾）も回復対象。
    #[test]
    fn oci5_semantically_corrupted_records_are_purgeable() {
        let t = TmpDir::new("semcorrupt");
        let store = t.open();
        for id in ["a", "b", "c"] {
            create(&store, id);
        }
        let w = |id: &str, body: &str| {
            fs::write(t.path().join(id).join("state.json"), body).unwrap();
        };
        w(
            "a",
            r#"{"ociVersion":"0.9.0","id":"a","status":"created","bundle":"/b","revision":0}"#,
        );
        w(
            "b",
            r#"{"ociVersion":"1.2.0","id":"z","status":"created","bundle":"/b","revision":1}"#,
        );
        w(
            "c",
            r#"{"ociVersion":"1.2.0","id":"c","status":"stopped","pid":5,"bundle":"/b","revision":2}"#,
        );
        assert_eq!(code(store.list(&list_req(10))), "INTERNAL");
        let found = store.find_corrupted().unwrap();
        assert_eq!(found, vec![cid("a"), cid("b"), cid("c")]);
        for id in ["a", "b", "c"] {
            store.purge_corrupted(&cid(id)).unwrap();
        }
        assert!(store.list(&list_req(10)).unwrap().records().is_empty());
    }

    /// OCI-5: 書き込み側の上限を超える bundle を持つ state.json は破損として扱い、回復できる。
    #[test]
    fn oci5_overlong_bundle_on_read_is_corrupted_and_purgeable() {
        let t = TmpDir::new("longread");
        let store = t.open();
        create(&store, "a");
        let long = format!("/{}", "a".repeat(MAX_BUNDLE_PATH_BYTES));
        assert_eq!(long.len(), MAX_BUNDLE_PATH_BYTES + 1);
        let body = format!(
            r#"{{"ociVersion":"1.2.0","id":"a","status":"created","bundle":"{long}","revision":0}}"#
        );
        fs::write(t.path().join("a").join("state.json"), body).unwrap();
        let e = store.get(&GetStateRequest::new(cid("a"))).unwrap_err();
        assert_eq!(e.code().as_str(), "INTERNAL");
        assert_eq!(e.message(), "state file is inconsistent");
        assert_eq!(store.find_corrupted().unwrap(), vec![cid("a")]);
        store.purge_corrupted(&cid("a")).unwrap();
        assert_eq!(
            code(store.get(&GetStateRequest::new(cid("a")))),
            "NOT_FOUND"
        );
        // 上限ちょうどの bundle は健全なレコードとして読める。
        create(&store, "b");
        let exact = format!("/{}", "b".repeat(MAX_BUNDLE_PATH_BYTES - 1));
        let body = format!(
            r#"{{"ociVersion":"1.2.0","id":"b","status":"created","bundle":"{exact}","revision":1}}"#
        );
        fs::write(t.path().join("b").join("state.json"), body).unwrap();
        let got = store.get(&GetStateRequest::new(cid("b"))).unwrap();
        assert_eq!(got.bundle().as_os_str().len(), MAX_BUNDLE_PATH_BYTES);
    }

    /// OCI-5: `@revision` が失われたら、全レコード削除後でも revision を再発行しない。
    #[test]
    fn oci5_missing_revision_file_without_records_fails_closed() {
        let t = TmpDir::new("revmiss2");
        let store = t.open();
        let first = create(&store, "a");
        store
            .delete(&DeleteStateRequest::new(cid("a"), first.revision()))
            .unwrap();
        fs::remove_file(t.path().join("@revision")).unwrap();
        drop(store);
        let store = t.open();
        let req =
            CreateStateRequest::new(ContainerStatus::created(cid("b"), None), bundle()).unwrap();
        assert_eq!(code(store.create(&req)), "INTERNAL");
    }

    /// OCI-5: 初期化途中の残骸（`@revision.init-*`）だけのルートは新規ストアとして初期化し直す。
    #[test]
    fn oci5_open_recovers_from_interrupted_revision_init() {
        let t = TmpDir::new("initresidue");
        fs::write(t.path().join("@revision.init-1-0"), b"0").unwrap();
        let store = t.open();
        assert_eq!(fs::read_to_string(t.path().join("@revision")).unwrap(), "0");
        assert_eq!(create(&store, "a").revision(), StateRevision::INITIAL);
    }

    /// OCI-5: 新規ストアの `open` 後は `@lock` より先に `@revision` が存在する。
    #[test]
    fn oci5_fresh_open_creates_revision_without_lock_file() {
        let t = TmpDir::new("freshnolock");
        let _store = t.open();
        assert!(t.path().join("@revision").is_file());
        assert!(!t.path().join("@lock").exists());
    }

    /// OCI-5: 権限不備のレコードは破損として列挙・削除せず、list も get と同じくエラーを返す。
    #[test]
    fn oci5_permission_error_is_not_treated_as_corruption() {
        use std::os::unix::fs::PermissionsExt;
        let t = TmpDir::new("permerr");
        let store = t.open();
        create(&store, "a");
        create(&store, "b");
        let dir = t.path().join("a");
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            code(store.get(&GetStateRequest::new(cid("a")))),
            "PERMISSION_DENIED"
        );
        assert_eq!(code(store.list(&list_req(10))), "PERMISSION_DENIED");
        assert_eq!(code(store.find_corrupted()), "PERMISSION_DENIED");
        assert_eq!(code(store.purge_corrupted(&cid("a"))), "PERMISSION_DENIED");
        assert!(dir.join("state.json").is_file());
        // state.json が読めない（I/O・権限）場合も削除しない。root 実行では権限が効かないため
        // モード 0 で実際に読めなくなったときだけ検査する。
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        let file = dir.join("state.json");
        fs::set_permissions(&file, fs::Permissions::from_mode(0o000)).unwrap();
        if File::open(&file).is_err() {
            assert_eq!(code(store.find_corrupted()), "INTERNAL");
            assert_eq!(code(store.purge_corrupted(&cid("a"))), "INTERNAL");
            assert!(file.is_file());
        }
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
    }

    /// OCI-5: symlink 化した状態エントリは list でもエラーにする（黙って除外しない）。
    #[test]
    fn oci5_list_reports_symlinked_entry() {
        let t = TmpDir::new("listsymlink");
        let store = t.open();
        create(&store, "a");
        let target = t.path().join("a");
        std::os::unix::fs::symlink(&target, t.path().join("evil")).unwrap();
        assert_eq!(code(store.list(&list_req(10))), "PERMISSION_DENIED");
    }

    /// OCI-5: ファイル種別が異常なエントリ（`<id>` が symlink・通常ファイル、`state.json` が
    /// symlink・ディレクトリ）は破損として特定・回復でき、symlink のリンク先は消さない。
    #[test]
    fn oci5_malformed_entries_are_found_and_purged_without_following_symlinks() {
        let t = TmpDir::new("malformed");
        let store = t.open();
        for id in ["a", "c", "d"] {
            create(&store, id);
        }
        // ルート外のファイル（ルート直下に置くと、それ自体が異常なエントリになる）。
        let other = TmpDir::new("malformed-outside");
        let outside = other.path().join("target.json");
        fs::write(&outside, b"keep").unwrap();
        // <id> が symlink（健全なレコード a を指す）と通常ファイル。
        std::os::unix::fs::symlink(t.path().join("a"), t.path().join("b")).unwrap();
        fs::write(t.path().join("e"), b"x").unwrap();
        // state.json が symlink（ルート外のファイルを指す）とディレクトリ（中身あり）。
        let c_state = t.path().join("c").join("state.json");
        fs::remove_file(&c_state).unwrap();
        std::os::unix::fs::symlink(&outside, &c_state).unwrap();
        let d_state = t.path().join("d").join("state.json");
        fs::remove_file(&d_state).unwrap();
        fs::create_dir(&d_state).unwrap();
        fs::write(d_state.join("inner"), b"x").unwrap();

        let e = store.get(&GetStateRequest::new(cid("c"))).unwrap_err();
        assert_eq!(e.message(), "state file is not a regular file");
        assert_eq!(
            store.find_corrupted().unwrap(),
            vec![cid("b"), cid("c"), cid("d"), cid("e")]
        );
        for id in ["b", "c", "d", "e"] {
            store.purge_corrupted(&cid(id)).unwrap();
        }
        assert!(!t.path().join("b").exists());
        assert!(!t.path().join("c").exists());
        assert!(!t.path().join("d").exists());
        assert!(!t.path().join("e").exists());
        // リンク先（健全なレコード a・ルート外のファイル）は残る。
        assert_eq!(fs::read(&outside).unwrap(), b"keep");
        let ids: Vec<String> = store
            .list(&list_req(10))
            .unwrap()
            .records()
            .iter()
            .map(|r| r.id().as_str().to_owned())
            .collect();
        assert_eq!(ids, ["a"]);
    }

    #[test]
    fn oci5_unsupported_oci_version_returns_internal() {
        let t = TmpDir::new("ociver");
        let store = t.open();
        create(&store, "a");
        let file = t.path().join("a").join("state.json");
        let bad =
            r#"{"ociVersion":"0.9.0","id":"a","status":"created","bundle":"/b","revision":0}"#;
        fs::write(&file, bad).unwrap();
        let err = store.get(&GetStateRequest::new(cid("a"))).unwrap_err();
        assert_eq!(err.code().as_str(), "INTERNAL");
        assert_eq!(err.message(), "state file has an unsupported ociVersion");
    }

    /// REPAIR-5: プロセス内ミューテックスの待機も有限時間で打ち切る。
    #[test]
    fn oci5_process_lock_wait_times_out() {
        let t = TmpDir::new("mutex-timeout");
        let store = t.open();
        let _held = store.process_lock.lock().unwrap();
        let started = Instant::now();
        let r = store.get(&GetStateRequest::new(cid("a")));
        assert_eq!(code(r), "TIMEOUT");
        assert!(started.elapsed() < STATE_LOCK_TIMEOUT + Duration::from_secs(5));
    }

    #[test]
    fn oci5_lock_file_is_mode_0600() {
        use std::os::unix::fs::PermissionsExt;
        let t = TmpDir::new("lockmode");
        let store = t.open();
        create(&store, "a");
        let mode = fs::metadata(t.path().join(LOCK_FILE))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    /// 親ディレクトリが group / other 書き込み可（sticky なし）なら拒否する。
    #[test]
    fn oci5_writable_ancestor_is_rejected() {
        use std::os::unix::fs::PermissionsExt;
        let t = TmpDir::new("ancestor");
        let parent = t.path().join("parent");
        fs::create_dir(&parent).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o770)).unwrap();
        let root = parent.join("root");
        let r = FileStateStore::open(StateRoot::from_override(root).unwrap());
        assert_eq!(code(r), "PERMISSION_DENIED");
    }

    #[test]
    fn oci5_status_roundtrip() {
        let t = TmpDir::new("roundtrip");
        let store = t.open();
        let cases = [
            ContainerStatus::creating(cid("s1")),
            ContainerStatus::created(cid("s2"), NonZeroU32::new(7)),
            ContainerStatus::running(cid("s3"), NonZeroU32::new(8)),
            ContainerStatus::stopped(cid("s4"), Some(-9)),
            ContainerStatus::stopped(cid("s5"), None),
        ];
        for status in cases {
            let req = CreateStateRequest::new(status.clone(), bundle()).unwrap();
            store.create(&req).unwrap();
            let got = store
                .get(&GetStateRequest::new(status.id().clone()))
                .unwrap();
            assert_eq!(got.status(), &status);
        }
    }

    /// OCI-5: symlink・0700 以外の既存ルートを拒否し、新規ルートは 0700 で作る。
    #[test]
    fn oci5_open_rejects_unsafe_root_and_creates_0700() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let t = TmpDir::new("perm");
        let real = t.path().join("real");
        fs::create_dir(&real).unwrap();
        let link = t.path().join("link");
        symlink(&real, &link).unwrap();
        assert_eq!(
            code(FileStateStore::open(
                StateRoot::from_override(link).unwrap()
            )),
            "PERMISSION_DENIED"
        );
        // 書き込みビットに加え、読み取り・実行ビットだけ（ID の列挙が可能）でも拒否する。
        for mode in [0o770, 0o755, 0o750, 0o701] {
            fs::set_permissions(&real, fs::Permissions::from_mode(mode)).unwrap();
            let e =
                FileStateStore::open(StateRoot::from_override(real.clone()).unwrap()).unwrap_err();
            assert_eq!(e.code().as_str(), "PERMISSION_DENIED", "mode {mode:o}");
            assert_eq!(
                e.message(),
                "state root must not be accessible by group or others"
            );
        }
        fs::set_permissions(&real, fs::Permissions::from_mode(0o700)).unwrap();
        FileStateStore::open(StateRoot::from_override(real).unwrap()).unwrap();
        let fresh = t.path().join("fresh");
        FileStateStore::open(StateRoot::from_override(fresh.clone()).unwrap()).unwrap();
        assert_eq!(
            fs::metadata(&fresh).unwrap().permissions().mode() & 0o777,
            0o700
        );
        let orphan = t.path().join("no-parent").join("root");
        assert_eq!(
            code(FileStateStore::open(
                StateRoot::from_override(orphan).unwrap()
            )),
            "NOT_FOUND"
        );
    }

    #[test]
    fn oci5_concurrent_create_and_update() {
        let t = TmpDir::new("conc");
        let store = Arc::new(t.open());
        let results: Vec<_> = (0..2)
            .map(|_| {
                let s = Arc::clone(&store);
                std::thread::spawn(move || {
                    let req =
                        CreateStateRequest::new(ContainerStatus::created(cid("a"), None), bundle())
                            .unwrap();
                    s.create(&req).map_err(|e| e.code().as_str())
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|h| h.join().unwrap())
            .collect();
        assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
        assert!(results.contains(&Err("ALREADY_EXISTS")));

        for id in ["u0", "u1", "u2", "u3"] {
            create(&store, id);
        }
        let revs: Vec<u64> = ["u0", "u1", "u2", "u3"]
            .into_iter()
            .map(|id| {
                let s = Arc::clone(&store);
                std::thread::spawn(move || {
                    let cur = s.get(&GetStateRequest::new(cid(id))).unwrap();
                    let up = UpdateStateRequest::new(
                        ContainerStatus::running(cid(id), None),
                        cur.revision(),
                    );
                    s.update(&up).unwrap().revision().value()
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|h| h.join().unwrap())
            .collect();
        let mut sorted = revs.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), 4);
    }
}
