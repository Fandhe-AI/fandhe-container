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
//!   クラッシュしても欠番になるだけで再利用しない。`@revision` が消えているのにレコードが
//!   残っている場合は fail-closed（`Internal`）
//! - 書き込みは同じディレクトリの一時ファイルへ書いて `rename` する。fsync・一時ファイルの
//!   残骸掃除・強制終了テストは TASK-31.2（#156）、結合テストは TASK-31.3（#157）で行う
//! - 状態ルートは信頼境界として扱う（`bundle` のすり替えは `start` の起動先のすり替えになるため。
//!   SEC-1・PLUG-12 と同じ姿勢）。symlink・所有者不一致（Linux）・group / other 書き込み可を
//!   `PermissionDenied` で拒否する。Windows の ACL 検査と、Linux 以外の unix での所有者検査は
//!   将来課題（未実装）
//! - エラーメッセージは固定の英語文言のみで、パス・errno を含めない

use std::collections::BinaryHeap;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
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

/// ファイルロックを待つ上限時間（REPAIR-5: 相手を無期限に待たない）。
pub const STATE_LOCK_TIMEOUT: Duration = Duration::from_secs(5);

/// ロック再試行の間隔。
const LOCK_RETRY_INTERVAL: Duration = Duration::from_millis(5);

/// `state.json` に書く OCI Runtime Spec のバージョン。
const OCI_VERSION: &str = "1.2.0";

const LOCK_FILE: &str = "@lock";
const REVISION_FILE: &str = "@revision";
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

/// ファイルベースの [`StateStore`] 実装。
#[derive(Debug)]
pub struct FileStateStore {
    root: PathBuf,
    /// プロセス内の排他。プロセス間は `@lock` のファイルロックが担う。
    process_lock: Mutex<()>,
}

/// ロックの RAII ガード。drop でファイルロックとミューテックスが解放される。
struct StoreGuard<'a> {
    _process: MutexGuard<'a, ()>,
    _file: File,
}

impl FileStateStore {
    /// 状態ルートを用意して検証する。
    ///
    /// ルートがなければ 0700（unix）で作る。親ディレクトリは作らない（`/run` や
    /// `$XDG_RUNTIME_DIR` がなければ `NotFound`）。symlink・ディレクトリでないもの・
    /// （Linux で）他ユーザー所有・group / other 書き込み可のルートは `PermissionDenied`。
    pub fn open(root: StateRoot) -> Result<Self, TraitError> {
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
        Ok(Self {
            root,
            process_lock: Mutex::new(()),
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
                        _process: process,
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

    /// `<id>/state.json` を読む。存在しなければ `None`（残骸ディレクトリのみも `None`）。
    fn read_record(&self, id: &ContainerId) -> Result<Option<StateRecord>, TraitError> {
        let dir = self.record_dir(id);
        match fs::symlink_metadata(&dir) {
            Ok(m) if m.is_dir() => {}
            Ok(_) => {
                return Err(err(
                    ErrorCode::PermissionDenied,
                    "state entry is not a directory",
                ));
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(internal("failed to inspect the state directory")),
        }
        let file_path = dir.join(STATE_FILE_NAME);
        match fs::symlink_metadata(&file_path) {
            Ok(m) if m.is_file() => {}
            Ok(_) => return Err(internal("state file is not a regular file")),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(internal("failed to inspect the state file")),
        }
        let bytes = read_limited(
            &file_path,
            MAX_STATE_FILE_BYTES,
            "state file exceeds the size limit",
        )?;
        let dto: StateDto =
            serde_json::from_slice(&bytes).map_err(|_| internal("state file is corrupted"))?;
        dto.into_record(id).map(Some)
    }

    /// 「`<id>/state.json` が通常ファイルとして存在するか」（list・新規ストア判定用）。
    fn has_record(&self, name: &str) -> bool {
        let dir = self.root.join(name);
        match fs::symlink_metadata(&dir) {
            Ok(m) if m.is_dir() => {}
            _ => return false,
        }
        matches!(fs::symlink_metadata(dir.join(STATE_FILE_NAME)), Ok(m) if m.is_file())
    }

    fn write_record(&self, record: &StateRecord) -> Result<(), TraitError> {
        let dto = StateDto::from_record(record)?;
        let bytes =
            serde_json::to_vec(&dto).map_err(|_| internal("failed to serialize the state"))?;
        write_file_replacing(&self.record_dir(record.id()), STATE_FILE_NAME, &bytes)
    }

    /// revision を 1 つ払い出し、上限値を先に永続化する（ロック保持下で呼ぶこと）。
    fn allocate_revision(&self) -> Result<StateRevision, TraitError> {
        let path = self.root.join(REVISION_FILE);
        let current = match fs::symlink_metadata(&path) {
            Ok(m) if m.is_file() => {
                let bytes =
                    read_limited(&path, MAX_REVISION_FILE_BYTES, "revision file is corrupted")?;
                let text = std::str::from_utf8(&bytes)
                    .map_err(|_| internal("revision file is corrupted"))?;
                let value: u64 = text
                    .trim()
                    .parse()
                    .map_err(|_| internal("revision file is corrupted"))?;
                StateRevision::from_raw(value)
            }
            Ok(_) => return Err(internal("revision file is not a regular file")),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                if self.any_record()? {
                    return Err(internal("revision high-water mark is missing"));
                }
                StateRevision::INITIAL
            }
            Err(_) => return Err(internal("failed to inspect the revision file")),
        };
        let next = current.next()?;
        write_file_replacing(
            &self.root,
            REVISION_FILE,
            next.value().to_string().as_bytes(),
        )?;
        Ok(current)
    }

    fn any_record(&self) -> Result<bool, TraitError> {
        let entries =
            fs::read_dir(&self.root).map_err(|_| internal("failed to read the state root"))?;
        for entry in entries {
            let entry = entry.map_err(|_| internal("failed to read the state root"))?;
            if let Some(name) = entry.file_name().to_str()
                && ContainerId::new(name).is_ok()
                && self.has_record(name)
            {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

impl StateStore for FileStateStore {
    fn create(&self, req: &CreateStateRequest) -> Result<StateRecord, TraitError> {
        let _guard = self.lock()?;
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
                    Ok(m) if m.is_dir() => {}
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
        let revision = self.allocate_revision()?;
        let record = StateRecord::new(req.status().clone(), req.bundle().to_path_buf(), revision)?;
        self.write_record(&record)?;
        Ok(record)
    }

    fn update(&self, req: &UpdateStateRequest) -> Result<StateRecord, TraitError> {
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
        let revision = self.allocate_revision()?;
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
    fn list(&self, req: &ListStateRequest) -> Result<StateList, TraitError> {
        let after = match req.cursor() {
            Some(c) => Some(ContainerId::new(c.as_str())?),
            None => None,
        };
        let _guard = self.lock()?;
        let page = req.page_size().get() as usize;
        // 保持件数を page + 1 に抑え、ストア全体の件数に比例したメモリを確保しない。
        let mut smallest: BinaryHeap<String> = BinaryHeap::with_capacity(page.saturating_add(1));
        let entries =
            fs::read_dir(&self.root).map_err(|_| internal("failed to read the state root"))?;
        for entry in entries {
            let entry = entry.map_err(|_| internal("failed to read the state root"))?;
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            if ContainerId::new(name.as_str()).is_err() {
                continue;
            }
            if let Some(a) = &after
                && name.as_str() <= a.as_str()
            {
                continue;
            }
            if !self.has_record(&name) {
                continue;
            }
            smallest.push(name);
            if smallest.len() > page.saturating_add(1) {
                smallest.pop();
            }
        }
        let mut names: Vec<String> = smallest.into_vec();
        names.sort();
        // 上の有界選択は「小さい方から page + 1 件」を残すため、超過分は最後の 1 件。
        let has_more = names.len() > page;
        names.truncate(page);
        let mut records = Vec::with_capacity(names.len());
        let mut last: Option<String> = None;
        for name in names {
            let id = ContainerId::new(name.as_str())?;
            let record = self
                .read_record(&id)?
                .ok_or_else(|| internal("state file disappeared during listing"))?;
            last = Some(name);
            records.push(record);
        }
        let next_cursor = match (has_more, last) {
            (true, Some(l)) => Some(StateListCursor::from_raw(l)?),
            _ => None,
        };
        Ok(StateList::new(records, next_cursor))
    }

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
        let dir = self.record_dir(req.id());
        fs::remove_file(dir.join(STATE_FILE_NAME))
            .map_err(|_| internal("failed to remove the state file"))?;
        match fs::remove_dir(&dir) {
            Ok(()) => {}
            // 他の部品（PLUG-12 の UDS 等）がファイルを置いている場合は残す。レコードの
            // 有無は state.json で判定するため整合する。
            Err(e) if e.kind() == std::io::ErrorKind::DirectoryNotEmpty => {}
            Err(_) => return Err(internal("failed to remove the state directory")),
        }
        Ok(DeleteStateResponse::new())
    }
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

/// 祖先ディレクトリが第三者にすり替えられないか検査する（unix）。
///
/// 各祖先は、group / other 書き込み不可（sticky ビット付きは許可。`/tmp` 等）であり、
/// （Linux では）root か現在のユーザーの所有でなければ `PermissionDenied`。
///
/// 制約（未実装。REPAIR-3）: 検査と使用の間の TOCTOU を閉じるには、ディレクトリ fd を基点に
/// `openat` 系で操作する必要がある。std には無く `sys` の unsafe ラッパーが要るため、
/// 別タスクで扱う。現状は「正規パスの固定＋祖先の権限検査」による緩和にとどまる。
/// Windows の ACL 検査も未実装。
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

/// 状態ルートが信頼できるか検査する（symlink・種別・所有者・書き込みビット）。
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
        if meta.mode() & 0o022 != 0 {
            return Err(err(
                ErrorCode::PermissionDenied,
                "state root must not be writable by group or others",
            ));
        }
        // 所有者検査は euid を取れる Linux のみ（unsafe を増やさないため。他 unix は将来課題）。
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

fn reject_symlink(path: &Path) -> Result<(), TraitError> {
    match fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_symlink() => Err(err(
            ErrorCode::PermissionDenied,
            "state entry must not be a symlink",
        )),
        _ => Ok(()),
    }
}

/// 通常ファイルを上限つきで読む。上限を超えたら `Internal`（無制限確保の防止）。
fn read_limited(path: &Path, max: u64, too_large: &'static str) -> Result<Vec<u8>, TraitError> {
    let file = File::open(path).map_err(|_| internal("failed to open the state file"))?;
    let mut buf = Vec::new();
    file.take(max.saturating_add(1))
        .read_to_end(&mut buf)
        .map_err(|_| internal("failed to read the state file"))?;
    if buf.len() as u64 > max {
        return Err(internal(too_large));
    }
    Ok(buf)
}

/// 同じディレクトリの `<name>.tmp` へ書いて `rename` する（トレイト契約 4 の不可分な書き込み）。
///
/// 全書き込みの唯一の経路。ファイルと親ディレクトリの fsync、一時ファイル名の衝突回避と
/// 残骸掃除は TASK-31.2（#156）で強化する予定で、現状は未実装（REPAIR-3）。
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
    drop(file);
    reject_symlink(&dest)?;
    fs::rename(&tmp, &dest).map_err(|_| internal("failed to replace the state file"))
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
    fn into_record(self, dir_id: &ContainerId) -> Result<StateRecord, TraitError> {
        let corrupted = || internal("state file is inconsistent");
        if self.oci_version != OCI_VERSION {
            return Err(internal("state file has an unsupported ociVersion"));
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

#[cfg(test)]
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
            #[cfg(unix)]
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
    fn oci5_root_path_resolution() {
        assert_eq!(
            resolve_default(true, None).unwrap(),
            PathBuf::from("/run/fandhe-container")
        );
        assert_eq!(
            resolve_default(false, Some(OsString::from("/run/user/1000"))).unwrap(),
            PathBuf::from("/run/user/1000").join("fandhe-container")
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
        fs::create_dir(t.path().join("residue")).unwrap();
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
        fs::create_dir(t.path().join("a")).unwrap();
        assert_eq!(create(&store, "a").id().as_str(), "a");
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

    #[cfg(unix)]
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
    #[cfg(unix)]
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

    #[cfg(unix)]
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
        fs::set_permissions(&real, fs::Permissions::from_mode(0o770)).unwrap();
        assert_eq!(
            code(FileStateStore::open(
                StateRoot::from_override(real).unwrap()
            )),
            "PERMISSION_DENIED"
        );
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
