//! サーバー側のファイル作成入口: 大文字小文字衝突の検出をファイル作成経路へ
//! 組み込む（TASK-19.2・IO-5・#100。検出ロジック本体は TASK-19.1・#99 の
//! [`crate::fs_normalize`]）。
//!
//! # 役割
//! ゲスト（ext4）は大文字小文字を区別するが、ホスト（APFS / NTFS）は区別しない。
//! ゲストが `Foo.txt` と `foo.txt` を同時に作ると、ホスト側で同一ファイルになり
//! 黙った上書き（データ損失）が起きる。[`GuestFileCreator`] は共有ルート配下への
//! ファイル作成の前に、共有の [`CaseCollisionSet`] で衝突を検査し、衝突なら
//! ファイルシステムに触れずに `AlreadyExists`（`case-insensitive path collision`）
//! の構造化エラーを返す。検査から作成までは 1 つの `Mutex` ガードで直列化する
//! ため、同時に届いた大小違いの作成要求の一方だけが成功する。
//!
//! # 呼び出し文脈
//! サーバーの上位層（将来の要求ディスパッチャ）がゲスト相対パスを渡して
//! [`GuestFileCreator::create_file`] を呼び、戻り値の [`AppendFileSink`] を
//! [`crate::writeback::serve_connection`] / [`crate::settings::BoundConnection::serve`]
//! へ書き込み先（[`crate::writeback::BatchSink`]）として渡す。`Arc` で複数接続から
//! 共有する（`Send + Sync`）。
//!
//! # スタブの明示（REPAIR-3）
//! ワイヤー形式（[`crate::payload`]）の `Write` はパスを持たず、ワイヤー上から
//! 作成要求を受ける経路はまだない。フレーム種別・ペイロードの拡張は IO-1 の
//! I/O 契約変更（`PROTOCOL_VERSION` の繰り上げを伴いうる）であり、本モジュールは
//! ワイヤー形式を変えずにサーバー側 API として組み込む。ワイヤーからの作成要求
//! （IO-1・TASK-14 のファイル操作ペイロード拡張）は後続。
//!
//! # 契約と既知の限界
//! - 閉じ込め: ゲストパスを `Path::join` へ渡さず、検証済みコンポーネント
//!   （ホスト上でちょうど 1 個の `Normal`。`\` と `:` は 3 OS とも拒否して挙動を
//!   揃える）だけを扱う。Linux / macOS では共有ルートのディレクトリ fd を起点に
//!   `openat` / `mkdirat`（`O_NOFOLLOW`）で祖先を 1 個ずつ辿り、末端は
//!   `O_CREAT|O_EXCL|O_NOFOLLOW` で作る（[`crate::sys::create_file_beneath`]）。
//!   パスを再解決しないため、祖先の symlink すり替え（TOCTOU）でも共有ルート外へ
//!   は出られない。
//! - Windows は `NtCreateFile` のルート相対ハンドル作成が未実装のため、祖先を
//!   1 階層ずつ「作成 → reparse point を辿らず `FILE_SHARE_DELETE` なしで開いて
//!   保持 → 通常ディレクトリか確認」で固定し、固定済みの祖先の配下へパス結合で
//!   葉を作る（保持ハンドルが改名・削除・差し替えを OS に拒否させる。REPAIR-3）。
//!   共有ルート自体が symlink のときは構築時に 1 回だけ正規化し、以降のパス結合は
//!   その正規パス（保持ハンドルと同じ実体）から始めて元のルートは再解決しない。
//! - 既存項目の取り込み: 索引は API 経由の登録だけでなく、作成のたびに祖先
//!   ディレクトリの実在エントリを毎回読み直して取り込む（別プロセスが後から
//!   足した項目も検出する。走査中の読み取り失敗や、既存項目どうしの大文字小文字衝突は作成を中止する）。共有
//!   ルートに元からある `Foo` があれば `foo/bar` は衝突になる。作成が祖先の
//!   作成後に失敗しても、残った祖先は次回の走査で取り込まれる。走査は名前の
//!   索引化だけに使い、書き込み先の解決には使わない（非 UTF-8 名は取り込めない）。
//! - 索引の確定: 衝突は [`CaseCollisionSet::check_insertable`] で先に検査し、
//!   実ファイルの作成に成功してから登録を確定する。作成が失敗しても索引は
//!   汚れない（末端が既存で `AlreadyExists` のときは実体があるため登録する）。
//! - 件数上限は完全一致の再登録も含めて先に判定する（判定を単純にするため）。
//! - 作成は全接続で直列化される（性能最適化は範囲外）。
//! - Unicode 正規化（NFC / NFD）は行わない（#103・TASK-21）。260 文字超の検証は
//!   TASK-20。

use std::fs::File;
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
use std::fs::OpenOptions;
use std::io::ErrorKind;
use std::path::{Component, Path, PathBuf};
use std::sync::Mutex;

use crate::error::{IoError, IoErrorCode};
use crate::fs_normalize::{CaseCollisionSet, quote_for_message};
use crate::writeback::AppendFileSink;

/// ゲスト相対パスのバイト長の上限（Linux の PATH_MAX 相当。DoS 防止のため
/// 畳み込みやアロケーションの前に検証する）。
pub const MAX_GUEST_PATH_BYTES: usize = 4096;

/// 索引へ登録できるパス件数の上限の最大値（`fs_normalize` は件数上限を呼び出し側の
/// 責務としているため本型が持つ）。
pub const MAX_TRACKED_GUEST_PATHS: usize = 1 << 20;

/// 共有ルート配下へのファイル作成に大文字小文字衝突検出を組み込む入口
/// （モジュール doc 参照。IO-5・TASK-19.2）。
pub struct GuestFileCreator {
    root: PathBuf,
    /// パス結合が必要な Windows の作成・走査が使う、symlink 解決済みの共有ルート。
    /// 構築時に 1 回だけ解決し、`root` のパスは再解決しない（`root` 自体が symlink
    /// でも、構築後に参照先を差し替えて共有範囲外へ書かせない。IO-5）。Linux /
    /// macOS はハンドル起点のため `root` と同値で、パス解決には使われない。
    base: PathBuf,
    /// 構築時に開いた共有ルートのディレクトリハンドル。走査・作成の起点はこの
    /// ハンドルで、`root` のパスは開き直さない（検証後にパスや親のエントリが
    /// 差し替えられても共有範囲外へ出ない。security.md の境界。IO-5）。
    /// Windows ではこのハンドルを `FILE_SHARE_DELETE` なしで保持し、ルートと祖先の
    /// 改名・削除を OS に拒否させる。
    root_dir: File,
    max_tracked: usize,
    index: Mutex<IndexState>,
}

/// 衝突索引。
struct IndexState {
    set: CaseCollisionSet,
}

fn invalid(message: &str) -> IoError {
    IoError::new(IoErrorCode::InvalidArgument, message)
}

fn poisoned() -> IoError {
    IoError::new(IoErrorCode::Internal, "guest file index lock is poisoned")
}

/// 単一のゲストパスコンポーネントがホスト上でちょうど 1 個の `Normal` に
/// なることを確かめる（`..`・空・`.`・`\`・`:`・NUL を拒否する）。
fn validate_host_component(component: &str) -> Result<(), IoError> {
    if component.contains(['\\', ':', '\0']) {
        return Err(invalid(
            "guest path component must not contain '\\', ':' or NUL",
        ));
    }
    let mut parts = Path::new(component).components();
    match (parts.next(), parts.next()) {
        (Some(Component::Normal(_)), None) => Ok(()),
        _ => Err(invalid("guest path component must be a single normal name")),
    }
}

impl GuestFileCreator {
    /// `root`（共有ルート。ディレクトリであること）を起点に作成する入口を作る。
    /// root は信頼できる設定値として扱い、root 自体が symlink でも許す（構築時に
    /// 1 回だけ辿って開き、以降はそのハンドルを起点にする）。
    pub fn new(root: PathBuf) -> Result<Self, IoError> {
        Self::with_max_tracked_paths(root, MAX_TRACKED_GUEST_PATHS)
    }

    /// 索引の件数上限（`1..=`[`MAX_TRACKED_GUEST_PATHS`]）を指定して作る。
    pub fn with_max_tracked_paths(root: PathBuf, max_tracked: usize) -> Result<Self, IoError> {
        if max_tracked == 0 || max_tracked > MAX_TRACKED_GUEST_PATHS {
            return Err(invalid("max tracked guest paths is out of range"));
        }
        let base = resolve_root_base(&root).map_err(|err| {
            IoError::new(
                IoErrorCode::InvalidArgument,
                format!("guest file root is not accessible ({:?})", err.kind()),
            )
        })?;
        let root_dir = open_root_handle(&base).map_err(|err| {
            IoError::new(
                IoErrorCode::InvalidArgument,
                format!("guest file root is not accessible ({:?})", err.kind()),
            )
        })?;
        let meta = root_dir.metadata().map_err(|err| {
            IoError::new(
                IoErrorCode::InvalidArgument,
                format!("guest file root is not accessible ({:?})", err.kind()),
            )
        })?;
        if !meta.is_dir() {
            return Err(invalid("guest file root must be a directory"));
        }
        Ok(Self {
            root,
            base,
            root_dir,
            max_tracked,
            index: Mutex::new(IndexState {
                set: CaseCollisionSet::new(),
            }),
        })
    }

    /// 共有ルート。
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// 索引に登録済みのパス件数。
    pub fn tracked_len(&self) -> Result<usize, IoError> {
        Ok(self.index.lock().map_err(|_| poisoned())?.set.len())
    }

    /// ゲスト相対パス `guest_path`（`/` 区切り）のファイルを新規作成して sink を返す。
    ///
    /// 大文字小文字だけが違う既存パスと衝突する場合は `AlreadyExists`
    /// （`case-insensitive path collision: ...`）、同一パスが既に存在する場合は
    /// `AlreadyExists`（`guest file already exists: ...`）、不正なパスは
    /// `InvalidArgument`、索引の件数上限超過は `ResourceExhausted`
    /// （IO-5・TASK-19.2）。
    pub fn create_file(&self, guest_path: &str) -> Result<AppendFileSink, IoError> {
        if guest_path.len() > MAX_GUEST_PATH_BYTES {
            return Err(invalid("guest path is too long"));
        }
        // 索引を汚さないよう、ロックと try_insert の前にホスト側の検証を済ませる。
        let components: Vec<&str> = guest_path.split('/').collect();
        for component in &components {
            validate_host_component(component)?;
        }

        // 検査から作成・登録までを同じガードで直列化する。
        let mut state = self.index.lock().map_err(|_| poisoned())?;
        let state = &mut *state;
        let (ancestors, leaf) = match components.split_last() {
            Some((leaf, ancestors)) => (ancestors, *leaf),
            None => return Err(invalid("guest path is empty")),
        };
        // 共有ルートに元からある項目（表記違いの祖先など）を先に索引へ取り込む。
        self.seed_existing(state, ancestors)?;
        let set = &mut state.set;
        if set.len() >= self.max_tracked {
            return Err(IoError::new(
                IoErrorCode::ResourceExhausted,
                "too many tracked guest paths",
            ));
        }
        // 索引は変更せず衝突だけ検査し、実ファイルの作成に成功してから登録を
        // 確定する（作成失敗で実体のないパスが索引に残らないようにする）。
        set.check_insertable(guest_path)?;

        let file = match create_beneath(&self.root_dir, &self.base, ancestors, leaf) {
            Ok(file) => file,
            Err(CreateError::Exists) => {
                // 実体が既に存在する。索引にも確定させたうえで報告する。
                let _ = set.try_insert(guest_path);
                return Err(IoError::new(
                    IoErrorCode::AlreadyExists,
                    format!(
                        "guest file already exists: {}",
                        quote_for_message(guest_path)
                    ),
                ));
            }
            // 祖先だけ作られて葉が失敗しても、次回の作成で走査して取り込み直す。
            Err(CreateError::Other(err)) => return Err(err),
        };
        set.try_insert(guest_path)?;
        AppendFileSink::new(file)
    }

    /// `ancestors` に沿って実在するディレクトリの項目を、作成のたびに読み直して
    /// 索引へ取り込む（表記どおりの実在ディレクトリだけを辿る。symlink は辿らない）。
    /// 別プロセスが共有ルートへ後から追加した項目も検出するため、走査済みの
    /// 印は持たない。走査は保持したルートのハンドル起点で行い（Linux / macOS は
    /// 各階層もハンドル相対で開く）、索引化専用で作成先の解決には使わない。
    /// 件数上限超過は `ResourceExhausted`、読み取りの失敗は `Internal`、
    /// 既存項目どうしの大文字小文字衝突は `AlreadyExists`
    /// （IO-5 の検査を完了できないまま作成へ進まない。fail-closed）。
    fn seed_existing(&self, state: &mut IndexState, ancestors: &[&str]) -> Result<(), IoError> {
        let mut cursor = ScanCursor::root(&self.root_dir, &self.base)?;
        let mut prefix = String::new();
        for level in 0..=ancestors.len() {
            let entries = cursor.read_entries(self.max_tracked)?;
            for name in entries {
                let Some(name) = name.to_str() else { continue };
                if state.set.len() >= self.max_tracked {
                    return Err(IoError::new(
                        IoErrorCode::ResourceExhausted,
                        "too many tracked guest paths",
                    ));
                }
                match state.set.try_insert(&format!("{prefix}{name}")) {
                    Ok(()) => {}
                    // 形式不正の名前（ホストで表現できない等）は索引化できないだけで
                    // 無視する。
                    Err(err) if err.code() == IoErrorCode::InvalidArgument => {}
                    // 共有ルートに元から大文字小文字違いの項目が併存している等、
                    // 衝突検出を完了できない状態は走査順で索引が変わるため、
                    // 握りつぶさず作成を中止する（fail-closed。IO-5）。
                    Err(err) => return Err(err),
                }
            }
            let Some(component) = ancestors.get(level) else {
                break;
            };
            // 未作成・通常ファイル・symlink の祖先より下に取り込む項目は無い
            // （作成時に新設される、または作成側が拒否する）。
            match cursor.descend(component)? {
                Some(next) => cursor = next,
                None => return Ok(()),
            }
            prefix.push_str(component);
            prefix.push('/');
        }
        Ok(())
    }
}

/// パス結合に使う共有ルートを決める。Windows では symlink を構築時に解決した
/// 正規パスを返し（以降の作成・走査は元の `root` を再解決しない）、それ以外は
/// ハンドル起点のため `root` をそのまま返す。
#[cfg(windows)]
fn resolve_root_base(root: &Path) -> std::io::Result<PathBuf> {
    std::fs::canonicalize(root)
}

#[cfg(not(windows))]
fn resolve_root_base(root: &Path) -> std::io::Result<PathBuf> {
    Ok(root.to_path_buf())
}

/// 共有ルートを開く（symlink は構築時のこの 1 回だけ辿る）。Windows では
/// `FILE_FLAG_BACKUP_SEMANTICS` でディレクトリを開き、`FILE_SHARE_DELETE` を
/// 付けずに共有してルートと祖先の改名・削除を拒否させる。
#[cfg(not(windows))]
fn open_root_handle(root: &Path) -> std::io::Result<File> {
    File::open(root)
}

#[cfg(windows)]
fn open_root_handle(root: &Path) -> std::io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    // FILE_FLAG_BACKUP_SEMANTICS
    const FLAGS: u32 = 0x0200_0000;
    // FILE_SHARE_READ | FILE_SHARE_WRITE（FILE_SHARE_DELETE は含めない）
    const SHARE: u32 = 0x1 | 0x2;
    OpenOptions::new()
        .read(true)
        .custom_flags(FLAGS)
        .share_mode(SHARE)
        .open(root)
}

/// 走査位置（Linux / macOS はディレクトリハンドル）。
#[cfg(any(target_os = "linux", target_os = "macos"))]
struct ScanCursor(File);

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl ScanCursor {
    fn root(root_dir: &File, _root: &Path) -> Result<Self, IoError> {
        root_dir
            .try_clone()
            .map(Self)
            .map_err(|err| internal("failed to scan guest directory", err.kind()))
    }

    /// ディレクトリハンドルから直接（`fdopendir`）エントリ名を読む。パスを
    /// 再解決しないため macOS でも動き、ルートの差し替えにも影響されない。
    fn read_entries(&self, max_entries: usize) -> Result<Vec<std::ffi::OsString>, IoError> {
        use crate::sys::{ReadDirError, read_dir_names};
        read_dir_names(&self.0, max_entries).map_err(|err| match err {
            ReadDirError::TooMany => IoError::new(
                IoErrorCode::ResourceExhausted,
                "too many tracked guest paths",
            ),
            ReadDirError::Io(kind) => internal("failed to scan guest directory", kind),
        })
    }

    fn descend(&self, name: &str) -> Result<Option<Self>, IoError> {
        use crate::sys::{BeneathError, open_dir_beneath};
        match open_dir_beneath(&self.0, name) {
            Ok(dir) => Ok(Some(Self(dir))),
            Err(BeneathError::AncestorNotDirectory) => Ok(None),
            Err(BeneathError::Io(ErrorKind::NotFound)) => Ok(None),
            Err(BeneathError::Io(kind)) => Err(internal("failed to inspect guest directory", kind)),
            Err(BeneathError::AlreadyExists) => Err(internal(
                "failed to inspect guest directory",
                ErrorKind::Other,
            )),
        }
    }
}

/// Windows 等のフォールバック（パス走査）。ルートは `open_root_handle` の
/// 共有拒否で改名・削除されないため、ルート配下のパス解決は範囲内に留まる。
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
struct ScanCursor(PathBuf);

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
impl ScanCursor {
    fn root(_root_dir: &File, root: &Path) -> Result<Self, IoError> {
        Ok(Self(root.to_path_buf()))
    }

    fn read_entries(&self, max_entries: usize) -> Result<Vec<std::ffi::OsString>, IoError> {
        let mut names = Vec::new();
        let dir = std::fs::read_dir(&self.0)
            .map_err(|err| internal("failed to scan guest directory", err.kind()))?;
        for entry in dir {
            let entry =
                entry.map_err(|err| internal("failed to scan guest directory", err.kind()))?;
            if names.len() >= max_entries {
                return Err(IoError::new(
                    IoErrorCode::ResourceExhausted,
                    "too many tracked guest paths",
                ));
            }
            names.push(entry.file_name());
        }
        Ok(names)
    }

    fn descend(&self, name: &str) -> Result<Option<Self>, IoError> {
        let next = self.0.join(name);
        match std::fs::symlink_metadata(&next) {
            Ok(meta) if meta.is_dir() => Ok(Some(Self(next))),
            Err(err) if err.kind() == ErrorKind::NotFound => Ok(None),
            Err(err) => Err(internal("failed to inspect guest directory", err.kind())),
            Ok(_) => Ok(None),
        }
    }
}

/// [`create_beneath`] の失敗種別。
enum CreateError {
    /// 末端が既に存在する。
    Exists,
    /// 構造化済みのその他のエラー。
    Other(IoError),
}

fn internal(context: &str, kind: ErrorKind) -> IoError {
    // ホストのパスは載せず kind だけを載せる（情報漏洩防止）。
    IoError::new(IoErrorCode::Internal, format!("{context} ({kind:?})"))
}

/// ルートのディレクトリハンドル起点・symlink 非追従で祖先を開き（無ければ作り）
/// 末端を新規作成する（Linux / macOS。`openat` 系。TOCTOU 防止。
/// [`crate::sys::create_file_beneath`]）。
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn create_beneath(
    root_dir: &File,
    _root: &Path,
    ancestors: &[&str],
    leaf: &str,
) -> Result<File, CreateError> {
    use crate::sys::{BeneathError, create_file_beneath};
    create_file_beneath(root_dir, ancestors, leaf).map_err(|err| match err {
        BeneathError::AlreadyExists => CreateError::Exists,
        BeneathError::AncestorNotDirectory => {
            CreateError::Other(invalid("guest path ancestor is not a directory"))
        }
        BeneathError::Io(kind) => CreateError::Other(internal("failed to create guest file", kind)),
    })
}

/// Windows 等のフォールバック。ルート直下から 1 階層ずつ、作成（`create_dir`）→
/// 「reparse point を辿らず（`FILE_FLAG_OPEN_REPARSE_POINT`）・`FILE_SHARE_DELETE`
/// なしで」ディレクトリを開いて保持→ reparse point / 非ディレクトリでないことを
/// 確認、の順で祖先を固定する。保持中のハンドルは改名・削除・差し替えを OS が
/// 拒否するため、以降のパス結合による解決は固定済みの祖先の配下に留まる
/// （ルートハンドルと同じ方式。TOCTOU 防止。IO-5・REPAIR-3）。`NtCreateFile` の
/// ルート相対ハンドル作成への置き換えは後続。
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn create_beneath(
    _root_dir: &File,
    root: &Path,
    ancestors: &[&str],
    leaf: &str,
) -> Result<File, CreateError> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    // FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT
    const FLAGS: u32 = 0x0200_0000 | 0x0020_0000;
    // FILE_SHARE_READ | FILE_SHARE_WRITE（FILE_SHARE_DELETE なし）
    const SHARE: u32 = 0x1 | 0x2;
    // FILE_ATTRIBUTE_REPARSE_POINT
    const REPARSE: u32 = 0x400;

    let mut path = root.to_path_buf();
    // 固定済みの祖先ハンドル（葉の作成が終わるまで保持する）。
    let mut pinned: Vec<File> = Vec::with_capacity(ancestors.len());
    for name in ancestors {
        path.push(name);
        match std::fs::create_dir(&path) {
            Ok(()) => {}
            Err(err) if err.kind() == ErrorKind::AlreadyExists => {}
            Err(err) => {
                return Err(CreateError::Other(internal(
                    "failed to create guest file",
                    err.kind(),
                )));
            }
        }
        let dir = OpenOptions::new()
            .read(true)
            .custom_flags(FLAGS)
            .share_mode(SHARE)
            .open(&path)
            .map_err(|err| {
                CreateError::Other(internal("failed to create guest file", err.kind()))
            })?;
        let meta = dir.metadata().map_err(|err| {
            CreateError::Other(internal("failed to create guest file", err.kind()))
        })?;
        if !meta.is_dir() || meta.file_attributes() & REPARSE != 0 {
            return Err(CreateError::Other(invalid(
                "guest path ancestor is not a directory",
            )));
        }
        pinned.push(dir);
    }
    let result = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path.join(leaf))
        .map_err(|err| {
            if err.kind() == ErrorKind::AlreadyExists {
                CreateError::Exists
            } else {
                CreateError::Other(internal("failed to create guest file", err.kind()))
            }
        });
    drop(pinned);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    struct Tmp(PathBuf);
    impl Tmp {
        fn new() -> Self {
            static N: AtomicU32 = AtomicU32::new(0);
            let p = std::env::temp_dir().join(format!(
                "fcio-gf-{}-{}",
                std::process::id(),
                N.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&p).expect("temp dir");
            Self(p)
        }
    }
    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn entries(p: &Path) -> usize {
        std::fs::read_dir(p).map(|d| d.count()).unwrap_or(0)
    }

    #[test]
    fn io5_case_only_second_create_is_rejected() {
        let t = Tmp::new();
        let c = GuestFileCreator::new(t.0.clone()).expect("creator");
        c.create_file("Foo.txt").expect("first");
        let err = c.create_file("foo.txt").err().expect("must collide");
        assert_eq!(err.code(), IoErrorCode::AlreadyExists);
        assert!(err.message().starts_with("case-insensitive path collision"));
        assert_eq!(entries(&t.0), 1);
    }

    #[test]
    fn io5_identical_path_reports_exists_not_collision() {
        let t = Tmp::new();
        let c = GuestFileCreator::new(t.0.clone()).expect("creator");
        c.create_file("a").expect("first");
        let err = c.create_file("a").err().expect("must fail");
        assert_eq!(err.code(), IoErrorCode::AlreadyExists);
        assert!(err.message().starts_with("guest file already exists"));
    }

    #[test]
    fn io5_depth_differing_collision_creates_no_directory() {
        let t = Tmp::new();
        let c = GuestFileCreator::new(t.0.clone()).expect("creator");
        c.create_file("a").expect("first");
        let err = c.create_file("A/b").err().expect("must collide");
        assert!(err.message().starts_with("case-insensitive path collision"));
        assert_eq!(entries(&t.0), 1);
    }

    #[test]
    fn io5_rejected_paths_do_not_pollute_index_or_fs() {
        let t = Tmp::new();
        let c = GuestFileCreator::new(t.0.clone()).expect("creator");
        let long = "x".repeat(MAX_GUEST_PATH_BYTES + 1);
        for p in [
            "..",
            "a/../b",
            "/abs",
            "a\\b",
            "C:x",
            "a:b",
            "",
            ".",
            "a//b",
            "a\0b",
            long.as_str(),
        ] {
            let err = c.create_file(p).err().expect("must be rejected");
            assert_eq!(err.code(), IoErrorCode::InvalidArgument, "path {p:?}");
        }
        assert_eq!(c.tracked_len().expect("len"), 0);
        assert_eq!(entries(&t.0), 0);
    }

    #[test]
    fn io5_tracked_limit_and_range() {
        let t = Tmp::new();
        let c = GuestFileCreator::with_max_tracked_paths(t.0.clone(), 1).expect("creator");
        c.create_file("a").expect("first");
        let err = c.create_file("b").err().expect("limit");
        assert_eq!(err.code(), IoErrorCode::ResourceExhausted);
        for n in [0, MAX_TRACKED_GUEST_PATHS + 1] {
            let err = GuestFileCreator::with_max_tracked_paths(t.0.clone(), n)
                .err()
                .expect("range");
            assert_eq!(err.code(), IoErrorCode::InvalidArgument);
        }
    }

    #[test]
    fn io5_root_must_be_directory() {
        let t = Tmp::new();
        let f = t.0.join("f");
        std::fs::write(&f, b"x").expect("write");
        let err = GuestFileCreator::new(f).err().expect("not a dir");
        assert_eq!(err.code(), IoErrorCode::InvalidArgument);
    }

    #[cfg(unix)]
    #[test]
    fn io5_symlink_ancestor_is_rejected() {
        let t = Tmp::new();
        let outside = Tmp::new();
        let root = t.0.join("root");
        std::fs::create_dir(&root).expect("root");
        std::os::unix::fs::symlink(&outside.0, root.join("link")).expect("symlink");
        let c = GuestFileCreator::new(root).expect("creator");
        let err = c.create_file("link/f").err().expect("must reject");
        assert_eq!(err.code(), IoErrorCode::InvalidArgument);
        assert_eq!(entries(&outside.0), 0);
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn io5_failed_create_does_not_pollute_index() {
        let t = Tmp::new();
        let c = GuestFileCreator::new(t.0.clone()).expect("creator");
        // a は通常ファイルなので a/b の作成は祖先エラーで失敗する。
        std::fs::write(t.0.join("a"), b"x").expect("write");
        let err = c.create_file("a/b").err().expect("must fail");
        assert_eq!(err.code(), IoErrorCode::InvalidArgument);
        // 取り込まれるのは実在する `a` だけで、失敗した `a/b` は登録されない。
        assert_eq!(c.tracked_len().expect("len"), 1);
    }

    #[cfg(unix)]
    #[test]
    fn io5_symlink_leaf_is_not_followed() {
        let t = Tmp::new();
        let outside = Tmp::new();
        let target = outside.0.join("victim");
        std::os::unix::fs::symlink(&target, t.0.join("f")).expect("symlink");
        let c = GuestFileCreator::new(t.0.clone()).expect("creator");
        let err = c.create_file("f").err().expect("must reject");
        assert_eq!(err.code(), IoErrorCode::AlreadyExists);
        assert!(!target.exists());
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn io5_preexisting_directory_case_variant_collides() {
        let t = Tmp::new();
        std::fs::create_dir(t.0.join("Foo")).expect("dir");
        let c = GuestFileCreator::new(t.0.clone()).expect("creator");
        let err = c.create_file("foo/bar").err().expect("must collide");
        assert_eq!(err.code(), IoErrorCode::AlreadyExists);
        assert!(err.message().starts_with("case-insensitive path collision"));
        assert_eq!(entries(&t.0.join("Foo")), 0);
        c.create_file("Foo/bar").expect("same spelling is fine");
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn io5_ancestors_left_after_leaf_failure_are_indexed() {
        let t = Tmp::new();
        let c = GuestFileCreator::new(t.0.clone()).expect("creator");
        // 葉が長すぎて作成に失敗する（祖先 `a` は作成済みで残る）。
        let long = "x".repeat(300);
        let err = c
            .create_file(&format!("a/{long}"))
            .err()
            .expect("must fail");
        assert_eq!(err.code(), IoErrorCode::Internal);
        assert!(t.0.join("a").is_dir());
        let err = c.create_file("A/b").err().expect("must collide");
        assert!(err.message().starts_with("case-insensitive path collision"));
        c.create_file("a/b").expect("real spelling still works");
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    #[test]
    fn io5_fallback_creates_paths_with_ancestors() {
        let t = Tmp::new();
        let c = GuestFileCreator::new(t.0.clone()).expect("creator");
        c.create_file("a/b/c").expect("nested create");
        assert!(t.0.join("a").join("b").join("c").is_file());
        c.create_file("top").expect("root-level file is allowed");
        let err = c.create_file("A/x").err().expect("must collide");
        assert!(err.message().starts_with("case-insensitive path collision"));
    }

    /// 別プロセスが作成後に共有ルートへ足した項目とも衝突を検出する。
    #[test]
    fn io5_externally_added_entry_is_detected_on_later_create() {
        let t = Tmp::new();
        let c = GuestFileCreator::new(t.0.clone()).expect("creator");
        c.create_file("first").expect("first");
        std::fs::write(t.0.join("Foo"), b"x").expect("external");
        let err = c.create_file("foo").err().expect("must collide");
        assert_eq!(err.code(), IoErrorCode::AlreadyExists);
        assert!(err.message().starts_with("case-insensitive path collision"));
        assert_eq!(entries(&t.0), 2);
    }

    /// 走査を完了できないときは索引不完全のまま作成せず構造化エラーで中止する。
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn io5_scan_failure_aborts_create() {
        let t = Tmp::new();
        let root = t.0.join("root");
        std::fs::create_dir(&root).expect("root");
        let c = GuestFileCreator::new(root.clone()).expect("creator");
        std::fs::remove_dir(&root).expect("remove root");
        let err = c.create_file("a").err().expect("must abort");
        assert_eq!(err.code(), IoErrorCode::Internal);
        assert_eq!(c.tracked_len().expect("len"), 0);
    }

    /// 構築後にルートのパスを範囲外への symlink へ差し替えても、作成は保持した
    /// ハンドルの元のディレクトリ内に留まる（IO-5・Codex P0 指摘）。
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn io5_swapped_root_path_does_not_escape() {
        let t = Tmp::new();
        let outside = Tmp::new();
        let root = t.0.join("root");
        std::fs::create_dir(&root).expect("root");
        let c = GuestFileCreator::new(root.clone()).expect("creator");
        let moved = t.0.join("moved");
        std::fs::rename(&root, &moved).expect("rename");
        std::os::unix::fs::symlink(&outside.0, &root).expect("symlink");
        c.create_file("sub/f").expect("create");
        assert_eq!(entries(&outside.0), 0);
        assert!(moved.join("sub").join("f").exists());
    }

    /// 共有ルートに大文字小文字違いが元から併存する場合は、走査順に依らず作成を
    /// 中止する（IO-5。ケース区別の FS でのみ作れるため Linux 限定）。
    #[cfg(target_os = "linux")]
    #[test]
    fn io5_preexisting_colliding_entries_abort_create() {
        let t = Tmp::new();
        std::fs::write(t.0.join("Foo"), b"x").expect("Foo");
        std::fs::write(t.0.join("foo"), b"x").expect("foo");
        let c = GuestFileCreator::new(t.0.clone()).expect("creator");
        let err = c.create_file("unrelated").err().expect("must abort");
        assert_eq!(err.code(), IoErrorCode::AlreadyExists);
        assert!(err.message().starts_with("case-insensitive path collision"));
        assert_eq!(entries(&t.0), 2);
    }

    /// Windows: root 自体が symlink でも、構築後に参照先を差し替えて範囲外へ
    /// 書けない（作成は構築時に解決した実体に留まる。IO-5。symlink 作成権限が
    /// 無い環境では skip 相当で return する）。
    #[cfg(windows)]
    #[test]
    fn io5_windows_swapped_root_symlink_does_not_escape() {
        let t = Tmp::new();
        let real = t.0.join("real");
        let outside = Tmp::new();
        let link = t.0.join("link");
        std::fs::create_dir(&real).expect("real");
        if std::os::windows::fs::symlink_dir(&real, &link).is_err() {
            return;
        }
        let c = GuestFileCreator::new(link.clone()).expect("creator");
        let _ = std::fs::remove_dir(&link);
        let _ = std::os::windows::fs::symlink_dir(&outside.0, &link);
        c.create_file("sub/f").expect("create");
        assert_eq!(entries(&outside.0), 0);
        assert!(real.join("sub").join("f").exists());
    }

    #[test]
    fn io5_creator_is_send_sync() {
        fn assert_ss<T: Send + Sync>() {}
        assert_ss::<GuestFileCreator>();
    }
}
