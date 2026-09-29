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
//!   揃える）だけを 1 個ずつ `push` する。祖先は `symlink_metadata` で確認し、
//!   symlink・非ディレクトリを拒否する。末端は `create_new`（O_EXCL 相当）で
//!   作り、末端の symlink を辿らない。
//! - 祖先の TOCTOU: 検査と作成の間にホスト上の別プロセスがディレクトリを
//!   symlink へすり替える競合は防げない。openat / `RESOLVE_BENEATH` 相当による
//!   完全な閉じ込めは後続（`sys` モジュール経由）。
//! - 索引と FS の食い違い: [`CaseCollisionSet`] に削除 API は無く、衝突検査通過後の
//!   FS 操作が失敗しても登録は残る。同じ表記の再試行は受理され、大小違いの表記は
//!   衝突として拒否される（過検出側。削除・rename の追跡は TASK-21 以降）。
//! - 件数上限は完全一致の再登録も含めて先に判定する（判定を単純にするため）。
//! - 作成は全接続で直列化される（性能最適化は範囲外）。
//! - Unicode 正規化（NFC / NFD）は行わない（#103・TASK-21）。260 文字超の検証は
//!   TASK-20。

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
    max_tracked: usize,
    index: Mutex<CaseCollisionSet>,
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
    /// root は信頼できる設定値として扱い、root 自体が symlink でも許す。
    pub fn new(root: PathBuf) -> Result<Self, IoError> {
        Self::with_max_tracked_paths(root, MAX_TRACKED_GUEST_PATHS)
    }

    /// 索引の件数上限（`1..=`[`MAX_TRACKED_GUEST_PATHS`]）を指定して作る。
    pub fn with_max_tracked_paths(root: PathBuf, max_tracked: usize) -> Result<Self, IoError> {
        if max_tracked == 0 || max_tracked > MAX_TRACKED_GUEST_PATHS {
            return Err(invalid("max tracked guest paths is out of range"));
        }
        let meta = std::fs::metadata(&root).map_err(|err| {
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
            max_tracked,
            index: Mutex::new(CaseCollisionSet::new()),
        })
    }

    /// 共有ルート。
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// 索引に登録済みのパス件数。
    pub fn tracked_len(&self) -> Result<usize, IoError> {
        Ok(self.index.lock().map_err(|_| poisoned())?.len())
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

        // 検査から作成までを同じガードで直列化する。
        let mut set = self.index.lock().map_err(|_| poisoned())?;
        if set.len() >= self.max_tracked {
            return Err(IoError::new(
                IoErrorCode::ResourceExhausted,
                "too many tracked guest paths",
            ));
        }
        set.try_insert(guest_path)?;

        let mut host = self.root.clone();
        let last = components.len().saturating_sub(1);
        for (i, component) in components.iter().enumerate() {
            host.push(component);
            if i < last {
                ensure_real_directory(&host)?;
            }
        }

        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&host)
            .map_err(|err| {
                if err.kind() == ErrorKind::AlreadyExists {
                    IoError::new(
                        IoErrorCode::AlreadyExists,
                        format!(
                            "guest file already exists: {}",
                            quote_for_message(guest_path)
                        ),
                    )
                } else {
                    // ホストのパスは載せず kind だけを載せる（情報漏洩防止）。
                    IoError::new(
                        IoErrorCode::Internal,
                        format!("failed to create guest file ({:?})", err.kind()),
                    )
                }
            })?;
        AppendFileSink::new(file)
    }
}

/// `dir` が実ディレクトリであることを保証する（無ければ作る。symlink・非
/// ディレクトリは拒否する）。
fn ensure_real_directory(dir: &Path) -> Result<(), IoError> {
    let check = |dir: &Path| -> Result<bool, IoError> {
        match std::fs::symlink_metadata(dir) {
            Ok(meta) if meta.is_dir() => Ok(true),
            Ok(_) => Err(invalid("guest path ancestor is not a directory")),
            Err(err) if err.kind() == ErrorKind::NotFound => Ok(false),
            Err(err) => Err(IoError::new(
                IoErrorCode::Internal,
                format!("failed to inspect guest path ancestor ({:?})", err.kind()),
            )),
        }
    };
    if check(dir)? {
        return Ok(());
    }
    match std::fs::create_dir(dir) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == ErrorKind::AlreadyExists => {
            if check(dir)? {
                Ok(())
            } else {
                Err(invalid("guest path ancestor is not a directory"))
            }
        }
        Err(err) => Err(IoError::new(
            IoErrorCode::Internal,
            format!("failed to create guest directory ({:?})", err.kind()),
        )),
    }
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

    #[test]
    fn io5_creator_is_send_sync() {
        fn assert_ss<T: Send + Sync>() {}
        assert_ss::<GuestFileCreator>();
    }
}
