//! ネットワーク定義ストアの Linux 実装（fd 起点の検査・flock・staging と rename による原子的な作成と削除。NET-6・#3059）。
//!
//! 役割と契約は親モジュール `network_store` の doc を参照。ここは std だけで書き、新しい FFI 宣言と `unsafe` は
//! 足さない（実効 uid は既存の `sys::effective_uid`）。親ディレクトリの fd 起点の操作は
//! `/proc/self/fd/<fd>/<名前>` で行う（前例: `sys::reopen_append`・core の `audit_log`）。名前は
//! `NetworkName`（`/`・NUL・`..` を作れない）・定数・`read_dir` の項目だけで、外部入力を直接連結しない。

use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, Read};
use std::marker::PhantomData;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use super::definition::{DEFINITION_MAX_BYTES, MAX_NETWORKS, is_reserved_network_name};
use super::{
    DEFAULT_LOCK_TIMEOUT, DIR_MODE, FILE_MODE, LOCK_HANDOFF_GAP, LOCK_RETRY, NetworkDefinition,
    NetworkListing, check_dir_meta, check_file_meta,
};
use crate::error::{NetError, NetErrorCode};
use crate::instrument::{NetOpKind, NetOpRecorder, NoopNetOpRecorder, record_net_op};
use crate::network::NetworkName;
use crate::sys;

const NETWORKS_DIR: &str = "@networks";
const LOCK_FILE: &str = "@lock";
const DEFINITION_FILE: &str = "definition";
const STAGING_PREFIX: &str = "@staging-";
const REMOVING_PREFIX: &str = "@removing-";
/// `@networks` の走査で許す項目数（定義の上限 + 残骸の余裕分）。
const SCAN_LIMIT: usize = MAX_NETWORKS + 64;
/// ネットワークのディレクトリの走査で許す項目数（これを超えれば確実に余分な項目がある）。
/// 正規の項目は definition・@lock・realized・realized.intent・members・members-intent・pending-reclaim の 7 つ。
const NET_DIR_SCAN_LIMIT: usize = 16;
/// 期限の上限（`Instant` の加算が溢れないよう丸める）。
const MAX_TIMEOUT: Duration = Duration::from_secs(24 * 60 * 60);

const FLAGS_DIR: i32 = sys::O_DIRECTORY | sys::O_NOFOLLOW;
const FLAGS_FILE: i32 = sys::O_NOFOLLOW | sys::O_NOCTTY | sys::O_NONBLOCK;

static LAST_RELEASE: Mutex<Option<Instant>> = Mutex::new(None);
static STAGE_SEQ: AtomicU64 = AtomicU64::new(0);

fn err(code: NetErrorCode, msg: &'static str) -> NetError {
    NetError::new(code, msg)
}

/// io エラーを分類へ写す。メッセージは固定で、errno・パスを載せない。
fn map_io(e: &io::Error, msg: &'static str) -> NetError {
    let code = match e.raw_os_error() {
        Some(c) if c == sys::ELOOP || c == sys::ENOTDIR => NetErrorCode::FailedPrecondition,
        Some(c) if c == sys::EACCES || c == sys::EPERM => NetErrorCode::PermissionDenied,
        Some(c) if c == sys::ENOENT => NetErrorCode::NotFound,
        Some(c) if c == sys::EEXIST => NetErrorCode::AlreadyExists,
        Some(c) if c == sys::EMFILE || c == sys::ENFILE || c == sys::ENOMEM => {
            NetErrorCode::ResourceExhausted
        }
        _ => NetErrorCode::Internal,
    };
    NetError::new(code, msg)
}

fn note_release() {
    if let Ok(mut g) = LAST_RELEASE.lock() {
        *g = Some(Instant::now());
    }
}

fn wait_handoff() {
    let last = LAST_RELEASE.lock().ok().and_then(|g| *g);
    if let Some(at) = last {
        let elapsed = at.elapsed();
        if elapsed < LOCK_HANDOFF_GAP {
            std::thread::sleep(LOCK_HANDOFF_GAP - elapsed);
        }
    }
}

/// flock を期限つきで取る（`try_lock` の再試行。REPAIR-5）。
fn acquire(
    file: &File,
    shared: bool,
    timeout: Duration,
    timeout_msg: &'static str,
) -> Result<(), NetError> {
    wait_handoff();
    let deadline = Instant::now() + timeout.min(MAX_TIMEOUT);
    loop {
        let r = if shared {
            file.try_lock_shared()
        } else {
            file.try_lock()
        };
        match r {
            Ok(()) => return Ok(()),
            Err(std::fs::TryLockError::WouldBlock) => {
                if Instant::now() >= deadline {
                    return Err(err(NetErrorCode::Timeout, timeout_msg));
                }
                std::thread::sleep(LOCK_RETRY);
            }
            Err(std::fs::TryLockError::Error(_)) => {
                return Err(err(NetErrorCode::Internal, "failed to lock network store"));
            }
        }
    }
}

/// 検査済みのディレクトリ fd。子要素はこの fd 起点で開く。
#[derive(Debug)]
struct Dir {
    file: File,
}

impl Dir {
    fn path(&self, name: &str) -> PathBuf {
        PathBuf::from(format!("/proc/self/fd/{}/{name}", self.file.as_raw_fd()))
    }

    /// 子ディレクトリを `O_NOFOLLOW` で開き、権限・所有者を検査する。
    fn open_subdir(&self, name: &str) -> Result<Dir, NetError> {
        open_dir_checked(&self.path(name))
    }

    fn sync(&self) -> Result<(), NetError> {
        self.file
            .sync_all()
            .map_err(|e| map_io(&e, "failed to sync network store directory"))
    }

    /// 項目名を `limit` 件まで集める。超えたら `ResourceExhausted`。
    fn entries(&self, limit: usize) -> Result<Vec<String>, NetError> {
        let rd = fs::read_dir(self.path("."))
            .map_err(|e| map_io(&e, "failed to read network store directory"))?;
        let mut out = Vec::new();
        for ent in rd {
            let ent = ent.map_err(|e| map_io(&e, "failed to read network store directory"))?;
            if out.len() >= limit {
                return Err(err(
                    NetErrorCode::ResourceExhausted,
                    "network store directory has too many entries",
                ));
            }
            out.push(ent.file_name().to_string_lossy().into_owned());
        }
        Ok(out)
    }

    /// 通常ファイルを開いて検査する。`create` なら無いときだけ 0600 で作る。
    fn open_regular(&self, name: &str, create: bool, max_len: u64) -> Result<File, NetError> {
        let path = self.path(name);
        let msg = "failed to open network store file";
        if create {
            match OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(FILE_MODE)
                .custom_flags(FLAGS_FILE)
                .open(&path)
            {
                Ok(f) => {
                    // umask の影響を除く。
                    f.set_permissions(fs::Permissions::from_mode(FILE_MODE))
                        .map_err(|e| map_io(&e, msg))?;
                    check_file(&f, max_len)?;
                    return Ok(f);
                }
                Err(e) if e.raw_os_error() == Some(sys::EEXIST) => {}
                Err(e) => return Err(map_io(&e, msg)),
            }
        }
        let f = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(FLAGS_FILE)
            .open(&path)
            .map_err(|e| map_io(&e, msg))?;
        check_file(&f, max_len)?;
        Ok(f)
    }

    /// 定義の読み取り専用で開く（FIFO 等でも止まらない）。
    fn open_regular_ro(&self, name: &str, max_len: u64) -> Result<File, NetError> {
        let f = OpenOptions::new()
            .read(true)
            .custom_flags(FLAGS_FILE)
            .open(self.path(name))
            .map_err(|e| map_io(&e, "failed to open network store file"))?;
        check_file(&f, max_len)?;
        Ok(f)
    }
}

/// 全体の @lock の欠落は「定義が無い」ではなく破損なので `NotFound` を `DataLoss` へ直す。
fn global_lock_missing_as_data_loss(e: NetError) -> NetError {
    if e.code() == NetErrorCode::NotFound {
        err(NetErrorCode::DataLoss, "network store lock file is missing")
    } else {
        e
    }
}

fn check_file(f: &File, max_len: u64) -> Result<(), NetError> {
    let m = f
        .metadata()
        .map_err(|e| map_io(&e, "failed to stat network store file"))?;
    check_file_meta(
        m.is_file(),
        m.uid(),
        m.mode(),
        m.nlink(),
        m.len(),
        sys::effective_uid(),
        max_len,
    )
}

fn open_dir_checked(path: &Path) -> Result<Dir, NetError> {
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(FLAGS_DIR)
        .open(path)
        .map_err(|e| map_io(&e, "failed to open network store directory"))?;
    let m = f
        .metadata()
        .map_err(|e| map_io(&e, "failed to stat network store directory"))?;
    check_dir_meta(m.is_dir(), m.uid(), m.mode(), sys::effective_uid())?;
    Ok(Dir { file: f })
}

/// 初期化で作ったエントリを永続化する。`@networks` 自身 → 親の state_root の順に fsync する。
fn sync_init(root: &Dir, networks: &Dir) -> Result<(), NetError> {
    networks.sync()?;
    root.sync()
}

/// 同一 inode か（取得後の `@lock` 照合）。
fn same_inode(a: &fs::Metadata, b: &fs::Metadata) -> bool {
    a.dev() == b.dev() && a.ino() == b.ino()
}

fn stage_name(prefix: &str) -> String {
    let seq = STAGE_SEQ.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    format!("{prefix}{}-{seq}-{nanos}", std::process::id())
}

/// ネットワーク定義ストア（`<state_root>/@networks`）。
pub struct NetworkStore {
    dir: Dir,
    lock_timeout: Duration,
    /// 操作の結果と所要時間の記録先（REPAIR-4）。既定は記録しない。
    recorder: Arc<dyn NetOpRecorder>,
}

impl std::fmt::Debug for NetworkStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NetworkStore")
            .field("dir", &self.dir)
            .field("lock_timeout", &self.lock_timeout)
            .finish_non_exhaustive()
    }
}

/// 全体のロックのガード。解放はドロップ時。
#[derive(Debug)]
pub struct GlobalLockGuard<'a> {
    store: &'a NetworkStore,
    file: File,
}

/// ネットワークのロックのガード。[`GlobalLockGuard`] を借用してしか作れない（順序「全体 → ネットワーク」の強制）。
pub struct NetworkLockGuard<'g> {
    _global: PhantomData<&'g ()>,
    name: NetworkName,
    /// 排他ロックか。記録の書き込みは排他ロックでだけ許す（#3067）。
    exclusive: bool,
    recorder: Arc<dyn NetOpRecorder>,
    dir: Dir,
    file: File,
}

impl std::fmt::Debug for NetworkLockGuard<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NetworkLockGuard")
            .field("name", &self.name)
            .field("exclusive", &self.exclusive)
            .finish_non_exhaustive()
    }
}

impl Drop for GlobalLockGuard<'_> {
    fn drop(&mut self) {
        note_release();
    }
}

impl Drop for NetworkLockGuard<'_> {
    fn drop(&mut self) {
        note_release();
    }
}

impl NetworkStore {
    /// `state_root` 配下の `@networks` と全体の `@lock` を用意して検査する。
    ///
    /// `state_root` は呼び出し側が与えた信頼するルート（core の状態ストアと同じ扱い）。`@networks` から先は
    /// 作成時に 0700 を明示し、既存のものは検査して違反なら自動修復せず拒否する。
    pub fn open(state_root: &Path) -> Result<Self, NetError> {
        Self::open_with_recorder(state_root, Arc::new(NoopNetOpRecorder))
    }

    /// [`open`](Self::open) に記録先を渡す。以降の open / create / get / list / remove の結果と所要時間を
    /// `recorder` へ渡す（早期エラー・ロック待ちの時間切れを含む。REPAIR-4）。記録先は有界時間で戻ること。
    pub fn open_with_recorder(
        state_root: &Path,
        recorder: Arc<dyn NetOpRecorder>,
    ) -> Result<Self, NetError> {
        let rec = Arc::clone(&recorder);
        record_net_op(&*rec, NetOpKind::NetworkStoreOpen, || {
            Self::open_inner(state_root, recorder)
        })
    }

    fn open_inner(state_root: &Path, recorder: Arc<dyn NetOpRecorder>) -> Result<Self, NetError> {
        // 対応外アーキでは O_NOFOLLOW 等が 0 になり symlink 拒否が効かないため、fail-closed で拒否する。
        if sys::O_NOFOLLOW == 0 || sys::O_DIRECTORY == 0 {
            return Err(err(
                NetErrorCode::Unimplemented,
                "network store requires O_NOFOLLOW support on this architecture",
            ));
        }
        if !Path::new("/proc/self/fd").is_dir() {
            return Err(err(
                NetErrorCode::Unimplemented,
                "network store requires /proc/self/fd",
            ));
        }
        let root = OpenOptions::new()
            .read(true)
            .custom_flags(sys::O_DIRECTORY)
            .open(state_root)
            .map_err(|e| map_io(&e, "failed to open network store state root"))?;
        let root = Dir { file: root };
        let path = root.path(NETWORKS_DIR);
        let created = match DirBuilder::new().mode(DIR_MODE).create(&path) {
            Ok(()) => true,
            Err(e) if e.raw_os_error() == Some(sys::EEXIST) => false,
            Err(e) => return Err(map_io(&e, "failed to create network store directory")),
        };
        if created {
            // umask が読み取りビットを落としていても開けるよう、open より先にパスで権限を整える。
            fs::set_permissions(&path, fs::Permissions::from_mode(DIR_MODE))
                .map_err(|e| map_io(&e, "failed to set network store directory mode"))?;
        }
        let f = OpenOptions::new()
            .read(true)
            .custom_flags(FLAGS_DIR)
            .open(&path)
            .map_err(|e| map_io(&e, "failed to open network store directory"))?;
        let m = f
            .metadata()
            .map_err(|e| map_io(&e, "failed to stat network store directory"))?;
        check_dir_meta(m.is_dir(), m.uid(), m.mode(), sys::effective_uid())?;
        let dir = Dir { file: f };
        // 全体のロックファイルを検査する（以降の取得は検査つきで開き直す）。作るのは初期化時（新規作成、
        // または中身が空）だけで、項目があるのに欠落している既存ストアは破損として拒否する（fail-closed）。
        let initializing = created || dir.entries(SCAN_LIMIT)?.is_empty();
        dir.open_regular(LOCK_FILE, initializing, u64::MAX)
            .map_err(global_lock_missing_as_data_loss)?;
        // 新規作成した `@networks` のエントリと `@lock` を永続化してから使う。既存でも（別プロセスが
        // 作った直後の可能性があるため）同期する。失敗は握りつぶさず返す（NET-6）。
        sync_init(&root, &dir)?;
        Ok(Self {
            dir,
            lock_timeout: DEFAULT_LOCK_TIMEOUT,
            recorder,
        })
    }

    /// ロック待ちの期限を差し替える（試験用。既定は [`DEFAULT_LOCK_TIMEOUT`]）。
    pub fn with_lock_timeout(mut self, timeout: Duration) -> Self {
        self.lock_timeout = timeout;
        self
    }

    fn lock_global(&self, shared: bool) -> Result<GlobalLockGuard<'_>, NetError> {
        // 欠落を作り直すと旧 inode の保持者と排他が破れるため、通常の取得では作らない。
        let file = self
            .dir
            .open_regular(LOCK_FILE, false, u64::MAX)
            .map_err(global_lock_missing_as_data_loss)?;
        acquire(
            &file,
            shared,
            self.lock_timeout,
            "timed out waiting for the network store lock",
        )?;
        // 取得までに差し替えられていないか、パスの inode と掴んだ fd を照合する。
        let on_disk = fs::symlink_metadata(self.dir.path(LOCK_FILE))
            .map_err(|e| map_io(&e, "failed to stat network store lock file"))?;
        let held = file
            .metadata()
            .map_err(|e| map_io(&e, "failed to stat network store lock file"))?;
        if !same_inode(&on_disk, &held) {
            return Err(err(
                NetErrorCode::Internal,
                "network store lock file was replaced",
            ));
        }
        Ok(GlobalLockGuard { store: self, file })
    }

    /// 全体の共有ロックを取る（期限つき）。
    pub fn lock_global_shared(&self) -> Result<GlobalLockGuard<'_>, NetError> {
        self.lock_global(true)
    }

    /// 全体の排他ロックを取る（期限つき）。
    pub fn lock_global_exclusive(&self) -> Result<GlobalLockGuard<'_>, NetError> {
        self.lock_global(false)
    }

    /// 定義を作る。カーネル資源は作らない。全体の排他ロックの下で、staging に書いてから rename で公開する。
    pub fn create(&self, def: &NetworkDefinition) -> Result<(), NetError> {
        self.create_with_sync(def, &Dir::sync)
    }

    /// [`create`](Self::create) の本体。ディレクトリの同期を差し替えられる（同期失敗の試験用）。
    ///
    /// rename 後の同期に失敗したら公開を巻き戻して（定義を staging 名へ戻して捨てる）失敗を返す。
    /// 永続化を確認できないまま成功を返さず、再試行が `AlreadyExists` にならないようにする（NET-6）。
    fn create_with_sync(
        &self,
        def: &NetworkDefinition,
        sync: &dyn Fn(&Dir) -> Result<(), NetError>,
    ) -> Result<(), NetError> {
        record_net_op(&*self.recorder, NetOpKind::NetworkStoreCreate, || {
            let name = def.name().as_str();
            if is_reserved_network_name(name) {
                return Err(err(
                    NetErrorCode::InvalidArgument,
                    "network name is reserved",
                ));
            }
            let _g = self.lock_global_exclusive()?;
            self.sweep_leftovers()?;
            self.ensure_absent(name)?;
            let count = self
                .dir
                .entries(SCAN_LIMIT)?
                .iter()
                .filter(|n| NetworkName::new(n).is_ok() && !is_reserved_network_name(n))
                .count();
            if count >= MAX_NETWORKS {
                return Err(err(
                    NetErrorCode::ResourceExhausted,
                    "too many networks are defined",
                ));
            }
            let stage = stage_name(STAGING_PREFIX);
            let result = self.write_staging(&stage, def).and_then(|()| {
                // rename は空の既存ディレクトリを置き換えるため、直前に不在を確かめ直す。
                self.ensure_absent(name)?;
                fs::rename(self.dir.path(&stage), self.dir.path(name))
                    .map_err(|e| map_io(&e, "failed to publish network definition"))
            });
            let result = result.and_then(|()| {
                sync(&self.dir).inspect_err(|_| {
                    // 巻き戻し（ベストエフォート）。戻せなければ定義は見えたままで、再試行は AlreadyExists になる。
                    let _ = fs::rename(self.dir.path(name), self.dir.path(&stage));
                })
            });
            if result.is_err() {
                self.discard(&stage);
            }
            result
        })
    }

    fn ensure_absent(&self, name: &str) -> Result<(), NetError> {
        match fs::symlink_metadata(self.dir.path(name)) {
            Ok(_) => Err(err(
                NetErrorCode::AlreadyExists,
                "network is already defined",
            )),
            Err(e) if e.raw_os_error() == Some(sys::ENOENT) => Ok(()),
            Err(e) => Err(map_io(&e, "failed to stat network entry")),
        }
    }

    fn write_staging(&self, stage: &str, def: &NetworkDefinition) -> Result<(), NetError> {
        use std::io::Write;
        let msg = "failed to write network definition";
        DirBuilder::new()
            .mode(DIR_MODE)
            .create(self.dir.path(stage))
            .map_err(|e| map_io(&e, msg))?;
        // umask が読み取りビットを落としていても開けるよう、open より先にパスで権限を整える。
        fs::set_permissions(self.dir.path(stage), fs::Permissions::from_mode(DIR_MODE))
            .map_err(|e| map_io(&e, msg))?;
        let sd = self.dir.open_subdir(stage)?;
        let mut f = sd.open_regular(DEFINITION_FILE, true, u64::MAX)?;
        f.write_all(&def.encode()).map_err(|e| map_io(&e, msg))?;
        f.sync_all().map_err(|e| map_io(&e, msg))?;
        sd.open_regular(LOCK_FILE, true, u64::MAX)?;
        sd.sync()
    }

    /// 自分が作った staging だけを消す（ベストエフォート）。
    fn discard(&self, stage: &str) {
        remove_tree(&self.dir, stage);
    }

    /// クラッシュの残骸（`@staging-*`・`@removing-*`）を掃除する。全体の排他ロックの下でだけ呼ぶ。
    fn sweep_leftovers(&self) -> Result<(), NetError> {
        for n in self.dir.entries(SCAN_LIMIT)? {
            if n.starts_with(STAGING_PREFIX) || n.starts_with(REMOVING_PREFIX) {
                remove_tree(&self.dir, &n);
            }
        }
        Ok(())
    }

    fn read_one(&self, name: &str) -> Result<NetworkDefinition, NetError> {
        let sub = self.dir.open_subdir(name)?;
        read_definition_in(&sub, name)
    }
}

/// ネットワークのディレクトリ `sub` から定義を読む（`read_one` と、ロック保持中の再読み込みの共通本体）。
/// `name` はディレクトリ名で、定義の名前と一致しなければ `DataLoss`。
fn read_definition_in(sub: &Dir, name: &str) -> Result<NetworkDefinition, NetError> {
    // 読み取りでも @lock を検査する（欠落・symlink・権限不正・複数ハードリンクは破損として扱う）。
    sub.open_regular_ro(LOCK_FILE, u64::MAX).map_err(|e| {
        if e.code() == NetErrorCode::NotFound {
            err(NetErrorCode::DataLoss, "network lock file is missing")
        } else {
            e
        }
    })?;
    let mut f = sub
        .open_regular_ro(DEFINITION_FILE, DEFINITION_MAX_BYTES as u64)
        .map_err(|e| {
            if e.code() == NetErrorCode::NotFound {
                err(NetErrorCode::DataLoss, "network definition file is missing")
            } else {
                e
            }
        })?;
    let len = usize::try_from(
        f.metadata()
            .map_err(|e| map_io(&e, "failed to stat network definition"))?
            .len(),
    )
    .map_err(|_| err(NetErrorCode::DataLoss, "network definition is too large"))?;
    // metadata は検査時と別の取得で拡張されうるため、確保は固定上限で頭打ちにする。
    let mut buf = Vec::with_capacity(len.min(DEFINITION_MAX_BYTES));
    (&mut f)
        .take(DEFINITION_MAX_BYTES as u64 + 1)
        .read_to_end(&mut buf)
        .map_err(|e| map_io(&e, "failed to read network definition"))?;
    if buf.len() != len {
        return Err(err(
            NetErrorCode::DataLoss,
            "network definition changed while reading",
        ));
    }
    let def = NetworkDefinition::decode(&buf)?;
    if def.name().as_str() != name {
        return Err(err(
            NetErrorCode::DataLoss,
            "network definition name does not match its directory",
        ));
    }
    Ok(def)
}

impl NetworkStore {
    /// 定義を 1 件読む。無ければ `NotFound`。
    pub fn get(&self, name: &NetworkName) -> Result<NetworkDefinition, NetError> {
        record_net_op(&*self.recorder, NetOpKind::NetworkStoreGet, || {
            let _g = self.lock_global_shared()?;
            self.read_one(name.as_str())
        })
    }

    /// 全定義を名前順に返す。破損した項目は `broken` に分類つきで載せ、他の定義を隠さない。
    pub fn list(&self) -> Result<NetworkListing, NetError> {
        record_net_op(&*self.recorder, NetOpKind::NetworkStoreList, || {
            let _g = self.lock_global_shared()?;
            let mut names = self.dir.entries(SCAN_LIMIT)?;
            names.sort();
            let mut out = NetworkListing::default();
            for n in names {
                if n == LOCK_FILE || n.starts_with(STAGING_PREFIX) || n.starts_with(REMOVING_PREFIX)
                {
                    continue;
                }
                if NetworkName::new(&n).is_err() || is_reserved_network_name(&n) {
                    out.unrecognized += 1;
                    continue;
                }
                match self.read_one(&n) {
                    Ok(d) => out.definitions.push(d),
                    Err(e) => out.broken.push((n, e.code())),
                }
            }
            Ok(out)
        })
    }

    /// 定義を消す。`definition` と `@lock` 以外の項目（メンバー等）があれば `FailedPrecondition`。
    ///
    /// 既知の制約: ネットワークのディレクトリに `@lock` が無い破損エントリ（`list` の `broken` に出る）は
    /// ロックを取れず `NotFound` となり、本メソッドでは回収できない。staging と rename で作成するため
    /// 通常運用では起きず、外部要因の破損に限る。その回収手順は後続 issue（#3067 周辺）で扱う（NET-6）。
    pub fn remove(&self, name: &NetworkName) -> Result<(), NetError> {
        self.remove_with_sync(name, &Dir::sync)
    }

    /// [`remove`](Self::remove) の本体。ディレクトリの同期を差し替えられる（同期失敗の試験用）。
    fn remove_with_sync(
        &self,
        name: &NetworkName,
        sync: &dyn Fn(&Dir) -> Result<(), NetError>,
    ) -> Result<(), NetError> {
        record_net_op(&*self.recorder, NetOpKind::NetworkStoreRemove, || {
            let g = self.lock_global_exclusive()?;
            let n = g.lock_network(name)?;
            let items = n.dir.entries(NET_DIR_SCAN_LIMIT).map_err(|e| {
                if e.code() == NetErrorCode::ResourceExhausted {
                    err(
                        NetErrorCode::FailedPrecondition,
                        "network has members or pending records",
                    )
                } else {
                    e
                }
            })?;
            // 空の既知ディレクトリ（記録が全部消えた後の残り）は許す。`realized` と中身のあるものは拒否する。
            if items.iter().any(|i| {
                i != DEFINITION_FILE
                    && i != LOCK_FILE
                    && !matches!(records::is_empty_known_dir(&n.dir, i), Ok(true))
            }) {
                return Err(err(
                    NetErrorCode::FailedPrecondition,
                    "network has members or pending records",
                ));
            }
            let gone = stage_name(REMOVING_PREFIX);
            fs::rename(self.dir.path(name.as_str()), self.dir.path(&gone))
                .map_err(|e| map_io(&e, "failed to remove network definition"))?;
            // 名前が消えたことの永続化を確認するまで中身を消さない。失敗したら名前を戻して失敗を返す
            // （戻せなければ残骸として残り、次の create が掃除する）。
            if let Err(e) = sync(&self.dir) {
                let _ = fs::rename(self.dir.path(&gone), self.dir.path(name.as_str()));
                return Err(e);
            }
            // 名前は原子的に消えた。中身の後始末の失敗は残骸として残り、次の create が掃除する。
            remove_tree(&self.dir, &gone);
            Ok(())
        })
    }
}

/// `parent` 直下の `name` ディレクトリを、既知のファイルとディレクトリ自身だけ消す（ベストエフォート）。
fn remove_tree(parent: &Dir, name: &str) {
    if let Ok(sub) = parent.open_subdir(name) {
        let _ = fs::remove_file(sub.path(DEFINITION_FILE));
        let _ = fs::remove_file(sub.path(LOCK_FILE));
        records::remove_known_dirs(&sub);
    }
    let _ = fs::remove_dir(parent.path(name));
}

impl GlobalLockGuard<'_> {
    fn lock_net(&self, name: &NetworkName, shared: bool) -> Result<NetworkLockGuard<'_>, NetError> {
        // 全体のロックの保持を型で示す（未使用警告の回避と、借用の意図の明示）。
        let _held = &self.file;
        let dir = self.store.dir.open_subdir(name.as_str())?;
        let file = dir.open_regular(LOCK_FILE, false, u64::MAX)?;
        acquire(
            &file,
            shared,
            self.store.lock_timeout,
            "timed out waiting for the network lock",
        )?;
        // 取得までに削除・作り直しされていないか、パスの inode と掴んだ fd を照合する。
        let on_disk = fs::symlink_metadata(dir.path(LOCK_FILE))
            .map_err(|e| map_io(&e, "failed to stat network lock file"))?;
        let held = file
            .metadata()
            .map_err(|e| map_io(&e, "failed to stat network lock file"))?;
        if !same_inode(&on_disk, &held) {
            return Err(err(
                NetErrorCode::NotFound,
                "network was replaced or removed",
            ));
        }
        Ok(NetworkLockGuard {
            _global: PhantomData,
            name: name.clone(),
            exclusive: !shared,
            recorder: Arc::clone(&self.store.recorder),
            dir,
            file,
        })
    }

    /// ネットワークの排他ロックを取る（期限つき）。無ければ `NotFound`。
    pub fn lock_network(&self, name: &NetworkName) -> Result<NetworkLockGuard<'_>, NetError> {
        self.lock_net(name, false)
    }

    /// ネットワークの共有ロックを取る（期限つき）。無ければ `NotFound`。
    pub fn lock_network_shared(
        &self,
        name: &NetworkName,
    ) -> Result<NetworkLockGuard<'_>, NetError> {
        self.lock_net(name, true)
    }
}

mod records;

impl NetworkLockGuard<'_> {
    /// ロックを保持している fd（保持の証跡。ドロップで解放される）。
    pub fn is_held(&self) -> bool {
        self.file.as_raw_fd() >= 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::netlink_route::IpPrefix;
    use std::net::{IpAddr, Ipv4Addr};
    use std::os::unix::fs::symlink;

    struct Tmp(PathBuf);
    impl Tmp {
        fn new(tag: &str) -> Self {
            let p = std::env::temp_dir().join(format!("fc-netstore-{}-{tag}", stage_name("t")));
            DirBuilder::new().mode(0o700).create(&p).unwrap();
            Tmp(p)
        }
        fn nets(&self) -> PathBuf {
            self.0.join("@networks")
        }
    }
    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// NET-6: rename 後の同期失敗は呼び出し側へ返し、状態を巻き戻して再試行できる。
    #[test]
    fn net6_3059_sync_failure_is_reported_and_rolled_back() {
        let t = Tmp::new("syncfail");
        let store = NetworkStore::open(&t.0).unwrap();
        let fail = |_: &Dir| Err(err(NetErrorCode::Internal, "injected sync failure"));
        let def = pasta("a");
        assert_eq!(
            code(store.create_with_sync(&def, &fail)),
            NetErrorCode::Internal
        );
        assert_eq!(code(store.get(&nn("a"))), NetErrorCode::NotFound);
        store.create(&def).unwrap();
        assert_eq!(
            code(store.remove_with_sync(&nn("a"), &fail)),
            NetErrorCode::Internal
        );
        // 巻き戻され、定義は読める。再試行で消せる。
        assert_eq!(store.get(&nn("a")).unwrap(), def);
        store.remove(&nn("a")).unwrap();
        assert_eq!(code(store.get(&nn("a"))), NetErrorCode::NotFound);
    }

    /// NET-6: 初期化の同期は成功時に Ok、fsync できない fd（/dev/null）では Err を返す。
    #[test]
    fn sync_init_ok_and_propagates_failure() {
        let t = Tmp::new("syncinit");
        let _s = NetworkStore::open(&t.0).unwrap();
        let root = open_dir_checked(&t.0).unwrap();
        let nets = open_dir_checked(&t.nets()).unwrap();
        assert!(sync_init(&root, &nets).is_ok());
        let bad = Dir {
            file: File::open("/dev/null").unwrap(),
        };
        assert!(sync_init(&root, &bad).is_err());
        assert!(sync_init(&bad, &nets).is_err());
    }

    fn nn(s: &str) -> NetworkName {
        NetworkName::new(s).unwrap()
    }
    fn pasta(s: &str) -> NetworkDefinition {
        NetworkDefinition::pasta(s).unwrap()
    }
    fn mode(p: &Path) -> u32 {
        fs::symlink_metadata(p).unwrap().mode() & 0o7777
    }
    fn code<T>(r: Result<T, NetError>) -> NetErrorCode {
        match r {
            Ok(_) => panic!("expected error"),
            Err(e) => e.code(),
        }
    }

    #[test]
    fn net6_3059_create_get_list_and_disk_state() {
        let t = Tmp::new("basic");
        let s = NetworkStore::open(&t.0).unwrap();
        let sub = IpPrefix::new(IpAddr::V4(Ipv4Addr::new(10, 89, 1, 0)), 24).unwrap();
        s.create(&pasta("zeta")).unwrap();
        s.create(&NetworkDefinition::bridge("alpha", sub).unwrap())
            .unwrap();
        assert_eq!(s.get(&nn("zeta")).unwrap(), pasta("zeta"));
        let l = s.list().unwrap();
        let names: Vec<_> = l.definitions.iter().map(|d| d.name().as_str()).collect();
        assert_eq!(names, ["alpha", "zeta"]);
        assert!(l.broken.is_empty());
        assert_eq!(l.unrecognized, 0);
        let uid = sys::effective_uid();
        assert_eq!(mode(&t.nets()), 0o700);
        assert_eq!(mode(&t.nets().join("zeta")), 0o700);
        for p in [
            t.nets().join("@lock"),
            t.nets().join("zeta/definition"),
            t.nets().join("zeta/@lock"),
        ] {
            let m = fs::symlink_metadata(&p).unwrap();
            assert_eq!(m.mode() & 0o7777, 0o600, "{p:?}");
            assert_eq!(m.uid(), uid);
            assert_eq!(m.nlink(), 1);
        }
        assert_eq!(code(s.create(&pasta("zeta"))), NetErrorCode::AlreadyExists);
        assert_eq!(code(s.get(&nn("nope"))), NetErrorCode::NotFound);
    }

    #[test]
    fn net6_3059_limit_256() {
        let t = Tmp::new("limit");
        let s = NetworkStore::open(&t.0).unwrap();
        for i in 0..MAX_NETWORKS {
            s.create(&pasta(&format!("n{i}"))).unwrap();
        }
        let before = fs::read_dir(t.nets()).unwrap().count();
        assert_eq!(
            code(s.create(&pasta("overflow"))),
            NetErrorCode::ResourceExhausted
        );
        assert_eq!(fs::read_dir(t.nets()).unwrap().count(), before);
    }

    #[test]
    fn net6_3059_remove() {
        let t = Tmp::new("remove");
        let s = NetworkStore::open(&t.0).unwrap();
        assert_eq!(code(s.remove(&nn("x"))), NetErrorCode::NotFound);
        s.create(&pasta("x")).unwrap();
        fs::create_dir(t.nets().join("x/members")).unwrap();
        assert_eq!(code(s.remove(&nn("x"))), NetErrorCode::FailedPrecondition);
        assert!(s.get(&nn("x")).is_ok());
        fs::remove_dir(t.nets().join("x/members")).unwrap();
        s.remove(&nn("x")).unwrap();
        assert_eq!(code(s.get(&nn("x"))), NetErrorCode::NotFound);
        let left: Vec<_> = fs::read_dir(t.nets())
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        assert_eq!(left, ["@lock"]);
    }

    #[test]
    fn net6_3059_fail_closed_on_violations() {
        // @networks が 0755
        let t = Tmp::new("mode");
        NetworkStore::open(&t.0).unwrap();
        fs::set_permissions(t.nets(), fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            code(NetworkStore::open(&t.0)),
            NetErrorCode::PermissionDenied
        );
        // @networks が symlink
        let t = Tmp::new("link");
        let other = Tmp::new("linkdst");
        symlink(&other.0, t.nets()).unwrap();
        assert_eq!(
            code(NetworkStore::open(&t.0)),
            NetErrorCode::FailedPrecondition
        );

        let t = Tmp::new("entries");
        let s = NetworkStore::open(&t.0).unwrap();
        for n in ["a", "b", "c", "d", "e", "f", "g"] {
            s.create(&pasta(n)).unwrap();
        }
        let def = |n: &str| t.nets().join(n).join("definition");
        // <name> が symlink
        fs::rename(t.nets().join("a"), t.nets().join("a-real")).unwrap();
        symlink(t.nets().join("a-real"), t.nets().join("a")).unwrap();
        assert_eq!(code(s.get(&nn("a"))), NetErrorCode::FailedPrecondition);
        // definition が symlink
        fs::rename(def("b"), t.nets().join("b/def2")).unwrap();
        symlink(t.nets().join("b/def2"), def("b")).unwrap();
        assert_eq!(code(s.get(&nn("b"))), NetErrorCode::FailedPrecondition);
        // definition が 0644
        fs::set_permissions(def("c"), fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(code(s.get(&nn("c"))), NetErrorCode::PermissionDenied);
        // ハードリンク
        fs::hard_link(def("d"), t.0.join("hl")).unwrap();
        assert_eq!(code(s.get(&nn("d"))), NetErrorCode::FailedPrecondition);
        // ディレクトリ
        fs::remove_file(def("e")).unwrap();
        fs::create_dir(def("e")).unwrap();
        assert_eq!(code(s.get(&nn("e"))), NetErrorCode::FailedPrecondition);
        // 4097 バイト
        fs::write(def("f"), vec![b'a'; 4097]).unwrap();
        fs::set_permissions(def("f"), fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(code(s.get(&nn("f"))), NetErrorCode::DataLoss);
        // 中の名前とディレクトリ名の不一致
        fs::write(def("g"), pasta("other").encode()).unwrap();
        assert_eq!(code(s.get(&nn("g"))), NetErrorCode::DataLoss);

        // list は破損を分類つきで出し、残りを隠さない
        let l = s.list().unwrap();
        assert!(l.definitions.is_empty());
        let broken: std::collections::BTreeMap<_, _> = l.broken.into_iter().collect();
        assert_eq!(broken["a"], NetErrorCode::FailedPrecondition);
        assert_eq!(broken["c"], NetErrorCode::PermissionDenied);
        assert_eq!(broken["f"], NetErrorCode::DataLoss);
        assert_eq!(broken["g"], NetErrorCode::DataLoss);
    }

    #[test]
    fn net6_3059_lock_file_violations() {
        let t = Tmp::new("lockfile");
        let s = NetworkStore::open(&t.0).unwrap();
        s.create(&pasta("n1")).unwrap();
        s.create(&pasta("n2")).unwrap();
        // ネットワークの @lock が nlink 2
        fs::hard_link(t.nets().join("n1/@lock"), t.0.join("hl")).unwrap();
        let g = s.lock_global_exclusive().unwrap();
        assert_eq!(
            code(g.lock_network(&nn("n1"))),
            NetErrorCode::FailedPrecondition
        );
        // ネットワークの @lock が symlink
        fs::remove_file(t.nets().join("n2/@lock")).unwrap();
        symlink("/dev/null", t.nets().join("n2/@lock")).unwrap();
        assert_eq!(
            code(g.lock_network(&nn("n2"))),
            NetErrorCode::FailedPrecondition
        );
        drop(g);
        // 全体の @lock が symlink / nlink 2
        fs::remove_file(t.nets().join("@lock")).unwrap();
        symlink("/dev/null", t.nets().join("@lock")).unwrap();
        assert_eq!(
            code(s.lock_global_shared()),
            NetErrorCode::FailedPrecondition
        );
        fs::remove_file(t.nets().join("@lock")).unwrap();
        fs::write(t.nets().join("@lock"), b"").unwrap();
        fs::set_permissions(t.nets().join("@lock"), fs::Permissions::from_mode(0o600)).unwrap();
        fs::hard_link(t.nets().join("@lock"), t.0.join("hl2")).unwrap();
        assert_eq!(
            code(s.lock_global_shared()),
            NetErrorCode::FailedPrecondition
        );
    }

    /// NET-6: 読み取りでもネットワークの @lock の破損を検出する（get はエラー、list は broken）。
    #[test]
    fn net6_3059_read_detects_broken_lock() {
        let t = Tmp::new("readlock");
        let s = NetworkStore::open(&t.0).unwrap();
        s.create(&pasta("n1")).unwrap();
        s.create(&pasta("n2")).unwrap();
        fs::remove_file(t.nets().join("n1/@lock")).unwrap();
        fs::remove_file(t.nets().join("n2/@lock")).unwrap();
        symlink("/dev/null", t.nets().join("n2/@lock")).unwrap();
        assert_eq!(code(s.get(&nn("n1"))), NetErrorCode::DataLoss);
        assert_eq!(code(s.get(&nn("n2"))), NetErrorCode::FailedPrecondition);
        let l = s.list().unwrap();
        assert!(l.definitions.is_empty());
        assert_eq!(
            l.broken,
            vec![
                ("n1".to_string(), NetErrorCode::DataLoss),
                ("n2".to_string(), NetErrorCode::FailedPrecondition)
            ]
        );
    }

    /// REPAIR-4: 各操作の結果（成功・失敗）が記録される。
    #[test]
    fn net6_3059_operations_are_recorded() {
        use crate::instrument::{NetOpOutcome, testing::Collect};
        let t = Tmp::new("recorded");
        let c = Arc::new(Collect::default());
        let s = NetworkStore::open_with_recorder(&t.0, c.clone()).unwrap();
        s.create(&pasta("n1")).unwrap();
        assert!(s.create(&pasta("n1")).is_err());
        s.get(&nn("n1")).unwrap();
        s.list().unwrap();
        s.remove(&nn("n1")).unwrap();
        assert!(s.get(&nn("n1")).is_err());
        use NetOpKind as K;
        use NetOpOutcome::{Failure as F, Success as S};
        assert_eq!(
            c.kinds(),
            vec![
                (K::NetworkStoreOpen, S),
                (K::NetworkStoreCreate, S),
                (K::NetworkStoreCreate, F),
                (K::NetworkStoreGet, S),
                (K::NetworkStoreList, S),
                (K::NetworkStoreRemove, S),
                (K::NetworkStoreGet, F),
            ]
        );
    }

    #[test]
    fn net6_3059_leftovers_and_unrecognized() {
        let t = Tmp::new("sweep");
        let s = NetworkStore::open(&t.0).unwrap();
        s.create(&pasta("keep")).unwrap();
        let st = t.nets().join("@staging-x");
        DirBuilder::new().mode(0o700).create(&st).unwrap();
        fs::write(st.join("definition"), b"x").unwrap();
        fs::write(st.join("@lock"), b"").unwrap();
        for d in ["Bad_Name", "none"] {
            DirBuilder::new()
                .mode(0o700)
                .create(t.nets().join(d))
                .unwrap();
        }
        let l = s.list().unwrap();
        assert_eq!(l.definitions.len(), 1);
        assert_eq!(l.unrecognized, 2);
        assert!(st.exists(), "list must not sweep");
        s.create(&pasta("other")).unwrap();
        assert!(!st.exists());
    }

    #[test]
    fn net6_3059_lock_timeout_and_order() {
        let t = Tmp::new("lock");
        let s = NetworkStore::open(&t.0)
            .unwrap()
            .with_lock_timeout(Duration::from_millis(50));
        s.create(&pasta("n1")).unwrap();
        s.create(&pasta("n2")).unwrap();
        {
            let _a = s.lock_global_exclusive().unwrap();
            let t0 = Instant::now();
            let e = s.lock_global_shared().unwrap_err();
            assert_eq!(e.code(), NetErrorCode::Timeout);
            assert_eq!(e.message(), "timed out waiting for the network store lock");
            assert!(t0.elapsed() >= Duration::from_millis(50));
        }
        {
            let a = s.lock_global_shared().unwrap();
            let b = s.lock_global_shared().unwrap();
            assert_eq!(code(s.lock_global_exclusive()), NetErrorCode::Timeout);
            drop((a, b));
        }
        // 全体 → ネットワークの順で保持している間、別 open の全体ロックは待たされる。
        let ga = s.lock_global_exclusive().unwrap();
        let _na = ga.lock_network(&nn("n1")).unwrap();
        let s2 = NetworkStore::open(&t.0)
            .unwrap()
            .with_lock_timeout(Duration::from_millis(50));
        // 別 open の B は全体のロック（A が保持）で待たされる。
        assert_eq!(
            s2.lock_global_shared().unwrap_err().message(),
            "timed out waiting for the network store lock"
        );
    }

    #[test]
    fn net6_3059_network_lock_message_and_default_timeout() {
        let t = Tmp::new("netlock");
        let s = NetworkStore::open(&t.0)
            .unwrap()
            .with_lock_timeout(Duration::from_millis(50));
        s.create(&pasta("n1")).unwrap();
        s.create(&pasta("n2")).unwrap();
        // ネットワークのロックだけを別の fd で保持する（全体は取らない）。
        let held = {
            let d = s.dir.open_subdir("n1").unwrap();
            let f = d.open_regular(LOCK_FILE, false, u64::MAX).unwrap();
            f.try_lock().unwrap();
            f
        };
        let g = s.lock_global_exclusive().unwrap();
        let e = g.lock_network(&nn("n1")).unwrap_err();
        assert_eq!(e.code(), NetErrorCode::Timeout);
        assert_eq!(e.message(), "timed out waiting for the network lock");
        assert!(g.lock_network(&nn("n2")).is_ok());
        drop(g);
        drop(held);

        // 既定の期限は 5 秒。
        let s = NetworkStore::open(&t.0).unwrap();
        let _a = s.lock_global_exclusive().unwrap();
        let s2 = NetworkStore::open(&t.0).unwrap();
        let t0 = Instant::now();
        assert_eq!(code(s2.lock_global_shared()), NetErrorCode::Timeout);
        let el = t0.elapsed();
        assert!(
            el >= Duration::from_secs(5) && el < Duration::from_secs(8),
            "{el:?}"
        );
    }

    /// NET-6: 項目があるストアで全体の @lock が欠落したら、取得も open も再作成せず失敗する（fail-closed）。
    #[test]
    fn net6_3059_missing_global_lock_is_not_recreated() {
        let t = Tmp::new("lockgone");
        let s = NetworkStore::open(&t.0).unwrap();
        s.create(&NetworkDefinition::pasta("alpha").unwrap())
            .unwrap();
        fs::remove_file(s.dir.path(LOCK_FILE)).unwrap();
        assert_eq!(code(s.lock_global_exclusive()), NetErrorCode::DataLoss);
        assert_eq!(code(NetworkStore::open(&t.0)), NetErrorCode::DataLoss);
        assert!(!s.dir.path(LOCK_FILE).exists());
    }
}
