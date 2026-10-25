//! 作成失敗の回収待ちの記録（請求書）と、attach の巻き戻しの取り残しの記録を plugin プロセスの再起動を
//! またいで残す置き場（NET-1・NET-6・REPAIR-3・REPAIR-4。#2604・#2681。設計は `docs/design/network-reclaim-persistence.md`）。
//!
//! 呼び出し元: [`super::NetsetupNetwork`] が、作成失敗で取り残しを登録する時点で [`ReclaimStore::save`]、
//! 回収を確認して記録を外した直後に [`ReclaimStore::remove_if_matches`]、起動時に [`ReclaimStore::load`] を呼ぶ。
//! 記録の中身（net の `FailedCreateClaim` の符号化）は本モジュールにとって不透明な文字列で、符号化と復号は
//! [`super::NetsetupBackend`] が担う。置き場は `<状態ルート>/.cri/net/pending-reclaim/<ネットワーク名>.claim`
//! の固定の場所で、要求の入力からは受けない。attach の取り残しの記録（net の `FailedAttachClaim` の符号化）は
//! 同じ置き場の下位ディレクトリ `attach/<endpoint>.attach` に置き、権限・原子的な書き込み・排他（親の `.lock` を共有）・
//! 長さの上限・読み込みの検査は作成失敗の記録と同じ（#2681）。
//!
//! # 安全性
//!
//! - ディレクトリは 0700 で作り、既存のものは symlink でなく、状態ルートと同じ所有者で、group / other の権限が
//!   無いことを確かめ、反すれば消さずに拒否する（fail-closed。unix のみ。他 OS は種別だけ見る）
//! - ファイルは同じディレクトリの一時ファイル（`O_EXCL`・0600）へ書いて `fsync` してから `rename` し、ディレクトリも
//!   `fsync` する。読み込みは通常ファイルであることと長さの上限を先に確かめる（ディレクトリが 0700 で自分の所有のため、
//!   確認と open の間に差し替えられる窓は同じユーザーにしか無い）
//! - プロセス間の排他は `.lock` の `File::try_lock` を期限つきで取る（REPAIR-5）。ロックは各操作の間だけ持つ
//! - エラー文言は固定で、パスや OS の文字列を含めない

use std::fs::{self, File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use fandhe_container_core::traits::{ErrorCode, TraitError};
use fandhe_container_net::network::{CLAIM_RECORD_MAX_LEN, EndpointId, NetworkName as NetName};

use super::{MAX_CONTAINERS_PER_NETWORK, MAX_NETWORKS};

/// 置き場の状態ルートからの相対位置（先頭が `.` のため `ContainerId` の状態ディレクトリと衝突しない）。
pub const RECLAIM_DIR: &str = ".cri/net/pending-reclaim";
/// 記録ファイルの拡張子。
const EXT: &str = ".claim";
/// attach の取り残しの記録を置く下位ディレクトリ名（`.claim` で終わらないため作成失敗の記録の列挙に混ざらない）。
const ATTACH_DIR: &str = "attach";
/// attach の取り残しの記録ファイルの拡張子。
const ATTACH_EXT: &str = ".attach";
/// 読み込む attach の記録の件数の上限（ネットワーク数 × ネットワークごとのコンテナ数）。
const MAX_ATTACH_RECORDS: usize = MAX_NETWORKS * MAX_CONTAINERS_PER_NETWORK;
/// プロセス間の排他に使うファイル名。
const LOCK_NAME: &str = ".lock";
/// 一時ファイルの名前の接頭辞（`.` 始まりで `*.claim` に一致しない）。
const TMP_PREFIX: &str = ".tmp-";
/// 排他の取得期限（REPAIR-5）。
pub const LOCK_TIMEOUT: Duration = Duration::from_secs(5);
/// 排他の再試行間隔。
const LOCK_RETRY: Duration = Duration::from_millis(5);

fn internal(msg: &'static str) -> TraitError {
    TraitError::new(ErrorCode::Internal, msg)
}

/// 読み込んだ記録 1 件。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredClaim {
    /// ファイル名から得たネットワーク名。
    pub name: String,
    /// 記録の中身。読めない・長すぎる・UTF-8 でない・通常ファイルでないときは `None`（壊れた記録）。
    pub record: Option<String>,
}

/// [`ReclaimStore::load`] の結果。
#[derive(Debug, Default, PartialEq, Eq)]
pub struct LoadReport {
    /// ネットワーク名のファイル名で見つけた記録。
    pub claims: Vec<StoredClaim>,
    /// `.claim` で終わるがネットワーク名として不正なファイルの件数（触れずに残す）。
    pub unrecognized: usize,
    /// attach の取り残しの記録（`name` は endpoint）。#2681。
    pub attach_claims: Vec<StoredClaim>,
    /// `.attach` で終わるが endpoint として不正なファイルの件数（触れずに残す）。
    pub attach_unrecognized: usize,
}

/// 回収待ちの記録の置き場。
#[derive(Debug, Clone)]
pub struct ReclaimStore {
    dir: PathBuf,
    /// attach の取り残しの記録の置き場（`dir` の下位）。
    attach_dir: PathBuf,
}

impl ReclaimStore {
    /// 状態ルート配下に置き場を用意して開く。既存のものが基準に反すれば拒否する（fail-closed）。
    pub fn open(state_root: &Path) -> Result<Self, TraitError> {
        let fail = || internal("failed to prepare the reclaim store");
        let owner = owner_of(state_root).ok_or_else(fail)?;
        let mut cur = state_root.to_path_buf();
        for part in RECLAIM_DIR.split('/') {
            cur.push(part);
            create_private_dir(&cur).map_err(|_| fail())?;
            if !dir_is_private(&cur, owner) {
                return Err(fail());
            }
        }
        let dir = cur.clone();
        cur.push(ATTACH_DIR);
        create_private_dir(&cur).map_err(|_| fail())?;
        if !dir_is_private(&cur, owner) {
            return Err(fail());
        }
        Ok(Self {
            dir,
            attach_dir: cur,
        })
    }

    /// 全記録を列挙する。件数が [`MAX_NETWORKS`] を超えれば fail-closed で失敗する。
    pub fn load(&self) -> Result<LoadReport, TraitError> {
        let fail = || internal("failed to load the reclaim store");
        let _lock = self.lock()?;
        let mut report = LoadReport::default();
        for entry in fs::read_dir(&self.dir).map_err(|_| fail())? {
            let entry = entry.map_err(|_| fail())?;
            let file_name = entry.file_name();
            let Some(file_name) = file_name.to_str() else {
                continue;
            };
            let Some(stem) = file_name.strip_suffix(EXT) else {
                continue;
            };
            if NetName::new(stem).is_err() {
                report.unrecognized = report.unrecognized.saturating_add(1);
                continue;
            }
            if report.claims.len() >= MAX_NETWORKS {
                return Err(internal("reclaim store holds too many records"));
            }
            report.claims.push(StoredClaim {
                name: stem.to_owned(),
                record: match read_record(&entry.path()) {
                    ReadOutcome::Record(r) => Some(r),
                    _ => None,
                },
            });
        }
        report.claims.sort_by(|a, b| a.name.cmp(&b.name));
        for entry in fs::read_dir(&self.attach_dir).map_err(|_| fail())? {
            let entry = entry.map_err(|_| fail())?;
            let file_name = entry.file_name();
            let Some(stem) = file_name.to_str().and_then(|f| f.strip_suffix(ATTACH_EXT)) else {
                continue;
            };
            if EndpointId::new(stem).is_err() {
                report.attach_unrecognized = report.attach_unrecognized.saturating_add(1);
                continue;
            }
            if report.attach_claims.len() >= MAX_ATTACH_RECORDS {
                return Err(internal("reclaim store holds too many records"));
            }
            report.attach_claims.push(StoredClaim {
                name: stem.to_owned(),
                record: match read_record(&entry.path()) {
                    ReadOutcome::Record(r) => Some(r),
                    _ => None,
                },
            });
        }
        report.attach_claims.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(report)
    }

    /// 記録を不可分に書く（同名があれば置き換える）。
    pub fn save(&self, name: &str, record: &str) -> Result<(), TraitError> {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        self.save_with_seq(name, record, &|| SEQ.fetch_add(1, Ordering::Relaxed))
    }

    /// `save` の本体。一時ファイル名の連番の供給元を差し込めるようにして、衝突時の再試行を試験で再現する。
    fn save_with_seq(
        &self,
        name: &str,
        record: &str,
        next_seq: &dyn Fn() -> u64,
    ) -> Result<(), TraitError> {
        let file = self.file_for(name)?;
        self.save_at(&self.dir, &file, record, next_seq)
    }

    /// attach の取り残しの記録を不可分に書く（同じ endpoint があれば置き換える。#2681）。
    pub fn save_attach(&self, endpoint: &str, record: &str) -> Result<(), TraitError> {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let file = self.attach_file_for(endpoint)?;
        self.save_at(&self.attach_dir, &file, record, &|| {
            SEQ.fetch_add(1, Ordering::Relaxed)
        })
    }

    /// `dir` 直下の `file` へ不可分に書く本体。一時ファイルは `dir` に作り、同じ親のロックで排他する。
    fn save_at(
        &self,
        dir: &Path,
        file: &Path,
        record: &str,
        next_seq: &dyn Fn() -> u64,
    ) -> Result<(), TraitError> {
        if record.len() > CLAIM_RECORD_MAX_LEN {
            return Err(internal("reclaim record is too long"));
        }
        let _lock = self.lock()?;
        self.write_locked(dir, file, record, next_seq)
    }

    /// ロックを持った状態で `file` へ不可分に書く本体（呼び出し側が `lock()` を保持していること）。
    fn write_locked(
        &self,
        dir: &Path,
        file: &Path,
        record: &str,
        next_seq: &dyn Fn() -> u64,
    ) -> Result<(), TraitError> {
        // 異常終了で残った同名の一時ファイル（PID の再利用で連番が 0 から始まり衝突しうる）が保存を妨げないよう、
        // `AlreadyExists` のときは連番を進めて有限回だけ別名で再試行する（NET-1・REPAIR-3・#2604）。
        const TMP_ATTEMPTS: usize = 16;
        let mut opened = None;
        for _ in 0..TMP_ATTEMPTS {
            let tmp = dir.join(format!("{TMP_PREFIX}{}-{}", std::process::id(), next_seq()));
            let mut opts = OpenOptions::new();
            opts.write(true).create_new(true);
            set_private_mode(&mut opts);
            match opts.open(&tmp) {
                Ok(f) => {
                    opened = Some((tmp, f));
                    break;
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(_) => return Err(internal("failed to persist the reclaim record")),
            }
        }
        let Some((tmp, mut f)) = opened else {
            return Err(internal("failed to persist the reclaim record"));
        };
        let written = f
            .write_all(record.as_bytes())
            .and_then(|()| f.sync_all())
            .and_then(|()| {
                drop(f);
                fs::rename(&tmp, file)
            });
        if written.is_err() {
            // best-effort。残った一時ファイルは `.claim` に一致しないため読み込みに影響しない。
            let _ = fs::remove_file(&tmp);
            return Err(internal("failed to persist the reclaim record"));
        }
        sync_dir(dir)
    }

    /// 記録の中身が `expected` と一致するときだけ消す。無ければ成功（冪等）。
    ///
    /// 同じ古い請求書を読んだ別プロセスが先に回収・削除し、同名の再作成で新しい請求書を保存した後に、遅れた側が
    /// 新しい請求書まで消さないための条件付き削除（排他の下で照合する。NET-1・#2604）。中身が違えば消さずに成功する。
    pub fn remove_if_matches(&self, name: &str, expected: &str) -> Result<(), TraitError> {
        let file = self.file_for(name)?;
        self.remove_at(&self.dir, &file, expected)
    }

    /// attach の取り残しの記録を、中身が `expected` と一致するときだけ消す（#2681）。無ければ成功（冪等）。
    pub fn remove_attach_if_matches(
        &self,
        endpoint: &str,
        expected: &str,
    ) -> Result<(), TraitError> {
        let file = self.attach_file_for(endpoint)?;
        self.remove_at(&self.attach_dir, &file, expected)
    }

    /// attach の取り残しの記録を、現在の中身が `expected` と一致するときだけ `record` へ置き換える（#2681）。
    ///
    /// 一致の照合と書き込みを同じプロセス間ロックの下で行う比較交換。古い請求書を読んだ側が、遅れて
    /// quarantine だけの記録へ更新しようとしても、その間に別プロセスが同じ endpoint の新しい世代の請求書を
    /// 保存していれば、上書きせず新しい請求書を保持する（NET-1）。記録が無い・中身が違うときは何も書かずに成功する
    /// （回収済み、または新しい世代に置き換わっている）。読めない記録は失敗する。
    pub fn update_attach_if_matches(
        &self,
        endpoint: &str,
        expected: &str,
        record: &str,
    ) -> Result<(), TraitError> {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        if record.len() > CLAIM_RECORD_MAX_LEN {
            return Err(internal("reclaim record is too long"));
        }
        let file = self.attach_file_for(endpoint)?;
        let _lock = self.lock()?;
        match read_record(&file) {
            ReadOutcome::Record(current) if current == expected => {}
            ReadOutcome::Missing | ReadOutcome::Record(_) => return Ok(()),
            ReadOutcome::Unreadable => {
                return Err(internal("failed to read the reclaim record"));
            }
        }
        self.write_locked(&self.attach_dir, &file, record, &|| {
            SEQ.fetch_add(1, Ordering::Relaxed)
        })
    }

    /// `file` を排他の下で照合して消す本体。
    fn remove_at(&self, dir: &Path, file: &Path, expected: &str) -> Result<(), TraitError> {
        let _lock = self.lock()?;
        match read_record(file) {
            ReadOutcome::Record(current) if current == expected => {}
            // 既に無い、または別の請求書に置き換わっている。消さずに成功する。
            ReadOutcome::Missing | ReadOutcome::Record(_) => return Ok(()),
            // 読めない・通常ファイルでない・壊れている記録は、回収済みかを判断できないので失敗して保持する。
            ReadOutcome::Unreadable => {
                return Err(internal("failed to read the reclaim record"));
            }
        }
        match fs::remove_file(file) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(_) => return Err(internal("failed to remove the reclaim record")),
        }
        sync_dir(dir)
    }

    /// endpoint（検証済みの文字種のみ）から attach の記録のパスを作る。
    fn attach_file_for(&self, endpoint: &str) -> Result<PathBuf, TraitError> {
        EndpointId::new(endpoint)
            .map_err(|_| TraitError::new(ErrorCode::InvalidArgument, "invalid endpoint id"))?;
        Ok(self.attach_dir.join(format!("{endpoint}{ATTACH_EXT}")))
    }

    /// ネットワーク名（検証済みの文字種のみ）から記録のパスを作る。
    fn file_for(&self, name: &str) -> Result<PathBuf, TraitError> {
        NetName::new(name)
            .map_err(|_| TraitError::new(ErrorCode::InvalidArgument, "invalid network name"))?;
        Ok(self.dir.join(format!("{name}{EXT}")))
    }

    /// プロセス間の排他を期限つきで取る。戻り値を落とすと解放される。
    fn lock(&self) -> Result<File, TraitError> {
        let path = self.dir.join(LOCK_NAME);
        if let Ok(m) = fs::symlink_metadata(&path)
            && !m.file_type().is_file()
        {
            return Err(internal("reclaim store lock is not a regular file"));
        }
        let mut opts = OpenOptions::new();
        opts.read(true).write(true).create(true).truncate(false);
        set_private_mode(&mut opts);
        let file = opts
            .open(&path)
            .map_err(|_| internal("failed to open the reclaim store lock"))?;
        let deadline = Instant::now() + LOCK_TIMEOUT;
        loop {
            match file.try_lock() {
                Ok(()) => return Ok(file),
                Err(std::fs::TryLockError::WouldBlock) => {
                    if Instant::now() >= deadline {
                        return Err(TraitError::new(
                            ErrorCode::Timeout,
                            "timed out waiting for the reclaim store lock",
                        ));
                    }
                    std::thread::sleep(LOCK_RETRY);
                }
                Err(std::fs::TryLockError::Error(_)) => {
                    return Err(internal("failed to lock the reclaim store"));
                }
            }
        }
    }
}

/// [`read_record`] の結果。不存在・読み取り失敗・壊れた内容を区別する。
#[derive(Debug, PartialEq, Eq)]
enum ReadOutcome {
    /// 記録が無い。
    Missing,
    /// 読めた記録。
    Record(String),
    /// 存在するが読めない（権限・I/O エラー）・通常ファイルでない・上限超過・UTF-8 でない。
    Unreadable,
}

/// 記録を読む。不存在（`NotFound`）とそれ以外の失敗を区別する。
fn read_record(path: &Path) -> ReadOutcome {
    let m = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return ReadOutcome::Missing,
        Err(_) => return ReadOutcome::Unreadable,
    };
    if !m.file_type().is_file() || m.len() > CLAIM_RECORD_MAX_LEN as u64 {
        return ReadOutcome::Unreadable;
    }
    let mut buf = Vec::new();
    let file = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return ReadOutcome::Missing,
        Err(_) => return ReadOutcome::Unreadable,
    };
    if file
        .take(CLAIM_RECORD_MAX_LEN as u64 + 1)
        .read_to_end(&mut buf)
        .is_err()
        || buf.len() > CLAIM_RECORD_MAX_LEN
    {
        return ReadOutcome::Unreadable;
    }
    String::from_utf8(buf).map_or(ReadOutcome::Unreadable, ReadOutcome::Record)
}

#[cfg(unix)]
fn set_private_mode(opts: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt as _;
    opts.mode(0o600);
}

#[cfg(not(unix))]
fn set_private_mode(_opts: &mut OpenOptions) {}

#[cfg(unix)]
fn create_private_dir(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt as _;
    match fs::DirBuilder::new().mode(0o700).create(path) {
        Err(e) if e.kind() != std::io::ErrorKind::AlreadyExists => Err(e),
        _ => Ok(()),
    }
}

#[cfg(not(unix))]
fn create_private_dir(path: &Path) -> std::io::Result<()> {
    match fs::create_dir(path) {
        Err(e) if e.kind() != std::io::ErrorKind::AlreadyExists => Err(e),
        _ => Ok(()),
    }
}

/// 状態ルートの所有者（unix は uid。他 OS は比較しないので 0）。
#[cfg(unix)]
fn owner_of(path: &Path) -> Option<u32> {
    use std::os::unix::fs::MetadataExt as _;
    fs::symlink_metadata(path).ok().map(|m| m.uid())
}

#[cfg(not(unix))]
fn owner_of(path: &Path) -> Option<u32> {
    fs::symlink_metadata(path).ok().map(|_| 0)
}

/// symlink でないディレクトリで、所有者が一致し、group / other の権限が無いか。
#[cfg(unix)]
fn dir_is_private(path: &Path, owner: u32) -> bool {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    fs::symlink_metadata(path).is_ok_and(|m| {
        m.file_type().is_dir() && m.uid() == owner && m.permissions().mode() & 0o077 == 0
    })
}

#[cfg(not(unix))]
fn dir_is_private(path: &Path, _owner: u32) -> bool {
    fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_dir())
}

/// macOS で `File::sync_all`（`F_FULLFSYNC`）がディレクトリ fd に対して返しうる errno（EINVAL=22・ENOTSUP=45）。
/// plugin-cri は `sys` モジュールを持たず `fsync(2)` を呼べないため、この 2 つに限り既に完了した
/// rename / unlink を失敗扱いにせず受け入れる（それ以外の errno は fail-closed。IO-5・CLI-1）。
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
const DIR_SYNC_UNSUPPORTED_ERRNOS: [i32; 2] = [22, 45];

/// `result` が失敗でも、`tolerated` に含まれる errno のときだけ成功として扱う。
#[cfg_attr(not(unix), allow(dead_code))]
fn tolerate_errnos(result: std::io::Result<()>, tolerated: &[i32]) -> std::io::Result<()> {
    match result {
        Err(e) if e.raw_os_error().is_some_and(|n| tolerated.contains(&n)) => Ok(()),
        other => other,
    }
}

/// ディレクトリの内容（rename・unlink）を永続化する。unix 以外では何もしない。
fn sync_dir(dir: &Path) -> Result<(), TraitError> {
    #[cfg(unix)]
    {
        #[cfg(target_os = "macos")]
        let tolerated: &[i32] = &DIR_SYNC_UNSUPPORTED_ERRNOS;
        #[cfg(not(target_os = "macos"))]
        let tolerated: &[i32] = &[];
        File::open(dir)
            .and_then(|d| tolerate_errnos(d.sync_all(), tolerated))
            .map_err(|_| internal("failed to sync the reclaim store directory"))
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_root(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "fandhe-reclaim-store-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        fs::create_dir_all(&p).expect("root");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).expect("mode");
        }
        p
    }

    /// NET-1・REPAIR-3・#2604・REPAIR-12: RECLAIM_DIR 配下に残った同名の一時ファイルと実際に衝突しても、
    /// 連番を進めて別名で保存できる。連番の供給元を差し込み、衝突した回数（供給回数）まで確認する。
    #[test]
    fn net1_store_save_survives_stale_tmp_collision() {
        use std::cell::Cell;
        let root = temp_root("stale");
        let s = ReclaimStore::open(&root).expect("open");
        for n in 100..108 {
            fs::write(
                root.join(RECLAIM_DIR)
                    .join(format!("{TMP_PREFIX}{}-{n}", std::process::id())),
                "stale",
            )
            .expect("stale");
        }
        let calls = Cell::new(0u64);
        s.save_with_seq("web", "rec-1\n", &|| {
            let n = 100 + calls.get();
            calls.set(calls.get() + 1);
            n
        })
        .expect("save despite stale tmp");
        // 100..=107 の 8 件と衝突し、9 回目（108）で成功する。
        assert_eq!(calls.get(), 9);
        let r = s.load().expect("load");
        assert_eq!(r.claims.len(), 1);
        assert_eq!(r.claims[0].record.as_deref(), Some("rec-1\n"));
    }

    /// IO-5・CLI-1: ディレクトリ同期の許容は指定 errno に限り、それ以外は失敗のまま返す。
    #[test]
    fn net1_store_tolerate_errnos_only_listed() {
        let e = |n| Err(std::io::Error::from_raw_os_error(n));
        assert!(tolerate_errnos(e(22), &[22, 45]).is_ok());
        assert!(tolerate_errnos(e(45), &[22, 45]).is_ok());
        assert_eq!(
            tolerate_errnos(e(5), &[22, 45]).unwrap_err().raw_os_error(),
            Some(5)
        );
        assert!(tolerate_errnos(e(22), &[]).is_err());
        assert!(tolerate_errnos(Ok(()), &[]).is_ok());
    }

    /// NET-1・#2604: 保存した記録が読み戻せ、削除で消え、削除は冪等。
    #[test]
    fn net1_store_save_load_remove_roundtrip() {
        let root = temp_root("rt");
        let s = ReclaimStore::open(&root).expect("open");
        s.save("web", "rec-1\n").expect("save");
        s.save("web", "rec-2\n").expect("replace");
        s.save("db", "rec-3\n").expect("save db");
        let r = s.load().expect("load");
        assert_eq!(
            r.claims,
            vec![
                StoredClaim {
                    name: "db".into(),
                    record: Some("rec-3\n".into())
                },
                StoredClaim {
                    name: "web".into(),
                    record: Some("rec-2\n".into())
                },
            ]
        );
        s.remove_if_matches("web", "stale\n")
            .expect("mismatch keeps");
        assert_eq!(s.load().expect("load").claims.len(), 2);
        s.remove_if_matches("web", "rec-2\n").expect("remove");
        s.remove_if_matches("web", "rec-2\n").expect("idempotent");
        assert_eq!(s.load().expect("load").claims.len(), 1);
        fs::remove_dir_all(&root).expect("cleanup");
    }

    /// 壊れたファイル（長すぎる・不正名）は記録なし・未認識として扱い、消さない。
    #[test]
    fn net1_store_flags_oversized_and_unrecognized_files() {
        let root = temp_root("bad");
        let s = ReclaimStore::open(&root).expect("open");
        let dir = root.join(RECLAIM_DIR);
        fs::write(dir.join("big.claim"), vec![b'a'; CLAIM_RECORD_MAX_LEN + 1]).expect("big");
        fs::write(dir.join("Bad Name.claim"), "x").expect("bad name");
        fs::write(dir.join("ignored.txt"), "x").expect("other");
        let r = s.load().expect("load");
        assert_eq!(
            r.claims,
            vec![StoredClaim {
                name: "big".into(),
                record: None
            }]
        );
        assert_eq!(r.unrecognized, 1);
        assert!(dir.join("big.claim").exists());
        assert_eq!(
            s.save("web", &"a".repeat(CLAIM_RECORD_MAX_LEN + 1))
                .expect_err("too long")
                .code(),
            ErrorCode::Internal
        );
        assert_eq!(
            s.save("../x", "r").expect_err("name").code(),
            ErrorCode::InvalidArgument
        );
        fs::remove_dir_all(&root).expect("cleanup");
    }

    /// 読み取り失敗（記録のパスがディレクトリ）では消さずに失敗し、不存在は成功する（NET-1・#2604）。
    #[test]
    fn net1_store_remove_fails_when_record_unreadable() {
        let root = temp_root("unreadable");
        let s = ReclaimStore::open(&root).expect("open");
        let dir = root.join(RECLAIM_DIR);
        fs::create_dir(dir.join("web.claim")).expect("dir as record");
        assert_eq!(
            s.remove_if_matches("web", "rec\n")
                .expect_err("unreadable")
                .message(),
            "failed to read the reclaim record"
        );
        assert!(dir.join("web.claim").exists());
        s.remove_if_matches("absent", "rec\n").expect("missing ok");
        fs::remove_dir_all(&root).expect("cleanup");
    }

    /// 件数が上限を超えたら fail-closed。
    #[test]
    fn net1_store_load_rejects_too_many_records() {
        let root = temp_root("many");
        let s = ReclaimStore::open(&root).expect("open");
        let dir = root.join(RECLAIM_DIR);
        for i in 0..=MAX_NETWORKS {
            fs::write(dir.join(format!("n{i}.claim")), "r").expect("write");
        }
        assert_eq!(
            s.load().expect_err("limit").message(),
            "reclaim store holds too many records"
        );
        fs::remove_dir_all(&root).expect("cleanup");
    }

    /// 権限違反・symlink の置き場は開けない（unix。SEC-1）。
    #[cfg(unix)]
    #[test]
    fn net1_store_open_rejects_loose_mode_and_symlink() {
        use std::os::unix::fs::PermissionsExt as _;
        let root = temp_root("perm");
        ReclaimStore::open(&root).expect("open");
        let dir = root.join(RECLAIM_DIR);
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o750)).expect("mode");
        assert!(ReclaimStore::open(&root).is_err());
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).expect("mode");
        fs::remove_dir_all(&dir).expect("rmdir");
        let elsewhere = temp_root("elsewhere");
        std::os::unix::fs::symlink(&elsewhere, &dir).expect("symlink");
        assert!(ReclaimStore::open(&root).is_err());
        fs::remove_dir_all(&root).expect("cleanup");
        fs::remove_dir_all(&elsewhere).expect("cleanup");
    }

    /// NET-1・#2681: attach の記録は `attach/` に保存・読み戻し・条件付き削除でき、作成失敗の記録と混ざらない。
    #[test]
    fn net1_store_attach_save_load_remove_roundtrip() {
        let root = temp_root("attach-rt");
        let s = ReclaimStore::open(&root).expect("open");
        s.save("web", "net-rec\n").expect("save net");
        s.save_attach("c1", "att-1\n").expect("save c1");
        s.save_attach("c1", "att-2\n").expect("replace c1");
        s.save_attach("c2.x", "att-3\n").expect("save c2");
        let file = root.join(RECLAIM_DIR).join(ATTACH_DIR).join("c1.attach");
        assert_eq!(fs::read_to_string(&file).expect("read"), "att-2\n");
        let r = s.load().expect("load");
        assert_eq!(r.claims.len(), 1);
        assert_eq!(
            r.attach_claims,
            vec![
                StoredClaim {
                    name: "c1".into(),
                    record: Some("att-2\n".into())
                },
                StoredClaim {
                    name: "c2.x".into(),
                    record: Some("att-3\n".into())
                },
            ]
        );
        s.remove_attach_if_matches("c1", "stale\n")
            .expect("mismatch keeps");
        assert!(file.exists());
        s.remove_attach_if_matches("c1", "att-2\n").expect("remove");
        s.remove_attach_if_matches("c1", "att-2\n")
            .expect("idempotent");
        assert!(!file.exists());
        assert_eq!(s.load().expect("load").attach_claims.len(), 1);
        fs::remove_dir_all(&root).expect("cleanup");
    }

    /// NET-1・#2681: 条件付き更新は中身が一致するときだけ置き換え、別世代の記録・記録なしでは書かない。
    #[test]
    fn net1_store_attach_update_if_matches_is_compare_and_swap() {
        let root = temp_root("attach-cas");
        let s = ReclaimStore::open(&root).expect("open");
        let file = root.join(RECLAIM_DIR).join(ATTACH_DIR).join("c1.attach");
        s.save_attach("c1", "gen-1\n").expect("save gen-1");
        // 別プロセスが新しい世代の請求書を保存した後に、遅れた旧世代の更新が走る。
        s.save_attach("c1", "gen-2\n").expect("save gen-2");
        s.update_attach_if_matches("c1", "gen-1\n", "gen-1-quarantine\n")
            .expect("stale update is a no-op");
        assert_eq!(fs::read_to_string(&file).expect("read"), "gen-2\n");
        // 一致すれば置き換わる。
        s.update_attach_if_matches("c1", "gen-2\n", "gen-2-quarantine\n")
            .expect("matching update");
        assert_eq!(
            fs::read_to_string(&file).expect("read"),
            "gen-2-quarantine\n"
        );
        // 記録が無ければ作らない。
        s.remove_attach_if_matches("c1", "gen-2-quarantine\n")
            .expect("remove");
        s.update_attach_if_matches("c1", "gen-2\n", "x\n")
            .expect("missing is a no-op");
        assert!(!file.exists());
        fs::remove_dir_all(&root).expect("cleanup");
    }

    /// NET-1・#2681: 不正な endpoint 名・長すぎる記録は保存を拒否し、壊れたファイルは記録なし・未認識として残す。
    #[test]
    fn net1_store_attach_rejects_bad_input_and_flags_bad_files() {
        let root = temp_root("attach-bad");
        let s = ReclaimStore::open(&root).expect("open");
        assert_eq!(
            s.save_attach("../x", "r").expect_err("name").code(),
            ErrorCode::InvalidArgument
        );
        assert_eq!(
            s.save_attach("c1", &"a".repeat(CLAIM_RECORD_MAX_LEN + 1))
                .expect_err("long")
                .code(),
            ErrorCode::Internal
        );
        let dir = root.join(RECLAIM_DIR).join(ATTACH_DIR);
        fs::write(dir.join("big.attach"), vec![b'a'; CLAIM_RECORD_MAX_LEN + 1]).expect("big");
        fs::write(dir.join("Bad Name.attach"), "x").expect("bad");
        fs::write(dir.join("ignored.txt"), "x").expect("other");
        let r = s.load().expect("load");
        assert_eq!(
            r.attach_claims,
            vec![StoredClaim {
                name: "big".into(),
                record: None
            }]
        );
        assert_eq!(r.attach_unrecognized, 1);
        assert!(dir.join("big.attach").exists());
        fs::remove_dir_all(&root).expect("cleanup");
    }

    /// SEC-1・#2681: attach の置き場の権限違反と symlink は開けない（unix）。
    #[cfg(unix)]
    #[test]
    fn net1_store_open_rejects_loose_attach_dir() {
        use std::os::unix::fs::PermissionsExt as _;
        let root = temp_root("attach-perm");
        ReclaimStore::open(&root).expect("open");
        let dir = root.join(RECLAIM_DIR).join(ATTACH_DIR);
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o750)).expect("mode");
        assert!(ReclaimStore::open(&root).is_err());
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).expect("mode");
        fs::remove_dir_all(&dir).expect("rmdir");
        let elsewhere = temp_root("attach-elsewhere");
        std::os::unix::fs::symlink(&elsewhere, &dir).expect("symlink");
        assert!(ReclaimStore::open(&root).is_err());
        fs::remove_dir_all(&root).expect("cleanup");
        fs::remove_dir_all(&elsewhere).expect("cleanup");
    }
}
