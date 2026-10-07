//! サイズ上限つき・世代ローテーションのファイル sink（SUP-7・TASK-164.2・#506。関連: ERR-1・REPAIR-3・REPAIR-5）。
//!
//! [`crate::logs::LogCapture`] のリーダースレッド（stdout / stderr の 2 本）から呼ばれる [`LogSink`] のファイル実装。
//! メモリ保持のスタブ [`crate::logs::MemoryLogSink`] と差し替えて使い、捕捉した行を `<container-id>.log` へ追記し、
//! 上限を超える前に `<id>.log.1` 〜 `<id>.log.<N-1>` へ世代を送る（新しいほど番号が小さい）。
//!
//! # 契約
//! - `generations` は現在ログを含む総ファイル数。ディスク使用量の上限は `max_file_bytes × generations`。
//! - 全ファイルは常に `len <= max_file_bytes`。現在ログは必ず空から始まり、空ファイルには最大レコードが
//!   収まる（[`MIN_LOG_FILE_BYTES`] 以上を要求する）ので、1 レコードが世代をまたいで分断されることもない。
//! - 1 レコード = `<stream 名> ` + 行バイト列 + LF。LF 区切りで一意に復元できるよう、[`LogSink::append`] は
//!   LF を含む行を `InvalidArgument` で拒否する（sink は失敗状態にしない）。それ以外の内容は不透明バイト列のまま
//!   書き、解釈・エスケープをしない。
//! - 同じ ID のログは同時に 1 つの sink だけが開ける。[`RotatingFileSink::open`] は `<id>.log.lock` への排他
//!   ロック（unix は flock、Windows は LockFileEx 相当。sink の生存中保持し、プロセス終了で OS が解放する）を
//!   取り、取れなければ（別の sink が使用中）既存ログを動かさず `FailedPrecondition` で拒否する。
//! - 1 つの sink は supervisor プロセスにつき 1 回作り、再起動・再捕捉では同じものを使い回す。
//!   [`RotatingFileSink::open`] は既存の `<id>.log` を開かず世代へ退避してから新規作成するため、
//!   open するたびに 1 世代を消費する。
//! - [`RotatingFileSink::open`] は既存の現在ログ・各世代が上限を超えていれば `InvalidArgument` で拒否し、
//!   `<id>.log.<n>` が NAME_MAX を超える長さの ID も拒否する（いずれも既存ファイルは動かさない）。
//! - 設定の世代数以上の番号の旧世代（`<id>.log.<n>`、`n >= generations`）が残っていれば、世代数を減らした
//!   開き直しとして `InvalidArgument` で拒否する（上限契約を守るため。既存ファイルは動かさず、手動整理を求める）。
//! - ローテーション・書き込みの失敗は握りつぶさず `Internal` で返し、sink を失敗状態に固定する（fail-closed）。
//!   以後の `append` は両ストリームとも `Err` になる。エラーメッセージにパス・行内容・errno は含めない（ERR-1）。
//!
//! # 安全性
//! - 現在ログは `create_new`（`O_CREAT|O_EXCL`）でのみ開く。最終要素が symlink でも辿らないため、
//!   symlink 先への追記を防ぐ。既存エントリは種別を問わず rename / remove（symlink を辿らない）で退避する。
//! - `dir` が symlink・非ディレクトリなら拒否し、unix では group / other 書き込み可も拒否する。
//!   経路上の親要素の symlink・`..` 要素も拒否し（unix は root 所有の symlink のみ許容）、検証後は解決済みパスへ固定する。
//!   新規ファイルは unix で 0600。ファイル名は検証済み [`ContainerId`] を小文字のみへ可逆変換（大文字 `X` → `_x`、`_` → `__`。
//!   大文字小文字非区別 FS での衝突回避。IO-5）した値と固定接尾辞から `Path::join` で組み立てる。
//!
//! # 未実装・制限（REPAIR-3）
//! - ローテーション境界の欠落・重複防止のバッファリング、フラッシュ / fsync 制御: #507（TASK-164.3）。
//!   本実装は `File` へ直接 `write_all` するだけで、クラッシュ時の耐久性は保証しない。
//! - 100 万行規模の欠落 0・重複 0 の検証: #508（TASK-164.4）。
//! - `logs` コマンドからの読み出し経路。退避した世代が symlink の可能性があるため、読み出し側は symlink を辿らず開くこと。
//! - 親ディレクトリ経路の検証後の差し替え（TOCTOU）は完全には防げない（dirfd 基準の固定には core の安全 open の公開が必要）。
//!   所有者（uid）の照合もしない。Windows では権限（ACL）を検査しない。
//! - `dir`（状態ルート配下のどこか）の決定は配線側の責務で、本モジュールは決めない。

use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

use fandhe_container_core::traits::{ContainerId, ErrorCode, TraitError};

use super::{LogSink, MAX_LINE_BYTES, StreamKind};

/// 既定の 1 ファイルあたり上限（1MiB。SUP-7）。
pub const DEFAULT_LOG_FILE_BYTES: u64 = 1024 * 1024;

/// 既定の世代数（現在ログを含む。SUP-7 の 3 世代）。
pub const DEFAULT_LOG_GENERATIONS: u32 = 3;

/// 1 ファイルあたり上限に指定できる最大値。
pub const MAX_LOG_FILE_BYTES: u64 = 1024 * 1024 * 1024;

/// 世代数に指定できる最大値。
pub const MAX_LOG_GENERATIONS: u32 = 16;

/// 旧世代の検査で走査するディレクトリエントリ数の上限（超過は fail-closed で拒否）。
const MAX_SCAN_ENTRIES: usize = 1 << 20;

/// ファイル名 1 要素の最大バイト数（NAME_MAX。Windows は UTF-16 単位 255 だがバイト数で見れば保守的）。
const MAX_FILE_NAME_BYTES: usize = 255;

/// レコード先頭の stream 名 + 区切りの最大長（`"stderr "`）。
const MAX_TAG_BYTES: usize = 7;

/// 1 ファイルあたり上限に指定できる最小値（最大 1 レコード長。空ファイルに必ず 1 レコードが収まる）。
pub const MIN_LOG_FILE_BYTES: u64 = (MAX_TAG_BYTES + MAX_LINE_BYTES + 1) as u64;

/// ローテーション設定（検証済み）。範囲外の値は作れない。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RotationConfig {
    max_file_bytes: u64,
    generations: u32,
}

impl RotationConfig {
    /// `max_file_bytes` が [`MIN_LOG_FILE_BYTES`]..=[`MAX_LOG_FILE_BYTES`]、`generations` が
    /// 1..=[`MAX_LOG_GENERATIONS`] の範囲外なら `InvalidArgument`。
    pub fn new(max_file_bytes: u64, generations: u32) -> Result<Self, TraitError> {
        if !(MIN_LOG_FILE_BYTES..=MAX_LOG_FILE_BYTES).contains(&max_file_bytes) {
            return Err(TraitError::new(
                ErrorCode::InvalidArgument,
                "log file size limit is out of range",
            ));
        }
        if !(1..=MAX_LOG_GENERATIONS).contains(&generations) {
            return Err(TraitError::new(
                ErrorCode::InvalidArgument,
                "log generation count is out of range",
            ));
        }
        Ok(Self {
            max_file_bytes,
            generations,
        })
    }

    /// 1 ファイルあたりの上限バイト数。
    pub fn max_file_bytes(&self) -> u64 {
        self.max_file_bytes
    }

    /// 世代数（現在ログを含む総ファイル数）。
    pub fn generations(&self) -> u32 {
        self.generations
    }
}

impl Default for RotationConfig {
    fn default() -> Self {
        Self {
            max_file_bytes: DEFAULT_LOG_FILE_BYTES,
            generations: DEFAULT_LOG_GENERATIONS,
        }
    }
}

enum State {
    Active {
        file: File,
        size: u64,
    },
    /// ローテーション・書き込みの失敗後。以後の追記はすべて拒否する。
    Failed,
}

struct Inner {
    state: State,
    rotations: u64,
}

/// ファイルへ追記し、上限超過の前に世代を送る [`LogSink`]。
pub struct RotatingFileSink {
    /// 同一 ID の同時使用を排他するロックファイル（生存中保持。ドロップで解放。SUP-7）。
    _lock: File,
    dir: PathBuf,
    base: String,
    config: RotationConfig,
    inner: Mutex<Inner>,
}

/// ID をファイル名用の小文字のみの可逆表現へ変換する（IO-5）。
///
/// [`ContainerId`] は大文字小文字だけが異なる ID（`A` と `a`）を別物として許すが、Windows / macOS の
/// 既定の大文字小文字非区別 FS では同じファイルを指しログが混在・消去される。そのため大文字 `X` は
/// `_x`、`_` は `__` へ写し、出力を小文字・数字・`.`・`-`・`_` のみにする。`_` が常にエスケープの
/// 開始なので単射であり、異なる ID は（大文字小文字を無視しても）異なるファイル名になる。
fn encode_file_stem(id: &str) -> String {
    let mut out = String::with_capacity(id.len().saturating_mul(2));
    for c in id.chars() {
        if c == '_' {
            out.push_str("__");
        } else if c.is_ascii_uppercase() {
            out.push('_');
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

fn internal(msg: &'static str) -> TraitError {
    TraitError::new(ErrorCode::Internal, msg)
}

impl RotatingFileSink {
    /// `dir` 直下に `<id>.log` を作って sink を開く。
    ///
    /// `dir` は既存のディレクトリで、symlink でなく（unix では）group / other 書き込み不可であること。
    /// 既存の `<id>.log` は開かず、世代へ退避してから新規作成する（symlink 先への追記を防ぐ）。
    pub fn open(dir: &Path, id: &ContainerId, config: RotationConfig) -> Result<Self, TraitError> {
        let dir = check_dir(dir)?;
        // `<id>.log.<n>` の最長名が NAME_MAX を超えると open / 初回ローテーションが失敗して
        // sink が failed のままになるため、ここで早期に拒否する。
        let base = format!("{}.log", encode_file_stem(id.as_str()));
        let gen_suffix = if config.generations > 1 {
            // "." + 最大世代番号の 10 進桁数
            1 + (config.generations - 1).to_string().len()
        } else {
            0
        };
        // ロックファイル `<base>.lock` の接尾辞（".lock"）も NAME_MAX に収める。
        let max_suffix = gen_suffix.max(LOCK_SUFFIX.len());
        if base.len().saturating_add(max_suffix) > MAX_FILE_NAME_BYTES {
            return Err(TraitError::new(
                ErrorCode::InvalidArgument,
                "container id is too long for log file names",
            ));
        }
        // 他の sink が同じ ID のログを使用中なら、何も動かさずに拒否する（先に開いた sink が
        // 退避済み世代へ書き続け、世代のサイズ上限・順序が崩れるのを防ぐ。SUP-7）。
        let lock = acquire_lock(&dir, &base)?;
        let sink = Self {
            _lock: lock,
            dir,
            base,
            config,
            inner: Mutex::new(Inner {
                state: State::Failed,
                rotations: 0,
            }),
        };
        // 既存の現在ログ・各世代が上限を超えていたら、何も動かさずに拒否する（契約:
        // 全ファイル len <= max_file_bytes）。上限を下げて開き直した場合は手動で整理させる。
        sink.check_existing_sizes()?;
        sink.check_stale_generations()?;
        // 既存エントリ（種別不問）があれば、辿らずに世代へ送ってから作り直す。
        if fs::symlink_metadata(sink.path(0)).is_ok() {
            sink.shift_generations()?;
        }
        let file = sink.create_active()?;
        sink.lock()?.state = State::Active { file, size: 0 };
        Ok(sink)
    }

    /// これまでのローテーション回数（観測用。REPAIR-4）。open 時の退避は数えない。
    pub fn rotations(&self) -> Result<u64, TraitError> {
        Ok(self.lock()?.rotations)
    }

    fn lock(&self) -> Result<MutexGuard<'_, Inner>, TraitError> {
        self.inner
            .lock()
            .map_err(|_| internal("rotating log sink lock poisoned"))
    }

    /// 世代 `n` のパス（0 = 現在ログ）。
    fn path(&self, n: u32) -> PathBuf {
        if n == 0 {
            self.dir.join(&self.base)
        } else {
            self.dir.join(format!("{}.{n}", self.base))
        }
    }

    /// 現在ログを世代 1 へ送り、古い世代を 1 つずつ後ろへずらす（最古は上書きで消える）。
    fn shift_generations(&self) -> Result<(), TraitError> {
        let fail = || internal("log rotation failed");
        if self.config.generations == 1 {
            return match fs::remove_file(self.path(0)) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
                Err(_) => Err(fail()),
            };
        }
        for i in (0..=self.config.generations - 2).rev() {
            match fs::rename(self.path(i), self.path(i + 1)) {
                Ok(()) => {}
                Err(e) if e.kind() == ErrorKind::NotFound => {}
                Err(_) => return Err(fail()),
            }
        }
        Ok(())
    }

    /// 既存の現在ログ・各世代（`0..generations`）が通常ファイルで、サイズが上限以内であることを確認する。
    ///
    /// ディレクトリ等の通常ファイル・symlink 以外は、`max_file_bytes × generations` の
    /// 契約に収まらずローテーションも失敗し得るため、ファイルを変更する前に拒否する（SUP-7・TASK-164.2）。
    /// symlink はリンク自体が rename / 削除されるだけで参照先を変更しないため許容する
    /// （`symlink_log_target_is_not_modified` テスト参照）。
    fn check_existing_sizes(&self) -> Result<(), TraitError> {
        for i in 0..self.config.generations {
            match fs::symlink_metadata(self.path(i)) {
                Ok(m) if !m.file_type().is_file() && !m.file_type().is_symlink() => {
                    return Err(TraitError::new(
                        ErrorCode::InvalidArgument,
                        "existing log path is not a regular file",
                    ));
                }
                Ok(m) if m.len() > self.config.max_file_bytes => {
                    return Err(TraitError::new(
                        ErrorCode::InvalidArgument,
                        "existing log file exceeds the size limit",
                    ));
                }
                Ok(_) => {}
                Err(e) if e.kind() == ErrorKind::NotFound => {}
                Err(_) => return Err(internal("log file inspection failed")),
            }
        }
        Ok(())
    }

    /// 設定の世代数以上の番号を持つ旧世代（`<id>.log.<n>`、`n >= generations`）が残っていないことを確認する。
    ///
    /// 世代数を減らして開き直すと、範囲外の旧世代はローテーションの対象外のまま残り、
    /// ディスク使用量の上限 `max_file_bytes × generations` の契約を破る。利用者のログを黙って
    /// 消さないため、ファイルを変更する前に `InvalidArgument` で拒否し、手動で整理させる（SUP-7・TASK-164.2）。
    fn check_stale_generations(&self) -> Result<(), TraitError> {
        let prefix = format!("{}.", self.base);
        let rd = fs::read_dir(&self.dir).map_err(|_| internal("log directory scan failed"))?;
        // 番号の上限では打ち切らず、ディレクトリを列挙して対象 ID の世代ファイルを全て検査する。
        // 走査件数には上限を設け（超過は fail-closed）、確保はエントリ単位の一時値のみに留める。
        let mut scanned = 0usize;
        for entry in rd {
            scanned += 1;
            if scanned > MAX_SCAN_ENTRIES {
                return Err(TraitError::new(
                    ErrorCode::InvalidArgument,
                    "log directory has too many entries to verify",
                ));
            }
            let entry = entry.map_err(|_| internal("log directory scan failed"))?;
            let name = entry.file_name();
            let Some(num) = name.to_str().and_then(|n| n.strip_prefix(prefix.as_str())) else {
                continue;
            };
            // 正規形（先頭 0 なしの 10 進数）だけが世代番号。桁あふれは十分大きい番号として扱う。
            if num.is_empty()
                || !num.bytes().all(|b| b.is_ascii_digit())
                || (num.len() > 1 && num.starts_with('0'))
            {
                continue;
            }
            let stale = num
                .parse::<u64>()
                .map_or(true, |n| n >= u64::from(self.config.generations));
            if stale {
                return Err(TraitError::new(
                    ErrorCode::InvalidArgument,
                    "stale log generation exists beyond the configured generation count",
                ));
            }
        }
        Ok(())
    }

    fn create_active(&self) -> Result<File, TraitError> {
        let mut opts = OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        opts.open(self.path(0))
            .map_err(|_| internal("log file create failed"))
    }
}

/// ロックファイル名の接尾辞（`<base>.lock`。世代番号は数字のみのため世代ファイルと衝突しない）。
const LOCK_SUFFIX: &str = ".lock";

/// `<base>.lock` を開き排他ロックを取る。取れなければ（別の sink が使用中）`FailedPrecondition`。
///
/// ロックファイルは内容を持たず、書き込みもしない。新規作成は `create_new`（symlink を辿らない）、
/// 既存は通常ファイル（symlink・FIFO 等は拒否）のときだけ読み取りで開く。
fn acquire_lock(dir: &Path, base: &str) -> Result<File, TraitError> {
    let path = dir.join(format!("{base}{LOCK_SUFFIX}"));
    let mut create = OpenOptions::new();
    create.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        create.mode(0o600);
    }
    let file = match create.open(&path) {
        Ok(f) => f,
        Err(e) if e.kind() == ErrorKind::AlreadyExists => {
            match fs::symlink_metadata(&path) {
                Ok(m) if m.file_type().is_file() => {}
                _ => {
                    return Err(TraitError::new(
                        ErrorCode::InvalidArgument,
                        "log lock path is not a regular file",
                    ));
                }
            }
            OpenOptions::new()
                .read(true)
                .open(&path)
                .map_err(|_| internal("log lock open failed"))?
        }
        Err(_) => return Err(internal("log lock create failed")),
    };
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(std::fs::TryLockError::WouldBlock) => Err(TraitError::new(
            ErrorCode::FailedPrecondition,
            "log is in use by another sink",
        )),
        Err(std::fs::TryLockError::Error(_)) => Err(internal("log lock failed")),
    }
}

/// `dir` が実在するディレクトリで、経路上に（信頼できない）symlink を含まず、（unix では）他者書き込み不可で
/// あることを確認し、解決済みの絶対パスを返す。以後のファイル操作はこの固定したパスで行う（再解決しない）。
///
/// 親要素の symlink は、リンク先が状態ルート外でも最終要素の検査を通ってしまうため、全祖先を検査する。
/// `..` 要素は拒否する。unix では root 所有の symlink（`/var` -> `/private/var` 等の OS 標準）のみ許容する
/// （一般ユーザーは root 所有の symlink を作れない）。他 OS では symlink を一律拒否する。
fn check_dir(dir: &Path) -> Result<PathBuf, TraitError> {
    let invalid = |msg: &'static str| TraitError::new(ErrorCode::InvalidArgument, msg);
    if dir
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(invalid("log directory path contains a parent reference"));
    }
    let meta = fs::symlink_metadata(dir).map_err(|_| invalid("log directory is not accessible"))?;
    if !meta.is_dir() {
        return Err(invalid("log directory is not a directory"));
    }
    for anc in dir.ancestors().skip(1) {
        if anc.as_os_str().is_empty() {
            continue;
        }
        let m = fs::symlink_metadata(anc)
            .map_err(|_| invalid("log directory parent is not accessible"))?;
        if m.file_type().is_symlink() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                if m.uid() == 0 {
                    continue;
                }
            }
            return Err(invalid("log directory path contains a symbolic link"));
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if meta.mode() & 0o022 != 0 {
            return Err(TraitError::new(
                ErrorCode::PermissionDenied,
                "log directory is writable by group or others",
            ));
        }
    }
    // 検証済みの実体パスへ固定する（以後 sink は元の `dir` を再解決しない）。
    fs::canonicalize(dir).map_err(|_| invalid("log directory is not accessible"))
}

impl LogSink for RotatingFileSink {
    fn append(&self, stream: StreamKind, line: &[u8]) -> Result<(), TraitError> {
        // LF を含むと 1 追記が複数レコードに見え、LF 区切りで一意に復元できなくなるため拒否する（SUP-7）。
        if line.contains(&b'\n') {
            return Err(TraitError::new(
                ErrorCode::InvalidArgument,
                "log line must not contain a line feed",
            ));
        }
        // 直接呼び出しでも確保量を抑えるため、確保前に MAX_LINE_BYTES へ切り詰める。
        let line = line.get(..MAX_LINE_BYTES).unwrap_or(line);
        let tag = stream.as_str();
        let mut rec = Vec::with_capacity(tag.len() + 1 + line.len() + 1);
        rec.extend_from_slice(tag.as_bytes());
        rec.push(b' ');
        rec.extend_from_slice(line);
        rec.push(b'\n');
        let rec_len = u64::try_from(rec.len()).map_err(|_| internal("log record too large"))?;

        let mut g = self.lock()?;
        let size = match &g.state {
            State::Active { size, .. } => *size,
            State::Failed => return Err(internal("log sink is in failed state")),
        };
        let needs_rotate = size
            .checked_add(rec_len)
            .is_none_or(|n| n > self.config.max_file_bytes);
        if needs_rotate {
            // Windows は開いたままのファイルを rename できないため、先に失敗状態へ落として File を閉じる。
            g.state = State::Failed;
            self.shift_generations()?;
            let file = self.create_active()?;
            g.state = State::Active { file, size: 0 };
            g.rotations = g.rotations.saturating_add(1);
        }
        let State::Active { file, size } = &mut g.state else {
            return Err(internal("log sink is in failed state"));
        };
        if file.write_all(&rec).is_err() {
            // 部分書き込みの可能性があるため以後は書かない。
            g.state = State::Failed;
            return Err(internal("log write failed"));
        }
        *size = size.saturating_add(rec_len);
        Ok(())
    }
}

#[cfg(test)]
mod tests;
