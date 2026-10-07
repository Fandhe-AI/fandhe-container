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
//! - 1 レコード = `<stream 名> ` + 行バイト列 + LF。行は LF を含まないため、LF 区切りで一意に復元できる。
//!   行の内容は不透明バイト列のまま書き、解釈・エスケープをしない。
//! - 1 つの sink は supervisor プロセスにつき 1 回作り、再起動・再捕捉では同じものを使い回す。
//!   [`RotatingFileSink::open`] は既存の `<id>.log` を開かず世代へ退避してから新規作成するため、
//!   open するたびに 1 世代を消費する。
//! - [`RotatingFileSink::open`] は既存の現在ログ・各世代が上限を超えていれば `InvalidArgument` で拒否し、
//!   `<id>.log.<n>` が NAME_MAX を超える長さの ID も拒否する（いずれも既存ファイルは動かさない）。
//! - ローテーション・書き込みの失敗は握りつぶさず `Internal` で返し、sink を失敗状態に固定する（fail-closed）。
//!   以後の `append` は両ストリームとも `Err` になる。エラーメッセージにパス・行内容・errno は含めない（ERR-1）。
//!
//! # 安全性
//! - 現在ログは `create_new`（`O_CREAT|O_EXCL`）でのみ開く。最終要素が symlink でも辿らないため、
//!   symlink 先への追記を防ぐ。既存エントリは種別を問わず rename / remove（symlink を辿らない）で退避する。
//! - `dir` が symlink・非ディレクトリなら拒否し、unix では group / other 書き込み可も拒否する。
//!   新規ファイルは unix で 0600。ファイル名は検証済み [`ContainerId`] と固定接尾辞から `Path::join` で組み立てる。
//!
//! # 未実装・制限（REPAIR-3）
//! - ローテーション境界の欠落・重複防止のバッファリング、フラッシュ / fsync 制御: #507（TASK-164.3）。
//!   本実装は `File` へ直接 `write_all` するだけで、クラッシュ時の耐久性は保証しない。
//! - 100 万行規模の欠落 0・重複 0 の検証: #508（TASK-164.4）。
//! - `logs` コマンドからの読み出し経路。退避した世代が symlink の可能性があるため、読み出し側は symlink を辿らず開くこと。
//! - 親ディレクトリ経路の検証後の差し替え（TOCTOU）は防げない（dirfd 基準の固定には core の安全 open の公開が必要）。
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
    dir: PathBuf,
    base: String,
    config: RotationConfig,
    inner: Mutex<Inner>,
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
        check_dir(dir)?;
        // `<id>.log.<n>` の最長名が NAME_MAX を超えると open / 初回ローテーションが失敗して
        // sink が failed のままになるため、ここで早期に拒否する。
        let base = format!("{}.log", id.as_str());
        let max_suffix = if config.generations > 1 {
            // "." + 最大世代番号の 10 進桁数
            1 + (config.generations - 1).to_string().len()
        } else {
            0
        };
        if base.len().saturating_add(max_suffix) > MAX_FILE_NAME_BYTES {
            return Err(TraitError::new(
                ErrorCode::InvalidArgument,
                "container id is too long for log file names",
            ));
        }
        let sink = Self {
            dir: dir.to_path_buf(),
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

/// `dir` が実在するディレクトリで、symlink でなく、（unix では）他者書き込み不可であることを確認する。
fn check_dir(dir: &Path) -> Result<(), TraitError> {
    let meta = fs::symlink_metadata(dir).map_err(|_| {
        TraitError::new(
            ErrorCode::InvalidArgument,
            "log directory is not accessible",
        )
    })?;
    if !meta.is_dir() {
        return Err(TraitError::new(
            ErrorCode::InvalidArgument,
            "log directory is not a directory",
        ));
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
    Ok(())
}

impl LogSink for RotatingFileSink {
    fn append(&self, stream: StreamKind, line: &[u8]) -> Result<(), TraitError> {
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
