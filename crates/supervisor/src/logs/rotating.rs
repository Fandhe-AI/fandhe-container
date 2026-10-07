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
//! - 1 レコード = `<stream 名> ` + 行バイト列 + LF。[`LogSink::append`] は行を先に [`MAX_LINE_BYTES`] へ
//!   切り詰め、記録する範囲に LF を含む行だけを `InvalidArgument` で拒否する（LF 区切りで一意に復元する
//!   ため。sink は失敗状態にしない）。それ以外の内容は不透明バイト列のまま書き、解釈・エスケープをしない。
//!   書き込み失敗で失敗状態になった sink のファイルは、末尾レコードが途中で切れていることがある。
//! - 同じ ID のログは同時に 1 つの sink だけが開ける。[`RotatingFileSink::open`] は `<id>.log.lock` への排他
//!   ロック（unix は flock、Windows は LockFileEx 相当。sink の生存中保持し、プロセス終了で OS が解放する）を
//!   取り、取れなければ（別の sink が使用中）既存ログを動かさず `FailedPrecondition` で拒否する。
//!   ロックファイルは空のまま残す（open が検査で失敗した場合も残る）。消すと排他が崩れるため、sink の
//!   生存中は消さないこと（コンテナ削除時の掃除は配線側の責務）。
//! - 1 つの sink は supervisor プロセスにつき 1 回作り、再起動・再捕捉では同じものを使い回す。
//!   [`RotatingFileSink::open`] は既存の `<id>.log` を開かず世代へ退避してから新規作成するため、
//!   open するたびに 1 世代を消費する（既存の `<id>.log` が空なら退避せず作り直し、世代を消費しない）。
//! - sink が使う名前空間は `<id>.log`・`<id>.log.lock`・`<id>.log.<10 進数字>` で、他の ID の名前とは
//!   重ならない。[`RotatingFileSink::open`] はディレクトリを列挙し、この名前空間のエントリを 1 つでも
//!   受理できなければ、既存ファイルを動かさず `InvalidArgument` で拒否する（手動整理を求める）。
//!   受理するのは、通常ファイルで `len <= max_file_bytes` の `<id>.log` と `<id>.log.<n>`
//!   （`1 <= n < generations`、先頭 0 なし）だけである。したがって世代番号 0・先頭 0 つき・世代数以上の
//!   番号（世代数を減らした開き直し）・上限超過・ディレクトリ・symlink・ASCII 大文字小文字だけが違う別名
//!   （大文字小文字非区別 FS では同じファイルを指す）は拒否する。これらはローテーションの対象外のまま
//!   残り、ディスク使用量の上限を破るためである。
//! - `<id>.log.<n>` が NAME_MAX を超える長さの ID も `InvalidArgument` で拒否する。
//! - ローテーション・書き込みの失敗は握りつぶさず `Internal` で返し、sink を失敗状態に固定する（fail-closed）。
//!   以後の `append` は両ストリームとも `Err` になる。エラーメッセージにパス・行内容・errno は含めない（ERR-1）。
//!
//! # 安全性
//! - 現在ログは `create_new`（`O_CREAT|O_EXCL`）でのみ開く。最終要素が symlink でも辿らないため、
//!   symlink 先への追記を防ぐ。既存ファイルは開かず、rename / remove（symlink を辿らない）だけで動かす。
//! - 既存のロックファイルは、開く前後の種別（unix は dev / inode も）が一致する通常ファイルのときだけ使い、
//!   読み取りでしか開かない（検査後に symlink へ差し替えられても、その先へ書かない）。
//! - `dir` は絶対パスに限る（相対パスは CWD より上の要素を検査できない）。末尾の区切り文字・`.` は要素から
//!   組み直して除く（`link/` は lstat が symlink を辿り、最終要素の検査をすり抜けるため）。`dir` が symlink・
//!   非ディレクトリなら拒否し、unix では group / other 書き込み可も拒否する。経路上の親要素の symlink・`..` 要素も
//!   拒否し（unix は root 所有の symlink のみ許容）、検証後は解決済みパスへ固定する。
//! - 新規ファイルは unix で 0600。ファイル名は検証済み [`ContainerId`] を小文字のみへ可逆変換（大文字 `X` → `_x`、
//!   `_` → `__`。大文字小文字非区別 FS での衝突回避。IO-5）した値と固定接尾辞から `Path::join` で組み立てる。
//!   Windows の予約デバイス名（`con`・`nul`・`com1` 等。拡張子つきでもデバイスとして開かれ得る）で始まる
//!   名前には、先頭に `_0` を付けて避ける（全 OS で同じ名前にする）。
//!
//! # バッファ・フラッシュ制御（TASK-164.3・#507）
//! - 書き込みは固定 [`WRITE_BUFFER_BYTES`] のバッファ越しに行う。[`LogSink::append`] の `Ok` は受理を意味し、
//!   ディスクへの到達は意味しない。読み出し側・リーダーは [`LogSink::flush`]（または drop）で書き出す。
//! - `size` はバッファ内を含む論理バイト数で、ローテーション判定は論理サイズで行う（ディスク上の長さは常にそれ以下なので
//!   「全ファイル `len <= max_file_bytes`」「1 レコードが世代をまたがない」は保たれる）。
//! - ローテーションの順序は固定: 残りバッファを退避前の旧ファイルへ書き切る → `sync_data` → ファイルを閉じる →
//!   世代の rename → （unix）ディレクトリの fsync → 新ファイル作成。バッファを新ファイルへ持ち越さないため、
//!   境界で行が欠落・重複・誤配置しない。Windows は開いたファイルを rename できないので、この順序が必須でもある。
//! - 失敗は fail-closed: 書き込み・flush・ローテーションが失敗した sink は失敗状態に固定し、バッファを捨てて再試行しない
//!   （再書き込みによる重複を作らない）。そのとき、バッファにあった受理済みの複数レコードが失われ得る。
//! - fsync はローテーションで退避する世代と、明示の [`RotatingFileSink::sync`] だけ。現在ログはクラッシュ時に
//!   最後の `sync` / ローテーション以降の分を失い得る。
//!
//! # 未実装・制限（REPAIR-3）
//! - flush ごとの fsync・設定可能な同期ポリシー・タイマーによる定期 flush（短い read を契機とする flush で代替）。
//!   [`RotatingFileSink::sync`] をコンテナ終了時などに呼ぶ配線も未実装（配線側の責務）。
//! - 100 万行規模の欠落 0・重複 0 の検証: #508（TASK-164.4）。
//! - `logs` コマンドからの読み出し経路。open 後に差し替えられた世代が symlink の可能性は残るため、
//!   読み出し側は symlink を辿らず開くこと。
//! - 親ディレクトリ経路の検証後の差し替え（TOCTOU）は完全には防げない（dirfd 基準の固定には core の安全 open の公開が必要）。
//!   所有者（uid）の照合もしない。Windows では権限（ACL）を検査しない。
//! - 名前空間の別名検査は ASCII の大文字小文字だけを見る。FS 固有の Unicode 畳み込み（APFS の `K` U+212A 等）
//!   による別名は検出しない。
//! - Windows では、他プロセスが世代ファイルを削除共有なしで開いていると rename が失敗し、sink は失敗状態に
//!   固定される（再試行しない）。読み出し側は削除共有つきで開くこと。
//! - `dir`（状態ルート配下のどこか）の決定は配線側の責務で、本モジュールは決めない。

use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, ErrorKind, Write};
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

/// 書き込みバッファの容量（固定。sink あたりの常駐メモリ増を [`super::READ_CHUNK_BYTES`] と同じ 8KiB に抑える。CORE-7）。
/// 容量を超えるレコードは `BufWriter` が直接書くので、確保は増えない。
const WRITE_BUFFER_BYTES: usize = 8 * 1024;

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
        writer: BufWriter<File>,
        /// バッファ内を含む論理バイト数。
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
///
/// ID の最初の `.` より前が Windows の予約デバイス名（[`is_reserved_device_name`]）なら、先頭に `_0` を
/// 付ける（`con.log` はコンソールデバイスとして開かれ得る）。`_` の直後が数字になる出力は他に無いので、
/// 単射性は保たれる。
fn encode_file_stem(id: &str) -> String {
    let mut out = String::with_capacity(id.len().saturating_mul(2).saturating_add(2));
    let first = id.split('.').next().unwrap_or(id);
    if is_reserved_device_name(first) {
        out.push_str("_0");
    }
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

/// Windows が拡張子の有無によらずデバイスとして扱う名前か（小文字で比較する。大文字を含む ID は
/// 変換で `_x` になり予約名と一致しなくなるため、小文字の一致だけを見ればよい）。
fn is_reserved_device_name(s: &str) -> bool {
    if matches!(s, "con" | "prn" | "aux" | "nul") {
        return true;
    }
    match s.as_bytes() {
        [a, b, c, d] => matches!(&[*a, *b, *c], b"com" | b"lpt") && d.is_ascii_digit(),
        _ => false,
    }
}

fn invalid(msg: &'static str) -> TraitError {
    TraitError::new(ErrorCode::InvalidArgument, msg)
}

fn internal(msg: &'static str) -> TraitError {
    TraitError::new(ErrorCode::Internal, msg)
}

impl RotatingFileSink {
    /// `dir` 直下に `<id>.log` を作って sink を開く。
    ///
    /// `dir` は絶対パスで指す既存のディレクトリで、symlink でなく（unix では）group / other 書き込み不可で
    /// あること。既存の `<id>.log` は開かず、世代へ退避してから新規作成する（symlink 先への追記を防ぐ）。
    /// 名前空間（モジュール doc「契約」）に受理できないエントリがあれば、既存ファイルを動かさず拒否する。
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
        // 名前空間のエントリを 1 つでも受理できなければ、何も動かさずに拒否する（契約: 全ファイルが
        // 通常ファイルで len <= max_file_bytes、総数は generations 以内）。手動で整理させる。
        sink.check_namespace()?;
        sink.check_existing_files()?;
        // 既存の現在ログは開かず、世代へ送ってから作り直す。空なら世代を消費せず消すだけにする
        // （出力の無い再起動が続いても、保持している世代を押し出さない）。
        match fs::symlink_metadata(sink.path(0)) {
            Ok(m) if m.len() == 0 => {
                fs::remove_file(sink.path(0)).map_err(|_| internal("log rotation failed"))?;
            }
            Ok(_) => sink.shift_generations()?,
            Err(e) if e.kind() == ErrorKind::NotFound => {}
            Err(_) => return Err(internal("log file inspection failed")),
        }
        let file = sink.create_active()?;
        sink.lock()?.state = State::Active {
            writer: BufWriter::with_capacity(WRITE_BUFFER_BYTES, file),
            size: 0,
        };
        Ok(sink)
    }

    /// これまでのローテーション回数（観測用。REPAIR-4）。open 時の退避は数えない。
    pub fn rotations(&self) -> Result<u64, TraitError> {
        Ok(self.lock()?.rotations)
    }

    /// バッファを書き出し、現在ログの内容を `sync_data` で永続化する（コンテナ終了時など、末尾行を確実に残したい
    /// 呼び出し側向け。TASK-164.3）。失敗すると sink は失敗状態に固定される。失敗状態では `Internal`。
    pub fn sync(&self) -> Result<(), TraitError> {
        let mut g = self.lock()?;
        let State::Active { writer, .. } = &mut g.state else {
            return Err(internal("log sink is in failed state"));
        };
        let ok = writer.flush().is_ok() && writer.get_ref().sync_data().is_ok();
        if ok {
            return Ok(());
        }
        fail_sink(&mut g.state);
        Err(internal("log sync failed"))
    }

    /// 旧ファイルを書き切って退避し、新しい現在ログを作る（ローテーションの順序はモジュール doc 参照）。
    /// 失敗時の呼び出し側は state を失敗状態にしたままにする。
    fn rotate(&self, writer: BufWriter<File>) -> Result<BufWriter<File>, TraitError> {
        let file = match writer.into_inner() {
            Ok(f) => f,
            Err(e) => {
                // バッファは捨てる（drop による暗黙の再書き込みを避け、重複を作らない）。
                let (_err, bw) = e.into_parts();
                let _ = bw.into_parts();
                return Err(internal("log write failed"));
            }
        };
        file.sync_data()
            .map_err(|_| internal("log rotation failed"))?;
        // Windows は開いたままのファイルを rename できないため、閉じてから世代を送る。
        drop(file);
        self.shift_generations()?;
        sync_dir(&self.dir)?;
        let file = self.create_active()?;
        Ok(BufWriter::with_capacity(WRITE_BUFFER_BYTES, file))
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
    /// ディレクトリ・symlink 等は `max_file_bytes × generations` の契約に収まらない（symlink の長さは
    /// 参照先のサイズではなく、ディレクトリはローテーションも失敗させる）ため、ファイルを変更する前に
    /// 拒否する（SUP-7・TASK-164.2）。現在ログは `create_new` でしか開かないので、検査後に symlink へ
    /// 差し替えられても参照先へは書かない。
    fn check_existing_files(&self) -> Result<(), TraitError> {
        for i in 0..self.config.generations {
            match fs::symlink_metadata(self.path(i)) {
                Ok(m) if !m.file_type().is_file() => {
                    return Err(invalid("existing log path is not a regular file"));
                }
                Ok(m) if m.len() > self.config.max_file_bytes => {
                    return Err(invalid("existing log file exceeds the size limit"));
                }
                Ok(_) => {}
                Err(e) if e.kind() == ErrorKind::NotFound => {}
                Err(_) => return Err(internal("log file inspection failed")),
            }
        }
        Ok(())
    }

    /// `dir` を列挙し、この sink の名前空間に受理できない名前のエントリが無いことを確認する。
    ///
    /// 名前空間は `<base>`・`<base>.lock`・`<base>.<10 進数字>`（ASCII の大文字小文字を無視して比較）。
    /// 他の ID の名前は `.log` / `.lock` / `<別の base>.<数字>` で終わるので、ここには入らない。
    /// 受理するのは、小文字の正確な綴りの `<base>`・`<base>.lock` と、先頭 0 なしで `1 <= n < generations`
    /// の `<base>.<n>` だけである。世代番号 0・先頭 0 つき・世代数以上の番号・大文字小文字違いの別名は、
    /// ローテーションの対象外のまま残って上限 `max_file_bytes × generations` を破るため、ファイルを
    /// 変更する前に `InvalidArgument` で拒否する（利用者のログを黙って消さない。SUP-7・TASK-164.2）。
    /// 種別とサイズは [`Self::check_existing_files`] が見る。
    fn check_namespace(&self) -> Result<(), TraitError> {
        let unexpected = || invalid("unexpected entry exists in the log file namespace");
        let lock_name = format!("{}{LOCK_SUFFIX}", self.base);
        let prefix = format!("{}.", self.base);
        let rd = fs::read_dir(&self.dir).map_err(|_| internal("log directory scan failed"))?;
        // 番号の上限では打ち切らず、ディレクトリを列挙して対象 ID の名前を全て検査する。
        // 走査件数には上限を設け（超過は fail-closed）、確保はエントリ単位の一時値のみに留める。
        let mut scanned = 0usize;
        for entry in rd {
            scanned = scanned.saturating_add(1);
            if scanned > MAX_SCAN_ENTRIES {
                return Err(invalid("log directory has too many entries to verify"));
            }
            let entry = entry.map_err(|_| internal("log directory scan failed"))?;
            let name = entry.file_name();
            // sink の名前は ASCII のみ。UTF-8 でない名前は名前空間に入らない。
            let Some(name) = name.to_str() else {
                continue;
            };
            let lower = name.to_ascii_lowercase();
            if lower == self.base || lower == lock_name {
                if name != lower {
                    return Err(unexpected());
                }
                continue;
            }
            let Some(num) = lower.strip_prefix(prefix.as_str()) else {
                continue;
            };
            if num.is_empty() || !num.bytes().all(|b| b.is_ascii_digit()) {
                continue;
            }
            // ここからは世代番号の名前空間。正規形（先頭 0 なし）で 1..generations の範囲だけを受理する。
            // 桁あふれは範囲外として扱う。
            let in_range = num
                .parse::<u64>()
                .is_ok_and(|n| n >= 1 && n < u64::from(self.config.generations));
            if name != lower || num.starts_with('0') || !in_range {
                return Err(TraitError::new(
                    ErrorCode::InvalidArgument,
                    "stale or malformed log generation exists outside the configured generations",
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
/// 既存は通常ファイル（symlink・FIFO 等は拒否）のときだけ読み取りで開く。std には `O_NOFOLLOW` 相当が
/// 無いため、開いた実体が検査したものと同じ通常ファイルであることを開いた後にも確かめる
/// （検査と open の間の差し替え対策。unix は dev / inode も照合する）。
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
        // 作れなかったときは、既存エントリの種別で分ける（既存がディレクトリのときの create_new の
        // エラー種別は OS で異なるため、種別は lstat で判定する）。
        Err(_) => {
            let not_regular = || invalid("log lock path is not a regular file");
            let before = match fs::symlink_metadata(&path) {
                Ok(m) if m.file_type().is_file() => m,
                Ok(_) => return Err(not_regular()),
                Err(_) => return Err(internal("log lock create failed")),
            };
            let file = OpenOptions::new()
                .read(true)
                .open(&path)
                .map_err(|_| internal("log lock open failed"))?;
            let after = file
                .metadata()
                .map_err(|_| internal("log lock open failed"))?;
            if !after.file_type().is_file() {
                return Err(not_regular());
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                if before.dev() != after.dev() || before.ino() != after.ino() {
                    return Err(not_regular());
                }
            }
            #[cfg(not(unix))]
            let _ = before;
            file
        }
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
///
/// 相対パスは拒否する（CWD より上の要素を検査できない）。検査の前に要素から組み直して、末尾の区切り文字と
/// `.` を除く（`link/` のような末尾の区切り文字があると `lstat` が最終要素の symlink を辿り、symlink 検査を
/// すり抜けるため。core の `StateRoot::from_override` と同じ扱い）。
fn check_dir(dir: &Path) -> Result<PathBuf, TraitError> {
    if !dir.is_absolute() {
        return Err(invalid("log directory must be an absolute path"));
    }
    if dir
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(invalid("log directory path contains a parent reference"));
    }
    let dir: PathBuf = dir.components().collect();
    let dir = dir.as_path();
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
        // 直接呼び出しでも確保量を抑えるため、確保前に MAX_LINE_BYTES へ切り詰める。
        let line = line.get(..MAX_LINE_BYTES).unwrap_or(line);
        // LF を含むと 1 追記が複数レコードに見え、LF 区切りで一意に復元できなくなるため拒否する（SUP-7）。
        // 検査は記録する範囲（切り詰め後）に対して行う。捨てる部分の LF は記録に現れない。
        if line.contains(&b'\n') {
            return Err(invalid("log line must not contain a line feed"));
        }
        let tag = stream.as_str();
        let mut rec = Vec::with_capacity(tag.len() + 1 + line.len() + 1);
        rec.extend_from_slice(tag.as_bytes());
        rec.push(b' ');
        rec.extend_from_slice(line);
        rec.push(b'\n');
        let rec_len = u64::try_from(rec.len()).map_err(|_| internal("log record too large"))?;
        // 空ファイルにも収まらないレコードは書かない（全ファイル len <= max_file_bytes の不変条件を、
        // stream 名が将来長くなっても破らないための防御。現状は MIN_LOG_FILE_BYTES の下限により到達しない）。
        if rec_len > self.config.max_file_bytes {
            return Err(internal("log record too large"));
        }

        let mut g = self.lock()?;
        let size = match &g.state {
            State::Active { size, .. } => *size,
            State::Failed => return Err(internal("log sink is in failed state")),
        };
        let needs_rotate = size
            .checked_add(rec_len)
            .is_none_or(|n| n > self.config.max_file_bytes);
        if needs_rotate {
            // 失敗状態へ落として writer を取り出す（以後どの失敗でも失敗状態のまま。再試行しない）。
            let State::Active { writer, .. } = std::mem::replace(&mut g.state, State::Failed)
            else {
                return Err(internal("log sink is in failed state"));
            };
            let writer = self.rotate(writer)?;
            g.state = State::Active { writer, size: 0 };
            g.rotations = g.rotations.saturating_add(1);
        }
        let State::Active { writer, size } = &mut g.state else {
            return Err(internal("log sink is in failed state"));
        };
        if writer.write_all(&rec).is_ok() {
            *size = size.saturating_add(rec_len);
            return Ok(());
        }
        // 部分書き込みの可能性があるため以後は書かない（バッファも捨てる）。
        fail_sink(&mut g.state);
        Err(internal("log write failed"))
    }

    /// バッファを書き出す（fsync はしない）。失敗すると sink は失敗状態に固定される（TASK-164.3）。
    fn flush(&self) -> Result<(), TraitError> {
        let mut g = self.lock()?;
        let State::Active { writer, .. } = &mut g.state else {
            return Err(internal("log sink is in failed state"));
        };
        if writer.flush().is_ok() {
            return Ok(());
        }
        fail_sink(&mut g.state);
        Err(internal("log flush failed"))
    }
}

impl Drop for RotatingFileSink {
    /// ロック解放（フィールドの drop）より前に、残りのバッファを best-effort で書き出す。失敗は捨てる。
    fn drop(&mut self) {
        if let Ok(mut g) = self.inner.lock()
            && let State::Active { writer, .. } = &mut g.state
        {
            let _ = writer.flush();
        }
    }
}

/// 失敗状態へ固定し、未書き出しのバッファを捨てる（`BufWriter` の drop による再書き込みを避ける）。
fn fail_sink(state: &mut State) {
    if let State::Active { writer, .. } = std::mem::replace(state, State::Failed) {
        let _ = writer.into_parts();
    }
}

/// ログディレクトリを fsync して rename を永続化する（unix。検証済みの `dir` を読み取りで開くだけ）。
/// 他 OS ではディレクトリの fsync 手段が無いため何もしない。
#[cfg(unix)]
fn sync_dir(dir: &Path) -> Result<(), TraitError> {
    let fail = || internal("log rotation failed");
    let d = File::open(dir).map_err(|_| fail())?;
    if !d.metadata().map_err(|_| fail())?.is_dir() {
        return Err(fail());
    }
    d.sync_all().map_err(|_| fail())
}

#[cfg(not(unix))]
fn sync_dir(_dir: &Path) -> Result<(), TraitError> {
    Ok(())
}

#[cfg(test)]
mod tests;
