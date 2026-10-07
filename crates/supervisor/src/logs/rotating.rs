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
//!   ロックファイルは空のままで、sink を閉じただけでは残る。消すのは次の 2 経路だけで、どちらもロックを
//!   取得した状態で行う（SUP-7・TASK-164 追補・#1469）: (1) [`RotatingFileSink::open`] がロック取得後の検査・
//!   初期化で失敗したとき（元のエラーを返す）、(2) [`RotatingFileSink::remove_all`]（現在ログ・全世代と
//!   一括。sink 生存中は `FailedPrecondition` で何も消さない）。ロック競合・ロックパスが通常ファイルでない
//!   ときの失敗では消さない（他の sink のものであるため）。sink の生存中に外から消してはならない。
//!   消すと排他が崩れ得るため、取得後にパスの実体を再照合し（unix は dev / inode）、Windows は削除共有なしで
//!   開く。コンテナ削除経路からの呼び出し配線は未実装（REPAIR-3）。
//! - 1 つの sink は supervisor プロセスにつき 1 回作り、再起動・再捕捉では同じものを使い回す。
//!   [`RotatingFileSink::open`] は既存の `<id>.log` を開かず世代へ退避してから新規作成するため、
//!   open するたびに 1 世代を消費する（既存の `<id>.log` が空なら退避せず作り直し、世代を消費しない）。
//! - sink が使う名前空間は `<id>.log`・`<id>.log.lock`・`<id>.log.<10 進数字>` で、他の ID の名前とは
//!   重ならない。[`RotatingFileSink::open`] はディレクトリを列挙し、この名前空間のエントリを 1 つでも
//!   受理できなければ、既存ファイルを動かさず `InvalidArgument` で拒否する（手動整理を求める）。
//!   受理するのは、通常ファイルで `len <= max_file_bytes` の `<id>.log` と `<id>.log.<n>`
//!   （`1 <= n < generations`、先頭 0 なし）だけである。したがって世代番号 0・先頭 0 つき・世代数以上の
//!   番号（世代数を減らした開き直し）・上限超過・ディレクトリ・symlink・ASCII 大文字小文字だけが違う別名
//!   （大文字小文字非区別 FS では同じファイルを指す）・Unicode の畳み込みで ASCII へ写る文字を含む別名
//!   （U+212A `K` 等。[`fold_for_alias`] の 4 文字）は拒否する。これらはローテーションの対象外のまま
//!   残り、ディスク使用量の上限を破るためである。
//! - `<id>.log.<n>` が NAME_MAX を超える長さの ID も `InvalidArgument` で拒否する。
//! - ローテーション・書き込みの失敗は握りつぶさず `Internal` で返し、sink を失敗状態に固定する（fail-closed）。
//!   以後の `append` は両ストリームとも `Err` になる。エラーメッセージにパス・行内容・errno は含めない（ERR-1）。
//!
//! # 安全性
//! - 現在ログは `create_new`（`O_CREAT|O_EXCL`）でのみ開く。最終要素が symlink でも辿らないため、
//!   symlink 先への追記を防ぐ。既存ファイルは開かず、rename / remove（symlink を辿らない）だけで動かす。
//! - 既存のロックファイルは、開く前後の種別が一致する通常ファイルのときだけ使い、読み取りでしか開かない
//!   （検査後に symlink へ差し替えられても、その先へ書かない）。同一性の照合は unix が dev / inode、Windows は
//!   reparse point を辿らず開いたうえで、2 回開いたハンドルのボリューム・ファイル ID（`FileIdInfo`。FAT 等の
//!   未対応 FS は取得失敗で拒否）。読み出し側の入口 [`open_for_read`] も同じ検査を使う。
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
//!   例外は世代の rename / remove で、バッファ書き出しとファイル close の後なので再書き込みを伴わず、
//!   Windows の共有違反（`ERROR_SHARING_VIOLATION`・`ERROR_LOCK_VIOLATION`）に限り有界で再試行する
//!   （10ms × 最大 4 回。1 回のローテーション全体で共有し、`logs` の最小の待ち上限 100ms を下回る）。
//!   予算が尽きれば従来どおり失敗状態に固定する。途中まで進んだ世代送りは巻き戻さない（世代に穴が空くだけで
//!   欠落・重複は生じず、開き直しも受理する）。
//! - 読み出し側の契約（Windows）: 現在ログ・世代ファイルは削除共有（`FILE_SHARE_DELETE`）つきで開くこと。
//!   正規の入口は [`open_for_read`]。削除共有なしで開いた読み手が居座ると、rename が再試行のあと失敗し sink は
//!   失敗状態になる（可用性より fail-closed を優先する）。
//! - fsync はローテーションで退避する世代と、明示の [`RotatingFileSink::sync`] だけ。現在ログはクラッシュ時に
//!   最後の `sync` / ローテーション以降の分を失い得る。
//!
//! # 未実装・制限（REPAIR-3）
//! - flush ごとの fsync・設定可能な同期ポリシー・タイマーによる定期 flush（短い read を契機とする flush で代替）。
//!   [`RotatingFileSink::sync`] をコンテナ終了時などに呼ぶ配線も未実装（配線側の責務）。
//! - 両ストリーム混在での大規模検証（stdout 単独の 100 万行検証は `tests/log_rotation.rs`〔TASK-164.4・#508〕で実装済み）。
//! - `logs` コマンド本体（読み出し経路の配線）。ログ名の列挙 [`log_file_paths`] は実装済みでロックファイルを含めず、
//!   入口 [`open_for_read`] を用意した。内容の読み出し・CLI 配線は未実装。open 後に差し替えられた
//!   世代が symlink の可能性は残るため、読み出し側は [`open_for_read`] か同等の「辿らず開く」手段を使うこと。
//! - 親ディレクトリ経路の検証後の差し替え（TOCTOU）と所有者（uid）の照合は、core の安全 open へ寄せられない
//!   ため未対応のまま残す（#1470 の判断）。core の fd 相対 open は `pub(crate)` かつ Linux 限定で、supervisor
//!   から呼べず、3 OS で動く sink の経路を置き換えられない。公開には OS 非依存の「ディレクトリハンドル相対
//!   open」を core の公開 API として設計する必要があり（crate 境界の設計変更）、本モジュールの範囲外。
//!   Windows では権限（ACL）も検査しない。
//! - 名前空間の別名検査は、ASCII の大文字小文字と、Unicode の畳み込みで ASCII へ写る 4 文字（[`fold_for_alias`]）を
//!   見る。それ以外の FS 固有の畳み込みで名前空間に入る別名は、sink が作る名前が ASCII のみであるため生じない。
//! - Windows の rename 再試行の対象外: 移動先が削除共有なしで開かれている場合などに `ERROR_ACCESS_DENIED` が
//!   返るなら再試行せず失敗状態になる（恒久エラーとの区別がつかないため。実機の CI 結果で要判断）。
//! - Windows のロックファイル削除は、自分のハンドルを閉じてから消すため、その間に別の sink が開くと
//!   削除が失敗してロックファイルが残る（排他は保たれる）。
//! - `dir`（状態ルート配下のどこか）の決定は配線側の責務で、本モジュールは決めない。

use std::fs::{self, File, OpenOptions};
use std::io::{self, BufWriter, ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

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
    /// `Option` なのは、`open` が取得後の検査で失敗したときに取り出してロックファイルを消すため
    /// （TASK-164 追補・#1469）。`open` が成功して返した sink では常に `Some`。
    lock: Option<File>,
    dir: PathBuf,
    base: String,
    config: RotationConfig,
    /// 世代 rename の一過性失敗に対する再試行方針（Windows の共有違反用。既定は [`RenameRetry::DEFAULT`]）。
    retry: RenameRetry,
    inner: Mutex<Inner>,
}

/// 世代 rename の再試行方針（1 回のローテーションで共有する予算。SUP-7・REPAIR-5）。
///
/// 待ち時間の総和（`interval × max_sleeps`）は、`inner` ロックを握ったままリーダースレッドから呼ばれる
/// 都合で、`logs` 側の最小の待ち上限（`CANCEL_SETTLE_TIMEOUT` = 100ms）を十分下回る値にする。
#[derive(Debug, Clone, Copy)]
struct RenameRetry {
    interval: Duration,
    max_sleeps: u32,
}

impl RenameRetry {
    /// 10ms × 4 回 = 総待ち最大 40ms。
    const DEFAULT: Self = Self {
        interval: Duration::from_millis(10),
        max_sleeps: 4,
    };
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

/// 名前空間の別名検査用に、名前を ASCII 小文字へ畳み込む（IO-5）。
///
/// sink が作る名前は小文字・数字・`.`・`-`・`_` の ASCII だけなので、別名になり得るのは「大文字小文字の畳み込みや
/// 正規化で ASCII 英字へ写る非 ASCII 文字」を含む名前だけである。ASCII は `to_ascii_lowercase`、非 ASCII は
/// Unicode の畳み込み（`CaseFolding.txt` の C / S / T）と正規等価で ASCII 1 文字へ写る次の 4 文字だけを写す
/// （std のみ・テーブル非依存）: U+212A（KELVIN SIGN。正規等価で `K`）→ `k`、U+017F（LATIN SMALL LETTER LONG S。
/// 大文字化で `S`）→ `s`、U+0131（LATIN SMALL LETTER DOTLESS I。大文字化で `I`）→ `i`、
/// U+0130（LATIN CAPITAL LETTER I WITH DOT ABOVE。T 行で `i`）→ `i`。
/// これ以外の文字は名前空間に入らないのでそのまま返す。
fn fold_for_alias(name: &str) -> String {
    name.chars()
        .map(|c| match c {
            '\u{212A}' => 'k',
            '\u{017F}' => 's',
            '\u{0131}' | '\u{0130}' => 'i',
            c => c.to_ascii_lowercase(),
        })
        .collect()
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
        let mut sink = Self {
            lock: Some(lock),
            dir,
            base,
            config,
            retry: RenameRetry::DEFAULT,
            inner: Mutex::new(Inner {
                state: State::Failed,
                rotations: 0,
            }),
        };
        // ロック取得後の検査・初期化に失敗したら、ロックファイルを残さず元のエラーを返す
        // （排他ロック保持中なので消しても他の sink と競合しない。掃除の失敗は握って元のエラーを優先する。
        // SUP-7・TASK-164 追補・#1469）。
        if let Err(e) = sink.initialize() {
            if let Some(lock) = sink.lock.take() {
                let _ = remove_lock_file(lock, &lock_path(&sink.dir, &sink.base), &sink.dir);
            }
            return Err(e);
        }
        Ok(sink)
    }

    /// ロック取得後の本体: 名前空間・既存ファイルの検査 → 現在ログの退避 → 新しい現在ログの作成。
    fn initialize(&self) -> Result<(), TraitError> {
        // 名前空間のエントリを 1 つでも受理できなければ、何も動かさずに拒否する（契約: 全ファイルが
        // 通常ファイルで len <= max_file_bytes、総数は generations 以内）。手動で整理させる。
        self.check_namespace()?;
        self.check_existing_files()?;
        // 既存の現在ログは開かず、世代へ送ってから作り直す。空なら世代を消費せず消すだけにする
        // （出力の無い再起動が続いても、保持している世代を押し出さない）。
        match fs::symlink_metadata(self.path(0)) {
            Ok(m) if m.len() == 0 => {
                fs::remove_file(self.path(0)).map_err(|_| internal("log rotation failed"))?;
            }
            Ok(_) => self.shift_generations()?,
            Err(e) if e.kind() == ErrorKind::NotFound => {}
            Err(_) => return Err(internal("log file inspection failed")),
        }
        let file = self.create_active()?;
        self.lock()?.state = State::Active {
            writer: BufWriter::with_capacity(WRITE_BUFFER_BYTES, file),
            size: 0,
        };
        Ok(())
    }

    /// コンテナ削除時に、この ID の現在ログ・全世代・ロックファイルをまとめて消す
    /// （SUP-7・TASK-164 追補・#1469。コンテナ削除経路の配線は未実装〔REPAIR-3〕。配線側が呼ぶ）。
    ///
    /// 同じ ID の sink が生存中なら、ロックを取れず `FailedPrecondition` で拒否し、何も消さない。
    /// `RotationConfig` は受け取らず、設定世代数を超える番号の世代も消す。名前空間に受理できない
    /// 別名・不正な世代番号・ディレクトリがあれば `InvalidArgument` で拒否し、ログを 1 つも消さない
    /// （利用者のデータを黙って消さない）。削除は `remove_file` のみで symlink は辿らずリンク自体を消す。
    /// 何も無い状態で呼んでも成功する（冪等）。ロックファイルは、成功・失敗を問わずロック取得後は消す。
    ///
    /// 全結果（成功・ロック競合・入力拒否・途中削除失敗・ロックファイル掃除失敗）で、成否・エラー code・
    /// 削除数・所要時間を構造化 1 行（JSON）で stderr へ出す（REPAIR-4。パス・errno は含めない。ERR-1）。
    pub fn remove_all(dir: &Path, id: &ContainerId) -> Result<RemovedLogs, TraitError> {
        let started = Instant::now();
        let (removed, result) = Self::remove_all_inner(dir, id);
        let (outcome, code) = match &result {
            Ok(_) => ("ok", ""),
            Err(e) => ("error", e.code().as_str()),
        };
        // eprintln! は stderr 書き込み失敗で panic するため、結果を無視する writeln! で出す（panic しない）。
        let _ = writeln!(
            std::io::stderr().lock(),
            "{{\"component\":\"supervisor.logs\",\"operation\":\"remove_all\",\"result\":\"{}\",\"code\":\"{}\",\"removed_log_files\":{},\"elapsed_us\":{}}}",
            outcome,
            code,
            removed,
            started.elapsed().as_micros()
        );
        result
    }

    /// [`Self::remove_all`] の本体。実際に消せた数と結果を別々に返す（失敗時も削除数を観測に出すため）。
    fn remove_all_inner(dir: &Path, id: &ContainerId) -> (u32, Result<RemovedLogs, TraitError>) {
        let dir = match check_dir(dir) {
            Ok(d) => d,
            Err(e) => return (0, Err(e)),
        };
        let base = format!("{}.log", encode_file_stem(id.as_str()));
        if base.len().saturating_add(LOCK_SUFFIX.len()) > MAX_FILE_NAME_BYTES {
            return (
                0,
                Err(invalid("container id is too long for log file names")),
            );
        }
        let lock = match acquire_lock(&dir, &base) {
            Ok(l) => l,
            Err(e) => return (0, Err(e)),
        };
        let (removed, log_result) = remove_log_files(&dir, &base);
        let lock_removed = remove_lock_file(lock, &lock_path(&dir, &base), &dir);
        // ログ削除側の失敗を優先して返す。
        if let Err(e) = log_result {
            return (removed, Err(e));
        }
        if lock_removed.is_err() {
            return (removed, Err(internal("log lock removal failed")));
        }
        (removed, Ok(RemovedLogs { log_files: removed }))
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
    ///
    /// rename / remove は、Windows の共有違反（[`is_transient_fs_error`]）に限り有界で再試行する。この時点で
    /// バッファは書き切り済み・ファイルは close 済みなので、再試行はレコードを再書き込みせず重複を生まない。
    /// 予算（[`RenameRetry`]）は世代数によらず 1 回のローテーション全体で共有する。尽きた場合・一過性でない
    /// 失敗は `Internal` で返し、呼び出し側は sink を失敗状態にする（fail-closed）。
    fn shift_generations(&self) -> Result<(), TraitError> {
        let fail = || internal("log rotation failed");
        let mut sleeps_left = self.retry.max_sleeps;
        let sleep = || std::thread::sleep(self.retry.interval);
        if self.config.generations == 1 {
            let r = retry_transient(
                || fs::remove_file(self.path(0)),
                is_transient_fs_error,
                &mut sleeps_left,
                sleep,
            );
            return match r {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
                Err(_) => Err(fail()),
            };
        }
        for i in (0..=self.config.generations - 2).rev() {
            let r = retry_transient(
                || fs::rename(self.path(i), self.path(i + 1)),
                is_transient_fs_error,
                &mut sleeps_left,
                sleep,
            );
            match r {
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
    /// 名前空間は `<base>`・`<base>.lock`・`<base>.<10 進数字>`（[`fold_for_alias`] で畳み込んで比較）。
    /// 他の ID の名前は `.log` / `.lock` / `<別の base>.<数字>` で終わるので、ここには入らない。
    /// 受理するのは、小文字の正確な綴りの `<base>`・`<base>.lock` と、先頭 0 なしで `1 <= n < generations`
    /// の `<base>.<n>` だけである。世代番号 0・先頭 0 つき・世代数以上の番号・大文字小文字違いの別名は、
    /// ローテーションの対象外のまま残って上限 `max_file_bytes × generations` を破るため、ファイルを
    /// 変更する前に `InvalidArgument` で拒否する（利用者のログを黙って消さない。SUP-7・TASK-164.2）。
    /// 種別とサイズは [`Self::check_existing_files`] が見る。
    fn check_namespace(&self) -> Result<(), TraitError> {
        let generations = u64::from(self.config.generations);
        for_each_entry(&self.dir, &self.base, |_, class| match class {
            NameClass::Rejected(msg) => Err(invalid(msg)),
            NameClass::Generation(n) if n >= generations => Err(invalid(MSG_BAD_GENERATION)),
            _ => Ok(()),
        })
    }

    fn create_active(&self) -> Result<File, TraitError> {
        let mut opts = OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let file = opts
            .open(self.path(0))
            .map_err(|_| internal("log file create failed"))?;
        // 新規作成したディレクトリエントリを永続化する。これが無いと `sync`（`sync_data`）成功後でも
        // クラッシュでログファイル名自体が失われ得る（SUP-7・TASK-164.3）。unix のみ（他 OS は sync_dir が no-op）。
        sync_dir(&self.dir).map_err(|_| internal("log file create failed"))?;
        Ok(file)
    }
}

/// 一過性の失敗なら再試行してよいか。Windows の `ERROR_SHARING_VIOLATION`（32）・`ERROR_LOCK_VIOLATION`（33）
/// だけを対象にする（他プロセスが削除共有なしで開いている間の rename / remove の失敗）。`ERROR_ACCESS_DENIED`（5）は
/// ディレクトリ衝突などの恒久的な失敗とも区別できないため含めない。他 OS では常に `false`（挙動は不変）。
#[cfg(windows)]
fn is_transient_fs_error(e: &io::Error) -> bool {
    matches!(e.raw_os_error(), Some(32 | 33))
}

#[cfg(not(windows))]
fn is_transient_fs_error(_e: &io::Error) -> bool {
    false
}

/// `op` を実行し、`is_transient` な失敗に限り、`sleeps_left` が残る間だけ `sleep` を挟んで再試行する。
///
/// `sleeps_left` は呼び出し側が持ち回る共有予算（1 回のローテーションの総待ち時間を有界にする。REPAIR-5）。
/// 予算切れ・一過性でない失敗は、その時点のエラーをそのまま返す。
fn retry_transient<T>(
    mut op: impl FnMut() -> io::Result<T>,
    is_transient: impl Fn(&io::Error) -> bool,
    sleeps_left: &mut u32,
    sleep: impl Fn(),
) -> io::Result<T> {
    loop {
        match op() {
            Err(e) if is_transient(&e) && *sleeps_left > 0 => {
                *sleeps_left -= 1;
                sleep();
            }
            r => return r,
        }
    }
}

/// ロックファイル名の接尾辞（`<base>.lock`。世代番号は数字のみのため世代ファイルと衝突しない）。
const LOCK_SUFFIX: &str = ".lock";

/// `<base>.lock` を開き排他ロックを取る。取れなければ（別の sink が使用中）`FailedPrecondition`。
///
/// ロックファイルは内容を持たず、書き込みもしない。新規作成は `create_new`（symlink を辿らない）、
/// 既存は通常ファイル（symlink・FIFO 等は拒否）のときだけ読み取りで開く。開いた実体が検査したものと同じ通常ファイルであることを開いた後にも確かめる
/// （検査と open の間の差し替え対策。unix は dev / inode も照合する）。
fn acquire_lock(dir: &Path, base: &str) -> Result<File, TraitError> {
    let path = lock_path(dir, base);
    let mut create = OpenOptions::new();
    create.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        create.mode(0o600);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        create.share_mode(WINDOWS_SHARE_NO_DELETE);
    }
    let file = match create.open(&path) {
        Ok(f) => f,
        // 作れなかったときは、既存エントリの種別で分ける（既存がディレクトリのときの create_new の
        // エラー種別は OS で異なるため、種別は lstat で判定する）。
        // 既存が無い（権限なし・書き込み不可ディレクトリ等で作れなかった）場合に `NotFound` を返すと、
        // 本来の `Internal` が隠れるため、フォールバックの不在は作成失敗として `Internal` に正規化する。
        Err(_) => open_existing_regular_read(&path, true).map_err(|e| {
            if e.code() == ErrorCode::NotFound {
                internal("log lock create failed")
            } else {
                e
            }
        })?,
    };
    match file.try_lock() {
        Ok(()) => {
            // ロックを取れた実体が、いまのパスの実体と同じであることを確かめる（unix）。別の掃除が
            // 取得の前後でロックファイルを消し、別の sink が作り直していた場合、孤立した inode の
            // ロックを持っても排他にならない（TASK-164 追補・#1469）。
            verify_lock_is_current(&file, &path)?;
            Ok(file)
        }
        Err(std::fs::TryLockError::WouldBlock) => Err(TraitError::new(
            ErrorCode::FailedPrecondition,
            "log is in use by another sink",
        )),
        Err(std::fs::TryLockError::Error(_)) => Err(internal("log lock failed")),
    }
}

/// 既存の通常ファイルを、symlink / reparse point を辿らず読み取りで開く（SUP-7・IO-5・WIN-4）。
///
/// ロックファイルの再利用（[`acquire_lock`]）と、読み出し側の入口 [`open_for_read`] が共有する。開いた実体が
/// 検査したものと同じ通常ファイルであることを、開いた後にも確かめる（検査と open の間の差し替え対策）。
/// unix は lstat と fstat の種別・dev / inode を照合する。Windows は reparse point を辿らずに開き（属性で
/// 通常ファイルを確認）、同じパスを 2 回開いたハンドルのボリューム・ファイル ID が一致することを照合する
/// （`FileIdInfo` を持たない FS では取得に失敗し、fail-closed で拒否する）。
/// 種別違反は `InvalidArgument`、存在しなければ `NotFound`、それ以外は `Internal`（パス・errno を含めない。ERR-1）。
#[cfg(not(windows))]
fn open_existing_regular_read(path: &Path, deny_delete: bool) -> Result<File, TraitError> {
    let _ = deny_delete;
    let not_regular = || invalid("log path is not a regular file");
    let before = fs::symlink_metadata(path).map_err(map_lstat_error)?;
    if !before.file_type().is_file() {
        return Err(not_regular());
    }
    // unix は `O_NONBLOCK` で開く。検査後にパスが FIFO（FIFO を指す symlink を含む）へ差し替えられても
    // open は停止せず（REPAIR-5）、開いた fd の種別・dev / inode の照合で拒否する。末尾要素の symlink への
    // 差し替えは `O_NOFOLLOW` で open 自体を拒否し、リンク先を開かない（副作用を起こさない）。
    // 通常ファイルの読み取りは影響を受けない。
    #[cfg(unix)]
    let opened = open_read_nofollow_nonblocking(path);
    #[cfg(not(unix))]
    let opened = OpenOptions::new().read(true).open(path);
    let file = opened.map_err(|_| internal("log file open failed"))?;
    let after = file
        .metadata()
        .map_err(|_| internal("log file open failed"))?;
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
    Ok(file)
}

#[cfg(windows)]
fn open_existing_regular_read(path: &Path, deny_delete: bool) -> Result<File, TraitError> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};

    /// `FILE_FLAG_OPEN_REPARSE_POINT`: reparse point（symlink・junction）を辿らず、その実体を開く。
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;

    let not_regular = || invalid("log path is not a regular file");
    let is_plain_file = |m: &fs::Metadata| {
        m.file_type().is_file() && m.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0
    };
    // ロックファイルは削除共有なし（他者による削除を拒む）、読み出し側は削除共有つきで開く。
    let share_mode = if deny_delete {
        WINDOWS_SHARE_NO_DELETE
    } else {
        READ_SHARE_MODE
    };
    let open = || -> Result<File, TraitError> {
        let file = OpenOptions::new()
            .read(true)
            .share_mode(share_mode)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
            .map_err(|e| match e.kind() {
                ErrorKind::NotFound => TraitError::new(ErrorCode::NotFound, "log file not found"),
                _ => internal("log file open failed"),
            })?;
        let meta = file
            .metadata()
            .map_err(|_| internal("log file open failed"))?;
        if !is_plain_file(&meta) {
            return Err(not_regular());
        }
        Ok(file)
    };
    let before = fs::symlink_metadata(path).map_err(map_lstat_error)?;
    if !is_plain_file(&before) {
        return Err(not_regular());
    }
    let file = open()?;
    // 開いている間にパスが別の実体へ差し替えられていないことを、2 本目のハンドルとのファイル ID 照合で確かめる。
    let again = open()?;
    let a = crate::sys::file_identity(&file).map_err(|_| internal("log file open failed"))?;
    let b = crate::sys::file_identity(&again).map_err(|_| internal("log file open failed"))?;
    if a != b {
        return Err(not_regular());
    }
    Ok(file)
}

/// `O_NOFOLLOW`（unix。末尾要素が symlink なら `open` が `ELOOP` で失敗する）。
/// 値は OS・アーキテクチャで異なるため `cfg` で分ける。定義できない環境は 0 で、lstat と開いた後の
/// dev / inode 照合のみが防御になる。
#[cfg(all(
    any(target_os = "linux", target_os = "android"),
    any(
        target_arch = "x86",
        target_arch = "x86_64",
        target_arch = "riscv32",
        target_arch = "riscv64",
        target_arch = "s390x",
        target_arch = "loongarch64"
    )
))]
const O_NOFOLLOW: i32 = 0o400000;
#[cfg(all(
    any(target_os = "linux", target_os = "android"),
    any(
        target_arch = "arm",
        target_arch = "aarch64",
        target_arch = "powerpc",
        target_arch = "powerpc64"
    )
))]
const O_NOFOLLOW: i32 = 0o100000;
#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly"
))]
const O_NOFOLLOW: i32 = 0x100;
#[cfg(all(
    unix,
    not(any(
        all(
            any(target_os = "linux", target_os = "android"),
            any(
                target_arch = "x86",
                target_arch = "x86_64",
                target_arch = "riscv32",
                target_arch = "riscv64",
                target_arch = "s390x",
                target_arch = "loongarch64",
                target_arch = "arm",
                target_arch = "aarch64",
                target_arch = "powerpc",
                target_arch = "powerpc64"
            )
        ),
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly"
    ))
))]
const O_NOFOLLOW: i32 = 0;

/// 読み取り専用・非ブロッキング・symlink 非追従（`O_NOFOLLOW`）でログを開く（unix。SUP-7・IO-5）。
///
/// lstat 後に末尾要素が symlink へ差し替えられても、リンク先を開かずに失敗する。
#[cfg(unix)]
pub(crate) fn open_read_nofollow_nonblocking(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .read(true)
        .custom_flags(crate::container_options::env::O_NONBLOCK | O_NOFOLLOW)
        .open(path)
}

fn map_lstat_error(e: io::Error) -> TraitError {
    if e.kind() == ErrorKind::NotFound {
        TraitError::new(ErrorCode::NotFound, "log file not found")
    } else {
        internal("log file inspection failed")
    }
}

/// Windows の読み取り open の共有モード（`FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE`）。
/// 削除共有を含めることで、読み手が開いたままでも sink の世代 rename が共有違反にならない。
/// std の `OpenOptions` の既定も同じ値だが、契約として明示する（SUP-7・WIN-4）。
#[cfg(windows)]
const READ_SHARE_MODE: u32 = 0x1 | 0x2 | 0x4;

/// `logs` の読み出し側が現在ログ・世代ファイルを読むための正規の入口（SUP-7・IO-5・WIN-4）。
///
/// symlink / reparse point を辿らず通常ファイルだけを読み取りで開く。Windows では削除共有つき
/// （`FILE_SHARE_DELETE`）で開くため、読み手が開いたままでも sink の rename を妨げない。読み出し側が独自に
/// 削除共有なしで開くと、sink の世代 rename が有界の再試行（[`RenameRetry`]）のあと失敗し、sink は失敗状態に
/// 固定される。`logs` コマンド本体は未実装（REPAIR-3）で、現状の呼び出し元は無い。
/// 種別違反は `InvalidArgument`、存在しなければ `NotFound`。
pub fn open_for_read(path: &Path) -> Result<File, TraitError> {
    open_existing_regular_read(path, false)
}

/// Windows でロックファイルを開くときの共有モード（`FILE_SHARE_READ | FILE_SHARE_WRITE`）。
/// `FILE_SHARE_DELETE` を含めないので、誰かが開いている間は他者による削除が共有違反で失敗する
/// （TASK-164 追補・#1469。Windows には stable std で使える dev / inode 照合が無いための代替）。
#[cfg(windows)]
const WINDOWS_SHARE_NO_DELETE: u32 = 0x1 | 0x2;

/// ロックファイルのパス（`<dir>/<base>.lock`）。
fn lock_path(dir: &Path, base: &str) -> PathBuf {
    dir.join(format!("{base}{LOCK_SUFFIX}"))
}

/// 保持中のロックの実体が `path` の現在の実体と同じ通常ファイルか確認する（unix は dev / inode）。
/// 違えば、取得中に並行する掃除・open と競合したとみなし、再試行せず `FailedPrecondition` で拒否する。
#[cfg(unix)]
fn verify_lock_is_current(file: &File, path: &Path) -> Result<(), TraitError> {
    use std::os::unix::fs::MetadataExt;
    let busy = || {
        TraitError::new(
            ErrorCode::FailedPrecondition,
            "log is in use by another sink",
        )
    };
    let held = file
        .metadata()
        .map_err(|_| internal("log lock open failed"))?;
    match fs::symlink_metadata(path) {
        Ok(now)
            if now.file_type().is_file() && now.dev() == held.dev() && now.ino() == held.ino() =>
        {
            Ok(())
        }
        _ => Err(busy()),
    }
}

#[cfg(not(unix))]
fn verify_lock_is_current(_file: &File, _path: &Path) -> Result<(), TraitError> {
    Ok(())
}

/// 保持中のロックファイルを消して解放する（`NotFound` は成功扱い）。
///
/// unix は排他ロックを保持したまま unlink する（削除する側は全員ロック保持者なので、取得時の同一性照合
/// と合わせ、孤立 inode への二重ロックを防ぐ）。その後ディレクトリを fsync してから解放する。
/// 他 OS は自分のハンドルが削除を拒むため、閉じてから消す。閉じてから消すまでの間に別の sink が
/// 開いた場合、削除は共有違反で失敗するだけで、その sink の排他は保たれる（ロックファイルが残る）。
fn remove_lock_file(lock: File, path: &Path, dir: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        let res = match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        };
        let res = res.and_then(|()| sync_dir(dir).map_err(|_| std::io::Error::other("fsync")));
        drop(lock);
        res
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
        drop(lock);
        match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }
}

/// 収集・削除する対象ファイル数の上限（無制限確保の防止。超過は fail-closed で `InvalidArgument`）。
const MAX_LOG_ENTRIES: usize = 1024;

const MSG_ALIAS: &str = "unexpected entry exists in the log file namespace";
const MSG_BAD_GENERATION: &str =
    "stale or malformed log generation exists outside the configured generations";

/// `dir` 内の名前の、ある ID（`base`）の名前空間における分類。
/// `open`・[`RotatingFileSink::remove_all`]・[`log_file_paths`] が同じ判定を使う（二重管理の防止）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NameClass {
    /// 名前空間の外（他 ID・無関係なファイル）。
    Other,
    /// 現在ログ `<base>`。
    Current,
    /// ロックファイル `<base>.lock`。ログではない。
    Lock,
    /// 世代 `<base>.<n>`（先頭 0 なしの `n >= 1`。上限は呼び出し側が見る）。
    Generation(u64),
    /// 名前空間内だが受理できない名前（別名・世代 0・先頭 0 つき・桁あふれ）。メッセージは英語固定。
    Rejected(&'static str),
}

fn classify_name(base: &str, name: &str) -> NameClass {
    let lower = fold_for_alias(name);
    let is_lock = lower.strip_prefix(base) == Some(LOCK_SUFFIX);
    if lower == base || is_lock {
        if name != lower {
            return NameClass::Rejected(MSG_ALIAS);
        }
        return if is_lock {
            NameClass::Lock
        } else {
            NameClass::Current
        };
    }
    let Some(num) = lower.strip_prefix(base).and_then(|r| r.strip_prefix('.')) else {
        return NameClass::Other;
    };
    if num.is_empty() || !num.bytes().all(|b| b.is_ascii_digit()) {
        return NameClass::Other;
    }
    match num.parse::<u64>() {
        Ok(n) if n >= 1 && name == lower && !num.starts_with('0') => NameClass::Generation(n),
        _ => NameClass::Rejected(MSG_BAD_GENERATION),
    }
}

/// `dir` を [`MAX_SCAN_ENTRIES`] 件を上限に列挙し、名前空間内のエントリ（`Other` 以外）ごとに `f` を呼ぶ。
/// UTF-8 でない名前は名前空間に入らない（sink の名前は ASCII のみ）。
fn for_each_entry(
    dir: &Path,
    base: &str,
    mut f: impl FnMut(&str, NameClass) -> Result<(), TraitError>,
) -> Result<(), TraitError> {
    let rd = fs::read_dir(dir).map_err(|_| internal("log directory scan failed"))?;
    let mut scanned = 0usize;
    for entry in rd {
        scanned = scanned.saturating_add(1);
        if scanned > MAX_SCAN_ENTRIES {
            return Err(invalid("log directory has too many entries to verify"));
        }
        let entry = entry.map_err(|_| internal("log directory scan failed"))?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        match classify_name(base, name) {
            NameClass::Other => {}
            class => f(name, class)?,
        }
    }
    Ok(())
}

/// ログ（現在ログ・世代）の名前を集める。受理できない名前・ディレクトリ（`require_regular` なら通常
/// ファイル以外）があれば `InvalidArgument`。返すのは（世代番号、名前）で、現在ログは番号 0。
/// 古い順（番号の大きい順）に並べる。
fn collect_log_names(
    dir: &Path,
    base: &str,
    require_regular: bool,
) -> Result<Vec<(u64, String)>, TraitError> {
    let mut out: Vec<(u64, String)> = Vec::new();
    for_each_entry(dir, base, |name, class| {
        let n = match class {
            NameClass::Rejected(msg) => return Err(invalid(msg)),
            NameClass::Current => 0,
            NameClass::Generation(n) => n,
            NameClass::Lock | NameClass::Other => return Ok(()),
        };
        // 列挙後に並行ローテーションの rename で消えたエントリは、正常動作なので除外する（SUP-7）。
        // それ以外の検査エラーは維持する。
        let meta = match fs::symlink_metadata(dir.join(name)) {
            Ok(m) => m,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(()),
            Err(_) => return Err(internal("log file inspection failed")),
        };
        let ft = meta.file_type();
        if ft.is_dir() || (require_regular && !ft.is_file()) {
            return Err(invalid("existing log path is not a regular file"));
        }
        if out.len() >= MAX_LOG_ENTRIES {
            return Err(invalid("too many log files"));
        }
        out.push((n, name.to_owned()));
        Ok(())
    })?;
    out.sort_by_key(|b| std::cmp::Reverse(b.0));
    Ok(out)
}

/// [`RotatingFileSink::remove_all`] の削除結果（将来の拡張に備えた構造体）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RemovedLogs {
    log_files: u32,
}

impl RemovedLogs {
    /// 消した現在ログ + 世代ファイルの数（ロックファイルは含まない）。
    pub fn log_files(&self) -> u32 {
        self.log_files
    }
}

/// ロック保持中に、検証してから現在ログ・世代を消す。検証で拒否したときは 1 つも消さない。
///
/// 実際に消せた数と結果を別々に返す（途中で失敗しても削除済みの数を観測に出すため）。
fn remove_log_files(dir: &Path, base: &str) -> (u32, Result<(), TraitError>) {
    // symlink は辿らずリンク自体を消すので検証では許容する（ディレクトリだけ拒否）。
    let names = match collect_log_names(dir, base, false) {
        Ok(n) => n,
        Err(e) => return (0, Err(e)),
    };
    let mut removed = 0u32;
    for (_, name) in &names {
        match fs::remove_file(dir.join(name)) {
            Ok(()) => removed = removed.saturating_add(1),
            Err(e) if e.kind() == ErrorKind::NotFound => {}
            Err(_) => return (removed, Err(internal("log removal failed"))),
        }
    }
    if removed > 0 && sync_dir(dir).is_err() {
        return (removed, Err(internal("log removal failed")));
    }
    (removed, Ok(()))
}

/// この ID のログファイルのパスを古い順（世代番号の大きい順 → 現在ログ）に列挙する。
/// ロックファイル・他 ID・無関係なファイルは含めない（`logs` 読み出し側が使う契約。SUP-7・TASK-164 追補・#1469）。
///
/// ロックは取らない（sink の生存中も呼べる）。ローテーションと並行すると、列挙後に世代の名前がずれ得る
/// （読み出し側の責務。REPAIR-3: 内容の読み出し・`logs` コマンドへの配線は未実装）。名前空間に受理できない名前・
/// ディレクトリ・symlink があれば `InvalidArgument`（読み出し側が symlink を辿らない入口）。
pub fn log_file_paths(dir: &Path, id: &ContainerId) -> Result<Vec<PathBuf>, TraitError> {
    let dir = check_dir(dir)?;
    let base = format!("{}.log", encode_file_stem(id.as_str()));
    let names = collect_log_names(&dir, &base, true)?;
    Ok(names.into_iter().map(|(_, n)| dir.join(n)).collect())
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
