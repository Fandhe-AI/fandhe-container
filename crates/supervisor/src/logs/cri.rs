//! CRI ログ形式の書き出し（kubelet・crictl が読む `log_directory/log_path`）
//! （CRI-2・SUP-4・TASK-114 追補・#2671）。
//!
//! 役割: supervisor が捕捉したコンテナの stdout / stderr の行を、CRI のログ形式
//! `<RFC3339Nano> <stdout|stderr> <F|P> <内容>\n` で 1 ファイルへ追記する [`LogSink`]（[`CriFileSink`]）と、
//! 既存の `@container-logs` への書き出し（[`super::RotatingFileSink`]）と同時に書く [`TeeLogSink`]。
//! 呼び出し元は supervisor bin の `start_entry` の `open_log_sink`（`--cri-log-path` 指定時。plugin-cri の StartContainer が
//! cri の結合・検証した書き先を渡す）。`fandhe logs` と delete のログ削除は従来どおり `@container-logs` だけを対象にし、
//! kubelet が所有する CRI ログファイルは削除しない（kubelet が pod のログディレクトリごと消す）。
//!
//! # 形式
//! - タイムスタンプは UTC の RFC3339 でナノ秒を固定 9 桁（kubelet の `parseCRILog` が読める形）。外部クレートを使わず
//!   [`format_timestamp`] が日付を計算する。エポックより前の時刻は 1970-01-01 に丸め、9999 年を超える時刻は 9999-12-31 に丸める。
//! - 1 行は [`CRI_LOG_CHUNK_BYTES`]（containerd の `max_container_log_line_size` の既定値 16384 に合わせる）ごとに分け、
//!   最後の断片を `F`（full）、それより前を `P`（partial）にする。空行は内容なしの `F` 1 件（`<ts> stdout F \n`）。
//! - 捕捉側の断片（[`LogSink::append_part`]。#4582）は containerd v2.1.0 の `redirectLogs` に合わせ、`Continued` と `Eof` の
//!   全チャンクを `P`、`Lf` の最後のチャンクだけを `F` で書く。[`super::MAX_LINE_BYTES`] を超える行も欠落せず、
//!   kubelet 規則（`P` は内容だけ・`F` は内容 + LF）で連結すると元のバイト列に戻る。LF の無い EOF の末尾は `P` で終わる。
//!   読み取りエラーで終わった未完了の末尾は書かない。総量の上限に達すると `F` の無い `P` で終わりうる。
//!   直接の [`LogSink::append`] は従来どおり [`super::MAX_LINE_BYTES`] で切り詰めて `F` で書く。
//!
//! # 安全性
//! - 開くとき最終要素は `O_NOFOLLOW`（symlink を辿らない）・`O_NONBLOCK`（FIFO で止まらない）・`O_NOCTTY` で、開いた後に通常ファイル
//!   であることを確かめる。`log_directory` は作らない（kubelet が作る）が、その直下の `containerName/` は 1 階層だけ 0o750 で作る
//!   （検査済みの祖先の直下に限る）。親ディレクトリは絶対パス・`..` なし・root 以外が所有する
//!   祖先の symlink なし・group / other 書き込み不可を確かめる（`rotating` の `check_dir` と同じ検査）。検査と open の間の差し替え
//!   （TOCTOU）は残る既知の制限で、`rotating` と同じ（core に fd 相対 open が公開されていない。#1470 の判断）。
//! - 特権ランチャー経由（ambient capability あり）では開かない（[`deny_elevated_capabilities`]）。`CAP_DAC_OVERRIDE` を持ったまま
//!   利用者の指定したパスを開くと DAC を越えて任意のファイルへ追記できてしまうため。
//! - エラー文言は固定の英語で、パス・errno・行の内容を含めない（ERR-1）。
//! - 自前のローテーションはしない（kubelet が rename して `ReopenContainerLog` を呼ぶ方式。開き直しは [`LogSink::reopen`]・制御チャネルの kind 10。#4652）。代わりに CRI ログ 1 本の
//!   総量に上限を設ける（[`CRI_LOG_MAX_BYTES`]。既存サイズも数える）。超えると書き出しを止め（`ResourceExhausted`）、[`TeeLogSink`] が
//!   構造化ログで通知する。`@container-logs` は `RotatingFileSink` の上限どおり続く。
//! - 上限を書き手ごとに数えるため、書き手は 1 ファイルにつき 1 つに限る。開いたファイルに排他ロック（`flock(2)`）を
//!   sink の生存中（supervisor プロセスの生存中）保持し、別の supervisor が同じパスを開こうとすると `FailedPrecondition` で
//!   start を拒否する（kubelet は `<containerName>/<restartCount>.log` を使い回さないため、正規の経路では起きない）。
//!   ロックは協調的で、ロックを取らない別プロセスの追記は防げない（kubelet 以外が書かない前提）。

#[cfg(unix)]
use std::io::Write as _;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use fandhe_container_core::traits::{ErrorCode, TraitError};

use super::{LinePart, LogSink, MAX_LINE_BYTES, PartEnd, ReopenGate, RetiredWriter, StreamKind};

/// 1 レコードに載せる内容の最大バイト数（containerd の `max_container_log_line_size` の既定値）。
pub const CRI_LOG_CHUNK_BYTES: usize = 16 * 1024;

// 捕捉側の断片（`MAX_LINE_BYTES`）の境界と CRI のチャンクの境界を揃えるため（#4580・CRI-2）。
const _: () =
    assert!(CRI_LOG_CHUNK_BYTES > 0 && MAX_LINE_BYTES.is_multiple_of(CRI_LOG_CHUNK_BYTES));

/// タイムスタンプ（`2016-10-06T00:17:09.669794202Z`）のバイト数。
pub const CRI_TIMESTAMP_LEN: usize = 30;

/// 書き込みバッファ（固定。`RotatingFileSink` と同じ 8 KiB）。
#[cfg(unix)]
const WRITE_BUFFER_BYTES: usize = 8 * 1024;

/// CRI ログファイル 1 本の総量の上限（50 MiB。kubelet の `containerLogMaxSize` 10 MiB × `containerLogMaxFiles` 5 に合わせる）。
/// 超えた時点で CRI ログへの書き出しを止める（`ResourceExhausted`。`@container-logs` 側の `RotatingFileSink` は影響を受けない）。
/// `ReopenContainerLog`（[`LogSink::reopen`]）で新しいファイルを開き直すと、大きさを数え直して再開する（#4652）。再起動をまたぐ追記も既存のサイズから数える。
pub const CRI_LOG_MAX_BYTES: u64 = 50 * 1024 * 1024;

/// 9999-12-31T23:59:59 のエポック秒（4 桁の年に収めるための上限）。
const MAX_EPOCH_SECS: u64 = 253_402_300_799;

fn invalid(msg: &'static str) -> TraitError {
    TraitError::new(ErrorCode::InvalidArgument, msg)
}

fn internal(msg: &'static str) -> TraitError {
    TraitError::new(ErrorCode::Internal, msg)
}

/// エポックからの経過時間を RFC3339 の UTC（ナノ秒 9 桁固定）に整形する（純関数）。
pub fn format_timestamp(since_epoch: Duration) -> [u8; CRI_TIMESTAMP_LEN] {
    let secs = since_epoch.as_secs().min(MAX_EPOCH_SECS);
    let nanos = if since_epoch.as_secs() > MAX_EPOCH_SECS {
        999_999_999
    } else {
        since_epoch.subsec_nanos()
    };
    // 範囲は MAX_EPOCH_SECS 以下で i64 に収まる。
    let secs = i64::try_from(secs).unwrap_or(0);
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    // Howard Hinnant の civil_from_days（グレゴリオ暦。1970-01-01 起点の日数から年月日）。
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    let (hour, minute, second) = (rem / 3_600, rem % 3_600 / 60, rem % 60);

    let mut out = [b'0'; CRI_TIMESTAMP_LEN];
    put_digits(&mut out, 0, 4, year);
    out[4] = b'-';
    put_digits(&mut out, 5, 2, month);
    out[7] = b'-';
    put_digits(&mut out, 8, 2, day);
    out[10] = b'T';
    put_digits(&mut out, 11, 2, hour);
    out[13] = b':';
    put_digits(&mut out, 14, 2, minute);
    out[16] = b':';
    put_digits(&mut out, 17, 2, second);
    out[19] = b'.';
    put_digits(&mut out, 20, 9, i64::from(nanos));
    out[29] = b'Z';
    out
}

/// `value` を `width` 桁のゼロ詰め 10 進で `buf[start..]` へ書く（`value` は非負で桁に収まる前提。収まらなければ下位桁）。
fn put_digits(buf: &mut [u8], start: usize, width: usize, mut value: i64) {
    for i in (0..width).rev() {
        if let Some(slot) = buf.get_mut(start + i) {
            // value.rem_euclid(10) は 0..=9 で u8 に収まる。
            *slot = b'0' + u8::try_from(value.rem_euclid(10)).unwrap_or(0);
        }
        value = value.div_euclid(10);
    }
}

/// 現在時刻の [`format_timestamp`]。時計がエポックより前なら 1970-01-01 に丸める（ログを止めない）。
fn now_timestamp() -> [u8; CRI_TIMESTAMP_LEN] {
    let since = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or(Duration::ZERO);
    format_timestamp(since)
}

/// 1 レコード（`<ts> <stream> <tag> <chunk>\n`）を `out` へ追記する。
fn push_record(
    stream: StreamKind,
    tag: u8,
    chunk: &[u8],
    timestamp: &[u8; CRI_TIMESTAMP_LEN],
    out: &mut Vec<u8>,
) {
    out.extend_from_slice(timestamp);
    out.push(b' ');
    out.extend_from_slice(stream.as_str().as_bytes());
    out.push(b' ');
    out.push(tag);
    out.push(b' ');
    out.extend_from_slice(chunk);
    out.push(b'\n');
}

/// 1 行（LF 抜き）を CRI のレコード列へ符号化して `out` へ追記する（純関数）。
///
/// [`CRI_LOG_CHUNK_BYTES`] ごとに分け、最後の断片だけ `F`、それより前は `P`。空行は内容なしの `F` 1 件。
/// 呼び出し側が LF を含む行を弾いておくこと（[`CriFileSink`] の `append` が拒否する）。
pub fn encode_records(
    stream: StreamKind,
    line: &[u8],
    timestamp: &[u8; CRI_TIMESTAMP_LEN],
    out: &mut Vec<u8>,
) {
    encode_part_records(stream, line, PartEnd::Lf, timestamp, out);
}

/// 捕捉側の 1 断片（[`LogSink::append_part`] の `bytes`。LF 抜き）を CRI のレコード列へ符号化して `out` へ追記する
/// （純関数。containerd v2.1.0 の `redirectLogs` と同じ規則。CRI-2・SUP-7・#4582）。
///
/// [`CRI_LOG_CHUNK_BYTES`] ごとに分け、`end` が [`PartEnd::Lf`] のときだけ最後のチャンクを `F`、それ以外
/// （[`PartEnd::Continued`]・[`PartEnd::Eof`]・将来の変種）は全チャンクを `P` にする。空の `bytes` は `Lf` なら
/// 内容なしの `F` 1 件（空行）、それ以外は何も書かない（空の `P` は雑音になるため。捕捉側は渡さない入力への防御）。
/// 呼び出し側が LF を含む入力を弾いておくこと（[`CriFileSink`] の `append_part` が拒否する）。
pub fn encode_part_records(
    stream: StreamKind,
    bytes: &[u8],
    end: PartEnd,
    timestamp: &[u8; CRI_TIMESTAMP_LEN],
    out: &mut Vec<u8>,
) {
    // `PartEnd` は non_exhaustive: 未知の変種は行の終端と見なさず `P`（続きがあるものとして扱う）にする。
    let last_tag = match end {
        PartEnd::Lf => b'F',
        _ => b'P',
    };
    if bytes.is_empty() {
        if end == PartEnd::Lf {
            push_record(stream, b'F', bytes, timestamp, out);
        }
        return;
    }
    let mut chunks = bytes.chunks(CRI_LOG_CHUNK_BYTES).peekable();
    while let Some(chunk) = chunks.next() {
        let tag = if chunks.peek().is_some() {
            b'P'
        } else {
            last_tag
        };
        push_record(stream, tag, chunk, timestamp, out);
    }
}

/// `/proc/self/status` の内容から、effective / permitted の capability が空であることを確かめる（純関数）。
///
/// 特権ランチャー経由の supervisor は `CAP_DAC_OVERRIDE` 等を ambient で持つため、利用者の指定したパスをその権限で開くと
/// DAC を越えて任意のファイルへ追記できる（権限昇格）。`CapEff` と `CapPrm` のどちらかが 0 でなければ、読めない・壊れている
/// 場合も含めて `Unimplemented` で拒否する（fail-closed。permitted を見るのは effective へ上げてから開く経路も塞ぐため）。
/// ランチャー経由での CRI ログは後続 issue で扱う。
pub fn deny_elevated_capabilities(status: &str) -> Result<(), TraitError> {
    let denied = || {
        TraitError::new(
            ErrorCode::Unimplemented,
            "cri log path is not supported with elevated capabilities",
        )
    };
    let field = |name: &str| -> Option<u64> {
        let value = status
            .lines()
            .find_map(|l| l.strip_prefix(name))?
            .strip_prefix(':')?
            .trim();
        if value.is_empty() || value.len() > 16 {
            return None;
        }
        u64::from_str_radix(value, 16).ok()
    };
    match (field("CapEff"), field("CapPrm")) {
        (Some(0), Some(0)) => Ok(()),
        _ => Err(denied()),
    }
}

/// CRI 形式でファイルへ追記する [`LogSink`]（unix のみ開ける）。
///
/// supervisor プロセスにつき 1 つで、再起動をまたいで使い回す（開き直さない）。書き込みは固定 8 KiB の `BufWriter` 越しで、
/// `flush` で書き出す。書き込みに失敗したら失敗状態に固定し、以後の `append` は `Err` を返す（再書き込みで重複を作らない）。
pub struct CriFileSink {
    inner: Mutex<Inner>,
    /// 開いたパス（`reopen` が同じパスを開き直す。`ReopenContainerLog`。CRI-2・#4652）。
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    path: std::path::PathBuf,
    /// 総量の上限（`reopen` が新しいファイルの残りを数え直す）。
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    max_bytes: u64,
    /// 失敗状態へ入った回数（入るたびに構造化ログ 1 行を出す。試験で 1 回だけ出ることを照合する）。
    #[cfg_attr(not(all(test, unix)), allow(dead_code))]
    notices: std::sync::atomic::AtomicU64,
    #[cfg(test)]
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    faults: Faults,
}

/// 試験用の故障注入の呼び出し（引数はパス）。
#[cfg(test)]
type Hook = Mutex<Option<Box<dyn Fn(&std::path::Path) + Send>>>;

/// 試験用の故障注入（`cfg(test)` のみ）。
#[cfg(test)]
#[derive(Default)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
struct Faults {
    /// 真なら次の書き込みを失敗させる。
    write: std::sync::atomic::AtomicBool,
    /// 真なら同じ inode の開き直しの flush を失敗させる。
    flush: std::sync::atomic::AtomicBool,
    /// 開けなかった後・`O_EXCL` で作る直前に呼ぶ（引数は対象のパス）。
    before_create: Hook,
    /// ファイルを作った直後（ロックの前）に呼ぶ。
    after_create: Hook,
    /// 確定の直前（待ちうる処理の後・関門の前。内部ロックを持つ）に呼ぶ。
    before_commit: Hook,
}

enum Inner {
    #[cfg(unix)]
    Active {
        writer: std::io::BufWriter<std::fs::File>,
        /// 上限までに書ける残りバイト数（ファイルの既存サイズを引いた値から始める）。
        remaining: u64,
    },
    /// 失敗状態に固定された（最初のエラーコードを持つ。`reopen` が解除する）。
    // 非 unix では `open` が常に失敗し、この状態を作る経路が無い。
    #[cfg_attr(not(unix), allow(dead_code))]
    Failed(ErrorCode),
}

/// 親ディレクトリを検査して実体パスを返す。親が無いときは、検査を通った祖先（kubelet が作る `log_directory`）の直下に限り
/// 1 階層だけ 0o750 で作る（CRI 標準の `<containerName>/<N>.log`。kubelet は `log_directory` しか作らない。containerd・
/// CRI-O は親を MkdirAll する）。作る前に祖先を `check_dir` で検査し、作った後も `check_dir` で再検査する。`mkdir` は最終要素の
/// symlink を辿らない（既存なら `AlreadyExists` で、その場合も再検査で symlink を拒否する）。2 階層以上欠けていれば作らない。
#[cfg(unix)]
fn ensure_parent_dir(
    parent: &std::path::Path,
    unopenable: impl Fn() -> TraitError,
) -> Result<std::path::PathBuf, TraitError> {
    use std::os::unix::fs::DirBuilderExt as _;

    match super::rotating::check_dir(parent) {
        Ok(dir) => return Ok(dir),
        Err(e) => {
            if std::fs::symlink_metadata(parent).is_ok() {
                return Err(e);
            }
        }
    }
    // 親が存在しない: その親（祖先）が検査を通ることを確かめてから 1 階層だけ作る。
    let Some(grand) = parent.parent() else {
        return Err(unopenable());
    };
    super::rotating::check_dir(grand)?;
    match std::fs::DirBuilder::new().mode(0o750).create(parent) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(_) => return Err(unopenable()),
    }
    super::rotating::check_dir(parent)
}

/// 排他ロック（`flock(2)`。open file description 単位）を試みる。`WouldBlock` なら短い猶予の中で数回やり直し、
/// それでも取れなければ `WouldBlock` を返す（`fandhe-container-platform-macos` の `console_log` と同じ方式。MAC-1・#2138）。
///
/// 猶予の理由: fd を `close` しても、他スレッドの `fork` が複製した fd が子の `exec` で閉じられるまで description が
/// 生き続け、直前に同じプロセスが解放したロックが一瞬「使用中」に見える（supervisor はコンテナのプロセスを起動する）。
/// 実際に書き手が生きていれば猶予を超えて保持し続けるため、二重の書き手を拒否する fail-closed の挙動は変わらない
/// （拒否が最大 [`LOCK_GRACE`] 遅れるだけ。REPAIR-5）。
#[cfg(unix)]
fn try_lock_with_grace(file: &std::fs::File) -> Result<(), std::fs::TryLockError> {
    let deadline = std::time::Instant::now() + LOCK_GRACE;
    loop {
        match file.try_lock() {
            Err(std::fs::TryLockError::WouldBlock) if std::time::Instant::now() < deadline => {
                std::thread::sleep(LOCK_RETRY_INTERVAL);
            }
            other => return other,
        }
    }
}

/// [`try_lock_with_grace`] が `WouldBlock` を再試行する合計時間（fork と exec の間の窓を覆う長さ）。
#[cfg(unix)]
const LOCK_GRACE: Duration = Duration::from_millis(250);

/// [`try_lock_with_grace`] の再試行間隔。
#[cfg(unix)]
const LOCK_RETRY_INTERVAL: Duration = Duration::from_millis(5);

/// 開けないときの固定のエラー（パス・errno を含めない。ERR-1）。
#[cfg(unix)]
fn unopenable() -> TraitError {
    TraitError::new(
        ErrorCode::FailedPrecondition,
        "cri log file cannot be opened",
    )
}

/// CRI ログを開く共通のオプション（追記・0o640・`O_NOFOLLOW`・`O_NONBLOCK`・`O_NOCTTY`）。
#[cfg(unix)]
fn log_open_options(create: bool) -> std::fs::OpenOptions {
    use std::os::unix::fs::OpenOptionsExt as _;

    let mut opts = std::fs::OpenOptions::new();
    opts.append(true).create(create).mode(0o640).custom_flags(
        super::rotating::O_NOFOLLOW
            | crate::container_options::env::O_NONBLOCK
            | crate::container_options::env::O_NOCTTY,
    );
    opts
}

/// CRI ログのファイルを、親の検査・`O_NOFOLLOW` つきで追記で開く（無ければ作る。ロックは取らない）。
/// 親ディレクトリは検査済みの祖先の直下に作る（`open` 専用。`reopen` はこの関数を使わない。CRI-2・#4652）。
/// 開けなければ `FailedPrecondition`。
#[cfg(unix)]
fn open_log_file(path: &std::path::Path) -> Result<std::fs::File, TraitError> {
    let (Some(parent), Some(name)) = (path.parent(), path.file_name()) else {
        return Err(invalid("cri log path has no file name"));
    };
    let dir = ensure_parent_dir(parent, unopenable)?;
    log_open_options(true)
        .open(dir.join(name))
        .map_err(|_| unopenable())
}

/// `reopen` 用に、親ディレクトリを検査して fd で開く（以後の open・作成・削除はこの fd の直下だけで行い、パスを再解決しない。
/// CRI-2・SEC-1・#4652）。パスの検査（[`super::rotating::check_dir`]。絶対・`..` なし・祖先の symlink なし）の後に
/// `O_DIRECTORY | O_NOFOLLOW` で開き、開いた fd 自体を `fstat` で確かめる（ディレクトリである・group / other 書き込み不可・
/// open の **前** に `lstat` したパスと同じ dev / ino。`lstat` から open までの間の差し替えを拒否する）。
/// 残る窓: `check_dir` の祖先の検査から `lstat` までの間に祖先を差し替えられると、`lstat` と open の両方が差し替え後を
/// 指して一致する（祖先に書き込める主体に限る。docs/design/cri-log-partial-lines.md「ReopenContainerLog との関係」）。
#[cfg(target_os = "linux")]
fn open_verified_dir(parent: &std::path::Path) -> Result<std::fs::File, TraitError> {
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};

    let canonical = super::rotating::check_dir(parent).map_err(|_| unopenable())?;
    let flags = crate::sys::open_dir_nofollow_flags().map_err(|_| unopenable())?;
    // 比べる側は open の前に取る（open の後に引き直すと、差し替え後どうしで一致してしまう）。
    let checked = std::fs::symlink_metadata(&canonical).map_err(|_| unopenable())?;
    let dir = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(flags)
        .open(&canonical)
        .map_err(|_| unopenable())?;
    let opened = dir.metadata().map_err(|_| unopenable())?;
    if !opened.is_dir()
        || opened.mode() & 0o022 != 0
        || opened.dev() != checked.dev()
        || opened.ino() != checked.ino()
    {
        return Err(unopenable());
    }
    Ok(dir)
}

/// 自分で作った `file` が、`dir` の直下の `name` に今もあるときだけ消す（同じ dev / ino を `O_PATH | O_NOFOLLOW` で確かめてから
/// `unlinkat`。他者が差し替えた名前・別の inode には触れない。パスを再解決しない。失敗は握りつぶす: 後始末の失敗で本来の
/// エラーを隠さない）。
/// 既知の制約: 照合と `unlinkat` の間（数 µs）に他者が同じ名前へ別の inode を rename すると、それを消しうる。Linux の
/// `unlinkat(2)` には「同じ inode のときだけ消す」条件が無く（FreeBSD の `funlinkat` 相当が無い）、この窓は閉じられない
/// （docs/design/cri-log-partial-lines.md「ReopenContainerLog との関係」）。
#[cfg(target_os = "linux")]
fn remove_if_same(dir: &std::fs::File, name: &std::ffi::OsStr, file: &std::fs::File) {
    use std::os::fd::AsFd as _;
    let Ok(at_name) = crate::sys::open_path_at(dir.as_fd(), name) else {
        return;
    };
    if same_inode(&at_name, file) {
        let _ = crate::sys::unlink_at(dir.as_fd(), name);
    }
}

/// 期限内にロックを取る（`Mutex` に待ち時間の指定が無いため `try_lock` を短い間隔で繰り返す）。取れなければ `None`。
#[cfg(target_os = "linux")]
fn lock_until<T>(m: &Mutex<T>, deadline: Instant) -> Option<std::sync::MutexGuard<'_, T>> {
    loop {
        match m.try_lock() {
            Ok(g) => return Some(g),
            Err(std::sync::TryLockError::Poisoned(p)) => return Some(p.into_inner()),
            Err(std::sync::TryLockError::WouldBlock) => {
                if Instant::now() >= deadline {
                    return None;
                }
                std::thread::sleep(Duration::from_millis(1));
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn timeout_error() -> TraitError {
    TraitError::new(ErrorCode::Timeout, "cri log reopen deadline exceeded")
}

#[cfg(target_os = "linux")]
fn not_permitted_error() -> TraitError {
    TraitError::new(
        ErrorCode::FailedPrecondition,
        "cri log reopen is no longer permitted",
    )
}

/// 確定点で期限までに残しておく余裕（応答をクライアントへ届ける分）。
#[cfg(target_os = "linux")]
const COMMIT_MARGIN: std::time::Duration = std::time::Duration::from_millis(200);

/// 待ちうる処理に入る前の事前確認（期限と、呼び出し元がまだ稼働中の世代か）。何も確定しない。確定は
/// [`CriFileSink::commit_switch`] の関門の中で改めて確認する。
#[cfg(target_os = "linux")]
fn check_budget(deadline: Instant, gate: ReopenGate<'_>) -> Result<(), TraitError> {
    if Instant::now() >= deadline {
        return Err(timeout_error());
    }
    if !gate(&mut || {}) {
        return Err(not_permitted_error());
    }
    Ok(())
}

/// 開いたファイルの排他ロックを取り、通常ファイルであることを確かめて大きさを返す。書き手は 1 ファイルにつき 1 つ
/// （総量の上限を書き手ごとに数えるため。別の supervisor が同じパスを開いていれば上限が書き手の数だけ増える）。
/// サイズは排他ロックを取ってから読む（先に読むと、解放直後の相手の書き込みを数え損ねる）。
#[cfg(unix)]
fn lock_and_size(file: &std::fs::File) -> Result<u64, TraitError> {
    match try_lock_with_grace(file) {
        Ok(()) => {}
        Err(std::fs::TryLockError::WouldBlock) => {
            return Err(TraitError::new(
                ErrorCode::FailedPrecondition,
                "cri log file is already in use by another writer",
            ));
        }
        Err(std::fs::TryLockError::Error(_)) => return Err(unopenable()),
    }
    let Ok(meta) = file.metadata() else {
        return Err(unopenable());
    };
    if !meta.is_file() {
        return Err(unopenable());
    }
    Ok(meta.len())
}

/// 2 つのファイルが同じ inode か（`reopen` が rename されていないパスの再 open と、作ったファイルの同一性を見分ける）。
#[cfg(target_os = "linux")]
fn same_inode(a: &std::fs::File, b: &std::fs::File) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    match (a.metadata(), b.metadata()) {
        (Ok(a), Ok(b)) => a.dev() == b.dev() && a.ino() == b.ino(),
        _ => false,
    }
}

/// `reopen` で旧 writer の flush が失敗したことの構造化 1 行を出す（黙って消さない。REPAIR-4。パスは含めない）。
#[cfg(target_os = "linux")]
fn report_reopen_flush_failure() {
    let line = "{\"component\":\"supervisor.logs\",\"operation\":\"cri_reopen\",\"result\":\"old_flush_failed\"}\n";
    let _ = crate::stderr_sink::stderr().emit(line.as_bytes().to_vec());
}

impl CriFileSink {
    /// `path`（cri が結合・検証した絶対パス）を追記で開く。親ディレクトリが安全でない・最終要素が symlink / 通常ファイル
    /// 以外のときは開かない。親ディレクトリが無ければ検査済みの祖先の直下に 1 階層だけ作る（`ensure_parent_dir`）。開けない場合と、別の書き手が排他ロックを
    /// 保持している場合は `FailedPrecondition`（launch の前の確定失敗）。
    #[cfg(unix)]
    pub fn open(
        path: &fandhe_container_core::traits::ContainerLogPath,
    ) -> Result<Self, TraitError> {
        Self::open_with_limit(path, CRI_LOG_MAX_BYTES)
    }

    /// [`Self::open`] の上限指定版（総量が `max_bytes` を超える書き込みは `ResourceExhausted` で止める）。
    #[cfg(unix)]
    fn open_with_limit(
        path: &fandhe_container_core::traits::ContainerLogPath,
        max_bytes: u64,
    ) -> Result<Self, TraitError> {
        let path = std::path::PathBuf::from(path.as_str());
        let file = open_log_file(&path)?;
        let len = lock_and_size(&file)?;
        Ok(Self {
            inner: Mutex::new(Inner::Active {
                writer: std::io::BufWriter::with_capacity(WRITE_BUFFER_BYTES, file),
                remaining: max_bytes.saturating_sub(len),
            }),
            path,
            max_bytes,
            notices: std::sync::atomic::AtomicU64::new(0),
            #[cfg(test)]
            faults: Faults::default(),
        })
    }

    /// 失敗状態へ固定し、最初の失敗を構造化ログ 1 行で通知する（REPAIR-4。`reopen` が解除するまで再通知しない。
    /// 状態は `Mutex<Inner>` の下にあるため、書き込みの失敗の記録と `reopen` の差し替えは同じ境界で直列化される）。
    #[cfg(unix)]
    fn enter_failed(&self, inner: &mut Inner, code: ErrorCode) {
        *inner = Inner::Failed(code);
        self.notices
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        report_destination_failure(1, code);
    }

    /// 符号化済みのレコード列を上限検査つきで書く（`append`・`append_part` の共通の書き込み口。CRI-2・SUP-4・#4582）。
    /// 上限（既存サイズ込み）を超える場合は 1 バイトも書かず、溜めた分だけ書き出して失敗状態に固定し `ResourceExhausted`。
    /// 書き込み失敗は `Internal` で失敗状態に固定する（再書き込みで重複を作らない）。
    fn write_records(&self, records: &[u8]) -> Result<(), TraitError> {
        // 非 unix では Active 腕が無く records を使わないため、未使用警告を避ける。
        #[cfg(not(unix))]
        let _ = records;
        let mut guard = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        match &mut *guard {
            #[cfg(unix)]
            Inner::Active { writer, remaining } => {
                let need = u64::try_from(records.len()).unwrap_or(u64::MAX);
                if need > *remaining {
                    // 上限に達した: 溜めた分だけ書き出して止める（回転が無いため以後は書かない。REPAIR-3）。
                    let _ = writer.flush();
                    self.enter_failed(&mut guard, ErrorCode::ResourceExhausted);
                    return Err(TraitError::new(
                        ErrorCode::ResourceExhausted,
                        "cri log size limit reached",
                    ));
                }
                #[cfg(test)]
                let injected = self
                    .faults
                    .write
                    .swap(false, std::sync::atomic::Ordering::SeqCst);
                #[cfg(not(test))]
                let injected = false;
                if injected || writer.write_all(records).is_err() {
                    self.enter_failed(&mut guard, ErrorCode::Internal);
                    return Err(internal("cri log write failed"));
                }
                *remaining -= need;
                Ok(())
            }
            Inner::Failed(_) => Err(internal("cri log sink is in failed state")),
        }
    }

    /// 新規に作ったファイル（`dir` の直下の `name` を `O_EXCL` で作った fd）への開き直し。待ちうる処理（ロック・メタデータ・
    /// 旧 writer の flush）を確定の前にすべて済ませ、確定は [`Self::commit_switch`] の関門だけで行う。どこで失敗しても
    /// （期限・世代・ロック・flush）、作ったファイルを消す（[`remove_if_same`]。同じ inode のときだけ）。
    #[cfg(target_os = "linux")]
    fn publish_new(
        &self,
        dir: &std::fs::File,
        name: &std::ffi::OsStr,
        file: std::fs::File,
        deadline: Instant,
        gate: ReopenGate<'_>,
    ) -> Result<RetiredWriter, TraitError> {
        let mut slot = Some(file);
        let result = self.prepare_and_commit_new(&mut slot, deadline, gate);
        // 確定していれば `slot` は空。残っていれば作ったまま公開された状態なので消す。
        if result.is_err()
            && let Some(file) = slot.as_ref()
        {
            remove_if_same(dir, name, file);
        }
        result
    }

    #[cfg(target_os = "linux")]
    fn prepare_and_commit_new(
        &self,
        slot: &mut Option<std::fs::File>,
        deadline: Instant,
        gate: ReopenGate<'_>,
    ) -> Result<RetiredWriter, TraitError> {
        let Some(file) = slot.as_ref() else {
            return Err(unopenable());
        };
        #[cfg(test)]
        self.run_hook(&self.faults.after_create);
        // 作ったファイルを検証・ロックしたのと同じ fd が、そのまま書き手になる（名前を再解決しない）。
        let len = lock_and_size(file)?;
        let Some(mut guard) = lock_until(&self.inner, deadline) else {
            return Err(timeout_error());
        };
        self.flush_old(&mut guard)?;
        #[cfg(test)]
        self.run_hook(&self.faults.before_commit);
        self.commit_switch(&mut guard, slot, len, deadline, gate)
    }

    /// 既にあるファイルへの開き直し: 同じ inode なら writer を残して flush と数え直しだけ（E）、別 inode ならロックを取って
    /// 旧 writer を flush してから差し替える。待ちうる処理はすべて確定の前に済ませる。
    #[cfg(target_os = "linux")]
    fn switch_existing(
        &self,
        file: std::fs::File,
        deadline: Instant,
        gate: ReopenGate<'_>,
    ) -> Result<RetiredWriter, TraitError> {
        let Some(mut guard) = lock_until(&self.inner, deadline) else {
            return Err(timeout_error());
        };
        check_budget(deadline, gate)?;
        if let Inner::Active { writer, .. } = &*guard
            && same_inode(writer.get_ref(), &file)
        {
            // 書き出せなかった分が BufWriter に残るため、成功として残りを数え直すと上限を超えうる。
            // 失敗は成功にせず、残りも変えない（E）。
            self.flush_old(&mut guard)?;
            let Ok(meta) = file.metadata() else {
                return Err(unopenable());
            };
            #[cfg(test)]
            self.run_hook(&self.faults.before_commit);
            // 同じ inode: writer は残し、残りだけを数え直す（`slot` は空）。
            return self.commit_switch(&mut guard, &mut None, meta.len(), deadline, gate);
        }
        // 別 inode の既存ファイルはリンクが 1 本のものだけ受ける（ログディレクトリの外の inode へのハードリンクへ
        // 書き込み先を移さない。ロックの前に見て、リンク先の正規の書き手の flock を一時的にも塞がない。SEC-1）。
        if !matches!(file.metadata(), Ok(m) if std::os::unix::fs::MetadataExt::nlink(&m) == 1) {
            return Err(unopenable());
        }
        let len = lock_and_size(&file)?;
        self.flush_old(&mut guard)?;
        #[cfg(test)]
        self.run_hook(&self.faults.before_commit);
        self.commit_switch(&mut guard, &mut Some(file), len, deadline, gate)
    }

    /// 旧 writer の未書き込み分を書き出す（確定の前。失敗なら構造化 1 行を出して `Err` を返し、旧 writer と未書き込みの行は
    /// そのまま残る。呼び出し側は差し替えない）。`Failed` の状態には書き出すものが無い。
    #[cfg(target_os = "linux")]
    fn flush_old(&self, inner: &mut Inner) -> Result<(), TraitError> {
        let Inner::Active { writer, .. } = inner else {
            return Ok(());
        };
        #[cfg(test)]
        let injected = self
            .faults
            .flush
            .swap(false, std::sync::atomic::Ordering::SeqCst);
        #[cfg(not(test))]
        let injected = false;
        if injected || writer.flush().is_err() {
            report_reopen_flush_failure();
            return Err(internal("cri log flush failed"));
        }
        Ok(())
    }

    /// 確定点。`gate`（呼び出し元のロックの下の世代確認）の中で、期限を再確認して `slot` の新しい writer へメモリ上で
    /// 差し替える（`slot` が空なら writer は残して残りだけを `len` から数え直す）。I/O をしない（旧 writer は flush 済みで、
    /// 取り外した旧 writer の close は関門の外）。期限切れ・世代の終了なら何も変えず `Err`（`slot` のファイルは呼び出し側が消す）。
    /// ロック順は sink の内部ロック（`guard`）→ 呼び出し元のロック（`gate` の中）で、逆向きに取る経路は無い。
    #[cfg(target_os = "linux")]
    fn commit_switch(
        &self,
        guard: &mut Inner,
        slot: &mut Option<std::fs::File>,
        len: u64,
        deadline: Instant,
        gate: ReopenGate<'_>,
    ) -> Result<RetiredWriter, TraitError> {
        let remaining = self.max_bytes.saturating_sub(len);
        let mut old = None;
        let mut expired = false;
        let permitted = gate(&mut || {
            // 期限の直前の確定は、応答がクライアントの期限に間に合わず kubelet が rename を戻しうるため、余裕を残して
            // 拒否する（確定したのにクライアントは期限切れを受け取る食い違いを避ける。REPAIR-5）。
            if Instant::now() + COMMIT_MARGIN >= deadline {
                expired = true;
                return;
            }
            match slot.take() {
                Some(file) => {
                    let new_state = Inner::Active {
                        writer: std::io::BufWriter::with_capacity(WRITE_BUFFER_BYTES, file),
                        remaining,
                    };
                    old = Some(std::mem::replace(guard, new_state));
                }
                None => {
                    if let Inner::Active { remaining: r, .. } = guard {
                        *r = remaining;
                    }
                }
            }
        });
        // 旧 writer は呼び出し元が応答の後に drop し、そこで旧 fd の flock が外れる（flush 済みで書き込みは起きない）。
        match (permitted, expired) {
            (true, false) => {
                Ok(old.map_or_else(RetiredWriter::default, |o| RetiredWriter::new(Box::new(o))))
            }
            (true, true) => Err(timeout_error()),
            (false, _) => Err(not_permitted_error()),
        }
    }

    /// 試験用の故障注入のフック（対象のパスを渡して呼ぶ）。
    #[cfg(all(test, target_os = "linux"))]
    fn run_hook(&self, hook: &Hook) {
        if let Some(f) = hook.lock().unwrap_or_else(PoisonError::into_inner).as_ref() {
            f(&self.path);
        }
    }

    /// 非 unix では開けない（`Unimplemented`。形式の純関数だけを 3 OS で提供する）。
    #[cfg(not(unix))]
    pub fn open(
        _path: &fandhe_container_core::traits::ContainerLogPath,
    ) -> Result<Self, TraitError> {
        Err(TraitError::new(
            ErrorCode::Unimplemented,
            "cri log file is not supported on this platform",
        ))
    }
}

impl LogSink for CriFileSink {
    fn append(&self, stream: StreamKind, line: &[u8]) -> Result<(), TraitError> {
        // 直接呼び出しでも確保量を抑えるため、確保前に MAX_LINE_BYTES へ切り詰める。
        let line = line.get(..MAX_LINE_BYTES).unwrap_or(line);
        // LF を含むとレコードの境界が崩れるため拒否する（`RotatingFileSink` と同じ）。
        if line.contains(&b'\n') {
            return Err(invalid("log line must not contain a line feed"));
        }
        let mut records = Vec::with_capacity(line.len() + CRI_TIMESTAMP_LEN + 8);
        encode_records(stream, line, &now_timestamp(), &mut records);
        self.write_records(&records)
    }

    /// 捕捉リーダーが渡す断片を `P` / `F` で書く（#4582・CRI-2・SUP-7）。LF を含む入力と [`MAX_LINE_BYTES`] を超える入力は
    /// 確保の前に `InvalidArgument` で拒否する（契約違反を黙って欠落させない。文言は固定で入力を含めない。ERR-1）。
    /// 総量の上限・失敗状態の扱いは [`Self::append`] と同じ（1 断片分の全部か無しか）。
    fn append_part(
        &self,
        stream: StreamKind,
        bytes: &[u8],
        part: LinePart<'_>,
    ) -> Result<(), TraitError> {
        if bytes.len() > MAX_LINE_BYTES {
            return Err(invalid("log line part exceeds the maximum length"));
        }
        if bytes.contains(&b'\n') {
            return Err(invalid("log line must not contain a line feed"));
        }
        let mut records = Vec::with_capacity(bytes.len() + CRI_TIMESTAMP_LEN + 8);
        // 1 断片に 1 時刻（containerd と同じ）。
        encode_part_records(stream, bytes, part.end, &now_timestamp(), &mut records);
        if records.is_empty() {
            return Ok(());
        }
        self.write_records(&records)
    }

    fn flush(&self) -> Result<(), TraitError> {
        let mut guard = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        match &mut *guard {
            #[cfg(unix)]
            Inner::Active { writer, .. } => {
                if writer.flush().is_err() {
                    self.enter_failed(&mut guard, ErrorCode::Internal);
                    return Err(internal("cri log write failed"));
                }
                Ok(())
            }
            Inner::Failed(_) => Err(internal("cri log sink is in failed state")),
        }
    }

    /// 同じパスを開き直す（kubelet のログ回転後の `ReopenContainerLog`。CRI-2・SUP-7・REPAIR-4・REPAIR-5・#4652）。
    ///
    /// 親ディレクトリを検査して fd で開き（`open_verified_dir`）、以後はその fd の直下だけを扱う（パスの再解決をしない）。
    /// 先に新しいファイルを用意し（`openat` の `O_NOFOLLOW`・排他ロック・通常ファイル）、失敗したら状態（`Active` / `Failed`）を
    /// 変えずに `Err` を返す。親ディレクトリは作らない。まず作らずに開き（既にあれば検証してそのまま使う）、無ければ
    /// `O_CREAT | O_EXCL` で作る（他者が先に作っていれば `EEXIST` で既存として開き直す）。検証・ロックした fd がそのまま
    /// 新しい writer になり、名前の引き直しも一時ファイルも使わない。待ちうる処理（開く・作る・ロック・メタデータ・旧 writer の
    /// flush）はすべて確定の前に済ませ、確定は `gate` の下で期限と世代を再確認してメモリ上で差し替えるだけにする
    /// （`commit_switch`）。確定できなければ自分で作ったファイルを消す（同じ inode のときだけ）。旧 writer の flush が
    /// 失敗したら切り替えず `Err`（旧 writer と未書き込みの行を残し、再試行できる）。総量の上限は新しいファイルの大きさから
    /// 数え直す。上限到達で止まった状態（`Failed`）からもここで再開し、失敗の記録は差し替えと同じ `Mutex` の下で解除される。
    ///
    /// rename 済み（別 inode）なら旧 fd を最後に閉じて旧ロックを外す。rename されていない（同じ inode）なら同一プロセスの
    /// 別 open file description のロックは衝突するため、旧 writer を残して flush し、大きさだけ数え直す。書き込みと同じ
    /// `Mutex` で直列化され、行の途中（部分行 `P` の続き）でも呼べる。`Mutex` の待ちは `deadline` まで、ファイルのロックの待ちは
    /// 最大 250ms（`LOCK_GRACE`）。ファイルの `open` 自体は期限で中断できない（呼び出し元は専用スレッドで実行すること）。
    /// Linux のみ（`openat`・`unlinkat` を使う。他の OS は `Unimplemented`）。
    fn reopen(&self, deadline: Instant, gate: ReopenGate<'_>) -> Result<RetiredWriter, TraitError> {
        #[cfg(target_os = "linux")]
        {
            use std::os::fd::AsFd as _;

            check_budget(deadline, gate)?;
            let (Some(parent), Some(name)) = (self.path.parent(), self.path.file_name()) else {
                return Err(invalid("cri log path has no file name"));
            };
            let dir = open_verified_dir(parent)?;
            // 作る瞬間に他者が先に作る競合は、既存として 1 回だけやり直す。
            for _ in 0..2 {
                match crate::sys::open_log_at(dir.as_fd(), name, false) {
                    Ok(file) => return self.switch_existing(file, deadline, gate),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(_) => return Err(unopenable()),
                }
                check_budget(deadline, gate)?;
                #[cfg(test)]
                self.run_hook(&self.faults.before_create);
                match crate::sys::open_log_at(dir.as_fd(), name, true) {
                    Ok(file) => return self.publish_new(&dir, name, file, deadline, gate),
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(_) => return Err(unopenable()),
                }
            }
            Err(unopenable())
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (deadline, gate);
            Err(TraitError::new(
                ErrorCode::Unimplemented,
                "cri log reopen is not supported on this platform",
            ))
        }
    }

    fn owns_failure_state(&self) -> bool {
        true
    }

    fn failure_code(&self) -> Option<ErrorCode> {
        match &*self.inner.lock().unwrap_or_else(PoisonError::into_inner) {
            Inner::Failed(code) => Some(*code),
            #[cfg(unix)]
            Inner::Active { .. } => None,
        }
    }
}

/// 2 つの [`LogSink`] の両方へ書く（`@container-logs` と CRI ログの二重書き。CRI-2・SUP-4・#2671）。
///
/// 片方が失敗してもう片方への `append` / `flush` は続ける（呼び出し元の `LineSplitter` は最初の `Err` でストリームの
/// 以降を読み捨てるため、片方の失敗で既存の `@container-logs` の記録を止めない。SUP-4）。主（`@container-logs`）は最初の
/// 失敗の後に呼ばず、その失敗を構造化ログ 1 行で stderr へ通知する（REPAIR-4）。
///
/// 副（CRI ログ）の扱いは [`LogSink::owns_failure_state`] で分ける（#4652）。
/// - 偽（通常の sink）: 最初の失敗を Tee が記録・通知し（1 行）、以後呼ばない。両方が失敗したら `Err`（従来どおり）。
/// - 真（[`CriFileSink`]）: 失敗状態の保持・最初の失敗の通知・`reopen` での解除は副の sink 自身が同じ `Mutex` の下で行い、
///   Tee は副を呼び続ける。開き直し（`ReopenContainerLog`）で復旧できるため、両方が失敗していても `Err` を返さない
///   （返すと `LineSplitter` がそのストリームを恒久的に読み捨て、開き直しの後も捕捉が再開しない）。失敗は副の通知と
///   [`Self::failed_codes`] で観測する。
///
/// 観測は [`Self::failed_codes`]。
pub struct TeeLogSink {
    primary: Arc<dyn LogSink>,
    secondary: Arc<dyn LogSink>,
    /// 主の最初のエラーコード。`Some` の間は主を呼ばない。
    primary_failed: Mutex<Option<ErrorCode>>,
    /// 副（自分で失敗状態を持たない sink）の最初のエラーコード。`Some` の間は副を呼ばない。
    secondary_failed: Mutex<Option<ErrorCode>>,
}

impl TeeLogSink {
    /// 主（`@container-logs`）と副（CRI ログ）から作る。
    pub fn new(primary: Arc<dyn LogSink>, secondary: Arc<dyn LogSink>) -> Self {
        Self {
            primary,
            secondary,
            primary_failed: Mutex::new(None),
            secondary_failed: Mutex::new(None),
        }
    }

    /// 出力先ごと（主・副の順）の最初の失敗のエラーコード。失敗していなければ `None`
    /// （副が [`LogSink::owns_failure_state`] なら副自身の [`LogSink::failure_code`]、そうでなければ Tee の記録）。
    pub fn failed_codes(&self) -> [Option<ErrorCode>; 2] {
        [
            *self
                .primary_failed
                .lock()
                .unwrap_or_else(PoisonError::into_inner),
            if self.secondary.owns_failure_state() {
                self.secondary.failure_code()
            } else {
                *self
                    .secondary_failed
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
            },
        ]
    }

    /// 両方へ `op` を適用する（主は失敗後に呼ばない）。両方が（以前から、または今回）失敗したときだけ `Err`。
    fn each(&self, op: impl Fn(&dyn LogSink) -> Result<(), TraitError>) -> Result<(), TraitError> {
        let mut last_err = None;
        let mut alive = 0usize;
        let already = *self
            .primary_failed
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(code) = already {
            last_err = Some(TraitError::new(code, "log destination is in failed state"));
        } else {
            match op(self.primary.as_ref()) {
                Ok(()) => alive += 1,
                Err(e) => {
                    let first = {
                        let mut g = self
                            .primary_failed
                            .lock()
                            .unwrap_or_else(PoisonError::into_inner);
                        let first = g.is_none();
                        g.get_or_insert(e.code());
                        first
                    };
                    if first {
                        report_destination_failure(0, e.code());
                    }
                    last_err = Some(e);
                }
            }
        }
        if self.secondary.owns_failure_state() {
            // 副が自分で状態を持つ: 常に呼ぶ。失敗でも `Err` にしない（開き直しの後に捕捉が再開できるように）。
            let _ = op(self.secondary.as_ref());
            return Ok(());
        }
        let already = *self
            .secondary_failed
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(code) = already {
            last_err = Some(TraitError::new(code, "log destination is in failed state"));
        } else {
            match op(self.secondary.as_ref()) {
                Ok(()) => alive += 1,
                Err(e) => {
                    let first = {
                        let mut g = self
                            .secondary_failed
                            .lock()
                            .unwrap_or_else(PoisonError::into_inner);
                        let first = g.is_none();
                        g.get_or_insert(e.code());
                        first
                    };
                    if first {
                        report_destination_failure(1, e.code());
                    }
                    last_err = Some(e);
                }
            }
        }
        match (alive, last_err) {
            (0, Some(e)) => Err(e),
            _ => Ok(()),
        }
    }
}

/// 出力先の失敗通知の構造化 1 行（JSON。末尾改行つき）を作る（パス・errno・行の内容は含めない。ERR-1）。
fn destination_failure_line(index: usize, code: ErrorCode) -> String {
    let destination = if index == 0 {
        "container_logs"
    } else {
        "cri_log"
    };
    format!(
        "{{\"component\":\"supervisor.logs\",\"operation\":\"tee_append\",\"result\":\"destination_failed\",\"destination\":\"{}\",\"code\":\"{}\"}}\n",
        destination,
        code.as_str()
    )
}

/// 出力先の最初の失敗を共有の非同期出力（`stderr_sink`）へ出す（REPAIR-4）。
/// 本番では stderr が `Stdio::null()` で、書き先が `@supervisor-logs` へ差し替わるため、
/// `std::io::stderr()` へ直接書かず sink 経由にする（保存経路を迂回せず、満杯でも捕捉スレッドを止めない）。
fn report_destination_failure(index: usize, code: ErrorCode) {
    let _ = crate::stderr_sink::stderr().emit(destination_failure_line(index, code).into_bytes());
}

impl LogSink for TeeLogSink {
    fn append(&self, stream: StreamKind, line: &[u8]) -> Result<(), TraitError> {
        self.each(|s| s.append(stream, line))
    }

    /// 断片を両方の出力先へ渡す。上書きしないと既定実装が先頭断片を `append` へ渡し、CRI ログも切り詰めになる（#4582）。
    /// 主（`RotatingFileSink`）は既定の `append_part` のまま行の終端まで遅延するため、`@container-logs` は切り詰めのまま。
    fn append_part(
        &self,
        stream: StreamKind,
        bytes: &[u8],
        part: LinePart<'_>,
    ) -> Result<(), TraitError> {
        self.each(|s| s.append_part(stream, bytes, part))
    }

    fn flush(&self) -> Result<(), TraitError> {
        self.each(|s| s.flush())
    }

    /// CRI ログ（副）だけを開き直す（`@container-logs` は従来どおり。CRI-2・#4652）。副が `Unimplemented`（CRI ログが無い）や
    /// 失敗のときはそのまま返す。失敗状態の解除は副の sink が差し替えと同じ `Mutex` の下で行う。
    fn reopen(&self, deadline: Instant, gate: ReopenGate<'_>) -> Result<RetiredWriter, TraitError> {
        self.secondary.reopen(deadline, gate)
    }
}

#[cfg(all(test, unix))]
mod part_tests;

#[cfg(test)]
mod tests {
    use super::*;

    /// REPAIR-4: 失敗通知は末尾改行つきの 1 行 JSON で、出力先名とコードだけを含む。
    #[test]
    fn repair4_destination_failure_line_is_single_json_line() {
        let line = destination_failure_line(1, ErrorCode::FailedPrecondition);
        assert!(
            line.ends_with("\"code\":\"FAILED_PRECONDITION\"}\n"),
            "{line}"
        );
        assert!(line.contains("\"destination\":\"cri_log\""), "{line}");
        assert_eq!(line.matches('\n').count(), 1);
    }

    fn ts(secs: u64, nanos: u32) -> String {
        String::from_utf8(format_timestamp(Duration::new(secs, nanos)).to_vec()).expect("ascii")
    }

    /// CRI-2・SUP-4: タイムスタンプは UTC の RFC3339 でナノ秒 9 桁固定（閏日・2038 年超・上限を含む）。
    #[test]
    fn cri2_timestamp_formats_fixed_width() {
        assert_eq!(ts(0, 0), "1970-01-01T00:00:00.000000000Z");
        assert_eq!(
            ts(1_475_713_029, 669_794_202),
            "2016-10-06T00:17:09.669794202Z"
        );
        assert_eq!(
            ts(1_709_251_199, 999_999_999),
            "2024-02-29T23:59:59.999999999Z"
        );
        assert_eq!(ts(4_107_542_400, 0), "2100-03-01T00:00:00.000000000Z");
        assert_eq!(ts(u64::MAX, 5), "9999-12-31T23:59:59.999999999Z");
        assert_eq!(ts(MAX_EPOCH_SECS, 7), "9999-12-31T23:59:59.000000007Z");
    }

    fn enc(stream: StreamKind, line: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        encode_records(stream, line, &format_timestamp(Duration::ZERO), &mut out);
        out
    }

    /// CRI-2・SUP-4: 1 レコードの形式。空行は内容なしの F、16 KiB ちょうどは F 1 件、超えたら P と F。
    #[test]
    fn cri2_records_format_and_chunking() {
        let t = "1970-01-01T00:00:00.000000000Z";
        assert_eq!(
            enc(StreamKind::Stdout, b"hello"),
            format!("{t} stdout F hello\n").into_bytes()
        );
        assert_eq!(
            enc(StreamKind::Stderr, b""),
            format!("{t} stderr F \n").into_bytes()
        );
        let exact = vec![b'a'; CRI_LOG_CHUNK_BYTES];
        let out = enc(StreamKind::Stdout, &exact);
        assert_eq!(out.iter().filter(|&&b| b == b'\n').count(), 1);
        assert!(out.starts_with(format!("{t} stdout F a").as_bytes()));
        let over = vec![b'b'; CRI_LOG_CHUNK_BYTES + 1];
        let out = enc(StreamKind::Stdout, &over);
        let text = String::from_utf8(out).expect("utf8");
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(
            lines[0],
            format!("{t} stdout P {}", "b".repeat(CRI_LOG_CHUNK_BYTES))
        );
        assert_eq!(lines[1], format!("{t} stdout F b"));
    }

    /// SEC-1・SUP-14: effective / permitted のどちらかが 0 でなければ、読めない・壊れている場合も含めて拒否する。
    #[test]
    fn cri2_capability_gate() {
        assert!(
            deny_elevated_capabilities(
                "Name:\tx\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\n"
            )
            .is_ok()
        );
        for bad in [
            "CapPrm:\t0000000000000000\nCapEff:\t0000000000000002\n",
            "CapPrm:\t0000000000000002\nCapEff:\t0000000000000000\n",
            "CapPrm:\t0000000000000000\n",
            "CapEff:\t0000000000000000\n",
            "CapPrm:\t0000000000000000\nCapEff:\tzzzz\n",
            "CapPrm:\t0000000000000000\nCapEff:\t\n",
            "",
        ] {
            let e = deny_elevated_capabilities(bad).expect_err(bad);
            assert_eq!(e.code(), ErrorCode::Unimplemented, "{bad:?}");
        }
    }

    /// 常に許可する関門（確定の関数をそのまま呼ぶ）。
    fn allow(f: &mut dyn FnMut()) -> bool {
        f();
        true
    }

    /// 5 秒の期限・常に許可で開き直す（試験の既定。期限・許可の個別の試験は直接 `reopen` を呼ぶ）。
    fn reopen_now(sink: &dyn LogSink) -> Result<(), TraitError> {
        sink.reopen(Instant::now() + Duration::from_secs(5), &allow)
            .map(drop)
    }

    /// 試験の同期点の待ち上限（到達しなければ、どの点か示して失敗する。REPAIR-5）。
    const SYNC_WAIT: Duration = Duration::from_secs(5);

    struct Recorder(Mutex<Vec<String>>, bool);

    impl LogSink for Recorder {
        fn append(&self, stream: StreamKind, line: &[u8]) -> Result<(), TraitError> {
            self.0.lock().expect("lock").push(format!(
                "{} {}",
                stream.as_str(),
                String::from_utf8_lossy(line)
            ));
            if self.1 {
                Err(internal("fail"))
            } else {
                Ok(())
            }
        }
    }

    /// CRI-2・SUP-4: tee は両方へ書き、片方が失敗しても他方への書き込みを続け（Ok）、両方失敗で Err を返す。
    #[test]
    fn cri2_tee_continues_with_healthy_sink_after_one_fails() {
        let a = Arc::new(Recorder(Mutex::new(Vec::new()), false));
        let b = Arc::new(Recorder(Mutex::new(Vec::new()), false));
        let tee = TeeLogSink::new(a.clone(), b.clone());
        tee.append(StreamKind::Stdout, b"x").expect("ok");
        assert_eq!(a.0.lock().expect("lock").clone(), ["stdout x"]);
        assert_eq!(b.0.lock().expect("lock").clone(), ["stdout x"]);
        assert_eq!(tee.failed_codes(), [None, None]);

        // 副（CRI ログ）が失敗しても主は継続し、失敗した副は以後呼ばれない。
        let bad = Arc::new(Recorder(Mutex::new(Vec::new()), true));
        let good = Arc::new(Recorder(Mutex::new(Vec::new()), false));
        let tee = TeeLogSink::new(good.clone(), bad.clone());
        tee.append(StreamKind::Stderr, b"y").expect("primary ok");
        tee.append(StreamKind::Stderr, b"z").expect("primary ok");
        tee.flush().expect("flush ok");
        assert_eq!(
            good.0.lock().expect("lock").clone(),
            ["stderr y", "stderr z"]
        );
        // 自分で失敗状態を持たない通常の副は、最初の失敗を Tee が記録し、以後呼ばない（従来どおり）。
        assert_eq!(bad.0.lock().expect("lock").clone(), ["stderr y"]);
        assert_eq!(tee.failed_codes(), [None, Some(ErrorCode::Internal)]);

        // 逆方向（主が失敗しても副は継続）。
        let bad = Arc::new(Recorder(Mutex::new(Vec::new()), true));
        let good = Arc::new(Recorder(Mutex::new(Vec::new()), false));
        let tee = TeeLogSink::new(bad.clone(), good.clone());
        tee.append(StreamKind::Stdout, b"p").expect("secondary ok");
        tee.append(StreamKind::Stdout, b"q").expect("secondary ok");
        assert_eq!(good.0.lock().expect("lock").len(), 2);
        assert_eq!(bad.0.lock().expect("lock").len(), 1);
        assert_eq!(tee.failed_codes(), [Some(ErrorCode::Internal), None]);

        // 両方失敗したときだけ Err。
        let b1 = Arc::new(Recorder(Mutex::new(Vec::new()), true));
        let b2 = Arc::new(Recorder(Mutex::new(Vec::new()), true));
        let tee = TeeLogSink::new(b1, b2);
        assert!(tee.append(StreamKind::Stdout, b"r").is_err());
        assert!(tee.append(StreamKind::Stdout, b"s").is_err());
    }

    /// CRI-2・SUP-7・#4652: 開き直し前に始まった副の `append` の失敗が、開き直しの後に記録されても副は止まらない（交錯の再現）。
    #[test]
    fn cri2_tee_reopen_ignores_failure_from_append_started_before_reopen() {
        use std::sync::mpsc::{Receiver, Sender, channel};

        struct Gate {
            entered: Mutex<Sender<()>>,
            release: Mutex<Receiver<()>>,
            fail_next: Mutex<bool>,
            got: Mutex<Vec<Vec<u8>>>,
        }
        impl LogSink for Gate {
            fn append(&self, _s: StreamKind, line: &[u8]) -> Result<(), TraitError> {
                let fail = std::mem::replace(&mut *self.fail_next.lock().expect("lock"), false);
                if fail {
                    self.entered.lock().expect("lock").send(()).expect("send");
                    self.release
                        .lock()
                        .expect("lock")
                        .recv_timeout(SYNC_WAIT)
                        .expect("sync point not reached: release signal for the stalled append");
                    return Err(internal("old state"));
                }
                self.got.lock().expect("lock").push(line.to_vec());
                Ok(())
            }
            fn reopen(&self, _: Instant, _: ReopenGate<'_>) -> Result<RetiredWriter, TraitError> {
                Ok(RetiredWriter::default())
            }
            // CRI ログの sink と同じく自分で失敗状態を持つ副（Tee は失敗を固定しない）。
            fn owns_failure_state(&self) -> bool {
                true
            }
        }

        let (entered_tx, entered_rx) = channel();
        let (release_tx, release_rx) = channel();
        let gate = Arc::new(Gate {
            entered: Mutex::new(entered_tx),
            release: Mutex::new(release_rx),
            fail_next: Mutex::new(true),
            got: Mutex::new(Vec::new()),
        });
        let primary = Arc::new(Recorder(Mutex::new(Vec::new()), false));
        let tee = Arc::new(TeeLogSink::new(primary, gate.clone()));
        let t = tee.clone();
        let h = std::thread::spawn(move || t.append(StreamKind::Stdout, b"old"));
        entered_rx
            .recv_timeout(SYNC_WAIT)
            .expect("sync point not reached: append did not reach the secondary sink");
        // 古い状態への append が副の中で止まっている間に開き直しが成功する。
        reopen_now(tee.as_ref()).expect("reopen");
        release_tx.send(()).expect("release");
        h.join().expect("join").expect("primary keeps ok");
        assert_eq!(tee.failed_codes(), [None, None]);
        tee.append(StreamKind::Stdout, b"new").expect("append");
        assert_eq!(gate.got.lock().expect("lock").clone(), [b"new".to_vec()]);
    }

    /// CRI-2・SUP-4・#4652: 自分で失敗状態を持たない通常の副は、最初の失敗を Tee が記録して以後呼ばず、通知は 1 回だけ
    /// （副の最初の失敗後に主が書き続けても、副の呼び出し回数・記録は増えない）。両方失敗したら `Err`。
    #[test]
    fn cri2_4652_ordinary_secondary_failure_is_recorded_once_and_not_called_again() {
        let primary = Arc::new(Recorder(Mutex::new(Vec::new()), false));
        let bad = Arc::new(Recorder(Mutex::new(Vec::new()), true));
        assert!(!bad.owns_failure_state());
        let tee = TeeLogSink::new(primary.clone(), bad.clone());
        for line in [b"1", b"2", b"3"] {
            tee.append(StreamKind::Stdout, line).expect("primary ok");
        }
        tee.flush().expect("flush");
        assert_eq!(bad.0.lock().expect("lock").clone(), ["stdout 1"]);
        assert_eq!(primary.0.lock().expect("lock").len(), 3);
        assert_eq!(tee.failed_codes(), [None, Some(ErrorCode::Internal)]);
    }

    /// CRI-2・SUP-7・#4652（P1）: 副が自分で状態を持つ（`CriFileSink`）とき、主と副の両方が失敗しても Tee は `Err` を返さず
    /// （`LineSplitter` が恒久停止しない）、開き直しの後に実際の捕捉（`LogCapture`）が新しいファイルへ再開する。
    #[cfg(target_os = "linux")]
    #[test]
    fn cri2_4652_capture_resumes_after_both_outputs_failed_and_reopen() {
        use crate::logs::{LogCapture, OutputStreams, ReaderBudget};
        use fandhe_container_core::traits::ContainerLogPath;
        use std::io::Write as _;
        use std::os::unix::fs::PermissionsExt as _;

        let root = crate::test_root::test_root_at(std::env::temp_dir().join(format!(
            "fc-crilog-resume-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        )));
        let dir = std::fs::canonicalize(&root).expect("canon");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o750)).expect("chmod");
        let path = ContainerLogPath::new(format!("{}/0.log", dir.display())).expect("path");
        let rotated = dir.join("0.log.1");
        // 1 行（42 バイト）で上限に達する CRI ログ。主は最初から失敗する。
        let cri = Arc::new(CriFileSink::open_with_limit(&path, 42).expect("open"));
        let primary = Arc::new(Recorder(Mutex::new(Vec::new()), true));
        let tee = Arc::new(TeeLogSink::new(primary, cri.clone()));
        let (out_r, mut out_w) = std::io::pipe().expect("pipe");
        let cap = LogCapture::start(
            OutputStreams::new(&ReaderBudget::with_max_limit(), Some(Box::new(out_r)), None),
            tee.clone(),
        )
        .expect("start");
        let wait_for = |what: &str, cond: &dyn Fn() -> bool| {
            let until = Instant::now() + SYNC_WAIT;
            while !cond() {
                assert!(Instant::now() < until, "sync point not reached: {what}");
                std::thread::sleep(Duration::from_millis(2));
            }
        };
        out_w.write_all(b"x\ny\n").expect("write");
        // 主は 1 行目で失敗、CRI は 2 行目で上限に達する（両方失敗）。それでも捕捉は止まらない。
        wait_for("both outputs failed", &|| {
            tee.failed_codes()
                == [
                    Some(ErrorCode::Internal),
                    Some(ErrorCode::ResourceExhausted),
                ]
        });
        std::fs::rename(path.as_str(), &rotated).expect("rename");
        reopen_now(tee.as_ref()).expect("reopen");
        assert_eq!(tee.failed_codes()[1], None);
        out_w.write_all(b"z\n").expect("write after reopen");
        wait_for("line after reopen reached the new file", &|| {
            cri.flush().is_ok()
                && std::fs::read_to_string(path.as_str())
                    .map(|t| t.ends_with(" stdout F z\n"))
                    .unwrap_or(false)
        });
        drop(out_w);
        let sum = cap.drain(Duration::from_secs(5)).expect("drain");
        let stdout = sum.stdout().expect("stdout summary");
        assert_eq!(stdout.lines(), 3);
        assert_eq!(stdout.error_code(), None, "capture never stopped");
        let old = std::fs::read_to_string(&rotated).expect("old");
        assert_eq!(old.lines().count(), 1);
        assert!(old.ends_with(" stdout F x\n"), "{old}");
    }

    #[cfg(unix)]
    mod file {
        use super::*;
        use fandhe_container_core::traits::ContainerLogPath;
        use std::os::unix::fs::{PermissionsExt as _, symlink};
        use std::path::{Path, PathBuf};
        use std::sync::atomic::{AtomicUsize, Ordering};
        #[cfg(target_os = "linux")]
        use std::time::Instant;

        /// 第 2 要素は残骸を消して作った実体（Drop で後始末する。REPAIR-12・#3435）。
        struct Tmp(PathBuf, #[allow(dead_code)] crate::test_root::TestRoot);

        impl Tmp {
            fn new(tag: &str) -> Self {
                static SEQ: AtomicUsize = AtomicUsize::new(0);
                let n = SEQ.fetch_add(1, Ordering::SeqCst);
                let p = std::env::temp_dir()
                    .join(format!("fc-crilog-{tag}-{}-{n}", std::process::id()));
                // 残骸・PID 再利用との衝突を避けるため排他作成し、既存の名前は消さず別名で作る（REPAIR-12・#3475）。
                let root = crate::test_root::test_root_at(p);
                let p = root.to_path_buf();
                // check_dir の試験条件として 0750 にする（test_root_at は 0700）。
                std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o750))
                    .expect("chmod");
                // 一時ディレクトリ自体が symlink 経由（macOS の /var 等）でも root 所有なら許される。
                Self(std::fs::canonicalize(&p).expect("canon"), root)
            }

            fn log(&self, rel: &str) -> ContainerLogPath {
                ContainerLogPath::new(format!("{}/{rel}", self.0.display())).expect("log path")
            }
        }

        fn read(p: &Path) -> String {
            std::fs::read_to_string(p).expect("read")
        }

        /// CRI-2・SUP-4: 総量の上限（既存サイズ込み）を超える書き込みは `ResourceExhausted` で止まり、上限内の分は残る。
        #[test]
        fn cri2_file_sink_stops_at_size_limit() {
            let t = Tmp::new("limit");
            let path = t.log("0.log");
            // 1 行は 30 + " stdout F x\n"(12) = 42 バイト。2 行ぶん（84）だけ許す。
            let sink = CriFileSink::open_with_limit(&path, 84).expect("open");
            sink.append(StreamKind::Stdout, b"x").expect("1");
            sink.append(StreamKind::Stdout, b"y").expect("2");
            let e = sink.append(StreamKind::Stdout, b"z").expect_err("limit");
            assert_eq!(e.code(), ErrorCode::ResourceExhausted);
            assert!(sink.flush().is_err());
            drop(sink);
            let text = read(Path::new(path.as_str()));
            assert_eq!(text.lines().count(), 2);
            // 開き直しても既存サイズから数えるため、上限に達していれば書けない。
            let sink = CriFileSink::open_with_limit(&path, 84).expect("reopen");
            let e = sink.append(StreamKind::Stdout, b"w").expect_err("full");
            assert_eq!(e.code(), ErrorCode::ResourceExhausted);
        }

        /// CRI-2・SUP-7・#4652: 上限到達で止まった CRI ログは、rename の後の `reopen` で新しいファイルへ再開する。
        /// 旧ファイルの内容は変わらず、残りは新しいファイルの大きさから数え直す（既存 42 バイトなら 84 - 42 = 42 で 1 行）。
        #[cfg(target_os = "linux")]
        #[test]
        fn cri2_4652_reopen_after_limit_resumes_on_new_file() {
            let t = Tmp::new("reopen-limit");
            let path = t.log("0.log");
            let rotated = t.0.join("0.log.1");
            let sink = CriFileSink::open_with_limit(&path, 84).expect("open");
            sink.append(StreamKind::Stdout, b"x").expect("1");
            sink.append(StreamKind::Stdout, b"y").expect("2");
            let e = sink.append(StreamKind::Stdout, b"z").expect_err("limit");
            assert_eq!(e.code(), ErrorCode::ResourceExhausted);
            let before = read(Path::new(path.as_str()));
            std::fs::rename(path.as_str(), &rotated).expect("rename");
            // 新ファイルに 42 バイトの既存内容がある場合（別の経路で先に作られた）も、残りはサイズから数える。
            std::fs::write(path.as_str(), vec![b'.'; 42]).expect("seed");
            reopen_now(&sink).expect("reopen");
            sink.append(StreamKind::Stdout, b"n")
                .expect("one line fits");
            let e = sink
                .append(StreamKind::Stdout, b"m")
                .expect_err("remaining is 42");
            assert_eq!(e.code(), ErrorCode::ResourceExhausted);
            drop(sink);
            assert_eq!(read(&rotated), before);
            let new = read(Path::new(path.as_str()));
            assert_eq!(new.len(), 84);
            assert!(new.ends_with(" stdout F n\n"), "{new}");
        }

        /// CRI-2・SUP-7・#4652: rename 済み（別 inode）で `Active` の `reopen` は旧ファイルのバッファを flush してから
        /// 新ファイルへ切り替える。切り替え後に旧ファイルへは書かず、旧ロックは外れる。
        #[cfg(target_os = "linux")]
        #[test]
        fn cri2_4652_reopen_after_rename_flushes_old_and_switches() {
            let t = Tmp::new("reopen-rename");
            let path = t.log("0.log");
            let rotated = t.0.join("0.log.1");
            let sink = CriFileSink::open(&path).expect("open");
            sink.append(StreamKind::Stdout, b"old").expect("append");
            std::fs::rename(path.as_str(), &rotated).expect("rename");
            reopen_now(&sink).expect("reopen");
            sink.append(StreamKind::Stderr, b"new").expect("append");
            sink.flush().expect("flush");
            let old_text = read(&rotated);
            let old: Vec<&str> = old_text.lines().collect();
            assert_eq!(old.len(), 1);
            assert!(old[0].ends_with(" stdout F old"), "{}", old[0]);
            let new = read(Path::new(path.as_str()));
            assert_eq!(new.lines().count(), 1);
            assert!(new.ends_with(" stderr F new\n"), "{new}");
            // 旧ファイルの flock は外れている（別の書き手が開ける）。
            drop(
                CriFileSink::open(
                    &ContainerLogPath::new(rotated.display().to_string()).expect("p"),
                )
                .expect("old lock released"),
            );
        }

        /// CRI-2・#4652: rename されていない（同じ inode）`reopen` も成功し、同じ writer のまま追記が続く
        /// （同一プロセスの別 open file description の flock と衝突しない）。残りはファイルの大きさから数え直す。
        #[cfg(target_os = "linux")]
        #[test]
        fn cri2_4652_reopen_same_inode_keeps_appending() {
            let t = Tmp::new("reopen-same");
            let path = t.log("0.log");
            let sink = CriFileSink::open_with_limit(&path, 84).expect("open");
            sink.append(StreamKind::Stdout, b"a").expect("append");
            reopen_now(&sink).expect("reopen same inode");
            sink.append(StreamKind::Stdout, b"b").expect("append");
            let e = sink.append(StreamKind::Stdout, b"c").expect_err("limit 84");
            assert_eq!(e.code(), ErrorCode::ResourceExhausted);
            drop(sink);
            let text = read(Path::new(path.as_str()));
            assert_eq!(text.lines().count(), 2);
            assert!(text.lines().next().expect("l").ends_with(" stdout F a"));
        }

        /// CRI-2・#4652: `Failed` からの再開は、同じ inode でも（失敗時に旧 writer が閉じられ旧ロックが外れているため）成功する。
        #[cfg(target_os = "linux")]
        #[test]
        fn cri2_4652_reopen_from_failed_same_inode_resumes() {
            let t = Tmp::new("reopen-failed");
            let path = t.log("0.log");
            let sink = CriFileSink::open_with_limit(&path, 42).expect("open");
            sink.append(StreamKind::Stdout, b"x").expect("1");
            assert!(sink.append(StreamKind::Stdout, b"y").is_err());
            assert!(sink.flush().is_err(), "failed state");
            reopen_now(&sink).expect("reopen");
            // 既存 42 バイトで上限 42: 残り 0 のため書けないが、失敗状態ではなく上限の判定に戻る。
            let e = sink.append(StreamKind::Stdout, b"z").expect_err("full");
            assert_eq!(e.code(), ErrorCode::ResourceExhausted);
            assert_eq!(read(Path::new(path.as_str())).lines().count(), 1);
        }

        /// SEC-1・CRI-2・#4652: 開き直せない（親が消えた・最終要素が symlink・別の書き手がロック）ときは状態を変えず `Err`。
        /// 親ディレクトリも新しいファイルも作らない。
        #[cfg(target_os = "linux")]
        #[test]
        fn cri2_4652_failed_reopen_changes_nothing_and_creates_nothing() {
            let t = Tmp::new("reopen-fail");
            let path = t.log("sub/0.log");
            let sink = CriFileSink::open(&path).expect("open");
            sink.append(StreamKind::Stdout, b"one").expect("append");
            let sub = t.0.join("sub");
            let moved = t.0.join("moved");
            std::fs::rename(&sub, &moved).expect("rename dir");
            let e = reopen_now(&sink).expect_err("parent gone");
            assert_eq!(e.code(), ErrorCode::FailedPrecondition);
            assert!(!sub.exists(), "the parent must not be recreated");
            // 旧 writer は生きている。
            sink.append(StreamKind::Stdout, b"two")
                .expect("still active");
            sink.flush().expect("flush");
            assert_eq!(read(&moved.join("0.log")).lines().count(), 2);

            // 最終要素が symlink に差し替えられた。
            std::fs::create_dir(&sub).expect("mkdir");
            std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o750)).expect("chmod");
            let target = t.0.join("target.txt");
            std::fs::write(&target, b"keep").expect("write");
            symlink(&target, sub.join("0.log")).expect("symlink");
            let e = reopen_now(&sink).expect_err("symlink");
            assert_eq!(e.code(), ErrorCode::FailedPrecondition);
            assert_eq!(read(&target), "keep");
            sink.append(StreamKind::Stdout, b"three")
                .expect("still active");

            // 別の書き手がロックしているファイル。
            std::fs::remove_file(sub.join("0.log")).expect("rm");
            let other = std::fs::OpenOptions::new()
                .append(true)
                .create(true)
                .open(sub.join("0.log"))
                .expect("create");
            other.lock().expect("lock");
            let e = reopen_now(&sink).expect_err("locked by another");
            assert_eq!(
                e.message(),
                "cri log file is already in use by another writer"
            );
            sink.append(StreamKind::Stdout, b"four")
                .expect("still active");
            drop(other);
        }

        /// CRI-2・SUP-7・#4652: `TeeLogSink::reopen` は CRI 側の失敗の記録を解除し、上限で止まった CRI ログだけが再開する。
        /// CRI ログを持たない sink を副にすると `Unimplemented`（記録は変えない）。
        #[cfg(target_os = "linux")]
        #[test]
        fn cri2_4652_tee_reopen_clears_cri_failure_flag() {
            let t = Tmp::new("tee-reopen");
            let path = t.log("0.log");
            let rotated = t.0.join("0.log.1");
            let primary = Arc::new(Recorder(Mutex::new(Vec::new()), false));
            let tee = TeeLogSink::new(
                primary.clone(),
                Arc::new(CriFileSink::open_with_limit(&path, 42).expect("open")),
            );
            tee.append(StreamKind::Stdout, b"x").expect("1");
            tee.append(StreamKind::Stdout, b"y")
                .expect("primary keeps going");
            assert_eq!(
                tee.failed_codes(),
                [None, Some(ErrorCode::ResourceExhausted)]
            );
            std::fs::rename(path.as_str(), &rotated).expect("rename");
            reopen_now(&tee).expect("reopen");
            assert_eq!(tee.failed_codes(), [None, None]);
            tee.append(StreamKind::Stdout, b"z").expect("resumed");
            tee.flush().expect("flush");
            assert!(read(Path::new(path.as_str())).ends_with(" stdout F z\n"));
            assert_eq!(primary.0.lock().expect("lock").len(), 3);

            let none = TeeLogSink::new(
                Arc::new(Recorder(Mutex::new(Vec::new()), false)),
                Arc::new(Recorder(Mutex::new(Vec::new()), false)),
            );
            let e = reopen_now(&none).expect_err("no cri file");
            assert_eq!(e.code(), ErrorCode::Unimplemented);
        }

        /// ディレクトリの中の名前（整列済み）。一時ファイルの残りと元のパスの有無を照合する。
        #[cfg(target_os = "linux")]
        fn names(dir: &Path) -> Vec<String> {
            let mut v: Vec<String> = std::fs::read_dir(dir)
                .expect("read_dir")
                .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
                .collect();
            v.sort();
            v
        }

        #[cfg(target_os = "linux")]
        fn in_secs(n: u64) -> Instant {
            Instant::now() + Duration::from_secs(n)
        }

        /// 試験の準備: パスを rename して旧ファイルを `0.log.1` に移した、CRI ログの sink。
        #[cfg(target_os = "linux")]
        fn rotated_sink(tag: &str) -> (Tmp, ContainerLogPath, PathBuf, CriFileSink) {
            let t = Tmp::new(tag);
            let path = t.log("0.log");
            let rotated = t.0.join("0.log.1");
            let sink = CriFileSink::open(&path).expect("open");
            std::fs::rename(path.as_str(), &rotated).expect("rename");
            (t, path, rotated, sink)
        }

        /// CRI-2・SEC-1・#4652（P0）: 作って検証・ロックした fd が、公開された名前のファイルそのもの（同じ dev / ino）で、
        /// 新しい writer の書き込みがそのパスに現れる（一時名・hard link を経由しないため名前は 1 つだけ）。
        #[cfg(target_os = "linux")]
        #[test]
        fn cri2_4652_published_file_is_the_verified_inode() {
            use std::os::unix::fs::MetadataExt as _;
            let (t, path, rotated, sink) = rotated_sink("reopen-ino");
            reopen_now(&sink).expect("reopen");
            assert_eq!(names(&t.0), ["0.log", "0.log.1"]);
            let at_path = std::fs::symlink_metadata(path.as_str()).expect("stat");
            let (dev, ino) = match &*sink.inner.lock().expect("lock") {
                Inner::Active { writer, .. } => {
                    let m = writer.get_ref().metadata().expect("fstat");
                    (m.dev(), m.ino())
                }
                Inner::Failed(_) => panic!("must be active"),
            };
            assert_eq!((dev, ino), (at_path.dev(), at_path.ino()));
            assert_eq!(at_path.nlink(), 1, "no temporary name or hard link");
            assert_eq!(at_path.mode() & 0o7777 & !0o640, 0, "mode within 0640");
            sink.append(StreamKind::Stdout, b"new").expect("append");
            sink.flush().expect("flush");
            assert!(read(Path::new(path.as_str())).ends_with(" stdout F new\n"));
            assert_eq!(read(&rotated), "");
        }

        /// CRI-2・SUP-7・#4652（D）: ファイルを作った後にロックが取れず失敗しても、元のパスにファイルが残らない
        /// （別の書き手が作ったファイルのロックを持つ場面を注入）。旧 writer は生きている。
        #[cfg(target_os = "linux")]
        #[test]
        fn cri2_4652_reopen_lock_failure_leaves_no_file() {
            let (t, _path, rotated, sink) = rotated_sink("reopen-lockfail");
            let holder: Arc<Mutex<Option<std::fs::File>>> = Arc::new(Mutex::new(None));
            let h = holder.clone();
            *sink.faults.after_create.lock().expect("lock") = Some(Box::new(move |target| {
                let f = std::fs::OpenOptions::new()
                    .append(true)
                    .open(target)
                    .expect("open created");
                f.lock().expect("lock created");
                *h.lock().expect("lock") = Some(f);
            }));
            let e = sink.reopen(in_secs(5), &allow).expect_err("lock fails");
            assert_eq!(e.code(), ErrorCode::FailedPrecondition);
            assert_eq!(
                e.message(),
                "cri log file is already in use by another writer"
            );
            assert_eq!(names(&t.0), ["0.log.1"]);
            sink.append(StreamKind::Stdout, b"still")
                .expect("old writer");
            sink.flush().expect("flush");
            assert_eq!(read(&rotated).lines().count(), 1);
        }

        /// CRI-2・SUP-7・#4652（D）: 作る直前に他者が公開先を作っていたら（`EEXIST`）、それを上書きせず既存のファイルとして
        /// 開き直す（既存の内容 42 バイトは上限の数え直しに入る）。
        #[cfg(target_os = "linux")]
        #[test]
        fn cri2_4652_reopen_uses_concurrently_created_target() {
            let t = Tmp::new("reopen-race");
            let path = t.log("0.log");
            let rotated = t.0.join("0.log.1");
            let sink = CriFileSink::open_with_limit(&path, 84).expect("open");
            std::fs::rename(path.as_str(), &rotated).expect("rename");
            let target = PathBuf::from(path.as_str());
            *sink.faults.before_create.lock().expect("lock") = Some(Box::new(move |p| {
                assert_eq!(p, target);
                std::fs::write(p, vec![b'.'; 42]).expect("seed");
            }));
            reopen_now(&sink).expect("reopen");
            assert_eq!(names(&t.0), ["0.log", "0.log.1"]);
            sink.append(StreamKind::Stdout, b"n").expect("one fits");
            let e = sink
                .append(StreamKind::Stdout, b"m")
                .expect_err("remaining is 42");
            assert_eq!(e.code(), ErrorCode::ResourceExhausted);
            drop(sink);
            let text = read(Path::new(path.as_str()));
            assert_eq!(text.len(), 84);
            assert!(text.starts_with(&".".repeat(42)), "{text}");
        }

        /// SEC-1・CRI-2・#4652: 公開先が別の inode へのハードリンク（リンク 2 本）なら、それへ書き込み先を移さず
        /// `FailedPrecondition` で拒否する。旧 writer は残り、リンク先の内容は変わらない。
        #[cfg(target_os = "linux")]
        #[test]
        fn sec1_4652_reopen_rejects_hard_linked_existing_file() {
            let (t, path, rotated, sink) = rotated_sink("reopen-hardlink");
            let outside = t.0.join("outside");
            std::fs::write(&outside, b"keep").expect("seed");
            std::fs::hard_link(&outside, path.as_str()).expect("link");
            let e = sink.reopen(in_secs(5), &allow).expect_err("hard link");
            assert_eq!(e.code(), ErrorCode::FailedPrecondition);
            assert_eq!(e.message(), "cri log file cannot be opened");
            sink.append(StreamKind::Stdout, b"still")
                .expect("old writer");
            sink.flush().expect("flush");
            assert_eq!(read(&rotated).lines().count(), 1);
            assert_eq!(read(&outside), "keep");
        }

        /// CRI-2・REPAIR-5・#4652: 別 inode への切り替えの成功は、旧 writer を `RetiredWriter` として返し、呼び出し元が
        /// drop するまで旧 fd（と flock）を閉じない（close(2) を応答の経路から外す）。drop の後は旧ファイルを開ける。
        #[cfg(target_os = "linux")]
        #[test]
        fn cri2_4652_retired_writer_keeps_old_fd_until_dropped() {
            let (_t, _path, rotated, sink) = rotated_sink("reopen-retired");
            let retired = sink.reopen(in_secs(5), &allow).expect("reopen");
            let old_path = ContainerLogPath::new(rotated.display().to_string()).expect("p");
            let Err(e) = CriFileSink::open(&old_path) else {
                panic!("old lock must still be held");
            };
            assert_eq!(e.code(), ErrorCode::FailedPrecondition);
            drop(retired);
            drop(CriFileSink::open(&old_path).expect("old lock released"));
        }

        /// CRI-2・SUP-7・#4652（C）: 確定点（関門）で稼働中でなくなっていたら（終了の割り込みを注入）、新しいファイルを
        /// 残さず、旧 writer を変えない。確定の関数は呼ばれない。
        #[cfg(target_os = "linux")]
        #[test]
        fn cri2_4652_reopen_refused_at_commit_leaves_no_file_and_does_not_switch() {
            let (t, _path, rotated, sink) = rotated_sink("reopen-exit");
            let running = Arc::new(std::sync::atomic::AtomicBool::new(true));
            let r = running.clone();
            *sink.faults.before_commit.lock().expect("lock") = Some(Box::new(move |_| {
                r.store(false, Ordering::SeqCst);
            }));
            let gate = |f: &mut dyn FnMut()| {
                if running.load(Ordering::SeqCst) {
                    f();
                    true
                } else {
                    false
                }
            };
            let e = sink
                .reopen(in_secs(5), &gate)
                .expect_err("exited in between");
            assert_eq!(e.code(), ErrorCode::FailedPrecondition);
            assert_eq!(e.message(), "cri log reopen is no longer permitted");
            assert_eq!(names(&t.0), ["0.log.1"]);
            sink.append(StreamKind::Stdout, b"old").expect("old writer");
            sink.flush().expect("flush");
            assert_eq!(read(&rotated).lines().count(), 1);
        }

        /// CRI-2・SEC-1・#4652（P0）: 確定を拒否されたときの後始末は、自分が作った inode のときだけ消す。名前が他者のファイルに
        /// 差し替わっていたら、それには触れない。
        #[cfg(target_os = "linux")]
        #[test]
        fn cri2_4652_cleanup_does_not_remove_someone_elses_file() {
            let (t, path, rotated, sink) = rotated_sink("reopen-foreign");
            let target = PathBuf::from(path.as_str());
            let running = Arc::new(std::sync::atomic::AtomicBool::new(true));
            let r = running.clone();
            *sink.faults.before_commit.lock().expect("lock") = Some(Box::new(move |p| {
                assert_eq!(p, target);
                r.store(false, Ordering::SeqCst);
                // 作った名前を退避し（inode 番号の再利用を避けるため消さない）、別の inode の他者のファイルへ差し替える。
                std::fs::rename(p, p.with_extension("ours")).expect("move ours");
                std::fs::write(p, b"theirs").expect("theirs");
            }));
            let gate = |f: &mut dyn FnMut()| {
                let ok = running.load(Ordering::SeqCst);
                if ok {
                    f();
                }
                ok
            };
            let e = sink.reopen(in_secs(5), &gate).expect_err("refused");
            assert_eq!(e.message(), "cri log reopen is no longer permitted");
            assert_eq!(names(&t.0), ["0.log", "0.log.1", "0.ours"]);
            assert_eq!(read(Path::new(path.as_str())), "theirs");
            sink.append(StreamKind::Stdout, b"old").expect("old writer");
            sink.flush().expect("flush");
            assert_eq!(read(&rotated).lines().count(), 1);
        }

        /// REPAIR-5・CRI-2・#4652（B）: 待ちうる処理の後の確定点で期限が切れていたら、何も差し替えず作ったファイルも残さない。
        #[cfg(target_os = "linux")]
        #[test]
        fn repair5_4652_deadline_expiring_before_commit_leaves_nothing() {
            let (t, _path, rotated, sink) = rotated_sink("reopen-late");
            *sink.faults.before_commit.lock().expect("lock") = Some(Box::new(|_| {
                std::thread::sleep(Duration::from_millis(300));
            }));
            let e = sink
                .reopen(Instant::now() + Duration::from_millis(150), &allow)
                .expect_err("deadline passes while waiting");
            assert_eq!(e.code(), ErrorCode::Timeout);
            assert_eq!(names(&t.0), ["0.log.1"]);
            sink.append(StreamKind::Stdout, b"old").expect("old writer");
            sink.flush().expect("flush");
            assert_eq!(read(&rotated).lines().count(), 1);
        }

        /// 既存ファイルへの切り替えでも、確定点で期限が切れていたら差し替えない（旧 writer のまま書ける）。
        #[cfg(target_os = "linux")]
        #[test]
        fn repair5_4652_deadline_expiring_before_commit_keeps_old_writer_for_existing() {
            let (t, path, rotated, sink) = rotated_sink("reopen-late-existing");
            std::fs::write(path.as_str(), b"").expect("seed");
            *sink.faults.before_commit.lock().expect("lock") = Some(Box::new(|_| {
                std::thread::sleep(Duration::from_millis(300));
            }));
            let e = sink
                .reopen(Instant::now() + Duration::from_millis(150), &allow)
                .expect_err("deadline passes while waiting");
            assert_eq!(e.code(), ErrorCode::Timeout);
            assert_eq!(names(&t.0), ["0.log", "0.log.1"]);
            sink.append(StreamKind::Stdout, b"old").expect("old writer");
            sink.flush().expect("flush");
            assert_eq!(read(&rotated).lines().count(), 1);
            assert_eq!(read(Path::new(path.as_str())), "");
        }

        /// REPAIR-5・CRI-2・#4652（B）: 期限を過ぎた要求は何も作らず何も差し替えない。書き込みがロックを持つ間は期限で
        /// 戻り（有限時間）、そのロックが空いた後も新しいファイルは作られない。
        #[cfg(target_os = "linux")]
        #[test]
        fn repair5_4652_reopen_after_deadline_creates_nothing_and_switches_nothing() {
            let (t, path, rotated, sink) = rotated_sink("reopen-deadline");
            let past = Instant::now() - Duration::from_millis(1);
            let e = sink.reopen(past, &allow).expect_err("expired");
            assert_eq!(e.code(), ErrorCode::Timeout);
            assert_eq!(names(&t.0), ["0.log.1"]);

            // 捕捉スレッドが `Mutex` を持って止まっている間: 期限で戻り、ファイルも残さない。
            let guard = sink.inner.lock().expect("lock");
            let started = Instant::now();
            let e = sink
                .reopen(Instant::now() + Duration::from_millis(100), &allow)
                .expect_err("lock wait is bounded");
            assert_eq!(e.code(), ErrorCode::Timeout);
            assert!(started.elapsed() < Duration::from_secs(3));
            drop(guard);
            assert_eq!(names(&t.0), ["0.log.1"]);
            // 既存のファイルがある場合も同じ（差し替えない）。
            std::fs::write(path.as_str(), b"").expect("seed");
            let guard = sink.inner.lock().expect("lock");
            let e = sink
                .reopen(Instant::now() + Duration::from_millis(100), &allow)
                .expect_err("lock wait is bounded");
            assert_eq!(e.code(), ErrorCode::Timeout);
            drop(guard);
            sink.append(StreamKind::Stdout, b"old").expect("old writer");
            sink.flush().expect("flush");
            assert_eq!(read(&rotated).lines().count(), 1);
            assert_eq!(read(Path::new(path.as_str())), "");
        }

        /// CRI-2・#4652（E）: 同じ inode の開き直しで旧 writer の flush が失敗したら成功にせず、上限の残りも変えない
        /// （BufWriter に残る未書き込み分を使用量から落として上限を超えさせない）。
        #[cfg(target_os = "linux")]
        #[test]
        fn cri2_4652_reopen_same_inode_flush_failure_keeps_budget() {
            let t = Tmp::new("reopen-flushfail");
            let path = t.log("0.log");
            let sink = CriFileSink::open_with_limit(&path, 84).expect("open");
            sink.append(StreamKind::Stdout, b"a").expect("append");
            let remaining = |s: &CriFileSink| match &*s.inner.lock().expect("lock") {
                Inner::Active { remaining, .. } => *remaining,
                Inner::Failed(_) => u64::MAX,
            };
            assert_eq!(remaining(&sink), 42);
            sink.faults.flush.store(true, Ordering::SeqCst);
            let e = sink.reopen(in_secs(5), &allow).expect_err("flush failed");
            assert_eq!(e.code(), ErrorCode::Internal);
            assert_eq!(e.message(), "cri log flush failed");
            assert_eq!(remaining(&sink), 42);
            // 未書き込みの分は writer に残っており、回復後の開き直しは成功し、上限を超えない。
            reopen_now(&sink).expect("recovered");
            sink.append(StreamKind::Stdout, b"b").expect("append");
            let e = sink.append(StreamKind::Stdout, b"c").expect_err("limit 84");
            assert_eq!(e.code(), ErrorCode::ResourceExhausted);
            drop(sink);
            assert_eq!(read(Path::new(path.as_str())).lines().count(), 2);
        }

        /// CRI-2・SUP-7・#4652（P1）: 別 inode への切り替えで旧 writer の flush が失敗したら、切り替えず `Err`。作ったファイルは
        /// 残さず、旧 writer と未書き込みの行を保持して、次の開き直しで 1 行も欠けず移る。
        #[cfg(target_os = "linux")]
        #[test]
        fn cri2_4652_old_writer_flush_failure_does_not_switch_and_keeps_bytes() {
            let (t, path, rotated, sink) = rotated_sink("reopen-oldflush");
            sink.append(StreamKind::Stdout, b"a").expect("buffered");
            sink.faults.flush.store(true, Ordering::SeqCst);
            let e = sink.reopen(in_secs(5), &allow).expect_err("flush failed");
            assert_eq!(e.message(), "cri log flush failed");
            assert_eq!(names(&t.0), ["0.log.1"], "the created file is removed");
            // 旧 writer は生きており、未書き込みの "a" を保持したまま追記が続く。
            sink.append(StreamKind::Stdout, b"b").expect("old writer");
            reopen_now(&sink).expect("retry succeeds");
            sink.append(StreamKind::Stdout, b"c").expect("new writer");
            sink.flush().expect("flush");
            let old = read(&rotated);
            let old: Vec<&str> = old.lines().collect();
            assert_eq!(old.len(), 2, "{old:?}");
            assert!(old[0].ends_with(" stdout F a") && old[1].ends_with(" stdout F b"));
            let new = read(Path::new(path.as_str()));
            assert_eq!(new.lines().count(), 1);
            assert!(new.ends_with(" stdout F c\n"), "{new}");
        }

        /// CRI-2・SUP-7・#4652（F）: 開き直しの直後の新しい writer への書き込みの失敗は、失敗状態として記録され
        /// 構造化ログ 1 行で通知される（取りこぼさない）。再通知はなく、開き直しで解除される。
        #[cfg(target_os = "linux")]
        #[test]
        fn cri2_4652_failure_on_new_writer_is_recorded_and_notified_once() {
            let t = Tmp::new("reopen-newfail");
            let path = t.log("0.log");
            let rotated = t.0.join("0.log.1");
            let primary = Arc::new(Recorder(Mutex::new(Vec::new()), false));
            let cri = Arc::new(CriFileSink::open(&path).expect("open"));
            let tee = TeeLogSink::new(primary, cri.clone());
            std::fs::rename(path.as_str(), &rotated).expect("rename");
            reopen_now(&tee).expect("reopen");
            cri.faults.write.store(true, Ordering::SeqCst);
            tee.append(StreamKind::Stdout, b"x")
                .expect("primary keeps going");
            assert_eq!(tee.failed_codes(), [None, Some(ErrorCode::Internal)]);
            tee.append(StreamKind::Stdout, b"y").expect("primary ok");
            assert_eq!(cri.notices.load(Ordering::SeqCst), 1);
            // 開き直しで解除され、再開する。次の失敗はもう 1 回だけ通知される。
            reopen_now(&tee).expect("reopen again");
            assert_eq!(tee.failed_codes(), [None, None]);
            tee.append(StreamKind::Stdout, b"z").expect("resumed");
            tee.flush().expect("flush");
            assert!(read(Path::new(path.as_str())).ends_with(" stdout F z\n"));
            cri.faults.write.store(true, Ordering::SeqCst);
            tee.append(StreamKind::Stdout, b"w").expect("primary ok");
            assert_eq!(cri.notices.load(Ordering::SeqCst), 2);
        }

        /// CRI-2・SUP-4: 同じファイルの 2 つ目の書き手は `FailedPrecondition` で拒否し（上限を書き手の数だけ増やさない）、
        /// 1 つ目を閉じた後は開ける。
        #[test]
        fn cri2_file_sink_rejects_second_writer() {
            let t = Tmp::new("lock");
            let path = t.log("0.log");
            let first = CriFileSink::open(&path).expect("open");
            let e = CriFileSink::open(&path).err().expect("second writer");
            assert_eq!(e.code(), ErrorCode::FailedPrecondition);
            assert_eq!(
                e.message(),
                "cri log file is already in use by another writer"
            );
            // 別のパスは影響を受けない。
            CriFileSink::open(&t.log("1.log")).expect("other path");
            drop(first);
            let again = CriFileSink::open(&path).expect("reopen after close");
            again.append(StreamKind::Stdout, b"ok").expect("append");
            again.flush().expect("flush");
            assert!(read(Path::new(path.as_str())).ends_with(" stdout F ok\n"));
        }

        /// CRI-2・SUP-4: 書いた行が CRI 形式でファイルに残り、開き直しても上書きせず追記する。
        #[test]
        fn cri2_file_sink_appends_and_reopens_without_truncation() {
            let t = Tmp::new("append");
            let path = t.log("0.log");
            let sink = CriFileSink::open(&path).expect("open");
            sink.append(StreamKind::Stdout, b"one").expect("append");
            sink.flush().expect("flush");
            drop(sink);
            let sink = CriFileSink::open(&path).expect("reopen");
            sink.append(StreamKind::Stderr, b"two").expect("append");
            sink.flush().expect("flush");
            let text = read(Path::new(path.as_str()));
            let lines: Vec<&str> = text.lines().collect();
            assert_eq!(lines.len(), 2);
            assert!(lines[0].ends_with(" stdout F one"), "{}", lines[0]);
            assert!(lines[1].ends_with(" stderr F two"), "{}", lines[1]);
            assert_eq!(lines[0].len(), CRI_TIMESTAMP_LEN + " stdout F one".len());
            let mode = std::fs::metadata(path.as_str())
                .expect("meta")
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o640 & !current_umask_bits());
        }

        /// 作成時の mode は umask で落ちるため、期待値側にも同じ umask を当てる（試験の環境差を吸収する）。
        fn current_umask_bits() -> u32 {
            let probe = std::env::temp_dir().join(format!("fc-umask-{}", std::process::id()));
            let _ = std::fs::remove_file(&probe);
            let f = std::fs::File::create(&probe).expect("create");
            let mode = f.metadata().expect("meta").permissions().mode() & 0o777;
            let _ = std::fs::remove_file(&probe);
            // File::create は 0o666 & !umask。
            0o666 & !mode
        }

        /// SEC-1: 最終要素の symlink・FIFO・ディレクトリを拒否し、symlink の先へ書かない。
        #[test]
        fn cri2_file_sink_rejects_symlink_fifo_and_dir() {
            let t = Tmp::new("final");
            let target = t.0.join("target.txt");
            std::fs::write(&target, b"keep").expect("write");
            symlink(&target, t.0.join("link.log")).expect("symlink");
            let e = CriFileSink::open(&t.log("link.log"))
                .err()
                .expect("symlink");
            assert_eq!(e.code(), ErrorCode::FailedPrecondition);
            assert_eq!(read(&target), "keep");

            let fifo = t.0.join("fifo.log");
            let status = std::process::Command::new("mkfifo")
                .arg(&fifo)
                .status()
                .expect("mkfifo");
            assert!(status.success());
            let e = CriFileSink::open(&t.log("fifo.log")).err().expect("fifo");
            assert_eq!(e.code(), ErrorCode::FailedPrecondition);

            std::fs::create_dir(t.0.join("dir.log")).expect("dir");
            let e = CriFileSink::open(&t.log("dir.log")).err().expect("dir");
            assert_eq!(e.code(), ErrorCode::FailedPrecondition);
        }

        /// SEC-1: 親ディレクトリが group 書き込み可・2 階層以上欠け・祖先に root 以外の symlink があれば拒否し、mkdir しない。
        #[test]
        fn cri2_file_sink_rejects_unsafe_parent() {
            let t = Tmp::new("parent");
            let open_dir = t.0.join("open");
            std::fs::create_dir(&open_dir).expect("dir");
            std::fs::set_permissions(&open_dir, std::fs::Permissions::from_mode(0o770))
                .expect("chmod");
            assert!(CriFileSink::open(&t.log("open/0.log")).is_err());

            // 2 階層以上欠けていれば作らない。
            assert!(CriFileSink::open(&t.log("missing/deeper/0.log")).is_err());
            assert!(!t.0.join("missing").exists());

            let real = t.0.join("real");
            std::fs::create_dir(&real).expect("dir");
            std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o750)).expect("chmod");
            symlink(&real, t.0.join("via")).expect("symlink");
            assert!(CriFileSink::open(&t.log("via/0.log")).is_err());
            assert!(!real.join("0.log").exists());
        }

        /// CRI-2・SUP-4: CRI 標準の `<containerName>/0.log` で親（containerName）が未作成でも、検査済みの祖先の直下に
        /// 1 階層だけ 0o750 で作って開ける。親が symlink なら作らず拒否する。
        #[test]
        fn cri2_file_sink_creates_missing_container_dir() {
            let t = Tmp::new("mkparent");
            let sink = CriFileSink::open(&t.log("web/0.log")).expect("open");
            sink.append(StreamKind::Stdout, b"hi").expect("append");
            sink.flush().expect("flush");
            assert!(read(&t.0.join("web/0.log")).ends_with(" stdout F hi\n"));
            let mode = std::fs::metadata(t.0.join("web"))
                .expect("meta")
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o750 & !current_umask_bits());

            let real = t.0.join("real");
            std::fs::create_dir(&real).expect("dir");
            std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o750)).expect("chmod");
            symlink(&real, t.0.join("sym")).expect("symlink");
            assert!(CriFileSink::open(&t.log("sym/0.log")).is_err());
            assert!(!real.join("0.log").exists());
        }

        /// 書き込み失敗後は失敗状態に固定され、以後の append は Err になる（重複を作らない）。
        #[test]
        fn cri2_file_sink_fails_closed_after_write_error() {
            let t = Tmp::new("fail");
            let sink = CriFileSink::open(&t.log("0.log")).expect("open");
            *sink.inner.lock().expect("lock") = Inner::Failed(ErrorCode::Internal);
            assert!(sink.append(StreamKind::Stdout, b"x").is_err());
            assert!(sink.flush().is_err());
            let lf = sink.append(StreamKind::Stdout, b"a\nb");
            assert_eq!(lf.expect_err("lf").code(), ErrorCode::InvalidArgument);
        }
    }
}
