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
//! - 捕捉側は 1 行を [`super::MAX_LINE_BYTES`] で切り詰めて渡す。切り詰めで落ちた分は P 断片として残らない（既知の制限。REPAIR-3）。
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
//! - 自前のローテーションはしない（kubelet が rename して `ReopenContainerLog` を呼ぶ方式。未実装は後続 issue）。そのため CRI ログの
//!   総量に上限は無い（既知の制限）。

#[cfg(unix)]
use std::io::Write as _;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use fandhe_container_core::traits::{ErrorCode, TraitError};

use super::{LogSink, MAX_LINE_BYTES, StreamKind};

/// 1 レコードに載せる内容の最大バイト数（containerd の `max_container_log_line_size` の既定値）。
pub const CRI_LOG_CHUNK_BYTES: usize = 16 * 1024;

/// タイムスタンプ（`2016-10-06T00:17:09.669794202Z`）のバイト数。
pub const CRI_TIMESTAMP_LEN: usize = 30;

/// 書き込みバッファ（固定。`RotatingFileSink` と同じ 8 KiB）。
#[cfg(unix)]
const WRITE_BUFFER_BYTES: usize = 8 * 1024;

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
    let mut push = |tag: u8, chunk: &[u8]| {
        out.extend_from_slice(timestamp);
        out.push(b' ');
        out.extend_from_slice(stream.as_str().as_bytes());
        out.push(b' ');
        out.push(tag);
        out.push(b' ');
        out.extend_from_slice(chunk);
        out.push(b'\n');
    };
    if line.is_empty() {
        push(b'F', line);
        return;
    }
    let mut chunks = line.chunks(CRI_LOG_CHUNK_BYTES).peekable();
    while let Some(chunk) = chunks.next() {
        push(if chunks.peek().is_some() { b'P' } else { b'F' }, chunk);
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
}

enum Inner {
    #[cfg(unix)]
    Active(std::io::BufWriter<std::fs::File>),
    // 非 unix では `open` が常に失敗し、この状態を作る経路が無い。
    #[cfg_attr(not(unix), allow(dead_code))]
    Failed,
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

impl CriFileSink {
    /// `path`（cri が結合・検証した絶対パス）を追記で開く。親ディレクトリが安全でない・最終要素が symlink / 通常ファイル
    /// 以外のときは開かない。親ディレクトリが無ければ検査済みの祖先の直下に 1 階層だけ作る（`ensure_parent_dir`）。開けない場合は `FailedPrecondition`（launch の前の確定失敗）。
    #[cfg(unix)]
    pub fn open(
        path: &fandhe_container_core::traits::ContainerLogPath,
    ) -> Result<Self, TraitError> {
        use std::os::unix::fs::OpenOptionsExt as _;
        use std::path::Path;

        let unopenable = || {
            TraitError::new(
                ErrorCode::FailedPrecondition,
                "cri log file cannot be opened",
            )
        };
        let path = Path::new(path.as_str());
        let (Some(parent), Some(name)) = (path.parent(), path.file_name()) else {
            return Err(invalid("cri log path has no file name"));
        };
        let dir = ensure_parent_dir(parent, unopenable)?;
        let file = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .mode(0o640)
            .custom_flags(
                super::rotating::O_NOFOLLOW
                    | crate::container_options::env::O_NONBLOCK
                    | crate::container_options::env::O_NOCTTY,
            )
            .open(dir.join(name))
            .map_err(|_| unopenable())?;
        let is_file = file.metadata().map(|m| m.is_file()).unwrap_or(false);
        if !is_file {
            return Err(unopenable());
        }
        Ok(Self {
            inner: Mutex::new(Inner::Active(std::io::BufWriter::with_capacity(
                WRITE_BUFFER_BYTES,
                file,
            ))),
        })
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
        let mut guard = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        match &mut *guard {
            #[cfg(unix)]
            Inner::Active(writer) => {
                if writer.write_all(&records).is_err() {
                    *guard = Inner::Failed;
                    return Err(internal("cri log write failed"));
                }
                Ok(())
            }
            Inner::Failed => Err(internal("cri log sink is in failed state")),
        }
    }

    fn flush(&self) -> Result<(), TraitError> {
        let mut guard = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        match &mut *guard {
            #[cfg(unix)]
            Inner::Active(writer) => {
                if writer.flush().is_err() {
                    *guard = Inner::Failed;
                    return Err(internal("cri log write failed"));
                }
                Ok(())
            }
            Inner::Failed => Err(internal("cri log sink is in failed state")),
        }
    }
}

/// 2 つの [`LogSink`] の両方へ書く（`@container-logs` と CRI ログの二重書き。CRI-2・SUP-4・#2671）。
///
/// 出力先ごとに失敗状態を持つ。片方が失敗してもその出力先だけを以後呼ばず、正常な出力先への `append` / `flush` は
/// 続ける（呼び出し元の `LineSplitter` は最初の `Err` でストリームの以降を読み捨てるため、片方の失敗で
/// 既存の `@container-logs` の記録を止めない。SUP-4）。`Err` を返すのは両方が失敗した場合だけ。
/// 片方の失敗は黙って消さず、[`Self::failed_codes`] で出力先ごとの最初のエラーコードを観測できる。
pub struct TeeLogSink {
    primary: Arc<dyn LogSink>,
    secondary: Arc<dyn LogSink>,
    /// 出力先ごと（主・副）の最初のエラーコード。`Some` の出力先は以後呼ばない。
    failed: Mutex<[Option<ErrorCode>; 2]>,
}

impl TeeLogSink {
    /// 主（`@container-logs`）と副（CRI ログ）から作る。
    pub fn new(primary: Arc<dyn LogSink>, secondary: Arc<dyn LogSink>) -> Self {
        Self {
            primary,
            secondary,
            failed: Mutex::new([None, None]),
        }
    }

    /// 出力先ごと（主・副の順）の最初の失敗のエラーコード。失敗していなければ `None`。
    pub fn failed_codes(&self) -> [Option<ErrorCode>; 2] {
        *self.failed.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// 失敗していない出力先へ `op` を適用する。両方が（以前から、または今回）失敗したときだけ `Err`。
    fn each(&self, op: impl Fn(&dyn LogSink) -> Result<(), TraitError>) -> Result<(), TraitError> {
        let sinks = [&self.primary, &self.secondary];
        let mut last_err = None;
        let mut alive = 0usize;
        for (i, sink) in sinks.into_iter().enumerate() {
            let already = self
                .failed
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .get(i)
                .copied()
                .flatten();
            if let Some(code) = already {
                last_err = Some(TraitError::new(code, "log destination is in failed state"));
                continue;
            }
            match op(sink.as_ref()) {
                Ok(()) => alive += 1,
                Err(e) => {
                    let mut g = self.failed.lock().unwrap_or_else(PoisonError::into_inner);
                    if let Some(slot) = g.get_mut(i) {
                        slot.get_or_insert(e.code());
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

impl LogSink for TeeLogSink {
    fn append(&self, stream: StreamKind, line: &[u8]) -> Result<(), TraitError> {
        self.each(|s| s.append(stream, line))
    }

    fn flush(&self) -> Result<(), TraitError> {
        self.each(|s| s.flush())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[cfg(unix)]
    mod file {
        use super::*;
        use fandhe_container_core::traits::ContainerLogPath;
        use std::os::unix::fs::{PermissionsExt as _, symlink};
        use std::path::{Path, PathBuf};
        use std::sync::atomic::{AtomicUsize, Ordering};

        struct Tmp(PathBuf);

        impl Tmp {
            fn new(tag: &str) -> Self {
                static SEQ: AtomicUsize = AtomicUsize::new(0);
                let n = SEQ.fetch_add(1, Ordering::SeqCst);
                let p = std::env::temp_dir()
                    .join(format!("fc-crilog-{tag}-{}-{n}", std::process::id()));
                std::fs::create_dir_all(&p).expect("mkdir");
                std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o750))
                    .expect("chmod");
                // 一時ディレクトリ自体が symlink 経由（macOS の /var 等）でも root 所有なら許される。
                Self(std::fs::canonicalize(&p).expect("canon"))
            }

            fn log(&self, rel: &str) -> ContainerLogPath {
                ContainerLogPath::new(format!("{}/{rel}", self.0.display())).expect("log path")
            }
        }

        impl Drop for Tmp {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }

        fn read(p: &Path) -> String {
            std::fs::read_to_string(p).expect("read")
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
            *sink.inner.lock().expect("lock") = Inner::Failed;
            assert!(sink.append(StreamKind::Stdout, b"x").is_err());
            assert!(sink.flush().is_err());
            let lf = sink.append(StreamKind::Stdout, b"a\nb");
            assert_eq!(lf.expect_err("lf").code(), ErrorCode::InvalidArgument);
        }
    }
}
