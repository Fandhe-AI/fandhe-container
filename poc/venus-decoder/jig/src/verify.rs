//! 記録ファイル（FCVNSREC）を実ファイルに対して検証する入口（GPU-6・REPAIR-2・REPAIR-12・TASK-172.5 後続・#1885）。
//!
//! 役割: bin `venus-jig --verify-record <絶対パス>` の本体。`fandhe_container_plugin_macos::gpu::venus::replay` の
//! `read_recording_file`（通常ファイル確認・256 MiB 上限・`O_NOFOLLOW | O_NONBLOCK`）と `validate`（全レコードの
//! チェックサムまで走査）をそのまま呼び、結果コード・レコード数・全体バイト数だけを 1 行の JSON にする。
//! 呼び出し元は bin（3 OS。採取は Linux 限定だが検証は 2 段目の Apple Silicon Mac でも使う）と結合試験。
//! #725（人間担当）が実機で採った記録を「壊れていない」と確かめる用途で、既存の検査は迂回しない。
//!
//! 出力の契約: `result`（`ok` または `venus_replay.*` / `venus_verify.*` の固定語彙）・`records`（成功時のみ）・`bytes`
//! （読み込めたときのみ）の 3 項目だけ。パス・payload・`VenusReplayError::message()`（CRC 値や seqno を含む）は
//! 出さない。実機のワークロード由来のデータをログへ漏らさないため。
//!
//! 待ちの上限（REPAIR-5）: 読み込みと検証は補助スレッドで行い、[`READ_TIMEOUT`] で打ち切る。
//!
//! 残存リスク: フラグ値が未確認の OS（Windows 等）では `read_recording_file` が通常の open にフォールバックし、
//! 検査と open の間の差し替えは塞がらない（設計書 7 章と同じ）。CRC-32C は偶発的な破損の検出用で改ざん耐性は無い。

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Duration;

use fandhe_container_plugin_macos::gpu::venus::replay::{
    VenusReplayError, read_recording_file, validate,
};

/// 読み込みと検証の待ちの上限（REPAIR-5）。
pub const READ_TIMEOUT: Duration = Duration::from_secs(60);

/// モードを選ぶ引数。
pub const MODE_FLAG: &str = "--verify-record";

/// 検証結果。出力は固定語彙と整数だけ。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifyReport {
    pub result: &'static str,
    pub records: Option<usize>,
    pub bytes: Option<u64>,
}

fn opt<T: std::fmt::Display>(v: Option<T>) -> String {
    v.map_or_else(|| "null".to_string(), |x| x.to_string())
}

impl VerifyReport {
    /// stdout に出す 1 行（改行なし）。値は固定語彙と整数だけなのでエスケープは不要。
    pub fn to_json_line(&self) -> String {
        format!(
            "{{\"result\":\"{}\",\"records\":{},\"bytes\":{}}}",
            self.result,
            opt(self.records),
            opt(self.bytes)
        )
    }

    /// 成功は 0、検証失敗は 1。
    pub fn exit_code(&self) -> i32 {
        if self.result == "ok" { 0 } else { 1 }
    }

    fn failure(result: &'static str, bytes: Option<u64>) -> Self {
        Self {
            result,
            records: None,
            bytes,
        }
    }
}

/// 読み込み済みのバイト列に `validate` だけを行う。
pub fn verify_bytes(bytes: &[u8]) -> VerifyReport {
    let len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    match validate(bytes) {
        Ok(v) => VerifyReport {
            result: "ok",
            records: Some(v.records().len()),
            bytes: Some(len),
        },
        Err(e) => VerifyReport::failure(e.code(), Some(len)),
    }
}

/// 読み込み関数を差し込める本体。補助スレッドで読み込みと検証を行い `timeout` で待つ。
pub(crate) fn verify_with<F>(read: F, timeout: Duration) -> VerifyReport
where
    F: FnOnce() -> Result<Vec<u8>, VenusReplayError> + Send + 'static,
{
    let (tx, rx) = mpsc::channel();
    let spawned = std::thread::Builder::new()
        .name("venus-verify".to_string())
        .spawn(move || {
            let report = match read() {
                Ok(buf) => verify_bytes(&buf),
                Err(e) => VerifyReport::failure(e.code(), None),
            };
            let _ = tx.send(report);
        });
    if spawned.is_err() {
        return VerifyReport::failure("venus_verify.thread_spawn_failed", None);
    }
    rx.recv_timeout(timeout)
        .unwrap_or_else(|_| VerifyReport::failure("venus_verify.timeout", None))
}

/// 実ファイルを検証する。
pub fn verify_recording_file(path: &Path, timeout: Duration) -> VerifyReport {
    let path = path.to_path_buf();
    verify_with(move || read_recording_file(&path), timeout)
}

/// 引数エラー（終了コード 2。stderr に JSON 1 行）。message にパスは含めない。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifyArgError {
    pub code: &'static str,
    pub message: &'static str,
}

impl VerifyArgError {
    pub fn to_json_line(&self) -> String {
        format!(
            "{{\"code\":\"{}\",\"message\":\"{}\"}}",
            self.code, self.message
        )
    }

    pub fn exit_code(&self) -> i32 {
        2
    }
}

/// 先頭が `--verify-record` でなければ `None`（通常の起動へ進む）。
/// ちょうど `--verify-record <絶対パス>` の 2 引数だけを受ける。
pub fn parse_verify_args(args: &[OsString]) -> Option<Result<PathBuf, VerifyArgError>> {
    if args.first().map(OsString::as_os_str) != Some(OsStr::new(MODE_FLAG)) {
        return None;
    }
    let (Some(path), 2) = (args.get(1), args.len()) else {
        return Some(Err(VerifyArgError {
            code: "INVALID_ARGUMENT",
            message: "usage: --verify-record <absolute-path> (no other arguments)",
        }));
    };
    let path = PathBuf::from(path);
    if !path.is_absolute() {
        return Some(Err(VerifyArgError {
            code: "PATH_NOT_ABSOLUTE",
            message: "recording path must be absolute",
        }));
    }
    Some(Ok(path))
}

/// bin の入口。モード外なら `None`、モードなら出力して終了コードを返す。
pub fn run_verify_mode(args: &[OsString]) -> Option<i32> {
    match parse_verify_args(args)? {
        Ok(path) => {
            let report = verify_recording_file(&path, READ_TIMEOUT);
            println!("{}", report.to_json_line());
            Some(report.exit_code())
        }
        Err(e) => {
            eprintln!("{}", e.to_json_line());
            Some(e.exit_code())
        }
    }
}

#[cfg(test)]
mod tests;
