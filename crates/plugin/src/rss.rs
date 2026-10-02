//! OS 別の常駐メモリ（RSS）サンプラー（PLUG-8・PLUG-9。TASK-112.1・#265）。
//!
//! # 役割
//! TASK-112（core / plugin 常駐 RSS 比較の自動計測）が共通で使う「RSS をバイト単位で取得する部品」。
//! `tests/rss_comparison.rs` と後続の TASK-112.2（#266・2 条件比較）・TASK-112.3（#267・常駐 plugin の
//! 計測。実装済みの実機前提テスト）から呼ばれる計測専用の部品で、製品の制御経路・UDS 境界からは呼ばれない。
//!
//! # 契約
//! - 単位はバイト。瞬間値であり単調性は保証しない
//! - Linux は `/proc/<pid|self>/status` の `VmRSS`（kB）、macOS は `proc_pidinfo(PROC_PIDTASKINFO)` の
//!   `pti_resident_size`（`crate::sys`。macOS 固有処理は `cfg(target_os = "macos")` に局所化）
//! - 上記以外の OS（Windows を含む）は `Unimplemented`（fail-closed。偽の 0 を返して PLUG-8・PLUG-9 の
//!   判定を通さない。実装は将来の拡張点）
//! - 待機を伴わない（ローカルの `/proc` 読み取りと syscall 1 回）ためタイムアウトは持たない。
//!   `/proc` の読み取りには上限を設ける

use crate::error::{PluginError, PluginErrorCode};

/// 取得元（どの OS API から RSS を得たか）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RssSource {
    /// Linux の `/proc/<pid>/status` の `VmRSS` 行。
    ProcStatusVmRss,
    /// macOS の `proc_pidinfo(PROC_PIDTASKINFO)` の `pti_resident_size`。
    ProcPidTaskInfo,
}

/// RSS の 1 回分の計測結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct RssSample {
    bytes: u64,
    source: RssSource,
}

impl RssSample {
    /// 常駐メモリ量（バイト）。
    pub fn bytes(&self) -> u64 {
        self.bytes
    }

    /// 取得元。
    pub fn source(&self) -> RssSource {
        self.source
    }
}

/// 自プロセスの RSS を取得する。
pub fn current() -> Result<RssSample, PluginError> {
    #[cfg(target_os = "linux")]
    {
        linux::sample("self")
    }
    #[cfg(target_os = "macos")]
    {
        macos::sample(std::process::id())
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        Err(unsupported())
    }
}

/// 指定 pid のプロセスの RSS を取得する（TASK-112.3 が親から常駐 plugin を測る場合の入口）。
///
/// pid 0 と `i32` に収まらない pid は `InvalidArgument`、対象なしは `NotFound`、
/// 権限不足は `PermissionDenied`。
pub fn of_pid(pid: u32) -> Result<RssSample, PluginError> {
    if pid == 0 || i32::try_from(pid).is_err() {
        return Err(PluginError::new(
            PluginErrorCode::InvalidArgument,
            "pid is out of range",
        ));
    }
    #[cfg(target_os = "linux")]
    {
        linux::sample(&pid.to_string())
    }
    #[cfg(target_os = "macos")]
    {
        macos::sample(pid)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        Err(unsupported())
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn unsupported() -> PluginError {
    PluginError::new(
        PluginErrorCode::Unimplemented,
        "RSS sampling is not implemented on this OS",
    )
}

/// `std::io::Error` を構造化エラーへ写す（OS メッセージは含めない）。
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn map_io_error(e: &std::io::Error) -> PluginError {
    use std::io::ErrorKind;
    let (code, msg) = match e.kind() {
        ErrorKind::NotFound => (PluginErrorCode::NotFound, "process not found"),
        ErrorKind::PermissionDenied => (
            PluginErrorCode::PermissionDenied,
            "permission denied while sampling RSS",
        ),
        ErrorKind::InvalidInput => (PluginErrorCode::InvalidArgument, "invalid pid"),
        _ => match e.raw_os_error() {
            // ESRCH（macOS の proc_pidinfo は対象なしでこれを返す）
            Some(3) => (PluginErrorCode::NotFound, "process not found"),
            // EPERM
            Some(1) => (
                PluginErrorCode::PermissionDenied,
                "permission denied while sampling RSS",
            ),
            _ => (PluginErrorCode::Internal, "failed to sample RSS"),
        },
    };
    PluginError::new(code, msg)
}

#[cfg(target_os = "macos")]
mod macos {
    use super::{RssSample, RssSource, map_io_error};
    use crate::error::PluginError;

    pub(super) fn sample(pid: u32) -> Result<RssSample, PluginError> {
        let bytes = crate::sys::resident_size_bytes(pid).map_err(|e| map_io_error(&e))?;
        Ok(RssSample {
            bytes,
            source: RssSource::ProcPidTaskInfo,
        })
    }
}

/// `/proc/<id>/status` から読む Linux 実装（`unsafe` なし）。
#[cfg(target_os = "linux")]
mod linux {
    use super::{RssSample, RssSource, map_io_error};
    use crate::error::{PluginError, PluginErrorCode};

    /// `/proc/<id>/status` の読み取り上限（バイト）。通常は 1 KiB 前後。
    const STATUS_MAX_BYTES: u64 = 64 * 1024;

    pub(super) fn sample(id: &str) -> Result<RssSample, PluginError> {
        use std::io::Read;
        // `id` は "self" か u32 の 10 進表記のみ（呼び出し元で組み立てる）。外部文字列は連結しない。
        let path = std::path::Path::new("/proc").join(id).join("status");
        let file = std::fs::File::open(path).map_err(|e| map_io_error(&e))?;
        let mut buf = Vec::new();
        file.take(STATUS_MAX_BYTES + 1)
            .read_to_end(&mut buf)
            .map_err(|e| map_io_error(&e))?;
        if buf.len() as u64 > STATUS_MAX_BYTES {
            return Err(PluginError::new(
                PluginErrorCode::Internal,
                "status file exceeds the read limit",
            ));
        }
        let text = String::from_utf8_lossy(&buf);
        Ok(RssSample {
            bytes: parse_vm_rss_bytes(&text)?,
            source: RssSource::ProcStatusVmRss,
        })
    }

    /// `status` の内容から `VmRSS` をバイトで取り出す。カーネル応答は外部入力として検証する。
    pub(super) fn parse_vm_rss_bytes(text: &str) -> Result<u64, PluginError> {
        let bad = |msg: &'static str| PluginError::new(PluginErrorCode::Internal, msg);
        let line = text
            .lines()
            .find_map(|l| l.strip_prefix("VmRSS:"))
            .ok_or_else(|| bad("VmRSS line not found"))?;
        let mut it = line.split_whitespace();
        let value = it.next().ok_or_else(|| bad("VmRSS value is missing"))?;
        if it.next() != Some("kB") || it.next().is_some() {
            return Err(bad("VmRSS unit is not kB"));
        }
        let kb: u64 = value
            .parse()
            .map_err(|_| bad("VmRSS value is not a number"))?;
        kb.checked_mul(1024)
            .ok_or_else(|| bad("VmRSS value overflows"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    use super::linux::parse_vm_rss_bytes;

    /// PLUG-8: kB をバイトへ変換する。
    #[cfg(target_os = "linux")]
    #[test]
    fn plug8_parse_converts_kb_to_bytes() {
        let text = "Name:\tx\nVmRSS:\t    3456 kB\nThreads:\t1\n";
        assert_eq!(parse_vm_rss_bytes(text).unwrap(), 3_538_944);
    }

    /// PLUG-8: VmRSS 行なし（カーネルスレッド・zombie）は Internal。
    #[cfg(target_os = "linux")]
    #[test]
    fn plug8_parse_rejects_missing_line() {
        let e = parse_vm_rss_bytes("Name:\tx\nThreads:\t1\n").unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::Internal);
    }

    /// PLUG-8: 非数値・単位違い・桁あふれは Internal。
    #[cfg(target_os = "linux")]
    #[test]
    fn plug8_parse_rejects_malformed_values() {
        for text in [
            "VmRSS:\tabc kB\n",
            "VmRSS:\t12 MB\n",
            "VmRSS:\t12\n",
            "VmRSS:\t12 kB extra\n",
            "VmRSS:\t18446744073709551615 kB\n",
        ] {
            let e = parse_vm_rss_bytes(text).unwrap_err();
            assert_eq!(e.code(), PluginErrorCode::Internal, "{text:?}");
        }
    }

    /// PLUG-8: `VmRSSX:` のような前方一致の別キーを誤検出しない（`VmRSS:` は区切りまで一致させる）。
    #[cfg(target_os = "linux")]
    #[test]
    fn plug8_parse_does_not_match_longer_key() {
        let e = parse_vm_rss_bytes("VmRSSX:\t5 kB\n").unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::Internal);
    }

    /// PLUG-9: pid 0 と i32 に収まらない pid は InvalidArgument。
    #[test]
    fn plug9_of_pid_rejects_invalid_pid() {
        for pid in [0, u32::MAX] {
            assert_eq!(
                of_pid(pid).unwrap_err().code(),
                PluginErrorCode::InvalidArgument
            );
        }
    }
}
