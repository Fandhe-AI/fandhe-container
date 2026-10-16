//! `/proc/cmdline` の上限つき読み取り（MAC-1・無制限確保の防止）。
//!
//! 呼び出し元は `init`（Linux）。arm64 の `COMMAND_LINE_SIZE` は 2048 のため、4096 バイトを上限とする。

use std::io::Read;

use crate::report::Errno;

/// 読み取る cmdline の最大バイト数。
pub const MAX_CMDLINE_BYTES: u64 = 4096;

/// cmdline 読み取りの失敗。
#[derive(Debug)]
pub enum CmdlineError {
    /// 上限を超えた。
    TooLong,
    /// UTF-8 でない。
    NotUtf8,
    /// 読み取り自体の失敗。
    Io(std::io::Error),
}

impl CmdlineError {
    /// 診断行に載せる errno。
    pub fn errno(&self) -> Errno {
        match self {
            Self::TooLong => Errno::E2BIG,
            Self::NotUtf8 => Errno::EINVAL,
            Self::Io(e) => Errno::from_io(e),
        }
    }
}

/// `r` から最大 `max` バイトを読み、超過・非 UTF-8 を拒否する。
pub fn read_bounded<R: Read>(r: R, max: u64) -> Result<String, CmdlineError> {
    let mut buf = Vec::new();
    r.take(max.saturating_add(1))
        .read_to_end(&mut buf)
        .map_err(CmdlineError::Io)?;
    if u64::try_from(buf.len()).is_ok_and(|n| n <= max) {
        String::from_utf8(buf).map_err(|_| CmdlineError::NotUtf8)
    } else {
        Err(CmdlineError::TooLong)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac1_reads_up_to_limit() {
        let data = vec![b'a'; 4096];
        assert_eq!(
            read_bounded(&data[..], MAX_CMDLINE_BYTES).unwrap().len(),
            4096
        );
    }

    #[test]
    fn mac1_rejects_over_limit_with_e2big() {
        let data = vec![b'a'; 4097];
        let e = read_bounded(&data[..], MAX_CMDLINE_BYTES).unwrap_err();
        assert!(matches!(e, CmdlineError::TooLong));
        assert_eq!(e.errno().get(), 7);
    }

    #[test]
    fn mac1_rejects_non_utf8_with_einval() {
        let e = read_bounded(&[0xff, 0xfe][..], 16).unwrap_err();
        assert!(matches!(e, CmdlineError::NotUtf8));
        assert_eq!(e.errno().get(), 22);
    }
}
