//! pasta の版の表記の解釈（OS 非依存の純関数。NET-9・`rootless-network.md` 12.12）。
//!
//! `pasta --version` の出力は信頼できない子の出力として扱い、受ける形式を Debian / Ubuntu の
//! `0.0~git<YYYYMMDD>.<hex 7〜40>-<rev>` に限る。上流の tag 形式などは一次情報で確かめるまで受けない
//! （fail-closed）。比較は実在する暦日の日付だけで行う。`binary` の版の検証から呼ばれる。

use crate::error::{NetError, NetErrorCode};

/// 受ける最小の版の日付（12.12。`20260120`）。
pub const PASTA_MIN_VERSION_DATE: PastaVersionDate = PastaVersionDate(20_260_120);
/// `--version` の 1 行目の上限バイト数。
pub const PASTA_VERSION_LINE_MAX: usize = 128;

/// 子が非 0 終了またはシグナルで終わった。
pub const MSG_VERSION_EXIT: &str = "pasta --version exited unsuccessfully";
/// 出力を解釈できない（形式違い・上限超過・非 UTF-8 を含む）。
pub const MSG_VERSION_UNPARSABLE: &str = "pasta --version output could not be parsed";
/// 最小版より古い。
pub const MSG_VERSION_TOO_OLD: &str = "pasta version is older than the minimum supported version";

/// 版の日付（実在の暦日だけを表す。`YYYYMMDD`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct PastaVersionDate(u32);

impl PastaVersionDate {
    /// 実在の暦日なら作る（閏年を判定する。年は 1 以上）。
    pub fn new(year: u32, month: u32, day: u32) -> Option<Self> {
        if year == 0 || year > 9999 || !(1..=12).contains(&month) || day == 0 {
            return None;
        }
        let leap =
            (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400);
        let max = match month {
            1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
            4 | 6 | 9 | 11 => 30,
            _ if leap => 29,
            _ => 28,
        };
        (day <= max).then_some(Self(year * 10_000 + month * 100 + day))
    }

    /// `YYYYMMDD` の整数。
    pub fn as_yyyymmdd(self) -> u32 {
        self.0
    }
}

fn unparsable() -> NetError {
    NetError::new(NetErrorCode::FailedPrecondition, MSG_VERSION_UNPARSABLE)
}

/// 版の文字列（`pasta ` の後ろ）から日付を取り出す。形式は Debian / Ubuntu のものに限る。
fn parse_debian_version(v: &str) -> Result<PastaVersionDate, NetError> {
    let rest = v.strip_prefix("0.0~git").ok_or_else(unparsable)?;
    let (date, rest) = rest.split_at_checked(8).ok_or_else(unparsable)?;
    if !date.bytes().all(|b| b.is_ascii_digit()) {
        return Err(unparsable());
    }
    let rest = rest.strip_prefix('.').ok_or_else(unparsable)?;
    let hex_len = rest
        .bytes()
        .take_while(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        .count();
    if !(7..=40).contains(&hex_len) {
        return Err(unparsable());
    }
    let rev = rest
        .get(hex_len..)
        .and_then(|r| r.strip_prefix('-'))
        .ok_or_else(unparsable)?;
    let rev_ok = (1..=32).contains(&rev.len())
        && rev
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'.' | b'~'));
    if !rev_ok {
        return Err(unparsable());
    }
    let n = |r: std::ops::Range<usize>| date.get(r).and_then(|s| s.parse::<u32>().ok());
    let (y, m, d) = (
        n(0..4).ok_or_else(unparsable)?,
        n(4..6).ok_or_else(unparsable)?,
        n(6..8).ok_or_else(unparsable)?,
    );
    PastaVersionDate::new(y, m, d).ok_or_else(unparsable)
}

/// `pasta --version` の終了状態と stdout から版の日付を得る（NET-9・12.12）。
///
/// 1 行目は `pasta ` で始まる 128 バイト以下の ASCII 印字可能文字で、`pasta ` + 版の文字列にちょうど
/// 一致すること（CR・末尾空白・余分なトークンは拒否）。最小版未満は拒否する。エラーに子の出力を入れない。
pub fn parse_version_output(status_ok: bool, stdout: &[u8]) -> Result<PastaVersionDate, NetError> {
    if !status_ok {
        return Err(NetError::new(
            NetErrorCode::FailedPrecondition,
            MSG_VERSION_EXIT,
        ));
    }
    let text = std::str::from_utf8(stdout).map_err(|_| unparsable())?;
    let (line, _) = text.split_once('\n').ok_or_else(unparsable)?;
    if line.len() > PASTA_VERSION_LINE_MAX || !line.bytes().all(|b| (0x20..=0x7e).contains(&b)) {
        return Err(unparsable());
    }
    let v = line.strip_prefix("pasta ").ok_or_else(unparsable)?;
    let date = parse_debian_version(v)?;
    if date < PASTA_MIN_VERSION_DATE {
        return Err(NetError::new(
            NetErrorCode::FailedPrecondition,
            MSG_VERSION_TOO_OLD,
        ));
    }
    Ok(date)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn out(v: &str) -> Vec<u8> {
        format!("pasta {v}\nCopyright Red Hat\n").into_bytes()
    }

    /// NET-9: 受ける形式（境界ちょうど・hex 長・rev の表記・閏日）。
    #[test]
    fn net9_version_accepts_table() {
        let cases = [
            ("0.0~git20260120.386b5f5-1", 20260120),
            ("0.0~git20260121.386b5f5-1", 20260121),
            ("0.0~git20991231.386b5f5-1", 20991231),
            ("0.0~git20280229.386b5f5-1", 20280229),
            (
                "0.0~git20260301.0123456789abcdef0123456789abcdef01234567-1",
                20260301,
            ),
            ("0.0~git20260301.386b5f5-1ubuntu1", 20260301),
            ("0.0~git20260301.386b5f5-1+deb13u1", 20260301),
        ];
        for (v, want) in cases {
            let got = parse_version_output(true, &out(v)).unwrap();
            assert_eq!(got.as_yyyymmdd(), want, "{v}");
        }
    }

    /// NET-9・ERR-1: 拒否する表。code と固定文言を完全一致で照合する。
    #[test]
    fn net9_version_rejects_table() {
        let unp = MSG_VERSION_UNPARSABLE;
        let old = MSG_VERSION_TOO_OLD;
        let long = format!("pasta 0.0~git20260301.386b5f5-{}\n", "a".repeat(100));
        let rev33 = format!("pasta 0.0~git20260301.386b5f5-{}\n", "a".repeat(33));
        let hex41 = format!("0.0~git20260301.{}-1", "a".repeat(41));
        let cases: Vec<(bool, Vec<u8>, &str)> = vec![
            (true, out("0.0~git20260119.386b5f5-1"), old),
            (true, out("0.0~git20260229.386b5f5-1"), unp),
            (true, out("0.0~git20260230.386b5f5-1"), unp),
            (true, out("0.0~git00000000.386b5f5-1"), unp),
            (true, out("0.0~git20260301.386b5f-1"), unp),
            (true, out(&hex41), unp),
            (true, out("0.0~git20260301.386B5F5-1"), unp),
            (true, out("0.0~git20260301.386b5f5-"), unp),
            (true, rev33.into_bytes(), unp),
            (true, out("1:0.0~git20260301.386b5f5-1"), unp),
            (true, out("2026_03_01.386b5f5"), unp),
            (true, b"passt 0.0~git20260301.386b5f5-1\n".to_vec(), unp),
            (true, b"pasta  0.0~git20260301.386b5f5-1\n".to_vec(), unp),
            (true, b"pasta 0.0~git20260301.386b5f5-1\r\n".to_vec(), unp),
            (true, b"pasta 0.0~git20260301.386b5f5-1 \n".to_vec(), unp),
            (true, long.into_bytes(), unp),
            (true, b"pasta 0.0~git20260301.386b5f5-1".to_vec(), unp),
            (true, Vec::new(), unp),
            (true, b"pasta \xff\n".to_vec(), unp),
            (false, out("0.0~git20260301.386b5f5-1"), MSG_VERSION_EXIT),
        ];
        for (ok, bytes, msg) in cases {
            let e = parse_version_output(ok, &bytes).unwrap_err();
            assert_eq!(e.code(), NetErrorCode::FailedPrecondition);
            assert_eq!(e.message(), msg, "{:?}", String::from_utf8_lossy(&bytes));
        }
    }

    /// NET-9: 暦日の判定（平年・閏年・世紀の例外）。
    #[test]
    fn net9_version_date_calendar() {
        assert!(PastaVersionDate::new(2026, 2, 28).is_some());
        assert!(PastaVersionDate::new(2026, 2, 29).is_none());
        assert!(PastaVersionDate::new(2028, 2, 29).is_some());
        assert!(PastaVersionDate::new(2100, 2, 29).is_none());
        assert!(PastaVersionDate::new(2000, 2, 29).is_some());
        assert!(PastaVersionDate::new(2026, 4, 31).is_none());
        assert!(PastaVersionDate::new(2026, 13, 1).is_none());
        assert!(PastaVersionDate::new(2026, 1, 0).is_none());
        assert_eq!(PASTA_MIN_VERSION_DATE.as_yyyymmdd(), 20260120);
    }
}
