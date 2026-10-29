//! FCOPT1 の kind `pasta` の本文（作成時に検証した pasta の実体の記録）と、起動時の再検証（NET-9・PLUG-11・SEC-4・SUP-12）。
//!
//! `docs/design/rootless-network.md` 12.4 / 12.14 の実装（#3199）。cli が作成時に [`super::binary::verify_pasta_binary`] で
//! 解決・検証した [`PastaBinary`] から [`PastaRecord`] を作り、本文（[`PastaRecord::to_body`]）を起動オプション文書へ書く。
//! supervisor は文書を復号するたびに本文を未信頼の入力として [`PastaRecord::parse_body`] で形だけ検証し（副作用なし）、
//! 起動の直前に [`PastaRecord::reverify`] でバイナリを辿り直す。exec に使えるのは `reverify` が返す [`PastaBinary`] だけで、
//! 記録型からパスを直接取り出して実行する経路は作らない（confused deputy と差し替えの防止）。
//!
//! # 本文の形
//!
//! ```text
//! <YYYYMMDD> <dev> <ino> <size> <mtime_sec> <mtime_nsec> <ctime_sec> <ctime_nsec> <uid> <mode(8 進)>\n<絶対パス>
//! ```
//!
//! 数値は正準形（先頭 0 なし・`+` なし）だけを受け、秒の 2 項目だけ負を許す。パスは [`super::binary`] と同じ形の規則
//! （絶対・UTF-8・制御文字なし・`.` / `..` なし・3072 バイト以下）を課すため、改行はパスに現れず区切りが一意になる。
//! 本文全体は [`PASTA_RECORD_MAX_BYTES`] 以下。
//!
//! # 将来仕様・残余（REPAIR-3）
//!
//! - start 経路からの再検証の呼び出しは supervisor が #1940 で実装済み。SEC-4 の監査の記録のうち起動時の識別の不一致は #3330、作成時の `PermissionDenied` は D2 と両立しないため記録しない（#3330 でも対象外）。本モジュールは
//!   監査の記録先を持たず、呼び出し側が [`PastaRecord::reverify`] の失敗を分類して記録する。
//! - エラーは固定の英文だけで、パス・値・子の出力を含めない。

use std::path::{Path, PathBuf};

use crate::error::{NetError, NetErrorCode};

#[cfg(test)]
use super::binary::{MSG_PATH_INVALID, MSG_PATH_TOO_LONG};
use super::binary::{PastaBinary, PastaBinaryIdentity, check_shape, verify_gated};
use super::version::{PASTA_MIN_VERSION_DATE, PastaVersionDate};

/// 本文の最大バイト数（4 KiB。FCOPT1 の 1 レコードの上限）。
pub const PASTA_RECORD_MAX_BYTES: usize = 4096;

/// 本文の形が不正（項目数・数値・版）。
pub const MSG_RECORD_INVALID: &str = "pasta record is malformed";
/// 本文が上限を超える。
pub const MSG_RECORD_TOO_LONG: &str = "pasta record is too long";
/// 作成時から起動時の間に pasta が変わった（差し替えの疑い。SEC-4）。
pub const MSG_RECORD_CHANGED: &str = "pasta binary changed between create and start";

/// 項目数（版・dev・ino・size・mtime 2・ctime 2・uid・mode）。
const FIELD_COUNT: usize = 10;

fn err(code: NetErrorCode, msg: &'static str) -> NetError {
    NetError::new(code, msg)
}

fn invalid() -> NetError {
    err(NetErrorCode::InvalidArgument, MSG_RECORD_INVALID)
}

/// 作成時に検証した pasta の実体の記録（未信頼の入力から作った値を含む。実行の手段にはならない）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PastaRecord {
    path: PathBuf,
    dev: u64,
    ino: u64,
    size: u64,
    mtime: (i64, i64),
    ctime: (i64, i64),
    uid: u32,
    mode: u32,
    version: PastaVersionDate,
}

impl PastaBinary {
    /// 検証済みのバイナリから FCOPT1 へ書く記録を作る（実体の正規パス・識別・版の日付）。
    pub fn record(&self) -> PastaRecord {
        let id = self.identity();
        PastaRecord {
            path: self.path().to_path_buf(),
            dev: id.dev(),
            ino: id.ino(),
            size: id.size(),
            mtime: id.mtime(),
            ctime: id.ctime(),
            uid: id.uid(),
            mode: id.mode(),
            version: self.version(),
        }
    }
}

/// 正準形の符号なし 10 進（`0` 以外は先頭 0 不可。`max_digits` 桁以下）。
fn parse_u64(s: &str, max_digits: usize) -> Result<u64, NetError> {
    let ok = !s.is_empty()
        && s.len() <= max_digits
        && s.bytes().all(|b| b.is_ascii_digit())
        && (s == "0" || !s.starts_with('0'));
    if !ok {
        return Err(invalid());
    }
    s.parse::<u64>().map_err(|_| invalid())
}

/// 正準形の符号つき 10 進（`-0` 不可）。
fn parse_i64(s: &str) -> Result<i64, NetError> {
    match s.strip_prefix('-') {
        Some(rest) => {
            let v = parse_u64(rest, 19)?;
            if v == 0 {
                return Err(invalid());
            }
            0i64.checked_sub_unsigned(v).ok_or_else(invalid)
        }
        None => i64::try_from(parse_u64(s, 19)?).map_err(|_| invalid()),
    }
}

fn parse_nsec(s: &str) -> Result<i64, NetError> {
    let v = parse_u64(s, 9)?;
    if v > 999_999_999 {
        return Err(invalid());
    }
    i64::try_from(v).map_err(|_| invalid())
}

/// 8 進の正準形（先頭 0 なし）で `0o7777` 以内、setuid / setgid なし。
fn parse_mode(s: &str) -> Result<u32, NetError> {
    let ok = !s.is_empty()
        && s.len() <= 5
        && s.bytes().all(|b| (b'0'..=b'7').contains(&b))
        && (s == "0" || !s.starts_with('0'));
    if !ok {
        return Err(invalid());
    }
    let mode = u32::from_str_radix(s, 8).map_err(|_| invalid())?;
    if mode > 0o7777 || mode & 0o6000 != 0 {
        return Err(invalid());
    }
    Ok(mode)
}

impl PastaRecord {
    /// 本文へ符号化する。
    pub fn to_body(&self) -> String {
        format!(
            "{} {} {} {} {} {} {} {} {} {:o}\n{}",
            self.version.as_yyyymmdd(),
            self.dev,
            self.ino,
            self.size,
            self.mtime.0,
            self.mtime.1,
            self.ctime.0,
            self.ctime.1,
            self.uid,
            self.mode,
            self.path.display()
        )
    }

    /// 未信頼の本文から作る（形だけ検証する。副作用なし。バイナリの辿り直しは [`Self::reverify`]）。
    pub fn parse_body(body: &str) -> Result<Self, NetError> {
        if body.len() > PASTA_RECORD_MAX_BYTES {
            return Err(err(NetErrorCode::InvalidArgument, MSG_RECORD_TOO_LONG));
        }
        let (head, path) = body.split_once('\n').ok_or_else(invalid)?;
        let f: Vec<&str> = head.split(' ').collect();
        if f.len() != FIELD_COUNT {
            return Err(invalid());
        }
        let at = |i: usize| f.get(i).copied().ok_or_else(invalid);
        let date = u32::try_from(parse_u64(at(0)?, 8)?).map_err(|_| invalid())?;
        let version = PastaVersionDate::new(date / 10_000, date / 100 % 100, date % 100)
            .ok_or_else(invalid)?;
        if version < PASTA_MIN_VERSION_DATE {
            return Err(invalid());
        }
        let mode = parse_mode(at(9)?)?;
        let path = Path::new(path);
        check_shape(path)?;
        Ok(Self {
            path: path.to_path_buf(),
            dev: parse_u64(at(1)?, 20)?,
            ino: parse_u64(at(2)?, 20)?,
            size: parse_u64(at(3)?, 20)?,
            mtime: (parse_i64(at(4)?)?, parse_nsec(at(5)?)?),
            ctime: (parse_i64(at(6)?)?, parse_nsec(at(7)?)?),
            uid: u32::try_from(parse_u64(at(8)?, 10)?).map_err(|_| invalid())?,
            mode,
            version,
        })
    }

    /// 記録した実体の正規パス（表示・診断用。exec には [`Self::reverify`] の結果を使う）。
    pub fn recorded_path(&self) -> &Path {
        &self.path
    }

    /// バイナリを検証し直し、記録と一致することを確かめる（起動時。12.4）。
    ///
    /// 順序は、パスを辿って得た正規パスと識別（dev・ino・size・mtime・ctime・uid・mode）の照合、一致したときだけ
    /// `--version` の実行、最後に版を含む全項目の照合。識別が違えば子を実行せず固定の変更エラーで返す。
    /// 失敗は `FailedPrecondition`（一致しない）か、辿り直しの失敗（`NotFound`・`PermissionDenied` ほか）。
    /// 副作用は `--version` の子の実行だけ。Linux 以外は `Unimplemented`。
    pub fn reverify(&self) -> Result<PastaBinary, NetError> {
        let gate = |p: &Path, id: &PastaBinaryIdentity| self.check_identity(p, id);
        self.check(verify_gated(&self.path, None, &gate)?)
    }

    /// 試験専用: [`Self::reverify`] の `anchor` 版（`verify_pasta_binary_below` と同じ緩和）。
    #[cfg(any(test, feature = "pasta-test-support"))]
    pub fn reverify_below(&self, anchor: &Path) -> Result<PastaBinary, NetError> {
        let gate = |p: &Path, id: &PastaBinaryIdentity| self.check_identity(p, id);
        self.check(verify_gated(&self.path, Some(anchor), &gate)?)
    }

    /// 辿って得た正規パスと識別が記録と一致するか（`--version` の実行前の照合）。
    fn check_identity(&self, path: &Path, id: &PastaBinaryIdentity) -> Result<(), NetError> {
        let same = path == self.path
            && (id.dev(), id.ino(), id.size()) == (self.dev, self.ino, self.size)
            && id.mtime() == self.mtime
            && id.ctime() == self.ctime
            && (id.uid(), id.mode()) == (self.uid, self.mode);
        if !same {
            return Err(err(NetErrorCode::FailedPrecondition, MSG_RECORD_CHANGED));
        }
        Ok(())
    }

    /// 辿り直した結果の記録（正規パス・識別・版）が、保存した記録と全項目一致するか。
    fn check(&self, now: PastaBinary) -> Result<PastaBinary, NetError> {
        if now.record() != *self {
            return Err(err(NetErrorCode::FailedPrecondition, MSG_RECORD_CHANGED));
        }
        Ok(now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> PastaRecord {
        PastaRecord {
            path: PathBuf::from("/usr/bin/pasta"),
            dev: 2049,
            ino: 131_074,
            size: 1_234_567,
            mtime: (1_760_000_000, 123_456_789),
            ctime: (-5, 0),
            uid: 0,
            mode: 0o755,
            version: PastaVersionDate::new(2026, 1, 20).expect("date"),
        }
    }

    const BODY: &str =
        "20260120 2049 131074 1234567 1760000000 123456789 -5 0 0 755\n/usr/bin/pasta";

    /// NET-9: 本文の具体値と往復。
    #[test]
    fn net9_pasta_record_body_exact_and_round_trip() {
        assert_eq!(sample().to_body(), BODY);
        assert_eq!(PastaRecord::parse_body(BODY).expect("parse"), sample());
    }

    /// NET-9: 本文の拒否表。
    #[test]
    fn net9_pasta_record_body_rejections() {
        let ok = BODY;
        let long_path = format!("/{}", "a".repeat(3072));
        let invalid_path = MSG_PATH_INVALID;
        let cases: Vec<(String, &str)> = vec![
            (ok.replace("755\n", "755 1\n"), MSG_RECORD_INVALID),
            ("20260120 2049\n/a".to_owned(), MSG_RECORD_INVALID),
            (
                ok.replace("2049 131074", "2049  131074"),
                MSG_RECORD_INVALID,
            ),
            (ok.replace("2049", "02049"), MSG_RECORD_INVALID),
            (ok.replace("2049", "+2049"), MSG_RECORD_INVALID),
            (ok.replace(" -5 ", " -0 "), MSG_RECORD_INVALID),
            (ok.replace("123456789", "1000000000"), MSG_RECORD_INVALID),
            (
                ok.replace("2049", "99999999999999999999999"),
                MSG_RECORD_INVALID,
            ),
            (ok.replace(" 755\n", " 4755\n"), MSG_RECORD_INVALID),
            (ok.replace(" 755\n", " 2755\n"), MSG_RECORD_INVALID),
            (ok.replace(" 755\n", " 0755\n"), MSG_RECORD_INVALID),
            (ok.replace(" 755\n", " 17777\n"), MSG_RECORD_INVALID),
            (ok.replace("20260120", "20260230"), MSG_RECORD_INVALID),
            (ok.replace("20260120", "20250101"), MSG_RECORD_INVALID),
            (ok.replace("/usr/bin/pasta", "usr/bin/pasta"), invalid_path),
            (ok.replace("/usr/bin/pasta", "/usr/../pasta"), invalid_path),
            (
                ok.replace("/usr/bin/pasta", "/usr/\u{7}pasta"),
                invalid_path,
            ),
            (ok.replace("/usr/bin/pasta", "/a\n/b"), invalid_path),
            (format!("{ok}\n"), invalid_path),
            (ok.replace("/usr/bin/pasta", &long_path), MSG_PATH_TOO_LONG),
            (format!("{ok}{}", "a".repeat(4097)), MSG_RECORD_TOO_LONG),
            (
                "20260120 1 1 1 1 1 1 1 1 755".to_owned(),
                MSG_RECORD_INVALID,
            ),
        ];
        for (body, msg) in cases {
            let e = PastaRecord::parse_body(&body).expect_err(&body);
            assert_eq!(e.code(), NetErrorCode::InvalidArgument, "{body:?}");
            assert_eq!(e.message(), msg, "{body:?}");
        }
    }

    /// NET-9: 最大のパスと各項目の最大値でも 4 KiB に収まる。
    #[test]
    fn net9_pasta_record_max_body_fits() {
        let r = PastaRecord {
            path: PathBuf::from(format!("/{}", "a".repeat(3071))),
            dev: u64::MAX,
            ino: u64::MAX,
            size: u64::MAX,
            mtime: (i64::MIN, 999_999_999),
            ctime: (i64::MIN, 999_999_999),
            uid: u32::MAX,
            mode: 0o1777,
            version: PastaVersionDate::new(2026, 12, 31).expect("date"),
        };
        let body = r.to_body();
        assert!(body.len() <= PASTA_RECORD_MAX_BYTES, "{}", body.len());
        assert_eq!(PastaRecord::parse_body(&body).expect("parse"), r);
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn net9_pasta_record_reverify_is_unimplemented_off_linux() {
        let e = sample().reverify().expect_err("non-linux");
        assert_eq!(e.code(), NetErrorCode::Unimplemented);
    }
}
