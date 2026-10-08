//! コンテナ用子 cgroup の `io.bfq.weight`（BFQ スケジューラの比例配分の重み）の検証・書き込み・読み戻し
//! （SUP-13・CORE-4・TASK-170 追補・MS-9・#1534）。
//!
//! # 役割
//! `--blkio-weight` を `io.bfq.weight` があるときはそちらへ書くための部品。`io_weight` サブモジュールの
//! `ContainerCgroup::set_blkio_weight` からだけ呼ばれ、単独の公開 API は持たない。
//! 値は [`BfqWeight`]（検証済みの型）でしか表現できず、範囲外の値はカーネルへ渡らない。
//!
//! # カーネル・runc の挙動（一次情報: `block/bfq-cgroup.c`・`bfq-iosched.h`、runc の `fs2/io.go`）
//! - 値域は `1..=1000`（既定 100）で範囲外は `-ERANGE`。Docker の `--blkio-weight`（`10..=1000`）は
//!   この値域に収まるため、`io.weight` 向けのような線形変換はせずそのまま書く（runc と同じ）
//! - 書き込みは数値のみ（例 `500`）。新しいカーネルは `default N` も受け付けるが、古いカーネルの
//!   `write_u64` は数値しか受け付けないため、両方で通る形を使う
//! - 読み戻しは新しいカーネルが `default N` の後に `MAJ:MIN N` 行が続く形、古いカーネルが `N` 単独。
//!   解析は両方を受け付ける
//! - ファイルがあることは「bfq の blkcg policy が登録されている」ことしか意味せず、どのデバイスが
//!   実際に BFQ を使っているかまでは意味しない
//!
//! # 契約
//! - ファイルが無い（`ENOENT`）ときは `Ok(None)` を返し、`io.weight` へのフォールバックは呼び出し側が決める。
//!   `ENOENT` 以外の open 失敗（symlink の `ELOOP`・ディレクトリの `EISDIR`・権限不足等）はエラーで、
//!   呼び出し側もフォールバックしない（fail-closed）
//! - 書き込み先は保持している O_PATH ディレクトリ fd 起点の `openat`（`O_NOFOLLOW`）で、パスを再解決しない
//! - 書き込み後に上限付きで読み戻し、値が要求と一致しなければ `FailedPrecondition`。読み戻しで失敗しても
//!   巻き戻さない（`io_weight`・`io_max` と同じ契約）
//! - 読み戻した内容はカーネル応答（外部入力）として `unwrap` / 添字アクセスなしで解析する
//! - `unsafe` は持たない。待機を伴わないファイル I/O のみのためタイムアウトは設けない
//!
//! # 未実装（REPAIR-3）
//! - 保証するのは「値がファイルへ入ったこと」までで、配分に効くことは保証しない
//! - デバイス別の重み（`--blkio-weight-device` 相当の `MAJ:MIN N` の書き込み）

use std::fs::File;
use std::io::Write as _;
use std::os::fd::BorrowedFd;

use super::{CgroupError, CgroupStep, SMALL_FILE_LIMIT, cstring, io_error, read_iface, sys_error};
use crate::sys::{self, SysError};
use crate::traits::ErrorCode;

/// `io.bfq.weight` の下限（カーネルの `BFQ_MIN_WEIGHT`）。
pub const BFQ_WEIGHT_MIN: u16 = 1;
/// `io.bfq.weight` の上限（カーネルの `BFQ_MAX_WEIGHT`）。
pub const BFQ_WEIGHT_MAX: u16 = 1_000;

const FILE_NAME: &str = "io.bfq.weight";

/// 検証済みの `io.bfq.weight` 値。構築は検証付きコンストラクタのみ（不正値を表現できない）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BfqWeight {
    weight: u16,
}

impl BfqWeight {
    /// `1..=`[`BFQ_WEIGHT_MAX`] の重み。範囲外は `InvalidArgument`（カーネルへは渡さない）。
    pub fn new(weight: u16) -> Result<Self, CgroupError> {
        if !(BFQ_WEIGHT_MIN..=BFQ_WEIGHT_MAX).contains(&weight) {
            return Err(CgroupError::new(
                ErrorCode::InvalidArgument,
                CgroupStep::SetIoBfqWeight,
                format!(
                    "io.bfq.weight {weight} is out of range [{BFQ_WEIGHT_MIN}, {BFQ_WEIGHT_MAX}]"
                ),
            ));
        }
        Ok(Self { weight })
    }

    /// 重み。
    pub fn weight(&self) -> u16 {
        self.weight
    }

    /// カーネルへ書く形式（数値のみ。古いカーネルの `write_u64` と互換）。
    fn to_file_content(self) -> String {
        self.weight.to_string()
    }

    /// 読み戻した `io.bfq.weight`（カーネル応答）の解析。
    /// `N` 単独、または `default N` に `MAJ:MIN N` 行が続く形を受け付ける。それ以外は `FailedPrecondition`。
    fn parse(text: &str) -> Result<Self, CgroupError> {
        let bad = |why: &str| {
            CgroupError::precondition(
                CgroupStep::SetIoBfqWeight,
                format!(
                    "unexpected io.bfq.weight content ({why}): {:?}",
                    text.trim_end()
                ),
            )
        };
        let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
        let value_of = |s: &str| -> Result<Self, CgroupError> {
            if !digits(s) {
                return Err(bad("weight is not a decimal number"));
            }
            let n = s.parse::<u16>().map_err(|_| bad("weight too large"))?;
            Self::new(n).map_err(|e| bad(&e.message))
        };
        let mut found: Option<Self> = None;
        let mut bare = false;
        let mut lines = 0usize;
        for line in text.lines().filter(|l| !l.is_empty()) {
            lines += 1;
            let mut it = line.split(' ');
            let (key, value, extra) = (it.next(), it.next(), it.next());
            match (key, value, extra) {
                (Some(n), None, None) => {
                    bare = true;
                    found = Some(value_of(n)?);
                }
                (Some(key), Some(value), None) => {
                    if key == "default" {
                        if found.is_some() {
                            return Err(bad("duplicate default line"));
                        }
                        found = Some(value_of(value)?);
                    } else {
                        let is_dev = key
                            .split_once(':')
                            .is_some_and(|(maj, min)| digits(maj) && digits(min));
                        if !is_dev {
                            return Err(bad("unknown key"));
                        }
                        if !digits(value) {
                            return Err(bad("weight is not a decimal number"));
                        }
                    }
                }
                _ => return Err(bad("expected `<number>` or `<key> <number>` lines")),
            }
        }
        if bare && lines != 1 {
            return Err(bad("bare number mixed with other lines"));
        }
        found.ok_or_else(|| bad("missing default line"))
    }
}

/// `dir` 直下の `io.bfq.weight` へ書き、読み戻して要求値との一致を確認する（テスト可能な実体）。
///
/// ファイルが無い（`ENOENT`）ときは何も書かず `Ok(None)`。その他の失敗はすべてエラー。
pub(super) fn write_bfq_weight_at(
    dir: BorrowedFd<'_>,
    weight: &BfqWeight,
) -> Result<Option<BfqWeight>, CgroupError> {
    let step = CgroupStep::SetIoBfqWeight;
    let name = cstring(step, FILE_NAME)?;
    let wfd = match sys::open_write_at(dir, &name) {
        Ok(fd) => fd,
        Err(SysError::Os(errno)) if errno == sys::ENOENT => return Ok(None),
        Err(e) => return Err(sys_error(step, "open io.bfq.weight", e)),
    };
    File::from(wfd)
        .write_all(weight.to_file_content().as_bytes())
        .map_err(|e| io_error(step, "write io.bfq.weight", &e))?;
    let actual = BfqWeight::parse(&read_iface(step, dir, FILE_NAME, SMALL_FILE_LIMIT)?)?;
    if actual != *weight {
        return Err(CgroupError::precondition(
            step,
            format!(
                "io.bfq.weight read back as {:?}, expected {:?}",
                actual.to_file_content(),
                weight.to_file_content()
            ),
        ));
    }
    Ok(Some(actual))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SUP-13・#1534: 重みの境界値と書き込み形式の完全一致。
    #[test]
    fn sup13_issue1534_bfq_weight_bounds_and_serialize() {
        for bad in [0, 1001, u16::MAX] {
            let e = BfqWeight::new(bad).unwrap_err();
            assert_eq!(e.code, ErrorCode::InvalidArgument);
            assert_eq!(e.step, CgroupStep::SetIoBfqWeight);
        }
        assert_eq!(BfqWeight::new(1).unwrap().weight(), 1);
        assert_eq!(BfqWeight::new(1000).unwrap().weight(), 1000);
        assert_eq!(BfqWeight::new(500).unwrap().to_file_content(), "500");
    }

    /// SUP-13・#1534: 読み戻し内容の解析（正常系と異常系）。
    #[test]
    fn sup13_issue1534_bfq_weight_parse() {
        let w = |n| BfqWeight::new(n).unwrap();
        assert_eq!(BfqWeight::parse("500\n").unwrap(), w(500));
        assert_eq!(BfqWeight::parse("default 500\n").unwrap(), w(500));
        assert_eq!(BfqWeight::parse("default 500\n8:0 300\n").unwrap(), w(500));
        for bad in [
            "",
            "\n",
            "0",
            "1001",
            "default",
            "default 0",
            "default +5",
            "+5",
            "default 1\ndefault 2\n",
            "500\n8:0 300\n",
            "8:0 300\n",
            "x:0 1\ndefault 1\n",
            "garbage",
            "default 1 2",
        ] {
            let e = BfqWeight::parse(bad).unwrap_err();
            assert_eq!(e.code, ErrorCode::FailedPrecondition, "{bad:?}");
            assert_eq!(e.step, CgroupStep::SetIoBfqWeight, "{bad:?}");
        }
    }
}
