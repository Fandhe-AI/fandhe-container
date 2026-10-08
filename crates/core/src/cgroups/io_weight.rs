//! コンテナ用子 cgroup の `io.weight`（I/O の比例配分の重み）の検証・書き込み・読み戻しと、
//! Docker 流 `--blkio-weight` からの変換（SUP-13・CORE-4・TASK-170.4・MS-9・#1474）。
//!
//! # 役割
//! 親モジュール [`super`] が作った [`ContainerCgroup`] に対し、`io.weight` へ `default <N>` を書く。
//! 値は [`IoWeight`]（検証済みの型）でしか表現できないため、範囲外の値はカーネルへ渡らない。
//! 絶対値スロットルの `io.max`（`io_max` サブモジュール）とは別ファイルで、併存できる。
//!
//! # 呼び出し文脈・契約
//! - 呼び出し元: 起動フロー（`--blkio-weight` の受け付けと launcher への結線は TASK-29 / TASK-157 系の担当）。
//!   本モジュールは単体の API で、起動フローからはまだ呼ばれない
//! - 前提: 親 cgroup の `cgroup.subtree_control` で `io` controller が有効化済み
//!   （[`super::DelegatedCgroup::enable_controllers`]）。未委譲なら有効化の時点で拒否される
//! - `io.weight` が存在しない（`io` が未有効、またはカーネルが提供しない）場合は `FailedPrecondition`
//!   （[`CgroupStep::SetIoWeight`]）で、成功扱いにしない
//! - 書き込み先は保持している O_PATH ディレクトリ fd 起点の `openat`（`O_NOFOLLOW`）で、
//!   パス文字列から cgroup を再解決しない（TOCTOU・symlink 対策）
//! - 書き込み後に上限付きで読み戻し、`default` 行が要求値と一致しなければ `FailedPrecondition`（fail-closed）
//! - 書き込みが成功した後に読み戻し（解析・一致確認）で失敗しても巻き戻さず、書いた値はカーネルに残る
//!   （子 cgroup は空で、呼び出し側が `remove_child` で削除する前提。`io_max` サブモジュールと同じ契約）
//! - 読み戻した内容はカーネル応答（外部入力）として `unwrap` / 添字アクセスなしで解析する
//! - `unsafe` は持たない。待機を伴わないファイル I/O のみのためタイムアウトは設けない
//!
//! # `--blkio-weight` の写像
//! [`IoWeight::from_blkio_weight`]: `10..=1000` を `1..=10000` へ写す線形写像（整数除算・切り捨て）
//! `io.weight = 1 + (blkio_weight - 10) * 9999 / 990`。範囲外（`0` を含む）は `InvalidArgument`。
//! Docker 流の「`0` = 未指定」の解釈は呼び出し側の責務で、本モジュールは曖昧な値を黙って既定値にしない。
//! 線形写像の性質上、Docker 既定相当の 500 は 4950 へ写り cgroup v2 の既定 100 とは一致しない
//! （未指定時は書き込まず既定 100 を保つ運用とする）。
//!
//! # `--blkio-weight` の書き込み先（#1534）
//! [`ContainerCgroup::set_blkio_weight`] は runc（`fs2/io.go`）互換で書き込み先を 1 つに決める。
//! `io.bfq.weight` があれば変換せずそこへだけ書き（BFQ の値域 `1..=1000` に Docker 値が収まる）、
//! `ENOENT` のときだけ上の写像で `io.weight` へ書く。`ENOENT` 以外の open 失敗はフォールバックせず
//! エラーにする（fail-closed）。実際の書き込み先は [`BlkioWeightTarget`] で返し、呼び出し側が
//! 利用者へ示せる。`io.bfq.weight` の詳細は `io_bfq_weight` サブモジュールを参照。
//!
//! 設計判断: 両方のファイルへ書く案は、失敗面が倍になりどちらが効いているか示せず、runc / crun の
//! 挙動からも外れるため採らない。`io.bfq.weight` があっても BFQ が使われているとは限らず、
//! 配分に効くことは保証しない。
//!
//! # 未実装（REPAIR-3）
//! - `io.weight` は I/O コスト制御が提供するファイルで、`io` を有効化してもカーネル構成によっては存在しない。
//!   重みが実効を持つのは対象デバイスで比例配分が有効な場合に限られ、本 API は「値がファイルへ入ったこと」
//!   までを保証する（配分の実効は保証しない）
//! - デバイス別重み（`--blkio-weight-device` 相当）
//! - OCI `linux.resources.blockIO.weight` からの反映と launcher への結線（TASK-29 / TASK-157 系）

use std::fs::File;
use std::io::Write as _;
use std::os::fd::{AsFd as _, BorrowedFd};

use super::io_bfq_weight::{BfqWeight, write_bfq_weight_at};
use super::{
    CgroupError, CgroupStep, ContainerCgroup, SMALL_FILE_LIMIT, cstring, io_error, read_iface,
    sys_error,
};
use crate::observability::{OpName, OpRecorder};
use crate::sys::{self, SysError};
use crate::traits::ErrorCode;

/// `io.weight` の下限。
pub const IO_WEIGHT_MIN: u16 = 1;
/// `io.weight` の上限。
pub const IO_WEIGHT_MAX: u16 = 10_000;
/// cgroup v2 の `io.weight` 既定値。
pub const IO_WEIGHT_DEFAULT: u16 = 100;
/// Docker `--blkio-weight` の下限。
pub const BLKIO_WEIGHT_MIN: u16 = 10;
/// Docker `--blkio-weight` の上限。
pub const BLKIO_WEIGHT_MAX: u16 = 1_000;

/// 検証済みの `io.weight` 値。構築は検証付きコンストラクタのみ（不正値を表現できない）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IoWeight {
    weight: u16,
}

impl Default for IoWeight {
    fn default() -> Self {
        Self {
            weight: IO_WEIGHT_DEFAULT,
        }
    }
}

fn invalid(message: String) -> CgroupError {
    CgroupError::new(ErrorCode::InvalidArgument, CgroupStep::SetIoWeight, message)
}

/// 検証済みの Docker 流 `--blkio-weight` 値（`10..=1000`）。
/// 書き込み先（`io.bfq.weight` か `io.weight`）の選択は [`ContainerCgroup::set_blkio_weight`] が行う。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlkioWeight {
    weight: u16,
}

impl BlkioWeight {
    /// `10..=1000` の値。範囲外（`0` を含む）は `InvalidArgument`。
    pub fn new(weight: u16) -> Result<Self, CgroupError> {
        if !(BLKIO_WEIGHT_MIN..=BLKIO_WEIGHT_MAX).contains(&weight) {
            return Err(invalid(format!(
                "blkio weight {weight} is out of range [{BLKIO_WEIGHT_MIN}, {BLKIO_WEIGHT_MAX}]"
            )));
        }
        Ok(Self { weight })
    }

    /// 重み。
    pub fn weight(&self) -> u16 {
        self.weight
    }
}

/// [`ContainerCgroup::set_blkio_weight`] が実際に書いた先と、読み戻して確かめた値。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum BlkioWeightTarget {
    /// `io.bfq.weight` へ無変換で書いた。
    Bfq(BfqWeight),
    /// `io.bfq.weight` が無く、変換して `io.weight` へ書いた。
    IoWeight(IoWeight),
}

impl IoWeight {
    /// `1..=`[`IO_WEIGHT_MAX`] の重み。範囲外は `InvalidArgument`（カーネルへは渡さない）。
    pub fn new(weight: u16) -> Result<Self, CgroupError> {
        if !(IO_WEIGHT_MIN..=IO_WEIGHT_MAX).contains(&weight) {
            return Err(invalid(format!(
                "io.weight {weight} is out of range [{IO_WEIGHT_MIN}, {IO_WEIGHT_MAX}]"
            )));
        }
        Ok(Self { weight })
    }

    /// `--blkio-weight`（`10..=1000`）から `io.weight` への線形変換。範囲外は `InvalidArgument`。
    pub fn from_blkio_weight(weight: u16) -> Result<Self, CgroupError> {
        Self::from_blkio(BlkioWeight::new(weight)?)
    }

    /// 検証済みの [`BlkioWeight`] から `io.weight` への線形変換。
    pub fn from_blkio(blkio: BlkioWeight) -> Result<Self, CgroupError> {
        let weight = blkio.weight();
        let span_in = u32::from(BLKIO_WEIGHT_MAX - BLKIO_WEIGHT_MIN);
        let span_out = u32::from(IO_WEIGHT_MAX - IO_WEIGHT_MIN);
        let offset = u32::from(weight - BLKIO_WEIGHT_MIN);
        let mapped = offset
            .checked_mul(span_out)
            .and_then(|v| v.checked_div(span_in))
            .and_then(|v| v.checked_add(u32::from(IO_WEIGHT_MIN)))
            .and_then(|v| u16::try_from(v).ok())
            .ok_or_else(|| invalid(format!("blkio weight {weight} could not be converted")))?;
        Self::new(mapped)
    }

    /// 重み。
    pub fn weight(&self) -> u16 {
        self.weight
    }

    /// カーネルへ書く形式（`default <N>`）。
    fn to_file_content(self) -> String {
        format!("default {}", self.weight)
    }

    /// 読み戻した `io.weight`（カーネル応答）の解析。`default` 行を取り出す。
    /// デバイス別の `MAJ:MIN <N>` 行は読み飛ばし、形式不正・範囲外は `FailedPrecondition`。
    fn parse(text: &str) -> Result<Self, CgroupError> {
        let bad = |why: &str| {
            CgroupError::precondition(
                CgroupStep::SetIoWeight,
                format!(
                    "unexpected io.weight content ({why}): {:?}",
                    text.trim_end()
                ),
            )
        };
        let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
        let mut found: Option<Self> = None;
        for line in text.lines().filter(|l| !l.is_empty()) {
            let mut it = line.split(' ');
            let (key, value, extra) = (it.next(), it.next(), it.next());
            let (Some(key), Some(value), None) = (key, value, extra) else {
                return Err(bad("expected `<key> <number>` lines"));
            };
            if !digits(value) {
                return Err(bad("weight is not a decimal number"));
            }
            if key == "default" {
                if found.is_some() {
                    return Err(bad("duplicate default line"));
                }
                let n = value.parse::<u16>().map_err(|_| bad("weight too large"))?;
                found = Some(Self::new(n).map_err(|e| bad(&e.message))?);
            } else {
                let is_dev = key
                    .split_once(':')
                    .is_some_and(|(maj, min)| digits(maj) && digits(min));
                if !is_dev {
                    return Err(bad("unknown key"));
                }
            }
        }
        found.ok_or_else(|| bad("missing default line"))
    }
}

impl ContainerCgroup {
    /// 子 cgroup の `io.weight` を書き込み、読み戻して検証した値を返す（SUP-13・TASK-170.4）。
    ///
    /// `io` controller が親で有効化されていない、またはカーネルが `io.weight` を提供しない場合は
    /// `FailedPrecondition`。
    ///
    /// open・write・読み戻しのどこで失敗しても、成功・失敗の件数と所要時間を `recorder` へ
    /// 操作名 `cgroup.set_io_weight` で記録する（REPAIR-4。全終了経路）。
    pub fn set_io_weight(
        &self,
        recorder: &OpRecorder,
        weight: &IoWeight,
    ) -> Result<IoWeight, CgroupError> {
        write_io_weight_recorded(self.fd.as_fd(), recorder, weight)
    }

    /// `--blkio-weight` を書く（SUP-13・CORE-4・#1534）。runc 互換で書き込み先を 1 つに決める。
    ///
    /// - `io.bfq.weight` がある: 変換せずそこへだけ書く
    /// - `io.bfq.weight` が無い（`ENOENT`）: 変換して `io.weight` へ書く
    /// - `io.bfq.weight` の open が `ENOENT` 以外で失敗: エラー（`io.weight` へフォールバックしない）
    ///
    /// 保証するのは値がファイルへ入ったことまでで、配分に効くことは保証しない。
    /// 操作名 `cgroup.set_blkio_weight` で全終了経路を記録する（REPAIR-4）。
    pub fn set_blkio_weight(
        &self,
        recorder: &OpRecorder,
        weight: &BlkioWeight,
    ) -> Result<BlkioWeightTarget, CgroupError> {
        let name = OpName::new(SET_BLKIO_WEIGHT_OP_NAME).map_err(|e| CgroupError {
            code: e.code(),
            step: CgroupStep::SetIoWeight,
            message: e.message().to_string(),
        })?;
        let dir = self.fd.as_fd();
        recorder.record_op(&name, || write_blkio_weight_at(dir, weight))
    }
}

/// [`OpRecorder`] に記録する操作名（REPAIR-4）。
const SET_BLKIO_WEIGHT_OP_NAME: &str = "cgroup.set_blkio_weight";

/// 書き込み先の振り分けの実体（テスト可能）。フォールバック先は記録なしの内側関数を直接呼ぶ。
fn write_blkio_weight_at(
    dir: BorrowedFd<'_>,
    weight: &BlkioWeight,
) -> Result<BlkioWeightTarget, CgroupError> {
    let bfq = BfqWeight::new(weight.weight())?;
    if let Some(actual) = write_bfq_weight_at(dir, &bfq)? {
        return Ok(BlkioWeightTarget::Bfq(actual));
    }
    let converted = IoWeight::from_blkio(*weight)?;
    write_io_weight_at(dir, &converted).map(BlkioWeightTarget::IoWeight)
}

/// [`OpRecorder`] に記録する操作名（REPAIR-4）。
const SET_IO_WEIGHT_OP_NAME: &str = "cgroup.set_io_weight";

/// [`write_io_weight_at`] を計測つきで実行する（テスト可能な実体）。
fn write_io_weight_recorded(
    dir: BorrowedFd<'_>,
    recorder: &OpRecorder,
    weight: &IoWeight,
) -> Result<IoWeight, CgroupError> {
    let name = OpName::new(SET_IO_WEIGHT_OP_NAME).map_err(|e| CgroupError {
        code: e.code(),
        step: CgroupStep::SetIoWeight,
        message: e.message().to_string(),
    })?;
    recorder.record_op(&name, || write_io_weight_at(dir, weight))
}

/// `dir` 直下の `io.weight` へ書き、読み戻して要求値との一致を確認する（テスト可能な実体）。
fn write_io_weight_at(dir: BorrowedFd<'_>, weight: &IoWeight) -> Result<IoWeight, CgroupError> {
    let step = CgroupStep::SetIoWeight;
    let name = cstring(step, "io.weight")?;
    let wfd = match sys::open_write_at(dir, &name) {
        Ok(fd) => fd,
        Err(SysError::Os(errno)) if errno == sys::ENOENT => {
            return Err(CgroupError::precondition(
                step,
                "io.weight not found: io controller is not enabled in the parent cgroup.subtree_control, or the kernel does not provide io.weight",
            ));
        }
        Err(e) => return Err(sys_error(step, "open io.weight", e)),
    };
    File::from(wfd)
        .write_all(weight.to_file_content().as_bytes())
        .map_err(|e| io_error(step, "write io.weight", &e))?;
    let actual = IoWeight::parse(&read_iface(step, dir, "io.weight", SMALL_FILE_LIMIT)?)?;
    if actual != *weight {
        return Err(CgroupError::precondition(
            step,
            format!(
                "io.weight read back as {:?}, expected {:?}",
                actual.to_file_content(),
                weight.to_file_content()
            ),
        ));
    }
    Ok(actual)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_invalid(r: Result<IoWeight, CgroupError>) {
        let e = r.unwrap_err();
        assert_eq!(e.code, ErrorCode::InvalidArgument);
        assert_eq!(e.step, CgroupStep::SetIoWeight);
    }

    /// SUP-13・TASK-170.4: 重みの境界値と既定値。
    #[test]
    fn sup13_task170_4_io_weight_bounds() {
        assert_invalid(IoWeight::new(0));
        assert_invalid(IoWeight::new(10_001));
        assert_eq!(IoWeight::new(1).unwrap().weight(), 1);
        assert_eq!(IoWeight::new(10_000).unwrap().weight(), 10_000);
        assert_eq!(IoWeight::default().weight(), 100);
    }

    /// SUP-13・TASK-170.4: `--blkio-weight` の写像（具体値）。
    #[test]
    fn sup13_task170_4_from_blkio_weight() {
        for (input, want) in [
            (10, 1),
            (11, 11),
            (100, 910),
            (500, 4950),
            (999, 9989),
            (1000, 10_000),
        ] {
            assert_eq!(IoWeight::from_blkio_weight(input).unwrap().weight(), want);
        }
        for bad in [0, 9, 1001, u16::MAX] {
            assert_invalid(IoWeight::from_blkio_weight(bad));
        }
    }

    /// SUP-13・TASK-170.4: カーネルへ書く形式の完全一致。
    #[test]
    fn sup13_task170_4_io_weight_serialize() {
        assert_eq!(IoWeight::default().to_file_content(), "default 100");
        assert_eq!(
            IoWeight::new(4950).unwrap().to_file_content(),
            "default 4950"
        );
    }

    /// SUP-13・TASK-170.4: 読み戻し内容の解析（正常系と異常系）。
    #[test]
    fn sup13_task170_4_io_weight_parse() {
        assert_eq!(
            IoWeight::parse("default 100\n").unwrap(),
            IoWeight::default()
        );
        assert_eq!(
            IoWeight::parse("default 250\n8:0 300\n").unwrap(),
            IoWeight::new(250).unwrap()
        );
        for bad in [
            "",
            "\n",
            "100",
            "default",
            "default 0",
            "default 10001",
            "default +5",
            "default 100 1",
            "default 100\ndefault 200\n",
            "garbage\n",
            "8:0 300\n",
            "x:0 300\ndefault 100\n",
        ] {
            let e = IoWeight::parse(bad).unwrap_err();
            assert_eq!(e.code, ErrorCode::FailedPrecondition, "{bad:?}");
            assert_eq!(e.step, CgroupStep::SetIoWeight, "{bad:?}");
        }
    }

    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    fn scratch(tag: &str) -> std::path::PathBuf {
        let base = std::env::temp_dir().join(format!("fc-ioweight-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        base
    }

    /// SUP-13・TASK-170.4: 通常ファイル上で書き込みと読み戻しが具体値で一致する。
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    fn sup13_task170_4_io_weight_write_and_read_back() {
        let base = scratch("ok");
        std::fs::write(base.join("io.weight"), b"").unwrap();
        let dir = File::open(&base).unwrap();
        let want = IoWeight::new(250).unwrap();
        assert_eq!(write_io_weight_at(dir.as_fd(), &want), Ok(want));
        assert_eq!(
            std::fs::read_to_string(base.join("io.weight")).unwrap(),
            "default 250"
        );
        std::fs::remove_dir_all(&base).unwrap();
    }

    /// SUP-13・TASK-170.4・REPAIR-4: 成功と失敗（open 失敗）の双方が件数として記録される。
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    fn sup13_task170_4_io_weight_operations_are_recorded() {
        let name = OpName::new(SET_IO_WEIGHT_OP_NAME).unwrap();
        let rec = OpRecorder::new();
        let ok = scratch("rec-ok");
        std::fs::write(ok.join("io.weight"), b"").unwrap();
        let dir = File::open(&ok).unwrap();
        write_io_weight_recorded(dir.as_fd(), &rec, &IoWeight::new(250).unwrap()).unwrap();
        let ng = scratch("rec-ng");
        let dir2 = File::open(&ng).unwrap();
        write_io_weight_recorded(dir2.as_fd(), &rec, &IoWeight::default()).unwrap_err();
        let stats = rec.snapshot_op(&name).expect("recorded");
        assert_eq!((stats.success(), stats.failure()), (1, 1));
        std::fs::remove_dir_all(&ok).unwrap();
        std::fs::remove_dir_all(&ng).unwrap();
    }

    /// SUP-13・TASK-170.4: `io.weight` が無い（controller 未有効等）場合は `FailedPrecondition`。
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    fn sup13_task170_4_io_weight_missing_file_is_failed_precondition() {
        let base = scratch("missing");
        let dir = File::open(&base).unwrap();
        let e = write_io_weight_at(dir.as_fd(), &IoWeight::default()).unwrap_err();
        assert_eq!(e.code, ErrorCode::FailedPrecondition);
        assert_eq!(e.step, CgroupStep::SetIoWeight);
        std::fs::remove_dir_all(&base).unwrap();
    }

    /// SUP-13・TASK-170.4: 読み戻した `default` 値が要求と食い違えば成功扱いにしない（不一致分岐）。
    ///
    /// 書き込みは `O_TRUNC` なしの上書きのため、`default 9999\n` へ `default 1` を書くと
    /// `default 1999\n` が残る。形式は正しいので解析を通り、値の不一致として検出される。
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    fn sup13_task170_4_io_weight_read_back_mismatch_fails() {
        let base = scratch("mismatch");
        std::fs::write(base.join("io.weight"), b"default 9999\n").unwrap();
        let dir = File::open(&base).unwrap();
        let e = write_io_weight_at(dir.as_fd(), &IoWeight::new(1).unwrap()).unwrap_err();
        assert_eq!(e.code, ErrorCode::FailedPrecondition);
        assert_eq!(e.step, CgroupStep::SetIoWeight);
        assert_eq!(
            e.message,
            "io.weight read back as \"default 1999\", expected \"default 1\""
        );
        assert_eq!(
            std::fs::read_to_string(base.join("io.weight")).unwrap(),
            "default 1999\n"
        );
        std::fs::remove_dir_all(&base).unwrap();
    }

    /// SUP-13・TASK-170.4: 読み戻した内容が形式不正なら、値の比較より前に解析エラーで失敗する。
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    fn sup13_task170_4_io_weight_read_back_malformed_fails() {
        let base = scratch("malformed");
        std::fs::write(
            base.join("io.weight"),
            b"default 9999\n8:0 300\nxxxxxxxxxxxx",
        )
        .unwrap();
        let dir = File::open(&base).unwrap();
        let e = write_io_weight_at(dir.as_fd(), &IoWeight::new(1).unwrap()).unwrap_err();
        assert_eq!(e.code, ErrorCode::FailedPrecondition);
        assert_eq!(e.step, CgroupStep::SetIoWeight);
        assert_eq!(
            e.message,
            "unexpected io.weight content (expected `<key> <number>` lines): \"default 1999\\n8:0 300\\nxxxxxxxxxxxx\""
        );
        std::fs::remove_dir_all(&base).unwrap();
    }

    /// SUP-13・TASK-170.4: `io.weight` が symlink なら `O_NOFOLLOW` で拒否され、リンク先へは書かれない。
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    fn sup13_task170_4_io_weight_symlink_is_rejected() {
        let base = scratch("symlink");
        std::fs::write(base.join("target"), b"untouched").unwrap();
        std::os::unix::fs::symlink(base.join("target"), base.join("io.weight")).unwrap();
        let dir = File::open(&base).unwrap();
        assert!(write_io_weight_at(dir.as_fd(), &IoWeight::default()).is_err());
        assert_eq!(
            std::fs::read_to_string(base.join("target")).unwrap(),
            "untouched"
        );
        std::fs::remove_dir_all(&base).unwrap();
    }

    fn blkio(n: u16) -> BlkioWeight {
        BlkioWeight::new(n).unwrap()
    }

    fn read(base: &std::path::Path, name: &str) -> String {
        std::fs::read_to_string(base.join(name)).unwrap()
    }

    /// SUP-13・#1534: `--blkio-weight` の境界値。
    #[test]
    fn sup13_issue1534_blkio_weight_bounds() {
        for bad in [0, 9, 1001, u16::MAX] {
            let e = BlkioWeight::new(bad).unwrap_err();
            assert_eq!(e.code, ErrorCode::InvalidArgument);
            assert_eq!(e.step, CgroupStep::SetIoWeight);
        }
        assert_eq!(blkio(10).weight(), 10);
        assert_eq!(blkio(1000).weight(), 1000);
    }

    /// SUP-13・#1534: `io.bfq.weight` があればそこへ無変換で書き、`io.weight` は触らない。
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    fn sup13_issue1534_bfq_present_writes_bfq_only() {
        let base = scratch("bfq-ok");
        std::fs::write(base.join("io.bfq.weight"), b"").unwrap();
        std::fs::write(base.join("io.weight"), b"default 100\n").unwrap();
        let dir = File::open(&base).unwrap();
        let got = write_blkio_weight_at(dir.as_fd(), &blkio(500)).unwrap();
        assert_eq!(got, BlkioWeightTarget::Bfq(BfqWeight::new(500).unwrap()));
        assert_eq!(read(&base, "io.bfq.weight"), "500");
        assert_eq!(read(&base, "io.weight"), "default 100\n");
        std::fs::remove_dir_all(&base).unwrap();
    }

    /// SUP-13・#1534: `io.bfq.weight` が無ければ変換して `io.weight` へ書く。
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    fn sup13_issue1534_bfq_absent_falls_back_to_io_weight() {
        let base = scratch("bfq-absent");
        std::fs::write(base.join("io.weight"), b"").unwrap();
        let dir = File::open(&base).unwrap();
        let got = write_blkio_weight_at(dir.as_fd(), &blkio(500)).unwrap();
        assert_eq!(
            got,
            BlkioWeightTarget::IoWeight(IoWeight::new(4950).unwrap())
        );
        assert_eq!(read(&base, "io.weight"), "default 4950");
        assert!(!base.join("io.bfq.weight").exists());
        std::fs::remove_dir_all(&base).unwrap();
    }

    /// SUP-13・#1534: 両方とも無ければ `io.weight` 側の `FailedPrecondition`。
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    fn sup13_issue1534_both_absent_is_failed_precondition() {
        let base = scratch("both-absent");
        let dir = File::open(&base).unwrap();
        let e = write_blkio_weight_at(dir.as_fd(), &blkio(500)).unwrap_err();
        assert_eq!(e.code, ErrorCode::FailedPrecondition);
        assert_eq!(e.step, CgroupStep::SetIoWeight);
        std::fs::remove_dir_all(&base).unwrap();
    }

    /// SUP-13・#1534: `io.bfq.weight` が ENOENT 以外（ここでは EISDIR）で開けないときは
    /// `io.weight` へフォールバックせずエラーにする。
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    fn sup13_issue1534_bfq_open_failure_does_not_fall_back() {
        let base = scratch("bfq-eisdir");
        std::fs::create_dir(base.join("io.bfq.weight")).unwrap();
        std::fs::write(base.join("io.weight"), b"default 100\n").unwrap();
        let dir = File::open(&base).unwrap();
        let e = write_blkio_weight_at(dir.as_fd(), &blkio(500)).unwrap_err();
        assert_eq!(e.step, CgroupStep::SetIoBfqWeight);
        assert_eq!(read(&base, "io.weight"), "default 100\n");
        std::fs::remove_dir_all(&base).unwrap();
    }

    /// SUP-13・#1534: `io.bfq.weight` が symlink なら拒否し、リンク先も `io.weight` も変えない。
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    fn sup13_issue1534_bfq_symlink_is_rejected_without_fallback() {
        let base = scratch("bfq-symlink");
        std::fs::write(base.join("target"), b"untouched").unwrap();
        std::os::unix::fs::symlink(base.join("target"), base.join("io.bfq.weight")).unwrap();
        std::fs::write(base.join("io.weight"), b"default 100\n").unwrap();
        let dir = File::open(&base).unwrap();
        let e = write_blkio_weight_at(dir.as_fd(), &blkio(500)).unwrap_err();
        assert_eq!(e.step, CgroupStep::SetIoBfqWeight);
        assert_eq!(read(&base, "target"), "untouched");
        assert_eq!(read(&base, "io.weight"), "default 100\n");
        std::fs::remove_dir_all(&base).unwrap();
    }

    /// SUP-13・#1534: 読み戻しの不一致は成功扱いにせず、巻き戻さない。
    /// `999\n` へ `10` を書くと `O_TRUNC` なしの上書きで `109\n` が残る。
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    fn sup13_issue1534_bfq_read_back_mismatch_fails() {
        let base = scratch("bfq-mismatch");
        std::fs::write(base.join("io.bfq.weight"), b"999\n").unwrap();
        let dir = File::open(&base).unwrap();
        let e = write_blkio_weight_at(dir.as_fd(), &blkio(10)).unwrap_err();
        assert_eq!(e.code, ErrorCode::FailedPrecondition);
        assert_eq!(e.step, CgroupStep::SetIoBfqWeight);
        assert_eq!(
            e.message,
            "io.bfq.weight read back as \"109\", expected \"10\""
        );
        assert_eq!(read(&base, "io.bfq.weight"), "109\n");
        std::fs::remove_dir_all(&base).unwrap();
    }

    /// SUP-13・#1534: 読み戻しが形式不正なら解析エラーで失敗する。
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    fn sup13_issue1534_bfq_read_back_malformed_fails() {
        let base = scratch("bfq-malformed");
        std::fs::write(base.join("io.bfq.weight"), b"999\nxxxxxx").unwrap();
        let dir = File::open(&base).unwrap();
        let e = write_blkio_weight_at(dir.as_fd(), &blkio(10)).unwrap_err();
        assert_eq!(e.code, ErrorCode::FailedPrecondition);
        assert_eq!(e.step, CgroupStep::SetIoBfqWeight);
        assert_eq!(
            e.message,
            "unexpected io.bfq.weight content (weight is not a decimal number): \"109\\nxxxxxx\""
        );
        std::fs::remove_dir_all(&base).unwrap();
    }

    /// SUP-13・#1534・REPAIR-4: `set_blkio_weight` の成功・失敗が `cgroup.set_blkio_weight` に記録される。
    /// 記録はラッパー経由（record_op）で、ここでは同じ名前と実体で直接確かめる。
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    fn sup13_issue1534_blkio_weight_operations_are_recorded() {
        let name = OpName::new(SET_BLKIO_WEIGHT_OP_NAME).unwrap();
        let rec = OpRecorder::new();
        let ok = scratch("rec-bfq-ok");
        std::fs::write(ok.join("io.bfq.weight"), b"").unwrap();
        let ng = scratch("rec-bfq-ng");
        std::fs::create_dir(ng.join("io.bfq.weight")).unwrap();
        for base in [&ok, &ng] {
            let dir = File::open(base).unwrap();
            let _ = rec.record_op(&name, || write_blkio_weight_at(dir.as_fd(), &blkio(500)));
        }
        let stats = rec.snapshot_op(&name).expect("recorded");
        assert_eq!((stats.success(), stats.failure()), (1, 1));
        std::fs::remove_dir_all(&ok).unwrap();
        std::fs::remove_dir_all(&ng).unwrap();
    }
}
