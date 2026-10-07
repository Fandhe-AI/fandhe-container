//! コンテナ用子 cgroup の `io.max`（デバイス単位の I/O 絶対値スロットル）の検証・書き込み・読み戻し
//! （SUP-13・TASK-170.2・MS-9・#533）。
//!
//! # 役割
//! 親モジュール [`super`]（委譲 cgroup 検出・子 cgroup 作成。TASK-32.1）が作った
//! [`ContainerCgroup`] に対し、`io.max` へ `"<MAJ:MIN> rbps= wbps= riops= wiops="` を 1 デバイス分
//! 書く。デバイスは [`BlockDevice`]（`dev_t` 幅を検証した数値 2 つ）、上限は [`IoMax`]（検証済みの型）
//! でしか表現できず、呼び出し元の文字列を連結しないため、改行・空白・追加キーの混入で別デバイスや
//! 別設定を書かせる経路はない。
//!
//! # 呼び出し文脈・契約
//! - 呼び出し元: 起動フロー（`--device-read-bps` 等の受け付けと launcher への結線は TASK-170.3・
//!   TASK-29 / TASK-157 系の担当）。本モジュールは単体の API で、起動フローからはまだ呼ばれない
//! - 前提: 親 cgroup の `cgroup.subtree_control` で `io` controller が有効化済み
//!   （[`super::DelegatedCgroup::enable_controllers`]）。未有効なら `io.max` が存在せず `FailedPrecondition`
//! - 書き込み先は保持している O_PATH ディレクトリ fd 起点の `openat`（`O_NOFOLLOW`）で、
//!   パス文字列から cgroup を再解決しない（TOCTOU・symlink 対策）
//! - 1 回の呼び出しは 1 デバイス。複数デバイスは呼び出し側が繰り返す。途中で失敗しても巻き戻さない
//!   （子 cgroup は空で、呼び出し側が `remove_child` で削除する前提。`set_memory_limits` と同じ契約）
//! - 書き込み後に上限付き（[`super::SMALL_FILE_LIMIT`]）で読み戻し、要求値と一致しなければ
//!   `FailedPrecondition`（fail-closed）。1 コンテナの子 cgroup に設定するデバイス数は少数の想定で、
//!   読み戻しが上限を超える場合もエラーになる（黙って切り詰めない）
//! - 読み戻した内容はカーネル応答（外部入力）として `unwrap` / 添字アクセスなしで解析する。
//!   カーネルは全項目が既定（`max`）のデバイス行を出力しないため、対象デバイスの行が無い場合は
//!   「4 値すべて `max`」として扱う
//! - 存在しないデバイス・ディスク全体でないデバイスの指定はカーネルが `ENODEV` で拒否し、
//!   `InvalidArgument` として返す
//! - `unsafe` は持たない。待機を伴わないファイル I/O のみのためタイムアウトは設けない
//!
//! # 未実装（REPAIR-3）
//! - `--blkio-weight`（比例配分の重み）は絶対値スロットルの `io.max` では表現できない。cgroup v2 での
//!   実体は `io.weight` で、本モジュールは `io.max` のみを扱い `io.weight` は未実装（SUP-13 / TASK-170
//!   の文言との不整合は spec 側の課題として報告済みの扱い）
//! - OCI `linux.resources.blockIO` からの反映と launcher への結線（TASK-170.3・TASK-29 / TASK-157 系）

use std::fs::File;
use std::io::Write as _;
use std::os::fd::{AsFd as _, BorrowedFd};

use super::{
    CgroupError, CgroupStep, ContainerCgroup, SMALL_FILE_LIMIT, cstring, io_error, read_iface,
    sys_error,
};
use crate::sys::{self, SysError};
use crate::traits::ErrorCode;

/// `ENODEV`（`include/uapi/asm-generic/errno-base.h`。x86_64・aarch64 で同値）。
const ENODEV: i32 = 19;
/// Linux の `dev_t` における major の上限（12 bit）。
const MAJOR_LIMIT: u32 = 1 << 12;
/// Linux の `dev_t` における minor の上限（20 bit）。
const MINOR_LIMIT: u32 = 1 << 20;

fn invalid(message: String) -> CgroupError {
    CgroupError::new(ErrorCode::InvalidArgument, CgroupStep::SetIoMax, message)
}

/// 検証済みのブロックデバイス番号（`MAJ:MIN`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockDevice {
    major: u32,
    minor: u32,
}

impl BlockDevice {
    /// `dev_t` 幅（major < 2^12・minor < 2^20）を検証して構築する。範囲外は `InvalidArgument`。
    pub fn new(major: u32, minor: u32) -> Result<Self, CgroupError> {
        if major >= MAJOR_LIMIT || minor >= MINOR_LIMIT {
            return Err(invalid(format!(
                "block device {major}:{minor} is out of range (major < {MAJOR_LIMIT}, minor < {MINOR_LIMIT})"
            )));
        }
        Ok(Self { major, minor })
    }

    /// major 番号。
    pub fn major(&self) -> u32 {
        self.major
    }

    /// minor 番号。
    pub fn minor(&self) -> u32 {
        self.minor
    }

    fn token(self) -> String {
        format!("{}:{}", self.major, self.minor)
    }
}

/// `io.max` の 1 項目の上限。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum IoLimit {
    /// 無制限（`max`）。
    Unlimited,
    /// 上限値（bytes/s または IOPS）。`1..u64::MAX` のみ有効（0 と `u64::MAX` は `IoMax::new` が拒否する）。
    Value(u64),
}

impl IoLimit {
    fn validated(self, key: &str) -> Result<Self, CgroupError> {
        match self {
            IoLimit::Value(v) if v == 0 || v == u64::MAX => Err(invalid(format!(
                "io.max {key}={v} is out of range [1, {}]",
                u64::MAX - 1
            ))),
            other => Ok(other),
        }
    }

    fn token(self) -> String {
        match self {
            IoLimit::Unlimited => "max".to_owned(),
            IoLimit::Value(v) => v.to_string(),
        }
    }
}

/// 検証済みの `io.max` 設定（1 デバイス分）。構築は検証付きコンストラクタのみ。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IoMax {
    device: BlockDevice,
    rbps: IoLimit,
    wbps: IoLimit,
    riops: IoLimit,
    wiops: IoLimit,
}

impl IoMax {
    /// 4 項目（read bps・write bps・read iops・write iops）を検証して構築する。範囲外は `InvalidArgument`。
    pub fn new(
        device: BlockDevice,
        rbps: IoLimit,
        wbps: IoLimit,
        riops: IoLimit,
        wiops: IoLimit,
    ) -> Result<Self, CgroupError> {
        Ok(Self {
            device,
            rbps: rbps.validated("rbps")?,
            wbps: wbps.validated("wbps")?,
            riops: riops.validated("riops")?,
            wiops: wiops.validated("wiops")?,
        })
    }

    /// 対象デバイス。
    pub fn device(&self) -> BlockDevice {
        self.device
    }

    /// read bytes/s の上限。
    pub fn rbps(&self) -> IoLimit {
        self.rbps
    }

    /// write bytes/s の上限。
    pub fn wbps(&self) -> IoLimit {
        self.wbps
    }

    /// read IOPS の上限。
    pub fn riops(&self) -> IoLimit {
        self.riops
    }

    /// write IOPS の上限。
    pub fn wiops(&self) -> IoLimit {
        self.wiops
    }

    /// カーネルへ書く形式（常に 4 キーすべてをカーネルの出力順で書く）。
    fn to_file_content(self) -> String {
        format!(
            "{} rbps={} wbps={} riops={} wiops={}",
            self.device.token(),
            self.rbps.token(),
            self.wbps.token(),
            self.riops.token(),
            self.wiops.token()
        )
    }

    /// 書き込み前の再検証（公開バリアントを直接構築した値への備え）。
    fn revalidated(&self) -> Result<Self, CgroupError> {
        Self::new(self.device, self.rbps, self.wbps, self.riops, self.wiops)
    }

    /// 読み戻した `io.max`（複数行・カーネル応答）から `device` の行を解析する。形式不正は
    /// `FailedPrecondition`。対象行が無ければ全項目 `max` とみなす。
    fn parse_for(text: &str, device: BlockDevice) -> Result<Self, CgroupError> {
        let bad = |why: &str| {
            CgroupError::precondition(
                CgroupStep::SetIoMax,
                format!("unexpected io.max content ({why}): {:?}", text.trim_end()),
            )
        };
        let want = device.token();
        let mut found: Option<Self> = None;
        for line in text.lines() {
            let mut tokens = line.split_whitespace();
            let Some(dev) = tokens.next() else {
                continue;
            };
            if dev != want {
                continue;
            }
            if found.is_some() {
                return Err(bad("duplicate device line"));
            }
            let (mut rbps, mut wbps, mut riops, mut wiops) = (None, None, None, None);
            for kv in tokens {
                let (key, value) = kv.split_once('=').ok_or_else(|| bad("missing `=`"))?;
                let slot = match key {
                    "rbps" => &mut rbps,
                    "wbps" => &mut wbps,
                    "riops" => &mut riops,
                    "wiops" => &mut wiops,
                    _ => return Err(bad("unknown key")),
                };
                if slot.is_some() {
                    return Err(bad("duplicate key"));
                }
                let limit = if value == "max" {
                    IoLimit::Unlimited
                } else if !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()) {
                    IoLimit::Value(value.parse::<u64>().map_err(|_| bad("not a number"))?)
                } else {
                    return Err(bad("value is neither `max` nor a decimal number"));
                };
                *slot = Some(limit);
            }
            let (Some(rbps), Some(wbps), Some(riops), Some(wiops)) = (rbps, wbps, riops, wiops)
            else {
                return Err(bad("missing key"));
            };
            found = Some(Self::new(device, rbps, wbps, riops, wiops).map_err(|e| bad(&e.message))?);
        }
        match found {
            Some(v) => Ok(v),
            None => Self::new(
                device,
                IoLimit::Unlimited,
                IoLimit::Unlimited,
                IoLimit::Unlimited,
                IoLimit::Unlimited,
            ),
        }
    }
}

impl ContainerCgroup {
    /// 子 cgroup の `io.max` へ 1 デバイス分を書き込み、読み戻して検証した値を返す（SUP-13・TASK-170.2）。
    ///
    /// `io` controller が親で有効化されていない場合は `FailedPrecondition`。存在しない・ディスク全体で
    /// ないデバイスは `InvalidArgument`。
    pub fn set_io_max(&self, limit: &IoMax) -> Result<IoMax, CgroupError> {
        write_io_max_at(self.fd.as_fd(), limit)
    }
}

/// `dir` 直下の `io.max` へ書き、読み戻して要求値との一致を確認する（テスト可能な実体）。
fn write_io_max_at(dir: BorrowedFd<'_>, limit: &IoMax) -> Result<IoMax, CgroupError> {
    let step = CgroupStep::SetIoMax;
    let limit = limit.revalidated()?;
    let name = cstring(step, "io.max")?;
    let wfd = match sys::open_write_at(dir, &name) {
        Ok(fd) => fd,
        Err(SysError::Os(errno)) if errno == sys::ENOENT => {
            return Err(CgroupError::precondition(
                step,
                "io.max not found: io controller is not enabled in the parent cgroup.subtree_control",
            ));
        }
        Err(e) => return Err(sys_error(step, "open io.max", e)),
    };
    File::from(wfd)
        .write_all(limit.to_file_content().as_bytes())
        .map_err(|e| {
            if e.raw_os_error() == Some(ENODEV) {
                invalid(format!(
                    "io.max rejected device {} (not a whole block device or does not exist)",
                    limit.device.token()
                ))
            } else {
                io_error(step, "write io.max", &e)
            }
        })?;
    let actual = IoMax::parse_for(
        &read_iface(step, dir, "io.max", SMALL_FILE_LIMIT)?,
        limit.device,
    )?;
    if actual != limit {
        return Err(CgroupError::precondition(
            step,
            format!(
                "io.max read back as {:?}, expected {:?}",
                actual.to_file_content(),
                limit.to_file_content()
            ),
        ));
    }
    Ok(actual)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dev(major: u32, minor: u32) -> BlockDevice {
        BlockDevice::new(major, minor).unwrap()
    }

    fn io(device: BlockDevice, r: IoLimit, w: IoLimit, ri: IoLimit, wi: IoLimit) -> IoMax {
        IoMax::new(device, r, w, ri, wi).unwrap()
    }

    const U: IoLimit = IoLimit::Unlimited;

    fn assert_invalid<T: std::fmt::Debug>(r: Result<T, CgroupError>) {
        let e = r.unwrap_err();
        assert_eq!(e.code, ErrorCode::InvalidArgument);
        assert_eq!(e.step, CgroupStep::SetIoMax);
    }

    /// SUP-13・TASK-170.2: デバイス番号の境界値（`dev_t` 幅）。
    #[test]
    fn sup13_task170_2_io_device_bounds() {
        assert!(BlockDevice::new(4095, 1_048_575).is_ok());
        assert_invalid(BlockDevice::new(4096, 0));
        assert_invalid(BlockDevice::new(0, 1_048_576));
        assert_eq!(dev(259, 0).major(), 259);
        assert_eq!(dev(259, 0).minor(), 0);
    }

    /// SUP-13・TASK-170.2: 上限値の境界（0 と `u64::MAX` は拒否）。
    #[test]
    fn sup13_task170_2_io_limit_bounds() {
        let d = dev(8, 0);
        assert_invalid(IoMax::new(d, IoLimit::Value(0), U, U, U));
        assert_invalid(IoMax::new(d, U, IoLimit::Value(0), U, U));
        assert_invalid(IoMax::new(d, U, U, IoLimit::Value(0), U));
        assert_invalid(IoMax::new(d, U, U, U, IoLimit::Value(u64::MAX)));
        assert!(IoMax::new(d, IoLimit::Value(1), U, U, U).is_ok());
        assert!(IoMax::new(d, IoLimit::Value(u64::MAX - 1), U, U, U).is_ok());
    }

    /// SUP-13・TASK-170.2: カーネルへ書く形式の完全一致。
    #[test]
    fn sup13_task170_2_io_serialize() {
        assert_eq!(
            io(dev(8, 0), IoLimit::Value(1_048_576), U, U, U).to_file_content(),
            "8:0 rbps=1048576 wbps=max riops=max wiops=max"
        );
        assert_eq!(
            io(
                dev(259, 0),
                IoLimit::Value(1_048_576),
                IoLimit::Value(2_097_152),
                IoLimit::Value(100),
                IoLimit::Value(200)
            )
            .to_file_content(),
            "259:0 rbps=1048576 wbps=2097152 riops=100 wiops=200"
        );
        assert_eq!(
            io(dev(8, 0), U, U, U, U).to_file_content(),
            "8:0 rbps=max wbps=max riops=max wiops=max"
        );
    }

    /// SUP-13・TASK-170.2: 読み戻し内容の解析（単一行・複数デバイス・行なし・キー順）。
    #[test]
    fn sup13_task170_2_io_parse() {
        let d = dev(8, 0);
        let want = io(d, IoLimit::Value(1_048_576), U, U, U);
        assert_eq!(
            IoMax::parse_for("8:0 rbps=1048576 wbps=max riops=max wiops=max\n", d).unwrap(),
            want
        );
        // 複数デバイス行から対象行を選ぶ。
        let multi = "259:0 rbps=5 wbps=max riops=max wiops=max\n\
                     8:0 rbps=1048576 wbps=max riops=max wiops=max\n";
        assert_eq!(IoMax::parse_for(multi, d).unwrap(), want);
        // キー順はカーネルの出力順に依存しない。
        assert_eq!(
            IoMax::parse_for("8:0 wiops=max riops=max wbps=max rbps=1048576", d).unwrap(),
            want
        );
        // 対象行なしは全 max。
        assert_eq!(
            IoMax::parse_for("259:0 rbps=5 wbps=max riops=max wiops=max\n", d).unwrap(),
            io(d, U, U, U, U)
        );
        assert_eq!(IoMax::parse_for("", d).unwrap(), io(d, U, U, U, U));
        for bad in [
            "8:0 rbps=1 wbps=max riops=max",
            "8:0 rbps=1 rbps=2 wbps=max riops=max wiops=max",
            "8:0 rbps=1 wbps=max riops=max wiops=max foo=1",
            "8:0 rbps=abc wbps=max riops=max wiops=max",
            "8:0 rbps=-1 wbps=max riops=max wiops=max",
            "8:0 rbps=0 wbps=max riops=max wiops=max",
            "8:0 rbps wbps=max riops=max wiops=max",
            "8:0 rbps= wbps=max riops=max wiops=max",
            "8:0 rbps=1 wbps=max riops=max wiops=max\n8:0 rbps=2 wbps=max riops=max wiops=max",
        ] {
            let e = IoMax::parse_for(bad, d).unwrap_err();
            assert_eq!(e.code, ErrorCode::FailedPrecondition, "{bad:?}");
            assert_eq!(e.step, CgroupStep::SetIoMax, "{bad:?}");
        }
    }

    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    fn scratch(tag: &str) -> std::path::PathBuf {
        let base = std::env::temp_dir().join(format!("fc-iomax-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        base
    }

    /// SUP-13・TASK-170.2: 通常ファイル上で書き込みと読み戻しが具体値で一致する（受け入れ条件の機械照合）。
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    fn sup13_task170_2_io_write_and_read_back() {
        let base = scratch("ok");
        std::fs::write(base.join("io.max"), b"").unwrap();
        let dir = File::open(&base).unwrap();
        let want = io(
            dev(259, 0),
            IoLimit::Value(1_048_576),
            IoLimit::Value(2_097_152),
            IoLimit::Value(100),
            IoLimit::Value(200),
        );
        assert_eq!(write_io_max_at(dir.as_fd(), &want), Ok(want));
        assert_eq!(
            std::fs::read_to_string(base.join("io.max")).unwrap(),
            "259:0 rbps=1048576 wbps=2097152 riops=100 wiops=200"
        );
        std::fs::remove_dir_all(&base).unwrap();
    }

    /// SUP-13・TASK-170.2: `io.max` が無い（controller 未有効）場合は `FailedPrecondition`。
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    fn sup13_task170_2_io_missing_file_is_failed_precondition() {
        let base = scratch("missing");
        let dir = File::open(&base).unwrap();
        let e = write_io_max_at(dir.as_fd(), &io(dev(8, 0), U, U, U, U)).unwrap_err();
        assert_eq!(e.code, ErrorCode::FailedPrecondition);
        assert_eq!(e.step, CgroupStep::SetIoMax);
        std::fs::remove_dir_all(&base).unwrap();
    }

    /// SUP-13・TASK-170.2: 読み戻しが要求と食い違えば成功扱いにしない。
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    fn sup13_task170_2_io_read_back_mismatch_fails() {
        let base = scratch("mismatch");
        let long = "8:0 rbps=1 wbps=max riops=max wiops=max\n".repeat(2);
        std::fs::write(base.join("io.max"), long).unwrap();
        let dir = File::open(&base).unwrap();
        let want = io(dev(8, 0), IoLimit::Value(1_048_576), U, U, U);
        let e = write_io_max_at(dir.as_fd(), &want).unwrap_err();
        assert_eq!(e.code, ErrorCode::FailedPrecondition);
        std::fs::remove_dir_all(&base).unwrap();
    }

    /// SUP-13・TASK-170.2: `io.max` が symlink なら `O_NOFOLLOW` で拒否され、リンク先へは書かれない。
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    fn sup13_task170_2_io_symlink_is_rejected() {
        let base = scratch("symlink");
        std::fs::write(base.join("target"), b"untouched").unwrap();
        std::os::unix::fs::symlink(base.join("target"), base.join("io.max")).unwrap();
        let dir = File::open(&base).unwrap();
        assert!(write_io_max_at(dir.as_fd(), &io(dev(8, 0), U, U, U, U)).is_err());
        assert_eq!(
            std::fs::read_to_string(base.join("target")).unwrap(),
            "untouched"
        );
        std::fs::remove_dir_all(&base).unwrap();
    }
}
