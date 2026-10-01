//! コンテナ用子 cgroup の `cpu.max`（CPU 帯域制限）の検証・書き込み・読み戻し（CORE-3・TASK-32.3・MS-2・#160）。
//!
//! # 役割
//! 親モジュール [`super`]（委譲 cgroup 検出・子 cgroup 作成。TASK-32.1）が作った
//! [`ContainerCgroup`] に対し、`cpu.max` へ `"<quota|max> <period>"` を書く。値は
//! [`CpuMax`]（検証済みの型）でしか表現できないため、範囲外の値はカーネルへ渡らない。
//!
//! # 呼び出し文脈・契約
//! - 呼び出し元: 起動フロー（`oci_runtime` の start 経路。OCI `linux.resources.cpu` の反映と結線は
//!   TASK-32.4・#161）。本モジュールは単体の API で、起動フローからはまだ呼ばれない
//! - 前提: 親 cgroup の `cgroup.subtree_control` で `cpu` controller が有効化済み
//!   （[`super::DelegatedCgroup::enable_controllers`]）。未有効なら `cpu.max` が存在せず
//!   `FailedPrecondition`
//! - 書き込み先は保持している O_PATH ディレクトリ fd 起点の `openat`（`O_NOFOLLOW`）で、
//!   パス文字列から cgroup を再解決しない（TOCTOU・symlink 対策。TASK-32.1 と同じ姿勢）
//! - 書き込み後に上限付きで読み戻し、要求値と一致しなければ `FailedPrecondition`（fail-closed）
//! - 読み戻した内容はカーネル応答（外部入力）として `unwrap` / 添字アクセスなしで解析する
//! - `unsafe` は持たない。待機を伴わないファイル I/O のみのためタイムアウトは設けない
//!
//! # 未実装（REPAIR-3）
//! `cpu.weight`・`cpu.max.burst`・OCI `cpu.shares` の変換、親 cgroup の quota との階層整合検証
//! （カーネルが書き込み時に `EINVAL` で拒否する場合は `Internal` として返る）。

use std::fs::File;
use std::io::Write as _;
use std::os::fd::{AsFd as _, BorrowedFd};

use super::{
    CgroupError, CgroupStep, ContainerCgroup, SMALL_FILE_LIMIT, cstring, io_error, read_iface,
    sys_error,
};
use crate::sys::{self, SysError};
use crate::traits::ErrorCode;

/// `cpu.max` の period の下限（µs）。
///
/// Linux `kernel/sched/core.c` の `tg_set_cfs_bandwidth` が `min_cfs_quota_period`（1ms）未満の
/// period を `EINVAL` で拒否する（カーネルソースでの再確認は未実施の既知値。実機結合試験で照合する）。
pub const MIN_PERIOD_US: u64 = 1_000;
/// `cpu.max` の period の上限（µs）。同関数の `max_cfs_quota_period`（1s）。
pub const MAX_PERIOD_US: u64 = 1_000_000;
/// `cpu.max` の quota（`Micros`）の下限（µs）。同関数の `min_cfs_quota_period`（1ms）が quota にも適用される。
pub const MIN_QUOTA_US: u64 = 1_000;
/// `cpu.max` の quota の上限（µs）。カーネルの `max_cfs_runtime`（`MAX_BW_USEC` = 2^44 - 1 µs）。
pub const MAX_QUOTA_US: u64 = (1u64 << 44) - 1;

/// `cpu.max` の quota 部。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CpuQuota {
    /// 無制限（`max`）。
    Unlimited,
    /// period あたりに使える CPU 時間（µs）。
    Micros(u64),
}

/// 検証済みの `cpu.max` 値（quota・period は µs）。構築は検証付きコンストラクタのみ。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CpuMax {
    quota: CpuQuota,
    period_us: u64,
}

fn invalid(message: String) -> CgroupError {
    CgroupError::new(ErrorCode::InvalidArgument, CgroupStep::SetCpuMax, message)
}

impl CpuMax {
    /// 既定の period（µs。カーネル既定・OCI の慣用値と同じ 100ms）。
    pub const DEFAULT_PERIOD_US: u64 = 100_000;

    /// 範囲を検証して構築する。範囲外は `InvalidArgument`（カーネルへは渡さない）。
    pub fn new(quota: CpuQuota, period_us: u64) -> Result<Self, CgroupError> {
        if !(MIN_PERIOD_US..=MAX_PERIOD_US).contains(&period_us) {
            return Err(invalid(format!(
                "cpu.max period {period_us}us is out of range [{MIN_PERIOD_US}, {MAX_PERIOD_US}]"
            )));
        }
        if let CpuQuota::Micros(q) = quota
            && !(MIN_QUOTA_US..=MAX_QUOTA_US).contains(&q)
        {
            return Err(invalid(format!(
                "cpu.max quota {q}us is out of range [{MIN_QUOTA_US}, {MAX_QUOTA_US}]"
            )));
        }
        Ok(Self { quota, period_us })
    }

    /// OCI `linux.resources.cpu.quota`（i64）互換。`-1` は無制限、その他の負数・0 は `InvalidArgument`。
    pub fn from_signed_quota(quota_us: i64, period_us: u64) -> Result<Self, CgroupError> {
        let quota = if quota_us == -1 {
            CpuQuota::Unlimited
        } else {
            match u64::try_from(quota_us) {
                Ok(q) => CpuQuota::Micros(q),
                Err(_) => {
                    return Err(invalid(format!("cpu.max quota {quota_us}us is negative")));
                }
            }
        };
        Self::new(quota, period_us)
    }

    /// quota 部。
    pub fn quota(&self) -> CpuQuota {
        self.quota
    }

    /// period（µs）。
    pub fn period_us(&self) -> u64 {
        self.period_us
    }

    /// カーネルへ書く形式（常に 2 トークン）。
    fn to_file_content(self) -> String {
        match self.quota {
            CpuQuota::Unlimited => format!("max {}", self.period_us),
            CpuQuota::Micros(q) => format!("{q} {}", self.period_us),
        }
    }

    /// 読み戻した `cpu.max`（カーネル応答）の解析。形式不正・範囲外は `FailedPrecondition`。
    fn parse(text: &str) -> Result<Self, CgroupError> {
        let bad = |why: &str| {
            CgroupError::precondition(
                CgroupStep::SetCpuMax,
                format!("unexpected cpu.max content ({why}): {:?}", text.trim_end()),
            )
        };
        let mut tokens = text.split_whitespace();
        let (Some(q), Some(p), None) = (tokens.next(), tokens.next(), tokens.next()) else {
            return Err(bad("expected two tokens"));
        };
        let quota = if q == "max" {
            CpuQuota::Unlimited
        } else {
            CpuQuota::Micros(q.parse::<u64>().map_err(|_| bad("quota is not a number"))?)
        };
        let period = p
            .parse::<u64>()
            .map_err(|_| bad("period is not a number"))?;
        Self::new(quota, period).map_err(|e| bad(&e.message))
    }
}

impl ContainerCgroup {
    /// 子 cgroup の `cpu.max` を書き込み、読み戻して検証した値を返す（CORE-3・TASK-32.3）。
    ///
    /// `cpu` controller が親で有効化されていない場合は `FailedPrecondition`。
    pub fn set_cpu_max(&self, limit: &CpuMax) -> Result<CpuMax, CgroupError> {
        write_cpu_max_at(self.fd.as_fd(), limit)
    }
}

/// `dir` 直下の `cpu.max` へ書き、読み戻して要求値との一致を確認する（テスト可能な実体）。
fn write_cpu_max_at(dir: BorrowedFd<'_>, limit: &CpuMax) -> Result<CpuMax, CgroupError> {
    let step = CgroupStep::SetCpuMax;
    let name = cstring(step, "cpu.max")?;
    let wfd = match sys::open_write_at(dir, &name) {
        Ok(fd) => fd,
        Err(SysError::Os(errno)) if errno == sys::ENOENT => {
            return Err(CgroupError::precondition(
                step,
                "cpu.max not found: cpu controller is not enabled in the parent cgroup.subtree_control",
            ));
        }
        Err(e) => return Err(sys_error(step, "open cpu.max", e)),
    };
    File::from(wfd)
        .write_all(limit.to_file_content().as_bytes())
        .map_err(|e| io_error(step, "write cpu.max", &e))?;
    let actual = CpuMax::parse(&read_iface(step, dir, "cpu.max", SMALL_FILE_LIMIT)?)?;
    if actual != *limit {
        return Err(CgroupError::precondition(
            step,
            format!(
                "cpu.max read back as {:?}, expected {:?}",
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

    fn micros(q: u64, p: u64) -> Result<CpuMax, CgroupError> {
        CpuMax::new(CpuQuota::Micros(q), p)
    }

    fn assert_invalid(r: Result<CpuMax, CgroupError>) {
        let e = r.unwrap_err();
        assert_eq!(e.code, ErrorCode::InvalidArgument);
        assert_eq!(e.step, CgroupStep::SetCpuMax);
    }

    /// CORE-3・TASK-32.3: period の境界値。
    #[test]
    fn core3_task32_3_period_bounds() {
        assert_invalid(micros(50_000, 999));
        assert!(micros(50_000, 1_000).is_ok());
        assert!(micros(50_000, 1_000_000).is_ok());
        assert_invalid(micros(50_000, 1_000_001));
        assert_invalid(CpuMax::new(CpuQuota::Unlimited, 0));
    }

    /// CORE-3・TASK-32.3: quota の境界値。
    #[test]
    fn core3_task32_3_quota_bounds() {
        assert_invalid(micros(0, 100_000));
        assert_invalid(micros(999, 100_000));
        assert!(micros(1_000, 100_000).is_ok());
        assert!(micros(MAX_QUOTA_US, 100_000).is_ok());
        assert_invalid(micros(MAX_QUOTA_US + 1, 100_000));
        assert!(CpuMax::new(CpuQuota::Unlimited, 100_000).is_ok());
    }

    /// CORE-3・TASK-32.3: OCI 互換の符号付き quota。
    #[test]
    fn core3_task32_3_from_signed_quota() {
        assert_eq!(
            CpuMax::from_signed_quota(-1, 100_000).unwrap().quota(),
            CpuQuota::Unlimited
        );
        assert_eq!(
            CpuMax::from_signed_quota(50_000, 100_000).unwrap().quota(),
            CpuQuota::Micros(50_000)
        );
        for q in [-2, 0, i64::MIN] {
            assert_invalid(CpuMax::from_signed_quota(q, 100_000));
        }
    }

    /// CORE-3・TASK-32.3: カーネルへ書く形式の完全一致。
    #[test]
    fn core3_task32_3_serialize() {
        let max = CpuMax::new(CpuQuota::Unlimited, CpuMax::DEFAULT_PERIOD_US).unwrap();
        assert_eq!(max.to_file_content(), "max 100000");
        assert_eq!(
            micros(50_000, 100_000).unwrap().to_file_content(),
            "50000 100000"
        );
    }

    /// CORE-3・TASK-32.3: 読み戻し内容の解析（正常系と異常系）。
    #[test]
    fn core3_task32_3_parse() {
        assert_eq!(
            CpuMax::parse("max 100000\n").unwrap(),
            CpuMax::new(CpuQuota::Unlimited, 100_000).unwrap()
        );
        assert_eq!(
            CpuMax::parse("50000 100000\n").unwrap(),
            micros(50_000, 100_000).unwrap()
        );
        for bad in [
            "",
            "max",
            "abc 100000",
            "50000 100000 1",
            "50000 abc",
            "-1 100000",
            "999 100000",
            "50000 999",
        ] {
            let e = CpuMax::parse(bad).unwrap_err();
            assert_eq!(e.code, ErrorCode::FailedPrecondition, "{bad:?}");
            assert_eq!(e.step, CgroupStep::SetCpuMax, "{bad:?}");
        }
    }

    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    fn scratch(tag: &str) -> std::path::PathBuf {
        let base = std::env::temp_dir().join(format!("fc-cpumax-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        base
    }

    /// CORE-3・TASK-32.3: 通常ファイル上で書き込みと読み戻しが具体値で一致する。
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    fn core3_task32_3_write_and_read_back() {
        let base = scratch("ok");
        std::fs::write(base.join("cpu.max"), b"").unwrap();
        let dir = File::open(&base).unwrap();
        let want = micros(50_000, 100_000).unwrap();
        assert_eq!(write_cpu_max_at(dir.as_fd(), &want), Ok(want));
        assert_eq!(
            std::fs::read_to_string(base.join("cpu.max")).unwrap(),
            "50000 100000"
        );
        std::fs::remove_dir_all(&base).unwrap();
    }

    /// CORE-3・TASK-32.3: `cpu.max` が無い（controller 未有効）場合は `FailedPrecondition`。
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    fn core3_task32_3_missing_file_is_failed_precondition() {
        let base = scratch("missing");
        let dir = File::open(&base).unwrap();
        let e = write_cpu_max_at(dir.as_fd(), &micros(50_000, 100_000).unwrap()).unwrap_err();
        assert_eq!(e.code, ErrorCode::FailedPrecondition);
        assert_eq!(e.step, CgroupStep::SetCpuMax);
        std::fs::remove_dir_all(&base).unwrap();
    }

    /// CORE-3・TASK-32.3: 読み戻しが要求と食い違えば成功扱いにしない（通常ファイルは O_TRUNC なしのため
    /// 長い既存内容が残り、読み戻しが不一致になる）。
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    fn core3_task32_3_read_back_mismatch_fails() {
        let base = scratch("mismatch");
        std::fs::write(base.join("cpu.max"), b"max 100000 padding-padding").unwrap();
        let dir = File::open(&base).unwrap();
        let e = write_cpu_max_at(dir.as_fd(), &micros(50_000, 100_000).unwrap()).unwrap_err();
        assert_eq!(e.code, ErrorCode::FailedPrecondition);
        std::fs::remove_dir_all(&base).unwrap();
    }

    /// CORE-3・TASK-32.3: `cpu.max` が symlink なら `O_NOFOLLOW` で拒否され、リンク先へは書かれない。
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    fn core3_task32_3_symlink_is_rejected() {
        let base = scratch("symlink");
        std::fs::write(base.join("target"), b"untouched").unwrap();
        std::os::unix::fs::symlink(base.join("target"), base.join("cpu.max")).unwrap();
        let dir = File::open(&base).unwrap();
        assert!(write_cpu_max_at(dir.as_fd(), &micros(50_000, 100_000).unwrap()).is_err());
        assert_eq!(
            std::fs::read_to_string(base.join("target")).unwrap(),
            "untouched"
        );
        std::fs::remove_dir_all(&base).unwrap();
    }
}
