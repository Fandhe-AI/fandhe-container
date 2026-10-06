//! cgroup v2 統計ファイル（`memory.current`・`cpu.stat`・`io.stat`）の読み取りと型付きパース（SUP-10・TASK-167.1・MS-9）。
//!
//! # 役割
//! `stats` コマンド（SUP-10）の入力側。パース（`&str` → 型）は OS 非依存の純関数で、3 OS の CI で
//! 具体値を照合する。cgroup からの読み取り（[`read_cgroup_stats`]）は Linux 限定で、core の
//! `ContainerCgroup::read_stat_file`（cgroup ディレクトリ fd 起点の上限付き `openat`）を使う。
//!
//! # 呼び出し文脈・契約
//! - 呼び出し元（予定）: 機械可読形式での出力と CLI 配線（TASK-167.2・#521）。本モジュールは出力形式
//!   （`Display`・JSON・キー名）を決めず、型付きの値だけを返す
//! - 各ファイルが存在しない（controller 未有効）場合は、その項目を `None` にする（0 とは区別する）
//! - カーネル応答は外部入力として扱い、`unwrap` / 添字アクセスを使わず、数値は `u64` / `u32` の範囲で
//!   検証する。形式不正は [`StatsError`]（`FailedPrecondition`・対象ファイル・英語の `message`）
//! - 相手の応答を待たない cgroupfs の擬似ファイル読み取りのみのため、タイムアウトは設けない
//!
//! # 未実装（REPAIR-3）
//! 機械可読形式での出力・CLI 呼び出し（TASK-167.2・#521）。supervisor が自コンテナの
//! `ContainerCgroup` を得る結線（状態記録の cgroup 配置から開く経路）も未実装。

use std::collections::BTreeSet;
use std::fmt;

use fandhe_container_core::traits::ErrorCode;

/// `io.stat` で受け入れるデバイス数の上限（無制限確保の防止）。
pub const MAX_IO_DEVICES: usize = 1024;

/// どの統計ファイルに関するエラーか。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum StatsFile {
    /// `memory.current`。
    MemoryCurrent,
    /// `cpu.stat`。
    CpuStat,
    /// `io.stat`。
    IoStat,
}

impl StatsFile {
    /// ファイル名。
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MemoryCurrent => "memory.current",
            Self::CpuStat => "cpu.stat",
            Self::IoStat => "io.stat",
        }
    }
}

/// 統計の読み取り・解析エラー（機械可読な `code` と対象ファイル、英語の `message`）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct StatsError {
    /// 機械可読なエラーコード。
    pub code: ErrorCode,
    /// 対象ファイル。
    pub file: StatsFile,
    /// 人間向けの説明（英語）。
    pub message: String,
}

impl StatsError {
    fn malformed(file: StatsFile, message: impl Into<String>) -> Self {
        Self {
            code: ErrorCode::FailedPrecondition,
            file,
            message: message.into(),
        }
    }
}

impl fmt::Display for StatsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} ({}): {}",
            self.code.as_str(),
            self.file.as_str(),
            self.message
        )
    }
}

impl std::error::Error for StatsError {}

/// `memory.current`（バイト）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryCurrent(pub u64);

/// `cpu.stat` の値（µs・回数）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct CpuStat {
    /// 総 CPU 使用時間（µs）。
    pub usage_usec: u64,
    /// ユーザ時間（µs）。
    pub user_usec: u64,
    /// システム時間（µs）。
    pub system_usec: u64,
    /// 経過した period 数（cpu controller 有効時のみ）。
    pub nr_periods: Option<u64>,
    /// スロットリングされた period 数（同上）。
    pub nr_throttled: Option<u64>,
    /// スロットリング時間（µs。同上）。
    pub throttled_usec: Option<u64>,
}

/// `io.stat` の 1 デバイス分。欠落したキーは 0 とせず `None`。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct IoDeviceStat {
    /// デバイスのメジャー番号。
    pub major: u32,
    /// デバイスのマイナー番号。
    pub minor: u32,
    /// 読み取りバイト数。
    pub rbytes: Option<u64>,
    /// 書き込みバイト数。
    pub wbytes: Option<u64>,
    /// 読み取り I/O 数。
    pub rios: Option<u64>,
    /// 書き込み I/O 数。
    pub wios: Option<u64>,
    /// discard バイト数。
    pub dbytes: Option<u64>,
    /// discard I/O 数。
    pub dios: Option<u64>,
}

/// `io.stat` 全体（デバイスなしの空を許容する）。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct IoStat {
    /// デバイスごとの統計（出現順）。
    pub devices: Vec<IoDeviceStat>,
}

/// 3 ファイルの統計。`None` はファイル不存在（controller 未有効）。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct CgroupStats {
    /// `memory.current`。
    pub memory: Option<MemoryCurrent>,
    /// `cpu.stat`。
    pub cpu: Option<CpuStat>,
    /// `io.stat`。
    pub io: Option<IoStat>,
}

fn parse_u64(file: StatsFile, what: &str, s: &str) -> Result<u64, StatsError> {
    // `u64::from_str` は先頭の `+` を許すため、数字のみであることを先に検証する。
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(StatsError::malformed(
            file,
            format!("{what}: value is not a decimal number"),
        ));
    }
    s.parse::<u64>()
        .map_err(|_| StatsError::malformed(file, format!("{what}: value out of range")))
}

/// `memory.current` を解析する（10 進数 1 個＋任意の末尾改行）。
pub fn parse_memory_current(text: &str) -> Result<MemoryCurrent, StatsError> {
    let body = text.strip_suffix('\n').unwrap_or(text);
    parse_u64(StatsFile::MemoryCurrent, "memory.current", body).map(MemoryCurrent)
}

/// `cpu.stat`（`key value` の行の並び）を解析する。未知キーは無視し、必須 3 キーの欠落・重複を拒否する。
pub fn parse_cpu_stat(text: &str) -> Result<CpuStat, StatsError> {
    const F: StatsFile = StatsFile::CpuStat;
    let mut usage = None;
    let mut user = None;
    let mut system = None;
    let mut nr_periods = None;
    let mut nr_throttled = None;
    let mut throttled = None;
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let mut it = line.split_whitespace();
        let (Some(key), Some(val), None) = (it.next(), it.next(), it.next()) else {
            return Err(StatsError::malformed(F, "line is not `key value`"));
        };
        let slot = match key {
            "usage_usec" => &mut usage,
            "user_usec" => &mut user,
            "system_usec" => &mut system,
            "nr_periods" => &mut nr_periods,
            "nr_throttled" => &mut nr_throttled,
            "throttled_usec" => &mut throttled,
            _ => {
                // 未知キー（nr_bursts 等）は前方互換のため無視するが、値の形式は検証しない。
                continue;
            }
        };
        if slot.is_some() {
            return Err(StatsError::malformed(F, format!("duplicate key {key}")));
        }
        *slot = Some(parse_u64(F, key, val)?);
    }
    let required = |v: Option<u64>, key: &str| {
        v.ok_or_else(|| StatsError::malformed(F, format!("missing required key {key}")))
    };
    Ok(CpuStat {
        usage_usec: required(usage, "usage_usec")?,
        user_usec: required(user, "user_usec")?,
        system_usec: required(system, "system_usec")?,
        nr_periods,
        nr_throttled,
        throttled_usec: throttled,
    })
}

fn parse_dev(s: &str) -> Result<(u32, u32), StatsError> {
    let bad = || StatsError::malformed(StatsFile::IoStat, "device is not `MAJ:MIN`");
    let (maj, min) = s.split_once(':').ok_or_else(bad)?;
    let digits = |p: &str| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit());
    if !digits(maj) || !digits(min) {
        return Err(bad());
    }
    let maj = maj.parse::<u32>().map_err(|_| bad())?;
    let min = min.parse::<u32>().map_err(|_| bad())?;
    Ok((maj, min))
}

/// `io.stat`（`MAJ:MIN key=val ...` の行の並び）を解析する。空・未知キーは許容する。
pub fn parse_io_stat(text: &str) -> Result<IoStat, StatsError> {
    const F: StatsFile = StatsFile::IoStat;
    let mut devices: Vec<IoDeviceStat> = Vec::new();
    let mut seen: BTreeSet<(u32, u32)> = BTreeSet::new();
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let mut it = line.split_whitespace();
        let Some(dev) = it.next() else {
            continue;
        };
        let (major, minor) = parse_dev(dev)?;
        if !seen.insert((major, minor)) {
            return Err(StatsError::malformed(F, "duplicate device"));
        }
        // 確保の前に件数を検証する。
        if seen.len() > MAX_IO_DEVICES {
            return Err(StatsError::malformed(F, "too many devices"));
        }
        let mut dev_stat = IoDeviceStat {
            major,
            minor,
            rbytes: None,
            wbytes: None,
            rios: None,
            wios: None,
            dbytes: None,
            dios: None,
        };
        let mut present: BTreeSet<&str> = BTreeSet::new();
        for tok in it {
            let Some((key, val)) = tok.split_once('=') else {
                return Err(StatsError::malformed(F, "token is not `key=value`"));
            };
            let slot = match key {
                "rbytes" => &mut dev_stat.rbytes,
                "wbytes" => &mut dev_stat.wbytes,
                "rios" => &mut dev_stat.rios,
                "wios" => &mut dev_stat.wios,
                "dbytes" => &mut dev_stat.dbytes,
                "dios" => &mut dev_stat.dios,
                // io.cost 系などの未知キーは無視する。
                _ => continue,
            };
            if !present.insert(key) {
                return Err(StatsError::malformed(F, format!("duplicate key {key}")));
            }
            *slot = Some(parse_u64(F, key, val)?);
        }
        devices.push(dev_stat);
    }
    Ok(IoStat { devices })
}

/// 委譲済みの `cgroup` から 3 ファイルを読み、パースして返す（Linux 限定）。
///
/// ファイル不存在は該当項目を `None` にする。読み取り失敗（上限超過・非 UTF-8 等）は
/// `StatsError` に写す。
#[cfg(target_os = "linux")]
pub fn read_cgroup_stats(
    cgroup: &fandhe_container_core::cgroups::ContainerCgroup,
) -> Result<CgroupStats, StatsError> {
    use fandhe_container_core::cgroups::StatFile;

    let read = |f: StatFile, file: StatsFile| {
        cgroup.read_stat_file(f).map_err(|e| StatsError {
            code: e.code,
            file,
            message: e.message,
        })
    };
    let memory = read(StatFile::MemoryCurrent, StatsFile::MemoryCurrent)?
        .map(|t| parse_memory_current(&t))
        .transpose()?;
    let cpu = read(StatFile::CpuStat, StatsFile::CpuStat)?
        .map(|t| parse_cpu_stat(&t))
        .transpose()?;
    let io = read(StatFile::IoStat, StatsFile::IoStat)?
        .map(|t| parse_io_stat(&t))
        .transpose()?;
    Ok(CgroupStats { memory, cpu, io })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fail<T: fmt::Debug>(r: Result<T, StatsError>, file: StatsFile) {
        let e = r.unwrap_err();
        assert_eq!(e.code, ErrorCode::FailedPrecondition, "{e}");
        assert_eq!(e.file, file, "{e}");
    }

    /// SUP-10・TASK-167.1: memory.current の受理値。
    #[test]
    fn sup10_task167_1_memory_current_accepts() {
        assert_eq!(
            parse_memory_current("12345678\n"),
            Ok(MemoryCurrent(12_345_678))
        );
        assert_eq!(parse_memory_current("7"), Ok(MemoryCurrent(7)));
        assert_eq!(parse_memory_current("0\n"), Ok(MemoryCurrent(0)));
        assert_eq!(
            parse_memory_current("18446744073709551615\n"),
            Ok(MemoryCurrent(u64::MAX))
        );
    }

    /// SUP-10・TASK-167.1: memory.current の拒否値。
    #[test]
    fn sup10_task167_1_memory_current_rejects() {
        for t in [
            "18446744073709551616\n",
            "",
            "\n",
            "max\n",
            "-1\n",
            "+5\n",
            "12 34\n",
            " 5\n",
        ] {
            fail(parse_memory_current(t), StatsFile::MemoryCurrent);
        }
    }

    const CPU_FULL: &str = "usage_usec 1000\nuser_usec 600\nsystem_usec 400\n\
nr_periods 10\nnr_throttled 2\nthrottled_usec 350\n";

    /// SUP-10・TASK-167.1: cpu.stat（controller 有効時の 6 キー）。
    #[test]
    fn sup10_task167_1_cpu_stat_full() {
        assert_eq!(
            parse_cpu_stat(CPU_FULL),
            Ok(CpuStat {
                usage_usec: 1000,
                user_usec: 600,
                system_usec: 400,
                nr_periods: Some(10),
                nr_throttled: Some(2),
                throttled_usec: Some(350),
            })
        );
    }

    /// SUP-10・TASK-167.1: cpu.stat の 3 キーのみ・未知キー入り。
    #[test]
    fn sup10_task167_1_cpu_stat_minimal_and_unknown_keys() {
        let want = CpuStat {
            usage_usec: 5,
            user_usec: 3,
            system_usec: 2,
            nr_periods: None,
            nr_throttled: None,
            throttled_usec: None,
        };
        assert_eq!(
            parse_cpu_stat("usage_usec 5\nuser_usec 3\nsystem_usec 2\n"),
            Ok(want)
        );
        assert_eq!(
            parse_cpu_stat(
                "usage_usec 5\nuser_usec 3\nsystem_usec 2\nnr_bursts 1\nburst_usec 9\ncore_sched.force_idle_usec 0\n"
            ),
            Ok(want)
        );
    }

    /// SUP-10・TASK-167.1: cpu.stat の拒否ケース。
    #[test]
    fn sup10_task167_1_cpu_stat_rejects() {
        for t in [
            "usage_usec 5\nuser_usec 3\n",
            "usage_usec 5\nusage_usec 6\nuser_usec 3\nsystem_usec 2\n",
            "usage_usec x\nuser_usec 3\nsystem_usec 2\n",
            "usage_usec 5 6\nuser_usec 3\nsystem_usec 2\n",
            "usage_usec\nuser_usec 3\nsystem_usec 2\n",
            "usage_usec 18446744073709551616\nuser_usec 3\nsystem_usec 2\n",
            "",
        ] {
            fail(parse_cpu_stat(t), StatsFile::CpuStat);
        }
    }

    fn dev(major: u32, minor: u32) -> IoDeviceStat {
        IoDeviceStat {
            major,
            minor,
            rbytes: None,
            wbytes: None,
            rios: None,
            wios: None,
            dbytes: None,
            dios: None,
        }
    }

    /// SUP-10・TASK-167.1: io.stat の 2 デバイス。
    #[test]
    fn sup10_task167_1_io_stat_two_devices() {
        let text = "8:0 rbytes=1024 wbytes=2048 rios=4 wios=8 dbytes=0 dios=0\n\
259:0 rbytes=10 wbytes=20 rios=1 wios=2 dbytes=3 dios=4\n";
        let got = parse_io_stat(text).unwrap();
        assert_eq!(
            got.devices,
            vec![
                IoDeviceStat {
                    rbytes: Some(1024),
                    wbytes: Some(2048),
                    rios: Some(4),
                    wios: Some(8),
                    dbytes: Some(0),
                    dios: Some(0),
                    ..dev(8, 0)
                },
                IoDeviceStat {
                    rbytes: Some(10),
                    wbytes: Some(20),
                    rios: Some(1),
                    wios: Some(2),
                    dbytes: Some(3),
                    dios: Some(4),
                    ..dev(259, 0)
                },
            ]
        );
    }

    /// SUP-10・TASK-167.1: io.stat の空・未知キー・値なし行。
    #[test]
    fn sup10_task167_1_io_stat_empty_unknown_and_bare() {
        assert_eq!(parse_io_stat(""), Ok(IoStat::default()));
        assert_eq!(parse_io_stat("\n"), Ok(IoStat::default()));
        let got = parse_io_stat("8:16 rbytes=5 cost.usage=77\n9:0\n").unwrap();
        assert_eq!(
            got.devices,
            vec![
                IoDeviceStat {
                    rbytes: Some(5),
                    ..dev(8, 16)
                },
                dev(9, 0)
            ]
        );
    }

    /// SUP-10・TASK-167.1: io.stat の拒否ケース。
    #[test]
    fn sup10_task167_1_io_stat_rejects() {
        for t in [
            "8-0 rbytes=1\n",
            "8: rbytes=1\n",
            "a:0 rbytes=1\n",
            "4294967296:0 rbytes=1\n",
            "8:0 rbytes\n",
            "8:0 rbytes=x\n",
            "8:0 rbytes=1 rbytes=2\n",
            "8:0 rbytes=1\n8:0 wbytes=2\n",
            "8:0 rbytes=18446744073709551616\n",
        ] {
            fail(parse_io_stat(t), StatsFile::IoStat);
        }
    }

    /// SUP-10・TASK-167.1: デバイス数上限。
    #[test]
    fn sup10_task167_1_io_stat_device_limit() {
        let ok: String = (0..MAX_IO_DEVICES)
            .map(|i| format!("8:{i} rbytes=1\n"))
            .collect();
        assert_eq!(parse_io_stat(&ok).unwrap().devices.len(), MAX_IO_DEVICES);
        let over = format!("{ok}8:{MAX_IO_DEVICES} rbytes=1\n");
        fail(parse_io_stat(&over), StatsFile::IoStat);
    }
}
