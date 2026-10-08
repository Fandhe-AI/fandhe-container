//! cgroup v2 統計ファイル（`memory.current`・`cpu.stat`・`io.stat`）の読み取りと型付きパース（SUP-10・TASK-167.1・MS-9）。
//!
//! # 役割
//! `stats` コマンド（SUP-10）の入力側（パース・読み取り）と出力側（JSON Lines 直列化。TASK-167.2）。パース（`&str` → 型）は OS 非依存の純関数で、3 OS の CI で
//! 具体値を照合する。cgroup からの読み取り（`read_cgroup_stats`）は Linux 限定で、core の
//! `ContainerCgroup::read_stat_file`（cgroup ディレクトリ fd 起点の上限付き `openat`）を使う。
//!
//! # 呼び出し文脈・契約
//! - 呼び出し元（予定）: `stats` の CLI 配線。パース・読み取りは型付きの値だけを返し、出力形式は
//!   [`CgroupStats::to_json_line`]（JSON Lines・キー名固定。契約は同メソッドの doc）が決める
//! - 各ファイルが存在しない（controller 未有効）場合は、その項目を `None` にする（0 とは区別する）
//! - カーネル応答は外部入力として扱い、`unwrap` / 添字アクセスを使わず、数値は `u64` / `u32` の範囲で
//!   検証する。形式不正は [`StatsError`]（`FailedPrecondition`・対象ファイル・英語の `message`）
//! - 相手の応答を待たない cgroupfs の擬似ファイル読み取りのみのため、タイムアウトは設けない
//!
//! # 未実装（REPAIR-3）
//! `stats` の CLI 呼び出し配線（`crates/cli` → supervisor の依存は crate 境界の設計判断が先。親 #519）。supervisor が自コンテナの
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
/// 機械可読出力（[`CgroupStats::to_json_line`]）の `schema` 値。出力形式を変えるときは版を上げる。
pub const STATS_SCHEMA: &str = "fandhe-container.stats/v1";

/// `Some(n)` を 10 進の裸の数値、`None` を `null` として追記する。
fn push_opt_u64(buf: &mut String, v: Option<u64>) {
    match v {
        Some(n) => buf.push_str(&n.to_string()),
        None => buf.push_str("null"),
    }
}

/// `"key":value` を追記する。`first` が偽なら先頭に区切りカンマを付ける。
fn push_field(buf: &mut String, first: bool, key: &str, v: Option<u64>) {
    if !first {
        buf.push(',');
    }
    buf.push('"');
    buf.push_str(key);
    buf.push_str("\":");
    push_opt_u64(buf, v);
}

impl CgroupStats {
    /// 機械可読形式（JSON Lines の 1 行）へ直列化する（SUP-10・TASK-167.2・#521）。
    ///
    /// 呼び出し元（予定）は `stats` の CLI 配線（未実装）で、出力先は [`Self::write_json_line`] 経由で
    /// 呼び出し側が決める。契約:
    /// - 1 行 1 JSON オブジェクト・末尾 LF・UTF-8・空白なし。キー順は `schema`・`memory`・`cpu`・`io` 固定
    /// - キー名は cgroup ファイルのキー名のまま。`None`（不存在・controller 未有効・キー欠落）は 0 に
    ///   せず `null`。キー自体は省略しない。`io.devices` は入力の出現順（空配列は `null` と区別する）
    /// - 数値は `u64` / `u32` の 10 進の裸の数値。2^53 を超える値は一部の JSON 実装で精度が落ちる
    ///   ため、利用側は 64 ビット整数として読むこと
    /// - 文字列エスケープは行わない。出力に含まれる文字列は固定の ASCII キーと [`STATS_SCHEMA`] のみで、
    ///   カーネル応答由来の文字列は流れない。文字列フィールドを足す場合はエスケープが必須
    pub fn to_json_line(&self) -> String {
        let mut b = String::with_capacity(256);
        b.push_str("{\"schema\":\"");
        b.push_str(STATS_SCHEMA);
        b.push_str("\",\"memory\":");
        match &self.memory {
            Some(m) => {
                b.push('{');
                push_field(&mut b, true, "current_bytes", Some(m.0));
                b.push('}');
            }
            None => b.push_str("null"),
        }
        b.push_str(",\"cpu\":");
        match &self.cpu {
            Some(c) => {
                b.push('{');
                push_field(&mut b, true, "usage_usec", Some(c.usage_usec));
                push_field(&mut b, false, "user_usec", Some(c.user_usec));
                push_field(&mut b, false, "system_usec", Some(c.system_usec));
                push_field(&mut b, false, "nr_periods", c.nr_periods);
                push_field(&mut b, false, "nr_throttled", c.nr_throttled);
                push_field(&mut b, false, "throttled_usec", c.throttled_usec);
                b.push('}');
            }
            None => b.push_str("null"),
        }
        b.push_str(",\"io\":");
        match &self.io {
            Some(io) => {
                b.push_str("{\"devices\":[");
                for (i, d) in io.devices.iter().enumerate() {
                    if i > 0 {
                        b.push(',');
                    }
                    b.push('{');
                    push_field(&mut b, true, "major", Some(u64::from(d.major)));
                    push_field(&mut b, false, "minor", Some(u64::from(d.minor)));
                    push_field(&mut b, false, "rbytes", d.rbytes);
                    push_field(&mut b, false, "wbytes", d.wbytes);
                    push_field(&mut b, false, "rios", d.rios);
                    push_field(&mut b, false, "wios", d.wios);
                    push_field(&mut b, false, "dbytes", d.dbytes);
                    push_field(&mut b, false, "dios", d.dios);
                    b.push('}');
                }
                b.push_str("]}");
            }
            None => b.push_str("null"),
        }
        b.push_str("}\n");
        b
    }

    /// [`Self::to_json_line`] の結果を 1 回の `write_all` で `out` へ書く（SUP-10・TASK-167.2）。
    ///
    /// 出力先（stdout・ファイル等）は呼び出し側が決める。書き込み失敗は `io::Error` で返し panic しない。
    pub fn write_json_line(&self, out: &mut dyn std::io::Write) -> std::io::Result<()> {
        out.write_all(self.to_json_line().as_bytes())
    }
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
    // ---- TASK-167.2: JSON 出力 ----

    /// テスト専用の最小 JSON 値木。
    #[derive(Debug, PartialEq)]
    enum J {
        Null,
        Bool(bool),
        Num(String),
        Str(String),
        Arr(Vec<J>),
        Obj(Vec<(String, J)>),
    }

    /// RFC 8259 準拠の最小再帰下降パーサ（serde を使えない supervisor 用の受け入れ検査器）。
    struct P<'a> {
        s: &'a [u8],
        i: usize,
    }

    impl P<'_> {
        fn ws(&mut self) {
            while matches!(self.s.get(self.i), Some(b' ' | b'\t' | b'\n' | b'\r')) {
                self.i += 1;
            }
        }
        fn eat(&mut self, c: u8) -> Result<(), String> {
            if self.s.get(self.i) == Some(&c) {
                self.i += 1;
                Ok(())
            } else {
                Err(format!("expected {} at {}", c as char, self.i))
            }
        }
        fn lit(&mut self, w: &str, v: J) -> Result<J, String> {
            if self.s.get(self.i..self.i + w.len()) == Some(w.as_bytes()) {
                self.i += w.len();
                Ok(v)
            } else {
                Err(format!("bad literal at {}", self.i))
            }
        }
        fn value(&mut self, depth: usize) -> Result<J, String> {
            if depth > 32 {
                return Err("too deep".into());
            }
            self.ws();
            match self.s.get(self.i) {
                Some(b'{') => {
                    self.i += 1;
                    let mut m: Vec<(String, J)> = Vec::new();
                    self.ws();
                    if self.s.get(self.i) == Some(&b'}') {
                        self.i += 1;
                        return Ok(J::Obj(m));
                    }
                    loop {
                        self.ws();
                        let k = self.string()?;
                        if m.iter().any(|(e, _)| *e == k) {
                            return Err(format!("duplicate key {k}"));
                        }
                        self.ws();
                        self.eat(b':')?;
                        let v = self.value(depth + 1)?;
                        m.push((k, v));
                        self.ws();
                        match self.s.get(self.i) {
                            Some(b',') => self.i += 1,
                            Some(b'}') => {
                                self.i += 1;
                                return Ok(J::Obj(m));
                            }
                            _ => return Err(format!("bad object at {}", self.i)),
                        }
                    }
                }
                Some(b'[') => {
                    self.i += 1;
                    let mut a = Vec::new();
                    self.ws();
                    if self.s.get(self.i) == Some(&b']') {
                        self.i += 1;
                        return Ok(J::Arr(a));
                    }
                    loop {
                        a.push(self.value(depth + 1)?);
                        self.ws();
                        match self.s.get(self.i) {
                            Some(b',') => self.i += 1,
                            Some(b']') => {
                                self.i += 1;
                                return Ok(J::Arr(a));
                            }
                            _ => return Err(format!("bad array at {}", self.i)),
                        }
                    }
                }
                Some(b'"') => Ok(J::Str(self.string()?)),
                Some(b't') => self.lit("true", J::Bool(true)),
                Some(b'f') => self.lit("false", J::Bool(false)),
                Some(b'n') => self.lit("null", J::Null),
                Some(b'-' | b'0'..=b'9') => self.number(),
                _ => Err(format!("unexpected at {}", self.i)),
            }
        }
        fn digits(&mut self) -> Result<(), String> {
            let st = self.i;
            while matches!(self.s.get(self.i), Some(b'0'..=b'9')) {
                self.i += 1;
            }
            if self.i == st {
                Err(format!("digits expected at {}", self.i))
            } else {
                Ok(())
            }
        }
        fn number(&mut self) -> Result<J, String> {
            let st = self.i;
            if self.s.get(self.i) == Some(&b'-') {
                self.i += 1;
            }
            if self.s.get(self.i) == Some(&b'0') {
                self.i += 1;
            } else {
                self.digits()?;
            }
            if self.s.get(self.i) == Some(&b'.') {
                self.i += 1;
                self.digits()?;
            }
            if matches!(self.s.get(self.i), Some(b'e' | b'E')) {
                self.i += 1;
                if matches!(self.s.get(self.i), Some(b'+' | b'-')) {
                    self.i += 1;
                }
                self.digits()?;
            }
            let t = std::str::from_utf8(&self.s[st..self.i]).map_err(|e| e.to_string())?;
            Ok(J::Num(t.to_string()))
        }
        fn string(&mut self) -> Result<String, String> {
            self.eat(b'"')?;
            let mut out: Vec<u8> = Vec::new();
            loop {
                let c = *self.s.get(self.i).ok_or("unterminated string")?;
                self.i += 1;
                match c {
                    b'"' => return String::from_utf8(out).map_err(|e| e.to_string()),
                    0..=0x1f => return Err("control char in string".into()),
                    b'\\' => {
                        let e = *self.s.get(self.i).ok_or("bad escape")?;
                        self.i += 1;
                        match e {
                            b'"' | b'\\' | b'/' => out.push(e),
                            b'b' => out.push(8),
                            b'f' => out.push(12),
                            b'n' => out.push(b'\n'),
                            b'r' => out.push(b'\r'),
                            b't' => out.push(b'\t'),
                            b'u' => {
                                let h = self.s.get(self.i..self.i + 4).ok_or("bad u escape")?;
                                let h = std::str::from_utf8(h).map_err(|e| e.to_string())?;
                                if !h.bytes().all(|b| b.is_ascii_hexdigit()) {
                                    return Err("bad u escape".into());
                                }
                                let cp = u32::from_str_radix(h, 16).map_err(|e| e.to_string())?;
                                self.i += 4;
                                let ch = char::from_u32(cp).unwrap_or('\u{fffd}');
                                let mut buf = [0u8; 4];
                                out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                            }
                            _ => return Err("bad escape".into()),
                        }
                    }
                    _ => out.push(c),
                }
            }
        }
    }

    fn parse_json(s: &str) -> Result<J, String> {
        let mut p = P {
            s: s.as_bytes(),
            i: 0,
        };
        let v = p.value(0)?;
        p.ws();
        if p.i != s.len() {
            return Err(format!("trailing data at {}", p.i));
        }
        Ok(v)
    }

    fn obj(v: &J) -> &Vec<(String, J)> {
        match v {
            J::Obj(m) => m,
            other => panic!("not an object: {other:?}"),
        }
    }

    fn get<'a>(v: &'a J, k: &str) -> &'a J {
        match obj(v).iter().find(|(e, _)| e == k) {
            Some((_, x)) => x,
            None => panic!("missing key {k}"),
        }
    }

    fn num(v: &J) -> &str {
        match v {
            J::Num(n) => n,
            other => panic!("not a number: {other:?}"),
        }
    }

    /// 検査器の自己テスト（検査器の欠陥で受け入れテストが空振りしないことの担保）。
    #[test]
    fn sup10_task167_2_json_checker_self_test() {
        for ok in [
            "{}",
            "[]",
            " null ",
            "{\"a\":[1,-2.5e+3,true,false,null,\"x\\n\\u0041\"],\"b\":{}}",
            "0",
        ] {
            assert!(parse_json(ok).is_ok(), "{ok}");
        }
        for bad in [
            "{\"a\":1,}",
            "[1,]",
            "{\"a\":1",
            "{a:1}",
            "01",
            "{} x",
            "{'a':1}",
            "{\"a\":1,\"a\":2}",
            "\"a\nb\"",
            "[1 2]",
            "-",
            "1.",
            "",
        ] {
            assert!(parse_json(bad).is_err(), "{bad}");
        }
    }

    fn full_stats() -> CgroupStats {
        CgroupStats {
            memory: Some(MemoryCurrent(12_345_678)),
            cpu: Some(CpuStat {
                usage_usec: 1000,
                user_usec: 600,
                system_usec: 400,
                nr_periods: Some(10),
                nr_throttled: Some(2),
                throttled_usec: Some(350),
            }),
            io: Some(IoStat {
                devices: vec![
                    IoDeviceStat {
                        major: 8,
                        minor: 0,
                        rbytes: Some(1024),
                        wbytes: Some(2048),
                        rios: Some(4),
                        wios: Some(8),
                        dbytes: Some(0),
                        dios: Some(0),
                    },
                    IoDeviceStat {
                        major: 259,
                        minor: 1,
                        rbytes: Some(1),
                        wbytes: Some(2),
                        rios: Some(3),
                        wios: Some(4),
                        dbytes: Some(5),
                        dios: Some(6),
                    },
                ],
            }),
        }
    }

    /// SUP-10・TASK-167.2: 全項目ありの完全一致。
    #[test]
    fn sup10_task167_2_json_full_exact() {
        assert_eq!(
            full_stats().to_json_line(),
            concat!(
                "{\"schema\":\"fandhe-container.stats/v1\",",
                "\"memory\":{\"current_bytes\":12345678},",
                "\"cpu\":{\"usage_usec\":1000,\"user_usec\":600,\"system_usec\":400,",
                "\"nr_periods\":10,\"nr_throttled\":2,\"throttled_usec\":350},",
                "\"io\":{\"devices\":[",
                "{\"major\":8,\"minor\":0,\"rbytes\":1024,\"wbytes\":2048,\"rios\":4,\"wios\":8,\"dbytes\":0,\"dios\":0},",
                "{\"major\":259,\"minor\":1,\"rbytes\":1,\"wbytes\":2,\"rios\":3,\"wios\":4,\"dbytes\":5,\"dios\":6}",
                "]}}\n"
            )
        );
    }

    /// SUP-10・TASK-167.2: 全項目なしは `null`（0 にしない）。
    #[test]
    fn sup10_task167_2_json_all_absent_exact() {
        assert_eq!(
            CgroupStats::default().to_json_line(),
            "{\"schema\":\"fandhe-container.stats/v1\",\"memory\":null,\"cpu\":null,\"io\":null}\n"
        );
    }

    /// SUP-10・TASK-167.2: 欠落キーは `null`・値なしデバイスも出力する。
    #[test]
    fn sup10_task167_2_json_partial_nulls_exact() {
        let s = CgroupStats {
            memory: None,
            cpu: Some(CpuStat {
                usage_usec: 5,
                user_usec: 3,
                system_usec: 2,
                nr_periods: None,
                nr_throttled: None,
                throttled_usec: None,
            }),
            io: Some(IoStat {
                devices: vec![IoDeviceStat {
                    major: 9,
                    minor: 0,
                    rbytes: None,
                    wbytes: Some(7),
                    rios: None,
                    wios: None,
                    dbytes: None,
                    dios: None,
                }],
            }),
        };
        assert_eq!(
            s.to_json_line(),
            concat!(
                "{\"schema\":\"fandhe-container.stats/v1\",\"memory\":null,",
                "\"cpu\":{\"usage_usec\":5,\"user_usec\":3,\"system_usec\":2,",
                "\"nr_periods\":null,\"nr_throttled\":null,\"throttled_usec\":null},",
                "\"io\":{\"devices\":[{\"major\":9,\"minor\":0,\"rbytes\":null,\"wbytes\":7,",
                "\"rios\":null,\"wios\":null,\"dbytes\":null,\"dios\":null}]}}\n"
            )
        );
    }

    /// SUP-10・TASK-167.2: デバイスなしの io は空配列（`null` と区別）。
    #[test]
    fn sup10_task167_2_json_empty_devices_exact() {
        let s = CgroupStats {
            io: Some(IoStat::default()),
            ..CgroupStats::default()
        };
        assert_eq!(
            s.to_json_line(),
            "{\"schema\":\"fandhe-container.stats/v1\",\"memory\":null,\"cpu\":null,\"io\":{\"devices\":[]}}\n"
        );
    }

    /// SUP-10・TASK-167.2: 出力が JSON として妥当にパースでき、構造が契約どおり（受け入れ条件）。
    #[test]
    fn sup10_task167_2_json_is_valid_json() {
        let dev = IoDeviceStat {
            major: u32::MAX,
            minor: u32::MAX,
            rbytes: Some(u64::MAX),
            wbytes: Some(u64::MAX),
            rios: Some(u64::MAX),
            wios: Some(u64::MAX),
            dbytes: Some(u64::MAX),
            dios: Some(u64::MAX),
        };
        let max = CgroupStats {
            memory: Some(MemoryCurrent(u64::MAX)),
            cpu: Some(CpuStat {
                usage_usec: u64::MAX,
                user_usec: u64::MAX,
                system_usec: u64::MAX,
                nr_periods: Some(u64::MAX),
                nr_throttled: Some(u64::MAX),
                throttled_usec: Some(u64::MAX),
            }),
            io: Some(IoStat {
                devices: vec![dev; MAX_IO_DEVICES],
            }),
        };
        for s in [
            full_stats(),
            CgroupStats::default(),
            CgroupStats {
                io: Some(IoStat::default()),
                ..CgroupStats::default()
            },
            max,
        ] {
            let line = s.to_json_line();
            let v = parse_json(&line).expect("valid json");
            let keys: Vec<&str> = obj(&v).iter().map(|(k, _)| k.as_str()).collect();
            assert_eq!(keys, ["schema", "memory", "cpu", "io"]);
            assert_eq!(get(&v, "schema"), &J::Str(STATS_SCHEMA.to_string()));
            let want = s.io.as_ref().map(|io| io.devices.len());
            match (get(&v, "io"), want) {
                (J::Null, None) => {}
                (io, Some(n)) => match get(io, "devices") {
                    J::Arr(a) => assert_eq!(a.len(), n),
                    other => panic!("devices not array: {other:?}"),
                },
                other => panic!("io mismatch: {other:?}"),
            }
        }
    }

    /// SUP-10・TASK-167.2: 出力値が元の構造体の値と 1 つずつ一致する（`u64::MAX` を丸めない）。
    #[test]
    fn sup10_task167_2_json_round_trip_values() {
        let s = CgroupStats {
            memory: Some(MemoryCurrent(u64::MAX)),
            cpu: Some(CpuStat {
                usage_usec: 1,
                user_usec: 2,
                system_usec: 3,
                nr_periods: Some(u64::MAX),
                nr_throttled: None,
                throttled_usec: Some(6),
            }),
            io: Some(IoStat {
                devices: vec![IoDeviceStat {
                    major: u32::MAX,
                    minor: 1,
                    rbytes: Some(u64::MAX),
                    wbytes: None,
                    rios: Some(3),
                    wios: Some(4),
                    dbytes: Some(5),
                    dios: Some(6),
                }],
            }),
        };
        let v = parse_json(&s.to_json_line()).expect("valid json");
        assert_eq!(
            num(get(get(&v, "memory"), "current_bytes")),
            "18446744073709551615"
        );
        let cpu = get(&v, "cpu");
        assert_eq!(num(get(cpu, "usage_usec")), "1");
        assert_eq!(num(get(cpu, "user_usec")), "2");
        assert_eq!(num(get(cpu, "system_usec")), "3");
        assert_eq!(num(get(cpu, "nr_periods")), "18446744073709551615");
        assert_eq!(get(cpu, "nr_throttled"), &J::Null);
        assert_eq!(num(get(cpu, "throttled_usec")), "6");
        let J::Arr(devs) = get(get(&v, "io"), "devices") else {
            panic!("devices not array");
        };
        let d = devs.first().expect("one device");
        assert_eq!(num(get(d, "major")), "4294967295");
        assert_eq!(num(get(d, "minor")), "1");
        assert_eq!(num(get(d, "rbytes")), "18446744073709551615");
        assert_eq!(get(d, "wbytes"), &J::Null);
        assert_eq!(num(get(d, "rios")), "3");
        assert_eq!(num(get(d, "wios")), "4");
        assert_eq!(num(get(d, "dbytes")), "5");
        assert_eq!(num(get(d, "dios")), "6");
    }

    /// SUP-10・TASK-167.2: 1 行・LF 終端・ASCII のみ。
    #[test]
    fn sup10_task167_2_json_single_line_lf() {
        let line = full_stats().to_json_line();
        assert!(line.ends_with('\n'));
        assert_eq!(line.matches('\n').count(), 1);
        assert!(!line.contains('\r'));
        assert!(line.is_ascii());
    }

    /// SUP-10・TASK-167.2: cgroup ファイル形式の文字列 → パース → JSON の一貫経路。
    #[test]
    fn sup10_task167_2_parse_then_json() {
        let s = CgroupStats {
            memory: Some(parse_memory_current("4096\n").expect("memory")),
            cpu: Some(
                parse_cpu_stat("usage_usec 100\nuser_usec 60\nsystem_usec 40\n").expect("cpu"),
            ),
            io: Some(
                parse_io_stat("8:16 rbytes=10 wbytes=20 rios=1 wios=2 dbytes=0 dios=0\n")
                    .expect("io"),
            ),
        };
        assert_eq!(
            s.to_json_line(),
            concat!(
                "{\"schema\":\"fandhe-container.stats/v1\",\"memory\":{\"current_bytes\":4096},",
                "\"cpu\":{\"usage_usec\":100,\"user_usec\":60,\"system_usec\":40,",
                "\"nr_periods\":null,\"nr_throttled\":null,\"throttled_usec\":null},",
                "\"io\":{\"devices\":[{\"major\":8,\"minor\":16,\"rbytes\":10,\"wbytes\":20,",
                "\"rios\":1,\"wios\":2,\"dbytes\":0,\"dios\":0}]}}\n"
            )
        );
    }

    struct FailWriter;
    impl std::io::Write for FailWriter {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("fail"))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// SUP-10・TASK-167.2: `write_json_line` の書き込み内容とエラー伝播。
    #[test]
    fn sup10_task167_2_write_json_line() {
        let s = full_stats();
        let mut buf: Vec<u8> = Vec::new();
        s.write_json_line(&mut buf).expect("write");
        assert_eq!(buf, s.to_json_line().into_bytes());
        assert!(s.write_json_line(&mut FailWriter).is_err());
    }
}
