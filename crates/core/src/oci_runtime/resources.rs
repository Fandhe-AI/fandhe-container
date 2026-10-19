//! `config.json` の `linux.resources` のうち、cgroup v2 で表せて setter がある項目の検証済みの型
//! （TASK-29 追補・#2019・CORE-3・CORE-4・SEC-1・SUP-13）。
//!
//! # 役割と呼び出し元
//!
//! パーサ（`config.rs`）が `linux.resources` を OCI の意味（符号の約束・swap の合計表現・デバイスごとの
//! 4 項目）のまま正規化してここの型に詰める。OS 非依存（3 OS でビルドする）。cgroup v2 の値への変換と
//! 範囲検査（`cpu.period` の範囲・pids の上限・blkio の重み・デバイス番号の幅）は Linux 限定の
//! `cgroups::ResourceLimitPlan` が担い、`create` の `validate_bundle` が Linux では変換を試して範囲外を
//! create の時点で拒否する。supervisor の start 経路は `load_resource_limits` で本型を取り出して plan を組み、
//! `cgroups::CgroupPrepared::apply_limits` で委譲 cgroup の制限ファイルへ書く。
//!
//! # 正規化の規則（OCI → cgroup v2）
//!
//! | OCI | 本型 | 備考 |
//! | --- | --- | --- |
//! | `memory.limit` | `memory_max` | `-1` は `Max`、`> 0` は `Bytes`。`0` と `< -1` は拒否 |
//! | `memory.swap`（メモリ+swap の合計） | `memory_swap_max`（swap 単体） | `-1` は `Max`。`> 0` は `limit` が `Bytes` かつ `swap >= limit` のとき `swap - limit`（runc の v2 変換と同じ）。それ以外は拒否 |
//! | `cpu.quota` / `cpu.period` | そのまま | quota は `-1` か `> 0`。period の範囲は plan が検査 |
//! | `pids.limit` | `pids_limit` | `-1` か `> 0`。上限は plan が検査 |
//! | `blockIO.weight` | `blkio_weight` | 範囲（10..=1000）は plan が検査 |
//! | `blockIO.throttle*Device[]` | デバイスごとにまとめた [`IoThrottle`] | rate の `0` と `u64::MAX` は拒否。同じリスト内の重複デバイスは拒否 |
//!
//! # 契約
//!
//! 未対応の既知項目は `OciConfig::unapplied_fields` に記録され、`create` / `start` が `Unimplemented` で拒否する。
//! エラーは固定のキー名だけを持ち、入力値を含めない（ERR-1）。

/// バイト数の上限値（`memory.max` / `memory.swap.max` に対応）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ByteLimit {
    /// 無制限（`max`）。
    Max,
    /// バイト数（`> 0`）。
    Bytes(u64),
}

/// 1 ブロックデバイス分の `io.max` 相当の指定。指定の無い項目は `None`（無制限として書く）。
///
/// デバイス番号は `u32` に収まることだけを検証済みで、`dev_t` の幅の検査は plan が行う。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct IoThrottle {
    pub(super) major: u32,
    pub(super) minor: u32,
    pub(super) rbps: Option<u64>,
    pub(super) wbps: Option<u64>,
    pub(super) riops: Option<u64>,
    pub(super) wiops: Option<u64>,
}

impl IoThrottle {
    pub(super) fn new(major: u32, minor: u32) -> Self {
        Self {
            major,
            minor,
            rbps: None,
            wbps: None,
            riops: None,
            wiops: None,
        }
    }

    /// デバイスの major 番号。
    pub fn major(&self) -> u32 {
        self.major
    }

    /// デバイスの minor 番号。
    pub fn minor(&self) -> u32 {
        self.minor
    }

    /// `throttleReadBpsDevice` の rate（bytes/s）。
    pub fn rbps(&self) -> Option<u64> {
        self.rbps
    }

    /// `throttleWriteBpsDevice` の rate（bytes/s）。
    pub fn wbps(&self) -> Option<u64> {
        self.wbps
    }

    /// `throttleReadIOPSDevice` の rate（IOPS）。
    pub fn riops(&self) -> Option<u64> {
        self.riops
    }

    /// `throttleWriteIOPSDevice` の rate（IOPS）。
    pub fn wiops(&self) -> Option<u64> {
        self.wiops
    }
}

/// 検証済みの `linux.resources`（受理する項目のみ）。`linux.resources` キー自体が無い config では
/// `OciConfig::linux_resources` が `None` になり、`{}` は全項目 `None`・空の `Some` になる。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct LinuxResourceLimits {
    pub(super) memory_max: Option<ByteLimit>,
    pub(super) memory_swap_max: Option<ByteLimit>,
    pub(super) cpu_quota: Option<i64>,
    pub(super) cpu_period: Option<u64>,
    pub(super) pids_limit: Option<i64>,
    pub(super) blkio_weight: Option<u16>,
    pub(super) io_throttles: Vec<IoThrottle>,
}

impl LinuxResourceLimits {
    /// `memory.max` に書く値。
    pub fn memory_max(&self) -> Option<ByteLimit> {
        self.memory_max
    }

    /// `memory.swap.max` に書く値（OCI の合計表現から swap 単体へ変換済み）。
    pub fn memory_swap_max(&self) -> Option<ByteLimit> {
        self.memory_swap_max
    }

    /// `cpu.quota`（µs。`-1` は無制限）。
    pub fn cpu_quota(&self) -> Option<i64> {
        self.cpu_quota
    }

    /// `cpu.period`（µs）。
    pub fn cpu_period(&self) -> Option<u64> {
        self.cpu_period
    }

    /// `pids.limit`（`-1` は無制限）。
    pub fn pids_limit(&self) -> Option<i64> {
        self.pids_limit
    }

    /// `blockIO.weight`。
    pub fn blkio_weight(&self) -> Option<u16> {
        self.blkio_weight
    }

    /// デバイスごとにまとめた throttle（`(major, minor)` の昇順）。
    pub fn io_throttles(&self) -> &[IoThrottle] {
        &self.io_throttles
    }
}

/// `linux.cgroupsPath`（上限つきの文字列。空と NUL は拒否済み）。
///
/// 値を配置に使わない方針（#2010）で、指定があれば `cgroup_requirement::check_cgroups_path` が拒否する。
/// 受理に開くなら委譲スコープ配下に閉じる検証（スコープ外へ出る経路の拒否）が前提になる。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CgroupsPath(pub(super) String);

impl CgroupsPath {
    /// 指定された文字列。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
