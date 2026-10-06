//! `--shm-size` / `--tmpfs` の解析（SUP-12・TASK-169.2・MS-9）。
//!
//! # 役割と呼び出し文脈
//!
//! CLI（TASK-79）や stack（TOML）が渡す Docker 互換の文字列を解析し、`fandhe-container-core` の
//! [`TmpfsMountSet`]（検証済みの仕様型）へ変換する。実マウントは core の `exec::mount_tmpfs` が
//! 「`prepare_rootfs` の後・`pivot_root` の前」で行う。本モジュールは OS 非依存の純粋な解析のみで、
//! `cfg` 分岐も `unsafe` も持たない。
//!
//! # 文法
//!
//! - `--shm-size <N>[b|k|kb|m|mb|g|gb]`: 10 進整数＋任意の単位（大文字小文字非区別・1024 進）。単位なしは
//!   バイト。0・小数・`%`・負値・空文字・桁あふれは拒否する
//! - `--tmpfs <dest>[:<opt>,...]`: 許可オプションは閉じた一覧（`rw`・`ro`・`exec`・`noexec`・`nosuid`・
//!   `nodev`・`size=<値>`・`mode=<8 進>`）。既定は `nosuid,nodev,noexec`（`nosuid`・`nodev` は常に付与）。
//!   `suid`・`dev` を含む未知のキーは拒否する。`size=` と `mode=` の重複も拒否する
//!
//! # 未対応（REPAIR-3: 実装済みを装わない）
//!
//! - 本番 launcher・CLI・stack（TOML）からの配線（TASK-79・TASK-169 の後続）
//! - `--shm-size` 未指定時に `/dev/shm` を既定 [`DEFAULT_SHM_SIZE_BYTES`] で常時マウントする挙動
//!   （launcher 配線と同時に決める）。サイズ未指定の `--tmpfs` はカーネル既定（Docker と同じ）
//! - `uid=`・`gid=`・`%` 指定・小数サイズ・`suid` / `dev` の許可
//! - `--ipc=host` / `shareable` と shm の関係（TASK-169.3）

use fandhe_container_core::tmpfs::{
    DEV_SHM_PATH, TmpfsMode, TmpfsMountSet, TmpfsMountSpec, TmpfsSize,
};
use fandhe_container_core::traits::{ErrorCode, TraitError};

/// Docker の `/dev/shm` 既定サイズ（64 MiB）。
pub const DEFAULT_SHM_SIZE_BYTES: u64 = 64 * 1024 * 1024;

/// `--tmpfs` 1 件の入力長上限（core の `CONFIG_MAX_PATH_BYTES` と同じ値）。
const MAX_OPTION_BYTES: usize = 4096;

/// `--tmpfs` 1 件のオプション数上限（core の `CONFIG_MAX_MOUNT_OPTIONS` と同じ値）。
const MAX_OPTION_ITEMS: usize = 64;

fn invalid(msg: impl Into<String>) -> TraitError {
    TraitError::new(ErrorCode::InvalidArgument, msg)
}

/// `--shm-size` の値（検証済み）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShmSize(TmpfsSize);

impl ShmSize {
    /// `64m`・`1g`・`65536k`・`1024` 等を解析する。
    pub fn parse(text: &str) -> Result<Self, TraitError> {
        parse_size(text).map(Self)
    }

    /// バイト数。
    pub fn bytes(self) -> u64 {
        self.0.bytes()
    }
}

/// サイズ文字列を [`TmpfsSize`] にする（`--shm-size` と `--tmpfs` の `size=` で共通）。
fn parse_size(text: &str) -> Result<TmpfsSize, TraitError> {
    let lower = text.to_ascii_lowercase();
    let split = lower
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(lower.len());
    let (digits, unit) = lower.split_at(split);
    if digits.is_empty() {
        return Err(invalid("size must start with a decimal integer"));
    }
    let multiplier: u64 = match unit {
        "" | "b" => 1,
        "k" | "kb" => 1024,
        "m" | "mb" => 1024 * 1024,
        "g" | "gb" => 1024 * 1024 * 1024,
        _ => return Err(invalid("size has an unsupported unit")),
    };
    let value: u64 = digits
        .parse()
        .map_err(|_| invalid("size is not a valid integer"))?;
    let bytes = value
        .checked_mul(multiplier)
        .ok_or_else(|| invalid("size overflows"))?;
    TmpfsSize::from_bytes(bytes)
}

/// `--tmpfs <dest>[:<opt>,...]` 1 件（検証済み）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TmpfsOption(TmpfsMountSpec);

impl TmpfsOption {
    /// `/run:rw,noexec,nosuid,size=65536k` 形式を解析する。
    pub fn parse(text: &str) -> Result<Self, TraitError> {
        if text.len() > MAX_OPTION_BYTES {
            return Err(invalid("tmpfs option is too long"));
        }
        let (dest, rest) = text.split_once(':').unwrap_or((text, ""));
        let mut spec = TmpfsMountSpec::new(dest, None)?;
        if rest.is_empty() {
            return Ok(Self(spec));
        }
        let items: Vec<&str> = rest.split(',').collect();
        if items.len() > MAX_OPTION_ITEMS {
            return Err(invalid("too many tmpfs options"));
        }
        let (mut size_seen, mut mode_seen) = (false, false);
        for item in items {
            match item {
                "rw" => spec.read_only = false,
                "ro" => spec.read_only = true,
                "exec" => spec.exec = true,
                "noexec" => spec.exec = false,
                // 常に付与されるため受理するだけ（外す指定 `suid`・`dev` は未知として拒否する）。
                "nosuid" | "nodev" => {}
                _ => {
                    if let Some(v) = item.strip_prefix("size=") {
                        if std::mem::replace(&mut size_seen, true) {
                            return Err(invalid("duplicate tmpfs option: size"));
                        }
                        spec.size = Some(parse_size(v)?);
                    } else if let Some(v) = item.strip_prefix("mode=") {
                        if std::mem::replace(&mut mode_seen, true) {
                            return Err(invalid("duplicate tmpfs option: mode"));
                        }
                        let bits = u32::from_str_radix(v, 8)
                            .map_err(|_| invalid("tmpfs mode must be an octal number"))?;
                        spec.mode = TmpfsMode::new(bits)?;
                    } else {
                        return Err(invalid("unsupported tmpfs option"));
                    }
                }
            }
        }
        Ok(Self(spec))
    }

    /// core の仕様型。
    pub fn spec(&self) -> &TmpfsMountSpec {
        &self.0
    }
}

/// マウント系オプション（`--shm-size`・`--tmpfs`）の束。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct MountOptions {
    /// `--shm-size`。
    pub shm_size: Option<ShmSize>,
    /// `--tmpfs`（指定順）。
    pub tmpfs: Vec<TmpfsOption>,
}

impl MountOptions {
    /// `--shm-size` を設定する（`non_exhaustive` のため外部 crate はビルダ経由で組み立てる）。
    #[must_use]
    pub fn with_shm_size(mut self, size: ShmSize) -> Self {
        self.shm_size = Some(size);
        self
    }

    /// `--tmpfs` を 1 件追加する（指定順）。
    #[must_use]
    pub fn with_tmpfs(mut self, tmpfs: TmpfsOption) -> Self {
        self.tmpfs.push(tmpfs);
        self
    }

    /// core の [`TmpfsMountSet`] へ変換する。`shm_size` 指定時は `/dev/shm` を先頭に置く。
    /// `--tmpfs /dev/shm` との同時指定は重複として拒否する（予約先・件数上限も core が検証する）。
    pub fn to_tmpfs_set(&self) -> Result<TmpfsMountSet, TraitError> {
        let mut set = TmpfsMountSet::new();
        if let Some(shm) = self.shm_size {
            set.push(TmpfsMountSpec::dev_shm(TmpfsSize::from_bytes(
                shm.bytes(),
            )?)?)?;
        }
        for t in &self.tmpfs {
            if self.shm_size.is_some() && t.spec().destination.as_str() == DEV_SHM_PATH {
                return Err(invalid(
                    "--tmpfs /dev/shm conflicts with --shm-size; specify only one",
                ));
            }
            set.push(t.spec().clone())?;
        }
        Ok(set)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SUP-12・TASK-169.2: 単位ごとの具体値。
    #[test]
    fn sup12_task169_2_shm_size_values() {
        for (text, bytes) in [
            ("64m", 67_108_864),
            ("64MB", 67_108_864),
            ("1g", 1_073_741_824),
            ("65536k", 67_108_864),
            ("1024", 1024),
            ("1b", 1),
            ("2Kb", 2048),
        ] {
            assert_eq!(ShmSize::parse(text).expect(text).bytes(), bytes, "{text}");
        }
    }

    /// SUP-12・TASK-169.2: 不正値の拒否（0・小数・%・負・桁あふれ・空・単位違い）。
    #[test]
    fn sup12_task169_2_shm_size_rejects() {
        for bad in [
            "0",
            "0m",
            "1.5g",
            "50%",
            "-1",
            "",
            "m",
            "1t",
            "1 m",
            "18446744073709551616",
            "17179869184g",
            "9223372036854775808",
        ] {
            let e = ShmSize::parse(bad).expect_err(bad);
            assert_eq!(e.code(), ErrorCode::InvalidArgument, "{bad}");
        }
    }

    /// SUP-12・TASK-169.2: 完全な `--tmpfs` 指定が仕様型と一致する。
    #[test]
    fn sup12_task169_2_tmpfs_full_option() {
        let t = TmpfsOption::parse("/run:rw,exec,nosuid,size=65536k,mode=755").expect("parse");
        let s = t.spec();
        assert_eq!(s.destination.as_str(), "/run");
        assert_eq!(s.size.map(|x| x.bytes()), Some(67_108_864));
        assert_eq!(s.mode.bits(), 0o755);
        assert!(!s.read_only && s.exec);
        assert_eq!(s.data_string(), "mode=755,size=67108864");
        let d = TmpfsOption::parse("/tmp").expect("default");
        assert!(!d.spec().exec && !d.spec().read_only && d.spec().size.is_none());
        assert!(TmpfsOption::parse("/ro:ro").expect("ro").spec().read_only);
        assert_eq!(
            TmpfsOption::parse("/x:")
                .expect("empty rest")
                .spec()
                .destination
                .as_str(),
            "/x"
        );
    }

    /// SUP-12・TASK-169.2: 未知・危険なオプションと不正な先の拒否。
    #[test]
    fn sup12_task169_2_tmpfs_rejects() {
        let many = format!("/x:{}", vec!["rw"; MAX_OPTION_ITEMS + 1].join(","));
        let long = format!("/{}", "a".repeat(MAX_OPTION_BYTES));
        for bad in [
            "/x:suid",
            "/x:dev",
            "/x:bogus",
            "/x:uid=1000",
            "/x:size=1m,size=2m",
            "/x:mode=1777,mode=755",
            "/x:mode=9",
            "/x:mode=17777",
            "/x:size=0",
            "/x:size=50%",
            "/x:rw,,ro",
            "/a/../b",
            "/",
            "",
            many.as_str(),
            long.as_str(),
        ] {
            let e = TmpfsOption::parse(bad).expect_err(bad);
            assert_eq!(e.code(), ErrorCode::InvalidArgument, "{bad}");
        }
    }

    /// SUP-12・TASK-169.2: shm_size は /dev/shm を先頭に置き、--tmpfs /dev/shm との併用は拒否する。
    #[test]
    fn sup12_task169_2_to_tmpfs_set() {
        let opts = MountOptions {
            shm_size: Some(ShmSize::parse("64m").expect("shm")),
            tmpfs: vec![TmpfsOption::parse("/run:size=1m").expect("run")],
        };
        let set = opts.to_tmpfs_set().expect("set");
        let dests: Vec<&str> = set
            .mounts()
            .iter()
            .map(|m| m.destination.as_str())
            .collect();
        assert_eq!(dests, ["/dev/shm", "/run"]);
        assert_eq!(set.mounts()[0].data_string(), "mode=1777,size=67108864");

        let conflict = MountOptions {
            shm_size: Some(ShmSize::parse("1m").expect("shm")),
            tmpfs: vec![TmpfsOption::parse("/dev/shm").expect("shm tmpfs")],
        };
        assert_eq!(
            conflict.to_tmpfs_set().expect_err("conflict").code(),
            ErrorCode::InvalidArgument
        );
        let reserved = MountOptions {
            shm_size: None,
            tmpfs: vec![TmpfsOption::parse("/proc").expect("proc")],
        };
        assert!(reserved.to_tmpfs_set().is_err());
    }
}
