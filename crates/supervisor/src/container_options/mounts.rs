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
//! - `--ipc=host` と `--shm-size` の併用は `ContainerOptions::tmpfs_set` が拒否する（TASK-169.5.2）。`shareable` との関係は変えない

use fandhe_container_core::tmpfs::{
    DEV_SHM_PATH, TMPFS_MAX_MOUNTS, TmpfsMode, TmpfsMountSet, TmpfsMountSpec, TmpfsSize,
};
use fandhe_container_core::traits::{ErrorCode, TraitError};

/// Docker の `/dev/shm` 既定サイズ（64 MiB）。
pub const DEFAULT_SHM_SIZE_BYTES: u64 = 64 * 1024 * 1024;

/// `--tmpfs` 1 件の入力長上限（core の `CONFIG_MAX_PATH_BYTES` と同じ値）。
const MAX_OPTION_BYTES: usize = 4096;

/// サイズ文字列（`--shm-size`・`size=`）の入力長上限。u64 の 10 進（最大 20 桁）と単位に十分な値で、
/// 小文字化の確保より前に検証して入力長比例の確保を防ぐ（SUP-12・TASK-169.2）。
const MAX_SIZE_TEXT_BYTES: usize = 64;

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
    if text.len() > MAX_SIZE_TEXT_BYTES {
        return Err(invalid("size is too long"));
    }
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
        // 件数は確保せずに数えてから、同じ分割を走査する。
        if rest.split(',').count() > MAX_OPTION_ITEMS {
            return Err(invalid("too many tmpfs options"));
        }
        let (mut size_seen, mut mode_seen) = (false, false);
        for item in rest.split(',') {
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
                        // `from_str_radix` は先頭の `+` を受理するため、8 進数字だけに限ってから解釈する。
                        if v.is_empty() || !v.bytes().all(|b| (b'0'..=b'7').contains(&b)) {
                            return Err(invalid("tmpfs mode must be an octal number"));
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
///
/// フィールドは非公開で、`--tmpfs` の追加は件数上限を検証する [`Self::with_tmpfs`] だけが行う
/// （core の [`TMPFS_MAX_MOUNTS`] を超える件数を保持できない。外部入力の件数に比例した確保を防ぐ）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MountOptions {
    shm_size: Option<ShmSize>,
    tmpfs: Vec<TmpfsOption>,
}

impl MountOptions {
    /// `--shm-size`。
    pub fn shm_size(&self) -> Option<ShmSize> {
        self.shm_size
    }

    /// `--tmpfs`（指定順。[`TMPFS_MAX_MOUNTS`] 件以下）。
    pub fn tmpfs(&self) -> &[TmpfsOption] {
        &self.tmpfs
    }

    /// `--shm-size` を設定する。
    #[must_use]
    pub fn with_shm_size(mut self, size: ShmSize) -> Self {
        self.shm_size = Some(size);
        self
    }

    /// `--tmpfs` を 1 件追加する（指定順）。[`TMPFS_MAX_MOUNTS`] 件を超える追加は確保せずに拒否する。
    pub fn with_tmpfs(mut self, tmpfs: TmpfsOption) -> Result<Self, TraitError> {
        if self.tmpfs.len() >= TMPFS_MAX_MOUNTS {
            return Err(invalid("too many tmpfs mounts"));
        }
        self.tmpfs.push(tmpfs);
        Ok(self)
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
        assert_eq!((s.read_only, s.exec), (false, true));
        assert_eq!(s.data_string(), "mode=755,size=67108864");
        let d = TmpfsOption::parse("/tmp").expect("default");
        assert_eq!(
            (d.spec().exec, d.spec().read_only, d.spec().size),
            (false, false, None)
        );
        assert_eq!(
            TmpfsOption::parse("/ro:ro")
                .expect("ro")
                .spec()
                .data_string(),
            "mode=1777"
        );
        let ro = TmpfsOption::parse("/ro:ro").expect("ro");
        assert_eq!((ro.spec().read_only, ro.spec().exec), (true, false));
        assert_eq!(
            TmpfsOption::parse("/x:")
                .expect("empty rest")
                .spec()
                .destination
                .as_str(),
            "/x"
        );
    }

    /// SUP-12・TASK-169.2: 未知・危険なオプションと不正な先の拒否（message まで具体値で照合）。
    #[test]
    fn sup12_task169_2_tmpfs_rejects() {
        let many = format!("/x:{}", vec!["rw"; MAX_OPTION_ITEMS + 1].join(","));
        let long = format!("/{}", "a".repeat(MAX_OPTION_BYTES));
        let deep = "/d".repeat(33);
        let unsupported = "unsupported tmpfs option";
        let octal = "tmpfs mode must be an octal number";
        let destination = "invalid tmpfs mount destination";
        for (bad, message) in [
            ("/x:suid", unsupported),
            ("/x:dev", unsupported),
            ("/x:bogus", unsupported),
            ("/x:uid=1000", unsupported),
            ("/x:rw,,ro", unsupported),
            ("/x:size=1m,size=2m", "duplicate tmpfs option: size"),
            ("/x:mode=1777,mode=755", "duplicate tmpfs option: mode"),
            ("/x:mode=9", octal),
            ("/x:mode=+777", octal),
            ("/x:mode=", octal),
            ("/x:mode=17777", "tmpfs mode must not exceed 07777"),
            ("/x:size=0", "tmpfs size must be greater than zero"),
            ("/x:size=50%", "size has an unsupported unit"),
            ("/a/../b", destination),
            ("/", destination),
            ("", destination),
            (deep.as_str(), "tmpfs mount destination is too deep"),
            (many.as_str(), "too many tmpfs options"),
            (long.as_str(), "tmpfs option is too long"),
        ] {
            let e = TmpfsOption::parse(bad).expect_err(bad);
            assert_eq!(e.code(), ErrorCode::InvalidArgument, "{bad}");
            assert_eq!(e.message(), message, "{bad}");
        }
        // 上限ちょうど（64 個）は受理する。
        let at_limit = format!("/x:{}", vec!["rw"; MAX_OPTION_ITEMS].join(","));
        assert_eq!(
            TmpfsOption::parse(&at_limit)
                .expect("64 options")
                .spec()
                .destination
                .as_str(),
            "/x"
        );
    }

    /// SUP-12・TASK-169.2: 過長なサイズ文字列は確保前に拒否する。
    #[test]
    fn sup12_task169_2_size_text_too_long_rejected() {
        let long = "1".repeat(MAX_SIZE_TEXT_BYTES + 1);
        let huge = "9".repeat(1_000_000);
        for e in [
            ShmSize::parse(&long).expect_err("long shm-size"),
            TmpfsOption::parse(&format!("/x:size={long}")).expect_err("long size="),
            ShmSize::parse(&huge).expect_err("huge"),
        ] {
            assert_eq!(e.code(), ErrorCode::InvalidArgument);
            assert_eq!(e.message(), "size is too long");
        }
        assert_eq!(ShmSize::parse("64m").expect("ok").bytes(), 67_108_864);
    }

    /// SUP-12・TASK-169.2: shm_size は /dev/shm を先頭に置き、--tmpfs /dev/shm との併用は拒否する。
    #[test]
    fn sup12_task169_2_to_tmpfs_set() {
        let opts = MountOptions::default()
            .with_shm_size(ShmSize::parse("64m").expect("shm"))
            .with_tmpfs(TmpfsOption::parse("/run:size=1m").expect("run"))
            .expect("add");
        assert_eq!(opts.shm_size().map(ShmSize::bytes), Some(67_108_864));
        assert_eq!(opts.tmpfs().len(), 1);
        let set = opts.to_tmpfs_set().expect("set");
        let dests: Vec<&str> = set
            .mounts()
            .iter()
            .map(|m| m.destination.as_str())
            .collect();
        assert_eq!(dests, ["/dev/shm", "/run"]);
        assert_eq!(set.mounts()[0].data_string(), "mode=1777,size=67108864");

        let conflict = MountOptions::default()
            .with_shm_size(ShmSize::parse("1m").expect("shm"))
            .with_tmpfs(TmpfsOption::parse("/dev/shm").expect("shm tmpfs"))
            .expect("add");
        assert_eq!(
            conflict.to_tmpfs_set().expect_err("conflict").code(),
            ErrorCode::InvalidArgument
        );
        let reserved = MountOptions::default()
            .with_tmpfs(TmpfsOption::parse("/proc").expect("proc"))
            .expect("add");
        let e = reserved.to_tmpfs_set().expect_err("reserved");
        assert_eq!(e.code(), ErrorCode::InvalidArgument);
        assert_eq!(e.message(), "tmpfs must not be mounted on /proc or below");
    }

    /// SUP-12・TASK-169.2: `--tmpfs` は上限（64 件）までしか保持せず、65 件目は追加時に拒否する。
    #[test]
    fn sup12_task169_2_with_tmpfs_enforces_count_limit() {
        let mut opts = MountOptions::default();
        for i in 0..TMPFS_MAX_MOUNTS {
            opts = opts
                .with_tmpfs(TmpfsOption::parse(&format!("/m{i}")).expect("parse"))
                .expect("within limit");
        }
        assert_eq!(opts.tmpfs().len(), 64);
        assert_eq!(opts.to_tmpfs_set().expect("set").mounts().len(), 64);
        let e = opts
            .with_tmpfs(TmpfsOption::parse("/extra").expect("parse"))
            .expect_err("over limit");
        assert_eq!(e.code(), ErrorCode::InvalidArgument);
        assert_eq!(e.message(), "too many tmpfs mounts");
    }
}
