//! 読み取り専用にするパスの暗黙の固定集合の唯一の定義（SEC-2・CORE-1・CORE-5・SEC-5・TASK-29 追補・#1850）。
//!
//! # 役割
//!
//! オーナー判断（2026-10-12・#1315）で、OCI の `linux.readonlyPaths` 相当は `config.json` に関係なく
//! ランタイムが常に適用する固定集合になった（`/dev` 系の先例は #1609 と [`crate::dev_mounts`]）。
//! 対象のパスをここに 1 か所で持つ。定義と適用を分け、適用側は `crate::exec` の
//! `run_pre_pivot` の段（`readonly_paths`）が担う。OS に依存しない純粋な定数と関数だけを置く。
//!
//! # 出典
//!
//! moby/moby の `daemon/pkg/oci/defaults.go`（commit `9fabd6dfbb926381278c436a866bc8d6ac222274`、Apache-2.0）の
//! `ReadonlyPaths` の一覧を写し、`/proc` 配下に絞った。写したのはパス文字列だけで、ロジックは写していない。
//! containerd の `pkg/oci/spec.go` の既定も同じ 5 件である。帰属表示はルートの `NOTICE` を参照する。
//!
//! # 未実装（REPAIR-3: 実装済みを装わない）
//!
//! - `/sys` 配下の個別項目: moby の一覧に `/sys` 配下は無い。実行層が sysfs を供給する時点（TASK-127）で
//!   足す。現状は rootfs の `/sys` を mount top ごと読み取り専用にするだけ（[`READONLY_SYS_PATH`]）
//! - config の `readonlyPaths` の解釈は #1852
//!
//! 覆う側（`maskedPaths` 相当）の固定集合は同じ置き場所の [`MASKED_PROC_PATHS`]（#1851）。

/// `/proc` 配下の読み取り専用にするパス（moby の `ReadonlyPaths` の写し。適用順もこの並び）。
pub const READONLY_PROC_PATHS: [&str; 5] = [
    "/proc/bus",
    "/proc/fs",
    "/proc/irq",
    "/proc/sys",
    "/proc/sysrq-trigger",
];

/// 覆う（中身を見せない）`/proc` 配下のパス（SEC-2・CORE-1・CORE-5・SEC-5・TASK-29 追補・#1851）。
///
/// OCI の `linux.maskedPaths` 相当。オーナー判断（2026-10-12・#1315）で `config.json` に関係なくランタイムが
/// 常に適用する固定集合になった。適用は `crate::exec` の `run_pre_pivot` の `masked_paths` 段が担う。
///
/// # 出典
///
/// moby/moby の `daemon/pkg/oci/defaults.go`（commit `9fabd6dfbb926381278c436a866bc8d6ac222274`、Apache-2.0）の
/// `MaskedPaths` の一覧を写し、`/proc` 配下の 10 件に絞った（並びも同じ）。containerd の `pkg/oci/spec.go` の
/// 既定も同じ 10 件で、並びだけが違う。写したのはパス文字列だけで、ロジックは写していない。帰属表示はルートの
/// `NOTICE` を参照する。
///
/// # 未実装（REPAIR-3: 実装済みを装わない）
///
/// moby の `/sys/devices/virtual/powercap`・`/sys/firmware`・`/sys/devices/system/cpu/cpuN/thermal_throttle` は
/// 対象外。実行層が sysfs を供給する時点（TASK-127）で足す。
pub const MASKED_PROC_PATHS: [&str; 10] = [
    "/proc/acpi",
    "/proc/asound",
    "/proc/interrupts",
    "/proc/kcore",
    "/proc/keys",
    "/proc/latency_stats",
    "/proc/sched_debug",
    "/proc/scsi",
    "/proc/timer_list",
    "/proc/timer_stats",
];

/// 覆う対象の種別（`fstat` の結果を OS 非依存の値にしたもの。適用側が写す）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TargetKind {
    /// 通常ファイル。
    File,
    /// ディレクトリ。
    Dir,
    /// symlink・デバイス・その他（覆わず拒否する）。
    Other,
}

/// 覆い方。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MaskMethod {
    /// 検証済みの `/dev/null` を載せる（読むと 0 バイト）。
    BindDevNull,
    /// 読み取り専用の空 tmpfs を載せる（空ディレクトリに見える）。
    EmptyTmpfs,
}

/// 種別ごとの覆い方（純関数）。想定外の種別は `None`（適用側が拒否する）。
pub fn mask_method(kind: TargetKind) -> Option<MaskMethod> {
    match kind {
        TargetKind::File => Some(MaskMethod::BindDevNull),
        TargetKind::Dir => Some(MaskMethod::EmptyTmpfs),
        TargetKind::Other => None,
    }
}

/// 読み取り専用にする `/sys`（rootfs 直下の `sys` が symlink でないディレクトリのときだけ、全体を再帰 bind して
/// mount top を読み取り専用にする。配下の個別項目は未実装）。
pub const READONLY_SYS_PATH: &str = "/sys";

/// 先頭の `/` を除き、`/` で区切った要素列にする。適用側が 1 要素ずつ `openat` するのに使う。
///
/// 空要素（`//`・末尾 `/`）と `.`・`..` を含むパスは `None`（固定集合には現れない形で、現れたら定義の誤り）。
pub fn components(path: &str) -> Option<Vec<&str>> {
    let rest = path.strip_prefix('/')?;
    let parts: Vec<&str> = rest.split('/').collect();
    if parts
        .iter()
        .any(|p| p.is_empty() || *p == "." || *p == "..")
    {
        return None;
    }
    Some(parts)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SEC-2・CORE-5（#1850）: `/proc` 配下の 5 件が moby の定義どおりの順序と値である。
    #[test]
    fn sec2_readonly_proc_paths_are_the_moby_five_in_order() {
        assert_eq!(
            READONLY_PROC_PATHS,
            [
                "/proc/bus",
                "/proc/fs",
                "/proc/irq",
                "/proc/sys",
                "/proc/sysrq-trigger"
            ]
        );
        assert_eq!(READONLY_SYS_PATH, "/sys");
    }

    /// SEC-2（#1850）: すべて `/proc/` 始まりで、正規形（`..`・`//`・末尾 `/` なし）である。
    #[test]
    fn sec2_readonly_proc_paths_are_canonical_and_under_proc() {
        for p in READONLY_PROC_PATHS {
            assert!(p.starts_with("/proc/"), "{p}");
            assert!(!p.contains(".."), "{p}");
            assert!(!p.contains("//"), "{p}");
            assert!(!p.ends_with('/'), "{p}");
            assert_eq!(components(p).map(|c| c.len()), Some(2), "{p}");
        }
    }

    /// SEC-2（#1850）: 要素列への分解は具体値で、不正な形は `None`。
    #[test]
    fn sec2_components_splits_and_rejects_non_canonical() {
        assert_eq!(components("/proc/sys"), Some(vec!["proc", "sys"]));
        assert_eq!(components("/sys"), Some(vec!["sys"]));
        assert_eq!(components("proc/sys"), None);
        assert_eq!(components("/proc//sys"), None);
        assert_eq!(components("/proc/sys/"), None);
        assert_eq!(components("/proc/../etc"), None);
        assert_eq!(components("/"), None);
    }

    /// SEC-2（#1851）: 覆う `/proc` 配下の 10 件が moby の定義どおりの順序と値である。
    #[test]
    fn sec2_masked_proc_paths_are_the_moby_ten_in_order() {
        assert_eq!(
            MASKED_PROC_PATHS,
            [
                "/proc/acpi",
                "/proc/asound",
                "/proc/interrupts",
                "/proc/kcore",
                "/proc/keys",
                "/proc/latency_stats",
                "/proc/sched_debug",
                "/proc/scsi",
                "/proc/timer_list",
                "/proc/timer_stats",
            ]
        );
    }

    /// SEC-2（#1851）: すべて `/proc/` 始まりの正規形（2 要素）で、読み取り専用の集合と互いに素である
    /// （適用順「読み取り専用 -> 覆う」の前提を機械で守る）。
    #[test]
    fn sec2_masked_proc_paths_are_canonical_and_disjoint_from_readonly() {
        for p in MASKED_PROC_PATHS {
            assert!(p.starts_with("/proc/"), "{p}");
            assert_eq!(components(p).map(|c| c.len()), Some(2), "{p}");
            assert!(!READONLY_PROC_PATHS.contains(&p), "{p}");
            assert!(
                !READONLY_PROC_PATHS
                    .iter()
                    .any(|r| p.starts_with(&format!("{r}/"))),
                "{p}"
            );
        }
    }

    /// SEC-2（#1851）: 種別ごとの覆い方。symlink・デバイス等は覆わない。
    #[test]
    fn sec2_mask_method_by_kind() {
        assert_eq!(mask_method(TargetKind::File), Some(MaskMethod::BindDevNull));
        assert_eq!(mask_method(TargetKind::Dir), Some(MaskMethod::EmptyTmpfs));
        assert_eq!(mask_method(TargetKind::Other), None);
    }
}
