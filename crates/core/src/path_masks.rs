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
//!
//! 覆う側（`maskedPaths` 相当）の固定集合は同じ置き場所の [`MASKED_PROC_PATHS`]（#1851）。
//!
//! # config の指定（追加のみ。#1852・TASK-29 追補）
//!
//! config の `linux.maskedPaths` / `linux.readonlyPaths` は検証済みの [`ProtectedPath`] として保持し、
//! [`readonly_targets`] / [`masked_targets`] で固定集合の後ろへ足す（和集合）。固定集合を外す・緩める手段は無い。
//! 固定集合や config 内で重複する指定は後ろを捨てる（覆い済みのパスは `/dev/null` の char device になり、
//! 2 回目の適用が `TargetKind::Other` で拒否されるため）。

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

/// コンテナ内パスの字句検証と正規化（ホスト OS 非依存。CORE-2・OCI-4）。
///
/// 空・NUL・`\` を含む値、`..` 要素（位置を問わず）、要素が 0 個になる値（`/` のみ）、正規化後に `max_bytes` を
/// 超える値は `None`。連続する `/`・`.` 要素・末尾の `/` は除いて `/a/b` 形式で返す（相対パスは `/` 起点にする）。
/// `mounts[].destination` と [`ProtectedPath`] が共有する（規則を 1 か所に保つ）。
pub fn normalize_container_path(value: &str, max_bytes: usize) -> Option<String> {
    if value.is_empty() || value.contains('\0') || value.contains('\\') {
        return None;
    }
    let mut parts: Vec<&str> = Vec::new();
    for part in value.split('/') {
        match part {
            "" | "." => {}
            ".." => return None,
            other => parts.push(other),
        }
    }
    if parts.is_empty() {
        return None;
    }
    let normalized = format!("/{}", parts.join("/"));
    // 相対パスは先頭に `/` が付き 1 バイト増えるため、正規化後にも上限を検証する。
    if normalized.len() > max_bytes {
        return None;
    }
    Some(normalized)
}

/// config の `linux.maskedPaths` / `linux.readonlyPaths` の 1 要素（検証済みの絶対パス。REPAIR-2）。
///
/// 生成は [`ProtectedPath::parse`] のみ。`..`・空要素・相対パス・rootfs 全体（`/`）は表現できない。
/// OCI Runtime Spec は両プロパティの要素を「コンテナ名前空間の絶対パス」(MUST) と定めるため、
/// `mounts[].destination` と違い相対パスは拒否する。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectedPath(String);

impl ProtectedPath {
    /// 検証・正規化する（絶対パス必須。それ以外の規則は [`normalize_container_path`]）。
    pub(crate) fn parse(value: &str, max_bytes: usize) -> Option<Self> {
        if !value.starts_with('/') {
            return None;
        }
        normalize_container_path(value, max_bytes).map(Self)
    }

    /// 正規化済みのコンテナ内パス（`/` 始まり）。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// 読み取り専用化の 1 対象（`dir_only` が真ならディレクトリだけを許す）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadonlyTarget<'a> {
    /// コンテナ内の絶対パス。
    pub path: &'a str,
    /// 真ならディレクトリだけを許す（`/sys`）。
    pub dir_only: bool,
}

/// 読み取り専用にする対象の全体。固定集合（`/proc` 配下 5 件 -> `/sys`）の後ろに config 由来を足す。
///
/// 固定集合と等しいもの・config 内で重複するものは後ろを捨てる。config 由来は `dir_only = false`。
pub fn readonly_targets(extra: &[ProtectedPath]) -> Vec<ReadonlyTarget<'_>> {
    let mut out: Vec<ReadonlyTarget<'_>> = READONLY_PROC_PATHS
        .iter()
        .map(|p| ReadonlyTarget {
            path: p,
            dir_only: false,
        })
        .chain(std::iter::once(ReadonlyTarget {
            path: READONLY_SYS_PATH,
            dir_only: true,
        }))
        .collect();
    for e in extra {
        if !out.iter().any(|t| t.path == e.as_str()) {
            out.push(ReadonlyTarget {
                path: e.as_str(),
                dir_only: false,
            });
        }
    }
    out
}

/// 覆う対象の全体。固定集合（[`MASKED_PROC_PATHS`]）の後ろに config 由来を足す（重複は後ろを捨てる）。
pub fn masked_targets(extra: &[ProtectedPath]) -> Vec<&str> {
    let mut out: Vec<&str> = MASKED_PROC_PATHS.to_vec();
    for e in extra {
        if !out.contains(&e.as_str()) {
            out.push(e.as_str());
        }
    }
    out
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

    fn pp(v: &str) -> ProtectedPath {
        ProtectedPath::parse(v, 4096).expect("valid")
    }

    /// OCI-4（#1852）: 正規化と拒否の具体値。
    #[test]
    fn oci4_protected_path_normalizes_and_rejects() {
        assert_eq!(pp("/proc//kcore/").as_str(), "/proc/kcore");
        assert_eq!(pp("/a/./b").as_str(), "/a/b");
        for bad in [
            "",
            "/",
            "proc/kcore",
            "/proc/../etc",
            "/..",
            "/a\0b",
            "/a\\b",
            "./a",
        ] {
            assert_eq!(ProtectedPath::parse(bad, 4096), None, "{bad:?}");
        }
        let at_limit = format!("/{}", "a".repeat(4095));
        assert!(ProtectedPath::parse(&at_limit, 4096).is_some());
        assert_eq!(ProtectedPath::parse(&format!("{at_limit}a"), 4096), None);
    }

    /// SEC-2（#1852）: config が空でも固定集合は同じ順序で全件残る（外せない）。
    #[test]
    fn sec2_targets_without_extra_equal_fixed_sets() {
        assert_eq!(masked_targets(&[]), MASKED_PROC_PATHS.to_vec());
        let ro = readonly_targets(&[]);
        assert_eq!(ro.len(), 6);
        assert_eq!(ro[0].path, "/proc/bus");
        assert_eq!(ro[5].path, "/sys");
        assert!(ro[5].dir_only);
        assert!(ro[..5].iter().all(|t| !t.dir_only));
    }

    /// SEC-2（#1852）: config 由来は固定集合の後ろに足され、重複は 1 つにまとまる。
    #[test]
    fn sec2_targets_append_extra_and_dedup() {
        let extra = [pp("/proc/kcore"), pp("/extra"), pp("/extra/"), pp("/sys")];
        let m = masked_targets(&extra);
        assert_eq!(m.len(), 12);
        assert_eq!(&m[..10], &MASKED_PROC_PATHS[..]);
        assert_eq!((m[10], m[11]), ("/extra", "/sys"));
        let r = readonly_targets(&extra);
        assert_eq!(r.len(), 8);
        assert_eq!((r[5].path, r[5].dir_only), ("/sys", true));
        assert_eq!((r[6].path, r[6].dir_only), ("/proc/kcore", false));
        assert_eq!((r[7].path, r[7].dir_only), ("/extra", false));
    }
}
