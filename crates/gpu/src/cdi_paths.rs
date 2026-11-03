//! CDI spec のパスの usr-merge 正規化（TASK-126.3・GPU-1・MS-10。根拠は PoC-14）。
//!
//! usr-merge 環境（Ubuntu 24.04 等）では `/lib`・`/bin`・`/sbin`・`/lib64` が `usr/...` への
//! シンボリックリンクで、`/proc/self/mountinfo` は解決後の `/usr/lib/...` を報告する。spec 側の
//! `/lib/firmware/...` を正規化しないと同じ対象が別物に見える。本モジュールは spec の文字列だけを
//! 書き換え、どのディレクトリが usr-merge 済みかは [`UsrMergeLayout`] で受ける。
//!
//! - 呼び出し元: `cdi_edits::aggregate_container_edits` の前処理（重複の畳み込みと衝突検出を
//!   正規化後のパスで働かせる）、PoC-14 の mountinfo 比較（#545）、適用時の TASK-127。
//! - 外部入力の扱い: spec 由来のパスはファイルシステムに当てない。[`detect_usr_merge_layout`] が
//!   読むのは `<root>` 直下の決まった 6 件のリンクだけで、リンクは辿らない。
//! - パスは Linux コンテナ内の `/` 区切り文字列として扱い `std::path::Path` を使わない
//!   （Windows ホストで区切り文字の解釈が変わるため）。
//!
//! 範囲外（REPAIR-3）: rootfs 内のリンクを辿る解決は行わない（#1910 の項目 5）。usr-merge の
//! リンクは本モジュールの正規化で避け、それ以外の symlink を含む宛先は core の適用の段が拒否する
//! （固定する試験は `tests/cdi_mount_destination_links.rs`。#2985・GPU-1・GPU-2・SEC-1）。
//! パスの絶対性・`..` の検証は `cdi_apply::mounts`（TASK-127.2）の字句検査が担う。
//! hooks の `path` は完全一致でのみ畳む規則のため正規化しない。

use std::borrow::Cow;
use std::io::ErrorKind;
use std::path::Path;

use crate::cdi_spec::{CdiSpec, CdiSpecError, CdiSpecErrorCode, ContainerEdits};

/// usr-merge の対象になりうるトップレベルのディレクトリ。任意の接頭辞の書き換えは表せない。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum UsrMergedDir {
    /// `/bin`
    Bin,
    /// `/sbin`
    Sbin,
    /// `/lib`
    Lib,
    /// `/lib32`
    Lib32,
    /// `/lib64`
    Lib64,
    /// `/libx32`
    Libx32,
}

impl UsrMergedDir {
    const ALL: [UsrMergedDir; 6] = [
        Self::Bin,
        Self::Sbin,
        Self::Lib,
        Self::Lib32,
        Self::Lib64,
        Self::Libx32,
    ];

    /// `/` を含まないディレクトリ名を返す。
    pub fn name(&self) -> &'static str {
        match self {
            Self::Bin => "bin",
            Self::Sbin => "sbin",
            Self::Lib => "lib",
            Self::Lib32 => "lib32",
            Self::Lib64 => "lib64",
            Self::Libx32 => "libx32",
        }
    }

    fn bit(&self) -> u8 {
        match self {
            Self::Bin => 1,
            Self::Sbin => 2,
            Self::Lib => 4,
            Self::Lib32 => 8,
            Self::Lib64 => 16,
            Self::Libx32 => 32,
        }
    }
}

/// どのディレクトリが `usr/...` へ merged されているかを表すレイアウト。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct UsrMergeLayout {
    bits: u8,
}

impl UsrMergeLayout {
    /// どれも merged でない構成（既定）。正規化は何も書き換えない。
    pub fn split() -> Self {
        Self { bits: 0 }
    }

    /// 6 件すべて merged の構成（Debian / Ubuntu / Fedora 型）。
    pub fn merged() -> Self {
        Self {
            bits: UsrMergedDir::ALL.iter().fold(0, |acc, d| acc | d.bit()),
        }
    }

    /// `dir` を merged として加えたレイアウトを返す。
    pub fn with(mut self, dir: UsrMergedDir) -> Self {
        self.bits |= dir.bit();
        self
    }

    /// `dir` が merged かを返す。
    pub fn is_merged(&self, dir: UsrMergedDir) -> bool {
        self.bits & dir.bit() != 0
    }
}

/// `hostPath` 用のホストのレイアウトと、`containerPath` / `deviceNodes[].path` 用の
/// コンテナ rootfs のレイアウト。PoC-14 の比較はコンテナ側で、両者は一致するとは限らない。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct PathLayouts {
    /// ホスト側（`hostPath`）のレイアウト。
    pub host: UsrMergeLayout,
    /// コンテナ rootfs 側（`containerPath`・`path`）のレイアウト。
    pub container: UsrMergeLayout,
}

impl PathLayouts {
    /// ホストとコンテナのレイアウトから組み立てる。
    pub fn new(host: UsrMergeLayout, container: UsrMergeLayout) -> Self {
        Self { host, container }
    }
}

/// 先頭の 1 要素が merged なディレクトリ名に完全一致するとき `/usr` を足す（冪等）。
///
/// 相対パス・空文字列・`//lib/x` など同じ対象と断定できない表記は変えない（検証は `cdi_apply::mounts` の字句検査。TASK-127.2）。
/// 書き換えるときだけ 1 回確保する（入力 + 4 バイト）。
pub fn normalize_usr_merge_path<'a>(path: &'a str, layout: &UsrMergeLayout) -> Cow<'a, str> {
    let Some(rest) = path.strip_prefix('/') else {
        return Cow::Borrowed(path);
    };
    let first = rest.split_once('/').map_or(rest, |(head, _)| head);
    let merged = UsrMergedDir::ALL
        .iter()
        .any(|d| d.name() == first && layout.is_merged(*d));
    if !merged {
        return Cow::Borrowed(path);
    }
    let mut out = String::with_capacity(path.len() + 4);
    out.push_str("/usr");
    out.push_str(path);
    Cow::Owned(out)
}

fn normalize_in_place(value: &mut String, layout: &UsrMergeLayout) {
    if let Cow::Owned(new) = normalize_usr_merge_path(value, layout) {
        *value = new;
    }
}

fn normalize_edits(edits: &mut ContainerEdits, layouts: &PathLayouts) {
    for node in &mut edits.device_nodes {
        // hostPath 省略時は path がホスト側の参照先も兼ねる。path を書き換える前に元の path を
        // 常にホスト側の参照先として明示化し（省略と明示の表現差で畳み込みが壊れないよう統一）、
        // ホスト用レイアウトで独立に正規化する。
        let host = node.host_path.get_or_insert_with(|| node.path.clone());
        normalize_in_place(host, &layouts.host);
        normalize_in_place(&mut node.path, &layouts.container);
    }
    for mount in &mut edits.mounts {
        normalize_in_place(&mut mount.container_path, &layouts.container);
        normalize_in_place(&mut mount.host_path, &layouts.host);
    }
}

/// spec 全体（トップレベルと全 `devices[]` の mounts・deviceNodes）のパスを正規化する。
///
/// `aggregate_container_edits` の前に呼ぶと、正規化後に同じになる `containerPath` / `path` は
/// 完全一致なら 1 件に畳まれ、内容が違えば `InvalidArgument` で拒否される（集計側の既存規則）。
pub fn normalize_cdi_spec_paths(spec: &mut CdiSpec, layouts: &PathLayouts) {
    normalize_edits(&mut spec.container_edits, layouts);
    for device in &mut spec.devices {
        normalize_edits(&mut device.container_edits, layouts);
    }
}

/// `root` 直下の決まった 6 件を `symlink_metadata` / `read_link` で調べてレイアウトを検出する。
///
/// リンク先が `usr/<name>` または `/usr/<name>` と完全一致するときだけ merged とする。
/// 項目なし・実ディレクトリ・別の先へのリンクは merged にしない（fail-closed）。
/// それ以外の I/O 失敗は `Internal`（パスは載せない）。リンクは辿らない。
pub fn detect_usr_merge_layout(root: &Path) -> Result<UsrMergeLayout, CdiSpecError> {
    let fail = || {
        CdiSpecError::new(
            CdiSpecErrorCode::Internal,
            "failed to inspect usr-merge layout",
        )
    };
    let mut layout = UsrMergeLayout::split();
    for dir in UsrMergedDir::ALL {
        let entry = root.join(dir.name());
        let meta = match std::fs::symlink_metadata(&entry) {
            Ok(m) => m,
            Err(e) if e.kind() == ErrorKind::NotFound => continue,
            Err(_) => return Err(fail()),
        };
        if !meta.file_type().is_symlink() {
            continue;
        }
        let target = std::fs::read_link(&entry).map_err(|_| fail())?;
        let Some(target) = target.to_str() else {
            continue;
        };
        let rel = format!("usr/{}", dir.name());
        if target == rel || target.strip_prefix('/') == Some(rel.as_str()) {
            layout = layout.with(dir);
        }
    }
    Ok(layout)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cdi_edits::aggregate_container_edits;
    use crate::cdi_spec::parse_cdi_spec;

    fn n(p: &str, l: &UsrMergeLayout) -> String {
        normalize_usr_merge_path(p, l).into_owned()
    }

    #[test]
    fn gpu1_merged_folds_lib_to_usr_lib() {
        let m = UsrMergeLayout::merged();
        assert_eq!(
            n("/lib/firmware/nvidia/595.91.07/gsp_ga10x.bin", &m),
            "/usr/lib/firmware/nvidia/595.91.07/gsp_ga10x.bin"
        );
        assert_eq!(
            n("/lib/firmware/nvidia/595.91.07/gsp_tu10x.bin", &m),
            "/usr/lib/firmware/nvidia/595.91.07/gsp_tu10x.bin"
        );
        assert_eq!(n("/bin/x", &m), "/usr/bin/x");
        assert_eq!(n("/sbin/x", &m), "/usr/sbin/x");
        assert_eq!(n("/lib64/x", &m), "/usr/lib64/x");
        assert_eq!(n("/lib32/x", &m), "/usr/lib32/x");
        assert_eq!(n("/libx32/x", &m), "/usr/libx32/x");
        assert_eq!(n("/lib", &m), "/usr/lib");
    }

    #[test]
    fn gpu1_split_keeps_paths() {
        let s = UsrMergeLayout::split();
        for p in ["/lib/x", "/bin/x", "/sbin/x", "/lib64/x", "/lib"] {
            assert!(matches!(normalize_usr_merge_path(p, &s), Cow::Borrowed(q) if q == p));
        }
    }

    #[test]
    fn gpu1_only_whole_first_component() {
        let m = UsrMergeLayout::merged();
        for p in [
            "/library/x",
            "/lib64x/y",
            "/usr/lib/x",
            "/etc/lib/x",
            "/dev/nvidia0",
            "lib/x",
            "",
            "//lib/x",
            "/",
        ] {
            assert_eq!(n(p, &m), p);
        }
    }

    #[test]
    fn gpu1_normalization_is_idempotent() {
        let m = UsrMergeLayout::merged();
        let once = n("/lib/a/b", &m);
        assert_eq!(n(&once, &m), once);
    }

    #[test]
    fn gpu1_partial_layout() {
        let l = UsrMergeLayout::split().with(UsrMergedDir::Lib);
        assert_eq!(n("/lib/x", &l), "/usr/lib/x");
        assert_eq!(n("/bin/x", &l), "/bin/x");
    }

    const SPEC: &str = "cdiVersion: 0.5.0
kind: nvidia.com/gpu
devices:
  - name: \"0\"
    containerEdits:
      mounts:
        - hostPath: /lib/firmware/a
          containerPath: /lib/firmware/a
containerEdits:
  mounts:
    - hostPath: /usr/lib/firmware/a
      containerPath: /usr/lib/firmware/a
";

    fn mount_count(layouts: Option<PathLayouts>, yaml: &str) -> Result<usize, CdiSpecErrorCode> {
        let mut spec = parse_cdi_spec(yaml).unwrap();
        if let Some(l) = layouts {
            normalize_cdi_spec_paths(&mut spec, &l);
        }
        aggregate_container_edits(&spec, &["0"])
            .map(|a| a.mounts().len())
            .map_err(|e| e.code())
    }

    #[test]
    fn gpu1_spec_normalization_folds_and_conflicts() {
        let m = UsrMergeLayout::merged();
        let s = UsrMergeLayout::split();
        assert_eq!(mount_count(None, SPEC), Ok(2));
        assert_eq!(mount_count(Some(PathLayouts::new(m, m)), SPEC), Ok(1));
        assert_eq!(mount_count(Some(PathLayouts::new(s, s)), SPEC), Ok(2));
        // hostPath が違えば正規化後の同一 containerPath は衝突として拒否される。
        let conflict = SPEC.replace("hostPath: /usr/lib/firmware/a", "hostPath: /opt/other");
        assert_eq!(
            mount_count(Some(PathLayouts::new(m, m)), &conflict),
            Err(CdiSpecErrorCode::InvalidArgument)
        );
    }

    #[test]
    fn gpu1_host_and_container_layouts_are_separate() {
        let mut spec = parse_cdi_spec(SPEC).unwrap();
        let layouts = PathLayouts::new(UsrMergeLayout::split(), UsrMergeLayout::merged());
        normalize_cdi_spec_paths(&mut spec, &layouts);
        let m = &spec.devices[0].container_edits.mounts[0];
        assert_eq!(m.host_path, "/lib/firmware/a");
        assert_eq!(m.container_path, "/usr/lib/firmware/a");
    }

    const NODE_SPEC: &str = "\
cdiVersion: 0.6.0
kind: vendor.com/gpu
devices:
  - name: \"0\"
    containerEdits:
      deviceNodes:
        - path: /lib/x
  - name: \"1\"
    containerEdits:
      deviceNodes:
        - path: /usr/lib/x
";

    #[test]
    fn gpu1_implicit_host_path_is_kept_when_layouts_differ() {
        let mut spec = parse_cdi_spec(NODE_SPEC).unwrap();
        let layouts = PathLayouts::new(UsrMergeLayout::split(), UsrMergeLayout::merged());
        normalize_cdi_spec_paths(&mut spec, &layouts);
        let n0 = &spec.devices[0].container_edits.device_nodes[0];
        assert_eq!(n0.path, "/usr/lib/x");
        assert_eq!(n0.host_path.as_deref(), Some("/lib/x"));
        let n1 = &spec.devices[1].container_edits.device_nodes[0];
        assert_eq!(n1.path, "/usr/lib/x");
        assert_eq!(n1.host_path.as_deref(), Some("/usr/lib/x"));
        // 暗黙のホスト参照先が異なるノードは畳まれず拒否される。
        assert_eq!(
            aggregate_container_edits(&spec, &["0", "1"])
                .map(|a| a.device_nodes().len())
                .map_err(|e| e.code()),
            Err(CdiSpecErrorCode::InvalidArgument)
        );
    }

    #[test]
    fn gpu1_implicit_host_path_folds_with_explicit_usr_form() {
        let mut spec = parse_cdi_spec(NODE_SPEC).unwrap();
        let m = UsrMergeLayout::merged();
        normalize_cdi_spec_paths(&mut spec, &PathLayouts::new(m, m));
        let a = aggregate_container_edits(&spec, &["0", "1"]).unwrap();
        assert_eq!(a.device_nodes().len(), 1);
        assert_eq!(a.device_nodes()[0].path, "/usr/lib/x");
    }

    #[cfg(unix)]
    #[test]
    fn gpu1_detect_layout() {
        use std::os::unix::fs::symlink;
        let root = std::env::temp_dir().join(format!("fandhe-gpu-usrmerge-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("usr/lib")).unwrap();
        std::fs::create_dir_all(root.join("usr/bin")).unwrap();
        std::fs::create_dir_all(root.join("lib64")).unwrap();
        symlink("usr/lib", root.join("lib")).unwrap();
        symlink("/usr/bin", root.join("bin")).unwrap();
        symlink("usr/bin", root.join("sbin")).unwrap();
        let got = detect_usr_merge_layout(&root);
        let _ = std::fs::remove_dir_all(&root);
        let expected = UsrMergeLayout::split()
            .with(UsrMergedDir::Lib)
            .with(UsrMergedDir::Bin);
        assert_eq!(got.unwrap(), expected);
    }
}
