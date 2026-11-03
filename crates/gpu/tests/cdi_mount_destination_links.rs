//! CDI mounts の宛先が usr-merge の正規化で rootfs 側のリンクに当たらないことの結合試験
//! （TASK-127 追補・TASK-126.3・#2985・GPU-1・GPU-2・SEC-1・REPAIR-12）。
//!
//! 一時ディレクトリに usr-merge / 非 usr-merge の rootfs を組み、PoC-14 の fixture を
//! `detect_usr_merge_layout` → `normalize_cdi_spec_paths` → `aggregate_container_edits`
//! → `cdi_bind_mounts` の公開 API だけで通し、宛先を rootfs の根から 1 要素ずつ
//! （`symlink_metadata`。リンクは辿らない）調べて、symlink に当たるかを具体値で照合する。
//! core の適用の段（`crates/core/src/exec/bind_mounts.rs` の契約 3・`path_symlink_or_not_directory`）が
//! 宛先の symlink を拒否する規則の字句上の写しで、gpu は core に依存しない。
//!
//! 範囲: usr-merge のリンク（rootfs 直下の 6 件）は正規化で避ける。それ以外の symlink を含む宛先は
//! gpu では解決せず core が拒否する（#1910 の項目 5）ことを境界として固定する。
//! 検出を呼ぶ配線と実 namespace での確認は #2774・#552 の範囲。

use std::collections::BTreeSet;

use fandhe_container_gpu::cdi_apply::mounts::cdi_bind_mounts;
use fandhe_container_gpu::cdi_edits::aggregate_container_edits;
use fandhe_container_gpu::cdi_paths::{PathLayouts, UsrMergeLayout, normalize_cdi_spec_paths};
use fandhe_container_gpu::cdi_spec::parse_cdi_spec;

const NODE4: &str = include_str!("fixtures/poc14-node4.json");
const DEVBOX02: &str = include_str!("fixtures/poc14-devbox02.json");
#[cfg(unix)]
const DEVBOX02_RAW: &str = include_str!("fixtures/poc14-devbox02-mount-paths-spec.txt");
#[cfg(unix)]
const DEVBOX02_NORMALIZED: &str =
    include_str!("fixtures/poc14-devbox02-mount-paths-spec-normalized.txt");

/// 正規化 → 集計 → bind 変換を通した宛先の一覧。
fn chain(src: &str, layouts: PathLayouts) -> Vec<String> {
    let mut spec = parse_cdi_spec(src).unwrap();
    normalize_cdi_spec_paths(&mut spec, &layouts);
    let edits = aggregate_container_edits(&spec, &["all"]).unwrap();
    cdi_bind_mounts(&edits)
        .unwrap()
        .iter()
        .map(|m| m.destination().to_string())
        .collect()
}

fn first_component(dest: &str) -> &str {
    let rest = dest.strip_prefix('/').unwrap();
    rest.split_once('/').map_or(rest, |(h, _)| h)
}

#[cfg(unix)]
mod unix {
    use super::*;
    use fandhe_container_gpu::cdi_paths::{UsrMergedDir, detect_usr_merge_layout};
    use std::os::unix::fs::symlink;
    use std::path::{Path, PathBuf};

    /// 宛先を rootfs の根から辿った結果（core の契約 3 の字句上の写し）。
    #[derive(Debug, PartialEq, Eq)]
    enum Walk {
        /// 最初に symlink だった接頭辞。
        Link(String),
        /// 中間要素が非ディレクトリだった接頭辞。
        NotDir(String),
        /// 問題なし。実在した要素数（以降は core が作る）と全要素数。
        Clean { existing: usize, total: usize },
    }

    fn walk(root: &Path, dest: &str) -> Walk {
        let parts: Vec<&str> = dest.strip_prefix('/').unwrap().split('/').collect();
        let mut cur = root.to_path_buf();
        let mut prefix = String::new();
        for (i, p) in parts.iter().enumerate() {
            cur.push(p);
            prefix.push('/');
            prefix.push_str(p);
            match std::fs::symlink_metadata(&cur) {
                Ok(m) if m.file_type().is_symlink() => return Walk::Link(prefix),
                Ok(m) if !m.is_dir() && i + 1 < parts.len() => return Walk::NotDir(prefix),
                Ok(_) => {}
                Err(_) => {
                    return Walk::Clean {
                        existing: i,
                        total: parts.len(),
                    };
                }
            }
        }
        Walk::Clean {
            existing: parts.len(),
            total: parts.len(),
        }
    }

    fn scratch(name: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "fandhe-gpu-destlinks-{}-{name}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    /// 正規化前の fixture の `containerPath`（rootfs の組み立てに使い、試験を循環させない）。
    fn raw_container_paths(src: &str) -> Vec<String> {
        let spec = parse_cdi_spec(src).unwrap();
        let edits = aggregate_container_edits(&spec, &["all"]).unwrap();
        edits
            .mounts()
            .iter()
            .map(|m| m.container_path.clone())
            .collect()
    }

    /// rootfs を組む。`merged` なら `lib` 等を `usr/...` へのリンクにし、続けて正規化前の
    /// `containerPath` の親を作る（merged ではリンク経由で `usr/lib/firmware/...` に実体ができる）。
    fn build_rootfs(root: &Path, merged: bool, raw_dests: &[String]) {
        for d in [
            "usr/bin",
            "usr/sbin",
            "usr/lib",
            "usr/lib64",
            "usr/share",
            "etc",
            "run",
        ] {
            std::fs::create_dir_all(root.join(d)).unwrap();
        }
        for d in ["lib", "bin", "sbin", "lib64"] {
            if merged {
                symlink(format!("usr/{d}"), root.join(d)).unwrap();
            } else {
                std::fs::create_dir_all(root.join(d)).unwrap();
            }
        }
        for dest in raw_dests {
            let rel = dest.strip_prefix('/').unwrap();
            let parent = Path::new(rel).parent().unwrap();
            std::fs::create_dir_all(root.join(parent)).unwrap();
        }
    }

    fn merged_four() -> UsrMergeLayout {
        UsrMergeLayout::split()
            .with(UsrMergedDir::Lib)
            .with(UsrMergedDir::Bin)
            .with(UsrMergedDir::Sbin)
            .with(UsrMergedDir::Lib64)
    }

    fn detect_chain(src: &str, root: &Path) -> (UsrMergeLayout, Vec<String>) {
        let detected = detect_usr_merge_layout(root).unwrap();
        let dests = chain(src, PathLayouts::new(UsrMergeLayout::merged(), detected));
        (detected, dests)
    }

    fn assert_all_clean(root: &Path, dests: &[String]) {
        for d in dests {
            match walk(root, d) {
                Walk::Clean { existing, total } => {
                    assert!(existing + 1 >= total, "parent missing for {d}");
                    assert!(existing >= 1, "empty walk for {d}");
                }
                other => panic!("{d}: {other:?}"),
            }
        }
    }

    /// GPU-1・GPU-2・SEC-1: usr-merge の rootfs で検出 → 正規化した宛先は、リンクを通らない。
    #[test]
    fn gpu1_gpu2_sec1_merged_rootfs_destinations_avoid_usr_merge_links() {
        for (name, src, total) in [("m-dev", DEVBOX02, 54), ("m-node4", NODE4, 47)] {
            let root = scratch(name);
            build_rootfs(&root, true, &raw_container_paths(src));
            let (detected, dests) = detect_chain(src, &root);
            assert_eq!(detected, merged_four());
            assert_eq!(dests.len(), total);
            assert_all_clean(&root, &dests);
            let set: BTreeSet<&str> = dests.iter().map(String::as_str).collect();
            assert!(!set.iter().any(|d| first_component(d) == "lib"));
            if src == DEVBOX02 {
                assert!(set.contains("/usr/lib/firmware/nvidia/595.91.07/gsp_ga10x.bin"));
                assert!(set.contains("/usr/lib/firmware/nvidia/595.91.07/gsp_tu10x.bin"));
                let want: BTreeSet<&str> = DEVBOX02_NORMALIZED.lines().collect();
                assert_eq!(set, want);
            }
            let _ = std::fs::remove_dir_all(&root);
        }
    }

    /// GPU-1・GPU-2・SEC-1: 非 usr-merge の rootfs では何も書き換えず、宛先にリンクは無い。
    #[test]
    fn gpu1_gpu2_sec1_split_rootfs_destinations_have_no_links() {
        for (name, src, total) in [("s-dev", DEVBOX02, 54), ("s-node4", NODE4, 47)] {
            let root = scratch(name);
            build_rootfs(&root, false, &raw_container_paths(src));
            let (detected, dests) = detect_chain(src, &root);
            assert_eq!(detected, UsrMergeLayout::split());
            assert_eq!(dests.len(), total);
            assert_all_clean(&root, &dests);
            if src == DEVBOX02 {
                let got: BTreeSet<&str> = dests.iter().map(String::as_str).collect();
                let want: BTreeSet<&str> = DEVBOX02_RAW.lines().collect();
                assert_eq!(got, want);
                assert!(got.contains("/lib/firmware/nvidia/595.91.07/gsp_ga10x.bin"));
            }
            let _ = std::fs::remove_dir_all(&root);
        }
    }

    /// 陽性対照: コンテナ側の正規化を飛ばすと firmware の 2 件だけが `/lib` のリンクに当たる。
    #[test]
    fn gpu1_gpu2_sec1_unnormalized_destination_hits_lib_link() {
        let root = scratch("unnormalized");
        build_rootfs(&root, true, &raw_container_paths(DEVBOX02));
        let dests = chain(
            DEVBOX02,
            PathLayouts::new(UsrMergeLayout::merged(), UsrMergeLayout::split()),
        );
        let hits: Vec<&String> = dests
            .iter()
            .filter(|d| matches!(walk(&root, d), Walk::Link(_)))
            .collect();
        assert_eq!(hits.len(), 2);
        for d in &hits {
            assert!(d.starts_with("/lib/firmware/nvidia/595.91.07/gsp_"));
            assert_eq!(walk(&root, d), Walk::Link("/lib".to_string()));
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    /// #1910 の項目 5 の境界: 検出に合わない形のリンクと usr-merge 以外のリンクは gpu が解決せず、
    /// 宛先に残って core が拒否する。
    #[test]
    fn gpu1_gpu2_sec1_non_usr_merge_links_are_left_for_core() {
        // (a) `lib -> ./usr/lib` は完全一致しないので merged と判定されない（fail-closed）。
        let root = scratch("odd-lib");
        build_rootfs(&root, true, &raw_container_paths(DEVBOX02));
        std::fs::remove_file(root.join("lib")).unwrap();
        symlink("./usr/lib", root.join("lib")).unwrap();
        let (detected, dests) = detect_chain(DEVBOX02, &root);
        assert!(!detected.is_merged(UsrMergedDir::Lib));
        assert!(detected.is_merged(UsrMergedDir::Bin));
        let fw = "/lib/firmware/nvidia/595.91.07/gsp_ga10x.bin";
        assert!(dests.iter().any(|d| d == fw));
        assert_eq!(walk(&root, fw), Walk::Link("/lib".to_string()));
        let _ = std::fs::remove_dir_all(&root);

        // (b) usr-merge 以外のリンク（`etc/vulkan`）は書き換わらず、当たる。
        let root = scratch("etc-vulkan");
        build_rootfs(&root, true, &raw_container_paths(DEVBOX02));
        std::fs::remove_dir_all(root.join("etc/vulkan")).unwrap();
        std::fs::create_dir_all(root.join("opt/vulkan")).unwrap();
        symlink("../opt/vulkan", root.join("etc/vulkan")).unwrap();
        let (_, dests) = detect_chain(DEVBOX02, &root);
        let mut linked = 0;
        for d in &dests {
            if d.starts_with("/etc/vulkan/") {
                linked += 1;
                assert_eq!(walk(&root, d), Walk::Link("/etc/vulkan".to_string()));
            } else {
                assert!(matches!(walk(&root, d), Walk::Clean { .. }), "{d}");
            }
        }
        assert!(linked >= 1);
        let _ = std::fs::remove_dir_all(&root);
    }
}

/// GPU-1・GPU-2・SEC-1（3 OS）: コンテナ側が merged なら、宛先の先頭要素は usr-merge の 6 名に当たらない。
/// split のままなら先頭要素は etc・lib・run・usr だけ。
#[test]
fn gpu1_gpu2_sec1_normalized_destinations_skip_usr_merge_names() {
    const NAMES: [&str; 6] = ["bin", "sbin", "lib", "lib32", "lib64", "libx32"];
    for src in [DEVBOX02, NODE4] {
        let merged = chain(
            src,
            PathLayouts::new(UsrMergeLayout::merged(), UsrMergeLayout::merged()),
        );
        assert!(merged.iter().all(|d| !NAMES.contains(&first_component(d))));
        let split = chain(
            src,
            PathLayouts::new(UsrMergeLayout::merged(), UsrMergeLayout::split()),
        );
        let firsts: BTreeSet<&str> = split.iter().map(|d| first_component(d)).collect();
        let want: BTreeSet<&str> = ["etc", "lib", "run", "usr"].into_iter().collect();
        assert_eq!(firsts, want);
    }
}
