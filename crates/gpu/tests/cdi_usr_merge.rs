//! usr-merge 正規化の結合試験（TASK-126.3・GPU-1）。公開 API のみを使い、PoC の値はリテラルで写す。
use fandhe_container_gpu::cdi_edits::aggregate_container_edits;
use fandhe_container_gpu::cdi_paths::{PathLayouts, UsrMergeLayout, normalize_cdi_spec_paths};
use fandhe_container_gpu::cdi_spec::parse_cdi_spec;

const YAML: &str = "cdiVersion: 0.5.0
kind: nvidia.com/gpu
devices:
  - name: \"0\"
    containerEdits:
      mounts:
        - hostPath: /lib/firmware/nvidia/595.91.07/gsp_ga10x.bin
          containerPath: /lib/firmware/nvidia/595.91.07/gsp_ga10x.bin
containerEdits:
  mounts:
    - hostPath: /usr/bin/nvidia-smi
      containerPath: /usr/bin/nvidia-smi
";

fn container_paths(layout: UsrMergeLayout) -> Vec<String> {
    let mut spec = parse_cdi_spec(YAML).unwrap();
    normalize_cdi_spec_paths(&mut spec, &PathLayouts::new(layout, layout));
    let a = aggregate_container_edits(&spec, &["0"]).unwrap();
    a.mounts()
        .iter()
        .map(|m| m.container_path.clone())
        .collect()
}

#[test]
fn gpu1_parse_normalize_aggregate() {
    assert_eq!(
        container_paths(UsrMergeLayout::merged()),
        [
            "/usr/lib/firmware/nvidia/595.91.07/gsp_ga10x.bin",
            "/usr/bin/nvidia-smi"
        ]
    );
    assert_eq!(
        container_paths(UsrMergeLayout::split()),
        [
            "/lib/firmware/nvidia/595.91.07/gsp_ga10x.bin",
            "/usr/bin/nvidia-smi"
        ]
    );
}

#[cfg(unix)]
mod unix {
    use fandhe_container_gpu::cdi_paths::{detect_usr_merge_layout, normalize_usr_merge_path};
    use std::os::unix::fs::{MetadataExt, symlink};
    use std::path::Path;

    fn ids(root: &Path, p: &str) -> Option<(u64, u64)> {
        std::fs::metadata(root.join(p.trim_start_matches('/')))
            .ok()
            .map(|m| (m.dev(), m.ino()))
    }

    #[test]
    fn gpu1_both_spellings_resolve_to_same_inode() {
        let base =
            std::env::temp_dir().join(format!("fandhe-gpu-usrmerge-it-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let merged = base.join("merged");
        let split = base.join("split");
        for r in [&merged, &split] {
            std::fs::create_dir_all(r.join("usr/lib/firmware")).unwrap();
            std::fs::write(r.join("usr/lib/firmware/x"), b"x").unwrap();
        }
        symlink("usr/lib", merged.join("lib")).unwrap();
        std::fs::create_dir_all(split.join("lib/firmware")).unwrap();
        std::fs::write(split.join("lib/firmware/x"), b"y").unwrap();

        let lm = detect_usr_merge_layout(&merged).unwrap();
        let a = normalize_usr_merge_path("/lib/firmware/x", &lm);
        let b = normalize_usr_merge_path("/usr/lib/firmware/x", &lm);
        assert_eq!(a, b);
        assert_eq!(
            ids(&merged, "/lib/firmware/x"),
            ids(&merged, "/usr/lib/firmware/x")
        );

        let ls = detect_usr_merge_layout(&split).unwrap();
        let a = normalize_usr_merge_path("/lib/firmware/x", &ls);
        let b = normalize_usr_merge_path("/usr/lib/firmware/x", &ls);
        assert_ne!(a, b);
        assert_ne!(
            ids(&split, "/lib/firmware/x"),
            ids(&split, "/usr/lib/firmware/x")
        );
        let _ = std::fs::remove_dir_all(&base);
    }
}
