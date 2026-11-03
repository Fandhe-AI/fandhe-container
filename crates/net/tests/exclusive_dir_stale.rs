//! `*_privileged` 試験の launcher が使う排他作成の補助（`support/exclusive_dir.rs`）が、残骸を消さずに
//! 連番を進めて作ることの照合（NET-1・REPAIR-12・#3375）。root 不要で既定のテスト集合で動く。

#![cfg(unix)]

#[path = "support/exclusive_dir.rs"]
mod exclusive_dir;

use std::os::unix::fs::PermissionsExt;

/// 専用の親（この試験が作って Drop で消す）の中で、連番 0 の残骸があっても 1 が作られ、残骸は残る。
#[test]
fn net1_repair12_exclusive_dir_skips_stale_residue() {
    let parent = std::env::temp_dir().join(format!(
        "fc-excl-stale-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    ));
    std::fs::create_dir(&parent).expect("parent");
    struct Cleanup(std::path::PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let _cleanup = Cleanup(parent.clone());

    let pid = std::process::id();
    let stale = parent.join(format!("pfx-{pid}-0"));
    std::fs::create_dir(&stale).expect("stale");
    std::fs::write(stale.join("old"), b"x").expect("stale file");

    let got = exclusive_dir::create_in(&parent, "pfx").expect("create");
    assert_eq!(got, parent.join(format!("pfx-{pid}-1")));
    assert!(
        stale.join("old").exists(),
        "stale residue must not be removed"
    );
    let mode = std::fs::metadata(&got).expect("meta").permissions().mode() & 0o777;
    assert_eq!(mode, 0o700);
}
