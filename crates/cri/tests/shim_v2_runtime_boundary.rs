//! shim v2 の実装が `ContainerRuntime` 境界（core の `traits`）だけに依存することの静的照合
//! （TASK-62.5・CRI-5・CRI-7・PLUG-1・REPAIR-12・MS-7）。
//!
//! `src/shim_v2.rs` と `src/shim_v2/` 配下の全ソースを走査し、実行層の具象型・他の workspace crate・
//! RuntimeService 側の具象への参照を禁じる。共有の動作確認は `shim_v2_shared_runtime.rs`。

use std::fs;
use std::path::{Path, PathBuf};

const EXPECTED: [&str; 9] = [
    "shim_v2.rs",
    "exec.rs",
    "frame.rs",
    "message.rs",
    "server.rs",
    "service.rs",
    "task_api.rs",
    "task_service.rs",
    "wait.rs",
];

const FORBIDDEN_CRATE_PATHS: [&str; 3] = [
    "crate::runtime_service",
    "crate::image_service",
    "crate::image_pull",
];

fn sources() -> Vec<(PathBuf, String)> {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = vec![src.join("shim_v2.rs")];
    for e in fs::read_dir(src.join("shim_v2")).expect("read shim_v2 dir") {
        let p = e.expect("dir entry").path();
        if p.extension().is_some_and(|x| x == "rs") {
            files.push(p);
        }
    }
    files.sort();
    files
        .into_iter()
        .map(|p| {
            let text = fs::read_to_string(&p).expect("read source");
            (p, text)
        })
        .collect()
}

/// コメント行（`//`・`//!`・`///`）を除いた行を返す。
fn code_lines(text: &str) -> impl Iterator<Item = &str> {
    text.lines().filter(|l| !l.trim_start().starts_with("//"))
}

/// CRI-7: shim v2 のソースが参照する workspace crate は core の `traits` だけ。
#[test]
fn cri7_shim_v2_depends_only_on_core_traits() {
    let files = sources();
    for name in EXPECTED {
        assert!(
            files
                .iter()
                .any(|(p, _)| p.file_name().is_some_and(|f| f == name)),
            "expected shim_v2 source missing: {name}"
        );
    }
    for (path, text) in &files {
        for line in code_lines(text) {
            let mut rest = line;
            while let Some(i) = rest.find("fandhe_container_") {
                let tail = &rest[i..];
                assert!(
                    tail.starts_with("fandhe_container_core::traits"),
                    "{}: forbidden workspace reference: {line}",
                    path.display()
                );
                rest = &tail["fandhe_container_".len()..];
            }
            for bad in FORBIDDEN_CRATE_PATHS {
                assert!(
                    !line.contains(bad),
                    "{}: shim_v2 must not depend on {bad}: {line}",
                    path.display()
                );
            }
        }
    }
}

/// 陽性対照: 少なくとも 1 ファイルが core の `traits` を実際に参照している（走査が空振りしていない）。
#[test]
fn cri7_shim_v2_scan_sees_core_traits_reference() {
    let found = sources()
        .iter()
        .any(|(_, t)| code_lines(t).any(|l| l.contains("fandhe_container_core::traits")));
    assert!(found, "no core::traits reference found; scan is vacuous");
}
