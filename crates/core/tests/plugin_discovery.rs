//! plugin 候補探索の結合試験（TASK-109.1・PLUG-4・PLUG-11・REPAIR-12）。
//!
//! 公開 API のみを使い、一時ディレクトリを system / user の管理ディレクトリに見立てて走査結果を
//! 具体値で照合する。実ホストの `/usr/libexec` には触れず、3 OS で同じ試験が動く。

use std::fs;
use std::path::{Path, PathBuf};

use fandhe_container_core::plugin_discovery::{
    PluginCandidate, PluginDirKind, PluginFileKind, PluginSearchDir, discover_candidates,
};

/// テスト用の一意な一時ディレクトリ（終了時に削除）。
struct Tmp(PathBuf);

impl Tmp {
    fn new(tag: &str) -> Self {
        let p = std::env::temp_dir().join(format!(
            "fandhe-plugin-discovery-{}-{}",
            std::process::id(),
            tag
        ));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).expect("create tmp dir");
        Self(p)
    }
}

impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn exe(name: &str) -> String {
    format!(
        "fandhe-container-plugin-{name}{}",
        std::env::consts::EXE_SUFFIX
    )
}

fn touch(dir: &Path, file: &str) {
    fs::write(dir.join(file), b"").expect("write file");
}

fn summary(c: &[PluginCandidate]) -> Vec<(String, PluginDirKind, PluginFileKind)> {
    c.iter()
        .map(|c| (c.name().to_owned(), c.origin(), c.file_kind()))
        .collect()
}

#[test]
fn plug11_scans_system_and_user_dirs_and_filters_by_name() {
    let tmp = Tmp::new("scan");
    let sys = tmp.0.join("system");
    let usr = tmp.0.join("user");
    fs::create_dir_all(&sys).unwrap();
    fs::create_dir_all(&usr).unwrap();
    touch(&sys, &exe("mcp"));
    touch(&sys, &exe("cri"));
    touch(&usr, &exe("macos"));
    for d in [&sys, &usr] {
        touch(d, "README");
        touch(d, "other-tool");
        touch(d, "fandhe-container-plugin-");
        touch(d, &exe("UPPER"));
        fs::create_dir_all(d.join(exe("subdir"))).unwrap();
    }
    let dirs = [
        PluginSearchDir::new(PluginDirKind::User, usr.clone()),
        PluginSearchDir::new(PluginDirKind::System, sys.clone()),
    ];
    let got = discover_candidates(&dirs).expect("discover");
    assert_eq!(
        summary(&got),
        vec![
            (
                "cri".to_owned(),
                PluginDirKind::System,
                PluginFileKind::File
            ),
            (
                "mcp".to_owned(),
                PluginDirKind::System,
                PluginFileKind::File
            ),
            (
                "macos".to_owned(),
                PluginDirKind::User,
                PluginFileKind::File
            ),
        ]
    );
    assert_eq!(got[0].path(), sys.join(exe("cri")));
    assert_eq!(got[2].path(), usr.join(exe("macos")));
}

#[test]
fn plug11_missing_dirs_yield_empty_list() {
    let tmp = Tmp::new("missing");
    let dirs = [
        PluginSearchDir::new(PluginDirKind::System, tmp.0.join("nope-a")),
        PluginSearchDir::new(PluginDirKind::User, tmp.0.join("nope-b")),
    ];
    assert_eq!(discover_candidates(&dirs).expect("ok"), vec![]);

    let present = tmp.0.join("present");
    fs::create_dir_all(&present).unwrap();
    touch(&present, &exe("mcp"));
    let dirs = [
        PluginSearchDir::new(PluginDirKind::System, tmp.0.join("nope-c")),
        PluginSearchDir::new(PluginDirKind::User, present),
    ];
    let got = discover_candidates(&dirs).expect("ok");
    assert_eq!(
        summary(&got),
        vec![("mcp".to_owned(), PluginDirKind::User, PluginFileKind::File)]
    );
}

#[test]
fn plug11_same_name_in_both_dirs_is_reported_twice() {
    let tmp = Tmp::new("dup");
    let sys = tmp.0.join("system");
    let usr = tmp.0.join("user");
    fs::create_dir_all(&sys).unwrap();
    fs::create_dir_all(&usr).unwrap();
    touch(&sys, &exe("mcp"));
    touch(&usr, &exe("mcp"));
    let dirs = [
        PluginSearchDir::new(PluginDirKind::System, sys),
        PluginSearchDir::new(PluginDirKind::User, usr),
    ];
    let got = discover_candidates(&dirs).expect("ok");
    assert_eq!(
        summary(&got),
        vec![
            (
                "mcp".to_owned(),
                PluginDirKind::System,
                PluginFileKind::File
            ),
            ("mcp".to_owned(), PluginDirKind::User, PluginFileKind::File),
        ]
    );
}

#[cfg(unix)]
#[test]
fn plug11_symlink_is_reported_without_following() {
    let tmp = Tmp::new("symlink");
    let sys = tmp.0.join("system");
    fs::create_dir_all(&sys).unwrap();
    std::os::unix::fs::symlink(tmp.0.join("dangling-target"), sys.join(exe("link"))).unwrap();
    let dirs = [PluginSearchDir::new(PluginDirKind::System, sys)];
    let got = discover_candidates(&dirs).expect("ok");
    assert_eq!(
        summary(&got),
        vec![(
            "link".to_owned(),
            PluginDirKind::System,
            PluginFileKind::Symlink
        )]
    );
}

#[cfg(target_os = "linux")]
#[test]
fn plug11_non_utf8_name_is_excluded() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;
    let tmp = Tmp::new("nonutf8");
    let sys = tmp.0.join("system");
    fs::create_dir_all(&sys).unwrap();
    let mut raw = b"fandhe-container-plugin-".to_vec();
    raw.extend_from_slice(&[0xff, 0xfe]);
    fs::write(sys.join(OsStr::from_bytes(&raw)), b"").unwrap();
    let dirs = [PluginSearchDir::new(PluginDirKind::System, sys)];
    assert_eq!(discover_candidates(&dirs).expect("ok"), vec![]);
}

#[test]
fn plug11_search_path_that_is_a_file_is_an_error() {
    let tmp = Tmp::new("isfile");
    let file = tmp.0.join("not-a-dir");
    fs::write(&file, b"").unwrap();
    let dirs = [PluginSearchDir::new(PluginDirKind::System, file)];
    let err = discover_candidates(&dirs).expect_err("must not swallow");
    #[cfg(target_os = "linux")]
    assert_eq!(err.code().as_str(), "INTERNAL");
    #[cfg(not(target_os = "linux"))]
    let _ = err;
}
