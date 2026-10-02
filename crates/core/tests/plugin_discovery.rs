//! plugin 候補探索の結合試験（TASK-109.1・PLUG-4・PLUG-11・REPAIR-12）。
//!
//! 公開 API のみを使い、一時ディレクトリを system / user の管理ディレクトリに見立てて走査結果を
//! 具体値で照合する。実ホストの `/usr/libexec` には触れず、3 OS で同じ試験が動く。

use std::fs;
use std::path::{Path, PathBuf};

use fandhe_container_core::plugin_discovery::{
    DiscoveryOptions, PathSearchPolicy, PluginCandidate, PluginDirKind, PluginFileKind,
    PluginSearchDir, discover_candidates, discover_with_options, write_path_warnings,
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

/// PATH 探索の試験用に、管理ディレクトリ（mcp）と PATH 用ディレクトリ（cri・macos・命名規約外）を作る。
fn path_fixture(tag: &str) -> (Tmp, Vec<PluginSearchDir>, PathBuf) {
    let tmp = Tmp::new(tag);
    let sys = tmp.0.join("system");
    let pdir = tmp.0.join("pathdir");
    fs::create_dir_all(&sys).unwrap();
    fs::create_dir_all(&pdir).unwrap();
    touch(&sys, &exe("mcp"));
    touch(&pdir, &exe("cri"));
    touch(&pdir, &exe("macos"));
    touch(&pdir, "README");
    touch(&pdir, "other-tool");
    let managed = vec![PluginSearchDir::new(PluginDirKind::System, sys)];
    (tmp, managed, pdir)
}

#[test]
fn plug11_path_search_disabled_by_default_finds_nothing_on_path() {
    let (_tmp, managed, pdir) = path_fixture("path-off");
    let value = std::env::join_paths([&pdir]).unwrap();
    let report =
        discover_with_options(&managed, Some(&value), &DiscoveryOptions::default()).unwrap();
    assert_eq!(
        summary(report.candidates()),
        vec![(
            "mcp".to_owned(),
            PluginDirKind::System,
            PluginFileKind::File
        )]
    );
    assert!(report.path_warnings().is_empty());
    let mut out = Vec::new();
    write_path_warnings(&report, &mut out).unwrap();
    assert_eq!(out.len(), 0);
}

#[test]
fn plug11_path_search_opt_in_warns_once_per_candidate() {
    let (_tmp, managed, pdir) = path_fixture("path-on");
    let value = std::env::join_paths([&pdir]).unwrap();
    let opts = DiscoveryOptions::new().with_path_search(PathSearchPolicy::Enabled);
    let report = discover_with_options(&managed, Some(&value), &opts).unwrap();
    assert_eq!(
        summary(report.candidates()),
        vec![
            (
                "mcp".to_owned(),
                PluginDirKind::System,
                PluginFileKind::File
            ),
            ("cri".to_owned(), PluginDirKind::Path, PluginFileKind::File),
            (
                "macos".to_owned(),
                PluginDirKind::Path,
                PluginFileKind::File
            ),
        ]
    );
    assert_eq!(report.path_warnings().len(), 2);
    let mut out = Vec::new();
    write_path_warnings(&report, &mut out).unwrap();
    let text = String::from_utf8(out).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 2);
    let names: Vec<String> = lines
        .iter()
        .map(|l| {
            assert!(l.contains("not registered"));
            let v: serde_json::Value = serde_json::from_str(l).unwrap();
            assert_eq!(v["level"], "warn");
            v["name"].as_str().unwrap().to_owned()
        })
        .collect();
    assert_eq!(names, vec!["cri", "macos"]);
}

#[test]
fn plug11_path_search_skips_missing_and_duplicate_entries() {
    let (tmp, managed, pdir) = path_fixture("path-skip");
    let plain = tmp.0.join("plain-file");
    fs::write(&plain, b"").unwrap();
    let missing = tmp.0.join("missing");
    let value = std::env::join_paths([&missing, &pdir, &plain, &pdir]).unwrap();
    // cri のみを残して 1 件にする
    fs::remove_file(pdir.join(exe("macos"))).unwrap();
    let opts = DiscoveryOptions::new().with_path_search(PathSearchPolicy::Enabled);
    let report = discover_with_options(&managed, Some(&value), &opts).unwrap();
    let on_path: Vec<_> = report
        .candidates()
        .iter()
        .filter(|c| c.origin() == PluginDirKind::Path)
        .collect();
    assert_eq!(on_path.len(), 1);
    let mut out = Vec::new();
    write_path_warnings(&report, &mut out).unwrap();
    assert_eq!(String::from_utf8(out).unwrap().lines().count(), 1);
}

#[test]
fn plug11_existing_discover_candidates_never_touches_path() {
    let (_tmp, managed, _pdir) = path_fixture("path-legacy");
    let found = discover_candidates(&managed).unwrap();
    assert!(found.iter().all(|c| c.origin() != PluginDirKind::Path));
    assert_eq!(found.len(), 1);
}
