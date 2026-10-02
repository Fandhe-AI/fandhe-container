//! plugin レジストリの結合試験（TASK-109.3・PLUG-4・PLUG-11・REPAIR-12）。
//!
//! 公開 API のみを使い、一時ディレクトリを system / user に見立てて `discover_candidates` の
//! 結果をレジストリへ登録し、重複解決を具体値で照合する。3 OS で同じ試験が動く。

use std::fs;
use std::path::{Path, PathBuf};

use fandhe_container_core::plugin_discovery::{
    PluginDirKind, PluginRegistry, PluginSearchDir, RegistrationStatus, discover_candidates,
};

/// テスト用の一意な一時ディレクトリ（終了時に削除）。
struct Tmp(PathBuf);

impl Tmp {
    fn new(tag: &str) -> Self {
        let p = std::env::temp_dir().join(format!(
            "fandhe-plugin-registry-{}-{}",
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

fn touch(dir: &Path, name: &str) {
    fs::write(dir.join(exe(name)), b"").expect("write plugin file");
}

#[test]
fn plug11_registry_resolves_system_user_duplicate_from_discovery() {
    let tmp = Tmp::new("dup");
    let sys = tmp.0.join("system");
    let usr = tmp.0.join("user");
    fs::create_dir_all(&sys).expect("mkdir system");
    fs::create_dir_all(&usr).expect("mkdir user");
    touch(&sys, "cri");
    touch(&usr, "cri");
    touch(&usr, "net");

    // user を先に渡しても system が勝つ（登録順非依存）。
    let candidates = discover_candidates(&[
        PluginSearchDir::new(PluginDirKind::User, usr.clone()),
        PluginSearchDir::new(PluginDirKind::System, sys.clone()),
    ])
    .expect("discover");
    let registry = PluginRegistry::from_candidates(candidates).expect("registry");

    let names: Vec<&str> = registry.iter().map(|c| c.name()).collect();
    assert_eq!(names, vec!["cri", "net"]);

    let cri = registry.get("cri").expect("cri");
    assert_eq!(cri.origin(), PluginDirKind::System);
    assert_eq!(cri.path(), sys.join(exe("cri")));
    assert_eq!(
        registry.get("net").map(|c| c.origin()),
        Some(PluginDirKind::User)
    );

    assert_eq!(registry.shadowed().len(), 1);
    let shadowed = &registry.shadowed()[0];
    assert_eq!(shadowed.candidate().origin(), PluginDirKind::User);
    assert_eq!(shadowed.candidate().path(), usr.join(exe("cri")));
    assert_eq!(shadowed.winner_origin(), PluginDirKind::System);
    assert_eq!(shadowed.winner_path(), sys.join(exe("cri")));
}

#[test]
fn plug4_registry_is_empty_for_missing_directories() {
    let tmp = Tmp::new("missing");
    let candidates = discover_candidates(&[PluginSearchDir::new(
        PluginDirKind::System,
        tmp.0.join("does-not-exist"),
    )])
    .expect("discover");
    let registry = PluginRegistry::from_candidates(candidates).expect("registry");
    assert!(registry.is_empty());
    assert!(registry.shadowed().is_empty());
}

#[test]
fn plug4_register_returns_structured_outcome() {
    let tmp = Tmp::new("outcome");
    let sys = tmp.0.join("system");
    fs::create_dir_all(&sys).expect("mkdir system");
    touch(&sys, "cri");
    let candidates =
        discover_candidates(&[PluginSearchDir::new(PluginDirKind::System, sys)]).expect("discover");
    let mut registry = PluginRegistry::new();
    for c in candidates.iter().cloned() {
        let outcome = registry.register(c).expect("register");
        assert_eq!(outcome.name(), "cri");
        assert_eq!(outcome.status(), RegistrationStatus::Registered);
    }
    let again = registry
        .register(candidates[0].clone())
        .expect("re-register");
    assert_eq!(again.status(), RegistrationStatus::AlreadyRegistered);
}
