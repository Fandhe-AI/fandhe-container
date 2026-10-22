//! `SpecBundleProvider`（bundle ディレクトリの作成・書き込み・解放）の試験
//! （CRI-1・CRI-2・OCI-4・SEC-1・REPAIR-12。#2395）。unix 前提のファイル権限の照合を含む。

#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use fandhe_container_core::oci_runtime;
use fandhe_container_cri::adapter::{BundleProvider, BundleRequest};
use fandhe_container_cri::bundle::{ImageDefaults, RootfsSource, SpecBundleProvider};
use fandhe_container_cri::error::{CriError, CriErrorCode};
use fandhe_container_cri::runtime::v1::{
    ContainerConfig, ContainerMetadata, ImageSpec, PodSandboxConfig,
};

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let p = std::env::temp_dir().join(format!(
            "fandhe-cri-bundle-{tag}-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&p).expect("mkdir");
        // umask 002 の環境でも root 検証（group 書き込み不可）を通すため 0755 に固定する。
        fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).expect("chmod");
        Self(p)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// 空の rootfs を作るだけのフェイク。失敗の注入と呼び出し回数の記録ができる。
#[derive(Default)]
struct FakeRootfs {
    fail_prepare: Mutex<bool>,
    prepares: AtomicUsize,
    releases: AtomicUsize,
    defaults: Mutex<ImageDefaults>,
}

impl RootfsSource for FakeRootfs {
    fn prepare(&self, _image: &ImageSpec, rootfs: &Path) -> Result<ImageDefaults, CriError> {
        self.prepares.fetch_add(1, Ordering::SeqCst);
        fs::create_dir(rootfs).map_err(|_| CriError::internal("rootfs"))?;
        if *self.fail_prepare.lock().unwrap() {
            return Err(CriError::resource_exhausted("no space"));
        }
        Ok(self.defaults.lock().unwrap().clone())
    }
    fn release(&self, rootfs: &Path) -> Result<(), CriError> {
        self.releases.fetch_add(1, Ordering::SeqCst);
        match fs::remove_dir_all(rootfs) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(CriError::internal("rootfs release")),
        }
    }
}

fn container() -> ContainerConfig {
    ContainerConfig {
        metadata: Some(ContainerMetadata {
            name: "c".into(),
            attempt: 0,
        }),
        image: Some(ImageSpec {
            image: "docker.io/library/alpine:3.20".into(),
            ..Default::default()
        }),
        command: vec!["/bin/sh".into(), "-c".into(), "sleep 30".into()],
        ..Default::default()
    }
}

fn setup(tag: &str) -> (TempDir, Arc<FakeRootfs>, SpecBundleProvider) {
    let tmp = TempDir::new(tag);
    let rootfs = Arc::new(FakeRootfs::default());
    let provider = SpecBundleProvider::new(tmp.0.clone(), rootfs.clone()).expect("provider");
    (tmp, rootfs, provider)
}

fn prepare(p: &SpecBundleProvider, id: &str, c: &ContainerConfig) -> Result<PathBuf, CriError> {
    let pod = PodSandboxConfig::default();
    p.prepare(&BundleRequest::new(id, "sb", &pod, c))
}

fn mode(p: &Path) -> u32 {
    fs::metadata(p).unwrap().permissions().mode() & 0o777
}

#[test]
fn prepare_creates_bundle_with_private_modes_and_a_parsable_config() {
    let (tmp, rootfs, p) = setup("ok");
    let dir = prepare(&p, "ctr1", &container()).expect("prepare");
    assert_eq!(dir, tmp.0.join("ctr1"));
    assert_eq!(mode(&dir), 0o700);
    assert!(dir.join("rootfs").is_dir());
    let cfg = dir.join("config.json");
    assert_eq!(mode(&cfg), 0o600);
    let parsed = oci_runtime::load_config(&cfg).expect("core parses config.json");
    assert!(parsed.unapplied_fields().is_empty());
    assert_eq!(
        parsed.process().expect("process").args(),
        ["/bin/sh", "-c", "sleep 30"]
    );
    assert_eq!(rootfs.prepares.load(Ordering::SeqCst), 1);
}

#[test]
fn image_defaults_from_the_rootfs_source_reach_the_config() {
    let (_tmp, rootfs, p) = setup("defaults");
    *rootfs.defaults.lock().unwrap() = ImageDefaults {
        entrypoint: vec!["/ep".into()],
        cmd: vec!["x".into()],
        ..Default::default()
    };
    let mut c = container();
    c.command.clear();
    let dir = prepare(&p, "ctr1", &c).expect("prepare");
    let parsed = oci_runtime::load_config(&dir.join("config.json")).unwrap();
    assert_eq!(parsed.process().unwrap().args(), ["/ep", "x"]);
}

#[test]
fn second_prepare_with_the_same_id_is_rejected_and_keeps_the_existing_bundle() {
    let (_tmp, _rootfs, p) = setup("dup");
    let dir = prepare(&p, "ctr1", &container()).unwrap();
    let before = fs::read(dir.join("config.json")).unwrap();
    let e = prepare(&p, "ctr1", &container()).unwrap_err();
    assert_eq!(e.code(), CriErrorCode::FailedPrecondition);
    assert_eq!(fs::read(dir.join("config.json")).unwrap(), before);
    assert!(dir.join("rootfs").is_dir());
}

#[test]
fn invalid_ids_are_rejected_without_touching_the_filesystem() {
    let (tmp, rootfs, p) = setup("ids");
    for id in ["../x", "a/b", "", ".", "..", "a\0b"] {
        let e = prepare(&p, id, &container()).unwrap_err();
        assert_eq!(e.code(), CriErrorCode::InvalidArgument, "{id:?}");
    }
    assert_eq!(fs::read_dir(&tmp.0).unwrap().count(), 0);
    assert_eq!(rootfs.prepares.load(Ordering::SeqCst), 0);
}

#[test]
fn rejected_config_does_not_create_a_directory() {
    let (tmp, rootfs, p) = setup("reject");
    let mut c = container();
    c.tty = true;
    let e = prepare(&p, "ctr1", &c).unwrap_err();
    assert_eq!(e.code(), CriErrorCode::Unimplemented);
    let mut c = container();
    c.image = None;
    let e = prepare(&p, "ctr2", &c).unwrap_err();
    assert_eq!(e.code(), CriErrorCode::InvalidArgument);
    assert_eq!(fs::read_dir(&tmp.0).unwrap().count(), 0);
    assert_eq!(rootfs.prepares.load(Ordering::SeqCst), 0);
}

#[test]
fn rootfs_failure_leaves_no_partial_bundle() {
    let (tmp, rootfs, p) = setup("rootfs-fail");
    *rootfs.fail_prepare.lock().unwrap() = true;
    let e = prepare(&p, "ctr1", &container()).unwrap_err();
    assert_eq!(e.code(), CriErrorCode::ResourceExhausted);
    assert_eq!(fs::read_dir(&tmp.0).unwrap().count(), 0);
    assert_eq!(rootfs.releases.load(Ordering::SeqCst), 1);
}

#[test]
fn missing_command_after_the_image_defaults_leaves_no_partial_bundle() {
    let (tmp, _rootfs, p) = setup("no-cmd");
    let mut c = container();
    c.command.clear();
    let e = prepare(&p, "ctr1", &c).unwrap_err();
    assert_eq!(e.code(), CriErrorCode::InvalidArgument);
    assert_eq!(fs::read_dir(&tmp.0).unwrap().count(), 0);
}

#[test]
fn release_removes_the_bundle_and_is_idempotent() {
    let (_tmp, rootfs, p) = setup("release");
    let dir = prepare(&p, "ctr1", &container()).unwrap();
    p.release("ctr1").expect("release");
    assert!(!dir.exists());
    assert_eq!(rootfs.releases.load(Ordering::SeqCst), 1);
    p.release("ctr1").expect("absent is ok");
    p.release("never-created").expect("absent is ok");
}

#[test]
fn release_refuses_symlinks_and_keeps_the_target() {
    let (tmp, _rootfs, p) = setup("symlink");
    let target = tmp.0.join("target-dir");
    fs::create_dir(&target).unwrap();
    fs::write(target.join("keep"), b"x").unwrap();
    std::os::unix::fs::symlink(&target, tmp.0.join("ctr1")).unwrap();
    let e = p.release("ctr1").unwrap_err();
    assert_eq!(e.code(), CriErrorCode::Internal);
    assert!(target.join("keep").exists());
    assert!(
        fs::symlink_metadata(tmp.0.join("ctr1"))
            .unwrap()
            .file_type()
            .is_symlink()
    );
    // 通常ファイルも消さない。
    fs::write(tmp.0.join("ctr2"), b"x").unwrap();
    assert_eq!(
        p.release("ctr2").unwrap_err().code(),
        CriErrorCode::Internal
    );
    assert!(tmp.0.join("ctr2").exists());
}

#[test]
fn prepare_does_not_follow_a_symlink_planted_at_the_bundle_path() {
    let (tmp, rootfs, p) = setup("plant");
    let victim = tmp.0.join("victim");
    fs::create_dir(&victim).unwrap();
    std::os::unix::fs::symlink(&victim, tmp.0.join("ctr1")).unwrap();
    let e = prepare(&p, "ctr1", &container()).unwrap_err();
    assert_eq!(e.code(), CriErrorCode::FailedPrecondition);
    assert_eq!(fs::read_dir(&victim).unwrap().count(), 0);
    assert_eq!(rootfs.prepares.load(Ordering::SeqCst), 0);
}

#[test]
fn new_rejects_unsafe_roots() {
    let rootfs = Arc::new(FakeRootfs::default());
    let e = SpecBundleProvider::new(PathBuf::from("relative/dir"), rootfs.clone()).unwrap_err();
    assert_eq!(e.code(), CriErrorCode::InvalidArgument);

    let tmp = TempDir::new("roots");
    let missing = tmp.0.join("missing");
    let e = SpecBundleProvider::new(missing, rootfs.clone()).unwrap_err();
    assert_eq!(e.code(), CriErrorCode::FailedPrecondition);

    let real = tmp.0.join("real");
    fs::create_dir(&real).unwrap();
    let link = tmp.0.join("link");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let e = SpecBundleProvider::new(link, rootfs.clone()).unwrap_err();
    assert_eq!(e.code(), CriErrorCode::FailedPrecondition);

    let file = tmp.0.join("file");
    fs::write(&file, b"x").unwrap();
    let e = SpecBundleProvider::new(file, rootfs.clone()).unwrap_err();
    assert_eq!(e.code(), CriErrorCode::FailedPrecondition);

    for bad in [0o775, 0o757, 0o777] {
        let d = tmp.0.join(format!("w{bad:o}"));
        fs::create_dir(&d).unwrap();
        fs::set_permissions(&d, fs::Permissions::from_mode(bad)).unwrap();
        let e = SpecBundleProvider::new(d, rootfs.clone()).unwrap_err();
        assert_eq!(e.code(), CriErrorCode::FailedPrecondition, "{bad:o}");
    }
}
