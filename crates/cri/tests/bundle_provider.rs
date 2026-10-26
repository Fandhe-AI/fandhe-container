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
use fandhe_container_cri::bundle::{
    ImageDefaults, RootfsSource, SpecBundleProvider, UserResolveRequest,
};
use fandhe_container_cri::error::{CriError, CriErrorCode};
use fandhe_container_cri::runtime::v1::{
    ContainerConfig, ContainerMetadata, DnsConfig, ImageSpec, Int64Value, LinuxContainerConfig,
    LinuxContainerSecurityContext, PodSandboxConfig, SupplementalGroupsPolicy,
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
        // `SpecBundleProvider` は symlink を含む bundle root を拒否する（SEC-1）。macOS の一時ディレクトリは
        // `/var` → `/private/var` の symlink 配下にあるため、正規パスに揃えてから渡す（#2537 と同じ扱い）。
        Self(fs::canonicalize(&p).expect("canonicalize"))
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
    /// 受け取った解決要求の run_as_username。
    seen_username: Mutex<Option<String>>,
    /// 真なら要求を解決して `resolved_run_as_username` を返す（偽は要求を無視する実装を模す）。
    resolve_username: Mutex<Option<(u32, u32)>>,
    /// 受け取った解決要求の (run_as_user, image_groups)（#2667）。
    seen_groups_request: Mutex<Option<(Option<u32>, bool)>>,
}

impl RootfsSource for FakeRootfs {
    fn prepare(
        &self,
        _image: &ImageSpec,
        rootfs: &Path,
        user: &UserResolveRequest<'_>,
    ) -> Result<ImageDefaults, CriError> {
        self.prepares.fetch_add(1, Ordering::SeqCst);
        *self.seen_username.lock().unwrap() = user.run_as_username.map(str::to_owned);
        *self.seen_groups_request.lock().unwrap() = Some((user.run_as_user, user.image_groups));
        fs::create_dir(rootfs).map_err(|_| CriError::internal("rootfs"))?;
        if *self.fail_prepare.lock().unwrap() {
            return Err(CriError::resource_exhausted("no space"));
        }
        let mut d = self.defaults.lock().unwrap().clone();
        if user.run_as_username.is_some() {
            d.resolved_run_as_username = *self.resolve_username.lock().unwrap();
        }
        Ok(d)
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

/// CRI-2・SEC-5（#2664）: run_as_username が RootfsSource へ渡り、解決結果が config.json の process.user になる。
#[test]
fn run_as_username_is_resolved_through_the_rootfs_source() {
    let (_tmp, rootfs, p) = setup("username");
    *rootfs.resolve_username.lock().unwrap() = Some((1000, 1001));
    let mut c = container();
    c.linux = Some(LinuxContainerConfig {
        security_context: Some(LinuxContainerSecurityContext {
            run_as_username: "app".into(),
            ..Default::default()
        }),
        ..Default::default()
    });
    let dir = prepare(&p, "ctr1", &c).expect("prepare");
    assert_eq!(rootfs.seen_username.lock().unwrap().as_deref(), Some("app"));
    oci_runtime::load_config(&dir.join("config.json")).expect("core parses config.json");
    let v: serde_json::Value =
        serde_json::from_slice(&fs::read(dir.join("config.json")).unwrap()).unwrap();
    assert_eq!(v["process"]["user"]["uid"], 1000);
    assert_eq!(v["process"]["user"]["gid"], 1001);
}

/// CRI-2・SEC-5（#2667）: run_as_user と方針（Merge か Strict）が解決要求に載り、RootfsSource が返したイメージ由来の
/// 補助グループが CRI の一覧に先立って config.json の additionalGids になる。Strict ではイメージ由来を使わない。
#[test]
fn supplemental_groups_request_and_merge_reach_the_config() {
    let sc = |policy: SupplementalGroupsPolicy| LinuxContainerConfig {
        security_context: Some(LinuxContainerSecurityContext {
            run_as_user: Some(Int64Value { value: 1000 }),
            supplemental_groups: vec![70, 60],
            supplemental_groups_policy: policy as i32,
            ..Default::default()
        }),
        ..Default::default()
    };
    let gids = |dir: &Path| -> serde_json::Value {
        let v: serde_json::Value =
            serde_json::from_slice(&fs::read(dir.join("config.json")).unwrap()).unwrap();
        v["process"]["user"]["additionalGids"].clone()
    };
    let (_tmp, rootfs, p) = setup("groups-merge");
    *rootfs.defaults.lock().unwrap() = ImageDefaults {
        supplementary_gids: vec![50, 60],
        ..Default::default()
    };
    let mut c = container();
    c.linux = Some(sc(SupplementalGroupsPolicy::Merge));
    let dir = prepare(&p, "ctr1", &c).expect("prepare");
    assert_eq!(
        *rootfs.seen_groups_request.lock().unwrap(),
        Some((Some(1000), true))
    );
    assert_eq!(gids(&dir), serde_json::json!([50, 60, 70]));
    oci_runtime::load_config(&dir.join("config.json")).expect("core parses config.json");

    c.linux = Some(sc(SupplementalGroupsPolicy::Strict));
    let dir = prepare(&p, "ctr2", &c).expect("prepare");
    assert_eq!(
        *rootfs.seen_groups_request.lock().unwrap(),
        Some((Some(1000), false))
    );
    assert_eq!(gids(&dir), serde_json::json!([70, 60]));
}

/// CRI-2・SEC-5（#2664）: 解決要求を無視する実装では UNIMPLEMENTED で拒否し、bundle を残さない。
#[test]
fn run_as_username_without_resolution_is_rejected_and_rolled_back() {
    let (tmp, rootfs, p) = setup("username-unresolved");
    let mut c = container();
    c.linux = Some(LinuxContainerConfig {
        security_context: Some(LinuxContainerSecurityContext {
            run_as_username: "app".into(),
            ..Default::default()
        }),
        ..Default::default()
    });
    let e = prepare(&p, "ctr1", &c).unwrap_err();
    assert_eq!(e.code(), CriErrorCode::Unimplemented);
    assert_eq!(rootfs.releases.load(Ordering::SeqCst), 1);
    assert!(!tmp.0.join("ctr1").exists());
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
#[test]
fn release_after_a_refused_existing_bundle_keeps_the_existing_data() {
    // CRI-1・REPAIR-12: 既存 bundle を理由に拒否された ID の巻き戻し release は、既存の実体を消さない。
    let (tmp, _rootfs, p) = setup("refused");
    let dir = prepare(&p, "ctr1", &container()).unwrap();
    let e = prepare(&p, "ctr1", &container()).unwrap_err();
    assert_eq!(e.code(), CriErrorCode::FailedPrecondition);
    p.release("ctr1").expect("rollback release is a no-op");
    assert!(dir.join("config.json").exists());
    assert!(tmp.0.join("ctr1").is_dir());
    // 通常の release は消す。
    p.release("ctr1").expect("release");
    assert!(!dir.exists());
}

#[test]
fn rootfs_release_failure_during_rollback_keeps_the_bundle() {
    // 解放失敗時は資源を保持し、後続の release が回収する（rootfs 解放 → bundle 削除の順）。
    struct StickyRootfs(Arc<FakeRootfs>);
    impl RootfsSource for StickyRootfs {
        fn prepare(
            &self,
            i: &ImageSpec,
            r: &Path,
            u: &UserResolveRequest<'_>,
        ) -> Result<ImageDefaults, CriError> {
            self.0.prepare(i, r, u)
        }
        fn release(&self, _r: &Path) -> Result<(), CriError> {
            Err(CriError::internal("rootfs release"))
        }
    }
    let tmp = TempDir::new("rollback-keep");
    let inner = Arc::new(FakeRootfs::default());
    *inner.fail_prepare.lock().unwrap() = true;
    let p = SpecBundleProvider::new(tmp.0.clone(), Arc::new(StickyRootfs(inner))).unwrap();
    let e = prepare(&p, "ctr1", &container()).unwrap_err();
    assert_eq!(e.code(), CriErrorCode::ResourceExhausted);
    assert!(tmp.0.join("ctr1").is_dir());
}

#[test]
fn release_after_a_precheck_failure_keeps_an_existing_bundle_with_the_same_id() {
    // CRI-1・REPAIR-12: 同 ID の既存 bundle があり事前検証（tty・image 欠落）で失敗しても、巻き戻し release は
    // 既存の bundle と rootfs を消さない。
    let (tmp, _rootfs, p) = setup("precheck-existing");
    let dir = prepare(&p, "ctr1", &container()).unwrap();
    let mut c = container();
    c.tty = true;
    let e = prepare(&p, "ctr1", &c).unwrap_err();
    assert_eq!(e.code(), CriErrorCode::Unimplemented);
    p.release("ctr1").expect("rollback release is a no-op");
    assert!(dir.join("config.json").exists());
    assert!(dir.join("rootfs").is_dir());

    let mut c = container();
    c.image = None;
    let e = prepare(&p, "ctr1", &c).unwrap_err();
    assert_eq!(e.code(), CriErrorCode::InvalidArgument);
    p.release("ctr1").expect("rollback release is a no-op");
    assert!(tmp.0.join("ctr1/rootfs").is_dir());

    // 通常の release は消す。
    p.release("ctr1").expect("release");
    assert!(!dir.exists());
}

fn dns_pod() -> PodSandboxConfig {
    PodSandboxConfig {
        dns_config: Some(DnsConfig {
            servers: vec!["10.0.0.10".into(), "2001:db8::1".into()],
            searches: vec!["svc.cluster.local".into()],
            options: vec!["ndots:5".into()],
        }),
        ..Default::default()
    }
}

fn prepare_dns(p: &SpecBundleProvider, id: &str) -> Result<PathBuf, CriError> {
    let pod = dns_pod();
    p.prepare(&BundleRequest::new(id, "sb", &pod, &container()))
}

/// CRI-2・NET-5（#2665）: resolv.conf が 0644 で生成され、config.json の bind の source になる。
#[test]
fn dns_config_generates_resolv_conf_and_binds_it() {
    let (_tmp, _rootfs, p) = setup("dns");
    let dir = prepare_dns(&p, "ctr1").expect("prepare");
    let resolv = dir.join("resolv.conf");
    assert_eq!(mode(&resolv), 0o644);
    assert_eq!(
        fs::read_to_string(&resolv).unwrap(),
        "# Generated by fandhe-container (CRI-2)\n\
         nameserver 10.0.0.10\n\
         nameserver 2001:db8::1\n\
         search svc.cluster.local\n\
         options ndots:5\n"
    );
    oci_runtime::load_config(&dir.join("config.json")).expect("core parses config.json");
    let v: serde_json::Value =
        serde_json::from_slice(&fs::read(dir.join("config.json")).unwrap()).unwrap();
    assert_eq!(v["mounts"][0]["destination"], "/etc/resolv.conf");
    assert_eq!(v["mounts"][0]["source"], resolv.to_str().unwrap());
}

/// CRI-2・NET-5（#2665）: umask 077 のプロセスでも resolv.conf は 0644（非 root のコンテナ側が読める）。
/// umask はプロセス全体の状態なので、`umask 077` を掛けた子プロセスとして自分自身を再実行して確かめる。
#[test]
fn dns_resolv_conf_is_0644_even_under_umask_077() {
    const CHILD: &str = "FANDHE_TEST_UMASK_CHILD";
    if std::env::var_os(CHILD).is_some() {
        let (_tmp, _rootfs, p) = setup("dnsumask");
        let dir = prepare_dns(&p, "ctr1").expect("prepare");
        assert_eq!(mode(&dir.join("resolv.conf")), 0o644);
        assert_eq!(mode(&dir.join("config.json")), 0o600);
        return;
    }
    let exe = std::env::current_exe().expect("exe");
    // REPAIR-5: 子が停止しても試験が止まらないよう、期限つきで待ち、超過したら kill して回収する。
    let mut child = std::process::Command::new("sh")
        .arg("-c")
        .arg("umask 077; exec \"$0\" --exact dns_resolv_conf_is_0644_even_under_umask_077 --test-threads=1")
        .arg(exe)
        .env(CHILD, "1")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn");
    // 出力は別スレッドで収集する（パイプ満杯による子のブロックを避ける）。結果は channel で受け、
    // 孫プロセスがパイプを握り続けても join で無期限に止まらないようにする。
    let mut so = child.stdout.take().expect("stdout");
    let mut se = child.stderr.take().expect("stderr");
    let (tx_out, rx_out) = std::sync::mpsc::channel::<Vec<u8>>();
    let (tx_err, rx_err) = std::sync::mpsc::channel::<Vec<u8>>();
    std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = std::io::Read::read_to_end(&mut so, &mut b);
        let _ = tx_out.send(b);
    });
    std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = std::io::Read::read_to_end(&mut se, &mut b);
        let _ = tx_err.send(b);
    });
    let grace = std::time::Duration::from_secs(5);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    let status = loop {
        if let Some(st) = child.try_wait().expect("try_wait") {
            break Some(st);
        }
        if std::time::Instant::now() >= deadline {
            // kill の結果を確認し、回収も有限の猶予内の try_wait ポーリングで行う。
            let kill_result = child.kill();
            let reap_deadline = std::time::Instant::now() + grace;
            let mut reaped = false;
            while std::time::Instant::now() < reap_deadline {
                if matches!(child.try_wait(), Ok(Some(_))) {
                    reaped = true;
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            panic!("child timed out after 60s (kill: {kill_result:?}, reaped: {reaped})");
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    };
    let stdout_bytes = rx_out.recv_timeout(grace).unwrap_or_default();
    let stderr_bytes = rx_err.recv_timeout(grace).unwrap_or_default();
    let stdout = String::from_utf8_lossy(&stdout_bytes);
    let status = status.expect("status is Some when the loop breaks normally");
    assert!(
        status.success(),
        "child failed: {stdout} {}",
        String::from_utf8_lossy(&stderr_bytes)
    );
    assert!(stdout.contains("1 passed"), "child did not run: {stdout}");
}

#[test]
fn no_dns_config_creates_no_resolv_conf() {
    let (_tmp, _rootfs, p) = setup("nodns");
    let dir = prepare(&p, "ctr1", &container()).expect("prepare");
    assert!(!dir.join("resolv.conf").exists());
}

#[test]
fn invalid_dns_config_creates_no_directory() {
    let (tmp, rootfs, p) = setup("baddns");
    let pod = PodSandboxConfig {
        dns_config: Some(DnsConfig {
            servers: vec!["bogus".into()],
            ..Default::default()
        }),
        ..Default::default()
    };
    let e = p
        .prepare(&BundleRequest::new("ctr1", "sb", &pod, &container()))
        .unwrap_err();
    assert_eq!(e.code(), CriErrorCode::InvalidArgument);
    assert!(!tmp.0.join("ctr1").exists());
    assert_eq!(rootfs.prepares.load(Ordering::SeqCst), 0);
}

#[test]
fn release_removes_the_resolv_conf_with_the_bundle() {
    let (_tmp, _rootfs, p) = setup("dns-release");
    let dir = prepare_dns(&p, "ctr1").expect("prepare");
    p.release("ctr1").expect("release");
    assert!(!dir.exists());
}
