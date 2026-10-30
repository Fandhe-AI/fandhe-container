//! `small_files` 計測ハーネスの結合試験（実ファイルを作る。TASK-189・IO-2・IO-6・REPAIR-3・REPAIR-5）。

#[cfg(any(target_os = "linux", target_os = "macos"))]
use fandhe_container_benches::small_files::wire::run_trial_in;
use fandhe_container_benches::small_files::{
    Config, Layout, Plan, Route, guest_path, run, run_trial, run_with_deadline,
};
use fandhe_container_io::{PersistSupport, persist_support};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// テスト専用の一意なルート。Drop で消す。
struct TestRoot(PathBuf);

impl TestRoot {
    fn new(tag: &str) -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let p = std::env::temp_dir().join(format!(
            "fandhe-sf-test-{tag}-{}-{nanos:x}",
            std::process::id()
        ));
        std::fs::create_dir(&p).expect("create test root");
        Self(p)
    }
    /// ソケットの親用。sun_path の上限（wire.rs の 100 バイト）に収まるよう、
    /// 短い接頭辞と短いルート（`/tmp` があればそれ）に置く。
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn new_short() -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let base = if Path::new("/tmp").is_dir() {
            PathBuf::from("/tmp")
        } else {
            std::env::temp_dir()
        };
        let p = base.join(format!(
            "fsp-{}-{:x}",
            std::process::id(),
            nanos & 0xffff_ffff
        ));
        std::fs::create_dir(&p).expect("create short test root");
        Self(p)
    }
    fn path(&self) -> &Path {
        &self.0
    }
    fn entries(&self) -> Vec<String> {
        std::fs::read_dir(&self.0)
            .expect("read root")
            .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
            .collect()
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn plan(count: u64, layout: Layout, batch_size: u64) -> Plan {
    Plan {
        count,
        batch_size,
        file_size: 5,
        layout,
        config: Config::Bind,
        route: Route::ServerApi,
        trials: 1,
        trial_timeout: Duration::from_secs(60),
        timeout: Duration::from_secs(120),
    }
}

fn far() -> Instant {
    Instant::now() + Duration::from_secs(60)
}

/// IO-2・IO-6: 1 試行が期待どおりの数と内容のファイルを作る。
#[test]
fn io2_io6_trial_creates_files_with_expected_content() {
    let root = TestRoot::new("content");
    if !persist_support().is_supported() {
        let err = run(&plan(16, Layout::Flat, 1), root.path()).unwrap_err();
        assert_eq!(err.code, "persist-unsupported");
        assert!(root.entries().is_empty());
        return;
    }
    for (name, layout) in [("flat", Layout::Flat), ("tree", Layout::Tree)] {
        let dir = root.path().join(name);
        std::fs::create_dir(&dir).unwrap();
        let p = plan(16, layout, 1);
        let elapsed = run_trial(&dir, &p, far(), far()).expect("trial");
        assert!(elapsed > Duration::ZERO);
        for i in 0..16 {
            let path = dir.join(guest_path(layout, i));
            assert_eq!(std::fs::read(&path).expect("file"), b"fffff");
        }
    }
    let tree_dir = root.path().join("tree").join("d000");
    assert_eq!(std::fs::read_dir(tree_dir).unwrap().count(), 16);
}

/// REPAIR-3: 後始末は自分が作った専用ディレクトリだけを消す。
#[test]
fn repair3_cleanup_removes_only_own_dir() {
    if !persist_support().is_supported() {
        return;
    }
    let root = TestRoot::new("cleanup");
    std::fs::write(root.path().join("sentinel"), b"keep").unwrap();
    let m = run(&plan(8, Layout::Flat, 1), root.path()).expect("run");
    assert_eq!(m.trials.len(), 1);
    assert_eq!(root.entries(), vec!["sentinel".to_string()]);
}

/// REPAIR-5: 期限切れは値を出さず `timeout` で、専用ディレクトリも消える。
#[test]
fn repair5_expired_deadline_yields_timeout_without_value() {
    if !persist_support().is_supported() {
        return;
    }
    let root = TestRoot::new("deadline");
    let err = run_with_deadline(&plan(8, Layout::Flat, 1), root.path(), Instant::now())
        .expect_err("deadline already passed");
    assert_eq!(err.code, "timeout");
    assert!(root.entries().is_empty());
}

/// IO-2: K ファイルごとの FLUSH は syncfs 対応の環境（Linux）だけ。
#[test]
fn io2_flush_every_k_is_linux_only() {
    let root = TestRoot::new("everyk");
    let result = run(&plan(16, Layout::Flat, 4), root.path());
    if persist_support() == PersistSupport::Supported {
        assert_eq!(result.expect("every-k run").trials.len(), 1);
    } else {
        let code = result.unwrap_err().code;
        assert!(
            code == "unsupported-flush-mode" || code == "persist-unsupported",
            "code: {code}"
        );
        assert!(root.entries().is_empty());
    }
}

/// REPAIR-3: 後始末は symlink を辿らない。
#[cfg(unix)]
#[test]
fn repair3_run_does_not_touch_outside_symlink_target() {
    if !persist_support().is_supported() {
        return;
    }
    let outside = TestRoot::new("outside");
    std::fs::write(outside.path().join("sentinel"), b"keep").unwrap();
    let root = TestRoot::new("symlink");
    std::os::unix::fs::symlink(outside.path(), root.path().join("link")).unwrap();
    run(&plan(8, Layout::Flat, 1), root.path()).expect("run");
    assert_eq!(outside.entries(), vec!["sentinel".to_string()]);
    assert_eq!(root.entries(), vec!["link".to_string()]);
}

/// wire 経路の試験用の計画（`plan` に経路だけ足したもの）。
fn wire_plan(count: u64, layout: Layout, batch_size: u64) -> Plan {
    Plan {
        route: Route::Wire,
        ..plan(count, layout, batch_size)
    }
}

/// wire 経路を動かせない環境（FLUSH 未対応。Linux は syncfs が要る）かどうか。
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn wire_unavailable() -> bool {
    if cfg!(target_os = "linux") {
        persist_support() != PersistSupport::Supported
    } else {
        !persist_support().is_supported()
    }
}

/// IO-1・IO-2・IO-6: wire 経路が期待どおりの件数と内容のファイルを作る（64 の境界をまたぐ）。
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn io1_io2_io6_wire_trial_creates_files_with_expected_content() {
    if wire_unavailable() {
        return;
    }
    let root = TestRoot::new("wire-content");
    for (name, layout) in [("flat", Layout::Flat), ("tree", Layout::Tree)] {
        let dir = root.path().join(name);
        std::fs::create_dir(&dir).unwrap();
        let p = wire_plan(70, layout, 1);
        let elapsed = run_trial(&dir, &p, far(), far()).expect("wire trial");
        assert!(elapsed > Duration::ZERO);
        for i in 0..70 {
            let path = dir.join(guest_path(layout, i));
            assert_eq!(std::fs::read(&path).expect("file"), b"fffff");
        }
    }
}

/// IO-2: wire 経路の K ごとの FLUSH が、バッチ（64）の境界をまたぐ K でも成功し内容が一致する。
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn io2_wire_flush_every_k_crosses_batch_boundary() {
    if wire_unavailable() {
        return;
    }
    let root = TestRoot::new("wire-everyk");
    for k in [5_u64, 64, 65] {
        let dir = root.path().join(format!("k{k}"));
        std::fs::create_dir(&dir).unwrap();
        run_trial(&dir, &wire_plan(200, Layout::Flat, k), far(), far()).expect("wire every-k");
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 200);
        let last = dir.join(guest_path(Layout::Flat, 199));
        assert_eq!(std::fs::read(last).unwrap(), b"fffff");
    }
}

/// REPAIR-5: wire 経路の期限切れは値を出さず `timeout` で、専用ディレクトリも残さない。
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn repair5_wire_expired_deadline_yields_timeout_without_value() {
    if wire_unavailable() {
        return;
    }
    let root = TestRoot::new("wire-deadline");
    let err = run_with_deadline(&wire_plan(8, Layout::Flat, 1), root.path(), Instant::now())
        .expect_err("deadline already passed");
    assert_eq!(err.code, "timeout");
    assert!(root.entries().is_empty());
}

/// REPAIR-3: wire 経路のソケット用ディレクトリは終了後に残らない。
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn repair3_wire_cleanup_removes_socket_dir() {
    if wire_unavailable() {
        return;
    }
    let root = TestRoot::new("wire-cleanup");
    let socket_parent = TestRoot::new_short();
    let trial = root.path().join("trial");
    std::fs::create_dir(&trial).unwrap();
    run_trial_in(
        socket_parent.path(),
        &trial,
        &wire_plan(8, Layout::Flat, 1),
        far(),
        far(),
    )
    .expect("wire trial");
    assert!(socket_parent.entries().is_empty());
}

/// REPAIR-3: UDS の無い OS では wire 経路を副作用の前に拒否する。
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
#[test]
fn repair3_wire_route_is_rejected_on_unsupported_os() {
    let root = TestRoot::new("wire-unsupported");
    let err = run(&wire_plan(8, Layout::Flat, 1), root.path()).unwrap_err();
    assert_eq!(err.code, "unsupported-route");
    assert!(root.entries().is_empty());
}
