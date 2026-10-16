//! `small_files` 計測ハーネスの結合試験（実ファイルを作る。TASK-189・IO-2・IO-6・REPAIR-3・REPAIR-5）。

use fandhe_container_benches::small_files::{
    Config, Layout, Plan, guest_path, run, run_trial, run_with_deadline,
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
