//! create の `mounts[].destination` 拒否が、本番の記録先 `<状態ルート>/@audit.log` へ届くことの結合試験
//! （SEC-4・OCI-4・CORE-2・#2480・REPAIR-12）。
//!
//! CLI の create と同じ構成（`FileStateStore` ＋ `FileAuditSink::in_state_store`）で `create_audited` を呼び、
//! 宛先の遡り・rootfs 全体・相対 `..` の 3 種の拒否（`InvalidArgument`）と、ファイルの JSON Lines
//! 3 行を具体値で照合する。root は使わない（既定のテスト集合で動く）。
//!
//! `FileAuditSink` は主経路のファイル I/O を fork した子プロセスで行うため、単一スレッドの `main`
//! （`harness = false`）で動かす。待ちは `RECORD_WAIT_LIMIT` が上限（REPAIR-5）。Linux 以外は適用外。

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("create_mount_audit_delivery: Linux only, not applicable on this OS");
}

#[cfg(target_os = "linux")]
fn main() {
    linux::run();
}

#[cfg(target_os = "linux")]
#[path = "support/scratch_root.rs"]
mod scratch_root;

#[cfg(target_os = "linux")]
mod linux {
    use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};
    use std::path::{Path, PathBuf};
    use std::time::{Duration, Instant};

    use fandhe_container_core::audit_log::{FileAuditSink, RECORD_WAIT_LIMIT};
    use fandhe_container_core::observability::OpRecorder;
    use fandhe_container_core::oci_runtime::create_audited;
    use fandhe_container_core::state_store::{FileStateStore, StateRoot};
    use fandhe_container_core::traits::{
        ContainerId, CreateRequest, ErrorCode, GetStateRequest, StateStore,
    };

    /// 記録の到達を待つ余裕（sink の最悪待ちに足す）。
    const POLL_MARGIN: Duration = Duration::from_secs(5);

    /// 排他作成する一時ディレクトリ（drop で削除）。
    #[allow(dead_code)] // 第 2 要素は親ディレクトリを drop まで保持するためだけに持つ。
    struct TempDir(PathBuf, super::scratch_root::ScratchDir);

    impl TempDir {
        fn new(tag: &str, mode: u32) -> Self {
            // 親（tmpfiles の flock 走査から守る）の子に作る。mode は子に明示設定する。
            let scratch = super::scratch_root::ScratchDir::new(
                &format!("fc-cmad-{tag}"),
                std::time::Duration::from_secs(10),
            );
            let path = scratch.path().join("d");
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&path)
                .expect("create temp dir");
            // umask に左右されないよう明示的に設定する。
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))
                .expect("set mode");
            Self(path, scratch)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// `@audit.log` を期限つきでポーリングし、`want` 行が出そろったら返す。
    fn wait_for_audit_lines(root: &Path, want: usize) -> Vec<String> {
        let log = root.join("@audit.log");
        let deadline = Instant::now() + RECORD_WAIT_LIMIT * 3 + POLL_MARGIN;
        loop {
            let lines: Vec<String> = std::fs::read_to_string(&log)
                .map(|t| t.lines().map(str::to_owned).collect())
                .unwrap_or_default();
            if lines.len() >= want || Instant::now() >= deadline {
                return lines;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    pub fn run() {
        let state = TempDir::new("state", 0o700);
        let bundles = TempDir::new("bundles", 0o700);
        let store = FileStateStore::open(StateRoot::from_override(state.0.clone()).expect("root"))
            .expect("open the file state store");
        let sink = FileAuditSink::in_state_store(&store);
        let recorder = OpRecorder::new();

        let dests = ["/../..", "/", "run/../../.."];
        for (n, dest) in dests.iter().enumerate() {
            let bundle = bundles.0.join(format!("b{n}"));
            std::fs::create_dir(&bundle).expect("bundle dir");
            std::fs::create_dir(bundle.join("rootfs")).expect("rootfs");
            let config = format!(
                r#"{{"ociVersion":"1.2.0","root":{{"path":"rootfs"}},
"process":{{"user":{{"uid":0,"gid":0}},"args":["/bin/true"],"cwd":"/"}},
"mounts":[{{"destination":"{dest}","type":"bind","source":"/tmp"}}]}}"#
            );
            std::fs::write(bundle.join("config.json"), config).expect("config");
            let id = ContainerId::new(format!("c{n}")).expect("id");
            let req = CreateRequest::new(id, bundle).expect("request");
            let err = create_audited(&store, &recorder, &req, &sink)
                .expect_err("a bad destination must be rejected");
            assert_eq!(err.code(), ErrorCode::InvalidArgument, "dest={dest}");
        }

        // 拒否は状態を作らない。
        for n in 0..dests.len() {
            let id = ContainerId::new(format!("c{n}")).expect("id");
            let got = store.get(&GetStateRequest::new(id));
            assert_eq!(
                got.expect_err("no state may be created").code(),
                ErrorCode::NotFound
            );
        }

        let lines = wait_for_audit_lines(&state.0, dests.len());
        assert_eq!(lines.len(), dests.len(), "audit lines: {lines:?}");
        for (n, line) in lines.iter().enumerate() {
            assert!(line.contains("\"layer\":\"mount\""), "layer: {line}");
            assert!(line.contains("\"path\":null"), "path: {line}");
            assert!(
                line.contains(&format!("\"container_id\":\"c{n}\"")),
                "container_id: {line}"
            );
            assert!(
                line.contains(&format!("\"pid\":{}", std::process::id())),
                "pid: {line}"
            );
        }
        println!("create_mount_audit_delivery: all scenarios passed");
    }
}
