//! plugin 信頼検証の拒否が、本番の記録先 `<状態ルート>/@audit.log` へ届くことの結合試験
//! （SEC-4・PLUG-11・TASK-41 追補・#2013・REPAIR-12）。
//!
//! 単体試験は収集用の sink を使う。本試験は CLI の plugin バックエンドと同じ構築関数
//! （`FileAuditSink::open_in_state_root`）で作った本番の sink を `verify_candidate_audited` へ渡し、
//! ファイルの JSON Lines まで具体値で照合する。root は使わない（既定のテスト集合で動く）。
//!
//! `FileAuditSink` は主経路のファイル I/O を fork した子プロセスで行うため、単一スレッドの `main`
//! （`harness = false`）で動かす。待ちは `RECORD_WAIT_LIMIT` が上限（REPAIR-5）。Linux と macOS（#2429。主経路の macOS 版）で実行し、Windows は適用外。
//! macOS の一時ディレクトリは `/var` が symlink のため、`canonicalize` した実体パスの下に作る（symlink の祖先は
//! 信頼検査が拒否し、期待する理由 `group_or_other_writable` に届かない）。

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn main() {
    println!("plugin_trust_audit_delivery: Linux and macOS only, not applicable on this OS");
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn main() {
    imp::run();
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod imp {
    use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};
    use std::path::{Path, PathBuf};
    use std::time::{Duration, Instant};

    use fandhe_container_core::audit_log::{AuditDelivery, FileAuditSink, RECORD_WAIT_LIMIT};
    use fandhe_container_core::plugin_discovery::{
        DiscoveryOptions, PluginDirKind, PluginSearchDir, discover_with_options,
    };
    use fandhe_container_core::plugin_trust::{PluginVerificationMethod, verify_candidate_audited};

    /// 記録の到達を待つ余裕（sink の最悪待ちに足す）。
    const POLL_MARGIN: Duration = Duration::from_secs(5);

    /// 排他作成する一時ディレクトリ（drop で削除。既存・symlink は追従せず失敗する）。
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str, mode: u32) -> Self {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0);
            // macOS の `/var` は symlink。実体パスの下に作る（上の冒頭コメント）。
            let base = std::fs::canonicalize(std::env::temp_dir()).expect("canonicalize temp dir");
            for attempt in 0..16u32 {
                let path = base.join(format!(
                    "fc-ptad-{tag}-{}-{nanos}-{attempt}",
                    std::process::id()
                ));
                match std::fs::DirBuilder::new().mode(0o700).create(&path) {
                    Ok(()) => {
                        // umask に左右されないよう明示的に設定する。
                        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))
                            .expect("set mode");
                        return Self(path);
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(e) => panic!("create temp dir: {e}"),
                }
            }
            panic!("could not create a unique temp dir");
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// `@audit.log` を期限つきでポーリングし、行が出そろったら返す。
    fn wait_for_audit_lines(root: &Path) -> Vec<String> {
        let log = root.join("@audit.log");
        let deadline = Instant::now() + RECORD_WAIT_LIMIT + POLL_MARGIN;
        loop {
            let lines: Vec<String> = std::fs::read_to_string(&log)
                .map(|t| t.lines().map(str::to_owned).collect())
                .unwrap_or_default();
            if !lines.is_empty() || Instant::now() >= deadline {
                return lines;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    pub fn run() {
        // 状態ルート（0700）と、group/other 書き込み可（0777）の plugin 置き場。
        let state = TempDir::new("state", 0o700);
        let plugins = TempDir::new("plugins", 0o777);
        std::fs::write(plugins.0.join("fandhe-container-plugin-macos"), b"stub").expect("write");

        let sink = FileAuditSink::open_in_state_root(Some(state.0.clone()))
            .expect("open the production audit sink");
        let dirs = [PluginSearchDir::new(
            PluginDirKind::System,
            plugins.0.clone(),
        )];
        let report =
            discover_with_options(&dirs, None, &DiscoveryOptions::new()).expect("discover");
        let (candidates, _warnings) = report.into_parts();
        let candidate = candidates.first().expect("one candidate");

        let rejection =
            verify_candidate_audited(candidate, &PluginVerificationMethod::default(), &sink)
                .expect_err("a group/other writable location must be rejected");
        assert_eq!(
            rejection.delivery,
            AuditDelivery::Recorded,
            "the rejection must reach the audit log"
        );
        assert_eq!(rejection.error.reason(), "group_or_other_writable");

        let lines = wait_for_audit_lines(&state.0);
        assert_eq!(lines.len(), 1, "exactly one audit line expected: {lines:?}");
        let line = lines.first().expect("one line");
        assert!(line.contains("\"layer\":\"plugin_trust\""), "layer: {line}");
        assert!(
            line.contains("\"reason\":\"group_or_other_writable\""),
            "reason: {line}"
        );
        // plugin の検証は特定のコンテナに属さないため container_id は載らない。
        assert!(
            line.contains("\"container_id\":null"),
            "container_id: {line}"
        );
        // パスは置き場かその祖先（untrusted。書き込み側が JSON エスケープする）。
        let reported = rejection.error.path().to_string_lossy().into_owned();
        assert!(
            plugins.0.starts_with(rejection.error.path())
                || rejection.error.path().starts_with(&plugins.0),
            "path should be the plugin directory or an ancestor: {reported}"
        );
        assert!(
            line.contains(&format!("\"path\":\"{reported}\"")),
            "path: {line}"
        );
        println!("plugin_trust_audit_delivery: all scenarios passed");
    }
}
