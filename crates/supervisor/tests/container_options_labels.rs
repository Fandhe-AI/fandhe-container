//! label（`--label`）がコンテナメタデータ（state.json の `annotations`）へ反映されることの受け入れ照合
//! （SUP-12・TASK-169.5.1・#855・MS-9・REPAIR-12）。
//!
//! 公開 API だけを使い、`Label::parse` → `Labels::resolve` → `ContainerOptions::with_labels` →
//! core の `CreateStateRequest::with_annotations` の変換までを 3 OS で、実ストア（`FileStateStore`。
//! Linux 限定）への永続化と supervisor の状態更新後の保持を Linux で具体値により照合する。
//! root 不要で既定のテスト集合で動く。

use fandhe_container_core::traits::{ContainerId, ContainerStatus, CreateStateRequest};
use fandhe_container_supervisor::container_options::{ContainerOptions, Label, Labels};

fn cid(s: &str) -> ContainerId {
    ContainerId::new(s).unwrap()
}

/// `--label` 文字列から、状態作成要求に載せる直前の `CreateStateRequest` までを組み立てる。
fn request_with_labels(id: &str, raw: &[&str]) -> CreateStateRequest {
    let labels = Labels::resolve(raw.iter().map(|s| Label::parse(s).unwrap()).collect()).unwrap();
    let opts = ContainerOptions::new().with_labels(labels);
    CreateStateRequest::new(
        ContainerStatus::created(cid(id), None),
        std::env::temp_dir().join("fandhe-sup-labels-bundle"),
    )
    .unwrap()
    .with_annotations(opts.labels().annotations().clone())
}

/// AC: `--label` の指定が、状態作成要求の annotations に具体値で反映される（3 OS 共通）。
#[test]
fn sup12_task169_5_1_labels_reach_create_request() {
    let req = request_with_labels(
        "web",
        &["app=web", "tier", "env=prod", "env=stg", "note=a=b"],
    );
    let got: Vec<(&str, &str)> = req.annotations().unwrap().iter().collect();
    assert_eq!(
        got,
        [
            ("app", "web"),
            ("env", "stg"),
            ("note", "a=b"),
            ("tier", "")
        ]
    );
}

#[cfg(target_os = "linux")]
mod linux {
    use std::fs;
    use std::num::NonZeroU32;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU32, Ordering};

    use fandhe_container_core::traits::{ContainerStatus, HealthStatus, SupervisionState};
    use fandhe_container_supervisor::state::{SupervisedState, open_default_store};

    use super::{cid, request_with_labels};

    static COUNTER: AtomicU32 = AtomicU32::new(0);

    /// テスト用一時ディレクトリ（0700。drop で削除）。
    struct TmpDir(PathBuf);

    impl TmpDir {
        fn new() -> Self {
            use std::os::unix::fs::PermissionsExt;
            let n = COUNTER.fetch_add(1, Ordering::SeqCst);
            let p =
                std::env::temp_dir().join(format!("fandhe-sup-labels-{}-{n}", std::process::id()));
            let _ = fs::remove_dir_all(&p);
            fs::create_dir_all(&p).unwrap();
            fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).unwrap();
            Self(p)
        }
        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TmpDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// AC: label が state.json に書かれ、supervisor の監視状態更新後も保持され、開き直しても読める。
    #[test]
    fn sup12_task169_5_1_labels_persist_in_state_json() {
        let t = TmpDir::new();
        let store = open_default_store(Some(t.path().to_path_buf())).unwrap();
        store
            .create(&request_with_labels("web", &["app=web", "tier"]))
            .unwrap();

        let mut s = SupervisedState::attach(store, cid("web")).unwrap();
        s.write(
            ContainerStatus::running(cid("web"), NonZeroU32::new(4321)),
            SupervisionState::new(NonZeroU32::new(1234), Some(HealthStatus::Healthy), 0),
        )
        .unwrap();
        let rec = s.write_supervision(SupervisionState::new(NonZeroU32::new(1234), None, 2));
        let rec = rec.unwrap();
        assert_eq!(rec.annotations().get("app"), Some("web"));
        assert_eq!(rec.annotations().get("tier"), Some(""));

        let raw = fs::read_to_string(t.path().join("web").join("state.json")).unwrap();
        assert!(
            raw.contains(r#""annotations":{"app":"web","tier":""}"#),
            "{raw}"
        );

        let reopened = SupervisedState::attach(
            open_default_store(Some(t.path().to_path_buf())).unwrap(),
            cid("web"),
        )
        .unwrap();
        assert_eq!(reopened.record().annotations().len(), 2);
        assert_eq!(reopened.record().annotations().get("app"), Some("web"));
    }
}

/// Linux 以外では実ストアは core が `Unimplemented`（CLI-1）。変換までを上のテストで照合している。
#[cfg(not(target_os = "linux"))]
#[test]
fn sup12_task169_5_1_store_is_unimplemented_outside_linux() {
    use fandhe_container_core::traits::ErrorCode;
    use fandhe_container_supervisor::state::open_default_store;
    let root =
        std::env::temp_dir().join(format!("fandhe-sup-labels-nolinux-{}", std::process::id()));
    let e = open_default_store(Some(root.clone())).err().unwrap();
    assert_eq!(e.code(), ErrorCode::Unimplemented);
    assert!(!root.exists());
}
