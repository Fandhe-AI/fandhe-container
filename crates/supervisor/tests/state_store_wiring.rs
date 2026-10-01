//! supervisor から core の `StateStore` 既定実装を呼ぶ配線の結合・受け入れ照合テスト（TASK-157.3・#237・SUP-1・OCI-5・REPAIR-12）。
//!
//! 公開 API だけを使い、core の `FileStateStore`（CLI 役）が作ったレコードを supervisor 側ハンドルが
//! 読み書きし、ストアを開き直しても同一値が復元されることを具体値で照合する。`FileStateStore` は
//! Linux 限定のため、ストアを使う試験は `linux` モジュールに置き、他 OS では fail-closed
//! （`Unimplemented`）を照合する（CLI-1）。root 不要で既定のテスト集合で動く。

/// AC2: supervisor が独自のシリアライズ処理・状態型を持たず、core への path 依存だけを持つこと。
///
/// 文字列照合であり TOML / Rust の構文解析ではない（tests/skeleton.rs と同じ手法）。
#[test]
fn task_157_3_supervisor_has_no_own_serialization() {
    const MANIFEST: &str = include_str!("../Cargo.toml");
    const STATE_RS: &str = include_str!("../src/state.rs");
    assert!(
        MANIFEST.contains("fandhe-container-core = { path = \"../core\" }"),
        "supervisor must depend on core via a path dependency"
    );
    assert!(
        !MANIFEST.contains("serde"),
        "supervisor manifest must not list serde"
    );
    // 本テスト自身ではなく state.rs の本体（テストモジュールより前）だけを対象にする。
    let body = STATE_RS.split("#[cfg(test)]").next().unwrap_or(STATE_RS);
    for banned in ["Serialize", "Deserialize", "serde_json"] {
        assert!(
            !body.contains(banned),
            "state.rs must not use {banned}: serialization lives in core"
        );
    }
}

/// OCI-5・CLI-1: Linux 以外では状態ルートを作らずに `Unimplemented` を返す。
#[cfg(not(target_os = "linux"))]
#[test]
fn sup1_task157_3_open_default_store_is_unimplemented_outside_linux() {
    use fandhe_container_core::traits::ErrorCode;
    use fandhe_container_supervisor::state::open_default_store;
    let root = std::env::temp_dir().join(format!("fandhe-sup-nolinux-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let e = open_default_store(Some(root.clone())).err().unwrap();
    assert_eq!(e.code(), ErrorCode::Unimplemented);
    assert!(!root.exists());
}

#[cfg(target_os = "linux")]
mod linux {
    use std::fs;
    use std::num::NonZeroU32;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};

    use fandhe_container_core::state_store::{FileStateStore, MAX_STATE_FILE_BYTES, StateRoot};
    use fandhe_container_core::traits::{
        ContainerId, ContainerState, ContainerStatus, CreateStateRequest, ErrorCode, HealthStatus,
        StateStore, SupervisionState, UpdateStateRequest,
    };
    use fandhe_container_supervisor::state::{SupervisedState, open_default_store};

    static COUNTER: AtomicU32 = AtomicU32::new(0);

    /// テスト用一時ディレクトリ（0700。drop で削除）。
    struct TmpDir(PathBuf);

    impl TmpDir {
        fn new(tag: &str) -> Self {
            use std::os::unix::fs::PermissionsExt;
            let n = COUNTER.fetch_add(1, Ordering::SeqCst);
            let p = std::env::temp_dir()
                .join(format!("fandhe-sup-it-{tag}-{}-{n}", std::process::id()));
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

    fn cid(s: &str) -> ContainerId {
        ContainerId::new(s).unwrap()
    }

    fn bundle() -> PathBuf {
        std::env::temp_dir().join("fandhe-sup-it-bundle")
    }

    fn open(root: &Path) -> Arc<dyn StateStore> {
        open_default_store(Some(root.to_path_buf())).unwrap()
    }

    /// CLI 役: core のストアで `created` レコードを作る。
    fn create(store: &Arc<dyn StateStore>, id: &str) {
        let req =
            CreateStateRequest::new(ContainerStatus::created(cid(id), None), bundle()).unwrap();
        store.create(&req).unwrap();
    }

    fn sup(pid: u32, n: u32) -> SupervisionState {
        SupervisionState::new(NonZeroU32::new(pid), Some(HealthStatus::Healthy), n)
    }

    /// AC1・AC3: 書いた値が、ストアを開き直した別ハンドルから同一値で読める。
    #[test]
    fn sup1_task157_3_supervision_round_trips_through_core_store() {
        let t = TmpDir::new("rt");
        let store = open(t.path());
        create(&store, "c1");
        let mut s = SupervisedState::attach(store, cid("c1")).unwrap();
        let before = s.record().revision();
        s.write(
            ContainerStatus::running(cid("c1"), NonZeroU32::new(4321)),
            sup(1234, 3),
        )
        .unwrap();

        let reopened = SupervisedState::attach(open(t.path()), cid("c1")).unwrap();
        let rec = reopened.record();
        assert_eq!(rec.id().as_str(), "c1");
        assert_eq!(rec.status().state(), ContainerState::Running);
        assert_eq!(rec.status().pid(), NonZeroU32::new(4321));
        assert_eq!(rec.supervisor_pid(), NonZeroU32::new(1234));
        assert_eq!(rec.health(), Some(HealthStatus::Healthy));
        assert_eq!(rec.restart_count(), 3);
        assert_eq!(rec.bundle(), bundle().as_path());
        assert!(rec.revision().value() > before.value());
    }

    /// AC1: `write_supervision` は status を変えず監視 3 項目だけを変える。
    #[test]
    fn sup1_task157_3_write_supervision_keeps_status() {
        let t = TmpDir::new("ws");
        let store = open(t.path());
        create(&store, "c1");
        let mut s = SupervisedState::attach(store, cid("c1")).unwrap();
        s.write(
            ContainerStatus::running(cid("c1"), NonZeroU32::new(55)),
            sup(1, 0),
        )
        .unwrap();
        let rec = s.write_supervision(sup(2, 9)).unwrap();
        assert_eq!(rec.status().state(), ContainerState::Running);
        assert_eq!(rec.status().pid(), NonZeroU32::new(55));
        assert_eq!(rec.supervisor_pid(), NonZeroU32::new(2));
        assert_eq!(rec.restart_count(), 9);
    }

    /// 契約 9: CLI 側の status 更新は監視項目を保持し、古い revision の supervisor 書き込みは
    /// `FailedPrecondition` になり、`refresh` 後は成功する。
    #[test]
    fn sup1_task157_3_cli_side_update_keeps_supervision() {
        let t = TmpDir::new("cli");
        let store = open(t.path());
        create(&store, "c1");
        let mut s = SupervisedState::attach(store.clone(), cid("c1")).unwrap();
        s.write_supervision(sup(77, 4)).unwrap();

        // CLI 役が supervision なしで update する。
        let req = UpdateStateRequest::new(
            ContainerStatus::stopped(cid("c1"), Some(0)),
            s.record().revision(),
        );
        store.update(&req).unwrap();

        let e = s.write_supervision(sup(77, 5)).unwrap_err();
        assert_eq!(e.code(), ErrorCode::FailedPrecondition);
        let rec = s.refresh().unwrap();
        assert_eq!(rec.status().state(), ContainerState::Stopped);
        assert_eq!(rec.supervisor_pid(), NonZeroU32::new(77));
        assert_eq!(rec.restart_count(), 4);
        assert_eq!(s.write_supervision(sup(77, 5)).unwrap().restart_count(), 5);
    }

    /// AC4: 破損した state.json は panic せず Err で返る。
    #[test]
    fn sup1_task157_3_corrupted_state_is_error_not_panic() {
        let oversized = "x".repeat(MAX_STATE_FILE_BYTES as usize + 1);
        let cases: [(&str, String); 3] = [
            ("not-json", "this is not json".to_string()),
            (
                "bad-health",
                r#"{"health":"bogus","status":"created"}"#.to_string(),
            ),
            ("oversized", oversized),
        ];
        for (tag, content) in cases {
            let t = TmpDir::new(tag);
            let store = open(t.path());
            create(&store, "c1");
            let mut s = SupervisedState::attach(store.clone(), cid("c1")).unwrap();
            let file = t.path().join("c1").join("state.json");
            fs::write(&file, content).unwrap();
            assert!(s.refresh().is_err(), "{tag}: refresh must fail");
            assert!(
                SupervisedState::attach(store, cid("c1")).is_err(),
                "{tag}: attach must fail"
            );
        }
    }

    /// レコードなしは `NotFound`（作成は CLI の責務）。
    #[test]
    fn sup1_task157_3_attach_missing_record_is_not_found() {
        let t = TmpDir::new("nf");
        let e = SupervisedState::attach(open(t.path()), cid("nope")).unwrap_err();
        assert_eq!(e.code(), ErrorCode::NotFound);
    }

    /// 別コンテナの status は `InvalidArgument`。
    #[test]
    fn sup1_task157_3_write_rejects_other_container_id() {
        let t = TmpDir::new("other");
        let store = open(t.path());
        create(&store, "c1");
        let mut s = SupervisedState::attach(store, cid("c1")).unwrap();
        let e = s
            .write(ContainerStatus::created(cid("c2"), None), sup(1, 0))
            .unwrap_err();
        assert_eq!(e.code(), ErrorCode::InvalidArgument);
    }

    /// `open_default_store` が core の `FileStateStore` と同じルートを指す。
    #[test]
    fn sup1_task157_3_default_store_shares_root_with_core_store() {
        let t = TmpDir::new("share");
        let core = FileStateStore::open(StateRoot::from_override(t.path().to_path_buf()).unwrap())
            .unwrap();
        let req =
            CreateStateRequest::new(ContainerStatus::created(cid("c1"), None), bundle()).unwrap();
        core.create(&req).unwrap();
        let s = SupervisedState::attach(open(t.path()), cid("c1")).unwrap();
        assert_eq!(s.record().status().state(), ContainerState::Created);
    }
}
