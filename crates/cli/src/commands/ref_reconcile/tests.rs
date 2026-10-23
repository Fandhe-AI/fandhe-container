//! `ref_reconcile` の単体試験（OCI-7・REPAIR-5・#2495）。状態ストアは `get` だけを差し替えた偽物を使い、root 不要。

use super::*;
use fandhe_container_core::traits::{
    DeleteStateRequest, DeleteStateResponse, ListStateRequest, StateList, UpdateStateRequest,
};
use std::sync::atomic::{AtomicUsize, Ordering};

/// `get` の呼び出し回数と結果を差し替える状態ストア（他の操作は到達しない）。
struct SpyStore {
    gets: AtomicUsize,
    result: ErrorCode,
}

impl SpyStore {
    fn failing(result: ErrorCode) -> Self {
        Self {
            gets: AtomicUsize::new(0),
            result,
        }
    }
}

impl StateStore for SpyStore {
    fn create(
        &self,
        _: &fandhe_container_core::traits::CreateStateRequest,
    ) -> Result<StateRecord, TraitError> {
        Err(TraitError::new(ErrorCode::Internal, "unused"))
    }
    fn update(&self, _: &UpdateStateRequest) -> Result<StateRecord, TraitError> {
        Err(TraitError::new(ErrorCode::Internal, "unused"))
    }
    fn get(&self, _: &GetStateRequest) -> Result<StateRecord, TraitError> {
        self.gets.fetch_add(1, Ordering::SeqCst);
        Err(TraitError::new(self.result, "spy"))
    }
    fn list(&self, _: &ListStateRequest) -> Result<StateList, TraitError> {
        Err(TraitError::new(ErrorCode::Internal, "unused"))
    }
    fn delete(&self, _: &DeleteStateRequest) -> Result<DeleteStateResponse, TraitError> {
        Err(TraitError::new(ErrorCode::Internal, "unused"))
    }
}

const SCOPE: &str = "0123456789abcdef0123456789abcdef";
const OTHER_SCOPE: &str = "fedcba9876543210fedcba9876543210";
const MANIFEST: &str = "sha256:a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0";

fn key(scope: &str, id: &str) -> ContainerRefId {
    ContainerRefId::new(&ref_key(scope, id)).expect("key")
}

struct Tmp(std::path::PathBuf);

impl Tmp {
    fn new(name: &str) -> Self {
        let dir =
            std::env::temp_dir().join(format!("fandhe-cli-refrec-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("dir");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        }
        Self(dir)
    }
}

impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn seeded_store(tmp: &Tmp) -> ImageStore {
    use fandhe_container_oci::image_management::ManifestComposition;
    use fandhe_container_oci::reference::Digest;
    let store = ImageStore::open(&tmp.0).expect("open");
    store
        .lock()
        .expect("lock")
        .register_manifest(
            Digest::parse(MANIFEST).expect("digest"),
            ManifestComposition::new(
                Digest::parse(
                    "sha256:c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1",
                )
                .expect("config"),
                vec![],
            )
            .expect("comp"),
        )
        .expect("manifest");
    store
}

fn register(store: &ImageStore, k: &ContainerRefId) {
    use fandhe_container_oci::reference::Digest;
    store
        .register_container_ref(k, &Digest::parse(MANIFEST).expect("digest"))
        .expect("register");
}

fn unbound_keys(store: &ImageStore) -> Vec<ContainerRefId> {
    store
        .lock()
        .expect("lock")
        .unbound_containers()
        .map(|(k, _, _)| k.clone())
        .collect()
}

/// OCI-7: `Ok` は Present、`NotFound` だけが Absent、それ以外は Undetermined。
#[test]
fn oci7_probe_maps_state_results() {
    let err = |c| Err(TraitError::new(c, "x"));
    assert_eq!(
        presence_of(&err(ErrorCode::NotFound)),
        ContainerStatePresence::Absent
    );
    for code in [
        ErrorCode::Timeout,
        ErrorCode::Internal,
        ErrorCode::PermissionDenied,
        ErrorCode::Unimplemented,
        ErrorCode::Unavailable,
        ErrorCode::InvalidArgument,
        ErrorCode::FailedPrecondition,
        ErrorCode::AlreadyExists,
    ] {
        assert_eq!(
            presence_of(&err(code)),
            ContainerStatePresence::Undetermined,
            "{code:?}"
        );
    }
}

/// OCI-7: 他の状態ルートの scope・畳んだ形のキーは状態を読まず Undetermined（呼び出し 0 回）。
#[test]
fn oci7_probe_skips_foreign_scope_and_folded_keys() {
    let spy = SpyStore::failing(ErrorCode::NotFound);
    let long = "a".repeat(255);
    for k in [key(OTHER_SCOPE, "c1"), key(SCOPE, &long)] {
        assert_eq!(
            probe_key(&spy, SCOPE, &k),
            ContainerStatePresence::Undetermined,
            "{}",
            k.as_str()
        );
    }
    assert_eq!(spy.gets.load(Ordering::SeqCst), 0);
    // 現在の scope の通常形は 1 回だけ読む。
    assert_eq!(
        probe_key(&spy, SCOPE, &key(SCOPE, "c1")),
        ContainerStatePresence::Absent
    );
    assert_eq!(spy.gets.load(Ordering::SeqCst), 1);
}

/// OCI-7: 状態を読めない（Timeout）参照は照合しても残り、kept_undetermined に載る。
#[test]
fn oci7_reconcile_keeps_undetermined() {
    let tmp = Tmp::new("undetermined");
    let store = seeded_store(&tmp);
    let k = key(SCOPE, "c1");
    register(&store, &k);
    let spy = SpyStore::failing(ErrorCode::Timeout);
    let r = reconcile_in_use(&store, &spy, SCOPE, std::slice::from_ref(&k)).expect("reconcile");
    assert_eq!(r.kept_undetermined(), std::slice::from_ref(&k));
    assert!(r.removed().is_empty());
    assert_eq!(unbound_keys(&store), vec![k]);
}

/// OCI-7: 別の状態ルートの参照は、同じイメージストアにあっても回収しない（読みもしない）。
#[test]
fn oci7_reconcile_does_not_cross_state_roots() {
    let tmp = Tmp::new("cross");
    let store = seeded_store(&tmp);
    let (ka, kb) = (key(SCOPE, "c1"), key(OTHER_SCOPE, "c1"));
    register(&store, &ka);
    register(&store, &kb);
    let spy = SpyStore::failing(ErrorCode::NotFound);
    let r = reconcile_in_use(&store, &spy, SCOPE, &[ka.clone(), kb.clone()]).expect("reconcile");
    let removed: Vec<&ContainerRefId> = r.removed().iter().map(|(k, _)| k).collect();
    assert_eq!(removed, vec![&ka]);
    assert_eq!(spy.gets.load(Ordering::SeqCst), 1);
    assert_eq!(unbound_keys(&store), vec![kb]);
}

/// OCI-7・REPAIR-5: 進行中の create（ゲートの共有）がある間は未確定参照を回収せず、終わった後は回収する。
#[test]
fn oci7_reclaim_skips_while_create_in_progress() {
    let tmp = Tmp::new("busy");
    let store = seeded_store(&tmp).with_timeout(std::time::Duration::from_millis(100));
    let holder = ImageStore::open(&tmp.0).expect("open holder");
    let k = key(SCOPE, "c1");
    let id = ContainerId::new("c1").expect("id");
    register(&store, &k);
    let pass = holder.enter_container_create().expect("pass");
    let spy = SpyStore::failing(ErrorCode::NotFound);
    assert!(reconcile_in_use(&store, &spy, SCOPE, std::slice::from_ref(&k)).is_none());
    assert_eq!(
        reclaim_stale_ref_for_create(&store, &spy, SCOPE, &id),
        StaleRefOutcome::Busy
    );
    assert_eq!(spy.gets.load(Ordering::SeqCst), 0);
    assert_eq!(unbound_keys(&store), vec![k.clone()]);
    drop(pass);
    let outcome = reclaim_stale_ref_for_create(&store, &spy, SCOPE, &id);
    assert!(matches!(outcome, StaleRefOutcome::ReclaimedUnbound(_)));
    assert_eq!(unbound_keys(&store), Vec::<ContainerRefId>::new());
}

/// OCI-7: 状態を確認できない・存在する未確定参照は、契機 A でも外さない。
#[test]
fn oci7_reclaim_keeps_unbound_when_undetermined() {
    let tmp = Tmp::new("keep");
    let store = seeded_store(&tmp);
    let k = key(SCOPE, "c1");
    let id = ContainerId::new("c1").expect("id");
    register(&store, &k);
    let timeout = SpyStore::failing(ErrorCode::Timeout);
    assert_eq!(
        reclaim_stale_ref_for_create(&store, &timeout, SCOPE, &id),
        StaleRefOutcome::KeptUndetermined
    );
    assert_eq!(unbound_keys(&store), vec![k]);
    // 登録の無い ID は何もしない。
    let other = ContainerId::new("zzz").expect("id");
    assert_eq!(
        reclaim_stale_ref_for_create(&store, &timeout, SCOPE, &other),
        StaleRefOutcome::NotRegistered
    );
}
