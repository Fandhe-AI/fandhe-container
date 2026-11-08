//! delete action の前段（`-id`・`-bundle` の検証と状態ルートの記録の照合）の試験（CRI-5・SEC-1・REPAIR-4・#4151）。
//!
//! 親の `shim` から `#[cfg(all(test, target_os = "linux"))]` で取り込む。実の `FileStateStore` を一時ディレクトリに作り、
//! 照合の前後で状態ルートの木（相対パス・種別・長さ・mtime・mode）が完全一致することで「副作用なし」を照合する。

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use fandhe_container_core::state_store::FileStateStore;
use fandhe_container_core::traits::{
    ContainerStatus, CreateStateRequest, DeleteStateRequest, DeleteStateResponse, ListStateRequest,
    StateList, StateRevision, TraitError, UpdateStateRequest,
};
use fandhe_container_cri::error::CriErrorCode;
use fandhe_container_cri::shim_v2::ShutdownSignal;
use fandhe_container_cri::shim_v2::bootstrap::{ShimIdentifier, parse_args};

use super::*;
use crate::test_root;

const ADDR: &str = "/run/c.sock";

type Snap = BTreeMap<String, (bool, u64, i64, i64, u32)>;

/// delete の argv を組んで解析する。
fn parse(id: &str, bundle: Option<&str>) -> Result<ShimInvocation, CriError> {
    let mut v: Vec<OsString> = ["-namespace", "default", "-address", ADDR, "-id", id]
        .iter()
        .map(OsString::from)
        .collect();
    if let Some(b) = bundle {
        v.push("-bundle".into());
        v.push(b.into());
    }
    v.push("delete".into());
    parse_args(v)
}

/// 木の完全な写し。前後で一致すれば何も書いていない。
fn snapshot(root: &Path) -> Snap {
    fn walk(dir: &Path, root: &Path, out: &mut Snap) {
        for e in std::fs::read_dir(dir).unwrap() {
            let e = e.unwrap();
            let md = std::fs::symlink_metadata(e.path()).unwrap();
            let rel = e.path().strip_prefix(root).unwrap().display().to_string();
            out.insert(
                rel,
                (
                    md.is_dir(),
                    md.len(),
                    md.mtime(),
                    md.mtime_nsec(),
                    md.mode(),
                ),
            );
            if md.is_dir() {
                walk(&e.path(), root, out);
            }
        }
    }
    let mut out = Snap::new();
    walk(root, root, &mut out);
    out
}

fn ctx() -> ServeContext {
    ServeContext::new(ShutdownSignal::new(), None).with_origin(
        Some(ShimIdentifier::parse("default").unwrap()),
        Some(PathBuf::from(ADDR)),
    )
}

/// bundle の実ディレクトリ `<root>/b/default/<id>` を作る。
fn make_bundle(root: &Path, id: &str) -> PathBuf {
    let b = root.join("b").join("default").join(id);
    std::fs::create_dir_all(&b).unwrap();
    b
}

/// serve と同じ `scoped_root` のストアへ記録を 1 件入れる。
fn seed(base: &Path, status: ContainerStatus, bundle: &Path) -> FileStateStore {
    let store = FileStateStore::open(scoped_root(base, &ctx()).unwrap()).unwrap();
    store
        .create(&CreateStateRequest::new(status, bundle.to_path_buf()).unwrap())
        .unwrap();
    store
}

fn cid(s: &str) -> ContainerId {
    ContainerId::new(s).unwrap()
}

/// CRI-5・SEC-1・#4151: 不正な `-id`・`-bundle` は構造化エラーで拒否され、状態ルートの木は変わらない。
#[test]
fn cri5_4151_delete_rejects_invalid_args_without_touching_state_root() {
    let guard = test_root::test_root("shim", "d-invalid");
    let base = guard.join("state");
    let good = make_bundle(&guard, "abc");
    seed(&base, ContainerStatus::created(cid("abc"), None), &good);
    let sib = guard.join("state-shim-state");
    let before = snapshot(&sib);

    std::fs::write(guard.join("b/default/file"), b"x").unwrap();
    std::os::unix::fs::symlink(&good, guard.join("b/default/link")).unwrap();
    std::fs::create_dir_all(guard.join("b/default/other")).unwrap();
    std::fs::create_dir_all(guard.join("b/default/gone").parent().unwrap()).unwrap();
    let g = |rel: &str| format!("{}/b/default/{rel}", guard.display());
    // (id, bundle, 期待する固定文言)
    let rows: Vec<(&str, Option<String>, &str)> = vec![
        ("abc", None, "bundle is required for delete"),
        (
            "abc",
            Some("rel/abc".into()),
            "bundle must be an absolute path",
        ),
        (
            "abc",
            Some(g("missing")),
            "bundle must end with the container id",
        ),
        ("file", Some(g("file")), "bundle must be a directory"),
        ("link", Some(g("link")), "bundle must not be a symlink"),
        (
            "link",
            Some(format!("{}/", g("link"))),
            "bundle must not be a symlink",
        ),
        (
            "abc",
            Some(g("other")),
            "bundle must end with the container id",
        ),
        (
            "abc",
            Some(g("./abc")),
            "bundle must not contain dot segments",
        ),
        (
            "abc",
            Some(g("../default/abc")),
            "bundle must not contain dot segments",
        ),
        ("gone", Some(g("gone")), "bundle does not exist"),
    ];
    for (id, bundle, msg) in rows {
        // parse_args が先に拒否する形（相対パス）は、検証関数単独でも同じ文言で守ることを確かめる。
        let inv = match parse(id, bundle.as_deref()) {
            Ok(i) => i,
            Err(e) => {
                assert_eq!(e.code(), CriErrorCode::InvalidArgument, "{id}");
                let mut i = parse(id, Some("/placeholder/x")).unwrap();
                i.bundle = bundle.as_deref().map(PathBuf::from);
                i
            }
        };
        let e = delete_preflight_in(&inv, &base).unwrap_err();
        assert_eq!(e.code(), CriErrorCode::InvalidArgument, "{id} {bundle:?}");
        assert_eq!(e.message(), msg, "{id} {bundle:?}");
    }
    // 不正な id は parse_args の段で拒否される。
    let long_id = "a".repeat(77);
    for id in ["", long_id.as_str(), "a/b", "..", "a..b"] {
        let e = parse(id, Some(&g("abc"))).unwrap_err();
        assert_eq!(e.code(), CriErrorCode::InvalidArgument, "{id:?}");
    }
    assert_eq!(snapshot(&sib), before, "state root must not change");
}

/// 読み取り専用の偽ストア: `get` だけが記録を返し、他は呼ばれたら数えて失敗する。
struct ReadOnlyStore {
    get: Result<StateRecord, ErrorCode>,
    calls: AtomicUsize,
    others: AtomicUsize,
}

impl StateStore for ReadOnlyStore {
    fn create(&self, _: &CreateStateRequest) -> Result<StateRecord, TraitError> {
        self.others.fetch_add(1, Ordering::SeqCst);
        Err(TraitError::new(ErrorCode::Internal, "unexpected create"))
    }
    fn update(&self, _: &UpdateStateRequest) -> Result<StateRecord, TraitError> {
        self.others.fetch_add(1, Ordering::SeqCst);
        Err(TraitError::new(ErrorCode::Internal, "unexpected update"))
    }
    fn get(&self, _: &GetStateRequest) -> Result<StateRecord, TraitError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        match &self.get {
            Ok(r) => Ok(r.clone()),
            Err(c) => Err(TraitError::new(*c, "x")),
        }
    }
    fn list(&self, _: &ListStateRequest) -> Result<StateList, TraitError> {
        self.others.fetch_add(1, Ordering::SeqCst);
        Err(TraitError::new(ErrorCode::Internal, "unexpected list"))
    }
    fn delete(&self, _: &DeleteStateRequest) -> Result<DeleteStateResponse, TraitError> {
        self.others.fetch_add(1, Ordering::SeqCst);
        Err(TraitError::new(ErrorCode::Internal, "unexpected delete"))
    }
}

fn target(id: &str, bundle: &str) -> DeleteTarget {
    DeleteTarget {
        id: cid(id),
        bundle: PathBuf::from(bundle),
    }
}

fn record(status: ContainerStatus, bundle: &str) -> StateRecord {
    StateRecord::new(status, PathBuf::from(bundle), StateRevision::INITIAL).unwrap()
}

fn run_match(
    get: Result<StateRecord, ErrorCode>,
    t: &DeleteTarget,
) -> (Result<DeleteRecordMatch, CriError>, usize, usize) {
    let s = ReadOnlyStore {
        get,
        calls: AtomicUsize::new(0),
        others: AtomicUsize::new(0),
    };
    let r = match_delete_record(&s, t);
    (
        r,
        s.calls.load(Ordering::SeqCst),
        s.others.load(Ordering::SeqCst),
    )
}

/// CRI-5・REPAIR-4・#4151: 各状態の記録・回収済み・期限切れ・不整合を分類し、`get` 以外を呼ばない。
#[test]
fn cri5_4151_match_classifies_records_with_get_only() {
    let t = target("abc", "/s/default/abc");
    let nz = std::num::NonZeroU32::new(4242);
    let (r, g, o) = run_match(Err(ErrorCode::NotFound), &t);
    assert_eq!(r.unwrap(), DeleteRecordMatch::AlreadyReclaimed);
    assert_eq!((g, o), (1, 0));

    for (st, state, pid, code) in [
        (
            ContainerStatus::created(cid("abc"), nz),
            "created",
            nz,
            None,
        ),
        (
            ContainerStatus::running(cid("abc"), nz),
            "running",
            nz,
            None,
        ),
        (
            ContainerStatus::stopped(cid("abc"), Some(7)),
            "stopped",
            None,
            Some(7),
        ),
    ] {
        let rec = record(st, "/s/default/abc");
        let (r, g, o) = run_match(Ok(rec.clone()), &t);
        let DeleteRecordMatch::Recorded(got) = r.unwrap() else {
            panic!("expected Recorded");
        };
        assert_eq!(*got, rec);
        assert_eq!(got.status().state().as_str(), state);
        assert_eq!(got.status().pid(), pid);
        assert_eq!(got.status().exit_code(), code);
        assert_eq!((g, o), (1, 0));
    }

    // 区切りの重複・末尾の区切りは Path の比較で同一視する。
    let rec = record(ContainerStatus::created(cid("abc"), nz), "/s//default/abc/");
    assert!(matches!(
        run_match(Ok(rec), &t).0.unwrap(),
        DeleteRecordMatch::Recorded(_)
    ));

    let (r, g, o) = run_match(Err(ErrorCode::Timeout), &t);
    assert_eq!(r.unwrap_err().code(), CriErrorCode::Timeout);
    assert_eq!((g, o), (1, 0));
    let (r, _, _) = run_match(Err(ErrorCode::Internal), &t);
    assert_eq!(r.unwrap_err().message(), "cannot read the state record");

    let other_bundle = record(ContainerStatus::created(cid("abc"), nz), "/s/default/zzz");
    let e = run_match(Ok(other_bundle), &t).0.unwrap_err();
    assert_eq!(e.code(), CriErrorCode::FailedPrecondition);
    assert_eq!(e.message(), "bundle does not match the recorded container");
    let other_id = record(ContainerStatus::created(cid("xyz"), nz), "/s/default/abc");
    let e = run_match(Ok(other_id), &t).0.unwrap_err();
    assert_eq!(e.message(), "state store is inconsistent");
}

/// CRI-5・REPAIR-4・#4151: 実の `FileStateStore` に対して、記録あり・回収済みを返し、状態ルートの木を一切変えない。
#[test]
fn cri5_4151_preflight_with_real_store_is_read_only() {
    let guard = test_root::test_root("shim", "d-real");
    let base = guard.join("state");
    let bundle = make_bundle(&guard, "abc");
    let store = seed(
        &base,
        ContainerStatus::running(cid("abc"), std::num::NonZeroU32::new(99)),
        &bundle,
    );
    drop(store);
    let sib = guard.join("state-shim-state");
    let before = snapshot(&sib);
    let inv = parse("abc", Some(bundle.to_str().unwrap())).unwrap();
    let DeleteRecordMatch::Recorded(rec) = delete_preflight_in(&inv, &base).unwrap() else {
        panic!("expected Recorded");
    };
    assert_eq!(rec.status().state().as_str(), "running");
    assert_eq!(rec.status().pid(), std::num::NonZeroU32::new(99));
    assert_eq!(rec.bundle(), bundle.as_path());
    assert_eq!(snapshot(&sib), before, "state root must not change");

    // 同じ ID の別 bundle は別のコンテナの記録として拒否する。
    let other = guard.join("b/ns2/abc");
    std::fs::create_dir_all(&other).unwrap();
    let inv2 = parse("abc", Some(other.to_str().unwrap())).unwrap();
    let e = delete_preflight_in(&inv2, &base).unwrap_err();
    assert_eq!(e.code(), CriErrorCode::FailedPrecondition);

    // 記録が無い id は回収済み。
    let gone = make_bundle(&guard, "gone");
    let inv3 = parse("gone", Some(gone.to_str().unwrap())).unwrap();
    assert_eq!(
        delete_preflight_in(&inv3, &base).unwrap(),
        DeleteRecordMatch::AlreadyReclaimed
    );
    assert_eq!(snapshot(&sib), before, "state root must not change");
}

/// CRI-5・SEC-1・#4151: 階層が無い・`@lock` が無いときは記録なし。不整合と開いた権限・symlink は拒否する。何も作らない。
#[test]
fn cri5_4151_preflight_not_recorded_and_fail_closed() {
    let guard = test_root::test_root("shim", "d-absent");
    let base = guard.join("state");
    let bundle = make_bundle(&guard, "abc");
    let inv = parse("abc", Some(bundle.to_str().unwrap())).unwrap();
    let sib = guard.join("state-shim-state");

    // 階層が全く無い: 記録なしで、何も作らない。
    assert_eq!(
        delete_preflight_in(&inv, &base).unwrap(),
        DeleteRecordMatch::NotRecorded
    );
    assert!(!sib.exists() && !base.exists());

    // 階層はあるが `@lock` も記録も無い（serve が開いて何もしていない）: 記録なし。
    let root = scoped_root_path(&base, inv.namespace.as_ref(), inv.address.as_deref()).unwrap();
    drop(FileStateStore::open(scoped_root(&base, &ctx()).unwrap()).unwrap());
    assert!(root.is_dir());
    let before = snapshot(&sib);
    assert_eq!(
        delete_preflight_in(&inv, &base).unwrap(),
        DeleteRecordMatch::NotRecorded
    );
    assert_eq!(snapshot(&sib), before);

    // `@lock` が無いのに記録の階層がある: 不整合。
    std::fs::create_dir(root.join("abc")).unwrap();
    let e = delete_preflight_in(&inv, &base).unwrap_err();
    assert_eq!(e.code(), CriErrorCode::Internal);
    assert_eq!(e.message(), "state store is inconsistent");
    std::fs::remove_dir(root.join("abc")).unwrap();

    // group / other に開いた権限は拒否する。
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755)).unwrap();
    let e = delete_preflight_in(&inv, &base).unwrap_err();
    assert_eq!(e.message(), "state root directory is not private");
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();

    // 途中の階層が symlink なら拒否する。
    let hashed = root.parent().unwrap().to_path_buf();
    let moved = guard.join("moved");
    std::fs::rename(&hashed, &moved).unwrap();
    std::os::unix::fs::symlink(&moved, &hashed).unwrap();
    let e = delete_preflight_in(&inv, &base).unwrap_err();
    assert_eq!(e.message(), "state root directory is not private");
}
