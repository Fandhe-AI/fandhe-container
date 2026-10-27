//! 記録ストア（`FileRecordStore`・`RecordStore`）の公開 API 経由の結合試験（CRI-1・OCI-7・REPAIR-12）。
//!
//! plugin-cri と同じ立場で、保存・再オープンでの復元・ID 昇順の列挙・削除（冪等）・上限超過の拒否を
//! 具体値で照合する。ユニット試験は `record_store/file.rs` に併置する。

#![cfg(unix)]

use std::fs;
use std::os::unix::fs::DirBuilderExt;
use std::path::PathBuf;

use fandhe_container_cri::error::CriErrorCode;
use fandhe_container_cri::runtime_service::{
    FileRecordStore, ListBudget, ListLimits, RecordId, RecordKind, RecordStore,
};

const ID_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const ID_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn temp_root(tag: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "fandhe-cri-record-store-it-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    fs::DirBuilder::new().mode(0o700).create(&p).unwrap();
    p
}

fn id(s: &str) -> RecordId {
    RecordId::new(s).unwrap()
}

fn list(store: &FileRecordStore, kind: RecordKind) -> Vec<(String, Vec<u8>)> {
    let l = store
        .list(kind, ListBudget::default(), ListLimits::for_kind(kind))
        .unwrap();
    assert_eq!(l.unrecognized, 0);
    l.records
        .into_iter()
        .map(|r| (r.id.as_str().to_string(), r.outcome.unwrap()))
        .collect()
}

/// CRI-1・OCI-7・REPAIR-12: 保存した記録が新しいインスタンスで復元され、ID の昇順で列挙される。
#[test]
fn cri1_record_store_put_reopen_list_in_id_order() {
    let root = temp_root("reopen");
    let store = FileRecordStore::open(&root).unwrap();
    // 逆順で置いても列挙は昇順。
    store.put(RecordKind::Sandbox, &id(ID_B), b"two").unwrap();
    store.put(RecordKind::Sandbox, &id(ID_A), b"one").unwrap();
    store.put(RecordKind::Container, &id(ID_A), b"ctr").unwrap();
    drop(store);

    let reopened = FileRecordStore::open(&root).unwrap();
    assert_eq!(
        list(&reopened, RecordKind::Sandbox),
        vec![
            (ID_A.to_string(), b"one".to_vec()),
            (ID_B.to_string(), b"two".to_vec())
        ]
    );
    assert_eq!(
        list(&reopened, RecordKind::Container),
        vec![(ID_A.to_string(), b"ctr".to_vec())]
    );
    fs::remove_dir_all(&root).unwrap();
}

/// CRI-1・REPAIR-12: 同名の put は置き換え、remove は消して冪等。
#[test]
fn cri1_record_store_overwrite_and_remove_is_idempotent() {
    let root = temp_root("remove");
    let store = FileRecordStore::open(&root).unwrap();
    let kind = RecordKind::Sandbox;
    store.put(kind, &id(ID_A), b"v1").unwrap();
    store.put(kind, &id(ID_A), b"v2").unwrap();
    assert_eq!(list(&store, kind), vec![(ID_A.to_string(), b"v2".to_vec())]);
    store.remove(kind, &id(ID_A)).unwrap();
    store.remove(kind, &id(ID_A)).unwrap();
    assert!(list(&store, kind).is_empty());
    fs::remove_dir_all(&root).unwrap();
}

/// REPAIR-5・REPAIR-12: 記録の長さ上限超過は何も書かずに拒否し、件数上限超過の列挙は全体を失敗にする。
#[test]
fn repair5_record_store_rejects_over_limit() {
    let root = temp_root("limit");
    let store = FileRecordStore::open(&root).unwrap();
    let kind = RecordKind::Sandbox;

    let big = vec![b'x'; kind.max_record_bytes() + 1];
    let e = store.put(kind, &id(ID_A), &big).unwrap_err();
    assert_eq!(e.code(), CriErrorCode::Internal);
    assert!(list(&store, kind).is_empty());

    store.put(kind, &id(ID_A), b"a").unwrap();
    store.put(kind, &id(ID_B), b"b").unwrap();
    let limits = ListLimits::for_kind(kind).with_max_records(kind, 1);
    let e = store.list(kind, ListBudget::default(), limits).unwrap_err();
    assert_eq!(e.code(), CriErrorCode::FailedPrecondition);
    let ok = ListLimits::for_kind(kind).with_max_records(kind, 2);
    assert_eq!(
        store
            .list(kind, ListBudget::default(), ok)
            .unwrap()
            .records
            .len(),
        2
    );
    fs::remove_dir_all(&root).unwrap();
}
