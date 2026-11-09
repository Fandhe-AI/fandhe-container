//! Linux・macOS 以外（Windows）でのファイルベース `StateStore` の挙動の照合（OCI-7・TASK-183.8.1・#2325）。
//!
//! `container_image_refs.rs` の create / delete 通し試験はファイルベースの `StateStore` を使うが、これは状態ルートを
//! 検証できる Linux でしか動かない（macOS は #2247 で `FileStateStore` が開けるようになったが通し試験の対象外。
//! Windows ホストは設計上の恒久拒否で `FailedPrecondition`。#2428 の案 C・#4332）。そのため通し試験は Linux 限定とし、
//! Windows では「状態ストアを開けず `FailedPrecondition` で明示的に拒否されること」を具体値で確かめる。

#![cfg(not(any(target_os = "linux", target_os = "macos")))]

use fandhe_container_core::state_store::{FileStateStore, StateRoot};
use fandhe_container_core::traits::ErrorCode;

/// Windows ホストでは `FileStateStore::open` が `FailedPrecondition` と固定のメッセージで失敗する（設計上の拒否）。
#[test]
fn oci7_file_state_store_is_rejected_by_design_on_windows_host() {
    let dir = std::env::temp_dir().join(format!("fandhe-oci-cimg-nl-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("dir");
    let root = StateRoot::from_override(dir.clone()).expect("state root");
    let err = FileStateStore::open(root).expect_err("must be rejected");
    assert_eq!(err.code(), ErrorCode::FailedPrecondition);
    assert_eq!(
        err.message(),
        "file state store is not supported on a Windows host by design; the state root belongs in the Linux guest"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
