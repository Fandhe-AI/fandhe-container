//! Linux・macOS 以外（Windows）でのファイルベース `StateStore` の挙動の照合（OCI-7・TASK-183.8.1・#2325）。
//!
//! `container_image_refs.rs` の create / delete 通し試験はファイルベースの `StateStore` を使うが、これは状態ルートを
//! 検証できる Linux でしか動かない（macOS は #2247 で `FileStateStore` が開けるようになったが通し試験の対象外。
//! Windows は `Unimplemented`）。そのため通し試験は Linux 限定とし、
//! Windows では「状態ストアを開けず `Unimplemented` で明示的に拒否されること」を具体値で確かめる。

#![cfg(not(any(target_os = "linux", target_os = "macos")))]

use fandhe_container_core::state_store::{FileStateStore, StateRoot};
use fandhe_container_core::traits::ErrorCode;

/// Linux 以外では `FileStateStore::open` が `Unimplemented` と固定のメッセージで失敗する。
#[test]
fn oci7_file_state_store_is_unimplemented_off_linux() {
    let dir = std::env::temp_dir().join(format!("fandhe-oci-cimg-nl-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("dir");
    let root = StateRoot::from_override(dir.clone()).expect("state root");
    let err = FileStateStore::open(root).expect_err("must be rejected");
    assert_eq!(err.code(), ErrorCode::Unimplemented);
    assert_eq!(
        err.message(),
        "file state store requires Linux or macOS to verify the state root"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
