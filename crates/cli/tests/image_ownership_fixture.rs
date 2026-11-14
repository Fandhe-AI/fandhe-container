//! `image_ownership::extract_ownership_for` を共有 fixture `crates/core/testdata/image_ownership_cases.txt` で照合する
//! （SEC-5・OCI-1・CORE-6・#4798。plugin-cri 側と同じ照合ドライバ・同じ期待値）。
#![cfg(target_os = "linux")]

#[path = "../../core/tests/support/image_ownership_cases.rs"]
mod cases;

use fandhe_container_cli::image_ownership::{ExtractChownMode, extract_ownership_for};

#[test]
fn sec5_oci1_core6_4798_cli_matches_shared_fixture() {
    cases::run(|r, u, g, in_ns| {
        let mode = if in_ns {
            ExtractChownMode::InUserNamespace
        } else {
            ExtractChownMode::InitialNamespace
        };
        extract_ownership_for(r, u, g, mode)
    });
}
