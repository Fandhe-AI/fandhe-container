//! 本番の入口（`production_bundle_provider` / `image_service`）が展開設定の権限解決を共有し、
//! 解決の失敗を呼び出し元へ伝える配線の結合試験（SEC-5・OCI-1・REPAIR-12。#2792）。
//!
//! `production()` は環境の状態ルート（`$XDG_RUNTIME_DIR/fandhe-container`）を使うため、試験バイナリ自身を
//! 一時の `XDG_RUNTIME_DIR` つきの子プロセスとして起動する（`production_image_inventory.rs` と同じ方式）。
//! 子の中で `with_extract_identity_resolver` に呼び出し回数を数える解決器を差し、公開入口だけを通して
//! 「2 つの入口で解決は 1 回」「解決の失敗は縮退せず `FAILED_PRECONDITION` で両入口に伝わる」を具体値で照合する。
//! 非 root 前提を明示検証し、満たさなければ失敗させる。子の実行は期限つきで回収する（REPAIR-5）。
#![cfg(target_os = "linux")]

#[path = "../../net/tests/support/exclusive_dir.rs"]
mod exclusive_dir;
#[path = "../../core/tests/support/reap.rs"]
mod reap;

use std::path::Path;
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use fandhe_container_cri::error::{CriError, CriErrorCode};
use fandhe_container_plugin_cri::adapter::CriPluginBackends;
use fandhe_container_plugin_cri::extract_identity::ExtractIdentity;

const ENV_PHASE: &str = "FC_CRI_EXID_PHASE";
const CHILD_TEST: &str = "child_phase";

fn is_root() -> bool {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("Uid:"))
                .map(|l| l.split_whitespace().nth(2) == Some("0"))
        })
        .unwrap_or(false)
}

/// 子プロセスの本体。`FC_CRI_EXID_PHASE` が無いとき（通常の試験実行）は何もしない。
#[test]
fn child_phase() {
    let Ok(phase) = std::env::var(ENV_PHASE) else {
        return;
    };
    let calls = Arc::new(AtomicUsize::new(0));
    let c = Arc::clone(&calls);
    let backends = CriPluginBackends::production().expect("production");
    match phase.as_str() {
        "shared" => {
            let backends = backends.with_extract_identity_resolver(move || {
                c.fetch_add(1, Ordering::SeqCst);
                Ok(ExtractIdentity::RootlessSingleId)
            });
            backends.production_bundle_provider().expect("provider");
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            backends.image_service().expect("image service");
            // 2 つ目の入口は保持した解決結果を使い、再解決しない。
            assert_eq!(calls.load(Ordering::SeqCst), 1);
        }
        "fail" => {
            let backends = backends.with_extract_identity_resolver(move || {
                c.fetch_add(1, Ordering::SeqCst);
                Err(CriError::failed_precondition("failed to resolve"))
            });
            let Err(e1) = backends.production_bundle_provider() else {
                panic!("provider must fail");
            };
            assert_eq!(e1.code(), CriErrorCode::FailedPrecondition);
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            // 失敗は保持せず、もう一方の入口も同じ区分で失敗する（既定値へ縮退しない）。
            let Err(e2) = backends.image_service() else {
                panic!("image service must fail");
            };
            assert_eq!(e2.code(), CriErrorCode::FailedPrecondition);
            assert_eq!(calls.load(Ordering::SeqCst), 2);
        }
        other => panic!("unknown phase {other}"),
    }
}

fn run_child(xdg: &Path, phase: &str) {
    let mut cmd = Command::new(std::env::current_exe().expect("exe"));
    cmd.args(["--exact", CHILD_TEST, "--nocapture", "--test-threads=1"])
        .env("XDG_RUNTIME_DIR", xdg)
        .env(ENV_PHASE, phase);
    let out = reap::output_within(&mut cmd, std::time::Duration::from_secs(120))
        .unwrap_or_else(|e| panic!("phase {phase} child: {e}"));
    assert!(
        out.status.success(),
        "phase {phase} failed: {}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("1 passed"),
        "phase {phase} did not run the child test"
    );
}

/// SEC-5・OCI-1・#2792: 公開入口 2 つで解決は 1 回だけ、失敗は両入口へ `FAILED_PRECONDITION` で伝わる。
#[test]
fn sec5_oci1_2792_entrypoints_share_resolution_and_propagate_failure() {
    if std::env::var_os(ENV_PHASE).is_some() {
        return;
    }
    assert!(
        !is_root(),
        "PRECONDITION FAILED: must run as non-root (the default state root would be a host path)"
    );
    let base = std::env::temp_dir().canonicalize().expect("temp dir");
    for phase in ["shared", "fail"] {
        let xdg = exclusive_dir::create_in(&base, "fc-cri-exid").expect("mkdir");
        run_child(&xdg, phase);
        let _ = std::fs::remove_dir_all(&xdg);
    }
}
