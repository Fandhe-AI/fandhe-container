//! 本番の組み立て（`CriPluginBackends::production`）を通した在庫の再起動復元の結合試験
//! （CRI-1・CRI-2・OCI-7・REPAIR-12。#4176）。
//!
//! `production()` は環境の状態ルート（rootless は `$XDG_RUNTIME_DIR/fandhe-container`）を使うため、試験バイナリ自身を
//! 子プロセスとして 2 回（pull 段・再起動後の確認段）起動し、同じ一時の `XDG_RUNTIME_DIR` を渡す。
//! pull はレジストリへ出ない固定の puller で行い、在庫の永続化と共有の配線だけを見る。root では既定の状態ルートが
//! 実機のパスになるため走らせない（root の確認は実機前提の別試験）。unix 限定。
#![cfg(unix)]

#[path = "../../net/tests/support/exclusive_dir.rs"]
mod exclusive_dir;

use std::path::Path;
use std::process::Command;
use std::sync::Arc;

use fandhe_container_cri::image_pull::{ImagePuller, PullError, PullRequest, PulledImage};
use fandhe_container_cri::image_service::CriImageService;
use fandhe_container_cri::runtime::v1::{self, image_service_server::ImageService as _};
use fandhe_container_plugin_cri::adapter::CriPluginBackends;
use tonic::Request;

const ENV_PHASE: &str = "FC_CRI_INV_PHASE";
const CHILD_TEST: &str = "child_phase";
const TAG: &str = "docker.io/library/busybox:1.36";

fn image_id() -> String {
    format!("sha256:{}", "c".repeat(64))
}

struct FixedPuller;

impl ImagePuller for FixedPuller {
    fn pull(&self, _request: &PullRequest) -> Result<PulledImage, PullError> {
        Ok(PulledImage {
            id: image_id(),
            repo_tags: vec![TAG.to_owned()],
            repo_digests: vec!["docker.io/library/busybox@sha256:1111".to_owned()],
            size: 4096,
        })
    }
}

fn spec() -> Option<v1::ImageSpec> {
    Some(v1::ImageSpec {
        image: TAG.to_owned(),
        ..Default::default()
    })
}

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

/// 子プロセスの本体。`FC_CRI_INV_PHASE` が無いとき（通常の試験実行）は何もしない。
#[tokio::test]
async fn child_phase() {
    let Ok(phase) = std::env::var(ENV_PHASE) else {
        return;
    };
    let backends = CriPluginBackends::production().expect("production");
    let svc = CriImageService::with_store(Arc::clone(backends.images()))
        .with_puller(Arc::new(FixedPuller));
    match phase.as_str() {
        "pull" => {
            let resp = svc
                .pull_image(Request::new(v1::PullImageRequest {
                    image: spec(),
                    ..Default::default()
                }))
                .await
                .expect("pull");
            assert_eq!(resp.into_inner().image_ref, image_id());
        }
        "verify" => {
            let images = svc
                .list_images(Request::new(v1::ListImagesRequest::default()))
                .await
                .expect("list")
                .into_inner()
                .images;
            assert_eq!(images.len(), 1);
            assert_eq!(images[0].id, image_id());
            assert_eq!(images[0].repo_tags, vec![TAG.to_owned()]);
            let status = svc
                .image_status(Request::new(v1::ImageStatusRequest {
                    image: spec(),
                    ..Default::default()
                }))
                .await
                .expect("status")
                .into_inner();
            assert_eq!(status.image.expect("image").id, image_id());
            // create のタグ解決（bundle 供給と共有の在庫）。
            let rec = backends.images().get(TAG).expect("get").expect("record");
            assert_eq!(rec.id(), image_id());
            backends
                .production_bundle_provider()
                .expect("bundle provider");
        }
        other => panic!("unknown phase {other}"),
    }
}

fn run_child(xdg: &Path, phase: &str) {
    let out = Command::new(std::env::current_exe().expect("exe"))
        .args(["--exact", CHILD_TEST, "--nocapture", "--test-threads=1"])
        .env("XDG_RUNTIME_DIR", xdg)
        .env(ENV_PHASE, phase)
        .output()
        .expect("spawn child");
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

/// CRI-1・CRI-2・OCI-7: 本番の組み立てで PullImage した在庫が、プロセスの再起動後も
/// ListImages・ImageStatus・タグの解決（create の入口）に同じ値で出る。
#[test]
fn cri1_cri2_oci7_production_inventory_survives_restart() {
    if std::env::var_os(ENV_PHASE).is_some() {
        return;
    }
    if is_root() {
        eprintln!("running as root: the default state root is a host path; not exercised");
        return;
    }
    let base = std::env::temp_dir().canonicalize().expect("temp dir");
    let xdg = exclusive_dir::create_in(&base, "fc-cri-prodinv").expect("mkdir");
    run_child(&xdg, "pull");
    run_child(&xdg, "verify");
    let _ = std::fs::remove_dir_all(&xdg);
}
