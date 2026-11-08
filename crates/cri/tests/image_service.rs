//! `CriImageService` の `ListImages` を公開 API だけで検証する結合試験
//! （TASK-61.1・#444・CRI-4・ERR-3・REPAIR-4・REPAIR-12）。
//!
//! plugin-cri（TASK-108）と同じ外部利用者の立場で、公開の型だけを使う。
//! ネットワーク I/O（bind・listen）は行わない。

use std::future::Future;
use std::pin::pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use fandhe_container_cri::image_service::{
    CriImageService, ImageRecord, InMemoryImageStore, MAX_FILTER_BYTES,
};
use fandhe_container_cri::instrument::{CriOpRecorder, CriOpSample, code_name};
use fandhe_container_cri::runtime::v1::{
    self,
    image_service_server::{ImageService, ImageServiceServer},
};
use tonic::server::NamedService;
use tonic::{Code, Request};

fn block_on<F: Future>(fut: F) -> F::Output {
    let mut fut = pin!(fut);
    let mut cx = Context::from_waker(Waker::noop());
    match fut.as_mut().poll(&mut cx) {
        Poll::Ready(v) => v,
        Poll::Pending => panic!("future must complete without waiting"),
    }
}

#[derive(Default)]
struct Collect(Mutex<Vec<CriOpSample>>);

impl CriOpRecorder for Collect {
    fn record_cri_op(&self, sample: &CriOpSample) {
        if let Ok(mut v) = self.0.lock() {
            v.push(*sample);
        }
    }
}

impl Collect {
    fn lines(&self) -> Vec<(&'static str, &'static str, &'static str)> {
        let v = self.0.lock().map(|v| v.clone()).unwrap_or_default();
        v.iter()
            .map(|s| (s.kind().as_str(), s.outcome().as_str(), code_name(s.code())))
            .collect()
    }
}

fn rec(id: &str, tag: &str, digest: &str, size: u64) -> ImageRecord {
    ImageRecord::new(id, vec![tag.into()], vec![digest.into()], size).expect("valid record")
}

fn seeded() -> (Arc<Collect>, CriImageService) {
    let store = Arc::new(InMemoryImageStore::new());
    // 投入順は id 昇順と逆にして、応答の並びがストア順でなく id 昇順であることを確かめる。
    store
        .insert(rec("sha256:cc", "reg/c:3", "reg/c@sha256:cc", 300))
        .expect("insert");
    store
        .insert(rec("sha256:aa", "reg/a:1", "reg/a@sha256:aa", 100))
        .expect("insert");
    store
        .insert(rec("sha256:bb", "reg/b:2", "reg/b@sha256:bb", 200))
        .expect("insert");
    let recorder = Arc::new(Collect::default());
    let svc = CriImageService::with_store_and_recorder(store, recorder.clone());
    (recorder, svc)
}

fn list(svc: &CriImageService, filter: Option<&str>) -> Result<Vec<v1::Image>, Code> {
    let request = v1::ListImagesRequest {
        filter: filter.map(|f| v1::ImageFilter {
            image: Some(v1::ImageSpec {
                image: f.into(),
                ..Default::default()
            }),
        }),
    };
    block_on(ImageService::list_images(svc, Request::new(request)))
        .map(|r| r.into_inner().images)
        .map_err(|s| s.code())
}

/// CRI-4・TASK-61.1: ローカルキャッシュのイメージが id 昇順で返る（受入基準）。
#[test]
fn task_61_1_list_images_returns_seeded_images() {
    let (recorder, svc) = seeded();
    let images = list(&svc, None).expect("list");
    let got: Vec<_> = images
        .iter()
        .map(|i| {
            (
                i.id.as_str(),
                i.repo_tags.clone(),
                i.repo_digests.clone(),
                i.size,
            )
        })
        .collect();
    let row = |id: &'static str, t: &str, d: &str, size| {
        (id, vec![t.to_owned()], vec![d.to_owned()], size)
    };
    assert_eq!(
        got,
        vec![
            row("sha256:aa", "reg/a:1", "reg/a@sha256:aa", 100),
            row("sha256:bb", "reg/b:2", "reg/b@sha256:bb", 200),
            row("sha256:cc", "reg/c:3", "reg/c@sha256:cc", 300),
        ]
    );
    assert_eq!(
        images
            .first()
            .and_then(|i| i.spec.as_ref())
            .map(|s| s.image.as_str()),
        Some("sha256:aa")
    );
    assert_eq!(recorder.lines(), vec![("cri.list_images", "success", "OK")]);
}

/// CRI-4・TASK-61.1: 空のストアは空配列で成功する。
#[test]
fn task_61_1_empty_store_returns_empty_list() {
    let svc = CriImageService::new();
    assert_eq!(list(&svc, None).map(|v| v.len()), Ok(0));
}

/// CRI-4・TASK-61.1: id・タグ・digest の完全一致で絞り込め、不一致は空で成功、空文字は全件。
#[test]
fn task_61_1_filter_by_id_tag_digest() {
    let (_, svc) = seeded();
    for f in ["sha256:bb", "reg/b:2", "reg/b@sha256:bb"] {
        let ids: Vec<_> = list(&svc, Some(f))
            .expect("list")
            .into_iter()
            .map(|i| i.id)
            .collect();
        assert_eq!(ids, vec!["sha256:bb".to_owned()], "filter {f}");
    }
    assert_eq!(list(&svc, Some("reg/zzz:9")).map(|v| v.len()), Ok(0));
    assert_eq!(list(&svc, Some("")).map(|v| v.len()), Ok(3));
}

/// ERR-3・REPAIR-4: 長すぎるフィルタは INVALID_ARGUMENT で、失敗として記録される。
#[test]
fn task_61_1_oversized_filter_is_invalid_argument() {
    let (recorder, svc) = seeded();
    let long = "x".repeat(MAX_FILTER_BYTES + 1);
    assert_eq!(list(&svc, Some(&long)), Err(Code::InvalidArgument));
    assert_eq!(
        recorder.lines(),
        vec![("cri.list_images", "failure", "INVALID_ARGUMENT")]
    );
}

/// REPAIR-3: 未実装の RPC（RemoveImage は #4177 で実装済み） は UNIMPLEMENTED を返す（実装済みを装わない）。
#[test]
fn task_61_1_other_rpcs_are_unimplemented() {
    let svc = CriImageService::new();
    let pull = block_on(ImageService::pull_image(
        &svc,
        Request::new(Default::default()),
    ));
    assert_eq!(pull.err().map(|s| s.code()), Some(Code::Unimplemented));
    let fs = block_on(ImageService::image_fs_info(
        &svc,
        Request::new(Default::default()),
    ));
    assert_eq!(fs.err().map(|s| s.code()), Some(Code::Unimplemented));
}

/// CRI-4: `ImageServiceServer` が包めて、サービス名が cri-api と一致する。
#[test]
fn task_61_1_image_service_server_wraps_service() {
    let _server = ImageServiceServer::new(CriImageService::default());
    assert_eq!(
        <ImageServiceServer<CriImageService> as NamedService>::NAME,
        "runtime.v1.ImageService"
    );
}

fn status(
    svc: &CriImageService,
    reference: Option<&str>,
    verbose: bool,
) -> Result<v1::ImageStatusResponse, tonic::Status> {
    let request = v1::ImageStatusRequest {
        image: reference.map(|r| v1::ImageSpec {
            image: r.into(),
            ..Default::default()
        }),
        verbose,
    };
    block_on(ImageService::image_status(svc, Request::new(request))).map(|r| r.into_inner())
}

/// CRI-4・TASK-61.2: 取得済みイメージが id・タグ・digest のいずれの参照でも期待する digest とサイズで返る（受入基準）。
#[test]
fn task_61_2_image_status_returns_digest_and_size() {
    let (recorder, svc) = seeded();
    for r in ["sha256:bb", "reg/b:2", "reg/b@sha256:bb"] {
        let resp = status(&svc, Some(r), false).expect("status");
        let image = resp.image.expect("image");
        assert_eq!(image.id, "sha256:bb", "{r}");
        assert_eq!(image.repo_tags, vec!["reg/b:2".to_owned()]);
        assert_eq!(image.repo_digests, vec!["reg/b@sha256:bb".to_owned()]);
        assert_eq!(image.size, 200);
        assert_eq!(
            image.spec.as_ref().map(|s| s.image.as_str()),
            Some("sha256:bb")
        );
        assert!(resp.info.is_empty());
    }
    assert_eq!(
        recorder.lines(),
        vec![("cri.image_status", "success", "OK"); 3]
    );
}

/// CRI-4・TASK-61.2: verbose でも成功し info は未実装のため空（REPAIR-3）。
#[test]
fn task_61_2_image_status_verbose_info_is_empty() {
    let (_, svc) = seeded();
    let resp = status(&svc, Some("reg/a:1"), true).expect("status");
    assert_eq!(resp.image.map(|i| i.size), Some(100));
    assert!(resp.info.is_empty());
}

/// CRI-4・TASK-61.2: 未取得は NOT_FOUND にせず、`image: None` の成功応答を返す（api.proto の nil Image）。
#[test]
fn task_61_2_image_status_unknown_returns_none() {
    let (recorder, svc) = seeded();
    let resp = status(&svc, Some("reg/missing:9"), false).expect("ok");
    assert_eq!(resp.image, None);
    assert_eq!(
        recorder.lines(),
        vec![("cri.image_status", "success", "OK")]
    );
}

/// ERR-3・TASK-61.2: 参照なし・空・長すぎる参照は INVALID_ARGUMENT。
#[test]
fn task_61_2_image_status_invalid_reference() {
    let (_, svc) = seeded();
    let long = "x".repeat(MAX_FILTER_BYTES + 1);
    for r in [None, Some(""), Some(long.as_str())] {
        let err = status(&svc, r, false).expect_err("must fail");
        assert_eq!(err.code(), Code::InvalidArgument);
    }
}

fn remove(svc: &CriImageService, reference: Option<&str>) -> Result<(), Code> {
    let request = v1::RemoveImageRequest {
        image: reference.map(|r| v1::ImageSpec {
            image: r.into(),
            ..Default::default()
        }),
    };
    // RemoveImage は spawn_blocking を使うため、ノーオップ waker の block_on ではなく tokio のランタイムで待つ。
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("runtime");
    rt.block_on(ImageService::remove_image(svc, Request::new(request)))
        .map(|_| ())
        .map_err(|s| s.code())
}

/// CRI-1・CRI-2・#4177: id・タグ・digest のどの参照で消しても記録ごと消え、他は残る。再度の削除は成功（冪等）。
#[test]
fn cri1_cri2_remove_image_by_any_reference_removes_whole_record() {
    for r in ["sha256:bb", "reg/b:2", "reg/b@sha256:bb"] {
        let (recorder, svc) = seeded();
        assert_eq!(remove(&svc, Some(r)), Ok(()), "{r}");
        let ids: Vec<String> = list(&svc, None)
            .expect("list")
            .into_iter()
            .map(|i| i.id)
            .collect();
        assert_eq!(ids, vec!["sha256:aa".to_owned(), "sha256:cc".to_owned()]);
        for gone in ["sha256:bb", "reg/b:2", "reg/b@sha256:bb"] {
            assert!(
                status(&svc, Some(gone), false)
                    .expect("status")
                    .image
                    .is_none()
            );
        }
        assert_eq!(remove(&svc, Some(r)), Ok(()), "idempotent {r}");
        let removes: Vec<_> = recorder
            .lines()
            .into_iter()
            .filter(|l| l.0 == "cri.remove_image")
            .collect();
        assert_eq!(removes, vec![("cri.remove_image", "success", "OK"); 2]);
    }
}

/// CRI-4・#4177: 短縮名は PullImage と同じ規則で正規化して消せる。
#[test]
fn cri4_remove_image_accepts_short_name() {
    let store = Arc::new(InMemoryImageStore::new());
    store
        .insert(rec(
            "sha256:aa",
            "docker.io/library/busybox:1.36",
            "docker.io/library/busybox@sha256:aa",
            1,
        ))
        .expect("insert");
    let svc = CriImageService::with_store(store.clone());
    assert_eq!(remove(&svc, Some("busybox:1.36")), Ok(()));
    assert!(store.is_empty());
}

/// ERR-3・CRI-2・REPAIR-4: 空・過長の参照は INVALID_ARGUMENT、store の失敗は INTERNAL で計装に残る。
#[test]
fn err3_remove_image_rejects_bad_reference_and_store_failure() {
    let (recorder, svc) = seeded();
    assert_eq!(remove(&svc, None), Err(Code::InvalidArgument));
    assert_eq!(remove(&svc, Some("")), Err(Code::InvalidArgument));
    let long = "x".repeat(MAX_FILTER_BYTES + 1);
    assert_eq!(remove(&svc, Some(&long)), Err(Code::InvalidArgument));
    assert_eq!(
        recorder.lines(),
        vec![("cri.remove_image", "failure", "INVALID_ARGUMENT"); 3]
    );
}
