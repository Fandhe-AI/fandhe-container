//! `crictl images` / `crictl pull` / `crictl inspecti` 相当の疎通結合試験（TASK-61.4・#447・CRI-4・OCI-1・REPAIR-4・REPAIR-12）。
//!
//! `ImageService` の `ListImages`・`PullImage`・`ImageStatus` を crictl の実行順に 1 本のシナリオで呼び、
//! すべて成功して結果が互いに整合することを具体値で照合する。実レジストリには接続せず `RegistryPullClient`
//! の偽実装を使うが、digest 検証・キャッシュ公開・ストア登録・ステージング後始末は本物の経路を通す。
//! 実 gRPC 経由の `crictl` 実機確認は plugin-cri（TASK-108・114）以降で、本ファイルの対象外。
//! `image_pull.rs` の偽クライアントのうち本シナリオに必要な最小部分だけを再掲している。

// 非 Unix ではキャッシュのアクセス制御を検証できず `OciImagePuller` が fail-closed で拒否するため Unix 限定。
#![cfg(unix)]

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use fandhe_container_cri::image_pull::{
    ImagePuller, OciImagePuller, PullConfig, PulledManifest, RegistryPullClient,
};
use fandhe_container_cri::image_service::{CriImageService, InMemoryImageStore};
use fandhe_container_cri::instrument::{CriOpOutcome, CriOpRecorder, CriOpSample};
use fandhe_container_cri::runtime::v1::{self, image_service_server::ImageService};
use fandhe_container_oci::auth::{BasicCredentials, RegistryAuth};
use fandhe_container_oci::error::{OciError, OciErrorCode};
use fandhe_container_oci::manifest::{
    Descriptor, ImageManifest, ParsedManifest, Platform, parse_manifest,
};
use fandhe_container_oci::reference::{Digest, Reference, RegistryHost, Repository};
use fandhe_container_oci::registry::RegistryEndpoint;
use tonic::{Code, Request};

// sha256 の既知値（`printf hello | sha256sum` など）。
const SHA_CONFIG: &str = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"; // "hello"
const SHA_LAYER1: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"; // "abc"
const SHA_LAYER2: &str = "486ea46224d1bb4fb680f34f7c9ad96a8f24ec88be73ea8e5a6c65260e9cb8a7"; // "world"
/// 偽クライアントが返す manifest の digest（試験では内容を持たない任意値）。
const SHA_INDEX_PICK: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

fn blob_body(hex: &str) -> &'static [u8] {
    match hex {
        SHA_CONFIG => b"hello",
        SHA_LAYER1 => b"abc",
        SHA_LAYER2 => b"world",
        _ => b"",
    }
}

fn manifest_json(config: &str, layers: &[(&str, u64)]) -> String {
    let layers: Vec<String> = layers
        .iter()
        .map(|(h, s)| {
            format!(
                r#"{{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"sha256:{h}","size":{s}}}"#
            )
        })
        .collect();
    format!(
        r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:{config}","size":5}},"layers":[{}]}}"#,
        layers.join(",")
    )
}
fn parse_image(json: &str) -> ImageManifest {
    match parse_manifest(
        json.as_bytes(),
        Some("application/vnd.oci.image.manifest.v1+json"),
    )
    .expect("manifest")
    {
        ParsedManifest::Image(m) => m,
        _ => panic!("image manifest expected"),
    }
}

fn two_layer_manifest() -> String {
    manifest_json(SHA_CONFIG, &[(SHA_LAYER1, 3), (SHA_LAYER2, 5)])
}

/// 偽クライアント。manifest 本文と blob 本文を返し、blob 取得回数を数える。
struct FakeClient {
    manifest_json: String,
    manifest_digest: Digest,
    corrupt_digest: Option<&'static str>,
    blob_fetches: AtomicUsize,
}

impl FakeClient {
    fn new(manifest_json: String) -> Self {
        Self {
            manifest_json,
            manifest_digest: Digest::parse(&format!("sha256:{SHA_INDEX_PICK}")).expect("digest"),
            corrupt_digest: None,
            blob_fetches: AtomicUsize::new(0),
        }
    }
}

impl RegistryPullClient for FakeClient {
    fn authenticate(
        &self,
        _e: &RegistryEndpoint,
        _r: &Repository,
        _c: Option<&BasicCredentials>,
        _t: &[RegistryHost],
    ) -> Result<RegistryAuth, OciError> {
        Ok(RegistryAuth::None)
    }

    fn fetch_manifest(
        &self,
        _e: &RegistryEndpoint,
        _r: &Repository,
        _reference: &Reference,
        _a: &RegistryAuth,
        _p: &Platform,
    ) -> Result<PulledManifest, OciError> {
        Ok(PulledManifest {
            manifest: parse_image(&self.manifest_json),
            selected_digest: None,
            manifest_digest: self.manifest_digest.clone(),
            index_digest: None,
        })
    }

    fn fetch_blob(
        &self,
        _e: &RegistryEndpoint,
        _r: &Repository,
        descriptor: &Descriptor,
        _a: &RegistryAuth,
        dest: &Path,
    ) -> Result<(), OciError> {
        self.blob_fetches.fetch_add(1, Ordering::SeqCst);
        let hex = descriptor.digest.as_str().trim_start_matches("sha256:");
        let mut body = blob_body(hex).to_vec();
        if self.corrupt_digest == Some(hex) {
            body = b"WORLD".to_vec();
        }
        fs::write(dest, body).map_err(|_| OciError::new(OciErrorCode::Internal, "write"))
    }
}

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let p = std::env::temp_dir().join(format!(
            "fandhe-cri-it-{tag}-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&p).expect("mkdir");
        // umask 002 の環境でも祖先検証（group 書き込み不可）を通すため 0755 に固定する。
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).expect("chmod");
        }
        Self(p)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn config(dir: &TempDir) -> PullConfig {
    let mut c = PullConfig::new(dir.0.join("cache")).expect("config");
    c.platform = Platform::new("linux", "amd64", None);
    c
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

const TAG: &str = "docker.io/library/alpine:3.20";

fn image_id() -> String {
    format!("sha256:{SHA_CONFIG}")
}

fn repo_digest() -> String {
    format!("docker.io/library/alpine@sha256:{SHA_INDEX_PICK}")
}

fn spec(image: &str) -> Option<v1::ImageSpec> {
    Some(v1::ImageSpec {
        image: image.to_owned(),
        ..Default::default()
    })
}

fn build(
    client: Arc<FakeClient>,
    dir: &TempDir,
    with_puller: bool,
) -> (CriImageService, Arc<Collect>) {
    let recorder = Arc::new(Collect::default());
    let svc = CriImageService::with_store_and_recorder(
        Arc::new(InMemoryImageStore::new()),
        recorder.clone(),
    );
    let svc = if with_puller {
        let puller: Arc<dyn ImagePuller> = Arc::new(OciImagePuller::new(client, config(dir)));
        svc.with_puller(puller)
    } else {
        svc
    };
    (svc, recorder)
}

/// `crictl images [filter]` 相当。
async fn images(svc: &CriImageService, filter: Option<&str>) -> Vec<v1::Image> {
    let req = v1::ListImagesRequest {
        filter: filter.map(|f| v1::ImageFilter { image: spec(f) }),
    };
    ImageService::list_images(svc, Request::new(req))
        .await
        .expect("list_images")
        .into_inner()
        .images
}

/// `crictl inspecti <ref>` 相当。`verbose` は crictl の実送信形（true）を検証するため切り替える。
async fn inspecti(svc: &CriImageService, image: &str, verbose: bool) -> Option<v1::Image> {
    let req = v1::ImageStatusRequest {
        image: spec(image),
        verbose,
    };
    ImageService::image_status(svc, Request::new(req))
        .await
        .expect("image_status")
        .into_inner()
        .image
}

/// `crictl pull <ref>` 相当。
async fn pull(svc: &CriImageService, image: &str) -> Result<String, tonic::Status> {
    let req = v1::PullImageRequest {
        image: spec(image),
        ..Default::default()
    };
    ImageService::pull_image(svc, Request::new(req))
        .await
        .map(|r| r.into_inner().image_ref)
}

/// CRI-4・OCI-1・REPAIR-4・TASK-61.4: images -> pull -> images -> inspecti が順に成功し互いに整合する。
#[tokio::test]
async fn task_61_4_images_pull_inspecti_sequence() {
    let dir = TempDir::new("seq");
    let client = Arc::new(FakeClient::new(two_layer_manifest()));
    let (svc, recorder) = build(client, &dir, true);

    // 1. crictl images: 取得前は空。
    assert_eq!(images(&svc, None).await, Vec::<v1::Image>::new());

    // 2. crictl pull alpine:3.20: image_ref は config digest 由来のイメージ ID。
    assert_eq!(pull(&svc, "alpine:3.20").await.expect("pull"), image_id());

    // 3. crictl images: 取り込んだ 1 件が具体値で見える。
    let listed = images(&svc, None).await;
    assert_eq!(listed.len(), 1);
    let image = listed[0].clone();
    assert_eq!(image.id, image_id());
    assert_eq!(image.repo_tags, vec![TAG.to_owned()]);
    assert_eq!(image.repo_digests, vec![repo_digest()]);
    assert_eq!(image.size, 13);
    assert_eq!(
        image.spec.as_ref().map(|s| s.image.clone()),
        Some(image_id())
    );

    // 4. crictl inspecti: タグ・短縮名・ID・repo digest のどれでも一覧と同一のイメージが返る。
    for reference in [
        TAG.to_owned(),
        "alpine:3.20".to_owned(),
        image_id(),
        repo_digest(),
    ] {
        assert_eq!(
            inspecti(&svc, &reference, false).await,
            Some(image.clone()),
            "{reference}"
        );
    }

    // 5. crictl inspecti は verbose=true で送る。image は verbose=false と同一（info は TASK-183・OCI-7 で別途）。
    assert_eq!(inspecti(&svc, TAG, true).await, Some(image.clone()));

    // 6. 未取得の参照はエラーではなく image 無しの成功応答（api.proto の契約）。
    assert_eq!(inspecti(&svc, "busybox:1.36", false).await, None);

    // 7. フィルタ付き一覧: 一致は同じ 1 件、不一致は空。
    assert_eq!(images(&svc, Some(TAG)).await, vec![image.clone()]);
    assert_eq!(images(&svc, Some("alpine:3.20")).await, vec![image.clone()]);
    assert_eq!(
        images(&svc, Some("busybox:1.36")).await,
        Vec::<v1::Image>::new()
    );

    // 8. REPAIR-4: 全呼び出しが成功として計装され、記録は固定の操作名のみ。
    let samples = recorder.0.lock().expect("lock");
    let kinds: Vec<&str> = samples.iter().map(|s| s.kind().as_str()).collect();
    let mut expected = vec!["cri.list_images", "cri.pull_image", "cri.list_images"];
    expected.extend(["cri.image_status"; 6]);
    expected.extend(["cri.list_images"; 3]);
    assert_eq!(kinds, expected);
    for s in samples.iter() {
        assert_eq!(s.code(), Code::Ok);
        assert_eq!(s.outcome(), CriOpOutcome::Success);
    }
}

/// OCI-1・CRI-4: 同じ参照の再 pull は冪等で、一覧は 1 件のまま・タグ重複なし・blob は再取得しない。
#[tokio::test]
async fn task_61_4_repull_is_idempotent() {
    let dir = TempDir::new("repull");
    let client = Arc::new(FakeClient::new(two_layer_manifest()));
    let (svc, _rec) = build(client.clone(), &dir, true);
    let first = pull(&svc, "alpine:3.20").await.expect("pull 1");
    let fetched = client.blob_fetches.load(Ordering::SeqCst);
    assert_eq!(fetched, 3);
    let second = pull(&svc, "alpine:3.20").await.expect("pull 2");
    assert_eq!(first, second);
    assert_eq!(client.blob_fetches.load(Ordering::SeqCst), fetched);
    let listed = images(&svc, None).await;
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].repo_tags, vec![TAG.to_owned()]);
}

/// OCI-1: blob が破損した pull は DataLoss で失敗し、一覧・照会に部分的なイメージを残さない（fail-closed）。
#[tokio::test]
async fn task_61_4_failed_pull_leaves_listing_unchanged() {
    let dir = TempDir::new("fail");
    let mut fake = FakeClient::new(two_layer_manifest());
    fake.corrupt_digest = Some(SHA_LAYER2);
    let (svc, _rec) = build(Arc::new(fake), &dir, true);
    let err = pull(&svc, "alpine:3.20").await.expect_err("corrupt");
    assert_eq!(err.code(), Code::DataLoss);
    assert_eq!(images(&svc, None).await, Vec::<v1::Image>::new());
    assert_eq!(inspecti(&svc, TAG, false).await, None);
}

/// REPAIR-3: puller 未設定の PullImage は Unimplemented で、同じサービスの list・inspecti は動く。
#[tokio::test]
async fn task_61_4_unconfigured_puller_is_unimplemented() {
    let dir = TempDir::new("nopuller");
    let client = Arc::new(FakeClient::new(two_layer_manifest()));
    let (svc, _rec) = build(client, &dir, false);
    let err = pull(&svc, "alpine:3.20").await.expect_err("unimplemented");
    assert_eq!(err.code(), Code::Unimplemented);
    assert_eq!(images(&svc, None).await, Vec::<v1::Image>::new());
    assert_eq!(inspecti(&svc, TAG, false).await, None);
}
