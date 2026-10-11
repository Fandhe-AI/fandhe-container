//! `PullImage` の結合試験（TASK-61.3・#446・CRI-4・OCI-1・OCI-3・ERR-3・REPAIR-4・REPAIR-5・REPAIR-12）。
//!
//! 実レジストリには接続せず、`RegistryPullClient` の偽実装で manifest / blob を返す。digest 検証・キャッシュ公開・
//! ステージング後始末・ストア登録は本物の経路を通す。実レジストリでの確認（`crictl pull`）は plugin-cri（TASK-114）以降。

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use fandhe_container_cri::image_pull::{
    ImagePuller, OciImagePuller, PullConfig, PullError, PullRequest, PulledImage, PulledManifest,
    RegistryPullClient,
};
use fandhe_container_cri::image_service::{CriImageService, ImageStore, InMemoryImageStore};
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
/// index から選ばれた manifest の digest（試験では内容を持たない任意値）。
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

/// 偽クライアント。private レジストリを模し、`require_credentials` なら資格情報なしを `PermissionDenied` にする。
struct FakeClient {
    manifest_json: String,
    require_credentials: bool,
    selected: Option<Digest>,
    corrupt_digest: Option<&'static str>,
    blob_fetches: AtomicUsize,
    seen_credentials: Mutex<Vec<bool>>,
    delay: Duration,
}

impl FakeClient {
    fn new(manifest_json: String) -> Self {
        Self {
            manifest_json,
            require_credentials: false,
            selected: None,
            corrupt_digest: None,
            blob_fetches: AtomicUsize::new(0),
            seen_credentials: Mutex::new(Vec::new()),
            delay: Duration::ZERO,
        }
    }
}

impl RegistryPullClient for FakeClient {
    fn authenticate(
        &self,
        _e: &RegistryEndpoint,
        _r: &Repository,
        credentials: Option<&BasicCredentials>,
        _t: &[RegistryHost],
    ) -> Result<RegistryAuth, OciError> {
        std::thread::sleep(self.delay);
        self.seen_credentials
            .lock()
            .expect("lock")
            .push(credentials.is_some());
        if self.require_credentials && credentials.is_none() {
            return Err(OciError::new(
                OciErrorCode::PermissionDenied,
                "private.example.com/secret/repo denied",
            ));
        }
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
            selected_digest: self.selected.clone(),
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
            "fandhe-cri-pull-{tag}-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&p).expect("mkdir");
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

fn blob_path(dir: &TempDir, hex: &str) -> PathBuf {
    dir.0.join("cache").join("blobs").join("sha256").join(hex)
}

fn staging_is_empty(dir: &TempDir) -> bool {
    match fs::read_dir(dir.0.join("cache").join("staging")) {
        Ok(mut it) => it.next().is_none(),
        Err(_) => true,
    }
}

fn two_layer_manifest() -> String {
    manifest_json(SHA_CONFIG, &[(SHA_LAYER1, 3), (SHA_LAYER2, 5)])
}

fn req(reference: &str) -> PullRequest {
    PullRequest {
        reference: reference.to_owned(),
        credentials: None,
    }
}

fn service_with(
    client: Arc<FakeClient>,
    cfg: PullConfig,
) -> (CriImageService, Arc<InMemoryImageStore>) {
    let store = Arc::new(InMemoryImageStore::new());
    let puller: Arc<dyn ImagePuller> = Arc::new(OciImagePuller::new(client, cfg));
    let svc = CriImageService::with_store(store.clone()).with_puller(puller);
    (svc, store)
}

fn pull_req(image: &str) -> v1::PullImageRequest {
    v1::PullImageRequest {
        image: Some(v1::ImageSpec {
            image: image.to_owned(),
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn status_req(image: &str) -> v1::ImageStatusRequest {
    v1::ImageStatusRequest {
        image: Some(v1::ImageSpec {
            image: image.to_owned(),
            ..Default::default()
        }),
        verbose: false,
    }
}

/// CRI-4・OCI-1: tag 指定で取り込むと ID は config digest、blob は公開され、ステージングは残らない。
#[test]
fn cri4_pull_tag_publishes_verified_blobs() {
    let dir = TempDir::new("tag");
    let client = Arc::new(FakeClient::new(two_layer_manifest()));
    let puller = OciImagePuller::new(client, config(&dir));
    let pulled = puller.pull(&req("alpine:3.20")).expect("pull");
    assert_eq!(
        pulled,
        PulledImage {
            id: format!("sha256:{SHA_CONFIG}"),
            repo_tags: vec!["docker.io/library/alpine:3.20".to_owned()],
            repo_digests: vec![],
            size: 13,
        }
    );
    assert_eq!(
        fs::read(blob_path(&dir, SHA_CONFIG)).expect("cfg"),
        b"hello"
    );
    assert_eq!(fs::read(blob_path(&dir, SHA_LAYER1)).expect("l1"), b"abc");
    assert_eq!(fs::read(blob_path(&dir, SHA_LAYER2)).expect("l2"), b"world");
    assert!(staging_is_empty(&dir));
}

/// OCI-1: index 経由なら選択 digest、digest 指定ならその digest が repo_digests に入る。
#[test]
fn cri4_pull_repo_digests() {
    let dir = TempDir::new("digest");
    let mut fake = FakeClient::new(two_layer_manifest());
    fake.selected = Some(Digest::parse(&format!("sha256:{SHA_INDEX_PICK}")).expect("digest"));
    let puller = OciImagePuller::new(Arc::new(fake), config(&dir));
    let pulled = puller
        .pull(&req("registry.example.com:5000/team/app:v1"))
        .expect("pull");
    assert_eq!(
        pulled.repo_tags,
        vec!["registry.example.com:5000/team/app:v1".to_owned()]
    );
    assert_eq!(
        pulled.repo_digests,
        vec![format!(
            "registry.example.com:5000/team/app@sha256:{SHA_INDEX_PICK}"
        )]
    );

    let dir2 = TempDir::new("digest2");
    let puller = OciImagePuller::new(
        Arc::new(FakeClient::new(two_layer_manifest())),
        config(&dir2),
    );
    let pulled = puller
        .pull(&req(&format!("alpine@sha256:{SHA_INDEX_PICK}")))
        .expect("pull");
    assert!(pulled.repo_tags.is_empty());
    assert_eq!(
        pulled.repo_digests,
        vec![format!("docker.io/library/alpine@sha256:{SHA_INDEX_PICK}")]
    );
}

/// OCI-1: 重複する layer は 1 回だけ取得する。キャッシュ命中は再取得せず、破損した既存 blob は再取得する。
#[test]
fn cri4_pull_dedup_and_cache_hit_and_repair() {
    let dir = TempDir::new("cache");
    let dup = manifest_json(SHA_CONFIG, &[(SHA_LAYER1, 3), (SHA_LAYER1, 3)]);
    let client = Arc::new(FakeClient::new(dup));
    let puller = OciImagePuller::new(client.clone(), config(&dir));
    puller.pull(&req("alpine")).expect("first");
    assert_eq!(client.blob_fetches.load(Ordering::SeqCst), 2);
    puller.pull(&req("alpine")).expect("second");
    assert_eq!(client.blob_fetches.load(Ordering::SeqCst), 2, "cache hit");

    fs::write(blob_path(&dir, SHA_LAYER1), b"xyz").expect("corrupt");
    puller.pull(&req("alpine")).expect("third");
    assert_eq!(client.blob_fetches.load(Ordering::SeqCst), 3, "refetch");
    assert_eq!(fs::read(blob_path(&dir, SHA_LAYER1)).expect("l1"), b"abc");
}

/// OCI-1: blob 本文が改ざんされていたら DATA_LOSS で、キャッシュにもストアにも残らない。
#[tokio::test]
async fn cri4_digest_mismatch_is_data_loss_and_leaves_nothing() {
    let dir = TempDir::new("tamper");
    let mut fake = FakeClient::new(two_layer_manifest());
    fake.corrupt_digest = Some(SHA_LAYER2);
    let (svc, store) = service_with(Arc::new(fake), config(&dir));
    let err = ImageService::pull_image(&svc, Request::new(pull_req("alpine")))
        .await
        .expect_err("must fail");
    assert_eq!(err.code(), Code::DataLoss);
    assert!(!blob_path(&dir, SHA_LAYER2).exists());
    assert!(staging_is_empty(&dir));
    assert!(store.is_empty());
}

/// OCI-3・CRI-4: private レジストリは資格情報（username+password / auth）があれば取得でき、
/// ImageStatus / ListImages で見える。資格情報なしは PERMISSION_DENIED。
#[tokio::test]
async fn cri4_private_registry_pull_with_credentials() {
    for auth in [
        v1::AuthConfig {
            username: "alice".into(),
            password: "s3cret".into(),
            ..Default::default()
        },
        v1::AuthConfig {
            auth: "YWxpY2U6czNjcmV0".into(), // alice:s3cret
            ..Default::default()
        },
    ] {
        let dir = TempDir::new("private");
        let mut fake = FakeClient::new(two_layer_manifest());
        fake.require_credentials = true;
        let client = Arc::new(fake);
        let (svc, _store) = service_with(client.clone(), config(&dir));

        let denied = ImageService::pull_image(
            &svc,
            Request::new(pull_req("private.example.com/team/app:1")),
        )
        .await
        .expect_err("anonymous must be denied");
        assert_eq!(denied.code(), Code::PermissionDenied);
        assert!(!denied.message().contains("private.example.com"));

        let mut request = pull_req("private.example.com/team/app:1");
        request.auth = Some(auth);
        let resp = ImageService::pull_image(&svc, Request::new(request))
            .await
            .expect("pull with credentials")
            .into_inner();
        assert_eq!(resp.image_ref, format!("sha256:{SHA_CONFIG}"));

        let status = ImageService::image_status(
            &svc,
            Request::new(status_req("private.example.com/team/app:1")),
        )
        .await
        .expect("status")
        .into_inner();
        let image = status.image.expect("image is visible");
        assert_eq!(image.id, resp.image_ref);
        assert_eq!(image.size, 13);
        let list = ImageService::list_images(&svc, Request::new(Default::default()))
            .await
            .expect("list")
            .into_inner();
        assert_eq!(list.images.len(), 1);
        assert_eq!(
            client.seen_credentials.lock().expect("lock").clone(),
            vec![false, true]
        );
    }
}

/// OCI-3: 資格情報はデバッグ出力とエラー文言に出ない。
#[test]
fn oci3_credentials_are_not_leaked() {
    let request = PullRequest {
        reference: "alpine".into(),
        credentials: Some(BasicCredentials::new("alice", "s3cret-pass").expect("creds")),
    };
    let debug = format!("{request:?}");
    assert!(!debug.contains("s3cret-pass"));
    assert!(!debug.contains("alice"));
    let err = PullError::new(OciErrorCode::PermissionDenied, "registry access denied");
    assert!(!err.to_string().contains("s3cret-pass"));
}

/// REPAIR-5・OCI-1: descriptor 合計が上限超なら通信前に RESOURCE_EXHAUSTED（blob は取得しない）。
#[test]
fn cri4_size_limit_is_checked_before_fetching() {
    let dir = TempDir::new("limit");
    let client = Arc::new(FakeClient::new(two_layer_manifest()));
    let mut cfg = config(&dir);
    cfg.max_image_bytes = 12; // 合計 13
    let puller = OciImagePuller::new(client.clone(), cfg);
    let err = puller.pull(&req("alpine")).expect_err("too large");
    assert_eq!(err.code(), OciErrorCode::ResourceExhausted);
    assert_eq!(client.blob_fetches.load(Ordering::SeqCst), 0);

    let mut cfg = config(&dir);
    cfg.max_config_bytes = 4; // config は 5
    let puller = OciImagePuller::new(client.clone(), cfg);
    let err = puller.pull(&req("alpine")).expect_err("config too large");
    assert_eq!(err.code(), OciErrorCode::ResourceExhausted);
    assert_eq!(client.blob_fetches.load(Ordering::SeqCst), 0);
}

/// REPAIR-5: 全体期限を過ぎたら TIMEOUT（gRPC では DEADLINE_EXCEEDED）。
#[test]
fn repair5_pull_deadline_is_enforced() {
    let dir = TempDir::new("deadline");
    let mut fake = FakeClient::new(two_layer_manifest());
    fake.delay = Duration::from_millis(30);
    let mut cfg = config(&dir);
    cfg.pull_deadline = Duration::from_millis(5);
    let puller = OciImagePuller::new(Arc::new(fake), cfg);
    let err = puller.pull(&req("alpine")).expect_err("deadline");
    assert_eq!(err.code(), OciErrorCode::Timeout);
}

/// CRI-4: 同じタグで別イメージを pull するとタグは新しいイメージへ移り、同一イメージの別タグは統合される。
#[tokio::test]
async fn cri4_tag_moves_and_tags_merge() {
    let dir = TempDir::new("tags");
    let cfg = config(&dir);
    let store = Arc::new(InMemoryImageStore::new());

    let first = OciImagePuller::new(
        Arc::new(FakeClient::new(manifest_json(
            SHA_CONFIG,
            &[(SHA_LAYER1, 3)],
        ))),
        cfg.clone(),
    );
    let svc = CriImageService::with_store(store.clone()).with_puller(Arc::new(first));
    ImageService::pull_image(&svc, Request::new(pull_req("alpine:1")))
        .await
        .expect("pull 1");
    ImageService::pull_image(&svc, Request::new(pull_req("alpine:2")))
        .await
        .expect("pull 2");
    assert_eq!(store.list().expect("list").len(), 1);
    let image = ImageService::list_images(&svc, Request::new(Default::default()))
        .await
        .expect("list")
        .into_inner()
        .images
        .remove(0);
    assert_eq!(
        image.repo_tags,
        vec![
            "docker.io/library/alpine:1".to_owned(),
            "docker.io/library/alpine:2".to_owned()
        ]
    );

    // 別イメージ（config が違う）が alpine:1 を奪う。
    let second = OciImagePuller::new(
        Arc::new(FakeClient::new(manifest_json(
            SHA_LAYER2,
            &[(SHA_LAYER1, 3)],
        ))),
        cfg,
    );
    let svc2 = CriImageService::with_store(store.clone()).with_puller(Arc::new(second));
    ImageService::pull_image(&svc2, Request::new(pull_req("alpine:1")))
        .await
        .expect("pull 3");
    let list = ImageService::list_images(&svc2, Request::new(Default::default()))
        .await
        .expect("list")
        .into_inner()
        .images;
    assert_eq!(list.len(), 2);
    let old = list
        .iter()
        .find(|i| i.id == format!("sha256:{SHA_CONFIG}"))
        .expect("old");
    let new = list
        .iter()
        .find(|i| i.id == format!("sha256:{SHA_LAYER2}"))
        .expect("new");
    assert_eq!(old.repo_tags, vec!["docker.io/library/alpine:2".to_owned()]);
    assert_eq!(new.repo_tags, vec!["docker.io/library/alpine:1".to_owned()]);
}

/// CRI-4・ERR-3: 入力検証（空・過大・不正な参照）はネットワークに触れず INVALID_ARGUMENT。
/// トークン系の資格情報は UNIMPLEMENTED。puller 未設定は従来どおり UNIMPLEMENTED。
#[tokio::test]
async fn cri4_input_validation_and_unconfigured() {
    let dir = TempDir::new("input");
    let client = Arc::new(FakeClient::new(two_layer_manifest()));
    let (svc, _store) = service_with(client.clone(), config(&dir));
    let too_long = "a".repeat(2000);
    for image in ["", too_long.as_str()] {
        let err = ImageService::pull_image(&svc, Request::new(pull_req(image)))
            .await
            .expect_err("invalid");
        assert_eq!(err.code(), Code::InvalidArgument);
    }
    let err = ImageService::pull_image(&svc, Request::new(Default::default()))
        .await
        .expect_err("no image");
    assert_eq!(err.code(), Code::InvalidArgument);
    // 構文不正（空白を含む）は参照の検証で弾かれ、認証通信まで進まない。
    let err = ImageService::pull_image(&svc, Request::new(pull_req("has space")))
        .await
        .expect_err("syntax");
    assert_eq!(err.code(), Code::InvalidArgument);
    assert!(client.seen_credentials.lock().expect("lock").is_empty());

    let mut with_token = pull_req("alpine");
    with_token.auth = Some(v1::AuthConfig {
        identity_token: "tok".into(),
        ..Default::default()
    });
    let err = ImageService::pull_image(&svc, Request::new(with_token))
        .await
        .expect_err("token unsupported");
    assert_eq!(err.code(), Code::Unimplemented);

    let bare = CriImageService::new();
    let err = ImageService::pull_image(&bare, Request::new(pull_req("alpine")))
        .await
        .expect_err("unconfigured");
    assert_eq!(err.code(), Code::Unimplemented);
}

/// 実行を保持する puller（同時数上限の検証用）。
struct Blocking {
    entered: Mutex<std::sync::mpsc::Sender<()>>,
    release: Mutex<std::sync::mpsc::Receiver<()>>,
}

impl ImagePuller for Blocking {
    fn pull(&self, _r: &PullRequest) -> Result<PulledImage, PullError> {
        let _ = self.entered.lock().expect("lock").send(());
        let _ = self
            .release
            .lock()
            .expect("lock")
            .recv_timeout(Duration::from_secs(10));
        Ok(PulledImage {
            id: "sha256:aa".into(),
            repo_tags: vec![],
            repo_digests: vec![],
            size: 1,
        })
    }
}

/// REPAIR-5: 同時 pull 数が上限を超えたら RESOURCE_EXHAUSTED。完了後はスロットが解放される。
#[tokio::test]
async fn repair5_concurrent_pull_limit_releases_slot() {
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let puller = Arc::new(Blocking {
        entered: Mutex::new(entered_tx),
        release: Mutex::new(release_rx),
    });
    let svc = Arc::new(
        CriImageService::new()
            .with_puller(puller)
            .with_max_concurrent_pulls(1),
    );
    let first = {
        let svc = svc.clone();
        tokio::spawn(async move {
            ImageService::pull_image(svc.as_ref(), Request::new(pull_req("alpine"))).await
        })
    };
    tokio::task::spawn_blocking(move || entered_rx.recv_timeout(Duration::from_secs(10)))
        .await
        .expect("join")
        .expect("first pull started");
    let err = ImageService::pull_image(svc.as_ref(), Request::new(pull_req("busybox")))
        .await
        .expect_err("limit");
    assert_eq!(err.code(), Code::ResourceExhausted);
    release_tx.send(()).expect("release");
    first.await.expect("join").expect("first pull ok");
    // 解放後は再び取得できる。
    release_tx.send(()).expect("release again");
    ImageService::pull_image(svc.as_ref(), Request::new(pull_req("busybox")))
        .await
        .expect("slot released");
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

/// REPAIR-4: PullImage の成功・失敗が cri.pull_image として記録される。
#[tokio::test]
async fn repair4_pull_is_recorded() {
    let dir = TempDir::new("record");
    let recorder = Arc::new(Collect::default());
    let puller: Arc<dyn ImagePuller> = Arc::new(OciImagePuller::new(
        Arc::new(FakeClient::new(two_layer_manifest())),
        config(&dir),
    ));
    let svc = CriImageService::with_store_and_recorder(
        Arc::new(InMemoryImageStore::new()),
        recorder.clone(),
    )
    .with_puller(puller);
    ImageService::pull_image(&svc, Request::new(pull_req("alpine")))
        .await
        .expect("ok");
    ImageService::pull_image(&svc, Request::new(pull_req("")))
        .await
        .expect_err("invalid");
    let samples = recorder.0.lock().expect("lock");
    assert_eq!(samples.len(), 2);
    assert_eq!(samples[0].kind().as_str(), "cri.pull_image");
    assert_eq!(samples[0].outcome(), CriOpOutcome::Success);
    assert_eq!(samples[1].outcome(), CriOpOutcome::Failure);
}
