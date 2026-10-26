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
use std::io::Write as _;
use std::path::PathBuf;
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
use fandhe_container_oci::image_management::StagedBlobWriter;
use fandhe_container_oci::manifest::{
    Descriptor, ImageManifest, ParsedManifest, Platform, parse_manifest,
};
use fandhe_container_oci::reference::{Digest, Reference, RegistryHost, Repository};
use fandhe_container_oci::registry::RegistryEndpoint;
use tonic::{Code, Request};

// fixture の sha256 は fixture のバイト列を書き出して `sha256sum` で求めた値で、`fixture_digests_match_bodies` が
// 実体と照合する（fixture を変えたときに気づけるようにする）。レイヤーは非圧縮 tar なので diff_id は blob の digest と同じ。
/// 2 層（layer1 + layer2）の config。
const SHA_CONFIG: &str = "2a5f645ff4c74446faf26364efce10b6d719685dacc7bc786f04d4dff63b683d";
/// 1 層（layer1 のみ）の config。
const SHA_CONFIG_L1: &str = "e3c1bb45a59fe7d8f51b7e3120b4f5284471b4b94782539aa52481cbb7cc0516";
/// `etc/`（0555）+ `etc/hello`（"abc"）の tar。
const SHA_LAYER1: &str = "fab1366a117f241f9419d25c8625e8f64bee0ba97a6964ac756297dbd94e61df";
/// `world`（"world"）の tar。
const SHA_LAYER2: &str = "b606f40ff971b51d3b88c65f32533c8836ddae9a02ca24351697a8e9f5a2321e";
const SIZE_CONFIG: u64 = 225;
const SIZE_LAYER1: u64 = 2560;
const SIZE_LAYER2: u64 = 2048;
/// config + 2 層の圧縮サイズ（非圧縮なので tar と同じ）の合計。
const SIZE_TOTAL: u64 = SIZE_CONFIG + SIZE_LAYER1 + SIZE_LAYER2;

/// 偽クライアントが返す manifest の digest（試験では内容を持たない任意値）。
const SHA_INDEX_PICK: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// ustar の 1 エントリ（ヘッダ 512 バイト + 512 バイト境界へ詰めたデータ）。mtime・uid・gid は 0 に固定する。
/// `dir` ならディレクトリ（typeflag `5`）。チェックサム欄は空白 8 個とみなして全バイトを足す。
fn tar_entry(name: &str, mode: u32, data: &[u8], dir: bool) -> Vec<u8> {
    let mut h = [0u8; 512];
    let mut put = |off: usize, bytes: &[u8]| h[off..off + bytes.len()].copy_from_slice(bytes);
    put(0, name.as_bytes());
    put(100, format!("{mode:07o}\0").as_bytes());
    put(108, b"0000000\0");
    put(116, b"0000000\0");
    put(124, format!("{:011o}\0", data.len()).as_bytes());
    put(136, b"00000000000\0");
    put(148, b"        ");
    put(156, if dir { b"5" } else { b"0" });
    put(257, b"ustar\0");
    put(263, b"00");
    let sum: u32 = h.iter().map(|b| u32::from(*b)).sum();
    h[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    let mut out = h.to_vec();
    out.extend_from_slice(data);
    out.resize(512 + data.len().div_ceil(512) * 512, 0);
    out
}

/// 非圧縮 tar（エントリ列 + 終端の 1024 バイトのゼロ）。非圧縮レイヤーでは diff_id が blob の digest と一致する。
fn tar_of(entries: &[Vec<u8>]) -> Vec<u8> {
    let mut out: Vec<u8> = entries.concat();
    out.extend_from_slice(&[0u8; 1024]);
    out
}

/// 1 層目: `etc/`（0555）と `etc/hello`（"abc"）。
fn layer1_body() -> Vec<u8> {
    tar_of(&[
        tar_entry("etc/", 0o555, b"", true),
        tar_entry("etc/hello", 0o644, b"abc", false),
    ])
}

/// 2 層目: `world`（"world"）。
fn layer2_body() -> Vec<u8> {
    tar_of(&[tar_entry("world", 0o644, b"world", false)])
}

/// image config（`rootfs.diff_ids` は下位から上位の順の sha256。バイト列を固定する）。
fn config_body(diff_ids: &[&str]) -> Vec<u8> {
    let ids: Vec<String> = diff_ids.iter().map(|h| format!("\"sha256:{h}\"")).collect();
    format!(
        r#"{{"architecture":"amd64","os":"linux","rootfs":{{"type":"layers","diff_ids":[{}]}}}}"#,
        ids.join(",")
    )
    .into_bytes()
}

fn blob_body(hex: &str) -> Vec<u8> {
    match hex {
        SHA_CONFIG => config_body(&[SHA_LAYER1, SHA_LAYER2]),
        SHA_CONFIG_L1 => config_body(&[SHA_LAYER1]),
        SHA_LAYER1 => layer1_body(),
        SHA_LAYER2 => layer2_body(),
        _ => Vec::new(),
    }
}

const MEDIA_TAR: &str = "application/vnd.oci.image.layer.v1.tar";

fn manifest_json(config: &str, layers: &[(&str, u64)]) -> String {
    manifest_json_media(config, layers, MEDIA_TAR)
}

fn manifest_json_media(config: &str, layers: &[(&str, u64)], media_type: &str) -> String {
    let layers: Vec<String> = layers
        .iter()
        .map(|(h, s)| format!(r#"{{"mediaType":"{media_type}","digest":"sha256:{h}","size":{s}}}"#))
        .collect();
    format!(
        r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:{config}","size":{}}},"layers":[{}]}}"#,
        blob_body(config).len(),
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
    manifest_json(
        SHA_CONFIG,
        &[(SHA_LAYER1, SIZE_LAYER1), (SHA_LAYER2, SIZE_LAYER2)],
    )
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
        dest: &mut StagedBlobWriter,
    ) -> Result<(), OciError> {
        self.blob_fetches.fetch_add(1, Ordering::SeqCst);
        let hex = descriptor.digest.as_str().trim_start_matches("sha256:");
        let mut body = blob_body(hex);
        if self.corrupt_digest == Some(hex) {
            body = b"WORLD".to_vec();
        }
        dest.write_all(&body)
            .map_err(|_| OciError::new(OciErrorCode::Internal, "write"))
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
    assert_eq!(image.size, SIZE_TOTAL);
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
