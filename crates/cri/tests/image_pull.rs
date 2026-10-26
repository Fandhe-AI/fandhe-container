//! `PullImage` の結合試験（TASK-61.3・#446・CRI-4・OCI-1・OCI-3・ERR-3・REPAIR-4・REPAIR-5・REPAIR-12）。
//!
//! 実レジストリには接続せず、`RegistryPullClient` の偽実装で manifest / blob を返す。digest 検証・キャッシュ公開・
//! ステージング後始末・ストア登録は本物の経路を通す。実レジストリでの確認（`crictl pull`）は plugin-cri（TASK-114）以降。

// 非 Unix ではキャッシュのアクセス制御を検証できず fail-closed で拒否するため、本ファイルは Unix 限定
// （非 Unix の拒否は `src/image_pull.rs` の `non_unix_tests`）。
#![cfg(unix)]

use std::fs;
use std::io::Write as _;
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
use fandhe_container_oci::image_management::StagedBlobWriter;
use fandhe_container_oci::layer::extract::ExtractLimits;
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
/// 3 層目 `.wh.world` の tar。
const SHA_LAYER3: &str = "3012d30d565bfb7f4fdd6045a976359ad5bd1d1126241c1d517634eac4ab14ad";
/// 3 層（layer1〜3）の config。
const SHA_CONFIG_L3: &str = "d167b2300d21a713edee1616b9943ec615bcb809f339f63dad134383440a986f";
/// diff_ids が [layer1, layer1] の config（layer1 を 2 回使う manifest に合う。[layer1, layer2] の manifest には 2 層目が合わない）。
const SHA_CONFIG_DUP: &str = "6f3d697df322cbd63aedddb069f12d4b1fe248d50a6633153fb1908bd51eebfd";
/// JSON でない config 本体（"not json"）。
const SHA_CONFIG_JSON: &str = "7ccfa1fbf3940e6f0c0375d87c0f9235a50514e14cb427bdfaf5077987b26ccf";
const SIZE_LAYER3: u64 = 1536;

/// index から選ばれた manifest の digest（試験では内容を持たない任意値）。
const SHA_INDEX_PICK: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// image index 本文の digest（試験では内容を持たない任意値。選択 manifest の `SHA_INDEX_PICK` とは別）。
const SHA_INDEX_TOP: &str = "1111111111111111111111111111111111111111111111111111111111111111";

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

/// 3 層目: `world` の whiteout（`.wh.world`）。
fn layer3_body() -> Vec<u8> {
    tar_of(&[tar_entry(".wh.world", 0o644, b"", false)])
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
        SHA_CONFIG_L3 => config_body(&[SHA_LAYER1, SHA_LAYER2, SHA_LAYER3]),
        SHA_CONFIG_DUP => config_body(&[SHA_LAYER1, SHA_LAYER1]),
        SHA_CONFIG_JSON => b"not json".to_vec(),
        SHA_LAYER3 => layer3_body(),
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

/// 偽クライアント。private レジストリを模し、`require_credentials` なら資格情報なしを `PermissionDenied` にする。
struct FakeClient {
    manifest_json: String,
    require_credentials: bool,
    selected: Option<Digest>,
    /// 偽の「本文ハッシュ」。digest 参照では oci と同様に要求 digest と突合し、不一致は DataLoss にする。
    manifest_digest: Digest,
    /// index 経由を模す場合の index 本文の偽ハッシュ。digest 参照はこの値と突合する。
    index_digest: Option<Digest>,
    blob_delay: Duration,
    corrupt_digest: Option<&'static str>,
    blob_fetches: AtomicUsize,
    seen_credentials: Mutex<Vec<bool>>,
    delay: Duration,
    /// 先頭から数えてこの回数だけ blob 取得を PermissionDenied にする（token 失効の模擬）。
    deny_blob_fetches: AtomicUsize,
    auth_calls: AtomicUsize,
    /// 指定すると `(キャッシュの staging ディレクトリ, symlink の向き先)`。取得中（writer を開いた後・commit の前）に
    /// pull ディレクトリの `<hex>` へこの向き先への symlink を置く（fetcher の外からの差し替えの模擬。#2765）。
    staged_symlink_target: Option<(PathBuf, PathBuf)>,
    /// 指定すると、最初の取得だけ本文の一部を書いてから PermissionDenied を返す（部分書きの後の再認証・再試行の模擬）。
    partial_then_denied: AtomicUsize,
}

impl FakeClient {
    fn new(manifest_json: String) -> Self {
        Self {
            manifest_json,
            require_credentials: false,
            selected: None,
            manifest_digest: Digest::parse(&format!("sha256:{SHA_INDEX_PICK}")).expect("digest"),
            index_digest: None,
            blob_delay: Duration::ZERO,
            corrupt_digest: None,
            blob_fetches: AtomicUsize::new(0),
            seen_credentials: Mutex::new(Vec::new()),
            delay: Duration::ZERO,
            deny_blob_fetches: AtomicUsize::new(0),
            auth_calls: AtomicUsize::new(0),
            staged_symlink_target: None,
            partial_then_denied: AtomicUsize::new(0),
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
        self.auth_calls.fetch_add(1, Ordering::SeqCst);
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
        reference: &Reference,
        _a: &RegistryAuth,
        _p: &Platform,
    ) -> Result<PulledManifest, OciError> {
        if let Reference::Digest(want) = reference
            && *want != *self.index_digest.as_ref().unwrap_or(&self.manifest_digest)
        {
            return Err(OciError::new(
                OciErrorCode::DataLoss,
                "manifest digest mismatch",
            ));
        }
        Ok(PulledManifest {
            manifest: parse_image(&self.manifest_json),
            selected_digest: self.selected.clone(),
            manifest_digest: self.manifest_digest.clone(),
            index_digest: self.index_digest.clone(),
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
        if self.deny_blob_fetches.load(Ordering::SeqCst) > 0 {
            self.deny_blob_fetches.fetch_sub(1, Ordering::SeqCst);
            return Err(OciError::new(
                OciErrorCode::PermissionDenied,
                "registry token has expired",
            ));
        }
        std::thread::sleep(self.blob_delay);
        let hex = descriptor.digest.as_str().trim_start_matches("sha256:");
        let mut body = blob_body(hex);
        if self.corrupt_digest == Some(hex) {
            body = b"WORLD".to_vec();
        }
        let write = |dest: &mut StagedBlobWriter, b: &[u8]| {
            dest.write_all(b)
                .map_err(|_| OciError::new(OciErrorCode::Internal, "write"))
        };
        if self.partial_then_denied.load(Ordering::SeqCst) > 0 {
            self.partial_then_denied.fetch_sub(1, Ordering::SeqCst);
            write(dest, b"partial")?;
            return Err(OciError::new(
                OciErrorCode::PermissionDenied,
                "registry token has expired",
            ));
        }
        if let Some((staging, target)) = &self.staged_symlink_target {
            // writer は開いた後。pull ディレクトリ（staging 直下の唯一のエントリ）の `<hex>` へ symlink を置く。
            for entry in fs::read_dir(staging).expect("staging").flatten() {
                std::os::unix::fs::symlink(target, entry.path().join(hex))
                    .map_err(|_| OciError::new(OciErrorCode::Internal, "symlink"))?;
            }
        }
        write(dest, &body)
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
        // umask 002 の環境でも祖先検証（group 書き込み不可）を通すため 0755 に固定する。
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).expect("chmod");
        }
        Self(p)
    }
}

/// 展開済み rootfs の 0555 のディレクトリを含む木も消せるよう、権限を戻しながら再帰削除する（試験の後始末）。
fn force_remove(path: &Path) {
    use std::os::unix::fs::PermissionsExt as _;
    let Ok(meta) = fs::symlink_metadata(path) else {
        return;
    };
    if meta.file_type().is_dir() {
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o755));
        if let Ok(entries) = fs::read_dir(path) {
            for entry in entries.flatten() {
                force_remove(&entry.path());
            }
        }
        let _ = fs::remove_dir(path);
    } else {
        let _ = fs::remove_file(path);
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        force_remove(&self.0);
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

/// 公開済み blob の（権限ビット, ハードリンク数）。symlink は辿らず、通常ファイルでなければ失敗する。
fn blob_stat(dir: &TempDir, hex: &str) -> (u32, u64) {
    use std::os::unix::fs::MetadataExt as _;
    let meta = fs::symlink_metadata(blob_path(dir, hex)).expect("stat");
    assert!(meta.file_type().is_file(), "blob must be a regular file");
    (meta.mode() & 0o777, meta.nlink())
}

fn blob_inode(dir: &TempDir, hex: &str) -> u64 {
    use std::os::unix::fs::MetadataExt as _;
    fs::symlink_metadata(blob_path(dir, hex))
        .expect("stat")
        .ino()
}

fn staging_is_empty(dir: &TempDir) -> bool {
    match fs::read_dir(dir.0.join("cache").join("staging")) {
        Ok(mut it) => it.next().is_none(),
        Err(_) => true,
    }
}

fn two_layer_manifest() -> String {
    manifest_json(
        SHA_CONFIG,
        &[(SHA_LAYER1, SIZE_LAYER1), (SHA_LAYER2, SIZE_LAYER2)],
    )
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
            repo_digests: vec![format!("docker.io/library/alpine@sha256:{SHA_INDEX_PICK}")],
            size: SIZE_TOTAL,
        }
    );
    assert_eq!(
        fs::read(blob_path(&dir, SHA_CONFIG)).expect("cfg"),
        blob_body(SHA_CONFIG)
    );
    assert_eq!(
        fs::read(blob_path(&dir, SHA_LAYER1)).expect("l1"),
        layer1_body()
    );
    assert_eq!(
        fs::read(blob_path(&dir, SHA_LAYER2)).expect("l2"),
        layer2_body()
    );
    assert!(staging_is_empty(&dir));
    // 公開した blob は取得側の umask に依らず所有者専用（0600）・リンク数 1 の通常ファイル（OCI-1・SEC）。
    for hex in [SHA_CONFIG, SHA_LAYER1, SHA_LAYER2] {
        assert_eq!(blob_stat(&dir, hex), (0o600, 1), "{hex}");
    }
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

/// OCI-1: digest 指定の manifest 本文が要求 digest と食い違えば DATA_LOSS で、何も登録・公開しない。
#[test]
fn oci1_digest_pull_with_mismatched_manifest_is_rejected() {
    let dir = TempDir::new("mismatch");
    let puller = OciImagePuller::new(
        Arc::new(FakeClient::new(two_layer_manifest())),
        config(&dir),
    );
    let err = puller
        .pull(&req(&format!("alpine@sha256:{SHA_CONFIG}")))
        .expect_err("mismatch");
    assert_eq!(err.code(), OciErrorCode::DataLoss);
    assert!(!blob_path(&dir, SHA_CONFIG).exists());
}

/// REPAIR-5: 最後の blob の処理で期限を超えたら成功を返さない。
#[test]
fn repair5_deadline_is_checked_after_last_blob() {
    let dir = TempDir::new("lastblob");
    let mut fake = FakeClient::new(manifest_json(SHA_CONFIG_L1, &[(SHA_LAYER1, SIZE_LAYER1)]));
    fake.blob_delay = Duration::from_millis(60);
    let mut cfg = config(&dir);
    cfg.pull_deadline = Duration::from_millis(90);
    let puller = OciImagePuller::new(Arc::new(fake), cfg);
    let err = puller.pull(&req("alpine")).expect_err("deadline");
    assert_eq!(err.code(), OciErrorCode::Timeout);
}

/// CRI-4: 短縮名は PullImage が登録する正規名へ正規化される（ID 等の解釈不能な文字列は None）。
#[test]
fn cri4_canonical_reference_matches_pull_registration() {
    use fandhe_container_cri::image_pull::canonical_reference;
    assert_eq!(
        canonical_reference("alpine:3.20").as_deref(),
        Some("docker.io/library/alpine:3.20")
    );
    assert_eq!(
        canonical_reference("registry.example.com:5000/team/app:v1").as_deref(),
        Some("registry.example.com:5000/team/app:v1")
    );
    assert_eq!(canonical_reference("Bad Name!"), None);
}

/// OCI-1: 重複する layer は 1 回だけ取得する。キャッシュ命中は再取得せず、破損した既存 blob は再取得する。
#[test]
fn cri4_pull_dedup_and_cache_hit_and_repair() {
    let dir = TempDir::new("cache");
    let dup = manifest_json(
        SHA_CONFIG_DUP,
        &[(SHA_LAYER1, SIZE_LAYER1), (SHA_LAYER1, SIZE_LAYER1)],
    );
    let client = Arc::new(FakeClient::new(dup));
    let puller = OciImagePuller::new(client.clone(), config(&dir));
    puller.pull(&req("alpine")).expect("first");
    assert_eq!(client.blob_fetches.load(Ordering::SeqCst), 2);
    puller.pull(&req("alpine")).expect("second");
    assert_eq!(client.blob_fetches.load(Ordering::SeqCst), 2, "cache hit");

    fs::write(blob_path(&dir, SHA_LAYER1), b"xyz").expect("corrupt");
    puller.pull(&req("alpine")).expect("third");
    assert_eq!(client.blob_fetches.load(Ordering::SeqCst), 3, "refetch");
    assert_eq!(
        fs::read(blob_path(&dir, SHA_LAYER1)).expect("l1"),
        layer1_body()
    );
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
        assert_eq!(image.size, SIZE_TOTAL);
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
    cfg.max_image_bytes = SIZE_TOTAL - 1;
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
            SHA_CONFIG_L1,
            &[(SHA_LAYER1, SIZE_LAYER1)],
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
    // 別イメージなら manifest の本文ハッシュも別になる（同じ digest で別構成は在庫が拒否する。#2539・OCI-7）。
    let mut second_client = FakeClient::new(manifest_json(
        SHA_CONFIG,
        &[(SHA_LAYER1, SIZE_LAYER1), (SHA_LAYER2, SIZE_LAYER2)],
    ));
    second_client.manifest_digest =
        Digest::parse(&format!("sha256:{}", "b".repeat(64))).expect("digest");
    let second = OciImagePuller::new(Arc::new(second_client), cfg);
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
        .find(|i| i.id == format!("sha256:{SHA_CONFIG_L1}"))
        .expect("old");
    let new = list
        .iter()
        .find(|i| i.id == format!("sha256:{SHA_CONFIG}"))
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

/// CRI-4・OCI-1: index の digest で pull した参照は、選択 manifest の digest と併せて index digest でも
/// ImageStatus / ListImages から引ける。tag 経由でも index digest が repo_digests に載る。
#[tokio::test]
async fn cri4_index_digest_pull_is_resolvable_by_index_digest() {
    let index = format!("alpine@sha256:{SHA_INDEX_TOP}");
    let dir = TempDir::new("index");
    let mut fake = FakeClient::new(two_layer_manifest());
    fake.selected = Some(Digest::parse(&format!("sha256:{SHA_INDEX_PICK}")).expect("digest"));
    fake.index_digest = Some(Digest::parse(&format!("sha256:{SHA_INDEX_TOP}")).expect("digest"));
    let (svc, _store) = service_with(Arc::new(fake), config(&dir));
    ImageService::pull_image(&svc, Request::new(pull_req(&index)))
        .await
        .expect("pull by index digest");

    for reference in [&index, &format!("alpine@sha256:{SHA_INDEX_PICK}")] {
        let status = ImageService::image_status(&svc, Request::new(status_req(reference)))
            .await
            .expect("status")
            .into_inner();
        let image = status.image.expect("resolvable by digest");
        assert_eq!(image.id, format!("sha256:{SHA_CONFIG}"));
        assert_eq!(
            image.repo_digests,
            vec![
                format!("docker.io/library/alpine@sha256:{SHA_INDEX_PICK}"),
                format!("docker.io/library/alpine@sha256:{SHA_INDEX_TOP}"),
            ]
        );
        let list = ImageService::list_images(
            &svc,
            Request::new(v1::ListImagesRequest {
                filter: Some(v1::ImageFilter {
                    image: Some(v1::ImageSpec {
                        image: reference.clone(),
                        ..Default::default()
                    }),
                }),
            }),
        )
        .await
        .expect("list")
        .into_inner();
        assert_eq!(list.images.len(), 1, "filter by {reference}");
    }

    let dir2 = TempDir::new("index-tag");
    let mut fake = FakeClient::new(two_layer_manifest());
    fake.index_digest = Some(Digest::parse(&format!("sha256:{SHA_INDEX_TOP}")).expect("digest"));
    let pulled = OciImagePuller::new(Arc::new(fake), config(&dir2))
        .pull(&req("alpine:3.20"))
        .expect("pull by tag");
    assert_eq!(
        pulled.repo_digests,
        vec![
            format!("docker.io/library/alpine@sha256:{SHA_INDEX_PICK}"),
            format!("docker.io/library/alpine@sha256:{SHA_INDEX_TOP}"),
        ]
    );
}

/// OCI-1: descriptor の宣言サイズが実サイズと食い違う manifest は、キャッシュの有無によらず DATA_LOSS。
#[test]
fn oci1_descriptor_size_mismatch_is_rejected_regardless_of_cache() {
    let dir = TempDir::new("size-mismatch");
    // 実際の "abc" は 3 バイトだが 4 と宣言する。
    let bad = manifest_json(SHA_CONFIG, &[(SHA_LAYER1, SIZE_LAYER1 + 1)]);
    let good = manifest_json(SHA_CONFIG_L1, &[(SHA_LAYER1, SIZE_LAYER1)]);
    let cold = OciImagePuller::new(Arc::new(FakeClient::new(bad.clone())), config(&dir));
    assert_eq!(
        cold.pull(&req("alpine")).expect_err("cold").code(),
        OciErrorCode::DataLoss
    );
    // 正しい manifest で blob をキャッシュへ載せた後でも、宣言サイズ違いは拒否される。
    OciImagePuller::new(Arc::new(FakeClient::new(good)), config(&dir))
        .pull(&req("alpine"))
        .expect("seed cache");
    let warm = OciImagePuller::new(Arc::new(FakeClient::new(bad)), config(&dir));
    assert_eq!(
        warm.pull(&req("alpine")).expect_err("warm").code(),
        OciErrorCode::DataLoss
    );
}

/// OCI-1: 同一 digest の descriptor が異なるサイズを宣言する manifest は拒否する。
#[test]
fn oci1_duplicate_descriptors_with_different_sizes_are_rejected() {
    let dir = TempDir::new("dup-size");
    let bad = manifest_json(
        SHA_CONFIG_DUP,
        &[(SHA_LAYER1, SIZE_LAYER1), (SHA_LAYER1, SIZE_LAYER1 + 1)],
    );
    let puller = OciImagePuller::new(Arc::new(FakeClient::new(bad)), config(&dir));
    assert_eq!(
        puller.pull(&req("alpine")).expect_err("dup").code(),
        OciErrorCode::DataLoss
    );
}

/// OCI-3: blob 取得が PermissionDenied（token 失効）なら再認証して再試行し、pull は成功する。
#[test]
fn oci3_pull_reauthenticates_when_blob_fetch_is_denied() {
    let dir = TempDir::new("reauth");
    let mut fake = FakeClient::new(two_layer_manifest());
    fake.deny_blob_fetches = AtomicUsize::new(1);
    let client = Arc::new(fake);
    let puller = OciImagePuller::new(client.clone(), config(&dir));
    puller.pull(&req("alpine:3.20")).expect("pull");
    assert_eq!(client.auth_calls.load(Ordering::SeqCst), 2);
    assert!(staging_is_empty(&dir));
}

/// OCI-3・OCI-1・OCI-7（#2765）: 本文の一部を書いた後に PermissionDenied になっても、再試行は書き込み先を開き直す
/// ため部分書きは持ち越されず、公開された blob は完全な内容（`partial` が混ざらない）になる。
#[test]
fn oci3_retry_after_partial_write_publishes_complete_blob() {
    let dir = TempDir::new("reauth-partial");
    let mut fake = FakeClient::new(two_layer_manifest());
    fake.partial_then_denied = AtomicUsize::new(1);
    let client = Arc::new(fake);
    let puller = OciImagePuller::new(client.clone(), config(&dir));
    puller.pull(&req("alpine:3.20")).expect("pull");
    assert_eq!(client.auth_calls.load(Ordering::SeqCst), 2);
    assert_eq!(
        fs::read(blob_path(&dir, SHA_CONFIG)).expect("published config"),
        blob_body(SHA_CONFIG)
    );
    assert!(staging_is_empty(&dir));
}

/// OCI-3: 再認証の再試行は有限回（2 回）で、超えたら PermissionDenied を返す。
#[test]
fn oci3_reauthentication_is_bounded() {
    let dir = TempDir::new("reauth-bound");
    let mut fake = FakeClient::new(two_layer_manifest());
    fake.deny_blob_fetches = AtomicUsize::new(100);
    let client = Arc::new(fake);
    let puller = OciImagePuller::new(client.clone(), config(&dir));
    let err = puller.pull(&req("alpine:3.20")).expect_err("denied");
    assert_eq!(err.code(), OciErrorCode::PermissionDenied);
    assert_eq!(client.auth_calls.load(Ordering::SeqCst), 3);
    assert_eq!(client.blob_fetches.load(Ordering::SeqCst), 3);
    assert!(staging_is_empty(&dir));
}

/// SEC・OCI-1: キャッシュ内の既存ディレクトリが symlink なら外部へ公開せず拒否する。
#[cfg(unix)]
#[test]
fn sec_pull_rejects_symlinked_cache_directory() {
    let dir = TempDir::new("symlink");
    let outside = dir.0.join("outside");
    fs::create_dir_all(&outside).expect("mkdir");
    let blobs = dir.0.join("cache").join("blobs");
    fs::create_dir_all(&blobs).expect("mkdir");
    std::os::unix::fs::symlink(&outside, blobs.join("sha256")).expect("symlink");
    let client = Arc::new(FakeClient::new(two_layer_manifest()));
    let puller = OciImagePuller::new(client.clone(), config(&dir));
    let err = puller.pull(&req("alpine:3.20")).expect_err("rejected");
    assert_eq!(err.code(), OciErrorCode::FailedPrecondition);
    assert_eq!(client.blob_fetches.load(Ordering::SeqCst), 0);
    assert_eq!(fs::read_dir(&outside).expect("read").count(), 0);
}

/// SEC・OCI-1: 他ユーザー書き込み可能な既存ディレクトリは拒否する。
#[cfg(unix)]
#[test]
fn sec_pull_rejects_world_writable_cache_directory() {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = TempDir::new("worldw");
    let sha = dir.0.join("cache").join("blobs").join("sha256");
    fs::create_dir_all(&sha).expect("mkdir");
    fs::set_permissions(&sha, fs::Permissions::from_mode(0o777)).expect("chmod");
    let client = Arc::new(FakeClient::new(two_layer_manifest()));
    let puller = OciImagePuller::new(client.clone(), config(&dir));
    let err = puller.pull(&req("alpine:3.20")).expect_err("rejected");
    assert_eq!(err.code(), OciErrorCode::FailedPrecondition);
    assert_eq!(client.blob_fetches.load(Ordering::SeqCst), 0);
}

/// SEC・OCI-1: キャッシュの祖先が他ユーザー書き込み可能（sticky なし）なら拒否する。
#[test]
fn sec_pull_rejects_world_writable_cache_ancestor() {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = TempDir::new("ancestorw");
    let shared = dir.0.join("shared");
    fs::create_dir_all(&shared).expect("mkdir");
    fs::set_permissions(&shared, fs::Permissions::from_mode(0o777)).expect("chmod");
    let mut cfg = config(&dir);
    cfg.cache_dir = shared.join("cache");
    let client = Arc::new(FakeClient::new(two_layer_manifest()));
    let puller = OciImagePuller::new(client.clone(), cfg);
    let err = puller.pull(&req("alpine:3.20")).expect_err("rejected");
    assert_eq!(err.code(), OciErrorCode::FailedPrecondition);
    assert_eq!(client.blob_fetches.load(Ordering::SeqCst), 0);
    assert_eq!(fs::read_dir(&shared).expect("read").count(), 0);
}

/// SEC・OCI-1: キャッシュパスの祖先が利用者所有の symlink なら（解決先が安全でも）拒否する。
#[cfg(unix)]
#[test]
fn sec_pull_rejects_symlinked_cache_ancestor() {
    let dir = TempDir::new("ancestorlink");
    let real = dir.0.join("real");
    fs::create_dir_all(&real).expect("mkdir");
    let link = dir.0.join("link");
    std::os::unix::fs::symlink(&real, &link).expect("symlink");
    let mut cfg = config(&dir);
    cfg.cache_dir = link.join("cache");
    let client = Arc::new(FakeClient::new(two_layer_manifest()));
    let puller = OciImagePuller::new(client.clone(), cfg);
    let err = puller.pull(&req("alpine:3.20")).expect_err("rejected");
    assert_eq!(err.code(), OciErrorCode::FailedPrecondition);
    assert_eq!(client.blob_fetches.load(Ordering::SeqCst), 0);
    // 拒否前にリンク先（キャッシュ外）へディレクトリ・probe ファイルを作らない。
    assert_eq!(fs::read_dir(&real).expect("read").count(), 0);
}

/// SEC・OCI-1: 内容が正しくても group / other 書き込み可の既存 blob は再利用せず、取得し直した
/// 所有者専用のファイルで置き換える（他の blob は再利用する）。
#[test]
fn sec_pull_replaces_cached_blob_writable_by_others() {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = TempDir::new("blobmode");
    let client = Arc::new(FakeClient::new(two_layer_manifest()));
    let puller = OciImagePuller::new(client.clone(), config(&dir));
    puller.pull(&req("alpine:3.20")).expect("first");
    assert_eq!(client.blob_fetches.load(Ordering::SeqCst), 3);

    let path = blob_path(&dir, SHA_LAYER1);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).expect("chmod");
    let old_inode = blob_inode(&dir, SHA_LAYER1);
    puller.pull(&req("alpine:3.20")).expect("second");
    assert_eq!(
        client.blob_fetches.load(Ordering::SeqCst),
        4,
        "only the untrusted blob is refetched"
    );
    assert_eq!(blob_stat(&dir, SHA_LAYER1), (0o600, 1));
    assert_ne!(
        blob_inode(&dir, SHA_LAYER1),
        old_inode,
        "replaced, not reused"
    );
    assert_eq!(fs::read(&path).expect("l1"), layer1_body());
    assert!(staging_is_empty(&dir));

    puller.pull(&req("alpine:3.20")).expect("third");
    assert_eq!(client.blob_fetches.load(Ordering::SeqCst), 4, "cache hit");
}

/// SEC・OCI-1: キャッシュ外の名前からハードリンクされた既存 blob は再利用せず、別の inode のファイルで
/// 置き換える。置き換え後は、元の名前から書き換えてもキャッシュの内容は変わらない。
#[test]
fn sec_pull_replaces_hard_linked_cached_blob() {
    let dir = TempDir::new("bloblink");
    let client = Arc::new(FakeClient::new(two_layer_manifest()));
    let puller = OciImagePuller::new(client.clone(), config(&dir));
    puller.pull(&req("alpine:3.20")).expect("first");
    assert_eq!(client.blob_fetches.load(Ordering::SeqCst), 3);

    let path = blob_path(&dir, SHA_LAYER2);
    let alias = dir.0.join("alias");
    fs::hard_link(&path, &alias).expect("link");
    assert_eq!(blob_stat(&dir, SHA_LAYER2), (0o600, 2));
    let old_inode = blob_inode(&dir, SHA_LAYER2);

    puller.pull(&req("alpine:3.20")).expect("second");
    assert_eq!(client.blob_fetches.load(Ordering::SeqCst), 4);
    assert_eq!(blob_stat(&dir, SHA_LAYER2), (0o600, 1));
    assert_ne!(blob_inode(&dir, SHA_LAYER2), old_inode);

    // 元の inode は alias に残る。そこへ書き込んでもキャッシュの blob は変わらない。
    fs::write(&alias, b"tampered").expect("tamper through the old link");
    assert_eq!(fs::read(&path).expect("l2"), layer2_body());
    puller.pull(&req("alpine:3.20")).expect("third");
    assert_eq!(client.blob_fetches.load(Ordering::SeqCst), 4, "cache hit");
}

/// SEC・OCI-1: 既存 blob のパスが symlink なら（先が正しい内容でも）辿らず、エントリを通常ファイルで
/// 置き換える。symlink の先のファイルには書き込まない。
#[test]
fn sec_pull_replaces_symlinked_cached_blob_without_touching_the_target() {
    use std::os::unix::fs::MetadataExt as _;
    let dir = TempDir::new("blobsymlink");
    let client = Arc::new(FakeClient::new(two_layer_manifest()));
    let puller = OciImagePuller::new(client.clone(), config(&dir));
    puller.pull(&req("alpine:3.20")).expect("first");
    assert_eq!(client.blob_fetches.load(Ordering::SeqCst), 3);

    let path = blob_path(&dir, SHA_LAYER1);
    let outside = dir.0.join("outside-blob");
    fs::write(&outside, layer1_body()).expect("write");
    let outside_before = fs::metadata(&outside).expect("stat");
    fs::remove_file(&path).expect("remove");
    std::os::unix::fs::symlink(&outside, &path).expect("symlink");

    puller.pull(&req("alpine:3.20")).expect("second");
    assert_eq!(client.blob_fetches.load(Ordering::SeqCst), 4);
    assert_eq!(blob_stat(&dir, SHA_LAYER1), (0o600, 1));
    assert_eq!(fs::read(&path).expect("l1"), layer1_body());

    let outside_after = fs::metadata(&outside).expect("stat");
    assert_eq!(outside_after.ino(), outside_before.ino());
    assert_eq!(outside_after.mode(), outside_before.mode());
    assert_eq!(outside_after.nlink(), 1);
    assert_ne!(blob_inode(&dir, SHA_LAYER1), outside_after.ino());
    assert_eq!(fs::read(&outside).expect("outside"), layer1_body());
}

/// SEC・OCI-1・OCI-7（#2765）: 取得の途中で pull ディレクトリの `<hex>` に symlink が置かれても、確定（`linkat`）は
/// 宛先を置き換えず拒否し、symlink の先は無傷のまま何も公開しない（先が正しい内容でも辿らない）。取得は 1 回で、
/// 書き込み先は検査済み root の fd 起点の writer のため、symlink の差し替えでは外へ書けない。
#[test]
fn sec_pull_does_not_publish_symlinked_staged_blob() {
    let dir = TempDir::new("stagedsymlink");
    let outside = dir.0.join("outside-blob");
    fs::write(&outside, blob_body(SHA_CONFIG)).expect("write");
    let mut client = FakeClient::new(two_layer_manifest());
    client.staged_symlink_target = Some((dir.0.join("cache").join("staging"), outside.clone()));
    let client = Arc::new(client);
    let puller = OciImagePuller::new(client.clone(), config(&dir));
    let err = puller.pull(&req("alpine:3.20")).expect_err("rejected");
    assert_eq!(err.code(), OciErrorCode::FailedPrecondition);
    assert_eq!(err.message(), "image cache precondition failed");
    assert_eq!(client.blob_fetches.load(Ordering::SeqCst), 1);
    assert!(
        fs::symlink_metadata(blob_path(&dir, SHA_CONFIG)).is_err(),
        "nothing is published"
    );
    assert!(staging_is_empty(&dir));
    assert_eq!(fs::read(&outside).expect("outside"), blob_body(SHA_CONFIG));
}
// ---- レイヤー展開の配線（#2323・OCI-1・OCI-2・CRI-3・ERR-3） ----

/// 公開済みエントリ（`rootfs/` と `unpack-record` を持つ。1 回の rename で公開される）。
fn entry_path(dir: &TempDir, config_hex: &str) -> PathBuf {
    dir.0
        .join("cache")
        .join("rootfs")
        .join("sha256")
        .join(config_hex)
}

fn rootfs_path(dir: &TempDir, config_hex: &str) -> PathBuf {
    entry_path(dir, config_hex).join("rootfs")
}

fn rootfs_exists(dir: &TempDir, config_hex: &str) -> bool {
    fs::symlink_metadata(entry_path(dir, config_hex)).is_ok()
}

fn mode_of(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt as _;
    fs::symlink_metadata(path)
        .expect("stat")
        .permissions()
        .mode()
        & 0o777
}

/// 展開の上限を 1 エントリに絞る（layer1 は 2 エントリ: `etc/` と `etc/hello`）。
fn tight_extract_limits() -> ExtractLimits {
    ExtractLimits::new(1, 1 << 20, 1 << 30, 1 << 20)
}

/// REPAIR-12: fixture の sha256 定数と実体（本体のバイト列・サイズ）が一致している。
#[test]
fn oci1_fixture_digests_match_bodies() {
    let dir = TempDir::new("fixture-digest");
    let cases = [
        (SHA_CONFIG, 225),
        (SHA_CONFIG_L1, 151),
        (SHA_CONFIG_L3, 299),
        (SHA_CONFIG_DUP, 225),
        (SHA_CONFIG_JSON, 8),
        (SHA_LAYER1, SIZE_LAYER1),
        (SHA_LAYER2, SIZE_LAYER2),
        (SHA_LAYER3, SIZE_LAYER3),
    ];
    for (hex, size) in cases {
        let path = dir.0.join(format!("fixture-{hex}"));
        fs::write(&path, blob_body(hex)).expect("write");
        let digest = Digest::parse(&format!("sha256:{hex}")).expect("digest");
        let verified =
            fandhe_container_oci::layer::verify_blob_digest(&path, &digest, size).expect("digest");
        assert_eq!(verified.size, size, "{hex}");
    }
    assert_eq!(SIZE_CONFIG, 225);
    assert_eq!(SIZE_TOTAL, 4833);
}

/// OCI-1・CRI-3: 2 層の pull が成功すると、検証済み blob から rootfs が展開されて公開される。
#[test]
fn oci1_pull_extracts_layers_into_rootfs() {
    let dir = TempDir::new("extract");
    let client = Arc::new(FakeClient::new(two_layer_manifest()));
    let puller = OciImagePuller::new(client, config(&dir));
    puller.pull(&req("alpine:3.20")).expect("pull");
    let root = rootfs_path(&dir, SHA_CONFIG);
    assert_eq!(fs::read(root.join("etc/hello")).expect("hello"), b"abc");
    assert_eq!(fs::read(root.join("world")).expect("world"), b"world");
    assert_eq!(mode_of(&root.join("etc")), 0o555);
    assert_eq!(mode_of(&root), 0o700);
    assert_eq!(
        mode_of(&dir.0.join("cache").join("rootfs").join("sha256")),
        0o700
    );
    assert!(staging_is_empty(&dir));
    let id = Digest::parse(&format!("sha256:{SHA_CONFIG}")).expect("digest");
    assert_eq!(puller.unpacked_rootfs_dir(&id), root);
}

/// OCI-2: 上位レイヤーの whiteout が下位レイヤーの実体を消す（層の順序が下位から上位）。
#[test]
fn oci2_pull_applies_whiteout_across_layers() {
    let dir = TempDir::new("whiteout");
    let manifest = manifest_json(
        SHA_CONFIG_L3,
        &[
            (SHA_LAYER1, SIZE_LAYER1),
            (SHA_LAYER2, SIZE_LAYER2),
            (SHA_LAYER3, SIZE_LAYER3),
        ],
    );
    let puller = OciImagePuller::new(Arc::new(FakeClient::new(manifest)), config(&dir));
    puller.pull(&req("alpine:3.20")).expect("pull");
    let root = rootfs_path(&dir, SHA_CONFIG_L3);
    assert_eq!(fs::read(root.join("etc/hello")).expect("hello"), b"abc");
    assert!(fs::symlink_metadata(root.join("world")).is_err());
    assert!(fs::symlink_metadata(root.join(".wh.world")).is_err());
}

/// OCI-1: 公開済みの rootfs は 2 回目の pull で展開し直さない。
#[test]
fn oci1_pull_rootfs_is_idempotent() {
    let dir = TempDir::new("idem");
    let client = Arc::new(FakeClient::new(two_layer_manifest()));
    let puller = OciImagePuller::new(client.clone(), config(&dir));
    puller.pull(&req("alpine:3.20")).expect("first");
    let marker = rootfs_path(&dir, SHA_CONFIG).join("marker");
    fs::write(&marker, b"m").expect("marker");
    puller.pull(&req("alpine:3.20")).expect("second");
    assert_eq!(fs::read(&marker).expect("marker"), b"m");
    assert_eq!(client.blob_fetches.load(Ordering::SeqCst), 3);
    assert!(staging_is_empty(&dir));
}

/// OCI-1: 公開済みでも layer 件数が config と食い違う manifest は DataLoss で拒否する（キャッシュ命中で飛ばさない）。
#[test]
fn oci1_pull_cached_rootfs_still_checks_layer_count() {
    let dir = TempDir::new("cached-count");
    let first = OciImagePuller::new(
        Arc::new(FakeClient::new(two_layer_manifest())),
        config(&dir),
    );
    first.pull(&req("alpine:3.20")).expect("first");
    let extra = manifest_json(
        SHA_CONFIG,
        &[
            (SHA_LAYER1, SIZE_LAYER1),
            (SHA_LAYER2, SIZE_LAYER2),
            (SHA_LAYER1, SIZE_LAYER1),
        ],
    );
    let second = OciImagePuller::new(Arc::new(FakeClient::new(extra)), config(&dir));
    let err = second.pull(&req("alpine:3.20")).expect_err("extra layer");
    assert_eq!(err.code(), OciErrorCode::DataLoss);
    assert_eq!(err.message(), "image layer count does not match the config");
}

/// OCI-1・SEC-5: 展開設定が違う pull は公開済み rootfs を再利用せず、既存の展開物も消さずに拒否する。
#[test]
fn oci1_pull_does_not_reuse_rootfs_unpacked_with_other_settings() {
    use fandhe_container_oci::layer::extract::{IdRange, SpecialBitsPolicy};
    let dir = TempDir::new("settings");
    let first = OciImagePuller::new(
        Arc::new(FakeClient::new(two_layer_manifest())),
        config(&dir),
    );
    first.pull(&req("alpine:3.20")).expect("first");
    let marker = rootfs_path(&dir, SHA_CONFIG).join("marker");
    fs::write(&marker, b"m").expect("marker");
    let mut other = config(&dir);
    let range = IdRange {
        container_id: 0,
        host_id: 100_000,
        count: 65_536,
    };
    other.extract_options =
        other
            .extract_options
            .with_special_bits(SpecialBitsPolicy::PreserveIfOwnerMapped {
                uid: range,
                gid: range,
            });
    let second = OciImagePuller::new(Arc::new(FakeClient::new(two_layer_manifest())), other);
    let err = second
        .pull(&req("alpine:3.20"))
        .expect_err("other settings");
    assert_eq!(err.code(), OciErrorCode::FailedPrecondition);
    assert_eq!(
        err.message(),
        "image rootfs cache entry was unpacked with different settings"
    );
    assert_eq!(fs::read(&marker).expect("kept"), b"m");
    // 同じ設定なら再利用できる。
    first.pull(&req("alpine:3.20")).expect("same settings");
}

/// OCI-1: 展開物と記録は同じエントリに入り、記録だけ・展開物だけが単独で公開されることはない（旧 `.fingerprint` は作らない）。
#[test]
fn oci1_pull_publishes_rootfs_and_record_together() {
    let dir = TempDir::new("entry");
    let puller = OciImagePuller::new(
        Arc::new(FakeClient::new(two_layer_manifest())),
        config(&dir),
    );
    puller.pull(&req("alpine:3.20")).expect("pull");
    let entry = entry_path(&dir, SHA_CONFIG);
    let mut names: Vec<String> = fs::read_dir(&entry)
        .expect("entry")
        .map(|e| e.expect("e").file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert_eq!(names, ["rootfs", "unpack-record"]);
    let sha256_dir = entry.parent().expect("parent");
    assert_eq!(fs::read_dir(sha256_dir).expect("dir").count(), 1);
    let record = fs::read_to_string(entry.join("unpack-record")).expect("record");
    assert!(
        record.contains("ownership=keep\nspecial-bits=strip\n"),
        "{record}"
    );
    assert!(record.contains(&format!("config=sha256:{SHA_CONFIG}\n")));
    // 記録の無いエントリ（旧版・手作業の残骸）は再利用せず拒否する。
    fs::remove_file(entry.join("unpack-record")).expect("rm record");
    let err = puller.pull(&req("alpine:3.20")).expect_err("no record");
    assert_eq!(err.code(), OciErrorCode::FailedPrecondition);
    assert_eq!(
        err.message(),
        "image rootfs cache entry has no unpack record"
    );
}

/// OCI-1: 公開済みでも layer の読み取り方式（mediaType）が違う manifest は、今回の descriptor に従って検証し直す。
/// 非圧縮 tar の blob を tar+gzip と宣言した manifest は、キャッシュ命中で通らず DataLoss になる。展開物は消さない。
#[test]
fn oci1_pull_cached_rootfs_revalidates_other_layer_media_type() {
    let dir = TempDir::new("cached-media");
    let first = OciImagePuller::new(
        Arc::new(FakeClient::new(two_layer_manifest())),
        config(&dir),
    );
    first.pull(&req("alpine:3.20")).expect("first");
    let marker = rootfs_path(&dir, SHA_CONFIG).join("marker");
    fs::write(&marker, b"m").expect("marker");
    let other = manifest_json_media(
        SHA_CONFIG,
        &[(SHA_LAYER1, SIZE_LAYER1), (SHA_LAYER2, SIZE_LAYER2)],
        "application/vnd.oci.image.layer.v1.tar+gzip",
    );
    let second = OciImagePuller::new(Arc::new(FakeClient::new(other)), config(&dir));
    let err = second.pull(&req("alpine:3.20")).expect_err("other media");
    assert_eq!(err.code(), OciErrorCode::DataLoss);
    assert_eq!(fs::read(&marker).expect("kept"), b"m");
    assert!(staging_is_empty(&dir));
    // 元の descriptor ならそのまま再利用できる。
    first.pull(&req("alpine:3.20")).expect("same descriptors");
}

/// REPAIR-4: 展開の計装は注入した記録先へ届く（レイヤーごとに `ExtractLayer` の成功が記録される）。
#[test]
fn repair4_pull_reports_extraction_to_the_injected_recorder() {
    use fandhe_container_oci::instrument::{OciOpKind, OciOpOutcome, OciOpRecorder, OciOpSample};
    #[derive(Debug, Default)]
    struct Rec(Mutex<Vec<(OciOpKind, OciOpOutcome)>>);
    impl OciOpRecorder for Rec {
        fn record_oci_op(&self, sample: &OciOpSample) {
            self.0
                .lock()
                .expect("lock")
                .push((sample.kind(), sample.outcome()));
        }
    }
    let dir = TempDir::new("recorder");
    let rec = Arc::new(Rec::default());
    let puller = OciImagePuller::new(
        Arc::new(FakeClient::new(two_layer_manifest())),
        config(&dir),
    )
    .with_recorder(rec.clone());
    puller.pull(&req("alpine:3.20")).expect("pull");
    let got = rec.0.lock().expect("lock").clone();
    let extract: Vec<_> = got
        .iter()
        .filter(|(k, _)| *k == OciOpKind::ExtractLayer)
        .cloned()
        .collect();
    assert_eq!(
        extract,
        vec![(OciOpKind::ExtractLayer, OciOpOutcome::Success); 2]
    );
    // ImageStore の操作（開始・公開）も同じ記録先へ届く（#2539・REPAIR-4）。
    for kind in [OciOpKind::BeginPull, OciOpKind::PublishPull] {
        assert_eq!(
            got.iter().filter(|(k, _)| *k == kind).count(),
            1,
            "{kind:?}"
        );
        assert!(got.contains(&(kind, OciOpOutcome::Success)));
    }
}

/// OCI-1・SEC: 公開先に通常ファイルや symlink があれば、消さずに FailedPrecondition で拒否する。
#[test]
fn oci1_pull_rejects_untrusted_rootfs_cache_entry() {
    let dir = TempDir::new("untrusted-rootfs");
    let client = Arc::new(FakeClient::new(two_layer_manifest()));
    let puller = OciImagePuller::new(client, config(&dir));
    puller.pull(&req("alpine:3.20")).expect("first");
    let final_path = entry_path(&dir, SHA_CONFIG);
    force_remove(&final_path);
    fs::write(&final_path, b"planted").expect("plant file");
    let err = puller.pull(&req("alpine:3.20")).expect_err("file");
    assert_eq!(err.code(), OciErrorCode::FailedPrecondition);
    assert_eq!(err.message(), "image rootfs cache entry is not trusted");
    assert_eq!(fs::read(&final_path).expect("kept"), b"planted");

    fs::remove_file(&final_path).expect("rm");
    let target = dir.0.join("elsewhere");
    fs::create_dir_all(&target).expect("mkdir");
    std::os::unix::fs::symlink(&target, &final_path).expect("symlink");
    let err = puller.pull(&req("alpine:3.20")).expect_err("symlink");
    assert_eq!(err.code(), OciErrorCode::FailedPrecondition);
    assert!(
        fs::symlink_metadata(&final_path)
            .expect("kept")
            .file_type()
            .is_symlink()
    );
    assert_eq!(fs::read_dir(&target).expect("read").count(), 0);
    assert!(staging_is_empty(&dir));
}

/// OCI-1: 2 層目の diff_id が合わないと DataLoss で、1 層目の展開物も rootfs として残らない。
#[test]
fn oci1_diff_id_mismatch_on_second_layer_leaves_no_rootfs() {
    let dir = TempDir::new("diffid");
    let manifest = manifest_json(
        SHA_CONFIG_DUP,
        &[(SHA_LAYER1, SIZE_LAYER1), (SHA_LAYER2, SIZE_LAYER2)],
    );
    let puller = OciImagePuller::new(Arc::new(FakeClient::new(manifest)), config(&dir));
    let err = puller.pull(&req("alpine:3.20")).expect_err("mismatch");
    assert_eq!(err.code(), OciErrorCode::DataLoss);
    assert_eq!(err.message(), "image layer failed validation");
    assert!(!rootfs_exists(&dir, SHA_CONFIG_DUP));
    assert!(staging_is_empty(&dir));
}

/// OCI-1: config の diff_ids と manifest の layers の件数が違えば、展開の I/O の前に DataLoss。
#[test]
fn oci1_layer_count_mismatch_is_data_loss() {
    let dir = TempDir::new("count");
    let manifest = manifest_json(
        SHA_CONFIG_L1,
        &[(SHA_LAYER1, SIZE_LAYER1), (SHA_LAYER2, SIZE_LAYER2)],
    );
    let puller = OciImagePuller::new(Arc::new(FakeClient::new(manifest)), config(&dir));
    let err = puller.pull(&req("alpine:3.20")).expect_err("count");
    assert_eq!(err.code(), OciErrorCode::DataLoss);
    assert_eq!(err.message(), "image layer count does not match the config");
    assert!(!rootfs_exists(&dir, SHA_CONFIG_L1));
    assert!(staging_is_empty(&dir));
}

/// OCI-1: 未対応の layer mediaType（zstd）は Unimplemented で、rootfs もステージングも残らない。
#[test]
fn oci1_unsupported_layer_media_type_is_unimplemented() {
    let dir = TempDir::new("zstd");
    let manifest = manifest_json_media(
        SHA_CONFIG,
        &[(SHA_LAYER1, SIZE_LAYER1), (SHA_LAYER2, SIZE_LAYER2)],
        "application/vnd.oci.image.layer.v1.tar+zstd",
    );
    let puller = OciImagePuller::new(Arc::new(FakeClient::new(manifest)), config(&dir));
    let err = puller.pull(&req("alpine:3.20")).expect_err("zstd");
    assert_eq!(err.code(), OciErrorCode::Unimplemented);
    assert_eq!(err.message(), "unsupported image layer format");
    assert!(!rootfs_exists(&dir, SHA_CONFIG));
    assert!(staging_is_empty(&dir));
}

/// OCI-1: 展開の上限（エントリ数）を超えたら ResourceExhausted で、rootfs もステージングも残らない。
#[test]
fn oci1_extract_limit_exceeded_is_resource_exhausted() {
    let dir = TempDir::new("limit");
    let mut cfg = config(&dir);
    cfg.extract_limits = tight_extract_limits();
    let puller = OciImagePuller::new(Arc::new(FakeClient::new(two_layer_manifest())), cfg);
    let err = puller.pull(&req("alpine:3.20")).expect_err("limit");
    assert_eq!(err.code(), OciErrorCode::ResourceExhausted);
    assert_eq!(err.message(), "image layer exceeds the extraction limit");
    assert!(!rootfs_exists(&dir, SHA_CONFIG));
    assert!(staging_is_empty(&dir));
}

/// OCI-1: digest は合っているが JSON でない config は DataLoss で、rootfs は作られない。
#[test]
fn oci1_config_not_json_is_data_loss() {
    let dir = TempDir::new("cfg-json");
    let manifest = manifest_json(SHA_CONFIG_JSON, &[(SHA_LAYER1, SIZE_LAYER1)]);
    let puller = OciImagePuller::new(Arc::new(FakeClient::new(manifest)), config(&dir));
    let err = puller.pull(&req("alpine:3.20")).expect_err("json");
    assert_eq!(err.code(), OciErrorCode::DataLoss);
    assert_eq!(err.message(), "image config failed validation");
    assert!(!rootfs_exists(&dir, SHA_CONFIG_JSON));
    assert!(staging_is_empty(&dir));
}

/// OCI-1: 上限を超える config descriptor は通信前に ResourceExhausted（blob の取得は 0 回）。
#[test]
fn oci1_config_over_limit_is_rejected_before_fetch() {
    let dir = TempDir::new("cfg-limit");
    let mut cfg = config(&dir);
    cfg.max_config_bytes = SIZE_CONFIG - 1;
    let client = Arc::new(FakeClient::new(two_layer_manifest()));
    let puller = OciImagePuller::new(client.clone(), cfg);
    let err = puller.pull(&req("alpine:3.20")).expect_err("limit");
    assert_eq!(err.code(), OciErrorCode::ResourceExhausted);
    assert_eq!(client.blob_fetches.load(Ordering::SeqCst), 0);
}

/// ERR-3・CRI-3: 展開・config の失敗が gRPC の status コードと固定文言へ写る（参照文字列を含まない）。
#[tokio::test]
async fn err3_pull_image_maps_extraction_failures() {
    let zstd = manifest_json_media(
        SHA_CONFIG,
        &[(SHA_LAYER1, SIZE_LAYER1), (SHA_LAYER2, SIZE_LAYER2)],
        "application/vnd.oci.image.layer.v1.tar+zstd",
    );
    let diff = manifest_json(
        SHA_CONFIG_DUP,
        &[(SHA_LAYER1, SIZE_LAYER1), (SHA_LAYER2, SIZE_LAYER2)],
    );
    let bad_cfg = manifest_json(SHA_CONFIG_JSON, &[(SHA_LAYER1, SIZE_LAYER1)]);
    let cases = [
        (diff, false, Code::DataLoss, "image layer failed validation"),
        (
            zstd,
            false,
            Code::Unimplemented,
            "unsupported image layer format",
        ),
        (
            two_layer_manifest(),
            true,
            Code::ResourceExhausted,
            "image layer exceeds the extraction limit",
        ),
        (
            bad_cfg,
            false,
            Code::DataLoss,
            "image config failed validation",
        ),
    ];
    for (i, (manifest, tight, code, message)) in cases.into_iter().enumerate() {
        let dir = TempDir::new(&format!("err3-extract-{i}"));
        let mut cfg = config(&dir);
        if tight {
            cfg.extract_limits = tight_extract_limits();
        }
        let (svc, store) = service_with(Arc::new(FakeClient::new(manifest)), cfg);
        let err = ImageService::pull_image(
            &svc,
            Request::new(pull_req("secret.example.com/team/app:v1")),
        )
        .await
        .expect_err("pull must fail");
        assert_eq!(err.code(), code, "case {i}");
        assert_eq!(err.message(), message, "case {i}");
        assert!(!err.message().contains("secret.example.com"));
        assert!(store.list().expect("list").is_empty());
    }
}
/// 公開済みエントリを作って返す（以後の pull は記録の照合に入る）。
fn pulled_entry(tag: &str) -> (TempDir, Arc<OciImagePuller<Arc<FakeClient>>>) {
    let dir = TempDir::new(tag);
    let puller = Arc::new(OciImagePuller::new(
        Arc::new(FakeClient::new(two_layer_manifest())),
        config(&dir),
    ));
    puller.pull(&req("alpine:3.20")).expect("first pull");
    (dir, puller)
}

/// OCI-1・SEC-5・REPAIR-5・#2534: 展開記録の位置が FIFO に差し替わっていても、pull は open で止まらず期限内に拒否する
/// （種別の確認と同じハンドルを非ブロッキングで開く）。既存の展開物は消さない。
#[test]
fn oci1_repair5_pull_rejects_fifo_unpack_record_without_hanging() {
    let (dir, puller) = pulled_entry("fifo-record");
    let record = entry_path(&dir, SHA_CONFIG).join("unpack-record");
    fs::remove_file(&record).expect("rm record");
    let status = std::process::Command::new("mkfifo")
        .arg(&record)
        .status()
        .expect("mkfifo");
    assert!(status.success(), "mkfifo failed");
    let (tx, rx) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        let _ = tx.send(puller.pull(&req("alpine:3.20")));
    });
    let result = rx
        .recv_timeout(Duration::from_secs(10))
        .expect("pull must not hang on a FIFO record");
    let err = result.expect_err("fifo record");
    assert_eq!(err.code(), OciErrorCode::FailedPrecondition);
    assert_eq!(
        err.message(),
        "image rootfs cache entry has no unpack record"
    );
    worker.join().expect("join");
    assert!(rootfs_path(&dir, SHA_CONFIG).is_dir());
}

/// OCI-1・SEC-5・#2534: 上限を超えた記録は黙って切り詰めず `ResourceExhausted` で拒否し、既存の展開物を消さない
/// （切り詰めると別 layer 扱いに化けて再展開になる）。
#[test]
fn oci1_pull_rejects_oversized_unpack_record_and_keeps_rootfs() {
    use std::os::unix::fs::PermissionsExt as _;
    let (dir, puller) = pulled_entry("big-record");
    let record = entry_path(&dir, SHA_CONFIG).join("unpack-record");
    let mut body = fs::read(&record).expect("read record");
    body.resize(64 * 1024 + 1, b'x');
    fs::write(&record, &body).expect("rewrite");
    fs::set_permissions(&record, fs::Permissions::from_mode(0o600)).expect("chmod");
    let marker = rootfs_path(&dir, SHA_CONFIG).join("marker");
    fs::write(&marker, b"m").expect("marker");
    let err = puller
        .pull(&req("alpine:3.20"))
        .expect_err("oversized record");
    assert_eq!(err.code(), OciErrorCode::ResourceExhausted);
    assert_eq!(
        err.message(),
        "image rootfs unpack record exceeds the size limit"
    );
    assert_eq!(fs::read(&marker).expect("kept"), b"m");
}

/// OCI-1・REPAIR-5・#2534: 展開中に期限を過ぎたら、展開の直後の確認で `Timeout` にし、公開も記録の書き込みもしない
/// （展開中の打ち切りは行わず、上限で有界にして前後で確認する方針）。
#[test]
fn oci1_repair5_pull_deadline_exceeded_during_extraction_is_not_published() {
    use fandhe_container_oci::instrument::{OciOpKind, OciOpRecorder, OciOpSample};
    #[derive(Debug)]
    struct SlowExtract;
    impl OciOpRecorder for SlowExtract {
        fn record_oci_op(&self, sample: &OciOpSample) {
            if sample.kind() == OciOpKind::ExtractLayer {
                std::thread::sleep(Duration::from_millis(1300));
            }
        }
    }
    let dir = TempDir::new("deadline-extract");
    let mut cfg = config(&dir);
    cfg.pull_deadline = Duration::from_secs(1);
    let puller = OciImagePuller::new(Arc::new(FakeClient::new(two_layer_manifest())), cfg)
        .with_recorder(Arc::new(SlowExtract));
    let err = puller.pull(&req("alpine:3.20")).expect_err("deadline");
    assert_eq!(err.code(), OciErrorCode::Timeout);
    assert!(!rootfs_exists(&dir, SHA_CONFIG));
    assert!(staging_is_empty(&dir));
}
