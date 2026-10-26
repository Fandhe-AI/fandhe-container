//! `PullImage` の結果が `ImageStore` の在庫へ登録されることの結合試験
//! （#2539・OCI-1・OCI-7・CRI-3・REPAIR-5・REPAIR-12）。
//!
//! 実レジストリには接続せず `RegistryPullClient` の偽実装を使う。確かめる内容は次のとおり。
//! 1. 別プロセスで pull したイメージが、新しく開いた `ImageStore` の在庫一覧に出て、CLI の `create` が
//!    呼ぶ `register_container_ref` / `bind_container_ref` が成功する（本番で在庫が空にならない配線）
//! 2. 取得の失敗・diff_id の不一致の後に、在庫 0 件・`staging/` 空・pull リース 0 件が残る（孤児リースを作らない）
//! 3. 同じイメージの再 pull は既存 blob を再利用し（取得 0 回）、在庫は 1 件のまま
//!
//! 待機にはすべて期限を置く（REPAIR-5）。skip・ignore はしない。

// 非 Unix ではキャッシュのアクセス制御を検証できず fail-closed で拒否するため、本ファイルは Unix 限定。
#![cfg(unix)]

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use fandhe_container_cri::image_pull::{
    ImagePuller, OciImagePuller, PullConfig, PullRequest, PulledManifest, RegistryPullClient,
};
use fandhe_container_oci::auth::{BasicCredentials, RegistryAuth};
use fandhe_container_oci::error::{OciError, OciErrorCode};
use fandhe_container_oci::image_management::StagedBlobWriter;
use fandhe_container_oci::image_management::{
    ContainerRefId, ContainerRefRegistration, ImageStore,
};
use fandhe_container_oci::manifest::{
    Descriptor, ImageManifest, ParsedManifest, Platform, parse_manifest,
};
use fandhe_container_oci::reference::{Digest, Reference, RegistryHost, Repository};
use fandhe_container_oci::registry::RegistryEndpoint;

const CHILD_TEST: &str = "oci7_inventory_child_pulls";
const ROOT_ENV: &str = "FC_CRI_INVENTORY_TEST_ROOT";
const DEADLINE: Duration = Duration::from_secs(120);

// fixture の sha256 は `tests/image_pull.rs` と同じ（そちらの `oci1_fixture_digests_match_bodies` が実体と照合する）。
const SHA_CONFIG: &str = "2a5f645ff4c74446faf26364efce10b6d719685dacc7bc786f04d4dff63b683d";
const SHA_CONFIG_L1: &str = "e3c1bb45a59fe7d8f51b7e3120b4f5284471b4b94782539aa52481cbb7cc0516";
const SHA_LAYER1: &str = "fab1366a117f241f9419d25c8625e8f64bee0ba97a6964ac756297dbd94e61df";
const SHA_LAYER2: &str = "b606f40ff971b51d3b88c65f32533c8836ddae9a02ca24351697a8e9f5a2321e";
const SIZE_LAYER1: u64 = 2560;
const SIZE_LAYER2: u64 = 2048;
/// 偽の manifest 本文ハッシュ（試験では内容を持たない任意値）。
const SHA_MANIFEST: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const MEDIA_TAR: &str = "application/vnd.oci.image.layer.v1.tar";

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

fn tar_of(entries: &[Vec<u8>]) -> Vec<u8> {
    let mut out: Vec<u8> = entries.concat();
    out.extend_from_slice(&[0u8; 1024]);
    out
}

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
        SHA_LAYER1 => tar_of(&[
            tar_entry("etc/", 0o555, b"", true),
            tar_entry("etc/hello", 0o644, b"abc", false),
        ]),
        SHA_LAYER2 => tar_of(&[tar_entry("world", 0o644, b"world", false)]),
        _ => Vec::new(),
    }
}

fn manifest_json(config: &str, layers: &[(&str, u64)]) -> String {
    let layers: Vec<String> = layers
        .iter()
        .map(|(h, s)| format!(r#"{{"mediaType":"{MEDIA_TAR}","digest":"sha256:{h}","size":{s}}}"#))
        .collect();
    format!(
        r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:{config}","size":{}}},"layers":[{}]}}"#,
        blob_body(config).len(),
        layers.join(",")
    )
}

fn one_layer_manifest() -> String {
    manifest_json(SHA_CONFIG_L1, &[(SHA_LAYER1, SIZE_LAYER1)])
}

fn two_layer_manifest() -> String {
    manifest_json(
        SHA_CONFIG,
        &[(SHA_LAYER1, SIZE_LAYER1), (SHA_LAYER2, SIZE_LAYER2)],
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

/// 偽クライアント。`fail_hex` の blob の取得だけ失敗させる。
struct FakeClient {
    manifest_json: String,
    fail_hex: Option<&'static str>,
    blob_fetches: AtomicUsize,
}

impl FakeClient {
    fn new(manifest_json: String) -> Self {
        Self {
            manifest_json,
            fail_hex: None,
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
            manifest_digest: Digest::parse(&format!("sha256:{SHA_MANIFEST}")).expect("digest"),
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
        if self.fail_hex == Some(hex) {
            return Err(OciError::new(OciErrorCode::Unavailable, "injected failure"));
        }
        dest.write_all(&blob_body(hex))
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
            "fandhe-cri-inv-{tag}-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&p).expect("mkdir");
        {
            use std::os::unix::fs::PermissionsExt as _;
            // umask 002 の環境でも祖先検証（group 書き込み不可）を通すため 0755 に固定する。
            fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).expect("chmod");
        }
        Self(p)
    }

    fn cache(&self) -> PathBuf {
        self.0.join("cache")
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

fn config_for(cache: &Path) -> PullConfig {
    let mut c = PullConfig::new(cache).expect("config");
    c.platform = Platform::new("linux", "amd64", None);
    c
}

fn request(reference: &str) -> PullRequest {
    PullRequest {
        reference: reference.to_owned(),
        credentials: None,
    }
}

fn digest(hex: &str) -> Digest {
    Digest::parse(&format!("sha256:{hex}")).expect("digest")
}

/// `staging/` 直下の件数（無ければ 0）。
fn staging_entries(cache: &Path) -> usize {
    fs::read_dir(cache.join("staging")).map_or(0, Iterator::count)
}

/// 構成の全 blob の pull リースが 0 件であること。
fn assert_no_leases(store: &ImageStore, hexes: &[&str]) {
    let guard = store.lock().expect("lock");
    for hex in hexes {
        assert_eq!(
            guard.blob_references(&digest(hex)).leases,
            Vec::new(),
            "lease left for {hex}"
        );
    }
}

/// 子側: 単層イメージをタグ参照で pull する。環境変数が無ければ何もしない。
#[test]
fn oci7_inventory_child_pulls() {
    let Some(cache) = std::env::var_os(ROOT_ENV).map(PathBuf::from) else {
        return;
    };
    let puller = OciImagePuller::new(
        Arc::new(FakeClient::new(one_layer_manifest())),
        config_for(&cache),
    );
    let pulled = puller.pull(&request("alpine:3.20")).expect("child pull");
    assert_eq!(pulled.id, format!("sha256:{SHA_CONFIG_L1}"));
}

/// 別プロセスで pull したイメージが、新しく開いたストアの在庫一覧に出て、`create` の参照登録が成功する。
#[test]
fn oci7_pull_in_another_process_is_listed_and_registrable() {
    let dir = TempDir::new("crossproc");
    let cache = dir.cache();
    let mut child = Command::new(std::env::current_exe().expect("exe"))
        .args(["--exact", CHILD_TEST, "--test-threads=1"])
        .env(ROOT_ENV, &cache)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn child");
    let deadline = Instant::now() + DEADLINE;
    let status = loop {
        if let Some(status) = child.try_wait().expect("try_wait") {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("child pull did not finish in time");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    assert!(status.success(), "child pull failed: {status:?}");

    // 親は pull していない別のハンドルでストアを開く（永続化された在庫だけが手がかり）。
    let store = ImageStore::open(&cache).expect("open");
    let list = store
        .lock()
        .expect("lock")
        .list_images(&cache)
        .expect("list_images");
    assert_eq!(list.entries.len(), 1);
    let entry = &list.entries[0];
    assert_eq!(entry.digest, digest(SHA_MANIFEST));
    assert_eq!(
        entry.tag.as_ref().map(ToString::to_string).as_deref(),
        Some("registry-1.docker.io/library/alpine:3.20")
    );
    assert!(entry.missing_blobs.is_empty(), "{:?}", entry.missing_blobs);
    assert!(entry.size_bytes >= SIZE_LAYER1);

    // CLI の `create --image-root --image <digest>` が呼ぶ API。
    let id = ContainerRefId::new("c1").expect("id");
    assert_eq!(
        store
            .register_container_ref(&id, &digest(SHA_MANIFEST))
            .expect("register"),
        ContainerRefRegistration::Registered
    );
    store.bind_container_ref(&id).expect("bind");

    // 孤児リースを作らない: 成功後は staging が空で、リースも残らない。
    assert_eq!(staging_entries(&cache), 0);
    assert_no_leases(&store, &[SHA_CONFIG_L1, SHA_LAYER1]);
}

/// 取得の失敗・diff_id の不一致の後は、在庫 0 件・`staging/` 空・リース 0 件になる。
#[test]
fn oci7_failed_pull_leaves_no_inventory_staging_or_lease() {
    // 2 個目の layer の取得を失敗させる。
    let dir = TempDir::new("fetchfail");
    let cache = dir.cache();
    let mut client = FakeClient::new(two_layer_manifest());
    client.fail_hex = Some(SHA_LAYER2);
    let puller = OciImagePuller::new(Arc::new(client), config_for(&cache));
    let err = puller
        .pull(&request("alpine:3.20"))
        .expect_err("fetch failure");
    assert_eq!(err.code(), OciErrorCode::Unavailable);
    let store = ImageStore::open(&cache).expect("open");
    let list = store
        .lock()
        .expect("lock")
        .list_images(&cache)
        .expect("list");
    assert_eq!(list.entries.len(), 0);
    assert_eq!(staging_entries(&cache), 0);
    assert_no_leases(&store, &[SHA_CONFIG, SHA_LAYER1, SHA_LAYER2]);

    // layer の並びが config の diff_ids と食い違う（展開の突合で拒否される）。
    let dir = TempDir::new("diffid");
    let cache = dir.cache();
    let swapped = manifest_json(
        SHA_CONFIG,
        &[(SHA_LAYER2, SIZE_LAYER2), (SHA_LAYER1, SIZE_LAYER1)],
    );
    let puller = OciImagePuller::new(Arc::new(FakeClient::new(swapped)), config_for(&cache));
    let err = puller
        .pull(&request("alpine:3.20"))
        .expect_err("diff_id mismatch");
    assert_eq!(err.code(), OciErrorCode::DataLoss);
    let store = ImageStore::open(&cache).expect("open");
    let list = store
        .lock()
        .expect("lock")
        .list_images(&cache)
        .expect("list");
    assert_eq!(list.entries.len(), 0);
    assert_eq!(staging_entries(&cache), 0);
    assert_no_leases(&store, &[SHA_CONFIG, SHA_LAYER1, SHA_LAYER2]);
    // 展開物も公開されない。
    assert!(
        !cache
            .join("rootfs")
            .join("sha256")
            .join(SHA_CONFIG)
            .exists()
    );
}

/// 同じイメージの再 pull は既存 blob を再利用し（取得 0 回）、在庫は 1 件のまま、リースも残らない。
#[test]
fn oci7_second_pull_reuses_blobs_and_keeps_one_inventory_entry() {
    let dir = TempDir::new("reuse");
    let cache = dir.cache();
    let client = Arc::new(FakeClient::new(two_layer_manifest()));
    let puller = OciImagePuller::new(client.clone(), config_for(&cache));
    puller.pull(&request("alpine:3.20")).expect("first");
    assert_eq!(client.blob_fetches.load(Ordering::SeqCst), 3);
    puller.pull(&request("alpine:3.20")).expect("second");
    assert_eq!(client.blob_fetches.load(Ordering::SeqCst), 3, "reused");

    let store = ImageStore::open(&cache).expect("open");
    let list = store
        .lock()
        .expect("lock")
        .list_images(&cache)
        .expect("list");
    assert_eq!(list.entries.len(), 1);
    assert!(list.entries[0].missing_blobs.is_empty());
    assert_eq!(staging_entries(&cache), 0);
    assert_no_leases(&store, &[SHA_CONFIG, SHA_LAYER1, SHA_LAYER2]);
}
