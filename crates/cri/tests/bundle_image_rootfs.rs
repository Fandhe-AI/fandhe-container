//! 本番の `RootfsSource`（`ImageRootfsSource`）と `SpecBundleProvider` の結合試験
//! （CRI-2・OCI-1・OCI-4・OCI-7・SEC-1・REPAIR-5・REPAIR-12。#2433）。
//!
//! 偽のレジストリクライアントで実際に `OciImagePuller` を通してキャッシュを作り、その検証済みキャッシュから
//! bundle を作る。キャッシュの信頼境界（改ざん・設定の食い違い・権限）は本物のファイルで再現する。
//! root 権限は要らない。unix 限定（非 unix はキャッシュの検証手段が無く fail-closed で拒否する）。

#![cfg(unix)]

use std::collections::HashMap;
use std::fs;
use std::io::Write as _;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use fandhe_container_core::oci_runtime;
use fandhe_container_cri::adapter::{BundleProvider, BundleRequest};
use fandhe_container_cri::bundle::{ImageExtractConfig, ImageRootfsSource, SpecBundleProvider};
use fandhe_container_cri::error::{CriError, CriErrorCode};
use fandhe_container_cri::image_pull::{
    ImagePuller, OciImagePuller, PullConfig, PullRequest, PulledManifest, RegistryPullClient,
};
use fandhe_container_cri::image_service::{ImageRecord, ImageStore, InMemoryImageStore};
use fandhe_container_cri::runtime::v1::{
    ContainerConfig, ContainerMetadata, ImageSpec, Int64Value, LinuxContainerConfig,
    LinuxContainerSecurityContext, PodSandboxConfig,
};
use fandhe_container_oci::auth::{BasicCredentials, RegistryAuth};
use fandhe_container_oci::error::{OciError, OciErrorCode};
use fandhe_container_oci::image_management::StagedBlobWriter;
use fandhe_container_oci::instrument::{OciOpKind, OciOpOutcome, OciOpRecorder, OciOpSample};
use fandhe_container_oci::layer::extract::{ExtractLimits, ExtractOptions, SpecialBitsPolicy};
use fandhe_container_oci::manifest::{
    Descriptor, ImageManifest, ParsedManifest, Platform, parse_manifest,
};
use fandhe_container_oci::reference::{Digest, Reference, RegistryHost, Repository};
use fandhe_container_oci::registry::RegistryEndpoint;

// ---- fixture（sha256 は純 Rust の最小実装で求め、oci の検証関数と照合する）----

fn sha256_hex(data: &[u8]) -> String {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&((data.len() as u64) * 8).to_be_bytes());
    for chunk in msg.chunks(64) {
        let mut w = [0u32; 64];
        for (i, b) in chunk.chunks(4).enumerate() {
            w[i] = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let mut v = h;
        for i in 0..64 {
            let s1 = v[4].rotate_right(6) ^ v[4].rotate_right(11) ^ v[4].rotate_right(25);
            let ch = (v[4] & v[5]) ^ (!v[4] & v[6]);
            let t1 = v[7]
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = v[0].rotate_right(2) ^ v[0].rotate_right(13) ^ v[0].rotate_right(22);
            let maj = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
            let t2 = s0.wrapping_add(maj);
            v = [
                t1.wrapping_add(t2),
                v[0],
                v[1],
                v[2],
                v[3].wrapping_add(t1),
                v[4],
                v[5],
                v[6],
            ];
        }
        for (a, b) in h.iter_mut().zip(v) {
            *a = a.wrapping_add(b);
        }
    }
    h.iter().map(|x| format!("{x:08x}")).collect()
}

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

/// symlink エントリ（typeflag `2`）。
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn tar_symlink(name: &str, target: &str) -> Vec<u8> {
    let mut e = tar_entry(name, 0o777, b"", false);
    e[156] = b'2';
    e[157..157 + target.len()].copy_from_slice(target.as_bytes());
    let sum: u32 = e[..512]
        .iter()
        .enumerate()
        .map(|(i, b)| {
            if (148..156).contains(&i) {
                32
            } else {
                u32::from(*b)
            }
        })
        .sum();
    e[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    e
}

fn tar_of(entries: &[Vec<u8>]) -> Vec<u8> {
    let mut out: Vec<u8> = entries.concat();
    out.extend_from_slice(&[0u8; 1024]);
    out
}

/// 下位層: `etc/`（0555）・`etc/hello`（"abc"）・`bin/`・`bin/app`（0755、"app"）。
fn layer1() -> Vec<u8> {
    tar_of(&[
        tar_entry("etc/", 0o555, b"", true),
        tar_entry("etc/hello", 0o644, b"abc", false),
        tar_entry("bin/", 0o755, b"", true),
        tar_entry("bin/app", 0o755, b"app", false),
    ])
}

/// 上位層: `world`（"world"）。
fn layer2() -> Vec<u8> {
    tar_of(&[tar_entry("world", 0o644, b"world", false)])
}

const MEDIA_TAR: &str = "application/vnd.oci.image.layer.v1.tar";

/// 偽レジストリ: blob を digest から返す。manifest は固定。
struct FakeClient {
    manifest: ImageManifest,
    blobs: HashMap<String, Vec<u8>>,
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
            manifest: self.manifest.clone(),
            selected_digest: None,
            manifest_digest: Digest::parse(&format!("sha256:{}", "1".repeat(64))).unwrap(),
            index_digest: None,
        })
    }

    fn fetch_blob(
        &self,
        _e: &RegistryEndpoint,
        _r: &Repository,
        d: &Descriptor,
        _a: &RegistryAuth,
        dest: &mut StagedBlobWriter,
    ) -> Result<(), OciError> {
        let hex = d.digest.as_str().trim_start_matches("sha256:");
        let body = self
            .blobs
            .get(hex)
            .ok_or_else(|| OciError::new(OciErrorCode::NotFound, "blob"))?;
        dest.write_all(body)
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
            "fandhe-cri-imgroot-{tag}-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&p).expect("mkdir");
        fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).expect("chmod");
        // `SpecBundleProvider` は symlink を含む bundle root を拒否する（SEC-1）。macOS の一時ディレクトリは
        // `/var` → `/private/var` の symlink 配下にあるため、正規パスに揃えてから渡す（#2537 と同じ扱い）。
        Self(fs::canonicalize(&p).expect("canonicalize"))
    }
}

/// 0555 等を含む木も消せるよう、権限を戻しながら再帰削除する（試験の後始末）。
fn force_remove(path: &Path) {
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

/// pull 済みのキャッシュと、bundle の置き場を持つ試験環境。
struct Env {
    tmp: TempDir,
    image_id: String,
    config_hex: String,
    layer_hexes: Vec<String>,
}

impl Env {
    fn cache(&self) -> PathBuf {
        self.tmp.0.join("cache")
    }
    fn bundles(&self) -> PathBuf {
        self.tmp.0.join("bundles")
    }
    fn blob(&self, hex: &str) -> PathBuf {
        self.cache().join("blobs").join("sha256").join(hex)
    }
    fn entry(&self) -> PathBuf {
        self.cache()
            .join("rootfs")
            .join("sha256")
            .join(&self.config_hex)
    }
    fn extract_config(&self) -> ImageExtractConfig {
        let mut pull = PullConfig::new(self.cache()).expect("config");
        pull.platform = Platform::new("linux", "amd64", None);
        ImageExtractConfig::from_pull_config(&pull)
    }
    fn provider_with(&self, source: ImageRootfsSource) -> SpecBundleProvider {
        SpecBundleProvider::new(self.bundles(), Arc::new(source)).expect("provider")
    }
    fn provider(&self) -> SpecBundleProvider {
        self.provider_with(ImageRootfsSource::new(self.extract_config()))
    }
}

/// `config_section` を `config` 節に持つ 2 層イメージを pull してキャッシュを作る。
fn pulled_env(tag: &str, config_section: &str) -> Env {
    pulled_env_with_layers(tag, config_section, layer1(), layer2())
}

/// 下位層・上位層の tar を指定して pull する（名前つき User の解決用に passwd 等を持つ層を渡す）。
fn pulled_env_with_layers(tag: &str, config_section: &str, l1: Vec<u8>, l2: Vec<u8>) -> Env {
    let tmp = TempDir::new(tag);
    let (h1, h2) = (sha256_hex(&l1), sha256_hex(&l2));
    let config = format!(
        r#"{{"architecture":"amd64","os":"linux",{config_section}"rootfs":{{"type":"layers","diff_ids":["sha256:{h1}","sha256:{h2}"]}}}}"#
    )
    .into_bytes();
    let hc = sha256_hex(&config);
    let layers: Vec<String> = [(&h1, l1.len()), (&h2, l2.len())]
        .iter()
        .map(|(h, s)| format!(r#"{{"mediaType":"{MEDIA_TAR}","digest":"sha256:{h}","size":{s}}}"#))
        .collect();
    let manifest_json = format!(
        r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:{hc}","size":{}}},"layers":[{}]}}"#,
        config.len(),
        layers.join(",")
    );
    let manifest = match parse_manifest(
        manifest_json.as_bytes(),
        Some("application/vnd.oci.image.manifest.v1+json"),
    )
    .expect("manifest")
    {
        ParsedManifest::Image(m) => m,
        _ => panic!("image manifest expected"),
    };
    let blobs = HashMap::from([(hc.clone(), config), (h1.clone(), l1), (h2.clone(), l2)]);
    let mut pull = PullConfig::new(tmp.0.join("cache")).expect("config");
    pull.platform = Platform::new("linux", "amd64", None);
    let puller = OciImagePuller::new(FakeClient { manifest, blobs }, pull);
    let pulled = puller
        .pull(&PullRequest {
            reference: "alpine:3.20".to_owned(),
            credentials: None,
        })
        .expect("pull");
    assert_eq!(pulled.id, format!("sha256:{hc}"));
    fs::create_dir(tmp.0.join("bundles")).expect("bundles");
    fs::set_permissions(tmp.0.join("bundles"), fs::Permissions::from_mode(0o755)).unwrap();
    Env {
        tmp,
        image_id: pulled.id,
        config_hex: hc,
        layer_hexes: vec![h1, h2],
    }
}

const CONFIG_SECTION: &str = r#""config":{"Entrypoint":["/bin/app"],"Cmd":["serve"],"Env":["A=img","B=img"],"WorkingDir":"/etc/","User":"1000:2000"},"#;

fn container(image: &str) -> ContainerConfig {
    ContainerConfig {
        metadata: Some(ContainerMetadata {
            name: "c".into(),
            attempt: 0,
        }),
        image: Some(ImageSpec {
            image: image.into(),
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn prepare(p: &SpecBundleProvider, id: &str, c: &ContainerConfig) -> Result<PathBuf, CriError> {
    let pod = PodSandboxConfig::default();
    p.prepare(&BundleRequest::new(id, "sb", &pod, c))
        .map(|b| b.path().to_path_buf())
}

/// 木の（相対パス, 種別, mode, 内容）の一覧。symlink は辿らない。
fn snapshot(root: &Path) -> Vec<(String, char, u32, Vec<u8>)> {
    fn walk(root: &Path, dir: &Path, out: &mut Vec<(String, char, u32, Vec<u8>)>) {
        let mut names: Vec<_> = fs::read_dir(dir).unwrap().flatten().collect();
        names.sort_by_key(|e| e.file_name());
        for e in names {
            let m = fs::symlink_metadata(e.path()).unwrap();
            let rel = e
                .path()
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .into_owned();
            if m.file_type().is_dir() {
                out.push((rel, 'd', m.mode() & 0o7777, Vec::new()));
                walk(root, &e.path(), out);
            } else if m.file_type().is_symlink() {
                out.push((rel, 'l', 0, Vec::new()));
            } else {
                out.push((rel, 'f', m.mode() & 0o7777, fs::read(e.path()).unwrap()));
            }
        }
    }
    let mut out = Vec::new();
    walk(root, root, &mut out);
    out
}

fn bundle_count(env: &Env) -> usize {
    fs::read_dir(env.bundles()).unwrap().count()
}

// ---- 試験 ----

/// fixture の sha256 実装が oci の検証と一致する（試験の土台の健全性）。
#[test]
fn fixture_sha256_matches_the_oci_verifier() {
    for data in [&b""[..], b"abc", &layer1(), &vec![7u8; 1000]] {
        let d = Digest::parse(&format!("sha256:{}", sha256_hex(data))).unwrap();
        fandhe_container_oci::layer::verify_bytes_digest(data, &d).expect("digest");
    }
    assert_eq!(
        sha256_hex(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

/// CRI-2・OCI-4: image ID で bundle が作られ、config.json にイメージ既定値が具体値で合成され、
/// rootfs に layer の内容が積まれる。
#[test]
fn cri2_prepare_builds_bundle_from_the_cached_image() {
    let env = pulled_env("ok", CONFIG_SECTION);
    let p = env.provider();
    let dir = prepare(&p, "ctr1", &container(&env.image_id)).expect("prepare");
    assert_eq!(dir, env.bundles().join("ctr1"));
    let parsed = oci_runtime::load_config(&dir.join("config.json")).expect("core parses");
    let process = parsed.process().expect("process");
    assert_eq!(process.args(), ["/bin/app", "serve"]);
    assert_eq!(process.env(), ["A=img", "B=img"]);
    assert_eq!(process.cwd(), Path::new("/etc"));
    assert_eq!((process.user().uid(), process.user().gid()), (1000, 2000));
    let root = dir.join("rootfs");
    assert_eq!(fs::read(root.join("etc/hello")).unwrap(), b"abc");
    assert_eq!(fs::read(root.join("bin/app")).unwrap(), b"app");
    assert_eq!(fs::read(root.join("world")).unwrap(), b"world");
    assert_eq!(
        fs::metadata(root.join("bin/app")).unwrap().mode() & 0o777,
        0o755
    );
    assert_eq!(
        fs::metadata(root.join("etc")).unwrap().mode() & 0o777,
        0o555
    );
}

/// CRI-2・SEC-1: rootfs 自体は非 root が検索できる 0755、外側の bundle ディレクトリは 0700 のまま。
#[test]
fn cri2_rootfs_root_is_searchable_by_non_root_users() {
    let env = pulled_env("rootmode", CONFIG_SECTION);
    let p = env.provider();
    let dir = prepare(&p, "ctr-mode", &container(&env.image_id)).expect("prepare");
    assert_eq!(
        fs::metadata(dir.join("rootfs")).unwrap().mode() & 0o777,
        0o755
    );
    assert_eq!(fs::metadata(&dir).unwrap().mode() & 0o777, 0o700);
}

/// CRI-2: CRI の command・args・envs・working_dir がイメージ既定値を置き換える。
#[test]
fn cri2_container_config_overrides_image_defaults() {
    let env = pulled_env("override", CONFIG_SECTION);
    let p = env.provider();
    let mut c = container(&env.image_id);
    c.command = vec!["/bin/other".into()];
    c.working_dir = "/world".into();
    let dir = prepare(&p, "ctr1", &c).expect("prepare");
    let parsed = oci_runtime::load_config(&dir.join("config.json")).unwrap();
    let process = parsed.process().unwrap();
    // command だけ指定すると Cmd は使われない（Kubernetes の規則）。
    assert_eq!(process.args(), ["/bin/other"]);
    assert_eq!(process.cwd(), Path::new("/world"));
}

/// A5・OCI-7・SEC-1: bundle の rootfs への書き込み・作成・chmod・symlink の差し替えがキャッシュに届かない。
#[test]
fn a5_container_writes_never_reach_the_cache() {
    let env = pulled_env("a5", CONFIG_SECTION);
    let cache_rootfs = env.entry().join("rootfs");
    let before_tree = snapshot(&cache_rootfs);
    let blob_names: Vec<String> = std::iter::once(env.config_hex.clone())
        .chain(env.layer_hexes.iter().cloned())
        .collect();
    let before_blobs: Vec<Vec<u8>> = blob_names
        .iter()
        .map(|h| fs::read(env.blob(h)).unwrap())
        .collect();
    let before_ino = fs::metadata(cache_rootfs.join("bin/app")).unwrap().ino();
    let p = env.provider();
    let dir = prepare(&p, "ctr1", &container(&env.image_id)).expect("prepare");
    let root = dir.join("rootfs");
    assert!(
        !fs::symlink_metadata(&root)
            .unwrap()
            .file_type()
            .is_symlink(),
        "bundle rootfs must be a real directory"
    );
    // 別実体（inode が違う）であること。
    let own = fs::metadata(root.join("bin/app")).unwrap();
    assert_ne!(own.ino(), before_ino);
    // コンテナ内からの書き込み相当の操作。
    fs::write(root.join("bin/app"), b"tampered").unwrap();
    fs::write(root.join("new-file"), b"new").unwrap();
    fs::set_permissions(root.join("etc"), fs::Permissions::from_mode(0o700)).unwrap();
    fs::remove_file(root.join("world")).unwrap();
    std::os::unix::fs::symlink("/etc/passwd", root.join("world")).unwrap();
    assert_eq!(snapshot(&cache_rootfs), before_tree);
    assert!(!cache_rootfs.join("new-file").exists());
    assert_eq!(
        fs::metadata(cache_rootfs.join("bin/app")).unwrap().nlink(),
        1
    );
    for (h, b) in blob_names.iter().zip(&before_blobs) {
        assert_eq!(&fs::read(env.blob(h)).unwrap(), b, "blob {h} changed");
    }
    // 次の create は書き換え前のイメージ内容から始まる。
    let dir2 = prepare(&p, "ctr2", &container(&env.image_id)).expect("prepare 2");
    assert_eq!(fs::read(dir2.join("rootfs/bin/app")).unwrap(), b"app");
    assert!(!dir2.join("rootfs/new-file").exists());
}

/// 参照の解決: タグは解決器が無ければ UNIMPLEMENTED、不正な ID 形は INVALID_ARGUMENT、未取得は NOT_FOUND。
#[test]
fn cri2_reference_resolution_codes() {
    let env = pulled_env("resolve", CONFIG_SECTION);
    let p = env.provider();
    let code = |image: &str| {
        let e = prepare(&p, "ctr1", &container(image)).unwrap_err();
        assert_eq!(bundle_count(&env), 0, "{image}: no bundle may remain");
        e.code()
    };
    assert_eq!(
        code("docker.io/library/alpine:3.20"),
        CriErrorCode::Unimplemented
    );
    assert_eq!(code("alpine"), CriErrorCode::Unimplemented);
    let hex = env.config_hex.clone();
    assert_eq!(code(&hex), CriErrorCode::InvalidArgument, "bare hex");
    assert_eq!(
        code(&format!("sha256:{}", hex.to_uppercase())),
        CriErrorCode::InvalidArgument
    );
    assert_eq!(code("sha256:abcd"), CriErrorCode::InvalidArgument);
    assert_eq!(
        code(&format!("sha256:{}", "a".repeat(64))),
        CriErrorCode::NotFound
    );
    let long = format!("sha256:{}", "a".repeat(2000));
    assert_eq!(code(&long), CriErrorCode::InvalidArgument);
    assert_eq!(code("sha256:\0"), CriErrorCode::InvalidArgument);
    // runtime_handler は黙って落とさない。
    let mut c = container(&env.image_id);
    c.image.as_mut().unwrap().runtime_handler = "kata".into();
    assert_eq!(
        prepare(&p, "ctr1", &c).unwrap_err().code(),
        CriErrorCode::Unimplemented
    );
    assert_eq!(bundle_count(&env), 0);
}

/// 解決器（ImageStore）を注入するとタグが image ID へ解決される。
#[test]
fn cri2_image_store_resolves_tags() {
    let env = pulled_env("store", CONFIG_SECTION);
    let store = Arc::new(InMemoryImageStore::new());
    store
        .upsert(
            ImageRecord::new(
                env.image_id.clone(),
                vec!["docker.io/library/alpine:3.20".to_owned()],
                vec![],
                10,
            )
            .unwrap(),
        )
        .unwrap();
    let p = env.provider_with(ImageRootfsSource::new(env.extract_config()).with_image_store(store));
    let dir = prepare(&p, "ctr1", &container("docker.io/library/alpine:3.20")).expect("prepare");
    assert_eq!(fs::read(dir.join("rootfs/world")).unwrap(), b"world");
}

/// 在庫の記録の `repo_digests[0]` が解決結果の digest 参照になり、image ID は config digest になる（CRI-2・OCI-1。#2831）。
#[test]
fn cri2_prepare_reports_resolved_image_with_digest_ref() {
    let env = pulled_env("store-digest-ref", CONFIG_SECTION);
    let digest_ref = format!("docker.io/library/alpine@sha256:{}", "d".repeat(64));
    let store = Arc::new(InMemoryImageStore::new());
    store
        .upsert(
            ImageRecord::new(
                env.image_id.clone(),
                vec!["docker.io/library/alpine:3.20".to_owned()],
                vec![digest_ref.clone()],
                10,
            )
            .unwrap(),
        )
        .unwrap();
    let p = env.provider_with(ImageRootfsSource::new(env.extract_config()).with_image_store(store));
    let pod = PodSandboxConfig::default();
    let c = container("docker.io/library/alpine:3.20");
    let prepared = p
        .prepare(&BundleRequest::new("ctr1", "sb", &pod, &c))
        .expect("prepare");
    let image = prepared.image().expect("image reported");
    assert_eq!(image.id_str(), env.image_id);
    assert_eq!(image.image_ref(), digest_ref);
}

/// 在庫なしで image ID を指定したときは image_ref も image ID（CRI-2・OCI-1。#2831）。
#[test]
fn cri2_prepare_reports_image_id_without_store() {
    let env = pulled_env("no-store-ref", CONFIG_SECTION);
    let p = env.provider();
    let pod = PodSandboxConfig::default();
    let c = container(&env.image_id);
    let prepared = p
        .prepare(&BundleRequest::new("ctr1", "sb", &pod, &c))
        .expect("prepare");
    let image = prepared.image().expect("image reported");
    assert_eq!(image.id_str(), env.image_id);
    assert_eq!(image.image_ref(), env.image_id);
}

/// 短縮名（`alpine:3.20`）は PullImage と同じ規則で正規化したタグ（`docker.io/library/alpine:3.20`）として登録された
/// 記録へ解決される（CRI-2・CRI-3・CRI-4。#2592）。
#[test]
fn cri2_image_store_resolves_short_name_via_canonical() {
    let env = pulled_env("store-short", CONFIG_SECTION);
    let store = Arc::new(InMemoryImageStore::new());
    store
        .upsert(
            ImageRecord::new(
                env.image_id.clone(),
                vec!["docker.io/library/alpine:3.20".to_owned()],
                vec![],
                10,
            )
            .unwrap(),
        )
        .unwrap();
    let p = env.provider_with(ImageRootfsSource::new(env.extract_config()).with_image_store(store));
    let dir = prepare(&p, "ctr1", &container("alpine:3.20")).expect("prepare");
    assert_eq!(fs::read(dir.join("rootfs/world")).unwrap(), b"world");
}

/// 正規化しても在庫に無い短縮名は NOT_FOUND で、bundle は残らない（CRI-2・CRI-3。#2592）。
#[test]
fn cri2_image_store_short_name_miss_is_not_found() {
    let env = pulled_env("store-short-miss", CONFIG_SECTION);
    let store = Arc::new(InMemoryImageStore::new());
    let p = env.provider_with(ImageRootfsSource::new(env.extract_config()).with_image_store(store));
    let e = prepare(&p, "ctr1", &container("alpine:3.20")).unwrap_err();
    assert_eq!(e.code(), CriErrorCode::NotFound);
    assert_eq!(e.message(), "image reference is not found");
    assert_eq!(bundle_count(&env), 0);
}

/// 解決器を注入済みで参照が未知のときは UNIMPLEMENTED ではなく NOT_FOUND（CRI-2）。
#[test]
fn cri2_image_store_miss_is_not_found() {
    let env = pulled_env("store-miss", CONFIG_SECTION);
    let store = Arc::new(InMemoryImageStore::new());
    let p = env.provider_with(ImageRootfsSource::new(env.extract_config()).with_image_store(store));
    let e = prepare(&p, "ctr1", &container("docker.io/library/unknown:1")).unwrap_err();
    assert_eq!(e.code(), CriErrorCode::NotFound);
    assert_eq!(bundle_count(&env), 0);
}

/// キャッシュの信頼境界: 信頼できない公開済みエントリ・記録の欠落・設定の食い違いは拒否され、キャッシュは消えず、
/// bundle も残らない。
#[test]
fn oci1_untrusted_cache_entries_are_rejected_without_deleting_them() {
    // group 書き込み可のエントリ。
    let env = pulled_env("trust-mode", CONFIG_SECTION);
    fs::set_permissions(env.entry(), fs::Permissions::from_mode(0o775)).unwrap();
    let e = prepare(&env.provider(), "c1", &container(&env.image_id)).unwrap_err();
    assert_eq!(e.code(), CriErrorCode::FailedPrecondition);
    assert!(env.entry().join("rootfs/world").exists());
    assert_eq!(bundle_count(&env), 0);

    // 記録が無い。
    let env = pulled_env("trust-norecord", CONFIG_SECTION);
    fs::remove_file(env.entry().join("unpack-record")).unwrap();
    let e = prepare(&env.provider(), "c1", &container(&env.image_id)).unwrap_err();
    assert_eq!(e.code(), CriErrorCode::FailedPrecondition);
    assert!(env.entry().join("rootfs/world").exists());
    assert_eq!(bundle_count(&env), 0);

    // 記録が symlink。
    let env = pulled_env("trust-symlink", CONFIG_SECTION);
    let rec = env.entry().join("unpack-record");
    let bytes = fs::read(&rec).unwrap();
    fs::remove_file(&rec).unwrap();
    let real = env.tmp.0.join("real-record");
    fs::write(&real, bytes).unwrap();
    std::os::unix::fs::symlink(&real, &rec).unwrap();
    let e = prepare(&env.provider(), "c1", &container(&env.image_id)).unwrap_err();
    assert_eq!(e.code(), CriErrorCode::FailedPrecondition);
    assert_eq!(bundle_count(&env), 0);

    // 展開設定の食い違い（今回は特殊ビットを保持する設定）。
    let env = pulled_env("trust-settings", CONFIG_SECTION);
    let mut cfg = env.extract_config();
    cfg.extract_options =
        ExtractOptions::new().with_special_bits(SpecialBitsPolicy::PreserveIfChowned);
    let p = env.provider_with(ImageRootfsSource::new(cfg));
    let e = prepare(&p, "c1", &container(&env.image_id)).unwrap_err();
    assert_eq!(e.code(), CriErrorCode::FailedPrecondition);
    assert!(env.entry().join("rootfs/world").exists());
    assert_eq!(bundle_count(&env), 0);

    // layer 行の件数が config の diff_ids と合わない。
    let env = pulled_env("trust-count", CONFIG_SECTION);
    let rec = env.entry().join("unpack-record");
    let text = fs::read_to_string(&rec).unwrap();
    let cut = text.trim_end().rsplit_once('\n').unwrap().0.to_owned() + "\n";
    fs::write(&rec, cut).unwrap();
    let e = prepare(&env.provider(), "c1", &container(&env.image_id)).unwrap_err();
    assert_eq!(e.code(), CriErrorCode::DataLoss);
    assert_eq!(bundle_count(&env), 0);

    // layer 行の digest が不正。
    let env = pulled_env("trust-line", CONFIG_SECTION);
    let rec = env.entry().join("unpack-record");
    let text = fs::read_to_string(&rec).unwrap();
    fs::write(&rec, text.replacen("layer=sha256:", "layer=sha256:../", 1)).unwrap();
    let e = prepare(&env.provider(), "c1", &container(&env.image_id)).unwrap_err();
    assert_eq!(e.code(), CriErrorCode::DataLoss);
    assert_eq!(bundle_count(&env), 0);
}

/// OCI-1: config や layer の blob が改ざんされていたら（digest 不一致）DATA_LOSS、config が上限超なら RESOURCE_EXHAUSTED。
#[test]
fn oci1_tampered_blobs_are_rejected() {
    let env = pulled_env("tamper-config", CONFIG_SECTION);
    let path = env.blob(&env.config_hex);
    let mut body = fs::read(&path).unwrap();
    body[2] = b'X';
    fs::write(&path, body).unwrap();
    let e = prepare(&env.provider(), "c1", &container(&env.image_id)).unwrap_err();
    assert_eq!(e.code(), CriErrorCode::DataLoss);
    assert_eq!(bundle_count(&env), 0);

    let env = pulled_env("tamper-big", CONFIG_SECTION);
    fs::write(env.blob(&env.config_hex), vec![b' '; 1024 * 1024 + 1]).unwrap();
    let e = prepare(&env.provider(), "c1", &container(&env.image_id)).unwrap_err();
    assert_eq!(e.code(), CriErrorCode::ResourceExhausted);
    assert_eq!(bundle_count(&env), 0);

    let env = pulled_env("tamper-layer", CONFIG_SECTION);
    let path = env.blob(&env.layer_hexes[1]);
    let mut body = fs::read(&path).unwrap();
    body[0] = b'X';
    fs::write(&path, body).unwrap();
    let e = prepare(&env.provider(), "c1", &container(&env.image_id)).unwrap_err();
    assert_eq!(e.code(), CriErrorCode::DataLoss);
    assert_eq!(bundle_count(&env), 0);
}

/// 展開上限（REPAIR-5 の有界化）を超えたら RESOURCE_EXHAUSTED で、途中までの bundle は残らない。
#[test]
fn oci1_extract_limits_are_enforced_and_leave_no_bundle() {
    let env = pulled_env("limits", CONFIG_SECTION);
    let mut cfg = env.extract_config();
    cfg.extract_limits = ExtractLimits::new(2, 1 << 20, 1 << 30, 100);
    let p = env.provider_with(ImageRootfsSource::new(cfg));
    let e = prepare(&p, "c1", &container(&env.image_id)).unwrap_err();
    assert_eq!(e.code(), CriErrorCode::ResourceExhausted);
    assert_eq!(bundle_count(&env), 0);
    // layer の合計サイズ上限。
    let mut cfg = env.extract_config();
    cfg.max_image_bytes = 1024;
    let p = env.provider_with(ImageRootfsSource::new(cfg));
    let e = prepare(&p, "c2", &container(&env.image_id)).unwrap_err();
    assert_eq!(e.code(), CriErrorCode::ResourceExhausted);
    assert_eq!(bundle_count(&env), 0);
    // 期限切れ。
    let mut cfg = env.extract_config();
    cfg.deadline = std::time::Duration::ZERO;
    let p = env.provider_with(ImageRootfsSource::new(cfg));
    let e = prepare(&p, "c3", &container(&env.image_id)).unwrap_err();
    assert_eq!(e.code(), CriErrorCode::Timeout);
    // blob の検証前に期限を確かめ、固定文言で返す（REPAIR-5・ERR-1・#2821）。
    assert_eq!(
        e.message(),
        "image rootfs preparation exceeded its deadline"
    );
    assert_eq!(bundle_count(&env), 0);
    // 上限内なら成功する（上の失敗が環境起因でないことの対）。
    let dir = prepare(&env.provider(), "c4", &container(&env.image_id)).expect("ok");
    assert!(dir.join("rootfs/world").exists());
}

/// 最初の `ExtractLayer` の記録を見たら取り消しの旗を立てる記録先（展開の途中を決定的に作る。#2899）。
#[derive(Debug)]
struct CancelAfterFirstLayer {
    flag: Arc<std::sync::atomic::AtomicBool>,
    samples: std::sync::Mutex<Vec<(OciOpKind, OciOpOutcome, Option<OciErrorCode>)>>,
}

impl OciOpRecorder for CancelAfterFirstLayer {
    fn record_oci_op(&self, sample: &OciOpSample) {
        self.samples
            .lock()
            .unwrap()
            .push((sample.kind(), sample.outcome(), sample.error_code()));
        if sample.kind() == OciOpKind::ExtractLayer {
            self.flag.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }
}

/// REPAIR-5・CRI-2（#2899）: 展開の途中（1 層目の後）で取り消しの旗が立つと、2 層目の前で止まり、
/// `DEADLINE_EXCEEDED` に写る固定文言で返り、rootfs・bundle が残らない。計装には 2 層目が TIMEOUT で残る。
#[test]
fn repair5_cancel_during_extraction_stops_at_next_layer_and_leaves_no_bundle() {
    let env = pulled_env("cancel", CONFIG_SECTION);
    let flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let rec = Arc::new(CancelAfterFirstLayer {
        flag: Arc::clone(&flag),
        samples: std::sync::Mutex::new(Vec::new()),
    });
    let source = ImageRootfsSource::new(env.extract_config()).with_recorder(rec.clone());
    let p = env.provider_with(source);
    let pod = PodSandboxConfig::default();
    let c = container(&env.image_id);
    let e = p
        .prepare(&BundleRequest::new("c1", "sb", &pod, &c).with_cancel(&flag))
        .map(|b| b.path().to_path_buf())
        .unwrap_err();
    assert_eq!(e.code(), CriErrorCode::Timeout);
    assert_eq!(
        e.message(),
        "image rootfs preparation exceeded its deadline"
    );
    assert_eq!(bundle_count(&env), 0);
    assert_eq!(
        rec.samples.lock().unwrap().clone(),
        vec![
            (OciOpKind::ExtractLayer, OciOpOutcome::Success, None),
            (
                OciOpKind::ExtractLayer,
                OciOpOutcome::Failure,
                Some(OciErrorCode::Timeout)
            ),
        ]
    );
}

/// release: 0555 を含む rootfs を含む bundle を消せ、不在は成功で冪等。
#[test]
fn oci7_release_removes_the_bundle_with_readonly_directories() {
    let env = pulled_env("release", CONFIG_SECTION);
    let p = env.provider();
    let dir = prepare(&p, "ctr1", &container(&env.image_id)).unwrap();
    assert_eq!(
        fs::metadata(dir.join("rootfs/etc")).unwrap().mode() & 0o777,
        0o555
    );
    p.release("ctr1").expect("release");
    assert!(!dir.exists());
    p.release("ctr1").expect("idempotent");
    // キャッシュは無傷。
    assert_eq!(
        fs::read(env.entry().join("rootfs/world")).unwrap(),
        b"world"
    );
}

/// release は rootfs が symlink なら辿らず消さずに拒否する。
#[test]
fn sec1_release_does_not_follow_a_rootfs_symlink() {
    let env = pulled_env("release-link", CONFIG_SECTION);
    let p = env.provider();
    let dir = prepare(&p, "ctr1", &container(&env.image_id)).unwrap();
    let victim = env.tmp.0.join("victim");
    fs::create_dir(&victim).unwrap();
    fs::write(victim.join("keep"), b"keep").unwrap();
    force_remove(&dir.join("rootfs"));
    std::os::unix::fs::symlink(&victim, dir.join("rootfs")).unwrap();
    assert!(p.release("ctr1").is_err());
    assert_eq!(fs::read(victim.join("keep")).unwrap(), b"keep");
}

/// イメージの User が名前・uid のみのとき、CRI の run_as_user が無ければ UNIMPLEMENTED（root へ落とさない）。
/// run_as_user があれば成功する。
#[test]
fn cri2_unresolved_image_user_is_not_silently_root() {
    let env = pulled_env(
        "user",
        r#""config":{"Entrypoint":["/bin/app"],"User":"app"},"#,
    );
    let p = env.provider();
    let e = prepare(&p, "c1", &container(&env.image_id)).unwrap_err();
    assert_eq!(e.code(), CriErrorCode::Unimplemented);
    assert_eq!(bundle_count(&env), 0);
    let mut c = container(&env.image_id);
    c.linux = Some(LinuxContainerConfig {
        security_context: Some(LinuxContainerSecurityContext {
            run_as_user: Some(Int64Value { value: 1234 }),
            ..Default::default()
        }),
        ..Default::default()
    });
    let dir = prepare(&p, "c2", &c).expect("run_as_user given");
    let parsed = oci_runtime::load_config(&dir.join("config.json")).unwrap();
    assert_eq!(parsed.process().unwrap().user().uid(), 1234);
}

/// config 節が無いイメージは既定値が空で、CRI の command が必要（無ければ INVALID_ARGUMENT）。
#[test]
fn cri2_image_without_config_section_needs_a_command() {
    let env = pulled_env("noconfig", "");
    let p = env.provider();
    let e = prepare(&p, "c1", &container(&env.image_id)).unwrap_err();
    assert_eq!(e.code(), CriErrorCode::InvalidArgument);
    assert_eq!(bundle_count(&env), 0);
    let mut c = container(&env.image_id);
    c.command = vec!["/bin/app".into()];
    prepare(&p, "c2", &c).expect("command given");
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn run_as_user_container(image: &str, uid: i64) -> ContainerConfig {
    let mut c = container(image);
    c.linux = Some(LinuxContainerConfig {
        security_context: Some(LinuxContainerSecurityContext {
            run_as_user: Some(Int64Value { value: uid }),
            ..Default::default()
        }),
        ..Default::default()
    });
    c
}

/// CRI-2・SEC-5: 名前つき User（`app:staff`）が rootfs の passwd / group で `1000:50` に解決される。
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[test]
fn cri2_named_image_user_is_resolved_from_rootfs_passwd_and_group() {
    let l1 = tar_of(&[
        tar_entry("etc/", 0o755, b"", true),
        tar_entry(
            "etc/passwd",
            0o644,
            b"root:x:0:0:r:/root:/bin/sh\napp:x:1000:1001::/h:/bin/sh\n",
            false,
        ),
        tar_entry("etc/group", 0o644, b"staff:x:50:app\n", false),
        tar_entry("bin/", 0o755, b"", true),
        tar_entry("bin/app", 0o755, b"app", false),
    ]);
    let env = pulled_env_with_layers(
        "named-user",
        r#""config":{"Entrypoint":["/bin/app"],"User":"app:staff"},"#,
        l1,
        layer2(),
    );
    let p = env.provider();
    let dir = prepare(&p, "c1", &container(&env.image_id)).expect("resolved");
    let parsed = oci_runtime::load_config(&dir.join("config.json")).unwrap();
    let u = parsed.process().unwrap().user();
    assert_eq!((u.uid(), u.gid()), (1000, 50));
}

/// SEC-1・SEC-5: `etc` がホスト側を指す symlink のイメージは passwd を読まず未解決になる。
/// run_as_user が無ければ UNIMPLEMENTED、あれば `(33, 0)` で成功する。
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[test]
fn sec1_symlinked_etc_in_image_is_not_read() {
    let l1 = tar_of(&[
        tar_symlink("etc", "/etc"),
        tar_entry("bin/", 0o755, b"", true),
        tar_entry("bin/app", 0o755, b"app", false),
    ]);
    let env = pulled_env_with_layers(
        "symlink-etc",
        r#""config":{"Entrypoint":["/bin/app"],"User":"root"},"#,
        l1,
        layer2(),
    );
    let p = env.provider();
    let e = prepare(&p, "c1", &container(&env.image_id)).unwrap_err();
    assert_eq!(e.code(), CriErrorCode::Unimplemented);
    assert_eq!(bundle_count(&env), 0);
    let dir = prepare(&p, "c2", &run_as_user_container(&env.image_id, 33)).expect("run_as_user");
    let parsed = oci_runtime::load_config(&dir.join("config.json")).unwrap();
    let u = parsed.process().unwrap().user();
    assert_eq!((u.uid(), u.gid()), (33, 0));
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn run_as_username_container(image: &str, name: &str, gid: Option<i64>) -> ContainerConfig {
    let mut c = container(image);
    c.linux = Some(LinuxContainerConfig {
        security_context: Some(LinuxContainerSecurityContext {
            run_as_username: name.into(),
            run_as_group: gid.map(|value| Int64Value { value }),
            ..Default::default()
        }),
        ..Default::default()
    });
    c
}

/// CRI-2・SEC-5（#2664）: run_as_username が rootfs の passwd で解決され、run_as_group が gid を上書きする。
/// イメージ User が未解決（`ghost`）でも username が解決すれば成功する。
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[test]
fn cri2_run_as_username_is_resolved_from_rootfs_passwd() {
    let l1 = tar_of(&[
        tar_entry("etc/", 0o755, b"", true),
        tar_entry(
            "etc/passwd",
            0o644,
            b"root:x:0:0:r:/root:/bin/sh\napp:x:1000:1001::/h:/bin/sh\n",
            false,
        ),
        tar_entry("bin/", 0o755, b"", true),
        tar_entry("bin/app", 0o755, b"app", false),
    ]);
    let env = pulled_env_with_layers(
        "run-as-username",
        r#""config":{"Entrypoint":["/bin/app"],"User":"ghost"},"#,
        l1,
        layer2(),
    );
    let p = env.provider();
    let ids = |dir: &Path| {
        let parsed = oci_runtime::load_config(&dir.join("config.json")).unwrap();
        let u = parsed.process().unwrap().user();
        (u.uid(), u.gid())
    };
    let d = prepare(
        &p,
        "c1",
        &run_as_username_container(&env.image_id, "app", None),
    )
    .expect("c1");
    assert_eq!(ids(&d), (1000, 1001));
    let d = prepare(
        &p,
        "c2",
        &run_as_username_container(&env.image_id, "app", Some(44)),
    )
    .expect("c2");
    assert_eq!(ids(&d), (1000, 44));
    // passwd に無い名前は INVALID_ARGUMENT で、bundle を残さない。
    let before = bundle_count(&env);
    let e = prepare(
        &p,
        "c3",
        &run_as_username_container(&env.image_id, "nobody", None),
    )
    .unwrap_err();
    assert_eq!(e.code(), CriErrorCode::InvalidArgument);
    assert_eq!(bundle_count(&env), before);
}

/// SEC-1・SEC-5（#2664）: `etc` がホストを指す symlink のイメージでは passwd を読まず FAILED_PRECONDITION にする。
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[test]
fn sec1_run_as_username_with_symlinked_etc_is_rejected() {
    let l1 = tar_of(&[
        tar_symlink("etc", "/etc"),
        tar_entry("bin/", 0o755, b"", true),
        tar_entry("bin/app", 0o755, b"app", false),
    ]);
    let env = pulled_env_with_layers(
        "username-symlink-etc",
        r#""config":{"Entrypoint":["/bin/app"]},"#,
        l1,
        layer2(),
    );
    let p = env.provider();
    let e = prepare(
        &p,
        "c1",
        &run_as_username_container(&env.image_id, "root", None),
    )
    .unwrap_err();
    assert_eq!(e.code(), CriErrorCode::FailedPrecondition);
    assert_eq!(bundle_count(&env), 0);
}
