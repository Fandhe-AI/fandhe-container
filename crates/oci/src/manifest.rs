//! マニフェストと image index のパース・platform 選択（TASK-51.3・OCI-1・MS-4・#402）。
//!
//! `RegistryClient::fetch_manifest`（`registry`）が受信した本文と `Content-Type` を `parse_manifest` へ渡し、
//! 検証済みの値型へ変換する。結果の config / layer の descriptor 一覧は blob 取得（#403）・digest 検証（#405）・
//! rootfs 展開（TASK-52）の入力になる。
//!
//! 対応する `mediaType` は OCI image manifest / image index と Docker schema 2 の manifest / manifest list の
//! 4 種のみ。これ以外（Docker schema 1 を含む）は `Unimplemented` で拒否する（互換範囲の最終確定は spec で検討中）。
//!
//! 本文はレジストリが返す非信頼入力として扱う。`unwrap` / `expect` / 添字アクセスを使わず、不正な JSON・
//! 必須項目の欠落・不正な digest は `DataLoss` に分類する。message は固定文で、本文の断片は載せない。
//!
//! 未実装（実装済みを装わない。REPAIR-3）: digest の突合（本文のハッシュと参照 digest・`Docker-Content-Digest`。
//! #405）。ここで返す値は未検証であり、digest で取得した場合の本文ハッシュ一致検証は呼び出し側が #405 で行う。

use crate::error::{OciError, OciErrorCode};
use crate::reference::Digest;
use serde::Deserialize;

/// OCI image manifest。
pub const MEDIA_TYPE_OCI_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
/// OCI image index。
pub const MEDIA_TYPE_OCI_INDEX: &str = "application/vnd.oci.image.index.v1+json";
/// Docker schema 2 の image manifest。
pub const MEDIA_TYPE_DOCKER_MANIFEST: &str = "application/vnd.docker.distribution.manifest.v2+json";
/// Docker schema 2 の manifest list。
pub const MEDIA_TYPE_DOCKER_LIST: &str =
    "application/vnd.docker.distribution.manifest.list.v2+json";

/// 受理する本文の最大バイト数（4 MiB。Distribution spec の推奨上限）。
pub const MANIFEST_MAX_BYTES: u64 = 4 * 1024 * 1024;
/// layers の最大件数。
pub const MAX_LAYERS: usize = 128;
/// image index の manifests の最大件数。
pub const MAX_INDEX_ENTRIES: usize = 1024;

/// descriptor の size の上限（OCI は int64 の範囲）。
const SIZE_MAX: u64 = i64::MAX as u64;

fn data_loss(msg: &'static str) -> OciError {
    OciError::new(OciErrorCode::DataLoss, msg)
}

/// 対象 platform（OS・アーキテクチャ・任意の variant）。
///
/// image index から manifest を選ぶ条件。`variant` は指定したときだけ一致を要求する。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Platform {
    os: String,
    architecture: String,
    variant: Option<String>,
}

impl Platform {
    /// platform を作る（OCI の名前。例: `linux` / `arm64` / `v8`）。
    pub fn new(os: &str, architecture: &str, variant: Option<&str>) -> Self {
        Self {
            os: os.to_string(),
            architecture: architecture.to_string(),
            variant: variant.map(str::to_string),
        }
    }

    /// ホストのアーキテクチャに対応する `linux` の platform。
    ///
    /// コンテナの対象 OS は macOS / Windows ホストでも VM 内の linux のため常に `linux`。
    /// 写像できないアーキテクチャは `Unimplemented`。
    pub fn host() -> Result<Self, OciError> {
        Self::for_arch(std::env::consts::ARCH)
    }

    /// Rust の `ARCH` 名から platform を作る（`host` の試験用の分離。`cfg` は使わない）。
    pub(crate) fn for_arch(arch: &str) -> Result<Self, OciError> {
        let name = match arch {
            "x86_64" => "amd64",
            "aarch64" => "arm64",
            "arm" => "arm",
            "riscv64" => "riscv64",
            "s390x" => "s390x",
            _ => {
                return Err(OciError::new(
                    OciErrorCode::Unimplemented,
                    "host architecture has no OCI platform mapping",
                ));
            }
        };
        Ok(Self::new("linux", name, None))
    }

    /// OS 名。
    pub fn os(&self) -> &str {
        &self.os
    }

    /// アーキテクチャ名。
    pub fn architecture(&self) -> &str {
        &self.architecture
    }

    /// variant（指定時のみ）。
    pub fn variant(&self) -> Option<&str> {
        self.variant.as_deref()
    }
}

/// 検証済みの descriptor（`digest` は `Digest::parse` を通過済み）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Descriptor {
    /// 対象の `mediaType`。
    pub media_type: String,
    /// 対象の digest（未検証の参照。本文との突合は #405）。
    pub digest: Digest,
    /// 宣言されたバイト数。
    pub size: u64,
    /// image index のエントリが持つ platform。
    pub platform: Option<Platform>,
}

/// image manifest（config と layers の descriptor）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ImageManifest {
    /// config blob。
    pub config: Descriptor,
    /// layer の一覧（適用順）。
    pub layers: Vec<Descriptor>,
}

/// image index / manifest list。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ImageIndex {
    /// 各 platform の manifest への descriptor。
    pub manifests: Vec<Descriptor>,
}

/// パース結果。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ParsedManifest {
    /// image manifest。
    Image(ImageManifest),
    /// image index / manifest list。
    Index(ImageIndex),
}

#[derive(Deserialize)]
struct RawPlatform {
    architecture: Option<String>,
    os: Option<String>,
    variant: Option<String>,
}

#[derive(Deserialize)]
struct RawDescriptor {
    #[serde(rename = "mediaType")]
    media_type: Option<String>,
    digest: Option<String>,
    size: Option<u64>,
    platform: Option<RawPlatform>,
}

#[derive(Deserialize)]
struct RawManifest {
    #[serde(rename = "schemaVersion")]
    schema_version: Option<u64>,
    #[serde(rename = "mediaType")]
    media_type: Option<String>,
    config: Option<RawDescriptor>,
    layers: Option<Vec<RawDescriptor>>,
    manifests: Option<Vec<RawDescriptor>>,
}

fn convert_descriptor(raw: RawDescriptor) -> Result<Descriptor, OciError> {
    let media_type = raw
        .media_type
        .ok_or_else(|| data_loss("descriptor is missing mediaType"))?;
    let digest = raw
        .digest
        .ok_or_else(|| data_loss("descriptor is missing digest"))?;
    let digest =
        Digest::parse(&digest).map_err(|_| data_loss("descriptor has an invalid digest"))?;
    let size = raw
        .size
        .filter(|s| *s <= SIZE_MAX)
        .ok_or_else(|| data_loss("descriptor has a missing or invalid size"))?;
    let platform = match raw.platform {
        Some(RawPlatform {
            architecture: Some(a),
            os: Some(o),
            variant,
        }) => Some(Platform {
            os: o,
            architecture: a,
            variant,
        }),
        _ => None,
    };
    Ok(Descriptor {
        media_type,
        digest,
        size,
        platform,
    })
}

/// `Content-Type` からパラメータ（`; charset=` 等）を除いて小文字化する。
fn normalize_content_type(ct: &str) -> String {
    ct.split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase()
}

/// 受信した manifest 本文を検証して値型へ変換する。
///
/// 本文長を先に検証し、本文の `mediaType` と `Content-Type` が両方あれば一致を要求する
/// （どちらか一方だけならそれを採用）。`schemaVersion` は 2 のみ受理する。
/// 件数は上限（`MAX_LAYERS`・`MAX_INDEX_ENTRIES`）を超えると `ResourceExhausted`。
pub fn parse_manifest(body: &[u8], content_type: Option<&str>) -> Result<ParsedManifest, OciError> {
    if body.len() as u64 > MANIFEST_MAX_BYTES {
        return Err(OciError::new(
            OciErrorCode::ResourceExhausted,
            "manifest body is too large",
        ));
    }
    let raw: RawManifest =
        serde_json::from_slice(body).map_err(|_| data_loss("manifest is not valid JSON"))?;
    if raw.schema_version != Some(2) {
        return Err(OciError::new(
            OciErrorCode::Unimplemented,
            "unsupported manifest schemaVersion",
        ));
    }
    let header = content_type.map(normalize_content_type);
    let media_type = match (raw.media_type.as_deref(), header.as_deref()) {
        (Some(b), Some(h)) if b != h => {
            return Err(data_loss("manifest mediaType does not match Content-Type"));
        }
        (Some(b), _) => b,
        (None, Some(h)) => h,
        (None, None) => return Err(data_loss("manifest mediaType is unknown")),
    };
    match media_type {
        MEDIA_TYPE_OCI_MANIFEST | MEDIA_TYPE_DOCKER_MANIFEST => {
            let config = raw
                .config
                .ok_or_else(|| data_loss("manifest is missing config"))?;
            let layers = raw
                .layers
                .ok_or_else(|| data_loss("manifest is missing layers"))?;
            if layers.len() > MAX_LAYERS {
                return Err(OciError::new(
                    OciErrorCode::ResourceExhausted,
                    "manifest has too many layers",
                ));
            }
            Ok(ParsedManifest::Image(ImageManifest {
                config: convert_descriptor(config)?,
                layers: layers
                    .into_iter()
                    .map(convert_descriptor)
                    .collect::<Result<_, _>>()?,
            }))
        }
        MEDIA_TYPE_OCI_INDEX | MEDIA_TYPE_DOCKER_LIST => {
            let manifests = raw
                .manifests
                .ok_or_else(|| data_loss("index is missing manifests"))?;
            if manifests.len() > MAX_INDEX_ENTRIES {
                return Err(OciError::new(
                    OciErrorCode::ResourceExhausted,
                    "index has too many entries",
                ));
            }
            Ok(ParsedManifest::Index(ImageIndex {
                manifests: manifests
                    .into_iter()
                    .map(convert_descriptor)
                    .collect::<Result<_, _>>()?,
            }))
        }
        _ => Err(OciError::new(
            OciErrorCode::Unimplemented,
            "unsupported manifest mediaType",
        )),
    }
}

/// index から対象 platform の manifest descriptor を選ぶ。
///
/// os・architecture が一致し、要求側が variant を指定したときは variant も一致するものの先頭。
/// platform を持たない（attestation 等の）エントリは対象外。一致なしは `NotFound`。
pub fn select_manifest<'a>(
    index: &'a ImageIndex,
    platform: &Platform,
) -> Result<&'a Descriptor, OciError> {
    index
        .manifests
        .iter()
        .find(|d| {
            d.platform.as_ref().is_some_and(|p| {
                p.os == platform.os
                    && p.architecture == platform.architecture
                    && platform
                        .variant
                        .as_ref()
                        .is_none_or(|v| p.variant.as_ref() == Some(v))
            })
        })
        .ok_or_else(|| {
            OciError::new(
                OciErrorCode::NotFound,
                "no manifest matches the requested platform",
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    const H1: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const H2: &str = "2222222222222222222222222222222222222222222222222222222222222222";
    const H3: &str = "3333333333333333333333333333333333333333333333333333333333333333";

    fn image_json(mt: &str) -> String {
        format!(
            r#"{{"schemaVersion":2,"mediaType":"{mt}","config":{{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:{H1}","size":7}},"layers":[{{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"sha256:{H2}","size":100}}]}}"#
        )
    }

    fn index_json(mt: &str) -> String {
        format!(
            r#"{{"schemaVersion":2,"mediaType":"{mt}","manifests":[
{{"mediaType":"{MEDIA_TYPE_OCI_MANIFEST}","digest":"sha256:{H1}","size":10,"platform":{{"architecture":"amd64","os":"linux"}}}},
{{"mediaType":"{MEDIA_TYPE_OCI_MANIFEST}","digest":"sha256:{H2}","size":10,"platform":{{"architecture":"arm64","os":"linux","variant":"v8"}}}},
{{"mediaType":"{MEDIA_TYPE_OCI_MANIFEST}","digest":"sha256:{H3}","size":10,"platform":{{"architecture":"unknown","os":"unknown"}}}}]}}"#
        )
    }

    fn index(mt: &str) -> ImageIndex {
        match parse_manifest(index_json(mt).as_bytes(), None).expect("parse") {
            ParsedManifest::Index(i) => i,
            other => panic!("expected index, got {other:?}"),
        }
    }

    /// OCI-1: OCI / Docker v2 の image manifest が config と layers の具体値で得られる。
    #[test]
    fn parses_image_manifests() {
        for mt in [MEDIA_TYPE_OCI_MANIFEST, MEDIA_TYPE_DOCKER_MANIFEST] {
            let ParsedManifest::Image(m) =
                parse_manifest(image_json(mt).as_bytes(), Some(mt)).expect("parse")
            else {
                panic!("expected image");
            };
            assert_eq!(m.config.digest.as_str(), format!("sha256:{H1}"));
            assert_eq!(m.config.size, 7);
            assert_eq!(m.layers.len(), 1);
            assert_eq!(m.layers[0].digest.as_str(), format!("sha256:{H2}"));
            assert_eq!(m.layers[0].size, 100);
        }
    }

    /// OCI-1: OCI index / Docker manifest list の双方でホスト相当の platform が解決される。
    #[test]
    fn selects_by_platform() {
        for mt in [MEDIA_TYPE_OCI_INDEX, MEDIA_TYPE_DOCKER_LIST] {
            let i = index(mt);
            assert_eq!(i.manifests.len(), 3);
            let amd = select_manifest(&i, &Platform::for_arch("x86_64").expect("p")).expect("amd");
            assert_eq!(amd.digest.as_str(), format!("sha256:{H1}"));
            let arm = select_manifest(&i, &Platform::for_arch("aarch64").expect("p")).expect("arm");
            assert_eq!(arm.digest.as_str(), format!("sha256:{H2}"));
        }
    }

    /// OCI-1: variant は要求側が指定したときだけ照合される。unknown/unknown は選ばれない。
    #[test]
    fn variant_and_not_found() {
        let i = index(MEDIA_TYPE_OCI_INDEX);
        let v8 = Platform::new("linux", "arm64", Some("v8"));
        assert_eq!(
            select_manifest(&i, &v8).expect("v8").digest.as_str(),
            format!("sha256:{H2}")
        );
        let v7 = Platform::new("linux", "arm64", Some("v7"));
        assert_eq!(
            select_manifest(&i, &v7).expect_err("v7").code(),
            OciErrorCode::NotFound
        );
        let s390 = Platform::new("linux", "s390x", None);
        assert_eq!(
            select_manifest(&i, &s390).expect_err("s390x").code(),
            OciErrorCode::NotFound
        );
    }

    /// OCI-1: ホスト arch 名の写像（具体値）。未知は Unimplemented。
    #[test]
    fn host_arch_mapping() {
        let p = Platform::for_arch("x86_64").expect("amd64");
        assert_eq!(
            (p.os(), p.architecture(), p.variant()),
            ("linux", "amd64", None)
        );
        assert_eq!(
            Platform::for_arch("aarch64").expect("arm64").architecture(),
            "arm64"
        );
        assert_eq!(
            Platform::for_arch("sparc").expect_err("unknown").code(),
            OciErrorCode::Unimplemented
        );
        // 実ホストでも panic せず Result で返る。
        let _ = Platform::host();
    }

    fn code_of(body: &[u8], ct: Option<&str>) -> OciErrorCode {
        parse_manifest(body, ct).expect_err("must fail").code()
    }

    /// OCI-1: 不正入力は panic せず、分類つきの Err になる。
    #[test]
    fn rejects_malformed_input() {
        assert_eq!(code_of(b"", None), OciErrorCode::DataLoss);
        assert_eq!(code_of(b"{not json", None), OciErrorCode::DataLoss);
        assert_eq!(code_of(b"[]", None), OciErrorCode::DataLoss);
        let deep = "[".repeat(100_000);
        assert_eq!(code_of(deep.as_bytes(), None), OciErrorCode::DataLoss);
        // schemaVersion 欠落・1
        assert_eq!(
            code_of(br#"{"mediaType":"x"}"#, None),
            OciErrorCode::Unimplemented
        );
        assert_eq!(
            code_of(br#"{"schemaVersion":1,"name":"a"}"#, None),
            OciErrorCode::Unimplemented
        );
        // 未知の mediaType（schema 1 の署名つき形式を含む）
        for mt in [
            "application/vnd.docker.distribution.manifest.v1+prettyjws",
            "text/html",
        ] {
            let b = format!(r#"{{"schemaVersion":2,"mediaType":"{mt}"}}"#);
            assert_eq!(code_of(b.as_bytes(), None), OciErrorCode::Unimplemented);
        }
        // mediaType が本文にも Content-Type にも無い
        assert_eq!(
            code_of(br#"{"schemaVersion":2}"#, None),
            OciErrorCode::DataLoss
        );
        // 本文と Content-Type の不一致
        let b = image_json(MEDIA_TYPE_OCI_MANIFEST);
        assert_eq!(
            code_of(b.as_bytes(), Some(MEDIA_TYPE_OCI_INDEX)),
            OciErrorCode::DataLoss
        );
    }

    /// OCI-1: Content-Type のパラメータは無視され、本文に mediaType が無ければ Content-Type を採用する。
    #[test]
    fn content_type_fallback_and_params() {
        let b = image_json(MEDIA_TYPE_OCI_MANIFEST);
        let ct = format!("{MEDIA_TYPE_OCI_MANIFEST}; charset=utf-8");
        assert!(parse_manifest(b.as_bytes(), Some(&ct)).is_ok());
        let no_mt = format!(
            r#"{{"schemaVersion":2,"config":{{"mediaType":"c","digest":"sha256:{H1}","size":1}},"layers":[]}}"#
        );
        assert!(matches!(
            parse_manifest(no_mt.as_bytes(), Some(MEDIA_TYPE_DOCKER_MANIFEST)),
            Ok(ParsedManifest::Image(_))
        ));
    }

    /// OCI-1: descriptor の不正（digest・size・欠落）は DataLoss。
    #[test]
    fn rejects_bad_descriptors() {
        let mt = MEDIA_TYPE_OCI_MANIFEST;
        let bads = [
            r#""digest":"sha256:abcd","size":1"#.to_string(),
            r#""digest":"sha512:abcd","size":1"#.to_string(),
            format!(r#""digest":"sha256:{H1}""#),
            format!(r#""digest":"sha256:{H1}","size":-1"#),
            format!(r#""digest":"sha256:{H1}","size":9223372036854775808"#),
            "\"size\":1".to_string(),
        ];
        for bad in &bads {
            let b = format!(
                r#"{{"schemaVersion":2,"mediaType":"{mt}","config":{{"mediaType":"c",{bad}}},"layers":[]}}"#
            );
            assert_eq!(code_of(b.as_bytes(), None), OciErrorCode::DataLoss, "{bad}");
        }
        let b = format!(r#"{{"schemaVersion":2,"mediaType":"{mt}","layers":[]}}"#);
        assert_eq!(code_of(b.as_bytes(), None), OciErrorCode::DataLoss);
    }

    /// OCI-1・REPAIR-5: 件数と本文長の上限は ResourceExhausted。
    #[test]
    fn enforces_limits() {
        let layer = format!(r#"{{"mediaType":"l","digest":"sha256:{H2}","size":1}}"#);
        let layers = vec![layer; MAX_LAYERS + 1].join(",");
        let b = format!(
            r#"{{"schemaVersion":2,"mediaType":"{MEDIA_TYPE_OCI_MANIFEST}","config":{{"mediaType":"c","digest":"sha256:{H1}","size":1}},"layers":[{layers}]}}"#
        );
        assert_eq!(code_of(b.as_bytes(), None), OciErrorCode::ResourceExhausted);
        let big = vec![b' '; MANIFEST_MAX_BYTES as usize + 1];
        assert_eq!(code_of(&big, None), OciErrorCode::ResourceExhausted);
    }
}
