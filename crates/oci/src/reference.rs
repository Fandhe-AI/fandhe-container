//! イメージ参照（registry / repository / tag・digest）の検証済み型とパース（TASK-51.1・OCI-1）。
//!
//! 外部入力（CLI 引数・CRI リクエスト・TOML）の参照文字列は、このモジュールの newtype に通してからでないと
//! URL の組み立て（`registry` モジュールの `RegistryEndpoint`）へ渡せない。userinfo・スキーム・`..`・
//! 制御文字の混入による接続先のすり替えやパストラバーサル型の URL 改変を防ぐ（OWASP インジェクション）。
//! 文法は OCI distribution-spec / Docker の参照規則に従う。検証は長さの上限を先に確かめてから行い、
//! `unwrap` や添字アクセスは使わない（coding-rust.md）。
//!
//! digest の形式検証のみを行う（`sha256:` + 小文字 hex 64 桁）。実データとの照合は #405 の担当。
//! 生成後の値は不変で、不正な値を表現できない（REPAIR-2）。

use crate::error::{OciError, OciErrorCode};
use std::fmt;

/// 参照文字列全体の最大バイト数。
pub const REFERENCE_MAX_BYTES: usize = 4096;
/// repository 名全体の最大バイト数（distribution-spec）。
pub const REPOSITORY_MAX_BYTES: usize = 255;
/// tag の最大バイト数（distribution-spec）。
pub const TAG_MAX_BYTES: usize = 128;
/// ホスト名の最大バイト数（DNS の上限）。
const HOST_MAX_BYTES: usize = 253;
/// Docker Hub の既定の接続先。
pub const DOCKER_HUB_REGISTRY_HOST: &str = "registry-1.docker.io";

fn invalid(message: &str) -> OciError {
    OciError::new(OciErrorCode::InvalidArgument, message)
}

/// レジストリのホスト（任意のポート付き）。userinfo・スキーム・パスを含められない。
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RegistryHost {
    host: String,
    port: Option<u16>,
}

impl RegistryHost {
    /// `host` または `host:port` を検証して作る。IPv6 リテラルは対象外として拒否する。
    pub fn parse(s: &str) -> Result<Self, OciError> {
        if s.is_empty() || s.len() > HOST_MAX_BYTES + 6 {
            return Err(invalid("invalid registry host length"));
        }
        let (host, port) = match s.split_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (s, None),
        };
        if host.is_empty() || host.len() > HOST_MAX_BYTES {
            return Err(invalid("invalid registry host length"));
        }
        for label in host.split('.') {
            let ok = !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-');
            if !ok {
                return Err(invalid("invalid registry host name"));
            }
        }
        let port = match port {
            None => None,
            Some(p) => {
                if p.is_empty() || p.len() > 5 || !p.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(invalid("invalid registry port"));
                }
                match p.parse::<u16>() {
                    Ok(n) if n >= 1 => Some(n),
                    _ => return Err(invalid("registry port out of range")),
                }
            }
        };
        Ok(Self {
            host: host.to_ascii_lowercase(),
            port,
        })
    }

    /// `host` または `host:port` を返す（URL の authority 部）。
    pub fn authority(&self) -> String {
        match self.port {
            Some(p) => format!("{}:{}", self.host, p),
            None => self.host.clone(),
        }
    }

    /// ホスト名（小文字化済み）を返す。
    pub fn host(&self) -> &str {
        &self.host
    }

    /// ポート（あれば）を返す。
    pub fn port(&self) -> Option<u16> {
        self.port
    }
}

impl fmt::Display for RegistryHost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.authority())
    }
}

/// repository 名（`/` 区切りの成分列）。各成分は `[a-z0-9]+((\.|_|__|-+)[a-z0-9]+)*`。
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Repository(String);

impl Repository {
    /// repository 名を検証して作る。空の成分・`.`・`..` は成分規則により拒否される。
    pub fn parse(s: &str) -> Result<Self, OciError> {
        if s.is_empty() || s.len() > REPOSITORY_MAX_BYTES {
            return Err(invalid("invalid repository length"));
        }
        if !s.split('/').all(valid_repository_component) {
            return Err(invalid("invalid repository name"));
        }
        Ok(Self(s.to_string()))
    }

    /// repository 名を返す（検証済みで `[a-z0-9._/-]` のみ）。
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// 成分数を返す。
    pub(crate) fn component_count(&self) -> usize {
        self.0.split('/').count()
    }
}

impl fmt::Display for Repository {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// repository の 1 成分が `[a-z0-9]+((\.|_|__|-+)[a-z0-9]+)*` に合致するか。
fn valid_repository_component(c: &str) -> bool {
    let mut seen_alnum = false;
    let mut sep = String::new();
    for b in c.bytes() {
        if b.is_ascii_lowercase() || b.is_ascii_digit() {
            if seen_alnum {
                let ok = matches!(sep.as_str(), "" | "." | "_" | "__")
                    || (!sep.is_empty() && sep.bytes().all(|x| x == b'-'));
                if !ok {
                    return false;
                }
            } else if !sep.is_empty() {
                return false;
            }
            seen_alnum = true;
            sep.clear();
        } else if matches!(b, b'.' | b'_' | b'-') {
            // 連続ハイフンの個数に独自の上限は設けない（文法上は無制限。全体は 255 バイト上限で抑える）。
            sep.push(b as char);
        } else {
            return false;
        }
    }
    seen_alnum && sep.is_empty()
}

/// digest（`sha256:` + 小文字 hex 64 桁のみ。他のアルゴリズムは fail-closed で拒否）。
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Digest(String);

impl Digest {
    /// `sha256:<64 桁の小文字 hex>` を検証して作る。
    pub fn parse(s: &str) -> Result<Self, OciError> {
        let Some(hex) = s.strip_prefix("sha256:") else {
            return Err(invalid("unsupported digest algorithm"));
        };
        if hex.len() != 64 || !hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
            return Err(invalid("invalid sha256 digest"));
        }
        Ok(Self(s.to_string()))
    }

    /// 任意のバイト列の SHA-256 から content digest（`sha256:<小文字 hex 64 桁>`）を計算する。
    ///
    /// OCI の content digest を求める入口。cli の参照キーの畳み込み・状態ルート識別子の導出
    /// （#2500・OCI-7）でも暗号学的ハッシュとして使う。失敗しない。
    pub fn sha256_of(bytes: &[u8]) -> Self {
        use sha2::{Digest as _, Sha256};
        use std::fmt::Write as _;
        let mut s = String::from("sha256:");
        for b in Sha256::digest(bytes) {
            // String への書き込みは失敗しない。
            let _ = write!(s, "{b:02x}");
        }
        Self(s)
    }

    /// `sha256:<hex>` 形式の文字列を返す。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// tag（`[A-Za-z0-9_][A-Za-z0-9._-]{0,127}`）。
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Tag(String);

impl Tag {
    /// tag を検証して作る。
    pub fn parse(s: &str) -> Result<Self, OciError> {
        let mut bytes = s.bytes();
        let first_ok = bytes
            .next()
            .is_some_and(|b| b.is_ascii_alphanumeric() || b == b'_');
        if !first_ok
            || s.len() > TAG_MAX_BYTES
            || !bytes.all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
        {
            return Err(invalid("invalid tag"));
        }
        Ok(Self(s.to_string()))
    }

    /// tag 文字列を返す。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Tag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// manifest の参照先（tag または digest）。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Reference {
    /// tag 指定。
    Tag(Tag),
    /// digest 指定。
    Digest(Digest),
}

impl Reference {
    /// URL の末尾に置く文字列（検証済みのため追加のエスケープは不要）。
    pub(crate) fn as_str(&self) -> &str {
        match self {
            Self::Tag(t) => t.as_str(),
            Self::Digest(d) => d.as_str(),
        }
    }
}

/// 検証・正規化済みのイメージ参照。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ImageReference {
    registry: RegistryHost,
    repository: Repository,
    reference: Reference,
}

impl ImageReference {
    /// `[host[:port]/]name[:tag][@digest]` を検証して作る。
    ///
    /// 正規化規則（Docker 互換）:
    /// - ホスト省略・`docker.io`・`index.docker.io` は接続先 `registry-1.docker.io` に写し、
    ///   単一成分の repository には `library/` を補う
    /// - tag も digest も無ければ `latest` を補う
    /// - `name:tag@digest` は digest を優先し、tag は保持しない
    ///
    /// 最初の `/` より前に `.` か `:` を含む、または `localhost` であればレジストリのホストとみなす。
    pub fn parse(input: &str) -> Result<Self, OciError> {
        if input.is_empty() || input.len() > REFERENCE_MAX_BYTES {
            return Err(invalid("invalid image reference length"));
        }
        // 許可文字の外（空白・制御文字・非 ASCII・スキームの `//` 以外の記号）は構文解析の前に拒否する。
        if !input.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'/' | b'@' | b'-')
        }) {
            return Err(invalid("image reference contains invalid characters"));
        }
        let (name, digest) = match input.split_once('@') {
            Some((n, d)) => (n, Some(Digest::parse(d)?)),
            None => (input, None),
        };
        let (host_part, rest) = match name.split_once('/') {
            Some((first, rest)) if first.contains(['.', ':']) || first == "localhost" => {
                (Some(first), rest)
            }
            _ => (None, name),
        };
        let (repo_part, tag) = match rest.rsplit_once(':') {
            Some((r, t)) => (r, Some(Tag::parse(t)?)),
            None => (rest, None),
        };
        let registry = match host_part {
            None => RegistryHost::parse(DOCKER_HUB_REGISTRY_HOST)?,
            Some(h) => RegistryHost::parse(h)?,
        };
        let is_hub = registry.port().is_none()
            && matches!(
                registry.host(),
                DOCKER_HUB_REGISTRY_HOST | "docker.io" | "index.docker.io"
            );
        let registry = if is_hub {
            RegistryHost::parse(DOCKER_HUB_REGISTRY_HOST)?
        } else {
            registry
        };
        let mut repository = Repository::parse(repo_part)?;
        if is_hub && repository.component_count() == 1 {
            repository = Repository::parse(&format!("library/{}", repository.as_str()))?;
        }
        let reference = match (digest, tag) {
            (Some(d), _) => Reference::Digest(d),
            (None, Some(t)) => Reference::Tag(t),
            (None, None) => Reference::Tag(Tag::parse("latest")?),
        };
        Ok(Self {
            registry,
            repository,
            reference,
        })
    }

    /// 接続先レジストリを返す。
    pub fn registry(&self) -> &RegistryHost {
        &self.registry
    }

    /// repository を返す。
    pub fn repository(&self) -> &Repository {
        &self.repository
    }

    /// tag または digest を返す。
    pub fn reference(&self) -> &Reference {
        &self.reference
    }
}

#[cfg(test)]
mod tests {
    /// OCI-7・REPAIR-12（#2500）: `Digest::sha256_of` が既知ベクタと一致し、`parse` を通る。
    #[test]
    fn oci7_digest_sha256_of_known_vectors() {
        let empty = Digest::sha256_of(b"");
        assert_eq!(
            empty.as_str(),
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        let abc = Digest::sha256_of(b"abc");
        assert_eq!(
            abc.as_str(),
            "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(Digest::parse(abc.as_str()).unwrap(), abc);
    }

    use super::*;

    const HEX: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn parts(s: &str) -> (String, String, String) {
        let r = ImageReference::parse(s).expect("parse");
        (
            r.registry().authority(),
            r.repository().to_string(),
            r.reference().as_str().to_string(),
        )
    }

    /// OCI-1: Docker Hub の正規化（ホスト省略・library 補完・latest 補完）。
    #[test]
    fn docker_hub_normalization() {
        assert_eq!(
            parts("alpine"),
            (
                "registry-1.docker.io".into(),
                "library/alpine".into(),
                "latest".into()
            )
        );
        assert_eq!(
            parts("docker.io/library/busybox:1.36"),
            (
                "registry-1.docker.io".into(),
                "library/busybox".into(),
                "1.36".into()
            )
        );
        assert_eq!(
            parts("index.docker.io/busybox"),
            (
                "registry-1.docker.io".into(),
                "library/busybox".into(),
                "latest".into()
            )
        );
        assert_eq!(
            parts("someuser/app:v2"),
            (
                "registry-1.docker.io".into(),
                "someuser/app".into(),
                "v2".into()
            )
        );
    }

    /// OCI-1: 文法上有効な長い連続ハイフンを受理する（全体の 255 バイト上限は別途検証される）。
    #[test]
    fn long_hyphen_run_is_accepted() {
        let name = format!("a{}b", "-".repeat(65));
        assert_eq!(Repository::parse(&name).expect("parse").as_str(), name);
    }

    /// OCI-1: 他レジストリ・digest 指定・localhost。
    #[test]
    fn other_registries_and_digest() {
        assert_eq!(
            parts(&format!("ghcr.io/org/repo@sha256:{HEX}")),
            ("ghcr.io".into(), "org/repo".into(), format!("sha256:{HEX}"))
        );
        assert_eq!(
            parts("localhost:5000/a/b:t"),
            ("localhost:5000".into(), "a/b".into(), "t".into())
        );
        // name:tag@digest は digest を優先する。
        assert_eq!(
            parts(&format!("ghcr.io/org/repo:v1@sha256:{HEX}")).2,
            format!("sha256:{HEX}")
        );
    }

    /// OCI-1・OWASP インジェクション: 不正な参照はすべて InvalidArgument。
    #[test]
    fn invalid_references_are_rejected() {
        let long_tag = format!("alpine:{}", "a".repeat(129));
        let long_all = "a".repeat(REFERENCE_MAX_BYTES + 1);
        let cases = [
            "".to_string(),
            "Alpine".to_string(),
            "ghcr.io/org/../repo".to_string(),
            "ghcr.io/org//repo".to_string(),
            "ghcr.io/./repo".to_string(),
            "user@host/repo".to_string(),
            "https://ghcr.io/org/repo".to_string(),
            "ghcr.io:0/org/repo".to_string(),
            "ghcr.io:65536/org/repo".to_string(),
            "ghcr.io:/org/repo".to_string(),
            format!("alpine@sha256:{HEX}0"),
            format!("alpine@sha256:{}", HEX.to_uppercase()),
            format!("alpine@sha512:{HEX}"),
            long_tag,
            long_all,
            "alpine\n".to_string(),
            "alpine tag".to_string(),
            "ghcr.io/org/repo-".to_string(),
            "ghcr.io/org/a___b".to_string(),
            "[::1]:5000/a".to_string(),
            "ghcr.io/org/a?x=1".to_string(),
        ];
        for c in cases {
            let e = ImageReference::parse(&c).expect_err(&c);
            assert_eq!(e.code(), OciErrorCode::InvalidArgument, "{c:?}");
        }
    }

    /// OCI-1: repository 成分規則の許可側（区切りの組み合わせ）。
    #[test]
    fn repository_separators() {
        for ok in ["a.b", "a_b", "a__b", "a-b", "a---b", "a/b-c.d/e__f", "a0"] {
            assert!(Repository::parse(ok).is_ok(), "{ok}");
        }
        for ng in ["a..b", "a._b", "-a", "a-", "a_-b", "a/", "/a", "a/./b"] {
            assert!(Repository::parse(ng).is_err(), "{ng}");
        }
    }
}
