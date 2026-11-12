//! core の `ContainerImageRefs` を oci の `ImageStore` で満たす plugin-cri 側のアダプタ
//! （OCI-7・CRI-2・PLUG-1・#2791。`unix` のみ）。
//!
//! # 役割と呼び出し元
//!
//! [`crate::adapter::CoreLifecycleRuntime`] の `create` が `oci_runtime::create_with_image[_audited]` へ、`delete` が
//! `delete_releasing_image_ref_with_options` へ渡す。core は oci に依存しない（`docs/architecture.md`）ため、両方に
//! 依存する plugin-cri が、トレイトの 5 メソッドを `ImageStore` の入口へ変換する。世代・確定・世代つき解除の原子性は
//! `ImageStore` の排他の内側にあり、ここでは ID・digest・世代・エラーの変換だけを行う。
//!
//! # 置き場所（暫定。REPAIR-3）
//!
//! CLI 側の対のアダプタ `fandhe-container-cli` の `commands::image_refs`（#2315）と式が同じ 2 つ目の実装である。
//! 置き場所のオーナー判断は #2315（`docs/design/image-store-adapter-placement.md`。承認待ち）で未取得で、既存の依存辺
//! （plugin-cri → oci・core）だけで足りる案 A を暫定で採った。判断で別 crate に決まったら `StoreImageRefs` を移して
//! 重複をなくす。重複によるキーの食い違い（他コンテナの参照を外す・外せない）は、共有 fixture
//! `crates/core/testdata/image_ref_key_cases.txt` を両 crate の単体試験が照合して抑える。
//!
//! # 参照キーの形式
//!
//! 新形式（SHA-256）のキーだけを書く。旧形式（FNV）と旧 scope の読み戻しは持たない（#2796。CRI の経路は旧版で
//! 参照を作ったことがない）。scope は開いた状態ストアの `host_state_root()` の SHA-256 の先頭 32 桁で、CLI の
//! `state_scope` と同じ規則。
//!
//! # config から manifest への解決
//!
//! 参照テーブルのキーは platform manifest の digest だが、CRI が持つのは image ID（config digest）である。
//! [`resolve_manifest`] が在庫を 1 回だけ排他して引き、`config == image ID` の manifest を探す。
//! 複数あれば digest の昇順で先頭を選ぶ（展開済み rootfs は image ID が鍵なので、どれを選んでも同じ。
//! `RemoveImage` 側は同じ config を持つ全 manifest の参照を見る）。無ければ `NotFound`（fail-closed）。
//!
//! # 残余（REPAIR-3）
//!
//! register の後・bind の前にクラッシュして残った未確定の参照と、delete が解除できずに残した確定済みの参照を
//! 後から回収する経路（CLI の `ref_reconcile` 相当）は、CRI 側には未実装（フォローアップ。#2791 の対象外）。
//! 残った参照は `RemoveImage` を拒否し続けうる（使用中として守る側に倒れる）。

use std::path::Path;

use fandhe_container_core::oci_runtime::{
    ContainerImageRefs, ImageManifestDigest, ImageRefGeneration, ImageRefRegistration,
    ImageRefRelease,
};
use fandhe_container_core::traits::{
    Annotations, ContainerId, CreateRequest, ErrorCode, StateStore, TraitError,
};
use fandhe_container_oci::error::{OciError, OciErrorCode};
use fandhe_container_oci::image_management::{
    ContainerRefGeneration, ContainerRefId, ContainerRefRegistration, ContainerRefRelease,
    ImageStore,
};
use fandhe_container_oci::reference::Digest;

/// create 時のイメージストア root を状態記録の annotations に残す予約キー（CLI の `IMAGE_ROOT_ANNOTATION` と同値）。
///
/// 値は `ImageStore::root()`。delete は値を信頼せず、設定済みの root を開いて一致を確かめる。
pub(crate) const IMAGE_ROOT_ANNOTATION: &str = "io.fandhe.container.image-root";

/// 参照キーの上限（`ContainerRefId` と同じ 255 バイト）。
const REF_KEY_MAX: usize = 255;

const MSG_NO_STATE_ROOT: &str = "the state store does not expose a host state root";
const MSG_IMAGE_ROOT_NOT_UTF8: &str = "image store root must be valid UTF-8";
const MSG_IMAGE_NOT_FOUND: &str = "image not found";
const MSG_LOCKED: &str = "image store is locked by another operation";
const MSG_REF_LIMIT: &str = "container reference limit exceeded";

/// `CreateContainer` の image ID（config digest）の検証。形式違反は `InvalidArgument`（値は信頼しない入力）。
pub(crate) fn parse_image_id(value: &str) -> Result<Digest, TraitError> {
    Digest::parse(value).map_err(|_| {
        TraitError::new(
            ErrorCode::InvalidArgument,
            "image id must be sha256:<64 lowercase hex>",
        )
    })
}

/// 状態ルートの識別子（参照キーの接頭辞）。CLI の `state_scope` と同じ規則（モジュール doc）。
pub(crate) fn state_scope(store: &dyn StateStore) -> Result<String, TraitError> {
    let root = store
        .host_state_root()
        .ok_or_else(|| TraitError::new(ErrorCode::FailedPrecondition, MSG_NO_STATE_ROOT))?;
    Ok(state_hash(root.as_os_str().as_encoded_bytes()))
}

/// パスのバイト列から scope の 32 桁 hex を作る。
fn state_hash(bytes: &[u8]) -> String {
    let full = sha256_hex(bytes);
    full.get(..32).map_or_else(|| full.clone(), str::to_owned)
}

/// SHA-256 の小文字 hex 64 桁（oci の `Digest::sha256_of` の `sha256:` を除く）。
fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Digest::sha256_of(bytes);
    let s = digest.as_str();
    s.strip_prefix("sha256:").unwrap_or(s).to_owned()
}

/// 状態ルートの `scope` とコンテナ ID から参照キーを作る。通常は `<scope>.<id>`、255 バイトを超えるなら
/// `<scope>-<id の SHA-256 の 64 桁>`（CLI の `ref_key` と同じ。結果は常に `[A-Za-z0-9._-]` かつ 255 バイト以下）。
pub(crate) fn ref_key(scope: &str, id: &str) -> String {
    let plain = format!("{scope}.{id}");
    if plain.len() <= REF_KEY_MAX {
        return plain;
    }
    format!("{scope}-{}", sha256_hex(id.as_bytes()))
}

/// oci の失敗を固定文言の `TraitError` へ写す。`OciError::message` は流さない（パス・digest・コンテナ ID を出さない）。
pub(crate) fn oci_failure(e: &OciError) -> TraitError {
    let (code, message) = match e.code() {
        OciErrorCode::NotFound => (ErrorCode::NotFound, MSG_IMAGE_NOT_FOUND),
        OciErrorCode::Timeout => (ErrorCode::Timeout, MSG_LOCKED),
        OciErrorCode::ResourceExhausted => (ErrorCode::ResourceExhausted, MSG_REF_LIMIT),
        OciErrorCode::InvalidArgument => (ErrorCode::InvalidArgument, "invalid argument"),
        OciErrorCode::AlreadyExists => (ErrorCode::AlreadyExists, "already exists"),
        OciErrorCode::FailedPrecondition => (ErrorCode::FailedPrecondition, "failed precondition"),
        OciErrorCode::PermissionDenied => (ErrorCode::PermissionDenied, "permission denied"),
        OciErrorCode::Unimplemented => {
            (ErrorCode::Unimplemented, "not implemented on this platform")
        }
        OciErrorCode::Unavailable => (ErrorCode::Unavailable, "unavailable"),
        _ => (ErrorCode::Internal, "operation failed"),
    };
    TraitError::new(code, message)
}

/// 在庫から `config == image_id` の manifest を 1 つ選ぶ（モジュール doc「config から manifest への解決」）。
///
/// 排他は 1 回だけ取り、ガードを手放してから返す（create ゲートや状態ストアの操作をまたいで保持しない。REPAIR-5）。
pub(crate) fn resolve_manifest(
    store: &ImageStore,
    image_id: &Digest,
) -> Result<ImageManifestDigest, TraitError> {
    let found: Option<String> = {
        let guard = store.lock().map_err(|e| oci_failure(&e))?;
        // `manifests()` は digest 昇順。先頭が決定的な選択になる。
        guard
            .manifests()
            .find(|(_, c)| c.config() == image_id)
            .map(|(d, _)| d.as_str().to_owned())
    };
    match found {
        Some(d) => ImageManifestDigest::new(&d),
        None => Err(TraitError::new(ErrorCode::NotFound, MSG_IMAGE_NOT_FOUND)),
    }
}

/// `req` の annotations に [`IMAGE_ROOT_ANNOTATION`] を足した要求を返す（同じキーの既存値は置き換える）。
///
/// UTF-8 にできない root と annotations の上限超過は `InvalidArgument` で失敗し、状態は作られない（fail-closed）。
pub(crate) fn attach_image_root(
    req: &CreateRequest,
    store: &ImageStore,
) -> Result<CreateRequest, TraitError> {
    let root = store
        .root()
        .to_str()
        .ok_or_else(|| TraitError::new(ErrorCode::InvalidArgument, MSG_IMAGE_ROOT_NOT_UTF8))?;
    let entries = req
        .annotations()
        .iter()
        .filter(|(k, _)| *k != IMAGE_ROOT_ANNOTATION)
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .chain(std::iter::once((
            IMAGE_ROOT_ANNOTATION.to_owned(),
            root.to_owned(),
        )));
    let annotations = Annotations::new(entries)?;
    Ok(req.clone().with_annotations(annotations))
}

/// 設定済みの在庫 root を開く（検査済み。期限は `timeout`）。失敗は固定文言。
pub(crate) fn open_image_store(
    root: &Path,
    timeout: std::time::Duration,
) -> Result<ImageStore, TraitError> {
    ImageStore::open(root)
        .map(|s| s.with_timeout(timeout))
        .map_err(|e| match e.code() {
            OciErrorCode::NotFound => {
                TraitError::new(ErrorCode::NotFound, "image store root not found")
            }
            OciErrorCode::FailedPrecondition => TraitError::new(
                ErrorCode::FailedPrecondition,
                "image store root is not a directory",
            ),
            _ => oci_failure(&e),
        })
}

/// `ImageStore` を借りて `ContainerImageRefs` を満たすアダプタ。参照キーは状態ルートごとに分ける。
pub(crate) struct StoreImageRefs<'a> {
    store: &'a ImageStore,
    scope: &'a str,
}

impl<'a> StoreImageRefs<'a> {
    /// `scope` は [`state_scope`] の戻り値（`[0-9a-f]` のみ）。
    pub(crate) fn new(store: &'a ImageStore, scope: &'a str) -> Self {
        Self { store, scope }
    }

    fn ref_id(&self, id: &ContainerId) -> Result<ContainerRefId, TraitError> {
        ContainerRefId::new(&ref_key(self.scope, id.as_str())).map_err(|e| oci_failure(&e))
    }
}

fn release_result(r: ContainerRefRelease) -> ImageRefRelease {
    match r {
        ContainerRefRelease::Released(_) => ImageRefRelease::Released,
        _ => ImageRefRelease::NotRegistered,
    }
}

impl ContainerImageRefs for StoreImageRefs<'_> {
    fn register(
        &self,
        id: &ContainerId,
        manifest: &ImageManifestDigest,
    ) -> Result<ImageRefRegistration, TraitError> {
        let id = self.ref_id(id)?;
        let digest = Digest::parse(manifest.as_str()).map_err(|e| oci_failure(&e))?;
        let r = self
            .store
            .register_container_ref(&id, &digest)
            .map_err(|e| oci_failure(&e))?;
        Ok(match r {
            ContainerRefRegistration::Registered => ImageRefRegistration::Registered,
            _ => ImageRefRegistration::AlreadyRegistered,
        })
    }

    fn release(&self, id: &ContainerId) -> Result<ImageRefRelease, TraitError> {
        let r = self
            .store
            .release_container_ref(&self.ref_id(id)?)
            .map_err(|e| oci_failure(&e))?;
        Ok(release_result(r))
    }

    fn bind(&self, id: &ContainerId) -> Result<ImageRefGeneration, TraitError> {
        let g = self
            .store
            .bind_container_ref(&self.ref_id(id)?)
            .map_err(|e| oci_failure(&e))?;
        Ok(ImageRefGeneration::from_raw(g.as_raw()))
    }

    fn registration(&self, id: &ContainerId) -> Result<Option<ImageRefGeneration>, TraitError> {
        let g = self
            .store
            .container_ref_registration(&self.ref_id(id)?)
            .map_err(|e| oci_failure(&e))?;
        Ok(g.map(|g| ImageRefGeneration::from_raw(g.as_raw())))
    }

    fn release_if(
        &self,
        id: &ContainerId,
        expected: ImageRefGeneration,
    ) -> Result<ImageRefRelease, TraitError> {
        let r = self
            .store
            .release_container_ref_if(
                &self.ref_id(id)?,
                ContainerRefGeneration::from_raw(expected.as_raw()),
            )
            .map_err(|e| oci_failure(&e))?;
        Ok(release_result(r))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `@rep:<1 文字>:<回数>` を繰り返しに展開する（共有 fixture の表記。CLI の試験と同じ規則）。
    fn expand_rep(field: &str) -> String {
        match field.split_once("@rep:") {
            None => field.to_owned(),
            Some((head, rest)) => {
                let (c, tail) = rest.split_once(':').expect("rep char");
                let digits: String = tail.chars().take_while(char::is_ascii_digit).collect();
                let n: usize = digits.parse().expect("rep count");
                let after = &tail[digits.len()..];
                format!("{head}{}{}", c.repeat(n), expand_rep(after))
            }
        }
    }

    /// OCI-7・CRI-2（#2791）: 参照キーの導出が共有 fixture（CLI の同名の試験と同じ表）の期待値と一致する。
    #[test]
    fn oci7_cri2_2791_ref_key_matches_shared_fixture() {
        let table = include_str!("../../core/testdata/image_ref_key_cases.txt");
        let (mut scopes, mut keys, mut anns) = (0, 0, 0);
        for line in table
            .lines()
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
        {
            let f: Vec<String> = line.split('\t').map(expand_rep).collect();
            match f.first().map(String::as_str) {
                Some("scope") => {
                    assert_eq!(state_hash(f[1].as_bytes()), f[2], "{line}");
                    scopes += 1;
                }
                Some("key") => {
                    assert_eq!(ref_key(&f[1], &f[2]), f[3], "{line}");
                    keys += 1;
                }
                Some("annotation") => {
                    assert_eq!(IMAGE_ROOT_ANNOTATION, f[1], "{line}");
                    anns += 1;
                }
                other => panic!("unknown fixture row {other:?}"),
            }
        }
        assert_eq!((scopes, keys, anns), (3, 3, 1));
    }

    /// OCI-7: image ID は小文字 hex 64 桁の sha256 だけを受け、それ以外は固定文言の `InvalidArgument`。
    #[test]
    fn oci7_cri2_2791_image_id_is_validated() {
        let good = format!("sha256:{}", "ab".repeat(32));
        assert!(parse_image_id(&good).is_ok());
        for bad in ["", "sha256:zz", "sha512:abc", "../etc", "sha256:ABCD"] {
            let err = parse_image_id(bad).expect_err(bad);
            assert_eq!(err.code(), ErrorCode::InvalidArgument, "{bad}");
            assert_eq!(err.message(), "image id must be sha256:<64 lowercase hex>");
        }
    }

    /// REPAIR-4: oci の失敗は固定文言に写り、元のメッセージ（パス等）を含まない。
    #[test]
    fn oci7_cri2_2791_oci_failure_uses_fixed_messages() {
        let e = OciError::new(
            OciErrorCode::NotFound,
            "manifest sha256:deadbeef not registered",
        );
        let t = oci_failure(&e);
        assert_eq!(
            (t.code(), t.message()),
            (ErrorCode::NotFound, "image not found")
        );
        let e = OciError::new(OciErrorCode::Timeout, "/secret/path");
        let t = oci_failure(&e);
        assert_eq!(
            (t.code(), t.message()),
            (
                ErrorCode::Timeout,
                "image store is locked by another operation"
            )
        );
    }
}
