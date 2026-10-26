//! core の `ContainerImageRefs` を oci の `ImageStore` で満たす本番アダプタ（OCI-7・TASK-183.8 追補・#2315）。
//!
//! # 役割と呼び出し元
//!
//! `create_start::run_create` が `create_with_image` へ、`stop_delete::run_delete` が
//! `delete_releasing_image_ref` へ渡す。core は oci に依存しない（`docs/architecture.md`）ため、両方に
//! 依存できる上位の cli がトレイトの 5 メソッドを `ImageStore` の入口へ変換する。世代・確定・世代つき解除の
//! 原子性は `ImageStore` の排他の内側にあり、ここでは ID・digest・世代・エラーの変換だけを行う。
//!
//! # 置き場所
//!
//! 置き場所のオーナー判断は #2315 で未取得で、既存の依存辺（`cli → oci`・`cli → core`）だけで足りる cli に
//! 暫定で置いた。判断で別 crate に決まったら、この module をそのまま移せる（外部へ公開する型は無い）。
//!
//! # 排他の契約
//!
//! 各呼び出しは `ImageStore` の期限つきの排他（`IMAGE_STORE_LOCK_TIMEOUT`）を内側で取り、返る前に解放する。
//! `StateStore` の操作や start の所有ロックをまたいで保持しない（REPAIR-5）。
//!
//! # 回収の契機と create ゲート（#854・#2495）
//!
//! 状態作成まで進まず未確定のまま残った参照、delete が解除できずに残した確定済み参照（記録を持たない古いコンテナを含む）の後追いの回収は、
//! `ref_reconcile` module が担う（契機 A: イメージつき create の core 呼び出し前に同じキー 1 件、契機 B: `image rm` が
//! 使用中で拒否したとき）。未確定参照の回収の前提「進行中の create が無いこと」は、oci の create ゲート
//! （`ImageStore::quiesce_container_creates`）で保証する。イメージつき create は `create_with_image` の呼び出し全体を
//! ゲートの共有（`ImageStore::enter_container_create`）で包む。本アダプタをゲートなしで `create_with_image` に渡す新しい
//! 呼び出し元（plugin 経由の配線等）を作るときは、同じ規約を守る。
//!
//! # 参照キーの形式と旧形式の扱い（#2500）
//!
//! `state_scope` と `ref_key` の畳み込みは SHA-256 にした（旧: 非暗号の FNV-1a 64 を 2 本）。旧形式のキーは移行しない。
//! 本番の `PullImage` は plugin-cri の ImageService（#2592）から在庫へ登録するが、CLI が `--image-root` に渡さない限り CLI のストアの在庫は空で `register` が `NOT_FOUND` のため、そのストアにコンテナ参照は無い。
//! 開発・試験環境に旧キーが残った場合、新コードから見て別の状態ルートのキーになり、delete は外さず契機 B は回収しない
//! （守りすぎの側に倒れる）。回復は、そのストアの `@container-refs.json` を消すかストアを作り直す。
//!
//! # 未実装（実装済みを装わない。REPAIR-3）
//!
//! - レイヤーの展開（本番の展開器）は #2377。展開器なしの `ContainerImage` を使うため、bundle の rootfs は展開済みの前提
//! - manifest の在庫の永続化は #2380 で oci 側に実装済み（`ImageStore::lock` が読み直す）。在庫を埋める経路は cri の
//!   `OciImagePuller::pull` に配線済み（#2539）で、本番の `PullImage` へも plugin-cri の ImageService（#2592）から届く。pull していない root では在庫が空で、`register` は `NOT_FOUND`
//! - `name@digest` 形式は受けない（在庫は manifest と repository を対応づけず、name を検証できないため fail-closed。#2496）
//!
//! # `create --image` の判別規則と解決（#2496・OCI-7・CLI-1）
//!
//! [`classify_create_image`]（ストアに触れない純関数）が次の順に判定する。
//!
//! 1. `/` も `@` も含まず、最初の `:` より前が digest のアルゴリズム名（`sha256`・`sha384`・`sha512`）の入力は digest の指定。
//!    `sha256:<小文字 hex 64 桁>` だけを受け、それ以外は `INVALID_ARGUMENT`（oci の `ImageReference::parse` が
//!    `sha256:AAAA…` を repository `sha256` のタグと誤読するため、先にここで拒否する）。
//!    この規則 1 は `image rm` / `image tag`（`image::parse_ref`）と [`is_bare_digest_form`] で共有する。`name@digest` の扱いだけは
//!    意図して異なり、rm / tag は既存契約（#2221・#2316）の digest 優先で受ける（理由と #2659 の再判断〔受け続ける〕は `image` module doc）。
//! 2. それ以外は oci の `ImageReference::parse`（Docker 互換の正規化。ホスト省略は `registry-1.docker.io`、単一成分は `library/`、
//!    タグ省略は `latest`）でタグ参照にする。repository 名が `sha256` のイメージは `docker.io/library/sha256:tag` と書けばよい。
//! 3. 解析に失敗する入力と `name@digest`・`name:tag@digest` は `INVALID_ARGUMENT`（素の digest で指定する。将来広げる余地はある）。
//!
//! タグは [`resolve_create_image`] が永続化済みの在庫から digest へ解決する（存在しなければ `NOT_FOUND`）。
//!
//! # 解決と登録のあいだの付け替え
//!
//! 解決はその時点のスナップショットで、create は解決した digest で参照を登録する。コンテナが保持するのはタグでなく manifest なので、
//! 解決後にタグが別の manifest へ付け替えられても、この create の登録先は変わらない（旧 manifest は参照で保護される）。
//! 解決後・登録前に旧 manifest が在庫から消えた場合は `register` が `NOT_FOUND`（`image not found`）で失敗し、状態も参照も残らない。
//! 解決から登録までを 1 つの排他区間にはしない（`register` は digest を受ける契約で、排他は呼び出しごとに取る。REPAIR-5）。

use fandhe_container_core::oci_runtime::{
    ContainerImageRefs, ImageManifestDigest, ImageRefGeneration, ImageRefRegistration,
    ImageRefRelease,
};
use fandhe_container_core::traits::{
    Annotations, ContainerId, CreateRequest, StateStore, TraitError,
};
use fandhe_container_oci::error::OciError;
use fandhe_container_oci::image_management::{
    ContainerRefGeneration, ContainerRefId, ContainerRefRegistration, ContainerRefRelease,
    ImageStore,
};
use fandhe_container_oci::reference::Digest;

use super::image::{MSG_TAG_NOT_FOUND, Stage, trait_failure};
use fandhe_container_core::traits::ErrorCode;
use fandhe_container_oci::image_management::TagKey;
use fandhe_container_oci::reference::{ImageReference, Reference};

/// `create --image` の判別結果（#2496）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum CreateImageRef {
    /// manifest digest の指定。
    Manifest(ImageManifestDigest),
    /// タグ参照（正規化済み）。
    Tag(TagKey),
}

const MSG_BAD_IMAGE: &str = "image must be a sha256 manifest digest or a tag reference";

/// digest に見える入力（`/` も `@` も含まず、最初の `:` より前が digest のアルゴリズム名）か。
/// `create --image` と `image rm` / `image tag` が共有する判別規則 1 の述語（ストアにも環境にも触れない）。
pub(super) fn is_bare_digest_form(input: &str) -> bool {
    !input.contains(['/', '@'])
        && input
            .split_once(':')
            .is_some_and(|(algo, _)| matches!(algo, "sha256" | "sha384" | "sha512"))
}

/// `--image` の値を digest かタグ参照かに判別する（規則は module doc。ストアにも環境にも触れない純関数）。
/// 外部入力なので `unwrap`・添字は使わず、エラー文言は固定（入力を含めない）。
pub(super) fn classify_create_image(input: &str) -> Result<CreateImageRef, TraitError> {
    let bad = || TraitError::new(ErrorCode::InvalidArgument, MSG_BAD_IMAGE);
    if is_bare_digest_form(input) {
        return ImageManifestDigest::new(input).map(CreateImageRef::Manifest);
    }
    let r = ImageReference::parse(input).map_err(|_| bad())?;
    match r.reference() {
        Reference::Tag(t) => Ok(CreateImageRef::Tag(TagKey::new(
            r.registry().clone(),
            r.repository().clone(),
            t.clone(),
        ))),
        _ => Err(bad()),
    }
}

/// 判別結果を manifest digest にする。タグは排他を 1 回だけ取って永続化済みの対応表から引き、ガードを手放してから返す
/// （create ゲートや状態ストアの操作をまたいで保持しない。走査はタグ件数の上限で抑えられる。REPAIR-5）。
/// 付け替え競合の扱いは module doc。
pub(super) fn resolve_create_image(
    store: &ImageStore,
    r: CreateImageRef,
) -> Result<ImageManifestDigest, TraitError> {
    let key = match r {
        CreateImageRef::Manifest(d) => return Ok(d),
        CreateImageRef::Tag(k) => k,
    };
    let found: Option<String> = {
        let guard = store
            .lock()
            .map_err(|e| trait_failure(&e, Stage::Resolve))?;
        guard
            .tags()
            .find(|(k, _)| **k == key)
            .map(|(_, d)| d.as_str().to_string())
    };
    match found {
        Some(d) => ImageManifestDigest::new(&d),
        None => Err(TraitError::new(ErrorCode::NotFound, MSG_TAG_NOT_FOUND)),
    }
}

/// 状態ルートの識別子（参照キーの接頭辞）を作る。
///
/// イメージストアは状態ルートをまたいで共有できる（`--root` と `--image-root` は独立）。参照キーが
/// `ContainerId` だけだと、別の状態ルートの同名コンテナの delete が他方の参照を外してしまう（OCI-7 の
/// 使用中イメージ保護の欠落）。そこで正規化済みの状態ルートのパスの SHA-256 の先頭 32 桁（128 bit の
/// 小文字 hex）を作り、キーを `<hex>.<id>` にする。入力は利用者が選ぶパスで、脅威は他人の scope への
/// 第 2 原像のため 128 bit で足りる（core の `scope_of` と同じ切り詰め。#2500・REPAIR-12）。
///
/// 入力は「開いた状態ストアの `host_state_root()`」（`FileStateStore::open` が親の symlink を解決して固定した
/// 正規パス）で、`--root` の表記（`//`・末尾 `/`・祖先の symlink）が create と delete で違っても同じ scope になる
/// （#2499 P2-2）。字面だけを畳んで存在しないパスを許す経路は作らない。大文字小文字を区別しない FS の同一視は
/// 範囲外（ローカル経路は Linux のみ）。
pub(super) fn state_scope(store: &dyn StateStore) -> Result<String, TraitError> {
    let root = store
        .host_state_root()
        .ok_or_else(|| TraitError::new(ErrorCode::FailedPrecondition, MSG_NO_STATE_ROOT))?;
    Ok(state_hash(root.as_os_str().as_encoded_bytes()))
}

/// 旧版の scope（`--root` の字面から決めた状態ルートのハッシュ）を、新しい scope と違うときだけ返す（#2499・OCI-7）。
///
/// 旧版は `StateRoot::resolve(--root)` の字面をハッシュしていた。現行は開いたストアの `host_state_root()`
/// （祖先の symlink を解決した正規パス）を使うため、`--root` に symlink を含む表記で作ったコンテナの参照は旧 scope の
/// キーで残っている。旧 scope のキーは新規には作らず、delete の解除・create 前の回収・`image rm` の照合・停止中の判定だけで
/// 読み戻す（既存の参照が回収不能になる退行を避ける互換処理）。解決できない・新 scope と同じなら `None`。
pub(super) fn legacy_scope(
    override_root: Option<std::path::PathBuf>,
    current: &str,
) -> Option<String> {
    let root = fandhe_container_core::state_store::StateRoot::resolve(override_root).ok()?;
    let legacy = state_hash(root.path().as_os_str().as_encoded_bytes());
    (legacy != current).then_some(legacy)
}

const MSG_NO_STATE_ROOT: &str = "the state store does not expose a host state root";

/// create 時のイメージストア root を状態記録の annotations に残す予約キー（#2499・OCI-7・CLI-1）。
///
/// 値は `ImageStore::root()`（検査済みの正規パス）。`--image-root` を省いた delete が、この記録のストアを開いて
/// 参照を解除する。利用者の `--label` では書けない（`create_options::labels_of` が拒否する）。分離・権限の
/// 判断には使わず、delete 側も値を信頼せず `ImageStore::open` の検査と開いた root との一致で確かめる。
pub(super) const IMAGE_ROOT_ANNOTATION: &str = "io.fandhe.container.image-root";

const MSG_IMAGE_ROOT_NOT_UTF8: &str = "image store root must be valid UTF-8";

/// `req` の annotations に [`IMAGE_ROOT_ANNOTATION`] を足した要求を返す（同じキーの既存値は置き換える）。
///
/// UTF-8 にできない root と、annotations の上限（`Annotations::new` の判定）を超える場合は
/// `INVALID_ARGUMENT` で失敗し、状態は作られない（fail-closed）。
pub(super) fn attach_image_root(
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

/// パスのバイト列から scope の 32 桁 hex を作る（[`state_scope`]・[`legacy_scope`] で共有）。
fn state_hash(bytes: &[u8]) -> String {
    let full = sha256_hex(bytes);
    full.get(..32).map_or_else(|| full.clone(), str::to_owned)
}

/// SHA-256 の小文字 hex 64 桁。oci の `Digest::sha256_of`（`sha256:` + 64 桁の不変条件）を使う。
fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Digest::sha256_of(bytes);
    let s = digest.as_str();
    s.strip_prefix("sha256:").unwrap_or(s).to_owned()
}

/// `ImageStore` を借りて `ContainerImageRefs` を満たすアダプタ。参照キーは状態ルートごとに分ける。
pub(super) struct StoreImageRefs<'a> {
    store: &'a ImageStore,
    scope: &'a str,
}

impl<'a> StoreImageRefs<'a> {
    /// `scope` は [`state_scope`] の戻り値（`[0-9a-f]` のみ）。
    pub(super) fn new(store: &'a ImageStore, scope: &'a str) -> Self {
        Self { store, scope }
    }

    fn ref_id(&self, id: &ContainerId) -> Result<ContainerRefId, TraitError> {
        ContainerRefId::new(&ref_key(self.scope, id.as_str())).map_err(fail)
    }
}

/// 参照キーの上限（`ContainerRefId` と同じ 255 バイト）。
const REF_KEY_MAX: usize = 255;

/// 状態ルートの `scope` とコンテナ ID から参照キーを作る（create / delete / 停止中スナップショットで共有）。
///
/// 通常は `<scope>.<id>`。接頭辞を足すと 255 バイトを超える長い ID（223 バイト以上）は
/// `<scope>-<id の SHA-256 の 64 桁 hex>`（256 bit。ID は攻撃者が選べる入力のため衝突耐性 2^128 を取る。
/// 非暗号の FNV からの置き換え。#2500・OCI-7）に畳む。区切りが `.` と `-` で違うため、通常形と畳んだ形は衝突しない。
/// 結果は常に `[A-Za-z0-9._-]` かつ 255 バイト以下で、変換は失敗しない。
pub(super) fn ref_key(scope: &str, id: &str) -> String {
    let plain = format!("{scope}.{id}");
    if plain.len() <= REF_KEY_MAX {
        return plain;
    }
    format!("{scope}-{}", sha256_hex(id.as_bytes()))
}

pub(super) fn fail(e: OciError) -> TraitError {
    trait_failure(&e, Stage::Refs)
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
        let digest = Digest::parse(manifest.as_str()).map_err(fail)?;
        let r = self
            .store
            .register_container_ref(&id, &digest)
            .map_err(fail)?;
        Ok(match r {
            ContainerRefRegistration::Registered => ImageRefRegistration::Registered,
            _ => ImageRefRegistration::AlreadyRegistered,
        })
    }

    fn release(&self, id: &ContainerId) -> Result<ImageRefRelease, TraitError> {
        let r = self
            .store
            .release_container_ref(&self.ref_id(id)?)
            .map_err(fail)?;
        Ok(release_result(r))
    }

    fn bind(&self, id: &ContainerId) -> Result<ImageRefGeneration, TraitError> {
        let g = self
            .store
            .bind_container_ref(&self.ref_id(id)?)
            .map_err(fail)?;
        Ok(ImageRefGeneration::from_raw(g.as_raw()))
    }

    fn registration(&self, id: &ContainerId) -> Result<Option<ImageRefGeneration>, TraitError> {
        let g = self
            .store
            .container_ref_registration(&self.ref_id(id)?)
            .map_err(fail)?;
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
            .map_err(fail)?;
        Ok(release_result(r))
    }
}

#[cfg(test)]
mod tests {
    /// OCI-7・CLI-1（#2600）: digest 風入力の述語（create と rm / tag が共有）。
    #[test]
    fn oci7_is_bare_digest_form() {
        for t in ["sha256:x", "sha512:x", "sha384:x", "sha256:", "sha256:AAAA"] {
            assert!(is_bare_digest_form(t), "{t}");
        }
        for t in [
            "sha1:x",
            "sha256",
            "a/sha256:x",
            "x@sha256:y",
            "docker.io/library/sha256:v1",
            "busybox:v2",
        ] {
            assert!(!is_bare_digest_form(t), "{t}");
        }
    }

    use super::*;
    use fandhe_container_core::traits::ErrorCode;
    use fandhe_container_oci::image_management::ManifestComposition;

    const MANIFEST: &str =
        "sha256:a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0";
    const OTHER: &str = "sha256:b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1";
    const SCOPE: &str = "00000000000000000000000000000001";
    const CONFIG: &str = "sha256:c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1";

    /// 一意な一時ディレクトリ（終了時に削除）。
    pub(crate) struct Tmp(std::path::PathBuf);

    impl Tmp {
        pub(crate) fn new(name: &str) -> Self {
            let dir = std::env::temp_dir()
                .join(format!("fandhe-cli-imgrefs-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).expect("dir");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
                    .expect("chmod");
            }
            Self(dir)
        }
        pub(crate) fn path(&self) -> &std::path::Path {
            &self.0
        }
    }

    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// 在庫に manifest を登録済みのストアを作る。
    fn seeded(root: &std::path::Path, manifests: &[&str]) -> ImageStore {
        let store = ImageStore::open(root).expect("open");
        for m in manifests {
            store
                .lock()
                .expect("lock")
                .register_manifest(
                    Digest::parse(m).expect("digest"),
                    ManifestComposition::new(Digest::parse(CONFIG).expect("config"), vec![])
                        .expect("comp"),
                )
                .expect("register manifest");
        }
        store
    }

    fn cid(s: &str) -> ContainerId {
        ContainerId::new(s).expect("id")
    }

    fn mdigest(s: &str) -> ImageManifestDigest {
        ImageManifestDigest::new(s).expect("manifest")
    }

    /// OCI-7: register の結果（新規・同一 manifest の再登録・別 manifest・在庫外）。
    #[test]
    fn oci7_register_outcomes() {
        let tmp = Tmp::new("register");
        let store = seeded(tmp.path(), &[MANIFEST, OTHER]);
        let refs = StoreImageRefs::new(&store, SCOPE);
        assert_eq!(
            refs.register(&cid("c1"), &mdigest(MANIFEST)).expect("new"),
            ImageRefRegistration::Registered
        );
        assert_eq!(
            refs.register(&cid("c1"), &mdigest(MANIFEST))
                .expect("again"),
            ImageRefRegistration::AlreadyRegistered
        );
        let err = refs
            .register(&cid("c1"), &mdigest(OTHER))
            .expect_err("different manifest");
        assert_eq!(err.code(), ErrorCode::AlreadyExists);
        let missing = "sha256:d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2";
        let err = refs
            .register(&cid("c2"), &mdigest(missing))
            .expect_err("not in inventory");
        assert_eq!(err.code(), ErrorCode::NotFound);
        assert_eq!(err.message(), "image not found");
    }

    /// OCI-7: registration は bind 前が None、bind 後が Some(世代)。
    #[test]
    fn oci7_registration_is_none_until_bound() {
        let tmp = Tmp::new("bind");
        let store = seeded(tmp.path(), &[MANIFEST]);
        let refs = StoreImageRefs::new(&store, SCOPE);
        refs.register(&cid("c1"), &mdigest(MANIFEST))
            .expect("register");
        assert_eq!(refs.registration(&cid("c1")).expect("unbound"), None);
        let g = refs.bind(&cid("c1")).expect("bind");
        assert_eq!(refs.registration(&cid("c1")).expect("bound"), Some(g));
    }

    /// OCI-7: release_if は世代違いで外さず、一致で外す。外して登録し直すと世代は変わる。
    #[test]
    fn oci7_release_if_checks_generation_and_never_reissues() {
        let tmp = Tmp::new("gen");
        let store = seeded(tmp.path(), &[MANIFEST]);
        let refs = StoreImageRefs::new(&store, SCOPE);
        refs.register(&cid("c1"), &mdigest(MANIFEST))
            .expect("register");
        let g1 = refs.bind(&cid("c1")).expect("bind");
        let wrong = ImageRefGeneration::from_raw(g1.as_raw() + 1000);
        assert_eq!(
            refs.release_if(&cid("c1"), wrong).expect("wrong"),
            ImageRefRelease::NotRegistered
        );
        assert_eq!(refs.registration(&cid("c1")).expect("kept"), Some(g1));
        assert_eq!(
            refs.release_if(&cid("c1"), g1).expect("match"),
            ImageRefRelease::Released
        );
        assert_eq!(refs.registration(&cid("c1")).expect("gone"), None);

        refs.register(&cid("c1"), &mdigest(MANIFEST))
            .expect("re-register");
        let g2 = refs.bind(&cid("c1")).expect("bind again");
        assert_ne!(g1, g2);
        assert_eq!(
            refs.release(&cid("c1")).expect("release"),
            ImageRefRelease::Released
        );
        assert_eq!(
            refs.release(&cid("c1")).expect("twice"),
            ImageRefRelease::NotRegistered
        );
    }

    /// OCI-7: 状態ルートが違えば同じコンテナ ID でも参照は別物で、他方の delete は外さない。
    #[test]
    fn oci7_refs_are_scoped_per_state_root() {
        let tmp = Tmp::new("scope");
        let store = seeded(tmp.path(), &[MANIFEST]);
        let a = StoreImageRefs::new(&store, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let b = StoreImageRefs::new(&store, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
        a.register(&cid("c1"), &mdigest(MANIFEST)).expect("a");
        let g = a.bind(&cid("c1")).expect("bind");
        assert_eq!(b.registration(&cid("c1")).expect("b none"), None);
        assert_eq!(
            b.release(&cid("c1")).expect("b release"),
            ImageRefRelease::NotRegistered
        );
        assert_eq!(a.registration(&cid("c1")).expect("kept"), Some(g));
    }

    /// OCI-7: 223 バイト以上・255 バイトの長い ID も register / bind / release が通り、別 ID と混ざらない。
    #[test]
    fn oci7_long_ids_round_trip() {
        let tmp = Tmp::new("long");
        let store = seeded(tmp.path(), &[MANIFEST]);
        let refs = StoreImageRefs::new(&store, SCOPE);
        for len in [222usize, 223, 254, 255] {
            let a = cid(&"a".repeat(len));
            let b = cid(&format!("{}b", "a".repeat(len - 1)));
            refs.register(&a, &mdigest(MANIFEST)).expect("register");
            let g = refs.bind(&a).expect("bind");
            assert_eq!(refs.registration(&a).expect("reg"), Some(g));
            assert_eq!(refs.registration(&b).expect("other"), None);
            assert_eq!(
                refs.release(&a).expect("release"),
                ImageRefRelease::Released
            );
        }
        assert!(ref_key(SCOPE, &"a".repeat(255)).len() <= 255);
        assert_ne!(
            ref_key(SCOPE, &"a".repeat(255)),
            ref_key(SCOPE, &"a".repeat(254))
        );
    }

    /// OCI-7: 状態ルートの識別子は決定的で、ルートが違えば変わり、キー全体が ID の上限に収まる。
    #[cfg(unix)]
    #[test]
    fn oci7_state_scope_is_deterministic_and_distinct() {
        use fandhe_container_core::state_store::{FileStateStore, StateRoot};
        let tmp = Tmp::new("scope-distinct");
        let open = |name: &str| {
            FileStateStore::open(StateRoot::from_override(tmp.path().join(name)).expect("root"))
                .expect("open")
        };
        let (a, b) = (open("a"), open("b"));
        assert_eq!(state_scope(&a).expect("a"), state_scope(&a).expect("a"));
        assert_ne!(state_scope(&a).expect("a"), state_scope(&b).expect("b"));
        assert_eq!(state_scope(&a).expect("a").len(), 32);
    }

    /// OCI-7・#2499（P2-2）: `//`・末尾 `/`・祖先の symlink のどの表記で開いても scope は同じになる。
    #[cfg(unix)]
    #[test]
    fn oci7_state_scope_is_stable_across_root_spellings() {
        use fandhe_container_core::state_store::{FileStateStore, StateRoot};
        let tmp = Tmp::new("scope-spellings");
        let real = tmp.path().join("real");
        std::fs::create_dir_all(&real).expect("real");
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        }
        std::os::unix::fs::symlink(&real, tmp.path().join("link")).expect("symlink");
        let scope = |root: std::path::PathBuf| {
            let store =
                FileStateStore::open(StateRoot::from_override(root).expect("root")).expect("open");
            state_scope(&store).expect("scope")
        };
        let via_link = scope(tmp.path().join("link").join("state"));
        let double_slash = scope(std::path::PathBuf::from(format!(
            "{}//state",
            real.display()
        )));
        let trailing = scope(std::path::PathBuf::from(format!(
            "{}/state/",
            real.display()
        )));
        assert_eq!(via_link, double_slash);
        assert_eq!(via_link, trailing);
        assert_eq!(via_link.len(), 32);
    }

    /// OCI-7・#2499: 状態ルートを示せないストアの scope は固定文言の `FAILED_PRECONDITION`。
    #[test]
    fn oci7_state_scope_without_host_root_fails_closed() {
        struct NoRoot;
        impl StateStore for NoRoot {
            fn create(
                &self,
                _: &fandhe_container_core::traits::CreateStateRequest,
            ) -> Result<fandhe_container_core::traits::StateRecord, TraitError> {
                Err(TraitError::new(ErrorCode::Unimplemented, "unused"))
            }
            fn get(
                &self,
                _: &fandhe_container_core::traits::GetStateRequest,
            ) -> Result<fandhe_container_core::traits::StateRecord, TraitError> {
                Err(TraitError::new(ErrorCode::Unimplemented, "unused"))
            }
            fn update(
                &self,
                _: &fandhe_container_core::traits::UpdateStateRequest,
            ) -> Result<fandhe_container_core::traits::StateRecord, TraitError> {
                Err(TraitError::new(ErrorCode::Unimplemented, "unused"))
            }
            fn list(
                &self,
                _: &fandhe_container_core::traits::ListStateRequest,
            ) -> Result<fandhe_container_core::traits::StateList, TraitError> {
                Err(TraitError::new(ErrorCode::Unimplemented, "unused"))
            }
            fn delete(
                &self,
                _: &fandhe_container_core::traits::DeleteStateRequest,
            ) -> Result<fandhe_container_core::traits::DeleteStateResponse, TraitError>
            {
                Err(TraitError::new(ErrorCode::Unimplemented, "unused"))
            }
        }
        let e = state_scope(&NoRoot).expect_err("no root");
        assert_eq!(e.code(), ErrorCode::FailedPrecondition);
        assert_eq!(e.message(), MSG_NO_STATE_ROOT);
    }

    /// OCI-7・#2499: create の要求にイメージストア root の記録が足され、既存の label は残り、同じキーは置き換わる。
    #[cfg(unix)]
    #[test]
    fn oci7_attach_image_root_adds_the_recorded_root() {
        let tmp = Tmp::new("attach-root");
        let store = ImageStore::open(tmp.path()).expect("open");
        let base = CreateRequest::new(
            ContainerId::new("c1").expect("id"),
            std::env::temp_dir().join("bundle"),
        )
        .expect("req")
        .with_annotations(
            Annotations::new([
                ("k".to_string(), "v".to_string()),
                (IMAGE_ROOT_ANNOTATION.to_string(), "/stale".to_string()),
            ])
            .expect("ann"),
        );
        let req = attach_image_root(&base, &store).expect("attach");
        assert_eq!(req.annotations().get("k"), Some("v"));
        assert_eq!(
            req.annotations().get(IMAGE_ROOT_ANNOTATION),
            store.root().to_str()
        );
    }

    /// OCI-7・#2499: root の記録を足すと annotations の合計上限を超える場合は `INVALID_ARGUMENT` で、状態を作る前に失敗する。
    /// 上限ちょうどまでは通る。
    ///
    /// 上限を超える長さの root を実ディレクトリで作ると macOS の PATH_MAX（1024）に当たるため、既存の
    /// annotations で残りの予算を埋めて境界を作る（3 OS で同じ判定を照合する。#2794）。
    #[cfg(unix)]
    #[test]
    fn oci7_attach_image_root_rejects_oversized_root() {
        use fandhe_container_core::traits::ANNOTATIONS_MAX_TOTAL_BYTES;
        let tmp = Tmp::new("attach-long");
        let store = ImageStore::open(tmp.path()).expect("open");
        let root_len = store.root().to_str().expect("utf-8").len();
        // 記録 1 件ぶん（キー + root）を足すと合計がちょうど上限になる既存 annotations の値の長さ。
        let fill = ANNOTATIONS_MAX_TOTAL_BYTES - IMAGE_ROOT_ANNOTATION.len() - root_len - "k".len();
        let with_value_len = |len: usize| {
            CreateRequest::new(
                ContainerId::new("c1").expect("id"),
                std::env::temp_dir().join("bundle"),
            )
            .expect("req")
            .with_annotations(Annotations::new([("k".to_string(), "v".repeat(len))]).expect("ann"))
        };
        let req = attach_image_root(&with_value_len(fill), &store).expect("at limit");
        assert_eq!(
            req.annotations().get(IMAGE_ROOT_ANNOTATION),
            store.root().to_str()
        );
        let e = attach_image_root(&with_value_len(fill + 1), &store).expect_err("too large");
        assert_eq!(e.code(), ErrorCode::InvalidArgument);
    }

    /// OCI-7・REPAIR-12（#2500）: 畳んだ参照キーは SHA-256 の具体値と一致する。
    #[test]
    fn oci7_ref_key_sha256_known_vector() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            ref_key(SCOPE, &"a".repeat(255)),
            format!("{SCOPE}-b0f3323e7a3cad8ae6778340cc2a17ae0cb31c818df3767cda7c3dd423725e90")
        );
    }

    /// OCI-7・REPAIR-12（#2500）: scope は状態ルートのパスの SHA-256 の先頭 32 桁。
    #[cfg(unix)]
    #[test]
    fn oci7_state_scope_is_sha256_prefix() {
        let tmp = Tmp::new("scope");
        let path = tmp.path().join("state");
        let bytes = path.as_os_str().as_encoded_bytes();
        assert_eq!(state_hash(bytes), sha256_hex(bytes)[..32]);
        assert_eq!(state_hash(b"/x/state"), "165fe1065cc95b4bb8e93c5a50ba3276");
    }

    /// OCI-7・REPAIR-12（#2500）: キーは常に `[A-Za-z0-9._-]` かつ 255 バイト以下。
    #[test]
    fn oci7_ref_key_charset_and_length() {
        for len in [1usize, 222, 223, 254, 255] {
            let id = "a".repeat(len);
            let k = ref_key(SCOPE, &id);
            assert!(k.len() <= 255, "{len}");
            assert!(
                k.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-')),
                "{len}"
            );
            if len <= 222 {
                assert_eq!(k, format!("{SCOPE}.{id}"));
            } else {
                assert!(k.starts_with(&format!("{SCOPE}-")), "{len}");
                let h = &k[SCOPE.len() + 1..];
                assert_eq!(h.len(), 64);
                assert!(h.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')));
                assert_eq!(k.len(), 97);
            }
        }
    }

    /// OCI-7・REPAIR-12（#2500・P2-3）: 長い別 ID の release / release_if は他方の確定済み参照を外さない。
    #[test]
    fn oci7_long_id_delete_does_not_release_other() {
        let tmp = Tmp::new("longdel");
        let store = seeded(tmp.path(), &[MANIFEST]);
        let refs = StoreImageRefs::new(&store, SCOPE);
        let base = |n: usize| "a".repeat(n);
        let pairs = [
            (format!("{}x", base(222)), format!("{}y", base(222))),
            (format!("{}x", base(253)), format!("{}y", base(253))),
            (format!("{}x", base(254)), format!("{}y", base(254))),
            (format!("{}xy", base(221)), format!("{}yx", base(221))),
            (base(223), base(224)),
        ];
        for (x, y) in pairs {
            let (a, b) = (cid(&x), cid(&y));
            refs.register(&a, &mdigest(MANIFEST)).expect("reg a");
            let ga = refs.bind(&a).expect("bind a");
            refs.register(&b, &mdigest(MANIFEST)).expect("reg b");
            let gb = refs.bind(&b).expect("bind b");
            assert_eq!(
                refs.release(&b).expect("release b"),
                ImageRefRelease::Released
            );
            assert_eq!(refs.registration(&a).expect("a"), Some(ga));
            assert_eq!(refs.registration(&b).expect("b"), None);
            let _ = gb;
            assert_eq!(
                refs.release(&a).expect("release a"),
                ImageRefRelease::Released
            );
        }
    }

    /// REPAIR-4・OCI-7: エラーの message は固定文言だけで、ID・パスを含まない。
    #[test]
    fn oci7_error_messages_are_fixed_strings() {
        let tmp = Tmp::new("msg");
        let store = seeded(tmp.path(), &[]);
        let refs = StoreImageRefs::new(&store, SCOPE);
        let id = cid("secret-container-id");
        let err = refs
            .register(&id, &mdigest(MANIFEST))
            .expect_err("not found");
        assert_eq!(err.message(), "image not found");
        let root = tmp.path().to_string_lossy().into_owned();
        assert!(!err.message().contains("secret-container-id"));
        assert!(!err.message().contains(&root));
        let err = refs.bind(&id).expect_err("no registration");
        assert!(!err.message().contains("secret-container-id"));
        assert!(!err.message().contains(&root));
    }

    const TAG_MSG: &str = "image must be a sha256 manifest digest or a tag reference";

    fn tag_key(host: &str, repo: &str, tag: &str) -> TagKey {
        TagKey::new(
            fandhe_container_oci::reference::RegistryHost::parse(host).expect("host"),
            fandhe_container_oci::reference::Repository::parse(repo).expect("repo"),
            fandhe_container_oci::reference::Tag::parse(tag).expect("tag"),
        )
    }

    /// OCI-7・CLI-1: digest とタグ参照の判別規則（#2496）。
    #[test]
    fn oci7_classify_create_image() {
        assert_eq!(
            classify_create_image(MANIFEST).expect("digest"),
            CreateImageRef::Manifest(mdigest(MANIFEST))
        );
        for (input, host, repo, tag) in [
            (
                "alpine:3.19",
                "registry-1.docker.io",
                "library/alpine",
                "3.19",
            ),
            ("alpine", "registry-1.docker.io", "library/alpine", "latest"),
            (
                "registry.example:5000/lib/app:v1",
                "registry.example:5000",
                "lib/app",
                "v1",
            ),
            (
                "docker.io/library/sha256:v1",
                "registry-1.docker.io",
                "library/sha256",
                "v1",
            ),
        ] {
            assert_eq!(
                classify_create_image(input).expect(input),
                CreateImageRef::Tag(tag_key(host, repo, tag)),
                "{input}"
            );
        }
        let upper = format!("sha256:{}", "A".repeat(64));
        let short = &MANIFEST[..MANIFEST.len() - 1];
        let sha512 = format!("sha512:{}", "a".repeat(128));
        let sha384 = format!("sha384:{}", "a".repeat(96));
        let at = format!("alpine@{MANIFEST}");
        let tag_at = format!("app:tag@{MANIFEST}");
        for bad in [
            upper.as_str(),
            short,
            sha512.as_str(),
            sha384.as_str(),
            "",
            at.as_str(),
            tag_at.as_str(),
            "has space:x",
            "UPPER/x:y",
        ] {
            let e = classify_create_image(bad).expect_err(bad);
            assert_eq!(e.code(), ErrorCode::InvalidArgument, "{bad}");
            assert!(
                e.message() == TAG_MSG
                    || e.message() == "manifest digest must be sha256:<64 lowercase hex>",
                "{bad}: {}",
                e.message()
            );
            if !bad.is_empty() {
                assert!(!e.message().contains(bad), "{bad}");
            }
        }
    }

    /// OCI-7・CLI-1: 永続化済みのタグを、別に開いたストアから digest へ解決できる。無いタグは NOT_FOUND（#2496）。
    #[cfg(unix)]
    #[test]
    fn oci7_resolve_tag_from_persisted_inventory() {
        let tmp = Tmp::new("resolve");
        let a = seeded(tmp.path(), &[MANIFEST, OTHER]);
        use fandhe_container_oci::image_management::ImageTagSource;
        a.tag_image(
            &ImageTagSource::Manifest(Digest::parse(MANIFEST).expect("d")),
            tag_key("registry.example", "lib/app", "v1"),
        )
        .expect("tag");
        let b = ImageStore::open(tmp.path()).expect("open b");
        let got = resolve_create_image(
            &b,
            classify_create_image("registry.example/lib/app:v1").expect("c"),
        )
        .expect("resolve");
        assert_eq!(got.as_str(), MANIFEST);
        let e = resolve_create_image(
            &b,
            classify_create_image("registry.example/lib/app:v2").expect("c"),
        )
        .expect_err("nf");
        assert_eq!(e.code(), ErrorCode::NotFound);
        assert_eq!(e.message(), "image tag not found");
        // digest 指定は在庫を引かずそのまま返す。
        let d = resolve_create_image(&b, CreateImageRef::Manifest(mdigest(OTHER))).expect("d");
        assert_eq!(d.as_str(), OTHER);
    }
}
