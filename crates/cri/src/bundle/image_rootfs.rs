//! 本番の [`RootfsSource`]: pull 済みイメージを bundle の `rootfs/` へ展開し、イメージ config の既定値を返す
//! （CRI-2・OCI-1・OCI-4・OCI-7・SEC-1・SEC-5・REPAIR-2・REPAIR-5。#2433）。
//!
//! 呼び出し元: [`super::SpecBundleProvider`] の `prepare`（`CreateContainer` の worker スレッド上）が `prepare` を、
//! Create の巻き戻しと `RemoveContainer` が `release` を呼ぶ。返した [`ImageDefaults`] は
//! [`super::build_runtime_config`] が `config.json` へ合成する。キャッシュを作る側は [`crate::image_pull`]
//! （`PullImage`）で、本モジュールはそのキャッシュを**読むだけ**で書き換えない。
//!
//! # rootfs の用意（A5・OCI-7・SEC-1）
//!
//! `PullImage` が公開した展開済み rootfs（`<cache>/rootfs/sha256/<hex>/rootfs`）はコンテナの rootfs として直接使わない
//! （コンテナの書き込みがキャッシュと次回以降の create に届くため）。ここでは公開済みエントリを「pull が検証を完了した」
//! 印と展開記録（`unpack-record`）の置き場としてだけ読み、**キャッシュの検証済み layer blob から bundle の `rootfs/` へ
//! 再展開**する（コンテナごとの私有の木ができる。複製の一形態）。pull と同じ入口（`VerifiedLayerBlob::open` →
//! `extract_image_layers_with_options`）を通すため、所有者の写像・特殊ビット・展開上限・diff_id 照合は pull と同一になる。
//!
//! 代償: create ごとに展開のコスト（時間・ディスク）がかかる。overlay の下位層にする最適化は `mount(2)` の `unsafe` を
//! 要し、本 crate には `sys` モジュールが無いため未実装（REPAIR-3）。
//!
//! # 検証の順序（信頼境界）
//!
//! 1. 要求（`ImageSpec`）の長さ・NUL・`runtime_handler` を、キャッシュに触れる前に検証する。参照はパス要素に使わず、
//!    `Digest::parse` で検証した 16 進部だけを使う
//! 2. キャッシュの `blobs/sha256`・`rootfs/sha256` を所有者・権限・symlink の検証つきで開き、公開済みエントリが
//!    信頼できなければ**消さずに**拒否する
//! 3. 展開記録を symlink を辿らず非ブロッキングで開き、同じハンドルの fstat で信頼条件を確かめ、`settings` 部が
//!    今回の展開設定と完全一致することを要求する（食い違えば `FAILED_PRECONDITION`。黙って別設定で展開しない）
//! 4. config blob は上限つきで 1 回だけ読み、**読んだバイト列そのもの**の sha256 を image ID と照合してから
//!    `rootfs.diff_ids` と `config` 節を同じ本文から解析する
//! 5. layer は記録の `layer=` 行から得る。件数は config の `diff_ids` と一致を要求し、各 blob は fstat のサイズで
//!    `VerifiedLayerBlob::open`（digest・サイズ照合）してから展開する
//!
//! # 未実装・簡易実装（REPAIR-3）
//!
//! - **タグ・digest 参照の解決**: [`ImageRootfsSource::with_image_store`] で `ImageStore` を注入したときだけタグを解決し
//!   （短縮名は `canonical_reference` で正規化して再照会する）、無ければ `sha256:<64 桁小文字 hex>` の image ID だけを受ける
//!   （それ以外は `UNIMPLEMENTED`。注入済みで未知の参照は `NOT_FOUND`）。plugin-cri は `ImageService` と同じプロセス内の在庫を
//!   注入する（#2592）。在庫は永続化されないため、plugin-cri の再起動でタグの対応は失われる（`PullImage` をやり直せば、
//!   キャッシュ済みの blob を再利用できる。永続の在庫への配線は TASK-183・#2315・#2380。REPAIR-3）
//! - **イメージの User**: 数値の `uid:gid` は rootfs を読まずに解決する。名前・uid のみ・名前つきの組は、展開後の
//!   rootfs の `/etc/passwd`・`/etc/group` を [`fandhe_container_oci::layer::read_rootfs_file`]（fd 起点・symlink を
//!   辿らない・1 MiB 上限）で読んで解決する（#2606・SEC-1・SEC-5。解決表は `docs/design/cri-config-acceptance.md`）。
//!   読めない・見つからない場合は [`ImageDefaults::user_unresolved`] のまま返し、`build_runtime_config` に拒否させる
//!   （root へ黙ってフォールバックしない）。イメージの `User` 単独（`/etc/group` の所属）
//!   からは補助グループを作らない。Merge のときの所属グループは [`ImageDefaults::supplementary_gids`]（#2667）で別に求める。
//!   `StopSignal` は [`ImageDefaults::stop_signal`] へ解釈する（解釈できない値は `INVALID_ARGUMENT`。#2771）
//! - **run_as_username**（CRI）: 展開後の rootfs の `/etc/passwd` を同じ読み口で読み、名前の完全一致で `(uid, gid)` を
//!   [`ImageDefaults::resolved_run_as_username`] へ返す（#2664・CRI-2・SEC-5）。見つからない・passwd が無い場合は
//!   `INVALID_ARGUMENT`、安全に読めない場合は `FAILED_PRECONDITION`、読む手段が無い場合は `UNIMPLEMENTED`。
//!   数字だけの名前は拒否する（数値は `run_as_user`。containerd は uid 扱いの既知の差）
//! - **展開設定**: 所有者・特殊ビットの本番の値は現状も既定の `Keep` + `Strip`。`ChownMapped` 等の配線は #2241
//!   （rootful の可否）・#2315・#482（core の user namespace 配線）が前提で（pull の呼び出し元の配線は #2592 で済み）、
//!   それまで据え置く（#2534・SEC-5。`docs/design/oci-layer-special-bits.md`）。pull と create の設定は
//!   [`ImageExtractConfig`] で 1 か所にまとめる
//! - 展開は `extract_image_layers_bounded` でエントリ単位に期限（この `prepare` の開始からの `deadline`）と取り消しの
//!   旗（`prepare_cancellable`）を確かめ、超過・取り消しは `Timeout`（`DEADLINE_EXCEEDED`）で止めて rootfs を消す
//!   （REPAIR-5・#2899）。分割できない区間は blob 1 本の sha256 検証・1 エントリの書き込み・失敗時の削除で、いずれも
//!   展開の上限で有界。`Timeout` は dispatch より前（bundle 用意）でしか起きないため、確定失敗の分類に入れない
//! - 展開済み rootfs・blob の GC は TASK-183（OCI-7）の担当

use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use fandhe_container_oci::config::{
    ImageProcessConfig, MAX_CONFIG_BYTES, parse_verified_image_config,
};
use fandhe_container_oci::error::OciErrorCode;
use fandhe_container_oci::instrument::{NoopOciOpRecorder, OciOpRecorder};
use fandhe_container_oci::layer::extract::{
    ExtractBudget, ExtractLimits, ExtractOptions, ImageLayer, extract_image_layers_bounded,
    remove_extracted_tree,
};
use fandhe_container_oci::layer::{
    BlobFileFacts, VerifiedLayerBlob, check_blob_trust, open_blob_nofollow, read_rootfs_file,
};
use fandhe_container_oci::manifest::MAX_LAYERS;
use fandhe_container_oci::reference::Digest;

use super::provider::{RootfsSource, UserResolveRequest};
use super::spec::{ImageDefaults, ResolvedImage};
use crate::error::CriError;
use crate::image_pull::{
    DEFAULT_MAX_IMAGE_BYTES, PullConfig, PullError, RECORD_FILE, canonical_reference,
    create_private_dir, digest_hex, expected_root_owner_for, inspect_published_rootfs,
    prepare_private_dir, read_unpack_record_body, record_settings,
};
use crate::image_service::{ImageStore, MAX_IMAGE_FIELD_BYTES};
use crate::runtime::v1::ImageSpec;

/// 1 回の rootfs 用意の既定の期限（展開の前後で確認する。REPAIR-5）。
pub const DEFAULT_ROOTFS_DEADLINE: Duration = Duration::from_secs(10 * 60);
/// `ImageSpec.annotations` の件数上限（本実装は使わないが、確保前に上限を検証する）。
const MAX_ANNOTATIONS: usize = 64;
/// イメージの User の数値 1 項目の最大桁数（`u32` の 10 桁）。
const MAX_ID_DIGITS: usize = 10;
/// `/etc/passwd`・`/etc/group` 1 ファイルの読み取り上限（REPAIR-5・SEC-1）。
const MAX_ETC_FILE_BYTES: u64 = 1 << 20;
/// 上記ファイルの行数の上限（超過は未解決。切り捨てない）。
const MAX_ETC_LINES: usize = 65_536;
/// 名前 1 件の最大バイト数。
const MAX_NAME_BYTES: usize = 256;

/// 展開に使う設定の束。`PullConfig` の対応する項目と同じ値を渡せる（pull と create で展開設定が食い違うと、
/// 記録の照合で `FAILED_PRECONDITION` になるため、1 か所から配る。本番の値の配線の前提は #2534 の記述を参照）。
#[derive(Debug, Clone)]
pub struct ImageExtractConfig {
    /// キャッシュのルート（`PullConfig::cache_dir` と同じ。`blobs/sha256` と `rootfs/sha256` を持つ）。
    pub cache_dir: PathBuf,
    /// レイヤー展開の所有者・特殊ビットの選択肢（pull 時の記録と一致すること）。
    pub extract_options: ExtractOptions,
    /// レイヤー展開の上限。
    pub extract_limits: ExtractLimits,
    /// 1 レイヤーあたりの展開後（tar）サイズの上限。
    pub max_uncompressed_layer_bytes: u64,
    /// layer blob の圧縮サイズ合計の上限。
    pub max_image_bytes: u64,
    /// 1 回の用意の期限。
    pub deadline: Duration,
}

impl ImageExtractConfig {
    /// pull と同じ既定値で作る（`Keep` + `Strip`。写せないアーキテクチャは `Unimplemented`）。
    pub fn new(cache_dir: impl Into<PathBuf>) -> Result<Self, CriError> {
        Ok(Self::from_pull_config(&PullConfig::new(cache_dir)?))
    }

    /// `PullConfig` の展開に関する項目をそのまま写す（pull と create の設定を一致させる）。
    pub fn from_pull_config(pull: &PullConfig) -> Self {
        Self {
            cache_dir: pull.cache_dir.clone(),
            extract_options: pull.extract_options.clone(),
            extract_limits: pull.extract_limits,
            max_uncompressed_layer_bytes: pull.max_uncompressed_layer_bytes,
            max_image_bytes: pull.max_image_bytes.min(DEFAULT_MAX_IMAGE_BYTES),
            deadline: DEFAULT_ROOTFS_DEADLINE,
        }
    }
}

/// 展開記録の `layer=` 行 1 件。
struct RecordedLayer {
    digest: Digest,
    media_type: String,
}

/// pull 済みイメージを bundle の `rootfs/` へ再展開する本番の [`RootfsSource`]。
pub struct ImageRootfsSource {
    config: ImageExtractConfig,
    store: Option<Arc<dyn ImageStore>>,
    recorder: Arc<dyn OciOpRecorder>,
}

impl std::fmt::Debug for ImageRootfsSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImageRootfsSource")
            .field("cache_dir", &self.config.cache_dir)
            .finish_non_exhaustive()
    }
}

impl ImageRootfsSource {
    /// 展開設定から作る。タグの解決器は無く、image ID（`sha256:<hex>`）だけを受ける。
    pub fn new(config: ImageExtractConfig) -> Self {
        Self {
            config,
            store: None,
            recorder: Arc::new(NoopOciOpRecorder),
        }
    }

    /// タグ・digest 参照を image ID へ解決する `ImageStore` を注入する（`ImageService` と同じストアを共有したとき用）。
    #[must_use]
    pub fn with_image_store(mut self, store: Arc<dyn ImageStore>) -> Self {
        self.store = Some(store);
        self
    }

    /// 展開の計装（REPAIR-4）の記録先を差し替える。
    #[must_use]
    pub fn with_recorder(mut self, recorder: Arc<dyn OciOpRecorder>) -> Self {
        self.recorder = recorder;
        self
    }

    /// `ImageSpec` を検証し、image ID（config digest）へ解決する。キャッシュには触れない。
    fn resolve_image(&self, spec: &ImageSpec) -> Result<ResolvedImage, CriError> {
        let bad = || CriError::invalid_argument("image reference is invalid");
        let too_long = |s: &str| s.len() > MAX_IMAGE_FIELD_BYTES;
        if spec.image.is_empty()
            || too_long(&spec.image)
            || spec.image.contains('\0')
            || too_long(&spec.user_specified_image)
            || too_long(&spec.image_ref)
            || spec.annotations.len() > MAX_ANNOTATIONS
            || spec
                .annotations
                .iter()
                .any(|(k, v)| too_long(k) || too_long(v))
        {
            return Err(bad());
        }
        if !spec.runtime_handler.is_empty() {
            return Err(CriError::unimplemented(
                "image runtime_handler is not supported",
            ));
        }
        if let Some(store) = &self.store {
            let found = store
                .get(&spec.image)
                .map_err(|_| CriError::internal("image store is unavailable"))?;
            if let Some(resolved) = found.and_then(|r| resolved_from_record(&r)) {
                return Ok(resolved);
            }
            // 短縮名（`alpine:3.20` 等）は PullImage と同じ規則で正規化して再照会する（`ImageStatus` と同じ。CRI-3・CRI-4）。
            // 長さ・NUL の検証は上で済ませてあり、正規化した文字列は在庫の照会にしか使わない（パス要素にしない）。
            if let Some(canonical) = canonical_reference(&spec.image)
                && canonical != spec.image
            {
                let found = store
                    .get(&canonical)
                    .map_err(|_| CriError::internal("image store is unavailable"))?;
                if let Some(resolved) = found.and_then(|r| resolved_from_record(&r)) {
                    return Ok(resolved);
                }
            }
        }
        let is_bare_hex =
            spec.image.len() == 64 && spec.image.bytes().all(|b| b.is_ascii_hexdigit());
        if spec.image.starts_with("sha256:") || is_bare_hex {
            // image ID の形をしているものは、形が不正なら INVALID_ARGUMENT（素の hex も受けない）。
            let id = Digest::parse(&spec.image).map_err(|_| bad())?;
            // 在庫があれば digest 参照も拾う（在庫に無い・照会できない場合は image ID だけ。#2831）。
            let record = self
                .store
                .as_ref()
                .and_then(|store| store.get(id.as_str()).ok().flatten());
            let reference = record
                .as_ref()
                .and_then(|r| r.repo_digests().first().cloned());
            let tag = record.as_ref().and_then(|r| r.repo_tags().first().cloned());
            return Ok(ResolvedImage::new(id, reference).with_tag(tag));
        }
        if self.store.is_some() {
            // 解決は実行済みで参照が未知なだけなので、機能欠如ではなく NOT_FOUND を返す。
            return Err(CriError::not_found("image reference is not found"));
        }
        Err(CriError::unimplemented(
            "image reference resolution is not available; use the image id",
        ))
    }

    fn check_deadline(&self, started: Instant) -> Result<(), CriError> {
        self.check_budget(started, None)
    }

    /// 期限に加えて取り消しの旗も確かめる（RPC が期限切れで worker を手放したとき。REPAIR-5・#2899）。
    fn check_budget(&self, started: Instant, cancel: Option<&AtomicBool>) -> Result<(), CriError> {
        if started.elapsed() >= self.config.deadline
            || cancel.is_some_and(|c| c.load(Ordering::Acquire))
        {
            return Err(CriError::timeout(
                "image rootfs preparation exceeded its deadline",
            ));
        }
        Ok(())
    }
}

/// 在庫の記録から image ID と digest 参照（`repo_digests[0]`）を取る（#2831・CRI-2・OCI-1）。
fn resolved_from_record(record: &crate::image_service::ImageRecord) -> Option<ResolvedImage> {
    let id = Digest::parse(record.id()).ok()?;
    Some(
        ResolvedImage::new(id, record.repo_digests().first().cloned())
            .with_tag(record.repo_tags().first().cloned()),
    )
}

/// 展開成功後に rootfs 自体へ検索権限（0755）を付ける（CRI-2・SEC-1）。
///
/// 展開中は 0700 のまま保ち（`create_private_dir`）、tar のルートエントリは展開処理が無視するため、放置すると
/// コンテナの `/` が 0700 になり、`User` が非 root（`1000:2000` や `run_as_user`）のプロセスが `/` 配下を
/// 検索できず EACCES になる。外側の bundle ディレクトリは 0700 のまま変えない（ホスト側の他ユーザーを締め出す）。
fn open_rootfs_for_search(rootfs: &Path) -> Result<(), CriError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(rootfs, std::fs::Permissions::from_mode(0o755))
            .map_err(|_| CriError::internal("failed to set rootfs permissions"))
    }
    #[cfg(not(unix))]
    {
        let _ = rootfs;
        Ok(())
    }
}

/// 展開後の rootfs に、core の起動が前提とするマウント先ディレクトリ（`proc`）が無ければ作る
/// （CRI-2・OCI-4・SEC-1。#2818）。
///
/// busybox 等のイメージは `/proc` を持たず、core の rootfs 用意（`prepare_rootfs`）は `proc` が無いと
/// `path_missing` で拒否するため、実イメージの起動が `PrepareRootfs` 段で失敗していた。ここは bundle が
/// 今作ったばかりの私有の木（0700 の外側 bundle 配下）に対してだけ呼ばれる。既存のエントリは種別を問わず
/// 触らない（symlink や通常ファイルは core 側の検査が拒否する。fail-closed）。
fn ensure_mountpoints(rootfs: &Path) -> Result<(), CriError> {
    let proc_path = rootfs.join("proc");
    match std::fs::symlink_metadata(&proc_path) {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir(&proc_path).map_err(|_| {
                CriError::internal("failed to create the proc mount point in the rootfs")
            })?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                std::fs::set_permissions(&proc_path, std::fs::Permissions::from_mode(0o555))
                    .map_err(|_| CriError::internal("failed to set the proc mount point mode"))?;
            }
            Ok(())
        }
        Err(_) => Err(CriError::internal(
            "failed to inspect the proc mount point in the rootfs",
        )),
    }
}

fn untrusted(message: &'static str) -> CriError {
    CriError::failed_precondition(message)
}

/// 展開記録を信頼条件つきで読み、`settings` 部の完全一致を確かめて `layer=` 行を返す。
fn read_layers(
    path: &Path,
    expected_settings: &str,
    owner: u32,
) -> Result<Vec<RecordedLayer>, CriError> {
    let body = read_unpack_record_body(path, owner).map_err(CriError::from)?;
    let Some(rest) = body.strip_prefix(expected_settings.as_bytes()) else {
        return Err(untrusted(
            "image rootfs cache entry was unpacked with different settings",
        ));
    };
    let data_loss = || {
        CriError::new(
            crate::error::CriErrorCode::DataLoss,
            "image rootfs unpack record is malformed",
        )
    };
    let text = std::str::from_utf8(rest).map_err(|_| data_loss())?;
    let mut layers = Vec::new();
    for line in text.lines() {
        if layers.len() >= MAX_LAYERS {
            return Err(CriError::resource_exhausted(
                "image rootfs unpack record has too many layers",
            ));
        }
        let entry = line.strip_prefix("layer=").ok_or_else(data_loss)?;
        let (digest, media_type) = entry.split_once(' ').ok_or_else(data_loss)?;
        let digest = Digest::parse(digest).map_err(|_| data_loss())?;
        layers.push(RecordedLayer {
            digest,
            media_type: media_type.to_owned(),
        });
    }
    Ok(layers)
}

/// config blob を信頼条件つきで上限まで 1 回だけ読み、読んだ本文の digest を image ID と照合してから解析する。
fn read_config(
    blobs: &Path,
    owner: u32,
    id: &Digest,
) -> Result<(Vec<Digest>, ImageProcessConfig), CriError> {
    let mut file = open_blob_nofollow(&blobs.join(digest_hex(id)))
        .map_err(|e| CriError::from(PullError::from_config(&e)))?;
    let facts = BlobFileFacts::from_file(&file)
        .ok_or_else(|| untrusted("cached image config is not trusted"))?;
    check_blob_trust(&facts, owner).map_err(|_| untrusted("cached image config is not trusted"))?;
    let mut body = Vec::new();
    (&mut file)
        .take(MAX_CONFIG_BYTES + 1)
        .read_to_end(&mut body)
        .map_err(|_| {
            CriError::new(
                crate::error::CriErrorCode::DataLoss,
                "image config could not be read",
            )
        })?;
    if body.len() as u64 > MAX_CONFIG_BYTES {
        return Err(CriError::resource_exhausted(
            "image config exceeds the size limit",
        ));
    }
    let (rootfs, process) = parse_verified_image_config(&body, id)
        .map_err(|e| CriError::from(PullError::from_config(&e)))?;
    Ok((rootfs.diff_ids().to_vec(), process))
}

/// イメージ config の実行既定値を [`ImageDefaults`] へ写す。
///
/// User は数値の `uid:gid` だけ解決し、名前・uid のみは未解決として印を付ける（root へ落とさない）。
fn defaults_from(process: &ImageProcessConfig) -> Result<ImageDefaults, CriError> {
    let working_dir = match process.working_dir() {
        "" => None,
        "/" => Some("/".to_owned()),
        w => Some(w.strip_suffix('/').unwrap_or(w).to_owned()),
    };
    let (user, user_unresolved) = parse_user(process.user())?;
    Ok(ImageDefaults {
        entrypoint: process.entrypoint().to_vec(),
        cmd: process.cmd().to_vec(),
        env: process.env().to_vec(),
        working_dir,
        user,
        user_unresolved,
        resolved_run_as_username: None,
        supplementary_gids: Vec::new(),
        stop_signal: crate::stop_signal::parse_image_stop_signal(process.stop_signal())?,
        resolved_image: None,
    })
}

fn parse_user(user: &str) -> Result<(Option<(u32, u32)>, bool), CriError> {
    if user.is_empty() {
        return Ok((None, false));
    }
    let numeric = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    let id = |s: &str| -> Result<u32, CriError> {
        if s.len() > MAX_ID_DIGITS {
            return Err(CriError::invalid_argument("image user is invalid"));
        }
        s.parse::<u32>()
            .map_err(|_| CriError::invalid_argument("image user is invalid"))
    };
    match user.split_once(':') {
        Some((u, g)) if numeric(u) && numeric(g) => Ok((Some((id(u)?, id(g)?)), false)),
        // 名前・uid のみ・名前つきの組は、passwd / group の解決が要るため未解決（拒否される）。
        _ => Ok((None, true)),
    }
}

/// User の 1 項目（uid / gid のどちらでも使う）。名前は passwd / group で引く。
#[derive(Debug, Clone, PartialEq, Eq)]
enum IdPart {
    Id(u32),
    Name(String),
}

/// 解決が要る User の指定（`user[:group]`）。
#[derive(Debug, Clone, PartialEq, Eq)]
struct UserLookup {
    user: IdPart,
    group: Option<IdPart>,
}

fn parse_id_part(s: &str) -> Option<IdPart> {
    if s.is_empty() {
        return None;
    }
    if s.bytes().all(|b| b.is_ascii_digit()) {
        if s.len() > MAX_ID_DIGITS {
            return None;
        }
        return s.parse::<u32>().ok().map(IdPart::Id);
    }
    if s.len() > MAX_NAME_BYTES || s.bytes().any(|b| matches!(b, 0 | b':' | b'\n' | b'/')) {
        return None;
    }
    Some(IdPart::Name(s.to_owned()))
}

/// 形式が不正なら `None`（未解決のまま拒否される）。
fn parse_user_lookup(user: &str) -> Option<UserLookup> {
    match user.split_once(':') {
        None => Some(UserLookup {
            user: parse_id_part(user)?,
            group: None,
        }),
        Some((u, g)) => Some(UserLookup {
            user: parse_id_part(u)?,
            group: Some(parse_id_part(g)?),
        }),
    }
}

/// passwd / group の行を走査する。空行・コメント・NIS（`+` `-`）行・UTF-8 でない行は読み飛ばす。
fn etc_fields(body: &[u8]) -> impl Iterator<Item = Vec<&str>> {
    body.split(|b| *b == b'\n')
        .filter_map(|l| std::str::from_utf8(l).ok())
        .map(|l| l.trim_end_matches('\r'))
        .filter(|l| !l.is_empty() && !l.starts_with(['#', '+', '-']))
        .map(|l| l.split(':').collect::<Vec<_>>())
}

/// passwd から `(uid, gid)` を引く（`by_name` か uid）。形式が崩れた行は読み飛ばし、最初の一致を採る。
fn passwd_entry(body: &[u8], key: &IdPart) -> Option<(u32, u32)> {
    etc_fields(body).find_map(|f| {
        let (name, uid, gid) = (
            f.first()?,
            f.get(2)?.parse::<u32>().ok()?,
            f.get(3)?.parse::<u32>().ok()?,
        );
        match key {
            IdPart::Name(n) if n == name => Some((uid, gid)),
            IdPart::Id(u) if *u == uid => Some((uid, gid)),
            _ => None,
        }
    })
}

/// group から gid を名前で引く。
fn group_gid(body: &[u8], name: &str) -> Option<u32> {
    etc_fields(body).find_map(|f| {
        if *f.first()? == name {
            f.get(2)?.parse::<u32>().ok()
        } else {
            None
        }
    })
}

/// passwd から uid の最初の一致の名前を引く（形式が崩れた行は読み飛ばす）。
fn passwd_name_of(body: &[u8], uid: u32) -> Option<String> {
    etc_fields(body).find_map(|f| {
        let (name, id) = (f.first()?, f.get(2)?.parse::<u32>().ok()?);
        // 空の名前は不正エントリとして除く（空名が group の空メンバーに一致するのを防ぐ。#2667・SEC-5）。
        (id == uid && !name.is_empty()).then(|| (*name).to_owned())
    })
}

/// group から、第 4 フィールド（メンバー一覧）に `user` を含む行の gid を行順に集める（重複は除く）。
///
/// グループ名が `user` と同じ行は除く（containerd の `WithAdditionalGIDs` と同じ。#2667）。形式が崩れた行は読み飛ばす。
fn group_memberships(body: &[u8], user: &str) -> Vec<u32> {
    // 空の検索名は空メンバー（`root:x:0:`）に一致して無関係な gid を混入させるため、何も返さない。
    if user.is_empty() {
        return Vec::new();
    }
    let mut out: Vec<u32> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for f in etc_fields(body) {
        let (Some(name), Some(gid), Some(members)) = (
            f.first(),
            f.get(2).and_then(|g| g.parse::<u32>().ok()),
            f.get(3),
        ) else {
            continue;
        };
        if *name != user && members.split(',').any(|m| m == user) && seen.insert(gid) {
            out.push(gid);
        }
    }
    out
}

/// `read_etc` の失敗を CRI のエラーへ写す（`Unsupported` は `UNIMPLEMENTED`、`Untrusted` は `FAILED_PRECONDITION`。
/// メッセージは固定文言）。
fn etc_read_error(e: EtcReadError, what: &'static str) -> CriError {
    match e {
        EtcReadError::Unsupported => {
            CriError::unimplemented(format!("image {what} cannot be read on this platform"))
        }
        EtcReadError::Untrusted => {
            CriError::failed_precondition(format!("image {what} could not be read"))
        }
    }
}

/// 実効ユーザーの `(uid, 名前)` を決める。決まらない（イメージ User が無い・名前が引けない・passwd を読めない等）と `None`。
///
/// 優先順位は CRI の `run_as_username`（解決済みの uid）→ `run_as_user`（passwd を uid で引く）→ イメージ User
/// （名前形式ならその名前、uid 形式なら passwd を uid で引く）。uid 0 は passwd を読まずに `None` とする
/// （root にはイメージ由来のグループを付けない。#2667）。
fn effective_username(
    rootfs: &Path,
    request: &UserResolveRequest<'_>,
    image_user: &str,
    defaults: &ImageDefaults,
) -> Result<Option<(u32, String)>, CriError> {
    let (uid, hint) = if let Some(name) = request.run_as_username {
        let Some((uid, _)) = defaults.resolved_run_as_username else {
            return Ok(None);
        };
        (uid, Some(name.to_owned()))
    } else if let Some(uid) = request.run_as_user {
        (uid, None)
    } else if let Some((uid, _)) = defaults.user {
        let hint = match parse_user_lookup(image_user).map(|l| l.user) {
            Some(IdPart::Name(n)) => Some(n),
            _ => None,
        };
        (uid, hint)
    } else {
        return Ok(None);
    };
    if uid == 0 {
        return Ok(None);
    }
    let name = match hint {
        Some(n) => n,
        None => {
            // passwd を安全に読めない場合は名前を決められないものとして扱い、イメージ由来のグループを付けない
            // （権限が弱くなる側。明示した run_as_user の起動を passwd の不備で止めない。#2667）。
            let Ok(body) = read_etc(rootfs, "passwd") else {
                return Ok(None);
            };
            match body.as_deref().and_then(|b| passwd_name_of(b, uid)) {
                Some(n) => n,
                None => return Ok(None),
            }
        }
    };
    Ok(Some((uid, name)))
}

/// 実効ユーザーのイメージの `/etc/group` での所属グループを求める（#2667・CRI-2・SEC-5）。
///
/// 実効 uid が 0 でなく名前が決まったときだけ group を読む。group が無ければ空、安全に読めなければ拒否する
/// （読めなかったグループを黙って空にしない）。
fn resolve_image_groups(
    rootfs: &Path,
    request: &UserResolveRequest<'_>,
    image_user: &str,
    defaults: &ImageDefaults,
) -> Result<Vec<u32>, CriError> {
    let Some((_, name)) = effective_username(rootfs, request, image_user, defaults)? else {
        return Ok(Vec::new());
    };
    let body = read_etc(rootfs, "group").map_err(|e| etc_read_error(e, "group"))?;
    Ok(body
        .as_deref()
        .map(|b| group_memberships(b, &name))
        .unwrap_or_default())
}

/// rootfs の `etc/<file>` を fd 起点で読む。`Ok(None)` は不在、`Err` は読めない（呼び出し側が未解決にする）。
fn read_etc(rootfs: &Path, file: &str) -> Result<Option<Vec<u8>>, EtcReadError> {
    let body = read_rootfs_file(rootfs, &["etc", file], MAX_ETC_FILE_BYTES).map_err(|e| {
        if e.code() == OciErrorCode::Unimplemented {
            EtcReadError::Unsupported
        } else {
            EtcReadError::Untrusted
        }
    })?;
    // 行数上限を超える本文は切り捨てず未解決にする（後続行の取りこぼしで gid が 0 に落ちるのを防ぐ）。
    if let Some(b) = &body
        && b.split(|c| *c == b'\n').count() > MAX_ETC_LINES
    {
        return Err(EtcReadError::Untrusted);
    }
    Ok(body)
}

/// `read_etc` の失敗の種類。`run_as_username` は両者でエラーコードを分ける（#2664）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EtcReadError {
    /// `openat2` 不可・非対応 OS など、安全に読む手段が無い（`UNIMPLEMENTED`）。
    Unsupported,
    /// symlink・FIFO・上限超過など、安全に読めない（`FAILED_PRECONDITION`）。
    Untrusted,
}

/// CRI の `run_as_username` を rootfs の `/etc/passwd` で `(uid, gid)` へ解決する（#2664・CRI-2・SEC-5）。
///
/// 名前は passwd の第 1 フィールドとの完全一致比較にだけ使い、パス要素にしない。見つからない・passwd が無い場合は
/// `INVALID_ARGUMENT`、安全に読めない場合は `FAILED_PRECONDITION`、読む手段が無い場合は `UNIMPLEMENTED`
/// （いずれも root へ黙って落とさない）。メッセージに名前は含めない。
fn resolve_run_as_username(rootfs: &Path, name: &str) -> Result<(u32, u32), CriError> {
    let key = match parse_id_part(name) {
        Some(k @ IdPart::Name(_)) => k,
        _ => return Err(CriError::invalid_argument("run_as_username is invalid")),
    };
    let body = match read_etc(rootfs, "passwd") {
        Ok(b) => b,
        Err(EtcReadError::Unsupported) => {
            return Err(CriError::unimplemented(
                "image passwd cannot be read on this platform",
            ));
        }
        Err(EtcReadError::Untrusted) => {
            return Err(CriError::failed_precondition(
                "image passwd could not be read",
            ));
        }
    };
    body.as_deref()
        .and_then(|b| passwd_entry(b, &key))
        .ok_or_else(|| CriError::invalid_argument("run_as_username is not present in the image"))
}

/// 名前・uid のみの User を `(uid, gid)` へ解決する。解決できなければ `None`（未解決）。
///
/// uid のみで passwd に行が無い（または passwd が無い）ときは gid 0（runc / containerd と同じ。uid は root にしない）。
/// passwd / group が読めない（symlink・FIFO・上限超過等）ときは gid 0 へ落とさず未解決にする。
fn resolve_user(rootfs: &Path, lookup: &UserLookup) -> Option<(u32, u32)> {
    let passwd = match &lookup.user {
        IdPart::Id(_) if matches!(lookup.group, Some(IdPart::Id(_))) => None,
        _ => Some(read_etc(rootfs, "passwd").ok()?),
    };
    let found = passwd
        .as_ref()
        .and_then(|b| b.as_deref())
        .and_then(|b| passwd_entry(b, &lookup.user));
    let uid = match (&lookup.user, found) {
        (_, Some((uid, _))) => uid,
        (IdPart::Id(u), None) => *u,
        (IdPart::Name(_), None) => return None,
    };
    let gid = match &lookup.group {
        Some(IdPart::Id(g)) => *g,
        Some(IdPart::Name(n)) => {
            let body = read_etc(rootfs, "group").ok()??;
            group_gid(&body, n)?
        }
        None => found.map_or(0, |(_, g)| g),
    };
    Some((uid, gid))
}

impl RootfsSource for ImageRootfsSource {
    fn prepare(
        &self,
        image: &ImageSpec,
        rootfs: &Path,
        user: &UserResolveRequest<'_>,
    ) -> Result<ImageDefaults, CriError> {
        self.prepare_cancellable(image, rootfs, user, None)
    }

    fn prepare_cancellable(
        &self,
        image: &ImageSpec,
        rootfs: &Path,
        user: &UserResolveRequest<'_>,
        cancel: Option<&AtomicBool>,
    ) -> Result<ImageDefaults, CriError> {
        let started = Instant::now();
        let resolved = self.resolve_image(image)?;
        let id = Digest::parse(resolved.id_str())
            .map_err(|_| CriError::internal("resolved image id is invalid"))?;
        let opts = &self.config.extract_options;
        let blobs = prepare_private_dir(&self.config.cache_dir, &["blobs", "sha256"])?;
        let entries = prepare_private_dir(&self.config.cache_dir, &["rootfs", "sha256"])?;
        let root_owner = expected_root_owner_for(opts, entries.owner)?;
        let entry = entries.path.join(digest_hex(&id));
        // 公開済みエントリは「pull が検証を完了した」印としてだけ見る。展開済み rootfs は開かず、書かない。
        if !inspect_published_rootfs(&entry, entries.owner, root_owner)? {
            return Err(CriError::not_found(
                "image is not present in the local cache",
            ));
        }
        let settings = record_settings(&id, opts)?;
        let layers = read_layers(&entry.join(RECORD_FILE), &settings, entries.owner)?;
        let (diff_ids, process) = read_config(&blobs.path, blobs.owner, &id)?;
        let mut defaults = defaults_from(&process)?;
        defaults.resolved_image = Some(resolved);
        if layers.len() != diff_ids.len() {
            return Err(CriError::new(
                crate::error::CriErrorCode::DataLoss,
                "image layer count does not match the config",
            ));
        }
        // 各 blob を fstat のサイズで検証つきに開く。サイズは上限内であること（digest 照合は open が行う）。
        let mut total: u64 = 0;
        let mut verified = Vec::with_capacity(layers.len());
        for l in &layers {
            // blob の sha256 検証は大きさに比例して長いため、1 本ごとに期限を確かめる（REPAIR-5・#2821）。
            self.check_budget(started, cancel)?;
            let path = blobs.path.join(digest_hex(&l.digest));
            let size = open_blob_nofollow(&path)
                .and_then(|f| {
                    f.metadata().map(|m| m.len()).map_err(|_| {
                        fandhe_container_oci::error::OciError::new(
                            OciErrorCode::DataLoss,
                            "layer blob could not be inspected",
                        )
                    })
                })
                .map_err(|e| CriError::from(PullError::from_extract(&e)))?;
            total = total.saturating_add(size);
            if size > self.config.max_image_bytes || total > self.config.max_image_bytes {
                return Err(CriError::resource_exhausted(
                    "image layers exceed the size limit",
                ));
            }
            verified.push(
                VerifiedLayerBlob::open(&path, &l.digest, size, blobs.owner)
                    .map_err(|e| CriError::from(PullError::from_extract(&e)))?,
            );
        }
        let image_layers: Vec<ImageLayer<'_>> = verified
            .iter()
            .zip(&layers)
            .zip(&diff_ids)
            .map(|((b, l), d)| ImageLayer::new(b, &l.media_type, d))
            .collect();
        self.check_budget(started, cancel)?;
        // 呼び出し元（SpecBundleProvider）が渡す不在のパスを 0700 で作る。作れなければ他人の実体の可能性があり消さない。
        create_private_dir(rootfs).map_err(CriError::from)?;
        // 展開はエントリ単位で期限（この prepare の開始からの deadline）と取り消しを確かめる。1 エントリの書き込みは分割しない。
        let mut budget = ExtractBudget::new();
        if let Some(d) = started.checked_add(self.config.deadline) {
            budget = budget.with_deadline(d);
        }
        if let Some(c) = cancel {
            budget = budget.with_cancel(c);
        }
        let extracted = extract_image_layers_bounded(
            self.recorder.as_ref(),
            &image_layers,
            rootfs,
            self.config.max_uncompressed_layer_bytes,
            self.config.extract_limits,
            opts,
            &budget,
        )
        .map_err(|e| {
            // CreateContainer から見える期限切れの文言を 1 つにそろえる（check_budget と同じ）。
            if e.code() == OciErrorCode::Timeout {
                CriError::timeout("image rootfs preparation exceeded its deadline")
            } else {
                CriError::from(PullError::from_extract(&e))
            }
        })
        .and_then(|_| self.check_budget(started, cancel))
        .and_then(|()| open_rootfs_for_search(rootfs))
        .and_then(|()| ensure_mountpoints(rootfs))
        .and_then(|()| {
            // CRI の run_as_username は展開後の私有 rootfs の passwd で解決する（失敗は拒否。#2664）。
            if let Some(name) = user.run_as_username {
                defaults.resolved_run_as_username = Some(resolve_run_as_username(rootfs, name)?);
            }
            // 名前・uid のみの User は、展開後の私有 rootfs の passwd / group で解決する（失敗は未解決のまま返す）。
            // run_as_username があるときは CRI 側が優先するため省略する。
            if user.run_as_username.is_none()
                && defaults.user_unresolved
                && let Some(lookup) = parse_user_lookup(process.user())
                && let Some(ids) = resolve_user(rootfs, &lookup)
            {
                defaults.user = Some(ids);
                defaults.user_unresolved = false;
            }
            // 補助グループ（Merge のとき）: 実効ユーザーの所属グループを /etc/group から求める（#2667）。
            if user.image_groups {
                defaults.supplementary_gids =
                    resolve_image_groups(rootfs, user, process.user(), &defaults)?;
            }
            self.check_deadline(started)
        });
        if let Err(e) = extracted {
            // 先行レイヤーの展開物が残るため、自分が作った rootfs だけを消す（0555 等も権限を戻して消す）。
            let _ = remove_extracted_tree(rootfs);
            return Err(e);
        }
        Ok(defaults)
    }

    fn release(&self, rootfs: &Path) -> Result<(), CriError> {
        match std::fs::symlink_metadata(rootfs) {
            Ok(m) if m.file_type().is_dir() => remove_extracted_tree(rootfs)
                .map_err(|_| CriError::internal("failed to remove rootfs")),
            // symlink・通常ファイル等は辿らず消さない（リンク先の削除を防ぐ。fail-closed）。
            Ok(_) => Err(CriError::internal("rootfs path is not a directory")),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(CriError::internal("failed to inspect rootfs")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn process(user: &str, wd: &str) -> ImageProcessConfig {
        let body = format!(r#"{{"config":{{"User":"{user}","WorkingDir":"{wd}"}}}}"#);
        fandhe_container_oci::config::parse_image_config_process(body.as_bytes()).unwrap()
    }

    /// CRI-2: User の変換表。数値の `uid:gid` だけ解決し、名前・uid のみは未解決の印を付ける。
    #[test]
    fn cri2_image_user_conversion_table() {
        let get = |u: &str| defaults_from(&process(u, "")).map(|d| (d.user, d.user_unresolved));
        assert_eq!(get("").unwrap(), (None, false));
        assert_eq!(get("1000:2000").unwrap(), (Some((1000, 2000)), false));
        assert_eq!(get("0:0").unwrap(), (Some((0, 0)), false));
        assert_eq!(get("0").unwrap(), (None, true));
        assert_eq!(get("1000").unwrap(), (None, true));
        assert_eq!(get("app").unwrap(), (None, true));
        assert_eq!(get("app:staff").unwrap(), (None, true));
        assert_eq!(get("1000:staff").unwrap(), (None, true));
        assert_eq!(
            get("4294967296:0").unwrap_err().code(),
            crate::error::CriErrorCode::InvalidArgument
        );
        assert_eq!(get("4294967295:1").unwrap(), (Some((u32::MAX, 1)), false));
    }

    /// OCI-1・CRI-2（#2771）: StopSignal が `ImageDefaults.stop_signal` へ写り、不正な値は INVALID_ARGUMENT。
    #[test]
    fn oci1_image_stop_signal_conversion() {
        use crate::runtime::v1::Signal;
        let get = |sig: &str| {
            let body = format!(r#"{{"config":{{"StopSignal":"{sig}"}}}}"#);
            let p =
                fandhe_container_oci::config::parse_image_config_process(body.as_bytes()).unwrap();
            defaults_from(&p).map(|d| d.stop_signal)
        };
        assert_eq!(get("").unwrap(), None);
        assert_eq!(get("SIGINT").unwrap(), Some(Signal::Sigint));
        assert_eq!(get("37").unwrap(), Some(Signal::Sigrtminplus3));
        assert_eq!(
            get("SIGFOO").unwrap_err().code(),
            crate::error::CriErrorCode::InvalidArgument
        );
        assert_eq!(
            get("32").unwrap_err().code(),
            crate::error::CriErrorCode::InvalidArgument
        );
    }

    /// CRI-2: WorkingDir は末尾の `/` を 1 つ除く。ルートと空は別扱い。
    #[test]
    fn cri2_image_working_dir_normalization() {
        let get = |w: &str| defaults_from(&process("", w)).unwrap().working_dir;
        assert_eq!(get(""), None);
        assert_eq!(get("/"), Some("/".to_owned()));
        assert_eq!(get("/srv/"), Some("/srv".to_owned()));
        assert_eq!(get("/srv"), Some("/srv".to_owned()));
        assert_eq!(get("rel"), Some("rel".to_owned()));
    }

    /// 上限定数は bundle 変換（spec.rs）と oci の config 解析で同値（依存の向きのため 2 か所で持つ）。
    #[test]
    fn cri2_process_limits_match_bundle_limits() {
        use fandhe_container_oci::config as c;
        assert_eq!(c::MAX_PROCESS_ITEMS, super::super::spec::MAX_ARGS);
        assert_eq!(c::MAX_PROCESS_ITEMS, super::super::spec::MAX_ENV);
        assert_eq!(
            c::MAX_PROCESS_STRING_BYTES,
            super::super::spec::MAX_STRING_BYTES
        );
        assert_eq!(
            c::MAX_PROCESS_PATH_BYTES,
            super::super::spec::MAX_PATH_BYTES
        );
    }

    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    fn lookup_rootfs(passwd: Option<&str>, group: Option<&str>) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU32, Ordering};
        static N: AtomicU32 = AtomicU32::new(0);
        let r = std::env::temp_dir().join(format!(
            "fc-cri-user-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&r);
        std::fs::create_dir_all(r.join("etc")).unwrap();
        if let Some(p) = passwd {
            std::fs::write(r.join("etc/passwd"), p).unwrap();
        }
        if let Some(g) = group {
            std::fs::write(r.join("etc/group"), g).unwrap();
        }
        r
    }

    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    const PASSWD: &str = "# c\nroot:x:0:0:r:/root:/bin/sh\n+@nis\nbad:x:zz:1\nshort:x\napp:x:1000:1001::/h:/bin/sh\napp:x:2000:2001::/h:/bin/sh\n";
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    const GROUP: &str = "root:x:0:\nstaff:x:50:app\nbad:x:q:\n";

    /// CRI-2・SEC-1（#2818）: `proc` が無ければ作り、あれば（symlink でも）触らない。
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[test]
    fn cri2_ensure_mountpoints_creates_proc_only_when_absent() {
        let r = lookup_rootfs(None, None);
        ensure_mountpoints(&r).unwrap();
        assert!(r.join("proc").is_dir());
        std::fs::remove_dir(r.join("proc")).unwrap();
        std::os::unix::fs::symlink("/proc", r.join("proc")).unwrap();
        ensure_mountpoints(&r).unwrap();
        assert!(
            std::fs::symlink_metadata(r.join("proc"))
                .unwrap()
                .file_type()
                .is_symlink()
        );
        let _ = std::fs::remove_dir_all(&r);
    }

    /// CRI-2・SEC-5: 名前・uid のみ・名前つきの組の解決表（具体値）。
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[test]
    fn cri2_image_user_name_resolution_table() {
        let r = lookup_rootfs(Some(PASSWD), Some(GROUP));
        let get = |u: &str| resolve_user(&r, &parse_user_lookup(u).unwrap());
        assert_eq!(get("app"), Some((1000, 1001)));
        assert_eq!(get("app:staff"), Some((1000, 50)));
        assert_eq!(get("app:60"), Some((1000, 60)));
        assert_eq!(get("1000:staff"), Some((1000, 50)));
        assert_eq!(get("1000"), Some((1000, 1001)));
        assert_eq!(get("0"), Some((0, 0)));
        assert_eq!(get("4242"), Some((4242, 0)));
        assert_eq!(get("nobody"), None);
        assert_eq!(get("app:nogroup"), None);
        assert_eq!(get("bad"), None);
        let _ = std::fs::remove_dir_all(&r);
    }

    /// REPAIR-5・SEC-5: 行数上限を超える passwd は切り捨てず未解決（後続行の gid を落として 0 にしない）。
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[test]
    fn repair5_passwd_over_line_limit_is_unresolved() {
        let body = format!(
            "{}app:x:1000:1001::/h:/bin/sh\n",
            "\n".repeat(MAX_ETC_LINES)
        );
        let r = lookup_rootfs(Some(&body), None);
        assert_eq!(resolve_user(&r, &parse_user_lookup("1000").unwrap()), None);
        assert_eq!(resolve_user(&r, &parse_user_lookup("app").unwrap()), None);
        let _ = std::fs::remove_dir_all(&r);
    }

    /// SEC-1: passwd が無いと uid のみは gid 0、名前は未解決。passwd が symlink なら uid のみも未解決。
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[test]
    fn sec1_missing_or_symlinked_passwd() {
        let r = lookup_rootfs(None, None);
        assert_eq!(
            resolve_user(&r, &parse_user_lookup("1000").unwrap()),
            Some((1000, 0))
        );
        assert_eq!(resolve_user(&r, &parse_user_lookup("app").unwrap()), None);
        std::os::unix::fs::symlink("/etc/passwd", r.join("etc/passwd")).unwrap();
        assert_eq!(resolve_user(&r, &parse_user_lookup("1000").unwrap()), None);
        assert_eq!(resolve_user(&r, &parse_user_lookup("root").unwrap()), None);
        let _ = std::fs::remove_dir_all(&r);
    }

    /// passwd 側の名前長の上限が CRI の変換側の上限と一致することを固定する。
    #[test]
    fn cri2_username_limit_matches_spec() {
        assert_eq!(MAX_NAME_BYTES, super::super::spec::MAX_USERNAME_BYTES);
    }

    /// CRI-2・SEC-5: run_as_username の解決（具体値とエラーコード）。
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[test]
    fn cri2_run_as_username_resolution() {
        use crate::error::CriErrorCode as C;
        let r = lookup_rootfs(Some(PASSWD), None);
        assert_eq!(resolve_run_as_username(&r, "app").unwrap(), (1000, 1001));
        assert_eq!(resolve_run_as_username(&r, "root").unwrap(), (0, 0));
        for bad in ["ghost", "bad"] {
            assert_eq!(
                resolve_run_as_username(&r, bad).unwrap_err().code(),
                C::InvalidArgument
            );
        }
        for bad in ["1000", "a:b", "a/b"] {
            assert_eq!(
                resolve_run_as_username(&r, bad).unwrap_err().code(),
                C::InvalidArgument
            );
        }
        assert_eq!(
            resolve_run_as_username(&r, &"a".repeat(MAX_NAME_BYTES + 1))
                .unwrap_err()
                .code(),
            C::InvalidArgument
        );
        let _ = std::fs::remove_dir_all(&r);
        let r = lookup_rootfs(None, None);
        assert_eq!(
            resolve_run_as_username(&r, "app").unwrap_err().code(),
            C::InvalidArgument
        );
        std::os::unix::fs::symlink("/etc/passwd", r.join("etc/passwd")).unwrap();
        assert_eq!(
            resolve_run_as_username(&r, "root").unwrap_err().code(),
            C::FailedPrecondition
        );
        let _ = std::fs::remove_dir_all(&r);
        let body = format!(
            "{}app:x:1000:1001::/h:/bin/sh\n",
            "\n".repeat(MAX_ETC_LINES)
        );
        let r = lookup_rootfs(Some(&body), None);
        assert_eq!(
            resolve_run_as_username(&r, "app").unwrap_err().code(),
            C::FailedPrecondition
        );
        let _ = std::fs::remove_dir_all(&r);
    }

    /// 形式の検証: 名前の禁止文字・長さ・`:` 過多は解決対象にしない。
    #[test]
    fn cri2_user_lookup_parse_rejects_malformed() {
        assert!(parse_user_lookup("a:b:c").is_none());
        assert!(parse_user_lookup(&"a".repeat(MAX_NAME_BYTES + 1)).is_none());
        assert!(parse_user_lookup("a/b").is_none());
        assert!(parse_user_lookup(":1").is_none());
        assert_eq!(
            parse_user_lookup("app:staff"),
            Some(UserLookup {
                user: IdPart::Name("app".into()),
                group: Some(IdPart::Name("staff".into()))
            })
        );
    }

    const GROUPS_PASSWD: &str =
        "root:x:0:0:r:/root:/bin/sh\napp:x:1000:1001::/h:/bin/sh\nother:x:2000:2000::/h:/bin/sh\n";
    const GROUPS_GROUP: &str = "root:x:0:app\nwheel:x:10:root,app\napp:x:1001:app\nstaff:x:50:other,app\nbad:x:q:app\nshort:x\nwheel2:x:10:app\n";

    /// CRI-2・SEC-5（#2667）: 所属グループは第 4 フィールドにユーザー名を含む行の gid を行順に集め、同名のグループ・
    /// 形式の崩れた行・重複する gid は除く。
    #[test]
    fn cri2_group_memberships_table() {
        let body = GROUPS_GROUP.as_bytes();
        assert_eq!(group_memberships(body, "app"), vec![0, 10, 50]);
        assert_eq!(group_memberships(body, "other"), vec![50]);
        assert_eq!(group_memberships(body, "nobody"), Vec::<u32>::new());
        assert_eq!(
            passwd_name_of(GROUPS_PASSWD.as_bytes(), 1000),
            Some("app".to_owned())
        );
        assert_eq!(passwd_name_of(GROUPS_PASSWD.as_bytes(), 7), None);
    }

    /// CRI-2・SEC-5（#2667）: 空名の passwd 行は採用せず、空の検索名は `root:x:0:` のような空メンバー行に
    /// 一致させない（gid 0 の混入を防ぐ）。
    #[test]
    fn cri2_empty_user_name_never_matches_groups() {
        let passwd = ":x:1000:1000::/:/bin/sh\n";
        assert_eq!(passwd_name_of(passwd.as_bytes(), 1000), None);
        let group = b"root:x:0:\nwheel:x:10:app\n";
        assert_eq!(group_memberships(group, ""), Vec::<u32>::new());
        assert_eq!(group_memberships(group, "app"), vec![10]);
    }

    /// CRI-2・SEC-5（#2667）: 実効ユーザーと rootfs の `/etc/group` からイメージ由来の補助グループを求める。
    /// 名前は username → run_as_user（passwd を uid で引く）→ イメージ User の順。uid 0 は group を読まない。
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[test]
    fn cri2_resolve_image_groups_table() {
        use crate::error::CriErrorCode as C;
        let r = lookup_rootfs(Some(GROUPS_PASSWD), Some(GROUPS_GROUP));
        let none = UserResolveRequest::none();
        let img = |uid: u32| ImageDefaults {
            user: Some((uid, uid)),
            ..Default::default()
        };
        // イメージ User が名前形式。
        assert_eq!(
            resolve_image_groups(&r, &none, "app", &img(1000)).unwrap(),
            vec![0, 10, 50]
        );
        // イメージ User が uid 形式 -> passwd を uid で引く。
        assert_eq!(
            resolve_image_groups(&r, &none, "1000:1001", &img(1000)).unwrap(),
            vec![0, 10, 50]
        );
        // run_as_user が優先（イメージ User は無視）。
        let req = UserResolveRequest::none().with_run_as_user(2000);
        assert_eq!(
            resolve_image_groups(&r, &req, "app", &img(1000)).unwrap(),
            vec![50]
        );
        // run_as_username（解決済み）。
        let req = UserResolveRequest::with_run_as_username("other");
        let d = ImageDefaults {
            resolved_run_as_username: Some((2000, 2000)),
            ..Default::default()
        };
        assert_eq!(resolve_image_groups(&r, &req, "", &d).unwrap(), vec![50]);
        // passwd に uid が無い・イメージ User が無い -> 空。
        let req = UserResolveRequest::none().with_run_as_user(7);
        assert!(
            resolve_image_groups(&r, &req, "", &img(1000))
                .unwrap()
                .is_empty()
        );
        assert!(
            resolve_image_groups(&r, &none, "", &ImageDefaults::default())
                .unwrap()
                .is_empty()
        );
        // uid 0 は読まない（group が symlink でもエラーにならない）。
        let _ = std::fs::remove_dir_all(&r);
        let r = lookup_rootfs(Some(GROUPS_PASSWD), None);
        std::os::unix::fs::symlink("/etc/passwd", r.join("etc/group")).unwrap();
        assert!(
            resolve_image_groups(&r, &none, "root", &img(0))
                .unwrap()
                .is_empty()
        );
        // 非 root で group が symlink -> FAILED_PRECONDITION。
        assert_eq!(
            resolve_image_groups(&r, &none, "app", &img(1000))
                .unwrap_err()
                .code(),
            C::FailedPrecondition
        );
        let _ = std::fs::remove_dir_all(&r);
        // group が無い -> 空。
        let r = lookup_rootfs(Some(GROUPS_PASSWD), None);
        assert!(
            resolve_image_groups(&r, &none, "app", &img(1000))
                .unwrap()
                .is_empty()
        );
        let _ = std::fs::remove_dir_all(&r);
    }
}
