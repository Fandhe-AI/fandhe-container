//! 範囲写像のレイヤー展開を、再 exec helper の展開モードで行う本番の展開器（Linux x86_64 / aarch64。
//! SEC-5・OCI-1・OCI-7・CORE-6・REPAIR-4・REPAIR-5。#4848。親 issue #4777）。
//!
//! `fandhe-container-cri` の注入点 [`SubordinateLayerExtractor`] の本番実装 [`UsernsLayerExtractor`]。呼び出し元は cri の
//! `OciImagePuller`（pull の `unpack/entry/rootfs`）と `ImageRootfsSource`（create の bundle `rootfs/`）で、展開設定が
//! `ChownInUserNamespace` のときだけ呼ばれる（範囲写像の行で通る。対応表の切り替えは H6・#4801 で有効化済み）。
//! CRI の worker スレッド・pull の blocking 区間から同期で呼ばれ、helper（[`UsernsHelperLauncher`]）を 1 回起動して
//! [`UsernsHelperLauncher::run_extract_bounded`] で展開させる。blob と展開先は fd で渡し（パスは渡さない）、写像は送らず
//! helper が参加に使ったものを使う（#4847 の契約）。
//!
//! # 契約
//! - 縮退しない: 失敗・期限切れはホスト側の展開へ落とさず、固定文言の [`OciError`] で返す（パス・errno・uid を含めない）
//! - spawn の前の拒否（副作用なし）: 展開設定が `ChownInUserNamespace` でない・特殊ビットが `Strip` / `PreserveIfChowned`
//!   以外・対応表に無い mediaType・要求の範囲違反
//! - 期限（REPAIR-5）・同時実行の上限（待たずに `Unavailable`）・回収できなかった子の保持は削除器と同じ（`slots`）。
//!   上限は削除器とは別に持ち、長い展開が削除を詰まらせない
//! - `Err` のとき展開先は途中まで書かれている。呼び出し側が破棄する（oci の契約と同じ）

use std::sync::{Arc, OnceLock};

use fandhe_container_core::traits::ErrorCode;
use fandhe_container_cri::adapter::ReleaseBudget;
use fandhe_container_cri::bundle::SubordinateLayerExtractor;
use fandhe_container_oci::error::{OciError, OciErrorCode};
use fandhe_container_oci::layer::extract::{
    ExtractLimits, ExtractOptions, ExtractRoot, ImageLayer, OwnershipPolicy, SpecialBitsPolicy,
};

use super::launcher::{UsernsHelperError, UsernsHelperLauncher};
use super::slots::{HelperSlots, work_budget_for};
use super::wire::{ExtractLayerSpec, ExtractRequest, ExtractSpecialBits, HelperErrorCode};

/// 同時に動かす展開の上限（稼働中の helper + 回収できていない子の合計）。
pub const MAX_CONCURRENT_EXTRACTIONS: usize = 4;

/// 本番の展開器。プロセスで 1 つ（[`UsernsLayerExtractor::shared`]）を pull 側と create 側が共有し、上限を 1 つにする。
pub struct UsernsLayerExtractor {
    launcher: UsernsHelperLauncher,
    slots: HelperSlots,
}

impl std::fmt::Debug for UsernsLayerExtractor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UsernsLayerExtractor")
            .field("max", &self.slots.max)
            .finish_non_exhaustive()
    }
}

impl UsernsLayerExtractor {
    /// plugin-cri 自身を helper として再 exec する展開器。
    pub fn new() -> Self {
        Self::build(UsernsHelperLauncher::new(), MAX_CONCURRENT_EXTRACTIONS)
    }

    /// プロセス共有の展開器（pull 側・create 側で同じ上限を使う）。
    pub fn shared() -> Arc<Self> {
        static SHARED: OnceLock<Arc<UsernsLayerExtractor>> = OnceLock::new();
        Arc::clone(SHARED.get_or_init(|| Arc::new(Self::new())))
    }

    /// 起動役と上限を差し替える（試験専用の偽 helper・上限の試験）。
    #[cfg(any(test, feature = "userns-helper-test-support"))]
    pub fn with_launcher_and_limit(launcher: UsernsHelperLauncher, max: usize) -> Self {
        Self::build(launcher, max)
    }

    fn build(launcher: UsernsHelperLauncher, max: usize) -> Self {
        Self {
            launcher,
            slots: HelperSlots::new(max),
        }
    }
}

impl Default for UsernsLayerExtractor {
    fn default() -> Self {
        Self::new()
    }
}

/// 展開設定の特殊ビットを wire の語彙へ写す。写像を伴う `PreserveIfOwnerMapped` と未知の値は拒否する（fail-closed）。
fn wire_special_bits(p: &SpecialBitsPolicy) -> Result<ExtractSpecialBits, OciError> {
    match p {
        SpecialBitsPolicy::Strip => Ok(ExtractSpecialBits::Strip),
        SpecialBitsPolicy::PreserveIfChowned => Ok(ExtractSpecialBits::PreserveIfChowned),
        _ => Err(OciError::new(
            OciErrorCode::FailedPrecondition,
            "special bits policy is not supported by the userns helper",
        )),
    }
}

/// helper の失敗の分類を oci の分類へ写す（固定文言。パス・errno・uid を含めない。REPAIR-4）。
fn map_error(e: &UsernsHelperError) -> OciError {
    if let Some(HelperErrorCode::ExtractFailed(c)) = e.helper_code() {
        return OciError::new(c, "layer extraction in the userns helper failed");
    }
    let (code, msg) = match e.code() {
        ErrorCode::Timeout => (
            OciErrorCode::Timeout,
            "subordinate-owned layer extraction exceeded its deadline",
        ),
        ErrorCode::FailedPrecondition => (
            OciErrorCode::FailedPrecondition,
            "subordinate-owned layer extraction was refused",
        ),
        ErrorCode::Unavailable => (OciErrorCode::Unavailable, "userns helper is unavailable"),
        ErrorCode::InvalidArgument => (
            OciErrorCode::InvalidArgument,
            "subordinate-owned layer extraction request is invalid",
        ),
        ErrorCode::Unimplemented => (
            OciErrorCode::Unimplemented,
            "subordinate-owned layer extraction is not supported",
        ),
        ErrorCode::ResourceExhausted => (
            OciErrorCode::ResourceExhausted,
            "subordinate-owned layer extraction exceeded a limit",
        ),
        _ => (
            OciErrorCode::Internal,
            "subordinate-owned layer extraction failed",
        ),
    };
    OciError::new(code, msg)
}

impl SubordinateLayerExtractor for UsernsLayerExtractor {
    fn extract_layers(
        &self,
        layers: &[ImageLayer<'_>],
        root: &ExtractRoot,
        max_uncompressed_layer_bytes: u64,
        limits: ExtractLimits,
        options: &ExtractOptions,
        budget: &ReleaseBudget<'_>,
    ) -> Result<(), OciError> {
        // 期限切れ・取り消しなら起動しない（副作用なし）。
        if budget.check().is_err() {
            return Err(OciError::new(
                OciErrorCode::Timeout,
                "subordinate-owned layer extraction exceeded its deadline",
            ));
        }
        // 写像そのものは送らない（helper が参加に使ったものを使う）が、展開設定の写像の指紋を送り、helper が参加した写像と
        // 照合させる（SEC-5。ずれたら書き込みの前に `FailedPrecondition`）。範囲写像の展開設定だけを受ける。
        let OwnershipPolicy::ChownInUserNamespace { uid, gid } = &options.ownership else {
            return Err(OciError::new(
                OciErrorCode::FailedPrecondition,
                "ownership policy is not a subordinate-id extraction",
            ));
        };
        let special_bits = wire_special_bits(&options.special_bits)?;
        let specs = layers
            .iter()
            .map(|l| {
                ExtractLayerSpec::new(
                    l.media_type,
                    l.blob.size(),
                    l.blob.digest().clone(),
                    l.diff_id.clone(),
                )
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(|c| match c {
                HelperErrorCode::Unimplemented => OciError::new(
                    OciErrorCode::Unimplemented,
                    "layer media type is not supported by the userns helper",
                ),
                _ => OciError::new(
                    OciErrorCode::InvalidArgument,
                    "layer descriptor is invalid for the userns helper",
                ),
            })?;
        let request =
            ExtractRequest::new(special_bits, limits, max_uncompressed_layer_bytes, specs)
                .map_err(|_| {
                    OciError::new(
                        OciErrorCode::InvalidArgument,
                        "layer extraction request is out of range",
                    )
                })?
                .with_expected_maps(uid, gid);
        let work = work_budget_for(budget.deadline).ok_or_else(|| {
            OciError::new(
                OciErrorCode::Internal,
                "failed to compute the extraction budget",
            )
        })?;
        let slot = self.slots.acquire().ok_or_else(|| {
            OciError::new(
                OciErrorCode::Unavailable,
                "too many subordinate-owned layer extractions in progress",
            )
        })?;
        let blobs: Vec<_> = layers.iter().map(|l| l.blob.as_fd()).collect();
        match self.launcher.run_extract_bounded(
            &request,
            &blobs,
            root.as_fd(),
            work,
            budget.deadline,
            budget.cancel,
        ) {
            Ok(report) if usize::try_from(report.layers).is_ok_and(|n| n == layers.len()) => Ok(()),
            Ok(_) => Err(OciError::new(
                OciErrorCode::Internal,
                "userns helper returned an unexpected report",
            )),
            Err(mut e) => {
                if let Some(child) = e.take_unreaped() {
                    self.slots.keep(child, slot);
                }
                Err(map_error(&e))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    use std::sync::atomic::Ordering;
    use std::time::{Duration, Instant};

    use fandhe_container_oci::layer::VerifiedLayerBlob;
    use fandhe_container_oci::layer::extract::{IdMap, IdRange};
    use fandhe_container_oci::reference::Digest;

    use super::super::launcher::JOIN_BUDGET;
    use super::*;

    const TAR: &str = "application/vnd.oci.image.layer.v1.tar";

    /// 自分所有の 0600 の blob ファイルから検証済み blob を作る。
    fn blob(dir: &std::path::Path, bytes: &[u8]) -> (VerifiedLayerBlob, Digest) {
        let p = dir.join("blob");
        std::fs::write(&p, bytes).expect("write");
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).expect("chmod");
        let d = Digest::sha256_of(bytes);
        let owner = std::fs::metadata(&p).expect("meta").uid();
        let size = u64::try_from(bytes.len()).expect("len");
        let v = VerifiedLayerBlob::from_file(File::open(&p).expect("open"), &d, size, owner)
            .expect("verified");
        (v, d)
    }

    fn userns_options() -> ExtractOptions {
        let map = IdMap::new(vec![IdRange {
            container_id: 0,
            host_id: 100_000,
            count: 65_536,
        }])
        .expect("map");
        ExtractOptions::new().with_ownership(OwnershipPolicy::ChownInUserNamespace {
            uid: map.clone(),
            gid: map,
        })
    }

    fn sleeper(max: usize) -> UsernsLayerExtractor {
        UsernsLayerExtractor::with_launcher_and_limit(
            UsernsHelperLauncher::with_fixed_command("/bin/sleep", vec!["60".into()])
                .with_join_budget(Duration::ZERO),
            max,
        )
    }

    fn nonexistent() -> UsernsLayerExtractor {
        UsernsLayerExtractor::with_launcher_and_limit(
            UsernsHelperLauncher::with_fixed_command("/nonexistent/helper", vec![]),
            MAX_CONCURRENT_EXTRACTIONS,
        )
    }

    struct Fixture {
        dir: std::path::PathBuf,
        blob: VerifiedLayerBlob,
        diff: Digest,
        root: ExtractRoot,
    }

    fn fixture(tag: &str) -> Fixture {
        let dir = std::env::temp_dir().join(format!("extractor-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).expect("mkdir");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        let (blob, diff) = blob(&dir, b"layer bytes");
        let root = ExtractRoot::create_private_dir(&dir.join("root")).expect("root");
        Fixture {
            dir,
            blob,
            diff,
            root,
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn run(
        ex: &UsernsLayerExtractor,
        f: &Fixture,
        media: &str,
        opts: &ExtractOptions,
        budget: &ReleaseBudget<'_>,
    ) -> Result<(), OciError> {
        let layers = [ImageLayer::new(&f.blob, media, &f.diff)];
        ex.extract_layers(
            &layers,
            &f.root,
            fandhe_container_oci::layer::DEFAULT_MAX_UNCOMPRESSED_LAYER_BYTES,
            ExtractLimits::default(),
            opts,
            budget,
        )
    }

    /// SEC-5・#4848: 範囲写像でない展開設定・写像を伴う特殊ビット・表に無い mediaType は、spawn の前に拒否する
    /// （存在しない実行ファイルでも `Unavailable` にならない）。
    #[test]
    fn sec5_4848_unsupported_inputs_are_rejected_before_spawn() {
        let f = fixture("reject");
        let ex = nonexistent();
        let b = ReleaseBudget::new();
        let keep = ExtractOptions::new();
        assert_eq!(
            run(&ex, &f, TAR, &keep, &b).expect_err("keep").code(),
            OciErrorCode::FailedPrecondition
        );
        let id = IdRange {
            container_id: 0,
            host_id: 1000,
            count: 1,
        };
        let mut owner_mapped = userns_options();
        owner_mapped.special_bits = SpecialBitsPolicy::PreserveIfOwnerMapped { uid: id, gid: id };
        assert_eq!(
            run(&ex, &f, TAR, &owner_mapped, &b)
                .expect_err("owner mapped")
                .code(),
            OciErrorCode::FailedPrecondition
        );
        assert_eq!(
            run(&ex, &f, "application/x-unknown", &userns_options(), &b)
                .expect_err("media")
                .code(),
            OciErrorCode::Unimplemented
        );
    }

    /// REPAIR-5・SEC-5・#4848: 応答しない helper は期限で `Timeout` になり、子は回収されて枠が戻る。
    #[test]
    fn sec5_4848_extractor_timeout_reaps_the_child_and_releases_the_slot() {
        let f = fixture("timeout");
        let ex = sleeper(MAX_CONCURRENT_EXTRACTIONS);
        let started = Instant::now();
        let e = run(
            &ex,
            &f,
            TAR,
            &userns_options(),
            &ReleaseBudget::new()
                .with_deadline(Instant::now() + JOIN_BUDGET + Duration::from_secs(1)),
        )
        .expect_err("must time out");
        assert_eq!(e.code(), OciErrorCode::Timeout);
        assert!(started.elapsed() < Duration::from_secs(10));
        assert_eq!(ex.slots.unreaped.lock().unwrap().len(), 0);
        assert_eq!(ex.slots.active.load(Ordering::Acquire), 0);
    }

    /// REPAIR-5・#4848: 上限に達していれば待たずに `Unavailable`。取っていない枠は返さない。
    #[test]
    fn sec5_4848_extractor_over_the_limit_is_unavailable() {
        let f = fixture("limit");
        let ex = sleeper(2);
        ex.slots.active.fetch_add(2, Ordering::AcqRel);
        let started = Instant::now();
        let e = run(&ex, &f, TAR, &userns_options(), &ReleaseBudget::new()).expect_err("limit");
        assert_eq!(e.code(), OciErrorCode::Unavailable);
        assert!(started.elapsed() < Duration::from_secs(1));
        assert_eq!(ex.slots.active.load(Ordering::Acquire), 2);
    }

    /// REPAIR-5・#4848: 期限切れの予算では helper を起動せず `Timeout`（副作用なし）。
    #[test]
    fn sec5_4848_extractor_expired_budget_does_not_spawn() {
        let f = fixture("expired");
        let ex = nonexistent();
        let e = run(
            &ex,
            &f,
            TAR,
            &userns_options(),
            &ReleaseBudget::new().with_deadline(Instant::now()),
        )
        .expect_err("expired");
        assert_eq!(e.code(), OciErrorCode::Timeout);
    }
}
