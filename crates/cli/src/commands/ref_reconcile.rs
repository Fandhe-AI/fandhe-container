//! コンテナ参照の照合と回収の起動点（OCI-7・OCI-5・CLI-1・CORE-1・#2495）。
//!
//! # 役割と呼び出し元
//!
//! create / delete が残した参照（`@container-refs.json`）のうち、状態の無いものを回収する。oci の部品
//! （`release_container_ref_if`・`release_unbound_container_ref_quiesced`・`reconcile_container_refs_quiesced`）
//! は core に依存できないため `StateStore` を直接受けず、本 module が `StateStore::get` の結果を
//! 照合用の probe へ写して橋渡しする（cli は oci と core の両方に依存できる。`image_refs` と同じ理由）。
//! 常駐デーモンの無い CLI（CORE-1）に「起動時に 1 回」は無いため、起動点は次の 2 つ。
//!
//! - 契機 A: `create --image-root --image` の core 呼び出し前（[`reclaim_stale_ref_for_create`]）。同じ参照キー 1 件
//! - 契機 B: `image rm` が使用中で拒否したとき（[`reconcile_in_use`]）。拒否に載った参照のうち現在の状態ルートのもの
//!
//! 未確定参照の回収は create ゲートの排他の下（`ImageStore::quiesce_container_creates`）に限る。排他が取れない
//! （進行中の create がある・期限切れ）ときは回収せず、余分に残す側に誤る（OCI-7）。設計は
//! `docs/design/container-ref-reconcile.md`。
//!
//! # 回収する条件
//!
//! 状態が `NotFound` と確認できた参照だけを外す。状態が存在する・読めない（`Timeout`・`Internal` 等）は残す。
//! 状態が存在して未確定の参照は昇格させない（オーナー確認待ち）。状態の削除後に「未確定かつ状態なし」になり回収される。
//!
//! # 制約（実装済みを装わない。REPAIR-3）
//!
//! - 畳んだ参照キー（223 バイト以上の ID の `<scope>-<hash>`）は元の ID を復元できないため、契機 B では回収しない
//!   （契機 A は元の ID を知っているので回収できる。キー形式は #2500）
//! - `image prune` の CLI は未配線。配線時に同じ契機 B のヘルパーを呼ぶ
//! - 結果は stderr へ出さない（OCI create / delete 互換の無出力を保つ）。計測（REPAIR-4）へ記録する

use std::collections::BTreeSet;
use std::time::Instant;

use fandhe_container_core::observability::OpRecorder;
use fandhe_container_core::traits::{
    ContainerId, ErrorCode, GetStateRequest, StateRecord, StateStore, TraitError,
};
use fandhe_container_oci::image_management::{
    ContainerRefGeneration, ContainerRefId, ContainerRefReconciliation, ContainerRefRelease,
    ContainerStatePresence, ImageStore,
};

use super::args::GlobalArgs;
use super::create_start::{OP_LOG_ENV, export_ops, open_store};
use super::image_refs::{ref_key, state_scope};
use super::list_logs::record_op;

/// 契機 B で 1 回に状態を読む参照の上限（ゲートの排他を長く握らない。REPAIR-5）。超過分は判定不能として残す。
pub(super) const MAX_RECONCILE_PROBES: usize = 256;

/// `StateStore::get` の結果を probe の 3 値へ写す。`Absent` は `NotFound` だけから作る（OCI-7）。
pub(super) fn presence_of(result: &Result<StateRecord, TraitError>) -> ContainerStatePresence {
    match result {
        Ok(_) => ContainerStatePresence::Present,
        Err(e) if e.code() == ErrorCode::NotFound => ContainerStatePresence::Absent,
        // Timeout・Internal・PermissionDenied・Unimplemented・Unavailable 等は確認できなかった扱い。
        Err(_) => ContainerStatePresence::Undetermined,
    }
}

/// 参照キーを現在の状態ルートの `scope` のコンテナ ID に戻す。他 scope・畳んだ形・不正は `None`。
fn id_of_key(scope: &str, key: &ContainerRefId) -> Option<ContainerId> {
    let rest = key.as_str().strip_prefix(scope)?.strip_prefix('.')?;
    let id = ContainerId::new(rest).ok()?;
    // 往復して同じキーになるものだけ（畳んだ形と衝突しない）。
    (ref_key(scope, id.as_str()) == key.as_str()).then_some(id)
}

/// 参照キーの状態の有無を調べる。解析できないキーは状態ストアを読まず `Undetermined`。
fn probe_key(state: &dyn StateStore, scope: &str, key: &ContainerRefId) -> ContainerStatePresence {
    match id_of_key(scope, key) {
        Some(id) => presence_of(&state.get(&GetStateRequest::new(id))),
        None => ContainerStatePresence::Undetermined,
    }
}

/// 契機 A の結果（将来の拡張に備え非網羅）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub(super) enum StaleRefOutcome {
    /// 参照が無かった。
    NotRegistered,
    /// 確定済みの残骸（状態なし）を外した。
    ReclaimedBound(ContainerRefGeneration),
    /// 未確定の残骸（状態なし）を外した。
    ReclaimedUnbound(ContainerRefGeneration),
    /// 状態があるため残した。
    KeptPresent,
    /// 状態を確認できないため残した。
    KeptUndetermined,
    /// 進行中の create があり（または期限切れで）未確定参照を回収できなかった。
    Busy,
    /// 参照テーブルの読み取りなどが失敗した（判定は core の `register` に任せる）。
    Failed(ErrorCode),
}

impl StaleRefOutcome {
    /// 計測に記録する成否（回収の不能・保留は失敗ではない）。
    fn is_failure(&self) -> bool {
        matches!(self, Self::Failed(_))
    }
}

/// 同じ参照キー 1 件の残骸を回収する（契機 A。create の core 呼び出し前）。
///
/// 手順: 登録を読む → 状態を調べる → 状態なしのときだけ世代つきで外す。未確定はゲート排他を取れたときだけ。
/// 失敗・保留でも create は続行できる（判定は core の `register` と `StateStore::create` が持つ）。
pub(super) fn reclaim_stale_ref_for_create(
    images: &ImageStore,
    state: &dyn StateStore,
    scope: &str,
    id: &ContainerId,
) -> StaleRefOutcome {
    let Ok(key) = ContainerRefId::new(&ref_key(scope, id.as_str())) else {
        return StaleRefOutcome::Failed(ErrorCode::Internal);
    };
    let request = GetStateRequest::new(id.clone());
    let bound = match images.container_ref_registration(&key) {
        Ok(g) => g,
        Err(e) => return StaleRefOutcome::Failed(super::image::map_code(e.code())),
    };
    if let Some(generation) = bound {
        return match presence_of(&state.get(&request)) {
            ContainerStatePresence::Absent => {
                match images.release_container_ref_if(&key, generation) {
                    Ok(ContainerRefRelease::Released(_)) => {
                        StaleRefOutcome::ReclaimedBound(generation)
                    }
                    Ok(_) => StaleRefOutcome::NotRegistered,
                    Err(e) => StaleRefOutcome::Failed(super::image::map_code(e.code())),
                }
            }
            ContainerStatePresence::Present => StaleRefOutcome::KeptPresent,
            _ => StaleRefOutcome::KeptUndetermined,
        };
    }
    let unbound = match images.lock() {
        Ok(g) => g
            .unbound_containers()
            .find(|(k, _, _)| **k == key)
            .map(|(_, generation, _)| generation),
        Err(e) => return StaleRefOutcome::Failed(super::image::map_code(e.code())),
    };
    let Some(generation) = unbound else {
        return StaleRefOutcome::NotRegistered;
    };
    let quiescence = match images.quiesce_container_creates() {
        Ok(Some(q)) => q,
        Ok(None) => return StaleRefOutcome::Busy,
        Err(e) => return StaleRefOutcome::Failed(super::image::map_code(e.code())),
    };
    // 排他を取った後に状態を調べる（進行中の create が無い時点の状態で判定する）。
    match presence_of(&state.get(&request)) {
        ContainerStatePresence::Absent => {
            match images.release_unbound_container_ref_quiesced(&quiescence, &key, generation) {
                Ok(ContainerRefRelease::Released(_)) => {
                    StaleRefOutcome::ReclaimedUnbound(generation)
                }
                Ok(_) => StaleRefOutcome::NotRegistered,
                Err(e) => StaleRefOutcome::Failed(super::image::map_code(e.code())),
            }
        }
        ContainerStatePresence::Present => StaleRefOutcome::KeptPresent,
        _ => StaleRefOutcome::KeptUndetermined,
    }
}

/// `candidates` のうち現在の状態ルートのものを照合して回収する（契機 B）。
///
/// ゲート排他が取れない・照合が失敗したら `None`（何も外さない）。候補集合の外・他 scope・畳んだ形・
/// 上限超過の参照は状態ストアを読まず `Undetermined`（残す）。
pub(super) fn reconcile_in_use(
    images: &ImageStore,
    state: &dyn StateStore,
    scope: &str,
    candidates: &[ContainerRefId],
) -> Option<ContainerRefReconciliation> {
    let quiescence = images.quiesce_container_creates().ok()??;
    let wanted: BTreeSet<&ContainerRefId> = candidates.iter().take(MAX_RECONCILE_PROBES).collect();
    images
        .reconcile_container_refs_quiesced(&quiescence, |key| {
            if wanted.contains(key) {
                probe_key(state, scope, key)
            } else {
                ContainerStatePresence::Undetermined
            }
        })
        .ok()
}

/// 契機 A の本体を呼び、結果を計測へ記録する（`image_ref_reclaim`。REPAIR-4）。
pub(super) fn reclaim_stale_ref_recorded(
    images: &ImageStore,
    state: &dyn StateStore,
    recorder: &OpRecorder,
    scope: &str,
    id: &ContainerId,
) -> StaleRefOutcome {
    let started = Instant::now();
    let outcome = reclaim_stale_ref_for_create(images, state, scope, id);
    record_op(
        recorder,
        "image_ref_reclaim",
        !outcome.is_failure(),
        started,
    );
    outcome
}

/// `image rm` の拒否に載った参照を、グローバル引数の状態ルートで照合する（契機 B の本番入口）。
///
/// 状態ストアを開けない・解決できないときは何もしない（従来どおり拒否に進む）。
pub(super) fn reconcile_for_image_rm(
    global: &GlobalArgs,
    images: &ImageStore,
    candidates: &[ContainerRefId],
) {
    let started = Instant::now();
    let recorder = OpRecorder::new();
    let ok = (|| {
        let state = open_store(global).ok()?;
        let scope = state_scope(&state).ok()?;
        reconcile_in_use(images, &state, &scope, candidates)
    })()
    .is_some();
    record_op(&recorder, "image_ref_reconcile", ok, started);
    export_ops(&recorder, std::env::var_os(OP_LOG_ENV).as_deref());
}

#[cfg(test)]
mod tests;
