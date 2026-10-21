//! pull 時の展開の所有者（`OwnershipPolicy`）を、start と同じ所有者の解決から作るアダプタ
//! （SEC-5・CORE-6・OCI-1・#2389）。
//!
//! # 役割
//! oci の `OwnershipPolicy::ChownMapped` / `ChownInUserNamespace` は「起動時の写像と同じものを渡す」契約だが、
//! 写像を作る部品が start（supervisor → core の本番 launcher）と別々だと所有者が食い違う。本モジュールは
//! 次の 1 本の経路だけを使い、start と展開が同じ解決部品から写像を得るようにする。
//!
//! 1. supervisor `id_model::resolve_rootless_id_source`: passwd（所有者名）→ subuid / subgid の分類 → モデルの選択
//! 2. core `SubordinateIdSource::resolve_id_maps`（範囲写像のとき）/ `rootless::single_id_mapping`（1 対 1 のとき）
//! 3. 本モジュール: core の `IdMapSet` を oci の `IdMap` へ変換する（oci は core に依存しないため cli が橋渡しする。
//!    `commands::image_refs` と同じ位置づけ）
//!
//! 所有者は「展開するプロセス」ではなく「コンテナを start する利用者」の uid / gid で解決する。`ChownMapped` は
//! 初期 user namespace で `CAP_CHOWN` を持つプロセス（典型はホスト root）が展開するため、`/proc/self` の euid を
//! 使うと root になってしまう。このため uid / gid は引数で受け、`/proc/self` を読まない。
//!
//! # 未配線（REPAIR-3）
//! 本番の呼び出し元はまだ無い。`PullImage` / create 経路の展開器（#2377）、rootless の user namespace へ入る配線
//! （#2315・#482）、rootful の start の判断（#2241）が済んでから配線する。今は両者が食い違わないことを
//! `tests/image_ownership_parity.rs` が照合する。
//!
//! エラー文言は固定の英語で、パス・ユーザー名・errno を含めない。

use std::path::Path;

use fandhe_container_core::oci_runtime::SubordinateIdSource;
use fandhe_container_core::rootless::{IdMapSet, single_id_mapping};
use fandhe_container_core::traits::{ErrorCode, TraitError};
use fandhe_container_oci::error::OciErrorCode;
use fandhe_container_oci::layer::extract::OwnershipPolicy;
use fandhe_container_oci::layer::idmap::{IdMap, IdRange};
use fandhe_container_supervisor::id_model::{RootlessIdResolution, resolve_rootless_id_source};

/// 展開の `chown` を行う場所（`OwnershipPolicy` の 2 つの形に対応する）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ExtractChownMode {
    /// 初期 user namespace から `CAP_CHOWN` で `chown` する（`OwnershipPolicy::ChownMapped`）。
    InitialNamespace,
    /// コンテナと同じ写像の user namespace の中で `chown` する（`OwnershipPolicy::ChownInUserNamespace`）。
    InUserNamespace,
}

/// 解決済みの所有者と start する利用者の uid / gid から、展開の所有者の方針を作る。
///
/// 写像の行は start の launcher が使うものと同一（範囲写像は `resolve_id_maps`、1 対 1 は `single_id_mapping`）。
/// uid / gid が 0 の利用者・範囲の不備は start と同じ code で拒否し、1 対 1 へ縮退しない。
pub fn extract_ownership_for(
    resolution: &RootlessIdResolution,
    uid: u32,
    gid: u32,
    mode: ExtractChownMode,
) -> Result<OwnershipPolicy, TraitError> {
    let (uid_set, gid_set) = match resolution {
        RootlessIdResolution::SingleId => (
            single_id_mapping(uid).map_err(|e| TraitError::new(e.code, SINGLE_FAILED))?,
            single_id_mapping(gid).map_err(|e| TraitError::new(e.code, SINGLE_FAILED))?,
        ),
        RootlessIdResolution::SubordinateIds(source) => subordinate_sets(source, uid, gid)?,
    };
    let (uid, gid) = (to_oci_map(&uid_set)?, to_oci_map(&gid_set)?);
    Ok(match mode {
        ExtractChownMode::InitialNamespace => OwnershipPolicy::ChownMapped { uid, gid },
        ExtractChownMode::InUserNamespace => OwnershipPolicy::ChownInUserNamespace { uid, gid },
    })
}

/// passwd / subuid / subgid から所有者を解決し、展開の所有者の方針まで一気に作る。
///
/// 解決は start と同じ `resolve_rootless_id_source`（`real` / `effective` は start する利用者の uid）。
pub fn resolve_extract_ownership(
    real: u32,
    effective: u32,
    gid: u32,
    passwd: &Path,
    subuid: &Path,
    subgid: &Path,
    mode: ExtractChownMode,
) -> Result<OwnershipPolicy, TraitError> {
    let resolution = resolve_rootless_id_source(real, effective, passwd, subuid, subgid)?;
    extract_ownership_for(&resolution, effective, gid, mode)
}

const SINGLE_FAILED: &str = "failed to resolve the single id mapping";

fn subordinate_sets(
    source: &SubordinateIdSource,
    uid: u32,
    gid: u32,
) -> Result<(IdMapSet, IdMapSet), TraitError> {
    let maps = source.resolve_id_maps(uid, gid)?;
    Ok((maps.uid().clone(), maps.gid().clone()))
}

/// core の検証済み写像を oci の `IdMap` へ移す。oci の検証は core より厳しい（ホスト範囲が `u32::MAX` を含む写像を
/// 拒否する）ため失敗しうる。失敗は oci の code を写し、`unwrap` しない。
fn to_oci_map(set: &IdMapSet) -> Result<IdMap, TraitError> {
    let lines = set
        .entries()
        .iter()
        .map(|e| IdRange {
            container_id: e.container_id,
            host_id: e.host_id,
            count: e.count,
        })
        .collect();
    IdMap::new(lines).map_err(|e| {
        let code = match e.code() {
            OciErrorCode::PermissionDenied => ErrorCode::PermissionDenied,
            OciErrorCode::InvalidArgument => ErrorCode::InvalidArgument,
            _ => ErrorCode::Internal,
        };
        TraitError::new(code, "the id mapping cannot be used for layer extraction")
    })
}
