//! pull 時の展開の所有者（`OwnershipPolicy`）を、start と同じ所有者の解決結果から作る変換
//! （SEC-5・CORE-6・OCI-1・REPAIR-1・#4798。判断は #4777 の判断事項 2）。
//!
//! # 役割
//! plugin-cri の本番の展開（helper 入口 H1・ずれの照合 H5 が使う部品）が cli に依存せずに、cli の
//! `crates/cli/src/image_ownership.rs` と同じ変換を使うための複製。core の `IdMapSet`（範囲写像は
//! `resolve_id_maps`、1 対 1 は `single_id_mapping`）を oci の `IdMap` へ移し（oci は core に依存しない）、
//! `ExtractChownMode` で `ChownMapped` / `ChownInUserNamespace` を選ぶ。passwd からの所有者解決
//! （cli の `resolve_extract_ownership`）は呼び出し元が出てから足す。
//!
//! # 一致の担保
//! cli 側と本ファイルの変換は共有 fixture `crates/core/testdata/image_ownership_cases.txt` で照合する
//! （`tests/image_ownership_fixture.rs`。cli 側も同じ照合ドライバを取り込む）。片方だけ直すと落ちる。
//!
//! # 未配線（REPAIR-3）
//! 本番の呼び出し元はまだ無い。エラー文言は固定の英語で、パス・ユーザー名・errno を含めない。

use fandhe_container_core::oci_runtime::SubordinateIdSource;
use fandhe_container_core::rootless::{IdMapSet, single_id_mapping};
use fandhe_container_core::traits::{ErrorCode, TraitError};
use fandhe_container_oci::error::OciErrorCode;
use fandhe_container_oci::layer::extract::OwnershipPolicy;
use fandhe_container_oci::layer::idmap::{IdMap, IdRange};
use fandhe_container_supervisor::id_model::RootlessIdResolution;

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
