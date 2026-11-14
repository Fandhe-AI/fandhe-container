//! 本番の rootfs 展開設定（`ExtractOptions`）を、start と同じ権限モデルの解決から選ぶ（SEC-5・OCI-1・CRI-2・#2792）。
//!
//! 呼び出し元は [`crate::adapter::CriPluginBackends`] で、`ImageService` の pull（`production_pull_config`）と
//! `CreateContainer` の bundle 供給（`bundle_provider_with`）が **同じ 1 回の解決結果**を使う。pull と create で
//! 展開の設定がずれると、cri の unpack-record 照合が `FAILED_PRECONDITION` で拒否するため、出所を 1 つにする。
//!
//! 権限モデルの判定は supervisor の `resolve_self_launch_privilege`（start の `resolve_launch_privilege` と同じ関数・
//! 同じ既定パス）を使い、pull / create と start の食い違いを構造で防ぐ。解決の失敗は既定値へ縮退させず、
//! 固定文言の `CriError` で失敗させる（fail-closed）。
//!
//! 対応表（[`extract_options_for`]）は現状どの行も `Keep` + `Strip` で、unpack-record の `settings` は従来と変わらない。
//! subuid のずれの照合は cri 側で実装済み（#4799）。残りの配線（`ChownInUserNamespace`・`PreserveIfOwnerMapped`）は後続 issue で、
//! 各 variant の doc に理由を書く。実装済みを装わない（REPAIR-3）。

use fandhe_container_cri::error::CriError;
use fandhe_container_oci::layer::extract::ExtractOptions;

/// 展開設定を選ぶための、自プロセスの権限モデル（start の解決結果の写し）。将来の variant 追加に備え `non_exhaustive`。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ExtractIdentity {
    /// ホスト root（euid 0）で動いている。本番の start は恒久的に拒否される（#2241 D1:A）ため写像先の uid が存在せず、
    /// イメージ由来の所有者・setuid をホストへ持ち込まない `Keep` + `Strip` にする。
    HostRoot,
    /// 非 root・範囲写像なし（1 対 1）。所有者は自 ID のままで `Keep` が正しい。特殊ビットは、展開後の bundle の
    /// rootfs を 0755 にする `open_rootfs_for_search` が `PreserveIfOwnerMapped` の「root を 0700 に保つ」契約と
    /// 両立しないため保持しない（後続 issue）。
    RootlessSingleId,
    /// 非 root・subuid / subgid の範囲写像あり。本来の値は `ChownInUserNamespace` だが、tokio のマルチスレッドの
    /// プロセス内では user namespace に入れない（core の `MultiThreaded` 拒否）ため暫定で `Keep` + `Strip`
    /// （後続 issue。subuid のずれの照合は cri の `match_recorded_settings` で実装済み・#4799。写像を持たせて配線するのは H6）。
    RootlessSubordinateIds,
    /// 権限モデルを解決できない OS（Linux 以外）。本番の経路には到達しないため `Keep` + `Strip`。
    Unsupported,
}

/// 権限モデルから展開設定を選ぶ対応表（網羅的な `match`。未知の variant を丸めない）。
#[must_use]
pub fn extract_options_for(identity: &ExtractIdentity) -> ExtractOptions {
    match identity {
        ExtractIdentity::HostRoot
        | ExtractIdentity::RootlessSingleId
        | ExtractIdentity::RootlessSubordinateIds
        | ExtractIdentity::Unsupported => ExtractOptions::new(),
    }
}

/// supervisor の権限モデルを [`ExtractIdentity`] に写す。`RootfulHostRoot` は start が恒久的に拒否するため、
/// ここでも `HostRoot` として受けず拒否する（fail-closed）。
#[cfg(target_os = "linux")]
fn identity_from_privilege(
    privilege: fandhe_container_core::exec::IsolationPrivilege,
) -> Result<ExtractIdentity, CriError> {
    use fandhe_container_core::exec::IsolationPrivilege;
    use fandhe_container_cri::error::CriErrorCode;
    match privilege {
        IsolationPrivilege::RootlessSingleId => Ok(ExtractIdentity::RootlessSingleId),
        IsolationPrivilege::RootlessSubordinateIds => Ok(ExtractIdentity::RootlessSubordinateIds),
        _ => Err(CriError::new(
            CriErrorCode::FailedPrecondition,
            "unsupported isolation privilege for image extraction",
        )),
    }
}

/// 本番の解決。Linux は euid 0 なら `HostRoot`、それ以外は start と同じ解決の結果を写す。
///
/// 失敗は元の区分を保ち、文言は固定の英語（パス・ユーザー名・errno を含めない）。
pub fn resolve_extract_identity() -> Result<ExtractIdentity, CriError> {
    #[cfg(target_os = "linux")]
    {
        // 資格情報を読めないときは root と断定せず、下の start と同じ解決の失敗に任せる。
        if matches!(crate::pod_holder::current_euid(), Ok(0)) {
            return Ok(ExtractIdentity::HostRoot);
        }
        let (privilege, _source) =
            fandhe_container_supervisor::start_entry::resolve_self_launch_privilege().map_err(
                |e| {
                    CriError::new(
                        CriError::from(&e).code(),
                        "failed to resolve the isolation privilege for image extraction",
                    )
                },
            )?;
        identity_from_privilege(privilege)
    }
    #[cfg(not(target_os = "linux"))]
    {
        Ok(ExtractIdentity::Unsupported)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SEC-5・OCI-1・#2792: 対応表は現状どの権限モデルでも既定（`Keep` + `Strip`）で、unpack-record の settings を変えない。
    #[test]
    fn sec5_oci1_2792_extract_options_table() {
        for id in [
            ExtractIdentity::HostRoot,
            ExtractIdentity::RootlessSingleId,
            ExtractIdentity::RootlessSubordinateIds,
            ExtractIdentity::Unsupported,
        ] {
            assert_eq!(extract_options_for(&id), ExtractOptions::new(), "{id:?}");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn sec5_oci1_2792_privilege_mapping_rejects_rootful_host_root() {
        use fandhe_container_core::exec::IsolationPrivilege as P;
        use fandhe_container_cri::error::CriErrorCode;
        assert_eq!(
            identity_from_privilege(P::RootlessSingleId).expect("single"),
            ExtractIdentity::RootlessSingleId
        );
        assert_eq!(
            identity_from_privilege(P::RootlessSubordinateIds).expect("subordinate"),
            ExtractIdentity::RootlessSubordinateIds
        );
        let err = identity_from_privilege(P::RootfulHostRoot).expect_err("rootful is rejected");
        assert_eq!(err.code(), CriErrorCode::FailedPrecondition);
        assert_eq!(
            err.message(),
            "unsupported isolation privilege for image extraction"
        );
    }
}
