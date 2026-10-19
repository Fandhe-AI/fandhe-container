//! cgroup を使う設定で join の手段が無い launch を fork の前に拒否する判定（TASK-29 追補・#1814・
//! CORE-3・CORE-4・SEC-6・SEC-1）。
//!
//! `config.json` が cgroup を使う設定（`linux.resources`・`linux.cgroupsPath` の指定）なのに、cgroup へ
//! 入る手段（`cgroups::DelegatedCgroup` の参加フックが返す `CgroupJoin`）が launcher に渡されていないと、
//! 資源制限が掛からないままコンテナが起動する。判定と拒否をこのモジュールの 1 か所に置き、本番
//! launcher（`ProductionLauncher`。#1816。supervisor の結線は #1819）が fork の前に [`launch_after_cgroup_check`] で呼ぶ。
//!
//! # 判定条件
//!
//! | 指定 | 扱い |
//! | --- | --- |
//! | `linux.resources` | キーがあれば中身（`{}`・null を含む）に関わらず cgroup を使う |
//! | `linux.cgroupsPath` | キーがあれば cgroup を使う |
//! | どちらも無し | 使わない（join の手段が無くても拒否しない） |
//!
//! 判定は型つきのアクセサ（`OciConfig::linux_resources` / `cgroups_path`）の有無で行う（#2019。以前は
//! `unapplied_fields` の記録で判定していた。resources を解釈済みへ移したため）。値で区別すると未知の
//! 制限の見逃し（fail-open）になるため、存在だけで要件とする（SEC-1）。
//!
//! # 判断の記録（#2010・TASK-29 追補。基盤は TASK-32〔CORE-3〕・TASK-170〔SUP-13〕）
//!
//! - `resources: {}` も「cgroup が必要」のままにし、値による「不要」判定への精緻化はしない。未対応の既知キー
//!   （`{"memory":{"reservation":1}}` 等）は `LinuxResourceLimits::default()` に正規化されて空に見えるため、
//!   値だけで判定すると fail-open になる。本番の start は常に supervisor の cgroup 連鎖で join の手段を渡すので、
//!   精緻化の実益も無い
//! - `linux.cgroupsPath` は配置に使わず、受理しない。cgroup は常に委譲スコープ配下の `fc-<id>@<n>` に置かれ、
//!   状態記録・記録済みスコープの検証つき削除（CORE-4・SEC-6）がその配置を前提にする。値を受理に開くなら、
//!   委譲スコープ配下に閉じる検証（`..`・絶対パス・symlink・別表記の拒否）と状態記録との整合が前提になる
//!
//! # 契約・制約
//!
//! - join の手段は制限適用の証跡 `LaunchReady` の条件に入れない（#1314）。cgroup の拒否は launcher が
//!   fork 前に行う別の関門で、本モジュールがその判定を担う
//! - join の手段は `CgroupJoin`（`OwnedFd` を持つ）で `LaunchSpec` に載せられないため、launcher が保持し、
//!   [`CgroupJoinMeans`] に写して渡す。`LaunchSpec` には要件 [`CgroupRequirement`] だけを載せる
//! - 呼び出し側は cgroup の作成（mkdir・制限設定）より前にも検査を呼ぶのが望ましい。順序は #1715・#1717 の責務
//! - エラー message は固定文言とキー名だけで、config の値・パスを含めない
//!
//! # 現状（REPAIR-3）
//!
//! `linux.resources` は #2019（TASK-29 追補）で受理に移り、要件が実際に効く。`linux.cgroupsPath` は値を配置に
//! 使わない方針のため [`check_cgroups_path`] が create / start で拒否する（#2010 で方針を確定）。したがって `LaunchSpec` に載る要件の `cgroups_path` は当面常に偽である。
//! モジュールは 3 OS でビルドされ（CLI-1）、`CgroupJoin` への依存は Linux 限定の `From` 実装に局所化している。

use super::config::OciConfig;
use crate::traits::{ErrorCode, TraitError};

/// config が cgroup を使う設定かどうか（指定の有無のみ。値は保持しない）。
///
/// `start` が `LaunchSpec` に載せ、launcher が fork 前に [`require_cgroup_join`] へ渡す。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct CgroupRequirement {
    resources: bool,
    cgroups_path: bool,
}

impl CgroupRequirement {
    /// `config` の `linux.resources` / `linux.cgroupsPath` の指定の有無から要件を求める。
    pub fn of_config(config: &OciConfig) -> Self {
        Self {
            resources: config.linux_resources().is_some(),
            cgroups_path: config.cgroups_path().is_some(),
        }
    }

    /// cgroup を使わない設定（要件なし）。
    pub fn none() -> Self {
        Self {
            resources: false,
            cgroups_path: false,
        }
    }

    /// cgroup が必要か。
    pub fn is_required(&self) -> bool {
        self.resources || self.cgroups_path
    }

    /// 要件の原因となった指定のキー名（固定文字列のみ。宣言順）。
    pub fn reasons(&self) -> Vec<&'static str> {
        let mut out = Vec::new();
        if self.resources {
            out.push("linux.resources");
        }
        if self.cgroups_path {
            out.push("linux.cgroupsPath");
        }
        out
    }
}

/// `linux.cgroupsPath` の受理の入口（#2019・TASK-29 追補。`create::validate_bundle` から呼ばれ、create と start の
/// 両方に効く）。
///
/// コンテナの cgroup は常に委譲スコープ配下の `fc-<id>@<n>` に置かれ、config の値を配置に使う実装は無い。
/// 値を黙って無視すると、指定した場所に置かれないまま起動する（SEC-1）ため、指定があれば `Unimplemented` で
/// 拒否する。値は配置に使わない方針（#2010）で、指定があれば値に関わらず（`..`・絶対パス・別表記を含め）拒否するため、
/// 委譲スコープの外へ出る経路は生じない。受理に開くなら委譲スコープ配下に閉じる検証が前提になる。
/// メッセージはキー名だけで、値を含めない（ERR-1）。
pub fn check_cgroups_path(config: &OciConfig) -> Result<(), TraitError> {
    if config.cgroups_path().is_none() {
        return Ok(());
    }
    Err(TraitError::new(
        ErrorCode::Unimplemented,
        "linux.cgroupsPath is not supported yet; the container cgroup is placed under the delegated scope",
    ))
}

/// launcher が cgroup へ入る手段を持っているか。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CgroupJoinMeans {
    /// join の手段が渡されている。
    Provided,
    /// join の手段が無い。
    Absent,
}

#[cfg(target_os = "linux")]
impl From<Option<&crate::cgroups::CgroupJoin>> for CgroupJoinMeans {
    fn from(join: Option<&crate::cgroups::CgroupJoin>) -> Self {
        if join.is_some() {
            Self::Provided
        } else {
            Self::Absent
        }
    }
}

/// cgroup が必要なのに join の手段が無ければ `FailedPrecondition` で拒否する（SEC-1・CORE-3）。
///
/// 他の 3 通り（不要 / 手段あり の組）は `Ok`。
pub fn require_cgroup_join(
    requirement: CgroupRequirement,
    join: CgroupJoinMeans,
) -> Result<(), TraitError> {
    if !requirement.is_required() || join == CgroupJoinMeans::Provided {
        return Ok(());
    }
    Err(TraitError::new(
        ErrorCode::FailedPrecondition,
        format!(
            "the config requires a cgroup ({}) but no cgroup join was provided; refusing to launch without limits",
            requirement.reasons().join(", ")
        ),
    ))
}

/// 検査を通ったときだけ `spawn`（fork を伴う起動）を呼ぶ関門。拒否時は `spawn` を呼ばない。
///
/// 本番 launcher が「fork 前に拒否」を 1 か所で守るための継ぎ目で、子プロセスを作らないことを
/// 呼び出し回数で試験できる。
pub fn launch_after_cgroup_check<T>(
    requirement: CgroupRequirement,
    join: CgroupJoinMeans,
    spawn: impl FnOnce() -> Result<T, TraitError>,
) -> Result<T, TraitError> {
    require_cgroup_join(requirement, join)?;
    spawn()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oci_runtime::parse_config_bytes;
    use serde_json::{Value, json};
    use std::cell::Cell;

    fn config(linux_extra: Value) -> OciConfig {
        let mut linux = json!({"namespaces": [{"type": "pid"}]});
        if let (Some(l), Some(e)) = (linux.as_object_mut(), linux_extra.as_object()) {
            for (k, v) in e {
                l.insert(k.clone(), v.clone());
            }
        }
        let v = json!({
            "ociVersion": "1.2.0",
            "root": {"path": "rootfs"},
            "process": {"args": ["/bin/true"], "cwd": "/", "user": {"uid": 0, "gid": 0}},
            "linux": linux
        });
        parse_config_bytes(&serde_json::to_vec(&v).expect("serialize")).expect("valid config")
    }

    /// CORE-3・SEC-1: 指定が無ければ cgroup は不要。
    #[test]
    fn core3_no_cgroup_keys_means_not_required() {
        let r = CgroupRequirement::of_config(&config(json!({})));
        assert!(!r.is_required());
        assert!(r.reasons().is_empty());
        assert_eq!(r, CgroupRequirement::none());
    }

    /// CORE-3・SEC-1: `linux.resources` は中身に関わらず要件（`{}`・入れ子が空・制限ありのどれも同じ）。
    #[test]
    fn core3_resources_key_is_required_even_if_empty() {
        for resources in [
            json!({}),
            json!({"memory": {}}),
            json!({"cpu": {}}),
            json!({"memory": {"limit": 1048576}, "pids": {"limit": 64}}),
        ] {
            let r = CgroupRequirement::of_config(&config(json!({ "resources": resources })));
            assert!(r.is_required(), "{resources}");
            assert_eq!(r.reasons(), vec!["linux.resources"], "{resources}");
        }
    }

    /// SEC-1: 未対応の既知キーは制限が空に見えても要件あり（「不要」と誤判定しない）。
    #[test]
    fn sec1_resources_with_unsupported_known_key_is_required() {
        for resources in [
            json!({"hugepageLimits": []}),
            json!({"memory": {"reservation": 1}}),
        ] {
            let c = config(json!({ "resources": resources }));
            assert_eq!(
                c.linux_resources(),
                Some(&crate::oci_runtime::LinuxResourceLimits::default()),
                "{resources}"
            );
            assert!(!c.unapplied_fields().is_empty(), "{resources}");
            let r = CgroupRequirement::of_config(&c);
            assert!(r.is_required(), "{resources}");
            assert_eq!(r.reasons(), vec!["linux.resources"], "{resources}");
        }
    }

    /// SEC-1: 未知のキーと null はパース段で拒否され、要件の計算まで進まない。
    #[test]
    fn sec1_resources_with_unknown_key_is_rejected_at_parse() {
        for resources in [
            json!({"futureLimit": 1}),
            json!({"memory": {"futureKnob": 1}}),
            Value::Null,
        ] {
            let v = json!({
                "ociVersion": "1.2.0",
                "root": {"path": "rootfs"},
                "process": {"args": ["/bin/true"], "cwd": "/", "user": {"uid": 0, "gid": 0}},
                "linux": {"namespaces": [{"type": "pid"}], "resources": resources}
            });
            let err = parse_config_bytes(&serde_json::to_vec(&v).expect("serialize"))
                .expect_err("reject");
            assert_eq!(err.code(), ErrorCode::InvalidArgument, "{resources}");
        }
    }

    /// CORE-3: `linux.cgroupsPath` のみ、および両方の理由列。
    #[test]
    fn core3_cgroups_path_and_both_reasons() {
        let r = CgroupRequirement::of_config(&config(json!({"cgroupsPath": "/x"})));
        assert_eq!(r.reasons(), vec!["linux.cgroupsPath"]);
        let r =
            CgroupRequirement::of_config(&config(json!({"cgroupsPath": "/x", "resources": {}})));
        assert_eq!(r.reasons(), vec!["linux.resources", "linux.cgroupsPath"]);
    }

    /// SEC-1: 必要 + 手段なしだけ拒否。構造化エラーで値を載せない。
    #[test]
    fn sec1_required_without_join_is_rejected_others_pass() {
        let req = CgroupRequirement::of_config(&config(json!({"resources": {}})));
        let err = require_cgroup_join(req, CgroupJoinMeans::Absent).expect_err("reject");
        assert_eq!(err.code(), ErrorCode::FailedPrecondition);
        assert_eq!(err.code().as_str(), "FAILED_PRECONDITION");
        assert_eq!(
            err.message(),
            "the config requires a cgroup (linux.resources) but no cgroup join was provided; refusing to launch without limits"
        );
        assert!(require_cgroup_join(req, CgroupJoinMeans::Provided).is_ok());
        let none = CgroupRequirement::none();
        assert!(require_cgroup_join(none, CgroupJoinMeans::Absent).is_ok());
        assert!(require_cgroup_join(none, CgroupJoinMeans::Provided).is_ok());
    }

    /// SEC-1: 拒否時は spawn（fork）を呼ばない。
    #[test]
    fn sec1_rejection_does_not_spawn() {
        let req = CgroupRequirement::of_config(&config(json!({"cgroupsPath": "/x"})));
        let calls = Cell::new(0u32);
        let spawn = || {
            calls.set(calls.get() + 1);
            Ok(7u8)
        };
        let r = launch_after_cgroup_check(req, CgroupJoinMeans::Absent, spawn);
        assert_eq!(r.expect_err("reject").code(), ErrorCode::FailedPrecondition);
        assert_eq!(calls.get(), 0);
        let r = launch_after_cgroup_check(req, CgroupJoinMeans::Provided, spawn);
        assert_eq!(r.expect("ok"), 7);
        assert_eq!(calls.get(), 1);
        let r =
            launch_after_cgroup_check(CgroupRequirement::none(), CgroupJoinMeans::Absent, spawn);
        assert_eq!(r.expect("ok"), 7);
        assert_eq!(calls.get(), 2);
    }

    /// #2010・CORE-3・SEC-1: `check_cgroups_path` は値に関わらず指定があれば `Unimplemented`（値は載せない）、
    /// 無ければ `Ok`。`..`・絶対パス・別表記でも受理しない。
    #[test]
    fn core3_sec1_cgroups_path_is_never_accepted() {
        assert!(check_cgroups_path(&config(json!({}))).is_ok());
        assert!(check_cgroups_path(&config(json!({"resources": {}}))).is_ok());
        for path in [
            "/secret/path",
            "../escape",
            "a/../../b",
            "/sys/fs/cgroup",
            "/user.slice/other",
            "fc/child",
            "machine.slice:prefix:name",
            "./a//b",
        ] {
            let err =
                check_cgroups_path(&config(json!({ "cgroupsPath": path }))).expect_err("refuse");
            assert_eq!(err.code(), ErrorCode::Unimplemented, "{path}");
            assert_eq!(
                err.message(),
                "linux.cgroupsPath is not supported yet; the container cgroup is placed under the delegated scope",
                "{path}"
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn core3_absent_join_maps_to_absent() {
        assert_eq!(CgroupJoinMeans::from(None), CgroupJoinMeans::Absent);
    }
}
