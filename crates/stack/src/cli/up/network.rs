//! `up` のネットワーク接続の計画と注入ポート（STACK-8・TASK-155.2・#619・NET-6・NET-12）。
//!
//! 呼び出し元は [`super::up`]。TOML の `[networks.<name>]` と `[services.<name>].networks` を
//! 起動前に検証し（[`plan_networks`]。副作用なしの純関数）、参照されるネットワークを
//! [`NetworkProvisioner`] で用意し、各サービスの launch へ [`NetworkAttachment`] を渡す。
//!
//! 実装済みの範囲と未実装（REPAIR-3）:
//! - 実装済み: 検証・用意のポート・launcher への接続指示。実プロセスを起動しない偽の世界で照合する。
//! - 未実装（#3639 で追跡）: 本番の `NetworkProvisioner`（CLI の `network create` と存在確認）、
//!   launcher での `create --network <name>` と pasta フラグの扱い、実 netns への接続の実機確認。
//!   rootful（bridge）は CLI 側で D13 待ちの `UNIMPLEMENTED`。
//!
//! 意図した compose との差: `networks` が空のサービスに暗黙の default ネットワークは作らず、
//! CLI の既定 `none` のままにする（SEC-1: 既定で閉じる）。名前に project 接頭辞は付けない。

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fmt;
use std::num::NonZeroU8;

use crate::schema::{Network, Service};

/// 予約名。SSOT は `crates/net/src/network_store/definition.rs` の `RESERVED_NETWORK_NAMES`。
/// stack は net に依存しない（依存辺はユーザー承認事項）ため複製し、乖離は単体テストで検出する。
const RESERVED_NETWORK_NAMES: [&str; 4] = ["none", "host", "bridge", "default"];

/// 名前の最大バイト数。SSOT は net の `NetworkName`（`crates/net/src/network.rs`）。
const MAX_NETWORK_NAME_LEN: usize = 64;

/// ネットワーク名の事前検査（早期拒否用。最終検証はアダプタ側で net の `NetworkName` が行う）。
fn valid_network_name(name: &str) -> bool {
    let b = name.as_bytes();
    if b.is_empty() || b.len() > MAX_NETWORK_NAME_LEN {
        return false;
    }
    let first_ok = b
        .first()
        .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit());
    first_ok
        && b.iter().all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'_' | b'.' | b'-')
        })
}

/// 対応する driver。
///
/// `Bridge` は「このインストールの既定のユーザー定義ネットワーク」を指す。rootless では pasta、
/// rootful では bridge のどちらになるかはアダプタと CLI が決める。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum NetworkDriver {
    /// 既定のユーザー定義ネットワーク。
    Bridge,
}

/// [`NetworkProvisioner::ensure`] への要求。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkRequest<'a> {
    /// ネットワーク名（TOML 由来。事前検査済みだが実装側でも検証する）。
    pub name: &'a str,
    /// driver。
    pub driver: NetworkDriver,
    /// `true` なら存在確認のみで作らない。
    pub external: bool,
}

/// 用意の結果の種別。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProvisionOutcome {
    /// 今回作った。
    Created,
    /// 既にあり、互換な定義だった。
    Reused,
    /// external として存在を確かめた。
    External,
}

/// 用意したネットワーク。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvisionedNetwork {
    name: String,
    outcome: ProvisionOutcome,
}

impl ProvisionedNetwork {
    /// 名前と結果で作る。
    pub fn new(name: impl Into<String>, outcome: ProvisionOutcome) -> Self {
        Self {
            name: name.into(),
            outcome,
        }
    }

    /// ネットワーク名。
    pub fn name(&self) -> &str {
        &self.name
    }

    /// 結果の種別。
    pub fn outcome(&self) -> ProvisionOutcome {
        self.outcome
    }
}

/// 用意の失敗。固定文字列だけを持ち、動的な値は入れない。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkProvisionError {
    code: &'static str,
    message: &'static str,
}

impl NetworkProvisionError {
    /// 機械可読な `code` と固定の英語 `message` で作る。
    pub fn new(code: &'static str, message: &'static str) -> Self {
        Self { code, message }
    }

    /// 機械可読なエラーコード。
    pub fn code(&self) -> &'static str {
        self.code
    }

    /// 固定の英語メッセージ。
    pub fn message(&self) -> &'static str {
        self.message
    }
}

impl fmt::Display for NetworkProvisionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for NetworkProvisionError {}

/// ネットワークを用意する入口（本番は CLI の `network create` と存在確認。#3639）。
///
/// 実装の契約:
/// - (a) `name` は TOML 由来の外部入力。net の `NetworkName` と予約名の検証を実装側でも必ず行う
///   （stack の事前検査は早期拒否のためで、SSOT は net）。
/// - (b) `external = true` は存在を確かめるだけで作らない。無ければエラーにする。
/// - (c) `external = false` は無ければ作る。既にあるときは互換な定義のときだけ `Reused` とする。
/// - (d) 返すのは今回の呼び出しで行ったことだけ。
/// - (e) ブロックする実装は期限を持つ（REPAIR-5）。
/// - (f) rootful では CLI と同じく `UNIMPLEMENTED` 相当を返す（D13 待ち）。
pub trait NetworkProvisioner {
    /// `request` のネットワークを用意する。
    fn ensure(
        &mut self,
        request: &NetworkRequest<'_>,
    ) -> Result<ProvisionedNetwork, NetworkProvisionError>;
}

/// launcher へ渡す接続指示（生の `Option<String>` にしない）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkAttachment<'a> {
    name: &'a str,
}

impl<'a> NetworkAttachment<'a> {
    pub(crate) fn new(name: &'a str) -> Self {
        Self { name }
    }

    /// 接続先のネットワーク名。
    pub fn name(&self) -> &'a str {
        self.name
    }

    /// CLI の `create` に渡す引数片（`--network` と名前を別要素で返し、連結しない）。
    pub fn create_option_args(&self) -> Vec<OsString> {
        vec![OsString::from("--network"), OsString::from(self.name)]
    }
}

/// ネットワーク計画の失敗。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum NetworkPlanError {
    /// サービスが 2 件以上のネットワークを指定した（CLI の `--network` は 1 回まで）。
    MultipleNetworks { service: String },
    /// 参照名が `[networks]` に無い。
    NotDefined { service: String, network: String },
    /// 予約名または名前の規則に反する。
    InvalidName { network: String },
    /// 未対応の driver。
    UnsupportedDriver { network: String },
}

impl NetworkPlanError {
    /// 機械可読なエラーコード。
    pub fn code(&self) -> &'static str {
        match self {
            Self::MultipleNetworks { .. } => "MULTIPLE_NETWORKS_UNSUPPORTED",
            Self::NotDefined { .. } => "NETWORK_NOT_DEFINED",
            Self::InvalidName { .. } => "INVALID_NETWORK_NAME",
            Self::UnsupportedDriver { .. } => "NETWORK_DRIVER_UNSUPPORTED",
        }
    }

    /// 固定の英語メッセージ（名前は含めない）。
    pub fn message(&self) -> &'static str {
        match self {
            Self::MultipleNetworks { .. } => "a service may join at most one network",
            Self::NotDefined { .. } => "service references an undefined network",
            Self::InvalidName { .. } => "network name is reserved or malformed",
            Self::UnsupportedDriver { .. } => "network driver is not supported",
        }
    }

    /// 非ゼロ終了コード（ERR-2。core の表と同じ値の複製。未対応=8・引数不正=2）。
    pub fn exit_code(&self) -> NonZeroU8 {
        let n = match self {
            Self::MultipleNetworks { .. } | Self::UnsupportedDriver { .. } => 8,
            Self::NotDefined { .. } | Self::InvalidName { .. } => 2,
        };
        NonZeroU8::new(n).unwrap_or(NonZeroU8::MIN)
    }
}

impl fmt::Display for NetworkPlanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let m = self.message();
        match self {
            Self::MultipleNetworks { service } => write!(f, "{m}: {service}"),
            Self::NotDefined { service, network } => write!(f, "{m}: {service} -> {network}"),
            Self::InvalidName { network } | Self::UnsupportedDriver { network } => {
                write!(f, "{m}: {network}")
            }
        }
    }
}

impl std::error::Error for NetworkPlanError {}

/// 検証済みのネットワーク計画。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NetworkPlan {
    /// 参照されるネットワークの要求（名前の昇順）。
    required: Vec<(String, NetworkDriver, bool)>,
    /// サービス名 → 接続先（1 件）。
    attach: BTreeMap<String, String>,
}

impl NetworkPlan {
    /// 用意するネットワークの要求（名前の昇順）。
    pub fn requests(&self) -> impl Iterator<Item = NetworkRequest<'_>> {
        self.required
            .iter()
            .map(|(name, driver, external)| NetworkRequest {
                name,
                driver: *driver,
                external: *external,
            })
    }

    /// `service` の接続指示。ネットワーク指定なしなら `None`（CLI の既定 `none`）。
    pub fn attachment_for(&self, service: &str) -> Option<NetworkAttachment<'_>> {
        self.attach
            .get(service)
            .map(|n| NetworkAttachment::new(n.as_str()))
    }
}

fn parse_driver(driver: Option<&str>) -> Option<NetworkDriver> {
    match driver {
        None | Some("bridge") => Some(NetworkDriver::Bridge),
        Some(_) => None,
    }
}

/// サービスの `networks` と `[networks]` を検証し、用意すべきネットワークを決める（STACK-8）。
///
/// 副作用なし。失敗したら何も用意も起動もしない。参照されない定義は用意しない。
pub fn plan_networks(
    services: &BTreeMap<String, Service>,
    networks: &BTreeMap<String, Network>,
) -> Result<NetworkPlan, NetworkPlanError> {
    let mut attach = BTreeMap::new();
    let mut referenced: BTreeSet<&str> = BTreeSet::new();
    for (name, svc) in services {
        let mut it = svc.networks.iter();
        let Some(first) = it.next() else { continue };
        if it.next().is_some() {
            return Err(NetworkPlanError::MultipleNetworks {
                service: name.clone(),
            });
        }
        if !networks.contains_key(first) {
            return Err(NetworkPlanError::NotDefined {
                service: name.clone(),
                network: first.clone(),
            });
        }
        referenced.insert(first.as_str());
        attach.insert(name.clone(), first.clone());
    }
    let mut required = Vec::new();
    for name in referenced {
        if RESERVED_NETWORK_NAMES.contains(&name) || !valid_network_name(name) {
            return Err(NetworkPlanError::InvalidName {
                network: name.to_string(),
            });
        }
        let def = networks.get(name);
        let Some(driver) = parse_driver(def.and_then(|d| d.driver.as_deref())) else {
            return Err(NetworkPlanError::UnsupportedDriver {
                network: name.to_string(),
            });
        };
        let external = def.and_then(|d| d.external).unwrap_or(false);
        required.push((name.to_string(), driver, external));
    }
    Ok(NetworkPlan { required, attach })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::ComposeToml;

    fn plan(src: &str) -> Result<NetworkPlan, NetworkPlanError> {
        let p: ComposeToml = toml::from_str(src).unwrap();
        plan_networks(&p.services, &p.networks)
    }

    fn with_net(name: &str) -> String {
        format!("[services.a]\nimage = \"x\"\nnetworks = [\"{name}\"]\n[networks.\"{name}\"]\n")
    }

    /// STACK-8: 予約名 4 種は拒否（終了コード 2）。
    #[test]
    fn stack_8_reserved_names_rejected() {
        for n in ["none", "host", "bridge", "default"] {
            let e = plan(&with_net(n)).unwrap_err();
            assert_eq!(e.code(), "INVALID_NETWORK_NAME", "{n}");
            assert_eq!(e.exit_code().get(), 2);
        }
    }

    /// STACK-8: 名前の規則（64 バイト上限・大文字・先頭の記号）。
    #[test]
    fn stack_8_malformed_names_rejected() {
        assert!(plan(&with_net(&"a".repeat(64))).is_ok());
        for n in [&"a".repeat(65), "Back", ".dot", "-x", "a/b", "a b"] {
            let e = plan(&with_net(n)).unwrap_err();
            assert_eq!(e.code(), "INVALID_NETWORK_NAME", "{n}");
        }
        assert!(plan(&with_net("a_b.c-1")).is_ok());
    }

    /// STACK-8: bridge 以外の driver は未対応（終了コード 8）。
    #[test]
    fn stack_8_unsupported_driver_rejected() {
        let src = "[services.a]\nimage=\"x\"\nnetworks=[\"n\"]\n[networks.n]\ndriver=\"overlay\"\n";
        let e = plan(src).unwrap_err();
        assert_eq!(e.code(), "NETWORK_DRIVER_UNSUPPORTED");
        assert_eq!(e.exit_code().get(), 8);
    }

    /// STACK-8: 2 件以上は拒否（黙って削らない）。
    #[test]
    fn stack_8_multiple_networks_rejected() {
        let src = "[services.a]\nimage=\"x\"\nnetworks=[\"n\",\"m\"]\n[networks.n]\n[networks.m]\n";
        let e = plan(src).unwrap_err();
        assert_eq!(e.code(), "MULTIPLE_NETWORKS_UNSUPPORTED");
        assert_eq!(e.exit_code().get(), 8);
    }

    /// STACK-8: 未定義の参照は拒否。
    #[test]
    fn stack_8_undefined_reference_rejected() {
        let e = plan("[services.a]\nimage=\"x\"\nnetworks=[\"zz\"]\n").unwrap_err();
        assert_eq!(e.code(), "NETWORK_NOT_DEFINED");
        assert_eq!(e.exit_code().get(), 2);
    }

    /// STACK-8: 参照される定義だけが名前の昇順で並び、未参照は用意しない。
    #[test]
    fn stack_8_only_referenced_sorted() {
        let src = "[services.a]\nimage=\"x\"\nnetworks=[\"zeta\"]\n\
                   [services.b]\nimage=\"x\"\nnetworks=[\"alpha\"]\n\
                   [services.c]\nimage=\"x\"\n\
                   [networks.zeta]\n[networks.alpha]\nexternal=true\n[networks.unused]\n";
        let p = plan(src).unwrap();
        let got: Vec<_> = p.requests().map(|r| (r.name, r.external)).collect();
        assert_eq!(got, vec![("alpha", true), ("zeta", false)]);
        assert_eq!(p.attachment_for("a").unwrap().name(), "zeta");
        assert!(p.attachment_for("c").is_none());
        assert_eq!(
            p.attachment_for("b").unwrap().create_option_args(),
            vec![OsString::from("--network"), OsString::from("alpha")]
        );
    }
}
