//! 起動オプションの `network`・`add-host`・`dns` の検証済みモデル(NET-6・NET-12・SUP-12・#3065)。
//!
//! # 役割と呼び出し文脈
//!
//! 起動オプション文書(`FCOPT1`。[`document`](super::document))の `network`・`add-host`・`dns` の生の文字列を、
//! 復号のたびに net のパーサ(`parse_add_hosts`・`parse_ip_addr`・`NetworkName::new`・`ResolvConfPlan::for_mode`)で
//! 再検証し、型で保持する(未信頼の入力として扱う。network-wiring.md の D4・D5)。
//! `ContainerOptionsDocument::to_container_options` が [`NetworkOptions::parse`] を呼び、
//! `ContainerOptions::launch_options` が [`NetworkOptions::launch_network_mode`] で core の `LaunchNetworkMode` へ写して
//! `LaunchOptions::with_network` へ渡す(D7。config との突き合わせは core が行う)。
//! 文書に `network` が無ければ `FromConfig`(従来の挙動)。
//!
//! # 未実装の範囲(REPAIR-3)
//!
//! - ユーザー定義名(`Named`)と `container:` 始まりは起動経路に結線されておらず `Unimplemented`
//!   (rootless の pasta は #1940、rootful の参加指定は #3069・#3074)。
//! - `publish`(`-p`)は検証済みの [`PastaPortForwards`] として保持するだけで、pasta への反映(`pasta_args()` の連結)は
//!   #1940(NET-9・NET-3。#3200 で kind を足した)。
//! - `add-host`・`dns` は検証済みの型として保持するだけで、hosts / resolv.conf への反映は #1873(D9)。
//!   反映されるまで `ContainerOptions::launch_options` が拒否する。
//! - D8 の host netns の照合と `network_mode=host` のログは #1873。CLI が kind を書く処理と既定の `none` も #1873。
//!
//! OS 非依存で、3 OS でビルド・テストする。エラーは固定の英語文言で、入力値を含めない。

use std::net::IpAddr;

use fandhe_container_core::oci_runtime::LaunchNetworkMode;
use fandhe_container_core::traits::types::{ErrorCode, TraitError};
use fandhe_container_net::add_host_dns::resolv_conf::{MAX_DNS_SERVERS, ResolvConfPlan};
use fandhe_container_net::add_host_dns::{AddHostEntry, parse_add_hosts, parse_ip_addr};
use fandhe_container_net::error::{NetError, NetErrorCode};
use fandhe_container_net::network::MAX_PORT_PUBLISHES;
use fandhe_container_net::network::NetworkName;
use fandhe_container_net::network_mode::NetworkMode;
use fandhe_container_net::pasta::PastaPortForwards;

/// 予約名の固定拒否文言。
const RESERVED_NAME_MESSAGE: &str = "reserved network name";
/// `publish` がユーザー定義名の `network` と組でないときの固定拒否文言。
const PUBLISH_NEEDS_NAMED_MESSAGE: &str = "publish records require a user-defined network";
/// 結線されていない指定の固定拒否文言。
const NAMED_NOT_WIRED_MESSAGE: &str = "user-defined networks are not wired to the launch path yet";

/// `--network` の検証済みの選択(NET-6)。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum NetworkSelection {
    /// `none`(loopback だけの新しい network namespace)。
    None,
    /// `host`(ホストの network namespace を共有する)。
    Host,
    /// ユーザー定義名(検証済み。起動経路への結線は #1940・#3069・#3074)。
    Named(NetworkName),
}

/// `network`・`add-host`・`dns` の検証済みの組(NET-6・NET-12)。
///
/// `selection` が `None`(文書に `network` が無い)なら `FromConfig` になり、従来のコンテナと同じ挙動。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetworkOptions {
    selection: Option<NetworkSelection>,
    add_hosts: Vec<AddHostEntry>,
    dns: Vec<IpAddr>,
    publish: PastaPortForwards,
}

/// 予約名(`bridge`・`default`)か(D1)。
pub fn is_reserved_network_name(name: &str) -> bool {
    matches!(name, "bridge" | "default")
}

/// net の固定メッセージを保ったまま `TraitError` へ写す(`NetErrorCode` は `#[non_exhaustive]`)。
pub(crate) fn net_error_to_trait(e: &NetError) -> TraitError {
    let code = match e.code() {
        NetErrorCode::InvalidArgument => ErrorCode::InvalidArgument,
        NetErrorCode::Unimplemented => ErrorCode::Unimplemented,
        NetErrorCode::ResourceExhausted => ErrorCode::ResourceExhausted,
        _ => ErrorCode::Internal,
    };
    TraitError::new(code, e.message())
}

impl NetworkOptions {
    /// 生の指定を net のパーサで検証して作る。`InvalidArgument` を `Unimplemented` より先に判定する。
    ///
    /// 1. `network`: `none` / `host`、予約名は `InvalidArgument`、`container:` 始まりは `Unimplemented`、
    ///    それ以外は `NetworkName::new` で検証して `Named`
    /// 2. `add_hosts`: 全件を `parse_add_hosts` で検証
    /// 3. `dns`: 全件を `parse_ip_addr` で検証し、`none` / `host` では `ResolvConfPlan::for_mode` も通す
    /// 4. `publish`: 件数を確かめてから `PastaPortForwards::parse_all` で全件を検証し、ユーザー定義名の
    ///    `network` が無い組(無指定・`none`・`host`・`container:`)は拒否する(#3200・NET-9)
    /// 5. `network` が無いのに `add_hosts` / `dns` がある不整合は拒否する(CLI は必ず `network` を書くため、
    ///    この形は改ざんか不整合でしか生じない。fail-closed)
    pub fn parse(
        network: Option<&str>,
        add_hosts: &[String],
        dns: &[String],
        publish: &[String],
    ) -> Result<Self, TraitError> {
        if publish.len() > MAX_PORT_PUBLISHES {
            return Err(TraitError::new(
                ErrorCode::InvalidArgument,
                "too many publish records",
            ));
        }
        // 確保前の件数検証: モードによらず上限を超える `dns` は入口で拒否する(Named にも効かせる)。
        if dns.len() > MAX_DNS_SERVERS {
            return Err(TraitError::new(
                ErrorCode::InvalidArgument,
                "too many dns servers",
            ));
        }
        let mut container_ref = false;
        let selection = match network {
            None => None,
            Some("none") => Some(NetworkSelection::None),
            Some("host") => Some(NetworkSelection::Host),
            Some(n) if is_reserved_network_name(n) => {
                return Err(TraitError::new(
                    ErrorCode::InvalidArgument,
                    RESERVED_NAME_MESSAGE,
                ));
            }
            Some(n) if n.starts_with("container:") => {
                container_ref = true;
                None
            }
            Some(n) => Some(NetworkSelection::Named(
                NetworkName::new(n).map_err(|e| net_error_to_trait(&e))?,
            )),
        };
        let entries = parse_add_hosts(add_hosts.iter().map(String::as_str))
            .map_err(|e| net_error_to_trait(&e))?;
        let addrs = dns
            .iter()
            .map(|d| parse_ip_addr(d))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| net_error_to_trait(&e))?;
        let mode = match &selection {
            Some(NetworkSelection::None) => Some(NetworkMode::None),
            Some(NetworkSelection::Host) => Some(NetworkMode::Host),
            _ => None,
        };
        if let Some(mode) = mode {
            let raw: Vec<&str> = dns.iter().map(String::as_str).collect();
            ResolvConfPlan::for_mode(mode, &raw).map_err(|e| net_error_to_trait(&e))?;
        }
        if network.is_none() && (!entries.is_empty() || !addrs.is_empty()) {
            return Err(TraitError::new(
                ErrorCode::InvalidArgument,
                "add-host / dns records require a network record",
            ));
        }
        let forwards = PastaPortForwards::parse_all(publish.iter().map(String::as_str))
            .map_err(|e| net_error_to_trait(&e))?;
        // `container:` は `selection` が `None` なので、ここで併せて拒否される。
        if !forwards.is_empty() && !matches!(selection, Some(NetworkSelection::Named(_))) {
            return Err(TraitError::new(
                ErrorCode::InvalidArgument,
                PUBLISH_NEEDS_NAMED_MESSAGE,
            ));
        }
        if container_ref {
            return Err(TraitError::new(
                ErrorCode::Unimplemented,
                NAMED_NOT_WIRED_MESSAGE,
            ));
        }
        Ok(Self {
            selection,
            add_hosts: entries,
            dns: addrs,
            publish: forwards,
        })
    }

    /// core の `LaunchNetworkMode` へ写す(D7)。指定なしは `FromConfig`、`none` は `Loopback`(実体は #3064 まで
    /// core が `Unimplemented`)、`host` は `Host`、ユーザー定義名は `Unimplemented`。
    pub fn launch_network_mode(&self) -> Result<LaunchNetworkMode, TraitError> {
        match &self.selection {
            None => Ok(LaunchNetworkMode::FromConfig),
            Some(NetworkSelection::None) => Ok(LaunchNetworkMode::Loopback),
            Some(NetworkSelection::Host) => Ok(LaunchNetworkMode::Host),
            Some(NetworkSelection::Named(_)) => Err(TraitError::new(
                ErrorCode::Unimplemented,
                NAMED_NOT_WIRED_MESSAGE,
            )),
        }
    }

    /// 検証済みの `--network` の選択(文書に無ければ `None`)。
    pub fn selection(&self) -> Option<&NetworkSelection> {
        self.selection.as_ref()
    }

    /// 検証済みの `--add-host`。
    pub fn add_hosts(&self) -> &[AddHostEntry] {
        &self.add_hosts
    }

    /// 検証済みの `--dns`。
    pub fn dns(&self) -> &[IpAddr] {
        &self.dns
    }

    /// 検証済みの `-p` / `--publish`(pasta の引数への変換は `PastaPortForwards::pasta_args`。#1940 が連結する)。
    pub fn publish(&self) -> &PastaPortForwards {
        &self.publish
    }

    /// 何も指定していないか。
    pub fn is_empty(&self) -> bool {
        self.selection.is_none()
            && self.add_hosts.is_empty()
            && self.dns.is_empty()
            && self.publish.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(
        network: Option<&str>,
        hosts: &[&str],
        dns: &[&str],
    ) -> Result<NetworkOptions, TraitError> {
        let h: Vec<String> = hosts.iter().map(|s| (*s).to_owned()).collect();
        let d: Vec<String> = dns.iter().map(|s| (*s).to_owned()).collect();
        NetworkOptions::parse(network, &h, &d, &[])
    }

    fn pp(network: Option<&str>, publish: &[&str]) -> Result<NetworkOptions, TraitError> {
        let v: Vec<String> = publish.iter().map(|s| (*s).to_owned()).collect();
        NetworkOptions::parse(network, &[], &[], &v)
    }

    fn code(r: Result<NetworkOptions, TraitError>) -> Option<ErrorCode> {
        r.err().map(|e| e.code())
    }

    const INV: Option<ErrorCode> = Some(ErrorCode::InvalidArgument);
    const UNI: Option<ErrorCode> = Some(ErrorCode::Unimplemented);

    /// NET-6・D1: `--network` の判定表。
    #[test]
    fn net6_network_selection_decision_table() {
        assert_eq!(
            p(Some("none"), &[], &[]).expect("none").selection(),
            Some(&NetworkSelection::None)
        );
        assert_eq!(
            p(Some("host"), &[], &[]).expect("host").selection(),
            Some(&NetworkSelection::Host)
        );
        for n in ["bridge", "default"] {
            let e = p(Some(n), &[], &[]).expect_err("reserved");
            assert_eq!(e.code(), ErrorCode::InvalidArgument);
            assert_eq!(e.message(), "reserved network name");
        }
        let long = "a".repeat(65);
        for n in ["Web", ".x", "", long.as_str()] {
            assert_eq!(code(p(Some(n), &[], &[])), INV, "{n:?}");
        }
        let ok64 = "a".repeat(64);
        assert!(matches!(
            p(Some(&ok64), &[], &[]).expect("64").selection(),
            Some(NetworkSelection::Named(_))
        ));
        assert!(matches!(
            p(Some("web"), &[], &[]).expect("web").selection(),
            Some(NetworkSelection::Named(_))
        ));
        assert_eq!(code(p(Some("container:x"), &[], &[])), UNI);
        assert_eq!(code(p(Some("container:x"), &["bad"], &[])), INV);
    }

    /// NET-6・D7: 変換先のモード。
    #[test]
    fn net6_launch_network_mode_mapping() {
        let mode = |n: Option<&str>| p(n, &[], &[]).expect("parse").launch_network_mode();
        assert_eq!(mode(None).expect("m"), LaunchNetworkMode::FromConfig);
        assert_eq!(mode(Some("none")).expect("m"), LaunchNetworkMode::Loopback);
        assert_eq!(mode(Some("host")).expect("m"), LaunchNetworkMode::Host);
        let e = mode(Some("web")).expect_err("named");
        assert_eq!(e.code(), ErrorCode::Unimplemented);
        assert!(NetworkOptions::default().is_empty());
    }

    /// NET-12: `--dns` の判定表(none は loopback に限る)。
    #[test]
    fn net12_dns_rules_by_mode() {
        assert_eq!(code(p(Some("none"), &[], &["8.8.8.8"])), INV);
        assert_eq!(code(p(Some("none"), &[], &["127.0.0.1"])), None);
        assert_eq!(code(p(Some("none"), &[], &["::1"])), None);
        assert_eq!(code(p(Some("none"), &[], &["::ffff:127.0.0.1"])), INV);
        assert_eq!(code(p(Some("host"), &[], &["8.8.8.8"])), None);
        assert_eq!(code(p(Some("host"), &[], &["example.com"])), INV);
    }

    /// NET-12: `--add-host` は最初の `:` で分割する。
    #[test]
    fn net12_add_host_split_and_invalid() {
        let o = p(Some("host"), &["name:::1"], &[]).expect("ok");
        assert_eq!(o.add_hosts().len(), 1);
        assert_eq!(o.add_hosts()[0].host().as_str(), "name");
        assert_eq!(o.add_hosts()[0].ip(), "::1".parse::<IpAddr>().expect("ip"));
        assert_eq!(code(p(Some("host"), &["name::::1"], &[])), INV);
        assert_eq!(code(p(Some("host"), &["web:999.1.1.1"], &[])), INV);
        assert_eq!(code(p(Some("host"), &["a\nb:1.2.3.4"], &[])), INV);
    }

    /// NET-12: `network` が無い add-host / dns は拒否する。
    #[test]
    fn net12_add_host_dns_require_network_record() {
        let e = p(None, &["web:192.0.2.1"], &[]).expect_err("add-host");
        assert_eq!(e.code(), ErrorCode::InvalidArgument);
        assert_eq!(
            e.message(),
            "add-host / dns records require a network record"
        );
        assert_eq!(code(p(None, &[], &["8.8.8.8"])), INV);
    }

    /// NET-12: `dns` の件数上限はモードによらず確保前に効く(Named でも 33 件は拒否)。
    #[test]
    fn net12_dns_count_limit_applies_to_named() {
        let ok = vec!["192.0.2.1"; MAX_DNS_SERVERS];
        assert!(p(Some("web"), &[], &ok).is_ok());
        let over = vec!["192.0.2.1"; MAX_DNS_SERVERS + 1];
        assert_eq!(code(p(Some("web"), &[], &over)), INV);
        assert_eq!(code(p(Some("host"), &[], &over)), INV);
        assert_eq!(code(p(None, &[], &over)), INV);
    }

    /// 固定文言は入力値を含まない。
    #[test]
    fn net12_messages_do_not_echo_input() {
        let e = p(Some("host"), &["evil host:1.2.3.4"], &[]).expect_err("e");
        assert!(!e.message().contains("evil"), "{}", e.message());
        let e = p(Some("none"), &[], &["8.8.8.8"]).expect_err("e");
        assert!(!e.message().contains("8.8.8.8"), "{}", e.message());
    }

    /// net のコードから `ErrorCode` への写像。
    #[test]
    fn net12_error_mapping() {
        let m = |c| net_error_to_trait(&NetError::new(c, "m")).code();
        assert_eq!(m(NetErrorCode::InvalidArgument), ErrorCode::InvalidArgument);
        assert_eq!(m(NetErrorCode::Unimplemented), ErrorCode::Unimplemented);
        assert_eq!(
            m(NetErrorCode::ResourceExhausted),
            ErrorCode::ResourceExhausted
        );
        assert_eq!(m(NetErrorCode::Timeout), ErrorCode::Internal);
    }

    /// NET-9・#3200: `publish` はユーザー定義名の `network` と組のときだけ受ける。
    #[test]
    fn net9_publish_decision_table() {
        let o = pp(Some("web"), &["8080:80", "0.0.0.0:53:53/udp"]).expect("named");
        assert_eq!(o.publish().len(), 2);
        assert_eq!(
            o.publish().pasta_args(),
            [
                "-t",
                "127.0.0.1/8080:80",
                "-u",
                "0.0.0.0/53:53",
                "-T",
                "none",
                "-U",
                "none"
            ]
        );
        assert!(!o.is_empty());
        for n in [None, Some("none"), Some("host"), Some("container:x")] {
            let e = pp(n, &["8080:80"]).expect_err("needs named");
            assert_eq!(e.code(), ErrorCode::InvalidArgument, "{n:?}");
            assert_eq!(
                e.message(),
                "publish records require a user-defined network"
            );
        }
        // 空の publish は従来どおり。
        assert!(pp(Some("host"), &[]).is_ok());
    }

    /// NET-9・#3200: 不正な指定と件数超過は net の固定文言のまま拒否する。
    #[test]
    fn net9_publish_invalid_and_count_limit() {
        for bad in ["[::1]:80:80", "0:80", "1-2:80", "80:80/sctp", ""] {
            assert_eq!(
                pp(Some("web"), &[bad]).err().map(|e| e.code()),
                INV,
                "{bad:?}"
            );
        }
        assert_eq!(
            pp(Some("web"), &["8080:80", "8080:80"])
                .err()
                .map(|e| e.code()),
            INV
        );
        let over: Vec<String> = (0..=MAX_PORT_PUBLISHES)
            .map(|i| format!("{}:80", 1000 + i))
            .collect();
        let refs: Vec<&str> = over.iter().map(String::as_str).collect();
        let e = pp(Some("web"), &refs).expect_err("over");
        assert_eq!(e.message(), "too many publish records");
        let e = pp(Some("web"), &["[::1]:80:80"]).expect_err("v6");
        assert!(!e.message().contains("::1"), "{}", e.message());
    }
}
