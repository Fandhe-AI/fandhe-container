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
//! - ユーザー定義名(`Named`)は Linux で `LaunchNetworkMode::Attachable` へ写り、supervisor の `pasta_attach` が
//!   holder と pasta を結線する(#1940)。CLI が `network <名前>` と `pasta` を FCOPT1 に書く入口は #3329。Linux 以外は
//!   `Unimplemented`。`container:` 始まりは結線されておらず `Unimplemented`(rootful の参加指定は #3069・#3074)。
//! - `publish`(`-p`)は検証済みの [`PastaPortForwards`] として保持し、`pasta_attach` が pasta の引数へ連結する(#1940。
//!   NET-9・NET-3。#3200 で kind を足した)。
//! - `add-host`・`dns` の hosts / resolv.conf への反映は start の手順 4b(`etc_files`。#1873・D9)。
//!   種別の決定は [`NetworkOptions::etc_file_selection`]。ユーザー定義名(pasta 構成)は `--dns` の有無に依らず
//!   resolv.conf を生成する(`--dns` が無ければ nameserver は [`PASTA_DEFAULT_NAMESERVER`]。D9・12.7)。
//!
//! OS 非依存で、3 OS でビルド・テストする。エラーは固定の英語文言で、入力値を含めない。

use std::net::IpAddr;

use fandhe_container_core::etc_files::{EtcFileKind, EtcFileSelection};
use fandhe_container_core::oci_runtime::LaunchNetworkMode;
use fandhe_container_core::traits::types::{ErrorCode, TraitError};
use fandhe_container_net::add_host_dns::resolv_conf::{MAX_DNS_SERVERS, ResolvConfPlan};
use fandhe_container_net::add_host_dns::{AddHostEntry, parse_add_hosts, parse_ip_addr};
use fandhe_container_net::error::{NetError, NetErrorCode};
use fandhe_container_net::network::MAX_PORT_PUBLISHES;
use fandhe_container_net::network::NetworkName;
use fandhe_container_net::network_mode::{NetworkChoice, NetworkMode};
use fandhe_container_net::pasta::PastaPortForwards;

/// `publish` がユーザー定義名の `network` と組でないときの固定拒否文言。
const PUBLISH_NEEDS_NAMED_MESSAGE: &str = "publish records require a user-defined network";
/// 結線されていない指定の固定拒否文言。
/// resolver にできない loopback 系のアドレスか(127.0.0.0/8・`::1`・IPv4-mapped / IPv4-compatible の loopback・
/// 未指定アドレス)。ユーザー定義名の `--dns` の検証と resolv.conf の書き込み時の再検証が同じ関数を使う
/// (コンテナの netns の loopback は resolver ではない。D1・NET-12)。
pub fn is_loopback_like(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_unspecified(),
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                // `::ffff:a.b.c.d`(mapped)と `::a.b.c.d`(compatible)の埋め込み IPv4。
                || v6.to_ipv4().is_some_and(|v4| v4.is_loopback() || v4.is_unspecified())
        }
    }
}

/// pasta 構成(ユーザー定義名)の既定の nameserver。pasta の `--dns-forward` と同じアドレス
/// (rootless-network.md 12.7・network-wiring.md D9。net の `pasta_argv` の固定引数と同じ値)。
pub const PASTA_DEFAULT_NAMESERVER: &str = "169.254.1.1";

/// ユーザー定義名の `--dns` に loopback を指定したときの固定拒否文言(コンテナの loopback は resolver ではない。D1)。
const NAMED_DNS_LOOPBACK_MESSAGE: &str =
    "dns on a user-defined network must not be a loopback address";

/// ユーザー定義名の `--dns` に IPv6 を指定したときの固定拒否文言(pasta 構成は IPv4 専用。NET-9)。
const NAMED_DNS_IPV6_MESSAGE: &str = "dns on a user-defined network must be an IPv4 address";

const NAMED_NOT_WIRED_MESSAGE: &str = "user-defined networks are not wired to the launch path yet";

/// `--network` の検証済みの選択(NET-6)。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum NetworkSelection {
    /// `none`(loopback だけの新しい network namespace)。
    None,
    /// `host`(ホストの network namespace を共有する)。
    Host,
    /// ユーザー定義名(検証済み。rootless の pasta 構成は #1940 で結線済み。rootful の参加指定は #3069・#3074)。
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

/// net の固定メッセージを保ったまま `TraitError` へ写す(`NetErrorCode` は `#[non_exhaustive]`)。
///
/// 入力検証(FCOPT1 の再検証・CLI の create 検証 `create_network.rs`)と `start --network host` の netns 照合が
/// 共有する写像(REPAIR-1)。返すコードは 4 種(`InvalidArgument`・`Unimplemented`・`ResourceExhausted`・
/// `FailedPrecondition`)に絞り、残りは `Internal` に畳む。この出力は `net12_error_mapping` が固定している。
///
/// コードを保つ写像(cli の pasta 解決・plugin-cri の netsetup・holder の起動が使う)は別の契約で、
/// [`crate::net_error::net_error_to_trait_keeping_code`] にある。本写像を広げると `HostNetns::detect` の
/// `NotFound`・`PermissionDenied` の出力が変わるため、統合していない。
pub fn net_error_to_trait(e: &NetError) -> TraitError {
    let code = match e.code() {
        NetErrorCode::InvalidArgument => ErrorCode::InvalidArgument,
        NetErrorCode::Unimplemented => ErrorCode::Unimplemented,
        NetErrorCode::ResourceExhausted => ErrorCode::ResourceExhausted,
        NetErrorCode::FailedPrecondition => ErrorCode::FailedPrecondition,
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
        // 分類規則は net の `NetworkChoice::parse` が唯一の判定(CLI と共有。REPAIR-1)。
        let selection = match network
            .map(NetworkChoice::parse)
            .transpose()
            .map_err(|e| net_error_to_trait(&e))?
        {
            None => None,
            Some(NetworkChoice::None) => Some(NetworkSelection::None),
            Some(NetworkChoice::Host) => Some(NetworkSelection::Host),
            Some(NetworkChoice::Named(n)) => Some(NetworkSelection::Named(n)),
            Some(NetworkChoice::ContainerRef) => {
                container_ref = true;
                None
            }
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
        // pasta 構成の `--dns` は resolv.conf の nameserver になる。コンテナの netns の loopback は resolver ではない(D1)。
        let named = matches!(selection, Some(NetworkSelection::Named(_)));
        // pasta 構成は常に `-4`(IPv4 専用。NET-9)。IPv6 の nameserver だけでは名前解決できないため受けない。
        if named && addrs.iter().any(IpAddr::is_ipv6) {
            return Err(TraitError::new(
                ErrorCode::InvalidArgument,
                NAMED_DNS_IPV6_MESSAGE,
            ));
        }
        if named && addrs.iter().any(is_loopback_like) {
            return Err(TraitError::new(
                ErrorCode::InvalidArgument,
                NAMED_DNS_LOOPBACK_MESSAGE,
            ));
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

    /// core の `LaunchNetworkMode` へ写す(D7)。指定なしは `FromConfig`、`none` は `Loopback`(実体の CLONE_NEWNET と
    /// `lo` の up は #3064 で実装済み)、`host` は `Host`、ユーザー定義名は Linux で `Attachable`(rootless の pasta 構成。#1940)、
    /// それ以外の OS では `Unimplemented`。
    pub fn launch_network_mode(&self) -> Result<LaunchNetworkMode, TraitError> {
        match &self.selection {
            None => Ok(LaunchNetworkMode::FromConfig),
            Some(NetworkSelection::None) => Ok(LaunchNetworkMode::Loopback),
            Some(NetworkSelection::Host) => Ok(LaunchNetworkMode::Host),
            // rootless の pasta 構成(exec 前の同期点で netns と user namespace の fd を supervisor へ渡す。#1940)。
            // Linux 以外にはこの経路が無い(挙動の差は固定の文言で示す。CLI-1)。
            // `--add-host` / `--dns` は手順 4b の hosts / resolv.conf の生成で反映する(`etc_file_selection`)。
            #[cfg(target_os = "linux")]
            Some(NetworkSelection::Named(_)) => Ok(LaunchNetworkMode::Attachable),
            #[cfg(not(target_os = "linux"))]
            Some(NetworkSelection::Named(_)) => Err(TraitError::new(
                ErrorCode::Unimplemented,
                NAMED_NOT_WIRED_MESSAGE,
            )),
        }
    }

    /// `/etc/hosts`・`/etc/resolv.conf` を生成して載せる種別(#1873・NET-12・D9)。
    ///
    /// `none` / `host` で `--add-host` があれば hosts、`--dns` があれば resolv.conf。ユーザー定義名(pasta 構成)は
    /// `--add-host` があれば hosts、resolv.conf は `--dns` の有無に依らず常に生成する(pasta の `--dns-forward` だけでは
    /// コンテナ内の resolver 設定は変わらないため。12.7・D9)。それ以外(文書なし)は空。生成(start の手順 4b)と
    /// bind(`LaunchOptions::with_etc_files`)が同じ関数で決まり、食い違わない。
    pub fn etc_file_selection(&self) -> EtcFileSelection {
        let mut sel = EtcFileSelection::default();
        match self.selection {
            Some(NetworkSelection::None | NetworkSelection::Host) => {
                if !self.dns.is_empty() {
                    sel = sel.with(EtcFileKind::ResolvConf);
                }
            }
            Some(NetworkSelection::Named(_)) => sel = sel.with(EtcFileKind::ResolvConf),
            None => return sel,
        }
        if !self.add_hosts.is_empty() {
            sel = sel.with(EtcFileKind::Hosts);
        }
        sel
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

    /// NET-6・D8: net の `FailedPrecondition`(host netns の不一致等)は `FailedPrecondition` のまま写り、Internal に畳まれない。
    #[test]
    fn net6_net_error_to_trait_keeps_failed_precondition() {
        let e = NetError::new(NetErrorCode::FailedPrecondition, "host netns mismatch");
        let t = net_error_to_trait(&e);
        assert_eq!(t.code(), ErrorCode::FailedPrecondition);
        assert_eq!(t.message(), "host netns mismatch");
    }

    const INV: Option<ErrorCode> = Some(ErrorCode::InvalidArgument);
    const UNI: Option<ErrorCode> = Some(ErrorCode::Unimplemented);

    /// NET-12・#1873: 生成する種別の判定表(none / host のみ。hosts は add-host、resolv.conf は dns)。
    #[test]
    fn net12_etc_file_selection_table() {
        let sel = |n: Option<&str>, h: &[&str], d: &[&str]| {
            p(n, h, d).expect("parse").etc_file_selection().kinds()
        };
        assert_eq!(
            sel(Some("none"), &["a:192.0.2.1"], &[]),
            vec![EtcFileKind::Hosts]
        );
        assert_eq!(
            sel(Some("host"), &[], &["192.0.2.53"]),
            vec![EtcFileKind::ResolvConf]
        );
        assert_eq!(
            sel(Some("none"), &["a:192.0.2.1"], &["127.0.0.1"]),
            vec![EtcFileKind::Hosts, EtcFileKind::ResolvConf]
        );
        assert!(sel(Some("host"), &[], &[]).is_empty());
        assert!(sel(None, &[], &[]).is_empty());
        // ユーザー定義名(pasta 構成)は --dns が無くても resolv.conf を生成する(既定は 169.254.1.1。12.7・D9)。
        assert_eq!(sel(Some("web"), &[], &[]), vec![EtcFileKind::ResolvConf]);
        assert_eq!(
            sel(Some("web"), &["a:192.0.2.1"], &["192.0.2.53"]),
            vec![EtcFileKind::Hosts, EtcFileKind::ResolvConf]
        );
    }

    /// NET-12・D1: ユーザー定義名の --dns に loopback 系(mapped・compatible・未指定を含む)は指定できない。
    #[test]
    fn net12_named_dns_rejects_loopback() {
        for bad in [
            "127.0.0.1",
            "127.0.0.53",
            "::1",
            "::ffff:127.0.0.1",
            "::127.0.0.1",
            "0.0.0.0",
            "::",
        ] {
            assert_eq!(code(p(Some("web"), &[], &[bad])), INV, "{bad}");
        }
        for ok in ["169.254.1.1", "1.1.1.1", "192.0.2.53"] {
            assert_eq!(code(p(Some("web"), &[], &[ok])), None, "{ok}");
        }
    }

    /// NET-9・NET-12: ユーザー定義名(pasta 構成は IPv4 専用)の --dns は IPv6 を拒否し、IPv4 は受理する。
    /// none / host の --dns は従来どおり IPv6 を受ける。
    #[test]
    fn net9_named_dns_rejects_ipv6_and_accepts_ipv4() {
        for bad in ["2001:db8::53", "fe80::1", "::ffff:1.1.1.1"] {
            let e = p(Some("web"), &[], &[bad]).expect_err(bad);
            assert_eq!(e.code(), ErrorCode::InvalidArgument, "{bad}");
            assert_eq!(
                e.message(),
                "dns on a user-defined network must be an IPv4 address"
            );
        }
        // 1 件でも IPv6 が混じれば拒否する。
        assert_eq!(code(p(Some("web"), &[], &["1.1.1.1", "2001:db8::53"])), INV);
        for ok in ["1.1.1.1", "169.254.1.1", "192.0.2.53"] {
            assert_eq!(code(p(Some("web"), &[], &[ok])), None, "{ok}");
        }
        assert_eq!(code(p(Some("host"), &[], &["2001:db8::53"])), None);
    }

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
            assert_eq!(e.message(), "network name is reserved");
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
        // ユーザー定義名は Linux で Attachable(#1940)、それ以外の OS では Unimplemented。
        #[cfg(target_os = "linux")]
        assert_eq!(
            mode(Some("web")).expect("named"),
            LaunchNetworkMode::Attachable
        );
        #[cfg(not(target_os = "linux"))]
        assert_eq!(
            mode(Some("web")).expect_err("named").code(),
            ErrorCode::Unimplemented
        );
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
