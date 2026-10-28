//! コンテナの network namespace の扱い(起動オプション側の指定)と config.json との突き合わせ(NET-6・SEC-1。#3058)。
//!
//! # 役割と呼び出し文脈
//!
//! `LaunchOptions` の network モード([`LaunchNetworkMode`])と `linux.namespaces` の network エントリを、
//! `docs/design/network-wiring.md` D7 の表で突き合わせ、実効の扱い([`EffectiveNetwork`])を決める OS 非依存の
//! 純粋関数 [`reconcile_network`] を置く。start の `build_spec` が予約(Running への更新)と fork より前に呼び、
//! 失敗してもプロセスのいない Running を残さない。launcher は `LaunchSpec` に載った結果を自身のモードと照合する。
//!
//! | モード | config の network エントリ | 結果 |
//! | ---- | ---- | ---- |
//! | `FromConfig` | 無し | `HostShared`(現行どおりホストの netns を共有) |
//! | `FromConfig` | 有り | `Unimplemented`(現行どおり) |
//! | `Loopback` | 無し、または path 無し | `NewLoopback`(新しい netns と lo の up) |
//! | `Loopback` | path 付き / 重複 | `InvalidArgument` |
//! | `Host` | 無し、または path 無し | `HostShared`(config のエントリより起動オプションを優先。`--ipc host` と同じ) |
//! | `Host` | path 付き / 重複 | `InvalidArgument` |
//!
//! # 実体と未実装(REPAIR-3)
//!
//! `NewLoopback` の実体(CLONE_NEWNET と lo の up)は #3064 で入った。rootless の中間プロセスが netns を作り、
//! exec の前に `exec::unshare_and_configure` が `lo` を up にする。exec 直前の同期点での netns 素性の照合(D8)は core に実装済み(#3206。`exec::netns_sync`。`Host` と `Loopback` の起動だけが通る)。`network_mode=host` の構造化ログと net crate の `HostNetns` を使う結線は未実装(#1873)。

use super::config::{NamespaceKind, OciConfig};
use crate::traits::types::{ErrorCode, TraitError};

/// コンテナの network namespace の扱い(NET-6・SEC-1)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LaunchNetworkMode {
    /// config.json の `linux.namespaces` に従う(既定。現行の挙動と同じ)。
    FromConfig,
    /// 新しい network namespace を作り lo だけを up する(`none`)。
    Loopback,
    /// ホストの network namespace を共有する(`host`)。起動オプションだけで許し、config からは選べない。
    Host,
}

/// 突き合わせの結果(実効の network の扱い)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EffectiveNetwork {
    /// ホストの network namespace を共有する(新しい netns を作らない)。
    HostShared,
    /// 新しい network namespace を作り lo を up する(実体は #3064 で実装済み)。
    NewLoopback,
}

/// D7 の表で config と起動オプションを突き合わせる(モジュール doc)。
pub(super) fn reconcile_network(
    config: &OciConfig,
    mode: LaunchNetworkMode,
) -> Result<EffectiveNetwork, TraitError> {
    let mut entries = config
        .namespaces()
        .iter()
        .filter(|n| n.kind() == NamespaceKind::Network);
    let first = entries.next();
    let has_second = entries.next().is_some();
    match mode {
        LaunchNetworkMode::FromConfig => match first {
            None => Ok(EffectiveNetwork::HostShared),
            Some(_) => Err(TraitError::new(
                ErrorCode::Unimplemented,
                "start does not support yet: network / cgroup / time namespace",
            )),
        },
        LaunchNetworkMode::Loopback | LaunchNetworkMode::Host => {
            if has_second {
                return Err(TraitError::new(
                    ErrorCode::InvalidArgument,
                    "linux.namespaces has a duplicate network entry",
                ));
            }
            if first.is_some_and(|n| n.path().is_some()) {
                return Err(TraitError::new(
                    ErrorCode::InvalidArgument,
                    "the network mode conflicts with a linux.namespaces network path",
                ));
            }
            Ok(if mode == LaunchNetworkMode::Loopback {
                EffectiveNetwork::NewLoopback
            } else {
                EffectiveNetwork::HostShared
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_with(namespaces: &str) -> OciConfig {
        let json = format!(
            r#"{{"ociVersion":"1.0.2","root":{{"path":"rootfs"}},
            "process":{{"user":{{"uid":0,"gid":0}},"args":["/bin/true"],"cwd":"/"}},
            "linux":{{"namespaces":[{namespaces}]}}}}"#
        );
        super::super::config::parse_config_bytes(json.as_bytes()).expect("config")
    }

    const NONE: &str = r#"{"type":"pid"}"#;
    const NET: &str = r#"{"type":"pid"},{"type":"network"}"#;
    const NET_PATH: &str = r#"{"type":"pid"},{"type":"network","path":"/run/netns/x"}"#;
    const NET_TWICE: &str = r#"{"type":"network"},{"type":"network"}"#;

    fn run(ns: &str, mode: LaunchNetworkMode) -> Result<EffectiveNetwork, TraitError> {
        reconcile_network(&config_with(ns), mode)
    }

    #[test]
    fn net6_from_config_without_entry_shares_host() {
        assert_eq!(
            run(NONE, LaunchNetworkMode::FromConfig).unwrap(),
            EffectiveNetwork::HostShared
        );
    }

    #[test]
    fn net6_from_config_with_entry_is_unimplemented_as_before() {
        for ns in [NET, NET_PATH] {
            let err = run(ns, LaunchNetworkMode::FromConfig).unwrap_err();
            assert_eq!(err.code(), ErrorCode::Unimplemented);
            assert_eq!(
                err.message(),
                "start does not support yet: network / cgroup / time namespace"
            );
        }
    }

    #[test]
    fn net6_loopback_accepts_no_entry_and_pathless_entry() {
        for ns in [NONE, NET] {
            assert_eq!(
                run(ns, LaunchNetworkMode::Loopback).unwrap(),
                EffectiveNetwork::NewLoopback
            );
        }
    }

    #[test]
    fn net6_sec1_loopback_and_host_reject_path_without_leaking_it() {
        for mode in [LaunchNetworkMode::Loopback, LaunchNetworkMode::Host] {
            let err = run(NET_PATH, mode).unwrap_err();
            assert_eq!(err.code(), ErrorCode::InvalidArgument);
            assert_eq!(
                err.message(),
                "the network mode conflicts with a linux.namespaces network path"
            );
            assert!(!err.message().contains("/run/netns"));
        }
    }

    #[test]
    fn net6_host_accepts_no_entry_and_pathless_entry() {
        for ns in [NONE, NET] {
            assert_eq!(
                run(ns, LaunchNetworkMode::Host).unwrap(),
                EffectiveNetwork::HostShared
            );
        }
    }

    #[test]
    fn net6_sec1_loopback_and_host_reject_duplicate_entries() {
        for mode in [LaunchNetworkMode::Loopback, LaunchNetworkMode::Host] {
            let err = run(NET_TWICE, mode).unwrap_err();
            assert_eq!(err.code(), ErrorCode::InvalidArgument);
            assert_eq!(
                err.message(),
                "linux.namespaces has a duplicate network entry"
            );
        }
    }
}
