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
//! | `FromConfig` | 有り(path 付きで、user と ipc の path の組がある〔pod の join。#2872〕) | `PodJoined`(pod の netns へ参加する) |
//! | `FromConfig` | 有り(上記以外) | `Unimplemented`(現行どおり) |
//! | `Loopback` | 無し、または path 無し | `NewLoopback`(新しい netns と lo の up) |
//! | `Loopback` | path 付き / 重複 | `InvalidArgument` |
//! | `Attachable` | 無し、または path 無し | `NewLoopback`(`Loopback` と同じ。exec 前の同期点で netns と user namespace の fd を呼び出し側へ渡す。#1939) |
//! | `Attachable` | path 付き / 重複 | `InvalidArgument` |
//! | `Host` | 無し、または path 無し | `HostShared`(config のエントリより起動オプションを優先。`--ipc host` と同じ) |
//! | `Host` | path 付き / 重複 | `InvalidArgument` |
//! | `JoinPinned` | 無し、または path 無し | `PinnedJoined`(init user namespace 所有の pin 済み netns へ、user namespace の作成前に参加する。D12・#3069) |
//! | `JoinPinned` | path 付き / 重複 | `InvalidArgument` |
//!
//! # 実体と未実装(REPAIR-3)
//!
//! `NewLoopback` の実体(CLONE_NEWNET と lo の up)は #3064 で入った。rootless の中間プロセスが netns を作り、
//! exec の前に `exec::unshare_and_configure` が `lo` を up にする。exec 直前の同期点での netns 素性の照合(D8)は core に実装済み(#3206。`exec::netns_sync`。`Host`・`Loopback`・`Attachable` の起動だけが通り、`Attachable` は fd 2 本と呼び出し側の合図を伴う〔#1939〕)。`network_mode=host` の構造化ログと net crate の `HostNetns` を使う結線は supervisor の start が担い、#1873(PR #3322)で実装済み。

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
    /// 外から付ける netns(rootless の pasta 構成。NET-9・CORE-6・#1939)。新しい netns と `lo` の up は `Loopback` と同じ。
    /// 違いは、exec 直前の同期点で子が netns と user namespace の fd を**この順で**呼び出し側へ渡し、呼び出し側が注入した
    /// 準備処理(`NetnsAttachHook`。holder の保持と pasta の起動は supervisor が #1940 で担う)が成功してから合図を受けて
    /// exec する点だけ。rootless の権限モデルに限り、ビルドの時点で他は拒否される(`ProductionLauncherBuilder::build`)。
    Attachable,
    /// rootful のユーザー定義ネットワークの netns(init user namespace 所有。`NetworkPlugin::create_netns` が作り置き場へ pin
    /// したもの)へ参加する(`docs/design/network-wiring.md` D12。NET-1・SEC-1・CORE-3・#3069)。パスと (dev, ino) は
    /// `LaunchOptions::with_netns_join` で対にして渡す。core が 1 回だけ開いて fd に固定し、user namespace を作る**前**に
    /// `setns(CLONE_NEWNET)` する。pod の join(`FromConfig` の path 付き。#2872)とは別の入口。
    JoinPinned,
}

/// 突き合わせの結果(実効の network の扱い)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EffectiveNetwork {
    /// ホストの network namespace を共有する(新しい netns を作らない)。
    HostShared,
    /// 新しい network namespace を作り lo を up する(実体は #3064 で実装済み)。
    NewLoopback,
    /// pod の保持役が作った network namespace へ、固定した fd で参加する(pod の user・ipc・net の join。
    /// CORE-3・SEC-5・NET-3・#2872。設計 #2838 の H7)。netns は作らず `lo` も触らない(保持役の責務)。
    PodJoined,
    /// 起動オプションで指定した init user namespace 所有の pin 済み netns へ、固定した fd で参加する(D12。
    /// NET-1・SEC-1・CORE-3・#3069)。netns は作らず `lo` も触らない(plugin の責務)。
    PinnedJoined,
}

/// D7 の表で config と起動オプションを突き合わせる(モジュール doc)。
///
/// `pod_net_join` は、`NamespaceJoin::paths_of` が network の path を含む user・ipc・net の組を返したか(start が先に
/// 純粋関数で判定して渡す)。`FromConfig` の path 付きエントリは、これが真のときだけ `PodJoined` になる。
pub(super) fn reconcile_network(
    config: &OciConfig,
    mode: LaunchNetworkMode,
    pod_net_join: bool,
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
            Some(n) if pod_net_join && !has_second && n.path().is_some() => {
                Ok(EffectiveNetwork::PodJoined)
            }
            Some(_) => Err(TraitError::new(
                ErrorCode::Unimplemented,
                "start does not support yet: network / cgroup / time namespace",
            )),
        },
        LaunchNetworkMode::Loopback
        | LaunchNetworkMode::Attachable
        | LaunchNetworkMode::Host
        | LaunchNetworkMode::JoinPinned => {
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
            Ok(match mode {
                LaunchNetworkMode::Host => EffectiveNetwork::HostShared,
                LaunchNetworkMode::JoinPinned => EffectiveNetwork::PinnedJoined,
                _ => EffectiveNetwork::NewLoopback,
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
        reconcile_network(&config_with(ns), mode, false)
    }

    /// CORE-3・SEC-5・NET-3・#2872: `FromConfig` の path 付き network は、pod の組の path があるとき(`pod_net_join`)だけ
    /// `PodJoined`。path 無し・重複は組があっても `Unimplemented` のまま。
    #[test]
    fn net3_2872_from_config_pod_net_join_accepts_only_a_path_entry() {
        let reconcile = |ns: &str, pod: bool| {
            reconcile_network(&config_with(ns), LaunchNetworkMode::FromConfig, pod)
        };
        assert_eq!(
            reconcile(NET_PATH, true).unwrap(),
            EffectiveNetwork::PodJoined
        );
        for (ns, pod) in [(NET_PATH, false), (NET, true), (NET_TWICE, true)] {
            let err = reconcile(ns, pod).unwrap_err();
            assert_eq!(err.code(), ErrorCode::Unimplemented);
            assert_eq!(
                err.message(),
                "start does not support yet: network / cgroup / time namespace"
            );
        }
        // 他モードは pod の組があっても path 付きを拒否する(起動オプションが優先。`InvalidArgument`)。
        for mode in [
            LaunchNetworkMode::Loopback,
            LaunchNetworkMode::Attachable,
            LaunchNetworkMode::Host,
        ] {
            let err = reconcile_network(&config_with(NET_PATH), mode, true).unwrap_err();
            assert_eq!(err.code(), ErrorCode::InvalidArgument);
        }
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
        for mode in [
            LaunchNetworkMode::Loopback,
            LaunchNetworkMode::Attachable,
            LaunchNetworkMode::Host,
        ] {
            let err = run(NET_PATH, mode).unwrap_err();
            assert_eq!(err.code(), ErrorCode::InvalidArgument);
            assert_eq!(
                err.message(),
                "the network mode conflicts with a linux.namespaces network path"
            );
            assert!(!err.message().contains("/run/netns"));
        }
    }

    /// NET-9・CORE-6(#1939): `Attachable` は `Loopback` と同じ行(エントリ無し・path 無しは `NewLoopback`)。
    #[test]
    fn net9_attachable_accepts_no_entry_and_pathless_entry() {
        for ns in [NONE, NET] {
            assert_eq!(
                run(ns, LaunchNetworkMode::Attachable).unwrap(),
                EffectiveNetwork::NewLoopback
            );
        }
    }

    /// NET-1・SEC-1・CORE-3(#3069): `JoinPinned` はエントリ無し・path 無しで `PinnedJoined`、path 付き・重複は
    /// `InvalidArgument`(既存の固定文言)。
    #[test]
    fn net1_sec1_3069_join_pinned_accepts_only_pathless_entries() {
        for ns in [NONE, NET] {
            assert_eq!(
                run(ns, LaunchNetworkMode::JoinPinned).unwrap(),
                EffectiveNetwork::PinnedJoined
            );
        }
        let err = run(NET_PATH, LaunchNetworkMode::JoinPinned).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        assert_eq!(
            err.message(),
            "the network mode conflicts with a linux.namespaces network path"
        );
        let err = run(NET_TWICE, LaunchNetworkMode::JoinPinned).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        assert_eq!(
            err.message(),
            "linux.namespaces has a duplicate network entry"
        );
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
        for mode in [
            LaunchNetworkMode::Loopback,
            LaunchNetworkMode::Attachable,
            LaunchNetworkMode::Host,
        ] {
            let err = run(NET_TWICE, mode).unwrap_err();
            assert_eq!(err.code(), ErrorCode::InvalidArgument);
            assert_eq!(
                err.message(),
                "linux.namespaces has a duplicate network entry"
            );
        }
    }
}
