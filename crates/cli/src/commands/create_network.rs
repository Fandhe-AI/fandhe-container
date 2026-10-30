//! `create` の `--network`・`--add-host`・`--dns` の意味検証(NET-12・NET-6・CLI-1・REPAIR-3・#1871)。
//!
//! # 役割と呼び出し文脈
//!
//! `args::parse_create` が集めた生の文字列([`CreateNetworkArgs`])を、`create_start::run_create` が
//! `production_runtime` へ渡す `build` クロージャの**先頭**で [`validate_network_options`] に通す。
//! `production_runtime` は `build` の後に状態ストアを開き(状態ルートが無ければ作る)、`build_create` は
//! イメージストアを開き `--env-file` を読むため、不正入力の拒否はそれらの副作用より前でなければならない(D2)。
//!
//! 形式の判定は net の検証関数(`parse_add_hosts`・`parse_ip_addr`・`ResolvConfPlan::for_mode`・
//! `NetworkName::new`)を唯一の判定とし、CLI は hostname・IP の規則を二重に書かない。
//! `--network` の分類は net の `NetworkChoice::parse` を唯一の判定とし(supervisor の `FCOPT1` 再検証と共有。D1・REPAIR-1)、
//! `NetError` の写像も supervisor の `net_error_to_trait` を共有する。
//!
//! # 判定順(`INVALID_ARGUMENT` が `UNIMPLEMENTED` に優先する)
//!
//! 1. `--network`: `none` / `host` はモード確定。`bridge` / `default` は `INVALID_ARGUMENT`。
//!    `container:` 始まりは保留(`UNIMPLEMENTED`)。それ以外は `NetworkName::new` で検証し、ユーザー定義名になる。
//! 2. `--add-host`: `parse_add_hosts` で全件検証(最初の `:` で分割。`name:::1` は (`name`, `::1`))。
//! 3. `--dns`: 全件を `parse_ip_addr` で検証。モードが `none` / `host` のときは続けて
//!    `ResolvConfPlan::for_mode` を呼び、none の非 loopback を拒否する。ユーザー定義名のときは supervisor の
//!    `NetworkOptions::parse` を通し、`--dns` の制約(IPv6・loopback 系の拒否)を作成前に適用する(規則を二重に書かない。#3329)。
//! 4. `-p` / `--publish`(#3200・NET-9・NET-3): net の `PastaPortForwards::parse_all` で全件を検証する
//!    (IPv6・範囲・ポート 0・重複・wildcard との重なりは `INVALID_ARGUMENT`)。ユーザー定義名の `--network` と組でなければ
//!    (指定なし・`none`・`host`・`container:`)モードによらず `INVALID_ARGUMENT`(rootless-network.md 12.15)。
//!    組であれば権限モデルを解決し、rootful は `UNIMPLEMENTED`(D13 の判断待ち)、解決の失敗は `FAILED_PRECONDITION`。
//!    解決は `-p` があるときだけ行い、通常の create に stat を増やさない。
//!
//! # ユーザー定義名の段(#3199・#3329)
//!
//! `--network` がユーザー定義名のとき、手順 1〜4 の後に `create_pasta`(インストールの種別の判定、定義ストアの存在・構成の
//! 照合 [`require_named_definition`]、`--pasta-path` / `--pasta-path-search` の解決・検証。NET-9)が入る。判定の順は
//! 「種別(rootful・非 Linux は `UNIMPLEMENTED`)→ pasta のフラグの有無 → 定義の照合(無ければ `NOT_FOUND`)→ pasta の
//! 解決(子プロセスの起動)」で、存在しないネットワークのために子プロセスを起動しない。いずれも状態ルート・`@networks`・
//! イメージストアの作成と `--env-file` の読み取りより前(D2)。その後の [`reject_unwired_network`] が残す拒否は
//! `container:` と非 Linux の network 系の指定だけ。start でも同じ照合をやり直す(supervisor の手順 2c。D10)。
//!
//! # 未実装の将来仕様(REPAIR-3)
//!
//! Linux の `none` / `host` / `--add-host` / `--dns` は #1873(PR #3322。文書 `FCOPT1` への記録と既定 `none` の導入。D4)で、
//! rootless のユーザー定義名(`pasta`・`publish` の記録を含む)は #3329 で結線済み。残る未結線の指定(`container:`、
//! 非 Linux の network 系の指定すべて)は、検証を通っても受理して黙って捨てずに `UNIMPLEMENTED` で拒否する
//! (`reject_unwired_network`)。rootful のユーザー定義名は D13 の判断待ちで、作成前に `UNIMPLEMENTED`
//! (`create_pasta::decide`)。Linux 以外は MAC / WIN 系の結線の後続。`--network` を省略しても #1871 では none 扱いにしない。
//!
//! エラーは固定の英語文言で、入力値を含めない。

use std::path::Path;
use std::sync::Arc;

use fandhe_container_core::state_store::StateRoot;
use fandhe_container_core::traits::types::{ErrorCode, TraitError};
use fandhe_container_net::add_host_dns::resolv_conf::ResolvConfPlan;
use fandhe_container_net::add_host_dns::{parse_add_hosts, parse_ip_addr};
use fandhe_container_net::instrument::NetOpRecorder;
use fandhe_container_net::network::NetworkName;
use fandhe_container_net::network_mode::{NetworkChoice, NetworkMode};
use fandhe_container_net::network_store::DEFAULT_LOCK_TIMEOUT;
use fandhe_container_net::pasta::PastaPortForwards;

use fandhe_container_supervisor::container_options::network::{NetworkOptions, net_error_to_trait};
use fandhe_container_supervisor::container_options::network_definition::{
    DefinitionCheck, check_pasta_definition,
};

use super::args::{CreateNetworkArgs, GlobalArgs};

/// 結線されていない指定(`container:`)の固定拒否文言。
const NOT_WIRED_MESSAGE: &str = "container: networks are not wired to the launch path yet";
/// rootful のユーザー定義名の固定拒否文言(D13 の判断待ち。`network create` と共有)。
pub(super) const MSG_ROOTFUL: &str =
    "user-defined networks on rootful installations are not supported yet";
/// ユーザー定義名の定義が無い(`network create` の `network not found` と同じ文言)。
pub(super) const MSG_NOT_FOUND: &str = "network not found";
/// 定義が rootless(pasta)構成ではない。
const MSG_NOT_ROOTLESS: &str = "network is not a rootless network";
/// 非 Linux で network 系の指定を拒否する固定文言(MAC / WIN 系の結線の後続。D1)。
pub(super) const PLATFORM_MESSAGE: &str = "network options are not supported on this platform yet";
/// `-p` がユーザー定義名の `--network` と組でないときの固定拒否文言。
const PUBLISH_NEEDS_NAMED_MESSAGE: &str = "port publishing requires a user-defined network";
/// rootful の `-p` の固定拒否文言(D13 の判断待ち)。
pub(super) const PUBLISH_ROOTFUL_MESSAGE: &str =
    "port publishing on rootful installations is not supported yet";
/// `-p` の権限モデルを解決できない環境の固定拒否文言(非 Linux)。
const PUBLISH_UNAVAILABLE_MESSAGE: &str = "port publishing is not supported on this platform yet";

/// `-p` の可否を決める権限モデル(NET-9・D13)。rootless の pasta だけが対象。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PublishPrivilege {
    /// rootless のインストール(CLI の隣に特権ランチャーが無い)。
    // 非 Linux の本番解決は構築しない(Linux の解決と試験が使う)。
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    Rootless,
    /// rootful のインストール(uid 0、または信頼できるランチャーが隣にある)。
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    Rootful,
    /// 権限モデルを判定できない環境(network 系の結線が無い OS)。
    // Linux の本番解決は構築しない(非 Linux の解決と試験が使う)。
    #[cfg_attr(target_os = "linux", allow(dead_code))]
    Unavailable,
}

/// 本番の権限モデルの解決。`start` と同じ `classify_launcher_beside` を使い、規則を重ねて書かない(SUP-14)。
///
/// ランチャーが在るのに信頼できない場合は rootless へ黙って落とさず `FailedPrecondition` にする。
#[cfg(target_os = "linux")]
pub(super) fn resolve_publish_privilege() -> Result<PublishPrivilege, TraitError> {
    use crate::user_scope::{Identity, identity_from_status, read_self_status};
    use fandhe_container_supervisor::start_client::{LauncherPresence, classify_launcher_beside};
    let fail = |m: &'static str| TraitError::new(ErrorCode::FailedPrecondition, m);
    let euid = match read_self_status()
        .as_deref()
        .map_or(Identity::Unreadable, identity_from_status)
    {
        Identity::Rootless { euid } => euid,
        Identity::Rootful => return Ok(PublishPrivilege::Rootful),
        Identity::Unreadable => return Err(fail("process status is unreadable")),
    };
    let exe =
        std::env::current_exe().map_err(|_| fail("the cli executable path cannot be resolved"))?;
    match classify_launcher_beside(&exe, euid) {
        Ok(LauncherPresence::Absent) => Ok(PublishPrivilege::Rootless),
        Ok(LauncherPresence::Trusted(_)) => Ok(PublishPrivilege::Rootful),
        Ok(_) => Err(fail("privileged launcher is not a trusted executable")),
        Err(_) => Err(fail("the cli executable path cannot be resolved")),
    }
}

/// 本番の権限モデルの解決(非 Linux は network 系が未結線のため判定しない)。
#[cfg(not(target_os = "linux"))]
pub(super) fn resolve_publish_privilege() -> Result<PublishPrivilege, TraitError> {
    Ok(PublishPrivilege::Unavailable)
}

/// 4 つのフラグを作成前に検証する。指定が無ければ `Ok(())`、不正は `InvalidArgument`、
/// 正しくても指定があれば `Unimplemented`(D3)。`resolve_privilege` は `-p` がユーザー定義名と組のときだけ呼ぶ。
#[cfg(test)]
pub(super) fn validate_network_options(
    args: &CreateNetworkArgs,
    resolve_privilege: impl FnOnce() -> Result<PublishPrivilege, TraitError>,
) -> Result<(), TraitError> {
    check_network_options(args, resolve_privilege)?;
    reject_unwired_network(args, cfg!(target_os = "linux"))
}

/// 4 つのフラグの形式検証だけを行い、`--network` がユーザー定義名ならその名前を返す(`container:` は `Unimplemented` にしない)。
///
/// `run_create` が pasta の段(`create_pasta`。#3199・#3329)を `InvalidArgument` の後・`Unimplemented` の前に挟むために
/// 分けてある。`resolve_privilege` は `-p` がユーザー定義名と組のときだけ呼ぶ(rootful 等の `Unimplemented` はここで返る)。
pub(super) fn check_network_options(
    args: &CreateNetworkArgs,
    resolve_privilege: impl FnOnce() -> Result<PublishPrivilege, TraitError>,
) -> Result<Option<NetworkName>, TraitError> {
    let choice = args
        .network
        .as_deref()
        .map(NetworkChoice::parse)
        .transpose()
        .map_err(|e| net_error_to_trait(&e))?;
    if !args.add_hosts.is_empty() {
        parse_add_hosts(args.add_hosts.iter().map(String::as_str))
            .map_err(|e| net_error_to_trait(&e))?;
    }
    for d in &args.dns {
        parse_ip_addr(d).map_err(|e| net_error_to_trait(&e))?;
    }
    let mode = match choice {
        Some(NetworkChoice::None) => Some(NetworkMode::None),
        Some(NetworkChoice::Host) => Some(NetworkMode::Host),
        // 名前つき・container: は for_mode(Bridge は UNIMPLEMENTED を返して検出を隠す)を通さない。
        Some(NetworkChoice::Named(_) | NetworkChoice::ContainerRef) => None,
        // 省略は `none` 扱い(D4・#1873。文書へは `none` が書かれる)。`--dns` の none の制約を create の時点で適用し、
        // supervisor の再検証との食い違いで start だけが失敗する状態を作らない。
        None => Some(NetworkMode::None),
    };
    if let Some(mode) = mode {
        let dns: Vec<&str> = args.dns.iter().map(String::as_str).collect();
        ResolvConfPlan::for_mode(mode, &dns).map_err(|e| net_error_to_trait(&e))?;
    }
    // ユーザー定義名の `--dns` の制約(IPv6・loopback 系)は supervisor の `NetworkOptions::parse` が唯一の判定で、
    // start の再検証と同じ関門を作成前に通す(副作用より前の拒否。D2・#3329)。
    if let Some(NetworkChoice::Named(n)) = &choice {
        NetworkOptions::parse(Some(n.as_str()), &args.add_hosts, &args.dns, &args.publish)?;
    }
    if !args.publish.is_empty() {
        PastaPortForwards::parse_all(args.publish.iter().map(String::as_str))
            .map_err(|e| net_error_to_trait(&e))?;
        if !matches!(choice, Some(NetworkChoice::Named(_))) {
            return Err(TraitError::new(
                ErrorCode::InvalidArgument,
                PUBLISH_NEEDS_NAMED_MESSAGE,
            ));
        }
        match resolve_privilege()? {
            PublishPrivilege::Rootless => {}
            PublishPrivilege::Rootful => {
                return Err(TraitError::new(
                    ErrorCode::Unimplemented,
                    PUBLISH_ROOTFUL_MESSAGE,
                ));
            }
            PublishPrivilege::Unavailable => {
                return Err(TraitError::new(
                    ErrorCode::Unimplemented,
                    PUBLISH_UNAVAILABLE_MESSAGE,
                ));
            }
        }
    }
    Ok(match choice {
        Some(NetworkChoice::Named(n)) => Some(n),
        _ => None,
    })
}

/// ユーザー定義名の定義が定義ストアにあり、rootless(pasta)構成であることを、何も作らずに確かめる(D2・D10・#3329)。
///
/// 状態ルートは [`StateRoot::resolve`](パスを組み立てるだけで副作用なし)で求め、ストアは `open_existing` で
/// 開くため、状態ルート・`@networks` を作らない。start も同じ照合をやり直す(supervisor の手順 2c)。
///
/// `recorder` は本番では `run_create` が `CliNetRecorder` を渡し、定義ストアの `network.store.open` / `get` が
/// `FANDHE_CONTAINER_OP_LOG` へ出る(start の再照合と同じ操作名。REPAIR-4・#3530)。
pub(super) fn require_named_definition(
    global: &GlobalArgs,
    name: &NetworkName,
    recorder: Option<Arc<dyn NetOpRecorder>>,
) -> Result<(), TraitError> {
    let root = StateRoot::resolve(global.root.clone())?;
    require_named_definition_at(root.path(), name, recorder)
}

/// [`require_named_definition`] の本体(状態ルートを直接渡せる。試験用の入口)。
fn require_named_definition_at(
    root: &Path,
    name: &NetworkName,
    recorder: Option<Arc<dyn NetOpRecorder>>,
) -> Result<(), TraitError> {
    check_pasta_definition(root, name, DEFAULT_LOCK_TIMEOUT, recorder).map_err(|c| match c {
        DefinitionCheck::Missing => TraitError::new(ErrorCode::NotFound, MSG_NOT_FOUND),
        DefinitionCheck::NotPasta => {
            TraitError::new(ErrorCode::FailedPrecondition, MSG_NOT_ROOTLESS)
        }
        // net の文言は固定の英文で入力値を含まない。コードを保つ(`Internal` に潰さない)。
        DefinitionCheck::Store(e) => {
            fandhe_container_supervisor::net_error::net_error_to_trait_keeping_code(&e)
        }
    })
}

/// 起動経路に結線されていない指定を `Unimplemented` で拒否する(D3・#1873。形式の検証は済んでいる前提)。
///
/// Linux は `none` / `host` と `--add-host` / `--dns`、rootless のユーザー定義名と `-p`(#3329)を受ける
/// (supervisor の start が反映する)。残る拒否は `container:`(将来仕様)と、非 Linux の network 系の指定すべて
/// (MAC / WIN 系の結線の後続。`linux` は試験で差し替えるための引数)。rootful のユーザー定義名と `-p` は D13 の
/// 判断待ちで、本関数より前の段(`create_pasta::decide`・`check_network_options`)が `UNIMPLEMENTED` にする。
pub(super) fn reject_unwired_network(
    args: &CreateNetworkArgs,
    linux: bool,
) -> Result<(), TraitError> {
    let unwired = args
        .network
        .as_deref()
        .map(NetworkChoice::parse)
        .and_then(Result::ok)
        .is_some_and(|c| matches!(c, NetworkChoice::ContainerRef));
    if unwired {
        return Err(TraitError::new(ErrorCode::Unimplemented, NOT_WIRED_MESSAGE));
    }
    if !linux && (args.network.is_some() || !args.add_hosts.is_empty() || !args.dns.is_empty()) {
        return Err(TraitError::new(ErrorCode::Unimplemented, PLATFORM_MESSAGE));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use fandhe_container_net::error::{NetError, NetErrorCode};

    fn a(network: Option<&str>, hosts: &[&str], dns: &[&str]) -> CreateNetworkArgs {
        CreateNetworkArgs {
            network: network.map(str::to_owned),
            add_hosts: hosts.iter().map(|s| (*s).to_owned()).collect(),
            dns: dns.iter().map(|s| (*s).to_owned()).collect(),
            publish: Vec::new(),
        }
    }

    fn ap(network: Option<&str>, publish: &[&str]) -> CreateNetworkArgs {
        CreateNetworkArgs {
            publish: publish.iter().map(|s| (*s).to_owned()).collect(),
            ..a(network, &[], &[])
        }
    }

    /// 権限モデルの解決を差し替えて判定し、解決が呼ばれた回数も返す。
    fn run(
        args: &CreateNetworkArgs,
        p: Result<PublishPrivilege, TraitError>,
    ) -> (Option<ErrorCode>, usize) {
        let calls = std::cell::Cell::new(0);
        let r = validate_network_options(args, || {
            calls.set(calls.get() + 1);
            p
        });
        (r.err().map(|e| e.code()), calls.get())
    }

    fn rootless() -> Result<PublishPrivilege, TraitError> {
        Ok(PublishPrivilege::Rootless)
    }

    fn code(args: &CreateNetworkArgs) -> Option<ErrorCode> {
        validate_network_options(args, || panic!("privilege must not be resolved"))
            .err()
            .map(|e| e.code())
    }

    const INV: Option<ErrorCode> = Some(ErrorCode::InvalidArgument);
    const UNI: Option<ErrorCode> = Some(ErrorCode::Unimplemented);
    /// none / host / add-host / dns は Linux では受理し、非 Linux では `UNIMPLEMENTED`(#1873・D1)。
    const WIRED: Option<ErrorCode> = if cfg!(target_os = "linux") { None } else { UNI };

    /// NET-12: 指定が無ければ従来どおり何も拒否しない。
    #[test]
    fn net12_empty_is_ok() {
        assert_eq!(code(&a(None, &[], &[])), None);
    }

    /// NET-12・D1: `--network` の判定表。
    #[test]
    fn net12_network_decision_table() {
        assert_eq!(code(&a(Some("bridge"), &[], &[])), INV);
        assert_eq!(code(&a(Some("default"), &[], &[])), INV);
        assert_eq!(code(&a(Some("Web"), &[], &[])), INV);
        assert_eq!(code(&a(Some(".x"), &[], &[])), INV);
        assert_eq!(code(&a(Some("container:x"), &[], &[])), UNI);
        assert_eq!(code(&a(Some("container:x"), &["bad"], &[])), INV);
        assert_eq!(code(&a(Some("none"), &[], &[])), WIRED);
        assert_eq!(code(&a(Some("host"), &[], &[])), WIRED);
        // ユーザー定義名は形式の検証を通れば Linux では受理される(rootless の定義の照合は create_pasta の段。#3329)。
        // 非 Linux は network 系の指定すべてが UNIMPLEMENTED。
        assert_eq!(code(&a(Some("web"), &[], &[])), WIRED);
        assert_eq!(
            code(&a(Some("web"), &["h:192.0.2.1"], &["192.0.2.53"])),
            WIRED
        );
    }

    /// NET-12・D2(#3329): ユーザー定義名の `--dns` の制約(IPv6・loopback 系)は、作成前の形式検証で `INVALID_ARGUMENT`。
    #[test]
    fn net12_3329_named_dns_constraints_apply_before_side_effects() {
        for bad in ["::1", "2001:db8::1", "127.0.0.1", "127.0.0.53"] {
            assert_eq!(code(&a(Some("web"), &[], &[bad])), INV, "{bad}");
        }
        assert_eq!(code(&a(Some("web"), &[], &["192.0.2.53"])), WIRED);
    }

    /// NET-12(#3329): 名前つきなら名前そのものを返し、none / host / `container:` / 省略は `None`。
    #[test]
    fn net12_3329_check_returns_the_named_network() {
        let r = |n: Option<&str>| {
            check_network_options(&a(n, &[], &[]), || panic!("no privilege"))
                .map(|o| o.map(|n| n.as_str().to_owned()))
        };
        assert_eq!(r(Some("web")).unwrap(), Some("web".to_owned()));
        for n in [None, Some("none"), Some("host"), Some("container:x")] {
            assert_eq!(r(n).unwrap(), None, "{n:?}");
        }
    }

    /// NET-12: `--dns` の判定表(none は loopback に限る。省略時は none 扱いにしない)。
    #[test]
    fn net12_dns_decision_table() {
        assert_eq!(code(&a(Some("none"), &[], &["192.0.2.1"])), INV);
        assert_eq!(code(&a(Some("none"), &[], &["127.0.0.1"])), WIRED);
        assert_eq!(code(&a(Some("none"), &[], &["::1"])), WIRED);
        assert_eq!(code(&a(Some("none"), &[], &["::ffff:127.0.0.1"])), INV);
        assert_eq!(code(&a(Some("host"), &[], &["192.0.2.1"])), WIRED);
        // 省略は none 扱い(D4)なので、非 loopback の `--dns` は create の時点で拒否する。
        assert_eq!(code(&a(None, &[], &["8.8.8.8"])), INV);
        assert_eq!(code(&a(None, &[], &["127.0.0.1"])), WIRED);
        assert_eq!(code(&a(Some("web"), &[], &["999.1.1.1"])), INV);
        assert_eq!(code(&a(None, &[], &["example.com"])), INV);
    }

    /// NET-12: `--add-host` は最初の `:` で分割する。
    #[test]
    fn net12_add_host_split() {
        assert_eq!(code(&a(None, &["name:::1"], &[])), WIRED);
        assert_eq!(code(&a(None, &["name::::1"], &[])), INV);
        assert_eq!(code(&a(None, &["web:999.1.1.1"], &[])), INV);
    }

    /// 固定文言は入力値を含まない。
    #[test]
    fn net12_messages_do_not_echo_input() {
        let e = validate_network_options(&a(None, &["evil host:1.2.3.4"], &[]), rootless)
            .expect_err("e");
        assert!(!e.message().contains("evil"), "{}", e.message());
        let e =
            validate_network_options(&a(Some("none"), &[], &["8.8.8.8"]), rootless).expect_err("e");
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

    /// NET-9(#3200・#3329): rootless でユーザー定義名と組の正しい `-p` は形式検証を通り、権限の解決は 1 回だけ呼ばれる。
    #[test]
    fn net9_publish_rootless_named_is_accepted_after_3329() {
        let (c, n) = run(
            &ap(Some("web"), &["8080:80", "127.0.0.1:8081:81/udp"]),
            rootless(),
        );
        assert_eq!((c, n), (WIRED, 1));
    }

    /// NET-9・D13(#3200): rootful の `-p` は `UNIMPLEMENTED`(専用の文言)。
    #[test]
    fn net9_publish_rootful_is_unimplemented() {
        let e = validate_network_options(&ap(Some("web"), &["8080:80"]), || {
            Ok(PublishPrivilege::Rootful)
        })
        .expect_err("rootful");
        assert_eq!(e.code(), ErrorCode::Unimplemented);
        assert_eq!(
            e.message(),
            "port publishing on rootful installations is not supported yet"
        );
        let e = validate_network_options(&ap(Some("web"), &["8080:80"]), || {
            Ok(PublishPrivilege::Unavailable)
        })
        .expect_err("unavailable");
        assert_eq!(e.code(), ErrorCode::Unimplemented);
    }

    /// NET-9(#3200): ユーザー定義名と組でない `-p` は、両モードで INVALID になり権限の解決も呼ばれない。
    #[test]
    fn net9_publish_without_user_defined_network_is_invalid() {
        for n in [None, Some("none"), Some("host"), Some("container:x")] {
            for p in [rootless(), Ok(PublishPrivilege::Rootful)] {
                assert_eq!(run(&ap(n, &["8080:80"]), p), (INV, 0), "{n:?}");
            }
        }
    }

    /// NET-9(#3200): 不正な指定は権限の解決より前に INVALID(IPv6・ポート 0・範囲・未知プロトコル・重複)。
    #[test]
    fn net9_publish_invalid_spec_before_privilege() {
        for bad in ["[::1]:80:80", "::1:80:80", "0:80", "1-2:80", "80:80/sctp"] {
            assert_eq!(
                run(&ap(Some("web"), &[bad]), rootless()),
                (INV, 0),
                "{bad:?}"
            );
        }
        assert_eq!(
            run(&ap(Some("web"), &["8080:80", "8080:81"]), rootless()),
            (INV, 0)
        );
    }

    /// NET-9・SUP-14(#3200): 権限モデルの解決の失敗はそのコードで伝わる。
    #[test]
    fn net9_publish_privilege_resolution_failure() {
        let r = Err(TraitError::new(ErrorCode::FailedPrecondition, "x"));
        assert_eq!(
            run(&ap(Some("web"), &["8080:80"]), r),
            (Some(ErrorCode::FailedPrecondition), 1)
        );
    }

    /// NET-6・NET-12(#1873・#3329): 結線の拒否の表。Linux は none / host と add-host / dns に加え、ユーザー定義名と `-p` も
    /// ここでは拒否しない(定義の照合と rootful の拒否は create_pasta の段)。`container:` は常に拒否。
    /// 非 Linux は network 系の指定すべてを固定文言で拒否する。
    #[test]
    fn net6_reject_unwired_network_table() {
        let r = |args: &CreateNetworkArgs, linux| {
            reject_unwired_network(args, linux).map_err(|e| (e.code(), e.message().to_owned()))
        };
        for linux in [true, false] {
            let (c, m) = r(&a(Some("container:x"), &[], &[]), linux).expect_err("container");
            assert_eq!(c, ErrorCode::Unimplemented);
            assert_eq!(m, NOT_WIRED_MESSAGE);
            assert_eq!(r(&a(None, &[], &[]), linux), Ok(()));
        }
        // ユーザー定義名と `-p` は Linux では通り、非 Linux では network 系の固定文言になる。
        assert_eq!(r(&a(Some("web"), &[], &[]), true), Ok(()));
        assert_eq!(r(&ap(Some("web"), &["8080:80"]), true), Ok(()));
        for args in [
            a(Some("web"), &[], &[]),
            ap(Some("web"), &["8080:80"]),
            a(Some("none"), &[], &[]),
            a(Some("host"), &["a:192.0.2.1"], &["192.0.2.53"]),
            a(None, &["a:192.0.2.1"], &[]),
        ] {
            assert_eq!(r(&args, true), Ok(()));
            let (c, m) = r(&args, false).expect_err("non-linux");
            assert_eq!(
                (c, m.as_str()),
                (ErrorCode::Unimplemented, PLATFORM_MESSAGE)
            );
        }
    }

    /// 通常の create(`-p` なし)では権限モデルを解決しない。
    #[test]
    fn net9_no_publish_never_resolves_privilege() {
        assert_eq!(run(&a(Some("web"), &[], &[]), rootless()), (WIRED, 0));
    }

    #[cfg(target_os = "linux")]
    fn tmp_root(tag: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!(
            "fc-cli-reqdef-{}-{tag}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        std::fs::create_dir(&p).expect("mkdir");
        std::fs::set_permissions(&p, std::os::unix::fs::PermissionsExt::from_mode(0o700))
            .expect("chmod");
        p
    }

    /// NET-6・CLI-1(#3329): 定義の照合の写像。無ければ `NOT_FOUND`、pasta 構成でなければ `FAILED_PRECONDITION`、
    /// 通れば `Ok`。文言は固定で入力値(ネットワーク名)を含まず、何も作らない。
    #[cfg(target_os = "linux")]
    #[test]
    fn net6_3329_require_named_definition_mapping() {
        use fandhe_container_net::netlink_route::IpPrefix;
        use fandhe_container_net::network_store::{NetworkDefinition, NetworkStore};
        let root = tmp_root("map");
        let name = NetworkName::new("secretname").expect("name");
        let e = require_named_definition_at(&root, &name, None).expect_err("missing");
        assert_eq!(
            (e.code(), e.message()),
            (ErrorCode::NotFound, "network not found")
        );
        assert!(!e.message().contains("secretname"));
        assert!(!root.join("@networks").exists());
        let store = NetworkStore::open(&root).expect("open");
        store
            .create(&NetworkDefinition::pasta("secretname").expect("def"))
            .expect("create");
        assert!(require_named_definition_at(&root, &name, None).is_ok());
        let sub = IpPrefix::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 89, 1, 0)),
            24,
        )
        .expect("prefix");
        store
            .create(&NetworkDefinition::bridge("br", sub).expect("def"))
            .expect("create");
        let e = require_named_definition_at(&root, &NetworkName::new("br").expect("n"), None)
            .expect_err("bridge");
        assert_eq!(
            (e.code(), e.message()),
            (
                ErrorCode::FailedPrecondition,
                "network is not a rootless network"
            )
        );
        store.remove(&name).expect("rm");
        let e = require_named_definition_at(&root, &name, None).expect_err("removed");
        assert_eq!(e.code(), ErrorCode::NotFound);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// REPAIR-4・NET-6・CLI-1(#3530): create 経路の定義照合(`run_create` が `CliNetRecorder` を渡す)が、
    /// 定義ストアの操作を `network.store.open` / `network.store.get` として記録する。名前は start の
    /// 再照合(supervisor の遅延ログ)と同じ固定文字列で、入力値(ネットワーク名)は含まない。
    #[cfg(target_os = "linux")]
    #[test]
    fn repair4_net6_3530_require_named_definition_records_store_ops() {
        use super::super::net_recorder::CliNetRecorder;
        use fandhe_container_core::observability::OpRecorder;
        use fandhe_container_net::network_store::{NetworkDefinition, NetworkStore};

        // 1 回の照合を新しい記録器で行い、(操作名, 成功数, 失敗数) と結果コードを返す。
        fn check(root: &Path, name: &str) -> (Vec<(String, u64, u64)>, Option<ErrorCode>) {
            let rec = Arc::new(OpRecorder::new());
            let r: Arc<dyn NetOpRecorder> = Arc::new(CliNetRecorder::new(Arc::clone(&rec)));
            let res =
                require_named_definition_at(root, &NetworkName::new(name).expect("n"), Some(r));
            let ops = rec
                .snapshot()
                .iter()
                .map(|s| (s.name().as_str().to_string(), s.success(), s.failure()))
                .collect();
            (ops, res.err().map(|e| e.code()))
        }
        let row = |n: &str, s: u64, f: u64| (n.to_string(), s, f);

        let root = tmp_root("rec");
        // @networks が無い: open_existing は Ok(None) で成功として記録される。get は呼ばれない。
        let (ops, code) = check(&root, "web");
        assert_eq!(ops, vec![row("network.store.open", 1, 0)]);
        assert_eq!(code, Some(ErrorCode::NotFound));
        assert!(!root.join("@networks").exists());

        let store = NetworkStore::open(&root).expect("open");
        // store はあるが名前が無い: get が失敗として記録される。
        let (ops, code) = check(&root, "web");
        assert_eq!(
            ops,
            vec![
                row("network.store.get", 0, 1),
                row("network.store.open", 1, 0)
            ]
        );
        assert_eq!(code, Some(ErrorCode::NotFound));

        store
            .create(&NetworkDefinition::pasta("web").expect("def"))
            .expect("create");
        let (ops, code) = check(&root, "web");
        assert_eq!(
            ops,
            vec![
                row("network.store.get", 1, 0),
                row("network.store.open", 1, 0)
            ]
        );
        assert_eq!(code, None);
        let _ = std::fs::remove_dir_all(&root);
    }
}
