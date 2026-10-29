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
//!    `container:` 始まりは保留(`UNIMPLEMENTED`)。それ以外は `NetworkName::new` で検証し、妥当でも保留。
//! 2. `--add-host`: `parse_add_hosts` で全件検証(最初の `:` で分割。`name:::1` は (`name`, `::1`))。
//! 3. `--dns`: 全件を `parse_ip_addr` で検証。モードが `none` / `host` のときは続けて
//!    `ResolvConfPlan::for_mode` を呼び、none の非 loopback を拒否する。
//! 4. `-p` / `--publish`(#3200・NET-9・NET-3): net の `PastaPortForwards::parse_all` で全件を検証する
//!    (IPv6・範囲・ポート 0・重複・wildcard との重なりは `INVALID_ARGUMENT`)。ユーザー定義名の `--network` と組でなければ
//!    (指定なし・`none`・`host`・`container:`)モードによらず `INVALID_ARGUMENT`(rootless-network.md 12.15)。
//!    組であれば権限モデルを解決し、rootful は `UNIMPLEMENTED`(D13 の判断待ち)、解決の失敗は `FAILED_PRECONDITION`。
//!    解決は `-p` があるときだけ行い、通常の create に stat を増やさない。
//! 5. 上記をすべて通り、かつ 4 つのどれかが指定されていれば `UNIMPLEMENTED`(D3)。
//!
//! # pasta の段(#3199)
//!
//! `--network` がユーザー定義名のとき、手順 1〜3 の後・手順 4 の前に `create_pasta`(`--pasta-path` / `--pasta-path-search` の
//! 判定と作成時の検証。NET-9)が入る。pasta の不備(`FAILED_PRECONDITION`・`NOT_FOUND` 等)は `UNIMPLEMENTED` より前に返る。
//!
//! # 未実装の将来仕様(REPAIR-3)
//!
//! Linux の `none` / `host` / `--add-host` / `--dns` は #1873(PR #3322。文書 `FCOPT1` への記録と既定 `none` の導入。D4)で
//! 結線済み。残る未結線の指定(ユーザー定義名・`container:`・`-p`、非 Linux の network 系の指定すべて)は、検証を通っても
//! 受理して黙って捨てずに `UNIMPLEMENTED` で拒否する(`reject_unwired_network`)。`-p` は pasta の結線(#1940 で
//! supervisor 側は実装済み)があっても、CLI がユーザー定義名を解除するまで反映できないため同じく `UNIMPLEMENTED`。
//! ユーザー定義名の解除は rootless が #3329、rootful が D13、Linux 以外は MAC / WIN 系の結線の後続。
//! ユーザー定義名の存在確認と bridge 向け上流転送の制約(3 件以下・loopback / link-local の拒否・gateway との一致の拒否)は、
//! 定義ストア(D10・#3059 で実装済み)を使って #3329 の段で入れる(`network create` 側は #3066)。`--network` を省略しても #1871 では none 扱いにしない。
//!
//! エラーは固定の英語文言で、入力値を含めない。

use fandhe_container_core::traits::types::{ErrorCode, TraitError};
use fandhe_container_net::add_host_dns::resolv_conf::ResolvConfPlan;
use fandhe_container_net::add_host_dns::{parse_add_hosts, parse_ip_addr};
use fandhe_container_net::network_mode::{NetworkChoice, NetworkMode};
use fandhe_container_net::pasta::PastaPortForwards;

use fandhe_container_supervisor::container_options::network::net_error_to_trait;

use super::args::CreateNetworkArgs;

/// 結線されていない指定(ユーザー定義名・`container:`・`-p`)の固定拒否文言。
const NOT_WIRED_MESSAGE: &str = "user-defined networks, container: networks and port publishing are not wired to the launch path yet";
/// 非 Linux で network 系の指定を拒否する固定文言(MAC / WIN 系の結線の後続。D1)。
const PLATFORM_MESSAGE: &str = "network options are not supported on this platform yet";
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

/// 4 つのフラグの形式検証だけを行い、`--network` がユーザー定義名かを返す(`Unimplemented` にはしない)。
///
/// `run_create` が pasta の段(`create_pasta`。#3199)を `InvalidArgument` の後・`Unimplemented` の前に挟むために分けてある。
/// `resolve_privilege` は `-p` がユーザー定義名と組のときだけ呼ぶ(rootful 等の `Unimplemented` はここで返る)。
pub(super) fn check_network_options(
    args: &CreateNetworkArgs,
    resolve_privilege: impl FnOnce() -> Result<PublishPrivilege, TraitError>,
) -> Result<bool, TraitError> {
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
    Ok(matches!(choice, Some(NetworkChoice::Named(_))))
}

/// 起動経路に結線されていない指定を `Unimplemented` で拒否する(D3・#1873。形式の検証は済んでいる前提)。
///
/// Linux は `none` / `host` と `--add-host` / `--dns` を受ける(supervisor の start が反映する)。
/// ユーザー定義名・`container:`・`-p` は将来仕様で `UNIMPLEMENTED`(rootless の pasta は #3329〔supervisor 側の pasta は #1940 で実装済み〕・NET-9、
/// rootful は D13〔#3207・#3069・#3074〕、定義の存在確認は #3066)。非 Linux は network 系の指定すべてを拒否する
/// (MAC / WIN 系の結線の後続。`linux` は試験で差し替えるための引数)。
pub(super) fn reject_unwired_network(
    args: &CreateNetworkArgs,
    linux: bool,
) -> Result<(), TraitError> {
    let unwired = !args.publish.is_empty()
        || args
            .network
            .as_deref()
            .map(NetworkChoice::parse)
            .and_then(Result::ok)
            .is_some_and(|c| matches!(c, NetworkChoice::Named(_) | NetworkChoice::ContainerRef));
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
        assert_eq!(code(&a(Some("web"), &[], &[])), UNI);
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

    /// NET-9(#3200): rootless でユーザー定義名と組の正しい `-p` は、結線まで `UNIMPLEMENTED`(受理して捨てない)。
    #[test]
    fn net9_publish_rootless_named_is_unimplemented_until_1873() {
        let (c, n) = run(
            &ap(Some("web"), &["8080:80", "127.0.0.1:8081:81/udp"]),
            rootless(),
        );
        assert_eq!((c, n), (UNI, 1));
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

    /// NET-6・NET-12(#1873): 結線の拒否の表。Linux は none / host と add-host / dns を受け、
    /// ユーザー定義名・`container:`・`-p` は常に拒否。非 Linux は network 系の指定すべてを固定文言で拒否する。
    #[test]
    fn net6_reject_unwired_network_table() {
        let r = |args: &CreateNetworkArgs, linux| {
            reject_unwired_network(args, linux).map_err(|e| (e.code(), e.message().to_owned()))
        };
        for linux in [true, false] {
            for n in ["web", "container:x"] {
                let (c, m) = r(&a(Some(n), &[], &[]), linux).expect_err(n);
                assert_eq!(c, ErrorCode::Unimplemented);
                assert_eq!(m, NOT_WIRED_MESSAGE);
            }
            let (c, m) = r(&ap(Some("web"), &["8080:80"]), linux).expect_err("publish");
            assert_eq!(
                (c, m.as_str()),
                (ErrorCode::Unimplemented, NOT_WIRED_MESSAGE)
            );
            assert_eq!(r(&a(None, &[], &[]), linux), Ok(()));
        }
        for args in [
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
        assert_eq!(run(&a(Some("web"), &[], &[]), rootless()), (UNI, 0));
    }
}
