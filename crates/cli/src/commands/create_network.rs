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
//! 予約名(`bridge`・`default`)だけは net に規則が無いため CLI 側に置く(D1)。
//!
//! # 判定順(`INVALID_ARGUMENT` が `UNIMPLEMENTED` に優先する)
//!
//! 1. `--network`: `none` / `host` はモード確定。`bridge` / `default` は `INVALID_ARGUMENT`。
//!    `container:` 始まりは保留(`UNIMPLEMENTED`)。それ以外は `NetworkName::new` で検証し、妥当でも保留。
//! 2. `--add-host`: `parse_add_hosts` で全件検証(最初の `:` で分割。`name:::1` は (`name`, `::1`))。
//! 3. `--dns`: 全件を `parse_ip_addr` で検証。モードが `none` / `host` のときは続けて
//!    `ResolvConfPlan::for_mode` を呼び、none の非 loopback を拒否する。
//! 4. 上記をすべて通り、かつ 3 つのどれかが指定されていれば `UNIMPLEMENTED`(D3)。
//!
//! # pasta の段(#3199)
//!
//! `--network` がユーザー定義名のとき、手順 1〜3 の後・手順 4 の前に `create_pasta`(`--pasta-path` / `--pasta-path-search` の
//! 判定と作成時の検証。NET-9)が入る。pasta の不備(`FAILED_PRECONDITION`・`NOT_FOUND` 等)は `UNIMPLEMENTED` より前に返る。
//!
//! # 未実装の将来仕様(REPAIR-3)
//!
//! 検証を通っても起動経路へ結線されていないため、受理して黙って捨てずに `UNIMPLEMENTED` で拒否する。
//! Linux での解除は #1873(文書 `FCOPT1` への記録と既定 `none` の導入。D4)、Linux 以外は MAC / WIN 系の結線の後続。
//! ユーザー定義名の存在確認と bridge 向け上流転送の制約(3 件以下・loopback / link-local の拒否・gateway との一致の拒否)は、
//! 定義ストア(D10・#3059)が要るため #3059・#3066・#1873 の段で入れる。`--network` を省略しても #1871 では none 扱いにしない。
//!
//! エラーは固定の英語文言で、入力値を含めない。

use fandhe_container_core::traits::types::{ErrorCode, TraitError};
use fandhe_container_net::add_host_dns::resolv_conf::ResolvConfPlan;
use fandhe_container_net::add_host_dns::{parse_add_hosts, parse_ip_addr};
use fandhe_container_net::error::{NetError, NetErrorCode};
use fandhe_container_net::network::NetworkName;
use fandhe_container_net::network_mode::NetworkMode;

use super::args::CreateNetworkArgs;

/// 結線されるまでの固定拒否文言。
const NOT_WIRED_MESSAGE: &str =
    "network options (--network, --add-host, --dns) are not wired to the launch path yet";
/// 予約名の固定拒否文言。
const RESERVED_NAME_MESSAGE: &str = "reserved network name";

/// `--network` の判定結果(内部用)。
enum Choice {
    None,
    Host,
    /// ユーザー定義名(検証済み)。
    Named,
    /// `container:` 始まり(保留)。
    Container,
}

/// 予約名か(`network create` が後で再利用できるよう独立させる。D1・#3066)。
pub(super) fn is_reserved_network_name(name: &str) -> bool {
    matches!(name, "bridge" | "default")
}

/// net の固定メッセージを保ったまま `TraitError` へ写す(`NetErrorCode` は `#[non_exhaustive]`)。
fn net_error_to_trait(e: &NetError) -> TraitError {
    let code = match e.code() {
        NetErrorCode::InvalidArgument => ErrorCode::InvalidArgument,
        NetErrorCode::Unimplemented => ErrorCode::Unimplemented,
        NetErrorCode::ResourceExhausted => ErrorCode::ResourceExhausted,
        _ => ErrorCode::Internal,
    };
    TraitError::new(code, e.message())
}

fn choose(network: &str) -> Result<Choice, TraitError> {
    match network {
        "none" => Ok(Choice::None),
        "host" => Ok(Choice::Host),
        n if is_reserved_network_name(n) => Err(TraitError::new(
            ErrorCode::InvalidArgument,
            RESERVED_NAME_MESSAGE,
        )),
        n if n.starts_with("container:") => Ok(Choice::Container),
        n => NetworkName::new(n)
            .map(|_| Choice::Named)
            .map_err(|e| net_error_to_trait(&e)),
    }
}

/// 3 つのフラグを作成前に検証する。指定が無ければ `Ok(())`、不正は `InvalidArgument`、
/// 正しくても指定があれば `Unimplemented`(D3)。
#[cfg(test)]
pub(super) fn validate_network_options(args: &CreateNetworkArgs) -> Result<(), TraitError> {
    check_network_options(args)?;
    reject_not_wired(args)
}

/// 3 つのフラグの形式検証だけを行い、`--network` がユーザー定義名かを返す(`Unimplemented` にはしない)。
///
/// `run_create` が pasta の段(`create_pasta`。#3199)を `InvalidArgument` の後・`Unimplemented` の前に挟むために分けてある。
pub(super) fn check_network_options(args: &CreateNetworkArgs) -> Result<bool, TraitError> {
    let choice = args.network.as_deref().map(choose).transpose()?;
    if !args.add_hosts.is_empty() {
        parse_add_hosts(args.add_hosts.iter().map(String::as_str))
            .map_err(|e| net_error_to_trait(&e))?;
    }
    for d in &args.dns {
        parse_ip_addr(d).map_err(|e| net_error_to_trait(&e))?;
    }
    let mode = match choice {
        Some(Choice::None) => Some(NetworkMode::None),
        Some(Choice::Host) => Some(NetworkMode::Host),
        // 名前つき・container: は for_mode(Bridge は UNIMPLEMENTED を返して検出を隠す)を通さない。
        Some(Choice::Named | Choice::Container) | None => None,
    };
    if let Some(mode) = mode {
        let dns: Vec<&str> = args.dns.iter().map(String::as_str).collect();
        ResolvConfPlan::for_mode(mode, &dns).map_err(|e| net_error_to_trait(&e))?;
    }
    Ok(matches!(choice, Some(Choice::Named)))
}

/// 検証を通った指定があれば `Unimplemented`(D3。起動経路への結線は #1873)。
pub(super) fn reject_not_wired(args: &CreateNetworkArgs) -> Result<(), TraitError> {
    if args.network.is_some() || !args.add_hosts.is_empty() || !args.dns.is_empty() {
        return Err(TraitError::new(ErrorCode::Unimplemented, NOT_WIRED_MESSAGE));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a(network: Option<&str>, hosts: &[&str], dns: &[&str]) -> CreateNetworkArgs {
        CreateNetworkArgs {
            network: network.map(str::to_owned),
            add_hosts: hosts.iter().map(|s| (*s).to_owned()).collect(),
            dns: dns.iter().map(|s| (*s).to_owned()).collect(),
        }
    }

    fn code(args: &CreateNetworkArgs) -> Option<ErrorCode> {
        validate_network_options(args).err().map(|e| e.code())
    }

    const INV: Option<ErrorCode> = Some(ErrorCode::InvalidArgument);
    const UNI: Option<ErrorCode> = Some(ErrorCode::Unimplemented);

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
        assert_eq!(code(&a(Some("none"), &[], &[])), UNI);
        assert_eq!(code(&a(Some("host"), &[], &[])), UNI);
        assert_eq!(code(&a(Some("web"), &[], &[])), UNI);
    }

    /// NET-12: `--dns` の判定表(none は loopback に限る。省略時は none 扱いにしない)。
    #[test]
    fn net12_dns_decision_table() {
        assert_eq!(code(&a(Some("none"), &[], &["192.0.2.1"])), INV);
        assert_eq!(code(&a(Some("none"), &[], &["127.0.0.1"])), UNI);
        assert_eq!(code(&a(Some("none"), &[], &["::1"])), UNI);
        assert_eq!(code(&a(Some("none"), &[], &["::ffff:127.0.0.1"])), INV);
        assert_eq!(code(&a(Some("host"), &[], &["192.0.2.1"])), UNI);
        assert_eq!(code(&a(None, &[], &["8.8.8.8"])), UNI);
        assert_eq!(code(&a(Some("web"), &[], &["999.1.1.1"])), INV);
        assert_eq!(code(&a(None, &[], &["example.com"])), INV);
    }

    /// NET-12: `--add-host` は最初の `:` で分割する。
    #[test]
    fn net12_add_host_split() {
        assert_eq!(code(&a(None, &["name:::1"], &[])), UNI);
        assert_eq!(code(&a(None, &["name::::1"], &[])), INV);
        assert_eq!(code(&a(None, &["web:999.1.1.1"], &[])), INV);
    }

    /// 固定文言は入力値を含まない。
    #[test]
    fn net12_messages_do_not_echo_input() {
        let e = validate_network_options(&a(None, &["evil host:1.2.3.4"], &[])).expect_err("e");
        assert!(!e.message().contains("evil"), "{}", e.message());
        let e = validate_network_options(&a(Some("none"), &[], &["8.8.8.8"])).expect_err("e");
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
}
