//! CRI `PodSandboxConfig.port_mappings` の検証と、公開指定（[`PodPortPublish`]）への変換（CRI-2・NET-3・NET-4。#2676）。
//!
//! 呼び出し元は 2 か所ある。`RuntimeService::run_pod_sandbox` は資源を作る前にここで検証し、公開する要素を
//! [`crate::adapter::PodNetworkRequest::port_publishes`] として `PodNetworkProvider` へ渡す。
//! `bundle::spec` は CreateContainer の最終の防壁として同じ判定を呼び、pod の netns が無い（公開できない）構成で
//! 公開指定があれば `UNIMPLEMENTED` にする。公開そのものは plugin-cri の `publish_port`（nft の DNAT）が行い、
//! cri は値の検証と型への変換だけを担う（壊れた値を下流へ流さない）。
//!
//! # 判定（値の不正を先に見て `INVALID_ARGUMENT`、次に未対応を `UNIMPLEMENTED`）
//! - `host_port == 0` は公開しない指定（kubelet は hostPort の無い containerPort も載せる）で、結果に含めない。
//! - `host_port > 0` は TCP / UDP と、明示した非 loopback の unicast IPv4 の `host_ip` だけ受ける。空・`0.0.0.0`
//!   （全アドレスへの公開。net が意図的に拒否する）・loopback・IPv6・SCTP は `UNIMPLEMENTED`（黙って別の値に
//!   置き換えない）。
//! - 契約 11 の判定キーは `(host_port, protocol)` のため、`host_ip` だけが違う同じ受け口も `UNIMPLEMENTED`。
//!
//! エラーメッセージは固定文言で、入力値を含めない（REPAIR-4）。

use std::net::{IpAddr, Ipv4Addr};
use std::num::NonZeroU16;

use fandhe_container_core::traits::Protocol;

use crate::error::CriError;
use crate::runtime::v1::PortMapping;

/// 1 pod で公開できる受け口の上限（net の `MAX_PORT_PUBLISHES` と同じ値）。
pub const MAX_PORT_PUBLISHES: usize = 64;

/// `host_ip` の文字列長の上限（IPv6 の最長表記より十分大きい。parse の前に検査する）。
const MAX_HOST_IP_BYTES: usize = 64;

/// 検証済みの公開指定 1 件。構築は [`parse_port_mappings`] だけで、壊れた値を作れない。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PodPortPublish {
    protocol: Protocol,
    host_ip: Ipv4Addr,
    host_port: NonZeroU16,
    container_port: NonZeroU16,
}

impl PodPortPublish {
    /// トランスポートプロトコル（TCP / UDP）。
    pub fn protocol(&self) -> Protocol {
        self.protocol
    }

    /// ホスト側で受ける IPv4 アドレス（明示した非 loopback の unicast）。
    pub fn host_ip(&self) -> Ipv4Addr {
        self.host_ip
    }

    /// ホスト側の公開ポート。
    pub fn host_port(&self) -> NonZeroU16 {
        self.host_port
    }

    /// コンテナ側の待受ポート。
    pub fn container_port(&self) -> NonZeroU16 {
        self.container_port
    }
}

/// 1 要素の判定結果。
enum Item {
    /// 公開しない（`host_port == 0`）。
    Skip,
    /// 公開する。
    Publish(PodPortPublish),
    /// 値は正しいが未対応。
    Unsupported,
}

fn invalid() -> CriError {
    CriError::invalid_argument("port_mappings is invalid")
}

fn unsupported() -> CriError {
    CriError::unimplemented("port_mappings is not supported")
}

fn parse_item(m: &PortMapping) -> Result<Item, CriError> {
    // protocol: TCP(0)・UDP(1)・SCTP(2)。
    let proto = match m.protocol {
        0 => Some(Protocol::Tcp),
        1 => Some(Protocol::Udp),
        2 => None,
        _ => return Err(invalid()),
    };
    let container_port = u16::try_from(m.container_port)
        .ok()
        .and_then(NonZeroU16::new)
        .ok_or_else(invalid)?;
    let host_port = u16::try_from(m.host_port).map_err(|_| invalid())?;
    if m.host_ip.len() > MAX_HOST_IP_BYTES {
        return Err(invalid());
    }
    let Some(host_port) = NonZeroU16::new(host_port) else {
        return Ok(Item::Skip);
    };
    let Some(protocol) = proto else {
        // SCTP の公開は net の nft ルールが対応しない。
        return Ok(Item::Unsupported);
    };
    if m.host_ip.is_empty() {
        return Ok(Item::Unsupported);
    }
    let ip: IpAddr = m.host_ip.parse().map_err(|_| invalid())?;
    let IpAddr::V4(host_ip) = ip else {
        return Ok(Item::Unsupported);
    };
    let o = host_ip.octets();
    if host_ip.is_unspecified() {
        return Ok(Item::Unsupported);
    }
    if host_ip.is_loopback() {
        return Ok(Item::Unsupported);
    }
    // 0.0.0.0 以外の 0/8・multicast・240/4（broadcast を含む）は host のアドレスになり得ない。
    if o[0] == 0 || host_ip.is_multicast() || o[0] >= 240 {
        return Err(invalid());
    }
    Ok(Item::Publish(PodPortPublish {
        protocol,
        host_ip,
        host_port,
        container_port,
    }))
}

/// `port_mappings` を検証し、公開する要素（`host_port > 0`）だけを返す。
///
/// 値の不正（`INVALID_ARGUMENT`）を先に見て、なければ未対応（`UNIMPLEMENTED`）を返す。公開する要素が
/// [`MAX_PORT_PUBLISHES`] を超えれば `INVALID_ARGUMENT`。
pub fn parse_port_mappings(mappings: &[PortMapping]) -> Result<Vec<PodPortPublish>, CriError> {
    let mut out: Vec<PodPortPublish> = Vec::new();
    let mut has_unsupported = false;
    for m in mappings {
        match parse_item(m)? {
            Item::Skip => {}
            Item::Unsupported => has_unsupported = true,
            Item::Publish(p) => {
                if out
                    .iter()
                    .any(|q| q.protocol == p.protocol && q.host_port == p.host_port)
                {
                    // 完全な重複は値の不正、host_ip だけの違いは契約 11 のキー上の未対応。
                    if out.contains(&p) {
                        return Err(invalid());
                    }
                    has_unsupported = true;
                } else {
                    // 確保前に上限を検証する（公開 API。呼び出し元の件数制限を前提にしない）。
                    if out.len() >= MAX_PORT_PUBLISHES {
                        return Err(invalid());
                    }
                    out.push(p);
                }
            }
        }
    }
    if has_unsupported {
        return Err(unsupported());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::CriErrorCode;

    fn m(protocol: i32, host_port: i32, container_port: i32, host_ip: &str) -> PortMapping {
        PortMapping {
            protocol,
            container_port,
            host_port,
            host_ip: host_ip.to_owned(),
        }
    }

    fn code(r: Result<Vec<PodPortPublish>, CriError>) -> CriErrorCode {
        r.expect_err("must be rejected").code()
    }

    /// CRI-2・NET-3: TCP / UDP の明示 IPv4 は具体値で変換し、`host_port == 0` は結果に含めない。
    #[test]
    fn cri2_accepts_explicit_ipv4_and_skips_zero_host_port() {
        let got = parse_port_mappings(&[
            m(0, 8080, 80, "192.0.2.10"),
            m(1, 5353, 53, "192.0.2.11"),
            m(0, 0, 9090, ""),
            m(2, 0, 7000, ""),
        ])
        .expect("accepted");
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].protocol(), Protocol::Tcp);
        assert_eq!(got[0].host_ip(), Ipv4Addr::new(192, 0, 2, 10));
        assert_eq!(got[0].host_port().get(), 8080);
        assert_eq!(got[0].container_port().get(), 80);
        assert_eq!(got[1].protocol(), Protocol::Udp);
        assert_eq!(got[1].host_port().get(), 5353);
        assert_eq!(got[1].container_port().get(), 53);
        assert!(parse_port_mappings(&[]).expect("empty").is_empty());
    }

    /// CRI-2: 未対応の指定は `UNIMPLEMENTED`。
    #[test]
    fn cri2_unsupported_is_unimplemented() {
        for bad in [
            m(2, 8080, 80, "192.0.2.10"),
            m(0, 8080, 80, ""),
            m(0, 8080, 80, "0.0.0.0"),
            m(0, 8080, 80, "127.0.0.1"),
            m(0, 8080, 80, "2001:db8::1"),
        ] {
            assert_eq!(
                code(parse_port_mappings(&[bad])),
                CriErrorCode::Unimplemented
            );
        }
        // host_ip だけが違う同じ (protocol, host_port) は契約 11 のキー上、未対応。
        assert_eq!(
            code(parse_port_mappings(&[
                m(0, 8080, 80, "192.0.2.10"),
                m(0, 8080, 81, "192.0.2.11"),
            ])),
            CriErrorCode::Unimplemented
        );
    }

    /// CRI-2: 値の不正は `INVALID_ARGUMENT`（未対応より先に見る）。
    #[test]
    fn cri2_invalid_values_are_invalid_argument() {
        let long = "1".repeat(65);
        for bad in [
            m(3, 8080, 80, "192.0.2.10"),
            m(-1, 8080, 80, "192.0.2.10"),
            m(0, 8080, 0, "192.0.2.10"),
            m(0, 8080, -1, "192.0.2.10"),
            m(0, 8080, 65536, "192.0.2.10"),
            m(0, -1, 80, "192.0.2.10"),
            m(0, 65536, 80, "192.0.2.10"),
            m(0, 8080, 80, "abc"),
            m(0, 8080, 80, "224.0.0.1"),
            m(0, 8080, 80, "255.255.255.255"),
            m(0, 8080, 80, &long),
        ] {
            assert_eq!(
                code(parse_port_mappings(&[bad])),
                CriErrorCode::InvalidArgument
            );
        }
        // 完全な重複。
        assert_eq!(
            code(parse_port_mappings(&[
                m(0, 8080, 80, "192.0.2.10"),
                m(0, 8080, 80, "192.0.2.10"),
            ])),
            CriErrorCode::InvalidArgument
        );
        // 値の不正は未対応より先に返る。
        assert_eq!(
            code(parse_port_mappings(&[
                m(2, 8080, 80, "192.0.2.10"),
                m(0, 8081, 0, "192.0.2.10"),
            ])),
            CriErrorCode::InvalidArgument
        );
    }

    /// CRI-2・NET-3: 公開する要素が 64 件を超えれば `INVALID_ARGUMENT`。64 件は受ける。
    #[test]
    fn cri2_publish_count_is_bounded() {
        let many = |n: i32| -> Vec<PortMapping> {
            (0..n).map(|i| m(0, 1000 + i, 80, "192.0.2.10")).collect()
        };
        assert_eq!(parse_port_mappings(&many(64)).expect("64").len(), 64);
        assert_eq!(
            code(parse_port_mappings(&many(65))),
            CriErrorCode::InvalidArgument
        );
    }

    /// CRI-2: 65 件目で打ち切る（大量の入力でも確保量・重複判定の走査が上限で止まる）。
    #[test]
    fn cri2_rejects_at_65th_before_scanning_the_rest() {
        let many: Vec<PortMapping> = (0..5000)
            .map(|i| m(0, 1000 + (i % 60000), 80, "192.0.2.10"))
            .collect();
        assert_eq!(
            code(parse_port_mappings(&many)),
            CriErrorCode::InvalidArgument
        );
    }

    /// REPAIR-4: エラーメッセージに入力値を含めない。
    #[test]
    fn cri2_error_messages_do_not_echo_input() {
        let e = parse_port_mappings(&[m(0, 8080, 80, "192.0.2.10x")]).expect_err("invalid");
        assert!(!e.message().contains("192.0.2"));
        let e = parse_port_mappings(&[m(0, 8080, 80, "127.0.0.1")]).expect_err("unsupported");
        assert!(!e.message().contains("127.0.0.1"));
    }
}
