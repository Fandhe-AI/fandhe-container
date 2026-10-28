//! pasta へ渡すポート公開指定の検証済みの型と、`-t` / `-u` / `-T` / `-U` の引数配列への変換
//! （TASK-147 追補・#1937・NET-9・NET-12・ERR-1・REPAIR-2・NET-6・SEC-4）。
//!
//! 呼び出し元は、CLI の `-p` の入口（`docs/design/rootless-network.md` 12.14 の cli 単位が [`PastaPortForward::parse`]
//! を呼ぶ）と、pasta を起動する単位（#1938。[`PastaPortForwards::pasta_args`] の戻りを argv の一部として連結する）。
//! シェルを介さず `OsString` の配列で返す。
//!
//! # 契約
//!
//! - 公開は IPv4 だけ。アドレスを省いたら `127.0.0.1`（loopback）に解決する。明示したアドレスは `0.0.0.0` を
//!   含めて受ける（bind できない `0.0.0.0/8` の残り・multicast・予約は拒否）。pasta の既定（アドレス省略で全アドレス、
//!   `auto` で自動公開）に落ちる値は型で作れない。
//! - ポート 0・範囲指定・IPv6・`%interface` は受けない。件数は `MAX_PORT_PUBLISHES` 以下。
//! - 出力は常に `-t <spec> ... -u <spec> ... -T none -U none`。公開が無いプロトコルは `none`。待ち受けアドレスごとに
//!   1 つの `-t <addr>/<host>:<ctr>[,...]` にまとめる（passt の `conf_ports` は SPEC を累積し、`/` の前のアドレスは
//!   その spec 全体にかかる。累積の実機確認は #1941）。
//! - rootful の DNAT 用 `PortPublish` は loopback と未指定を拒否する。pasta はホストの socket を
//!   bind するため loopback も `0.0.0.0` も成り立つので別の型にし、[`PortProtocol`] だけを共有する。
//! - エラーの message は固定の英文で、利用者の入力値を含めない（ERR-1）。

use std::ffi::OsString;
use std::net::Ipv4Addr;
use std::num::NonZeroU16;
use std::str::FromStr;

use crate::error::{NetError, NetErrorCode};
use crate::network::{MAX_PORT_PUBLISHES, PortProtocol};

/// 1 件の指定文字列の最大バイト長（FCOPT1 の `publish` レコードの上限と同じ。12.6）。
pub const MAX_PORT_FORWARD_SPEC_LEN: usize = 64;

/// アドレスを省いたときの待ち受けアドレス（loopback）。
pub const DEFAULT_LISTEN_ADDR: Ipv4Addr = Ipv4Addr::LOCALHOST;

fn invalid(msg: &'static str) -> NetError {
    NetError::new(NetErrorCode::InvalidArgument, msg)
}

/// bind できる待ち受けアドレスか。`0.0.0.0` と `127.0.0.0/8` を含む unicast を受ける。
fn is_bindable(addr: Ipv4Addr) -> bool {
    if addr == Ipv4Addr::UNSPECIFIED {
        return true;
    }
    let first = addr.octets()[0];
    first != 0 && first < 224
}

/// ポート公開 1 件（検証済み）。フィールドは非公開。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PastaPortForward {
    protocol: PortProtocol,
    listen_addr: Ipv4Addr,
    host_port: NonZeroU16,
    container_port: NonZeroU16,
}

impl PastaPortForward {
    /// 検証して作る。`listen_addr` が `None` なら `127.0.0.1`。ポート 0・bind できないアドレスは `InvalidArgument`。
    pub fn new(
        protocol: PortProtocol,
        listen_addr: Option<Ipv4Addr>,
        host_port: u16,
        container_port: u16,
    ) -> Result<Self, NetError> {
        let listen_addr = listen_addr.unwrap_or(DEFAULT_LISTEN_ADDR);
        if !is_bindable(listen_addr) {
            return Err(invalid("port forward listen address is not bindable"));
        }
        let host_port =
            NonZeroU16::new(host_port).ok_or_else(|| invalid("port must not be zero"))?;
        let container_port =
            NonZeroU16::new(container_port).ok_or_else(|| invalid("port must not be zero"))?;
        Ok(Self {
            protocol,
            listen_addr,
            host_port,
            container_port,
        })
    }

    /// `[<ipv4>:]<host>:<container>[/tcp|udp]` を解析する（12.6）。プロトコル省略は TCP。
    pub fn parse(spec: &str) -> Result<Self, NetError> {
        if spec.len() > MAX_PORT_FORWARD_SPEC_LEN {
            return Err(invalid("port forward spec is too long"));
        }
        if spec.is_empty() {
            return Err(invalid("port forward spec is empty"));
        }
        if !spec.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(invalid(
                "port forward spec contains a control character, whitespace or a non-ASCII character",
            ));
        }
        if spec.contains(['[', ']']) || spec.matches(':').count() >= 3 {
            return Err(invalid(
                "IPv6 addresses are not supported for port forwards",
            ));
        }
        if spec.contains('-') {
            return Err(invalid("port ranges are not supported for port forwards"));
        }
        let (body, protocol) = match spec.split_once('/') {
            None => (spec, PortProtocol::Tcp),
            Some((body, proto)) => {
                if proto.contains('/') {
                    return Err(invalid("invalid port forward spec format"));
                }
                let protocol = match proto {
                    "tcp" => PortProtocol::Tcp,
                    "udp" => PortProtocol::Udp,
                    _ => return Err(invalid("unsupported port forward protocol")),
                };
                (body, protocol)
            }
        };
        let parts: Vec<&str> = body.split(':').collect();
        let (addr, host, container) = match parts.as_slice() {
            [h, c] => (None, *h, *c),
            [a, h, c] => {
                let addr = Ipv4Addr::from_str(a)
                    .map_err(|_| invalid("invalid IPv4 address for port forward"))?;
                (Some(addr), *h, *c)
            }
            _ => return Err(invalid("invalid port forward spec format")),
        };
        Self::new(protocol, addr, parse_port(host)?, parse_port(container)?)
    }

    /// プロトコル。
    pub fn protocol(&self) -> PortProtocol {
        self.protocol
    }

    /// 待ち受けアドレス（省略時は `127.0.0.1` に解決済み）。
    pub fn listen_addr(&self) -> Ipv4Addr {
        self.listen_addr
    }

    /// ホスト側のポート。
    pub fn host_port(&self) -> u16 {
        self.host_port.get()
    }

    /// コンテナ側のポート。
    pub fn container_port(&self) -> u16 {
        self.container_port.get()
    }
}

/// ASCII 数字 1〜5 桁・先頭ゼロなし・1〜65535 のポートを数値にする。
fn parse_port(s: &str) -> Result<u16, NetError> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(invalid("invalid port forward spec format"));
    }
    if s.len() > 5 {
        return Err(invalid("port is out of range"));
    }
    if s.len() > 1 && s.starts_with('0') {
        return Err(invalid("port has a non-canonical form"));
    }
    let n: u32 = s.parse().map_err(|_| invalid("port is out of range"))?;
    if n == 0 {
        return Err(invalid("port must not be zero"));
    }
    u16::try_from(n).map_err(|_| invalid("port is out of range"))
}

/// ポート公開の集合（検証済み。入力順を保つ）。0 件でも [`Self::pasta_args`] は 4 方向を閉じる。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PastaPortForwards {
    forwards: Vec<PastaPortForward>,
}

impl PastaPortForwards {
    /// 0 件。
    pub fn new() -> Self {
        Self::default()
    }

    /// 件数上限と重複を検証して作る。上限は追加の前に検査する。
    pub fn try_from_forwards<I: IntoIterator<Item = PastaPortForward>>(
        items: I,
    ) -> Result<Self, NetError> {
        let iter = items.into_iter();
        let cap = iter.size_hint().0.min(MAX_PORT_PUBLISHES);
        let mut forwards: Vec<PastaPortForward> = Vec::with_capacity(cap);
        for f in iter {
            if forwards.len() >= MAX_PORT_PUBLISHES {
                return Err(invalid("too many port forwards"));
            }
            for e in &forwards {
                if e.protocol != f.protocol || e.host_port != f.host_port {
                    continue;
                }
                if e.listen_addr == f.listen_addr {
                    return Err(invalid("duplicate port forward"));
                }
                if e.listen_addr == Ipv4Addr::UNSPECIFIED || f.listen_addr == Ipv4Addr::UNSPECIFIED
                {
                    return Err(invalid("port forward overlaps a wildcard listener"));
                }
            }
            forwards.push(f);
        }
        Ok(Self { forwards })
    }

    /// 文字列の列を全件解析する（全件成功か全件失敗）。
    pub fn parse_all<'a, I: IntoIterator<Item = &'a str>>(specs: I) -> Result<Self, NetError> {
        let mut parsed = Vec::new();
        for s in specs {
            if parsed.len() >= MAX_PORT_PUBLISHES {
                return Err(invalid("too many port forwards"));
            }
            parsed.push(PastaPortForward::parse(s)?);
        }
        Self::try_from_forwards(parsed)
    }

    /// 件数。
    pub fn len(&self) -> usize {
        self.forwards.len()
    }

    /// 0 件か。
    pub fn is_empty(&self) -> bool {
        self.forwards.is_empty()
    }

    /// 入力順の反復。
    pub fn iter(&self) -> impl Iterator<Item = &PastaPortForward> {
        self.forwards.iter()
    }

    /// pasta の引数配列。`-t` 群、`-u` 群、`-T none -U none` の順。検証済みの値からだけ組むので失敗しない。
    pub fn pasta_args(&self) -> Vec<OsString> {
        let mut args = Vec::new();
        self.push_proto(&mut args, PortProtocol::Tcp, "-t");
        self.push_proto(&mut args, PortProtocol::Udp, "-u");
        for s in ["-T", "none", "-U", "none"] {
            args.push(OsString::from(s));
        }
        args
    }

    fn push_proto(&self, args: &mut Vec<OsString>, proto: PortProtocol, flag: &str) {
        let mut groups: Vec<(Ipv4Addr, Vec<&PastaPortForward>)> = Vec::new();
        for f in self.forwards.iter().filter(|f| f.protocol == proto) {
            match groups.iter_mut().find(|(a, _)| *a == f.listen_addr) {
                Some((_, v)) => v.push(f),
                None => groups.push((f.listen_addr, vec![f])),
            }
        }
        if groups.is_empty() {
            args.push(OsString::from(flag));
            args.push(OsString::from("none"));
            return;
        }
        for (addr, fs) in groups {
            let ports: Vec<String> = fs
                .iter()
                .map(|f| format!("{}:{}", f.host_port, f.container_port))
                .collect();
            args.push(OsString::from(flag));
            args.push(OsString::from(format!("{addr}/{}", ports.join(","))));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(f: &PastaPortForwards) -> Vec<String> {
        f.pasta_args()
            .into_iter()
            .map(|o| o.into_string().unwrap())
            .collect()
    }

    fn parsed(specs: &[&str]) -> Vec<String> {
        args(&PastaPortForwards::parse_all(specs.iter().copied()).unwrap())
    }

    fn err_msg(spec: &str) -> String {
        let e = PastaPortForward::parse(spec).unwrap_err();
        assert_eq!(e.code(), NetErrorCode::InvalidArgument);
        e.message().to_string()
    }

    #[test]
    fn net9_zero_forwards_close_all_four_directions() {
        assert_eq!(
            args(&PastaPortForwards::new()),
            ["-t", "none", "-u", "none", "-T", "none", "-U", "none"]
        );
    }

    #[test]
    fn net9_mixed_output_is_exact() {
        let got = parsed(&[
            "127.0.0.1:8080:80",
            "0.0.0.0:8443:443",
            "9000:9000",
            "5353:53/udp",
        ]);
        assert_eq!(
            got,
            [
                "-t",
                "127.0.0.1/8080:80,9000:9000",
                "-t",
                "0.0.0.0/8443:443",
                "-u",
                "127.0.0.1/5353:53",
                "-T",
                "none",
                "-U",
                "none"
            ]
        );
    }

    #[test]
    fn net9_udp_only_keeps_tcp_none() {
        assert_eq!(
            parsed(&["192.0.2.1:53:53/udp"]),
            [
                "-t",
                "none",
                "-u",
                "192.0.2.1/53:53",
                "-T",
                "none",
                "-U",
                "none"
            ]
        );
    }

    #[test]
    fn net9_omitted_address_resolves_to_loopback() {
        let f = PastaPortForward::parse("8080:80").unwrap();
        assert_eq!(f.listen_addr(), Ipv4Addr::LOCALHOST);
        assert_eq!(f.protocol(), PortProtocol::Tcp);
        assert_eq!((f.host_port(), f.container_port()), (8080, 80));
    }

    #[test]
    fn net9_listen_address_acceptance() {
        for ok in ["0.0.0.0:80:80", "192.0.2.1:80:80", "127.0.0.2:80:80"] {
            PastaPortForward::parse(ok).unwrap();
        }
        for bad in ["0.1.2.3:80:80", "224.0.0.1:80:80", "255.255.255.255:80:80"] {
            assert_eq!(err_msg(bad), "port forward listen address is not bindable");
        }
    }

    #[test]
    fn net9_port_validation_and_fixed_messages() {
        for ok in ["1:1", "65535:65535"] {
            PastaPortForward::parse(ok).unwrap();
        }
        assert_eq!(err_msg("0:80"), "port must not be zero");
        assert_eq!(err_msg("00:80"), "port has a non-canonical form");
        assert_eq!(err_msg("080:80"), "port has a non-canonical form");
        assert_eq!(err_msg("65536:80"), "port is out of range");
        assert_eq!(err_msg("99999999999:80"), "port is out of range");
        assert_eq!(err_msg("+80:80"), "invalid port forward spec format");
        assert_eq!(err_msg(":80"), "invalid port forward spec format");
        assert_eq!(err_msg("80"), "invalid port forward spec format");
        // ERR-1: 入力値を載せない
        assert!(!err_msg("99999:80").contains("99999"));
        assert!(!err_msg("0x7f.0.0.1:80:80").contains("0x7f"));
    }

    #[test]
    fn net9_rejects_ranges_ipv6_and_pasta_syntax() {
        assert_eq!(
            err_msg("8000-8001:80"),
            "port ranges are not supported for port forwards"
        );
        for v6 in ["[::1]:80:80", "::1:80:80"] {
            assert_eq!(
                err_msg(v6),
                "IPv6 addresses are not supported for port forwards"
            );
        }
        for bad in ["127.0.0.1%eth0:80:80", "~80:80", "80,81:80", "80:80,81"] {
            PastaPortForward::parse(bad).unwrap_err();
        }
    }

    #[test]
    fn net9_rejects_control_whitespace_nonascii_and_long() {
        for bad in ["80:80\0", "80 :80", "80:\t80", "80:80\n", "８０:80"] {
            assert_eq!(
                err_msg(bad),
                "port forward spec contains a control character, whitespace or a non-ASCII character"
            );
        }
        let long = format!("{}80:80", "1".repeat(60));
        assert_eq!(long.len(), 65);
        assert_eq!(err_msg(&long), "port forward spec is too long");
        assert_eq!(err_msg(""), "port forward spec is empty");
    }

    #[test]
    fn net9_rejects_address_notation_variants() {
        for bad in [
            "010.0.0.1:80:80",
            "0x7f.0.0.1:80:80",
            "127.1:80:80",
            "1.2.3.4.5:80:80",
        ] {
            PastaPortForward::parse(bad).unwrap_err();
        }
    }

    #[test]
    fn net9_protocol_suffix() {
        assert_eq!(
            PastaPortForward::parse("80:80/tcp").unwrap().protocol(),
            PortProtocol::Tcp
        );
        assert_eq!(
            PastaPortForward::parse("80:80/udp").unwrap().protocol(),
            PortProtocol::Udp
        );
        for bad in ["80:80/TCP", "80:80/sctp", "80:80/"] {
            assert_eq!(err_msg(bad), "unsupported port forward protocol");
        }
        assert_eq!(err_msg("80:80/a/b"), "invalid port forward spec format");
    }

    #[test]
    fn net9_new_rejects_zero_ports() {
        assert!(PastaPortForward::new(PortProtocol::Tcp, None, 0, 80).is_err());
        assert!(
            PastaPortForward::new(PortProtocol::Tcp, Some(Ipv4Addr::LOCALHOST), 80, 0).is_err()
        );
        assert!(PastaPortForward::new(PortProtocol::Tcp, None, 80, 80).is_ok());
    }

    #[test]
    fn net9_count_limit_checked_before_allocation() {
        let mk = |i: u16| PastaPortForward::new(PortProtocol::Tcp, None, 1000 + i, 80).unwrap();
        let ok = PastaPortForwards::try_from_forwards((0..64).map(mk)).unwrap();
        assert_eq!(ok.len(), 64);
        let pulled = std::cell::Cell::new(0usize);
        let it = (0..1000u16).map(|i| {
            pulled.set(pulled.get() + 1);
            mk(i)
        });
        let e = PastaPortForwards::try_from_forwards(it).unwrap_err();
        assert_eq!(e.code(), NetErrorCode::InvalidArgument);
        assert_eq!(e.message(), "too many port forwards");
        assert_eq!(pulled.get(), 65);
    }

    #[test]
    fn net9_duplicates_and_wildcard_overlap() {
        let e = PastaPortForwards::parse_all(["80:80", "127.0.0.1:80:81"]).unwrap_err();
        assert_eq!(e.message(), "duplicate port forward");
        let e = PastaPortForwards::parse_all(["0.0.0.0:80:80", "127.0.0.1:80:81"]).unwrap_err();
        assert_eq!(e.message(), "port forward overlaps a wildcard listener");
        // プロトコルが違えば同じポートでも受ける。コンテナ側の重複も受ける。
        PastaPortForwards::parse_all(["80:80", "80:80/udp", "81:80"]).unwrap();
    }

    /// 組み合わせ全体で `auto`・アドレスの無い spec が出ず、`none` と明示が並ばない（NET-9）。
    #[test]
    fn net9_exhaustive_combinations_never_open_implicitly() {
        let addrs = ["", "127.0.0.1:", "0.0.0.0:", "192.0.2.1:"];
        let protos = ["", "/udp"];
        let mut atoms = Vec::new();
        for p in protos {
            for ad in addrs {
                atoms.push((p, ad));
            }
        }
        let mut checked = 0;
        for n in 0..=3usize {
            for start in 0..atoms.len() {
                let list: Vec<String> = (0..n)
                    .map(|k| {
                        let (p, ad) = atoms[(start + k * 3) % atoms.len()];
                        format!("{ad}{}:{}{p}", 2000 + k, 80 + k)
                    })
                    .collect();
                let Ok(f) = PastaPortForwards::parse_all(list.iter().map(String::as_str)) else {
                    continue;
                };
                checked += 1;
                let v = args(&f);
                assert_eq!(&v[v.len() - 4..], ["-T", "none", "-U", "none"]);
                let body = &v[..v.len() - 4];
                assert_eq!(body.len() % 2, 0);
                for flag in ["-t", "-u"] {
                    let (mut none, mut explicit) = (0, 0);
                    for pair in body.chunks(2) {
                        assert!(pair[0] == "-t" || pair[0] == "-u");
                        if pair[0] != flag {
                            continue;
                        }
                        if pair[1] == "none" {
                            none += 1;
                        } else {
                            explicit += 1;
                            assert!(is_explicit_spec(&pair[1]), "bad spec {}", pair[1]);
                        }
                    }
                    assert!(none + explicit >= 1);
                    assert!(none == 0 || explicit == 0);
                }
                for s in &v {
                    assert!(s != "auto" && s != "all");
                    assert!(!s.contains(['\0', ' ', '%', '~']));
                }
            }
        }
        assert!(checked > 20);
    }

    /// `^<ipv4>/<d>:<d>(,<d>:<d>)*$` を手で照合する。
    fn is_explicit_spec(s: &str) -> bool {
        let Some((addr, ports)) = s.split_once('/') else {
            return false;
        };
        if Ipv4Addr::from_str(addr).is_err() {
            return false;
        }
        ports.split(',').all(|p| {
            let mut it = p.split(':');
            let (h, c, rest) = (it.next(), it.next(), it.next());
            rest.is_none()
                && [h, c].iter().all(|x| {
                    x.is_some_and(|x| !x.is_empty() && x.bytes().all(|b| b.is_ascii_digit()))
                })
        })
    }
}
