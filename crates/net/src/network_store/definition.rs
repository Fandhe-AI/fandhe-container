//! ネットワーク定義の符号化（FCNET1）と、予約名・上限の定数（NET-6・CORE-1・REPAIR-2・REPAIR-5・#3059）。
//!
//! 役割: `network_store` が `<state_root>/@networks/<name>/definition` に置く 1 レコードの形式を、
//! 「壊れた値を表現できない」型（[`NetworkDefinition`]）と正準形だけを受ける復号で固定する。
//! OS 非依存で、ファイルには触れない（置き場の検査とロックは親モジュール側）。
//! 呼び出し元の想定: CLI の `network create/rm/ls`（#3066）、supervisor、`NetworkPlugin` の実装、
//! start 時の再照合（#1873）。いずれも [`NetworkDefinition::pasta`] / [`NetworkDefinition::bridge`] か
//! [`NetworkDefinition::decode`] を通る（関門は 1 つ）。
//!
//! # 形式（FCNET1）
//! ```text
//! FCNET1\n
//! name <len>\n<len バイト>\n
//! mode <len>\n<pasta|bridge>\n
//! subnet <len>\n<a.b.c.d/nn>\n      (mode が bridge のときだけ。pasta では禁止)
//! ```
//! 並びは固定で、正準形だけを受ける（重複・未知の kind・順序違い・欠落・末尾のごみは `DataLoss`）。
//! `len` は 10 進で先頭の 0 と `+` を拒否し、最大 4 桁。文書全体は [`DEFINITION_MAX_BYTES`] 以下で、
//! 解析の前にサイズで拒否する（無制限確保の防止）。
//!
//! 未実装（REPAIR-3）: subnet の pool（`10.89.0.0/16` の /24）からの予約は D13 の判断待ち（#3057）。
//! ここでは任意の IPv4 ネットワークアドレスを受けるだけで、pool への所属は検査しない。

use std::net::{IpAddr, Ipv4Addr};

use crate::error::{NetError, NetErrorCode};
use crate::netlink_route::IpPrefix;
use crate::network::NetworkName;

/// 定義文書 1 件の最大バイト数（NET-6。D10）。超過は解析の前に `DataLoss`。
pub const DEFINITION_MAX_BYTES: usize = 4096;

/// ストアに置ける定義の最大数（D10。D13 の pool と一致）。
pub const MAX_NETWORKS: usize = 256;

/// 予約名（Docker 互換の組み込みネットワーク名。ユーザー定義には使えない）。
pub const RESERVED_NETWORK_NAMES: [&str; 4] = ["none", "host", "bridge", "default"];

const MAGIC: &str = "FCNET1\n";

/// 予約名か。
pub fn is_reserved_network_name(name: &str) -> bool {
    RESERVED_NETWORK_NAMES.contains(&name)
}

/// ネットワークのインストール方式。`network_mode::NetworkMode`（コンテナ側の選択）とは別物。
///
/// `Pasta` は rootless のインストール、`Bridge` は rootful のインストール。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InstallMode {
    /// rootless（pasta）。subnet を持たない。
    Pasta,
    /// rootful（bridge）。IPv4 のネットワークアドレスの subnet を持つ。
    Bridge {
        /// bridge の subnet（IPv4・ホスト部 0・prefix 1〜30）。
        subnet: IpPrefix,
    },
}

/// 検証済みのネットワーク定義。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkDefinition {
    name: NetworkName,
    install: InstallMode,
}

fn err(code: NetErrorCode, msg: &'static str) -> NetError {
    NetError::new(code, msg)
}

fn check_name(name: &str) -> Result<NetworkName, NetError> {
    let n = NetworkName::new(name)?;
    if is_reserved_network_name(name) {
        return Err(err(
            NetErrorCode::InvalidArgument,
            "network name is reserved",
        ));
    }
    Ok(n)
}

fn check_subnet(subnet: &IpPrefix) -> Result<(), NetError> {
    if !subnet.addr().is_ipv4() {
        return Err(err(
            NetErrorCode::InvalidArgument,
            "subnet must be an IPv4 prefix",
        ));
    }
    if !(1..=30).contains(&subnet.prefix_len()) {
        return Err(err(
            NetErrorCode::InvalidArgument,
            "subnet prefix length must be 1 to 30",
        ));
    }
    if !subnet.is_network() {
        return Err(err(
            NetErrorCode::InvalidArgument,
            "subnet host bits must be zero",
        ));
    }
    Ok(())
}

impl NetworkDefinition {
    /// rootless（pasta）の定義。名前の検証違反・予約名は `InvalidArgument`。
    pub fn pasta(name: &str) -> Result<Self, NetError> {
        Ok(Self {
            name: check_name(name)?,
            install: InstallMode::Pasta,
        })
    }

    /// rootful（bridge）の定義。subnet は IPv4 のネットワークアドレスで prefix 1〜30。
    pub fn bridge(name: &str, subnet: IpPrefix) -> Result<Self, NetError> {
        let name = check_name(name)?;
        check_subnet(&subnet)?;
        Ok(Self {
            name,
            install: InstallMode::Bridge { subnet },
        })
    }

    /// ネットワーク名。
    pub fn name(&self) -> &NetworkName {
        &self.name
    }

    /// インストール方式。
    pub fn install(&self) -> &InstallMode {
        &self.install
    }

    /// 正準形の FCNET1 へ符号化する。
    pub fn encode(&self) -> Vec<u8> {
        let mut out = String::from(MAGIC);
        push_field(&mut out, "name", self.name.as_str());
        match &self.install {
            InstallMode::Pasta => push_field(&mut out, "mode", "pasta"),
            InstallMode::Bridge { subnet } => {
                push_field(&mut out, "mode", "bridge");
                push_field(
                    &mut out,
                    "subnet",
                    &format!("{}/{}", subnet.addr(), subnet.prefix_len()),
                );
            }
        }
        out.into_bytes()
    }

    /// FCNET1 を復号する。外部入力（ディスク上の文書）なので、違反はすべて `DataLoss`。
    pub fn decode(bytes: &[u8]) -> Result<Self, NetError> {
        let bad = |msg: &'static str| err(NetErrorCode::DataLoss, msg);
        if bytes.len() > DEFINITION_MAX_BYTES {
            return Err(bad("network definition exceeds the size limit"));
        }
        let text =
            std::str::from_utf8(bytes).map_err(|_| bad("network definition is not UTF-8"))?;
        let mut rest = text
            .strip_prefix(MAGIC)
            .ok_or_else(|| bad("network definition magic mismatch"))?;
        let name = take_field(&mut rest, "name")?;
        let mode = take_field(&mut rest, "mode")?;
        let def = match mode {
            "pasta" => Self::pasta(name),
            "bridge" => {
                let subnet = take_field(&mut rest, "subnet")?;
                let prefix = parse_subnet(subnet)?;
                Self::bridge(name, prefix)
            }
            _ => return Err(bad("network definition mode is unknown")),
        }
        .map_err(|_| bad("network definition holds an invalid value"))?;
        if !rest.is_empty() {
            return Err(bad("network definition has trailing data"));
        }
        Ok(def)
    }
}

fn push_field(out: &mut String, kind: &str, value: &str) {
    out.push_str(kind);
    out.push(' ');
    out.push_str(&value.len().to_string());
    out.push('\n');
    out.push_str(value);
    out.push('\n');
}

/// `kind <len>\n<値>\n` を 1 つ読み、値を返して `rest` を進める。
fn take_field<'a>(rest: &mut &'a str, kind: &str) -> Result<&'a str, NetError> {
    let bad = |msg: &'static str| err(NetErrorCode::DataLoss, msg);
    let after_kind = rest
        .strip_prefix(kind)
        .and_then(|r| r.strip_prefix(' '))
        .ok_or_else(|| bad("network definition field is missing or out of order"))?;
    let (len_str, body) = after_kind
        .split_once('\n')
        .ok_or_else(|| bad("network definition length line is unterminated"))?;
    let canonical = !len_str.is_empty()
        && len_str.len() <= 4
        && len_str.bytes().all(|b| b.is_ascii_digit())
        && (len_str == "0" || !len_str.starts_with('0'));
    if !canonical {
        return Err(bad("network definition length is not canonical"));
    }
    let len: usize = len_str
        .parse()
        .map_err(|_| bad("network definition length is not canonical"))?;
    let value = body
        .get(..len)
        .ok_or_else(|| bad("network definition length exceeds the remaining data"))?;
    let after_value = body
        .get(len..)
        .and_then(|r| r.strip_prefix('\n'))
        .ok_or_else(|| bad("network definition value is not newline terminated"))?;
    *rest = after_value;
    Ok(value)
}

fn parse_subnet(s: &str) -> Result<IpPrefix, NetError> {
    let bad = || {
        err(
            NetErrorCode::DataLoss,
            "network definition subnet is malformed",
        )
    };
    let (addr, len) = s.split_once('/').ok_or_else(bad)?;
    let addr: Ipv4Addr = addr.parse().map_err(|_| bad())?;
    if len.is_empty() || len.len() > 2 || !len.bytes().all(|b| b.is_ascii_digit()) {
        return Err(bad());
    }
    let len: u8 = len.parse().map_err(|_| bad())?;
    let prefix = IpPrefix::new(IpAddr::V4(addr), len).map_err(|_| bad())?;
    // 正準形（再符号化と一致すること）だけを受ける。
    if format!("{}/{}", prefix.addr(), prefix.prefix_len()) != s {
        return Err(bad());
    }
    Ok(prefix)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sn(a: [u8; 4], len: u8) -> IpPrefix {
        IpPrefix::new(IpAddr::V4(Ipv4Addr::from(a)), len).unwrap()
    }

    fn code<T: std::fmt::Debug>(r: Result<T, NetError>) -> NetErrorCode {
        r.unwrap_err().code()
    }

    #[test]
    fn net6_3059_constants() {
        assert_eq!(DEFINITION_MAX_BYTES, 4096);
        assert_eq!(MAX_NETWORKS, 256);
        assert_eq!(
            RESERVED_NETWORK_NAMES,
            ["none", "host", "bridge", "default"]
        );
    }

    #[test]
    fn net6_3059_encode_exact_bytes() {
        let p = NetworkDefinition::pasta("web").unwrap();
        assert_eq!(p.encode(), b"FCNET1\nname 3\nweb\nmode 5\npasta\n");
        let b = NetworkDefinition::bridge("web", sn([10, 89, 0, 0], 24)).unwrap();
        assert_eq!(
            b.encode(),
            b"FCNET1\nname 3\nweb\nmode 6\nbridge\nsubnet 12\n10.89.0.0/24\n".to_vec()
        );
    }

    #[test]
    fn net6_3059_roundtrip() {
        for d in [
            NetworkDefinition::pasta("a-b_c.d").unwrap(),
            NetworkDefinition::bridge("x", sn([192, 168, 4, 0], 30)).unwrap(),
        ] {
            assert_eq!(NetworkDefinition::decode(&d.encode()).unwrap(), d);
        }
    }

    #[test]
    fn net6_3059_decode_rejects_malformed() {
        let cases: &[&[u8]] = &[
            b"FCNET2\nname 3\nweb\nmode 5\npasta\n",
            b"FCNET1\nnome 3\nweb\nmode 5\npasta\n",
            b"FCNET1\nmode 5\npasta\nname 3\nweb\n",
            b"FCNET1\nname 3\nweb\n",
            b"FCNET1\nname 3\nweb\nmode 5\npasta\nname 3\nweb\n",
            b"FCNET1\nname 3\nweb\nmode 5\npasta\nsubnet 12\n10.89.0.0/24\n",
            b"FCNET1\nname 3\nweb\nmode 6\nbridge\n",
            b"FCNET1\nname 03\nweb\nmode 5\npasta\n",
            b"FCNET1\nname +3\nweb\nmode 5\npasta\n",
            b"FCNET1\nname 00003\nweb\nmode 5\npasta\n",
            b"FCNET1\nname 9\nweb\nmode 5\npasta\n",
            b"FCNET1\nname 3\nweb\nmode 5\npasta",
            b"FCNET1\nname 3\nweb\nmode 5\npasta\nx",
            b"FCNET1\nname 3\nw\xff\xfe\nmode 5\npasta\n",
            b"FCNET1\nname 4\nnone\nmode 5\npasta\n",
            b"FCNET1\nname 3\nweb\nmode 4\nhost\n",
            b"FCNET1\nname 3\nweb\nmode 6\nbridge\nsubnet 12\n10.89.0.1/24\n",
            b"FCNET1\nname 3\nweb\nmode 6\nbridge\nsubnet 10\n10.89.0.0/0\n",
            b"FCNET1\nname 3\nweb\nmode 6\nbridge\nsubnet 4\n::/8\n",
            b"FCNET1\nname 3\nweb\nmode 6\nbridge\nsubnet 12\n10.89.0.0/31\n",
            b"FCNET1\nname 3\nweb\nmode 6\nbridge\nsubnet 12\n10.89.0.0/024\n",
        ];
        for c in cases {
            assert_eq!(
                code(NetworkDefinition::decode(c)),
                NetErrorCode::DataLoss,
                "{:?}",
                String::from_utf8_lossy(c)
            );
        }
        let big = vec![b'a'; DEFINITION_MAX_BYTES + 1];
        assert_eq!(
            code(NetworkDefinition::decode(&big)),
            NetErrorCode::DataLoss
        );
    }

    #[test]
    fn net6_3059_constructors_reject() {
        for n in RESERVED_NETWORK_NAMES {
            assert_eq!(
                code(NetworkDefinition::pasta(n)),
                NetErrorCode::InvalidArgument
            );
        }
        for n in ["", "@x", "../x"] {
            assert_eq!(
                code(NetworkDefinition::pasta(n)),
                NetErrorCode::InvalidArgument
            );
        }
        for s in [
            sn([10, 89, 0, 1], 24),
            sn([10, 89, 0, 0], 0),
            sn([10, 89, 0, 0], 31),
            sn([10, 89, 0, 0], 32),
            IpPrefix::new("fd00::".parse().unwrap(), 64).unwrap(),
        ] {
            assert_eq!(
                code(NetworkDefinition::bridge("web", s)),
                NetErrorCode::InvalidArgument
            );
        }
        assert!(is_reserved_network_name("bridge"));
        assert!(!is_reserved_network_name("web"));
    }
}
