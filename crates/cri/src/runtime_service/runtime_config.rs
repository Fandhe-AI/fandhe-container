//! `UpdateRuntimeConfig` の pod CIDR の検証と型（CRI-1・CRI-2・#2896）。
//!
//! kubelet がノードの pod CIDR（`node.Spec.PodCIDRs` を `,` で連結した文字列。デュアルスタックは 2 件）を
//! `RuntimeConfig.network_config.pod_cidr` で渡す。`CriRuntimeService::update_runtime_config` が本モジュールの
//! [`parse_pod_cidrs`] で外部入力として検証し、受け入れた値を [`PodCidrs`] として記録する。
//!
//! 未実装（REPAIR-3）: 記録した値を読む利用者はまだ無く、`PodNetworkProvider`・plugin-cri の
//! `PodSubnetPool` へは渡さない。結線は pod network の本番注入（`docs/design/cri-config-acceptance.md` の順 13）と
//! 一緒に後続で行う。cri は net crate に依存できない（CRI-7）ため、std の `IpAddr` だけで解釈する。

use std::net::IpAddr;
use std::str::FromStr;

use crate::error::CriError;

/// `pod_cidr` 全体の UTF-8 バイト長の上限（分割前に検査する。IPv4 CIDR 18 + IPv6 CIDR 43 + 区切りで足りる）。
pub const MAX_POD_CIDR_BYTES: usize = 128;

/// 受け入れる CIDR の件数の上限（kubelet のデュアルスタックは IPv4 と IPv6 の 2 件）。
pub const MAX_POD_CIDRS: usize = 2;

/// 検証済みの CIDR 1 件（アドレスとプレフィックス長。ホスト部のビットは正規化せずそのまま保つ）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PodCidr {
    addr: IpAddr,
    prefix_len: u8,
}

impl PodCidr {
    /// アドレス部。
    pub fn addr(&self) -> IpAddr {
        self.addr
    }

    /// プレフィックス長（IPv4 は 0〜32、IPv6 は 0〜128）。
    pub fn prefix_len(&self) -> u8 {
        self.prefix_len
    }
}

/// 検証済みの pod CIDR の組（1 件、または IPv4 と IPv6 の 2 件）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PodCidrs {
    cidrs: Vec<PodCidr>,
}

impl PodCidrs {
    /// 受け入れた CIDR（kubelet が渡した順）。
    pub fn as_slice(&self) -> &[PodCidr] {
        &self.cidrs
    }
}

fn invalid(message: &'static str) -> CriError {
    // 入力値は文言へ含めない（外部入力を反射しない）。
    CriError::invalid_argument(message)
}

fn parse_one(text: &str) -> Result<PodCidr, CriError> {
    let (addr_text, prefix_text) = text
        .split_once('/')
        .ok_or_else(|| invalid("pod_cidr is invalid"))?;
    let addr = IpAddr::from_str(addr_text).map_err(|_| invalid("pod_cidr is invalid"))?;
    let well_formed = !prefix_text.is_empty()
        && prefix_text.len() <= 3
        && prefix_text.bytes().all(|b| b.is_ascii_digit())
        && (prefix_text == "0" || !prefix_text.starts_with('0'));
    if !well_formed {
        return Err(invalid("pod_cidr is invalid"));
    }
    let prefix_len: u8 = prefix_text
        .parse()
        .map_err(|_| invalid("pod_cidr is invalid"))?;
    let max = if addr.is_ipv4() { 32 } else { 128 };
    if prefix_len > max {
        return Err(invalid("pod_cidr is invalid"));
    }
    Ok(PodCidr { addr, prefix_len })
}

/// `pod_cidr` を検証する。空は `Ok(None)`（何もしない）。
///
/// 規則: 長さ 128 バイト以下 → `,` で分割し各要素の前後の ASCII 空白を除去 → 1〜2 件（空要素は拒否）→
/// 各要素は `<IP>/<プレフィックス>`（先頭 0 の桁なし）→ 2 件なら IPv4 と IPv6 が 1 件ずつ。
pub fn parse_pod_cidrs(raw: &str) -> Result<Option<PodCidrs>, CriError> {
    if raw.is_empty() {
        return Ok(None);
    }
    if raw.len() > MAX_POD_CIDR_BYTES {
        return Err(invalid("pod_cidr is too long"));
    }
    let mut cidrs = Vec::new();
    for part in raw.split(',') {
        if cidrs.len() == MAX_POD_CIDRS {
            return Err(invalid("pod_cidr has too many entries"));
        }
        cidrs.push(parse_one(
            part.trim_matches(|c: char| c.is_ascii_whitespace()),
        )?);
    }
    if let [a, b] = cidrs.as_slice()
        && a.addr.is_ipv4() == b.addr.is_ipv4()
    {
        return Err(invalid("pod_cidr dual stack needs one IPv4 and one IPv6"));
    }
    Ok(Some(PodCidrs { cidrs }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::CriErrorCode;

    fn ok(s: &str) -> PodCidrs {
        parse_pod_cidrs(s).expect("valid").expect("some")
    }

    fn bad(s: &str) {
        let err = parse_pod_cidrs(s).expect_err(s);
        assert_eq!(err.code(), CriErrorCode::InvalidArgument, "{s}");
    }

    /// CRI-1: 空は何もしない。
    #[test]
    fn cri_1_empty_is_none() {
        assert_eq!(parse_pod_cidrs("").expect("ok"), None);
    }

    /// CRI-1: IPv4 単独・IPv6 単独・デュアルスタック・前後空白・ホスト部つきを受ける。
    #[test]
    fn cri_1_accepts_valid_forms() {
        let v4 = ok("10.244.0.0/24");
        assert_eq!(v4.as_slice().len(), 1);
        assert_eq!(
            v4.as_slice()[0].addr(),
            "10.244.0.0".parse::<IpAddr>().unwrap()
        );
        assert_eq!(v4.as_slice()[0].prefix_len(), 24);
        let dual = ok(" 10.244.0.0/24 , fd00:10:244::/64 ");
        assert_eq!(dual.as_slice().len(), 2);
        assert_eq!(dual.as_slice()[1].prefix_len(), 64);
        assert_eq!(
            ok("10.0.0.1/24").as_slice()[0].addr().to_string(),
            "10.0.0.1"
        );
        assert_eq!(ok("0.0.0.0/0").as_slice()[0].prefix_len(), 0);
        assert_eq!(ok("10.0.0.0/32").as_slice()[0].prefix_len(), 32);
        assert_eq!(ok("::/128").as_slice()[0].prefix_len(), 128);
    }

    /// CRI-1: 形式違反・境界超過は INVALID_ARGUMENT。
    #[test]
    fn cri_1_rejects_invalid_forms() {
        for s in [
            "10.0.0.0/33",
            "::/129",
            "10.0.0.0/024",
            "10.0.0.0/",
            "10.0.0.0",
            "/24",
            "fe80::1%eth0/64",
            "[::1]/128",
            "10.0.0.0/+8",
            "10.0.0.0/２４",
            "10.0.0.0/24,",
            ",10.0.0.0/24",
            "10.0.0.0/24,fd00::/64,fd01::/64",
            "10.0.0.0/24,10.1.0.0/24",
            "fd00::/64,fd01::/64",
            "10.0.0.0/24/8",
            "secret-like",
        ] {
            bad(s);
        }
    }

    /// CRI-1: 128 バイトは分割以降の検査へ進み、129 バイトは長さで拒否する。エラー文言に入力を含めない。
    #[test]
    fn cri_1_length_boundary_and_no_reflection() {
        let at = format!("{}/24", "1".repeat(MAX_POD_CIDR_BYTES - 3));
        assert_eq!(at.len(), MAX_POD_CIDR_BYTES);
        assert_eq!(
            parse_pod_cidrs(&at).unwrap_err().message(),
            "pod_cidr is invalid"
        );
        let over = format!("{}/24", "1".repeat(MAX_POD_CIDR_BYTES - 2));
        let err = parse_pod_cidrs(&over).unwrap_err();
        assert_eq!(err.message(), "pod_cidr is too long");
        let err = parse_pod_cidrs("secret-like-token").unwrap_err();
        assert!(!err.message().contains("secret"));
    }
}
