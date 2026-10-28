//! 作成済みネットワークの記録 `realized`（FCREA1）と操作中の意図記録 `realized.intent`（FCRIN1）（NET-1・NET-6・REPAIR-2・#3067）。
//!
//! 役割: `network::create_network` が返す `CreatedNetwork`（bridge・ifindex・所有トークン・nft テーブル・gateway）を
//! プロセスをまたいで引き継ぐための記録。`<name>/realized` はカーネル資源の作成に成功した後に書き、
//! `<name>/realized.intent` は作成・削除のカーネル操作の前に書いて完了後に消す（D11）。残った `realized.intent` は
//! 「操作の途中で落ちた」ことを示し、カーネル照合（所有トークンでの昇格または巻き戻し）は後続の担当で、
//! それまでは `network::recorded` が fail-closed で次の操作を拒否する。OS 非依存でファイルには触れない。
//!
//! # 形式
//! ```text
//! FCREA1\n                                  FCRIN1\n
//! name <len>\n<ネットワーク名>\n              op <len>\n<create|delete>\n
//! bridge <len>\n<bridge 名>\n                name <len>\n<ネットワーク名>\n
//! ifindex <len>\n<10 進>\n                   bridge <len>\n<bridge 名>\n
//! token <len>\n<所有トークン>\n               token <len>\n<所有トークン>\n
//! table <len>\n<nft テーブル名>\n             subnet <len>\n<a.b.c.d/nn>\n
//! table-handle <len>\n<10 進・非 0>\n
//! gateway <len>\n<a.b.c.d/nn>\n
//! subnet <len>\n<a.b.c.d/nn>\n
//! ```
//! 復号は `bridge`・`table` がネットワーク名から導出した名前と一致すること、`token` がそのネットワークの発行形式で
//! あること、`gateway` が `subnet` に属すること（prefix 長一致・network / broadcast でない）を検査する。
//! `CreatedNetwork::name_resolution` は列挙に無いため記録しない（復元時は呼び出し側が渡す）。
//!
//! `table-handle` は作成直後に GETTABLE で確かめた nft テーブルのカーネル採番ハンドルで必須項目（#3068・NET-3）。
//! 再起動後の公開の個別解除が、`members/<id>` に記録したルールハンドルを使う前に生きたテーブルのハンドルと照合する鍵で、
//! テーブルが作り直されていれば値が変わる。書き込み側（supervisor #3074・plugin-cri #3075）が未着手で FCREA1 の出荷済みの
//! 環境が無いため、magic は変えず必須にした（旧形式の記録は `DataLoss`）。公開の記録は `member`。

use super::codec::{
    bad, finish, format_prefix, open, parse_prefix, push_field, take_field, token_is_sane,
};
use crate::error::NetError;
use crate::etc_hosts::NameResolution;
use crate::netlink_route::{IfIndex, IfName, IpPrefix};
use crate::network::{CreatedNetwork, NetworkName, NetworkResourceNames, token_names_network};
use crate::nftables_batch::{NftName, NftTableHandle};

const REALIZED_MAGIC: &str = "FCREA1\n";
const INTENT_MAGIC: &str = "FCRIN1\n";

fn derived_names(name: &NetworkName) -> Result<(IfName, NftName), NetError> {
    let names = NetworkResourceNames::derive(name)
        .map_err(|_| bad("network record name cannot derive resource names"))?;
    Ok((names.bridge().clone(), names.table().clone()))
}

fn check_subnet(subnet: &IpPrefix) -> Result<u32, NetError> {
    let std::net::IpAddr::V4(a) = subnet.addr() else {
        return Err(bad("network record subnet must be IPv4"));
    };
    if !(1..=30).contains(&subnet.prefix_len()) || !subnet.is_network() {
        return Err(bad("network record subnet is not a network address"));
    }
    Ok(u32::from(a))
}

/// gateway が subnet に属し（prefix 長一致・network / broadcast でない）、subnet が妥当かを検査する。
/// 記録の復号と、`network::recorded` の作成前の検査が共有する。違反は `DataLoss`。
pub(crate) fn check_gateway(gateway: &IpPrefix, subnet: &IpPrefix) -> Result<(), NetError> {
    let base = check_subnet(subnet)?;
    let std::net::IpAddr::V4(g) = gateway.addr() else {
        return Err(bad("network record gateway must be IPv4"));
    };
    let mask = u32::MAX << (32 - u32::from(subnet.prefix_len()));
    let g = u32::from(g);
    if gateway.prefix_len() != subnet.prefix_len()
        || g & mask != base
        || g == base
        || g == base | !mask
    {
        return Err(bad("network record gateway is outside the subnet"));
    }
    Ok(())
}

/// nft のテーブルハンドルが有効な「ホストの世代」: boot ID と、nft 要求を送るプロセスの network namespace の
/// 同一性（`/proc/self/ns/net` の st_dev・st_ino）。ハンドルは永続的な識別子ではなく、再起動や namespace の
/// 再作成後に同じ数値が再利用されうるため、記録したハンドルを使う前に現在の世代と一致することを確かめる
/// （NET-3・SEC-1・#3068）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostGeneration {
    boot_id: String,
    netns_dev: u64,
    netns_ino: u64,
}

impl HostGeneration {
    /// boot ID は UUID 形式（36 文字の小文字 16 進とハイフン）に限る。
    pub fn new(boot_id: &str, netns_dev: u64, netns_ino: u64) -> Result<Self, NetError> {
        let ok = boot_id.len() == 36
            && boot_id
                .bytes()
                .all(|b| b == b'-' || b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        if !ok {
            return Err(bad("host generation boot id is malformed"));
        }
        Ok(Self {
            boot_id: boot_id.to_owned(),
            netns_dev,
            netns_ino,
        })
    }

    /// 現在のプロセスの世代を読む（Linux。読めなければ `Err` で、呼び出し側は fail-closed に扱う）。
    #[cfg(target_os = "linux")]
    pub fn current() -> Result<Self, NetError> {
        use crate::error::NetErrorCode;
        use std::io::Read;
        use std::os::unix::fs::MetadataExt;
        let io = |_: std::io::Error| {
            NetError::new(NetErrorCode::Internal, "cannot read the host generation")
        };
        // boot_id は 37 バイト（UUID と改行）。上限つきで読む。
        let mut buf = Vec::new();
        std::fs::File::open("/proc/sys/kernel/random/boot_id")
            .map_err(io)?
            .take(64)
            .read_to_end(&mut buf)
            .map_err(io)?;
        let text = std::str::from_utf8(&buf)
            .map_err(|_| bad("host generation boot id is not UTF-8"))?
            .trim_end_matches('\n');
        let meta = std::fs::metadata("/proc/self/ns/net").map_err(io)?;
        Self::new(text, meta.dev(), meta.ino())
    }

    /// 非 Linux には nft が無く世代の意味が無い。OS 非依存の本体を試験できるよう固定値を返す。
    #[cfg(not(target_os = "linux"))]
    pub fn current() -> Result<Self, NetError> {
        Self::new("00000000-0000-0000-0000-000000000000", 0, 0)
    }

    /// boot ID。
    pub fn boot_id(&self) -> &str {
        &self.boot_id
    }
}

/// カーネル資源の作成に成功したネットワークの記録（FCREA1）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RealizedRecord {
    generation: HostGeneration,
    name: NetworkName,
    bridge: IfName,
    ifindex: IfIndex,
    token: String,
    table: NftName,
    table_handle: NftTableHandle,
    gateway: IpPrefix,
    subnet: IpPrefix,
}

impl RealizedRecord {
    /// 作成結果と定義の subnet、作成直後に確かめたテーブルハンドルから作る。名前の導出・トークン・gateway の
    /// 所属が食い違えば `DataLoss`。
    pub fn from_created(
        created: &CreatedNetwork,
        subnet: IpPrefix,
        table_handle: NftTableHandle,
        generation: HostGeneration,
    ) -> Result<Self, NetError> {
        let rec = Self {
            generation,
            name: created.name.clone(),
            bridge: created.bridge.clone(),
            ifindex: created.bridge_index,
            token: created.bridge_token.clone(),
            table: created.table.clone(),
            table_handle,
            gateway: created.gateway,
            subnet,
        };
        rec.validate()?;
        Ok(rec)
    }

    fn validate(&self) -> Result<(), NetError> {
        let (bridge, table) = derived_names(&self.name)?;
        if self.bridge != bridge || self.table != table {
            return Err(bad(
                "network record resource names do not match the network",
            ));
        }
        if !token_is_sane(&self.token) || !token_names_network(&self.token, &self.name) {
            return Err(bad("network record token does not name the network"));
        }
        check_gateway(&self.gateway, &self.subnet)
    }

    /// `CreatedNetwork` へ戻す。`name_resolution` は記録に無いため呼び出し側が渡す。
    pub fn to_created(&self, name_resolution: NameResolution) -> CreatedNetwork {
        CreatedNetwork {
            name: self.name.clone(),
            bridge: self.bridge.clone(),
            bridge_index: self.ifindex,
            bridge_token: self.token.clone(),
            table: self.table.clone(),
            gateway: self.gateway,
            name_resolution,
        }
    }

    /// ネットワーク名。
    pub fn name(&self) -> &NetworkName {
        &self.name
    }

    /// bridge の所有トークン。
    pub fn token(&self) -> &str {
        &self.token
    }

    /// テーブルハンドルを採った時点のホストの世代。
    pub fn generation(&self) -> &HostGeneration {
        &self.generation
    }

    /// 作成時に確かめた nft テーブルのハンドル（公開の解除の照合に使う。#3068）。
    pub fn table_handle(&self) -> NftTableHandle {
        self.table_handle
    }

    /// gateway（prefix 長つき）。
    pub fn gateway(&self) -> IpPrefix {
        self.gateway
    }

    /// subnet（ネットワークアドレス）。
    pub fn subnet(&self) -> IpPrefix {
        self.subnet
    }

    /// 正準形の FCREA1 へ符号化する。
    pub fn encode(&self) -> Vec<u8> {
        let mut out = String::from(REALIZED_MAGIC);
        push_field(&mut out, "name", self.name.as_str());
        push_field(&mut out, "bridge", self.bridge.as_str());
        push_field(&mut out, "ifindex", &self.ifindex.get().to_string());
        push_field(&mut out, "token", &self.token);
        push_field(&mut out, "table", self.table.as_str());
        push_field(
            &mut out,
            "table-handle",
            &self.table_handle.get().to_string(),
        );
        push_field(&mut out, "boot-id", &self.generation.boot_id);
        push_field(
            &mut out,
            "netns",
            &format!(
                "{}:{}",
                self.generation.netns_dev, self.generation.netns_ino
            ),
        );
        push_field(&mut out, "gateway", &format_prefix(&self.gateway));
        push_field(&mut out, "subnet", &format_prefix(&self.subnet));
        out.into_bytes()
    }

    /// FCREA1 を復号する。違反はすべて `DataLoss`。
    pub fn decode(bytes: &[u8]) -> Result<Self, NetError> {
        let mut rest = open(bytes, REALIZED_MAGIC)?;
        let invalid_value = |_: NetError| bad("realized record holds an invalid value");
        let name = NetworkName::new(take_field(&mut rest, "name")?).map_err(invalid_value)?;
        let bridge = IfName::new(take_field(&mut rest, "bridge")?).map_err(invalid_value)?;
        let index = take_field(&mut rest, "ifindex")?;
        let ifindex = index
            .parse::<u32>()
            .ok()
            .filter(|n| n.to_string() == index)
            .and_then(|n| IfIndex::new(n).ok())
            .ok_or_else(|| bad("realized record ifindex is malformed"))?;
        let token = take_field(&mut rest, "token")?.to_owned();
        let table = NftName::new(take_field(&mut rest, "table")?).map_err(invalid_value)?;
        let handle = take_field(&mut rest, "table-handle")?;
        let table_handle = handle
            .parse::<u64>()
            .ok()
            .filter(|n| n.to_string() == handle)
            .and_then(|n| NftTableHandle::new(n).ok())
            .ok_or_else(|| bad("realized record table handle is malformed"))?;
        let boot_id = take_field(&mut rest, "boot-id")?;
        let netns = take_field(&mut rest, "netns")?;
        let generation = netns
            .split_once(':')
            .and_then(|(d, i)| Some((d.parse::<u64>().ok()?, i.parse::<u64>().ok()?)))
            .filter(|(d, i)| format!("{d}:{i}") == netns)
            .ok_or_else(|| bad("realized record netns identity is malformed"))
            .and_then(|(d, i)| HostGeneration::new(boot_id, d, i))?;
        let gateway = parse_prefix(take_field(&mut rest, "gateway")?)?;
        let subnet = parse_prefix(take_field(&mut rest, "subnet")?)?;
        finish(rest)?;
        let rec = Self {
            generation,
            name,
            bridge,
            ifindex,
            token,
            table,
            table_handle,
            gateway,
            subnet,
        };
        rec.validate()?;
        Ok(rec)
    }
}

/// 操作中の種別。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RealizedOp {
    /// 作成中。
    Create,
    /// 削除中。
    Delete,
}

impl RealizedOp {
    fn as_str(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Delete => "delete",
        }
    }
}

/// 作成・削除のカーネル操作の前に書く意図記録（FCRIN1）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RealizedIntent {
    op: RealizedOp,
    name: NetworkName,
    bridge: IfName,
    token: String,
    subnet: IpPrefix,
}

impl RealizedIntent {
    /// 検証して作る。bridge は名前から導出した名前に固定し、トークンはそのネットワークの発行形式に限る。
    pub fn new(
        op: RealizedOp,
        name: NetworkName,
        token: &str,
        subnet: IpPrefix,
    ) -> Result<Self, NetError> {
        let (bridge, _) = derived_names(&name)?;
        let rec = Self {
            op,
            name,
            bridge,
            token: token.to_owned(),
            subnet,
        };
        rec.validate()?;
        Ok(rec)
    }

    fn validate(&self) -> Result<(), NetError> {
        let (bridge, _) = derived_names(&self.name)?;
        if self.bridge != bridge {
            return Err(bad("realized intent bridge does not match the network"));
        }
        if !token_is_sane(&self.token) || !token_names_network(&self.token, &self.name) {
            return Err(bad("realized intent token does not name the network"));
        }
        check_subnet(&self.subnet).map(|_| ())
    }

    /// 操作の種別。
    pub fn op(&self) -> RealizedOp {
        self.op
    }

    /// ネットワーク名。
    pub fn name(&self) -> &NetworkName {
        &self.name
    }

    /// 刻む（または刻んだ）所有トークン。
    pub fn token(&self) -> &str {
        &self.token
    }

    /// 正準形の FCRIN1 へ符号化する。
    pub fn encode(&self) -> Vec<u8> {
        let mut out = String::from(INTENT_MAGIC);
        push_field(&mut out, "op", self.op.as_str());
        push_field(&mut out, "name", self.name.as_str());
        push_field(&mut out, "bridge", self.bridge.as_str());
        push_field(&mut out, "token", &self.token);
        push_field(&mut out, "subnet", &format_prefix(&self.subnet));
        out.into_bytes()
    }

    /// FCRIN1 を復号する。違反はすべて `DataLoss`。
    pub fn decode(bytes: &[u8]) -> Result<Self, NetError> {
        let mut rest = open(bytes, INTENT_MAGIC)?;
        let invalid_value = |_: NetError| bad("realized intent holds an invalid value");
        let op = match take_field(&mut rest, "op")? {
            "create" => RealizedOp::Create,
            "delete" => RealizedOp::Delete,
            _ => return Err(bad("realized intent op is unknown")),
        };
        let name = NetworkName::new(take_field(&mut rest, "name")?).map_err(invalid_value)?;
        let bridge = IfName::new(take_field(&mut rest, "bridge")?).map_err(invalid_value)?;
        let token = take_field(&mut rest, "token")?.to_owned();
        let subnet = parse_prefix(take_field(&mut rest, "subnet")?)?;
        finish(rest)?;
        let rec = Self {
            op,
            name,
            bridge,
            token,
            subnet,
        };
        rec.validate()?;
        Ok(rec)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::NetErrorCode;
    use std::net::{IpAddr, Ipv4Addr};

    const TOKEN: &str = "fandhe-net:web:1:0:0";

    fn pfx(a: [u8; 4], len: u8) -> IpPrefix {
        IpPrefix::new(IpAddr::V4(Ipv4Addr::from(a)), len).unwrap()
    }

    fn created() -> CreatedNetwork {
        let name = NetworkName::new("web").unwrap();
        let names = NetworkResourceNames::derive(&name).unwrap();
        CreatedNetwork {
            bridge: names.bridge().clone(),
            bridge_index: IfIndex::new(7).unwrap(),
            bridge_token: TOKEN.to_owned(),
            table: names.table().clone(),
            gateway: pfx([10, 0, 0, 1], 24),
            name_resolution: NameResolution::default(),
            name,
        }
    }

    fn th(n: u64) -> NftTableHandle {
        NftTableHandle::new(n).unwrap()
    }

    fn code<T: std::fmt::Debug>(r: Result<T, NetError>) -> NetErrorCode {
        r.unwrap_err().code()
    }

    /// NET-1・#3067: 具体バイト列・往復・CreatedNetwork への復元。
    #[test]
    fn net1_3067_realized_encode_exact_and_roundtrip() {
        let c = created();
        let r = RealizedRecord::from_created(
            &c,
            pfx([10, 0, 0, 0], 24),
            th(42),
            HostGeneration::new("0123abcd-4567-89ab-cdef-0123456789ab", 5, 4026531833).unwrap(),
        )
        .unwrap();
        assert_eq!(r.table_handle().get(), 42);
        let text = String::from_utf8(r.encode()).unwrap();
        let expected = format!(
            "FCREA1\nname 3\nweb\nbridge {}\n{}\nifindex 1\n7\ntoken 20\n{TOKEN}\ntable {}\n{}\ntable-handle 2\n42\nboot-id 36\n0123abcd-4567-89ab-cdef-0123456789ab\nnetns 12\n5:4026531833\ngateway 11\n10.0.0.1/24\nsubnet 11\n10.0.0.0/24\n",
            c.bridge.as_str().len(),
            c.bridge.as_str(),
            c.table.as_str().len(),
            c.table.as_str()
        );
        assert_eq!(text, expected);
        let back = RealizedRecord::decode(&r.encode()).unwrap();
        assert_eq!(back, r);
        assert_eq!(back.to_created(NameResolution::default()), c);
        assert_eq!(back.subnet(), pfx([10, 0, 0, 0], 24));
    }

    /// NET-3・SEC-1・#3068: 世代の無い旧形式（boot-id・netns 行が無い FCREA1）は DataLoss で拒否する。
    #[test]
    fn net3_3068_realized_without_generation_is_rejected() {
        let c = created();
        let old = format!(
            "FCREA1\nname 3\nweb\nbridge {}\n{}\nifindex 1\n7\ntoken 20\n{TOKEN}\ntable {}\n{}\ntable-handle 2\n42\ngateway 11\n10.0.0.1/24\nsubnet 11\n10.0.0.0/24\n",
            c.bridge.as_str().len(),
            c.bridge.as_str(),
            c.table.as_str().len(),
            c.table.as_str()
        );
        assert_eq!(
            code(RealizedRecord::decode(old.as_bytes())),
            NetErrorCode::DataLoss
        );
    }

    #[test]
    fn net1_3067_realized_decode_rejects_malformed() {
        let c = created();
        let good = String::from_utf8(
            RealizedRecord::from_created(
                &c,
                pfx([10, 0, 0, 0], 24),
                th(42),
                HostGeneration::current().unwrap(),
            )
            .unwrap()
            .encode(),
        )
        .unwrap();
        let cases = vec![
            good.replace("FCREA1", "FCREA2"),
            good.replace("ifindex 1\n7", "ifindex 1\n0"),
            good.replace("ifindex 1\n7", "ifindex 2\n07"),
            // #3068: テーブルハンドルの欠落・0・先頭 0・符号・範囲外・順序違い。
            good.replace("table-handle 2\n42\n", ""),
            // NET-3・SEC-1・#3068: 世代（boot ID・netns）の欠落（旧形式）・不正値・順序違いは fail-closed。
            good.replace(
                &format!(
                    "boot-id 36\n{}\n",
                    HostGeneration::current().unwrap().boot_id()
                ),
                "",
            ),
            good.replace("netns 12\n", "netns 3\nx\n"),
            good.replace("boot-id 36", "boot-id 35"),
            good.replace("table-handle 2\n42", "table-handle 1\n0"),
            good.replace("table-handle 2\n42", "table-handle 3\n042"),
            good.replace("table-handle 2\n42", "table-handle 3\n+42"),
            good.replace(
                "table-handle 2\n42",
                "table-handle 20\n18446744073709551616",
            ),
            good.replace("table-handle 2\n42", "table-handle 0\n"),
            good.replace(TOKEN, "fandhe-net:other:1:0:0"),
            good.replace("gateway 11\n10.0.0.1/24", "gateway 11\n10.0.1.1/24"),
            good.replace("gateway 11\n10.0.0.1/24", "gateway 11\n10.0.0.0/24"),
            good.replace("gateway 11\n10.0.0.1/24", "gateway 13\n10.0.0.255/24"),
            good.replace("subnet 11\n10.0.0.0/24", "subnet 11\n10.0.0.1/24"),
            format!("{good}x"),
        ];
        for bad_case in &cases {
            assert_eq!(
                code(RealizedRecord::decode(bad_case.as_bytes())),
                NetErrorCode::DataLoss,
                "{bad_case:?}"
            );
        }
        // bridge 名がネットワーク名の導出と一致しない。
        let swapped = good.replace(c.bridge.as_str(), "fcbr0000000000");
        assert_eq!(
            code(RealizedRecord::decode(swapped.as_bytes())),
            NetErrorCode::DataLoss
        );
    }

    #[test]
    fn net1_3067_realized_intent_exact_and_roundtrip() {
        let i = RealizedIntent::new(
            RealizedOp::Create,
            NetworkName::new("web").unwrap(),
            TOKEN,
            pfx([10, 0, 0, 0], 24),
        )
        .unwrap();
        let text = String::from_utf8(i.encode()).unwrap();
        assert!(text.starts_with("FCRIN1\nop 6\ncreate\nname 3\nweb\nbridge "));
        assert!(text.ends_with("subnet 11\n10.0.0.0/24\n"));
        assert_eq!(RealizedIntent::decode(&i.encode()).unwrap(), i);
        assert_eq!(i.op(), RealizedOp::Create);
        let bad_op = text.replace("op 6\ncreate", "op 4\nkeep");
        assert_eq!(
            code(RealizedIntent::decode(bad_op.as_bytes())),
            NetErrorCode::DataLoss
        );
        assert_eq!(
            code(RealizedIntent::new(
                RealizedOp::Delete,
                NetworkName::new("web").unwrap(),
                "fandhe-net:other:1:0:0",
                pfx([10, 0, 0, 0], 24)
            )),
            NetErrorCode::DataLoss
        );
    }
}
