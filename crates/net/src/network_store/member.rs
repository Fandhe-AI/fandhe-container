//! メンバー記録（FCMEM1）と attach 前の意図記録（FCMIN1）の符号化（NET-1・NET-7・REPAIR-2・#3067）。
//!
//! 役割: ネットワークに接続したコンテナ 1 件ごとの記録を `<name>/members/<id>`（確定記録。attach の成功後に書く）と
//! `<name>/members-intent/<id>`（意図記録。カーネル操作の前に書き、確定記録の後に消す）に置く形式を、
//! 「壊れた値を表現できない」型と正準形だけを受ける復号で固定する。OS 非依存でファイルには触れない
//! （置き場の検査・原子的な書き込みは `network_store::imp`）。IPAM は独立したカウンタを持たず、これらの記録から
//! `ipam_rebuild::rebuild_ipam` で組み直す（D11）。呼び出し元の想定は `network::recorded`（記録つきの attach / detach。
//! supervisor #3074・plugin-cri #3075 が使う）。設計の正は `docs/design/network-wiring.md` の D10・D11。
//!
//! # 形式
//! ```text
//! FCMEM1\n                                       FCMIN1\n
//! id <len>\n<メンバー ID>\n                       id <len>\n<メンバー ID>\n
//! endpoint <len>\n<EndpointId>\n                 endpoint <len>\n<EndpointId>\n
//! address <len>\n<a.b.c.d/nn>\n                  address <len>\n<a.b.c.d/nn>\n
//! token <len>\n<host veth の所有トークン>\n         token <len>\n<host veth の所有トークン>\n
//! netns-dir <len>\n<絶対パス>\n
//! netns-dir-id <len>\n<dev:ino>\n
//! dns <len>\n<ip>\n                  (0〜3 回)
//! ```
//! `token`・`netns-dir`・`netns-dir-id` は D11 の列挙に無い補助項目で、組み直した IPAM に netns pin 置き場の記録
//! （`NetnsDirRecord`）を戻して `delete_network` が pin を判定不能として扱う劣化を防ぐことと、後続の所有照合のために置く。
//! 公開（受け口と rule handle）は #3068 が kind を足す。`len` の規則・並び・末尾のごみは `codec` を参照（違反は `DataLoss`）。

use std::net::IpAddr;
use std::path::{Component, Path, PathBuf};

use super::codec::{
    bad, finish, format_prefix, open, parse_dir_id, parse_prefix, push_field, take_field,
    take_optional, token_is_sane,
};
use crate::dns_helper::upstream::{MAX_UPSTREAMS_PER_CONTAINER, UpstreamServer};
use crate::error::{NetError, NetErrorCode};
use crate::netlink_route::IpPrefix;
use crate::network::{EndpointId, NetnsDirRecord};

const MEMBER_MAGIC: &str = "FCMEM1\n";
const INTENT_MAGIC: &str = "FCMIN1\n";
/// `netns-dir` の最大バイト数。
const NETNS_DIR_MAX_BYTES: usize = 1024;
/// `MemberId` の最大バイト数（core の `ContainerId` と同じ）。
const MEMBER_ID_MAX_BYTES: usize = 255;

fn invalid(msg: &'static str) -> NetError {
    NetError::new(NetErrorCode::InvalidArgument, msg)
}

/// 検証済みのメンバー ID（コンテナの識別子。ファイル名にそのまま使う）。
///
/// core の `ContainerId` と同じ規則（`[A-Za-z0-9._-]`・1〜255 バイト・`.` と `..` は拒否）。net は core に依存しない
/// 葉 crate（`docs/architecture.md`）のため規則を複製する。先頭の `.` と大文字を許すため、置き場の一時ファイルは
/// 必ず `@tmp-` 接頭辞にする（`@` は本型にも `NetworkName` にも現れない）。
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MemberId(String);

impl MemberId {
    /// 検証して作る。違反は `InvalidArgument`（入力値はメッセージに載せない）。
    pub fn new(id: &str) -> Result<Self, NetError> {
        if id.is_empty() || id.len() > MEMBER_ID_MAX_BYTES {
            return Err(invalid("member id length must be 1 to 255 bytes"));
        }
        if id == "." || id == ".." {
            return Err(invalid("member id must not be . or .."));
        }
        if !id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        {
            return Err(invalid("member id contains invalid characters"));
        }
        Ok(Self(id.to_owned()))
    }

    /// ID を返す。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn check_netns_dir(path: &Path) -> Result<String, NetError> {
    let s = path
        .to_str()
        .ok_or_else(|| invalid("netns directory must be UTF-8"))?;
    if !path.is_absolute()
        || s.len() > NETNS_DIR_MAX_BYTES
        || s.chars().any(char::is_control)
        || path
            .components()
            .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
    {
        return Err(invalid(
            "netns directory is not an acceptable absolute path",
        ));
    }
    Ok(s.to_owned())
}

fn check_ipv4_member_address(address: &IpPrefix) -> Result<(), NetError> {
    if !address.addr().is_ipv4() || !(1..=30).contains(&address.prefix_len()) {
        return Err(invalid("member address must be an IPv4 prefix of 1 to 30"));
    }
    Ok(())
}

fn check_token(token: &str, endpoint: &EndpointId) -> Result<(), NetError> {
    // 形式は `<bridge_token>/ep/<endpoint>/g/<世代>`。bridge_token との整合は組み直し時に照合する。
    let marker = format!("/ep/{}/g/", endpoint.as_str());
    if !token_is_sane(token) || !token.contains(&marker) {
        return Err(invalid("member token is not valid for the endpoint"));
    }
    Ok(())
}

/// 確定したメンバー記録（FCMEM1）。attach の成功後にだけ書く。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberRecord {
    id: MemberId,
    endpoint: EndpointId,
    address: IpPrefix,
    token: String,
    netns_dir: PathBuf,
    netns_dir_id: (u64, u64),
    dns: Vec<IpAddr>,
}

impl MemberRecord {
    /// 検証して作る。`netns_dir` は接続時の netns pin 置き場の絶対パス、`netns_dir_id` はその (st_dev, st_ino)。`dns` は 0〜3 件で、`UpstreamServer::new` が受けるもの・重複なし。
    pub fn new(
        id: MemberId,
        endpoint: EndpointId,
        address: IpPrefix,
        token: &str,
        netns_dir: &Path,
        netns_dir_id: (u64, u64),
        dns: &[IpAddr],
    ) -> Result<Self, NetError> {
        check_ipv4_member_address(&address)?;
        check_token(token, &endpoint)?;
        check_netns_dir(netns_dir)?;
        if dns.len() > MAX_UPSTREAMS_PER_CONTAINER {
            return Err(invalid("too many dns servers for a member"));
        }
        for (i, ip) in dns.iter().enumerate() {
            UpstreamServer::new(*ip)?;
            if dns.iter().skip(i + 1).any(|o| o == ip) {
                return Err(invalid("duplicate dns server for a member"));
            }
        }
        Ok(Self {
            id,
            endpoint,
            address,
            token: token.to_owned(),
            netns_dir: netns_dir.to_path_buf(),
            netns_dir_id,
            dns: dns.to_vec(),
        })
    }

    /// メンバー ID。
    pub fn id(&self) -> &MemberId {
        &self.id
    }

    /// endpoint。
    pub fn endpoint(&self) -> &EndpointId {
        &self.endpoint
    }

    /// 払い出したアドレス（prefix 長つき）。
    pub fn address(&self) -> IpPrefix {
        self.address
    }

    /// host veth の所有トークン。
    pub fn token(&self) -> &str {
        &self.token
    }

    /// 接続時の netns pin 置き場の記録（組み直した IPAM に戻す）。
    pub(crate) fn netns_dir_record(&self) -> NetnsDirRecord {
        NetnsDirRecord::new(self.netns_dir.clone(), self.netns_dir_id)
    }

    /// `--dns` の上流。
    pub fn dns(&self) -> &[IpAddr] {
        &self.dns
    }

    /// 正準形の FCMEM1 へ符号化する。
    pub fn encode(&self) -> Vec<u8> {
        let mut out = String::from(MEMBER_MAGIC);
        push_field(&mut out, "id", self.id.as_str());
        push_field(&mut out, "endpoint", self.endpoint.as_str());
        push_field(&mut out, "address", &format_prefix(&self.address));
        push_field(&mut out, "token", &self.token);
        push_field(&mut out, "netns-dir", &self.netns_dir.to_string_lossy());
        push_field(
            &mut out,
            "netns-dir-id",
            &format!("{}:{}", self.netns_dir_id.0, self.netns_dir_id.1),
        );
        for ip in &self.dns {
            push_field(&mut out, "dns", &ip.to_string());
        }
        out.into_bytes()
    }

    /// FCMEM1 を復号する。外部入力（ディスク上の文書）なので、違反はすべて `DataLoss`。
    pub fn decode(bytes: &[u8]) -> Result<Self, NetError> {
        let mut rest = open(bytes, MEMBER_MAGIC)?;
        let invalid_value = |_: NetError| bad("member record holds an invalid value");
        let id = MemberId::new(take_field(&mut rest, "id")?).map_err(invalid_value)?;
        let endpoint =
            EndpointId::new(take_field(&mut rest, "endpoint")?).map_err(invalid_value)?;
        let address = parse_prefix(take_field(&mut rest, "address")?)?;
        let token = take_field(&mut rest, "token")?;
        let dir = take_field(&mut rest, "netns-dir")?;
        let dir_id = parse_dir_id(take_field(&mut rest, "netns-dir-id")?)?;
        let mut dns = Vec::new();
        while let Some(v) = take_optional(&mut rest, "dns")? {
            let ip: IpAddr = v.parse().map_err(|_| bad("member dns is malformed"))?;
            if ip.to_string() != v {
                return Err(bad("member dns is not canonical"));
            }
            dns.push(ip);
        }
        finish(rest)?;
        Self::new(id, endpoint, address, token, Path::new(dir), dir_id, &dns).map_err(invalid_value)
    }
}

/// attach 前の意図記録（FCMIN1）。カーネル操作の前に書き、確定記録の後に消す。
///
/// 残っていれば「カーネル側に資源が残りうる」ため、アドレスを使用中として数え続ける（再割り当てしない）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberIntent {
    id: MemberId,
    endpoint: EndpointId,
    address: IpPrefix,
    token: String,
}

impl MemberIntent {
    /// 検証して作る。
    pub fn new(
        id: MemberId,
        endpoint: EndpointId,
        address: IpPrefix,
        token: &str,
    ) -> Result<Self, NetError> {
        check_ipv4_member_address(&address)?;
        check_token(token, &endpoint)?;
        Ok(Self {
            id,
            endpoint,
            address,
            token: token.to_owned(),
        })
    }

    /// メンバー ID。
    pub fn id(&self) -> &MemberId {
        &self.id
    }

    /// endpoint。
    pub fn endpoint(&self) -> &EndpointId {
        &self.endpoint
    }

    /// 割り当てるアドレス。
    pub fn address(&self) -> IpPrefix {
        self.address
    }

    /// 刻む予定の host veth の所有トークン。
    pub fn token(&self) -> &str {
        &self.token
    }

    /// 正準形の FCMIN1 へ符号化する。
    pub fn encode(&self) -> Vec<u8> {
        let mut out = String::from(INTENT_MAGIC);
        push_field(&mut out, "id", self.id.as_str());
        push_field(&mut out, "endpoint", self.endpoint.as_str());
        push_field(&mut out, "address", &format_prefix(&self.address));
        push_field(&mut out, "token", &self.token);
        out.into_bytes()
    }

    /// FCMIN1 を復号する。違反はすべて `DataLoss`。
    pub fn decode(bytes: &[u8]) -> Result<Self, NetError> {
        let mut rest = open(bytes, INTENT_MAGIC)?;
        let invalid_value = |_: NetError| bad("member intent holds an invalid value");
        let id = MemberId::new(take_field(&mut rest, "id")?).map_err(invalid_value)?;
        let endpoint =
            EndpointId::new(take_field(&mut rest, "endpoint")?).map_err(invalid_value)?;
        let address = parse_prefix(take_field(&mut rest, "address")?)?;
        let token = take_field(&mut rest, "token")?;
        finish(rest)?;
        Self::new(id, endpoint, address, token).map_err(invalid_value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    const TOKEN: &str = "fandhe-net:web:1:0:0/ep/c1/g/00000000000000000000000000000001";

    fn pfx(a: [u8; 4], len: u8) -> IpPrefix {
        IpPrefix::new(IpAddr::V4(Ipv4Addr::from(a)), len).unwrap()
    }

    fn member(dns: &[IpAddr]) -> MemberRecord {
        MemberRecord::new(
            MemberId::new("C1").unwrap(),
            EndpointId::new("c1").unwrap(),
            pfx([10, 0, 0, 2], 24),
            TOKEN,
            Path::new("/run/ns"),
            (8, 9),
            dns,
        )
        .unwrap()
    }

    fn code<T: std::fmt::Debug>(r: Result<T, NetError>) -> NetErrorCode {
        r.unwrap_err().code()
    }

    /// NET-1・#3067: 具体バイト列と往復。
    #[test]
    fn net1_3067_member_encode_exact_and_roundtrip() {
        let m = member(&["1.1.1.1".parse().unwrap(), "8.8.8.8".parse().unwrap()]);
        let expected = format!(
            "FCMEM1\nid 2\nC1\nendpoint 2\nc1\naddress 11\n10.0.0.2/24\ntoken {}\n{TOKEN}\nnetns-dir 7\n/run/ns\nnetns-dir-id 3\n8:9\ndns 7\n1.1.1.1\ndns 7\n8.8.8.8\n",
            TOKEN.len()
        );
        assert_eq!(m.encode(), expected.as_bytes());
        assert_eq!(MemberRecord::decode(&m.encode()).unwrap(), m);
        assert_eq!(
            MemberRecord::decode(&member(&[]).encode())
                .unwrap()
                .dns()
                .len(),
            0
        );
    }

    #[test]
    fn net1_3067_intent_encode_exact_and_roundtrip() {
        let i = MemberIntent::new(
            MemberId::new("c1").unwrap(),
            EndpointId::new("c1").unwrap(),
            pfx([10, 0, 0, 4], 24),
            TOKEN,
        )
        .unwrap();
        let expected = format!(
            "FCMIN1\nid 2\nc1\nendpoint 2\nc1\naddress 11\n10.0.0.4/24\ntoken {}\n{TOKEN}\n",
            TOKEN.len()
        );
        assert_eq!(i.encode(), expected.as_bytes());
        assert_eq!(MemberIntent::decode(&i.encode()).unwrap(), i);
    }

    #[test]
    fn net1_3067_member_decode_rejects_malformed() {
        let good = String::from_utf8(member(&[]).encode()).unwrap();
        let cases: Vec<String> = vec![
            good.replace("FCMEM1", "FCMEM2"),
            good.replace("id 2\nC1\nendpoint 2\nc1\n", "endpoint 2\nc1\nid 2\nC1\n"),
            format!("{good}x"),
            format!("{good}dns 7\n1.1.1.1\ndns 7\n1.1.1.1\ndns 7\n8.8.8.8\ndns 7\n9.9.9.9\n"),
            format!("{good}dns 9\n127.0.0.1\n"),
            good.replace("netns-dir 7\n/run/ns", "netns-dir 6\nrun/ns"),
            good.replace("netns-dir 7\n/run/ns", "netns-dir 9\n/run/../ns"),
            good.replace("netns-dir-id 3\n8:9", "netns-dir-id 4\n08:9"),
            good.replace("address 11\n10.0.0.2/24", "address 11\n10.0.0.2/24\n"),
            good.replace("id 2\nC1", "id 2\n.."),
            good.replace("c1\naddress", "c2\naddress"),
        ];
        for c in &cases {
            assert_eq!(
                code(MemberRecord::decode(c.as_bytes())),
                NetErrorCode::DataLoss,
                "{c:?}"
            );
        }
        let big = vec![b'a'; 4097];
        assert_eq!(code(MemberRecord::decode(&big)), NetErrorCode::DataLoss);
        assert_eq!(code(MemberIntent::decode(&big)), NetErrorCode::DataLoss);
    }

    #[test]
    fn net1_3067_member_constructors_reject() {
        let mk = |dns: &[IpAddr], token: &str| {
            MemberRecord::new(
                MemberId::new("c1").unwrap(),
                EndpointId::new("c1").unwrap(),
                pfx([10, 0, 0, 2], 24),
                token,
                Path::new("/run/ns"),
                (8, 9),
                dns,
            )
        };
        let four: Vec<IpAddr> = ["1.1.1.1", "1.0.0.1", "8.8.8.8", "9.9.9.9"]
            .iter()
            .map(|s| s.parse().unwrap())
            .collect();
        assert_eq!(code(mk(&four, TOKEN)), NetErrorCode::InvalidArgument);
        assert_eq!(
            code(mk(&[], "no-endpoint-marker")),
            NetErrorCode::InvalidArgument
        );
        for bad_id in ["", ".", "..", "a/b", "a b", "@x"] {
            assert_eq!(code(MemberId::new(bad_id)), NetErrorCode::InvalidArgument);
        }
        assert!(MemberId::new(".hidden-1").is_ok());
        assert_eq!(
            code(MemberId::new(&"a".repeat(256))),
            NetErrorCode::InvalidArgument
        );
    }
}
