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
//! table-handle <len>\n<10 進・非 0>\n   (公開が 1 件以上のときだけ 1 回)
//! publish <len>\n<proto addr:host-port container-port prerouting output>\n   (0〜64 回)
//! ```
//! `token`・`netns-dir`・`netns-dir-id` は D11 の列挙に無い補助項目で、組み直した IPAM に netns pin 置き場の記録
//! （`NetnsDirRecord`）を戻して `delete_network` が pin を判定不能として扱う劣化を防ぐことと、後続の所有照合のために置く。
//! `table-handle`・`publish` は公開（受け口と nft の rule handle 2 本）の記録で、再起動後に dump を使わず永続化した値から
//! 公開の個別解除を復元する（#3068・NET-3・D11）。`table-handle` は公開を投入した nft テーブルのカーネル採番ハンドルで、解除の
//! 前に生きたテーブルのハンドルと照合する（テーブルが作り直されていれば rule handle は古く、削除に使わない）。`publish` が
//! 1 件以上あるときだけ `table-handle` を置く。`publish` の値は `tcp|udp <ipv4>:<host-port> <container-port> <prerouting> <output>`
//! の正準形だけを受ける（解除の意図を DELRULE の前に残した公開には末尾に ` unpublishing` が付く。再起動後に ENOENT を
//! 「既に消えた」と扱う唯一の根拠で、テーブルハンドルの照合後にだけ使う）。公開の無い旧形式（#3067）はそのまま読める。`len` の規則・並び・末尾のごみは `codec` を参照（違反は `DataLoss`）。

use std::net::IpAddr;
use std::path::{Component, Path, PathBuf};

use super::codec::{
    RECORD_MAX_BYTES, bad, finish, format_prefix, open, parse_dir_id, parse_prefix, push_field,
    take_field, take_optional, token_is_sane,
};
use super::realized::RealizedRecord;
use crate::dns_helper::upstream::{MAX_UPSTREAMS_PER_CONTAINER, UpstreamServer};
use crate::error::{NetError, NetErrorCode};
use crate::netlink_route::IpPrefix;
use crate::network::{
    EndpointId, MAX_PORT_PUBLISHES, NetnsDirRecord, PortProtocol, PortPublish, PublishedPort,
};
use crate::nftables_batch::NftTableHandle;
use crate::nftables_rules::NftRuleHandle;

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
    // 記録は OS 非依存（FCNET1 と同じ）なので、Windows で `/run/ns` を拒む `Path::is_absolute` ではなく
    // 先頭が `/` かどうかで判定する。
    if !s.starts_with('/')
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

/// 記録する公開 1 件（受け口と、投入した DNAT ルール 2 本のカーネル採番ハンドル。#3068）。
///
/// `network::unpublish::PublishedPort` から必要な値だけを写した値型。ハンドルは 0 を表現できない。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordedPublish {
    publish: PortPublish,
    prerouting: NftRuleHandle,
    output: NftRuleHandle,
    /// 解除の意図を DELRULE の前に残した印（再起動後に ENOENT を「既に消えた」と扱ってよい根拠。NET-3・#3068）。
    unpublishing: bool,
}

impl RecordedPublish {
    /// 組み立てる。
    pub fn new(publish: PortPublish, prerouting: NftRuleHandle, output: NftRuleHandle) -> Self {
        Self {
            publish,
            prerouting,
            output,
            unpublishing: false,
        }
    }

    /// 解除の意図の印が付いているか（DELRULE の前に記録される。付いた記録は再起動後の解除の回復に使う）。
    pub fn unpublishing(&self) -> bool {
        self.unpublishing
    }

    /// 公開の指定（受け口とコンテナ側ポート）。
    pub fn publish(&self) -> &PortPublish {
        &self.publish
    }

    /// `prerouting` チェインのルールハンドル。
    pub fn prerouting(&self) -> NftRuleHandle {
        self.prerouting
    }

    /// `output` チェインのルールハンドル。
    pub fn output(&self) -> NftRuleHandle {
        self.output
    }

    fn encode(&self) -> String {
        let proto = match self.publish.protocol() {
            PortProtocol::Tcp => "tcp",
            PortProtocol::Udp => "udp",
        };
        format!(
            "{proto} {}:{} {} {} {}{}",
            self.publish.host_addr(),
            self.publish.host_port(),
            self.publish.container_port(),
            self.prerouting.get(),
            self.output.get(),
            if self.unpublishing {
                " unpublishing"
            } else {
                ""
            }
        )
    }

    /// 正準形だけを受ける。再符号化して一致しなければ `DataLoss`。
    fn decode(v: &str) -> Result<Self, NetError> {
        let malformed = || bad("member publish is malformed");
        let parts: Vec<&str> = v.split(' ').collect();
        let (proto, listener, cport, pre, out, unpublishing) = match parts.as_slice() {
            [a, b, c, d, e] => (a, b, c, d, e, false),
            [a, b, c, d, e, "unpublishing"] => (a, b, c, d, e, true),
            _ => return Err(malformed()),
        };
        let protocol = match *proto {
            "tcp" => PortProtocol::Tcp,
            "udp" => PortProtocol::Udp,
            _ => return Err(malformed()),
        };
        let (addr, hport) = listener.split_once(':').ok_or_else(malformed)?;
        let addr: std::net::Ipv4Addr = addr.parse().map_err(|_| malformed())?;
        let hport: u16 = hport.parse().map_err(|_| malformed())?;
        let cport: u16 = cport.parse().map_err(|_| malformed())?;
        let pre: u64 = pre.parse().map_err(|_| malformed())?;
        let out: u64 = out.parse().map_err(|_| malformed())?;
        let publish = PortPublish::new(protocol, addr, hport, cport).map_err(|_| malformed())?;
        let mut rec = Self::new(
            publish,
            NftRuleHandle::new(pre).map_err(|_| malformed())?,
            NftRuleHandle::new(out).map_err(|_| malformed())?,
        );
        rec.unpublishing = unpublishing;
        if rec.encode() != v {
            return Err(bad("member publish is not canonical"));
        }
        Ok(rec)
    }
}

/// 公開の記録の整合（件数・受け口の重複・rule handle の重複）を検査する。
fn check_publishes(publishes: &[RecordedPublish]) -> Result<(), NetError> {
    if publishes.len() > MAX_PORT_PUBLISHES {
        return Err(invalid("too many published ports for a member"));
    }
    for (i, p) in publishes.iter().enumerate() {
        if p.prerouting == p.output {
            return Err(invalid("publish rule handles must differ"));
        }
        for q in publishes.iter().skip(i + 1) {
            if p.publish.same_listener(&q.publish) {
                return Err(invalid("duplicate published listener for a member"));
            }
            let (a, b) = ([p.prerouting, p.output], [q.prerouting, q.output]);
            if a.iter().any(|h| b.contains(h)) {
                return Err(invalid("duplicate publish rule handle for a member"));
            }
        }
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
    table_handle: Option<NftTableHandle>,
    publishes: Vec<RecordedPublish>,
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
            table_handle: None,
            publishes: Vec::new(),
        })
    }

    /// 公開（受け口と rule handle）と、それを投入したテーブルのハンドルを載せる（#3068）。
    ///
    /// `publishes` が空なら記録に載せない。件数は `MAX_PORT_PUBLISHES` 以下、受け口の重複なし、rule handle 2 本
    /// どうし・他の公開との重複なし、符号化後が `RECORD_MAX_BYTES` 以下であること。違反は `InvalidArgument`。
    pub fn with_publishes(
        mut self,
        table_handle: NftTableHandle,
        publishes: Vec<RecordedPublish>,
    ) -> Result<Self, NetError> {
        if publishes.is_empty() {
            self.table_handle = None;
            self.publishes = publishes;
            return Ok(self);
        }
        check_publishes(&publishes)?;
        self.table_handle = Some(table_handle);
        self.publishes = publishes;
        if self.encode().len() > RECORD_MAX_BYTES {
            return Err(invalid("member record exceeds the size limit"));
        }
        Ok(self)
    }

    /// 公開を投入したテーブルのハンドル（公開が無ければ `None`）。
    pub fn table_handle(&self) -> Option<NftTableHandle> {
        self.table_handle
    }

    /// 記録した公開。
    pub fn publishes(&self) -> &[RecordedPublish] {
        &self.publishes
    }

    /// 指定した受け口の公開に「解除の意図」の印を付けた記録を返す（DELRULE の前に永続化する。NET-3・#3068）。
    /// 記録に無ければ `NotFound`。
    pub fn with_unpublishing(&self, publish: &PortPublish) -> Result<Self, NetError> {
        let mut next = self.clone();
        let Some(p) = next
            .publishes
            .iter_mut()
            .find(|p| p.publish.same_listener(publish))
        else {
            return Err(NetError::new(
                NetErrorCode::NotFound,
                "publish is not recorded for the member",
            ));
        };
        p.unpublishing = true;
        Ok(next)
    }

    /// 指定した受け口の公開に解除の意図の印が付いているか。
    pub fn is_unpublishing(&self, publish: &PortPublish) -> bool {
        self.publishes
            .iter()
            .any(|p| p.unpublishing && p.publish.same_listener(publish))
    }

    /// 指定した受け口の公開を外した記録を返す。最後の 1 件を外したら `table-handle` も外す。
    /// 記録に無ければ `NotFound`。
    pub fn without_publish(&self, publish: &PortPublish) -> Result<Self, NetError> {
        let mut next = self.clone();
        next.publishes.retain(|p| !p.publish.same_listener(publish));
        if next.publishes.len() == self.publishes.len() {
            return Err(NetError::new(
                NetErrorCode::NotFound,
                "publish is not recorded for the member",
            ));
        }
        if next.publishes.is_empty() {
            next.table_handle = None;
        }
        Ok(next)
    }

    /// 記録から公開の個別解除に使う [`PublishedPort`] を復元する（dump は使わない。再起動後の経路。#3068）。
    ///
    /// ネットワーク名と所有トークンは同じネットワークの `realized` から、テーブルハンドルは記録から取る。
    /// 解除（`unpublish_ports_with`）が生きたテーブルのハンドルと照合する。
    // 呼び出し元の `network::recorded` の復元口は OS 非依存の本体だが、実機の呼び出しは Linux 限定。
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn published_ports(&self, realized: &RealizedRecord) -> Vec<PublishedPort> {
        let Some(handle) = self.table_handle else {
            return Vec::new();
        };
        self.publishes
            .iter()
            .map(|p| {
                PublishedPort::new(
                    realized.name(),
                    realized.token(),
                    &self.endpoint,
                    p.publish,
                    (p.prerouting, p.output),
                )
                .with_table_handle(handle)
            })
            .collect()
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
        if let Some(h) = self.table_handle {
            push_field(&mut out, "table-handle", &h.get().to_string());
        }
        for p in &self.publishes {
            push_field(&mut out, "publish", &p.encode());
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
        let table_handle = match take_optional(&mut rest, "table-handle")? {
            Some(v) => Some(
                v.parse::<u64>()
                    .ok()
                    .filter(|n| n.to_string() == v)
                    .and_then(|n| NftTableHandle::new(n).ok())
                    .ok_or_else(|| bad("member table handle is malformed"))?,
            ),
            None => None,
        };
        let mut publishes = Vec::new();
        while let Some(v) = take_optional(&mut rest, "publish")? {
            if publishes.len() >= MAX_PORT_PUBLISHES {
                return Err(bad("member record has too many publishes"));
            }
            publishes.push(RecordedPublish::decode(v)?);
        }
        finish(rest)?;
        let rec = Self::new(id, endpoint, address, token, Path::new(dir), dir_id, &dns)
            .map_err(invalid_value)?;
        match (table_handle, publishes.is_empty()) {
            (None, true) => Ok(rec),
            (Some(h), false) => rec.with_publishes(h, publishes).map_err(invalid_value),
            _ => Err(bad(
                "member table handle and publishes must appear together",
            )),
        }
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
    use crate::network::PortProtocol;
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
        let big = vec![b'a'; RECORD_MAX_BYTES + 1];
        assert_eq!(code(MemberRecord::decode(&big)), NetErrorCode::DataLoss);
        assert_eq!(code(MemberIntent::decode(&big)), NetErrorCode::DataLoss);
    }

    fn publish(proto: PortProtocol, port: u16, cport: u16) -> PortPublish {
        PortPublish::new(proto, Ipv4Addr::new(192, 0, 2, 10), port, cport).unwrap()
    }

    fn rp(proto: PortProtocol, port: u16, pre: u64, out: u64) -> RecordedPublish {
        RecordedPublish::new(
            publish(proto, port, 80),
            NftRuleHandle::new(pre).unwrap(),
            NftRuleHandle::new(out).unwrap(),
        )
    }

    fn th(n: u64) -> NftTableHandle {
        NftTableHandle::new(n).unwrap()
    }

    fn with_two() -> MemberRecord {
        member(&[])
            .with_publishes(
                th(42),
                vec![
                    rp(PortProtocol::Tcp, 8080, 2, 3),
                    rp(PortProtocol::Udp, 5353, 4, 5),
                ],
            )
            .unwrap()
    }

    /// NET-3・#3068: 公開 2 件とテーブルハンドルを含む FCMEM1 の具体バイト列と往復。
    #[test]
    fn net3_3068_member_publish_encode_exact_and_roundtrip() {
        let m = with_two();
        let base = String::from_utf8(member(&[]).encode()).unwrap();
        let expected = format!(
            "{base}table-handle 2\n42\npublish 26\ntcp 192.0.2.10:8080 80 2 3\npublish 26\nudp 192.0.2.10:5353 80 4 5\n"
        );
        assert_eq!(m.encode(), expected.as_bytes());
        let back = MemberRecord::decode(&m.encode()).unwrap();
        assert_eq!(back, m);
        assert_eq!(back.table_handle().map(NftTableHandle::get), Some(42));
        assert_eq!(back.publishes().len(), 2);
        assert_eq!(back.publishes()[1].output().get(), 5);
        // 公開の無い旧形式（#3067 の形）はそのまま読め、公開は空。
        let old = MemberRecord::decode(base.as_bytes()).unwrap();
        assert_eq!((old.table_handle(), old.publishes().len()), (None, 0));
    }

    /// NET-3・REPAIR-1・#3068: 解除の意図の印は ` unpublishing` として符号化され往復し、他の公開に波及しない。
    #[test]
    fn net3_3068_member_unpublishing_mark_roundtrip() {
        let m = with_two()
            .with_unpublishing(&publish(PortProtocol::Udp, 5353, 80))
            .unwrap();
        let base = String::from_utf8(member(&[]).encode()).unwrap();
        let expected = format!(
            "{base}table-handle 2\n42\npublish 26\ntcp 192.0.2.10:8080 80 2 3\npublish 39\nudp 192.0.2.10:5353 80 4 5 unpublishing\n"
        );
        assert_eq!(m.encode(), expected.as_bytes());
        let back = MemberRecord::decode(&m.encode()).unwrap();
        assert_eq!(back, m);
        assert!(back.is_unpublishing(&publish(PortProtocol::Udp, 5353, 80)));
        assert!(!back.is_unpublishing(&publish(PortProtocol::Tcp, 8080, 80)));
        let none = member(&[]);
        assert!(
            none.with_unpublishing(&publish(PortProtocol::Tcp, 1, 80))
                .is_err()
        );
    }

    /// NET-3・REPAIR-2・#3068: 公開まわりの不正な記録はすべて `DataLoss`。
    #[test]
    fn net3_3068_member_publish_decode_rejects_malformed() {
        let base = String::from_utf8(member(&[]).encode()).unwrap();
        let line = "publish 26\ntcp 192.0.2.10:8080 80 2 3\n";
        let line2 = "publish 26\nudp 192.0.2.10:5353 80 4 5\n";
        let mut cases: Vec<String> = vec![
            // table-handle だけ / publish だけ
            format!("{base}table-handle 2\n42\n"),
            format!("{base}{line}"),
            // 受け口の重複・rule handle の重複
            format!("{base}table-handle 2\n42\n{line}{line}"),
            format!("{base}table-handle 2\n42\n{line}publish 26\ntcp 192.0.2.10:8081 80 3 9\n"),
            // 非正準形・未知の protocol・handle 0・ポート 0
            format!("{base}table-handle 2\n42\npublish 27\ntcp 192.0.2.10:08080 80 2 3\n"),
            format!("{base}table-handle 2\n42\npublish 26\nsctp 192.0.2.10:8080 80 2 3\n"),
            format!("{base}table-handle 2\n42\npublish 26\ntcp 192.0.2.10:8080 80 0 3\n"),
            format!("{base}table-handle 2\n42\npublish 25\ntcp 192.0.2.10:0 80 2 3\n"),
            format!("{base}table-handle 2\n42\npublish 25\ntcp 192.0.2.10:8080 80 2\n"),
            format!("{base}table-handle 2\n42\npublish 28\ntcp 192.0.2.10:8080 80 2 3 \n"),
            // table-handle: 0・先頭 0・範囲外
            format!("{base}table-handle 1\n0\n{line}"),
            format!("{base}table-handle 3\n042\n{line}"),
            format!("{base}table-handle 20\n18446744073709551616\n{line}"),
            // 並び順（publish が table-handle より前、dns より前）
            format!("{base}{line}table-handle 2\n42\n"),
            format!("{base}table-handle 2\n42\n{line}dns 7\n1.1.1.1\n"),
            format!("{base}table-handle 2\n42\npublish 26\ntcp 127.0.0.1:8080 80 2 3\n"),
        ];
        // 65 件
        let mut many = format!("{base}table-handle 2\n42\n");
        for i in 0..65u64 {
            let v = format!("tcp 192.0.2.10:{} 80 {} {}", 1000 + i, 2 * i + 1, 2 * i + 2);
            many.push_str(&format!("publish {}\n{v}\n", v.len()));
        }
        cases.push(many);
        cases.push(format!("{base}table-handle 2\n42\n{line2}{line2}"));
        for c in &cases {
            assert_eq!(
                code(MemberRecord::decode(c.as_bytes())),
                NetErrorCode::DataLoss,
                "{c:?}"
            );
        }
    }

    /// NET-3・#3068: `with_publishes` の拒否と `without_publish`・`published_ports`。
    #[test]
    fn net3_3068_member_with_publishes_validation_and_removal() {
        let bad: Vec<Vec<RecordedPublish>> = vec![
            vec![
                rp(PortProtocol::Tcp, 8080, 2, 3),
                rp(PortProtocol::Tcp, 8080, 4, 5),
            ],
            vec![
                rp(PortProtocol::Tcp, 8080, 2, 3),
                rp(PortProtocol::Tcp, 8081, 3, 9),
            ],
            vec![rp(PortProtocol::Tcp, 8080, 2, 2)],
            (0..65u64)
                .map(|i| rp(PortProtocol::Tcp, 1000 + i as u16, 2 * i + 1, 2 * i + 2))
                .collect(),
        ];
        for b in bad {
            assert_eq!(
                code(member(&[]).with_publishes(th(42), b)),
                NetErrorCode::InvalidArgument
            );
        }
        // 空の公開は table-handle も載せない。
        assert_eq!(
            member(&[]).with_publishes(th(42), Vec::new()).unwrap(),
            member(&[])
        );
        // 1 件外すと table-handle は残り、最後の 1 件を外すと消える。
        let m = with_two();
        let one = m
            .without_publish(&publish(PortProtocol::Tcp, 8080, 80))
            .unwrap();
        assert_eq!(one.publishes().len(), 1);
        assert_eq!(one.table_handle().map(NftTableHandle::get), Some(42));
        let none = one
            .without_publish(&publish(PortProtocol::Udp, 5353, 80))
            .unwrap();
        assert_eq!((none.table_handle(), none.publishes().len()), (None, 0));
        assert_eq!(none, member(&[]));
        assert_eq!(
            code(none.without_publish(&publish(PortProtocol::Udp, 5353, 80))),
            NetErrorCode::NotFound
        );
    }

    /// REPAIR-12・#3068: 最悪値（token 256・netns-dir 1024・dns 3・公開 64 件・u64 最大の handle）でも
    /// `RECORD_MAX_BYTES` に収まり、往復できる。
    #[test]
    fn net3_3068_member_worst_case_fits_record_limit() {
        let ep = "e".repeat(40);
        let head = format!("/ep/{ep}/g/{}", "0".repeat(32));
        let token = format!("{}{head}", "t".repeat(256 - head.len()));
        assert_eq!(token.len(), 256);
        let dir = format!("/{}", "d".repeat(1023));
        let dns: Vec<IpAddr> = ["255.255.255.254", "223.255.255.254", "198.51.100.254"]
            .iter()
            .map(|s| s.parse().unwrap())
            .collect();
        let publishes: Vec<RecordedPublish> = (0..64u64)
            .map(|i| {
                RecordedPublish::new(
                    PortPublish::new(
                        PortProtocol::Udp,
                        Ipv4Addr::new(223, 255, 255, 254),
                        65535 - i as u16,
                        65535,
                    )
                    .unwrap(),
                    NftRuleHandle::new(u64::MAX - 2 * i).unwrap(),
                    NftRuleHandle::new(u64::MAX - 2 * i - 1).unwrap(),
                )
            })
            .collect();
        let m = MemberRecord::new(
            MemberId::new(&"m".repeat(255)).unwrap(),
            EndpointId::new(&ep).unwrap(),
            pfx([10, 0, 0, 2], 24),
            &token,
            Path::new(&dir),
            (u64::MAX, u64::MAX),
            &dns,
        )
        .unwrap()
        .with_publishes(th(u64::MAX), publishes)
        .unwrap();
        let bytes = m.encode();
        assert!(
            bytes.len() <= RECORD_MAX_BYTES,
            "{} > {RECORD_MAX_BYTES}",
            bytes.len()
        );
        assert_eq!(MemberRecord::decode(&bytes).unwrap(), m);
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
