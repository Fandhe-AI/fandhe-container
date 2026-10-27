//! 公開の前にカーネルの `fandhe_net_*` テーブルの DNAT を dump して受け口の衝突を検出する
//! （NET-3・NET-1・#3063。設計は `docs/design/network-wiring.md` の D11「ポート予約」の行）。
//!
//! # 役割と呼び出し元
//!
//! [`PortRegistry`](super::publish::PortRegistry) はプロセス内か、状態ルートごとの共有ファイルでしか
//! 受け口を管理できない。別の状態ルート（CLI と plugin-cri の `.cri`、別の `--root`）が公開済みの受け口とは
//! 衝突を検出できず、nft は同じ受け口の DNAT を重複して投入しても拒否しないため、後から入れた公開が
//! 黙って機能しなくなる。本モジュールは**カーネルを正**として、公開の前に全 `fandhe_net_*` テーブルの
//! DNAT ルールを dump し、これから公開する受け口と照合する多層防御である。
//!
//! 呼び出し元は `network::publish_ports_with`（attach 後の公開 `publish_container_ports`）と
//! `network::attach_with_source`（attach 時の公開。`AttachOps::published_listeners` 経由）で、いずれも
//! `PortRegistry::reserve` の前に呼ぶ。衝突しても何も投入せず、予約にも触れない。
//!
//! # 手順（`scan_with`。OS 非依存でカーネル操作は呼び出し側が渡す）
//!
//! 1. `NFT_MSG_GETTABLE` の dump（ipv4）でテーブル名を集め、接頭辞 `fandhe_net_` のものだけを残す
//! 2. 残した各テーブルについて `NFT_MSG_GETRULE` の dump（`NFTA_RULE_TABLE` で絞り込み）を取る。family 全体を
//!    1 回で取らないのは、docker・kube-proxy 等の無関係なルールまで件数上限に数えて公開が fail-closed に
//!    なるのを避けるため
//! 3. ルールごとに DNAT の受け口 `(proto, daddr, dport)` を認識し、集合にして返す
//!
//! # 信頼境界・上限（REPAIR-5）
//!
//! カーネル応答は外部入力。復号は件数と深さの上限つき（`NftRuleExprs::decode`）で、応答の総量は
//! `MAX_REPLY_BYTES` / `MAX_REPLY_MESSAGES` に収まる。加えて次を超えたら `ResourceExhausted`
//! （fail-closed）で打ち切る。値は暫定の方針値（REPAIR-3）で、D10 の「状態ルートあたり 256 ネットワーク」
//! に複数ルート分の余裕を見た。実測で足りなければ見直す。
//!
//! - [`MAX_DUMP_TABLES`] は GETTABLE dump で受け取る ipv4 テーブルの総数
//! - [`MAX_FANDHE_TABLES`] は接頭辞が一致したテーブル数
//! - [`MAX_DUMP_RULES`] は全 `fandhe_net_*` テーブルのルール総数（1 公開あたり 2 ルール）
//!
//! 期限は呼び出し側の `Deadline` で dump 全体を覆い、超えたら `Timeout`。dump 中の変更
//! （`NLM_F_DUMP_INTR`）は `FailedPrecondition` で返し、再試行はしない（公開は fail-closed）。
//! エラーメッセージにアドレス・ポート・テーブル名は載せない。
//!
//! # DNAT の認識
//!
//! `NatFlags::from_bits` は `MAP_IPS` / `PROTO_SPECIFIED` を拒否するが、カーネルの `nft_nat_init` は
//! アドレス・ポートのレジスタがあるとこの 2 ビットを `flags` に立て、`nft_nat_dump` が
//! `NFTA_NAT_FLAGS` として返す。`NftNat::from_expr`（投入側の検証）は通さず、expr 名と `NFTA_NAT_TYPE` を
//! 直接読む（投入側の検証は緩めない）。
//! `fandhe_net_*` テーブル内の DNAT ルールで、自分が投入する形（`PortPublish::dnat_rule_exprs`）の
//! 3 組（`ip daddr`・`ip protocol`・`th dport` の payload → cmp eq）を過不足なく取り出せないものは、そのテーブルの
//! 受け口を確定できないため `FailedPrecondition` で fail-closed にする。DNAT を含まないルール
//! （masquerade 等）は無視する。チェインは問わない（`prerouting` と `output` に同じ受け口が入る）。
//!
//! # 未実装範囲（REPAIR-3。D11 の全体を満たしてはいない）
//!
//! - 状態ルートに依らない共有ロック（照会から投入までを排他する）と、投入後にもう一度 dump して自分の
//!   受け口が複数あれば自分のルールを消す事後確認は**未実装**。このため、照会から投入までの間に別の
//!   `--root` が割り込むと二重に投入できる窓（TOCTOU）が残る。専用グループの用意と特権ランチャーの
//!   構成が前提で、担当は #3191
//! - 照合の対象は ipv4 family の `fandhe_net_*` テーブルのみ（本 crate が作るテーブルはすべて ipv4）
//! - 再起動後に手放したハンドルは復元しない（#3068）。残ったルールは本物の衝突として扱う

use std::collections::HashSet;
use std::net::Ipv4Addr;

use super::TABLE_PREFIX;
use super::publish::{PortProtocol, PortPublish};
use crate::error::{NetError, NetErrorCode};
use crate::nftables_batch::NftName;
use crate::nftables_rules::{
    DumpedRule, NFT_NAT_DNAT, NFT_NAT_SNAT, NFTA_NAT_TYPE, NftCmp, NftCmpOp, NftExpr, NftPayload,
    NftRuleExprs, PayloadBase,
};

/// GETTABLE dump で受け取る ipv4 テーブルの総数の上限。
pub const MAX_DUMP_TABLES: usize = 4096;
/// 接頭辞 `fandhe_net_` が一致したテーブル数の上限。
pub const MAX_FANDHE_TABLES: usize = 1024;
/// 全 `fandhe_net_*` テーブルのルール総数の上限。
pub const MAX_DUMP_RULES: usize = 65_536;

const NAT_EXPR: &str = "nat";
const PAYLOAD_EXPR: &str = "payload";
const CMP_EXPR: &str = "cmp";

/// カーネルの DNAT ルールから読み取った公開済みの受け口 1 件。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PublishedListener {
    protocol: PortProtocol,
    host_addr: Ipv4Addr,
    host_port: u16,
}

impl PublishedListener {
    /// プロトコル。
    pub fn protocol(&self) -> PortProtocol {
        self.protocol
    }

    /// host 側のアドレス。
    pub fn host_addr(&self) -> Ipv4Addr {
        self.host_addr
    }

    /// host 側のポート。
    pub fn host_port(&self) -> u16 {
        self.host_port
    }
}

/// カーネル上の全 `fandhe_net_*` テーブルが公開済みの受け口の集合（重複なし）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PublishedListeners {
    listeners: Vec<PublishedListener>,
}

impl PublishedListeners {
    /// 受け口の一覧（順序は保証しない）。
    pub fn listeners(&self) -> &[PublishedListener] {
        &self.listeners
    }

    /// 受け口の件数。
    pub fn len(&self) -> usize {
        self.listeners.len()
    }

    /// 受け口が 0 件か。
    pub fn is_empty(&self) -> bool {
        self.listeners.is_empty()
    }

    /// 指定した受け口が公開済みのカーネルを模した集合を作る（他モジュールの単体試験用）。
    #[cfg(test)]
    pub(crate) fn from_ports_for_test(ports: &[PortPublish]) -> Self {
        Self {
            listeners: ports
                .iter()
                .map(|p| PublishedListener {
                    protocol: p.protocol(),
                    host_addr: p.host_addr(),
                    host_port: p.host_port(),
                })
                .collect(),
        }
    }

    /// `port` と同じ受け口（プロトコル・アドレス・ポート）が公開済みか。
    pub fn contains(&self, port: &PortPublish) -> bool {
        self.listeners.iter().any(|l| {
            l.protocol == port.protocol()
                && l.host_addr == port.host_addr()
                && l.host_port == port.host_port()
        })
    }
}

/// これから公開する `ports` の受け口が、カーネル上で公開済みの `published` と衝突しないことを確かめる。
/// 1 件でも一致すれば `AlreadyExists`（メッセージは固定で、値は載せない）。
pub(crate) fn ensure_no_listener_conflict(
    published: &PublishedListeners,
    ports: &[PortPublish],
) -> Result<(), NetError> {
    if ports.iter().any(|p| published.contains(p)) {
        return Err(NetError::new(
            NetErrorCode::AlreadyExists,
            "port listener is already published by a fandhe_net table in the kernel",
        ));
    }
    Ok(())
}

fn unrecognized() -> NetError {
    NetError::new(
        NetErrorCode::FailedPrecondition,
        "unrecognized DNAT rule in a fandhe_net table",
    )
}

/// `nat` expr の変換種別を `NFTA_NAT_TYPE` から直接読む。DNAT なら真、SNAT なら偽、読めない・未知なら
/// `FailedPrecondition`。`NFTA_NAT_FLAGS` はカーネルが `MAP_IPS | PROTO_SPECIFIED` を立てて返すため読まない。
fn is_dnat(expr: &NftExpr) -> Result<bool, NetError> {
    let ty = expr
        .data()
        .iter()
        .find(|a| a.attr_type() == NFTA_NAT_TYPE)
        .and_then(|a| a.as_u32_be())
        .ok_or_else(unrecognized)?;
    match ty {
        NFT_NAT_DNAT => Ok(true),
        NFT_NAT_SNAT => Ok(false),
        _ => Err(unrecognized()),
    }
}

/// 同じ項目を 2 回読んだら認識失敗にして 1 件目を保持する。
fn set_once<T>(slot: &mut Option<T>, value: T) -> Result<(), NetError> {
    if slot.is_some() {
        return Err(unrecognized());
    }
    *slot = Some(value);
    Ok(())
}

/// 1 ルールの expr 列から DNAT の受け口を認識する。
///
/// DNAT を含まなければ `Ok(None)`。含むのに受け口の 3 組を過不足なく取り出せなければ
/// `FailedPrecondition`（モジュール doc「DNAT の認識」）。
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn recognize_dnat_listener(
    exprs: &NftRuleExprs,
) -> Result<Option<PublishedListener>, NetError> {
    let mut has_dnat = false;
    for e in exprs.exprs() {
        if e.name().as_str() == NAT_EXPR && is_dnat(e)? {
            has_dnat = true;
        }
    }
    if !has_dnat {
        return Ok(None);
    }
    let mut loaded: Option<NftPayload> = None;
    let mut daddr: Option<Ipv4Addr> = None;
    let mut proto: Option<u8> = None;
    let mut dport: Option<u16> = None;
    for e in exprs.exprs() {
        match e.name().as_str() {
            PAYLOAD_EXPR => loaded = Some(NftPayload::from_expr(e).map_err(|_| unrecognized())?),
            CMP_EXPR => {
                let cmp = NftCmp::from_expr(e).map_err(|_| unrecognized())?;
                let Some(p) = loaded.filter(|p| p.dreg().wire_value() == cmp.sreg().wire_value())
                else {
                    continue;
                };
                let field = (p.base(), p.offset(), p.byte_len());
                let is_listener_field = matches!(
                    field,
                    (PayloadBase::Network, 16, 4)
                        | (PayloadBase::Network, 9, 1)
                        | (PayloadBase::Transport, 2, 2)
                );
                if !is_listener_field {
                    continue;
                }
                if cmp.op() != NftCmpOp::Eq {
                    return Err(unrecognized());
                }
                let data = cmp.data().as_bytes();
                match field {
                    (PayloadBase::Network, 16, 4) => {
                        let o = <[u8; 4]>::try_from(data).map_err(|_| unrecognized())?;
                        set_once(&mut daddr, Ipv4Addr::from(o))?;
                    }
                    (PayloadBase::Network, 9, 1) => match data {
                        [n] => set_once(&mut proto, *n)?,
                        _ => return Err(unrecognized()),
                    },
                    _ => {
                        let o = <[u8; 2]>::try_from(data).map_err(|_| unrecognized())?;
                        set_once(&mut dport, u16::from_be_bytes(o))?;
                    }
                }
            }
            _ => {}
        }
    }
    let (Some(host_addr), Some(proto), Some(host_port)) = (daddr, proto, dport) else {
        return Err(unrecognized());
    };
    let protocol = match proto {
        6 => PortProtocol::Tcp,
        17 => PortProtocol::Udp,
        _ => return Err(unrecognized()),
    };
    if host_port == 0 {
        return Err(unrecognized());
    }
    Ok(Some(PublishedListener {
        protocol,
        host_addr,
        host_port,
    }))
}

fn exhausted(msg: &'static str) -> NetError {
    NetError::new(NetErrorCode::ResourceExhausted, msg)
}

fn timed_out() -> NetError {
    NetError::new(
        NetErrorCode::Timeout,
        "listener dump deadline passed before the scan finished",
    )
}

/// 全 `fandhe_net_*` テーブルの DNAT を dump して受け口の集合を作る本体（OS 非依存）。
///
/// `list_tables` は ipv4 のテーブル名の一覧、`dump_rules` は 1 テーブルの全ルールを返す。`expired` は
/// 全体の期限が過ぎたかで、各 dump の前後で確認し、過ぎていれば `Timeout`（REPAIR-5）。
/// 上限（[`MAX_DUMP_TABLES`]・[`MAX_FANDHE_TABLES`]・[`MAX_DUMP_RULES`]）を超えたら
/// `ResourceExhausted` で打ち切る。接頭辞が一致しないテーブルには dump を送らない。
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn scan_with(
    list_tables: impl FnOnce() -> Result<Vec<NftName>, NetError>,
    mut dump_rules: impl FnMut(&NftName) -> Result<Vec<DumpedRule>, NetError>,
    expired: impl Fn() -> bool,
) -> Result<PublishedListeners, NetError> {
    let tables = list_tables()?;
    if expired() {
        return Err(timed_out());
    }
    if tables.len() > MAX_DUMP_TABLES {
        return Err(exhausted("too many nftables tables in the ipv4 family"));
    }
    let ours: Vec<&NftName> = tables
        .iter()
        .filter(|t| t.as_str().starts_with(TABLE_PREFIX))
        .collect();
    if ours.len() > MAX_FANDHE_TABLES {
        return Err(exhausted("too many fandhe_net tables"));
    }
    let mut seen: HashSet<PublishedListener> = HashSet::new();
    let mut found = Vec::new();
    let mut total_rules = 0usize;
    for table in ours {
        if expired() {
            return Err(timed_out());
        }
        let rules = dump_rules(table)?;
        total_rules = total_rules.saturating_add(rules.len());
        if total_rules > MAX_DUMP_RULES {
            return Err(exhausted("too many rules in fandhe_net tables"));
        }
        for rule in &rules {
            if let Some(l) = recognize_dnat_listener(rule.exprs())?
                && seen.insert(l)
            {
                found.push(l);
            }
        }
    }
    if expired() {
        return Err(timed_out());
    }
    Ok(PublishedListeners { listeners: found })
}

/// 全 `fandhe_net_*` テーブルの DNAT を dump して受け口の集合を返す（Linux。読み取り専用）。
///
/// `CAP_NET_ADMIN` が必要で、本 crate は権限を上げない。`deadline` は dump 全体（テーブル一覧と全テーブルの
/// ルール）を覆う。
#[cfg(target_os = "linux")]
pub(crate) fn scan_published_listeners(
    nft: &crate::nftables_batch::NetlinkNetfilterSocket,
    deadline: &crate::sys::Deadline,
) -> Result<PublishedListeners, NetError> {
    use crate::nftables_batch::NftFamily;
    use crate::nftables_rules::RuleDump;
    scan_with(
        || nft.dump_table_names(NftFamily::Ipv4, deadline.remaining()),
        |table| {
            nft.dump_rules(
                &RuleDump::new(NftFamily::Ipv4, table.clone()),
                deadline.remaining(),
            )
        },
        || deadline.remaining().is_zero(),
    )
}

/// 全 `fandhe_net_*` テーブルの DNAT を dump して、公開済みの受け口の集合を返す（Linux。読み取り専用。
/// NET-3・#3063）。`timeout` は dump 全体の期限。上限・失敗の扱いはモジュール doc のとおり。
#[cfg(target_os = "linux")]
pub fn published_dnat_listeners(
    nft: &crate::nftables_batch::NetlinkNetfilterSocket,
    timeout: std::time::Duration,
) -> Result<PublishedListeners, NetError> {
    scan_published_listeners(nft, &crate::sys::Deadline::after(timeout))
}

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};

    use super::*;
    use crate::netlink::NlMsgBuilder;
    use crate::nftables_batch::{NFGENMSG_LEN, NfGenMsg, NftFamily};
    use crate::nftables_rules::{
        NFTA_NAT_FAMILY, NFTA_NAT_FLAGS, NFTA_NAT_REG_ADDR_MIN, NFTA_NAT_REG_PROTO_MIN,
        NFTA_RULE_CHAIN, NFTA_RULE_TABLE, NftDataValue, NftExprAttr, NftExprName, NftImmediate,
        NftMasq, NftNat, NftRegister,
    };

    fn name(s: &str) -> NftName {
        NftName::new(s).expect("name")
    }

    fn port(proto: PortProtocol, addr: [u8; 4], host: u16) -> PortPublish {
        PortPublish::new(proto, Ipv4Addr::from(addr), host, 80).expect("port")
    }

    /// 自分が投入する形の expr 列。
    fn ours(p: &PortPublish) -> NftRuleExprs {
        p.dnat_rule_exprs(Ipv4Addr::new(10, 0, 0, 2))
            .expect("exprs")
    }

    /// カーネルが dump で返す形（`nft_nat_init` が立てる `MAP_IPS | PROTO_SPECIFIED` を含む）の DNAT。
    fn kernel_shaped(p: &PortPublish) -> NftRuleExprs {
        let src = ours(p);
        let mut out = NftRuleExprs::new();
        for e in src.exprs() {
            if e.name().as_str() == NAT_EXPR {
                let r1 = NftRegister::REG_1.wire_value();
                let r2 = NftRegister::REG_2.wire_value();
                let nat = NftExpr::new(
                    NftExprName::new(NAT_EXPR).expect("n"),
                    vec![
                        NftExprAttr::u32_be(NFTA_NAT_TYPE, NFT_NAT_DNAT).expect("a"),
                        NftExprAttr::u32_be(NFTA_NAT_FAMILY, 2).expect("a"),
                        NftExprAttr::u32_be(NFTA_NAT_REG_ADDR_MIN, r1).expect("a"),
                        NftExprAttr::u32_be(NFTA_NAT_REG_PROTO_MIN, r2).expect("a"),
                        NftExprAttr::u32_be(NFTA_NAT_FLAGS, 0x3).expect("a"),
                    ],
                )
                .expect("nat");
                out.push(nat).expect("push");
            } else {
                out.push(e.clone()).expect("push");
            }
        }
        out
    }

    /// NEWRULE 応答相当のペイロード。
    fn rule_payload(table: &str, exprs: &NftRuleExprs) -> Vec<u8> {
        let mut b = NlMsgBuilder::new(0x0a06, 0, 1, 0);
        NfGenMsg::new(2, 0).put_into(&mut b).expect("nfgen");
        name(table).put_into(&mut b, NFTA_RULE_TABLE).expect("t");
        name("prerouting")
            .put_into(&mut b, NFTA_RULE_CHAIN)
            .expect("c");
        exprs.put_into(&mut b).expect("exprs");
        let bytes = b.finish().expect("finish");
        let msg = crate::netlink::NlMsgIter::new(&bytes)
            .next()
            .expect("one")
            .expect("msg");
        msg.payload().to_vec()
    }

    fn dumped(table: &str, exprs: &NftRuleExprs) -> DumpedRule {
        DumpedRule::decode(&rule_payload(table, exprs), NftFamily::Ipv4, &name(table))
            .expect("decode")
    }

    /// NET-3: 自分の形の DNAT から受け口を取り出せる（tcp・192.0.2.10:8080）。
    #[test]
    fn net3_recognizes_own_tcp_rule() {
        let p = port(PortProtocol::Tcp, [192, 0, 2, 10], 8080);
        let l = recognize_dnat_listener(&ours(&p))
            .expect("ok")
            .expect("some");
        assert_eq!(l.protocol(), PortProtocol::Tcp);
        assert_eq!(l.host_addr(), Ipv4Addr::new(192, 0, 2, 10));
        assert_eq!(l.host_port(), 8080);
    }

    /// NET-3: udp も認識する。
    #[test]
    fn net3_recognizes_udp_rule() {
        let p = port(PortProtocol::Udp, [198, 51, 100, 7], 5353);
        let l = recognize_dnat_listener(&ours(&p))
            .expect("ok")
            .expect("some");
        assert_eq!(
            (l.protocol(), l.host_addr(), l.host_port()),
            (PortProtocol::Udp, Ipv4Addr::new(198, 51, 100, 7), 5353)
        );
    }

    /// NET-3: カーネルは `NFTA_NAT_FLAGS = MAP_IPS | PROTO_SPECIFIED`（0x3）を返す。
    /// 投入側の `NftNat::from_expr` はこのビットを拒否するが、dump の認識は通す（投入側は緩めない）。
    #[test]
    fn net3_recognizes_kernel_nat_flags() {
        let p = port(PortProtocol::Tcp, [192, 0, 2, 10], 8080);
        let kernel = kernel_shaped(&p);
        let nat = kernel
            .exprs()
            .iter()
            .find(|e| e.name().as_str() == NAT_EXPR)
            .expect("nat");
        assert!(NftNat::from_expr(nat).is_err(), "投入側の検証は緩めない");
        let l = recognize_dnat_listener(&kernel).expect("ok").expect("some");
        assert_eq!(
            (l.protocol(), l.host_addr(), l.host_port()),
            (PortProtocol::Tcp, Ipv4Addr::new(192, 0, 2, 10), 8080)
        );
    }

    /// NET-3: masquerade のみのルールは無視する。
    #[test]
    fn net3_ignores_masquerade_rule() {
        let mut e = NftRuleExprs::new();
        e.push(NftMasq::new().to_expr().expect("m")).expect("push");
        assert_eq!(recognize_dnat_listener(&e).expect("ok"), None);
    }

    /// NET-3: SNAT は DNAT ではないので無視する。
    #[test]
    fn net3_ignores_snat() {
        let mut e = NftRuleExprs::new();
        e.push(
            NftExpr::new(
                NftExprName::new(NAT_EXPR).expect("n"),
                vec![NftExprAttr::u32_be(NFTA_NAT_TYPE, NFT_NAT_SNAT).expect("a")],
            )
            .expect("e"),
        )
        .expect("push");
        assert_eq!(recognize_dnat_listener(&e).expect("ok"), None);
    }

    /// NET-3: DNAT だが dport の組が欠けたルールは fail-closed。
    #[test]
    fn net3_dnat_without_dport_is_failed_precondition() {
        let p = port(PortProtocol::Tcp, [192, 0, 2, 10], 8080);
        let src = ours(&p);
        // dport の payload（index 4）と cmp（index 5）を落とす。
        let mut e = NftRuleExprs::new();
        for (i, x) in src.exprs().iter().enumerate() {
            if i != 4 && i != 5 {
                e.push(x.clone()).expect("push");
            }
        }
        let err = recognize_dnat_listener(&e).expect_err("reject");
        assert_eq!(err.code(), NetErrorCode::FailedPrecondition);
    }

    /// NET-3: 同じ組が 2 回現れるルールは fail-closed。
    #[test]
    fn net3_duplicated_pair_is_failed_precondition() {
        let p = port(PortProtocol::Tcp, [192, 0, 2, 10], 8080);
        let src = ours(&p);
        let mut e = NftRuleExprs::new();
        for x in &src.exprs()[..2] {
            e.push(x.clone()).expect("push");
        }
        for x in src.exprs() {
            e.push(x.clone()).expect("push");
        }
        let err = recognize_dnat_listener(&e).expect_err("reject");
        assert_eq!(err.code(), NetErrorCode::FailedPrecondition);
    }

    /// NET-3: プロトコルが tcp / udp 以外の DNAT は fail-closed。
    #[test]
    fn net3_unknown_protocol_is_failed_precondition() {
        let r1 = NftRegister::REG_1;
        let mut e = NftRuleExprs::new();
        e.push(NftPayload::ipv4_daddr(r1).expect("p").to_expr().expect("e"))
            .expect("push");
        e.push(
            NftCmp::eq(r1, NftDataValue::new(&[192, 0, 2, 10]).expect("d"))
                .expect("c")
                .to_expr()
                .expect("e"),
        )
        .expect("push");
        e.push(
            NftPayload::ipv4_protocol(r1)
                .expect("p")
                .to_expr()
                .expect("e"),
        )
        .expect("push");
        e.push(
            NftCmp::eq(r1, NftDataValue::new(&[1]).expect("d"))
                .expect("c")
                .to_expr()
                .expect("e"),
        )
        .expect("push");
        e.push(
            NftPayload::transport_dport(r1)
                .expect("p")
                .to_expr()
                .expect("e"),
        )
        .expect("push");
        e.push(
            NftCmp::eq(r1, NftDataValue::new(&[0x1f, 0x90]).expect("d"))
                .expect("c")
                .to_expr()
                .expect("e"),
        )
        .expect("push");
        e.push(
            NftImmediate::ipv4_addr(r1, Ipv4Addr::new(10, 0, 0, 2))
                .expect("i")
                .to_expr()
                .expect("e"),
        )
        .expect("push");
        e.push(
            NftNat::dnat_ipv4(r1, None)
                .expect("n")
                .to_expr()
                .expect("e"),
        )
        .expect("push");
        let err = recognize_dnat_listener(&e).expect_err("reject");
        assert_eq!(err.code(), NetErrorCode::FailedPrecondition);
    }

    /// NET-3: 壊れた expr 列を含む応答は `DataLoss`（復号の段階で拒否）。
    #[test]
    fn net3_malformed_rule_payload_is_data_loss() {
        let p = port(PortProtocol::Tcp, [192, 0, 2, 10], 8080);
        let good = rule_payload("fandhe_net_a", &ours(&p));
        for cut in [0, 3, NFGENMSG_LEN, NFGENMSG_LEN + 3, good.len() - 5] {
            let bad = &good[..cut];
            let e = DumpedRule::decode(bad, NftFamily::Ipv4, &name("fandhe_net_a"))
                .expect_err("reject");
            assert_eq!(e.code(), NetErrorCode::DataLoss, "cut {cut}");
        }
        // family 違い・テーブル名の不一致。
        let mut other_family = good.clone();
        other_family[0] = 10;
        assert_eq!(
            DumpedRule::decode(&other_family, NftFamily::Ipv4, &name("fandhe_net_a"))
                .expect_err("family")
                .code(),
            NetErrorCode::DataLoss
        );
        assert_eq!(
            DumpedRule::decode(&good, NftFamily::Ipv4, &name("fandhe_net_b"))
                .expect_err("table")
                .code(),
            NetErrorCode::DataLoss
        );
    }

    /// NET-3: 同じ受け口なら `AlreadyExists`。ポート・アドレス・プロトコルのどれかが違えば通る。
    #[test]
    fn net3_conflict_requires_same_proto_addr_port() {
        let existing = port(PortProtocol::Tcp, [192, 0, 2, 10], 8080);
        let published = PublishedListeners {
            listeners: vec![
                recognize_dnat_listener(&ours(&existing))
                    .expect("ok")
                    .expect("some"),
            ],
        };
        let e = ensure_no_listener_conflict(&published, &[existing]).expect_err("conflict");
        assert_eq!(e.code(), NetErrorCode::AlreadyExists);
        for ok in [
            port(PortProtocol::Tcp, [192, 0, 2, 10], 8081),
            port(PortProtocol::Tcp, [192, 0, 2, 11], 8080),
            port(PortProtocol::Udp, [192, 0, 2, 10], 8080),
        ] {
            ensure_no_listener_conflict(&published, &[ok]).expect("no conflict");
        }
        // 複数件の 2 件目が衝突しても拒否する。
        let both = [port(PortProtocol::Tcp, [192, 0, 2, 10], 9000), existing];
        assert_eq!(
            ensure_no_listener_conflict(&published, &both)
                .expect_err("conflict")
                .code(),
            NetErrorCode::AlreadyExists
        );
        // メッセージに値を載せない。
        assert!(!e.to_string().contains("8080"));
        assert!(!e.to_string().contains("192.0.2"));
    }

    fn tables(names: &[&str]) -> Vec<NftName> {
        names.iter().map(|n| name(n)).collect()
    }

    /// NET-3: `fandhe_net_` 以外のテーブルには dump を送らず、自ネットワーク以外の受け口も集める。
    #[test]
    fn net3_scan_dumps_only_fandhe_tables() {
        let a = port(PortProtocol::Tcp, [192, 0, 2, 10], 8080);
        let b = port(PortProtocol::Udp, [192, 0, 2, 10], 5353);
        let asked = RefCell::new(Vec::new());
        let got = scan_with(
            || Ok(tables(&["filter", "fandhe_net_a", "nat", "fandhe_net_b"])),
            |t| {
                asked.borrow_mut().push(t.as_str().to_owned());
                Ok(match t.as_str() {
                    "fandhe_net_a" => vec![dumped("fandhe_net_a", &kernel_shaped(&a))],
                    // masquerade と、同じ受け口の重複（prerouting / output）。
                    _ => vec![
                        dumped("fandhe_net_b", &kernel_shaped(&b)),
                        dumped("fandhe_net_b", &kernel_shaped(&b)),
                        dumped("fandhe_net_b", &{
                            let mut m = NftRuleExprs::new();
                            m.push(NftMasq::new().to_expr().expect("m")).expect("push");
                            m
                        }),
                    ],
                })
            },
            || false,
        )
        .expect("scan");
        assert_eq!(asked.into_inner(), ["fandhe_net_a", "fandhe_net_b"]);
        assert_eq!(got.len(), 2);
        assert!(got.contains(&a));
        assert!(got.contains(&b));
    }

    /// NET-3・REPAIR-5: テーブル数の上限ちょうどは通り、超えると `ResourceExhausted`。
    #[test]
    fn net3_scan_table_limits() {
        let mk = |n: usize, prefix: &str| -> Vec<NftName> {
            (0..n).map(|i| name(&format!("{prefix}{i}"))).collect()
        };
        let ok = scan_with(
            || Ok(mk(MAX_FANDHE_TABLES, "fandhe_net_t")),
            |_| Ok(Vec::new()),
            || false,
        )
        .expect("at limit");
        assert!(ok.is_empty());
        let e = scan_with(
            || Ok(mk(MAX_FANDHE_TABLES + 1, "fandhe_net_t")),
            |_| Ok(Vec::new()),
            || false,
        )
        .expect_err("over");
        assert_eq!(e.code(), NetErrorCode::ResourceExhausted);
        // 総数の上限（接頭辞が違うものも数える）。
        let called = Cell::new(0);
        let e = scan_with(
            || Ok(mk(MAX_DUMP_TABLES + 1, "other")),
            |_| {
                called.set(called.get() + 1);
                Ok(Vec::new())
            },
            || false,
        )
        .expect_err("over total");
        assert_eq!(e.code(), NetErrorCode::ResourceExhausted);
        assert_eq!(called.get(), 0);
        scan_with(
            || Ok(mk(MAX_DUMP_TABLES, "other")),
            |_| Ok(Vec::new()),
            || false,
        )
        .expect("total at limit");
    }

    /// NET-3・REPAIR-5: ルール総数の上限ちょうどは通り、超えると `ResourceExhausted`。
    #[test]
    fn net3_scan_rule_limit() {
        let masq = {
            let mut m = NftRuleExprs::new();
            m.push(NftMasq::new().to_expr().expect("m")).expect("push");
            m
        };
        let rules = |n: usize| -> Vec<DumpedRule> {
            (0..n).map(|_| dumped("fandhe_net_a", &masq)).collect()
        };
        scan_with(
            || Ok(tables(&["fandhe_net_a"])),
            |_| Ok(rules(MAX_DUMP_RULES)),
            || false,
        )
        .expect("at limit");
        let e = scan_with(
            || Ok(tables(&["fandhe_net_a"])),
            |_| Ok(rules(MAX_DUMP_RULES + 1)),
            || false,
        )
        .expect_err("over");
        assert_eq!(e.code(), NetErrorCode::ResourceExhausted);
        // 複数テーブルの合計で超える場合。
        let e = scan_with(
            || Ok(tables(&["fandhe_net_a", "fandhe_net_b"])),
            |_| Ok(rules(MAX_DUMP_RULES / 2 + 1)),
            || false,
        )
        .expect_err("sum over");
        assert_eq!(e.code(), NetErrorCode::ResourceExhausted);
    }

    /// NET-3・REPAIR-5: 途中で期限が切れたら `Timeout`。
    #[test]
    fn net3_scan_deadline_expiry_is_timeout() {
        let polls = Cell::new(0);
        let e = scan_with(
            || Ok(tables(&["fandhe_net_a", "fandhe_net_b"])),
            |_| Ok(Vec::new()),
            || {
                polls.set(polls.get() + 1);
                // テーブル一覧の後・1 テーブル目の前は未経過、2 テーブル目の前で経過。
                polls.get() >= 3
            },
        )
        .expect_err("expired");
        assert_eq!(e.code(), NetErrorCode::Timeout);
        let e = scan_with(
            || Ok(tables(&["fandhe_net_a"])),
            |_| Ok(Vec::new()),
            || true,
        )
        .expect_err("expired at once");
        assert_eq!(e.code(), NetErrorCode::Timeout);
    }

    /// NET-3: dump の失敗（`NLM_F_DUMP_INTR` 相当の `FailedPrecondition`）はそのまま返す。
    #[test]
    fn net3_scan_propagates_dump_errors() {
        let e = scan_with(
            || Ok(tables(&["fandhe_net_a"])),
            |_| {
                Err(NetError::new(
                    NetErrorCode::FailedPrecondition,
                    "netlink dump was interrupted",
                ))
            },
            || false,
        )
        .expect_err("interrupted");
        assert_eq!(e.code(), NetErrorCode::FailedPrecondition);
        let e = scan_with(
            || Err(NetError::new(NetErrorCode::PermissionDenied, "denied")),
            |_| Ok(Vec::new()),
            || false,
        )
        .expect_err("denied");
        assert_eq!(e.code(), NetErrorCode::PermissionDenied);
    }
}
