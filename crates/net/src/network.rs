//! ユーザー定義ネットワークの作成処理（bridge・専用 nft テーブル。TASK-139.1・#314・NET-1・MS-8）。
//!
//! ネットワーク名から bridge 名と nft テーブル名を決定的に導出し、bridge の作成 → gateway アドレス付与 →
//! up → 専用 nft テーブルと NAT base chain の作成までを 1 つの操作として行い、途中で失敗したら
//! 自分が作ったリソースだけをロールバックする。`netlink_route`（bridge・address・link 削除）と
//! `nftables_batch`（table・chain）の上に載る統合層で、PoC-15 `netsetup` の `net-create` に相当する。
//! 後続のネットワーク削除（TASK-139.4）は [`NetworkResourceNames::derive`] で同じ名前を再導出して使う。
//!
//! # 命名（ワイヤー契約と同じ扱い）
//!
//! - nft テーブル名: `fandhe_net_<name>`（`NetworkName` の文字種は `NftName` の部分集合で、単射）
//! - bridge 名: `fcbr` + FNV-1a 64bit の下位 44bit を小文字 hex 11 桁（合計 15 バイト = `IFNAMSIZ` 未満）
//!
//! プレフィックス・ハッシュ関数・桁数を変えると既存ネットワークの名前が変わり、削除や再作成で
//! 残骸を取り残すため、変更は互換性を壊す変更として扱う。`DefaultHasher` は Rust の版をまたいで
//! 値が安定しないので使わない。
//!
//! # 衝突検出
//!
//! 作成は bridge に `NLM_F_EXCL`、table に `exclusive` を付けるため、ハッシュ衝突も前回の削除漏れ
//! （残骸）も `AlreadyExists` として検出される。`AlreadyExists` のリソースは自分が作ったものではない
//! ので削除しない。名前が違うのに導出名が一致するネットワーク同士は
//! [`NetworkResourceNames::conflicts_with`] で事前に検出できる。
//!
//! # ロールバック
//!
//! bridge は作成時に `IFLA_IFALIAS` へ作成ごとに一意な所有トークンを付け、名前から ifindex を引く際に
//! トークン一致を確認する。不一致（同名 link への差し替え）なら操作も削除もしない。bridge 作成要求が
//! 送信後の応答エラー（`ResourceExhausted` 等）で失敗した場合は作成済みの可能性があるため
//! `ResourceState::Unknown` で報告する（確定的な拒否のみ空報告）。
//! 自分が作ったと確定した bridge のみ削除する（address は bridge と一緒に消える）。作成結果が
//! 不明（`Timeout` / `DataLoss`）なリソースは fail-closed で削除せず、[`RollbackReport::leftover`]
//! に `ResourceState::Unknown` として報告する。nft バッチは all-or-nothing なので `Aborted` /
//! `NotSent` では nft 側に何も残らない。
//!
//! # 未実装範囲（REPAIR-3）
//!
//! - masquerade ルール本体（`bitwise` / `meta` expr が `nftables_rules` に未実装のため `postrouting`
//!   チェインは空。条件なし masq は host の全外向き通信を SNAT するため入れない）。TASK-139.3
//! - netns・veth・IPAM・default route（TASK-139.2 以降）、ネットワーク削除（TASK-139.4）
//! - IPv6 と `NftFamily::Inet`（IPv4 のみ。静的 IPAM が IPv4 のみのため）

use std::fmt;
#[cfg(target_os = "linux")]
use std::time::Duration;

use crate::error::{NetError, NetErrorCode};
#[cfg(target_os = "linux")]
use crate::netlink_route::{
    AddrScope, AddressSpec, LinkCreate, LinkDelete, LinkIndex, LinkRef, LinkSet, NetlinkRouteSocket,
};
use crate::netlink_route::{IfIndex, IfName, IpPrefix};
#[cfg(target_os = "linux")]
use crate::nftables_batch::{
    BaseChain, ChainCreate, ChainType, NF_IP_PRI_NAT_DST, NF_IP_PRI_NAT_SRC,
    NetlinkNetfilterSocket, NfInetHook, NftFamily, TableCreate,
};
use crate::nftables_batch::{NftBatchOutcome, NftName};

/// bridge 名のプレフィックス。
const BRIDGE_PREFIX: &str = "fcbr";
/// nft テーブル名のプレフィックス。
const TABLE_PREFIX: &str = "fandhe_net_";
/// ネットワーク名の最大長（バイト）。
const NAME_MAX_LEN: usize = 64;
/// FNV-1a 64bit の offset basis。
const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
/// FNV-1a 64bit の prime。
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

fn invalid(msg: &'static str) -> NetError {
    NetError::new(NetErrorCode::InvalidArgument, msg)
}

/// 検証済みのネットワーク名（REPAIR-2）。1〜64 バイト、先頭 `[a-z0-9]`、以降 `[a-z0-9_.-]`。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NetworkName(String);

impl NetworkName {
    /// 検証して作る。違反は `InvalidArgument`（入力値はメッセージに載せない）。
    pub fn new(name: &str) -> Result<Self, NetError> {
        if name.is_empty() || name.len() > NAME_MAX_LEN {
            return Err(invalid("network name length must be 1 to 64 bytes"));
        }
        let mut bytes = name.bytes();
        let first_ok = bytes
            .next()
            .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit());
        let rest_ok = bytes.all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'_' | b'.' | b'-')
        });
        if !first_ok || !rest_ok {
            return Err(invalid("network name contains invalid characters"));
        }
        Ok(Self(name.to_owned()))
    }

    /// 名前を返す。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// FNV-1a 64bit。
fn fnv1a64(data: &[u8]) -> u64 {
    data.iter().fold(FNV_OFFSET, |h, &b| {
        (h ^ u64::from(b)).wrapping_mul(FNV_PRIME)
    })
}

/// ネットワーク名から導出したリソース名。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkResourceNames {
    network: NetworkName,
    bridge: IfName,
    table: NftName,
}

/// 導出名の衝突種別。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum NameConflict {
    /// bridge 名が一致した。
    Bridge,
    /// nft テーブル名が一致した。
    Table,
}

impl NetworkResourceNames {
    /// 決定的に導出する。
    pub fn derive(network: &NetworkName) -> Result<Self, NetError> {
        let hash = fnv1a64(network.as_str().as_bytes()) & ((1u64 << 44) - 1);
        let bridge = IfName::new(&format!("{BRIDGE_PREFIX}{hash:011x}"))?;
        let table = NftName::new(&format!("{TABLE_PREFIX}{}", network.as_str()))?;
        Ok(Self {
            network: network.clone(),
            bridge,
            table,
        })
    }

    /// ネットワーク名。
    pub fn network(&self) -> &NetworkName {
        &self.network
    }

    /// bridge 名。
    pub fn bridge(&self) -> &IfName {
        &self.bridge
    }

    /// nft テーブル名。
    pub fn table(&self) -> &NftName {
        &self.table
    }

    /// 別ネットワークと導出名が衝突するか。同じネットワーク名どうしは衝突扱いにしない。
    pub fn conflicts_with(&self, other: &Self) -> Option<NameConflict> {
        if self.network == other.network {
            return None;
        }
        if self.bridge == other.bridge {
            Some(NameConflict::Bridge)
        } else if self.table == other.table {
            Some(NameConflict::Table)
        } else {
            None
        }
    }

    /// 既存ネットワーク群の中から `candidate` と衝突するものを探す（状態レジストリからの利用を想定）。
    pub fn find_conflict<'a>(
        existing: impl IntoIterator<Item = &'a Self>,
        candidate: &Self,
    ) -> Option<NameConflict> {
        existing
            .into_iter()
            .find_map(|e| e.conflicts_with(candidate))
    }
}

/// ネットワーク作成の入力（検証済み）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkCreateSpec {
    name: NetworkName,
    gateway: IpPrefix,
}

impl NetworkCreateSpec {
    /// gateway は IPv4 で prefix 1〜30、ネットワークアドレス・ブロードキャストアドレスは不可。
    /// 違反は `InvalidArgument`（netlink は一切送らない）。
    pub fn new(name: NetworkName, gateway: IpPrefix) -> Result<Self, NetError> {
        let std::net::IpAddr::V4(addr) = gateway.addr() else {
            return Err(invalid("gateway must be an IPv4 address"));
        };
        let len = gateway.prefix_len();
        if !(1..=30).contains(&len) {
            return Err(invalid("gateway prefix length must be 1 to 30"));
        }
        if gateway.is_network() {
            return Err(invalid("gateway must not be the network address"));
        }
        let host_mask = u32::MAX >> len;
        if u32::from(addr) & host_mask == host_mask {
            return Err(invalid("gateway must not be the broadcast address"));
        }
        Ok(Self { name, gateway })
    }

    /// ネットワーク名。
    pub fn name(&self) -> &NetworkName {
        &self.name
    }

    /// gateway（bridge に付与するアドレス）。
    pub fn gateway(&self) -> IpPrefix {
        self.gateway
    }
}

/// 作成に成功したネットワーク。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CreatedNetwork {
    /// ネットワーク名。
    pub name: NetworkName,
    /// bridge 名。
    pub bridge: IfName,
    /// bridge の ifindex。
    pub bridge_index: IfIndex,
    /// 専用 nft テーブル名。
    pub table: NftName,
    /// bridge に付与した gateway。
    pub gateway: IpPrefix,
}

/// 失敗した手順。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CreateStep {
    /// 名前の導出。
    DeriveNames,
    /// bridge 作成。
    CreateBridge,
    /// ifindex の取得。
    ResolveIndex,
    /// gateway アドレスの付与。
    AddAddress,
    /// bridge の up。
    SetUp,
    /// nft テーブル・チェインの作成。
    CreateNftTable,
}

/// ロールバック対象のリソース。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum NetworkResource {
    /// bridge。
    Bridge(IfName),
    /// nft テーブル。
    NftTable(NftName),
}

/// 取り残したリソースの状態。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ResourceState {
    /// 存在することが分かっている（削除に失敗した）。
    Present,
    /// 存在するか不明（作成結果が `Timeout` 等で不明。fail-closed で削除しない）。
    Unknown,
}

/// ロールバックの結果。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct RollbackReport {
    /// 削除に成功したリソース。
    pub removed: Vec<NetworkResource>,
    /// 取り残したリソースとその状態。
    pub leftover: Vec<(NetworkResource, ResourceState)>,
}

/// ネットワーク作成の失敗（元のエラー・失敗手順・ロールバック結果。ERR-1）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct NetworkCreateError {
    /// 失敗の原因（ロールバック失敗では上書きしない）。
    pub error: NetError,
    /// 失敗した手順。
    pub step: CreateStep,
    /// ロールバックの結果。
    pub rollback: RollbackReport,
}

impl NetworkCreateError {
    /// 機械可読な分類。
    pub fn code(&self) -> NetErrorCode {
        self.error.code()
    }

    /// 英語のメッセージ。
    pub fn message(&self) -> &str {
        self.error.message()
    }
}

impl fmt::Display for NetworkCreateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.error.fmt(f)
    }
}

impl std::error::Error for NetworkCreateError {}

/// nft 適用の失敗（原因と、バッチが適用されたかどうか）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NftApplyFailure {
    pub(crate) error: NetError,
    pub(crate) outcome: NftBatchOutcome,
}

/// 作成手順が使うカーネル操作の境界。Linux 実装とテストの fake を差し替えるための crate 内部トレイトで、
/// 公開の拡張点（PLUG-1）ではない。
pub(crate) trait NetworkOps {
    /// bridge を作り、`IFLA_IFALIAS` に所有トークン `token` を付ける。
    fn create_bridge(&self, name: &IfName, token: &str) -> Result<(), NetError>;
    /// 名前から ifindex を引く。`IFLA_IFALIAS` が `token` と一致しない（同名の別 link に差し替わった）
    /// 場合は `FailedPrecondition` で失敗し、その link を操作させない。
    fn link_index(&self, name: &IfName, token: &str) -> Result<IfIndex, NetError>;
    fn add_address(&self, index: IfIndex, gateway: &IpPrefix) -> Result<(), NetError>;
    /// 取得済みの ifindex で up にする（名前再解決で別 link を操作しない）。
    fn set_up(&self, index: IfIndex) -> Result<(), NetError>;
    /// 取得済みの ifindex で削除する。外部で bridge が消され同名の別 link ができても巻き込まない。
    fn delete_bridge(&self, index: IfIndex) -> Result<(), NetError>;
    fn apply_nft(&self, table: &NftName) -> Result<(), NftApplyFailure>;
}

const COLLISION_MSG: &str =
    "network resources already exist (name collision or stale network; delete it first)";

fn collision_or(e: NetError) -> NetError {
    if e.code() == NetErrorCode::AlreadyExists {
        NetError::new(NetErrorCode::AlreadyExists, COLLISION_MSG)
    } else {
        e
    }
}

/// 作成が不明な結果（時間切れ・応答破損）か。
fn is_indeterminate(code: NetErrorCode) -> bool {
    matches!(code, NetErrorCode::Timeout | NetErrorCode::DataLoss)
}

/// bridge 作成要求がカーネルに拒否された（作成されていない）と確定できる分類か。
/// 送信後の応答エラー（`ResourceExhausted`〔件数・サイズ超過〕・`Internal` 等）は要求が適用済みか
/// 判別できないため、ここに含めず `Unknown` として報告する（fail-closed）。
fn is_definitely_rejected(code: NetErrorCode) -> bool {
    matches!(
        code,
        NetErrorCode::AlreadyExists
            | NetErrorCode::PermissionDenied
            | NetErrorCode::InvalidArgument
            | NetErrorCode::NotFound
            | NetErrorCode::FailedPrecondition
            | NetErrorCode::Unimplemented
    )
}

/// 作成ごとに一意な所有トークン（bridge の `IFLA_IFALIAS` に付ける）。プロセス ID・時刻・連番を含み、
/// 他者が推測して同名 link に付け替えることは想定しない（そもそも `CAP_NET_ADMIN` が必要）。
fn ownership_token(network: &NetworkName) -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    format!(
        "fandhe-net:{}:{}:{nanos:x}:{}",
        network.as_str(),
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    )
}

fn rollback_bridge(
    ops: &impl NetworkOps,
    bridge: &IfName,
    index: IfIndex,
    report: &mut RollbackReport,
) {
    match ops.delete_bridge(index) {
        Ok(()) => report.removed.push(NetworkResource::Bridge(bridge.clone())),
        // Timeout / DataLoss は削除が適用されたか不明なので、Present と断定せず Unknown で報告する。
        Err(e) => {
            let state = if is_indeterminate(e.code()) {
                ResourceState::Unknown
            } else {
                ResourceState::Present
            };
            report
                .leftover
                .push((NetworkResource::Bridge(bridge.clone()), state));
        }
    }
}

/// 作成手順本体（OS 非依存。`ops` を差し替えて 3 OS で単体テストできる）。
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn create_network_with(
    ops: &impl NetworkOps,
    spec: &NetworkCreateSpec,
) -> Result<CreatedNetwork, NetworkCreateError> {
    let fail = |error, step, rollback| NetworkCreateError {
        error,
        step,
        rollback,
    };
    let names = NetworkResourceNames::derive(spec.name())
        .map_err(|e| fail(e, CreateStep::DeriveNames, RollbackReport::default()))?;
    let bridge = names.bridge().clone();
    let table = names.table().clone();

    // 1. bridge 作成（所有トークン付き）。AlreadyExists は他者のリソースなので削除しない。
    // 確定的な拒否以外（送信後の応答エラー等）は作成済みの可能性があるため Unknown で報告する。
    let token = ownership_token(spec.name());
    if let Err(e) = ops.create_bridge(&bridge, &token) {
        let mut report = RollbackReport::default();
        if !is_definitely_rejected(e.code()) {
            report
                .leftover
                .push((NetworkResource::Bridge(bridge), ResourceState::Unknown));
        }
        return Err(fail(collision_or(e), CreateStep::CreateBridge, report));
    }

    // 2〜4. ifindex 取得後の失敗は、その ifindex で bridge を削除する（address も一緒に消える）。
    // ifindex は所有トークンの一致を確認して得るため、作成後に同名の別 link へ差し替えられても
    // それを操作・削除しない。取得前（不一致を含む）は自分の bridge と確定できないため、名前では
    // 削除せず Unknown で報告する（fail-closed）。
    let index = match ops.link_index(&bridge, &token) {
        Ok(i) => i,
        Err(e) => {
            let mut report = RollbackReport::default();
            report.leftover.push((
                NetworkResource::Bridge(bridge.clone()),
                ResourceState::Unknown,
            ));
            return Err(fail(e, CreateStep::ResolveIndex, report));
        }
    };
    let step_fail = |e: NetError, step: CreateStep| {
        let mut report = RollbackReport::default();
        rollback_bridge(ops, &bridge, index, &mut report);
        fail(e, step, report)
    };
    ops.add_address(index, &spec.gateway())
        .map_err(|e| step_fail(e, CreateStep::AddAddress))?;
    ops.set_up(index)
        .map_err(|e| step_fail(e, CreateStep::SetUp))?;

    // 5. nft テーブル。バッチは all-or-nothing のため、Unknown 以外は nft 側に何も残らない。
    if let Err(f) = ops.apply_nft(&table) {
        let mut report = RollbackReport::default();
        rollback_bridge(ops, &bridge, index, &mut report);
        if !matches!(
            f.outcome,
            NftBatchOutcome::Aborted | NftBatchOutcome::NotSent
        ) {
            report
                .leftover
                .push((NetworkResource::NftTable(table), ResourceState::Unknown));
        }
        return Err(fail(
            collision_or(f.error),
            CreateStep::CreateNftTable,
            report,
        ));
    }

    Ok(CreatedNetwork {
        name: spec.name().clone(),
        bridge,
        bridge_index: index,
        table,
        gateway: spec.gateway(),
    })
}

/// Linux のカーネル実装。各要求に `timeout` を期限として渡す（REPAIR-5）。
#[cfg(target_os = "linux")]
struct LinuxNetworkOps<'a> {
    route: &'a NetlinkRouteSocket,
    nft: &'a NetlinkNetfilterSocket,
    timeout: Duration,
}

#[cfg(target_os = "linux")]
impl NetworkOps for LinuxNetworkOps<'_> {
    fn create_bridge(&self, name: &IfName, token: &str) -> Result<(), NetError> {
        self.route
            .create_link(
                &LinkCreate::bridge(name.clone()).with_alias(token)?,
                self.timeout,
            )
            .map(|_| ())
    }

    fn link_index(&self, name: &IfName, token: &str) -> Result<IfIndex, NetError> {
        self.route.link_index_owned(name, token, self.timeout)
    }

    fn add_address(&self, index: IfIndex, gateway: &IpPrefix) -> Result<(), NetError> {
        self.route
            .add_address(
                &AddressSpec::new(index, *gateway, AddrScope::Universe),
                self.timeout,
            )
            .map(|_| ())
    }

    fn set_up(&self, index: IfIndex) -> Result<(), NetError> {
        let idx = LinkIndex::new(i32::try_from(index.get()).map_err(|_| {
            NetError::new(NetErrorCode::InvalidArgument, "ifindex exceeds i32::MAX")
        })?)?;
        self.route
            .set_link(&LinkSet::up(LinkRef::Index(idx)), self.timeout)
            .map(|_| ())
    }

    fn delete_bridge(&self, index: IfIndex) -> Result<(), NetError> {
        let idx = LinkIndex::new(i32::try_from(index.get()).map_err(|_| {
            NetError::new(NetErrorCode::InvalidArgument, "ifindex exceeds i32::MAX")
        })?)?;
        self.route
            .delete_link(&LinkDelete::new(LinkRef::Index(idx)), self.timeout)
            .map(|_| ())
    }

    fn apply_nft(&self, table: &NftName) -> Result<(), NftApplyFailure> {
        self.nft
            .send_batch(self.timeout, |batch| {
                batch.push_with(|seq| {
                    TableCreate::new(NftFamily::Ipv4, table.clone())
                        .exclusive()
                        .build(seq)
                })?;
                for (name, hook, priority) in [
                    ("postrouting", NfInetHook::PostRouting, NF_IP_PRI_NAT_SRC),
                    ("prerouting", NfInetHook::PreRouting, NF_IP_PRI_NAT_DST),
                    ("output", NfInetHook::LocalOut, NF_IP_PRI_NAT_DST),
                ] {
                    batch.push_with(|seq| {
                        ChainCreate::base(
                            NftFamily::Ipv4,
                            table.clone(),
                            NftName::new(name)?,
                            BaseChain {
                                chain_type: ChainType::Nat,
                                hook,
                                priority,
                            },
                        )?
                        .exclusive()
                        .build(seq)
                    })?;
                }
                Ok(())
            })
            .map(|_| ())
            .map_err(|e| NftApplyFailure {
                outcome: e.outcome(),
                error: e.into(),
            })
    }
}

/// ネットワークを作成する（bridge・gateway・up・専用 nft テーブルと NAT base chain）。
///
/// 失敗時は自分が作ったと確定した bridge を削除し、結果を [`NetworkCreateError::rollback`] で返す。
/// `CAP_NET_ADMIN` が必要で、本 crate は権限を上げない。`timeout` は各要求の期限（REPAIR-5）。
#[cfg(target_os = "linux")]
pub fn create_network(
    route: &NetlinkRouteSocket,
    nft: &NetlinkNetfilterSocket,
    spec: &NetworkCreateSpec,
    timeout: Duration,
) -> Result<CreatedNetwork, NetworkCreateError> {
    create_network_with(
        &LinuxNetworkOps {
            route,
            nft,
            timeout,
        },
        spec,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::net::{IpAddr, Ipv4Addr};

    fn nname(s: &str) -> NetworkName {
        NetworkName::new(s).unwrap()
    }

    fn gw(a: [u8; 4], len: u8) -> IpPrefix {
        IpPrefix::new(IpAddr::V4(Ipv4Addr::from(a)), len).unwrap()
    }

    fn spec(n: &str) -> NetworkCreateSpec {
        NetworkCreateSpec::new(nname(n), gw([10, 89, 0, 1], 24)).unwrap()
    }

    /// NET-1・TASK-139.1: 導出名の具体値（版をまたいで安定すること）。
    #[test]
    fn net1_derived_names_are_fixed() {
        let names = NetworkResourceNames::derive(&nname("frontend")).unwrap();
        assert_eq!(names.table().as_str(), "fandhe_net_frontend");
        let h = fnv1a64(b"frontend") & ((1u64 << 44) - 1);
        assert_eq!(names.bridge().as_str(), format!("fcbr{h:011x}"));
        assert_eq!(names.bridge().as_str().len(), 15);
        // FNV-1a 64bit の公開テストベクタ。
        assert_eq!(fnv1a64(b""), 0xcbf2_9ce4_8422_2325);
        assert_eq!(fnv1a64(b"a"), 0xaf63_dc4c_8601_ec8c);
        assert_eq!(fnv1a64(b"foobar"), 0x8594_4171_f739_67e8);
    }

    /// NET-1: 名前の境界と禁止文字。
    #[test]
    fn net1_network_name_validation() {
        assert!(NetworkName::new(&"a".repeat(64)).is_ok());
        for bad in [
            "".to_owned(),
            "a".repeat(65),
            "Front".to_owned(),
            "-a".to_owned(),
            ".a".to_owned(),
            "_a".to_owned(),
            "a/b".to_owned(),
            "a b".to_owned(),
            "a\0b".to_owned(),
        ] {
            assert_eq!(
                NetworkName::new(&bad).unwrap_err().code(),
                NetErrorCode::InvalidArgument,
                "{bad:?}"
            );
        }
        let long = NetworkResourceNames::derive(&nname(&"a".repeat(64))).unwrap();
        assert_eq!(long.bridge().as_str().len(), 15);
    }

    /// NET-1: `a-b` と `a_b` のテーブル名は衝突しない。
    #[test]
    fn net1_table_names_are_injective() {
        let a = NetworkResourceNames::derive(&nname("a-b")).unwrap();
        let b = NetworkResourceNames::derive(&nname("a_b")).unwrap();
        assert_ne!(a.table(), b.table());
        assert_eq!(a.conflicts_with(&b), None);
    }

    /// NET-1: 導出名が一致する別ネットワークは種別つきで検出し、同名どうしは衝突扱いにしない。
    #[test]
    fn net1_conflict_detection() {
        let a = NetworkResourceNames::derive(&nname("alpha")).unwrap();
        let mut b = NetworkResourceNames::derive(&nname("beta")).unwrap();
        assert_eq!(a.conflicts_with(&b), None);
        assert_eq!(a.conflicts_with(&a), None);
        b.bridge = a.bridge.clone();
        assert_eq!(a.conflicts_with(&b), Some(NameConflict::Bridge));
        let mut c = NetworkResourceNames::derive(&nname("gamma")).unwrap();
        c.table = a.table.clone();
        assert_eq!(a.conflicts_with(&c), Some(NameConflict::Table));
        assert_eq!(
            NetworkResourceNames::find_conflict([&b, &c], &a),
            Some(NameConflict::Bridge)
        );
    }

    /// NET-1: gateway の検証。
    #[test]
    fn net1_spec_validation() {
        let v6 = IpPrefix::new(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST), 64).unwrap();
        for bad in [
            v6,
            gw([10, 0, 0, 1], 0),
            gw([10, 0, 0, 1], 31),
            gw([10, 0, 0, 1], 32),
            gw([10, 0, 0, 0], 24),
            gw([10, 0, 0, 255], 24),
        ] {
            assert_eq!(
                NetworkCreateSpec::new(nname("x"), bad).unwrap_err().code(),
                NetErrorCode::InvalidArgument,
                "{bad:?}"
            );
        }
        assert!(NetworkCreateSpec::new(nname("x"), gw([10, 0, 0, 1], 30)).is_ok());
        assert!(NetworkCreateSpec::new(nname("x"), gw([10, 0, 0, 1], 1)).is_ok());
    }

    /// 呼び出し列を記録し、指定ステップで失敗を注入する fake。
    #[derive(Default)]
    struct Fake {
        calls: RefCell<Vec<&'static str>>,
        fail_bridge: Option<NetErrorCode>,
        fail_index: bool,
        fail_addr: bool,
        fail_up: bool,
        fail_nft: Option<(NetErrorCode, NftBatchOutcome)>,
        fail_delete: bool,
        delete_code: Option<NetErrorCode>,
    }

    impl Fake {
        fn rec(&self, c: &'static str) {
            self.calls.borrow_mut().push(c);
        }
        fn calls(&self) -> Vec<&'static str> {
            self.calls.borrow().clone()
        }
    }

    fn err(code: NetErrorCode) -> NetError {
        NetError::new(code, "injected")
    }

    impl NetworkOps for Fake {
        fn create_bridge(&self, _: &IfName, _: &str) -> Result<(), NetError> {
            self.rec("create_bridge");
            self.fail_bridge.map_or(Ok(()), |c| Err(err(c)))
        }
        fn link_index(&self, _: &IfName, _: &str) -> Result<IfIndex, NetError> {
            self.rec("link_index");
            if self.fail_index {
                return Err(err(NetErrorCode::NotFound));
            }
            IfIndex::new(7)
        }
        fn add_address(&self, _: IfIndex, _: &IpPrefix) -> Result<(), NetError> {
            self.rec("add_address");
            if self.fail_addr {
                return Err(err(NetErrorCode::Internal));
            }
            Ok(())
        }
        fn set_up(&self, _: IfIndex) -> Result<(), NetError> {
            self.rec("set_up");
            if self.fail_up {
                return Err(err(NetErrorCode::Internal));
            }
            Ok(())
        }
        fn delete_bridge(&self, _: IfIndex) -> Result<(), NetError> {
            self.rec("delete_bridge");
            if self.fail_delete {
                return Err(err(self.delete_code.unwrap_or(NetErrorCode::Internal)));
            }
            Ok(())
        }
        fn apply_nft(&self, _: &NftName) -> Result<(), NftApplyFailure> {
            self.rec("apply_nft");
            match self.fail_nft {
                Some((c, o)) => Err(NftApplyFailure {
                    error: err(c),
                    outcome: o,
                }),
                None => Ok(()),
            }
        }
    }

    fn bridge_of(n: &str) -> IfName {
        NetworkResourceNames::derive(&nname(n)).unwrap().bridge
    }

    fn table_of(n: &str) -> NftName {
        NetworkResourceNames::derive(&nname(n)).unwrap().table
    }

    /// NET-1・TASK-139.1: 全手順成功。
    #[test]
    fn net1_create_success() {
        let f = Fake::default();
        let c = create_network_with(&f, &spec("web")).unwrap();
        assert_eq!(
            f.calls(),
            [
                "create_bridge",
                "link_index",
                "add_address",
                "set_up",
                "apply_nft"
            ]
        );
        assert_eq!(c.bridge, bridge_of("web"));
        assert_eq!(c.table.as_str(), "fandhe_net_web");
        assert_eq!(c.bridge_index.get(), 7);
        assert_eq!(c.gateway, gw([10, 89, 0, 1], 24));
    }

    /// NET-1: bridge の AlreadyExists は削除せず衝突として返す。
    #[test]
    fn net1_bridge_exists_is_not_deleted() {
        let f = Fake {
            fail_bridge: Some(NetErrorCode::AlreadyExists),
            ..Default::default()
        };
        let e = create_network_with(&f, &spec("web")).unwrap_err();
        assert_eq!(f.calls(), ["create_bridge"]);
        assert_eq!(e.code(), NetErrorCode::AlreadyExists);
        assert_eq!(e.message(), COLLISION_MSG);
        assert_eq!(e.step, CreateStep::CreateBridge);
        assert_eq!(e.rollback, RollbackReport::default());
    }

    /// NET-1: 送信後の応答エラー（ResourceExhausted・Internal 等）は作成済みか不明なので Unknown で報告し、
    /// 確定的な拒否（PermissionDenied 等）は何も報告しない。
    #[test]
    fn net1_bridge_post_send_errors_are_unknown_leftover() {
        for code in [
            NetErrorCode::ResourceExhausted,
            NetErrorCode::Internal,
            NetErrorCode::DataLoss,
        ] {
            let f = Fake {
                fail_bridge: Some(code),
                ..Default::default()
            };
            let e = create_network_with(&f, &spec("web")).unwrap_err();
            assert_eq!(f.calls(), ["create_bridge"], "{code:?}");
            assert_eq!(
                e.rollback.leftover,
                [(
                    NetworkResource::Bridge(bridge_of("web")),
                    ResourceState::Unknown
                )],
                "{code:?}"
            );
        }
        let f = Fake {
            fail_bridge: Some(NetErrorCode::PermissionDenied),
            ..Default::default()
        };
        let e = create_network_with(&f, &spec("web")).unwrap_err();
        assert_eq!(e.rollback, RollbackReport::default());
    }

    /// NET-1: 所有トークンは作成ごとに一意で、可視 ASCII のみ。
    #[test]
    fn net1_ownership_token_is_unique_and_graphic() {
        let n = nname("web");
        let (a, b) = (ownership_token(&n), ownership_token(&n));
        assert_ne!(a, b);
        assert!(a.starts_with("fandhe-net:web:"));
        assert!(a.bytes().all(|c| c.is_ascii_graphic()) && a.len() <= 255);
    }

    /// NET-1: bridge 作成の Timeout は fail-closed（削除せず Unknown で報告）。
    #[test]
    fn net1_bridge_timeout_is_unknown_leftover() {
        let f = Fake {
            fail_bridge: Some(NetErrorCode::Timeout),
            ..Default::default()
        };
        let e = create_network_with(&f, &spec("web")).unwrap_err();
        assert_eq!(f.calls(), ["create_bridge"]);
        assert_eq!(
            e.rollback.leftover,
            [(
                NetworkResource::Bridge(bridge_of("web")),
                ResourceState::Unknown
            )]
        );
        assert!(e.rollback.removed.is_empty());
    }

    /// NET-1: 手順 3〜4 の失敗は bridge を削除する。
    #[test]
    fn net1_steps_2_to_4_roll_back_bridge() {
        let cases = [
            (
                Fake {
                    fail_addr: true,
                    ..Default::default()
                },
                CreateStep::AddAddress,
                vec![
                    "create_bridge",
                    "link_index",
                    "add_address",
                    "delete_bridge",
                ],
            ),
            (
                Fake {
                    fail_up: true,
                    ..Default::default()
                },
                CreateStep::SetUp,
                vec![
                    "create_bridge",
                    "link_index",
                    "add_address",
                    "set_up",
                    "delete_bridge",
                ],
            ),
        ];
        for (f, step, calls) in cases {
            let e = create_network_with(&f, &spec("web")).unwrap_err();
            assert_eq!(f.calls(), calls);
            assert_eq!(e.step, step);
            assert_eq!(
                e.rollback.removed,
                [NetworkResource::Bridge(bridge_of("web"))]
            );
            assert!(e.rollback.leftover.is_empty());
        }
    }

    /// NET-1: ifindex 取得前の失敗は所有を確認できないため名前で削除せず Unknown で報告する。
    #[test]
    fn net1_resolve_index_failure_does_not_delete_by_name() {
        let f = Fake {
            fail_index: true,
            ..Default::default()
        };
        let e = create_network_with(&f, &spec("web")).unwrap_err();
        assert_eq!(f.calls(), ["create_bridge", "link_index"]);
        assert_eq!(e.step, CreateStep::ResolveIndex);
        assert!(e.rollback.removed.is_empty());
        assert_eq!(
            e.rollback.leftover,
            [(
                NetworkResource::Bridge(bridge_of("web")),
                ResourceState::Unknown
            )]
        );
    }

    /// NET-1: nft の Aborted / NotSent は bridge だけ削除する。AlreadyExists は衝突として返す。
    #[test]
    fn net1_nft_aborted_rolls_back_bridge_only() {
        for outcome in [NftBatchOutcome::Aborted, NftBatchOutcome::NotSent] {
            let f = Fake {
                fail_nft: Some((NetErrorCode::PermissionDenied, outcome)),
                ..Default::default()
            };
            let e = create_network_with(&f, &spec("web")).unwrap_err();
            assert_eq!(e.step, CreateStep::CreateNftTable);
            assert_eq!(e.code(), NetErrorCode::PermissionDenied);
            assert_eq!(
                e.rollback.removed,
                [NetworkResource::Bridge(bridge_of("web"))]
            );
            assert!(e.rollback.leftover.is_empty());
        }
        let f = Fake {
            fail_nft: Some((NetErrorCode::AlreadyExists, NftBatchOutcome::Aborted)),
            ..Default::default()
        };
        let e = create_network_with(&f, &spec("web")).unwrap_err();
        assert_eq!(e.message(), COLLISION_MSG);
        assert_eq!(f.calls().last(), Some(&"delete_bridge"));
    }

    /// NET-1: nft の Unknown は table を Unknown で報告し、bridge は削除する。
    #[test]
    fn net1_nft_unknown_reports_table() {
        let f = Fake {
            fail_nft: Some((NetErrorCode::Timeout, NftBatchOutcome::Unknown)),
            ..Default::default()
        };
        let e = create_network_with(&f, &spec("web")).unwrap_err();
        assert_eq!(
            e.rollback.removed,
            [NetworkResource::Bridge(bridge_of("web"))]
        );
        assert_eq!(
            e.rollback.leftover,
            [(
                NetworkResource::NftTable(table_of("web")),
                ResourceState::Unknown
            )]
        );
    }

    /// NET-1: ロールバックの削除失敗でも元のエラーを保ち、bridge を Present で報告する。
    #[test]
    fn net1_rollback_failure_keeps_original_error() {
        let f = Fake {
            fail_up: true,
            fail_delete: true,
            ..Default::default()
        };
        let e = create_network_with(&f, &spec("web")).unwrap_err();
        assert_eq!(e.step, CreateStep::SetUp);
        assert_eq!(e.code(), NetErrorCode::Internal);
        assert_eq!(e.message(), "injected");
        assert!(e.rollback.removed.is_empty());
        assert_eq!(
            e.rollback.leftover,
            [(
                NetworkResource::Bridge(bridge_of("web")),
                ResourceState::Present
            )]
        );
        assert_eq!(e.to_string(), "INTERNAL: injected");
    }

    /// NET-1: ロールバックの削除が Timeout / DataLoss なら削除結果が不明なので Unknown で報告する。
    #[test]
    fn net1_rollback_delete_indeterminate_is_unknown() {
        for code in [NetErrorCode::Timeout, NetErrorCode::DataLoss] {
            let f = Fake {
                fail_up: true,
                fail_delete: true,
                delete_code: Some(code),
                ..Default::default()
            };
            let e = create_network_with(&f, &spec("web")).unwrap_err();
            assert_eq!(
                e.rollback.leftover,
                [(
                    NetworkResource::Bridge(bridge_of("web")),
                    ResourceState::Unknown
                )]
            );
        }
    }
}
