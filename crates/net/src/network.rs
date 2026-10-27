//! ユーザー定義ネットワークの作成処理（bridge・専用 nft テーブル。TASK-139.1・#314・NET-1・MS-8）。
//!
//! ネットワーク名から bridge 名と nft テーブル名を決定的に導出し、bridge の作成 → gateway アドレス付与 →
//! up → 専用 nft テーブルと NAT base chain の作成までを 1 つの操作として行い、途中で失敗したら
//! 自分が作ったリソースだけをロールバックする。`netlink_route`（bridge・address・link 削除）と
//! `nftables_batch`（table・chain）の上に載る統合層で、PoC-15 `netsetup` の `net-create` に相当する。
//! ネットワーク削除（`delete_network`。TASK-139.4）は [`NetworkResourceNames::derive`] で同じ名前を再導出して使う。
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
//! カーネルは作成要求（`RTM_NEWLINK`）の `IFLA_IFALIAS` を反映しない（torvalds/linux v7.0 の
//! `net/core/rtnetlink.c` で `IFLA_IFALIAS` を処理するのは `do_setlink` の `netif_set_alias` だけ。
//! Issue #1925）。そのため bridge は `NLM_F_EXCL` で作成した後、次の順で所有トークンを刻む。
//!
//! 1. 名前から ifindex と別名を 1 回の `RTM_GETLINK` で引く。別名が既にあれば別者が差し替えた link なので
//!    止まる（削除しない）
//! 2. その ifindex 指定の `RTM_SETLINK` で作成ごとに一意な所有トークンを `IFLA_IFALIAS` に付ける
//!    （名前では指定しない。名前の差し替えを巻き込まない）
//! 3. 名前から引き直して、ifindex が 1 と同じで別名がトークンと一致することを確認する
//!
//! 3 までに同名 link へ差し替えられれば ifindex か別名が食い違って検出する。確認後の操作はすべてトークン一致
//! を確認してから行い、不一致（同名 link への差し替え）なら操作も削除もしない。2 の `RTM_SETLINK` が
//! 失敗・時間切れの場合だけ、再照会して「ifindex が 1 と同じ」かつ（別名がトークン、または別名が空のまま）
//! のときに限り、ifindex 指定で削除する（`rollback_unstamped`）。残余リスク: 1 の直前に `CAP_NET_ADMIN`
//! 保持者が自分の bridge を別名なしで差し替えた場合に限り、その link に印を付ける窓が残る。同じ権限を持つ者が
//! 相手のため権限境界は越えず、`NLM_F_EXCL` と ifindex 指定（名前の再解決なし）で窓を最小化している。
//! bridge 作成要求が
//! 送信後の応答エラー（`ResourceExhausted` 等）で失敗した場合は作成済みの可能性があるため
//! `ResourceState::Unknown` で報告する（確定的な拒否のみ空報告）。
//! 取り残しは `NetworkCreateError::reclaim_claim` の請求書（[`FailedCreateClaim`]）で `reclaim_failed_create`
//! （Linux のみ。#2467）から回収できる。請求書のトークンで証明できるのは、トークンを刻んだ後の失敗
//! （`AddAddress` / `SetUp` / `CreateNftTable`）で残った bridge と nft テーブルだけで、刻む前の失敗
//! （`CreateBridge` の結果不明・`ResolveIndex`・`SetOwnerToken`）で残った bridge は別名が空のため
//! 回収側が `Unknown` のまま触れない（手動回収。観測の方法と手順は `docs/setup/network-reclaim-recovery.md`）。
//! 請求書は [`FailedCreateClaim::to_record`] / [`FailedCreateClaim::from_record`] の固定テキスト記録で
//! プロセスをまたいで残せる（置き場所・排他は呼び出し側。`docs/design/network-reclaim-persistence.md`・#2604）。
//! 自分が作ったと確定した bridge のみ削除する（address は bridge と一緒に消える）。作成結果が
//! 不明（`Timeout` / `DataLoss`）なリソースは fail-closed で削除せず、[`RollbackReport::leftover`]
//! に `ResourceState::Unknown` として報告する。nft バッチは all-or-nothing なので `Aborted` /
//! `NotSent` では nft 側に何も残らない。
//!
//! # コンテナ接続（TASK-139.2.1・#847）
//!
//! `attach_container`（Linux のみ）はコンテナ単位の接続処理で、netns の作成と pin（`crate::netns`）→ veth ペア作成 →
//! host 側の bridge 接続（`IFLA_MASTER`）と up → peer 側の netns 移動までを行い、途中で失敗したら
//! 自分が作った veth と netns だけを戻す。veth は host 側 `fcvh` / peer 側 `fcvp` + [`EndpointId`] の
//! FNV-1a 下位 44bit hex 11 桁（[`VethNames`]。互換性に関わる契約）。veth には所有トークンを付けられない
//! ため `NLM_F_EXCL` 作成 + 直後の ifindex 確保 + ifindex 指定の削除で運用する（`attach_container_with` の doc）。
//!
//! 失敗して取り残した veth・pin は `ContainerAttachError::reclaim_claim` の請求書（[`FailedAttachClaim`]）で
//! `reclaim_failed_attach`（Linux のみ。#2681）から回収できる（`delete` モジュール doc「attach の取り残しの回収」）。
//!
//! 接続の最後に [`StaticIpam`]（`ipam`。TASK-139.2.2・#848）で重複しない IPv4 アドレスを払い出す。
//! 払い出しに失敗（枯渇 `ResourceExhausted` 等）したら veth と netns を戻す。IPAM の状態は呼び出し側が
//! 所有し、接続失敗時は変更されない。
//!
//! # netns 内の設定と default route・ポート公開（TASK-139.3・#316）
//!
//! 払い出しの後、netns 内で開いた route ソケット（`crate::netns` の使い捨てスレッドで開く）で
//! `lo` を up → peer 側の ifindex を再解決（移動で変わりうるため）→ 払い出しアドレスの付与 →
//! peer 側 up → default route（`0.0.0.0/0 via <bridge アドレス>`）の順に設定する。peer が down / 無アドレス
//! のままだと gateway 経由の route はカーネルに拒否されるため、この順序は必須。続けて
//! [`ContainerAttachSpec::with_port_publishes`] の指定があれば、DNAT ルール全件を 1 つの nft バッチ
//! （all-or-nothing）でネットワーク専用テーブルの `prerouting` / `output` へ投入する（[`PortPublish`]）。
//!
//! これらのいずれかが失敗したら接続全体（IPAM の払い出し・veth・netns）を戻す。`RTM_DELROUTE` /
//! `RTM_DELADDR` が未実装で、公開済みルールの個別の巻き戻し（`unpublish_container_port`）は attach の失敗経路に組み込んでいないため、個別の巻き戻しができず、netns 内の address・route は
//! veth と netns の破棄で消え、nft バッチは失敗時に何も適用されない（`Aborted` / `NotSent`）ことに
//! 依存する。結果が不明なバッチは `AttachResource::PortRules` と `AttachResource::Address` を `Unknown` で報告し、
//! IPAM のアドレスと [`PortRegistry`] の予約を保持する（残ったルールが別コンテナへ転送しないための quarantine。
//! 解放はテーブルの削除を確認できた場合に `delete_network` が行う。TASK-139.4）。受け口の競合（コンテナ間・ネットワーク間）は
//! 投入前に [`PortRegistry`] で検出して `AlreadyExists` とする。
//!
//! # ネットワーク削除（TASK-139.4・#317）
//!
//! `delete_network`（`delete` モジュール）は、渡されたコンテナの veth 削除と netns の unpin → 専用 nft
//! テーブルの削除（bridge の所有確認が通った場合のみ）→ bridge の削除 → IPAM・ポート予約の解放を行う。接続中のコンテナを呼び出し側が渡す
//! 設計で、渡されていない生存コンテナがあれば何も変更せず拒否する。方針・順序・残余リスクは
//! `delete` モジュールの doc を参照。
//!
//! # 実機検証（TASK-139.5・#318）
//!
//! 作成・接続・削除の統合 API を通しで使う 3 経路疎通と所要時間計測は、実機前提テスト
//! `tests/network_paths_privileged.rs`（`--ignored` / `--measure`。`AGENTS.md`「実機前提テスト」節）が担う。
//!
//! # 未実装範囲（REPAIR-3）
//!
//! - masquerade ルール本体（`bitwise` / `meta` expr が `nftables_rules` に未実装のため `postrouting`
//!   チェインは空。saddr のみの masq は `bridge-nf-call-iptables` 有効環境で bridge 内通信まで書き換える）。
//!   このため default route を張っても、コンテナ発の通信を host 外部へ届けるには masquerade と host の
//!   `ip_forward` が別途必要（本 crate は host のグローバル設定を変更しない）。担当 Issue 未確定
//! - peer の `eth0` へのリネーム（`LinkSet` に `IFLA_IFNAME` 変更が無い）、コンテナ単位のポート公開解除
//!   （公開は attach 後にも `publish_container_ports` で追加でき、NEWRULE の echo 応答から取ったルールハンドルを
//!   [`PublishedPort`] で返す。個別の解除は `unpublish_container_port`。#2676・#2839・NET-3・NET-4。
//!   再起動後のハンドル復元は未実装）、`RTM_DELROUTE` / `RTM_DELADDR`。担当 Issue 未確定
//! - IPAM 状態の永続化、コンテナ単体の切り離し。担当 Issue 未確定（作成失敗の請求書の永続化は #2604 で済み。
//!   attach の取り残しの請求書 [`FailedAttachClaim`] と所有確認つきの回収 `reclaim_failed_attach` は #2681 で追加。回収できるのは host 側 veth と、
//!   請求書と永続の所有記録（置き場の `.owned/<endpoint>`。#2824）に一致する pin まで。再起動後のネットワーク本体は手動。
//!   所有記録の無い pin（旧い請求書・none モード）も手動。write-ahead は #1870 の後に再検討）
//! - netns の事前作成（`create_container_netns`・`attach_prepared_container`・`release_container_netns`。#2675）は
//!   作成と pin だけを切り出した入口で、コンテナがその netns へ入る側（core）は未実装。未 attach の
//!   `PreparedNetns` は呼び出し側が必ず解放する（Drop では unpin しない）
//! - IPv6 と `NftFamily::Inet`（IPv4 のみ。静的 IPAM が IPv4 のみのため）

pub mod attach_claim;
// 試験専用の故障注入。単体試験（3 OS）と、feature 有効な Linux の結合試験だけで有効にする（NET-1・#2971）。
#[cfg(any(test, all(feature = "attach-fault-test-support", target_os = "linux")))]
mod attach_fault;
pub mod delete;
pub mod ipam;
pub mod publish;
pub mod unpublish;

use std::fmt;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
#[cfg(target_os = "linux")]
use std::time::Duration;

pub use attach_claim::FailedAttachClaim;
#[cfg(all(feature = "attach-fault-test-support", target_os = "linux"))]
pub use attach_fault::{AttachFault, AttachFaultPoint, attach_container_with_fault_for_test};
#[cfg(target_os = "linux")]
pub use delete::delete_network;
#[cfg(target_os = "linux")]
pub use delete::reclaim_failed_attach;
#[cfg(target_os = "linux")]
pub use delete::reclaim_failed_create;
pub use delete::{DeleteResource, DeleteStep, NetworkDeleteError, NetworkDeleteReport};
pub(crate) use ipam::NetnsDirRecord;
pub use ipam::StaticIpam;
pub use publish::{MAX_PORT_PUBLISHES, PortProtocol, PortPublish, PortRegistry};
#[cfg(target_os = "linux")]
pub use unpublish::unpublish_container_port;
pub use unpublish::{PublishedPort, UnpublishPortError, UnpublishRules};

use crate::error::{NetError, NetErrorCode};
use crate::etc_hosts::NameResolution;
#[cfg(target_os = "linux")]
use crate::netlink_route::{
    AddrScope, AddressSpec, LinkCreate, LinkDelete, LinkIndex, LinkRef, LinkSet,
    NetlinkRouteSocket, NetnsFd, NetnsTarget, RouteNextHop, RouteSpec,
};
use crate::netlink_route::{IfIndex, IfName, IpPrefix};
#[cfg(target_os = "linux")]
use crate::netns::{self, ContainerNetns};
#[cfg(target_os = "linux")]
use crate::nftables_batch::{
    BaseChain, ChainCreate, ChainType, NF_IP_PRI_NAT_DST, NF_IP_PRI_NAT_SRC,
    NetlinkNetfilterSocket, NfInetHook, NftFamily, TableCreate,
};
use crate::nftables_batch::{NftBatchOutcome, NftName};
use crate::nftables_rules::NftRuleHandle;
#[cfg(target_os = "linux")]
use crate::nftables_rules::RuleCreate;

/// bridge 名のプレフィックス。
const BRIDGE_PREFIX: &str = "fcbr";
/// nft テーブル名のプレフィックス。
const TABLE_PREFIX: &str = "fandhe_net_";
/// ネットワーク名の最大長（バイト）。CLI の `--network` 1 値の argv 上限が参照する（#1871・NET-12）。
pub const NAME_MAX_LEN: usize = 64;
/// FNV-1a 64bit の offset basis。
const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
/// FNV-1a 64bit の prime。
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

fn invalid(msg: &'static str) -> NetError {
    NetError::new(NetErrorCode::InvalidArgument, msg)
}

/// 名前の検証違反の種類（`NetworkName` と `EndpointId` が共有する文字種規則）。
enum NameFault {
    Length,
    Chars,
}

/// 1〜64 バイト、先頭 `[a-z0-9]`、以降 `[a-z0-9_.-]` の規則に反する点を返す。`/`・NUL・空白・
/// 先頭の `.` を含み得ないので、パス要素としても安全（パストラバーサル不能）。
fn name_fault(name: &str) -> Option<NameFault> {
    if name.is_empty() || name.len() > NAME_MAX_LEN {
        return Some(NameFault::Length);
    }
    let mut bytes = name.bytes();
    let first_ok = bytes
        .next()
        .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit());
    let rest_ok = bytes
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'_' | b'.' | b'-'));
    if first_ok && rest_ok {
        None
    } else {
        Some(NameFault::Chars)
    }
}

/// 検証済みのネットワーク名（REPAIR-2）。1〜64 バイト、先頭 `[a-z0-9]`、以降 `[a-z0-9_.-]`。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NetworkName(String);

impl NetworkName {
    /// 検証して作る。違反は `InvalidArgument`（入力値はメッセージに載せない）。
    pub fn new(name: &str) -> Result<Self, NetError> {
        match name_fault(name) {
            Some(NameFault::Length) => Err(invalid("network name length must be 1 to 64 bytes")),
            Some(NameFault::Chars) => Err(invalid("network name contains invalid characters")),
            None => Ok(Self(name.to_owned())),
        }
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
    name_resolution: NameResolution,
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
        Ok(Self {
            name,
            gateway,
            name_resolution: NameResolution::default(),
        })
    }

    /// ネットワーク名。
    pub fn name(&self) -> &NetworkName {
        &self.name
    }

    /// gateway（bridge に付与するアドレス）。
    pub fn gateway(&self) -> IpPrefix {
        self.gateway
    }

    /// 名前解決方式を指定する（既定は [`NameResolution::DnsHelper`]）。`StaticHosts` を選ぶと
    /// DNS ヘルパーを起動しない軽量運用になる（NET-8・TASK-146.1・#334）。
    pub fn with_name_resolution(mut self, resolution: NameResolution) -> Self {
        self.name_resolution = resolution;
        self
    }

    /// 名前解決方式。
    pub fn name_resolution(&self) -> NameResolution {
        self.name_resolution
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
    /// bridge の `IFLA_IFALIAS` に作成後の `RTM_SETLINK` で付けた所有トークン（接続時に同名の別 link で
    /// ないことを確認する）。
    pub bridge_token: String,
    /// 専用 nft テーブル名。
    pub table: NftName,
    /// bridge に付与した gateway。
    pub gateway: IpPrefix,
    /// 名前解決方式（NET-7 の DNS ヘルパーか、NET-8 の hosts 静的注入か。TASK-146.1・#334）。
    /// プロセスをまたぐ永続化は未実装（REPAIR-3）。
    pub name_resolution: NameResolution,
}

/// 失敗した手順。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CreateStep {
    /// 名前の導出。
    DeriveNames,
    /// bridge 作成。
    CreateBridge,
    /// ifindex の取得と、所有トークンの読み戻し確認。
    ResolveIndex,
    /// 所有トークンの付与（`RTM_SETLINK`。Issue #1925）。
    SetOwnerToken,
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
    /// この作成が発行した所有トークンとネットワーク名（名前の導出に失敗した場合は未発行で `None`）。
    /// 回収用の請求書（[`FailedCreateClaim`]）の元になるためだけに保持し、公開しない（#2467）。
    /// `Err` の型を大きくしないため Box にする。
    owner_token: Option<Box<(NetworkName, String)>>,
}

/// 作成失敗で取り残した資源を回収するための請求書（NET-1・#2467）。
///
/// 作成が失敗して `NetworkCreateError::rollback` の `leftover` が残ったとき、その資源が「この作成が
/// 作ったもの」だと後から証明するための所有トークンを、ネットワーク名と取り残した資源の種類と一緒に持つ。
/// フィールドは非公開で、構築口は `NetworkCreateError::reclaim_claim`・[`FailedCreateClaim::from_created`]・
/// plugin 自身が書いた永続化記録の復号 [`FailedCreateClaim::from_record`] だけ。トークンを返すアクセサも置かない。回収は
/// `network::reclaim_failed_create`（Linux のみ）が、名前の再導出とトークンの完全一致を確かめてから行う。
/// plugin-cri の netsetup が作成失敗の回収待ちの記録に保持し、削除要求で回収に使う。
///
/// プロセスをまたぐ永続化は [`FailedCreateClaim::to_record`] / [`FailedCreateClaim::from_record`] の固定テキスト記録で行う
/// （置き場所・排他は呼び出し側 plugin-cri の責務。`docs/design/network-reclaim-persistence.md`・#2604）。
/// 記録は信頼しない入力として厳密に検証するが、所有の最終的な判定はカーネル側の別名・userdata と
/// トークンの完全一致で行う。トークン内の pid は発行したプロセスのもので、再起動後の照合は
/// 名前と接頭辞だけで成り立つため直さない。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct FailedCreateClaim {
    network: NetworkName,
    token: String,
    bridge: bool,
    table: bool,
}

impl FailedCreateClaim {
    /// 作成には成功したが、後続の処理（IPAM 等）の失敗でネットワークごと戻したい場合の請求書
    /// （bridge・テーブルの両方を対象にする）。
    pub fn from_created(created: &CreatedNetwork) -> Self {
        Self {
            network: created.name.clone(),
            token: created.bridge_token.clone(),
            bridge: true,
            table: true,
        }
    }

    /// 永続化記録（固定のテキスト。LF・ASCII。NET-1・#2604）へ符号化する。
    pub fn to_record(&self) -> String {
        format!(
            "{RECORD_VERSION_LINE}\nnetwork={}\ntoken={}\nbridge={}\ntable={}\n",
            self.network.as_str(),
            self.token,
            u8::from(self.bridge),
            u8::from(self.table),
        )
    }

    /// [`FailedCreateClaim::to_record`] の記録を復号する。版・キーの順序・名前・トークン形式・フラグを
    /// 厳密に検証し、違反は `InvalidArgument`（入力値はメッセージに載せない）。
    pub fn from_record(record: &str) -> Result<Self, NetError> {
        if record.len() > CLAIM_RECORD_MAX_LEN {
            return Err(invalid("claim record too long"));
        }
        let mut lines = record.strip_suffix('\n').unwrap_or("").split('\n');
        if !record.ends_with('\n') || lines.next() != Some(RECORD_VERSION_LINE) {
            return Err(invalid("claim record version mismatch"));
        }
        let mut field = |key: &str| -> Result<&str, NetError> {
            lines
                .next()
                .and_then(|l| l.strip_prefix(key))
                .and_then(|l| l.strip_prefix('='))
                .ok_or_else(|| invalid("claim record malformed"))
        };
        let network = NetworkName::new(field("network")?)?;
        let token = field("token")?;
        let bridge = parse_flag(field("bridge")?)?;
        let table = parse_flag(field("table")?)?;
        if lines.next().is_some() {
            return Err(invalid("claim record malformed"));
        }
        if token.len() > CLAIM_TOKEN_MAX_LEN
            || !token.bytes().all(|b| b.is_ascii_graphic())
            || !token_names_network(token, &network)
        {
            return Err(invalid("claim record token invalid"));
        }
        if !(bridge || table) {
            return Err(invalid("claim record names no resource"));
        }
        Ok(Self {
            network,
            token: token.to_owned(),
            bridge,
            table,
        })
    }

    /// 対象のネットワーク名。
    pub fn network(&self) -> &NetworkName {
        &self.network
    }

    /// bridge を回収対象に含むか。
    pub fn includes_bridge(&self) -> bool {
        self.bridge
    }

    /// nft テーブルを回収対象に含むか。
    pub fn includes_table(&self) -> bool {
        self.table
    }

    /// 回収側（`delete.rs`）が所有の証明に使うトークン。
    pub(crate) fn token(&self) -> &str {
        &self.token
    }

    /// テスト用の組み立て（別ネットワークのトークン等の不正な請求書を作る）。
    #[cfg(test)]
    pub(crate) fn for_test(network: NetworkName, token: &str, bridge: bool, table: bool) -> Self {
        Self {
            network,
            token: token.to_owned(),
            bridge,
            table,
        }
    }
}

/// 請求書の記録の先頭行（版）。
const RECORD_VERSION_LINE: &str = "fandhe-net-claim v1";
/// 請求書の記録全体の長さの上限（バイト）。
pub const CLAIM_RECORD_MAX_LEN: usize = 1024;
/// 記録内のトークンの長さの上限（バイト）。
const CLAIM_TOKEN_MAX_LEN: usize = 256;

fn parse_flag(v: &str) -> Result<bool, NetError> {
    match v {
        "0" => Ok(false),
        "1" => Ok(true),
        _ => Err(invalid("claim record flag invalid")),
    }
}

impl NetworkCreateError {
    /// 取り残した資源（`rollback.leftover`）の回収用の請求書。取り残しが無い、またはトークン未発行
    /// （名前の導出に失敗）なら `None`。請求書に載るのは取り残しとして報告された資源の種類だけで、
    /// 他者の同名資源との衝突（`AlreadyExists`）で作れなかった資源は含まれない。
    pub fn reclaim_claim(&self) -> Option<FailedCreateClaim> {
        let (network, token) = &**self.owner_token.as_ref()?;
        let has =
            |f: fn(&NetworkResource) -> bool| self.rollback.leftover.iter().any(|(r, _)| f(r));
        let bridge = has(|r| matches!(r, NetworkResource::Bridge(_)));
        let table = has(|r| matches!(r, NetworkResource::NftTable(_)));
        (bridge || table).then(|| FailedCreateClaim {
            network: network.clone(),
            token: token.clone(),
            bridge,
            table,
        })
    }
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
    /// bridge を `NLM_F_EXCL` で作る。カーネルは作成時の `IFLA_IFALIAS` を反映しないため、所有トークンは
    /// 作成後に [`set_owner_token`](Self::set_owner_token) で付ける（Issue #1925）。
    fn create_bridge(&self, name: &IfName) -> Result<(), NetError>;
    /// 名前から ifindex と現在の別名（`IFLA_IFALIAS`。無ければ `None`）を引く。所有の確認はしない。
    /// 作成直後の link に別名が既にあれば、差し替えられた別者の link と判断するために使う。
    fn link_state(&self, name: &IfName) -> Result<(IfIndex, Option<String>), NetError>;
    /// ifindex 指定の `RTM_SETLINK` で `IFLA_IFALIAS` に所有トークンを付ける（名前は再解決しない）。
    fn set_owner_token(&self, index: IfIndex, token: &str) -> Result<(), NetError>;
    /// 操作直前の所有再確認。`name` が今も `index` を指し、かつ所有トークンが `token` と一致する
    /// 場合のみ `Ok`。確認後に bridge が削除され ifindex が別 link に再利用された場合を、各操作の
    /// 直前で検出するために使う。不一致は `FailedPrecondition`。
    fn verify_owned(&self, name: &IfName, token: &str, index: IfIndex) -> Result<(), NetError>;
    fn add_address(&self, index: IfIndex, gateway: &IpPrefix) -> Result<(), NetError>;
    /// 取得済みの ifindex で up にする（名前再解決で別 link を操作しない）。
    fn set_up(&self, index: IfIndex) -> Result<(), NetError>;
    /// 取得済みの ifindex で削除する。外部で bridge が消され同名の別 link ができても巻き込まない。
    fn delete_bridge(&self, index: IfIndex) -> Result<(), NetError>;
    /// 専用テーブルと NAT base chain を作る。テーブルには所有トークン（`token`）を `NFTA_TABLE_USERDATA` で
    /// 載せ、削除時に照合できるようにする（TASK-139.4・#317）。
    fn apply_nft(&self, table: &NftName, token: &str) -> Result<(), NftApplyFailure>;
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
pub(crate) fn is_indeterminate(code: NetErrorCode) -> bool {
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

/// 作成ごとに一意な所有トークン（bridge の `IFLA_IFALIAS` に作成後の `RTM_SETLINK` で付ける）。プロセス ID・時刻・連番を含み、
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

/// `token` が `network` の作成時に [`ownership_token`] で発行した形式（`fandhe-net:<名前>:...`）か。
/// 削除（`delete_network`。TASK-139.4）が、呼び出し側の渡す `CreatedNetwork` の各フィールドがネットワーク名と
/// 食い違っていない（別ネットワークのトークンを組み合わせていない）ことの確認に使う。
pub(crate) fn token_names_network(token: &str, network: &NetworkName) -> bool {
    token
        .strip_prefix("fandhe-net:")
        .and_then(|rest| rest.strip_prefix(network.as_str()))
        .is_some_and(|rest| rest.starts_with(':'))
}

/// 操作直前に ifindex の所有を再確認する。
fn ensure_owned(
    ops: &impl NetworkOps,
    bridge: &IfName,
    token: &str,
    index: IfIndex,
) -> Result<(), NetError> {
    ops.verify_owned(bridge, token, index)
}

/// 所有を再確認してから削除する。再確認できない（不一致・消失・時間切れ等）場合は別 link を
/// 巻き込まないよう削除せず Unknown で報告する。カーネルには所有トークン条件付きの削除が無く、
/// 再確認から削除までの極小の窓は残る（ifindex は単調増加で割り当てられ、短時間での再利用は
/// 通常起きない）。
fn rollback_bridge(
    ops: &impl NetworkOps,
    bridge: &IfName,
    token: &str,
    index: IfIndex,
    report: &mut RollbackReport,
) {
    if ensure_owned(ops, bridge, token, index).is_err() {
        report.leftover.push((
            NetworkResource::Bridge(bridge.clone()),
            ResourceState::Unknown,
        ));
        return;
    }
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

/// 所有トークンの `RTM_SETLINK` が失敗・時間切れだった bridge を、自分のものと確定できる場合だけ戻す
/// （Issue #1925）。名前から ifindex と別名を再照会し、
///
/// - `NotFound`: 残るものは無い（空報告）
/// - ifindex が `index`（作成直後に別名なしで確認した link）と同じで、別名がトークン（反映済み）:
///   [`rollback_bridge`]（所有再確認つき）で削除する
/// - ifindex が `index` と同じで別名が空: 確認した link と同一で印が無いだけなので、ifindex 指定で削除する
/// - それ以外（ifindex 違い・別の別名・再照会の失敗）: 差し替えと判断し、削除せず `Unknown` で報告する
///
/// 削除は常に ifindex 指定で、名前では削除しない。
fn rollback_unstamped(
    ops: &impl NetworkOps,
    bridge: &IfName,
    token: &str,
    index: IfIndex,
    report: &mut RollbackReport,
) {
    match ops.link_state(bridge) {
        Err(e) if e.code() == NetErrorCode::NotFound => {}
        Ok((i, Some(alias))) if i == index && alias == token => {
            rollback_bridge(ops, bridge, token, index, report);
        }
        Ok((i, alias)) if i == index && alias.as_deref().is_none_or(str::is_empty) => {
            match ops.delete_bridge(index) {
                Ok(()) => report.removed.push(NetworkResource::Bridge(bridge.clone())),
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
        _ => report.leftover.push((
            NetworkResource::Bridge(bridge.clone()),
            ResourceState::Unknown,
        )),
    }
}

/// 作成手順本体（OS 非依存。`ops` を差し替えて 3 OS で単体テストできる）。
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn create_network_with(
    ops: &impl NetworkOps,
    spec: &NetworkCreateSpec,
) -> Result<CreatedNetwork, NetworkCreateError> {
    // 所有トークンは名前の導出より前に発行し、DeriveNames 以外の全失敗経路で回収用の請求書
    // （`NetworkCreateError::reclaim_claim`。#2467）へ引き継ぐ。
    let token = ownership_token(spec.name());
    let fail = |error, step, rollback| NetworkCreateError {
        error,
        step,
        rollback,
        owner_token: Some(Box::new((spec.name().clone(), token.clone()))),
    };
    let names = NetworkResourceNames::derive(spec.name()).map_err(|error| NetworkCreateError {
        error,
        step: CreateStep::DeriveNames,
        rollback: RollbackReport::default(),
        owner_token: None,
    })?;
    let bridge = names.bridge().clone();
    let table = names.table().clone();

    // 1. bridge 作成。カーネルは作成時の IFLA_IFALIAS を反映しないため、この要求では所有を刻まない。
    // AlreadyExists は他者のリソースなので削除しない。確定的な拒否以外（送信後の応答エラー等）は
    // 作成済みの可能性があるため Unknown で報告する。
    if let Err(e) = ops.create_bridge(&bridge) {
        let mut report = RollbackReport::default();
        if !is_definitely_rejected(e.code()) {
            report
                .leftover
                .push((NetworkResource::Bridge(bridge), ResourceState::Unknown));
        }
        return Err(fail(collision_or(e), CreateStep::CreateBridge, report));
    }

    // 2. 作成直後の ifindex と別名を引く。別名が空でなければ別者が差し替えた link なので、自分のものと
    // 確定できず削除しない（Unknown）。NotFound は残るものが無い。
    let unknown_bridge = |report: &mut RollbackReport| {
        report.leftover.push((
            NetworkResource::Bridge(bridge.clone()),
            ResourceState::Unknown,
        ));
    };
    let index = match ops.link_state(&bridge) {
        Ok((i, alias)) if alias.as_deref().is_none_or(str::is_empty) => i,
        Ok(_) => {
            let mut report = RollbackReport::default();
            unknown_bridge(&mut report);
            return Err(fail(
                NetError::new(
                    NetErrorCode::FailedPrecondition,
                    "new bridge already has an alias (link was replaced)",
                ),
                CreateStep::ResolveIndex,
                report,
            ));
        }
        Err(e) => {
            let mut report = RollbackReport::default();
            if e.code() != NetErrorCode::NotFound {
                unknown_bridge(&mut report);
            }
            return Err(fail(e, CreateStep::ResolveIndex, report));
        }
    };

    // 3. ifindex 指定の RTM_SETLINK で所有トークンを付ける。失敗・時間切れでも反映済みの可能性があるため、
    // 再照会して自分のものと確定できる場合だけ ifindex 指定で戻す。
    if let Err(e) = ops.set_owner_token(index, &token) {
        let mut report = RollbackReport::default();
        rollback_unstamped(ops, &bridge, &token, index, &mut report);
        return Err(fail(e, CreateStep::SetOwnerToken, report));
    }

    // 4. 読み戻し。名前から引き直した ifindex と別名が一致しなければ差し替えられたので、削除しない。
    if let Err(e) = ops.verify_owned(&bridge, &token, index) {
        let mut report = RollbackReport::default();
        unknown_bridge(&mut report);
        return Err(fail(e, CreateStep::ResolveIndex, report));
    }

    // 5〜7. 所有確認後の失敗は、その ifindex で bridge を削除する（address も一緒に消える）。
    // 各操作の直前にトークン一致を再確認するため、同名の別 link へ差し替えられてもそれを操作・削除しない。
    let step_fail = |e: NetError, step: CreateStep| {
        let mut report = RollbackReport::default();
        rollback_bridge(ops, &bridge, &token, index, &mut report);
        fail(e, step, report)
    };
    ensure_owned(ops, &bridge, &token, index).map_err(|e| step_fail(e, CreateStep::AddAddress))?;
    ops.add_address(index, &spec.gateway())
        .map_err(|e| step_fail(e, CreateStep::AddAddress))?;
    ensure_owned(ops, &bridge, &token, index).map_err(|e| step_fail(e, CreateStep::SetUp))?;
    ops.set_up(index)
        .map_err(|e| step_fail(e, CreateStep::SetUp))?;

    // 8. nft テーブル。バッチは all-or-nothing のため、Unknown 以外は nft 側に何も残らない。
    if let Err(f) = ops.apply_nft(&table, &token) {
        let mut report = RollbackReport::default();
        rollback_bridge(ops, &bridge, &token, index, &mut report);
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
        bridge_token: token,
        table,
        gateway: spec.gateway(),
        name_resolution: spec.name_resolution(),
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
    fn create_bridge(&self, name: &IfName) -> Result<(), NetError> {
        self.route
            .create_link(&LinkCreate::bridge(name.clone()), self.timeout)
            .map(|_| ())
    }

    fn link_state(&self, name: &IfName) -> Result<(IfIndex, Option<String>), NetError> {
        self.route.link_index_alias(name, self.timeout)
    }

    fn set_owner_token(&self, index: IfIndex, token: &str) -> Result<(), NetError> {
        let idx = LinkIndex::new(i32::try_from(index.get()).map_err(|_| {
            NetError::new(NetErrorCode::InvalidArgument, "ifindex exceeds i32::MAX")
        })?)?;
        self.route
            .set_link(
                &LinkSet::set_alias(LinkRef::Index(idx), token)?,
                self.timeout,
            )
            .map(|_| ())
    }

    fn verify_owned(&self, name: &IfName, token: &str, index: IfIndex) -> Result<(), NetError> {
        let now = self.route.link_index_owned(name, token, self.timeout)?;
        if now == index {
            Ok(())
        } else {
            Err(NetError::new(
                NetErrorCode::FailedPrecondition,
                "link ifindex changed (link was replaced)",
            ))
        }
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

    fn apply_nft(&self, table: &NftName, token: &str) -> Result<(), NftApplyFailure> {
        self.nft
            .send_batch(self.timeout, |batch| {
                batch.push_with(|seq| {
                    TableCreate::new(NftFamily::Ipv4, table.clone())
                        .exclusive()
                        .with_userdata(token.as_bytes())?
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

// ---------------------------------------------------------------------------
// コンテナ接続（netns 作成・veth 作成 / attach。TASK-139.2.1・#847）
// ---------------------------------------------------------------------------

/// veth の host 側名のプレフィックス。
const VETH_HOST_PREFIX: &str = "fcvh";
/// veth の peer（コンテナ）側名のプレフィックス。
const VETH_PEER_PREFIX: &str = "fcvp";

/// 検証済みのエンドポイント ID（コンテナ 1 つの接続口の識別子。REPAIR-2）。`NetworkName` と同じ文字種規則
/// （1〜64 バイト、先頭 `[a-z0-9]`、以降 `[a-z0-9_.-]`）で、netns の pin ファイル名にそのまま使う。
/// ホスト全体で一意であること（veth 名は ID だけから導出する）は呼び出し側（状態レジストリ）の責務。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EndpointId(String);

impl EndpointId {
    /// 検証して作る。違反は `InvalidArgument`（入力値はメッセージに載せない）。
    pub fn new(id: &str) -> Result<Self, NetError> {
        match name_fault(id) {
            Some(NameFault::Length) => Err(invalid("endpoint id length must be 1 to 64 bytes")),
            Some(NameFault::Chars) => Err(invalid("endpoint id contains invalid characters")),
            None => Ok(Self(id.to_owned())),
        }
    }

    /// ID を返す。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// エンドポイント ID から導出した veth の名前。
///
/// host 側 `fcvh` + FNV-1a 64bit の下位 44bit を小文字 hex 11 桁、peer 側 `fcvp` + 同じ 11 桁
/// （いずれも 15 バイトで `IFNAMSIZ` 未満）。bridge 名と同じく、プレフィックス・ハッシュ関数・桁数は
/// 互換性に関わる契約で、変更すると既存コンテナの veth を名前で辿れなくなる（`delete_network`（TASK-139.4）が
/// 同じ名前を再導出する）。異なる ID のハッシュ衝突は `NLM_F_EXCL` の `AlreadyExists` として検出される。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VethNames {
    host: IfName,
    peer: IfName,
}

impl VethNames {
    /// 決定的に導出する。
    pub fn derive(endpoint: &EndpointId) -> Result<Self, NetError> {
        let hash = fnv1a64(endpoint.as_str().as_bytes()) & ((1u64 << 44) - 1);
        Ok(Self {
            host: IfName::new(&format!("{VETH_HOST_PREFIX}{hash:011x}"))?,
            peer: IfName::new(&format!("{VETH_PEER_PREFIX}{hash:011x}"))?,
        })
    }

    /// host 側（bridge に接続する側）の名前。
    pub fn host(&self) -> &IfName {
        &self.host
    }

    /// peer 側（コンテナの netns へ移す側）の名前。
    pub fn peer(&self) -> &IfName {
        &self.peer
    }
}

/// コンテナ接続の入力（検証済み）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerAttachSpec {
    endpoint: EndpointId,
    bridge: IfName,
    bridge_index: IfIndex,
    bridge_token: String,
    netns_dir: PathBuf,
    network: NetworkName,
    gateway: IpPrefix,
    table: NftName,
    ports: Vec<PortPublish>,
}

impl ContainerAttachSpec {
    /// `network` は `create_network`（Linux のみ）が返したネットワーク。`netns_dir` は netns の pin を置く
    /// ディレクトリの絶対パス（所有者・権限の検査は作成時に行う。`crate::netns`）。
    /// 相対パスは `InvalidArgument`。
    pub fn new(
        endpoint: EndpointId,
        network: &CreatedNetwork,
        netns_dir: PathBuf,
    ) -> Result<Self, NetError> {
        if !netns_dir.is_absolute() {
            return Err(invalid("netns directory must be an absolute path"));
        }
        Ok(Self {
            endpoint,
            bridge: network.bridge.clone(),
            bridge_index: network.bridge_index,
            bridge_token: network.bridge_token.clone(),
            netns_dir,
            network: network.name.clone(),
            gateway: network.gateway,
            table: network.table.clone(),
            ports: Vec::new(),
        })
    }

    /// ポート公開の指定を加える（既定は公開なし）。件数が [`MAX_PORT_PUBLISHES`] を超える、または
    /// 同じ受け口（プロトコル・host アドレス・host ポート）が重複していれば `InvalidArgument`
    /// （上限を検証してから保持する）。他コンテナ・他ネットワークとの受け口の競合は
    /// `attach_container` が [`PortRegistry`] で投入前に検出して接続を失敗させる。
    pub fn with_port_publishes(mut self, ports: Vec<PortPublish>) -> Result<Self, NetError> {
        if ports.len() > MAX_PORT_PUBLISHES {
            return Err(invalid("too many port publishes"));
        }
        for (i, p) in ports.iter().enumerate() {
            if ports.iter().skip(i + 1).any(|q| p.same_listener(q)) {
                return Err(invalid("duplicate port publish listener"));
            }
        }
        self.ports = ports;
        Ok(self)
    }

    /// 公開指定。
    pub fn port_publishes(&self) -> &[PortPublish] {
        &self.ports
    }

    /// エンドポイント ID。
    pub fn endpoint(&self) -> &EndpointId {
        &self.endpoint
    }

    /// netns の pin 先パス（`netns_dir` 直下に ID 名のファイル）。
    pub fn netns_path(&self) -> PathBuf {
        self.netns_dir.join(self.endpoint.as_str())
    }
}

/// 接続に成功したコンテナ。`N` は netns ハンドル（Linux では `crate::netns::ContainerNetns`）。
///
/// peer 側は netns へ移動済みで、netns 内で `lo` と peer が up、払い出しアドレスの付与と default route
/// （gateway = bridge アドレス）の設定、およびポート公開指定の DNAT 投入まで済んでいる
/// （TASK-139.3・#316）。`eth0` へのリネームは未実施（REPAIR-3）。
#[derive(Debug)]
#[non_exhaustive]
pub struct AttachedContainer<N> {
    /// エンドポイント ID。
    pub endpoint: EndpointId,
    /// host 側 veth の名前。
    pub host_veth: IfName,
    /// host 側 veth の ifindex（bridge に接続済みで up）。
    pub host_index: IfIndex,
    /// host 側 veth の `IFLA_IFALIAS` に付けた所有トークン。ifindex は再利用されうるため、削除直前に
    /// このトークンの一致で元の veth であることを確認する（`delete_network`。TASK-139.4・NET-1）。
    pub host_token: String,
    /// コンテナ netns に入った peer 側 veth の名前（netns 内での名前。リネーム前）。
    pub peer_veth: IfName,
    /// netns の pin 先パス。
    pub netns_path: PathBuf,
    /// 静的 IPAM で払い出し、netns 内の peer へ設定したアドレス。
    pub address: IpPrefix,
    /// netns ハンドル（fd を保持する。解放は pin の unpin）。
    pub netns: N,
    /// attach 時のポート公開で投入した DNAT ルールのハンドル（`ContainerAttachSpec` の公開指定の順。
    /// 個別の解除は `unpublish_container_port`。指定が無ければ空。NET-3・#2839）。
    pub published_ports: Vec<PublishedPort>,
}

impl<N> AttachedContainer<N> {
    /// 請求書の記録の `pin=` 行の値（この接続の pin の識別子。特定できなければ `-`）。成功した接続の請求書の
    /// 記録を試験で組むための口で、記録を信頼する根拠にはならない（回収側が所有記録と照合する。NET-1・#2681）。
    pub fn netns_pin_record_value(&self) -> String {
        attach_claim::pin_record_value(&self.netns_path)
    }
}

/// 失敗した手順。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AttachStep {
    /// veth 名の導出。
    DeriveNames,
    /// 接続先 bridge の名前と ifindex の一致確認。
    VerifyBridge,
    /// netns の作成と pin。
    CreateNetns,
    /// veth ペアの作成。
    CreateVeth,
    /// 作成直後の veth の ifindex 解決。
    ResolveIndex,
    /// host 側 veth への所有トークン（`IFLA_IFALIAS`）の付与。
    SetOwnerToken,
    /// host 側の bridge への接続（`IFLA_MASTER`）。
    SetMaster,
    /// host 側の up。
    SetUp,
    /// peer 側の netns への移動。
    MoveToNetns,
    /// 静的 IPAM によるアドレス払い出し（対応しない IPAM なら資源を作る前に失敗する）。
    AllocateAddress,
    /// netns 内の `lo` の up。
    ConfigureLoopback,
    /// netns 内での peer 側 veth の ifindex 解決（移動で変わりうる）。
    ResolvePeer,
    /// netns 内の peer へのアドレス付与。
    AddAddress,
    /// netns 内の peer 側の up。
    PeerUp,
    /// netns 内の default route 設定。
    DefaultRoute,
    /// ポート公開（DNAT ルール）の投入。
    PublishPorts,
}

/// ロールバック対象のリソース。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AttachResource {
    /// veth ペア（host 側の名前。peer 側は同時に消える）。
    Veth(IfName),
    /// pin 済みの netns（pin 先パス）。
    Netns(PathBuf),
    /// ポート公開の DNAT ルールを投入した nft テーブル（結果不明のバッチ。個別削除の手段が無く、
    /// `delete_network` がテーブルごと解放する。TASK-139.4）。
    PortRules(NftName),
    /// 払い出し済みのまま保持している IPAM アドレス（`PortRules` が不明な間は、残った DNAT ルールが
    /// 別コンテナへ転送しないよう再利用させない〔quarantine〕。解放は `delete_network` が、テーブルの削除を確認
    /// できた場合に行う）。
    Address(IpPrefix),
    /// 解放に失敗したポート予約（共有予約表のロック・読み書きの失敗。残ったままだと後続コンテナが
    /// 同じポートを公開できない。呼び出し側が `PortRegistry::release` を再試行する）。
    PortReservation(NetworkName, EndpointId),
}

/// コンテナ接続のロールバック結果。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct AttachRollbackReport {
    /// 削除に成功したリソース。
    pub removed: Vec<AttachResource>,
    /// 取り残したリソースとその状態（結果不明は fail-closed で削除せず `Unknown`）。
    pub leftover: Vec<(AttachResource, ResourceState)>,
}

/// 回収用の請求書の元になる、接続の所有情報（[`ContainerAttachError`] の非公開フィールド）。
#[derive(Debug, Clone, PartialEq, Eq)]
struct AttachOwner {
    network: NetworkName,
    token: String,
    endpoint: EndpointId,
    generation: String,
    /// 失敗の時点で控えた取り残し pin の実体の識別子（請求書の生成時に採り直さない）。
    pin: Option<attach_claim::PinIdentity>,
}

/// コンテナ接続の失敗（元のエラー・失敗手順・ロールバック結果。ERR-1）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ContainerAttachError {
    /// 失敗の原因（ロールバック失敗では上書きしない）。
    pub error: NetError,
    /// 失敗した手順。
    pub step: AttachStep,
    /// ロールバックの結果。
    pub rollback: AttachRollbackReport,
    /// この接続のネットワーク名・bridge の所有トークン・endpoint。回収用の請求書
    /// （[`FailedAttachClaim`]）の元になるためだけに保持し、公開しない（#2681）。
    /// `Err` の型を大きくしないため Box にする。
    owner: Option<Box<AttachOwner>>,
}

impl ContainerAttachError {
    /// 取り残した資源（`rollback.leftover`）の回収用の請求書。取り残しが無ければ `None`。
    /// quarantine（アドレス・DNAT ルール・ポート予約）はプロセス内の保持で、カーネル側の回収対象ではない。
    pub fn reclaim_claim(&self) -> Option<FailedAttachClaim> {
        let o = &**self.owner.as_ref()?;
        FailedAttachClaim::from_error(
            &o.network,
            &o.token,
            &o.endpoint,
            &o.generation,
            o.pin,
            self,
        )
    }

    /// 機械可読な分類。
    pub fn code(&self) -> NetErrorCode {
        self.error.code()
    }

    /// 英語のメッセージ。
    pub fn message(&self) -> &str {
        self.error.message()
    }
}

impl fmt::Display for ContainerAttachError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.error.fmt(f)
    }
}

impl std::error::Error for ContainerAttachError {}

/// netns 作成の失敗。作成途中の残骸が残りうるかを `leftover` で伝える。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NetnsFailure {
    /// 失敗の原因。
    pub(crate) error: NetError,
    /// 取り残した pin の状態。何も残していなければ `None`。
    /// `Present`: 後始末（ファイル削除）に失敗した。`Unknown`: 時間切れ等で mount の有無が不明
    /// （fail-closed のため削除しない）。
    pub(crate) leftover: Option<ResourceState>,
}

/// pin 解除の失敗。解除できなかった netns ハンドルを手放さず、再試行できるよう呼び出し側へ返す。
#[derive(Debug)]
pub(crate) struct UnpinFailure<N> {
    /// 失敗の原因。
    pub(crate) error: NetError,
    /// 解除できなかった netns ハンドル（fd と pin パスを保持したまま）。
    pub(crate) netns: N,
}

/// 接続ごとの世代識別子の長さ（小文字 16 進。128 bit）。
pub(crate) const GENERATION_LEN: usize = 32;

/// 接続ごとの世代識別子を作る（時刻 ns・PID・プロセス内連番。各 16 進 16・8・8 桁）。
///
/// 同じ endpoint を再接続しても別の値になり、host 側 veth の所有トークンと取り残しの請求書に載せて
/// 「どの接続の資源か」を区別する（古い請求書を新しい接続の veth へ適用して正常な veth を消さないため。
/// NET-1・#2681）。暗号論的な乱数ではない（敵対者への耐性ではなく、並行する回収との取り違えの防止が目的）。
pub(crate) fn new_generation() -> String {
    use std::sync::atomic::{AtomicU32, Ordering};
    static SEQ: AtomicU32 = AtomicU32::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    format!(
        "{nanos:016x}{:08x}{:08x}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    )
}

/// 世代識別子の形式（小文字 16 進のちょうど [`GENERATION_LEN`] 桁）を満たすか。
pub(crate) fn is_valid_generation(g: &str) -> bool {
    g.len() == GENERATION_LEN && g.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// host 側 veth の所有トークン（`IFLA_IFALIAS`）を、ネットワークの所有トークン・endpoint・接続の世代から導出する。
///
/// 接続（`attach_container`）が刻み、削除（`delete_network`。TASK-139.4・NET-1）が形式を再検証して照合する
/// （呼び出し側が渡す `AttachedContainer::host_token` をそのまま所有の証明に使わないため）。世代を含めるのは、
/// 同じ endpoint の再接続で同じトークンになると、古い請求書が新しい正常な veth に一致してしまうため（#2681）。
/// 形式は `<bridge_token>/ep/<endpoint>/g/<世代>`。
pub(crate) fn host_owner_token(
    bridge_token: &str,
    endpoint: &EndpointId,
    generation: &str,
) -> String {
    format!("{bridge_token}/ep/{}/g/{generation}", endpoint.as_str())
}

/// `token` が、このネットワーク・endpoint の発行形式（世代が正しい形式）か。世代の値そのものは問わない。
/// `delete_network` が呼び出し側の渡した `host_token` の出自を検査するのに使う。
pub(crate) fn host_token_is_for(bridge_token: &str, endpoint: &EndpointId, token: &str) -> bool {
    token
        .strip_prefix(bridge_token)
        .and_then(|r| r.strip_prefix("/ep/"))
        .and_then(|r| r.strip_prefix(endpoint.as_str()))
        .and_then(|r| r.strip_prefix("/g/"))
        .is_some_and(is_valid_generation)
}

/// attach の前に作って pin した netns（#2675・NET-1・CRI-2・PLUG-1）。
///
/// `create_container_netns` が作り、`attach_prepared_container` が使う。CRI の POD モードは「netns が
/// コンテナの作成より前に存在する」ため、`attach_container` が netns の作成を内部で行う形とは別に、作成だけを
/// 先に行える入口として持つ。pin のファイルと fd を所有し、手放すときは `release_container_netns`
/// （unpin）か attach の成功（以後は `AttachedContainer::netns` が所有）で行う。**Drop では unpin しない**
/// （pin は mount でプロセスの外に残るため。放置すると pin が残る。呼び出し側が必ず解放すること）。
/// 未 attach の間は netns 内の route ソケットを fd として 1 本保持する（件数は呼び出し側の上限で有界）。
#[derive(Debug)]
pub struct PreparedNetns<N> {
    netns: N,
    pin_dir_id: (u64, u64),
    endpoint: EndpointId,
    dir: PathBuf,
}

impl<N> PreparedNetns<N> {
    /// このエンドポイント ID 用の netns。
    pub fn endpoint(&self) -> &EndpointId {
        &self.endpoint
    }

    /// pin 先のパス（`<置き場>/<エンドポイント ID>`）。
    pub fn pin_path(&self) -> PathBuf {
        self.dir.join(self.endpoint.as_str())
    }
}

/// 解除の失敗（原因と、解除できなかった netns）。`Err` を小さく保つため Box。
type ReleaseFailure<N> = Box<(NetError, PreparedNetns<N>)>;

/// 接続手順の失敗（原因と、事前作成の netns を使った場合に unpin せず返すその netns）。`Err` を小さく保つため Box。
type AttachFailure<N> = Box<(ContainerAttachError, Option<PreparedNetns<N>>)>;

/// 事前作成した netns を unpin する（未 attach のまま不要になったとき）。失敗時はハンドルを返して再試行できる。
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn release_prepared_with<O: AttachOps>(
    ops: &O,
    prepared: PreparedNetns<O::Netns>,
) -> Result<(), ReleaseFailure<O::Netns>> {
    let PreparedNetns {
        netns,
        pin_dir_id,
        endpoint,
        dir,
    } = prepared;
    ops.unpin_netns(netns).map_err(|f| {
        Box::new((
            f.error,
            PreparedNetns {
                netns: f.netns,
                pin_dir_id,
                endpoint,
                dir,
            },
        ))
    })
}

/// 接続手順が使うカーネル操作の境界。Linux 実装とテストの fake を差し替えるための crate 内部トレイトで、
/// 公開の拡張点（PLUG-1）ではない。[`NetworkOps`] とは独立（ネットワーク作成のテストに影響させない）。
pub(crate) trait AttachOps {
    /// netns ハンドル（Linux では fd と pin パス）。
    type Netns;
    /// `dir` 直下に `id` 名で pin した新しい netns を作る。失敗時は自分が作った部分資源を片付けてある。
    /// 成功時は netns ハンドルと、検査して開いた置き場ディレクトリの識別子 (st_dev, st_ino) を返す。
    /// 識別子は IPAM へ記録し、`delete_network` が置き場の差し替えを検出するのに使う（TASK-139.4）。
    fn create_netns(
        &self,
        dir: &Path,
        id: &EndpointId,
    ) -> Result<(Self::Netns, (u64, u64)), NetnsFailure>;
    /// pin を外す（umount → ファイル削除）。失敗時は `ns` を [`UnpinFailure`] で返し、呼び出し側が
    /// 再試行できるようにする。
    fn unpin_netns(&self, ns: Self::Netns) -> Result<(), UnpinFailure<Self::Netns>>;
    /// veth ペアを `NLM_F_EXCL` で作る。
    fn create_veth(&self, host: &IfName, peer: &IfName) -> Result<(), NetError>;
    /// 名前から ifindex を引く。
    fn link_index(&self, name: &IfName) -> Result<IfIndex, NetError>;
    /// bridge の名前から ifindex を引く。`IFLA_IFALIAS` が `token` と一致しない（同名の別 link）
    /// 場合は `FailedPrecondition` で失敗する。
    fn owned_bridge_index(&self, name: &IfName, token: &str) -> Result<IfIndex, NetError>;
    /// `link` の `IFLA_IFALIAS` に所有トークン `token` を設定する。
    fn set_owner_token(&self, link: IfIndex, token: &str) -> Result<(), NetError>;
    /// `link` を `master`（bridge）へ接続する。
    fn set_master(&self, link: IfIndex, master: IfIndex) -> Result<(), NetError>;
    /// ifindex 指定で up にする。
    fn set_up(&self, link: IfIndex) -> Result<(), NetError>;
    /// ifindex 指定で `ns` へ移動する。
    fn move_to_netns(&self, link: IfIndex, ns: &Self::Netns) -> Result<(), NetError>;
    /// ifindex 指定で link を削除する（veth は peer も一緒に消える）。
    fn delete_link(&self, link: IfIndex) -> Result<(), NetError>;
    /// `ns` の中で名前から ifindex を引く。
    fn netns_link_index(&self, ns: &Self::Netns, name: &IfName) -> Result<IfIndex, NetError>;
    /// `ns` の中で ifindex 指定で up にする。
    fn netns_set_up(&self, ns: &Self::Netns, link: IfIndex) -> Result<(), NetError>;
    /// `ns` の中で `link` にアドレスを付与する。
    fn netns_add_address(
        &self,
        ns: &Self::Netns,
        link: IfIndex,
        addr: IpPrefix,
    ) -> Result<(), NetError>;
    /// `ns` の中に `0.0.0.0/0 via gateway dev oif` を追加する。
    fn netns_add_default_route(
        &self,
        ns: &Self::Netns,
        gateway: Ipv4Addr,
        oif: IfIndex,
    ) -> Result<(), NetError>;
    /// 接続成功時に netns 内の route ソケットを閉じる（fd を常駐させない。CORE-9）。
    fn release_netns_socket(&self, ns: &mut Self::Netns);
    /// `table` の `prerouting` / `output` へ DNAT ルールを 1 バッチで投入する。
    /// 戻り値は `ports` と同じ順の `(prerouting, output)` のルールハンドル（echo 応答。NET-3）。
    fn publish_ports(
        &self,
        table: &NftName,
        container: Ipv4Addr,
        ports: &[PortPublish],
    ) -> Result<Vec<RuleHandlePair>, NftApplyFailure>;
}

/// 公開 1 件の DNAT ルール 2 本の `(prerouting, output)` のハンドル。
pub(crate) type RuleHandlePair = (NftRuleHandle, NftRuleHandle);

/// pin を外し、結果をロールバック報告へ載せる。
fn rollback_netns<O: AttachOps>(
    ops: &O,
    ns: O::Netns,
    pin: &Path,
    report: &mut AttachRollbackReport,
) {
    match ops.unpin_netns(ns) {
        Ok(()) => report.removed.push(AttachResource::Netns(pin.to_owned())),
        // ハンドルはここで手放すが、pin のマウントは fd と独立に残るため、同じプロセス内なら報告した
        // pin パスから `netns::unpin_path`（公開・冪等。所有記録のある pin だけを扱う）で解除をやり直せる。
        Err(UnpinFailure { error, netns }) => {
            drop(netns);
            let state = if is_indeterminate(error.code()) {
                ResourceState::Unknown
            } else {
                ResourceState::Present
            };
            report
                .leftover
                .push((AttachResource::Netns(pin.to_owned()), state));
        }
    }
}

/// 作成直後に確保した ifindex 指定で veth を削除する。`Timeout` / `DataLoss` は適用済みか不明なので
/// `Unknown`、それ以外の失敗は存在が分かっているので `Present` で報告する。
fn rollback_veth<O: AttachOps>(
    ops: &O,
    host: &IfName,
    index: IfIndex,
    report: &mut AttachRollbackReport,
) {
    match ops.delete_link(index) {
        Ok(()) => report.removed.push(AttachResource::Veth(host.clone())),
        Err(e) => {
            let state = if is_indeterminate(e.code()) {
                ResourceState::Unknown
            } else {
                ResourceState::Present
            };
            report
                .leftover
                .push((AttachResource::Veth(host.clone()), state));
        }
    }
}

/// 接続手順本体（OS 非依存。`ops` を差し替えて 3 OS で単体テストできる）。
///
/// 手順: 名前導出 → bridge の名前 ↔ ifindex 確認 → netns 作成 → veth 作成 → 作成直後に両端の ifindex を
/// 名前から解決 → host 側を bridge へ接続 → host 側 up → peer 側を netns へ移動 → アドレス払い出し（IPAM。
/// 失敗時も veth・netns を戻し、IPAM の状態は変えない）→ netns 内設定（`lo` up・peer へのアドレス付与と up・
/// default route。TASK-139.3）→ ポート公開（指定があれば DNAT を一括投入）。失敗時は自分が作った
/// 部分資源（veth・netns・IPAM の払い出し）だけを戻し、元のエラーはロールバックの失敗で上書きしない。
///
/// veth も bridge と同じく作成時に `IFLA_IFALIAS` を付けられない（カーネルが反映しない。`LinkCreate::bridge` の doc）ため、
/// 「`NLM_F_EXCL` 作成 + 直後の ifindex 確保 + `RTM_SETLINK` で所有トークンを刻む + 以降は ifindex 指定」で
/// 運用する。作成から解決・刻印までの極小の窓に同名 link へ差し替えられる残余リスクは残る
/// （`CAP_NET_ADMIN` を持つ者に限られる）。削除側はトークンの一致を確認してから消す（ifindex は再利用されうる）。
/// ifindex を解決できなかった場合は名前では削除せず `Unknown` で報告する（fail-closed）。
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn attach_container_with<O: AttachOps>(
    ops: &O,
    spec: &ContainerAttachSpec,
    ipam: &mut StaticIpam,
    ports: &mut PortRegistry,
) -> Result<AttachedContainer<O::Netns>, ContainerAttachError> {
    attach_container_with_generation(ops, spec, ipam, ports, &new_generation())
}

/// [`attach_container_with`] の本体。接続の世代識別子を呼び出し側から受ける（attach の試行ごとに発行するため
/// spec には持たせない。テストでは固定値を渡す）。世代は veth の所有トークンと取り残しの請求書に載る
/// （NET-1・#2681）。
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn attach_container_with_generation<O: AttachOps>(
    ops: &O,
    spec: &ContainerAttachSpec,
    ipam: &mut StaticIpam,
    ports: &mut PortRegistry,
    generation: &str,
) -> Result<AttachedContainer<O::Netns>, ContainerAttachError> {
    attach_with_source(ops, spec, None, ipam, ports, generation).map_err(|failure| failure.0)
}

/// 事前に作って pin した netns へ接続する版の手順本体（#2675・NET-1・CRI-2）。
///
/// [`attach_container_with`] との違いは netns を作らず `prepared` を使うことだけで、後半（veth・アドレス・
/// route・DNAT）は同じ。失敗時は veth・IPAM の払い出し・受け口の予約を同じ規則で戻すが、**netns は unpin せず**
/// 呼び出し側へ返す（netns の寿命は事前に作った側が持つ。`PreparedNetns` の doc）。世代は試行ごとに呼び出し側が
/// 発行する（[`attach_container_with_generation`] と同じ。#2681）。
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn attach_prepared_with<O: AttachOps>(
    ops: &O,
    spec: &ContainerAttachSpec,
    prepared: PreparedNetns<O::Netns>,
    ipam: &mut StaticIpam,
    ports: &mut PortRegistry,
    generation: &str,
) -> Result<AttachedContainer<O::Netns>, AttachFailure<O::Netns>> {
    attach_with_source(ops, spec, Some(prepared), ipam, ports, generation)
}

/// [`attach_container_with`]・[`attach_prepared_with`] の共通本体。`source` が `Some` なら netns を作らず、
/// 失敗時はその netns を unpin せずに返す。世代は veth の所有トークンと取り残しの請求書に載る（#2681）。
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn attach_with_source<O: AttachOps>(
    ops: &O,
    spec: &ContainerAttachSpec,
    source: Option<PreparedNetns<O::Netns>>,
    ipam: &mut StaticIpam,
    ports: &mut PortRegistry,
    generation: &str,
) -> Result<AttachedContainer<O::Netns>, AttachFailure<O::Netns>> {
    let fail = |error, step, rollback: AttachRollbackReport| {
        // 取り残した pin の識別子は、この失敗の時点で控える（請求書の生成時に採り直さない。NET-1）。
        let pin = rollback
            .leftover
            .iter()
            .find_map(|(r, _)| match r {
                AttachResource::Netns(path) => Some(path.as_path()),
                _ => None,
            })
            .and_then(attach_claim::pin_identity_of);
        ContainerAttachError {
            error,
            step,
            rollback,
            owner: Some(Box::new(AttachOwner {
                network: spec.network.clone(),
                token: spec.bridge_token.clone(),
                endpoint: spec.endpoint.clone(),
                generation: generation.to_owned(),
                pin,
            })),
        }
    };
    // 事前作成の netns が別のエンドポイント・置き場のものなら、何も作らず拒否して返す。
    if let Some(p) = &source
        && (p.endpoint != spec.endpoint || p.dir != spec.netns_dir)
    {
        return Err(Box::new((
            fail(
                NetError::new(
                    NetErrorCode::FailedPrecondition,
                    "prepared netns does not belong to this endpoint",
                ),
                AttachStep::CreateNetns,
                AttachRollbackReport::default(),
            ),
            source,
        )));
    }
    // 何かを作る前の検査（すべて読み取りのみ）。失敗時は `source` をそのまま返す。
    let precheck = || -> Result<(VethNames, Ipv4Addr), (NetError, AttachStep)> {
        let names = VethNames::derive(&spec.endpoint).map_err(|e| (e, AttachStep::DeriveNames))?;
        // default route の gateway（bridge アドレス）は IPv4 に限る。
        let IpAddr::V4(gateway) = spec.gateway.addr() else {
            return Err((
                NetError::new(
                    NetErrorCode::FailedPrecondition,
                    "network gateway is not an IPv4 address",
                ),
                AttachStep::DefaultRoute,
            ));
        };
        // 別ネットワークの IPAM を渡す誤用は止める。
        if ipam.network() != &spec.network || ipam.gateway() != spec.gateway {
            return Err((
                NetError::new(
                    NetErrorCode::FailedPrecondition,
                    "ipam pool does not belong to this network",
                ),
                AttachStep::AllocateAddress,
            ));
        }
        // 接続先が作成時の bridge のままであることを確認する。
        match ops.owned_bridge_index(&spec.bridge, &spec.bridge_token) {
            Ok(i) if i == spec.bridge_index => Ok((names, gateway)),
            Ok(_) => Err((
                NetError::new(
                    NetErrorCode::FailedPrecondition,
                    "bridge ifindex changed (network was replaced)",
                ),
                AttachStep::VerifyBridge,
            )),
            Err(e) => Err((e, AttachStep::VerifyBridge)),
        }
    };
    let (names, gateway) = match precheck() {
        Ok(v) => v,
        Err((e, step)) => {
            return Err(Box::new((
                fail(e, step, AttachRollbackReport::default()),
                source,
            )));
        }
    };

    let pin = spec.netns_path();
    // 事前作成の netns を使う場合は、失敗しても unpin せず呼び出し側へ返す。
    let keep_netns = source.is_some();
    let (mut netns, pin_dir_id) = match source {
        Some(p) => (p.netns, p.pin_dir_id),
        None => match ops.create_netns(&spec.netns_dir, &spec.endpoint) {
            Ok(created) => created,
            Err(f) => {
                let mut report = AttachRollbackReport::default();
                if let Some(state) = f.leftover {
                    report.leftover.push((AttachResource::Netns(pin), state));
                }
                return Err(Box::new((
                    fail(f.error, AttachStep::CreateNetns, report),
                    None,
                )));
            }
        },
    };
    let give_back = |netns: O::Netns| PreparedNetns {
        netns,
        pin_dir_id,
        endpoint: spec.endpoint.clone(),
        dir: spec.netns_dir.clone(),
    };

    // 以降の失敗は、veth の後始末（あれば）→ netns の unpin の順で戻す（事前作成の netns は unpin せず返す）。
    let abort =
        |netns: O::Netns, mut report: AttachRollbackReport, error: NetError, step: AttachStep| {
            let back = if keep_netns {
                Some(give_back(netns))
            } else {
                rollback_netns(ops, netns, &pin, &mut report);
                None
            };
            Box::new((fail(error, step, report), back))
        };

    if let Err(e) = ops.create_veth(names.host(), names.peer()) {
        let mut report = AttachRollbackReport::default();
        // 確定的な拒否（`AlreadyExists` 含む）以外は作成済みの可能性があるため Unknown で報告する。
        if !is_definitely_rejected(e.code()) {
            report.leftover.push((
                AttachResource::Veth(names.host().clone()),
                ResourceState::Unknown,
            ));
        }
        return Err(abort(
            netns,
            report,
            veth_collision_or(e),
            AttachStep::CreateVeth,
        ));
    }

    let resolved = ops
        .link_index(names.host())
        .and_then(|host| ops.link_index(names.peer()).map(|peer| (host, peer)));
    let (host_index, peer_index) = match resolved {
        Ok(pair) => pair,
        Err(e) => {
            let mut report = AttachRollbackReport::default();
            report.leftover.push((
                AttachResource::Veth(names.host().clone()),
                ResourceState::Unknown,
            ));
            return Err(abort(netns, report, e, AttachStep::ResolveIndex));
        }
    };

    // ifindex は再利用されうるため、削除時に元の veth と照合できるよう所有トークンを刻む。
    let host_token = host_owner_token(&spec.bridge_token, &spec.endpoint, generation);
    let attach = || {
        ops.set_owner_token(host_index, &host_token)
            .map_err(|e| (e, AttachStep::SetOwnerToken))?;
        ops.set_master(host_index, spec.bridge_index)
            .map_err(|e| (e, AttachStep::SetMaster))?;
        ops.set_up(host_index).map_err(|e| (e, AttachStep::SetUp))?;
        ops.move_to_netns(peer_index, &netns)
            .map_err(|e| (e, AttachStep::MoveToNetns))
    };
    if let Err((error, step)) = attach() {
        let mut report = AttachRollbackReport::default();
        rollback_veth(ops, names.host(), host_index, &mut report);
        return Err(abort(netns, report, error, step));
    }

    // netns 内でのアドレス設定の直前に払い出す。失敗時は作った資源をすべて戻す。
    // 払い出しと同時に pin 置き場（パスと識別子）を記録し、削除時に残存 pin を同じ置き場で確認できるようにする
    // （TASK-139.4）。記録は払い出しの解放（ロールバックを含む）で一緒に消える。
    let pin_dir = NetnsDirRecord::new(spec.netns_dir.clone(), pin_dir_id);
    let address = match ipam.allocate_pinned(&spec.endpoint, pin_dir) {
        Ok(a) => a,
        Err(e) => {
            let mut report = AttachRollbackReport::default();
            rollback_veth(ops, names.host(), host_index, &mut report);
            return Err(abort(netns, report, e, AttachStep::AllocateAddress));
        }
    };

    // 公開する受け口を、ルールを入れる前に予約する。他のコンテナ・ネットワークが公開済みなら
    // 接続を失敗させる（nft は重複ルールを拒否せず、後から入れた公開が機能しないため）。
    if let Err(e) = ports.reserve(&spec.network, &spec.endpoint, &spec.ports) {
        let _ = ipam.release(&spec.endpoint);
        let mut report = AttachRollbackReport::default();
        rollback_veth(ops, names.host(), host_index, &mut report);
        return Err(abort(netns, report, e, AttachStep::PublishPorts));
    }

    // netns 内の設定 → ポート公開。ここからの失敗は veth・netns を戻す（モジュール doc）。
    let published_ports =
        match configure_in_netns(ops, spec, &netns, names.peer(), address, gateway) {
            Ok(p) => p,
            Err(f) => {
                let mut report = AttachRollbackReport::default();
                if f.ports_unknown {
                    // DNAT ルールが入っている可能性がある。ルールの不存在を確認・削除できるまで、アドレスと
                    // 受け口の予約を解放しない（別コンテナへ再払い出しすると、残ったルールがそちらへ転送しうる）。
                    report.leftover.push((
                        AttachResource::PortRules(spec.table.clone()),
                        ResourceState::Unknown,
                    ));
                    report
                        .leftover
                        .push((AttachResource::Address(address), ResourceState::Unknown));
                }
                rollback_veth(ops, names.host(), host_index, &mut report);
                let back = if keep_netns {
                    Some(give_back(netns))
                } else {
                    rollback_netns(ops, netns, &pin, &mut report);
                    None
                };
                if !f.ports_unknown {
                    // veth・netns の後始末が完了したことを確認できた場合に限り、払い出しと予約を戻す。
                    // 資源が残った・結果不明の場合は、設定済みアドレスを持つ資源が生きている可能性があるため、
                    // アドレスと受け口の予約を残して `leftover` で報告する（別コンテナへの再払い出しで衝突させない。
                    // 特権操作の後始末の fail-closed）。解放は呼び出し側が資源の除去を確認してから行う。
                    if report.leftover.is_empty() {
                        let _ = ipam.release(&spec.endpoint);
                        // 公開指定が無ければ共有予約表に予約は無い。解放の失敗は予約が残るため leftover で報告する。
                        if !spec.ports.is_empty()
                            && ports.release(&spec.network, &spec.endpoint).is_err()
                        {
                            report.leftover.push((
                                AttachResource::PortReservation(
                                    spec.network.clone(),
                                    spec.endpoint.clone(),
                                ),
                                ResourceState::Present,
                            ));
                        }
                    } else {
                        report
                            .leftover
                            .push((AttachResource::Address(address), ResourceState::Unknown));
                    }
                }
                return Err(Box::new((fail(f.error, f.step, report), back)));
            }
        };
    ops.release_netns_socket(&mut netns);

    Ok(AttachedContainer {
        endpoint: spec.endpoint.clone(),
        host_veth: names.host().clone(),
        host_index,
        host_token,
        peer_veth: names.peer().clone(),
        netns_path: pin,
        address,
        netns,
        published_ports,
    })
}

/// netns 内設定・ポート公開の失敗（失敗手順と、DNAT バッチの結果が不明かどうか）。
struct ConfigureFailure {
    error: NetError,
    step: AttachStep,
    /// DNAT バッチが適用されたか不明（`Aborted` / `NotSent` 以外）。
    ports_unknown: bool,
}

/// netns 内の設定（`lo` up → peer 再解決 → アドレス付与 → peer up → default route）と、
/// 指定があればポート公開（DNAT 一括投入）を行う。呼び出し元は `attach_container_with` だけ。
fn configure_in_netns<O: AttachOps>(
    ops: &O,
    spec: &ContainerAttachSpec,
    netns: &O::Netns,
    peer: &IfName,
    address: IpPrefix,
    gateway: Ipv4Addr,
) -> Result<Vec<PublishedPort>, ConfigureFailure> {
    let step = |step: AttachStep| {
        move |error: NetError| ConfigureFailure {
            error,
            step,
            ports_unknown: false,
        }
    };
    // `lo` は up にするだけでよい。カーネルが新規 netns の loopback を up にする際に 127.0.0.1/8 を自動で
    // 付与する（`inetdev_event` の NETDEV_UP）ため、明示的な付与は `AlreadyExists` になる。
    let lo = IfName::new("lo").map_err(step(AttachStep::ConfigureLoopback))?;
    let lo_index = ops
        .netns_link_index(netns, &lo)
        .map_err(step(AttachStep::ConfigureLoopback))?;
    ops.netns_set_up(netns, lo_index)
        .map_err(step(AttachStep::ConfigureLoopback))?;
    // peer は netns への移動で ifindex が変わりうるため、移動先で名前から引き直す。
    let peer_index = ops
        .netns_link_index(netns, peer)
        .map_err(step(AttachStep::ResolvePeer))?;
    ops.netns_add_address(netns, peer_index, address)
        .map_err(step(AttachStep::AddAddress))?;
    ops.netns_set_up(netns, peer_index)
        .map_err(step(AttachStep::PeerUp))?;
    ops.netns_add_default_route(netns, gateway, peer_index)
        .map_err(step(AttachStep::DefaultRoute))?;
    if !spec.ports.is_empty() {
        let IpAddr::V4(container) = address.addr() else {
            return Err(step(AttachStep::PublishPorts)(NetError::new(
                NetErrorCode::FailedPrecondition,
                "container address is not an IPv4 address",
            )));
        };
        let handles = ops
            .publish_ports(&spec.table, container, &spec.ports)
            .map_err(|f| ConfigureFailure {
                ports_unknown: !matches!(
                    f.outcome,
                    NftBatchOutcome::Aborted | NftBatchOutcome::NotSent
                ),
                error: f.error,
                step: AttachStep::PublishPorts,
            })?;
        // ハンドルの本数が公開指定と食い違う応答は、投入結果を信用できないので結果不明として扱う（quarantine）。
        return bind_published(
            &spec.network,
            &spec.bridge_token,
            &spec.endpoint,
            &spec.ports,
            handles,
        )
        .map_err(|error| ConfigureFailure {
            error,
            step: AttachStep::PublishPorts,
            ports_unknown: true,
        });
    }
    Ok(Vec::new())
}

/// 公開指定と同じ順のハンドル列を [`PublishedPort`] に束ねる。本数の不一致は `Internal`（呼び出し側は
/// 結果不明として予約を保持する）。
fn bind_published(
    network: &NetworkName,
    bridge_token: &str,
    endpoint: &EndpointId,
    ports: &[PortPublish],
    handles: Vec<RuleHandlePair>,
) -> Result<Vec<PublishedPort>, NetError> {
    if handles.len() != ports.len() {
        return Err(NetError::new(
            NetErrorCode::Internal,
            "rule handle count does not match the port publishes",
        ));
    }
    Ok(ports
        .iter()
        .zip(handles)
        .map(|(p, h)| PublishedPort::new(network, bridge_token, endpoint, *p, h))
        .collect())
}

/// attach 後のポート公開の失敗（原因と、DNAT バッチの結果が不明かどうか）。
///
/// `rules_unknown` が真のとき、DNAT ルールが入っている可能性があるため受け口の予約を保持している
/// （quarantine）。解放は `delete_network` がテーブルごと行う（NET-1・NET-4）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct PublishPortsError {
    /// 失敗の原因。
    pub error: NetError,
    /// DNAT バッチが適用されたか不明（`Aborted` / `NotSent` 以外）、または予約を戻せていない。
    pub rules_unknown: bool,
}

impl fmt::Display for PublishPortsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.error.fmt(f)
    }
}

impl std::error::Error for PublishPortsError {}

/// 接続済みコンテナへ DNAT ルールを追加する本体（OS 非依存。呼び出し元は Linux 限定の
/// `publish_container_ports` と試験）。plugin-cri の `publish_port`（NET-4）が attach 後に
/// コンテナ単位で公開するための口。`publish` は `table`・コンテナのアドレス・受け口を受けて DNAT を投入する
/// 操作（Linux では `send_dnat_batch`）。
///
/// 手順: 件数と重複の検証 → コンテナのアドレスがネットワークのサブネット内の IPv4 であることの
/// 再確認（取り違えの多層防御）→ 受け口の予約（衝突は `AlreadyExists`。この時点では何も変えない）→
/// DNAT の 1 バッチ投入。確定的な失敗（`Aborted` / `NotSent`）では今回の予約だけを戻し、結果不明では
/// 予約を保持する。
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn publish_ports_with(
    publish: impl FnOnce(
        &NftName,
        Ipv4Addr,
        &[PortPublish],
    ) -> Result<Vec<RuleHandlePair>, NftApplyFailure>,
    network: &CreatedNetwork,
    endpoint: &EndpointId,
    container_addr: IpPrefix,
    ports: &[PortPublish],
    registry: &mut PortRegistry,
) -> Result<Vec<PublishedPort>, PublishPortsError> {
    let known = |error: NetError| PublishPortsError {
        error,
        rules_unknown: false,
    };
    if ports.is_empty() || ports.len() > MAX_PORT_PUBLISHES {
        return Err(known(NetError::new(
            NetErrorCode::InvalidArgument,
            "port publish count is out of range",
        )));
    }
    for (i, p) in ports.iter().enumerate() {
        if ports.iter().skip(i + 1).any(|q| p.same_listener(q)) {
            return Err(known(NetError::new(
                NetErrorCode::InvalidArgument,
                "duplicate port publish listener",
            )));
        }
    }
    let (IpAddr::V4(container), IpAddr::V4(gateway)) =
        (container_addr.addr(), network.gateway.addr())
    else {
        return Err(known(NetError::new(
            NetErrorCode::FailedPrecondition,
            "container address is not an IPv4 address",
        )));
    };
    let prefix = u32::from(network.gateway.prefix_len().min(32));
    let mask = u32::MAX.checked_shl(32 - prefix).unwrap_or(0);
    if u32::from(container) & mask != u32::from(gateway) & mask {
        return Err(known(NetError::new(
            NetErrorCode::FailedPrecondition,
            "container address is outside the network subnet",
        )));
    }
    registry
        .reserve(&network.name, endpoint, ports)
        .map_err(known)?;
    let handles = match publish(&network.table, container, ports) {
        Ok(h) => h,
        Err(f) => return Err(publish_failed(f, network, endpoint, ports, registry)),
    };
    // 本数の食い違いは、ルールが入っているのにハンドルを確定できない状態。結果不明として予約を保持する。
    bind_published(
        &network.name,
        &network.bridge_token,
        endpoint,
        ports,
        handles,
    )
    .map_err(|error| PublishPortsError {
        error,
        rules_unknown: true,
    })
}

/// 公開バッチの失敗を [`PublishPortsError`] へ写す（結果不明なら予約を保持し、確定失敗なら今回分を戻す）。
fn publish_failed(
    f: NftApplyFailure,
    network: &CreatedNetwork,
    endpoint: &EndpointId,
    ports: &[PortPublish],
    registry: &mut PortRegistry,
) -> PublishPortsError {
    let known = |error: NetError| PublishPortsError {
        error,
        rules_unknown: false,
    };
    if !matches!(
        f.outcome,
        NftBatchOutcome::Aborted | NftBatchOutcome::NotSent
    ) {
        // DNAT ルールが入っている可能性がある。予約は保持する（quarantine）。
        return PublishPortsError {
            error: f.error,
            rules_unknown: true,
        };
    }
    // 確定的に適用されていない。今回の予約だけを戻す。戻せなければ予約が残るため結果不明と同じ扱い
    // （fail-closed。解放は delete_network）。
    match registry.release_listeners(&network.name, endpoint, ports) {
        Ok(_) => known(f.error),
        Err(_) => PublishPortsError {
            error: f.error,
            rules_unknown: true,
        },
    }
}

/// 接続済みコンテナへ DNAT ルールを追加する（attach 後のポート公開。NET-4・NET-1）。
///
/// `ports` の受け口は `registry`（全ネットワークで共有する [`PortRegistry`]）へ予約してから
/// 専用テーブルの `prerouting` / `output` へ 1 バッチで投入する。失敗時の扱いは [`PublishPortsError`]。
/// `CAP_NET_ADMIN` が必要で、本 crate は権限を上げない。`timeout` は nft 要求の期限（REPAIR-5）。
///
/// 成功すると `ports` と同じ順の [`PublishedPort`] を返す。ルールは `NLM_F_ECHO` 付きで投入し、echo 応答の
/// ハンドルを検証して保持する（応答が欠けた・壊れた場合は結果不明として予約を保持する。NET-3・#2839）。
/// 個別の解除は [`unpublish_container_port`]。
///
/// # 未実装範囲（REPAIR-3）
/// [`PublishedPort`] のプロセス再起動後の復元は無い（`delete_network` がテーブルごと解放する）。
/// masquerade と host の `ip_forward` は別途必要。
#[cfg(target_os = "linux")]
pub fn publish_container_ports<N>(
    nft: &NetlinkNetfilterSocket,
    network: &CreatedNetwork,
    container: &AttachedContainer<N>,
    ports: &[PortPublish],
    registry: &mut PortRegistry,
    timeout: Duration,
) -> Result<Vec<PublishedPort>, PublishPortsError> {
    publish_ports_with(
        |table, addr, ports| send_dnat_batch(nft, timeout, table, addr, ports),
        network,
        &container.endpoint,
        container.address,
        ports,
        registry,
    )
}
const VETH_COLLISION_MSG: &str =
    "container veth already exists (endpoint id collision or stale endpoint; delete it first)";

fn veth_collision_or(e: NetError) -> NetError {
    if e.code() == NetErrorCode::AlreadyExists {
        NetError::new(NetErrorCode::AlreadyExists, VETH_COLLISION_MSG)
    } else {
        e
    }
}

/// Linux のカーネル実装。各要求に `timeout` を期限として渡す（REPAIR-5）。
#[cfg(target_os = "linux")]
struct LinuxAttachOps<'a> {
    route: &'a NetlinkRouteSocket,
    nft: &'a NetlinkNetfilterSocket,
    timeout: Duration,
}

#[cfg(target_os = "linux")]
impl LinuxAttachOps<'_> {
    /// netns 内の route ソケット（接続処理の途中だけ存在する）。
    fn ns_route(ns: &ContainerNetns) -> Result<&NetlinkRouteSocket, NetError> {
        ns.route_socket().ok_or_else(|| {
            NetError::new(
                NetErrorCode::FailedPrecondition,
                "netns route socket is not available",
            )
        })
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn link_ref(index: IfIndex) -> Result<LinkRef, NetError> {
    let raw = i32::try_from(index.get())
        .map_err(|_| NetError::new(NetErrorCode::InvalidArgument, "ifindex exceeds i32::MAX"))?;
    Ok(LinkRef::Index(LinkIndex::new(raw)?))
}

#[cfg(target_os = "linux")]
impl AttachOps for LinuxAttachOps<'_> {
    type Netns = ContainerNetns;

    fn create_netns(
        &self,
        dir: &Path,
        id: &EndpointId,
    ) -> Result<(ContainerNetns, (u64, u64)), NetnsFailure> {
        netns::create_pinned(dir, id, self.timeout, self.route.recorder())
    }

    fn unpin_netns(&self, ns: ContainerNetns) -> Result<(), UnpinFailure<ContainerNetns>> {
        netns::unpin(ns)
    }

    fn create_veth(&self, host: &IfName, peer: &IfName) -> Result<(), NetError> {
        self.route
            .create_link(&LinkCreate::veth(host.clone(), peer.clone())?, self.timeout)
            .map(|_| ())
    }

    fn link_index(&self, name: &IfName) -> Result<IfIndex, NetError> {
        self.route.link_index(name, self.timeout)
    }

    fn owned_bridge_index(&self, name: &IfName, token: &str) -> Result<IfIndex, NetError> {
        self.route.link_index_owned(name, token, self.timeout)
    }

    fn set_owner_token(&self, link: IfIndex, token: &str) -> Result<(), NetError> {
        self.route
            .set_link(&LinkSet::set_alias(link_ref(link)?, token)?, self.timeout)
            .map(|_| ())
    }

    fn set_master(&self, link: IfIndex, master: IfIndex) -> Result<(), NetError> {
        self.route
            .set_link(&LinkSet::set_master(link_ref(link)?, master), self.timeout)
            .map(|_| ())
    }

    fn set_up(&self, link: IfIndex) -> Result<(), NetError> {
        self.route
            .set_link(&LinkSet::up(link_ref(link)?), self.timeout)
            .map(|_| ())
    }

    fn move_to_netns(&self, link: IfIndex, ns: &ContainerNetns) -> Result<(), NetError> {
        let fd = NetnsFd::new(ns.fd())?;
        self.route
            .set_link(
                &LinkSet::move_to_netns(link_ref(link)?, NetnsTarget::Fd(fd)),
                self.timeout,
            )
            .map(|_| ())
    }

    fn delete_link(&self, link: IfIndex) -> Result<(), NetError> {
        self.route
            .delete_link(&LinkDelete::new(link_ref(link)?), self.timeout)
            .map(|_| ())
    }

    fn netns_link_index(&self, ns: &ContainerNetns, name: &IfName) -> Result<IfIndex, NetError> {
        Self::ns_route(ns)?.link_index(name, self.timeout)
    }

    fn netns_set_up(&self, ns: &ContainerNetns, link: IfIndex) -> Result<(), NetError> {
        Self::ns_route(ns)?
            .set_link(&LinkSet::up(link_ref(link)?), self.timeout)
            .map(|_| ())
    }

    fn netns_add_address(
        &self,
        ns: &ContainerNetns,
        link: IfIndex,
        addr: IpPrefix,
    ) -> Result<(), NetError> {
        Self::ns_route(ns)?
            .add_address(
                &AddressSpec::new(link, addr, AddrScope::Universe),
                self.timeout,
            )
            .map(|_| ())
    }

    fn netns_add_default_route(
        &self,
        ns: &ContainerNetns,
        gateway: Ipv4Addr,
        oif: IfIndex,
    ) -> Result<(), NetError> {
        let spec = RouteSpec::new(
            IpPrefix::default_v4(),
            RouteNextHop::Gateway {
                gateway: IpAddr::V4(gateway),
                oif: Some(oif),
            },
        )?;
        Self::ns_route(ns)?
            .add_route(&spec, self.timeout)
            .map(|_| ())
    }

    fn release_netns_socket(&self, ns: &mut ContainerNetns) {
        ns.release_route_socket();
    }

    fn publish_ports(
        &self,
        table: &NftName,
        container: Ipv4Addr,
        ports: &[PortPublish],
    ) -> Result<Vec<RuleHandlePair>, NftApplyFailure> {
        send_dnat_batch(self.nft, self.timeout, table, container, ports)
    }
}

/// `table` の `prerouting` / `output` へ DNAT ルールを 1 バッチで投入する（attach 時と attach 後の
/// 公開で共有）。
#[cfg(target_os = "linux")]
fn send_dnat_batch(
    nft: &NetlinkNetfilterSocket,
    timeout: Duration,
    table: &NftName,
    container: Ipv4Addr,
    ports: &[PortPublish],
) -> Result<Vec<RuleHandlePair>, NftApplyFailure> {
    let ack = nft
        .send_batch(timeout, |batch| {
            for port in ports {
                // 外部から（prerouting）とホスト自身から（output）の両経路へ同じルールを入れる。
                for chain in ["prerouting", "output"] {
                    let rule = RuleCreate::new(
                        NftFamily::Ipv4,
                        table.clone(),
                        NftName::new(chain)?,
                        port.dnat_rule_exprs(container)?,
                    );
                    // echo 応答（NLM_F_ECHO）でカーネル採番のルールハンドルを受け取る（NET-3・#2839）。
                    batch.push_with(|seq| rule.build_echo(seq))?;
                }
            }
            Ok(())
        })
        .map_err(|e| NftApplyFailure {
            outcome: e.outcome(),
            error: e.into(),
        })?;
    // 公開 i のルールは本体の添字 2i（prerouting）・2i+1（output）。ACK 判定は echo を要求した本体の
    // ハンドルが揃わなければ成功にしない（ここでの欠落は防御。結果不明として予約を保持させる）。
    let missing = || NftApplyFailure {
        outcome: NftBatchOutcome::Unknown,
        error: NetError::new(
            NetErrorCode::DataLoss,
            "rule handle missing from echo reply",
        ),
    };
    (0..ports.len())
        .map(|i| {
            let pre = ack.rule_handle(i * 2).ok_or_else(missing)?;
            let out = ack.rule_handle(i * 2 + 1).ok_or_else(missing)?;
            Ok((pre, out))
        })
        .collect()
}

/// コンテナをネットワークへ接続する（netns の作成と pin・veth ペアの作成・host 側の bridge 接続と up・
/// peer 側の netns 移動。PoC-15 `netsetup` の `netns-create` / `veth-attach` に相当。NET-1・TASK-139.2.1）。
///
/// 続けて `ipam` から重複しないアドレスを払い出し（TASK-139.2.2・#848）、netns 内の `lo` / peer を up にして
/// アドレスと default route（gateway = bridge アドレス）を設定し、`spec` にポート公開の指定があれば
/// `nft` で DNAT ルールを投入する（TASK-139.3・#316）。
/// ポート公開の受け口は投入前に `ports`（全ネットワークで共有する [`PortRegistry`]）へ予約し、他のコンテナ・
/// ネットワークが公開済みなら `AlreadyExists` で失敗させる（共有予約ファイル使用時は、そのサイズ上限超過の
/// `ResourceExhausted`・破損の `Internal`・ロック待ち期限切れの `Timeout` でも失敗させる。[`PortRegistry`]）。
/// 失敗時は自分が作った veth と netns と IPAM の払い出し・受け口の予約を戻し、結果を [`ContainerAttachError::rollback`] で返す。
/// ただし DNAT バッチの結果が不明な場合は、残ったルールが再利用先へ転送しないよう IPAM のアドレスと受け口の予約を
/// 保持する（quarantine。`AttachResource::Address`・`PortRules` を `Unknown` で報告）。
/// `CAP_NET_ADMIN`（netlink）と `CAP_SYS_ADMIN`（`unshare` / `mount`）が必要で、本 crate は権限を上げない。
/// `timeout` は各カーネル要求と netns 作成スレッドの待ちの期限（REPAIR-5）。
///
/// # 未実装範囲（REPAIR-3）
/// `eth0` へのリネーム・masquerade・コンテナ単位のポート公開解除は含まない（モジュール doc「未実装範囲」）。
/// ホストの外へ届けるには masquerade と host の `ip_forward` が別途必要。IPAM 状態の永続化は呼び出し側・
/// 後続 Issue の責務。ネットワーク・コンテナ側資源の削除は `delete_network`（TASK-139.4・#317）。
#[cfg(target_os = "linux")]
pub fn attach_container(
    route: &NetlinkRouteSocket,
    nft: &NetlinkNetfilterSocket,
    spec: &ContainerAttachSpec,
    ipam: &mut StaticIpam,
    ports: &mut PortRegistry,
    timeout: Duration,
) -> Result<AttachedContainer<ContainerNetns>, ContainerAttachError> {
    attach_container_with(
        &LinuxAttachOps {
            route,
            nft,
            timeout,
        },
        spec,
        ipam,
        ports,
    )
}

/// [`create_container_netns`] の失敗。作成途中の残骸が残りうるかを `leftover` で伝える。
#[cfg(target_os = "linux")]
#[derive(Debug)]
#[non_exhaustive]
pub struct NetnsCreateError {
    /// 失敗の原因。
    pub error: NetError,
    /// 取り残した pin の状態（何も残していなければ `None`。`Present` は後始末の失敗、`Unknown` は結果不明で
    /// fail-closed のため削除していない）。
    pub leftover: Option<ResourceState>,
    /// `lo` の up に失敗し、unpin もできなかった netns（fd と pin を保持したまま）。呼び出し側が保持して
    /// [`release_container_netns`] で再試行できるようにする（捨てるとハンドルを失い二度と回収できない。#2675）。
    pub retained: Option<Box<PreparedNetns<ContainerNetns>>>,
}

/// [`attach_prepared_container`] の失敗。事前作成の netns は unpin せずに返す。
#[cfg(target_os = "linux")]
#[derive(Debug)]
#[non_exhaustive]
pub struct PreparedAttachError {
    /// 失敗の内容と veth・IPAM・受け口のロールバック結果（netns は含まない）。
    pub error: ContainerAttachError,
    /// 返却された netns（再試行または [`release_container_netns`] で解放する）。現在の実装は失敗時に必ず
    /// `Some` で返す。`None` は netns を返せなかった場合を表す（呼び出し側は pin が残りうるとして扱う）。
    pub netns: Option<PreparedNetns<ContainerNetns>>,
}

/// [`release_container_netns`] の失敗。解除できなかった netns を返して再試行できるようにする。
#[cfg(target_os = "linux")]
#[derive(Debug)]
#[non_exhaustive]
pub struct ReleaseNetnsError {
    /// 失敗の原因。
    pub error: NetError,
    /// 解除できなかった netns（fd と pin を保持したまま）。
    pub netns: PreparedNetns<ContainerNetns>,
}

/// コンテナ用の netns を attach より前に作って pin する（#2675・NET-1・CRI-2・PLUG-1）。
///
/// `attach_container` が内部で行う「netns の作成と pin」だけを切り出した入口で、安全性の検査（置き場の所有者・
/// 権限・symlink、`O_EXCL`、`shared` 伝播の拒否）は同じ関数を通る。`lo` は作成時点で up にする（失敗したら
/// netns を unpin して回収する）。attach の netns 内設定も `lo` を up にするが、up 済みなら冪等。
/// 作った netns は [`attach_prepared_container`] へ渡すか、不要なら [`release_container_netns`] で解放する。
/// `CAP_SYS_ADMIN`（`unshare` / `mount`）が必要で、本 crate は権限を上げない。`timeout` は netns 作成の待ちの期限
/// （REPAIR-5）。
#[cfg(target_os = "linux")]
pub fn create_container_netns(
    route: &NetlinkRouteSocket,
    netns_dir: &Path,
    endpoint: &EndpointId,
    timeout: Duration,
) -> Result<PreparedNetns<ContainerNetns>, NetnsCreateError> {
    if !netns_dir.is_absolute() {
        return Err(NetnsCreateError {
            error: invalid("netns directory must be an absolute path"),
            leftover: None,
            retained: None,
        });
    }
    match netns::create_pinned(netns_dir, endpoint, timeout, route.recorder()) {
        Ok((netns, pin_dir_id)) => {
            // 契約どおり作成時点で `lo` を up にする。失敗したら作った netns を unpin して回収する
            // （回収もできなければ pin が残るため `leftover` で報告する）。
            if let Err(error) = netns_loopback_up(&netns, timeout) {
                return Err(match netns::unpin(netns) {
                    Ok(()) => NetnsCreateError {
                        error,
                        leftover: None,
                        retained: None,
                    },
                    // unpin に失敗したら netns を返して再試行できるようにする（#2675）。
                    Err(f) => NetnsCreateError {
                        error,
                        leftover: Some(ResourceState::Present),
                        retained: Some(Box::new(PreparedNetns {
                            netns: f.netns,
                            pin_dir_id,
                            endpoint: endpoint.clone(),
                            dir: netns_dir.to_owned(),
                        })),
                    },
                });
            }
            Ok(PreparedNetns {
                netns,
                pin_dir_id,
                endpoint: endpoint.clone(),
                dir: netns_dir.to_owned(),
            })
        }
        Err(f) => Err(NetnsCreateError {
            error: f.error,
            leftover: f.leftover,
            retained: None,
        }),
    }
}

/// 作成直後の netns の中で `lo` を up にする（`create_container_netns` だけが呼ぶ。#2675・NET-2）。
#[cfg(target_os = "linux")]
fn netns_loopback_up(ns: &ContainerNetns, timeout: Duration) -> Result<(), NetError> {
    let route = ns.route_socket().ok_or_else(|| {
        NetError::new(
            NetErrorCode::FailedPrecondition,
            "netns route socket is not available",
        )
    })?;
    let lo = IfName::new("lo")?;
    let index = route.link_index(&lo, timeout)?;
    route
        .set_link(&LinkSet::up(link_ref(index)?), timeout)
        .map(|_| ())
}

/// 事前作成した netns へコンテナを接続する（#2675）。[`attach_container`] と同じ手順で、netns を作らない点だけが違う。
///
/// `prepared` のエンドポイント ID と置き場は `spec` と一致していること（不一致は `FailedPrecondition` で、何も作らず
/// netns を返す）。失敗時は veth・IPAM の払い出し・受け口の予約を [`attach_container`] と同じ規則で戻し、
/// netns は unpin せず [`PreparedAttachError::netns`] で返す。成功すると netns の所有は
/// [`AttachedContainer::netns`] に移り、解放は `delete_network` が行う。
#[cfg(target_os = "linux")]
pub fn attach_prepared_container(
    route: &NetlinkRouteSocket,
    nft: &NetlinkNetfilterSocket,
    spec: &ContainerAttachSpec,
    prepared: PreparedNetns<ContainerNetns>,
    ipam: &mut StaticIpam,
    ports: &mut PortRegistry,
    timeout: Duration,
) -> Result<AttachedContainer<ContainerNetns>, Box<PreparedAttachError>> {
    attach_prepared_with(
        &LinuxAttachOps {
            route,
            nft,
            timeout,
        },
        spec,
        prepared,
        ipam,
        ports,
        &new_generation(),
    )
    .map_err(|failure| {
        let (error, netns) = *failure;
        Box::new(PreparedAttachError { error, netns })
    })
}

/// 未 attach の事前作成 netns を解放する（unpin: umount → ファイル削除）。失敗時は netns を返して再試行できる。
#[cfg(target_os = "linux")]
pub fn release_container_netns(
    route: &NetlinkRouteSocket,
    nft: &NetlinkNetfilterSocket,
    prepared: PreparedNetns<ContainerNetns>,
    timeout: Duration,
) -> Result<(), Box<ReleaseNetnsError>> {
    release_prepared_with(
        &LinuxAttachOps {
            route,
            nft,
            timeout,
        },
        prepared,
    )
    .map_err(|failure| {
        let (error, netns) = *failure;
        Box::new(ReleaseNetnsError { error, netns })
    })
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
        /// 最初の link_state の失敗（作成直後の ifindex 取得）。
        fail_index: Option<NetErrorCode>,
        /// 作成直後に既に付いている別名（差し替えられた link の模型）。
        initial_alias: Option<String>,
        /// set_owner_token が返す失敗。`stamp_on_fail` なら失敗でも別名は反映済みにする。
        fail_setlink: Option<NetErrorCode>,
        stamp_on_fail: bool,
        /// set_owner_token の後に link が差し替わる模型（ifindex と別名を置き換える）。
        swap_after_setlink: Option<(u32, Option<String>)>,
        /// set_owner_token の失敗後の再照会（2 回目以降の link_state）の失敗。
        fail_requery: Option<NetErrorCode>,
        /// カーネル模型: 現在の (ifindex, 別名)。
        kernel: RefCell<Option<(u32, Option<String>)>>,
        link_state_count: std::cell::Cell<u32>,
        fail_addr: bool,
        fail_up: bool,
        fail_nft: Option<(NetErrorCode, NftBatchOutcome)>,
        fail_delete: bool,
        delete_code: Option<NetErrorCode>,
        /// 指定回数の verify_owned 成功後に FailedPrecondition を返す（差し替えの注入）。
        fail_verify_after: Option<u32>,
        verify_count: std::cell::Cell<u32>,
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
        fn create_bridge(&self, _: &IfName) -> Result<(), NetError> {
            self.rec("create_bridge");
            if let Some(c) = self.fail_bridge {
                return Err(err(c));
            }
            // 実カーネルと同じく、作成直後は別名なし（initial_alias は差し替えの注入）。
            *self.kernel.borrow_mut() = Some((7, self.initial_alias.clone()));
            Ok(())
        }
        fn link_state(&self, _: &IfName) -> Result<(IfIndex, Option<String>), NetError> {
            self.rec("link_state");
            let n = self.link_state_count.get() + 1;
            self.link_state_count.set(n);
            if n == 1 {
                if let Some(c) = self.fail_index {
                    return Err(err(c));
                }
            } else if let Some(c) = self.fail_requery {
                return Err(err(c));
            }
            let (i, a) = self
                .kernel
                .borrow()
                .clone()
                .ok_or_else(|| err(NetErrorCode::NotFound))?;
            Ok((IfIndex::new(i)?, a))
        }
        fn set_owner_token(&self, _: IfIndex, token: &str) -> Result<(), NetError> {
            self.rec("set_owner_token");
            if let Some(c) = self.fail_setlink {
                if self.stamp_on_fail
                    && let Some(k) = self.kernel.borrow_mut().as_mut()
                {
                    k.1 = Some(token.to_owned());
                }
                return Err(err(c));
            }
            if let Some(k) = self.kernel.borrow_mut().as_mut() {
                k.1 = Some(token.to_owned());
            }
            if let Some(sw) = self.swap_after_setlink.clone() {
                *self.kernel.borrow_mut() = Some(sw);
            }
            Ok(())
        }
        fn verify_owned(&self, _: &IfName, token: &str, index: IfIndex) -> Result<(), NetError> {
            self.rec("verify_owned");
            let ok = self
                .kernel
                .borrow()
                .as_ref()
                .is_some_and(|(i, a)| *i == index.get() && a.as_deref() == Some(token));
            if !ok {
                return Err(err(NetErrorCode::FailedPrecondition));
            }
            if self.fail_verify_after.is_some_and(|n| {
                let c = self.verify_count.get() + 1;
                self.verify_count.set(c);
                c > n
            }) {
                return Err(err(NetErrorCode::FailedPrecondition));
            }
            Ok(())
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
        fn apply_nft(&self, _: &NftName, _: &str) -> Result<(), NftApplyFailure> {
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

    /// NET-8・TASK-146.1: 名前解決方式の既定は DnsHelper で、指定値が CreatedNetwork へ引き継がれる。
    #[test]
    fn net8_name_resolution_is_carried_to_created_network() {
        assert_eq!(spec("web").name_resolution(), NameResolution::DnsHelper);
        let c = create_network_with(&Fake::default(), &spec("web")).unwrap();
        assert_eq!(c.name_resolution, NameResolution::DnsHelper);
        let s = spec("web").with_name_resolution(NameResolution::StaticHosts);
        assert_eq!(s.name_resolution(), NameResolution::StaticHosts);
        let c = create_network_with(&Fake::default(), &s).unwrap();
        assert_eq!(c.name_resolution, NameResolution::StaticHosts);
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
                "link_state",
                "set_owner_token",
                "verify_owned",
                "verify_owned",
                "add_address",
                "verify_owned",
                "set_up",
                "apply_nft"
            ]
        );
        assert!(token_names_network(&c.bridge_token, &nname("web")));
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

    /// NET-1・TASK-139.4: `token_names_network` は発行形式（`fandhe-net:<名前>:`）の名前部分だけを照合する
    /// （接頭辞が一致する別名 `web2` や形式外の値を受け入れない）。
    #[test]
    fn net1_token_names_network_matches_exact_name() {
        let web = NetworkName::new("web").unwrap();
        assert!(token_names_network(&ownership_token(&web), &web));
        assert!(token_names_network("fandhe-net:web:1:0:0", &web));
        assert!(!token_names_network("fandhe-net:web2:1:0:0", &web));
        assert!(!token_names_network("fandhe-net:db:1:0:0", &web));
        assert!(!token_names_network("fandhe-net:web", &web));
        assert!(!token_names_network("other:web:1:0:0", &web));
    }

    /// NET-1・#2467: 作成失敗の請求書は、失敗手順と取り残しの種類に応じた値になり、
    /// トークンは bridge に刻んだものと一致する。
    #[test]
    fn net1_reclaim_claim_follows_leftover() {
        // 取り残しなし（rollback 成功）・名前の導出失敗相当でない成功は None。
        let f = Fake {
            fail_up: true,
            ..Default::default()
        };
        let e = create_network_with(&f, &spec("web")).unwrap_err();
        assert_eq!(e.reclaim_claim(), None);

        // SetUp 失敗＋bridge 削除失敗: bridge のみ。トークンは bridge の別名と一致する。
        let f = Fake {
            fail_up: true,
            fail_delete: true,
            ..Default::default()
        };
        let e = create_network_with(&f, &spec("web")).unwrap_err();
        let claim = e.reclaim_claim().unwrap();
        assert_eq!(claim.network(), &nname("web"));
        assert!(claim.includes_bridge() && !claim.includes_table());
        let alias = f.kernel.borrow().clone().unwrap().1.unwrap();
        assert_eq!(claim.token(), alias);

        // nft 結果不明: テーブルのみ（bridge は rollback 済み）。
        let f = Fake {
            fail_nft: Some((NetErrorCode::Timeout, NftBatchOutcome::Unknown)),
            ..Default::default()
        };
        let e = create_network_with(&f, &spec("web")).unwrap_err();
        let claim = e.reclaim_claim().unwrap();
        assert!(!claim.includes_bridge() && claim.includes_table());

        // nft 結果不明＋bridge 削除失敗: 両方。
        let f = Fake {
            fail_nft: Some((NetErrorCode::Timeout, NftBatchOutcome::Unknown)),
            fail_delete: true,
            ..Default::default()
        };
        let e = create_network_with(&f, &spec("web")).unwrap_err();
        let claim = e.reclaim_claim().unwrap();
        assert!(claim.includes_bridge() && claim.includes_table());

        // 他者の同名 bridge との衝突は取り残しなしで None。
        let f = Fake {
            fail_bridge: Some(NetErrorCode::AlreadyExists),
            ..Default::default()
        };
        let e = create_network_with(&f, &spec("web")).unwrap_err();
        assert_eq!(e.reclaim_claim(), None);
    }

    /// NET-1・#2467: `from_created` は bridge・テーブルの両方を、作成結果のトークンで対象にする。
    #[test]
    fn net1_claim_from_created_covers_both() {
        let c = create_network_with(&Fake::default(), &spec("web")).unwrap();
        let claim = FailedCreateClaim::from_created(&c);
        assert_eq!(claim.network(), &nname("web"));
        assert_eq!(claim.token(), c.bridge_token);
        assert!(claim.includes_bridge() && claim.includes_table());
    }

    /// NET-1・#2604: 請求書は記録へ往復で一致する。
    #[test]
    fn net1_claim_record_roundtrip() {
        let c = create_network_with(&Fake::default(), &spec("web")).unwrap();
        let claim = FailedCreateClaim::from_created(&c);
        let rec = claim.to_record();
        assert!(rec.starts_with("fandhe-net-claim v1\nnetwork=web\ntoken=fandhe-net:web:"));
        assert!(rec.ends_with("\nbridge=1\ntable=1\n"));
        assert_eq!(FailedCreateClaim::from_record(&rec), Ok(claim));
        let one = FailedCreateClaim::for_test(nname("web"), "fandhe-net:web:1:2:3", false, true);
        assert_eq!(FailedCreateClaim::from_record(&one.to_record()), Ok(one));
    }

    /// NET-1・#2604: 壊れた・不正な記録はすべて InvalidArgument で拒否する。
    #[test]
    fn net1_claim_record_rejects_malformed() {
        let ok =
            "fandhe-net-claim v1\nnetwork=web\ntoken=fandhe-net:web:1:2:3\nbridge=1\ntable=0\n";
        assert!(FailedCreateClaim::from_record(ok).is_ok());
        let long_tok = format!("fandhe-net:web:{}", "a".repeat(300));
        let long_rec = format!("{}x", ok.replace("fandhe-net:web:1:2:3", &long_tok));
        let bad = [
            ok.replace("v1", "v2"),
            ok.replace("network=web", "network=We b"),
            ok.replace("token=fandhe-net:web:", "token=fandhe-net:other:"),
            ok.replace("token=fandhe-net:web:", "token=web:"),
            ok.replace("1:2:3", "1:2\u{1}3"),
            ok.replace("bridge=1", "bridge=2"),
            ok.replace("bridge=1", "bridge=0"),
            format!("{ok}table=1\n"),
            ok.replace("bridge=1\ntable=0", "table=0\nbridge=1"),
            ok.replace("bridge=1\n", "bridge=1\nextra=1\n"),
            ok.replace('\n', "\r\n"),
            ok.trim_end().to_owned(),
            long_rec,
            ok.replace(&"fandhe-net:web:1:2:3".to_string(), &long_tok),
            String::new(),
        ];
        for r in bad {
            let e = FailedCreateClaim::from_record(&r).unwrap_err();
            assert_eq!(e.code(), NetErrorCode::InvalidArgument, "{r:?}");
        }
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
                    "link_state",
                    "set_owner_token",
                    "verify_owned",
                    "verify_owned",
                    "add_address",
                    "verify_owned",
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
                    "link_state",
                    "set_owner_token",
                    "verify_owned",
                    "verify_owned",
                    "add_address",
                    "verify_owned",
                    "set_up",
                    "verify_owned",
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
            fail_index: Some(NetErrorCode::Internal),
            ..Default::default()
        };
        let e = create_network_with(&f, &spec("web")).unwrap_err();
        assert_eq!(f.calls(), ["create_bridge", "link_state"]);
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

    /// NET-1: add_address 直前の所有再確認で差し替えを検出したら、操作も削除もせず Unknown で報告する。
    #[test]
    fn net1_replaced_before_add_address_touches_nothing() {
        let f = Fake {
            fail_verify_after: Some(1),
            ..Default::default()
        };
        let e = create_network_with(&f, &spec("web")).unwrap_err();
        assert_eq!(
            f.calls(),
            [
                "create_bridge",
                "link_state",
                "set_owner_token",
                "verify_owned",
                "verify_owned",
                "verify_owned"
            ]
        );
        assert_eq!(e.step, CreateStep::AddAddress);
        assert_eq!(e.code(), NetErrorCode::FailedPrecondition);
        assert!(e.rollback.removed.is_empty());
        assert_eq!(
            e.rollback.leftover,
            [(
                NetworkResource::Bridge(bridge_of("web")),
                ResourceState::Unknown
            )]
        );
    }

    /// NET-1: set_up 直前の差し替えも検出し、up も削除もしない。
    #[test]
    fn net1_replaced_before_set_up_touches_nothing() {
        let f = Fake {
            fail_verify_after: Some(2),
            ..Default::default()
        };
        let e = create_network_with(&f, &spec("web")).unwrap_err();
        assert_eq!(e.step, CreateStep::SetUp);
        assert!(!f.calls().contains(&"set_up"));
        assert!(!f.calls().contains(&"delete_bridge"));
        assert_eq!(
            e.rollback.leftover,
            [(
                NetworkResource::Bridge(bridge_of("web")),
                ResourceState::Unknown
            )]
        );
    }

    /// NET-1: ロールバック削除の直前に差し替わっていたら削除せず Unknown で報告する。
    #[test]
    fn net1_replaced_before_rollback_delete_is_not_deleted() {
        let f = Fake {
            fail_up: true,
            fail_verify_after: Some(3),
            ..Default::default()
        };
        let e = create_network_with(&f, &spec("web")).unwrap_err();
        assert_eq!(e.step, CreateStep::SetUp);
        assert!(!f.calls().contains(&"delete_bridge"));
        assert!(e.rollback.removed.is_empty());
        assert_eq!(
            e.rollback.leftover,
            [(
                NetworkResource::Bridge(bridge_of("web")),
                ResourceState::Unknown
            )]
        );
    }
    fn unknown_bridge(n: &str) -> Vec<(NetworkResource, ResourceState)> {
        vec![(
            NetworkResource::Bridge(bridge_of(n)),
            ResourceState::Unknown,
        )]
    }

    /// NET-1・Issue #1925: 作成直後の link に別名が既にある（差し替え）なら、印を付けず削除もしない。
    #[test]
    fn net1_pre_aliased_new_link_is_not_stamped_or_deleted() {
        let f = Fake {
            initial_alias: Some("someone-else".to_owned()),
            ..Default::default()
        };
        let e = create_network_with(&f, &spec("web")).unwrap_err();
        assert_eq!(f.calls(), ["create_bridge", "link_state"]);
        assert_eq!(e.step, CreateStep::ResolveIndex);
        assert_eq!(e.code(), NetErrorCode::FailedPrecondition);
        assert!(e.rollback.removed.is_empty());
        assert_eq!(e.rollback.leftover, unknown_bridge("web"));
    }

    /// NET-1・Issue #1925: 非 UTF-8 の別名（復号結果は置換文字入りの非空文字列）は所有者不明として扱い、
    /// 作成直後は上書きせず、印の付与後に差し替わっても削除しない（ロールバックは `_` 腕で Unknown）。
    #[test]
    fn net1_non_utf8_alias_is_unknown_owner() {
        let lossy = "\u{fffd}".to_owned();
        let f = Fake {
            initial_alias: Some(lossy.clone()),
            ..Default::default()
        };
        let e = create_network_with(&f, &spec("web")).unwrap_err();
        assert_eq!(f.calls(), ["create_bridge", "link_state"]);
        assert!(e.rollback.removed.is_empty());
        assert_eq!(e.rollback.leftover, unknown_bridge("web"));

        let f = Fake {
            swap_after_setlink: Some((7, Some(lossy))),
            ..Default::default()
        };
        let e = create_network_with(&f, &spec("web")).unwrap_err();
        assert_eq!(e.step, CreateStep::ResolveIndex);
        assert!(e.rollback.removed.is_empty());
        assert_eq!(e.rollback.leftover, unknown_bridge("web"));
        assert!(!f.calls().contains(&"delete_bridge"));
    }

    /// NET-1・Issue #1925: 作成直後の NotFound は残るものが無く空報告。
    #[test]
    fn net1_new_link_not_found_reports_nothing() {
        let f = Fake {
            fail_index: Some(NetErrorCode::NotFound),
            ..Default::default()
        };
        let e = create_network_with(&f, &spec("web")).unwrap_err();
        assert_eq!(e.step, CreateStep::ResolveIndex);
        assert_eq!(e.rollback, RollbackReport::default());
    }

    /// NET-1・Issue #1925: 印を付けた後に ifindex が差し替わったら、読み戻しで検出して削除しない。
    #[test]
    fn net1_swap_after_stamp_detected_by_readback() {
        for swapped in [
            (9, None),
            (9, Some("x".to_owned())),
            (7, Some("x".to_owned())),
        ] {
            let f = Fake {
                swap_after_setlink: Some(swapped),
                ..Default::default()
            };
            let e = create_network_with(&f, &spec("web")).unwrap_err();
            assert_eq!(
                f.calls(),
                [
                    "create_bridge",
                    "link_state",
                    "set_owner_token",
                    "verify_owned"
                ]
            );
            assert_eq!(e.step, CreateStep::ResolveIndex);
            assert_eq!(e.code(), NetErrorCode::FailedPrecondition);
            assert!(e.rollback.removed.is_empty());
            assert_eq!(e.rollback.leftover, unknown_bridge("web"));
        }
    }

    /// NET-1・Issue #1925: RTM_SETLINK の失敗でも印が反映済みなら、所有再確認つきで ifindex 指定で削除する。
    #[test]
    fn net1_setlink_failure_with_stamp_applied_deletes_by_index() {
        let f = Fake {
            fail_setlink: Some(NetErrorCode::Timeout),
            stamp_on_fail: true,
            ..Default::default()
        };
        let e = create_network_with(&f, &spec("web")).unwrap_err();
        assert_eq!(
            f.calls(),
            [
                "create_bridge",
                "link_state",
                "set_owner_token",
                "link_state",
                "verify_owned",
                "delete_bridge"
            ]
        );
        assert_eq!(e.step, CreateStep::SetOwnerToken);
        assert_eq!(e.code(), NetErrorCode::Timeout);
        assert_eq!(
            e.rollback.removed,
            [NetworkResource::Bridge(bridge_of("web"))]
        );
        assert!(e.rollback.leftover.is_empty());
    }

    /// NET-1・Issue #1925: RTM_SETLINK が失敗し別名が空のまま（同じ ifindex）なら、確認済みの自分の
    /// link なので ifindex 指定で削除する。
    #[test]
    fn net1_setlink_failure_unstamped_same_index_deletes_by_index() {
        let f = Fake {
            fail_setlink: Some(NetErrorCode::Internal),
            ..Default::default()
        };
        let e = create_network_with(&f, &spec("web")).unwrap_err();
        assert_eq!(
            f.calls(),
            [
                "create_bridge",
                "link_state",
                "set_owner_token",
                "link_state",
                "delete_bridge"
            ]
        );
        assert_eq!(e.step, CreateStep::SetOwnerToken);
        assert_eq!(
            e.rollback.removed,
            [NetworkResource::Bridge(bridge_of("web"))]
        );
    }

    /// NET-1・Issue #1925: RTM_SETLINK の失敗後に消えていれば空報告、再照会の失敗は削除せず Unknown。
    #[test]
    fn net1_setlink_failure_requery_outcomes() {
        let f = Fake {
            fail_setlink: Some(NetErrorCode::Internal),
            fail_requery: Some(NetErrorCode::NotFound),
            ..Default::default()
        };
        let e = create_network_with(&f, &spec("web")).unwrap_err();
        assert_eq!(e.rollback, RollbackReport::default());
        assert!(!f.calls().contains(&"delete_bridge"));

        let f = Fake {
            fail_setlink: Some(NetErrorCode::Internal),
            fail_requery: Some(NetErrorCode::Timeout),
            ..Default::default()
        };
        let e = create_network_with(&f, &spec("web")).unwrap_err();
        assert!(e.rollback.removed.is_empty());
        assert_eq!(e.rollback.leftover, unknown_bridge("web"));
        assert!(!f.calls().contains(&"delete_bridge"));
    }

    /// NET-1・Issue #1925: 再照会で ifindex が違う・別の別名なら差し替えと判断し、削除しない。
    #[test]
    fn net1_setlink_failure_replaced_link_is_not_deleted() {
        for swapped in [
            (9, None),
            (7, Some("x".to_owned())),
            (9, Some("x".to_owned())),
        ] {
            let f = Fake {
                fail_setlink: Some(NetErrorCode::Internal),
                ..Default::default()
            };
            // 1 回目の link_state の後、set_owner_token の失敗前に差し替わった状態を再現する。
            let ops = SwapOnSetlink {
                inner: &f,
                swapped: swapped.clone(),
            };
            let e = create_network_with(&ops, &spec("web")).unwrap_err();
            assert_eq!(e.step, CreateStep::SetOwnerToken, "{swapped:?}");
            assert!(e.rollback.removed.is_empty(), "{swapped:?}");
            assert_eq!(e.rollback.leftover, unknown_bridge("web"), "{swapped:?}");
            assert!(!f.calls().contains(&"delete_bridge"), "{swapped:?}");
        }
    }

    /// `set_owner_token` の直前に link を差し替える包み（差し替え競合の注入）。
    struct SwapOnSetlink<'a> {
        inner: &'a Fake,
        swapped: (u32, Option<String>),
    }

    impl NetworkOps for SwapOnSetlink<'_> {
        fn create_bridge(&self, n: &IfName) -> Result<(), NetError> {
            self.inner.create_bridge(n)
        }
        fn link_state(&self, n: &IfName) -> Result<(IfIndex, Option<String>), NetError> {
            self.inner.link_state(n)
        }
        fn set_owner_token(&self, i: IfIndex, t: &str) -> Result<(), NetError> {
            *self.inner.kernel.borrow_mut() = Some(self.swapped.clone());
            self.inner.set_owner_token(i, t)
        }
        fn verify_owned(&self, n: &IfName, t: &str, i: IfIndex) -> Result<(), NetError> {
            self.inner.verify_owned(n, t, i)
        }
        fn add_address(&self, i: IfIndex, g: &IpPrefix) -> Result<(), NetError> {
            self.inner.add_address(i, g)
        }
        fn set_up(&self, i: IfIndex) -> Result<(), NetError> {
            self.inner.set_up(i)
        }
        fn delete_bridge(&self, i: IfIndex) -> Result<(), NetError> {
            self.inner.delete_bridge(i)
        }
        fn apply_nft(&self, t: &NftName, k: &str) -> Result<(), NftApplyFailure> {
            self.inner.apply_nft(t, k)
        }
    }
}
#[cfg(test)]
mod attach_tests {
    use super::*;
    use std::cell::RefCell;
    use std::net::{IpAddr, Ipv4Addr};

    fn eid(s: &str) -> EndpointId {
        EndpointId::new(s).unwrap()
    }

    fn created() -> CreatedNetwork {
        let names = NetworkResourceNames::derive(&NetworkName::new("web").unwrap()).unwrap();
        CreatedNetwork {
            name: NetworkName::new("web").unwrap(),
            bridge: names.bridge().clone(),
            bridge_index: IfIndex::new(7).unwrap(),
            bridge_token: "fandhe-net:web:1:0:0".to_owned(),
            table: names.table().clone(),
            gateway: IpPrefix::new(IpAddr::V4(Ipv4Addr::new(10, 89, 0, 1)), 24).unwrap(),
            name_resolution: Default::default(),
        }
    }

    /// netns 置き場のテスト用ディレクトリ。`is_absolute` が 3 OS で真になるよう `temp_dir` 起点にする
    /// （Windows では `/run/...` が絶対パスと判定されないため。実在は不要で、fake は触らない）。
    fn netns_dir() -> PathBuf {
        std::env::temp_dir().join("fc-netns")
    }

    fn ipam() -> StaticIpam {
        StaticIpam::for_network(&created()).unwrap()
    }

    fn spec(id: &str) -> ContainerAttachSpec {
        ContainerAttachSpec::new(eid(id), &created(), netns_dir()).unwrap()
    }

    /// 世代を固定して接続する（本番は試行ごとに発行。fake の呼び出し列を決定的にするため）。
    fn attach_container_with<O: AttachOps>(
        ops: &O,
        spec: &ContainerAttachSpec,
        ipam: &mut StaticIpam,
        ports: &mut PortRegistry,
    ) -> Result<AttachedContainer<O::Netns>, ContainerAttachError> {
        super::attach_container_with_generation(ops, spec, ipam, ports, TEST_GEN)
    }

    /// 呼び出しを記録し、指定手順で失敗を注入する fake。link の ifindex は名前の接頭辞で決める。
    #[derive(Default)]
    struct Fake {
        calls: RefCell<Vec<String>>,
        bridge_index: Option<u32>,
        fail_bridge_lookup: bool,
        fail_netns: Option<(NetErrorCode, Option<ResourceState>)>,
        fail_veth: Option<NetErrorCode>,
        fail_host_lookup: bool,
        fail_peer_lookup: bool,
        fail_master: bool,
        fail_up: bool,
        fail_move: Option<NetErrorCode>,
        delete_err: Option<NetErrorCode>,
        unpin_fails: bool,
        /// netns 内の手順名（`ns_index_lo` 等）のうち失敗させるもの。
        fail_ns: Option<&'static str>,
        /// ポート公開の失敗（原因・バッチ結果）。
        fail_publish: Option<(NetErrorCode, NftBatchOutcome)>,
    }

    impl Fake {
        fn rec(&self, s: impl Into<String>) {
            self.calls.borrow_mut().push(s.into());
        }
        fn calls(&self) -> Vec<String> {
            self.calls.borrow().clone()
        }
    }

    fn err(code: NetErrorCode) -> NetError {
        NetError::new(code, "injected")
    }

    impl AttachOps for Fake {
        type Netns = ();

        fn create_netns(
            &self,
            dir: &Path,
            id: &EndpointId,
        ) -> Result<((), (u64, u64)), NetnsFailure> {
            self.rec(format!("create_netns {}", dir.join(id.as_str()).display()));
            match self.fail_netns {
                Some((c, leftover)) => Err(NetnsFailure {
                    error: err(c),
                    leftover,
                }),
                None => Ok(((), (8, 9))),
            }
        }
        fn unpin_netns(&self, (): ()) -> Result<(), UnpinFailure<()>> {
            self.rec("unpin_netns");
            if self.unpin_fails {
                Err(UnpinFailure {
                    error: err(NetErrorCode::Internal),
                    netns: (),
                })
            } else {
                Ok(())
            }
        }
        fn create_veth(&self, host: &IfName, peer: &IfName) -> Result<(), NetError> {
            self.rec(format!("create_veth {} {}", host.as_str(), peer.as_str()));
            self.fail_veth.map_or(Ok(()), |c| Err(err(c)))
        }
        fn link_index(&self, name: &IfName) -> Result<IfIndex, NetError> {
            self.rec(format!("link_index {}", name.as_str()));
            if name.as_str().starts_with("fcbr") {
                if self.fail_bridge_lookup {
                    return Err(err(NetErrorCode::NotFound));
                }
                return IfIndex::new(self.bridge_index.unwrap_or(7));
            }
            if name.as_str().starts_with("fcvh") {
                if self.fail_host_lookup {
                    return Err(err(NetErrorCode::Timeout));
                }
                return IfIndex::new(21);
            }
            if self.fail_peer_lookup {
                return Err(err(NetErrorCode::NotFound));
            }
            IfIndex::new(22)
        }
        fn owned_bridge_index(&self, name: &IfName, token: &str) -> Result<IfIndex, NetError> {
            if token != "fandhe-net:web:1:0:0" {
                return Err(err(NetErrorCode::FailedPrecondition));
            }
            self.link_index(name)
        }
        fn set_owner_token(&self, link: IfIndex, token: &str) -> Result<(), NetError> {
            self.rec(format!("set_owner_token {} {}", link.get(), token));
            Ok(())
        }
        fn set_master(&self, link: IfIndex, master: IfIndex) -> Result<(), NetError> {
            self.rec(format!("set_master {} {}", link.get(), master.get()));
            if self.fail_master {
                Err(err(NetErrorCode::Internal))
            } else {
                Ok(())
            }
        }
        fn set_up(&self, link: IfIndex) -> Result<(), NetError> {
            self.rec(format!("set_up {}", link.get()));
            if self.fail_up {
                Err(err(NetErrorCode::Internal))
            } else {
                Ok(())
            }
        }
        fn move_to_netns(&self, link: IfIndex, (): &()) -> Result<(), NetError> {
            self.rec(format!("move_to_netns {}", link.get()));
            self.fail_move.map_or(Ok(()), |c| Err(err(c)))
        }
        fn delete_link(&self, link: IfIndex) -> Result<(), NetError> {
            self.rec(format!("delete_link {}", link.get()));
            self.delete_err.map_or(Ok(()), |c| Err(err(c)))
        }
        fn netns_link_index(&self, (): &(), name: &IfName) -> Result<IfIndex, NetError> {
            let (tag, idx) = if name.as_str() == "lo" {
                ("ns_index_lo", 1)
            } else {
                ("ns_index_peer", 5)
            };
            self.rec(format!("{tag} {}", name.as_str()));
            if self.fail_ns == Some(tag) {
                return Err(err(NetErrorCode::NotFound));
            }
            IfIndex::new(idx)
        }
        fn netns_set_up(&self, (): &(), link: IfIndex) -> Result<(), NetError> {
            let tag = if link.get() == 1 {
                "ns_up_lo"
            } else {
                "ns_up_peer"
            };
            self.rec(format!("{tag} {}", link.get()));
            if self.fail_ns == Some(tag) {
                return Err(err(NetErrorCode::Internal));
            }
            Ok(())
        }
        fn netns_add_address(
            &self,
            (): &(),
            link: IfIndex,
            addr: IpPrefix,
        ) -> Result<(), NetError> {
            self.rec(format!("ns_addr {} {}", link.get(), addr_str(addr)));
            if self.fail_ns == Some("ns_addr") {
                return Err(err(NetErrorCode::AlreadyExists));
            }
            Ok(())
        }
        fn netns_add_default_route(
            &self,
            (): &(),
            gateway: Ipv4Addr,
            oif: IfIndex,
        ) -> Result<(), NetError> {
            self.rec(format!("ns_route {gateway} {}", oif.get()));
            if self.fail_ns == Some("ns_route") {
                return Err(err(NetErrorCode::Internal));
            }
            Ok(())
        }
        fn release_netns_socket(&self, (): &mut ()) {
            self.rec("release_socket");
        }
        fn publish_ports(
            &self,
            table: &NftName,
            container: Ipv4Addr,
            ports: &[PortPublish],
        ) -> Result<Vec<RuleHandlePair>, NftApplyFailure> {
            self.rec(format!(
                "publish {} {container} {}",
                table.as_str(),
                ports.len()
            ));
            match self.fail_publish {
                Some((c, outcome)) => Err(NftApplyFailure {
                    error: err(c),
                    outcome,
                }),
                None => Ok(test_handles(ports.len())),
            }
        }
    }

    /// 公開指定の順に `(2i + 2, 2i + 3)` を返す（新規テーブルで chain 作成の次から採番した想定の具体値）。
    fn test_handles(n: usize) -> Vec<RuleHandlePair> {
        (0..n as u64)
            .map(|i| {
                (
                    NftRuleHandle::new(2 * i + 2).unwrap(),
                    NftRuleHandle::new(2 * i + 3).unwrap(),
                )
            })
            .collect()
    }

    fn addr_str(p: IpPrefix) -> String {
        format!("{}/{}", p.addr(), p.prefix_len())
    }

    fn host_of(id: &str) -> IfName {
        VethNames::derive(&eid(id)).unwrap().host().clone()
    }

    fn pin_of(id: &str) -> PathBuf {
        netns_dir().join(id)
    }

    /// NET-1・TASK-139.2.1: 導出名は決まった形式で、長さは 15 バイト（`IFNAMSIZ` 未満）。
    #[test]
    fn net1_veth_names_are_fixed() {
        let n = VethNames::derive(&eid("web-1")).unwrap();
        let h = fnv1a64(b"web-1") & ((1u64 << 44) - 1);
        assert_eq!(n.host().as_str(), format!("fcvh{h:011x}"));
        assert_eq!(n.peer().as_str(), format!("fcvp{h:011x}"));
        assert_eq!(n.host().as_str().len(), 15);
        assert_eq!(n.peer().as_str().len(), 15);
        assert_ne!(n.host(), n.peer());
        let long = VethNames::derive(&eid(&"a".repeat(64))).unwrap();
        assert_eq!(long.host().as_str().len(), 15);
    }

    /// NET-1: エンドポイント ID はパス要素として安全な文字だけを受け付ける。
    #[test]
    fn net1_endpoint_id_validation() {
        assert!(EndpointId::new(&"a".repeat(64)).is_ok());
        for bad in [
            "".to_owned(),
            "a".repeat(65),
            "A".to_owned(),
            ".".to_owned(),
            "..".to_owned(),
            ".hidden".to_owned(),
            "a/b".to_owned(),
            "../x".to_owned(),
            "a b".to_owned(),
            "a\0b".to_owned(),
        ] {
            assert_eq!(
                EndpointId::new(&bad).unwrap_err().code(),
                NetErrorCode::InvalidArgument,
                "{bad:?}"
            );
        }
    }

    /// テストで固定する接続の世代識別子。
    const TEST_GEN: &str = "0123456789abcdef0123456789abcdef";

    /// NET-1・#2681: 世代識別子は発行ごとに別の値で、形式を満たす。
    #[test]
    fn net1_generation_is_unique_per_attempt() {
        let a = new_generation();
        let b = new_generation();
        assert_ne!(a, b);
        assert!(is_valid_generation(&a));
        assert_eq!(a.len(), GENERATION_LEN);
    }

    /// NET-1・#2681: 同じ spec での 2 回の試行は別の世代の所有トークンを刻む（再接続が古い請求書と重ならない）。
    #[test]
    fn net1_same_spec_attempts_get_distinct_tokens() {
        let sp = spec("c1");
        let a = super::attach_container_with(
            &Fake::default(),
            &sp,
            &mut ipam(),
            &mut PortRegistry::new(),
        )
        .unwrap();
        let b = super::attach_container_with(
            &Fake::default(),
            &sp,
            &mut ipam(),
            &mut PortRegistry::new(),
        )
        .unwrap();
        assert_ne!(a.host_token, b.host_token);
    }

    /// NET-1: netns 置き場は絶対パスのみ。pin 先は置き場直下の ID 名。
    #[test]
    fn net1_spec_requires_absolute_netns_dir() {
        let e =
            ContainerAttachSpec::new(eid("c1"), &created(), PathBuf::from("rel/dir")).unwrap_err();
        assert_eq!(e.code(), NetErrorCode::InvalidArgument);
        assert_eq!(spec("c1").netns_path(), pin_of("c1"));
    }

    /// NET-1・TASK-139.2.1: 全手順成功。呼び出し列と戻り値を具体値で照合する。
    #[test]
    fn net1_attach_success() {
        let f = Fake::default();
        let mut pool = ipam();
        let a =
            attach_container_with(&f, &spec("web-1"), &mut pool, &mut PortRegistry::new()).unwrap();
        let n = VethNames::derive(&eid("web-1")).unwrap();
        assert_eq!(
            f.calls(),
            [
                format!("link_index {}", created().bridge.as_str()),
                format!("create_netns {}", pin_of("web-1").display()),
                format!("create_veth {} {}", n.host().as_str(), n.peer().as_str()),
                format!("link_index {}", n.host().as_str()),
                format!("link_index {}", n.peer().as_str()),
                "set_owner_token 21 fandhe-net:web:1:0:0/ep/web-1/g/0123456789abcdef0123456789abcdef".to_owned(),
                "set_master 21 7".to_owned(),
                "set_up 21".to_owned(),
                "move_to_netns 22".to_owned(),
                "ns_index_lo lo".to_owned(),
                "ns_up_lo 1".to_owned(),
                format!("ns_index_peer {}", n.peer().as_str()),
                "ns_addr 5 10.89.0.2/24".to_owned(),
                "ns_up_peer 5".to_owned(),
                "ns_route 10.89.0.1 5".to_owned(),
                "release_socket".to_owned(),
            ]
        );
        assert_eq!(a.host_index.get(), 21);
        assert_eq!(a.host_veth, *n.host());
        assert_eq!(a.peer_veth, *n.peer());
        assert_eq!(a.netns_path, pin_of("web-1"));
        assert_eq!(a.address, ip(2));
        // 削除時の残存 pin の照合用に、置き場のパスと識別子を払い出しと同時に記録する（TASK-139.4）。
        assert_eq!(
            pool.netns_dir_of(&eid("web-1")),
            Some(&NetnsDirRecord::new(netns_dir(), (8, 9)))
        );
    }

    fn ip(last: u8) -> IpPrefix {
        IpPrefix::new(IpAddr::V4(Ipv4Addr::new(10, 89, 0, last)), 24).unwrap()
    }

    /// NET-1・TASK-139.2.2: 同じ IPAM で続けて接続すると重複しないアドレスになる。
    #[test]
    fn net1_attach_allocates_distinct_addresses() {
        let f = Fake::default();
        let mut m = ipam();
        let a = attach_container_with(&f, &spec("c1"), &mut m, &mut PortRegistry::new()).unwrap();
        let b = attach_container_with(&f, &spec("c2"), &mut m, &mut PortRegistry::new()).unwrap();
        assert_eq!(a.address, ip(2));
        assert_eq!(b.address, ip(3));
        assert_eq!(m.allocated_count(), 2);
    }

    /// 払い出し済みで枯渇した /30 の IPAM を作る。
    fn exhausted_ipam() -> StaticIpam {
        let mut net = created();
        net.gateway = IpPrefix::new(IpAddr::V4(Ipv4Addr::new(10, 89, 0, 1)), 30).unwrap();
        let mut m = StaticIpam::for_network(&net).unwrap();
        m.allocate(&eid("other")).unwrap();
        m
    }

    fn spec_for(id: &str, gateway_len: u8) -> ContainerAttachSpec {
        let mut net = created();
        net.gateway = IpPrefix::new(IpAddr::V4(Ipv4Addr::new(10, 89, 0, 1)), gateway_len).unwrap();
        ContainerAttachSpec::new(eid(id), &net, netns_dir()).unwrap()
    }

    /// NET-1・ERR-1・TASK-139.2.2: プール枯渇で veth と netns をこの順に戻し、元のエラーを返す。
    #[test]
    fn net1_attach_pool_exhausted_rolls_back() {
        let f = Fake::default();
        let mut m = exhausted_ipam();
        let e = attach_container_with(&f, &spec_for("c1", 30), &mut m, &mut PortRegistry::new())
            .unwrap_err();
        assert_eq!(e.step, AttachStep::AllocateAddress);
        assert_eq!(e.code(), NetErrorCode::ResourceExhausted);
        assert_eq!(e.message(), "address pool exhausted");
        let calls = f.calls();
        assert_eq!(&calls[calls.len() - 2..], ["delete_link 21", "unpin_netns"]);
        assert_eq!(
            e.rollback.removed,
            [
                AttachResource::Veth(host_of("c1")),
                AttachResource::Netns(pin_of("c1"))
            ]
        );
        assert!(e.rollback.leftover.is_empty());
        assert_eq!(m.allocated_count(), 1);
    }

    /// NET-1: 枯渇に veth 削除失敗が重なっても元のエラーは上書きしない。
    #[test]
    fn net1_attach_pool_exhausted_with_delete_failure() {
        let f = Fake {
            delete_err: Some(NetErrorCode::Internal),
            ..Default::default()
        };
        let mut m = exhausted_ipam();
        let e = attach_container_with(&f, &spec_for("c1", 30), &mut m, &mut PortRegistry::new())
            .unwrap_err();
        assert_eq!(e.code(), NetErrorCode::ResourceExhausted);
        assert_eq!(
            e.rollback.leftover,
            [(AttachResource::Veth(host_of("c1")), ResourceState::Present)]
        );
        assert_eq!(e.rollback.removed, [AttachResource::Netns(pin_of("c1"))]);
    }

    /// NET-1: 別ネットワークの IPAM は資源を作る前に FailedPrecondition で拒否する。
    #[test]
    fn net1_attach_ipam_mismatch_creates_nothing() {
        let f = Fake::default();
        let mut m =
            StaticIpam::new(&NetworkName::new("other").unwrap(), created().gateway).unwrap();
        let e =
            attach_container_with(&f, &spec("c1"), &mut m, &mut PortRegistry::new()).unwrap_err();
        assert_eq!(e.step, AttachStep::AllocateAddress);
        assert_eq!(e.code(), NetErrorCode::FailedPrecondition);
        assert!(f.calls().is_empty());
        assert!(e.rollback.removed.is_empty() && e.rollback.leftover.is_empty());
    }

    /// NET-1: bridge の ifindex が作成時と違う（差し替え）なら、何も作らず拒否する。
    #[test]
    fn net1_attach_bridge_mismatch_creates_nothing() {
        let f = Fake {
            bridge_index: Some(9),
            ..Default::default()
        };
        let e = attach_container_with(&f, &spec("c1"), &mut ipam(), &mut PortRegistry::new())
            .unwrap_err();
        assert_eq!(f.calls().len(), 1);
        assert_eq!(e.step, AttachStep::VerifyBridge);
        assert_eq!(e.code(), NetErrorCode::FailedPrecondition);
        assert_eq!(e.rollback, AttachRollbackReport::default());

        let f = Fake {
            fail_bridge_lookup: true,
            ..Default::default()
        };
        let e = attach_container_with(&f, &spec("c1"), &mut ipam(), &mut PortRegistry::new())
            .unwrap_err();
        assert_eq!(f.calls().len(), 1);
        assert_eq!(e.step, AttachStep::VerifyBridge);
        assert_eq!(e.code(), NetErrorCode::NotFound);
    }

    /// NET-1: bridge の所有トークンが一致しない（ifindex が同じでも別所有者の同名 bridge）なら拒否する。
    #[test]
    fn net1_attach_bridge_token_mismatch_creates_nothing() {
        let mut sp = spec("c1");
        sp.bridge_token = "other-owner".to_owned();
        let f = Fake::default();
        let e = attach_container_with(&f, &sp, &mut ipam(), &mut PortRegistry::new()).unwrap_err();
        assert_eq!(e.step, AttachStep::VerifyBridge);
        assert_eq!(e.code(), NetErrorCode::FailedPrecondition);
        assert_eq!(f.calls().len(), 0);
    }

    /// NET-1: netns 作成の失敗。取り残しが無ければ空報告、結果不明なら Unknown で pin パスを報告する。
    #[test]
    fn net1_attach_netns_failure_reports_leftover() {
        let f = Fake {
            fail_netns: Some((NetErrorCode::PermissionDenied, None)),
            ..Default::default()
        };
        let e = attach_container_with(&f, &spec("c1"), &mut ipam(), &mut PortRegistry::new())
            .unwrap_err();
        assert_eq!(e.step, AttachStep::CreateNetns);
        assert_eq!(e.code(), NetErrorCode::PermissionDenied);
        assert_eq!(e.rollback, AttachRollbackReport::default());
        assert_eq!(f.calls().len(), 2);

        let f = Fake {
            fail_netns: Some((NetErrorCode::Timeout, Some(ResourceState::Unknown))),
            ..Default::default()
        };
        let e = attach_container_with(&f, &spec("c1"), &mut ipam(), &mut PortRegistry::new())
            .unwrap_err();
        assert_eq!(
            e.rollback.leftover,
            [(AttachResource::Netns(pin_of("c1")), ResourceState::Unknown)]
        );
        assert!(e.rollback.removed.is_empty());
    }

    /// NET-1・#2681: 取り残しの種類ごとに請求書のフラグが決まる。取り残しが無ければ請求書は無い。
    #[test]
    fn net1_attach_error_reclaim_claim_flags() {
        let f = Fake {
            fail_netns: Some((NetErrorCode::Timeout, Some(ResourceState::Unknown))),
            ..Default::default()
        };
        let e = attach_container_with(&f, &spec("c1"), &mut ipam(), &mut PortRegistry::new())
            .unwrap_err();
        let claim = e.reclaim_claim().unwrap();
        assert_eq!(claim.endpoint().as_str(), "c1");
        assert_eq!(claim.network().as_str(), "web");
        assert!(!claim.includes_veth() && claim.includes_netns() && !claim.includes_quarantine());
        assert_eq!(
            FailedAttachClaim::from_record(&claim.to_record()),
            Ok(claim)
        );

        let mut e = e;
        e.rollback.leftover = vec![
            (
                AttachResource::Veth(VethNames::derive(&eid("c1")).unwrap().host().clone()),
                ResourceState::Present,
            ),
            (
                AttachResource::PortReservation(NetworkName::new("web").unwrap(), eid("c1")),
                ResourceState::Present,
            ),
        ];
        let claim = e.reclaim_claim().unwrap();
        assert!(claim.includes_veth() && !claim.includes_netns() && claim.includes_quarantine());

        e.rollback.leftover.clear();
        assert_eq!(e.reclaim_claim(), None);
    }

    /// NET-1: veth の AlreadyExists は他者のリソースなので削除せず、netns だけ戻す。
    #[test]
    fn net1_attach_veth_exists_is_not_deleted() {
        let f = Fake {
            fail_veth: Some(NetErrorCode::AlreadyExists),
            ..Default::default()
        };
        let e = attach_container_with(&f, &spec("c1"), &mut ipam(), &mut PortRegistry::new())
            .unwrap_err();
        assert_eq!(e.step, AttachStep::CreateVeth);
        assert_eq!(e.code(), NetErrorCode::AlreadyExists);
        assert_eq!(e.message(), VETH_COLLISION_MSG);
        assert_eq!(e.rollback.removed, [AttachResource::Netns(pin_of("c1"))]);
        assert!(e.rollback.leftover.is_empty());
        assert!(!f.calls().iter().any(|c| c.starts_with("delete_link")));
        assert_eq!(f.calls().last().unwrap(), "unpin_netns");
    }

    /// NET-1: 送信後の応答エラーは作成済みの可能性があるので veth を Unknown で報告し、名前では削除しない。
    #[test]
    fn net1_attach_veth_post_send_error_is_unknown() {
        for code in [
            NetErrorCode::Timeout,
            NetErrorCode::DataLoss,
            NetErrorCode::Internal,
        ] {
            let f = Fake {
                fail_veth: Some(code),
                ..Default::default()
            };
            let e = attach_container_with(&f, &spec("c1"), &mut ipam(), &mut PortRegistry::new())
                .unwrap_err();
            assert_eq!(
                e.rollback.leftover,
                [(AttachResource::Veth(host_of("c1")), ResourceState::Unknown)],
                "{code:?}"
            );
            assert_eq!(e.rollback.removed, [AttachResource::Netns(pin_of("c1"))]);
            assert!(!f.calls().iter().any(|c| c.starts_with("delete_link")));
        }
    }

    /// NET-1: ifindex を解決できなければ名前では削除せず Unknown（fail-closed）。netns は戻す。
    #[test]
    fn net1_attach_resolve_failure_is_unknown() {
        for (host, peer) in [(true, false), (false, true)] {
            let f = Fake {
                fail_host_lookup: host,
                fail_peer_lookup: peer,
                ..Default::default()
            };
            let e = attach_container_with(&f, &spec("c1"), &mut ipam(), &mut PortRegistry::new())
                .unwrap_err();
            assert_eq!(e.step, AttachStep::ResolveIndex);
            assert_eq!(
                e.rollback.leftover,
                [(AttachResource::Veth(host_of("c1")), ResourceState::Unknown)]
            );
            assert_eq!(e.rollback.removed, [AttachResource::Netns(pin_of("c1"))]);
            assert!(!f.calls().iter().any(|c| c.starts_with("delete_link")));
        }
    }

    /// NET-1: 接続以降の失敗は ifindex 指定で veth を削除してから netns を戻す。
    #[test]
    fn net1_attach_late_failures_roll_back_veth_then_netns() {
        let cases = [
            (
                Fake {
                    fail_master: true,
                    ..Default::default()
                },
                AttachStep::SetMaster,
            ),
            (
                Fake {
                    fail_up: true,
                    ..Default::default()
                },
                AttachStep::SetUp,
            ),
            (
                Fake {
                    fail_move: Some(NetErrorCode::Internal),
                    ..Default::default()
                },
                AttachStep::MoveToNetns,
            ),
        ];
        for (f, step) in cases {
            let e = attach_container_with(&f, &spec("c1"), &mut ipam(), &mut PortRegistry::new())
                .unwrap_err();
            assert_eq!(e.step, step);
            assert_eq!(e.code(), NetErrorCode::Internal);
            assert_eq!(
                e.rollback.removed,
                [
                    AttachResource::Veth(host_of("c1")),
                    AttachResource::Netns(pin_of("c1"))
                ],
                "{step:?}"
            );
            assert!(e.rollback.leftover.is_empty());
            let calls = f.calls();
            let n = calls.len();
            assert_eq!(calls[n - 2], "delete_link 21");
            assert_eq!(calls[n - 1], "unpin_netns");
        }
    }

    fn prepared(id: &str, dir: PathBuf) -> PreparedNetns<()> {
        PreparedNetns {
            netns: (),
            pin_dir_id: (8, 9),
            endpoint: eid(id),
            dir,
        }
    }

    /// NET-1・CRI-2（#2675）: 事前作成の netns への接続は netns を作らず、後半の手順は通常の接続と同じ。
    #[test]
    fn net1_attach_prepared_does_not_create_netns() {
        let f = Fake::default();
        let mut pool = ipam();
        let a = attach_prepared_with(
            &f,
            &spec("web-1"),
            prepared("web-1", netns_dir()),
            &mut pool,
            &mut PortRegistry::new(),
            TEST_GEN,
        )
        .unwrap();
        let calls = f.calls();
        assert!(!calls.iter().any(|c| c.starts_with("create_netns")));
        assert!(!calls.iter().any(|c| c.starts_with("unpin_netns")));
        let n = VethNames::derive(&eid("web-1")).unwrap();
        assert_eq!(
            calls,
            [
                format!("link_index {}", created().bridge.as_str()),
                format!("create_veth {} {}", n.host().as_str(), n.peer().as_str()),
                format!("link_index {}", n.host().as_str()),
                format!("link_index {}", n.peer().as_str()),
                "set_owner_token 21 fandhe-net:web:1:0:0/ep/web-1/g/0123456789abcdef0123456789abcdef".to_owned(),
                "set_master 21 7".to_owned(),
                "set_up 21".to_owned(),
                "move_to_netns 22".to_owned(),
                "ns_index_lo lo".to_owned(),
                "ns_up_lo 1".to_owned(),
                format!("ns_index_peer {}", n.peer().as_str()),
                "ns_addr 5 10.89.0.2/24".to_owned(),
                "ns_up_peer 5".to_owned(),
                "ns_route 10.89.0.1 5".to_owned(),
                "release_socket".to_owned(),
            ]
        );
        assert_eq!(a.netns_path, pin_of("web-1"));
        assert_eq!(a.address, ip(2));
        // 削除時の残存 pin の照合用の置き場記録も、事前作成の置き場の識別子で払い出しと同時に残る。
        assert_eq!(
            pool.netns_dir_of(&eid("web-1")),
            Some(&NetnsDirRecord::new(netns_dir(), (8, 9)))
        );
    }

    /// NET-1・CRI-2（#2675）: 事前作成の netns への接続が失敗しても、veth は戻すが netns は unpin せず返す。
    #[test]
    fn net1_attach_prepared_failure_hands_netns_back_without_unpin() {
        let cases = [
            (
                Fake {
                    fail_master: true,
                    ..Default::default()
                },
                AttachStep::SetMaster,
            ),
            (
                Fake {
                    fail_move: Some(NetErrorCode::Internal),
                    ..Default::default()
                },
                AttachStep::MoveToNetns,
            ),
            (
                Fake {
                    fail_ns: Some("ns_addr"),
                    ..Default::default()
                },
                AttachStep::AddAddress,
            ),
        ];
        for (f, step) in cases {
            let (e, back) = *attach_prepared_with(
                &f,
                &spec("c1"),
                prepared("c1", netns_dir()),
                &mut ipam(),
                &mut PortRegistry::new(),
                TEST_GEN,
            )
            .unwrap_err();
            assert_eq!(e.step, step);
            assert_eq!(e.rollback.removed, [AttachResource::Veth(host_of("c1"))]);
            assert!(e.rollback.leftover.is_empty());
            let calls = f.calls();
            assert!(
                !calls.iter().any(|c| c.starts_with("unpin_netns")),
                "{step:?}"
            );
            let back = back.expect("netns is handed back");
            assert_eq!(back.endpoint(), &eid("c1"));
            assert_eq!(back.pin_path(), pin_of("c1"));
        }
    }

    /// NET-1・CRI-2（#2675）: エンドポイントまたは置き場が違う事前作成の netns は、何も作らず拒否して返す。
    #[test]
    fn net1_attach_prepared_mismatch_creates_nothing() {
        for p in [
            prepared("other", netns_dir()),
            prepared("c1", PathBuf::from("/elsewhere")),
        ] {
            let f = Fake::default();
            let (e, back) = *attach_prepared_with(
                &f,
                &spec("c1"),
                p,
                &mut ipam(),
                &mut PortRegistry::new(),
                TEST_GEN,
            )
            .unwrap_err();
            assert_eq!(e.code(), NetErrorCode::FailedPrecondition);
            assert!(f.calls().is_empty(), "{:?}", f.calls());
            assert!(back.is_some());
        }
    }

    /// NET-1（#2675）: 事前検査（bridge の不一致）の失敗でも netns は返る。
    #[test]
    fn net1_attach_prepared_precheck_failure_hands_netns_back() {
        let f = Fake {
            bridge_index: Some(99),
            ..Default::default()
        };
        let (e, back) = *attach_prepared_with(
            &f,
            &spec("c1"),
            prepared("c1", netns_dir()),
            &mut ipam(),
            &mut PortRegistry::new(),
            TEST_GEN,
        )
        .unwrap_err();
        assert_eq!(e.step, AttachStep::VerifyBridge);
        assert!(back.is_some());
        assert!(!f.calls().iter().any(|c| c.starts_with("create_")));
    }

    /// NET-1（#2675）: 未 attach の事前作成 netns の解放は unpin を 1 回呼び、失敗時はハンドルを返す。
    #[test]
    fn net1_release_prepared_unpins_and_returns_handle_on_failure() {
        let f = Fake::default();
        release_prepared_with(&f, prepared("c1", netns_dir())).unwrap();
        assert_eq!(f.calls(), ["unpin_netns"]);
        let f = Fake {
            unpin_fails: true,
            ..Default::default()
        };
        let (e, back) = *release_prepared_with(&f, prepared("c1", netns_dir())).unwrap_err();
        assert_eq!(e.code(), NetErrorCode::Internal);
        assert_eq!(back.pin_path(), pin_of("c1"));
    }

    /// NET-1: ロールバックが失敗しても元のエラーを保ち、状態を Present / Unknown で分けて報告する。
    #[test]
    fn net1_attach_rollback_failure_keeps_original_error() {
        let f = Fake {
            fail_move: Some(NetErrorCode::PermissionDenied),
            delete_err: Some(NetErrorCode::Internal),
            unpin_fails: true,
            ..Default::default()
        };
        let e = attach_container_with(&f, &spec("c1"), &mut ipam(), &mut PortRegistry::new())
            .unwrap_err();
        assert_eq!(e.step, AttachStep::MoveToNetns);
        assert_eq!(e.code(), NetErrorCode::PermissionDenied);
        assert!(e.rollback.removed.is_empty());
        assert_eq!(
            e.rollback.leftover,
            [
                (AttachResource::Veth(host_of("c1")), ResourceState::Present),
                (AttachResource::Netns(pin_of("c1")), ResourceState::Present)
            ]
        );

        let f = Fake {
            fail_up: true,
            delete_err: Some(NetErrorCode::Timeout),
            ..Default::default()
        };
        let e = attach_container_with(&f, &spec("c1"), &mut ipam(), &mut PortRegistry::new())
            .unwrap_err();
        assert_eq!(
            e.rollback.leftover,
            [(AttachResource::Veth(host_of("c1")), ResourceState::Unknown)]
        );
        assert_eq!(e.rollback.removed, [AttachResource::Netns(pin_of("c1"))]);
    }

    fn port(host_port: u16) -> PortPublish {
        PortPublish::new(
            PortProtocol::Tcp,
            Ipv4Addr::new(192, 0, 2, 10),
            host_port,
            80,
        )
        .unwrap()
    }

    fn spec_with_ports(id: &str, ports: Vec<PortPublish>) -> ContainerAttachSpec {
        spec(id).with_port_publishes(ports).unwrap()
    }

    /// NET-1・TASK-139.3: ポート公開が無ければ nft へは何も送らない。あれば default route の後に 1 回だけ投入する。
    #[test]
    fn net1_attach_publishes_ports_after_route() {
        let f = Fake::default();
        attach_container_with(&f, &spec("p0"), &mut ipam(), &mut PortRegistry::new()).unwrap();
        assert!(!f.calls().iter().any(|c| c.starts_with("publish")));

        let f = Fake::default();
        let s = spec_with_ports("p1", vec![port(8080), port(8081)]);
        assert_eq!(s.port_publishes().len(), 2);
        attach_container_with(&f, &s, &mut ipam(), &mut PortRegistry::new()).unwrap();
        let calls = f.calls();
        let n = calls.len();
        assert_eq!(calls[n - 3], "ns_route 10.89.0.1 5");
        assert_eq!(
            calls[n - 2],
            format!("publish {} 10.89.0.2 2", created().table.as_str())
        );
        assert_eq!(calls[n - 1], "release_socket");
    }

    /// NET-1・TASK-139.3: netns 内の各手順の失敗は、失敗手順と元のエラーを返し、IPAM の払い出し・veth・netns を戻す。
    #[test]
    fn net1_attach_netns_config_failures_roll_back_everything() {
        let cases = [
            (
                "ns_index_lo",
                AttachStep::ConfigureLoopback,
                NetErrorCode::NotFound,
            ),
            (
                "ns_up_lo",
                AttachStep::ConfigureLoopback,
                NetErrorCode::Internal,
            ),
            (
                "ns_index_peer",
                AttachStep::ResolvePeer,
                NetErrorCode::NotFound,
            ),
            (
                "ns_addr",
                AttachStep::AddAddress,
                NetErrorCode::AlreadyExists,
            ),
            ("ns_up_peer", AttachStep::PeerUp, NetErrorCode::Internal),
            ("ns_route", AttachStep::DefaultRoute, NetErrorCode::Internal),
        ];
        for (tag, step, code) in cases {
            let f = Fake {
                fail_ns: Some(tag),
                ..Default::default()
            };
            let mut pool = ipam();
            let e = attach_container_with(&f, &spec("c1"), &mut pool, &mut PortRegistry::new())
                .unwrap_err();
            assert_eq!(e.step, step, "{tag}");
            assert_eq!(e.code(), code, "{tag}");
            assert_eq!(
                e.rollback.removed,
                [
                    AttachResource::Veth(host_of("c1")),
                    AttachResource::Netns(pin_of("c1"))
                ],
                "{tag}"
            );
            assert!(e.rollback.leftover.is_empty(), "{tag}");
            assert_eq!(pool.allocated_count(), 0, "{tag}");
            assert_eq!(pool.address_of(&eid("c1")), None, "{tag}");
            assert_eq!(pool.netns_dir_of(&eid("c1")), None, "{tag}");
            assert!(!f.calls().contains(&"release_socket".to_owned()), "{tag}");
        }
    }

    /// NET-1・TASK-139.3: netns 内の失敗時にロールバック自体が失敗しても元のエラーを保ち、資源が残った・
    /// 結果不明の間は IPAM のアドレスと受け口の予約を保持する（再払い出しで同じ IP を衝突させない）。
    #[test]
    fn net1_attach_config_failure_with_rollback_failure_keeps_address() {
        for (delete_err, unpin_fails) in [(Some(NetErrorCode::Timeout), false), (None, true)] {
            let f = Fake {
                fail_ns: Some("ns_route"),
                delete_err,
                unpin_fails,
                ..Default::default()
            };
            let mut pool = ipam();
            let mut reg = PortRegistry::new();
            let s = spec_with_ports("c1", vec![port(8080)]);
            let e = attach_container_with(&f, &s, &mut pool, &mut reg).unwrap_err();
            assert_eq!(e.step, AttachStep::DefaultRoute);
            assert_eq!(e.code(), NetErrorCode::Internal);
            let addr = pool.address_of(&eid("c1")).unwrap();
            assert_eq!(pool.allocated_count(), 1);
            // 保持したアドレスには置き場の記録も残る（削除時に残存 pin を同じ置き場で確認する。TASK-139.4）。
            assert_eq!(
                pool.netns_dir_of(&eid("c1")),
                Some(&NetnsDirRecord::new(netns_dir(), (8, 9)))
            );
            assert_eq!(reg.len(), 1);
            assert_eq!(
                e.rollback.leftover.last(),
                Some(&(AttachResource::Address(addr), ResourceState::Unknown))
            );
            if unpin_fails {
                assert!(
                    e.rollback
                        .leftover
                        .iter()
                        .any(|(r, _)| matches!(r, AttachResource::Netns(_)))
                );
            } else {
                assert_eq!(e.rollback.removed, [AttachResource::Netns(pin_of("c1"))]);
                assert_eq!(
                    e.rollback.leftover[0],
                    (AttachResource::Veth(host_of("c1")), ResourceState::Unknown)
                );
            }
        }
    }

    /// NET-1・TASK-139.3: DNAT バッチが確定的に失敗（`Aborted` / `NotSent`）なら nft 側の残置は報告せず、
    /// IPAM と受け口の予約も戻す。結果不明（`Unknown`）なら `PortRules` と `Address` を `Unknown` で報告し、
    /// 残ったルールが別コンテナへ転送しないよう IPAM のアドレスと受け口の予約を保持する（quarantine）。
    /// いずれも veth・netns は戻す。
    #[test]
    fn net1_attach_publish_failure_reports_unknown_rules() {
        for (outcome, unknown) in [
            (NftBatchOutcome::Aborted, false),
            (NftBatchOutcome::NotSent, false),
            (NftBatchOutcome::Unknown, true),
        ] {
            let f = Fake {
                fail_publish: Some((NetErrorCode::Timeout, outcome)),
                ..Default::default()
            };
            let mut pool = ipam();
            let mut reg = PortRegistry::new();
            let s = spec_with_ports("c1", vec![port(8080)]);
            let e = attach_container_with(&f, &s, &mut pool, &mut reg).unwrap_err();
            assert_eq!(e.step, AttachStep::PublishPorts);
            assert_eq!(e.code(), NetErrorCode::Timeout);
            assert_eq!(
                e.rollback.removed,
                [
                    AttachResource::Veth(host_of("c1")),
                    AttachResource::Netns(pin_of("c1"))
                ]
            );
            let want: Vec<(AttachResource, ResourceState)> = if unknown {
                vec![
                    (
                        AttachResource::PortRules(created().table.clone()),
                        ResourceState::Unknown,
                    ),
                    (AttachResource::Address(ip(2)), ResourceState::Unknown),
                ]
            } else {
                Vec::new()
            };
            assert_eq!(e.rollback.leftover, want, "{outcome:?}");
            assert_eq!(pool.allocated_count(), usize::from(unknown), "{outcome:?}");
            assert_eq!(reg.len(), usize::from(unknown), "{outcome:?}");
            if unknown {
                // 保持中のアドレスは別コンテナへ払い出されない。
                assert_eq!(pool.address_of(&eid("c1")), Some(ip(2)));
                assert_eq!(pool.allocate(&eid("c2")).unwrap(), ip(3));
            }
        }
    }

    /// NET-1・TASK-139.3: 既に公開済みの受け口（別コンテナ・別ネットワーク）を指定した接続は、veth・netns・IPAM を戻して `AlreadyExists`（`PublishPorts`）で失敗し、DNAT は投入しない。
    /// 公開済みの予約は壊れない。
    #[test]
    fn net1_attach_rejects_conflicting_listener() {
        let f = Fake::default();
        let mut pool = ipam();
        let mut reg = PortRegistry::new();
        attach_container_with(
            &f,
            &spec_with_ports("c1", vec![port(8080)]),
            &mut pool,
            &mut reg,
        )
        .unwrap();
        assert_eq!(reg.len(), 1);
        let f2 = Fake::default();
        let e = attach_container_with(
            &f2,
            &spec_with_ports("c2", vec![port(9090), port(8080)]),
            &mut pool,
            &mut reg,
        )
        .unwrap_err();
        assert_eq!(e.step, AttachStep::PublishPorts);
        assert_eq!(e.code(), NetErrorCode::AlreadyExists);
        assert_eq!(
            e.rollback.removed,
            [
                AttachResource::Veth(host_of("c2")),
                AttachResource::Netns(pin_of("c2"))
            ]
        );
        assert!(e.rollback.leftover.is_empty());
        assert!(!f2.calls().iter().any(|c| c.starts_with("publish")));
        assert_eq!(pool.allocated_count(), 1);
        assert_eq!(reg.len(), 1);
    }

    /// NET-1・TASK-139.3: 公開指定の件数上限と受け口の重複は `InvalidArgument`。
    #[test]
    fn net1_port_publishes_limits_and_duplicates() {
        let many: Vec<PortPublish> = (1..=65u16).map(port).collect();
        assert_eq!(many.len(), MAX_PORT_PUBLISHES + 1);
        let e = spec("c1").with_port_publishes(many).unwrap_err();
        assert_eq!(e.code(), NetErrorCode::InvalidArgument);
        let ok: Vec<PortPublish> = (1..=64u16).map(port).collect();
        assert!(spec("c1").with_port_publishes(ok).is_ok());
        let e = spec("c1")
            .with_port_publishes(vec![port(80), port(80)])
            .unwrap_err();
        assert_eq!(e.code(), NetErrorCode::InvalidArgument);
    }

    /// attach 後の公開の試験用に、投入内容を記録して結果を注入するクロージャの状態。
    fn publish_with(
        outcome: Option<(NetErrorCode, NftBatchOutcome)>,
        addr: IpPrefix,
        ports: &[PortPublish],
        reg: &mut PortRegistry,
        calls: &RefCell<Vec<String>>,
    ) -> Result<Vec<PublishedPort>, PublishPortsError> {
        super::publish_ports_with(
            |table, container, ports| {
                calls.borrow_mut().push(format!(
                    "publish {} {container} {}",
                    table.as_str(),
                    ports.len()
                ));
                match outcome {
                    Some((c, o)) => Err(NftApplyFailure {
                        error: NetError::new(c, "injected"),
                        outcome: o,
                    }),
                    None => Ok(test_handles(ports.len())),
                }
            },
            &created(),
            &eid("c1"),
            addr,
            ports,
            reg,
        )
    }

    /// NET-3・NET-4・#2839: 公開の成功結果は公開指定と同じ順の `PublishedPort` で、ハンドルとネットワーク・
    /// endpoint・受け口の束縛が具体値で一致する。ハンドルの本数が食い違う応答は結果不明として予約を保持する。
    #[test]
    fn net3_publish_returns_bound_handles_and_rejects_count_mismatch() {
        let calls = RefCell::new(Vec::new());
        let mut reg = PortRegistry::new();
        let got = publish_with(None, ip(2), &[port(8080), port(8081)], &mut reg, &calls).unwrap();
        let view: Vec<(u16, u64, u64)> = got
            .iter()
            .map(|p| {
                (
                    p.publish().host_port(),
                    p.prerouting_handle().get(),
                    p.output_handle().get(),
                )
            })
            .collect();
        assert_eq!(view, vec![(8080, 2, 3), (8081, 4, 5)]);
        assert!(got.iter().all(|p| p.network().as_str() == "web"));
        assert!(got.iter().all(|p| p.endpoint().as_str() == "c1"));

        let mut reg = PortRegistry::new();
        let e = super::publish_ports_with(
            |_, _, _| Ok(test_handles(1)),
            &created(),
            &eid("c1"),
            ip(2),
            &[port(8080), port(8081)],
            &mut reg,
        )
        .unwrap_err();
        assert_eq!(e.error.code(), NetErrorCode::Internal);
        assert!(e.rules_unknown);
        assert_eq!(reg.len(), 2, "reservation is kept when handles are unknown");
    }

    /// NET-3・#2839: attach 時の公開でも、ハンドルが公開指定の順に `AttachedContainer::published_ports` へ残る。
    #[test]
    fn net3_attach_keeps_published_handles() {
        let fake = Fake::default();
        let mut ipam = ipam();
        let mut ports = PortRegistry::new();
        let sp = spec("c1")
            .with_port_publishes(vec![port(8080), port(8081)])
            .unwrap();
        let c = attach_container_with(&fake, &sp, &mut ipam, &mut ports).unwrap();
        let view: Vec<(u16, u64, u64)> = c
            .published_ports
            .iter()
            .map(|p| {
                (
                    p.publish().host_port(),
                    p.prerouting_handle().get(),
                    p.output_handle().get(),
                )
            })
            .collect();
        assert_eq!(view, vec![(8080, 2, 3), (8081, 4, 5)]);
        let none = attach_container_with(&fake, &spec("c2"), &mut ipam, &mut ports).unwrap();
        assert!(none.published_ports.is_empty());
    }

    /// NET-1・NET-4: attach 後の公開は予約してから 1 バッチで投入する。衝突はバッチを送らない。
    #[test]
    fn net4_publish_after_attach_reserves_then_sends_one_batch() {
        let calls = RefCell::new(Vec::new());
        let mut reg = PortRegistry::new();
        publish_with(None, ip(2), &[port(8080)], &mut reg, &calls).unwrap();
        assert_eq!(reg.len(), 1);
        assert_eq!(calls.borrow().len(), 1);
        assert!(calls.borrow()[0].ends_with("10.89.0.2 1"));
        let e = publish_with(None, ip(2), &[port(8080)], &mut reg, &calls).unwrap_err();
        assert_eq!(e.error.code(), NetErrorCode::AlreadyExists);
        assert!(!e.rules_unknown);
        assert_eq!(calls.borrow().len(), 1, "no batch on conflict");
    }

    /// NET-4: 確定的な失敗は今回の予約だけを戻し、先の公開は残す。結果不明は予約を保持する。
    #[test]
    fn net4_publish_after_attach_failure_releases_only_own_reservation() {
        let calls = RefCell::new(Vec::new());
        let mut reg = PortRegistry::new();
        publish_with(None, ip(2), &[port(8081)], &mut reg, &calls).unwrap();
        for outcome in [NftBatchOutcome::Aborted, NftBatchOutcome::NotSent] {
            let e = publish_with(
                Some((NetErrorCode::Timeout, outcome)),
                ip(2),
                &[port(8080)],
                &mut reg,
                &calls,
            )
            .unwrap_err();
            assert_eq!(e.error.code(), NetErrorCode::Timeout);
            assert!(!e.rules_unknown, "{outcome:?}");
            assert_eq!(reg.len(), 1, "{outcome:?}");
        }
        let e = publish_with(
            Some((NetErrorCode::Timeout, NftBatchOutcome::Unknown)),
            ip(2),
            &[port(8080)],
            &mut reg,
            &calls,
        )
        .unwrap_err();
        assert!(e.rules_unknown);
        assert_eq!(reg.len(), 2);
    }

    /// NET-4: サブネット外のアドレスは `FailedPrecondition`、65 件と重複は `InvalidArgument`。
    #[test]
    fn net4_publish_after_attach_validates_inputs() {
        let calls = RefCell::new(Vec::new());
        let mut reg = PortRegistry::new();
        let outside = IpPrefix::new(IpAddr::V4(Ipv4Addr::new(10, 90, 0, 2)), 24).unwrap();
        let e = publish_with(None, outside, &[port(8080)], &mut reg, &calls).unwrap_err();
        assert_eq!(e.error.code(), NetErrorCode::FailedPrecondition);
        let many: Vec<PortPublish> = (0..=MAX_PORT_PUBLISHES as u16)
            .map(|i| port(1000 + i))
            .collect();
        assert_eq!(many.len(), MAX_PORT_PUBLISHES + 1);
        let e = publish_with(None, ip(2), &many, &mut reg, &calls).unwrap_err();
        assert_eq!(e.error.code(), NetErrorCode::InvalidArgument);
        let e = publish_with(None, ip(2), &[port(80), port(80)], &mut reg, &calls).unwrap_err();
        assert_eq!(e.error.code(), NetErrorCode::InvalidArgument);
        assert!(calls.borrow().is_empty());
        assert_eq!(reg.len(), 0);
    }

    // ---- 故障注入（attach_fault）の照合（NET-1・REPAIR-3・#2971） ----

    use super::attach_fault::{AttachFault, AttachFaultPoint, FaultyAttachOps, expected_record};

    /// 故障点、対応する Fake の呼び出し記録の接頭辞、IPAM 払い出し後の段か。
    const FAULT_POINTS: [(AttachFaultPoint, &str, bool); 6] = [
        (AttachFaultPoint::SetOwnerToken, "set_owner_token", false),
        (AttachFaultPoint::SetMaster, "set_master", false),
        (AttachFaultPoint::SetUp, "set_up", false),
        (AttachFaultPoint::MoveToNetns, "move_to_netns", false),
        (AttachFaultPoint::AddAddress, "ns_addr", true),
        (AttachFaultPoint::DefaultRoute, "ns_route", true),
    ];

    /// NET-1・REPAIR-3・#2971: 故障点ごとに、巻き戻しの失敗の 4 通りで残る資源・請求書の記録・IPAM の保持を
    /// 具体値で照合する。IPAM 払い出し前の段は IPAM を変えず、払い出し後の段は取り残しがあるときだけ
    /// アドレスを保持して quarantine の請求書になる。
    #[test]
    fn net1_attach_fault_leftover_matrix() {
        use AttachResource::{Netns, Veth};
        use ResourceState::{Present, Unknown};
        let host = host_of("c1");
        let pin = pin_of("c1");
        for (point, _, post_ipam) in FAULT_POINTS {
            // (veth 削除の失敗, unpin の失敗, removed, leftover, 請求書の (veth, netns))
            let ie = NetErrorCode::Internal;
            let to = NetErrorCode::Timeout;
            let cases = [
                (
                    Some(ie),
                    Some(ie),
                    vec![],
                    vec![(Veth(host.clone()), Present), (Netns(pin.clone()), Present)],
                    Some((true, true)),
                ),
                (
                    Some(to),
                    None,
                    vec![Netns(pin.clone())],
                    vec![(Veth(host.clone()), Unknown)],
                    Some((true, false)),
                ),
                (
                    None,
                    Some(ie),
                    vec![Veth(host.clone())],
                    vec![(Netns(pin.clone()), Present)],
                    Some((false, true)),
                ),
                (
                    None,
                    None,
                    vec![Veth(host.clone()), Netns(pin.clone())],
                    vec![],
                    None,
                ),
            ];
            for (veth_del, unpin, removed, mut leftover, flags) in cases {
                let mut fault = AttachFault::new(point);
                if let Some(c) = veth_del {
                    fault = fault.with_veth_delete_failure(c);
                }
                if let Some(c) = unpin {
                    fault = fault.with_unpin_failure(c);
                }
                let ops = FaultyAttachOps {
                    inner: Fake::default(),
                    fault,
                };
                let mut pool = ipam();
                let e =
                    attach_container_with(&ops, &spec("c1"), &mut pool, &mut PortRegistry::new())
                        .unwrap_err();
                let ctx = format!("{point:?} veth_del={veth_del:?} unpin={unpin:?}");
                assert_eq!(e.step, point.step(), "{ctx}");
                assert_eq!(e.code(), NetErrorCode::Internal, "{ctx}");
                assert_eq!(e.rollback.removed, removed, "{ctx}");
                let quarantine = post_ipam && !leftover.is_empty();
                if quarantine {
                    leftover.push((AttachResource::Address(ip(2)), Unknown));
                }
                assert_eq!(e.rollback.leftover, leftover, "{ctx}");
                match flags {
                    Some((veth, netns)) => {
                        let claim = e.reclaim_claim().expect(&ctx);
                        assert_eq!(
                            claim.to_record(),
                            expected_record("c1", veth, netns, quarantine),
                            "{ctx}"
                        );
                        assert_eq!(claim.quarantine_only().is_some(), quarantine, "{ctx}");
                    }
                    None => assert_eq!(e.reclaim_claim(), None, "{ctx}"),
                }
                // IPAM: 払い出し前の段は変えない。払い出し後の段は取り残しがあるときだけアドレスを保持する。
                let held = usize::from(quarantine);
                assert_eq!(pool.allocated_count(), held, "{ctx}");
                assert_eq!(
                    pool.address_of(&eid("c1")),
                    quarantine.then(|| ip(2)),
                    "{ctx}"
                );
            }
        }
    }

    /// NET-1・#2971: 故障点以外の操作は内側へ委譲される。巻き戻しの失敗を指定しなければ、呼び出し列は
    /// 成功時の列を故障点の直前で切り、続けて veth 削除と unpin が並ぶだけになる。
    #[test]
    fn net1_attach_fault_delegates_everything_else() {
        let ok = Fake::default();
        attach_container_with(&ok, &spec("c1"), &mut ipam(), &mut PortRegistry::new()).unwrap();
        let success = ok.calls();
        for (point, tag, _) in FAULT_POINTS {
            let ops = FaultyAttachOps {
                inner: Fake::default(),
                fault: AttachFault::new(point),
            };
            attach_container_with(&ops, &spec("c1"), &mut ipam(), &mut PortRegistry::new())
                .unwrap_err();
            let cut = success
                .iter()
                .position(|c| c.starts_with(tag))
                .expect("fault op appears in the success sequence");
            let mut expected: Vec<String> = success[..cut].to_vec();
            expected.push("delete_link 21".to_owned());
            expected.push("unpin_netns".to_owned());
            assert_eq!(ops.inner.calls(), expected, "{point:?}");
        }
    }

    /// NET-1・#2971: 巻き戻しの失敗は内側を呼ばずに返す（veth の削除も unpin も実際には行わない）。
    #[test]
    fn net1_attach_fault_rollback_failures_skip_inner() {
        let ops = FaultyAttachOps {
            inner: Fake::default(),
            fault: AttachFault::new(AttachFaultPoint::SetUp)
                .with_veth_delete_failure(NetErrorCode::Internal)
                .with_unpin_failure(NetErrorCode::Internal),
        };
        attach_container_with(&ops, &spec("c1"), &mut ipam(), &mut PortRegistry::new())
            .unwrap_err();
        let calls = ops.inner.calls();
        assert!(!calls.iter().any(|c| c.starts_with("delete_link")));
        assert!(!calls.iter().any(|c| c.starts_with("unpin_netns")));
        assert_eq!(calls.last().map(String::as_str), Some("set_master 21 7"));
    }
}
