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
//! bridge は作成時に `IFLA_IFALIAS` へ作成ごとに一意な所有トークンを付け、名前から ifindex を引く際に
//! トークン一致を確認する。不一致（同名 link への差し替え）なら操作も削除もしない。bridge 作成要求が
//! 送信後の応答エラー（`ResourceExhausted` 等）で失敗した場合は作成済みの可能性があるため
//! `ResourceState::Unknown` で報告する（確定的な拒否のみ空報告）。
//! 自分が作ったと確定した bridge のみ削除する（address は bridge と一緒に消える）。作成結果が
//! 不明（`Timeout` / `DataLoss`）なリソースは fail-closed で削除せず、[`RollbackReport::leftover`]
//! に `ResourceState::Unknown` として報告する。nft バッチは all-or-nothing なので `Aborted` /
//! `NotSent` では nft 側に何も残らない。
//!
//! # コンテナ接続（TASK-139.2.1・#847）
//!
//! [`attach_container`] はコンテナ単位の接続処理で、netns の作成と pin（`crate::netns`）→ veth ペア作成 →
//! host 側の bridge 接続（`IFLA_MASTER`）と up → peer 側の netns 移動までを行い、途中で失敗したら
//! 自分が作った veth と netns だけを戻す。veth は host 側 `fcvh` / peer 側 `fcvp` + [`EndpointId`] の
//! FNV-1a 下位 44bit hex 11 桁（[`VethNames`]。互換性に関わる契約）。veth には所有トークンを付けられない
//! ため `NLM_F_EXCL` 作成 + 直後の ifindex 確保 + ifindex 指定の削除で運用する（`attach_container_with` の doc）。
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
//! `RTM_DELADDR` / ルールハンドル取得が未実装のため個別の巻き戻しができず、netns 内の address・route は
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
//!   （ルールハンドルの取得経路が無い）、`RTM_DELROUTE` / `RTM_DELADDR`。担当 Issue 未確定
//! - IPAM 状態の永続化とプロセスをまたぐ残置 pin の清掃、コンテナ単体の切り離し。担当 Issue 未確定
//! - IPv6 と `NftFamily::Inet`（IPv4 のみ。静的 IPAM が IPv4 のみのため）

pub mod delete;
pub mod ipam;
pub mod publish;

use std::fmt;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
#[cfg(target_os = "linux")]
use std::time::Duration;

#[cfg(target_os = "linux")]
pub use delete::delete_network;
pub use delete::{DeleteResource, DeleteStep, NetworkDeleteError, NetworkDeleteReport};
pub(crate) use ipam::NetnsDirRecord;
pub use ipam::StaticIpam;
pub use publish::{MAX_PORT_PUBLISHES, PortProtocol, PortPublish, PortRegistry};

use crate::error::{NetError, NetErrorCode};
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
#[cfg(target_os = "linux")]
use crate::nftables_rules::RuleCreate;

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
    /// bridge の `IFLA_IFALIAS` に付けた所有トークン（接続時に同名の別 link でないことを確認する）。
    pub bridge_token: String,
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
        rollback_bridge(ops, &bridge, &token, index, &mut report);
        fail(e, step, report)
    };
    ensure_owned(ops, &bridge, &token, index).map_err(|e| step_fail(e, CreateStep::AddAddress))?;
    ops.add_address(index, &spec.gateway())
        .map_err(|e| step_fail(e, CreateStep::AddAddress))?;
    ensure_owned(ops, &bridge, &token, index).map_err(|e| step_fail(e, CreateStep::SetUp))?;
    ops.set_up(index)
        .map_err(|e| step_fail(e, CreateStep::SetUp))?;

    // 5. nft テーブル。バッチは all-or-nothing のため、Unknown 以外は nft 側に何も残らない。
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
    /// `network` は [`create_network`] が返したネットワーク。`netns_dir` は netns の pin を置く
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
    /// [`attach_container`] が [`PortRegistry`] で投入前に検出して接続を失敗させる。
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
}

impl ContainerAttachError {
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

/// host 側 veth の所有トークン（`IFLA_IFALIAS`）を、ネットワークの所有トークンと endpoint から導出する。
///
/// 接続（`attach_container`）が刻み、削除（`delete_network`。TASK-139.4・NET-1）が再導出して照合する
/// （呼び出し側が渡す `AttachedContainer::host_token` をそのまま所有の証明に使わないため）。形式
/// （`<bridge_token>/ep/<endpoint>`）は既存 veth の照合に関わる契約で、変更すると削除で所有を証明できなくなる。
pub(crate) fn host_owner_token(bridge_token: &str, endpoint: &EndpointId) -> String {
    format!("{bridge_token}/ep/{}", endpoint.as_str())
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
    fn publish_ports(
        &self,
        table: &NftName,
        container: Ipv4Addr,
        ports: &[PortPublish],
    ) -> Result<(), NftApplyFailure>;
}

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
/// veth は作成時に `IFLA_IFALIAS` を付けられない（`LinkCreate::with_alias` は veth を拒否する）ため、
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
    let fail = |error, step, rollback| ContainerAttachError {
        error,
        step,
        rollback,
    };
    let names = VethNames::derive(&spec.endpoint)
        .map_err(|e| fail(e, AttachStep::DeriveNames, AttachRollbackReport::default()))?;

    // default route の gateway（bridge アドレス）は IPv4 に限る。何かを作る前に確認する。
    let IpAddr::V4(gateway) = spec.gateway.addr() else {
        return Err(fail(
            NetError::new(
                NetErrorCode::FailedPrecondition,
                "network gateway is not an IPv4 address",
            ),
            AttachStep::DefaultRoute,
            AttachRollbackReport::default(),
        ));
    };

    // 別ネットワークの IPAM を渡す誤用は、何かを作る前に止める。
    if ipam.network() != &spec.network || ipam.gateway() != spec.gateway {
        return Err(fail(
            NetError::new(
                NetErrorCode::FailedPrecondition,
                "ipam pool does not belong to this network",
            ),
            AttachStep::AllocateAddress,
            AttachRollbackReport::default(),
        ));
    }

    // 何かを作る前に、接続先が作成時の bridge のままであることを確認する。
    match ops.owned_bridge_index(&spec.bridge, &spec.bridge_token) {
        Ok(i) if i == spec.bridge_index => {}
        Ok(_) => {
            return Err(fail(
                NetError::new(
                    NetErrorCode::FailedPrecondition,
                    "bridge ifindex changed (network was replaced)",
                ),
                AttachStep::VerifyBridge,
                AttachRollbackReport::default(),
            ));
        }
        Err(e) => {
            return Err(fail(
                e,
                AttachStep::VerifyBridge,
                AttachRollbackReport::default(),
            ));
        }
    }

    let pin = spec.netns_path();
    let (mut netns, pin_dir_id) = match ops.create_netns(&spec.netns_dir, &spec.endpoint) {
        Ok(created) => created,
        Err(f) => {
            let mut report = AttachRollbackReport::default();
            if let Some(state) = f.leftover {
                report.leftover.push((AttachResource::Netns(pin), state));
            }
            return Err(fail(f.error, AttachStep::CreateNetns, report));
        }
    };

    // 以降の失敗は、veth の後始末（あれば）→ netns の unpin の順で戻す。
    let abort =
        |netns: O::Netns, mut report: AttachRollbackReport, error: NetError, step: AttachStep| {
            rollback_netns(ops, netns, &pin, &mut report);
            fail(error, step, report)
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
    let host_token = host_owner_token(&spec.bridge_token, &spec.endpoint);
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
    if let Err(f) = configure_in_netns(ops, spec, &netns, names.peer(), address, gateway) {
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
        rollback_netns(ops, netns, &pin, &mut report);
        if !f.ports_unknown {
            // veth・netns の後始末が完了したことを確認できた場合に限り、払い出しと予約を戻す。
            // 資源が残った・結果不明の場合は、設定済みアドレスを持つ資源が生きている可能性があるため、
            // アドレスと受け口の予約を残して `leftover` で報告する（別コンテナへの再払い出しで衝突させない。
            // 特権操作の後始末の fail-closed）。解放は呼び出し側が資源の除去を確認してから行う。
            if report.leftover.is_empty() {
                let _ = ipam.release(&spec.endpoint);
                // 公開指定が無ければ共有予約表に予約は無い。解放の失敗は予約が残るため leftover で報告する。
                if !spec.ports.is_empty() && ports.release(&spec.network, &spec.endpoint).is_err() {
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
        return Err(fail(f.error, f.step, report));
    }
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
) -> Result<(), ConfigureFailure> {
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
        ops.publish_ports(&spec.table, container, &spec.ports)
            .map_err(|f| ConfigureFailure {
                ports_unknown: !matches!(
                    f.outcome,
                    NftBatchOutcome::Aborted | NftBatchOutcome::NotSent
                ),
                error: f.error,
                step: AttachStep::PublishPorts,
            })?;
    }
    Ok(())
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
    ) -> Result<(), NftApplyFailure> {
        self.nft
            .send_batch(self.timeout, |batch| {
                for port in ports {
                    // 外部から（prerouting）とホスト自身から（output）の両経路へ同じルールを入れる。
                    for chain in ["prerouting", "output"] {
                        let rule = RuleCreate::new(
                            NftFamily::Ipv4,
                            table.clone(),
                            NftName::new(chain)?,
                            port.dnat_rule_exprs(container)?,
                        );
                        batch.push_with(|seq| rule.build(seq))?;
                    }
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
        fn verify_owned(&self, _: &IfName, _: &str, _: IfIndex) -> Result<(), NetError> {
            self.rec("verify_owned");
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
                "verify_owned",
                "add_address",
                "verify_owned",
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
                    "link_index",
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

    /// NET-1: add_address 直前の所有再確認で差し替えを検出したら、操作も削除もせず Unknown で報告する。
    #[test]
    fn net1_replaced_before_add_address_touches_nothing() {
        let f = Fake {
            fail_verify_after: Some(0),
            ..Default::default()
        };
        let e = create_network_with(&f, &spec("web")).unwrap_err();
        assert_eq!(
            f.calls(),
            [
                "create_bridge",
                "link_index",
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
            fail_verify_after: Some(1),
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
            fail_verify_after: Some(2),
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
        ) -> Result<(), NftApplyFailure> {
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
                None => Ok(()),
            }
        }
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
                "set_owner_token 21 fandhe-net:web:1:0:0/ep/web-1".to_owned(),
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
}
