//! ネットワーク削除処理（bridge・veth・netns・専用 nft テーブルの一括解放。TASK-139.4・#317・NET-1・MS-8）。
//!
//! 親モジュール `network` の `create_network` と `attach_container` が作った資源を、名前を再導出して
//! 解放する統合層で、PoC-15 `netsetup` の `net-delete` に相当する。将来 `NetworkPlugin` 境界（TASK-114）の
//! `TearDownPod` 相当から呼ばれる想定で、現状の呼び出し元は結合テストのみ。
//!
//! # 参加中のコンテナの扱い
//!
//! 「明示的な解放」と「渡されていない生存コンテナの拒否」を組み合わせる。呼び出し側はネットワークに接続中の
//! コンテナ（[`AttachedContainer`]）を `containers` で渡し、渡されたものの veth と netns の pin を解放する。
//! IPAM に払い出しがあるのに渡されていない endpoint は、veth が存在する（または有無を判定できない）場合に
//! 何も変更せず `FailedPrecondition` で拒否する（fail-closed。生存コンテナの veth を bridge から外したまま
//! 孤児にしない）。veth が無いと確認できた endpoint（quarantine 中のアドレス等）は削除を続けるが、
//! `netns_dir` 直下の pin（`<netns_dir>/<endpoint>`）が残っている、または有無を判定できない場合は、
//! アドレスを解放せず保持して取り残しに載せる。
//!
//! # 順序
//!
//! 入力検証 → 渡されていない endpoint の preflight → コンテナごとの veth 削除と netns の unpin → bridge の
//! 所有確認 → 専用 nft テーブルの削除（配下の chain と DNAT ルールも消える）→ bridge の削除 → 予約の解放。
//! 各段を可能な限り試し（best-effort）、取り残しを [`NetworkDeleteReport::leftover`] にまとめて `Err` で
//! 返す。最初のエラーは後続の失敗で上書きしない（ERR-1）。各段は「すでに無い」（`NotFound`）を完了扱いにする。
//! unpin に失敗したコンテナは netns ハンドルごと [`NetworkDeleteError::retry`] で返すので、取り残しを
//! 片付けてから（`retry` を `containers` に渡して）再実行すれば成功に収束する。
//!
//! IPAM のアドレスとポート予約は、専用テーブルが消えたと確認できた場合にだけ解放する（残った DNAT ルールが
//! 再払い出し先へ転送しないための quarantine を維持する）。アドレスはさらに、その endpoint の veth と netns が
//! 解放済みの場合に限る。
//!
//! # nft テーブルの所有
//!
//! テーブル名はネットワーク名からの導出で、名前だけでは所有を証明できない。そのため bridge の所有確認
//! （作成時に付けた `IFLA_IFALIAS` のトークンと ifindex の一致）が通った場合にだけテーブルを削除する。
//! 確認できない（別 link への差し替え・判定不能）ならテーブルには触れず `Unknown` で報告する。bridge は
//! テーブルの削除を確認してから消す（テーブルの削除に失敗したら bridge を残し、再実行で証明を再利用する）。
//! bridge が無い場合は前回の削除でテーブルも解放済みと扱う（bridge はテーブルの後に消すため）。
//!
//! # 残余リスクと未実装（REPAIR-3）
//!
//! - nft テーブル自体の所有（ハンドル・userdata での照合）は未実装で、bridge の所有確認による間接的な証明に
//!   とどまる。bridge が外部から先に消された場合、テーブルが残っていても解放済みと扱う。担当 Issue 未確定
//! - link の dump API が無いため、IPAM に記録されていない孤児 veth は回収しない。担当 Issue 未確定
//! - コンテナ単体の切り離しと、プロセスをまたぐ残置 pin の清掃は未実装。担当 Issue 未確定

use std::collections::HashSet;
use std::path::{Path, PathBuf};
#[cfg(target_os = "linux")]
use std::time::Duration;

use crate::error::{NetError, NetErrorCode};
use crate::netlink_route::{IfIndex, IfName, IpPrefix};
#[cfg(target_os = "linux")]
use crate::netlink_route::{LinkDelete, NetlinkRouteSocket};
#[cfg(target_os = "linux")]
use crate::netns::{self, ContainerNetns};
#[cfg(target_os = "linux")]
use crate::nftables_batch::{NetlinkNetfilterSocket, NftFamily, TableDelete};
use crate::nftables_batch::{NftBatchOutcome, NftName};

#[cfg(target_os = "linux")]
use super::link_ref;
use super::{
    AttachedContainer, CreatedNetwork, EndpointId, NetworkName, NftApplyFailure, PortRegistry,
    ResourceState, StaticIpam, UnpinFailure, VethNames, is_indeterminate,
};

/// 失敗した手順。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DeleteStep {
    /// 入力の検証（何も変更しない）。
    Validate,
    /// 渡されていない endpoint の生存確認（何も変更しない）。
    Preflight,
    /// veth の削除。
    DeleteVeth,
    /// netns の pin 解除。
    UnpinNetns,
    /// 専用 nft テーブルの削除。
    DeleteNftTable,
    /// bridge の削除。
    DeleteBridge,
    /// IPAM・ポート予約の解放。
    ReleaseReservations,
}

/// 削除対象のリソース。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DeleteResource {
    /// bridge。
    Bridge(IfName),
    /// 専用 nft テーブル。
    NftTable(NftName),
    /// veth ペア（host 側の名前）。
    Veth(IfName),
    /// pin 済みの netns（pin 先パス）。
    Netns(PathBuf),
    /// IPAM のアドレス。
    Address(EndpointId, IpPrefix),
    /// ポート予約（ネットワーク単位）。
    PortReservation(NetworkName),
}

/// ネットワーク削除の結果。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct NetworkDeleteReport {
    /// 解放できたリソース。「すでに無かった」ものも含む。
    pub removed: Vec<DeleteResource>,
    /// 取り残したリソースとその状態（結果不明は fail-closed で `Unknown`）。
    pub leftover: Vec<(DeleteResource, ResourceState)>,
}

/// ネットワーク削除の失敗（最初の原因・失敗手順・解放の結果。ERR-1）。
#[derive(Debug)]
#[non_exhaustive]
pub struct NetworkDeleteError<N = ()> {
    /// 最初の失敗の原因（後続の失敗で上書きしない）。
    pub error: NetError,
    /// 最初に失敗した手順。
    pub step: DeleteStep,
    /// ここまでに解放できたものと取り残し。
    pub report: NetworkDeleteReport,
    /// pin の解除に失敗したコンテナ（netns ハンドルを手放さずに返す）。`containers` にそのまま渡して
    /// 再実行すると unpin を再試行できる（ハンドルを drop すると fd が閉じ、再試行の経路を失うため）。
    pub retry: Vec<AttachedContainer<N>>,
}

impl<N> NetworkDeleteError<N> {
    /// 機械可読な分類。
    pub fn code(&self) -> NetErrorCode {
        self.error.code()
    }

    /// 英語のメッセージ。
    pub fn message(&self) -> &str {
        self.error.message()
    }
}

impl<N> std::fmt::Display for NetworkDeleteError<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.error.fmt(f)
    }
}

impl<N: std::fmt::Debug> std::error::Error for NetworkDeleteError<N> {}

/// 削除手順が使うカーネル操作の境界。Linux 実装とテストの fake を差し替えるための crate 内部トレイトで、
/// 公開の拡張点（PLUG-1）ではない。作成・接続の trait とは独立。
pub(crate) trait DeleteOps {
    /// netns ハンドル（Linux では fd と pin パス）。
    type Netns;
    /// 名前から ifindex を引く。
    fn link_index(&self, name: &IfName) -> Result<IfIndex, NetError>;
    /// bridge の名前から ifindex を引く。`IFLA_IFALIAS` が `token` と一致しなければ `FailedPrecondition`。
    fn owned_bridge_index(&self, name: &IfName, token: &str) -> Result<IfIndex, NetError>;
    /// ifindex 指定で link を削除する（veth は peer も消える）。
    fn delete_link(&self, link: IfIndex) -> Result<(), NetError>;
    /// pin を外す。失敗時はハンドルを返す。
    fn unpin_netns(&self, ns: Self::Netns) -> Result<(), UnpinFailure<Self::Netns>>;
    /// pin 先に何か残っているか（`symlink_metadata` 相当。`NotFound` だけが `Ok(false)`）。
    fn pin_exists(&self, path: &Path) -> Result<bool, NetError>;
    /// 専用テーブルを削除する（配下の chain・ルールも消える）。
    fn delete_table(&self, table: &NftName) -> Result<(), NftApplyFailure>;
}

fn precondition(msg: &'static str) -> NetError {
    NetError::new(NetErrorCode::FailedPrecondition, msg)
}

fn state_of(code: NetErrorCode) -> ResourceState {
    if is_indeterminate(code) {
        ResourceState::Unknown
    } else {
        ResourceState::Present
    }
}

/// 最初のエラーだけを保持する記録（ERR-1）。
#[derive(Default)]
struct Failures {
    first: Option<(NetError, DeleteStep)>,
}

impl Failures {
    fn note(&mut self, error: NetError, step: DeleteStep) {
        if self.first.is_none() {
            self.first = Some((error, step));
        }
    }
}

fn fail<N>(
    error: NetError,
    step: DeleteStep,
    report: NetworkDeleteReport,
) -> NetworkDeleteError<N> {
    NetworkDeleteError {
        error,
        step,
        report,
        retry: Vec::new(),
    }
}

/// bridge の所有確認の結果。nft テーブルの所有の証明にも使う（モジュール doc「nft テーブルの所有」）。
enum BridgeProof {
    /// 所有トークンと ifindex が一致した（このネットワークの bridge が生きている）。
    Owned,
    /// bridge が無い（前回の削除で解放済み）。
    Gone,
    /// 別 link への差し替え・判定不能。
    Unproven(NetError),
}

fn prove_bridge<O: DeleteOps>(ops: &O, network: &CreatedNetwork) -> BridgeProof {
    match ops.owned_bridge_index(&network.bridge, &network.bridge_token) {
        Ok(now) if now == network.bridge_index => BridgeProof::Owned,
        Ok(_) => BridgeProof::Unproven(precondition("bridge ifindex changed (link was replaced)")),
        Err(e) if e.code() == NetErrorCode::NotFound => BridgeProof::Gone,
        Err(e) => BridgeProof::Unproven(e),
    }
}

/// 削除手順本体（OS 非依存。`ops` を差し替えて 3 OS で単体テストできる）。手順と方針はモジュール doc。
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn delete_network_with<O: DeleteOps>(
    ops: &O,
    network: &CreatedNetwork,
    containers: Vec<AttachedContainer<O::Netns>>,
    netns_dir: &Path,
    ipam: &mut StaticIpam,
    ports: &mut PortRegistry,
) -> Result<NetworkDeleteReport, NetworkDeleteError<O::Netns>> {
    let mut report = NetworkDeleteReport::default();

    // 0. 入力検証（何も変更しない）。
    if ipam.network() != &network.name || ipam.gateway() != network.gateway {
        return Err(fail(
            precondition("ipam does not belong to the network"),
            DeleteStep::Validate,
            report,
        ));
    }
    let mut passed: HashSet<EndpointId> = HashSet::new();
    for c in &containers {
        if !passed.insert(c.endpoint.clone()) {
            return Err(fail(
                NetError::new(
                    NetErrorCode::InvalidArgument,
                    "duplicate endpoint in containers",
                ),
                DeleteStep::Validate,
                report,
            ));
        }
        let names = VethNames::derive(&c.endpoint)
            .map_err(|e| fail(e, DeleteStep::Validate, NetworkDeleteReport::default()))?;
        if ipam.address_of(&c.endpoint) != Some(c.address) || names.host() != &c.host_veth {
            return Err(fail(
                precondition("container does not belong to the network"),
                DeleteStep::Validate,
                report,
            ));
        }
    }

    // 1. preflight。渡されていない endpoint の veth が存在する（判定できない）なら何も触らず拒否する。
    let unpassed: Vec<EndpointId> = ipam
        .endpoints()
        .filter(|(e, _)| !passed.contains(*e))
        .map(|(e, _)| e.clone())
        .collect();
    // アドレスを解放してよい endpoint（veth・netns とも解放済み）。
    let mut releasable: Vec<EndpointId> = Vec::new();
    // veth は無いが pin が残っている（または判定できない）endpoint。アドレスを保持して報告する。
    let mut pin_kept: Vec<(PathBuf, ResourceState, NetError)> = Vec::new();
    for endpoint in unpassed {
        let names = VethNames::derive(&endpoint)
            .map_err(|e| fail(e, DeleteStep::Preflight, NetworkDeleteReport::default()))?;
        match ops.link_index(names.host()) {
            Err(e) if e.code() == NetErrorCode::NotFound => {
                // veth が無くても netns の pin が残っていれば、中のコンテナは生きているかもしれない。
                let pin = netns_dir.join(endpoint.as_str());
                match ops.pin_exists(&pin) {
                    Ok(false) => releasable.push(endpoint),
                    Ok(true) => pin_kept.push((
                        pin,
                        ResourceState::Present,
                        precondition("netns pin of an unpassed endpoint remains"),
                    )),
                    Err(e) => pin_kept.push((pin, ResourceState::Unknown, e)),
                }
            }
            _ => {
                return Err(fail(
                    precondition("a live container is attached but not passed to delete"),
                    DeleteStep::Preflight,
                    report,
                ));
            }
        }
    }

    let mut failures = Failures::default();
    for (pin, state, error) in pin_kept {
        report.leftover.push((DeleteResource::Netns(pin), state));
        failures.note(error, DeleteStep::Preflight);
    }
    let mut retry: Vec<AttachedContainer<O::Netns>> = Vec::new();

    // 2. コンテナ側の解放。veth を ifindex 指定で消してから pin を外す。
    for c in containers {
        let AttachedContainer {
            endpoint,
            host_veth,
            host_index,
            peer_veth,
            netns_path,
            address,
            netns,
        } = c;
        let veth_gone = delete_veth(ops, &host_veth, host_index, &mut report, &mut failures);
        let unpinned = match ops.unpin_netns(netns) {
            Ok(()) => {
                report.removed.push(DeleteResource::Netns(netns_path));
                true
            }
            Err(UnpinFailure { error, netns }) => {
                report.leftover.push((
                    DeleteResource::Netns(netns_path.clone()),
                    state_of(error.code()),
                ));
                failures.note(error, DeleteStep::UnpinNetns);
                // ハンドルを手放さず呼び出し側へ返し、再試行の経路を保つ。
                retry.push(AttachedContainer {
                    endpoint: endpoint.clone(),
                    host_veth,
                    host_index,
                    peer_veth,
                    netns_path,
                    address,
                    netns,
                });
                false
            }
        };
        if veth_gone && unpinned {
            releasable.push(endpoint);
        }
    }

    // 3. 専用 nft テーブル。bridge の所有確認（作成時の IFLA_IFALIAS トークン）をテーブルの所有の証明にする。
    //    bridge が無ければ前回の削除でテーブルも解放済み（bridge はテーブルの後に消す）と扱い、
    //    名前だけでは所有を証明できないテーブルには触れない。
    let proof = prove_bridge(ops, network);
    let table_gone = match &proof {
        BridgeProof::Gone => true,
        BridgeProof::Unproven(_) => {
            report.leftover.push((
                DeleteResource::NftTable(network.table.clone()),
                ResourceState::Unknown,
            ));
            false
        }
        BridgeProof::Owned => match ops.delete_table(&network.table) {
            Ok(()) => true,
            // `Aborted` + `NotFound` は「すでに無い」（冪等）。
            Err(f)
                if f.outcome == NftBatchOutcome::Aborted
                    && f.error.code() == NetErrorCode::NotFound =>
            {
                true
            }
            Err(f) => {
                let state = if f.outcome == NftBatchOutcome::Unknown {
                    ResourceState::Unknown
                } else {
                    ResourceState::Present
                };
                report
                    .leftover
                    .push((DeleteResource::NftTable(network.table.clone()), state));
                failures.note(f.error, DeleteStep::DeleteNftTable);
                false
            }
        },
    };
    if table_gone {
        report
            .removed
            .push(DeleteResource::NftTable(network.table.clone()));
    }

    // 4. bridge。テーブルが消えたと確認できてから ifindex 指定で消す（失敗時に所有の証明を残し、再実行で収束させる）。
    delete_bridge(ops, network, proof, table_gone, &mut report, &mut failures);

    // 5. 予約の解放。テーブルが消えたと確認できた場合だけ。
    if table_gone {
        match ports.release_network(&network.name) {
            Ok(_) => report
                .removed
                .push(DeleteResource::PortReservation(network.name.clone())),
            Err(e) => {
                report.leftover.push((
                    DeleteResource::PortReservation(network.name.clone()),
                    ResourceState::Present,
                ));
                failures.note(e, DeleteStep::ReleaseReservations);
            }
        }
        for endpoint in releasable {
            if let Ok(addr) = ipam.release(&endpoint) {
                report.removed.push(DeleteResource::Address(endpoint, addr));
            }
        }
    }

    match failures.first {
        None => Ok(report),
        Some((error, step)) => Err(NetworkDeleteError {
            error,
            step,
            report,
            retry,
        }),
    }
}

/// veth を ifindex 指定で削除する。消えている（または今回消せた）なら `true`。
fn delete_veth<O: DeleteOps>(
    ops: &O,
    host: &IfName,
    expected: IfIndex,
    report: &mut NetworkDeleteReport,
    failures: &mut Failures,
) -> bool {
    let res = DeleteResource::Veth(host.clone());
    match ops.link_index(host) {
        Err(e) if e.code() == NetErrorCode::NotFound => {
            report.removed.push(res);
            true
        }
        Err(e) => {
            // 存在を確認できない。名前では消さない。
            report.leftover.push((res, ResourceState::Unknown));
            failures.note(e, DeleteStep::DeleteVeth);
            false
        }
        Ok(now) if now != expected => {
            // 同名の別 link に差し替わっている。巻き込まない。
            report.leftover.push((res, ResourceState::Unknown));
            failures.note(
                precondition("veth ifindex changed (link was replaced)"),
                DeleteStep::DeleteVeth,
            );
            false
        }
        Ok(_) => match ops.delete_link(expected) {
            Ok(()) => {
                report.removed.push(res);
                true
            }
            Err(e) if e.code() == NetErrorCode::NotFound => {
                report.removed.push(res);
                true
            }
            Err(e) => {
                report.leftover.push((res, state_of(e.code())));
                failures.note(e, DeleteStep::DeleteVeth);
                false
            }
        },
    }
}

/// bridge を、確認済みの所有（`proof`）に基づいて削除する。`table_gone` でなければ削除しない
/// （テーブルの所有の証明となる bridge を残し、再実行で収束させる）。
fn delete_bridge<O: DeleteOps>(
    ops: &O,
    network: &CreatedNetwork,
    proof: BridgeProof,
    table_gone: bool,
    report: &mut NetworkDeleteReport,
    failures: &mut Failures,
) {
    let res = DeleteResource::Bridge(network.bridge.clone());
    match proof {
        BridgeProof::Gone => report.removed.push(res),
        BridgeProof::Unproven(e) => {
            // トークン不一致・判定不能。別 link を巻き込まない。
            report.leftover.push((res, ResourceState::Unknown));
            failures.note(e, DeleteStep::DeleteBridge);
        }
        BridgeProof::Owned if !table_gone => {
            report.leftover.push((res, ResourceState::Present));
        }
        BridgeProof::Owned => match ops.delete_link(network.bridge_index) {
            Ok(()) => report.removed.push(res),
            Err(e) if e.code() == NetErrorCode::NotFound => report.removed.push(res),
            Err(e) => {
                report.leftover.push((res, state_of(e.code())));
                failures.note(e, DeleteStep::DeleteBridge);
            }
        },
    }
}

/// Linux のカーネル実装。各要求に `timeout` を期限として渡す（REPAIR-5）。
#[cfg(target_os = "linux")]
struct LinuxDeleteOps<'a> {
    route: &'a NetlinkRouteSocket,
    nft: &'a NetlinkNetfilterSocket,
    timeout: Duration,
}

#[cfg(target_os = "linux")]
impl DeleteOps for LinuxDeleteOps<'_> {
    type Netns = ContainerNetns;

    fn link_index(&self, name: &IfName) -> Result<IfIndex, NetError> {
        self.route.link_index(name, self.timeout)
    }

    fn owned_bridge_index(&self, name: &IfName, token: &str) -> Result<IfIndex, NetError> {
        self.route.link_index_owned(name, token, self.timeout)
    }

    fn delete_link(&self, link: IfIndex) -> Result<(), NetError> {
        self.route
            .delete_link(&LinkDelete::new(link_ref(link)?), self.timeout)
            .map(|_| ())
    }

    fn unpin_netns(&self, ns: ContainerNetns) -> Result<(), UnpinFailure<ContainerNetns>> {
        netns::unpin(ns)
    }

    fn pin_exists(&self, path: &Path) -> Result<bool, NetError> {
        match std::fs::symlink_metadata(path) {
            Ok(_) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(NetError::new(
                NetErrorCode::Internal,
                match e.raw_os_error() {
                    Some(errno) => format!("stat netns pin failed: errno {errno}"),
                    None => "stat netns pin failed".to_owned(),
                },
            )),
        }
    }

    fn delete_table(&self, table: &NftName) -> Result<(), NftApplyFailure> {
        self.nft
            .send_batch(self.timeout, |batch| {
                batch
                    .push_with(|seq| TableDelete::new(NftFamily::Ipv4, table.clone()).build(seq))?;
                Ok(())
            })
            .map(|_| ())
            .map_err(|e| NftApplyFailure {
                outcome: e.outcome(),
                error: e.into(),
            })
    }
}

/// ネットワークを削除する（コンテナ側の veth・netns pin → 専用 nft テーブル → bridge → IPAM・ポート予約）。
///
/// `containers` は接続中のコンテナで、渡されたものを明示的に解放する。渡されていない生存コンテナがあれば
/// 何も変更せず `FailedPrecondition` で拒否する（モジュール doc「参加中のコンテナの扱い」）。
/// 取り残しがあれば `Err` で、[`NetworkDeleteError::report`] に解放済みと取り残しを全件載せる。
/// `CAP_NET_ADMIN` と、unpin に必要な `CAP_SYS_ADMIN` は呼び出し側の責務で、本 crate は権限を上げない。
/// `netns_dir` は接続時に渡した netns の pin 置き場で、渡されていない endpoint の pin の残存確認に使う。
/// pin の解除に失敗したコンテナは [`NetworkDeleteError::retry`] で netns ハンドルごと返る。
/// `timeout` は各カーネル要求の期限（REPAIR-5）。
#[cfg(target_os = "linux")]
// 公開 API の引数は、カーネル操作の socket 2 本・削除対象・状態 2 種・期限で、まとめる単位が無い。
#[allow(clippy::too_many_arguments)]
pub fn delete_network(
    route: &NetlinkRouteSocket,
    nft: &NetlinkNetfilterSocket,
    network: &CreatedNetwork,
    containers: Vec<AttachedContainer<ContainerNetns>>,
    netns_dir: &Path,
    ipam: &mut StaticIpam,
    ports: &mut PortRegistry,
    timeout: Duration,
) -> Result<NetworkDeleteReport, NetworkDeleteError<ContainerNetns>> {
    delete_network_with(
        &LinuxDeleteOps {
            route,
            nft,
            timeout,
        },
        network,
        containers,
        netns_dir,
        ipam,
        ports,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::netlink_route::IfIndex;
    use crate::network::NetworkResourceNames;
    use std::cell::RefCell;
    use std::net::{IpAddr, Ipv4Addr};

    const TOKEN: &str = "fandhe-net:web:1:0:0";

    fn eid(s: &str) -> EndpointId {
        EndpointId::new(s).unwrap()
    }

    fn created() -> CreatedNetwork {
        let names = NetworkResourceNames::derive(&NetworkName::new("web").unwrap()).unwrap();
        CreatedNetwork {
            name: NetworkName::new("web").unwrap(),
            bridge: names.bridge().clone(),
            bridge_index: IfIndex::new(7).unwrap(),
            bridge_token: TOKEN.to_owned(),
            table: names.table().clone(),
            gateway: IpPrefix::new(IpAddr::V4(Ipv4Addr::new(10, 89, 0, 1)), 24).unwrap(),
        }
    }

    fn err(code: NetErrorCode) -> NetError {
        NetError::new(code, "injected")
    }

    /// 呼び出しを記録し、失敗を注入する fake。veth の ifindex は 21 固定。
    #[derive(Default)]
    struct Fake {
        calls: RefCell<Vec<String>>,
        /// veth が存在しない endpoint の host 名に含まれる印は使わず、名前集合で指定する。
        absent_veths: Vec<String>,
        veth_lookup_err: Option<NetErrorCode>,
        veth_index: Option<u32>,
        veth_delete_err: Option<NetErrorCode>,
        unpin_fails: bool,
        /// pin が残っている（`Ok(true)`）とみなす endpoint 名。
        pins_present: Vec<PathBuf>,
        pin_check_err: bool,
        table_err: Option<(NetErrorCode, NftBatchOutcome)>,
        bridge_lookup_err: Option<NetErrorCode>,
        bridge_index: Option<u32>,
        bridge_delete_err: Option<NetErrorCode>,
    }

    impl Fake {
        fn rec(&self, s: impl Into<String>) {
            self.calls.borrow_mut().push(s.into());
        }
        fn calls(&self) -> Vec<String> {
            self.calls.borrow().clone()
        }
    }

    impl DeleteOps for Fake {
        type Netns = ();

        fn link_index(&self, name: &IfName) -> Result<IfIndex, NetError> {
            self.rec(format!("link_index {}", name.as_str()));
            if self.absent_veths.iter().any(|n| n == name.as_str()) {
                return Err(err(NetErrorCode::NotFound));
            }
            if let Some(c) = self.veth_lookup_err {
                return Err(err(c));
            }
            IfIndex::new(self.veth_index.unwrap_or(21))
        }
        fn owned_bridge_index(&self, name: &IfName, token: &str) -> Result<IfIndex, NetError> {
            self.rec(format!("owned_bridge_index {}", name.as_str()));
            if token != TOKEN {
                return Err(err(NetErrorCode::FailedPrecondition));
            }
            if let Some(c) = self.bridge_lookup_err {
                return Err(err(c));
            }
            IfIndex::new(self.bridge_index.unwrap_or(7))
        }
        fn delete_link(&self, link: IfIndex) -> Result<(), NetError> {
            self.rec(format!("delete_link {}", link.get()));
            let e = if link.get() == 7 {
                self.bridge_delete_err
            } else {
                self.veth_delete_err
            };
            e.map_or(Ok(()), |c| Err(err(c)))
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
        fn pin_exists(&self, path: &Path) -> Result<bool, NetError> {
            self.rec(format!("pin_exists {}", path.display()));
            if self.pin_check_err {
                return Err(err(NetErrorCode::Internal));
            }
            Ok(self.pins_present.iter().any(|p| p == path))
        }
        fn delete_table(&self, table: &NftName) -> Result<(), NftApplyFailure> {
            self.rec(format!("delete_table {}", table.as_str()));
            match self.table_err {
                Some((c, outcome)) => Err(NftApplyFailure {
                    error: err(c),
                    outcome,
                }),
                None => Ok(()),
            }
        }
    }

    fn host_of(id: &str) -> IfName {
        VethNames::derive(&eid(id)).unwrap().host().clone()
    }

    fn netns_dir() -> PathBuf {
        std::env::temp_dir().join("fc-netns")
    }

    fn pin(id: &str) -> PathBuf {
        netns_dir().join(id)
    }

    /// `ipam` へ払い出した endpoint を `AttachedContainer` として組む。
    fn attached(ipam: &mut StaticIpam, id: &str) -> AttachedContainer<()> {
        let endpoint = eid(id);
        let address = ipam.allocate(&endpoint).unwrap();
        let names = VethNames::derive(&endpoint).unwrap();
        AttachedContainer {
            endpoint,
            host_veth: names.host().clone(),
            host_index: IfIndex::new(21).unwrap(),
            peer_veth: names.peer().clone(),
            netns_path: pin(id),
            address,
            netns: (),
        }
    }

    fn setup() -> (CreatedNetwork, StaticIpam, PortRegistry) {
        let net = created();
        let ipam = StaticIpam::for_network(&net).unwrap();
        (net, ipam, PortRegistry::new())
    }

    fn reserve_port(ports: &mut PortRegistry, id: &str, host_port: u16) {
        use crate::network::{PortProtocol, PortPublish};
        let p = PortPublish::new(
            PortProtocol::Tcp,
            Ipv4Addr::new(192, 0, 2, 10),
            host_port,
            80,
        )
        .unwrap();
        ports
            .reserve(&NetworkName::new("web").unwrap(), &eid(id), &[p])
            .unwrap();
    }

    /// NET-1・TASK-139.4: 正常系は veth → unpin → テーブル → bridge の順に解放し、IPAM と予約が空になる。
    #[test]
    fn net1_delete_success_releases_everything() {
        let (net, mut ipam, mut ports) = setup();
        let c1 = attached(&mut ipam, "c1");
        let addr = c1.address;
        reserve_port(&mut ports, "c1", 8080);
        let fake = Fake::default();
        let report =
            delete_network_with(&fake, &net, vec![c1], &netns_dir(), &mut ipam, &mut ports)
                .unwrap();
        let host = host_of("c1");
        assert_eq!(
            fake.calls(),
            vec![
                format!("link_index {}", host.as_str()),
                "delete_link 21".to_owned(),
                "unpin_netns".to_owned(),
                format!("owned_bridge_index {}", net.bridge.as_str()),
                format!("delete_table {}", net.table.as_str()),
                "delete_link 7".to_owned(),
            ]
        );
        assert_eq!(
            report.removed,
            vec![
                DeleteResource::Veth(host),
                DeleteResource::Netns(pin("c1")),
                DeleteResource::NftTable(net.table.clone()),
                DeleteResource::Bridge(net.bridge.clone()),
                DeleteResource::PortReservation(net.name.clone()),
                DeleteResource::Address(eid("c1"), addr),
            ]
        );
        assert!(report.leftover.is_empty());
        assert_eq!(ipam.allocated_count(), 0);
        assert!(ports.is_empty());
    }

    /// NET-1・TASK-139.4: 渡されていない endpoint の veth が存在すると、何も変更せず拒否する。
    #[test]
    fn net1_delete_rejects_unpassed_live_endpoint() {
        let (net, mut ipam, mut ports) = setup();
        let _unpassed = attached(&mut ipam, "c1");
        let fake = Fake::default();
        let e = delete_network_with(&fake, &net, vec![], &netns_dir(), &mut ipam, &mut ports)
            .unwrap_err();
        assert_eq!(e.code(), NetErrorCode::FailedPrecondition);
        assert_eq!(e.step, DeleteStep::Preflight);
        assert_eq!(
            fake.calls(),
            vec![format!("link_index {}", host_of("c1").as_str())]
        );
        assert_eq!(ipam.allocated_count(), 1);
    }

    /// NET-1・TASK-139.4: preflight で veth の有無を判定できない（`Timeout`）場合も拒否する。
    #[test]
    fn net1_delete_preflight_timeout_rejects() {
        let (net, mut ipam, mut ports) = setup();
        let _unpassed = attached(&mut ipam, "c1");
        let fake = Fake {
            veth_lookup_err: Some(NetErrorCode::Timeout),
            ..Fake::default()
        };
        let e = delete_network_with(&fake, &net, vec![], &netns_dir(), &mut ipam, &mut ports)
            .unwrap_err();
        assert_eq!(e.code(), NetErrorCode::FailedPrecondition);
        assert_eq!(e.step, DeleteStep::Preflight);
        assert_eq!(fake.calls().len(), 1);
    }

    /// NET-1・TASK-139.4: 渡されていない endpoint の veth が無ければ（quarantine 中のアドレス）、
    /// テーブルの削除後に IPAM と予約を解放する。
    #[test]
    fn net1_delete_releases_quarantined_endpoint() {
        let (net, mut ipam, mut ports) = setup();
        let _q = attached(&mut ipam, "c1");
        reserve_port(&mut ports, "c1", 8080);
        let fake = Fake {
            absent_veths: vec![host_of("c1").as_str().to_owned()],
            ..Fake::default()
        };
        let report =
            delete_network_with(&fake, &net, vec![], &netns_dir(), &mut ipam, &mut ports).unwrap();
        assert!(report.leftover.is_empty());
        assert_eq!(ipam.allocated_count(), 0);
        assert!(ports.is_empty());
    }

    /// NET-1・TASK-139.4: 検証違反は何も呼ばずに失敗する（IPAM 不一致・アドレス不一致・重複）。
    #[test]
    fn net1_delete_validation_touches_nothing() {
        let (net, mut ipam, mut ports) = setup();
        let c1 = attached(&mut ipam, "c1");
        let fake = Fake::default();

        // 別ネットワークの IPAM。
        let mut other = StaticIpam::new(
            &NetworkName::new("db").unwrap(),
            IpPrefix::new(IpAddr::V4(Ipv4Addr::new(10, 90, 0, 1)), 24).unwrap(),
        )
        .unwrap();
        let e = delete_network_with(&fake, &net, vec![], &netns_dir(), &mut other, &mut ports)
            .unwrap_err();
        assert_eq!(
            (e.code(), e.step),
            (NetErrorCode::FailedPrecondition, DeleteStep::Validate)
        );

        // アドレス不一致。
        let mut bad = attached(&mut ipam, "c2");
        bad.address = c1.address;
        let e = delete_network_with(&fake, &net, vec![bad], &netns_dir(), &mut ipam, &mut ports)
            .unwrap_err();
        assert_eq!(
            (e.code(), e.step),
            (NetErrorCode::FailedPrecondition, DeleteStep::Validate)
        );

        // host_veth 不一致。
        let mut bad = attached(&mut ipam, "c3");
        bad.host_veth = host_of("zzz");
        let e = delete_network_with(&fake, &net, vec![bad], &netns_dir(), &mut ipam, &mut ports)
            .unwrap_err();
        assert_eq!(e.code(), NetErrorCode::FailedPrecondition);

        // endpoint の重複。
        let dup = AttachedContainer {
            endpoint: c1.endpoint.clone(),
            host_veth: c1.host_veth.clone(),
            host_index: c1.host_index,
            peer_veth: c1.peer_veth.clone(),
            netns_path: c1.netns_path.clone(),
            address: c1.address,
            netns: (),
        };
        let e = delete_network_with(
            &fake,
            &net,
            vec![c1, dup],
            &netns_dir(),
            &mut ipam,
            &mut ports,
        )
        .unwrap_err();
        assert_eq!(
            (e.code(), e.step),
            (NetErrorCode::InvalidArgument, DeleteStep::Validate)
        );
        assert!(fake.calls().is_empty());
        assert_eq!(ipam.allocated_count(), 3);
    }

    /// NET-1・TASK-139.4: veth の ifindex が変わっていたら削除せず `Unknown`。アドレスは保持し、他の段は続ける。
    #[test]
    fn net1_delete_veth_index_mismatch_is_unknown() {
        let (net, mut ipam, mut ports) = setup();
        let c1 = attached(&mut ipam, "c1");
        let fake = Fake {
            veth_index: Some(99),
            ..Fake::default()
        };
        let e = delete_network_with(&fake, &net, vec![c1], &netns_dir(), &mut ipam, &mut ports)
            .unwrap_err();
        assert_eq!(e.step, DeleteStep::DeleteVeth);
        assert_eq!(e.code(), NetErrorCode::FailedPrecondition);
        assert_eq!(
            e.report.leftover,
            vec![(DeleteResource::Veth(host_of("c1")), ResourceState::Unknown)]
        );
        assert!(!fake.calls().contains(&"delete_link 99".to_owned()));
        assert!(fake.calls().contains(&"delete_link 7".to_owned()));
        assert_eq!(ipam.allocated_count(), 1);
    }

    /// NET-1・TASK-139.4: veth がすでに無ければ完了扱い（冪等）。
    #[test]
    fn net1_delete_veth_not_found_is_idempotent() {
        let (net, mut ipam, mut ports) = setup();
        let c1 = attached(&mut ipam, "c1");
        let fake = Fake {
            absent_veths: vec![host_of("c1").as_str().to_owned()],
            ..Fake::default()
        };
        let report =
            delete_network_with(&fake, &net, vec![c1], &netns_dir(), &mut ipam, &mut ports)
                .unwrap();
        assert!(
            report
                .removed
                .contains(&DeleteResource::Veth(host_of("c1")))
        );
        assert_eq!(ipam.allocated_count(), 0);
    }

    /// NET-1・TASK-139.4: veth 削除の `Timeout` は `Unknown`、`Internal` は `Present`。アドレスは保持する。
    #[test]
    fn net1_delete_veth_delete_errors() {
        for (code, state) in [
            (NetErrorCode::Timeout, ResourceState::Unknown),
            (NetErrorCode::Internal, ResourceState::Present),
        ] {
            let (net, mut ipam, mut ports) = setup();
            let c1 = attached(&mut ipam, "c1");
            let fake = Fake {
                veth_delete_err: Some(code),
                ..Fake::default()
            };
            let e = delete_network_with(&fake, &net, vec![c1], &netns_dir(), &mut ipam, &mut ports)
                .unwrap_err();
            assert_eq!(e.code(), code);
            assert_eq!(
                e.report.leftover,
                vec![(DeleteResource::Veth(host_of("c1")), state)]
            );
            assert_eq!(ipam.allocated_count(), 1);
        }
    }

    /// NET-1・TASK-139.4: unpin の失敗は pin パスを `Present` で報告し、アドレスは保持する。
    #[test]
    fn net1_delete_unpin_failure_reports_pin_path() {
        let (net, mut ipam, mut ports) = setup();
        let c1 = attached(&mut ipam, "c1");
        let fake = Fake {
            unpin_fails: true,
            ..Fake::default()
        };
        let e = delete_network_with(&fake, &net, vec![c1], &netns_dir(), &mut ipam, &mut ports)
            .unwrap_err();
        assert_eq!(
            (e.code(), e.step),
            (NetErrorCode::Internal, DeleteStep::UnpinNetns)
        );
        assert_eq!(
            e.report.leftover,
            vec![(DeleteResource::Netns(pin("c1")), ResourceState::Present)]
        );
        assert_eq!(ipam.allocated_count(), 1);
        // テーブルが消えたので予約は解放される。
        assert!(
            e.report
                .removed
                .contains(&DeleteResource::PortReservation(net.name.clone()))
        );
    }

    /// NET-1・TASK-139.4: テーブルがすでに無い（`Aborted` + `NotFound`）なら完了扱い。
    #[test]
    fn net1_delete_table_not_found_is_idempotent() {
        let (net, mut ipam, mut ports) = setup();
        let fake = Fake {
            table_err: Some((NetErrorCode::NotFound, NftBatchOutcome::Aborted)),
            ..Fake::default()
        };
        let report =
            delete_network_with(&fake, &net, vec![], &netns_dir(), &mut ipam, &mut ports).unwrap();
        assert!(
            report
                .removed
                .contains(&DeleteResource::NftTable(net.table.clone()))
        );
    }

    /// NET-1・TASK-139.4: テーブル削除の結果が不明なら、bridge は試すが IPAM・予約は一切解放しない。
    #[test]
    fn net1_delete_table_unknown_keeps_reservations() {
        let (net, mut ipam, mut ports) = setup();
        let _q = attached(&mut ipam, "c1");
        reserve_port(&mut ports, "c1", 8080);
        let fake = Fake {
            absent_veths: vec![host_of("c1").as_str().to_owned()],
            table_err: Some((NetErrorCode::Timeout, NftBatchOutcome::Unknown)),
            ..Fake::default()
        };
        let e = delete_network_with(&fake, &net, vec![], &netns_dir(), &mut ipam, &mut ports)
            .unwrap_err();
        assert_eq!(
            (e.code(), e.step),
            (NetErrorCode::Timeout, DeleteStep::DeleteNftTable)
        );
        assert_eq!(
            e.report.leftover,
            vec![
                (
                    DeleteResource::NftTable(net.table.clone()),
                    ResourceState::Unknown
                ),
                (
                    DeleteResource::Bridge(net.bridge.clone()),
                    ResourceState::Present
                ),
            ]
        );
        // テーブルが消えたと確認できないので bridge は残す（再実行で所有の証明を使えるように）。
        assert!(!fake.calls().contains(&"delete_link 7".to_owned()));
        assert_eq!(ipam.allocated_count(), 1);
        assert_eq!(ports.len(), 1);
    }

    /// NET-1・TASK-139.4: テーブルが拒否された（`Aborted` + `PermissionDenied`）なら `Present`。
    #[test]
    fn net1_delete_table_rejected_is_present() {
        let (net, mut ipam, mut ports) = setup();
        let fake = Fake {
            table_err: Some((NetErrorCode::PermissionDenied, NftBatchOutcome::Aborted)),
            ..Fake::default()
        };
        let e = delete_network_with(&fake, &net, vec![], &netns_dir(), &mut ipam, &mut ports)
            .unwrap_err();
        assert_eq!(
            e.report.leftover,
            vec![
                (
                    DeleteResource::NftTable(net.table.clone()),
                    ResourceState::Present
                ),
                (
                    DeleteResource::Bridge(net.bridge.clone()),
                    ResourceState::Present
                ),
            ]
        );
    }

    /// NET-1・TASK-139.4: 所有トークンが一致しない bridge は削除せず `Unknown`。
    #[test]
    fn net1_delete_bridge_token_mismatch_not_deleted() {
        let (mut net, mut ipam, mut ports) = setup();
        net.bridge_token = "other".to_owned();
        let fake = Fake::default();
        let e = delete_network_with(&fake, &net, vec![], &netns_dir(), &mut ipam, &mut ports)
            .unwrap_err();
        assert_eq!(
            (e.code(), e.step),
            (NetErrorCode::FailedPrecondition, DeleteStep::DeleteBridge)
        );
        assert_eq!(
            e.report.leftover,
            vec![
                (
                    DeleteResource::NftTable(net.table.clone()),
                    ResourceState::Unknown
                ),
                (
                    DeleteResource::Bridge(net.bridge.clone()),
                    ResourceState::Unknown
                ),
            ]
        );
        // 所有を証明できないので、テーブルにも bridge にも触れない（P0）。
        assert!(!fake.calls().iter().any(|c| c.starts_with("delete_")));
    }

    /// NET-1・TASK-139.4: bridge がすでに無ければ完了扱い。ifindex 不一致は削除しない。
    #[test]
    fn net1_delete_bridge_not_found_and_index_mismatch() {
        let (net, mut ipam, mut ports) = setup();
        let fake = Fake {
            bridge_lookup_err: Some(NetErrorCode::NotFound),
            ..Fake::default()
        };
        let report =
            delete_network_with(&fake, &net, vec![], &netns_dir(), &mut ipam, &mut ports).unwrap();
        assert!(
            report
                .removed
                .contains(&DeleteResource::Bridge(net.bridge.clone()))
        );

        let fake = Fake {
            bridge_index: Some(8),
            ..Fake::default()
        };
        let e = delete_network_with(&fake, &net, vec![], &netns_dir(), &mut ipam, &mut ports)
            .unwrap_err();
        assert_eq!(e.step, DeleteStep::DeleteBridge);
        assert!(!fake.calls().iter().any(|c| c.starts_with("delete_link")));
    }

    /// NET-1・TASK-139.4・ERR-1: 最初のエラーを後続の失敗で上書きしない。
    #[test]
    fn net1_delete_keeps_first_error() {
        let (net, mut ipam, mut ports) = setup();
        let c1 = attached(&mut ipam, "c1");
        let fake = Fake {
            veth_delete_err: Some(NetErrorCode::Internal),
            table_err: Some((NetErrorCode::PermissionDenied, NftBatchOutcome::Aborted)),
            bridge_delete_err: Some(NetErrorCode::ResourceExhausted),
            ..Fake::default()
        };
        let e = delete_network_with(&fake, &net, vec![c1], &netns_dir(), &mut ipam, &mut ports)
            .unwrap_err();
        assert_eq!(
            (e.code(), e.step),
            (NetErrorCode::Internal, DeleteStep::DeleteVeth)
        );
        assert_eq!(e.report.leftover.len(), 3);
    }

    /// NET-1・TASK-139.4: 取り残しを片付けた後、`containers` を空にして再実行すると成功に収束する。
    #[test]
    fn net1_delete_retry_converges() {
        let (net, mut ipam, mut ports) = setup();
        let c1 = attached(&mut ipam, "c1");
        let failing = Fake {
            bridge_delete_err: Some(NetErrorCode::Internal),
            ..Fake::default()
        };
        let e = delete_network_with(
            &failing,
            &net,
            vec![c1],
            &netns_dir(),
            &mut ipam,
            &mut ports,
        )
        .unwrap_err();
        assert_eq!(e.step, DeleteStep::DeleteBridge);
        assert_eq!(ipam.allocated_count(), 0);
        // 再実行では veth・テーブル・bridge がすでに無い。
        let gone = Fake {
            table_err: Some((NetErrorCode::NotFound, NftBatchOutcome::Aborted)),
            bridge_lookup_err: Some(NetErrorCode::NotFound),
            ..Fake::default()
        };
        let report =
            delete_network_with(&gone, &net, vec![], &netns_dir(), &mut ipam, &mut ports).unwrap();
        assert!(report.leftover.is_empty());
    }

    /// NET-1・TASK-139.4: unpin に失敗したコンテナは netns ハンドルごとエラーで返り、再実行に渡せる。
    #[test]
    fn net1_delete_unpin_failure_returns_handle_for_retry() {
        let (net, mut ipam, mut ports) = setup();
        let c1 = attached(&mut ipam, "c1");
        let failing = Fake {
            unpin_fails: true,
            ..Fake::default()
        };
        let mut e = delete_network_with(
            &failing,
            &net,
            vec![c1],
            &netns_dir(),
            &mut ipam,
            &mut ports,
        )
        .unwrap_err();
        assert_eq!(e.retry.len(), 1);
        let kept = e.retry.pop().unwrap();
        assert_eq!(
            (kept.endpoint.clone(), kept.netns_path.clone()),
            (eid("c1"), pin("c1"))
        );
        // 返されたコンテナを渡して再実行すると、unpin が成功して収束する。
        let ok = Fake::default();
        let report =
            delete_network_with(&ok, &net, vec![kept], &netns_dir(), &mut ipam, &mut ports)
                .unwrap();
        assert!(report.leftover.is_empty());
        assert_eq!(ipam.allocated_count(), 0);
    }

    /// NET-1・TASK-139.4: veth が無くても pin が残る（または判定できない）未指定 endpoint のアドレスは保持する。
    #[test]
    fn net1_delete_keeps_address_when_unpassed_pin_remains() {
        for (present, check_err, state) in [
            (true, false, ResourceState::Present),
            (false, true, ResourceState::Unknown),
        ] {
            let (net, mut ipam, mut ports) = setup();
            let _q = attached(&mut ipam, "c1");
            let fake = Fake {
                absent_veths: vec![host_of("c1").as_str().to_owned()],
                pins_present: if present { vec![pin("c1")] } else { vec![] },
                pin_check_err: check_err,
                ..Fake::default()
            };
            let e = delete_network_with(&fake, &net, vec![], &netns_dir(), &mut ipam, &mut ports)
                .unwrap_err();
            assert_eq!(e.step, DeleteStep::Preflight);
            assert_eq!(
                e.report.leftover,
                vec![(DeleteResource::Netns(pin("c1")), state)]
            );
            assert_eq!(ipam.allocated_count(), 1);
        }
    }

    /// NET-1・TASK-139.4: 共有予約ファイルの解放に失敗したら `PortReservation` を `Present` で報告する。
    #[test]
    fn net1_delete_reservation_release_failure_is_reported() {
        let dir = std::env::temp_dir().join(format!("fc-delete-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // ファイルの代わりにディレクトリを共有パスに指定し、ロックの open を失敗させる。
        let path = dir.join("ports.reg");
        std::fs::create_dir_all(&path).unwrap();
        let (net, mut ipam, _) = setup();
        let mut ports = PortRegistry::with_shared_file(path);
        let fake = Fake::default();
        let e = delete_network_with(&fake, &net, vec![], &netns_dir(), &mut ipam, &mut ports)
            .unwrap_err();
        assert_eq!(e.step, DeleteStep::ReleaseReservations);
        assert_eq!(
            e.report.leftover,
            vec![(
                DeleteResource::PortReservation(net.name.clone()),
                ResourceState::Present
            )]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
