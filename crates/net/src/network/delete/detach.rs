//! attach 済みコンテナ 1 件だけの切り離し（NET-1・NET-3・NET-4・REPAIR-5・SEC-1・#3062）。
//!
//! `delete_network` はネットワーク全体を一括で解放するが、共有ネットワークでは他のコンテナを残したまま
//! 1 件だけを外す必要がある（CRI の `NetworkPlugin::detach` の attach 済みの分岐、stack / CLI の
//! 「最後の detach → delete_network」。`docs/design/network-wiring.md` D11・D13）。本モジュールはその本体で、
//! 呼び出し元は plugin-cri の `LinuxNetsetup::detach`（Linux）と試験。bridge と専用 nft テーブルには触れず、
//! 他のコンテナの公開（DNAT ルール・受け口の予約）・veth・IPAM のアドレスに影響しない。
//!
//! # 手順（`detach_container_with`。OS 非依存。カーネル操作は `DeleteOps` で差し替える）
//!
//! 0. 入力検証（何も変更しない。失敗はコンテナと公開ハンドルを返す）: ネットワーク・IPAM・コンテナの整合
//!    （`delete_network` と同じ照合）、公開ハンドルの endpoint・network の束縛、受け口の重複、件数の上限
//! 1. 公開の個別解除（`unpublish_ports_with`。逆順。1 件の失敗で止めず残りも続ける。全体の期限が切れたら
//!    残りの件は要求を出さずに取り残し〔`Present`〕として報告する）
//! 2. 結果不明の公開が残した予約の確認（残っていればアドレスを保持する）
//! 3. veth の所有確認と削除（`delete_veth`。`delete_network` と同じ規則。期限が切れていれば要求を出さず
//!    `Present` の取り残しとして報告する）
//! 4. veth が消えたときだけ netns の pin を外す
//! 5. veth・pin が消え、予約も残っていないときだけ IPAM のアドレスを解放する
//!
//! 公開 → veth → netns の逆順は `NetworkPlugin::detach` の契約（契約 9）に従う。取り残しがあれば `Err` で
//! 返し、カーネル操作を始めた後の失敗では [`ContainerDetachError::reclaim_claim`] の請求書を返す。
//! 請求書は `reclaim_failed_attach` で回収できる（同じ記録形式）。ハンドルは手放して請求書に一本化する
//! （同じプロセスでの再試行も、再起動後の回収も、回収の 1 経路に収束させる）。
//!
//! # 契約・未実装範囲（REPAIR-3）
//!
//! - 期限（REPAIR-5・#3258）: [`detach_container`] の `timeout` は切り離し全体の 1 つの期限で、各カーネル要求は
//!   その残り時間で打ち切る。切れたら以降のカーネル要求（公開の解除・veth の削除）は出さず、取り残しを
//!   `Present` で報告して fail-closed にする（アドレスと予約は保持）。判定と送信の間に切れた場合は送信側が
//!   `Timeout` を返し、既存の経路で `Unknown` になる。pin の解除と IPAM の解放は netlink 要求ではないため対象外
//! - DNAT ルールのハンドルは請求書に載せない（#3258 の判断・NET-1・NET-6）。同じプロセスでは `delete_network` の
//!   テーブル削除で消えるが、再起動後に復元したネットワークでは手動回収になる。担当は #3285
//! - アドレスと受け口の予約は、DNAT ルールが残りうる間は解放しない（quarantine。解放は `delete_network`）。
//!   ルールの残存が確定しているか不明かは [`NetworkDeleteReport::leftover`] の状態で区別する
//! - メンバー記録（`members/<id>`）の削除は #3067、公開ハンドルとテーブルハンドルの記録は #3068（`network::recorded`）、
//!   DNS ヘルパーの参照カウントは #3070。IPAM はメモリ上の状態で、永続化は #3075。公開のテーブルハンドルが生きたものと
//!   食い違う（テーブルが作り直された）場合、公開の解除は DELRULE を送らず [`UnpublishRules::StaleHandles`] で断り、
//!   本関数はその公開を `Unknown` の取り残し（quarantine）として報告する

use std::fmt;
#[cfg(target_os = "linux")]
use std::time::Duration;

#[cfg(target_os = "linux")]
use super::LinuxDeleteOps;
use super::{
    DeleteOps, DeleteResource, DeleteStep, Failures, NetworkDeleteReport, delete_veth,
    precondition, state_of, validate_container, validate_network,
};
use crate::error::{NetError, NetErrorCode};
#[cfg(target_os = "linux")]
use crate::netlink_route::NetlinkRouteSocket;
#[cfg(target_os = "linux")]
use crate::netns::ContainerNetns;
use crate::network::attach_claim::FailedAttachClaim;
use crate::network::unpublish::{UnpublishRules, unpublish_ports_with};
use crate::network::{
    AttachedContainer, CreatedNetwork, MAX_PORT_PUBLISHES, PortRegistry, PublishedPort,
    ResourceState, StaticIpam, UnpinFailure,
};
#[cfg(target_os = "linux")]
use crate::nftables_batch::NetlinkNetfilterSocket;

/// 単体の切り離しの失敗（最初の原因・失敗手順・解放の結果。ERR-1）。
#[derive(Debug)]
#[non_exhaustive]
pub struct ContainerDetachError<N> {
    /// 最初の失敗の原因（後続の失敗で上書きしない）。
    pub error: NetError,
    /// 最初に失敗した手順。
    pub step: DeleteStep,
    /// ここまでに解放できたものと取り残し。
    pub report: NetworkDeleteReport,
    /// 入力検証の失敗（何も変えていない）のときだけ、渡されたコンテナをハンドルごと返す。再試行できる（型が大きいため `Box`）。
    pub retry: Option<Box<AttachedContainer<N>>>,
    /// 入力検証の失敗のときに返す、渡された attach 後の公開ハンドル（未使用）。
    pub published: Vec<PublishedPort>,
    /// カーネル操作を始めた後の取り残しの請求書。
    claim: Option<Box<FailedAttachClaim>>,
}

impl<N> ContainerDetachError<N> {
    /// 機械可読な分類。
    pub fn code(&self) -> NetErrorCode {
        self.error.code()
    }

    /// 英語のメッセージ。
    pub fn message(&self) -> &str {
        self.error.message()
    }

    /// 取り残した資源の請求書（`reclaim_failed_attach` で回収できる）。取り残しが無い・入力検証の失敗では `None`。
    /// 請求書は外部入力から作れず、この失敗だけが返す。
    pub fn reclaim_claim(&self) -> Option<FailedAttachClaim> {
        self.claim.as_deref().cloned()
    }
}

impl<N> fmt::Display for ContainerDetachError<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.error.fmt(f)
    }
}

impl<N: fmt::Debug> std::error::Error for ContainerDetachError<N> {}

/// 入力検証（何も変更しない）。公開ハンドルは本コンテナのものに限り、他のコンテナのハンドルで
/// そのコンテナの DNAT を消せないようにする（`unpublish_ports_with` は network とトークンしか見ない）。
fn validate<N>(
    network: &CreatedNetwork,
    ipam: &StaticIpam,
    container: &AttachedContainer<N>,
    extra: &[PublishedPort],
) -> Result<(), NetError> {
    validate_network(network, ipam)?;
    validate_container(network, ipam, container)?;
    let all: Vec<&PublishedPort> = container.published_ports.iter().chain(extra).collect();
    if all.len() > MAX_PORT_PUBLISHES {
        return Err(NetError::new(
            NetErrorCode::ResourceExhausted,
            "too many published ports for the container",
        ));
    }
    for (i, p) in all.iter().enumerate() {
        if p.endpoint() != &container.endpoint || p.network() != &network.name {
            return Err(precondition(
                "published port does not belong to the container",
            ));
        }
        if all[i + 1..]
            .iter()
            .any(|q| p.publish().same_listener(q.publish()))
        {
            return Err(NetError::new(
                NetErrorCode::InvalidArgument,
                "duplicate published listener",
            ));
        }
    }
    Ok(())
}

/// 切り離しの本体（OS 非依存。手順と方針はモジュール doc）。`extra_published` は attach 後の
/// `publish_container_ports` で得たハンドル。
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn detach_container_with<O: DeleteOps>(
    ops: &O,
    network: &CreatedNetwork,
    container: AttachedContainer<O::Netns>,
    extra_published: Vec<PublishedPort>,
    ipam: &mut StaticIpam,
    ports: &mut PortRegistry,
) -> Result<NetworkDeleteReport, Box<ContainerDetachError<O::Netns>>> {
    // 0. 入力検証。
    if let Err(error) = validate(network, ipam, &container, &extra_published) {
        return Err(Box::new(ContainerDetachError {
            error,
            step: DeleteStep::Validate,
            report: NetworkDeleteReport::default(),
            retry: Some(Box::new(container)),
            published: extra_published,
            claim: None,
        }));
    }
    let AttachedContainer {
        endpoint,
        host_veth,
        host_index,
        host_token,
        netns_path,
        address,
        netns,
        published_ports,
        pin_identity,
        ..
    } = container;
    let mut report = NetworkDeleteReport::default();
    let mut failures = Failures::default();
    // DNAT ルールが残りうる（または受け口の予約が残る）ためアドレスと予約を保持するか。
    let mut quarantine = false;

    // 1. 公開の個別解除（逆順。1 件の失敗で止めず残りも続ける）。
    for published in published_ports.into_iter().chain(extra_published).rev() {
        let publish = *published.publish();
        if ops.deadline_exceeded() {
            // 全体の期限切れ。DELRULE を送っていないのでルールは確実に残っている（予約も戻さない）。
            quarantine = true;
            report.leftover.push((
                DeleteResource::PortRules(endpoint.clone(), publish),
                ResourceState::Present,
            ));
            failures.note(
                NetError::new(NetErrorCode::Timeout, "detach deadline exceeded"),
                DeleteStep::UnpublishPorts,
            );
            continue;
        }
        let result = unpublish_ports_with(
            |t| ops.table_info(t),
            |t, h| ops.delete_rules(t, h),
            network,
            published,
            ports,
        );
        match result {
            Ok(()) => report
                .removed
                .push(DeleteResource::PortRules(endpoint.clone(), publish)),
            Err(e) => {
                quarantine = true;
                // ハンドルは破棄する（DNAT ルールはテーブルごと `delete_network` が消す。再起動後は
                // 手動回収で、請求書へ載せる担当は #3285）。
                let (resource, state) = match e.rules {
                    UnpublishRules::Present => (
                        DeleteResource::PortRules(endpoint.clone(), publish),
                        ResourceState::Present,
                    ),
                    UnpublishRules::Removed => (
                        // ルールは消え、予約の解放だけが失敗した。
                        DeleteResource::PortReservation(network.name.clone()),
                        ResourceState::Present,
                    ),
                    _ => (
                        DeleteResource::PortRules(endpoint.clone(), publish),
                        ResourceState::Unknown,
                    ),
                };
                report.leftover.push((resource, state));
                failures.note(e.error, DeleteStep::UnpublishPorts);
            }
        }
    }

    // 2. 結果不明のまま記録した公開（ハンドルが無い）の予約が残っていないか。残っていれば、そのルールが
    //    このアドレスへ転送しうるので解放しない。確認できない場合も同じく保持する（fail-closed）。
    if !quarantine {
        match ports.held_by(&network.name, &endpoint) {
            Ok(0) => {}
            Ok(_) => quarantine = true,
            Err(e) => {
                quarantine = true;
                failures.note(e, DeleteStep::ReleaseReservations);
            }
        }
    }

    // 3. veth。pin の識別子は接続時に固定したものを使う（現在のパスから採り直すと、pin が作り直された
    //    ときに新世代の識別子を請求書へ取り込み、新世代の pin を回収で外せてしまう。NET-1）。
    let veth_gone = if ops.deadline_exceeded() {
        // 全体の期限切れ。要求を出さず、veth は残るものとして報告する（pin も外さない）。
        report.leftover.push((
            DeleteResource::Veth(host_veth.clone()),
            ResourceState::Present,
        ));
        failures.note(
            NetError::new(NetErrorCode::Timeout, "detach deadline exceeded"),
            DeleteStep::DeleteVeth,
        );
        false
    } else {
        delete_veth(
            ops,
            &host_veth,
            host_index,
            &host_token,
            network.bridge_index,
            &mut report,
            &mut failures,
        )
    };

    // 4. pin。veth が残るあいだは外さない（所有の証明を残し、回収で収束させる）。ハンドルは手放し、
    //    請求書の識別子と所有記録の照合で回収できる（`netns::unpin_path` の doc）。
    let unpinned = if veth_gone {
        match ops.unpin_netns(netns) {
            Ok(()) => {
                report.removed.push(DeleteResource::Netns(netns_path));
                true
            }
            Err(UnpinFailure { error, .. }) => {
                report
                    .leftover
                    .push((DeleteResource::Netns(netns_path), state_of(error.code())));
                failures.note(error, DeleteStep::UnpinNetns);
                false
            }
        }
    } else {
        report
            .leftover
            .push((DeleteResource::Netns(netns_path), ResourceState::Present));
        false
    };

    // 5. アドレス。公開の残りがなく、veth・pin が消えたときだけ解放する。解放できなかった（保持した）
    //    ときは請求書に quarantine を立てる。立てないと、回収（veth・pin だけ）が記録を外して成功し、
    //    IPAM のアドレスだけが残って同じ endpoint の再 attach が `AlreadyExists` になる（NET-1・#3062）。
    if veth_gone && unpinned && !quarantine {
        match ipam.release(&endpoint) {
            Ok(addr) => report
                .removed
                .push(DeleteResource::Address(endpoint.clone(), addr)),
            Err(e) => {
                quarantine = true;
                report.leftover.push((
                    DeleteResource::Address(endpoint.clone(), address),
                    ResourceState::Present,
                ));
                failures.note(e, DeleteStep::ReleaseReservations);
            }
        }
    } else {
        // アドレスを保持する。カーネル側の回収後も記録を残し、`delete_network` が解放する。
        quarantine = true;
        let state = if report
            .leftover
            .iter()
            .any(|(_, s)| *s == ResourceState::Unknown)
        {
            ResourceState::Unknown
        } else {
            ResourceState::Present
        };
        report
            .leftover
            .push((DeleteResource::Address(endpoint.clone(), address), state));
        if failures.first.is_none() {
            // 他は成功したが公開の予約が残っている。成功を装わない。
            failures.note(
                precondition(
                    "published port rules may remain; address is held until delete_network",
                ),
                DeleteStep::ReleaseReservations,
            );
        }
    }

    match failures.first {
        None => Ok(report),
        Some((error, step)) => {
            let claim = FailedAttachClaim::from_detach(
                &network.name,
                &network.bridge_token,
                &endpoint,
                &host_token,
                pin_identity,
                !veth_gone,
                !unpinned,
                quarantine,
            );
            Err(Box::new(ContainerDetachError {
                error,
                step,
                report,
                retry: None,
                published: Vec::new(),
                claim: claim.map(Box::new),
            }))
        }
    }
}

/// attach 済みコンテナ 1 件を切り離す（公開 → veth → netns の pin → IPAM。NET-1・NET-3）。
///
/// 手順・失敗時の扱いはモジュール doc と [`ContainerDetachError`]。`extra_published` は attach 後の
/// `publish_container_ports` で得たハンドル（attach 時の公開は `container.published_ports`）。他のコンテナの
/// 資源・bridge・専用テーブルには触れない。`CAP_NET_ADMIN` と pin の解除に必要な `CAP_SYS_ADMIN` は
/// 呼び出し側の責務で、本 crate は権限を上げない。`timeout` は切り離し全体の 1 つの期限で、各カーネル要求は
/// その残り時間で打ち切る（REPAIR-5・#3258。モジュール doc の期限）。
#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
pub fn detach_container(
    route: &NetlinkRouteSocket,
    nft: &NetlinkNetfilterSocket,
    network: &CreatedNetwork,
    container: AttachedContainer<ContainerNetns>,
    extra_published: Vec<PublishedPort>,
    ipam: &mut StaticIpam,
    ports: &mut PortRegistry,
    timeout: Duration,
) -> Result<NetworkDeleteReport, Box<ContainerDetachError<ContainerNetns>>> {
    detach_container_with(
        &LinuxDeleteOps {
            route,
            nft,
            timeout,
            deadline: Some(crate::sys::Deadline::after(timeout)),
        },
        network,
        container,
        extra_published,
        ipam,
        ports,
    )
}
