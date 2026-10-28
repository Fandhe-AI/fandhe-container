//! 状態ストアの記録つきのネットワーク操作（create / attach / detach / delete。NET-1・NET-7・REPAIR-3・REPAIR-4・#3067）。
//!
//! 役割: `network_store` の記録（`realized`・`members/<id>`・各 intent・`pending-reclaim/`）の書き込み順序と、
//! カーネル操作（`create_network`・`attach_container`・`detach_container`・`delete_network`）の合成を 1 か所に置く。
//! 順序は D11 の write-ahead に従う: 意図記録 → カーネル操作 → 確定記録（成功）または請求書（取り残しつきの失敗）。
//! IPAM は独立したカウンタを持たず、ネットワークの排他ロックの下で記録から組み直す（`NetworkLockGuard::rebuild_ipam`）。
//! 呼び出し元の想定は supervisor（#3074）と plugin-cri（#3075）。ロック順序は「全体 → ネットワーク」で、
//! `NetworkLockGuard` が `GlobalLockGuard` の借用でしか作れないことで型が強制する。排他ロックのガードだけを受ける。
//!
//! # 構造
//! 本体の `*_recorded_with` はカーネル操作をクロージャで受ける OS 非依存の手順で、root なしで単体試験できる。
//! Linux 限定の公開ラッパー（`create_network_recorded` 等）が、netlink ソケットと期限を実カーネル操作へ束ねる。
//!
//! # 失敗時の規則（fail-closed）
//! - カーネル操作が成功したのに確定記録を書けなかった場合は [`RecordedError::Uncommitted`] で成功の値を返す。
//!   意図記録は消さない（アドレスは使用中のまま数え続ける）。呼び出し側は値を使って後始末か再記録を行う
//! - カーネル操作が取り残しつきで失敗した場合は、請求書を `pending-reclaim/` に保存してから意図記録を消す。
//!   保存に失敗したら意図記録を残し [`RecordedError::ReclaimUnsaved`] を返す。quarantine（アドレス・DNAT・ポート予約）を
//!   伴う attach の失敗では意図記録を消さない（再割り当てしない）
//! - 残った `realized.intent` は未完了の操作を示す。カーネル照合は後続の担当で、それまで次の操作は
//!   `FailedPrecondition`（`network has an unreconciled operation`）で拒否する
//!
//! # 未実装範囲（REPAIR-3）
//! - 残った `realized.intent` / `members-intent/*` のカーネル照合による昇格・巻き戻し（link の dump API が前提）
//! - 公開（受け口・rule handle）とテーブル handle の記録（#3068）。`PortRegistry` は呼び出し側が持つ
//! - 検証で拒否した detach は渡された `AttachedContainer` を返さず破棄する（netns の pin は残る。記録から
//!   請求書を作って回収する経路は #3075）

use std::net::IpAddr;

use super::{
    AttachedContainer, ContainerAttachError, ContainerAttachSpec, CreatedNetwork,
    NetworkCreateError, NetworkDeleteReport, StaticIpam, host_owner_token, new_generation,
    ownership_token,
};
use crate::error::{NetError, NetErrorCode};
use crate::etc_hosts::NameResolution;
use crate::netlink_route::IpPrefix;
use crate::network_store::realized::check_gateway;
use crate::network_store::{
    InstallMode, MemberId, MemberIntent, MemberRecord, NetworkDefinition, NetworkLockGuard,
    RealizedIntent, RealizedOp, RealizedRecord, rebuild_ipam,
};

/// 記録つきの操作の失敗。
#[derive(Debug)]
#[non_exhaustive]
pub enum RecordedError<E, T> {
    /// 記録の読み書き・検査の失敗（カーネル操作は始めていない）。
    Store(NetError),
    /// カーネル操作の失敗（請求書は保存済み。意図記録の扱いはモジュール doc）。
    Op(E),
    /// カーネル操作は失敗し取り残しの請求書があるが、保存できなかった（意図記録は残してある）。
    ReclaimUnsaved {
        /// 請求書の保存の失敗。
        persist: NetError,
        /// 元のカーネル操作の失敗。
        op: E,
    },
    /// カーネル操作は成功したが、確定記録を書けなかった（意図記録は残してある）。
    Uncommitted {
        /// 記録の失敗。
        error: NetError,
        /// 成功した操作の結果。
        value: Box<T>,
    },
}

impl<E, T> RecordedError<E, T> {
    /// 記録側の失敗の分類。カーネル操作の失敗（`Op`）は `None`。
    pub fn store_code(&self) -> Option<NetErrorCode> {
        match self {
            Self::Store(e) => Some(e.code()),
            Self::Uncommitted { error, .. } => Some(error.code()),
            Self::ReclaimUnsaved { persist, .. } => Some(persist.code()),
            Self::Op(_) => None,
        }
    }
}

fn precondition(msg: &'static str) -> NetError {
    NetError::new(NetErrorCode::FailedPrecondition, msg)
}

fn unreconciled() -> NetError {
    precondition("network has an unreconciled operation")
}

/// `realized` を読み、未完了の操作が無いことを確かめる。
fn require_settled<E, T>(
    guard: &NetworkLockGuard<'_>,
) -> Result<RealizedRecord, RecordedError<E, T>> {
    let store = RecordedError::Store;
    let realized = guard
        .realized()
        .map_err(store)?
        .ok_or_else(|| RecordedError::Store(precondition("network is not realized")))?;
    if guard
        .realized_intent()
        .map_err(RecordedError::Store)?
        .is_some()
    {
        return Err(RecordedError::Store(unreconciled()));
    }
    Ok(realized)
}

/// attach を記録つきで行う本体。`run` は払い出し済みの IPAM と接続の世代を受けて接続する。
///
/// 手順: 記録から IPAM を組み直す → 世代とアドレスを決める → 意図記録を書く → `run` → 成功なら確定記録、
/// 失敗なら請求書（取り残しがあるとき）と意図記録の後始末。`dns` は確定記録にだけ載せる（`--dns` の上流。NET-12）。
pub(crate) fn attach_recorded_with<N, F>(
    guard: &NetworkLockGuard<'_>,
    member_id: &MemberId,
    spec: &ContainerAttachSpec,
    dns: &[IpAddr],
    run: F,
) -> Result<AttachedContainer<N>, RecordedError<Box<ContainerAttachError>, AttachedContainer<N>>>
where
    F: FnOnce(&mut StaticIpam, &str) -> Result<AttachedContainer<N>, ContainerAttachError>,
{
    let realized = require_settled(guard)?;
    if &spec.network != realized.name() || spec.bridge_token != realized.token() {
        return Err(RecordedError::Store(precondition(
            "attach spec does not belong to the network",
        )));
    }
    let store = RecordedError::Store;
    let members = guard.members().map_err(store)?;
    let intents = guard.member_intents().map_err(RecordedError::Store)?;
    if members.iter().any(|m| m.id() == member_id) || intents.iter().any(|i| i.id() == member_id) {
        return Err(RecordedError::Store(NetError::new(
            NetErrorCode::AlreadyExists,
            "member already exists",
        )));
    }
    let mut ipam = rebuild_ipam(&realized, &members, &intents).map_err(RecordedError::Store)?;
    let generation = new_generation();
    let host_token = host_owner_token(realized.token(), spec.endpoint(), &generation);
    // 払い出しは決定的（最小の空き）なので、複製で先に決めた値を意図記録に書き、本番の ipam が同じ値を出す。
    let address = ipam
        .clone()
        .allocate(spec.endpoint())
        .map_err(RecordedError::Store)?;
    let intent = MemberIntent::new(
        member_id.clone(),
        spec.endpoint().clone(),
        address,
        &host_token,
    )
    .map_err(RecordedError::Store)?;
    guard
        .write_member_intent(&intent)
        .map_err(RecordedError::Store)?;

    match run(&mut ipam, &generation) {
        Ok(att) => commit_attached(guard, member_id, dns, &ipam, address, &host_token, att),
        Err(e) => {
            let claim = e.reclaim_claim();
            if let Some(c) = &claim
                && let Err(persist) = guard.save_reclaim_attach(c)
            {
                return Err(RecordedError::ReclaimUnsaved {
                    persist,
                    op: Box::new(e),
                });
            }
            // quarantine（アドレス・DNAT・ポート予約）が残るときは、再割り当てしないよう意図記録を残す。
            if !claim.is_some_and(|c| c.includes_quarantine()) {
                // 消せなければ意図記録が残るだけ（アドレスを使用中として数え続ける安全側）。
                let _ = guard.remove_member_intent(member_id);
            }
            Err(RecordedError::Op(Box::new(e)))
        }
    }
}

type AttachResult<N> =
    Result<AttachedContainer<N>, RecordedError<Box<ContainerAttachError>, AttachedContainer<N>>>;

fn commit_attached<N>(
    guard: &NetworkLockGuard<'_>,
    member_id: &MemberId,
    dns: &[IpAddr],
    ipam: &StaticIpam,
    address: IpPrefix,
    host_token: &str,
    att: AttachedContainer<N>,
) -> AttachResult<N> {
    let uncommitted = |error: NetError, att: AttachedContainer<N>| RecordedError::Uncommitted {
        error,
        value: Box::new(att),
    };
    if att.address != address || att.host_token != host_token {
        return Err(uncommitted(
            NetError::new(
                NetErrorCode::Internal,
                "attach result differs from the recorded intent",
            ),
            att,
        ));
    }
    let Some(dir) = ipam.netns_dir_of(&att.endpoint) else {
        return Err(uncommitted(
            NetError::new(
                NetErrorCode::Internal,
                "attach did not record the netns directory",
            ),
            att,
        ));
    };
    let rec = MemberRecord::new(
        member_id.clone(),
        att.endpoint.clone(),
        att.address,
        &att.host_token,
        dir.path(),
        dir.dir_id(),
        dns,
    );
    match rec.and_then(|r| guard.commit_member(&r)) {
        Ok(()) => Ok(att),
        Err(e) => Err(uncommitted(e, att)),
    }
}

/// detach を記録つきで行う本体。`run` は記録から復元した `CreatedNetwork` と IPAM を受けて切り離す。
///
/// 成功したらメンバー記録（と残っていれば意図記録）を消す。失敗して請求書があれば保存し、メンバー記録は残す
/// （切り離しが完了していないため）。`CreatedNetwork::name_resolution` は記録に無いので既定値で復元する
/// （切り離しは参照しない）。
pub(crate) fn detach_recorded_with<E, F>(
    guard: &NetworkLockGuard<'_>,
    member_id: &MemberId,
    run: F,
) -> Result<NetworkDeleteReport, RecordedError<E, NetworkDeleteReport>>
where
    F: FnOnce(&CreatedNetwork, &mut StaticIpam) -> Result<NetworkDeleteReport, E>,
    E: DetachClaim,
{
    let realized = require_settled(guard)?;
    let members = guard.members().map_err(RecordedError::Store)?;
    let intents = guard.member_intents().map_err(RecordedError::Store)?;
    if !members.iter().any(|m| m.id() == member_id) {
        return Err(RecordedError::Store(NetError::new(
            NetErrorCode::NotFound,
            "member not found",
        )));
    }
    let mut ipam = rebuild_ipam(&realized, &members, &intents).map_err(RecordedError::Store)?;
    let created = realized.to_created(NameResolution::default());
    match run(&created, &mut ipam) {
        Ok(report) => {
            let removed = guard
                .remove_member(member_id)
                .and_then(|_| guard.remove_member_intent(member_id).map(|_| ()));
            match removed {
                Ok(()) => Ok(report),
                Err(error) => Err(RecordedError::Uncommitted {
                    error,
                    value: Box::new(report),
                }),
            }
        }
        Err(e) => {
            if let Some(c) = e.attach_claim()
                && let Err(persist) = guard.save_reclaim_attach(&c)
            {
                return Err(RecordedError::ReclaimUnsaved { persist, op: e });
            }
            Err(RecordedError::Op(e))
        }
    }
}

/// detach の失敗から請求書を取り出す口（`ContainerDetachError` と試験用の型を同じ手順で扱う）。
pub(crate) trait DetachClaim {
    /// 取り残しの請求書。無ければ `None`。
    fn attach_claim(&self) -> Option<super::FailedAttachClaim>;
}

impl<N> DetachClaim for Box<super::ContainerDetachError<N>> {
    fn attach_claim(&self) -> Option<super::FailedAttachClaim> {
        self.reclaim_claim()
    }
}

/// create を記録つきで行う本体。`run` は発行済みの所有トークンを受けて作成する。
///
/// 定義が `Bridge` でなければ `FailedPrecondition`。`gateway` は定義の subnet に属する必要がある
/// （カーネル操作の前に検査する）。
pub(crate) fn create_recorded_with<F>(
    guard: &NetworkLockGuard<'_>,
    definition: &NetworkDefinition,
    gateway: IpPrefix,
    run: F,
) -> Result<CreatedNetwork, RecordedError<Box<NetworkCreateError>, CreatedNetwork>>
where
    F: FnOnce(&str) -> Result<CreatedNetwork, NetworkCreateError>,
{
    let InstallMode::Bridge { subnet } = *definition.install() else {
        return Err(RecordedError::Store(precondition(
            "only a bridge definition can be realized",
        )));
    };
    if definition.name() != guard.network() {
        return Err(RecordedError::Store(precondition(
            "definition does not belong to the locked network",
        )));
    }
    check_gateway(&gateway, &subnet).map_err(|_| {
        RecordedError::Store(NetError::new(
            NetErrorCode::InvalidArgument,
            "gateway is outside the network subnet",
        ))
    })?;
    if guard.realized().map_err(RecordedError::Store)?.is_some() {
        return Err(RecordedError::Store(NetError::new(
            NetErrorCode::AlreadyExists,
            "network is already realized",
        )));
    }
    if guard
        .realized_intent()
        .map_err(RecordedError::Store)?
        .is_some()
    {
        return Err(RecordedError::Store(unreconciled()));
    }
    let token = ownership_token(definition.name());
    let intent = RealizedIntent::new(
        RealizedOp::Create,
        definition.name().clone(),
        &token,
        subnet,
    )
    .map_err(RecordedError::Store)?;
    guard
        .write_realized_intent(&intent)
        .map_err(RecordedError::Store)?;
    match run(&token) {
        Ok(created) => {
            let committed = RealizedRecord::from_created(&created, subnet)
                .and_then(|r| guard.commit_realized(&r));
            match committed {
                Ok(()) => Ok(created),
                Err(error) => Err(RecordedError::Uncommitted {
                    error,
                    value: Box::new(created),
                }),
            }
        }
        Err(e) => {
            if let Some(c) = e.reclaim_claim()
                && let Err(persist) = guard.save_reclaim_create(&c)
            {
                return Err(RecordedError::ReclaimUnsaved {
                    persist,
                    op: Box::new(e),
                });
            }
            // 消せなければ意図記録が残り、次の操作が未完了として拒否される（安全側）。
            let _ = guard.remove_realized_intent();
            Err(RecordedError::Op(Box::new(e)))
        }
    }
}

/// delete を記録つきで行う本体。メンバー記録・意図記録が残っていれば `FailedPrecondition`。
///
/// `run` は記録から復元した `CreatedNetwork` と（空の）IPAM を受けて削除する。成功したら `realized` を消す。
/// 失敗したときは `realized.intent`（op=delete）を残す（どこまで消えたか不明なため。カーネル照合は後続）。
pub(crate) fn delete_recorded_with<T, E, F>(
    guard: &NetworkLockGuard<'_>,
    run: F,
) -> Result<T, RecordedError<E, T>>
where
    F: FnOnce(&CreatedNetwork, &mut StaticIpam) -> Result<T, E>,
{
    let realized = require_settled(guard)?;
    let members = guard.members().map_err(RecordedError::Store)?;
    let intents = guard.member_intents().map_err(RecordedError::Store)?;
    if !members.is_empty() || !intents.is_empty() {
        return Err(RecordedError::Store(precondition(
            "network still has members",
        )));
    }
    let mut ipam = rebuild_ipam(&realized, &members, &intents).map_err(RecordedError::Store)?;
    let created = realized.to_created(NameResolution::default());
    let intent = RealizedIntent::new(
        RealizedOp::Delete,
        realized.name().clone(),
        realized.token(),
        realized.subnet(),
    )
    .map_err(RecordedError::Store)?;
    guard
        .write_realized_intent(&intent)
        .map_err(RecordedError::Store)?;
    match run(&created, &mut ipam) {
        Ok(v) => match guard.remove_realized() {
            Ok(()) => Ok(v),
            Err(error) => Err(RecordedError::Uncommitted {
                error,
                value: Box::new(v),
            }),
        },
        Err(e) => Err(RecordedError::Op(e)),
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::time::Duration;

    use super::*;
    use crate::netlink_route::NetlinkRouteSocket;
    use crate::netns::ContainerNetns;
    use crate::network::delete::{ContainerDetachError, NetworkDeleteError};
    use crate::network::{
        LinuxAttachOps, LinuxNetworkOps, NetworkCreateSpec, PortRegistry, PublishedPort,
        attach_container_with_generation, create_network_with_token, delete_network,
        detach_container,
    };
    use crate::nftables_batch::NetlinkNetfilterSocket;

    /// ネットワークを作って `realized` に記録する（`create_network` の記録つき版）。
    ///
    /// `spec` の名前と `definition` の名前、`spec` の gateway と定義の subnet が整合している必要がある。
    /// `CAP_NET_ADMIN` は呼び出し側の責務。失敗時の規則はモジュール doc。
    pub fn create_network_recorded(
        route: &NetlinkRouteSocket,
        nft: &NetlinkNetfilterSocket,
        guard: &NetworkLockGuard<'_>,
        definition: &NetworkDefinition,
        spec: &NetworkCreateSpec,
        timeout: Duration,
    ) -> Result<CreatedNetwork, RecordedError<Box<NetworkCreateError>, CreatedNetwork>> {
        if spec.name() != definition.name() {
            return Err(RecordedError::Store(NetError::new(
                NetErrorCode::InvalidArgument,
                "spec and definition name differ",
            )));
        }
        create_recorded_with(guard, definition, spec.gateway(), |token| {
            create_network_with_token(
                &LinuxNetworkOps {
                    route,
                    nft,
                    timeout,
                },
                spec,
                token.to_owned(),
            )
        })
    }

    /// コンテナを接続して `members/<id>` に記録する（`attach_container` の記録つき版）。
    ///
    /// IPAM は記録から組み直すため、呼び出し側は `StaticIpam` を持たない。`ports` は呼び出し側の予約表
    /// （公開の記録は #3068）。`CAP_NET_ADMIN`・`CAP_SYS_ADMIN` は呼び出し側の責務。
    #[allow(clippy::too_many_arguments)]
    pub fn attach_container_recorded(
        route: &NetlinkRouteSocket,
        nft: &NetlinkNetfilterSocket,
        guard: &NetworkLockGuard<'_>,
        member_id: &MemberId,
        spec: &ContainerAttachSpec,
        dns: &[IpAddr],
        ports: &mut PortRegistry,
        timeout: Duration,
    ) -> Result<
        AttachedContainer<ContainerNetns>,
        RecordedError<Box<ContainerAttachError>, AttachedContainer<ContainerNetns>>,
    > {
        attach_recorded_with(guard, member_id, spec, dns, |ipam, generation| {
            attach_container_with_generation(
                &LinuxAttachOps {
                    route,
                    nft,
                    timeout,
                },
                spec,
                ipam,
                ports,
                generation,
            )
        })
    }

    /// コンテナを切り離して `members/<id>` を消す（`detach_container` の記録つき版）。
    ///
    /// 記録の検証で拒否した場合、渡した `container` は破棄される（pin は残る。モジュール doc の未実装範囲）。
    #[allow(clippy::too_many_arguments)]
    pub fn detach_container_recorded(
        route: &NetlinkRouteSocket,
        nft: &NetlinkNetfilterSocket,
        guard: &NetworkLockGuard<'_>,
        member_id: &MemberId,
        container: AttachedContainer<ContainerNetns>,
        extra_published: Vec<PublishedPort>,
        ports: &mut PortRegistry,
        timeout: Duration,
    ) -> Result<
        NetworkDeleteReport,
        RecordedError<Box<ContainerDetachError<ContainerNetns>>, NetworkDeleteReport>,
    > {
        detach_recorded_with(guard, member_id, |created, ipam| {
            detach_container(
                route,
                nft,
                created,
                container,
                extra_published,
                ipam,
                ports,
                timeout,
            )
        })
    }

    /// メンバーのいないネットワークを削除して `realized` を消す（`delete_network` の記録つき版）。
    pub fn delete_network_recorded(
        route: &NetlinkRouteSocket,
        nft: &NetlinkNetfilterSocket,
        guard: &NetworkLockGuard<'_>,
        ports: &mut PortRegistry,
        timeout: Duration,
    ) -> Result<
        NetworkDeleteReport,
        RecordedError<Box<NetworkDeleteError<ContainerNetns>>, NetworkDeleteReport>,
    > {
        delete_recorded_with(guard, |created, ipam| {
            delete_network(route, nft, created, Vec::new(), ipam, ports, timeout).map_err(Box::new)
        })
    }
}

#[cfg(target_os = "linux")]
pub use linux::{
    attach_container_recorded, create_network_recorded, delete_network_recorded,
    detach_container_recorded,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::netlink_route::{IfIndex, IfName};
    use crate::network::{
        AttachResource, AttachRollbackReport, AttachStep, CONTAINER_IFNAME, CreateStep, EndpointId,
        NetnsDirRecord, NetworkName, NetworkResource, NetworkResourceNames, ResourceState,
        RollbackReport, VethNames,
    };
    use crate::network_store::NetworkStore;
    use std::net::Ipv4Addr;
    use std::path::{Path, PathBuf};

    const BRIDGE_TOKEN: &str = "fandhe-net:web:1:0:0";
    const NETNS_DIR: &str = "/run/fc-test-ns";

    struct Tmp(PathBuf);
    impl Tmp {
        fn new(tag: &str) -> Self {
            let p = std::env::temp_dir().join(format!(
                "fc-netrecorded-{}-{}-{tag}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_nanos())
            ));
            std::fs::create_dir(&p).unwrap();
            std::fs::set_permissions(&p, std::os::unix::fs::PermissionsExt::from_mode(0o700))
                .unwrap();
            Tmp(p)
        }
    }
    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn pfx(a: [u8; 4], len: u8) -> IpPrefix {
        IpPrefix::new(IpAddr::V4(Ipv4Addr::from(a)), len).unwrap()
    }
    fn name() -> NetworkName {
        NetworkName::new("web").unwrap()
    }
    fn def() -> NetworkDefinition {
        NetworkDefinition::bridge("web", pfx([10, 0, 0, 0], 24)).unwrap()
    }
    fn created() -> CreatedNetwork {
        let n = name();
        let names = NetworkResourceNames::derive(&n).unwrap();
        CreatedNetwork {
            bridge: names.bridge().clone(),
            bridge_index: IfIndex::new(7).unwrap(),
            bridge_token: BRIDGE_TOKEN.to_owned(),
            table: names.table().clone(),
            gateway: pfx([10, 0, 0, 1], 24),
            name_resolution: NameResolution::default(),
            name: n,
        }
    }
    fn setup(t: &Tmp) -> NetworkStore {
        let store = NetworkStore::open(&t.0).unwrap();
        store.create(&def()).unwrap();
        store
    }
    fn realize(guard: &NetworkLockGuard<'_>) {
        guard
            .commit_realized(
                &RealizedRecord::from_created(&created(), pfx([10, 0, 0, 0], 24)).unwrap(),
            )
            .unwrap();
    }
    fn spec(ep: &str) -> ContainerAttachSpec {
        ContainerAttachSpec::new(
            EndpointId::new(ep).unwrap(),
            &created(),
            PathBuf::from(NETNS_DIR),
        )
        .unwrap()
    }
    fn mid(s: &str) -> MemberId {
        MemberId::new(s).unwrap()
    }

    /// 成功する attach の代役。IPAM に払い出して接続結果を返す。
    fn ok_run(
        spec: &ContainerAttachSpec,
    ) -> impl FnOnce(&mut StaticIpam, &str) -> Result<AttachedContainer<()>, ContainerAttachError> + '_
    {
        move |ipam, generation| {
            let ep = spec.endpoint().clone();
            let address = ipam
                .allocate_pinned(&ep, NetnsDirRecord::new(PathBuf::from(NETNS_DIR), (8, 9)))
                .unwrap();
            let names = VethNames::derive(&ep).unwrap();
            Ok(AttachedContainer {
                host_veth: names.host().clone(),
                host_index: IfIndex::new(10).unwrap(),
                host_token: host_owner_token(BRIDGE_TOKEN, &ep, generation),
                peer_veth: names.peer().clone(),
                container_ifname: IfName::new(CONTAINER_IFNAME).unwrap(),
                netns_path: Path::new(NETNS_DIR).join(ep.as_str()),
                address,
                netns: (),
                published_ports: Vec::new(),
                pin_identity: None,
                endpoint: ep,
            })
        }
    }

    /// 取り残し（host veth）つきで失敗する attach の代役。
    fn failing_run(
        spec: &ContainerAttachSpec,
        leftover: Vec<(AttachResource, ResourceState)>,
    ) -> impl FnOnce(&mut StaticIpam, &str) -> Result<AttachedContainer<()>, ContainerAttachError> + '_
    {
        move |_ipam, generation| {
            let names = VethNames::derive(spec.endpoint()).unwrap();
            let leftover = leftover
                .into_iter()
                .map(|(r, s)| match r {
                    AttachResource::Veth(_) => (AttachResource::Veth(names.host().clone()), s),
                    other => (other, s),
                })
                .collect();
            Err(ContainerAttachError {
                error: NetError::new(NetErrorCode::Internal, "injected attach failure"),
                step: AttachStep::SetMaster,
                rollback: AttachRollbackReport {
                    removed: Vec::new(),
                    leftover,
                },
                owner: Some(Box::new(super::super::AttachOwner {
                    network: name(),
                    token: BRIDGE_TOKEN.to_owned(),
                    endpoint: spec.endpoint().clone(),
                    generation: generation.to_owned(),
                    pin: None,
                })),
            })
        }
    }

    fn veth_leftover() -> Vec<(AttachResource, ResourceState)> {
        vec![(
            AttachResource::Veth(IfName::new("placeholder").unwrap()),
            ResourceState::Present,
        )]
    }

    /// NET-1・#3067: attach の成功後にメンバー記録が具体値で読め、意図記録は残らない。
    #[test]
    fn net1_3067_attach_writes_member_after_success() {
        let t = Tmp::new("attach-ok");
        let store = setup(&t);
        let g = store.lock_global_exclusive().unwrap();
        let n = g.lock_network(&name()).unwrap();
        realize(&n);
        let s = spec("c1");
        let dns: Vec<IpAddr> = vec!["1.1.1.1".parse().unwrap()];
        let att = attach_recorded_with(&n, &mid("c1"), &s, &dns, ok_run(&s)).unwrap();
        assert_eq!(att.address, pfx([10, 0, 0, 2], 24));
        let members = n.members().unwrap();
        assert_eq!(members.len(), 1);
        assert_eq!(members[0].address(), pfx([10, 0, 0, 2], 24));
        assert_eq!(members[0].endpoint().as_str(), "c1");
        assert_eq!(members[0].dns(), dns.as_slice());
        assert_eq!(members[0].token(), att.host_token);
        assert!(n.member_intents().unwrap().is_empty());
        // 二重の attach は拒否される。
        let again = attach_recorded_with(&n, &mid("c1"), &s, &[], ok_run(&s));
        assert_eq!(
            again.unwrap_err().store_code(),
            Some(NetErrorCode::AlreadyExists)
        );
    }

    /// 取り残しつきの失敗: メンバー記録は無く、請求書が保存される。取り残しだけなら意図記録は消える。
    #[test]
    fn net1_3067_attach_failure_keeps_no_member_and_saves_claim() {
        let t = Tmp::new("attach-fail");
        let store = setup(&t);
        let g = store.lock_global_exclusive().unwrap();
        let n = g.lock_network(&name()).unwrap();
        realize(&n);
        let s = spec("c1");
        let r = attach_recorded_with(&n, &mid("c1"), &s, &[], failing_run(&s, veth_leftover()));
        assert!(matches!(r, Err(RecordedError::Op(_))));
        assert!(n.members().unwrap().is_empty());
        assert!(n.member_intents().unwrap().is_empty());
        let claims = n.reclaim_records().unwrap();
        assert_eq!(claims.attach.len(), 1);
        assert_eq!(claims.attach[0].endpoint().as_str(), "c1");
        assert!(claims.attach[0].includes_veth());
        // 取り残しが無い失敗は請求書を作らない。
        let s2 = spec("c2");
        let r = attach_recorded_with(&n, &mid("c2"), &s2, &[], failing_run(&s2, Vec::new()));
        assert!(matches!(r, Err(RecordedError::Op(_))));
        assert_eq!(n.reclaim_records().unwrap().attach.len(), 1);
        assert!(n.member_intents().unwrap().is_empty());
    }

    /// quarantine つきの失敗では意図記録を残し、そのアドレスを再割り当てしない。
    #[test]
    fn net1_3067_attach_quarantine_keeps_intent_and_address() {
        let t = Tmp::new("attach-quar");
        let store = setup(&t);
        let g = store.lock_global_exclusive().unwrap();
        let n = g.lock_network(&name()).unwrap();
        realize(&n);
        let s = spec("c1");
        let leftover = vec![(
            AttachResource::Address(pfx([10, 0, 0, 2], 24)),
            ResourceState::Unknown,
        )];
        let _ = attach_recorded_with(&n, &mid("c1"), &s, &[], failing_run(&s, leftover));
        assert_eq!(n.member_intents().unwrap().len(), 1);
        let s2 = spec("c2");
        let att = attach_recorded_with(&n, &mid("c2"), &s2, &[], ok_run(&s2)).unwrap();
        assert_eq!(att.address, pfx([10, 0, 0, 3], 24));
    }

    /// 意図記録だけが残った（落ちた）後の attach は、そのアドレスを避ける。
    #[test]
    fn net1_3067_crash_after_intent_counts_address() {
        let t = Tmp::new("crash");
        let store = setup(&t);
        let g = store.lock_global_exclusive().unwrap();
        let n = g.lock_network(&name()).unwrap();
        realize(&n);
        let host_token = host_owner_token(
            BRIDGE_TOKEN,
            &EndpointId::new("c1").unwrap(),
            "00000000000000000000000000000001",
        );
        n.write_member_intent(
            &MemberIntent::new(
                mid("c1"),
                EndpointId::new("c1").unwrap(),
                pfx([10, 0, 0, 2], 24),
                &host_token,
            )
            .unwrap(),
        )
        .unwrap();
        let s = spec("c2");
        let att = attach_recorded_with(&n, &mid("c2"), &s, &[], ok_run(&s)).unwrap();
        assert_eq!(att.address, pfx([10, 0, 0, 3], 24));
    }

    /// 確定記録の永続化に失敗しても成功した接続の値は返り、意図記録は残る。
    #[test]
    fn net1_3067_attach_result_mismatch_keeps_intent() {
        let t = Tmp::new("mismatch");
        let store = setup(&t);
        let g = store.lock_global_exclusive().unwrap();
        let n = g.lock_network(&name()).unwrap();
        realize(&n);
        let s = spec("c1");
        let r = attach_recorded_with(&n, &mid("c1"), &s, &[], |ipam, generation| {
            let mut att = ok_run(&s)(ipam, generation)?;
            att.address = pfx([10, 0, 0, 9], 24);
            Ok(att)
        });
        assert!(matches!(r, Err(RecordedError::Uncommitted { .. })));
        assert_eq!(n.member_intents().unwrap().len(), 1);
        assert!(n.members().unwrap().is_empty());
    }

    /// detach の成功後にメンバー記録が消え、次の attach が同じアドレスを再び払い出す。
    #[test]
    fn net1_3067_detach_removes_member_and_frees_address() {
        let t = Tmp::new("detach");
        let store = setup(&t);
        let g = store.lock_global_exclusive().unwrap();
        let n = g.lock_network(&name()).unwrap();
        realize(&n);
        let s1 = spec("c1");
        attach_recorded_with(&n, &mid("c1"), &s1, &[], ok_run(&s1)).unwrap();
        let s2 = spec("c2");
        attach_recorded_with(&n, &mid("c2"), &s2, &[], ok_run(&s2)).unwrap();
        assert_eq!(n.rebuild_ipam().unwrap().allocated_count(), 2);
        let seen = std::cell::Cell::new(0usize);
        let r =
            detach_recorded_with::<Box<ContainerDetachErrorUnit>, _>(&n, &mid("c1"), |_c, ipam| {
                seen.set(ipam.allocated_count());
                Ok(NetworkDeleteReport::default())
            });
        assert!(r.is_ok());
        assert_eq!(seen.get(), 2, "run には組み直した IPAM が渡る");
        assert_eq!(n.members().unwrap().len(), 1);
        assert_eq!(n.rebuild_ipam().unwrap().allocated_count(), 1);
        let s3 = spec("c3");
        let att = attach_recorded_with(&n, &mid("c3"), &s3, &[], ok_run(&s3)).unwrap();
        assert_eq!(att.address, pfx([10, 0, 0, 2], 24));
        // 記録に無いメンバーの detach は NotFound。
        let r =
            detach_recorded_with::<Box<ContainerDetachErrorUnit>, _>(&n, &mid("zz"), |_c, _i| {
                Ok(NetworkDeleteReport::default())
            });
        assert_eq!(r.unwrap_err().store_code(), Some(NetErrorCode::NotFound));
    }

    /// detach が失敗してもメンバー記録は残る。
    #[test]
    fn net1_3067_detach_failure_keeps_member() {
        let t = Tmp::new("detach-fail");
        let store = setup(&t);
        let g = store.lock_global_exclusive().unwrap();
        let n = g.lock_network(&name()).unwrap();
        realize(&n);
        let s1 = spec("c1");
        attach_recorded_with(&n, &mid("c1"), &s1, &[], ok_run(&s1)).unwrap();
        let r = detach_recorded_with(&n, &mid("c1"), |_c, _i| {
            Err::<NetworkDeleteReport, _>(Box::new(ContainerDetachErrorUnit))
        });
        assert!(matches!(r, Err(RecordedError::Op(_))));
        assert_eq!(n.members().unwrap().len(), 1);
    }

    /// 試験用の切り離し失敗（請求書なし）。
    #[derive(Debug)]
    struct ContainerDetachErrorUnit;
    impl DetachClaim for Box<ContainerDetachErrorUnit> {
        fn attach_claim(&self) -> Option<super::super::FailedAttachClaim> {
            None
        }
    }

    fn create_err(leftover: Vec<(NetworkResource, ResourceState)>) -> NetworkCreateError {
        NetworkCreateError {
            error: NetError::new(NetErrorCode::Internal, "injected create failure"),
            step: CreateStep::CreateNftTable,
            rollback: RollbackReport {
                removed: Vec::new(),
                leftover,
            },
            owner_token: Some(Box::new((name(), BRIDGE_TOKEN.to_owned()))),
        }
    }

    /// create の成功で `realized` が書かれ、意図記録は消える。二重の create は拒否される。
    #[test]
    fn net1_3067_create_success_writes_realized() {
        let t = Tmp::new("create-ok");
        let store = setup(&t);
        let g = store.lock_global_exclusive().unwrap();
        let n = g.lock_network(&name()).unwrap();
        let seen = std::cell::RefCell::new(String::new());
        let out = create_recorded_with(&n, &def(), pfx([10, 0, 0, 1], 24), |token| {
            *seen.borrow_mut() = token.to_owned();
            // 実行中は意図記録が読める。
            assert_eq!(
                n.realized_intent().unwrap().unwrap().token(),
                token,
                "カーネル操作の前に意図記録がある"
            );
            let mut c = created();
            c.bridge_token = token.to_owned();
            Ok(c)
        })
        .unwrap();
        assert_eq!(out.bridge_token, *seen.borrow());
        let rec = n.realized().unwrap().unwrap();
        assert_eq!(rec.gateway(), pfx([10, 0, 0, 1], 24));
        assert_eq!(rec.subnet(), pfx([10, 0, 0, 0], 24));
        assert_eq!(n.realized_intent().unwrap(), None);
        let again = create_recorded_with(&n, &def(), pfx([10, 0, 0, 1], 24), |_| Ok(created()));
        assert_eq!(
            again.unwrap_err().store_code(),
            Some(NetErrorCode::AlreadyExists)
        );
    }

    /// create が取り残しつきで失敗したら請求書を残し、意図記録は消える。保存できなければ意図記録が残る。
    #[test]
    fn net1_3067_create_failure_leaves_claim() {
        let t = Tmp::new("create-fail");
        let store = setup(&t);
        let g = store.lock_global_exclusive().unwrap();
        let n = g.lock_network(&name()).unwrap();
        let leftover = vec![(
            NetworkResource::Bridge(IfName::new("fcbr0").unwrap()),
            ResourceState::Unknown,
        )];
        let r = create_recorded_with(&n, &def(), pfx([10, 0, 0, 1], 24), |_| {
            Err(create_err(leftover))
        });
        assert!(matches!(r, Err(RecordedError::Op(_))));
        assert_eq!(n.realized().unwrap(), None);
        assert_eq!(n.realized_intent().unwrap(), None);
        let claim = n.reclaim_records().unwrap().create.unwrap();
        assert!(claim.includes_bridge());
        assert!(!claim.includes_table());
        // gateway が subnet の外なら、カーネル操作の前に拒否する。
        let r = create_recorded_with(&n, &def(), pfx([10, 9, 0, 1], 24), |_| {
            panic!("must not run")
        });
        assert_eq!(
            r.unwrap_err().store_code(),
            Some(NetErrorCode::InvalidArgument)
        );
    }

    /// 残った `realized.intent` は次の操作を拒否する（未照合の fail-closed）。
    #[test]
    fn net1_3067_unreconciled_intent_is_fail_closed() {
        let t = Tmp::new("unreconciled");
        let store = setup(&t);
        let g = store.lock_global_exclusive().unwrap();
        let n = g.lock_network(&name()).unwrap();
        realize(&n);
        n.write_realized_intent(
            &RealizedIntent::new(
                RealizedOp::Delete,
                name(),
                BRIDGE_TOKEN,
                pfx([10, 0, 0, 0], 24),
            )
            .unwrap(),
        )
        .unwrap();
        let s = spec("c1");
        let r = attach_recorded_with(&n, &mid("c1"), &s, &[], ok_run(&s));
        assert_eq!(
            r.unwrap_err().store_code(),
            Some(NetErrorCode::FailedPrecondition)
        );
        assert!(n.member_intents().unwrap().is_empty());
    }

    /// delete: メンバーがいれば拒否、いなければ成功して `realized` が消える。失敗なら意図記録が残る。
    #[test]
    fn net1_3067_delete_removes_realized() {
        let t = Tmp::new("delete");
        let store = setup(&t);
        let g = store.lock_global_exclusive().unwrap();
        let n = g.lock_network(&name()).unwrap();
        realize(&n);
        let s = spec("c1");
        attach_recorded_with(&n, &mid("c1"), &s, &[], ok_run(&s)).unwrap();
        let r = delete_recorded_with::<(), (), _>(&n, |_c, _i| Ok(()));
        assert_eq!(
            r.unwrap_err().store_code(),
            Some(NetErrorCode::FailedPrecondition)
        );
        n.remove_member(&mid("c1")).unwrap();
        let failed = delete_recorded_with::<(), &str, _>(&n, |_c, _i| Err("boom"));
        assert!(matches!(failed, Err(RecordedError::Op("boom"))));
        assert!(n.realized_intent().unwrap().is_some());
        // 未完了の操作が残っていれば、次の delete も拒否される。
        let blocked = delete_recorded_with::<(), (), _>(&n, |_c, _i| Ok(()));
        assert_eq!(
            blocked.unwrap_err().store_code(),
            Some(NetErrorCode::FailedPrecondition)
        );
        n.remove_realized_intent().unwrap();
        delete_recorded_with::<(), (), _>(&n, |c, ipam| {
            assert_eq!(c.name.as_str(), "web");
            assert_eq!(ipam.allocated_count(), 0);
            Ok(())
        })
        .unwrap();
        assert_eq!(n.realized().unwrap(), None);
        assert_eq!(n.realized_intent().unwrap(), None);
    }
}
