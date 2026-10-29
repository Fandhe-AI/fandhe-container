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
//! # 公開の記録と再起動後の個別解除（NET-3・#3068）
//! create は成功の直後に GETTABLE で専用テーブルを照会し、`NFTA_TABLE_USERDATA` が所有トークンと一致することを
//! 確かめたうえでテーブルのカーネル採番ハンドルを `realized` に記録する（確かめられなければ [`RecordedError::Uncommitted`]
//! で意図記録を残す）。attach は公開の受け口と rule handle 2 本を、そのテーブルハンドルとともに `members/<id>` に記録する
//! （返す `AttachedContainer::published_ports` にもテーブルハンドルを束縛する）。再起動後は
//! `restore_published_ports_recorded` が dump を使わず記録から [`PublishedPort`] を復元し、
//! `unpublish_port_recorded_with` が復元した値を記録と照合して個別に解除する。解除は rule handle を使う前に毎回
//! 生きたテーブルのハンドルと照合し、食い違えば（テーブルが作り直されている）DELRULE を送らず
//! [`UnpublishRules::StaleHandles`] で断る。解除の成功後は、そのメンバー記録から該当の公開を外して書き直す。
//!
//! # 再起動後の detach（記録だけからの切り離し。NET-1・NET-6・REPAIR-4・#3347）
//! `detach_member_recorded` は生きた `AttachedContainer` を取らず、`members/<id>` から請求書を合成して
//! 既存の回収（`reclaim_failed_attach` と同じ規則）で DNAT ルール → host veth → netns の pin を外し、ポート予約と
//! メンバー記録（= IPAM のアドレス）を解放する。pin の三者照合のため、メンバー記録は pin の識別子を持つ
//! （FCMEM1 の `pin`。無い旧形式は pin が残っていれば `Unknown` の取り残しで手動回収）。所有トークン・世代・
//! 回収待ちの請求書・置き場・解除の印を、カーネル操作の前に fail-closed で確かめる（`detach_member_recorded_with`）。
//!
//! # 検証で拒否した `detach_container_recorded`（#3347）
//! 記録との照合で拒否した場合、渡された `AttachedContainer` は破棄され、netns の pin・host veth・DNAT は残る
//! （fd が閉じるだけ）。拒否の時点では渡されたコンテナと記録が同じものと証明できず、外すと別メンバーの pin を
//! 外しうるため、あえて外さない。見分け方と回収は `docs/setup/network-reclaim-recovery.md` を参照。
//! メンバー記録が残る拒否は `detach_member_recorded` で回収に収束できる。
//!
//! # 未実装範囲（REPAIR-3）
//! - 残った `realized.intent` / `members-intent/*` のカーネル照合による昇格・巻き戻し（link の dump API が前提）
//! - ホストの再起動（boot ID が変わる）をまたぐ記録だけからの detach。世代が違うと断り、手動回収に回す
//! - `@networks` の経路で保留中の請求書を回収する結線は後続（#3075 系）
//! - 記録から `PortRegistry`（ポート予約）を組み直すこと。再起動直後は空の予約表を渡すと、解除はルールの削除だけを
//!   行い、予約の解放は 0 件で成功する

use std::net::IpAddr;
use std::path::Path;

use super::attach_claim::ClaimedRules;
use super::{
    AttachedContainer, ContainerAttachError, ContainerAttachSpec, CreatedNetwork,
    FailedAttachClaim, NetnsDirRecord, NetworkCreateError, NetworkDeleteReport, StaticIpam,
    host_owner_token, new_generation, ownership_token,
};
use crate::dns_helper::upstream::{MAX_UPSTREAMS_PER_CONTAINER, UpstreamServer};
use crate::error::{NetError, NetErrorCode};
use crate::etc_hosts::NameResolution;
use crate::instrument::{NetOpKind, record_net_op};
use crate::netlink_route::IpPrefix;
use crate::network_store::MAX_MEMBERS_PER_NETWORK;
use crate::network_store::realized::check_gateway;
use crate::network_store::{
    HostGeneration, InstallMode, MemberId, MemberIntent, MemberRecord, NetworkDefinition,
    NetworkLockGuard, RealizedIntent, RealizedOp, RealizedRecord, RecordedPublish, rebuild_ipam,
};
use crate::nftables_batch::{NftBatchOutcome, NftName, TableInfo};
use crate::nftables_rules::NftRuleHandle;

use super::NftApplyFailure;
use super::delete::require_table_owned;
use super::unpublish::{delete_published_rules_with, release_published_listener};
use super::{PortRegistry, PublishedPort, UnpublishPortError, UnpublishRules};
use crate::network_store::member::PublishState;

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
fn settled_realized(guard: &NetworkLockGuard<'_>) -> Result<RealizedRecord, NetError> {
    let realized = guard
        .realized()?
        .ok_or_else(|| precondition("network is not realized"))?;
    if guard.realized_intent()?.is_some() {
        return Err(unreconciled());
    }
    Ok(realized)
}

/// `realized` の世代（boot ID・network namespace）が現在と一致することを確かめる。
///
/// nft のテーブルハンドルは再起動や namespace の再作成後に同じ数値が再利用されうるため、世代を確認できない
/// 記録のハンドルは使わない（DELRULE 等の前に `FailedPrecondition` で断る。NET-3・SEC-1・#3068）。
/// `delete_recorded_with` には適用しない（再起動後の残骸の回収を妨げないため。所有はトークンで証明する）。
fn check_generation(realized: &RealizedRecord, now: &HostGeneration) -> Result<(), NetError> {
    if realized.generation() != now {
        return Err(precondition(
            "recorded nft handles belong to another boot or network namespace",
        ));
    }
    Ok(())
}

/// [`settled_realized`] の `RecordedError` 版。
fn require_settled<E, T>(
    guard: &NetworkLockGuard<'_>,
) -> Result<RealizedRecord, RecordedError<E, T>> {
    settled_realized(guard).map_err(RecordedError::Store)
}

/// [`require_settled`] に世代の確認を足したもの（ルールハンドルを使う経路用）。
fn require_settled_current<E, T>(
    guard: &NetworkLockGuard<'_>,
    host: &HostGeneration,
) -> Result<RealizedRecord, RecordedError<E, T>> {
    let realized = require_settled(guard)?;
    check_generation(&realized, host).map_err(RecordedError::Store)?;
    Ok(realized)
}

/// 排他ロックのガードであることを、カーネル操作の前に確かめる。
fn require_exclusive_guard<E, T>(guard: &NetworkLockGuard<'_>) -> Result<(), RecordedError<E, T>> {
    if guard.is_exclusive() {
        Ok(())
    } else {
        Err(RecordedError::Store(precondition(
            "network operations need the exclusive network lock",
        )))
    }
}

/// `--dns` の上流を、意図記録とカーネル操作の前に検証する（`MemberRecord::new` と `rebuild_ipam` の規則と同じ）。
fn check_dns(dns: &[IpAddr], gateway: IpAddr) -> Result<(), NetError> {
    let invalid = |m: &'static str| NetError::new(NetErrorCode::InvalidArgument, m);
    if dns.len() > MAX_UPSTREAMS_PER_CONTAINER {
        return Err(invalid("too many dns servers for a member"));
    }
    for (i, ip) in dns.iter().enumerate() {
        UpstreamServer::new(*ip)?;
        if dns.iter().skip(i + 1).any(|o| o == ip) {
            return Err(invalid("duplicate dns server for a member"));
        }
        if *ip == gateway {
            return Err(invalid("dns server is the network gateway"));
        }
    }
    Ok(())
}

/// attach を記録つきで行う本体。`run` は払い出し済みの IPAM と接続の世代を受けて接続する。
///
/// 手順: 記録から IPAM を組み直す → 世代とアドレスを決める → 意図記録を書く → `run` → 成功なら確定記録、
/// 失敗なら請求書（取り残しがあるとき）と意図記録の後始末。`dns` は確定記録にだけ載せる（`--dns` の上流。NET-12）。
pub(crate) fn attach_recorded_with<N, G, F>(
    host: &HostGeneration,
    guard: &NetworkLockGuard<'_>,
    member_id: &MemberId,
    spec: &ContainerAttachSpec,
    dns: &[IpAddr],
    table_info: G,
    run: F,
) -> Result<AttachedContainer<N>, RecordedError<Box<ContainerAttachError>, AttachedContainer<N>>>
where
    G: FnOnce(&NftName) -> Result<TableInfo, NetError>,
    F: FnOnce(&mut StaticIpam, &str) -> Result<AttachedContainer<N>, ContainerAttachError>,
{
    require_exclusive_guard(guard)?;
    let realized = require_settled_current(guard, host)?;
    check_dns(dns, realized.gateway().addr()).map_err(RecordedError::Store)?;
    if &spec.network != realized.name() || spec.bridge_token != realized.token() {
        return Err(RecordedError::Store(precondition(
            "attach spec does not belong to the network",
        )));
    }
    // 生きたテーブルのハンドルが `realized` の記録と一致しなければ、カーネル資源を作る前に断る。食い違うまま
    // attach すると新しいルールに古いハンドルが束縛され、個別解除も detach も `StaleHandles` で拒否され続ける
    // （NET-3・SEC-1・#3068）。照会はテーブルの所有トークンの照合も兼ねる（読み取りのみ）。
    let table = realized.to_created(NameResolution::default()).table;
    let live =
        require_table_owned(table_info(&table), realized.token()).map_err(RecordedError::Store)?;
    if live != realized.table_handle() {
        return Err(RecordedError::Store(precondition(
            "nft table was recreated; recorded table handle is stale",
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
    // 上限はカーネル操作の前に検査する（超過で確定記録だけ書けず生きたコンテナが残るのを防ぐ）。
    // 確定記録を書いた後、意図記録を消す前に落ちた窓では同じメンバーが両方に残る。整合性の検証
    // （`rebuild_ipam`）の後に、重複を除いた数で判定する。
    let distinct = members.len()
        + intents
            .iter()
            .filter(|i| !members.iter().any(|m| m.id() == i.id()))
            .count();
    if distinct >= MAX_MEMBERS_PER_NETWORK {
        return Err(RecordedError::Store(NetError::new(
            NetErrorCode::ResourceExhausted,
            "too many members",
        )));
    }
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
        Ok(att) => commit_attached(
            guard,
            member_id,
            dns,
            &ipam,
            (address, &host_token),
            &realized,
            att,
        ),
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
    (address, host_token): (IpPrefix, &str),
    realized: &RealizedRecord,
    mut att: AttachedContainer<N>,
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
    // 公開は realized に記録したテーブルのハンドルに束縛する（返す値の個別解除も生きたテーブルと照合できる）。
    let table_handle = realized.table_handle();
    att.published_ports = std::mem::take(&mut att.published_ports)
        .into_iter()
        .map(|p| p.with_table_handle(table_handle))
        .collect();
    let recorded: Vec<RecordedPublish> = att
        .published_ports
        .iter()
        .map(|p| RecordedPublish::new(*p.publish(), p.prerouting_handle(), p.output_handle()))
        .collect();
    let rec = MemberRecord::new(
        member_id.clone(),
        att.endpoint.clone(),
        att.address,
        &att.host_token,
        dir.path(),
        dir.dir_id(),
        dns,
    )
    .and_then(|r| r.with_publishes(table_handle, recorded))
    // pin の識別子も控える（再起動後の記録だけからの detach が三者照合に使う。#3347）。
    .map(|r| match att.pin_identity {
        Some(pin) => r.with_pin(pin),
        None => r,
    });
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
    host: &HostGeneration,
    guard: &NetworkLockGuard<'_>,
    member_id: &MemberId,
    container: ContainerIdentity<'_>,
    run: F,
) -> Result<NetworkDeleteReport, RecordedError<E, NetworkDeleteReport>>
where
    F: FnOnce(&CreatedNetwork, &mut StaticIpam) -> Result<NetworkDeleteReport, E>,
    E: DetachClaim,
{
    require_exclusive_guard(guard)?;
    let realized = require_settled_current(guard, host)?;
    let members = guard.members().map_err(RecordedError::Store)?;
    let intents = guard.member_intents().map_err(RecordedError::Store)?;
    let Some(recorded) = members.iter().find(|m| m.id() == member_id) else {
        return Err(RecordedError::Store(NetError::new(
            NetErrorCode::NotFound,
            "member not found",
        )));
    };
    // 別メンバーのハンドルで切り離して、記録だけ別のメンバーのものを消す事故を防ぐ（カーネル操作の前に照合する）。
    if recorded.endpoint() != container.endpoint
        || recorded.address() != container.address
        || recorded.token() != container.host_token
    {
        return Err(RecordedError::Store(precondition(
            "container does not match the member record",
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

/// 記録だけから、メンバー 1 件を切り離す本体（OS 非依存。カーネル操作は `run` で差し替える。NET-1・NET-6・REPAIR-4・#3347）。
///
/// 再起動後は生きた `AttachedContainer` を持てない。`members/<id>` から請求書（`FailedAttachClaim`）を合成し、
/// `run` が既存の回収（DNAT ルール → host veth → netns の pin。所有はトークン・bridge への所属・pin の三者照合で
/// 証明する）で外す。成功したらポート予約を解放し、メンバー記録（と残っていれば意図記録）を消す。アドレスは
/// IPAM を記録から組み直すので、メンバー記録を消せば解放される。呼び出し元の想定は supervisor（#3074）と
/// plugin-cri（#3075）の再起動後の経路。
///
/// カーネル操作の前に、次をすべて確かめ、満たさなければ何も変えずに断る（fail-closed）。
/// - 排他ロックのガード・未完了の操作（`realized.intent`）が無い・世代（boot ID と network namespace）の一致
///   （ホストの再起動をまたぐ回収は対象外で、`docs/setup/network-reclaim-recovery.md` の手動回収に回す）
/// - メンバー記録があり、所有トークンがこのネットワークのもの（`DataLoss`）
/// - 同じ endpoint の回収待ちの請求書（`pending-reclaim/attach`）が無い。切り離しの失敗で残る請求書は記録に無い
///   `extra_published` のルールを載せうるため、合成した請求書で代えない。先に `reclaim_failed_attach` で回収する
/// - `netns_dir`（呼び出し側の固定設定）が記録の置き場とバイト単位で一致する（実体の照合は `run` 側）
/// - 解除の印つきの公開が無い。ルールの回収が黙って省かれないよう、先に `unpublish_port_recorded` で回復する
///
/// `run` が失敗したらメンバー記録を残して [`RecordedError::Op`] を返す（請求書は保存しない。記録自体が回収の
/// 入力で、再実行は冪等に収束する）。成功したのに予約の解放・記録の削除に失敗したときは [`RecordedError::Uncommitted`]
/// （記録は残るので、再実行で収束する）。
/// 記録に pin の識別子が無い旧形式は、pin が無ければ回収済み、残っていれば `Unknown` の取り残しで手動回収になる。
// 実機の呼び出し（公開ラッパー）は Linux 限定。他 OS では試験だけが使う。
#[cfg(any(target_os = "linux", test))]
pub(crate) fn detach_member_recorded_with<E, F>(
    host: &HostGeneration,
    guard: &NetworkLockGuard<'_>,
    member_id: &MemberId,
    netns_dir: &Path,
    ports: &mut PortRegistry,
    run: F,
) -> Result<NetworkDeleteReport, RecordedError<E, NetworkDeleteReport>>
where
    F: FnOnce(&FailedAttachClaim, &NetnsDirRecord) -> Result<NetworkDeleteReport, E>,
{
    // 検証拒否・回収失敗・記録の削除失敗・成功のすべてを 1 件の操作として結果と所要時間を記録する（REPAIR-4）。
    record_net_op(
        guard.net_op_recorder(),
        NetOpKind::MemberDetachRecorded,
        || detach_member_recorded_inner(host, guard, member_id, netns_dir, ports, run),
    )
}

fn detach_member_recorded_inner<E, F>(
    host: &HostGeneration,
    guard: &NetworkLockGuard<'_>,
    member_id: &MemberId,
    netns_dir: &Path,
    ports: &mut PortRegistry,
    run: F,
) -> Result<NetworkDeleteReport, RecordedError<E, NetworkDeleteReport>>
where
    F: FnOnce(&FailedAttachClaim, &NetnsDirRecord) -> Result<NetworkDeleteReport, E>,
{
    require_exclusive_guard(guard)?;
    let realized = require_settled_current(guard, host)?;
    let members = guard.members().map_err(RecordedError::Store)?;
    let Some(rec) = members.iter().find(|m| m.id() == member_id) else {
        return Err(RecordedError::Store(NetError::new(
            NetErrorCode::NotFound,
            "member not found",
        )));
    };
    check_member_owned(&realized, rec).map_err(RecordedError::Store)?;
    let reclaim = guard.reclaim_records().map_err(RecordedError::Store)?;
    if reclaim
        .attach
        .iter()
        .any(|c| c.endpoint() == rec.endpoint())
    {
        return Err(RecordedError::Store(precondition(
            "endpoint has a pending reclaim record",
        )));
    }
    let dir = rec.netns_dir_record();
    if dir.path() != netns_dir {
        return Err(RecordedError::Store(NetError::new(
            NetErrorCode::InvalidArgument,
            "netns directory does not match the member record",
        )));
    }
    if rec.publishes().iter().any(RecordedPublish::unpublishing) {
        return Err(RecordedError::Store(precondition(
            "member has an unpublishing mark; recover it with unpublish first",
        )));
    }
    // 墓標（`unpublished`。ルールの削除を確かめ済みで予約だけが残る公開。#3343）は回収するルールが無いので除く。
    // 有効（Active）な公開だけを請求書のルールに載せ、墓標は記録の削除（と予約の解放）で片付く。
    let active: Vec<RecordedPublish> = rec
        .publishes()
        .iter()
        .filter(|p| !p.unpublished())
        .cloned()
        .collect();
    let rules = match rec.table_handle() {
        Some(th) if !active.is_empty() => {
            // 空・上限超過・整合違反は `None`。ルールの回収が黙って省かれるので断る。
            Some(ClaimedRules::new(th, active).ok_or_else(|| {
                RecordedError::Store(NetError::new(
                    NetErrorCode::DataLoss,
                    "member publish records are inconsistent",
                ))
            })?)
        }
        _ => None,
    };
    let claim = FailedAttachClaim::from_detach(
        realized.name(),
        realized.token(),
        rec.endpoint(),
        rec.token(),
        rec.pin(),
        true,
        true,
        rules.is_some(),
        rules,
    )
    .ok_or_else(|| {
        RecordedError::Store(NetError::new(
            NetErrorCode::Internal,
            "cannot build a reclaim claim from the member record",
        ))
    })?;
    let report = run(&claim, &dir).map_err(RecordedError::Op)?;
    let endpoint = rec.endpoint().clone();
    let finished = ports
        .release(realized.name(), &endpoint)
        .map(|_| ())
        .and_then(|()| guard.remove_member(member_id))
        .and_then(|_| guard.remove_member_intent(member_id).map(|_| ()));
    match finished {
        Ok(()) => Ok(report),
        Err(error) => Err(RecordedError::Uncommitted {
            error,
            value: Box::new(report),
        }),
    }
}

/// detach に渡されたコンテナの同一性（メンバー記録との照合用）。
pub(crate) struct ContainerIdentity<'a> {
    pub(crate) endpoint: &'a super::EndpointId,
    pub(crate) address: IpPrefix,
    pub(crate) host_token: &'a str,
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
/// （カーネル操作の前に検査する）。`table_info` は `run` の成功後に専用テーブルを照会する（読み取りのみ）。
/// userdata が所有トークンと一致するテーブルのハンドルを確かめられなければ、`realized` を書かず
/// [`RecordedError::Uncommitted`] を返す（意図記録は残す。NET-3・#3068）。
pub(crate) fn create_recorded_with<F, G>(
    host: &HostGeneration,
    guard: &NetworkLockGuard<'_>,
    definition: &NetworkDefinition,
    gateway: IpPrefix,
    run: F,
    table_info: G,
) -> Result<CreatedNetwork, RecordedError<Box<NetworkCreateError>, CreatedNetwork>>
where
    F: FnOnce(&str) -> Result<CreatedNetwork, NetworkCreateError>,
    G: FnOnce(&NftName) -> Result<TableInfo, NetError>,
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
    // ロック保持中の定義を読み直し、渡された定義（方式・subnet を含む）と一致することを確かめる（D10）。
    // 取得後・ロック前に同名のネットワークが削除・再作成された場合や、別方式の定義での呼び出しを拒否する。
    let stored = guard.definition().map_err(RecordedError::Store)?;
    if &stored != definition {
        return Err(RecordedError::Store(precondition(
            "definition differs from the stored definition",
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
    // 作成失敗の請求書が回収待ちで残る間は再作成しない（新しい所有トークンの bridge と古い請求書が併存し、
    // delete も reclaim も所有を証明できなくなる）。回収完了（請求書の削除）まで拒否する。
    let pending = guard.reclaim_records().map_err(RecordedError::Store)?;
    if pending.create.is_some() {
        return Err(RecordedError::Store(precondition(
            "network has a pending create reclaim record",
        )));
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
            let committed = require_table_owned(table_info(&created.table), &created.bridge_token)
                .and_then(|h| RealizedRecord::from_created(&created, subnet, h, host.clone()))
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
    require_exclusive_guard(guard)?;
    let realized = require_settled(guard)?;
    let members = guard.members().map_err(RecordedError::Store)?;
    let intents = guard.member_intents().map_err(RecordedError::Store)?;
    // 回収待ちの請求書が残る間は削除しない（bridge が消えると、取り残しの所属を後から証明できなくなる）。
    let reclaim = guard.reclaim_records().map_err(RecordedError::Store)?;
    if reclaim.create.is_some() || !reclaim.attach.is_empty() {
        return Err(RecordedError::Store(precondition(
            "network has pending reclaim records",
        )));
    }
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

/// メンバー記録の所有トークンがこのネットワークのものか照合する（`rebuild_ipam` と同じ `host_token_is_for`）。
/// 復元・解除は IPAM の組み直しを通らないため、ここで DataLoss として断る（NET-3・SEC-1・#3068）。
fn check_member_owned(
    realized: &RealizedRecord,
    rec: &crate::network_store::MemberRecord,
) -> Result<(), NetError> {
    if super::host_token_is_for(realized.token(), rec.endpoint(), rec.token()) {
        Ok(())
    } else {
        Err(NetError::new(
            NetErrorCode::DataLoss,
            "member token does not belong to the network",
        ))
    }
}

/// 記録から、メンバーの公開を [`PublishedPort`] として復元する（dump は使わない。再起動後の経路。NET-3・#3068）。
///
/// 読み取りだけなので共有ロックのガードでもよい。未完了の操作が残るネットワーク・`realized` の無いネットワーク・
/// 記録に無いメンバーは `FailedPrecondition` / `NotFound`。公開の無いメンバーは空の列を返す。復元した値は
/// 記録したテーブルハンドルを束縛しており、`unpublish_port_recorded_with` が解除の前に生きたテーブルと照合する。
/// 墓標（ルールの削除を確かめ済みで予約が残る公開。#3343）は含めない（`restore_unpublished_ports_recorded`）。
pub(crate) fn restore_published_ports_recorded(
    host: &HostGeneration,
    guard: &NetworkLockGuard<'_>,
    member_id: &MemberId,
) -> Result<Vec<PublishedPort>, NetError> {
    restore_with(host, guard, member_id, |rec, realized| {
        rec.published_ports(realized)
    })
}

/// 記録から、メンバーの墓標（DELRULE で消えたことを確かめ済みで、予約の解放だけが残る公開）を復元する（#3343）。
///
/// 世代・所有の照合は `restore_published_ports_recorded` と同じ。返した値は `unpublish_port_recorded_with` にだけ
/// 渡す（カーネル操作なしで予約の解放を完了する）。`detach_container` の `extra_published` に渡してはならない
/// （消えたルールへ DELRULE する）。墓標の予約が残ったままの detach は、`held_by` が 1 以上になり quarantine される。
// 実機の呼び出し（公開ラッパー）は Linux 限定。
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn restore_unpublished_ports_recorded(
    host: &HostGeneration,
    guard: &NetworkLockGuard<'_>,
    member_id: &MemberId,
) -> Result<Vec<PublishedPort>, NetError> {
    restore_with(host, guard, member_id, |rec, realized| {
        rec.unpublished_ports(realized)
    })
}

fn restore_with(
    host: &HostGeneration,
    guard: &NetworkLockGuard<'_>,
    member_id: &MemberId,
    pick: impl FnOnce(&crate::network_store::MemberRecord, &RealizedRecord) -> Vec<PublishedPort>,
) -> Result<Vec<PublishedPort>, NetError> {
    let realized = settled_realized(guard)?;
    check_generation(&realized, host)?;
    let members = guard.members()?;
    let rec = members
        .iter()
        .find(|m| m.id() == member_id)
        .ok_or_else(|| NetError::new(NetErrorCode::NotFound, "member not found"))?;
    check_member_owned(&realized, rec)?;
    Ok(pick(rec, &realized))
}

/// 公開 1 件を記録つきで個別に解除する本体（OS 非依存。カーネル操作は呼び出し側が渡す。NET-3・SEC-1・#3068・#3343）。
///
/// 手順: 排他ロックと未完了の操作が無いことを確かめる → `published` が当該メンバーの記録の 1 件と完全に一致する
/// こと（受け口・rule handle・テーブルハンドル・ネットワーク・トークン）を照合する → 生きたテーブルのハンドルと
/// 照合したうえで DELRULE → 成功したらメンバー記録から該当の公開を外して書き直し、**その後に**受け口の予約を解放する。
/// 記録に受け口の行がある間は予約を解放しない（取り残しは `delete_network` と detach の quarantine が回収する安全側）。
/// 照合で拒否・失敗したときは記録を変えず、`published` を [`UnpublishPortError`] に入れて返す。
///
/// 記録の書き直しに失敗したときは記録を読み直す。行が残っていれば（rename の前の失敗）予約を解放せず
/// [`RecordedError::Uncommitted`]（ルールは消えており、記録には古い公開が残る）。行が消えていれば（rename 後の失敗）
/// 予約を解放したうえで `Uncommitted` を返す。予約の解放に失敗したときは、ルールの削除を確かめ済みの印として墓標
/// （`unpublished` 印）を書き戻し（失敗しても取り残しの向き）、`rules: Removed`・`reservation_held: true` を返す。
/// 墓標と完全に一致する値での再試行は、カーネル操作をせず（DELRULE を送らず）予約の解放だけを完了する。
///
/// DELRULE の直前に記録へ残す解除の意図の印でも回復できる: 再試行で DELRULE が `NotFound`（バッチは all-or-nothing で
/// 何も消えていない）になっても、印があり生きたテーブルのハンドルが一致していれば、2 本を `delete_one` で 1 本ずつ
/// 削除する（各 1 本の ENOENT はそのルールが既に無い確認とみなし、残っているルールは確実に消す）。どちらかが ENOENT
/// 以外で失敗すれば記録と予約を保つ。印が無い ENOENT は成功扱いにしない。記録に当該の公開が無い値は、解除済みを示す
/// 永続記録が無いので受け付けず、DELRULE も予約の解放も行わない（予約は `delete_network` まで保持する）。
/// `registry` が空（再起動直後）なら予約の解放は 0 件で成功する。
// 理由: 世代・ガード・メンバー・公開・予約表に、カーネル操作の 3 本の注入（照会・一括削除・1 本削除）と記録の書き込みを
// 足した形で、まとめる型を作ると借用の寿命が呼び出し側へ漏れるため引数で受ける。
#[allow(clippy::too_many_arguments)]
pub(crate) fn unpublish_port_recorded_with<G, D, S, W>(
    host: &HostGeneration,
    guard: &NetworkLockGuard<'_>,
    member_id: &MemberId,
    published: PublishedPort,
    registry: &mut PortRegistry,
    table_info: G,
    delete: D,
    mut delete_one: S,
    mut write_member: W,
) -> Result<(), RecordedError<Box<UnpublishPortError>, ()>>
where
    G: FnOnce(&NftName) -> Result<TableInfo, NetError>,
    D: FnOnce(&NftName, (NftRuleHandle, NftRuleHandle)) -> Result<(), NftApplyFailure>,
    S: FnMut(&NftName, &'static str, NftRuleHandle) -> Result<(), NftApplyFailure>,
    W: FnMut(&crate::network_store::MemberRecord) -> Result<(), NetError>,
{
    require_exclusive_guard(guard)?;
    let realized = require_settled_current(guard, host)?;
    let members = guard.members().map_err(RecordedError::Store)?;
    let Some(rec) = members.iter().find(|m| m.id() == member_id) else {
        return Err(RecordedError::Store(NetError::new(
            NetErrorCode::NotFound,
            "member not found",
        )));
    };
    // 別ネットワークのトークンを持つ記録は、DELRULE の前に DataLoss で断る（復元は `realized` のトークンで値を
    // 作るため、後段の完全一致では検出できない）。
    check_member_owned(&realized, rec).map_err(RecordedError::Store)?;
    // 記録に無い公開は、予約の存在だけでは解除済みと証明できない（recorded attach 後の `publish_container_ports` で
    // 足した公開や、古い値と再公開の取り違えを区別できない）。DELRULE も予約の解放もせず断る（予約は delete_network
    // まで保持する。fail-closed。NET-3・SEC-1）。記録と食い違う公開（別メンバーのもの・ハンドル違い）も同じ。
    let Some(state) = rec.publish_state_of(&realized, &published) else {
        return Err(RecordedError::Op(Box::new(UnpublishPortError {
            error: precondition("published port does not match the member record"),
            rules: UnpublishRules::Unknown,
            reservation_held: true,
            published: Some(Box::new(published)),
        })));
    };
    let publish = *published.publish();
    let created = realized.to_created(NameResolution::default());
    // 墓標: ルールの削除は確かめ済み。カーネル操作（照会・DELRULE）をせず、消えたルールの handle を再び使わない。
    let published = if state == PublishState::Unpublished {
        published
    } else {
        // 前回の試行が DELRULE の前に残した解除の意図の印（再起動をまたいで DELRULE 成功後の記録更新失敗から回復する根拠）。
        let was_marked = state == PublishState::Unpublishing;
        // 印は生きたテーブルのハンドルとの照合を通った後、DELRULE の直前に書く（照合で断る経路では記録を変えない）。
        // 印を書けなければ DELRULE を送らない。印があれば、DELRULE の ENOENT（失敗のバッチは all-or-nothing で何も
        // 消えていない）は、前回の DELRULE が成功した後に記録の更新だけが失敗した状態とみなして続行する。
        // 印が無い初回の ENOENT は外部要因なので成功扱いにせず断る（fail-closed）。
        let delete = |table: &NftName, handles| {
            if !was_marked {
                let marked = rec
                    .with_unpublishing(&publish)
                    .and_then(|next| write_member(&next))
                    .map_err(|error| NftApplyFailure {
                        error,
                        outcome: NftBatchOutcome::NotSent,
                    });
                marked?;
            }
            let is_absent = |f: &NftApplyFailure| {
                f.outcome == NftBatchOutcome::Aborted && f.error.code() == NetErrorCode::NotFound
            };
            match delete(table, handles) {
                // 2 本の一括削除は片方の ENOENT で全体が中止される。印があるときは 1 本ずつ削除し、各 ENOENT だけを
                // そのルールが既に無いこととみなす。残っているルールの削除に失敗すれば、記録と予約を保つ。
                Err(f) if was_marked && is_absent(&f) => {
                    for (chain, handle) in [("prerouting", handles.0), ("output", handles.1)] {
                        match delete_one(table, chain, handle) {
                            Err(f) if !is_absent(&f) => return Err(f),
                            _ => {}
                        }
                    }
                    Ok(())
                }
                other => other,
            }
        };
        delete_published_rules_with(table_info, delete, &created, published)
            .map_err(|e| RecordedError::Op(Box::new(e)))?
    };
    // ルールは消えた。記録から公開を外す（予約の解放より先。記録に行がある間は予約を解放しない。#3343）。
    let uncommitted = |error: NetError| RecordedError::Uncommitted {
        error,
        value: Box::new(()),
    };
    let next = rec.without_publish(&publish).map_err(uncommitted)?;
    let mut write_error = None;
    if let Err(error) = write_member(&next) {
        // 書き込みの失敗が rename の前か後か判らない。読み直し、行が見えている（または確かめられない）間は予約を
        // 解放せず、次の再試行（印または墓標の経路）に委ねる。
        match guard.members() {
            Ok(ms)
                if ms
                    .iter()
                    .any(|m| m.id() == member_id && !m.has_publish(&publish)) =>
            {
                write_error = Some(error);
            }
            _ => return Err(uncommitted(error)),
        }
    }
    if let Err(error) = release_published_listener(registry, &published) {
        // 予約は残っている。ルール削除の確認済みを墓標として残す（書き戻しに失敗しても取り残しの向きで安全）。
        if let Ok(tomb) = rec.with_unpublished(&publish) {
            let _ = write_member(&tomb);
        }
        return Err(RecordedError::Op(Box::new(UnpublishPortError {
            error,
            rules: UnpublishRules::Removed,
            reservation_held: true,
            published: None,
        })));
    }
    match write_error {
        Some(error) => Err(uncommitted(error)),
        None => Ok(()),
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::time::Duration;

    use super::*;
    use crate::netlink_route::NetlinkRouteSocket;
    use crate::netns::ContainerNetns;
    use crate::network::delete::member_detach::reclaim_member;
    use crate::network::delete::{ContainerDetachError, NetworkDeleteError};
    use crate::network::unpublish::{linux_delete_rule, linux_delete_rules, linux_table_info};
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
        let host = nft.host_generation().map_err(RecordedError::Store)?;
        create_recorded_with(
            &host,
            guard,
            definition,
            spec.gateway(),
            |token| {
                create_network_with_token(
                    &LinuxNetworkOps {
                        route,
                        nft,
                        timeout,
                    },
                    spec,
                    token.to_owned(),
                )
            },
            |table| linux_table_info(nft, table, timeout),
        )
    }

    /// 記録から、メンバーの公開を [`PublishedPort`] として復元する（再起動後の経路。dump は使わない）。
    ///
    /// 復元した値は [`unpublish_port_recorded`] に渡す。契約は `restore_published_ports_recorded`。
    pub fn restore_published_ports(
        nft: &NetlinkNetfilterSocket,
        guard: &NetworkLockGuard<'_>,
        member_id: &MemberId,
    ) -> Result<Vec<PublishedPort>, NetError> {
        restore_published_ports_recorded(&nft.host_generation()?, guard, member_id)
    }

    /// 記録から、メンバーの墓標（ルールの削除を確かめ済みで予約が残る公開）を復元する（#3343）。
    ///
    /// 返した値は [`unpublish_port_recorded`] にだけ渡す（カーネル操作なしで予約の解放を完了する）。
    /// `detach_container_recorded` の前に片付ける。契約は `restore_unpublished_ports_recorded`。
    pub fn restore_unpublished_ports(
        nft: &NetlinkNetfilterSocket,
        guard: &NetworkLockGuard<'_>,
        member_id: &MemberId,
    ) -> Result<Vec<PublishedPort>, NetError> {
        restore_unpublished_ports_recorded(&nft.host_generation()?, guard, member_id)
    }

    /// 公開 1 件を記録つきで個別に解除する（`unpublish_container_port` の記録つき版。NET-3・#3068）。
    ///
    /// `published` は同じメンバーの記録から復元した値（または同じプロセスで attach した結果）に限る。
    /// 生きたテーブルのハンドルが記録と食い違えば DELRULE を送らず断る。`CAP_NET_ADMIN` は呼び出し側の責務。
    /// 失敗時の規則は `unpublish_port_recorded_with`。
    pub fn unpublish_port_recorded(
        nft: &NetlinkNetfilterSocket,
        guard: &NetworkLockGuard<'_>,
        member_id: &MemberId,
        published: PublishedPort,
        registry: &mut PortRegistry,
        timeout: Duration,
    ) -> Result<(), RecordedError<Box<UnpublishPortError>, ()>> {
        let host = nft.host_generation().map_err(RecordedError::Store)?;
        unpublish_port_recorded_with(
            &host,
            guard,
            member_id,
            published,
            registry,
            |table| linux_table_info(nft, table, timeout),
            |table, handles| linux_delete_rules(nft, timeout, table, handles),
            |table, chain, handle| linux_delete_rule(nft, timeout, table, chain, handle),
            |r| guard.replace_member(r),
        )
    }

    /// コンテナを接続して `members/<id>` に記録する（`attach_container` の記録つき版）。
    ///
    /// IPAM は記録から組み直すため、呼び出し側は `StaticIpam` を持たない。`ports` は呼び出し側の予約表
    /// （公開の記録は #3068）。`CAP_NET_ADMIN`・`CAP_SYS_ADMIN` は呼び出し側の責務。
    // 理由: 非記録版 `attach_container` と同じく、netlink の 2 本のソケット・ロードガード・要求 ID・仕様・DNS・
    // ポート予約表・期限は別の所有者のもので、まとめる型を作ると借用の寿命が呼び出し側へ漏れるため引数で受ける。
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
        let host = nft.host_generation().map_err(RecordedError::Store)?;
        attach_recorded_with(
            &host,
            guard,
            member_id,
            spec,
            dns,
            |table| linux_table_info(nft, table, timeout),
            |ipam, generation| {
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
            },
        )
    }

    /// コンテナを切り離して `members/<id>` を消す（`detach_container` の記録つき版）。
    ///
    /// 記録の検証で拒否した場合、渡した `container` は破棄される（netns の pin・veth・DNAT は残る）。外さない理由、
    /// 見分け方、`detach_member_recorded` での回収はモジュール doc「検証で拒否した `detach_container_recorded`」と
    /// `docs/setup/network-reclaim-recovery.md`。
    // 理由: 下位の `detach_container` の引数（ソケット 2 本・接続済みコンテナ・公開ポート・予約表・期限）に
    // ガードと ID を足した形で、所有者がばらばらの借用をまとめる型を作ると寿命が呼び出し側へ漏れるため引数で受ける。
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
        let (endpoint, host_token) = (container.endpoint.clone(), container.host_token.clone());
        let identity = ContainerIdentity {
            endpoint: &endpoint,
            address: container.address,
            host_token: &host_token,
        };
        let host = nft.host_generation().map_err(RecordedError::Store)?;
        detach_recorded_with(&host, guard, member_id, identity, |created, ipam| {
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

    /// 記録だけからメンバー 1 件を切り離して `members/<id>` を消す（再起動後の detach の入口。NET-1・NET-6・REPAIR-4・#3347）。
    ///
    /// 生きた `AttachedContainer` を取らない。`netns_dir` は接続時と同じ呼び出し側の固定設定で、記録の置き場と
    /// 一致しなければ断る。手順・関門・失敗時の規則は `detach_member_recorded_with`。`timeout` は切り離し全体の
    /// 1 つの期限（REPAIR-5）。`CAP_NET_ADMIN`・`CAP_SYS_ADMIN` は呼び出し側の責務。
    pub fn detach_member_recorded(
        route: &NetlinkRouteSocket,
        nft: &NetlinkNetfilterSocket,
        guard: &NetworkLockGuard<'_>,
        member_id: &MemberId,
        netns_dir: &Path,
        ports: &mut PortRegistry,
        timeout: Duration,
    ) -> Result<
        NetworkDeleteReport,
        RecordedError<Box<NetworkDeleteError<ContainerNetns>>, NetworkDeleteReport>,
    > {
        let host = nft.host_generation().map_err(RecordedError::Store)?;
        detach_member_recorded_with(&host, guard, member_id, netns_dir, ports, |claim, dir| {
            reclaim_member(route, nft, claim, dir, timeout).map_err(Box::new)
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
    detach_container_recorded, detach_member_recorded, restore_published_ports,
    restore_unpublished_ports, unpublish_port_recorded,
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
    use crate::network::{PortProtocol, PortPublish};
    use crate::network_store::NetworkStore;
    use crate::nftables_batch::NftTableHandle;
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
    /// 試験用の世代（呼び出したスレッドの現在値）。
    fn host() -> HostGeneration {
        HostGeneration::current().unwrap()
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
    /// テーブルハンドル 42 で `realized` を書く。
    fn realize(guard: &NetworkLockGuard<'_>) {
        realize_in(guard, HostGeneration::current().unwrap());
    }
    /// 世代を指定して `realized` を書く。
    fn realize_in(guard: &NetworkLockGuard<'_>, generation: HostGeneration) {
        guard
            .commit_realized(
                &RealizedRecord::from_created(
                    &created(),
                    pfx([10, 0, 0, 0], 24),
                    NftTableHandle::new(42).unwrap(),
                    generation,
                )
                .unwrap(),
            )
            .unwrap();
    }

    /// GETTABLE の応答の代役（handle 属性 4 と userdata 属性 6）。
    fn table_info_reply(handle: u64, userdata: &str) -> Result<TableInfo, NetError> {
        let mut p = vec![2u8, 0, 0, 0];
        for (ty, data) in [(4u16, &handle.to_be_bytes()[..]), (6, userdata.as_bytes())] {
            p.extend_from_slice(&((4 + data.len()) as u16).to_ne_bytes());
            p.extend_from_slice(&ty.to_ne_bytes());
            p.extend_from_slice(data);
            while p.len() % 4 != 0 {
                p.push(0);
            }
        }
        TableInfo::decode(&p)
    }
    /// 生きたテーブルのハンドルが `handle` で、所有トークンが一致する照会の代役。
    fn live_table(handle: u64) -> impl FnOnce(&NftName) -> Result<TableInfo, NetError> {
        move |_| table_info_reply(handle, BRIDGE_TOKEN)
    }
    fn spec(ep: &str) -> ContainerAttachSpec {
        ContainerAttachSpec::new(
            EndpointId::new(ep).unwrap(),
            &created(),
            PathBuf::from(NETNS_DIR),
        )
        .unwrap()
    }
    /// 記録済みメンバーと同じ同一性（detach の照合を通す側）。
    fn own(n: &NetworkLockGuard<'_>, id: &str) -> (EndpointId, IpPrefix, String) {
        let m = n
            .members()
            .unwrap()
            .into_iter()
            .find(|m| m.id().as_str() == id)
            .unwrap();
        (m.endpoint().clone(), m.address(), m.token().to_owned())
    }
    fn ident(o: &(EndpointId, IpPrefix, String)) -> ContainerIdentity<'_> {
        ContainerIdentity {
            endpoint: &o.0,
            address: o.1,
            host_token: &o.2,
        }
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
        let att = attach_recorded_with(
            &host(),
            &n,
            &mid("c1"),
            &s,
            &dns,
            live_table(42),
            ok_run(&s),
        )
        .unwrap();
        assert_eq!(att.address, pfx([10, 0, 0, 2], 24));
        let members = n.members().unwrap();
        assert_eq!(members.len(), 1);
        assert_eq!(members[0].address(), pfx([10, 0, 0, 2], 24));
        assert_eq!(members[0].endpoint().as_str(), "c1");
        assert_eq!(members[0].dns(), dns.as_slice());
        assert_eq!(members[0].token(), att.host_token);
        assert!(n.member_intents().unwrap().is_empty());
        // 二重の attach は拒否される。
        let again =
            attach_recorded_with(&host(), &n, &mid("c1"), &s, &[], live_table(42), ok_run(&s));
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
        let r = attach_recorded_with(
            &host(),
            &n,
            &mid("c1"),
            &s,
            &[],
            live_table(42),
            failing_run(&s, veth_leftover()),
        );
        assert!(matches!(r, Err(RecordedError::Op(_))));
        assert!(n.members().unwrap().is_empty());
        assert!(n.member_intents().unwrap().is_empty());
        let claims = n.reclaim_records().unwrap();
        assert_eq!(claims.attach.len(), 1);
        assert_eq!(claims.attach[0].endpoint().as_str(), "c1");
        assert!(claims.attach[0].includes_veth());
        // 取り残しが無い失敗は請求書を作らない。
        let s2 = spec("c2");
        let r = attach_recorded_with(
            &host(),
            &n,
            &mid("c2"),
            &s2,
            &[],
            live_table(42),
            failing_run(&s2, Vec::new()),
        );
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
        let _ = attach_recorded_with(
            &host(),
            &n,
            &mid("c1"),
            &s,
            &[],
            live_table(42),
            failing_run(&s, leftover),
        );
        assert_eq!(n.member_intents().unwrap().len(), 1);
        let s2 = spec("c2");
        let att = attach_recorded_with(
            &host(),
            &n,
            &mid("c2"),
            &s2,
            &[],
            live_table(42),
            ok_run(&s2),
        )
        .unwrap();
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
        let att =
            attach_recorded_with(&host(), &n, &mid("c2"), &s, &[], live_table(42), ok_run(&s))
                .unwrap();
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
        let r = attach_recorded_with(
            &host(),
            &n,
            &mid("c1"),
            &s,
            &[],
            live_table(42),
            |ipam, generation| {
                let mut att = ok_run(&s)(ipam, generation)?;
                att.address = pfx([10, 0, 0, 9], 24);
                Ok(att)
            },
        );
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
        attach_recorded_with(
            &host(),
            &n,
            &mid("c1"),
            &s1,
            &[],
            live_table(42),
            ok_run(&s1),
        )
        .unwrap();
        let s2 = spec("c2");
        attach_recorded_with(
            &host(),
            &n,
            &mid("c2"),
            &s2,
            &[],
            live_table(42),
            ok_run(&s2),
        )
        .unwrap();
        assert_eq!(n.rebuild_ipam().unwrap().allocated_count(), 2);
        let seen = std::cell::Cell::new(0usize);
        let o1 = own(&n, "c1");
        let r = detach_recorded_with::<Box<ContainerDetachErrorUnit>, _>(
            &host(),
            &n,
            &mid("c1"),
            ident(&o1),
            |_c, ipam: &mut StaticIpam| {
                seen.set(ipam.allocated_count());
                Ok(NetworkDeleteReport::default())
            },
        );
        assert!(r.is_ok());
        assert_eq!(seen.get(), 2, "run には組み直した IPAM が渡る");
        assert_eq!(n.members().unwrap().len(), 1);
        assert_eq!(n.rebuild_ipam().unwrap().allocated_count(), 1);
        let s3 = spec("c3");
        let att = attach_recorded_with(
            &host(),
            &n,
            &mid("c3"),
            &s3,
            &[],
            live_table(42),
            ok_run(&s3),
        )
        .unwrap();
        assert_eq!(att.address, pfx([10, 0, 0, 2], 24));
        // 記録に無いメンバーの detach は NotFound。
        let o3 = own(&n, "c3");
        let r = detach_recorded_with::<Box<ContainerDetachErrorUnit>, _>(
            &host(),
            &n,
            &mid("zz"),
            ident(&o3),
            |_c, _i| Ok(NetworkDeleteReport::default()),
        );
        assert_eq!(r.unwrap_err().store_code(), Some(NetErrorCode::NotFound));
    }

    /// NET-1・#3067: 別メンバーの同一性での detach はカーネル操作の前に拒否され、記録は残る。
    #[test]
    fn net1_3067_detach_rejects_foreign_container() {
        let t = Tmp::new("detach-foreign");
        let store = setup(&t);
        let g = store.lock_global_exclusive().unwrap();
        let n = g.lock_network(&name()).unwrap();
        realize(&n);
        let (s1, s2) = (spec("c1"), spec("c2"));
        attach_recorded_with(
            &host(),
            &n,
            &mid("c1"),
            &s1,
            &[],
            live_table(42),
            ok_run(&s1),
        )
        .unwrap();
        attach_recorded_with(
            &host(),
            &n,
            &mid("c2"),
            &s2,
            &[],
            live_table(42),
            ok_run(&s2),
        )
        .unwrap();
        let o2 = own(&n, "c2");
        let ran = std::cell::Cell::new(false);
        let r = detach_recorded_with::<Box<ContainerDetachErrorUnit>, _>(
            &host(),
            &n,
            &mid("c1"),
            ident(&o2),
            |_c, _i| {
                ran.set(true);
                Ok(NetworkDeleteReport::default())
            },
        );
        assert_eq!(
            r.unwrap_err().store_code(),
            Some(NetErrorCode::FailedPrecondition)
        );
        assert!(!ran.get(), "カーネル操作は始めない");
        assert_eq!(n.members().unwrap().len(), 2);
    }

    /// NET-1・#3067: 共有ガードでは detach / attach / delete をカーネル操作の前に拒否する。
    #[test]
    fn net1_3067_shared_guard_rejected_before_kernel_ops() {
        let t = Tmp::new("shared-guard");
        let store = setup(&t);
        {
            let g = store.lock_global_exclusive().unwrap();
            let n = g.lock_network(&name()).unwrap();
            realize(&n);
            let s1 = spec("c1");
            attach_recorded_with(
                &host(),
                &n,
                &mid("c1"),
                &s1,
                &[],
                live_table(42),
                ok_run(&s1),
            )
            .unwrap();
        }
        let g = store.lock_global_shared().unwrap();
        let n = g.lock_network_shared(&name()).unwrap();
        let o1 = own(&n, "c1");
        let ran = std::cell::Cell::new(false);
        let r = detach_recorded_with::<Box<ContainerDetachErrorUnit>, _>(
            &host(),
            &n,
            &mid("c1"),
            ident(&o1),
            |_c, _i| {
                ran.set(true);
                Ok(NetworkDeleteReport::default())
            },
        );
        assert_eq!(
            r.unwrap_err().store_code(),
            Some(NetErrorCode::FailedPrecondition)
        );
        let r = delete_recorded_with::<(), (), _>(&n, |_c, _i| {
            ran.set(true);
            Ok(())
        });
        assert_eq!(
            r.unwrap_err().store_code(),
            Some(NetErrorCode::FailedPrecondition)
        );
        assert!(!ran.get());
    }

    /// NET-1・#3067: gateway と同じ DNS・重複 DNS の attach は意図記録もカーネル操作も無しで拒否する。
    #[test]
    fn net1_3067_attach_rejects_bad_dns_before_intent() {
        let t = Tmp::new("attach-bad-dns");
        let store = setup(&t);
        let g = store.lock_global_exclusive().unwrap();
        let n = g.lock_network(&name()).unwrap();
        realize(&n);
        let s1 = spec("c1");
        let gw = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let ext = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        for dns in [vec![gw], vec![ext, ext]] {
            let r = attach_recorded_with::<(), _, _>(
                &host(),
                &n,
                &mid("c1"),
                &s1,
                &dns,
                live_table(42),
                |_i, _g| panic!("カーネル操作は始めない"),
            );
            assert_eq!(
                r.unwrap_err().store_code(),
                Some(NetErrorCode::InvalidArgument)
            );
            assert!(n.member_intents().unwrap().is_empty());
        }
    }

    /// NET-1・#3067: 回収待ちの請求書が残るネットワークは削除しない。
    #[test]
    fn net1_3067_delete_rejects_pending_reclaim() {
        let t = Tmp::new("delete-reclaim");
        let store = setup(&t);
        let g = store.lock_global_exclusive().unwrap();
        let n = g.lock_network(&name()).unwrap();
        realize(&n);
        let s1 = spec("c1");
        let r = attach_recorded_with(
            &host(),
            &n,
            &mid("c1"),
            &s1,
            &[],
            live_table(42),
            failing_run(&s1, veth_leftover()),
        );
        assert!(matches!(r, Err(RecordedError::Op(_))));
        assert!(!n.reclaim_records().unwrap().attach.is_empty());
        let r = delete_recorded_with::<(), (), _>(&n, |_c, _i| panic!("カーネル操作は始めない"));
        assert_eq!(
            r.unwrap_err().store_code(),
            Some(NetErrorCode::FailedPrecondition)
        );
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
        attach_recorded_with(
            &host(),
            &n,
            &mid("c1"),
            &s1,
            &[],
            live_table(42),
            ok_run(&s1),
        )
        .unwrap();
        let o1 = own(&n, "c1");
        let r = detach_recorded_with(&host(), &n, &mid("c1"), ident(&o1), |_c, _i| {
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
        let out = create_recorded_with(
            &host(),
            &n,
            &def(),
            pfx([10, 0, 0, 1], 24),
            |token| {
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
            },
            |_| table_info_reply(42, &seen.borrow()),
        )
        .unwrap();
        assert_eq!(out.bridge_token, *seen.borrow());
        let rec = n.realized().unwrap().unwrap();
        assert_eq!(
            rec.table_handle().get(),
            42,
            "作成直後に照会したハンドルを記録する"
        );
        assert_eq!(rec.gateway(), pfx([10, 0, 0, 1], 24));
        assert_eq!(rec.subnet(), pfx([10, 0, 0, 0], 24));
        assert_eq!(n.realized_intent().unwrap(), None);
        let again = create_recorded_with(
            &host(),
            &n,
            &def(),
            pfx([10, 0, 0, 1], 24),
            |_| Ok(created()),
            |_| table_info_reply(42, BRIDGE_TOKEN),
        );
        assert_eq!(
            again.unwrap_err().store_code(),
            Some(NetErrorCode::AlreadyExists)
        );
    }

    /// 保存済みの定義と方式・subnet が違う定義での create は、意図記録もカーネル操作も無しで拒否する（D10）。
    #[test]
    fn net1_3067_create_rejects_definition_differing_from_stored() {
        let t = Tmp::new("create-def-mismatch");
        let store = setup(&t);
        let g = store.lock_global_exclusive().unwrap();
        let n = g.lock_network(&name()).unwrap();
        let other_subnet = NetworkDefinition::bridge("web", pfx([10, 1, 0, 0], 24)).unwrap();
        let pasta = NetworkDefinition::pasta("web").unwrap();
        for d in [other_subnet, pasta] {
            let r = create_recorded_with(
                &host(),
                &n,
                &d,
                pfx([10, 1, 0, 1], 24),
                |_| panic!("カーネル操作は始めない"),
                |_| panic!("照会も始めない"),
            );
            assert_eq!(
                r.unwrap_err().store_code(),
                Some(NetErrorCode::FailedPrecondition)
            );
            assert_eq!(n.realized_intent().unwrap(), None);
        }
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
        let r = create_recorded_with(
            &host(),
            &n,
            &def(),
            pfx([10, 0, 0, 1], 24),
            |_| Err(create_err(leftover)),
            |_| panic!("失敗した作成では照会しない"),
        );
        assert!(matches!(r, Err(RecordedError::Op(_))));
        assert_eq!(n.realized().unwrap(), None);
        assert_eq!(n.realized_intent().unwrap(), None);
        let claim = n.reclaim_records().unwrap().create.unwrap();
        assert!(claim.includes_bridge());
        assert!(!claim.includes_table());
        // gateway が subnet の外なら、カーネル操作の前に拒否する。
        let r = create_recorded_with(
            &host(),
            &n,
            &def(),
            pfx([10, 9, 0, 1], 24),
            |_| panic!("must not run"),
            |_| panic!("must not run"),
        );
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
        let r = attach_recorded_with(&host(), &n, &mid("c1"), &s, &[], live_table(42), ok_run(&s));
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
        attach_recorded_with(&host(), &n, &mid("c1"), &s, &[], live_table(42), ok_run(&s)).unwrap();
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

    // ---- #3068: 公開ハンドルとテーブルハンドルの記録・再起動後の個別解除 ----

    fn rule(n: u64) -> NftRuleHandle {
        NftRuleHandle::new(n).unwrap()
    }

    fn web_publish() -> PortPublish {
        PortPublish::new(PortProtocol::Tcp, Ipv4Addr::new(192, 0, 2, 10), 8080, 80).unwrap()
    }

    /// 公開 1 件（handle 2・3）を返す attach の代役。
    fn run_with_publish(
        spec: &ContainerAttachSpec,
    ) -> impl FnOnce(&mut StaticIpam, &str) -> Result<AttachedContainer<()>, ContainerAttachError> + '_
    {
        move |ipam, generation| {
            let mut att = ok_run(spec)(ipam, generation)?;
            att.published_ports = vec![PublishedPort::new(
                &name(),
                BRIDGE_TOKEN,
                spec.endpoint(),
                web_publish(),
                (rule(2), rule(3)),
            )];
            Ok(att)
        }
    }

    /// 解除の試験の結果: (結果, DELRULE に渡った (table, pre, out), delete の回数)。
    type UnpubOut = (
        Result<(), RecordedError<Box<UnpublishPortError>, ()>>,
        Vec<String>,
        u32,
    );

    fn unpublish_with(
        n: &NetworkLockGuard<'_>,
        published: PublishedPort,
        reg: &mut PortRegistry,
        live_handle: u64,
    ) -> UnpubOut {
        let calls = std::cell::RefCell::new(Vec::new());
        let count = std::cell::Cell::new(0u32);
        let r = unpublish_port_recorded_with(
            &host(),
            n,
            &mid("c1"),
            published,
            reg,
            |_| table_info_reply(live_handle, BRIDGE_TOKEN),
            |t, (a, b)| {
                count.set(count.get() + 1);
                calls
                    .borrow_mut()
                    .push(format!("{} {} {}", t.as_str(), a.get(), b.get()));
                Ok(())
            },
            |_, _, _| unreachable!("delete_one must not be called"),
            |r| n.replace_member(r),
        );
        (r, calls.into_inner(), count.get())
    }

    /// 公開 1 件つきで attach し、ストアを閉じて開き直す（再起動の模擬）ための準備。
    fn attach_published(t: &Tmp) {
        let store = setup(t);
        let g = store.lock_global_exclusive().unwrap();
        let n = g.lock_network(&name()).unwrap();
        realize(&n);
        let s = spec("c1");
        let att = attach_recorded_with(
            &host(),
            &n,
            &mid("c1"),
            &s,
            &[],
            live_table(42),
            run_with_publish(&s),
        )
        .unwrap();
        // 同じプロセスで返す値にも、記録したテーブルハンドルが束縛される。
        assert_eq!(att.published_ports.len(), 1);
        assert_eq!(
            att.published_ports[0]
                .table_handle()
                .map(NftTableHandle::get),
            Some(42)
        );
        let m = n.members().unwrap();
        assert_eq!(m[0].table_handle().map(NftTableHandle::get), Some(42));
        assert_eq!(m[0].publishes().len(), 1);
        assert_eq!(m[0].publishes()[0].prerouting().get(), 2);
        assert_eq!(m[0].publishes()[0].output().get(), 3);
        assert_eq!(*m[0].publishes()[0].publish(), web_publish());
    }

    /// NET-3・#3068: create は作成直後に照会したテーブルハンドルを記録する。userdata が他者のもの・照会失敗なら
    /// `realized` を書かず `Uncommitted`（意図記録は残る）。
    #[test]
    fn net3_3068_create_requires_owned_table_handle() {
        for reply in [
            table_info_reply(42, "someone-else"),
            Err(NetError::new(NetErrorCode::Timeout, "slow")),
        ] {
            let t = Tmp::new("create-handle");
            let store = setup(&t);
            let g = store.lock_global_exclusive().unwrap();
            let n = g.lock_network(&name()).unwrap();
            let r = create_recorded_with(
                &host(),
                &n,
                &def(),
                pfx([10, 0, 0, 1], 24),
                |token| {
                    let mut c = created();
                    c.bridge_token = token.to_owned();
                    Ok(c)
                },
                |_| reply,
            );
            assert!(matches!(r, Err(RecordedError::Uncommitted { .. })));
            assert_eq!(n.realized().unwrap(), None);
            assert!(n.realized_intent().unwrap().is_some());
        }
    }

    /// NET-3・#3068: attach の成功で公開（受け口と rule handle 2 本）とテーブルハンドルがメンバー記録に載る。
    #[test]
    fn net3_3068_attach_records_publish_and_table_handle() {
        let t = Tmp::new("attach-publish");
        attach_published(&t);
    }

    /// NET-3・#3068（受け入れ条件 2）: 再起動を模して（ストアを開き直し）記録から公開を復元し、空の `PortRegistry` で
    /// 個別解除が成功する。DELRULE に記録した handle（2・3）が渡り、メンバー記録から公開が消える。
    #[test]
    fn net3_3068_restart_restore_then_unpublish_succeeds() {
        let t = Tmp::new("restart-ok");
        attach_published(&t);
        let store = NetworkStore::open(&t.0).unwrap();
        let g = store.lock_global_exclusive().unwrap();
        let n = g.lock_network(&name()).unwrap();
        let mut restored = restore_published_ports_recorded(&host(), &n, &mid("c1")).unwrap();
        assert_eq!(restored.len(), 1);
        let p = restored.remove(0);
        assert_eq!(p.table_handle().map(NftTableHandle::get), Some(42));
        assert_eq!(*p.publish(), web_publish());
        assert_eq!(p.endpoint().as_str(), "c1");
        let mut reg = PortRegistry::new();
        let (r, calls, count) = unpublish_with(&n, p, &mut reg, 42);
        r.unwrap();
        assert_eq!(count, 1);
        assert_eq!(calls, vec![format!("{} 2 3", created().table.as_str())]);
        // 空の予約表では解放が 0 件で、それでも成功する。記録からは公開とテーブルハンドルが消える。
        assert_eq!(reg.len(), 0);
        let m = n.members().unwrap();
        assert_eq!((m[0].table_handle(), m[0].publishes().len()), (None, 0));
        assert!(
            restore_published_ports_recorded(&host(), &n, &mid("c1"))
                .unwrap()
                .is_empty()
        );
    }

    /// NET-3・SEC-1・#3068（受け入れ条件 1）: 再起動後、テーブルが作り直されて生きたハンドルが 77 になっていれば、
    /// userdata が一致していても DELRULE を送らず `StaleHandles` で断り、メンバー記録は変わらない。
    #[test]
    fn net3_3068_restart_recreated_table_refuses_without_deleting() {
        let t = Tmp::new("restart-stale");
        attach_published(&t);
        let store = NetworkStore::open(&t.0).unwrap();
        let g = store.lock_global_exclusive().unwrap();
        let n = g.lock_network(&name()).unwrap();
        let before = std::fs::read(t.0.join("@networks/web/members/c1")).unwrap();
        let p = restore_published_ports_recorded(&host(), &n, &mid("c1"))
            .unwrap()
            .remove(0);
        let mut reg = PortRegistry::new();
        let (r, calls, count) = unpublish_with(&n, p, &mut reg, 77);
        assert_eq!(count, 0, "他者のルールを消さない");
        assert!(calls.is_empty());
        let Err(RecordedError::Op(e)) = r else {
            panic!("expected Op error");
        };
        assert_eq!(e.error.code(), NetErrorCode::FailedPrecondition);
        assert_eq!(e.rules, UnpublishRules::StaleHandles);
        assert!(e.published.is_some());
        let after = std::fs::read(t.0.join("@networks/web/members/c1")).unwrap();
        assert_eq!(before, after, "記録は書き換えない");
    }

    /// NET-3・SEC-1・#3068: テーブルが作り直されて生きたハンドルが記録と違うとき、attach はカーネル資源を作る前
    /// （`run` と意図記録の前）に断り、メンバー記録を書かない。
    #[test]
    fn net3_3068_attach_refuses_recreated_table_before_kernel_ops() {
        let t = Tmp::new("attach-stale-table");
        let store = setup(&t);
        let g = store.lock_global_exclusive().unwrap();
        let n = g.lock_network(&name()).unwrap();
        realize(&n);
        let s = spec("c1");
        let ran = std::cell::Cell::new(false);
        let r = attach_recorded_with::<(), _, _>(
            &host(),
            &n,
            &mid("c1"),
            &s,
            &[],
            live_table(77),
            |_, _| {
                ran.set(true);
                unreachable!("run must not be called")
            },
        );
        let Err(RecordedError::Store(e)) = r else {
            panic!("expected Store error");
        };
        assert_eq!(e.code(), NetErrorCode::FailedPrecondition);
        assert!(!ran.get());
        assert!(n.members().unwrap().is_empty());
        assert!(n.member_intents().unwrap().is_empty());
    }

    /// NET-3・SEC-1・#3068: 他者のテーブル（userdata 不一致）でも attach を断る。
    #[test]
    fn net3_3068_attach_refuses_foreign_table() {
        let t = Tmp::new("attach-foreign-table");
        let store = setup(&t);
        let g = store.lock_global_exclusive().unwrap();
        let n = g.lock_network(&name()).unwrap();
        realize(&n);
        let s = spec("c1");
        let r = attach_recorded_with::<(), _, _>(
            &host(),
            &n,
            &mid("c1"),
            &s,
            &[],
            |_| table_info_reply(42, "someone-else"),
            |_, _| unreachable!("run must not be called"),
        );
        assert!(matches!(r, Err(RecordedError::Store(_))));
        assert!(n.member_intents().unwrap().is_empty());
    }

    /// NET-3・REPAIR-1・#3068: DELRULE の成功後に記録の更新が済まないまま再起動した状態（意図の印が残り、ルールは
    /// 既に無い）から、DELRULE の ENOENT を許して記録の更新だけを再開できる。印の無い初回の ENOENT は断る。
    #[test]
    fn net3_3068_unpublish_recovers_after_delrule_succeeded_but_record_stale() {
        let t = Tmp::new("unpublish-recover");
        attach_published(&t);
        let store = NetworkStore::open(&t.0).unwrap();
        let g = store.lock_global_exclusive().unwrap();
        let n = g.lock_network(&name()).unwrap();
        let enoent = || NftApplyFailure {
            error: NetError::new(NetErrorCode::NotFound, "no such rule"),
            outcome: NftBatchOutcome::Aborted,
        };
        let run = |reg: &mut PortRegistry, fail: Option<NftApplyFailure>| {
            let p = restore_published_ports_recorded(&host(), &n, &mid("c1"))
                .unwrap()
                .remove(0);
            unpublish_port_recorded_with(
                &host(),
                &n,
                &mid("c1"),
                p,
                reg,
                |_| table_info_reply(42, BRIDGE_TOKEN),
                |_, _| fail.map_or(Ok(()), Err),
                // 1 本ずつの削除では 2 本とも既に無い（ENOENT）。
                |_, _, _| Err(enoent()),
                |r| n.replace_member(r),
            )
        };
        let mut reg = PortRegistry::new();
        // 初回: 印を書いてから DELRULE を送る。ENOENT は断り、公開と印が記録に残る。
        let Err(RecordedError::Op(e)) = run(&mut reg, Some(enoent())) else {
            panic!("expected Op error");
        };
        assert_eq!(e.error.code(), NetErrorCode::NotFound);
        assert_eq!(e.rules, UnpublishRules::Present);
        let m = n.members().unwrap();
        assert_eq!(m[0].publishes().len(), 1);
        assert!(m[0].is_unpublishing(&web_publish()));
        // 再起動後の再試行: 印があるので ENOENT でも記録の更新だけが進む。
        run(&mut reg, Some(enoent())).unwrap();
        let m = n.members().unwrap();
        assert_eq!((m[0].table_handle(), m[0].publishes().len()), (None, 0));
    }

    /// NET-3・REPAIR-1・#3068: 印があっても、ENOENT 以外の失敗（結果不明など）は成功扱いにしない。
    #[test]
    fn net3_3068_unpublish_marked_non_enoent_failure_stays_refused() {
        let t = Tmp::new("unpublish-marked-fail");
        attach_published(&t);
        let store = NetworkStore::open(&t.0).unwrap();
        let g = store.lock_global_exclusive().unwrap();
        let n = g.lock_network(&name()).unwrap();
        let rec = n.members().unwrap().remove(0);
        n.replace_member(&rec.with_unpublishing(&web_publish()).unwrap())
            .unwrap();
        let p = restore_published_ports_recorded(&host(), &n, &mid("c1"))
            .unwrap()
            .remove(0);
        let mut reg = PortRegistry::new();
        let r = unpublish_port_recorded_with(
            &host(),
            &n,
            &mid("c1"),
            p,
            &mut reg,
            |_| table_info_reply(42, BRIDGE_TOKEN),
            |_, _| {
                Err(NftApplyFailure {
                    error: NetError::new(NetErrorCode::Internal, "timeout"),
                    outcome: NftBatchOutcome::Unknown,
                })
            },
            |_, _, _| unreachable!("delete_one must not be called"),
            |r| n.replace_member(r),
        );
        let Err(RecordedError::Op(e)) = r else {
            panic!("expected Op error");
        };
        assert_eq!(e.rules, UnpublishRules::Unknown);
        assert_eq!(n.members().unwrap()[0].publishes().len(), 1);
    }

    /// NET-3・SEC-1・#3068: 印があり一括削除が ENOENT で中止されても、片方のルールだけが残っていればそれを 1 本ずつ
    /// 確実に消す。残りの削除が失敗すれば記録（公開と印）を保ち、成功なら記録を更新する。
    #[test]
    fn net3_3068_unpublish_marked_enoent_deletes_remaining_rule_individually() {
        let t = Tmp::new("unpublish-partial");
        attach_published(&t);
        let store = NetworkStore::open(&t.0).unwrap();
        let g = store.lock_global_exclusive().unwrap();
        let n = g.lock_network(&name()).unwrap();
        let rec = n.members().unwrap().remove(0);
        n.replace_member(&rec.with_unpublishing(&web_publish()).unwrap())
            .unwrap();
        let enoent = || NftApplyFailure {
            error: NetError::new(NetErrorCode::NotFound, "no such rule"),
            outcome: NftBatchOutcome::Aborted,
        };
        let run = |one_out: Result<(), NftApplyFailure>| {
            let p = restore_published_ports_recorded(&host(), &n, &mid("c1"))
                .unwrap()
                .remove(0);
            let calls = std::cell::RefCell::new(Vec::new());
            let r = unpublish_port_recorded_with(
                &host(),
                &n,
                &mid("c1"),
                p,
                &mut PortRegistry::new(),
                |_| table_info_reply(42, BRIDGE_TOKEN),
                |_, _| Err(enoent()),
                |_, chain, h| {
                    calls.borrow_mut().push(format!("{chain} {}", h.get()));
                    if chain == "prerouting" {
                        Err(enoent())
                    } else {
                        one_out.clone()
                    }
                },
                |r| n.replace_member(r),
            );
            (r, calls.into_inner())
        };
        // 残った output の削除が失敗: 記録と印を保ち、予約も保つ。
        let (r, calls) = run(Err(NftApplyFailure {
            error: NetError::new(NetErrorCode::Internal, "timeout"),
            outcome: NftBatchOutcome::Unknown,
        }));
        assert!(matches!(r, Err(RecordedError::Op(_))));
        assert_eq!(calls, ["prerouting 2", "output 3"]);
        let m = n.members().unwrap();
        assert_eq!(m[0].publishes().len(), 1);
        assert!(m[0].is_unpublishing(&web_publish()));
        // output の削除が成功: 記録から公開が外れる。
        let (r, _) = run(Ok(()));
        r.unwrap();
        assert_eq!(n.members().unwrap()[0].publishes().len(), 0);
    }

    /// NET-3・SEC-1・#3068: 記録に無い公開は、予約があっても解除済みとは証明できないので、DELRULE も予約の解放もせず
    /// 断る（recorded attach 後の追加公開や古い値での再試行が、別の公開の予約を外さない）。
    #[test]
    fn net3_3068_unpublish_not_in_record_keeps_reservation() {
        let t = Tmp::new("unpublish-rewritten");
        attach_published(&t);
        let store = NetworkStore::open(&t.0).unwrap();
        let g = store.lock_global_exclusive().unwrap();
        let n = g.lock_network(&name()).unwrap();
        let p = restore_published_ports_recorded(&host(), &n, &mid("c1"))
            .unwrap()
            .remove(0);
        let rec = n.members().unwrap().remove(0);
        n.replace_member(&rec.without_publish(&web_publish()).unwrap())
            .unwrap();
        let mut reg = PortRegistry::new();
        reg.reserve(&name(), p.endpoint(), &[*p.publish()]).unwrap();
        let r = unpublish_port_recorded_with(
            &host(),
            &n,
            &mid("c1"),
            p,
            &mut reg,
            |_| unreachable!("table_info must not be called"),
            |_, _| unreachable!("delete must not be called"),
            |_, _, _| unreachable!("delete_one must not be called"),
            |r| n.replace_member(r),
        );
        let Err(RecordedError::Op(e)) = r else {
            panic!("expected Op error");
        };
        assert_eq!(e.error.code(), NetErrorCode::FailedPrecondition);
        assert!(e.reservation_held && e.published.is_some());
        // 予約は 1 件のまま残る。
        assert_eq!(reg.held_by(&name(), &EndpointId::new("c1").unwrap()), Ok(1));
    }

    /// NET-3・SEC-1・#3068: 別の boot ID・network namespace の世代で採ったハンドルの記録は、復元・解除・attach の
    /// いずれもカーネル操作の前に FailedPrecondition で断る（再起動後にハンドルが偶然一致しても別のルールを消さない）。
    #[test]
    fn net3_3068_foreign_generation_refused_before_kernel_ops() {
        let t = Tmp::new("foreign-generation");
        let store = setup(&t);
        let g = store.lock_global_exclusive().unwrap();
        let n = g.lock_network(&name()).unwrap();
        let now = HostGeneration::current().unwrap();
        let other_boot = HostGeneration::new(
            "ffffffff-ffff-ffff-ffff-ffffffffffff",
            crate::network_store::NetnsIdentity::new(5, 1),
        )
        .unwrap();
        assert_ne!(now, other_boot);
        realize_in(&n, other_boot);
        let msg = "recorded nft handles belong to another boot or network namespace";
        let r = restore_published_ports_recorded(&host(), &n, &mid("c1"));
        assert_eq!(r.unwrap_err().message(), msg);
        let p = PublishedPort::new(
            &name(),
            BRIDGE_TOKEN,
            &EndpointId::new("c1").unwrap(),
            web_publish(),
            (rule(2), rule(3)),
        )
        .with_table_handle(NftTableHandle::new(42).unwrap());
        let mut reg = PortRegistry::new();
        let r = unpublish_port_recorded_with(
            &host(),
            &n,
            &mid("c1"),
            p,
            &mut reg,
            |_| unreachable!("table_info must not be called"),
            |_, _| unreachable!("delete must not be called"),
            |_, _, _| unreachable!("delete_one must not be called"),
            |r| n.replace_member(r),
        );
        let Err(RecordedError::Store(e)) = r else {
            panic!("expected Store error");
        };
        assert_eq!(e.code(), NetErrorCode::FailedPrecondition);
        assert_eq!(e.message(), msg);
        let s = spec("c1");
        let r = attach_recorded_with(
            &host(),
            &n,
            &mid("c1"),
            &s,
            &[],
            live_table(42),
            run_with_publish(&s),
        );
        assert!(matches!(r, Err(RecordedError::Store(ref e)) if e.message() == msg));
        // 拒否は意図記録の前: メンバー記録は作られない。
        assert!(n.members().unwrap().is_empty());
    }

    /// NET-3・SEC-1・#3068: 世代の照合は、呼び出し側が渡す（操作対象のソケットの）世代と行う。boot ID が同じでも
    /// network namespace の同一性が違えば、プロセス既定の値が記録と一致していても断る。
    #[test]
    fn net3_3068_same_boot_other_netns_refused() {
        let t = Tmp::new("other-netns");
        let store = setup(&t);
        let g = store.lock_global_exclusive().unwrap();
        let n = g.lock_network(&name()).unwrap();
        // 記録はこのスレッドの現在値で書く。
        realize(&n);
        let cur = host();
        assert!(
            restore_published_ports_recorded(&cur, &n, &mid("c1"))
                .is_err_and(|e| e.code() == NetErrorCode::NotFound)
        );
        let other = HostGeneration::new(
            cur.boot_id(),
            crate::network_store::NetnsIdentity::new(
                cur.netns().dev().wrapping_add(1),
                cur.netns().ino(),
            ),
        )
        .unwrap();
        let e = restore_published_ports_recorded(&other, &n, &mid("c1")).unwrap_err();
        assert_eq!(e.code(), NetErrorCode::FailedPrecondition);
        assert_eq!(
            e.message(),
            "recorded nft handles belong to another boot or network namespace"
        );
    }

    /// NET-3・SEC-1・#3068: 記録と一致しない公開（テーブルハンドル違い・受け口違い）は、カーネル操作の前に断る。
    #[test]
    fn net3_3068_unpublish_rejects_port_not_in_record() {
        let t = Tmp::new("unpublish-mismatch");
        attach_published(&t);
        let store = NetworkStore::open(&t.0).unwrap();
        let g = store.lock_global_exclusive().unwrap();
        let n = g.lock_network(&name()).unwrap();
        let good = restore_published_ports_recorded(&host(), &n, &mid("c1"))
            .unwrap()
            .remove(0);
        let other_handle = PublishedPort::new(
            &name(),
            BRIDGE_TOKEN,
            good.endpoint(),
            *good.publish(),
            (good.prerouting_handle(), good.output_handle()),
        )
        .with_table_handle(NftTableHandle::new(41).unwrap());
        let other_port = PublishedPort::new(
            &name(),
            BRIDGE_TOKEN,
            good.endpoint(),
            PortPublish::new(PortProtocol::Tcp, Ipv4Addr::new(192, 0, 2, 10), 9090, 80).unwrap(),
            (rule(2), rule(3)),
        )
        .with_table_handle(NftTableHandle::new(42).unwrap());
        let unbound = PublishedPort::new(
            &name(),
            BRIDGE_TOKEN,
            good.endpoint(),
            *good.publish(),
            (rule(2), rule(3)),
        );
        for p in [other_handle, other_port, unbound] {
            let mut reg = PortRegistry::new();
            let (r, _, count) = unpublish_with(&n, p, &mut reg, 42);
            assert_eq!(count, 0);
            let Err(RecordedError::Op(e)) = r else {
                panic!("expected Op error");
            };
            assert_eq!(e.error.code(), NetErrorCode::FailedPrecondition);
            assert!(e.reservation_held && e.published.is_some());
        }
        assert_eq!(n.members().unwrap()[0].publishes().len(), 1);
    }

    /// NET-3・SEC-1・#3068: 別ネットワークのトークンを持つメンバー記録は、復元も解除も DataLoss で断り、
    /// DELRULE を送らず記録も変えない。
    #[test]
    fn net3_3068_foreign_token_record_refused_on_restore_and_unpublish() {
        let t = Tmp::new("foreign-token");
        attach_published(&t);
        let store = NetworkStore::open(&t.0).unwrap();
        let g = store.lock_global_exclusive().unwrap();
        let n = g.lock_network(&name()).unwrap();
        let good = restore_published_ports_recorded(&host(), &n, &mid("c1"))
            .unwrap()
            .remove(0);
        let path = t.0.join("@networks/web/members/c1");
        let bytes = std::fs::read(&path).unwrap();
        let alt: String = BRIDGE_TOKEN
            .chars()
            .map(|c| if c == 'a' { 'b' } else { 'a' })
            .collect();
        assert_ne!(alt, BRIDGE_TOKEN);
        let mut text = String::from_utf8(bytes).unwrap();
        text = text.replace(BRIDGE_TOKEN, &alt);
        std::fs::write(&path, text.as_bytes()).unwrap();
        let before = std::fs::read(&path).unwrap();
        let e = restore_published_ports_recorded(&host(), &n, &mid("c1")).unwrap_err();
        assert_eq!(e.code(), NetErrorCode::DataLoss);
        let mut reg = PortRegistry::new();
        let (r, calls, count) = unpublish_with(&n, good, &mut reg, 42);
        assert_eq!(count, 0, "他者のルールを消さない");
        assert!(calls.is_empty());
        let Err(RecordedError::Store(e)) = r else {
            panic!("expected Store error");
        };
        assert_eq!(e.code(), NetErrorCode::DataLoss);
        assert_eq!(before, std::fs::read(&path).unwrap());
    }

    /// NET-3・#3068: 共有ロックのガードでは解除せず（カーネル操作の前に拒否）、復元（読み取り）はできる。
    #[test]
    fn net3_3068_shared_guard_restores_but_cannot_unpublish() {
        let t = Tmp::new("unpublish-shared");
        attach_published(&t);
        let store = NetworkStore::open(&t.0).unwrap();
        let g = store.lock_global_shared().unwrap();
        let n = g.lock_network_shared(&name()).unwrap();
        let p = restore_published_ports_recorded(&host(), &n, &mid("c1"))
            .unwrap()
            .remove(0);
        let mut reg = PortRegistry::new();
        let (r, _, count) = unpublish_with(&n, p, &mut reg, 42);
        assert_eq!(count, 0);
        assert_eq!(
            r.unwrap_err().store_code(),
            Some(NetErrorCode::FailedPrecondition)
        );
        assert_eq!(
            restore_published_ports_recorded(&host(), &n, &mid("zz"))
                .unwrap_err()
                .code(),
            NetErrorCode::NotFound
        );
    }
    // ---- #3343: 解除済みを示す墓標（`unpublished` 印）と、記録を先に書いて予約を後に解放する順序 ----

    use crate::network_store::MemberRecord;

    type TombOut = (Result<(), RecordedError<Box<UnpublishPortError>, ()>>, u32);

    /// 記録つきの解除を、カーネル操作の回数を数え `write_member` を差し込んで実行する。
    /// `forbid_kernel` が真なら照会・削除の呼び出しで panic する（墓標の経路はカーネル操作をしない）。
    fn unpublish_writing(
        n: &NetworkLockGuard<'_>,
        host: &HostGeneration,
        published: PublishedPort,
        reg: &mut PortRegistry,
        forbid_kernel: bool,
        write: impl FnMut(&MemberRecord) -> Result<(), NetError>,
    ) -> TombOut {
        let count = std::cell::Cell::new(0u32);
        let enoent = || NftApplyFailure {
            error: NetError::new(NetErrorCode::NotFound, "no such rule"),
            outcome: NftBatchOutcome::Aborted,
        };
        let r = unpublish_port_recorded_with(
            host,
            n,
            &mid("c1"),
            published,
            reg,
            |_| {
                assert!(!forbid_kernel, "table_info must not be called");
                table_info_reply(42, BRIDGE_TOKEN)
            },
            |_, _| {
                assert!(!forbid_kernel, "delete must not be called");
                count.set(count.get() + 1);
                Ok(())
            },
            |_, _, _| {
                assert!(!forbid_kernel, "delete_one must not be called");
                count.set(count.get() + 1);
                Err(enoent())
            },
            write,
        );
        (r, count.get())
    }

    fn held(reg: &mut PortRegistry) -> usize {
        reg.held_by(&name(), &EndpointId::new("c1").unwrap())
            .unwrap()
    }

    /// 共有ファイルの予約表（予約済み）と、その正しい内容・壊した内容を返す。
    fn shared_reg(t: &Tmp) -> (PortRegistry, PathBuf, Vec<u8>) {
        let path = t.0.join("ports.reg");
        let mut reg = PortRegistry::with_shared_file(path.clone());
        reg.reserve(&name(), &EndpointId::new("c1").unwrap(), &[web_publish()])
            .unwrap();
        let good = std::fs::read(&path).unwrap();
        (reg, path, good)
    }

    /// 予約の解放を失敗させ（共有ファイルを壊す）、墓標を残した状態にする。再試行用の復元値と共有ファイルの正しい内容を返す。
    fn leave_tombstone(t: &Tmp) -> (PortRegistry, PathBuf, Vec<u8>, Vec<PublishedPort>) {
        attach_published(t);
        let store = NetworkStore::open(&t.0).unwrap();
        let g = store.lock_global_exclusive().unwrap();
        let n = g.lock_network(&name()).unwrap();
        let (mut reg, path, good) = shared_reg(t);
        let retry = restore_published_ports_recorded(&host(), &n, &mid("c1")).unwrap();
        let p = restore_published_ports_recorded(&host(), &n, &mid("c1"))
            .unwrap()
            .remove(0);
        std::fs::write(&path, b"garbage\n").unwrap();
        let (r, count) =
            unpublish_writing(&n, &host(), p, &mut reg, false, |r| n.replace_member(r));
        assert_eq!(count, 1);
        let Err(RecordedError::Op(e)) = r else {
            panic!("expected Op error");
        };
        assert_eq!(e.rules, UnpublishRules::Removed);
        assert!(e.reservation_held && e.published.is_none());
        std::fs::write(&path, &good).unwrap();
        (reg, path, good, retry)
    }

    /// NET-3・SEC-1・#3343: DELRULE の成功後に予約の解放が失敗しても、墓標が永続化され、復元は墓標を
    /// 通常の公開として返さない（detach に渡すと消えたルールへ DELRULE するため）。
    #[test]
    fn net3_3343_release_failure_leaves_tombstone_and_keeps_reservation() {
        let t = Tmp::new("tomb-leave");
        let (mut reg, _path, _good, _retry) = leave_tombstone(&t);
        let store = NetworkStore::open(&t.0).unwrap();
        let g = store.lock_global_exclusive().unwrap();
        let n = g.lock_network(&name()).unwrap();
        let m = n.members().unwrap();
        assert_eq!(m[0].publishes().len(), 1);
        assert!(m[0].is_unpublished(&web_publish()));
        assert!(!m[0].is_unpublishing(&web_publish()));
        assert!(
            restore_published_ports_recorded(&host(), &n, &mid("c1"))
                .unwrap()
                .is_empty()
        );
        let tomb = restore_unpublished_ports_recorded(&host(), &n, &mid("c1")).unwrap();
        assert_eq!(tomb.len(), 1);
        assert_eq!(
            (
                tomb[0].prerouting_handle().get(),
                tomb[0].output_handle().get(),
                tomb[0].table_handle().map(NftTableHandle::get)
            ),
            (2, 3, Some(42))
        );
        assert_eq!(held(&mut reg), 1);
    }

    /// NET-3・SEC-1・#3343: 墓標と完全に一致する値での再試行は、カーネル操作をせずに予約を解放して完了する。
    #[test]
    fn net3_3343_tombstone_retry_releases_without_kernel_ops() {
        let t = Tmp::new("tomb-retry");
        let (mut reg, _path, _good, mut retry) = leave_tombstone(&t);
        let store = NetworkStore::open(&t.0).unwrap();
        let g = store.lock_global_exclusive().unwrap();
        let n = g.lock_network(&name()).unwrap();
        assert_eq!(held(&mut reg), 1);
        let tomb = restore_unpublished_ports_recorded(&host(), &n, &mid("c1"))
            .unwrap()
            .remove(0);
        let (r, count) =
            unpublish_writing(&n, &host(), tomb, &mut reg, true, |r| n.replace_member(r));
        r.unwrap();
        assert_eq!(count, 0);
        assert_eq!(held(&mut reg), 0);
        let m = n.members().unwrap();
        assert_eq!((m[0].table_handle(), m[0].publishes().len()), (None, 0));
        // 通常の公開として復元した値（記録の外れた古い値）は断る。
        let stale = retry.remove(0);
        let (r, count) =
            unpublish_writing(&n, &host(), stale, &mut reg, true, |r| n.replace_member(r));
        assert_eq!(count, 0);
        assert!(matches!(r, Err(RecordedError::Op(_))));
    }

    /// NET-3・SEC-1・#3343: 墓標と一致しない値（別の rule handle・別のテーブルハンドル・別の受け口）は、
    /// 記録も予約も変えず `FailedPrecondition` で断る。
    #[test]
    fn net3_3343_tombstone_mismatch_refused_keeps_reservation() {
        let t = Tmp::new("tomb-mismatch");
        let (mut reg, _path, _good, _retry) = leave_tombstone(&t);
        let store = NetworkStore::open(&t.0).unwrap();
        let g = store.lock_global_exclusive().unwrap();
        let n = g.lock_network(&name()).unwrap();
        let before = n.members().unwrap();
        let other_listener =
            PortPublish::new(PortProtocol::Tcp, Ipv4Addr::new(192, 0, 2, 10), 9090, 80).unwrap();
        let mk = |publish: PortPublish, h: (u64, u64), table: u64| {
            PublishedPort::new(
                &name(),
                BRIDGE_TOKEN,
                &EndpointId::new("c1").unwrap(),
                publish,
                (rule(h.0), rule(h.1)),
            )
            .with_table_handle(NftTableHandle::new(table).unwrap())
        };
        for p in [
            mk(web_publish(), (2, 9), 42),
            mk(web_publish(), (9, 3), 42),
            mk(web_publish(), (2, 3), 43),
            mk(other_listener, (2, 3), 42),
        ] {
            let (r, count) =
                unpublish_writing(&n, &host(), p, &mut reg, true, |r| n.replace_member(r));
            assert_eq!(count, 0);
            let Err(RecordedError::Op(e)) = r else {
                panic!("expected Op error");
            };
            assert_eq!(e.error.code(), NetErrorCode::FailedPrecondition);
            assert!(e.reservation_held);
            assert_eq!(n.members().unwrap(), before);
            assert_eq!(held(&mut reg), 1);
        }
    }

    /// NET-3・SEC-1・#3343: 行を外す書き込みが rename の前に失敗したら予約を解放せず `Uncommitted`。記録は印のまま残り、
    /// その後の再試行（印の経路）で完了する。
    #[test]
    fn net3_3343_removal_write_failed_before_rename_keeps_reservation() {
        let t = Tmp::new("removal-before-rename");
        attach_published(&t);
        let store = NetworkStore::open(&t.0).unwrap();
        let g = store.lock_global_exclusive().unwrap();
        let n = g.lock_network(&name()).unwrap();
        let mut reg = PortRegistry::new();
        reg.reserve(&name(), &EndpointId::new("c1").unwrap(), &[web_publish()])
            .unwrap();
        let p = restore_published_ports_recorded(&host(), &n, &mid("c1"))
            .unwrap()
            .remove(0);
        let calls = std::cell::Cell::new(0u32);
        let (r, count) = unpublish_writing(&n, &host(), p, &mut reg, false, |r| {
            calls.set(calls.get() + 1);
            if calls.get() == 1 {
                n.replace_member(r)
            } else {
                Err(NetError::new(NetErrorCode::Internal, "write failed"))
            }
        });
        assert_eq!(count, 1);
        assert!(matches!(r, Err(RecordedError::Uncommitted { .. })));
        assert_eq!(held(&mut reg), 1);
        let m = n.members().unwrap();
        assert!(m[0].is_unpublishing(&web_publish()));
        // 再試行: 印の経路（一括削除は ENOENT、1 本ずつの削除も ENOENT）。
        let enoent = || NftApplyFailure {
            error: NetError::new(NetErrorCode::NotFound, "no such rule"),
            outcome: NftBatchOutcome::Aborted,
        };
        let p = restore_published_ports_recorded(&host(), &n, &mid("c1"))
            .unwrap()
            .remove(0);
        unpublish_port_recorded_with(
            &host(),
            &n,
            &mid("c1"),
            p,
            &mut reg,
            |_| table_info_reply(42, BRIDGE_TOKEN),
            |_, _| Err(enoent()),
            |_, _, _| Err(enoent()),
            |r| n.replace_member(r),
        )
        .unwrap();
        assert_eq!(held(&mut reg), 0);
        assert_eq!(n.members().unwrap()[0].publishes().len(), 0);
    }

    /// NET-3・SEC-1・#3343: 行を外す書き込みが rename の後に失敗した（行は消えている）なら、予約は解放し、
    /// 永続化を確認できていないので `Uncommitted` を返す。
    #[test]
    fn net3_3343_removal_renamed_then_failed_releases_and_reports_uncommitted() {
        let t = Tmp::new("removal-after-rename");
        attach_published(&t);
        let store = NetworkStore::open(&t.0).unwrap();
        let g = store.lock_global_exclusive().unwrap();
        let n = g.lock_network(&name()).unwrap();
        let mut reg = PortRegistry::new();
        reg.reserve(&name(), &EndpointId::new("c1").unwrap(), &[web_publish()])
            .unwrap();
        let p = restore_published_ports_recorded(&host(), &n, &mid("c1"))
            .unwrap()
            .remove(0);
        let calls = std::cell::Cell::new(0u32);
        let (r, _) = unpublish_writing(&n, &host(), p, &mut reg, false, |r| {
            calls.set(calls.get() + 1);
            n.replace_member(r)?;
            if calls.get() == 2 {
                Err(NetError::new(NetErrorCode::Internal, "fsync failed"))
            } else {
                Ok(())
            }
        });
        assert!(matches!(r, Err(RecordedError::Uncommitted { .. })));
        assert_eq!(held(&mut reg), 0);
        assert_eq!(n.members().unwrap()[0].publishes().len(), 0);
    }

    /// NET-3・SEC-1・#3343: 予約の解放も墓標の書き戻しも失敗したら、記録に行は無く予約が残る（取り残しの向き）。
    /// その後の再試行は記録に無い値として断り、予約を外さない。
    #[test]
    fn net3_3343_tombstone_writeback_failure_keeps_reservation_fail_closed() {
        let t = Tmp::new("tomb-writeback-fail");
        attach_published(&t);
        let store = NetworkStore::open(&t.0).unwrap();
        let g = store.lock_global_exclusive().unwrap();
        let n = g.lock_network(&name()).unwrap();
        let (mut reg, path, good) = shared_reg(&t);
        let p = restore_published_ports_recorded(&host(), &n, &mid("c1"))
            .unwrap()
            .remove(0);
        let again = restore_published_ports_recorded(&host(), &n, &mid("c1"))
            .unwrap()
            .remove(0);
        std::fs::write(&path, b"garbage\n").unwrap();
        let calls = std::cell::Cell::new(0u32);
        let (r, _) = unpublish_writing(&n, &host(), p, &mut reg, false, |r| {
            calls.set(calls.get() + 1);
            if calls.get() <= 2 {
                n.replace_member(r)
            } else {
                Err(NetError::new(NetErrorCode::Internal, "write failed"))
            }
        });
        let Err(RecordedError::Op(e)) = r else {
            panic!("expected Op error");
        };
        assert_eq!(
            (e.rules, e.reservation_held),
            (UnpublishRules::Removed, true)
        );
        assert_eq!(n.members().unwrap()[0].publishes().len(), 0);
        std::fs::write(&path, &good).unwrap();
        assert_eq!(held(&mut reg), 1);
        let (r, count) =
            unpublish_writing(&n, &host(), again, &mut reg, true, |r| n.replace_member(r));
        assert_eq!(count, 0);
        let Err(RecordedError::Op(e)) = r else {
            panic!("expected Op error");
        };
        assert_eq!(e.error.code(), NetErrorCode::FailedPrecondition);
        assert_eq!(held(&mut reg), 1);
    }

    /// NET-3・SEC-1・#3343: 別の世代で見た墓標は、カーネル操作も予約の解放もせずに断る。
    #[test]
    fn net3_3343_tombstone_foreign_generation_refused() {
        let t = Tmp::new("tomb-foreign-gen");
        let (mut reg, _path, _good, _retry) = leave_tombstone(&t);
        let store = NetworkStore::open(&t.0).unwrap();
        let g = store.lock_global_exclusive().unwrap();
        let n = g.lock_network(&name()).unwrap();
        let tomb = restore_unpublished_ports_recorded(&host(), &n, &mid("c1"))
            .unwrap()
            .remove(0);
        let other = HostGeneration::new(
            "ffffffff-ffff-ffff-ffff-ffffffffffff",
            crate::network_store::NetnsIdentity::new(5, 1),
        )
        .unwrap();
        assert!(restore_unpublished_ports_recorded(&other, &n, &mid("c1")).is_err());
        let (r, count) =
            unpublish_writing(&n, &other, tomb, &mut reg, true, |r| n.replace_member(r));
        assert_eq!(count, 0);
        let Err(RecordedError::Store(e)) = r else {
            panic!("expected Store error");
        };
        assert_eq!(e.code(), NetErrorCode::FailedPrecondition);
        assert_eq!(held(&mut reg), 1);
        assert!(n.members().unwrap()[0].is_unpublished(&web_publish()));
    }

    /// NET-3・SEC-1・#3343: `published_ports` は墓標を返さず、`unpublished_ports` は墓標だけを返す（handle・テーブルハンドルは
    /// 記録の値）。最後の墓標を外すと `table-handle` も外れる。
    #[test]
    fn net3_3343_member_published_ports_excludes_tombstone() {
        let t = Tmp::new("tomb-member-ports");
        attach_published(&t);
        let store = NetworkStore::open(&t.0).unwrap();
        let g = store.lock_global_exclusive().unwrap();
        let n = g.lock_network(&name()).unwrap();
        let realized = settled_realized(&n).unwrap();
        let rec = n.members().unwrap().remove(0);
        assert_eq!(rec.published_ports(&realized).len(), 1);
        assert!(rec.unpublished_ports(&realized).is_empty());
        let tomb = rec.with_unpublished(&web_publish()).unwrap();
        assert!(tomb.published_ports(&realized).is_empty());
        let ports = tomb.unpublished_ports(&realized);
        assert_eq!(ports.len(), 1);
        assert_eq!(
            (
                ports[0].prerouting_handle().get(),
                ports[0].output_handle().get(),
                ports[0].table_handle().map(NftTableHandle::get)
            ),
            (2, 3, Some(42))
        );
        let gone = tomb.without_publish(&web_publish()).unwrap();
        assert_eq!((gone.table_handle(), gone.publishes().len()), (None, 0));
    }

    const PIN: crate::network::attach_claim::PinIdentity =
        crate::network::attach_claim::PinIdentity {
            dev: 8,
            ino: 9,
            serial: 77,
        };

    /// 公開 1 件と pin の識別子を返す attach の代役（#3347）。
    fn run_with_publish_and_pin(
        spec: &ContainerAttachSpec,
    ) -> impl FnOnce(&mut StaticIpam, &str) -> Result<AttachedContainer<()>, ContainerAttachError> + '_
    {
        move |ipam, generation| {
            let mut att = run_with_publish(spec)(ipam, generation)?;
            att.pin_identity = Some(PIN);
            Ok(att)
        }
    }

    /// c1（公開 1 件・pin つき）と c2（公開なし・pin なし）を attach したストアを用意する。
    fn attach_two(t: &Tmp) {
        let store = setup(t);
        let g = store.lock_global_exclusive().unwrap();
        let n = g.lock_network(&name()).unwrap();
        realize(&n);
        let s1 = spec("c1");
        attach_recorded_with(
            &host(),
            &n,
            &mid("c1"),
            &s1,
            &[],
            live_table(42),
            run_with_publish_and_pin(&s1),
        )
        .unwrap();
        let s2 = spec("c2");
        attach_recorded_with(
            &host(),
            &n,
            &mid("c2"),
            &s2,
            &[],
            live_table(42),
            ok_run(&s2),
        )
        .unwrap();
    }

    type DetachOut = Result<NetworkDeleteReport, RecordedError<(), NetworkDeleteReport>>;

    /// 記録だけからの detach を、`run` に渡った請求書を控えて実行する。
    fn detach_member(
        n: &NetworkLockGuard<'_>,
        id: &str,
        dir: &str,
        reg: &mut PortRegistry,
        run_result: Result<(), ()>,
    ) -> (DetachOut, Option<super::super::FailedAttachClaim>) {
        let seen = std::cell::RefCell::new(None);
        let r = detach_member_recorded_with(&host(), n, &mid(id), Path::new(dir), reg, |c, d| {
            assert_eq!(d.path(), Path::new(NETNS_DIR));
            assert_eq!(d.dir_id(), (8, 9));
            *seen.borrow_mut() = Some(c.clone());
            run_result.map(|()| NetworkDeleteReport::default())
        });
        (r, seen.into_inner())
    }

    /// NET-1・NET-6・REPAIR-4・#3347: 再起動後（開き直したストア）でも、記録だけから請求書を合成し、成功したら
    /// メンバー記録・アドレス・ポート予約を解放する。兄弟の記録は変わらない。
    #[test]
    fn net1_3347_detach_member_synthesizes_claim_and_releases() {
        let t = Tmp::new("member-detach");
        attach_two(&t);
        let store = NetworkStore::open(&t.0).unwrap();
        let g = store.lock_global_exclusive().unwrap();
        let n = g.lock_network(&name()).unwrap();
        assert_eq!(n.rebuild_ipam().unwrap().allocated_count(), 2);
        let mut reg = PortRegistry::new();
        reg.reserve(&name(), &EndpointId::new("c1").unwrap(), &[web_publish()])
            .unwrap();
        let other =
            PortPublish::new(PortProtocol::Tcp, Ipv4Addr::new(192, 0, 2, 10), 9090, 80).unwrap();
        reg.reserve(&name(), &EndpointId::new("c2").unwrap(), &[other])
            .unwrap();
        let (r, claim) = detach_member(&n, "c1", NETNS_DIR, &mut reg, Ok(()));
        assert!(r.is_ok());
        let claim = claim.expect("run was called");
        assert_eq!(claim.network(), &name());
        assert_eq!(claim.endpoint().as_str(), "c1");
        assert_eq!(claim.token(), BRIDGE_TOKEN);
        assert!(claim.includes_veth() && claim.includes_netns() && claim.includes_quarantine());
        assert_eq!(claim.pin(), Some(PIN));
        assert!(
            claim.to_record().contains("v2"),
            "ルールつきなら v2 の記録: {}",
            claim.to_record()
        );
        let rules = claim.port_rules().expect("rules from the member record");
        assert_eq!(rules.table.get(), 42);
        assert_eq!(rules.ports.len(), 1);
        assert_eq!(*rules.ports[0].publish(), web_publish());
        assert_eq!(
            (
                rules.ports[0].prerouting().get(),
                rules.ports[0].output().get()
            ),
            (2, 3)
        );
        // 記録・アドレス・予約: c1 だけが消え、c2 は残る。
        let ids: Vec<String> = n
            .members()
            .unwrap()
            .iter()
            .map(|m| m.id().as_str().to_owned())
            .collect();
        assert_eq!(ids, vec!["c2".to_owned()]);
        assert_eq!(n.rebuild_ipam().unwrap().allocated_count(), 1);
        assert_eq!(reg.len(), 1);
        // 同じ endpoint を再 attach できる（アドレスが解放されている）。
        let s = spec("c1");
        let att =
            attach_recorded_with(&host(), &n, &mid("c1"), &s, &[], live_table(42), ok_run(&s))
                .unwrap();
        assert_eq!(att.address, pfx([10, 0, 0, 2], 24));
    }

    /// NET-1・#3347: 公開も pin の識別子も無いメンバーは、ルール無し・pin 無しの請求書になる。
    #[test]
    fn net1_3347_detach_member_without_publish_or_pin() {
        let t = Tmp::new("member-detach-plain");
        attach_two(&t);
        let store = NetworkStore::open(&t.0).unwrap();
        let g = store.lock_global_exclusive().unwrap();
        let n = g.lock_network(&name()).unwrap();
        let (r, claim) = detach_member(&n, "c2", NETNS_DIR, &mut PortRegistry::new(), Ok(()));
        assert!(r.is_ok());
        let claim = claim.unwrap();
        assert_eq!(claim.pin(), None);
        assert!(claim.port_rules().is_none());
        assert!(!claim.includes_quarantine());
    }

    /// NET-1・REPAIR-4・#3347: `run` が失敗したらメンバー記録を残し、請求書は保存せず、アドレスは使用中のまま。
    #[test]
    fn net1_3347_detach_member_failure_keeps_record() {
        let t = Tmp::new("member-detach-fail");
        attach_two(&t);
        let store = NetworkStore::open(&t.0).unwrap();
        let g = store.lock_global_exclusive().unwrap();
        let n = g.lock_network(&name()).unwrap();
        let mut reg = PortRegistry::new();
        reg.reserve(&name(), &EndpointId::new("c1").unwrap(), &[web_publish()])
            .unwrap();
        let (r, claim) = detach_member(&n, "c1", NETNS_DIR, &mut reg, Err(()));
        assert!(matches!(r, Err(RecordedError::Op(()))));
        assert!(claim.is_some());
        assert_eq!(n.members().unwrap().len(), 2);
        assert_eq!(n.rebuild_ipam().unwrap().allocated_count(), 2);
        assert!(n.reclaim_records().unwrap().attach.is_empty());
        assert_eq!(reg.len(), 1, "予約は成功するまで解放しない");
    }

    /// NET-1・SEC-1・REPAIR-4・#3347: 関門を満たさないときは `run` を呼ばず、記録も変えずに断る。
    #[test]
    fn net1_3347_detach_member_gates_refuse_before_kernel_ops() {
        let t = Tmp::new("member-detach-gates");
        attach_two(&t);
        let store = NetworkStore::open(&t.0).unwrap();
        {
            // 共有ロックのガードでは断る。
            let g = store.lock_global_shared().unwrap();
            let n = g.lock_network_shared(&name()).unwrap();
            let (r, claim) = detach_member(&n, "c1", NETNS_DIR, &mut PortRegistry::new(), Ok(()));
            assert_eq!(
                r.unwrap_err().store_code(),
                Some(NetErrorCode::FailedPrecondition)
            );
            assert!(claim.is_none());
        }
        let g = store.lock_global_exclusive().unwrap();
        let n = g.lock_network(&name()).unwrap();
        let refuse = |id: &str, dir: &str, code: NetErrorCode, msg: &str| {
            let (r, claim) = detach_member(&n, id, dir, &mut PortRegistry::new(), Ok(()));
            let Err(RecordedError::Store(e)) = r else {
                panic!("expected Store error for {id} {dir}");
            };
            assert_eq!((e.code(), e.message()), (code, msg), "{id} {dir}");
            assert!(claim.is_none(), "run must not be called: {id} {dir}");
            assert_eq!(n.members().unwrap().len(), 2);
        };
        // 記録に無いメンバー。
        refuse("zz", NETNS_DIR, NetErrorCode::NotFound, "member not found");
        // 置き場が記録と違う。
        refuse(
            "c1",
            "/run/other-ns",
            NetErrorCode::InvalidArgument,
            "netns directory does not match the member record",
        );
        // 同じ endpoint の回収待ちの請求書。
        n.save_reclaim_attach(&super::super::FailedAttachClaim::for_test(
            name(),
            EndpointId::new("c1").unwrap(),
            BRIDGE_TOKEN,
            "0123456789abcdef0123456789abcdef",
            true,
            false,
            false,
        ))
        .unwrap();
        refuse(
            "c1",
            NETNS_DIR,
            NetErrorCode::FailedPrecondition,
            "endpoint has a pending reclaim record",
        );
        // 別 endpoint の請求書は妨げない。
        let (r, claim) = detach_member(&n, "c2", NETNS_DIR, &mut PortRegistry::new(), Ok(()));
        assert!(r.is_ok() && claim.is_some());
    }

    fn api_publish() -> PortPublish {
        PortPublish::new(PortProtocol::Tcp, Ipv4Addr::new(192, 0, 2, 10), 9090, 81).unwrap()
    }

    /// 墓標のみのメンバー（ルールは回収済み）でも detach でき、請求書にルールを載せず記録を落とす（#3347・#3343）。
    #[test]
    fn net1_3347_detach_member_with_tombstone_only_has_no_rules() {
        let t = Tmp::new("member-detach-tomb-only");
        attach_two(&t);
        let store = NetworkStore::open(&t.0).unwrap();
        let g = store.lock_global_exclusive().unwrap();
        let n = g.lock_network(&name()).unwrap();
        let rec = n
            .members()
            .unwrap()
            .into_iter()
            .find(|m| m.id().as_str() == "c1")
            .unwrap();
        n.replace_member(&rec.with_unpublished(&web_publish()).unwrap())
            .unwrap();
        let mut reg = PortRegistry::new();
        reg.reserve(&name(), &EndpointId::new("c1").unwrap(), &[web_publish()])
            .unwrap();
        let (r, claim) = detach_member(&n, "c1", NETNS_DIR, &mut reg, Ok(()));
        assert!(r.is_ok());
        assert!(claim.expect("run was called").port_rules().is_none());
        assert_eq!(n.members().unwrap().len(), 1);
        assert_eq!(reg.len(), 0);
    }

    /// Active と墓標が混在するメンバーは、Active のルールだけを請求書に載せる（#3347・#3343）。
    #[test]
    fn net1_3347_detach_member_with_active_and_tombstone_claims_only_active() {
        let t = Tmp::new("member-detach-mixed");
        let store = setup(&t);
        let g = store.lock_global_exclusive().unwrap();
        let n = g.lock_network(&name()).unwrap();
        realize(&n);
        let s1 = spec("c1");
        attach_recorded_with(
            &host(),
            &n,
            &mid("c1"),
            &s1,
            &[],
            live_table(42),
            |ipam, generation| {
                let mut att = run_with_publish_and_pin(&s1)(ipam, generation)?;
                att.published_ports.push(PublishedPort::new(
                    &name(),
                    BRIDGE_TOKEN,
                    s1.endpoint(),
                    api_publish(),
                    (rule(4), rule(5)),
                ));
                Ok(att)
            },
        )
        .unwrap();
        let rec = n.members().unwrap().remove(0);
        n.replace_member(&rec.with_unpublished(&api_publish()).unwrap())
            .unwrap();
        let mut reg = PortRegistry::new();
        reg.reserve(
            &name(),
            &EndpointId::new("c1").unwrap(),
            &[web_publish(), api_publish()],
        )
        .unwrap();
        let (r, claim) = detach_member(&n, "c1", NETNS_DIR, &mut reg, Ok(()));
        assert!(r.is_ok());
        let claim = claim.expect("run was called");
        let rules = claim.port_rules().expect("active rule remains");
        assert_eq!(rules.ports.len(), 1);
        assert_eq!(*rules.ports[0].publish(), web_publish());
        assert!(n.members().unwrap().is_empty());
        assert_eq!(reg.len(), 0);
    }

    /// REPAIR-4・#3347: 成功・検証拒否・回収失敗のどれでも操作 1 件が記録される。
    #[test]
    fn repair4_3347_detach_member_records_every_outcome() {
        use crate::instrument::NetOpOutcome;
        use crate::instrument::testing::Collect;
        let t = Tmp::new("member-detach-instr");
        attach_two(&t);
        let c = std::sync::Arc::new(Collect::default());
        let store = NetworkStore::open_with_recorder(&t.0, c.clone()).unwrap();
        let g = store.lock_global_exclusive().unwrap();
        let n = g.lock_network(&name()).unwrap();
        let count = |c: &Collect| {
            c.kinds()
                .into_iter()
                .filter(|(k, _)| *k == NetOpKind::MemberDetachRecorded)
                .map(|(_, o)| o)
                .collect::<Vec<_>>()
        };
        let mut reg = PortRegistry::new();
        let (r, _) = detach_member(&n, "nope", NETNS_DIR, &mut reg, Ok(()));
        assert!(r.is_err());
        let (r, _) = detach_member(&n, "c1", NETNS_DIR, &mut reg, Err(()));
        assert!(r.is_err());
        let (r, _) = detach_member(&n, "c1", NETNS_DIR, &mut reg, Ok(()));
        assert!(r.is_ok());
        assert_eq!(
            count(&c),
            vec![
                NetOpOutcome::Failure,
                NetOpOutcome::Failure,
                NetOpOutcome::Success
            ]
        );
    }

    /// NET-3・SEC-1・#3347: 解除の印つきの公開が残るメンバーは、ルールの回収が黙って省かれないよう断る。
    #[test]
    fn net1_3347_detach_member_refuses_unpublishing_mark() {
        let t = Tmp::new("member-detach-mark");
        attach_two(&t);
        let store = NetworkStore::open(&t.0).unwrap();
        let g = store.lock_global_exclusive().unwrap();
        let n = g.lock_network(&name()).unwrap();
        let rec = n
            .members()
            .unwrap()
            .into_iter()
            .find(|m| m.id().as_str() == "c1")
            .unwrap();
        n.replace_member(&rec.with_unpublishing(&web_publish()).unwrap())
            .unwrap();
        let (r, claim) = detach_member(&n, "c1", NETNS_DIR, &mut PortRegistry::new(), Ok(()));
        let Err(RecordedError::Store(e)) = r else {
            panic!("expected Store error");
        };
        assert_eq!(e.code(), NetErrorCode::FailedPrecondition);
        assert_eq!(
            e.message(),
            "member has an unpublishing mark; recover it with unpublish first"
        );
        assert!(claim.is_none());
        assert_eq!(n.members().unwrap().len(), 2);
    }

    /// NET-3・SEC-1・#3347: 別 netns の世代・別ネットワークのトークン・未完了の操作（`realized.intent`）では断る。
    #[test]
    fn net1_3347_detach_member_refuses_other_generation_foreign_token_and_unsettled() {
        let t = Tmp::new("member-detach-gen");
        attach_two(&t);
        let store = NetworkStore::open(&t.0).unwrap();
        let g = store.lock_global_exclusive().unwrap();
        let n = g.lock_network(&name()).unwrap();
        // 別 netns の世代。
        let cur = host();
        let other = HostGeneration::new(
            cur.boot_id(),
            crate::network_store::NetnsIdentity::new(
                cur.netns().dev().wrapping_add(1),
                cur.netns().ino(),
            ),
        )
        .unwrap();
        let ran = std::cell::Cell::new(false);
        let r = detach_member_recorded_with::<(), _>(
            &other,
            &n,
            &mid("c1"),
            Path::new(NETNS_DIR),
            &mut PortRegistry::new(),
            |_, _| {
                ran.set(true);
                Ok(NetworkDeleteReport::default())
            },
        );
        let Err(RecordedError::Store(e)) = r else {
            panic!("expected Store error");
        };
        assert_eq!(
            e.message(),
            "recorded nft handles belong to another boot or network namespace"
        );
        // 別ネットワークのトークン。
        let path = t.0.join("@networks/web/members/c1");
        let alt: String = BRIDGE_TOKEN
            .chars()
            .map(|c| if c == 'a' { 'b' } else { 'a' })
            .collect();
        let good = String::from_utf8(std::fs::read(&path).unwrap()).unwrap();
        std::fs::write(&path, good.replace(BRIDGE_TOKEN, &alt).as_bytes()).unwrap();
        let (r, claim) = detach_member(&n, "c1", NETNS_DIR, &mut PortRegistry::new(), Ok(()));
        assert!(claim.is_none());
        let Err(RecordedError::Store(e)) = r else {
            panic!("expected Store error");
        };
        assert_eq!(e.code(), NetErrorCode::DataLoss);
        // 未完了の操作。
        std::fs::write(&path, good.as_bytes()).unwrap();
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
        let (r, claim) = detach_member(&n, "c1", NETNS_DIR, &mut PortRegistry::new(), Ok(()));
        assert!(claim.is_none() && !ran.get());
        assert_eq!(
            r.unwrap_err().store_code(),
            Some(NetErrorCode::FailedPrecondition)
        );
    }
}
