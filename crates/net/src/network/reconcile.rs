//! 残った `realized.intent` のカーネル照合と、実体の無い `members-intent/*` の掃除（NET-1・NET-7・REPAIR-3・REPAIR-4・#3346）。
//!
//! 役割: `network::recorded` の記録つき操作は、カーネル操作の前に意図記録（`realized.intent`・`members-intent/<id>`）を
//! 書く（D11 の write-ahead）。操作の途中でプロセスが落ちると意図記録だけが残り、`recorded` の本体は fail-closed で
//! 次の操作を拒否し、`rebuild_ipam` は残ったアドレスを使用中として数え続ける。本モジュールは次の特権操作の先頭で、
//! 所有トークンでカーネル側を照合して、残った記録を昇格・巻き戻し・破棄する。呼び出し元は `recorded` の Linux ラッパー
//! 4 本（先頭で呼ぶ）と、supervisor / plugin-cri が任意の時点で呼べる公開入口 [`reconcile_network_recorded`]。
//!
//! # `realized.intent` の照合（op と `realized` の有無）
//! 照合の材料はネットワーク名から決まる bridge 名・nft テーブル名と、意図記録の所有トークンだけ。bridge は
//! `IFLA_IFALIAS`、テーブルは `NFTA_TABLE_USERDATA` がトークンと完全一致するときだけ「所有」とし、無ければ「不在」、
//! それ以外（空・他者の値・照会の失敗・期限切れ）は「証明できない」として何も変えない（fail-closed）。
//!
//! | op | `realized` | bridge / テーブル | 処理 |
//! | -- | ---------- | ------------------ | ---- |
//! | create | あり | トークン一致 | `commit_realized` の後に意図記録だけ残った窓。意図記録を消す（不一致は `DataLoss`） |
//! | create | なし | 両方所有 | 昇格。意図記録の gateway・subnet と照会で得た ifindex・ハンドルから `realized` を作る |
//! | create | なし | 両方不在 | カーネル操作の前に落ちた。意図記録を消す |
//! | create | なし | 所有と不在の混在 | 所有する資源だけを `reclaim_failed_create_with` で巻き戻して意図記録を消す |
//! | delete | あり / なし | 両方不在 | 削除は完了済み。`realized`（あれば）と意図記録を消す |
//! | delete | あり / なし | 所有あり・証明不能なし | 所有する資源を巻き戻して削除を完了する |
//! | いずれも | | 1 つでも証明不能 | 据え置き（従来どおり次の操作は `FailedPrecondition`） |
//!
//! 巻き戻しに失敗したときは意図記録を消さず、次の照合が再試行する。請求書（`pending-reclaim/create`）へ移さない理由は、
//! `@networks` 経路で請求書を消費する結線が未実装（#3075 系）で、移すと別の記録で同じく止まるだけになるため。
//! 同じトークンの `pending-reclaim/create` が残っていれば、巻き戻しの成功後に消す。
//!
//! # `members-intent/*` の掃除
//! `realized` が確定していて `realized.intent` が無いときだけ行う。次の順で全部を満たす意図記録だけを消す
//! （アドレスは続く `rebuild_ipam` で空きへ戻る）。
//! 1. 同じ ID の確定記録があり同一性が一致する: 冗長な意図記録（`commit_member` の後に落ちた窓）。確定記録は残す
//! 2. `pending-reclaim/attach/<endpoint>` の請求書が無い（quarantine・取り残しの追跡中は残す）
//! 3. host 側 veth が不在と確かめられる（生きた veth・照会の失敗は残す）
//! 4. netns の pin が不在と確かめられる（置き場は意図記録に記録した接続時のもの。無い旧形式は掃除しない）
//! 5. DNAT の帳尻が合う: 専用テーブルの DNAT の受け口が、全メンバー記録の公開（解除中を含む。1 件 2 ルール）で
//!    説明できる。説明できない DNAT が残っていれば、`ReclaimUnsaved` の quarantine のようにそのアドレスへ
//!    転送しうるため、候補をすべて残す
//!
//! # 残余（REPAIR-3）
//! - 記録の無い孤児 veth（意図記録も無いもの）の回収は link の全件 dump が前提で未実装
//! - 公開の帳尻は受け口の一致で保守的に判定する（`DumpedRule` はルールハンドルを読まない）。記録の無い公開が
//!   あると掃除を見送る側に倒れる
//! - 共有ロックのガードでは何も変えない（各本体が従来どおり `FailedPrecondition` で断る）

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::path::Path;
use std::time::Duration;

use super::delete::{LinkAttachment, LinuxDeleteOps, TableProof, judge_table_info};
use super::{
    CreatedNetwork, EndpointId, FailedCreateClaim, NetworkResourceNames, PortProtocol,
    PublishedListener, VethNames,
};
use crate::error::{NetError, NetErrorCode};
use crate::etc_hosts::NameResolution;
use crate::netlink_route::{IfIndex, IfName, NetlinkRouteSocket};
use crate::network::listener_dump::{MAX_DUMP_RULES, recognize_dnat_listener};
use crate::network_store::{
    HostGeneration, InstallMode, MemberId, NetworkLockGuard, RealizedIntent, RealizedOp,
    RealizedRecord,
};
use crate::nftables_batch::{
    NetlinkNetfilterSocket, NftFamily, NftName, NftTableHandle, TableInfo,
};
use crate::nftables_rules::RuleDump;

fn data_loss(msg: &'static str) -> NetError {
    NetError::new(NetErrorCode::DataLoss, msg)
}

/// 照合が使うカーネル操作の境界。Linux 実装と単体試験の fake を差し替えるための crate 内部トレイトで、
/// 公開の拡張点（PLUG-1）ではない。
pub(crate) trait ReconcileOps {
    /// 名前で引いた link の ifindex・master・別名。無ければ `NotFound`。
    fn link_attachment(&self, name: &IfName) -> Result<LinkAttachment, NetError>;
    /// 専用テーブルのハンドルとユーザーデータ。無ければ `NotFound`。
    fn table_info(&self, table: &NftName) -> Result<TableInfo, NetError>;
    /// 請求書の対象を、所有を証明してから巻き戻す（`reclaim_failed_create_with`）。取り残しがあれば `Err`。
    fn rollback(&self, claim: &FailedCreateClaim) -> Result<(), NetError>;
    /// 置き場 `dir` の直下に `endpoint` 名の pin が無いと確かめられるか（`Ok(true)` だけが不存在）。
    fn pin_absent(&self, dir: &Path, endpoint: &EndpointId) -> Result<bool, NetError>;
    /// 専用テーブルの DNAT ルールが示す受け口（重複を含む。1 公開 2 ルール）。
    fn dnat_listeners(&self, table: &NftName) -> Result<Vec<PublishedListener>, NetError>;
}

/// `realized.intent` の照合の結果。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RealizedReconcile {
    /// 照合する記録が無かった。
    None,
    /// 実体が揃っていたため `realized` へ昇格した。
    Promoted,
    /// 未完成の作成を巻き戻して意図記録を消した。
    RolledBack,
    /// カーネル側に何も無かったため意図記録だけを消した。
    Discarded,
    /// 削除の完了、または確定済みの操作の意図記録の削除をした。
    Completed,
    /// 証明できないため何も変えなかった（次の操作は `FailedPrecondition`）。
    Unresolved(Unresolved),
}

/// 据え置きの理由（REPAIR-4 の観測点。アドレス・トークン・名前を載せない）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Unresolved {
    /// bridge またはテーブルの所有を証明できない（空・他者の値・照会の失敗）。
    Unproven,
    /// 巻き戻しで取り残しがあった（次の照合が再試行する）。
    RollbackIncomplete,
}

/// 意図記録を残した理由。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum IntentKeep {
    /// attach の請求書が残っている（quarantine または取り残しの追跡中）。
    AttachClaim,
    /// host 側 veth が残っている。
    VethPresent,
    /// host 側 veth の有無を判定できない。
    VethUnproven,
    /// netns の pin が残っている。
    PinPresent,
    /// pin の有無を判定できない（置き場が与えられない場合を含む）。
    PinUnknown,
    /// DNAT の受け口が公開の記録で説明できない、または確かめられない。
    DnatUnaccounted,
}

/// 照合と掃除の報告。呼び出し側がログに出せる値（REPAIR-4）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ReconcileReport {
    /// `realized.intent` の照合結果。
    pub realized: RealizedReconcile,
    /// 消した `members-intent`。
    pub removed_intents: Vec<MemberId>,
    /// 残した `members-intent` とその理由。
    pub kept_intents: Vec<(MemberId, IntentKeep)>,
}

impl ReconcileReport {
    fn new(realized: RealizedReconcile) -> Self {
        Self {
            realized,
            removed_intents: Vec::new(),
            kept_intents: Vec::new(),
        }
    }
}

/// カーネル側の資源の所有の三値判定。
enum Proof<T> {
    Absent,
    Owned(T),
    Unproven,
}

fn prove_bridge<O: ReconcileOps>(ops: &O, bridge: &IfName, token: &str) -> Proof<IfIndex> {
    match ops.link_attachment(bridge) {
        Err(e) if e.code() == NetErrorCode::NotFound => Proof::Absent,
        Ok(l) if l.alias.as_deref() == Some(token) => Proof::Owned(l.index),
        _ => Proof::Unproven,
    }
}

fn prove_table<O: ReconcileOps>(ops: &O, table: &NftName, token: &str) -> Proof<NftTableHandle> {
    match judge_table_info(ops.table_info(table), token) {
        TableProof::Absent => Proof::Absent,
        TableProof::Owned(h) => NftTableHandle::new(h).map_or(Proof::Unproven, Proof::Owned),
        TableProof::Unproven(_) => Proof::Unproven,
    }
}

/// 同じトークンの `pending-reclaim/create` が残っていれば消す（トークンが違うものには触れない）。
fn drop_matching_create_claim(
    guard: &NetworkLockGuard<'_>,
    claim: &FailedCreateClaim,
) -> Result<(), NetError> {
    if let Some(saved) = guard.reclaim_records()?.create
        && saved.token() == claim.token()
    {
        guard.remove_reclaim_create_if(&saved)?;
    }
    Ok(())
}

/// 所有を証明できた資源だけを巻き戻す。成功なら `true`、取り残しがあれば `false`。
fn roll_back_owned<O: ReconcileOps>(
    guard: &NetworkLockGuard<'_>,
    ops: &O,
    intent: &RealizedIntent,
    bridge_owned: bool,
    table_owned: bool,
) -> Result<bool, NetError> {
    // 両方不在なら巻き戻す物が無い。請求書の同トークンの回収待ちだけを片付ける。
    let claim = FailedCreateClaim::for_reconcile(
        intent.name().clone(),
        intent.token(),
        bridge_owned || !table_owned,
        table_owned,
    )?;
    if (bridge_owned || table_owned) && ops.rollback(&claim).is_err() {
        return Ok(false);
    }
    drop_matching_create_claim(guard, &claim)?;
    Ok(true)
}

fn reconcile_intent<O: ReconcileOps>(
    host: &HostGeneration,
    guard: &NetworkLockGuard<'_>,
    ops: &O,
    intent: &RealizedIntent,
    realized: Option<&RealizedRecord>,
) -> Result<RealizedReconcile, NetError> {
    if intent.name() != guard.network() {
        return Err(data_loss("realized intent belongs to another network"));
    }
    let names = NetworkResourceNames::derive(intent.name())?;
    let token = intent.token();
    match (intent.op(), realized) {
        (RealizedOp::Create, Some(r)) => {
            if r.token() != token {
                return Err(data_loss("realized intent token differs from realized"));
            }
            guard.remove_realized_intent()?;
            return Ok(RealizedReconcile::Completed);
        }
        (RealizedOp::Delete, Some(r)) => {
            if r.token() != token
                || r.subnet() != intent.subnet()
                || r.gateway() != intent.gateway()
            {
                return Err(data_loss("realized intent differs from realized"));
            }
        }
        (RealizedOp::Create, None) => {
            let definition = guard.definition()?;
            let InstallMode::Bridge { subnet } = *definition.install() else {
                return Err(data_loss("realized intent needs a bridge definition"));
            };
            if subnet != intent.subnet() {
                return Err(data_loss("realized intent subnet differs from definition"));
            }
        }
        (RealizedOp::Delete, None) => {}
    }

    let bridge = prove_bridge(ops, names.bridge(), token);
    let table = prove_table(ops, names.table(), token);
    let (bridge_owned, table_owned) = match (&bridge, &table) {
        (Proof::Unproven, _) | (_, Proof::Unproven) => {
            return Ok(RealizedReconcile::Unresolved(Unresolved::Unproven));
        }
        (Proof::Owned(index), Proof::Owned(handle))
            if intent.op() == RealizedOp::Create && realized.is_none() =>
        {
            // 昇格: 両方の所有が証明できた。bridge の別名とテーブルの userdata は、アドレス設定と up の後・
            // nft バッチの最後に作られる資源にしか付かないため、作成の手順は完了している。
            let created = CreatedNetwork {
                name: intent.name().clone(),
                bridge: names.bridge().clone(),
                bridge_index: *index,
                bridge_token: token.to_owned(),
                table: names.table().clone(),
                gateway: intent.gateway(),
                name_resolution: NameResolution::default(),
            };
            let rec =
                RealizedRecord::from_created(&created, intent.subnet(), *handle, host.clone())?;
            guard.commit_realized(&rec)?;
            return Ok(RealizedReconcile::Promoted);
        }
        (b, t) => (matches!(b, Proof::Owned(_)), matches!(t, Proof::Owned(_))),
    };

    if !roll_back_owned(guard, ops, intent, bridge_owned, table_owned)? {
        return Ok(RealizedReconcile::Unresolved(
            Unresolved::RollbackIncomplete,
        ));
    }
    let nothing_in_kernel = !bridge_owned && !table_owned;
    match intent.op() {
        RealizedOp::Create => {
            guard.remove_realized_intent()?;
            Ok(if nothing_in_kernel {
                RealizedReconcile::Discarded
            } else {
                RealizedReconcile::RolledBack
            })
        }
        RealizedOp::Delete => {
            // `remove_realized` は `realized` を消してから意図記録を消す。`realized` が無ければ意図記録だけ。
            if realized.is_some() {
                guard.remove_realized()?;
            } else {
                guard.remove_realized_intent()?;
            }
            Ok(RealizedReconcile::Completed)
        }
    }
}

/// 公開の記録から期待する DNAT の受け口の数（1 公開 2 ルール）。
fn expected_listeners(
    guard: &NetworkLockGuard<'_>,
) -> Result<HashMap<(PortProtocol, Ipv4Addr, u16), usize>, NetError> {
    let mut out: HashMap<(PortProtocol, Ipv4Addr, u16), usize> = HashMap::new();
    for m in guard.members()? {
        for p in m.publishes() {
            let port = p.publish();
            let n = out
                .entry((port.protocol(), port.host_addr(), port.host_port()))
                .or_insert(0);
            *n = n.saturating_add(2);
        }
    }
    Ok(out)
}

/// 実測の DNAT の受け口がすべて公開の記録で説明できるか。
fn dnat_accounted<O: ReconcileOps>(guard: &NetworkLockGuard<'_>, ops: &O, table: &NftName) -> bool {
    let Ok(expected) = expected_listeners(guard) else {
        return false;
    };
    let Ok(observed) = ops.dnat_listeners(table) else {
        return false;
    };
    let mut seen: HashMap<(PortProtocol, Ipv4Addr, u16), usize> = HashMap::new();
    for l in &observed {
        let key = (l.protocol(), l.host_addr(), l.host_port());
        let n = seen.entry(key).or_insert(0);
        *n = n.saturating_add(1);
        if *n > expected.get(&key).copied().unwrap_or(0) {
            return false;
        }
    }
    true
}

/// 実体の無い `members-intent/*` を掃除する。`realized` は確定していて意図記録が無いこと。
fn sweep_member_intents<O: ReconcileOps>(
    guard: &NetworkLockGuard<'_>,
    ops: &O,
    realized: &RealizedRecord,
    report: &mut ReconcileReport,
) -> Result<(), NetError> {
    let intents = guard.member_intents()?;
    if intents.is_empty() {
        return Ok(());
    }
    let members = guard.members()?;
    let claims = guard.reclaim_records()?;
    let mut candidates = Vec::new();
    for it in intents {
        // 1. 確定記録があれば冗長な意図記録。同一性が違えば記録の矛盾。
        if let Some(m) = members.iter().find(|m| m.id() == it.id()) {
            if m.endpoint() != it.endpoint()
                || m.address() != it.address()
                || m.token() != it.token()
            {
                return Err(data_loss("member intent conflicts with the member record"));
            }
            if guard.remove_member_intent(it.id())? {
                report.removed_intents.push(it.id().clone());
            }
            continue;
        }
        // 2. attach の請求書。
        if claims.attach.iter().any(|c| c.endpoint() == it.endpoint()) {
            report
                .kept_intents
                .push((it.id().clone(), IntentKeep::AttachClaim));
            continue;
        }
        // 3. host 側 veth。
        let veth = VethNames::derive(it.endpoint())?;
        match ops.link_attachment(veth.host()) {
            Err(e) if e.code() == NetErrorCode::NotFound => {}
            Ok(_) => {
                report
                    .kept_intents
                    .push((it.id().clone(), IntentKeep::VethPresent));
                continue;
            }
            Err(_) => {
                report
                    .kept_intents
                    .push((it.id().clone(), IntentKeep::VethUnproven));
                continue;
            }
        }
        // 4. netns の pin。置き場は意図記録が持つ（接続ごとに違いうるため、呼び出しごとの単一の置き場では
        //    確かめない）。記録の無い旧形式は判定不能として残す。
        let Some(dir) = it.netns_dir() else {
            report
                .kept_intents
                .push((it.id().clone(), IntentKeep::PinUnknown));
            continue;
        };
        match ops.pin_absent(dir, it.endpoint()) {
            Ok(true) => candidates.push(it),
            Ok(false) => report
                .kept_intents
                .push((it.id().clone(), IntentKeep::PinPresent)),
            Err(_) => report
                .kept_intents
                .push((it.id().clone(), IntentKeep::PinUnknown)),
        }
    }
    if candidates.is_empty() {
        return Ok(());
    }
    // 5. DNAT の帳尻（候補があるときだけ 1 回照会する）。
    let names = NetworkResourceNames::derive(realized.name())?;
    if !dnat_accounted(guard, ops, names.table()) {
        for it in candidates {
            report
                .kept_intents
                .push((it.id().clone(), IntentKeep::DnatUnaccounted));
        }
        return Ok(());
    }
    // 6. 消す。
    for it in candidates {
        if guard.remove_member_intent(it.id())? {
            report.removed_intents.push(it.id().clone());
        }
    }
    Ok(())
}

/// 照合と掃除の本体（OS 非依存の手順。カーネル操作は `ops`）。共有ロックのガードでは何も変えず空の報告を返す。
///
/// `Err` は記録の破損・矛盾（`DataLoss`）と記録の読み書きの失敗。証明できずに据え置いたものは `Ok` の報告で返し、
/// 次の操作が従来どおり `FailedPrecondition` で断る。
pub(crate) fn reconcile_recorded_with<O: ReconcileOps>(
    host: &HostGeneration,
    guard: &NetworkLockGuard<'_>,
    ops: &O,
) -> Result<ReconcileReport, NetError> {
    if !guard.is_exclusive() {
        return Ok(ReconcileReport::new(RealizedReconcile::None));
    }
    let mut report = ReconcileReport::new(RealizedReconcile::None);
    if let Some(intent) = guard.realized_intent()? {
        let realized = guard.realized()?;
        report.realized = reconcile_intent(host, guard, ops, &intent, realized.as_ref())?;
        if matches!(report.realized, RealizedReconcile::Unresolved(_)) {
            return Ok(report);
        }
    }
    // 掃除は `realized` が確定し、未完了の操作が無いときだけ。
    if guard.realized_intent()?.is_some() {
        return Ok(report);
    }
    if let Some(realized) = guard.realized()? {
        sweep_member_intents(guard, ops, &realized, &mut report)?;
    }
    Ok(report)
}

/// 照合が、前回途中で落ちた削除を完了させたか（`realized` が無くなった `Completed`）。
///
/// 完了していれば、記録つき削除の呼び出し側は本体（`realized` を要する）に進まず成功として返す。
/// 確定済みの作成の意図記録だけを消した `Completed` では `realized` が残るため `false`。
pub(crate) fn delete_completed_by_reconcile(
    report: &ReconcileReport,
    guard: &NetworkLockGuard<'_>,
) -> Result<bool, NetError> {
    Ok(report.realized == RealizedReconcile::Completed && guard.realized()?.is_none())
}

/// Linux のカーネル実装。各要求に `timeout` を期限として渡す（REPAIR-5）。
struct LinuxReconcileOps<'a> {
    inner: LinuxDeleteOps<'a>,
}

impl ReconcileOps for LinuxReconcileOps<'_> {
    fn link_attachment(&self, name: &IfName) -> Result<LinkAttachment, NetError> {
        use super::delete::DeleteOps;
        self.inner.link_attachment(name)
    }

    fn table_info(&self, table: &NftName) -> Result<TableInfo, NetError> {
        use super::delete::DeleteOps;
        self.inner.table_info(table)
    }

    fn rollback(&self, claim: &FailedCreateClaim) -> Result<(), NetError> {
        super::delete::reclaim_failed_create_with(&self.inner, claim)
            .map(|_| ())
            .map_err(|e| e.error)
    }

    fn pin_absent(&self, dir: &Path, endpoint: &EndpointId) -> Result<bool, NetError> {
        use super::delete::DeleteOps;
        self.inner.pin_absent(dir, endpoint)
    }

    fn dnat_listeners(&self, table: &NftName) -> Result<Vec<PublishedListener>, NetError> {
        let rules = self.inner.nft.dump_rules(
            &RuleDump::new(NftFamily::Ipv4, table.clone()),
            self.inner.timeout,
        )?;
        if rules.len() > MAX_DUMP_RULES {
            return Err(NetError::new(
                NetErrorCode::ResourceExhausted,
                "too many rules in the network table",
            ));
        }
        let mut out = Vec::new();
        for rule in &rules {
            if let Some(l) = recognize_dnat_listener(rule.exprs())? {
                out.push(l);
            }
        }
        Ok(out)
    }
}

/// `recorded` のラッパーが操作の先頭で呼ぶ照合（Linux 実装を束ねる）。共有ロックでは何もしない。
pub(crate) fn reconcile_with_sockets(
    route: &NetlinkRouteSocket,
    nft: &NetlinkNetfilterSocket,
    guard: &NetworkLockGuard<'_>,
    timeout: Duration,
) -> Result<ReconcileReport, NetError> {
    let host = nft.host_generation()?;
    reconcile_recorded_with(
        &host,
        guard,
        &LinuxReconcileOps {
            inner: LinuxDeleteOps {
                route,
                nft,
                timeout,
                deadline: None,
            },
        },
    )
}

/// 残った `realized.intent` をカーネルと照合して昇格・巻き戻しし、実体の無い `members-intent/*` を掃除する
/// （NET-1・NET-7・#3346）。判定表と残余はモジュール doc。
///
/// 排他ロックのガードが必要（共有ロックは `FailedPrecondition`）。pin の置き場は各 `members-intent` が記録して
/// おり、置き場の無い旧形式の意図記録は pin の不存在を確かめられないため掃除しない。`CAP_NET_ADMIN` は呼び出し側の
/// 責務（netns の pin の検査は読み取りのみ）。`timeout` は各カーネル要求の期限（REPAIR-5）。
pub fn reconcile_network_recorded(
    route: &NetlinkRouteSocket,
    nft: &NetlinkNetfilterSocket,
    guard: &NetworkLockGuard<'_>,
    timeout: Duration,
) -> Result<ReconcileReport, NetError> {
    guard.require_exclusive()?;
    reconcile_with_sockets(route, nft, guard, timeout)
}

#[cfg(test)]
mod tests;
