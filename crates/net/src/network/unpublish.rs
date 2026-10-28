//! ポート公開 1 件の個別解除（NET-3・NET-4・CRI-2・REPAIR-2・REPAIR-5・SEC-1・#2839）。
//!
//! 公開（`publish_container_ports`・attach 時の公開）は NEWRULE を `NLM_F_ECHO` 付きで送り、echo 応答の
//! ルールハンドルを [`PublishedPort`] に保持して返す。本モジュールはその [`PublishedPort`] を受けて、
//! 専用 nft テーブルの DNAT ルール 2 本（`prerouting`・`output`）をハンドル指定で消し、受け口の予約を戻す。
//! 呼び出し元は plugin-cri の `LinuxNetsetup::unpublish_port`（Linux）と試験。ネットワーク全体の解放
//! （`delete_network`）は従来どおりテーブルごと行い、本モジュールとは独立している。
//!
//! # 手順（`unpublish_ports_with`。OS 非依存。カーネル操作は呼び出し側が渡す）
//!
//! 1. 束縛の確認: [`PublishedPort`] が記録したネットワーク名・所有トークンが `network` と一致すること
//! 2. テーブルの所有の証明: 専用テーブルの `NFTA_TABLE_USERDATA` が所有トークンと一致すること。ルールの
//!    ハンドルはテーブルごとに採番されるため、同名で作り直された別のテーブルで古いハンドルが別のルールを
//!    消す事故をここで防ぐ（不一致・不在・照会失敗は何も変えずに `FailedPrecondition` 等で断る）。
//!    [`PublishedPort`] が公開時のテーブルハンドルを持つ（記録つき経路・再起動後の復元。#3068）ときは、生きた
//!    テーブルのハンドルとも照合する。userdata が同じでもルールセットの退避・復元でテーブルが作り直されると
//!    ハンドルが変わり、記録したルールハンドルは別のルールを指しうるため、食い違えば DELRULE を送らず
//!    `FailedPrecondition`（[`UnpublishRules::StaleHandles`]）で断る
//! 3. `DELRULE` 2 本を 1 バッチ（all-or-nothing）で送る
//! 4. 結果: 成功なら受け口の予約を戻す。`Aborted` / `NotSent` ならルールは残っている（確定）ので予約を
//!    保持し [`PublishedPort`] を返して再試行できるようにする。結果不明（`Unknown`）も予約を保持する
//!    （quarantine。残ったルールが同じ受け口で別のコンテナへ転送する事故を防ぐ）。ENOENT を「既に消えた」と
//!    推測して予約を戻すことはしない
//!
//! # 契約・未実装範囲（REPAIR-3）
//!
//! - `CAP_NET_ADMIN` は呼び出し側の責務で、本 crate は権限を上げない。期限は `timeout`（REPAIR-5）
//! - 所有の証明から DELRULE までの間に、同じ権限を持つ者がテーブルを差し替える窓が残る
//!   （`delete_network` と同じ水準。nft にテーブルハンドルを条件にした削除は無い）
//! - [`PublishedPort`] 自体はメモリ上の値で、再起動後は `network::recorded` が `members/<id>` の記録
//!   （受け口・ルールハンドル・テーブルハンドル。#3068）から復元する。dump は使わない。記録の無い公開
//!   （`table_handle` が `None`）の再起動後の解放は `delete_network` によるテーブル単位の一括解放だけ
//! - `NetworkPlugin::unpublish_port`（#2904・PLUG-1）は追加済みで、plugin-cri の `netsetup` が本 API を呼ぶ。
//!   呼び出し元は `set_up_sandbox` の公開途中の失敗の巻き戻し（`pod_network`）。attach 済みコンテナの `detach` は `detach_container`（#3062）が本モジュールの本体 `unpublish_ports_with` を再利用して公開を個別に解除する

use std::fmt;

use super::delete::require_table_owned;
use super::{CreatedNetwork, EndpointId, NetworkName, NftApplyFailure, PortPublish, PortRegistry};
use crate::error::{NetError, NetErrorCode};
use crate::nftables_batch::{NftBatchOutcome, NftName, NftTableHandle, TableInfo};
use crate::nftables_rules::NftRuleHandle;

/// 公開 1 件で投入した DNAT ルール 2 本（`prerouting`・`output`）のハンドル。
///
/// echo 応答から取ったカーネル採番のハンドルで、外から組み立てられない（フィールド非公開・REPAIR-2）。
/// 公開したネットワーク名・所有トークン・endpoint に束縛され、解除（`unpublish_ports_with`）が束縛と
/// テーブルの所有を確認してから使う。複製できない（解除に 1 度だけ渡す）。
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct PublishedPort {
    network: NetworkName,
    bridge_token: String,
    endpoint: EndpointId,
    publish: PortPublish,
    prerouting: NftRuleHandle,
    output: NftRuleHandle,
    /// ルールを投入したテーブルのハンドル（記録つきの経路だけが持つ。`None` は userdata だけで照合する）。
    table_handle: Option<NftTableHandle>,
}

impl PublishedPort {
    /// 公開の成功結果から組み立てる（crate 内の公開経路だけが呼ぶ）。
    pub(crate) fn new(
        network: &NetworkName,
        bridge_token: &str,
        endpoint: &EndpointId,
        publish: PortPublish,
        handles: (NftRuleHandle, NftRuleHandle),
    ) -> Self {
        Self {
            network: network.clone(),
            bridge_token: bridge_token.to_owned(),
            endpoint: endpoint.clone(),
            publish,
            prerouting: handles.0,
            output: handles.1,
            table_handle: None,
        }
    }

    /// ルールを投入したテーブルのハンドルを束縛する（記録つき経路の attach 結果と、記録からの復元が使う。#3068）。
    // 呼び出し元の `network::recorded` と `MemberRecord::published_ports` は Linux 限定（単体試験は全 OS で使う）。
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn with_table_handle(mut self, handle: NftTableHandle) -> Self {
        self.table_handle = Some(handle);
        self
    }

    /// 公開時のテーブルハンドル（束縛が無ければ `None`）。解除の前に生きたテーブルのハンドルと照合する。
    pub fn table_handle(&self) -> Option<NftTableHandle> {
        self.table_handle
    }

    /// 公開時のネットワークの bridge 所有トークン（記録との照合用）。
    pub(crate) fn bridge_token(&self) -> &str {
        &self.bridge_token
    }

    /// 記録の書き直しが済んだ後の再試行で、予約の解放だけを行う（DELRULE は送らない。NET-3・#3068）。
    /// 呼び出し側が、記録に当該の受け口が無いことと同一メンバー・ネットワークであることを確認済みの経路だけが呼ぶ。
    pub(crate) fn release_committed(
        &self,
        registry: &mut PortRegistry,
    ) -> Result<usize, UnpublishPortError> {
        registry
            .release_listeners(
                &self.network,
                &self.endpoint,
                std::slice::from_ref(&self.publish),
            )
            .map_err(|error| UnpublishPortError {
                error,
                rules: UnpublishRules::Removed,
                reservation_held: true,
                published: None,
            })
    }

    /// 公開したネットワーク。
    pub fn network(&self) -> &NetworkName {
        &self.network
    }

    /// 公開したコンテナの endpoint。
    pub fn endpoint(&self) -> &EndpointId {
        &self.endpoint
    }

    /// 公開の指定（受け口とコンテナ側ポート）。
    pub fn publish(&self) -> &PortPublish {
        &self.publish
    }

    /// `prerouting` チェインのルールハンドル。
    pub fn prerouting_handle(&self) -> NftRuleHandle {
        self.prerouting
    }

    /// `output` チェインのルールハンドル。
    pub fn output_handle(&self) -> NftRuleHandle {
        self.output
    }
}

/// 解除に失敗したときの DNAT ルールの状態。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum UnpublishRules {
    /// ルールは残っている（カーネルが拒否した、または送信前に断った。確定）。
    Present,
    /// ルールが残っているか不明（結果不明のバッチ・所有を証明できなかった等）。
    Unknown,
    /// ルールは消えた（予約の解放だけが失敗した）。
    Removed,
    /// 記録したテーブルハンドルが生きたテーブルと食い違う（テーブルが作り直された）。DELRULE は送っておらず、
    /// 記録したルールハンドルは古い。ルールが残っているかは判らないので `Unknown` と同じ扱い（quarantine）にする
    /// （NET-3・SEC-1・#3068）。
    StaleHandles,
}

/// 公開の個別解除の失敗。形は `PublishPortsError` に揃える。
///
/// `published` は再試行用に返す（`rules` が `Removed` のときは `None`。型が大きいため `Box`）。`reservation_held` が真なら受け口の
/// 予約を保持している（quarantine。最終的な解放は `delete_network`）。
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct UnpublishPortError {
    /// 失敗の原因。
    pub error: NetError,
    /// DNAT ルールの状態。
    pub rules: UnpublishRules,
    /// 受け口の予約を保持しているか。
    pub reservation_held: bool,
    /// 再試行用に返す公開の記録（ルールが消えていれば `None`）。
    pub published: Option<Box<PublishedPort>>,
}

impl fmt::Display for UnpublishPortError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.error.fmt(f)
    }
}

impl std::error::Error for UnpublishPortError {}

/// 公開 1 件の解除の本体（OS 非依存。手順と方針はモジュール doc）。`table_info` はテーブルの
/// ハンドルとユーザーデータの照会（読み取りのみ）、`delete` は `(prerouting, output)` のルールハンドルを
/// 指定した DELRULE 2 本の 1 バッチ投入（Linux では `unpublish_container_port` が渡す）。
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn unpublish_ports_with(
    table_info: impl FnOnce(&NftName) -> Result<TableInfo, NetError>,
    delete: impl FnOnce(&NftName, (NftRuleHandle, NftRuleHandle)) -> Result<(), NftApplyFailure>,
    network: &CreatedNetwork,
    published: PublishedPort,
    registry: &mut PortRegistry,
) -> Result<(), UnpublishPortError> {
    // 何も変えずに断る失敗。ルールの状態は判らないので Unknown とし、予約と記録を保つ。
    let refuse = |error: NetError, published: PublishedPort| UnpublishPortError {
        error,
        rules: UnpublishRules::Unknown,
        reservation_held: true,
        published: Some(Box::new(published)),
    };
    if published.network != network.name || published.bridge_token != network.bridge_token {
        return Err(refuse(
            NetError::new(
                NetErrorCode::FailedPrecondition,
                "published port does not belong to the network",
            ),
            published,
        ));
    }
    let live = match require_table_owned(table_info(&network.table), &network.bridge_token) {
        Ok(h) => h,
        Err(e) => return Err(refuse(e, published)),
    };
    // 記録したテーブルハンドルが生きたものと食い違えば、記録したルールハンドルは別のテーブルのもの。
    if published.table_handle.is_some_and(|rec| rec != live) {
        return Err(UnpublishPortError {
            error: NetError::new(
                NetErrorCode::FailedPrecondition,
                "nft table was recreated; recorded rule handles are stale",
            ),
            rules: UnpublishRules::StaleHandles,
            reservation_held: true,
            published: Some(Box::new(published)),
        });
    }
    let handles = (published.prerouting, published.output);
    if let Err(f) = delete(&network.table, handles) {
        let rules = if matches!(
            f.outcome,
            NftBatchOutcome::Aborted | NftBatchOutcome::NotSent
        ) {
            UnpublishRules::Present
        } else {
            UnpublishRules::Unknown
        };
        return Err(UnpublishPortError {
            error: f.error,
            rules,
            reservation_held: true,
            published: Some(Box::new(published)),
        });
    }
    // ルールは消えた。予約を戻せなければ予約だけが残る（fail-closed。解放は delete_network）。
    registry
        .release_listeners(
            &published.network,
            &published.endpoint,
            std::slice::from_ref(&published.publish),
        )
        .map(|_| ())
        .map_err(|error| UnpublishPortError {
            error,
            rules: UnpublishRules::Removed,
            reservation_held: true,
            published: None,
        })
}

/// 公開 1 件を解除する（DNAT ルール 2 本の削除と受け口の予約の解放。NET-3・NET-4）。
///
/// 手順・失敗時の扱いはモジュール doc と [`UnpublishPortError`]。`registry` は公開に使ったものと同じ
/// [`PortRegistry`]。`CAP_NET_ADMIN` が必要で、本 crate は権限を上げない。`timeout` は各 nft 要求の
/// 期限（REPAIR-5）。
#[cfg(target_os = "linux")]
pub fn unpublish_container_port(
    nft: &crate::nftables_batch::NetlinkNetfilterSocket,
    network: &CreatedNetwork,
    published: PublishedPort,
    registry: &mut PortRegistry,
    timeout: std::time::Duration,
) -> Result<(), UnpublishPortError> {
    unpublish_ports_with(
        |table| linux_table_info(nft, table, timeout),
        |table, handles| linux_delete_rules(nft, timeout, table, handles),
        network,
        published,
        registry,
    )
}

/// 専用テーブルの照会（GETTABLE。読み取りのみ）。記録つきの解除（`network::recorded`）と共用する。
#[cfg(target_os = "linux")]
pub(crate) fn linux_table_info(
    nft: &crate::nftables_batch::NetlinkNetfilterSocket,
    table: &NftName,
    timeout: std::time::Duration,
) -> Result<TableInfo, NetError> {
    use crate::nftables_batch::{NftFamily, TableGet};
    nft.table_info(&TableGet::new(NftFamily::Ipv4, table.clone()), timeout)
}

/// `(prerouting, output)` のルールハンドルを指定した DELRULE 2 本を 1 バッチ（all-or-nothing）で送る。
/// 記録つきの解除（`network::recorded`）と共用する。
#[cfg(target_os = "linux")]
pub(crate) fn linux_delete_rules(
    nft: &crate::nftables_batch::NetlinkNetfilterSocket,
    timeout: std::time::Duration,
    table: &NftName,
    (prerouting, output): (NftRuleHandle, NftRuleHandle),
) -> Result<(), NftApplyFailure> {
    use crate::nftables_batch::NftFamily;
    use crate::nftables_rules::RuleDelete;
    nft.send_batch(timeout, |batch| {
        for (chain, handle) in [("prerouting", prerouting), ("output", output)] {
            let rule =
                RuleDelete::new(NftFamily::Ipv4, table.clone(), NftName::new(chain)?, handle);
            batch.push_with(|seq| rule.build(seq))?;
        }
        Ok(())
    })
    .map(|_| ())
    .map_err(|e| NftApplyFailure {
        outcome: e.outcome(),
        error: e.into(),
    })
}

/// 指定したチェインのルール 1 本だけを DELRULE する（1 バッチ）。記録つきの解除が、2 本の一括削除が ENOENT で
/// 中止された後に、残っているルールを 1 本ずつ確実に消すために使う（NET-3・SEC-1・#3068）。
#[cfg(target_os = "linux")]
pub(crate) fn linux_delete_rule(
    nft: &crate::nftables_batch::NetlinkNetfilterSocket,
    timeout: std::time::Duration,
    table: &NftName,
    chain: &'static str,
    handle: NftRuleHandle,
) -> Result<(), NftApplyFailure> {
    use crate::nftables_batch::NftFamily;
    use crate::nftables_rules::RuleDelete;
    nft.send_batch(timeout, |batch| {
        let rule = RuleDelete::new(NftFamily::Ipv4, table.clone(), NftName::new(chain)?, handle);
        batch.push_with(|seq| rule.build(seq))?;
        Ok(())
    })
    .map(|_| ())
    .map_err(|e| NftApplyFailure {
        outcome: e.outcome(),
        error: e.into(),
    })
}

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;
    use crate::netlink_route::{IfIndex, IpPrefix};
    use crate::network::{NetworkResourceNames, PortProtocol};

    const TOKEN: &str = "fandhe-net:web:1:0:0";

    fn network() -> CreatedNetwork {
        let name = NetworkName::new("web").unwrap();
        let names = NetworkResourceNames::derive(&name).unwrap();
        CreatedNetwork {
            name,
            bridge: names.bridge().clone(),
            bridge_index: IfIndex::new(7).unwrap(),
            bridge_token: TOKEN.to_owned(),
            table: names.table().clone(),
            gateway: IpPrefix::new(IpAddr::V4(Ipv4Addr::new(10, 89, 0, 1)), 24).unwrap(),
            name_resolution: Default::default(),
        }
    }

    fn publish(host_port: u16) -> PortPublish {
        PortPublish::new(
            PortProtocol::Tcp,
            Ipv4Addr::new(192, 0, 2, 10),
            host_port,
            80,
        )
        .unwrap()
    }

    fn handle(n: u64) -> NftRuleHandle {
        NftRuleHandle::new(n).unwrap()
    }

    fn published(token: &str, net: &str) -> PublishedPort {
        PublishedPort::new(
            &NetworkName::new(net).unwrap(),
            token,
            &EndpointId::new("c1").unwrap(),
            publish(8080),
            (handle(2), handle(3)),
        )
    }

    /// 公開済みの状態（予約 1 件）を作る。
    fn reserved() -> PortRegistry {
        let mut reg = PortRegistry::new();
        reg.reserve(
            &NetworkName::new("web").unwrap(),
            &EndpointId::new("c1").unwrap(),
            &[publish(8080)],
        )
        .unwrap();
        reg
    }

    fn info(userdata: &[u8]) -> Result<TableInfo, NetError> {
        let mut p = vec![2u8, 0, 0, 0];
        for (ty, data) in [(4u16, &99u64.to_be_bytes()[..]), (6, userdata)] {
            p.extend_from_slice(&((4 + data.len()) as u16).to_ne_bytes());
            p.extend_from_slice(&ty.to_ne_bytes());
            p.extend_from_slice(data);
            while p.len() % 4 != 0 {
                p.push(0);
            }
        }
        TableInfo::decode(&p)
    }

    fn fail(code: NetErrorCode, outcome: NftBatchOutcome) -> NftApplyFailure {
        NftApplyFailure {
            error: NetError::new(code, "injected"),
            outcome,
        }
    }

    /// 解除を実行し、結果・delete に渡った (table, prerouting, output)・delete の呼び出し回数を返す。
    fn run(
        table: Result<TableInfo, NetError>,
        delete: Result<(), NftApplyFailure>,
        published: PublishedPort,
        reg: &mut PortRegistry,
    ) -> (Result<(), UnpublishPortError>, Vec<String>, u32) {
        let calls = RefCell::new(Vec::new());
        let n = Cell::new(0u32);
        let r = unpublish_ports_with(
            |_| table,
            |t, (a, b)| {
                n.set(n.get() + 1);
                calls
                    .borrow_mut()
                    .push(format!("{} {} {}", t.as_str(), a.get(), b.get()));
                delete
            },
            &network(),
            published,
            reg,
        );
        (r, calls.into_inner(), n.get())
    }

    /// NET-3: 成功で DELRULE にハンドル（2・3）が渡り、予約が解放されて同じ受け口を再び予約できる。
    #[test]
    fn net3_unpublish_deletes_by_handle_and_releases_reservation() {
        let mut reg = reserved();
        assert_eq!(reg.len(), 1);
        let (r, calls, n) = run(
            info(TOKEN.as_bytes()),
            Ok(()),
            published(TOKEN, "web"),
            &mut reg,
        );
        r.unwrap();
        assert_eq!(n, 1);
        assert_eq!(calls, vec![format!("{} 2 3", network().table.as_str())]);
        assert_eq!(reg.len(), 0);
        reg.reserve(
            &NetworkName::new("web").unwrap(),
            &EndpointId::new("c2").unwrap(),
            &[publish(8080)],
        )
        .unwrap();
    }

    /// NET-3: カーネルが拒否（Aborted / NotSent）なら予約を保持して記録を返し、ルールは Present。
    #[test]
    fn net3_unpublish_rejected_keeps_reservation_and_returns_record() {
        for outcome in [NftBatchOutcome::Aborted, NftBatchOutcome::NotSent] {
            let mut reg = reserved();
            let (r, _, _) = run(
                info(TOKEN.as_bytes()),
                Err(fail(NetErrorCode::NotFound, outcome)),
                published(TOKEN, "web"),
                &mut reg,
            );
            let e = r.unwrap_err();
            assert_eq!(e.error.code(), NetErrorCode::NotFound);
            assert_eq!(e.rules, UnpublishRules::Present);
            assert!(e.reservation_held);
            assert_eq!(e.published, Some(Box::new(published(TOKEN, "web"))));
            assert_eq!(reg.len(), 1, "no inference from ENOENT");
        }
    }

    /// NET-3: 結果不明は予約を保持して quarantine（ルールは Unknown）。
    #[test]
    fn net3_unpublish_unknown_outcome_quarantines() {
        let mut reg = reserved();
        let (r, _, _) = run(
            info(TOKEN.as_bytes()),
            Err(fail(NetErrorCode::Timeout, NftBatchOutcome::Unknown)),
            published(TOKEN, "web"),
            &mut reg,
        );
        let e = r.unwrap_err();
        assert_eq!(
            (e.rules, e.reservation_held, e.published.is_some()),
            (UnpublishRules::Unknown, true, true)
        );
        assert_eq!(reg.len(), 1);
    }

    /// テーブルハンドルを束縛した公開。
    fn published_at(table_handle: u64) -> PublishedPort {
        published(TOKEN, "web").with_table_handle(NftTableHandle::new(table_handle).unwrap())
    }

    /// NET-3・#3068: 記録のテーブルハンドルが生きたもの（99）と一致すれば、DELRULE に (2, 3) が渡り予約が解放される。
    #[test]
    fn net3_3068_matching_table_handle_deletes() {
        let mut reg = reserved();
        let (r, calls, n) = run(info(TOKEN.as_bytes()), Ok(()), published_at(99), &mut reg);
        r.unwrap();
        assert_eq!(n, 1);
        assert_eq!(calls, vec![format!("{} 2 3", network().table.as_str())]);
        assert_eq!(reg.len(), 0);
    }

    /// NET-3・SEC-1・#3068: 記録のテーブルハンドル（98）が生きたもの（99）と違えば、userdata が一致していても
    /// DELRULE を送らず、予約と記録を保って `StaleHandles` で断る。
    #[test]
    fn net3_3068_stale_table_handle_refuses_without_deleting() {
        let mut reg = reserved();
        let (r, calls, n) = run(info(TOKEN.as_bytes()), Ok(()), published_at(98), &mut reg);
        let e = r.unwrap_err();
        assert_eq!(n, 0, "delete must not be called");
        assert!(calls.is_empty());
        assert_eq!(e.error.code(), NetErrorCode::FailedPrecondition);
        assert_eq!(e.rules, UnpublishRules::StaleHandles);
        assert!(e.reservation_held);
        assert_eq!(reg.len(), 1);
        let kept = e.published.unwrap();
        assert_eq!(kept.table_handle().map(NftTableHandle::get), Some(98));
        assert_eq!(kept.prerouting_handle().get(), 2);
    }

    /// NET-3・#3068: 束縛の無い公開（メモリ上の経路）は従来どおり userdata だけで判定する。
    #[test]
    fn net3_3068_unbound_table_handle_keeps_userdata_only_check() {
        assert_eq!(published(TOKEN, "web").table_handle(), None);
        let mut reg = reserved();
        let (r, _, n) = run(
            info(TOKEN.as_bytes()),
            Ok(()),
            published(TOKEN, "web"),
            &mut reg,
        );
        r.unwrap();
        assert_eq!(n, 1);
    }

    /// NET-3・SEC-1・#3068: 照会の応答にテーブルハンドルが無ければ、記録があっても断って delete を呼ばない。
    #[test]
    fn net3_3068_missing_live_handle_refuses() {
        let mut p = vec![2u8, 0, 0, 0];
        let ud = TOKEN.as_bytes();
        p.extend_from_slice(&((4 + ud.len()) as u16).to_ne_bytes());
        p.extend_from_slice(&6u16.to_ne_bytes());
        p.extend_from_slice(ud);
        while p.len() % 4 != 0 {
            p.push(0);
        }
        let mut reg = reserved();
        let (r, _, n) = run(TableInfo::decode(&p), Ok(()), published_at(99), &mut reg);
        let e = r.unwrap_err();
        assert_eq!(n, 0);
        assert_eq!(e.error.code(), NetErrorCode::FailedPrecondition);
        assert!(e.reservation_held && e.published.is_some());
        assert_eq!(reg.len(), 1);
    }

    /// NET-3・SEC-1: 別ネットワーク・別トークンの記録とテーブル所有の不一致・不在・照会失敗は
    /// `FailedPrecondition` 等で断り、delete を呼ばず予約も変えない。
    #[test]
    fn net3_unpublish_refuses_foreign_binding_or_table_without_deleting() {
        type Case = (
            &'static str,
            PublishedPort,
            Result<TableInfo, NetError>,
            NetErrorCode,
        );
        let cases: Vec<Case> = vec![
            (
                "other network",
                published(TOKEN, "db"),
                info(TOKEN.as_bytes()),
                NetErrorCode::FailedPrecondition,
            ),
            (
                "other token",
                published("someone-else", "web"),
                info(TOKEN.as_bytes()),
                NetErrorCode::FailedPrecondition,
            ),
            (
                "table replaced",
                published(TOKEN, "web"),
                info(b"someone-else"),
                NetErrorCode::FailedPrecondition,
            ),
            (
                "table absent",
                published(TOKEN, "web"),
                Err(NetError::new(NetErrorCode::NotFound, "gone")),
                NetErrorCode::FailedPrecondition,
            ),
            (
                "query failed",
                published(TOKEN, "web"),
                Err(NetError::new(NetErrorCode::Timeout, "slow")),
                NetErrorCode::Timeout,
            ),
        ];
        for (desc, p, table, code) in cases {
            let mut reg = reserved();
            let (r, _, n) = run(table, Ok(()), p, &mut reg);
            let e = r.unwrap_err();
            assert_eq!(e.error.code(), code, "{desc}");
            assert_eq!(n, 0, "{desc}: delete must not be called");
            assert!(e.reservation_held && e.published.is_some(), "{desc}");
            assert_eq!(reg.len(), 1, "{desc}");
        }
    }
}
