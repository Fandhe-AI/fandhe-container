//! ホストの再起動をまたぐ記録だけの detach の回収本体（NET-1・NET-3・SEC-1・REPAIR-4・REPAIR-5・#3412）。
//!
//! 役割: 呼び出し元の `network::recorded::detach_member_after_reboot_with` は、`realized` の boot ID が現在と
//! 違うメンバー記録から請求書（[`FailedAttachClaim`]。DNAT ルールは載せない）を合成して本モジュールへ渡す。
//! 前の boot の bridge・veth・nsfs のマウント・nft テーブルは再起動でカーネルから消えているはずなので、
//! 本モジュールは **カーネル資源を一切消さない**（`delete_link`・`delete_table`・`delete_rules`・`delete_rule`・
//! nsfs の umount を呼ばない）。呼ぶのは次の照会と、残った空の pin ファイルの除去だけ。
//!
//! # 「何も無い」ことの確認（カーネルの照会。変更前にすべて満たさなければ断る）
//! boot ID の不一致だけは信用しない。記録の改ざんや、nftables.service によるルールセットの復元に備え、
//! 次をすべて確かめてから進む（fail-closed。`DeleteStep::Validate`・`FailedPrecondition`）。
//! 1. 専用テーブルの照会が `NotFound`（所有トークンの一致・不一致を問わず、あれば断る。照会の失敗も断る）
//! 2. bridge の照会が `NotFound`
//! 3. host veth の照会が `NotFound`
//! 4. pin: 置き場が記録と同じ実体なら、マウントされていない空ファイルで、所有記録と請求書の識別子が
//!    一致するときだけ消す（`unpin_stale_path`。マウントがあれば umount せず断る）。置き場の実体が違うとき
//!    （tmpfs の作り直し等）は、固定設定の置き場に同名の pin が無いと確かめられたときだけ進む。識別子の無い
//!    旧形式は pin が無ければ進み、あれば断る
//!
//! nft のルールハンドルはテーブルごとの採番で、新しい boot で作り直されたテーブルでは同じ番号が再利用されうる。
//! そのためルールは請求書に載せず、DELRULE を送らない。
//!
//! 全体で 1 つの期限を持つ（REPAIR-5。Linux 実装の `deadline`）。

use super::{
    DeleteOps, DeleteResource, DeleteStep, NetworkDeleteError, NetworkDeleteReport, PinCheckError,
    fail, precondition,
};
use crate::error::{NetError, NetErrorCode};
use crate::netlink_route::IfName;
use crate::network::attach_claim::FailedAttachClaim;
use crate::network::{NetnsDirRecord, NetworkResourceNames, VethNames};
use crate::nftables_batch::NftName;

#[cfg(target_os = "linux")]
use super::LinuxDeleteOps;
#[cfg(target_os = "linux")]
use crate::netlink_route::NetlinkRouteSocket;
#[cfg(target_os = "linux")]
use crate::netns::ContainerNetns;
#[cfg(target_os = "linux")]
use crate::nftables_batch::NetlinkNetfilterSocket;
#[cfg(target_os = "linux")]
use std::time::Duration;

/// 照会の結果が「無い」(`NotFound`) ならそのまま、あれば `present`、照会の失敗・期限切れは断る。
fn require_absent<T>(probe: Result<T, NetError>, present: &'static str) -> Result<(), NetError> {
    match probe {
        Ok(_) => Err(precondition(present)),
        Err(e) if e.code() == NetErrorCode::NotFound => Ok(()),
        // 照会の失敗・期限切れ（`Timeout`）は存在しないと言えないので、分類をそのまま返して断る。
        Err(e) => Err(e),
    }
}

fn expired() -> NetError {
    NetError::new(NetErrorCode::Timeout, "reclaim deadline exceeded")
}

/// 記録から合成した請求書 `claim` について、再起動後に残った pin だけを片付ける（OS 非依存。照会は `DeleteOps`）。
///
/// カーネル資源が残っていれば何も変えずに [`DeleteStep::Validate`] で断る。モジュール doc の手順どおり。
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn reclaim_member_after_reboot_with<O: DeleteOps>(
    ops: &O,
    claim: &FailedAttachClaim,
    dir: &NetnsDirRecord,
) -> Result<NetworkDeleteReport, NetworkDeleteError<O::Netns>> {
    let report = NetworkDeleteReport::default();
    let reject = |e: NetError, report: NetworkDeleteReport| {
        fail(e, DeleteStep::Validate, report, Vec::new())
    };
    let names = NetworkResourceNames::derive(claim.network());
    let veth = VethNames::derive(claim.endpoint());
    let (names, veth) = match (names, veth) {
        (Ok(n), Ok(v)) => (n, v),
        (Err(e), _) | (_, Err(e)) => return Err(reject(e, report)),
    };
    let table: &NftName = names.table();
    let bridge: &IfName = names.bridge();

    // 1〜3. カーネルに同名の資源が無いことを、変更の前に確かめる。
    if ops.deadline_exceeded() {
        return Err(reject(expired(), report));
    }
    require_absent(
        ops.table_info(table),
        "resources of the recorded network exist in this boot",
    )
    .map_err(|e| reject(e, NetworkDeleteReport::default()))?;
    if ops.deadline_exceeded() {
        return Err(reject(expired(), report));
    }
    require_absent(
        ops.link_attachment(bridge),
        "resources of the recorded network exist in this boot",
    )
    .map_err(|e| reject(e, NetworkDeleteReport::default()))?;
    if ops.deadline_exceeded() {
        return Err(reject(expired(), report));
    }
    require_absent(
        ops.link_attachment(veth.host()),
        "host veth of the member exists in this boot",
    )
    .map_err(|e| reject(e, NetworkDeleteReport::default()))?;

    // 4. pin。置き場が記録と同じ実体かを見てから、残った空ファイルだけを消す。
    if ops.deadline_exceeded() {
        return Err(reject(expired(), report));
    }
    let pin_path = dir.path().join(claim.endpoint().as_str());
    let pin_state = match ops.pin_exists(dir, claim.endpoint()) {
        Ok(present) => Ok(present),
        Err(PinCheckError::Dir(_)) => {
            // 置き場が作り直されていて同一性を言えない。設定の置き場に同名の pin が無いと確かめられたときだけ進む。
            match ops.pin_absent(dir.path(), claim.endpoint()) {
                Ok(true) => Ok(false),
                Ok(false) => Err(precondition(
                    "netns pin remains in a directory that differs from the record",
                )),
                Err(e) => Err(e),
            }
        }
        Err(PinCheckError::Pin(e)) => Err(e),
    };
    let mut report = report;
    match pin_state {
        Err(e) => return Err(reject(e, report)),
        Ok(false) => {}
        Ok(true) => {
            let Some(id) = claim.pin() else {
                return Err(reject(
                    precondition("claim has no pin identity; netns pin left in place"),
                    report,
                ));
            };
            if let Err(e) = ops.unpin_stale_path(&pin_path, id) {
                report
                    .leftover
                    .push((DeleteResource::Netns(pin_path), super::state_of(e.code())));
                return Err(fail(e, DeleteStep::UnpinNetns, report, Vec::new()));
            }
        }
    }
    report.removed.push(DeleteResource::Netns(pin_path));
    Ok(report)
}

/// [`reclaim_member_after_reboot_with`] の Linux 実装（全体で 1 つの期限を持つ。REPAIR-5）。
///
/// 照会だけで、`CAP_NET_ADMIN` は要らない（pin の除去は置き場の所有者の権限）。
#[cfg(target_os = "linux")]
pub(crate) fn reclaim_member_after_reboot(
    route: &NetlinkRouteSocket,
    nft: &NetlinkNetfilterSocket,
    claim: &FailedAttachClaim,
    dir: &NetnsDirRecord,
    timeout: Duration,
) -> Result<NetworkDeleteReport, NetworkDeleteError<ContainerNetns>> {
    reclaim_member_after_reboot_with(
        &LinuxDeleteOps {
            route,
            nft,
            timeout,
            deadline: Some(crate::sys::Deadline::after(timeout)),
        },
        claim,
        dir,
    )
}
