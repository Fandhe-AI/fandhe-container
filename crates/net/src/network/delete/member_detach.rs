//! 記録だけから行う detach の回収本体（NET-1・NET-6・REPAIR-4・SEC-1・#3347）。
//!
//! 役割: プロセスの再起動後は、生きた `AttachedContainer`（netns の fd・host veth の ifindex）を持てない。
//! 呼び出し元の `network::recorded::detach_member_recorded_with` は `members/<id>` から請求書
//! （[`FailedAttachClaim`]）を合成して本モジュールへ渡し、本モジュールは既存の `reclaim_failed_attach_with`
//! （DNAT ルール → host veth → netns の pin の順。所有の証明はそちらの規則を流用する）で外す。
//! 呼び出し元の想定は supervisor（#3074）と plugin-cri（#3075）。
//!
//! # 本モジュールが足す関門（カーネル操作の前・何も変えずに断る）
//! 回収側は pin の置き場を呼び出し側の固定設定 `netns_dir` から受ける。記録の置き場（接続時に控えた実体）と
//! 同じ実体であることを `pin_exists`（st_dev・st_ino の照合）で先に確かめ、食い違えば [`DeleteStep::Validate`] で
//! 断る。別の置き場の同名の pin を外さないため。
//!
//! # 残余リスク（REPAIR-3）
//! - 記録に pin の識別子が無い旧形式は、回収側の「識別子なし」の分岐を通る（pin が無ければ回収済み、
//!   残っていれば `Unknown` の取り残しで手動回収）
//! - 冪等: 各段が「既に無い」を回収済みとして扱うため、失敗後の再実行は収束する（記録は成功まで残る）

#[cfg(target_os = "linux")]
use std::time::Duration;

#[cfg(target_os = "linux")]
use super::LinuxDeleteOps;
use super::{
    DeleteOps, DeleteStep, NetworkDeleteError, NetworkDeleteReport, PinCheckError, fail,
    precondition, reclaim_failed_attach_with,
};
#[cfg(target_os = "linux")]
use crate::netlink_route::NetlinkRouteSocket;
#[cfg(target_os = "linux")]
use crate::netns::ContainerNetns;
use crate::network::NetnsDirRecord;
use crate::network::attach_claim::FailedAttachClaim;
#[cfg(target_os = "linux")]
use crate::nftables_batch::NetlinkNetfilterSocket;

/// 記録から合成した請求書 `claim` の資源を外す（OS 非依存。カーネル操作は `DeleteOps` で差し替える）。
///
/// `dir` は記録した pin の置き場（パスと接続時の実体の識別子）。置き場が同じ実体と確認できなければ、
/// 何も変更せず [`DeleteStep::Validate`] で断る。確認後は `reclaim_failed_attach_with` に委ねる。
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn reclaim_member_with<O: DeleteOps>(
    ops: &O,
    claim: &FailedAttachClaim,
    dir: &NetnsDirRecord,
) -> Result<NetworkDeleteReport, NetworkDeleteError<O::Netns>> {
    match ops.pin_exists(dir, claim.endpoint()) {
        Ok(_) => {}
        Err(PinCheckError::Dir(_)) => {
            return Err(fail(
                precondition("netns directory does not match the member record"),
                DeleteStep::Validate,
                NetworkDeleteReport::default(),
                Vec::new(),
            ));
        }
        // pin の有無を判定できないだけ。置き場の実体は記録どおりなので、回収側が `Unknown` で扱う。
        Err(PinCheckError::Pin(_)) => {}
    }
    reclaim_failed_attach_with(ops, claim, dir.path())
}

/// [`reclaim_member_with`] の Linux 実装（全体で 1 つの期限を持つ。REPAIR-5）。
///
/// `CAP_NET_ADMIN`（と unpin の `CAP_SYS_ADMIN`）は呼び出し側の責務。
#[cfg(target_os = "linux")]
pub(crate) fn reclaim_member(
    route: &NetlinkRouteSocket,
    nft: &NetlinkNetfilterSocket,
    claim: &FailedAttachClaim,
    dir: &NetnsDirRecord,
    timeout: Duration,
) -> Result<NetworkDeleteReport, NetworkDeleteError<ContainerNetns>> {
    reclaim_member_with(
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
