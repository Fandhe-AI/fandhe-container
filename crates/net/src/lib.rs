//! fandhe-container-net: netlink・nftables・bridge/veth/netns・DNS ヘルパー・host/none モード・ポート公開。
//!
//! 実装済みは netlink の nlmsghdr / rtattr バイト列コーデック・共通エラー型
//! （`netlink`・`error`。TASK-136.1・NET-11）と `NETLINK_ROUTE` ソケットの open / bind / send / recv
//! （`netlink_route`。Linux のみ。TASK-136.2.1・#843）と、seq 採番・ACK / `NLMSG_ERROR` 判定・
//! 期限つき往復（`NetlinkRouteSocket::request`。TASK-136.2.2・#844）。操作ごとの成功 / 失敗・所要時間の記録先を
//! 受け取る計装連携点（`instrument`。REPAIR-4）も持つ。link / address / route 操作・
//! nftables・DNS ヘルパー等は未実装で、G10（TASK-136〜148・TASK-185〜186）で実装する（REPAIR-3）。
//! PLUG-1 区分は検討中
//! （制御面の `NetworkPlugin` は plugin 側に区分される一方、DNS ヘルパー・rootless 転送のデータパス
//! 判定は未確定。crate-naming.md）。確定扱いにはしない（spec-reference）。

pub mod error;
pub mod instrument;
pub mod netlink;
pub mod netlink_route;
#[cfg(target_os = "linux")]
mod sys;
