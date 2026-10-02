//! fandhe-container-net: netlink・nftables・bridge/veth/netns・DNS ヘルパー・host/none モード・ポート公開。
//!
//! 実装済みは netlink の nlmsghdr / rtattr バイト列コーデックと共通エラー型のみ
//! （`netlink`・`error`。TASK-136.1・NET-11）。ソケット送受信・link / address / route 操作・
//! nftables・DNS ヘルパー等は未実装で、G10（TASK-136〜148・TASK-185〜186）で実装する（REPAIR-3）。
//! PLUG-1 区分は検討中
//! （制御面の `NetworkPlugin` は plugin 側に区分される一方、DNS ヘルパー・rootless 転送のデータパス
//! 判定は未確定。crate-naming.md）。確定扱いにはしない（spec-reference）。

pub mod error;
pub mod netlink;
pub mod netlink_route;
