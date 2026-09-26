//! fandhe-container-net: netlink・nftables・bridge/veth/netns・DNS ヘルパー・host/none モード・ポート公開。
//!
//! 現状は雛形のみで、実装はない（TASK-1.3・REPAIR-1。スタブの明示は REPAIR-3）。
//! 本体は G10（TASK-136〜148・TASK-185〜186）で実装する。PLUG-1 区分は検討中
//! （制御面の `NetworkPlugin` は plugin 側に区分される一方、DNS ヘルパー・rootless 転送のデータパス
//! 判定は未確定。crate-naming.md）。確定扱いにはしない（spec-reference）。
