//! fandhe-container-net: netlink・nftables・bridge/veth/netns・DNS ヘルパー・host/none モード・ポート公開。
//!
//! 実装済みは netlink の nlmsghdr / rtattr バイト列コーデック・共通エラー型
//! （`netlink`・`error`。TASK-136.1・NET-11）と `NETLINK_ROUTE` ソケットの open / bind / send / recv
//! （`netlink_route`。Linux のみ。TASK-136.2.1・#843）と、seq 採番・ACK / `NLMSG_ERROR` 判定・
//! 期限つき往復（`NetlinkRouteSocket::request`。TASK-136.2.2・#844）と、bridge・veth の
//! `RTM_NEWLINK` 作成メッセージの組み立て（`netlink_route::LinkCreate`。OS 非依存。TASK-136.3.1・#845）と、
//! `RTM_SETLINK` の netns 移動・up の組み立て（`LinkSet`）および link 作成・設定の送信ラッパー
//! （`NetlinkRouteSocket::create_link` / `set_link`。TASK-136.3.2・#846）と、
//! 静的 address / route の追加（`RTM_NEWADDR` / `RTM_NEWROUTE`。`netlink_route::addr_route`。TASK-136.4・#301）。
//! nfnetlink の nfgenmsg ヘッダーとバッチフレーミング（BATCH_BEGIN / END。`nftables_batch`。OS 非依存。TASK-137.1・#304）と、
//! nf_tables の NEWTABLE / NEWCHAIN / DELTABLE の組み立て（`nftables_batch::table_chain`。TASK-137.2・#305）と、
//! nf_tables バッチの送信と ACK / エラー判定（`nftables_batch::NetlinkNetfilterSocket`。Linux のみ。TASK-137.3・#306）と、
//! nf_tables ルールの expr 列（`NFTA_RULE_EXPRESSIONS` / `NFTA_LIST_ELEM` / `NFTA_EXPR_*`）のネスト属性コーデック（`nftables_rules`。OS 非依存。TASK-138.1・#309）と、
//! payload（load 形式）・masq の型付き expr と NEWRULE の組み立て（`nftables_rules`。TASK-138.2・#310）と、
//! cmp・immediate・nat（DNAT）の型付き expr とハンドル指定のルール削除 DELRULE の組み立て（`nftables_rules`。TASK-138.3・#311）と、
//! 操作ごとの成功 / 失敗・所要時間の記録先を受け取る計装連携点（`instrument`。REPAIR-4）、ネットワーク作成処理（bridge・gateway・専用 nft テーブルと NAT base chain の作成と失敗時ロールバック。
//! `RTM_DELLINK`・ifindex 取得を含む。`network`。TASK-139.1・#314）と、コンテナ接続（netns の作成と pin〔`netns`。Linux のみ〕・
//! veth ペア作成・host 側の bridge 接続と up・peer 側の netns 移動と失敗時ロールバック。`network::attach_container`。静的 IPAM（`network::ipam::StaticIpam`。TASK-139.2.2・#848）によるアドレス払い出しと、枯渇時の veth・netns ロールバック。
//! `unshare` / `mount` は `sys` の薄いラッパー。TASK-139.2.1・#847）に加え、netns 内の `lo` / peer の up・アドレス付与・default route の設定と、
//! ポート公開指定の DNAT ルール一括投入（`network::PortPublish`。TASK-139.3・#316）も持つ。ネットワーク削除（veth・netns pin・専用 nft テーブル・bridge の一括解放と IPAM・ポート予約の解放。`network::delete_network`。TASK-139.4・#317）も持つ。none モード（`lo` のみの netns の作成・pin と解放。`network_mode::none`。NET-6・TASK-143.2・#327）も持つ（host モード〔TASK-143.1・#326〕は未実装）。link の down、
//! DNS ヘルパーのプロセス起動・UDP 待受・不正パケット破棄（`dns_helper`。仮応答のみ。TASK-141.1・#321）も持つ。masquerade ルール本体（nftables の bitwise / meta expr が前提）・ルールハンドルの取得経路・`eth0` へのリネーム、DNS ヘルパーの A 応答（TASK-141.2）等は未実装で、G10（TASK-136〜148・TASK-185〜186）で実装する（REPAIR-3）。
//! PLUG-1 区分は検討中
//! （制御面の `NetworkPlugin` は plugin 側に区分される一方、DNS ヘルパー・rootless 転送のデータパス
//! 判定は未確定。crate-naming.md）。確定扱いにはしない（spec-reference）。

pub mod dns_helper;
pub mod error;
pub mod instrument;
pub mod netlink;
pub mod netlink_route;
#[cfg(target_os = "linux")]
pub mod netns;
pub mod network;
pub mod network_mode;
pub mod nftables_batch;
pub mod nftables_rules;
#[cfg(target_os = "linux")]
mod sys;
