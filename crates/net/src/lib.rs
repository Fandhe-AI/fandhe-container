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
//! ポート公開指定の DNAT ルール一括投入（`network::PortPublish`。TASK-139.3・#316）も持つ。チェイン policy の読み取り照会（`nftables_batch::ChainGet`・`NetlinkNetfilterSocket::chain_info`。TASK-148.1・NET-10）も持つ。ネットワーク削除（veth・netns pin・専用 nft テーブル・bridge の一括解放と IPAM・ポート予約の解放。`network::delete_network`。TASK-139.4・#317）も持つ。作成失敗で取り残した bridge・nft テーブルの所有確認つき回収（`network::reclaim_failed_create`。NET-1・#2467）も持つ。`create_network` は専用テーブルの `postrouting` へ masquerade（`ip saddr <subnet> oifname != <bridge>`）も投入する（`network::masquerade`。NET-1・NET-11・#3073。host の `ip_forward` は変更しない）。none モード（`lo` のみの netns の作成・pin と解放。`network_mode::none`。NET-6・TASK-143.2・#327）も持つ。host モード（ホスト netns 共有の検証と bridge / host / none の排他的なモード選択。`network_mode`。TASK-143.1・#326）も持つ。link の down、
//! DNS ヘルパーのプロセス起動・UDP 待受・不正パケット破棄（`dns_helper`。TASK-141.1・#321）と A レコード応答・REFUSED（管理外名）・コンテナ名レジストリ（TASK-141.2・#322。ヘルパープロセスへの外部からの登録経路は未実装）も持つ。参照カウントによる DNS ヘルパーのオンデマンド起動・終了（`dns_helper::refcount`。プロセス内のみ。NET-7・TASK-144.1・#329）も持つ。ユーザー定義ネットワーク上の `--dns` 上流転送先マッピングと転送（`dns_helper::upstream`。プロセス内のみで、ヘルパープロセスへの登録経路・製品入口への接続は未実装〔REPAIR-3〕。NET-12・TASK-185.3・#346）も持つ。`--add-host` / `--dns` の hostname・IP 入力検証（`add_host_dns`。NET-12・TASK-185.1・#335）と、host/none モードでの `--dns` の resolv.conf 反映・none の loopback 制限（`add_host_dns::resolv_conf`。NET-12・TASK-185.4・#347）も持つ。`--add-host` の分割パースおよびコンテナ hosts ファイルへの追記（`add_host_dns::apply_add_hosts`。Linux 限定。NET-12・TASK-185.2・#345）も持つ。軽量運用（DNS ヘルパーなし）のサービス名 hosts 静的注入と名前解決方式の選択（`etc_hosts`・`dns_helper::refcount::DnsHelperRefCounts::join_network`。NET-8・TASK-146.1・#334。動的更新は未実装〔REPAIR-3〕）と、軽量運用での `--dns` の `resolv.conf` 直接書き込み（`etc_hosts::apply_static_dns`。NET-8・TASK-146.2・#336）も持つ。GETRULE dump によるハンドルの再照会等は未実装で（ルールハンドルは NEWRULE の `NLM_F_ECHO` 応答から取得済み。公開の個別解除は `network::unpublish_container_port`。NET-3・#2839）、G10（TASK-136〜148・TASK-185〜186）で実装する（REPAIR-3）。
//! pasta（rootless のユーザー定義ネットワークの外部ヘルパー）のバイナリの探索と検証（`pasta`。絶対パス・所有者・権限・版数。
//! 検証済みの型 `pasta::binary::PastaBinary` と opt-in の `PATH` 探索、`--version` の解釈。NET-9・PLUG-11・#1936）と、
//! ポート公開指定の検証と引数配列への変換（`pasta::port_forward`。OS 非依存。NET-9・#1937）も持つ。
//! ネットワーク定義の状態ストア（`network_store`。`@networks`・FCNET1・ロック・権限・上限。Linux のみ。NET-6・CORE-1・REPAIR-5・#3059）と、メンバー記録・`realized`・記録からの IPAM の組み直し・回収待ちの請求書（`network_store::member`・`realized`・`ipam_rebuild`、記録つきの合成 `network::recorded`。NET-1・NET-7・#3067。残った意図記録のカーネル照合は後続）も持つ。
//! pasta 構成の netns holder（`netns_holder`。supervisor が `/proc/self/exe netns-holder` として exec し直す専用プロセスの本体
//! `run_netns_holder_main`・supervisor 側の端 `NetnsHolderChannel`・固定長フレーム。Linux 以外は本体が `UNIMPLEMENTED`。
//! NET-9・CORE-6・#3197。supervisor の振り分けと launch への組み込みは後続）も持つ。
//! pasta の起動・監視・回収は supervisor（core 側）が `crates/net` の関数で行う。DNS ヘルパー（NET-5）は
//! plugin 側の `NetworkPlugin` の実装が起動する（PLUG-1 の区分。2026-10-12 のオーナー決定・#4。`docs/design/rootless-network.md` 12 章）。

// 試験専用の故障注入（attach の巻き戻しを失敗させる入口）を製品のリリースビルドへ入れない。最適化ビルド
// （`debug_assertions` が無効）で有効になっていたらコンパイルを止める（NET-1・REPAIR-3・#2971）。
#[cfg(all(feature = "attach-fault-test-support", not(debug_assertions)))]
compile_error!(
    "the `attach-fault-test-support` feature exposes test-only fault injection and must not be enabled in release builds"
);

// 試験専用の入口（anchor より上の所有者・権限の検査を省く `verify_pasta_binary_below`）を製品のリリースビルドへ
// 入れない。最適化ビルドで有効になっていたらコンパイルを止める（NET-9・PLUG-11・#1936）。
#[cfg(all(feature = "pasta-test-support", not(debug_assertions)))]
compile_error!(
    "the `pasta-test-support` feature skips ancestor trust checks and must not be enabled in release builds"
);

// 試験専用の入口（holder へ任意のバイト列・fd を送る `send_raw_for_test`）を製品のリリースビルドへ入れない
// （NET-9・REPAIR-2・#3197）。
#[cfg(all(feature = "netns-holder-test-support", not(debug_assertions)))]
compile_error!(
    "the `netns-holder-test-support` feature exposes raw frame injection and must not be enabled in release builds"
);

/// uapi 定数を `libc` と `const` 評価で照合するマクロ（Linux の試験ビルド限定。#3102・#1318・MVM-4・REPAIR-12）。
///
/// `crates/core/src/sys.rs` の同名マクロの複製（crate をまたいで共有できないため。方式は
/// `docs/design/ffi-libc-check.md`）。両辺の型を引数で明記し、`libc` 側の型が将来変わったときは E0308 で
/// 表に出る。比較は `as i128` で行い、64 bit 以下の整数同士では値を切り詰めない。食い違いは宣言を直す別
/// issue とし、試験側を宣言に合わせて通さない。関数は呼ばず `unsafe` を使わない。各モジュールの
/// `libc_abi`（宣言の隣）から使うため、`pub mod` 列より前に置く（`macro_rules` はテキスト順にしか見えない）。
#[cfg(all(test, target_os = "linux"))]
macro_rules! libc_const_eq {
    ($name:ident, $own_ty:ty, $lib_ty:ty) => {
        libc_const_eq!(super::$name, $own_ty, libc::$name, $lib_ty)
    };
    ($own:expr, $own_ty:ty, $lib:expr, $lib_ty:ty) => {{
        const OWN: $own_ty = $own;
        const LIB: $lib_ty = $lib;
        assert!(
            OWN as i128 == LIB as i128,
            concat!("libc mismatch: ", stringify!($own))
        );
    }};
}

pub mod add_host_dns;
pub mod dns_helper;
pub mod error;
pub mod etc_hosts;
pub mod instrument;
pub mod netlink;
pub mod netlink_route;
#[cfg(target_os = "linux")]
pub mod netns;
pub mod netns_holder;
pub mod network;
pub mod network_mode;
pub mod network_store;
pub mod nftables_batch;
pub mod nftables_rules;
pub mod pasta;
#[cfg(target_os = "linux")]
mod sys;
