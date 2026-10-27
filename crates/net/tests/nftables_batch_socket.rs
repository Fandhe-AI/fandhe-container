//! `NetlinkNetfilterSocket` の実カーネル往復の結合試験（NET-11・REPAIR-5・TASK-137.3・#306・MS-8）。
//!
//! 存在しない一意な名前のテーブルを `DELTABLE` するバッチ 1 件を `NETLINK_NETFILTER` へ送り、
//! 「どのメッセージが失敗したか」の構造化エラーを実カーネルで照合する。ホストのルールセットは変更しない
//! （存在しないテーブルの削除だけ）。ソケットは非特権でも開けるため、既定の結合試験集合で実行する。
//!
//! - `CAP_NET_ADMIN` なし: カーネルは先頭（BEGIN）に `EPERM` を返す → `Begin`・`PermissionDenied`
//! - `CAP_NET_ADMIN` あり: 本体に `ENOENT` を返す → `Body { index: 0 }`・`NotFound`
//!
//! root を要する作成 / 削除の往復と既定集合からの分離は `nftables_batch_privileged.rs`（TASK-137.4・#307）が担う。

#![cfg(target_os = "linux")]

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use fandhe_container_net::error::NetErrorCode;
use fandhe_container_net::nftables_batch::{
    NetlinkNetfilterSocket, NftBatchOutcome, NftBatchPosition, NftFamily, NftName, TableDelete,
};

fn unique_name() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    format!("fandhe-it-{}-{nanos}", std::process::id())
}

fn delete_missing() -> TableDelete {
    TableDelete::new(NftFamily::Inet, NftName::new(&unique_name()).expect("name"))
}

/// NET-11・REPAIR-5: 存在しないテーブルの DELTABLE が構造化エラーで返り、期限内に戻る。
#[test]
fn net11_deltable_of_missing_table_reports_failed_message() {
    let socket = NetlinkNetfilterSocket::open().expect("open NETLINK_NETFILTER");
    let del = delete_missing();
    let timeout = Duration::from_secs(5);
    let started = Instant::now();
    let err = socket
        .send_batch(timeout, |batch| {
            batch.push_with(|seq| del.build(seq)).map(|_| ())
        })
        .expect_err("a missing table cannot be deleted");
    assert!(started.elapsed() < timeout);
    // nfnetlink が使えない環境は弱めずに失敗させる（ci.md）。
    assert_ne!(err.code(), NetErrorCode::Unimplemented, "{err}");
    assert_eq!(err.outcome(), NftBatchOutcome::Aborted, "{err}");
    assert_eq!(err.failures().len(), 1, "{err}");
    let failure = err.failures().first().copied().expect("one failure");
    match failure.position() {
        NftBatchPosition::Begin => {
            assert_eq!(failure.errno(), 1);
            assert_eq!(err.code(), NetErrorCode::PermissionDenied);
        }
        NftBatchPosition::Body { index } => {
            assert_eq!(index, 0);
            assert_eq!(failure.errno(), 2);
            assert_eq!(err.code(), NetErrorCode::NotFound);
        }
        other => panic!("unexpected position {other:?}"),
    }
}

/// NET-11: 同じソケットで続けて送っても seq が衝突せず、同じ判定が得られる。
#[test]
fn net11_second_batch_on_same_socket_is_judged_independently() {
    let socket = NetlinkNetfilterSocket::open().expect("open");
    for _ in 0..2 {
        let del = delete_missing();
        let err = socket
            .send_batch(Duration::from_secs(5), |batch| {
                batch.push_with(|seq| del.build(seq)).map(|_| ())
            })
            .expect_err("missing table");
        assert_eq!(err.outcome(), NftBatchOutcome::Aborted, "{err}");
        assert_eq!(err.failures().len(), 1, "{err}");
    }
}

/// NET-10・TASK-148.1: 存在しないチェインの GETCHAIN が構造化エラーで返る（ルールセットは変更しない）。
///
/// `CAP_NET_ADMIN` なしは `PermissionDenied`、ありは `NotFound`。
#[test]
fn net10_getchain_of_missing_chain_reports_structured_error() {
    use fandhe_container_net::nftables_batch::ChainGet;
    let socket = NetlinkNetfilterSocket::open().expect("open NETLINK_NETFILTER");
    let req = ChainGet::new(
        NftFamily::Ipv4,
        NftName::new(&unique_name()).expect("name"),
        NftName::new("FORWARD").expect("name"),
    );
    let started = Instant::now();
    let err = socket
        .chain_info(&req, Duration::from_secs(5))
        .expect_err("a missing chain cannot be read");
    assert!(started.elapsed() < Duration::from_secs(5));
    assert!(
        matches!(
            err.code(),
            NetErrorCode::PermissionDenied | NetErrorCode::NotFound
        ),
        "{err}"
    );
}

/// NET-3・#3063: GETTABLE / GETRULE の dump が実カーネルで往復し、ハングせず期限内に戻る
/// （読み取り専用でルールセットは変更しない）。
///
/// `CAP_NET_ADMIN` なしは `PermissionDenied`、ありは成功（存在しない一意なテーブルの GETRULE dump は
/// 空の結果）。nfnetlink の dump は ACK を送らず `NLMSG_DONE` で終わるため、その終端規則の実カーネルでの確認を兼ねる。
#[test]
fn net3_dump_of_tables_and_rules_terminates_with_done() {
    use fandhe_container_net::nftables_rules::RuleDump;
    let socket = NetlinkNetfilterSocket::open().expect("open NETLINK_NETFILTER");
    let limit = Duration::from_secs(5);

    let started = Instant::now();
    match socket.dump_table_names(NftFamily::Ipv4, "fandhe_net_", limit) {
        Ok(names) => {
            // 取得できた名前はすべて検証済みの nft 名で、重複を含まない。
            let mut sorted: Vec<&str> = names.iter().map(NftName::as_str).collect();
            sorted.sort_unstable();
            let n = sorted.len();
            sorted.dedup();
            assert_eq!(sorted.len(), n, "table names must be unique");
        }
        Err(e) => assert_eq!(e.code(), NetErrorCode::PermissionDenied, "{e}"),
    }
    assert!(started.elapsed() < limit);

    let started = Instant::now();
    let req = RuleDump::new(NftFamily::Ipv4, NftName::new(&unique_name()).expect("name"));
    match socket.dump_rules(&req, limit) {
        Ok(rules) => assert!(rules.is_empty(), "a missing table has no rules"),
        Err(e) => assert_eq!(e.code(), NetErrorCode::PermissionDenied, "{e}"),
    }
    assert!(started.elapsed() < limit);
}
