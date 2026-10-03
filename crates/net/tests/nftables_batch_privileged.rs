//! nf_tables バッチ（`NEWTABLE` / `NEWCHAIN` / `DELTABLE`）の実機前提結合試験（NET-11・TASK-137.4・#307・MS-8）。
//!
//! `NetlinkNetfilterSocket::send_batch` で、隔離 netns の中にテーブル・regular chain・nat base chain を
//! 作って消す往復と、失敗バッチが all-or-nothing（何も適用されない）であることを実カーネルで照合する。
//! 成功時の同期点（`NFT_MSG_GETGEN` → `NEWGEN` → errno 0 の ACK。#306 で実機未確認だった経路）の確認も兼ねる。
//!
//! `CAP_NET_ADMIN` が必要なため既定のテスト集合から `#[ignore]` で分離する（ci.md「実機前提テスト」。
//! 既定集合の網羅は root を要さない `nftables_batch_socket` が担う）。host の ruleset を変更しないよう、
//! 自プロセスの netns が親プロセスの netns と異なる隔離 netns でなければ panic で拒否する（fail-closed）。
//! 実行方法・必要環境は AGENTS.md「実機前提テスト」節を参照。Linux のみ。

#![cfg(target_os = "linux")]

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use fandhe_container_net::error::{NetError, NetErrorCode};
use fandhe_container_net::nftables_batch::{
    BaseChain, ChainCreate, ChainType, NF_IP_PRI_NAT_SRC, NetlinkNetfilterSocket, NfInetHook,
    NftBatch, NftBatchAck, NftBatchError, NftBatchOutcome, NftBatchPosition, NftFamily, NftName,
    TableCreate, TableDelete,
};

/// 待ちの期限（REPAIR-5）。`FANDHE_CONTAINER_TEST_TIMEOUT_SECS`（1〜600、既定 10 秒）で上書きできる。
fn timeout() -> Duration {
    let secs = std::env::var("FANDHE_CONTAINER_TEST_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|s| (1..=600).contains(s))
        .unwrap_or(10);
    Duration::from_secs(secs)
}

/// 自プロセスと親プロセスの network namespace が別物であることを検証する（fail-closed）。
///
/// `unshare -n <exe>` は unshare 自身が exec で置き換わるため、親は host netns のシェル等になる。
/// 素の `cargo test -- --ignored` では親が cargo（host netns）になり、ここで拒否される。
fn assert_isolated_from_parent_netns() {
    let own = std::fs::read_link("/proc/self/ns/net").expect("read own netns link");
    let parent_path = format!("/proc/{}/ns/net", std::os::unix::process::parent_id());
    let parent = std::fs::read_link(&parent_path)
        .unwrap_or_else(|e| panic!("refusing to run: cannot read parent netns {parent_path}: {e}"));
    assert_ne!(
        own, parent,
        "refusing to run: same network namespace as the parent process; run under `unshare -n` so the host ruleset is not modified"
    );
}

fn unique_name(tag: &str) -> NftName {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    NftName::new(&format!("fandhe-it-{tag}-{}-{nanos}", std::process::id())).expect("name")
}

fn name(s: &str) -> NftName {
    NftName::new(s).expect("name")
}

/// バッチを送り、期限内に戻ったことも確認する（REPAIR-5）。
fn send(
    socket: &NetlinkNetfilterSocket,
    fill: impl FnOnce(&mut NftBatch) -> Result<(), NetError>,
) -> Result<NftBatchAck, NftBatchError> {
    let limit = timeout();
    let started = Instant::now();
    let result = socket.send_batch(limit, fill);
    assert!(started.elapsed() < limit, "batch exceeded {limit:?}");
    result
}

/// 失敗が 1 件だけで、位置・errno・code が期待どおりであることを照合する。
fn assert_single_failure(err: &NftBatchError, index: usize, errno: i32, code: NetErrorCode) {
    // nfnetlink が使えない環境は弱めずに失敗させる（ci.md）。
    assert_ne!(err.code(), NetErrorCode::Unimplemented, "{err}");
    assert_eq!(err.outcome(), NftBatchOutcome::Aborted, "{err}");
    assert_eq!(err.failures().len(), 1, "{err}");
    let f = err.failures().first().copied().expect("one failure");
    assert_eq!(f.position(), NftBatchPosition::Body { index }, "{err}");
    assert_eq!(f.errno(), errno, "{err}");
    assert_eq!(f.code(), code, "{err}");
    assert_eq!(err.code(), code, "{err}");
}

/// テスト途中で失敗しても作ったテーブルを消す（ベストエフォート。隔離 netns なので host には影響しない）。
struct Cleanup<'a> {
    socket: &'a NetlinkNetfilterSocket,
    table: NftName,
}

impl Drop for Cleanup<'_> {
    fn drop(&mut self) {
        let del = TableDelete::new(NftFamily::Inet, self.table.clone());
        let _ = self
            .socket
            .send_batch(timeout(), |b| b.push_with(|seq| del.build(seq)).map(|_| ()));
    }
}

/// NET-11・TASK-137.4: テーブル・regular chain・nat base chain の作成と削除が往復できる。
#[test]
#[ignore = "requires CAP_NET_ADMIN inside an isolated network namespace (e.g. unshare -n as root); NET-11"]
fn net11_table_chain_create_delete_roundtrip_in_isolated_netns() {
    assert_isolated_from_parent_netns();
    let socket = NetlinkNetfilterSocket::open().expect("open NETLINK_NETFILTER");
    let t = unique_name("rt");
    let _cleanup = Cleanup {
        socket: &socket,
        table: t.clone(),
    };

    // 作成: 同期点（GETGEN → NEWGEN → ACK）を含めて成功する。
    let create_table = TableCreate::new(NftFamily::Inet, t.clone()).exclusive();
    let regular = ChainCreate::regular(NftFamily::Inet, t.clone(), name("fwd"));
    let base = ChainCreate::base(
        NftFamily::Inet,
        t.clone(),
        name("postrouting"),
        BaseChain {
            chain_type: ChainType::Nat,
            hook: NfInetHook::PostRouting,
            priority: NF_IP_PRI_NAT_SRC,
        },
    )
    .expect("base chain");
    let ack = send(&socket, |b| {
        b.push_with(|seq| create_table.build(seq))?;
        b.push_with(|seq| regular.build(seq))?;
        b.push_with(|seq| base.build(seq))?;
        Ok(())
    })
    .expect("create table and chains");
    let seqs = ack.body_seqs();
    assert_eq!(seqs.len(), 3);
    assert!(ack.begin_seq() < seqs[0], "begin before body");
    assert!(seqs[0] < seqs[1] && seqs[1] < seqs[2], "body order");
    assert!(seqs[2] < ack.end_seq(), "body before end");

    // 作成の確認: EXCL の再作成は EEXIST（17）。
    let err = send(&socket, |b| {
        b.push_with(|seq| create_table.build(seq)).map(|_| ())
    })
    .expect_err("table already exists");
    assert_single_failure(&err, 0, 17, NetErrorCode::AlreadyExists);

    // 削除（DELTABLE は配下の chain もまとめて消す）。
    let del = TableDelete::new(NftFamily::Inet, t.clone());
    send(&socket, |b| b.push_with(|seq| del.build(seq)).map(|_| ())).expect("delete table");

    // 削除の確認: 再削除は ENOENT（2）。
    let err = send(&socket, |b| b.push_with(|seq| del.build(seq)).map(|_| ()))
        .expect_err("table already deleted");
    assert_single_failure(&err, 0, 2, NetErrorCode::NotFound);
}

/// NET-11・TASK-137.4: 途中で失敗したバッチは何も適用されない（all-or-nothing）。
#[test]
#[ignore = "requires CAP_NET_ADMIN inside an isolated network namespace (e.g. unshare -n as root); NET-11"]
fn net11_failed_batch_is_all_or_nothing_in_isolated_netns() {
    assert_isolated_from_parent_netns();
    let socket = NetlinkNetfilterSocket::open().expect("open NETLINK_NETFILTER");
    let t = unique_name("aon");
    let _cleanup = Cleanup {
        socket: &socket,
        table: t.clone(),
    };

    // 1 件目は有効、2 件目は存在しないテーブルへの chain 作成で失敗する。
    let create_table = TableCreate::new(NftFamily::Inet, t.clone()).exclusive();
    let orphan = ChainCreate::regular(NftFamily::Inet, unique_name("missing"), name("c"));
    let err = send(&socket, |b| {
        b.push_with(|seq| create_table.build(seq))?;
        b.push_with(|seq| orphan.build(seq))?;
        Ok(())
    })
    .expect_err("second message must fail");
    assert_single_failure(&err, 1, 2, NetErrorCode::NotFound);

    // 1 件目も適用されていない: 削除は ENOENT になる。
    let del = TableDelete::new(NftFamily::Inet, t.clone());
    let err = send(&socket, |b| b.push_with(|seq| del.build(seq)).map(|_| ()))
        .expect_err("table must not exist");
    assert_single_failure(&err, 0, 2, NetErrorCode::NotFound);
}
