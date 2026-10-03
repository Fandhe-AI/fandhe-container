//! `nftables_batch` 公開 API の結合試験（NET-11・TASK-137.1・#304・MS-8）。
//!
//! crate 外部から公開 API だけで BEGIN・本体・END のバッチを組み立て、バイト列と seq を機械照合する。
//! ソケットを使わない OS 非依存のテストのため 3 OS の既定結合試験集合で実行する（ci.md）。

use fandhe_container_net::error::{NetError, NetErrorCode};
use fandhe_container_net::netlink::{NLM_F_ACK, NLM_F_REQUEST, NlMsgBuilder, NlMsgIter};
use fandhe_container_net::nftables_batch::{
    NFNL_MSG_BATCH_BEGIN, NFNL_MSG_BATCH_END, NFNL_SUBSYS_NFTABLES, NFPROTO_INET, NfGenMsg,
    NftBatch, nfnl_msg_type,
};

const NEWTABLE: u16 = nfnl_msg_type(NFNL_SUBSYS_NFTABLES, 0);

fn body(seq: u32) -> Result<NlMsgBuilder, NetError> {
    let mut b = NlMsgBuilder::new(NEWTABLE, NLM_F_REQUEST | NLM_F_ACK, seq, 0);
    NfGenMsg::new(NFPROTO_INET, 0).put_into(&mut b)?;
    Ok(b)
}

/// NET-11: BEGIN → 本体 2 件 → END のバイト列・type・flags・seq・nfgenmsg を照合する。
#[test]
fn net11_batch_bytes_and_seq() {
    let mut batch = NftBatch::new(200).expect("new");
    assert_eq!(batch.push_with(body).expect("push"), 201);
    assert_eq!(batch.push_with(body).expect("push"), 202);
    let out = batch.finish().expect("finish");

    assert_eq!(out.bytes().len(), 80);
    assert_eq!((out.begin_seq(), out.end_seq()), (200, 203));
    assert_eq!(out.body_seqs(), &[201, 202][..]);

    let got: Vec<(u16, u16, u32)> = NlMsgIter::new(out.bytes())
        .map(|m| {
            let h = m.expect("decode").header();
            (h.msg_type(), h.flags(), h.seq())
        })
        .collect();
    let req = NLM_F_REQUEST;
    let ra = NLM_F_REQUEST | NLM_F_ACK;
    assert_eq!(
        got,
        vec![
            (NFNL_MSG_BATCH_BEGIN, req, 200),
            (NEWTABLE, ra, 201),
            (NEWTABLE, ra, 202),
            (NFNL_MSG_BATCH_END, req, 203),
        ]
    );
    // BEGIN の nfgenmsg: family=UNSPEC, version=0, res_id=NFNL_SUBSYS_NFTABLES (BE)
    assert_eq!(out.bytes()[16..20], [0x00, 0x00, 0x00, 0x0A]);
    // 本体の nfgenmsg: family=INET, version=0, res_id=0
    assert_eq!(out.bytes()[36..40], [NFPROTO_INET, 0x00, 0x00, 0x00]);
    // END の nfgenmsg
    assert_eq!(out.bytes()[76..80], [0x00, 0x00, 0x00, 0x0A]);
}

/// NET-11・REPAIR-2: NLM_F_ACK のない本体は拒否し、body_seqs に登録しない。
#[test]
fn net11_body_without_ack_is_rejected() {
    let mut batch = NftBatch::new(1).expect("new");
    let err = batch
        .push_with(|s| {
            let mut m = NlMsgBuilder::new(NEWTABLE, NLM_F_REQUEST, s, 0);
            NfGenMsg::new(NFPROTO_INET, 0).put_into(&mut m)?;
            Ok(m)
        })
        .expect_err("must reject");
    assert_eq!(err.code(), NetErrorCode::InvalidArgument);
    let out = batch.finish().expect("finish");
    assert!(out.body_seqs().is_empty());
    assert_eq!(out.bytes().len(), 40);
}

/// NET-11・TASK-137.2: 公開 API だけで「テーブル作成 → nat base chain 作成 → テーブル削除」を組む。
#[test]
fn net11_table_chain_batch_via_public_api() {
    use fandhe_container_net::netlink::NLM_F_CREATE;
    use fandhe_container_net::nftables_batch::{
        BaseChain, ChainCreate, ChainType, NF_IP_PRI_NAT_SRC, NfInetHook, NftFamily, NftName,
        TableCreate, TableDelete,
    };

    let t = NftName::new("fandhe").expect("name");
    let create = TableCreate::new(NftFamily::Inet, t.clone());
    let chain = ChainCreate::base(
        NftFamily::Inet,
        t.clone(),
        NftName::new("postrouting").expect("name"),
        BaseChain {
            chain_type: ChainType::Nat,
            hook: NfInetHook::PostRouting,
            priority: NF_IP_PRI_NAT_SRC,
        },
    )
    .expect("base");
    let del = TableDelete::new(NftFamily::Inet, t);

    let mut batch = NftBatch::new(1).expect("new");
    batch.push_with(|s| create.build(s)).expect("create");
    batch.push_with(|s| chain.build(s)).expect("chain");
    batch.push_with(|s| del.build(s)).expect("del");
    let out = batch.finish().expect("finish");

    assert_eq!(out.body_seqs(), &[2, 3, 4][..]);
    let got: Vec<(u16, u16, u32)> = NlMsgIter::new(out.bytes())
        .map(|m| {
            let h = m.expect("decode").header();
            (h.msg_type(), h.flags(), h.seq())
        })
        .collect();
    let ra = NLM_F_REQUEST | NLM_F_ACK;
    assert_eq!(
        got,
        vec![
            (NFNL_MSG_BATCH_BEGIN, NLM_F_REQUEST, 1),
            (0x0A00, ra | NLM_F_CREATE, 2),
            (0x0A03, ra | NLM_F_CREATE, 3),
            (0x0A02, ra, 4),
            (NFNL_MSG_BATCH_END, NLM_F_REQUEST, 5),
        ]
    );
}
