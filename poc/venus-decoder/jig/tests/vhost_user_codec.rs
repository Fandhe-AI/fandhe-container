//! 公開 API 経由の vhost-user codec 結合試験（GPU-6・MVM-4・REPAIR-2・TASK-172 F1.1・#1516。3 OS・既定集合）。
//!
//! 要求・応答の具体バイト列の照合と、不正入力の拒否（検査順を含む）を確認する。ソケット I/O は含まない（F1.2）。

use fandhe_container_poc_venus_jig::vhost_user::{
    Ack, CodecErrorCode, ConfigPayload, HEADER_LEN, Header, MemRegion, MemTable, Reply, Request,
    RequestCode, VringFd, VringState, decode_reply, decode_request, decode_request_payload,
};

fn hdr(request: u32, flags: u32, payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&request.to_le_bytes());
    v.extend_from_slice(&flags.to_le_bytes());
    v.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    v.extend_from_slice(payload);
    v
}

fn u32s(vals: &[u32]) -> Vec<u8> {
    vals.iter().flat_map(|v| v.to_le_bytes()).collect()
}

#[test]
fn f1_1_gpu6_encode_requests_match_exact_bytes() {
    // GET_FEATURES: ペイロードなし、version 1。
    let m = Request::GetFeatures.encode(false).unwrap();
    assert_eq!(m.as_bytes(), &[1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0][..]);
    // SET_VRING_NUM index=1 num=256、NEED_REPLY（flags=0x9）。
    let m = Request::SetVringNum(VringState { index: 1, num: 256 })
        .encode(true)
        .unwrap();
    assert_eq!(m.as_bytes(), hdr(8, 0x9, &u32s(&[1, 256])).as_slice());
    // SET_VRING_KICK index=2 NOFD。
    let m = Request::SetVringKick(VringFd {
        index: 2,
        no_fd: true,
    })
    .encode(false)
    .unwrap();
    assert_eq!(m.as_bytes(), hdr(12, 1, &0x102u64.to_le_bytes()).as_slice());
}

#[test]
fn f1_1_gpu6_decode_requests_from_exact_bytes() {
    let d = decode_request(&hdr(2, 0x1, &0x4000_0000u64.to_le_bytes())).unwrap();
    assert_eq!(d.request, Request::SetFeatures(0x4000_0000));
    assert!(!d.need_reply);
    let d = decode_request(&hdr(3, 0x9, &[])).unwrap();
    assert_eq!(d.request, Request::SetOwner);
    assert!(d.need_reply);
    let region = MemRegion {
        guest_phys_addr: 1,
        memory_size: 2,
        userspace_addr: 3,
        mmap_offset: 4,
    };
    let mut p = u32s(&[1, 0]);
    p.extend([1u64, 2, 3, 4].iter().flat_map(|v| v.to_le_bytes()));
    let d = decode_request(&hdr(5, 1, &p)).unwrap();
    assert_eq!(
        d.request,
        Request::SetMemTable(MemTable::new(&[region]).unwrap())
    );
}

#[test]
fn f1_1_gpu6_two_stage_decode_via_public_api() {
    // 公開 API のみで「ヘッダ検証 → payload_len 確認 → ペイロード復号」を通す（REPAIR-2）。
    let msg = hdr(8, 0x9, &u32s(&[1, 256]));
    let header = Header::decode_request(&msg[..HEADER_LEN]).unwrap();
    assert_eq!(header.request(), RequestCode::SetVringNum);
    assert!(header.need_reply());
    assert!(!header.is_reply());
    assert_eq!(header.payload_len(), 8);
    let d = decode_request_payload(&header, &msg[HEADER_LEN..]).unwrap();
    assert_eq!(
        d.request,
        Request::SetVringNum(VringState { index: 1, num: 256 })
    );
    assert!(d.need_reply);
    // 応答方向（REPLY ビット）のヘッダは要求として拒否される。
    let err = Header::decode_request(&hdr(1, 0x5, &[])[..HEADER_LEN]).unwrap_err();
    assert_eq!(err.code, CodecErrorCode::InvalidFlags);
    // 12 バイト未満は ShortHeader。
    let err = Header::decode_request(&msg[..11]).unwrap_err();
    assert_eq!(err.code, CodecErrorCode::ShortHeader);
}

#[test]
fn f1_1_gpu6_reply_roundtrip_exact_bytes() {
    let m = Reply::Features(0x4000_0000).encode().unwrap();
    // flags = version 1 + REPLY(0x4) = 0x5。
    assert_eq!(
        m.as_bytes(),
        hdr(1, 0x5, &0x4000_0000u64.to_le_bytes()).as_slice()
    );
    assert_eq!(
        decode_reply(m.as_bytes(), RequestCode::GetFeatures).unwrap(),
        Reply::Features(0x4000_0000)
    );
    // 要求 ID が期待と違う応答は拒否する。
    assert_eq!(
        decode_reply(m.as_bytes(), RequestCode::GetQueueNum)
            .unwrap_err()
            .code,
        CodecErrorCode::InvalidValue
    );
    // config 応答の往復。
    let c = ConfigPayload::new(RequestCode::GetConfig, 0, 1, &[0xAB; 16]).unwrap();
    let m = Reply::Config(c).encode().unwrap();
    assert_eq!(
        decode_reply(m.as_bytes(), RequestCode::GetConfig).unwrap(),
        Reply::Config(c)
    );
}

#[test]
fn f1_1_gpu6_invalid_inputs_are_rejected_with_specific_codes() {
    let code = |b: &[u8]| decode_request(b).unwrap_err().code;
    assert_eq!(code(&[0; 11]), CodecErrorCode::ShortHeader);
    assert_eq!(code(&hdr(1, 0x2, &[])), CodecErrorCode::UnsupportedVersion);
    // 予約ビット（bit 4）と REPLY ビット付きの要求。
    assert_eq!(code(&hdr(1, 0x11, &[])), CodecErrorCode::InvalidFlags);
    assert_eq!(code(&hdr(1, 0x5, &[])), CodecErrorCode::InvalidFlags);
    // 最小集合外（REPLY_ACK 系の既知 ID 40）。
    assert_eq!(code(&hdr(40, 1, &[])), CodecErrorCode::UnknownRequest);
    // size がペイロード上限を超える（ペイロードを読む前に拒否）。
    let mut big = hdr(2, 1, &[]);
    big[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(code(&big), CodecErrorCode::PayloadTooLarge);
    // 種別ごとの期待長の不一致。
    assert_eq!(code(&hdr(2, 1, &[0; 4])), CodecErrorCode::LengthMismatch);
    // kick の予約ビット。
    assert_eq!(
        code(&hdr(12, 1, &0x200u64.to_le_bytes())),
        CodecErrorCode::InvalidValue
    );
}

#[test]
fn f1_1_gpu6_length_is_checked_before_value() {
    let code = |b: &[u8]| decode_request(b).unwrap_err().code;
    // GET_CONFIG size=257 でデータなし: 期待長不一致が先。
    assert_eq!(
        code(&hdr(24, 1, &u32s(&[0, 257, 1]))),
        CodecErrorCode::LengthMismatch
    );
    // SET_MEM_TABLE n=33 で領域データなし: 期待長不一致が先。
    assert_eq!(
        code(&hdr(5, 1, &u32s(&[33, 0]))),
        CodecErrorCode::LengthMismatch
    );
    // 長さが一致した値の不正は INVALID_VALUE（config size=257、n=0）。
    let mut p = u32s(&[0, 257, 1]);
    p.extend([0u8; 257]);
    assert_eq!(code(&hdr(24, 1, &p)), CodecErrorCode::InvalidValue);
    assert_eq!(
        code(&hdr(5, 1, &u32s(&[0, 0]))),
        CodecErrorCode::InvalidValue
    );
}

/// GPU-6・REPAIR-2・TASK-172 F5.2b.1（#1639）: ack は size 8・REPLY の u64 で、成功は 0、失敗は 1。復号で往復する。
#[test]
fn f5_2b_1_gpu6_ack_encodes_exact_bytes_and_roundtrips() {
    let ok = Reply::Ack(Ack::success(RequestCode::SetOwner).unwrap());
    let m = ok.encode().unwrap();
    assert_eq!(
        m.as_bytes(),
        &[3, 0, 0, 0, 5, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0][..]
    );
    assert_eq!(
        decode_reply(m.as_bytes(), RequestCode::SetOwner).unwrap(),
        ok
    );
    let bad = Reply::Ack(Ack::failure(RequestCode::SetVringNum).unwrap());
    let m = bad.encode().unwrap();
    assert_eq!(
        m.as_bytes(),
        &[8, 0, 0, 0, 5, 0, 0, 0, 8, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0][..]
    );
    assert_eq!(
        decode_reply(m.as_bytes(), RequestCode::SetVringNum).unwrap(),
        bad
    );
}

/// 応答本体を持つ `GET_*` の要求 ID では ack を作れない（値が応答値と誤解されるのを型で防ぐ）。
#[test]
fn f5_2b_1_gpu6_ack_rejects_requests_with_reply_body() {
    for code in [
        RequestCode::GetFeatures,
        RequestCode::GetProtocolFeatures,
        RequestCode::GetQueueNum,
        RequestCode::GetVringBase,
        RequestCode::GetConfig,
    ] {
        assert!(code.has_reply_body());
        assert_eq!(
            Ack::success(code).unwrap_err().code,
            CodecErrorCode::InvalidValue
        );
        assert_eq!(
            Ack::failure(code).unwrap_err().code,
            CodecErrorCode::InvalidValue
        );
    }
    assert!(!RequestCode::SetMemTable.has_reply_body());
}

/// ack の size が 8 でない・要求 ID が食い違う応答は拒否する。
#[test]
fn f5_2b_1_gpu6_decode_ack_rejects_bad_length_and_id() {
    let short = hdr(3, 5, &[0, 0, 0, 0]);
    assert_eq!(
        decode_reply(&short, RequestCode::SetOwner)
            .unwrap_err()
            .code,
        CodecErrorCode::LengthMismatch
    );
    let ok = hdr(3, 5, &[0u8; 8]);
    assert_eq!(
        decode_reply(&ok, RequestCode::SetVringNum)
            .unwrap_err()
            .code,
        CodecErrorCode::InvalidValue
    );
}
