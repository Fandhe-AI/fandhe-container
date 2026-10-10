//! vhost-user codec のユニットテスト（GPU-6・REPAIR-2・TASK-172 F1.1・#1516）。期待値は具体バイト列で書く。

use super::*;

/// 12 バイトヘッダを組む（テスト専用の素朴な組み立て）。
fn hdr(request: u32, flags: u32, size: u32) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&request.to_le_bytes());
    v.extend_from_slice(&flags.to_le_bytes());
    v.extend_from_slice(&size.to_le_bytes());
    v
}

fn msg(request: u32, flags: u32, payload: &[u8]) -> Vec<u8> {
    let mut v = hdr(request, flags, payload.len() as u32);
    v.extend_from_slice(payload);
    v
}

fn u32s(vals: &[u32]) -> Vec<u8> {
    vals.iter().flat_map(|v| v.to_le_bytes()).collect()
}

fn u64s(vals: &[u64]) -> Vec<u8> {
    vals.iter().flat_map(|v| v.to_le_bytes()).collect()
}

fn region(n: u64) -> MemRegion {
    MemRegion {
        guest_phys_addr: n,
        memory_size: n + 1,
        userspace_addr: n + 2,
        mmap_offset: n + 3,
    }
}

fn mem_table_bytes(n: u32, regions: &[MemRegion]) -> Vec<u8> {
    let mut p = u32s(&[n, 0]);
    for m in regions {
        p.extend(u64s(&[
            m.guest_phys_addr,
            m.memory_size,
            m.userspace_addr,
            m.mmap_offset,
        ]));
    }
    p
}

fn config(req: RequestCode, size: usize) -> ConfigPayload {
    ConfigPayload::new(req, 0, 0x1, &vec![0xAB; size]).unwrap()
}

fn config_bytes(offset: u32, size: u32, flags: u32, data: &[u8]) -> Vec<u8> {
    let mut p = u32s(&[offset, size, flags]);
    p.extend_from_slice(data);
    p
}

fn reply_code(r: Result<Reply, CodecError>) -> &'static str {
    r.unwrap_err().code.as_str()
}

fn code_of(r: Result<Decoded, CodecError>) -> &'static str {
    r.unwrap_err().code.as_str()
}

#[test]
fn f1_1_gpu6_request_roundtrip_all_18_kinds() {
    let state = VringState { index: 1, num: 256 };
    let addr = VringAddr {
        index: 1,
        flags: 0,
        descriptor: 0x1000,
        used: 0x3000,
        available: 0x2000,
        log: 0,
    };
    let cfg = config(RequestCode::GetConfig, 16);
    let cfg_set = config(RequestCode::SetConfig, 4);
    let features = (1u64 << 30) | (1 << 32) | 0x19;
    let cases: Vec<(Request, Vec<u8>)> = vec![
        (Request::GetFeatures, msg(1, 1, &[])),
        (
            Request::SetFeatures(features),
            msg(2, 1, &u64s(&[features])),
        ),
        (Request::SetOwner, msg(3, 1, &[])),
        (
            Request::SetMemTable(MemTable::new(&[region(0x10)]).unwrap()),
            msg(5, 1, &mem_table_bytes(1, &[region(0x10)])),
        ),
        (
            Request::SetMemTable(MemTable::new(&[region(0x10), region(0x20)]).unwrap()),
            msg(5, 1, &mem_table_bytes(2, &[region(0x10), region(0x20)])),
        ),
        (Request::SetVringNum(state), msg(8, 1, &u32s(&[1, 256]))),
        (
            Request::SetVringAddr(addr),
            msg(9, 1, &{
                let mut p = u32s(&[1, 0]);
                p.extend(u64s(&[0x1000, 0x3000, 0x2000, 0]));
                p
            }),
        ),
        (Request::SetVringBase(state), msg(10, 1, &u32s(&[1, 256]))),
        (Request::GetVringBase(state), msg(11, 1, &u32s(&[1, 256]))),
        (
            Request::SetVringKick(VringFd {
                index: 1,
                no_fd: true,
            }),
            msg(12, 1, &u64s(&[0x101])),
        ),
        (
            Request::SetVringCall(VringFd {
                index: 0,
                no_fd: false,
            }),
            msg(13, 1, &u64s(&[0])),
        ),
        (Request::GetProtocolFeatures, msg(15, 1, &[])),
        (
            Request::SetProtocolFeatures(PROTOCOL_F_MQ | PROTOCOL_F_CONFIG),
            msg(16, 1, &u64s(&[0x201])),
        ),
        (Request::GetQueueNum, msg(17, 1, &[])),
        (
            Request::SetVringEnable(VringState { index: 0, num: 1 }),
            msg(18, 1, &u32s(&[0, 1])),
        ),
        (
            Request::GetConfig(cfg),
            msg(24, 1, &config_bytes(0, 16, 1, &[0xAB; 16])),
        ),
        (
            Request::SetConfig(cfg_set),
            msg(25, 1, &config_bytes(0, 4, 1, &[0xAB; 4])),
        ),
        (Request::SetBackendReqFd, msg(21, 1, &[])),
        (Request::GetShmemConfig, msg(44, 1, &[])),
    ];
    // SET_MEM_TABLE は 1 領域と 2 領域の 2 件を持つので 19 件で、要求種別は 18 種。
    assert_eq!(cases.len(), 19);
    let mut kinds: Vec<u32> = cases.iter().map(|(r, _)| r.code().as_u32()).collect();
    kinds.dedup();
    assert_eq!(kinds.len(), 18);
    for (req, bytes) in cases {
        let d = decode_request(&bytes).unwrap();
        assert_eq!(d.request, req, "decode {:?}", req.code());
        assert!(!d.need_reply);
        assert_eq!(req.encode(false).unwrap().as_bytes(), &bytes[..]);
    }
}

#[test]
fn f1_1_gpu6_get_features_exact_bytes_and_need_reply() {
    let bytes = [1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0];
    assert_eq!(
        Request::GetFeatures.encode(false).unwrap().as_bytes(),
        &bytes
    );
    let nr = msg(3, 0x9, &[]);
    let d = decode_request(&nr).unwrap();
    assert_eq!(d.request, Request::SetOwner);
    assert!(d.need_reply);
    assert_eq!(Request::SetOwner.encode(true).unwrap().as_bytes(), &nr[..]);
}

#[test]
fn f1_1_gpu6_reply_roundtrip() {
    let cases: Vec<(Reply, Vec<u8>)> = vec![
        (
            Reply::Features(0x4000_0000),
            msg(1, 5, &u64s(&[0x4000_0000])),
        ),
        (Reply::ProtocolFeatures(0x201), msg(15, 5, &u64s(&[0x201]))),
        (Reply::QueueNum(2), msg(17, 5, &u64s(&[2]))),
        (
            Reply::VringBase(VringState { index: 1, num: 7 }),
            msg(11, 5, &u32s(&[1, 7])),
        ),
        (
            Reply::Config(config(RequestCode::GetConfig, 16)),
            msg(24, 5, &config_bytes(0, 16, 1, &[0xAB; 16])),
        ),
        (
            Reply::Config(ConfigPayload::new(RequestCode::GetConfig, 0, 0, &[]).unwrap()),
            msg(24, 5, &config_bytes(0, 0, 0, &[])),
        ),
    ];
    for (reply, bytes) in cases {
        assert_eq!(reply.encode().unwrap().as_bytes(), &bytes[..]);
        assert_eq!(decode_reply(&bytes, reply.code()).unwrap(), reply);
    }
}

#[test]
fn f1_1_gpu6_reply_rejections() {
    // 方向: REPLY ビットなし、NEED_REPLY 付き。
    let e = decode_reply(&msg(1, 1, &u64s(&[0])), RequestCode::GetFeatures).unwrap_err();
    assert_eq!(e.code, CodecErrorCode::InvalidFlags);
    let e = decode_reply(&msg(1, 0xD, &u64s(&[0])), RequestCode::GetFeatures).unwrap_err();
    assert_eq!(e.code, CodecErrorCode::InvalidFlags);
    // 要求 ID の不一致。
    let e = decode_reply(&msg(15, 5, &u64s(&[0])), RequestCode::GetFeatures).unwrap_err();
    assert_eq!(e.code.as_str(), "INVALID_VALUE");
    // 応答の size 不整合: GET_FEATURES が 4 バイト。
    let e = decode_reply(&msg(1, 5, &[0; 4]), RequestCode::GetFeatures).unwrap_err();
    assert_eq!(e.code.as_str(), "LENGTH_MISMATCH");
    // GET_CONFIG の size フィールドとデータ長の食い違い。
    let bad = msg(24, 5, &config_bytes(0, 8, 1, &[0; 16]));
    let e = decode_reply(&bad, RequestCode::GetConfig).unwrap_err();
    assert_eq!(e.code.as_str(), "LENGTH_MISMATCH");
}

#[test]
fn f1_1_gpu6_repair2_short_header() {
    assert_eq!(code_of(decode_request(&[])), "SHORT_HEADER");
    assert_eq!(code_of(decode_request(&[0u8; 11])), "SHORT_HEADER");
}

#[test]
fn f1_1_gpu6_repair2_payload_too_large_before_payload_read() {
    // ヘッダだけ（ペイロード未着）でも size 超過が先に判定される。
    assert_eq!(MAX_PAYLOAD_LEN, 1032);
    assert_eq!(
        code_of(decode_request(&hdr(5, 1, 1033))),
        "PAYLOAD_TOO_LARGE"
    );
    assert_eq!(
        code_of(decode_request(&hdr(5, 1, u32::MAX))),
        "PAYLOAD_TOO_LARGE"
    );
    // 境界値: 32 領域 = 1032 バイトは受理。
    let regions: Vec<MemRegion> = (0..32).map(region).collect();
    let bytes = msg(5, 1, &mem_table_bytes(32, &regions));
    assert_eq!(bytes.len(), MAX_MSG_LEN);
    let d = decode_request(&bytes).unwrap();
    assert_eq!(
        d.request,
        Request::SetMemTable(MemTable::new(&regions).unwrap())
    );
    assert_eq!(d.request.encode(false).unwrap().as_bytes(), &bytes[..]);
}

#[test]
fn f1_1_gpu6_unknown_request() {
    // 0・未割り当て・最小集合外の既知 ID（SET_LOG_BASE=6・CHECK_DEVICE_STATE=43）・範囲外。
    for id in [0u32, 99, 6, 43, 1004] {
        let e = decode_request(&msg(id, 1, &[])).unwrap_err();
        assert_eq!(e.code.as_str(), "UNKNOWN_REQUEST", "id={id}");
        assert_eq!(e.request, Some(id));
    }
}

#[test]
fn f1_1_gpu6_invalid_flags() {
    for flags in [0x11u32, 0x8000_0001, 0x21] {
        assert_eq!(
            code_of(decode_request(&msg(3, flags, &[]))),
            "INVALID_FLAGS"
        );
    }
    // 要求に REPLY ビット。
    assert_eq!(code_of(decode_request(&msg(3, 0x5, &[]))), "INVALID_FLAGS");
}

#[test]
fn f1_1_gpu6_unsupported_version() {
    assert_eq!(
        code_of(decode_request(&msg(3, 0x0, &[]))),
        "UNSUPPORTED_VERSION"
    );
    assert_eq!(
        code_of(decode_request(&msg(3, 0x2, &[]))),
        "UNSUPPORTED_VERSION"
    );
}

#[test]
fn f1_1_gpu6_check_order_is_fixed() {
    // version 不正と予約ビットが同時なら version が先。
    assert_eq!(
        code_of(decode_request(&msg(99, 0x10, &[]))),
        "UNSUPPORTED_VERSION"
    );
    // 予約ビットと size 超過なら flags が先、size 超過と未知 ID なら size が先。
    assert_eq!(
        code_of(decode_request(&hdr(99, 0x11, 2000))),
        "INVALID_FLAGS"
    );
    assert_eq!(
        code_of(decode_request(&hdr(99, 1, 2000))),
        "PAYLOAD_TOO_LARGE"
    );
    // 未知 ID と全体長の不一致なら未知 ID が先。
    assert_eq!(code_of(decode_request(&hdr(99, 1, 8))), "UNKNOWN_REQUEST");
}

#[test]
fn f1_1_gpu6_length_mismatch() {
    // バッファ長が 12 + size と違う（不足・余り）。
    assert_eq!(code_of(decode_request(&hdr(2, 1, 8))), "LENGTH_MISMATCH");
    let mut long = msg(2, 1, &[0; 8]);
    long.push(0);
    assert_eq!(code_of(decode_request(&long)), "LENGTH_MISMATCH");
    // 種別ごとの期待長: SET_FEATURES が 4 バイト、GET_FEATURES に余分なペイロード。
    assert_eq!(
        code_of(decode_request(&msg(2, 1, &[0; 4]))),
        "LENGTH_MISMATCH"
    );
    assert_eq!(
        code_of(decode_request(&msg(1, 1, &[0; 4]))),
        "LENGTH_MISMATCH"
    );
    // SET_MEM_TABLE で n=2 なのに 1 領域分（size 40）。
    let p = mem_table_bytes(2, &[region(1)]);
    assert_eq!(p.len(), 40);
    assert_eq!(code_of(decode_request(&msg(5, 1, &p))), "LENGTH_MISMATCH");
    // n=1 なのに 2 領域分のデータ。
    let p = mem_table_bytes(1, &[region(1), region(2)]);
    assert_eq!(code_of(decode_request(&msg(5, 1, &p))), "LENGTH_MISMATCH");
    // config: size フィールドがデータ長より大きい。
    let p = config_bytes(0, 16, 1, &[0; 4]);
    assert_eq!(code_of(decode_request(&msg(24, 1, &p))), "LENGTH_MISMATCH");
}

#[test]
fn f1_1_gpu6_invalid_value() {
    // n=0 は期待長（領域データなし）と一致したうえで値として拒否する。
    let p = mem_table_bytes(0, &[]);
    assert_eq!(code_of(decode_request(&msg(5, 1, &p))), "INVALID_VALUE");
    // n=33 で領域データなしは、値より先に期待長で LENGTH_MISMATCH（検査順は固定）。
    // 33 領域分のデータを付けると size が MAX_PAYLOAD_LEN を超え PAYLOAD_TOO_LARGE になる。
    let p = mem_table_bytes(33, &[]);
    assert_eq!(code_of(decode_request(&msg(5, 1, &p))), "LENGTH_MISMATCH");
    // config: size=257 でデータなしも LENGTH_MISMATCH が先。
    let p = config_bytes(0, 257, 1, &[]);
    assert_eq!(code_of(decode_request(&msg(24, 1, &p))), "LENGTH_MISMATCH");
    // kick / call の bit 9。
    for id in [12u32, 13] {
        assert_eq!(
            code_of(decode_request(&msg(id, 1, &u64s(&[0x200])))),
            "INVALID_VALUE"
        );
    }
    // config: size=257、flags の未定義ビット。
    let p = config_bytes(0, 257, 1, &[0; 257]);
    assert_eq!(code_of(decode_request(&msg(24, 1, &p))), "INVALID_VALUE");
    let p = config_bytes(0, 4, 0x4, &[0; 4]);
    assert_eq!(code_of(decode_request(&msg(25, 1, &p))), "INVALID_VALUE");
    // flags=0x1 と 0x2 は受理（crosvm のビットマスク）。
    for f in [0u32, 1, 2, 3] {
        let p = config_bytes(0, 4, f, &[0; 4]);
        assert!(decode_request(&msg(25, 1, &p)).is_ok(), "flags={f}");
    }
    // config の上限ちょうど（256）は受理。
    let p = config_bytes(0, 256, 1, &[0; 256]);
    assert!(decode_request(&msg(25, 1, &p)).is_ok());
}

#[test]
fn f1_1_gpu6_encode_side_is_fail_closed() {
    assert_eq!(
        MemTable::new(&[]).unwrap_err().code,
        CodecErrorCode::InvalidValue
    );
    let too_many: Vec<MemRegion> = (0..33).map(region).collect();
    assert_eq!(
        MemTable::new(&too_many).unwrap_err().code,
        CodecErrorCode::InvalidValue
    );
    assert_eq!(
        ConfigPayload::new(RequestCode::SetConfig, 0, 0, &[0; 257])
            .unwrap_err()
            .code,
        CodecErrorCode::InvalidValue
    );
    assert_eq!(
        ConfigPayload::new(RequestCode::SetConfig, 0, 0x8, &[])
            .unwrap_err()
            .code,
        CodecErrorCode::InvalidValue
    );
}

#[test]
fn f1_1_gpu6_error_display_has_no_input_echo() {
    let e = decode_request(&msg(99, 1, &[])).unwrap_err();
    assert_eq!(
        e.to_string(),
        "UNKNOWN_REQUEST (request=99): vhost-user request is not supported"
    );
}

#[test]
fn f1_1_gpu6_two_stage_decode_matches_one_shot() {
    // F1.2 の 2 段読み（ヘッダ → size 検証 → ペイロード）。
    let bytes = msg(8, 1, &u32s(&[2, 128]));
    let (h, payload) = bytes.split_at(HEADER_LEN);
    let header = Header::decode(h, Direction::Request).unwrap();
    assert_eq!(header.request(), RequestCode::SetVringNum);
    assert_eq!(header.payload_len(), 8);
    assert_eq!(
        decode_request_payload(&header, payload).unwrap().request,
        Request::SetVringNum(VringState { index: 2, num: 128 })
    );
    // ペイロード長が size と違えば拒否。
    assert_eq!(
        decode_request_payload(&header, &payload[..4])
            .unwrap_err()
            .code,
        CodecErrorCode::LengthMismatch
    );
}

/// GET_CONFIG のエラー応答はヘッダ size = 0 の空ペイロードで往復できる（GPU-6 F1.1）。
#[test]
fn f1_1_gpu6_get_config_error_reply_is_empty_payload() {
    let bytes = msg(24, 5, &[]);
    assert_eq!(bytes, vec![24, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(Reply::ConfigError.encode().unwrap().as_bytes(), &bytes[..]);
    assert_eq!(
        decode_reply(&bytes, RequestCode::GetConfig).unwrap(),
        Reply::ConfigError
    );
}

/// SET_VRING_KICK / CALL は値検証より先に期待長（8 バイト）を照合する（LENGTH_MISMATCH → INVALID_VALUE）。
#[test]
fn f1_1_gpu6_vring_fd_length_before_value() {
    for code in [12u32, 13] {
        // 0x200 は不正値だが、ペイロードが 9 バイトなので LENGTH_MISMATCH が先。
        let mut p = 0x200u64.to_le_bytes().to_vec();
        p.push(0);
        assert_eq!(
            decode_request(&msg(code, 1, &p)).unwrap_err().code,
            CodecErrorCode::LengthMismatch
        );
        // 長さが一致した不正値は INVALID_VALUE。
        assert_eq!(
            decode_request(&msg(code, 1, &0x200u64.to_le_bytes()))
                .unwrap_err()
                .code,
            CodecErrorCode::InvalidValue
        );
    }
}

// ---- GPU-6・TASK-172 F5.2b.2（#1641）: SET_BACKEND_REQ_FD・GET_SHMEM_CONFIG ----

fn shmem_one(size: u64) -> ShmemConfig {
    ShmemConfig::new(&[ShmemRegion { id: 1, size }]).unwrap()
}

/// 21・44 の要求はペイロードなしの 12 バイト。ペイロード付きは LENGTH_MISMATCH。
#[test]
fn f5_2b_2_gpu6_new_requests_are_header_only() {
    assert_eq!(
        Request::SetBackendReqFd.encode(false).unwrap().as_bytes(),
        &[21, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0]
    );
    assert_eq!(
        Request::GetShmemConfig.encode(false).unwrap().as_bytes(),
        &[44, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0]
    );
    for id in [21u32, 44] {
        assert_eq!(
            code_of(decode_request(&msg(id, 1, &[0u8; 8]))),
            "LENGTH_MISMATCH"
        );
    }
}

/// 応答は総長 2068（ヘッダ 12 + 2056）。nregions = 1・padding = 0・sizes[1] のみ非 0。
#[test]
fn f5_2b_2_gpu6_shmem_config_reply_bytes() {
    let m = Reply::ShmemConfig(shmem_one(0x0800_0000)).encode().unwrap();
    let b = m.as_bytes();
    assert_eq!(b.len(), 2068);
    assert_eq!(b[..12], [44, 0, 0, 0, 5, 0, 0, 0, 8, 8, 0, 0]);
    assert_eq!(b[12..16], 1u32.to_le_bytes());
    assert_eq!(b[16..20], 0u32.to_le_bytes());
    assert_eq!(b[20..28], 0u64.to_le_bytes());
    assert_eq!(b[28..36], 0x0800_0000u64.to_le_bytes());
    assert!(b[36..].iter().all(|x| *x == 0));
    let r = decode_reply(b, RequestCode::GetShmemConfig).unwrap();
    assert_eq!(r, Reply::ShmemConfig(shmem_one(0x0800_0000)));
    assert_eq!(r.code(), RequestCode::GetShmemConfig);
}

/// 組み立ての拒否: 大きさ 0・ページの倍数でない・id 重複・257 件はいずれも INVALID_VALUE（request = 44）。
#[test]
fn f5_2b_2_gpu6_shmem_config_new_rejects_bad_regions() {
    let r = |id, size| ShmemRegion { id, size };
    let bad = [
        vec![r(1, 0)],
        vec![r(1, 4095)],
        vec![r(1, 4097)],
        vec![r(1, 4096), r(1, 8192)],
    ];
    for regions in bad {
        let e = ShmemConfig::new(&regions).unwrap_err();
        assert_eq!(
            (e.code.as_str(), e.request),
            ("INVALID_VALUE", Some(44)),
            "{regions:?}"
        );
    }
    let many: Vec<ShmemRegion> = (0..257).map(|_| r(0, 4096)).collect();
    assert_eq!(
        ShmemConfig::new(&many).unwrap_err().code,
        CodecErrorCode::InvalidValue
    );
    // 空は nregions = 0、最大 id 255 は受理する。
    assert_eq!(ShmemConfig::new(&[]).unwrap().nregions(), 0);
    let top = ShmemConfig::new(&[r(255, 4096)]).unwrap();
    assert_eq!((top.nregions(), top.size(255)), (1, 4096));
}

/// frontend 役の復号の拒否: 長さ違いは LENGTH_MISMATCH、padding・nregions の食い違いは INVALID_VALUE。
#[test]
fn f5_2b_2_gpu6_shmem_config_reply_decode_rejects_inconsistent_payload() {
    let good = Reply::ShmemConfig(shmem_one(0x0800_0000)).encode().unwrap();
    let good = good.as_bytes().to_vec();
    // 2055 バイトは ShmemConfig の期待長（2056）に満たず LENGTH_MISMATCH、2057 バイトは応答の上限超過。
    for (size, want) in [(2055u32, "LENGTH_MISMATCH"), (2057, "PAYLOAD_TOO_LARGE")] {
        let mut b = good.clone();
        b.resize(12 + size as usize, 0);
        b[8..12].copy_from_slice(&size.to_le_bytes());
        assert_eq!(
            reply_code(decode_reply(&b, RequestCode::GetShmemConfig)),
            want,
            "size={size}"
        );
    }
    let mutate = |f: &dyn Fn(&mut Vec<u8>)| {
        let mut b = good.clone();
        f(&mut b);
        reply_code(decode_reply(&b, RequestCode::GetShmemConfig))
    };
    // padding != 0。
    assert_eq!(mutate(&|b| b[16] = 1), "INVALID_VALUE");
    // nregions = 2 だが非 0 は 1 個。
    assert_eq!(mutate(&|b| b[12] = 2), "INVALID_VALUE");
    // nregions = 1 だが非 0 が 2 個。
    assert_eq!(
        mutate(&|b| b[36..44].copy_from_slice(&4096u64.to_le_bytes())),
        "INVALID_VALUE"
    );
    // ページの倍数でない非 0。
    assert_eq!(
        mutate(&|b| b[28..36].copy_from_slice(&4097u64.to_le_bytes())),
        "INVALID_VALUE"
    );
}

/// 上限は向きごと: 要求は 1032 のまま（1033 と 2056 の要求は PAYLOAD_TOO_LARGE）、応答は 2056 まで。
#[test]
fn f5_2b_2_gpu6_payload_limits_are_per_direction() {
    assert_eq!(MAX_PAYLOAD_LEN, 1032);
    assert_eq!(MAX_REPLY_PAYLOAD_LEN, 2056);
    assert_eq!(MAX_ENCODED_LEN, 2068);
    assert_eq!(
        Header::new(RequestCode::SetMemTable, false, false, 1033)
            .unwrap_err()
            .code,
        CodecErrorCode::PayloadTooLarge
    );
    assert!(Header::new(RequestCode::GetShmemConfig, true, false, 2056).is_ok());
    assert_eq!(
        Header::new(RequestCode::GetShmemConfig, true, false, 2057)
            .unwrap_err()
            .code,
        CodecErrorCode::PayloadTooLarge
    );
    // 受信側: 要求の向きでは 2056 を受け付けない（受信の上限を広げていない）。
    assert_eq!(
        code_of(decode_request(&hdr(44, 1, 2056))),
        "PAYLOAD_TOO_LARGE"
    );
    assert_eq!(
        Header::decode_request(&hdr(5, 1, 1033)).unwrap_err().code,
        CodecErrorCode::PayloadTooLarge
    );
}

/// 44 は応答本体を持つので ack を作れない。21 は持たない。
#[test]
fn f5_2b_2_gpu6_get_shmem_config_has_reply_body() {
    assert!(RequestCode::GetShmemConfig.has_reply_body());
    assert!(!RequestCode::SetBackendReqFd.has_reply_body());
    assert_eq!(
        Ack::success(RequestCode::GetShmemConfig).unwrap_err().code,
        CodecErrorCode::InvalidValue
    );
    assert!(Ack::success(RequestCode::SetBackendReqFd).is_ok());
}
