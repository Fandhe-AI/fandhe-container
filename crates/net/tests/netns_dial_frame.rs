//! `netns_dial` の固定長 frame codec の公開 API 結合試験（CRI-6・NET-3・SEC-1・REPAIR-2・REPAIR-12・#4477）。
//!
//! crate 外部から公開 API だけで、要求・応答の固定バイト列との相互変換と、
//! 不正フレーム（長さ・magic・version・予約欄・種別・範囲外の値）の拒否を具体値で照合する。
//! ソケットも OS 固有 API も使わない OS 非依存の試験のため 3 OS の既定結合試験集合で実行する。

use std::num::NonZeroU16;

use fandhe_container_net::error::NetErrorCode;
use fandhe_container_net::netns_dial::{
    ConnectTimeout, DialErrorCode, DialRequest, DialRequestFrame, DialResponse, DialResponseFrame,
    FRAME_LEN, MAX_CONNECT_TIMEOUT_MS,
};

fn request(port: u16, ms: u32) -> DialRequest {
    DialRequest::new(
        NonZeroU16::new(port).expect("nonzero port"),
        ConnectTimeout::new(ms).expect("timeout in range"),
    )
}

#[test]
fn request_encodes_to_fixed_bytes_and_roundtrips() {
    // port 8080 = 0x1f90、期限 5000 ms = 0x1388（いずれも LE）。
    let frame = DialRequestFrame::encode(request(8080, 5000));
    let expect: [u8; FRAME_LEN] = [
        b'F', b'C', b'N', b'D', 1, 1, 0, 0, 0x90, 0x1f, 0, 0, 0x88, 0x13, 0, 0,
    ];
    assert_eq!(frame.as_bytes(), &expect);
    let back = DialRequestFrame::decode(&expect).expect("decode");
    assert_eq!(back.port().get(), 8080);
    assert_eq!(back.connect_timeout().as_millis(), 5000);
    assert_eq!(back, request(8080, 5000));
}

#[test]
fn response_encodes_to_fixed_bytes_and_roundtrips() {
    let connected = DialResponseFrame::encode(DialResponse::Connected);
    let expect: [u8; FRAME_LEN] = [b'F', b'C', b'N', b'D', 1, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    assert_eq!(connected.as_bytes(), &expect);
    assert_eq!(
        DialResponseFrame::decode(&expect).expect("decode"),
        DialResponse::Connected
    );

    for (i, code) in DialErrorCode::ALL.iter().copied().enumerate() {
        let frame = DialResponseFrame::encode(DialResponse::Error(code));
        let mut want = [b'F', b'C', b'N', b'D', 1, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        want[12] = u8::try_from(i + 1).expect("small");
        assert_eq!(frame.as_bytes(), &want, "{}", code.as_str());
        assert_eq!(
            DialResponseFrame::decode(&want).expect("decode"),
            DialResponse::Error(code)
        );
    }
}

#[test]
fn timeout_range_is_enforced() {
    assert_eq!(
        ConnectTimeout::new(0).expect_err("zero").code(),
        NetErrorCode::InvalidArgument
    );
    assert_eq!(
        ConnectTimeout::new(MAX_CONNECT_TIMEOUT_MS + 1)
            .expect_err("over")
            .code(),
        NetErrorCode::InvalidArgument
    );
    assert_eq!(ConnectTimeout::new(1).expect("min").as_millis(), 1);
    assert_eq!(
        ConnectTimeout::new(10_000).expect("max").as_millis(),
        10_000
    );
}

#[test]
fn malformed_request_frames_are_rejected() {
    let good = *DialRequestFrame::encode(request(8080, 5000)).as_bytes();
    let reject = |bytes: &[u8]| {
        let err = DialRequestFrame::decode(bytes).expect_err("must reject");
        assert_eq!(err.code(), NetErrorCode::FailedPrecondition);
    };
    // 長さ違い。
    reject(&[]);
    reject(&good[..FRAME_LEN - 1]);
    let mut long = good.to_vec();
    long.push(0);
    reject(&long);
    // 各欄の不正。
    let mutate = |at: usize, v: u8| {
        let mut b = good;
        b[at] = v;
        b
    };
    reject(&mutate(0, b'X')); // magic
    reject(&mutate(4, 2)); // version
    reject(&mutate(5, 0)); // 種別 0
    reject(&mutate(5, 9)); // 未知の種別
    reject(&mutate(5, 2)); // 応答種別
    reject(&mutate(5, 3));
    reject(&mutate(6, 1)); // 予約欄
    reject(&mutate(11, 1));
    // port 0・期限 0・期限の上限超え。
    let mut b = good;
    b[8] = 0;
    b[9] = 0;
    reject(&b);
    let mut b = good;
    b[12..16].copy_from_slice(&0u32.to_le_bytes());
    reject(&b);
    let mut b = good;
    b[12..16].copy_from_slice(&(MAX_CONNECT_TIMEOUT_MS + 1).to_le_bytes());
    reject(&b);
}

#[test]
fn malformed_response_frames_are_rejected() {
    let ok = *DialResponseFrame::encode(DialResponse::Error(DialErrorCode::Refused)).as_bytes();
    let reject = |bytes: &[u8]| {
        let err = DialResponseFrame::decode(bytes).expect_err("must reject");
        assert_eq!(err.code(), NetErrorCode::FailedPrecondition);
    };
    reject(&[]);
    reject(&ok[..FRAME_LEN - 1]);
    let mutate = |at: usize, v: u8| {
        let mut b = ok;
        b[at] = v;
        b
    };
    reject(&mutate(0, 0)); // magic
    reject(&mutate(4, 0)); // version
    reject(&mutate(5, 1)); // 要求種別（方向の取り違え）
    reject(&mutate(5, 4)); // 未知の種別
    reject(&mutate(7, 1)); // 予約欄
    reject(&mutate(10, 1));
    reject(&mutate(8, 1)); // Error の port は 0 のみ
    reject(&mutate(12, 0)); // エラーコード 0
    reject(&mutate(12, 7)); // エラーコード範囲外
    // Connected は port・tail が 0 のみ。
    let connected = *DialResponseFrame::encode(DialResponse::Connected).as_bytes();
    let mut b = connected;
    b[12] = 1;
    reject(&b);
    let mut b = connected;
    b[8] = 1;
    reject(&b);
    // 要求のバイト列を応答として読めない。
    reject(DialRequestFrame::encode(request(80, 1)).as_bytes());
}
