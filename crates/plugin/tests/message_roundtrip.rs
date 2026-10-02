//! 制御メッセージがフレームのワイヤー表現を通っても保たれることの結合試験
//! （PLUG-2・TASK-107.3・#247）。公開 API のみを使う。

use fandhe_container_plugin::{
    ControlMessage, Frame, MessageId, PluginErrorCode, decode_message, encode_message,
};

#[test]
fn plug2_message_survives_frame_wire_roundtrip() {
    let msg = ControlMessage::Request {
        id: MessageId::new(42),
        body: vec!["a".to_string(), "あ".to_string()],
    };
    let wire = encode_message(&msg).expect("encode").encode();
    let frame = Frame::decode(&wire).expect("frame decode");
    let back: ControlMessage<Vec<String>> = decode_message(&frame).expect("decode");
    assert_eq!(back, msg);
}

#[test]
fn plug2_bit_flip_on_wire_is_data_loss() {
    let msg = ControlMessage::Response {
        id: MessageId::new(1),
        body: "ok".to_string(),
    };
    let mut wire = encode_message(&msg).expect("encode").encode();
    let mid = wire.len() / 2;
    if let Some(b) = wire.get_mut(mid) {
        *b ^= 0x01;
    }
    let e = Frame::decode(&wire).expect_err("must fail");
    assert_eq!(e.code(), PluginErrorCode::DataLoss);
}
