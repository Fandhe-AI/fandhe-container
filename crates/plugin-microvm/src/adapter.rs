//! 要求ハンドラ（`frame_loop::RequestHandler` の実装）。TASK-117.1・#710。PLUG-1・MVM-1・REPAIR-3。
//!
//! 呼び出し元: `main.rs` が `frame_loop::serve` へ渡す。core 側 proxy（#1869 の設計）が送る要求の先頭要素
//! （操作名）で分岐する暫定契約（本体 `Vec<String>`）。VM 内部の I/O パスは plugin 境界の対象外（MVM-1）。
//!
//! # 操作
//! | 操作 | 要求 | 応答 |
//! | ---- | ---- | ---- |
//! | ping | `["ping"]`（要素 1 つ） | `["pong"]` |
//!
//! 余分な要素つきの `ping` は固定文言の `INVALID_ARGUMENT`。それ以外の操作は `UNIMPLEMENTED`
//! （実装済みを装わない。microVM の start / stop は TASK-117.2・#711 で `fandhe-container-microvm` へ委譲して実装する。REPAIR-3）。

use fandhe_container_plugin::{PluginError, PluginErrorCode};

use crate::frame_loop::RequestHandler;

/// ヘルスチェック操作名。
pub const OP_PING: &str = "ping";
/// `ping` の応答。
pub const REPLY_PONG: &str = "pong";

const MSG_MALFORMED: &str = "malformed request";
const MSG_UNIMPLEMENTED: &str = "operation is not implemented";

/// microVM 制御のアダプタ（暫定名）。今は `ping` のみ処理する。
#[derive(Debug, Default, Clone, Copy)]
pub struct MicrovmRuntimeAdapter;

impl MicrovmRuntimeAdapter {
    /// 新しいアダプタを作る。
    pub fn new() -> Self {
        Self
    }
}

impl RequestHandler for MicrovmRuntimeAdapter {
    fn handle(&mut self, body: &[String]) -> Result<Vec<String>, PluginError> {
        match body.first().map(String::as_str) {
            Some(OP_PING) if body.len() == 1 => Ok(vec![REPLY_PONG.to_string()]),
            Some(OP_PING) => Err(PluginError::new(
                PluginErrorCode::InvalidArgument,
                MSG_MALFORMED,
            )),
            _ => Err(PluginError::new(
                PluginErrorCode::Unimplemented,
                MSG_UNIMPLEMENTED,
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    /// MVM-1・PLUG-1: ping は pong を返し、余分な要素は固定文言で拒否する（入力値を反射しない）。
    #[test]
    fn mvm1_plug1_ping_returns_pong_and_rejects_extra() {
        let mut a = MicrovmRuntimeAdapter::new();
        assert_eq!(a.handle(&s(&["ping"])).expect("ping"), s(&["pong"]));
        let e = a.handle(&s(&["ping", "SECRETARG"])).unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::InvalidArgument);
        assert_eq!(e.message(), "malformed request");
    }

    /// PLUG-1・REPAIR-3: 未実装の操作は UNIMPLEMENTED（入力値を含めない）。
    #[test]
    fn plug1_unknown_op_is_unimplemented() {
        let mut a = MicrovmRuntimeAdapter::new();
        for op in ["start", "stop", "SECRETOP"] {
            let e = a.handle(&s(&[op, "x"])).unwrap_err();
            assert_eq!(e.code(), PluginErrorCode::Unimplemented);
            assert_eq!(e.message(), "operation is not implemented");
        }
    }
}
