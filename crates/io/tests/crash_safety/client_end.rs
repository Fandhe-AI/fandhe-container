//! 結合試験用の UDS クライアント端点（`crash_safety.rs` と `power_loss.rs` が `#[path]` で共有する）。
//!
//! 本番の UDS クライアント `UdsClientConnection`（#3165）は接続前のパス検査と接続先 uid の照合を
//! 伴う。単一 sink モードのケースと `power_loss.rs` は生の `UnixStream` で接続したいため、std の
//! `UnixStream` を `FrameSender` / `FrameReceiver` として包み、`PipelineClient` から使えるようにする
//! この試験用の端点を残している（IO-1・IO-2・IO-3。TASK-18）。ファイル操作モードのケース
//! （#3167）は本番の `UdsClientConnection` を使う。

use std::io::{Read, Write as _};
use std::os::unix::net::UnixStream;

use fandhe_container_io::{
    FRAME_HEADER_LEN, Frame, FrameHeader, FrameReceiver, FrameSender, IoError, IoErrorCode,
    IoTimeout,
};

/// テスト用の UDS クライアント端点（`FrameSender` + `FrameReceiver`）。
///
/// 本番の `UdsClientConnection`（#3165）の接続前検査を通さずに生の `UnixStream` で接続する
/// 試験のために、`PipelineClient` から使えるよう std の `UnixStream` を包む。ACK の順序・種別の
/// 検証は `PipelineClient::recv_ack` に任せ、ここでは観測数を水増ししない。
/// 一度でも `Err` を返したら以後は `Unavailable` を返す（transport の poison 契約と同じ）。
pub struct UnixClientEnd {
    stream: UnixStream,
    poisoned: bool,
}

impl UnixClientEnd {
    pub fn new(stream: UnixStream) -> Self {
        Self {
            stream,
            poisoned: false,
        }
    }

    fn fail(&mut self, e: &std::io::Error) -> IoError {
        self.poisoned = true;
        let code = match e.kind() {
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => IoErrorCode::Timeout,
            _ => IoErrorCode::Unavailable,
        };
        IoError::new(code, format!("unix client io failed: {e}"))
    }

    fn poisoned_error() -> IoError {
        IoError::new(
            IoErrorCode::Unavailable,
            "unix client end is poisoned by a previous error",
        )
    }
}

impl FrameSender for UnixClientEnd {
    type Frame = Frame;

    fn send_frame(&mut self, frame: &Frame, timeout: IoTimeout) -> Result<(), IoError> {
        if self.poisoned {
            return Err(Self::poisoned_error());
        }
        let result = self
            .stream
            .set_write_timeout(Some(timeout.as_duration()))
            .and_then(|()| self.stream.write_all(&frame.encode()));
        result.map_err(|e| self.fail(&e))
    }
}

impl FrameReceiver for UnixClientEnd {
    type Frame = Frame;

    fn recv_frame(&mut self, timeout: IoTimeout) -> Result<Frame, IoError> {
        if self.poisoned {
            return Err(Self::poisoned_error());
        }
        let mut header_bytes = [0u8; FRAME_HEADER_LEN];
        if let Err(e) = self
            .stream
            .set_read_timeout(Some(timeout.as_duration()))
            .and_then(|()| self.stream.read_exact(&mut header_bytes))
        {
            return Err(self.fail(&e));
        }
        let header = match FrameHeader::from_bytes(header_bytes) {
            Ok(h) => h,
            Err(e) => {
                self.poisoned = true;
                return Err(e);
            }
        };
        // body 長は検証済みの FrameHeader（MAX_FRAME_LEN 以内）の値だけを使う
        let mut body = vec![0u8; header.body_len()];
        if let Err(e) = self.stream.read_exact(&mut body) {
            return Err(self.fail(&e));
        }
        match Frame::decode_body(header, &body) {
            Ok(frame) => Ok(frame),
            Err(e) => {
                self.poisoned = true;
                Err(e)
            }
        }
    }
}
