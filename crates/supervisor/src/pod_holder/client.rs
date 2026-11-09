//! 保持役の READY を期限つきで受ける受信側の補助（Linux のみ。CRI-2・REPAIR-5・#2874）。
//!
//! 呼び出し元は plugin-cri の保持役の起動処理（H6・#2877）と実機試験。長さは [`FRAME_LEN`] に固定され、
//! 待ちは `poll(2)` の `timeout = 0` の確認と短い sleep の繰り返しで、スレッドも新しい unsafe も使わない。
//! 文言は固定の英文で、受信内容・errno を含めない（REPAIR-4）。

use std::fs::File;
use std::io::Read as _;
use std::os::fd::BorrowedFd;
use std::time::{Duration, Instant};

use fandhe_container_core::traits::types::{ErrorCode, TraitError};

use super::frame::{FRAME_LEN, PodHolderFrame, PodHolderMessage, PodHolderReady};
use crate::sys;

/// ポーリングの間隔。
const POLL_STEP: Duration = Duration::from_millis(5);

fn err(code: ErrorCode, message: &'static str) -> TraitError {
    TraitError::new(code, message)
}

/// `fd`（保持役の stdout の読み端）から READY をちょうど [`FRAME_LEN`] バイト読んで解釈する。
///
/// 期限切れは `Timeout`、期限前の EOF・不正なフレームは `FailedPrecondition`、ERROR フレームはそのコードの
/// `TraitError` を返す。fd の所有は呼び出し側に残る。
pub fn read_ready(fd: BorrowedFd<'_>, deadline: Instant) -> Result<PodHolderReady, TraitError> {
    let owned = fd.try_clone_to_owned().map_err(|_| {
        err(
            ErrorCode::Internal,
            "failed to duplicate the holder channel",
        )
    })?;
    let mut file = File::from(owned);
    let mut buf = [0u8; FRAME_LEN];
    let mut filled = 0usize;
    while filled < FRAME_LEN {
        if Instant::now() >= deadline {
            return Err(err(
                ErrorCode::Timeout,
                "timed out waiting for the pod holder",
            ));
        }
        let revents = sys::poll_revents_now(fd, sys::POLL_IN)
            .map_err(|_| err(ErrorCode::Internal, "failed to poll the holder channel"))?;
        if revents == 0 {
            let left = deadline.saturating_duration_since(Instant::now());
            std::thread::sleep(POLL_STEP.min(left));
            continue;
        }
        let Some(dst) = buf.get_mut(filled..) else {
            break;
        };
        match file.read(dst) {
            Ok(0) => {
                return Err(err(
                    ErrorCode::FailedPrecondition,
                    "the pod holder closed the channel before READY",
                ));
            }
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => {
                return Err(err(
                    ErrorCode::Internal,
                    "failed to read the holder channel",
                ));
            }
        }
    }
    match PodHolderFrame::decode(&buf)? {
        PodHolderMessage::Ready(r) => Ok(r),
        PodHolderMessage::Error(code) => Err(err(code, "the pod holder reported a failure")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pod_holder::frame::NsId;
    use std::io::Write as _;
    use std::os::fd::AsFd as _;

    fn ready() -> PodHolderReady {
        let ns = |i| NsId { dev: 4, ino: i };
        PodHolderReady::new(77, ns(10), ns(11), ns(12)).unwrap()
    }

    fn soon() -> Instant {
        Instant::now() + Duration::from_secs(5)
    }

    /// CRI-2・REPAIR-5・#2874: 正常、分割到着、EOF、期限切れ、ERROR、壊れたフレームを具体値で。
    #[test]
    fn cri2_read_ready_cases() {
        let (r, mut w) = std::io::pipe().unwrap();
        let frame = PodHolderFrame::ready(&ready());
        w.write_all(frame.as_bytes()).unwrap();
        assert_eq!(read_ready(r.as_fd(), soon()).unwrap(), ready());

        // 分割到着。
        let (r, mut w) = std::io::pipe().unwrap();
        let bytes = *frame.as_bytes();
        let t = std::thread::spawn(move || {
            w.write_all(&bytes[..10]).unwrap();
            std::thread::sleep(Duration::from_millis(50));
            w.write_all(&bytes[10..]).unwrap();
        });
        assert_eq!(read_ready(r.as_fd(), soon()).unwrap(), ready());
        t.join().unwrap();

        // 途中の EOF。
        let (r, mut w) = std::io::pipe().unwrap();
        w.write_all(&frame.as_bytes()[..5]).unwrap();
        drop(w);
        let e = read_ready(r.as_fd(), soon()).unwrap_err();
        assert_eq!(e.code(), ErrorCode::FailedPrecondition);

        // 期限切れ（書き端は開いたまま）。
        let (r, _w) = std::io::pipe().unwrap();
        let e = read_ready(r.as_fd(), Instant::now() + Duration::from_millis(50)).unwrap_err();
        assert_eq!(e.code(), ErrorCode::Timeout);

        // ERROR フレーム。
        let (r, mut w) = std::io::pipe().unwrap();
        w.write_all(PodHolderFrame::error(ErrorCode::PermissionDenied).as_bytes())
            .unwrap();
        let e = read_ready(r.as_fd(), soon()).unwrap_err();
        assert_eq!(e.code(), ErrorCode::PermissionDenied);

        // 壊れたフレーム。
        let (r, mut w) = std::io::pipe().unwrap();
        w.write_all(&[0xAB; FRAME_LEN]).unwrap();
        let e = read_ready(r.as_fd(), soon()).unwrap_err();
        assert_eq!(e.code(), ErrorCode::FailedPrecondition);
    }
}
