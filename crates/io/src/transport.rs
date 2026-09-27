//! パイプライン送信・バッチ ACK に使う送受信抽象（TASK-11.1・IO-1）。
//!
//! ホストとゲストの間のファイル共有プロトコル（IO-1）で、TASK-12（パイプライン送信
//! クライアント）・TASK-13（バッチ write-back サーバー）・TASK-83 が共通で使う「送受信の
//! 抽象」をここで定める。フレームの具体形（ヘッダ newtype・チェックサム）は
//! TASK-11.2（#69）・TASK-11.3（#70）が `protocol` モジュールに追加する。本モジュールは
//! 現時点でフレーム型の実装を 1 つも持たない（REPAIR-3。実装済みを装わない）。
//!
//! OS 固有の型（`std::os::unix` 等）・`cfg(target_os = ...)` 分岐は持たない。UDS・vsock・
//! named pipe などの具象トランスポート実装は後続タスクの担当 crate / モジュールに置く。

use std::time::Duration;

use crate::error::{IoError, IoErrorCode};

/// パイプライン送信・バッチ ACK が上限時間を超えて待ち続けないための境界
/// （AGENTS.md の CI 結合試験ステップ上限 10 分に合わせる。値の見直しは
/// TASK-12・TASK-13 で行う）。
pub const MAX_IO_TIMEOUT: Duration = Duration::from_secs(600);

/// [`FrameSender::send_frame`]・[`FrameReceiver::recv_frame`] に渡すタイムアウト。
///
/// `Duration::ZERO`（「待たない」と「即時タイムアウト」の曖昧さがある）と
/// [`MAX_IO_TIMEOUT`] 超過を構築時に拒否し、無期限待ちを型として表現できないようにする
/// （REPAIR-5）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IoTimeout(Duration);

impl IoTimeout {
    /// 上限付きタイムアウトを作る。
    ///
    /// `duration` が `Duration::ZERO` または [`MAX_IO_TIMEOUT`] を超える場合は
    /// [`IoErrorCode::InvalidArgument`] を返す。
    pub fn new(duration: Duration) -> Result<Self, IoError> {
        if duration == Duration::ZERO {
            return Err(IoError::new(
                IoErrorCode::InvalidArgument,
                "io timeout must not be zero",
            ));
        }
        if duration > MAX_IO_TIMEOUT {
            return Err(IoError::new(
                IoErrorCode::InvalidArgument,
                format!("io timeout must be at most {MAX_IO_TIMEOUT:?}"),
            ));
        }
        Ok(Self(duration))
    }

    /// タイムアウト値を `Duration` として返す。
    pub fn as_duration(&self) -> Duration {
        self.0
    }
}

impl TryFrom<Duration> for IoTimeout {
    type Error = IoError;

    fn try_from(value: Duration) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

/// crate 外からの実装を禁じるための封印（sealed pattern）。
///
/// [`WireFrame`] を実装できるのは本 crate 内の検証済みフレーム型だけに限る
/// （REPAIR-2: 生バイト列を公開 API の関連型に指定させない）。
mod sealed {
    /// [`super::WireFrame`] の封印用トレイト。crate 外はこれを実装できない。
    pub trait Sealed {}
}

/// パイプライン送信・バッチ ACK でやり取りする「壊れたフレームを表現できない」型の境界
/// （REPAIR-2）。
///
/// 実装できるのは本 crate 内で構築時に検証済みのフレーム型のみ（[`sealed::Sealed`] で
/// 封印）。長さ上限の検証・チェックサムの検証はフレーム型の構築時（TASK-11.2・
/// TASK-11.3）に行われ、[`FrameReceiver::recv_frame`] は検証済みの値だけを返す契約と
/// する。本 crate は現時点でこのトレイトを実装する非テストの型を 1 つも持たない
/// （REPAIR-3）。
pub trait WireFrame: sealed::Sealed + Send + core::fmt::Debug {}

/// フレームをトランスポートへ送る側の抽象（IO-1: パイプライン送信）。
///
/// # 契約
/// - `send_frame` は相手の ACK を待たずに戻る。`Ok(())` は「トランスポートへ書き出した」
///   ことだけを意味し、相手の受理・永続化を保証しない。
/// - ACK の種別（通常の書き込み ACK と FLUSH ACK。IO-2）はフレーム種別
///   （TASK-11.2・TASK-11.3）と TASK-12・TASK-13・TASK-15 が扱う。本トレイトは
///   ACK の意味論を持たない。
/// - `timeout` 以内に書き出せなければ [`IoErrorCode::Timeout`] を返す（REPAIR-5:
///   無期限にブロックしない）。
/// - `&mut self` を要求し、1 つの接続を同時に使えるのは 1 スレッドのみとする
///   （ソケットのような状態を持つトランスポートを想定）。並行化（送信側と受信側の分割）は
///   TASK-12 で扱う。
pub trait FrameSender: Send {
    /// このトランスポートが送るフレームの型。
    type Frame: WireFrame;

    /// フレームをトランスポートへ書き出す。ACK は待たない。
    fn send_frame(&mut self, frame: &Self::Frame, timeout: IoTimeout) -> Result<(), IoError>;
}

/// フレームをトランスポートから受け取る側の抽象（IO-1）。
///
/// # 契約
/// - `timeout` 以内にフレームが揃わなければ [`IoErrorCode::Timeout`] を返す
///   （無期限にブロックしない。REPAIR-5）。
/// - 相手が切断していれば [`IoErrorCode::Unavailable`] を返す。
/// - 受信したバイト列の検証（長さ上限・チェックサム）は `Self::Frame` の構築時
///   （TASK-11.2・TASK-11.3）に行われ、`recv_frame` は検証済みの値のみを返す。
/// - `&mut self` を要求し、1 つの接続を同時に使えるのは 1 スレッドのみとする。
pub trait FrameReceiver: Send {
    /// このトランスポートが受け取るフレームの型。
    type Frame: WireFrame;

    /// トランスポートからフレームを 1 つ受け取る。`timeout` 以内に揃わなければ
    /// [`IoErrorCode::Timeout`] を返す。
    fn recv_frame(&mut self, timeout: IoTimeout) -> Result<Self::Frame, IoError>;
}

/// 送受信を両方持つトランスポートの名前（IO-1）。
///
/// 送信スレッドと ACK 受信スレッドを並行に動かすパイプライン送信のため、
/// [`FrameSender`]・[`FrameReceiver`] を別トレイトに分けている。送信側・受信側への
/// 分割 API（`split()` 等）は OS ごとのソケット実装に依存するため、本件では定義せず
/// TASK-12 で決める。
///
/// フレーム型の一致（`FrameSender::Frame == FrameReceiver::Frame`）は、supertrait の
/// 宣言で `FrameReceiver<Frame = <Self as FrameSender>::Frame>` という関連型の等式
/// 制約を課すことでコンパイル時に強制する（REPAIR-2: 型の不一致を実装者の注意のみに
/// 委ねない）。`Box<dyn FrameTransport<Frame = F>>` のように `FrameTransport` 自体が
/// 関連型 `Frame` を持つ形にすると呼び出し側で出どころが曖昧になる（E0222）ため、
/// `FrameTransport` 自身は関連型を持たせず、supertrait 境界としてのみ等式制約を課す。
pub trait FrameTransport:
    FrameSender + FrameReceiver<Frame = <Self as FrameSender>::Frame>
{
}

impl<T> FrameTransport for T where T: FrameSender + FrameReceiver<Frame = <T as FrameSender>::Frame> {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    /// テスト専用のフレーム型。`Sealed` は crate 内のみ実装できるため、
    /// このモジュール（crate 内）からのみ `WireFrame` を実装できる。
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct MockFrame(u32);

    impl sealed::Sealed for MockFrame {}
    impl WireFrame for MockFrame {}

    /// テスト専用の mock トランスポート。送信したフレームをキューへ積み、
    /// 受信はキューから取り出す（キューが空なら Timeout を返す）。
    #[derive(Debug, Default)]
    struct MockTransport {
        queue: VecDeque<MockFrame>,
    }

    impl FrameSender for MockTransport {
        type Frame = MockFrame;

        fn send_frame(&mut self, frame: &Self::Frame, _timeout: IoTimeout) -> Result<(), IoError> {
            self.queue.push_back(frame.clone());
            Ok(())
        }
    }

    impl FrameReceiver for MockTransport {
        type Frame = MockFrame;

        fn recv_frame(&mut self, _timeout: IoTimeout) -> Result<Self::Frame, IoError> {
            self.queue
                .pop_front()
                .ok_or_else(|| IoError::new(IoErrorCode::Timeout, "mock queue is empty"))
        }
    }

    fn test_timeout() -> IoTimeout {
        IoTimeout::new(Duration::from_millis(1)).expect("1ms must be a valid timeout")
    }

    /// IO-1: `Duration::ZERO` は `InvalidArgument` として拒否される。
    #[test]
    fn io1_io_timeout_rejects_zero() {
        let err = IoTimeout::new(Duration::ZERO).expect_err("zero must be rejected");
        assert_eq!(err.code(), IoErrorCode::InvalidArgument);
    }

    /// IO-1: 1ns と `MAX_IO_TIMEOUT` はちょうど受理され、値が保持される。
    #[test]
    fn io1_io_timeout_accepts_boundaries() {
        let lower = IoTimeout::new(Duration::from_nanos(1)).expect("1ns must be accepted");
        assert_eq!(lower.as_duration(), Duration::from_nanos(1));

        let upper = IoTimeout::new(MAX_IO_TIMEOUT).expect("MAX_IO_TIMEOUT must be accepted");
        assert_eq!(upper.as_duration(), MAX_IO_TIMEOUT);
    }

    /// IO-1: `MAX_IO_TIMEOUT` 超過・`Duration::MAX` は `InvalidArgument` として拒否される。
    #[test]
    fn io1_io_timeout_rejects_above_max() {
        let just_over = MAX_IO_TIMEOUT + Duration::from_nanos(1);
        let err = IoTimeout::new(just_over).expect_err("MAX_IO_TIMEOUT + 1ns must be rejected");
        assert_eq!(err.code(), IoErrorCode::InvalidArgument);

        let err_max = IoTimeout::new(Duration::MAX).expect_err("Duration::MAX must be rejected");
        assert_eq!(err_max.code(), IoErrorCode::InvalidArgument);
    }

    /// IO-1: `FrameSender` / `FrameReceiver` はそれぞれ dyn 互換であり、
    /// `Box<dyn FrameSender<..>>` / `Box<dyn FrameReceiver<..>>` として呼び出せる。
    /// 送信したフレームを（具象型のまま）受信で 1 件往復して取り出せることも確認する。
    #[test]
    fn io1_frame_sender_and_receiver_are_dyn_compatible() {
        // 具象型のまま送受信し、往復（send → recv）が成立することを確認する。
        let mut transport = MockTransport::default();
        let frame = MockFrame(42);
        transport
            .send_frame(&frame, test_timeout())
            .expect("send must succeed");
        let received = transport
            .recv_frame(test_timeout())
            .expect("recv must succeed");
        assert_eq!(received, frame);

        // FrameSender の dyn 互換性: Box<dyn FrameSender<..>> として呼び出せる。
        let mut sender: Box<dyn FrameSender<Frame = MockFrame>> =
            Box::new(MockTransport::default());
        sender
            .send_frame(&frame, test_timeout())
            .expect("send via dyn FrameSender must succeed");

        // FrameReceiver の dyn 互換性: Box<dyn FrameReceiver<..>> として呼び出せる。
        // 空のキューからは Timeout が返る契約を確認する。
        let mut receiver: Box<dyn FrameReceiver<Frame = MockFrame>> =
            Box::new(MockTransport::default());
        let err = receiver
            .recv_frame(test_timeout())
            .expect_err("empty queue must time out");
        assert_eq!(err.code(), IoErrorCode::Timeout);
    }

    /// IO-1: mock がジェネリック関数上で `FrameTransport` として受理される
    /// （blanket impl の成立とメソッド呼び出しの確認）。フレーム型の一致は
    /// `where` 節で明示し、`FrameTransport` 自体には持たせていない設計を反映する。
    #[test]
    fn io1_frame_transport_blanket_impl_applies() {
        fn use_transport<T>(t: &mut T)
        where
            T: FrameTransport + FrameSender<Frame = MockFrame> + FrameReceiver<Frame = MockFrame>,
        {
            let frame = MockFrame(7);
            FrameSender::send_frame(t, &frame, test_timeout()).expect("send must succeed");
            let received = FrameReceiver::recv_frame(t, test_timeout()).expect("recv must succeed");
            assert_eq!(received, frame);
        }

        let mut transport = MockTransport::default();
        use_transport(&mut transport);
    }

    fn assert_send<T: Send>() {}

    /// IO-1: `FrameSender` / `FrameReceiver` の実装は `Send` を満たす。
    #[test]
    fn io1_mock_transport_is_send() {
        assert_send::<MockTransport>();
    }
}
