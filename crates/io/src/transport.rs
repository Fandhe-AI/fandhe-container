//! パイプライン送信・バッチ ACK に使う送受信抽象（TASK-11.1・IO-1・MS-1）。
//!
//! ホストとゲストの間のファイル共有プロトコル（IO-1）で、TASK-12（パイプライン送信
//! クライアント）・TASK-13（バッチ write-back サーバー）・TASK-83 が共通で使う「送受信の
//! 抽象」をここで定める。フレームの具体形（ヘッダ newtype・チェックサム付きフレーム
//! 全体型）は TASK-11.2（#69）・TASK-11.3（#70）が `protocol` モジュールに追加した
//! （[`crate::protocol::Frame`]。REPAIR-2）。本モジュール自体はトランスポートの具象実装
//! （UDS・vsock・named pipe 等）を持たない（REPAIR-3。実装済みを装わない）。
//!
//! OS 固有の型（`std::os::unix` 等）・`cfg(target_os = ...)` 分岐は持たない。UDS・vsock・
//! named pipe などの具象トランスポート実装は後続タスクの担当 crate / モジュールに置く。
//! UDS のサーバー側（Linux / macOS）は [`crate::server`] が TASK-13.2.1（#820）で
//! 具象実装を追加した。
//!
//! 1 本の接続を送信側・受信側へ分けて別スレッドから並行に使う API は
//! [`SplitTransport`]（#1118・IO-1・P1-3・REPAIR-5）が定める。

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use crate::error::{IoError, IoErrorCode};

/// ACK・plugin RPC・子プロセスなど「相手の応答を 1 回待つ」処理が上限時間を超えて
/// 待ち続けないための境界（REPAIR-5・IO-1）。
///
/// AGENTS.md「推奨タイムアウト値」（REPAIR-5・REPAIR-10 (c)）が個別の応答待ちに定める
/// 既定レンジ（5〜10 秒。PoC-8 実測・CI の `FANDHE_CONTAINER_TEST_TIMEOUT_SECS: "10"`）の
/// 上限に合わせる。結合試験ステップ全体の上限（10 分。TASK-86.2・#36）や
/// ジョブ全体の上限とは別物であり、それらは [`FrameSender::send_frame`]・
/// [`FrameReceiver::recv_frame`] 呼び出し 1 回分の待ち時間には使わない
/// （長時間待機が必要な用途が生じた場合は、この定数を流用せず別の型・定数として
/// 分離し、根拠を明記する）。
pub const MAX_IO_TIMEOUT: Duration = Duration::from_secs(10);

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
///
/// `pub(crate)` にして crate 内の兄弟モジュールから参照できるようにしている。
/// `protocol` モジュールのフレーム型（[`crate::protocol::Frame`]。TASK-11.2（#69）・
/// TASK-11.3（#70））が `sealed::Sealed` を実装できる必要があるため（`protocol` は
/// `transport` の親ではなく兄弟モジュールで、`mod` 既定の非公開のままだと参照できない）。
/// crate 外からは `sealed` モジュール自体が非公開のままなので封印の効果は変わらない。
pub(crate) mod sealed {
    /// [`super::WireFrame`] の封印用トレイト。crate 外はこれを実装できない。
    pub trait Sealed {}
}

/// パイプライン送信・バッチ ACK でやり取りする「壊れたフレームを表現できない」型の境界
/// （REPAIR-2）。
///
/// 実装できるのは本 crate 内で構築時に検証済みのフレーム型のみ（[`sealed::Sealed`] で
/// 封印）。長さ上限の検証・チェックサムの検証はフレーム型の構築時（TASK-11.2・
/// TASK-11.3）に行われ、[`FrameReceiver::recv_frame`] は検証済みの値だけを返す契約と
/// する。本 crate では [`crate::protocol::Frame`]（TASK-11.3・#70）がこのトレイトを
/// 実装する。
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
///   （ソケットのような状態を持つトランスポートを想定）。送信側と受信側を別スレッドで
///   並行に使いたい場合は [`SplitTransport::split`] で分割する（#1118）。
///
/// # エラー後の接続再利用（P1-3・設計レビュー・2026-09-28 オーナー決定・REPAIR-5・
/// REPAIR-6）
/// [`Self::send_frame`] が [`IoErrorCode::Timeout`]・[`IoErrorCode::DataLoss`]・
/// [`IoErrorCode::InvalidArgument`]・[`IoErrorCode::Unimplemented`] 等、いずれの
/// エラーを返した後も、その接続は以後**使用不可**とする（fail-closed）。
/// [`FrameHeader`](crate::protocol::FrameHeader) には同期マーカー（フレーム境界を
/// 再同期するための番兵バイト列）がないため、送信の途中でエラーが起きると、
/// 相手側が受信中のバイト列のどこまでを読んだかを送信側が知る手段がなく、
/// 以後のバイト列がフレーム境界からずれて解釈される可能性がある。実装は
/// エラーを返した後の呼び出しに対して実際の読み書きを一切行わず
/// [`IoErrorCode::Unavailable`] を返さなければならず、呼び出し元は同じ接続を
/// 再利用せず再接続しなければならない。
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
///
/// # エラー後の接続再利用（P1-3・設計レビュー・2026-09-28 オーナー決定・REPAIR-5・
/// REPAIR-6）
/// [`FrameSender::send_frame`] のドキュメンテーションコメントと同じ契約が
/// [`Self::recv_frame`] にも適用される。[`Self::recv_frame`] がいずれのエラー
/// （[`IoErrorCode::Timeout`] を含む）を返した後も、その接続は以後使用不可と
/// なる。実装は途中まで読んだ不完全なバイト列を次回呼び出しへ持ち越して
/// 「続きから読む」処理をしてはならない（フレーム境界がずれた状態から
/// 再開すると、以後のフレームをすべて誤ったオフセットで解釈しうるため）。
/// エラー後の呼び出しは即座に [`IoErrorCode::Unavailable`] を返し、呼び出し元は
/// 再接続すること。
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
/// [`FrameSender`]・[`FrameReceiver`] を別トレイトに分けている。1 本の接続を送信側・
/// 受信側へ分ける API は [`SplitTransport`]（#1118）が定める。
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

/// 両半分が共有する poison 状態（P1-3・#1118）。
///
/// 分割後の送信側・受信側のどちらかがエラーを返したら立て、もう片側の以後の呼び出しを
/// I/O なしで [`IoErrorCode::Unavailable`] にする（fail-closed）。具象トランスポート
/// （[`crate::server`] の分割型）が使う内部部品で、公開面は増やさない。
#[derive(Debug, Clone, Default)]
pub(crate) struct SharedPoison(Arc<AtomicBool>);

impl SharedPoison {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// poison を立てる。もう片側の Acquire 読み出しから観測できるよう Release にする。
    pub(crate) fn poison(&self) {
        self.0.store(true, Ordering::Release);
    }

    pub(crate) fn is_poisoned(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

/// 1 本の接続を送信側・受信側へ分けられるトランスポート（IO-1・P1-3・REPAIR-5・#1118）。
///
/// パイプライン送信で送信スレッドと ACK 受信スレッドを並行に動かすために使う。
/// OS 非依存のトレイトで、UDS サーバー側の [`crate::server::UdsConnection`]
/// （Linux / macOS）が実装する。将来のクライアント接続型も同じ形で実装する。
///
/// # 契約
/// - [`Self::split`] は `self` を消費する。分割前の値は分割後に使えない（型で保証）。
/// - すでに poison 済み（エラー後）の接続の `split` は [`IoErrorCode::Unavailable`] を
///   返し、接続は閉じる（P1-3: 再利用させない）。fd の複製に失敗した場合も `Err` を
///   返し、接続は閉じる（呼び出し元は再接続する）。
/// - **poison の共有（P1-3）**: 両半分は poison 状態を共有する。片側がエラーを返したら
///   もう片側の以後の呼び出しは I/O なしで `Unavailable` を返し、ブロック中の
///   呼び出しも接続の shutdown で速やかに `Unavailable` になる。
/// - **期限（REPAIR-5）・受信上限**: 各呼び出しは [`IoTimeout`] で打ち切られ、受信側の
///   受信上限（`ReceiveLimits`。TASK-13.4）も分割前と同じ。
/// - **片側だけ drop した場合**: 送信側の drop は（poison されていなければ）書き込み側の
///   half-close となり、相手は EOF を受けるが受信側はそのまま使える。受信側の drop は
///   何もしない。どちらの drop も poison を立てない。
pub trait SplitTransport: FrameTransport + Sized {
    /// 分割後の送信側。
    type SendHalf: FrameSender<Frame = <Self as FrameSender>::Frame> + Send;
    /// 分割後の受信側。
    type RecvHalf: FrameReceiver<Frame = <Self as FrameSender>::Frame> + Send;

    /// 接続を送信側・受信側へ分ける。
    fn split(self) -> Result<(Self::SendHalf, Self::RecvHalf), IoError>;
}

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
    ///
    /// `poisoned` は P1-3（エラー後の接続再利用禁止。REPAIR-5・REPAIR-6）の契約を
    /// 検証するための状態。[`FrameSender::send_frame`] / [`FrameReceiver::recv_frame`]
    /// のいずれかが一度でも `Err` を返すと `true` になり、以後は両メソッドとも
    /// キューに触れず [`IoErrorCode::Unavailable`] を返す。
    #[derive(Debug, Default)]
    struct MockTransport {
        queue: VecDeque<MockFrame>,
        poisoned: bool,
    }

    impl FrameSender for MockTransport {
        type Frame = MockFrame;

        fn send_frame(&mut self, frame: &Self::Frame, _timeout: IoTimeout) -> Result<(), IoError> {
            if self.poisoned {
                return Err(IoError::new(
                    IoErrorCode::Unavailable,
                    "connection is poisoned by a previous error and must be reconnected",
                ));
            }
            self.queue.push_back(frame.clone());
            Ok(())
        }
    }

    impl FrameReceiver for MockTransport {
        type Frame = MockFrame;

        fn recv_frame(&mut self, _timeout: IoTimeout) -> Result<Self::Frame, IoError> {
            if self.poisoned {
                return Err(IoError::new(
                    IoErrorCode::Unavailable,
                    "connection is poisoned by a previous error and must be reconnected",
                ));
            }
            match self.queue.pop_front() {
                Some(frame) => Ok(frame),
                None => {
                    self.poisoned = true;
                    Err(IoError::new(IoErrorCode::Timeout, "mock queue is empty"))
                }
            }
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

    /// 共有 poison を持つ分割可能な mock（#1118）。`fail_next` が立つと次の呼び出しが
    /// `Timeout` を返して poison を立てる。
    #[derive(Debug, Default)]
    struct MockSplit {
        queue: VecDeque<MockFrame>,
        poison: SharedPoison,
        fail_next: bool,
    }

    #[derive(Debug)]
    struct MockSendHalf {
        queue: std::sync::Arc<std::sync::Mutex<VecDeque<MockFrame>>>,
        poison: SharedPoison,
        fail_next: bool,
    }

    #[derive(Debug)]
    struct MockRecvHalf {
        queue: std::sync::Arc<std::sync::Mutex<VecDeque<MockFrame>>>,
        poison: SharedPoison,
        fail_next: bool,
    }

    fn poisoned_err() -> IoError {
        IoError::new(
            IoErrorCode::Unavailable,
            "connection is poisoned by a previous error and must be reconnected",
        )
    }

    impl FrameSender for MockSplit {
        type Frame = MockFrame;
        fn send_frame(&mut self, frame: &MockFrame, _t: IoTimeout) -> Result<(), IoError> {
            if self.poison.is_poisoned() {
                return Err(poisoned_err());
            }
            self.queue.push_back(frame.clone());
            Ok(())
        }
    }

    impl FrameReceiver for MockSplit {
        type Frame = MockFrame;
        fn recv_frame(&mut self, _t: IoTimeout) -> Result<MockFrame, IoError> {
            if self.poison.is_poisoned() {
                return Err(poisoned_err());
            }
            self.queue
                .pop_front()
                .ok_or_else(|| IoError::new(IoErrorCode::Timeout, "mock queue is empty"))
        }
    }

    impl FrameSender for MockSendHalf {
        type Frame = MockFrame;
        fn send_frame(&mut self, frame: &MockFrame, _t: IoTimeout) -> Result<(), IoError> {
            if self.poison.is_poisoned() {
                return Err(poisoned_err());
            }
            if self.fail_next {
                self.poison.poison();
                return Err(IoError::new(IoErrorCode::Timeout, "mock send failed"));
            }
            self.queue
                .lock()
                .expect("mock lock")
                .push_back(frame.clone());
            Ok(())
        }
    }

    impl FrameReceiver for MockRecvHalf {
        type Frame = MockFrame;
        fn recv_frame(&mut self, _t: IoTimeout) -> Result<MockFrame, IoError> {
            if self.poison.is_poisoned() {
                return Err(poisoned_err());
            }
            if self.fail_next {
                self.poison.poison();
                return Err(IoError::new(IoErrorCode::Timeout, "mock recv failed"));
            }
            self.queue
                .lock()
                .expect("mock lock")
                .pop_front()
                .ok_or_else(|| IoError::new(IoErrorCode::Timeout, "mock queue is empty"))
        }
    }

    impl SplitTransport for MockSplit {
        type SendHalf = MockSendHalf;
        type RecvHalf = MockRecvHalf;
        fn split(self) -> Result<(MockSendHalf, MockRecvHalf), IoError> {
            if self.poison.is_poisoned() {
                return Err(poisoned_err());
            }
            let queue = std::sync::Arc::new(std::sync::Mutex::new(self.queue));
            Ok((
                MockSendHalf {
                    queue: queue.clone(),
                    poison: self.poison.clone(),
                    fail_next: false,
                },
                MockRecvHalf {
                    queue,
                    poison: self.poison,
                    fail_next: self.fail_next,
                },
            ))
        }
    }

    /// IO-1・#1118: 分割後の両半分は `Send`（別スレッドへ移せる）。
    #[test]
    fn io1_split_transport_halves_are_send() {
        assert_send::<MockSendHalf>();
        assert_send::<MockRecvHalf>();
    }

    /// P1-3・#1118: 片側がエラーを返すともう片側の次の呼び出しが `Unavailable` になり、
    /// キューに触れない。
    #[test]
    fn p1_3_split_poison_propagates_to_other_half() {
        let transport = MockSplit {
            fail_next: true,
            ..MockSplit::default()
        };
        let (mut send, mut recv) = transport.split().expect("split must succeed");
        let err = recv
            .recv_frame(test_timeout())
            .expect_err("recv half must fail");
        assert_eq!(err.code(), IoErrorCode::Timeout);
        let err = send
            .send_frame(&MockFrame(1), test_timeout())
            .expect_err("send half must be poisoned");
        assert_eq!(err.code(), IoErrorCode::Unavailable);
        assert!(send.queue.lock().expect("mock lock").is_empty());
    }

    /// P1-3・#1118: poison 済みの接続の `split` は `Unavailable` で拒否される。
    #[test]
    fn p1_3_split_rejects_poisoned_transport() {
        let transport = MockSplit::default();
        transport.poison.poison();
        let err = transport
            .split()
            .expect_err("poisoned transport must not split");
        assert_eq!(err.code(), IoErrorCode::Unavailable);
    }

    /// `SharedPoison` の clone は同じ状態を共有する。
    #[test]
    fn p1_3_shared_poison_is_shared_between_clones() {
        let a = SharedPoison::new();
        let b = a.clone();
        assert!(!b.is_poisoned());
        a.poison();
        assert!(b.is_poisoned());
    }

    /// IO-1: `FrameSender` / `FrameReceiver` の実装は `Send` を満たす。
    #[test]
    fn io1_mock_transport_is_send() {
        assert_send::<MockTransport>();
    }

    /// P1-3・REPAIR-5・REPAIR-6（設計レビュー・2026-09-28 オーナー決定）:
    /// `recv_frame` がエラー（ここでは `Timeout`）を返した後、その接続は
    /// `send_frame`・`recv_frame` のいずれを呼んでも `Unavailable` を返し、
    /// キューの状態も変化しない（fail-closed。エラー後の接続再利用を禁じる契約の
    /// 確認）。
    #[test]
    fn p1_3_connection_becomes_unavailable_after_error() {
        let mut transport = MockTransport::default();

        let err = transport
            .recv_frame(test_timeout())
            .expect_err("empty queue must time out");
        assert_eq!(err.code(), IoErrorCode::Timeout);

        // タイムアウト後、送信を試みても接続は再利用できない。
        let err = transport
            .send_frame(&MockFrame(1), test_timeout())
            .expect_err("send after a prior error must be rejected");
        assert_eq!(err.code(), IoErrorCode::Unavailable);
        assert!(
            transport.queue.is_empty(),
            "poisoned send must not touch the queue"
        );

        // 受信を試みても同様に再利用できない。
        let err = transport
            .recv_frame(test_timeout())
            .expect_err("recv after a prior error must be rejected");
        assert_eq!(err.code(), IoErrorCode::Unavailable);
    }
}
