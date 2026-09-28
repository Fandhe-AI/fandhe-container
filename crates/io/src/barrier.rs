//! FLUSH バリアの ACK 契約を、通常 ACK と型で分離する（IO-1・IO-2・TASK-15.1・
//! #85）。
//!
//! [`crate::client::PipelineClient::recv_ack`]（TASK-12.2・#74）は当初
//! `AckReceipt`（1 つの構造体に `ack_kind: FrameKind` フィールドを持たせ、
//! `ack_kind()` で判別する形）を返していたが、呼び出し元が `ack_kind()` の
//! 確認を怠ると、永続化を保証しない通常 ACK（[`FrameKind::Ack`]・IO-1）を
//! 永続化済み（[`FrameKind::FlushAck`]・IO-2）として扱えてしまい、データ損失
//! （ERR-3 `DATA_LOSS`）につながる余地があった（親 #84 の受入基準：同一型の
//! 判別フィールドで区別しない API にすること）。本モジュールはこれを
//! [`WriteAck`]・[`FlushAck`] という別々の型に分け、[`AckReceipt`] をその
//! 直和（`enum`）にすることで、呼び出し元が種別確認を忘れても取り違えを
//! コンパイル時に検出できるようにする。
//!
//! # 構築経路（偽造できないことの根拠）
//!
//! [`WriteAck`]・[`FlushAck`]・[`AckReceipt`] のフィールドはすべて非公開で、
//! 生成できるのは本 crate 内の `AckReceipt::from_matched`（`pub(crate)`）
//! だけである。これは [`crate::client::PipelineClient::recv_ack`] が、送信順・
//! 種別対応を検証済みの [`crate::client::InFlightRequest`] とワイヤーから
//! 復号した [`FrameKind`] からのみ呼び出す。相互変換（`WriteAck` ↔ `FlushAck`）
//! は一切実装しない。したがって crate 外のコードは実際に受信した ACK を
//! `recv_ack` に通す以外の方法で `FlushAck` を得られず、「バッファリング ACK を
//! 永続化済みとして偽装する」経路は型として存在しない。
//!
//! # 未実装範囲（REPAIR-3）
//!
//! 本モジュールが表すのはクライアント側のプロトコル契約（型の区別）のみ。
//! サーバー側で FLUSH バリア以前の書き込みを実際に永続化（`syncfs` 等）して
//! から [`FrameKind::FlushAck`] を送出する処理はまだない
//! （`crates/io/src/writeback.rs` は `Flush` 受信時に `Unimplemented` で終える。
//! TASK-15.2・#823・#824 の範囲。`docs/design/io-protocol.md` の「FLUSH フレーム
//! の扱い」参照）。

use crate::client::{InFlightRequest, RequestId};
use crate::error::{IoError, IoErrorCode};
use crate::protocol::FrameKind;

/// 通常 ACK（[`FrameKind::Ack`]）の受領記録（IO-1）。
///
/// 対応する書き込みが受信プロセスにバッファリングされたことのみを保証し、
/// **永続化は保証しない**。永続化完了の保証が必要な呼び出し元は
/// [`FlushAck`] を待つこと。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WriteAck {
    request: InFlightRequest,
}

impl WriteAck {
    /// この ACK が対応付けた、送信済みだった元のリクエストを返す。
    pub fn request(&self) -> InFlightRequest {
        self.request
    }
}

/// FLUSH バリアに対する ACK（[`FrameKind::FlushAck`]）の受領記録（IO-2）。
///
/// このバリア以前に受理したすべての書き込みが永続化済みであることを保証する。
/// [`WriteAck`] とは異なる型であるため、呼び出し元が誤って通常 ACK を
/// 永続化済みとして扱うことはコンパイル時に防がれる（本モジュールの
/// `//!` ドキュメント「構築経路」参照）。
///
/// # 例（コンパイルできる: `FlushAck` を要求する箇所に `FlushAck` を渡せる）
///
/// ```
/// use fandhe_container_io::barrier::FlushAck;
///
/// fn require_durable(_: &FlushAck) {}
///
/// fn demo(ack: &FlushAck) {
///     require_durable(ack);
/// }
/// ```
///
/// # 例（コンパイルできない: `WriteAck` を `FlushAck` の代わりに渡せない）
///
/// ```compile_fail
/// use fandhe_container_io::barrier::{FlushAck, WriteAck};
///
/// fn require_durable(_: &FlushAck) {}
///
/// fn demo(ack: &WriteAck) {
///     require_durable(ack); // 型が合わずコンパイルエラーになる
/// }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlushAck {
    request: InFlightRequest,
}

impl FlushAck {
    /// この ACK が対応付けた、送信済みだった元の FLUSH リクエストを返す。
    pub fn request(&self) -> InFlightRequest {
        self.request
    }

    /// このリクエストに対応する [`FlushBarrier`] を返す。
    ///
    /// [`Self`] は `AckReceipt::from_matched` が種別 [`FrameKind::Flush`] の
    /// リクエストからのみ構築するため（本モジュールの `//!` ドキュメント参照）、
    /// ここでの変換は常に成功する。呼び出し元は
    /// [`crate::client::PipelineClient::flush`] が返した [`FlushBarrier`] との
    /// 対応を `ack.barrier() == barrier` で確認できる。
    pub fn barrier(&self) -> FlushBarrier {
        FlushBarrier(self.request)
    }
}

/// 種別が [`FrameKind::Flush`] であることが保証された、発行済みバリアの
/// ハンドル（IO-2・TASK-15.1・#85）。
///
/// [`crate::client::PipelineClient::flush`] が送信直後に返し、
/// [`FlushAck::barrier`] が受信した FLUSH ACK から返す。両者を
/// `PartialEq`（[`InFlightRequest`] の id・種別による比較）で突き合わせられる。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlushBarrier(InFlightRequest);

impl FlushBarrier {
    /// このバリアの元になったリクエストを返す。
    pub fn request(&self) -> InFlightRequest {
        self.0
    }

    /// このバリアの識別子（[`RequestId`]）を返す。
    pub fn id(&self) -> RequestId {
        self.0.id()
    }
}

impl TryFrom<InFlightRequest> for FlushBarrier {
    type Error = IoError;

    /// `request` の種別が [`FrameKind::Flush`] でなければ
    /// [`IoErrorCode::InvalidArgument`] で拒否する。
    fn try_from(request: InFlightRequest) -> Result<Self, Self::Error> {
        if request.kind() == FrameKind::Flush {
            Ok(Self(request))
        } else {
            Err(IoError::new(
                IoErrorCode::InvalidArgument,
                "FlushBarrier can only be built from a Flush-kind in-flight request",
            ))
        }
    }
}

/// [`crate::client::PipelineClient::recv_ack`] が返す、検証・対応付け済みの
/// ACK 受領記録（IO-1・IO-2・TASK-12.2・TASK-15.1・#74・#85）。
///
/// 通常 ACK（[`WriteAck`]）と FLUSH ACK（[`FlushAck`]）を同一型の判別
/// フィールドではなく別バリアントとして表現する（本モジュールの `//!`
/// ドキュメント参照）。`#[non_exhaustive]` により、将来 3 つ目の ACK 種別を
/// 追加してもこの enum を外部で網羅的に `match` しているコードを壊さない。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AckReceipt {
    /// [`FrameKind::Ack`]（IO-1）。
    Write(WriteAck),
    /// [`FrameKind::FlushAck`]（IO-2）。
    Flush(FlushAck),
}

impl AckReceipt {
    /// 検証・対応付け済みの ACK 受領記録を、種別の組み合わせから構築する
    /// （`pub(crate)`。本モジュールの `//!` ドキュメント「構築経路」参照）。
    ///
    /// [`crate::client::PipelineClient::recv_ack`] だけが呼び出す想定で、
    /// `request` は送信順・`ack_kind` はペイロード検証済みのワイヤー値を渡す。
    /// `(Write, Ack)` → [`AckReceipt::Write`]、`(Flush, FlushAck)` →
    /// [`AckReceipt::Flush`] 以外の組み合わせは、呼び出し元がすでに
    /// `expected_ack_kind` で種別対応を検証しているため到達しないはずだが、
    /// `unwrap`・`expect` を使わず [`IoErrorCode::Internal`] を返して安全側
    /// （拒否）に倒す（coding-rust「ライブラリコードでは panic させない」）。
    pub(crate) fn from_matched(
        request: InFlightRequest,
        ack_kind: FrameKind,
    ) -> Result<Self, IoError> {
        match (request.kind(), ack_kind) {
            (FrameKind::Write, FrameKind::Ack) => Ok(AckReceipt::Write(WriteAck { request })),
            (FrameKind::Flush, FrameKind::FlushAck) => Ok(AckReceipt::Flush(FlushAck { request })),
            _ => Err(IoError::new(
                IoErrorCode::Internal,
                "in-flight request kind and ack frame kind do not correspond; this must not happen",
            )),
        }
    }

    /// この ACK が対応付けた、送信済みだった元のリクエストを返す
    /// （[`WriteAck::request`] / [`FlushAck::request`] の共通アクセサ。
    /// TASK-12.2 時点の `AckReceipt::request` との互換のため残す）。
    pub fn request(&self) -> InFlightRequest {
        match self {
            AckReceipt::Write(ack) => ack.request(),
            AckReceipt::Flush(ack) => ack.request(),
        }
    }
}

impl TryFrom<AckReceipt> for WriteAck {
    type Error = IoError;

    /// `receipt` が [`AckReceipt::Flush`] であれば
    /// [`IoErrorCode::InvalidArgument`] で拒否する。
    fn try_from(receipt: AckReceipt) -> Result<Self, Self::Error> {
        match receipt {
            AckReceipt::Write(ack) => Ok(ack),
            AckReceipt::Flush(_) => Err(IoError::new(
                IoErrorCode::InvalidArgument,
                "AckReceipt is a Flush ack, not a Write ack",
            )),
        }
    }
}

impl TryFrom<AckReceipt> for FlushAck {
    type Error = IoError;

    /// `receipt` が [`AckReceipt::Write`] であれば
    /// [`IoErrorCode::InvalidArgument`] で拒否する。
    fn try_from(receipt: AckReceipt) -> Result<Self, Self::Error> {
        match receipt {
            AckReceipt::Flush(ack) => Ok(ack),
            AckReceipt::Write(_) => Err(IoError::new(
                IoErrorCode::InvalidArgument,
                "AckReceipt is a Write ack, not a Flush ack",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::{InFlightLimit, SendQueue};

    /// テスト専用: 指定した種別の [`InFlightRequest`] を、公開 API
    /// （[`SendQueue::register`]）経由で作る。
    fn make_request(kind: FrameKind) -> InFlightRequest {
        let limit = InFlightLimit::new(1).expect("1 must be a valid limit");
        let mut queue = SendQueue::new(limit);
        queue.register(kind).expect("register must succeed")
    }

    /// IO-1・TASK-15.1: `(Write, Ack)` の組み合わせは `AckReceipt::Write` になる。
    #[test]
    fn io1_from_matched_write_ack_yields_write_variant() {
        let request = make_request(FrameKind::Write);
        let receipt =
            AckReceipt::from_matched(request, FrameKind::Ack).expect("must accept (Write, Ack)");
        match receipt {
            AckReceipt::Write(ack) => assert_eq!(ack.request().id().get(), request.id().get()),
            AckReceipt::Flush(_) => panic!("expected Write variant"),
        }
    }

    /// IO-2・TASK-15.1: `(Flush, FlushAck)` の組み合わせは `AckReceipt::Flush` になる。
    #[test]
    fn io2_from_matched_flush_ack_yields_flush_variant() {
        let request = make_request(FrameKind::Flush);
        let receipt = AckReceipt::from_matched(request, FrameKind::FlushAck)
            .expect("must accept (Flush, FlushAck)");
        match receipt {
            AckReceipt::Flush(ack) => assert_eq!(ack.request().id().get(), request.id().get()),
            AckReceipt::Write(_) => panic!("expected Flush variant"),
        }
    }

    /// IO-1・IO-2・TASK-15.1: 種別が対応しない組み合わせは `Internal` で拒否する。
    #[test]
    fn io2_from_matched_rejects_mismatched_kind_combinations() {
        let write_request = make_request(FrameKind::Write);
        let err = AckReceipt::from_matched(write_request, FrameKind::FlushAck)
            .expect_err("(Write, FlushAck) must be rejected");
        assert_eq!(err.code(), IoErrorCode::Internal);

        let flush_request = make_request(FrameKind::Flush);
        let err = AckReceipt::from_matched(flush_request, FrameKind::Ack)
            .expect_err("(Flush, Ack) must be rejected");
        assert_eq!(err.code(), IoErrorCode::Internal);
    }

    /// IO-2・TASK-15.1: `FlushBarrier::try_from` は `Flush` のみ受理し、
    /// `Write` は `InvalidArgument` で拒否する。
    #[test]
    fn io2_flush_barrier_try_from_accepts_flush_rejects_write() {
        let flush_request = make_request(FrameKind::Flush);
        let barrier =
            FlushBarrier::try_from(flush_request).expect("Flush request must be accepted");
        assert_eq!(barrier.id().get(), flush_request.id().get());

        let write_request = make_request(FrameKind::Write);
        let err =
            FlushBarrier::try_from(write_request).expect_err("Write request must be rejected");
        assert_eq!(err.code(), IoErrorCode::InvalidArgument);
    }

    /// IO-2・TASK-15.1: `FlushAck::barrier()` の id は元の FLUSH リクエストと一致する。
    #[test]
    fn io2_flush_ack_barrier_id_matches_original_flush_request() {
        let request = make_request(FrameKind::Flush);
        let receipt = AckReceipt::from_matched(request, FrameKind::FlushAck)
            .expect("must accept (Flush, FlushAck)");
        let AckReceipt::Flush(flush_ack) = receipt else {
            panic!("expected Flush variant");
        };
        let barrier = flush_ack.barrier();
        assert_eq!(barrier.id().get(), request.id().get());
        assert_eq!(
            barrier,
            FlushBarrier::try_from(request).expect("Flush accepted")
        );
    }

    /// IO-1・TASK-15.1: `FlushAck::try_from(AckReceipt::Write(..))` は
    /// `InvalidArgument` で拒否する。
    #[test]
    fn io1_flush_ack_try_from_write_receipt_is_rejected() {
        let request = make_request(FrameKind::Write);
        let receipt =
            AckReceipt::from_matched(request, FrameKind::Ack).expect("must accept (Write, Ack)");
        let err = FlushAck::try_from(receipt).expect_err("Write receipt must be rejected");
        assert_eq!(err.code(), IoErrorCode::InvalidArgument);
    }

    /// IO-2・TASK-15.1: `WriteAck::try_from(AckReceipt::Flush(..))` は
    /// `InvalidArgument` で拒否する。
    #[test]
    fn io2_write_ack_try_from_flush_receipt_is_rejected() {
        let request = make_request(FrameKind::Flush);
        let receipt = AckReceipt::from_matched(request, FrameKind::FlushAck)
            .expect("must accept (Flush, FlushAck)");
        let err = WriteAck::try_from(receipt).expect_err("Flush receipt must be rejected");
        assert_eq!(err.code(), IoErrorCode::InvalidArgument);
    }
}
