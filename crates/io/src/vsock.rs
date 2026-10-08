//! vsock トランスポート（Linux `AF_VSOCK`。IO-1・REPAIR-3/4/5・P1-3・TASK-13.4・#1119）。
//!
//! ホストと VM ゲスト（microVM の vhost-vsock・WSL2・macOS Virtualization.framework の
//! ゲスト）の間で、I/O 共有層のフレーム（[`crate::protocol::Frame`]）を送受信する
//! トランスポートである。UDS 版（[`crate::server`]）と同じ [`FrameSender`] /
//! [`FrameReceiver`] / [`SplitTransport`] の契約（フレーム単位の期限・poison・受信上限・
//! 観測フック）を満たし、ストリーム上の期限付き read / write は
//! `crate::stream_io` を UDS と共有する。
//!
//! # 呼び出し文脈
//! - ホスト側: microVM 層（`fandhe-container-plugin-microvm`。MVM 系）が [`VsockServer`] で
//!   待ち受け、ゲストエージェントの接続を [`VsockServer::accept`] で受ける。受けた
//!   [`VsockConnection`] を `crate::writeback::serve_connection` 等へ渡す。
//! - ゲスト側: ゲストエージェントが [`VsockConnection::connect`] でホスト（CID 2）へ接続し、
//!   `Ack` / `FlushAck` を受ける側として使う（クライアント側は `Write` / `Flush` を送る）。
//!   `crate::client::PipelineClient` との結線は本タスクの範囲外。
//!
//! # 対応範囲（REPAIR-3: 実装済みを装わない）
//! | 環境 | 状態 |
//! | ---- | ---- |
//! | Linux x86_64 / aarch64（ホスト側 vhost-vsock・ゲスト側） | 実装済み |
//! | Linux のその他のアーキテクチャ | [`IoErrorCode::Unimplemented`]（定数を流用しない。fail-closed） |
//! | macOS（`VZVirtioSocketDevice`） | 未実装。`bind` / `connect` は `Unimplemented`。Virtualization.framework が返す接続済み fd の取り込みは `objc2*` 依存の承認後に platform-macos 側で扱う（MAC 系） |
//! | Windows（hvsock / `AF_HYPERV`） | 未実装。`Unimplemented`。`windows-sys` の承認後に扱う |
//!
//! # 接続元の検証（PLUG-12 相当・SEC-4）
//! vsock には `SO_PEERCRED` 相当がないため、UDS の uid 照合の代わりに **接続元 CID の照合**
//! を使う。[`VsockServer::bind`] は期待する相手 CID を [`VsockPeerPolicy`] として必須で
//! 受け取り（暗黙の既定・全許可を作らない）、一致しない CID の接続は accept 直後に閉じる
//! （fail-closed）。
//!
//! - 信頼の根拠: CID はホストの VMM（vhost-vsock）が割り当て、ゲストは自分の CID を
//!   詐称できない。ホストから見た接続元 CID は VMM が保証する。
//! - ポート番号は認証されない。相手プロセスの同定には使わない。
//! - 限界 1: 同じ CID 内（同じゲストの中）の別プロセスは区別できない。ゲスト内の権限分離は
//!   ゲスト側の責務である（UDS の「到達経路を塞ぐのは呼び出し側」と同じ整理）。
//! - 限界 2: ホストで `vsock_loopback` がロードされていると、ホスト上の **任意 uid の
//!   プロセスが CID 1（`VMADDR_CID_LOCAL`）経由で接続できる**。このため CID 1 / 0 / 2 も
//!   呼び出し側が [`VsockPeerPolicy::exact_cid`] で明示したときだけ受理し、
//!   `VMADDR_CID_ANY` を「任意の相手」として受理するポリシーは作れない。
//!
//! 拒否は UDS の peer credential 拒否と同じ経路で扱う: 1 件の拒否で受付ループを止めず、
//! [`ServerOutcome::RejectedPeerCredential`] の個別イベント（`peer_cid` つき）を即時に通知し、
//! 期限と再試行上限（`MAX_ACCEPT_ABORT_RETRIES`）の両方で有界に再試行する。
//!
//! # `TcpStream` を使う理由
//! 接続済みの vsock fd は `std::net::TcpStream::from(OwnedFd)` に包んで read / write /
//! `SO_RCVTIMEO` / `SO_SNDTIMEO` / `shutdown` / `dup` に使う。これらの syscall はアドレス
//! ファミリに依存せず、`TcpStream` のメソッドは `peer_addr` 以外でソケットのアドレスを
//! 解釈しない（`peer_addr` / `local_addr` は使わず、`crate::sys` の `getpeername` を使う）。
//! `timeval` のレイアウトを自前の FFI で持たずに済む。
//!
//! # 範囲外
//! - 受付ループ・同時接続数の上限（呼び出し側の責務。`crate::server` の「範囲外」節と同じ）
//! - クライアント側の接続試行の観測イベント（connect の成否はエラーとして返す。接続後の
//!   送受信は [`ServerObserver`] へ通知する）
//! - macOS・Windows のホスト側実装（上表）

use crate::error::{IoError, IoErrorCode};
use crate::observe::{SendEventError, ServerEvent, ServerObserver, ServerOp, ServerOutcome};
use crate::protocol::{Frame, FrameKind};
use crate::recv_limits::ReceiveLimits;
use crate::transport::{FrameReceiver, FrameSender, IoTimeout, SplitTransport};

use std::time::{Duration, Instant};

use crate::server::{
    SharedObserver, emit_failure, emit_success, notify_failure, notify_success,
    unavailable_after_poison,
};
use crate::transport::SharedPoison;

/// `VMADDR_CID_ANY`（`bind` で「自分の任意の CID」を意味する）。接続元の期待値には使えない。
const VMADDR_CID_ANY: u32 = u32::MAX;
/// `VMADDR_PORT_ANY`（`bind` でカーネルにポートを割り当てさせる）。
const VMADDR_PORT_ANY: u32 = u32::MAX;

/// vsock のアドレス（CID とポート）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VsockAddr {
    cid: u32,
    port: u32,
}

impl VsockAddr {
    /// `VMADDR_CID_ANY`。`bind` の CID にだけ使える（自分のどの CID 宛の接続も受ける）。
    pub const CID_ANY: u32 = VMADDR_CID_ANY;
    /// `VMADDR_CID_HYPERVISOR`（0）。
    pub const CID_HYPERVISOR: u32 = 0;
    /// `VMADDR_CID_LOCAL`（1。`vsock_loopback` 経由の同一ホスト内通信）。
    pub const CID_LOCAL: u32 = 1;
    /// `VMADDR_CID_HOST`（2。ゲストから見たホスト）。
    pub const CID_HOST: u32 = 2;
    /// `VMADDR_PORT_ANY`。`bind` のポートにだけ使える（カーネルが割り当てる）。
    pub const PORT_ANY: u32 = VMADDR_PORT_ANY;

    /// CID とポートからアドレスを作る。
    pub const fn new(cid: u32, port: u32) -> Self {
        Self { cid, port }
    }

    /// CID を返す。
    pub const fn cid(&self) -> u32 {
        self.cid
    }

    /// ポートを返す。
    pub const fn port(&self) -> u32 {
        self.port
    }
}

/// 接続元として受理する CID の指定（PLUG-12 相当。モジュール doc「接続元の検証」節）。
///
/// [`VsockServer::bind`] の必須引数で、既定値や「任意の相手を受理する」値は作れない
/// （[`ReceiveLimits`]・観測フックと同じく、暗黙の既定を避ける）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VsockPeerPolicy {
    expected_cid: u32,
}

impl VsockPeerPolicy {
    /// 接続元 CID が `cid` と一致する接続だけを受理するポリシーを作る。
    ///
    /// CID 0（hypervisor）・1（local）・2（host）も、呼び出し側が明示したときだけ受理する。
    /// `VMADDR_CID_ANY`（`u32::MAX`）は「任意の相手」を意味しかねないため
    /// [`IoErrorCode::InvalidArgument`] で拒否する。
    pub fn exact_cid(cid: u32) -> Result<Self, IoError> {
        if cid == VMADDR_CID_ANY {
            return Err(IoError::new(
                IoErrorCode::InvalidArgument,
                "VMADDR_CID_ANY cannot be used as the expected peer CID",
            ));
        }
        Ok(Self { expected_cid: cid })
    }

    /// 受理する接続元 CID を返す。
    pub fn expected_cid(&self) -> u32 {
        self.expected_cid
    }
}

/// vsock の接続受け付け役（IO-1・#1119）。UDS の [`crate::server::UdsServer`] の vsock 版。
///
/// `O: ServerObserver` は [`Self::bind`] の必須の観測フックで、[`Self::accept`] のイベント
/// （[`ServerOp::Accept`]。CID 不一致の拒否は `peer_cid` つき）を通知する。`limits` は
/// [`Self::accept`] が返す各 [`VsockConnection`] へ引き継がれる（TASK-13.4）。
pub struct VsockServer<O: ServerObserver> {
    inner: imp::ServerInner,
    observer: O,
    limits: ReceiveLimits,
}

impl<O: ServerObserver> core::fmt::Debug for VsockServer<O> {
    /// 内部状態（fd・観測フックの中身）は出さない（`O: Debug` を要求しない）。
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VsockServer").finish_non_exhaustive()
    }
}

impl<O: ServerObserver> VsockServer<O> {
    /// `addr` で待ち受ける。`peer_policy`・`limits`・`observer` はすべて必須。
    ///
    /// CID には自分の CID または [`VsockAddr::CID_ANY`]、ポートには [`VsockAddr::PORT_ANY`]
    /// （実ポートは [`Self::local_addr`]）を指定できる。ポート 1023 以下の bind には
    /// `CAP_NET_BIND_SERVICE` が必要で、無ければ `InvalidArgument` になる。vsock 非対応の
    /// カーネルでは `Unavailable`、非対応の OS・アーキテクチャでは `Unimplemented`。
    pub fn bind(
        addr: VsockAddr,
        peer_policy: VsockPeerPolicy,
        limits: ReceiveLimits,
        observer: O,
    ) -> Result<Self, IoError> {
        Ok(Self {
            inner: imp::ServerInner::bind(addr, peer_policy)?,
            observer,
            limits,
        })
    }

    /// 実際に bind されたアドレス（[`VsockAddr::PORT_ANY`] で bind した場合の実ポートを得る）。
    pub fn local_addr(&self) -> Result<VsockAddr, IoError> {
        self.inner.local_addr()
    }

    /// 接続を 1 件、`timeout` を上限に受け付ける（REPAIR-5）。
    ///
    /// 期限までに来なければ [`IoErrorCode::Timeout`]。CID が不一致の接続は閉じて個別に通知し
    /// （[`ServerOutcome::RejectedPeerCredential`]）、期限と再試行上限の範囲で待ち直す。
    /// 上限を超えると `Unavailable`（リスナーは健全で、再度呼んでよい）。成功・失敗のいずれでも
    /// この呼び出しの [`ServerOp::Accept`] イベントを [`Self::bind`] の観測フックへ 1 回通知する。
    pub fn accept<C: ServerObserver>(
        &mut self,
        timeout: IoTimeout,
        conn_observer: C,
    ) -> Result<VsockConnection<C>, IoError> {
        let started = Instant::now();
        let observer = &mut self.observer;
        let attempt = self.inner.accept(timeout, &mut |event: &ServerEvent<'_>| {
            observer.on_event(event);
        });
        let elapsed = started.elapsed();
        let (outcome, error) = match &attempt.result {
            Ok(_) => (ServerOutcome::Success, None),
            Err(err) => (ServerOutcome::Failure, Some(err)),
        };
        self.observer.on_event(&ServerEvent {
            op: ServerOp::Accept,
            kind: None,
            outcome,
            latency: elapsed,
            accept_aborted_retries: attempt.aborted_retries,
            peer_credential_rejections: attempt.peer_credential_rejections,
            peer_uid: None,
            peer_cid: None,
            coalesced: None,
            error: error.map(|err| SendEventError {
                code: err.code(),
                message: err.message(),
            }),
        });
        attempt.result.map(|inner| VsockConnection {
            inner,
            direction: Direction::ServerSide,
            poisoned: false,
            observer: conn_observer,
            limits: self.limits,
        })
    }

    /// [`Self::bind`] で渡した観測フックを参照する。
    pub fn observer(&self) -> &O {
        &self.observer
    }

    /// [`Self::bind`] で渡した観測フックを可変参照で取り出す。
    pub fn observer_mut(&mut self) -> &mut O {
        &mut self.observer
    }
}

/// 接続のどちら側か。受信してよいフレーム種別が逆になる（IO-1・REPAIR-2）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Direction {
    /// [`VsockServer::accept`] した側。`Write` / `Flush` を受け、`Ack` / `FlushAck` を返す。
    ServerSide,
    /// [`VsockConnection::connect`] した側。`Ack` / `FlushAck` を受け、`Write` / `Flush` を送る。
    ClientSide,
}

/// 方向違いのフレームを確保前に拒否する関数を選ぶ。
fn accept_kind_for(direction: Direction) -> fn(FrameKind) -> Result<(), IoError> {
    match direction {
        Direction::ServerSide => reject_client_originated_response_frame,
        Direction::ClientSide => reject_server_originated_request_frame,
    }
}

/// `stream_io` を持つ OS（Linux・macOS）では UDS と共有する実体を使う。
#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::stream_io::reject_client_originated_response_frame;

/// Windows には `stream_io` モジュールが存在しない（UDS 非対応。vsock は
/// `Unimplemented` を返す）ため、`stream_io` 側と同じ判定を局所的に持つ（IO-1・REPAIR-2）。
/// 型は到達しないが `Direction` の `match` を全 OS で同形に保つために必要。
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn reject_client_originated_response_frame(kind: FrameKind) -> Result<(), IoError> {
    match kind {
        FrameKind::Write | FrameKind::Flush => Ok(()),
        FrameKind::Ack | FrameKind::FlushAck => Err(IoError::new(
            IoErrorCode::InvalidArgument,
            format!("server does not accept client-originated response frames: {kind:?}"),
        )),
    }
}

/// クライアント側が受信してはならない要求系種別（`Write`・`Flush`）を拒否する。
fn reject_server_originated_request_frame(kind: FrameKind) -> Result<(), IoError> {
    match kind {
        FrameKind::Ack | FrameKind::FlushAck => Ok(()),
        FrameKind::Write | FrameKind::Flush => Err(IoError::new(
            IoErrorCode::InvalidArgument,
            format!("client does not accept server-originated request frames: {kind:?}"),
        )),
    }
}

/// vsock 接続 1 本（受け付けた側 / 接続した側。IO-1・#1119）。
///
/// [`FrameSender`]・[`FrameReceiver`] を実装し、単一スレッドで `&mut self` を使う前提。
/// 送受信を別スレッドで並行に使う場合は [`SplitTransport::split`] で
/// [`VsockSendHalf`]・[`VsockRecvHalf`] へ分ける。`send_frame` / `recv_frame` のいずれかが
/// 一度でも `Err` を返すと以後 [`IoErrorCode::Unavailable`] を返し続ける（P1-3。フレーム境界を
/// 復元できないため再利用しない）。期限の判定位置は UDS と同じ（`crate::server`
/// の `UdsConnection` doc「期限の判定位置」節）。
pub struct VsockConnection<C: ServerObserver> {
    inner: imp::ConnectionInner,
    direction: Direction,
    poisoned: bool,
    observer: C,
    limits: ReceiveLimits,
}

impl<C: ServerObserver> core::fmt::Debug for VsockConnection<C> {
    /// 向きと poison 状態のみを出す（fd・観測フックの中身は出さない）。
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VsockConnection")
            .field("direction", &self.direction)
            .field("poisoned", &self.poisoned)
            .finish()
    }
}

impl<C: ServerObserver> VsockConnection<C> {
    /// `addr` へ `timeout` を上限に接続する（ゲスト側がホストへ繋ぐ用途。REPAIR-5）。
    ///
    /// 接続後に `getpeername` の CID が `addr.cid()` と一致することを確かめる（不一致は
    /// 切断して `InvalidArgument`）。`addr.cid()` に [`VsockAddr::CID_ANY`] は使えない。
    /// 受信してよいのは `Ack` / `FlushAck` のみ（`Write` / `Flush` を受けると
    /// `InvalidArgument` で poison）。`limits` は受信上限で、既定値を暗黙に使わない。
    /// 応答しない CID への接続は `Timeout`、相手がいない場合は `Unavailable`。
    pub fn connect(
        addr: VsockAddr,
        timeout: IoTimeout,
        limits: ReceiveLimits,
        observer: C,
    ) -> Result<Self, IoError> {
        Ok(Self {
            inner: imp::ConnectionInner::connect(addr, timeout)?,
            direction: Direction::ClientSide,
            poisoned: false,
            observer,
            limits,
        })
    }

    /// 接続時（accept / connect）に渡した観測フックを参照する。
    pub fn observer(&self) -> &C {
        &self.observer
    }

    /// 接続時に渡した観測フックを可変参照で取り出す。
    pub fn observer_mut(&mut self) -> &mut C {
        &mut self.observer
    }
}

impl<C: ServerObserver> VsockConnection<C> {
    /// 結果を見て poison 状態を更新する（P1-3 の契約を守る箇所を 1 か所に集約する）。
    fn poison_on_err<T>(&mut self, result: Result<T, IoError>) -> Result<T, IoError> {
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
}

impl<C: ServerObserver> FrameSender for VsockConnection<C> {
    type Frame = Frame;

    fn send_frame(&mut self, frame: &Frame, timeout: IoTimeout) -> Result<(), IoError> {
        if self.poisoned {
            let err = unavailable_after_poison();
            emit_failure(
                &mut self.observer,
                ServerOp::Send,
                Some(frame.kind()),
                ServerOutcome::RejectedPoisoned,
                Duration::ZERO,
                &err,
            );
            return Err(err);
        }
        let started = Instant::now();
        let result = self.inner.send_frame(frame, timeout);
        let elapsed = started.elapsed();
        match &result {
            Ok(()) => emit_success(
                &mut self.observer,
                ServerOp::Send,
                Some(frame.kind()),
                elapsed,
            ),
            Err(err) => emit_failure(
                &mut self.observer,
                ServerOp::Send,
                Some(frame.kind()),
                ServerOutcome::Failure,
                elapsed,
                err,
            ),
        }
        self.poison_on_err(result)
    }
}

impl<C: ServerObserver> FrameReceiver for VsockConnection<C> {
    type Frame = Frame;

    fn recv_frame(&mut self, timeout: IoTimeout) -> Result<Frame, IoError> {
        if self.poisoned {
            let err = unavailable_after_poison();
            emit_failure(
                &mut self.observer,
                ServerOp::Recv,
                None,
                ServerOutcome::RejectedPoisoned,
                Duration::ZERO,
                &err,
            );
            return Err(err);
        }
        let started = Instant::now();
        let (result, attempt_kind) =
            self.inner
                .recv_frame(timeout, self.limits, accept_kind_for(self.direction));
        let elapsed = started.elapsed();
        match &result {
            Ok(frame) => emit_success(
                &mut self.observer,
                ServerOp::Recv,
                Some(frame.kind()),
                elapsed,
            ),
            Err(err) => emit_failure(
                &mut self.observer,
                ServerOp::Recv,
                attempt_kind,
                ServerOutcome::Failure,
                elapsed,
                err,
            ),
        }
        self.poison_on_err(result)
    }
}

/// [`SplitTransport::split`] が返す送信側（P1-3）。drop 時、poison されていなければ
/// 書き込み側を half-close する。
pub struct VsockSendHalf<C: ServerObserver> {
    inner: imp::ConnectionInner,
    poison: SharedPoison,
    observer: SharedObserver<C>,
}

/// [`SplitTransport::split`] が返す受信側（P1-3）。[`VsockConnection`] の `ReceiveLimits` と
/// 向き（受理するフレーム種別）をそのまま引き継ぐ。
pub struct VsockRecvHalf<C: ServerObserver> {
    inner: imp::ConnectionInner,
    poison: SharedPoison,
    observer: SharedObserver<C>,
    limits: ReceiveLimits,
    direction: Direction,
}

impl<C: ServerObserver> core::fmt::Debug for VsockSendHalf<C> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VsockSendHalf")
            .field("poisoned", &self.poison.is_poisoned())
            .finish()
    }
}

impl<C: ServerObserver> core::fmt::Debug for VsockRecvHalf<C> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VsockRecvHalf")
            .field("poisoned", &self.poison.is_poisoned())
            .finish()
    }
}

impl<C: ServerObserver> VsockSendHalf<C> {
    /// 両半分で共有している観測フックへ、ロックを取って `f` を適用する
    /// （`UdsSendHalf::with_observer` と同じ契約。`f` の中から `with_observer` を再入しない）。
    pub fn with_observer<R>(&self, f: impl FnOnce(&mut C) -> R) -> R {
        self.observer.with(f)
    }
}

impl<C: ServerObserver> VsockRecvHalf<C> {
    /// 両半分で共有している観測フックへ、ロックを取って `f` を適用する
    /// （[`VsockSendHalf::with_observer`] と同じ契約）。
    pub fn with_observer<R>(&self, f: impl FnOnce(&mut C) -> R) -> R {
        self.observer.with(f)
    }
}

/// I/O の結果に共有 poison の規則を適用する（`crate::server` の `settle_shared` の vsock 版）。
/// `Err` なら poison を立てて `shutdown(Both)` でもう片側を起こす。`Ok` でも他方が既に
/// poison を立てていれば結果を捨てて `Unavailable` にする。戻り値の bool は「poison 済みの
/// ため結果を捨てた」（観測上 [`ServerOutcome::RejectedPoisoned`]）。
fn settle_shared<T>(
    inner: &imp::ConnectionInner,
    poison: &SharedPoison,
    result: Result<T, IoError>,
) -> (Result<T, IoError>, bool) {
    match result {
        Err(e) => {
            let already = poison.poison();
            inner.shutdown_both();
            if already {
                (Err(unavailable_after_poison()), true)
            } else {
                (Err(e), false)
            }
        }
        Ok(_) if poison.is_poisoned() => (Err(unavailable_after_poison()), true),
        Ok(v) => (Ok(v), false),
    }
}

impl<C: ServerObserver> FrameSender for VsockSendHalf<C> {
    type Frame = Frame;

    fn send_frame(&mut self, frame: &Frame, timeout: IoTimeout) -> Result<(), IoError> {
        let until = Instant::now() + timeout.as_duration();
        let kind = Some(frame.kind());
        if self.poison.is_poisoned() {
            let err = unavailable_after_poison();
            notify_failure(
                &self.observer,
                ServerOp::Send,
                kind,
                ServerOutcome::RejectedPoisoned,
                Duration::ZERO,
                &err,
                until,
            );
            return Err(err);
        }
        let started = Instant::now();
        let result = self.inner.send_frame(frame, timeout);
        let elapsed = started.elapsed();
        let (result, rejected) = settle_shared(&self.inner, &self.poison, result);
        match &result {
            Ok(()) => notify_success(&self.observer, ServerOp::Send, kind, elapsed, until),
            Err(err) => {
                let outcome = if rejected {
                    ServerOutcome::RejectedPoisoned
                } else {
                    ServerOutcome::Failure
                };
                notify_failure(
                    &self.observer,
                    ServerOp::Send,
                    kind,
                    outcome,
                    elapsed,
                    err,
                    until,
                );
            }
        }
        result
    }
}

impl<C: ServerObserver> FrameReceiver for VsockRecvHalf<C> {
    type Frame = Frame;

    fn recv_frame(&mut self, timeout: IoTimeout) -> Result<Frame, IoError> {
        let until = Instant::now() + timeout.as_duration();
        if self.poison.is_poisoned() {
            let err = unavailable_after_poison();
            notify_failure(
                &self.observer,
                ServerOp::Recv,
                None,
                ServerOutcome::RejectedPoisoned,
                Duration::ZERO,
                &err,
                until,
            );
            return Err(err);
        }
        let started = Instant::now();
        let (result, attempt_kind) =
            self.inner
                .recv_frame(timeout, self.limits, accept_kind_for(self.direction));
        let elapsed = started.elapsed();
        let (result, rejected) = settle_shared(&self.inner, &self.poison, result);
        match &result {
            Ok(frame) => notify_success(
                &self.observer,
                ServerOp::Recv,
                Some(frame.kind()),
                elapsed,
                until,
            ),
            Err(err) => {
                let outcome = if rejected {
                    ServerOutcome::RejectedPoisoned
                } else {
                    ServerOutcome::Failure
                };
                notify_failure(
                    &self.observer,
                    ServerOp::Recv,
                    attempt_kind,
                    outcome,
                    elapsed,
                    err,
                    until,
                );
            }
        }
        result
    }
}

impl<C: ServerObserver> Drop for VsockSendHalf<C> {
    /// poison されていなければ書き込み側を half-close する（相手は送信済みデータを読み切った後に
    /// EOF を受ける。受信側は使い続けられる）。失敗は無視する。
    fn drop(&mut self) {
        if !self.poison.is_poisoned() {
            self.inner.shutdown_write();
        }
    }
}

impl<C: ServerObserver> SplitTransport for VsockConnection<C> {
    type SendHalf = VsockSendHalf<C>;
    type RecvHalf = VsockRecvHalf<C>;

    /// poison 済みなら `Unavailable`（接続はここで drop して閉じる）。fd の複製に失敗した場合も
    /// エラーを返し、接続は閉じる。
    fn split(self) -> Result<(VsockSendHalf<C>, VsockRecvHalf<C>), IoError> {
        if self.poisoned {
            return Err(unavailable_after_poison());
        }
        let recv_inner = self.inner.try_clone()?;
        let poison = SharedPoison::new();
        let observer = SharedObserver::new(self.observer);
        Ok((
            VsockSendHalf {
                inner: self.inner,
                poison: poison.clone(),
                observer: observer.clone(),
            },
            VsockRecvHalf {
                inner: recv_inner,
                poison,
                observer,
                limits: self.limits,
                direction: self.direction,
            },
        ))
    }
}

/// 受け付け結果に再試行件数を添えて持ち帰る非公開型（`crate::server` の `AcceptAttempt` と同じ役割）。
struct AcceptAttempt<C> {
    result: Result<C, IoError>,
    aborted_retries: u32,
    peer_credential_rejections: u32,
}

#[cfg(target_os = "linux")]
mod imp {
    //! Linux の実装（fd は `crate::sys::vsock`、ストリーム I/O は `crate::stream_io`）。

    use std::net::{Shutdown, TcpStream};
    use std::os::fd::{AsFd as _, OwnedFd};
    use std::time::Instant;

    use super::{
        AcceptAttempt, Duration, IoError, IoErrorCode, IoTimeout, ReceiveLimits, SendEventError,
        ServerEvent, ServerOp, ServerOutcome, VsockAddr, VsockPeerPolicy,
    };
    use crate::protocol::{Frame, FrameKind};
    use crate::stream_io::{
        MAX_ACCEPT_ABORT_RETRIES, accept_retry_deadline_or_limit, accept_timeout_error,
        recv_frame_on, send_frame_on,
    };
    use crate::sys::vsock::{self as sys, AcceptStep, RawAddr};

    /// `listen(2)` の backlog。受付ループが 1 件ずつ処理する前提の控えめな値で、超過分は
    /// カーネルが接続を拒否する（無制限に溜めない。security.md「無制限リソース確保」）。
    const LISTEN_BACKLOG: i32 = 16;

    pub(super) struct ServerInner {
        listener: OwnedFd,
        expected_cid: u32,
    }

    impl ServerInner {
        pub(super) fn bind(addr: VsockAddr, policy: VsockPeerPolicy) -> Result<Self, IoError> {
            let listener = sys::listen_nonblocking(
                RawAddr {
                    cid: addr.cid(),
                    port: addr.port(),
                },
                LISTEN_BACKLOG,
            )?;
            Ok(Self {
                listener,
                expected_cid: policy.expected_cid(),
            })
        }

        pub(super) fn local_addr(&self) -> Result<VsockAddr, IoError> {
            let raw = sys::local_addr(self.listener.as_fd())?;
            Ok(VsockAddr::new(raw.cid, raw.port))
        }

        /// 接続を 1 件受け付ける。CID 不一致の拒否は、1 件ごとに `on_event` へ即時通知し
        /// （SEC-4）、件数の加算と通知は期限判定より先に行う（UDS の H3 と同じ）。
        pub(super) fn accept(
            &self,
            timeout: IoTimeout,
            on_event: &mut dyn FnMut(&ServerEvent<'_>),
        ) -> AcceptAttempt<ConnectionInner> {
            let deadline = Instant::now() + timeout.as_duration();
            let mut abort_retries = 0u32;
            let mut rejections = 0u32;
            let finish = |result, abort_retries, rejections| AcceptAttempt {
                result,
                aborted_retries: abort_retries,
                peer_credential_rejections: rejections,
            };
            loop {
                if Instant::now() >= deadline {
                    return finish(Err(accept_timeout_error()), abort_retries, rejections);
                }
                match sys::accept_step(self.listener.as_fd(), deadline) {
                    Err(e) => return finish(Err(e), abort_retries, rejections),
                    Ok(AcceptStep::TimedOut) => {
                        return finish(Err(accept_timeout_error()), abort_retries, rejections);
                    }
                    Ok(AcceptStep::Spurious) => {}
                    Ok(AcceptStep::Aborted) => {
                        abort_retries = abort_retries.saturating_add(1);
                        let remaining = deadline.saturating_duration_since(Instant::now());
                        if let Some(err) = accept_retry_deadline_or_limit(
                            remaining,
                            abort_retries,
                            MAX_ACCEPT_ABORT_RETRIES,
                            "accept exceeded the retry limit after repeated peer disconnects \
                             before accept completed",
                        ) {
                            return finish(Err(err), abort_retries, rejections);
                        }
                    }
                    Ok(AcceptStep::Connected(fd, peer)) => {
                        if peer.cid != self.expected_cid {
                            drop(fd);
                            rejections = rejections.saturating_add(1);
                            let err = IoError::new(
                                IoErrorCode::InvalidArgument,
                                "connecting peer CID does not match the expected CID",
                            );
                            on_event(&ServerEvent {
                                op: ServerOp::Accept,
                                kind: None,
                                outcome: ServerOutcome::RejectedPeerCredential,
                                latency: Duration::ZERO,
                                accept_aborted_retries: 0,
                                peer_credential_rejections: rejections,
                                peer_uid: None,
                                peer_cid: Some(peer.cid),
                                coalesced: None,
                                error: Some(SendEventError {
                                    code: err.code(),
                                    message: err.message(),
                                }),
                            });
                            let remaining = deadline.saturating_duration_since(Instant::now());
                            if let Some(err) = accept_retry_deadline_or_limit(
                                remaining,
                                rejections,
                                MAX_ACCEPT_ABORT_RETRIES,
                                "accept exceeded the retry limit after repeatedly rejecting \
                                 connections with a mismatched peer CID",
                            ) {
                                return finish(Err(err), abort_retries, rejections);
                            }
                            continue;
                        }
                        // 期限を過ぎてから返さない（accept・照合の間に過ぎたら閉じて Timeout。K1）。
                        if Instant::now() >= deadline {
                            drop(fd);
                            return finish(Err(accept_timeout_error()), abort_retries, rejections);
                        }
                        let result = ConnectionInner::from_fd(fd);
                        return finish(result, abort_retries, rejections);
                    }
                }
            }
        }
    }

    pub(super) struct ConnectionInner {
        stream: TcpStream,
    }

    impl ConnectionInner {
        /// 接続済みの blocking fd を包む。`TcpStream::from(OwnedFd)` が fd の所有を引き継ぐ。
        fn from_fd(fd: OwnedFd) -> Result<Self, IoError> {
            let stream = TcpStream::from(fd);
            stream.set_nonblocking(false).map_err(|e| {
                IoError::new(
                    IoErrorCode::Internal,
                    format!("failed to clear nonblocking mode on a vsock stream: {e}"),
                )
            })?;
            Ok(Self { stream })
        }

        pub(super) fn connect(addr: VsockAddr, timeout: IoTimeout) -> Result<Self, IoError> {
            if addr.cid() == VsockAddr::CID_ANY {
                return Err(IoError::new(
                    IoErrorCode::InvalidArgument,
                    "VMADDR_CID_ANY cannot be used as a connect target",
                ));
            }
            let deadline = Instant::now() + timeout.as_duration();
            let fd = sys::connect_nonblocking_until(
                RawAddr {
                    cid: addr.cid(),
                    port: addr.port(),
                },
                deadline,
            )?
            .ok_or_else(|| IoError::new(IoErrorCode::Timeout, "vsock connect timed out"))?;
            // 接続後の CID 照合（接続先と実際の相手が一致すること。不一致なら fd は drop で閉じる）。
            let peer = sys::peer_addr(fd.as_fd())?;
            if peer.cid != addr.cid() {
                return Err(IoError::new(
                    IoErrorCode::InvalidArgument,
                    "connected peer CID does not match the requested CID",
                ));
            }
            Self::from_fd(fd)
        }

        /// fd を複製して分割後の受信側用の `ConnectionInner` を作る。
        pub(super) fn try_clone(&self) -> Result<Self, IoError> {
            self.stream
                .try_clone()
                .map(|stream| Self { stream })
                .map_err(crate::stream_io::map_io_error)
        }

        pub(super) fn shutdown_both(&self) {
            let _ = self.stream.shutdown(Shutdown::Both);
        }

        pub(super) fn shutdown_write(&self) {
            let _ = self.stream.shutdown(Shutdown::Write);
        }

        pub(super) fn send_frame(
            &mut self,
            frame: &Frame,
            timeout: IoTimeout,
        ) -> Result<(), IoError> {
            send_frame_on(&mut self.stream, frame, timeout)
        }

        pub(super) fn recv_frame(
            &mut self,
            timeout: IoTimeout,
            limits: ReceiveLimits,
            accept_kind: fn(FrameKind) -> Result<(), IoError>,
        ) -> (Result<Frame, IoError>, Option<FrameKind>) {
            let attempt = recv_frame_on(&mut self.stream, timeout, limits, accept_kind);
            (attempt.result, attempt.kind)
        }
    }
}

/// 非 Linux（macOS・Windows）。`bind` / `connect` は `Unimplemented`（モジュール doc「対応範囲」）。
/// 型は uninhabited で、`bind` / `connect` が成功しないため他のメソッドには到達しない。
#[cfg(not(target_os = "linux"))]
mod imp {
    use super::{
        AcceptAttempt, Frame, FrameKind, IoError, IoErrorCode, IoTimeout, ReceiveLimits,
        ServerEvent, VsockAddr, VsockPeerPolicy,
    };

    fn unimplemented_on_this_os() -> IoError {
        IoError::new(
            IoErrorCode::Unimplemented,
            "vsock transport is only implemented on Linux",
        )
    }

    pub(super) enum ServerInner {}

    impl ServerInner {
        pub(super) fn bind(_addr: VsockAddr, _policy: VsockPeerPolicy) -> Result<Self, IoError> {
            Err(unimplemented_on_this_os())
        }

        pub(super) fn local_addr(&self) -> Result<VsockAddr, IoError> {
            match *self {}
        }

        pub(super) fn accept(
            &self,
            _timeout: IoTimeout,
            _on_event: &mut dyn FnMut(&ServerEvent<'_>),
        ) -> AcceptAttempt<ConnectionInner> {
            match *self {}
        }
    }

    pub(super) enum ConnectionInner {}

    impl ConnectionInner {
        pub(super) fn connect(_addr: VsockAddr, _timeout: IoTimeout) -> Result<Self, IoError> {
            Err(unimplemented_on_this_os())
        }

        pub(super) fn try_clone(&self) -> Result<Self, IoError> {
            match *self {}
        }

        pub(super) fn shutdown_both(&self) {
            match *self {}
        }

        pub(super) fn shutdown_write(&self) {
            match *self {}
        }

        pub(super) fn send_frame(
            &mut self,
            _frame: &Frame,
            _timeout: IoTimeout,
        ) -> Result<(), IoError> {
            match *self {}
        }

        pub(super) fn recv_frame(
            &mut self,
            _timeout: IoTimeout,
            _limits: ReceiveLimits,
            _accept_kind: fn(FrameKind) -> Result<(), IoError>,
        ) -> (Result<Frame, IoError>, Option<FrameKind>) {
            match *self {}
        }
    }
}
