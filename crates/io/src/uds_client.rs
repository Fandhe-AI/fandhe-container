//! UDS クライアント側の接続 [`UdsClientConnection`]（IO-1・PLUG-12・REPAIR-5。TASK-13.2・#3165）。
//!
//! # 役割と呼び出し文脈
//! `crate::server::UdsServer`（サーバー側）の対になるクライアント側の入口で、
//! `PipelineClient`（`crate::client`）を実際の UDS の上で動かす経路になる
//! （`docs/design/io-protocol.md`「UDS クライアントと connect」F12〜F14）。接続後の送受信は
//! [`crate::server::UdsConnection`] と同じ実装（`crate::stream_io` のフレーム単位の期限・
//! P1-3 の poison・[`SplitTransport`] の契約）を使い、受信してよいフレーム種別だけを
//! 応答系（`Ack`・`FlushAck`・`Nack`）に切り替える（`Write` / `Flush` 等の要求系を受けると
//! `InvalidArgument` で poison する。確保前に拒否する）。
//!
//! # 接続の手順（F12）
//! 1. 期限（`timeout`）を 1 回だけ決め、期待 uid を 1 回だけ解決する
//!    （[`UdsServerPolicy`]。パス検査と peer の照合に同じ値を使う）
//! 2. **補助の検査**: 親ディレクトリ（symlink でない・ディレクトリ・group / other に
//!    アクセスを許さない・所有者が期待 uid）とソケット自体（`lstat` でソケット・symlink でない・
//!    所有者が期待 uid）。サーバーの bind 検査（`UdsServer::bind`）に揃えた多層防御で、
//!    検査（lstat）と `connect` の間にはパスの差し替えの窓が残る
//! 3. `crate::sys::uds` の期限つき非ブロッキング `connect`（期限切れは `Timeout`）
//! 4. **正の検証**: 接続後に `crate::sys::peer_uid` で相手の uid を照合する（SEC-4・PLUG-12）。
//!    取得失敗・未対応も拒否（fail-closed）し、不一致なら切断して `InvalidArgument` を返し、
//!    観測へ [`crate::observe::ServerOutcome::RejectedPeerCredential`]（op = [`crate::observe::ServerOp::Connect`]）を 1 件通知する
//! 5. blocking へ戻し、期限が過ぎていれば接続を閉じて `Timeout`
//!
//! # 観測フックの扱い（利用上の注意）
//! `connect` が `Err` を返すと観測フック `C` は呼び出し元へ戻らず drop される。拒否イベントを
//! 呼び出し元側で残したい場合は、記録先を共有するフック（例: `Arc<Mutex<_>>` を内包するもの）を
//! 渡す。成功した接続はイベントを出さない（vsock の `VsockConnection::connect` と同じ）。
//!
//! # 未対応
//! Windows など UDS 非対応の OS では [`UdsClientConnection::connect`] は `Unimplemented` を返す
//! （REPAIR-3。実装済みを装わない）。

use std::path::Path;

use crate::error::{IoError, IoErrorCode};
use crate::observe::ServerObserver;
use crate::protocol::Frame;
use crate::recv_limits::ReceiveLimits;
use crate::server::{UdsConnection, UdsRecvHalf, UdsSendHalf};
use crate::transport::{FrameReceiver, FrameSender, IoTimeout, SplitTransport};

/// 接続先サーバーの uid をどう照合するか（PLUG-12・SEC-4）。
///
/// 値は「期待する uid を 1 つ」に限る。全許可は表現できず（`Default` も無い）、
/// 呼び出し側は必ず `exact_uid` か `same_effective_uid` を明示する。
///
/// 注意: `exact_uid` に overflowuid（Linux 既定 65534）を渡すと、user namespace の写像の外にいる
/// 相手（カーネルが overflowuid として見せる）を受理しうる。拒否するかどうかは設計にまだ無い。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdsServerPolicy {
    kind: PolicyKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PolicyKind {
    Exact(u32),
    SameEffective,
}

impl UdsServerPolicy {
    /// 実効 uid が `uid` のサーバーだけを受理する。`u32::MAX`（`(uid_t)-1`。実在しない uid の
    /// 表現）は `InvalidArgument`。
    pub fn exact_uid(uid: u32) -> Result<Self, IoError> {
        if uid == u32::MAX {
            return Err(IoError::new(
                IoErrorCode::InvalidArgument,
                "u32::MAX cannot be used as the expected server uid",
            ));
        }
        Ok(Self {
            kind: PolicyKind::Exact(uid),
        })
    }

    /// 自プロセスと同じ実効 uid のサーバーだけを受理する（`connect` の呼び出し時点の euid）。
    pub fn same_effective_uid() -> Self {
        Self {
            kind: PolicyKind::SameEffective,
        }
    }
}

/// UDS クライアント側の接続 1 本（IO-1・PLUG-12・REPAIR-5。#3165）。
///
/// [`UdsConnection`] を包み、受信してよい種別を応答系に限る。送受信・poison・観測・
/// [`SplitTransport`] の契約は [`UdsConnection`] と同じ。
pub struct UdsClientConnection<C: ServerObserver> {
    inner: UdsConnection<C>,
}

impl<C: ServerObserver> core::fmt::Debug for UdsClientConnection<C> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("UdsClientConnection")
            .field("inner", &self.inner)
            .finish()
    }
}

impl<C: ServerObserver> UdsClientConnection<C> {
    /// `path` のサーバーへ `timeout` を上限に接続し、接続先の uid を `policy` で照合する。
    ///
    /// 手順と補助 / 正の検証の区別はモジュール doc を参照。`limits` は受信上限で、既定値を
    /// 暗黙に使わない（応答のペイロードは `ReceiveLimits::admit` が 16 B 以下に固定する）。
    /// サーバー不在（`ENOENT`・`ECONNREFUSED`）は `Unavailable`、期限切れは `Timeout`、
    /// パス・uid の不一致は `InvalidArgument`。UDS 非対応の OS は `Unimplemented`。
    pub fn connect(
        path: &Path,
        timeout: IoTimeout,
        policy: UdsServerPolicy,
        limits: ReceiveLimits,
        observer: C,
    ) -> Result<Self, IoError> {
        imp::connect(path, timeout, policy, limits, observer).map(|inner| Self { inner })
    }
}

/// 観測フックへのアクセス（接続を作れる OS のみ）。
#[cfg(any(target_os = "linux", target_os = "macos"))]
impl<C: ServerObserver> UdsClientConnection<C> {
    /// 観測フックへの参照。
    pub fn observer(&self) -> &C {
        self.inner.observer_ref()
    }

    /// 観測フックへの可変参照。
    pub fn observer_mut(&mut self) -> &mut C {
        self.inner.observer_mut_ref()
    }
}

impl<C: ServerObserver> FrameSender for UdsClientConnection<C> {
    type Frame = Frame;

    fn send_frame(&mut self, frame: &Frame, timeout: IoTimeout) -> Result<(), IoError> {
        self.inner.send_frame(frame, timeout)
    }
}

impl<C: ServerObserver> FrameReceiver for UdsClientConnection<C> {
    type Frame = Frame;

    fn recv_frame(&mut self, timeout: IoTimeout) -> Result<Frame, IoError> {
        self.inner.recv_frame(timeout)
    }
}

impl<C: ServerObserver> SplitTransport for UdsClientConnection<C> {
    type SendHalf = UdsSendHalf<C>;
    type RecvHalf = UdsRecvHalf<C>;

    fn split(self) -> Result<(UdsSendHalf<C>, UdsRecvHalf<C>), IoError> {
        self.inner.split()
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod imp {
    use std::fs;
    use std::io;
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    use std::os::unix::net::UnixStream;
    use std::path::Path;
    use std::time::Instant;

    use super::{PolicyKind, UdsServerPolicy};
    use crate::error::{IoError, IoErrorCode};
    use crate::observe::{SendEventError, ServerEvent, ServerObserver, ServerOp, ServerOutcome};
    use crate::recv_limits::ReceiveLimits;
    use crate::server::{UdsConnection, validate_socket_parent_dir};
    use crate::transport::IoTimeout;

    pub(super) fn connect<C: ServerObserver>(
        path: &Path,
        timeout: IoTimeout,
        policy: UdsServerPolicy,
        limits: ReceiveLimits,
        mut observer: C,
    ) -> Result<UdsConnection<C>, IoError> {
        let started = Instant::now();
        let deadline = started + timeout.as_duration();
        let expected_uid = match policy.kind {
            PolicyKind::Exact(uid) => uid,
            PolicyKind::SameEffective => crate::sys::effective_uid(),
        };

        precheck_server_path(path, expected_uid)?;

        let stream = crate::sys::uds::connect_unix_until(path, deadline)?.ok_or_else(|| {
            IoError::new(
                IoErrorCode::Timeout,
                "timed out connecting to the unix domain socket",
            )
        })?;
        // `stream_io` は SO_RCVTIMEO / SO_SNDTIMEO に依存するため blocking へ戻す。
        stream.set_nonblocking(false).map_err(|e| {
            IoError::new(
                IoErrorCode::Internal,
                format!("failed to switch the socket to blocking mode: {e}"),
            )
        })?;
        verify_server_peer(&stream, expected_uid, &mut observer, started)?;
        if Instant::now() > deadline {
            // 期限を過ぎた成功は成功扱いにしない（stream は drop で閉じる）。
            return Err(IoError::new(
                IoErrorCode::Timeout,
                "timed out connecting to the unix domain socket",
            ));
        }
        Ok(UdsConnection::from_client_stream(stream, observer, limits))
    }

    /// 接続前の補助検査（F12 手順 2）。サーバーの bind 検査に揃える。
    pub(super) fn precheck_server_path(path: &Path, expected_uid: u32) -> Result<(), IoError> {
        validate_socket_parent_dir(path, expected_uid)?;
        let meta = match fs::symlink_metadata(path) {
            Ok(m) => m,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Err(IoError::new(
                    IoErrorCode::Unavailable,
                    "unix domain socket server is not available",
                ));
            }
            Err(e) => {
                return Err(IoError::new(
                    IoErrorCode::Internal,
                    format!("failed to stat socket path: {e}"),
                ));
            }
        };
        if meta.file_type().is_symlink() {
            return Err(IoError::new(
                IoErrorCode::InvalidArgument,
                "socket path must not be a symlink",
            ));
        }
        if !meta.file_type().is_socket() {
            return Err(IoError::new(
                IoErrorCode::InvalidArgument,
                "socket path is not a unix domain socket",
            ));
        }
        if meta.uid() != expected_uid {
            return Err(IoError::new(
                IoErrorCode::InvalidArgument,
                "socket file is not owned by the expected uid",
            ));
        }
        Ok(())
    }

    /// 接続後の peer uid の照合（正の検証。SEC-4・PLUG-12）。取得失敗も不一致も拒否し、
    /// 観測へ 1 件通知する。呼び出し元は `Err` なら `stream` を drop して切断する。
    pub(crate) fn verify_server_peer<C: ServerObserver>(
        stream: &UnixStream,
        expected_uid: u32,
        observer: &mut C,
        started: Instant,
    ) -> Result<(), IoError> {
        let (peer_uid, err) = match crate::sys::peer_uid(stream) {
            Ok(uid) if uid == expected_uid => return Ok(()),
            Ok(uid) => (
                Some(uid),
                IoError::new(
                    IoErrorCode::InvalidArgument,
                    "connected server uid does not match the expected uid",
                ),
            ),
            Err(e) => (None, e),
        };
        observer.on_event(&ServerEvent {
            op: ServerOp::Connect,
            kind: None,
            outcome: ServerOutcome::RejectedPeerCredential,
            latency: started.elapsed(),
            accept_aborted_retries: 0,
            peer_credential_rejections: 1,
            peer_uid,
            peer_cid: None,
            coalesced: None,
            error: Some(SendEventError {
                code: err.code(),
                message: err.message(),
            }),
        });
        Err(err)
    }

    #[cfg(test)]
    pub(super) use verify_server_peer as verify_server_peer_for_test;
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
mod imp {
    use std::path::Path;

    use super::UdsServerPolicy;
    use crate::error::{IoError, IoErrorCode};
    use crate::observe::ServerObserver;
    use crate::recv_limits::ReceiveLimits;
    use crate::server::UdsConnection;
    use crate::transport::IoTimeout;

    pub(super) fn connect<C: ServerObserver>(
        _path: &Path,
        _timeout: IoTimeout,
        _policy: UdsServerPolicy,
        _limits: ReceiveLimits,
        _observer: C,
    ) -> Result<UdsConnection<C>, IoError> {
        Err(IoError::new(
            IoErrorCode::Unimplemented,
            "unix domain socket transport is not supported on this platform",
        ))
    }
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod tests {
    use super::imp::{precheck_server_path, verify_server_peer_for_test};
    use super::*;
    use crate::observe::{ServerEvent, ServerOp, ServerOutcome};
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::PathBuf;
    use std::time::Instant;

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct Rec {
        op: ServerOp,
        outcome: ServerOutcome,
        peer_uid: Option<u32>,
        rejections: u32,
        code: Option<IoErrorCode>,
    }

    #[derive(Clone, Default)]
    struct Recorder(std::sync::Arc<std::sync::Mutex<Vec<Rec>>>);

    impl ServerObserver for Recorder {
        fn on_event(&mut self, e: &ServerEvent<'_>) {
            self.0.lock().expect("lock").push(Rec {
                op: e.op,
                outcome: e.outcome,
                peer_uid: e.peer_uid,
                rejections: e.peer_credential_rejections,
                code: e.error.as_ref().map(|x| x.code),
            });
        }
    }

    fn euid() -> u32 {
        crate::sys::effective_uid()
    }

    /// 0700 の一時ディレクトリ（テストごとに固有）。
    fn private_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "fc-io-udsc-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create dir");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        dir
    }

    /// PLUG-12・#3165: `u32::MAX` は期待 uid にできない。
    #[test]
    fn plug12_uds_server_policy_rejects_invalid_uid() {
        let err = UdsServerPolicy::exact_uid(u32::MAX).expect_err("must reject");
        assert_eq!(err.code(), IoErrorCode::InvalidArgument);
        assert_eq!(
            UdsServerPolicy::exact_uid(1000).expect("ok").kind,
            PolicyKind::Exact(1000)
        );
    }

    #[test]
    fn plug12_same_effective_uid_resolves_to_euid() {
        assert_eq!(
            UdsServerPolicy::same_effective_uid().kind,
            PolicyKind::SameEffective
        );
    }

    /// PLUG-12・SEC-4・#3165: peer uid が違えば `InvalidArgument` で拒否し、観測へ 1 件通知する。
    #[test]
    fn plug12_sec4_verify_server_peer_rejects_mismatched_uid_and_notifies() {
        let (a, _b) = UnixStream::pair().expect("pair");
        let mut rec = Recorder::default();
        let log = rec.0.clone();
        let wrong = euid().wrapping_add(1);
        let err = verify_server_peer_for_test(&a, wrong, &mut rec, Instant::now())
            .expect_err("must reject");
        assert_eq!(err.code(), IoErrorCode::InvalidArgument);
        let events = log.lock().expect("lock").clone();
        assert_eq!(
            events,
            vec![Rec {
                op: ServerOp::Connect,
                outcome: ServerOutcome::RejectedPeerCredential,
                peer_uid: Some(euid()),
                rejections: 1,
                code: Some(IoErrorCode::InvalidArgument),
            }]
        );
    }

    /// PLUG-12・#3165: 一致すれば通知なしで受理する。
    #[test]
    fn plug12_verify_server_peer_accepts_matching_uid() {
        let (a, _b) = UnixStream::pair().expect("pair");
        let mut rec = Recorder::default();
        let log = rec.0.clone();
        verify_server_peer_for_test(&a, euid(), &mut rec, Instant::now()).expect("accept");
        assert!(log.lock().expect("lock").is_empty());
    }

    /// IO-1・PLUG-12・#3165: パス検査の各ケース。
    #[test]
    fn io1_plug12_precheck_server_path_cases() {
        let me = euid();

        // 正常: 自分所有の 0700 ディレクトリ内のソケット。
        let dir = private_dir("ok");
        let sock = dir.join("s.sock");
        let _l = UnixListener::bind(&sock).expect("bind");
        precheck_server_path(&sock, me).expect("owner socket is accepted");
        // 所有者の不一致。
        let err = precheck_server_path(&sock, me.wrapping_add(1)).expect_err("owner mismatch");
        assert_eq!(err.code(), IoErrorCode::InvalidArgument);

        // 存在しない。
        let err = precheck_server_path(&dir.join("none.sock"), me).expect_err("missing");
        assert_eq!(err.code(), IoErrorCode::Unavailable);

        // 通常ファイル。
        let file = dir.join("plain");
        std::fs::write(&file, b"x").expect("write");
        let err = precheck_server_path(&file, me).expect_err("not a socket");
        assert_eq!(err.code(), IoErrorCode::InvalidArgument);

        // ソケットへの symlink。
        let link = dir.join("link.sock");
        std::os::unix::fs::symlink(&sock, &link).expect("symlink");
        let err = precheck_server_path(&link, me).expect_err("symlink");
        assert_eq!(err.code(), IoErrorCode::InvalidArgument);

        // 親ディレクトリが group / other に開かれている。
        for mode in [0o720, 0o702, 0o770] {
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(mode)).expect("chmod");
            let err = precheck_server_path(&sock, me).expect_err("open parent");
            assert_eq!(err.code(), IoErrorCode::InvalidArgument, "mode={mode:o}");
        }
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).expect("chmod");

        // 親ディレクトリが symlink。
        let real = private_dir("real");
        let real_sock = real.join("s.sock");
        let _l2 = UnixListener::bind(&real_sock).expect("bind");
        let parent_link = dir.join("parent-link");
        std::os::unix::fs::symlink(&real, &parent_link).expect("symlink");
        let err = precheck_server_path(&parent_link.join("s.sock"), me).expect_err("parent link");
        assert_eq!(err.code(), IoErrorCode::InvalidArgument);

        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&real);
    }
}
