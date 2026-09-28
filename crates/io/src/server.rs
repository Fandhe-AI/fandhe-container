//! UDS（Unix domain socket）のサーバー側トランスポート（TASK-13.2.1・IO-1・#820）。
//!
//! [`crate::transport`] が定めるトランスポート抽象（[`FrameSender`]・
//! [`FrameReceiver`]）の、具象実装の 1 つ目（REPAIR-3: `transport` モジュールは
//! 具象実装を持たないと明記していたが、本タスクで Linux / macOS 向けの UDS
//! サーバー側を追加した）。TASK-13.2.2（#822）がこの上にバッチ書き込み・
//! ACK 返却を積む想定で、本モジュールは「1 本の接続でフレームを送受信できる
//! こと」までを提供する。
//!
//! # 受付ループの組み方（呼び出し側の責務）
//!
//! std だけでは `UnixListener::accept()` を無期限に待たずに済ませられないため
//! （REPAIR-5: 相手の応答を待つ処理には必ずタイムアウトを設ける）、
//! [`UdsServer::accept`] は期限付きの 1 回分の受け付けまでしか提供しない。
//! 「受け付け → 処理 → 次の受け付け」のループ自体は呼び出し側（TASK-13.2.2 の
//! サーバー本体）が組み、同時接続数の上限などの運用方針もそちら側で決める
//! （本 crate は 1 接続の送受信責務のみを負う）。
//!
//! # OS 対応
//!
//! Linux / macOS では [`UdsServer`]・[`UdsConnection`] は実際に UDS を bind・
//! accept・送受信する。それ以外の OS（Windows）では [`UdsServer::bind`] が
//! 常に [`IoErrorCode::Unimplemented`] を返し、内部状態は uninhabited な enum
//! で表すため他のメソッドは呼び出し不能になる（実装済みを装わない。
//! REPAIR-3）。Windows のトランスポート（`windows-sys` を使った AF_UNIX、または
//! named pipe）は `windows-sys` の依存承認が必要な別タスクとする。
//!
//! # 範囲外（TASK-13.2.2 以降・別タスク）
//!
//! - ACK フレームの送出方針・ディスク書き込み・[`crate::batch::BatchBuffer`] との
//!   つなぎ込み（TASK-13.2.2・#822）
//! - 同時接続数の上限（TASK-13.4）
//! - [`recv_limits::ReceiveLimits::admit`] の滞留件数（`pending_frames`）は本
//!   モジュールでは常に `0` を渡す（この層は単一接続しか見えず、複数接続を
//!   跨いだ実際の準備完了キューを持たないため）。実際のキューとの配線は
//!   [`crate::batch::BatchBuffer`] を導入する TASK-13.2.2（#822）の責務
//!   （`crates/io/src/recv_limits.rs` モジュール doc 参照）
//! - peer credential の検証（`SO_PEERCRED` / `getpeereid`）: std だけでは実装
//!   できず `libc` / `nix` の依存承認が必要（PLUG-12 の別観点。所有 UID の
//!   照合自体は本タスクで [`imp::check_socket_owner`] により実装済み）
//! - 送信側と受信側の分割 API（`try_clone` を使った split。TASK-12）
//! - クライアント側の UDS 接続（`connect`）・[`crate::client::PipelineClient`]
//!   との結合（TASK-12.2 以降）
//! - vsock（microVM）トランスポート
//! - bind から `0600` への chmod 完了までの短い窓（[`UdsServer::bind`] の
//!   ドキュメンテーションコメント参照）は親ディレクトリの権限で塞ぐ設計とし、
//!   ソケットファイル自体の一時的なモードには依存しない
//! - `path` の直近の親ディレクトリ以外（祖先のパス要素）の symlink 検査は
//!   行わない（[`imp::validate_parent_dir`] のドキュメンテーションコメント
//!   参照）
//!
//! # SIGPIPE の前提
//!
//! Rust の実行時環境（バイナリ・テストハーネス双方）は SIGPIPE を無視するよう
//! 設定しているため、切断済みの相手への書き込みは（プロセスを終了させずに）
//! `BrokenPipe` エラーとして観測でき、本実装はそれを
//! [`IoErrorCode::Unavailable`] へ変換する。本 library を Rust 以外の実行時
//! から使う場合はこの前提が崩れうるため範囲外とする。

use std::path::Path;

use crate::error::{IoError, IoErrorCode};
use crate::protocol::Frame;
use crate::transport::{FrameReceiver, FrameSender, IoTimeout};

/// UDS の接続受け付け役（TASK-13.2.1・IO-1）。
///
/// `bind` したソケットファイルは [`Drop`] で片付ける。片付けの直前に
/// 「自分が bind したパスがまだソケットファイルのままであること」を
/// `symlink_metadata` で確かめ、別種のファイルに置き換わっていた場合は
/// 削除しない（任意のファイルを消す経路を作らないため。security.md）。
pub struct UdsServer {
    inner: imp::ServerInner,
}

impl core::fmt::Debug for UdsServer {
    /// パス以外の内部状態（socket fd 等）は出力しない。
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("UdsServer")
            .field("path", &self.path())
            .finish()
    }
}

impl UdsServer {
    /// `path` に UDS を bind する。
    ///
    /// bind 前に親ディレクトリ（symlink でない・ディレクトリである・
    /// owner 以外に read / write / search のいずれも与えない）と `path` 自体
    /// （既存パスは拒否し、自動 unlink はしない）を検証する（security.md の
    /// UDS 観点。fail-closed）。bind 直後には、作成されたソケットファイルの
    /// 所有者（bind したプロセスの実効 uid と一致する）が親ディレクトリの
    /// 所有者と一致することも確かめ（PLUG-12・[`imp::check_socket_owner`]）、
    /// 不一致ならソケットファイルを片付けてから拒否する。検証後はソケット
    /// ファイルを `0600` にし、listener を非ブロッキングにする。
    ///
    /// # 既知の残存リスク（bind から chmod までの窓）
    /// `UnixListener::bind` はソケットファイルの作成と listen の開始を同時に
    /// 行うため、上記の検証・`0600` へのチャモードが完了するまでの短い間、
    /// ソケットファイルの実効モードは umask 依存になる。親ディレクトリを
    /// owner 専用（`0700` 以下）にする検証が実質的な防壁であり、この窓の
    /// 間に到達できるのは親ディレクトリを辿れる者（＝ owner 本人）に限られる。
    pub fn bind(path: &Path) -> Result<Self, IoError> {
        Ok(Self {
            inner: imp::ServerInner::bind(path)?,
        })
    }

    /// 接続を 1 件、`timeout` を上限に受け付ける。
    ///
    /// 期限を過ぎても接続が来なければ [`IoErrorCode::Timeout`] を返す
    /// （REPAIR-5: 無期限にブロックしない）。呼び出し側は次の接続を待つために
    /// 再度この関数を呼ぶ（受付ループはこのモジュールの外で組む）。
    pub fn accept(&self, timeout: IoTimeout) -> Result<UdsConnection, IoError> {
        Ok(UdsConnection {
            inner: self.inner.accept(timeout)?,
            poisoned: false,
        })
    }

    /// bind したソケットファイルのパスを返す。
    pub fn path(&self) -> &Path {
        self.inner.path()
    }
}

/// 受け付けた UDS 接続 1 本（TASK-13.2.1・IO-1）。
///
/// [`FrameSender`]・[`FrameReceiver`] を実装し（blanket impl により
/// [`crate::transport::FrameTransport`] にもなる）、単一スレッドで `&mut self`
/// を使う前提とする（`transport` モジュールの契約どおり。送信側・受信側の
/// 分割は TASK-12 の範囲）。
///
/// `send_frame` / `recv_frame` のいずれかが一度でも `Err` を返すと以後
/// [`IoErrorCode::Unavailable`] を返し続ける（P1-3・REPAIR-5・REPAIR-6。
/// `FrameHeader` に同期マーカーがなく、送受信途中のエラー後はフレーム境界を
/// 復元できないため接続を再利用しない）。
pub struct UdsConnection {
    inner: imp::ConnectionInner,
    poisoned: bool,
}

impl core::fmt::Debug for UdsConnection {
    /// socket fd 等の内部状態は出力せず、poison 状態のみを出す。
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("UdsConnection")
            .field("poisoned", &self.poisoned)
            .finish()
    }
}

impl UdsConnection {
    /// `send_frame` / `recv_frame` の結果を見て poison 状態を更新する
    /// （P1-3 の契約を守る箇所をここ 1 か所に集約する）。
    fn poison_on_err<T>(&mut self, result: Result<T, IoError>) -> Result<T, IoError> {
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
}

/// poison 済み接続への呼び出しに返すエラー（P1-3）。
fn unavailable_after_poison() -> IoError {
    IoError::new(
        IoErrorCode::Unavailable,
        "connection is poisoned by a previous error and must be reconnected",
    )
}

impl FrameSender for UdsConnection {
    type Frame = Frame;

    fn send_frame(&mut self, frame: &Frame, timeout: IoTimeout) -> Result<(), IoError> {
        if self.poisoned {
            return Err(unavailable_after_poison());
        }
        let result = self.inner.send_frame(frame, timeout);
        self.poison_on_err(result)
    }
}

impl FrameReceiver for UdsConnection {
    type Frame = Frame;

    fn recv_frame(&mut self, timeout: IoTimeout) -> Result<Frame, IoError> {
        if self.poisoned {
            return Err(unavailable_after_poison());
        }
        let result = self.inner.recv_frame(timeout);
        self.poison_on_err(result)
    }
}

/// Linux / macOS 向けの UDS 実装（`server.rs` の外へ OS 固有型を漏らさない。
/// coding-rust「クロスプラットフォーム」節）。
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod imp {
    use std::fs::{self, Permissions};
    use std::io::{self, Read, Write};
    use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::{Path, PathBuf};
    use std::time::{Duration, Instant};

    use crate::error::{IoError, IoErrorCode};
    use crate::protocol::{FRAME_HEADER_LEN, Frame, FrameHeader};
    use crate::recv_limits::ReceiveLimits;
    use crate::transport::IoTimeout;

    /// `WouldBlock` になった `accept` を待ち直す際の 1 回あたりの上限
    /// スリープ時間。std だけでは poll(2) が使えないため、上限つきの
    /// ポーリングで代用する（根拠: coding-rust は `unsafe` な syscall 直叩きを
    /// 最小限にする方針であり、本タスクの受け入れ条件は依存追加なしの
    /// std 実装を求めている）。
    const ACCEPT_POLL_INTERVAL: Duration = Duration::from_millis(5);

    /// `accept` が `ConnectionAborted`（相手が accept 完了前に切断した）を
    /// 受け続けた場合の再試行回数の上限（REPAIR-5: 相手の応答を待つ処理は
    /// 無期限にループしない。`deadline` 自体も毎回照合するため、この上限は
    /// 「短時間に大量の切断が続く」病的なケースの保険）。
    const MAX_ACCEPT_ABORT_RETRIES: u32 = 32;

    /// 本体読み込みを少しずつ伸ばす際の 1 回あたりの読み取り上限
    /// （申告された `body_len` が最大 64 MiB + 4 バイトでも、悪意ある相手の
    /// 申告だけを信用して一度に確保しない。security.md）。
    const BODY_READ_CHUNK: usize = 64 * 1024;

    pub(super) struct ServerInner {
        listener: UnixListener,
        path: PathBuf,
    }

    impl ServerInner {
        pub(super) fn bind(path: &Path) -> Result<Self, IoError> {
            let parent_uid = validate_parent_dir(path)?;
            reject_existing_path(path)?;

            let listener = UnixListener::bind(path).map_err(map_bind_error)?;

            // bind 後の後始末（所有者検証・chmod・nonblocking 化）が失敗したら、
            // 作成済みのソケットファイルを片付けてからエラーを返す（後始末自体の
            // 失敗は握りつぶし、元のエラーを優先して返す。cleanup_socket_file
            // 参照）。
            if let Err(err) = finish_bind(&listener, path, parent_uid) {
                cleanup_socket_file(path);
                return Err(err);
            }

            Ok(Self {
                listener,
                path: path.to_path_buf(),
            })
        }

        pub(super) fn path(&self) -> &Path {
            &self.path
        }

        pub(super) fn accept(&self, timeout: IoTimeout) -> Result<ConnectionInner, IoError> {
            let deadline = Instant::now() + timeout.as_duration();
            let mut abort_retries = 0u32;
            loop {
                match self.listener.accept() {
                    Ok((stream, _addr)) => {
                        // macOS では accept() した stream がリスナーの
                        // O_NONBLOCK を引き継ぐ（Linux では引き継がないが、
                        // 呼んでも無害なので常に呼ぶ）。
                        stream.set_nonblocking(false).map_err(|e| {
                            IoError::new(
                                IoErrorCode::Internal,
                                format!("failed to clear nonblocking mode on accepted stream: {e}"),
                            )
                        })?;
                        return Ok(ConnectionInner { stream });
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        let remaining = deadline.saturating_duration_since(Instant::now());
                        if remaining.is_zero() {
                            return Err(IoError::new(
                                IoErrorCode::Timeout,
                                "accept timed out waiting for a client connection",
                            ));
                        }
                        std::thread::sleep(remaining.min(ACCEPT_POLL_INTERVAL));
                    }
                    Err(e) if e.kind() == io::ErrorKind::ConnectionAborted => {
                        // 相手が accept 完了前に切断しただけであり、受付ループ
                        // 自体を終わらせる理由にはならない（REPAIR-5 の趣旨:
                        // 一時的な相手都合で受付が止まらないようにする）。
                        // ただし無期限にリトライしないよう、期限と回数の両方で
                        // 打ち切る。
                        let remaining = deadline.saturating_duration_since(Instant::now());
                        if remaining.is_zero() {
                            return Err(IoError::new(
                                IoErrorCode::Timeout,
                                "accept timed out waiting for a client connection",
                            ));
                        }
                        abort_retries += 1;
                        if abort_retries > MAX_ACCEPT_ABORT_RETRIES {
                            return Err(IoError::new(
                                IoErrorCode::Internal,
                                "accept exceeded the retry limit after repeated peer \
                                 disconnects before accept completed",
                            ));
                        }
                    }
                    Err(e) => {
                        return Err(IoError::new(
                            IoErrorCode::Internal,
                            format!("accept failed: {e}"),
                        ));
                    }
                }
            }
        }
    }

    impl Drop for ServerInner {
        fn drop(&mut self) {
            cleanup_socket_file(&self.path);
        }
    }

    /// 自分が bind したソケットファイルを片付ける。削除の直前に
    /// `symlink_metadata` でソケットのままであることを確かめ、別種の
    /// ファイル（他プロセスが同じパスへ作り直した等）に置き換わっていたら
    /// 削除しない。
    fn cleanup_socket_file(path: &Path) {
        if let Ok(meta) = fs::symlink_metadata(path)
            && meta.file_type().is_socket()
        {
            let _ = fs::remove_file(path);
        }
    }

    /// bind 直後の後始末: 所有者検証（PLUG-12）→ `0600` への chmod →
    /// listener の非ブロッキング化、の順に行う。いずれかに失敗すれば
    /// 呼び出し元（[`ServerInner::bind`]）がソケットファイルを片付ける。
    fn finish_bind(listener: &UnixListener, path: &Path, parent_uid: u32) -> Result<(), IoError> {
        let socket_uid = fs::symlink_metadata(path)
            .map_err(|e| {
                IoError::new(
                    IoErrorCode::Internal,
                    format!("failed to stat the socket file after bind: {e}"),
                )
            })?
            .uid();
        check_socket_owner(socket_uid, parent_uid)?;

        fs::set_permissions(path, Permissions::from_mode(0o600)).map_err(|e| {
            IoError::new(
                IoErrorCode::Internal,
                format!("failed to set socket file permissions to 0600: {e}"),
            )
        })?;
        listener.set_nonblocking(true).map_err(|e| {
            IoError::new(
                IoErrorCode::Internal,
                format!("failed to set listener to nonblocking mode: {e}"),
            )
        })?;
        Ok(())
    }

    /// ソケットファイルの所有者（`socket_uid`）が親ディレクトリの所有者
    /// （`parent_uid`）と一致することを確かめる（PLUG-12・security.md「UDS は
    /// 所有者・権限・symlink を検証してから bind」）。
    ///
    /// プロセスの実効 uid は std だけでは直接取得できないため（`libc` の
    /// `geteuid` 相当の依存が必要）、bind 直後のソケットファイルの所有者
    /// （自分が作成したので実効 uid と一致する）を実効 uid の代理として使う。
    /// uid の比較自体は純粋関数に切り出し、実機で別ユーザーを用意できない
    /// 単体テストからも具体的な uid の組で検証できるようにする
    /// （コミット 2・項目 10）。
    fn check_socket_owner(socket_uid: u32, parent_uid: u32) -> Result<(), IoError> {
        if socket_uid != parent_uid {
            return Err(IoError::new(
                IoErrorCode::InvalidArgument,
                format!(
                    "socket file owner (uid {socket_uid}) does not match the parent \
                     directory owner (uid {parent_uid})"
                ),
            ));
        }
        Ok(())
    }

    /// 親ディレクトリが symlink でなく・ディレクトリであり・owner 以外に
    /// read / write / search のいずれも与えていないことを確かめる
    /// （security.md の UDS 観点。fail-closed）。検証に成功した場合は
    /// [`finish_bind`] の所有者照合で使う親ディレクトリの uid を返す。
    ///
    /// `0o077` まで絞る理由: bind 直後から `0600` への chmod が完了するまでの
    /// 短い間、ソケットファイル自体のモードは umask 依存で緩くなりうる
    /// （[`UdsServer::bind`] のドキュメンテーションコメント参照）。ソケットは
    /// 最終的に owner 専用になるため、親ディレクトリを owner 専用にしても
    /// 正当な用途を妨げない一方、この窓を親ディレクトリの権限で実質的に塞げる。
    ///
    /// 直近の親ディレクトリのみを検査し、祖先のパス要素（親の親など）の
    /// symlink は検査しない（`Path::parent()` はパスを正規化しないため、
    /// 祖先を辿るには `canonicalize` 相当の解決が必要になるが、macOS の
    /// `/tmp` が `/private/tmp` への symlink であるように、canonicalize 結果を
    /// 素朴に比較する方式は環境依存の誤判定を生みやすく採らない。範囲外として
    /// `server.rs` モジュール doc に明記する）。
    fn validate_parent_dir(path: &Path) -> Result<u32, IoError> {
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .ok_or_else(|| {
                IoError::new(
                    IoErrorCode::InvalidArgument,
                    "socket path must have a parent directory",
                )
            })?;
        let meta = fs::symlink_metadata(parent).map_err(|e| {
            IoError::new(
                IoErrorCode::InvalidArgument,
                format!("failed to stat parent directory: {e}"),
            )
        })?;
        if meta.file_type().is_symlink() {
            return Err(IoError::new(
                IoErrorCode::InvalidArgument,
                "parent directory of the socket path must not be a symlink",
            ));
        }
        if !meta.is_dir() {
            return Err(IoError::new(
                IoErrorCode::InvalidArgument,
                "parent path of the socket path is not a directory",
            ));
        }
        if meta.mode() & 0o077 != 0 {
            return Err(IoError::new(
                IoErrorCode::InvalidArgument,
                "parent directory of the socket path must not grant access to \
                 non-owner users",
            ));
        }
        Ok(meta.uid())
    }

    /// 既存パス（ファイル・symlink・古いソケット等）を拒否する。任意のファイルを
    /// 消す経路を作らないため、ここでの自動 unlink はしない。
    fn reject_existing_path(path: &Path) -> Result<(), IoError> {
        match fs::symlink_metadata(path) {
            Ok(_) => Err(IoError::new(
                IoErrorCode::InvalidArgument,
                "socket path already exists; remove it before binding",
            )),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(IoError::new(
                IoErrorCode::Internal,
                format!("failed to stat socket path: {e}"),
            )),
        }
    }

    /// `UnixListener::bind` のエラーを `IoError` へ変換する。sun_path の上限
    /// （Linux 108 / macOS 104 バイト）超過は std が `InvalidInput` を返すため
    /// `InvalidArgument` にまとめる。
    fn map_bind_error(e: io::Error) -> IoError {
        if e.kind() == io::ErrorKind::InvalidInput {
            IoError::new(
                IoErrorCode::InvalidArgument,
                "socket path exceeds the platform's maximum unix domain socket path length",
            )
        } else {
            IoError::new(
                IoErrorCode::Internal,
                format!("failed to bind unix domain socket: {e}"),
            )
        }
    }

    pub(super) struct ConnectionInner {
        stream: UnixStream,
    }

    impl ConnectionInner {
        /// `frame.encode()` の結果を、フレーム単位の期限つきで最後まで書き切る。
        pub(super) fn send_frame(
            &mut self,
            frame: &Frame,
            timeout: IoTimeout,
        ) -> Result<(), IoError> {
            let deadline = Instant::now() + timeout.as_duration();
            let bytes = frame.encode();
            write_all_until(&mut self.stream, &bytes, deadline)
        }

        /// `crate::protocol` の「ストリーム読みの手順」（1: 固定長ヘッダを読む→
        /// 2: `FrameHeader::from_bytes` で検証→3: `ReceiveLimits::admit` で
        /// 確保前の受理判定→4: 検証済みの `body_len` を上限に本体を読む→
        /// 5: `Frame::decode_body` に渡す）どおりに実装する。
        ///
        /// `ReceiveLimits::admit` に渡す滞留件数（`pending_frames`）は常に
        /// `0` にする。この層は単一接続の送受信のみを担い、複数接続を跨いだ
        /// 実際の準備完了キューを持たないため（本ファイルのモジュール doc
        /// 「範囲外」節・`crates/io/src/recv_limits.rs` モジュール doc
        /// 参照）。したがってここで効くのは `ReceiveLimits` のペイロード長
        /// 上限（`Write` は `BatchConfig` 由来の設定上限、制御フレームは
        /// `MAX_CONTROL_PAYLOAD_LEN`）の確保前検証のみであり、滞留件数上限の
        /// 実効化は TASK-13.2.2（#822）が `BatchBuffer` を配線した時点で
        /// 初めて機能する。
        pub(super) fn recv_frame(&mut self, timeout: IoTimeout) -> Result<Frame, IoError> {
            let deadline = Instant::now() + timeout.as_duration();

            let mut header_bytes = [0u8; FRAME_HEADER_LEN];
            read_exact_until(
                &mut self.stream,
                &mut header_bytes,
                deadline,
                "frame header",
            )?;

            let header = FrameHeader::from_bytes(header_bytes)?;
            let admitted = ReceiveLimits::default().admit(header, 0)?;

            let body = read_body_until(&mut self.stream, admitted.body_len(), deadline)?;

            admitted.decode_body(&body)
        }
    }

    /// `deadline` までの残り時間を返す。残りが 0 以下ならその場で
    /// [`IoErrorCode::Timeout`] を返す（`Duration::ZERO` を
    /// `set_read_timeout` / `set_write_timeout` に渡すと std がエラーに
    /// するため、ここで先に弾く）。
    fn remaining_or_timeout(deadline: Instant) -> Result<Duration, IoError> {
        let now = Instant::now();
        if now >= deadline {
            return Err(IoError::new(
                IoErrorCode::Timeout,
                "frame deadline exceeded before the operation completed",
            ));
        }
        Ok(deadline - now)
    }

    /// `io::Error` を `IoError` へ変換する（`crate::error` の `IoErrorCode`・
    /// ERR-1 対応）。相手から届いたデータを message に含めず、`ErrorKind`
    /// 程度の情報のみを載せる（security.md「情報漏えい」観点）。
    ///
    /// `WouldBlock` / `TimedOut` もここでは `Timeout` に写像するが、
    /// `read_exact_until` / `read_body_until` / `write_all_until` は
    /// これらのエラーを本関数に渡さず、`remaining_or_timeout` によるフレーム
    /// 全体の期限の再計算へループを戻す（REPAIR-5・項目 4）。テスト
    /// （`task13_2_1_map_io_error_maps_would_block_and_timed_out_to_timeout`）
    /// のために写像自体はここに残す。
    fn map_io_error(e: io::Error) -> IoError {
        match e.kind() {
            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => {
                IoError::new(IoErrorCode::Timeout, "io operation timed out")
            }
            io::ErrorKind::BrokenPipe
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::NotConnected => IoError::new(
                IoErrorCode::Unavailable,
                format!("peer connection is unavailable: {}", e.kind()),
            ),
            other => IoError::new(IoErrorCode::Internal, format!("io error: {other}")),
        }
    }

    /// `buf` を埋め切るまで読む。フレーム全体の `deadline` を基準に毎回残り
    /// 時間を計算し直すため、1 バイトずつ小出しに送ってくる相手でも
    /// フレーム全体の期限で必ず打ち切られる（REPAIR-5）。
    fn read_exact_until(
        stream: &mut UnixStream,
        buf: &mut [u8],
        deadline: Instant,
        what: &'static str,
    ) -> Result<(), IoError> {
        let mut filled = 0usize;
        while filled < buf.len() {
            let remaining = remaining_or_timeout(deadline)?;
            stream.set_read_timeout(Some(remaining)).map_err(|e| {
                IoError::new(
                    IoErrorCode::Internal,
                    format!("failed to set read timeout: {e}"),
                )
            })?;
            let Some(dst) = buf.get_mut(filled..) else {
                return Err(IoError::new(
                    IoErrorCode::Internal,
                    "read buffer index out of range",
                ));
            };
            match stream.read(dst) {
                Ok(0) => {
                    return Err(IoError::new(
                        IoErrorCode::Unavailable,
                        format!("peer closed the connection before sending a complete {what}"),
                    ));
                }
                Ok(n) => filled += n,
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::Interrupted
                            | io::ErrorKind::WouldBlock
                            | io::ErrorKind::TimedOut
                    ) =>
                {
                    // 個々の read 呼び出しの期限切れ（`WouldBlock` /
                    // `TimedOut`）では即座に諦めず、`remaining_or_timeout` に
                    // よるフレーム全体の期限の再計算へループを戻す
                    // （REPAIR-5）。期限を過ぎていれば次の周回の先頭で
                    // `remaining_or_timeout` が `Timeout` を返す。
                    continue;
                }
                Err(e) => return Err(map_io_error(e)),
            }
        }
        Ok(())
    }

    /// `body_len` バイトの本体を、届いた分だけ少しずつ確保しながら読む
    /// （申告された長さだけで一度に確保しない。security.md の DoS 対策）。
    fn read_body_until(
        stream: &mut UnixStream,
        body_len: usize,
        deadline: Instant,
    ) -> Result<Vec<u8>, IoError> {
        let mut body = Vec::with_capacity(body_len.min(BODY_READ_CHUNK));
        let mut chunk = [0u8; BODY_READ_CHUNK];
        while body.len() < body_len {
            let remaining = remaining_or_timeout(deadline)?;
            stream.set_read_timeout(Some(remaining)).map_err(|e| {
                IoError::new(
                    IoErrorCode::Internal,
                    format!("failed to set read timeout: {e}"),
                )
            })?;
            let want = (body_len - body.len()).min(chunk.len());
            let Some(dst) = chunk.get_mut(..want) else {
                return Err(IoError::new(
                    IoErrorCode::Internal,
                    "read chunk index out of range",
                ));
            };
            match stream.read(dst) {
                Ok(0) => {
                    return Err(IoError::new(
                        IoErrorCode::Unavailable,
                        "peer closed the connection before sending a complete frame body",
                    ));
                }
                Ok(n) => {
                    if let Some(read) = dst.get(..n) {
                        body.extend_from_slice(read);
                    }
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::Interrupted
                            | io::ErrorKind::WouldBlock
                            | io::ErrorKind::TimedOut
                    ) =>
                {
                    // read_exact_until と同じ理由でループを戻す（REPAIR-5）。
                    continue;
                }
                Err(e) => return Err(map_io_error(e)),
            }
        }
        Ok(body)
    }

    /// `bytes` を書き切るまで送る（`write_all` 相当をフレーム単位の期限付きで
    /// 自前実装したもの）。
    fn write_all_until(
        stream: &mut UnixStream,
        bytes: &[u8],
        deadline: Instant,
    ) -> Result<(), IoError> {
        let mut written = 0usize;
        while written < bytes.len() {
            let remaining = remaining_or_timeout(deadline)?;
            stream.set_write_timeout(Some(remaining)).map_err(|e| {
                IoError::new(
                    IoErrorCode::Internal,
                    format!("failed to set write timeout: {e}"),
                )
            })?;
            let Some(src) = bytes.get(written..) else {
                return Err(IoError::new(
                    IoErrorCode::Internal,
                    "write buffer index out of range",
                ));
            };
            match stream.write(src) {
                Ok(0) => {
                    return Err(IoError::new(
                        IoErrorCode::Unavailable,
                        "peer connection accepted zero bytes",
                    ));
                }
                Ok(n) => written += n,
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::Interrupted
                            | io::ErrorKind::WouldBlock
                            | io::ErrorKind::TimedOut
                    ) =>
                {
                    // read_exact_until と同じ理由でループを戻す（REPAIR-5）。
                    continue;
                }
                Err(e) => return Err(map_io_error(e)),
            }
        }
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// TASK-13.2.1: `WouldBlock` / `TimedOut` は `Timeout` に写像される。
        #[test]
        fn task13_2_1_map_io_error_maps_would_block_and_timed_out_to_timeout() {
            let err = map_io_error(io::Error::from(io::ErrorKind::WouldBlock));
            assert_eq!(err.code(), IoErrorCode::Timeout);

            let err = map_io_error(io::Error::from(io::ErrorKind::TimedOut));
            assert_eq!(err.code(), IoErrorCode::Timeout);
        }

        /// TASK-13.2.1: 切断系の `ErrorKind` は `Unavailable` に写像される。
        #[test]
        fn task13_2_1_map_io_error_maps_disconnect_kinds_to_unavailable() {
            for kind in [
                io::ErrorKind::BrokenPipe,
                io::ErrorKind::ConnectionReset,
                io::ErrorKind::ConnectionAborted,
                io::ErrorKind::NotConnected,
            ] {
                let err = map_io_error(io::Error::from(kind));
                assert_eq!(err.code(), IoErrorCode::Unavailable, "kind={kind:?}");
            }
        }

        /// TASK-13.2.1: 上記以外は `Internal` に写像される。
        #[test]
        fn task13_2_1_map_io_error_maps_other_kinds_to_internal() {
            let err = map_io_error(io::Error::from(io::ErrorKind::PermissionDenied));
            assert_eq!(err.code(), IoErrorCode::Internal);
        }

        /// REPAIR-5: 期限をすでに過ぎていれば `remaining_or_timeout` は
        /// 即座に `Timeout` を返す。
        #[test]
        fn repair5_remaining_or_timeout_returns_timeout_when_deadline_passed() {
            let deadline = Instant::now() - Duration::from_millis(1);
            let err = remaining_or_timeout(deadline).expect_err("past deadline must time out");
            assert_eq!(err.code(), IoErrorCode::Timeout);
        }

        /// REPAIR-5: 期限に余裕があれば正の残り時間を返す。
        #[test]
        fn repair5_remaining_or_timeout_returns_positive_duration_before_deadline() {
            let deadline = Instant::now() + Duration::from_secs(5);
            let remaining = remaining_or_timeout(deadline).expect("future deadline must succeed");
            assert!(remaining > Duration::ZERO);
            assert!(remaining <= Duration::from_secs(5));
        }

        /// PLUG-12・security.md（項目 3・10 の回帰テスト）: uid が一致すれば
        /// `check_socket_owner` は受理する。他ユーザーを実機で用意できないため、
        /// uid の比較ロジックを具体値で確かめる純粋関数のテストに留める
        /// （`server.rs` モジュール doc「範囲外」節）。
        #[test]
        fn plug12_check_socket_owner_accepts_matching_uid() {
            check_socket_owner(1000, 1000).expect("matching uid must be accepted");
        }

        /// PLUG-12・security.md（項目 3・10 の回帰テスト）: uid が不一致なら
        /// `InvalidArgument` で拒否し、両方の uid を message に含める
        /// （デバッグ容易性。秘密情報ではないため security.md の情報漏えい観点には
        /// 抵触しない）。
        #[test]
        fn plug12_check_socket_owner_rejects_mismatched_uid() {
            let err = check_socket_owner(1000, 0)
                .expect_err("a socket owned by a different uid than the parent must be rejected");
            assert_eq!(err.code(), IoErrorCode::InvalidArgument);
            assert!(err.message().contains("1000"));
            assert!(err.message().contains('0'));
        }
    }
}

/// UDS 非対応 OS（Windows）向けのスタブ実装（REPAIR-3: 実装済みを装わない）。
///
/// 内部状態を uninhabited な enum で表すことで `bind` 以外のメソッドは
/// コンパイル時に到達不能になる。Windows のトランスポート（`windows-sys` を
/// 使った AF_UNIX、または named pipe）は依存承認が必要な別タスクとする。
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
mod imp {
    use std::path::Path;

    use crate::error::{IoError, IoErrorCode};
    use crate::protocol::Frame;
    use crate::transport::IoTimeout;

    #[derive(Debug)]
    pub(super) enum ServerInner {}

    impl ServerInner {
        pub(super) fn bind(_path: &Path) -> Result<Self, IoError> {
            Err(IoError::new(
                IoErrorCode::Unimplemented,
                "unix domain socket transport is not supported on this platform",
            ))
        }

        pub(super) fn path(&self) -> &Path {
            match *self {}
        }

        pub(super) fn accept(&self, _timeout: IoTimeout) -> Result<ConnectionInner, IoError> {
            match *self {}
        }
    }

    #[derive(Debug)]
    pub(super) enum ConnectionInner {}

    impl ConnectionInner {
        pub(super) fn send_frame(
            &mut self,
            _frame: &Frame,
            _timeout: IoTimeout,
        ) -> Result<(), IoError> {
            match *self {}
        }

        pub(super) fn recv_frame(&mut self, _timeout: IoTimeout) -> Result<Frame, IoError> {
            match *self {}
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// TASK-13.2.1: UDS 非対応 OS では `bind` が `Unimplemented` を返す。
        #[test]
        fn task13_2_1_bind_is_unimplemented_on_unsupported_platform() {
            let err = ServerInner::bind(Path::new("/tmp/does-not-matter.sock"))
                .expect_err("unsupported platform must reject bind");
            assert_eq!(err.code(), IoErrorCode::Unimplemented);
        }
    }
}
