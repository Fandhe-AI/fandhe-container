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
//! # 観測（REPAIR-4・REPAIR-5・#820 reviewer/security-auditor 指摘対応）
//!
//! [`UdsServer::bind`]・[`UdsServer::accept`] は [`crate::observe::ServerObserver`]
//! を必須引数として要求する（[`crate::client::PipelineClient::new`] が
//! [`crate::observe::SendObserver`] を必須にするのと同じ理由。観測しない場合は
//! 呼び出し元が [`crate::observe::NoopServerObserver`] を明示的に渡す。暗黙の
//! 既定にはしない）。accept は [`UdsServer`] が構築時に受け取った観測フックへ、
//! 1 接続内の送受信（[`FrameSender::send_frame`]・[`FrameReceiver::recv_frame`]）は
//! [`UdsServer::accept`] が受け取る接続ごとの観測フックへ、それぞれ通知する。
//! 全分岐（成功・各拒否・タイムアウト・poison 済みでの拒否）で必ず 1 回通知し、
//! 通知自体は [`crate::observe::ServerObserver::on_event`] の契約どおり
//! ブロックする I/O を行わない（[`crate::observe::ServerObserver`] のドキュメント
//! 参照）。accept 1 回の呼び出しの中で peer credential 拒否（下記「peer
//! credential の検証」節）が発生した場合は、その都度の拒否イベントに加えて
//! 最終的な成功・失敗イベントも通知され、1 回の [`UdsServer::accept`] 呼び出しで
//! 複数回 `on_event` が呼ばれることがある（H1・#820 security-auditor 指摘対応）。
//!
//! # 受信上限（[`crate::recv_limits::ReceiveLimits`]。F・#820 codex P1 指摘対応）
//!
//! [`UdsServer::bind`] は検証済みの [`crate::recv_limits::ReceiveLimits`] を
//! 構築時の必須引数として受け取り、[`UdsServer::accept`] が返す
//! [`UdsConnection`] へそのまま引き継ぐ。`recv_frame`（`imp::ConnectionInner`）は
//! この受け取った上限を使い、`ReceiveLimits::default()` を暗黙に使うことはない。
//! これにより、呼び出し側が [`crate::batch::BatchConfig::with_max_bytes`] 等で
//! 既定値より小さい上限を設定した場合、その設定が実際の UDS 受信経路（本体
//! バッファの確保前検証）へ確実に反映される。
//!
//! # peer credential の検証（PLUG-12・security.md「UDS は所有者・権限・
//! symlink を検証してから bind し、別 UID からの接続は peer credential 検証で
//! 切断する」。E・#820 codex P0 指摘対応。H1・H3・H4・H6・#820 security-auditor
//! 指摘対応）
//!
//! [`UdsServer::accept`] は、accept した接続の相手側 uid
//! （`crate::sys::peer_uid`。Linux は `SO_PEERCRED`、macOS は `getpeereid(2)`）が
//! 自プロセスの実効 uid（`crate::sys::effective_uid`）と一致することを確かめる
//! （`imp::verify_peer_credential`。Linux / macOS 限定の非公開関数）。
//! 不一致・取得失敗（対応していないアーキテクチャを含む）のいずれも拒否し
//! （fail-closed）、拒否した接続はすぐに閉じる。1 件の不正な接続で受付ループ
//! 自体は止めない。ただし `ConnectionAborted`（相手都合の切断）と peer
//! credential 拒否は件数を分けて数え（H1・#820 security-auditor 指摘対応。
//! SEC-4「分離違反の試行は監査ログに記録する」の対象になる事象を、単なる
//! 相手都合の切断と混同しないため）、それぞれ独立に期限・
//! [`imp::MAX_ACCEPT_ABORT_RETRIES`] の両方で有界に再試行する
//! （`AcceptAttempt` のドキュメンテーションコメント参照）。件数の加算と
//! （peer credential 拒否の場合の）観測通知は、期限切れの判定より必ず先に
//! 行う（H3・#820 security-auditor 指摘対応。期限の直前に起きた拒否も記録に
//! 残すため）。再試行の上限を超えた場合のエラーコードは、実装バグを示す
//! `Internal` ではなく、相手に起因する異常を示す
//! [`IoErrorCode::Unavailable`] を返す（H4・#820 security-auditor 指摘対応）。
//!
//! peer credential 拒否は、正常な接続が最終的に成立した場合でもそれまでの
//! 拒否が記録から失われないよう、拒否 1 件ごとに個別のイベント
//! （[`crate::observe::ServerOutcome::RejectedPeerCredential`]）として
//! [`UdsServer::bind`] で渡した観測フックへ即座に通知する（H1・#820
//! security-auditor 指摘対応。SEC-4）。累積件数
//! （[`crate::observe::ServerEvent::peer_credential_rejections`]）は最終的な
//! Accept の成功・失敗イベントにも載る。取得できた場合の接続元 uid
//! （[`crate::observe::ServerEvent::peer_uid`]。数値のみで秘密情報を含まない）
//! も個々の拒否イベントに載る。通知自体は他の観測イベントと同じくブロックする
//! I/O を行わない契約（モジュール doc「観測」節参照）を守る。拒否時の
//! エラーコードは新設せず、bind 時の所有者照合（`imp::check_socket_owner`）と
//! 同じ [`IoErrorCode::InvalidArgument`] を使う。
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
//! - 同時接続数の上限（TASK-13.2.2・#822）
//! - [`crate::recv_limits::ReceiveLimits::admit`] の滞留件数
//!   （`pending_frames`）は本モジュールでは常に `0` を渡す（この層は単一接続
//!   しか見えず、複数接続を跨いだ実際の準備完了キューを持たないため）。
//!   実際のキューとの配線は [`crate::batch::BatchBuffer`] を導入する
//!   TASK-13.2.2（#822）の責務（`crates/io/src/recv_limits.rs` モジュール
//!   doc 参照）
//! - 送信側と受信側の分割 API（`try_clone` を使った split。TASK-12）
//! - クライアント側の UDS 接続（`connect`）・[`crate::client::PipelineClient`]
//!   との結合（TASK-13.2.2・#822）
//! - vsock（microVM）トランスポート
//! - bind から `0600` への chmod 完了までの短い窓（[`UdsServer::bind`] の
//!   ドキュメンテーションコメント参照）は親ディレクトリの権限で塞ぐ設計とし、
//!   ソケットファイル自体の一時的なモードには依存しない
//! - `path` の直近の親ディレクトリ以外（祖先のパス要素）の symlink 検査は
//!   行わない（`imp::validate_parent_dir`（Linux / macOS 限定の非公開関数）
//!   のドキュメンテーションコメント参照）。祖先ディレクトリが bind 後に
//!   symlink へ差し替えられた場合、[`UdsServer`] の [`Drop`] が呼ぶ
//!   `imp::cleanup_socket_file`（自分が bind したソケットファイルの自動削除）
//!   が意図しないパスを操作しうるが、これも本タスクの範囲外とする
//!   （security P2・#820 レビュー指摘。`cleanup_socket_file` 自体は削除直前に
//!   `symlink_metadata` でソケットのままであることを確かめるため、任意の
//!   ファイルを消す経路にはならない）
//! - macOS の ACL（Access Control List）は `st_mode` のパーミッションビット
//!   検査の対象外であり、`imp::validate_parent_dir` の owner 専用チェックを
//!   ACL で上書きされていても検出できない（security Low・#820 レビュー指摘。
//!   POSIX パーミッションのみを信頼境界として扱う既定方針は他の crate と共通）
//!
//! # SIGPIPE の前提
//!
//! Rust の実行時環境（バイナリ・テストハーネス双方）は SIGPIPE を無視するよう
//! 設定しているため、切断済みの相手への書き込みは（プロセスを終了させずに）
//! `BrokenPipe` エラーとして観測でき、本実装はそれを
//! [`IoErrorCode::Unavailable`] へ変換する。本 library を Rust 以外の実行時
//! から使う場合はこの前提が崩れうるため範囲外とする。

use std::path::Path;
use std::time::{Duration, Instant};

use crate::error::{IoError, IoErrorCode};
use crate::observe::{SendEventError, ServerEvent, ServerObserver, ServerOp, ServerOutcome};
use crate::protocol::{Frame, FrameKind};
use crate::recv_limits::ReceiveLimits;
use crate::transport::{FrameReceiver, FrameSender, IoTimeout};

/// [`imp::ServerInner::accept`] の結果に、受付ループ内で再試行した回数
/// （[`crate::observe::ServerEvent::accept_aborted_retries`]・
/// [`crate::observe::ServerEvent::peer_credential_rejections`] に必要）を
/// 添えて呼び出し元（[`UdsServer::accept`]）へ持ち帰るための非公開型
/// （TASK-13.2.1・#820・reviewer 指摘対応。REPAIR-4）。`imp` モジュールの外へ
/// OS 固有型を漏らさないため、`C` は `imp::ConnectionInner` を指す型引数
/// として使う。
///
/// 再試行には 2 種類あり（E・#820 codex P0 指摘対応で追加）、件数は別々に
/// 数える（H1・#820 security-auditor 指摘対応。SEC-4「分離違反の試行は
/// 監査ログに記録する」の対象になる peer credential 拒否と、単なる相手都合の
/// 切断を混同しないため）: 相手が accept 完了前に切断した場合
/// （`ConnectionAborted`）は [`Self::aborted_retries`]、accept 自体は完了した
/// が peer credential の検証（`imp::verify_peer_credential`）に失敗した場合は
/// [`Self::peer_credential_rejections`] を増分する。どちらも「1 件の不正・
/// 無効な接続で受付ループ全体を止めない」という同じ目的のため、同じ上限
/// （`imp::MAX_ACCEPT_ABORT_RETRIES`）をそれぞれ独立に適用する。
struct AcceptAttempt<C> {
    result: Result<C, IoError>,
    aborted_retries: u32,
    peer_credential_rejections: u32,
}

/// [`imp::ConnectionInner::recv_frame`] の結果に、ヘッダ検証を通過した時点で
/// 確定するフレーム種別（[`crate::observe::ServerEvent::kind`] に必要）を
/// 添えて呼び出し元（[`UdsConnection::recv_frame`]）へ持ち帰るための非公開型
/// （TASK-13.2.1・#820・reviewer 指摘対応。REPAIR-4）。
struct RecvAttempt {
    result: Result<Frame, IoError>,
    kind: Option<FrameKind>,
}

/// UDS の接続受け付け役（TASK-13.2.1・IO-1）。
///
/// `bind` したソケットファイルは [`Drop`] で片付ける。片付けの直前に
/// 「自分が bind したパスがまだソケットファイルのままであること」を
/// `symlink_metadata` で確かめ、別種のファイルに置き換わっていた場合は
/// 削除しない（任意のファイルを消す経路を作らないため。security.md）。
///
/// `O: ServerObserver` は [`Self::bind`] が受け取る必須の観測フックで、
/// [`Self::accept`] のイベント（[`crate::observe::ServerOp::Accept`]）を
/// 通知する（モジュール doc「観測」節参照）。
///
/// `limits`（[`crate::recv_limits::ReceiveLimits`]）は [`Self::bind`] が受け取る
/// 必須引数で、[`Self::accept`] が返す各 [`UdsConnection`] へそのまま引き継がれる
/// （モジュール doc「受信上限」節参照。F・#820 codex P1 指摘対応）。
pub struct UdsServer<O: ServerObserver> {
    inner: imp::ServerInner,
    observer: O,
    limits: ReceiveLimits,
}

impl<O: ServerObserver> core::fmt::Debug for UdsServer<O> {
    /// パス以外の内部状態（socket fd・観測フックの中身等）は出力しない
    /// （[`crate::observe::SendObserver`] のドキュメント「`Debug` は要求しない」
    /// と同じ方針。`O: Debug` を要求しない）。
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("UdsServer")
            .field("path", &self.path())
            .finish()
    }
}

impl<O: ServerObserver> UdsServer<O> {
    /// `path` に UDS を bind する。
    ///
    /// bind 前に親ディレクトリ（symlink でない・ディレクトリである・
    /// owner 以外に read / write / search のいずれも与えない）と `path` 自体
    /// （既存パスは拒否し、自動 unlink はしない）を検証する（security.md の
    /// UDS 観点。fail-closed）。bind 直後には、作成されたソケットファイルの
    /// 所有者（bind したプロセスの実効 uid と一致する）が親ディレクトリの
    /// 所有者と一致することも確かめ（PLUG-12・`imp::check_socket_owner`。
    /// Linux / macOS 限定の非公開関数）、
    /// 不一致ならソケットファイルを片付けてから拒否する。検証後はソケット
    /// ファイルを `0600` にし、listener を非ブロッキングにする。
    ///
    /// `limits` は [`Self::accept`] が返す各接続の `recv_frame` が使う受信上限で、
    /// 必須引数である（モジュール doc「受信上限」節参照。F・#820 codex P1
    /// 指摘対応。既定の上限で良い場合は呼び出し元が
    /// [`crate::recv_limits::ReceiveLimits::default`] を明示的に渡す）。
    ///
    /// `observer` は [`Self::accept`] が通知する Accept イベントの送り先で、
    /// 必須引数である（観測しない場合は [`crate::observe::NoopServerObserver`]
    /// を明示的に渡す。モジュール doc「観測」節参照）。bind 自体は
    /// [`crate::observe::ServerOp`] に含まれないため観測イベントを発生させず、
    /// 失敗時は `observer` を保持せずそのまま破棄する（bind 失敗はこの層より
    /// 前の入力検証であり、accept・送受信のような繰り返し呼ばれる操作ではない
    /// ため。#820 レビュー指摘）。
    ///
    /// # 既知の残存リスク（bind から chmod までの窓）
    /// `UnixListener::bind` はソケットファイルの作成と listen の開始を同時に
    /// 行うため、上記の検証・`0600` へのチャモードが完了するまでの短い間、
    /// ソケットファイルの実効モードは umask 依存になる。親ディレクトリを
    /// owner 専用（`0700` 以下）にする検証が実質的な防壁であり、この窓の
    /// 間に到達できるのは親ディレクトリを辿れる者（＝ owner 本人）に限られる。
    pub fn bind(path: &Path, limits: ReceiveLimits, observer: O) -> Result<Self, IoError> {
        Ok(Self {
            inner: imp::ServerInner::bind(path)?,
            observer,
            limits,
        })
    }

    /// 接続を 1 件、`timeout` を上限に受け付ける。
    ///
    /// 期限を過ぎても接続が来なければ [`IoErrorCode::Timeout`] を返す
    /// （REPAIR-5: 無期限にブロックしない）。呼び出し側は次の接続を待つために
    /// 再度この関数を呼ぶ（受付ループはこのモジュールの外で組む）。
    ///
    /// `conn_observer` は返す [`UdsConnection`] が送受信イベント
    /// （[`crate::observe::ServerOp::Recv`]・[`crate::observe::ServerOp::Send`]）を
    /// 通知する先で、必須引数である（モジュール doc「観測」節参照）。成功・
    /// 失敗のいずれでも、この呼び出し自体の Accept イベントは
    /// [`Self::bind`] で渡した観測フックへ 1 回通知する（`&mut self` を要求する
    /// のはこの通知のため）。
    pub fn accept<C: ServerObserver>(
        &mut self,
        timeout: IoTimeout,
        conn_observer: C,
    ) -> Result<UdsConnection<C>, IoError> {
        let started = Instant::now();
        // `observer` と `self.inner` は互いに素なフィールドの借用のため、
        // `self.inner.accept(...)` へ渡すクロージャの中で `observer` を
        // 可変借用しても衝突しない（H1・#820 security-auditor 指摘対応。
        // peer credential 拒否の都度、`imp` 層のループから観測フックへ
        // 個別に通知するための経路。`&mut dyn FnMut` はブロックしない・
        // 借用は呼び出しの間だけという `ServerObserver::on_event` の契約を
        // そのまま伝播する）。
        let observer = &mut self.observer;
        let attempt = self.inner.accept(timeout, &mut |event: &ServerEvent<'_>| {
            observer.on_event(event);
        });
        let elapsed = started.elapsed();
        match &attempt.result {
            Ok(_) => self.observer.on_event(&ServerEvent {
                op: ServerOp::Accept,
                kind: None,
                outcome: ServerOutcome::Success,
                latency: elapsed,
                accept_aborted_retries: attempt.aborted_retries,
                peer_credential_rejections: attempt.peer_credential_rejections,
                peer_uid: None,
                error: None,
            }),
            Err(err) => self.observer.on_event(&ServerEvent {
                op: ServerOp::Accept,
                kind: None,
                outcome: ServerOutcome::Failure,
                latency: elapsed,
                accept_aborted_retries: attempt.aborted_retries,
                peer_credential_rejections: attempt.peer_credential_rejections,
                peer_uid: None,
                error: Some(SendEventError {
                    code: err.code(),
                    message: err.message(),
                }),
            }),
        }
        attempt.result.map(|inner| UdsConnection {
            inner,
            poisoned: false,
            observer: conn_observer,
            limits: self.limits,
        })
    }

    /// bind したソケットファイルのパスを返す。
    pub fn path(&self) -> &Path {
        self.inner.path()
    }

    /// [`Self::bind`] で渡した観測フックを参照する
    /// （[`crate::client::PipelineClient::observer`] と同じ用途）。
    pub fn observer(&self) -> &O {
        &self.observer
    }

    /// [`Self::bind`] で渡した観測フックを可変参照で取り出す
    /// （[`crate::observe::JsonLinesServerObserver::drain_lines`] 等、呼び出し元が
    /// 明示的にためた行を取り出す操作に使う）。
    pub fn observer_mut(&mut self) -> &mut O {
        &mut self.observer
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
///
/// `C: ServerObserver` は [`UdsServer::accept`] から受け取る必須の観測フックで、
/// `send_frame` / `recv_frame` のすべての分岐（成功・poison による拒否・
/// その他の失敗）を通知する（モジュール doc「観測」節参照）。
///
/// `limits` は [`UdsServer::bind`] で渡された受信上限をそのまま引き継いだもので、
/// `recv_frame` が本体バッファ確保前の受理判定（`ReceiveLimits::admit`）に使う
/// （モジュール doc「受信上限」節参照。F・#820 codex P1 指摘対応）。
pub struct UdsConnection<C: ServerObserver> {
    inner: imp::ConnectionInner,
    poisoned: bool,
    observer: C,
    limits: ReceiveLimits,
}

impl<C: ServerObserver> core::fmt::Debug for UdsConnection<C> {
    /// socket fd・観測フックの中身等の内部状態は出力せず、poison 状態のみを出す
    /// （`C: Debug` を要求しない。[`UdsServer`] の `Debug` と同じ方針）。
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("UdsConnection")
            .field("poisoned", &self.poisoned)
            .finish()
    }
}

impl<C: ServerObserver> UdsConnection<C> {
    /// `send_frame` / `recv_frame` の結果を見て poison 状態を更新する
    /// （P1-3 の契約を守る箇所をここ 1 か所に集約する）。
    fn poison_on_err<T>(&mut self, result: Result<T, IoError>) -> Result<T, IoError> {
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }

    /// 成功イベントを観測フックへ通知する（`send_frame`・`recv_frame` の成功
    /// 分岐で共有。TASK-13.2.1・#820。REPAIR-4）。
    fn notify_success(&mut self, op: ServerOp, kind: Option<FrameKind>, latency: Duration) {
        self.observer.on_event(&ServerEvent {
            op,
            kind,
            outcome: ServerOutcome::Success,
            latency,
            accept_aborted_retries: 0,
            peer_credential_rejections: 0,
            peer_uid: None,
            error: None,
        });
    }

    /// 失敗イベントを観測フックへ通知する（`send_frame`・`recv_frame` の失敗
    /// 分岐で共有。`outcome` は呼び出し元が [`ServerOutcome::RejectedPoisoned`]
    /// （P1-3 の poison 拒否）と [`ServerOutcome::Failure`]（それ以外）を選ぶ。
    /// TASK-13.2.1・#820。REPAIR-4）。
    fn notify_failure(
        &mut self,
        op: ServerOp,
        kind: Option<FrameKind>,
        outcome: ServerOutcome,
        latency: Duration,
        err: &IoError,
    ) {
        self.observer.on_event(&ServerEvent {
            op,
            kind,
            outcome,
            latency,
            accept_aborted_retries: 0,
            peer_credential_rejections: 0,
            peer_uid: None,
            error: Some(SendEventError {
                code: err.code(),
                message: err.message(),
            }),
        });
    }

    /// [`UdsServer::accept`] で渡した観測フックを参照する。
    pub fn observer(&self) -> &C {
        &self.observer
    }

    /// [`UdsServer::accept`] で渡した観測フックを可変参照で取り出す。
    pub fn observer_mut(&mut self) -> &mut C {
        &mut self.observer
    }
}

/// poison 済み接続への呼び出しに返すエラー（P1-3）。
fn unavailable_after_poison() -> IoError {
    IoError::new(
        IoErrorCode::Unavailable,
        "connection is poisoned by a previous error and must be reconnected",
    )
}

impl<C: ServerObserver> FrameSender for UdsConnection<C> {
    type Frame = Frame;

    fn send_frame(&mut self, frame: &Frame, timeout: IoTimeout) -> Result<(), IoError> {
        if self.poisoned {
            let err = unavailable_after_poison();
            self.notify_failure(
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
            Ok(()) => self.notify_success(ServerOp::Send, Some(frame.kind()), elapsed),
            Err(err) => self.notify_failure(
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

impl<C: ServerObserver> FrameReceiver for UdsConnection<C> {
    type Frame = Frame;

    fn recv_frame(&mut self, timeout: IoTimeout) -> Result<Frame, IoError> {
        if self.poisoned {
            let err = unavailable_after_poison();
            self.notify_failure(
                ServerOp::Recv,
                None,
                ServerOutcome::RejectedPoisoned,
                Duration::ZERO,
                &err,
            );
            return Err(err);
        }
        let started = Instant::now();
        let attempt = self.inner.recv_frame(timeout, self.limits);
        let elapsed = started.elapsed();
        match &attempt.result {
            Ok(frame) => self.notify_success(ServerOp::Recv, Some(frame.kind()), elapsed),
            Err(err) => self.notify_failure(
                ServerOp::Recv,
                attempt.kind,
                ServerOutcome::Failure,
                elapsed,
                err,
            ),
        }
        self.poison_on_err(attempt.result)
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
    use crate::observe::{SendEventError, ServerEvent, ServerOp, ServerOutcome};
    use crate::protocol::{FRAME_HEADER_LEN, Frame, FrameHeader, FrameKind};
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

        /// 接続を 1 件受け付ける。戻り値には `ConnectionAborted` を再試行した
        /// 回数（[`crate::observe::ServerEvent::accept_aborted_retries`] の
        /// 出どころ）と peer credential 拒否により再試行した回数
        /// （[`crate::observe::ServerEvent::peer_credential_rejections`] の
        /// 出どころ。H1・#820 security-auditor 指摘対応）を必ず添える（成功・
        /// タイムアウト・retry 上限超過のいずれでも。TASK-13.2.1・#820・
        /// reviewer 指摘対応。REPAIR-4）。
        ///
        /// `on_event` は peer credential 拒否の都度、個別のイベントを通知する
        /// ための呼び出し先（H1・#820 security-auditor 指摘対応。SEC-4「分離
        /// 違反の試行は監査ログに記録する」）。`crate::observe::ServerObserver::
        /// on_event` と同じ契約（ブロックする I/O をしない・借用は呼び出しの
        /// 間だけ有効）を守ることは呼び出し元（[`super::UdsServer::accept`]）の
        /// 責務であり、本関数はその契約を満たす `on_event` を受け取る前提で
        /// 動く。
        pub(super) fn accept(
            &self,
            timeout: IoTimeout,
            on_event: &mut dyn FnMut(&ServerEvent<'_>),
        ) -> super::AcceptAttempt<ConnectionInner> {
            let deadline = Instant::now() + timeout.as_duration();
            let mut abort_retries = 0u32;
            let mut credential_rejections = 0u32;
            loop {
                match self.listener.accept() {
                    Ok((stream, _addr)) => {
                        // macOS では accept() した stream がリスナーの
                        // O_NONBLOCK を引き継ぐ（Linux では引き継がないが、
                        // 呼んでも無害なので常に呼ぶ）。
                        if let Err(e) = stream.set_nonblocking(false) {
                            return super::AcceptAttempt {
                                result: Err(IoError::new(
                                    IoErrorCode::Internal,
                                    format!(
                                        "failed to clear nonblocking mode on accepted stream: {e}"
                                    ),
                                )),
                                aborted_retries: abort_retries,
                                peer_credential_rejections: credential_rejections,
                            };
                        }

                        // E・#820 codex P0 指摘対応（PLUG-12・security.md）:
                        // 接続元の peer credential を検証し、自プロセスの実効
                        // uid と一致しない（取得自体に失敗した場合を含む）
                        // 接続は fail-closed で拒否する。1 件の不正な接続で
                        // 受付ループ全体を止めないため、`ConnectionAborted` とは
                        // 別のカウンタ・同じ上限（`MAX_ACCEPT_ABORT_RETRIES`）で
                        // 再試行する（H1・#820 security-auditor 指摘対応。
                        // `AcceptAttempt` のドキュメンテーションコメント参照）。
                        if let Err(rejection) = verify_peer_credential(&stream) {
                            drop(stream);
                            // H3・#820 security-auditor 指摘対応: 件数の加算・
                            // 拒否の通知は、期限切れの判定より必ず先に行う
                            // （期限の直前に起きた拒否も記録に残すため）。
                            credential_rejections = credential_rejections.saturating_add(1);
                            on_event(&peer_credential_rejection_event(
                                &rejection,
                                credential_rejections,
                            ));

                            let remaining = deadline.saturating_duration_since(Instant::now());
                            if let Some(err) = accept_retry_deadline_or_limit(
                                remaining,
                                credential_rejections,
                                MAX_ACCEPT_ABORT_RETRIES,
                                "accept exceeded the retry limit after repeatedly rejecting \
                                 connections with mismatched peer credentials",
                            ) {
                                return super::AcceptAttempt {
                                    result: Err(err),
                                    aborted_retries: abort_retries,
                                    peer_credential_rejections: credential_rejections,
                                };
                            }
                            // H6・#820 security-auditor 指摘対応: WouldBlock・
                            // ConnectionAborted の経路と同じ理由で、期限内で
                            // あっても busy-loop せずに一呼吸置いてから再試行
                            // する（相手が不正な接続を高頻度で繰り返す病的な
                            // ケースで CPU を使い切らないため）。
                            std::thread::sleep(remaining.min(ACCEPT_POLL_INTERVAL));
                            continue;
                        }

                        return super::AcceptAttempt {
                            result: Ok(ConnectionInner { stream }),
                            aborted_retries: abort_retries,
                            peer_credential_rejections: credential_rejections,
                        };
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        let remaining = deadline.saturating_duration_since(Instant::now());
                        if remaining.is_zero() {
                            return super::AcceptAttempt {
                                result: Err(IoError::new(
                                    IoErrorCode::Timeout,
                                    "accept timed out waiting for a client connection",
                                )),
                                aborted_retries: abort_retries,
                                peer_credential_rejections: credential_rejections,
                            };
                        }
                        std::thread::sleep(remaining.min(ACCEPT_POLL_INTERVAL));
                    }
                    Err(e) if e.kind() == io::ErrorKind::ConnectionAborted => {
                        // 相手が accept 完了前に切断しただけであり、受付ループ
                        // 自体を終わらせる理由にはならない（REPAIR-5 の趣旨:
                        // 一時的な相手都合で受付が止まらないようにする）。
                        // ただし無期限にリトライしないよう、期限と回数の両方で
                        // 打ち切る。カウンタは saturating で数える（REPAIR-4・
                        // #820 レビュー指摘。u32 の桁あふれで別の事象に見えて
                        // しまわないようにする）。H3・#820 security-auditor
                        // 指摘対応: 件数の加算は期限切れの判定より必ず先に行う。
                        abort_retries = abort_retries.saturating_add(1);
                        let remaining = deadline.saturating_duration_since(Instant::now());
                        if let Some(err) = accept_retry_deadline_or_limit(
                            remaining,
                            abort_retries,
                            MAX_ACCEPT_ABORT_RETRIES,
                            "accept exceeded the retry limit after repeated peer disconnects \
                             before accept completed",
                        ) {
                            return super::AcceptAttempt {
                                result: Err(err),
                                aborted_retries: abort_retries,
                                peer_credential_rejections: credential_rejections,
                            };
                        }
                        // WouldBlock と同じ理由で、期限内であっても busy-loop
                        // せずに一呼吸置いてから再試行する（B4・#820 レビュー
                        // 指摘。相手が接続の確立と切断を高頻度で繰り返す病的な
                        // ケースで CPU を使い切らないため）。
                        std::thread::sleep(remaining.min(ACCEPT_POLL_INTERVAL));
                    }
                    Err(e) => {
                        return super::AcceptAttempt {
                            result: Err(IoError::new(
                                IoErrorCode::Internal,
                                format!("accept failed: {e}"),
                            )),
                            aborted_retries: abort_retries,
                            peer_credential_rejections: credential_rejections,
                        };
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
        check_socket_owner(crate::sys::effective_uid(), parent_uid)?;

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

    /// bind したプロセスの実効 uid（`effective_uid`）が親ディレクトリの所有者
    /// （`parent_uid`）と一致することを確かめる（PLUG-12・security.md「UDS は
    /// 所有者・権限・symlink を検証してから bind」）。
    ///
    /// 第 1 ラウンド（#820）時点では std だけでは実効 uid を直接取得できず
    /// （`libc`/`nix` の依存承認が必要）、bind 直後のソケットファイルの所有者
    /// （自分が作成したので実効 uid と一致する）を代理として使っていた。
    /// `crate::sys::effective_uid`（E・#820 codex P0 指摘対応で追加。`geteuid(2)`
    /// を FFI で直接呼ぶ `sys` モジュール）を導入したことで、代理を使わず
    /// 実際の実効 uid を直接比較できるようになった。uid の比較自体は純粋関数に
    /// 切り出し、実機で別ユーザーを用意できない単体テストからも具体的な uid の
    /// 組で検証できるようにする（#820 レビュー指摘）。
    fn check_socket_owner(effective_uid: u32, parent_uid: u32) -> Result<(), IoError> {
        if effective_uid != parent_uid {
            return Err(IoError::new(
                IoErrorCode::InvalidArgument,
                format!(
                    "socket owner (effective uid {effective_uid}) does not match the parent \
                     directory owner (uid {parent_uid})"
                ),
            ));
        }
        Ok(())
    }

    /// [`verify_peer_credential`] の拒否理由（H1・#820 security-auditor 指摘
    /// 対応）。取得できた場合の接続元 uid（秘密情報を含まない数値）と、拒否の
    /// 詳細（エラーコード・メッセージ）を両方保持し、呼び出し元
    /// （[`ServerInner::accept`]）が観測イベント
    /// （[`crate::observe::ServerOutcome::RejectedPeerCredential`]）へ個別に
    /// 載せられるようにする。
    struct PeerCredentialRejection {
        /// `crate::sys::peer_uid` の取得自体は成功したが
        /// `crate::sys::effective_uid` と不一致だった場合の接続元 uid。取得自体
        /// に失敗した場合（対応していないアーキテクチャを含む）は `None`。
        peer_uid: Option<u32>,
        /// 拒否の詳細（エラーコード・メッセージ）。
        error: IoError,
    }

    /// 接続元（`stream`）の peer credential を検証する（E・#820 codex P0
    /// 指摘対応。PLUG-12・security.md「別 UID からの接続は peer credential
    /// 検証で切断する」）。
    ///
    /// `crate::sys::peer_uid`（Linux は `SO_PEERCRED`、macOS は
    /// `getpeereid(2)`）で接続元の実 uid を取得し、`crate::sys::effective_uid`
    /// （bind したプロセス自身の実効 uid）と一致するかを
    /// [`peer_credential_matches`]（純粋関数。単体テスト対象）で判定する。
    /// `peer_uid` の取得自体に失敗した場合（対応していないアーキテクチャを
    /// 含む）も、判定不能を「別 UID からの接続」と同じ扱いにして拒否する
    /// （fail-closed）。拒否時のエラーコードは [`check_socket_owner`]（bind 時の
    /// 所有者照合）と同じ [`IoErrorCode::InvalidArgument`] を使い、新しいコードは
    /// 追加しない（#820 修正計画 E）。
    fn verify_peer_credential(stream: &UnixStream) -> Result<(), PeerCredentialRejection> {
        let peer_uid = match crate::sys::peer_uid(stream) {
            Ok(uid) => uid,
            Err(error) => {
                return Err(PeerCredentialRejection {
                    peer_uid: None,
                    error,
                });
            }
        };
        let expected_uid = crate::sys::effective_uid();
        if !peer_credential_matches(peer_uid, expected_uid) {
            return Err(PeerCredentialRejection {
                peer_uid: Some(peer_uid),
                error: IoError::new(
                    IoErrorCode::InvalidArgument,
                    format!(
                        "connecting peer uid ({peer_uid}) does not match the server's \
                         effective uid ({expected_uid})"
                    ),
                ),
            });
        }
        Ok(())
    }

    /// uid の一致判定のみを担う純粋関数（[`check_socket_owner`] と同じ方針。
    /// 実機で別ユーザーを用意できない単体テストから具体値で検証できるように
    /// する。E・#820）。
    fn peer_credential_matches(peer_uid: u32, expected_uid: u32) -> bool {
        peer_uid == expected_uid
    }

    /// [`PeerCredentialRejection`] から観測イベントを組み立てる（H1・#820
    /// security-auditor 指摘対応。SEC-4）。純粋関数として切り出し、別 uid の
    /// 接続を実機で作れなくても具体値でテストできるようにする
    /// （[`peer_credential_matches`] と同じ方針）。`peer_credential_rejections`
    /// は呼び出し元（[`ServerInner::accept`]）が管理する累積件数
    /// （[`crate::observe::ServerEvent::peer_credential_rejections`]）をそのまま
    /// 渡す。
    fn peer_credential_rejection_event(
        rejection: &PeerCredentialRejection,
        peer_credential_rejections: u32,
    ) -> ServerEvent<'_> {
        ServerEvent {
            op: ServerOp::Accept,
            kind: None,
            outcome: ServerOutcome::RejectedPeerCredential,
            // 個々の拒否は accept() の呼び出し中に即座に検出・通知され、
            // 別途トランスポートを介した待ち時間を持たないため `ZERO`
            // （`notify_success`/`notify_failure` の早期拒否分岐と同じ扱い）。
            latency: Duration::ZERO,
            accept_aborted_retries: 0,
            peer_credential_rejections,
            peer_uid: rejection.peer_uid,
            error: Some(SendEventError {
                code: rejection.error.code(),
                message: rejection.error.message(),
            }),
        }
    }

    /// 受付ループの再試行判定（H3・H4・#820 security-auditor 指摘対応）。
    ///
    /// `remaining` が `Duration::ZERO` なら [`IoErrorCode::Timeout`]、
    /// `retries` が `max_retries` を超えていれば [`IoErrorCode::Unavailable`]
    /// （相手に起因する異常であり、実装バグを示す `Internal` ではない。H4）、
    /// どちらでもなければ `None`（再試行を続ける）を返す純粋関数。
    ///
    /// 呼び出し元（[`ServerInner::accept`]）は、この判定の**前に**必ず件数の
    /// 加算・（peer credential 拒否の場合の）拒否の通知を済ませておく（H3。
    /// 期限の直前に起きた拒否も件数・記録に残すため）。
    fn accept_retry_deadline_or_limit(
        remaining: Duration,
        retries: u32,
        max_retries: u32,
        exceeded_message: &str,
    ) -> Option<IoError> {
        if remaining.is_zero() {
            return Some(IoError::new(
                IoErrorCode::Timeout,
                "accept timed out waiting for a client connection",
            ));
        }
        if retries > max_retries {
            return Some(IoError::new(
                IoErrorCode::Unavailable,
                exceeded_message.to_string(),
            ));
        }
        None
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
        /// 2: `FrameHeader::from_bytes` で検証→3: サーバーが受信してはならない
        /// 応答系種別（`Ack`・`FlushAck`）を確保前に拒否→4: `ReceiveLimits::admit`
        /// で確保前の受理判定→5: 検証済みの `body_len` を上限に本体を読む→
        /// 6: `Frame::decode_body` に渡す）どおりに実装する。
        ///
        /// # 応答フレームの拒否（IO-1・REPAIR-2・#820 レビュー指摘）
        /// UDS サーバー側はクライアントからの `Write` / `Flush` を受け取り
        /// `Ack` / `FlushAck` を返す側であり、クライアントから `Ack` /
        /// `FlushAck` が届くことはプロトコル違反（`Frame` 自体は妥当だが
        /// 文脈上不正）である。ヘッダの `header_crc`・種別自体の検証
        /// （`FrameHeader::from_bytes`）が通った直後・本体バッファを確保する
        /// 前に拒否し、`IoErrorCode::InvalidArgument` を返す。他の拒否経路
        /// （壊れたヘッダ・確保前の長さ超過）と同じく [`FrameSender::send_frame`]
        /// / [`FrameReceiver::recv_frame`]（[`super::UdsConnection`]）の
        /// poison 契約に従い、このエラーも呼び出し元で `Unavailable` への
        /// 固定化に使われる（P1-3）。
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
        ///
        /// # 戻り値にフレーム種別を添える理由（観測。TASK-13.2.1・#820）
        /// ヘッダ検証（`FrameHeader::from_bytes`）を通過した時点でフレーム種別は
        /// 確定するため、その後の拒否（応答系種別の拒否・`admit` の拒否・本体
        /// 読み込み失敗）でも種別を呼び出し元（[`super::UdsConnection::recv_frame`]）
        /// へ持ち帰り、[`crate::observe::ServerEvent::kind`] に載せられるように
        /// する。ヘッダ自体の読み込み・検証に失敗した場合は種別が確定しないため
        /// `None` のままにする。
        ///
        /// # `limits` の出どころ（F・#820 codex P1 指摘対応）
        /// `limits` は [`super::UdsServer::bind`] が受け取った検証済みの
        /// [`ReceiveLimits`] を [`super::UdsServer::accept`]・
        /// [`super::UdsConnection`] 経由でそのまま引き継いだもの。本関数は
        /// `ReceiveLimits::default()` を暗黙に使わない（呼び出し側が設定した
        /// 上限が、本体バッファ確保前の受理判定に確実に反映される）。
        pub(super) fn recv_frame(
            &mut self,
            timeout: IoTimeout,
            limits: ReceiveLimits,
        ) -> super::RecvAttempt {
            let deadline = Instant::now() + timeout.as_duration();

            let mut header_bytes = [0u8; FRAME_HEADER_LEN];
            if let Err(e) = read_exact_until(
                &mut self.stream,
                &mut header_bytes,
                deadline,
                "frame header",
            ) {
                return super::RecvAttempt {
                    result: Err(e),
                    kind: None,
                };
            }

            let header = match FrameHeader::from_bytes(header_bytes) {
                Ok(header) => header,
                Err(e) => {
                    return super::RecvAttempt {
                        result: Err(e),
                        kind: None,
                    };
                }
            };
            let kind = header.kind();

            if let Err(e) = reject_client_originated_response_frame(kind) {
                return super::RecvAttempt {
                    result: Err(e),
                    kind: Some(kind),
                };
            }
            let admitted = match limits.admit(header, 0) {
                Ok(admitted) => admitted,
                Err(e) => {
                    return super::RecvAttempt {
                        result: Err(e),
                        kind: Some(kind),
                    };
                }
            };

            let body = match read_body_until(&mut self.stream, admitted.body_len(), deadline) {
                Ok(body) => body,
                Err(e) => {
                    return super::RecvAttempt {
                        result: Err(e),
                        kind: Some(kind),
                    };
                }
            };

            super::RecvAttempt {
                result: admitted.decode_body(&body),
                kind: Some(kind),
            }
        }
    }

    /// サーバーが受信してはならない応答系種別（`Ack`・`FlushAck`）を拒否する
    /// （IO-1・REPAIR-2・#820 レビュー指摘）。
    ///
    /// UDS サーバー側はクライアントからの `Write` / `Flush` のみを受け取る
    /// 想定であり（`Ack` / `FlushAck` はサーバーからクライアントへ返す側）、
    /// クライアントからこれらが届くのはプロトコル違反として扱う
    /// （`FrameKind` の全バリアントを列挙する `match` にし、将来種別が
    /// 追加された場合はここがコンパイルエラーになって判断漏れを防ぐ。
    /// fail-closed）。`crates/io/src/recv_limits.rs` モジュール doc の
    /// 「スコープ外」節が「サーバー側で Ack / FlushAck を受信した場合の拒否は
    /// TASK-13.2.1（#820）が担う」としている箇所の実体がこの関数である。
    fn reject_client_originated_response_frame(kind: FrameKind) -> Result<(), IoError> {
        match kind {
            FrameKind::Write | FrameKind::Flush => Ok(()),
            FrameKind::Ack | FrameKind::FlushAck => Err(IoError::new(
                IoErrorCode::InvalidArgument,
                format!("server does not accept client-originated response frames: {kind:?}"),
            )),
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
    /// 全体の期限の再計算へループを戻す（REPAIR-5・#820 レビュー指摘）。テスト
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

    /// `set_read_timeout` / `set_write_timeout` の失敗を `IoError` へ変換する
    /// （D・#820・PR #1113 の macOS CI 失敗の修正）。
    ///
    /// # macOS での `EINVAL`（`InvalidInput`）
    /// macOS の `setsockopt(2)`（`SO_RCVTIMEO` / `SO_SNDTIMEO` の設定に使う）は、
    /// マニュアルの `[EINVAL]` 項に「ソケットが接続済みでなければならない
    /// オプションを、接続されていないソケットに指定した」場合に返ると明記されて
    /// おり、相手がすでに切断した（あるいは accept 前に切断された）ソケットに対して
    /// タイムアウトを設定しようとすると発生しうる。この実装は `read_exact_until`・
    /// `read_body_until`・`write_all_until` のループの毎回、`remaining_or_timeout`
    /// で残り時間を計算し直した直後に `set_read_timeout` / `set_write_timeout` を
    /// 呼び直す（B4・#820 レビュー指摘対応）ため、相手が接続直後に切断した場合
    /// （`io1_uds_recv_reports_unavailable_on_peer_close` が再現するケース）に、
    /// 最初のループでこの `EINVAL` を踏みうる。Linux では同じ状況でも
    /// `setsockopt` 自体は成功し、直後の `read`/`write` が `map_io_error` の
    /// 切断系 `ErrorKind` を返す（実装差）。
    ///
    /// `remaining_or_timeout` は `Duration::ZERO` を `set_*_timeout` へ渡さない
    /// （呼び出し前に自身が `Timeout` を返して打ち切るため）ため、この経路の
    /// `InvalidInput` が「ゼロ Duration を渡した」という別要因で起きることはなく、
    /// 「相手の接続がすでに閉じている」ことを示すと判断して良い。したがって
    /// `map_io_error` とは別にここで `Unavailable` へ変換し、
    /// 切断済みの相手への操作を `Internal`（本来は実装のバグを示すコード）で
    /// 誤って報告しないようにする。それ以外の失敗（`EBADF` 等）は引き続き
    /// `Internal` として扱う。
    fn map_set_timeout_error(e: io::Error) -> IoError {
        if e.kind() == io::ErrorKind::InvalidInput {
            IoError::new(
                IoErrorCode::Unavailable,
                format!("peer connection is unavailable: failed to set io timeout: {e}"),
            )
        } else {
            IoError::new(
                IoErrorCode::Internal,
                format!("failed to set io timeout: {e}"),
            )
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
            stream
                .set_read_timeout(Some(remaining))
                .map_err(map_set_timeout_error)?;
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
    ///
    /// # `AdmittedHeader::allocate_body` を経由しない理由（B1・#820 レビュー
    /// 指摘。security P2）
    /// `crate::recv_limits::AdmittedHeader::allocate_body` は一括確保する経路
    /// （`crate::protocol::Frame::decode_body` 等が本体をまるごと読める場合
    /// 向け）であり、本関数は相手が遅い・悪意ある場合でも接続 1 本あたりの
    /// 瞬間的なメモリ使用量を抑えるため、あえて `body_len` 分を分割して読む。
    /// どちらの経路でも「確保量の上限は `admit` を通過した
    /// `AdmittedHeader`（ここでは `body_len`）からしか得ない」という契約は
    /// 変わらない（`crates/io/src/recv_limits.rs` モジュール doc「埋める穴」
    /// 節・`AdmittedHeader::allocate_body` のドキュメンテーションコメント
    /// 参照）。
    fn read_body_until(
        stream: &mut UnixStream,
        body_len: usize,
        deadline: Instant,
    ) -> Result<Vec<u8>, IoError> {
        let mut body = Vec::with_capacity(body_len.min(BODY_READ_CHUNK));
        let mut chunk = [0u8; BODY_READ_CHUNK];
        while body.len() < body_len {
            let remaining = remaining_or_timeout(deadline)?;
            stream
                .set_read_timeout(Some(remaining))
                .map_err(map_set_timeout_error)?;
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
            stream
                .set_write_timeout(Some(remaining))
                .map_err(map_set_timeout_error)?;
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

        /// D・#820（PR #1113 の macOS CI 失敗の修正）: `set_read_timeout` /
        /// `set_write_timeout` の `InvalidInput`（macOS の `EINVAL`。相手が
        /// すでに切断済みのソケットへタイムアウトを設定しようとした場合）は
        /// `Internal` ではなく `Unavailable` に写像される
        /// （`map_set_timeout_error` のドキュメンテーションコメント参照）。
        #[test]
        fn d_820_map_set_timeout_error_maps_invalid_input_to_unavailable() {
            let err = map_set_timeout_error(io::Error::from(io::ErrorKind::InvalidInput));
            assert_eq!(err.code(), IoErrorCode::Unavailable);
        }

        /// D・#820: `InvalidInput` 以外のタイムアウト設定失敗（例: 無効な fd を
        /// 示す `EBADF` 相当）は引き続き `Internal` に写像される
        /// （実装のバグを示す経路と、相手の切断を示す経路を区別する）。
        #[test]
        fn d_820_map_set_timeout_error_maps_other_kinds_to_internal() {
            let err = map_set_timeout_error(io::Error::from(io::ErrorKind::PermissionDenied));
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

        /// PLUG-12・security.md（#820 レビュー指摘の回帰テスト）: uid が一致すれば
        /// `check_socket_owner` は受理する。他ユーザーを実機で用意できないため、
        /// uid の比較ロジックを具体値で確かめる純粋関数のテストに留める
        /// （`server.rs` モジュール doc「範囲外」節）。
        #[test]
        fn plug12_check_socket_owner_accepts_matching_uid() {
            check_socket_owner(1000, 1000).expect("matching uid must be accepted");
        }

        /// PLUG-12・security.md（#820 レビュー指摘の回帰テスト）: uid が不一致なら
        /// `InvalidArgument` で拒否し、両方の uid を message に含める
        /// （デバッグ容易性。秘密情報ではないため security.md の情報漏えい観点には
        /// 抵触しない）。
        #[test]
        fn plug12_check_socket_owner_rejects_mismatched_uid() {
            let err = check_socket_owner(1000, 0)
                .expect_err("a socket owned by a different uid than the parent must be rejected");
            assert_eq!(err.code(), IoErrorCode::InvalidArgument);
            assert!(err.message().contains("(effective uid 1000)"));
            assert!(err.message().contains("(uid 0)"));
        }

        /// E・#820（PLUG-12・security.md）: uid が一致すれば
        /// `peer_credential_matches` は `true` を返す。別 uid の接続は root が
        /// ないと実機で用意できないため、uid の一致判定ロジックを具体値で
        /// 確かめる純粋関数のテストに留める（`server.rs` モジュール doc「peer
        /// credential の検証」節）。
        #[test]
        fn e_820_peer_credential_matches_accepts_matching_uid() {
            assert!(peer_credential_matches(1000, 1000));
        }

        /// E・#820（PLUG-12・security.md）: uid が不一致なら
        /// `peer_credential_matches` は `false` を返す。
        #[test]
        fn e_820_peer_credential_matches_rejects_mismatched_uid() {
            assert!(!peer_credential_matches(1000, 0));
        }

        /// H1・H8・#820（security-auditor 指摘対応。SEC-4）: 接続元 uid が
        /// 取得できた（が不一致だった）拒否では、`peer_credential_rejection_event`
        /// が組み立てるイベントに `peer_uid` を数値のまま載せる。別 uid の
        /// 接続は実機で作れないため、イベント組み立て部分を純粋関数として
        /// テストする。
        #[test]
        fn h1_peer_credential_rejection_event_includes_peer_uid_when_available() {
            let rejection = PeerCredentialRejection {
                peer_uid: Some(1000),
                error: IoError::new(
                    IoErrorCode::InvalidArgument,
                    "connecting peer uid (1000) does not match the server's effective uid (0)",
                ),
            };

            let event = peer_credential_rejection_event(&rejection, 3);

            assert_eq!(event.op, ServerOp::Accept);
            assert_eq!(event.outcome, ServerOutcome::RejectedPeerCredential);
            assert_eq!(event.peer_uid, Some(1000));
            assert_eq!(event.peer_credential_rejections, 3);
            assert_eq!(event.accept_aborted_retries, 0);
            let error = event.error.expect("rejection must carry error detail");
            assert_eq!(error.code, IoErrorCode::InvalidArgument);
            assert!(error.message.contains("1000"));
        }

        /// H1・H8・#820: 接続元 uid の取得自体に失敗した拒否では `peer_uid` が
        /// `None` になる。
        #[test]
        fn h1_peer_credential_rejection_event_omits_peer_uid_when_unavailable() {
            let rejection = PeerCredentialRejection {
                peer_uid: None,
                error: IoError::new(IoErrorCode::Internal, "getsockopt(SO_PEERCRED) failed"),
            };

            let event = peer_credential_rejection_event(&rejection, 1);

            assert_eq!(event.peer_uid, None);
        }

        /// H3・H4・H8・#820（security-auditor 指摘対応）: 残り時間がゼロなら
        /// `Timeout`、上限を超えていれば実装バグ用の `Internal` ではなく
        /// 相手に起因する異常を示す `Unavailable`、どちらでもなければ再試行
        /// （`None`）を返す。
        #[test]
        fn h3_h4_accept_retry_deadline_or_limit_returns_timeout_when_deadline_passed() {
            let err = accept_retry_deadline_or_limit(
                Duration::ZERO,
                0,
                MAX_ACCEPT_ABORT_RETRIES,
                "exceeded",
            )
            .expect("a zero remaining duration must produce an error");
            assert_eq!(err.code(), IoErrorCode::Timeout);
        }

        #[test]
        fn h3_h4_accept_retry_deadline_or_limit_returns_unavailable_when_retries_exceeded() {
            let err = accept_retry_deadline_or_limit(
                Duration::from_secs(1),
                MAX_ACCEPT_ABORT_RETRIES + 1,
                MAX_ACCEPT_ABORT_RETRIES,
                "exceeded the retry limit",
            )
            .expect("retries beyond the limit must produce an error");
            assert_eq!(err.code(), IoErrorCode::Unavailable);
            assert!(err.message().contains("exceeded the retry limit"));
        }

        #[test]
        fn h3_h4_accept_retry_deadline_or_limit_returns_none_when_retrying_is_allowed() {
            let outcome = accept_retry_deadline_or_limit(
                Duration::from_secs(1),
                MAX_ACCEPT_ABORT_RETRIES,
                MAX_ACCEPT_ABORT_RETRIES,
                "exceeded",
            );
            assert!(outcome.is_none());
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
    use crate::observe::ServerEvent;
    use crate::protocol::Frame;
    use crate::recv_limits::ReceiveLimits;
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

        pub(super) fn accept(
            &self,
            _timeout: IoTimeout,
            _on_event: &mut dyn FnMut(&ServerEvent<'_>),
        ) -> super::AcceptAttempt<ConnectionInner> {
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

        pub(super) fn recv_frame(
            &mut self,
            _timeout: IoTimeout,
            _limits: ReceiveLimits,
        ) -> super::RecvAttempt {
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
