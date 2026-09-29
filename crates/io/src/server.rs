//! UDS（Unix domain socket）のサーバー側トランスポート（TASK-13.2.1・IO-1・#820）。
//!
//! [`crate::transport`] が定めるトランスポート抽象（[`FrameSender`]・
//! [`FrameReceiver`]）の、具象実装の 1 つ目（REPAIR-3: `transport` モジュールは
//! 具象実装を持たないと明記していたが、本タスクで Linux / macOS 向けの UDS
//! サーバー側を追加した）。[`crate::writeback::serve_connection`]
//! （TASK-13.2.2・#822）がこの上にバッチ書き込み・ACK 返却を積んでおり、
//! 本モジュールは「1 本の接続でフレームを送受信できること」までを提供する。
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
//! 全分岐（成功・各拒否・タイムアウト・poison 済みでの拒否）で最終結果を 1 回通知し、
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
//! 切断する」。E・#820 codex P0 指摘対応。H1〜H4・H6・#820 security-auditor
//! 指摘対応）
//!
//! [`UdsServer::accept`] は、accept した接続の相手側の**接続時点の実効 uid
//! （euid）**（`crate::sys::peer_uid`。Linux は `SO_PEERCRED` が返す
//! `struct ucred.uid`、macOS は `getpeereid(2)` が返す euid で、どちらも
//! 「相手プロセスの実 uid」ではなく接続時点の euid を指す。H2・#820
//! security-auditor 指摘対応）が、[`UdsServer::bind`] の時点で 1 回だけ取得して
//! 保存した自プロセスの実効 uid（`crate::sys::effective_uid`。accept のたびに
//! 取り直さない。I2・#820 security-auditor 再監査指摘対応）と一致することを
//! 確かめる（`imp::verify_peer_credential`。Linux / macOS 限定の非公開関数）。
//! 接続元が user namespace の外側から見えている場合、namespace 外の uid は
//! マッピングを持たないため `overflowuid`（Linux の既定値 `65534`）として
//! 観測されることがあり、実効 uid と一致せず拒否されうる（H2・#820
//! security-auditor 指摘対応。想定内の fail-closed 挙動であり、正しい uid
//! マッピングを持つ呼び出し元からの接続を妨げない）。
//!
//! 比較するのは uid のみで、gid・pid・所属する user namespace は見ない。
//! したがって、user namespace の中にいても本プロセス側から見て同じ uid に
//! 写されるプロセス（rootless コンテナ内の root が、本プロセスを実行している
//! ホストの非特権 uid に写されている場合等。SEC-5）は、本プロセスと同じ主体と
//! して受理する（I6・#820 security-auditor 再監査指摘対応）。これは、ソケットの
//! パス（とその親ディレクトリ）をコンテナへマウントしないことを前提にした
//! 設計であり、コンテナ内のプロセスがソケットへ到達できる構成では
//! この照合だけでは分離にならない（到達経路を塞ぐのは呼び出し側・マウント
//! 構成の責務）。
//!
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
//! 拒否の通知が取り消されないよう、拒否 1 件ごとに個別のイベント
//! （[`crate::observe::ServerOutcome::RejectedPeerCredential`]）として
//! [`UdsServer::bind`] で渡した観測フックへ即座に通知する（H1・#820
//! security-auditor 指摘対応。SEC-4）。既定実装の
//! [`crate::observe::JsonLinesServerObserver`] は、このイベントを通常イベントと
//! 別枠の有界な監査枠に積み、あふれた分は捨てずに集約行（件数・最後の接続元
//! uid）として残す（拒否は黙って失われない。#820 codex P0 指摘対応）。
//! 永続的な監査ログへの配線は後続 sub-issue（要起票）で行う。累積件数
//! （[`crate::observe::ServerEvent::peer_credential_rejections`]）は最終的な
//! Accept の成功・失敗イベントにも載る。取得できた場合の接続元 uid
//! （[`crate::observe::ServerEvent::peer_uid`]。数値のみで秘密情報を含まない）
//! も個々の拒否イベントに載る。通知自体は他の観測イベントと同じくブロックする
//! I/O を行わない契約（モジュール doc「観測」節参照）を守る。拒否時の
//! エラーコードは新設せず、bind 時の所有者照合（`imp::check_socket_owner`）と
//! 同じ [`IoErrorCode::InvalidArgument`] を使う。
//!
//! # ソケットファイルの権限と片付け（PLUG-12・security.md。J2・J3・#820 codex
//! P0 / P1 指摘対応）
//!
//! [`UdsServer::bind`] は、bind の後にソケットのパスを再解決する操作
//! （パス経由の chmod 等）を行わない。bind 後にパスや祖先ディレクトリが
//! 差し替えられた場合、パス経由の操作は symlink の参照先など別のファイルに
//! サーバープロセスの権限で作用しうるため（J2）。bind した socket の fd 経由で
//! 権限を変える方法も採らない: Linux では socket fd への `fchmod(2)` は sockfs
//! 側の inode にしか作用せず、ファイルシステム上のソケットファイル（パスの
//! inode）のモードは変わらない（#820 で実測: fd 側の `fstat` は `0600` に
//! 変わるが、パスの `lstat` は umask 由来のモードのまま）。macOS では socket
//! fd への `fchmod(2)` 自体がエラーになる。
//!
//! したがってソケットファイル自体のモードは bind 時の umask に従い（umask
//! `000` なら `0777` のまま）、本モジュールはそれに依存しない。別 uid の到達を
//! 遮断するのは次の 2 段で、ソケットファイルのモードではない:
//!
//! 1. bind 前に検証する親ディレクトリ（symlink でない・ディレクトリである・
//!    `mode & 0o077 == 0`・所有者 == 自プロセスの実効 uid。
//!    `imp::validate_parent_dir`）。パス名での `connect(2)` には親ディレクトリの
//!    search 権限が要るため、owner 以外はソケットファイルのモードに関係なく
//!    到達できない。この検証は bind 時点の 1 回だけで、以後も親ディレクトリを
//!    owner 専用に保つのは所有者（呼び出し側）の責務とする。
//! 2. accept 時の peer credential 検証（下記「peer credential の検証」節）。
//!
//! [`UdsServer`] の [`Drop`]（と bind 失敗時の後始末）がソケットファイルを
//! 削除するのは、bind 直後に `symlink_metadata` で記録した実体（ソケットで
//! あること・所有者 uid・`(dev, ino)`）と、削除直前に `symlink_metadata` で
//! 取り直した実体がすべて一致する場合だけである（J3。`imp::SocketFileIdentity`）。
//! bind 後に元のパスが unlink され、別の listener が同じパスへ bind した場合でも、
//! 古い [`UdsServer`] の drop が新しいソケットを削除して接続不能にすることはない。
//! bind 直後の記録で自分が作ったソケットだと確認できなかった場合（別物に
//! 差し替わっていた等）は、listener を閉じてエラーを返し、パス上のファイルは
//! 削除しない。
//!
//! 検査（`symlink_metadata`）と削除（`remove_file`）の間には競合の窓が残るが、
//! この窓でパス上のファイルを差し替えられるのは親ディレクトリ（owner 専用・
//! 自プロセスの実効 uid が所有）に書き込める主体、すなわち同じ uid か root に
//! 限られ、それらは窓がなくても同じファイルを直接操作できるため、新たな
//! 権限昇格の経路にはならない。
//!
//! # 分割（split。#1118・IO-1・P1-3・REPAIR-5）
//!
//! [`UdsConnection`] は [`SplitTransport`] を実装し、[`UdsSendHalf`]・[`UdsRecvHalf`] へ
//! 分けて別スレッドから並行に使える（契約の全体は [`SplitTransport`] を参照）。
//! 実装上の要点:
//!
//! - fd は `UnixStream::try_clone` で複製する。poison は `SharedPoison`（内部型）で共有する。
//!   各呼び出しは (1) I/O の前に共有 poison を確認して立っていれば I/O せず
//!   `Unavailable`、(2) I/O が `Err` なら poison を立てて `shutdown(Both)`（もう片側で
//!   ブロック中の read / write を起こし、EOF / EPIPE で速やかに `Unavailable` にする）、
//!   (3) I/O 完了後に poison を再確認し、立っていれば結果（受信済みフレームを含む）を
//!   捨てて `Unavailable` を返す（死んだ接続のフレームを上位へ渡さない）。
//! - 観測フックは両半分で 1 つを `Arc<Mutex<_>>` 共有する（1 接続に 1 フック）。ロックは
//!   `on_event` の間だけ取り、I/O をまたいで保持しない。ロック保持中の通知は
//!   有界の保留キューへ積み、保持側が解放時に排出する（欠落させない）。
//! - 送信側の drop は poison されていなければ `shutdown(Write)`（half-close）を呼ぶ。
//!   受信側の drop は何もしない。
//! - **`O_NONBLOCK` 共有の不変条件**: `O_NONBLOCK` は複製した fd と共有される
//!   （open file description のフラグ）。受信側の drain モード（`ReadWait`）が
//!   nonblocking に切り替えるのは、macOS で `set_read_timeout` が `EINVAL` を返した
//!   とき、すなわち相手が送受信とも shutdown 済みと見なせるときだけである。この
//!   状態の送信は `set_write_timeout` の `EINVAL` か write の EPIPE で直ちに
//!   `Unavailable` になり、仮に `WouldBlock` で再試行しても期限（REPAIR-5）で
//!   打ち切られる。`SO_RCVTIMEO` / `SO_SNDTIMEO` は別オプションで互いに干渉しない。
//!   drain を `recv(MSG_DONTWAIT)` に置き換えて fd の状態を変えない方式は `unsafe` を
//!   伴うため本件の範囲外（要起票）。
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
//! # 範囲外（別タスク。要起票）
//!
//! ACK フレームの送出・ディスク書き込み・[`crate::batch::BatchBuffer`] との
//! つなぎ込みは [`crate::writeback::serve_connection`]（TASK-13.2.2・#822）が
//! 実装済み。本モジュールに残る範囲外は次のとおり:
//!
//! - UDS 接続受付ループ（accept → [`crate::writeback::serve_connection`] →
//!   次の accept）・同時接続数の上限
//! - [`crate::recv_limits::ReceiveLimits::admit`] の滞留件数
//!   （`pending_frames`）は本モジュールでは常に `0` を渡す（この層は単一接続
//!   しか見えないため）。[`crate::writeback::serve_connection`] の write-back は
//!   同期的（発火したバッチをその場で書き込み・ACK まで終えてから次を受信する）
//!   で、受信時点の「排出済みだが未書き込み」のキューは常に空になるため、
//!   この `0` は現行の呼び出し方（1 バッチ完結の同期処理）の下で構造上正確
//!   （`crates/io/src/writeback.rs` モジュール doc「受信上限」節参照）
//! - クライアント側の UDS 接続（`connect`）・[`crate::client::PipelineClient`]
//!   との本番結合
//! - vsock（microVM）トランスポート
//! - `path` の直近の親ディレクトリ以外（祖先のパス要素）の symlink 検査は
//!   行わない（`imp::validate_parent_dir`（Linux / macOS 限定の非公開関数）
//!   のドキュメンテーションコメント参照）。祖先ディレクトリが bind 後に
//!   symlink へ差し替えられた場合、[`UdsServer`] の [`Drop`] が呼ぶ
//!   `imp::cleanup_socket_file`（自分が bind したソケットファイルの自動削除）
//!   が別のディレクトリのパスを lstat しうるが、これも本タスクの範囲外とする
//!   （security P2・#820 レビュー指摘。`cleanup_socket_file` は bind 直後に
//!   記録したソケットの実体〔`(dev, ino)`・所有者 uid〕と一致するファイルしか
//!   削除しないため、任意のファイルや別の主体のソケットを消す経路にはならない。
//!   上記「ソケットファイルの権限と片付け」節参照）
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

use std::collections::VecDeque;
use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use crate::error::{IoError, IoErrorCode};
use crate::observe::{SendEventError, ServerEvent, ServerObserver, ServerOp, ServerOutcome};
use crate::protocol::{Frame, FrameKind};
use crate::recv_limits::ReceiveLimits;
use crate::transport::{FrameReceiver, FrameSender, IoTimeout, SharedPoison, SplitTransport};

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
/// 「パス上のファイルが bind 直後に記録した自分のソケットと同じ実体
/// （ソケットであること・所有者 uid・`(dev, ino)`）であること」を
/// `symlink_metadata` で確かめ、一致しなければ削除しない（任意のファイルや、
/// 同じパスへ後から bind された別の listener のソケットを消す経路を作らない
/// ため。security.md・J3・#820 codex P1 指摘対応。モジュール doc「ソケット
/// ファイルの権限と片付け」節参照）。
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
    /// UDS 観点。fail-closed）。同じく bind 前に、自プロセスの実効 uid
    /// （bind で作られるソケットファイルの所有者になる uid）と親ディレクトリの
    /// 所有者を照合し（PLUG-12・`imp::check_socket_owner`。Linux / macOS 限定の
    /// 非公開関数）、不一致ならソケットファイルを作らずに
    /// [`IoErrorCode::InvalidArgument`] で拒否する（I1・#820 security-auditor
    /// 再監査指摘対応）。このとき取得した実効 uid は保存し、[`Self::accept`] の
    /// peer credential 照合の基準にする（モジュール doc「peer credential の
    /// 検証」節参照）。
    ///
    /// bind 後に行うのは、作成したソケットファイルの実体の記録と listener の
    /// 非ブロッキング化のみで、bind 後にソケットのパスを再解決して権限を
    /// 変える操作は行わない（J2・#820 codex P0 指摘対応。下記「ソケット
    /// ファイルのモード」節）。実体の記録（bind 直後の `symlink_metadata` で、
    /// ソケットであること・所有者 uid が上記の実効 uid と一致することを確かめ、
    /// `(dev, ino)` を保存する。J3・#820 codex P1 指摘対応）に失敗した場合は、
    /// 自分が作ったと確認できないためパス上のファイルを削除せず、listener を
    /// 閉じてエラーを返す（`symlink_metadata` 自体の失敗は
    /// [`IoErrorCode::Internal`]、ソケットでない・所有者 uid が異なる場合は
    /// 所有者照合と同じ [`IoErrorCode::InvalidArgument`]）。非ブロッキング化に
    /// 失敗した場合は、記録した実体と一致する場合に限り作成済みのソケット
    /// ファイルを片付けてから（`imp::cleanup_socket_file`）エラーを返す。
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
    /// # ソケットファイルのモード（J2・#820 codex P0 指摘対応）
    /// ソケットファイル自体のモードは bind 時の umask に従い、本関数は変更
    /// しない（umask `000` なら `0777` のまま）。以前は bind 後にパス経由で
    /// `0600` へ chmod していたが、bind 後にパスや祖先ディレクトリを差し替え
    /// られると symlink の参照先など別のファイルのモードを変えうるため廃止した。
    /// socket fd 経由の `fchmod(2)` は、Linux では sockfs 側の inode にしか
    /// 作用せずパスの inode のモードを変えず（#820 で実測）、macOS では
    /// エラーになるため代替にならない。別 uid の到達は、bind 前に検証した
    /// 親ディレクトリ（owner 専用・自プロセスの実効 uid が所有。パス名での
    /// 接続には親ディレクトリの search 権限が要る）と、[`Self::accept`] の
    /// peer credential 検証で遮断する（モジュール doc「ソケットファイルの権限と
    /// 片付け」節参照）。
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
    /// # 期限の判定位置（REPAIR-5・K1・K2・#820 codex P1 指摘対応）
    /// 期限は listen キューから接続を取り出す前（毎回の再試行を含む）と、peer
    /// credential の照合を通過して接続を返す直前の両方で判定する。期限を過ぎて
    /// から取り出しを始めることはなく、取り出し・照合の間に期限を過ぎた接続は
    /// 閉じて（クライアント側は EOF を読む）`Timeout` を返す（成功を返した後の
    /// 接続は呼び出し元の責任になるため、期限内に返せる接続だけを返す）。
    ///
    /// # 返す `Unavailable` の意味（I7・#820 security-auditor 再監査指摘対応）
    /// 本関数が [`IoErrorCode::Unavailable`] を返すのは、1 回の呼び出しの中で
    /// `ConnectionAborted` または peer credential 拒否が再試行上限
    /// （`imp::MAX_ACCEPT_ABORT_RETRIES`）を超えた場合で、不正・無効な接続が
    /// 続いたことを示すだけであり、リスナー（[`UdsServer`]）自体は健全である。
    /// 呼び出し側は同じ [`UdsServer`] で本関数を再度呼んでよい（受付ループを
    /// 継続できる。受付ループ自体の組み方は後続 sub-issue〔要起票〕の扱い）。
    /// これに対し、
    /// [`UdsConnection`] の送受信が返す `Unavailable` は、その接続が poison 済み
    /// （P1-3）で以後使えないことを示し、再接続が必要になる。
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
        self.accept_via(conn_observer, |inner, on_event| {
            inner.accept(timeout, on_event)
        })
    }

    /// [`Self::accept`] の本体（観測フックへの配線と最終イベントの組み立て）。
    ///
    /// `inner_accept` は `imp` 層の 1 回分の受け付けを行う呼び出しで、本番
    /// （非テスト）で呼ぶのは [`Self::accept`] のみであり、そこでは常に
    /// `imp::ServerInner::accept`（peer credential 照合は固定の
    /// `imp::verify_peer_credential`）を渡す。照合を差し替えた
    /// `imp::ServerInner::accept_with` を渡すのは `imp` のテスト（`#[cfg(test)]`）
    /// だけで、拒否 1 件ごとの通知から最終イベントまでの配線を実際のソケットで
    /// 確かめるために使う（I4・#820 security-auditor 再監査指摘対応。SEC-4・
    /// PLUG-12）。本関数は非公開のため、差し替えの経路が crate 外へ漏れることはない。
    fn accept_via<C, F>(
        &mut self,
        conn_observer: C,
        inner_accept: F,
    ) -> Result<UdsConnection<C>, IoError>
    where
        C: ServerObserver,
        F: FnOnce(
            &imp::ServerInner,
            &mut dyn FnMut(&ServerEvent<'_>),
        ) -> AcceptAttempt<imp::ConnectionInner>,
    {
        let started = Instant::now();
        // `observer` と `self.inner` は互いに素なフィールドの借用のため、
        // `inner_accept` へ渡すクロージャの中で `observer` を
        // 可変借用しても衝突しない（H1・#820 security-auditor 指摘対応。
        // peer credential 拒否の都度、`imp` 層のループから観測フックへ
        // 個別に通知するための経路。`&mut dyn FnMut` はブロックしない・
        // 借用は呼び出しの間だけという `ServerObserver::on_event` の契約を
        // そのまま伝播する）。
        let observer = &mut self.observer;
        let attempt = inner_accept(&self.inner, &mut |event: &ServerEvent<'_>| {
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
/// # 期限の判定位置（REPAIR-5・K2・#820）
/// `send_frame` / `recv_frame` は 1 回ごとの read / write を始める前に必ず期限を
/// 判定し（期限後に I/O を始めない）、各 read / write の待ちも残り時間を上限に
/// する。期限内に始めた最後の read / write が期限をわずかに（ソケットの
/// タイムアウトの粒度の範囲で）超えて完了した場合は成功として返す。完了した
/// バイト列はすでにカーネルへ渡した / ストリームから取り出した後であり、
/// `Timeout` にすると送信では相手が完全なフレームを受け取っているのに失敗扱い
/// （poison・再接続・再送による重複）になり、受信ではそのフレームを失うため
/// である（何も授受していない accept の成功経路とは扱いが異なる。
/// [`UdsServer::accept`] の「期限の判定位置」節参照）。
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
        emit_success(&mut self.observer, op, kind, latency);
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
        emit_failure(&mut self.observer, op, kind, outcome, latency, err);
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

/// 成功イベントを組み立てて `observer` へ通知する（[`UdsConnection`] と分割後の
/// 両半分が共有。REPAIR-4）。
fn emit_success<C: ServerObserver>(
    observer: &mut C,
    op: ServerOp,
    kind: Option<FrameKind>,
    latency: Duration,
) {
    observer.on_event(&ServerEvent {
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

/// 失敗イベントを組み立てて `observer` へ通知する（[`emit_success`] の失敗版）。
fn emit_failure<C: ServerObserver>(
    observer: &mut C,
    op: ServerOp,
    kind: Option<FrameKind>,
    outcome: ServerOutcome,
    latency: Duration,
    err: &IoError,
) {
    observer.on_event(&ServerEvent {
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

/// 観測フックへ後から適用する保留イベント（所有データのみを持つ）。
type PendingEvent<C> = Box<dyn FnOnce(&mut C) + Send>;

/// 保留イベントの上限件数（無制限確保の防止。security.md）。超えた分は破棄する。
const MAX_PENDING_EVENTS: usize = 1024;

struct SharedObserverInner<C: ServerObserver> {
    hook: Mutex<C>,
    pending: Mutex<VecDeque<PendingEvent<C>>>,
}

/// 分割後の両半分が共有する観測フック（#1118。1 接続に 1 フックの意味論を保つ）。
///
/// ロックは `on_event` / [`Self::with`] の間だけ取り、I/O をまたいで保持しない
/// （両半分の間でデッドロックしない）。他方のスレッドが panic してロックが poison
/// されても `into_inner` で続行し、ここから panic を伝播させない。
///
/// I/O 経路（`send_frame` / `recv_frame`）からの通知は [`Self::notify`] を使う。
/// イベントをいったん保留キューへ積み、フックのロックが取れれば待たずに順序どおり
/// 適用する。他方（`with_observer` のクロージャや別スレッドの通知）がロックを保持
/// 中ならブロックせずに戻り（期限を超えない。REPAIR-5）、ロック保持側が解放後に
/// キューを排出する（REPAIR-4: 並行終了でもイベントを欠落させない）。
struct SharedObserver<C: ServerObserver>(Arc<SharedObserverInner<C>>);

impl<C: ServerObserver> Clone for SharedObserver<C> {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl<C: ServerObserver> SharedObserver<C> {
    fn new(hook: C) -> Self {
        Self(Arc::new(SharedObserverInner {
            hook: Mutex::new(hook),
            pending: Mutex::new(VecDeque::new()),
        }))
    }

    fn lock_pending(&self) -> std::sync::MutexGuard<'_, VecDeque<PendingEvent<C>>> {
        self.0
            .pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// 保留キューを空になるまでフックへ適用する（フックのロック保持中に呼ぶ）。
    /// キューのロックは `on_event` の実行中は保持しない。
    fn drain_locked(&self, hook: &mut C) {
        loop {
            let next = self.lock_pending().pop_front();
            match next {
                Some(event) => event(hook),
                None => break,
            }
        }
    }

    /// ロックを取って `f` を適用し、その間に積まれた保留イベントも排出する。
    fn with<R>(&self, f: impl FnOnce(&mut C) -> R) -> R {
        let result = {
            let mut guard = self.0.hook.lock().unwrap_or_else(PoisonError::into_inner);
            let r = f(&mut guard);
            self.drain_locked(&mut guard);
            r
        };
        // 解放直前に他方が積んで try_lock に失敗した分を取りこぼさない。
        self.flush();
        result
    }

    /// ロックが取れる間、保留イベントを排出する。取れなければ保持側に任せる。
    fn flush(&self) {
        loop {
            {
                let mut guard = match self.0.hook.try_lock() {
                    Ok(g) => g,
                    Err(std::sync::TryLockError::Poisoned(p)) => p.into_inner(),
                    Err(std::sync::TryLockError::WouldBlock) => return,
                };
                self.drain_locked(&mut guard);
            }
            if self.lock_pending().is_empty() {
                return;
            }
        }
    }

    /// イベントを保留キューへ積み、待たずに排出を試みる（キュー満杯なら破棄）。
    fn notify(&self, event: PendingEvent<C>) {
        {
            let mut q = self.lock_pending();
            if q.len() >= MAX_PENDING_EVENTS {
                return;
            }
            q.push_back(event);
        }
        self.flush();
    }
}

/// 成功イベントを保留キュー経由で通知する。
fn notify_success<C: ServerObserver>(
    observer: &SharedObserver<C>,
    op: ServerOp,
    kind: Option<FrameKind>,
    latency: Duration,
) {
    observer.notify(Box::new(move |o| emit_success(o, op, kind, latency)));
}

/// 失敗イベントを保留キュー経由で通知する（エラーは所有データへ複製する）。
fn notify_failure<C: ServerObserver>(
    observer: &SharedObserver<C>,
    op: ServerOp,
    kind: Option<FrameKind>,
    outcome: ServerOutcome,
    latency: Duration,
    err: &IoError,
) {
    let err = IoError::new(err.code(), err.message().to_owned());
    observer.notify(Box::new(move |o| {
        emit_failure(o, op, kind, outcome, latency, &err)
    }));
}

/// [`SplitTransport::split`] が返す送信側（#1118・IO-1・P1-3）。
///
/// [`UdsConnection`] の複製 fd を持つ。契約は [`SplitTransport`] とモジュール doc
/// 「分割」節を参照。drop 時、poison されていなければ書き込み側を half-close する。
pub struct UdsSendHalf<C: ServerObserver> {
    inner: imp::ConnectionInner,
    poison: SharedPoison,
    observer: SharedObserver<C>,
}

/// [`SplitTransport::split`] が返す受信側（#1118・IO-1・P1-3）。
///
/// [`UdsConnection`] が持っていた `ReceiveLimits`（TASK-13.4）をそのまま引き継ぎ、
/// 本体バッファ確保前の受理判定も分割前と同じ。
pub struct UdsRecvHalf<C: ServerObserver> {
    inner: imp::ConnectionInner,
    poison: SharedPoison,
    observer: SharedObserver<C>,
    limits: ReceiveLimits,
}

impl<C: ServerObserver> core::fmt::Debug for UdsSendHalf<C> {
    /// poison 状態のみを出す（[`UdsConnection`] の `Debug` と同じ方針）。
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("UdsSendHalf")
            .field("poisoned", &self.poison.is_poisoned())
            .finish()
    }
}

impl<C: ServerObserver> core::fmt::Debug for UdsRecvHalf<C> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("UdsRecvHalf")
            .field("poisoned", &self.poison.is_poisoned())
            .finish()
    }
}

impl<C: ServerObserver> UdsSendHalf<C> {
    /// 両半分で共有している観測フックへ、ロックを取って `f` を適用する
    /// （[`UdsConnection::observer_mut`] の分割後の代替）。`f` の実行中に他方の半分が
    /// 通知したイベントは待たずに保留キューへ積まれ、`f` の後に順序どおり適用される
    /// （I/O 期限を守りつつ欠落させない）。
    pub fn with_observer<R>(&self, f: impl FnOnce(&mut C) -> R) -> R {
        self.observer.with(f)
    }
}

impl<C: ServerObserver> UdsRecvHalf<C> {
    /// 両半分で共有している観測フックへ、ロックを取って `f` を適用する
    /// （[`UdsConnection::observer_mut`] の分割後の代替）。`f` の実行中に他方の半分が
    /// 通知したイベントは待たずに保留キューへ積まれ、`f` の後に順序どおり適用される
    /// （I/O 期限を守りつつ欠落させない）。
    pub fn with_observer<R>(&self, f: impl FnOnce(&mut C) -> R) -> R {
        self.observer.with(f)
    }
}

/// I/O の結果に共有 poison の規則（モジュール doc「分割」節の (2)・(3)）を適用する。
///
/// `Err` なら poison を立てて `shutdown(Both)` でもう片側を起こす。`Ok` でも他方が
/// 既に poison を立てていれば結果を捨てて `Unavailable` にする。戻り値の bool は
/// 「poison 済みのため結果を捨てた」（観測上 [`ServerOutcome::RejectedPoisoned`]）。
fn settle_shared<T>(
    inner: &imp::ConnectionInner,
    poison: &SharedPoison,
    result: Result<T, IoError>,
) -> (Result<T, IoError>, bool) {
    match result {
        Err(e) => {
            // 他方がすでに poison を立てていた場合、この Err は多くが shutdown(Both) で
            // 起こされた結果の I/O エラーなので、元のエラーではなく `Unavailable` に揃える。
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

impl<C: ServerObserver> FrameSender for UdsSendHalf<C> {
    type Frame = Frame;

    fn send_frame(&mut self, frame: &Frame, timeout: IoTimeout) -> Result<(), IoError> {
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
            );
            return Err(err);
        }
        let started = Instant::now();
        let result = self.inner.send_frame(frame, timeout);
        let elapsed = started.elapsed();
        let (result, rejected) = settle_shared(&self.inner, &self.poison, result);
        match &result {
            Ok(()) => notify_success(&self.observer, ServerOp::Send, kind, elapsed),
            Err(err) => {
                let outcome = if rejected {
                    ServerOutcome::RejectedPoisoned
                } else {
                    ServerOutcome::Failure
                };
                notify_failure(&self.observer, ServerOp::Send, kind, outcome, elapsed, err);
            }
        }
        result
    }
}

impl<C: ServerObserver> FrameReceiver for UdsRecvHalf<C> {
    type Frame = Frame;

    fn recv_frame(&mut self, timeout: IoTimeout) -> Result<Frame, IoError> {
        if self.poison.is_poisoned() {
            let err = unavailable_after_poison();
            notify_failure(
                &self.observer,
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
        let attempt_kind = attempt.kind;
        let (result, rejected) = settle_shared(&self.inner, &self.poison, attempt.result);
        match &result {
            Ok(frame) => {
                notify_success(&self.observer, ServerOp::Recv, Some(frame.kind()), elapsed)
            }
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
                );
            }
        }
        result
    }
}

impl<C: ServerObserver> Drop for UdsSendHalf<C> {
    /// poison されていなければ書き込み側を half-close する（相手は送信済みデータを
    /// 読み切った後に EOF を受ける。受信側は使い続けられる）。shutdown の失敗
    /// （ENOTCONN 等）は無視する。
    fn drop(&mut self) {
        if !self.poison.is_poisoned() {
            self.inner.shutdown_write();
        }
    }
}

impl<C: ServerObserver> SplitTransport for UdsConnection<C> {
    type SendHalf = UdsSendHalf<C>;
    type RecvHalf = UdsRecvHalf<C>;

    /// poison 済みなら `Unavailable`（接続はここで drop して閉じる）。fd の複製に
    /// 失敗した場合もエラーを返し、接続は閉じる。
    fn split(self) -> Result<(UdsSendHalf<C>, UdsRecvHalf<C>), IoError> {
        if self.poisoned {
            return Err(unavailable_after_poison());
        }
        let recv_inner = self.inner.try_clone()?;
        let poison = SharedPoison::new();
        let observer = SharedObserver::new(self.observer);
        Ok((
            UdsSendHalf {
                inner: self.inner,
                poison: poison.clone(),
                observer: observer.clone(),
            },
            UdsRecvHalf {
                inner: recv_inner,
                poison,
                observer,
                limits: self.limits,
            },
        ))
    }
}

/// Linux / macOS 向けの UDS 実装（`server.rs` の外へ OS 固有型を漏らさない。
/// coding-rust「クロスプラットフォーム」節）。
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod imp {
    use std::fs;
    use std::io::{self, Read, Write};
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
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

    /// 本体読み込みを少しずつ伸ばす際の 1 回あたりの伸長量の上限
    /// （申告された `body_len` が最大 64 MiB + 4 バイトでも、悪意ある相手の
    /// 申告だけを信用して一度に確保しない。security.md。伸ばし方は
    /// `BodyBuffer` 参照）。
    const BODY_READ_CHUNK: usize = 64 * 1024;

    pub(super) struct ServerInner {
        listener: UnixListener,
        path: PathBuf,
        /// bind 時点で 1 回だけ取得した自プロセスの実効 uid
        /// （`crate::sys::effective_uid`）。bind 前の親ディレクトリ所有者との照合
        /// （[`check_socket_owner`]）と、accept ごとの peer credential 照合
        /// （[`verify_peer_credential`]）の比較基準を同じ値に固定する（I1・I2・
        /// #820 security-auditor 再監査指摘対応。bind 後に `seteuid` 等で実効 uid が
        /// 変わっても、照合の基準は bind したときの主体のまま変わらない）。
        effective_uid: u32,
        /// bind 直後に記録したソケットファイルの実体（J3・#820 codex P1 指摘
        /// 対応）。[`Drop`] の [`cleanup_socket_file`] は、パス上のファイルが
        /// これと一致する場合だけ削除する。
        socket_identity: SocketFileIdentity,
    }

    impl ServerInner {
        pub(super) fn bind(path: &Path) -> Result<Self, IoError> {
            // I1・#820 security-auditor 再監査指摘対応: 実効 uid と親ディレクトリの
            // 所有者の照合は bind より前（`validate_parent_dir` の中）で行い、
            // 不一致なら何も作らずに拒否する。以前は bind 後に照合していたため、
            // 不一致時に作成済みのソケットファイルを `cleanup_socket_file`
            // （stat → unlink の 2 段階）で消す必要があり、その間に親ディレクトリを
            // symlink へ差し替えられると意図しないパスを unlink しうる TOCTOU が
            // あった（特に root 実行時）。
            let effective_uid = crate::sys::effective_uid();
            validate_parent_dir(path, effective_uid)?;
            reject_existing_path(path)?;

            let listener = UnixListener::bind(path).map_err(map_bind_error)?;

            // J3・#820 codex P1 指摘対応: bind 直後にパス上のファイルの実体を
            // 記録する。自分が作ったソケットだと確認できなければ、パス上の
            // ファイルは削除せず（`cleanup_socket_file` を呼ばない）、`listener`
            // をこのスコープの終わりで閉じてエラーを返す。
            let socket_identity = SocketFileIdentity::capture(path, effective_uid)?;

            // bind 後の後始末（nonblocking 化）が失敗したら、記録した実体と
            // 一致する場合に限り作成済みのソケットファイルを片付けてからエラーを
            // 返す（後始末自体の失敗は握りつぶし、元のエラーを優先して返す。
            // cleanup_socket_file 参照）。J2・#820 codex P0 指摘対応で、bind 後に
            // パスを再解決して権限を変える操作（旧 `0600` への chmod）は廃止した。
            if let Err(err) = finish_bind(&listener) {
                cleanup_socket_file(path, &socket_identity);
                return Err(err);
            }

            Ok(Self {
                listener,
                path: path.to_path_buf(),
                effective_uid,
                socket_identity,
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
            self.accept_with(timeout, on_event, &mut verify_peer_credential)
        }

        /// [`Self::accept`] の本体。peer credential の照合を `verify` として
        /// 受け取る（I4・#820 security-auditor 再監査指摘対応。SEC-4・PLUG-12）。
        ///
        /// 非公開（`imp` の外からは呼べない）で、本番の呼び出し元は
        /// [`Self::accept`] だけであり、そこでは常に固定の
        /// [`verify_peer_credential`] を渡す。別の照合を渡すのは本モジュールの
        /// テスト（`#[cfg(test)]`）だけで、別 uid の接続を実機で用意できなくても
        /// 「拒否 1 件ごとの通知 → 件数の加算 → 期限・上限判定 → 再試行」の配線を
        /// 実際のソケット（同一 uid の接続）で確かめるために使う。`verify` の
        /// 第 2 引数は bind 時点で保存した実効 uid（[`ServerInner`] の
        /// `effective_uid`）。
        fn accept_with(
            &self,
            timeout: IoTimeout,
            on_event: &mut dyn FnMut(&ServerEvent<'_>),
            verify: &mut dyn FnMut(&UnixStream, u32) -> Result<(), PeerCredentialRejection>,
        ) -> super::AcceptAttempt<ConnectionInner> {
            let deadline = Instant::now() + timeout.as_duration();
            let mut abort_retries = 0u32;
            let mut credential_rejections = 0u32;
            loop {
                // K2・#820 codex P1 指摘対応（REPAIR-5）: 次の accept を始める前に
                // 期限を判定する。WouldBlock・ConnectionAborted・peer credential
                // 拒否の各経路の `sleep` が期限をまたいだ場合に、期限後に listen
                // キューから接続を取り出して（下の成功経路の判定で）閉じるだけに
                // なるのを避け、その接続をキューに残したまま `Timeout` を返す。
                // 初回は `deadline` を計算した直後のため、ごく短い timeout でない
                // 限り通過する（通過しなくても `Timeout` を返すだけで、接続は
                // キューに残る）。
                if Instant::now() >= deadline {
                    return super::AcceptAttempt {
                        result: Err(accept_timeout_error()),
                        aborted_retries: abort_retries,
                        peer_credential_rejections: credential_rejections,
                    };
                }
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
                        if let Err(rejection) = verify(&stream, self.effective_uid) {
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

                        // K1・#820 codex P1 指摘対応（REPAIR-5）: 成功経路でも、
                        // 接続を呼び出し元へ渡す直前に期限を判定する。accept・
                        // peer credential 照合の間に期限を過ぎた場合は、接続を
                        // 閉じて（クライアント側は EOF を読む）`Timeout` を返す
                        // （渡した後は呼び出し元の責任になるため、期限付き受付の
                        // 契約はここで閉じる）。拒否経路の「件数の加算と通知は
                        // 期限判定より先」（H3）は上の分岐で済んでおり、ここでは
                        // 件数を変えずにそのまま添える。
                        if Instant::now() >= deadline {
                            drop(stream);
                            return super::AcceptAttempt {
                                result: Err(accept_timeout_error()),
                                aborted_retries: abort_retries,
                                peer_credential_rejections: credential_rejections,
                            };
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
                                result: Err(accept_timeout_error()),
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
            cleanup_socket_file(&self.path, &self.socket_identity);
        }
    }

    /// bind したソケットファイルの実体（J3・#820 codex P1 指摘対応。PLUG-12）。
    ///
    /// [`ServerInner::bind`] が bind 直後に [`Self::capture`] で記録し、
    /// [`cleanup_socket_file`] が削除直前に取り直した値と比べる。`(dev, ino)` で
    /// ファイルシステム上の同一ファイルを識別し、所有者 uid もあわせて比べる
    /// （bind 後に元のパスが unlink され、別の listener が同じパスへ bind した
    /// 場合、その新しいソケットは別の `(dev, ino)` を持つため削除対象にならない）。
    /// socket fd の `fstat` は sockfs 側の inode を返し、パスの inode とは一致
    /// しないため（#820 で実測）、記録にはパスの `symlink_metadata` を使う。
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct SocketFileIdentity {
        dev: u64,
        ino: u64,
        uid: u32,
    }

    impl SocketFileIdentity {
        /// `meta` がソケットファイルならその実体を返し、それ以外（通常ファイル・
        /// symlink・ディレクトリ等）なら `None` を返す純粋関数。
        fn from_metadata(meta: &fs::Metadata) -> Option<Self> {
            meta.file_type().is_socket().then(|| Self {
                dev: meta.dev(),
                ino: meta.ino(),
                uid: meta.uid(),
            })
        }

        /// bind 直後の `path` を `symlink_metadata` で調べ、ソケットであり・所有者
        /// uid が `effective_uid`（bind 時点の自プロセスの実効 uid）と一致する
        /// 場合に、その実体を返す。
        ///
        /// 失敗した場合、呼び出し元（[`ServerInner::bind`]）はパス上のファイルを
        /// 削除しない（自分が作ったと確認できないため）。`symlink_metadata`
        /// 自体の失敗（bind 直後に unlink された等）は [`IoErrorCode::Internal`]、
        /// ソケットでない・所有者 uid が異なる（別物に差し替わっていた）場合は
        /// bind 前の所有者照合（[`check_socket_owner`]）と同じ分類の
        /// [`IoErrorCode::InvalidArgument`] を返す（メッセージは親ディレクトリでは
        /// なくソケットファイル自身の所有者を比べたことを示す専用のもの）。
        fn capture(path: &Path, effective_uid: u32) -> Result<Self, IoError> {
            let meta = fs::symlink_metadata(path).map_err(|e| {
                IoError::new(
                    IoErrorCode::Internal,
                    format!("failed to stat the socket file right after bind: {e}"),
                )
            })?;
            let identity = Self::from_metadata(&meta).ok_or_else(|| {
                IoError::new(
                    IoErrorCode::InvalidArgument,
                    "the socket path no longer refers to a socket right after bind",
                )
            })?;
            if identity.uid != effective_uid {
                return Err(IoError::new(
                    IoErrorCode::InvalidArgument,
                    format!(
                        "the socket file created by bind is owned by uid {} but the server's \
                         effective uid is {effective_uid}",
                        identity.uid
                    ),
                ));
            }
            Ok(identity)
        }
    }

    /// 自分が bind したソケットファイルを片付ける（[`ServerInner`] の [`Drop`]・
    /// bind 失敗時の後始末から呼ばれる）。削除の直前に `symlink_metadata` で
    /// 取り直した実体が、bind 直後に記録した `expected`（ソケットであること・
    /// `(dev, ino)`・所有者 uid）とすべて一致する場合だけ削除し、一致しなければ
    /// 何もしない（J3・#820 codex P1 指摘対応。別種のファイルや、同じパスへ
    /// 後から bind された別の listener のソケットを消さない）。
    ///
    /// 検査と削除の間の残る競合は、親ディレクトリ（owner 専用・自プロセスの
    /// 実効 uid が所有）に書き込める主体（同じ uid か root）にしか使えない
    /// （モジュール doc「ソケットファイルの権限と片付け」節参照）。
    fn cleanup_socket_file(path: &Path, expected: &SocketFileIdentity) {
        if let Ok(meta) = fs::symlink_metadata(path)
            && SocketFileIdentity::from_metadata(&meta).as_ref() == Some(expected)
        {
            let _ = fs::remove_file(path);
        }
    }

    /// bind 直後の後始末: listener の非ブロッキング化。失敗すれば呼び出し元
    /// （[`ServerInner::bind`]）が、記録した実体と一致する場合に限り
    /// ソケットファイルを片付ける。所有者の照合（PLUG-12・[`check_socket_owner`]）
    /// はここではなく bind 前の [`validate_parent_dir`] と bind 直後の
    /// [`SocketFileIdentity::capture`] で済ませている（I1・J3・#820）。
    ///
    /// ソケットファイルのパスは受け取らない（J2・#820 codex P0 指摘対応。
    /// bind 後にパスを再解決して権限を変える操作をしないことを型で保つ。
    /// 旧実装の `0600` への chmod を廃止した理由は [`super::UdsServer::bind`]
    /// の「ソケットファイルのモード」節参照）。
    fn finish_bind(listener: &UnixListener) -> Result<(), IoError> {
        listener.set_nonblocking(true).map_err(|e| {
            IoError::new(
                IoErrorCode::Internal,
                format!("failed to set listener to nonblocking mode: {e}"),
            )
        })?;
        Ok(())
    }

    /// bind するプロセスの実効 uid（`effective_uid`。bind で作られるソケット
    /// ファイルの所有者になる uid）が親ディレクトリの所有者（`parent_uid`）と
    /// 一致することを確かめる（PLUG-12・security.md「UDS は所有者・権限・
    /// symlink を検証してから bind」）。
    ///
    /// [`validate_parent_dir`] から bind より前に呼ばれ、不一致ならソケット
    /// ファイルを作る前に拒否する（I1・#820 security-auditor 再監査指摘対応。
    /// 比べる 2 値はどちらも bind 前に確定しているため、bind 後に照合して
    /// 作成済みのファイルを片付ける必要がない）。
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
        /// `crate::sys::peer_uid` の取得自体は成功したが bind 時点の実効 uid
        /// （[`ServerInner`] が保存した値）と不一致だった場合の接続元 uid。取得自体
        /// に失敗した場合（対応していないアーキテクチャを含む）は `None`。
        peer_uid: Option<u32>,
        /// 拒否の詳細（エラーコード・メッセージ）。
        error: IoError,
    }

    /// 接続元（`stream`）の peer credential を検証する（E・#820 codex P0
    /// 指摘対応。PLUG-12・security.md「別 UID からの接続は peer credential
    /// 検証で切断する」）。
    ///
    /// `crate::sys::peer_uid`（Linux は `SO_PEERCRED` が返す
    /// `struct ucred.uid`、macOS は `getpeereid(2)` が返す euid）で接続元の
    /// **接続時点の実効 uid（euid）**を取得し、`expected_uid`（[`ServerInner`] が
    /// bind 時点で取得・保存した自プロセスの実効 uid。accept のたびに
    /// `geteuid(2)` を取り直さない。I2・#820 security-auditor 再監査指摘対応）と
    /// 一致するかを
    /// [`peer_credential_matches`]（純粋関数。単体テスト対象）で判定する（H2・
    /// #820 security-auditor 指摘対応。「実 uid」ではなく euid である点・
    /// user namespace の外の uid は `overflowuid` として観測されうる点は
    /// `server.rs` モジュール doc「peer credential の検証」節参照）。
    /// `peer_uid` の取得自体に失敗した場合（対応していないアーキテクチャを
    /// 含む）も、判定不能を「別 UID からの接続」と同じ扱いにして拒否する
    /// （fail-closed）。拒否時のエラーコードは [`check_socket_owner`]（bind 時の
    /// 所有者照合）と同じ [`IoErrorCode::InvalidArgument`] を使い、新しいコードは
    /// 追加しない（#820 修正計画 E）。
    fn verify_peer_credential(
        stream: &UnixStream,
        expected_uid: u32,
    ) -> Result<(), PeerCredentialRejection> {
        let peer_uid = match crate::sys::peer_uid(stream) {
            Ok(uid) => uid,
            Err(error) => {
                return Err(PeerCredentialRejection {
                    peer_uid: None,
                    error,
                });
            }
        };
        if !peer_credential_matches(peer_uid, expected_uid) {
            return Err(PeerCredentialRejection {
                peer_uid: Some(peer_uid),
                error: IoError::new(
                    IoErrorCode::InvalidArgument,
                    format!(
                        "connecting peer uid ({peer_uid}) does not match the server's \
                         effective uid at bind time ({expected_uid})"
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

    /// accept の期限切れを表すエラー（[`ServerInner::accept`] の全経路で共有する。
    /// ループ先頭・成功経路・WouldBlock・再試行判定のどこで期限切れを検出しても
    /// 同じ `code` / `message` を返し、観測イベントの見分けがつくようにする。
    /// REPAIR-4・REPAIR-5・#820）。
    fn accept_timeout_error() -> IoError {
        IoError::new(
            IoErrorCode::Timeout,
            "accept timed out waiting for a client connection",
        )
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
            return Some(accept_timeout_error());
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
    /// （security.md の UDS 観点。fail-closed）。あわせて、親ディレクトリの
    /// 所有者が `effective_uid`（bind するプロセスの実効 uid）と一致することを
    /// [`check_socket_owner`] で確かめる（PLUG-12）。いずれも bind より前に
    /// 行い、失敗した場合は何も作らずに拒否する（I1・#820 security-auditor
    /// 再監査指摘対応）。
    ///
    /// `0o077` まで絞る理由: ソケットファイル自体のモードは bind 時の umask に
    /// 従い、bind 後に変更しない（J2・#820 codex P0 指摘対応。
    /// [`super::UdsServer::bind`] の「ソケットファイルのモード」節参照）。
    /// パス名での接続には親ディレクトリの search 権限が要るため、親ディレクトリを
    /// owner 専用にすることが、ソケットファイルのモードに関係なく owner 以外の
    /// 到達を遮断する境界になる（accept 時の peer credential 検証と合わせた
    /// 2 段。モジュール doc「ソケットファイルの権限と片付け」節参照）。
    ///
    /// 直近の親ディレクトリのみを検査し、祖先のパス要素（親の親など）の
    /// symlink は検査しない（`Path::parent()` はパスを正規化しないため、
    /// 祖先を辿るには `canonicalize` 相当の解決が必要になるが、macOS の
    /// `/tmp` が `/private/tmp` への symlink であるように、canonicalize 結果を
    /// 素朴に比較する方式は環境依存の誤判定を生みやすく採らない。範囲外として
    /// `server.rs` モジュール doc に明記する）。
    fn validate_parent_dir(path: &Path, effective_uid: u32) -> Result<(), IoError> {
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
        check_socket_owner(effective_uid, meta.uid())
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
        /// fd を複製して分割後の受信側用の `ConnectionInner` を作る（#1118）。
        /// `O_NONBLOCK` は複製間で共有される点は上位モジュール doc「分割」節参照。
        pub(super) fn try_clone(&self) -> Result<Self, IoError> {
            self.stream
                .try_clone()
                .map(|stream| Self { stream })
                .map_err(map_io_error)
        }

        /// 読み書きの両方向を shutdown する。もう片側でブロック中の read / write を
        /// 起こすために使う。失敗（ENOTCONN 等）は無視する。
        pub(super) fn shutdown_both(&self) {
            let _ = self.stream.shutdown(std::net::Shutdown::Both);
        }

        /// 書き込み方向のみ shutdown する（half-close）。失敗は無視する。
        pub(super) fn shutdown_write(&self) {
            let _ = self.stream.shutdown(std::net::Shutdown::Write);
        }

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
        /// `MAX_CONTROL_PAYLOAD_LEN`）の確保前検証のみである。滞留件数上限が
        /// 実効化されない（常に `0` を渡す）のは、[`crate::writeback::serve_connection`]
        /// （TASK-13.2.2・#822）の write-back が同期的で、受信時点の
        /// 「排出済みだが未書き込み」のキューが常に空であるという前提の下で
        /// 構造上正確だからである（`crates/io/src/writeback.rs` モジュール doc
        /// 「受信上限」節参照。非同期化する場合はこの前提を見直す必要がある）。
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
                result: admitted.decode_body_owned(body),
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

    /// `set_read_timeout` / `set_write_timeout` に渡す残り時間の下限
    /// （#1115 codex レビュー指摘対応・macOS CI 実バグ修正）。
    ///
    /// これらの std API は `Duration` をマイクロ秒精度の `timeval` へ変換して
    /// `setsockopt(2)` へ渡す。期限直前で `remaining_or_timeout` が返す残り
    /// 時間がこの精度を下回る（例: 数百ナノ秒）と、`timeval` 変換の結果が
    /// 実質ゼロになる。macOS はゼロの `SO_RCVTIMEO` / `SO_SNDTIMEO` を
    /// `EINVAL` で拒否し（`is_peer_shutdown_einval` はこの `EINVAL` を「相手が
    /// すでに切断した」と判定する既存のヒューリスティック）、相手がまだ接続
    /// したままでも `Unavailable` を誤って返してしまう
    /// （`repair5_uds_send_times_out_on_unresponsive_peer` の macOS CI 再現失敗。
    /// PR #1115 の `bench-regression` 以外の rust-ci macOS ジョブで観測。
    /// 期限を過ぎたかどうかの判定自体は変えず、`timeval` 精度未満の残り時間を
    /// 「実質期限切れ」として扱うだけで直す）。
    const MIN_REMAINING_TIMEOUT: Duration = Duration::from_micros(1);

    /// `deadline` までの残り時間を返す。残りが [`MIN_REMAINING_TIMEOUT`] 未満
    /// ならその場で [`IoErrorCode::Timeout`] を返す（`Duration::ZERO` を
    /// `set_read_timeout` / `set_write_timeout` に渡すと std がエラーにする上、
    /// それを僅かに上回るだけの残り時間も `timeval` 精度未満に丸まりうるため、
    /// 実用上の下限を [`MIN_REMAINING_TIMEOUT`] として先に弾く）。
    fn remaining_or_timeout(deadline: Instant) -> Result<Duration, IoError> {
        let now = Instant::now();
        let remaining = deadline.checked_duration_since(now);
        match remaining {
            Some(remaining) if remaining >= MIN_REMAINING_TIMEOUT => Ok(remaining),
            _ => Err(IoError::new(
                IoErrorCode::Timeout,
                "frame deadline exceeded before the operation completed",
            )),
        }
    }

    /// `io::Error` を `IoError` へ変換する（`crate::error` の `IoErrorCode`・
    /// ERR-1 対応）。相手から届いたデータを message に含めず、`ErrorKind`
    /// 程度の情報のみを載せる（security.md「情報漏えい」観点）。
    ///
    /// `WouldBlock` / `TimedOut` もここでは `Timeout` に写像するが、
    /// `read_exact_until` / `read_body_until` / `write_all_until` は
    /// これらのエラーを本関数に渡さず、`remaining_or_timeout` によるフレーム
    /// 全体の期限の再計算へループを戻す（REPAIR-5・#820 レビュー指摘。ただし
    /// 読み取り経路の drain モードでの `WouldBlock` は、ループを戻さず EOF と
    /// 同じ `Unavailable` にする。[`ReadWait`] 参照）。テスト
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

    /// この OS で、`set_read_timeout` / `set_write_timeout`（`setsockopt(2)` の
    /// `SO_RCVTIMEO` / `SO_SNDTIMEO`）が返す `EINVAL` を「相手がすでに切断した」
    /// ことの手がかりとして扱うか。macOS だけ `true`（根拠は
    /// [`is_peer_shutdown_einval`] 参照。H7・#820）。
    ///
    /// cfg を実行時の判定から切り離して bool 定数に閉じ込め、判定関数
    /// （[`classify_read_timeout_error`]・[`map_write_timeout_error`]）には引数で
    /// 渡す。これにより macOS 側の分岐も Linux 上のユニットテストで確かめられる。
    const SET_TIMEOUT_EINVAL_MEANS_PEER_SHUTDOWN: bool = cfg!(target_os = "macos");

    /// タイムアウト設定の失敗が「相手の切断を示す `EINVAL`」かを判定する純粋関数
    /// （D・H7・#820。PR #1113 の macOS CI 失敗の修正）。
    ///
    /// `einval_means_peer_shutdown` には通常 [`SET_TIMEOUT_EINVAL_MEANS_PEER_SHUTDOWN`]
    /// を渡す（テストだけが両方の値を渡す）。`true` かつ `e` が OS の返した
    /// `EINVAL`（`kind() == InvalidInput` かつ `raw_os_error()` を持つ）のときだけ
    /// `true` を返す。std が OS を呼ばずに合成する `InvalidInput`（`Duration::ZERO`
    /// を渡した場合等。`raw_os_error()` を持たない）は対象外にし、実装の誤りを
    /// 相手の切断と取り違えない（加えて `remaining_or_timeout` が
    /// `Duration::ZERO` を渡さない）。
    ///
    /// # macOS で `EINVAL` を相手の切断とみなす根拠
    /// - 実測: macOS CI では、相手が close した後のソケットに対する
    ///   `set_read_timeout` が `EINVAL`（os error 22）を返す
    ///   （`io1_uds_recv_reports_unavailable_on_peer_close` が再現するケースと、
    ///   PR #1113 で失敗した 2 テスト）
    /// - XNU のソース（`sosetoptlock`）を読む限り、ソケットが送受信とも
    ///   shutdown 済み（`SS_CANTRCVMORE` と `SS_CANTSENDMORE` の両方が立った状態。
    ///   UDS では相手の close でこの状態になるように見える）のとき、setsockopt は
    ///   オプションの種類によらず `EINVAL` を返すように見える。macOS の
    ///   `setsockopt(2)` のマニュアルの `[EINVAL]` 項にも、接続済みであることを
    ///   要するオプションを接続されていないソケットに指定した場合に返るとある。
    ///   ただしどの状態で `EINVAL` になるかを実機で網羅的に確かめたものではない
    ///
    /// # Linux（`false`）
    /// Linux では相手が切断済みでも `setsockopt` 自体は成功し、直後の
    /// `read` / `write` が `map_io_error` の切断系 `ErrorKind` を返す。したがって
    /// `EINVAL` は相手の接続とは無関係な実装上の異常（不正な timeout 値の指定等）を
    /// 示す可能性が高い。macOS の判断を Linux に転用すると、本来 `Internal`
    /// （実装バグ）として報告すべきものを相手の切断に読み替えてバグを隠す側に
    /// 倒れるため、Linux では常に `false` を返す（H7・#820 security-auditor 指摘
    /// 対応）。
    fn is_peer_shutdown_einval(e: &io::Error, einval_means_peer_shutdown: bool) -> bool {
        einval_means_peer_shutdown
            && e.kind() == io::ErrorKind::InvalidInput
            && e.raw_os_error().is_some()
    }

    /// 読み取り経路の `set_read_timeout` が失敗したときの処置
    /// （[`classify_read_timeout_error`] の戻り値）。
    #[derive(Debug)]
    enum ReadTimeoutAction {
        /// 相手が切断済みとみなし、タイムアウトを設定せずに受信バッファの残りを
        /// 読み出す（[`ReadWait`] の drain モードへ入る）。
        DrainWithoutTimeout,
        /// 読み取りを打ち切ってこのエラーを返す。
        Fail(IoError),
    }

    /// 読み取り経路（`read_exact_until`・`read_body_until`）の `set_read_timeout`
    /// の失敗を処置へ振り分ける純粋関数（IO-1・REPAIR-5・#820。PR #1113 の macOS
    /// CI 失敗の修正）。
    ///
    /// - [`is_peer_shutdown_einval`] が `true`（macOS の `EINVAL`）:
    ///   [`ReadTimeoutAction::DrainWithoutTimeout`]
    /// - それ以外（Linux の `EINVAL`・他の `ErrorKind`・std が合成した
    ///   `InvalidInput`）: `Internal` の [`ReadTimeoutAction::Fail`]
    ///
    /// # 失敗にせず読み続ける理由
    /// 相手が close 前に送り切ったデータは受信バッファに残っており、ここで
    /// `Unavailable` にすると正当なフレーム（1 フレーム送って閉じる相手の最後の
    /// フレーム等）を読まずに失う。以前の実装（H7）は macOS の `EINVAL` を
    /// 読み取り経路でも `Unavailable` にしていたため、このフレームを失っていた。
    /// タイムアウトを設定できなくてもハングしないことは、XNU の性質（送受信とも
    /// shutdown 済みのソケットの read は受信バッファのデータを返し、尽きれば 0 を
    /// 返してブロックしないように見えること）には依存させず、[`ReadWait`] が
    /// ソケットを nonblocking にしてから read することで担保する。
    fn classify_read_timeout_error(
        e: io::Error,
        einval_means_peer_shutdown: bool,
    ) -> ReadTimeoutAction {
        if is_peer_shutdown_einval(&e, einval_means_peer_shutdown) {
            ReadTimeoutAction::DrainWithoutTimeout
        } else {
            ReadTimeoutAction::Fail(IoError::new(
                IoErrorCode::Internal,
                format!("failed to set io timeout: {e}"),
            ))
        }
    }

    /// 書き込み経路（`write_all_until`）の `set_write_timeout` の失敗を
    /// `IoError` へ変換する純粋関数（D・H7・#820）。
    ///
    /// - [`is_peer_shutdown_einval`] が `true`（macOS の `EINVAL`）: `Unavailable`
    ///   （相手が閉じていれば書けないため、読み取り経路と違い続行しない。
    ///   切断済みの相手への操作を実装バグを示す `Internal` で誤って報告しない）
    /// - それ以外: `Internal`
    fn map_write_timeout_error(e: io::Error, einval_means_peer_shutdown: bool) -> IoError {
        if is_peer_shutdown_einval(&e, einval_means_peer_shutdown) {
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

    /// 読み取り経路（`read_exact_until`・`read_body_until`）の 1 回の呼び出しの
    /// 間、各 read の前の期限判定・待ち時間の設定と、相手の切断後に受信バッファの
    /// 残りを読み出す drain モードを管理する（IO-1・REPAIR-5・#820。PR #1113 の
    /// macOS CI 失敗の修正）。
    ///
    /// # drain モード
    /// [`Self::before_read`] で `set_read_timeout` の失敗が
    /// [`ReadTimeoutAction::DrainWithoutTimeout`] に振り分けられると、ソケットを
    /// nonblocking に切り替えて drain モードへ入る。drain モードでは:
    ///
    /// - 各 read の前の期限判定（`remaining_or_timeout`）は通常時と同じく行う
    /// - `set_read_timeout` はその呼び出しの残りでは呼び直さない（相手の切断は
    ///   元に戻らず、呼び直しても同じ失敗になるだけのため）
    /// - read はブロックせず、データ・0（EOF）・`WouldBlock` のいずれかで即座に
    ///   返る。`WouldBlock` は受信バッファが空であることを示し、相手はもう送って
    ///   こないため EOF と同じ `Unavailable` にする（呼び出し元が
    ///   [`Self::is_draining`] で判定する。通常時のように待ち直すと期限まで
    ///   busy loop になる）
    ///
    /// # blocking への復帰
    /// [`Self::finish`] が読み取り関数の終了時（成功・失敗とも）に blocking へ
    /// 戻し、読み取り関数の外から見たソケットの状態を「blocking＋呼び出しごとの
    /// タイムアウト」に保つ。`EINVAL` が相手の切断以外の原因だった場合に
    /// nonblocking のまま返すと、次の recv / send で `set_*_timeout` が成功しても
    /// read / write が `WouldBlock` を返し続け、期限まで busy loop になりうる
    /// （`write_all_until` は blocking＋`SO_SNDTIMEO` が前提）。相手が本当に切断
    /// 済みなら、次の recv は再び drain モードへ入り、send は `set_write_timeout`
    /// の失敗で `Unavailable` になるため、戻しても害はない。
    ///
    /// nonblocking の切り替えが失敗した場合は `Internal` を返す（fail-closed。
    /// 復帰の失敗では受信済みのフレームも失う）。accept 経路（`accept_with`）は
    /// 相手が切断済みの接続にも `set_nonblocking(false)` を呼んでおり、その接続の
    /// 最初の `set_read_timeout` が `EINVAL` になる
    /// `io1_uds_recv_reports_unavailable_on_peer_close` が macOS CI で通っている
    /// ことから、この状態のソケットでも切り替えは成功すると見込んでいる。
    struct ReadWait {
        draining: bool,
    }

    impl ReadWait {
        fn new() -> Self {
            Self { draining: false }
        }

        fn is_draining(&self) -> bool {
            self.draining
        }

        /// read の直前に呼ぶ。期限を過ぎていれば `Timeout`、drain モードでなければ
        /// 残り時間を `set_read_timeout` に設定する（失敗は
        /// [`classify_read_timeout_error`] で振り分ける）。
        fn before_read(&mut self, stream: &UnixStream, deadline: Instant) -> Result<(), IoError> {
            let remaining = remaining_or_timeout(deadline)?;
            if self.draining {
                return Ok(());
            }
            match stream.set_read_timeout(Some(remaining)) {
                Ok(()) => Ok(()),
                Err(e) => {
                    match classify_read_timeout_error(e, SET_TIMEOUT_EINVAL_MEANS_PEER_SHUTDOWN) {
                        ReadTimeoutAction::DrainWithoutTimeout => self.enter_drain(stream),
                        ReadTimeoutAction::Fail(err) => Err(err),
                    }
                }
            }
        }

        /// ソケットを nonblocking に切り替えて drain モードへ入る（テストは
        /// Linux 上で drain モードを強制するために直接呼ぶ）。
        fn enter_drain(&mut self, stream: &UnixStream) -> Result<(), IoError> {
            stream.set_nonblocking(true).map_err(|e| {
                IoError::new(
                    IoErrorCode::Internal,
                    format!("failed to switch a peer-closed stream to nonblocking mode: {e}"),
                )
            })?;
            self.draining = true;
            Ok(())
        }

        /// 読み取り関数の結果を受け取り、drain モードに入っていれば blocking へ
        /// 戻してから返す。読み取り自体がエラーならそのエラーを優先する（接続は
        /// 呼び出し元で poison され以後使われないため、復帰の失敗は捨てる）。
        fn finish<T>(self, stream: &UnixStream, result: Result<T, IoError>) -> Result<T, IoError> {
            if !self.draining {
                return result;
            }
            let restored = stream.set_nonblocking(false);
            match (result, restored) {
                (Err(e), _) => Err(e),
                (Ok(value), Ok(())) => Ok(value),
                (Ok(_), Err(e)) => Err(IoError::new(
                    IoErrorCode::Internal,
                    format!("failed to restore blocking mode after draining: {e}"),
                )),
            }
        }
    }

    /// `buf` を埋め切るまで読む。フレーム全体の `deadline` を基準に毎回残り
    /// 時間を計算し直すため、1 バイトずつ小出しに送ってくる相手でも
    /// フレーム全体の期限で打ち切られる（期限後に read を始めず、各 read の待ちも
    /// 残り時間が上限。超過はソケットのタイムアウトの粒度の範囲に収まる。
    /// REPAIR-5）。
    ///
    /// 相手が切断済みでも受信バッファに残ったデータは読み切り、尽きたところで
    /// `Unavailable` を返す（macOS の扱いは [`ReadWait`] 参照。IO-1・#820）。
    fn read_exact_until(
        stream: &mut UnixStream,
        buf: &mut [u8],
        deadline: Instant,
        what: &'static str,
    ) -> Result<(), IoError> {
        let mut wait = ReadWait::new();
        let result = read_exact_with(stream, buf, deadline, what, &mut wait);
        wait.finish(stream, result)
    }

    /// [`read_exact_until`] の読み取りループ本体。`wait` の drain モードの
    /// 後始末（blocking への復帰）は呼び出し元が [`ReadWait::finish`] で行う
    /// （テストは drain モードを強制した `wait` を渡して直接呼ぶ）。
    fn read_exact_with(
        stream: &mut UnixStream,
        buf: &mut [u8],
        deadline: Instant,
        what: &'static str,
        wait: &mut ReadWait,
    ) -> Result<(), IoError> {
        let peer_closed = || {
            IoError::new(
                IoErrorCode::Unavailable,
                format!("peer closed the connection before sending a complete {what}"),
            )
        };
        let mut filled = 0usize;
        while filled < buf.len() {
            wait.before_read(stream, deadline)?;
            let Some(dst) = buf.get_mut(filled..) else {
                return Err(IoError::new(
                    IoErrorCode::Internal,
                    "read buffer index out of range",
                ));
            };
            match stream.read(dst) {
                Ok(0) => return Err(peer_closed()),
                Ok(n) => filled += n,
                // drain モード（相手が切断済み）で受信バッファが尽きた。EOF と
                // 同じ扱いにする（ReadWait 参照）。
                Err(e) if wait.is_draining() && e.kind() == io::ErrorKind::WouldBlock => {
                    return Err(peer_closed());
                }
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

    /// 受信中のフレーム本体（`body_len` バイト）を、届いた分だけ少しずつ
    /// 確保しながらためるバッファ（REPAIR-2・security.md の DoS 対策。#820
    /// codex P0 指摘対応）。[`read_body_until`] が読み取りループの中で使う。
    ///
    /// # 確保容量の上限（#820 codex P0 指摘対応）
    /// 容量を `body_len` 以下に保つ。`Vec::extend_from_slice` 等の
    /// 償却つき成長は容量を幾何級数的に増やすため、実際の確保容量が受理済みの
    /// `body_len` を超えうる（以前の実装の問題）。本型は次の 2 点でこれを防ぐ:
    ///
    /// - 初期容量は `min(body_len, BODY_READ_CHUNK)`
    /// - 空き領域を使い切ったときだけ `reserve_exact(min(BODY_READ_CHUNK,
    ///   body_len - 容量))` で伸ばす（`reserve_exact` は償却つきの上乗せを
    ///   せず、要求量は `body_len` を超えない。std の文書はアロケータが要求より
    ///   多い領域を返すことを許すが、現行の `Vec` はその余剰を容量に含めない。
    ///   容量の推移はテストで具体値を照合する）。`resize` は伸ばした直後に
    ///   その空き領域をゼロ埋めするためだけに呼び、容量ぴったりまでしか
    ///   伸ばさないので内部で再確保は起きない
    ///
    /// 伸長は空きを使い切ったときに限るため、相手が 1 バイトずつ小出しに
    /// 送ってきても再確保は最大 `ceil(body_len / BODY_READ_CHUNK)` 回、
    /// ゼロ埋めも各バイト 1 回ずつに収まる（1 回の read ごとにゼロ埋めや
    /// 再確保をやり直す実装にすると、小出しの相手に CPU を浪費させられる）。
    /// 読み込み先は `Vec` の領域そのもので、ペイロード大の中間バッファ・
    /// 二重コピーを使わない（以前の実装が持っていた 64 KiB のスタック上の
    /// 一時配列も使わない）。
    ///
    /// # 不変条件
    /// `filled <= buf.len() <= buf.capacity() <= body_len`。`buf.len()` は
    /// 初期化済み（ゼロ埋め済みまたは受信済み）の範囲、`filled` はそのうち
    /// 実際に受信したバイト数を表す。受信していないゼロ埋め領域を本体として
    /// 返さないよう、[`Self::into_body`] は `filled == body_len` のときだけ
    /// 本体を返す。
    struct BodyBuffer {
        buf: Vec<u8>,
        filled: usize,
        body_len: usize,
    }

    impl BodyBuffer {
        /// `body_len` は [`crate::recv_limits::AdmittedHeader::body_len`]
        /// （`admit` を通過した検証済みの長さ）だけを渡す。
        fn new(body_len: usize) -> Self {
            Self {
                buf: Vec::with_capacity(body_len.min(BODY_READ_CHUNK)),
                filled: 0,
                body_len,
            }
        }

        fn is_complete(&self) -> bool {
            self.filled >= self.body_len
        }

        /// `reader` から 1 回だけ読み、受信したバイト数を返す（`Ok(0)` は相手の
        /// 切断、`Err` は `reader` のエラーをそのまま返す。いずれの場合も
        /// 不変条件は崩れず、`Interrupted` 等で呼び直してよい）。
        fn read_once<R: Read>(&mut self, reader: &mut R) -> io::Result<usize> {
            if self.filled == self.buf.len() {
                self.grow_initialized();
            }
            let Some(dst) = self.buf.get_mut(self.filled..) else {
                return Err(io::Error::other("body buffer index out of range"));
            };
            if dst.is_empty() {
                // `is_complete` のときにしか起きない（呼び出し元は完了後に
                // 呼ばない）。0 を返すと切断と区別できないため別扱いにする。
                return Err(io::Error::other("body buffer is already complete"));
            }
            let got = reader.read(dst)?;
            // `Read` の契約上 `got <= dst.len()` だが、実装の誤りで超えても
            // 不変条件を崩さないよう初期化済みの範囲で頭打ちにする。
            self.filled = self.filled.saturating_add(got).min(self.buf.len());
            Ok(got)
        }

        /// 初期化済みの範囲を 1 段（最大 `BODY_READ_CHUNK`）伸ばす。容量に
        /// 空きがなければ先に `reserve_exact` で `body_len` を超えない範囲だけ
        /// 容量を増やし、その後 `resize` で容量ぴったりまでゼロ埋めする
        /// （`resize` の要求量が容量以下なので、`resize` の内部で償却つきの
        /// 再確保は起きない）。
        fn grow_initialized(&mut self) {
            let len = self.buf.len();
            if len == self.buf.capacity() {
                let additional = self.body_len.saturating_sub(len).min(BODY_READ_CHUNK);
                self.buf.reserve_exact(additional);
            }
            let target = self.buf.capacity().min(self.body_len);
            if target > len {
                self.buf.resize(target, 0);
            }
        }

        /// 受信し終えた本体を返す。未完了なら `Internal`（呼び出し元の
        /// ループの誤り）を返し、ゼロ埋めのまま受信していない領域を本体と
        /// して扱わない。
        fn into_body(self) -> Result<Vec<u8>, IoError> {
            if self.filled != self.body_len || self.buf.len() != self.body_len {
                return Err(IoError::new(
                    IoErrorCode::Internal,
                    "frame body buffer is incomplete",
                ));
            }
            Ok(self.buf)
        }

        #[cfg(test)]
        fn capacity(&self) -> usize {
            self.buf.capacity()
        }

        #[cfg(test)]
        fn filled(&self) -> usize {
            self.filled
        }
    }

    /// `body_len` バイトの本体を、届いた分だけ少しずつ確保しながら読む
    /// （申告された長さだけで一度に確保しない。security.md の DoS 対策）。
    /// 確保容量を `body_len` 以下に保つ仕組みは [`BodyBuffer`] を参照
    /// （#820 codex P0 指摘対応）。
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
    ///
    /// # 受信 1 フレームあたりの確保量
    /// 本関数が返す本体の容量は `body_len` ちょうど。呼び出し元
    /// （[`ConnectionInner::recv_frame`]）はこれを
    /// `AdmittedHeader::decode_body_owned` → `crate::protocol::Frame::decode_body_owned`
    /// へ所有権ごと渡し、チェックサム検証後に末尾のチェックサムを落とした同じ
    /// 領域をペイロードとして使う（複製しない。#820 codex P0 指摘対応）。
    /// したがって 1 フレームの受信で申告長に比例して確保するのは、
    /// `AdmittedHeader` 由来の `body_len` ぶんの 1 回だけである。
    ///
    /// # 相手の切断後（IO-1・#820）
    /// 相手が切断済みでも受信バッファに残ったデータは読み切り、尽きたところで
    /// `Unavailable` を返す（macOS の扱いは [`ReadWait`] 参照）。
    fn read_body_until(
        stream: &mut UnixStream,
        body_len: usize,
        deadline: Instant,
    ) -> Result<Vec<u8>, IoError> {
        let mut wait = ReadWait::new();
        let result = read_body_with(stream, body_len, deadline, &mut wait);
        wait.finish(stream, result)
    }

    /// [`read_body_until`] の読み取りループ本体（後始末の分担は
    /// [`read_exact_with`] と同じ）。
    fn read_body_with(
        stream: &mut UnixStream,
        body_len: usize,
        deadline: Instant,
        wait: &mut ReadWait,
    ) -> Result<Vec<u8>, IoError> {
        let peer_closed = || {
            IoError::new(
                IoErrorCode::Unavailable,
                "peer closed the connection before sending a complete frame body",
            )
        };
        let mut body = BodyBuffer::new(body_len);
        while !body.is_complete() {
            wait.before_read(stream, deadline)?;
            match body.read_once(stream) {
                Ok(0) => return Err(peer_closed()),
                Ok(_) => {}
                // read_exact_with と同じく、drain モードで受信バッファが尽きたら
                // EOF と同じ扱いにする。
                Err(e) if wait.is_draining() && e.kind() == io::ErrorKind::WouldBlock => {
                    return Err(peer_closed());
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::Interrupted
                            | io::ErrorKind::WouldBlock
                            | io::ErrorKind::TimedOut
                    ) =>
                {
                    // read_exact_with と同じ理由でループを戻す（REPAIR-5）。
                    // `BodyBuffer::read_once` はエラー時に `filled` を進めない
                    // ため、ゼロ埋め済みの未受信領域が本体として数えられる
                    // ことはない。
                    continue;
                }
                Err(e) => return Err(map_io_error(e)),
            }
        }
        body.into_body()
    }

    /// `bytes` を書き切るまで送る（`write_all` 相当をフレーム単位の期限付きで
    /// 自前実装したもの）。
    ///
    /// `set_write_timeout` の失敗は [`map_write_timeout_error`] で変換する
    /// （macOS で相手が切断済みなら `Unavailable`。読み取り経路と違い、相手が
    /// 閉じていれば書けないため続行しない）。
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
                .map_err(|e| map_write_timeout_error(e, SET_TIMEOUT_EINVAL_MEANS_PEER_SHUTDOWN))?;
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
                    // read_exact_with と同じ理由でループを戻す（REPAIR-5）。
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

        /// Linux・macOS 共通の `EINVAL` の errno 値（std はこれを
        /// `ErrorKind::InvalidInput` に写像する）。`imp` は両 OS でだけ
        /// コンパイルされるため、テストでも同じ値を使える。
        const TEST_EINVAL: i32 = 22;
        /// Linux・macOS 共通の `EBADF` の errno 値（`EINVAL` 以外の OS エラーの例）。
        const TEST_EBADF: i32 = 9;

        /// IO-1・H7・#820: macOS の本番の設定値
        /// （[`SET_TIMEOUT_EINVAL_MEANS_PEER_SHUTDOWN`]）では、`EINVAL` は読み取り
        /// 経路で drain モード、書き込み経路で `Unavailable` になる。
        #[cfg(target_os = "macos")]
        #[test]
        fn io1_h7_820_macos_setting_drains_reads_and_fails_writes_on_einval() {
            match classify_read_timeout_error(
                io::Error::from_raw_os_error(TEST_EINVAL),
                SET_TIMEOUT_EINVAL_MEANS_PEER_SHUTDOWN,
            ) {
                ReadTimeoutAction::DrainWithoutTimeout => {}
                ReadTimeoutAction::Fail(err) => {
                    panic!("EINVAL on the read path must drain on macOS, got {err:?}")
                }
            }
            let err = map_write_timeout_error(
                io::Error::from_raw_os_error(TEST_EINVAL),
                SET_TIMEOUT_EINVAL_MEANS_PEER_SHUTDOWN,
            );
            assert_eq!(err.code(), IoErrorCode::Unavailable);
        }

        /// H7・#820（security-auditor 指摘対応）: Linux の本番の設定値では、
        /// `EINVAL` を相手の切断の手がかりとして扱わず、読み取り・書き込みとも
        /// `Internal`。
        #[cfg(target_os = "linux")]
        #[test]
        fn h7_820_linux_setting_keeps_einval_internal_on_both_paths() {
            let err = expect_read_fail(classify_read_timeout_error(
                io::Error::from_raw_os_error(TEST_EINVAL),
                SET_TIMEOUT_EINVAL_MEANS_PEER_SHUTDOWN,
            ));
            assert_eq!(err.code(), IoErrorCode::Internal);
            let err = map_write_timeout_error(
                io::Error::from_raw_os_error(TEST_EINVAL),
                SET_TIMEOUT_EINVAL_MEANS_PEER_SHUTDOWN,
            );
            assert_eq!(err.code(), IoErrorCode::Internal);
        }

        /// IO-1・REPAIR-5・#820（PR #1113 の macOS CI 失敗の修正）: macOS の
        /// 意味論（`true`）では、読み取り経路の `EINVAL` は失敗にせず drain
        /// モードへ進む（受信バッファの残りを読む）。
        #[test]
        fn io1_repair5_820_read_timeout_einval_drains_with_macos_semantics() {
            let e = io::Error::from_raw_os_error(TEST_EINVAL);
            assert_eq!(e.kind(), io::ErrorKind::InvalidInput);
            match classify_read_timeout_error(e, true) {
                ReadTimeoutAction::DrainWithoutTimeout => {}
                ReadTimeoutAction::Fail(err) => {
                    panic!("EINVAL on the read path must drain on macOS, got {err:?}")
                }
            }
        }

        /// H7・#820: Linux の意味論（`false`）では、読み取り経路の `EINVAL` も
        /// 従来どおり `Internal`。
        #[test]
        fn h7_820_read_timeout_einval_is_internal_with_linux_semantics() {
            let err = expect_read_fail(classify_read_timeout_error(
                io::Error::from_raw_os_error(TEST_EINVAL),
                false,
            ));
            assert_eq!(err.code(), IoErrorCode::Internal);
            assert_eq!(
                err.message(),
                format!(
                    "failed to set io timeout: {}",
                    io::Error::from_raw_os_error(TEST_EINVAL)
                )
            );
        }

        /// D・H7・#820: `EINVAL` 以外の OS エラー・std が合成した
        /// `InvalidInput`（`raw_os_error()` を持たない。`Duration::ZERO` を渡した
        /// 場合等）は、macOS の意味論でも読み取り経路で `Internal`（実装の誤りを
        /// 相手の切断と取り違えない）。
        #[test]
        fn d_h7_820_read_timeout_other_errors_are_internal_on_both_semantics() {
            for semantics in [true, false] {
                for e in [
                    io::Error::from_raw_os_error(TEST_EBADF),
                    io::Error::from(io::ErrorKind::InvalidInput),
                ] {
                    let label = format!("{e:?} semantics={semantics}");
                    let err = expect_read_fail(classify_read_timeout_error(e, semantics));
                    assert_eq!(err.code(), IoErrorCode::Internal, "{label}");
                }
            }
        }

        /// D・H7・#820: macOS の意味論では、書き込み経路の `EINVAL` は続行せず
        /// `Unavailable`（相手が閉じていれば書けないため）。
        #[test]
        fn d_h7_820_write_timeout_einval_is_unavailable_with_macos_semantics() {
            let err = map_write_timeout_error(io::Error::from_raw_os_error(TEST_EINVAL), true);
            assert_eq!(err.code(), IoErrorCode::Unavailable);
            assert_eq!(
                err.message(),
                format!(
                    "peer connection is unavailable: failed to set io timeout: {}",
                    io::Error::from_raw_os_error(TEST_EINVAL)
                )
            );
        }

        /// H7・#820: Linux の意味論では、書き込み経路の `EINVAL` も `Internal`。
        /// `EINVAL` 以外・std が合成した `InvalidInput` は両方の意味論で
        /// `Internal`。
        #[test]
        fn d_h7_820_write_timeout_other_cases_are_internal() {
            let err = map_write_timeout_error(io::Error::from_raw_os_error(TEST_EINVAL), false);
            assert_eq!(err.code(), IoErrorCode::Internal);
            for semantics in [true, false] {
                for e in [
                    io::Error::from_raw_os_error(TEST_EBADF),
                    io::Error::from(io::ErrorKind::InvalidInput),
                ] {
                    let label = format!("{e:?} semantics={semantics}");
                    let err = map_write_timeout_error(e, semantics);
                    assert_eq!(err.code(), IoErrorCode::Internal, "{label}");
                }
            }
        }

        fn expect_read_fail(action: ReadTimeoutAction) -> IoError {
            match action {
                ReadTimeoutAction::Fail(err) => err,
                ReadTimeoutAction::DrainWithoutTimeout => {
                    panic!("this case must fail instead of draining")
                }
            }
        }

        /// IO-1・REPAIR-5・#820: drain モード（macOS で相手の切断後に入る経路を
        /// Linux 上でも強制して確かめる）では、相手が close 前に送り切ったデータを
        /// ヘッダ・本体とも読み切り、尽きたところで `Unavailable` を返す。
        #[test]
        fn io1_repair5_820_drain_mode_reads_buffered_data_after_peer_close() {
            let (mut reader, mut writer) = UnixStream::pair().expect("socketpair");
            let header = patterned_bytes(10);
            let body = patterned_bytes(300);
            writer.write_all(&header).expect("writer must send header");
            writer.write_all(&body).expect("writer must send body");
            drop(writer);
            let deadline = Instant::now() + Duration::from_secs(5);

            let mut wait = ReadWait::new();
            wait.enter_drain(&reader)
                .expect("nonblocking switch must succeed");
            let mut got_header = [0u8; 10];
            let result = read_exact_with(
                &mut reader,
                &mut got_header,
                deadline,
                "frame header",
                &mut wait,
            );
            wait.finish(&reader, result)
                .expect("buffered header must be read in drain mode");
            assert_eq!(got_header.as_slice(), header.as_slice());

            let mut wait = ReadWait::new();
            wait.enter_drain(&reader)
                .expect("nonblocking switch must succeed");
            let result = read_body_with(&mut reader, body.len(), deadline, &mut wait);
            let got_body = wait
                .finish(&reader, result)
                .expect("buffered body must be read in drain mode");
            assert_eq!(got_body, body);
            assert_eq!(got_body.capacity(), body.len());

            let mut wait = ReadWait::new();
            wait.enter_drain(&reader)
                .expect("nonblocking switch must succeed");
            let mut one = [0u8; 1];
            let result =
                read_exact_with(&mut reader, &mut one, deadline, "frame header", &mut wait);
            let err = wait
                .finish(&reader, result)
                .expect_err("reading past the buffered data must fail");
            assert_eq!(err.code(), IoErrorCode::Unavailable);
            assert_eq!(
                err.message(),
                "peer closed the connection before sending a complete frame header"
            );
        }

        /// REPAIR-5・#820: drain モードの read はブロックしない。相手が生きていて
        /// データがない場合も、期限（5 秒）まで待たずに即座に `Unavailable` を
        /// 返す。その後 [`ReadWait::finish`] が blocking に戻すため、以後の read は
        /// 設定したタイムアウトまで待つ（nonblocking のまま残ると即座に返る）。
        #[test]
        fn repair5_820_drain_mode_never_blocks_and_finish_restores_blocking() {
            let (mut reader, writer) = UnixStream::pair().expect("socketpair");
            let deadline = Instant::now() + Duration::from_secs(5);

            let started = Instant::now();
            let mut wait = ReadWait::new();
            wait.enter_drain(&reader)
                .expect("nonblocking switch must succeed");
            let result = read_body_with(&mut reader, 4, deadline, &mut wait);
            let err = wait
                .finish(&reader, result)
                .expect_err("an empty receive buffer in drain mode must fail");
            assert_eq!(err.code(), IoErrorCode::Unavailable);
            assert_eq!(
                err.message(),
                "peer closed the connection before sending a complete frame body"
            );
            assert!(
                started.elapsed() < Duration::from_secs(1),
                "drain mode must not wait for the deadline: {:?}",
                started.elapsed()
            );

            const PROBE: Duration = Duration::from_millis(100);
            reader
                .set_read_timeout(Some(PROBE))
                .expect("set_read_timeout must succeed on a live connection");
            let probe_started = Instant::now();
            let mut buf = [0u8; 1];
            let probe = reader.read(&mut buf).expect_err("no data was sent");
            assert!(
                matches!(
                    probe.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ),
                "kind={:?}",
                probe.kind()
            );
            assert!(
                probe_started.elapsed() >= PROBE / 2,
                "the stream must be blocking again after finish: {:?}",
                probe_started.elapsed()
            );
            drop(writer);
        }

        /// REPAIR-5・#820: drain モードでも各 read の前の期限判定は行う
        /// （期限切れなら受信バッファにデータがあっても `Timeout`）。
        #[test]
        fn repair5_820_drain_mode_still_honors_the_deadline() {
            let (mut reader, mut writer) = UnixStream::pair().expect("socketpair");
            writer.write_all(&[1, 2, 3]).expect("writer must send");
            drop(writer);
            let deadline = Instant::now() - Duration::from_millis(1);

            let mut wait = ReadWait::new();
            wait.enter_drain(&reader)
                .expect("nonblocking switch must succeed");
            let mut buf = [0u8; 3];
            let result =
                read_exact_with(&mut reader, &mut buf, deadline, "frame header", &mut wait);
            let err = wait
                .finish(&reader, result)
                .expect_err("a past deadline must time out even in drain mode");
            assert_eq!(err.code(), IoErrorCode::Timeout);
        }

        /// [`BodyBuffer`] のテスト用の `Read` 実装。`source` を `pattern` の
        /// 大きさ（`Err` の場合はそのエラー）で順繰りに小出しに返す。
        struct TricklingReader {
            source: Vec<u8>,
            pos: usize,
            pattern: Vec<Result<usize, io::ErrorKind>>,
            step: usize,
        }

        impl TricklingReader {
            fn new(source: Vec<u8>, pattern: Vec<Result<usize, io::ErrorKind>>) -> Self {
                Self {
                    source,
                    pos: 0,
                    pattern,
                    step: 0,
                }
            }
        }

        impl Read for TricklingReader {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                let planned = self
                    .pattern
                    .get(self.step % self.pattern.len())
                    .copied()
                    .unwrap_or(Ok(1));
                self.step += 1;
                let want = match planned {
                    Ok(n) => n,
                    Err(kind) => return Err(io::Error::from(kind)),
                };
                let rest = &self.source[self.pos..];
                let n = want.min(buf.len()).min(rest.len());
                buf[..n].copy_from_slice(&rest[..n]);
                self.pos += n;
                Ok(n)
            }
        }

        /// 決定的な疑似データ（内容の取り違えを検出できるよう位置ごとに値を変える）。
        fn patterned_bytes(len: usize) -> Vec<u8> {
            (0..len).map(|i| (i % 251) as u8).collect()
        }

        /// REPAIR-2・#820（codex P0 指摘対応）: 本体長が `BODY_READ_CHUNK` の
        /// 3 倍 + 1 のフレームを、相手が奇数サイズで小出しに送ってきても、
        /// 各 read の後の容量は受理済みの `body_len` を超えず、読み終わりで
        /// 容量・長さとも `body_len` ちょうどになる。容量の推移は
        /// `BODY_READ_CHUNK` 刻みの `reserve_exact` だけで、償却つき成長
        /// （2 倍化）が起きないことを具体値の列で確かめる。
        #[test]
        fn repair2_820_body_buffer_capacity_never_exceeds_body_len_on_trickled_reads() {
            let body_len = BODY_READ_CHUNK * 3 + 1;
            let source = patterned_bytes(body_len);
            let mut reader =
                TricklingReader::new(source.clone(), vec![Ok(1), Ok(7), Ok(40_001), Ok(65_537)]);
            let mut body = BodyBuffer::new(body_len);
            assert_eq!(body.capacity(), BODY_READ_CHUNK);

            let mut capacities = vec![body.capacity()];
            let mut reads = 0usize;
            while !body.is_complete() {
                let got = body.read_once(&mut reader).expect("mock read must succeed");
                assert!(got > 0, "the mock never reports EOF before the end");
                reads += 1;
                assert!(
                    body.capacity() <= body_len,
                    "capacity {} exceeded body_len {body_len} after read #{reads}",
                    body.capacity()
                );
                assert!(body.filled() <= body.capacity());
                if capacities.last() != Some(&body.capacity()) {
                    capacities.push(body.capacity());
                }
            }

            assert_eq!(
                capacities,
                vec![
                    BODY_READ_CHUNK,
                    BODY_READ_CHUNK * 2,
                    BODY_READ_CHUNK * 3,
                    BODY_READ_CHUNK * 3 + 1,
                ]
            );
            assert_eq!(body.capacity(), body_len);
            let body = body.into_body().expect("a complete body must be returned");
            assert_eq!(body.len(), body_len);
            assert_eq!(body.capacity(), body_len);
            assert_eq!(body, source);
        }

        /// REPAIR-2・REPAIR-5・#820: 読み取りの途中で `WouldBlock`・`Interrupted`・
        /// `TimedOut` が挟まっても、ゼロ埋め済みの未受信領域を受信済みとして
        /// 数えず、最終的な内容が送信内容と一致する。
        #[test]
        fn repair2_repair5_820_body_buffer_ignores_zero_filled_region_on_transient_errors() {
            let body_len = BODY_READ_CHUNK + 3;
            let source = patterned_bytes(body_len);
            let mut reader = TricklingReader::new(
                source.clone(),
                vec![
                    Ok(5),
                    Err(io::ErrorKind::WouldBlock),
                    Ok(9_999),
                    Err(io::ErrorKind::Interrupted),
                    Err(io::ErrorKind::TimedOut),
                    Ok(3),
                ],
            );
            let mut body = BodyBuffer::new(body_len);
            let mut transient_errors = 0usize;
            while !body.is_complete() {
                let filled_before = body.filled();
                match body.read_once(&mut reader) {
                    Ok(got) => assert_eq!(body.filled(), filled_before + got),
                    Err(e) => {
                        assert!(matches!(
                            e.kind(),
                            io::ErrorKind::WouldBlock
                                | io::ErrorKind::Interrupted
                                | io::ErrorKind::TimedOut
                        ));
                        assert_eq!(body.filled(), filled_before);
                        transient_errors += 1;
                    }
                }
                assert!(body.capacity() <= body_len);
            }

            assert!(transient_errors >= 3);
            let body = body.into_body().expect("a complete body must be returned");
            assert_eq!(body.len(), body_len);
            assert_eq!(body.capacity(), body_len);
            assert_eq!(body, source);
        }

        /// REPAIR-2・#820: 未完了のバッファは本体として返さない（ゼロ埋めの
        /// 未受信領域を本体として扱わない）。
        #[test]
        fn repair2_820_body_buffer_into_body_rejects_incomplete_buffer() {
            let mut reader = TricklingReader::new(patterned_bytes(10), vec![Ok(4)]);
            let mut body = BodyBuffer::new(10);
            assert_eq!(body.read_once(&mut reader).expect("mock read"), 4);
            let err = body
                .into_body()
                .expect_err("incomplete body must be rejected");
            assert_eq!(err.code(), IoErrorCode::Internal);
        }

        /// REPAIR-2・#820: 本体長 0（`admit` はペイロード長 0 を受理しうるが、
        /// 本体にはチェックサムが付くため実際には呼ばれない想定）でも確保せず
        /// 空の本体を返す。
        #[test]
        fn repair2_820_body_buffer_zero_length_allocates_nothing() {
            let body = BodyBuffer::new(0);
            assert!(body.is_complete());
            assert_eq!(body.capacity(), 0);
            let body = body.into_body().expect("empty body must be returned");
            assert_eq!(body.len(), 0);
            assert_eq!(body.capacity(), 0);
        }

        /// REPAIR-2・REPAIR-5・#820（codex P0 指摘対応）: 実際の UDS ソケット
        /// 越しに相手が奇数サイズで小出しに送っても、`read_body_until` が返す
        /// 本体は長さ・容量とも `body_len` ちょうどで、内容が一致する。
        #[test]
        fn repair2_repair5_820_read_body_until_returns_exact_capacity_over_socket() {
            let body_len = BODY_READ_CHUNK * 3 + 1;
            let source = patterned_bytes(body_len);
            let (mut reader, mut writer) = UnixStream::pair().expect("socketpair");
            let to_send = source.clone();
            let sender = std::thread::spawn(move || {
                let sizes = [1usize, 7, 40_001, 3, 65_537];
                let mut pos = 0usize;
                let mut i = 0usize;
                while pos < to_send.len() {
                    let n = sizes[i % sizes.len()].min(to_send.len() - pos);
                    writer
                        .write_all(&to_send[pos..pos + n])
                        .expect("writer must be able to send");
                    pos += n;
                    i += 1;
                }
            });

            let deadline = Instant::now() + Duration::from_secs(10);
            let body = read_body_until(&mut reader, body_len, deadline)
                .expect("the full body must be received before the deadline");
            sender.join().expect("sender thread must not panic");

            assert_eq!(body.len(), body_len);
            assert_eq!(body.capacity(), body_len);
            assert_eq!(body, source);
        }

        /// REPAIR-2・IO-1・#820（codex P0 指摘対応）: 受信経路の本体読み込み
        /// （`read_body_until`）→ 受理済みヘッダでの復号（`decode_body_owned`）を
        /// 通しても、ペイロードは読み込んだ本体と同じ領域（ポインタ一致）・同じ
        /// 容量（`body_len`）のままで、1 フレームあたりの申告長に比例する確保は
        /// `body_len` ぶんの 1 回だけになる。
        #[test]
        fn repair2_io1_820_recv_path_decodes_without_copying_the_payload() {
            let payload = patterned_bytes(BODY_READ_CHUNK * 2 + 7);
            let frame = Frame::new(FrameKind::Write, payload.clone()).expect("Frame::new");
            let encoded = frame.encode();
            let (header_bytes, wire_body) = encoded
                .split_first_chunk::<FRAME_HEADER_LEN>()
                .expect("encoded frame must have a header");
            let header = FrameHeader::from_bytes(*header_bytes).expect("header must decode");
            let admitted = ReceiveLimits::default()
                .admit(header, 0)
                .expect("the default limits must admit this frame");
            let body_len = admitted.body_len();
            assert_eq!(body_len, payload.len() + 4);

            let (mut reader, mut writer) = UnixStream::pair().expect("socketpair");
            let to_send = wire_body.to_vec();
            let sender = std::thread::spawn(move || {
                for chunk in to_send.chunks(40_001) {
                    writer
                        .write_all(chunk)
                        .expect("writer must be able to send");
                }
            });
            let deadline = Instant::now() + Duration::from_secs(10);
            let body = read_body_until(&mut reader, body_len, deadline)
                .expect("the full body must be received before the deadline");
            sender.join().expect("sender thread must not panic");
            let body_ptr = body.as_ptr();
            assert_eq!(body.capacity(), body_len);

            let decoded = admitted
                .decode_body_owned(body)
                .expect("a valid frame must decode");
            let out = decoded.into_payload();
            assert_eq!(out.as_ptr(), body_ptr);
            assert_eq!(out.capacity(), body_len);
            assert_eq!(out.len(), payload.len());
            assert_eq!(out, payload);
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

        /// #1115 codex レビュー指摘対応（macOS CI 実バグ修正）:
        /// 残り時間が [`MIN_REMAINING_TIMEOUT`] 未満（`timeval` 精度未満）なら、
        /// 期限をまだ過ぎていなくても `Timeout` を返す。`set_write_timeout` へ
        /// 渡した際に `timeval` 変換で実質ゼロへ丸まり、macOS で `EINVAL`
        /// （`is_peer_shutdown_einval` に誤って「相手の切断」と判定される）を
        /// 引き起こす経路を、値を渡す前に断つ
        /// （`repair5_uds_send_times_out_on_unresponsive_peer` の macOS CI 再現
        /// 失敗の根本原因）。
        #[test]
        fn repair5_remaining_or_timeout_returns_timeout_below_min_granularity() {
            let deadline = Instant::now() + Duration::from_nanos(100);
            let err = remaining_or_timeout(deadline)
                .expect_err("sub-microsecond remaining time must be treated as timed out");
            assert_eq!(err.code(), IoErrorCode::Timeout);
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

        /// I1・#820（security-auditor 再監査指摘対応。PLUG-12）: 親ディレクトリの
        /// 所有者と実効 uid が一致しない場合、`validate_parent_dir` は bind より
        /// 前の段階で `InvalidArgument` を返し、ソケットファイルを作らない。
        /// 別ユーザー所有のディレクトリは root がないと用意できないため、実在の
        /// 自分所有のディレクトリに対して「実効 uid」側を自分の uid と異なる値に
        /// して呼ぶ。
        #[test]
        fn i1_validate_parent_dir_rejects_owner_mismatch_before_bind() {
            let dir = super::super::test_support::TempSocketDir::new();
            let path = dir.socket_path();
            let other_uid = crate::sys::effective_uid().wrapping_add(1);

            let err = validate_parent_dir(&path, other_uid)
                .expect_err("an owner mismatch must be rejected before bind");

            assert_eq!(err.code(), IoErrorCode::InvalidArgument);
            assert!(
                err.message()
                    .contains(&format!("(effective uid {other_uid})")),
                "message={}",
                err.message()
            );
            assert_eq!(
                fs::symlink_metadata(&path).map_err(|e| e.kind()).err(),
                Some(io::ErrorKind::NotFound),
                "no socket file may be created when the owner check fails"
            );
        }

        /// I4 のテストで観測イベントを owned な要約として記録する観測フック
        /// （`ServerEvent` は `on_event` の間だけ有効な借用を含むため、比較に
        /// 必要なフィールドだけを写し取る）。
        #[derive(Default)]
        struct RecordingObserver {
            events: Vec<RecordedEvent>,
        }

        #[derive(Debug, Clone, PartialEq, Eq)]
        struct RecordedEvent {
            op: ServerOp,
            outcome: ServerOutcome,
            accept_aborted_retries: u32,
            peer_credential_rejections: u32,
            peer_uid: Option<u32>,
            code: Option<IoErrorCode>,
        }

        impl crate::observe::ServerObserver for RecordingObserver {
            fn on_event(&mut self, event: &ServerEvent<'_>) {
                self.events.push(RecordedEvent {
                    op: event.op,
                    outcome: event.outcome,
                    accept_aborted_retries: event.accept_aborted_retries,
                    peer_credential_rejections: event.peer_credential_rejections,
                    peer_uid: event.peer_uid,
                    code: event.error.as_ref().map(|e| e.code),
                });
            }
        }

        /// I4 のテストで差し替える照合が返す拒否（本番の
        /// [`verify_peer_credential`] が uid 不一致で返すものと同じ形）。
        fn injected_rejection(peer_uid: u32, expected_uid: u32) -> PeerCredentialRejection {
            PeerCredentialRejection {
                peer_uid: Some(peer_uid),
                error: IoError::new(
                    IoErrorCode::InvalidArgument,
                    format!(
                        "connecting peer uid ({peer_uid}) does not match the server's \
                         effective uid at bind time ({expected_uid})"
                    ),
                ),
            }
        }

        /// accept 前に `count` 本の接続を listen キューへ積んでおく（backlog は
        /// 33 本より十分大きい）。拒否された接続が accept 前に閉じられると
        /// `ConnectionAborted` として別のカウンタへ乗ってしまうため、返した
        /// `UnixStream` はテストの最後まで保持する。
        ///
        /// 読み取りタイムアウトは connect の直後（サーバーがまだ接続を閉じて
        /// いない間）に設定しておく。macOS の `setsockopt(SO_RCVTIMEO)` は、相手が
        /// 切断済みのソケットに対しては `EINVAL` を返すため（本番側は
        /// `classify_read_timeout_error`・`map_write_timeout_error` で扱う
        /// 挙動）、サーバーが拒否した接続を閉じた後に設定すると失敗する（J1・
        /// #820 PR #1113 の macOS CI 失敗の修正）。
        fn connect_clients(path: &Path, count: usize) -> Vec<UnixStream> {
            (0..count)
                .map(|_| {
                    let client = UnixStream::connect(path).expect("client must be able to connect");
                    client
                        .set_read_timeout(Some(Duration::from_secs(5)))
                        .expect("set_read_timeout must succeed while the connection is open");
                    client
                })
                .collect()
        }

        fn injection_test_timeout() -> IoTimeout {
            IoTimeout::new(Duration::from_secs(5)).expect("5s must be a valid IoTimeout")
        }

        /// I4・#820（security-auditor 再監査指摘対応。SEC-4・PLUG-12）: peer
        /// credential 照合を差し替えて 3 回拒否させたあと、4 回目は本番の
        /// [`verify_peer_credential`]（同一 uid の接続なので受理）に通す。
        /// 拒否 1 件ごとに `RejectedPeerCredential` が通知され、件数が 1, 2, 3 と
        /// 単調に増え、最後の Accept 成功イベントの件数が 3 と一致する。拒否した
        /// 接続はすぐに閉じられ、クライアント側は EOF を読む。
        #[test]
        fn i4_sec4_plug12_accept_notifies_each_rejection_then_succeeds() {
            const REJECTIONS: u32 = 3;
            let dir = super::super::test_support::TempSocketDir::new();
            let path = dir.socket_path();
            let mut server = super::super::UdsServer::bind(
                &path,
                ReceiveLimits::default(),
                RecordingObserver::default(),
            )
            .expect("bind must succeed in a 0700 directory owned by the test user");
            let expected_uid = crate::sys::effective_uid();
            let fake_peer_uid = expected_uid.wrapping_add(1);
            let mut clients = connect_clients(&path, REJECTIONS as usize + 1);

            let mut calls = 0u32;
            let mut verify = |stream: &UnixStream, bind_uid: u32| {
                calls += 1;
                // 差し替えた照合にも bind 時点の実効 uid が渡る（I2）。
                assert_eq!(bind_uid, expected_uid);
                if calls <= REJECTIONS {
                    Err(injected_rejection(fake_peer_uid, bind_uid))
                } else {
                    verify_peer_credential(stream, bind_uid)
                }
            };
            let conn = server
                .accept_via(crate::observe::NoopServerObserver, |inner, on_event| {
                    inner.accept_with(injection_test_timeout(), on_event, &mut verify)
                })
                .expect("the 4th connection from the same uid must be accepted");
            drop(conn);
            assert_eq!(calls, REJECTIONS + 1);

            let rejection = |n: u32| RecordedEvent {
                op: ServerOp::Accept,
                outcome: ServerOutcome::RejectedPeerCredential,
                accept_aborted_retries: 0,
                peer_credential_rejections: n,
                peer_uid: Some(fake_peer_uid),
                code: Some(IoErrorCode::InvalidArgument),
            };
            assert_eq!(
                server.observer().events,
                vec![
                    rejection(1),
                    rejection(2),
                    rejection(3),
                    RecordedEvent {
                        op: ServerOp::Accept,
                        outcome: ServerOutcome::Success,
                        accept_aborted_retries: 0,
                        peer_credential_rejections: REJECTIONS,
                        peer_uid: None,
                        code: None,
                    },
                ]
            );

            // 拒否した 3 本はサーバー側で閉じられている（EOF を読む）。読み取り
            // タイムアウトは `connect_clients` が接続中に設定済み（J1）。
            for client in clients.iter_mut().take(REJECTIONS as usize) {
                let mut buf = [0u8; 1];
                let n = client
                    .read(&mut buf)
                    .expect("a rejected connection must be closed, not left hanging");
                assert_eq!(n, 0);
            }
        }

        /// I4・#820（security-auditor 再監査指摘対応。SEC-4・PLUG-12・H4）: 照合を
        /// 常に拒否へ差し替えると、`MAX_ACCEPT_ABORT_RETRIES` を超えた
        /// （`MAX_ACCEPT_ABORT_RETRIES + 1` 件目の）拒否で `Unavailable` を返す。
        /// 拒否の通知は `MAX_ACCEPT_ABORT_RETRIES + 1` 回（件数 1 から順に単調
        /// 増加）で、最後の Accept 失敗イベントは同じ件数と `Unavailable` を載せる。
        #[test]
        fn i4_sec4_plug12_accept_returns_unavailable_after_rejection_limit() {
            let limit_plus_one = MAX_ACCEPT_ABORT_RETRIES + 1;
            let dir = super::super::test_support::TempSocketDir::new();
            let path = dir.socket_path();
            let mut server = super::super::UdsServer::bind(
                &path,
                ReceiveLimits::default(),
                RecordingObserver::default(),
            )
            .expect("bind must succeed in a 0700 directory owned by the test user");
            let expected_uid = crate::sys::effective_uid();
            let fake_peer_uid = expected_uid.wrapping_add(1);
            let _clients = connect_clients(&path, limit_plus_one as usize);

            let mut calls = 0u32;
            let mut verify = |_stream: &UnixStream, bind_uid: u32| {
                calls += 1;
                Err(injected_rejection(fake_peer_uid, bind_uid))
            };
            let err = server
                .accept_via(crate::observe::NoopServerObserver, |inner, on_event| {
                    inner.accept_with(injection_test_timeout(), on_event, &mut verify)
                })
                .expect_err("exceeding the rejection limit must fail the accept");
            assert_eq!(err.code(), IoErrorCode::Unavailable);
            assert_eq!(calls, limit_plus_one);

            let mut expected: Vec<RecordedEvent> = (1..=limit_plus_one)
                .map(|n| RecordedEvent {
                    op: ServerOp::Accept,
                    outcome: ServerOutcome::RejectedPeerCredential,
                    accept_aborted_retries: 0,
                    peer_credential_rejections: n,
                    peer_uid: Some(fake_peer_uid),
                    code: Some(IoErrorCode::InvalidArgument),
                })
                .collect();
            expected.push(RecordedEvent {
                op: ServerOp::Accept,
                outcome: ServerOutcome::Failure,
                accept_aborted_retries: 0,
                peer_credential_rejections: limit_plus_one,
                peer_uid: None,
                code: Some(IoErrorCode::Unavailable),
            });
            assert_eq!(server.observer().events, expected);
        }

        /// K1・REPAIR-5・#820（codex P1 指摘対応）: accept と peer credential 照合が
        /// 成功しても、その間に期限を過ぎていれば接続を返さず `Timeout` を返す。
        /// 差し替えた照合の中で timeout（50ms）の 4 倍眠ってから本番の
        /// [`verify_peer_credential`]（同一 uid なので受理）に通す。最終イベントは
        /// Accept の Failure・`Timeout`（件数はいずれも 0）の 1 件だけで、渡さなかった
        /// 接続はサーバー側で閉じられクライアント側は EOF を読む。
        #[test]
        fn k1_repair5_accept_returns_timeout_when_deadline_passes_after_success() {
            const TIMEOUT: Duration = Duration::from_millis(50);
            let dir = super::super::test_support::TempSocketDir::new();
            let path = dir.socket_path();
            let mut server = super::super::UdsServer::bind(
                &path,
                ReceiveLimits::default(),
                RecordingObserver::default(),
            )
            .expect("bind must succeed in a 0700 directory owned by the test user");
            // 読み取りタイムアウトは `connect_clients` が接続中に設定する（J1。
            // macOS は相手が閉じた後の `set_read_timeout` で EINVAL を返す）。
            let mut clients = connect_clients(&path, 1);

            let mut calls = 0u32;
            let mut verify = |stream: &UnixStream, bind_uid: u32| {
                calls += 1;
                std::thread::sleep(TIMEOUT * 4);
                verify_peer_credential(stream, bind_uid)
            };
            let err = server
                .accept_via(crate::observe::NoopServerObserver, |inner, on_event| {
                    inner.accept_with(
                        IoTimeout::new(TIMEOUT).expect("50ms must be a valid IoTimeout"),
                        on_event,
                        &mut verify,
                    )
                })
                .expect_err("a connection verified after the deadline must not be returned");
            assert_eq!(err.code(), IoErrorCode::Timeout);
            assert_eq!(
                err.message(),
                "accept timed out waiting for a client connection"
            );
            assert_eq!(calls, 1);
            assert_eq!(
                server.observer().events,
                vec![RecordedEvent {
                    op: ServerOp::Accept,
                    outcome: ServerOutcome::Failure,
                    accept_aborted_retries: 0,
                    peer_credential_rejections: 0,
                    peer_uid: None,
                    code: Some(IoErrorCode::Timeout),
                }]
            );

            let client = clients
                .first_mut()
                .expect("connect_clients must return one client");
            let mut buf = [0u8; 1];
            let n = client
                .read(&mut buf)
                .expect("a connection dropped after the deadline must be closed, not left hanging");
            assert_eq!(n, 0);
        }

        /// I1・#820（PLUG-12）: 実効 uid が親ディレクトリの所有者と一致すれば
        /// `validate_parent_dir` は受理する（自分所有の `0700` ディレクトリ）。
        #[test]
        fn i1_validate_parent_dir_accepts_matching_owner() {
            let dir = super::super::test_support::TempSocketDir::new();
            validate_parent_dir(&dir.socket_path(), crate::sys::effective_uid())
                .expect("a 0700 directory owned by the effective uid must be accepted");
        }

        /// J3・#820（codex P1 指摘対応。PLUG-12）: bind 直後のパスがソケットで
        /// なければ（別物に差し替わっていた場合に相当）、`SocketFileIdentity::capture`
        /// は `InvalidArgument` を返し、パス上のファイルには触れない。
        #[test]
        fn j3_plug12_capture_rejects_non_socket_and_keeps_the_file() {
            let dir = super::super::test_support::TempSocketDir::new();
            let path = dir.socket_path();
            fs::write(&path, b"not a socket").expect("must be able to create a regular file");

            let err = SocketFileIdentity::capture(&path, crate::sys::effective_uid())
                .expect_err("a regular file must not be recorded as our socket");

            assert_eq!(err.code(), IoErrorCode::InvalidArgument);
            assert_eq!(
                fs::read(&path).expect("the regular file must remain"),
                b"not a socket".to_vec()
            );
        }

        /// J3・#820（PLUG-12）: bind 直後のソケットの所有者 uid が bind 時点の
        /// 実効 uid と異なれば、`SocketFileIdentity::capture` は `InvalidArgument`
        /// を返し、ソケットファイルは削除しない。別 uid 所有のソケットは root が
        /// ないと用意できないため、「実効 uid」側を自分の uid と異なる値にして呼ぶ。
        #[test]
        fn j3_plug12_capture_rejects_owner_mismatch_and_keeps_the_socket() {
            let dir = super::super::test_support::TempSocketDir::new();
            let path = dir.socket_path();
            let _listener = UnixListener::bind(&path).expect("bind must succeed");
            let other_uid = crate::sys::effective_uid().wrapping_add(1);

            let err = SocketFileIdentity::capture(&path, other_uid)
                .expect_err("a socket owned by another uid must not be recorded as ours");

            assert_eq!(err.code(), IoErrorCode::InvalidArgument);
            let own_uid = crate::sys::effective_uid();
            assert_eq!(
                err.message(),
                format!(
                    "the socket file created by bind is owned by uid {own_uid} but the \
                     server's effective uid is {other_uid}"
                )
            );
            assert!(
                fs::symlink_metadata(&path)
                    .expect("the socket must remain")
                    .file_type()
                    .is_socket()
            );
        }

        /// J3・#820（PLUG-12）: bind 直後にパスが消えていれば（stat 自体の失敗）
        /// `SocketFileIdentity::capture` は `Internal` を返す。
        #[test]
        fn j3_plug12_capture_reports_missing_path_as_internal() {
            let dir = super::super::test_support::TempSocketDir::new();

            let err = SocketFileIdentity::capture(&dir.socket_path(), crate::sys::effective_uid())
                .expect_err("a missing path must not be recorded");

            assert_eq!(err.code(), IoErrorCode::Internal);
        }

        /// J3・#820（codex P1 指摘対応。PLUG-12）: `cleanup_socket_file` は、
        /// 記録した実体と `(dev, ino)` または所有者 uid が 1 つでも異なるソケットは
        /// 削除せず、すべて一致する場合だけ削除する。元のパスを unlink して別の
        /// listener が同じパスへ bind した状況を実際のソケットで作る。
        #[test]
        fn j3_plug12_cleanup_socket_file_removes_only_the_recorded_socket() {
            let dir = super::super::test_support::TempSocketDir::new();
            let path = dir.socket_path();
            let euid = crate::sys::effective_uid();

            let old_listener = UnixListener::bind(&path).expect("first bind must succeed");
            let old = SocketFileIdentity::capture(&path, euid).expect("must record the socket");
            fs::remove_file(&path).expect("must be able to unlink the first socket");
            let _new_listener = UnixListener::bind(&path).expect("second bind must succeed");
            drop(old_listener);
            let new = SocketFileIdentity::capture(&path, euid).expect("must record the socket");
            assert_ne!(
                (old.dev, old.ino),
                (new.dev, new.ino),
                "the filesystem reused the inode, so the two sockets cannot be told apart"
            );

            // (dev, ino) が異なる: 後から bind された別の listener のソケットは消さない。
            cleanup_socket_file(&path, &old);
            assert_eq!(
                SocketFileIdentity::capture(&path, euid).expect("the new socket must remain"),
                new
            );

            // (dev, ino) は同じでも所有者 uid が異なる記録とは一致しない。
            let other_owner = SocketFileIdentity {
                uid: euid.wrapping_add(1),
                ..new
            };
            cleanup_socket_file(&path, &other_owner);
            assert_eq!(
                SocketFileIdentity::capture(&path, euid).expect("the new socket must remain"),
                new
            );

            // すべて一致すれば削除する。
            cleanup_socket_file(&path, &new);
            assert_eq!(
                fs::symlink_metadata(&path).map_err(|e| e.kind()).err(),
                Some(io::ErrorKind::NotFound)
            );
        }

        /// J3・#820（PLUG-12）: 記録したソケットのパスが通常ファイルに差し替わって
        /// いれば、`cleanup_socket_file` は削除しない。
        #[test]
        fn j3_plug12_cleanup_socket_file_keeps_a_replaced_regular_file() {
            let dir = super::super::test_support::TempSocketDir::new();
            let path = dir.socket_path();
            let listener = UnixListener::bind(&path).expect("bind must succeed");
            let recorded = SocketFileIdentity::capture(&path, crate::sys::effective_uid())
                .expect("must record the socket");
            drop(listener);
            fs::remove_file(&path).expect("must be able to unlink the socket");
            fs::write(&path, b"replaced").expect("must be able to create a regular file");

            cleanup_socket_file(&path, &recorded);

            assert_eq!(
                fs::read(&path).expect("the replaced file must remain"),
                b"replaced".to_vec()
            );
        }
    }
}

/// `imp` 層・`UdsServer` の単体テストが共有する一時ディレクトリ
/// （`crates/io/tests/server.rs` の `TempSocketDir` と同じ手順。テスト専用）。
#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod test_support {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// テストごとに固有かつ短い `0700` のディレクトリを作り、`Drop` で削除する。
    /// macOS の sun_path 上限（104 バイト）に近づかないよう名前を短く保ち、
    /// umask の影響を受けないよう作成直後に `set_permissions` でモードを確定させる。
    pub(super) struct TempSocketDir {
        path: PathBuf,
    }

    impl TempSocketDir {
        pub(super) fn new() -> Self {
            static COUNTER: AtomicU32 = AtomicU32::new(0);
            let n = COUNTER.fetch_add(1, Ordering::Relaxed);
            let pid = std::process::id();
            let dir = std::env::temp_dir().join(format!("fcu-{pid}-{n}"));
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&dir)
                .expect("must be able to create a temp dir for the socket");
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
                .expect("must be able to force the directory mode regardless of umask");
            Self { path: dir }
        }

        pub(super) fn socket_path(&self) -> PathBuf {
            self.path.join("s.sock")
        }
    }

    impl Drop for TempSocketDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
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
