//! バッチ write-back の実行と、サーバー側 ACK 返却（TASK-13.2.2・IO-1・#822）。
//!
//! [`crate::batch::BatchBuffer`]（TASK-13.1）がメモリ内で集約した
//! [`crate::batch::Batch`] を実際にディスクへ書き込み、書き込み完了後に
//! [`crate::protocol::FrameKind::Ack`] フレームを返すところまでをつなぐ。
//! [`crate::server::UdsConnection`]（TASK-13.2.1・#820）のようなトランスポート
//! 1 本（[`crate::transport::FrameSender`] + [`crate::transport::FrameReceiver`]）を
//! 受け取り、そのトランスポート固有のコードには依存しない（generic）ため、
//! 偽トランスポートによる単体テストと、実際の UDS を使った結合試験の両方から
//! 検証できる。
//!
//! # ACK の意味論（受入基準 2・3。IO-1 と IO-2 の区別）
//!
//! [`serve_connection`] が返す通常 ACK（[`FrameKind::Ack`]）は、**そのバッチの
//! 全フレームについて [`BatchSink::write_batch`] が `Ok` を返した時点**（＝OS の
//! ページキャッシュへの `write()` 発行が完了した時点）で送る。`fsync(2)` /
//! `syncfs(2)` 等の永続化は待たない。プロセスが正常に動いている限りこの時点の
//! データは他の reader から見えるが、プロセスクラッシュや電源断では失われうる。
//! これは IO-1 が言う「バッファリング時点で ACK」の、本実装における対応物である。
//!
//! 永続化完了を保証するのは IO-2 の FLUSH ACK（[`FrameKind::FlushAck`]）のみで
//! あり、`Flush` 受信時に [`BatchSink::persist`] の成功を待ってから送る
//! （下記「FLUSH フレームの扱い」節。TASK-15.2.2・#824）。ACK の
//! API としての文書化（利用者向けの説明）は TASK-17 で行う。
//!
//! # 書き込み先（ワイヤーにパスがない。D1）
//!
//! [`crate::payload`]（TASK-12.2）が定めるワイヤー形式は `[request_id][body]`
//! のみでパス・オフセットを持たないため、本モジュールはファイル命名規則を
//! 独自に作らない。代わりに書き込み先を [`BatchSink`] トレイトとして抽象化し、
//! 呼び出し側が開いた [`std::fs::File`] へ不透明な `body` を到着順に追記する
//! だけの実装（[`AppendFileSink`]）を提供する。サーバーはワイヤーからパスを
//! 一切受け取らず解決もしないため、パストラバーサル・symlink 経由の書き込み
//! 経路は構造上生まれない（security.md）。
//!
//! `body` を不透明なバイト列として追記するのはスタブの意味論であり
//! （REPAIR-3）、ファイル操作（パス・rename・truncate 等。TASK-14 の整合性
//! スイートが要する）をペイロードで表す形式は、今後のプロトコル拡張
//! （IO-1 の I/O 契約変更。`PROTOCOL_VERSION` の繰り上げを伴いうる）として
//! 別途扱う。
//!
//! パスを持つ作成の入口は [`crate::guest_files::GuestFileCreator`]（TASK-19.2・
//! IO-5・#100）で、サーバー側 API が大文字小文字衝突を検査したうえでファイルを
//! 作り、[`AppendFileSink`] を返す。ワイヤーは引き続きパスを持たない。
//!
//! # FLUSH フレームの扱い（IO-2・TASK-15.2.2・#824。FlushAck は偽装しない）
//!
//! [`FrameKind::Flush`] を受信すると、まず [`decode_request`] で形式
//! （request id がちょうど 8 バイト・body が空）を検証する（Codex #822
//! レビュー指摘。`Write` と同じ検証を経ないまま `take_pending` へ進むと、
//! request id 欠如や余分な body を持つ不正な Flush までバリアとして働き、
//! クライアントが ACK していない保留分を誤って確定させてしまうため）。
//! 検証を通ったら [`crate::batch::BatchBuffer::take_pending`] で件数未達の
//! まま滞留していた分を取り出して書き込み、通常 ACK を返した後、
//! [`BatchSink::persist`]（Linux の [`AppendFileSink`] は `syncfs(2)`）で
//! 永続化し、**成功したときだけ** [`FrameKind::FlushAck`] を送ってループを
//! 継続する。`persist` が失敗・タイムアウト・未対応（既定実装・Linux 5.8 未満・
//! 非 Linux は [`crate::error::IoErrorCode::Unimplemented`]。判定は
//! [`crate::barrier::persist_support`]）のときは FlushAck を送らず、
//! そのエラーで処理を終える（fail-closed。プロトコルにエラーフレームはなく、
//! クライアントは EOF を `Unavailable` として観測する）。
//!
//! # バッチが件数未達のまま残る場合の発火条件（D3。運用制約）
//!
//! ACK をバッチ書き込みの後に返すため、クライアントが `batch_size` 未満だけ
//! 送って ACK を待つと、サーバー側に発火のきっかけがない。本実装で使える
//! 発火条件は [`crate::batch::BatchTrigger::SizeReached`]・
//! [`crate::batch::BatchTrigger::BytesLimitReached`]・[`FrameKind::Flush`] の
//! 3 つのみ（時間ベースの追い出しは範囲外。IO-10・TASK-16）。呼び出し側は
//! 「クライアントの in-flight 上限 ≥ `batch_size`、または件数未達分の後に
//! `Flush` を送ること」を運用上の前提とする（既定値 64 / 64 で整合）。
//!
//! # ACK していない保留分の扱い（D5。接続断・エラー時は破棄）
//!
//! 受信エラー（EOF を含む）・プロトコル違反・sink の失敗で処理を終えるとき、
//! [`crate::batch::BatchBuffer`] に残った保留分は**書き込まずに破棄**する
//! （[`WritebackStats::discarded_pending_frames`] に件数を残す）。ACK を返して
//! いない以上クライアントはそれらを前提にできず、書いてしまうと再送時に
//! 重複を生むため（P1-3 の fail-closed と一貫する）。
//!
//! # sink の失敗（D6）
//!
//! [`BatchSink::write_batch`] が `Err` を返すと、そのバッチのフレームには
//! ACK を 1 件も返さずに処理を終える。バッチの途中まで書き込まれた可能性が
//! ある（部分書き込み）ため、ACK 前の書き込みは「書かれたかどうか不定」と
//! いう意味論になる。
//!
//! # 受信上限（D9。`pending_frames` に `0` を渡す根拠）
//!
//! 本モジュールの write-back は同期的（`Ready` になったバッチをその場で
//! 書き込み・ACK まで終えてから次のフレームを受信する）であり、受信時点で
//! 「排出済みだが未書き込み」のキューは常に空になる。また
//! `BatchBuffer::len() < batch_size ≤ max_pending_frames`（`ReceiveLimits::for_batch`
//! 由来の場合）も常に成り立つ。したがって [`crate::recv_limits::ReceiveLimits::admit`]
//! へ渡す `pending_frames` は常に `0` で構造上正確であり（[`crate::server`]・
//! [`crate::recv_limits`] も同じ不変条件を前提とする）、本モジュールが独自に
//! 別の値を計算する必要はない。write-back を非同期化する場合はこの前提を
//! 見直す必要がある。
//!
//! # 呼び出し文脈
//!
//! [`crate::server::UdsConnection`]（TASK-13.2.1・#820）のような
//! `FrameSender<Frame = Frame> + FrameReceiver<Frame = Frame>` を実装する
//! 1 接続分のトランスポートを受け取り、[`serve_connection`] が受信ループを
//! 回す。受付ループ（accept → serve_connection → 次の accept）・同時接続数の
//! 上限・クライアント側 UDS 接続との本番結合は本モジュールの範囲外で、
//! 別 sub-issue（要起票。`server.rs` モジュール doc 参照）が担う。

use std::fs::File;
use std::io::{self, Seek as _, SeekFrom, Write as _};
use std::path::Path;

use crate::batch::{Batch, BatchBuffer, BatchConfig, PushOutcome};
use crate::error::{IoError, IoErrorCode};
use crate::payload::{decode_request, encode_ack};
use crate::protocol::{Frame, FrameKind};
use crate::transport::{FrameReceiver, FrameSender, IoTimeout, MAX_IO_TIMEOUT};
use std::time::Duration;

/// [`BatchSink::write_batch`] が書き込んだ内容の要約（REPAIR-4: 可観測性）。
///
/// `#[non_exhaustive]` により、将来のフィールド追加に備える。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct SinkWriteReport {
    /// このバッチで書き込んだフレーム件数。
    pub frames_written: usize,
    /// このバッチで書き込んだ body の合計バイト数。
    pub bytes_written: u64,
}

impl SinkWriteReport {
    /// `frames_written`・`bytes_written` から [`SinkWriteReport`] を作る。
    ///
    /// `#[non_exhaustive]` によりフィールドが `pub` でも構造体リテラルでは
    /// crate 外から組み立てられないため、[`BatchSink`] を crate 外で実装する
    /// 側（公開拡張点。coding-rust「crate 境界」参照）が `write_batch` の
    /// 戻り値を作るための唯一の入口として用意する。
    pub fn new(frames_written: usize, bytes_written: u64) -> Self {
        Self {
            frames_written,
            bytes_written,
        }
    }
}

/// バッチをディスク（または他の永続先）へ書き込む抽象（D1）。
///
/// [`serve_connection`] は `Batch` の中身をワイヤーの request id しか知らない
/// 不透明なバイト列として扱い、書き込み先の解決（パス・ファイル種別）は
/// 本トレイトの実装側の責務とする。
///
/// # 契約
/// - `write_batch` はバッチ内の全フレームの書き込みが完了してから `Ok` を返す
///   （部分成功を `Ok` として返さない。呼び出し元〔[`serve_connection`]〕は
///   `Ok` を「バッチ全体が書けた」の意味で ACK 送出の合図に使う）
/// - `Err` を返した場合、呼び出し元はそのバッチのフレームへ ACK を送らない
///   （D6）。バッチの途中まで書き込まれている可能性がある（部分書き込み）
pub trait BatchSink {
    /// バッチ内の各 [`FrameKind::Write`] フレームの body を、挿入順に書き込む。
    fn write_batch(&mut self, batch: &Batch) -> Result<SinkWriteReport, IoError>;

    /// これまでに `write_batch` が `Ok` を返した書き込みをすべて永続化する
    /// （FLUSH バリア用。IO-2・TASK-15.2.2・#824）。
    ///
    /// [`serve_connection`] が `Flush` 受信時に、滞留分の書き込みと通常 ACK の
    /// 後に呼び、`Ok` のときだけ [`FrameKind::FlushAck`] を送る。
    ///
    /// # 契約
    /// - `Ok` を返してよいのは、本呼び出し前に `write_batch` が `Ok` を返した
    ///   書き込みがすべて永続化済みのときだけ
    /// - 1 回の呼び出しで永続化の syscall は 1 回だけ発行し、失敗しても
    ///   再試行しない
    /// - 保証の対象は `write_batch` 経由で受理した書き込み（IO-2 の「バリア以前に
    ///   受理した書き込み」）に限る。sink の外（呼び出し側が保持する別の `File`
    ///   ハンドル・別プロセス）からの変更は対象外
    ///
    /// 既定実装は [`IoErrorCode::Unimplemented`] を返す（fail-closed。永続化を
    /// 実装しない sink は FlushAck を出せない）。
    fn persist(&mut self) -> Result<SinkPersistReport, IoError> {
        Err(IoError::new(
            IoErrorCode::Unimplemented,
            "this sink does not implement persist (IO-2)",
        ))
    }
}

/// [`BatchSink::persist`] の結果の要約（REPAIR-4: 可観測性）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct SinkPersistReport {
    /// 永続化に要した時間。
    pub elapsed: Duration,
}

impl SinkPersistReport {
    /// `elapsed` から [`SinkPersistReport`] を作る（crate 外の [`BatchSink`]
    /// 実装が戻り値を作る唯一の入口。`#[non_exhaustive]` のため）。
    pub fn new(elapsed: Duration) -> Self {
        Self { elapsed }
    }
}

/// [`BatchSink`] の最小実装: 呼び出し側が開いた [`File`] へ、バッチ内の各
/// `Write` フレームの body を到着順に `write_all` で追記する（D1）。
///
/// パス解決・ファイルの作成・rename・truncate は行わない（それらはワイヤーに
/// 表現がなく、TASK-14 のファイル操作ペイロード拡張までは呼び出し側が
/// `File` を用意する）。
///
/// # 永続化（IO-2・TASK-15.2.2）
/// [`BatchSink::persist`] は [`crate::barrier::persist_support`] が対応と判定した
/// 環境で永続化する（Linux 5.8 以上は `syncfs(2)`、macOS / Windows は TASK-15.3・#88 の
/// ファイルへの `fcntl(F_FULLFSYNC)` / `FlushFileBuffers` に加え、[`AppendFileSink::open_in`] /
/// [`crate::GuestFileCreator`] が
/// ファイルを開いた・作ったディレクトリハンドルの同期。[`AppendFileSink::new`] で作った
/// 親ディレクトリのない sink はエントリを保証できず `Unimplemented`。他は
/// `Unimplemented`）。syncfs を発行した後に失敗・タイムアウトした
/// sink はポイズンされ（カーネル版数拒否・fd 複製・枠確保・スレッド生成など
/// 発行前の失敗はポイズンせず再試行可）、以後の `persist` は syscall を発行せず
/// `Internal` を返す。
/// dup した fd は open file description を共有するため、タイムアウトした
/// helper が後から書き戻しエラー（errseq）を消費すると、再試行の `syncfs` が
/// 永続化されていないのに 0 を返しうるため。
///
/// # 保証範囲と単一書き込み元の前提（IO-2。Codex #1142 指摘）
/// FlushAck が保証するのは、`write_batch` 経由で受理した書き込みの永続化だけで
/// ある。呼び出し側が `new` に渡す前に `try_clone()` したハンドルや、同じファイルを
/// 別に開いたハンドル・別プロセスからの書き込みは保証の対象外で、dirty 追跡にも
/// 反映されない（直近の成功以降に `write_batch` がなければ、それらの書き込みが
/// あっても syncfs を省略して FlushAck を返す）。本 sink を使う呼び出し側は、
/// 対象ファイルへの書き込みをこの sink に一本化すること（`new` の「単一の
/// `serve_connection` ループからのみ使われる前提」と同じ契約）。書き込みを伴わない
/// FLUSH で syncfs を省略するのは、同一 UID の接続元が FS 全体の同期を繰り返し
/// 起動できる増幅（#824 の A4・Codex #1142 の P1 指摘）への対策であり、FLUSH ごとに
/// 無条件で syncfs を発行する方式には戻さない。書き込みを挟む FLUSH については、
/// プロセス全体で同時に実行中の syncfs の数を [`crate::barrier::MaxConcurrentPersist`]
/// （既定 2）までに抑え、超えた FLUSH は `with_flush_timeout` の期限内で枠を待つ
/// （期限切れは FlushAck なしの `Timeout`・ポイズンなし）。接続を増やしても同時負荷は
/// 上限までに留まるが、syncfs の回数そのものは減らさず（この sink は必ず自分の fd で
/// 発行する）、頻度（間隔）の制限も行わない。
///
/// 未対応の範囲（REPAIR-3）: タイムアウトは最大 10 秒で、未書き戻しデータが
/// 大量にあると超えうる（その場合 FlushAck は返らない）。fd を開く前に起きた
/// 書き戻しエラーは報告されない。Linux 5.8 未満は書き戻しエラーが報告されないため
/// `Unimplemented` で拒否する（`barrier` モジュール参照。ポイズンしない）。
/// 電源断への耐性は本 crate では検証しない（TASK-18）。
pub struct AppendFileSink {
    file: File,
    flush_timeout: IoTimeout,
    persist_poisoned: bool,
    /// 直近の成功した `persist` 以降に書き込み（失敗した書き込みの一部書き込みを
    /// 含む）が発生した可能性があるか。初期値は真（既存内容の永続化状態が不明）。
    /// 偽のとき `persist` は syncfs を再発行せず成功を返す（連続 FLUSH による
    /// FS 全体同期の増幅を防ぐ合流。IO-2・security.md「無制限リソース確保」）。
    /// 追跡するのは `write_batch` 経由の書き込みだけで、sink の外のハンドルからの
    /// 書き込みは反映しない（構造体 doc「保証範囲と単一書き込み元の前提」）。
    dirty_since_persist: bool,
    /// `syncfs` の同時実行数を抑える limiter（既定はプロセス全体の
    /// `crate::barrier::default_persist_limiter`。単体テストだけが差し替える）。
    persist_limiter: &'static crate::barrier::PersistLimiter,
    /// 対象ファイルのディレクトリエントリを永続化するために同期する親ディレクトリ
    /// （TASK-15.3・#88。macOS / Windows 専用。Linux は `syncfs` が FS 全体を
    /// 同期するため使わない）。ファイルを開いた・作ったハンドルだけが入る
    /// （[`AppendFileSink::open_in`]・`GuestFileCreator`）。`None` は未指定で、その環境
    /// ではファイルの名前が電源断で失われうるため `persist` は `Unimplemented` で拒否する。
    parent_dirs: Option<Vec<File>>,
    /// `parent_dirs` の同期が成功済みか。エントリは作成時に 1 回永続化すれば足りる
    /// ため、成功後の `persist` では再同期しない。
    parent_dirs_synced: bool,
}

impl AppendFileSink {
    /// 追記先の `file` から sink を作る。`file` は呼び出し側が書き込みモードで
    /// 開いたものとする。以後の対象ファイルへの書き込みはこの sink に一本化する
    /// こと（別ハンドルからの書き込みは FlushAck の保証対象外。構造体 doc
    /// 「保証範囲と単一書き込み元の前提」。IO-2）。
    ///
    /// # 末尾への位置合わせ（Codex #822 / #1125 レビュー指摘）
    ///
    /// `AppendFileSink` は「到着順に追記する」契約（構造体ドキュメント参照）を
    /// 持つが、`file` を `OpenOptions::write(true)`（`append(true)` を付けずに）
    /// で開いただけでは書き込み位置が既定でファイル先頭になり、`write_batch`
    /// の `write_all` が既存内容を上書きしてしまう。呼び出し側がどちらの
    /// モードで開いたかに関わらず追記契約を満たせるよう、ここで明示的に
    /// `SeekFrom::End(0)` へ位置合わせしてから返す（`seek` の失敗を生成時点で
    /// 呼び出し側へ返すため）。
    ///
    /// 位置合わせはここ一度きりではなく、[`BatchSink::write_batch`] の先頭でも
    /// バッチごとに行う。通常モード（非 `O_APPEND`）で一度だけ `seek` すると、
    /// バッチの合間に外部から truncate されたときカーソルが古い EOF に残り、
    /// 次のバッチが `[新 EOF, 古い EOF)` をゼロ埋めの穴にして書き込むため
    /// （IO-4・TASK-14.2）。回帰確認は unit test
    /// `io4_append_file_sink_follows_external_truncate_between_batches`（3 OS）
    /// と、UDS 経由で ACK 受信後に truncate してから次バッチを送る結合試験
    /// `tests/writeback.rs` の `io4_io1_uds_writeback_follows_external_truncate_after_ack`
    /// （Linux / macOS）で行う。
    /// バッチ単位の位置合わせで保証するのは「バッチの合間（ACK 送出後の
    /// 静止点）に行われた外部 truncate・拡張への追随」までであり、バッチの
    /// 書き込み途中の外部 truncate や他プロセスとの競合書き込みは対象外
    /// （本 sink は単一の `serve_connection` ループからのみ使われる前提。
    /// 書き込みごとのアトミックな末尾追記が必要なら呼び出し側が
    /// `OpenOptions::append(true)` で開く）。
    pub fn new(mut file: File) -> Result<Self, IoError> {
        file.seek(SeekFrom::End(0)).map_err(|err| {
            IoError::new(
                IoErrorCode::Internal,
                format!("failed to seek to end of file ({:?})", err.kind()),
            )
        })?;
        Ok(Self {
            file,
            flush_timeout: IoTimeout::new(MAX_IO_TIMEOUT)?,
            persist_poisoned: false,
            dirty_since_persist: true,
            persist_limiter: crate::barrier::default_persist_limiter(),
            parent_dirs: None,
            parent_dirs_synced: false,
        })
    }

    /// ディレクトリ `dir` 直下のファイル `name` を `mode` で開き、そのディレクトリの
    /// ハンドルを親として持つ sink を作る（IO-2・IO-3・TASK-15.3・#88）。
    ///
    /// macOS / Windows の `persist` は、ファイル自体の同期（`F_FULLFSYNC` / `FlushFileBuffers`）
    /// に加えて、ここで開いた
    /// ディレクトリハンドルを初回成功時に同期し、ファイルのディレクトリエントリ
    /// （新規作成・再オープンのどちらでも）を永続化する。親の同一性は検証ではなく構造で
    /// 保証する: 先に `dir` を開き、ファイルはそのハンドル相対で開く（Linux / macOS は
    /// `openat`、Windows は `NtCreateFile` の `RootDirectory`）。パスを再解決しないため、
    /// 途中で `dir` のパスが差し替えられても、同期するディレクトリはファイルを開いた
    /// ディレクトリそのもの（Codex #1146 P0 指摘への対応。任意の親ディレクトリを後から
    /// 登録する API は持たない）。
    ///
    /// `name` は区切り文字・`.`・`..`・`\`・`:`・NUL を含まない単一の名前に限る
    /// （`InvalidArgument`）。末端の symlink・reparse point は辿らず、通常ファイル以外は
    /// 拒否する（`InvalidArgument` または `Internal`。FIFO を開いて待ち続けない）。
    /// [`SinkOpenMode::CreateNew`] で既存なら `AlreadyExists`。それ以外の失敗は
    /// `Internal`（`ErrorKind` だけを含め、パスは含めない）。Linux・macOS・Windows
    /// 以外の OS（および `crate::sys` が対応しない Linux のアーキテクチャ）では開けず
    /// エラーを返す。`dir`・`name` はホスト側の信頼できる設定値として扱い、ゲスト由来の
    /// パスは [`crate::GuestFileCreator`] を経由させること（IO-5）。Linux の `persist` は
    /// `syncfs` が FS 全体を同期するため、保持したディレクトリハンドルは使わない。
    pub fn open_in(dir: &Path, name: &str, mode: SinkOpenMode) -> Result<Self, IoError> {
        validate_sink_file_name(name)?;
        let (leaf, truncate) = match mode {
            SinkOpenMode::CreateNew => (LeafOpen::CreateNew, false),
            SinkOpenMode::CreateOrTruncate => (LeafOpen::CreateOrOpen, true),
            SinkOpenMode::Existing => (LeafOpen::Existing, false),
            SinkOpenMode::CreateOrAppend => (LeafOpen::CreateOrAppend, false),
        };
        let (dir_handle, file) = open_leaf_in_dir(dir, name, leaf)?;
        let meta = file.metadata().map_err(|err| {
            IoError::new(
                IoErrorCode::Internal,
                format!("failed to inspect sink file ({:?})", err.kind()),
            )
        })?;
        #[cfg(windows)]
        let is_reparse = {
            use std::os::windows::fs::MetadataExt;
            // FILE_ATTRIBUTE_REPARSE_POINT
            meta.file_attributes() & 0x400 != 0
        };
        #[cfg(not(windows))]
        let is_reparse = false;
        if !meta.is_file() || is_reparse {
            return Err(IoError::new(
                IoErrorCode::InvalidArgument,
                "sink target is not a regular file",
            ));
        }
        if truncate {
            // 通常ファイルであることを確かめてから切り詰める（開く時点で切り詰めると、
            // Windows で reparse point 自体を開いた場合に拒否の前に中身を変えうるため）。
            file.set_len(0).map_err(|err| {
                IoError::new(
                    IoErrorCode::Internal,
                    format!("failed to truncate sink file ({:?})", err.kind()),
                )
            })?;
        }
        Ok(Self::new(file)?.with_parent_dir_handles(vec![dir_handle]))
    }

    /// ファイルを開いた・作ったときに使ったディレクトリハンドルを、同期する親として
    /// 登録する（crate 内専用。`open_in` と `GuestFileCreator::create_file` だけが、
    /// 自分が開いたハンドルを渡す。外部から任意のディレクトリを登録させない。IO-2・IO-3・
    /// TASK-15.3・Codex #1146 P0）。`dirs` は末端の親から順に、ファイルとともに新設した
    /// 祖先を含める。空の `dirs` は `persist` が未指定と同じく拒否する。登録は未永続化
    /// 状態として扱い、次の Flush で必ず同期する。
    pub(crate) fn with_parent_dir_handles(mut self, dirs: Vec<File>) -> Self {
        self.parent_dirs = Some(dirs);
        self.parent_dirs_synced = false;
        self.dirty_since_persist = true;
        self
    }

    /// [`BatchSink::persist`] のタイムアウトを差し替える（既定は
    /// [`MAX_IO_TIMEOUT`]。REPAIR-5）。
    ///
    /// この期限は `syncfs` の同時実行数の枠待ち（[`crate::barrier::MaxConcurrentPersist`]）
    /// と `syncfs` 本体の実行を合わせたもの。枠待ちで期限が尽きたら FlushAck を
    /// 返さず [`IoErrorCode::Timeout`] で確定する（syncfs 未発行のためポイズンしない）。
    pub fn with_flush_timeout(mut self, timeout: IoTimeout) -> Self {
        self.flush_timeout = timeout;
        self
    }

    /// 内部の [`File`] を所有権ごと取り出す。
    ///
    /// `&File` を返す `get_ref` は意図的に提供しない: 共有参照経由の書き込みは
    /// `dirty_since_persist` に反映されず、次の `persist` が syncfs を省略して
    /// 未永続化のまま FlushAck を送りうるため（IO-2。Codex #1142 指摘）。
    pub fn into_inner(self) -> File {
        self.file
    }
}

/// [`std::io::Error`] を [`IoError`] へ変換する（D6）。
///
/// `message` にはエラー種別（[`io::ErrorKind`]）とバッチ内フレーム件数だけを
/// 載せ、書き込んだデータの中身・パスは含めない（security.md「情報漏えい」
/// 観点）。`ErrorKind::StorageFull`（ENOSPC 相当）は
/// [`IoErrorCode::ResourceExhausted`] とし、それ以外は [`IoErrorCode::Internal`]
/// とする。
fn sink_error_from_io(err: &io::Error, batch_len: usize) -> IoError {
    let code = if err.kind() == io::ErrorKind::StorageFull {
        IoErrorCode::ResourceExhausted
    } else {
        IoErrorCode::Internal
    };
    IoError::new(
        code,
        format!(
            "sink write failed ({:?}) while writing a batch of {batch_len} frame(s)",
            err.kind()
        ),
    )
}

impl BatchSink for AppendFileSink {
    fn write_batch(&mut self, batch: &Batch) -> Result<SinkWriteReport, IoError> {
        // 書き込み前に立てる（途中失敗でも一部が書かれうるため。persist の合流判定）。
        self.dirty_since_persist = true;
        // バッチごとに現在の EOF へ位置合わせする（`AppendFileSink::new` の
        // 「末尾への位置合わせ」節参照。バッチの合間の外部 truncate 後に古い
        // オフセットへ書いてゼロ埋めの穴を作らないため。IO-4）。失敗時は `Err`
        // を返し、呼び出し元はこのバッチへ ACK を送らない（D6）。メッセージは
        // write 失敗と区別できるよう seek 専用にし、`new` と同じく
        // [`IoErrorCode::Internal`] とする（データの中身・パスは含めない）。
        self.file.seek(SeekFrom::End(0)).map_err(|err| {
            IoError::new(
                IoErrorCode::Internal,
                format!(
                    "sink seek to end failed ({:?}) before writing a batch of {} frame(s)",
                    err.kind(),
                    batch.len()
                ),
            )
        })?;

        let mut frames_written: usize = 0;
        let mut bytes_written: u64 = 0;

        for frame in batch.frames() {
            // batch.rs の契約により frame.kind() は常に Write。decode_request は
            // serve_connection が受信直後に一度検証済みだが、Batch は Frame を
            // 値として保持するため、body を取り出すにはもう一度呼ぶ必要がある
            // （unwrap せず Result のまま扱う。coding-rust「外部入力の経路では
            // unwrap しない」）。
            let envelope = decode_request(frame)?;
            self.file
                .write_all(envelope.body())
                .map_err(|err| sink_error_from_io(&err, batch.len()))?;

            frames_written = frames_written.checked_add(1).ok_or_else(|| {
                IoError::new(IoErrorCode::Internal, "frames_written counter overflowed")
            })?;
            let body_len = u64::try_from(envelope.body().len()).map_err(|_| {
                IoError::new(IoErrorCode::Internal, "body length does not fit in u64")
            })?;
            bytes_written = bytes_written.checked_add(body_len).ok_or_else(|| {
                IoError::new(IoErrorCode::Internal, "bytes_written counter overflowed")
            })?;
        }

        Ok(SinkWriteReport::new(frames_written, bytes_written))
    }

    fn persist(&mut self) -> Result<SinkPersistReport, IoError> {
        self.persist_with_support(crate::barrier::persist_support())
    }
}

impl AppendFileSink {
    /// [`BatchSink::persist`] の本体。実行環境の判定（[`crate::barrier::persist_support`]）
    /// を引数で受け、5.8 以上のホストでも旧カーネル・非 Linux の経路（ポイズンせず
    /// dirty のまま `Unimplemented`）を単体テストで決定的に照合できるようにする。
    fn persist_with_support(
        &mut self,
        support: crate::barrier::PersistSupport,
    ) -> Result<SinkPersistReport, IoError> {
        if self.persist_poisoned {
            return Err(IoError::new(
                IoErrorCode::Internal,
                "persist is poisoned by an earlier failure",
            ));
        }
        if support == crate::barrier::PersistSupport::SupportedFileSync
            && self.parent_dirs.as_ref().is_none_or(|dirs| dirs.is_empty())
        {
            // ファイル自体の sync だけでは新規作成ファイルのディレクトリエントリが
            // 永続化されない。親ディレクトリが不明な sink は保証できないため、
            // syscall を発行せず拒否する（ポイズンしない。IO-2・IO-3）。
            return Err(IoError::new(
                IoErrorCode::Unimplemented,
                "parent directories are not configured; cannot persist the directory entry, refusing to send FlushAck",
            ));
        }
        if !self.dirty_since_persist {
            // 直近の成功以降に書き込みがなく、その成功が既に全書き込みを永続化
            // 済みのため、FS 全体同期を再発行せず合流する。
            return Ok(SinkPersistReport::new(Duration::ZERO));
        }
        let dirs: &[File] = match (&self.parent_dirs, self.parent_dirs_synced) {
            (Some(dirs), false) => dirs,
            _ => &[],
        };
        match crate::barrier::persist_file_system(
            support,
            self.persist_limiter,
            &self.file,
            dirs,
            self.flush_timeout,
        ) {
            Ok(elapsed) => {
                self.dirty_since_persist = false;
                self.parent_dirs_synced = true;
                Ok(SinkPersistReport::new(elapsed))
            }
            Err(failure) => {
                // syncfs を発行した（発行しうる）失敗だけポイズンする。カーネル版数
                // 拒否・fd 複製・枠確保・スレッド生成の失敗は errseq を消費して
                // おらず一時的なため、ポイズンせず次の Flush で再試行できる。
                if failure.issued {
                    self.persist_poisoned = true;
                }
                Err(failure.error)
            }
        }
    }
}

/// [`AppendFileSink::open_in`] の開き方（IO-2・TASK-15.3）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SinkOpenMode {
    /// 新規作成のみ（既存なら `AlreadyExists`。symlink を含む）。
    CreateNew,
    /// 無ければ作成し、あれば長さ 0 に切り詰める。
    CreateOrTruncate,
    /// 既存のファイルを切り詰めずに開く（無ければ失敗）。
    Existing,
    /// 無ければ作成し、追記モード（`O_APPEND` / `FILE_APPEND_DATA` のみ）で開く。
    CreateOrAppend,
}

/// `crate::sys` / `crate::sys_windows` へ渡す開き方（[`SinkOpenMode`] から切り詰めを
/// 除いたもの）。切り詰めは [`AppendFileSink::open_in`] が通常ファイルであることを
/// 確かめた後に行う（Windows の reparse point など、種別の確認前に中身を変えないため）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LeafOpen {
    /// 新規作成のみ（既存なら失敗）。
    CreateNew,
    /// 無ければ作成し、あれば切り詰めずに開く。
    CreateOrOpen,
    /// 既存のみ（切り詰めない）。
    Existing,
    /// 無ければ作成し、追記モードで開く。
    CreateOrAppend,
}

/// [`AppendFileSink::open_in`] の `name` が単一の通常の名前か（`GuestFileCreator` の
/// コンポーネント検証と同じ基準。3 OS で挙動を揃えるため `\`・`:` も拒否する）。
fn validate_sink_file_name(name: &str) -> Result<(), IoError> {
    let invalid = || {
        IoError::new(
            IoErrorCode::InvalidArgument,
            "sink file name must be a single normal path component",
        )
    };
    if name.contains(['\\', ':', '\0']) {
        return Err(invalid());
    }
    let mut parts = Path::new(name).components();
    match (parts.next(), parts.next()) {
        (Some(std::path::Component::Normal(_)), None) => Ok(()),
        _ => Err(invalid()),
    }
}

/// `dir` を開き、そのハンドル相対で `name` を開く（[`AppendFileSink::open_in`] の OS 別
/// 本体。戻り値は `(ディレクトリハンドル, ファイル)`）。Linux / macOS は `crate::sys` の
/// `openat` ラッパー、Windows は `crate::sys_windows` の `NtCreateFile` ラッパーを使う。
/// Windows のディレクトリハンドルは `FlushFileBuffers` のため書き込みアクセスで開く。
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn open_leaf_in_dir(dir: &Path, name: &str, mode: LeafOpen) -> Result<(File, File), IoError> {
    use crate::sys::BeneathError;
    let map = |context: &str, err: BeneathError| match err {
        BeneathError::AlreadyExists => {
            IoError::new(IoErrorCode::AlreadyExists, "sink file already exists")
        }
        BeneathError::AncestorNotDirectory => IoError::new(
            IoErrorCode::InvalidArgument,
            "sink directory is not a directory",
        ),
        BeneathError::Io(kind) => {
            IoError::new(IoErrorCode::Internal, format!("{context} ({kind:?})"))
        }
    };
    let dir_handle =
        crate::sys::open_dir_path(dir).map_err(|err| map("failed to open sink directory", err))?;
    let file = crate::sys::open_leaf_beneath(&dir_handle, name, mode)
        .map_err(|err| map("failed to open sink file", err))?;
    Ok((dir_handle, file))
}

#[cfg(target_os = "windows")]
fn open_leaf_in_dir(dir: &Path, name: &str, mode: LeafOpen) -> Result<(File, File), IoError> {
    use std::os::windows::fs::OpenOptionsExt;
    // FILE_FLAG_BACKUP_SEMANTICS（ディレクトリを開くのに必須）。
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    let dir_handle = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(dir)
        .map_err(|err| {
            IoError::new(
                IoErrorCode::Internal,
                format!("failed to open sink directory ({:?})", err.kind()),
            )
        })?;
    let is_dir = dir_handle
        .metadata()
        .map_err(|err| {
            IoError::new(
                IoErrorCode::Internal,
                format!("failed to open sink directory ({:?})", err.kind()),
            )
        })?
        .is_dir();
    if !is_dir {
        return Err(IoError::new(
            IoErrorCode::InvalidArgument,
            "sink directory is not a directory",
        ));
    }
    let file = crate::sys_windows::open_file_beneath(&dir_handle, name, mode).map_err(|err| {
        if err.kind() == std::io::ErrorKind::AlreadyExists {
            IoError::new(IoErrorCode::AlreadyExists, "sink file already exists")
        } else {
            IoError::new(
                IoErrorCode::Internal,
                format!("failed to open sink file ({:?})", err.kind()),
            )
        }
    })?;
    Ok((dir_handle, file))
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn open_leaf_in_dir(_dir: &Path, _name: &str, _mode: LeafOpen) -> Result<(File, File), IoError> {
    Err(IoError::new(
        IoErrorCode::Unimplemented,
        "opening a sink file beneath a directory is not implemented on this OS",
    ))
}

/// [`serve_connection`] が送受信それぞれに使うタイムアウト（REPAIR-5）。
#[derive(Debug, Clone, Copy)]
pub struct WritebackTimeouts {
    /// [`FrameReceiver::recv_frame`] に渡すタイムアウト。
    pub recv: IoTimeout,
    /// [`FrameSender::send_frame`]（ACK 送出）に渡すタイムアウト。
    pub send: IoTimeout,
}

/// [`serve_connection`] が返す統計（REPAIR-4: 可観測性）。
///
/// 真偽値・フラットな文字列ではなく件数を持つ構造体として返す
/// （coding-rust「戻り値は将来拡張できる構造を持つ型にする」）。
/// `#[non_exhaustive]` により将来のフィールド追加に備える。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct WritebackStats {
    /// 受信したフレームの総数（種別を問わない）。
    pub frames_received: u64,
    /// 書き込みを実行したバッチの総数。
    pub batches_written: u64,
    /// 書き込んだ body の合計バイト数。
    pub bytes_written: u64,
    /// 送出した通常 ACK（[`FrameKind::Ack`]）の総数。
    pub acks_sent: u64,
    /// 送出した FLUSH ACK（[`FrameKind::FlushAck`]）の総数（IO-2）。
    pub flush_acks_sent: u64,
    /// [`BatchSink::persist`] が成功した回数（REPAIR-4）。
    pub persist_succeeded: u64,
    /// [`BatchSink::persist`] が失敗した回数（タイムアウト・未対応を含む。REPAIR-4）。
    pub persist_failed: u64,
    /// 成功した persist の所要時間の合計（マイクロ秒。飽和加算。REPAIR-4）。
    pub persist_elapsed_micros: u64,
    /// ACK を送らずに破棄した滞留フレーム件数（D5）。
    pub discarded_pending_frames: u64,
}

/// [`serve_connection`] の戻り値（D7）。
///
/// ループは常にエラー（EOF を含む。P1-3 の下では EOF も
/// [`IoErrorCode::Unavailable`] になる）で終わるため、「Ok 側を持たない
/// `Result`」を表現する代わりに本構造体を返す（coding-rust「戻り値は
/// 将来拡張できる構造を持つ型にする」）。`end` がループの終了原因、`stats` が
/// そこまでの累積統計。
#[derive(Debug)]
#[non_exhaustive]
pub struct WritebackReport {
    /// ループ終了時点までの累積統計。
    pub stats: WritebackStats,
    /// ループの終了原因（正常終了はない。上記モジュール doc 参照）。
    pub end: IoError,
}

/// バッチ内の各フレームへ、挿入順（到着順）に通常 ACK を送る（[`FrameKind::Ack`]。
/// D2）。[`decode_request`] の再デコードが失敗するのは構造上起こらない分岐だが
/// `unwrap` せず [`IoErrorCode::Internal`] として扱う。
fn send_acks_in_order<T>(
    conn: &mut T,
    batch: &Batch,
    timeout: IoTimeout,
    stats: &mut WritebackStats,
) -> Result<(), IoError>
where
    T: FrameSender<Frame = Frame>,
{
    for frame in batch.frames() {
        let envelope = decode_request(frame).map_err(|_| {
            IoError::new(
                IoErrorCode::Internal,
                "failed to re-decode a frame already accepted by BatchBuffer::push",
            )
        })?;
        let ack = encode_ack(FrameKind::Ack, envelope.id())?;
        conn.send_frame(&ack, timeout)?;
        stats.acks_sent = stats.acks_sent.saturating_add(1);
    }
    Ok(())
}

/// バッチを `sink` へ書き込み、成功したら到着順に通常 ACK を送る（D2・D6の
/// 「sink 失敗時は ACK を 1 件も返さない」を 1 か所にまとめる）。
///
/// `sink.write_batch` の契約（[`BatchSink`] のドキュメント）は
/// 「バッチ全体が書けたときだけ `Ok`」だが、`Ok` の中身（`frames_written`）を
/// 信頼せずここで `batch.len()` と突き合わせて検証する。現行の
/// [`AppendFileSink`] は常に一致するが、将来別実装の `sink` が件数不一致の
/// `Ok` を返す可能性に備えたフェイルクローズ（防御的検証。coding-rust
/// 「外部入力の経路では明示的に処理する」の趣旨を sink 実装の誤りにも適用）。
fn write_batch_and_ack<T, W>(
    conn: &mut T,
    sink: &mut W,
    batch: &Batch,
    timeout: IoTimeout,
    stats: &mut WritebackStats,
) -> Result<(), IoError>
where
    T: FrameSender<Frame = Frame>,
    W: BatchSink,
{
    let report = sink.write_batch(batch)?;
    if report.frames_written != batch.len() {
        return Err(IoError::new(
            IoErrorCode::Internal,
            format!(
                "sink reported frames_written={} but batch.len()={}",
                report.frames_written,
                batch.len()
            ),
        ));
    }
    stats.batches_written = stats.batches_written.saturating_add(1);
    stats.bytes_written = stats.bytes_written.saturating_add(report.bytes_written);
    send_acks_in_order(conn, batch, timeout, stats)
}

/// 1 接続分のバッチ write-back を実行する（TASK-13.2.2・IO-1・#822）。
///
/// `conn` は [`FrameSender`] + [`FrameReceiver`]（[`Frame`] を扱う）を実装する
/// トランスポート 1 本（[`crate::server::UdsConnection`] 等）。`config` は
/// [`BatchBuffer`] の集約設定、`sink` は書き込み先（[`AppendFileSink`] 等）、
/// `timeouts` は送受信それぞれのタイムアウト（REPAIR-5）。
///
/// 受信した [`FrameKind::Write`] を [`BatchBuffer::push`] へ渡し、発火した
/// バッチを `sink` へ書き込んでから到着順に ACK を送る。[`FrameKind::Flush`]
/// は滞留分を書き込み・ACK した後 [`BatchSink::persist`] を呼び、成功したら
/// [`FrameKind::FlushAck`] を送って継続する（失敗時は FlushAck なしで
/// そのエラーで終える。IO-2）。[`FrameKind::Ack`] / [`FrameKind::FlushAck`]（クライアントが送る
/// べきでない種別。UDS 経由では [`crate::server`] の受信層が先に拒否するが、
/// generic なトランスポート向けの防御として本関数でも拒否する）は
/// [`IoErrorCode::InvalidArgument`] で終える。
///
/// ループは常にエラーで終わる（[`WritebackReport`] 参照）。終了時、
/// [`BatchBuffer`] に残っていた滞留フレームは書き込まずに破棄し件数を
/// [`WritebackStats::discarded_pending_frames`] へ残す（D5）。
///
/// `config` は [`crate::settings::WritebackSettings::batch_config`] から
/// 渡し、対応する [`crate::server::UdsServer::bind`] には同じ
/// [`crate::settings::WritebackSettings`] インスタンスの
/// [`crate::settings::WritebackSettings::receive_limits`] を渡すことを推奨する
/// （TASK-13.3・#78。両者を別々の設定値から個別に構築すると、受信ゲートと
/// 集約ロジックのバッチサイズが食い違う経路を作れてしまう）。この対応を型で
/// 保証したい場合は、本関数を直接呼ぶ代わりに
/// [`crate::settings::WritebackSettings::bind`] が返す
/// [`crate::settings::BoundWriteback`] と、その [`accept`][ba] が返す
/// [`crate::settings::BoundConnection::serve`] を使う（REPAIR-2・#1115 codex
/// レビュー指摘対応。`serve` は `BatchConfig` を引数に取らず、常に接続元の
/// `WritebackSettings` から導くため、別の設定値を混ぜる経路自体が無い）。
///
/// [ba]: crate::settings::BoundWriteback::accept
pub fn serve_connection<T, W>(
    conn: &mut T,
    config: BatchConfig,
    sink: &mut W,
    timeouts: WritebackTimeouts,
) -> WritebackReport
where
    T: FrameSender<Frame = Frame> + FrameReceiver<Frame = Frame>,
    W: BatchSink,
{
    let mut stats = WritebackStats::default();
    let mut buffer = BatchBuffer::new(config);

    /// ループを終える共通処理: 滞留分を破棄件数として記録し `WritebackReport` を返す
    /// （D5。マクロではなくローカル関数だと `stats`/`buffer` の可変借用が絡むため、
    /// 呼び出し側で都度 1 行にまとめる代わりにこの内部ヘルパーへ集約する）。
    fn finish(mut stats: WritebackStats, buffer: &BatchBuffer, end: IoError) -> WritebackReport {
        // buffer.len() は BatchConfig の上限（バッチサイズ）に抑えられており
        // u64 の範囲を超えることはないが、同ファイル内の他箇所（`sink` 実装
        // 等）と流儀を揃えて `as` キャストではなく `u64::try_from` で扱う。
        // 上限を超えることは構造上ないため通常は到達しないが、万一変換に
        // 失敗した場合は 0 件（＝破棄なし）ではなく `u64::MAX` を用いる
        // （このファイルの他のカウンタが `saturating_add` で飽和側へ倒す
        // のと同じ「失敗を過小報告しない」方針。discarded_pending_frames は
        // 可観測性用カウンタだが、変換失敗を理由にループ終了処理自体は
        // 失敗させない）。
        stats.discarded_pending_frames = u64::try_from(buffer.len()).unwrap_or(u64::MAX);
        WritebackReport { stats, end }
    }

    loop {
        let frame = match conn.recv_frame(timeouts.recv) {
            Ok(frame) => frame,
            Err(err) => return finish(stats, &buffer, err),
        };
        stats.frames_received = stats.frames_received.saturating_add(1);

        match frame.kind() {
            FrameKind::Write => {
                // decode_request は Write フレームの形式（request id + body 長）を
                // 検証する。8 バイト未満（request id すら入っていない）等の違反は
                // ここで検出し、バッファへは触れずに終える。
                if let Err(err) = decode_request(&frame) {
                    return finish(stats, &buffer, err);
                }

                let outcome = match buffer.push(frame) {
                    Ok(outcome) => outcome,
                    Err(err) => return finish(stats, &buffer, err),
                };

                let batches: Vec<Batch> = match outcome {
                    PushOutcome::Buffered { .. } => Vec::new(),
                    PushOutcome::Ready(batch) => vec![batch],
                    PushOutcome::ReadyTwice(first, second) => vec![first, second],
                };
                for batch in &batches {
                    if let Err(err) =
                        write_batch_and_ack(conn, sink, batch, timeouts.send, &mut stats)
                    {
                        return finish(stats, &buffer, err);
                    }
                }
            }
            FrameKind::Flush => {
                // Codex #822 レビュー指摘: Write と同様、`decode_request` で
                // 形式（request id ちょうど 8 バイト・body 空）を検証してから
                // 滞留分（`buffer.take_pending()`）へ触れる。request id が
                // 欠けている・余分な body を持つ不正な Flush をバリアとして
                // 扱うと、クライアントが ACK していない書き込みを誤って
                // 確定させてしまうため（D5 の fail-closed と一貫させる）。
                let envelope = match decode_request(&frame) {
                    Ok(envelope) => envelope,
                    Err(err) => return finish(stats, &buffer, err),
                };

                if let Some(batch) = buffer.take_pending()
                    && let Err(err) =
                        write_batch_and_ack(conn, sink, &batch, timeouts.send, &mut stats)
                {
                    return finish(stats, &buffer, err);
                }
                // IO-2・TASK-15.2.2: FLUSH ACK は永続化の保証であり、persist が
                // `Ok` を返したときだけ送る（エラー・タイムアウト・未対応は
                // FlushAck を送らず終了。fail-closed）。
                match sink.persist() {
                    Ok(report) => {
                        stats.persist_succeeded = stats.persist_succeeded.saturating_add(1);
                        let micros = u64::try_from(report.elapsed.as_micros()).unwrap_or(u64::MAX);
                        stats.persist_elapsed_micros =
                            stats.persist_elapsed_micros.saturating_add(micros);
                    }
                    Err(err) => {
                        stats.persist_failed = stats.persist_failed.saturating_add(1);
                        return finish(stats, &buffer, err);
                    }
                }
                let flush_ack = match encode_ack(FrameKind::FlushAck, envelope.id()) {
                    Ok(ack) => ack,
                    Err(err) => return finish(stats, &buffer, err),
                };
                if let Err(err) = conn.send_frame(&flush_ack, timeouts.send) {
                    return finish(stats, &buffer, err);
                }
                stats.flush_acks_sent = stats.flush_acks_sent.saturating_add(1);
            }
            FrameKind::Ack | FrameKind::FlushAck => {
                let err = IoError::new(
                    IoErrorCode::InvalidArgument,
                    "client must not send Ack/FlushAck frames to the writeback server",
                );
                return finish(stats, &buffer, err);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::{InFlightLimit, SendQueue};
    use crate::payload::{WireRequestId, encode_request};
    use std::collections::VecDeque;

    fn test_timeout() -> IoTimeout {
        IoTimeout::new(std::time::Duration::from_millis(50)).expect("50ms must be valid")
    }

    fn write_frame(id: u64, body: &[u8]) -> Frame {
        encode_request(FrameKind::Write, wire_id(id), body).expect("encode_request must succeed")
    }

    fn flush_frame(id: u64) -> Frame {
        encode_request(FrameKind::Flush, wire_id(id), &[]).expect("encode_request must succeed")
    }

    fn wire_id(value: u64) -> WireRequestId {
        // WireRequestId::from_wire は非公開のため、テストでは client 側の経路
        // （新しい SendQueue で `0` から順に採番される連番。`RequestId` →
        // `From<RequestId>`）を経由して作る。`SendQueue::register` は
        // 呼ぶたびに連番を 1 つずつ払い出すだけ（`remove` しなくても上限には
        // 達しない小さな `value` のみを本テストで使う）なので、`value + 1` 回
        // 呼んで最後に払い出された id を使えば `value` そのものが得られる。
        let limit = InFlightLimit::new(crate::client::MAX_IN_FLIGHT_LIMIT)
            .expect("MAX_IN_FLIGHT_LIMIT must be a valid limit");
        let mut queue = SendQueue::new(limit);
        let mut last = None;
        for _ in 0..=value {
            let registered = queue
                .register(FrameKind::Write)
                .expect("register must succeed");
            last = Some(registered.id());
        }
        WireRequestId::from(last.expect("loop runs at least once"))
    }

    /// テスト専用の偽トランスポート: `VecDeque` から受信し、送信内容は
    /// `Vec<Frame>` に記録する。受信キューが尽きたら [`IoErrorCode::Unavailable`]
    /// を返す（EOF 相当。P1-3 と同じ意味論。一度 `exhausted` になったら以後も
    /// `Unavailable` を返し続け、poison 済み接続の再利用禁止と同じ形にする）。
    struct FakeTransport {
        incoming: VecDeque<Frame>,
        sent: Vec<Frame>,
        exhausted: bool,
    }

    impl FakeTransport {
        fn new(frames: Vec<Frame>) -> Self {
            Self {
                incoming: frames.into(),
                sent: Vec::new(),
                exhausted: false,
            }
        }
    }

    impl FrameSender for FakeTransport {
        type Frame = Frame;

        fn send_frame(&mut self, frame: &Frame, _timeout: IoTimeout) -> Result<(), IoError> {
            self.sent.push(frame.clone());
            Ok(())
        }
    }

    impl FrameReceiver for FakeTransport {
        type Frame = Frame;

        fn recv_frame(&mut self, _timeout: IoTimeout) -> Result<Frame, IoError> {
            if self.exhausted {
                return Err(IoError::new(
                    IoErrorCode::Unavailable,
                    "fake transport exhausted",
                ));
            }
            match self.incoming.pop_front() {
                Some(frame) => Ok(frame),
                None => {
                    self.exhausted = true;
                    Err(IoError::new(
                        IoErrorCode::Unavailable,
                        "fake transport exhausted",
                    ))
                }
            }
        }
    }

    /// テスト専用の偽 sink: 書いた body を記録し、`fail_at`（1-based のバッチ
    /// 呼び出し回数）に達したら以後 `Err` を返す。
    struct FakeSink {
        written: Vec<Vec<u8>>,
        calls: usize,
        fail_at: Option<usize>,
    }

    impl FakeSink {
        fn new() -> Self {
            Self {
                written: Vec::new(),
                calls: 0,
                fail_at: None,
            }
        }

        fn failing_at(fail_at: usize) -> Self {
            Self {
                written: Vec::new(),
                calls: 0,
                fail_at: Some(fail_at),
            }
        }
    }

    impl BatchSink for FakeSink {
        fn write_batch(&mut self, batch: &Batch) -> Result<SinkWriteReport, IoError> {
            self.calls += 1;
            if self.fail_at == Some(self.calls) {
                return Err(IoError::new(IoErrorCode::Internal, "fake sink failure"));
            }
            let mut frames_written = 0usize;
            let mut bytes_written = 0u64;
            for frame in batch.frames() {
                let envelope = decode_request(frame).expect("test frames must decode");
                self.written.push(envelope.body().to_vec());
                frames_written += 1;
                bytes_written += envelope.body().len() as u64;
            }
            // `SinkWriteReport::new` を使う（crate 外実装が使う唯一の構築経路
            // であることの回帰確認を兼ねる。Bugbot #822 レビュー指摘）。
            Ok(SinkWriteReport::new(frames_written, bytes_written))
        }
    }

    fn timeouts() -> WritebackTimeouts {
        WritebackTimeouts {
            recv: test_timeout(),
            send: test_timeout(),
        }
    }

    /// IO-1: `batch_size = 3` で Write を 6 件送ると、ACK が 6 件・id が送信順・
    /// sink の呼び出しが 2 回になり、各バッチの書き込みがその ACK より先に
    /// 完了している（sink 呼び出し後に ACK が積まれる実装のため、`sent` の
    /// 並び自体が書き込み → ACK の順序を保証する）。
    #[test]
    fn io1_writeback_batches_and_acks_in_order() {
        let frames: Vec<Frame> = (0..6u64).map(|id| write_frame(id, b"x")).collect();
        let mut conn = FakeTransport::new(frames);
        let mut sink = FakeSink::new();
        let config = BatchConfig::new(3).expect("3 must be valid");

        let report = serve_connection(&mut conn, config, &mut sink, timeouts());

        assert_eq!(report.stats.acks_sent, 6);
        assert_eq!(report.stats.batches_written, 2);
        assert_eq!(report.stats.discarded_pending_frames, 0);
        assert_eq!(sink.calls, 2);
        assert_eq!(sink.written.len(), 6);

        let acked_ids: Vec<u64> = conn.sent.iter().map(ack_id).collect();
        assert_eq!(acked_ids, vec![0, 1, 2, 3, 4, 5]);
    }

    /// `Frame`（Ack）から request id を取り出すテスト専用ヘルパー。
    fn ack_id(frame: &Frame) -> u64 {
        crate::payload::decode_ack(frame)
            .expect("sent frame must be a valid ack")
            .id()
            .get()
    }

    /// IO-1・D4: `persist` を実装しない sink（既定実装）では、Write 2 件 +
    /// Flush で ACK が 2 件・FlushAck は 0 件、終了原因が `Unimplemented` になる
    /// （実行環境に依存しない fail-closed。IO-2）。
    #[test]
    fn io1_writeback_flush_acks_pending_then_unimplemented() {
        let frames = vec![write_frame(0, b"a"), write_frame(1, b"b"), flush_frame(2)];
        let mut conn = FakeTransport::new(frames);
        let mut sink = FakeSink::new();
        let config = BatchConfig::default();

        let report = serve_connection(&mut conn, config, &mut sink, timeouts());

        assert_eq!(report.stats.acks_sent, 2);
        assert_eq!(report.stats.discarded_pending_frames, 0);
        assert_eq!(report.end.code(), IoErrorCode::Unimplemented);
        assert!(conn.sent.iter().all(|frame| frame.kind() == FrameKind::Ack));
    }

    /// IO-1・REPAIR-2（Codex #822 レビュー指摘）: request id を持たない
    /// （空ペイロードの）Flush は `decode_request` に拒否され
    /// `InvalidArgument` で終わる。滞留していた Write はバリアとして
    /// 書き込まれず（`sink.calls == 0`）、ACK も送らず破棄される
    /// （`discarded_pending_frames`）。
    #[test]
    fn io1_writeback_rejects_malformed_flush_without_touching_pending() {
        let malformed_flush =
            Frame::new(FrameKind::Flush, Vec::new()).expect("empty payload must construct");
        let frames = vec![write_frame(0, b"a"), malformed_flush];
        let mut conn = FakeTransport::new(frames);
        let mut sink = FakeSink::new();
        let config = BatchConfig::new(4).expect("4 must be valid");

        let report = serve_connection(&mut conn, config, &mut sink, timeouts());

        assert_eq!(report.stats.acks_sent, 0);
        assert_eq!(sink.calls, 0, "malformed flush must not trigger a write");
        assert_eq!(report.stats.discarded_pending_frames, 1);
        assert_eq!(report.end.code(), IoErrorCode::InvalidArgument);
    }

    /// IO-1・REPAIR-2（Codex #822 レビュー指摘）: request id に続けて余分な
    /// body を持つ Flush も同様に `InvalidArgument` で拒否される。
    #[test]
    fn io1_writeback_rejects_flush_with_extra_body_without_touching_pending() {
        let mut payload = 7u64.to_le_bytes().to_vec();
        payload.extend_from_slice(b"unexpected-body");
        let malformed_flush =
            Frame::new(FrameKind::Flush, payload).expect("payload must construct");
        let frames = vec![write_frame(0, b"a"), malformed_flush];
        let mut conn = FakeTransport::new(frames);
        let mut sink = FakeSink::new();
        let config = BatchConfig::new(4).expect("4 must be valid");

        let report = serve_connection(&mut conn, config, &mut sink, timeouts());

        assert_eq!(report.stats.acks_sent, 0);
        assert_eq!(sink.calls, 0, "malformed flush must not trigger a write");
        assert_eq!(report.stats.discarded_pending_frames, 1);
        assert_eq!(report.end.code(), IoErrorCode::InvalidArgument);
    }

    /// IO-1・D5: `batch_size = 4` で 2 件送って EOF（`Unavailable`）になると、
    /// ACK は 0 件・sink は呼ばれず、`discarded_pending_frames == 2`。
    #[test]
    fn io1_writeback_discards_pending_on_disconnect() {
        let frames = vec![write_frame(0, b"a"), write_frame(1, b"b")];
        let mut conn = FakeTransport::new(frames);
        let mut sink = FakeSink::new();
        let config = BatchConfig::new(4).expect("4 must be valid");

        let report = serve_connection(&mut conn, config, &mut sink, timeouts());

        assert_eq!(report.stats.acks_sent, 0);
        assert_eq!(sink.calls, 0);
        assert_eq!(report.stats.discarded_pending_frames, 2);
        assert_eq!(report.end.code(), IoErrorCode::Unavailable);
    }

    /// IO-1・REPAIR-2: 8 バイト未満の Write（request id すら入っていない）は
    /// `InvalidArgument` で終わり、ACK は 0 件。
    #[test]
    fn io1_writeback_rejects_malformed_write() {
        let malformed =
            Frame::new(FrameKind::Write, vec![0u8; 4]).expect("short payload must construct");
        let mut conn = FakeTransport::new(vec![malformed]);
        let mut sink = FakeSink::new();

        let report = serve_connection(&mut conn, BatchConfig::default(), &mut sink, timeouts());

        assert_eq!(report.stats.acks_sent, 0);
        assert_eq!(report.end.code(), IoErrorCode::InvalidArgument);
    }

    /// D6: sink の失敗では、そのバッチの ACK が 0 件で、終了原因のコードが
    /// sink のエラー由来（本テストでは `Internal`）になる。
    #[test]
    fn d6_writeback_sink_failure_sends_no_ack_for_that_batch() {
        let frames = vec![write_frame(0, b"a"), write_frame(1, b"b")];
        let mut conn = FakeTransport::new(frames);
        let mut sink = FakeSink::failing_at(1);
        let config = BatchConfig::new(2).expect("2 must be valid");

        let report = serve_connection(&mut conn, config, &mut sink, timeouts());

        assert_eq!(report.stats.acks_sent, 0);
        assert_eq!(report.end.code(), IoErrorCode::Internal);
    }

    /// クライアント発の `Ack` / `FlushAck` は `InvalidArgument` になる
    /// （generic なトランスポート向けの防御。UDS では受信層が先に拒否する）。
    #[test]
    fn writeback_rejects_client_sent_ack_kinds() {
        for kind in [FrameKind::Ack, FrameKind::FlushAck] {
            let ack = encode_ack(kind, wire_id(0)).expect("encode_ack must succeed");
            let mut conn = FakeTransport::new(vec![ack]);
            let mut sink = FakeSink::new();

            let report = serve_connection(&mut conn, BatchConfig::default(), &mut sink, timeouts());

            assert_eq!(report.stats.acks_sent, 0);
            assert_eq!(report.end.code(), IoErrorCode::InvalidArgument);
        }
    }

    /// バイト数上限で `BytesLimitReached` が発火したバッチも到着順に ACK される。
    #[test]
    fn writeback_acks_batch_fired_by_bytes_limit() {
        // BatchBuffer が上限と比較する `frame.payload().len()` は「request id
        // （REQUEST_ID_WIRE_LEN = 8 バイト）+ body」の合計（`crate::batch` の
        // `push` ドキュメンテーションコメント参照）。batch_size は十分大きく、
        // bytes 側の上限（1 フレームぶんの payload 長ちょうど = 8 + 4 = 12 バイト）
        // だけが効くようにする。1 件 4 バイトの body（payload 12 バイト）を
        // 2 件送ると、2 件目の push で 1 件目が BytesLimitReached として発火する。
        let max_bytes = crate::payload::REQUEST_ID_WIRE_LEN + 4;
        let config = BatchConfig::with_max_bytes(64, max_bytes).expect("valid config must succeed");
        let frames = vec![write_frame(0, b"aaaa"), write_frame(1, b"bbbb")];
        let mut conn = FakeTransport::new(frames);
        let mut sink = FakeSink::new();

        let report = serve_connection(&mut conn, config, &mut sink, timeouts());

        // 1 件目は BytesLimitReached で発火し ACK 済み、2 件目は EOF 時点で
        // 滞留したまま破棄される。
        assert_eq!(report.stats.acks_sent, 1);
        assert_eq!(report.stats.discarded_pending_frames, 1);
        assert_eq!(sink.written, vec![b"aaaa".to_vec()]);
    }

    /// [`AppendFileSink`] は body を到着順に追記し、`into_inner` で
    /// 内部の `File` を取り出せる（`&File` を返す `get_ref` は dirty 追跡を
    /// 迂回するため提供しない。IO-2・TASK-15.2.2・#824）。
    #[test]
    fn append_file_sink_appends_bodies_in_order() {
        let dir = std::env::temp_dir().join(format!(
            "fcio-writeback-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).expect("must create temp dir");
        let path = dir.join("out.bin");
        let mut sink = AppendFileSink::open_in(&dir, "out.bin", SinkOpenMode::CreateOrTruncate)
            .expect("seek to end must succeed");
        let mut buffer = BatchBuffer::new(BatchConfig::new(2).expect("2 must be valid"));
        let batch = match buffer
            .push(write_frame(0, b"ab"))
            .expect("push must succeed")
        {
            PushOutcome::Buffered { .. } => {
                match buffer
                    .push(write_frame(1, b"cd"))
                    .expect("push must succeed")
                {
                    PushOutcome::Ready(batch) => batch,
                    other => panic!("expected Ready, got {other:?}"),
                }
            }
            other => panic!("expected Buffered on first push, got {other:?}"),
        };

        let report = sink.write_batch(&batch).expect("write_batch must succeed");
        assert_eq!(report.frames_written, 2);
        assert_eq!(report.bytes_written, 4);

        // `path` 経由で書き込み内容を読む（`File` からパスを復元する API はない）。
        let contents = std::fs::read(&path).expect("must read output file");
        assert_eq!(contents, b"abcd");

        let _ = sink.into_inner();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Codex #822 レビュー指摘: `file` を `truncate(false)`（かつ `append(true)`
    /// を付けない）`write(true)` で開いた既存ファイルへ `AppendFileSink::new`
    /// を渡しても、`write_batch` は先頭から上書きせず既存内容の末尾へ追記する
    /// （追記契約〔構造体ドキュメント〕の回帰確認）。
    #[test]
    fn append_file_sink_appends_after_existing_content_without_append_mode() {
        let dir = std::env::temp_dir().join(format!(
            "fcio-writeback-existing-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).expect("must create temp dir");
        let path = dir.join("out.bin");
        std::fs::write(&path, b"existing").expect("must seed existing content");

        // `append(true)` を付けず、`truncate` もしない（=呼び出し側が
        // 追記の作法を守らなくても `AppendFileSink::new` 自身が末尾へ
        // 位置合わせすることの確認。`Existing` は `O_APPEND` なしで開く）。
        let mut sink = AppendFileSink::open_in(&dir, "out.bin", SinkOpenMode::Existing)
            .expect("seek to end must succeed");
        let mut buffer = BatchBuffer::new(BatchConfig::new(1).expect("1 must be valid"));
        let batch = match buffer
            .push(write_frame(0, b"-new"))
            .expect("push must succeed")
        {
            PushOutcome::Ready(batch) => batch,
            other => panic!("expected Ready with batch_size=1, got {other:?}"),
        };

        let report = sink.write_batch(&batch).expect("write_batch must succeed");
        assert_eq!(report.frames_written, 1);
        assert_eq!(report.bytes_written, 4);

        let contents = std::fs::read(&path).expect("must read output file");
        assert_eq!(
            contents, b"existing-new",
            "write_batch must append after existing content, not overwrite it from offset 0"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// IO-4・TASK-14.2（Codex #1125 レビュー指摘）: 通常モード（非 `O_APPEND`）
    /// で開いた sink へ 1 バッチ書いた後、別ハンドルで `set_len(0)` してから
    /// 次のバッチを書く。`write_batch` がバッチごとに現在の EOF へ位置合わせ
    /// するため、次のバッチは新しい EOF（先頭）に着地し、truncate 前の
    /// オフセットまでのゼロ埋めの穴ができないことを確認する。
    #[test]
    fn io4_append_file_sink_follows_external_truncate_between_batches() {
        let dir = std::env::temp_dir().join(format!(
            "fcio-writeback-truncate-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).expect("must create temp dir");
        let path = dir.join("out.bin");

        let mut sink = AppendFileSink::open_in(&dir, "out.bin", SinkOpenMode::CreateOrTruncate)
            .expect("seek to end must succeed");
        let mut buffer = BatchBuffer::new(BatchConfig::new(1).expect("1 must be valid"));

        let first = match buffer
            .push(write_frame(0, b"before-truncate"))
            .expect("push must succeed")
        {
            PushOutcome::Ready(batch) => batch,
            other => panic!("expected Ready with batch_size=1, got {other:?}"),
        };
        sink.write_batch(&first)
            .expect("first write_batch must succeed");

        let external = std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .expect("must open for external truncate");
        external.set_len(0).expect("external truncate must succeed");
        drop(external);

        let second = match buffer
            .push(write_frame(1, b"after"))
            .expect("push must succeed")
        {
            PushOutcome::Ready(batch) => batch,
            other => panic!("expected Ready with batch_size=1, got {other:?}"),
        };
        let report = sink
            .write_batch(&second)
            .expect("second write_batch must succeed");
        assert_eq!(report.frames_written, 1);
        assert_eq!(report.bytes_written, 5);

        let contents = std::fs::read(&path).expect("must read output file");
        assert_eq!(
            contents, b"after",
            "write_batch must land at the post-truncate EOF, not leave a zero-fill hole"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// IO-1: `serve_connection` へ渡す `FakeTransport` は `Send` を満たす
    /// （`FrameSender`/`FrameReceiver` が crate 内で `Send` を要求する契約と
    /// 整合。コンパイル時確認。`BatchSink` 自体は `Send` を要求しない）。
    #[test]
    fn io1_fake_transport_is_send() {
        fn assert_send<T: Send>() {}
        assert_send::<FakeTransport>();
    }

    /// テスト専用 sink: 書き込みは `FakeSink` に委譲し、`persist` の成否と
    /// 呼び出しを共有ログへ記録する。
    struct PersistSink {
        inner: FakeSink,
        persist_calls: usize,
        persist_result: Option<IoErrorCode>,
    }

    impl BatchSink for PersistSink {
        fn write_batch(&mut self, batch: &Batch) -> Result<SinkWriteReport, IoError> {
            self.inner.write_batch(batch)
        }

        fn persist(&mut self) -> Result<SinkPersistReport, IoError> {
            self.persist_calls += 1;
            match self.persist_result {
                Some(code) => Err(IoError::new(code, "injected persist failure")),
                None => Ok(SinkPersistReport::new(Duration::from_millis(1))),
            }
        }
    }

    fn persist_sink(persist_result: Option<IoErrorCode>) -> PersistSink {
        PersistSink {
            inner: FakeSink::new(),
            persist_calls: 0,
            persist_result,
        }
    }

    /// IO-2・TASK-15.2.2: Write 2 件 + Flush で、通常 ACK 0・1 → FlushAck 2 の
    /// 順に送られ、セッションは継続して EOF（`Unavailable`）で終わる。
    #[test]
    fn io2_writeback_flush_returns_flush_ack_after_persist() {
        let frames = vec![write_frame(0, b"a"), write_frame(1, b"b"), flush_frame(2)];
        let mut conn = FakeTransport::new(frames);
        let mut sink = persist_sink(None);

        let report = serve_connection(&mut conn, BatchConfig::default(), &mut sink, timeouts());

        assert_eq!(report.end.code(), IoErrorCode::Unavailable);
        assert_eq!(report.stats.acks_sent, 2);
        assert_eq!(report.stats.flush_acks_sent, 1);
        assert_eq!(sink.persist_calls, 1);
        let kinds: Vec<FrameKind> = conn.sent.iter().map(|f| f.kind()).collect();
        assert_eq!(
            kinds,
            vec![FrameKind::Ack, FrameKind::Ack, FrameKind::FlushAck]
        );
        let ids: Vec<u64> = conn.sent.iter().map(ack_id).collect();
        assert_eq!(ids, vec![0, 1, 2]);
    }

    /// IO-2・TASK-15.2.2: persist が失敗したら FlushAck を送らず、注入した
    /// エラーコードで終わる（Write の ACK は届く）。
    #[test]
    fn io2_writeback_persist_failure_sends_no_flush_ack() {
        let frames = vec![write_frame(0, b"a"), flush_frame(1)];
        let mut conn = FakeTransport::new(frames);
        let mut sink = persist_sink(Some(IoErrorCode::Timeout));

        let report = serve_connection(&mut conn, BatchConfig::default(), &mut sink, timeouts());

        assert_eq!(report.end.code(), IoErrorCode::Timeout);
        assert_eq!(report.stats.flush_acks_sent, 0);
        assert_eq!(conn.sent.len(), 1);
        assert_eq!(conn.sent[0].kind(), FrameKind::Ack);
    }

    /// IO-2・REPAIR-2: 形式が不正な Flush では persist を呼ばない。
    #[test]
    fn io2_writeback_malformed_flush_does_not_persist() {
        let bad = encode_request_raw_flush();
        let mut conn = FakeTransport::new(vec![bad]);
        let mut sink = persist_sink(None);

        let report = serve_connection(&mut conn, BatchConfig::default(), &mut sink, timeouts());

        assert_eq!(report.end.code(), IoErrorCode::InvalidArgument);
        assert_eq!(sink.persist_calls, 0);
        assert_eq!(report.stats.flush_acks_sent, 0);
    }

    fn encode_request_raw_flush() -> Frame {
        Frame::new(FrameKind::Flush, Vec::new()).expect("empty flush frame must build")
    }

    fn temp_append_sink(tag: &str) -> AppendFileSink {
        let dir = std::env::temp_dir();
        let name = format!("fandhe-io-{tag}-{}", std::process::id());
        let sink = AppendFileSink::open_in(&dir, &name, SinkOpenMode::CreateOrTruncate)
            .expect("sink must construct");
        let _ = std::fs::remove_file(dir.join(&name));
        sink
    }

    /// IO-2・TASK-15.2.2: 書き込みのない連続 persist は syncfs を再発行せず
    /// 合流する（elapsed が 0）。書き込み後は再び dirty になる。期待値は
    /// production と同じ判定（`persist_support`）で分け、非対応環境（5.8 未満・
    /// 非 Linux）では `Unimplemented` で拒否され dirty・非ポイズンのままである
    /// ことを照合する（任意のエラーで早期 return しない。Codex #1142 指摘）。
    #[test]
    fn io2_append_file_sink_coalesces_persist_without_writes() {
        let mut sink = temp_append_sink("coalesce");
        assert!(sink.dirty_since_persist);
        let support = crate::barrier::persist_support();
        let first = sink.persist();
        if support.is_supported() {
            first.expect("persist must succeed on a supported kernel");
            assert!(!sink.dirty_since_persist);
            let second = sink.persist().expect("coalesced persist must succeed");
            assert_eq!(second.elapsed, Duration::ZERO);
        } else {
            let err = first.expect_err("unsupported environment must be rejected");
            assert_eq!(err.code(), IoErrorCode::Unimplemented, "{support:?}");
            assert!(sink.dirty_since_persist);
            assert!(!sink.persist_poisoned);
        }
    }

    /// IO-2・IO-3（Codex #1142 指摘）: 旧カーネル・非 Linux の判定を注入すると、
    /// 実行ホストに関係なく `Unimplemented` で拒否され、sink はポイズンされず
    /// dirty のまま（errseq を消費していないため、対応環境なら再試行できる）。
    #[test]
    fn io2_append_file_sink_unsupported_is_not_poisoned() {
        use crate::barrier::PersistSupport;
        let mut sink = temp_append_sink("unsupported");
        for support in [PersistSupport::KernelTooOld, PersistSupport::UnsupportedOs] {
            let err = sink
                .persist_with_support(support)
                .expect_err("unsupported environment must be rejected");
            assert_eq!(err.code(), IoErrorCode::Unimplemented, "{support:?}");
            assert!(sink.dirty_since_persist, "{support:?}");
            assert!(!sink.persist_poisoned, "{support:?}");
        }
    }

    /// IO-2・IO-3（Codex #1146 P0）: macOS / Windows 方式の判定
    /// （`SupportedFileSync`）では、親ディレクトリが未指定の sink は新規作成
    /// ファイルのエントリを永続化できないため、実行 OS に関係なく syscall を
    /// 発行せず `Unimplemented` で拒否し、ポイズンも dirty 解除もしない。
    #[test]
    fn io2_file_sync_without_parent_dirs_is_rejected() {
        use crate::barrier::PersistSupport;
        let mut sink =
            AppendFileSink::new(temp_append_sink("no-parent-dirs").into_inner()).expect("sink");
        assert!(sink.parent_dirs.is_none());
        let err = sink
            .persist_with_support(PersistSupport::SupportedFileSync)
            .expect_err("missing parent dirs must be rejected");
        assert_eq!(err.code(), IoErrorCode::Unimplemented);
        assert!(err.message().contains("parent directories"), "{err:?}");
        assert!(sink.dirty_since_persist);
        assert!(!sink.persist_poisoned);
    }

    /// IO-2・IO-3（Codex #1146 P0）: 空のハンドル列を登録した sink も未指定と同じく
    /// `SupportedFileSync` で `Unimplemented` となり、ポイズンも dirty 解除もしない。
    #[test]
    fn io2_file_sync_with_empty_parent_dirs_is_rejected() {
        use crate::barrier::PersistSupport;
        let mut sink = AppendFileSink::new(temp_append_sink("empty-parent-dirs").into_inner())
            .expect("sink")
            .with_parent_dir_handles(vec![]);
        assert_eq!(sink.parent_dirs.as_ref().map(Vec::len), Some(0));
        let err = sink
            .persist_with_support(PersistSupport::SupportedFileSync)
            .expect_err("empty parent dirs must be rejected");
        assert_eq!(err.code(), IoErrorCode::Unimplemented);
        assert!(err.message().contains("parent directories"), "{err:?}");
        assert!(sink.dirty_since_persist);
        assert!(!sink.persist_poisoned);
    }

    /// 一時ディレクトリ（テストごとに一意）を作り、drop で消す。
    struct TempDirGuard(std::path::PathBuf);
    impl TempDirGuard {
        fn new(tag: &str) -> Self {
            use std::sync::atomic::{AtomicU32, Ordering};
            static N: AtomicU32 = AtomicU32::new(0);
            let path = std::env::temp_dir().join(format!(
                "fcio-open-in-{tag}-{}-{}",
                std::process::id(),
                N.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&path).expect("temp dir");
            Self(path)
        }
    }
    impl Drop for TempDirGuard {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// IO-2・IO-3・TASK-15.3（Codex #1146 P0）: `open_in` はファイルを開いたディレクトリの
    /// ハンドルを 1 つだけ親として登録し、未同期・dirty の状態で返す。mode ごとに作成・
    /// 既存のみ・追記・切り詰めを使い分け、ファイルは `dir` 直下にだけ作る。
    #[test]
    fn io2_open_in_registers_opening_directory() {
        let t = TempDirGuard::new("modes");
        let sink = AppendFileSink::open_in(&t.0, "a", SinkOpenMode::CreateNew).expect("create");
        assert_eq!(sink.parent_dirs.as_ref().map(Vec::len), Some(1));
        assert!(!sink.parent_dirs_synced);
        assert!(sink.dirty_since_persist);
        drop(sink);
        std::fs::write(t.0.join("a"), b"seed").expect("seed");
        assert_eq!(
            AppendFileSink::open_in(&t.0, "a", SinkOpenMode::CreateNew)
                .err()
                .map(|err| err.code()),
            Some(IoErrorCode::AlreadyExists)
        );
        assert!(AppendFileSink::open_in(&t.0, "a", SinkOpenMode::Existing).is_ok());
        assert!(AppendFileSink::open_in(&t.0, "a", SinkOpenMode::CreateOrAppend).is_ok());
        assert_eq!(std::fs::read(t.0.join("a")).expect("a"), b"seed");
        assert!(AppendFileSink::open_in(&t.0, "a", SinkOpenMode::CreateOrTruncate).is_ok());
        assert_eq!(std::fs::read(t.0.join("a")).expect("a"), b"");
        assert_eq!(
            AppendFileSink::open_in(&t.0, "missing", SinkOpenMode::Existing)
                .err()
                .map(|err| err.code()),
            Some(IoErrorCode::Internal)
        );
        assert!(!t.0.join("missing").exists());
    }

    /// IO-2・IO-5・TASK-15.3: `open_in` の `name` は単一の通常の名前に限り、`dir` の外や
    /// 祖先を指す名前は何も開かずに `InvalidArgument` で拒否する。
    #[test]
    fn io2_open_in_rejects_names_outside_directory() {
        let t = TempDirGuard::new("names");
        let inner = t.0.join("inner");
        std::fs::create_dir(&inner).expect("inner");
        for name in ["", ".", "..", "../x", "a/b", "a\\b", "a:b", "a\0b"] {
            assert_eq!(
                AppendFileSink::open_in(&inner, name, SinkOpenMode::CreateOrTruncate)
                    .err()
                    .map(|err| err.code()),
                Some(IoErrorCode::InvalidArgument),
                "{name:?}"
            );
        }
        assert_eq!(std::fs::read_dir(&inner).expect("inner").count(), 0);
        assert_eq!(std::fs::read_dir(&t.0).expect("outer").count(), 1);
    }

    /// IO-2・TASK-15.3: `open_in` は通常ファイル以外（ディレクトリ）を sink にしない。
    /// `dir` がディレクトリでなければ失敗する。
    #[test]
    fn io2_open_in_rejects_non_regular_targets() {
        let t = TempDirGuard::new("nonreg");
        std::fs::create_dir(t.0.join("sub")).expect("sub");
        std::fs::write(t.0.join("file"), b"x").expect("file");
        assert!(AppendFileSink::open_in(&t.0, "sub", SinkOpenMode::Existing).is_err());
        assert!(AppendFileSink::open_in(&t.0.join("file"), "x", SinkOpenMode::CreateNew).is_err());
        assert!(!t.0.join("file").join("x").exists());
    }

    /// IO-2・TASK-15.3: 末端が symlink なら、どの mode でも辿らずに失敗し、リンク先を
    /// 作らない・切り詰めない（切り詰めは通常ファイルと確かめた後にだけ行う）。
    #[cfg(unix)]
    #[test]
    fn io2_open_in_does_not_follow_or_truncate_symlink_leaf() {
        let t = TempDirGuard::new("symlink");
        let target = t.0.join("target");
        std::fs::write(&target, b"keep").expect("target");
        std::os::unix::fs::symlink(&target, t.0.join("l")).expect("symlink");
        std::os::unix::fs::symlink(t.0.join("absent"), t.0.join("dangling")).expect("dangling");
        for mode in [
            SinkOpenMode::CreateNew,
            SinkOpenMode::CreateOrTruncate,
            SinkOpenMode::Existing,
            SinkOpenMode::CreateOrAppend,
        ] {
            assert!(
                AppendFileSink::open_in(&t.0, "l", mode).is_err(),
                "{mode:?}"
            );
            assert!(
                AppendFileSink::open_in(&t.0, "dangling", mode).is_err(),
                "{mode:?}"
            );
        }
        assert_eq!(std::fs::read(&target).expect("target"), b"keep");
        assert!(!t.0.join("absent").exists());
    }

    /// IO-2・IO-3・TASK-15.3（Codex #1146 P0）: `open_in` が登録するのはファイルを開いた
    /// ディレクトリの実体で、開いた後に `dir` のパスが別のディレクトリへ差し替えられても
    /// 変わらない（パスを再解決しない）。差し替え後のパスに同名のファイルがあっても、sink の
    /// 書き込みは元のディレクトリのファイルに入る。
    #[cfg(unix)]
    #[test]
    fn io2_open_in_keeps_directory_after_path_swap() {
        use std::os::unix::fs::MetadataExt;
        let t = TempDirGuard::new("swap");
        let dir = t.0.join("d");
        std::fs::create_dir(&dir).expect("d");
        let sink = AppendFileSink::open_in(&dir, "f", SinkOpenMode::CreateNew).expect("sink");
        let original = std::fs::metadata(&dir).expect("meta").ino();
        std::fs::rename(&dir, t.0.join("moved")).expect("move d");
        std::fs::create_dir(&dir).expect("new d");
        std::fs::write(dir.join("f"), b"decoy").expect("decoy");
        let handles = sink.parent_dirs.as_ref().expect("parent dirs");
        assert_eq!(handles.len(), 1);
        let held = handles
            .first()
            .expect("one handle")
            .metadata()
            .expect("meta");
        assert_eq!(held.ino(), original);
        assert_ne!(held.ino(), std::fs::metadata(&dir).expect("meta").ino());
        let mut sink = sink;
        let mut buffer = BatchBuffer::new(BatchConfig::new(1).expect("1 must be valid"));
        let batch = match buffer.push(write_frame(0, b"x")).expect("push") {
            PushOutcome::Ready(batch) => batch,
            other => panic!("expected Ready, got {other:?}"),
        };
        sink.write_batch(&batch).expect("write");
        assert_eq!(std::fs::read(t.0.join("moved").join("f")).expect("f"), b"x");
        assert_eq!(std::fs::read(dir.join("f")).expect("decoy"), b"decoy");
    }

    /// IO-2・IO-3（Codex #1146 P0）: persist 済みの sink にハンドルを登録し直すと
    /// 未永続化状態へ戻り、次の persist が登録したディレクトリを必ず同期する。
    #[test]
    fn io2_parent_dir_handles_after_persist_marks_dirty() {
        let t = TempDirGuard::new("dirty");
        let mut sink =
            AppendFileSink::new(temp_append_sink("dirs-dirty").into_inner()).expect("sink");
        sink.dirty_since_persist = false;
        sink.parent_dirs_synced = true;
        let mut options = std::fs::OpenOptions::new();
        options.read(true);
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            // FILE_FLAG_BACKUP_SEMANTICS（ディレクトリを開くのに必須）。
            options.custom_flags(0x0200_0000);
        }
        let handle = options.open(&t.0).expect("open dir");
        let sink = sink.with_parent_dir_handles(vec![handle]);
        assert!(sink.dirty_since_persist);
        assert!(!sink.parent_dirs_synced);
        assert_eq!(sink.parent_dirs.as_ref().map(Vec::len), Some(1));
    }

    /// IO-2（#824 A4）・REPAIR-5: syncfs の同時実行数の枠が埋まったまま FLUSH の
    /// 期限を過ぎると、FlushAck を返さず `Timeout` で確定する（Write の ACK は届く）。
    /// syncfs は未発行のため sink はポイズンされず dirty のままで、枠が空けば次の
    /// persist は成功する。
    ///
    /// `serve_connection` 経由の期待値は production と同じ判定（`persist_support`）で
    /// 分ける（非対応環境では枠を待たず `Unimplemented`）。枠待ちの経路そのものは
    /// 判定を `Supported` に注入してどのカーネル版数でも照合する。
    #[cfg(target_os = "linux")]
    #[test]
    fn io2_writeback_flush_times_out_waiting_for_syncfs_slot() {
        use crate::barrier::{PersistLimiter, PersistSupport};
        static L: PersistLimiter = PersistLimiter::new(1);
        // 枠を占有する helper（戻るまで枠を保持する）。
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let (started_tx, started_rx) = std::sync::mpsc::channel::<()>();
        let holder = std::thread::spawn(move || {
            let slot = L
                .acquire(std::time::Instant::now() + Duration::from_secs(5))
                .expect("holder must get the only slot");
            let _ = started_tx.send(());
            let _ = release_rx.recv();
            drop(slot);
        });
        started_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("holder must take the slot");

        let mut sink = temp_append_sink("slot-timeout");
        sink.persist_limiter = &L;
        sink.flush_timeout = IoTimeout::new(Duration::from_millis(100)).expect("valid timeout");
        let mut conn = FakeTransport::new(vec![write_frame(0, b"a"), flush_frame(1)]);

        let report = serve_connection(&mut conn, BatchConfig::default(), &mut sink, timeouts());

        assert_eq!(report.stats.flush_acks_sent, 0);
        assert_eq!(report.stats.persist_failed, 1);
        assert_eq!(conn.sent.len(), 1);
        assert_eq!(conn.sent[0].kind(), FrameKind::Ack);
        let support = crate::barrier::persist_support();
        if support.is_supported() {
            assert_eq!(report.end.code(), IoErrorCode::Timeout);
            assert!(report.end.message().contains("syncfs slot"));
        } else {
            assert_eq!(report.end.code(), IoErrorCode::Unimplemented, "{support:?}");
        }
        assert!(!sink.persist_poisoned);
        assert!(sink.dirty_since_persist);

        // 判定を注入した枠待ちの経路（カーネル版数に依存しない）。
        let err = sink
            .persist_with_support(PersistSupport::Supported)
            .expect_err("slot is still occupied");
        assert_eq!(err.code(), IoErrorCode::Timeout);
        assert!(!sink.persist_poisoned);
        assert!(sink.dirty_since_persist);

        // 枠が空けば、同じ sink の persist は自分の fd で syncfs を発行して成功する。
        release_tx.send(()).expect("holder still waiting");
        holder.join().expect("holder must not panic");
        // 実 syncfs はファイルシステム全体を書き戻すため、CI runner では数秒
        // かかりうる。許容上限（MAX_IO_TIMEOUT）まで待つ。
        sink.flush_timeout = IoTimeout::new(MAX_IO_TIMEOUT).expect("valid timeout");
        sink.persist_with_support(PersistSupport::Supported)
            .expect("persist must succeed once the slot is free");
        assert!(!sink.dirty_since_persist);
        assert_eq!(L.running(), 0);
    }

    /// IO-2・TASK-15.2.2（受け入れ条件 2）: 実際の `syncfs` ラッパーが失敗
    /// （O_PATH の fd は EBADF）すると FlushAck を返さず `Internal` で終わり、
    /// sink はポイズンされて以後の persist は syscall なしで `Internal`。
    ///
    /// `serve_connection` 経由の期待値は production と同じ判定（`persist_support`）
    /// で分ける（非対応環境では syscall を発行せず `Unimplemented`。Codex #1142
    /// 指摘）。実 syscall の失敗とポイズンは、判定を `Supported` に注入して
    /// どのカーネル版数でも照合する（EBADF はカーネル版数に依存しない）。
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[test]
    fn io2_writeback_real_syncfs_failure_sends_no_flush_ack_and_poisons() {
        use crate::barrier::{PersistLimiter, PersistSupport};
        use std::os::unix::fs::OpenOptionsExt as _;
        // 並列に走る他のテストの実 syncfs とプロセス全体の枠を奪い合わないよう、
        // このテスト専用の limiter を使う（枠待ちの期限切れで Timeout にならない）。
        static L: PersistLimiter = PersistLimiter::new(1);
        // O_PATH（x86_64・aarch64 とも 0o10000000）。`syncfs` は EBADF で失敗する。
        const O_PATH: i32 = 0o10_000_000;
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(O_PATH)
            .open(std::env::temp_dir())
            .expect("open temp dir with O_PATH");
        let mut sink = AppendFileSink {
            file,
            flush_timeout: test_timeout(),
            persist_poisoned: false,
            dirty_since_persist: true,
            persist_limiter: &L,
            parent_dirs: None,
            parent_dirs_synced: false,
        };
        let mut conn = FakeTransport::new(vec![flush_frame(0)]);

        let report = serve_connection(&mut conn, BatchConfig::default(), &mut sink, timeouts());

        // どちらの経路でも FlushAck は送らない（fail-closed）。
        assert_eq!(report.stats.flush_acks_sent, 0);
        assert_eq!(report.stats.persist_failed, 1);
        assert!(conn.sent.is_empty());
        let support = crate::barrier::persist_support();
        if support.is_supported() {
            assert_eq!(report.end.code(), IoErrorCode::Internal);
            assert!(report.end.message().contains("syncfs failed"));
            assert!(sink.persist_poisoned);
        } else {
            // 非対応環境: syscall を発行せず拒否し、ポイズンしない。
            assert_eq!(report.end.code(), IoErrorCode::Unimplemented, "{support:?}");
            assert!(!sink.persist_poisoned);
            let err = sink
                .persist_with_support(PersistSupport::Supported)
                .expect_err("syncfs on an O_PATH fd must fail");
            assert_eq!(err.code(), IoErrorCode::Internal);
            assert!(err.message().contains("syncfs failed"));
            assert!(sink.persist_poisoned);
        }

        let err = sink
            .persist_with_support(PersistSupport::Supported)
            .expect_err("poisoned sink must fail");
        assert_eq!(err.code(), IoErrorCode::Internal);
        assert!(err.message().contains("poisoned"));
    }
}
