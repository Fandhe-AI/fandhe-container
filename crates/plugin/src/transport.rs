//! plugin 境界の UDS 転送層（PLUG-2・TASK-107.4・#248・TASK-107.5・#249・MS-3）。
//!
//! core 側が plugin プロセスからの接続を待ち受ける `UdsListener`（bind / listen / accept）と、
//! accept / connect で得た検証済み 1 接続を表す `UdsStream` を提供する。待ち受けは core 側
//! （TASK-109・TASK-114）、接続（`UdsStream::connect`）は plugin プロセス側が使う。フレーム符号化（#245・#247）は本型の `Read` / `Write`
//! の上に載る。
//!
//! # PLUG-12 の保護（本モジュールで実施する範囲）
//!
//! - bind 前に socket 配置ディレクトリを検証する: symlink でない・自 UID 所有・group/other の
//!   権限が一切ない（0700 相当）。他 UID はこのディレクトリを辿れないため、socket の mode が
//!   bind 直後の umask 次第でも他 UID が接続できる窓は生じない（0600 化は多層防御）
//! - 配置ディレクトリへの経路は `canonicalize` 後にルートから 1 要素ずつ `openat(O_NOFOLLOW)` で
//!   辿り（検証後に祖先が symlink へ差し替わると失敗）、bind 自体も検証済み fd 基準で行う
//!   （Linux は `/proc/self/fd/<fd>/<name>`。祖先パスを再解決しない。macOS は bind 自体に残余あり〔`bind_target` 参照〕。bind 後の識別情報の確認は macOS も `fstatat` で fd 基準。#1307）
//! - 配置ディレクトリは 1 度だけ開いた fd（検証対象そのもの）を保持し、bind 後の 0600 化
//!   （`fchmodat(dirfd, name, AT_SYMLINK_NOFOLLOW)`）と Drop 時の削除（`unlinkat(dirfd, name)`）は
//!   その fd 基準で行う。パスを再解決しないため、検証後に中間要素・`..`・symlink が差し替わっても
//!   別ファイルの chmod・削除には到達しない。bind パスの `..` は拒否する
//! - 接続先として公開する [`UdsListener::path`] は、検証済み配置ディレクトリの解決後パス
//!   （`canonicalize` 結果）＋ socket 名とする。呼び出し側が渡した symlink を含む経路は保持しない
//!   ため、bind 後にその symlink が差し替わっても、`path()` を使う client が別の接続先へ誘導されない
//! - 公開パスと bind に使うパスの両方が `sockaddr_un.sun_path`（Linux 108・macOS 104 バイト。終端
//!   NUL 込み）に収まることを bind 前に確認し、超える場合は socket を作らず `InvalidArgument` で
//!   拒否する（bind できても公開パスで接続できない構成を作らない。PLUG-2）
//! - 残余: 0700 の自 UID 所有ディレクトリ内でエントリを差し替えられるのは同一 UID のみで、
//!   同一 UID は脅威モデル外（socket と同一性の照合は行わず、ディレクトリ fd 基準で名前を操作する）
//! - peer 認証で拒否した接続は 1 件ごとに監査イベントとして通知する（`crate::audit`。
//!   `accept_observed` / `connect_observed`、未指定の `accept` / `connect` は stderr へ JSON Lines。
//!   SEC-4・TASK-124.5・#1388）。永続的な監査ログへの配線は core 側 proxy（TASK-114）で未実装（REPAIR-3）
//! - accept した接続の peer credential（`SO_PEERCRED` / `getpeereid`。`crate::sys`）を検証し、
//!   自 UID 以外は切断して `PermissionDenied` を返す
//! - 受け付けた接続には既定の read / write 期限を付ける（REPAIR-5）
//! - client 接続（`UdsStream::connect`）は connect 自体に期限を付け、接続直後に server の peer
//!   credential を自 UID と照合する（不一致は 1 バイトも送らず切断。listener 側 accept と対称。
//!   同一 UID の偽 listener は脅威モデル外。socket 配置ディレクトリの検証は client では行わない）
//!
//! # フレーム単位の待機（REPAIR-5・TASK-107.6・#250）
//!
//! [`UdsStream::read_frame`] / [`UdsStream::write_frame`] は [`RpcTimeout`]（必須引数。0 と上限超過は
//! 構築不能）を取り、syscall 1 回ごとではなく **フレーム全体の合計期限** で打ち切る（少量ずつ送り
//! 続ける相手による引き延ばしを防ぐ）。期限切れは `Timeout`、相手切断は `Unavailable`、
//! チェックサム不一致は `DataLoss`。受信は固定長ヘッダを検証（長さ上限）してから本体を小さな塊ずつ
//! 確保する。途中でエラーになった接続はフレーム境界がずれうるため以後使用不可（`Unavailable`）に
//! なる。呼び出し側は再接続する（fail-closed）。
//!
//! # 未実装の範囲（REPAIR-3）
//!
//! - 既存パスは bind 前に lstat 検証する（PLUG-12・TASK-123.2）。symlink・他 UID 所有は削除せず
//!   `PermissionDenied`、生存中の listener や socket 以外は `AlreadyExists`、bind ロックを取得でき管理下の
//!   自 UID 所有 stale socket のみ削除して再 bind する（詳細は `uds_security` モジュール doc）
//! - gRPC（TASK-108）
//! - 要求 ID と応答 ID の対応づけ・要求→応答の 1 往復ヘルパー（core 側 proxy。TASK-114）
//! - ACK 専用のワイヤー種別（`ControlMessage` のワイヤー形変更を伴うため行わない。本 crate での
//!   「ACK / RPC 応答待ち」は [`UdsStream::read_frame`] を指す）
//!
//! # cfg 方針
//!
//! 実体は `cfg(unix)` の `std::os::unix::net` のみ。それ以外の OS では `bind` が
//! `Unimplemented` を返す（Windows は WIN-1 により WSL2 内の Linux 側機構に乗る。理由は `uds_security` のモジュール doc 参照）。

use std::io::{self, Read, Write};
use std::path::Path;
use std::time::Duration;

use crate::audit::{PeerAuthObserver, StderrPeerAuthObserver};
use crate::error::{PluginError, PluginErrorCode};
use crate::frame::Frame;

/// `accept` の期限の上限。これを超える指定は `InvalidArgument`（REPAIR-5）。
/// 接続待ち（`connect`）は [`UDS_CONNECT_TIMEOUT_MAX`]、フレーム待ちは [`RpcTimeout`] が別に持つ。
pub const UDS_ACCEPT_TIMEOUT_MAX: Duration = Duration::from_secs(600);

/// `UdsStream::connect` の期限の上限（600 秒）。これを超える指定は `InvalidArgument`（REPAIR-5）。
/// 接続待ちと RPC 応答待ちは目的が違うため、[`UDS_RPC_TIMEOUT_MAX`] とは別の定数にしている。
pub const UDS_CONNECT_TIMEOUT_MAX: Duration = Duration::from_secs(600);

/// 生の `Read` / `Write` の既定の 1 回あたり read / write 期限（REPAIR-5。安全網）。
/// フレーム単位の待機は [`UdsStream::read_frame`] / [`UdsStream::write_frame`] の [`RpcTimeout`] が
/// 合計期限を持つ。[`UdsStream::set_io_timeout`] で変更できる。
pub const UDS_DEFAULT_IO_TIMEOUT: Duration = Duration::from_secs(30);

/// ACK / RPC 応答待ち 1 回分の既定のタイムアウト（10 秒。`RpcTimeout::default()`）。
///
/// AGENTS.md「推奨タイムアウト値」の 5〜10 秒のレンジ上限。PLUG-2・PLUG-5・REPAIR-5・
/// TASK-107.6（#250）。
pub const UDS_RPC_TIMEOUT_DEFAULT: Duration = Duration::from_secs(10);

/// [`RpcTimeout`] の上限（10 秒）。これを超える指定は `InvalidArgument`（REPAIR-5）。
///
/// 長時間待ちが必要な RPC（イメージ取得等）が出てきても本定数は緩めず、根拠つきで別の型・定数に
/// 分離する（検出が弱まる方向の変更を避ける。TASK-114 設計時に再検討）。
pub const UDS_RPC_TIMEOUT_MAX: Duration = Duration::from_secs(10);

/// ACK / RPC 応答待ちのタイムアウト（PLUG-2・PLUG-5・REPAIR-5・TASK-107.6・#250）。
///
/// 呼び出し側が [`UdsStream::read_frame`] / [`UdsStream::write_frame`] へ必ず明示する値で、0 と
/// [`UDS_RPC_TIMEOUT_MAX`] 超は構築できない（無期限待ちを型として表現できない。REPAIR-2 の考え方）。
/// 既定値は [`UDS_RPC_TIMEOUT_DEFAULT`]（10 秒。`Default`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RpcTimeout(Duration);

impl RpcTimeout {
    /// 0 または [`UDS_RPC_TIMEOUT_MAX`] 超は `InvalidArgument`。
    pub fn new(timeout: Duration) -> Result<Self, PluginError> {
        if timeout.is_zero() || timeout > UDS_RPC_TIMEOUT_MAX {
            return Err(PluginError::new(
                PluginErrorCode::InvalidArgument,
                "rpc timeout must be non-zero and within the maximum",
            ));
        }
        Ok(Self(timeout))
    }

    /// 保持している期間を返す。
    pub fn as_duration(&self) -> Duration {
        self.0
    }
}

impl Default for RpcTimeout {
    /// [`UDS_RPC_TIMEOUT_DEFAULT`]（10 秒）。
    fn default() -> Self {
        Self(UDS_RPC_TIMEOUT_DEFAULT)
    }
}

impl TryFrom<Duration> for RpcTimeout {
    type Error = PluginError;

    fn try_from(timeout: Duration) -> Result<Self, Self::Error> {
        Self::new(timeout)
    }
}

/// plugin からの接続を待ち受ける UDS listener（PLUG-2・PLUG-12）。
///
/// Drop 時は自分が作った socket ファイルに限り best-effort で削除する。
#[derive(Debug)]
pub struct UdsListener {
    inner: imp::ListenerInner,
}

impl UdsListener {
    /// `path` に UDS を bind し listen する（PLUG-2）。
    ///
    /// 既存パスは unlink せず `AlreadyExists` で拒否する（fail-closed）。
    /// 配置ディレクトリ（symlink 不可・自 UID 所有・0700 相当）を検証してから bind する。
    /// 相対パスは bind 時点の絶対パスへ変換し、配置ディレクトリの symlink を解決した実体のパスを
    /// 保持する（Drop 時の cwd 変更・bind 後の symlink 差し替えの影響を避ける。[`Self::path`] 参照）。
    /// 解決後のパス（[`Self::path`]）が `sun_path` の長さ制限を超える場合は `InvalidArgument`
    /// （Linux は bind に使う `/proc/self/fd/<fd>/<名前>` も同じ制限を受けるため、socket 名が
    /// 長い場合も拒否する）。
    ///
    /// 既存エントリがある場合は lstat で検証する（PLUG-12・TASK-123.2）。symlink・他 UID 所有は削除せず
    /// `PermissionDenied`、生存中の listener・socket 以外は `AlreadyExists`、自 UID 所有の stale socket
    /// （bind ロックを取得でき管理下のもの）のみ削除して再 bind する。
    pub fn bind(path: &Path) -> Result<Self, PluginError> {
        // `..` は bind 時点とそれ以降で解決先が変わりうるため拒否する（`std::path::absolute` は
        // `..` を残す。PLUG-12）。
        if path
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            return Err(PluginError::new(
                PluginErrorCode::InvalidArgument,
                "socket path must not contain parent directory components",
            ));
        }
        let abs = std::path::absolute(path).map_err(|_| {
            PluginError::new(PluginErrorCode::InvalidArgument, "invalid socket path")
        })?;
        let inner = imp::ListenerInner::bind(&abs)?;
        Ok(Self { inner })
    }

    /// 1 接続を期限付きで受け付ける（REPAIR-5）。
    ///
    /// `timeout` が 0 または [`UDS_ACCEPT_TIMEOUT_MAX`] 超なら `InvalidArgument`、期限切れは `Timeout`。
    /// 1 呼び出しで 1 接続まで。受付ループ・同時接続数の上限は呼び出し側（TASK-109・TASK-114）の責務。
    /// 返す接続は peer credential が自 UID であることを確認済み。不一致は接続を切断して
    /// `PermissionDenied` を返す（呼び出し側の受付ループは継続してよい）。
    ///
    /// 拒否した接続は既定の出力先（stderr の JSON Lines 1 行）へ監査イベントとして通知する
    /// （PLUG-12・SEC-4・TASK-124.5）。出力先を指定する場合は [`Self::accept_observed`]。
    /// 通知は非同期の出力キューへの投入までで出力完了を待たない（REPAIR-5）。拒否の直後に終了する
    /// プロセスは、終了前に [`crate::audit::flush_default_audit`] を呼んで回収する。
    pub fn accept(&self, timeout: Duration) -> Result<UdsStream, PluginError> {
        self.accept_observed(timeout, &mut StderrPeerAuthObserver)
    }

    /// [`Self::accept`] の監査イベント出力先指定版（PLUG-12・SEC-4・TASK-124.5・#1388）。
    ///
    /// peer 認証で拒否した接続 1 件につき `observer` へ 1 件通知する（UID 不一致・peer UID 取得失敗）。
    /// 通知は切断後・エラー返却前に行い、返すエラーは `accept` と同じ（UID 値を含まない固定文言）。
    /// 観測しない場合は `NoopPeerAuthObserver` を明示的に渡す。
    pub fn accept_observed(
        &self,
        timeout: Duration,
        observer: &mut dyn PeerAuthObserver,
    ) -> Result<UdsStream, PluginError> {
        if timeout.is_zero() || timeout > UDS_ACCEPT_TIMEOUT_MAX {
            return Err(PluginError::new(
                PluginErrorCode::InvalidArgument,
                "accept timeout must be non-zero and within the maximum",
            ));
        }
        self.inner
            .accept(timeout, None, &mut || None, observer)
            .map(|inner| UdsStream {
                inner,
                poisoned: false,
                io_timeout_unrestored: false,
            })
    }

    /// [`Self::accept`] に「応答者を特定の子プロセスに限定する」「待機中に中断条件を確認する」を加えた版
    /// （都度起動モード専用。PLUG-7・PLUG-12・REPAIR-5。`crate::lifecycle::call_once` が使う）。
    ///
    /// peer の pid が `expected_pid` と一致しない接続（同一 UID の別プロセス）は切断して受付を継続する
    /// （期限内に限る。pid を取得できない環境は fail-closed でエラー）。pid 照合は数値比較のため、子の終了後に
    /// 同じ pid が再利用される窓が残る（pidfd 等での緩和は将来課題。`crate::sys` の「限界」・PLUG-12）。接続待ちの間は `abort` を
    /// 繰り返し呼び、`Some(err)` を返したらその `err` で受付を中断する。保留中の接続がある場合は
    /// `abort` より接続の受理を優先する（期限切れ間際に届いた接続を取りこぼさない）。
    /// 拒否した接続（UID・pid の不一致・取得失敗）は 1 件ごとに `observer` へ通知する（TASK-124.5）。
    pub(crate) fn accept_peer_pid(
        &self,
        timeout: Duration,
        expected_pid: u32,
        abort: &mut dyn FnMut() -> Option<PluginError>,
        observer: &mut dyn PeerAuthObserver,
    ) -> Result<UdsStream, PluginError> {
        if timeout.is_zero() || timeout > UDS_ACCEPT_TIMEOUT_MAX {
            return Err(PluginError::new(
                PluginErrorCode::InvalidArgument,
                "accept timeout must be non-zero and within the maximum",
            ));
        }
        self.inner
            .accept(timeout, Some(expected_pid), abort, observer)
            .map(|inner| UdsStream {
                inner,
                poisoned: false,
                io_timeout_unrestored: false,
            })
    }

    /// client が接続に使う socket のパスを返す（PLUG-12）。
    ///
    /// `bind` に渡したパスそのものではなく、検証済み配置ディレクトリの解決後パス（symlink を
    /// 含まない絶対パス）＋ socket 名を返す。渡したパスの祖先に symlink があっても、bind 後の
    /// 差し替えで本パスの指す先は変わらない（実際に socket を作成したディレクトリを指し続ける）。
    pub fn path(&self) -> &Path {
        self.inner.path()
    }
}

impl Drop for UdsListener {
    fn drop(&mut self) {
        // 検証済み配置ディレクトリ fd 基準の unlinkat で削除する（パス再解決なし）。
        // 既存 socket の stale 判定・削除は bind 時（`clear_stale_socket`。TASK-123.2）に行う。
        self.inner.cleanup();
    }
}

/// accept / connect で得た検証済み 1 接続（peer credential 検証済み。PLUG-12）。生の read / write には
/// [`UDS_DEFAULT_IO_TIMEOUT`] の期限が付く（REPAIR-5）。フレーム単位の送受信は
/// [`Self::read_frame`] / [`Self::write_frame`]（合計期限つき）を使う。
#[derive(Debug)]
pub struct UdsStream {
    inner: imp::StreamInner,
    /// フレーム I/O が失敗した接続はフレーム境界がずれうるため以後使用不可にする（fail-closed）。
    poisoned: bool,
    /// 相手切断により socket の既定期限を復元できなかった接続。生の read / write は想定外の期限で
    /// 待ちうるため拒否する（REPAIR-5）。フレーム I/O は操作ごとに自前の期限を掛け直すため
    /// 続行でき、相手が切断前に送り終えたフレームを受信バッファから読める。
    io_timeout_unrestored: bool,
}

impl UdsStream {
    /// plugin プロセス側から core の UDS（[`UdsListener::path`] が想定入力）へ期限付きで接続する
    /// （PLUG-2・PLUG-12・REPAIR-5）。#250 の RPC 待機がこの接続の上に載る。
    ///
    /// `timeout` が 0 または [`UDS_CONNECT_TIMEOUT_MAX`] 超なら `InvalidArgument`。パスが空・内部 NUL・`sun_path` 超過の場合も `InvalidArgument`。
    /// 存在しなければ `NotFound`、listener 不在の stale socket は `Unavailable`、権限不足は
    /// `PermissionDenied`、期限切れ（backlog 満杯を含む）は `Timeout`。接続後に server の peer UID が
    /// 自 UID でなければ切断して `PermissionDenied`、取得できない環境は `Unimplemented`（fail-closed）。
    ///
    /// server の peer 認証で拒否した場合は既定の出力先（stderr の JSON Lines 1 行）へ監査イベントを
    /// 通知する（PLUG-12・SEC-4・TASK-124.5）。出力先を指定する場合は [`Self::connect_observed`]。
    /// 通知は非同期の出力キューへの投入までで出力完了を待たない（REPAIR-5）。拒否の直後に終了する
    /// プロセスは、終了前に [`crate::audit::flush_default_audit`] を呼んで回収する。
    pub fn connect(path: &Path, timeout: Duration) -> Result<Self, PluginError> {
        Self::connect_observed(path, timeout, &mut StderrPeerAuthObserver)
    }

    /// [`Self::connect`] の監査イベント出力先指定版（PLUG-12・SEC-4・TASK-124.5・#1388）。
    /// 拒否 1 件につき `observer` へ 1 件通知する。返すエラーは `connect` と同じ。
    pub fn connect_observed(
        path: &Path,
        timeout: Duration,
        observer: &mut dyn PeerAuthObserver,
    ) -> Result<Self, PluginError> {
        if timeout.is_zero() || timeout > UDS_CONNECT_TIMEOUT_MAX {
            return Err(PluginError::new(
                PluginErrorCode::InvalidArgument,
                "connect timeout must be non-zero and within the maximum",
            ));
        }
        imp::StreamInner::connect(path, timeout, observer).map(|inner| Self {
            inner,
            poisoned: false,
            io_timeout_unrestored: false,
        })
    }

    /// read / write の期限を変更する。0 は `InvalidArgument`（無期限にしない。REPAIR-5）。
    pub fn set_io_timeout(&self, timeout: Duration) -> Result<(), PluginError> {
        self.inner.set_io_timeout(timeout)
    }

    /// 相手からのフレーム 1 つ（ACK・RPC 応答・要求のいずれも）を合計 `timeout` 以内に受ける
    /// （PLUG-2・PLUG-5・REPAIR-5）。
    ///
    /// 期限切れは `Timeout`、相手切断は `Unavailable`、長さ超過・チェックサム不一致は検証エラー
    /// （`InvalidArgument`・`DataLoss`）。失敗した接続は以後使用不可（`Unavailable`）になるため、
    /// 呼び出し側は再接続する（`crates/io` の `FrameSender` と同じ契約）。
    /// 呼び出し前の read / write 期限（[`UDS_DEFAULT_IO_TIMEOUT`] 等）は呼び出し後に復元する。
    /// 相手切断で復元できなかった場合、以後の生 read / write は拒否するが、フレーム I/O は続行できる
    /// （切断前に相手が送り終えたフレームは読める。読み切った後は `Unavailable`）。
    pub fn read_frame(&mut self, timeout: RpcTimeout) -> Result<Frame, PluginError> {
        if self.poisoned {
            return Err(poisoned_error());
        }
        let (result, restored) = self.inner.read_frame(timeout);
        self.finish_frame_op(result, restored)
    }

    /// フレーム 1 つを合計 `timeout` 以内に全量送る（PLUG-2・PLUG-5・REPAIR-5）。相手が読まず
    /// 送信バッファが詰まった場合も `Timeout` で打ち切る。失敗後の扱いは [`Self::read_frame`] と同じ。
    pub fn write_frame(&mut self, frame: &Frame, timeout: RpcTimeout) -> Result<(), PluginError> {
        if self.poisoned {
            return Err(poisoned_error());
        }
        let (result, restored) = self.inner.write_frame(frame, timeout);
        self.finish_frame_op(result, restored)
    }

    /// フレーム操作の後始末（REPAIR-5）。
    ///
    /// - 操作の失敗、または復元失敗（`Failed`）は接続を全面的に使用不可にする。`Failed` は Ok の
    ///   結果を握りつぶさずエラーとして返す。
    /// - `PeerClosed`（EINVAL。相手切断済みで復元不能）は操作結果を尊重し、生 I/O だけを拒否する。
    ///   フレーム I/O は拒否しない。要求の送信直後に相手が応答を書いて切断した場合、応答は受信
    ///   バッファに残っており、続く `read_frame` で読める必要があるため（都度起動モード。PLUG-7）。
    ///   フレーム I/O は操作ごとに自前の期限を掛け直し、期限を設定できない socket では
    ///   non-blocking で 1 回だけ試すので、既定期限が未復元でも無期限には待たない。
    /// - 既に `PeerClosed` を観測した接続では、以後の復元結果を問わない（切断済み socket では期限の
    ///   保存・復元がどちらも失敗し得る。生 I/O は拒否済みで、復元すべき期限の利用者がいない）。
    fn finish_frame_op<T>(
        &mut self,
        result: Result<T, PluginError>,
        restored: TimeoutRestore,
    ) -> Result<T, PluginError> {
        if result.is_err() {
            self.poisoned = true;
        }
        if self.io_timeout_unrestored {
            return result;
        }
        match restored {
            TimeoutRestore::Restored => result,
            TimeoutRestore::PeerClosed => {
                self.io_timeout_unrestored = true;
                result
            }
            TimeoutRestore::Failed => {
                self.poisoned = true;
                result.and_then(|_| {
                    Err(PluginError::new(
                        PluginErrorCode::Internal,
                        "failed to restore io timeout",
                    ))
                })
            }
        }
    }

    /// 失敗後、または既定期限を復元できなかった接続への生 I/O を拒否する（フレーム I/O と同じ
    /// 「失敗後は使用不可」契約。期限未復元の socket で生 I/O を待たせない。REPAIR-5）。
    fn check_raw_io(&self) -> io::Result<()> {
        if self.poisoned || self.io_timeout_unrestored {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "connection is unusable after a previous frame error",
            ));
        }
        Ok(())
    }
}

impl Read for UdsStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.check_raw_io()?;
        self.inner.read(buf)
    }
}

impl Write for UdsStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.check_raw_io()?;
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.check_raw_io()?;
        self.inner.flush()
    }
}

/// フレーム操作後の socket 期限の復元結果（REPAIR-5）。
///
/// 構築するのは unix 実装（`restore_timeouts`）のみ。他 OS では UDS が未実装で接続を作れず、
/// どの値も構築されないため、非 unix に限り未使用の警告を抑止する。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(unix), allow(dead_code))]
enum TimeoutRestore {
    /// 元の期限へ戻せた。
    Restored,
    /// 相手切断で復元できなかった（EINVAL）。生 I/O を拒否する（フレーム I/O は続行できる）。
    PeerClosed,
    /// 復元に失敗した、または元の期限を保存できなかった。
    Failed,
}

fn poisoned_error() -> PluginError {
    PluginError::new(
        PluginErrorCode::Unavailable,
        "connection is unusable after a previous frame error",
    )
}

/// フレーム I/O の方向（エラー message の出し分け用）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(unix), allow(dead_code))]
enum FrameOp {
    Read,
    Write,
}

/// フレーム I/O の `io::Error` を `PluginError` へ写像する（REPAIR-5）。期限切れ（`Timeout`）と
/// 相手切断（`Unavailable`）を区別する。パス・相手由来データはメッセージへ載せない。
#[cfg_attr(not(unix), allow(dead_code))]
fn map_frame_io_error(kind: io::ErrorKind, op: FrameOp) -> PluginError {
    let (code, message) = match (kind, op) {
        (io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut, FrameOp::Read) => {
            (PluginErrorCode::Timeout, "timed out waiting for a frame")
        }
        (io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut, FrameOp::Write) => {
            (PluginErrorCode::Timeout, "timed out sending a frame")
        }
        (
            io::ErrorKind::UnexpectedEof
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::BrokenPipe
            | io::ErrorKind::NotConnected,
            _,
        ) => (PluginErrorCode::Unavailable, "peer closed the connection"),
        (_, FrameOp::Read) => (PluginErrorCode::Internal, "failed to read a frame"),
        (_, FrameOp::Write) => (PluginErrorCode::Internal, "failed to send a frame"),
    };
    PluginError::new(code, message)
}

/// `bind` の `io::Error` を `PluginError` へ写像する。相手由来データはメッセージへ載せない。
#[cfg_attr(not(unix), allow(dead_code))]
fn map_bind_error(kind: io::ErrorKind) -> PluginError {
    let (code, message) = match kind {
        io::ErrorKind::AddrInUse | io::ErrorKind::AlreadyExists => (
            PluginErrorCode::AlreadyExists,
            "socket path is already in use",
        ),
        io::ErrorKind::PermissionDenied => (
            PluginErrorCode::PermissionDenied,
            "permission denied while binding socket",
        ),
        io::ErrorKind::NotFound => (
            PluginErrorCode::NotFound,
            "socket parent directory does not exist",
        ),
        io::ErrorKind::InvalidInput => (PluginErrorCode::InvalidArgument, "invalid socket path"),
        _ => (PluginErrorCode::Internal, "failed to bind socket"),
    };
    PluginError::new(code, message)
}

/// `connect` の `io::Error` を `PluginError` へ写像する。パス・相手由来データはメッセージへ載せない。
#[cfg_attr(not(unix), allow(dead_code))]
fn map_connect_error(kind: io::ErrorKind) -> PluginError {
    let (code, message) = match kind {
        io::ErrorKind::NotFound => (PluginErrorCode::NotFound, "socket does not exist"),
        io::ErrorKind::ConnectionRefused => (
            PluginErrorCode::Unavailable,
            "no listener is accepting on the socket",
        ),
        io::ErrorKind::PermissionDenied => (
            PluginErrorCode::PermissionDenied,
            "permission denied while connecting to socket",
        ),
        io::ErrorKind::InvalidInput => (PluginErrorCode::InvalidArgument, "invalid socket path"),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => {
            (PluginErrorCode::Timeout, "timed out connecting to socket")
        }
        io::ErrorKind::Unsupported => (
            PluginErrorCode::Unimplemented,
            "unix domain socket client is not supported on this platform",
        ),
        _ => (PluginErrorCode::Internal, "failed to connect to socket"),
    };
    PluginError::new(code, message)
}

#[cfg(unix)]
mod imp {
    use super::{
        FrameOp, PeerAuthObserver, RpcTimeout, TimeoutRestore, UDS_DEFAULT_IO_TIMEOUT,
        map_bind_error, map_connect_error, map_frame_io_error,
    };
    use crate::audit::{PeerAuthOp, PeerAuthRejectReason, PeerAuthRejection};
    use crate::error::{PluginError, PluginErrorCode};
    use crate::frame::{FRAME_HEADER_LEN, Frame, FrameHeader};
    use crate::sys;
    use std::ffi::CString;
    use std::fs::File;
    use std::io::{self, Read, Write};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::{Path, PathBuf};
    use std::thread;
    use std::time::{Duration, Instant};

    /// 受信本体バッファを伸ばす 1 回あたりの塊（ヘッダだけ送って巨大確保させない。REPAIR-5）。
    const BODY_CHUNK: usize = 64 * 1024;

    /// accept のポーリング間隔の上限（busy loop 回避。crates/io の ACCEPT_POLL_INTERVAL に合わせる）。
    const ACCEPT_POLL_INTERVAL: Duration = Duration::from_millis(5);

    /// accept のポーリング間隔の初期値。待ち始めは短く刻み、空振りのたびに倍々で
    /// [`ACCEPT_POLL_INTERVAL`] まで伸ばす。子プロセス起動直後に接続が届く都度起動の経路
    /// （PLUG-6・TASK-113.4）で、固定 5 ms の sleep 粒度（macOS では更に延びる）が接続受理の
    /// レイテンシへそのまま上乗せされるのを避けつつ、長い待ちでは従来どおりの低頻度に落ち着く。
    const ACCEPT_POLL_INITIAL: Duration = Duration::from_micros(250);

    fn denied(m: &'static str) -> PluginError {
        PluginError::new(PluginErrorCode::PermissionDenied, m)
    }

    /// 親ディレクトリを開き、symlink でなく、自 UID 所有で、group/other の権限が一切ないことを
    /// 開いた fd 自体に対して検証する（PLUG-12）。以降の chmod・unlink はこの fd 基準で行う。
    /// 他 UID は辿れないため、socket の mode が umask 次第でも他 UID が接続できる窓は生じない。
    fn open_parent_dir(path: &Path, euid: u32) -> Result<(File, PathBuf), PluginError> {
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .ok_or_else(|| denied("socket path has no parent directory"))?;
        let link_meta = std::fs::symlink_metadata(parent).map_err(|e| map_bind_error(e.kind()))?;
        if !link_meta.file_type().is_dir() {
            return Err(denied("socket parent is not a directory"));
        }
        // 祖先要素の symlink は canonicalize で解決した上で、解決後の絶対パスをルートから
        // 1 要素ずつ O_NOFOLLOW で辿って fd を得る。canonicalize 後に祖先が symlink へ差し替わると
        // openat が失敗する（fail-closed。PLUG-12）。
        let canonical = std::fs::canonicalize(parent).map_err(|e| map_bind_error(e.kind()))?;
        let dir = sys::open_dir_nofollow(&canonical).map_err(|e| match e.kind() {
            io::ErrorKind::NotFound => map_bind_error(e.kind()),
            _ => denied("socket directory path could not be opened without following symlinks"),
        })?;
        let meta = dir.metadata().map_err(|e| map_bind_error(e.kind()))?;
        // 開いた fd が symlink 判定した実体と同一であること（検査と open の間の差し替え検出）。
        if !meta.file_type().is_dir()
            || meta.dev() != link_meta.dev()
            || meta.ino() != link_meta.ino()
        {
            return Err(denied("socket directory changed during bind"));
        }
        if meta.uid() != euid {
            return Err(denied("socket directory is not owned by the current user"));
        }
        if meta.mode() & 0o077 != 0 {
            return Err(denied(
                "socket directory must not be accessible by group or others",
            ));
        }
        Ok((dir, canonical))
    }

    /// `sockaddr_un.sun_path` の容量（終端 NUL を含むバイト数）。Linux は 108。
    #[cfg(target_os = "linux")]
    pub(super) const SUN_PATH_CAPACITY: usize = 108;
    /// `sockaddr_un.sun_path` の容量（終端 NUL を含むバイト数）。macOS・BSD 系は 104。
    #[cfg(not(target_os = "linux"))]
    pub(super) const SUN_PATH_CAPACITY: usize = 104;

    /// `p` が `sun_path` に収まる（終端 NUL の 1 バイトを残せる）ことを確認する。
    /// 収まらないパスは bind も connect もできないため `InvalidArgument` で拒否する（PLUG-2）。
    pub(crate) fn check_sun_path_len(p: &Path) -> Result<(), PluginError> {
        if p.as_os_str().as_bytes().len() >= SUN_PATH_CAPACITY {
            return Err(PluginError::new(
                PluginErrorCode::InvalidArgument,
                "socket path is too long",
            ));
        }
        Ok(())
    }

    /// 検証済みディレクトリ fd 基準で bind するために kernel へ渡すパスを組み立てる（PLUG-12）。
    ///
    /// Linux: `/proc/self/fd/<fd>/<name>`。kernel が検証済み fd の指すディレクトリ直下に socket を
    /// 作る（祖先パスの再解決なし。`/proc` 不在なら bind が失敗＝fail-closed）。
    /// 他の unix（macOS）: `bindat` 相当が無いため `canonical/name`（＝公開パス）へ bind し、直後の
    /// `configure`（fd 基準の所有者・種別確認と 0600 化）で検証する。残余: 祖先ディレクトリの
    /// 書き込み権限を持つ他主体が bind の瞬間に差し替える窓が残る。bind 後の確認（`lstat_at`）は macOS でも `fstatat` で検証済み fd 基準（#1307）。
    fn bind_target(dir: &File, public: &Path, name: &Path) -> PathBuf {
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::io::AsRawFd;
            let _ = public;
            Path::new("/proc/self/fd")
                .join(dir.as_raw_fd().to_string())
                .join(name)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (dir, name);
            public.to_path_buf()
        }
    }

    #[derive(Debug)]
    pub(super) struct ListenerInner {
        listener: UnixListener,
        /// 検証済みの配置ディレクトリ fd（chmod・unlink の基準。パスを再解決しない）。
        dir: File,
        /// 配置ディレクトリ内の socket 名（NUL を含まない）。
        name: CString,
        /// bind 排他ロック（listener の生存期間中保持し、stale 判定の根拠になる。TASK-123.2）。
        lock: crate::uds_security::BindLock,
        /// socket の公開パス（検証済み配置ディレクトリの `canonicalize` 結果＋socket 名。
        /// `UdsListener::path` が返す。PLUG-12）。Linux 以外では identity 取得の縮退にも使う。
        path: PathBuf,
        /// bind 直後の socket の識別情報。取得失敗時は None（Drop で削除しない）。
        identity: Option<sys::FileIdent>,
        /// bind 時点の自プロセスの実効 uid（accept ごとの peer 照合の基準）。
        euid: u32,
        /// テスト専用: peer 認証で拒否した接続を drop せず退避する（PLUG-12・TASK-124.6・#1389）。
        /// 拒否時に相手が先送りしたフレームが 1 バイトも読まれていないことを、退避した stream から
        /// 受信キューを読んで照合するため。リリースビルドには存在せず、拒否した接続は従来どおり drop する。
        #[cfg(test)]
        rejected: std::sync::Mutex<Option<UnixStream>>,
    }

    impl ListenerInner {
        /// `path` は `..` を含まない絶対パス（`UdsListener::bind` が検証・変換済み）。
        pub(super) fn bind(path: &Path) -> Result<Self, PluginError> {
            let euid = sys::effective_uid();
            let (dir, canonical) = open_parent_dir(path, euid)?;
            let file_name = path.file_name().ok_or_else(|| {
                PluginError::new(PluginErrorCode::InvalidArgument, "invalid socket path")
            })?;
            let name = CString::new(file_name.as_bytes()).map_err(|_| {
                PluginError::new(PluginErrorCode::InvalidArgument, "invalid socket path")
            })?;
            // 公開パス（client が接続に使う）と bind に使うパスの両方が `sun_path` に収まることを
            // bind 前に確認する。短い symlink 経由で長い実体ディレクトリを指定した場合など、bind は
            // できても公開パスでは接続できない構成を作らない（socket を作る前に拒否。PLUG-2）。
            let bound = canonical.join(file_name);
            check_sun_path_len(&bound)?;
            let target = bind_target(&dir, &bound, Path::new(file_name));
            check_sun_path_len(&target)?;
            // 既存エントリの lstat 検証と、自 UID 所有の stale socket の削除（PLUG-12・TASK-123.2）。
            // 生存判定は接続 probe でなく sibling lock の flock（既存 listener に副作用を与えない）。
            // 以降で失敗した場合、記録の無いロックファイルは `BindLock` の drop が解放の直前に削除する
            // （削除と取得の競合は取得側の同一性確認で排除する。`BindLock` の doc 参照）。
            let lock = crate::uds_security::acquire_bind_lock(&dir, &name, euid)?;
            crate::uds_security::clear_stale_socket(&dir, &name, euid, &lock)?;
            let listener = UnixListener::bind(&target).map_err(|e| map_bind_error(e.kind()))?;
            // 以降の設定が失敗しても socket ファイルを残さないよう、先に後始末を持つ値を作る。
            let identity = sys::lstat_at(&dir, &name).ok();
            let inner = Self {
                listener,
                dir,
                name,
                lock,
                path: bound,
                identity,
                euid,
                #[cfg(test)]
                rejected: std::sync::Mutex::new(None),
            };
            // 管理下の証拠として socket の同一性をロックへ記録する。記録できないまま listener を返すと、
            // 異常終了時に記録の無い socket が残り、以後の bind が stale と判定できず `AlreadyExists` に
            // なるため、記録失敗は bind 失敗として作成した socket を後始末する（TASK-123.2）。
            // identity が無い場合は記録せず、直後の `configure` が拒否する。
            if let Some(ident) = inner.identity.as_ref()
                && inner.lock.record_socket(ident).is_err()
            {
                inner.cleanup();
                return Err(PluginError::new(
                    PluginErrorCode::Internal,
                    "failed to record bound socket",
                ));
            }
            if let Err(e) = inner.configure() {
                inner.cleanup();
                return Err(e);
            }
            Ok(inner)
        }

        /// テスト用: 期待 UID を差し替える（拒否経路を同一 UID の実接続で再現するため。TASK-124.5）。
        /// 本番ビルドには存在しない。
        #[cfg(test)]
        pub(super) fn set_expected_uid_for_test(&mut self, uid: u32) {
            self.euid = uid;
        }

        /// 公開パス（検証済み配置ディレクトリの解決後パス＋socket 名。PLUG-12）。
        pub(super) fn path(&self) -> &Path {
            &self.path
        }

        /// bind 直後の設定（nonblocking 化・0600 化。PLUG-12）。
        /// 0600 化は検証済みディレクトリ fd 基準の `fchmodat(AT_SYMLINK_NOFOLLOW)`。差し替えで
        /// 名前が別ディレクトリへ解決された場合は ENOENT・symlink なら拒否となり失敗する（fail-closed）。
        /// 失敗時の socket 削除は呼び出し側（`bind`）が行う。
        fn configure(&self) -> Result<(), PluginError> {
            self.listener.set_nonblocking(true).map_err(|_| {
                PluginError::new(PluginErrorCode::Internal, "failed to configure listener")
            })?;
            // 作成した自 UID 所有の socket であることを確認してから 0600 化する。
            let ident = self
                .identity
                .ok_or_else(|| denied("failed to inspect bound socket"))?;
            if !ident.is_socket || ident.uid != self.euid {
                return Err(denied("bound socket is not the expected socket"));
            }
            sys::fchmodat_nofollow(&self.dir, &self.name, 0o600).map_err(|_| {
                PluginError::new(PluginErrorCode::Internal, "failed to restrict socket mode")
            })
        }

        pub(super) fn accept(
            &self,
            timeout: Duration,
            expected_pid: Option<u32>,
            abort: &mut dyn FnMut() -> Option<PluginError>,
            observer: &mut dyn PeerAuthObserver,
        ) -> Result<StreamInner, PluginError> {
            self.accept_with(timeout, self.euid, expected_pid, abort, observer)
        }

        /// テスト専用: 期待 UID をずらして peer 認証を拒否させる入口（PLUG-12・TASK-124.6・#1389）。
        /// 検証（`verify_peer`）は必ず通る。検証を省く経路ではない。
        #[cfg(test)]
        pub(super) fn accept_with_expected_uid(
            &self,
            timeout: Duration,
            expected_uid: u32,
        ) -> Result<StreamInner, PluginError> {
            self.accept_with(
                timeout,
                expected_uid,
                None,
                &mut || None,
                &mut crate::audit::NoopPeerAuthObserver,
            )
        }

        /// テスト専用: 拒否して退避した接続を取り出す。
        #[cfg(test)]
        pub(super) fn take_rejected(&self) -> Option<UnixStream> {
            self.rejected
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take()
        }

        /// `accept` の本体。`expected_uid` は公開経路では常に `self.euid`。
        fn accept_with(
            &self,
            timeout: Duration,
            expected_uid: u32,
            expected_pid: Option<u32>,
            abort: &mut dyn FnMut() -> Option<PluginError>,
            observer: &mut dyn PeerAuthObserver,
        ) -> Result<StreamInner, PluginError> {
            let deadline = Instant::now() + timeout;
            let mut poll_interval = ACCEPT_POLL_INITIAL;
            loop {
                match self.listener.accept() {
                    Ok((stream, _)) => {
                        // 期限後に到着した接続は受理せず閉じて Timeout を返す（REPAIR-5。
                        // 期限直前のポーリング後のスリープ中に到着した接続が成功する経路を塞ぐ）。
                        // drop で fd を閉じるため相手は切断される。
                        if Instant::now() >= deadline {
                            return Err(PluginError::new(
                                PluginErrorCode::Timeout,
                                "timed out waiting for a connection",
                            ));
                        }
                        // 別 UID（取得不能を含む）は切断して拒否する（PLUG-12・fail-closed）。
                        // drop で fd を閉じるため相手は切断される。
                        // accept 直後・最初の read より前に検証する（TASK-124.1・#292）。
                        // 拒否は「（テスト以外は drop で切断）→ 監査通知 → Err」の順（TASK-124.5・SEC-4）。
                        // 通知は戻り値を持たず、拒否判定には影響しない。順序は
                        // `transport::tests::plug12_order` で機械照合する（TASK-124.6・#1389）。
                        if let Err(rej) = crate::uds_security::verify_peer(&stream, expected_uid) {
                            // テストでは拒否した接続を退避する（drop しない。`rejected` 参照）。
                            #[cfg(test)]
                            {
                                *self.rejected.lock().unwrap_or_else(|p| p.into_inner()) =
                                    Some(stream);
                            }
                            #[cfg(not(test))]
                            drop(stream);
                            observer.on_rejection(&PeerAuthRejection {
                                op: PeerAuthOp::Accept,
                                reason: rej.reason,
                                code: rej.error.code(),
                                expected_uid,
                                peer_uid: rej.peer_uid,
                                expected_pid: None,
                                peer_pid: None,
                                socket_path: &self.path,
                            });
                            return Err(rej.error);
                        }
                        // 応答者の限定指定がある場合、spawn した子以外（同一 UID の別プロセス）は
                        // 切断して受付を継続する（PLUG-7。取得不能は fail-closed でエラー）。
                        if let Some(pid) = expected_pid {
                            let peer_pid = match sys::peer_pid(&stream) {
                                Ok(p) => p,
                                Err(e) => {
                                    drop(stream);
                                    observer.on_rejection(&PeerAuthRejection {
                                        op: PeerAuthOp::Accept,
                                        reason: PeerAuthRejectReason::PeerPidUnavailable,
                                        code: e.code(),
                                        expected_uid: self.euid,
                                        peer_uid: Some(self.euid),
                                        expected_pid: Some(pid),
                                        peer_pid: None,
                                        socket_path: &self.path,
                                    });
                                    return Err(e);
                                }
                            };
                            if peer_pid != pid {
                                // 別プロセスの接続が続いても子の早期終了を検知できるよう、
                                // 不一致の接続を閉じた後にも abort を確認する（Unavailable 契約）。
                                drop(stream);
                                observer.on_rejection(&PeerAuthRejection {
                                    op: PeerAuthOp::Accept,
                                    reason: PeerAuthRejectReason::PidMismatch,
                                    code: PluginErrorCode::PermissionDenied,
                                    expected_uid: self.euid,
                                    peer_uid: Some(self.euid),
                                    expected_pid: Some(pid),
                                    peer_pid: Some(peer_pid),
                                    socket_path: &self.path,
                                });
                                if let Some(e) = abort() {
                                    return Err(e);
                                }
                                continue;
                            }
                        }
                        // macOS 等は listener の nonblocking を継承するため明示的に戻す。
                        stream.set_nonblocking(false).map_err(|_| {
                            PluginError::new(
                                PluginErrorCode::Internal,
                                "failed to configure accepted stream",
                            )
                        })?;
                        let inner = StreamInner { stream };
                        inner.set_io_timeout(UDS_DEFAULT_IO_TIMEOUT)?;
                        return Ok(inner);
                    }
                    Err(e)
                        if matches!(
                            e.kind(),
                            io::ErrorKind::WouldBlock
                                | io::ErrorKind::Interrupted
                                | io::ErrorKind::ConnectionAborted
                        ) =>
                    {
                        let now = Instant::now();
                        if now >= deadline {
                            return Err(PluginError::new(
                                PluginErrorCode::Timeout,
                                "timed out waiting for a connection",
                            ));
                        }
                        if let Some(e) = abort() {
                            return Err(e);
                        }
                        thread::sleep((deadline - now).min(poll_interval));
                        poll_interval = (poll_interval * 2).min(ACCEPT_POLL_INTERVAL);
                    }
                    Err(_) => {
                        return Err(PluginError::new(
                            PluginErrorCode::Internal,
                            "failed to accept connection",
                        ));
                    }
                }
            }
        }

        /// 検証済みディレクトリ fd 基準で、bind 時と同一性（dev/ino）が一致する socket のみ
        /// unlink する（best-effort）。Linux では照合も削除もパスを再解決しない。
        ///
        /// ロックの記録（管理下の証拠。TASK-123.2）は、記録した socket がパス上から無くなったと
        /// 確認できた後にだけ消す。先に消すと、unlink の失敗や途中の異常終了で socket だけが残り、
        /// 以後の bind が stale と判定できず常に `AlreadyExists` になるため。socket が残る場合
        /// （unlink 失敗・確認不能）は記録も残し、次回の bind が削除できるようにする。
        pub(super) fn cleanup(&self) {
            // identity が無い場合は記録も書いていない（`bind` 参照）ため何もしない。
            let Some(expected) = self.identity else {
                return;
            };
            let gone = match sys::lstat_at(&self.dir, &self.name) {
                Ok(now) if now == expected => match sys::unlinkat(&self.dir, &self.name) {
                    Ok(()) => true,
                    Err(e) => e.kind() == io::ErrorKind::NotFound,
                },
                // 別のエントリへ差し替え済み: 自分の socket はパス上に無い。記録を残すと inode 番号の
                // 再利用で別の socket を管理下と誤認し得るため消す（差し替え後のエントリには触れない）。
                Ok(_) => true,
                Err(e) => e.kind() == io::ErrorKind::NotFound,
            };
            if gone {
                // 消去に失敗しても後始末（Drop）からは報告できない。記録が残っても、次回の bind の
                // `clear_stale_socket` が「記録した socket がパス上に無い」と確認した時点で消す。
                let _ = self.lock.clear_record();
            }
        }
    }

    #[derive(Debug)]
    pub(super) struct StreamInner {
        stream: UnixStream,
    }

    impl StreamInner {
        /// テスト用: 接続済みの `UnixStream` をそのまま包む（peer credential 検証なし）。
        #[cfg(test)]
        pub(super) fn from_std(stream: UnixStream) -> Self {
            Self { stream }
        }

        /// 期限付き connect → server の peer UID 照合 → blocking 化 → 既定 I/O 期限の付与。
        pub(super) fn connect(
            path: &Path,
            timeout: Duration,
            observer: &mut dyn PeerAuthObserver,
        ) -> Result<Self, PluginError> {
            Self::connect_with_expected(path, timeout, sys::effective_uid(), observer)
        }

        /// `connect` の本体。期待 UID を引数に取るのはテストで期待値をずらすためで、本番経路
        /// （`connect`）は常に自 euid を渡す。可視性は `pub(super)` のため非テストビルドにも
        /// 存在するが、呼び出し元は `connect` とテストに限る（TASK-124.5・TASK-124.6）。
        pub(super) fn connect_with_expected(
            path: &Path,
            timeout: Duration,
            expected_uid: u32,
            observer: &mut dyn PeerAuthObserver,
        ) -> Result<Self, PluginError> {
            check_sun_path_len(path)?;
            let deadline = Instant::now() + timeout;
            let stream =
                sys::connect_unix(path, deadline).map_err(|e| map_connect_error(e.kind()))?;
            // 偽 listener への誘導対策（PLUG-12）。不一致・取得不能は何も送らず drop で切断する。
            // 最初の送信より前に検証する。順序は `transport::tests::plug12_order` で機械照合する
            // （TASK-124.6・#1389）。
            if let Err(rej) = crate::uds_security::verify_peer(&stream, expected_uid) {
                drop(stream);
                observer.on_rejection(&PeerAuthRejection {
                    op: PeerAuthOp::Connect,
                    reason: rej.reason,
                    code: rej.error.code(),
                    expected_uid,
                    peer_uid: rej.peer_uid,
                    expected_pid: None,
                    peer_pid: None,
                    socket_path: path,
                });
                return Err(rej.error);
            }
            stream.set_nonblocking(false).map_err(|_| {
                PluginError::new(
                    PluginErrorCode::Internal,
                    "failed to configure connected stream",
                )
            })?;
            let inner = Self { stream };
            inner.set_io_timeout(UDS_DEFAULT_IO_TIMEOUT)?;
            Ok(inner)
        }

        pub(super) fn set_io_timeout(&self, timeout: Duration) -> Result<(), PluginError> {
            if timeout.is_zero() {
                return Err(PluginError::new(
                    PluginErrorCode::InvalidArgument,
                    "io timeout must be non-zero",
                ));
            }
            let fail = |_| PluginError::new(PluginErrorCode::Internal, "failed to set io timeout");
            self.stream.set_read_timeout(Some(timeout)).map_err(fail)?;
            self.stream.set_write_timeout(Some(timeout)).map_err(fail)
        }
        pub(super) fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.stream.read(buf)
        }
        pub(super) fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.stream.write(buf)
        }
        pub(super) fn flush(&mut self) -> io::Result<()> {
            self.stream.flush()
        }

        /// 期限つきでフレームを 1 つ受ける。戻り値は socket 期限の復元結果。
        pub(super) fn read_frame(
            &mut self,
            timeout: RpcTimeout,
        ) -> (Result<Frame, PluginError>, TimeoutRestore) {
            let saved = self.save_timeouts();
            let deadline = Instant::now() + timeout.as_duration();
            let result = self.read_frame_inner(deadline);
            let restored = self.restore_timeouts(saved);
            (result, restored)
        }

        /// 期限つきでフレームを 1 つ全量送る。戻り値は socket 期限の復元結果。
        pub(super) fn write_frame(
            &mut self,
            frame: &Frame,
            timeout: RpcTimeout,
        ) -> (Result<(), PluginError>, TimeoutRestore) {
            let saved = self.save_timeouts();
            let deadline = Instant::now() + timeout.as_duration();
            // encode（最大 16 MiB のコピーとチェックサム計算）も合計期限に含める。encode 後に期限を
            // 超えていれば 1 バイトも送らず Timeout にする（REPAIR-5）。
            let encoded = frame.encode();
            let result = remaining_until(deadline, FrameOp::Write)
                .and_then(|_| self.write_all_deadline(&encoded, deadline));
            let restored = self.restore_timeouts(saved);
            (result, restored)
        }

        fn save_timeouts(&self) -> Option<(Option<Duration>, Option<Duration>)> {
            Some((
                self.stream.read_timeout().ok()?,
                self.stream.write_timeout().ok()?,
            ))
        }

        fn restore_timeouts(
            &self,
            saved: Option<(Option<Duration>, Option<Duration>)>,
        ) -> TimeoutRestore {
            let Some((r, w)) = saved else {
                return TimeoutRestore::Failed;
            };
            // 片方が失敗しても必ず両方を試す（短絡させない）。
            // macOS は peer close 後の UDS で set_*_timeout が EINVAL を返す。復元できたとは見なさず
            // `PeerClosed` として区別し、呼び出し側が接続を使用不可にする（期限未復元のまま再利用させない。
            // 操作自体の成功は保つ）。それ以外の失敗は `Failed`。
            let classify = |r: io::Result<()>| match r {
                Ok(()) => TimeoutRestore::Restored,
                Err(e) if e.kind() == io::ErrorKind::InvalidInput => TimeoutRestore::PeerClosed,
                Err(_) => TimeoutRestore::Failed,
            };
            match (
                classify(self.stream.set_read_timeout(r)),
                classify(self.stream.set_write_timeout(w)),
            ) {
                (TimeoutRestore::Restored, TimeoutRestore::Restored) => TimeoutRestore::Restored,
                (TimeoutRestore::Failed, _) | (_, TimeoutRestore::Failed) => TimeoutRestore::Failed,
                _ => TimeoutRestore::PeerClosed,
            }
        }

        fn read_frame_inner(&mut self, deadline: Instant) -> Result<Frame, PluginError> {
            let mut head = [0u8; FRAME_HEADER_LEN];
            self.read_exact_deadline(&mut head, deadline)?;
            // 長さ上限の検証を通ってから本体を確保する。
            let header = FrameHeader::from_bytes(head)?;
            let body_len = header.body_len();
            let mut body: Vec<u8> = Vec::new();
            while body.len() < body_len {
                let start = body.len();
                let chunk = BODY_CHUNK.min(body_len - start);
                body.resize(start + chunk, 0);
                let slice = body.get_mut(start..).ok_or_else(internal_read)?;
                self.read_exact_deadline(slice, deadline)?;
            }
            let frame = Frame::decode_body(header, &body)?;
            // チェックサム検証・ペイロードコピーの後に期限を超えていれば成功扱いにしない（REPAIR-5）。
            remaining_until(deadline, FrameOp::Read)?;
            Ok(frame)
        }

        /// 合計期限 `deadline` までに `buf` をちょうど埋める。残り時間で read 期限を掛け直す。
        fn read_exact_deadline(
            &mut self,
            buf: &mut [u8],
            deadline: Instant,
        ) -> Result<(), PluginError> {
            let mut filled = 0usize;
            while filled < buf.len() {
                let remaining = remaining_until(deadline, FrameOp::Read)?;
                let slice = buf.get_mut(filled..).ok_or_else(internal_read)?;
                // macOS は peer close 後の UDS で set_read_timeout が EINVAL を返す。期限を掛けられない
                // まま blocking read に進むと上限を超えて待ちうるため、EINVAL のときは non-blocking
                // read で 1 回だけ試す（切断済みなら残りバイトか EOF を即返す。何も来なければ
                // 期限を保証できないので失敗させる）。それ以外の失敗も読まずに失敗させる
                // （PLUG-2・REPAIR-5）。
                let res = match self.stream.set_read_timeout(Some(remaining)) {
                    Ok(()) => self.stream.read(slice),
                    Err(e) if e.kind() == io::ErrorKind::InvalidInput => {
                        self.nonblocking_once(FrameOp::Read, |mut s| s.read(slice))?
                    }
                    Err(_) => return Err(internal_read()),
                };
                match res {
                    Ok(0) => {
                        return Err(map_frame_io_error(
                            io::ErrorKind::UnexpectedEof,
                            FrameOp::Read,
                        ));
                    }
                    Ok(n) => filled = filled.checked_add(n).ok_or_else(internal_read)?,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    Err(e) => return Err(map_frame_io_error(e.kind(), FrameOp::Read)),
                }
            }
            // 最後の read が期限後に成功した場合も合計期限超過として扱う（REPAIR-5）。
            remaining_until(deadline, FrameOp::Read)?;
            Ok(())
        }

        /// socket を一時的に non-blocking にして `op` を 1 回だけ実行する。期限を設定できない
        /// socket で blocking I/O に進まないための経路。WouldBlock（進捗なし）は期限を保証できない
        /// ため `Internal` で失敗させ、blocking への復元に失敗した場合も失敗させる（REPAIR-5）。
        fn nonblocking_once(
            &self,
            frame_op: FrameOp,
            op: impl FnOnce(&UnixStream) -> io::Result<usize>,
        ) -> Result<io::Result<usize>, PluginError> {
            // 失敗は呼び出し元の方向（read / write）で報告する。
            let internal = || map_frame_io_error(io::ErrorKind::Other, frame_op);
            self.stream.set_nonblocking(true).map_err(|_| internal())?;
            let res = op(&self.stream);
            self.stream.set_nonblocking(false).map_err(|_| internal())?;
            match res {
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => Err(internal()),
                other => Ok(other),
            }
        }

        fn write_all_deadline(
            &mut self,
            bytes: &[u8],
            deadline: Instant,
        ) -> Result<(), PluginError> {
            let mut sent = 0usize;
            while sent < bytes.len() {
                let remaining = remaining_until(deadline, FrameOp::Write)?;
                let slice = bytes.get(sent..).ok_or_else(internal_write)?;
                // 読み取り側と同様、EINVAL のときは non-blocking write で 1 回だけ試す
                // （切断済みなら EPIPE 等が Unavailable に写像される）。他の失敗は書かずに失敗させる。
                let res = match self.stream.set_write_timeout(Some(remaining)) {
                    Ok(()) => self.stream.write(slice),
                    Err(e) if e.kind() == io::ErrorKind::InvalidInput => {
                        self.nonblocking_once(FrameOp::Write, |mut s| s.write(slice))?
                    }
                    Err(_) => return Err(internal_write()),
                };
                match res {
                    Ok(0) => {
                        return Err(map_frame_io_error(
                            io::ErrorKind::BrokenPipe,
                            FrameOp::Write,
                        ));
                    }
                    Ok(n) => sent = sent.checked_add(n).ok_or_else(internal_write)?,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    Err(e) => return Err(map_frame_io_error(e.kind(), FrameOp::Write)),
                }
            }
            // 最後の write が期限後に成功した場合も合計期限超過として扱う（REPAIR-5）。
            remaining_until(deadline, FrameOp::Write)?;
            Ok(())
        }
    }

    fn internal_read() -> PluginError {
        map_frame_io_error(io::ErrorKind::Other, FrameOp::Read)
    }

    fn internal_write() -> PluginError {
        map_frame_io_error(io::ErrorKind::Other, FrameOp::Write)
    }

    /// 期限までの残り時間（0 なら `Timeout`）。
    fn remaining_until(deadline: Instant, op: FrameOp) -> Result<Duration, PluginError> {
        deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or_else(|| map_frame_io_error(io::ErrorKind::TimedOut, op))
    }
}

/// `uds_security::RuntimeDir::socket_path` が bind 前の早期検出に使う `sun_path` 長検証の再公開
/// （PLUG-12・TASK-123.3・#288）。ロジックは `imp` 側の 1 箇所に置き、重複させない。
#[cfg(unix)]
pub(crate) use imp::check_sun_path_len;

#[cfg(not(unix))]
mod imp {
    use super::{PeerAuthObserver, RpcTimeout, TimeoutRestore};
    use crate::error::{PluginError, PluginErrorCode};
    use crate::frame::Frame;
    use std::io;
    use std::path::Path;
    use std::time::Duration;

    /// 構築不能（非 unix では listener を作れない）。
    #[derive(Debug)]
    pub(super) enum ListenerInner {}

    #[derive(Debug)]
    pub(super) enum StreamInner {}

    impl ListenerInner {
        pub(super) fn bind(_path: &Path) -> Result<Self, PluginError> {
            Err(PluginError::new(
                PluginErrorCode::Unimplemented,
                "unix domain socket listener is not supported on this platform",
            ))
        }
        pub(super) fn path(&self) -> &Path {
            match *self {}
        }
        pub(super) fn accept(
            &self,
            _timeout: Duration,
            _expected_pid: Option<u32>,
            _abort: &mut dyn FnMut() -> Option<PluginError>,
            _observer: &mut dyn PeerAuthObserver,
        ) -> Result<StreamInner, PluginError> {
            match *self {}
        }
        pub(super) fn cleanup(&self) {
            match *self {}
        }
    }

    impl StreamInner {
        pub(super) fn connect(
            _path: &Path,
            _timeout: Duration,
            _observer: &mut dyn PeerAuthObserver,
        ) -> Result<Self, PluginError> {
            Err(PluginError::new(
                PluginErrorCode::Unimplemented,
                "unix domain socket client is not supported on this platform",
            ))
        }
        pub(super) fn set_io_timeout(&self, _timeout: Duration) -> Result<(), PluginError> {
            match *self {}
        }
        pub(super) fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
            match *self {}
        }
        pub(super) fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
            match *self {}
        }
        pub(super) fn flush(&mut self) -> io::Result<()> {
            match *self {}
        }
        pub(super) fn read_frame(
            &mut self,
            _timeout: RpcTimeout,
        ) -> (Result<Frame, PluginError>, TimeoutRestore) {
            match *self {}
        }
        pub(super) fn write_frame(
            &mut self,
            _frame: &Frame,
            _timeout: RpcTimeout,
        ) -> (Result<(), PluginError>, TimeoutRestore) {
            match *self {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use crate::audit::{PeerAuthOp, PeerAuthRejectReason, PeerAuthRejection};

    /// PLUG-12・TASK-124.6: peer 認証が最初のフレーム読み取り（accept）・最初の送信（connect）より
    /// 前であることを実接続で照合するテスト群。
    #[cfg(all(
        unix,
        any(
            target_os = "macos",
            all(
                target_os = "linux",
                any(target_arch = "x86_64", target_arch = "aarch64")
            )
        )
    ))]
    mod plug12_order {
        use super::*;
        use std::io::{Read, Write};
        use std::os::unix::fs::DirBuilderExt;
        use std::os::unix::net::{UnixListener, UnixStream};
        use std::path::PathBuf;
        use std::sync::atomic::{AtomicU32, Ordering};
        use std::sync::mpsc;

        const WAIT: Duration = Duration::from_secs(5);
        const MISMATCH: &str = "peer credential does not match the current user";

        /// 0700 の一時ディレクトリ（socket の配置先。drop で削除）。
        struct TempDir(PathBuf);
        impl TempDir {
            fn new() -> Self {
                static N: AtomicU32 = AtomicU32::new(0);
                let p = std::env::temp_dir().join(format!(
                    "fctr-{}-{}",
                    std::process::id(),
                    N.fetch_add(1, Ordering::Relaxed)
                ));
                std::fs::DirBuilder::new().mode(0o700).create(&p).unwrap();
                Self(p)
            }
            fn sock(&self) -> PathBuf {
                self.0.join("s.sock")
            }
        }
        impl Drop for TempDir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }

        fn shifted_uid() -> u32 {
            crate::sys::effective_uid().wrapping_add(1)
        }

        fn presend_frame() -> Vec<u8> {
            Frame::new(b"presend-frame".to_vec()).unwrap().encode()
        }

        /// 生 client が connect 直後にフレームを送り、送信完了を通知して EOF を待つスレッドを起こす。
        #[allow(clippy::type_complexity)]
        fn spawn_presend_client(
            path: PathBuf,
            bytes: Vec<u8>,
        ) -> (
            mpsc::Receiver<()>,
            std::thread::JoinHandle<std::io::Result<usize>>,
        ) {
            let (tx, rx) = mpsc::channel();
            let h = std::thread::spawn(move || {
                let mut c = UnixStream::connect(&path)?;
                c.set_read_timeout(Some(WAIT))?;
                c.write_all(&bytes)?;
                tx.send(()).ok();
                let mut buf = [0u8; 16];
                c.read(&mut buf)
            });
            (rx, h)
        }

        /// accept 側。peer 認証の拒否時、先送りされたフレームは 1 バイトも読まれず
        /// （受信キューに全量残り）、`UdsStream` も作られない。
        #[test]
        fn plug12_accept_rejection_leaves_presend_frame_unread() {
            let dir = TempDir::new();
            let l = UdsListener::bind(&dir.sock()).unwrap();
            let bytes = presend_frame();
            let (sent, h) = spawn_presend_client(l.path().to_path_buf(), bytes.clone());
            sent.recv_timeout(WAIT).unwrap();

            let e = l
                .inner
                .accept_with_expected_uid(WAIT, shifted_uid())
                .unwrap_err();
            assert_eq!(e.code(), PluginErrorCode::PermissionDenied);
            assert_eq!(e.message(), MISMATCH);

            let mut rejected = l.inner.take_rejected().expect("rejected stream stashed");
            rejected.set_nonblocking(false).unwrap();
            rejected.set_read_timeout(Some(WAIT)).unwrap();
            let mut got = vec![0u8; bytes.len()];
            rejected.read_exact(&mut got).unwrap();
            assert_eq!(got, bytes);
            rejected.set_nonblocking(true).unwrap();
            let mut extra = [0u8; 1];
            let e = rejected.read(&mut extra).unwrap_err();
            assert_eq!(e.kind(), io::ErrorKind::WouldBlock);

            // 退避した接続を閉じると client は EOF を観測する。
            drop(rejected);
            assert_eq!(h.join().unwrap().unwrap(), 0);

            // 拒否後も同じ listener は同一 UID の接続を受理し続ける。
            let (sent, h) = spawn_presend_client(l.path().to_path_buf(), bytes);
            sent.recv_timeout(WAIT).unwrap();
            let mut s = l.accept(WAIT).unwrap();
            let f = s.read_frame(RpcTimeout::new(WAIT).unwrap()).unwrap();
            assert_eq!(f.payload(), b"presend-frame");
            drop(s);
            h.join().unwrap().unwrap();
        }

        /// 陽性対照。検証を通る接続では先送りフレームが最初のフレームとして読め、退避された接続は
        /// 無い（拒否時だけを捉える計測であることの確認）。
        #[test]
        fn plug12_accept_success_reads_presend_frame_as_first_frame() {
            let dir = TempDir::new();
            let l = UdsListener::bind(&dir.sock()).unwrap();
            let (sent, h) = spawn_presend_client(l.path().to_path_buf(), presend_frame());
            sent.recv_timeout(WAIT).unwrap();
            let inner = l
                .inner
                .accept_with_expected_uid(WAIT, crate::sys::effective_uid())
                .unwrap();
            assert!(l.inner.take_rejected().is_none());
            let mut s = UdsStream {
                inner,
                poisoned: false,
                io_timeout_unrestored: false,
            };
            let f = s.read_frame(RpcTimeout::new(WAIT).unwrap()).unwrap();
            assert_eq!(f.payload(), b"presend-frame");
            drop(s);
            h.join().unwrap().unwrap();
        }

        /// connect 側。server 検証の拒否時は `StreamInner` が作られず、server は 1 バイトも
        /// 受信しない（EOF のみ）。
        #[test]
        fn plug12_connect_rejection_sends_no_bytes() {
            let dir = TempDir::new();
            let server = UnixListener::bind(dir.sock()).unwrap();
            let e = imp::StreamInner::connect_with_expected(
                &dir.sock(),
                WAIT,
                shifted_uid(),
                &mut crate::audit::NoopPeerAuthObserver,
            )
            .unwrap_err();
            assert_eq!(e.code(), PluginErrorCode::PermissionDenied);
            assert_eq!(e.message(), MISMATCH);

            server.set_nonblocking(true).unwrap();
            let deadline = std::time::Instant::now() + WAIT;
            let conn = loop {
                match server.accept() {
                    Ok((c, _)) => break c,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        assert!(std::time::Instant::now() < deadline, "no connection");
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(e) => panic!("accept failed: {e}"),
                }
            };
            // client は既に close 済み。macOS では set_read_timeout が EINVAL になり得るため、
            // nonblocking のまま期限付きで読む。
            conn.set_nonblocking(true).unwrap();
            let mut conn = conn;
            let mut buf = [0u8; 16];
            let n = loop {
                match conn.read(&mut buf) {
                    Ok(n) => break n,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        assert!(std::time::Instant::now() < deadline, "no EOF");
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(e) => panic!("read failed: {e}"),
                }
            };
            assert_eq!(n, 0);

            // 対照: 期待 UID をずらさなければ同じ listener へ接続できる。
            let ok = imp::StreamInner::connect_with_expected(
                &dir.sock(),
                WAIT,
                crate::sys::effective_uid(),
                &mut crate::audit::NoopPeerAuthObserver,
            );
            assert!(ok.is_ok());
        }
    }

    /// 相手側の生 socket と、検証を経ずに包んだ `UdsStream` の対を作る。
    #[cfg(unix)]
    fn stream_pair() -> (UdsStream, std::os::unix::net::UnixStream) {
        let (ours, peer) = std::os::unix::net::UnixStream::pair().unwrap();
        let stream = UdsStream {
            inner: imp::StreamInner::from_std(ours),
            poisoned: false,
            io_timeout_unrestored: false,
        };
        (stream, peer)
    }

    /// PLUG-7・PLUG-2・REPAIR-5: 送信直後に相手が応答を書いて切断し、期限を復元できなかった
    /// （`PeerClosed`）場合でも、受信バッファの応答フレームは読める。生 I/O は拒否する。
    #[cfg(unix)]
    #[test]
    fn plug7_peer_closed_after_write_still_reads_buffered_frame() {
        let (mut stream, mut peer) = stream_pair();
        let response = Frame::new(b"pong".to_vec()).unwrap();
        peer.write_all(&response.encode()).unwrap();
        drop(peer);

        // write_frame が成功し、期限の復元だけが相手切断で失敗した状態。
        let written = stream.finish_frame_op(Ok(()), TimeoutRestore::PeerClosed);
        assert_eq!(written, Ok(()));
        assert!(!stream.poisoned);
        assert!(stream.io_timeout_unrestored);

        let mut raw = [0u8; 1];
        let e = stream.read(&mut raw).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::NotConnected);
        let e = stream.write(b"x").unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::NotConnected);

        let timeout = RpcTimeout::new(Duration::from_secs(5)).unwrap();
        let got = stream.read_frame(timeout).unwrap();
        assert_eq!(got.payload(), b"pong");
        // 読み切った後は相手切断として失敗し、以後は全面的に使用不可。
        let e = stream.read_frame(timeout).unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::Unavailable);
        assert!(stream.poisoned);
    }

    /// REPAIR-5: `PeerClosed` を観測済みの接続では、以後の復元失敗で成功した操作を失敗に変えない。
    /// 未観測の接続での復元失敗（`Failed`）は従来どおり全面的に使用不可にしてエラーを返す。
    #[cfg(unix)]
    #[test]
    fn repair5_restore_failure_handling_depends_on_peer_closed_state() {
        let (mut stream, _peer) = stream_pair();
        let e = stream
            .finish_frame_op(Ok(()), TimeoutRestore::Failed)
            .unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::Internal);
        assert_eq!(e.message(), "failed to restore io timeout");
        assert!(stream.poisoned);

        let (mut stream, _peer) = stream_pair();
        assert_eq!(
            stream.finish_frame_op(Ok(1u8), TimeoutRestore::PeerClosed),
            Ok(1u8)
        );
        assert_eq!(
            stream.finish_frame_op(Ok(2u8), TimeoutRestore::Failed),
            Ok(2u8)
        );
        assert!(!stream.poisoned);
        let failed: Result<u8, PluginError> = Err(poisoned_error());
        assert!(
            stream
                .finish_frame_op(failed, TimeoutRestore::Restored)
                .is_err()
        );
        assert!(stream.poisoned);
    }

    /// PLUG-2: bind の ErrorKind 写像（具体値で照合）。
    #[test]
    fn plug2_map_bind_error_maps_io_error_kinds() {
        let cases = [
            (io::ErrorKind::AddrInUse, PluginErrorCode::AlreadyExists),
            (
                io::ErrorKind::PermissionDenied,
                PluginErrorCode::PermissionDenied,
            ),
            (io::ErrorKind::NotFound, PluginErrorCode::NotFound),
            (
                io::ErrorKind::InvalidInput,
                PluginErrorCode::InvalidArgument,
            ),
            (io::ErrorKind::Other, PluginErrorCode::Internal),
        ];
        for (kind, code) in cases {
            assert_eq!(map_bind_error(kind).code(), code);
        }
    }

    /// PLUG-2: connect の ErrorKind 写像（具体値で照合）。
    #[test]
    fn plug2_map_connect_error_maps_io_error_kinds() {
        let cases = [
            (io::ErrorKind::NotFound, PluginErrorCode::NotFound),
            (
                io::ErrorKind::ConnectionRefused,
                PluginErrorCode::Unavailable,
            ),
            (
                io::ErrorKind::PermissionDenied,
                PluginErrorCode::PermissionDenied,
            ),
            (
                io::ErrorKind::InvalidInput,
                PluginErrorCode::InvalidArgument,
            ),
            (io::ErrorKind::WouldBlock, PluginErrorCode::Timeout),
            (io::ErrorKind::TimedOut, PluginErrorCode::Timeout),
            (io::ErrorKind::Unsupported, PluginErrorCode::Unimplemented),
            (io::ErrorKind::Other, PluginErrorCode::Internal),
        ];
        for (kind, code) in cases {
            assert_eq!(map_connect_error(kind).code(), code);
        }
    }

    /// REPAIR-5: 0 と上限超過は構築できず、上限ちょうどは許可する。
    #[test]
    fn repair5_rpc_timeout_rejects_zero_and_over_max() {
        let e = RpcTimeout::new(Duration::ZERO).unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::InvalidArgument);
        let ok = RpcTimeout::new(UDS_RPC_TIMEOUT_MAX).unwrap();
        assert_eq!(ok.as_duration(), Duration::from_secs(10));
        let e = RpcTimeout::try_from(UDS_RPC_TIMEOUT_MAX + Duration::from_nanos(1)).unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::InvalidArgument);
    }

    /// REPAIR-5: 既定値・上限の具体値。
    #[test]
    fn repair5_rpc_timeout_default_is_ten_seconds() {
        assert_eq!(RpcTimeout::default().as_duration(), Duration::from_secs(10));
        assert_eq!(UDS_RPC_TIMEOUT_DEFAULT, Duration::from_secs(10));
        assert_eq!(UDS_RPC_TIMEOUT_MAX, Duration::from_secs(10));
        assert_eq!(UDS_CONNECT_TIMEOUT_MAX, Duration::from_secs(600));
    }

    /// PLUG-2・REPAIR-5: フレーム I/O の ErrorKind 写像（Timeout と Unavailable を区別する）。
    #[test]
    fn plug2_map_frame_io_error_maps_io_error_kinds() {
        use io::ErrorKind as K;
        let t = PluginErrorCode::Timeout;
        let u = PluginErrorCode::Unavailable;
        let i = PluginErrorCode::Internal;
        let cases = [
            (
                K::TimedOut,
                FrameOp::Read,
                t,
                "timed out waiting for a frame",
            ),
            (
                K::WouldBlock,
                FrameOp::Read,
                t,
                "timed out waiting for a frame",
            ),
            (K::TimedOut, FrameOp::Write, t, "timed out sending a frame"),
            (
                K::WouldBlock,
                FrameOp::Write,
                t,
                "timed out sending a frame",
            ),
            (
                K::UnexpectedEof,
                FrameOp::Read,
                u,
                "peer closed the connection",
            ),
            (
                K::ConnectionReset,
                FrameOp::Read,
                u,
                "peer closed the connection",
            ),
            (
                K::ConnectionAborted,
                FrameOp::Write,
                u,
                "peer closed the connection",
            ),
            (
                K::BrokenPipe,
                FrameOp::Write,
                u,
                "peer closed the connection",
            ),
            (
                K::NotConnected,
                FrameOp::Write,
                u,
                "peer closed the connection",
            ),
            (K::Other, FrameOp::Read, i, "failed to read a frame"),
            (K::Other, FrameOp::Write, i, "failed to send a frame"),
        ];
        for (kind, op, code, msg) in cases {
            let e = map_frame_io_error(kind, op);
            assert_eq!(e.code(), code);
            assert_eq!(e.message(), msg);
        }
        assert_eq!(
            map_frame_io_error(io::ErrorKind::TimedOut, FrameOp::Read)
                .code()
                .as_str(),
            "TIMEOUT"
        );
    }

    /// PLUG-2: `sun_path` に収まる最大長（容量 - 1 バイト。終端 NUL 分）は許可し、容量ちょうどは
    /// `InvalidArgument` で拒否する（Linux 108・それ以外の unix 104）。
    #[cfg(unix)]
    #[test]
    fn plug2_sun_path_length_boundary() {
        #[cfg(target_os = "linux")]
        assert_eq!(imp::SUN_PATH_CAPACITY, 108);
        #[cfg(target_os = "macos")]
        assert_eq!(imp::SUN_PATH_CAPACITY, 104);
        let fits = format!("/{}", "a".repeat(imp::SUN_PATH_CAPACITY - 2));
        assert_eq!(fits.len(), imp::SUN_PATH_CAPACITY - 1);
        assert_eq!(imp::check_sun_path_len(Path::new(&fits)), Ok(()));
        let over = format!("/{}", "a".repeat(imp::SUN_PATH_CAPACITY - 1));
        assert_eq!(over.len(), imp::SUN_PATH_CAPACITY);
        let err = imp::check_sun_path_len(Path::new(&over)).unwrap_err();
        assert_eq!(err.code(), PluginErrorCode::InvalidArgument);
        assert_eq!(err.message(), "socket path is too long");
    }

    /// 拒否イベントを所有コピーで積むテスト用の受け手。
    #[cfg(unix)]
    #[derive(Default)]
    struct Recorder(Vec<RecordedRejection>);

    #[cfg(unix)]
    #[derive(Debug, PartialEq, Eq)]
    struct RecordedRejection {
        op: PeerAuthOp,
        reason: PeerAuthRejectReason,
        code: PluginErrorCode,
        expected_uid: u32,
        peer_uid: Option<u32>,
        expected_pid: Option<u32>,
        peer_pid: Option<u32>,
        socket_path: std::path::PathBuf,
    }

    #[cfg(unix)]
    impl PeerAuthObserver for Recorder {
        fn on_rejection(&mut self, e: &PeerAuthRejection<'_>) {
            self.0.push(RecordedRejection {
                op: e.op,
                reason: e.reason,
                code: e.code,
                expected_uid: e.expected_uid,
                peer_uid: e.peer_uid,
                expected_pid: e.expected_pid,
                peer_pid: e.peer_pid,
                socket_path: e.socket_path.to_path_buf(),
            });
        }
    }

    /// 実 listener（0700 の一時ディレクトリ配下）を作る。
    #[cfg(unix)]
    fn audit_listener(tag: &str) -> (UdsListener, std::path::PathBuf) {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("fc-audit-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let l = UdsListener::bind(&dir.join("a.sock")).unwrap();
        (l, dir)
    }

    #[cfg(unix)]
    fn rejection(
        op: PeerAuthOp,
        reason: PeerAuthRejectReason,
        expected_uid: u32,
        peer_uid: Option<u32>,
        path: &Path,
    ) -> RecordedRejection {
        RecordedRejection {
            op,
            reason,
            code: PluginErrorCode::PermissionDenied,
            expected_uid,
            peer_uid,
            expected_pid: None,
            peer_pid: None,
            socket_path: path.to_path_buf(),
        }
    }

    /// 実 peer credential が取れる OS・アーキテクチャに限定する（`uds_security` のテストと同じ条件）。
    #[cfg(any(
        target_os = "macos",
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    ))]
    mod peercred {
        use super::*;

        fn noop_connect(path: &Path) -> Result<UdsStream, PluginError> {
            UdsStream::connect_observed(
                path,
                Duration::from_secs(2),
                &mut crate::audit::NoopPeerAuthObserver,
            )
        }

        /// PLUG-12・SEC-4: accept 側で期待 UID をずらすと拒否 1 件が記録され、エラーに UID を含まない。
        #[test]
        fn plug12_sec4_accept_uid_mismatch_emits_one_audit_event() {
            let me = crate::sys::effective_uid();
            let (mut l, dir) = audit_listener("acc-mm");
            l.inner.set_expected_uid_for_test(me.wrapping_add(1));
            let path = l.path().to_path_buf();
            let t = std::thread::spawn(move || {
                let _ = noop_connect(&path);
            });
            let mut rec = Recorder::default();
            let e = l
                .accept_observed(Duration::from_secs(5), &mut rec)
                .unwrap_err();
            t.join().unwrap();
            assert_eq!(e.code(), PluginErrorCode::PermissionDenied);
            assert_eq!(
                e.message(),
                "peer credential does not match the current user"
            );
            assert!(!e.to_string().contains(&me.to_string()));
            assert_eq!(
                rec.0,
                vec![rejection(
                    PeerAuthOp::Accept,
                    PeerAuthRejectReason::UidMismatch,
                    me.wrapping_add(1),
                    Some(me),
                    l.path()
                )]
            );
            drop(l);
            let _ = std::fs::remove_dir_all(&dir);
        }

        /// PLUG-12・SEC-4: 同一 UID の受理では記録 0 件。
        #[test]
        fn plug12_sec4_accept_same_uid_emits_no_audit_event() {
            let (l, dir) = audit_listener("acc-ok");
            let _c = noop_connect(l.path()).unwrap();
            let mut rec = Recorder::default();
            assert!(l.accept_observed(Duration::from_secs(5), &mut rec).is_ok());
            assert_eq!(rec.0, vec![]);
            drop(l);
            let _ = std::fs::remove_dir_all(&dir);
        }

        /// PLUG-12・SEC-4: connect 側で期待 UID をずらすと拒否 1 件が記録される。
        #[test]
        fn plug12_sec4_connect_uid_mismatch_emits_one_audit_event() {
            let me = crate::sys::effective_uid();
            let (l, dir) = audit_listener("con-mm");
            let mut rec = Recorder::default();
            let e = imp::StreamInner::connect_with_expected(
                l.path(),
                Duration::from_secs(2),
                me.wrapping_add(1),
                &mut rec,
            )
            .unwrap_err();
            assert_eq!(e.code(), PluginErrorCode::PermissionDenied);
            assert!(!e.to_string().contains(&me.to_string()));
            assert_eq!(
                rec.0,
                vec![rejection(
                    PeerAuthOp::Connect,
                    PeerAuthRejectReason::UidMismatch,
                    me.wrapping_add(1),
                    Some(me),
                    l.path()
                )]
            );
            drop(l);
            let _ = std::fs::remove_dir_all(&dir);
        }

        /// PLUG-12・SEC-4: 通常の connect では記録 0 件。
        #[test]
        fn plug12_sec4_connect_same_uid_emits_no_audit_event() {
            let (l, dir) = audit_listener("con-ok");
            let mut rec = Recorder::default();
            assert!(
                UdsStream::connect_observed(l.path(), Duration::from_secs(2), &mut rec).is_ok()
            );
            assert_eq!(rec.0, vec![]);
            drop(l);
            let _ = std::fs::remove_dir_all(&dir);
        }

        /// PLUG-12・SEC-4: pid 不一致は接続ごとに 1 件、正しい pid の受理は 0 件。
        #[test]
        fn plug12_sec4_accept_peer_pid_mismatch_emits_one_event_per_rejection() {
            let me = std::process::id();
            let uid = crate::sys::effective_uid();
            let (l, dir) = audit_listener("pid-mm");
            let _c1 = noop_connect(l.path()).unwrap();
            let _c2 = noop_connect(l.path()).unwrap();
            let mut rec = Recorder::default();
            let e = l
                .accept_peer_pid(
                    Duration::from_millis(500),
                    me.wrapping_add(1),
                    &mut || None,
                    &mut rec,
                )
                .unwrap_err();
            assert_eq!(e.code(), PluginErrorCode::Timeout);
            let one = || RecordedRejection {
                expected_pid: Some(me.wrapping_add(1)),
                peer_pid: Some(me),
                ..rejection(
                    PeerAuthOp::Accept,
                    PeerAuthRejectReason::PidMismatch,
                    uid,
                    Some(uid),
                    l.path(),
                )
            };
            assert_eq!(rec.0, vec![one(), one()]);
            // 正しい pid の受理は記録を増やさない。
            let _c3 = noop_connect(l.path()).unwrap();
            let mut rec2 = Recorder::default();
            assert!(
                l.accept_peer_pid(Duration::from_secs(2), me, &mut || None, &mut rec2)
                    .is_ok()
            );
            assert_eq!(rec2.0, vec![]);
            drop(l);
            let _ = std::fs::remove_dir_all(&dir);
        }

        /// PLUG-12・SEC-4・A5: 監査枠を使い切っていても不一致接続は Err のまま（受理に倒れない）で、
        /// 集約件数が増える。
        #[test]
        fn plug12_sec4_audit_sink_overflow_does_not_admit_connection() {
            let me = crate::sys::effective_uid();
            let (mut l, dir) = audit_listener("overflow");
            l.inner.set_expected_uid_for_test(me.wrapping_add(1));
            let mut obs = crate::audit::JsonLinesPeerAuthObserver::new();
            let p = Path::new("/x.sock");
            for _ in 0..crate::audit::PEER_AUTH_AUDIT_LOG_CAPACITY {
                obs.on_rejection(&PeerAuthRejection {
                    op: PeerAuthOp::Accept,
                    reason: PeerAuthRejectReason::UidMismatch,
                    code: PluginErrorCode::PermissionDenied,
                    expected_uid: 1,
                    peer_uid: Some(2),
                    expected_pid: None,
                    peer_pid: None,
                    socket_path: p,
                });
            }
            let path = l.path().to_path_buf();
            let t = std::thread::spawn(move || {
                let _ = noop_connect(&path);
            });
            let e = l
                .accept_observed(Duration::from_secs(5), &mut obs)
                .unwrap_err();
            t.join().unwrap();
            assert_eq!(e.code(), PluginErrorCode::PermissionDenied);
            assert_eq!(obs.len(), crate::audit::PEER_AUTH_AUDIT_LOG_CAPACITY);
            assert_eq!(obs.coalesced_rejections(), 1);
            drop(l);
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    /// PLUG-12・SEC-4: peer UID 取得失敗の拒否は peer_uid なしの行になる（実 socket では取得失敗を
    /// 再現できないため、拒否の材料から組んだイベントで行を固定する）。
    #[cfg(unix)]
    #[test]
    fn plug12_sec4_peer_uid_unavailable_is_recorded_without_peer_uid() {
        let ev = PeerAuthRejection {
            op: PeerAuthOp::Connect,
            reason: PeerAuthRejectReason::PeerUidUnavailable,
            code: PluginErrorCode::Internal,
            expected_uid: 1000,
            peer_uid: None,
            expected_pid: None,
            peer_pid: None,
            socket_path: Path::new("/x.sock"),
        };
        assert_eq!(
            ev.to_json_line(),
            "{\"event\":\"plugin_peer_auth\",\"op\":\"connect\",\"outcome\":\"error\",\"reason\":\"peer_uid_unavailable\",\"code\":\"INTERNAL\",\"expected_uid\":1000,\"socket_path\":\"/x.sock\"}"
        );
    }
}
