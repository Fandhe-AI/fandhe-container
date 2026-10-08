//! plugin プロセスの都度起動モード（PLUG-7・TASK-110.1・#258）と、子モジュール `resident` の常駐モード
//! （TASK-110.2・#259。起動仕様 [`OneShotPlugin`]・stderr 収集・子の回収ガードを共用する）と、
//! 子モジュール `mode` のモード選択 API（TASK-110.3・#260）。
//!
//! 呼び出しごとに plugin プロセスを spawn し、1 往復（要求フレーム送信 -> 応答フレーム受信）の
//! 完了後に終了させる。呼び出し元は core 側の plugin proxy（TASK-114 ほか。依存方向は
//! `core -> plugin` のため、本モジュールは core の登録表を参照せず検証済みの絶対パスを受け取る）。
//!
//! # 契約
//!
//! - 接続方向は「core 側が [`UdsListener`] を bind し、plugin が接続する」（`transport` 冒頭の契約）。
//!   socket の絶対パスは環境変数 [`PLUGIN_SOCKET_ENV`] で子へ渡す（暫定契約。spec 未規定）。
//! - spawn から応答受信までは [`OneShotTimeout`] の合計期限で打ち切る（REPAIR-5）。応答後の自発終了
//!   待ちは別枠の [`ONE_SHOT_EXIT_TIMEOUT`]。猶予内に終了しなければ強制終了する。
//! - 子プロセスの回収: [`call_once`] が `Ok` を返した時点で、直接起動した子は wait または kill で
//!   回収済み。`Err` の場合も、返す前に必ず kill と [`ONE_SHOT_REAP_TIMEOUT`] までの回収を試みる。
//!   回収を確認できなかった場合に限り、`Internal`（メッセージに `could not be reaped` と子の pid を
//!   含む）を元のエラーに代えて返す。報告した pid の子は、この呼び出しではそれ以降回収しない
//!   （報告後に回収すると、解放済みの pid を未回収として伝えることになるため）。子は終了済みでも
//!   ゾンビとして残り、親プロセスの終了時に OS が引き取る。呼び出し側はその pid を未回収として扱う。
//! - プロセスグループの停止失敗（#1311）: 直接の子は回収できたが、子のプロセスグループ宛ての kill が
//!   失敗して孫の停止を保証できない場合は、未回収の子とは別の `Internal`（メッセージに
//!   `process group could not be killed` を含み、解放済みの子の pid は含めない）を元のエラーに代えて
//!   返す。`could not be reaped` とは報告しない（PLUG-7・REPAIR-5）。
//! - 子の環境変数は `env_clear()` 後に [`PLUGIN_SOCKET_ENV`] のみ設定する（資格情報を継承させない）。
//!   stdin / stdout は null。stderr は親へ継承させず、専用の UNIX ソケット対で受けて
//!   [`OneShotStderr`] として返す（untrusted。保持は [`ONE_SHOT_STDERR_MAX_BYTES`] まで。超過分は
//!   読み捨てて件数だけ数える）。親の stderr・構造化ログへ内容を転記しない（量の上限なしの出力・
//!   ログ行の偽装を防ぐ）。子から見た stderr は端末でも pipe でもなくソケットで、書き込みは pipe と
//!   同様に扱える（`/dev/stderr` の開き直しは Linux では失敗する）。
//! - 親の強制終了時の停止（#1514・#1403 の方式 B・PLUG-7・REPAIR-5・CORE-1）: Linux では spawn 直前に
//!   `prctl(PR_SET_PDEATHSIG, SIGKILL)` を子へ設定し、親が SIGKILL・abort で落ちても plugin 本体が
//!   孤児で残らないようにする（fork から prctl までに親が先に終わった競合は `getppid` の照合で exec を
//!   中止して拾う）。効くのは直接の子だけで、孫には届かない（未実装節の孫の項目と #1397・#1513 を参照）。
//!   発火条件は子を fork した**スレッド**の終了で、都度起動は呼び出しスレッド上で完結するため影響しない
//!   （常駐モードの契約は `resident` を参照）。setuid・ファイル capability つき実行ファイルでは設定が
//!   解除される。macOS には同等の機構がなく親の強制終了で残留し得る（kqueue `NOTE_EXIT` は将来課題）。
//!   Windows は対象外。
//! - stderr の読み取りスレッドは呼び出しごとに 1 本で、[`call_once`] が戻るまでに停止させる
//!   （呼び出しを繰り返してもスレッドが増え続けない）。子の回収後 [`ONE_SHOT_STDERR_DRAIN_TIMEOUT`]
//!   以内に終端へ達しなければ、ソケットを shutdown して読み取りを打ち切る。
//!
//! # 未実装（REPAIR-3）
//!
//! - 外部管理の常駐 plugin への再接続（attach）と、観測記録を受け取る統一 API（`mode` の冒頭を参照）。
//! - 起動対象の信頼性検証（所有者・モード・sha256 照合。TASK-122・PLUG-11）。本 API は検証を
//!   行わず、呼び出し側が検証済みの絶対パスを渡すことを前提とする。
//! - 孫プロセスの回収の残る制限（#1311）。タイムアウト・後始末の kill は子のプロセスグループ全体へ
//!   送るため孫も止まるが、(a) plugin が自発終了・正常終了して先に回収した経路（回収後は pid が再利用
//!   され得るためグループへ送らない）、(b) `setsid` / `setpgid` でグループを抜けた孫、(c) Windows
//!   （プロセスグループ単位の kill が無く、相当する Job Object は別タスク）では孫が残る。孫が stderr の
//!   書き込み端を保持し続けた場合、収集は [`ONE_SHOT_STDERR_DRAIN_TIMEOUT`] で打ち切り、
//!   [`OneShotStderr::is_complete`] が false になる。打ち切り後は読み取り側を閉じるため、孫の以後の
//!   書き込みは `EPIPE` になる。子は親と別のプロセスグループになるため、端末由来のシグナル（Ctrl-C 等）は
//!   カーネルからは届かない。親が受けた SIGINT・SIGTERM・SIGHUP は CLI バイナリのハンドラが
//!   `signal_forward` 経由でグループ宛て（`kill(-pid)`）に転送し、孫まで届く（#1513）。親が SIGKILL・
//!   abort で落ちた場合は転送されず、Linux の `PR_SET_PDEATHSIG` が止めるのは plugin 本体だけで孫は
//!   残留し得る。macOS では plugin 本体も孫も残留し得る（kqueue `NOTE_EXIT` は将来課題）。
//! - 要求 ID と応答 ID の対応づけ（TASK-114）。

mod mode;
mod resident;

pub use mode::{
    OneShotSummary, PluginCallOutcome, PluginCallRecord, PluginMode, PluginModeKind, PluginSession,
    PluginSessionShutdown,
};

pub use resident::{
    RESIDENT_EXIT_DETECT_TIMEOUT, RESIDENT_START_TIMEOUT_DEFAULT, RESIDENT_START_TIMEOUT_MAX,
    ResidentCallRecord, ResidentPlugin, ResidentShutdown, ResidentShutdownError,
    ResidentStartTimeout, ResidentState,
};

use crate::error::{PluginError, PluginErrorCode};
use crate::frame::Frame;
use crate::signal_forward::{PLUGIN_REGISTRY, Registry, SlotToken};
use crate::transport::{RpcTimeout, UdsListener};
use std::ffi::OsString;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, mpsc};
use std::time::{Duration, Instant};

/// 子へ接続先 socket の絶対パスを渡す環境変数名。
pub const PLUGIN_SOCKET_ENV: &str = "FANDHE_CONTAINER_PLUGIN_SOCKET";

/// [`OneShotTimeout`] の既定値（10 秒）。
pub const ONE_SHOT_TIMEOUT_DEFAULT: Duration = Duration::from_secs(10);

/// [`OneShotTimeout`] の上限（10 秒。残り時間を常に `RpcTimeout` へ変換できる値にする）。
pub const ONE_SHOT_TIMEOUT_MAX: Duration = Duration::from_secs(10);

/// 応答受信後に子の自発終了を待つ猶予（合計期限とは別枠）。
pub const ONE_SHOT_EXIT_TIMEOUT: Duration = Duration::from_secs(5);

/// 起動引数の件数上限。
pub const ONE_SHOT_ARGS_MAX_COUNT: usize = 64;

/// 起動引数の合計バイト数上限。
pub const ONE_SHOT_ARGS_MAX_BYTES: usize = 4096;

/// 子の終了待ちポーリング間隔の上限。
const POLL_MAX: Duration = Duration::from_millis(5);

/// 強制終了後の回収（`try_wait` ポーリング）を待つ上限（REPAIR-5。無期限の `wait` を避ける）。
pub const ONE_SHOT_REAP_TIMEOUT: Duration = Duration::from_secs(2);

/// plugin の stderr として保持するバイト数の上限（64 KiB。超過分は読み捨てる。無制限確保の防止）。
pub const ONE_SHOT_STDERR_MAX_BYTES: usize = 64 * 1024;

/// 子の回収後に stderr の読み取り完了（終端）を待つ上限（REPAIR-5。合計期限とは別枠）。
/// 子が終了していれば書き込み端は閉じており即座に完了する。孫プロセスが書き込み端を保持している
/// 場合のみこの期限まで待ち、読み取りを打ち切ってスレッドを停止させる。
pub const ONE_SHOT_STDERR_DRAIN_TIMEOUT: Duration = Duration::from_millis(500);

/// 打ち切りを指示した後、読み取りスレッドの停止を確認するまで待つ上限（REPAIR-5）。
/// shutdown で読み取りは即座に戻るため通常は待たない。スケジューリング遅延への余裕として設ける。
pub const ONE_SHOT_STDERR_STOP_TIMEOUT: Duration = Duration::from_secs(1);

/// stderr の読み取り 1 回の待ち上限。読み取りスレッドはこの間隔で停止指示を確認する
/// （shutdown による起床が効かない場合でも、この間隔で停止できる）。
#[cfg(unix)]
const STDERR_READ_POLL: Duration = Duration::from_millis(100);

/// spawn から応答受信までの合計期限（REPAIR-5）。0 と [`ONE_SHOT_TIMEOUT_MAX`] 超は構築できない。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OneShotTimeout(Duration);

impl OneShotTimeout {
    /// 0 または [`ONE_SHOT_TIMEOUT_MAX`] 超は `InvalidArgument`。
    pub fn new(timeout: Duration) -> Result<Self, PluginError> {
        if timeout.is_zero() || timeout > ONE_SHOT_TIMEOUT_MAX {
            return Err(PluginError::new(
                PluginErrorCode::InvalidArgument,
                "one-shot timeout must be non-zero and within the maximum",
            ));
        }
        Ok(Self(timeout))
    }

    /// 保持している期間を返す。
    pub fn as_duration(&self) -> Duration {
        self.0
    }
}

impl Default for OneShotTimeout {
    /// [`ONE_SHOT_TIMEOUT_DEFAULT`]（10 秒）。
    fn default() -> Self {
        Self(ONE_SHOT_TIMEOUT_DEFAULT)
    }
}

impl TryFrom<Duration> for OneShotTimeout {
    type Error = PluginError;

    fn try_from(timeout: Duration) -> Result<Self, Self::Error> {
        Self::new(timeout)
    }
}

/// 都度起動する plugin の起動仕様。検証済みの値のみ保持する。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OneShotPlugin {
    program: PathBuf,
    args: Vec<OsString>,
    socket_dir: PathBuf,
}

impl OneShotPlugin {
    /// `program` は絶対パス必須（`PATH` 探索をしない。PLUG-11）。引数は件数・合計バイト数を検証する。
    /// `socket_dir` は listener を置く 0700 ディレクトリ（通常は `RuntimeDir::path()`）。
    /// 違反は `InvalidArgument`。`program` の信頼性（ハッシュ等）は検証しない（TASK-122）。
    pub fn new(
        program: PathBuf,
        args: Vec<OsString>,
        socket_dir: PathBuf,
    ) -> Result<Self, PluginError> {
        if !program.is_absolute() {
            return Err(PluginError::new(
                PluginErrorCode::InvalidArgument,
                "plugin program path must be absolute",
            ));
        }
        let total: usize = args.iter().map(|a| a.len()).sum();
        if args.len() > ONE_SHOT_ARGS_MAX_COUNT || total > ONE_SHOT_ARGS_MAX_BYTES {
            return Err(PluginError::new(
                PluginErrorCode::InvalidArgument,
                "plugin arguments exceed the allowed count or size",
            ));
        }
        Ok(Self {
            program,
            args,
            socket_dir,
        })
    }

    /// 起動する実行ファイルの絶対パス。
    pub fn program(&self) -> &Path {
        &self.program
    }
}

/// 応答受信後の子プロセスの終了状況。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum OneShotTermination {
    /// 自発終了した（強制終了を試みる直前・直後に自発終了していた場合を含む）。`code` はシグナル
    /// 終了などで取得できない場合 `None`。
    Exited { code: Option<i32> },
    /// 猶予内に終了せず強制終了し、回収まで確認した（回収した終了状態が強制終了によるもの）。
    Killed,
    /// 強制終了を試みたが、[`ONE_SHOT_REAP_TIMEOUT`] 内に直接の子の回収を確認できなかった（直接の子への
    /// kill 失敗を含む）。呼び出し側は孤児の可能性として扱う（REPAIR-5・PLUG-7）。
    Unreaped,
    /// 直接の子は回収済み（pid は解放済み）だが、子のプロセスグループ宛ての kill が失敗し、孫プロセスの
    /// 停止を保証できない（#1311・PLUG-7・REPAIR-5）。未回収の子（[`Self::Unreaped`]）とは別の結果で、
    /// 成功した呼び出しの結果には現れない（呼び出しは `Internal` で失敗する）。
    ///
    /// 契約の限界: 送信自体が失敗した場合だけを表す。Linux の `killpg` は 1 プロセスにでも送れれば成功する
    /// ため、setuid 実行ファイル等で UID を変えた孫には SIGKILL が届かず残り得る。この部分配送による
    /// 残留は検出できず保証対象外（全数停止は cgroup・pidfd 等を要する別課題）。
    GroupKillFailed,
}

/// plugin が stderr へ書いた内容の収集結果（untrusted。出所は起動した plugin プロセス）。
///
/// 内容は plugin が任意に書けるバイト列であり、解釈・検証はしていない。呼び出し側がログへ出す
/// 場合は、plugin 由来であることを明示し、エスケープしたうえで扱うこと（構造化ログの行を偽装
/// され得るため、そのまま自プロセスの stderr・ログへ流さない）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OneShotStderr {
    bytes: Vec<u8>,
    total_bytes: u64,
    complete: bool,
    reader_stopped: bool,
}

impl OneShotStderr {
    /// 何も収集していない完了済みの結果（子を spawn しなかった経路用。読み取りスレッドなし）。
    fn empty() -> Self {
        Self {
            bytes: Vec::new(),
            total_bytes: 0,
            complete: true,
            reader_stopped: true,
        }
    }

    /// 保持している先頭部分（最大 [`ONE_SHOT_STDERR_MAX_BYTES`] バイト）。
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// 収集を打ち切るまでに plugin が書いた総バイト数（読み捨てた分を含む）。
    pub fn total_bytes(&self) -> u64 {
        self.total_bytes
    }

    /// 上限超過で読み捨てた部分があるか。
    pub fn is_truncated(&self) -> bool {
        u64::try_from(self.bytes.len()).map_or(true, |kept| self.total_bytes > kept)
    }

    /// 終端（全書き込み端の close）まで読み切ったか。false は [`ONE_SHOT_STDERR_DRAIN_TIMEOUT`] で
    /// 打ち切ったことを表す（孫プロセスが書き込み端を保持している等）。
    pub fn is_complete(&self) -> bool {
        self.complete
    }

    /// 読み取りスレッドの停止を確認できたか（終端到達、または打ち切り指示への応答）。
    /// false はスレッドが [`ONE_SHOT_STDERR_STOP_TIMEOUT`] 内に停止を返さなかったことを表し、
    /// 呼び出し側は資源の残留として扱う（REPAIR-4 の観測記録にも出す）。
    pub fn reader_stopped(&self) -> bool {
        self.reader_stopped
    }
}

/// 子の stderr を専用スレッドで読み、上限つきで保持する収集器（REPAIR-5）。
///
/// 読み取りは接続待ちの前から別スレッドで行う。親（呼び出しスレッド）は接続待ち・往復・回収の
/// 間に読まないため、子がバッファを超えて書いても子は詰まらず、親も読み取りでブロックしない。
/// 結果の受け取り（[`Self::finish`]）は期限つきで、期限内に終端へ達しなければ読み取りを打ち切って
/// スレッドを停止させる（スレッドを残さない）。`join` は行わず、停止の確認も期限つきで行う。
/// 常駐モード（`resident`。TASK-110.2）はセッション全期間で 1 本の収集器を保持する。
struct StderrCapture {
    state: Arc<Mutex<OneShotStderr>>,
    done: mpsc::Receiver<()>,
    stop_requested: Arc<AtomicBool>,
    /// ブロック中の読み取りを起こす操作（ソケットの shutdown）。1 回だけ実行する。
    wake: Option<Box<dyn FnOnce() + Send>>,
}

impl StderrCapture {
    /// `source` を終端または停止指示まで読むスレッドを起動する。起動できなければ `Err`
    /// （呼び出し側が子を回収する）。
    ///
    /// `source` の `read` は有限時間で戻ること（読み取り期限を設定済みで、期限切れは `WouldBlock` /
    /// `TimedOut` を返す）。`wake` はブロック中の `read` を即座に戻すための操作で、停止指示の後に
    /// 1 回だけ呼ぶ。
    fn start<R: Read + Send + 'static>(
        source: R,
        wake: Box<dyn FnOnce() + Send>,
    ) -> io::Result<Self> {
        let state = Arc::new(Mutex::new(OneShotStderr {
            bytes: Vec::new(),
            total_bytes: 0,
            complete: false,
            reader_stopped: false,
        }));
        let stop_requested = Arc::new(AtomicBool::new(false));
        let (tx, done) = mpsc::channel();
        let shared = Arc::clone(&state);
        let stop = Arc::clone(&stop_requested);
        std::thread::Builder::new()
            .name("plugin-stderr".to_string())
            .spawn(move || {
                drain_stderr(source, &shared, &stop);
                // 受け手が先に去っていても構わない。
                let _ = tx.send(());
            })?;
        Ok(Self {
            state,
            done,
            stop_requested,
            wake: Some(wake),
        })
    }

    /// 子の stderr を受けるソケットの読み取り側から収集を始める。停止時はソケットを shutdown して
    /// ブロック中の読み取りを起こす（以後、書き込み端を保持する孫の書き込みは `EPIPE` になる）。
    #[cfg(unix)]
    fn attach(reader: StderrReader) -> io::Result<Self> {
        let waker = reader.try_clone()?;
        Self::start(
            reader,
            Box::new(move || {
                let _ = waker.shutdown(std::net::Shutdown::Both);
            }),
        )
    }

    /// 非 unix では子を spawn しないため、空の入力を読むだけになる（即座に終端へ達する）。
    #[cfg(not(unix))]
    fn attach(reader: StderrReader) -> io::Result<Self> {
        Self::start(reader, Box::new(|| {}))
    }

    /// 読み取りスレッドへ停止を指示し、ブロック中の読み取りを起こす。
    fn request_stop(&mut self) {
        self.stop_requested.store(true, Ordering::SeqCst);
        if let Some(wake) = self.wake.take() {
            wake();
        }
    }

    /// 読み取り完了を `limit` まで待ち、その時点までの収集結果を返す。期限内に終端へ達しなければ
    /// 読み取りを打ち切り、スレッドの停止を [`ONE_SHOT_STDERR_STOP_TIMEOUT`] まで確認して
    /// `is_complete() == false` の途中結果を返す。
    fn finish(mut self, limit: Duration) -> OneShotStderr {
        // 送信側の消滅（Disconnected）はスレッドが終了したことを意味するため、停止済みとして扱う。
        let timed_out =
            |r: Result<(), mpsc::RecvTimeoutError>| r == Err(mpsc::RecvTimeoutError::Timeout);
        let mut stopped = !timed_out(self.done.recv_timeout(limit));
        if !stopped {
            self.request_stop();
            stopped = !timed_out(self.done.recv_timeout(ONE_SHOT_STDERR_STOP_TIMEOUT));
        }
        let mut result = lock_stderr(&self.state).clone();
        result.reader_stopped = stopped;
        result
    }
}

impl Drop for StderrCapture {
    /// `finish` を経ずに破棄される経路（panic 等）でもスレッドを残さない。
    fn drop(&mut self) {
        self.request_stop();
    }
}

/// 読み取りスレッドが panic しても収集結果を取り出せるよう、poison を無視して lock する。
fn lock_stderr(state: &Mutex<OneShotStderr>) -> MutexGuard<'_, OneShotStderr> {
    state.lock().unwrap_or_else(PoisonError::into_inner)
}

/// `source` を終端・エラー・停止指示のいずれかまで読み、先頭 [`ONE_SHOT_STDERR_MAX_BYTES`] バイト
/// だけ保持する。上限到達後も読み捨てを続ける（読むのを止めると子が書き込みで詰まり、応答・終了が
/// 遅れるため）。停止指示は読み取りのたびに確認するので、書き込みが続いていても停止できる。
fn drain_stderr<R: Read>(mut source: R, state: &Mutex<OneShotStderr>, stop: &AtomicBool) {
    let mut chunk = [0u8; 4096];
    loop {
        if stop.load(Ordering::SeqCst) {
            return;
        }
        match source.read(&mut chunk) {
            // 停止指示による shutdown でも 0 が返るため、指示後の 0 は終端として扱わない。
            Ok(0) => {
                if !stop.load(Ordering::SeqCst) {
                    lock_stderr(state).complete = true;
                }
                return;
            }
            Ok(n) => {
                let mut s = lock_stderr(state);
                let room = ONE_SHOT_STDERR_MAX_BYTES.saturating_sub(s.bytes.len());
                if let Some(kept) = chunk.get(..n.min(room)) {
                    s.bytes.extend_from_slice(kept);
                }
                s.total_bytes = s
                    .total_bytes
                    .saturating_add(u64::try_from(n).unwrap_or(u64::MAX));
            }
            // 読み取り期限切れ・割り込みは継続する（ループ先頭で停止指示を確認する）。
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::Interrupted
                ) => {}
            // その他の読み取りエラーは終端として扱わない（complete を立てない）。
            Err(_) => return,
        }
    }
}

/// 親が読む側の stderr 入力。unix は UNIX ソケット、非 unix は空の入力（子を spawn しないため）。
#[cfg(unix)]
type StderrReader = std::os::unix::net::UnixStream;
#[cfg(not(unix))]
type StderrReader = io::Empty;

/// 子の stderr に渡す書き込み端と、親が読む側の組を作る（REPAIR-5）。
///
/// pipe ではなく UNIX ソケット対を使う。pipe の読み取りは期限を掛けられず、書き込み端を孫が保持
/// している間は読み取りスレッドを止められない。ソケットなら読み取り期限と shutdown で確実に止め
/// られる（標準ライブラリの安全な API だけで実現できる）。子から見た書き込みは pipe と同様（端末ではなく、読み手が
/// 閉じれば `EPIPE`）。どちらの端も close-on-exec で、子へ渡るのは fd 2 に複製した書き込み端のみ。
#[cfg(unix)]
fn stderr_channel() -> io::Result<(Stdio, StderrReader)> {
    let (reader, writer) = std::os::unix::net::UnixStream::pair()?;
    // 相手が健在なうちに期限を設定する（macOS は相手切断後の設定が EINVAL になる）。
    reader.set_read_timeout(Some(STDERR_READ_POLL))?;
    Ok((Stdio::from(std::os::fd::OwnedFd::from(writer)), reader))
}

/// 非 unix では listener を bind できず子を spawn しないため到達しない（stderr は破棄する設定を返す）。
#[cfg(not(unix))]
fn stderr_channel() -> io::Result<(Stdio, StderrReader)> {
    Ok((Stdio::null(), io::empty()))
}

/// [`call_once`] の成功結果。
#[derive(Debug)]
#[non_exhaustive]
pub struct OneShotOutcome {
    response: Frame,
    termination: OneShotTermination,
    stderr: OneShotStderr,
}

impl OneShotOutcome {
    /// plugin から受信した応答フレーム（untrusted。内容は解釈していない）。
    pub fn response(&self) -> &Frame {
        &self.response
    }

    /// 応答フレームを取り出す。
    pub fn into_response(self) -> Frame {
        self.response
    }

    /// 子プロセスの終了状況。
    pub fn termination(&self) -> OneShotTermination {
        self.termination
    }

    /// plugin が stderr へ書いた内容（untrusted・上限つき）。
    pub fn stderr(&self) -> &OneShotStderr {
        &self.stderr
    }
}

/// 子プロセスを保持し、Drop で kill・回収を試みるガード（panic 等の早期離脱でも子を残さない）。
///
/// 回収の成否を呼び出し側へ返す責務は明示的な [`Self::kill_and_reap`] / [`Self::wait_or_kill`] の
/// 呼び出しが担う。直接の子の未回収（`Unreaped`）と、直接の子は回収済みでプロセスグループの停止だけが
/// 失敗した場合（`GroupKillFailed`）は別の結果として返し、呼び出し側はそれぞれ [`unreaped_error`]・
/// [`group_kill_failed_error`] で報告する（#1311・PLUG-7・REPAIR-5）。未回収として報告した後（[`unreaped_error`]）は `Drop` で回収しない。報告後に回収
/// すると、呼び出し側へ伝えた pid が解放済みになり、別プロセスを指し得るため（kill は報告前に送信
/// 済みで、`Drop` での再試行は待ち時間を延ばすだけになる）。
struct ChildGuard {
    child: Option<Child>,
    /// 未回収として pid を報告済みか。true なら `Drop` で回収しない。
    reported_unreaped: bool,
    /// シグナル転送の登録表のスロット（#1513）。子を回収し得る `waitpid` の前に登録を外し、回収した時点で
    /// 解放する。回収後に再利用された pid へシグナルを送らないための構造で、回収は必ず
    /// [`Self::try_wait`] / [`Self::kill_and_reap`] を経由する。
    slot: Option<SlotToken>,
    /// 直接の子（プロセスグループのリーダー）を wait 済みか。true ならグループ宛ての送信をしない。
    /// 回収後は pid（= pgid）が再利用され得るため、別プロセスのグループへ誤送信しないための印。
    /// `try_wait` が `Some` を返した時点で立てる。`Err`（状態確認の失敗）は回収済みの証明にならない
    /// ため立てず、グループ宛ての SIGKILL を省略しない（孫が残り得る。#1311・PLUG-7・REPAIR-5）。
    leader_reaped: bool,
}

impl ChildGuard {
    fn new(child: Child) -> Self {
        Self {
            child: Some(child),
            reported_unreaped: false,
            slot: None,
            leader_reaped: false,
        }
    }

    /// 登録表のスロットを持たせる（[`spawn_registered`] が使う）。
    fn with_slot(mut self, slot: SlotToken) -> Self {
        self.slot = Some(slot);
        self
    }

    fn pid(&self) -> Option<u32> {
        self.child.as_ref().map(Child::id)
    }

    /// 終了を非ブロックで確認する。回収し得るため、直前に登録表から外し（進行中の転送の完了を待つ）、
    /// まだ動いていれば戻す。外した窓の間に届いたシグナルは転送されない（取りこぼす側）。進行中の転送の
    /// 完了を確認できないときは回収せず `Ok(None)`（まだ動いている扱い）を返し、次の周回に委ねる。
    /// 将来 `suspend` を使わず pidfd 等で回収と転送の競合を除く案がある（現状は #1514 の `PR_SET_PDEATHSIG` で補完する）。
    fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        let Some(c) = self.child.as_mut() else {
            return Ok(None);
        };
        if let Some(slot) = &self.slot
            && !slot.suspend()
        {
            slot.resume();
            return Ok(None);
        }
        let result = c.try_wait();
        match result {
            // 回収した。pid は再利用され得るため、登録を戻さず解放する。グループ宛ての送信も止める。
            Ok(Some(_)) => {
                self.slot = None;
                self.leader_reaped = true;
            }
            // Err は状態不明のため leader_reaped を立てない（グループ停止を試みられるようにする。fail-closed）。
            _ => {
                if let Some(slot) = &self.slot {
                    slot.resume();
                }
            }
        }
        result
    }

    /// 子を回収済みとして手放す。以後 `kill_and_reap` は何も送らない。
    fn release_reaped(&mut self) {
        self.child = None;
        self.slot = None;
        self.leader_reaped = true;
    }

    /// kill して回収を `ONE_SHOT_REAP_TIMEOUT` まで待つ。
    ///
    /// kill の失敗は無視せず、回収確認ができなければ `Unreaped` を返す（呼び出し側が報告する）。
    /// 直接の子を回収できてもグループ宛ての送信が許容外のエラーで失敗した場合は `GroupKillFailed` を
    /// 返す（子は手放し済みで、未回収とは区別する）。
    /// 回収できなかった場合は `Child` を保持し続ける（呼び出し側が pid を報告できるよう手放さない）。
    /// 回収できた場合は終了状態を捨てずに返す。kill の直前・直後に子が自発終了していた場合、
    /// 回収される状態は「こちらの kill」ではなく子自身の終了状態になるため、呼び出し側が
    /// [`classify_reaped`] で区別する（異常終了を強制終了と取り違えて成功扱いしない。PLUG-7）。
    fn kill_and_reap(&mut self) -> Reap {
        let Some(c) = self.child.as_mut() else {
            return Reap::AlreadyReaped;
        };
        // 直後に SIGKILL するため転送は不要。以後の回収で pid が再利用され得るので、先に登録を外し、
        // 進行中の転送の完了を待つ。上限内に確認できなければ回収しない（ロード済みの pid へ送信中の
        // 転送スレッドが、回収後に再利用された pid へ送る誤配送を防ぐ。PLUG-7・fail-closed）。
        // この場合も kill は安全（未回収の子の pid は再利用されない）なので送り、`Unreaped` を返す。
        // `Child` は保持し続け、回収は行わない（pid を回収前に手放さない）。
        if let Some(slot) = self.slot.take()
            && !slot.suspend()
        {
            // 直接の子は未回収なので pid（= pgid）は再利用されず、グループへの送信は安全。
            #[cfg(unix)]
            if !self.leader_reaped {
                let _ = crate::sys::kill_process_group(c.id());
            }
            let _ = c.kill();
            self.slot = Some(slot);
            return Reap::Unreaped;
        }
        // 子のプロセスグループ全体（孫を含む）へ SIGKILL を 1 回送る（#1311）。リーダーを自分がまだ
        // wait していない間に限る。ゾンビでも未回収の間は pid（= pgid）が再利用されないため、送信先は
        // 自分が起動したグループに限られる。最初の `try_wait` より前に送るのは、自発終了済み（ゾンビ）の
        // 子を先に回収すると孫へ送る安全な機会を失うため（ゾンビの終了状態はシグナルで変わらず、
        // `classify_reaped` の区別は保たれる）。許容するエラーは「グループに生存者がいない」ことを
        // 示すものに限る（`group_kill_tolerated`）。それ以外の失敗は孫の停止を保証できないため、
        // 直接の子を回収できても `GroupKillFailed` を返す（成功扱いにしない。回収済みの子を未回収とも
        // 報告しない。PLUG-7・REPAIR-5）。直接の子も回収できなければ `Unreaped` が優先する。
        #[cfg(unix)]
        let group_failed = !self.leader_reaped
            && kill_group_retrying_eperm(c.id())
                .err()
                .is_some_and(|e| !group_kill_tolerated(&e));
        #[cfg(not(unix))]
        let group_failed = false;
        // kill の前に終了済みかを確認し、自発終了の状態をそのまま拾う（kill との競合窓を狭める）。
        if let Ok(Some(status)) = c.try_wait() {
            self.release_reaped();
            if group_failed {
                return Reap::GroupKillFailed;
            }
            return Reap::Reaped(status);
        }
        // setsid / setpgid でグループを抜けた plugin 本体も確実に止めるフォールバック。
        let _ = c.kill();
        let start = Instant::now();
        let mut interval = Duration::from_millis(1);
        loop {
            match c.try_wait() {
                Ok(Some(status)) => {
                    self.release_reaped();
                    if group_failed {
                        return Reap::GroupKillFailed;
                    }
                    return Reap::Reaped(status);
                }
                Ok(None) => {}
                Err(_) => return Reap::Unreaped,
            }
            if start.elapsed() >= ONE_SHOT_REAP_TIMEOUT {
                return Reap::Unreaped;
            }
            std::thread::sleep(interval);
            interval = (interval * 2).min(POLL_MAX);
        }
    }

    /// 終了を `limit` まで待つ。終了していれば状態を返し、猶予超過なら強制終了する。
    /// 強制終了後に回収した終了状態は [`classify_reaped`] で分類する（`Killed` と決め打ちしない）。
    fn wait_or_kill(&mut self, limit: Duration) -> OneShotTermination {
        let start = Instant::now();
        let mut interval = Duration::from_millis(1);
        loop {
            match self.try_wait() {
                Ok(Some(status)) => {
                    self.release_reaped();
                    return OneShotTermination::Exited {
                        code: status.code(),
                    };
                }
                Ok(None) => {}
                Err(_) => break,
            }
            if start.elapsed() >= limit {
                break;
            }
            std::thread::sleep(interval);
            interval = (interval * 2).min(POLL_MAX);
        }
        termination_after_kill(self.kill_and_reap())
    }
}

/// 終了猶予の超過後に行った [`ChildGuard::kill_and_reap`] の結果を終了状況へ写す（PLUG-7・REPAIR-5）。
///
/// グループ停止の失敗（直接の子は回収済み）は未回収の子と区別して保つ。`Unreaped` へ畳むと、呼び出し側が
/// 回収済みの子を「回収できなかった」と誤って報告するため（#1311）。
fn termination_after_kill(reap: Reap) -> OneShotTermination {
    match reap {
        Reap::Reaped(status) => classify_reaped(status),
        // 孫の停止を保証できないため成功扱いにしないが、直接の子は回収済みなので未回収にもしない。
        Reap::GroupKillFailed => OneShotTermination::GroupKillFailed,
        // 既に回収済みのガードに対して呼ばれることはないが、終了状態が不明なため成功扱いしない。
        Reap::AlreadyReaped | Reap::Unreaped => OneShotTermination::Unreaped,
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if !self.reported_unreaped {
            let _ = self.kill_and_reap();
        }
    }
}

/// `EPERM` が出た間だけ短時間再送する上限（#1311・PLUG-7・REPAIR-5）。
#[cfg(unix)]
const GROUP_KILL_EPERM_RETRY: Duration = Duration::from_millis(200);

/// プロセスグループへ `SIGKILL` を送る。`EPERM` のときだけ [`GROUP_KILL_EPERM_RETRY`] まで再送する。
///
/// macOS は spawn 直後で plugin 本体が `exec` 中の窓にも `kill(2)` が `EPERM` を返すことがあり、この一過性の
/// 失敗を 1 回で確定すると生存中のグループを `GroupKillFailed` と誤報し、直後の `Child::kill` も同じ窓で
/// 失敗して回収できなくなる。窓は短いので再送で解消する。ゾンビのみのグループの `EPERM` は解消しないため、
/// 上限後は最後のエラーをそのまま返し、呼び出し側が `GroupKillFailed` として報告する（成功扱いにしない）。
/// 呼び出し側の不変条件（リーダー未回収）は [`crate::sys::kill_process_group`] と同じ。
#[cfg(unix)]
fn kill_group_retrying_eperm(pgid: u32) -> io::Result<()> {
    const EPERM: i32 = 1;
    let start = Instant::now();
    let mut interval = Duration::from_millis(1);
    loop {
        match crate::sys::kill_process_group(pgid) {
            Err(e)
                if e.raw_os_error() == Some(EPERM) && start.elapsed() < GROUP_KILL_EPERM_RETRY =>
            {
                std::thread::sleep(interval);
                interval = (interval * 2).min(POLL_MAX);
            }
            other => return other,
        }
    }
}

/// プロセスグループへの `SIGKILL` 送信エラーのうち、グループに生存者がいないことを示すものか。
///
/// `ESRCH`（グループが空）は正常。`EPERM` はどの OS でも許容しない。macOS ではゾンビのみのグループでも
/// 生存者への送信権限不足（setuid 実行ファイル経由で別 UID に変わった孫など）でも `EPERM` になり、再送後も
/// 両者を区別できないため、生存者不在の証明として扱わず、孫の停止を保証できない失敗として呼び出し側
/// （`kill_and_reap`）が `GroupKillFailed` として報告する（PLUG-7・REPAIR-5）。`Unsupported` はグループ送信を持たない unix
/// （Linux・macOS 以外）で、送信自体ができないことと直接の子の回収成否は別問題のため許容し、
/// `Child::kill` による直接の子の kill・回収だけにフォールバックする（孫の回収は保証しない。この環境では
/// 回収済みの pid を未回収として報告しない。PLUG-7・#1311）。それ以外（`InvalidInput` 等）は孫の停止を
/// 保証できず、同じく `GroupKillFailed` として報告する（直接の子も回収できなかった場合だけ `Unreaped`）。
#[cfg(unix)]
fn group_kill_tolerated(e: &io::Error) -> bool {
    const ESRCH: i32 = 3;
    if e.kind() == io::ErrorKind::Unsupported {
        return true;
    }
    e.raw_os_error() == Some(ESRCH)
}

/// [`ChildGuard::kill_and_reap`] の結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reap {
    /// 今回の呼び出しで回収した。終了状態は子の自発終了・こちらの kill のどちらの場合もある。
    Reaped(ExitStatus),
    /// 既に回収済みで保持している子がない。
    AlreadyReaped,
    /// 直接の子は回収済み（pid は解放済みで報告対象にしない）だが、グループ宛て SIGKILL が許容外の
    /// エラーで失敗し、孫の停止を保証できない。呼び出し側は `Unreaped`（未回収の子）へ畳まず、元の
    /// エラーに代えて [`group_kill_failed_error`] を返す（PLUG-7・REPAIR-5）。
    GroupKillFailed,
    /// kill 失敗または期限超過で回収を確認できなかった（孤児の可能性）。
    Unreaped,
}

impl Reap {
    /// 直接の子の回収とグループ停止の両方を確認できたか。`GroupKillFailed` は孫の停止を保証できない
    /// ため偽（呼び出し側は [`group_kill_failed_error`] で後始末の失敗として報告する）。
    #[cfg(test)]
    fn is_reaped(self) -> bool {
        matches!(self, Self::Reaped(_) | Self::AlreadyReaped)
    }
}

/// 強制終了を試みた後に回収した終了状態を分類する（PLUG-7・REPAIR-5）。
///
/// 終了猶予の境界では、最後の `try_wait` と `kill` の間に子が自発終了し得る。その場合に回収される
/// のは子自身の終了状態であり、`Killed`（成功扱い）にすると非ゼロ終了を見逃す。そのため終了コードを
/// 持つ状態と `SIGKILL` 以外のシグナルによる終了は `Exited` として返し、成功 / 失敗の判定を
/// `call_once` 側の終了コード検査へ委ねる。`SIGKILL` による終了のみ `Killed` とする
/// （外部からの `SIGKILL` とこちらの kill は区別できないが、どちらも kill を試みた後の強制終了である）。
fn classify_reaped(status: ExitStatus) -> OneShotTermination {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if status.signal() == Some(crate::sys::SIGKILL) {
            return OneShotTermination::Killed;
        }
        OneShotTermination::Exited {
            code: status.code(),
        }
    }
    // 非 unix では listener を bind できず子を spawn しないため到達しない。終了コード 0 の自発終了
    // だけを `Exited` とし、それ以外は強制終了（`TerminateProcess` 相当）と区別できないため
    // `Killed` として扱う。
    #[cfg(not(unix))]
    {
        match status.code() {
            Some(0) => OneShotTermination::Exited { code: Some(0) },
            _ => OneShotTermination::Killed,
        }
    }
}

fn remaining(deadline: Instant) -> Result<Duration, PluginError> {
    match deadline.checked_duration_since(Instant::now()) {
        Some(d) if !d.is_zero() => Ok(d),
        _ => Err(timeout_error()),
    }
}

fn timeout_error() -> PluginError {
    PluginError::new(PluginErrorCode::Timeout, "one-shot plugin call timed out")
}

fn rpc_timeout(remaining: Duration) -> Result<RpcTimeout, PluginError> {
    RpcTimeout::new(remaining.min(ONE_SHOT_TIMEOUT_MAX))
}

fn spawn_error(e: &io::Error) -> PluginError {
    let (code, msg) = match e.kind() {
        io::ErrorKind::NotFound => (PluginErrorCode::NotFound, "plugin program not found"),
        io::ErrorKind::PermissionDenied => (
            PluginErrorCode::PermissionDenied,
            "permission denied spawning plugin program",
        ),
        _ => (
            PluginErrorCode::Unavailable,
            "failed to spawn plugin program",
        ),
    };
    PluginError::new(code, msg)
}

/// plugin を 1 回起動して 1 往復し、終了を確認して回収する（PLUG-7・REPAIR-5）。
///
/// 流れ: 一意名で listener を bind -> 子を spawn -> 接続を受け付け -> `request` 送信 -> 応答受信 ->
/// 接続を閉じて子の終了を待つ。spawn から応答受信までが `timeout` の合計期限。接続前に子が
/// 終了した場合は期限を待たず `Unavailable`。応答は得たが子が [`ONE_SHOT_EXIT_TIMEOUT`] 内に
/// 終了しなかった場合は強制終了し、`Ok` と [`OneShotTermination::Killed`] を返す。応答後に非ゼロ・
/// シグナルで終了した場合は `Unavailable`、回収を確認できない場合は `Internal` を返す（このときだけ
/// 子が残っている可能性がある。メッセージに子の pid を含み、その子は以後回収しない。モジュール冒頭の
/// 契約を参照）。
///
/// stderr の読み取りスレッドは戻るまでに停止させる。停止を確認できなかった場合は
/// [`OneShotStderr::reader_stopped`] が false になる。
/// 非 unix では listener の bind が `Unimplemented` を返し、子は spawn されない。
///
/// plugin の stderr は親へ継承させず [`OneShotOutcome::stderr`] で返す。本関数が親の stderr へ出す
/// 構造化ログには、plugin の stderr の内容は含めず件数のみ載せる。失敗時の内容が必要な呼び出し側は
/// [`call_once_observed`] の [`OneShotRecord::stderr`] を使う。
///
/// `audit` は受付で拒否した接続（UID・pid の不一致・取得失敗）の監査イベントの受け手で、拒否 1 件に
/// つき 1 回、同期で呼ばれる（PLUG-12・SEC-4・TASK-124.5）。必須で、既定の出力先は無い（出力・永続化は
/// 呼び出し側の責務。`crate::audit` のモジュール doc）。
pub fn call_once(
    plugin: &OneShotPlugin,
    request: &Frame,
    timeout: OneShotTimeout,
    audit: &mut dyn crate::audit::PeerAuthObserver,
) -> Result<OneShotOutcome, PluginError> {
    call_once_observed(plugin, request, timeout, audit, &mut |record| {
        use std::io::Write;
        // 構造化ログ（JSON Lines）を stderr へ 1 行出す。書き込み失敗は呼び出し結果に影響させない。
        let _ = writeln!(io::stderr(), "{}", record.to_json_line());
    })
}

/// 1 回の [`call_once`] の観測記録（成功 / 失敗とレイテンシ。REPAIR-4）。
///
/// 呼び出し側（core の plugin proxy 等）が `observer` で受け取り、成功 / 失敗件数とレイテンシ分布へ
/// 集計する。`fandhe-container-core` の `OpRecorder` は依存方向（`core -> plugin`）のため本 crate から
/// 参照できないので、記録の受け渡しは本型で行う。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct OneShotRecord {
    /// 操作名（固定値 `plugin.call_once`）。
    pub operation: &'static str,
    /// 成功したか。
    pub success: bool,
    /// 失敗時の機械可読な `code`（ERR-1）。成功時は `None`。
    pub error_code: Option<&'static str>,
    /// 開始から戻るまでの所要時間（子の回収待ち・stderr の収集待ちを含む）。
    pub elapsed: Duration,
    /// plugin が stderr へ書いた内容（untrusted・上限つき）。成功・失敗のどちらでも渡す。
    /// [`Self::to_json_line`] には内容を含めず、件数と打ち切りの有無だけを出す。
    pub stderr: OneShotStderr,
}

impl OneShotRecord {
    /// JSON Lines の 1 行（改行なし）へ符号化する。値はすべて固定文字列・数値・真偽値のみで、外部入力
    /// （plugin の stderr の内容を含む）を埋め込まない。stderr は出所を明示したキー
    /// （`plugin_stderr_*`）で件数・打ち切りの有無・読み取りスレッドの停止確認だけを出す。
    pub fn to_json_line(&self) -> String {
        let code = match self.error_code {
            Some(c) => format!("\"{c}\""),
            None => "null".to_string(),
        };
        format!(
            "{{\"op\":\"{}\",\"success\":{},\"error_code\":{},\"elapsed_us\":{},\
             \"plugin_stderr_bytes\":{},\"plugin_stderr_truncated\":{},\
             \"plugin_stderr_complete\":{},\"plugin_stderr_reader_stopped\":{}}}",
            self.operation,
            self.success,
            code,
            self.elapsed.as_micros(),
            self.stderr.total_bytes(),
            self.stderr.is_truncated(),
            self.stderr.is_complete(),
            self.stderr.reader_stopped()
        )
    }
}

/// [`call_once`] と同じ処理を行い、終了時に 1 件の [`OneShotRecord`] を `observer` へ渡す（REPAIR-4）。
///
/// 成功・失敗のどの終了経路でも必ず 1 回だけ呼ばれる。`observer` は呼び出しスレッド上で同期的に
/// 実行されるため、長時間ブロックしないこと。`audit` は [`call_once`] と同じ（peer 認証の拒否イベントの
/// 受け手。必須）。
pub fn call_once_observed(
    plugin: &OneShotPlugin,
    request: &Frame,
    timeout: OneShotTimeout,
    audit: &mut dyn crate::audit::PeerAuthObserver,
    observer: &mut dyn FnMut(&OneShotRecord),
) -> Result<OneShotOutcome, PluginError> {
    let start = Instant::now();
    let (result, stderr) = call_once_inner(plugin, request, timeout, audit, &PLUGIN_REGISTRY);
    observer(&OneShotRecord {
        operation: "plugin.call_once",
        success: result.is_ok(),
        error_code: result.as_ref().err().map(|e| e.code().as_str()),
        elapsed: start.elapsed(),
        stderr: stderr.clone(),
    });
    result.map(|(response, termination)| OneShotOutcome {
        response,
        termination,
        stderr,
    })
}

/// plugin 本体（直接の子）を親の生存に結び付ける（Linux のみ。`PR_SET_PDEATHSIG`。#1514・#1403 の方式 B・
/// PLUG-7・REPAIR-5・CORE-1）。都度起動 / 常駐の spawn 直前に呼び、spawn 箇所へ cfg を持ち込まない。
/// Linux 以外では何もしない（macOS に同等の機構はなく残留し得る。Windows は対象外）。
#[cfg(target_os = "linux")]
fn bind_to_parent_lifetime(cmd: &mut Command) -> Result<(), PluginError> {
    crate::sys::set_parent_death_sigkill(cmd, std::process::id()).map_err(|_| {
        PluginError::new(
            PluginErrorCode::Internal,
            "failed to configure plugin parent-death signal",
        )
    })
}

/// Linux 以外では親死亡シグナルを設定しない（従来どおり起動する）。
#[cfg(not(target_os = "linux"))]
fn bind_to_parent_lifetime(_cmd: &mut Command) -> Result<(), PluginError> {
    Ok(())
}

/// listener の bind・子の spawn・stderr の収集・往復・回収までを行う。戻り値の第 2 要素は、
/// 成功・失敗のどちらでも子の回収後に確定した stderr の収集結果（spawn 前の失敗は空）。
fn call_once_inner(
    plugin: &OneShotPlugin,
    request: &Frame,
    timeout: OneShotTimeout,
    audit: &mut dyn crate::audit::PeerAuthObserver,
    registry: &'static Registry,
) -> (
    Result<(Frame, OneShotTermination), PluginError>,
    OneShotStderr,
) {
    static SEQ: AtomicU64 = AtomicU64::new(0);

    let Some(deadline) = Instant::now().checked_add(timeout.as_duration()) else {
        return (Err(timeout_error()), OneShotStderr::empty());
    };

    // 異常終了で残るこの名前の socket とロックファイルは、runtime directory の初期化時に掃除される
    // （`RuntimeDir::sweep_one_shot_leftovers`。#1310）。呼び出しごとの列挙で境界レイテンシを増やさない。
    let name = format!(
        "oneshot-{}-{}.sock",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    );
    let listener = match UdsListener::bind(&plugin.socket_dir.join(name)) {
        Ok(l) => l,
        Err(e) => return (Err(e), OneShotStderr::empty()),
    };

    // stderr は親へ継承させない（plugin が親の stderr へ任意の量・内容を書けてしまうため）。
    let (child_stderr, reader) = match stderr_channel() {
        Ok(pair) => pair,
        Err(_) => {
            return (
                Err(PluginError::new(
                    PluginErrorCode::Internal,
                    "failed to prepare capturing plugin stderr",
                )),
                OneShotStderr::empty(),
            );
        }
    };
    // `Command` は文の終わりで drop され、親側に書き込み端は残らない（終端の検出を妨げない）。
    let spawned = {
        let mut cmd = Command::new(&plugin.program);
        cmd.args(&plugin.args)
            .env_clear()
            .env(PLUGIN_SOCKET_ENV, listener.path())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(child_stderr);
        if let Err(e) = bind_to_parent_lifetime(&mut cmd) {
            return (Err(e), OneShotStderr::empty());
        }
        spawn_registered(&mut cmd, registry)
    };
    let mut guard = match spawned {
        Ok(g) => g,
        Err(e) => return (Err(e), OneShotStderr::empty()),
    };

    // 接続待ちより前に読み取りを始める（子が接続前に大量に書いても詰まらせない）。
    let capture = match StderrCapture::attach(reader) {
        Ok(c) => c,
        // 読み取り手がいないまま子を走らせるとバッファが埋まって子が詰まるため、往復せず回収する。
        Err(_) => {
            drop(listener);
            let error = reap_after_failure(
                &mut guard,
                PluginError::new(
                    PluginErrorCode::Internal,
                    "failed to start capturing plugin stderr",
                ),
            );
            return (Err(error), OneShotStderr::empty());
        }
    };
    let result = exchange_and_reap(&mut guard, listener, request, deadline, audit);
    // 子の回収後に収集結果を受け取る。子が終了していれば書き込み端は閉じており即座に完了する。
    // 戻る時点で読み取りスレッドは停止している（停止を確認できなければ結果に記録する）。
    let stderr = capture.finish(ONE_SHOT_STDERR_DRAIN_TIMEOUT);
    (result, stderr)
}

/// 登録表のスロットを確保してから子を spawn し、pid を登録したガードを返す（#1513・PLUG-7）。
///
/// unix では子を新しいプロセスグループ（pgid == 子の pid）で起動する（`process_group(0)`。#1311）。
/// 都度起動・常駐の両モードがこの関数を共用するので 2 か所の起動条件は食い違わない。`ChildGuard::kill_and_reap` が
/// グループ全体へ SIGKILL を送って plugin の孫を残さず、登録表のシグナル転送（#1513）も `kill(-pid)` で
/// 孫まで届く。`PR_SET_PDEATHSIG`（#1514。`bind_to_parent_lifetime`）とは独立に併用できる（前者は `pre_exec`、
/// 後者は fork 時のグループ設定で干渉しない）。
/// Windows にプロセスグループ単位の kill は無く（Job Object は別タスク）、unix transport も無いため対象外。
///
/// 確保を spawn より前に行うので、表が満杯のときは子を一切起動せず `ResourceExhausted` で拒否する
/// （fail-closed。追跡できない子を作らない）。spawn の失敗・pid の範囲外ではスロットを解放し、
/// 起動済みの子は kill・回収する。`registry` は本番では [`PLUGIN_REGISTRY`]（テストは局所の表）。
fn spawn_registered(
    cmd: &mut Command,
    registry: &'static Registry,
) -> Result<ChildGuard, PluginError> {
    let mut slot = registry.reserve()?;
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }
    let child = cmd.spawn().map_err(|e| spawn_error(&e))?;
    let pid = child.id();
    // activate が失敗した場合は guard の Drop が子を kill・回収する。
    let guard = ChildGuard::new(child);
    slot.activate(pid)?;
    Ok(guard.with_slot(slot))
}

/// 応答前の失敗経路で子を明示的に kill・回収する。回収を確認できなければ、元のエラーではなく
/// 回収失敗（`Internal`）を返す（孤児の可能性を呼び出し側へ伝える。REPAIR-5・PLUG-7）。
fn reap_after_failure(guard: &mut ChildGuard, error: PluginError) -> PluginError {
    match guard.kill_and_reap() {
        Reap::Reaped(_) | Reap::AlreadyReaped => error,
        Reap::GroupKillFailed => group_kill_failed_error("a failed exchange"),
        Reap::Unreaped => unreaped_error(guard, "a failed exchange"),
    }
}

/// 直接の子は回収済みだが、プロセスグループ宛て SIGKILL が失敗し孫の停止を保証できないことを
/// 伝えるエラー（`Internal`）。元のエラーに隠さず、後始末の失敗として呼び出し側へ返す
/// （PLUG-7・REPAIR-5・#1311）。直接の子の pid は解放済みのため含めない。
pub(crate) fn group_kill_failed_error(phase: &str) -> PluginError {
    PluginError::new(
        PluginErrorCode::Internal,
        format!(
            "plugin process group could not be killed after {phase}; the direct child was reaped but descendant processes may remain"
        ),
    )
}

/// 回収を確認できなかった子についてのエラー（`Internal`）。呼び出し側が未回収の子を特定できるよう
/// pid を含める（pid は自プロセスが起動した子のもので、外部入力ではない）。
///
/// 報告した pid を以後も有効に保つため、`guard` に報告済みの印を付けて `Drop` での回収を止める。
fn unreaped_error(guard: &mut ChildGuard, phase: &str) -> PluginError {
    let message = match guard.pid() {
        Some(pid) => {
            guard.reported_unreaped = true;
            // 以後は回収しないが、SIGKILL は送信済み。スロットのリークを防ぐため解放する。
            guard.slot = None;
            format!("plugin process (pid {pid}) could not be reaped after {phase}")
        }
        None => format!("plugin process could not be reaped after {phase}"),
    };
    PluginError::new(PluginErrorCode::Internal, message)
}

/// 接続の受付・1 往復・子の回収を行う。`Ok` で戻る時点で子は回収済み。回収を確認できなかった場合は
/// `Internal`（[`unreaped_error`]）を返し、以後 `guard` はその子を回収しない。子は回収できたが
/// プロセスグループを停止できなかった場合は `Internal`（[`group_kill_failed_error`]）を返す。
fn exchange_and_reap(
    guard: &mut ChildGuard,
    listener: UdsListener,
    request: &Frame,
    deadline: Instant,
    audit: &mut dyn crate::audit::PeerAuthObserver,
) -> Result<(Frame, OneShotTermination), PluginError> {
    // 受付・往復はブロック内で完結させ、抜けた時点で接続を閉じて子に EOF を見せる
    // （続けて listener を drop して socket を unlink してから終了を待つ）。
    let exchange = (|| -> Result<Frame, PluginError> {
        let child_pid = guard.pid().ok_or_else(|| {
            PluginError::new(
                PluginErrorCode::Internal,
                "plugin process handle is missing",
            )
        })?;
        let mut stream = {
            let left = remaining(deadline)?;
            // 接続待ちの間は子の早期終了を確認し、期限を待たず Unavailable にする。
            // 応答者は spawn した子の pid に限定する（同一 UID の別プロセスの先取りを防ぐ。PLUG-7）。
            let mut check_child = || match guard.try_wait() {
                Ok(None) => None,
                Ok(Some(_)) | Err(_) => Some(PluginError::new(
                    PluginErrorCode::Unavailable,
                    "plugin exited before connecting",
                )),
            };
            listener.accept_peer_pid(left, child_pid, &mut check_child, audit)?
        };
        stream.write_frame(request, rpc_timeout(remaining(deadline)?)?)?;
        stream.read_frame(rpc_timeout(remaining(deadline)?)?)
    })();
    drop(listener);
    // 応答前のエラー経路でも、ここで子を明示的に kill・回収し、回収失敗を呼び出し側へ返す（REPAIR-5・PLUG-7）。
    let response = match exchange {
        Ok(r) => r,
        Err(e) => return Err(reap_after_failure(guard, e)),
    };
    let termination = guard.wait_or_kill(ONE_SHOT_EXIT_TIMEOUT);
    check_termination_after_response(guard, termination).map(|()| (response, termination))
}

/// 応答受信後の終了状況を検査する。回収を確認できない子（孤児の可能性）・グループ停止の失敗（孫が残る
/// 可能性）・異常終了（非ゼロ・シグナル）は成功扱いにしない（REPAIR-5・PLUG-7）。
///
/// グループ停止の失敗では直接の子は回収済みのため、未回収（[`unreaped_error`]）としては報告せず、
/// `guard` に報告済みの印も付けない（#1311）。
fn check_termination_after_response(
    guard: &mut ChildGuard,
    termination: OneShotTermination,
) -> Result<(), PluginError> {
    match termination {
        OneShotTermination::Unreaped => Err(unreaped_error(guard, "the response")),
        OneShotTermination::GroupKillFailed => Err(group_kill_failed_error("the response")),
        OneShotTermination::Exited { code: Some(0) } | OneShotTermination::Killed => Ok(()),
        OneShotTermination::Exited { .. } => Err(PluginError::new(
            PluginErrorCode::Unavailable,
            "plugin process exited abnormally after the response",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// PLUG-7・#1311: グループ送信エラーの許容は ESRCH と Unsupported（送信非対応 unix で直接の子の
    /// 回収結果を Unreaped に変えない）のみ。InvalidInput は許容しない。
    #[cfg(unix)]
    #[test]
    fn plug7_group_kill_tolerates_only_empty_group_errors() {
        assert!(group_kill_tolerated(&io::Error::from_raw_os_error(3)));
        assert!(!group_kill_tolerated(&io::Error::from(
            io::ErrorKind::InvalidInput
        )));
        assert!(group_kill_tolerated(&io::Error::from(
            io::ErrorKind::Unsupported
        )));
        assert!(!group_kill_tolerated(&io::Error::from_raw_os_error(22)));
        // EPERM は生存者への権限不足と区別できないため、どの OS でも失敗として扱う。
        assert!(!group_kill_tolerated(&io::Error::from_raw_os_error(1)));
    }

    #[test]
    fn plug7_timeout_rejects_zero_and_over_max() {
        for d in [
            Duration::ZERO,
            ONE_SHOT_TIMEOUT_MAX + Duration::from_millis(1),
        ] {
            let e = OneShotTimeout::new(d).unwrap_err();
            assert_eq!(e.code(), PluginErrorCode::InvalidArgument);
        }
        assert_eq!(
            OneShotTimeout::default().as_duration(),
            Duration::from_secs(10)
        );
        assert!(OneShotTimeout::new(ONE_SHOT_TIMEOUT_MAX).is_ok());
    }

    /// REPAIR-4: 失敗経路でも観測記録が 1 件・機械可読 code 付きで渡される。
    #[test]
    fn repair4_observer_receives_failure_record() {
        let abs = if cfg!(windows) { "C:\\p" } else { "/bin/p" };
        let dir = std::env::temp_dir().join("fcos-nonexistent-observer-dir");
        let plugin = OneShotPlugin::new(abs.into(), vec![], dir).unwrap();
        let req = Frame::new(Vec::new()).unwrap();
        let mut records = Vec::new();
        let r = call_once_observed(
            &plugin,
            &req,
            OneShotTimeout::default(),
            &mut crate::audit::NoopPeerAuthObserver,
            &mut |rec| records.push(rec.clone()),
        );
        assert!(r.is_err());
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].operation, "plugin.call_once");
        assert!(!records[0].success);
        assert!(records[0].error_code.is_some());
        // 子を spawn していない経路では stderr の収集結果は空で完了済み。
        assert_eq!(records[0].stderr, OneShotStderr::empty());
    }

    #[test]
    fn repair4_record_json_line_is_stable() {
        let rec = OneShotRecord {
            operation: "plugin.call_once",
            success: false,
            error_code: Some("TIMEOUT"),
            elapsed: Duration::from_micros(1500),
            stderr: OneShotStderr {
                bytes: b"\"}\n{\"op\":\"forged\"}".to_vec(),
                total_bytes: 70000,
                complete: false,
                reader_stopped: true,
            },
        };
        // plugin の stderr の内容は行へ埋め込まず、出所を明示したキーで件数だけを出す。
        assert_eq!(
            rec.to_json_line(),
            "{\"op\":\"plugin.call_once\",\"success\":false,\"error_code\":\"TIMEOUT\",\
             \"elapsed_us\":1500,\"plugin_stderr_bytes\":70000,\
             \"plugin_stderr_truncated\":true,\"plugin_stderr_complete\":false,\
             \"plugin_stderr_reader_stopped\":true}"
        );
    }

    /// PLUG-7・REPAIR-5: 強制終了を試みた後に回収した終了状態を、子自身の終了と取り違えない。
    #[cfg(unix)]
    #[test]
    fn plug7_classify_reaped_keeps_own_exit_status() {
        use std::os::unix::process::ExitStatusExt;
        // wait status の生値: 終了コードは上位 8 bit、シグナル番号は下位 7 bit。
        assert_eq!(
            classify_reaped(ExitStatus::from_raw(0)),
            OneShotTermination::Exited { code: Some(0) }
        );
        assert_eq!(
            classify_reaped(ExitStatus::from_raw(3 << 8)),
            OneShotTermination::Exited { code: Some(3) }
        );
        assert_eq!(
            classify_reaped(ExitStatus::from_raw(9)),
            OneShotTermination::Killed
        );
        // SIGKILL 以外のシグナル（SIGSEGV = 11）は強制終了扱いにせず、異常終了として返す。
        assert_eq!(
            classify_reaped(ExitStatus::from_raw(11)),
            OneShotTermination::Exited { code: None }
        );
    }

    /// テスト用の局所の登録表（グローバル表を汚さない）。
    #[cfg(unix)]
    fn local_registry(n: usize) -> &'static Registry {
        use std::sync::atomic::AtomicI32;
        let slots: &'static [AtomicI32] = Box::leak(
            (0..n)
                .map(|_| AtomicI32::new(0))
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        );
        Box::leak(Box::new(Registry::over(slots)))
    }

    #[cfg(unix)]
    fn sh(script: &str) -> Command {
        let mut c = Command::new("/bin/sh");
        c.args(["-c", script])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        c
    }

    /// PLUG-7・#1513 (A3): 表が満杯なら子を起動せず `RESOURCE_EXHAUSTED` で拒否する。
    #[cfg(unix)]
    #[test]
    fn plug7_spawn_registered_rejects_when_table_full_without_spawning() {
        let reg = local_registry(1);
        let _held = reg.reserve().unwrap();
        let marker = std::env::temp_dir().join(format!("fcos-spawn-marker-{}", std::process::id()));
        let _ = std::fs::remove_file(&marker);
        let script = format!("touch '{}'", marker.display());
        let e = spawn_registered(&mut sh(&script), reg).err().unwrap();
        assert_eq!(e.code(), PluginErrorCode::ResourceExhausted);
        assert_eq!(e.code().as_str(), "RESOURCE_EXHAUSTED");
        std::thread::sleep(Duration::from_millis(100));
        assert!(!marker.exists(), "child must not be spawned");
    }

    /// PLUG-7・#1513 (A2): 登録は spawn 成功で載り、kill・回収・自発終了の回収・未回収報告のいずれでも外れる。
    #[cfg(unix)]
    #[test]
    fn plug7_registration_is_released_on_every_reap_path() {
        use crate::signal_forward::ForwardSignal;
        let reg = local_registry(4);
        let targets = |r: &Registry| r.forward(ForwardSignal::Hangup).targets;
        // 登録の有無（targets）だけを見る。確認用の転送（SIGHUP）で死なないよう HUP を無視する子を使う。
        // trap 設定前の HUP で sh が死ぬ競合（macOS ではゾンビのみのグループへの killpg が EPERM になる）を
        // 避けるため、trap 後にマーカーを作らせ、確認してから転送する。
        let marker_dir = std::env::temp_dir();
        let make_ignoring = |tag: &str| {
            let marker = marker_dir.join(format!("fcos-trap-{}-{tag}", std::process::id()));
            let _ = std::fs::remove_file(&marker);
            let script = format!("trap '' HUP; touch '{}'; exec sleep 30", marker.display());
            (script, marker)
        };
        let wait_marker = |m: &std::path::Path| {
            let start = Instant::now();
            while !m.exists() {
                assert!(start.elapsed() < Duration::from_secs(10), "trap marker");
                std::thread::sleep(Duration::from_millis(2));
            }
            let _ = std::fs::remove_file(m);
        };
        // kill_and_reap
        let (script, marker) = make_ignoring("a");
        let mut g = spawn_registered(&mut sh(&script), reg).unwrap();
        wait_marker(&marker);
        assert_eq!(targets(reg), 1);
        assert!(g.kill_and_reap().is_reaped());
        assert_eq!(targets(reg), 0);
        // 自発終了を try_wait で回収
        let mut g = spawn_registered(&mut sh("exit 0"), reg).unwrap();
        let start = Instant::now();
        while g.try_wait().unwrap().is_none() {
            assert!(start.elapsed() < Duration::from_secs(5));
            std::thread::sleep(Duration::from_millis(2));
        }
        assert_eq!(targets(reg), 0);
        // 生存中の try_wait は登録を保つ
        let (script, marker) = make_ignoring("b");
        let mut live = spawn_registered(&mut sh(&script), reg).unwrap();
        wait_marker(&marker);
        assert!(live.try_wait().unwrap().is_none());
        assert_eq!(targets(reg), 1);
        // 未回収の報告でスロットを解放する
        let _ = unreaped_error(&mut live, "test");
        assert_eq!(targets(reg), 0);
        // 後始末（報告済みの子は Drop で回収されない）
        live.reported_unreaped = false;
        assert!(live.kill_and_reap().is_reaped());
    }

    /// PLUG-7・#1513 (A2): 登録していない生存中の子には転送しない。
    #[cfg(unix)]
    #[test]
    fn plug7_forward_does_not_touch_unregistered_children() {
        use crate::signal_forward::ForwardSignal;
        let reg = local_registry(2);
        let mut other = ChildGuard::new(sh("exec sleep 30").spawn().unwrap());
        assert_eq!(reg.forward(ForwardSignal::Terminate).targets, 0);
        std::thread::sleep(Duration::from_millis(50));
        assert!(other.try_wait().unwrap().is_none());
        assert!(other.kill_and_reap().is_reaped());
    }

    /// PLUG-7・#1513: 登録中の子へ転送するとシグナルで終了する。
    #[cfg(unix)]
    #[test]
    fn plug7_forward_terminates_registered_child() {
        use crate::signal_forward::ForwardSignal;
        use std::os::unix::process::ExitStatusExt;
        let reg = local_registry(2);
        let mut g = spawn_registered(&mut sh("exec sleep 30"), reg).unwrap();
        assert_eq!(reg.forward(ForwardSignal::Terminate).targets, 1);
        let start = Instant::now();
        let status = loop {
            if let Some(st) = g.try_wait().unwrap() {
                break st;
            }
            assert!(start.elapsed() < Duration::from_secs(5));
            std::thread::sleep(Duration::from_millis(2));
        };
        assert_eq!(status.signal(), Some(15));
        assert_eq!(reg.forward(ForwardSignal::Terminate).targets, 0);
    }

    /// #1311・#1513・PLUG-7: 登録中の plugin へ転送した SIGTERM・SIGHUP は、`spawn_registered` が作る
    /// プロセスグループ宛て（`kill(-pid)`）で孫にも届き、plugin 本体と孫の両方が止まる。
    /// SIGINT は非対話 sh が非同期起動の孫で無視するため、孫の停止は SIGTERM・SIGHUP で確かめる。
    #[cfg(unix)]
    #[test]
    fn plug7_forward_stops_plugin_and_grandchild_via_group() {
        use crate::signal_forward::ForwardSignal;
        for sig in [ForwardSignal::Terminate, ForwardSignal::Hangup] {
            let reg = local_registry(2);
            let mut cmd = sh("/bin/sleep 30 >/dev/null 2>&1 & echo $!; wait");
            cmd.stdout(Stdio::piped());
            let mut g = spawn_registered(&mut cmd, reg).unwrap();
            let out = g.child.as_mut().unwrap().stdout.take().unwrap();
            let gc: u32 = read_grandchild_pid(&mut g, out);
            assert!(is_running(gc));
            assert_eq!(reg.forward(sig).targets, 1);
            let start = Instant::now();
            while g.try_wait().unwrap().is_none() {
                assert!(
                    start.elapsed() < Duration::from_secs(5),
                    "{sig:?}: leader alive"
                );
                std::thread::sleep(Duration::from_millis(5));
            }
            while is_running(gc) {
                assert!(
                    start.elapsed() < Duration::from_secs(5),
                    "{sig:?}: grandchild {gc} alive"
                );
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    }

    /// PLUG-7: kill の前に自発終了していた子は、その終了状態のまま回収される（`Killed` にしない）。
    #[cfg(unix)]
    #[test]
    fn plug7_kill_and_reap_returns_status_of_already_exited_child() {
        let mut child = Command::new("/bin/sh")
            .args(["-c", "exit 3"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        // stdout の EOF は子の終了処理の開始後にしか来ない。回収（wait）はせずに終了だけを待つ。
        let mut out = child.stdout.take().unwrap();
        let mut sink = Vec::new();
        io::Read::read_to_end(&mut out, &mut sink).unwrap();
        assert_eq!(sink, b"");
        let mut guard = ChildGuard::new(child);
        let Reap::Reaped(status) = guard.kill_and_reap() else {
            panic!("child was not reaped");
        };
        assert_eq!(status.code(), Some(3));
        assert_eq!(
            classify_reaped(status),
            OneShotTermination::Exited { code: Some(3) }
        );
        assert_eq!(guard.kill_and_reap(), Reap::AlreadyReaped);
    }

    /// 子の標準出力 1 行目の孫 pid を有限の期限内に読む（REPAIR-5・#1311）。期限内に改行も EOF も来なければ
    /// 起動したグループへ SIGKILL を送り、直接の子を回収してから panic する（`read_line` の無期限ブロック防止）。
    #[cfg(unix)]
    fn read_grandchild_pid(guard: &mut ChildGuard, out: std::process::ChildStdout) -> u32 {
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let mut line = String::new();
            let r = io::BufRead::read_line(&mut io::BufReader::new(out), &mut line).map(|_| line);
            let _ = tx.send(r);
        });
        match rx.recv_timeout(Duration::from_secs(10)) {
            Ok(Ok(line)) => line.trim().parse().expect("grandchild pid line"),
            Ok(Err(e)) => {
                let _ = guard.kill_and_reap();
                panic!("failed to read grandchild pid: {e}");
            }
            Err(_) => {
                let reap = guard.kill_and_reap();
                panic!("timed out reading grandchild pid (reap: {reap:?})");
            }
        }
    }

    /// 新しいプロセスグループで `script` を起動し、標準出力 1 行目の孫 pid を返す（#1311 のテスト用）。
    #[cfg(unix)]
    fn spawn_group_with_grandchild(script: &str) -> (ChildGuard, u32) {
        use std::os::unix::process::CommandExt;
        let child = Command::new("/bin/sh")
            .args(["-c", script])
            .process_group(0)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut guard = ChildGuard::new(child);
        let out = guard.child.as_mut().unwrap().stdout.take().unwrap();
        let pid = read_grandchild_pid(&mut guard, out);
        (guard, pid)
    }

    /// 孫が実行中か（Linux ではゾンビ `Z` を実行中に数えない）。
    #[cfg(unix)]
    fn is_running(pid: u32) -> bool {
        let alive = Command::new("/bin/kill")
            .args(["-0", &pid.to_string()])
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success();
        #[cfg(target_os = "linux")]
        let alive = alive
            && std::fs::read_to_string(format!("/proc/{pid}/stat"))
                .map(|st| {
                    !st.rsplit(')')
                        .next()
                        .unwrap_or("")
                        .trim_start()
                        .starts_with('Z')
                })
                .unwrap_or(false);
        alive
    }

    #[cfg(unix)]
    fn force_kill(pid: u32) {
        let _ = Command::new("/bin/kill")
            .args(["-9", &pid.to_string()])
            .status();
    }

    #[cfg(unix)]
    const GRANDCHILD_SCRIPT_EXIT: &str = "/bin/sleep 30 >/dev/null 2>&1 & echo $!; exit 0";
    #[cfg(unix)]
    const GRANDCHILD_SCRIPT_WAIT: &str = "/bin/sleep 30 >/dev/null 2>&1 & echo $!; wait";

    /// #1311・PLUG-7: 子が生存中の `kill_and_reap` はグループ内の孫も止める。
    #[cfg(unix)]
    #[test]
    fn plug7_kill_and_reap_kills_grandchild_in_process_group() {
        let (mut guard, gc) = spawn_group_with_grandchild(GRANDCHILD_SCRIPT_WAIT);
        assert!(is_running(gc));
        assert!(matches!(guard.kill_and_reap(), Reap::Reaped(_)));
        let start = Instant::now();
        while is_running(gc) {
            assert!(
                start.elapsed() < Duration::from_secs(5),
                "grandchild {gc} alive"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// #1311・PLUG-7: `try_wait` で回収済み（`child` は `Some` のまま）なら、グループへ送らない
    /// （pid 再利用による誤送信の防止）。
    #[cfg(unix)]
    #[test]
    fn plug7_kill_and_reap_skips_group_after_try_wait_reaped_leader() {
        let (mut guard, gc) = spawn_group_with_grandchild(GRANDCHILD_SCRIPT_EXIT);
        let start = Instant::now();
        while guard.try_wait().unwrap().is_none() {
            assert!(
                start.elapsed() < Duration::from_secs(5),
                "leader did not exit"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(guard.child.is_some());
        let _ = guard.kill_and_reap();
        let still_running = is_running(gc);
        force_kill(gc);
        assert!(
            still_running,
            "group was signalled after the leader was reaped"
        );
    }

    /// #1311・PLUG-7・REPAIR-5: グループ送信失敗は後始末の成功に数えない（`is_reaped` は偽）。
    #[test]
    fn plug7_group_kill_failed_is_not_a_successful_reap() {
        assert!(!Reap::GroupKillFailed.is_reaped());
        assert!(!Reap::Unreaped.is_reaped());
        assert!(Reap::AlreadyReaped.is_reaped());
    }

    /// #1311・PLUG-7・REPAIR-5: 終了猶予超過後のグループ停止失敗は、未回収の子（`Unreaped`）へ畳まずに
    /// 別の終了状況として保つ。
    #[test]
    fn plug7_termination_after_kill_keeps_group_kill_failure_distinct() {
        assert_eq!(
            termination_after_kill(Reap::GroupKillFailed),
            OneShotTermination::GroupKillFailed
        );
        assert_eq!(
            termination_after_kill(Reap::Unreaped),
            OneShotTermination::Unreaped
        );
        assert_eq!(
            termination_after_kill(Reap::AlreadyReaped),
            OneShotTermination::Unreaped
        );
    }

    /// #1311・PLUG-7・REPAIR-5: 応答後のグループ停止失敗は `group_kill_failed_error` で報告し、回収済みの
    /// 子を「回収できなかった」とは報告しない（pid を含めず、報告済みの印も付けない）。
    #[cfg(unix)]
    #[test]
    fn plug7_group_kill_failure_after_response_is_not_reported_as_unreaped() {
        let child = Command::new("/bin/sh")
            .args(["-c", "exit 0"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut guard = ChildGuard::new(child);
        // グループ停止失敗の時点で直接の子は回収済み（`child` は `None`）。その状態を再現する。
        assert_eq!(
            guard.wait_or_kill(Duration::from_secs(5)),
            OneShotTermination::Exited { code: Some(0) }
        );
        assert_eq!(guard.pid(), None);

        let e = check_termination_after_response(&mut guard, OneShotTermination::GroupKillFailed)
            .unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::Internal);
        assert_eq!(
            e.message(),
            "plugin process group could not be killed after the response; \
             the direct child was reaped but descendant processes may remain"
        );
        assert!(!guard.reported_unreaped);

        // 未回収の子は従来どおり別のメッセージで報告する（両者を取り違えない）。
        let e =
            check_termination_after_response(&mut guard, OneShotTermination::Unreaped).unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::Internal);
        assert_eq!(
            e.message(),
            "plugin process could not be reaped after the response"
        );
        assert_eq!(
            check_termination_after_response(&mut guard, OneShotTermination::Killed),
            Ok(())
        );
    }

    /// #1311・PLUG-7: 回収済みで `child` を手放した後は何も送らない（`AlreadyReaped`）。
    #[cfg(unix)]
    #[test]
    fn plug7_kill_and_reap_skips_group_after_release() {
        let (mut guard, gc) = spawn_group_with_grandchild(GRANDCHILD_SCRIPT_EXIT);
        assert_eq!(
            guard.wait_or_kill(Duration::from_secs(5)),
            OneShotTermination::Exited { code: Some(0) }
        );
        assert_eq!(guard.kill_and_reap(), Reap::AlreadyReaped);
        let still_running = is_running(gc);
        force_kill(gc);
        assert!(
            still_running,
            "group was signalled after the leader was reaped"
        );
    }

    /// PLUG-7: 終了猶予を使い切った後の回収でも、自発的な非ゼロ終了は `Exited` として返る。
    #[cfg(unix)]
    #[test]
    fn plug7_wait_or_kill_reports_killed_only_for_forced_kill() {
        let spawn = |script: &str| {
            Command::new("/bin/sh")
                .args(["-c", script])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap()
        };
        let mut lingering = ChildGuard::new(spawn("exec sleep 60"));
        assert_eq!(
            lingering.wait_or_kill(Duration::from_millis(50)),
            OneShotTermination::Killed
        );
        let mut failing = ChildGuard::new(spawn("exit 7"));
        assert_eq!(
            failing.wait_or_kill(Duration::from_secs(5)),
            OneShotTermination::Exited { code: Some(7) }
        );
    }

    /// REPAIR-5・PLUG-7: 回収できなかった子のエラーは `Internal` で、未回収の pid を特定できる。
    #[cfg(unix)]
    #[test]
    fn repair5_unreaped_error_names_the_child_pid() {
        let child = Command::new("/bin/sh")
            .args(["-c", "exec sleep 60"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let pid = child.id();
        let mut guard = ChildGuard::new(child);
        let e = unreaped_error(&mut guard, "the response");
        assert!(guard.reported_unreaped);
        assert_eq!(e.code(), PluginErrorCode::Internal);
        assert_eq!(
            e.message(),
            format!("plugin process (pid {pid}) could not be reaped after the response")
        );
        // 回収済み（ハンドルなし）の場合は pid を含めない。
        assert!(guard.kill_and_reap().is_reaped());
        let e = unreaped_error(&mut guard, "a failed exchange");
        assert_eq!(
            e.message(),
            "plugin process could not be reaped after a failed exchange"
        );
    }

    /// 上限を超える stderr は先頭 `ONE_SHOT_STDERR_MAX_BYTES` だけ保持し、総量を数える（REPAIR-5）。
    #[test]
    fn plug7_stderr_capture_keeps_only_the_cap() {
        let mut data = vec![b'a'; ONE_SHOT_STDERR_MAX_BYTES];
        data.extend_from_slice(&[b'b'; 34_464]);
        let capture = StderrCapture::start(io::Cursor::new(data), Box::new(|| {})).unwrap();
        let got = capture.finish(Duration::from_secs(5));
        assert_eq!(got.bytes().len(), 65_536);
        assert_eq!(got.bytes().iter().filter(|b| **b == b'a').count(), 65_536);
        assert_eq!(got.total_bytes(), 100_000);
        assert!(got.is_truncated());
        assert!(got.is_complete());
    }

    /// 上限以内の stderr はそのまま保持する。
    #[test]
    fn plug7_stderr_capture_keeps_small_output_verbatim() {
        let capture =
            StderrCapture::start(io::Cursor::new(b"warn: x\n".to_vec()), Box::new(|| {})).unwrap();
        let got = capture.finish(Duration::from_secs(5));
        assert_eq!(got.bytes(), b"warn: x\n");
        assert_eq!(got.total_bytes(), 8);
        assert!(!got.is_truncated());
        assert!(got.is_complete());
        assert!(got.reader_stopped());
    }

    /// REPAIR-5: 書き込み端が閉じない（孫プロセスが保持する等）場合でも、収集待ちは期限で打ち切り、
    /// 読み取りスレッドは停止指示で止まる（スレッドを残さない）。
    #[test]
    fn repair5_stderr_capture_finish_stops_reader_when_source_never_closes() {
        /// 最初に 3 バイト返し、その後は終端に達しないまま読み取り期限切れを返し続ける入力。
        struct Stalled(Option<&'static [u8]>);
        impl Read for Stalled {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                if let Some(first) = self.0.take() {
                    let n = first.len().min(buf.len());
                    buf[..n].copy_from_slice(&first[..n]);
                    return Ok(n);
                }
                std::thread::sleep(Duration::from_millis(10));
                Err(io::ErrorKind::WouldBlock.into())
            }
        }
        let woken = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&woken);
        let capture = StderrCapture::start(
            Stalled(Some(b"abc")),
            Box::new(move || flag.store(true, Ordering::SeqCst)),
        )
        .unwrap();
        // 先頭の 3 バイトが保持されるまで待つ（最大 5 秒）。
        let waited = Instant::now();
        while lock_stderr(&capture.state).total_bytes < 3 {
            assert!(waited.elapsed() < Duration::from_secs(5));
            std::thread::sleep(Duration::from_millis(1));
        }
        let started = Instant::now();
        let got = capture.finish(Duration::from_millis(100));
        let elapsed = started.elapsed();
        assert!(elapsed >= Duration::from_millis(100), "{elapsed:?}");
        assert!(elapsed < Duration::from_secs(5), "{elapsed:?}");
        assert_eq!(got.bytes(), b"abc");
        assert_eq!(got.total_bytes(), 3);
        assert!(!got.is_complete());
        assert!(got.reader_stopped());
        assert!(woken.load(Ordering::SeqCst));
    }

    /// REPAIR-5・PLUG-7: 子の終了後も別プロセスが stderr の書き込み端を保持している場合、収集は
    /// 期限で打ち切り、ソケットの shutdown で読み取りスレッドを停止させる。
    #[cfg(unix)]
    #[test]
    fn repair5_stderr_capture_stops_reader_while_another_process_holds_the_writer() {
        let (child_stderr, reader) = stderr_channel().unwrap();
        // 書き込み端を保持したまま何も書かないプロセス（孫プロセスの代役）。
        let holder = Command::new("/bin/sh")
            .args(["-c", "echo held >&2; exec sleep 30"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(child_stderr)
            .spawn()
            .unwrap();
        let mut holder = ChildGuard::new(holder);
        let capture = StderrCapture::attach(reader).unwrap();
        let waited = Instant::now();
        while lock_stderr(&capture.state).total_bytes < 5 {
            assert!(waited.elapsed() < Duration::from_secs(5));
            std::thread::sleep(Duration::from_millis(1));
        }
        let started = Instant::now();
        let got = capture.finish(Duration::from_millis(100));
        let elapsed = started.elapsed();
        assert!(elapsed < Duration::from_secs(5), "{elapsed:?}");
        assert_eq!(got.bytes(), b"held\n");
        assert_eq!(got.total_bytes(), 5);
        assert!(!got.is_complete());
        assert!(got.reader_stopped());
        assert!(holder.kill_and_reap().is_reaped());
    }

    /// PLUG-7: 未回収として pid を報告した子は、ガードの破棄時に回収しない（報告した pid を
    /// 解放済みにしない）。報告していない子は破棄時に kill・回収する。
    #[cfg(unix)]
    #[test]
    fn plug7_reported_unreaped_child_is_not_reaped_on_drop() {
        let spawn = |script: &str| {
            Command::new("/bin/sh")
                .args(["-c", script])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap()
        };
        let exists = |pid: u32| std::path::Path::new(&format!("/proc/{pid}")).exists();

        // すぐ自発終了する子。回収しなければゾンビとして pid が残る。
        let mut reported = ChildGuard::new(spawn("exit 0"));
        let reported_pid = reported.pid().unwrap();
        let e = unreaped_error(&mut reported, "the response");
        assert_eq!(
            e.message(),
            format!("plugin process (pid {reported_pid}) could not be reaped after the response")
        );
        drop(reported);

        let unreported = ChildGuard::new(spawn("exec sleep 30"));
        let unreported_pid = unreported.pid().unwrap();
        drop(unreported);

        // `/proc` で確認できるのは Linux のみ。他の unix では破棄が戻ることだけを確認する。
        if cfg!(target_os = "linux") {
            assert!(exists(reported_pid), "pid {reported_pid}");
            assert!(!exists(unreported_pid), "pid {unreported_pid}");
        }
    }

    #[test]
    fn plug7_plugin_rejects_relative_program() {
        let e = OneShotPlugin::new("plugin".into(), vec![], "/tmp".into()).unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::InvalidArgument);
        assert_eq!(e.message(), "plugin program path must be absolute");
    }

    #[test]
    fn plug7_plugin_rejects_too_many_or_too_long_args() {
        let abs = if cfg!(windows) { "C:\\p" } else { "/bin/p" };
        let many = vec![OsString::from("a"); ONE_SHOT_ARGS_MAX_COUNT + 1];
        let e = OneShotPlugin::new(abs.into(), many, "/tmp".into()).unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::InvalidArgument);
        let long = vec![OsString::from("a".repeat(ONE_SHOT_ARGS_MAX_BYTES + 1))];
        let e = OneShotPlugin::new(abs.into(), long, "/tmp".into()).unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::InvalidArgument);
        let ok = vec![OsString::from("a"); ONE_SHOT_ARGS_MAX_COUNT];
        assert!(OneShotPlugin::new(abs.into(), ok, "/tmp".into()).is_ok());
    }

    /// 応答者を pid で限定する: 同一 UID でも pid が異なる接続は受理しない（PLUG-7）。
    #[cfg(unix)]
    #[test]
    fn plug7_accept_rejects_other_pid_and_accepts_expected() {
        use crate::transport::UdsStream;
        use std::os::unix::fs::DirBuilderExt;
        let dir = std::env::temp_dir().join(format!("fcos-unit-{}", std::process::id()));
        std::fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
        let listener = UdsListener::bind(&dir.join("a.sock")).unwrap();
        let path = listener.path().to_path_buf();
        let me = std::process::id();
        let _c = UdsStream::connect(
            &path,
            Duration::from_secs(2),
            &mut crate::audit::NoopPeerAuthObserver,
        )
        .unwrap();
        let e = listener
            .accept_peer_pid(
                Duration::from_millis(300),
                me.wrapping_add(1),
                &mut || None,
                &mut crate::audit::NoopPeerAuthObserver,
            )
            .unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::Timeout);
        let _c2 = UdsStream::connect(
            &path,
            Duration::from_secs(2),
            &mut crate::audit::NoopPeerAuthObserver,
        )
        .unwrap();
        assert!(
            listener
                .accept_peer_pid(
                    Duration::from_secs(2),
                    me,
                    &mut || None,
                    &mut crate::audit::NoopPeerAuthObserver,
                )
                .is_ok()
        );
        drop(listener);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// pid 不一致の接続が続いても abort を確認し、子の早期終了を期限前に返す（PLUG-7・REPAIR-5）。
    #[cfg(unix)]
    #[test]
    fn plug7_abort_is_checked_after_pid_mismatch() {
        use crate::transport::UdsStream;
        use std::os::unix::fs::DirBuilderExt;
        let dir = std::env::temp_dir().join(format!("fcos-abort-{}", std::process::id()));
        std::fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
        let listener = UdsListener::bind(&dir.join("a.sock")).unwrap();
        let path = listener.path().to_path_buf();
        let me = std::process::id();
        let _c = UdsStream::connect(
            &path,
            Duration::from_secs(2),
            &mut crate::audit::NoopPeerAuthObserver,
        )
        .unwrap();
        let mut calls = 0u32;
        let started = std::time::Instant::now();
        let e = listener
            .accept_peer_pid(
                Duration::from_secs(10),
                me.wrapping_add(1),
                &mut || {
                    calls += 1;
                    Some(PluginError::new(
                        PluginErrorCode::Unavailable,
                        "child exited early",
                    ))
                },
                &mut crate::audit::NoopPeerAuthObserver,
            )
            .unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::Unavailable);
        assert_eq!(calls, 1);
        assert!(started.elapsed() < Duration::from_secs(5));
        drop(listener);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
