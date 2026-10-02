//! plugin プロセスの都度起動モード（PLUG-7・TASK-110.1・#258）。
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
//! - 子の環境変数は `env_clear()` 後に [`PLUGIN_SOCKET_ENV`] のみ設定する（資格情報を継承させない）。
//!   stdin / stdout は null。stderr は親へ継承させず、専用の pipe で受けて [`OneShotStderr`] として
//!   返す（untrusted。保持は [`ONE_SHOT_STDERR_MAX_BYTES`] まで。超過分は読み捨てて件数だけ数える）。
//!   親の stderr・構造化ログへ内容を転記しない（量の上限なしの出力・ログ行の偽装を防ぐ）。
//!
//! # 未実装（REPAIR-3）
//!
//! - 常駐モード（TASK-110.2）・モード選択 API（TASK-110.3）。
//! - 起動対象の信頼性検証（所有者・モード・sha256 照合。TASK-122・PLUG-11）。本 API は検証を
//!   行わず、呼び出し側が検証済みの絶対パスを渡すことを前提とする。
//! - 孫プロセスの回収（プロセスグループ単位の kill は未対応）。孫が stderr の pipe を保持し続けた
//!   場合、収集は [`ONE_SHOT_STDERR_DRAIN_TIMEOUT`] で打ち切り、[`OneShotStderr::is_complete`] が
//!   false になる（読み取りスレッドは pipe が閉じるまで読み捨てを続ける）。
//! - 要求 ID と応答 ID の対応づけ（TASK-114）。

use crate::error::{PluginError, PluginErrorCode};
use crate::frame::Frame;
use crate::transport::{RpcTimeout, UdsListener};
use std::ffi::OsString;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
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

/// 子の回収後に stderr の読み取り完了（EOF）を待つ上限（REPAIR-5。合計期限とは別枠）。
/// 子が終了していれば pipe は閉じており即座に完了する。孫プロセスが pipe を保持している場合のみ
/// この期限まで待ち、打ち切る。
pub const ONE_SHOT_STDERR_DRAIN_TIMEOUT: Duration = Duration::from_millis(500);

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
    /// 強制終了を試みたが、[`ONE_SHOT_REAP_TIMEOUT`] 内に回収を確認できなかった（kill 失敗を含む）。
    /// 呼び出し側は孤児の可能性として扱う（REPAIR-5・PLUG-7）。
    Unreaped,
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
}

impl OneShotStderr {
    /// 何も収集していない完了済みの結果（子を spawn しなかった経路用）。
    fn empty() -> Self {
        Self {
            bytes: Vec::new(),
            total_bytes: 0,
            complete: true,
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

    /// pipe の終端（EOF）まで読み切ったか。false は [`ONE_SHOT_STDERR_DRAIN_TIMEOUT`] で打ち切った
    /// ことを表す（孫プロセスが pipe を保持している等）。
    pub fn is_complete(&self) -> bool {
        self.complete
    }
}

/// 子の stderr を専用スレッドで読み、上限つきで保持する収集器（REPAIR-5）。
///
/// 読み取りは子の spawn 直後から別スレッドで行う。親（呼び出しスレッド）は接続待ち・往復・回収の
/// 間に pipe を読まないため、子が pipe バッファを超えて書いても子は詰まらず、親も読み取りで
/// ブロックしない。結果の受け取り（[`Self::finish`]）は期限つきで、スレッドの `join` は行わない。
/// 常駐モード（TASK-110.2）でも同じ収集器を使える形にしている。
struct StderrCapture {
    state: Arc<Mutex<OneShotStderr>>,
    done: mpsc::Receiver<()>,
}

impl StderrCapture {
    /// `source` を EOF まで読むスレッドを起動する。起動できなければ `Err`（呼び出し側が子を回収する）。
    fn start<R: Read + Send + 'static>(source: R) -> io::Result<Self> {
        let state = Arc::new(Mutex::new(OneShotStderr {
            bytes: Vec::new(),
            total_bytes: 0,
            complete: false,
        }));
        let (tx, done) = mpsc::channel();
        let shared = Arc::clone(&state);
        std::thread::Builder::new()
            .name("plugin-stderr".to_string())
            .spawn(move || {
                drain_stderr(source, &shared);
                // 受け手が期限切れで去っていても構わない。
                let _ = tx.send(());
            })?;
        Ok(Self { state, done })
    }

    /// 読み取り完了を `limit` まで待ち、その時点までの収集結果を返す。期限内に EOF へ達しなければ
    /// `is_complete() == false` の途中結果を返す（スレッドは pipe が閉じるまで読み捨てを続け、
    /// 保持量は上限のまま増えない）。
    fn finish(self, limit: Duration) -> OneShotStderr {
        // タイムアウト・送信側の消滅（スレッドの異常終了）はどちらも途中結果として扱う。
        let _ = self.done.recv_timeout(limit);
        lock_stderr(&self.state).clone()
    }
}

/// 読み取りスレッドが panic しても収集結果を取り出せるよう、poison を無視して lock する。
fn lock_stderr(state: &Mutex<OneShotStderr>) -> MutexGuard<'_, OneShotStderr> {
    state.lock().unwrap_or_else(PoisonError::into_inner)
}

/// `source` を EOF またはエラーまで読み、先頭 [`ONE_SHOT_STDERR_MAX_BYTES`] バイトだけ保持する。
/// 上限到達後も読み捨てを続ける（読むのを止めると子が書き込みで詰まり、応答・終了が遅れるため）。
fn drain_stderr<R: Read>(mut source: R, state: &Mutex<OneShotStderr>) {
    let mut chunk = [0u8; 4096];
    loop {
        match source.read(&mut chunk) {
            Ok(0) => break,
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
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            // 読み取りエラーは EOF として扱わない（complete を立てない）。
            Err(_) => return,
        }
    }
    lock_stderr(state).complete = true;
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
/// 呼び出しが担う。未回収として報告した後（[`unreaped_error`]）は `Drop` で回収しない。報告後に回収
/// すると、呼び出し側へ伝えた pid が解放済みになり、別プロセスを指し得るため（kill は報告前に送信
/// 済みで、`Drop` での再試行は待ち時間を延ばすだけになる）。
struct ChildGuard {
    child: Option<Child>,
    /// 未回収として pid を報告済みか。true なら `Drop` で回収しない。
    reported_unreaped: bool,
}

impl ChildGuard {
    fn new(child: Child) -> Self {
        Self {
            child: Some(child),
            reported_unreaped: false,
        }
    }

    fn pid(&self) -> Option<u32> {
        self.child.as_ref().map(Child::id)
    }

    /// 子の stderr（pipe の読み取り側）を取り出す。2 回目以降・回収済みは `None`。
    fn take_stderr(&mut self) -> Option<std::process::ChildStderr> {
        self.child.as_mut().and_then(|c| c.stderr.take())
    }

    fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        match self.child.as_mut() {
            Some(c) => c.try_wait(),
            None => Ok(None),
        }
    }

    /// kill して回収を `ONE_SHOT_REAP_TIMEOUT` まで待つ。
    ///
    /// kill の失敗は無視せず、回収確認ができなければ `Unreaped` を返す（呼び出し側が報告する）。
    /// 回収できなかった場合は `Child` を保持し続ける（呼び出し側が pid を報告できるよう手放さない）。
    /// 回収できた場合は終了状態を捨てずに返す。kill の直前・直後に子が自発終了していた場合、
    /// 回収される状態は「こちらの kill」ではなく子自身の終了状態になるため、呼び出し側が
    /// [`classify_reaped`] で区別する（異常終了を強制終了と取り違えて成功扱いしない。PLUG-7）。
    fn kill_and_reap(&mut self) -> Reap {
        let Some(c) = self.child.as_mut() else {
            return Reap::AlreadyReaped;
        };
        // kill の前に終了済みかを確認し、自発終了の状態をそのまま拾う（kill との競合窓を狭める）。
        if let Ok(Some(status)) = c.try_wait() {
            self.child = None;
            return Reap::Reaped(status);
        }
        let _ = c.kill();
        let start = Instant::now();
        let mut interval = Duration::from_millis(1);
        loop {
            match c.try_wait() {
                Ok(Some(status)) => {
                    self.child = None;
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
                    self.child = None;
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
        match self.kill_and_reap() {
            Reap::Reaped(status) => classify_reaped(status),
            // 既に回収済みのガードに対して呼ばれることはないが、終了状態が不明なため成功扱いしない。
            Reap::AlreadyReaped | Reap::Unreaped => OneShotTermination::Unreaped,
        }
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if !self.reported_unreaped {
            let _ = self.kill_and_reap();
        }
    }
}

/// [`ChildGuard::kill_and_reap`] の結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reap {
    /// 今回の呼び出しで回収した。終了状態は子の自発終了・こちらの kill のどちらの場合もある。
    Reaped(ExitStatus),
    /// 既に回収済みで保持している子がない。
    AlreadyReaped,
    /// kill 失敗または期限超過で回収を確認できなかった（孤児の可能性）。
    Unreaped,
}

impl Reap {
    /// 子が残っていない（回収を確認できた）か。
    fn is_reaped(self) -> bool {
        !matches!(self, Self::Unreaped)
    }
}

/// `Child::kill` が unix で送るシグナル番号（`SIGKILL`。Linux・macOS とも 9）。
#[cfg(unix)]
const SIGKILL: i32 = 9;

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
        if status.signal() == Some(SIGKILL) {
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
/// 非 unix では listener の bind が `Unimplemented` を返し、子は spawn されない。
///
/// plugin の stderr は親へ継承させず [`OneShotOutcome::stderr`] で返す。本関数が親の stderr へ出す
/// 構造化ログには、plugin の stderr の内容は含めず件数のみ載せる。失敗時の内容が必要な呼び出し側は
/// [`call_once_observed`] の [`OneShotRecord::stderr`] を使う。
pub fn call_once(
    plugin: &OneShotPlugin,
    request: &Frame,
    timeout: OneShotTimeout,
) -> Result<OneShotOutcome, PluginError> {
    call_once_observed(plugin, request, timeout, &mut |record| {
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
    /// （`plugin_stderr_*`）で件数と打ち切りの有無だけを出す。
    pub fn to_json_line(&self) -> String {
        let code = match self.error_code {
            Some(c) => format!("\"{c}\""),
            None => "null".to_string(),
        };
        format!(
            "{{\"op\":\"{}\",\"success\":{},\"error_code\":{},\"elapsed_us\":{},\
             \"plugin_stderr_bytes\":{},\"plugin_stderr_truncated\":{},\
             \"plugin_stderr_complete\":{}}}",
            self.operation,
            self.success,
            code,
            self.elapsed.as_micros(),
            self.stderr.total_bytes(),
            self.stderr.is_truncated(),
            self.stderr.is_complete()
        )
    }
}

/// [`call_once`] と同じ処理を行い、終了時に 1 件の [`OneShotRecord`] を `observer` へ渡す（REPAIR-4）。
///
/// 成功・失敗のどの終了経路でも必ず 1 回だけ呼ばれる。`observer` は呼び出しスレッド上で同期的に
/// 実行されるため、長時間ブロックしないこと。
pub fn call_once_observed(
    plugin: &OneShotPlugin,
    request: &Frame,
    timeout: OneShotTimeout,
    observer: &mut dyn FnMut(&OneShotRecord),
) -> Result<OneShotOutcome, PluginError> {
    let start = Instant::now();
    let (result, stderr) = call_once_inner(plugin, request, timeout);
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

/// listener の bind・子の spawn・stderr の収集・往復・回収までを行う。戻り値の第 2 要素は、
/// 成功・失敗のどちらでも子の回収後に確定した stderr の収集結果（spawn 前の失敗は空）。
fn call_once_inner(
    plugin: &OneShotPlugin,
    request: &Frame,
    timeout: OneShotTimeout,
) -> (
    Result<(Frame, OneShotTermination), PluginError>,
    OneShotStderr,
) {
    static SEQ: AtomicU64 = AtomicU64::new(0);

    let Some(deadline) = Instant::now().checked_add(timeout.as_duration()) else {
        return (Err(timeout_error()), OneShotStderr::empty());
    };

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
    // `Command` は文の終わりで drop され、親側に pipe の書き込み端は残らない（EOF を妨げない）。
    let spawned = Command::new(&plugin.program)
        .args(&plugin.args)
        .env_clear()
        .env(PLUGIN_SOCKET_ENV, listener.path())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn();
    let mut guard = match spawned {
        Ok(child) => ChildGuard::new(child),
        Err(e) => return (Err(spawn_error(&e)), OneShotStderr::empty()),
    };

    // 接続待ちより前に読み取りを始める（子が接続前に大量に書いても詰まらせない）。
    let capture = guard.take_stderr().map(StderrCapture::start);
    let result = match &capture {
        Some(Ok(_)) => exchange_and_reap(&mut guard, listener, request, deadline),
        // 読み取り手がいないまま子を走らせると pipe が埋まって子が詰まるため、往復せず回収する。
        Some(Err(_)) | None => {
            drop(listener);
            Err(reap_after_failure(
                &mut guard,
                PluginError::new(
                    PluginErrorCode::Internal,
                    "failed to start capturing plugin stderr",
                ),
            ))
        }
    };
    // 子の回収後に収集結果を受け取る。子が終了していれば pipe は閉じており即座に完了する。
    let stderr = match capture {
        Some(Ok(c)) => c.finish(ONE_SHOT_STDERR_DRAIN_TIMEOUT),
        Some(Err(_)) | None => OneShotStderr::empty(),
    };
    (result, stderr)
}

/// 応答前の失敗経路で子を明示的に kill・回収する。回収を確認できなければ、元のエラーではなく
/// 回収失敗（`Internal`）を返す（孤児の可能性を呼び出し側へ伝える。REPAIR-5・PLUG-7）。
fn reap_after_failure(guard: &mut ChildGuard, error: PluginError) -> PluginError {
    if guard.kill_and_reap().is_reaped() {
        error
    } else {
        unreaped_error(guard, "a failed exchange")
    }
}

/// 回収を確認できなかった子についてのエラー（`Internal`）。呼び出し側が未回収の子を特定できるよう
/// pid を含める（pid は自プロセスが起動した子のもので、外部入力ではない）。
///
/// 報告した pid を以後も有効に保つため、`guard` に報告済みの印を付けて `Drop` での回収を止める。
fn unreaped_error(guard: &mut ChildGuard, phase: &str) -> PluginError {
    let message = match guard.pid() {
        Some(pid) => {
            guard.reported_unreaped = true;
            format!("plugin process (pid {pid}) could not be reaped after {phase}")
        }
        None => format!("plugin process could not be reaped after {phase}"),
    };
    PluginError::new(PluginErrorCode::Internal, message)
}

/// 接続の受付・1 往復・子の回収を行う。`Ok` で戻る時点で子は回収済み。回収を確認できなかった場合は
/// `Internal`（[`unreaped_error`]）を返し、以後 `guard` はその子を回収しない。
fn exchange_and_reap(
    guard: &mut ChildGuard,
    listener: UdsListener,
    request: &Frame,
    deadline: Instant,
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
            listener.accept_peer_pid(left, child_pid, &mut check_child)?
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
    // 回収を確認できない子（孤児の可能性）と異常終了（非ゼロ・シグナル）は成功扱いにしない（REPAIR-5・PLUG-7）。
    match termination {
        OneShotTermination::Unreaped => Err(unreaped_error(guard, "the response")),
        OneShotTermination::Exited { code: Some(0) } | OneShotTermination::Killed => {
            Ok((response, termination))
        }
        OneShotTermination::Exited { .. } => Err(PluginError::new(
            PluginErrorCode::Unavailable,
            "plugin process exited abnormally after the response",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let r = call_once_observed(&plugin, &req, OneShotTimeout::default(), &mut |rec| {
            records.push(rec.clone())
        });
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
            },
        };
        // plugin の stderr の内容は行へ埋め込まず、出所を明示したキーで件数だけを出す。
        assert_eq!(
            rec.to_json_line(),
            "{\"op\":\"plugin.call_once\",\"success\":false,\"error_code\":\"TIMEOUT\",\
             \"elapsed_us\":1500,\"plugin_stderr_bytes\":70000,\
             \"plugin_stderr_truncated\":true,\"plugin_stderr_complete\":false}"
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
        let capture = StderrCapture::start(io::Cursor::new(data)).unwrap();
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
        let capture = StderrCapture::start(io::Cursor::new(b"warn: x\n".to_vec())).unwrap();
        let got = capture.finish(Duration::from_secs(5));
        assert_eq!(got.bytes(), b"warn: x\n");
        assert_eq!(got.total_bytes(), 8);
        assert!(!got.is_truncated());
        assert!(got.is_complete());
    }

    /// REPAIR-5: 書き込み端が閉じない（孫プロセスが保持する等）場合でも、収集待ちは期限で打ち切る。
    #[test]
    fn repair5_stderr_capture_finish_is_bounded_when_source_never_closes() {
        /// 最初に 3 バイト返し、その後は送信側が drop されるまで読み取りをブロックする入力。
        struct Stalled(Option<&'static [u8]>, mpsc::Receiver<()>);
        impl Read for Stalled {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                if let Some(first) = self.0.take() {
                    let n = first.len().min(buf.len());
                    buf[..n].copy_from_slice(&first[..n]);
                    return Ok(n);
                }
                let _ = self.1.recv();
                Ok(0)
            }
        }
        let (release, blocked) = mpsc::channel::<()>();
        let capture = StderrCapture::start(Stalled(Some(b"abc"), blocked)).unwrap();
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
        drop(release);
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
        let _c = UdsStream::connect(&path, Duration::from_secs(2)).unwrap();
        let e = listener
            .accept_peer_pid(Duration::from_millis(300), me.wrapping_add(1), &mut || None)
            .unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::Timeout);
        let _c2 = UdsStream::connect(&path, Duration::from_secs(2)).unwrap();
        assert!(
            listener
                .accept_peer_pid(Duration::from_secs(2), me, &mut || None)
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
        let _c = UdsStream::connect(&path, Duration::from_secs(2)).unwrap();
        let mut calls = 0u32;
        let started = std::time::Instant::now();
        let e = listener
            .accept_peer_pid(Duration::from_secs(10), me.wrapping_add(1), &mut || {
                calls += 1;
                Some(PluginError::new(
                    PluginErrorCode::Unavailable,
                    "child exited early",
                ))
            })
            .unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::Unavailable);
        assert_eq!(calls, 1);
        assert!(started.elapsed() < Duration::from_secs(5));
        drop(listener);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
