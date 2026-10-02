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
//! - [`call_once`] が戻った（`Ok` / `Err` いずれの）時点で、直接起動した子プロセスは kill または
//!   wait で回収済み。
//! - 子の環境変数は `env_clear()` 後に [`PLUGIN_SOCKET_ENV`] のみ設定する（資格情報を継承させない）。
//!   stdin / stdout は null、stderr は継承する。
//!
//! # 未実装（REPAIR-3）
//!
//! - 常駐モード（TASK-110.2）・モード選択 API（TASK-110.3）。
//! - 起動対象の信頼性検証（所有者・モード・sha256 照合。TASK-122・PLUG-11）。本 API は検証を
//!   行わず、呼び出し側が検証済みの絶対パスを渡すことを前提とする。
//! - 孫プロセスの回収（プロセスグループ単位の kill は未対応）。
//! - 要求 ID と応答 ID の対応づけ（TASK-114）。

use crate::error::{PluginError, PluginErrorCode};
use crate::frame::Frame;
use crate::transport::{RpcTimeout, UdsListener};
use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
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
    /// 猶予内に自発終了した。`code` はシグナル終了などで取得できない場合 `None`。
    Exited { code: Option<i32> },
    /// 猶予内に終了せず強制終了し、回収まで確認した。
    Killed,
    /// 強制終了を試みたが、[`ONE_SHOT_REAP_TIMEOUT`] 内に回収を確認できなかった（kill 失敗を含む）。
    /// 呼び出し側は孤児の可能性として扱う（REPAIR-5・PLUG-7）。
    Unreaped,
}

/// [`call_once`] の成功結果。
#[derive(Debug)]
#[non_exhaustive]
pub struct OneShotOutcome {
    response: Frame,
    termination: OneShotTermination,
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
}

/// 子プロセスを保持し、Drop で必ず kill・回収するガード（全エラー経路で孤児を残さない）。
struct ChildGuard(Option<Child>);

impl ChildGuard {
    fn pid(&self) -> Option<u32> {
        self.0.as_ref().map(Child::id)
    }

    fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        match self.0.as_mut() {
            Some(c) => c.try_wait(),
            None => Ok(None),
        }
    }

    /// kill して回収を `ONE_SHOT_REAP_TIMEOUT` まで待つ。回収を確認できたら true。
    /// kill の失敗は無視せず、回収確認ができなければ false を返す（呼び出し側が報告する）。
    /// 回収できなかった場合は `Child` を保持し続ける（再試行・`Drop` での最終試行のため手放さない）。
    fn kill_and_reap(&mut self) -> bool {
        let Some(c) = self.0.as_mut() else {
            return true;
        };
        let _ = c.kill();
        let start = Instant::now();
        let mut interval = Duration::from_millis(1);
        loop {
            match c.try_wait() {
                Ok(Some(_)) => {
                    self.0 = None;
                    return true;
                }
                Ok(None) => {}
                Err(_) => return false,
            }
            if start.elapsed() >= ONE_SHOT_REAP_TIMEOUT {
                return false;
            }
            std::thread::sleep(interval);
            interval = (interval * 2).min(POLL_MAX);
        }
    }

    /// 終了を `limit` まで待つ。終了していれば状態を返し、猶予超過なら強制終了して `Killed`。
    fn wait_or_kill(&mut self, limit: Duration) -> OneShotTermination {
        let start = Instant::now();
        let mut interval = Duration::from_millis(1);
        loop {
            match self.try_wait() {
                Ok(Some(status)) => {
                    self.0 = None;
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
        if self.kill_and_reap() {
            OneShotTermination::Killed
        } else {
            OneShotTermination::Unreaped
        }
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.kill_and_reap();
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
/// シグナルで終了した場合は `Unavailable`、回収を確認できない場合は `Internal` を返す。
/// 非 unix では listener の bind が `Unimplemented` を返し、子は spawn されない。
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
    /// 開始から戻るまでの所要時間（子の回収待ちを含む）。
    pub elapsed: Duration,
}

impl OneShotRecord {
    /// JSON Lines の 1 行（改行なし）へ符号化する。値はすべて固定文字列・数値のみで、外部入力を含まない。
    pub fn to_json_line(&self) -> String {
        let code = match self.error_code {
            Some(c) => format!("\"{c}\""),
            None => "null".to_string(),
        };
        format!(
            "{{\"op\":\"{}\",\"success\":{},\"error_code\":{},\"elapsed_us\":{}}}",
            self.operation,
            self.success,
            code,
            self.elapsed.as_micros()
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
    let result = call_once_inner(plugin, request, timeout);
    observer(&OneShotRecord {
        operation: "plugin.call_once",
        success: result.is_ok(),
        error_code: result.as_ref().err().map(|e| e.code().as_str()),
        elapsed: start.elapsed(),
    });
    result
}

fn call_once_inner(
    plugin: &OneShotPlugin,
    request: &Frame,
    timeout: OneShotTimeout,
) -> Result<OneShotOutcome, PluginError> {
    static SEQ: AtomicU64 = AtomicU64::new(0);

    let deadline = Instant::now()
        .checked_add(timeout.as_duration())
        .ok_or_else(timeout_error)?;

    let name = format!(
        "oneshot-{}-{}.sock",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    );
    let listener = UdsListener::bind(&plugin.socket_dir.join(name))?;

    let child = Command::new(&plugin.program)
        .args(&plugin.args)
        .env_clear()
        .env(PLUGIN_SOCKET_ENV, listener.path())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| spawn_error(&e))?;
    let mut guard = ChildGuard(Some(child));

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
        Err(e) => {
            if !guard.kill_and_reap() {
                return Err(PluginError::new(
                    PluginErrorCode::Internal,
                    "plugin process could not be reaped after a failed exchange",
                ));
            }
            return Err(e);
        }
    };
    let termination = guard.wait_or_kill(ONE_SHOT_EXIT_TIMEOUT);
    // 回収を確認できない子（孤児の可能性）と異常終了（非ゼロ・シグナル）は成功扱いにしない（REPAIR-5・PLUG-7）。
    match termination {
        OneShotTermination::Unreaped => {
            return Err(PluginError::new(
                PluginErrorCode::Internal,
                "plugin process could not be reaped after the response",
            ));
        }
        OneShotTermination::Exited { code: Some(0) } | OneShotTermination::Killed => {}
        OneShotTermination::Exited { .. } => {
            return Err(PluginError::new(
                PluginErrorCode::Unavailable,
                "plugin process exited abnormally after the response",
            ));
        }
    }
    Ok(OneShotOutcome {
        response,
        termination,
    })
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
    }

    #[test]
    fn repair4_record_json_line_is_stable() {
        let rec = OneShotRecord {
            operation: "plugin.call_once",
            success: false,
            error_code: Some("TIMEOUT"),
            elapsed: Duration::from_micros(1500),
        };
        assert_eq!(
            rec.to_json_line(),
            "{\"op\":\"plugin.call_once\",\"success\":false,\"error_code\":\"TIMEOUT\",\"elapsed_us\":1500}"
        );
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
}
