//! plugin プロセスの常駐モード（PLUG-7・TASK-110.2・#259）。
//!
//! plugin プロセスを 1 回だけ起動し、確立した接続を保持したまま複数の要求を順次処理する。
//! 呼び出し元は core 側の plugin proxy（TASK-114 ほか。依存方向は `core -> plugin` のため、本モジュールは
//! core の登録表を参照せず、検証済みの絶対パスを持つ起動仕様 [`OneShotPlugin`] を受け取る。
//! 起動仕様の型は都度起動モードと共用。モード選択 API は TASK-110.3 の `mode`。型名の中立化は未実施）。
//!
//! # 契約
//!
//! - 接続モデル: spawn 1 回 -> accept 1 回 -> listener を即 drop（socket を unlink）-> 保持した
//!   [`UdsStream`] 上で要求 / 応答を順次往復する。接続後は socket が残らず、同一 UID の別プロセスが
//!   割り込める入口を作らない（PLUG-12 の方針）。応答者は spawn した子の pid に限定する。
//! - 順次性: [`ResidentPlugin::call`] は `&mut self` を取り、同時に 1 往復しか走らない（借用規則で保証）。
//! - 期限（REPAIR-5）: 起動は [`ResidentStartTimeout`]、1 往復は呼び出しごとの [`RpcTimeout`]（送信と受信の
//!   合計）、終了待ち・回収待ち・stderr 収集待ちは都度起動モードの定数を共用する。
//! - 異常終了の検知: 往復前の終了確認と、往復失敗後の短い猶予（[`RESIDENT_EXIT_DETECT_TIMEOUT`]）つき終了
//!   確認で、子の終了を `Unavailable` の構造化エラーへ読み替える。メッセージには自プロセスが取得した終了
//!   コードの数値のみを含め、plugin 由来の文字列は含めない。終了コード 0 の自発終了も、常駐すべき
//!   プロセスの終了として同様に `Unavailable` とする。
//! - 失敗した接続は再利用しない。往復が失敗した時点で接続を閉じ、子を kill・回収してセッションを終了
//!   状態にする。以後の [`ResidentPlugin::call`] は I/O せず `FailedPrecondition`。回収を確認できない
//!   場合は `Internal`（pid つき）を返し、その子は以後回収しない（都度起動モードと同じ契約）。子は回収
//!   できたがプロセスグループを停止できなかった場合は、未回収とは別の `Internal`（pid なし。
//!   `process group could not be killed`）を返し、状態は [`ResidentState::GroupKillFailed`] になる。
//! - 子の環境は `env_clear()` 後に [`PLUGIN_SOCKET_ENV`] のみ。stdin / stdout は null、stderr は
//!   セッション全期間で 1 本の読み取りスレッドが上限つきで収集し、[`ResidentPlugin::shutdown`] の結果
//!   （失敗時も [`ResidentShutdownError`] に載せる）でのみ返す（untrusted）。[`ResidentPlugin`] の破棄（panic 等を含む）でも子の kill・回収とスレッド停止を行う。
//! - 応答は untrusted。フレームの長さ上限・チェックサムは transport 側で検証済みで、内容は解釈しない。
//!
//! # 孫プロセス（#1311）
//!
//! 呼び出しタイムアウト・shutdown・`Drop` の kill は子のプロセスグループ全体へ送り、孫も止める。
//! plugin の自発終了後に先に回収した場合・グループを抜けた孫・Windows は対象外（`super` のモジュール doc を参照）。
//!
//! # 未実装（REPAIR-3）
//!
//! - core の別プロセス起動をまたいで外部管理の常駐 plugin へ再接続する経路（attach）。plugin 発見・
//!   登録（TASK-109）と proxy（TASK-114）側の責務とする。PLUG-7 は「呼び出しごとに接続のみ行う」と
//!   記すが、本実装は起動後に接続を保持する形である（spec 側の表現との差は PR で報告）。
//! - 起動対象の信頼性検証（TASK-122・PLUG-11。検証から spawn までの
//!   差し替え〔TOCTOU〕も本タスクでは解決しない）、要求 ID と応答 ID の対応づけ（TASK-114）。

use super::{
    ChildGuard, ONE_SHOT_EXIT_TIMEOUT, ONE_SHOT_STDERR_DRAIN_TIMEOUT, OneShotPlugin, OneShotStderr,
    OneShotTermination, Reap, StderrCapture, classify_reaped, group_kill_failed_error, rpc_timeout,
    spawn_error, stderr_channel, unreaped_error,
};
use crate::error::{PluginError, PluginErrorCode};
use crate::frame::Frame;
use crate::transport::{RpcTimeout, UdsListener, UdsStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// [`ResidentStartTimeout`] の既定値（10 秒）。
pub const RESIDENT_START_TIMEOUT_DEFAULT: Duration = Duration::from_secs(10);

/// [`ResidentStartTimeout`] の上限（10 秒。残り時間を常に `RpcTimeout` へ変換できる値にする）。
pub const RESIDENT_START_TIMEOUT_MAX: Duration = Duration::from_secs(10);

/// 往復の失敗後に、子の終了を確認するために待つ猶予（I/O エラーと終了の観測順の競合を吸収する）。
pub const RESIDENT_EXIT_DETECT_TIMEOUT: Duration = Duration::from_millis(200);

/// 終了確認のポーリング間隔。
const EXIT_POLL: Duration = Duration::from_millis(5);

/// spawn から接続確立までの合計期限（REPAIR-5）。0 と [`RESIDENT_START_TIMEOUT_MAX`] 超は構築できない。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResidentStartTimeout(Duration);

impl ResidentStartTimeout {
    /// 0 または [`RESIDENT_START_TIMEOUT_MAX`] 超は `InvalidArgument`。
    pub fn new(timeout: Duration) -> Result<Self, PluginError> {
        if timeout.is_zero() || timeout > RESIDENT_START_TIMEOUT_MAX {
            return Err(PluginError::new(
                PluginErrorCode::InvalidArgument,
                "resident start timeout must be non-zero and within the maximum",
            ));
        }
        Ok(Self(timeout))
    }

    /// 保持している期間を返す。
    pub fn as_duration(&self) -> Duration {
        self.0
    }
}

impl Default for ResidentStartTimeout {
    /// [`RESIDENT_START_TIMEOUT_DEFAULT`]（10 秒）。
    fn default() -> Self {
        Self(RESIDENT_START_TIMEOUT_DEFAULT)
    }
}

impl TryFrom<Duration> for ResidentStartTimeout {
    type Error = PluginError;

    fn try_from(timeout: Duration) -> Result<Self, Self::Error> {
        Self::new(timeout)
    }
}

/// 常駐セッションの状態。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ResidentState {
    /// 子が稼働中で、接続を保持している。
    Running,
    /// 子が自発的に終了し、回収済み。`code` はシグナル終了などで取得できない場合 `None`。
    Exited { code: Option<i32> },
    /// 往復の失敗等でこちらが強制終了し、回収まで確認した。
    Killed,
    /// 強制終了を試みたが回収を確認できなかった（孤児の可能性。pid はエラーで報告済み）。
    Unreaped,
    /// 直接の子は回収済み（pid は解放済みで報告しない）だが、子のプロセスグループ宛ての kill が失敗し、
    /// 孫プロセスの停止を保証できない（#1311・PLUG-7・REPAIR-5）。未回収の子（[`Self::Unreaped`]）とは
    /// 別の状態で、[`ResidentPlugin::shutdown`] も後始末の失敗（`Internal`）を返す。
    GroupKillFailed,
}

/// [`ResidentPlugin::shutdown`] の結果。
#[derive(Debug)]
#[non_exhaustive]
pub struct ResidentShutdown {
    termination: OneShotTermination,
    stderr: OneShotStderr,
}

impl ResidentShutdown {
    /// 子プロセスの終了状況。
    pub fn termination(&self) -> OneShotTermination {
        self.termination
    }

    /// セッション全期間に plugin が stderr へ書いた内容（untrusted・上限つき）。
    pub fn stderr(&self) -> &OneShotStderr {
        &self.stderr
    }
}

/// [`ResidentPlugin::shutdown`] の失敗結果。エラーと、失敗経路でも回収した stderr を併せ持つ。
///
/// plugin がクラッシュした場合の診断情報を失わないため、[`ResidentShutdown`] と同じ stderr を載せる。
#[derive(Debug)]
#[non_exhaustive]
pub struct ResidentShutdownError {
    error: PluginError,
    stderr: OneShotStderr,
}

impl ResidentShutdownError {
    /// 失敗の構造化エラー。
    pub fn error(&self) -> &PluginError {
        &self.error
    }

    /// セッション全期間に plugin が stderr へ書いた内容（untrusted・上限つき）。
    pub fn stderr(&self) -> &OneShotStderr {
        &self.stderr
    }

    /// 構造化エラーだけを取り出す（stderr は捨てる）。
    pub fn into_error(self) -> PluginError {
        self.error
    }
}

/// 1 回の [`ResidentPlugin::call_observed`] の観測記録（成功 / 失敗とレイテンシ。REPAIR-4）。
///
/// 呼び出し側（core の plugin proxy 等）が集計する。stderr は毎回複製しないため載せない
/// （[`ResidentShutdown::stderr`]、失敗時は [`ResidentShutdownError::stderr`] で受け取る）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ResidentCallRecord {
    /// 操作名（固定値 `plugin.resident_call`）。
    pub operation: &'static str,
    /// 成功したか。
    pub success: bool,
    /// 失敗時の機械可読な `code`（ERR-1）。成功時は `None`。
    pub error_code: Option<&'static str>,
    /// 開始から戻るまでの所要時間。
    pub elapsed: Duration,
}

impl ResidentCallRecord {
    /// JSON Lines の 1 行（改行なし）へ符号化する。
    ///
    /// `operation` と `error_code` は公開フィールドで呼び出し側が任意の値を入れ得るため、
    /// 引用符・バックスラッシュ・制御文字（改行を含む）を JSON 文字列としてエスケープし、
    /// 常に単一行の妥当な JSON になることを保証する（REPAIR-4）。
    pub fn to_json_line(&self) -> String {
        let code = match self.error_code {
            Some(c) => format!("\"{}\"", json_escape(c)),
            None => "null".to_string(),
        };
        format!(
            "{{\"op\":\"{}\",\"success\":{},\"error_code\":{},\"elapsed_us\":{}}}",
            json_escape(self.operation),
            self.success,
            code,
            self.elapsed.as_micros()
        )
    }
}

/// JSON 文字列リテラルの内側へ埋め込める形にエスケープする（RFC 8259 §7）。
///
/// `"`・`\`・U+0000〜U+001F をエスケープし、それ以外（非 ASCII を含む）はそのまま出す。
fn json_escape(s: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

/// 常駐 plugin プロセスとの接続を保持するセッション（PLUG-7）。
///
/// [`Self::start`] で起動し、[`Self::call`] で要求を順次処理し、[`Self::shutdown`] で終了させる。
/// 破棄（panic 等を含む）時も、子の kill・回収と stderr 読み取りスレッドの停止を行う。
pub struct ResidentPlugin {
    // 破棄時は接続（子への EOF）、子の回収、stderr 収集の順に後始末する。
    stream: Option<UdsStream>,
    guard: ChildGuard,
    capture: Option<StderrCapture>,
    state: ResidentState,
}

impl std::fmt::Debug for ResidentPlugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResidentPlugin")
            .field("pid", &self.guard.pid())
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

fn start_timeout_error() -> PluginError {
    PluginError::new(PluginErrorCode::Timeout, "resident plugin start timed out")
}

fn call_timeout_error() -> PluginError {
    PluginError::new(PluginErrorCode::Timeout, "resident plugin call timed out")
}

fn remaining_or(deadline: Instant, err: fn() -> PluginError) -> Result<Duration, PluginError> {
    match deadline.checked_duration_since(Instant::now()) {
        Some(d) if !d.is_zero() => Ok(d),
        _ => Err(err()),
    }
}

/// 子の生存確認（`try_wait`）自体が失敗したことを表す `Unavailable`（OS のエラー文字列は含めない）。
fn status_check_error() -> PluginError {
    PluginError::new(
        PluginErrorCode::Unavailable,
        "failed to check resident plugin process status",
    )
}

/// 子の終了を表す `Unavailable`。値は自プロセスが回収で得た終了コードの数値のみ。
fn exited_error(code: Option<i32>) -> PluginError {
    let message = match code {
        Some(c) => format!("resident plugin process exited unexpectedly with exit code {c}"),
        None => "resident plugin process exited unexpectedly without an exit code".to_string(),
    };
    PluginError::new(PluginErrorCode::Unavailable, message)
}

impl ResidentPlugin {
    /// plugin を 1 回起動し、接続を確立して保持する（PLUG-7・REPAIR-5）。
    ///
    /// 一意名で listener を bind -> 子を spawn -> 接続を 1 回受け付け -> listener を drop。接続前に子が
    /// 終了した場合は期限を待たず `Unavailable`。失敗経路ではいずれも子を kill・回収してから返し、
    /// 回収を確認できない場合は `Internal`（pid つき）を返す。非 unix では bind が `Unimplemented` を
    /// 返し、子は spawn されない。
    pub fn start(
        plugin: &OneShotPlugin,
        timeout: ResidentStartTimeout,
    ) -> Result<Self, PluginError> {
        static SEQ: AtomicU64 = AtomicU64::new(0);

        let deadline = Instant::now()
            .checked_add(timeout.as_duration())
            .ok_or_else(start_timeout_error)?;
        let name = format!(
            "resident-{}-{}.sock",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        );
        let listener = UdsListener::bind(&plugin.socket_dir.join(name))?;

        let (child_stderr, reader) = stderr_channel().map_err(|_| {
            PluginError::new(
                PluginErrorCode::Internal,
                "failed to prepare capturing plugin stderr",
            )
        })?;
        let spawned =
            super::spawn_plugin(&plugin.program, &plugin.args, listener.path(), child_stderr);
        let mut guard = match spawned {
            Ok(child) => ChildGuard::new(child),
            Err(e) => return Err(spawn_error(&e)),
        };

        // 接続待ちより前に読み取りを始める（子が接続前に大量に書いても詰まらせない）。
        let capture = match StderrCapture::attach(reader) {
            Ok(c) => c,
            Err(_) => {
                drop(listener);
                return Err(reap_after_failure(
                    &mut guard,
                    PluginError::new(
                        PluginErrorCode::Internal,
                        "failed to start capturing plugin stderr",
                    ),
                ));
            }
        };

        let connected = (|| -> Result<UdsStream, PluginError> {
            let child_pid = guard.pid().ok_or_else(|| {
                PluginError::new(
                    PluginErrorCode::Internal,
                    "plugin process handle is missing",
                )
            })?;
            let left = remaining_or(deadline, start_timeout_error)?;
            // 応答者は spawn した子の pid に限定し、接続前の早期終了は期限を待たず検知する。
            let mut check_child = || match guard.try_wait() {
                Ok(None) => None,
                Ok(Some(_)) | Err(_) => Some(PluginError::new(
                    PluginErrorCode::Unavailable,
                    "plugin exited before connecting",
                )),
            };
            listener.accept_peer_pid(left, child_pid, &mut check_child)
        })();
        // 接続後は入口を残さない（socket を unlink する）。
        drop(listener);
        match connected {
            Ok(stream) => Ok(Self {
                stream: Some(stream),
                guard,
                capture: Some(capture),
                state: ResidentState::Running,
            }),
            Err(e) => Err(reap_after_failure(&mut guard, e)),
        }
    }

    /// 子の pid（回収後は `None`）。
    pub fn pid(&self) -> Option<u32> {
        self.guard.pid()
    }

    /// セッションの現在状態（最後に観測した時点のもの）。
    pub fn state(&self) -> ResidentState {
        self.state
    }

    /// 要求を 1 往復する（送信と受信を合わせて `timeout` の合計期限）。
    ///
    /// 応答（untrusted）は解釈せず [`Frame`] のまま返す。セッションが `Running` でなければ I/O せず
    /// `FailedPrecondition`。子の終了を検知した場合は `Unavailable`（モジュール冒頭の契約）。失敗した
    /// 呼び出しの後は接続を再利用せず、セッションは終了状態になる。
    pub fn call(&mut self, request: &Frame, timeout: RpcTimeout) -> Result<Frame, PluginError> {
        if self.state != ResidentState::Running {
            return Err(not_running_error());
        }
        // 往復の前に、呼び出し間で自発終了していないかを確認する。
        match self.guard.try_wait() {
            Ok(None) => {}
            Ok(Some(status)) => {
                self.guard.release_reaped();
                self.stream = None;
                let code = status.code();
                self.state = ResidentState::Exited { code };
                return Err(exited_error(code));
            }
            // 生存を確認できないまま通信しない。確認エラーもセッション失敗として接続を閉じ、
            // 子を kill・回収した結果を含む構造化エラーを返す。
            Err(_) => return Err(self.fail_session(status_check_error())),
        }
        let Some(deadline) = Instant::now().checked_add(timeout.as_duration()) else {
            return Err(call_timeout_error());
        };
        let Some(stream) = self.stream.as_mut() else {
            return Err(not_running_error());
        };
        let exchange = (|| -> Result<Frame, PluginError> {
            stream.write_frame(
                request,
                rpc_timeout(remaining_or(deadline, call_timeout_error)?)?,
            )?;
            stream.read_frame(rpc_timeout(remaining_or(deadline, call_timeout_error)?)?)
        })();
        match exchange {
            Ok(response) => Ok(response),
            Err(e) => Err(self.fail_session(e)),
        }
    }

    /// [`Self::call`] と同じ処理を行い、終了時に 1 件の [`ResidentCallRecord`] を `observer` へ渡す
    /// （REPAIR-4）。成功・失敗のどの経路でも 1 回だけ、呼び出しスレッド上で同期的に呼ばれる。
    pub fn call_observed(
        &mut self,
        request: &Frame,
        timeout: RpcTimeout,
        observer: &mut dyn FnMut(&ResidentCallRecord),
    ) -> Result<Frame, PluginError> {
        let start = Instant::now();
        let result = self.call(request, timeout);
        observer(&ResidentCallRecord {
            operation: "plugin.resident_call",
            success: result.is_ok(),
            error_code: result.as_ref().err().map(|e| e.code().as_str()),
            elapsed: start.elapsed(),
        });
        result
    }

    /// 往復の失敗後処理。接続を閉じ、子の終了を短い猶予つきで確認し、終了していれば `Unavailable` へ
    /// 読み替える。終了していなければ元のエラーを保ち、子を kill・回収する。
    fn fail_session(&mut self, original: PluginError) -> PluginError {
        self.stream = None;
        let start = Instant::now();
        loop {
            match self.guard.try_wait() {
                Ok(Some(status)) => {
                    self.guard.release_reaped();
                    let code = status.code();
                    self.state = ResidentState::Exited { code };
                    // 終了コード 0 の後始末（EOF を受けた正常終了）は通信失敗の原因ではないため、
                    // 元のエラーを保つ。異常終了（非ゼロ・取得不能）のときだけ読み替える。
                    return if code == Some(0) {
                        original
                    } else {
                        exited_error(code)
                    };
                }
                Ok(None) => {}
                Err(_) => break,
            }
            if start.elapsed() >= RESIDENT_EXIT_DETECT_TIMEOUT {
                break;
            }
            std::thread::sleep(EXIT_POLL);
        }
        match self.guard.kill_and_reap() {
            Reap::Reaped(status) => match classify_reaped(status) {
                OneShotTermination::Exited { code } => {
                    self.state = ResidentState::Exited { code };
                    if code == Some(0) {
                        original
                    } else {
                        exited_error(code)
                    }
                }
                _ => {
                    self.state = ResidentState::Killed;
                    original
                }
            },
            Reap::AlreadyReaped => {
                self.state = ResidentState::Killed;
                original
            }
            // 直接の子は回収済み（pid は解放済みで報告しない）だが、孫の停止を保証できない。
            // 元のエラーに隠さず後始末の失敗として返す。状態は未回収の子（`Unreaped`）と区別して
            // `GroupKillFailed` にし、shutdown でも同じ種類の失敗を報告する（#1311・PLUG-7・REPAIR-5）。
            Reap::GroupKillFailed => {
                self.state = ResidentState::GroupKillFailed;
                group_kill_failed_error("a failed call")
            }
            Reap::Unreaped => {
                self.state = ResidentState::Unreaped;
                unreaped_error(&mut self.guard, "a failed call")
            }
        }
    }

    /// セッションを終了させる。接続を閉じて EOF を見せ、[`ONE_SHOT_EXIT_TIMEOUT`] まで自発終了を待ち、
    /// 超過で強制終了・回収する。既に終了済みのセッションでは、その終了状況をそのまま使う。
    ///
    /// 自発終了が非ゼロ・取得不能なら `Unavailable`、回収を確認できなければ `Internal`（pid つき）、子は
    /// 回収できたがプロセスグループを停止できなければ `Internal`（pid なし。未回収とは別のメッセージ）を
    /// [`ResidentShutdownError`] で返す。いずれの経路でも、エラーを返す前に stderr の収集結果を
    /// 期限つき（[`ONE_SHOT_STDERR_DRAIN_TIMEOUT`]）で受け取って読み取りスレッドの停止を確認し、
    /// 診断情報（クラッシュ時の plugin の stderr 等）を [`ResidentShutdownError::stderr`] で渡す。
    pub fn shutdown(mut self) -> Result<ResidentShutdown, ResidentShutdownError> {
        self.stream = None;
        let termination = match self.state {
            ResidentState::Running => self.guard.wait_or_kill(ONE_SHOT_EXIT_TIMEOUT),
            ResidentState::Exited { code } => OneShotTermination::Exited { code },
            ResidentState::Killed => OneShotTermination::Killed,
            ResidentState::Unreaped => OneShotTermination::Unreaped,
            ResidentState::GroupKillFailed => OneShotTermination::GroupKillFailed,
        };
        // 失敗の判定を先に済ませ（報告済みの印は `unreaped_error` が付ける）、stderr は必ず回収する。
        let failure = if termination == OneShotTermination::Unreaped {
            self.state = ResidentState::Unreaped;
            Some(unreaped_error(&mut self.guard, "shutdown"))
        } else if termination == OneShotTermination::GroupKillFailed {
            // 直接の子は回収済みのため未回収としては報告しない（pid も報告済みの印も付けない）。
            self.state = ResidentState::GroupKillFailed;
            Some(group_kill_failed_error("shutdown"))
        } else if let OneShotTermination::Exited { code } = termination
            && code != Some(0)
        {
            // 最終応答後の異常終了（非ゼロ・取得不能）を成功として返さない（PLUG-7）。
            self.state = ResidentState::Exited { code };
            Some(exited_error(code))
        } else {
            None
        };
        let stderr = match self.capture.take() {
            Some(capture) => capture.finish(ONE_SHOT_STDERR_DRAIN_TIMEOUT),
            None => OneShotStderr::empty(),
        };
        match failure {
            Some(error) => Err(ResidentShutdownError { error, stderr }),
            None => Ok(ResidentShutdown {
                termination,
                stderr,
            }),
        }
    }
}

fn not_running_error() -> PluginError {
    PluginError::new(
        PluginErrorCode::FailedPrecondition,
        "resident plugin session is not running",
    )
}

/// 起動失敗経路で子を kill・回収する。回収を確認できなければ元のエラーに代えて `Internal`。
fn reap_after_failure(guard: &mut ChildGuard, error: PluginError) -> PluginError {
    match guard.kill_and_reap() {
        Reap::Reaped(_) | Reap::AlreadyReaped => error,
        Reap::GroupKillFailed => group_kill_failed_error("a failed start"),
        Reap::Unreaped => unreaped_error(guard, "a failed start"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// PLUG-7: 起動期限は 0 と上限超過を拒否する。
    #[test]
    fn plug7_resident_start_timeout_rejects_zero_and_over_max() {
        for d in [
            Duration::ZERO,
            RESIDENT_START_TIMEOUT_MAX + Duration::from_millis(1),
        ] {
            let e = ResidentStartTimeout::new(d).unwrap_err();
            assert_eq!(e.code(), PluginErrorCode::InvalidArgument);
        }
        assert_eq!(
            ResidentStartTimeout::default().as_duration(),
            Duration::from_secs(10)
        );
        assert!(ResidentStartTimeout::try_from(RESIDENT_START_TIMEOUT_MAX).is_ok());
    }

    /// REPAIR-4: 観測記録の JSON Lines は固定形式（具体文字列で照合）。
    #[test]
    fn repair4_resident_record_json_line_is_stable() {
        let rec = ResidentCallRecord {
            operation: "plugin.resident_call",
            success: false,
            error_code: Some("UNAVAILABLE"),
            elapsed: Duration::from_micros(2500),
        };
        assert_eq!(
            rec.to_json_line(),
            "{\"op\":\"plugin.resident_call\",\"success\":false,\
             \"error_code\":\"UNAVAILABLE\",\"elapsed_us\":2500}"
        );
        let ok = ResidentCallRecord {
            error_code: None,
            success: true,
            ..rec
        };
        assert_eq!(
            ok.to_json_line(),
            "{\"op\":\"plugin.resident_call\",\"success\":true,\
             \"error_code\":null,\"elapsed_us\":2500}"
        );
    }

    /// REPAIR-4: 引用符・バックスラッシュ・改行・制御文字を含む値でも単一行の妥当な JSON になる。
    #[test]
    fn repair4_resident_record_json_line_escapes_fields() {
        let rec = ResidentCallRecord {
            operation: "a\"b\\c\nd\te\u{1}",
            success: false,
            error_code: Some("X\"\r\ny"),
            elapsed: Duration::from_micros(1),
        };
        let line = rec.to_json_line();
        assert!(!line.contains('\n') && !line.contains('\r'));
        assert_eq!(
            line,
            "{\"op\":\"a\\\"b\\\\c\\nd\\te\\u0001\",\"success\":false,\
             \"error_code\":\"X\\\"\\r\\ny\",\"elapsed_us\":1}"
        );
    }

    /// PLUG-7: 異常終了のエラーは数値のみを含む構造化エラー。
    #[test]
    fn plug7_resident_exited_error_reports_code_only() {
        let e = exited_error(Some(3));
        assert_eq!(e.code(), PluginErrorCode::Unavailable);
        assert_eq!(
            e.message(),
            "resident plugin process exited unexpectedly with exit code 3"
        );
        assert_eq!(
            exited_error(None).message(),
            "resident plugin process exited unexpectedly without an exit code"
        );
    }

    /// PLUG-7: socket ディレクトリが無ければ bind で失敗し、子は spawn されない（プログラム不在の
    /// `NotFound` ではなく bind 側のエラーになる）。
    #[test]
    fn plug7_resident_start_reports_bind_failure_without_spawn() {
        let abs = if cfg!(windows) { "C:\\p" } else { "/bin/p" };
        let dir = std::env::temp_dir().join("fcos-nonexistent-resident-dir");
        let plugin = OneShotPlugin::new(abs.into(), vec![], dir).unwrap();
        let e = ResidentPlugin::start(&plugin, ResidentStartTimeout::default()).unwrap_err();
        assert_ne!(e.message(), "plugin program not found");
    }
}
