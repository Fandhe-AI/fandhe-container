//! plugin の起動モード選択 API（PLUG-7・TASK-110.3・#260）。
//!
//! 都度起動（[`call_once`]。TASK-110.1）と常駐（[`ResidentPlugin`]。TASK-110.2）を、呼び出し側が
//! 値（[`PluginMode`]）で選べる統一入口 [`PluginSession`] として束ねる。呼び出し元は core 側の
//! plugin proxy（TASK-114 ほか。依存方向は `core -> plugin`）で、本モジュールは起動・接続・回収・
//! stderr 収集を自前で行わず、各モードの実装へ委譲する。既存の [`call_once`] / [`ResidentPlugin`] は
//! 変更せず公開のまま残す。
//!
//! # 起動コストの目安（参考値）
//!
//! PoC-13（PLUG-7）の実測を要約した目安で、実装の保証値ではない。
//!
//! - 都度起動: 呼び出しごとに spawn する。spawn から READY までの中央値（5 試行）は、長さ接頭辞
//!   フレーム方式で約 2.037 ms（macOS）・約 0.414 ms（Linux・KVM 仮想マシン）。
//! - 常駐: 起動は 1 回で、以後の呼び出しは往復コストのみ。PoC の約 4.500 ms（macOS）・約 0.920 ms
//!   （Linux）は接続だけの時間ではなく、呼び出し側ハーネスの起動・UDS 接続・4 RPC を含む保守的な値
//!   である（都度起動の値と直接比較しない）。
//! - PoC-13 は bincode ペイロードでの計測で、現行の serde_json ペイロードでの再計測は TASK-113 の
//!   回帰ベンチで行う予定。
//!
//! # モードの切替
//!
//! セッションに可変のモード切替メソッドは持たせない（切替途中の失敗状態を型に持ち込まないため）。
//! 切り替えるときは [`PluginSession::shutdown`] で現在のセッションを閉じてから、同じ
//! [`OneShotPlugin`] に別の [`PluginMode`] で [`PluginSession::start`] する。
//!
//! # 契約
//!
//! - 期限は各モード固有の型（[`OneShotTimeout`]・[`ResidentStartTimeout`]・[`RpcTimeout`]）を
//!   [`PluginMode`] が保持する。無期限待ちや 0 / 上限超過は構築できない（REPAIR-5）。
//! - 子プロセスの回収・socket の後始末・stderr の扱い・環境変数の遮断は各モードの契約に従う。
//!   [`PluginSession`] の破棄でも、常駐の子は [`ResidentPlugin`] の `Drop` で kill・回収される。
//! - 非 unix では既存 API の挙動をそのまま伝播する（都度起動は `start` が成功し `call` が
//!   `Unimplemented`、常駐は `start` が `Unimplemented`）。
//!
//! # 未実装（REPAIR-3）
//!
//! - 起動対象の信頼性検証（TASK-122・PLUG-11）との結線。本 API は検証せず、呼び出し側が検証済みの
//!   絶対パスを持つ [`OneShotPlugin`] を渡す前提とする。
//! - 外部管理の常駐 plugin への attach、[`OneShotPlugin`] の中立名への改名。

use super::{
    OneShotPlugin, OneShotStderr, OneShotTermination, OneShotTimeout, ResidentPlugin,
    ResidentShutdown, ResidentShutdownError, ResidentStartTimeout, call_once_observed,
};
use crate::error::PluginError;
use crate::frame::Frame;
use crate::transport::RpcTimeout;
use std::time::Duration;

/// 起動モードの選択（PLUG-7）。各モード固有の期限型をそのまま保持する。
///
/// 起動コストの目安はモジュール冒頭の「起動コストの目安」を参照。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PluginMode {
    /// 都度起動。呼び出しごとに spawn し、1 往復後に子を終了・回収する（約 2.037 ms〔macOS〕・
    /// 約 0.414 ms〔Linux〕 / 呼び出し。PoC-13 の参考値）。
    OneShot {
        /// spawn から応答受信までの合計期限。
        timeout: OneShotTimeout,
    },
    /// 常駐。起動と接続は 1 回で、以後は同じ接続上で往復する（PoC-13 の参考値は約 4.500 ms〔macOS〕・
    /// 約 0.920 ms〔Linux〕。接続以外の計測コストを含む保守的な値）。
    Resident {
        /// spawn から接続確立までの合計期限。
        start: ResidentStartTimeout,
        /// 1 往復ごとの期限。
        rpc: RpcTimeout,
    },
}

impl PluginMode {
    /// 既定の期限つき都度起動モード。
    pub fn one_shot() -> Self {
        Self::OneShot {
            timeout: OneShotTimeout::default(),
        }
    }

    /// 既定の期限つき常駐モード。
    pub fn resident() -> Self {
        Self::Resident {
            start: ResidentStartTimeout::default(),
            rpc: RpcTimeout::default(),
        }
    }

    /// 期限を除いたモード種別を返す。
    pub fn kind(&self) -> PluginModeKind {
        match self {
            Self::OneShot { .. } => PluginModeKind::OneShot,
            Self::Resident { .. } => PluginModeKind::Resident,
        }
    }
}

/// 期限を除いたモード種別（ログ・比較用）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PluginModeKind {
    /// 都度起動。
    OneShot,
    /// 常駐。
    Resident,
}

impl PluginModeKind {
    /// 構造化ログ向けの安定した識別子（`"one_shot"` / `"resident"`）。
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::OneShot => "one_shot",
            Self::Resident => "resident",
        }
    }
}

/// 都度起動セッションが保持する直近の呼び出し結果（`shutdown` で返す。子は呼び出しごとに回収済み）。
#[derive(Default)]
struct OneShotStats {
    calls: u64,
    last_termination: Option<OneShotTermination>,
    last_stderr: Option<OneShotStderr>,
}

/// [`PluginSession::call`] の結果（モードを問わない統一形）。
///
/// 都度起動では子の終了状況と stderr（untrusted・上限つき）を保持する。常駐では子が呼び出しを
/// またいで生きているため `None` で、終了状況と stderr は [`PluginSession::shutdown`] で受け取る。
#[derive(Debug)]
#[non_exhaustive]
pub struct PluginCallOutcome {
    response: Frame,
    termination: Option<OneShotTermination>,
    stderr: Option<OneShotStderr>,
}

impl PluginCallOutcome {
    /// plugin から受信した応答フレーム（untrusted。内容は解釈していない）。
    pub fn response(&self) -> &Frame {
        &self.response
    }

    /// 応答フレームを取り出す。
    pub fn into_response(self) -> Frame {
        self.response
    }

    /// 子の終了状況。都度起動のみ `Some`。
    pub fn termination(&self) -> Option<OneShotTermination> {
        self.termination
    }

    /// plugin が stderr へ書いた内容（untrusted・上限つき）。都度起動のみ `Some`。
    pub fn stderr(&self) -> Option<&OneShotStderr> {
        self.stderr.as_ref()
    }
}

/// [`PluginSession::call_observed`] が 1 呼び出しごとに 1 回渡す観測記録（成功 / 失敗とレイテンシ。
/// REPAIR-4）。モードを問わず同じ形で受け取れる。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct PluginCallRecord {
    /// 呼び出しのモード種別。
    pub mode: PluginModeKind,
    /// 操作名（`plugin.call_once` または `plugin.resident_call`）。
    pub operation: &'static str,
    /// 成功したか。
    pub success: bool,
    /// 失敗時の機械可読な `code`（ERR-1）。成功時は `None`。
    pub error_code: Option<&'static str>,
    /// 開始から戻るまでの所要時間。
    pub elapsed: Duration,
    /// plugin の stderr（untrusted・上限つき）。都度起動のみ `Some`（成功・失敗のどちらでも）。
    pub stderr: Option<OneShotStderr>,
}

impl PluginCallRecord {
    /// JSON Lines の 1 行（改行なし）へ符号化する。値は固定文字列・数値・真偽値のみで、plugin の
    /// stderr の内容は埋め込まない（件数と打ち切りの有無だけを `plugin_stderr_*` で出す）。
    pub fn to_json_line(&self) -> String {
        let code = match self.error_code {
            Some(c) => format!("\"{c}\""),
            None => "null".to_string(),
        };
        let stderr = match &self.stderr {
            Some(e) => format!(
                ",\"plugin_stderr_bytes\":{},\"plugin_stderr_truncated\":{},\
                 \"plugin_stderr_complete\":{},\"plugin_stderr_reader_stopped\":{}",
                e.total_bytes(),
                e.is_truncated(),
                e.is_complete(),
                e.reader_stopped()
            ),
            None => String::new(),
        };
        format!(
            "{{\"mode\":\"{}\",\"op\":\"{}\",\"success\":{},\"error_code\":{},\"elapsed_us\":{}{}}}",
            self.mode.as_str(),
            self.operation,
            self.success,
            code,
            self.elapsed.as_micros(),
            stderr
        )
    }
}

enum Inner {
    OneShot {
        plugin: OneShotPlugin,
        timeout: OneShotTimeout,
        stats: OneShotStats,
    },
    Resident {
        session: ResidentPlugin,
        rpc: RpcTimeout,
    },
}

/// 選択したモードで plugin を呼び出すセッション（PLUG-7）。
///
/// 切替は「[`shutdown`](Self::shutdown) してから別モードで [`start`](Self::start)」で行う。
pub struct PluginSession {
    inner: Inner,
}

impl std::fmt::Debug for PluginSession {
    // plugin 由来の内容を出さないため、種別のみ表示する。
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PluginSession")
            .field("mode", &self.mode())
            .finish_non_exhaustive()
    }
}

impl PluginSession {
    /// `mode` でセッションを開始する。
    ///
    /// 都度起動は起動仕様と期限を保持するだけで spawn しない（spawn は [`call`](Self::call) ごと）。
    /// 常駐は [`ResidentPlugin::start`] で子を起動し接続を確立する（失敗はそのエラーを返す）。
    pub fn start(plugin: &OneShotPlugin, mode: PluginMode) -> Result<Self, PluginError> {
        let inner = match mode {
            PluginMode::OneShot { timeout } => Inner::OneShot {
                plugin: plugin.clone(),
                timeout,
                stats: OneShotStats::default(),
            },
            PluginMode::Resident { start, rpc } => Inner::Resident {
                session: ResidentPlugin::start(plugin, start)?,
                rpc,
            },
        };
        Ok(Self { inner })
    }

    /// セッションのモード種別を返す。
    pub fn mode(&self) -> PluginModeKind {
        match &self.inner {
            Inner::OneShot { .. } => PluginModeKind::OneShot,
            Inner::Resident { .. } => PluginModeKind::Resident,
        }
    }

    /// 要求を 1 往復させる。観測記録は両モードとも構造化ログ（JSON Lines）として stderr へ 1 行出す
    /// （REPAIR-4。都度起動は従来の [`call_once`](super::call_once) と同じ挙動）。記録を自分で受け取るなら
    /// [`call_observed`](Self::call_observed) を使う。応答は untrusted。
    pub fn call(&mut self, request: &Frame) -> Result<PluginCallOutcome, PluginError> {
        self.call_observed(request, &mut |record| {
            use std::io::Write;
            // 書き込み失敗は呼び出し結果に影響させない。
            let _ = writeln!(std::io::stderr(), "{}", record.to_json_line());
        })
    }

    /// [`call`](Self::call) と同じ処理を行い、終了時に 1 件の [`PluginCallRecord`] を `observer` へ
    /// 渡す（REPAIR-4）。成功・失敗のどの経路でも 1 回だけ呼ばれ、呼び出しスレッド上で同期実行される
    /// ため長時間ブロックしないこと。都度起動は [`call_once_observed`] へ、常駐は
    /// [`ResidentPlugin::call_observed`] へ委譲する。
    pub fn call_observed(
        &mut self,
        request: &Frame,
        observer: &mut dyn FnMut(&PluginCallRecord),
    ) -> Result<PluginCallOutcome, PluginError> {
        match &mut self.inner {
            Inner::OneShot {
                plugin,
                timeout,
                stats,
            } => {
                let mut stderr = None;
                let result = call_once_observed(plugin, request, *timeout, &mut |rec| {
                    stderr = Some(rec.stderr.clone());
                    observer(&PluginCallRecord {
                        mode: PluginModeKind::OneShot,
                        operation: rec.operation,
                        success: rec.success,
                        error_code: rec.error_code,
                        elapsed: rec.elapsed,
                        stderr: Some(rec.stderr.clone()),
                    });
                });
                stats.calls = stats.calls.saturating_add(1);
                stats.last_stderr = stderr.clone();
                match result {
                    Ok(outcome) => {
                        let termination = outcome.termination();
                        stats.last_termination = Some(termination);
                        Ok(PluginCallOutcome {
                            response: outcome.into_response(),
                            termination: Some(termination),
                            stderr,
                        })
                    }
                    Err(e) => {
                        stats.last_termination = None;
                        Err(e)
                    }
                }
            }
            Inner::Resident { session, rpc } => session
                .call_observed(request, *rpc, &mut |rec| {
                    observer(&PluginCallRecord {
                        mode: PluginModeKind::Resident,
                        operation: rec.operation,
                        success: rec.success,
                        error_code: rec.error_code,
                        elapsed: rec.elapsed,
                        stderr: None,
                    });
                })
                .map(|response| PluginCallOutcome {
                    response,
                    termination: None,
                    stderr: None,
                }),
        }
    }

    /// セッションを閉じる。常駐は子の終了・回収と stderr 収集の結果を、都度起動は呼び出し回数と
    /// 直近の呼び出しの終了状況・stderr を返す。
    pub fn shutdown(self) -> Result<PluginSessionShutdown, ResidentShutdownError> {
        match self.inner {
            Inner::OneShot { stats, .. } => Ok(PluginSessionShutdown::OneShot(OneShotSummary {
                calls: stats.calls,
                last_termination: stats.last_termination,
                last_stderr: stats.last_stderr,
            })),
            Inner::Resident { session, .. } => {
                session.shutdown().map(PluginSessionShutdown::Resident)
            }
        }
    }
}

/// 都度起動セッションの [`PluginSession::shutdown`] 結果。保持しているプロセスはなく（各呼び出しで
/// 回収済み）、直近の呼び出しの情報だけを返す。
#[derive(Debug)]
#[non_exhaustive]
pub struct OneShotSummary {
    calls: u64,
    last_termination: Option<OneShotTermination>,
    last_stderr: Option<OneShotStderr>,
}

impl OneShotSummary {
    /// セッションで行った呼び出し回数（失敗を含む）。
    pub fn calls(&self) -> u64 {
        self.calls
    }

    /// 直近の呼び出しが成功していればその子の終了状況。未呼び出し・直近が失敗なら `None`。
    pub fn last_termination(&self) -> Option<OneShotTermination> {
        self.last_termination
    }

    /// 直近の呼び出しで plugin が stderr へ書いた内容（untrusted・上限つき）。未呼び出しなら `None`。
    pub fn last_stderr(&self) -> Option<&OneShotStderr> {
        self.last_stderr.as_ref()
    }
}

/// [`PluginSession::shutdown`] の結果（モードつき）。
#[derive(Debug)]
#[non_exhaustive]
pub enum PluginSessionShutdown {
    /// 都度起動。保持しているプロセスはない（各 [`PluginSession::call`] で回収済み）。
    OneShot(OneShotSummary),
    /// 常駐。終了状況と stderr を含む。
    Resident(ResidentShutdown),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// PLUG-7: 識別子は構造化ログで使うため固定。
    #[test]
    fn plug7_mode_kind_strings_are_stable() {
        assert_eq!(PluginModeKind::OneShot.as_str(), "one_shot");
        assert_eq!(PluginModeKind::Resident.as_str(), "resident");
        assert_eq!(PluginMode::one_shot().kind(), PluginModeKind::OneShot);
        assert_eq!(PluginMode::resident().kind(), PluginModeKind::Resident);
    }

    /// PLUG-7・REPAIR-5: 既定モードは各期限型の既定値（10 秒）を持つ。
    #[test]
    fn plug7_mode_defaults_use_default_timeouts() {
        let ten = Duration::from_secs(10);
        match PluginMode::one_shot() {
            PluginMode::OneShot { timeout } => assert_eq!(timeout.as_duration(), ten),
            other => panic!("unexpected mode: {other:?}"),
        }
        match PluginMode::resident() {
            PluginMode::Resident { start, rpc } => {
                assert_eq!(start.as_duration(), ten);
                assert_eq!(rpc.as_duration(), ten);
            }
            other => panic!("unexpected mode: {other:?}"),
        }
    }

    /// PLUG-7: 都度起動の start は spawn しない（存在しない実行ファイルでも成功する）。
    #[test]
    fn plug7_one_shot_session_start_does_not_spawn() {
        let dir = std::env::temp_dir();
        let program = dir.join("no-such-plugin");
        let plugin = OneShotPlugin::new(program, vec![], dir).unwrap();
        let session = PluginSession::start(&plugin, PluginMode::one_shot()).unwrap();
        assert_eq!(session.mode(), PluginModeKind::OneShot);
        assert!(matches!(
            session.shutdown().unwrap(),
            PluginSessionShutdown::OneShot(_)
        ));
    }
}
