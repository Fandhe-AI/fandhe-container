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
//! - 観測記録（REPAIR-4）を受け取る統一 API。必要な場合は [`call_once_observed`] と
//!   [`ResidentPlugin::call_observed`] を直接使う（proxy 実装の TASK-114 で検討）。
//! - 外部管理の常駐 plugin への attach、[`OneShotPlugin`] の中立名への改名。

#[cfg(doc)]
use super::call_once_observed;
use super::{
    OneShotOutcome, OneShotPlugin, OneShotTimeout, ResidentPlugin, ResidentShutdown,
    ResidentShutdownError, ResidentStartTimeout, call_once,
};
use crate::error::PluginError;
use crate::frame::Frame;
use crate::transport::RpcTimeout;

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

enum Inner {
    OneShot {
        plugin: OneShotPlugin,
        timeout: OneShotTimeout,
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

    /// 要求を 1 往復させて応答フレームを返す。
    ///
    /// 都度起動は [`call_once`] へ、常駐は [`ResidentPlugin::call`] へ委譲する。応答は untrusted。
    pub fn call(&mut self, request: &Frame) -> Result<Frame, PluginError> {
        match &mut self.inner {
            Inner::OneShot { plugin, timeout } => {
                call_once(plugin, request, *timeout).map(OneShotOutcome::into_response)
            }
            Inner::Resident { session, rpc } => session.call(request, *rpc),
        }
    }

    /// セッションを閉じる。常駐は子の終了・回収と stderr 収集の結果を返す。
    pub fn shutdown(self) -> Result<PluginSessionShutdown, ResidentShutdownError> {
        match self.inner {
            Inner::OneShot { .. } => Ok(PluginSessionShutdown::OneShot),
            Inner::Resident { session, .. } => {
                session.shutdown().map(PluginSessionShutdown::Resident)
            }
        }
    }
}

/// [`PluginSession::shutdown`] の結果（モードつき）。
#[derive(Debug)]
#[non_exhaustive]
pub enum PluginSessionShutdown {
    /// 都度起動。保持しているプロセスはない（各 [`PluginSession::call`] で回収済み）。
    OneShot,
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
            PluginSessionShutdown::OneShot
        ));
    }
}
