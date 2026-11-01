//! `down`: 依存グラフの逆トポロジカル順でサービスを停止する（STACK-8・TASK-155.3・#620）。
//!
//! 呼び出し元は CLI の `down` サブコマンド（結線は未実装。#3639）。プロジェクトの全サービスを
//! 渡す想定（docker compose down は profiles に関係なくプロジェクトのコンテナを止める）。
//! 流れ: `plan_startup`（`up` と同じ計画）→ その steps を逆順にたどり、依存元を先、依存先を後に
//! [`ServiceStopper::stop`] する。待ちは持たない（`up` の healthy / started 待ちや `completed` の
//! 事前検査は写さない）。
//!
//! `up` との意図的な差:
//! - 部分失敗でも止めずに続ける。1 件の停止失敗で残りを止めると「全サービスが停止状態」
//!   （受け入れ条件）を満たせないため、失敗を全件集めて [`DownFailure`] で返す。順序は逆順のまま保ち、
//!   失敗したサービスの依存先も止める（down の目的を優先）。
//! - 計画に失敗（循環・未定義の依存先）したら何も止めず失敗する（fail-closed。終了コード 2）。
//!   計画できない TOML は `up` で起動できていない。名前順へのフォールバックは意味を黙って変えるため採らない。
//!
//! 実装済みを装わない（REPAIR-3）。未実装（#3639 で追跡）:
//! - 本番の [`ServiceStopper`]（CLI の `stop` を子プロセスで呼ぶ）、CLI 結線、TOML parse の入口
//! - コンテナ・ネットワークの削除、`UpFailure::launched` を使った部分集合の停止
//!
//! エラーと報告にはサービス名と固定文字列だけを入れ、`Service` の内容（`env` に資格情報を含みうる）は入れない。

use std::collections::BTreeMap;
use std::fmt;
use std::num::NonZeroU8;

use crate::depends_on::{DependsOnError, plan_startup};
use crate::schema::Service;

/// 停止の失敗（[`ServiceStopper`] が返す）。固定文字列だけを持ち、動的な値は入れない。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StopError {
    code: &'static str,
    message: &'static str,
}

impl StopError {
    /// 機械可読な `code` と固定の英語 `message` で作る。
    pub fn new(code: &'static str, message: &'static str) -> Self {
        Self { code, message }
    }

    /// 機械可読なエラーコード。
    pub fn code(&self) -> &'static str {
        self.code
    }

    /// 固定の英語メッセージ。
    pub fn message(&self) -> &'static str {
        self.message
    }
}

impl fmt::Display for StopError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for StopError {}

/// 停止の結果。「既に止まっている」は失敗ではない（冪等性）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum StopOutcome {
    /// 今回の呼び出しで停止した。
    Stopped,
    /// 既に停止していた（または存在しなかった）。
    AlreadyStopped,
}

/// 1 サービスの停止を行う入口（本番は CLI の stop 等を子プロセスで呼ぶ。#3639）。
///
/// 実装の契約:
/// - (a) `service` は TOML 由来の外部入力。ID・パス要素にする前に実装側で検証する（パストラバーサル防止）。
/// - (b) 停止対象は当該プロジェクトのコンテナに限る（他プロジェクトを止めない）。
/// - (c) ブロックする実装は短い上限を持つ（REPAIR-5）。
/// - (d) `spec` は資格情報（`env`）を含みうる。ログ・エラーへ `{:?}` で出さない。
pub trait ServiceStopper {
    /// `service` を停止する。既に止まっていれば [`StopOutcome::AlreadyStopped`] を返す。
    fn stop(&mut self, service: &str, spec: &Service) -> Result<StopOutcome, StopError>;
}

/// 1 サービスの停止結果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DownStepReport {
    service: String,
    outcome: StopOutcome,
}

impl DownStepReport {
    /// サービス名。
    pub fn service(&self) -> &str {
        &self.service
    }

    /// 停止の結果。
    pub fn outcome(&self) -> StopOutcome {
        self.outcome
    }
}

/// `down` の成功報告（停止順）。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DownReport {
    steps: Vec<DownStepReport>,
}

impl DownReport {
    /// 停止順のステップ。
    pub fn steps(&self) -> &[DownStepReport] {
        &self.steps
    }

    /// 停止したサービス名（停止順）。
    pub fn service_names(&self) -> impl Iterator<Item = &str> {
        self.steps.iter().map(|s| s.service.as_str())
    }
}

/// `down` のエラー 1 件。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DownError {
    /// 計画に失敗した（循環・未定義の依存先）。何も止めていない。
    Plan(DependsOnError),
    /// サービスの停止に失敗した。
    Stop { service: String, source: StopError },
    /// 計画にあるサービスが map に無い（計画上は起きない内部不整合）。
    Internal { service: String },
}

impl DownError {
    /// 機械可読なエラーコード。
    pub fn code(&self) -> &'static str {
        match self {
            Self::Plan(e) => e.code(),
            Self::Stop { .. } => "SERVICE_STOP_FAILED",
            Self::Internal { .. } => "INTERNAL",
        }
    }

    /// 固定の英語メッセージ（サービス名は含めない）。
    pub fn message(&self) -> &'static str {
        match self {
            Self::Plan(e) => e.message(),
            Self::Stop { .. } => "failed to stop a service",
            Self::Internal { .. } => "internal inconsistency in the shutdown plan",
        }
    }

    /// プロセスの非ゼロ終了コード（ERR-2。`UpError::exit_code` と同じ表）。
    pub fn exit_code(&self) -> NonZeroU8 {
        match self {
            Self::Plan(_) => NonZeroU8::new(2).unwrap_or(NonZeroU8::MIN),
            Self::Stop { .. } | Self::Internal { .. } => NonZeroU8::MIN,
        }
    }
}

impl fmt::Display for DownError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Plan(e) => e.fmt(f),
            Self::Stop { service, source } => {
                write!(f, "{}: {} ({})", self.message(), service, source.code())
            }
            Self::Internal { service } => write!(f, "{}: {}", self.message(), service),
        }
    }
}

impl std::error::Error for DownError {}

/// `down` の失敗。1 件以上のエラー（停止順）と、成功した停止を返す。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DownFailure {
    errors: Vec<DownError>,
    stopped: Vec<DownStepReport>,
}

impl DownFailure {
    /// 失敗の原因（1 件以上。停止順）。
    pub fn errors(&self) -> &[DownError] {
        &self.errors
    }

    /// 失敗までに停止できたサービス（停止順）。
    pub fn stopped(&self) -> &[DownStepReport] {
        &self.stopped
    }

    /// 先頭のエラーの `code`。
    pub fn code(&self) -> &'static str {
        self.errors.first().map_or("INTERNAL", DownError::code)
    }

    /// 終了コード。計画失敗があれば 2、それ以外は 1。
    pub fn exit_code(&self) -> NonZeroU8 {
        self.errors
            .iter()
            .map(DownError::exit_code)
            .max()
            .unwrap_or(NonZeroU8::MIN)
    }
}

impl fmt::Display for DownFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.errors.first() {
            Some(e) => write!(
                f,
                "{e} (failed: {}, stopped: {})",
                self.errors.len(),
                self.stopped.len()
            ),
            None => write!(f, "down failed (stopped: {})", self.stopped.len()),
        }
    }
}

impl std::error::Error for DownFailure {}

/// 依存グラフの逆トポロジカル順にサービスを停止する（STACK-8・TASK-155.3）。
///
/// 停止は失敗しても続け、結果を全件集める。計画に失敗したら何も止めない。
pub fn down<S: ServiceStopper>(
    services: &BTreeMap<String, Service>,
    stopper: &mut S,
) -> Result<DownReport, DownFailure> {
    let plan = match plan_startup(services) {
        Ok(p) => p,
        Err(e) => {
            return Err(DownFailure {
                errors: vec![DownError::Plan(e)],
                stopped: vec![],
            });
        }
    };
    let mut stopped = Vec::new();
    let mut errors = Vec::new();
    for step in plan.steps().iter().rev() {
        let name = step.service();
        let Some(spec) = services.get(name) else {
            errors.push(DownError::Internal {
                service: name.to_string(),
            });
            continue;
        };
        match stopper.stop(name, spec) {
            Ok(outcome) => stopped.push(DownStepReport {
                service: name.to_string(),
                outcome,
            }),
            Err(source) => errors.push(DownError::Stop {
                service: name.to_string(),
                source,
            }),
        }
    }
    if errors.is_empty() {
        Ok(DownReport { steps: stopped })
    } else {
        Err(DownFailure { errors, stopped })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// STACK-8: エラーの code・message・終了コードの具体値。
    #[test]
    fn down_error_codes_messages_and_exit_codes() {
        let stop = DownError::Stop {
            service: "b".into(),
            source: StopError::new("X", "y"),
        };
        assert_eq!(stop.code(), "SERVICE_STOP_FAILED");
        assert_eq!(stop.message(), "failed to stop a service");
        assert_eq!(stop.exit_code().get(), 1);
        assert_eq!(stop.to_string(), "failed to stop a service: b (X)");
        let internal = DownError::Internal {
            service: "b".into(),
        };
        assert_eq!(internal.code(), "INTERNAL");
        assert_eq!(internal.exit_code().get(), 1);
        let cycle = DownError::Plan(DependsOnError::Cycle {
            path: vec!["a".into(), "a".into()],
        });
        assert_eq!(cycle.code(), "DEPENDENCY_CYCLE");
        assert_eq!(cycle.exit_code().get(), 2);
        let unknown = DownError::Plan(DependsOnError::UnknownDependency {
            service: "a".into(),
            dependency: "z".into(),
        });
        assert_eq!(unknown.code(), "UNKNOWN_DEPENDENCY");
        assert_eq!(unknown.exit_code().get(), 2);
    }
}
