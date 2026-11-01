//! `ps`: プロジェクト内の各サービスの状態を一覧にする（STACK-8・TASK-155.4・#621）。
//!
//! 呼び出し元は CLI の `ps` サブコマンド（結線は未実装。#3639）。`up` と同じく profiles で絞った
//! `BTreeMap<String, Service>` を受け、キー（サービス名）の昇順で [`ServiceStatusSource`] に状態を問う。
//! `plan_startup` は通さないため、`depends_on` に循環があっても一覧を出せる。`Service` の値は読まない
//! （`env` に資格情報を含みうるため、行・エラー・`Debug` のどこにも入れない）。
//!
//! 最初の観測失敗で止める（fail-closed。`up` と同じ。行ごとのエラー表示は採らない）。
//!
//! 実装済みを装わない（REPAIR-3）。未実装（#3639 で追跡）: 本番の [`ServiceStatusSource`]
//! （core の state.json 読み取り）、CLI 結線、`--format`、ポート・イメージ・コンテナ ID の列、
//! profiles の適用（STACK-10）。

use std::collections::BTreeMap;
use std::fmt;
use std::num::NonZeroU8;

use crate::depends_on::ObservedHealth;
use crate::depends_on::wait::{DependencyObservation, ObserveError};
use crate::schema::Service;

/// 1 サービスの現在の状態（コンテナの状態と、あれば healthcheck の判定）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServiceStatus {
    state: DependencyObservation,
    health: Option<ObservedHealth>,
}

impl ServiceStatus {
    /// 状態と health から作る。healthcheck が無ければ `health` は `None`。
    pub fn new(state: DependencyObservation, health: Option<ObservedHealth>) -> Self {
        Self { state, health }
    }

    /// コンテナの状態。
    pub fn state(&self) -> DependencyObservation {
        self.state
    }

    /// healthcheck の判定。
    pub fn health(&self) -> Option<ObservedHealth> {
        self.health
    }
}

/// サービスの現在の状態を読む入口（状態ストアの背後。本番のアダプタは #3639）。
///
/// 実装の契約:
/// - (a) `service` は TOML 由来の外部入力。パス要素にする前に実装側で検証する（パストラバーサル防止）。
/// - (b) 返すのはプロジェクトの現在の記録（前回の up の分も含む）。今回の up の分だけを返す
///   `DependencyObserver` の契約とは逆。
/// - (c) ブロックする実装は短い上限を持つ（REPAIR-5）。
/// - (d) `Service` の内容は受け取らず、エラーにも入れない。
pub trait ServiceStatusSource {
    /// `service` の現在の状態を返す。
    fn status(&mut self, service: &str) -> Result<ServiceStatus, ObserveError>;
}

/// 一覧の 1 行。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PsRow {
    service: String,
    status: ServiceStatus,
}

impl PsRow {
    /// サービス名（TOML のキーそのまま。エスケープは描画だけで行う）。
    pub fn service(&self) -> &str {
        &self.service
    }

    /// 状態。
    pub fn status(&self) -> ServiceStatus {
        self.status
    }
}

/// `ps` の結果（サービス名の昇順）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PsReport {
    rows: Vec<PsRow>,
}

const HEADERS: [&str; 3] = ["SERVICE", "STATE", "HEALTH"];

fn state_str(s: DependencyObservation) -> &'static str {
    // `#[non_exhaustive]` でも同じ crate 内なので網羅 match になる。
    match s {
        DependencyObservation::Absent => "absent",
        DependencyObservation::Creating => "creating",
        DependencyObservation::Created => "created",
        DependencyObservation::Running => "running",
        DependencyObservation::Stopped => "stopped",
    }
}

/// 端末へ出す前に制御文字をエスケープする（ANSI 列や改行による表示の乗っ取りを防ぐ）。
fn sanitize(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c.is_control() {
            out.extend(c.escape_default());
        } else {
            out.push(c);
        }
    }
    out
}

impl PsReport {
    /// 行（サービス名の昇順）。
    pub fn rows(&self) -> &[PsRow] {
        &self.rows
    }

    /// サービス名（昇順）。
    pub fn service_names(&self) -> Vec<&str> {
        self.rows.iter().map(|r| r.service.as_str()).collect()
    }

    /// 英語ヘッダーつきの表。列幅は内容から計算し、各行は LF で終わる。0 件ならヘッダー行だけ。
    pub fn render_table(&self) -> String {
        let cells: Vec<[String; 3]> = self
            .rows
            .iter()
            .map(|r| {
                [
                    sanitize(&r.service),
                    state_str(r.status.state).to_string(),
                    r.status
                        .health
                        .map_or("-", ObservedHealth::as_str)
                        .to_string(),
                ]
            })
            .collect();
        let mut widths = HEADERS.map(|h| h.chars().count());
        for row in &cells {
            for (w, c) in widths.iter_mut().zip(row.iter()) {
                *w = (*w).max(c.chars().count());
            }
        }
        let mut out = String::new();
        let mut line = |cols: [&str; 3]| {
            for (i, (c, w)) in cols.iter().zip(widths.iter()).enumerate() {
                out.push_str(c);
                if i < 2 {
                    let pad = w.saturating_sub(c.chars().count());
                    out.extend(std::iter::repeat_n(' ', pad + 2));
                }
            }
            out.push('\n');
        };
        line(HEADERS);
        for row in &cells {
            line([&row[0], &row[1], &row[2]]);
        }
        out
    }
}

impl fmt::Display for PsReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.render_table())
    }
}

/// `ps` の失敗。`Service` の内容は持たない。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PsError {
    /// 状態の観測に失敗した（最初の失敗で止める）。
    Observe {
        /// 失敗したサービス名。
        service: String,
        /// 観測側のエラー。
        source: ObserveError,
    },
}

impl PsError {
    /// 機械可読なエラーコード。
    pub fn code(&self) -> &'static str {
        match self {
            Self::Observe { .. } => "SERVICE_STATUS_OBSERVE_FAILED",
        }
    }

    /// 固定の英語メッセージ。
    pub fn message(&self) -> &'static str {
        match self {
            Self::Observe { .. } => "failed to observe service status",
        }
    }

    /// 終了コード（`DependencyWaitError::Observe` と同じ 1）。
    pub fn exit_code(&self) -> NonZeroU8 {
        NonZeroU8::MIN
    }
}

impl fmt::Display for PsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Observe { service, source } => write!(
                f,
                "{}: {} ({})",
                self.message(),
                sanitize(service),
                source.code()
            ),
        }
    }
}

impl std::error::Error for PsError {}

/// 各サービスの状態を名前の昇順で集める。最初の観測失敗で [`PsError::Observe`] を返す。
pub fn ps<S: ServiceStatusSource>(
    services: &BTreeMap<String, Service>,
    source: &mut S,
) -> Result<PsReport, PsError> {
    let mut rows = Vec::with_capacity(services.len());
    for name in services.keys() {
        let status = source.status(name).map_err(|e| PsError::Observe {
            service: name.clone(),
            source: e,
        })?;
        rows.push(PsRow {
            service: name.clone(),
            status,
        });
    }
    Ok(PsReport { rows })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    struct Fake {
        map: HashMap<String, Result<ServiceStatus, ObserveError>>,
        calls: Vec<String>,
    }

    impl ServiceStatusSource for Fake {
        fn status(&mut self, service: &str) -> Result<ServiceStatus, ObserveError> {
            self.calls.push(service.to_string());
            self.map
                .get(service)
                .cloned()
                .unwrap_or_else(|| Err(ObserveError::new("MISSING", "missing")))
        }
    }

    fn services(names: &[&str]) -> BTreeMap<String, Service> {
        let mut src = String::new();
        for n in names {
            src.push_str(&format!("[services.\"{n}\"]\nimage = \"x/y:1\"\n"));
        }
        let c: crate::schema::ComposeToml = toml::from_str(&src).unwrap();
        c.services
    }

    fn st(
        s: DependencyObservation,
        h: Option<ObservedHealth>,
    ) -> Result<ServiceStatus, ObserveError> {
        Ok(ServiceStatus::new(s, h))
    }

    #[test]
    fn stack_8_ps_lists_every_state() {
        let svcs = services(&["a", "bb", "c", "d", "e"]);
        let mut f = Fake {
            map: HashMap::from([
                ("a".into(), st(DependencyObservation::Absent, None)),
                ("bb".into(), st(DependencyObservation::Creating, None)),
                ("c".into(), st(DependencyObservation::Created, None)),
                (
                    "d".into(),
                    st(
                        DependencyObservation::Running,
                        Some(ObservedHealth::Healthy),
                    ),
                ),
                (
                    "e".into(),
                    st(
                        DependencyObservation::Stopped,
                        Some(ObservedHealth::Unhealthy),
                    ),
                ),
            ]),
            calls: vec![],
        };
        let r = ps(&svcs, &mut f).unwrap();
        assert_eq!(f.calls, ["a", "bb", "c", "d", "e"]);
        assert_eq!(
            r.render_table(),
            "SERVICE  STATE     HEALTH\n\
             a        absent    -\n\
             bb       creating  -\n\
             c        created   -\n\
             d        running   healthy\n\
             e        stopped   unhealthy\n"
        );
        assert_eq!(r.to_string(), r.render_table());
    }

    #[test]
    fn stack_8_ps_empty_services_header_only() {
        let mut f = Fake {
            map: HashMap::new(),
            calls: vec![],
        };
        let r = ps(&BTreeMap::new(), &mut f).unwrap();
        assert!(r.rows().is_empty());
        assert_eq!(r.render_table(), "SERVICE  STATE  HEALTH\n");
    }

    #[test]
    fn stack_8_ps_observe_failure_stops() {
        let svcs = services(&["a", "b", "c"]);
        let mut f = Fake {
            map: HashMap::from([
                ("a".into(), st(DependencyObservation::Running, None)),
                (
                    "b".into(),
                    Err(ObserveError::new("STATE_READ_FAILED", "read failed")),
                ),
            ]),
            calls: vec![],
        };
        let e = ps(&svcs, &mut f).unwrap_err();
        assert_eq!(f.calls, ["a", "b"]);
        assert_eq!(e.code(), "SERVICE_STATUS_OBSERVE_FAILED");
        assert_eq!(e.exit_code().get(), 1);
        assert_eq!(
            e.to_string(),
            "failed to observe service status: b (STATE_READ_FAILED)"
        );
    }

    #[test]
    fn stack_8_ps_control_chars_escaped() {
        let name = "x\u{1b}[31m\ny";
        let mut svcs = BTreeMap::new();
        svcs.insert(name.to_string(), services(&["z"]).remove("z").unwrap());
        let mut f = Fake {
            map: HashMap::from([(name.to_string(), st(DependencyObservation::Running, None))]),
            calls: vec![],
        };
        let r = ps(&svcs, &mut f).unwrap();
        assert_eq!(r.rows()[0].service(), name);
        let t = r.render_table();
        assert!(!t.contains('\u{1b}'));
        assert_eq!(t.lines().count(), 2);
        assert!(t.contains("x\\u{1b}[31m\\ny"));
    }
}
