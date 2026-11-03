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

/// 一覧に出せるサービス数の上限（出力の増幅を抑える。SEC-1・REPAIR-5）。
pub const MAX_PS_SERVICES: usize = 1024;
/// サービス名 1 件の最大バイト長（エスケープ前）。
pub const MAX_PS_NAME_BYTES: usize = 253;
/// 表全体の最大バイト数（列幅のパディングを含む見積もり）。
pub const MAX_PS_OUTPUT_BYTES: usize = 256 * 1024;

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

/// Cc 以外で表示を乱す文字（Zl / Zp と書式文字 Cf の主要範囲。bidi 制御・ゼロ幅・BOM 等）か。
/// 依存を足さず範囲で判定する（依存は承認制）。
fn is_display_hazard(c: char) -> bool {
    matches!(c as u32,
        0x00AD | 0x0600..=0x0605 | 0x061C | 0x06DD | 0x070F | 0x08E2 | 0x180E
        | 0x200B..=0x200F | 0x2028 | 0x2029 | 0x202A..=0x202E | 0x2060..=0x206F
        | 0xFEFF | 0xFFF9..=0xFFFB | 0xE0001 | 0xE0020..=0xE007F)
}

/// 端末へ出す前に制御文字をエスケープする（ANSI 列や改行による表示の乗っ取りを防ぐ）。
fn sanitize(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c.is_control() || is_display_hazard(c) {
            out.extend(c.escape_default());
        } else {
            out.push(c);
        }
    }
    out
}

/// 端末上の表示幅（列数）の近似。結合文字・ゼロ幅は 0、東アジアの全角・絵文字は 2、他は 1。
/// 依存を足さず自前で判定する（依存は承認制）。制御文字は `sanitize` 済みの前提。
fn display_width(s: &str) -> usize {
    s.chars().map(char_width).sum()
}

fn char_width(c: char) -> usize {
    match u32::from(c) {
        0x0300..=0x036F | 0x200B..=0x200F | 0x20D0..=0x20FF | 0xFE00..=0xFE0F | 0xFE20..=0xFE2F => {
            0
        }
        0x1100..=0x115F
        | 0x2E80..=0x303E
        | 0x3041..=0xA4CF
        | 0xAC00..=0xD7A3
        | 0xF900..=0xFAFF
        | 0xFE30..=0xFE6F
        | 0xFF00..=0xFF60
        | 0xFFE0..=0xFFE6
        | 0x1F300..=0x1F64F
        | 0x1F900..=0x1F9FF
        | 0x20000..=0x3FFFD => 2,
        _ => 1,
    }
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
        let mut widths = HEADERS.map(display_width);
        for row in &cells {
            for (w, c) in widths.iter_mut().zip(row.iter()) {
                *w = (*w).max(display_width(c));
            }
        }
        let mut out = String::new();
        let mut line = |cols: [&str; 3]| {
            for (i, (c, w)) in cols.iter().zip(widths.iter()).enumerate() {
                out.push_str(c);
                if i < 2 {
                    let pad = w.saturating_sub(display_width(c));
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
    /// サービス数・名前長・出力量のいずれかが上限を超えた（観測の前に拒否する）。
    LimitExceeded {
        /// 超えた上限の種類。
        limit: PsLimit,
    },
}

/// 超過した上限の種類。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PsLimit {
    /// サービス数（[`MAX_PS_SERVICES`]）。
    Services,
    /// サービス名のバイト長（[`MAX_PS_NAME_BYTES`]）。
    NameBytes,
    /// 表全体の出力量（[`MAX_PS_OUTPUT_BYTES`]）。
    OutputBytes,
}

impl PsError {
    /// 機械可読なエラーコード。
    pub fn code(&self) -> &'static str {
        match self {
            Self::Observe { .. } => "SERVICE_STATUS_OBSERVE_FAILED",
            Self::LimitExceeded { .. } => "SERVICE_LIST_LIMIT_EXCEEDED",
        }
    }

    /// 固定の英語メッセージ。
    pub fn message(&self) -> &'static str {
        match self {
            Self::Observe { .. } => "failed to observe service status",
            Self::LimitExceeded { .. } => "service list exceeds output limits",
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
            Self::LimitExceeded { limit } => write!(f, "{} ({limit:?})", self.message()),
        }
    }
}

impl std::error::Error for PsError {}

/// 観測・表の組み立ての前に件数・名前長・出力量の見積もりを検証する（checked 演算）。
fn check_limits(services: &BTreeMap<String, Service>) -> Result<(), PsError> {
    let exceeded = |limit| PsError::LimitExceeded { limit };
    if services.len() > MAX_PS_SERVICES {
        return Err(exceeded(PsLimit::Services));
    }
    // 表示幅（パディング用）とエスケープ後のバイト長を分けて集計する。
    let mut max_width = display_width(HEADERS[0]);
    let mut names: Vec<(usize, usize)> = Vec::with_capacity(services.len());
    for name in services.keys() {
        if name.len() > MAX_PS_NAME_BYTES {
            return Err(exceeded(PsLimit::NameBytes));
        }
        let escaped = sanitize(name);
        let width = display_width(&escaped);
        max_width = max_width.max(width);
        names.push((escaped.len(), width));
    }
    // 1 行 = 名前（バイト長）+ パディング（最大幅 - 表示幅 + 2）+ 状態列（最大 8 + 2）+ health（最大 9）+ LF。
    let fixed = 2 + 8 + 2 + 9 + 1;
    let header = (HEADERS[0].len(), display_width(HEADERS[0]));
    let mut total: usize = 0;
    for (bytes, width) in std::iter::once(header).chain(names) {
        let line = bytes
            .checked_add(max_width - width)
            .and_then(|v| v.checked_add(fixed))
            .ok_or_else(|| exceeded(PsLimit::OutputBytes))?;
        total = total
            .checked_add(line)
            .ok_or_else(|| exceeded(PsLimit::OutputBytes))?;
        if total > MAX_PS_OUTPUT_BYTES {
            return Err(exceeded(PsLimit::OutputBytes));
        }
    }
    Ok(())
}

/// 各サービスの状態を名前の昇順で集める。最初の観測失敗で [`PsError::Observe`] を返す。
pub fn ps<S: ServiceStatusSource>(
    services: &BTreeMap<String, Service>,
    source: &mut S,
) -> Result<PsReport, PsError> {
    check_limits(services)?;
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

    #[test]
    fn stack_8_ps_format_and_separator_chars_escaped() {
        let name = "a\u{2028}b\u{2029}c\u{202e}d\u{200f}e\u{feff}";
        let mut svcs = BTreeMap::new();
        svcs.insert(name.to_string(), services(&["z"]).remove("z").unwrap());
        let mut f = Fake {
            map: HashMap::from([(name.to_string(), st(DependencyObservation::Running, None))]),
            calls: vec![],
        };
        let r = ps(&svcs, &mut f).unwrap();
        let t = r.render_table();
        for c in ['\u{2028}', '\u{2029}', '\u{202e}', '\u{200f}', '\u{feff}'] {
            assert!(!t.contains(c), "raw {c:?} remained");
        }
        assert_eq!(t.lines().count(), 2);
        assert!(t.contains("a\\u{2028}b\\u{2029}c\\u{202e}d\\u{200f}e\\u{feff}"));
        assert_eq!(sanitize("\u{2066}"), "\\u{2066}");
    }

    #[test]
    fn stack_8_ps_rejects_long_name_before_observing() {
        let name = "n".repeat(MAX_PS_NAME_BYTES + 1);
        let mut svcs = BTreeMap::new();
        svcs.insert(name, services(&["z"]).remove("z").unwrap());
        let mut f = Fake {
            map: HashMap::new(),
            calls: vec![],
        };
        let e = ps(&svcs, &mut f).unwrap_err();
        assert_eq!(
            e,
            PsError::LimitExceeded {
                limit: PsLimit::NameBytes
            }
        );
        assert_eq!(e.code(), "SERVICE_LIST_LIMIT_EXCEEDED");
        assert!(f.calls.is_empty());
    }

    #[test]
    fn stack_8_ps_rejects_too_many_services() {
        let tmpl = services(&["z"]).remove("z").unwrap();
        let mut svcs = BTreeMap::new();
        for i in 0..=MAX_PS_SERVICES {
            svcs.insert(format!("s{i:05}"), tmpl.clone());
        }
        let mut f = Fake {
            map: HashMap::new(),
            calls: vec![],
        };
        let e = ps(&svcs, &mut f).unwrap_err();
        assert_eq!(
            e,
            PsError::LimitExceeded {
                limit: PsLimit::Services
            }
        );
        assert!(f.calls.is_empty());
    }

    #[test]
    fn stack_8_ps_rejects_amplified_output() {
        // 1 件の長い名前 + 多数の短い名前: 253 * 1000 + ... が 256 KiB を超える。
        let tmpl = services(&["z"]).remove("z").unwrap();
        let mut svcs = BTreeMap::new();
        svcs.insert("n".repeat(MAX_PS_NAME_BYTES), tmpl.clone());
        for i in 0..1000 {
            svcs.insert(format!("s{i:04}"), tmpl.clone());
        }
        let mut f = Fake {
            map: HashMap::new(),
            calls: vec![],
        };
        let e = ps(&svcs, &mut f).unwrap_err();
        assert_eq!(
            e,
            PsError::LimitExceeded {
                limit: PsLimit::OutputBytes
            }
        );
        assert!(f.calls.is_empty());
    }

    #[test]
    fn stack_8_ps_rejects_utf8_wide_names_by_byte_length() {
        // 「日」83 文字 + 連番 4 桁 = 253 バイト・表示幅 170。1024 件で実表は 272572 バイト。
        let tmpl = services(&["z"]).remove("z").unwrap();
        let mut svcs = BTreeMap::new();
        for i in 0..MAX_PS_SERVICES {
            svcs.insert(format!("{}{i:04}", "日".repeat(83)), tmpl.clone());
        }
        assert_eq!(svcs.len(), 1024);
        assert!(svcs.keys().all(|k| k.len() == 253));
        let mut f = Fake {
            map: HashMap::new(),
            calls: vec![],
        };
        let e = ps(&svcs, &mut f).unwrap_err();
        assert_eq!(
            e,
            PsError::LimitExceeded {
                limit: PsLimit::OutputBytes
            }
        );
        assert!(f.calls.is_empty());
    }

    #[test]
    fn stack_8_ps_display_width_aligns_wide_and_combining() {
        assert_eq!(display_width("abc"), 3);
        assert_eq!(display_width("日本"), 4);
        assert_eq!(display_width("e\u{301}"), 1);
        let name = "日本";
        let mut svcs = BTreeMap::new();
        svcs.insert(name.to_string(), services(&["z"]).remove("z").unwrap());
        svcs.insert("ab".to_string(), services(&["z"]).remove("z").unwrap());
        let mut f = Fake {
            map: HashMap::from([
                (name.to_string(), st(DependencyObservation::Running, None)),
                ("ab".to_string(), st(DependencyObservation::Running, None)),
            ]),
            calls: vec![],
        };
        let t = ps(&svcs, &mut f).unwrap().render_table();
        assert_eq!(
            t,
            "SERVICE  STATE    HEALTH\nab       running  -\n日本     running  -\n"
        );
    }
}
