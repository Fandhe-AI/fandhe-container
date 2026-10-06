//! healthcheck 定義の解釈と検証（TASK-161.1・#493・SUP-4・MS-9）。
//!
//! 役割: command / interval / timeout / start_period / retries を表す未検証入力 [`RawHealthcheck`] を
//! 検証し、壊れた値を表現できない [`HealthcheckDefinition`] へ変換する。入力は stack の `healthcheck`
//! （STACK-1）等が組み立て、出力は後続の周期実行エンジン（#495・TASK-161.2）と `health` 反映
//! （#496・TASK-161.3）が読む。
//!
//! # 実装範囲の線引き（REPAIR-3）
//! - 提供するもの: 時間文字列の解釈 [`parse_duration`]・定義の検証 [`HealthcheckDefinition::parse`]。
//! - **未実装**: コマンド実行・周期実行（#495）、`health` 遷移と書き込み（#496）、TOML / compose からの
//!   デシリアライズ（`crates/stack`・`crates/compose-convert`。STACK-1・STACK-3）。実行時の分離
//!   （seccomp / Landlock 再適用の fail-closed）は TASK-163（SUP-6）の責務で、本モジュールは純粋な値検証のみを行う。
//!
//! # 設計判断（spec の SUP-4 は既定値・上限値を定めていないため、本実装の判断であり spec 確定値ではない）
//! - コマンドは argv のみ。シェル文字列と compose の予約語（`CMD-SHELL` / `CMD` / `NONE`）は拒否する
//!   （変換は compose-convert 側の責務）。NUL バイトは後続の exec で引数が切り詰められるため拒否する。
//! - 既定値は compose の意味論を参考にした値（[`DEFAULT_INTERVAL`] 等）。上限は無制限確保・
//!   ビジーループ防止のための値（[`MAX_INTERVAL`] 等）。
//! - 時間文字列は 10 進整数 + 単位（`ms`・`s`・`m`・`h`）の連結のみ。小数・`us` / `ns` は未対応。
//! - エラーメッセージには不正だった項目名と理由のみを入れ、command の中身は出さない（秘密情報の漏えい防止）。

use std::num::NonZeroU32;
use std::time::Duration;

use fandhe_container_core::traits::{ErrorCode, TraitError};

/// argv の最大要素数。
pub const MAX_COMMAND_ARGS: usize = 256;
/// argv の合計バイト長の上限。
pub const MAX_COMMAND_BYTES: usize = 64 * 1024;
/// 時間文字列の最大バイト長。
pub const MAX_DURATION_TEXT_BYTES: usize = 64;
/// interval の上限（24 時間）。
pub const MAX_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);
/// timeout の上限（1 時間）。
pub const MAX_TIMEOUT: Duration = Duration::from_secs(60 * 60);
/// start_period の上限（24 時間）。
pub const MAX_START_PERIOD: Duration = Duration::from_secs(24 * 60 * 60);
/// retries の上限。
pub const MAX_RETRIES: u32 = 1000;

/// interval 省略時の既定値（30 秒）。
pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(30);
/// timeout 省略時の既定値（30 秒）。
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
/// start_period 省略時の既定値（0 秒）。
pub const DEFAULT_START_PERIOD: Duration = Duration::ZERO;
/// retries 省略時の既定値（3 回）。
pub const DEFAULT_RETRIES: u32 = 3;

/// compose 由来の予約語（argv[0] としては拒否する）。
const RESERVED_COMMANDS: [&str; 3] = ["CMD-SHELL", "CMD", "NONE"];

/// 未検証の healthcheck 定義（PoC-16 のスキーマ相当）。
///
/// stack / compose-convert / CLI が組み立てて [`HealthcheckDefinition::parse`] へ渡す。
/// `retries` は負値を明示的に拒否できるよう符号付き。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RawHealthcheck {
    /// 実行する argv（シェル文字列ではない）。
    pub command: Vec<String>,
    /// 実行間隔（時間文字列。省略時は [`DEFAULT_INTERVAL`]）。
    pub interval: Option<String>,
    /// 1 回の実行のタイムアウト（時間文字列。省略時は [`DEFAULT_TIMEOUT`]）。
    pub timeout: Option<String>,
    /// 失敗を数え始めるまでの猶予（時間文字列。省略時は [`DEFAULT_START_PERIOD`]）。
    pub start_period: Option<String>,
    /// unhealthy と判定する連続失敗回数（省略時は [`DEFAULT_RETRIES`]）。
    pub retries: Option<i64>,
}

/// 検証済みの healthcheck 定義。生成経路は [`HealthcheckDefinition::parse`] のみ。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct HealthcheckDefinition {
    command: Vec<String>,
    interval: Duration,
    timeout: Duration,
    start_period: Duration,
    retries: NonZeroU32,
}

impl HealthcheckDefinition {
    /// 未検証入力を検証して定義を作る。検査順は command → interval → timeout → start_period → retries
    /// で、最初に検出した 1 件の `InvalidArgument` を返す。
    pub fn parse(raw: &RawHealthcheck) -> Result<Self, TraitError> {
        validate_command(&raw.command)?;
        let interval = field_duration("interval", raw.interval.as_deref(), DEFAULT_INTERVAL)?;
        if interval.is_zero() || interval > MAX_INTERVAL {
            return Err(invalid(
                "interval must be greater than zero and within the upper limit",
            ));
        }
        let timeout = field_duration("timeout", raw.timeout.as_deref(), DEFAULT_TIMEOUT)?;
        if timeout.is_zero() || timeout > MAX_TIMEOUT {
            return Err(invalid(
                "timeout must be greater than zero and within the upper limit",
            ));
        }
        let start_period = field_duration(
            "start_period",
            raw.start_period.as_deref(),
            DEFAULT_START_PERIOD,
        )?;
        if start_period > MAX_START_PERIOD {
            return Err(invalid("start_period exceeds the upper limit"));
        }
        let retries = validate_retries(raw.retries)?;
        Ok(Self {
            command: raw.command.clone(),
            interval,
            timeout,
            start_period,
            retries,
        })
    }

    /// 実行する argv。
    pub fn command(&self) -> &[String] {
        &self.command
    }

    /// 実行間隔（0 より大きい）。
    pub fn interval(&self) -> Duration {
        self.interval
    }

    /// 1 回の実行のタイムアウト（0 より大きい）。
    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// 失敗を数え始めるまでの猶予。
    pub fn start_period(&self) -> Duration {
        self.start_period
    }

    /// unhealthy と判定する連続失敗回数（1 以上）。
    pub fn retries(&self) -> NonZeroU32 {
        self.retries
    }
}

impl TryFrom<&RawHealthcheck> for HealthcheckDefinition {
    type Error = TraitError;

    fn try_from(raw: &RawHealthcheck) -> Result<Self, Self::Error> {
        Self::parse(raw)
    }
}

impl TryFrom<RawHealthcheck> for HealthcheckDefinition {
    type Error = TraitError;

    fn try_from(raw: RawHealthcheck) -> Result<Self, Self::Error> {
        Self::parse(&raw)
    }
}

fn invalid(message: &str) -> TraitError {
    TraitError::new(ErrorCode::InvalidArgument, message)
}

fn validate_command(command: &[String]) -> Result<(), TraitError> {
    let Some(program) = command.first() else {
        return Err(invalid("healthcheck command must not be empty"));
    };
    if program.is_empty() {
        return Err(invalid("healthcheck command program must not be empty"));
    }
    if RESERVED_COMMANDS.contains(&program.as_str()) {
        return Err(invalid(
            "healthcheck command must be an argv, not a reserved compose keyword",
        ));
    }
    if command.len() > MAX_COMMAND_ARGS {
        return Err(invalid("healthcheck command has too many arguments"));
    }
    let mut total: usize = 0;
    for arg in command {
        if arg.contains('\0') {
            return Err(invalid("healthcheck command must not contain NUL bytes"));
        }
        total = total.saturating_add(arg.len());
    }
    if total > MAX_COMMAND_BYTES {
        return Err(invalid("healthcheck command is too long"));
    }
    Ok(())
}

fn field_duration(
    field: &str,
    text: Option<&str>,
    default: Duration,
) -> Result<Duration, TraitError> {
    match text {
        None => Ok(default),
        Some(text) => {
            parse_duration(text).map_err(|e| invalid(&format!("{field}: {}", e.message())))
        }
    }
}

fn validate_retries(retries: Option<i64>) -> Result<NonZeroU32, TraitError> {
    let value = match retries {
        None => DEFAULT_RETRIES,
        Some(n) => u32::try_from(n)
            .ok()
            .filter(|v| (1..=MAX_RETRIES).contains(v))
            .ok_or_else(|| invalid("retries must be between 1 and the upper limit"))?,
    };
    NonZeroU32::new(value).ok_or_else(|| invalid("retries must be between 1 and the upper limit"))
}

/// 時間文字列（10 進整数 + `ms`・`s`・`m`・`h` の 1 個以上の連結。例 `1m30s`）を解釈する。
///
/// 空文字・符号・単位なし・未知の単位・小数・空白・オーバーフロー・長さ超過は `InvalidArgument`。
/// 小数と `us` / `ns` 単位は未対応。
pub fn parse_duration(text: &str) -> Result<Duration, TraitError> {
    if text.is_empty() {
        return Err(invalid("duration must not be empty"));
    }
    if text.len() > MAX_DURATION_TEXT_BYTES {
        return Err(invalid("duration text is too long"));
    }
    let mut rest = text;
    let mut total_ms: u64 = 0;
    while !rest.is_empty() {
        let digits_end = rest
            .char_indices()
            .find(|(_, c)| !c.is_ascii_digit())
            .map_or(rest.len(), |(i, _)| i);
        let (digits, after) = rest.split_at(digits_end);
        if digits.is_empty() {
            return Err(invalid(
                "duration must be digits followed by a unit (ms, s, m, h)",
            ));
        }
        let number: u64 = digits
            .parse()
            .map_err(|_| invalid("duration number is out of range"))?;
        // `ms` を `m` より先に判定する。
        let (unit_ms, remaining) = if let Some(r) = after.strip_prefix("ms") {
            (1u64, r)
        } else if let Some(r) = after.strip_prefix('s') {
            (1_000, r)
        } else if let Some(r) = after.strip_prefix('m') {
            (60_000, r)
        } else if let Some(r) = after.strip_prefix('h') {
            (3_600_000, r)
        } else {
            return Err(invalid(
                "duration has a missing or unknown unit (use ms, s, m, h)",
            ));
        };
        let part = number
            .checked_mul(unit_ms)
            .ok_or_else(|| invalid("duration is out of range"))?;
        total_ms = total_ms
            .checked_add(part)
            .ok_or_else(|| invalid("duration is out of range"))?;
        rest = remaining;
    }
    Ok(Duration::from_millis(total_ms))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(cmd: &[&str]) -> RawHealthcheck {
        RawHealthcheck {
            command: cmd.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        }
    }

    fn err_of(r: &RawHealthcheck) -> TraitError {
        HealthcheckDefinition::parse(r).unwrap_err()
    }

    /// SUP-4・TASK-161.1: 受理される時間文字列の具体値。
    #[test]
    fn sup4_parse_duration_accepts() {
        assert_eq!(parse_duration("30s").unwrap(), Duration::from_secs(30));
        assert_eq!(parse_duration("1m30s").unwrap(), Duration::from_secs(90));
        assert_eq!(parse_duration("500ms").unwrap(), Duration::from_millis(500));
        assert_eq!(parse_duration("2h").unwrap(), Duration::from_secs(7200));
        assert_eq!(parse_duration("0s").unwrap(), Duration::ZERO);
    }

    /// SUP-4・TASK-161.1: 拒否される時間文字列は InvalidArgument。
    #[test]
    fn sup4_parse_duration_rejects() {
        let long = format!("{}s", "1".repeat(MAX_DURATION_TEXT_BYTES));
        for case in [
            "",
            "-5s",
            "+5s",
            "30",
            "5x",
            "1.5s",
            " 5s",
            "5s ",
            "s",
            "ms",
            "5",
            "1m30",
            "99999999999999999999h",
            "18446744073709551615h",
            &long,
        ] {
            let e = parse_duration(case).unwrap_err();
            assert_eq!(e.code(), ErrorCode::InvalidArgument, "case {case:?}");
        }
    }

    /// SUP-4・TASK-161.1: 省略時は既定値の具体値になる。
    #[test]
    fn sup4_defaults() {
        let d = HealthcheckDefinition::parse(&raw(&["true"])).unwrap();
        assert_eq!(d.command(), ["true".to_string()]);
        assert_eq!(d.interval(), Duration::from_secs(30));
        assert_eq!(d.timeout(), Duration::from_secs(30));
        assert_eq!(d.start_period(), Duration::ZERO);
        assert_eq!(d.retries().get(), 3);
    }

    /// SUP-4・TASK-161.1: command の拒否条件。
    #[test]
    fn sup4_command_rejections() {
        let e = err_of(&raw(&[]));
        assert_eq!(e.code(), ErrorCode::InvalidArgument);
        assert_eq!(e.message(), "healthcheck command must not be empty");
        assert!(err_of(&raw(&[""])).message().contains("program"));
        assert!(err_of(&raw(&["a\0b"])).message().contains("NUL"));
        for kw in ["CMD-SHELL", "CMD", "NONE"] {
            assert!(err_of(&raw(&[kw, "x"])).message().contains("reserved"));
        }
        let mut many = raw(&["true"]);
        many.command.resize(MAX_COMMAND_ARGS + 1, "x".to_string());
        assert!(err_of(&many).message().contains("too many"));
        let mut ok = raw(&["true"]);
        ok.command.resize(MAX_COMMAND_ARGS, "x".to_string());
        assert!(HealthcheckDefinition::parse(&ok).is_ok());
        let big = raw(&["true", &"a".repeat(MAX_COMMAND_BYTES)]);
        assert!(err_of(&big).message().contains("too long"));
    }

    /// SUP-4・TASK-161.1: interval / timeout / start_period の境界。
    #[test]
    fn sup4_duration_fields() {
        let mut r = raw(&["true"]);
        r.interval = Some("-5s".into());
        let e = err_of(&r);
        assert_eq!(e.code(), ErrorCode::InvalidArgument);
        assert!(e.message().starts_with("interval:"));
        r.interval = Some("0s".into());
        assert!(err_of(&r).message().starts_with("interval must"));
        r.interval = Some("24h".into());
        assert_eq!(
            HealthcheckDefinition::parse(&r).unwrap().interval(),
            MAX_INTERVAL
        );
        r.interval = Some("86400001ms".into());
        assert!(err_of(&r).message().starts_with("interval must"));

        let mut r = raw(&["true"]);
        r.timeout = Some("0s".into());
        assert!(err_of(&r).message().starts_with("timeout must"));
        r.timeout = Some("1h".into());
        assert_eq!(
            HealthcheckDefinition::parse(&r).unwrap().timeout(),
            MAX_TIMEOUT
        );
        r.timeout = Some("3600001ms".into());
        assert!(err_of(&r).message().starts_with("timeout must"));
        r.timeout = Some("x".into());
        assert!(err_of(&r).message().starts_with("timeout:"));

        let mut r = raw(&["true"]);
        r.start_period = Some("0s".into());
        assert_eq!(
            HealthcheckDefinition::parse(&r).unwrap().start_period(),
            Duration::ZERO
        );
        r.start_period = Some("24h1ms".into());
        assert!(err_of(&r).message().starts_with("start_period"));
    }

    /// SUP-4・TASK-161.1: retries の境界。
    #[test]
    fn sup4_retries() {
        let mut r = raw(&["true"]);
        for bad in [-1, 0, i64::from(MAX_RETRIES) + 1, i64::MAX, i64::MIN] {
            r.retries = Some(bad);
            let e = err_of(&r);
            assert_eq!(e.code(), ErrorCode::InvalidArgument, "retries {bad}");
            assert!(e.message().starts_with("retries"));
        }
        for (ok, want) in [(1, 1), (i64::from(MAX_RETRIES), MAX_RETRIES)] {
            r.retries = Some(ok);
            assert_eq!(
                HealthcheckDefinition::parse(&r).unwrap().retries().get(),
                want
            );
        }
    }

    /// SUP-4・TASK-161.1: TryFrom 経路と検査順（command が先）。
    #[test]
    fn sup4_try_from_and_order() {
        let mut r = raw(&["pg_isready", "-q"]);
        r.interval = Some("10s".into());
        let d = HealthcheckDefinition::try_from(&r).unwrap();
        assert_eq!(d, HealthcheckDefinition::try_from(r.clone()).unwrap());
        let mut bad = raw(&[]);
        bad.interval = Some("-1s".into());
        assert!(err_of(&bad).message().contains("command"));
    }
}
