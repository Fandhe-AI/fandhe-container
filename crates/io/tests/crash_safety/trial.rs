//! SIGKILL 耐性テスト（IO-3・TASK-18）の試行判定ロジック（TASK-18.1.2・#826）。
//!
//! 役割: 1 回の SIGKILL 試行で観測した事実（[`TrialObservation`]）から、その試行を損失集計に
//! 含めてよいか（有効試行）を判定し（[`classify_trial`]）、有効試行が目標数に達するまで
//! 試行を繰り返す台帳（[`TrialLedger`]・[`run_until_valid`]）を提供する。
//! ACK を観測できなかった試行や、サーバーが kill 前に終了していた試行を「無効試行」として
//! 除外するのは、spec の Linux 実機検証（`sigkill_flushack.py`・`sigkill_precise2.py`）で
//! codex P1 指摘を受けて採った方式に揃えるため（IO-3）。
//!
//! 呼び出し元: `crash_safety.rs` の `unix` モジュール（実プロセスを使う 1 試行の実行）と、
//! 後続 issue #95（TASK-18.2）の対照ケース。本モジュールは OS 非依存の純粋ロジックで、
//! 3 OS でコンパイルしユニットテストを実行する。
//!
//! 境界: 損失件数の計測（ディスク上のレコード照合）・「有効 10/10 で損失 0」のアサーション・
//! 未フラッシュ対照ケースは #95 の範囲であり、ここでは扱わない（REPAIR-3）。
//! [`TrialRecord`] は #95 が損失件数などのフィールドを足せる構造体として置く。

use fandhe_container_io::IoErrorCode;

/// 損失集計に必要な有効試行数の目標（IO-3: 最低 10 回）。
pub const TARGET_VALID_TRIALS: usize = 10;
/// 試行回数の上限（目標の 3 倍。無限ループを避ける。REPAIR-5）。
pub const MAX_ATTEMPTS: usize = TARGET_VALID_TRIALS * 3;
/// SIGKILL のシグナル番号（Linux / macOS 共通）。
pub const SIGKILL: i32 = 9;

/// 子プロセスの終了状態。`ExitStatus` はテストから構築できないため、値として持つ。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerExit {
    pub code: Option<i32>,
    pub signal: Option<i32>,
}

/// 1 試行で観測した事実。判定は [`classify_trial`] が行う。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrialObservation {
    /// kill 前に観測した通常 ACK（Write ACK）の数。
    pub acks_observed: u64,
    /// kill 前に観測したかった通常 ACK の数。
    pub ack_target: u64,
    /// FLUSH ACK の観測が必要な試行か。
    pub flush_ack_required: bool,
    /// FLUSH ACK を観測したか。
    pub flush_ack_observed: bool,
    /// kill 直前の `try_wait` で既に終了していたサーバーの状態。
    pub server_exited_before_kill: Option<ServerExit>,
    /// 送受信で起きたクライアント側の失敗。
    pub client_error: Option<IoErrorCode>,
    /// kill 後に回収した最終状態。期限内に回収できなければ `None`。
    pub final_exit: Option<ServerExit>,
}

/// 無効試行の理由（機械可読）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvalidReason {
    /// kill 前にサーバーが終了していた。
    ServerExitedEarly(ServerExit),
    /// クライアントの送受信が失敗した。
    ClientFailed(IoErrorCode),
    /// 通常 ACK が目標数に届かなかった。
    AckTimeout { observed: u64, target: u64 },
    /// FLUSH ACK が必要なのに観測できなかった。
    FlushAckMissing,
    /// 最終状態が SIGKILL による終了ではなかった。
    NotKilledBySigkill(Option<ServerExit>),
}

/// 試行の判定結果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrialVerdict {
    Valid { acks_observed: u64 },
    Invalid(InvalidReason),
}

/// 観測値から有効 / 無効を判定する。優先順位は PoC に揃える
/// （サーバー早期終了 > クライアント失敗 > ACK 未達 > FLUSH ACK 未観測）。
/// 最後に、SIGKILL で終了したことを確認する（PoC にない追加条件）。
pub fn classify_trial(obs: &TrialObservation) -> TrialVerdict {
    if let Some(exit) = obs.server_exited_before_kill {
        return TrialVerdict::Invalid(InvalidReason::ServerExitedEarly(exit));
    }
    if let Some(code) = obs.client_error {
        return TrialVerdict::Invalid(InvalidReason::ClientFailed(code));
    }
    if obs.acks_observed < obs.ack_target {
        return TrialVerdict::Invalid(InvalidReason::AckTimeout {
            observed: obs.acks_observed,
            target: obs.ack_target,
        });
    }
    if obs.flush_ack_required && !obs.flush_ack_observed {
        return TrialVerdict::Invalid(InvalidReason::FlushAckMissing);
    }
    match obs.final_exit {
        Some(exit) if exit.signal == Some(SIGKILL) => TrialVerdict::Valid {
            acks_observed: obs.acks_observed,
        },
        other => TrialVerdict::Invalid(InvalidReason::NotKilledBySigkill(other)),
    }
}

/// 台帳に残す 1 試行の記録。#95 が損失件数などのフィールドを足す拡張点。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrialRecord {
    pub index: usize,
    pub observation: TrialObservation,
    pub verdict: TrialVerdict,
}

/// 台帳の集計。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrialSummary {
    pub attempts: usize,
    pub valid: usize,
    pub invalid: usize,
    /// 有効試行が目標に届かないまま試行上限に達した。
    pub aborted: bool,
}

/// 有効試行を集める台帳。無効試行は `valid_trials` に入らず、損失集計から除外される。
#[derive(Debug)]
pub struct TrialLedger {
    target_valid: usize,
    max_attempts: usize,
    records: Vec<TrialRecord>,
}

impl TrialLedger {
    pub fn new(target_valid: usize, max_attempts: usize) -> Self {
        Self {
            target_valid,
            max_attempts,
            records: Vec::new(),
        }
    }

    /// 観測値を判定して記録し、その記録への参照を返す。
    pub fn record(&mut self, observation: TrialObservation) -> &TrialRecord {
        let verdict = classify_trial(&observation);
        let index = self.records.len();
        self.records.push(TrialRecord {
            index,
            observation,
            verdict,
        });
        &self.records[index]
    }

    fn valid_count(&self) -> usize {
        self.valid_trials().count()
    }

    pub fn is_complete(&self) -> bool {
        self.valid_count() >= self.target_valid
    }

    pub fn is_exhausted(&self) -> bool {
        self.records.len() >= self.max_attempts
    }

    pub fn should_continue(&self) -> bool {
        !self.is_complete() && !self.is_exhausted()
    }

    pub fn valid_trials(&self) -> impl Iterator<Item = &TrialRecord> {
        self.records
            .iter()
            .filter(|r| matches!(r.verdict, TrialVerdict::Valid { .. }))
    }

    pub fn invalid_trials(&self) -> impl Iterator<Item = &TrialRecord> {
        self.records
            .iter()
            .filter(|r| matches!(r.verdict, TrialVerdict::Invalid(_)))
    }

    pub fn summary(&self) -> TrialSummary {
        let valid = self.valid_count();
        TrialSummary {
            attempts: self.records.len(),
            valid,
            invalid: self.records.len().saturating_sub(valid),
            aborted: !self.is_complete() && self.is_exhausted(),
        }
    }
}

/// 有効試行が目標数に達するか試行上限に達するまで `run_one` を繰り返す。
/// `run_one` には 0 始まりの試行番号を渡す。上限に達したら必ず抜ける（REPAIR-5）。
pub fn run_until_valid<F>(ledger: &mut TrialLedger, mut run_one: F) -> TrialSummary
where
    F: FnMut(usize) -> TrialObservation,
{
    while ledger.should_continue() {
        let index = ledger.records.len();
        let observation = run_one(index);
        ledger.record(observation);
    }
    ledger.summary()
}

#[cfg(test)]
mod tests {
    use super::*;

    const KILLED: ServerExit = ServerExit {
        code: None,
        signal: Some(SIGKILL),
    };

    fn good(acks: u64) -> TrialObservation {
        TrialObservation {
            acks_observed: acks,
            ack_target: 30,
            flush_ack_required: false,
            flush_ack_observed: false,
            server_exited_before_kill: None,
            client_error: None,
            final_exit: Some(KILLED),
        }
    }

    fn bad() -> TrialObservation {
        good(29)
    }

    /// IO-3・TASK-18.1.2: 全条件を満たす試行は有効で、ACK 観測数が記録される。
    #[test]
    fn io3_classify_valid_trial_reports_ack_count() {
        assert_eq!(
            classify_trial(&good(30)),
            TrialVerdict::Valid { acks_observed: 30 }
        );
    }

    /// IO-3・TASK-18.1.2: ACK が目標未満なら無効（AckTimeout）。
    #[test]
    fn io3_classify_ack_shortfall_is_invalid() {
        assert_eq!(
            classify_trial(&good(29)),
            TrialVerdict::Invalid(InvalidReason::AckTimeout {
                observed: 29,
                target: 30
            })
        );
    }

    /// IO-3・TASK-18.1.2: FLUSH ACK が必要なのに未観測なら無効。観測済みなら有効。
    #[test]
    fn io3_classify_flush_ack_requirement() {
        let mut obs = good(30);
        obs.flush_ack_required = true;
        assert_eq!(
            classify_trial(&obs),
            TrialVerdict::Invalid(InvalidReason::FlushAckMissing)
        );
        obs.flush_ack_observed = true;
        assert_eq!(
            classify_trial(&obs),
            TrialVerdict::Valid { acks_observed: 30 }
        );
    }

    /// IO-3・TASK-18.1.2: サーバー早期終了はクライアント失敗・ACK 未達より優先される。
    #[test]
    fn io3_classify_server_exit_has_top_priority() {
        let exit = ServerExit {
            code: Some(4),
            signal: None,
        };
        let mut obs = bad();
        obs.server_exited_before_kill = Some(exit);
        obs.client_error = Some(IoErrorCode::Unavailable);
        assert_eq!(
            classify_trial(&obs),
            TrialVerdict::Invalid(InvalidReason::ServerExitedEarly(exit))
        );
    }

    /// IO-3・TASK-18.1.2: クライアント失敗は ACK 未達より優先される。
    #[test]
    fn io3_classify_client_failure_beats_ack_shortfall() {
        let mut obs = bad();
        obs.client_error = Some(IoErrorCode::Timeout);
        assert_eq!(
            classify_trial(&obs),
            TrialVerdict::Invalid(InvalidReason::ClientFailed(IoErrorCode::Timeout))
        );
    }

    /// IO-3・TASK-18.1.2: 最終状態が SIGKILL でない（自然終了・回収失敗）試行は無効。
    #[test]
    fn io3_classify_not_killed_by_sigkill_is_invalid() {
        let exited = ServerExit {
            code: Some(0),
            signal: None,
        };
        let mut obs = good(30);
        obs.final_exit = Some(exited);
        assert_eq!(
            classify_trial(&obs),
            TrialVerdict::Invalid(InvalidReason::NotKilledBySigkill(Some(exited)))
        );
        obs.final_exit = None;
        assert_eq!(
            classify_trial(&obs),
            TrialVerdict::Invalid(InvalidReason::NotKilledBySigkill(None))
        );
    }

    /// IO-3・TASK-18.1.2: 既定の目標は有効 10 回・試行上限 30 回。
    #[test]
    fn io3_default_targets_are_10_valid_and_30_attempts() {
        assert_eq!(TARGET_VALID_TRIALS, 10);
        assert_eq!(MAX_ATTEMPTS, 30);
    }

    /// IO-3・TASK-18.1.2: 有効 10 件で打ち切り、無効試行は有効集合から除外される。
    #[test]
    fn io3_ledger_excludes_invalid_and_stops_at_target() {
        let mut ledger = TrialLedger::new(TARGET_VALID_TRIALS, MAX_ATTEMPTS);
        for _ in 0..3 {
            ledger.record(bad());
        }
        assert!(ledger.should_continue());
        for _ in 0..10 {
            ledger.record(good(30));
        }
        assert!(!ledger.should_continue());
        assert!(ledger.is_complete());
        assert!(!ledger.is_exhausted());
        assert_eq!(
            ledger.summary(),
            TrialSummary {
                attempts: 13,
                valid: 10,
                invalid: 3,
                aborted: false
            }
        );
        assert_eq!(ledger.valid_trials().count(), 10);
        assert!(
            ledger
                .valid_trials()
                .all(|r| matches!(r.verdict, TrialVerdict::Valid { acks_observed: 30 }))
        );
        let invalid: Vec<usize> = ledger.invalid_trials().map(|r| r.index).collect();
        assert_eq!(invalid, vec![0, 1, 2]);
        assert_eq!(
            ledger
                .invalid_trials()
                .next()
                .map(|r| r.observation.acks_observed),
            Some(29)
        );
    }

    /// IO-3・TASK-18.1.2: 全試行が無効なら上限 30 回で打ち切り、aborted になる。
    #[test]
    fn io3_run_until_valid_aborts_at_max_attempts() {
        let mut ledger = TrialLedger::new(TARGET_VALID_TRIALS, MAX_ATTEMPTS);
        let mut calls = Vec::new();
        let summary = run_until_valid(&mut ledger, |i| {
            calls.push(i);
            bad()
        });
        assert_eq!(calls.len(), 30);
        assert_eq!(calls.first(), Some(&0));
        assert_eq!(calls.last(), Some(&29));
        assert_eq!(
            summary,
            TrialSummary {
                attempts: 30,
                valid: 0,
                invalid: 30,
                aborted: true
            }
        );
    }

    /// IO-3・TASK-18.1.2: 有効試行が目標に届いた時点で試行を止める（無効混在）。
    #[test]
    fn io3_run_until_valid_stops_when_target_reached() {
        let mut ledger = TrialLedger::new(2, 6);
        // 偶数番号を無効、奇数番号を有効にする
        let summary = run_until_valid(&mut ledger, |i| if i % 2 == 0 { bad() } else { good(30) });
        assert_eq!(
            summary,
            TrialSummary {
                attempts: 4,
                valid: 2,
                invalid: 2,
                aborted: false
            }
        );
    }
}
