//! SIGKILL 耐性テスト（IO-3・TASK-18）の試行判定ロジック（TASK-18.1.2・#826）。
//!
//! 役割: 1 回の SIGKILL 試行で観測した事実（[`TrialObservation`]）から、その試行を損失集計に
//! 含めてよいか（有効試行）を判定し（[`classify_trial`]）、有効試行が目標数に達するまで
//! 試行を繰り返す台帳（[`TrialLedger`]・[`run_until_valid`]）を提供する。
//! ACK を観測できなかった試行や、サーバーが kill 前に終了していた試行を「無効試行」として
//! 除外するのは、spec の Linux 実機検証（`sigkill_flushack.py`・`sigkill_precise2.py`）で
//! codex P1 指摘を受けて採った方式に揃えるため（IO-3）。
//!
//! さらに #95（TASK-18.2）で、kill 後にディスク上の `data.bin` を読んだレコード列を期待値
//! （seq 0..n）と照合する純粋関数（[`check_disk_records`]）と、有効試行の損失集計
//! （[`loss_summary`]）を追加した。
//!
//! 呼び出し元: `crash_safety.rs` の `unix` モジュール（実プロセスを使う 1 試行の実行と、
//! フラッシュ済み / 未フラッシュ対照の 2 ケース）。本モジュールは OS 非依存の純粋ロジックで、
//! 3 OS でコンパイルしユニットテストを実行する。
//!
//! 境界: 損失件数を有効 / 無効の判定には使わない（[`classify_trial`] は ACK 観測と終了状態だけで
//! 決める）。損失は有効試行について後から集計する。実測結果レポートと対照としての妥当性の
//! 判断は TASK-18 の人間担当であり、ここでは扱わない（REPAIR-3）。

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
    /// kill 後のディスク照合結果（#95）。照合しない試行は `None`。[`classify_trial`] は参照しない。
    pub disk: Option<DiskObservation>,
}

/// `data.bin` の 1 レコードのバイト長（Write の body は seq の u64 LE。`drive_client` 参照）。
pub const RECORD_LEN: usize = 8;

/// ディスク上のレコード列と期待値（seq 0..expected）の照合結果（IO-3・TASK-18.2）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiskCheck {
    /// 期待した件数（ACK 目標数）。
    pub expected: u64,
    /// ディスク上にあった完全レコードの seq（ファイル順）。
    pub found: Vec<u64>,
    /// 期待集合にあるのにディスクに無かった seq（昇順）。損失件数はこの長さ。
    pub missing: Vec<u64>,
    /// 期待集合の範囲外の値、または重複して現れた seq（ファイル順）。
    pub unexpected: Vec<u64>,
    /// 末尾の `RECORD_LEN` に満たない半端なバイト数。
    pub trailing_partial_bytes: usize,
}

impl DiskCheck {
    /// 損失件数（ACK 済みなのにディスクに無い件数）。
    pub fn lost(&self) -> u64 {
        u64::try_from(self.missing.len()).unwrap_or(u64::MAX)
    }

    /// 0..expected がこの順にちょうど並び、想定外も半端バイトも無い。
    pub fn is_exact(&self) -> bool {
        self.missing.is_empty()
            && self.unexpected.is_empty()
            && self.trailing_partial_bytes == 0
            && self.found.iter().copied().eq(0..self.expected)
    }
}

/// ディスク照合の結果。読めなかった場合も試行の記録に残す（黙って損失 0 扱いにしない）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiskObservation {
    Checked(DiskCheck),
    /// 読み出しに失敗した（`io::ErrorKind` の Debug 表記のみ。パス・中身は含めない）。
    ReadFailed(String),
    /// ファイルが上限（`cap` バイト）を超えていたため読まなかった。
    /// 構築するのは UDS 対応 OS（Linux・macOS）のハーネスのみ。他 OS では未使用になる。
    #[cfg_attr(
        not(any(target_os = "linux", target_os = "macos")),
        expect(
            dead_code,
            reason = "constructed only by the UDS harness on Linux/macOS"
        )
    )]
    TooLarge {
        len: u64,
        cap: u64,
    },
}

/// `data.bin` の内容を seq 0..expected と照合する。外部入力扱いのため添字を使わない。
pub fn check_disk_records(bytes: &[u8], expected: u64) -> DiskCheck {
    let (chunks, remainder) = bytes.as_chunks::<RECORD_LEN>();
    let trailing_partial_bytes = remainder.len();
    let found: Vec<u64> = chunks.iter().map(|c| u64::from_le_bytes(*c)).collect();
    let mut seen = std::collections::BTreeSet::new();
    let mut unexpected = Vec::new();
    for &seq in &found {
        if seq >= expected || !seen.insert(seq) {
            unexpected.push(seq);
        }
    }
    let missing = (0..expected).filter(|s| !seen.contains(s)).collect();
    DiskCheck {
        expected,
        found,
        missing,
        unexpected,
        trailing_partial_bytes,
    }
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

/// 有効試行のディスク照合の集計（無効試行は含めない）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LossSummary {
    pub valid_trials: usize,
    /// 照合が成立（`Checked`）した有効試行数。
    pub checked_trials: usize,
    pub total_lost: u64,
    pub max_lost: u64,
    pub trials_with_loss: usize,
    /// 照合済みだが `is_exact` でない（想定外・半端バイト・欠落のいずれか）有効試行数。
    pub unexact_trials: usize,
}

/// 台帳の有効試行だけを対象に損失を集計する。
pub fn loss_summary(ledger: &TrialLedger) -> LossSummary {
    let mut out = LossSummary {
        valid_trials: 0,
        checked_trials: 0,
        total_lost: 0,
        max_lost: 0,
        trials_with_loss: 0,
        unexact_trials: 0,
    };
    for rec in ledger.valid_trials() {
        out.valid_trials += 1;
        if let Some(DiskObservation::Checked(check)) = &rec.observation.disk {
            let lost = check.lost();
            out.checked_trials += 1;
            out.total_lost = out.total_lost.saturating_add(lost);
            out.max_lost = out.max_lost.max(lost);
            if lost > 0 {
                out.trials_with_loss += 1;
            }
            if !check.is_exact() {
                out.unexact_trials += 1;
            }
        }
    }
    out
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
            disk: None,
        }
    }

    fn bytes_of(seqs: &[u64]) -> Vec<u8> {
        seqs.iter().flat_map(|s| s.to_le_bytes()).collect()
    }

    fn with_disk(seqs: &[u64], expected: u64) -> TrialObservation {
        let mut obs = good(expected);
        obs.ack_target = expected;
        obs.disk = Some(DiskObservation::Checked(check_disk_records(
            &bytes_of(seqs),
            expected,
        )));
        obs
    }

    /// IO-3・TASK-18.2: 0..3 がちょうど並ぶと損失 0 で is_exact。
    #[test]
    fn io3_disk_check_exact() {
        let c = check_disk_records(&bytes_of(&[0, 1, 2]), 3);
        assert_eq!(c.found, vec![0, 1, 2]);
        assert!(c.missing.is_empty() && c.unexpected.is_empty());
        assert_eq!(c.lost(), 0);
        assert!(c.is_exact());
    }

    /// IO-3・TASK-18.2: 末尾・途中の欠落は missing に出る。
    #[test]
    fn io3_disk_check_missing_tail_and_middle() {
        let tail = check_disk_records(&bytes_of(&[0, 1]), 3);
        assert_eq!(tail.missing, vec![2]);
        assert_eq!(tail.lost(), 1);
        assert!(!tail.is_exact());
        let mid = check_disk_records(&bytes_of(&[0, 2, 3]), 4);
        assert_eq!(mid.missing, vec![1]);
        assert!(mid.unexpected.is_empty());
    }

    /// IO-3・TASK-18.2: 8 バイトに満たない末尾は半端バイトとして数え、損失には数えない。
    #[test]
    fn io3_disk_check_trailing_partial_bytes() {
        let mut bytes = bytes_of(&[0, 1, 2]);
        bytes.extend_from_slice(&[9, 9, 9]);
        let c = check_disk_records(&bytes, 3);
        assert_eq!(c.trailing_partial_bytes, 3);
        assert_eq!(c.lost(), 0);
        assert!(!c.is_exact());
    }

    /// IO-3・TASK-18.2: 範囲外の値と重複は unexpected に出る。
    #[test]
    fn io3_disk_check_unexpected_and_duplicate() {
        let c = check_disk_records(&bytes_of(&[0, 1, 1, 7]), 3);
        assert_eq!(c.unexpected, vec![1, 7]);
        assert_eq!(c.missing, vec![2]);
        assert!(!c.is_exact());
    }

    /// IO-3・TASK-18.2: 空ファイルは全件が欠落になる。
    #[test]
    fn io3_disk_check_empty_file_loses_everything() {
        let c = check_disk_records(&[], 4);
        assert_eq!(c.missing, vec![0, 1, 2, 3]);
        assert_eq!(c.lost(), 4);
    }

    /// IO-3・TASK-18.2: loss_summary は無効試行を除外し、合計・最大・損失あり件数を出す。
    #[test]
    fn io3_loss_summary_counts_only_valid_trials() {
        let mut ledger = TrialLedger::new(10, 30);
        ledger.record(with_disk(&[0, 1, 2], 3)); // 損失 0
        ledger.record(with_disk(&[0], 3)); // 損失 2
        ledger.record(with_disk(&[0, 1], 3)); // 損失 1
        let mut invalid = with_disk(&[], 3);
        invalid.client_error = Some(IoErrorCode::Timeout); // 無効。損失 3 は集計しない
        ledger.record(invalid);
        let mut unread = with_disk(&[], 3);
        unread.disk = Some(DiskObservation::ReadFailed("NotFound".into()));
        ledger.record(unread);
        assert_eq!(
            loss_summary(&ledger),
            LossSummary {
                valid_trials: 4,
                checked_trials: 3,
                total_lost: 3,
                max_lost: 2,
                trials_with_loss: 2,
                unexact_trials: 2,
            }
        );
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
