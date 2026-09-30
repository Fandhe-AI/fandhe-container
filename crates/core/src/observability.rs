//! 観測性（メトリクス）の集計型（REPAIR-4・TASK-84.1）。
//!
//! read / write / create / start 等の各操作について、成功・失敗カウントとレイテンシ分布
//! （min・mean・p95・max。PoC-8 の `op_stats` 相当）を表す固定スキーマの値型だけを定義する。
//! 後続の記録・出力・計装はこの型の上に積まれる。「壊れた値を表現できない型」（REPAIR-2）とし、
//! 生成は検証つきコンストラクタのみ、フィールドは private にして構築後の矛盾を防ぐ。
//! エラーは拡張点トレイトと共通の [`TraitError`]（`ErrorCode::InvalidArgument`。ERR-1）。
//!
//! # 記録 API（TASK-84.2）
//!
//! [`OpRecorder`] が操作の開始・終了を計測し、成功 / 失敗とレイテンシをスレッドセーフに集計する。
//! 確定した判断は次のとおり。
//!
//! - p95 は nearest-rank（ソートして添字 `ceil(0.95 * n) - 1`。PoC-8 と同じ）で、対象は直近
//!   [`LATENCY_WINDOW_CAP`] 件のウィンドウに限る（長寿命の supervisor でメモリを増やさないため）。
//!   min・mean・max は記録した全サンプルの厳密値
//! - 成功・失敗の両方のレイテンシを集計に含める（レイテンシのサンプル数は常に成功 + 失敗と一致）
//! - 操作名の種類数は [`MAX_TRACKED_OPS`] まで。件数が `u64` に達した後の記録は捨てて
//!   [`OpRecorder::dropped_records`] に数える
//! - 集計は `Mutex` 1 個で保護し、poison は回復する（ロック内で panic しうる処理を置かないため状態は整合する）
//!
//! # 未実装範囲（REPAIR-3）
//!
//! 以下は未実装である。
//!
//! - 構造化ログ / JSON Lines での出力: TASK-84.3
//! - create / start / kill / delete への計装: TASK-84.4
//! - io の read / write 向け連携点と io 側の計装: TASK-84.5・TASK-84.7
//! - 結合テスト: TASK-84.6

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use crate::traits::{ErrorCode, TraitError};

/// 操作名の許容バイト数の上限。ログのフィールドとして出すため短く抑える。
pub const OP_NAME_MAX_LEN: usize = 64;

/// レイテンシのウィンドウ長（p95 の算出対象とする直近サンプル数の上限）。
pub const LATENCY_WINDOW_CAP: usize = 1024;

/// [`OpRecorder`] が追跡する操作名の種類数の上限（名前の動的生成による無制限確保の防止）。
pub const MAX_TRACKED_OPS: usize = 64;

/// 検証済みの操作名（`read`・`write`・`create`・`start` 等）。
///
/// TASK-84.3 で JSON Lines のキー / 値として出力するため、`[A-Za-z0-9._-]` かつ
/// [`OP_NAME_MAX_LEN`] バイト以下に限り、改行・引用符・制御文字によるログ行の偽装や分割を
/// 型の段階で防ぐ。閉じた enum にしないのは、TASK-84.5 で io 側の操作名を core に依存せず
/// 渡す方式が未決定のため。資格情報やホスト側の実パスをログのフィールドになる操作名に入れない。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OpName(String);

impl OpName {
    /// 入力文字列を検証して操作名を作る。
    ///
    /// 空文字列・上限長超過・`[A-Za-z0-9._-]` 以外の文字を含む場合は
    /// `ErrorCode::InvalidArgument` を返す。
    pub fn new(value: impl Into<String>) -> Result<Self, TraitError> {
        let value = value.into();
        if value.is_empty() {
            return Err(TraitError::new(
                ErrorCode::InvalidArgument,
                "operation name must not be empty",
            ));
        }
        if value.len() > OP_NAME_MAX_LEN {
            return Err(TraitError::new(
                ErrorCode::InvalidArgument,
                format!("operation name must be at most {OP_NAME_MAX_LEN} bytes"),
            ));
        }
        if !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        {
            return Err(TraitError::new(
                ErrorCode::InvalidArgument,
                "operation name must match [A-Za-z0-9._-]",
            ));
        }
        Ok(Self(value))
    }

    /// 検証済み文字列への参照を返す。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for OpName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<&str> for OpName {
    type Error = TraitError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl TryFrom<String> for OpName {
    type Error = TraitError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

/// レイテンシ分布の要約（min・mean・p95・max。REPAIR-4）。
///
/// `Duration` のため負値は表現できず、`min <= mean <= max` かつ `min <= p95 <= max` を
/// 構築時に保証する。p95 は 95 パーセンタイルの推定値で、[`OpRecorder`] は直近
/// [`LATENCY_WINDOW_CAP`] 件に対する nearest-rank で算出する（TASK-84.2）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LatencySummary {
    min: Duration,
    mean: Duration,
    p95: Duration,
    max: Duration,
}

impl LatencySummary {
    /// 4 値の順序関係を検証して要約を作る。
    ///
    /// `min > max`、または `mean`・`p95` が `[min, max]` の外にある場合は
    /// `ErrorCode::InvalidArgument` を返す。
    pub fn new(
        min: Duration,
        mean: Duration,
        p95: Duration,
        max: Duration,
    ) -> Result<Self, TraitError> {
        if min > max {
            return Err(TraitError::new(
                ErrorCode::InvalidArgument,
                "latency min must not exceed max",
            ));
        }
        if mean < min || mean > max {
            return Err(TraitError::new(
                ErrorCode::InvalidArgument,
                "latency mean must be within [min, max]",
            ));
        }
        if p95 < min || p95 > max {
            return Err(TraitError::new(
                ErrorCode::InvalidArgument,
                "latency p95 must be within [min, max]",
            ));
        }
        Ok(Self {
            min,
            mean,
            p95,
            max,
        })
    }

    /// 最小レイテンシ。
    pub fn min(&self) -> Duration {
        self.min
    }

    /// 平均レイテンシ。
    pub fn mean(&self) -> Duration {
        self.mean
    }

    /// 95 パーセンタイルの推定値。
    pub fn p95(&self) -> Duration {
        self.p95
    }

    /// 最大レイテンシ。
    pub fn max(&self) -> Duration {
        self.max
    }
}

/// 操作 1 種類分の集計スナップショット（REPAIR-4・PoC-8 の `op_stats` 相当）。
///
/// 成功数・失敗数の合計が `u64` に収まること、および 0 件なのにレイテンシがある矛盾が
/// ないことを構築時に保証する。件数 1 以上でレイテンシを必須にはしない
/// （型としての緩さ。[`OpRecorder`] は成功・失敗の両方をレイテンシに含めるため、1 件以上なら常に `Some`。TASK-84.2）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpStats {
    name: OpName,
    success: u64,
    failure: u64,
    latency: Option<LatencySummary>,
}

impl OpStats {
    /// 集計スナップショットを作る。
    ///
    /// `success + failure` が `u64` を超える場合、または 0 件なのに `latency` が
    /// `Some` の場合は `ErrorCode::InvalidArgument` を返す。
    pub fn new(
        name: OpName,
        success: u64,
        failure: u64,
        latency: Option<LatencySummary>,
    ) -> Result<Self, TraitError> {
        let Some(total) = success.checked_add(failure) else {
            return Err(TraitError::new(
                ErrorCode::InvalidArgument,
                "total operation count must fit in u64",
            ));
        };
        if total == 0 && latency.is_some() {
            return Err(TraitError::new(
                ErrorCode::InvalidArgument,
                "latency must be absent when no operations were recorded",
            ));
        }
        Ok(Self {
            name,
            success,
            failure,
            latency,
        })
    }

    /// 操作名。
    pub fn name(&self) -> &OpName {
        &self.name
    }

    /// 成功件数。
    pub fn success(&self) -> u64 {
        self.success
    }

    /// 失敗件数。
    pub fn failure(&self) -> u64 {
        self.failure
    }

    /// レイテンシ分布の要約（未計測なら `None`）。
    pub fn latency(&self) -> Option<&LatencySummary> {
        self.latency.as_ref()
    }

    /// 成功と失敗の合計件数（構築時に桁あふれしないことを保証済み）。
    pub fn total(&self) -> u64 {
        self.success.saturating_add(self.failure)
    }
}

/// 操作の結果（成功 / 失敗）。真偽値でなく enum にして将来の分類追加に備える。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpOutcome {
    /// 成功。
    Success,
    /// 失敗。
    Failure,
}

impl OpOutcome {
    /// `Result` の `Ok` を成功、`Err` を失敗に対応づける。
    pub fn from_result<T, E>(result: &Result<T, E>) -> Self {
        if result.is_ok() {
            Self::Success
        } else {
            Self::Failure
        }
    }
}

/// 操作 1 種類分の可変アキュムレータ（`OpRecorder` の内部専用）。
#[derive(Debug)]
struct OpAccumulator {
    success: u64,
    failure: u64,
    min: Duration,
    max: Duration,
    sum_nanos: u128,
    window: VecDeque<Duration>,
}

impl OpAccumulator {
    fn new() -> Self {
        Self {
            success: 0,
            failure: 0,
            min: Duration::ZERO,
            max: Duration::ZERO,
            sum_nanos: 0,
            window: VecDeque::new(),
        }
    }

    /// 1 サンプルを反映する。件数が `u64` に収まらなくなる場合は何も変えず `false` を返す。
    fn record_sample(&mut self, outcome: OpOutcome, latency: Duration) -> bool {
        let Some(total) = self.success.checked_add(self.failure) else {
            return false;
        };
        if total.checked_add(1).is_none() {
            return false;
        }
        if total == 0 {
            self.min = latency;
            self.max = latency;
        } else {
            self.min = self.min.min(latency);
            self.max = self.max.max(latency);
        }
        match outcome {
            OpOutcome::Success => self.success += 1,
            OpOutcome::Failure => self.failure += 1,
        }
        self.sum_nanos = self.sum_nanos.saturating_add(latency.as_nanos());
        if self.window.len() >= LATENCY_WINDOW_CAP {
            self.window.pop_front();
        }
        self.window.push_back(latency);
        true
    }

    /// ロック内で取り出す複製（ソート等の重い処理をロック外で行うため）。
    fn copy_out(&self, name: OpName) -> AccSnapshot {
        AccSnapshot {
            name,
            success: self.success,
            failure: self.failure,
            min: self.min,
            max: self.max,
            sum_nanos: self.sum_nanos,
            window: self.window.iter().copied().collect(),
        }
    }
}

/// ロック内から取り出した 1 操作分の複製。
struct AccSnapshot {
    name: OpName,
    success: u64,
    failure: u64,
    min: Duration,
    max: Duration,
    sum_nanos: u128,
    window: Vec<Duration>,
}

const NANOS_PER_SEC: u128 = 1_000_000_000;

/// `u128` のナノ秒を `Duration` へ戻す（秒が `u64` を超えたら `Duration::MAX` に飽和）。
fn duration_from_nanos_saturating(nanos: u128) -> Duration {
    let Ok(secs) = u64::try_from(nanos / NANOS_PER_SEC) else {
        return Duration::MAX;
    };
    let sub = u32::try_from(nanos % NANOS_PER_SEC).unwrap_or(0);
    Duration::new(secs, sub)
}

/// nearest-rank の p95（ソート済みの `sorted` に対し添字 `ceil(0.95 * n) - 1`）。
fn nearest_rank_p95(sorted: &[Duration]) -> Option<Duration> {
    let rank = sorted.len().saturating_mul(95).div_ceil(100);
    sorted.get(rank.saturating_sub(1)).copied()
}

impl AccSnapshot {
    /// 検証済みの不変条件から `OpStats` を組み立てる。要約が作れない場合は `latency: None` に退避する（panic しない）。
    fn into_stats(mut self) -> Option<OpStats> {
        let total = self.success.checked_add(self.failure)?;
        let latency = if total == 0 {
            None
        } else {
            self.window.sort_unstable();
            let mean_nanos = self.sum_nanos / u128::from(total);
            let mean = duration_from_nanos_saturating(mean_nanos).clamp(self.min, self.max);
            nearest_rank_p95(&self.window)
                .and_then(|p95| LatencySummary::new(self.min, mean, p95, self.max).ok())
        };
        OpStats::new(self.name, self.success, self.failure, latency).ok()
    }
}

#[derive(Debug, Default)]
struct RecorderState {
    ops: HashMap<OpName, OpAccumulator>,
    dropped: u64,
}

/// 操作の成功 / 失敗とレイテンシをスレッドセーフに集計する記録器（REPAIR-4・TASK-84.2）。
///
/// supervisor・core のライフサイクル操作や io の read / write の計装が、`Arc<OpRecorder>` で
/// 共有して呼ぶ想定（保持場所は TASK-84.4・84.5 で決める。グローバル static は置かない）。
/// 集計全体を `Mutex` 1 個で保護し、ロック保持は O(1)（ソートはロック外）。ユーザーのクロージャは
/// ロック外で実行するため再入してもデッドロックしない。計測の失敗は呼び出し元の操作の結果に
/// 影響させず、記録できなかった件数は [`OpRecorder::dropped_records`] で見える。
/// 操作名に資格情報やホストの実パスを含めないこと。
///
/// # ガード型
///
/// ```
/// use fandhe_container_core::observability::{OpName, OpRecorder};
/// use fandhe_container_core::traits::TraitError;
///
/// fn read_something(recorder: &OpRecorder, name: &OpName, fail: bool) -> Result<(), ()> {
///     let guard = recorder.start(name.clone());
///     if fail {
///         // `?` や早期 return でガードが Drop されると失敗として記録される。
///         return Err(());
///     }
///     guard.success();
///     Ok(())
/// }
///
/// let recorder = OpRecorder::new();
/// let read = OpName::new("read")?;
/// assert!(read_something(&recorder, &read, false).is_ok());
/// assert!(read_something(&recorder, &read, true).is_err());
/// let stats = recorder.snapshot_op(&read).expect("recorded");
/// assert_eq!((stats.success(), stats.failure()), (1, 1));
/// # Ok::<(), TraitError>(())
/// ```
///
/// # クロージャ渡し
///
/// ```
/// use fandhe_container_core::observability::{OpName, OpRecorder};
/// use fandhe_container_core::traits::TraitError;
///
/// let recorder = OpRecorder::new();
/// let write = OpName::new("write")?;
/// let ok: Result<u32, String> = recorder.record_op(&write, || Ok(7));
/// let ng: Result<u32, String> = recorder.record_op(&write, || Err("boom".to_string()));
/// assert_eq!(ok, Ok(7));
/// assert_eq!(ng, Err("boom".to_string()));
/// let stats = recorder.snapshot_op(&write).expect("recorded");
/// assert_eq!((stats.success(), stats.failure()), (1, 1));
/// # Ok::<(), TraitError>(())
/// ```
#[derive(Debug, Default)]
pub struct OpRecorder {
    state: Mutex<RecorderState>,
}

impl OpRecorder {
    /// 空の記録器を作る。
    pub fn new() -> Self {
        Self::default()
    }

    /// poison から回復してロックを取る。ロック内では算術（checked / saturating）と
    /// 確保済みバッファへの push しか行わず、途中で panic しても状態は整合したまま残る。
    fn lock(&self) -> MutexGuard<'_, RecorderState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// 1 件の結果とレイテンシを記録する（低レベル API。通常は [`Self::start`] か [`Self::record_op`] を使う）。
    ///
    /// 操作名の種類数が [`MAX_TRACKED_OPS`] に達している状態で新しい名前を渡した場合、または
    /// その名前の件数が `u64` に達している場合は記録せず `dropped_records` に加算し、
    /// `ErrorCode::FailedPrecondition` を返す。
    pub fn record(
        &self,
        name: &OpName,
        outcome: OpOutcome,
        latency: Duration,
    ) -> Result<(), TraitError> {
        let mut state = self.lock();
        if !state.ops.contains_key(name) {
            if state.ops.len() >= MAX_TRACKED_OPS {
                state.dropped = state.dropped.saturating_add(1);
                return Err(TraitError::new(
                    ErrorCode::FailedPrecondition,
                    "operation name limit reached",
                ));
            }
            state.ops.insert(name.clone(), OpAccumulator::new());
        }
        let recorded = state
            .ops
            .get_mut(name)
            .is_some_and(|acc| acc.record_sample(outcome, latency));
        if recorded {
            Ok(())
        } else {
            state.dropped = state.dropped.saturating_add(1);
            Err(TraitError::new(
                ErrorCode::FailedPrecondition,
                "operation counter saturated",
            ))
        }
    }

    /// 計測を開始してガードを返す。`success` / `failure` / `finish` で結果を確定し、
    /// 未確定のまま Drop されたら失敗として記録する。
    pub fn start(&self, name: OpName) -> OpGuard<'_> {
        OpGuard {
            recorder: self,
            name: Some(name),
            started: Instant::now(),
        }
    }

    /// クロージャを実行して所要時間を記録する。`Ok` は成功、`Err` は失敗として数え、
    /// 戻り値はそのまま返す。クロージャはロック外で実行される。
    ///
    /// クロージャが panic して巻き戻った場合も、実行前に作った [`OpGuard`] が Drop で
    /// 失敗とレイテンシを記録する（REPAIR-4。失敗件数から漏れない）。
    pub fn record_op<T, E>(&self, name: &OpName, f: impl FnOnce() -> Result<T, E>) -> Result<T, E> {
        let guard = self.start(name.clone());
        let result = f();
        guard.finish_with(&result);
        result
    }

    /// 全操作の集計スナップショットを名前の昇順で返す。
    pub fn snapshot(&self) -> Vec<OpStats> {
        let mut copies: Vec<AccSnapshot> = {
            let state = self.lock();
            state
                .ops
                .iter()
                .map(|(name, acc)| acc.copy_out(name.clone()))
                .collect()
        };
        copies.sort_by(|a, b| a.name.as_str().cmp(b.name.as_str()));
        copies
            .into_iter()
            .filter_map(AccSnapshot::into_stats)
            .collect()
    }

    /// 指定した操作の集計スナップショットを返す（未記録なら `None`）。
    pub fn snapshot_op(&self, name: &OpName) -> Option<OpStats> {
        let copy = self.lock().ops.get(name)?.copy_out(name.clone());
        copy.into_stats()
    }

    /// 上限超過などで記録できなかった件数。
    pub fn dropped_records(&self) -> u64 {
        self.lock().dropped
    }
}

/// 計測中の操作を表すガード（[`OpRecorder::start`] が返す）。
///
/// `?` による早期 return や panic の巻き戻しでも失敗として記録される（fail-closed）。
#[must_use = "dropping an OpGuard without finishing records a failure"]
#[derive(Debug)]
pub struct OpGuard<'a> {
    recorder: &'a OpRecorder,
    name: Option<OpName>,
    started: Instant,
}

impl OpGuard<'_> {
    /// 成功として確定する。
    pub fn success(self) {
        self.finish(OpOutcome::Success);
    }

    /// 失敗として確定する。
    pub fn failure(self) {
        self.finish(OpOutcome::Failure);
    }

    /// `outcome` で確定する。
    pub fn finish(mut self, outcome: OpOutcome) {
        self.commit(outcome);
    }

    /// `Result` の `Ok` / `Err` に応じて確定する。
    pub fn finish_with<T, E>(self, result: &Result<T, E>) {
        self.finish(OpOutcome::from_result(result));
    }

    fn commit(&mut self, outcome: OpOutcome) {
        if let Some(name) = self.name.take() {
            // 計測の失敗で本来の操作の結果を変えない。落とした件数は dropped_records に残る。
            let _ = self.recorder.record(&name, outcome, self.started.elapsed());
        }
    }
}

impl Drop for OpGuard<'_> {
    fn drop(&mut self) {
        self.commit(OpOutcome::Failure);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ms(v: u64) -> Duration {
        Duration::from_millis(v)
    }

    fn code<T: fmt::Debug>(r: Result<T, TraitError>) -> ErrorCode {
        r.expect_err("must be rejected").code()
    }

    #[test]
    fn repair4_op_name_accepts_valid() {
        assert_eq!(OpName::new("create").unwrap().as_str(), "create");
        assert_eq!(OpName::new("a.b_c-1").unwrap().to_string(), "a.b_c-1");
        assert!(OpName::new("a".repeat(OP_NAME_MAX_LEN)).is_ok());
    }

    #[test]
    fn repair4_op_name_rejects_invalid() {
        let cases = [
            String::new(),
            "a".repeat(OP_NAME_MAX_LEN + 1),
            "a/b".to_string(),
            "a b".to_string(),
            "作成".to_string(),
            "\n".to_string(),
        ];
        for c in cases {
            assert_eq!(code(OpName::new(c)), ErrorCode::InvalidArgument);
        }
    }

    #[test]
    fn repair4_latency_accepts_ordered_values() {
        let l = LatencySummary::new(ms(1), ms(3), ms(5), ms(6)).unwrap();
        assert_eq!(
            (l.min(), l.mean(), l.p95(), l.max()),
            (ms(1), ms(3), ms(5), ms(6))
        );
        assert!(LatencySummary::new(ms(2), ms(2), ms(2), ms(2)).is_ok());
    }

    #[test]
    fn repair4_latency_rejects_min_above_max() {
        assert_eq!(
            code(LatencySummary::new(ms(7), ms(7), ms(7), ms(6))),
            ErrorCode::InvalidArgument
        );
    }

    #[test]
    fn repair4_latency_rejects_mean_below_min() {
        assert_eq!(
            code(LatencySummary::new(ms(2), ms(1), ms(3), ms(6))),
            ErrorCode::InvalidArgument
        );
    }

    #[test]
    fn repair4_latency_rejects_mean_above_max() {
        assert_eq!(
            code(LatencySummary::new(ms(1), ms(7), ms(3), ms(6))),
            ErrorCode::InvalidArgument
        );
    }

    #[test]
    fn repair4_latency_rejects_p95_below_min() {
        assert_eq!(
            code(LatencySummary::new(ms(2), ms(3), ms(1), ms(6))),
            ErrorCode::InvalidArgument
        );
    }

    #[test]
    fn repair4_latency_rejects_p95_above_max() {
        assert_eq!(
            code(LatencySummary::new(ms(1), ms(3), ms(7), ms(6))),
            ErrorCode::InvalidArgument
        );
    }

    fn name() -> OpName {
        OpName::new("read").unwrap()
    }

    #[test]
    fn repair4_op_stats_total_and_accessors() {
        let l = LatencySummary::new(ms(1), ms(3), ms(5), ms(6)).unwrap();
        let s = OpStats::new(name(), 3, 2, Some(l)).unwrap();
        assert_eq!(s.name().as_str(), "read");
        assert_eq!((s.success(), s.failure(), s.total()), (3, 2, 5));
        assert_eq!(s.latency(), Some(&l));
    }

    #[test]
    fn repair4_op_stats_rejects_count_overflow() {
        assert_eq!(
            code(OpStats::new(name(), u64::MAX, 1, None)),
            ErrorCode::InvalidArgument
        );
    }

    #[test]
    fn repair4_op_stats_rejects_latency_without_operations() {
        let l = LatencySummary::new(ms(1), ms(1), ms(1), ms(1)).unwrap();
        assert_eq!(
            code(OpStats::new(name(), 0, 0, Some(l))),
            ErrorCode::InvalidArgument
        );
    }

    #[test]
    fn repair4_op_stats_accepts_boundaries() {
        assert_eq!(OpStats::new(name(), 0, 0, None).unwrap().total(), 0);
        assert_eq!(OpStats::new(name(), 5, 0, None).unwrap().total(), 5);
        assert_eq!(
            OpStats::new(name(), u64::MAX, 0, None).unwrap().total(),
            u64::MAX
        );
    }

    use std::sync::Arc;

    fn nm(v: &str) -> OpName {
        OpName::new(v).unwrap()
    }

    #[test]
    fn repair4_recorder_counts_success_and_failure() {
        let r = OpRecorder::new();
        let n = nm("read");
        for _ in 0..3 {
            r.record(&n, OpOutcome::Success, ms(1)).unwrap();
        }
        for _ in 0..2 {
            r.record(&n, OpOutcome::Failure, ms(1)).unwrap();
        }
        let s = r.snapshot_op(&n).unwrap();
        assert_eq!((s.success(), s.failure(), s.total()), (3, 2, 5));
    }

    #[test]
    fn repair4_recorder_latency_min_mean_max_p95() {
        let r = OpRecorder::new();
        let n = nm("write");
        for v in 1..=20 {
            r.record(&n, OpOutcome::Success, ms(v)).unwrap();
        }
        let l = *r.snapshot_op(&n).unwrap().latency().unwrap();
        assert_eq!(l.min(), ms(1));
        assert_eq!(l.max(), ms(20));
        assert_eq!(l.mean(), Duration::from_micros(10_500));
        assert_eq!(l.p95(), ms(19));
    }

    #[test]
    fn repair4_recorder_window_is_bounded() {
        let r = OpRecorder::new();
        let n = nm("read");
        // 先頭 10 件が 1ms、以降が 100ms。ウィンドウから先頭 10 件は押し出される。
        for _ in 0..10 {
            r.record(&n, OpOutcome::Success, ms(1)).unwrap();
        }
        for _ in 0..LATENCY_WINDOW_CAP {
            r.record(&n, OpOutcome::Success, ms(100)).unwrap();
        }
        let s = r.snapshot_op(&n).unwrap();
        assert_eq!(s.total(), (LATENCY_WINDOW_CAP + 10) as u64);
        let l = s.latency().unwrap();
        assert_eq!(l.min(), ms(1));
        assert_eq!(l.p95(), ms(100));
        assert_eq!(l.max(), ms(100));
    }

    #[test]
    fn repair4_recorder_concurrent_records_are_consistent() {
        let r = Arc::new(OpRecorder::new());
        let n = nm("read");
        std::thread::scope(|scope| {
            for t in 0..8u64 {
                let r = Arc::clone(&r);
                let n = n.clone();
                scope.spawn(move || {
                    for i in 0..1000u64 {
                        let outcome = if i % 2 == 0 {
                            OpOutcome::Success
                        } else {
                            OpOutcome::Failure
                        };
                        r.record(&n, outcome, ms(1 + t)).unwrap();
                    }
                });
            }
        });
        let s = r.snapshot_op(&n).unwrap();
        assert_eq!((s.success(), s.failure(), s.total()), (4000, 4000, 8000));
        let l = s.latency().unwrap();
        assert_eq!((l.min(), l.max()), (ms(1), ms(8)));
        assert_eq!(l.mean(), Duration::from_micros(4500));
    }

    #[test]
    fn repair4_recorder_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<OpRecorder>();
    }

    #[test]
    fn repair4_guard_drop_records_failure() {
        let r = OpRecorder::new();
        let n = nm("start");
        drop(r.start(n.clone()));
        let s = r.snapshot_op(&n).unwrap();
        assert_eq!((s.success(), s.failure()), (0, 1));
        assert!(s.latency().is_some());
    }

    #[test]
    fn repair4_guard_success_and_record_op() {
        let r = OpRecorder::new();
        let n = nm("create");
        r.start(n.clone()).success();
        r.start(n.clone()).finish_with(&Err::<(), ()>(()));
        assert_eq!(r.record_op(&n, || Ok::<u8, ()>(5)), Ok(5));
        assert_eq!(r.record_op(&n, || Err::<u8, &str>("x")), Err("x"));
        let s = r.snapshot_op(&n).unwrap();
        assert_eq!((s.success(), s.failure()), (2, 2));
    }

    #[test]
    fn repair4_record_op_records_failure_on_panic() {
        let r = OpRecorder::new();
        let n = nm("panic_op");
        let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = r.record_op(&n, || -> Result<(), ()> { panic!("boom") });
        }));
        assert!(caught.is_err());
        let s = r.snapshot_op(&n).unwrap();
        assert_eq!((s.success(), s.failure()), (0, 1));
        assert!(s.latency().is_some());
    }

    #[test]
    fn repair4_recorder_rejects_ops_beyond_limit() {
        let r = OpRecorder::new();
        for i in 0..MAX_TRACKED_OPS {
            r.record(&nm(&format!("op{i}")), OpOutcome::Success, ms(1))
                .unwrap();
        }
        let err = r
            .record(&nm("extra"), OpOutcome::Success, ms(1))
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::FailedPrecondition);
        assert_eq!(r.dropped_records(), 1);
        assert!(r.snapshot_op(&nm("extra")).is_none());
        r.record(&nm("op0"), OpOutcome::Failure, ms(1)).unwrap();
        assert_eq!(r.snapshot_op(&nm("op0")).unwrap().total(), 2);
        assert_eq!(r.snapshot().len(), MAX_TRACKED_OPS);
    }

    #[test]
    fn repair4_snapshot_sorted_by_name() {
        let r = OpRecorder::new();
        for n in ["write", "create", "read"] {
            r.record(&nm(n), OpOutcome::Success, ms(1)).unwrap();
        }
        let names: Vec<String> = r.snapshot().iter().map(|s| s.name().to_string()).collect();
        assert_eq!(names, ["create", "read", "write"]);
    }

    #[test]
    fn repair4_snapshot_empty_recorder() {
        let r = OpRecorder::new();
        assert!(r.snapshot().is_empty());
        assert_eq!(r.dropped_records(), 0);
    }
}
