//! shim v2 の serve の起動時の `@container-logs`・`@supervisor-logs` 走査（D7 の「2 つ目の契機」。CRI-5・SUP-7・REPAIR-4・REPAIR-5・#4280・#4343）。
//!
//! 呼び出し元: `shim::registry_parts_in`（登録簿の組み立てに成功した後。serve だけが通る）。呼び出し先: plugin-cri の起動時の走査と同じ
//! [`crate::adapter::sweep_leftover_logs_at_startup`]（新しい削除ロジックは持たない。guard は「状態記録が無い」かつ「sink の flock が
//! 外れている」。読み取りの失敗は消さない側へ倒れる）。
//!
//! 背景: shim の状態は containerd の address・namespace ごとの scoped 状態ルートに置かれ、plugin-cri 自身の起動時の走査（#2760）は
//! そこを見ない。CRI は ID を使い回さないため、delete の `AlreadyReclaimed` での回収（#4279）が走らなかったコンテナログは溜まり続ける。
//!
//! 契約:
//! - 走査は detached の std thread で 1 回だけ行い、serve の開始を待たせない。全体の期限は [`SHIM_STARTUP_LOG_SWEEP_BUDGET`]
//! - 対象は `@container-logs` → `@supervisor-logs` の順（#4296 のオーナー判断）。期限は 1 つを共有し、コンテナログを全期限で先に走査して
//!   supervisor ログは残り時間で走る（コンテナログの期限を食わない・置き去りにされうる thread の上限を保つ・共有の削除作業枠を奪い合わない）。
//!   コンテナログが期限を使い切ると supervisor ログは予算 0 の `timed_out` になり、残りは次の shim の起動で回収される
//! - `@container-options`（起動オプション文書）は走査しない（容認する残余。D7）
//! - 出力は件数だけの要約行（`event: container_log_sweep` と `event: supervisor_log_sweep`）。何も無かったときは出さない
//!   （コンテナごとに起動する shim の `daemon.log` を空の行で埋めない）。thread を作れなかった固定行は両方の走査が走らないことを表す
//! - どちらかの回収が 1 件以上あったときだけ、走査の完了時点の共有記録器のスナップショットを core の `OpRecorder::export_json_lines` 形式
//!   （`event: op_stats` 行と `op_stats_meta` 行）で 1 回だけ `emit` へ流す（#4319・REPAIR-4）。値は固定語彙の操作名と整数だけで、
//!   ID・パスは含まない。書き出しの失敗・送り先の詰まりは走査の結果・削除に影響しない（送り先は `try_send` で行を件数へ集約する）
//!
//! 残余（REPAIR-3）: 書き出しは走査完了時点の 1 回だけで、その後の lifecycle 操作の計数は shim からは出ない（定期出力は無い。
//! `docs/design/cri-op-stats-export.md` で shim は対象外）。
//!
//! 残余: 並行して起動した別の shim の走査とは競合しうるが、ID ごとの削除はロックの下で guard を評価するため無害（片方が消し、もう片方は
//! 見送る）。serve が走査より先に終わるとプロセスの終了で走査が途中で切れ、次の shim の起動時に回収される。稼働中に発生した残りも次の
//! 起動まで残る。

use std::sync::{Arc, mpsc};
use std::time::Duration;

use fandhe_container_core::observability::OpRecorder;
use fandhe_container_core::traits::StateStore;
use fandhe_container_supervisor::logs::SweepReport;

/// 走査の全体の期限（plugin-cri の起動時の走査と同じ値。D7・REPAIR-5）。
pub(crate) const SHIM_STARTUP_LOG_SWEEP_BUDGET: Duration = crate::adapter::STARTUP_LOG_SWEEP_BUDGET;

/// thread を作れなかったときの固定の 1 行（パス・errno は含めない。REPAIR-4）。
const SPAWN_FAILED_LINE: &str =
    r#"{"level":"warn","event":"container_log_sweep","outcome":"spawn_failed"}"#;

/// 走査 thread の起動結果（真偽値に潰さない）。
// 結果の受け口は試験だけが読む（本番は待たずに捨てる）ため、試験無効の構成では読まれない。
#[cfg_attr(not(test), allow(dead_code))]
#[non_exhaustive]
pub(crate) enum StartupSweep {
    /// 起動した。本番は待たずに捨て、試験は [`SweepHandle::wait_within`] で結果を期限つきで待つ。
    Spawned(SweepHandle),
    /// thread を作れなかった（serve は続ける。固定の警告行を出した）。
    SpawnFailed,
}

/// 起動時の走査の結果（コンテナログと supervisor ログ。`@container-logs` が無い等で走査できなかった側は `None`）。
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug)]
pub(crate) struct StartupSweepReports {
    /// `@container-logs` の走査結果。
    pub(crate) containers: Option<SweepReport>,
    /// `@supervisor-logs` の走査結果。
    pub(crate) supervisors: Option<SweepReport>,
}

/// 走査の結果の受け口。捨てても thread は最後まで走る。
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) struct SweepHandle {
    rx: mpsc::Receiver<StartupSweepReports>,
}

#[cfg_attr(not(test), allow(dead_code))]
impl SweepHandle {
    /// 期限までに走査が終われば結果を返す。終わらなければ `Timeout`。
    pub(crate) fn wait_within(
        &self,
        limit: Duration,
    ) -> Result<StartupSweepReports, mpsc::RecvTimeoutError> {
        self.rx.recv_timeout(limit)
    }
}

/// 記録の無い ID の残りのコンテナログと supervisor ログを、裏の thread で 1 回だけ回収する。呼び出し側は待たない。
///
/// `emit` は要約行の送り先（本番は `telemetry::stderr_sink` の `submit`。試験が行を捕まえるために注入できる）。
pub(crate) fn spawn_startup_log_sweep(
    state: Arc<dyn StateStore>,
    recorder: Arc<OpRecorder>,
    budget: Duration,
    emit: Arc<dyn Fn(String) + Send + Sync>,
) -> StartupSweep {
    let (tx, rx) = mpsc::channel();
    let emit_in = Arc::clone(&emit);
    let spawned = std::thread::Builder::new()
        .name("cri-shim-log-sweep".to_owned())
        .spawn(move || {
            let (containers, supervisors) =
                crate::adapter::sweep_leftover_logs_at_startup(&state, &recorder, budget);
            if let Some(r) = &containers
                && *r != SweepReport::default()
            {
                emit_in(crate::adapter::sweep_summary_line(r));
            }
            if let Some(r) = &supervisors
                && *r != SweepReport::default()
            {
                emit_in(crate::adapter::supervisor_log_sweep_summary_line(r));
            }
            let reclaimed =
                |r: &Option<SweepReport>| r.as_ref().is_some_and(|r| r.reclaimed_ids > 0);
            if reclaimed(&containers) || reclaimed(&supervisors) {
                export_reclaim_stats(&recorder, &*emit_in);
            }
            // 受け手が捨てられていても構わない。
            let _ = tx.send(StartupSweepReports {
                containers,
                supervisors,
            });
        });
    match spawned {
        Ok(_) => StartupSweep::Spawned(SweepHandle { rx }),
        Err(_) => {
            emit(SPAWN_FAILED_LINE.to_owned());
            StartupSweep::SpawnFailed
        }
    }
}

/// 共有記録器の集計を `export_json_lines` の形式で 1 行ずつ `emit` へ流す（#4319・REPAIR-4）。
///
/// 走査 thread から、回収が 1 件以上あったときだけ呼ばれる。符号化の失敗（固定スキーマでは起きない）は 1 行も出さずに戻る。
/// 出した行数を返す（真偽値に潰さない）。
fn export_reclaim_stats(recorder: &OpRecorder, emit: &dyn Fn(String)) -> usize {
    let mut buf: Vec<u8> = Vec::new();
    if recorder.export_json_lines(Some(&mut buf)).is_err() {
        return 0;
    }
    let text = String::from_utf8_lossy(&buf);
    let mut n = 0;
    for line in text.lines() {
        emit(line.to_owned());
        n += 1;
    }
    n
}

#[cfg(test)]
#[path = "startup_sweep_tests.rs"]
mod tests;
