//! shim v2 の serve の終了時に、共有記録器の操作統計を stderr へ 1 回だけ書き出す（CRI-5・REPAIR-4・REPAIR-5・#4408）。
//!
//! 呼び出し元: `shim::registry_parts_in` が exec 起動役の包みとして [`ServeEndLauncher`] を v2・v3 の `TaskService` へ差す。
//! cri の bootstrap に終了の注入口を足さずに済ませるため、`run_serve` の終わりに `TtrpcServer` が drop され登録簿・`TaskService` の
//! 最後の参照が落ちたときの `Drop` を契機にする（Shutdown RPC でも socket 消失でも同じ）。以前の `StopHelpersOnDrop`（#4149）の後継で、
//! helper の停止（`ShimExecLauncher::shutdown_all`）の後に書き出す（停止後の計数を最終値として出す）。
//!
//! 契約:
//! - 書き出しは `OpRecorder::export_json_lines` 形式（`op_stats` 行と `op_stats_meta` 行）で、起動時の走査の後の 1 回（`startup_sweep`）と同じ。
//!   値は固定語彙の操作名と整数だけで、ID・パス・errno は含まない。終了時の値は serve 開始からの累計（起動時に出した計数も含む）
//! - 集計対象が 0 件なら何も出さない（コンテナごとに起動する shim の `daemon.log` を空のブロックで埋めない）
//! - 待ちは [`SHIM_FINAL_OP_STATS_WAIT`] で打ち切る（REPAIR-5）。stderr の受け手が詰まっても shim の終了は最長この時間しか遅れず、
//!   積めなかった行は `LineSink` の欠落件数へ集約される
//! - 書き出しは 1 回だけ（二重の呼び出しは何もしない）
//!
//! 残余（REPAIR-3）: `ServerHandle::shutdown` の期限切れで接続スレッドが登録簿を握り続ける場合と shim の SIGKILL では `Drop` が走らず、
//! 出ない。定期出力・ファイル公開口は無い（`docs/design/cri-op-stats-export.md`）。

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use fandhe_container_core::observability::OpRecorder;
use fandhe_container_core::traits::ContainerId;
use fandhe_container_cri::error::CriError;
use fandhe_container_cri::shim_v2::exec::{
    ExecId, ExecProcessSpec, TaskExecLauncher, TaskExecProcess,
};

use crate::task_exec::ShimExecLauncher;
use crate::telemetry::LineSink;

/// 終了時の書き出しの待ちの上限（plugin-cri 本体の停止時の最後の書き出しと同じ値。REPAIR-5）。
pub(crate) const SHIM_FINAL_OP_STATS_WAIT: Duration = crate::shutdown::OP_STATS_FINAL_WRITE_WAIT;

/// [`FinalOpStatsExport::export`] の結果（真偽値に潰さない）。
// 本番は結果を捨てる（Drop 内）ため、試験無効の構成では値が読まれない。
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub(crate) enum FinalExportOutcome {
    /// 集計対象が 0 件、または既に書き出し済みで、何も出さなかった。
    Empty,
    /// 符号化に失敗し、1 行も出さなかった（固定スキーマでは起きない）。
    EncodeFailed,
    /// `lines` 行を積んだ。`flushed` は期限内に全行が書き出されたか。
    Exported { lines: usize, flushed: bool },
}

/// 共有記録器の最終集計を 1 回だけ `sink` へ書き出す口。
pub(crate) struct FinalOpStatsExport {
    recorder: Arc<OpRecorder>,
    sink: LineSink,
    wait: Duration,
    done: AtomicBool,
}

impl FinalOpStatsExport {
    /// 記録器・送り先・待ちの上限から作る。本番の送り先は `telemetry::stderr_sink()`、上限は [`SHIM_FINAL_OP_STATS_WAIT`]。
    pub(crate) fn new(recorder: Arc<OpRecorder>, sink: LineSink, wait: Duration) -> Self {
        Self {
            recorder,
            sink,
            wait,
            done: AtomicBool::new(false),
        }
    }

    /// 書き出す。2 回目以降は `Empty`。
    pub(crate) fn export(&self) -> FinalExportOutcome {
        if self.done.swap(true, Ordering::SeqCst) {
            return FinalExportOutcome::Empty;
        }
        let Some((lines, ops)) = crate::telemetry::op_stats_lines(&self.recorder) else {
            return FinalExportOutcome::EncodeFailed;
        };
        if ops == 0 {
            return FinalExportOutcome::Empty;
        }
        let n = lines.len();
        for line in lines {
            let _ = self.sink.submit(line);
        }
        FinalExportOutcome::Exported {
            lines: n,
            flushed: self.sink.flush(self.wait),
        }
    }
}

/// shim の終了時に追跡中の exec helper を止め、続けて操作統計を 1 回書き出す `TaskExecLauncher` の包み（#4149・#4408）。
///
/// `launch` は中の [`ShimExecLauncher`] へ委ねるだけ。v2・v3 の `TaskService` が 1 つの `Arc` を共有するので、最後の参照が落ちたときに
/// `Drop` が 1 回だけ走る。残余は module doc のとおり。
pub(crate) struct ServeEndLauncher {
    launcher: Arc<ShimExecLauncher>,
    final_stats: FinalOpStatsExport,
}

impl ServeEndLauncher {
    pub(crate) fn new(launcher: Arc<ShimExecLauncher>, final_stats: FinalOpStatsExport) -> Self {
        Self {
            launcher,
            final_stats,
        }
    }
}

impl TaskExecLauncher for ServeEndLauncher {
    fn launch(
        &self,
        container: &ContainerId,
        exec_id: &ExecId,
        spec: &ExecProcessSpec,
        expected_instance: Option<u64>,
    ) -> Result<Arc<dyn TaskExecProcess>, CriError> {
        self.launcher
            .launch(container, exec_id, spec, expected_instance)
    }
}

impl Drop for ServeEndLauncher {
    fn drop(&mut self) {
        self.launcher.shutdown_all();
        let _ = self.final_stats.export();
    }
}

#[cfg(test)]
#[path = "serve_end_tests.rs"]
pub(crate) mod tests;
