//! 起動・再起動をまたぐコンテナ出力の捕捉ハブ（TASK-164 追補・#1471・SUP-7・SUP-1。関連: REPAIR-5・CORE-1・D-19）。
//!
//! core の launcher が子の stdout / stderr をパイプへ接続して返す読み取り側（`LaunchedProcess::take_output`）を、
//! 行単位捕捉（[`crate::logs::LogCapture`]）へ渡して 1 つの [`LogSink`]（本番は `RotatingFileSink`）へ流す。
//! `crate::start_entry::run_supervised`（初回の起動）と `crate::restart::LauncherRelauncher`（再起動）が呼ぶ。
//! 監視ループ（`supervise_with_restart`）は書き換えず、捕捉は監視と独立したリーダースレッドで進む。
//!
//! # 契約
//! - sink と [`ReaderBudget`] は supervisor プロセスにつき 1 つずつ（ハブが保持し、再起動・再捕捉をまたいで
//!   使い回す。`logs` モジュール doc の契約）。
//! - 生きている捕捉の取っ手は高々 1 つ。[`CaptureHub::attach`] は新しい捕捉を先に開始してから、直前の捕捉を短い期限で
//!   `drain` する（旧プロセスは終了検知済みで EOF が届くはず。孫がパイプを保持して期限切れなら `drain` が自動で取り消し、
//!   リーダー数は予算が上限管理する）。新しい捕捉を先にするのは、restart のレイテンシに drain の待ちを載せないため。
//! - 読み取りスレッドを作るのは `oci_runtime::start` の完了後に限る（start は単一スレッド前提で、入口スレッドが手順 8 を
//!   直接行う。start_entry 参照）。再起動の launch の直前には [`CaptureHub::quiesce`] で直前の捕捉を畳み、捕捉スレッドを
//!   0 にしてから launch する（core の fork 経路が `Threads: 1` を要求するため）。ただし `relaunch_bounded` の実行
//!   スレッドや `stderr_sink` の常駐スレッドが別途存在するため、quiesce だけでは本番 launcher の要求を満たせず、
//!   再 launch は拒否される（fail-closed）。再 launch を呼び出しスレッドで直接行う再構成は #2043（SUP-3・CORE-1）。
//! - 捕捉を開始できなかったときは `Err` を返す。読み取り側を破棄するとコンテナは次の `write` で SIGPIPE を受けるため、
//!   呼び出し側は fail-closed（起動・再起動を失敗として扱いプロセスを回収する）にする。ログ喪失を黙って許さない（REPAIR-4）。
//! - 出力は非信頼バイト列として不透明に扱い、supervisor 自身のログへ行内容を出さない。

use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use fandhe_container_core::oci_runtime::ContainerOutput;
use fandhe_container_core::traits::TraitError;

use crate::logs::{CaptureSummary, LogCapture, LogSink, OutputStreams, ReaderBudget};

/// `drain` の結果を構造化ログへ報告する（REPAIR-4）。
///
/// `drain` は読み取り・append・flush の失敗でも `Ok(CaptureSummary)` を返し、障害は
/// `StreamSummary::error_code` と破棄行数にだけ残る。そのため `Err` だけでなく集計内の失敗も出す
/// （ディスク容量不足などでログが失われても通知されるように）。行の内容は出さない。
fn report_drain(event: &'static str, drained: &Result<CaptureSummary, TraitError>) {
    let mut failures: Vec<(&'static str, &'static str, u64)> = Vec::new();
    match drained {
        Err(e) => failures.push(("both", e.code().as_str(), 0)),
        Ok(summary) => {
            for (name, stream) in [("stdout", summary.stdout()), ("stderr", summary.stderr())] {
                if let Some(st) = stream
                    && let Some(code) = st.error_code()
                {
                    failures.push((name, code.as_str(), st.discarded_lines()));
                }
            }
        }
    }
    for (stream, code, discarded) in failures {
        let line = format!(
            "{{\"component\":\"supervisor\",\"event\":\"{event}\",\"stream\":\"{stream}\",\"code\":\"{code}\",\"discarded_lines\":{discarded}}}\n"
        );
        // 満杯・書き込み失敗でも処理は止めない（ログの欠落は許す）。
        let _ = crate::stderr_sink::stderr().emit(line.into_bytes());
    }
}

/// 直前の捕捉を畳むときの `drain` の期限（旧プロセスは回収済みで、通常は EOF が即座に届く。REPAIR-5）。
pub const PREVIOUS_DRAIN_TIMEOUT: Duration = Duration::from_millis(500);

/// コンテナ出力の捕捉ハブ。1 つの sink へ、起動ごとの出力を順に流す。
pub struct CaptureHub {
    sink: Arc<dyn LogSink>,
    budget: ReaderBudget,
    live: Mutex<Option<LogCapture>>,
}

impl std::fmt::Debug for CaptureHub {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CaptureHub")
            .field("budget", &self.budget)
            .finish_non_exhaustive()
    }
}

impl CaptureHub {
    /// `sink` へ流すハブを作る。リーダー数の予算は supervisor プロセスにつき 1 つ（ここで作る）。
    pub fn new(sink: Arc<dyn LogSink>) -> Self {
        Self {
            sink,
            budget: ReaderBudget::with_max_limit(),
            live: Mutex::new(None),
        }
    }

    /// 新しいプロセスの出力の捕捉を開始し、直前の捕捉があれば畳む。出力が空（どちらのストリームも無い）なら何もしない。
    ///
    /// 開始に失敗したら `Err`（`output` は破棄され、書き込み側のコンテナは SIGPIPE を受け得る。呼び出し側が
    /// プロセスを回収すること）。直前の捕捉の `drain` が期限切れ・失敗でも、新しい捕捉は成功として扱う
    /// （失敗は返さず、取り消された旧捕捉の行は sink の契約どおり flush 済み）。
    pub fn attach(&self, output: ContainerOutput) -> Result<(), TraitError> {
        let streams = OutputStreams::new(&self.budget, output.stdout, output.stderr);
        if streams.is_empty() {
            return Ok(());
        }
        let capture = LogCapture::start(streams, Arc::clone(&self.sink))?;
        let previous = self
            .live
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .replace(capture);
        if let Some(previous) = previous {
            // 期限切れでも `drain` が自動で取り消す。ここで待つのは旧プロセスの EOF だけ。
            report_drain(
                "log_capture_previous_drain_failed",
                &previous.drain(PREVIOUS_DRAIN_TIMEOUT),
            );
        }
        Ok(())
    }

    /// 直前の捕捉を `PREVIOUS_DRAIN_TIMEOUT` まで待って畳み、読み取りスレッドを残さない（SUP-7）。
    ///
    /// 再起動の launch の直前に呼ぶ。core の fork 経路は `Threads: 1`（シングルスレッド）を要求するため、
    /// 捕捉スレッドが生きたまま launch すると `MultiThreaded` で拒否される。旧プロセスは回収済みで EOF が即座に届くはず。
    /// 期限切れの場合は `drain` が自動で取り消す（孫がパイプを保持している場合のスレッド残存は予算が上限管理する）。
    pub fn quiesce(&self) {
        let previous = self
            .live
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some(previous) = previous {
            report_drain(
                "log_capture_previous_drain_failed",
                &previous.drain(PREVIOUS_DRAIN_TIMEOUT),
            );
        }
    }

    /// 生きている捕捉を `timeout` まで待って畳み、末尾の行を sink へ flush する。捕捉が無ければ `None`。
    ///
    /// supervisor の全終了経路で呼ぶ（末尾の行が sink 内のバッファに残らないように）。
    ///
    /// `timeout` は `LogCapture::drain` の上限（`MAX_DRAIN_TIMEOUT`）に切り詰めて渡す。`StartTimeouts` の terminate は
    /// 最大 600 秒まで許すため、そのまま渡すと drain が `InvalidArgument` で EOF を待たず捕捉を取り消し、
    /// 正常終了でも末尾行が失われる（SUP-7・REPAIR-5）。
    pub fn finish(&self, timeout: Duration) -> Option<Result<CaptureSummary, TraitError>> {
        let live = self
            .live
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        live.map(|capture| {
            let drained = capture.drain(timeout.min(crate::logs::MAX_DRAIN_TIMEOUT));
            report_drain("log_capture_finish_failed", &drained);
            drained
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logs::{MemoryLogSink, StreamKind};
    use std::io::Cursor;

    fn output(out: &str, err: &str) -> ContainerOutput {
        ContainerOutput {
            stdout: Some(Box::new(Cursor::new(out.as_bytes().to_vec()))),
            stderr: Some(Box::new(Cursor::new(err.as_bytes().to_vec()))),
        }
    }

    fn lines_of(sink: &MemoryLogSink, kind: StreamKind) -> Vec<Vec<u8>> {
        sink.snapshot()
            .expect("snapshot")
            .into_iter()
            .filter(|l| l.stream == kind)
            .map(|l| l.bytes)
            .collect()
    }

    /// SUP-7・REPAIR-5（#1471）: terminate が drain の上限（60 秒）を超える 120 秒でも、finish は拒否されず
    /// LF なしの末尾行まで sink に flush する。
    #[test]
    fn sup7_1471_finish_clamps_timeout_above_drain_limit() {
        let sink = Arc::new(MemoryLogSink::default());
        let hub = CaptureHub::new(sink.clone());
        hub.attach(output(
            "a1
last-no-lf",
            "",
        ))
        .expect("attach");
        let summary = hub
            .finish(Duration::from_secs(120))
            .expect("live capture")
            .expect("drain must not reject a 120s timeout");
        assert!(summary.stdout().is_some());
        assert_eq!(
            lines_of(&sink, StreamKind::Stdout),
            vec![b"a1".to_vec(), b"last-no-lf".to_vec()]
        );
    }

    /// SUP-7・SUP-1（#1471）: 2 回 attach しても、両方のプロセスの行がストリーム別に欠落・重複なく sink に入る。
    #[test]
    fn sup7_1471_hub_captures_both_launches() {
        let sink = Arc::new(MemoryLogSink::default());
        let hub = CaptureHub::new(sink.clone());
        hub.attach(output("a1\na2\n", "e1\n")).expect("first");
        hub.attach(output("b1\n", "e2\ne3")).expect("second");
        let summary = hub
            .finish(Duration::from_secs(5))
            .expect("live capture")
            .expect("drain");
        assert_eq!(summary.stdout().map(|s| s.lines()), Some(1));
        assert_eq!(summary.stderr().map(|s| s.lines()), Some(2));
        let mut stdout = lines_of(&sink, StreamKind::Stdout);
        stdout.sort();
        assert_eq!(stdout, vec![b"a1".to_vec(), b"a2".to_vec(), b"b1".to_vec()]);
        let mut stderr = lines_of(&sink, StreamKind::Stderr);
        stderr.sort();
        assert_eq!(stderr, vec![b"e1".to_vec(), b"e2".to_vec(), b"e3".to_vec()]);
    }

    /// SUP-7（#1471）: `quiesce` の後は読み取りスレッドが 0 になり、末尾の行も sink へ入っている。
    #[test]
    fn sup7_1471_quiesce_leaves_no_reader_threads() {
        let sink = Arc::new(MemoryLogSink::default());
        let hub = CaptureHub::new(sink.clone());
        hub.attach(output("a1\n", "e1")).expect("attach");
        hub.quiesce();
        // #3507 の後、リーダーは送信の前に枠を手放すため、quiesce から戻った時点で枠は同期的に 0
        // （待ちで補償しない。#3549・REPAIR-5）。
        assert_eq!(hub.budget.live(), 0);
        assert!(hub.finish(Duration::from_secs(1)).is_none());
        assert_eq!(lines_of(&sink, StreamKind::Stdout), vec![b"a1".to_vec()]);
        assert_eq!(lines_of(&sink, StreamKind::Stderr), vec![b"e1".to_vec()]);
    }

    /// 出力の無いプロセスは捕捉を始めず、`finish` も `None`。
    #[test]
    fn sup7_1471_hub_without_streams_is_noop() {
        let hub = CaptureHub::new(Arc::new(MemoryLogSink::default()));
        hub.attach(ContainerOutput::default()).expect("noop");
        assert!(hub.finish(Duration::from_secs(1)).is_none());
    }
}
