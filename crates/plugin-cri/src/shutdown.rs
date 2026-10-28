//! 正常停止の待ち future・固定語彙の 1 行・待ちの上限の定数（#3226・CRI-1・CORE-1・REPAIR-4・REPAIR-5）。
//!
//! 呼び出し元: `main.rs` の `serve` が [`wait_for_signal`] を `server::serve_with_audit` の shutdown に渡し、
//! 終了時に [`shutdown_line`] を stderr へ出す。シグナルの受信記録は `sys`（自前の `signal(3)` 宣言）が持つ。
//! 受け取ってからの流れ（受付の停止 → 実行中の RPC を [`crate::adapter::PLUGIN_SHUTDOWN_GRACE`] まで待つ →
//! 猶予超過は接続を強制的に閉じて回収 → socket の削除は `UdsListener::drop`）は `server` の doc と
//! `docs/design/cri-record-readoption.md`「停止の契約」を参照。tokio の `signal` / `sync` feature は使わない。

use std::time::Duration;

use crate::sys::{self, ShutdownSignal};

/// 受信フラグを見る周期。atomic の load だけなので待機中の CPU 負荷は無視できる（CORE-7）。
/// 検知の遅れの上限でもある（停止の全体の上限に足す。[`SHUTDOWN_TOTAL_BOUND`]）。
pub const SHUTDOWN_SIGNAL_POLL: Duration = Duration::from_millis(100);

/// `block_on` から戻った後に tokio の `Runtime` が `spawn_blocking` のタスクを待つ上限。
/// 暗黙の drop は完了を無期限に待つため、`shutdown_timeout` で置き去りにする（PullImage の取り込み等。結果不明として
/// 再起動時に R7・OCI-7 が扱う）。
pub const RUNTIME_SHUTDOWN_WAIT: Duration = Duration::from_secs(1);

/// 最後の書き出し（stderr の sink の待ち）の上限。
pub const FINAL_FLUSH_WAIT: Duration = Duration::from_millis(200);

/// 停止シグナルを受けるまで待つ。`serve_with_audit` の shutdown future として渡す（SIGTERM・SIGINT 共通）。
pub async fn wait_for_signal() {
    while sys::received().is_none() {
        tokio::time::sleep(SHUTDOWN_SIGNAL_POLL).await;
    }
}

/// 停止がどの段で止まったか。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShutdownStage {
    /// 起動段（受付の前）の境界で受信を見つけて、bind せずに終えた。
    Startup,
    /// 受付中に受信し、実行中の RPC の完了を待って終えた。
    Serve,
}

/// 正常停止の完了を示す stderr の固定の 1 行。パス・pid・ID・OS のエラー文字列を含めない（REPAIR-4）。
pub fn shutdown_line(signal: ShutdownSignal, stage: ShutdownStage) -> String {
    let stage = match stage {
        ShutdownStage::Startup => "startup",
        ShutdownStage::Serve => "serve",
    };
    format!(
        "cri plugin shutdown: signal={} stage={stage}",
        signal.as_str()
    )
}

/// 停止の全体の上限: 検知の周期 + 猶予 + 強制回収（`serve_router` の `FORCE_RECLAIM_WAIT` 2 秒）+ 最後の書き出し（2 回）
/// + ランタイムの待ち。これを超えて待つ経路は無い（REPAIR-5）。
pub const SHUTDOWN_TOTAL_BOUND: Duration = Duration::from_millis(
    SHUTDOWN_SIGNAL_POLL.as_millis() as u64
        + crate::adapter::PLUGIN_SHUTDOWN_GRACE.as_millis() as u64
        + 2_000
        + 2 * FINAL_FLUSH_WAIT.as_millis() as u64
        + RUNTIME_SHUTDOWN_WAIT.as_millis() as u64,
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shutdown_line_is_fixed_vocabulary() {
        assert_eq!(
            shutdown_line(ShutdownSignal::Term, ShutdownStage::Serve),
            "cri plugin shutdown: signal=SIGTERM stage=serve"
        );
        assert_eq!(
            shutdown_line(ShutdownSignal::Int, ShutdownStage::Serve),
            "cri plugin shutdown: signal=SIGINT stage=serve"
        );
        assert_eq!(
            shutdown_line(ShutdownSignal::Term, ShutdownStage::Startup),
            "cri plugin shutdown: signal=SIGTERM stage=startup"
        );
        assert_eq!(
            shutdown_line(ShutdownSignal::Int, ShutdownStage::Startup),
            "cri plugin shutdown: signal=SIGINT stage=startup"
        );
    }

    /// CRI-1・REPAIR-5: 停止の全体の上限が 15 秒以下で、systemd の既定の停止猶予（90 秒）より十分短い。
    #[test]
    fn total_bound_is_within_fifteen_seconds() {
        assert_eq!(SHUTDOWN_TOTAL_BOUND, Duration::from_millis(13_500));
        assert!(SHUTDOWN_TOTAL_BOUND <= Duration::from_secs(15));
    }
}
