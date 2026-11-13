//! VM 保持役の受付ループと終了手順（MAC-4・CORE-1・PLUG-12・REPAIR-5）。
//!
//! `vm_keeper::run_main`（bin）と結合試験が [`run`] を呼ぶ。起動手順は 配置ディレクトリの検証 → ロック取得 → UDS bind →
//! 受付ループ。UDS は `fandhe-container-plugin` の `UdsListener` で、配置ディレクトリの検証・stale socket の検証つき削除・
//! accept ごとの peer UID 照合（不一致は切断して監査イベントを observer へ）を担う。1 接続 1 要求で、要求ごとに期限
//! （[`REQUEST_IO_TIMEOUT`]）を持つ。peer 拒否が続くときは上限つきの指数バックオフを入れる（busy loop の防止。
//! `grpc::UdsIncoming` と同じ形）。

use std::path::Path;
use std::time::{Duration, Instant};

use fandhe_container_core::traits::TraitError;
use fandhe_container_plugin::{
    Frame, JsonLinesPeerAuthObserver, RpcTimeout, RuntimeDir, UdsListener, UdsStream,
};

use super::lock::KeeperLock;
use super::protocol::{Reason, Request, Response};
use super::registry::{Registry, Reject};
use super::{
    KeeperConfig, KeeperExit, REQUEST_IO_TIMEOUT, VM_STOP_DEADLINE, VmLifecycle, VmStopOutcome,
    from_plugin,
};

/// socket 名（VM 名は今回は固定の `default`）。
pub(crate) const SOCKET_NAME: &str = "vm-keeper-default.sock";

/// accept 1 回の待ちの上限。`UdsListener::accept` は期限後に観測した接続を閉じて `Timeout` を返す（期限直前のポーリング中に
/// 届いた接続を取りこぼす窓が最大 5ms ある）ため、周回を減らして窓の頻度を下げる。参照数が 1 以上の間は猶予の判定が
/// 要らないので、この長さで待つ。起動役は取りこぼしを `Unavailable` として 1 回だけやり直す（`client`）。
const ACCEPT_SLICE: Duration = Duration::from_secs(30);
/// accept 1 回の待ちの下限（0 にしない）。
const ACCEPT_MIN: Duration = Duration::from_millis(1);
/// peer 拒否が続くときのバックオフ（4 件目から 10ms 起点・上限 500ms）。
const BACKOFF_START: Duration = Duration::from_millis(10);
const BACKOFF_MAX: Duration = Duration::from_millis(500);
const BACKOFF_FREE_REJECTIONS: u32 = 3;
/// peer 拒否以外の accept の失敗がこの回数続いたら保持役を落とす（fail-closed。ロックはプロセス終了で外れる）。
const MAX_CONSECUTIVE_ACCEPT_ERRORS: u32 = 32;

/// 構造化ログ 1 行を stderr の sink へ出す（英語の固定文言のみ。パス・UID は含めない。待たない出力経路）。
fn log(level: &'static str, message: &'static str) {
    let line =
        format!("{{\"level\":\"{level}\",\"event\":\"vm_keeper\",\"message\":\"{message}\"}}\n");
    let _ = crate::stderr_sink::stderr().emit(line.into_bytes());
}

/// 要求種別ごとの結果分類別カウント（REPAIR-4）。保持役のプロセス内だけで持ち、1 要求ごとの構造化ログに現在値を載せる。
#[derive(Debug, Default)]
struct OpStats {
    /// `[種別][結果分類]` の件数。種別は register・unregister・status、結果分類は `reason_index` の 0〜4。
    counts: [[u64; 5]; 3],
}

impl OpStats {
    fn record(&mut self, op: usize, reason: Reason) -> u64 {
        let cell = self
            .counts
            .get_mut(op)
            .and_then(|row| row.get_mut(reason_index(reason)));
        match cell {
            Some(c) => {
                *c = c.saturating_add(1);
                *c
            }
            None => 0,
        }
    }
}

fn reason_index(reason: Reason) -> usize {
    match reason {
        Reason::Ok => 0,
        Reason::AlreadyRegistered => 1,
        Reason::NotRegistered => 2,
        Reason::CapacityExceeded => 3,
        Reason::ShuttingDown => 4,
    }
}

fn reason_name(reason: Reason) -> &'static str {
    match reason {
        Reason::Ok => "ok",
        Reason::AlreadyRegistered => "already_registered",
        Reason::NotRegistered => "not_registered",
        Reason::CapacityExceeded => "capacity_exceeded",
        Reason::ShuttingDown => "shutting_down",
    }
}

fn op_of(request: &Request) -> (usize, &'static str) {
    match request {
        Request::Register(_) => (0, "register"),
        Request::Unregister(_) => (1, "unregister"),
        Request::Status => (2, "status"),
    }
}

/// 1 要求の結果を構造化ログ 1 行で出す（英語の固定語彙のみ。ID・パスは含めない）。
fn log_op(op: &'static str, reason: Reason, count: u64, refcount: u16, elapsed: Duration) {
    let elapsed_us = u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX);
    let result = reason_name(reason);
    let line = format!(
        "{{\"level\":\"info\",\"event\":\"vm_keeper_op\",\"op\":\"{op}\",\"result\":\"{result}\",\"count\":{count},\"refcount\":{refcount},\"elapsed_us\":{elapsed_us}}}\n"
    );
    let _ = crate::stderr_sink::stderr().emit(line.into_bytes());
}

fn drain_observer(observer: &mut JsonLinesPeerAuthObserver) {
    for mut line in observer.drain_lines() {
        line.push('\n');
        let _ = crate::stderr_sink::stderr().emit(line.into_bytes());
    }
}

fn backoff(rejections: u32) -> Duration {
    let Some(step) = rejections.checked_sub(BACKOFF_FREE_REJECTIONS + 1) else {
        return Duration::ZERO;
    };
    BACKOFF_START
        .checked_mul(1u32.checked_shl(step.min(16)).unwrap_or(u32::MAX))
        .map_or(BACKOFF_MAX, |d| d.min(BACKOFF_MAX))
}

fn reason_of(reject: Reject) -> Reason {
    match reject {
        Reject::AlreadyRegistered => Reason::AlreadyRegistered,
        Reject::NotRegistered => Reason::NotRegistered,
        Reject::CapacityExceeded => Reason::CapacityExceeded,
        Reject::ShuttingDown => Reason::ShuttingDown,
    }
}

/// 要求を登録簿へ適用して応答を作る。
fn apply(registry: &mut Registry, request: Request, now: Instant, pid: u32) -> Response {
    let reason = match request {
        Request::Register(id) => registry
            .register(id)
            .map_or_else(reason_of, |()| Reason::Ok),
        Request::Unregister(id) => registry
            .unregister(&id, now)
            .map_or_else(reason_of, |()| Reason::Ok),
        Request::Status => Reason::Ok,
    };
    Response {
        reason,
        refcount: u16::try_from(registry.refcount()).unwrap_or(u16::MAX),
        keeper_pid: pid,
    }
}

/// 1 接続の 1 要求を処理する。失敗は呼び出し側が接続を捨てる（受付ループは継続する）。
fn serve_one(
    stream: &mut UdsStream,
    registry: &mut Registry,
    stats: &mut OpStats,
    pid: u32,
) -> Result<(), TraitError> {
    let timeout = RpcTimeout::new(REQUEST_IO_TIMEOUT).map_err(from_plugin)?;
    let frame = stream.read_frame(timeout).map_err(from_plugin)?;
    let request = Request::decode(frame.payload())?;
    let (op, op_name) = op_of(&request);
    let started = Instant::now();
    let response = apply(registry, request, started, pid);
    let count = stats.record(op, response.reason);
    log_op(
        op_name,
        response.reason,
        count,
        response.refcount,
        started.elapsed(),
    );
    let out = Frame::new(response.encode()).map_err(from_plugin)?;
    stream.write_frame(&out, timeout).map_err(from_plugin)
}

/// 保持役を実行する。猶予後に終了すると [`KeeperExit`] を返す。
///
/// `base` は検証済みの配置ディレクトリの基底（絶対パス・自 UID 所有・存在すること）。ロックを取れなければ
/// `FAILED_PRECONDITION`（`vm keeper is already running`）で何も起動せず返る。
pub fn run(
    config: &KeeperConfig,
    base: &Path,
    vm: &mut dyn VmLifecycle,
) -> Result<KeeperExit, TraitError> {
    let dir = RuntimeDir::ensure_under(base).map_err(from_plugin)?;
    let lock = KeeperLock::try_acquire(dir.path())?;
    let socket = dir.socket_path(SOCKET_NAME).map_err(from_plugin)?;
    let listener = UdsListener::bind(&socket).map_err(from_plugin)?;
    log("info", "vm keeper started");

    let pid = std::process::id();
    let mut registry = Registry::new(config.idle_grace(), Instant::now());
    let mut observer = JsonLinesPeerAuthObserver::new();
    let mut rejections: u32 = 0;
    let mut other_errors: u32 = 0;
    let mut stats = OpStats::default();
    // 受付ループの致命的な失敗。停止順（VM stop → listener drop → lock 解放）を飛ばさないため、
    // ここへ退避して後段の停止手順を必ず通してから返す。
    let mut fatal: Option<TraitError> = None;

    loop {
        let now = Instant::now();
        if registry.should_exit(now) {
            break;
        }
        let wait = registry
            .remaining_grace(now)
            .map_or(ACCEPT_SLICE, |r| r.clamp(ACCEPT_MIN, ACCEPT_SLICE));
        match listener.accept(wait, &mut observer) {
            Ok(mut stream) => {
                rejections = 0;
                other_errors = 0;
                if serve_one(&mut stream, &mut registry, &mut stats, pid).is_err() {
                    log("warn", "vm keeper request failed");
                }
            }
            Err(e) if e.code() == fandhe_container_plugin::PluginErrorCode::Timeout => {
                // 正常な待ち切れは健全な周回。「連続」失敗の数え直しに含める。
                rejections = 0;
                other_errors = 0;
            }
            Err(e) if e.code() == fandhe_container_plugin::PluginErrorCode::PermissionDenied => {
                rejections = rejections.saturating_add(1);
                drain_observer(&mut observer);
                std::thread::sleep(backoff(rejections));
            }
            Err(e) => {
                other_errors += 1;
                if other_errors > MAX_CONSECUTIVE_ACCEPT_ERRORS {
                    fatal = Some(from_plugin(e));
                    break;
                }
                std::thread::sleep(BACKOFF_START);
            }
        }
        drain_observer(&mut observer);
    }

    // 終了の順序: VM の停止 → socket の削除（listener の drop）→ ロックの解放。
    log(
        "info",
        if fatal.is_some() {
            "vm keeper stopping after a fatal accept failure"
        } else {
            "vm keeper idle grace elapsed"
        },
    );
    let vm_stop = match vm.stop(VM_STOP_DEADLINE) {
        Ok(outcome) => outcome,
        Err(_) => {
            log("error", "vm keeper failed to stop the vm");
            VmStopOutcome::Failed
        }
    };
    drain_observer(&mut observer);
    drop(listener);
    drop(lock);
    match fatal {
        Some(e) => Err(e),
        None => Ok(KeeperExit { vm_stop }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fandhe_container_core::traits::{ContainerId, ErrorCode};

    fn id(s: &str) -> ContainerId {
        ContainerId::new(s).expect("valid id")
    }

    #[test]
    fn mac4_backoff_starts_at_fourth_rejection_and_caps() {
        assert_eq!(backoff(1), Duration::ZERO);
        assert_eq!(backoff(3), Duration::ZERO);
        assert_eq!(backoff(4), Duration::from_millis(10));
        assert_eq!(backoff(5), Duration::from_millis(20));
        assert_eq!(backoff(9), Duration::from_millis(320));
        assert_eq!(backoff(10), Duration::from_millis(500));
        assert_eq!(backoff(u32::MAX), Duration::from_millis(500));
    }

    #[test]
    fn mac4_op_stats_count_per_op_and_result() {
        let mut s = OpStats::default();
        assert_eq!(s.record(0, Reason::Ok), 1);
        assert_eq!(s.record(0, Reason::Ok), 2);
        assert_eq!(s.record(0, Reason::AlreadyRegistered), 1);
        assert_eq!(s.record(1, Reason::NotRegistered), 1);
        assert_eq!(s.record(9, Reason::Ok), 0);
    }

    #[test]
    fn mac4_apply_maps_registry_results_to_reasons() {
        let t0 = Instant::now();
        let mut r = Registry::new(Duration::from_secs(30), t0);
        let reg = apply(&mut r, Request::Register(id("a")), t0, 7);
        assert_eq!(
            (reg.reason, reg.refcount, reg.keeper_pid),
            (Reason::Ok, 1, 7)
        );
        let dup = apply(&mut r, Request::Register(id("a")), t0, 7);
        assert_eq!((dup.reason, dup.refcount), (Reason::AlreadyRegistered, 1));
        let unknown = apply(&mut r, Request::Unregister(id("b")), t0, 7);
        assert_eq!(
            (unknown.reason, unknown.refcount),
            (Reason::NotRegistered, 1)
        );
        let status = apply(&mut r, Request::Status, t0, 7);
        assert_eq!((status.reason, status.refcount), (Reason::Ok, 1));
        let un = apply(&mut r, Request::Unregister(id("a")), t0, 7);
        assert_eq!((un.reason, un.refcount), (Reason::Ok, 0));
    }

    // plugin の分類が構造化エラーの分類へ写ること（DataLoss は Internal へ倒す）。
    #[test]
    fn mac4_from_plugin_keeps_code_class() {
        let e = from_plugin(fandhe_container_plugin::PluginError::new(
            fandhe_container_plugin::PluginErrorCode::DataLoss,
            "x",
        ));
        assert_eq!(e.code(), ErrorCode::Internal);
    }
}
