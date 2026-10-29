//! virtiofs 実機試験の補助関数の共通化（MAC-1・REPAIR-1・#3099・#3351）。
//!
//! `virtiofs_io.rs`（IO-5・TASK-65.4）と `virtiofs_link.rs`（SEC-4・#1877）が複製していた
//! コンソールログの確定待ち・期限の解決をここへ 1 本にまとめる。スクラッチ・環境変数のパス読み・
//! 末尾切り出しは std だけの `common.rs` に置く（#3351）。片方だけ直して食い違うことを防ぐ（REPAIR-1）。
//!
//! 呼び出し元は `virtiofs_io.rs`・`virtiofs_link.rs` と、本モジュールの単体試験 `virtiofs_harness.rs` の 3 つ。
//! いずれも `#[path = "support/common.rs"] mod common;` を先に、続けて
//! `#[path = "support/virtiofs_harness.rs"] mod harness;` をトップレベルで取り込む
//! （本ファイルは `super::common` を参照する）。
//!
//! `console_log::TRUNCATION_MARKER` と `std::os::unix` を使うため、取り込み側は unix 限定
//! （`#![cfg(unix)]` か `#![cfg(target_os = "macos")]`）にすること。ファイル自体には cfg を付けない
//! （`guest_markers.rs` と同じ流儀）。
//!
//! VM 起動後の「done 行の期限つき待ち → 停止 → 書き出し側の確定待ち → 確定後ログの打ち切り検査」
//! （#3416）は本モジュールの `launch_until_done` に寄せた。純粋な部分（`wait_done_line`・
//! `read_settled_log`）は cfg なしで置き Linux でも単体試験する。`Vm` を触る `launch_until_done` だけ
//! 関数単位で `cfg(target_os = "macos")` を付ける（`Vm` は macOS 限定で、本ファイルは Linux の単体試験
//! target からも取り込まれるため）。期限・ポーリング間隔・失敗 message の文言は寄せる前から変えていない。
//!
//! ゲスト資産（kernel・initrd・disk・cmdline）の環境変数の読み取りは `vm_guest.rs` の `GuestAssets` に
//! 寄せた（#3456。help 文は引数で渡せ、`virtiofs_link` が disk を読んで使わないだけで挙動差は無い）。
//! 各試験に残すもの: help 文の文言と probe timeout の読み取り、fixture・spec の組み立て、ログの復号
//! （`parse_probe_log` / `parse_link_log`）、停止後の共有の検証・観測。ゲスト出力は untrusted で、
//! 検証責務は試験固有のため。`vm_boot` の 100 ms ポーリングと `vm_cold_start` の 1 ms watcher は
//! 計測の意味が違うため統合しない（#3400）。

use std::path::Path;
use std::time::{Duration, Instant};

#[cfg(target_os = "macos")]
use fandhe_container_platform_macos::config::VmConfigSpec;
use fandhe_container_platform_macos::console_log::TRUNCATION_MARKER;
#[cfg(target_os = "macos")]
use fandhe_container_platform_macos::vm::{OpTimeouts, Vm, VmState};

use super::common::tail_lossy;

/// VM 破棄後、コンソールログの書き出しスレッドが EOF で終わるのを待つ上限（REPAIR-5）。
pub const CONSOLE_LOG_SETTLE_TIMEOUT: Duration = Duration::from_secs(30);

/// コンソールログが書き出しスレッドの上限（`MAX_CONSOLE_LOG_BYTES`）で打ち切られたか。
/// 区切り文は上限到達時に末尾へ 1 回だけ書かれ、以後ゲスト出力は破棄されるため、
/// 末尾が区切り文ならプローブ行の後続は観測できない。
pub fn log_truncated(bytes: &[u8]) -> bool {
    bytes.ends_with(TRUNCATION_MARKER)
}

/// コンソールログの書き出しスレッド（`console_log`）がログを閉じ終えるまで待つ。
///
/// 書き出しスレッドはログへの排他 advisory lock（unix では `flock(2)`）を EOF でファイルを閉じるまで
/// 保持する（`console_log` モジュールの「排他」）。EOF は VM と設定が解放され serial の書き込み端が
/// すべて閉じたときに来るため、`Vm` を破棄した後に lock を取れれば、ゲスト出力はすべてファイルへ
/// 反映済みで以後増えない。期限内に取れなければ不完全なログで判定しないよう `Err` を返す（fail-closed）。
pub fn wait_console_log_settled(path: &Path, timeout: Duration) -> Result<(), String> {
    let file = std::fs::File::open(path).map_err(|e| format!("open console log: {e}"))?;
    let deadline = Instant::now() + timeout;
    loop {
        match file.try_lock() {
            // 取得した lock は `file` の drop で解放される。
            Ok(()) => return Ok(()),
            Err(std::fs::TryLockError::WouldBlock) => {}
            Err(std::fs::TryLockError::Error(e)) => {
                return Err(format!("lock console log: {e}"));
            }
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "console log writer did not finish within {timeout:?}"
            ));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// 実機試験の期限（秒）を解決する。未指定は 60 秒、指定は 1..=600 のみ受け付ける。
pub fn resolve_probe_timeout(raw: Option<String>) -> Result<Duration, String> {
    super::common::resolve_secs(raw, 60, (1, 600))
        .map(Duration::from_secs)
        .map_err(|_| {
            "FANDHE_CONTAINER_MACOS_VM_PROBE_TIMEOUT_SECS must be an integer in 1..=600".to_string()
        })
}

/// done 行の待ちのポーリング間隔。
pub const DONE_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// 失敗 message に含めるコンソール末尾のバイト数。
pub const CONSOLE_TAIL_BYTES: usize = 4096;

/// `wait_done_line` の結果。各 variant は最後に読めたログ全体を持つ。
#[derive(Debug, PartialEq, Eq)]
pub enum DoneWait {
    /// done 行を観測した。
    Done(Vec<u8>),
    /// done 行より前にログが上限で打ち切られた（以後のゲスト出力は破棄される）。
    Truncated(Vec<u8>),
    /// 期限内に done 行を観測できなかった。
    TimedOut(Vec<u8>),
}

/// コンソールログを `DONE_POLL_INTERVAL` ごとに読み、`done` が真になるまで期限つきで待つ。
///
/// 判定順は done → 打ち切り → 期限（done が打ち切りに勝つ）。読み込みに失敗した回は前回値を保つ。
/// ログの大きさは書き出しスレッドが `MAX_CONSOLE_LOG_BYTES` で打ち切るため、読み込みは有界（REPAIR-5）。
pub fn wait_done_line(
    log_path: &Path,
    timeout: Duration,
    done: impl Fn(&[u8]) -> bool,
) -> DoneWait {
    let deadline = Instant::now() + timeout;
    let mut last = Vec::new();
    loop {
        if let Ok(bytes) = std::fs::read(log_path) {
            last = bytes;
        }
        if done(&last) {
            return DoneWait::Done(last);
        }
        if log_truncated(&last) {
            return DoneWait::Truncated(last);
        }
        if Instant::now() >= deadline {
            return DoneWait::TimedOut(last);
        }
        std::thread::sleep(DONE_POLL_INTERVAL);
    }
}

/// 失敗側の `DoneWait` の panic message。`Done` は `None`。`label` は `probe` / `link`。
pub fn done_wait_failure_message(
    wait: &DoneWait,
    label: &str,
    timeout: Duration,
) -> Option<String> {
    match wait {
        DoneWait::Done(_) => None,
        DoneWait::Truncated(last) => Some(format!(
            "console log hit the size limit before the {label} done line; console tail:\n{}",
            tail_lossy(last, CONSOLE_TAIL_BYTES)
        )),
        DoneWait::TimedOut(last) => Some(format!(
            "{label} done line not observed within {timeout:?}; console tail:\n{}",
            tail_lossy(last, CONSOLE_TAIL_BYTES)
        )),
    }
}

/// VM 破棄後にログの確定を待ち、確定したログを読み直して返す。
///
/// 確定待ちの失敗には settle 前の `last` の末尾を付ける。読み直したログが上限で打ち切られていれば、
/// done の後のゲスト出力が失われているため `Err`（fail-closed）。
pub fn read_settled_log(
    log_path: &Path,
    last: &[u8],
    label: &str,
    settle_timeout: Duration,
) -> Result<Vec<u8>, String> {
    wait_console_log_settled(log_path, settle_timeout).map_err(|e| {
        format!(
            "{e}; console tail:\n{}",
            tail_lossy(last, CONSOLE_TAIL_BYTES)
        )
    })?;
    let settled =
        std::fs::read(log_path).map_err(|e| format!("read settled console log: {e:?}"))?;
    if log_truncated(&settled) {
        return Err(format!(
            "console log hit the size limit after the {label} done line; later guest output was lost; console tail:\n{}",
            tail_lossy(&settled, CONSOLE_TAIL_BYTES)
        ));
    }
    Ok(settled)
}

/// VM を起動し、done 行を期限つきで待って停止し、確定したコンソールログを返す。
///
/// `virtiofs_io::boot_and_probe` と `virtiofs_link::boot_and_observe` から呼ばれる。ゲストとの TOCTOU を
/// 避けるため、停止（`Stopped`）と VM の破棄、ログの確定まで済ませてから返る。呼び出し側は戻りの
/// bytes を復号し、共有の検証・観測をそのあとに行う。失敗は panic（試験の補助）。
#[cfg(target_os = "macos")]
#[allow(
    dead_code,
    reason = "virtiofs_harness の単体試験 target では使わない（各 tests/*.rs は別 crate）"
)]
pub fn launch_until_done(
    spec: &VmConfigSpec,
    log_path: &Path,
    label: &str,
    timeout: Duration,
    done: impl Fn(&[u8]) -> bool,
) -> Vec<u8> {
    let vm = match Vm::launch(spec, OpTimeouts::default()) {
        Ok(vm) => vm,
        Err(e) => panic!("launch failed: code={} message={}", e.code(), e.message()),
    };
    let wait = wait_done_line(log_path, timeout, done);
    if let Some(msg) = done_wait_failure_message(&wait, label, timeout) {
        // 上限後のゲスト出力は破棄されるため、待っても done は観測できない。明示的に失敗させる。
        let _ = vm.stop();
        panic!("{msg}");
    }
    let DoneWait::Done(last) = wait else {
        unreachable!("failure variants returned a message above")
    };
    // ゲストとの TOCTOU を避けるため、停止を確認してから共有の中身を検証する。
    vm.stop().expect("stop");
    assert_eq!(vm.state(), VmState::Stopped);
    // stop は VM の停止だけを待ち、pipe からログへの書き出しは非同期に続く。VM を破棄して書き込み端を
    // 閉じ、書き出しスレッドの終了（lock の解放）を確認してから確定したログで最終判定する。
    drop(vm);
    read_settled_log(log_path, &last, label, CONSOLE_LOG_SETTLE_TIMEOUT)
        .unwrap_or_else(|m| panic!("{m}"))
}
