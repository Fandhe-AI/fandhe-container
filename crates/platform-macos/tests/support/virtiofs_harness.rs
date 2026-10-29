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
//! `Vm` を使う起動・待ちループや、untrusted なゲスト出力を扱う検証・観測は各試験に残す（共通化しない）。

use std::path::Path;
use std::time::{Duration, Instant};

use fandhe_container_platform_macos::console_log::TRUNCATION_MARKER;

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
