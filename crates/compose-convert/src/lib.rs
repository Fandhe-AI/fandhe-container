//! fandhe-container-compose-convert: `compose.yaml` → TOML の片方向変換ツール。
//!
//! YAML の読み込みとアンカー / マージキーの展開は [`compose_convert`] で実装済み（TASK-151.1・#595）。
//! GPU 予約の検出（`gpu_reservation`。TASK-156.1・STACK-9）も実装済み。
//! キー分類表（`classify`。TASK-151.2・#596・STACK-3）も実装済み。
//! `container_name`・`working_dir` の変換（TASK-153.1・#609・STACK-6）も実装済み。
//! `security_opt`・`cap_drop` の変換（TASK-153.2・#610・STACK-6）も実装済み。`cap_add` はオーナー判断待ちで error-unsupported-yet。
//! `stdin_open`・`tty` の変換（TASK-153.3・#611・STACK-6）も実装済み。`create` への写しは未実装（REPAIR-3）。
//! 入力ディレクトリの走査・読み込みとエラーの終了コード対応（`input_scan`。TASK-151.5・#600・STACK-3）も実装済み。
//! スカラーと short syntax キーの TOML 変換（`convert`・`shell_split`。TASK-151.3.1・#864・STACK-3・MS-12）も実装済み。
//! マッピング配列キー（long syntax）の short syntax への変換（`long_syntax`。TASK-151.3.2・#865・STACK-3）も実装済みで、`convert` へ結線済み（#599）。
//! ファイル単位のレポートと `error_free` 判定（`report`。TASK-151.4・#599・STACK-3）も実装済み。
//! キーパスの走査器（`key_scan`。TASK-151.6・#601・STACK-3）も実装済み。
//! `build:` と Docker ソケット bind（short / long syntax）のエラーへの外部手順の案内の付与は TASK-154.1（`classify`・`report`・`report_json`・#614・STACK-7）で実装済み。移行手順の文書（`docs/design/build-migration.md`）は TASK-154.2（#615）。
//! 引数解析とレポート出力（`entry`・`report_json`）、bin の結線は TASK-151.7（#602・STACK-3）で実装済み。
//! bin は入力ディレクトリを受け取り、キー単位の変換レポート（4 分類・unrecognized の件数・`value_drops`・`downgraded`）を
//! stderr へ 1 行 JSON で出す。stdout は将来 TOML を出す経路として空けてあり、TOML の書き出しは未実装（REPAIR-3）。
//! `--downgrade=<key>[,...]` の解析と格下げ許可の判定は `downgrade`（TASK-182.1・#627・STACK-3）で実装済み。
//! 不可のキーの指定は変換せず `INVALID_ARGUMENT`（2）で止める。
//! depends_on・ulimits・healthcheck・deploy の変換は未実装（`ServiceConversion::unhandled` に載る。REPAIR-3）。
//! `fandhe-container-stack` への一方向の path 依存は配線済み。YAML パーサーの依存は本 crate に限り、
//! `fandhe-container-cli`・`fandhe-container-stack` の依存木には現れない（TASK-155 の経路へリンクしない）。
//! 本体は G11（TASK-151 が変換器本体、TASK-152・153・154・156・182）で実装する。
//! plugin ではない独立ツールで、PLUG-1 区分の対象外（crate-naming.md 決定 5）。

pub mod classify;
pub mod compose_convert;
pub mod convert;
pub mod downgrade;
pub mod entry;
pub mod gpu_reservation;
pub mod input_scan;
pub mod key_scan;
pub mod long_syntax;
pub mod report;
pub mod report_json;
pub mod shell_split;

use std::ffi::OsString;
use std::io::Write;
use std::process::ExitCode;
use std::sync::mpsc;
use std::time::Duration;

/// stderr への書き込み完了を待つ基準時間（REPAIR-5）。出力量に応じて [`write_timeout_for`] が加算する。
const STDERR_WRITE_BASE_TIMEOUT: Duration = Duration::from_secs(2);

/// 出力 1 MiB ごとに加える待ち時間。
const STDERR_WRITE_PER_MIB: Duration = Duration::from_secs(1);

/// 待ち時間の上限。
const STDERR_WRITE_MAX_TIMEOUT: Duration = Duration::from_secs(30);

/// 未実装時の終了コード。CLI の ERR-2 の慣行（8 = 未実装）に合わせる。core へ依存しないため値を直接書く。
pub use entry::UNIMPLEMENTED_EXIT_CODE;

/// 出力量に比例した書き込みの待ち時間（基準 2 秒 + 1 MiB ごとに 1 秒、上限 30 秒）。
fn write_timeout_for(len: usize) -> Duration {
    let mib = u32::try_from(len / (1024 * 1024)).unwrap_or(u32::MAX);
    STDERR_WRITE_BASE_TIMEOUT
        .saturating_add(STDERR_WRITE_PER_MIB.saturating_mul(mib))
        .min(STDERR_WRITE_MAX_TIMEOUT)
}

/// bin の入口から呼ばれる。引数を [`entry::run_args`] で処理し、レポートを stderr へ書いて終了コードを返す。
/// stdout は将来 TOML を出す経路のため何も書かない。書き込みが失敗・期限切れのときは、レポートが届いていないため
/// 成功を返さず終了コード 1（INTERNAL）にする。stderr が満杯で読み手が止まっていても、書き込みは別スレッドで行い
/// 有限の期限で待つため戻れる（REPAIR-5）。
pub fn run() -> ExitCode {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    let outcome = entry::run_args(&args);
    let timeout = write_timeout_for(outcome.stderr.len());
    let text = outcome.stderr;
    let delivered = write_with_deadline(timeout, move || {
        let mut err = std::io::stderr().lock();
        err.write_all(text.as_bytes())?;
        err.flush()
    });
    if delivered {
        ExitCode::from(outcome.exit_code)
    } else {
        ExitCode::from(1)
    }
}

/// `write` を別スレッドで実行し、`timeout` までだけ完了を待つ。成功（`Ok`）で完了したときだけ true。
/// 期限切れ・スレッド起動失敗・書き込み失敗は false。期限切れでも書き込みスレッドの完了は待たない
/// （プロセス終了時に破棄される）。
fn write_with_deadline<F>(timeout: Duration, write: F) -> bool
where
    F: FnOnce() -> std::io::Result<()> + Send + 'static,
{
    let (tx, rx) = mpsc::channel::<bool>();
    let spawned = std::thread::Builder::new()
        .name("compose-convert-stderr".to_string())
        .spawn(move || {
            let _ = tx.send(write().is_ok());
        });
    spawned.is_ok() && rx.recv_timeout(timeout).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// STACK-3・REPAIR-12: 未実装の終了コードは 8。
    #[test]
    fn unimplemented_exit_code_is_8() {
        assert_eq!(UNIMPLEMENTED_EXIT_CODE, 8);
    }

    /// REPAIR-5: 待ち時間は出力量に比例し、上限を超えない。
    #[test]
    fn write_timeout_scales_with_output() {
        assert_eq!(write_timeout_for(0), Duration::from_secs(2));
        assert_eq!(write_timeout_for(3 * 1024 * 1024), Duration::from_secs(5));
        assert_eq!(write_timeout_for(usize::MAX), Duration::from_secs(30));
    }

    /// REPAIR-5・REPAIR-12: 書き込みが戻らなくても期限内に false で戻る。
    #[test]
    fn blocked_writer_returns_false_after_timeout() {
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let timeout = Duration::from_millis(200);
        let start = std::time::Instant::now();
        let ok = write_with_deadline(timeout, move || {
            let _ = release_rx.recv();
            Ok(())
        });
        let elapsed = start.elapsed();
        assert!(!ok);
        assert!(elapsed >= timeout, "returned early: {elapsed:?}");
        assert!(elapsed < Duration::from_secs(5), "too slow: {elapsed:?}");
        let _ = release_tx.send(());
    }

    /// REPAIR-5: 書き込み成功は true、失敗は false。
    #[test]
    fn writer_result_is_reported() {
        assert!(write_with_deadline(Duration::from_secs(5), || Ok(())));
        assert!(!write_with_deadline(Duration::from_secs(5), || Err(
            std::io::Error::other("x")
        )));
    }
}
