//! fandhe-container-compose-convert: `compose.yaml` → TOML の片方向変換ツール。
//!
//! YAML の読み込みとアンカー / マージキーの展開は [`compose_convert`] で実装済み（TASK-151.1・#595）。
//! GPU 予約の検出（`gpu_reservation`。TASK-156.1・STACK-9）も実装済み。
//! キー分類表（`classify`。TASK-151.2・#596・STACK-3）も実装済み。
//! 入力ディレクトリの走査・読み込みとエラーの終了コード対応（`input_scan`。TASK-151.5・#600・STACK-3）も実装済み（bin への結線は #602）。
//! TOML 変換以降の変換器の本体は未実装（TASK-1.3・REPAIR-1。スタブの明示は REPAIR-3）。
//! bin は未実装を構造化して返す雛形（TASK-151.0・#1070・STACK-3）。
//! `fandhe-container-stack` への一方向の path 依存は配線済みで、型の利用は TASK-151.7（#602）以降。
//! 本体は G11（TASK-151 が変換器本体、TASK-152・153・154・156・182）で実装する。
//! plugin ではない独立ツールで、PLUG-1 区分の対象外（crate-naming.md 決定 5）。

pub mod classify;
pub mod compose_convert;
pub mod gpu_reservation;
pub mod input_scan;

use std::io::Write;
use std::process::ExitCode;
use std::sync::mpsc;
use std::time::Duration;

/// stderr への書き込み完了を待つ上限（REPAIR-5）。読み手が止まった pipe / socket でも終了コードを返すため。
const STDERR_WRITE_TIMEOUT: Duration = Duration::from_secs(2);

/// 未実装時の終了コード。CLI の ERR-2 の慣行（8 = 未実装）に合わせる。core へ依存しないため値を直接書く。
pub const UNIMPLEMENTED_EXIT_CODE: u8 = 8;

/// 未実装を表す固定の 1 行 JSON（stderr へ出す）。argv・環境変数の値は埋め込まない。
pub const UNIMPLEMENTED_JSON: &str =
    "{\"code\":\"UNIMPLEMENTED\",\"message\":\"compose-convert is not implemented yet\"}";

/// bin の入口から呼ばれる stub。引数は解釈せず、stderr へ固定文言を出して終了コード 8 を返す。
/// stdout は将来 TOML を出す経路のため何も書かない。書き込み失敗でも panic しない（REPAIR-3）。
/// stderr が満杯で読み手が止まっていても、書き込みは別スレッドで行い有限の期限で待つため戻れる（REPAIR-5）。
pub fn run() -> ExitCode {
    run_with(STDERR_WRITE_TIMEOUT, || {
        let _ = writeln!(std::io::stderr(), "{UNIMPLEMENTED_JSON}");
    })
}

/// `write` を別スレッドで実行し、`timeout` までだけ完了を待って終了コード 8 を返す。
/// 期限切れ・スレッド起動失敗でも書き込みスレッドの完了は待たない（プロセス終了時に破棄される）。
fn run_with<F>(timeout: Duration, write: F) -> ExitCode
where
    F: FnOnce() + Send + 'static,
{
    let (tx, rx) = mpsc::channel::<()>();
    let spawned = std::thread::Builder::new()
        .name("compose-convert-stderr".to_string())
        .spawn(move || {
            write();
            let _ = tx.send(());
        });
    if spawned.is_ok() {
        let _ = rx.recv_timeout(timeout);
    }
    ExitCode::from(UNIMPLEMENTED_EXIT_CODE)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// STACK-3・REPAIR-12: 未実装の終了コードは 8。
    #[test]
    fn unimplemented_exit_code_is_8() {
        assert_eq!(UNIMPLEMENTED_EXIT_CODE, 8);
    }

    /// STACK-3・REPAIR-3: 固定 JSON は ASCII の 1 行で code と message を持つ。
    #[test]
    fn unimplemented_json_is_single_ascii_line() {
        assert!(!UNIMPLEMENTED_JSON.contains('\n'));
        assert!(UNIMPLEMENTED_JSON.is_ascii());
        assert!(UNIMPLEMENTED_JSON.contains("\"code\":\"UNIMPLEMENTED\""));
        assert!(UNIMPLEMENTED_JSON.contains("\"message\":"));
    }

    /// REPAIR-5・REPAIR-12: 書き込みが戻らなくても期限内に終了コード 8 で戻る。
    #[test]
    fn blocked_writer_returns_exit_code_after_timeout() {
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let timeout = Duration::from_millis(200);
        let start = std::time::Instant::now();
        let code = run_with(timeout, move || {
            let _ = release_rx.recv();
        });
        let elapsed = start.elapsed();
        assert!(elapsed >= timeout, "returned early: {elapsed:?}");
        assert!(elapsed < Duration::from_secs(5), "too slow: {elapsed:?}");
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::from(8)));
        let _ = release_tx.send(());
    }
}
