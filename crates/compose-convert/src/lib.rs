//! fandhe-container-compose-convert: `compose.yaml` → TOML の片方向変換ツール。
//!
//! 変換器の本体は未実装（TASK-1.3・REPAIR-1。スタブの明示は REPAIR-3）。
//! bin は未実装を構造化して返す雛形（TASK-151.0・#1070・STACK-3）。
//! `fandhe-container-stack` への一方向の path 依存は配線済みで、型の利用は TASK-151.7（#602）以降。
//! 本体は G11（TASK-151 が変換器本体、TASK-152・153・154・156・182）で実装する。
//! plugin ではない独立ツールで、PLUG-1 区分の対象外（crate-naming.md 決定 5）。

use std::io::Write;
use std::process::ExitCode;

/// 未実装時の終了コード。CLI の ERR-2 の慣行（8 = 未実装）に合わせる。core へ依存しないため値を直接書く。
pub const UNIMPLEMENTED_EXIT_CODE: u8 = 8;

/// 未実装を表す固定の 1 行 JSON（stderr へ出す）。argv・環境変数の値は埋め込まない。
pub const UNIMPLEMENTED_JSON: &str =
    "{\"code\":\"UNIMPLEMENTED\",\"message\":\"compose-convert is not implemented yet\"}";

/// bin の入口から呼ばれる stub。引数は解釈せず、stderr へ固定文言を出して終了コード 8 を返す。
/// stdout は将来 TOML を出す経路のため何も書かない。書き込み失敗でも panic しない（REPAIR-3）。
pub fn run() -> ExitCode {
    let _ = writeln!(std::io::stderr(), "{UNIMPLEMENTED_JSON}");
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
}
