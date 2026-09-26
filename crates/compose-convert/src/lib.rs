//! fandhe-container-compose-convert: `compose.yaml` → TOML の片方向変換ツール。
//!
//! 現状は雛形のみで、実装はない（TASK-1.3・REPAIR-1。スタブの明示は REPAIR-3）。
//! 本体は G11（TASK-151 が crate 雛形・変換器本体、TASK-152・153・154・156・182）で実装する。
//! `fandhe-container-stack` の TOML 型を使う一方向依存（決定 5。逆方向の依存を作らない）。
//! plugin ではない独立ツールで、PLUG-1 区分の対象外（crate-naming.md 決定 5）。
