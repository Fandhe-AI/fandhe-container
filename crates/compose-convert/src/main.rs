//! バイナリ `fandhe-container-compose-convert` の入口（薄い入口。実体は lib の `run`）。
//!
//! 使い方: `fandhe-container-compose-convert [--] <input_dir>`。入力ディレクトリ直下の `yml` / `yaml` を全件読み、
//! ファイルごとのキー単位の変換レポート（4 分類・unrecognized の件数・`value_drops`・`downgraded`・`error_free`）を
//! stderr へ 1 ファイル 1 行の JSON で出し、最後に集計行を出す（TASK-151.7・#602・STACK-3）。
//! stdout は将来 TOML を出す経路として空けてあり、何も書かない（TOML の書き出しは未実装。REPAIR-3）。
//! `--downgrade` は TASK-182（#627）まで未実装として拒否する。
//!
//! 終了コード: 0 = レポートを出し終えた（`error_free` でないファイルがあっても 0。判断はレポートの `error_free` で行う）、
//! 2 = 引数の誤り・同名 `file_id` の重複、3 = 入力が無い、6 = 権限不足、10 = 上限超過、1 = 内部エラー・書き込み失敗、
//! 8 = 未実装（ERR-2 の慣行）。
#![deny(unsafe_code)]

fn main() -> std::process::ExitCode {
    fandhe_container_compose_convert::run()
}
