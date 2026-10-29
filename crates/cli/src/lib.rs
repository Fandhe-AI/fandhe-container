//! fandhe-container-cli: 統一 CLI・基本コマンド（create/start/stop/delete/list/logs/ps）、観測性。
//!
//! [`doctor`] は判定材料取得（TASK-148.1）と評価層（警告・DOCKER-USER 案内・終了コード。TASK-148.2・NET-10）に加え、
//! `systemd-run` と user マネージャの前提の診断（CORE-3・CORE-4）を持ち、サブコマンド `doctor` として結線済み（#2133）。
//! バイナリ `fandhe-container` の入口と [`commands`] の骨格は TASK-79.1（#638・CLI-1・MS-6）で追加した。
//! `create` は core を直接呼ぶ（TASK-79.2.1・#866）。`start` は supervisor の bin を起動して結果を期限付きで受け取る（#1718。supervisor が core の本番 launcher で起動する。rootless のみ）。
//! `stop` / `delete` は TASK-79.2.2、`list` は状態ストアから一覧を出し、`logs` は存在確認の後に supervisor の読み出し入口でコンテナログを出す（TASK-79.3・#640・#1543）。
//! [`error`] は ERR-1 の構造化エラー型と stderr 出力（TASK-95.1・#649）。各コマンドの終了経路（`commands::CliExit`）へ配線済み（TASK-95.2・#650）。
//! `setup` は OS 固有設定の要求ステップを提示する（TASK-80.1・CLI-2。Linux は rootful の特権ランチャーのインストール手順の表示のみ〔#1722〕。検出・適用は未実装。日常操作コマンドからは到達しない。TASK-80.2）。
//! `signals` は親が受けた SIGINT・SIGTERM・SIGHUP を起動中の plugin へ転送してから終了する（#1513・PLUG-7。unix のみ）。
//! それ以外は雛形のまま実装がない（TASK-1.3・REPAIR-1）。
//! 本体は G6（TASK-79〜98 の一部。crate の中核成果物は TASK-79〔基本コマンド〕・TASK-95〔エラー形式〕）で
//! 実装する。PLUG-1 区分は core（crate-naming.md）。

// `signal-test-support` は試験専用の入口（固定の記録ハンドラの登録と読み出し）を公開する feature で、製品の
// バイナリに含める理由がない。最適化ビルド（`debug_assertions` が無効）で有効になっていたらコンパイルを止める
// （#1513・PLUG-7・REPAIR-3。supervisor・core の `exec-test-support` と同じ方式。テスト・clippy は dev プロファイル
// のため影響しない）。
#[cfg(all(feature = "signal-test-support", not(debug_assertions)))]
compile_error!(
    "the `signal-test-support` feature exposes test-only signal handler entry points and must not be enabled in release builds"
);

// `start-test-support` は start の systemd-run の解決を環境変数で差し替える試験専用の入口を有効にする feature で、
// 製品のバイナリに含める理由がない。最適化ビルドで有効になっていたらコンパイルを止める（#2081・CORE-3・REPAIR-3。
// `signal-test-support` と同じ方式）。
#[cfg(all(feature = "start-test-support", not(debug_assertions)))]
compile_error!(
    "the `start-test-support` feature lets the systemd-run path be overridden by an environment variable and must not be enabled in release builds"
);

// `logs-test-support` は logs --follow の期限を環境変数で短くする試験専用の入口を有効にする feature で、製品のバイナリに
// 含める理由がない。最適化ビルドで有効になっていたらコンパイルを止める（#2447・CLI-1・REPAIR-3。`start-test-support` と同じ方式）。
#[cfg(all(feature = "logs-test-support", not(debug_assertions)))]
compile_error!(
    "the `logs-test-support` feature lets the logs --follow deadline be overridden by an environment variable and must not be enabled in release builds"
);

pub mod commands;
pub mod doctor;
pub mod error;
#[cfg(target_os = "linux")]
pub mod image_ownership;
mod json;
pub mod setup;
#[cfg(unix)]
pub mod signals;
#[cfg(unix)]
pub(crate) mod sys;
#[cfg(target_os = "linux")]
pub(crate) mod user_scope;

// 単体試験の一時領域の親を tmpfiles の flock 走査から守る共有部品（#3141・CORE-5・REPAIR-12）。
// 利用者が Linux 限定のため Linux の試験ビルドだけで取り込む。試験専用で製品・rlib に影響しない。
#[cfg(all(test, target_os = "linux"))]
#[path = "../../core/tests/support/scratch_root.rs"]
mod scratch_root;

// pid だけの名前の一時ディレクトリを残骸に強くする共有部品（oci の結合試験の補助を取り込む。
// REPAIR-12・#3375）。試験専用で製品・rlib に影響しない。
#[cfg(test)]
#[path = "../../oci/tests/support/test_root.rs"]
mod test_root;
