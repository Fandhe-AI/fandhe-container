#!/usr/bin/env bash
# scripts/check-agents-ci-consistency.sh の自己テスト（TASK-94.1・REPAIR-10・REPAIR-12）。
#
# 役割: 固定 fixture（scripts/testdata/agents-ci-consistency/）を用い、照合スクリプトの
# 終了コードを具体値で照合する。受け入れ基準「AGENTS.md 記載コマンドと CI 設定の
# 齟齬を検出できる」ことを CI 上で毎回機械照合する（REPAIR-12）。
# 呼び出し元は Makefile の `agents-ci-check-selftest` ターゲットと
# `.github/workflows/ci.yml` の `bench-regression` ジョブ末尾のステップ。
#
# fixture は `ok/`（AGENTS.md.txt・ci.yml.txt・Makefile.txt の 3 点セット）を基準にし、
# 各不一致ケースは壊した 1 ファイルだけを持つ（他の 2 ファイルは ok/ を使い回す。
# scripts/check-bench-regression-selftest.sh と同じ run_case 形式）。
#
# 期待と異なる終了コードが 1 件でもあれば非ゼロで終了する（fail-closed）。

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
check_script="${script_dir}/check-agents-ci-consistency.sh"
fixtures_dir="${script_dir}/testdata/agents-ci-consistency"
ok_dir="${fixtures_dir}/ok"

failures=0

# 引数: <ケース名> <AGENTS.md> <ci.yml> <Makefile> <期待終了コード>
run_case() {
  local name="$1"
  local agents_arg="$2"
  local ci_arg="$3"
  local makefile_arg="$4"
  local expected="$5"
  local actual=0

  bash "$check_script" "$agents_arg" "$ci_arg" "$makefile_arg" >/dev/null 2>&1 || actual=$?

  if [ "$actual" -eq "$expected" ]; then
    echo "PASS: ${name} (exit=${actual})"
  else
    echo "FAIL: ${name} (expected exit=${expected}, actual exit=${actual})" >&2
    failures=$((failures + 1))
  fi
}

# 基準 fixture は齟齬なし（0）
run_case "ok" "${ok_dir}/AGENTS.md.txt" "${ok_dir}/ci.yml.txt" "${ok_dir}/Makefile.txt" 0

# REPAIR-5: ジョブ全体の timeout-minutes が AGENTS.md の記載と食い違う（1）
run_case "timeout-mismatch" "${ok_dir}/AGENTS.md.txt" "${fixtures_dir}/timeout-mismatch/ci.yml.txt" "${ok_dir}/Makefile.txt" 1

# REPAIR-5: 結合試験の実行ステップ timeout-minutes が食い違う（1）
run_case "step-timeout-mismatch" "${ok_dir}/AGENTS.md.txt" "${fixtures_dir}/step-timeout-mismatch/ci.yml.txt" "${ok_dir}/Makefile.txt" 1

# REPAIR-5: FANDHE_CONTAINER_TEST_TIMEOUT_SECS が食い違う（1）
run_case "env-timeout-mismatch" "${ok_dir}/AGENTS.md.txt" "${fixtures_dir}/env-timeout-mismatch/ci.yml.txt" "${ok_dir}/Makefile.txt" 1

# REPAIR-10: AGENTS.md に載っているコマンドが Makefile に存在しない（1）
run_case "missing-target" "${fixtures_dir}/missing-target/AGENTS.md.txt" "${ok_dir}/ci.yml.txt" "${ok_dir}/Makefile.txt" 1

# REPAIR-10: 注記の cargo コマンドが Makefile レシピと食い違う（1）
run_case "cargo-cmd-mismatch" "${fixtures_dir}/cargo-cmd-mismatch/AGENTS.md.txt" "${ok_dir}/ci.yml.txt" "${ok_dir}/Makefile.txt" 1

# TASK-94: 対応表が参照するジョブが ci.yml に存在しない（1）
run_case "missing-job" "${fixtures_dir}/missing-job/AGENTS.md.txt" "${ok_dir}/ci.yml.txt" "${ok_dir}/Makefile.txt" 1

# TASK-94: 回帰確認コマンド一覧にあるコマンドが対応表に無い（網羅性。1）
run_case "unmapped-command" "${fixtures_dir}/unmapped-command/AGENTS.md.txt" "${ok_dir}/ci.yml.txt" "${ok_dir}/Makefile.txt" 1

# TASK-94: ci-complete.needs と AGENTS.md の列挙が食い違う（1）
run_case "needs-mismatch" "${fixtures_dir}/needs-mismatch/AGENTS.md.txt" "${ok_dir}/ci.yml.txt" "${ok_dir}/Makefile.txt" 1

# PR #1097 codex レビュー P1 の回帰確認: 対応表（各コマンドと CI ジョブの対応）の
# 右列ジョブ名が存在するだけでなく、左列の各ターゲットがそのジョブの実行ステップ
# から実際に到達できるかを照合する。bench-regression ジョブから
# `make bench-check` の呼び出しステップを削除しても、これまではジョブ名の存在
# チェックだけを通って合格（0）になっていたが、削除後は不一致として fail（1）
# すること（拡張した AGENTS.md.txt/Makefile.txt を使い、ok/ci.yml.txt を基準に
# ステップを 1 つ削った ci.yml.txt と比較する）。
run_case "step-removed-baseline" "${fixtures_dir}/step-removed/AGENTS.md.txt" "${ok_dir}/ci.yml.txt" "${fixtures_dir}/step-removed/Makefile.txt" 0
run_case "step-removed" "${fixtures_dir}/step-removed/AGENTS.md.txt" "${fixtures_dir}/step-removed/ci.yml.txt" "${fixtures_dir}/step-removed/Makefile.txt" 1

# PR #1097 codex レビュー P1 の回帰確認: 対応表の実行内容照合が `run:` のコマンドを
# ステップ単位ではなくジョブ本文全体へのテキスト検索で行っていたため、
# `cargo test --workspace --test '*' --no-run`（ビルド用ステップ）が実行コマンド
# `cargo test --workspace --test '*'`（`--no-run` なし）を部分文字列として含み、
# 実行ステップ自体を削除してもビルド用ステップへの一致で誤って合格していた。
# baseline（ビルド用ステップ・実行ステップの両方が揃っている）は合格（0）のまま、
# 実行ステップだけを削除した fixture は不一致として fail（1）すること。
run_case "no-run-collision-baseline" "${fixtures_dir}/no-run-collision-baseline/AGENTS.md.txt" "${fixtures_dir}/no-run-collision-baseline/ci.yml.txt" "${fixtures_dir}/no-run-collision-baseline/Makefile.txt" 0
run_case "no-run-collision" "${fixtures_dir}/no-run-collision/AGENTS.md.txt" "${fixtures_dir}/no-run-collision/ci.yml.txt" "${fixtures_dir}/no-run-collision/Makefile.txt" 1

# OSS-4/OSS-5: cargo-deny バージョンが Makefile と ci.yml で食い違う（1）
run_case "deny-version-mismatch" "${ok_dir}/AGENTS.md.txt" "${ok_dir}/ci.yml.txt" "${fixtures_dir}/deny-version-mismatch/Makefile.txt" 1

# REPAIR-7: 想定する見出し（アンカー）が無く解析できない → 入力エラー（2。fail-closed）
run_case "no-anchor" "${fixtures_dir}/no-anchor/AGENTS.md.txt" "${ok_dir}/ci.yml.txt" "${ok_dir}/Makefile.txt" 2

# REPAIR-10 レビュー修正の回帰確認: 「結合試験の実行ステップ」行が無い場合、
# grep -oE の非マッチで `set -e` により無出力 exit 1 で落ちず、
# anchor-not-found のメッセージ付き exit 2 で止まること（fail-closed の経路自体を検証）
run_case "missing-step-anchor" "${fixtures_dir}/missing-step-anchor/AGENTS.md.txt" "${ok_dir}/ci.yml.txt" "${ok_dir}/Makefile.txt" 2

# PR #1097 codex レビュー P0 の回帰確認: 「ジョブ全体」表に列挙された
# *ローカル*ジョブ（`uses:` を持たず `steps:` で実行する bench-regression 等）から
# timeout-minutes が消えたら、5-3 節の graceful-degradation（note 出力・continue）
# ではなく不一致として fail（1）すること。note で素通りしてよいのは
# reusable workflow 呼び出し（`uses:` を持つジョブ。lint-docs・rust-ci 等）に
# 限る（このジョブは Fandhe-AI/actions 側の設定を要し本スクリプトの照合範囲外）。
run_case "missing-job-timeout" "${ok_dir}/AGENTS.md.txt" "${fixtures_dir}/missing-job-timeout/ci.yml.txt" "${ok_dir}/Makefile.txt" 1

# 上記 P0 修正の反例確認: reusable workflow 呼び出しジョブ（`uses:` を持つ
# lint-docs）を「ジョブ全体」表に加えても、timeout-minutes 未検出は
# note のみに留まり合格（0）のままであること（照合できない範囲の正しい免除）
run_case "reusable-job-timeout-exempt" "${fixtures_dir}/reusable-job-timeout-exempt/AGENTS.md.txt" "${ok_dir}/ci.yml.txt" "${ok_dir}/Makefile.txt" 0

# 存在しないファイル → 入力エラー（2）
run_case "missing-file" "${ok_dir}/AGENTS.md.txt" "${ok_dir}/ci.yml.txt" "${fixtures_dir}/does-not-exist.txt" 2

# 引数不足 → 入力エラー（2）
actual=0
bash "$check_script" "${ok_dir}/AGENTS.md.txt" "${ok_dir}/ci.yml.txt" >/dev/null 2>&1 || actual=$?
if [ "$actual" -eq 2 ]; then
  echo "PASS: arg-count (exit=${actual})"
else
  echo "FAIL: arg-count (expected exit=2, actual exit=${actual})" >&2
  failures=$((failures + 1))
fi

if [ "$failures" -gt 0 ]; then
  echo "self-test failed: ${failures} case(s) did not match the expected exit code" >&2
  exit 1
fi

echo "self-test passed: all cases matched the expected exit code"
