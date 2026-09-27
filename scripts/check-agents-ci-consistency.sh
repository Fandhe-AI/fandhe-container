#!/usr/bin/env bash
# AGENTS.md 記載コマンドと CI 設定の機械照合（TASK-94.1・REPAIR-10・REPAIR-12）。
#
# 役割: AGENTS.md の「回帰確認コマンド一覧」節・「各コマンドと CI ジョブの対応」表・
# 「推奨タイムアウト値」表・`make ci` の成功基準行・ci-complete の needs 記述が、
# 実際の Makefile・.github/workflows/ci.yml と食い違っていないかを機械照合する。
# AGENTS.md は REPAIR-10（Codex レビューの基準）が「内容と実際の CI 設定に齟齬が
# ないこと」を求めており、一度の目視確認で終わらせず CI 上で毎回照合する
# （REPAIR-12。受け入れ基準を機械照合するテストを置く）。
# 呼び出し元は Makefile の `agents-ci-check` ターゲットと
# `.github/workflows/ci.yml` の `bench-regression` ジョブ末尾のステップ
# （新規ジョブを追加すると check-run 名が増え ruleset 更新〔オーナー作業〕が
# 要るため、既存ジョブへステップとして追加している。詳細は ci.yml のコメント）。
#
# 使い方: check-agents-ci-consistency.sh <AGENTS.md> <ci.yml> <Makefile>
#
# 終了コード:
#   0: 合格（照合した全項目が一致）
#   1: 齟齬を検出（1 件以上の不一致。全件を報告してから終了する）
#   2: 入力エラー（引数不正・ファイルなし・サイズ超過・想定するアンカー（節見出し・
#      テーブル）が見つからない・jq 未導入）。解析できない場合は合格扱いにしない
#      （fail-closed。REPAIR-10 の P0 観点「回帰検出の後退」を作らない）
#
# 照合できる範囲: リポジトリ内のファイルだけで完結する項目に限る。
# `Fandhe-AI/actions` の reusable workflow（`@latest` 参照）の中身は
# ネットワーク取得が必要なため対象外（手動確認。PR 本文に記録する）。
# YAML の一般的な構文解析は行わず、現行 ci.yml の書式
# （jobs: 直下は 2 スペース、ジョブ本体は 4 スペース、ステップ内は 8 スペース
# インデント）を前提にした awk 抽出で済ませる。前提が崩れて解析できない場合は
# 黙って合格にせず exit 2 で止める。

set -euo pipefail

readonly MAX_FILE_BYTES=1048576

err() {
  # ERR 系の構造化形式（.claude/rules/coding-rust.md）に揃える。
  echo "error: $1: $2" >&2
}

note() {
  echo "notice: $1" >&2
}

if [ "$#" -ne 3 ]; then
  err "arg-count" "usage: check-agents-ci-consistency.sh <AGENTS.md> <ci.yml> <Makefile>"
  exit 2
fi

agents_file="$1"
ci_file="$2"
makefile="$3"

if ! command -v jq >/dev/null 2>&1; then
  err "missing-tool" "jq is required but not found in PATH"
  exit 2
fi

check_input_file() {
  local path="$1"
  if [ -L "$path" ]; then
    err "invalid-input" "$path is a symlink, refusing to read"
    exit 2
  fi
  if [ ! -f "$path" ]; then
    err "invalid-input" "$path does not exist or is not a regular file"
    exit 2
  fi
  local size
  if ! size=$(wc -c <"$path" 2>/dev/null | tr -d ' '); then
    err "invalid-input" "$path could not be read"
    exit 2
  fi
  if [ "$size" -gt "$MAX_FILE_BYTES" ]; then
    err "invalid-input" "$path exceeds ${MAX_FILE_BYTES} bytes"
    exit 2
  fi
}

check_input_file "$agents_file"
check_input_file "$ci_file"
check_input_file "$makefile"

fail_count=0
report() {
  # 不一致は即終了せず集める（全件を報告してから exit 1。bench スクリプトと違い、
  # 本スクリプトは複数の独立した観点を照合するため、1 件目で止めると残りの
  # 齟齬が PR で見つからないまま残る）。
  echo "MISMATCH: $1" >&2
  fail_count=$((fail_count + 1))
}

# --------------------------------------------------
# 1. 「回帰確認コマンド一覧」コードブロックの抽出
# --------------------------------------------------
# 見出しをアンカーにして最初の ```bash フェンスの中身だけを取り出す。
cmd_block="$(awk '
  /^### 回帰確認コマンド一覧/ { in_section = 1; next }
  in_section && /^```bash/ { in_fence = 1; next }
  in_section && in_fence && /^```/ { exit }
  in_fence { print }
  in_section && /^## / { exit }
' "$agents_file")"

if [ -z "$cmd_block" ]; then
  err "anchor-not-found" "AGENTS.md: '### 回帰確認コマンド一覧' の bash コードブロックが見つからない"
  exit 2
fi

# 各行から `make <target>` と、任意の `# cargo ...` 注記を取り出す。
# 対象行以外（空行・注記のみの行）は無視する。
declare -a cmd_targets=()
declare -a cmd_cargo_hints=()
while IFS= read -r line; do
  [ -z "$line" ] && continue
  case "$line" in
    make\ *) ;;
    *) continue ;;
  esac
  target="$(printf '%s' "$line" | awk '{print $2}')"
  if ! printf '%s' "$target" | grep -qE '^[A-Za-z0-9_-]+$'; then
    err "parse-error" "AGENTS.md: 'make ' に続くターゲット名を解釈できない行: ${line}"
    exit 2
  fi
  hint=""
  if printf '%s' "$line" | grep -q '# cargo '; then
    hint="$(printf '%s' "$line" | sed -E 's/^.*# *(cargo [^（]*).*$/\1/' | sed -E 's/[[:space:]]+$//')"
  fi
  cmd_targets+=("$target")
  cmd_cargo_hints+=("$hint")
done <<<"$cmd_block"

if [ "${#cmd_targets[@]}" -eq 0 ]; then
  err "anchor-not-found" "AGENTS.md: '回帰確認コマンド一覧' コードブロックから make ターゲットを 1 件も抽出できない"
  exit 2
fi

# --------------------------------------------------
# 2. コマンド存在チェック・cargo コマンド一致チェック
# --------------------------------------------------
for i in "${!cmd_targets[@]}"; do
  target="${cmd_targets[$i]}"
  hint="${cmd_cargo_hints[$i]}"

  if ! grep -qE "^${target}:" "$makefile"; then
    report "AGENTS.md の回帰確認コマンド一覧にある 'make ${target}' が Makefile に '${target}:' ターゲットとして存在しない"
    continue
  fi

  if [ -n "$hint" ]; then
    recipe="$(awk -v t="^${target}:" '
      $0 ~ t { in_target = 1; next }
      in_target && /^[A-Za-z0-9_.-]+:/ { exit }
      in_target && /^\.PHONY:/ { exit }
      in_target { print }
    ' "$makefile")"
    if ! printf '%s' "$recipe" | grep -qF "$hint"; then
      report "AGENTS.md の 'make ${target}' 注記のコマンド '${hint}' が Makefile の '${target}' レシピに見つからない"
    fi
  fi
done

# --------------------------------------------------
# 3. `make ci` の構成順序チェック
# --------------------------------------------------
ci_row_seq="$(grep -oE '(`[A-Za-z][A-Za-z0-9_-]*`[[:space:]]*→[[:space:]]*)+`[A-Za-z][A-Za-z0-9_-]*`[[:space:]]*の順に実行' "$agents_file" | head -n1 | sed -E 's/の順に実行$//' || true)"
if [ -z "$ci_row_seq" ]; then
  err "anchor-not-found" "AGENTS.md: 'make ci' の構成順序（'... の順に実行'）が見つからない"
  exit 2
fi
agents_ci_order="$(printf '%s' "$ci_row_seq" | grep -oE '`[A-Za-z][A-Za-z0-9_-]*`' | tr -d '`' | tr '\n' ' ' | sed -E 's/[[:space:]]+$//' || true)"

makefile_ci_line="$(grep -E '^ci:' "$makefile" | head -n1 || true)"
if [ -z "$makefile_ci_line" ]; then
  err "anchor-not-found" "Makefile: 'ci:' ターゲットが見つからない"
  exit 2
fi
# `ci: a b c ## comment` から prerequisites だけを取り出す（## 以降のヘルプ文言は除く）。
makefile_ci_order="$(printf '%s' "$makefile_ci_line" | sed -E 's/^ci:[[:space:]]*//; s/##.*$//' | sed -E 's/[[:space:]]+$//')"

if [ "$agents_ci_order" != "$makefile_ci_order" ]; then
  report "AGENTS.md の 'make ci' 構成順序 [${agents_ci_order}] が Makefile の ci: prerequisites [${makefile_ci_order}] と一致しない"
fi

# ジョブブロック（ジョブ名 → 本文）を抽出する補助関数。ジョブ本体は
# 次のジョブ見出し（2 スペースインデント）または EOF までとする。
# 節 4（対応表の実行内容照合）・節 5（タイムアウト値の照合）の両方から使う。
job_block() {
  local name="$1"
  awk -v n="^  ${name}:[[:space:]]*\$" '
    $0 ~ n { in_job = 1; next }
    in_job && /^  [A-Za-z0-9_-]+:[[:space:]]*$/ { exit }
    in_job { print }
  ' "$ci_file"
}

job_level_timeout() {
  # ジョブ本体（4 スペースインデント）の timeout-minutes のみを対象にする
  # （8 スペースインデントのステップ個別 timeout-minutes は含めない）。
  local block="$1"
  # 該当行が無い場合（reusable 呼び出し等）は空文字を返す（grep 非マッチによる
  # 呼び出し元の set -e 停止を避け、呼び出し元の [ -z ] 分岐へ確実に到達させる）。
  printf '%s\n' "$block" | grep -E '^    timeout-minutes:' | head -n1 | grep -oE '[0-9]+' || true
}

job_is_reusable_call() {
  # ジョブ本体（4 スペースインデント）が `uses:`（reusable workflow 呼び出し）を
  # 持つかを判定する。reusable 呼び出しの中身（timeout-minutes・実行ステップ）は
  # `Fandhe-AI/actions` 側（ネットワーク取得が要る）にしか無いため、
  # 「照合できない範囲」として note に留めてよいのはこの場合のみに限る。
  # ローカルジョブ（`steps:` を持つ）はここで検証できるため、未検出は
  # 齟齬として fail させる（P0/P1: Codex レビュー・PR #1097。設定欠落・
  # ステップ削除を notice や無検査で素通りさせない）。
  local block="$1"
  printf '%s\n' "$block" | grep -qE '^    uses:'
}

# make ターゲット名から、回帰確認コマンド一覧（節 1）で記録した
# `# cargo ...` 注記（cmd_cargo_hints）を引く補助関数。無ければ空文字を返す。
cmd_hint_for_target() {
  local tgt="$1"
  local i
  for i in "${!cmd_targets[@]}"; do
    if [ "${cmd_targets[$i]}" = "$tgt" ]; then
      printf '%s' "${cmd_cargo_hints[$i]}"
      return 0
    fi
  done
  printf ''
}

# --------------------------------------------------
# 4. 対応表の網羅性・ジョブ存在・実行内容の到達可能性チェック
#    （各コマンドと CI ジョブの対応）
# --------------------------------------------------
mapping_block="$(awk '
  /^\| コマンド \| 対応する CI ジョブ \|/ { in_table = 1; print; next }
  in_table && /^\|/ { print; next }
  in_table { exit }
' "$agents_file")"

if [ -z "$mapping_block" ]; then
  err "anchor-not-found" "AGENTS.md: '各コマンドと CI ジョブの対応' 表が見つからない"
  exit 2
fi

# ci.yml の jobs: 直下（2 スペースインデント）のジョブ名一覧を抽出する。
job_names="$(awk '
  /^jobs:/ { in_jobs = 1; next }
  in_jobs && /^  [A-Za-z0-9_-]+:[[:space:]]*$/ {
    name = $0
    sub(/^  /, "", name)
    sub(/:[[:space:]]*$/, "", name)
    print name
  }
' "$ci_file")"

if [ -z "$job_names" ]; then
  err "anchor-not-found" "ci.yml: 'jobs:' 直下のジョブが見つからない"
  exit 2
fi

mapped_targets=""
# ヘッダ行・区切り行（|----|----|）を除いた本体行だけを処理する。
table_rows="$(printf '%s\n' "$mapping_block" | tail -n +3)"
while IFS= read -r row; do
  [ -z "$row" ] && continue
  left="$(printf '%s' "$row" | awk -F'|' '{print $2}')"
  right="$(printf '%s' "$row" | awk -F'|' '{print $3}')"

  row_targets="$(printf '%s' "$left" | grep -oE '`[A-Za-z][A-Za-z0-9_-]*`' | tr -d '`' || true)"
  if [ -z "$row_targets" ]; then
    err "parse-error" "AGENTS.md: 対応表の左列を解釈できない行: ${row}"
    exit 2
  fi
  mapped_targets="${mapped_targets}
${row_targets}"

  if printf '%s' "$right" | grep -qF 'CI では直接実行しない'; then
    continue
  fi
  row_jobs="$(printf '%s' "$right" | grep -oE '`[A-Za-z][A-Za-z0-9_-]*`' | tr -d '`' || true)"
  if [ -z "$row_jobs" ]; then
    err "parse-error" "AGENTS.md: 対応表の右列を解釈できない行（ジョブ名も 'CI では直接実行しない' も無い）: ${row}"
    exit 2
  fi
  while IFS= read -r job; do
    [ -z "$job" ] && continue
    if ! printf '%s\n' "$job_names" | grep -qxF "$job"; then
      report "AGENTS.md 対応表が参照するジョブ '${job}'（コマンド: ${left}）が ci.yml の jobs に存在しない"
      continue
    fi

    # 実行内容の到達可能性チェック（P1: Codex レビュー・PR #1097）。
    # ジョブ名が存在するだけでなく、対応表の左列に挙げた各ターゲットが
    # そのジョブの実行ステップから到達可能か（`make <target>` の直接呼び出し、
    # または回帰確認コマンド一覧の `# cargo ...` 注記と同じコマンドの再現）を
    # 照合する。reusable workflow 呼び出し（`uses:`）はステップの中身が
    # `Fandhe-AI/actions` 側（ネットワーク取得が要る）にしか無く本スクリプトの
    # 照合範囲外のため、note に留めて exit 2/1 にはしない。
    job_body="$(job_block "$job")"
    if [ -z "$job_body" ]; then
      # 直前の存在チェックを通っている以上ここには来ないはずだが、
      # 解析前提の崩れ（見出し書式の変化等）を黙って合格にしない。
      err "parse-error" "ci.yml: ジョブ '${job}' の本文を抽出できない（書式前提の崩れの可能性）"
      exit 2
    fi
    if job_is_reusable_call "$job_body"; then
      note "対応表の実行内容照合: '${job}' は reusable workflow 呼び出しのため ci.yml 上でステップの中身を照合できない（手動確認）"
      continue
    fi
    while IFS= read -r tgt; do
      [ -z "$tgt" ] && continue
      hint="$(cmd_hint_for_target "$tgt")"
      if [ -n "$hint" ]; then
        # `grep -qF` によるジョブ本文全体への部分文字列一致だと、
        # `cargo test --workspace --test '*' --no-run`（ビルド用ステップ）が
        # 実行コマンド `cargo test --workspace --test '*'` を部分文字列として
        # 含むため、実行ステップを削除してもビルド用ステップへの一致で
        # 合格してしまう（P1: Codex レビュー・PR #1097）。hint を正規表現
        # エスケープしたうえで、コマンドの前後が行頭 / 空白 / クォート・行末
        # （空白 / クォートのみ許容）であることを要求し、`--no-run` 等の
        # 追加引数を伴う別コマンドを実行コマンドと誤認しないようにする。
        hint_re="$(printf '%s' "$hint" | sed -e 's/[][\.^$*+?(){}|\\]/\\&/g')"
        if printf '%s\n' "$job_body" | grep -qE "(^|[\"'\`[:space:]:|])${hint_re}[[:space:]\"']*\$"; then
          continue
        fi
        report "対応表の実行内容照合: 'make ${tgt}' の注記コマンド '${hint}' がジョブ '${job}' の実行ステップから到達できない（削除・書き換えの可能性）"
        continue
      fi
      if printf '%s' "$job_body" | grep -qE "make[[:space:]]+${tgt}([[:space:]]|\$|')"; then
        continue
      fi
      report "対応表の実行内容照合: 'make ${tgt}' の呼び出しがジョブ '${job}' の実行ステップから到達できない（削除・書き換えの可能性）"
    done <<<"$row_targets"
  done <<<"$row_jobs"
done <<<"$table_rows"

# コードブロックの全ターゲットが対応表の左列に出てくるか（網羅性）。
for target in "${cmd_targets[@]}"; do
  if ! printf '%s\n' "$mapped_targets" | grep -qxF "$target"; then
    report "回帰確認コマンド一覧の 'make ${target}' が対応表（各コマンドと CI ジョブの対応）の左列に見つからない"
  fi
done

# --------------------------------------------------
# 5. タイムアウト値の照合（推奨タイムアウト値節）
# --------------------------------------------------
# 5-1: テスト 1 件の応答待ち（env FANDHE_CONTAINER_TEST_TIMEOUT_SECS）
agents_env_secs="$(grep -oE 'CI 設定値 [0-9]+ 秒' "$agents_file" | head -n1 | grep -oE '[0-9]+' || true)"
if [ -z "$agents_env_secs" ]; then
  err "anchor-not-found" "AGENTS.md: 'CI 設定値 N 秒' の記載が見つからない"
  exit 2
fi
it_block="$(job_block integration-test)"
if [ -z "$it_block" ]; then
  err "anchor-not-found" "ci.yml: integration-test ジョブが見つからない"
  exit 2
fi
ci_env_secs="$(printf '%s\n' "$it_block" | grep -oE 'FANDHE_CONTAINER_TEST_TIMEOUT_SECS:[[:space:]]*"[0-9]+"' | head -n1 | grep -oE '[0-9]+' || true)"
if [ -z "$ci_env_secs" ]; then
  err "anchor-not-found" "ci.yml: integration-test ジョブに FANDHE_CONTAINER_TEST_TIMEOUT_SECS が見つからない"
  exit 2
fi
if [ "$agents_env_secs" != "$ci_env_secs" ]; then
  report "テスト 1 件の応答待ち: AGENTS.md '${agents_env_secs} 秒' が ci.yml の FANDHE_CONTAINER_TEST_TIMEOUT_SECS '${ci_env_secs}' と一致しない"
fi

# 5-2: 結合試験の実行ステップ（step-level timeout-minutes）
agents_step_min="$(grep -A1 '結合試験の実行ステップ' "$agents_file" | grep -oE '[0-9]+ 分' | head -n1 | grep -oE '[0-9]+' || true)"
if [ -z "$agents_step_min" ]; then
  err "anchor-not-found" "AGENTS.md: '結合試験の実行ステップ' の分数が見つからない"
  exit 2
fi
ci_step_min="$(printf '%s\n' "$it_block" | grep -E '^        timeout-minutes:' | head -n1 | grep -oE '[0-9]+' || true)"
if [ -z "$ci_step_min" ]; then
  err "anchor-not-found" "ci.yml: integration-test ジョブの実行ステップに timeout-minutes が見つからない"
  exit 2
fi
if [ "$agents_step_min" != "$ci_step_min" ]; then
  report "結合試験の実行ステップ: AGENTS.md '${agents_step_min} 分' が ci.yml の実行ステップ timeout-minutes '${ci_step_min}' と一致しない"
fi

# 5-3: ジョブ全体（「ジョブ全体」行に列挙された `job` N 分 の組）
overall_row="$(grep -E '^\| ジョブ全体 \|' "$agents_file" | head -n1 || true)"
if [ -z "$overall_row" ]; then
  err "anchor-not-found" "AGENTS.md: 推奨タイムアウト値表の 'ジョブ全体' 行が見つからない"
  exit 2
fi
overall_cell="$(printf '%s' "$overall_row" | awk -F'|' '{print $3}')"
pairs="$(printf '%s' "$overall_cell" | grep -oE '`[A-Za-z][A-Za-z0-9_-]*`[[:space:]]*[0-9]+[[:space:]]*分' || true)"
if [ -z "$pairs" ]; then
  err "anchor-not-found" "AGENTS.md: 'ジョブ全体' 行から '\`job\` N 分' の組を 1 件も抽出できない"
  exit 2
fi
while IFS= read -r pair; do
  [ -z "$pair" ] && continue
  job="$(printf '%s' "$pair" | grep -oE '`[A-Za-z][A-Za-z0-9_-]*`' | tr -d '`' || true)"
  minutes="$(printf '%s' "$pair" | grep -oE '[0-9]+' || true)"
  block="$(job_block "$job")"
  if [ -z "$block" ]; then
    report "ジョブ全体タイムアウト: AGENTS.md が挙げる '${job}' ジョブが ci.yml に存在しない"
    continue
  fi
  ci_minutes="$(job_level_timeout "$block")"
  if [ -z "$ci_minutes" ]; then
    if job_is_reusable_call "$block"; then
      note "ジョブ全体タイムアウト: '${job}' は reusable workflow 呼び出しのため ci.yml 上で timeout-minutes を直接持たない（手動確認）"
      continue
    fi
    report "ジョブ全体タイムアウト: AGENTS.md が挙げる '${job}' ジョブ（ローカルジョブ）に ci.yml 上の timeout-minutes が見つからない（AGENTS.md 記載値 '${minutes} 分'）"
    continue
  fi
  if [ "$minutes" != "$ci_minutes" ]; then
    report "ジョブ全体タイムアウト: AGENTS.md '${job} ${minutes} 分' が ci.yml の timeout-minutes '${ci_minutes}' と一致しない"
  fi
done <<<"$pairs"

# --------------------------------------------------
# 6. ci-complete の needs 照合
# --------------------------------------------------
cc_block="$(job_block ci-complete)"
if [ -z "$cc_block" ]; then
  err "anchor-not-found" "ci.yml: ci-complete ジョブが見つからない"
  exit 2
fi
ci_needs="$(printf '%s\n' "$cc_block" | awk '
  /needs:/ { in_needs = 1 }
  in_needs { print }
  in_needs && /\]/ { exit }
' | grep -oE '[A-Za-z0-9_-]+' | grep -vxF 'needs' || true)"
if [ -z "$ci_needs" ]; then
  err "anchor-not-found" "ci.yml: ci-complete の needs を解釈できない"
  exit 2
fi

agents_needs_sentence="$(grep -oE '集約ジョブ `ci-complete` が[^。]*全ジョブ' "$agents_file" | head -n1 || true)"
if [ -z "$agents_needs_sentence" ]; then
  err "anchor-not-found" "AGENTS.md: '集約ジョブ \`ci-complete\` が ... 全ジョブ' の記述が見つからない"
  exit 2
fi
agents_needs="$(printf '%s' "$agents_needs_sentence" | sed -E 's/^集約ジョブ `ci-complete` が//' | grep -oE '`[A-Za-z][A-Za-z0-9_-]*`' | tr -d '`' || true)"

# (i) AGENTS.md の列挙と ci.yml の needs が集合として一致するか
diff_a="$(comm -23 <(printf '%s\n' "$ci_needs" | sort -u) <(printf '%s\n' "$agents_needs" | sort -u))"
diff_b="$(comm -13 <(printf '%s\n' "$ci_needs" | sort -u) <(printf '%s\n' "$agents_needs" | sort -u))"
if [ -n "$diff_a" ] || [ -n "$diff_b" ]; then
  report "ci-complete.needs [$(printf '%s' "$ci_needs" | tr '\n' ' ')] と AGENTS.md の列挙 [$(printf '%s' "$agents_needs" | tr '\n' ' ')] が一致しない"
fi

# (ii) ci.yml の全ジョブ（ci-complete を除く）と needs が一致するか
all_other_jobs="$(printf '%s\n' "$job_names" | grep -vxF 'ci-complete')"
diff_c="$(comm -23 <(printf '%s\n' "$all_other_jobs" | sort -u) <(printf '%s\n' "$ci_needs" | sort -u))"
diff_d="$(comm -13 <(printf '%s\n' "$all_other_jobs" | sort -u) <(printf '%s\n' "$ci_needs" | sort -u))"
if [ -n "$diff_c" ] || [ -n "$diff_d" ]; then
  report "ci-complete.needs [$(printf '%s' "$ci_needs" | tr '\n' ' ')] が ci.yml の全ジョブ（ci-complete 除く）[$(printf '%s' "$all_other_jobs" | tr '\n' ' ')] と一致しない"
fi

# --------------------------------------------------
# 7. deny の checks 集合・cargo-deny バージョン照合
# --------------------------------------------------
makefile_deny_checks="$(grep -E 'cargo deny --locked check' "$makefile" | head -n1 | sed -E 's/^.*cargo deny --locked check[[:space:]]*//' | tr -s ' ' || true)"
ci_deny_checks="$(grep -E 'deny-checks:' "$ci_file" | head -n1 | sed -E 's/^.*deny-checks:[[:space:]]*//' | tr -s ' ' || true)"
if [ -z "$makefile_deny_checks" ]; then
  err "anchor-not-found" "Makefile: 'cargo deny --locked check ...' が見つからない"
  exit 2
fi
if [ -z "$ci_deny_checks" ]; then
  err "anchor-not-found" "ci.yml: 'deny-checks:' が見つからない"
  exit 2
fi
if [ "$makefile_deny_checks" != "$ci_deny_checks" ]; then
  report "deny checks: Makefile '${makefile_deny_checks}' が ci.yml の deny-checks '${ci_deny_checks}' と一致しない"
fi

makefile_deny_version="$(grep -E '^CARGO_DENY_VERSION[[:space:]]*:=' "$makefile" | head -n1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' || true)"
ci_deny_version="$(grep -E 'cargo-deny-version:' "$ci_file" | head -n1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' || true)"
if [ -z "$makefile_deny_version" ]; then
  err "anchor-not-found" "Makefile: 'CARGO_DENY_VERSION := ...' が見つからない"
  exit 2
fi
if [ -z "$ci_deny_version" ]; then
  err "anchor-not-found" "ci.yml: 'cargo-deny-version:' が見つからない"
  exit 2
fi
if [ "$makefile_deny_version" != "$ci_deny_version" ]; then
  report "cargo-deny バージョン: Makefile CARGO_DENY_VERSION '${makefile_deny_version}' が ci.yml cargo-deny-version '${ci_deny_version}' と一致しない"
fi

# --------------------------------------------------
# 結果判定
# --------------------------------------------------
if [ "$fail_count" -gt 0 ]; then
  echo "check-agents-ci-consistency: ${fail_count} 件の齟齬を検出した" >&2
  exit 1
fi

echo "check-agents-ci-consistency: AGENTS.md と ci.yml・Makefile の照合に成功した"
