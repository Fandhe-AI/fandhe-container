#!/usr/bin/env bash
# CLI 基本 6 コマンドの 3 OS 同一構文・挙動の比較スクリプト（TASK-125.1・CLI-1・MS-6）。
#
# 役割: fandhe-container の基本 6 コマンド（create / start / stop / delete / list / logs）を固定のケース表で
# 実行し、終了コード・stderr の `code`・stdout の形を正規化して 1 ケース 1 行で記録する（capture）。
# 別 OS で取った記録同士を突き合わせる（compare）。期待値は「Linux ネイティブ実行と同一」で、
# 比較の基準は Linux で取った capture ファイルとする。実機での実行・結果の記録・CLI-1 の合否判定は
# #661（TASK-125.h1・人間担当）が行う。本スクリプトは準備物であり、compare の終了コード 1 は機械照合の
# 事実の報告にとどまる。
#
# ケースの層（docs/verification/cli-cross-platform-parity.md のチェックリストと ID を一致させる）:
#   A 層: 構文・使い方エラー。OS 非依存の引数解析だけで決まる。3 OS で今すぐ比較できる。
#   B 層: 挙動（Linux は core 直接、macOS / Windows は plugin 発見機構経由）。非 Linux の plugin 起動と
#         RPC は未配線（TASK-114。REPAIR-3）のため、現時点で非 Linux の B 層は Linux と一致しない。
#         不一致は「前提未達」の事実であり、合格に見せてはならない。
#
# 呼び出し元: Makefile の `cli-parity`（操作者が明示実行。make ci には含めない）。自己テストは
# scripts/cli-parity-check-selftest.sh（`make cli-parity-selftest`。CI の integration-test ジョブ）。
# 本スクリプトは sudo を呼ばない。状態ルートは毎回 mktemp -d の専用ディレクトリで、全ケースで --root を
# 明示する（既定の状態ルートやホスト設定に触れない）。
#
# 記録の内容（情報漏えい防止）: 正規化済みの固定語彙だけを書く。生の stderr 文言・パス・ホスト名・
# ユーザー名・環境変数は書かない。list の PID 列は <pid> に置換し、想定外の出力は内容を写さず
# <unexpected>:行数 とする。
#
# 使い方:
#   cli-parity-check.sh capture --cli <絶対パス> --output <新規ファイル> [--timeout SECS（既定 20。1〜600）]
#   cli-parity-check.sh compare --baseline <capture> --candidate <capture>
#
# 終了コード: 0 = 全ケース一致（capture は全ケース実行完了）/ 1 = 不一致・欠落・タイムアウト /
#   2 = 引数・入力・出力先エラー / 3 = 前提欠如（CLI 不在・実行不可・未対応 OS。0 で合格に見せない）。
#
# 動作環境: bash 3.2 以上（macOS 標準）。GNU / BSD 双方のツールで動く書き方にしている。
# Windows は Git Bash での実行を想定するが CI では未検証（手動手順は検証ドキュメントを参照）。
set -euo pipefail

readonly FORMAT_HEADER='# fandhe-container-cli-parity v1'
readonly COLUMNS_LINE=$'case\tlayer\texit\tcode\tstdout'
readonly MAX_LINES=200
readonly MAX_LINE_LEN=512
readonly TAB=$'\t'

err() {
  local LC_ALL=C msg
  msg="error: $1: $2"
  msg="${msg//[^[:print:]]/?}"
  printf '%s\n' "$msg" >&2 || true
}

usage() {
  sed -n '2,/^set -euo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'
}

# --------------------------------------------------
# ケース表: ID|層|種別|argv（空白区切り。@R@ = 状態ルート、@B@ = バンドル、@M@ = 存在しない状態ルート）
# 種別 l = stdout が list 形式、n = 成功時の stdout は空であるべき。
# B 層は上から順に実行する（状態遷移を観測する）。ID・層はドキュメントのチェックリストと一致させる。
# --------------------------------------------------
CASES=(
  'A01|A|n|--root @R@'
  'A02|A|n|--root @R@ bogus'
  'A03|A|n|--root @R@ create'
  'A04|A|n|--root @R@ create c1'
  'A05|A|n|--root @R@ create --bundle @B@'
  'A06|A|n|--root @R@ create --bundle @B@ c1 c2'
  'A07|A|n|--root @R@ start'
  'A08|A|n|--root @R@ start c1 c2'
  'A09|A|n|--root @R@ stop'
  'A10|A|n|--root @R@ delete'
  'A11|A|n|--root @R@ delete --force --force c1'
  'A12|A|l|--root @R@ list extra'
  'A13|A|n|--root @R@ logs'
  'A14|A|n|--root @R@ start a/b'
  'A15|A|n|--root @R@ --root @R@ list'
  'A16|A|n|--plugin-path-search --plugin-path-search --root @R@ list'
  'A17|A|n|--root'
  'A18|A|n|--root @R@ start --bogus c1'
  'B01|B|l|--root @R@ list'
  'B02|B|n|--root @R@ create --bundle @B@ c1'
  'B03|B|l|--root @R@ list'
  'B04|B|n|--root @R@ create --bundle @B@ c1'
  'B05|B|n|--root @R@ start c1'
  'B06|B|l|--root @R@ list'
  'B07|B|n|--root @R@ logs c1'
  'B08|B|n|--root @R@ stop c1'
  'B09|B|n|--root @R@ delete c1'
  'B10|B|l|--root @R@ list'
  'B11|B|n|--root @R@ start nonexist'
  'B12|B|n|--root @R@ stop nonexist'
  'B13|B|n|--root @R@ delete nonexist'
  'B14|B|n|--root @R@ logs nonexist'
  'B15|B|l|--root @M@ list'
)

# --------------------------------------------------
# capture
# --------------------------------------------------
tmp_dir=""
watchdog_pid=""
run_pid=""
# プロセスグループ（pgid = $1）ごと TERM → KILL し、最大 5 秒（0.1 秒 x 50）で全員の消滅を確かめる。
# CLI を set -m の別グループで起動しているため、子孫（スタブの sleep 等）も同時に回収できる（REPAIR-5）。
kill_group() {
  local pg="$1" w=0
  kill -TERM -- "-$pg" 2>/dev/null || true
  while kill -0 -- "-$pg" 2>/dev/null && [ "$w" -lt 5 ]; do
    sleep 0.1
    w=$((w + 1))
  done
  kill -KILL -- "-$pg" 2>/dev/null || true
  kill -KILL "$pg" 2>/dev/null || true
  w=0
  while kill -0 -- "-$pg" 2>/dev/null && [ "$w" -lt 50 ]; do
    sleep 0.1
    w=$((w + 1))
  done
}

cleanup() {
  if [ -n "$watchdog_pid" ]; then
    kill "$watchdog_pid" 2>/dev/null || true
    watchdog_pid=""
  fi
  # 中断時に実行中の CLI とその子孫を残さない。グループごと回収を待ってから一時ディレクトリを消す。
  if [ -n "$run_pid" ]; then
    kill_group "$run_pid"
    wait "$run_pid" 2>/dev/null || true
    run_pid=""
  fi
  if [ -n "$tmp_dir" ] && [ -d "$tmp_dir" ]; then
    rm -rf -- "$tmp_dir"
  fi
}

detect_os() {
  case "$(uname -s 2>/dev/null)" in
    Linux) printf 'linux' ;;
    Darwin) printf 'macos' ;;
    MINGW* | MSYS* | CYGWIN*) printf 'windows' ;;
    *) return 1 ;;
  esac
}

# CLI を 1 回実行する。結果は run_exit（終了コード）・run_timed_out（1 = 期限切れで強制終了）に入れ、
# 標準出力・標準エラーは $tmp_dir/out・$tmp_dir/err へ書く。出力ファイルは ulimit -f で肥大化を抑える。
# タイムアウトは timeout / gtimeout の有無に依存しないよう、バックグラウンド実行 + 監視 kill で実装する
# （macOS に timeout が標準で無いため。黙って無期限待ちにしない。REPAIR-5）。
run_exit=0
run_timed_out=0
run_cli() {
  local cli="$1" limit="$2"
  shift 2
  local pid ticks i
  : >"$tmp_dir/out"
  : >"$tmp_dir/err"
  rm -f -- "$tmp_dir/timed_out"
  # set -m でバックグラウンドジョブを独立したプロセスグループ（pgid = pid）にする。setsid が無い
  # macOS でも使える。タイムアウト・中断時はグループ単位で子孫ごと回収する。
  set -m
  (
    ulimit -f 256 2>/dev/null || true
    exec "$cli" "$@" </dev/null >"$tmp_dir/out" 2>"$tmp_dir/err"
  ) &
  pid=$!
  set +m
  run_pid="$pid"
  ticks=$((limit * 10))
  (
    i=0
    while [ "$i" -lt "$ticks" ]; do
      kill -0 "$pid" 2>/dev/null || exit 0
      sleep 0.1
      i=$((i + 1))
    done
    if kill -0 "$pid" 2>/dev/null; then
      : >"$tmp_dir/timed_out"
      kill_group "$pid"
    fi
  ) &
  watchdog_pid=$!
  run_exit=0
  wait "$pid" || run_exit=$?
  # 正常終了後に残った子孫（バックグラウンド起動の残り等）もグループごと回収する。
  kill_group "$pid"
  kill "$watchdog_pid" 2>/dev/null || true
  wait "$watchdog_pid" 2>/dev/null || true
  watchdog_pid=""
  run_pid=""
  if [ -e "$tmp_dir/timed_out" ]; then
    run_timed_out=1
  else
    run_timed_out=0
  fi
}

# stderr から機械可読な code だけを取り出す（文言・パスは写さない）。
norm_code() {
  local e raw
  raw="$(wc -c <"$tmp_dir/err" | tr -d ' ')"
  e="$(LC_ALL=C tr -d '\000' <"$tmp_dir/err" | head -c 4096)"
  if [ "$raw" -eq 0 ]; then
    printf -- '-'
  elif [[ $e =~ \"code\":\"([A-Z_]{1,40})\" ]]; then
    printf '%s' "${BASH_REMATCH[1]}"
  else
    printf '<unparsed>'
  fi
}

# stdout を正規化する。種別 l は list 形式（ヘッダ + 行）を厳格に検査し PID 列を <pid> へ置換する。
norm_stdout() {
  local kind="$1" o line n header_expected row_re joined first ok raw stripped
  # 空判定は元ファイルのバイト数で行う（コマンド置換は末尾改行を落とし、tr は NUL を落とすため、
  # 改行のみ・NUL 含みの出力が空出力と同じ '-' になるのを防ぐ）。内容は写さず異常として記録する。
  raw="$(wc -c <"$tmp_dir/out" | tr -d ' ')"
  if [ "$raw" -eq 0 ]; then
    printf -- '-'
    return 0
  fi
  stripped="$(LC_ALL=C tr -d '\000' <"$tmp_dir/out" | wc -c | tr -d ' ')"
  if [ "$stripped" -ne "$raw" ]; then
    printf '<unexpected>:nul'
    return 0
  fi
  o="$(LC_ALL=C head -c 65536 "$tmp_dir/out")"
  n="$(wc -l <"$tmp_dir/out" | tr -d ' ')"
  if [ -z "$o" ]; then
    printf '<unexpected>:%s' "$n"
    return 0
  fi
  if [ "$kind" != "l" ]; then
    printf '<unexpected>:%s' "$n"
    return 0
  fi
  # 行単位検査は元ファイルから直接読む（コマンド置換は末尾の空行を落とし、余分な空行を見逃すため）。
  LC_ALL=C head -c 65536 "$tmp_dir/out" >"$tmp_dir/out.cut"
  header_expected="ID${TAB}STATUS${TAB}PID"
  row_re="^([A-Za-z0-9_-]{1,64})${TAB}([a-z]{1,16})${TAB}([0-9]{1,10}|-)$"
  first=1
  ok=1
  joined=""
  while IFS= read -r line || [ -n "$line" ]; do
    if [ "$first" -eq 1 ]; then
      first=0
      if [ "$line" != "$header_expected" ]; then
        ok=0
        break
      fi
      joined="H"
    elif [[ $line =~ $row_re ]]; then
      local pidcol="${BASH_REMATCH[3]}"
      [ "$pidcol" = "-" ] || pidcol="<pid>"
      joined="${joined};${BASH_REMATCH[1]},${BASH_REMATCH[2]},${pidcol}"
    else
      ok=0
      break
    fi
  done <"$tmp_dir/out.cut"
  if [ "$ok" -eq 1 ]; then
    printf 'list:%s' "$joined"
  else
    printf '<unexpected>:%s' "$n"
  fi
}

do_capture() {
  local cli="" output="" limit=20
  while [ $# -gt 0 ]; do
    case "$1" in
      --cli) [ $# -ge 2 ] || { err invalid-argument "--cli requires a value"; exit 2; }; cli="$2"; shift 2 ;;
      --output) [ $# -ge 2 ] || { err invalid-argument "--output requires a value"; exit 2; }; output="$2"; shift 2 ;;
      --timeout) [ $# -ge 2 ] || { err invalid-argument "--timeout requires a value"; exit 2; }; limit="$2"; shift 2 ;;
      *) err invalid-argument "unknown option for capture"; exit 2 ;;
    esac
  done
  [ -n "$cli" ] || { err invalid-argument "--cli is required"; exit 2; }
  [ -n "$output" ] || { err invalid-argument "--output is required"; exit 2; }
  [[ $limit =~ ^[1-9][0-9]{0,2}$ ]] && [ "$limit" -le 600 ] || { err invalid-argument "--timeout must be 1..600"; exit 2; }
  case "$cli" in
    /*) ;;
    [A-Za-z]:[/\\]*) ;;
    *) err invalid-argument "--cli must be an absolute path"; exit 2 ;;
  esac
  # 出力は新規ファイルのみ（既存ファイル・symlink 先を上書きしない）。親ディレクトリは存在が必要。
  if [ -e "$output" ] || [ -L "$output" ]; then
    err invalid-argument "--output already exists"
    exit 2
  fi
  local out_dir
  out_dir="$(dirname -- "$output")"
  [ -d "$out_dir" ] || { err invalid-argument "--output parent directory does not exist"; exit 2; }

  local os_kind
  os_kind="$(detect_os)" || { err unsupported-os "only linux, macos and windows (Git Bash) are supported"; exit 3; }
  if [ ! -f "$cli" ] || [ ! -x "$cli" ]; then
    err missing-prerequisite "CLI is not an executable file"
    exit 3
  fi

  tmp_dir="$(mktemp -d)"
  trap cleanup EXIT
  trap 'cleanup; exit 130' INT
  trap 'cleanup; exit 143' TERM
  trap 'cleanup; exit 129' HUP

  local state="$tmp_dir/state" bundle="$tmp_dir/bundle" missing="$tmp_dir/nope/missing"
  mkdir -p -- "$state" "$bundle/rootfs"
  chmod 700 "$state"
  local fixture
  fixture="$(cd "$(dirname -- "$0")" && pwd)/testdata/cli-parity/config.json"
  [ -f "$fixture" ] || { err missing-prerequisite "fixture config.json not found"; exit 3; }
  cp -- "$fixture" "$bundle/config.json"

  local lines=() entry id layer kind argstr tok mapped any_timeout=0
  lines+=("$FORMAT_HEADER" "# os=${os_kind}" "$COLUMNS_LINE")
  for entry in "${CASES[@]}"; do
    IFS='|' read -r id layer kind argstr <<<"$entry"
    local argv=()
    for tok in $argstr; do
      case "$tok" in
        @R@) mapped="$state" ;;
        @B@) mapped="$bundle" ;;
        @M@) mapped="$missing" ;;
        *) mapped="$tok" ;;
      esac
      argv+=("$mapped")
    done
    run_cli "$cli" "$limit" "${argv[@]}"
    if [ "$run_timed_out" -eq 1 ]; then
      any_timeout=1
      lines+=("${id}${TAB}${layer}${TAB}${run_exit}${TAB}<timeout>${TAB}<timeout>")
      continue
    fi
    lines+=("${id}${TAB}${layer}${TAB}${run_exit}${TAB}$(norm_code)${TAB}$(norm_stdout "$kind")")
  done

  (
    set -o noclobber
    printf '%s\n' "${lines[@]}" >"$output"
  ) || { err invalid-argument "failed to create --output"; exit 2; }
  printf 'captured %s cases (os=%s)\n' "${#CASES[@]}" "$os_kind"
  if [ "$any_timeout" -eq 1 ]; then
    err timeout "at least one case exceeded the time limit"
    exit 1
  fi
  exit 0
}

# --------------------------------------------------
# compare
# --------------------------------------------------
# capture ファイルを書式検証して読み込む。変数 <prefix>_<ID> に "exit<TAB>code<TAB>stdout" を入れ、
# 順序つき ID 一覧を <prefix>_ids に、OS 種別を <prefix>_os に入れる（bash 3.2 は連想配列が無いため間接参照）。
load_capture() {
  local prefix="$1" file="$2" n=0 line id layer ex code so os_line
  local ids=()
  [ -f "$file" ] && [ ! -L "$file" ] || { err invalid-input "capture file is not a regular file"; exit 2; }
  local size
  size="$(wc -c <"$file" | tr -d ' ')"
  [ "$size" -le $((MAX_LINES * MAX_LINE_LEN)) ] || { err invalid-input "capture file is too large"; exit 2; }
  local id_re='^[AB][0-9]{2}$' ex_re='^[0-9]{1,3}$' code_re='^([A-Z_]{1,40}|-|<unparsed>|<timeout>)$'
  local so_re='^[-A-Za-z0-9_,;<>:]{1,300}$'
  while IFS= read -r line || [ -n "$line" ]; do
    n=$((n + 1))
    [ "$n" -le "$MAX_LINES" ] || { err invalid-input "capture file has too many lines"; exit 2; }
    [ "${#line}" -le "$MAX_LINE_LEN" ] || { err invalid-input "capture line is too long"; exit 2; }
    case "$n" in
      1) [ "$line" = "$FORMAT_HEADER" ] || { err invalid-input "unsupported capture format"; exit 2; } ;;
      2)
        [[ $line =~ ^'# os='(linux|macos|windows)$ ]] || { err invalid-input "invalid os line"; exit 2; }
        os_line="${BASH_REMATCH[1]}"
        printf -v "${prefix}_os" '%s' "$os_line"
        ;;
      3) [ "$line" = "$COLUMNS_LINE" ] || { err invalid-input "invalid columns line"; exit 2; } ;;
      *)
        IFS="$TAB" read -r id layer ex code so <<<"$line"
        [[ $id =~ $id_re ]] && [ "$layer" = "${id:0:1}" ] && [[ $ex =~ $ex_re ]] && [ "$((10#$ex))" -le 255 ] \
          && [[ $code =~ $code_re ]] && [[ $so =~ ^(-|'<timeout>')$ || $so =~ $so_re ]] \
          || { err invalid-input "malformed case line $n"; exit 2; }
        local var="${prefix}_${id}"
        [ -z "${!var+x}" ] || { err invalid-input "duplicate case id"; exit 2; }
        printf -v "$var" '%s' "${ex}/${code}/${so}"
        ids+=("$id")
        ;;
    esac
  done <"$file"
  [ "$n" -ge 4 ] || { err invalid-input "capture file has no cases"; exit 2; }
  printf -v "${prefix}_ids" '%s' "${ids[*]}"
}

do_compare() {
  local base="" cand=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --baseline) [ $# -ge 2 ] || { err invalid-argument "--baseline requires a value"; exit 2; }; base="$2"; shift 2 ;;
      --candidate) [ $# -ge 2 ] || { err invalid-argument "--candidate requires a value"; exit 2; }; cand="$2"; shift 2 ;;
      *) err invalid-argument "unknown option for compare"; exit 2 ;;
    esac
  done
  [ -n "$base" ] && [ -n "$cand" ] || { err invalid-argument "--baseline and --candidate are required"; exit 2; }
  load_capture base "$base"
  load_capture cand "$cand"

  local all_ids id bv cv bvar cvar layer entry
  local a_match=0 a_mis=0 a_miss=0 b_match=0 b_mis=0 b_miss=0
  # 比較対象は CASES から作る期待 ID 集合（固定ケース表）を基準とし、双方に無いケースも MISSING にする。
  # 入力にだけある想定外 ID は末尾に足す（こちらも片側欠落として MISSING になる）。
  all_ids=""
  for entry in "${CASES[@]}"; do
    all_ids="${all_ids:+$all_ids }${entry%%|*}"
  done
  for id in $base_ids $cand_ids; do
    case " $all_ids " in *" $id "*) ;; *) all_ids="$all_ids $id" ;; esac
  done
  printf 'baseline os=%s candidate os=%s\n' "$base_os" "$cand_os"
  for id in $all_ids; do
    layer="${id:0:1}"
    bvar="base_${id}"
    cvar="cand_${id}"
    bv="${!bvar-}"
    cv="${!cvar-}"
    local verdict
    if [ -z "${!bvar+x}" ] || [ -z "${!cvar+x}" ]; then
      verdict="MISSING"
      printf '%s MISSING (baseline=%s candidate=%s)\n' "$id" "${bv:-absent}" "${cv:-absent}"
    elif [[ $bv == *'<timeout>'* || $cv == *'<timeout>'* ]]; then
      # タイムアウト記録は値が一致しても成功にしない（ハングした事実を合格に見せない。REPAIR-5）。
      verdict="MISMATCH"
      printf '%s TIMEOUT (baseline=%s candidate=%s)\n' "$id" "$bv" "$cv"
    elif [[ $bv == *'<unexpected>'* || $cv == *'<unexpected>'* || $bv == *'<unparsed>'* || $cv == *'<unparsed>'* ]]; then
      # 解析不能マーカーは内容を記録しないため、同形でも同一性を確認できていない。一致扱いにしない。
      verdict="MISMATCH"
      printf '%s UNVERIFIED (baseline=%s candidate=%s)\n' "$id" "$bv" "$cv"
    elif [ "$bv" = "$cv" ]; then
      verdict="MATCH"
      printf '%s MATCH\n' "$id"
    else
      verdict="MISMATCH"
      printf '%s MISMATCH (baseline=%s candidate=%s)\n' "$id" "$bv" "$cv"
    fi
    case "${layer}:${verdict}" in
      A:MATCH) a_match=$((a_match + 1)) ;;
      A:MISMATCH) a_mis=$((a_mis + 1)) ;;
      A:MISSING) a_miss=$((a_miss + 1)) ;;
      B:MATCH) b_match=$((b_match + 1)) ;;
      B:MISMATCH) b_mis=$((b_mis + 1)) ;;
      B:MISSING) b_miss=$((b_miss + 1)) ;;
    esac
  done
  printf 'layer A (syntax): match=%s mismatch=%s missing=%s\n' "$a_match" "$a_mis" "$a_miss"
  printf 'layer B (behavior): match=%s mismatch=%s missing=%s\n' "$b_match" "$b_mis" "$b_miss"
  if [ $((a_mis + a_miss + b_mis + b_miss)) -eq 0 ]; then
    exit 0
  fi
  exit 1
}

# --------------------------------------------------
# エントリ
# --------------------------------------------------
if [ $# -lt 1 ]; then
  usage >&2
  exit 2
fi
sub="$1"
shift
case "$sub" in
  capture) do_capture "$@" ;;
  compare) do_compare "$@" ;;
  --help | -h) usage ;;
  *) err invalid-argument "unknown subcommand"; exit 2 ;;
esac
