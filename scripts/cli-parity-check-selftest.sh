#!/usr/bin/env bash
# scripts/cli-parity-check.sh の自己テスト（TASK-125.1・CLI-1・REPAIR-12）。
#
# 役割: 製品バイナリ・root を使わず、契約どおりの出力を返すスタブ CLI（一時ディレクトリに生成する bash
# スクリプト）だけで capture / compare の挙動を具体値で照合する。実機での 3 OS 比較そのものは
# #661（人間担当）の範囲で、本テストはその道具が壊れていないことだけを確かめる。
#
# 呼び出し元: Makefile の `cli-parity-selftest`（CI の integration-test ジョブもこのターゲットを使う。ubuntu・macos・windows の
# 3 OS。Windows は Git Bash）。make ci には含めない。
# 失敗は `FAIL:` 行を出し、最後に非 0 で終了する。bash 3.2 以上で動く。
#
# 構成: capture は 8 本を同時に起動してから結果を照合する。Git Bash はプロセス生成が遅く、直列では
# CI の時間枠を圧迫するため。同時実行の負荷は、CLI が即座に終わるときの監視サブシェル停止の競合
# （cli-parity-check.sh の run_cli を参照）が再発した場合に表面化しやすくするが、確定的な回帰テストではない。
set -uo pipefail

script_dir="$(cd "$(dirname -- "$0")" && pwd)"
target="$script_dir/cli-parity-check.sh"
work="$(mktemp -d)"
trap 'rm -rf -- "$work"' EXIT
fails=0
tab=$'\t'

fail() {
  printf 'FAIL: %s\n' "$1"
  fails=$((fails + 1))
}
pass() { printf 'ok: %s\n' "$1"; }

# 期待する終了コードと一致するか確かめる。
expect_rc() {
  local name="$1" want="$2" got="$3"
  if [ "$got" = "$want" ]; then pass "$name"; else fail "$name (want rc=$want got rc=$got)"; fi
}

# 文字列の一致を確かめる（不一致なら実際の値を出す）。
expect_eq() {
  local name="$1" want="$2" got="$3"
  if [ "$got" = "$want" ]; then pass "$name"; else fail "$name (want '$want' got '$got')"; fi
}

# --------------------------------------------------
# スタブ CLI。STUB_MODE で挙動を切り替える。
#   ok       = Linux の現行挙動を模した固定応答
#   nonlinux = 引数解析は同じで、解析後の全コマンドが FAILED_PRECONDITION（5）
#   diff     = ok と同じだが create 後の list の終了コードだけ変える
#   noisy    = ok と同じ終了コードで、stderr / stdout にパス風文字列・制御文字を流す
#   hang     = 未知コマンド（bogus）だけ止まる（子孫の sleep を残し得る構成）
# 環境変数で出力を差し替える（fixture 表。カウンタはそのディレクトリの count に置く）:
#   STUB_ERR_DIR = 使い方エラーの n 回目に err.<n> があれば、その内容をそのまま stderr へ流す。
#                  A 層 18 ケースは全て使い方エラーで順に呼ばれるため、n 回目 = ケース A<n>。
#   STUB_OUT_DIR = 成功するコマンドの n 回目に out.<n> があれば、その内容をそのまま stdout へ流す。
#                  成功の順は B01 list・B02 create・B03 list・B06 list・B09 delete・B10 list。
#
# stderr の形は製品 CLI に合わせる（crates/cli/src/commands.rs の CliExit::write_stderr）:
#   固定文言（使い方エラー・list の状態ルート不在・logs）= {"code":..,"message":..}
#   core 由来（create / start / stop / delete の失敗。OciRuntimeError::write_json_line）
#     = {"op":..,"code":..,"message":..}。stop の op は kill。
# --------------------------------------------------
stub="$work/stub-cli"
cat >"$stub" <<'STUB'
#!/usr/bin/env bash
mode="${STUB_MODE:-ok}"
# 受け取った LC_ALL を記録する（無効なロケールを CLI へ渡していないことの照合用。#1548）。
[ -z "${STUB_LOCALE_FILE:-}" ] || printf '%s\n' "${LC_ALL-<unset>}" >>"$STUB_LOCALE_FILE"
seen_root=0
seen_pps=0
root=""
# <ディレクトリ> の count を 1 増やし、その値を next_n に入れる。
next_n=0
bump() {
  next_n=0
  [ -f "$1/count" ] && IFS= read -r next_n <"$1/count"
  next_n=$((next_n + 1))
  printf '%s\n' "$next_n" >"$1/count"
}
bad() {
  if [ -n "${STUB_ERR_DIR:-}" ]; then
    bump "$STUB_ERR_DIR"
    if [ -f "$STUB_ERR_DIR/err.$next_n" ]; then
      cat "$STUB_ERR_DIR/err.$next_n" >&2
      exit 2
    fi
  fi
  if [ "$mode" = "noisy" ]; then
    printf '{"code":"INVALID_ARGUMENT","message":"/home/secret-user/path \001 host-leak"}\n' >&2
  else
    printf '{"code":"INVALID_ARGUMENT","message":"usage"}\n' >&2
  fi
  exit 2
}
fail_with() { printf '{"code":"%s","message":"x"}\n' "$2" >&2; exit "$1"; }
# core 由来の失敗（op 付き）。<終了コード> <code> <op>
fail_op() { printf '{"op":"%s","code":"%s","message":"x"}\n' "$3" "$2" >&2; exit "$1"; }
# 成功時の stdout を fixture で差し替える。差し替えたら 0、しなければ 1 を返す。
out_override() {
  [ -n "${STUB_OUT_DIR:-}" ] || return 1
  bump "$STUB_OUT_DIR"
  [ -f "$STUB_OUT_DIR/out.$next_n" ] || return 1
  cat "$STUB_OUT_DIR/out.$next_n"
  return 0
}
while [ $# -gt 0 ]; do
  case "$1" in
    --root) [ $# -ge 2 ] || bad; [ "$seen_root" = 0 ] || bad; seen_root=1; root="$2"; shift 2 ;;
    --plugin-path-search) [ "$seen_pps" = 0 ] || bad; seen_pps=1; shift ;;
    *) break ;;
  esac
done
[ $# -ge 1 ] || bad
cmd="$1"; shift
valid_id() { [[ "$1" =~ ^[A-Za-z0-9_-]{1,64}$ ]]; }
case "$cmd" in
  bogus)
    if [ "$mode" = "hang" ]; then
      # 子孫プロセスを作る（pid を記録して、回収されたか自己テストで確認する）。
      sleep 30 &
      [ -z "${STUB_PIDFILE:-}" ] || echo $! >>"$STUB_PIDFILE"
      wait
    fi
    bad ;;
  create)
    bundle=""; id=""; n=0
    while [ $# -gt 0 ]; do
      case "$1" in
        --bundle) [ $# -ge 2 ] || bad; [ -z "$bundle" ] || bad; bundle="$2"; shift 2 ;;
        -*) bad ;;
        *) id="$1"; n=$((n + 1)); shift ;;
      esac
    done
    [ -n "$bundle" ] && [ "$n" -eq 1 ] && valid_id "$id" || bad ;;
  start | stop | logs)
    [ $# -eq 1 ] && valid_id "$1" && [ "${1#-}" = "$1" ] || bad; id="$1" ;;
  delete)
    force=0; n=0
    while [ $# -gt 0 ]; do
      case "$1" in
        --force) [ "$force" = 0 ] || bad; force=1; shift ;;
        -*) bad ;;
        *) id="$1"; n=$((n + 1)); shift ;;
      esac
    done
    [ "$n" -eq 1 ] && valid_id "$id" || bad ;;
  list) [ $# -eq 0 ] || bad ;;
  *) bad ;;
esac
# 非 Linux は plugin 未配線の固定文言（CliExit::failed() が返す CliExit::Error。op なし）。
[ "$mode" = "nonlinux" ] && fail_with 5 FAILED_PRECONDITION
case "$cmd" in
  list)
    [ -d "$root" ] || fail_with 3 NOT_FOUND
    if ! out_override; then
      printf 'ID\tSTATUS\tPID\n'
      for f in "$root"/*.c; do
        [ -e "$f" ] || continue
        b="${f##*/}"
        printf '%s\tcreated\t-\n' "${b%.c}"
      done
    fi
    [ "$mode" = "diff" ] && [ -e "$root/c1.c" ] && exit 7
    ;;
  create)
    [ -d "$root" ] || fail_op 3 NOT_FOUND create
    [ -e "$root/$id.c" ] && fail_op 4 ALREADY_EXISTS create
    : >"$root/$id.c"
    out_override || { [ "$mode" = "noisy" ] && printf '/home/secret-user/out\n'; }
    ;;
  start) [ -e "$root/$id.c" ] || fail_op 3 NOT_FOUND start; fail_op 8 UNIMPLEMENTED start ;;
  logs) [ -e "$root/$id.c" ] || fail_with 3 NOT_FOUND; fail_with 8 UNIMPLEMENTED ;;
  stop) [ -e "$root/$id.c" ] || fail_op 3 NOT_FOUND kill; fail_op 5 FAILED_PRECONDITION kill ;;
  delete)
    [ -e "$root/$id.c" ] || fail_op 3 NOT_FOUND delete
    rm -f "$root/$id.c"
    out_override || true
    ;;
esac
exit 0
STUB
chmod +x "$stub"

# --------------------------------------------------
# fixture 表
# --------------------------------------------------
# stderr fixture（A01〜A18）。err.<n> を A<n> の stderr として流し、記録の code 欄を具体値で照合する。
errdir="$work/errtable"
mkdir -p "$errdir"
want_codes=()
add_err() { # <期待する code 欄> <printf の書式（stderr の全バイト）>
  local idx=$((${#want_codes[@]} + 1))
  # shellcheck disable=SC2059 # 書式は本ファイル内の固定 fixture（バイト列を 8 進エスケープで書くため）
  printf "$2" >"$errdir/err.$idx"
  want_codes+=("$1")
}
# 受理（A01〜A06）: 固定文言形・op 付き形・エスケープ・非 ASCII（UTF-8）・空 message・DEL
add_err INVALID_ARGUMENT '{"code":"INVALID_ARGUMENT","message":"usage: fandhe-container <create|start>"}\n'
add_err ALREADY_EXISTS '{"op":"create","code":"ALREADY_EXISTS","message":"container already exists"}\n'
add_err NOT_FOUND '{"op":"kill","code":"NOT_FOUND","message":"a\\"b\\\\c \\u0041 \\/ \\n"}\n'
add_err NOT_FOUND '{"op":"start","code":"NOT_FOUND","message":"\343\201\202 \303\251"}\n'
add_err FAILED_PRECONDITION '{"code":"FAILED_PRECONDITION","message":""}\n'
add_err INTERNAL '{"op":"delete","code":"INTERNAL","message":"del \177 ok"}\n'
# 拒否（A07〜A18）: code らしき文字列を含んでいても <unparsed>
add_err '<unparsed>' '{"op":"create","message":"x"}\n'
add_err '<unparsed>' '{"code":"INVALID_ARGUMENT","message":"a"b"}\n'
add_err '<unparsed>' '{"code":"INVALID_ARGUMENT","message":"a \001 b"}\n'
add_err '<unparsed>' 'error: INVALID_ARGUMENT "code":"INVALID_ARGUMENT"\n'
add_err '<unparsed>' '{"code":"NOT_FOUND","message":"a"}\n{"code":"NOT_FOUND","message":"b"}\n'
add_err '<unparsed>' '{"code":"NOT_FOUND","message":"no trailing newline"}'
add_err '<unparsed>' '{"code":"NOT_FOUND","message":"bad utf8 \377"}\n'
add_err '<unparsed>' '{"code":"NOT_FOUND","message":"m","extra":"y"}\n'
add_err '<unparsed>' '{"code":"NOT_FOUND","message":"bad escape \\x"}\n'
add_err '<unparsed>' '{"code":"NOT_FOUND","op":"start","message":"key order"}\n'
add_err '<unparsed>' '{"code":"NOT_FOUND","message":"short \\u12"}\n'
add_err '<unparsed>' '{"code":"NOT_FOUND","message":"crlf"}\r\n'
expect_eq "errtable has 18 fixtures" 18 "${#want_codes[@]}"

# stderr fixture その 2（上限と、過去に検出した壊れ方）。
#   err.1 = core の message 上限（4096 バイト）が全バイト 2 バイトへエスケープされた正規の出力（受理）
#   err.2 = 検査上限（16384 バイト）を超える出力（先頭が正常でも拒否）
#   err.3 = 途中で切れた JSON / err.4 = 同じ code の JSON 2 行 / err.5 = message 内の NUL
errmax="$work/errmax"
mkdir -p "$errmax"
q64='\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"'
q4096=""
i=0
while [ "$i" -lt 64 ]; do
  q4096="${q4096}${q64}"
  i=$((i + 1))
done
expect_eq "escaped max message is 8192 bytes" 8192 "${#q4096}"
printf '{"op":"create","code":"INVALID_ARGUMENT","message":"%s"}\n' "$q4096" >"$errmax/err.1"
printf '{"code":"INVALID_ARGUMENT","message":"%s%s%s"}\n' "$q4096" "$q4096" "$q4096" >"$errmax/err.2"
printf '{"code":"INVALID_ARGUMENT"\n' >"$errmax/err.3"
printf '{"code":"INVALID_ARGUMENT","message":"a"}\n{"code":"INVALID_ARGUMENT","message":"b"}\n' >"$errmax/err.4"
printf '{"code":"INVALID_ARGUMENT","message":"a\000b"}\n' >"$errmax/err.5"
# err.6 / err.7 = op / code に非 ASCII（UTF-8 として妥当）を含む。message 以外の非 ASCII は受理しない。
printf '{"op":"cr\303\251ate","code":"NOT_FOUND","message":"m"}\n' >"$errmax/err.6"
printf '{"code":"NOT_\303\251FOUND","message":"m"}\n' >"$errmax/err.7"
# err.8 = 同じ非 ASCII が message にあれば受理する（対照）。
printf '{"op":"create","code":"NOT_FOUND","message":"cr\303\251ate"}\n' >"$errmax/err.8"
# 同じ capture の stdout fixture: PID 列が数値の list 行（<pid> へ置換されること）。
# カウンタ（count）が stderr fixture と混ざらないよう別ディレクトリに置く。
pidout="$work/pidout"
mkdir -p "$pidout"
printf 'ID\tSTATUS\tPID\nc1\trunning\t4242\nc2\tcreated\t-\n' >"$pidout/out.1"
# out.3 = B03 list: CRLF 終端（LF 固定の出力と区別する。Git Bash でも CR を見落とさないこと）
printf 'ID\tSTATUS\tPID\r\nc1\tcreated\t-\r\n' >"$pidout/out.3"

# stdout fixture（成功するコマンドの順）。
#   out.1 = B01 list: ヘッダだけで LF 終端なし
#   out.2 = B02 create: 改行のみ（空出力 '-' と区別する）
#   out.3 = B03 list: 末尾に余分な空行
#   out.4 = B06 list: 検査上限（64 KiB）を超える（先頭は正常な行）
#   out.5 = B09 delete: NUL を含む
#   out.6 = B10 list: 最終レコードが LF 終端なし
outdir="$work/outtable"
mkdir -p "$outdir"
printf 'ID\tSTATUS\tPID' >"$outdir/out.1"
printf '\n' >"$outdir/out.2"
printf 'ID\tSTATUS\tPID\nc1\tcreated\t-\n\n' >"$outdir/out.3"
{
  printf 'ID\tSTATUS\tPID\n'
  i=0
  while [ "$i" -lt 8000 ]; do
    printf 'x%s\tcreated\t-\n' "$i"
    i=$((i + 1))
  done
} >"$outdir/out.4"
printf 'a\000b' >"$outdir/out.5"
printf 'ID\tSTATUS\tPID\nc1\tcreated\t4242' >"$outdir/out.6"

# --------------------------------------------------
# capture を同時に起動し、全て終わってから照合する。
# --------------------------------------------------
start_capture() { # <名前> <mode> [追加引数...]。結果は $work/<名前>.txt / .err / .rc
  local name="$1" mode="$2"
  shift 2
  (
    STUB_MODE="$mode" "$target" capture --cli "$stub" --output "$work/$name.txt" "$@" >/dev/null 2>"$work/$name.err"
    printf '%s\n' "$?" >"$work/$name.rc"
  ) &
}
rc_of() { # <名前>
  local v="missing"
  [ -f "$work/$1.rc" ] && IFS= read -r v <"$work/$1.rc"
  printf '%s' "$v"
}
line_of() { # <名前> <case id>
  local line found=""
  [ -f "$work/$1.txt" ] || return 0
  while IFS= read -r line; do
    case "$line" in "$2$tab"*)
      found="$line"
      break
      ;;
    esac
  done <"$work/$1.txt"
  printf '%s' "$found"
}
expect_line() { # <表示名> <名前> <期待する行>
  expect_eq "$1" "$3" "$(line_of "$2" "${3%%"$tab"*}")"
}

mkdir -p "$work/tmpdir"
: >"$work/pids.txt"
start_capture ok ok
# 無効な LC_ALL（#1548・CLI-1）。bash 製スタブの setlocale 警告が stderr に混ざらず、CLI へは C が渡る。
LC_ALL=xx_XX.UTF-8 STUB_LOCALE_FILE="$work/locale.txt" start_capture lcall ok
start_capture nonlinux nonlinux
TMPDIR="$work/tmpdir" start_capture diff diff
start_capture noisy noisy
STUB_PIDFILE="$work/pids.txt" start_capture hang hang --timeout 1
STUB_ERR_DIR="$errdir" start_capture errtable ok
STUB_ERR_DIR="$errmax" STUB_OUT_DIR="$pidout" start_capture errmax ok
STUB_OUT_DIR="$outdir" start_capture outtable ok
wait

for name in ok lcall nonlinux diff noisy errtable errmax outtable; do
  expect_rc "capture $name exits 0" 0 "$(rc_of "$name")"
done
for name in ok lcall nonlinux diff noisy errtable errmax outtable; do
  # 失敗の調査用。capture の stderr は固定語彙の 1 行で、パスや環境の値を含まない。
  [ "$(rc_of "$name")" = "0" ] || [ ! -s "$work/$name.err" ] || sed "s/^/  $name stderr: /" "$work/$name.err"
done

# --- capture: 具体値 ---
count=0
while IFS= read -r l; do
  case "$l" in [AB][0-9][0-9]"$tab"*) count=$((count + 1)) ;; esac
done <"$work/ok.txt"
expect_eq "capture records 33 cases" 33 "$count"
expect_line "A02 usage error" ok "A02${tab}A${tab}2${tab}INVALID_ARGUMENT${tab}-"
expect_line "B01 empty list" ok "B01${tab}B${tab}0${tab}-${tab}list:H"
expect_line "B03 list after create" ok "B03${tab}B${tab}0${tab}-${tab}list:H;c1,created,-"
expect_line "B04 duplicate create" ok "B04${tab}B${tab}4${tab}ALREADY_EXISTS${tab}-"
# --- 無効な LC_ALL（#1548） ---
# macOS の bash 3.2 は警告を出さないことがあり、その環境ではこのケースが回帰を判別しない（診断のみ。値の照合は全 OS で行う）。
warn_probe="$(LC_ALL=xx_XX.UTF-8 bash -c : 2>&1 || true)"
if [ -n "$warn_probe" ]; then echo "note: invalid LC_ALL emits a bash warning on this runner: yes"; else echo "note: invalid LC_ALL emits a bash warning on this runner: no"; fi
expect_line "lcall A02 usage error" lcall "A02${tab}A${tab}2${tab}INVALID_ARGUMENT${tab}-"
expect_line "lcall B01 empty list" lcall "B01${tab}B${tab}0${tab}-${tab}list:H"
expect_line "lcall B04 duplicate create" lcall "B04${tab}B${tab}4${tab}ALREADY_EXISTS${tab}-"
expect_line "lcall B15 missing state root" lcall "B15${tab}B${tab}3${tab}NOT_FOUND${tab}-"
loc_n=0
loc_bad=0
while IFS= read -r l; do
  loc_n=$((loc_n + 1))
  [ "$l" = "C" ] || loc_bad=$((loc_bad + 1))
done <"$work/locale.txt"
expect_eq "lcall stub invocations" 33 "$loc_n"
expect_eq "lcall stub got LC_ALL other than C" 0 "$loc_bad"
expect_line "B15 missing state root" ok "B15${tab}B${tab}3${tab}NOT_FOUND${tab}-"
{
  IFS= read -r meta1
  IFS= read -r meta2
  IFS= read -r meta3
} <"$work/ok.txt"
expect_eq "format header line" '# fandhe-container-cli-parity v1' "$meta1"
case "$meta2" in
  '# os=linux' | '# os=macos' | '# os=windows') pass "os line present" ;;
  *) fail "os line present (got '$meta2')" ;;
esac
expect_eq "columns line" "case${tab}layer${tab}exit${tab}code${tab}stdout" "$meta3"

# --- capture: 既存ファイルへの --output / 引数不足 / CLI 不在 ---
STUB_MODE=ok "$target" capture --cli "$stub" --output "$work/ok.txt" >/dev/null 2>&1
expect_rc "capture refuses existing --output" 2 $?
"$target" capture --cli "$stub" >/dev/null 2>&1
expect_rc "capture without --output is rc 2" 2 $?
"$target" capture --cli relative/path --output "$work/rel.txt" >/dev/null 2>&1
expect_rc "capture with relative --cli is rc 2" 2 $?
"$target" capture --cli "$work/does-not-exist" --output "$work/none.txt" >/dev/null 2>&1
expect_rc "capture with missing CLI is rc 3" 3 $?
if [ ! -e "$work/none.txt" ]; then pass "no output file for missing CLI"; else fail "no output file for missing CLI"; fi

# --- compare ---
# compare は「基準 = Linux の capture、候補 = 別 OS の capture」だけを受け付ける。自己テストは 1 つの OS
# でしか capture を取れないため、fixture の os 行（2 行目）だけを書き換えた写しを作って渡す
# （基準は linux、候補は macos）。判定ロジックには手を入れず、製品と同じ経路を通す。
with_os() { # <名前> <os>。$work/<名前>.<os>.txt を作る
  local l2=""
  [ -f "$work/$1.txt" ] || return 0
  {
    IFS= read -r _
    IFS= read -r l2
  } <"$work/$1.txt"
  case "$l2" in
    '# os='*)
      # 1 行目と 3 行目以降はバイト列のまま写す（NUL・余分なタブ・LF 終端なし等の壊れ方を保つ）。
      {
        head -n 1 "$work/$1.txt"
        printf '# os=%s\n' "$2"
        tail -n +3 "$work/$1.txt"
      } >"$work/$1.$2.txt"
      ;;
    *) cp "$work/$1.txt" "$work/$1.$2.txt" ;; # os 行を持たない壊れた入力はそのまま渡す
  esac
}
compare_raw() { # <baseline ファイル名> <candidate ファイル名>（$work からの相対）。os 行は書き換えない
  "$target" compare --baseline "$work/$1" --candidate "$work/$2" >"$work/cmp.txt" 2>&1
}
compare() { # <baseline 名> <candidate 名>。出力は $work/cmp.txt、終了コードを返す
  with_os "$1" linux
  with_os "$2" macos
  compare_raw "$1.linux.txt" "$2.macos.txt"
}
cmp_has() { # <表示名> <cmp.txt に完全一致で現れるべき行>
  local line hit=0
  while IFS= read -r line; do
    [ "$line" = "$2" ] && hit=1
  done <"$work/cmp.txt"
  if [ "$hit" -eq 1 ]; then pass "$1"; else fail "$1 (line not found: $2)"; fi
}
cmp_has_prefix() { # <表示名> <cmp.txt のいずれかの行の先頭に現れるべき文字列>
  local line hit=0
  while IFS= read -r line; do
    case "$line" in "$2"*) hit=1 ;; esac
  done <"$work/cmp.txt"
  if [ "$hit" -eq 1 ]; then pass "$1"; else fail "$1 (prefix not found: $2)"; fi
}

compare ok ok
expect_rc "compare identical is rc 0" 0 $?
cmp_has "layer A summary" 'layer A (syntax): match=18 mismatch=0 missing=0'
cmp_has "layer B summary" 'layer B (behavior): match=15 mismatch=0 missing=0'
compare ok lcall
expect_rc "compare ok vs lcall is rc 0" 0 $?
cmp_has "lcall layer A summary" 'layer A (syntax): match=18 mismatch=0 missing=0'
cmp_has "lcall layer B summary" 'layer B (behavior): match=15 mismatch=0 missing=0'

compare ok diff
expect_rc "compare with changed exit code is rc 1" 1 $?
cmp_has_prefix "B03 reported as MISMATCH" 'B03 MISMATCH'
cmp_has "unchanged case stays MATCH" 'B01 MATCH'

compare ok nonlinux
expect_rc "non-linux stub differs in layer B (rc 1)" 1 $?
cmp_has "non-linux layer A all match" 'layer A (syntax): match=18 mismatch=0 missing=0'
cmp_has "non-linux layer B mismatches (B08 coincides at 5)" 'layer B (behavior): match=1 mismatch=14 missing=0'

# ケース欠落は MISSING
grep -v "^B05${tab}" "$work/ok.txt" >"$work/missing.txt"
compare ok missing
expect_rc "missing case is rc 1" 1 $?
cmp_has_prefix "B05 reported as MISSING" 'B05 MISSING'

# 両側から同じケースが欠落しても MISSING（期待 ID 集合は CASES から作る）
compare missing missing
expect_rc "case missing on both sides is rc 1" 1 $?
cmp_has_prefix "B05 missing on both sides reported" 'B05 MISSING'

# 環境に結果変数と同名の変数があっても、ファイルに無いケースを読み込んだことにしない。
base_B05="0/-/-" cand_B05="0/-/-" base_ids="B05" cand_os="macos" compare missing missing
expect_rc "inherited env vars do not hide a missing case (rc 1)" 1 $?
cmp_has "B05 still MISSING with base_B05/cand_B05 in env" 'B05 MISSING (baseline=absent candidate=absent)'
cmp_has "layer B counts the missing case" 'layer B (behavior): match=14 mismatch=0 missing=1'
# 想定外 ID（B99）と同名の環境変数があっても重複扱いにならず、片側だけにある ID は MISSING になる。
{
  cat "$work/ok.txt"
  printf 'B99\tB\t0\t-\t-\n'
} >"$work/extra.txt"
base_B99="0/-/-" cand_B99="0/-/-" compare extra ok
expect_rc "inherited env var for an unexpected id is ignored (rc 1)" 1 $?
cmp_has "B99 MISSING on candidate side" 'B99 MISSING (baseline=0/-/- candidate=absent)'

# --- compare の前提: 基準は Linux の capture、候補は別 OS の capture（それ以外は rc 3） ---
with_os ok linux
with_os ok macos
with_os ok windows
compare_raw ok.linux.txt ok.windows.txt
expect_rc "linux baseline vs windows candidate is compared (rc 0)" 0 $?
cmp_has "os line is reported" 'baseline os=linux candidate os=windows'
compare_raw ok.macos.txt ok.macos.txt
expect_rc "macos vs macos is rc 3" 3 $?
cmp_has "non-linux baseline message" 'error: missing-prerequisite: --baseline must be a capture taken on linux'
compare_raw ok.macos.txt ok.linux.txt
expect_rc "macos baseline vs linux candidate is rc 3" 3 $?
compare_raw ok.windows.txt ok.macos.txt
expect_rc "windows baseline vs macos candidate is rc 3" 3 $?
compare_raw ok.linux.txt ok.linux.txt
expect_rc "linux vs linux is rc 3" 3 $?
cmp_has "same-os candidate message" 'error: missing-prerequisite: --candidate must be a capture taken on an OS other than linux'
if grep -q 'MATCH' "$work/cmp.txt"; then fail "rejected compare printed verdicts"; else pass "rejected compare prints no verdicts"; fi
# 入力の書式エラー（rc 2）は OS の前提（rc 3）より先に判定する。
compare_raw ok.macos.txt broken-not-there.txt
expect_rc "invalid input wins over os precondition (rc 2)" 2 $?

# --- タイムアウト ---
expect_rc "hanging CLI is rc 1" 1 "$(rc_of hang)"
# 終了コード欄は強制終了のシグナル（TERM = 143 / KILL = 137）で変わるため、タイムアウトの印だけを照合する。
case "$(line_of hang A02)" in
  "A02${tab}A${tab}143${tab}<timeout>${tab}<timeout>" | "A02${tab}A${tab}137${tab}<timeout>${tab}<timeout>")
    pass "A02 recorded as timeout"
    ;;
  *) fail "A02 recorded as timeout (got '$(line_of hang A02)')" ;;
esac
# タイムアウト記録同士は値が一致しても rc 1
compare hang hang
expect_rc "matching timeout records are rc 1" 1 $?
cmp_has_prefix "A02 timeout reported" 'A02 TIMEOUT'
# タイムアウト時に子孫プロセス（スタブの sleep）が残らない
alive=0
recorded=0
while IFS= read -r p; do
  recorded=$((recorded + 1))
  kill -0 "$p" 2>/dev/null && alive=$((alive + 1))
done <"$work/pids.txt"
if [ "$recorded" -ge 1 ] && [ "$alive" -eq 0 ]; then
  pass "no descendant left after timeout"
else
  fail "descendants left after timeout (recorded=$recorded alive=$alive)"
fi

# --- 壊れた capture は rc 2 ---
printf 'garbage\n' >"$work/broken.txt"
compare ok broken
expect_rc "compare with broken capture is rc 2" 2 $?
sed "s/^A02${tab}A${tab}2/A02${tab}A${tab}999/" "$work/ok.txt" >"$work/badexit.txt"
compare ok badexit
expect_rc "compare with malformed exit field is rc 2" 2 $?
"$target" compare --baseline "$work/ok.linux.txt" >/dev/null 2>&1
expect_rc "compare without --candidate is rc 2" 2 $?

# stdout 欄が正規化形式でない capture は拒否する（garbage / list:garbage / 種別 n の list 形式）
sed "s/^B03${tab}B${tab}0${tab}-${tab}.*/B03${tab}B${tab}0${tab}-${tab}garbage/" "$work/ok.txt" >"$work/g1.txt"
compare g1 g1
expect_rc "garbage stdout field is rejected" 2 $?
sed "s/^B03${tab}B${tab}0${tab}-${tab}.*/B03${tab}B${tab}0${tab}-${tab}list:garbage/" "$work/ok.txt" >"$work/g2.txt"
compare g2 g2
expect_rc "list:garbage stdout field is rejected" 2 $?
sed "s/^B02${tab}B${tab}0${tab}-${tab}.*/B02${tab}B${tab}0${tab}-${tab}list:H/" "$work/ok.txt" >"$work/g3.txt"
compare g3 g3
expect_rc "list form on a non-list case is rejected" 2 $?

# 元のバイト列で検証する: 余分なタブ（空欄）・NUL・LF 終端なしは、read が畳んだ後の値が正常でも拒否する。
# 両側に同じ壊れたファイルを渡し、MATCH（rc 0）にならないことを確かめる。
sed "s/^A02${tab}A${tab}2${tab}/A02${tab}A${tab}${tab}2${tab}/" "$work/ok.txt" >"$work/t1.txt"
compare t1 t1
expect_rc "doubled tab (empty column) is rejected" 2 $?
sed "s/^A02${tab}.*/&${tab}/" "$work/ok.txt" >"$work/t2.txt"
compare t2 t2
expect_rc "trailing tab is rejected" 2 $?
sed "s/^A02${tab}/${tab}A02${tab}/" "$work/ok.txt" >"$work/t3.txt"
compare t3 t3
expect_rc "leading tab is rejected" 2 $?
sed "s/^A02${tab}A${tab}2${tab}INVALID_ARGUMENT/A02${tab}A${tab}2${tab}INVALID_ZARGUMENT/" "$work/ok.txt" | LC_ALL=C tr 'Z' '\000' >"$work/t4.txt"
compare t4 t4
expect_rc "NUL inside a field is rejected" 2 $?
printf '%s' "$(cat "$work/ok.txt")" >"$work/t5.txt"
compare t5 t5
expect_rc "capture without trailing newline is rejected" 2 $?

# --- 情報漏えい防止: パス風文字列・制御文字・ホスト名が記録に現れない ---
if grep -qE 'secret-user|host-leak|/home' "$work/noisy.txt"; then fail "noisy output leaked into capture"; else pass "noisy output not leaked"; fi
if LC_ALL=C grep -q "$(printf '\001')" "$work/noisy.txt"; then fail "control char leaked into capture"; else pass "control chars not leaked"; fi
expect_line "unexpected stdout is summarized" noisy "B02${tab}B${tab}0${tab}-${tab}<unexpected>:1"
expect_line "raw control char in stderr is unparsed" noisy "A02${tab}A${tab}2${tab}<unparsed>${tab}-"

# --- 解析不能な出力同士は一致扱いにしない（UNVERIFIED・rc 1） ---
compare noisy noisy
expect_rc "identical <unexpected> records are rc 1" 1 $?
cmp_has_prefix "B02 <unexpected> reported as UNVERIFIED" 'B02 UNVERIFIED'
cmp_has_prefix "A02 <unparsed> reported as UNVERIFIED" 'A02 UNVERIFIED'

# --- stderr 1 行 JSON の 2 つの形（固定文言・core 由来の op 付き）の受理と、壊れた形の拒否（ERR-1・ERR-2） ---
# スタブの create / start / stop / delete の失敗は製品と同じ op 付きで出している。code だけが記録に残る。
expect_line "op form (start) yields code" ok "B11${tab}B${tab}3${tab}NOT_FOUND${tab}-"
expect_line "op form (stop = kill) yields code" ok "B12${tab}B${tab}3${tab}NOT_FOUND${tab}-"
expect_line "op form (delete) yields code" ok "B13${tab}B${tab}3${tab}NOT_FOUND${tab}-"
expect_line "fixed form (logs) yields code" ok "B14${tab}B${tab}3${tab}NOT_FOUND${tab}-"
if grep -qE '"op"|kill|start|delete' "$work/ok.txt"; then fail "op leaked into capture"; else pass "op is not recorded"; fi

i=0
for want in "${want_codes[@]}"; do
  i=$((i + 1))
  cid="$(printf 'A%02d' "$i")"
  expect_line "stderr fixture $cid -> $want" errtable "${cid}${tab}A${tab}2${tab}${want}${tab}-"
done
if grep -qE 'usage|exists|"message"' "$work/errtable.txt"; then fail "stderr message leaked into capture"; else pass "stderr message not recorded"; fi

expect_line "max-length escaped message is accepted" errmax "A01${tab}A${tab}2${tab}INVALID_ARGUMENT${tab}-"
expect_line "oversized stderr is unparsed" errmax "A02${tab}A${tab}2${tab}<unparsed>${tab}-"
expect_line "truncated JSON stderr is unparsed" errmax "A03${tab}A${tab}2${tab}<unparsed>${tab}-"
expect_line "multi-line stderr is unparsed" errmax "A04${tab}A${tab}2${tab}<unparsed>${tab}-"
expect_line "NUL in stderr is unparsed" errmax "A05${tab}A${tab}2${tab}<unparsed>${tab}-"
expect_line "non-ASCII in op is unparsed" errmax "A06${tab}A${tab}2${tab}<unparsed>${tab}-"
expect_line "non-ASCII in code is unparsed" errmax "A07${tab}A${tab}2${tab}<unparsed>${tab}-"
expect_line "non-ASCII in message is accepted" errmax "A08${tab}A${tab}2${tab}NOT_FOUND${tab}-"
expect_line "numeric PID column is replaced" errmax "B01${tab}B${tab}0${tab}-${tab}list:H;c1,running,<pid>;c2,created,-"
expect_line "CRLF-terminated list is unexpected" errmax "B03${tab}B${tab}0${tab}-${tab}<unexpected>:2"

# 片側だけ壊れた stderr は、正常な baseline と MATCH にならない（A08 = 未エスケープの引用符）。
compare ok errtable
expect_rc "broken stderr on one side is rc 1" 1 $?
cmp_has_prefix "A08 broken JSON reported as UNVERIFIED" 'A08 UNVERIFIED'
cmp_has "A01 valid fixed form still MATCH" 'A01 MATCH'

# --- stdout の異常（LF 終端なし・改行のみ・余分な空行・上限超過・NUL）は正常出力と区別する ---
expect_line "list header without LF is unexpected" outtable "B01${tab}B${tab}0${tab}-${tab}<unexpected>:0"
expect_line "newline-only stdout is unexpected" outtable "B02${tab}B${tab}0${tab}-${tab}<unexpected>:1"
expect_line "trailing blank line in list is unexpected" outtable "B03${tab}B${tab}0${tab}-${tab}<unexpected>:3"
expect_line "oversized list is unexpected" outtable "B06${tab}B${tab}0${tab}-${tab}<unexpected>:big"
expect_line "NUL stdout is unexpected" outtable "B09${tab}B${tab}0${tab}-${tab}<unexpected>:nul"
expect_line "last list record without LF is unexpected" outtable "B10${tab}B${tab}0${tab}-${tab}<unexpected>:1"
compare ok outtable
expect_rc "abnormal stdout differs from ok (rc 1)" 1 $?
for cid in B01 B02 B03 B06 B09 B10; do
  cmp_has_prefix "$cid abnormal stdout reported as UNVERIFIED" "$cid UNVERIFIED"
done
compare outtable outtable
expect_rc "unexpected-stdout captures pass format validation (rc 1, not 2)" 1 $?

# --- 後始末: capture 自身の mktemp -d が残らない（diff の capture は TMPDIR を専用ディレクトリにしている） ---
leftover=0
for f in "$work/tmpdir"/* "$work/tmpdir"/.[!.]*; do
  [ -e "$f" ] && leftover=$((leftover + 1))
done
expect_eq "no leftover temp directories" 0 "$leftover"

if [ "$fails" -ne 0 ]; then
  printf '%s check(s) failed\n' "$fails"
  exit 1
fi
printf 'all cli-parity-check self tests passed\n'
