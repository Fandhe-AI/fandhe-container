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
# scripts/cli-parity-check-selftest.sh（`make cli-parity-selftest`。CI の platform-ci ジョブ）。
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
#   2 = 引数・入力・出力先エラー / 3 = 前提欠如（CLI 不在・実行不可・未対応 OS、compare の基準が
#   Linux の capture でない・候補が基準と同じ OS。0 で合格に見せない）。
#
# 後始末の限界: タイムアウト・中断時の回収は CLI を起動したプロセスグループ単位で行う。CLI の子孫が
# setsid 等で別セッション / 別グループへ出た場合は回収できない（追跡手段が無い。REPAIR-5 の範囲外として残る）。
# Windows（Git Bash）のネイティブ exe の子は POSIX の pgid を持たないため、未回収の CLI に限り
# taskkill /T でツリーごと回収する（kill_win_tree。#1548）。CLI の正常終了後に残った子孫と、期限前に
# 親が死んで孤児になった子孫は辿れない。CI での確認は scripts/cli-parity-native-reclaim-check.sh。
# taskkill と run_cli の wait には wall clock の上限が無い（kill が届かないと塞がる。#1688）。CI では
# reclaim-check 側の全体期限（既定 150 秒）で外から止めている。
#
# 動作環境: bash 3.2 以上（macOS 標準）。GNU / BSD 双方のツールで動く書き方にしている。
# Windows は Git Bash で実行する。自己テスト（スタブ CLI）は CI の windows runner でも実行するが、
# 製品バイナリ（ネイティブ exe）に対する動作は実機確認（#661）の範囲で、CI では確かめていない。
# Git Bash はプロセス生成が遅いため、判定は可能な限り bash の組み込みで行い外部コマンドを減らしている。
set -euo pipefail

# 文字クラス・範囲・文字列長（${#var} はバイト数になる）の解釈を実行環境のロケールに依存させない
# （OS 間で判定が変わるのを防ぐ）。検査対象の CLI も同じ LC_ALL=C で実行する（#1548・CLI-1）。製品 CLI は
# setlocale を呼ばず出力は英語固定のため、ホストのロケールを渡しても比較の情報は増えない。一方、無効な
# LC_ALL を bash 製スタブへ渡すと子の bash が setlocale 警告を stderr に足し、code の判定を壊す。
# 残る限界: 本スクリプト自身の起動時に bash が出す setlocale 警告（スクリプトの stderr）は抑えられないが、
# 記録内容と終了コードには影響しない。
export LC_ALL=C

# Git Bash（MSYS2）か。ネイティブ exe の子孫回収（kill_win_tree）を Windows でだけ行うために使う。
case "${OSTYPE:-}" in msys* | cygwin*) readonly IS_WINDOWS_HOST=1 ;; *) readonly IS_WINDOWS_HOST=0 ;; esac

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
#
# シグナルはグループ宛て（負の pid）だけに送り、送る前に毎回グループの生存を確かめる。グループに
# 生存メンバーがいる間、その pgid は別プロセスの pid として再利用されない。メンバーが居なくなれば
# 生存確認が失敗して何も送らないため、回収済みの pid が再利用されていても無関係なプロセスを撃たない。
# リーダー（pid = pgid）もグループ宛てのシグナルに含まれるので、pid 単体へは送らない。
kill_group() {
  local pg="$1" w=0
  kill -0 -- "-$pg" 2>/dev/null || return 0
  kill -TERM -- "-$pg" 2>/dev/null || true
  while kill -0 -- "-$pg" 2>/dev/null && [ "$w" -lt 5 ]; do
    sleep 0.1
    w=$((w + 1))
  done
  if kill -0 -- "-$pg" 2>/dev/null; then
    kill -KILL -- "-$pg" 2>/dev/null || true
  fi
  w=0
  while kill -0 -- "-$pg" 2>/dev/null && [ "$w" -lt 50 ]; do
    sleep 0.1
    w=$((w + 1))
  done
}

# Windows のネイティブ exe の子孫を taskkill /T でツリーごと回収する（#1548・REPAIR-5）。Git Bash では
# ネイティブ exe の子が POSIX の pgid を持たず kill_group が届かない。Windows の PID は /proc/<pid>/winpid
# から数字だけ読み、検証してから渡す（インジェクション防止）。呼んでよいのは CLI が未回収の間だけ
# （回収済みの pid の winpid を使わない）。先に親が死ぬと /T が辿れないので kill_group より前に呼ぶ。
kill_win_tree() {
  [ "$IS_WINDOWS_HOST" -eq 1 ] || return 0
  local w=""
  [ -r "/proc/$1/winpid" ] || return 0
  IFS= read -r w <"/proc/$1/winpid" || true
  case "$w" in '' | *[!0-9]* | ???????????*) return 0 ;; esac
  taskkill //F //T //PID "$w" >/dev/null 2>&1 || true
}

# 未回収（まだ wait していない）の子 $1 が、グループ宛ての回収の後も生きている場合に限り pid 単体へ
# KILL を送る。set -m が効かずプロセスグループが分かれなかった環境で、ハングした CLI を残さないための
# 保険。呼び出してよいのは親が wait する前だけ（未回収の子の pid は再利用されない）。
kill_unreaped_child() {
  if kill -0 "$1" 2>/dev/null; then
    kill -KILL "$1" 2>/dev/null || true
  fi
}

cleanup() {
  if [ -n "$watchdog_pid" ]; then
    kill -KILL "$watchdog_pid" 2>/dev/null || true
    watchdog_pid=""
  fi
  # 中断時に実行中の CLI とその子孫を残さない。グループごと回収を待ってから一時ディレクトリを消す。
  # run_pid は run_cli が wait を終えた直後に空にするので、ここへ来る時点では未回収である。
  if [ -n "$run_pid" ]; then
    kill_win_tree "$run_pid"
    kill_group "$run_pid"
    kill_unreaped_child "$run_pid"
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
run_seq=0
run_cli() {
  local cli="$1" limit="$2"
  shift 2
  local pid ticks i marker
  : >"$tmp_dir/out"
  : >"$tmp_dir/err"
  # 期限切れの印は実行ごとに別名にする（前回の印を消す外部コマンドを不要にする）。
  run_seq=$((run_seq + 1))
  marker="$tmp_dir/timed_out.$run_seq"
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
    # 期限切れ。親はまだ wait 中で CLI は未回収なので、pid は CLI 自身を指している。親が wait を
    # 終えていたら（done の印）何もしない（回収済みの pid を調べない・撃たない）。
    if [ ! -e "$marker.done" ] && kill -0 "$pid" 2>/dev/null; then
      : >"$marker"
      kill_win_tree "$pid"
      kill_group "$pid"
      [ -e "$marker.done" ] || kill_unreaped_child "$pid"
    fi
  ) &
  watchdog_pid=$!
  run_exit=0
  wait "$pid" || run_exit=$?
  # ここから先、pid は回収済みで再利用され得る。pid 単体へは何も送らない。
  run_pid=""
  : >"$marker.done"
  # 正常終了後に残った子孫（バックグラウンド起動の残り等）をグループごと回収する。kill_group は
  # グループに生存メンバーがいる場合だけシグナルを送る。
  kill_group "$pid"
  # 監視サブシェルは KILL で止める。TERM だと、fork 直後でまだ親の trap を引き継いだままの監視
  # サブシェルが「cleanup; exit 143」を実行し、実行中の一時ディレクトリを消してしまう（CLI が即座に
  # 終わる場合に高負荷で起きる競合）。KILL は trap を通らない。監視が残す子は sleep 0.1 だけである。
  kill -KILL "$watchdog_pid" 2>/dev/null || true
  wait "$watchdog_pid" 2>/dev/null || true
  watchdog_pid=""
  if [ -e "$marker" ]; then
    run_timed_out=1
  else
    run_timed_out=0
  fi
}

# stderr から機械可読な code だけを取り出す（文言・パス・op は写さない）。
#
# 受理する形は製品 CLI が出す次の 2 つだけで、どちらも 1 行・LF 終端・空白なし・キー順固定（ERR-1・ERR-2）:
#   固定文言: {"code":"X","message":"..."}          （使い方エラー・未実装・状態ルート不在など）
#   core 由来: {"op":"O","code":"X","message":"..."}  （OciRuntimeError::write_json_line。O は
#              create / start / kill / delete。stop は kill になる）
# op の有無と値は記録・比較の対象にしない（機械可読契約は code。op は core の付加情報で、CLI の
# エラー形式は TASK-95〔ERR 系〕で確定するため、op の有無を OS 差として数えない）。
# キーの追加など形式が変わった場合は ERR_LINE_RE を追従させる（追従前は <unparsed> になり合格に見えない）。
#
# message は JSON 文字列として検証する: 未エスケープの `"`・`\`・制御文字（U+0000〜U+001F）を拒否し、
# エスケープは \" \\ \/ \b \f \n \r \t \uXXXX だけを受理する。非 ASCII バイトは UTF-8 として妥当な
# ときだけ受理する（iconv で検証。iconv が無ければ検証できないので受理しない）。
# 検証できない出力（上限超過・NUL・LF が行末の 1 個でない・キーの欠落 / 追加 / 順序違い・不正な文字列）は、
# code らしき文字列を含んでいても一致扱いにせず <unparsed> とする。
#
# 上限 MAX_ERR_BYTES は core の message 上限（OCI_ERROR_MESSAGE_MAX_BYTES = 4096 バイト）が全バイト
# 2 バイトへエスケープされた場合（8192）と外枠を収める値にしている（正規の出力を上限で落とさない）。
readonly MAX_ERR_BYTES=16384
readonly JSON_STR_BODY='([^"\\[:cntrl:]]|\\["\\/bfnrt]|\\u[0-9a-fA-F]{4})*'
readonly ERR_LINE_RE='^\{("op":"[a-z_]{1,32}",)?"code":"([A-Z_]{1,40})","message":"'"$JSON_STR_BODY"'"\}$'
# 結果は norm_code_out に入れる（コマンド置換のサブシェルを作らない。Git Bash はプロセス生成が遅い）。
norm_code_out=""
norm_code() {
  local e rest size
  if [ ! -s "$tmp_dir/err" ]; then
    norm_code_out='-'
    return 0
  fi
  norm_code_out='<unparsed>'
  # wc の出力は実装により前後に空白が付く。算術展開で数値だけにする。
  size=$(($(wc -c <"$tmp_dir/err")))
  [ "$size" -le "$MAX_ERR_BYTES" ] || return 0
  # 1 行目を組み込みの read で読む。read の成功は LF 終端を意味する。read は NUL を黙って落とすので、
  # 「読めたバイト数 + LF 1 個 = ファイルのバイト数」の一致で、NUL が無いこと・LF が行末の 1 個だけで
  # あること・2 行目が無いことをまとめて確かめる（LC_ALL=C なので ${#e} はバイト数）。
  e=""
  IFS= read -r e <"$tmp_dir/err" || return 0
  [ $((${#e} + 1)) -eq "$size" ] || return 0
  # 印字可能 ASCII（0x20〜0x7E）以外のバイトを含む場合だけ外部コマンドで検証する（製品の固定文言は
  # ASCII のみなので通常は通らない）。
  rest="${e//[ -~]/}"
  if [ -n "$rest" ]; then
    # U+0001〜U+001F の制御文字（CR を含む）は JSON 文字列に生では書けない。先に拒否する。
    case "$e" in
      *[$'\001'-$'\037']*) return 0 ;;
    esac
    command -v iconv >/dev/null 2>&1 || return 0
    iconv -f UTF-8 -t UTF-8 <"$tmp_dir/err" >/dev/null 2>&1 || return 0
    # 残るのは DEL と非 ASCII バイト（上で UTF-8 として検証済み）で、JSON 文字列内にそのまま書ける。
    # 照合前に ASCII の 1 文字へ写し、正規表現が ASCII だけを見るようにする（OS ごとの正規表現実装の
    # 高位バイトの扱いの差を避ける）。写像先は `~` にする: op（[a-z_]）・code（[A-Z_]）・キー名・
    # 構造文字のどれにも含まれず、message の文字列本体でだけ受理される。これで非 ASCII を含む op や
    # code は写像後も字句の正規表現に合わず拒否される。
    # 写像は read 済みの値に対して組み込みで行う。ファイルをコマンド置換で読み直してはならない
    # （Git Bash の bash はコマンド置換の結果から CR を落とすため、CRLF 終端の出力が LF 終端と
    # 区別できなくなる。自己テストの CRLF fixture が windows runner で検出した）。
    e="${e//[! -~]/~}"
  fi
  if [[ $e =~ $ERR_LINE_RE ]]; then
    norm_code_out="${BASH_REMATCH[2]}"
  fi
  return 0
}

# stdout を正規化する。種別 l は list 形式（ヘッダ + 行）を厳格に検査し PID 列を <pid> へ置換する。
# 結果は norm_stdout_out に入れる。
norm_stdout_out=""
norm_stdout() {
  local kind="$1" line header_expected row_re joined first ok raw stripped pidcol
  # 空判定は元ファイルのバイト数で行う（改行のみ・NUL 含みの出力が空出力と同じ '-' になるのを防ぐ）。
  # 内容は写さず異常として記録する。
  if [ ! -s "$tmp_dir/out" ]; then
    norm_stdout_out='-'
    return 0
  fi
  raw=$(($(wc -c <"$tmp_dir/out")))
  stripped=$(($(tr -d '\000' <"$tmp_dir/out" | wc -c)))
  if [ "$stripped" -ne "$raw" ]; then
    norm_stdout_out='<unexpected>:nul'
    return 0
  fi
  # 検査上限を超える出力は先頭が正常でも後続を検査できないため、一致扱いにせず異常として記録する。
  if [ "$raw" -gt 65536 ]; then
    norm_stdout_out='<unexpected>:big'
    return 0
  fi
  ok=0
  joined=""
  if [ "$kind" = "l" ]; then
    # 行単位検査は元ファイルから直接読む（コマンド置換は末尾の空行を落とし、余分な空行を見逃すため）。
    header_expected="ID${TAB}STATUS${TAB}PID"
    row_re="^([A-Za-z0-9_-]{1,64})${TAB}([a-z]{1,16})${TAB}([0-9]{1,10}|-)$"
    first=1
    ok=1
    line=""
    # read は LF で終わらない最終行を「失敗 + 非空の line」で返す。それを行として扱うと、LF 終端の
    # 無い出力が正規の出力と同じ記録になるため、ループでは LF 終端の行だけを処理し、残りは下で異常にする。
    while IFS= read -r line; do
      if [ "$first" -eq 1 ]; then
        first=0
        if [ "$line" != "$header_expected" ]; then
          ok=0
          break
        fi
        joined="H"
      elif [[ $line =~ $row_re ]]; then
        pidcol="${BASH_REMATCH[3]}"
        [ "$pidcol" = "-" ] || pidcol="<pid>"
        joined="${joined};${BASH_REMATCH[1]},${BASH_REMATCH[2]},${pidcol}"
      else
        ok=0
        break
      fi
    done <"$tmp_dir/out"
    # 最終行が LF で終わっていない（出力の改行は LF 固定。CLI-1）、またはヘッダ行が無い。
    if [ -n "$line" ] || [ "$first" -eq 1 ]; then
      ok=0
    fi
  fi
  if [ "$ok" -eq 1 ]; then
    norm_stdout_out="list:${joined}"
  else
    norm_stdout_out="<unexpected>:$(($(wc -l <"$tmp_dir/out")))"
  fi
  return 0
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
    norm_code
    norm_stdout "$kind"
    lines+=("${id}${TAB}${layer}${TAB}${run_exit}${TAB}${norm_code_out}${TAB}${norm_stdout_out}")
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
  # 結果を入れる変数を先に消す。同名の変数が環境から渡っていると（例: base_B05）、ファイルに無い
  # ケースを「読み込んだ」と誤認し、欠落を MATCH にしてしまう。ID の書式（[AB][0-9]{2}）が取り得る
  # 200 個すべてを対象にする（想定外 ID の重複判定も環境の値に影響されないようにする）。
  local u_layer u_n
  unset "${prefix}_os" "${prefix}_ids"
  for u_layer in A B; do
    u_n=0
    while [ "$u_n" -lt 100 ]; do
      if [ "$u_n" -lt 10 ]; then
        unset "${prefix}_${u_layer}0${u_n}"
      else
        unset "${prefix}_${u_layer}${u_n}"
      fi
      u_n=$((u_n + 1))
    done
  done
  [ -f "$file" ] && [ ! -L "$file" ] || { err invalid-input "capture file is not a regular file"; exit 2; }
  local size
  size=$(($(wc -c <"$file")))
  [ "$size" -le $((MAX_LINES * MAX_LINE_LEN)) ] || { err invalid-input "capture file is too large"; exit 2; }
  # bash の read は NUL を黙って落とすため、行単位の検証の前に元のバイト列で NUL を拒否する。
  [ "$(($(LC_ALL=C tr -d '\000' <"$file" | wc -c)))" -eq "$size" ] || { err invalid-input "capture file contains NUL"; exit 2; }
  local id_re='^[AB][0-9]{2}$' ex_re='^[0-9]{1,3}$' code_re='^([A-Z_]{1,40}|-|<unparsed>|<timeout>)$'
  local so_unexp_re='^<unexpected>:(nul|big|[0-9]{1,10})$'
  local so_list_re='^list:H(;[A-Za-z0-9_-]{1,64},[a-z]{1,16},(<pid>|-))*$'
  local k entry_id so_ok
  line=""
  while IFS= read -r line; do
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
          && [[ $code =~ $code_re ]] || { err invalid-input "malformed case line $n"; exit 2; }
        # タブを IFS にした read は連続するタブ・先頭や末尾のタブを 1 個の区切りとして畳む。分解した
        # 5 欄をタブ 1 個ずつで組み直した結果が元の行と一致することを確かめ、余分な空欄を持つ行を拒否する。
        [ "$line" = "${id}${TAB}${layer}${TAB}${ex}${TAB}${code}${TAB}${so}" ] \
          || { err invalid-input "malformed case line $n"; exit 2; }
        # stdout 欄は固定の正規化形式（空 / 異常マーカー / list:H とレコード列）だけを受理し、
        # 種別 n（成功時は空出力）のケースの list 形式は拒否する。種別は固定ケース表から引く。
        k=""
        for entry_id in "${CASES[@]}"; do
          if [ "${entry_id%%|*}" = "$id" ]; then
            k="${entry_id#*|*|}"
            k="${k%%|*}"
            break
          fi
        done
        so_ok=0
        if [ "${#so}" -le 300 ]; then
          if [ "$so" = "-" ] || [ "$so" = "<timeout>" ] || [[ $so =~ $so_unexp_re ]]; then
            so_ok=1
          elif [ "$k" != "n" ] && [[ $so =~ $so_list_re ]]; then
            so_ok=1
          fi
        fi
        [ "$so_ok" -eq 1 ] || { err invalid-input "malformed case line $n"; exit 2; }
        local var="${prefix}_${id}"
        [ -z "${!var+x}" ] || { err invalid-input "duplicate case id"; exit 2; }
        printf -v "$var" '%s' "${ex}/${code}/${so}"
        ids+=("$id")
        ;;
    esac
  done <"$file"
  # read が LF 終端の無い最終行を残した場合（capture は全行を LF 終端で書く）。
  [ -z "$line" ] || { err invalid-input "capture file does not end with a newline"; exit 2; }
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
  # 期待値は「Linux ネイティブ実行と同一」なので、基準は Linux の capture、候補は別 OS の capture で
  # なければ比較が成立しない。同じ OS 同士・非 Linux 基準の全一致を合格に見せない（前提欠如）。
  # shellcheck disable=SC2154 # base_os / cand_os は load_capture が printf -v で間接代入する
  if [ "$base_os" != "linux" ]; then
    err missing-prerequisite "--baseline must be a capture taken on linux"
    exit 3
  fi
  if [ "$cand_os" = "$base_os" ]; then
    err missing-prerequisite "--candidate must be a capture taken on an OS other than linux"
    exit 3
  fi

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
