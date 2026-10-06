#!/usr/bin/env bash
# アイドル時常駐メモリ計測スクリプト（TASK-45.1・CORE-7・SUP-1）。
#
# 役割: コンテナが 0 個のとき、fandhe-container 関連の常駐プロセス数と PSS / RSS の合計を
# /proc から計測して出力する。CORE-7（常駐メモリ目標。PoC-17 supervisor-model の実測で確定済み）
# の前提データ取得と、SUP-1（コンテナ 0 個なら常駐プロセス 0 個）の機械照合に使う。
# 呼び出し元は Makefile の `idle-memory` ターゲット。後続の実測レポート（TASK-45.2）・
# 回帰テスト（TASK-47。`idle_memory_supervised.sh` が `--expect-zero` 付きで呼ぶ）・supervisor の PSS 計測（TASK-158。`supervisor_pss.sh` が識別規則を踏襲）が参照し、
# 出力フィールド名と終了コードはそれらとの契約として固定する。
#
# 使い方:
#   idle_memory.sh [--format text|json] [--output <file>] [--expect-zero] [--expected-dir <dir>]... [--help]
#
# 計測対象: /proc/<pid>/exe のリンク先 basename が ^fandhe-container(-[a-z0-9-]+)?$ に一致する
#   プロセス（CLI・supervisor・plugin）。exe を読めないプロセスはカーネルスレッド
#   〔pid 2 / PPid=2〕とゾンビ〔State が Z / X。メモリを解放済みで常駐しない〕以外すべて計測失敗とする
#   （他ユーザーのプロセスの exe は権限が要るため、操作者が権限付きシェルから実行する）。
#   識別できないものを成功扱いにしない（fail-closed）ため、次の場合は計測失敗（終了コード 3）にする:
#   - exe の basename は対象名でないが、argv[0] の basename または comm の先頭 15 文字が対象名に
#     一致する（別名で配置・起動された対象バイナリの疑い。exe の basename だけでは見逃すため）
#   - --expected-dir（複数指定可）を与えた場合に、対象名の exe がそのディレクトリ直下にない
#     （同名の無関係な実行ファイルの混入の疑い）
#   - exe の basename が対象名でないプロセスの cmdline または comm を開けない（別名起動の疑いを
#     確認できないため。pid 消滅なら走査をやり直す）
#   - ゾンビの comm が対象名に一致する、または comm を開けない（exe を読めず識別できないため）
#   残余リスク: exe も argv[0] も comm も対象名でない名前へ改名・偽装されたバイナリは検出できない
#   （ハッシュ照合は TASK-45.2 以降の検討。操作者が配置物を管理する前提）。
#   cmdline 全文・環境変数は資格情報を含みうるため出力しない（argv[0] の basename 照合にのみ使い、
#   出すのは basename・pid・数値のみ）。
#
# 終了コード:
#   0 = 計測成功（--expect-zero 指定時は process_count=0 も満たした）
#   1 = --expect-zero 指定で process_count が 0 でない（結果は標準出力にも --output にも公開しない）
#   2 = 引数・入力エラー（--proc-root は FANDHE_IDLE_MEMORY_SELFTEST=1 なしでは拒否）、非 Linux（unsupported-os。0 を返して合格に見せない。REPAIR-3）、
#       または出力先エラー（--output が既存ディレクトリ・一時ファイルを作れない・書けない／置換できない、標準出力へ書けない）
#   3 = 計測失敗（対象名を名乗るが exe が一致しない／--expected-dir 外の対象名 exe、exe（カーネルスレッド以外）・メモリ値が読めない／数値でない、
#       対象外 exe の cmdline・comm を開けない、comm が対象名または読めないゾンビ、pid 消滅が続き走査が収束しない。
#       0 として足さず fail-closed。pid 消滅時は走査全体をやり直し、上限超過で 3）
#   上記以外の値（set -e による暗黙終了で 1 と衝突する等）を返さないよう、失敗しうる操作は明示的に分岐する。
#
# 前提:
#   - Linux 限定（smaps_rollup はカーネル 4.14 以降）。macOS / Windows の計測は CORE-8・TASK-49 の担当で、
#     ci.md の「3 OS 必須」はビルド・テストのゲート対象のため本計測ツールは対象外。
#   - 「コンテナが 0 個」の前提は CLI 未実装のため本スクリプトでは確認しない（操作者が保証する）。
#   - 他ユーザーのプロセスの smaps_rollup は権限が要る。スクリプト内で sudo は呼ばない
#     （root 権限コマンドは操作者が明示的に権限付きシェルから実行する）。読めない値を 0 として
#     足すと過小計上になる（PoC-17 で実際に起きた不具合）ため、読めなければ終了コード 3 で止める。
#
# 既知の制約:
#   - /proc の読み取り自体にはタイムアウトを設けていない（REPAIR-5）。ハングしたプロセスの
#     smaps_rollup 等は mmap_lock 待ちで読み取りがブロックし得るため、Makefile の `idle-memory`
#     ターゲットは `timeout` で包む（超過時は計測失敗として扱う）。uninterruptible sleep（D 状態）
#     で止まった読み取りは SIGKILL でも即座には解除できない。
#   - 任意のユーザーが argv[0]・comm を対象名に偽装したプロセスを起動すると、識別できないものを
#     成功扱いにしない方針（fail-closed）により計測は終了コード 3 になる（計測の妨害は可能だが
#     偽の成功にはならない）。エラーに出る pid を操作者が調べて取り除く前提とする。
#   - stderr に出す外部由来の文字列（exe のリンク先・引数・パス等）は、印字可能な ASCII 以外を
#     `?` に置換してから出す（端末へのエスケープシーケンス注入の防止）。

set -euo pipefail

# 走査する pid 数の上限（無制限走査による DoS 防止）。
readonly MAX_PIDS=65536
# pid 消滅で走査をやり直す最大回数。
readonly MAX_SCAN_ATTEMPTS=10

# 構造化エラーを stderr へ出す。メッセージは外部由来の文字列を含み得るため、印字可能な ASCII
# （0x20-0x7e）以外を `?` に置換して無害化する（LC_ALL=C で 1 バイト単位に判定する）。
# stderr が閉じている・書けない場合も終了コードを変えない（set -e で 1〔--expect-zero 違反〕に
# ならないよう `|| true`。呼び出し側が契約どおりの値で exit する）。
err() {
  local LC_ALL=C msg
  msg="error: $1: $2"
  msg="${msg//[^[:print:]]/?}"
  printf '%s\n' "$msg" >&2 || true
}

usage() {
  sed -n '2,/^set -euo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'
}

format="text"
output=""
expect_zero=0
proc_root=""
proc_root_given=0
expected_dirs=()

while [ $# -gt 0 ]; do
  case "$1" in
    --format)
      [ $# -ge 2 ] || { err "invalid-argument" "--format requires a value"; exit 2; }
      format="$2"
      shift 2
      ;;
    --output)
      [ $# -ge 2 ] || { err "invalid-argument" "--output requires a value"; exit 2; }
      output="$2"
      shift 2
      ;;
    --proc-root)
      [ $# -ge 2 ] || { err "invalid-argument" "--proc-root requires a value"; exit 2; }
      proc_root="$2"
      proc_root_given=1
      shift 2
      ;;
    --expected-dir)
      [ $# -ge 2 ] || { err "invalid-argument" "--expected-dir requires a value"; exit 2; }
      expected_dirs+=("${2%/}")
      shift 2
      ;;
    --expect-zero)
      expect_zero=1
      shift
      ;;
    --help | -h)
      if ! usage 2>/dev/null; then
        err "output-failed" "cannot write usage to stdout"
        exit 2
      fi
      exit 0
      ;;
    *)
      err "invalid-argument" "unknown argument: $1"
      exit 2
      ;;
  esac
done

case "$format" in
  text | json) ;;
  *) err "invalid-argument" "--format must be text or json"; exit 2 ;;
esac

# --proc-root（疑似 /proc）は selftest 専用。通常利用で非 Linux 判定を回避できないよう、
# FANDHE_IDLE_MEMORY_SELFTEST=1 のときだけ受け付ける。
if [ "$proc_root_given" -eq 1 ]; then
  if [ "${FANDHE_IDLE_MEMORY_SELFTEST:-}" != "1" ]; then
    err "invalid-argument" "--proc-root is for selftest only (set FANDHE_IDLE_MEMORY_SELFTEST=1)"
    exit 2
  fi
  case "$proc_root" in
    -*) err "invalid-argument" "proc root must not start with '-'"; exit 2 ;;
  esac
fi

# FANDHE_IDLE_MEMORY_UNAME_S は selftest 専用の OS 名差し替え（非 Linux 判定の検証用）。
# uname の失敗を set -e 任せにすると終了コード 1 と衝突するため、明示的に 2 とする。
if [ -n "${FANDHE_IDLE_MEMORY_UNAME_S:-}" ]; then
  os_name="$FANDHE_IDLE_MEMORY_UNAME_S"
elif ! os_name="$(uname -s)"; then
  err "unsupported-os" "cannot determine OS name"
  exit 2
fi
if [ "$proc_root_given" -eq 0 ]; then
  if [ "$os_name" != "Linux" ]; then
    err "unsupported-os" "only Linux is supported (got ${os_name})"
    exit 2
  fi
  proc_root="/proc"
fi

if [ ! -d "$proc_root" ]; then
  err "invalid-argument" "proc root is not a directory: ${proc_root}"
  exit 2
fi

if [ -n "$output" ]; then
  # 既存ディレクトリを渡すと mv がその中へ移動して成功扱いになるため、事前に拒否する
  # （検査と置換の間にディレクトリが作られる TOCTOU は mv -T で防ぐ）。
  if [ -d "$output" ]; then
    err "invalid-argument" "output path is a directory: ${output}"
    exit 2
  fi
  # dirname の失敗を set -e 任せにしないよう、パラメータ展開で親ディレクトリを求める。
  output_dir="${output%/*}"
  [ "$output_dir" != "$output" ] || output_dir="."
  [ -n "$output_dir" ] || output_dir="/"
  if [ ! -d "$output_dir" ]; then
    err "invalid-argument" "output directory does not exist: ${output_dir}"
    exit 2
  fi
fi

name_re='^fandhe-container(-[a-z0-9-]+)?$'
# pid・kB 値として受け付ける 10 進数。先頭 0 付き（09・010）は bash 算術で 8 進と解釈され
# エラー（終了コード 1）や誤読になるため拒否し、桁数は 13 桁（< 10^13 kB = 約 9 PB）までとする
# （MAX_PIDS 件の合計でも 64 bit 符号付き整数をあふれない: 65536 * 10^13 < 2^63）。
num_re='^(0|[1-9][0-9]{0,12})$'

# 1 回の走査で集計する値。走査中に pid が消えたら不完全な結果を捨てて走査をやり直す。
process_count=0
pss_total=0
rss_total=0
# 走査のやり直しを引き起こした pid 消滅の累計（最終的に採用した走査では 0 件）。
vanished=0
scanned=0
# 各要素は "pid name pss rss"。
records=()

# <file> から "<key>:" 行の最初の値（kB 値・PPid・State の 1 文字等）を取り出す。見つからなければ空。
read_kb() {
  awk -v key="$2:" '$1 == key { print $2; exit }' "$1"
}

# comm は 15 文字で切れる（fandhe-container-supervisor → fandhe-containe）ため、切り詰め後の形も対象名とみなす。
comm_claims_name() {
  [[ "$1" =~ $name_re ]] || [ "$1" = "fandhe-containe" ]
}

# <dir> の comm を呼び出し側の変数 comm へ読む（bash の動的スコープで scan_once の local に代入する）。
# 戻り値: 0 = 読めた（空も可）/ 10 = 開けず pid も消えた。開けないが pid が残っていれば計測失敗（3）で終了する。
# 開けない場合（read は実行されない）と空・EOF（read が 1 を返す）を `|| opened=0` で区別する
# （`if ! { ...; } <file` は bash でリダイレクト失敗時に否定が効かず真にならないため使わない）。
load_comm() {
  local opened=1
  comm=""
  { IFS= read -r comm || true; } 2>/dev/null <"$1/comm" || opened=0
  if [ "$opened" -eq 0 ]; then
    [ -d "$1" ] || return 10
    err "measurement-failed" "cannot read comm of pid $2 ($3); cannot rule out a renamed target"
    exit 3
  fi
  return 0
}

# 1 回走査する。戻り値: 0 = 完了 / 10 = 走査中に pid が消えた（呼び出し側でやり直す）。
# 計測不能は即 exit 3、入力異常は exit 2。
#
# 識別は /proc/<pid>/exe のリンク先 basename で行う（argv[0] は prctl・exec -a で自己申告でき、
# 偽装で対象に見せかけ／対象から外せるため）。exe が読めない場合（権限不足）はカーネルスレッド
# （pid 2 または PPid=2）とゾンビ（comm が対象名でないもの）だけを対象外とし、それ以外は argv[0] に
# 関わらず計測失敗とする。
scan_once() {
  process_count=0
  pss_total=0
  rss_total=0
  scanned=0
  records=()
  local dir pid exe_target name ppid state pss rss claimed argv0 comm opened exe_dir in_expected d
  for dir in "$proc_root"/[0-9]*; do
    pid="${dir##*/}"
    [[ "$pid" =~ $num_re ]] || continue
    scanned=$((scanned + 1))
    if [ "$scanned" -gt "$MAX_PIDS" ]; then
      err "invalid-input" "too many pids under ${proc_root} (limit ${MAX_PIDS})"
      exit 2
    fi

    # readlink の `--` は GNU 拡張（BSD / macOS では失敗する）のため使わない（proc_root は '-' 始まりを拒否済み）。
    if exe_target="$(readlink "$dir/exe" 2>/dev/null)" && [ -n "$exe_target" ]; then
      # 削除済みバイナリのリンク先は末尾に " (deleted)" が付く。
      exe_target="${exe_target% (deleted)}"
      name="${exe_target##*/}"
    else
      # exe を読めない。pid 消滅なら走査をやり直す（対象かどうか確定できないため）。
      [ -d "$dir" ] || return 10
      # argv[0] は自己申告で偽装できるため、exe 不明のプロセスを名前で対象外にしない。
      # 対象外にできるのはカーネルスレッド（pid 2 または PPid=2。status は全ユーザーが読める）と、
      # comm が対象名でないゾンビのみで、それ以外は確認不能として計測失敗にする（--expect-zero の偽成功を防ぐ）。
      if ! ppid="$(read_kb "$dir/status" PPid 2>/dev/null)" ||
        ! state="$(read_kb "$dir/status" State 2>/dev/null)"; then
        [ -d "$dir" ] || return 10
        err "measurement-failed" "cannot read exe or status of pid ${pid} (insufficient permission?)"
        exit 3
      fi
      if [ "$pid" = "2" ] || [ "$ppid" = "2" ]; then
        continue
      fi
      # ゾンビ（Z）・終了処理中（X）は exe リンクが切れるが、メモリを解放済みで常駐しない（PSS / RSS に
      # 寄与しない）。親に回収されるまで残り走査のやり直しでは解消しないため、対象外とする。
      # ただし comm が対象名なら対象プロセスの残骸か識別できないため計測失敗にする。
      if [ "$state" = "Z" ] || [ "$state" = "X" ]; then
        load_comm "$dir" "$pid" "zombie" || return 10
        if comm_claims_name "$comm"; then
          err "measurement-failed" "zombie pid ${pid} claims a fandhe-container name via comm; cannot identify"
          exit 3
        fi
        continue
      fi
      [ -d "$dir" ] || return 10
      err "measurement-failed" "cannot verify executable of pid ${pid} (insufficient permission?)"
      exit 3
    fi
    if ! [[ "$name" =~ $name_re ]]; then
      # exe は対象名でない。対象バイナリを別名で配置・起動した疑い（argv[0]・comm が対象名）は
      # 識別不能として計測失敗にする（--expect-zero の偽成功を防ぐ）。
      # argv0 / comm は pid ごとに初期化する（未初期化のまま set -u で参照すると終了コード 1 で落ち、
      # 前の pid の値を引き継ぐと別名起動を見逃す）。開けない場合（read は実行されない）と
      # 空・EOF（read が 1 を返す）を区別し、開けなければ pid 消滅以外は計測失敗にする。
      # scan_once は `||` の文脈で呼ばれ set -e が効かないため、失敗はすべて明示的に扱う。
      # `if ! { ...; } <file` は bash でリダイレクト失敗時に否定が効かず真にならないため、
      # 開けたかどうかは `|| opened=0` で受ける（comm は load_comm が同じ方法で読む）。
      claimed=""
      argv0=""
      opened=1
      { IFS= read -r -d '' argv0 || true; } 2>/dev/null <"$dir/cmdline" || opened=0
      if [ "$opened" -eq 0 ]; then
        [ -d "$dir" ] || return 10
        err "measurement-failed" "cannot read cmdline of pid ${pid} (exe basename '${name}'); cannot rule out a renamed target"
        exit 3
      fi
      argv0="${argv0##*/}"
      load_comm "$dir" "$pid" "exe basename '${name}'" || return 10
      if [[ "$argv0" =~ $name_re ]]; then
        claimed="argv[0]"
      elif comm_claims_name "$comm"; then
        claimed="comm"
      fi
      if [ -n "$claimed" ]; then
        err "measurement-failed" "pid ${pid} claims a fandhe-container name via ${claimed} but exe basename is '${name}'; cannot identify"
        exit 3
      fi
      continue
    fi
    if [ "${#expected_dirs[@]}" -gt 0 ]; then
      exe_dir="${exe_target%/*}"
      in_expected=0
      for d in "${expected_dirs[@]}"; do
        if [ "$exe_dir" = "$d" ]; then in_expected=1; break; fi
      done
      if [ "$in_expected" -eq 0 ]; then
        err "measurement-failed" "pid ${pid} exe is outside --expected-dir: ${exe_target}"
        exit 3
      fi
    fi

    # 対象確定後の消滅は過少計上になるため、値を確定できない場合は走査をやり直す。
    if ! pss="$(read_kb "$dir/smaps_rollup" Pss 2>/dev/null)" ||
      ! rss="$(read_kb "$dir/status" VmRSS 2>/dev/null)"; then
      [ -d "$dir" ] || return 10
      err "measurement-failed" "cannot read memory counters of pid ${pid} (insufficient permission?)"
      exit 3
    fi
    if ! [[ "$pss" =~ $num_re ]] || ! [[ "$rss" =~ $num_re ]]; then
      [ -d "$dir" ] || return 10
      err "measurement-failed" "non-numeric or missing Pss/VmRSS for pid ${pid}"
      exit 3
    fi

    process_count=$((process_count + 1))
    pss_total=$((pss_total + pss))
    rss_total=$((rss_total + rss))
    records+=("${pid} ${name} ${pss} ${rss}")
  done
  return 0
}

shopt -s nullglob
attempt=0
while :; do
  rc=0
  scan_once || rc=$?
  [ "$rc" -eq 0 ] && break
  vanished=$((vanished + 1))
  attempt=$((attempt + 1))
  if [ "$attempt" -ge "$MAX_SCAN_ATTEMPTS" ]; then
    err "measurement-failed" "pids kept vanishing during scan (${attempt} attempts)"
    exit 3
  fi
done

# 出力はバッファ（out_buf）に組み立て、書き込みは末尾で 1 回だけ行い成否を明示的に確認する
# （関数内の echo 失敗を set -e 任せにすると終了コード 1〔--expect-zero 違反〕と衝突するため）。
out_buf=""

append() {
  out_buf+="$1"$'\n'
}

render_text() {
  append "process_count=${process_count}"
  append "pss_kb=${pss_total}"
  append "rss_kb=${rss_total}"
  append "vanished_count=${vanished}"
  local rec pid name pss rss
  for rec in "${records[@]+"${records[@]}"}"; do
    read -r pid name pss rss <<<"$rec"
    append "process pid=${pid} name=${name} pss_kb=${pss} rss_kb=${rss}"
  done
}

# name は正規表現で照合済み（[a-z0-9-] のみ）のため JSON エスケープ不要。
# 付帯情報（時刻・カーネル・アーキテクチャ）を取得できなければ計測失敗（3）にする。
render_json() {
  local ts kernel arch rec pid name pss rss line first=1
  if ! ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)" || ! kernel="$(uname -r)" || ! arch="$(uname -m)"; then
    err "measurement-failed" "cannot determine timestamp, kernel or arch"
    exit 3
  fi
  # JSON 文字列へ埋め込むため、安全な文字以外を除く（bash 5 の既定 globasciiranges で範囲は ASCII）。
  kernel="${kernel//[^A-Za-z0-9._+-]/}"
  arch="${arch//[^A-Za-z0-9._-]/}"
  append "{"
  append "  \"schema_version\": 1,"
  append "  \"behavior\": \"CORE-7\","
  append "  \"task\": \"TASK-45\","
  append "  \"timestamp\": \"${ts}\","
  append "  \"kernel\": \"${kernel}\","
  append "  \"arch\": \"${arch}\","
  append "  \"process_count\": ${process_count},"
  append "  \"pss_kb\": ${pss_total},"
  append "  \"rss_kb\": ${rss_total},"
  append "  \"vanished_count\": ${vanished},"
  append "  \"processes\": ["
  for rec in "${records[@]+"${records[@]}"}"; do
    read -r pid name pss rss <<<"$rec"
    printf -v line '    {"pid": %s, "name": "%s", "pss_kb": %s, "rss_kb": %s}' "$pid" "$name" "$pss" "$rss"
    if [ "$first" -eq 0 ]; then out_buf="${out_buf%$'\n'},"$'\n'; fi
    first=0
    append "$line"
  done
  append "  ]"
  append "}"
}

if [ "$format" = "json" ]; then render_json; else render_text; fi

# 結果は --expect-zero の成否を確定してから公開する（失敗した計測結果を正規の成果物として残さない）。
if [ -n "$output" ]; then
  if ! tmp="$(mktemp "${output}.XXXXXX" 2>/dev/null)"; then
    err "output-failed" "cannot create temporary file next to ${output}"
    exit 2
  fi
  trap 'rm -f "$tmp"' EXIT
  if ! printf '%s' "$out_buf" 2>/dev/null >"$tmp"; then
    err "output-failed" "cannot write temporary file ${tmp}"
    exit 2
  fi
  if [ "$expect_zero" -eq 1 ] && [ "$process_count" -ne 0 ]; then
    err "expect-zero-failed" "process_count=${process_count} (expected 0); output not published"
    exit 1
  fi
  # -T: 出力先をディレクトリとして扱わない（事前検査後にディレクトリが作られても、その中へ
  # 移動して成功扱いにしない。GNU coreutils の拡張で、本スクリプトは Linux 限定）。
  if ! mv -fT "$tmp" "$output" 2>/dev/null; then
    err "output-failed" "cannot publish output to ${output}"
    exit 2
  fi
  trap - EXIT
else
  # 標準出力も --output と同じく、--expect-zero の成否を確定してから書く（違反結果を後続が正規の
  # 計測値として収集しないよう、違反時は何も出さない）。
  if [ "$expect_zero" -eq 1 ] && [ "$process_count" -ne 0 ]; then
    err "expect-zero-failed" "process_count=${process_count} (expected 0); output not published"
    exit 1
  fi
  if ! printf '%s' "$out_buf" 2>/dev/null; then
    err "output-failed" "cannot write to stdout"
    exit 2
  fi
fi
exit 0
