#!/usr/bin/env bash
# scripts/cli-parity-check.sh の自己テスト（TASK-125.1・CLI-1・REPAIR-12）。
#
# 役割: 製品バイナリ・root を使わず、契約どおりの出力を返すスタブ CLI（一時ディレクトリに生成する bash
# スクリプト）だけで capture / compare の挙動を具体値で照合する。実機での 3 OS 比較そのものは
# #661（人間担当）の範囲で、本テストはその道具が壊れていないことだけを確かめる。
#
# 呼び出し元: Makefile の `cli-parity-selftest`（CI の platform-ci ジョブもこのターゲットを使う。main への push では
# ubuntu・macos・windows の 3 OS、PR では ubuntu。Windows は Git Bash）。make ci には含めない。
# 失敗は `FAIL:` 行を出し、最後に非 0 で終了する。bash 3.2 以上で動く。
#
# 構成: capture は 30 本近くを同時に起動してから結果を照合する。Git Bash はプロセス生成が遅く、直列では
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
#   nostart  = ok と同じだが、起動用 bundle の start も失敗する（supervisor 未配置など start の前提が無い環境。#2891）
#   stuck    = ok と同じだが、stop しても running のまま（B23 の終了待ちが期限切れになる。#2891）
#   delfail  = ok と同じだが、c2 の delete が失敗し c2 が残る（後始末の inspect は成功する。#2891）
#   delgone  = c2 の delete は失敗するが c2 は消える（後始末の inspect は NOT_FOUND。#2891）
#   sigdel   = c2 の delete が止まる（1 回目 = 連鎖中、2 回目 = 後始末中。印は STUB_SIGDEL_DIR の m1 / m2。#2891 の再入）
#   deldeny  = c2 の delete が失敗し、以後の c2 の inspect が PERMISSION_DENIED で失敗する（#2891）
# 環境変数で出力を差し替える（fixture 表。カウンタはそのディレクトリの count に置く）:
#   STUB_ERR_DIR = 使い方エラーの n 回目に err.<n> があれば、その内容をそのまま stderr へ流す。
#                  A 層 18 ケースは全て使い方エラーで順に呼ばれるため、n 回目 = ケース A<n>。
#   STUB_OUT_DIR = 成功するコマンドの n 回目に out.<n> があれば、その内容をそのまま stdout へ流す。
#                  成功の順は B01 list・B02 create・B03 list・B06 list・B09 delete・B10 list。
#   STUB_INSPECT_DIR = 存在する ID の inspect（B17。成功は 1 回だけ）の stdout を、そのディレクトリの
#                  out ファイルの内容で差し替える（無ければ製品と同じ形の created の 1 行 JSON）。
#                  STUB_OUT_DIR とはカウンタを共有しない（既存の fixture の番号をずらさないため）。
#                  差し替えるのは c1 の inspect だけ（起動用の c2 の inspect〔B19・B21・B23〕には波及させない）。
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
    bundle=""; id=""; n=0; ro=0
    while [ $# -gt 0 ]; do
      case "$1" in
        # 製品 CLI の --read-only は値を取らず 1 回まで（値つきは余剰の位置引数になる。#2828）。
        --read-only) [ "$ro" = 0 ] || bad; ro=1; shift ;;
        --bundle) [ $# -ge 2 ] || bad; [ -z "$bundle" ] || bad; bundle="$2"; shift 2 ;;
        # 製品 CLI の --cap-drop は core の語彙で検証する。スタブは代表の名前だけを受ける（#2775）。
        --cap-drop) [ $# -ge 2 ] || bad
          [[ "$2" =~ ^(ALL|(CAP_)?(CHOWN|KILL|NET_RAW))$ ]] || bad; shift 2 ;;
        -*) bad ;;
        *) id="$1"; n=$((n + 1)); shift ;;
      esac
    done
    [ -n "$bundle" ] && [ "$n" -eq 1 ] && valid_id "$id" || bad
    # 起動用 bundle（ディレクトリ名 sbundle）と --read-only の有無を、コンテナの記録（<id>.c）へ残す。
    sb=plain; [ "${bundle##*/}" = "sbundle" ] && sb=sbundle ;;
  logs)
    # 製品 CLI の logs の引数規則（--tail は 0..1000000 の整数・--stream は stdout|stderr・--follow と --escape（短縮形は無い） は 1 回まで）。
    follow=0; escape=0; tail_seen=0; stream_seen=0; n=0; id=""
    while [ $# -gt 0 ]; do
      case "$1" in
        --tail) [ $# -ge 2 ] && [ "$tail_seen" = 0 ] || bad; tail_seen=1
          [[ "$2" =~ ^[0-9]{1,7}$ ]] && [ "$((10#$2))" -le 1000000 ] || bad; shift 2 ;;
        --stream) [ $# -ge 2 ] && [ "$stream_seen" = 0 ] || bad; stream_seen=1
          case "$2" in stdout | stderr) ;; *) bad ;; esac; shift 2 ;;
        --follow) [ "$follow" = 0 ] || bad; follow=1; shift ;;
        --escape) [ "$escape" = 0 ] || bad; escape=1; shift ;;
        -*) bad ;;
        *) id="$1"; n=$((n + 1)); shift ;;
      esac
    done
    [ "$n" -eq 1 ] && valid_id "$id" || bad ;;
  stop)
    # 製品 CLI の --signal は Docker 表記（番号は 1..64 で 32・33 を除く）。スタブは代表の名前だけを受ける（#2775）。
    sig_seen=0; n=0; id=""
    while [ $# -gt 0 ]; do
      case "$1" in
        --signal) [ $# -ge 2 ] && [ "$sig_seen" = 0 ] || bad; sig_seen=1
          if [[ "$2" =~ ^[0-9]{1,3}$ ]]; then
            v=$((10#$2)); [ "$v" -ge 1 ] && [ "$v" -le 64 ] && [ "$v" -ne 32 ] && [ "$v" -ne 33 ] || bad
          else
            [[ "$2" =~ ^(SIG)?(TERM|KILL|INT|HUP)$ ]] || bad
          fi
          shift 2 ;;
        -*) bad ;;
        *) id="$1"; n=$((n + 1)); shift ;;
      esac
    done
    [ "$n" -eq 1 ] && valid_id "$id" || bad ;;
  start | inspect)
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
    printf '%s %s\n' "$sb" "$ro" >"$root/$id.c"
    out_override || { [ "$mode" = "noisy" ] && printf '/home/secret-user/out\n'; }
    ;;
  start)
    [ -e "$root/$id.c" ] || fail_op 3 NOT_FOUND start
    # 通常の bundle（rootfs が空）は supervisor 未配置と同じ FAILED_PRECONDITION。起動用 bundle だけ成功する。
    read -r sb ro <"$root/$id.c"
    { [ "$sb" = "sbundle" ] && [ "$mode" != "nostart" ]; } || fail_op 5 FAILED_PRECONDITION start
    : >"$root/$id.started" ;;
  logs) [ -e "$root/$id.c" ] || fail_with 3 NOT_FOUND; fail_with 8 UNIMPLEMENTED ;;
  inspect)
    [ -e "$root/$id.c" ] || fail_with 3 NOT_FOUND
    [ "$mode" = "deldeny" ] && [ -e "$root/$id.denied" ] && fail_with 6 PERMISSION_DENIED
    caps13='"CAP_CHOWN","CAP_DAC_OVERRIDE","CAP_FSETID","CAP_FOWNER","CAP_MKNOD","CAP_SETGID","CAP_SETUID","CAP_SETFCAP","CAP_SETPCAP","CAP_NET_BIND_SERVICE","CAP_SYS_CHROOT","CAP_KILL","CAP_AUDIT_WRITE"'
    read -r sb ro <"$root/$id.c"
    rojson=false; [ "$ro" = "1" ] && rojson=true
    if [ -e "$root/$id.started" ] || [ -e "$root/$id.stopped" ]; then
      # start 済み / 停止後の inspect。bundle・cgroup・hostId・reason にはパス風の文字列を入れ、漏えいしないことを照合する。
      if [ -e "$root/$id.started" ]; then st='"status":"running","pid":4242,"exitCode":null'; ex=not_recorded
      else st='"status":"stopped","pid":null,"exitCode":-9'; ex=recorded; fi
      printf '{"id":"%s",%s,"bundle":"/home/secret-user/sbundle","revision":3,"cgroupScope":"/user/secret-slice","cgroupInstance":2,"supervisorPid":4141,"health":null,"restartCount":0,"auditCoverage":{"policy":"evaluated","seccompKill":{"mode":"kill","reason":null},"landlock":{"mode":"enforce","reason":"kernel 6.12 secret"},"record":null},"idMapping":{"model":"single","uid":[{"containerId":0,"hostId":100000,"size":1}],"gid":[{"containerId":0,"hostId":100000,"size":1}]},"explicitStop":"%s","capabilities":{"bounding":[%s]},"rootReadonly":%s}\n' "$id" "$st" "$ex" "$caps13" "$rojson"
    elif [ "$id" = "c1" ] && [ -n "${STUB_INSPECT_DIR:-}" ] && [ -f "$STUB_INSPECT_DIR/out" ]; then
      cat "$STUB_INSPECT_DIR/out"
    else
      # 製品の InspectReport::to_json と同じキー順。bundle にはパス風の文字列を入れ、漏えいしないことを照合する。
      printf '{"id":"%s","status":"created","pid":null,"exitCode":null,"bundle":"/home/secret-user/bundle","revision":1,"cgroupScope":null,"cgroupInstance":null,"supervisorPid":null,"health":null,"restartCount":0,"auditCoverage":null,"idMapping":null,"explicitStop":"not_recorded","capabilities":null,"rootReadonly":null}\n' "$id"
    fi
    ;;
  stop)
    [ -e "$root/$id.c" ] || fail_op 3 NOT_FOUND kill
    [ -e "$root/$id.started" ] || fail_op 5 FAILED_PRECONDITION kill
    # stuck は stop を受けても running のまま。
    [ "$mode" = "stuck" ] || mv "$root/$id.started" "$root/$id.stopped" ;;
  delete)
    [ -e "$root/$id.c" ] || fail_op 3 NOT_FOUND delete
    if [ "$id" = "c2" ]; then
      case "$mode" in
        sigdel)
          echo "$PPID" >"$STUB_SIGDEL_DIR/ppid"
          if [ -e "$STUB_SIGDEL_DIR/m1" ]; then : >"$STUB_SIGDEL_DIR/m2"; else : >"$STUB_SIGDEL_DIR/m1"; fi
          sleep 30 ;;
        delfail) fail_op 6 INTERNAL delete ;;
        delgone) rm -f "$root/$id.c" "$root/$id.started" "$root/$id.stopped"; fail_op 6 INTERNAL delete ;;
        deldeny) : >"$root/$id.denied"; fail_op 6 INTERNAL delete ;;
      esac
    fi
    rm -f "$root/$id.c" "$root/$id.started" "$root/$id.stopped"
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


# inspect fixture（B17 の stdout）。1 ケース 1 capture で、B17 の行を具体値で照合する。
inspdir="$work/insp"
mkdir -p "$inspdir"
mkinsp() { # <名前> <printf の書式（stdout の全バイト）>
  mkdir -p "$inspdir/$1"
  # shellcheck disable=SC2059 # 書式は本ファイル内の固定 fixture
  printf "$2" >"$inspdir/$1/out"
}
cap_names='"CAP_CHOWN","CAP_KILL","CAP_NET_RAW"'
ext1='{"containerId":0,"hostId":100000,"size":65536}'
ext2='{"containerId":65536,"hostId":300000,"size":10}'
head_ok='{"id":"web-1","status":"running","pid":42,"exitCode":-9,"bundle":"/home/secret-user/b\\"q\\" \303\251","revision":5,'
mkinsp full "${head_ok//%/%%}"'"cgroupScope":"/user/secret-slice","cgroupInstance":2,"supervisorPid":7,"health":"healthy","restartCount":2,"auditCoverage":{"policy":"evaluated","seccompKill":{"mode":"kill","reason":null},"landlock":{"mode":"enforce","reason":"kernel 6.12 secret"},"record":"failed"},"idMapping":{"model":"subordinate","uid":['"$ext1,$ext2"'],"gid":['"$ext1"']},"explicitStop":"recorded","capabilities":{"bounding":['"$cap_names"']},"rootReadonly":true}\n'
tail_ok='"cgroupScope":null,"cgroupInstance":null,"supervisorPid":null,"health":null,"restartCount":0,"auditCoverage":null,"idMapping":null,"explicitStop":"not_recorded","capabilities":null,"rootReadonly":null}'
base_head='{"id":"c1","status":"created","pid":null,"exitCode":null,"bundle":"/b","revision":1,'
mkinsp order '{"status":"created","id":"c1","pid":null,"exitCode":null,"bundle":"/b","revision":1,'"$tail_ok"'\n'
mkinsp extra "$base_head"'"cgroupScope":null,"cgroupInstance":null,"supervisorPid":null,"health":null,"restartCount":0,"auditCoverage":null,"idMapping":null,"explicitStop":"not_recorded","capabilities":null,"extra":1}\n'
mkinsp rofalse "$base_head"'"cgroupScope":null,"cgroupInstance":null,"supervisorPid":null,"health":null,"restartCount":0,"auditCoverage":null,"idMapping":null,"explicitStop":"not_recorded","capabilities":null,"rootReadonly":false}\n'
mkinsp noro "$base_head"'"cgroupScope":null,"cgroupInstance":null,"supervisorPid":null,"health":null,"restartCount":0,"auditCoverage":null,"idMapping":null,"explicitStop":"not_recorded","capabilities":null}\n'
mkinsp badro "$base_head"'"cgroupScope":null,"cgroupInstance":null,"supervisorPid":null,"health":null,"restartCount":0,"auditCoverage":null,"idMapping":null,"explicitStop":"not_recorded","capabilities":null,"rootReadonly":"yes"}\n'
mkinsp extrarw "$base_head"'"cgroupScope":null,"cgroupInstance":null,"supervisorPid":null,"health":null,"restartCount":0,"auditCoverage":null,"idMapping":null,"explicitStop":"not_recorded","capabilities":null,"rootReadonly":true,"extra":1}\n'
mkinsp missing '{"id":"c1","status":"created","pid":null,"exitCode":null,"bundle":"/b","revision":1,"cgroupScope":null,"cgroupInstance":null,"supervisorPid":null,"health":null,"restartCount":0,"auditCoverage":null,"idMapping":null,"capabilities":null,"rootReadonly":null}\n'
mkinsp nolf "$base_head$tail_ok"
mkinsp crlf "$base_head$tail_ok"'\r\n'
mkinsp twolines "$base_head$tail_ok"'\n'"$base_head$tail_ok"'\n'
mkinsp badcap "$base_head"'"cgroupScope":null,"cgroupInstance":null,"supervisorPid":null,"health":null,"restartCount":0,"auditCoverage":null,"idMapping":null,"explicitStop":"not_recorded","capabilities":{"bounding":["cap_chown"]},"rootReadonly":null}\n'
mkinsp badstr '{"id":"c1","status":"created","pid":null,"exitCode":null,"bundle":"a"b","revision":1,'"$tail_ok"'\n'
mkinsp lead0pid '{"id":"c1","status":"running","pid":042,"exitCode":null,"bundle":"/b","revision":1,'"$tail_ok"'\n'
mkinsp lead0ext "$base_head"'"cgroupScope":null,"cgroupInstance":null,"supervisorPid":null,"health":null,"restartCount":0,"auditCoverage":null,"idMapping":{"model":"subordinate","uid":[{"containerId":00,"hostId":100000,"size":1}],"gid":[]},"explicitStop":"not_recorded","capabilities":null,"rootReadonly":null}\n'
mkinsp lead0cg "$base_head"'"cgroupScope":null,"cgroupInstance":01,"supervisorPid":null,"health":null,"restartCount":0,"auditCoverage":null,"idMapping":null,"explicitStop":"not_recorded","capabilities":null,"rootReadonly":null}\n'
mkinsp besteffort "$base_head"'"cgroupScope":null,"cgroupInstance":null,"supervisorPid":null,"health":null,"restartCount":0,"auditCoverage":{"policy":"best-effort","seccompKill":{"mode":"kill","reason":null},"landlock":{"mode":"enforce","reason":null},"record":null},"idMapping":null,"explicitStop":"not_recorded","capabilities":null,"rootReadonly":null}\n'
mkinsp empty ''
mkdir -p "$inspdir/big"
{
  printf '{"id":"c1","status":"created","pid":null,"exitCode":null,"bundle":"'
  i=0
  while [ "$i" -lt 9000 ]; do
    printf 'aaaaaaaa'
    i=$((i + 1))
  done
  printf '",'
  printf '%s\n' "$tail_ok"
} >"$inspdir/big/out"

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
start_capture nostart nostart
start_capture stuck stuck --timeout 1
TMPDIR="$work/tmpdir" start_capture diff diff
# c2 の delete 失敗後の後始末（#2891・REPAIR-5）。TMPDIR を専用にして状態ルートの残存を数える。
for m in delfail delgone deldeny; do
  mkdir -p "$work/tmp-$m"
  TMPDIR="$work/tmp-$m" start_capture "$m" "$m"
done
start_capture noisy noisy
# 後始末（stop / delete）の最中に TERM を再度受けても状態ルートを消さない（#2891・REPAIR-5）。
mkdir -p "$work/tmp-sigdel" "$work/sigdel"
STUB_SIGDEL_DIR="$work/sigdel" TMPDIR="$work/tmp-sigdel" start_capture sigdel sigdel
# lddhang: ldd が止まっても capture が期限内に終わる（スタブの ldd を PATH の先頭に置く。Linux のみ。REPAIR-5）
if [ "$(uname -s 2>/dev/null)" = "Linux" ]; then
  mkdir -p "$work/lddbin"
  cat >"$work/lddbin/ldd" <<'LDD'
#!/usr/bin/env bash
printf '%s\n' "$$" >"$LDD_PIDFILE"
exec sleep 300
LDD
  chmod +x "$work/lddbin/ldd"
  LDD_PIDFILE="$work/ldd.pid" CLI_PARITY_LDD_LIMIT_SECS=1 PATH="$work/lddbin:$PATH" start_capture lddhang ok
fi
STUB_PIDFILE="$work/pids.txt" start_capture hang hang --timeout 1
STUB_ERR_DIR="$errdir" start_capture errtable ok
STUB_ERR_DIR="$errmax" STUB_OUT_DIR="$pidout" start_capture errmax ok
STUB_OUT_DIR="$outdir" start_capture outtable ok
insp_names="full rofalse noro badro extrarw order extra missing nolf crlf twolines badcap badstr big lead0pid lead0ext lead0cg besteffort empty"
for n in $insp_names; do
  STUB_INSPECT_DIR="$inspdir/$n" start_capture "insp_$n" ok
done
# sigdel: 連鎖中の delete（m1）で 1 回目の TERM、後始末中の delete（m2）で 2 回目の TERM を送る。
wait_for_file() { # <パス>。最大 60 秒
  local n=0
  while [ ! -e "$1" ] && [ "$n" -lt 600 ]; do sleep 0.1; n=$((n + 1)); done
  [ -e "$1" ]
}
if wait_for_file "$work/sigdel/m1"; then
  IFS= read -r sigdel_pid <"$work/sigdel/ppid"
  kill -TERM "$sigdel_pid" 2>/dev/null || true
  if wait_for_file "$work/sigdel/m2"; then
    kill -TERM "$sigdel_pid" 2>/dev/null || true
  else
    fail "sigdel: cleanup reached delete"
  fi
else
  fail "sigdel: chain reached delete"
fi
wait

if [ "$(uname -s 2>/dev/null)" = "Linux" ]; then
  expect_rc "ldd hang: capture finishes with rc 0" 0 "$(rc_of lddhang)"
  if grep -q 'start rootfs was not assembled' "$work/lddhang.err"; then pass "ldd hang: rootfs assembly reported as failed"; else fail "ldd hang: rootfs assembly reported as failed"; fi
  ldd_alive=0
  if [ -r "$work/ldd.pid" ]; then
    IFS= read -r lddp <"$work/ldd.pid"
    kill -0 "$lddp" 2>/dev/null && ldd_alive=1
  else
    ldd_alive=2
  fi
  expect_eq "ldd hang: stub ldd was reclaimed" 0 "$ldd_alive"
fi
all_caps="ok lcall nonlinux nostart diff noisy errtable errmax outtable"
for n in $insp_names; do all_caps="$all_caps insp_$n"; done
for name in $all_caps; do
  expect_rc "capture $name exits 0" 0 "$(rc_of "$name")"
done
for name in $all_caps; do
  # 失敗の調査用。capture の stderr は固定語彙の 1 行で、パスや環境の値を含まない。
  [ "$(rc_of "$name")" = "0" ] || [ ! -s "$work/$name.err" ] || sed "s/^/  $name stderr: /" "$work/$name.err"
done

# --- capture: 具体値 ---
count=0
while IFS= read -r l; do
  case "$l" in [ABD][0-9][0-9]"$tab"*) count=$((count + 1)) ;; esac
done <"$work/ok.txt"
expect_eq "capture records 59 cases" 59 "$count"
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
expect_eq "lcall stub invocations" 59 "$loc_n"
expect_eq "lcall stub got LC_ALL other than C" 0 "$loc_bad"
expect_line "A20 unknown stop signal" ok "A20${tab}A${tab}2${tab}INVALID_ARGUMENT${tab}-"
expect_line "A23 unknown cap-drop name" ok "A23${tab}A${tab}2${tab}INVALID_ARGUMENT${tab}-"
expect_line "A26 duplicate read-only" ok "A26${tab}A${tab}2${tab}INVALID_ARGUMENT${tab}-"
expect_line "A27 read-only with a value" ok "A27${tab}A${tab}2${tab}INVALID_ARGUMENT${tab}-"
expect_line "B16 inspect of a missing container" ok "B16${tab}B${tab}3${tab}NOT_FOUND${tab}-"
expect_line "B15 missing state root" ok "B15${tab}B${tab}3${tab}NOT_FOUND${tab}-"
expect_line "D01 tail without value" ok "D01${tab}D${tab}2${tab}INVALID_ARGUMENT${tab}-"
expect_line "D03 tail over the limit" ok "D03${tab}D${tab}2${tab}INVALID_ARGUMENT${tab}-"
expect_line "D05 duplicate follow" ok "D05${tab}D${tab}2${tab}INVALID_ARGUMENT${tab}-"
expect_line "D06 short form is rejected" ok "D06${tab}D${tab}2${tab}INVALID_ARGUMENT${tab}-"
expect_line "D24 follow on a missing container" ok "D24${tab}D${tab}3${tab}NOT_FOUND${tab}-"
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
cmp_has "layer A summary" 'layer A (syntax): match=27 mismatch=0 missing=0'
cmp_has "layer B summary" 'layer B (behavior): match=25 mismatch=0 missing=0'
cmp_has "layer D summary" 'layer D (logs options): match=7 mismatch=0 missing=0'
compare ok lcall
expect_rc "compare ok vs lcall is rc 0" 0 $?
cmp_has "lcall layer A summary" 'layer A (syntax): match=27 mismatch=0 missing=0'
cmp_has "lcall layer B summary" 'layer B (behavior): match=25 mismatch=0 missing=0'

compare ok diff
expect_rc "compare with changed exit code is rc 1" 1 $?
cmp_has_prefix "B03 reported as MISMATCH" 'B03 MISMATCH'
cmp_has "unchanged case stays MATCH" 'B01 MATCH'

compare ok nonlinux
expect_rc "non-linux stub differs in layer B (rc 1)" 1 $?
cmp_has "non-linux layer A all match" 'layer A (syntax): match=27 mismatch=0 missing=0'
cmp_has "non-linux layer B mismatches (B05 and B08 coincide at 5; B21 and B23 are not started)" 'layer B (behavior): match=2 mismatch=21 missing=0'

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
cmp_has "layer B counts the missing case" 'layer B (behavior): match=24 mismatch=0 missing=1'
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
# 終了コード欄は強制終了のシグナル（TERM = 143 / KILL = 137。Windows の Bash では 0 になることもある）
# で変わるため、タイムアウトの印（コード・stdout 欄の <timeout>）だけを照合する。
case "$(line_of hang A02)" in
  "A02${tab}A${tab}"[0-9]*"${tab}<timeout>${tab}<timeout>")
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

# --- inspect の 1 行 JSON（種別 i。B17）---
expect_line "B17 inspect of a created container" ok "B17${tab}B${tab}0${tab}-${tab}inspect:c1,created,pid=-,exit=-,rev=1,cg=-,sup=-,health=-,rst=0,audit=-,idmap=-,stop=not_recorded,caps=-,ro=-"
expect_line "B17 inspect with every object is normalized" insp_full "B17${tab}B${tab}0${tab}-${tab}inspect:web-1,running,pid=<pid>,exit=-9,rev=5,cg=<set>,sup=<pid>,health=healthy,rst=2,audit=evaluated/kill/enforce/failed,idmap=subordinate:2:1,stop=recorded,caps=3,ro=true"
# 行数は case で先に決める（$( ) の中の case は macOS の /bin/bash 3.2 が `)` を取り違えて構文エラーにするため）
for n in order extra noro badro extrarw missing nolf crlf twolines badcap badstr; do
  case $n in
    nolf) lines=0 ;;
    twolines) lines=2 ;;
    *) lines=1 ;;
  esac
  expect_line "B17 malformed inspect ($n) is unexpected" "insp_$n" "B17${tab}B${tab}0${tab}-${tab}<unexpected>:${lines}"
done
for n in lead0pid lead0ext lead0cg; do
  expect_line "B17 leading-zero number ($n) is unexpected" "insp_$n" "B17${tab}B${tab}0${tab}-${tab}<unexpected>:1"
done
expect_line "B17 rootReadonly false is accepted" insp_rofalse "B17${tab}B${tab}0${tab}-${tab}inspect:c1,created,pid=-,exit=-,rev=1,cg=-,sup=-,health=-,rst=0,audit=-,idmap=-,stop=not_recorded,caps=-,ro=false"
expect_line "B17 hyphenated audit policy is accepted" insp_besteffort "B17${tab}B${tab}0${tab}-${tab}inspect:c1,created,pid=-,exit=-,rev=1,cg=-,sup=-,health=-,rst=0,audit=best-effort/kill/enforce/-,idmap=-,stop=not_recorded,caps=-,ro=-"
expect_line "B17 empty stdout on success is unexpected" insp_empty "B17${tab}B${tab}0${tab}-${tab}<unexpected>:0"
expect_line "B17 oversized inspect is unexpected" insp_big "B17${tab}B${tab}0${tab}-${tab}<unexpected>:big"
# 漏えい検査: bundle のパス・cgroup 名・ホストの id・reason は capture に現れない
leak=0
for n in ok insp_full; do
  while IFS= read -r l; do
    case "$l" in *secret*|*100000*|*300000*|*kernel*) leak=$((leak + 1)) ;; esac
  done <"$work/$n.txt"
done
expect_eq "inspect capture leaks no path / cgroup / hostId / reason" 0 "$leak"
compare ok insp_order
expect_rc "malformed inspect differs from ok (rc 1)" 1 $?
cmp_has_prefix "B17 malformed inspect reported as UNVERIFIED" "B17 UNVERIFIED"
compare ok insp_full
expect_rc "different inspect values differ (rc 1)" 1 $?
cmp_has_prefix "B17 different values reported as MISMATCH" "B17 MISMATCH"
compare ok nonlinux
cmp_has_prefix "B17 non-linux is MISMATCH" "B17 MISMATCH"
# load_capture: 種別ごとに受理する形式を限定する
sed "s/^B02${tab}B${tab}0${tab}-${tab}.*/B02${tab}B${tab}0${tab}-${tab}inspect:c1,created,pid=-,exit=-,rev=1,cg=-,sup=-,health=-,rst=0,audit=-,idmap=-,stop=x,caps=-,ro=-/" "$work/ok.txt" >"$work/i1.txt"
compare i1 i1
expect_rc "inspect form on a non-inspect case is rejected" 2 $?
sed "s/^B17${tab}B${tab}0${tab}-${tab}.*/B17${tab}B${tab}0${tab}-${tab}list:H/" "$work/ok.txt" >"$work/i2.txt"
compare i2 i2
expect_rc "list form on an inspect case is rejected" 2 $?
sed "s/^B17${tab}B${tab}0${tab}-${tab}.*/B17${tab}B${tab}0${tab}-${tab}inspect:garbage/" "$work/ok.txt" >"$work/i3.txt"
compare i3 i3
expect_rc "inspect:garbage stdout field is rejected" 2 $?

# --- start 済みの inspect（種別 s / w。B18〜B25。#2891・SEC-1・CLI-1） ---
expect_line "B18 create with --read-only --cap-drop on the start bundle" ok "B18${tab}B${tab}0${tab}-${tab}-"
expect_line "B19 inspect before start records nothing" ok "B19${tab}B${tab}0${tab}-${tab}inspect:c2,created,pid=-,exit=-,rev=1,cg=-,sup=-,health=-,rst=0,audit=-,idmap=-,stop=not_recorded,caps=-,ro=-"
expect_line "B20 start of the start bundle" ok "B20${tab}B${tab}0${tab}-${tab}-"
expect_line "B21 inspect after start (caps=13, ro=true)" ok "B21${tab}B${tab}0${tab}-${tab}started:c2,running,pid=<pid>,sup=<pid>,cg=<set>,health=-,audit=<set>,idmap=<set>,stop=not_recorded,caps=13,ro=true"
expect_line "B22 stop --signal KILL" ok "B22${tab}B${tab}0${tab}-${tab}-"
expect_line "B23 inspect after the stop" ok "B23${tab}B${tab}0${tab}-${tab}started:c2,stopped,pid=-,sup=<pid>,cg=<set>,health=-,audit=<set>,idmap=<set>,stop=recorded,caps=13,ro=true"
expect_line "B24 delete" ok "B24${tab}B${tab}0${tab}-${tab}-"
expect_line "B25 list after the chain" ok "B25${tab}B${tab}0${tab}-${tab}list:H"
expect_line "B05 start of the empty rootfs bundle fails" ok "B05${tab}B${tab}5${tab}FAILED_PRECONDITION${tab}-"
# start が成功しない環境（nostart）は印だけを残す。
expect_line "nostart B20 start fails" nostart "B20${tab}B${tab}5${tab}FAILED_PRECONDITION${tab}-"
expect_line "nostart B21 is start-failed" nostart "B21${tab}B${tab}0${tab}-${tab}<start-failed>"
expect_line "nostart B23 is start-failed" nostart "B23${tab}B${tab}0${tab}-${tab}<start-failed>"
expect_line "nostart B24 delete of the created container" nostart "B24${tab}B${tab}0${tab}-${tab}-"
expect_line "nostart B25 list is empty again" nostart "B25${tab}B${tab}0${tab}-${tab}list:H"
compare ok nostart
expect_rc "compare with a not started side is rc 1" 1 $?
cmp_has_prefix "B21 reported as NOT_STARTED" 'B21 NOT_STARTED'
cmp_has_prefix "B23 reported as NOT_STARTED" 'B23 NOT_STARTED'
cmp_has "not started count" 'not started (start precondition unmet): 2'
compare nostart nostart
expect_rc "matching <start-failed> records are rc 1" 1 $?
cmp_has_prefix "B21 not started on both sides is NOT_STARTED" 'B21 NOT_STARTED'
compare ok ok
cmp_has "not started count is 0 when started" 'not started (start precondition unmet): 0'
compare ok nonlinux
cmp_has_prefix "B21 non-linux is NOT_STARTED" 'B21 NOT_STARTED'
# 終了待ちが期限切れ（stop しても running のまま）
expect_rc "stuck capture is rc 1" 1 "$(rc_of stuck)"
case "$(line_of stuck B23)" in
  "B23${tab}B${tab}"[0-9]*"${tab}<timeout>${tab}<timeout>") pass "B23 recorded as timeout" ;;
  *) fail "B23 recorded as timeout (got '$(line_of stuck B23)')" ;;
esac
expect_line "stuck B24 still deletes" stuck "B24${tab}B${tab}0${tab}-${tab}-"
# 漏えい検査: bundle・cgroup・hostId・reason は started の記録に現れない
leak=0
for n in nostart stuck; do
  [ -f "$work/$n.txt" ] || continue
  while IFS= read -r l; do
    case "$l" in *secret*|*100000*|*kernel*|*sbundle*|*rootfs*) leak=$((leak + 1)) ;; esac
  done <"$work/$n.txt"
done
while IFS= read -r l; do
  case "$l" in *secret*|*100000*|*kernel*|*sbundle*|*rootfs*) leak=$((leak + 1)) ;; esac
done <"$work/ok.txt"
expect_eq "started capture leaks no path / cgroup / hostId / reason" 0 "$leak"
# load_capture: started 形式・<start-failed> は種別 s / w にだけ置ける
sed "s/^B19${tab}B${tab}0${tab}-${tab}.*/B19${tab}B${tab}0${tab}-${tab}started:c2,running,pid=-,sup=-,cg=-,health=-,audit=-,idmap=-,stop=x,caps=-,ro=-/" "$work/ok.txt" >"$work/s1.txt"
compare s1 s1
expect_rc "started form on an inspect case is rejected" 2 $?
sed "s/^B21${tab}B${tab}0${tab}-${tab}.*/B21${tab}B${tab}0${tab}-${tab}list:H/" "$work/ok.txt" >"$work/s2.txt"
compare s2 s2
expect_rc "list form on a started case is rejected" 2 $?
sed "s/^B21${tab}B${tab}0${tab}-${tab}.*/B21${tab}B${tab}0${tab}-${tab}started:garbage/" "$work/ok.txt" >"$work/s3.txt"
compare s3 s3
expect_rc "started:garbage stdout field is rejected" 2 $?
sed "s/^B20${tab}B${tab}0${tab}-${tab}.*/B20${tab}B${tab}0${tab}-${tab}<start-failed>/" "$work/ok.txt" >"$work/s4.txt"
compare s4 s4
expect_rc "<start-failed> on a non-start-inspect case is rejected" 2 $?
sed "s/^B21${tab}B${tab}0${tab}-${tab}.*/B21${tab}B${tab}0${tab}-${tab}inspect:c2,running,pid=-,exit=-,rev=1,cg=-,sup=-,health=-,rst=0,audit=-,idmap=-,stop=x,caps=-,ro=-/" "$work/ok.txt" >"$work/s5.txt"
compare s5 s5
expect_rc "inspect form on a started case is rejected" 2 $?

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
if grep -qE '"op"|kill|delete|start[^e]' "$work/ok.txt"; then fail "op leaked into capture"; else pass "op is not recorded"; fi

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

# --- c2 の delete 失敗後は不在を確認できたときだけ状態ルートを消す（#2891・REPAIR-5） ---
count_left() { # <ディレクトリ>
  local n=0 f
  for f in "$1"/* "$1"/.[!.]*; do [ -e "$f" ] && n=$((n + 1)); done
  printf '%s' "$n"
}
expect_eq "delete failed and c2 remains (inspect ok): state root is kept" 1 "$(count_left "$work/tmp-delfail")"
expect_eq "delete failed and inspect is PERMISSION_DENIED: state root is kept" 1 "$(count_left "$work/tmp-deldeny")"
expect_eq "delete failed but inspect is NOT_FOUND: state root is removed" 0 "$(count_left "$work/tmp-delgone")"
expect_eq "signal re-entry during cleanup delete: state root is kept" 1 "$(count_left "$work/tmp-sigdel")"
expect_eq "signal re-entry during cleanup delete: exit 143" 143 "$(rc_of sigdel)"
if grep -q 'could not be reclaimed' "$work/delfail.err"; then pass "delfail warns about manual cleanup"; else fail "delfail warns about manual cleanup"; fi
if grep -q 'could not be reclaimed' "$work/deldeny.err"; then pass "deldeny warns about manual cleanup"; else fail "deldeny warns about manual cleanup"; fi
if grep -q 'could not be reclaimed' "$work/delgone.err"; then fail "delgone must not warn"; else pass "delgone does not warn"; fi

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
