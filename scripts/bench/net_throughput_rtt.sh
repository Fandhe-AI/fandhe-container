#!/usr/bin/env bash
# iperf3 スループットと 1 バイト TCP 往復の計測・Docker 比の算出スクリプト
# （TASK-140 準備・#1882・NET-2・NET-3・REPAIR-5・REPAIR-12）。
#
# 役割: TASK-140（#319。人間担当）の条件 2（全経路・ストリーム数 1 と 4 のスループットが Docker の 90% 以上。
# NET-2）と条件 3（1 バイト TCP 往復の p50 が Docker の 1.1 倍以内・p99 が 1.2 倍以内。NET-3）を測る入力を作る。
#   --mode measure（既定）: 3 経路 x ストリーム数 1・4 の iperf3（TCP）と 1 バイト TCP 往復を流し、経路ごとの
#                           試行中央値を JSON で出す。--target own|docker|both。both は試行ごとに own -> docker を
#                           交互に回す（NET-2 の「交互に計測する」。own を全部測ってから docker を測る順にはしない）
#   --mode compare:         2 つの measure 結果から、スループットの Docker 比（%）と p50・p99 の倍率を出す。
#                           合否は出さない（% は 90 と、倍率は 1.1・1.2 と人間が見比べる）
# 自前側は保持入口（crates/net/tests/network_paths_privileged.rs の `--hold --max-secs N`）が作るトポロジー、
# 往復は crates/net/tests/tcp_rtt_probe.rs を使う（契約は docs/design/net-tcp-rtt-bench.md）。
#
# 呼び出し元: Makefile の `net-throughput-rtt`（measure）・`net-throughput-rtt-compare`（compare）。実機前提のため
# `make ci` には含めない。自己テストは scripts/bench/net_throughput_rtt_selftest.sh（`net-throughput-rtt-selftest`・
# CI の bench-regression ジョブ）。本スクリプトは sudo も cargo も呼ばない。
#
# 重要（承認）: Agent は root でも docker でも実行しない。docker はホストの bridge・nftables を変えるため、
# `--target docker|both` の実行は人間の承認後に行う。既定の `--target own` は docker に一切触れない。
#
# 値の位置づけ: 暫定値（#319 の 2026-10-12 のコメントの推奨案）。出力はすべて `provisional: true` を持ち、
# NET-2・NET-3 の判定には使わない。判定は製品の起動経路（#1812〜#1819・#1873）がつながった後の測り直しで行う。
#
# 方法の差（`method` にも記録。比較時に読み違えないこと。REPAIR-3）:
#   - 両側とも、ホストの同じ iperf3 と tcp_rtt_probe（検証済みの複製）を `nsenter --net=<netns>` でコンテナ役の
#     netns へ入れて起動する。コンテナ役は製品の起動経路（namespace 隔離・cgroup・seccomp）も Docker の起動経路も
#     通らない（Docker 側は netns を借りるだけ。コンテナ本体は sleep するだけ）
#   - 自前のホスト役は隔離 netns（`unshare --net --mount`）で、物理 NIC・ホストの firewall を通らない。masquerade は未実装。
#     Docker のホスト役は実ホストの netns で、ホストの firewall のルールを通る
#   - Docker の (c) は daemon の userland-proxy の設定により docker-proxy を通り得る
#   - iperf3 は受信側（end.sum_received）の値を使う。PoC-15 は実ホスト上の自作ツールで、本計測とは場所が違う
#
# 経路（net-tcp-rtt-bench.md「3 経路の置き方」。iperf3 は 5201、往復は (a) 9101・(b) 9102・(c) 9080）:
#   (a) コンテナ間 c1 -> c2 / (b) ホスト -> c1 / (c) ホスト -> 公開ポート（自前 10.214.1.1:15201・:18080、
#   Docker は --host-addr:15201・:18080。-p で公開）
#
# 使い方:
#   net_throughput_rtt.sh --probe <abs> [--exe <abs>] [--target own|docker|both] [--iperf3 <abs>] [--nsenter <abs>]
#       [--docker <abs> --host-addr <IPv4> [--image IMG]] [--trials N] [--iperf-secs S] [--rtt-rounds N]
#       [--rtt-warmup W] [--timeout SECS] [--label NAME] [--output FILE]
#   net_throughput_rtt.sh --mode compare --own-result FILE --docker-result FILE [--output FILE]
#   --exe     保持入口（network_paths_privileged の実行ファイル）。--target docker 以外で必須
#   --probe   tcp_rtt_probe の実行ファイル
#   --iperf3 / --nsenter  省略時は PATH から探す（無ければ終了コード 3）。iperf3 は同梱も導入もしない
#   --docker  docker CLI の絶対パス（--target docker|both で必須）。--host-addr は非ループバックの IPv4（同上で必須）
#   --image   既定 busybox:1.36（事前に取得済みであること。--pull never。無ければ失敗）
#   実行ファイルは正規化済みの絶対パス・通常ファイル・symlink 不可・所有者は root / 実行ユーザー / SUDO_UID・
#   group/other 書き込み不可・祖先ディレクトリも同様に検証し、検証した fd から 0700 の私有ディレクトリへ複製して実行する
#   --trials 1..20（既定 5）--iperf-secs 1..60（既定 10）--rtt-rounds 1..100000（既定 10000）--rtt-warmup 0..10000
#   （既定 100）--timeout 全体の期限 1..3600（既定 1800）--output は新規ファイルのみ
#
# 出力 JSON: measure は schema "fandhe-container.net-throughput-rtt/v1"、compare は
#   "fandhe-container.net-throughput-rtt-compare/v1"。どちらも provisional: true・verdict なし。
#
# 終了コード:
#   0: 成功
#   1: 計測失敗（子の非ゼロ終了・期限・不正な出力・保持入口の後始末が ok でない・Docker イメージ無し・比較入力の schema 不一致）
#   2: 入力エラー（引数・実行ファイル・output の検証失敗）
#   3: 前提ツール欠如（bash・jq・timeout・mktemp・stat -c・setsid・realpath・mkfifo・iperf3・nsenter）
#   4: Docker の後始末失敗（ラベルのコンテナ・ネットワークが残った。他より優先）

set -euo pipefail
umask 077

readonly SCHEMA="fandhe-container.net-throughput-rtt/v1"
readonly CMP_SCHEMA="fandhe-container.net-throughput-rtt-compare/v1"
readonly RTT_SCHEMA="fandhe-container.tcp-rtt/v1"
readonly HOLD_SCHEMA="fandhe-container.net-hold/v1"
readonly OUT_LIMIT_KIB=4096

usage_error() {
  echo "net_throughput_rtt: $1" >&2
  exit 2
}
fail_measure() {
  echo "net_throughput_rtt: $1" >&2
  exit 1
}

for tool in jq timeout mktemp stat setsid realpath cat chmod mkfifo grep sleep kill; do
  command -v "$tool" >/dev/null 2>&1 || {
    echo "net_throughput_rtt: required tool not found: $tool" >&2
    exit 3
  }
done
stat -c '%a' -- / >/dev/null 2>&1 || {
  echo "net_throughput_rtt: GNU-compatible stat (-c) is required" >&2
  exit 3
}

mode="measure"
target="own"
exe=""
probe=""
iperf3_arg=""
nsenter_arg=""
docker_arg=""
host_addr=""
image="busybox:1.36"
trials=5
iperf_secs=10
rtt_rounds=10000
rtt_warmup=100
limit=1800
label="net-throughput-rtt"
output=""
own_result=""
docker_result=""

while [ $# -gt 0 ]; do
  case "$1" in
    --mode | --target | --exe | --probe | --iperf3 | --nsenter | --docker | --host-addr | --image | --trials | \
      --iperf-secs | --rtt-rounds | --rtt-warmup | --timeout | --label | --output | --own-result | --docker-result)
      [ $# -ge 2 ] || usage_error "missing value for $1"
      case "$1" in
        --mode) mode="$2" ;;
        --target) target="$2" ;;
        --exe) exe="$2" ;;
        --probe) probe="$2" ;;
        --iperf3) iperf3_arg="$2" ;;
        --nsenter) nsenter_arg="$2" ;;
        --docker) docker_arg="$2" ;;
        --host-addr) host_addr="$2" ;;
        --image) image="$2" ;;
        --trials) trials="$2" ;;
        --iperf-secs) iperf_secs="$2" ;;
        --rtt-rounds) rtt_rounds="$2" ;;
        --rtt-warmup) rtt_warmup="$2" ;;
        --timeout) limit="$2" ;;
        --label) label="$2" ;;
        --output) output="$2" ;;
        --own-result) own_result="$2" ;;
        --docker-result) docker_result="$2" ;;
      esac
      shift 2
      ;;
    *) usage_error "unknown argument: $1" ;;
  esac
done

check_int() { # name value min max
  [[ "$2" =~ ^[0-9]{1,6}$ ]] || usage_error "$1 must be an integer"
  local v=$((10#$2))
  if [ "$v" -lt "$3" ] || [ "$v" -gt "$4" ]; then
    usage_error "$1 must be in $3..$4"
  fi
}
[[ "$label" =~ ^[A-Za-z0-9._-]{1,64}$ ]] || usage_error "--label must match [A-Za-z0-9._-]{1,64}"
case "$mode" in measure | compare) ;; *) usage_error "--mode must be measure or compare" ;; esac

if [ -n "$output" ]; then
  if [ -e "$output" ] || [ -L "$output" ]; then
    usage_error "--output already exists; refusing to overwrite"
  fi
fi

emit() { # JSON 文字列を出力先へ（新規ファイルのみ）
  if [ -n "$output" ]; then
    (
      set -C
      printf '%s\n' "$1" >"$output"
    ) || usage_error "cannot create --output"
  else
    printf '%s\n' "$1"
  fi
}

# ---------------------------------------------------------------- compare モード
if [ "$mode" = "compare" ]; then
  [ -n "$own_result" ] || usage_error "--own-result is required"
  [ -n "$docker_result" ] || usage_error "--docker-result is required"
  load_result() { # flag path side -> stdout は使わず検証のみ
    local p="$2"
    [ -f "$p" ] && [ ! -L "$p" ] || usage_error "$1 must be a regular file and not a symlink"
    local sz
    sz="$(stat -c '%s' -- "$p")" || usage_error "cannot stat $1"
    [ "$sz" -le 1048576 ] || usage_error "$1 is larger than 1 MiB"
    local ok
    ok="$(jq -e --arg s "$SCHEMA" --arg side "$3" '
      .schema == $s and .provisional == true
      and (.results[$side].paths | type == "object")
      and ([.results[$side].paths | (.a, .b, .c)
            | (.throughput["1"].median, .throughput["4"].median, .rtt.p50.median, .rtt.p99.median)]
           | length == 12 and all(type == "number" and . > 0))' "$p" 2>/dev/null)" || ok=""
    [ "$ok" = "true" ] || fail_measure "$1 is not a valid $SCHEMA result with a '$3' section (positive medians required)"
  }
  load_result --own-result "$own_result" own
  load_result --docker-result "$docker_result" docker
  result="$(jq -n -S --arg schema "$CMP_SCHEMA" --slurpfile o "$own_result" --slurpfile d "$docker_result" '
    def r3: (. * 1000 | round) / 1000;
    $o[0] as $O | $d[0] as $D
    | {
        schema: $schema,
        provisional: true,
        own_label: $O.label,
        docker_label: $D.label,
        params_match: ($O.params == $D.params),
        unit: {throughput_pct_of_docker: "percent", rtt_ratio: "own / docker"},
        paths: ([("a", "b", "c")] | map(. as $p | {key: $p, value: {
          throughput_pct_of_docker: ([("1", "4")] | map(. as $s | {key: $s, value:
            (($O.results.own.paths[$p].throughput[$s].median / $D.results.docker.paths[$p].throughput[$s].median * 100) | r3)}) | from_entries),
          rtt_p50_ratio: (($O.results.own.paths[$p].rtt.p50.median / $D.results.docker.paths[$p].rtt.p50.median) | r3),
          rtt_p99_ratio: (($O.results.own.paths[$p].rtt.p99.median / $D.results.docker.paths[$p].rtt.p99.median) | r3)
        }}) | from_entries),
        notes: [
          "provisional values: not for the NET-2/NET-3 verdict; no pass/fail is computed here",
          "compare throughput_pct_of_docker with 90 and rtt_p50_ratio / rtt_p99_ratio with 1.1 / 1.2 by hand (TASK-140, #319)",
          "own and docker sides differ in method; see results.*.method in the input files"
        ]
      }')"
  emit "$result"
  exit 0
fi

# ---------------------------------------------------------------- measure モード
check_int --trials "$trials" 1 20
check_int --iperf-secs "$iperf_secs" 1 60
check_int --rtt-rounds "$rtt_rounds" 1 100000
check_int --rtt-warmup "$rtt_warmup" 0 10000
check_int --timeout "$limit" 1 3600
trials=$((10#$trials))
iperf_secs=$((10#$iperf_secs))
rtt_rounds=$((10#$rtt_rounds))
rtt_warmup=$((10#$rtt_warmup))
limit=$((10#$limit))

case "$target" in
  own) targets="own" ;;
  docker) targets="docker" ;;
  both) targets="own docker" ;;
  *) usage_error "--target must be own, docker or both" ;;
esac
use_own=0
use_docker=0
case "$target" in own | both) use_own=1 ;; esac
case "$target" in docker | both) use_docker=1 ;; esac
ntargets=$((use_own + use_docker))

[ -n "$probe" ] || usage_error "--probe is required"
if [ "$use_own" -eq 1 ]; then
  [ -n "$exe" ] || usage_error "--exe is required unless --target docker"
fi
if [ "$use_docker" -eq 1 ]; then
  [ -n "$docker_arg" ] || usage_error "--docker is required for --target docker|both"
  [ -n "$host_addr" ] || usage_error "--host-addr is required for --target docker|both"
  [[ "$host_addr" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || usage_error "--host-addr must be an IPv4 address"
  for o in "${BASH_REMATCH[@]:1}"; do
    [ $((10#$o)) -le 255 ] || usage_error "--host-addr octet out of range"
  done
  case "$host_addr" in 127.* | 0.0.0.0) usage_error "--host-addr must not be loopback or 0.0.0.0" ;; esac
  [[ "$image" =~ ^[A-Za-z0-9][A-Za-z0-9._/:@-]{0,254}$ ]] || usage_error "--image has an invalid format"
fi
# 最小所要時間（iperf3 の試行だけで期限を超えるなら実行前に拒否する）
min_secs=$((trials * 3 * 2 * iperf_secs * ntargets))
[ "$min_secs" -le "$limit" ] || usage_error "--timeout $limit is shorter than the minimum measurement time ${min_secs}s"

self_uid="$(id -u)"
sudo_uid=""
if [[ "${SUDO_UID:-}" =~ ^[1-9][0-9]{0,9}$ ]]; then
  sudo_uid="$SUDO_UID"
fi
owner_allowed() {
  [ "$1" = "0" ] || [ "$1" = "$self_uid" ] || { [ -n "$sudo_uid" ] && [ "$1" = "$sudo_uid" ]; }
}
check_owner_perm() { # path allow_sticky_root
  local p="$1" owner mode
  owner="$(stat -c '%u' -- "$p")" || usage_error "cannot stat $p"
  mode="$(stat -c '%a' -- "$p")" || usage_error "cannot stat $p"
  owner_allowed "$owner" || usage_error "$p must be owned by root, the current user or the sudo invoking user"
  if [ $((8#$mode & 8#022)) -ne 0 ]; then
    if [ "$2" = "yes" ] && [ "$owner" = "0" ] && [ $((8#$mode & 8#1000)) -ne 0 ]; then
      return 0
    fi
    usage_error "$p must not be group/other writable"
  fi
}

work="$(mktemp -d)"
servers=""
hold_pid=""
hold_inner_pid=""
hold_inner_start=""
hold_open=0
docker_active=0
docker_leftover=0
cleanup_bad=0
dk_net_id=""
dk_label=""

kill_servers() {
  local p
  for p in $servers; do
    kill -KILL -- "-$p" 2>/dev/null || true
    wait "$p" 2>/dev/null || true
  done
  servers=""
}

# /proc/<pid>/stat から "pgrp starttime state" を出す（comm に空白・括弧があっても最後の ") " 以降で切る）。
proc_ident() {
  local s f
  s="$(cat "/proc/$1/stat" 2>/dev/null)" || return 1
  s="${s##*) }"
  read -r -a f <<<"$s"
  [ "${#f[@]}" -ge 20 ] || return 1
  printf '%s %s %s' "${f[2]}" "${f[19]}" "${f[0]}"
}
# 保持入口の内部プロセス（unshare の子。launcher が別プロセスグループにするため外側グループの SIGKILL では届かない）が
# ready 行で記録した本人か（pgrp が自身の PID・開始時刻が一致・ゾンビでない）。PID の再利用で他人を撃たないための照合。
inner_ours() {
  local pg st state
  [ -n "$hold_inner_pid" ] || return 1
  read -r pg st state <<<"$(proc_ident "$hold_inner_pid")" || return 1
  [ "$pg" = "$hold_inner_pid" ] && [ "$st" = "$hold_inner_start" ] && [ "$state" != "Z" ]
}
# 内部プロセスグループを所有確認のうえ SIGKILL し、消えたことを期限つきで確かめる。消えなければ cleanup_bad。
kill_inner() {
  [ -n "$hold_inner_pid" ] || return 0
  if inner_ours; then
    local i=0
    cleanup_bad=1
    echo "net_throughput_rtt: hold inner process group $hold_inner_pid still alive; killing it" >&2
    kill -KILL -- "-$hold_inner_pid" 2>/dev/null || true
    while inner_ours && [ "$i" -lt 100 ]; do
      sleep 0.05
      i=$((i + 1))
    done
    if inner_ours; then
      echo "net_throughput_rtt: hold inner process group $hold_inner_pid survived SIGKILL (manual cleanup needed)" >&2
    fi
  fi
  hold_inner_pid=""
}

# 保持入口を解放する（fifo へ release を書き、released 行の cleanup が ok であることを照合する）。
release_own() {
  [ -n "$hold_pid" ] || { kill_inner; return 0; }
  if [ "$hold_open" -eq 1 ]; then
    # 読み手（保持入口）が先に終了していると SIGPIPE で自分が死ぬため、サブシェルで PIPE を無視して書く。
    (
      trap '' PIPE
      printf 'release\n' >&4
    ) 2>/dev/null || true
    exec 4>&-
    hold_open=0
  fi
  local i=0
  while kill -0 "$hold_pid" 2>/dev/null && [ "$i" -lt 300 ]; do
    sleep 0.05
    i=$((i + 1))
  done
  if kill -0 "$hold_pid" 2>/dev/null; then
    kill -KILL -- "-$hold_pid" 2>/dev/null || true
    cleanup_bad=1
    echo "net_throughput_rtt: hold did not exit after release" >&2
  fi
  wait "$hold_pid" 2>/dev/null || true
  hold_pid=""
  kill_inner
  if ! tail -n 1 "$work/hold.out" 2>/dev/null | jq -e --arg s "$HOLD_SCHEMA" \
    '.schema == $s and .event == "released" and .cleanup == "ok"' >/dev/null 2>&1; then
    cleanup_bad=1
    echo "net_throughput_rtt: hold did not report cleanup ok" >&2
  fi
}

# 所有を証明できるもの（cidfile の ID・作成で得たネットワーク ID）だけを消し、ラベルで残りを確かめる。
# 準備・計測中の docker 呼び出しは --timeout の残り時間で頭打ちにする（残りが無ければ 124 を返し何も実行しない。
# 期限後に新しい資源を作らない。サブシェルで呼ばれても exit しないよう fail_measure は呼び出し側で行う）。
dk() {
  remaining
  [ "$REM" -gt 0 ] || return 124
  local cap=60
  [ "$REM" -ge "$cap" ] || cap="$REM"
  timeout --foreground --kill-after=5 "$cap" "$docker_run" "$@"
}
# 後始末の docker 呼び出しは全体期限と別の有限予算（合計 CLEAN_BUDGET 秒・1 回 30 秒まで）で行う。
CLEAN_BUDGET=120
clean_end=0
dkc() {
  local left=$((clean_end - SECONDS)) cap=30
  [ "$left" -gt 0 ] || return 124
  [ "$left" -ge "$cap" ] || cap="$left"
  timeout --foreground --kill-after=5 "$cap" "$docker_run" "$@"
}
cleanup_docker() {
  [ "$docker_active" -eq 1 ] || return 0
  # 削除と残存確認が終わるまで active を保つ（途中の INT・TERM で on_exit から再入して続きを行えるようにする）
  local f id left
  [ "$clean_end" -gt 0 ] || clean_end=$((SECONDS + CLEAN_BUDGET))
  for f in "$work"/c1.cid "$work"/c2.cid; do
    [ -s "$f" ] || continue
    id="$(head -c 128 "$f" 2>/dev/null || true)"
    [[ "$id" =~ ^[0-9a-f]{64}$ ]] && dkc rm -f "$id" >/dev/null 2>&1 || true
  done
  if [[ "$dk_net_id" =~ ^[0-9a-f]{12,64}$ ]]; then
    dkc network rm "$dk_net_id" >/dev/null 2>&1 || true
  fi
  left="$(dkc ps -a -q --filter "label=$dk_label" 2>/dev/null || echo UNKNOWN)"
  left="$left$(dkc network ls -q --filter "label=$dk_label" 2>/dev/null || echo UNKNOWN)"
  if [ -n "$left" ]; then
    docker_leftover=1
    echo "net_throughput_rtt: docker resources with label $dk_label remain: $left" >&2
  fi
  docker_active=0
}

teardown() {
  kill_servers
  release_own
  cleanup_docker
}
on_exit() {
  local rc=$?
  trap - EXIT
  # 後始末中の INT・TERM は無視する（削除の途中で抜けて資源を残さない。個々の docker 呼び出しには期限がある）
  trap '' INT TERM
  teardown
  rm -rf "$work"
  if [ "$docker_leftover" -eq 1 ]; then exit 4; fi
  if [ "$cleanup_bad" -eq 1 ] && [ "$rc" -eq 0 ]; then exit 1; fi
  exit "$rc"
}
trap on_exit EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

mkdir -m 700 "$work/bin"

# 実行ファイルを検証し、検証した fd から複製する（TOCTOU 回避）。out が空なら検証のみ。
verify_bin() { # flag path out
  local flag="$1" p="$2" out="$3" canon dir
  case "$p" in /*) ;; *) usage_error "$flag must be an absolute path" ;; esac
  [ ! -L "$p" ] || usage_error "$flag must not be a symlink"
  if [ ! -f "$p" ] || [ ! -x "$p" ]; then usage_error "$flag must be an executable regular file"; fi
  canon="$(realpath -e -- "$p" 2>/dev/null)" || usage_error "cannot resolve $flag"
  [ "$canon" = "$p" ] || usage_error "$flag must be a canonical path (no symlink components)"
  check_owner_perm "$p" no
  dir="$(dirname -- "$p")"
  while :; do
    [ -d "$dir" ] && [ ! -L "$dir" ] || usage_error "$flag ancestor is not a plain directory: $dir"
    check_owner_perm "$dir" yes
    [ "$dir" != "/" ] || break
    dir="$(dirname -- "$dir")"
  done
  [ -n "$out" ] || return 0
  exec 3<"$p" || usage_error "cannot open $flag"
  local fo fm
  fo="$(stat -L -c '%u' -- /proc/self/fd/3 2>/dev/null || stat -L -c '%u' -- "$p")"
  fm="$(stat -L -c '%a' -- /proc/self/fd/3 2>/dev/null || stat -L -c '%a' -- "$p")"
  if ! owner_allowed "$fo" || [ $((8#$fm & 8#022)) -ne 0 ]; then
    usage_error "$flag changed or has unsafe owner/permissions"
  fi
  cat <&3 >"$out" || usage_error "cannot copy $flag"
  exec 3<&-
  chmod 700 "$out"
}

[ -n "$iperf3_arg" ] || iperf3_arg="$(command -v iperf3 2>/dev/null || true)"
[ -n "$iperf3_arg" ] || {
  echo "net_throughput_rtt: required tool not found: iperf3 (not bundled; install iperf3 3.x)" >&2
  exit 3
}
[ -n "$nsenter_arg" ] || nsenter_arg="$(command -v nsenter 2>/dev/null || true)"
[ -n "$nsenter_arg" ] || {
  echo "net_throughput_rtt: required tool not found: nsenter (util-linux)" >&2
  exit 3
}
verify_bin --iperf3 "$iperf3_arg" "$work/bin/iperf3"
verify_bin --nsenter "$nsenter_arg" "$work/bin/nsenter"
verify_bin --probe "$probe" "$work/bin/probe"
[ "$use_own" -eq 0 ] || verify_bin --exe "$exe" "$work/bin/hold"
docker_run=""
if [ "$use_docker" -eq 1 ]; then
  verify_bin --docker "$docker_arg" ""
  docker_run="$docker_arg"
fi
IPERF3="$work/bin/iperf3"
NSENTER="$work/bin/nsenter"
PROBE="$work/bin/probe"

# 応答しない実行ファイルで止まらないよう期限をつける（期限超過は空になり、下で失敗として扱う。REPAIR-5）
iperf_version="$(timeout --foreground --kill-after=2 10 "$IPERF3" --version 2>/dev/null | head -n 1 || true)"
[[ "$iperf_version" =~ ^iperf\ 3\. ]] || usage_error "--iperf3 must be iperf 3.x (got: ${iperf_version:-none})"
iperf_version="${iperf_version:0:80}"

# ---- 時間管理
remaining() { REM=$((limit - SECONDS)); }
cap_for() { # 上限秒 -> CAP（残り時間で頭打ち）
  remaining
  [ "$REM" -gt 0 ] || fail_measure "deadline exceeded (--timeout $limit)"
  CAP="$1"
  [ "$REM" -ge "$CAP" ] || CAP="$REM"
}

# ---- 子プロセスの起動
NSP=()
ns_prefix() { # netns（"-" はホストの netns のまま）
  if [ "$1" = "-" ]; then NSP=(); else NSP=("$NSENTER" "--net=$1" --); fi
}
wait_line() { # file regex secs pid
  local end=$((SECONDS + $3))
  while ! grep -q -E -- "$2" "$1" 2>/dev/null; do
    if ! kill -0 "$4" 2>/dev/null; then
      grep -q -E -- "$2" "$1" 2>/dev/null && return 0
      return 1
    fi
    [ "$SECONDS" -lt "$end" ] || return 1
    sleep 0.05
  done
}
start_server() { # out ns cmd...（別プロセスグループで起動。SPID に PID）
  local out="$1" ns="$2"
  shift 2
  ns_prefix "$ns"
  cap_for 600
  # 前回の待受行で wait_line が成功しないよう、切り詰めは親で同期的に済ませてから起動する
  : >"$out"
  (
    ulimit -f "$OUT_LIMIT_KIB"
    exec setsid timeout --foreground --kill-after=5 "$CAP" ${NSP[@]+"${NSP[@]}"} "$@" >"$out" 2>&1
  ) &
  SPID=$!
  servers="$servers $SPID"
}
run_client() { # out cap ns cmd...
  local out="$1" cap="$2" ns="$3" rc=0
  shift 3
  ns_prefix "$ns"
  cap_for "$cap"
  (
    ulimit -f "$OUT_LIMIT_KIB"
    exec timeout --foreground --kill-after=5 "$CAP" ${NSP[@]+"${NSP[@]}"} "$@" >"$out" 2>"$out.err"
  ) || rc=$?
  [ "$rc" -eq 0 ] || fail_measure "client command failed (exit $rc): $(head -c 200 "$out.err" 2>/dev/null | tr '\n' ' ')"
}

# ---- 自前側の準備（保持入口）
OWN_C1NS="" OWN_C2NS="" OWN_HOSTNS="" OWN_C1IP="" OWN_C2IP="" OWN_OUTER=""
prepare_own() {
  mkfifo -m 600 "$work/hold.in"
  (
    ulimit -f 64
    exec setsid timeout --foreground --kill-after=10 "$((limit + 30))" "$work/bin/hold" --hold --max-secs "$limit" \
      <"$work/hold.in" >"$work/hold.out" 2>"$work/hold.err"
  ) &
  hold_pid=$!
  exec 4>"$work/hold.in"
  hold_open=1
  cap_for 120
  wait_line "$work/hold.out" '"event":"ready"' "$CAP" "$hold_pid" || fail_measure "hold did not report ready: $(head -c 200 "$work/hold.err" 2>/dev/null | tr '\n' ' ')"
  local ready ipid ist ipg
  ready="$(grep -m 1 '"event":"ready"' "$work/hold.out")"
  # 検証より先に内部プロセスの身元（PID・開始時刻）を記録し、検証失敗の経路でも後始末で内部グループを回収できるようにする。
  ipid="$(printf '%s' "$ready" | jq -r '.inner_pid | select(type == "number" and . > 1 and . == floor) | tostring' 2>/dev/null || true)"
  if [[ "$ipid" =~ ^[1-9][0-9]{0,9}$ ]] && read -r ipg ist _ <<<"$(proc_ident "$ipid")" && [ "$ipg" = "$ipid" ]; then
    hold_inner_pid="$ipid"
    hold_inner_start="$ist"
  fi
  printf '%s' "$ready" | jq -e --arg s "$HOLD_SCHEMA" '
    def safe: type == "string" and test("^[A-Za-z0-9/._-]+$");
    def ip: type == "string" and test("^[0-9]{1,3}(\\.[0-9]{1,3}){3}$");
    (.inner_pid | tostring) as $pre
    | .schema == $s and .event == "ready" and .provisional == true
    and (.inner_pid | type == "number") and (.containers | length == 2)
    and (.host_netns | safe) and (.host_netns | startswith("/proc/" + $pre + "/"))
    and all(.containers[]; (.netns | safe) and (.netns | startswith("/proc/" + $pre + "/")) and (.addr | ip))
    and (.host.outer_addr | ip)' >/dev/null 2>&1 || fail_measure "hold ready line failed validation"
  OWN_C1NS="$(printf '%s' "$ready" | jq -r '.containers[0].netns')"
  OWN_C2NS="$(printf '%s' "$ready" | jq -r '.containers[1].netns')"
  OWN_C1IP="$(printf '%s' "$ready" | jq -r '.containers[0].addr')"
  OWN_C2IP="$(printf '%s' "$ready" | jq -r '.containers[1].addr')"
  OWN_HOSTNS="$(printf '%s' "$ready" | jq -r '.host_netns')"
  OWN_OUTER="$(printf '%s' "$ready" | jq -r '.host.outer_addr')"
}

# ---- Docker 側の準備
# 自己テスト専用: 偽の /proc の置き場所（既定は /proc）。
PROC_ROOT="${FANDHE_NET_RTT_PROC_ROOT:-/proc}"
PROC_TOK_VAR="FANDHE_NET_RTT_RUN"
DK_C1NS="" DK_C2NS="" DK_C1IP="" DK_C2IP="" dk_version=""
prepare_docker() {
  local tok
  # 資源を作る前に、docker CLI がこのホストのローカルデーモンを指していることを確かめる（State.Pid をローカルの
  # /proc の PID として使うため。DOCKER_HOST・DOCKER_CONTEXT・選択中の context が遠隔を指す構成を拒否する）。
  case "${DOCKER_HOST:-}" in "" | unix://*) ;; *) fail_measure "docker-not-local: DOCKER_HOST=${DOCKER_HOST:0:64} is not a unix socket" ;; esac
  case "${DOCKER_CONTEXT:-}" in "" | default) ;; *) fail_measure "docker-not-local: DOCKER_CONTEXT is not default" ;; esac
  [ "$(dk context show 2>/dev/null | head -c 64 | tr -d '\n')" = "default" ] || fail_measure "docker-not-local: the selected docker context is not 'default'"
  tok="$(head -c 8 /dev/urandom | od -An -tx1 | tr -d ' \n')"
  [[ "$tok" =~ ^[0-9a-f]{16}$ ]] || fail_measure "cannot create a run token"
  dk_label="fandhe.net-throughput.run=$tok"
  dk image inspect "$image" >/dev/null 2>&1 || fail_measure "image-missing: $image is not present locally (pull is never run by this script)"
  dk_version="$(dk version --format '{{.Server.Version}}' 2>/dev/null | head -c 64 | tr -d '\n' || true)"
  docker_active=1
  local netname="fcnetbench-$tok" hold_secs=$((limit + 60))
  dk_net_id="$(dk network create --driver bridge --label "$dk_label" "$netname" 2>/dev/null | head -c 128 | tr -d '\n')" || true
  [[ "$dk_net_id" =~ ^[0-9a-f]{12,64}$ ]] || fail_measure "docker network create failed"
  dk run -d --pull never --cidfile "$work/c1.cid" --network "$netname" --label "$dk_label" --env "$PROC_TOK_VAR=$tok" \
    -p "$host_addr:15201:5201/tcp" -p "$host_addr:18080:9080/tcp" "$image" sleep "$hold_secs" >/dev/null 2>&1 || fail_measure "docker run (c1) failed"
  dk run -d --pull never --cidfile "$work/c2.cid" --network "$netname" --label "$dk_label" --env "$PROC_TOK_VAR=$tok" \
    "$image" sleep "$hold_secs" >/dev/null 2>&1 || fail_measure "docker run (c2) failed"
  local n info pid ip
  for n in 1 2; do
    local cid
    cid="$(head -c 128 "$work/c$n.cid")"
    [[ "$cid" =~ ^[0-9a-f]{64}$ ]] || fail_measure "invalid container id for c$n"
    info="$(dk inspect "$cid" 2>/dev/null | head -c 1048576)" || fail_measure "docker inspect failed"
    pid="$(printf '%s' "$info" | jq -r '.[0].State.Pid' 2>/dev/null || true)"
    ip="$(printf '%s' "$info" | jq -r --arg n "$netname" '.[0].NetworkSettings.Networks[$n].IPAddress' 2>/dev/null || true)"
    [[ "$pid" =~ ^[1-9][0-9]{0,9}$ ]] || fail_measure "invalid container pid for c$n"
    # 取得した PID がこの実行で作った（今のホストの）コンテナ本人のものか、環境変数の実行トークンで確かめる。
    tr '\0' '\n' <"$PROC_ROOT/$pid/environ" 2>/dev/null | grep -q -x -F -- "$PROC_TOK_VAR=$tok" ||
      fail_measure "docker-pid-not-ours: pid $pid of c$n is not this run's container on this host"
    [[ "$ip" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || fail_measure "invalid container address for c$n"
    if [ "$n" = 1 ]; then
      DK_C1NS="/proc/$pid/ns/net"
      DK_C1IP="$ip"
    else
      DK_C2NS="/proc/$pid/ns/net"
      DK_C2IP="$ip"
    fi
  done
}

# ---- 経路の定義（SNS: サーバー netns / SBIND: bind / CNS: クライアント netns / DIP: 宛先）
SNS="" SBIND="" CNS="" DIP="" IPERF_SPORT=5201 IPERF_DPORT=5201 RTT_SPORT=9101 RTT_DPORT=9101
set_path() { # target path
  case "$1:$2" in
    own:a) SNS="$OWN_C2NS" SBIND="$OWN_C2IP" CNS="$OWN_C1NS" DIP="$OWN_C2IP" IPERF_DPORT=5201 RTT_SPORT=9101 RTT_DPORT=9101 ;;
    own:b) SNS="$OWN_C1NS" SBIND="$OWN_C1IP" CNS="$OWN_HOSTNS" DIP="$OWN_C1IP" IPERF_DPORT=5201 RTT_SPORT=9102 RTT_DPORT=9102 ;;
    own:c) SNS="$OWN_C1NS" SBIND="0.0.0.0" CNS="$OWN_HOSTNS" DIP="$OWN_OUTER" IPERF_DPORT=15201 RTT_SPORT=9080 RTT_DPORT=18080 ;;
    docker:a) SNS="$DK_C2NS" SBIND="$DK_C2IP" CNS="$DK_C1NS" DIP="$DK_C2IP" IPERF_DPORT=5201 RTT_SPORT=9101 RTT_DPORT=9101 ;;
    docker:b) SNS="$DK_C1NS" SBIND="$DK_C1IP" CNS="-" DIP="$DK_C1IP" IPERF_DPORT=5201 RTT_SPORT=9102 RTT_DPORT=9102 ;;
    docker:c) SNS="$DK_C1NS" SBIND="0.0.0.0" CNS="-" DIP="$host_addr" IPERF_DPORT=15201 RTT_SPORT=9080 RTT_DPORT=18080 ;;
    *) fail_measure "internal: unknown path $1:$2" ;;
  esac
}

samples="$work/samples.jsonl"
num_re='^[0-9]+(\.[0-9]+)?$'

measure_iperf() { # target path streams
  local o="$work/iperf.out" v
  start_server "$o.srv" "$SNS" "$IPERF3" -s -1 --forceflush -B "$SBIND" -p "$IPERF_SPORT"
  wait_line "$o.srv" 'Server listening on' 15 "$SPID" || fail_measure "iperf3 server did not start ($1 path $2)"
  run_client "$o" $((iperf_secs + 30)) "$CNS" "$IPERF3" -c "$DIP" -p "$IPERF_DPORT" -t "$iperf_secs" -P "$3" -J
  kill_servers
  v="$(jq -e -r '.end.sum_received.bits_per_second | select(type == "number" and . > 0) | (. / 1e6 * 1000 | round) / 1000' "$o" 2>/dev/null)" ||
    fail_measure "iperf3 output failed validation ($1 path $2 streams $3)"
  [[ "$v" =~ $num_re ]] || fail_measure "iperf3 value is not a number"
  jq -n -c --arg t "$1" --arg p "$2" --argjson s "$3" --argjson v "$v" '{t: $t, p: $p, k: "tp", s: $s, v: $v}' >>"$samples"
}
measure_rtt() { # target path
  local o="$work/rtt.out" vals p50 p99
  start_server "$o.srv" "$SNS" "$PROBE" --serve "$SBIND:$RTT_SPORT"
  wait_line "$o.srv" '"tcp_rtt_probe":"listening"' 15 "$SPID" || fail_measure "tcp_rtt_probe server did not start ($1 path $2)"
  run_client "$o" 330 "$CNS" "$PROBE" --client "$DIP:$RTT_DPORT" --rounds "$rtt_rounds" --warmup "$rtt_warmup"
  kill_servers
  vals="$(jq -e -r --arg s "$RTT_SCHEMA" 'select(.schema == $s and .unit == "us" and (.p50 | type == "number") and (.p99 | type == "number") and .p50 > 0 and .p99 > 0) | "\(.p50) \(.p99)"' "$o" 2>/dev/null)" ||
    fail_measure "tcp_rtt_probe output failed validation ($1 path $2)"
  p50="${vals% *}"
  p99="${vals#* }"
  [[ "$p50" =~ $num_re && "$p99" =~ $num_re ]] || fail_measure "tcp_rtt_probe values are not numbers"
  jq -n -c --arg t "$1" --arg p "$2" --argjson a "$p50" --argjson b "$p99" '{t: $t, p: $p, k: "rtt", p50: $a, p99: $b}' >>"$samples"
}

[ "$use_own" -eq 0 ] || prepare_own
[ "$use_docker" -eq 0 ] || prepare_docker

trial=0
while [ "$trial" -lt "$trials" ]; do
  trial=$((trial + 1))
  for t in $targets; do
    for p in a b c; do
      set_path "$t" "$p"
      for s in 1 4; do measure_iperf "$t" "$p" "$s"; done
      measure_rtt "$t" "$p"
    done
  done
done

# 計測後に先に後始末する（残りがあれば exit 1 / 4 を出力より前に確定させる）。
teardown
if [ "$docker_leftover" -eq 1 ]; then exit 4; fi
[ "$cleanup_bad" -eq 0 ] || fail_measure "cleanup verification failed"

case "$target" in
  own) order="own" ;;
  docker) order="docker" ;;
  *) order="alternate" ;;
esac

method_own="iperf3 and tcp_rtt_probe run from the host via nsenter into netns pins of a hold entry (unshare --net --mount, fresh netns); container roles do not go through the product launch path (no isolation, cgroup or seccomp); host role is an isolated netns without the host firewall or physical NIC; masquerade is unimplemented; iperf3 value is the receiver side (end.sum_received); differs from PoC-15 (real host, custom tool)"
method_docker="same host iperf3 and tcp_rtt_probe via nsenter into the netns of docker bridge containers that only sleep; host role is the real host netns through the host firewall; path (c) goes through docker published ports and may pass docker-proxy depending on daemon userland-proxy; iperf3 value is the receiver side (end.sum_received); differs from PoC-15 (real host, custom tool)"

result="$(jq -s -S \
  --arg schema "$SCHEMA" --arg label "$label" --arg order "$order" \
  --argjson trials "$trials" --argjson isecs "$iperf_secs" --argjson rounds "$rtt_rounds" --argjson warm "$rtt_warmup" \
  --arg mo "$method_own" --arg md "$method_docker" --arg iv "$iperf_version" --arg dv "$dk_version" '
  def r3: (. * 1000 | round) / 1000;
  def med: sort as $s | ($s | length) as $n
    | (if $n % 2 == 1 then $s[($n - 1) / 2] else ($s[$n / 2 - 1] + $s[$n / 2]) / 2 end) | r3;
  def st: {samples: length, median: med};
  . as $all
  | def tgt($t; $method; $iso; $ver):
      [$all[] | select(.t == $t)] as $r
      | if ($r | length) == 0 then null else {
          method: $method, isolation: $iso, versions: $ver,
          paths: (["a", "b", "c"] | map(. as $p | {key: $p, value: {
            throughput: (["1", "4"] | map(. as $s | {key: $s, value:
              ([$r[] | select(.p == $p and .k == "tp" and (.s | tostring) == $s) | .v] | st)}) | from_entries),
            rtt: {
              p50: ([$r[] | select(.p == $p and .k == "rtt") | .p50] | st),
              p99: ([$r[] | select(.p == $p and .k == "rtt") | .p99] | st)
            }
          }}) | from_entries)
        } end;
  {
    schema: $schema, provisional: true, label: $label, order: $order,
    unit: {throughput: "Mbit/s", rtt: "us"},
    params: {trials: $trials, iperf_secs: $isecs, streams: [1, 4], rtt_rounds: $rounds, rtt_warmup: $warm},
    results: ({
      own: tgt("own"; $mo; "unshare --net --mount (fresh netns)"; {iperf3: $iv}),
      docker: tgt("docker"; $md; "host netns"; {iperf3: $iv, docker: $dv})
    } | with_entries(select(.value != null)))
  }' "$samples")"

emit "$result"
