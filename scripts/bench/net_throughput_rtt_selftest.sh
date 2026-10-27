#!/usr/bin/env bash
# scripts/bench/net_throughput_rtt.sh の自己テスト（TASK-140 準備・#1882・NET-2・NET-3・REPAIR-12）。
#
# 役割: 実機（root・netns・iperf3・docker）を使わず、bash のスタブ（保持入口・nsenter・iperf3・tcp_rtt_probe・
# docker）で、引数の検証・実行ファイルの拒否・前提ツール欠如・自前 / Docker の集計値・交互の計測順・
# Docker の後始末（--pull never・ラベル・rm -f・network rm・残り検出）・保持入口の後始末の照合・期限での
# 子孫回収・比較の % と倍率を、具体値で機械照合する。実測そのものは行わない（実測は TASK-140・#319。人間）。
# 呼び出し元は Makefile の `net-throughput-rtt-selftest` ターゲットと ci.yml の bench-regression ジョブ。
#
# 期待と異なる結果が 1 件でもあれば非ゼロで終了する（fail-closed）。各ケースの失敗は failures に数えて
# 最後まで実行を続け、末尾のサマリーで判定する。

# shellcheck disable=SC2016  # スタブ本文は意図的に単引用符（展開はスタブ実行時）
set -euo pipefail
umask 022

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
target_script="${script_dir}/net_throughput_rtt.sh"
bash_bin="$(command -v bash)"

failures=0
tmp_root="$(mktemp -d)"
trap 'rm -rf "$tmp_root"' EXIT

last_stdout=""
last_stderr=""
last_rc=0

fail() {
  echo "FAIL: $1" >&2
  failures=$((failures + 1))
}
pass() { echo "PASS: $1"; }

run_target() {
  local errfile="$tmp_root/stderr.txt"
  last_rc=0
  last_stdout="$("$bash_bin" "$target_script" "$@" 2>"$errfile")" || last_rc=$?
  last_stderr="$(cat "$errfile")"
}
expect_rc() { # 名前 期待 rc 引数...
  local name="$1" expected="$2"
  shift 2
  run_target "$@"
  if [ "$last_rc" -eq "$expected" ]; then
    pass "$name (rc=$last_rc)"
  else
    fail "$name: expected rc=$expected, got rc=$last_rc (stderr: $last_stderr)"
  fi
}
expect_json() { # 名前 jq 式
  if printf '%s' "$last_stdout" | jq -e "$2" >/dev/null 2>&1; then
    pass "$1"
  else
    fail "$1: jq expression failed: $2 (stdout: $last_stdout)"
  fi
}
expect_stderr() { # 名前 部分文字列
  case "$last_stderr" in
    *"$2"*) pass "$1" ;;
    *) fail "$1: stderr lacks '$2' (stderr: $last_stderr)" ;;
  esac
}
count_alive() { # pid ファイル
  local pid n=0
  while read -r pid; do
    if kill -0 "$pid" 2>/dev/null; then n=$((n + 1)); fi
  done <"$1"
  echo "$n"
}

# ---- スタブ ----
stubs="$tmp_root/stubs"
mkdir -p "$stubs"
export SB_LOG="$tmp_root/sb"
mkdir -p "$SB_LOG"

mk() { # パス 本文
  printf '#!%s\n%s\n' "$bash_bin" "$2" >"$1"
  chmod 755 "$1"
}

mk "$stubs/hold" '
[ "$1" = "--hold" ] && [ "$2" = "--max-secs" ] && [ -n "$3" ] || exit 2
echo "hold start $3" >>"$SB_LOG/hold.log"
[ "${SB_HOLD_NOREADY:-}" = 1 ] && exit 1
ns="/proc/$$/ns/net"
[ "${SB_HOLD_BADNS:-}" = 1 ] && ns="/proc/$$/ns/net;touch-evil"
printf "{\"schema\":\"fandhe-container.net-hold/v1\",\"event\":\"ready\",\"provisional\":true,\"inner_pid\":%s,\"host_netns\":\"/proc/%s/ns/net\",\"host\":{\"bridge_addr\":\"10.214.0.1\",\"outer_addr\":\"10.214.1.1\"},\"containers\":[{\"id\":\"c1\",\"addr\":\"10.214.0.2\",\"netns\":\"%s\"},{\"id\":\"c2\",\"addr\":\"10.214.0.3\",\"netns\":\"/proc/%s/root/pin2\"}]}\n" "$$" "$$" "$ns" "$$"
read -r line || line=EOF
echo "hold got $line" >>"$SB_LOG/hold.log"
cl=ok
[ "${SB_HOLD_BADCLEAN:-}" = 1 ] && cl=failed
printf "{\"schema\":\"fandhe-container.net-hold/v1\",\"event\":\"released\",\"reason\":\"release\",\"cleanup\":\"%s\",\"provisional\":true}\n" "$cl"
'

mk "$stubs/nsenter" '
case "$1" in --net=*) ;; *) exit 2 ;; esac
[ "$2" = "--" ] || exit 2
echo "nsenter ${1#--net=}" >>"$SB_LOG/nsenter.log"
shift 2
exec "$@"
'

# 呼び出し回数（キーごと）で値を変える: 1000 900 800 1100 1200 の順。own 宛先（10.*）は x1、それ以外は x2。
mk "$stubs/iperf3" '
if [ "$1" = "--version" ]; then echo "iperf 3.16 (cJSON 1.7.15)"; exit 0; fi
if [ "$1" = "-s" ]; then
  echo $$ >>"$SB_LOG/server.pids"
  echo "Server listening on 5201"
  exec sleep 60
fi
[ "$1" = "-c" ] || exit 2
dst="$2"; port="$4"; secs="$6"; par="$8"
echo "iperf-c $dst $port -t $secs -P $par" >>"$SB_LOG/iperf.log"
[ "${SB_IPERF_HANG:-}" = 1 ] && exec sleep 60
key="$SB_LOG/cnt-$dst-$port-$par"
n=$(cat "$key" 2>/dev/null || echo 0); n=$((n + 1)); echo "$n" >"$key"
seq=(1000 900 800 1100 1200)
base=${seq[$(((n - 1) % 5))]}
scale=2; case "$dst" in 10.*) scale=1 ;; esac
echo "{\"end\":{\"sum_received\":{\"bits_per_second\":$((base * par * scale * 1000000))}}}"
'

mk "$stubs/probe" '
if [ "$1" = "--serve" ]; then
  echo $$ >>"$SB_LOG/server.pids"
  printf "{\"tcp_rtt_probe\":\"listening\",\"addr\":\"%s\"}\n" "$2"
  exec sleep 60
fi
[ "$1" = "--client" ] || exit 2
dst="$2"
echo "rtt-client $dst $*" >>"$SB_LOG/rtt.log"
key="$SB_LOG/rcnt-$dst"
n=$(cat "$key" 2>/dev/null || echo 0); n=$((n + 1)); echo "$n" >"$key"
seq=(10 11 12 13 14)
v=${seq[$(((n - 1) % 5))]}
scale=2; case "$dst" in 10.*) scale=1 ;; esac
p50=$((v * scale))
printf "{\"schema\":\"fandhe-container.tcp-rtt/v1\",\"unit\":\"us\",\"target\":\"%s\",\"rounds\":10,\"warmup\":1,\"p50\":%s.500,\"p99\":%s.000,\"min\":1.000,\"max\":9.000,\"mean\":5.000,\"nodelay\":true,\"provisional\":true,\"method\":\"x\"}\n" "$dst" "$p50" "$((p50 * 10))"
'

a64="$(printf 'a%.0s' $(seq 1 64))"
b64="$(printf 'b%.0s' $(seq 1 64))"
n64="$(printf '1%.0s' $(seq 1 64))"
mk "$stubs/docker" '
echo "docker $*" >>"$SB_LOG/docker.log"
case "$1 $2" in
  "image inspect") [ "${SB_DK_NOIMAGE:-}" = 1 ] && exit 1; exit 0 ;;
  "network create") for last; do :; done; echo "$last" >"$SB_LOG/netname"; echo "'"$n64"'"; exit 0 ;;
  "network rm") exit 0 ;;
  "network ls") exit 0 ;;
esac
case "$1" in
  version) echo "27.0.1" ;;
  run)
    while [ $# -gt 0 ]; do
      if [ "$1" = "--cidfile" ]; then cid="$2"; fi
      shift
    done
    if [ ! -e "$SB_LOG/c1.made" ]; then id='"$a64"'; : >"$SB_LOG/c1.made"; else id='"$b64"'; fi
    printf "%s" "$id" >"$cid"; echo "$id" ;;
  inspect)
    nn=$(cat "$SB_LOG/netname"); pid=4243; ip=172.30.0.3
    case "$2" in a*) pid=4242; ip=172.30.0.2 ;; esac
    printf "[{\"State\":{\"Pid\":%s},\"NetworkSettings\":{\"Networks\":{\"%s\":{\"IPAddress\":\"%s\"}}}}]\n" "$pid" "$nn" "$ip" ;;
  rm) exit 0 ;;
  ps) [ "${SB_DK_LEFTOVER:-}" = 1 ] && echo deadbeef0001; exit 0 ;;
  *) exit 0 ;;
esac
'

reset_logs() {
  rm -rf "$SB_LOG"
  mkdir -p "$SB_LOG"
}

common=(--probe "$stubs/probe" --iperf3 "$stubs/iperf3" --nsenter "$stubs/nsenter" --iperf-secs 1 --rtt-rounds 10 --rtt-warmup 1)
own_args=(--exe "$stubs/hold" "${common[@]}")
dk_args=(--docker "$stubs/docker" --host-addr 192.0.2.10)

# ---- 入力エラー（rc=2）----
expect_rc "未知の引数" 2 --bogus
expect_rc "--probe 必須" 2 --exe "$stubs/hold"
expect_rc "--exe 必須（own）" 2 "${common[@]}"
expect_rc "--trials 0" 2 "${own_args[@]}" --trials 0
expect_rc "--iperf-secs 61" 2 "${own_args[@]}" --iperf-secs 61
expect_rc "--rtt-rounds 100001" 2 "${own_args[@]}" --rtt-rounds 100001
expect_rc "--timeout 3601" 2 "${own_args[@]}" --timeout 3601
expect_rc "--label 不正" 2 "${own_args[@]}" --label 'a b'
expect_rc "--target 不正" 2 "${own_args[@]}" --target none
expect_rc "docker 未指定の both" 2 "${own_args[@]}" --target both
expect_rc "--host-addr 必須" 2 "${own_args[@]}" --target both --docker "$stubs/docker"
expect_rc "--host-addr loopback" 2 "${own_args[@]}" --target both --docker "$stubs/docker" --host-addr 127.0.0.1
expect_rc "--host-addr 範囲外" 2 "${own_args[@]}" --target both --docker "$stubs/docker" --host-addr 10.0.0.300
expect_rc "最小所要時間の超過" 2 "${own_args[@]}" --trials 20 --iperf-secs 60 --timeout 100
expect_rc "相対パスの --exe" 2 "${common[@]}" --exe rel_exe
ln -s "$stubs/hold" "$stubs/hold_link"
expect_rc "symlink の --exe" 2 "${common[@]}" --exe "$stubs/hold_link"
cp "$stubs/probe" "$stubs/probe_w"
chmod 775 "$stubs/probe_w"
expect_rc "group 書き込み可の --probe" 2 --exe "$stubs/hold" --probe "$stubs/probe_w" --iperf3 "$stubs/iperf3" --nsenter "$stubs/nsenter"
expect_rc "存在しない --iperf3" 2 --exe "$stubs/hold" --probe "$stubs/probe" --iperf3 "$stubs/none" --nsenter "$stubs/nsenter"
mk "$stubs/iperf3_bad" 'echo "iperf 2.1.9"'
expect_rc "iperf 3 系以外" 2 --exe "$stubs/hold" --probe "$stubs/probe" --iperf3 "$stubs/iperf3_bad" --nsenter "$stubs/nsenter"
echo old >"$tmp_root/existing.json"
expect_rc "既存 output は上書きしない" 2 "${own_args[@]}" --output "$tmp_root/existing.json"

# ---- 前提ツール欠如（rc=3）。iperf3 を含まない PATH で実行する ----
toolbin="$tmp_root/toolbin"
mkdir -p "$toolbin"
for t in jq timeout mktemp stat setsid realpath cat chmod mkfifo grep sleep id dirname head tr od rm tail mkdir; do
  src="$(command -v "$t" 2>/dev/null || true)"
  if [ -n "$src" ]; then ln -sf "$src" "$toolbin/$t"; fi
done
last_rc=0
last_stderr="$(PATH="$toolbin" "$bash_bin" "$target_script" --exe "$stubs/hold" --probe "$stubs/probe" 2>&1 >/dev/null)" || last_rc=$?
if [ "$last_rc" -eq 3 ]; then pass "iperf3 が無い (rc=3)"; else fail "iperf3 が無い: rc=$last_rc ($last_stderr)"; fi
expect_stderr "iperf3 欠如のメッセージ" "iperf3"

# ---- 自前のみ: 5 試行の集計値 ----
reset_logs
run_target "${own_args[@]}" --trials 5 --timeout 120 --label selftest
if [ "$last_rc" -eq 0 ]; then pass "own 5 試行 (rc=0)"; else fail "own 5 試行: rc=$last_rc ($last_stderr)"; fi
expect_json "schema・provisional・verdict なし" '.schema == "fandhe-container.net-throughput-rtt/v1" and .provisional == true and .label == "selftest" and (has("verdict") | not) and .order == "own"'
expect_json "単位と params" '.unit == {throughput: "Mbit/s", rtt: "us"} and .params == {trials: 5, iperf_secs: 1, streams: [1, 4], rtt_rounds: 10, rtt_warmup: 1}'
expect_json "own のスループット中央値（1000 900 800 1100 1200 -> 1000、4 本は 4000）" '.results.own.paths | all(.[]; .throughput["1"] == {samples: 5, median: 1000} and .throughput["4"] == {samples: 5, median: 4000})'
expect_json "own の RTT 中央値（p50 12.5 / p99 120）" '.results.own.paths | all(.[]; .rtt.p50 == {samples: 5, median: 12.5} and .rtt.p99 == {samples: 5, median: 120})'
expect_json "docker 節が無い・isolation と method" '(.results | has("docker") | not) and .results.own.isolation == "unshare --net --mount (fresh netns)" and (.results.own.method | contains("PoC-15")) and .results.own.versions.iperf3 == "iperf 3.16 (cJSON 1.7.15)"'
expect_json "絶対パスを出力しない" '(tostring | contains("/tmp") | not)'
if [ ! -e "$SB_LOG/docker.log" ]; then pass "own のみでは docker に触れない"; else fail "own のみで docker が呼ばれた"; fi
if grep -q "^hold got release" "$SB_LOG/hold.log" && grep -q "^hold start 120$" "$SB_LOG/hold.log"; then
  pass "保持入口へ --max-secs と release を渡す"
else
  fail "保持入口のログ不正: $(cat "$SB_LOG/hold.log")"
fi
alive="$(count_alive "$SB_LOG/server.pids")"
if [ "$alive" -eq 0 ]; then pass "サーバーが残らない ($(wc -l <"$SB_LOG/server.pids") 件起動)"; else fail "サーバーが $alive 件残っている"; fi
if grep -q -- "-t 1 -P 4" "$SB_LOG/iperf.log" && grep -q "10.214.1.1 15201" "$SB_LOG/iperf.log" && grep -q "^rtt-client 10.214.1.1:18080 " "$SB_LOG/rtt.log"; then
  pass "(c) は公開ポート宛て"
else
  fail "(c) の宛先不正"
fi

# ---- both: 交互の順・Docker の後始末・比較 ----
reset_logs
both_out="$tmp_root/both.json"
run_target "${own_args[@]}" "${dk_args[@]}" --target both --trials 2 --timeout 120 --output "$both_out"
if [ "$last_rc" -eq 0 ]; then pass "both 2 試行 (rc=0)"; else fail "both: rc=$last_rc ($last_stderr)"; fi
order="$(grep -- '-P 1$' "$SB_LOG/iperf.log" | awk '$2 == "10.214.1.1" {print "own"} $2 == "192.0.2.10" {print "docker"}' | uniq | tr '\n' ' ')"
if [ "$order" = "own docker own docker " ]; then pass "試行ごとに own と docker を交互に計測 ($order)"; else fail "交互の順が不正: '$order'"; fi
if jq -e '.order == "alternate" and .results.own.paths.a.throughput["1"].median == 950 and .results.docker.paths.a.throughput["1"].median == 1900 and .results.docker.isolation == "host netns" and .results.docker.versions.docker == "27.0.1"' "$both_out" >/dev/null; then
  pass "both の集計（2 試行の中央値は平均）"
else
  fail "both の集計不正: $(cat "$both_out")"
fi
dlog="$SB_LOG/docker.log"
if grep -q -- "--pull never" "$dlog" && grep -q -- "--label fandhe.net-throughput.run=" "$dlog" && grep -q "^docker run -d .*-p 192.0.2.10:15201:5201/tcp" "$dlog" &&
  grep -q "^docker rm -f $a64" "$dlog" && grep -q "^docker rm -f $b64" "$dlog" && grep -q "^docker network rm $n64" "$dlog" &&
  ! grep -q "docker pull" "$dlog"; then
  pass "docker: --pull never・ラベル・公開ポート・rm -f・network rm"
else
  fail "docker ログ不正: $(cat "$dlog")"
fi
if grep -q "^nsenter /proc/4243/ns/net" "$SB_LOG/nsenter.log" && grep -q "^nsenter /proc/4242/ns/net" "$SB_LOG/nsenter.log"; then
  pass "docker の netns（State.Pid）へ nsenter"
else
  fail "docker の nsenter ログ不正"
fi

# ---- Docker の異常系 ----
reset_logs
SB_DK_LEFTOVER=1 run_target "${common[@]}" --probe "$stubs/probe" "${dk_args[@]}" --target docker --trials 1 --timeout 60
if [ "$last_rc" -eq 4 ]; then pass "docker の残りは rc=4"; else fail "docker の残り: rc=$last_rc ($last_stderr)"; fi
expect_stderr "残った ID を報告" "deadbeef0001"
reset_logs
SB_DK_NOIMAGE=1 run_target "${common[@]}" "${dk_args[@]}" --target docker --trials 1 --timeout 60
if [ "$last_rc" -eq 1 ] && ! grep -q "^docker run" "$SB_LOG/docker.log"; then pass "イメージ無しは rc=1・pull も run もしない"; else fail "イメージ無し: rc=$last_rc"; fi
expect_stderr "image-missing" "image-missing"

# ---- 保持入口の異常系（rc=1）----
reset_logs
SB_HOLD_BADCLEAN=1 run_target "${own_args[@]}" --trials 1 --timeout 60
if [ "$last_rc" -eq 1 ]; then pass "cleanup が ok でない保持入口は rc=1"; else fail "badclean: rc=$last_rc"; fi
reset_logs
SB_HOLD_BADNS=1 run_target "${own_args[@]}" --trials 1 --timeout 60
if [ "$last_rc" -eq 1 ]; then pass "netns の文字種違反は rc=1"; else fail "badns: rc=$last_rc"; fi
expect_stderr "検証失敗のメッセージ" "failed validation"
reset_logs
SB_HOLD_NOREADY=1 run_target "${own_args[@]}" --trials 1 --timeout 60
if [ "$last_rc" -eq 1 ]; then pass "ready 前に終了する保持入口は rc=1"; else fail "noready: rc=$last_rc"; fi

# ---- 期限: クライアントのハングで全体期限が効き、サーバーと保持入口を回収する ----
reset_logs
SB_IPERF_HANG=1 run_target "${own_args[@]}" --trials 1 --timeout 7
if [ "$last_rc" -eq 1 ]; then pass "クライアントのハングは期限で rc=1"; else fail "hang: rc=$last_rc ($last_stderr)"; fi
alive="$(count_alive "$SB_LOG/server.pids")"
if [ "$alive" -eq 0 ]; then pass "期限後にサーバーが残らない"; else fail "期限後にサーバーが $alive 件残る"; fi
if grep -q "^hold got release" "$SB_LOG/hold.log"; then pass "期限後に保持入口を解放する"; else fail "保持入口が解放されない"; fi

# ---- 比較モード ----
mk_result() { # ファイル side tp1 tp4 p50 p99 [schema]
  jq -n --arg side "$2" --argjson a "$3" --argjson b "$4" --argjson c "$5" --argjson d "$6" --arg sch "${7:-fandhe-container.net-throughput-rtt/v1}" '
    {schema: $sch, provisional: true, label: "fx", params: {trials: 5},
     results: {($side): {paths: (["a", "b", "c"] | map({key: ., value: {
       throughput: {"1": {samples: 5, median: $a}, "4": {samples: 5, median: $b}},
       rtt: {p50: {samples: 5, median: $c}, p99: {samples: 5, median: $d}}}}) | from_entries)}}}' >"$1"
}
mk_result "$tmp_root/o.json" own 900 3600 11 24
mk_result "$tmp_root/d.json" docker 1000 4000 10 20
run_target --mode compare --own-result "$tmp_root/o.json" --docker-result "$tmp_root/d.json"
if [ "$last_rc" -eq 0 ]; then pass "compare (rc=0)"; else fail "compare: rc=$last_rc ($last_stderr)"; fi
expect_json "compare の % と倍率" '.schema == "fandhe-container.net-throughput-rtt-compare/v1" and .paths.a.throughput_pct_of_docker == {"1": 90, "4": 90} and .paths.c.rtt_p50_ratio == 1.1 and .paths.b.rtt_p99_ratio == 1.2 and .params_match == true'
expect_json "compare は暫定値で合否を出さない" '.provisional == true and (has("verdict") | not) and (has("pass") | not)'
run_target --mode compare --own-result "$both_out" --docker-result "$both_out"
if [ "$last_rc" -eq 0 ]; then pass "both の出力を両方に渡せる"; else fail "both compare: rc=$last_rc ($last_stderr)"; fi
expect_json "both の比較（950 / 1900 = 50%・p50 倍率 11 / 21.5 = 0.512）" '.paths.a.throughput_pct_of_docker["1"] == 50 and .paths.a.rtt_p50_ratio == 0.512 and .paths.a.rtt_p99_ratio == 0.5'
ln -s "$tmp_root/o.json" "$tmp_root/o_link.json"
expect_rc "compare: symlink の入力" 2 --mode compare --own-result "$tmp_root/o_link.json" --docker-result "$tmp_root/d.json"
mk_result "$tmp_root/bad_schema.json" own 900 3600 11 24 "other/v1"
expect_rc "compare: schema 違い" 1 --mode compare --own-result "$tmp_root/bad_schema.json" --docker-result "$tmp_root/d.json"
mk_result "$tmp_root/d0.json" docker 0 4000 10 20
expect_rc "compare: docker の中央値が 0" 1 --mode compare --own-result "$tmp_root/o.json" --docker-result "$tmp_root/d0.json"
expect_rc "compare: 入力の欠落" 2 --mode compare --own-result "$tmp_root/o.json"

if [ "$failures" -ne 0 ]; then
  echo "net_throughput_rtt selftest: $failures failure(s)" >&2
  exit 1
fi
echo "net_throughput_rtt selftest: all passed"
