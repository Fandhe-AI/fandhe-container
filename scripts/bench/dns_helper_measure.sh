#!/usr/bin/env bash
# DNS ヘルパーの正答率・レイテンシ・常駐 PSS 計測ラッパー兼集計スクリプト
# （TASK-141.3・#323・NET-5・MS-8）。
#
# 役割: 実機前提テスト `crates/net/tests/dns_helper_privileged.rs` の `--measure` モードを `--exe` で受け取って
# 実行し、1 クエリ 1 行の JSONL（series / trial / warmup / ok / latency_us）を検証したうえで、正答率と
# p50 / p99 レイテンシ（単位 us）を全体・系列ごとに集計する。あわせて、専用 cgroup の `cgroup.procs` から
# DNS ヘルパー本体の PID を取り、`/proc/<pid>/smaps_rollup` の Pss / Rss（単位 kB）を読む。
# TASK-142（担当: 人間）が NET-5 の期待値（正答率 100%・p50 1ms 以下・p99 5ms 以下・常駐 PSS 5MB 以下）や
# PoC-15 / PoC-17 の実測値と比べる入力として使う。実測・比較・合否判定は TASK-142 が行い、本スクリプトは
# 合否判定を出さない。
#
# 呼び出し元: Makefile の `dns-helper-measure` ターゲット（実機前提のため `make ci` には含めない）。自己テストは
# scripts/bench/dns_helper_measure_selftest.sh（`dns-helper-measure-selftest`・CI の bench-regression ジョブ）。
# 本スクリプトは sudo も cargo も呼ばない。root での実行は人間の明示操作:
#   cargo test -p fandhe-container-net --test dns_helper_privileged --no-run   # 実行ファイルのパスを得る
#   sudo make dns-helper-measure EXE=<そのパス>
#
# PID 取得の方式（PoC-15 の不具合の再発防止）:
#   PoC-15 は `sudo dns-helper & DNSPID=$!` で sudo 自身の PID を測り、PSS 1,615kB を不採用にした。PoC-17 は専用
#   cgroup の `cgroup.procs` から実 PID を取る方式に直した（確定値 PSS 530kB）。本スクリプトも同じ方式を必須とする:
#   計測専用ヘルパーは READY より前に自身を本スクリプトが作った専用 cgroup へ参加させ、本スクリプトは
#   `cgroup.procs` の PID が「ちょうど 1 個」であることを確かめ、`/proc/<pid>/exe` が検証済みの複製 exe と一致する
#   ことを主たる証明にする（sudo・unshare・nsenter ではないことの確認）。補助として argv[1] も照合する。
#
# 計測対象の注意（REPAIR-3: 実装済みを装わない）:
#   製品の入口 run_dns_helper_main は、プロセス外から名前を登録する経路が無く NOTIMP 固定のため測れない。計測対象は
#   テストバイナリが DnsHelperServer + RegistryHandler（製品のサーバー本体・応答組み立て）を直接組み立てた
#   計測専用ヘルパーである。系列構成は PoC-15 と同じ（コンテナ netns 2 個 x 登録名 3 個 x N クエリ）。
#
# 使い方:
#   dns_helper_measure.sh --exe <絶対パス> [--queries N] [--warmup W] [--timeout SECS] [--label NAME] [--output FILE]
#   --exe     dns_helper_privileged のテスト実行ファイル（正規化済みの絶対パス・通常ファイル・symlink 不可・所有者は
#             root・実行ユーザー・sudo の呼び出しユーザー〔SUDO_UID〕・group/other 書き込み不可。祖先ディレクトリも
#             同様に検証する〔sticky 付きは root 所有に限り許容〕。検証に使った fd から 0700 の私有ディレクトリへ
#             複製し、複製を実行する〔検証対象と実行対象の同一性を保つ。TOCTOU 対策〕）
#   --queries 系列（コンテナ x 名前）ごとの本計測クエリ数（1〜10000・既定 1000。PoC-15 は 6 系列合計 6,000）
#   --warmup  系列ごとのウォームアップ数（0〜1000・既定 100。集計から除外）
#   --timeout exe 全体の上限秒数（1〜3600・既定 600）
#   --label   出力に記録するラベル（[A-Za-z0-9._-]・64 文字以下）
#   --output  出力先（新規ファイルのみ。既存ファイルは上書きせず失敗）。省略時は stdout
#
# 出力 JSON: schema "fandhe-container.dns-helper-measure/v1"・label・queries_per_series・warmup・isolation・
#   accuracy.{correct,total,ratio,percent}・latency.{unit:"us",samples,p50,p99,min,max,mean}・per_series[]・
#   memory.{unit:"kB",pss_kb,rss_kb,pid_source,cgroup}・method
#
# 終了コード（net_setup_timing.sh と同じ形式。呼び出し元はこの具体値で分岐する）:
#   0: 成功
#   1: 計測失敗（exe の非ゼロ終了・タイムアウト・出力のサイズ超過・出力の検証失敗・cgroup.procs の PID が 1 個でない・
#      /proc/<pid>/exe の不一致・smaps_rollup が読めない・専用 cgroup を後始末できない）
#   2: 入力エラー（引数・exe・output の検証失敗・root でない・cgroup v2 でない）
#   3: 前提ツール欠如（bash・jq・timeout・mktemp・setsid・realpath・readlink・GNU 互換の stat -c 等）
#
# 自己テスト専用: 環境変数 FANDHE_DNS_HELPER_MEASURE_SELFTEST=1 のときだけ、root・cgroup v2 の確認を省略し、
# --cgroup-parent / --proc-root（疑似ディレクトリ）を受け付ける。本番の実行では設定しない。

set -euo pipefail
umask 077

readonly SCHEMA="fandhe-container.dns-helper-measure/v1"
readonly ISOLATION="unshare --net --mount (fresh netns); helper in a dedicated cgroup v2"

usage_error() {
  echo "dns_helper_measure: $1" >&2
  exit 2
}

for tool in jq timeout mktemp stat setsid realpath readlink cat chmod mkdir rmdir sleep rm touch head tr sed wc seq id dirname; do
  command -v "$tool" >/dev/null 2>&1 || {
    echo "dns_helper_measure: required tool not found: $tool" >&2
    exit 3
  }
done
# `timeout --kill-after` と `stat -c`（GNU 互換）を使う。BSD/macOS 版では動かないため先に確認する。
stat -c '%a' -- / >/dev/null 2>&1 || {
  echo "dns_helper_measure: GNU-compatible stat (-c) is required" >&2
  exit 3
}

selftest=0
[ "${FANDHE_DNS_HELPER_MEASURE_SELFTEST:-}" = "1" ] && selftest=1

exe=""
queries=1000
warmup=100
limit=600
label="dns-helper"
output=""
cgroup_parent="/sys/fs/cgroup"
proc_root="/proc"

while [ $# -gt 0 ]; do
  case "$1" in
    --exe | --queries | --warmup | --timeout | --label | --output | --cgroup-parent | --proc-root)
      [ $# -ge 2 ] || usage_error "missing value for $1"
      case "$1" in
        --exe) exe="$2" ;;
        --queries) queries="$2" ;;
        --warmup) warmup="$2" ;;
        --timeout) limit="$2" ;;
        --label) label="$2" ;;
        --output) output="$2" ;;
        --cgroup-parent | --proc-root)
          [ "$selftest" -eq 1 ] || usage_error "$1 is only available in self-test mode"
          if [ "$1" = "--cgroup-parent" ]; then cgroup_parent="$2"; else proc_root="$2"; fi
          ;;
      esac
      shift 2
      ;;
    *) usage_error "unknown argument: $1" ;;
  esac
done

# 数値は桁数も制限してから範囲を比較する（算術評価に不正な文字列を渡さない）。
check_int() { # name value min max
  [[ "$2" =~ ^[0-9]{1,5}$ ]] || usage_error "$1 must be an integer"
  local v=$((10#$2))
  if [ "$v" -lt "$3" ] || [ "$v" -gt "$4" ]; then
    usage_error "$1 must be in $3..$4"
  fi
}
check_int --queries "$queries" 1 10000
check_int --warmup "$warmup" 0 1000
check_int --timeout "$limit" 1 3600
queries=$((10#$queries))
warmup=$((10#$warmup))
limit=$((10#$limit))

[[ "$label" =~ ^[A-Za-z0-9._-]{1,64}$ ]] || usage_error "--label must match [A-Za-z0-9._-]{1,64}"

[ -n "$exe" ] || usage_error "--exe is required"
case "$exe" in /*) ;; *) usage_error "--exe must be an absolute path" ;; esac
[ ! -L "$exe" ] || usage_error "--exe must not be a symlink"
if [ ! -f "$exe" ] || [ ! -x "$exe" ]; then
  usage_error "--exe must be an executable regular file"
fi
# 全パス要素が symlink・`..`・重複スラッシュを含まない正規形であることを要求する。
canon="$(realpath -e -- "$exe" 2>/dev/null)" || usage_error "cannot resolve --exe"
[ "$canon" = "$exe" ] || usage_error "--exe must be a canonical path (no symlink components)"

self_uid="$(id -u)"
# sudo 経由の実行では実効 UID が 0 になり、呼び出しユーザー所有の cargo test バイナリ（と祖先ディレクトリ）が
# 拒否されてしまう。sudo が設定する SUDO_UID（数値のみ・0 以外）を追加の許容所有者として受け付ける。
# SUDO_UID を設定できるのは root の環境を制御できる者だけで、その者は任意の exe を直接実行できるため
# 権限境界は広がらない。
sudo_uid=""
if [[ "${SUDO_UID:-}" =~ ^[1-9][0-9]{0,9}$ ]]; then
  sudo_uid="$SUDO_UID"
fi
owner_allowed() { # uid
  [ "$1" = "0" ] || [ "$1" = "$self_uid" ] || { [ -n "$sudo_uid" ] && [ "$1" = "$sudo_uid" ]; }
}
# 所有者が root・実行ユーザー・sudo の呼び出しユーザーのいずれかで、group/other 書き込み不可であることを検査する。
# 祖先ディレクトリでは sticky（01000）付きかつ root 所有の場合のみ group/other 書き込みを許す（/tmp 等）。
check_owner_perm() { # path allow_sticky_root
  local p="$1" owner mode
  owner="$(stat -c '%u' -- "$p")" || usage_error "cannot stat $p"
  mode="$(stat -c '%a' -- "$p")" || usage_error "cannot stat $p"
  if ! owner_allowed "$owner"; then
    usage_error "$p must be owned by root, the current user or the sudo invoking user"
  fi
  if [ $((8#$mode & 8#022)) -ne 0 ]; then
    if [ "$2" = "yes" ] && [ "$owner" = "0" ] && [ $((8#$mode & 8#1000)) -ne 0 ]; then
      return 0
    fi
    usage_error "$p must not be group/other writable"
  fi
}
check_owner_perm "$exe" no
dir="$(dirname -- "$exe")"
while :; do
  [ -d "$dir" ] && [ ! -L "$dir" ] || usage_error "--exe ancestor is not a plain directory: $dir"
  check_owner_perm "$dir" yes
  [ "$dir" != "/" ] || break
  dir="$(dirname -- "$dir")"
done

if [ -n "$output" ]; then
  if [ -e "$output" ] || [ -L "$output" ]; then
    usage_error "--output already exists; refusing to overwrite"
  fi
fi

# root と cgroup v2 の確認（自己テスト以外）。専用 cgroup の作成と cgroup.procs への参加は root の操作。
if [ "$selftest" -ne 1 ]; then
  [ "$self_uid" = "0" ] || usage_error "must run as root (euid 0); see AGENTS.md"
  [ -f "$cgroup_parent/cgroup.controllers" ] || usage_error "cgroup v2 is required ($cgroup_parent/cgroup.controllers not found)"
fi
[ -d "$cgroup_parent" ] || usage_error "cgroup parent is not a directory"
[ -d "$proc_root" ] || usage_error "proc root is not a directory"

work="$(mktemp -d)"
raw="${work}/raw.jsonl"
run_exe="${work}/exe"
sync_dir="${work}/sync"
cgdir=""
pgid=""
cg_leak=0

# exe が起動した子孫（unshare・inner・ヘルパー・クライアント）を新セッションのプロセスグループごと終了して回収する。
# namespace は所属プロセスの終了で解放される。timeout・中断（INT/TERM）・通常終了のいずれでも呼ぶ。
kill_group() {
  if [ -n "$pgid" ]; then
    kill -KILL -- "-$pgid" 2>/dev/null || true
    wait "$pgid" 2>/dev/null || true
    pgid=""
  fi
}

# 専用 cgroup を空にして削除する。残存プロセスは cgroup.kill（カーネル 5.14 以降）で終了させる。
# 後始末できなかった場合は警告して cg_leak=1 を立てる（呼び出し側が失敗として扱う）。
cgroup_cleanup() {
  [ -n "$cgdir" ] || return 0
  if [ -d "$cgdir" ]; then
    local i
    for i in $(seq 1 50); do
      [ -z "$(timeout 5 cat -- "$cgdir/cgroup.procs" 2>/dev/null || true)" ] && break
      if [ "$i" -eq 5 ] && [ -e "$cgdir/cgroup.kill" ]; then
        printf '1' >"$cgdir/cgroup.kill" 2>/dev/null || true
      fi
      sleep 0.1
    done
    # 疑似 cgroup（自己テスト）は通常ファイルを含むため、rmdir の前に消す。
    if [ "$selftest" -eq 1 ]; then
      rm -f -- "$cgdir/cgroup.procs" "$cgdir/cgroup.kill"
    fi
    if ! rmdir -- "$cgdir" 2>/dev/null; then
      echo "dns_helper_measure: WARNING: could not remove cgroup $cgdir" >&2
      cg_leak=1
    fi
  fi
  cgdir=""
}

cleanup() {
  kill_group
  cgroup_cleanup
  rm -rf "$work"
}
trap cleanup EXIT
trap 'cleanup; exit 130' INT
trap 'cleanup; exit 143' TERM

# 検証した fd から複製して複製を実行する（検証後の差し替え対策。TOCTOU 回避）。
exec 3<"$exe" || usage_error "cannot open --exe"
fd_owner="$(stat -L -c '%u' -- /proc/self/fd/3 2>/dev/null || stat -L -c '%u' -- "$exe")"
fd_mode="$(stat -L -c '%a' -- /proc/self/fd/3 2>/dev/null || stat -L -c '%a' -- "$exe")"
if ! owner_allowed "$fd_owner" || [ $((8#$fd_mode & 8#022)) -ne 0 ]; then
  usage_error "--exe changed or has unsafe owner/permissions"
fi
cat <&3 >"$run_exe" || usage_error "cannot copy --exe"
exec 3<&-
chmod 700 "$run_exe"
mkdir -m 700 -- "$sync_dir"

# 専用 cgroup はスクリプトが名前を生成し、既存のものは再利用しない（利用者入力から作らない）。
cg_name="fandhe-dns-measure-$$-${RANDOM}"
cgdir="${cgroup_parent}/${cg_name}"
if [ -e "$cgdir" ]; then
  cgdir=""
  echo "dns_helper_measure: cgroup already exists; refusing to reuse" >&2
  exit 1
fi
if ! mkdir -- "$cgdir" 2>/dev/null; then
  cgdir=""
  echo "dns_helper_measure: cannot create cgroup" >&2
  exit 1
fi
# 自己テストでは疑似 cgroup に cgroup.procs を用意する（実 cgroup はカーネルが作る）。
if [ "$selftest" -eq 1 ]; then
  : >"$cgdir/cgroup.procs"
fi

# stdout（JSONL 専用）の上限。(10000+1000)*6 行 × 約 100B ≒ 6.6MB に対し十分大きい 16MiB。超過書き込みは
# ulimit -f（1024B 単位）で拒否し、集計（jq）の前に失敗させる。診断は stderr へ出る。
readonly OUT_LIMIT_KIB=16384
readonly OUT_LIMIT_BYTES=$((OUT_LIMIT_KIB * 1024))

# exe 全体に上限を設ける（REPAIR-5）。新セッション（setsid）で起動し、グループ全体を制御する。
(
  ulimit -f "$OUT_LIMIT_KIB"
  # --foreground: GNU timeout は既定で子を新しいプロセスグループへ移し、INT/TERM 時の kill_group（-pgid 宛て）
  # が timeout 自身にしか届かず unshare 以下の子孫が残る。--foreground で子を setsid のグループに留める。
  exec setsid timeout --foreground --kill-after=10 "$limit" "$run_exe" --measure \
    --queries "$queries" --warmup "$warmup" --cgroup "$cgdir" --sync-dir "$sync_dir" >"$raw"
) &
pgid=$!

fail() {
  echo "dns_helper_measure: $1" >&2
  exit 1
}

# 全クエリ後のアイドル時に exe が pss-ready を作るまで待つ（期限つき。exe が先に終了したら失敗）。
ready=0
start_s=$SECONDS
while [ $((SECONDS - start_s)) -le "$limit" ]; do
  if [ -e "$sync_dir/pss-ready" ]; then
    ready=1
    break
  fi
  if ! kill -0 "$pgid" 2>/dev/null; then
    break
  fi
  sleep 0.1
done

# メモリ計測（pss-ready 後のみ）。失敗は理由を mem_err に残し、exe を解放してから失敗として終了する。
mem_err=""
pss_kb=""
rss_kb=""
read_smaps_kb() { # file key -> echo value (kB)
  local content k v rest
  content="$(timeout 5 cat -- "$1" 2>/dev/null)" || return 1
  while read -r k v rest; do
    if [ "$k" = "$2:" ]; then
      [[ "$v" =~ ^[0-9]{1,12}$ ]] || return 1
      [ "$((10#$v))" -gt 0 ] || return 1
      echo "$((10#$v))"
      return 0
    fi
  done <<<"$content"
  return 1
}
if [ "$ready" -eq 1 ]; then
  procs="$(timeout 5 cat -- "$cgdir/cgroup.procs" 2>/dev/null || true)"
  if [ -z "$procs" ]; then
    mem_err="cgroup.procs is empty (the helper did not join the dedicated cgroup)"
  elif [ "$(printf '%s\n' "$procs" | wc -l)" -ne 1 ]; then
    mem_err="cgroup.procs does not contain exactly one pid"
  elif ! [[ "$procs" =~ ^[1-9][0-9]{0,9}$ ]]; then
    mem_err="cgroup.procs contains an invalid pid"
  else
    hpid="$procs"
    exe_link="$(readlink -- "$proc_root/$hpid/exe" 2>/dev/null || true)"
    if [ "$exe_link" != "$run_exe" ]; then
      mem_err="pid in cgroup.procs is not the measured executable (/proc/<pid>/exe mismatch; sudo-pid guard)"
    else
      # 補助照合: argv[1] が計測専用ヘルパーのモードであること。cmdline の中身は出力しない。
      argv1="$(timeout 5 head -c 4096 -- "$proc_root/$hpid/cmdline" 2>/dev/null | tr '\0' '\n' | sed -n 2p || true)"
      if [ "$argv1" != "--dns-measure-helper" ]; then
        mem_err="pid in cgroup.procs is not running in --dns-measure-helper mode"
      elif ! pss_kb="$(read_smaps_kb "$proc_root/$hpid/smaps_rollup" Pss)"; then
        mem_err="cannot read a valid Pss from smaps_rollup"
      elif ! rss_kb="$(read_smaps_kb "$proc_root/$hpid/smaps_rollup" Rss)"; then
        mem_err="cannot read a valid Rss from smaps_rollup"
      fi
    fi
  fi
fi

# exe に PSS 読み取りの完了を伝え（失敗時もヘルパーを解放するため常に伝える）、終了を待つ。
touch "$sync_dir/pss-done"
rc=0
wait "$pgid" || rc=$?
# 正常終了後も残った子孫があれば回収する。
kill_group
cgroup_cleanup

if [ "$ready" -ne 1 ]; then
  echo "dns_helper_measure: measurement failed before the idle sync point (exit $rc)" >&2
  exit 1
fi
if [ -n "$mem_err" ]; then
  fail "memory measurement failed: $mem_err"
fi
if [ "$rc" -ne 0 ]; then
  fail "measurement failed (exit $rc)"
fi
if [ "$cg_leak" -ne 0 ]; then
  fail "dedicated cgroup could not be removed"
fi
raw_size="$(stat -c '%s' -- "$raw")" || fail "cannot stat measurement output"
if [ "$raw_size" -ge "$OUT_LIMIT_BYTES" ]; then
  fail "measurement output too large (limit ${OUT_LIMIT_BYTES} bytes)"
fi

# 全行をスキーマ検証する。壊れた計測値は集計せず失敗にする。ok:false（誤答・無応答）は正答率に反映するだけで
# 失敗扱いにしない（正答率 100% の判定は TASK-142）。
expected=$((6 * (queries + warmup)))
validate='
  def series: ["c1/svc-a","c1/svc-b","c1/svc-c","c2/svc-a","c2/svc-b","c2/svc-c"];
  length == $expected
  and all(.[];
    type == "object"
    and (keys | sort) == ["latency_us","ok","series","trial","warmup"]
    and (.series | IN(series[]))
    and (.trial | type == "number" and . == floor and . >= 0)
    and (.warmup | type == "boolean")
    and (.ok | type == "boolean")
    and (.latency_us == null or (.latency_us | type == "number" and . >= 0))
    and (.ok == false or .latency_us != null))
  and (. as $rows
       | all(series[];
             . as $s
             | ([$rows[] | select(.series == $s and .warmup == true) | .trial] | sort) == [range(0; $warmup)]
               and ([$rows[] | select(.series == $s and .warmup == false) | .trial] | sort) == [range(0; $queries)]))
'
if ! jq -s -e --argjson expected "$expected" --argjson queries "$queries" --argjson warmup "$warmup" \
  "$validate" "$raw" >/dev/null 2>&1; then
  fail "measurement output failed validation"
fi

method="measured target is the test binary assembling DnsHelperServer + RegistryHandler (product server body and response builder), NOT the product entry run_dns_helper_main (NOTIMP-only until an out-of-process registration path exists; REPAIR-3); series layout matches PoC-15 (2 container netns x 3 names x N queries); latency is send-to-matching-reply per query over replies received (ok or not), p50/p99 use nearest-rank on the sorted samples; accuracy counts replies matching ID, QR=1, RCODE=0, ANCOUNT=1, TYPE=A and the expected address over all non-warmup queries (no reply counts as incorrect); PSS/RSS are read once after all queries while the helper is idle, from smaps_rollup of the single pid in the dedicated cgroup.procs; no pass/fail judgement (TASK-142)"

result="$(jq -s -S \
  --arg schema "$SCHEMA" --arg label "$label" --arg isolation "$ISOLATION" --arg method "$method" \
  --argjson queries "$queries" --argjson warmup "$warmup" \
  --argjson pss "$pss_kb" --argjson rss "$rss_kb" --arg cgroup "$cg_name" '
  def r3: (. * 1000 | round) / 1000;
  def stats:
    if length == 0 then null else
      sort as $s | ($s | length) as $n
      | {
          samples: $n,
          p50: ($s[(($n + 1) / 2 | floor) - 1] | r3),
          p99: ($s[(($n * 99 + 99) / 100 | floor) - 1] | r3),
          min: ($s[0] | r3),
          max: ($s[$n - 1] | r3),
          mean: ((add / $n) | r3)
        }
    end;
  def acc:
    (map(select(.ok)) | length) as $c | length as $t
    | { correct: $c, total: $t,
        ratio: (if $t == 0 then null else (($c / $t * 1000000 | round) / 1000000) end),
        percent: (if $t == 0 then null else ($c * 100 / $t | r3) end) };
  def lat: [.[] | select(.latency_us != null) | .latency_us] | stats;
  [.[] | select(.warmup | not)] as $m
  | {
      schema: $schema,
      label: $label,
      queries_per_series: $queries,
      warmup: $warmup,
      isolation: $isolation,
      accuracy: ($m | acc),
      latency: (($m | lat) + {unit: "us"}),
      per_series: ([$m | group_by(.series)[] | { series: .[0].series, accuracy: acc, latency: (lat + {unit: "us"}) }]),
      memory: { unit: "kB", pss_kb: $pss, rss_kb: $rss, pid_source: "cgroup.procs", cgroup: $cgroup },
      method: $method
    }' "$raw")"

if [ -n "$output" ]; then
  # noclobber で競合時も上書きしない。
  (
    set -C
    printf '%s\n' "$result" >"$output"
  ) || usage_error "cannot create --output"
else
  printf '%s\n' "$result"
fi
