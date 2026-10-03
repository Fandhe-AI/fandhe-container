#!/usr/bin/env bash
# ネットワーク作成・コンテナ接続・ネットワーク削除の所要時間計測ラッパー兼集計スクリプト
# （TASK-139.5・NET-1・NET-4・MS-8）。
#
# 役割: 実機前提テスト `crates/net/tests/network_paths_privileged.rs` の `--measure` モードを
# `--exe` で受け取って実行し、1 操作 1 行の JSONL（trial / warmup / op / elapsed_ms / ok）を
# 検証したうえで、ウォームアップを除いた試行の中央値・最小・最大・p90・平均を操作ごとに集計して
# 1 つの JSON（単位 ms）で出力する。TASK-140（担当: 人間）が PoC-15 の実測値
# （作成 17.0ms・接続 39.5ms・削除 50.5ms。NET-4）や Docker と比べる入力として使う。
# 実測・比較・合否判定は TASK-140 が行う。本スクリプトは合否判定を出さない。
#
# 呼び出し元: Makefile の `net-setup-timing` ターゲット（実機前提のため `make ci` には含めない）。
# 自己テストは scripts/bench/net_setup_timing_selftest.sh（`net-setup-timing-selftest`・CI の
# bench-regression ジョブ）。本スクリプトは sudo も cargo も呼ばない。root での実行は人間の明示操作:
#   cargo test -p fandhe-container-net --test network_paths_privileged --no-run   # 実行ファイルのパスを得る
#   sudo make net-setup-timing EXE=<そのパス>
#
# 計測区間と PoC-15 との差（REPAIR-3: 実装済みを装わない。比較時に読み違えないこと）:
#   - net_create: create_network の呼び出し全体（bridge 作成・gateway 付与・up・専用 nft テーブル作成）。
#     PoC-15 (i) は DNS ヘルパーの起動を含むが、本計測は含まない（DNS ヘルパーは TASK-141 で未実装）。
#   - container_attach: attach_container（ポート公開なし）の呼び出し全体。netns の作成・pin、veth 作成・
#     bridge 接続・peer の netns 移動、静的 IPAM、netns 内のアドレス・default route 設定を含み、到達確認
#     （ping 等）は含まない。PoC-15 (ii) は「veth 作成から ping 到達まで」で netns 作成を含まない。
#   - net_delete: delete_network の呼び出し全体（veth 削除・netns unpin・nft テーブル・bridge 削除）。
#   - 環境: host netns ではなく `unshare --net --mount` の新規の隔離 netns で計測する。
#
# 使い方:
#   net_setup_timing.sh --exe <絶対パス> [--trials N] [--warmup W] [--timeout SECS] [--label NAME] [--output FILE]
#   --exe     network_paths_privileged のテスト実行ファイル（絶対パス・通常ファイル・symlink 不可・
#             group/other 書き込み不可。root で実行するため、他者が差し替え得るバイナリを拒否する）
#   --trials  計測試行数（1〜200・既定 20。PoC-15 と同じ）
#   --warmup  ウォームアップ試行数（0〜20・既定 1。集計から除外）
#   --timeout exe 全体の上限秒数（1〜3600・既定 600）
#   --label   出力に記録するラベル（[A-Za-z0-9._-]・64 文字以下）
#   --output  出力先（新規ファイルのみ。既存ファイルは上書きせず失敗）。省略時は stdout
#
# 出力 JSON: schema "fandhe-container.net-setup-timing/v1"・unit "ms"・label・trials・warmup・isolation・
#   metrics.{net_create,container_attach,net_delete}.{samples,median,min,max,p90,mean}・method
#
# 終了コード（startup_latency.sh と同じ形式。呼び出し元はこの具体値で分岐する）:
#   0: 成功
#   1: 計測失敗（exe の非ゼロ終了・タイムアウト・出力の検証失敗〔不正 JSON・ok:false・件数不足・未知の op〕）
#   2: 入力エラー（引数・exe・output の検証失敗）
#   3: 前提ツール欠如（bash・jq・timeout・mktemp・GNU 互換の stat -c）

set -euo pipefail
umask 077

readonly SCHEMA="fandhe-container.net-setup-timing/v1"
readonly ISOLATION="unshare --net --mount (fresh netns)"

usage_error() {
  echo "net_setup_timing: $1" >&2
  exit 2
}

for tool in jq timeout mktemp stat; do
  command -v "$tool" >/dev/null 2>&1 || {
    echo "net_setup_timing: required tool not found: $tool" >&2
    exit 3
  }
done
# `timeout --kill-after` と `stat -c`（GNU 互換）を使う。BSD/macOS 版では動かないため先に確認する。
stat -c '%a' -- / >/dev/null 2>&1 || {
  echo "net_setup_timing: GNU-compatible stat (-c) is required" >&2
  exit 3
}

exe=""
trials=20
warmup=1
limit=600
label="net-setup"
output=""

while [ $# -gt 0 ]; do
  case "$1" in
    --exe | --trials | --warmup | --timeout | --label | --output)
      [ $# -ge 2 ] || usage_error "missing value for $1"
      case "$1" in
        --exe) exe="$2" ;;
        --trials) trials="$2" ;;
        --warmup) warmup="$2" ;;
        --timeout) limit="$2" ;;
        --label) label="$2" ;;
        --output) output="$2" ;;
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
check_int --trials "$trials" 1 200
check_int --warmup "$warmup" 0 20
check_int --timeout "$limit" 1 3600
trials=$((10#$trials))
warmup=$((10#$warmup))
limit=$((10#$limit))

[[ "$label" =~ ^[A-Za-z0-9._-]{1,64}$ ]] || usage_error "--label must match [A-Za-z0-9._-]{1,64}"

[ -n "$exe" ] || usage_error "--exe is required"
case "$exe" in /*) ;; *) usage_error "--exe must be an absolute path" ;; esac
[ ! -L "$exe" ] || usage_error "--exe must not be a symlink"
if [ ! -f "$exe" ] || [ ! -x "$exe" ]; then
  usage_error "--exe must be an executable regular file"
fi
perm="$(stat -c '%a' -- "$exe")" || usage_error "cannot stat --exe"
# group/other の書き込みビット（020・002）を検査する。
if [ $((8#$perm & 8#022)) -ne 0 ]; then
  usage_error "--exe must not be group/other writable"
fi

if [ -n "$output" ]; then
  if [ -e "$output" ] || [ -L "$output" ]; then
    usage_error "--output already exists; refusing to overwrite"
  fi
fi

raw="$(mktemp)"
trap 'rm -f "$raw"' EXIT

# exe 全体に上限を設ける（REPAIR-5）。stdout は JSONL 専用、診断は stderr へ出る。
rc=0
timeout --kill-after=10 "$limit" "$exe" --measure --trials "$trials" --warmup "$warmup" >"$raw" || rc=$?
if [ "$rc" -ne 0 ]; then
  echo "net_setup_timing: measurement failed (exit $rc)" >&2
  exit 1
fi

# 全行をスキーマ検証する。壊れた計測値は集計せず失敗にする。
expected=$(((trials + warmup) * 3))
validate='
  length == $expected
  and all(.[];
    type == "object"
    and (keys | sort) == ["elapsed_ms","ok","op","trial","warmup"]
    and (.trial | type == "number" and . == floor and . >= 0)
    and (.warmup | type == "boolean")
    and (.op | IN("net_create","container_attach","net_delete"))
    and (.elapsed_ms | type == "number" and . >= 0)
    and .ok == true)
  and ([.[] | select(.warmup | not)] | length == $trials * 3)
  and ([.[] | select(.warmup)] | length == $warmup * 3)
  and ([.[] | select(.warmup | not)] | group_by(.trial)
       | length == $trials and all(.[]; (map(.op) | sort) == ["container_attach","net_create","net_delete"]))
'
if ! jq -s -e --argjson expected "$expected" --argjson trials "$trials" --argjson warmup "$warmup" \
  "$validate" "$raw" >/dev/null 2>&1; then
  echo "net_setup_timing: measurement output failed validation" >&2
  exit 1
fi

method_create="create_network call only; excludes DNS helper startup (PoC-15 (i) includes it; DNS helper is TASK-141, unimplemented)"
method_attach="attach_container call only (no port publish); includes netns create/pin, veth, IPAM, in-netns address and default route; excludes reachability check (PoC-15 (ii) is veth creation to ping reachability and excludes netns creation)"
method_delete="delete_network call only (veth, netns unpin, nft table, bridge)"

result="$(jq -s -S \
  --arg schema "$SCHEMA" --arg label "$label" --arg isolation "$ISOLATION" \
  --argjson trials "$trials" --argjson warmup "$warmup" \
  --arg mc "$method_create" --arg ma "$method_attach" --arg md "$method_delete" '
  def r3: (. * 1000 | round) / 1000;
  def stats:
    sort as $s | ($s | length) as $n
    | {
        samples: $n,
        median: (if $n % 2 == 1 then $s[($n - 1) / 2] else ($s[$n / 2 - 1] + $s[$n / 2]) / 2 end | r3),
        min: ($s[0] | r3),
        max: ($s[$n - 1] | r3),
        p90: ($s[(($n * 9 + 9) / 10 | floor) - 1] | r3),
        mean: ((add / $n) | r3)
      };
  . as $rows
  | def op($name): [$rows[] | select((.warmup | not) and .op == $name) | .elapsed_ms] | stats;
  {
    schema: $schema,
    unit: "ms",
    label: $label,
    trials: $trials,
    warmup: $warmup,
    isolation: $isolation,
    metrics: {
      net_create: op("net_create"),
      container_attach: op("container_attach"),
      net_delete: op("net_delete")
    },
    method: { net_create: $mc, container_attach: $ma, net_delete: $md }
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
