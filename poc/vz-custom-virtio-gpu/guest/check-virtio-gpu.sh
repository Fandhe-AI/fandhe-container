#!/usr/bin/env bash
# ゲスト（Linux）内の dmesg から virtio-gpu の probe 結果を判定する確認スクリプト
# （TASK-172.6・GPU-6・MAC-5・#1056）。
#
# 役割: macOS 27 の VZCustomVirtioDevice で登録した最小 virtio-gpu（VENUS capset のみ・
# scanout なし・F_VIRGL / F_CONTEXT_INIT / F_RESOURCE_BLOB・host visible 共有メモリ）を
# ゲストが受理したかを、ゲストのカーネルログで確認する。結果は #1057（TASK-172.h5。
# 人間担当）の VMM 方式判定に使う。ホスト側の登録コードは承認待ちで未実装（REPAIR-3）。
#
# 入力は信頼しないデータとして扱う: 固定パターンの grep のみで照合し、eval・source・
# コマンド置換へ展開しない。入力サイズは読み込み前に上限で切る。vulkaninfo は起動せず
# ファイル入力のみ（無限待ちを作らない）。
#
# 使い方: check-virtio-gpu.sh [--dmesg-file PATH] [--vulkaninfo-file PATH]
#   --dmesg-file 省略時は dmesg を実行する（root が必要な場合はゲスト内で人間が実行）
# 出力: 英語の key=value 行。終了コード 0 = 必須項目がすべて期待どおり、
#   1 = 期待外れの項目あり、2 = 入力・引数エラー
set -euo pipefail
export LC_ALL=C

readonly MAX_INPUT_BYTES=$((16 * 1024 * 1024))

usage() {
  echo "usage: check-virtio-gpu.sh [--dmesg-file PATH] [--vulkaninfo-file PATH]" >&2
}

dmesg_file=""
vk_file=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --dmesg-file)
      [ "$#" -ge 2 ] || { usage; exit 2; }
      dmesg_file="$2"
      shift 2
      ;;
    --vulkaninfo-file)
      [ "$#" -ge 2 ] || { usage; exit 2; }
      vk_file="$2"
      shift 2
      ;;
    *)
      echo "error: unknown argument" >&2
      usage
      exit 2
      ;;
  esac
done

tmp="$(mktemp)"
tmpvk="$(mktemp)"
trap 'rm -f "$tmp" "$tmpvk"' EXIT

# 入力を一時ファイルへ取り込む。読み込み前にサイズを検査する。
load_limited() { # $1=src $2=dest
  local src="$1" dest="$2" size
  if [ ! -f "$src" ] || [ ! -r "$src" ]; then
    echo "error: input file not readable" >&2
    exit 2
  fi
  size="$(wc -c <"$src")"
  if [ "$size" -gt "$MAX_INPUT_BYTES" ]; then
    echo "error: input exceeds size limit" >&2
    exit 2
  fi
  cat -- "$src" >"$dest"
}

if [ -n "$dmesg_file" ]; then
  load_limited "$dmesg_file" "$tmp"
else
  dmesg 2>/dev/null | head -c "$((MAX_INPUT_BYTES + 1))" >"$tmp" || true
  if [ "$(wc -c <"$tmp")" -gt "$MAX_INPUT_BYTES" ]; then
    echo "error: input exceeds size limit" >&2
    exit 2
  fi
fi
if [ -n "$vk_file" ]; then
  load_limited "$vk_file" "$tmpvk"
fi

rc=0
fail() { rc=1; }

# features 行（例: virtio_gpu virtio0: features: +virgl -edid +resource_blob +host_visible）
# context_init は別行（features: +context_init）に出る。両行を結合して照合する。
feats="$(grep -E 'virtio.?gpu.*features: ' "$tmp" || true)"

if [ -n "$feats" ]; then
  echo "probe=ok"
else
  echo "probe=missing"
  fail
fi

# 1 つの feature トークンが features 行で +（有効）/ -（無効）/ 不在のどれかを出力し、
# 期待（+ は有効必須、- は有効だと不可）と照合する。
feature() { # $1=name $2=expect
  local name="$1" expect="$2" got="unknown"
  if printf '%s\n' "$feats" | grep -qE "[ :]\\+$name( |\$)"; then
    got="enabled"
  elif printf '%s\n' "$feats" | grep -qE "[ :]-$name( |\$)"; then
    got="disabled"
  fi
  echo "$name=$got"
  if [ "$expect" = "+" ] && [ "$got" != "enabled" ]; then fail; fi
  if [ "$expect" = "-" ] && [ "$got" = "enabled" ]; then fail; fi
}
feature virgl +
feature resource_blob +
feature context_init +
feature host_visible +
feature edid -

if grep -qE 'num_scanouts is zero' "$tmp"; then
  echo "kms=probe_failed_zero_scanouts"
  fail
elif grep -qE 'KMS disabled|number of scanouts: 0$' "$tmp"; then
  echo "kms=disabled"
elif grep -qE 'number of scanouts: [0-9]+' "$tmp"; then
  echo "kms=scanouts_present"
  fail
else
  echo "kms=unknown"
  fail
fi

cs="$(grep -oE 'number of cap sets: [0-9]+' "$tmp" | head -n 1 || true)"
if [ -n "$cs" ]; then
  echo "capset_count=${cs##*: }"
  [ "${cs##*: }" = "1" ] || fail
else
  echo "capset_count=unknown"
  fail
fi

if grep -qE 'timed out waiting for cap set' "$tmp"; then
  echo "capset_info=timeout"
  fail
else
  ci="$(grep -E 'cap set [0-9]+: id 4, max-version [0-9]+, max-size [0-9]+' "$tmp" | head -n 1 || true)"
  if [ -n "$ci" ]; then
    ver="$(printf '%s' "$ci" | sed -E 's/.*max-version ([0-9]+).*/\1/')"
    sz="$(printf '%s' "$ci" | sed -E 's/.*max-size ([0-9]+).*/\1/')"
    echo "capset_info=venus"
    echo "capset_max_version=$ver"
    echo "capset_max_size=$sz"
    # max-size 0 は PoC-14 の既知の失敗形（Mesa が物理デバイス 0 件と判定）。
    [ "$sz" = "160" ] || fail
  else
    echo "capset_info=missing"
    fail
  fi
fi

hm="$(grep -oE 'Host memory window: 0x[0-9a-fA-F]+ \+0x[0-9a-fA-F]+' "$tmp" | head -n 1 || true)"
if [ -n "$hm" ]; then
  echo "host_memory_window=present"
  echo "host_memory_window_size=${hm##*+}"
else
  echo "host_memory_window=missing"
  fail
fi

# venus 初期化（任意）。vulkaninfo --summary の出力に venus ドライバがあるか。
if [ -n "$vk_file" ]; then
  if grep -qiE 'venus' "$tmpvk"; then
    echo "venus_init=ok"
  else
    echo "venus_init=missing"
    fail
  fi
else
  echo "venus_init=not_checked"
fi

exit "$rc"
