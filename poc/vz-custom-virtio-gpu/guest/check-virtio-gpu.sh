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
  # 検査と取り込みの間に入力が増えても上限を超えないよう、最大 MAX_INPUT_BYTES+1 バイトだけ
  # 取り込み、取り込んだ実サイズで超過を判定する（TOCTOU 回避）。
  head -c "$((MAX_INPUT_BYTES + 1))" -- "$src" >"$dest" || {
    echo "error: failed to read input" >&2
    exit 2
  }
  size="$(wc -c <"$dest")"
  if [ "$size" -gt "$MAX_INPUT_BYTES" ]; then
    echo "error: input exceeds size limit" >&2
    exit 2
  fi
}

if [ -n "$dmesg_file" ]; then
  load_limited "$dmesg_file" "$tmp"
else
  # 取得失敗（権限不足・dmesg 不在）は入力エラーとして終了コード 2 で返す。上限超過による
  # head の早期終了（dmesg 側の SIGPIPE = 141）だけは意図的な打ち切りとして区別する。
  set +e
  dmesg 2>/dev/null | head -c "$((MAX_INPUT_BYTES + 1))" >"$tmp"
  dmesg_status=("${PIPESTATUS[@]}")
  set -e
  if [ "$(wc -c <"$tmp")" -gt "$MAX_INPUT_BYTES" ]; then
    echo "error: input exceeds size limit" >&2
    exit 2
  fi
  if [ "${dmesg_status[0]}" -ne 0 ] || [ "${dmesg_status[1]}" -ne 0 ]; then
    echo "error: failed to read dmesg" >&2
    exit 2
  fi
fi
if [ -n "$vk_file" ]; then
  load_limited "$vk_file" "$tmpvk"
fi

rc=0
fail() { rc=1; }

# 複数の virtio-gpu が混在すると別デバイスの行を組み合わせて合否が決まるため、デバイス
# 識別子（virtioN）単位に限定する。デバイスが複数、または probe 区間が複数（再 probe・
# 接頭辞なしの [drm] 行が別デバイス由来の可能性）ある場合は帰属を決められないので
# fail-closed で打ち切る。
# 実カーネルの DRM_INFO 系ログ（Host memory window・num_scanouts is zero・KMS disabled・
# capset timeout 等）は "virtio_gpu virtioN:" ではなく "[drm]" 接頭辞だけで出るため、
# 単一デバイス時は当該デバイス接頭辞の行に加えて "[drm]" 行も判定対象に残す。
# probe 失敗行はデバイス接頭辞の有無に関わらず（例: "virtio_gpu: probe of virtio0 failed with
# error -12"）下のデバイス単位フィルタで落ちるため、フィルタ前の全文で検出して拒否する。
# 後続に失敗行がある限り、先行する features / capset 行があっても成功にしない。
probe_failed=0
if grep -qiE 'virtio.?gpu.*(probe .*failed|failed to (initialize|probe)|initialization failed)' "$tmp"; then
  probe_failed=1
fi
devs="$(grep -oE 'virtio.?gpu virtio[0-9]+:' "$tmp" | grep -oE 'virtio[0-9]+' | sort -u || true)"
dev_count="$(printf '%s' "$devs" | grep -c . || true)"
if [ "$dev_count" -gt 1 ]; then
  echo "probe=multiple_devices"
  exit 1
elif [ "$dev_count" -eq 1 ]; then
  tmpdev="$(mktemp)"
  trap 'rm -f "$tmp" "$tmpvk" "$tmpdev"' EXIT
  grep -E "virtio.?gpu ${devs}:|\[drm\]" "$tmp" >"$tmpdev" || true
  mv -f -- "$tmpdev" "$tmp"
fi
sections="$(grep -c 'number of cap sets: ' "$tmp" || true)"
if [ "$sections" -gt 1 ]; then
  echo "probe=multiple_sections"
  exit 1
fi

# features 行（例: virtio_gpu virtio0: features: +virgl -edid +resource_blob +host_visible）
# context_init は別行（features: +context_init）に出る。両行を結合して照合する。
feats="$(grep -E '(virtio.?gpu|\[drm\]).*features: ' "$tmp" || true)"

if [ "$probe_failed" -eq 1 ]; then
  echo "probe=failed"
  fail
elif [ -n "$feats" ]; then
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
elif grep -qE 'number of scanouts: [1-9][0-9]*' "$tmp"; then
  # 非ゼロ scanout の記録は KMS disabled 等と併存しても矛盾として先に拒否する。
  echo "kms=scanouts_present"
  fail
elif grep -qE 'KMS disabled|number of scanouts: 0$' "$tmp"; then
  echo "kms=disabled"
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
    [ "$ver" = "0" ] || fail
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
  hm_size="${hm##*+}"
  echo "host_memory_window_size=$hm_size"
  # サイズ 0（+0x0）は共有メモリ窓として無効。
  if [ -z "$(printf '%s' "${hm_size#0x}" | sed -E 's/^0+//')" ]; then
    echo "host_memory_window=zero_size"
    fail
  fi
else
  echo "host_memory_window=missing"
  fail
fi

# venus 初期化（任意）。vulkaninfo --summary の出力に venus ドライバがあるか。
if [ -n "$vk_file" ]; then
  # GPU の列挙と driverName = venus を構造に沿って確認する（診断文の出現では成功にしない）。
  if ! grep -qE '^GPU[0-9]+:' "$tmpvk"; then
    echo "venus_init=no_devices"
    fail
  elif grep -qiE '^[[:space:]]*driverName[[:space:]]*=[[:space:]]*venus[[:space:]]*$' "$tmpvk"; then
    echo "venus_init=ok"
  else
    echo "venus_init=missing"
    fail
  fi
else
  echo "venus_init=not_checked"
fi

exit "$rc"
