#!/usr/bin/env bash
# check-virtio-gpu.sh の自己テスト（TASK-172.6・GPU-6・REPAIR-12）。
# 合成 fixture（testdata/）だけで照合し、実機・dmesg・Vulkan は使わない。
# 期待する key=value 行と終了コードを具体値で照合する。
set -euo pipefail
export LC_ALL=C

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
script="$here/check-virtio-gpu.sh"
fx="$here/testdata"
failures=0

# expect_case NAME EXPECTED_RC EXPECTED_LINES(改行区切り。出力に全行が含まれること) ARGS...
# 全ケース共通で「各 key は 1 回だけ出る」ことも照合する（同一 key に矛盾する値を
# 重ねて出すと、先頭行だけを読む利用側が誤判定するため。GPU-6・REPAIR-12）。
expect_case() {
  local name="$1" want_rc="$2" want_lines="$3" out rc line dups
  shift 3
  set +e
  out="$(bash "$script" "$@" 2>/dev/null)"
  rc=$?
  set -e
  if [ "$rc" -ne "$want_rc" ]; then
    echo "FAIL $name: exit code $rc, want $want_rc" >&2
    failures=$((failures + 1))
    return
  fi
  dups="$(printf '%s\n' "$out" | grep -E '^[^=]+=' | cut -d= -f1 | sort | uniq -d || true)"
  if [ -n "$dups" ]; then
    echo "FAIL $name: duplicate key(s): $(printf '%s' "$dups" | tr '\n' ' ')" >&2
    failures=$((failures + 1))
    return
  fi
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    if ! printf '%s\n' "$out" | grep -qxF -- "$line"; then
      echo "FAIL $name: missing line '$line'" >&2
      failures=$((failures + 1))
      return
    fi
  done <<<"$want_lines"
  echo "ok   $name"
}

expect_case success 0 "probe=ok
virgl=enabled
resource_blob=enabled
context_init=enabled
host_visible=enabled
edid=disabled
kms=disabled
capset_count=1
capset_info=venus
capset_max_version=0
capset_max_size=160
host_memory_window=present
host_memory_window_size=0x0000000100000000
venus_init=not_checked" --dmesg-file "$fx/ok.log"

expect_case venus-ok 0 "venus_init=ok" --dmesg-file "$fx/ok.log" --vulkaninfo-file "$fx/vulkaninfo-venus.txt"
expect_case venus-missing 1 "venus_init=missing" --dmesg-file "$fx/ok.log" --vulkaninfo-file "$fx/vulkaninfo-none.txt"
expect_case no-host-visible 1 "host_visible=disabled
host_memory_window=missing" --dmesg-file "$fx/no-host-visible.log"
expect_case scanout-present 1 "kms=scanouts_present" --dmesg-file "$fx/scanout-present.log"
expect_case kms-disabled-with-scanout 1 "kms=scanouts_present" --dmesg-file "$fx/kms-disabled-with-scanout.log"
expect_case capset-size-zero 1 "capset_info=venus
capset_max_size=0" --dmesg-file "$fx/capset-size-zero.log"
expect_case capset-timeout 1 "capset_info=timeout" --dmesg-file "$fx/capset-timeout.log"
expect_case old-kernel-zero-scanouts 1 "kms=probe_failed_zero_scanouts" --dmesg-file "$fx/old-kernel-zero-scanouts.log"
expect_case no-virtio-gpu 1 "probe=missing
capset_info=missing" --dmesg-file "$fx/no-virtio-gpu.log"
expect_case empty-input 1 "probe=missing" --dmesg-file "$fx/empty.log"
expect_case multi-device 1 "probe=multiple_devices" --dmesg-file "$fx/multi-device.log"
# 実カーネルの DRM_INFO 系ログは "[drm]" 接頭辞のみでデバイス識別子を持たない。
expect_case drm-prefix-ok 0 "probe=ok
virgl=enabled
context_init=enabled
kms=disabled
capset_info=venus
capset_max_size=160
host_memory_window=present" --dmesg-file "$fx/drm-prefix-ok.log"
expect_case drm-prefix-zero-scanouts 1 "kms=probe_failed_zero_scanouts
host_memory_window=present" --dmesg-file "$fx/drm-prefix-zero-scanouts.log"
expect_case drm-prefix-multi-section 1 "probe=multiple_sections" --dmesg-file "$fx/drm-prefix-multi-section.log"
expect_case capset-version-nonzero 1 "capset_max_version=3" --dmesg-file "$fx/capset-version-nonzero.log"
# サイズ 0 の窓は zero_size だけを出し、present を併記しない（key 重複検査と併せて照合）。
expect_case host-window-zero 1 "probe=ok
capset_info=venus
capset_max_size=160
host_memory_window=zero_size
host_memory_window_size=0x0000000000000000
venus_init=not_checked" --dmesg-file "$fx/host-window-zero.log"
expect_case probe-failed 1 "probe=failed" --dmesg-file "$fx/probe-failed.log"
expect_case probe-failed-driver 1 "probe=failed" --dmesg-file "$fx/probe-failed-driver.log"
expect_case venus-diagnostic-only 1 "venus_init=missing" --dmesg-file "$fx/ok.log" --vulkaninfo-file "$fx/vulkaninfo-diagnostic.txt"
expect_case venus-no-devices 1 "venus_init=no_devices" --dmesg-file "$fx/ok.log" --vulkaninfo-file "$fx/vulkaninfo-nodevices.txt"

# dmesg 取得失敗は終了コード 2（偽の dmesg を PATH 先頭に置く）
fakebin="$(mktemp -d)"
printf '#!/bin/sh\necho "dmesg: read kernel buffer failed: Operation not permitted" >&2\nexit 1\n' >"$fakebin/dmesg"
chmod +x "$fakebin/dmesg"
set +e
PATH="$fakebin:$PATH" bash "$script" >/dev/null 2>&1
dm_rc=$?
set -e
if [ "$dm_rc" -ne 2 ]; then
  echo "FAIL dmesg-failure: exit code $dm_rc, want 2" >&2
  failures=$((failures + 1))
else
  echo "ok   dmesg-failure"
fi
rm -rf "$fakebin"

# 入力・引数エラー（終了コード 2）
expect_case missing-file 2 "" --dmesg-file "$fx/does-not-exist.log"
expect_case unknown-arg 2 "" --bogus
expect_case missing-value 2 "" --dmesg-file

# 上限超過（16 MiB + 1 バイト）。sparse なファイルを scratch に作って検査する。
big="$(mktemp)"
trap 'rm -f "$big"' EXIT
truncate -s $((16 * 1024 * 1024 + 1)) "$big"
expect_case oversize 2 "" --dmesg-file "$big"

if [ "$failures" -ne 0 ]; then
  echo "check-virtio-gpu selftest: $failures failure(s)" >&2
  exit 1
fi
echo "check-virtio-gpu selftest: all passed"
