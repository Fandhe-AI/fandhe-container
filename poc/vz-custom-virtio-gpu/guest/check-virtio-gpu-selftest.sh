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
expect_case() {
  local name="$1" want_rc="$2" want_lines="$3" out rc line
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
expect_case capset-size-zero 1 "capset_info=venus
capset_max_size=0" --dmesg-file "$fx/capset-size-zero.log"
expect_case capset-timeout 1 "capset_info=timeout" --dmesg-file "$fx/capset-timeout.log"
expect_case old-kernel-zero-scanouts 1 "kms=probe_failed_zero_scanouts" --dmesg-file "$fx/old-kernel-zero-scanouts.log"
expect_case no-virtio-gpu 1 "probe=missing
capset_info=missing" --dmesg-file "$fx/no-virtio-gpu.log"
expect_case empty-input 1 "probe=missing" --dmesg-file "$fx/empty.log"

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
