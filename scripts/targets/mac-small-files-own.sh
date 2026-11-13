#!/usr/bin/env bash
# 自前側の小ファイル多数ワークロードの計測（make mac-small-files-own。MAC-3・#3106・TASK-70 準備）。
#
# mac_small_files.sh の `--mode own` を呼ぶ。自前 CLI（create / start / state / logs / inspect / delete）で測る。
# 共有ルート（VM に構成済み）・bundle（rootfs/ を含む）・イメージ ID の申告が必要。macOS の実経路
# （#4705・#2280・#2281 ほか）が入るまでは、実機では構造化エラーで終了コード 1 になる。
# 合否判定は #381（TASK-70）で人間が行う。
# 入力は環境変数: FANDHE・SHARED_ROOT・HOST_DIR・BUNDLE・IMAGE_ID（必須）、IMAGE・COUNT・TRIALS・BATCH・LABEL・
# TRIAL_TIMEOUT_SECS・TIMEOUT_SECS・OUTPUT（任意）。
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib.sh
source "${DIR}/../lib.sh"

if [ -z "${FANDHE:-}" ] || [ -z "${SHARED_ROOT:-}" ] || [ -z "${HOST_DIR:-}" ] || [ -z "${BUNDLE:-}" ] || [ -z "${IMAGE_ID:-}" ]; then
  echo "usage: make mac-small-files-own FANDHE=<abs-path of the own CLI> SHARED_ROOT=<abs real path of the shared root configured in the VM> HOST_DIR=<abs real path under SHARED_ROOT> BUNDLE=<abs real path under SHARED_ROOT with rootfs/ and no config.json> IMAGE_ID=<sha256:... id of the image the rootfs came from> [IMAGE=<ref, display only, default alpine:3.20>] [COUNT=<n>] [TRIALS=<n>] [BATCH=<n>] [LABEL=<label>] [TRIAL_TIMEOUT_SECS=<n>] [TIMEOUT_SECS=<n>] [OUTPUT=<new file>]" >&2
  exit 2
fi
args=(--mode own --runtime "${FANDHE}" --shared-root "${SHARED_ROOT}" --host-dir "${HOST_DIR}" --bundle "${BUNDLE}" --image-id "${IMAGE_ID}")
if [ -n "${IMAGE:-}" ]; then args+=(--image "${IMAGE}"); fi
if [ -n "${COUNT:-}" ]; then args+=(--count "${COUNT}"); fi
if [ -n "${TRIALS:-}" ]; then args+=(--trials "${TRIALS}"); fi
if [ -n "${BATCH:-}" ]; then args+=(--batch "${BATCH}"); fi
if [ -n "${LABEL:-}" ]; then args+=(--label "${LABEL}"); fi
if [ -n "${TRIAL_TIMEOUT_SECS:-}" ]; then args+=(--trial-timeout-secs "${TRIAL_TIMEOUT_SECS}"); fi
if [ -n "${TIMEOUT_SECS:-}" ]; then args+=(--timeout-secs "${TIMEOUT_SECS}"); fi
if [ -n "${OUTPUT:-}" ]; then args+=(--output "${OUTPUT}"); fi
# docker 版と同じく、コマンド行を stdout へ出す run を介さず直接呼ぶ（JSON を壊さない）。
bash scripts/bench/mac_small_files.sh "${args[@]}"
