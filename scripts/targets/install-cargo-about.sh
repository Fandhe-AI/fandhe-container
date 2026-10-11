#!/usr/bin/env bash
# cargo-about を CARGO_ABOUT_VERSION（scripts/versions.sh）へ完全固定で導入する（make install-cargo-about。TASK-103.2・OSS-5）。
#
# platform-ci（ubuntu）が third-party-licenses の前に実行する。バイナリは feature `cli` が要る（無いと導入されない）。
# 既に同じ版なら再導入せず、導入後は `cargo about --version` が版と完全一致することを検査する。
# 依存ではなくツールのため Cargo.toml・Cargo.lock には入らない。ビルドに C コンパイラが要る（ring 等）。
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib.sh
source "${DIR}/../lib.sh"

export PATH="${HOME}/.cargo/bin:${PATH}"
want="cargo-about ${CARGO_ABOUT_VERSION}"
if [ "$(cargo about --version 2>/dev/null || true)" != "${want}" ]; then
  echo "installing ${want}"
  cargo install "cargo-about@${CARGO_ABOUT_VERSION}" --locked --features cli --force
fi
got="$(cargo about --version 2>/dev/null || true)"
if [ "${got}" != "${want}" ]; then
  echo "error: expected ${want} but got '${got}'" >&2
  exit 1
fi
echo "${got}"
