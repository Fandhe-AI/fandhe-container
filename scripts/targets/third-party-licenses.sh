#!/usr/bin/env bash
# サードパーティのライセンス表記を cargo-about で生成する（make third-party-licenses。TASK-103.1・OSS-5）。
#
# `make ci` には含めない。cargo-deny と違い自動導入しない（fail-closed）。導入は開発コンテナ（Dockerfile）か
# `make install-cargo-about`。未導入なら scripts/generate-third-party-licenses.sh が exit 2 で止まる。
# OUTPUT=<file> で出力先を指定できる（既定: target/third-party-licenses/）。値の検証は生成スクリプトに任せる。
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib.sh
source "${DIR}/../lib.sh"

skip_unless_workspace third-party-licenses
export PATH="${HOME}/.cargo/bin:${PATH}"
if [ -n "${OUTPUT:-}" ]; then
  bash scripts/generate-third-party-licenses.sh --output "${OUTPUT}"
else
  bash scripts/generate-third-party-licenses.sh
fi
