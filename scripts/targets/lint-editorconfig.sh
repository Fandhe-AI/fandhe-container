#!/usr/bin/env bash
# editorconfig-checker（.editorconfig + .editorconfig-checker.json 参照。make lint-editorconfig）。
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib.sh
source "${DIR}/../lib.sh"

run npx --yes "editorconfig-checker@${EC_NPM_VERSION}"
