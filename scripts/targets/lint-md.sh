#!/usr/bin/env bash
# markdownlint（.markdownlint.jsonc / .markdownlintignore 参照。make lint-md）。
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib.sh
source "${DIR}/../lib.sh"

run npx --yes "markdownlint-cli@${MARKDOWNLINT_VERSION}" --ignore-path .markdownlintignore "**/*.md"
