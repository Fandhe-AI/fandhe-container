#!/usr/bin/env bash
# yamllint（.yamllint 参照。make lint-yaml）。
#
# yamllint は Python 製のため npx で賄えない。導入済みの実体（brew / pip）を優先し、uvx があれば固定版の
# ワンショット実行で代替する。いずれも無ければ fail-closed で導入方法を案内して失敗する
# （silent skip は CI との false-green 乖離になるため行わない）。
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib.sh
source "${DIR}/../lib.sh"

if command -v yamllint >/dev/null 2>&1; then
  yamllint .
elif command -v uvx >/dev/null 2>&1; then
  uvx "yamllint==${YAMLLINT_VERSION}" .
else
  echo "yamllint not found: install with brew install yamllint / pip install yamllint==${YAMLLINT_VERSION}" >&2
  exit 1
fi
