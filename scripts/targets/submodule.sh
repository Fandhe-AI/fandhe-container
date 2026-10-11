#!/usr/bin/env bash
# docs/spec サブモジュールを初期化・更新する（make submodule）。
#
# docs/spec（fandhe-container-spec）は private リポジトリのため、アクセス権のない環境では取得に失敗する。
# 実装コードのビルド・テストは docs/spec 抜きでも成立させる方針（CLAUDE.md）のため、失敗しても警告のみで成功終了する。
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib.sh
source "${DIR}/../lib.sh"

git submodule update --init ||
  echo "warning: failed to fetch docs/spec (private). Expected without access; build and tests do not need it"
