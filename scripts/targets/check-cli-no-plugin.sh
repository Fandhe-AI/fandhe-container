#!/usr/bin/env bash
# CLI の plugin 無効構成の検証（make check-cli-no-plugin。PLUG-3・REPAIR-7・#3204）。
#
# `--no-default-features` で CLI の lib / bin が警告なしにビルド（clippy）でき、依存ツリーに plugin 境界基盤
# （fandhe-container-plugin）が入らないことを確認する。`make ci` には含めない（CI の platform-ci ジョブが同じ
# ターゲットを実行する。main では 3 OS で、Windows・macOS の cfg 分岐もネイティブで見る）。
#
# 実行時の契約も照合する（REPAIR-12）。CLI の試験は自己参照 dev-dependency が既定の plugin feature を再有効化するため
# `cargo test --no-default-features` では無効側を検証できない。そこで plugin 無効の実行ファイルを `cargo build` し、
# 実バイナリを直接起動して終了コード・stdout 空・stderr の構造化エラー 1 行を具体値で照合する（各起動は
# `run_limited`（lib.sh。macOS に `timeout` が無いため）で有限時間に限る。REPAIR-5）。継承した SIGCHLD の SIG_IGN の下でも同じ結果になることも見る。
# シグナルによる終了（再送）の実行時照合は、plugin 無効でも待てる長時間コマンドが無いため未実施（後続で扱う）。
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib.sh
source "${DIR}/../lib.sh"

skip_unless_workspace check-cli-no-plugin
require_cmd jq
start="${SECONDS}"
run cargo clippy -p fandhe-container-cli --no-default-features --lib --bins -- -D warnings
tree="$(cargo tree -p fandhe-container-cli --no-default-features -e normal --target all)" || {
  echo "NG: cargo tree failed" >&2
  exit 1
}
if printf '%s\n' "${tree}" | grep -q 'fandhe-container-plugin'; then
  echo "NG: the plugin-disabled CLI dependency tree contains fandhe-container-plugin" >&2
  exit 1
fi
run cargo build -p fandhe-container-cli --no-default-features --bin fandhe-container
# JSON を jq で復号する（Windows のパスのバックスラッシュは JSON 上でエスケープされているため sed では戻せない）。
target_dir="$(cargo metadata --format-version 1 --no-deps | jq -r '.target_directory')"
exe_suffix=""
os_name="$(uname -s)"
case "${os_name}" in
  MINGW* | MSYS* | CYGWIN*)
    exe_suffix=".exe"
    # Windows の bash で扱える POSIX 形式へ変換する（cygpath が無い環境では元の値のまま）。
    if command -v cygpath >/dev/null 2>&1; then
      target_dir="$(cygpath -u "${target_dir}")"
    fi
    ;;
esac
bin="${target_dir}/debug/fandhe-container${exe_suffix}"
if [[ ! -x "${bin}" ]]; then
  echo "NG: plugin-disabled binary not found: ${bin}" >&2
  exit 1
fi
work="$(mktemp -d)"
RUN_LIMITED_DIR="${work}"
trap 'run_limited_abort; rm -rf "${work}"' EXIT
usage_json='{"code":"INVALID_ARGUMENT","message":"usage: fandhe-container <create|start|stop|kill|delete|list|logs|inspect|state|image|system|setup|doctor>"}'

# 1 回起動して終了コード・stdout・stderr を照合する。引数: 名前 期待コード 期待 stderr 引数...
expect_run() {
  local name="$1" want_rc="$2" want_err="$3"
  shift 3
  local rc=0
  run_limited 30 "$@" >"${work}/out" 2>"${work}/err" </dev/null || rc=$?
  if [[ "${rc}" != "${want_rc}" ]]; then
    echo "NG: ${name}: exit code ${rc}, want ${want_rc}" >&2
    exit 1
  fi
  if [[ -s "${work}/out" ]]; then
    echo "NG: ${name}: stdout is not empty" >&2
    exit 1
  fi
  if [[ "$(cat "${work}/err")" != "${want_err}" ]]; then
    echo "NG: ${name}: unexpected stderr: $(cat "${work}/err")" >&2
    exit 1
  fi
}

expect_run usage 2 "${usage_json}" "${bin}"
# SIGCHLD を無視した状態で起動する（継承した SIG_IGN。bash の trap '' は exec 先へ引き継がれる）。
# 無視は exec 先の CLI だけに掛ける（見張り役の run_limited 自身の子の回収には影響させない）。
expect_run usage-sigchld-ignored 2 "${usage_json}" \
  bash -c 'trap "" CHLD; exec "$0" "$@"' "${bin}"
# 状態ストアは Linux の open_store の契約（親不在は NOT_FOUND・終了コード 3）。非 Linux は別バックエンドの
# 構造化エラーになるため、ここでは Linux に限る（CLI-1）。
if [[ "${os_name}" == "Linux" ]]; then
  expect_run missing-root 3 '{"code":"NOT_FOUND","message":"parent of the state root not found"}' \
    "${bin}" --root "${work}/absent/root" logs --follow abc
  echo "OK: the plugin-disabled CLI binary reports structured errors with exit codes 2 and 3 (also under an inherited SIGCHLD ignore)"
else
  echo "OK: the plugin-disabled CLI binary reports the usage error with exit code 2 (also under an inherited SIGCHLD ignore; missing-root is Linux only)"
fi
echo "OK: the plugin-disabled CLI builds and fandhe-container-plugin is not in its dependency tree ($((SECONDS - start)) s)"
