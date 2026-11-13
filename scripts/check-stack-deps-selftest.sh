#!/usr/bin/env bash
# scripts/check-stack-deps.sh の自己テスト（make check-stack-deps-selftest。STACK-8・REPAIR-12・#4638）。
#
# 一時ディレクトリにスタブの `cargo`（metadata は fixture の JSON）を置き、STACK_DEPS_CARGO で差して判定本体を実行する。
# 実際の cargo・ネットワーク・root は使わない（jq と tsort は必要）。1 件でも期待と違えば非 0 で終わる。
set -euo pipefail
export LC_ALL=C

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
checker="${here}/check-stack-deps.sh"
work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT

for tool in jq tsort; do
  if ! command -v "${tool}" >/dev/null 2>&1; then
    echo "${tool} is required but not found" >&2
    exit 1
  fi
done

cat >"${work}/cargo" <<'EOT'
#!/usr/bin/env bash
if [ "${STUB_METADATA_FAIL:-}" = 1 ]; then exit 101; fi
cat "${STUB_METADATA_FILE}"
EOT
chmod +x "${work}/cargo"

# meta <名前:依存名,依存名 ...>: パッケージ id = 名前。
meta() {
  local spec nodes="" pkgs="" first=1 name deps depjson d
  for spec in "$@"; do
    name="${spec%%:*}"
    deps="${spec#*:}"
    depjson=""
    if [ -n "${deps}" ]; then
      for d in $(printf '%s' "${deps}" | tr ',' ' '); do
        depjson="${depjson:+${depjson},}{\"pkg\":\"${d}\",\"dep_kinds\":[{\"kind\":null,\"target\":null}]}"
      done
    fi
    if [ "${first}" = 0 ]; then
      nodes="${nodes},"
      pkgs="${pkgs},"
    fi
    first=0
    nodes="${nodes}{\"id\":\"${name}\",\"deps\":[${depjson}]}"
    pkgs="${pkgs}{\"id\":\"${name}\",\"name\":\"${name}\"}"
  done
  printf '{"packages":[%s],"resolve":{"nodes":[%s]}}\n' "${pkgs}" "${nodes}"
}

failures=0
# expect <期待する終了コード> <説明> <metadata ファイル> [期待する stderr の部分文字列]
expect() {
  local want="$1" label="$2" file="$3" needle="${4:-}" got=0 err
  err="$(STUB_METADATA_FILE="${file}" STACK_DEPS_CARGO="${work}/cargo" "${checker}" 2>&1 >/dev/null)" || got=$?
  if [ "${got}" -ne "${want}" ]; then
    echo "FAIL: ${label}: exit ${got}, want ${want}: ${err}" >&2
    failures=$((failures + 1))
    return
  fi
  if [ -n "${needle}" ] && ! printf '%s' "${err}" | grep -Fq "${needle}"; then
    echo "FAIL: ${label}: stderr lacks '${needle}': ${err}" >&2
    failures=$((failures + 1))
    return
  fi
  echo "ok: ${label}"
}

C=fandhe-container-cli
S=fandhe-container-stack
P=fandhe-container-plugin
K=fandhe-container-core

meta "${C}:${S},${K},${P}" "${S}:" "${P}:" "${K}:" "serde:" >"${work}/ok.json"
expect 0 "cli -> stack, stack leaf" "${work}/ok.json"

meta "${C}:${K}" "${S}:" "${P}:" "${K}:" >"${work}/no-edge.json"
expect 1 "cli does not depend on stack" "${work}/no-edge.json" "does not depend on fandhe-container-stack"

meta "${C}:${S}" "${S}:${K}" "${P}:" "${K}:" >"${work}/stack-core.json"
expect 1 "stack -> core" "${work}/stack-core.json" "must not depend on any fandhe-container"

meta "${C}:${S}" "${S}:${C}" "${P}:" "${K}:" >"${work}/stack-cli.json"
expect 1 "stack -> cli (also a cycle)" "${work}/stack-cli.json" "must not depend on any fandhe-container"

meta "${C}:${S}" "${S}:" "${P}:${S}" "${K}:" >"${work}/plugin-stack.json"
expect 1 "plugin -> stack" "${work}/plugin-stack.json" "fandhe-container-plugin must not depend on"

meta "${C}:${S}" "${S}:" "${P}:${K}" "${K}:${P}" >"${work}/cycle.json"
expect 1 "cycle between plugin and core" "${work}/cycle.json" "contains a cycle"

meta "${C}:${S},${C}" "${S}:" "${P}:" "${K}:" >"${work}/self.json"
expect 0 "self dev-dependency is ignored" "${work}/self.json"

meta "${S}:" "${P}:" >"${work}/missing-cli.json"
expect 1 "package missing" "${work}/missing-cli.json" "is missing"

echo '{}' >"${work}/empty.json"
expect 1 "empty metadata is fail-closed" "${work}/empty.json"

got=0
STUB_METADATA_FAIL=1 STUB_METADATA_FILE="${work}/ok.json" STACK_DEPS_CARGO="${work}/cargo" "${checker}" >/dev/null 2>&1 || got=$?
if [ "${got}" -ne 1 ]; then
  echo "FAIL: metadata failure must exit 1 (got ${got})" >&2
  failures=$((failures + 1))
else
  echo "ok: metadata failure is fail-closed"
fi

if [ "${failures}" -ne 0 ]; then
  echo "${failures} case(s) failed" >&2
  exit 1
fi
echo "ok: all check-stack-deps selftest cases passed"
