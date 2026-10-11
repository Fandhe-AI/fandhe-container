#!/usr/bin/env bash
# scripts/lib.sh の workspace 判定（has_cargo・has_members・skip_unless_workspace）の回帰テスト。
#
# 一時ディレクトリに scripts/lib.sh・scripts/versions.sh を複製した疑似リポジトリを作り、Cargo.toml・
# crates/*/Cargo.toml の有無の組み合わせごとに判定結果と skip の出力を具体値で照合する。
# 実行する bash は PATH 上の bash に加え、/bin/bash があればそれでも回す（macOS 標準の bash 3.2 で
# glob 不一致時の判定が崩れないことを確かめる。PR #1756 の指摘）。リポジトリ内のファイルは変更しない。
# 呼び出し元: Makefile の `lib-selftest`（CI の platform-ci ジョブ。PR は ubuntu・main は 3 OS）。
# 終了コード: 0 = 全件一致、1 = 不一致あり。
set -euo pipefail

src_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(mktemp -d)"
trap 'rm -rf "${root}"' EXIT

shells=()
path_bash="$(command -v bash)"
shells+=("${path_bash}")
if [ -x /bin/bash ] && [ "/bin/bash" != "${path_bash}" ]; then
  shells+=(/bin/bash)
fi

failures=0
pass() { echo "PASS: $1"; }
fail() {
  echo "FAIL: $1" >&2
  failures=$((failures + 1))
}

# make_repo <dir> <cargo:0|1> <layout>: layout は none（crates/ 無し）・empty（crates/ のみ）・
# dironly（crates/a/ に Cargo.toml 無し）・member（crates/a/Cargo.toml あり）
make_repo() {
  local dir="$1" cargo="$2" layout="$3"
  mkdir -p "${dir}/scripts"
  cp "${src_dir}/lib.sh" "${src_dir}/versions.sh" "${dir}/scripts/"
  if [ "${cargo}" = 1 ]; then : >"${dir}/Cargo.toml"; fi
  case "${layout}" in
    none) ;;
    empty) mkdir -p "${dir}/crates" ;;
    dironly) mkdir -p "${dir}/crates/a" ;;
    member) mkdir -p "${dir}/crates/a" && : >"${dir}/crates/a/Cargo.toml" ;;
  esac
  cat >"${dir}/scripts/probe.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"
if has_cargo; then c=1; else c=0; fi
if has_members; then m=1; else m=0; fi
echo "cargo=${c} members=${m}"
skip_unless_workspace probe
echo "ran"
EOF
}

# check <名前> <cargo> <layout> <期待する出力（改行は |）>
check() {
  local name="$1" cargo="$2" layout="$3" want="$4" sh dir got rc
  for sh in "${shells[@]}"; do
    dir="${root}/${name}-$(basename "$(dirname "${sh}")")-$$-${RANDOM}"
    make_repo "${dir}" "${cargo}" "${layout}"
    rc=0
    got="$(cd / && "${sh}" "${dir}/scripts/probe.sh" 2>&1)" || rc=$?
    got="$(printf '%s' "${got}" | tr '\n' '|')"
    if [ "${rc}" -eq 0 ] && [ "${got}" = "${want}" ]; then
      pass "${name} (${sh})"
    else
      fail "${name} (${sh}): exit=${rc} got='${got}' want='${want}'"
    fi
  done
}

skip_line="skip: Cargo.toml is missing or the workspace has no member crate, skipping probe"
check no-cargo-no-crates 0 none "cargo=0 members=0|${skip_line}"
check cargo-no-crates 1 none "cargo=1 members=0|${skip_line}"
check cargo-empty-crates 1 empty "cargo=1 members=0|${skip_line}"
check cargo-dir-without-manifest 1 dironly "cargo=1 members=0|${skip_line}"
check member-without-root-cargo 0 member "cargo=0 members=1|${skip_line}"
check cargo-and-member 1 member "cargo=1 members=1|ran"

for sh in "${shells[@]}"; do
  # shellcheck disable=SC2016 # BASH_VERSION は子の bash 側で展開させる
  echo "shell: ${sh} ($("${sh}" -c 'echo "${BASH_VERSION}"'))"
done
if [ "${failures}" -ne 0 ]; then
  echo "${failures} case(s) failed" >&2
  exit 1
fi
echo "all cases passed"
