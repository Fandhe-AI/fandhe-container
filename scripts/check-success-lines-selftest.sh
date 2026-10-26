#!/usr/bin/env bash
# scripts/check-success-lines.sh の自己テスト（#2768・REPAIR-12）。
#
# 役割: 成功行の導出（複数行に折られたリテラル・{name} の直積・{} の位置置換・--subst-re）と、
# fail-closed の各分岐（導出 0 件・min 未満・ログ欠落・期待外の行・forbid・書式指定つき等）を確かめる。
# fixture はすべて mktemp の中に生成する。実機・root・ネットワークに依存しない。
# 呼び出し元: Makefile の `check-success-lines-selftest`（CI の platform-ci の自己テスト群）。
# 終了コード: 0 全件成功 / 1 失敗。bash 3.2 互換。
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
target="${here}/check-success-lines.sh"
work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT

fails=0
# expect <期待終了コード> <名前> -- <check-success-lines の引数>
expect() {
  local want="$1" label="$2" got=0
  shift 3
  "${BASH:-bash}" "${target}" "$@" > "${work}/out" 2> "${work}/err" || got=$?
  if [ "${got}" -ne "${want}" ]; then
    echo "NG: ${label}: want exit ${want}, got ${got}" >&2
    cat "${work}/err" >&2
    fails=$((fails + 1))
  else
    echo "ok: ${label}"
  fi
}

cat > "${work}/t.rs" <<'EOF'
// println!("t: scenario commented verified");
fn main() {
    println!("t: scenario {name} verified (uid={})", 1);
    println!(
        "t: fixed line"
    );
    let c = '"';
    println!("t: after char {{braces}}"); let _ = c;
    println!("other: not selected {x:?}");
}
EOF
printf 't: scenario direct verified (uid=5)\r\nt: scenario helper verified (uid=5)\nt: fixed line\nt: after char {braces}\nother\n' > "${work}/ok.log"

base=(--name t --src "${work}/t.rs" --log "${work}/ok.log" --select '^t: ')
expect 0 "positional and named expansion" -- "${base[@]}" --subst name=direct,helper --subst-pos 5
expect 0 "forbid not in log" -- --name t --src "${work}/t.rs" --log "${work}/ok.log" \
  --select '^t: ' --subst name=direct,helper --subst-pos 5 --forbid ignored
expect 1 "missing placeholder value" -- "${base[@]}" --subst-pos 5
expect 1 "positional count mismatch" -- "${base[@]}" --subst name=direct,helper
expect 1 "missing scenario in log" -- "${base[@]}" --subst name=direct,helper,extra --subst-pos 5
expect 1 "unexpected log line" -- "${base[@]}" --subst name=direct --subst-pos 5
expect 1 "wrong positional value" -- "${base[@]}" --subst name=direct,helper --subst-pos 6
expect 1 "min not met" -- "${base[@]}" --subst name=direct,helper --subst-pos 5 --min 99
expect 1 "zero derived" -- --name t --src "${work}/t.rs" --log "${work}/ok.log" --select '^nomatch: '
expect 1 "forbidden string" -- "${base[@]}" --subst name=direct,helper --subst-pos 5 --forbid 'other'
expect 2 "forbid conflicts with expected" -- "${base[@]}" --subst name=direct,helper --subst-pos 5 --forbid 'fixed line'
expect 1 "format spec placeholder" -- --name t --src "${work}/t.rs" --log "${work}/ok.log" --select '^other: '
expect 1 "missing src" -- --name t --src "${work}/none.rs" --log "${work}/ok.log" --select '^t: '
ln -s "${work}/t.rs" "${work}/link.rs"
expect 1 "symlink src rejected" -- --name t --src "${work}/link.rs" --log "${work}/ok.log" --select '^t: '
expect 2 "unknown arg" -- --bogus
expect 2 "missing required arg" -- --name t
expect 2 "bad name" -- --name 'a b' --src x --log y --select z

cat > "${work}/re.rs" <<'EOF'
fn main() { println!("r: samples={n} done"); }
EOF
printf 'r: samples=123 done\n' > "${work}/re.log"
expect 0 "subst-re anchored" -- --name r --src "${work}/re.rs" --log "${work}/re.log" --select '^r: ' --subst-re 'n=[0-9]+'
printf 'r: samples=12x done\n' > "${work}/re2.log"
expect 1 "subst-re mismatch" -- --name r --src "${work}/re.rs" --log "${work}/re2.log" --select '^r: ' --subst-re 'n=[0-9]+'
printf 'r: samples=1 done extra\n' > "${work}/re3.log"
expect 1 "subst-re no prefix match" -- --name r --src "${work}/re.rs" --log "${work}/re3.log" --select '^r: ' --subst-re 'n=[0-9]+'

if [ "${fails}" -ne 0 ]; then
  echo "check-success-lines-selftest: ${fails} case(s) failed" >&2
  exit 1
fi
echo "check-success-lines-selftest: all cases passed"
