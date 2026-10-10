// monitorPrompt 手順 3g（ruleset の required context が HEAD に揃うまで ready を返さない）の回帰テスト
// （upstream agent-cli-skills#577）。
//
// 事象: 速く終わる App（AI レビュー・Bugbot）のチェックだけが HEAD に揃い、ruleset の required
// context を出す CI の check-run がまだ作られていない段階で monitor が「存在するチェックが全 green」
// として ready を返し、merge-exec の G0 (v-b) が issuer-unbound で終端していた。
//
// 本テストは (1) プロンプト契約（3g の存在・未発行時に ready を返さず timeout へ倒す・件数のみ・
// 手順 6 / 7 への接続）と、(2) プロンプトに書かれた jq 式そのものを fixture に対して実行し、
// 受け入れ条件（required でないチェックだけが success の状態では未発行件数 = N、required が揃えば 0、
// 取得失敗では数値を出さない）を機械照合する。(3) 3g の Bash ブロックが merge-guard hook で
// deny されない（読み取りのみ）ことも確認する。
//
// 読み込み方式は g0-gates.test.mjs と同じ（駆動部マーカーより上を切り出して import する）。
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, writeFileSync, mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, dirname } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { execFileSync, spawnSync } from 'node:child_process'

const HERE = dirname(fileURLToPath(import.meta.url))
const SCRIPT_PATH = join(HERE, '..', 'scripts', 'implement-issue-tree.src.js')
const HOOK = join(HERE, '..', 'scripts', 'merge-guard-hook.sh')
const DRIVER_MARKER = '__IMPLEMENT_ISSUE_TREE_DRIVER_START__'

const source = readFileSync(SCRIPT_PATH, 'utf8')
const markerIndex = source.indexOf(DRIVER_MARKER)
if (markerIndex < 0) {
  throw new Error(`テスト境界マーカー ${DRIVER_MARKER} が実装スクリプトに存在しない（削除・改名は回帰テストを無効化する）`)
}
const definitionPart = source.slice(0, source.lastIndexOf('\n', markerIndex))
const sliceDir = mkdtempSync(join(tmpdir(), 'implement-issue-tree-req-ctx-'))
const slicePath = join(sliceDir, 'implement-issue-tree-defs.mjs')
writeFileSync(slicePath, `${definitionPart}\nexport { monitorPrompt, mergeExecutePrompt }\n`)
const { monitorPrompt, mergeExecutePrompt } = await import(pathToFileURL(slicePath).href)

const item = { number: 577, title: 'テストイシュー' }
const impl = { prNumber: 888, branch: 'fix/577-required-contexts' }

// 外部チェック構成ごとのプロンプト（3g は外部チェック構成・autoMerge の有無によらず常に入る）
const VARIANTS = [
  ['外部チェックなし・autoMerge', () => monitorPrompt(item, impl, [], true, true)],
  ['外部チェックなし・opt-out', () => monitorPrompt(item, impl, [], true, false)],
  ['cursor あり', () => monitorPrompt(item, impl, ['cursor'], true, true)],
  ['cursor 以外あり', () => monitorPrompt(item, impl, ['chatgpt-codex-connector'], true, true)],
  ['外部チェック未確定', () => monitorPrompt(item, impl, [], false, false)],
]

function section3g(prompt) {
  const start = prompt.indexOf('\n   g. ')
  assert.ok(start >= 0, '手順 3g が見つからない')
  const end = prompt.indexOf('\n4. ', start)
  assert.ok(end > start, '手順 3g が手順 4 より前にない')
  return prompt.slice(start, end)
}

// 3g の Bash ブロック（HEAD_SHA= 行から check-runs 行まで）を行単位で取り出す
function bashBlock(prompt) {
  const lines = section3g(prompt).split('\n').map((l) => l.trim())
  const from = lines.findIndex((l) => l.startsWith('HEAD_SHA='))
  const to = lines.findIndex((l) => l.includes('/check-runs"'))
  assert.ok(from >= 0 && to > from, '3g の Bash ブロックを特定できない')
  return lines.slice(from, to + 1)
}

// 行中の「| jq ...」以降（gh api の出力を受ける jq 呼び出し）をシェル引数の配列へ分解する。
// 単純なクォート（'...' / "..."）のみを扱う（プロンプトの jq 式はこの形しか持たない）。
function jqArgv(line) {
  const idx = line.indexOf('| jq ')
  assert.ok(idx >= 0, `jq 呼び出しがない: ${line}`)
  let rest = line.slice(idx + 2).replace(/\)$/, '')
  const argv = []
  const re = /'([^']*)'|"([^"]*)"|(\S+)/g
  let m
  while ((m = re.exec(rest)) !== null) argv.push(m[1] ?? m[2] ?? m[3])
  assert.equal(argv[0], 'jq')
  return argv.slice(1)
}

function runJq(args, input, vars = {}) {
  // "$REQ" / "$ST" をテスト側の値へ置換する（シェル展開の再現）
  const resolved = args.map((a) => (a.startsWith('$') && a.slice(1) in vars ? vars[a.slice(1)] : a))
  return spawnSync('jq', resolved, { input, encoding: 'utf8' })
}

const hasJq = spawnSync('jq', ['--version'], { encoding: 'utf8' }).status === 0

test('前提: jq が利用できる（プロンプトの jq 式を実行して照合するため必須）', () => {
  assert.ok(hasJq, 'jq が見つからない。本スキルのプロンプトは jq を前提にしているため、テスト環境にも jq が必要')
})

test('monitorPrompt: 全構成で手順 3g が 3f の後・手順 4 の前にある', () => {
  for (const [name, build] of VARIANTS) {
    const prompt = build()
    const idxF = prompt.indexOf('\n   f. 手順 3c で state: needs-fix')
    const idxG = prompt.indexOf('\n   g. ')
    const idx4 = prompt.indexOf('\n4. ')
    assert.ok(idxF >= 0 && idxG > idxF && idx4 > idxG, `${name}: 手順 3g の位置が 3f と手順 4 の間にない`)
  }
})

test('monitorPrompt 3g: required context の取得式は merge-exec G0 (v) と同一', () => {
  const block = bashBlock(monitorPrompt(item, impl, [], true, true))
  const reqLine = block.find((l) => l.startsWith('REQ='))
  assert.ok(reqLine, 'REQ の取得行がない')
  const exec = mergeExecutePrompt(item, impl, true, [{ app: 'cursor', contexts: ['Cursor Bugbot'] }])
  const execReq = exec.split('\n').map((l) => l.trim()).find((l) => l.startsWith('REQ='))
  assert.ok(execReq, 'merge-exec の REQ 取得行が見つからない')
  assert.equal(reqLine, execReq, 'monitor と merge-exec で required context の取得式が食い違っている')
  assert.ok(reqLine.includes('rules/branches/main'), 'ベースブランチの rules を取得していない')
  assert.ok(reqLine.includes('--paginate --slurp'), '全ページ取得（--paginate --slurp）になっていない')
})

test('monitorPrompt 3g: 未発行が残る・取得失敗では ready を返さず timeout へ倒す', () => {
  for (const [name, build] of VARIANTS) {
    const g = section3g(build())
    assert.ok(g.includes('CI 全 green とみなさない'), `${name}: 未発行を green とみなさない指示がない`)
    assert.ok(g.includes('pending と同じ扱い'), `${name}: 未発行を pending として扱う指示がない`)
    assert.ok(g.includes('通算 10 分'), `${name}: 待機が有界でない`)
    assert.ok(g.includes('手順 2 の --watch へ戻る'), `${name}: チェック増加時に --watch へ戻る指示がない`)
    assert.ok(g.includes('数値が出ない（取得失敗）'), `${name}: 取得失敗の扱いがない`)
    assert.ok(g.includes('ready にせず state: timeout を返す'), `${name}: ready を禁じて timeout を返す指示がない`)
  }
})

test('monitorPrompt 3g: context 名・App 名を取得・転記せず件数のみを扱う（権限境界）', () => {
  for (const [name, build] of VARIANTS) {
    const g = section3g(build())
    assert.ok(g.includes('件数のみを数える'), `${name}: 件数のみの指示がない`)
    assert.ok(g.includes('context 名・App 名は取得・転記せず summary には件数のみ書く'), `${name}: 名前の転記禁止がない`)
    assert.ok(g.includes('REQ・ST は表示しない'), `${name}: シェル変数の表示禁止がない`)
    // 最終出力は件数（length）へ正規化され、名前の一覧を出力しない
    const block = bashBlock(build())
    assert.ok(block.at(-1).endsWith("| length'"), `${name}: 最終出力が件数へ正規化されていない`)
    assert.ok(!g.includes('echo'), `${name}: 値を表示する指示が混入している`)
  }
})

test('monitorPrompt: 手順 6（両分岐）が手順 3g の未発行 0 件を ready の前提にする', () => {
  for (const clientMerge of [true, false]) {
    const prompt = monitorPrompt(item, impl, [], true, clientMerge)
    const line6 = prompt.split('\n').find((l) => l.startsWith('6. '))
    assert.ok(line6, '手順 6 が見つからない')
    assert.ok(line6.includes('手順 3g の未発行 0 件'), `clientMerge=${clientMerge}: 手順 6 に 3g の条件がない`)
  }
})

test('monitorPrompt: 手順 7 の timeout 許可に手順 3g が含まれる', () => {
  const prompt = monitorPrompt(item, impl, [], true, true)
  const line7 = prompt.split('\n').find((l) => l.startsWith('7. '))
  assert.ok(line7.includes('と手順 3g の場合だけに限定する'), '手順 7 に 3g の timeout が許可されていない')
  // 既存の契約（0 件は timeout にしない）は維持する
  assert.ok(line7.includes('チェックが 1 件以上存在し'))
  assert.ok(line7.includes('checksTotal: 0 の timeout を受理しない'))
})

// --- jq 式の実行による受け入れ条件の照合 -------------------------------------------------

const REQUIRED = ['build (ubuntu-latest)', 'test (macos-latest)', 'deny']
// ruleset の rules/branches 応答（--paginate --slurp でページ配列に束ねた形）
const RULES_PAGES = JSON.stringify([
  [
    { type: 'pull_request', ruleset_id: 1, parameters: { required_review_thread_resolution: true } },
    {
      type: 'required_status_checks',
      ruleset_id: 1,
      parameters: { required_status_checks: REQUIRED.slice(0, 2).map((context) => ({ context, integration_id: 15368 })) },
    },
  ],
  [
    { type: 'required_status_checks', ruleset_id: 2, parameters: { required_status_checks: [{ context: 'deny', integration_id: 15368 }] } },
  ],
])
const checkRunsPages = (names) => JSON.stringify([{ total_count: names.length, check_runs: names.map((name) => ({ name, app: { id: 15368 } })) }])
const statusesPages = (contexts) => JSON.stringify([contexts.map((context) => ({ context, state: 'success' }))])

function countMissing(prompt, { rules = RULES_PAGES, statuses = statusesPages([]), runs }) {
  const block = bashBlock(prompt)
  const reqArgs = jqArgv(block.find((l) => l.startsWith('REQ=')))
  const stArgs = jqArgv(block.find((l) => l.startsWith('ST=')))
  const countArgs = jqArgv(block.at(-1))
  const req = runJq(reqArgs, rules)
  const st = runJq(stArgs, statuses)
  // シェルの $(...) は失敗時に空文字列になる（gh / jq の失敗は stdout を残さない）
  const vars = { REQ: req.status === 0 ? req.stdout.trim() : '', ST: st.status === 0 ? st.stdout.trim() : '' }
  return runJq(countArgs, runs, vars)
}

test('jq 照合: required でないチェックだけが success の段階では未発行件数 = required 件数（ready にしない）', () => {
  const prompt = monitorPrompt(item, impl, ['cursor'], true, true)
  const r = countMissing(prompt, { runs: checkRunsPages(['codex-review', 'Cursor Bugbot', 'ai-review']) })
  assert.equal(r.status, 0, r.stderr)
  assert.equal(r.stdout.trim(), String(REQUIRED.length))
})

test('jq 照合: required context が一部だけ発行済みなら残りの件数を返す（2 ページ目の ruleset も数える）', () => {
  const prompt = monitorPrompt(item, impl, [], true, true)
  const r = countMissing(prompt, { runs: checkRunsPages(['codex-review', 'build (ubuntu-latest)']) })
  assert.equal(r.status, 0, r.stderr)
  assert.equal(r.stdout.trim(), '2')
})

test('jq 照合: required context が全件 check-run として発行されれば 0（ready へ進める）', () => {
  const prompt = monitorPrompt(item, impl, [], true, true)
  const r = countMissing(prompt, { runs: checkRunsPages(['codex-review', ...REQUIRED]) })
  assert.equal(r.status, 0, r.stderr)
  assert.equal(r.stdout.trim(), '0')
})

test('jq 照合: commit status で発行済みの context も「発行済み」に数える（発行元束縛は merge-exec の (v-b) が判定）', () => {
  const prompt = monitorPrompt(item, impl, [], true, true)
  const r = countMissing(prompt, { runs: checkRunsPages(REQUIRED.slice(0, 2)), statuses: statusesPages(['deny']) })
  assert.equal(r.status, 0, r.stderr)
  assert.equal(r.stdout.trim(), '0')
})

test('jq 照合: ruleset に required status checks が無ければ 0（G0 側の判定へ委ねる）', () => {
  const prompt = monitorPrompt(item, impl, [], true, true)
  const r = countMissing(prompt, { rules: JSON.stringify([[]]), runs: checkRunsPages(['codex-review']) })
  assert.equal(r.status, 0, r.stderr)
  assert.equal(r.stdout.trim(), '0')
})

test('jq 照合: rules の取得失敗（エラー応答・空出力）では数値を出さない（0 へ倒さない）', () => {
  const prompt = monitorPrompt(item, impl, [], true, true)
  for (const rules of [JSON.stringify([{ message: 'Not Found', status: '404' }]), '']) {
    const r = countMissing(prompt, { rules, runs: checkRunsPages(['codex-review']) })
    assert.notEqual(r.status, 0, `rules=${JSON.stringify(rules)}: 取得失敗なのに jq が成功している`)
    assert.equal(r.stdout.trim(), '', `rules=${JSON.stringify(rules)}: 取得失敗なのに数値が出力された`)
  }
})

// --- merge-guard hook の許可（読み取りのみ） ------------------------------------------------

test('3g の Bash ブロックは merge-guard hook で deny されない（読み取りのみ）', () => {
  const command = bashBlock(monitorPrompt(item, impl, [], true, true)).join('\n')
  const input = { tool_name: 'Bash', tool_input: { command }, agent_id: 'agent-1' }
  const out = execFileSync('bash', [HOOK], { input: JSON.stringify(input) }).toString()
  assert.equal(out.trim(), '', `hook が 3g のコマンドを止めた: ${out}`)
})
