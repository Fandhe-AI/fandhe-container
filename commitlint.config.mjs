// commitlint 設定。
//
// CI では Fandhe-AI/actions の lint-docs reusable workflow（commitlint）が
// `--extends @commitlint/config-conventional` 付きで PR の commit 範囲を検証し、
// 本ファイルのルールが extends 側を上書きする（agent-cli-skills の同名設定と同方針）。

// PR #1397 の bd28ab01 のコミットメッセージ全体（`ignores` で完全一致に使う。改行は LF）。
const BD28AB01_MESSAGE = [
  'fix(plugin): 確認用の外部コマンド待機に期限を設ける',
  '',
  'ps・kill の output()/status() が無期限に待つ問題を、spawn と try_wait の期限付きポーリング' +
    '（超過時は kill と有限時間の回収）に置き換える。Refs #1311 (REPAIR-5, PLUG-7)',
  '',
  'Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>',
].join('\n');

export default {
  rules: {
    // 日本語 subject は「Claude Code スキル体系を導入」のように英大文字始まりの
    // 固有名詞・識別子で始まることが多く、config-conventional の subject-case
    // （sentence-case 等の禁止）と構造的に衝突するため大文字小文字の検査は無効化する
    'subject-case': [0],
    // .claude/rules/conventional-commits.md が定義する 9 種類の type に限定する
    // （lefthook の commit-msg フック（正規表現）と検証範囲を揃える）
    'type-enum': [
      2,
      'always',
      ['feat', 'fix', 'refactor', 'perf', 'test', 'docs', 'ci', 'build', 'chore'],
    ],
  },
  // `git merge --no-edit`（origin/main 取り込み）が生成する既定のマージコミット
  // メッセージ（「Merge branch '...' into ...」等）は commitlint の
  // `defaultIgnores` により既に対象外のため、個別の ignore エントリは置かない
  // （下記の bd28ab01 は push 済みで直せない既知の違反に限った例外）。type-enum に無い独自 type（`merge:` 等）を使う
  // 過去コミットが将来見つかった場合は、その既知のコミットの subject 行（1 行目）
  // への完全一致でここへ追加する（`merge:` 接頭辞の正規表現のような包括的な
  // ignore にはしない。今後 subject 内容を問わず追加される任意の `merge: ...`
  // コミットまで恒久的に検証対象外にしてしまうため）。
  ignores: [
    // PR #1397（#1311）の bd28ab01。本文 1 行が 100 文字を超え body-max-line-length に
    // 違反するが、push 済みで force push（履歴の書き換え）を禁止しているため直せない。
    // 既知のメッセージ全体（末尾の改行を除く）との完全一致に限って対象外にする（subject・
    // 本文・footer のどこかが異なる新しいコミットは引き続き全ルールで検証する）。
    (message) => message.replace(/\n+$/, '') === BD28AB01_MESSAGE,
  ],
};
