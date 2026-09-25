// commitlint 設定。
//
// CI では Fandhe-AI/actions の lint-docs reusable workflow（commitlint）が
// `--extends @commitlint/config-conventional` 付きで PR の commit 範囲を検証し、
// 本ファイルのルールが extends 側を上書きする（agent-cli-skills の同名設定と同方針）。
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
  // `defaultIgnores` により既に対象外のため、本リポでは現時点で個別の ignore
  // エントリは不要（空配列）。type-enum に無い独自 type（`merge:` 等）を使う
  // 過去コミットが将来見つかった場合は、その既知のコミットの subject 行（1 行目）
  // への完全一致でここへ追加する（`merge:` 接頭辞の正規表現のような包括的な
  // ignore にはしない。今後 subject 内容を問わず追加される任意の `merge: ...`
  // コミットまで恒久的に検証対象外にしてしまうため）。
  ignores: [
  ],
};
