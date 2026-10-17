# fandhe-container への貢献

`fandhe-container` は Rust でフルスクラッチ開発する軽量なコンテナ実行基盤です（TASK-2・`OSS-1`・`OSS-2`・MS-0）。本ドキュメントはコントリビュータ向けの入口です。

## 体制・連絡

意思決定・レビュー体制は [MAINTAINERS.md](./MAINTAINERS.md) を参照してください。Issue / PR で連絡を受け付けます。

## PR フロー・レビュー基準

PR フローとレビュー基準は TASK-99（[#654](https://github.com/Fandhe-AI/fandhe-container/issues/654)・`OSS-6`・MS-6）のオーナー決定（2026-10-15）に沿って運用します。

### PR フロー

1. Issue を起点にする。作業は TASK-n に対応する Issue から始めます。スコープ外の事項は [out-of-scope-tracking](./.claude/rules/out-of-scope-tracking.md) に従い、別 Issue に切り出します。
2. main から作業ブランチを切る。
3. Conventional Commits 形式でコミットする。形式は `<type>(<scope>): <日本語の説明>` で、type は `feat`・`fix`・`refactor`・`perf`・`test`・`docs`・`ci`・`build`・`chore` の 9 種です。scope は crate の短縮名に合わせます（[crate-naming](./docs/design/crate-naming.md)）。1 コミットに複数の関心事を混在させません。`git commit --no-verify` は使わず、commit-msg フックの検査を通します（詳細は [conventional-commits](./.claude/rules/conventional-commits.md)）。
4. ローカルで変更範囲の確認を行う。`make fmt` で整形し、変更した crate について `cargo clippy -p <パッケージ名> --all-targets -- -D warnings` と `cargo test -p <パッケージ名>` を通します。`<パッケージ名>` は `fandhe-container-<短縮名>` です。共有の型・公開トレイト・`Cargo.toml`・feature・`cfg` を変えた場合は `cargo check --workspace --all-targets` も通します。ワークスペース全体の検証は CI が担います（[ci](./.claude/rules/ci.md)「ローカルゲート」）。
5. PR を作る。PR 本文には次を記載します。
   - タイトルは Conventional Commits 形式にします。
   - 関係する TASK-n・ビヘイビア ID を併記します（[spec-reference](./.claude/rules/spec-reference.md)）。
   - 依存の追加・`unsafe` の追加・ライセンス判断を含む場合は、後述「承認が要る変更」の記録を入れます。
   - 実機前提テストは、実機での実行結果を記録します（[ci](./.claude/rules/ci.md)「実機前提テスト」）。
6. CI と AI レビューの結果を待つ。
   - CI の必須チェックは、ruleset に登録された check-run がすべて通ることを条件とします（[ci](./.claude/rules/ci.md)「3 OS CI」）。
   - PR では macOS・Windows のネイティブ実行を行わず、型検査（`cross-target-check`）で代えます。ネイティブ実行は main への push 後に 3 OS で行われます。
   - AI レビューは `ai-review` ワークフローの Codex と Cursor Bugbot が行います。
7. メンテナが承認し、squash merge する。

### レビュー基準

マージの条件は次の 2 つです。

- CI の全必須チェックの通過
- メンテナ（オーナー）1 名の承認

AI レビュー（`ai-review` の Codex と Cursor Bugbot）は併用します。P0 の指摘は修正するまでマージしません。P1 の指摘は修正するか、対応が不要な理由をスレッドに書いて resolve してからマージします。優先度（P0・P1・P2）の定義は [AGENTS.md](./AGENTS.md)「優先度定義」を参照してください。

レビューで見る観点は [AGENTS.md](./AGENTS.md)「レビュー観点」の観点集が正です。AI レビューも同じ観点集を読みます。AGENTS.md への変更はマージ後の次の PR から効きます。

spec（OSS-6）は承認者の例として「CI 全通過＋レビュアー 2 名承認」を挙げています。今回は立ち上げ期の体制に合わせて 1 名にしました。現在のメンテナは 1 名です（[MAINTAINERS.md](./MAINTAINERS.md)）。メンテナが増えた時点で人数の条件を見直します（[#654](https://github.com/Fandhe-AI/fandhe-container/issues/654) の決定）。

### 承認が要る変更

次の変更は、実装の前にメンテナの承認を経ます。

- 依存の追加・更新: `=x.y.z` で完全固定し、承認を得ます（[dependency-policy](./.claude/rules/dependency-policy.md)）
- ライセンス判断: 補助 crate のデュアルライセンス化、コピーレフト系の依存の扱い（[licensing](./.claude/rules/licensing.md)）
- `unsafe` の追加: `sys` モジュール（syscall・ioctl・FFI のラッパー）の外の `unsafe` は個別承認が必要です。`sys` モジュール内の追加は事前承認の範囲で、PR 本文に記録が必要です（[coding-rust](./.claude/rules/coding-rust.md)「unsafe・FFI・syscall」）
- spec（SSOT）の変更: 本リポでは `docs/spec` を編集しません。spec リポ側の変更はメンテナの承認を経ます（[spec-reference](./.claude/rules/spec-reference.md)・[MAINTAINERS.md](./MAINTAINERS.md)「コアチームの権限」）

### セキュリティ

- 秘密情報（実トークン・レジストリ資格情報・API キー・接続資格情報）をコード・テスト・fixture・ドキュメント・設定へ含めません。例示はダミー値に限ります。`.env` 等の資格情報ファイルもコミットしません（[security](./.claude/rules/security.md)）。
- コンテナ分離（namespace・capability・seccomp・Landlock 等）と plugin 境界（UDS・plugin の登録）に触れる変更は、PR を作る前に OWASP Top 10 とあわせて分離・plugin 信頼境界の観点で確認し、結果を PR 本文に記載します（[security](./.claude/rules/security.md)）。
