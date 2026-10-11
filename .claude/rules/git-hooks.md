---
paths:
  - "lefthook.yml"
  - "scripts/check-commit-msg-line-length.sh"
  - "scripts/check-commit-msg-line-length-selftest.sh"
---

# Git hooks（lefthook）編集規約（リポ固有）

## 目的

フックはコミットのたびに実行されるため、遅いフックはそのまま開発速度の低下になる。
フックはローカルでの早期検知専用であり、CI の代替ではない。**開発速度を落とさないことを最優先**し、
重い検査・網羅的な検査は CI（`.github/workflows/ci.yml`）に任せる。

ローカルゲート（`make ci`。[ci](ci.md)）の規約自体は変わらない。フックで強制しないだけで、
コミット・PR 前に `make fmt-check`・`make lint`・`make test`・`make doc`（まとめて `make ci`）を通す運用は維持する。

## 時間予算

| フック | 予算 | 判定方法 |
| --- | --- | --- |
| pre-commit | 通常のコミット（staged 数ファイル）で全ジョブ合計 1 秒未満 | `lefthook run pre-commit`（stage した状態で実行）の `summary: (done in N seconds)` |
| pre-commit（最悪ケース） | 下記「明示的な例外」の rustfmt-check を除き合計 1 秒未満 | `lefthook run pre-commit --all-files` の各ジョブの秒数 |
| commit-msg | 即時（ネットワーク不可。`scripts/` のシェルスクリプト呼び出しまで） | 実コミット時に表示される commit-msg の summary（メッセージファイルを引数に取るため `--all-files` では計測しない） |
| pre-push・post-checkout・post-merge 等 | 原則追加しない | 追加する場合は理由と実測値を PR 本文に記載する |

`--all-files` は全追跡ファイルを対象にする最悪ケースであり、実際のコミット（staged のみ）はこれより速い。
secrets-content-guard は staged diff（`git diff --cached`）を走査するため `--all-files` では計測できない。
変更時は大きめの diff（数千行）を stage して `lefthook run pre-commit` で計測する。

## フックに置かないもの（→ `ci.yml` へ）

- `cargo build`・`cargo clippy`・`cargo test`・`cargo doc`・`cargo deny`（`make lint` / `make test` / `make doc` / `make deny` を含む）
  - 既定 feature: `platform-ci` ジョブ（PR は ubuntu・main は 3 OS）が `make lint` / `make test` と同一コマンドと `make doc` を実行する
  - `--all-features`・fmt・deny: `rust-ci` ジョブ（reusable `rust-base-ci`）
  - macOS・Windows・aarch64 向けの型検査: `cross-target-check` ジョブ
- リポジトリ全体を走査する lint / fmt チェック（`cargo fmt --all --check`・`make lint-docs` 全体の呼び出しを含む。lint-docs は `lint-docs` ジョブが担う）
- 依存パッケージのインストール・ネットワークアクセス（`npx` 経由の commitlint 等。正式な commitlint は `lint-docs` ジョブと `make lint-commits` が担う）
- `ci.yml` のジョブと同じコマンドを同じ範囲で実行するもの
- フックスクリプト自体のテスト（`make commit-msg-line-length-selftest`）。`platform-ci` ジョブのステップとして実行する

## フックに置いてよいもの

- `{staged_files}` に限定し、`glob` で対象を絞った 1 秒未満の検査
- CI ではコミット単位で検知できない、または push 後では遅いもの
  - secrets-guard / secrets-content-guard: 秘密情報は push 前に止める必要がある（CI に同等の検査は無い。
    サーバー側の最終防御線は GitHub の secret scanning + push protection。[security](security.md)）
  - commit-msg（正規表現と `scripts/check-commit-msg-line-length.sh`）: CI の commitlint は PR 単位で、
    コミット作成時には検知できない

### 明示的な例外

- pre-commit の rustfmt-check は `rust-ci` ジョブの fmt（`cargo fmt --all --check`）と重複するが、
  staged の `*.rs` に限定しており通常のコミットでは十分速いため維持する（2026-10-11 計測・決定）
  - 計測値: 末端モジュール 5 ファイルの stage で 0.07 秒、`lib.rs` 3 ファイルの stage で 0.53 秒、
    `--all-files`（486 ファイル）で約 2.6 秒
  - rustfmt は `mod` 宣言をたどって子モジュールも検査するため、`lib.rs` を stage すると crate 全体が対象になり遅くなる
  - 整形は PostToolUse フック・`make fmt` で済んでいる想定で、コミット時に整形漏れを止めると CI の待ち時間を節約できる

## 書き方の規約

- `pre-commit` の `parallel: true` を維持する（直列化しない）
- `{staged_files}` と `glob` で対象を絞る
- cargo 系ジョブは `Cargo.toml` 未追加・ツール未導入なら `skip:` を出して成功終了する（`scripts/lib.sh` の `skip_unless_workspace` の判定と同一方針）
- diff の行数・ファイル数に比例してプロセスを起動するループを書かない。awk / grep を 1 回だけ起動して一括で判定する
  （行 × パターンごとに grep を起動していた旧 secrets-content-guard は 3000 行の diff で約 47 秒、
  ファイルごとに grep を起動していた旧 secrets-guard は `--all-files` で約 7 秒かかった）
- 秘密情報の検査は fail-closed にする（diff の取得・抽出に失敗したら検査済み扱いにせず拒否する。
  grep の終了状態 2 以上〔検査エラー〕を「一致なし」と同一視しない）
- 利用者の環境で出力・挙動が変わらないようにする（`git diff` に `--no-color --no-ext-diff --no-renames` を付ける。
  非 UTF-8 の内容で BSD awk / grep が異常終了しないよう `LC_ALL=C` で実行し、grep は `-a` を付ける）
- 実体が長くなる場合は `scripts/` へ切り出し、`lefthook.yml` は呼び出しのみにする（例: `scripts/check-commit-msg-line-length.sh`）
- 条件付き実行が必要な場合は lefthook の `skip` / `only` を使ってよい
  （`.claude/skills/lefthook/references/examples/skip.md`）

## 検査を追加するときの判断手順

1. その検査は `ci.yml` で既に実施されているか
    - 実施済みで、staged 限定にしても 1 秒以上かかる → フックに入れない
2. staged ファイルに限定できるか
    - できない → CI へ置く
3. CI へ置く場合は既存ジョブ（`platform-ci` 等）のステップとして追加する
    - フックスクリプトを追加・変更したら、その自己テストも `platform-ci` のステップに置く
    - ジョブを増やすと check-run 名と ruleset の必須チェックに影響するため、[ci](ci.md)「3 OS CI」の方針に従う
    - 新しいジョブを追加する場合は、集約ジョブ `ci-complete` の `needs` にも必ず追加する
4. 編集後に以下を実行し、summary の合計時間をユーザーへ報告する（予算を超えるなら構成を見直す）

```bash
time lefthook run pre-commit --all-files
```

## 手元で CI 相当を確認する

フックで強制しない検査は、必要に応じて手元で実行する。

```bash
make ci        # lint-docs・check-workspace-manifest・fmt-check・lint・test・doc・deny を一括実行
make lint      # cargo clippy（既定 feature）
make test      # cargo test（既定 feature）
```

## バイパス禁止

遅いからといって `--no-verify` や `LEFTHOOK=0` で回避しない。遅いフックはフック側を直す
（検査を CI へ移す・staged 限定にする・対象 glob を絞る・プロセス起動を一括にする）。
