---
paths:
  - ".github/workflows/**"
---

# GitHub Actions 編集規約（リポ固有）

CI の構成・段階ゲート・3 OS 方針・実機前提テストの扱いは [ci](ci.md)、フックとの役割分担は [git-hooks](git-hooks.md)、Makefile・scripts の規約は [makefile](makefile.md) を参照する。本書はワークフロー（`ci.yml`・`ai-review.yml`・`update-external.yml`・`release.yml`・`linux-env-probe.yml`）を編集するときの規約。

## runner 方針

本リポジトリは **public**。public は GitHub ホステッド runner を使う（組織方針: Fandhe-AI/actions の `docs/runner-policy.md`）。private リポジトリは self-hosted が正だが、本リポジトリには該当しない。

| ワークフロー | runner | 理由・備考 |
| ------------ | ------ | ---------- |
| `ci.yml` | `ubuntu-latest`（`platform-ci` は main への push と `workflow_dispatch` で `macos-latest`・`windows-latest` も） | macOS・Windows のネイティブ実行は OS 要件（[ci](ci.md)「3 OS CI」）。PR では使わない（macOS の同時実行枠待ちで CI が詰まったため） |
| `update-external.yml`・`release.yml` | `ubuntu-latest` | |
| `linux-env-probe.yml` | `ubuntu-24.04`・`ubuntu-22.04`・`ubuntu-24.04-arm` | ホステッド runner の KVM・sudo 可否の実測が目的（OS 要件） |
| `ai-review.yml`（`codex / review`） | self-hosted（codex 専用ラベル。呼び出し先 reusable の既定値） | 例外。資格情報を扱うため専用 runner を使う。fork PR は reusable 側が fail-closed で拒否する。`preflight`・`post_feedback` は `ubuntu-latest` |

- **public リポジトリで self-hosted を使うと、fork PR 経由で任意コードが self-hosted 上で実行されるリスクがある**。新たに self-hosted を使うジョブを足さない。`pull_request_target` も使わない（fork からの secrets 露出を防ぐ）
- 既存の例外（`codex / review`）を変更する場合は、fork PR を拒否するガードが維持されていること（`Fandhe-AI/actions` の `ai-review/README.md`）を確認し、ユーザー判断を仰ぐ
- runner の種別・ラベルや Actions 設定の変更はリポジトリ設定の変更でありオーナー作業

## 必須チェック（ruleset `main-protection`）と集約ジョブ

必須チェック（2026-10-11 時点。`gh api repos/Fandhe-AI/fandhe-container/rulesets/<id>` の `required_status_checks`。branch protection は未設定）:

- `ci-complete`（集約ジョブ）・`bench-regression`・`platform-ci (ubuntu-latest)`・`cross-target-check`
- `lint-docs / commitlint`・`lint-docs / editorconfig-checker`・`lint-docs / lint-docs-complete`・`lint-docs / markdownlint`・`lint-docs / yamllint`
- `rust-ci (ubuntu-latest) / cargo clippy`・`... / cargo deny check`・`... / cargo fmt --check`・`... / cargo test`・`... / rust-base-ci-complete`
- `codex / preflight`・`codex / review`・`codex / post_feedback`（`ai-review.yml`）と外部 App の `Cursor Bugbot`

- ジョブ ID・`name:`・matrix の値を変えると check-run 名が変わる。**改名・追加・削除は ruleset の更新が必要**（リポジトリ設定のためオーナー作業）。旧名が必須のまま残ると新しい check-run が報告されず全 PR がマージ不能になり、新しいジョブが未登録だと implement-issue-tree の自動マージ前ゲート（PR 上の全 check-run が必須チェックに含まれること）で止まる
- このため **新しいジョブ・ワークフローを増やさず、既存ジョブのステップとして足す**のが既定（`ci.yml` の各ステップのコメントにも同じ理由がある）
- `ci-complete` は `lint-docs`・`rust-ci`・`platform-ci`・`bench-regression`・`cross-target-check` の `needs` 結果を fail-closed で検証する。ジョブを足したら `needs` にも追加する（漏れると失敗が反映されない）。skipped を許容するジョブは `allow_skipped` に明示する（現状は空）

## 発火条件

- `ci.yml`: `pull_request`・`push`（main のみ）・`workflow_dispatch`。push を default ブランチのみにして、PR ブランチの push と `pull_request` の二重実行を避ける（新しいワークフローも同じ）
- `concurrency` は `group: ${{ github.workflow }}-${{ github.event.pull_request.number || github.ref }}` と `cancel-in-progress: true`。PR 番号を含めるのは fork 間の同名ブランチの別 PR が互いを cancel しないため。main への push は新しい push が古い実行を取り消す（オーナー承認の挙動。[ci](ci.md)「3 OS CI」）。cancel してはいけない実行（release 等）は `cancel-in-progress: false` にする（`update-external.yml`・`release.yml`）
- **`paths` / `paths-ignore` を、必須チェックを含むワークフローに付けない**。ワークフローが起動しないと必須チェックが pending のままになり、永久にマージできない。docs だけの変更で重い CI を省きたい場合は、ワークフロー単位の `paths` ではなく、ジョブ内で変更検知（`git diff` 等）して重いステップを `if:` で飛ばし、skipped を `ci-complete` の `allow_skipped` で許容する（新しい検知ジョブは check-run が増えるため ruleset の更新が要る。ユーザー判断事項）。必須チェックを含まないワークフロー（`linux-env-probe.yml` は `paths` で自身の変更時のみ）は `paths` を使ってよい
- draft PR をスキップする場合は `pull_request` の `types` に `ready_for_review` を含める。ただし draft のとき `ci-complete` が skipped になり必須チェックを満たさなくなる点に注意（本リポジトリは draft を除外していない）
- `schedule` は必要最小限の頻度にする（現状は `update-external.yml` の日次 1 回のみ）。手動のみのもの（`release.yml`・`linux-env-probe.yml`）に `schedule` を足さない
- `${{ }}` は `run:` に直接埋め込まず `env:` 経由で渡す（スクリプトインジェクション対策）。`permissions` は最小（`contents: read`）にする

## ジョブ・ステップを追加するときのチェックリスト

1. 既存ワークフローの既存ジョブにステップとして足せないか（ワークフロー数・check-run 名を増やさない）。足すなら ruleset と `ci-complete` の `needs` への影響を確認する
2. ロジックを YAML に書かず、`make <target>` か `scripts/` のスクリプトを呼ぶ（ローカルと CI で同じコマンドにする。[makefile](makefile.md)）。CI 専用のロジックが要る場合も複数行 `run:` を避けてスクリプトへ
3. フック（lefthook）と同じ検査を CI に重複させない／逆にフックへ CI の検査を移さない（[git-hooks](git-hooks.md)）
4. 直列の `needs` チェーンを作らない。独立なステップは並列にする。1 ジョブ内の独立した重い自己テストは `scripts/run-parallel.sh <並列数> <make-target>...` で並列化できる（経過秒を照合するテストがあるため並列数は 3 程度に絞る）。逆に、セットアップ（checkout・toolchain・キャッシュ復元）が支配的な小さいジョブは分けずに統合する
5. キャッシュ: 下の「キャッシュ方針」に従う。ソースビルドで導入するツールは `actions/cache` でバイナリを引き継ぐ（`platform-ci` の cargo-deny・cargo-about。key は `scripts/versions.sh` のハッシュ）。`platform-ci` などの `target/` のキャッシュは未導入（導入するなら prune と容量を確認し、別途判断する）。`fetch-depth` は既定の 1 を維持し、履歴が要るステップだけ fetch する（`plug4-core-invariance` の例）
6. action は **SHA 固定＋バージョンコメント**（`uses: owner/repo@<40 桁 SHA> # vX.Y.Z`）。`@latest` が許されるのは `Fandhe-AI/actions` のみ。新しい action は信頼できる配布元（GitHub 公式・組織内）に限り、既存と同じ版を使う。action の版の更新は本規約の範囲外
7. `timeout-minutes` を必ず付ける（ハング時の多層防御。NFR-10）。reusable workflow を呼ぶジョブには付けられないので上流の契約に任せる
8. 変更後は `actionlint .github/workflows/*.yml`（無ければ YAML の構文確認）と `yamllint` を通す。PR 上で CI を走らせ、変更前後の所要時間とジョブ数を PR 本文に書く
9. 所要時間の目安（2026-10-11 実測の PR 中央値）を超えて遅くしない: 下表

## 計測方法と実測値

```bash
gh run list --workflow ci.yml --limit 30 --json databaseId,conclusion,createdAt,updatedAt,event
gh run view <run-id> --json jobs --jq '.jobs[] | "\(.name)\t\((.completedAt|fromdate)-(.startedAt|fromdate))s"'
```

`createdAt`〜`updatedAt` は待ち行列を含む wall-clock。ジョブ単位は `jobs[].startedAt/completedAt`、ステップ単位は `jobs[].steps[]`。

2026-10-11 の棚卸し結果（直近 30 件、成功・失敗のみ。変更前）:

| ワークフロー | トリガー | wall-clock 中央値（最大） | 備考 |
| ------------ | -------- | ------------------------- | ---- |
| `ci.yml` | pull_request（18 件） | 585 秒（723 秒） | 最長は `platform-ci (ubuntu-latest)` 約 700 秒、次に `bench-regression` 約 325 秒 |
| `ci.yml` | push main（4 件） | 710 秒（738 秒） | `platform-ci` が macOS 約 595 秒・Windows 約 556 秒を含む |
| `ai-review.yml` | pull_request（30 件） | 115 秒（167 秒） | 失敗 8 件は指摘による |
| `update-external.yml` | schedule（16 件） | 113 秒（141 秒） | |
| `linux-env-probe.yml` | pull_request（4 件） | 36 秒（39 秒） | 自身の変更時のみ |
| `release.yml` | 手動のみ | 実績 0 件 | |

変更前の `platform-ci (ubuntu-latest)` の長いステップ: `cargo test`（既定 feature）162 秒・venus 治具の cargo deny 111 秒（cargo-deny のソースビルド）・cargo about 107 秒（同）・結合試験 84 秒・cli 期限・回収の自己テスト 89 秒。`bench-regression` は自己テスト合計約 250 秒（concurrent-memory 125 秒・supervisor-independence 52 秒・startup-latency 40 秒）。変更後の実測は PR 本文を参照。

reusable workflow の `rust-ci (ubuntu-latest) / cargo deny check`（約 120 秒）は `Fandhe-AI/actions` 側が cargo-deny をソースビルドしている。短縮は上流側の変更になる。

## キャッシュ方針

Actions のキャッシュはリポジトリあたり **10 GB** が上限で、超えると最終アクセスの古いものから追い出され（LRU）、7 日間アクセスの無いものは削除される。上限超過分の課金の予算は $0 のため、**10 GB の中でヒット率を保つ**ことを目的にする。

| キャッシュ | 場所 | key | 中身・サイズ（2026-10-11） |
| ---------- | ---- | --- | -------------------------- |
| `fandhe-container-<os>-clippy-v3-*`・`-test-v3-*` | `rust-ci`（reusable `rust-base-ci` の `cache: true`） | `Cargo.lock` のハッシュ（[#165](https://github.com/Fandhe-AI/actions/pull/165) 以降は `-v4-<rustc -vV のハッシュ>-<ルート Cargo.lock のハッシュ>`）。`restore-keys` は前方一致 | `~/.cargo/registry`・`target`（workspace メンバーの成果物は保存前に prune）。各 105〜145 MB |
| `fandhe-container-<os>-deny-*` | 同上の deny ジョブ | 同上 | `~/.cargo/registry` のみ。30〜41 MB |
| `cargo-tools-Linux-*` | `platform-ci`（ubuntu のみ） | `scripts/versions.sh` のハッシュ | cargo-deny・cargo-about のバイナリ。10 MB |

- **保存は main の push だけにし、PR は restore のみにする**（大きい blob が対象）。PR の cache は `refs/pull/<N>/merge` スコープに保存され、他の PR・main からは読めない。`Cargo.lock` を変えた PR や、main の保存より先に走った PR が main と同内容の blob を PR ごとに重複保存し、容量を消費する。`rust-ci` は reusable の `cache-save` 入力（`Fandhe-AI/actions` [#165](https://github.com/Fandhe-AI/actions/pull/165) で追加。マージ後に `cache-save: ${{ github.ref == 'refs/heads/main' }}` を渡す）、自前の `actions/cache` は `actions/cache/restore` と、main だけで走る `actions/cache/save` に分ける
- 例外: 版だけで決まる小さいツールのバイナリ（`cargo-tools-Linux-*`）は既定の保存のままでよい。PR に重複が出るのは `scripts/versions.sh` を変えた PR だけで、main の `platform-ci` は concurrency の取り消しで保存まで届かないことがあるため、PR 側で保存できるほうが再ビルド（約 220 秒）を避けられる
- **key には中身を決める入力だけを入れる**。SHA・`run_id`・日付など毎回変わる値を入れない（再利用されない blob が溜まる）。ハッシュの入力は必要なファイルに絞る（`**/Cargo.lock` は `.agents/skills/make/samples/**`（`.claude/skills` の symlink 経由も）や `poc/venus-decoder/jig` の `Cargo.lock` の変更でもキーを変える。#1758 でスキルのサンプルが入っただけで clippy・test・deny のキーが変わった。reusable は [#165](https://github.com/Fandhe-AI/actions/pull/165) でルートの `Cargo.lock` だけにした）。`target/` のようにコンパイラの版で中身が変わるものは key に rustc の版（`rustc -vV` のハッシュ）を入れる。`rust-toolchain.toml` は stable 追従のため runner イメージの更新で rustc が変わり、key に無いと旧 rustc の blob に exact hit し続けて依存を毎回全再ビルドし、exact hit のため保存もされない（#165 で対応）
- `restore-keys` で前方一致の部分復元を必ず効かせる（key が変わっても cold にしない）。追い出しが起きても、最新の main の blob は毎回アクセスされるため LRU の最後まで残り、ヒットは続く
- OS・ジョブをまたいで中身が同じなら key を共有する。中身が OS で変わるものは `runner.os` を入れる。使わなくなった key（2026-10-10 のジョブ再構成で `rust-ci` が ubuntu のみになった後の `fandhe-container-macOS-*`）は 7 日で消えるのを待つか、`gh cache delete` で消す
- 新しいキャッシュを足すときは、blob サイズ × key が変わる頻度（1 日あたり）× 7 日 で容量を見積もり、他のキャッシュと合わせて 10 GB に収まることを確かめる。復元時間が節約時間より長いジョブにはキャッシュを付けない

計測方法:

```bash
gh api repos/Fandhe-AI/fandhe-container/actions/cache/usage
gh api --paginate "repos/Fandhe-AI/fandhe-container/actions/caches?per_page=100" \
  --jq '.actions_caches[] | [.key, .ref, .size_in_bytes, .created_at, .last_accessed_at] | @tsv'
# ジョブごとのヒット（exact は "Cache hit occurred on the primary key"、部分復元は
# "Cache restored from key" が primary key と異なる、miss は "Cache not found"）と保存の有無
gh api repos/Fandhe-AI/fandhe-container/actions/jobs/<job-id>/logs \
  | grep -E "Cache (restored from key|not found|saved with key|hit occurred)|Cache Size"
```

2026-10-11 の実測（変更前。main の push 5 件・PR 14 件の `rust-ci` の clippy・test・deny 57 ステップ）:

- 使用量 5.4 GB・177 件（上限の約半分）。最古の blob は 7 日前で、追い出しは起きていない。miss は 0 件（exact hit 39・部分復元 18）。部分復元は `Cargo.lock` を変えた PR と、main の保存前に走った PR
- 件数が多い原因は、`Cargo.lock` が 8 日で 14 回変わり（workspace 内の依存追加でも変わる）、そのたびに main と PR の両方で新しい key を保存していたこと。PR スコープの blob が約 3.1 GB（約 6 割）で、同じ key の blob が main と PR 3 件で 4 重に保存された例がある（#1759 のマージ直後）。macOS の blob（約 1.4 GB）は 2026-10-10 以降どのジョブも読まない
- #1759（gRPC のコード生成）以降、blob は clippy 30→105 MB・test 45→120 MB に増えた。この増え方で key が 1 日 2 回変わり PR の重複も続くと、7 日分で 10 GB に近づく
- `cargo-tools-Linux-*`（#1756）は main の保存（run 38119539753）以降の PR がすべて exact hit し、`platform-ci (ubuntu-latest)` は約 590〜700 秒から約 360〜430 秒になった
- `rust-ci / cargo deny check`（約 100〜130 秒）の大半（84 秒）は cargo-deny のソースビルド。[#165](https://github.com/Fandhe-AI/actions/pull/165) で reusable がバイナリを cache するようにし、検証用 PR（#1763）で約 93 秒 → 10 秒になった
