---
paths:
  - "Makefile"
  - "scripts/*.sh"
  - "scripts/targets/**"
---

# Makefile・scripts 編集規約（リポ固有）

フックから呼ぶスクリプト（`scripts/check-commit-msg-line-length.sh` とその自己テスト）と `lefthook.yml` は [git-hooks](git-hooks.md) の担当で、スクリプト自体の書き方（下記「新規スクリプトの規約」）以外は本書を適用しない。詳細な設計原則は make skill（`.claude/skills/make`）の `SKILL.md` と `references/architecture/` を参照する。

## 方針

- Makefile は **薄い入口**。各レシピは `@scripts/<path>.sh [args]` の 1 行呼び出しか、言語ネイティブの 1 コマンド（`docker compose build` 等）だけにする
- 複数行・`if`/`for`・`curl`・ツール導入・timeout や終了コードの変換などの処理は `scripts/` 配下の bash に書く。Makefile にチェック内容を二重定義しない
- 構成:
  - `scripts/targets/<target>.sh`: ターゲットの実体（入力は make 変数＝環境変数。必須変数と既定値は各スクリプト冒頭のコメントに書く）
  - `scripts/lib.sh`: 共通ヘルパー（`skip_unless_workspace`・`validate_timeout`・`require_cmd`・期限つき実行の `run_limited` と `run_limited_abort` 等）。source するとリポジトリルートへ移動する（利用者の相対パスを cwd 基準で扱うスクリプトは source 前に `$PWD` を保存して戻す）
  - `scripts/versions.sh`: 固定バージョン（lint ツール・cargo-deny・cargo-about・lefthook）の単一の定義元。`Dockerfile`・`ci.yml` の値と同期する
  - `scripts/with-tools.sh`（必須コマンド確認）・`scripts/with-workspace.sh`（workspace 未整備なら skip）・`scripts/run-parallel.sh`（CI 用の並列実行）・`scripts/help.sh`（Make 非依存の一覧）
  - それ以外の `scripts/*.sh`（`scripts/bench/` を含む）は既存の判定・計測スクリプトと自己テスト。Makefile から直接呼ぶ
- 入力は make 変数で渡す（`make fio-bench TARGET_DIR=... LABEL=...`）。コマンドラインの make 変数は環境変数としてレシピに渡るため、スクリプト側は同名の環境変数として読む。値はシェル文字列へ埋め込まず `"${VAR}"` の引用付きで参照する

## ターゲットを追加・改名・削除するとき

1. Makefile の `.PHONY` に追加（改名・削除なら更新）し、ターゲット行に `## 説明` を付ける（`make help` はこのコメントから生成される。`## ` が無いターゲットは表示されない）
2. 実体を `scripts/targets/<target>.sh` に書く（下記「新規スクリプトの規約」）
3. `scripts/help.sh` の一覧を同じ変更で更新する（`make help` との自動同期は無い）
4. 呼び出し元を洗い出して更新する: `git grep -n "make <target>" -- .github .claude docs README.md CLAUDE.md AGENTS.md lefthook.yml scripts`。CI（`ci.yml` の `make ...`）・`lefthook.yml`・ドキュメント・他スクリプトの自己テスト（`make` 経由で終了コードを照合するもの）が対象
5. `make help` で一覧を確認し、変更したターゲットを `make -n <target>` と実行で確認する。`shellcheck -x -P SCRIPTDIR scripts/*.sh scripts/targets/*.sh` と editorconfig-checker・markdownlint を通す

## 禁止・制約

- 中身の無いターゲット（`@true` 等）を置かない。呼び出し元が終了コードを信用してしまう。集約ターゲット（`ci`・`lint-docs`）は依存の列挙だけで、レシピを持たなくてよい
- GNU Make 3.81（macOS 標準）で動くこと。`.ONESHELL`・`.RECIPEPREFIX`・`$(file ...)` 等の 3.82 以降専用機能を使わない。`SHELL := /bin/bash` 前提（Windows は Git Bash の bash）
- 既存のターゲット名・変数名・終了コード・stderr の文言は維持する（CI・自己テストが照合している。例: `idle-memory` 系の `Error <n>` と `error: measurement-failed: ...`）。改名が必要なら呼び出し元も同じ PR で更新する
- skip メッセージは `skip:` で始める（[ci](ci.md) と AGENTS.md は「`skip:` が出たら異常・合格の根拠にしない」と定めている）
- 固定バージョンは `scripts/versions.sh` にだけ書き、`Dockerfile` と `ci.yml` の同期コメントを更新する。バージョンの追加・更新は[依存管理](dependency-policy.md)の承認制に従う

## 新規スクリプトの規約

- 先頭は `#!/usr/bin/env bash` と役割コメント（日本語。呼び出し元・入力・終了コードの契約を書く）。`set -euo pipefail` を付け、`scripts/lib.sh` を source する（`# shellcheck source=` ディレクティブ付き）
- `scripts/lib.sh` の判定（`has_cargo`・`has_members`・`skip_unless_workspace`・`run_limited`）を変えたら `make lib-selftest`（`scripts/lib-selftest.sh`。PATH の bash と `/bin/bash` の両方で照合する）を通し、ケースを追加する
- 実行権限を付ける（`chmod +x`。git の mode 100755）。Makefile は `@scripts/...` で直接実行するため、権限が無いと失敗する
- shellcheck をエラー・警告なしで通す。macOS 標準の bash 3.2 でも動く書き方にする（`local -n`・連想配列・`wait -n`・`${var,,}` を使わない。空配列の展開は `${arr[@]+"${arr[@]}"}`）。例外は CI 専用の `scripts/run-parallel.sh`（bash 4.3 以上）
- プログラムの出力文字列（エラーメッセージ・ログ）は英語、コメントは日本語（[japanese-style](japanese-style.md)）
- 引数を取らないスクリプトは未知の入力を黙って無視せず usage を出して終了コード 2 にする。必須入力の不足も 2。想定外の失敗は fail-closed（無言で成功扱いにしない）
- 一時ファイル・ディレクトリは `mktemp` で作り `trap` で必ず削除する。リポジトリ内のファイルを書き換えない（出力先は引数・`target/` 配下）

## ターゲットの契約（このリポジトリに実在するもの）

| 種別 | ターゲット | 契約 |
| ---- | ---------- | ---- |
| 読み取り専用の検査 | `lint-*`・`fmt-check`・`lint`・`doc`・`test`・`check-*`・`deny`・`*-selftest` | ソースを変更しない。失敗は非 0 で返す。`*-selftest` は一時ディレクトリ・スタブ・fixture だけを使い、実機・root・ネットワークに依存しない |
| 整形 | `fmt` | `cargo fmt --all` でソースを書き換える唯一のターゲット。検査用は `fmt-check` |
| 環境構築 | `setup`・`hooks`・`install-cargo-about` | 再実行しても安全（冪等）。`rustup` は確認のみで自動導入しない（`curl \| sh` を作らない。[security](security.md)） |
| 取得と実ビルド | `guest-kernel-build`・`guest-initrd-build` | `guest-kernel-build` はネットワーク取得と実ビルド（#1874）、`guest-initrd-build` はネットワーク取得なしのローカルの実ビルド（ゲスト init の静的リンクと initrd の梱包。#1878）を行う人間用のターゲット。`make ci` と CI には含めない。成果物は `target/` 配下へ出し、既存の出力は上書きしない |
| 生成 | `third-party-licenses`・`bench-baseline`・`bench-baseline-manual` | 出力先は `target/` 配下か `OUTPUT` / `BENCH_BASELINE_OUT` で指定した 1 ファイルのみ |
| 実機前提 | `bench-check-manual`・`cli-parity`・`fio-bench`・`startup-latency*`・`net-setup-timing`・`net-throughput-rtt*`・`small-files-compare`・`dns-helper-measure`・`idle-memory*`・`supervisor-*`・`concurrent-memory*`・`restart-latency`・`crictl-smoke` | `make ci` に含めない。必須変数が無ければ usage を出して終了コード 2。sudo をスクリプト内で呼ばない（root 実行は操作者の明示操作）。timeout で包み、終了コードは契約の値へ変換する |
| 集約 | `ci` | ワークスペース全体の任意の一括確認（CI の失敗の再現・リリース前。ローカル必須ではない。[ci](ci.md)「ローカルゲート」）。CI 全体とは同一ではない |

- `clean` ターゲットは無い。追加する場合は `target/` など自分が作った生成物だけを消し、共有ディレクトリ（`$HOME`・リポジトリ外・`docs/spec` submodule）を消さない
- cargo 系ターゲットは `Cargo.toml` 未追加・member crate 無しなら `skip:` を出して成功終了する（冪等セルフヒール。`scripts/lib.sh` の `skip_unless_workspace`）
