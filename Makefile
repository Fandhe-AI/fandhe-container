# fandhe-container の開発タスクランナー。
#
# `make setup` 一発で開発環境（サブモジュール・rustup・lefthook）を構築し、
# `make ci` でローカル検証（.claude/rules/ci.md のローカルゲート）を一括実行する。
# 実装は未着手（`crates/` 配下に実クレート未追加）のため、cargo 系ターゲットは
# HAS_CARGO / HAS_MEMBERS 判定でスキップし、workspace 作成後に自動で有効化される
# （冪等セルフヒール。deny も deny.toml + Cargo.toml + メンバー crate が揃った
# 時点で有効化）。
# Docker で環境非依存に開発・検証する場合は docker-* ターゲットを使う（compose.yaml 参照）。
# Fandhe-AI/rust-ai-library の Makefile と同一方針。

.DEFAULT_GOAL := help
SHELL := /bin/bash

# Cargo.toml の有無（無ければ cargo 系をスキップ。workspace 作成後に有効化）
HAS_CARGO := $(wildcard Cargo.toml)
HAS_DENY := $(wildcard deny.toml)
# workspace のメンバー crate（`crates/*/Cargo.toml`）の有無。member crate が
# 1 つも無い仮想 workspace（`members = []`）に対しては `cargo fmt --all --check`・
# `cargo clippy --workspace`・`cargo test --workspace`・`cargo tree --workspace`・
# `cargo deny check ...` のいずれも「対象パッケージが無い」エラーで落ちる
# （cargo の仕様。実機検証済み。フォーマット・lint・テストの対象コードが
# 実在しないため妥当な失敗であり、これらのターゲットは HAS_MEMBERS でスキップする）。
# 一方 Cargo.toml 自体の構文・workspace 定義としての妥当性は member の有無に
# 依存せず常に検証可能なため、`check-workspace-manifest`（下記）は HAS_CARGO のみで
# 判定し、root Cargo.toml の追加直後〜最初の crate が追加されるまでの
# 中間状態でも Cargo.toml の妥当性検証をスキップしない。
HAS_MEMBERS := $(wildcard crates/*/Cargo.toml)

# lint ツールの固定バージョン。CI（Fandhe-AI/actions の lint-docs reusable workflow）の
# 既定値に合わせる（CI 側が正。乖離したらこちらを追従させる）。
# EC_NPM_VERSION のみ npm ラッパーパッケージの版（CI は Go バイナリ release タグ v3.8.0 を
# 直接取得するため版番号体系が異なる。ローカル再現用の近似として npm 最新安定を固定する）。
MARKDOWNLINT_VERSION := 0.49.1
YAMLLINT_VERSION := 1.38.0
EC_NPM_VERSION := 6.1.1
COMMITLINT_VERSION := 21.2.1
COMMITLINT_CONFIG_VERSION := 21.2.0

# 導入系ツールの固定バージョン（`=x.y.z` 完全固定方針に合わせ exact 固定。
# CARGO_DENY_VERSION は Dockerfile の先行導入と値を同期させる）。
LEFTHOOK_VERSION := 2.1.10
CARGO_DENY_VERSION := 0.20.2

.PHONY: help
help: ## ターゲット一覧を表示する
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-24s\033[0m %s\n", $$1, $$2}'

# --------------------------------------------------
# 環境構築
# --------------------------------------------------

# 依存ターゲット並記だと -j 実行時に順序が保証されず、cargo フォールバックを持つ hooks が
# rustup より先に走りうるため、再帰 make で「submodule → rustup → hooks」の順を明示する
# （rust-ai-library と同一方針）。
.PHONY: setup
setup: ## 開発環境を一括構築する（サブモジュール → rustup → lefthook の順を保証）
	$(MAKE) submodule
	$(MAKE) rustup
	$(MAKE) hooks
	@echo "setup 完了"

# rustup は前提条件として確認のみ行い、自動導入はしない。取得したインストーラを検証なしに
# 実行する経路（curl | sh）を作らないため（security.md・サプライチェーン対策）。未導入時は
# 公式の導入手順を案内して停止する。toolchain は rust-toolchain.toml が単一真実源。
.PHONY: rustup
rustup: ## rustup（cargo）の導入を確認する（未導入なら公式手順を案内して停止）
	@if ! command -v rustup >/dev/null 2>&1 && [ ! -x "$$HOME/.cargo/bin/rustup" ]; then \
		echo "error: rustup が見つかりません。公式手順（https://rustup.rs/）で導入してから再実行してください" >&2; \
		exit 1; \
	fi

# docs/spec（fandhe-container-spec）は private リポジトリのため、アクセス権のない環境では
# 取得に失敗する。実装コードのビルド・テストは docs/spec 抜きでも成立させる方針
# （CLAUDE.md）のため、失敗しても setup 全体は止めない。
.PHONY: submodule
submodule: ## docs/spec サブモジュールを初期化・更新する（private・アクセス権が無ければ警告のみ）
	@git submodule update --init || \
		echo "警告: docs/spec（private）の取得に失敗しました。アクセス権のない環境では想定内です（ビルド・テストは spec 抜きで成立します）"

# lefthook（Go 製。crates.io には存在しないため cargo フォールバックは置かない）は
# brew（バージョン固定不可だが常用導線）を優先し、無ければ npm 配布版を exact 固定の
# npx ワンショットで実行する（lefthook が生成する hook スクリプトは PATH → npx の順で
# 本体を解決するため、npx 経由の導入でもコミット時にフックが機能する）。
.PHONY: hooks
hooks: ## lefthook の git hooks を導入する（未導入なら lefthook 本体も導入）
	@if command -v lefthook >/dev/null 2>&1; then \
		lefthook install; \
	elif command -v brew >/dev/null 2>&1; then \
		echo "lefthook を導入します"; \
		brew install lefthook && lefthook install; \
	elif command -v npx >/dev/null 2>&1; then \
		echo "lefthook（npx 固定版）で hooks を導入します"; \
		npx --yes lefthook@$(LEFTHOOK_VERSION) install; \
	else \
		echo "brew / npx が見つかりません。https://lefthook.dev/installation/ を参照してください" >&2; \
		exit 1; \
	fi

# --------------------------------------------------
# ドキュメント／設定ファイル系 lint（CI の lint-docs ジョブと同等の内容）
# --------------------------------------------------

.PHONY: lint-md
lint-md: ## markdownlint（.markdownlint.jsonc / .markdownlintignore 参照）
	npx --yes markdownlint-cli@$(MARKDOWNLINT_VERSION) --ignore-path .markdownlintignore "**/*.md"

# yamllint は Python 製のため npx で賄えない。導入済みの実体（brew / pip）を優先し、
# uvx があれば固定版のワンショット実行で代替する。いずれも無ければ fail-closed で
# 導入方法を案内して失敗する（silent skip は CI との false-green 乖離になるため行わない）。
.PHONY: lint-yaml
lint-yaml: ## yamllint（.yamllint 参照）
	@if command -v yamllint >/dev/null 2>&1; then \
		yamllint .; \
	elif command -v uvx >/dev/null 2>&1; then \
		uvx yamllint==$(YAMLLINT_VERSION) .; \
	else \
		echo "yamllint 未導入: brew install yamllint / pip install yamllint==$(YAMLLINT_VERSION) で導入してください" >&2; \
		exit 1; \
	fi

.PHONY: lint-editorconfig
lint-editorconfig: ## editorconfig-checker（.editorconfig + .editorconfig-checker.json 参照）
	npx --yes editorconfig-checker@$(EC_NPM_VERSION)

# main からの分岐点以降のコミットを CI（lint-docs の commitlint ジョブ）と同じ
# extends 構成で検証する。origin/main が未取得の環境では範囲を決められないためスキップする。
# `git rev-parse --verify --quiet refs/remotes/origin/main` は「参照が存在しない」場合に
# 終了コード 1 を返す（`--quiet` は該当時の "not a valid ref" 系メッセージを抑制する）。
# これだけを skip 条件にし、終了コードが 1 以外の失敗（`fatal: detected dubious
# ownership` 等。git がリポジトリを開く時点で発生し、`--quiet` の有無や対象 ref の
# 存在有無に関係なく典型的には終了コード 128 になる）は「参照が存在しない」とは別扱いにし、
# エラーメッセージを表示して非 0 終了する（fail-closed。Bugbot 指摘の是正: 以前は
# `git rev-parse --verify origin/main` の失敗全般（終了コードを問わない）を
# 「origin/main 未取得」とみなして stderr を捨てていたため、dubious ownership 等の
# 実エラーも無音 skip になっていた。単に非 0 かどうかだけで判定すると dubious
# ownership も終了コード 1 以外の非 0 になるだけで区別できないため、終了コードの値まで見る）。
.PHONY: lint-commits
lint-commits: ## commitlint（origin/main からの分岐点以降のコミットを検証）
	@out=$$(git rev-parse --verify --quiet refs/remotes/origin/main 2>&1 >/dev/null); st=$$?; \
	if [ "$$st" -eq 1 ]; then \
		echo "skip: origin/main が未取得のため commitlint をスキップ"; \
		exit 0; \
	elif [ "$$st" -ne 0 ]; then \
		printf '%s\n' "$$out" >&2; \
		echo "NG: origin/main の参照確認に失敗しました（git rev-parse exit=$$st ）" >&2; \
		exit 1; \
	fi; \
	base=$$(git merge-base origin/main HEAD) || { \
		echo "NG: git merge-base の実行に失敗しました" >&2; \
		exit 1; \
	}; \
	npx --yes -p @commitlint/cli@$(COMMITLINT_VERSION) -p @commitlint/config-conventional@$(COMMITLINT_CONFIG_VERSION) \
		commitlint --extends @commitlint/config-conventional --from "$$base" --to HEAD

.PHONY: lint-docs
lint-docs: lint-md lint-yaml lint-editorconfig lint-commits ## ドキュメント／設定ファイル系 lint を一括実行する

# --------------------------------------------------
# 品質チェック（Rust。Cargo.toml 追加後に有効化）
# --------------------------------------------------

# workspace 仮想 manifest（Cargo.toml）自体の構文・定義としての妥当性を検証する。
# `cargo verify-project` は member crate が 0 件の仮想 workspace でも成功する
# （fmt/clippy/test 等の「対象パッケージが無い」失敗とは異なる。実機検証済み）ため、
# HAS_MEMBERS を条件にせず HAS_CARGO のみで常時実行する。root Cargo.toml の追加直後
# のように member crate がまだ 1 つも無い段階でも、追加した Cargo.toml が
# cargo にとって解釈可能な manifest であることをこのターゲットが保証する。
.PHONY: check-workspace-manifest
check-workspace-manifest: ## cargo verify-project で workspace manifest の妥当性を検証する
ifneq ($(HAS_CARGO),)
	@out=$$(cargo verify-project 2>&1) || { \
		echo "$$out" >&2; \
		echo "NG: Cargo.toml が cargo にとって不正な manifest です" >&2; \
		exit 1; \
	}; \
	if ! printf '%s\n' "$$out" | grep -q '"success"'; then \
		echo "$$out" >&2; \
		echo "NG: cargo verify-project が success を返しませんでした" >&2; \
		exit 1; \
	fi
else
	@echo "skip: Cargo.toml 未追加のため check-workspace-manifest をスキップ"
endif

.PHONY: fmt
fmt: ## cargo fmt --all で整形する
ifneq ($(and $(HAS_CARGO),$(HAS_MEMBERS)),)
	cargo fmt --all
else
	@echo "skip: Cargo.toml 未追加、または workspace にメンバー crate が無いため fmt をスキップ"
endif

.PHONY: fmt-check
fmt-check: ## cargo fmt --check（整形差分の検出）
ifneq ($(and $(HAS_CARGO),$(HAS_MEMBERS)),)
	cargo fmt --all --check
else
	@echo "skip: Cargo.toml 未追加、または workspace にメンバー crate が無いため fmt-check をスキップ"
endif

# 既定 feature のみで検証する（`--all-features` 込みの検証は CI の rust-ci ジョブが
# 担う。CI の rust-ci-default-features ジョブと同一コマンド）。
.PHONY: lint
lint: ## cargo clippy -D warnings（既定 feature。lint ゲート）
ifneq ($(and $(HAS_CARGO),$(HAS_MEMBERS)),)
	cargo clippy --workspace --all-targets -- -D warnings
else
	@echo "skip: Cargo.toml 未追加、または workspace にメンバー crate が無いため lint をスキップ"
endif

.PHONY: test
test: ## cargo test（既定 feature。workspace 全体）
ifneq ($(and $(HAS_CARGO),$(HAS_MEMBERS)),)
	cargo test --workspace
else
	@echo "skip: Cargo.toml 未追加、または workspace にメンバー crate が無いため test をスキップ"
endif

.PHONY: deny
deny: ## cargo deny check advisories bans licenses sources（依存監査。cargo-deny 未導入なら自動導入）
ifneq ($(and $(HAS_CARGO),$(HAS_DENY),$(HAS_MEMBERS)),)
	@export PATH="$$HOME/.cargo/bin:$$PATH"; \
	command -v cargo-deny >/dev/null 2>&1 || { \
		echo "cargo-deny を導入します"; \
		cargo install cargo-deny@$(CARGO_DENY_VERSION) --locked; \
	}; \
	cargo deny --locked check advisories bans licenses sources
else
	@echo "skip: Cargo.toml・deny.toml のいずれか未追加、または workspace にメンバー crate が無いため deny をスキップ"
endif

.PHONY: ci
ci: lint-docs check-workspace-manifest fmt-check lint test deny ## ローカルゲート（.claude/rules/ci.md）と同等のチェックを一括実行する

# --------------------------------------------------
# Docker（環境非依存の開発・検証。詳細は compose.yaml / Dockerfile 参照）
# --------------------------------------------------

.PHONY: docker-build
docker-build: ## 開発コンテナイメージをビルドする
	docker compose build

.PHONY: docker-shell
docker-shell: ## 開発コンテナのシェルに入る
	docker compose run --rm dev

.PHONY: docker-ci
docker-ci: ## コンテナ内で make ci を実行する（環境非依存の検証）
	docker compose run --rm dev make ci
