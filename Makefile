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
# CARGO_DENY_VERSION は Dockerfile の先行導入・.github/workflows/ci.yml の
# rust-ci.with.cargo-deny-version（REPAIR-7 ステージ 5）と値を同期させる）。
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
	@# crates/supervisor が workspace members から外れると `cargo test --workspace` が
	@# crate 内の機械照合テストごと実行しなくなるため、workspace 外のここで登録を検証する
	@# （TASK-157.1・#235・SUP-1・REPAIR-12）。
	@# ディレクトリ存在と members 登録はそれぞれ必須とする。`cargo pkgid` は Cargo.lock の
	@# resolve グラフを参照し members を見ないため使わず、`cargo metadata --no-deps`
	@# （packages に workspace members のみを列挙する）の `manifest_path` が
	@# crates/supervisor/Cargo.toml であるパッケージの有無で照合する。パッケージ名や
	@# 他 member の dependencies に同名が残っていても通らないよう、依存エントリには
	@# 現れない `manifest_path` キーのみを見る。Windows の cargo metadata はバックスラッシュ
	@# 区切り（JSON 上は `\\`）を返すため、区切りは `/` と `\` の両方を受け付ける。
	@[ -d crates/supervisor ] || { \
		echo "NG: crates/supervisor が存在しません" >&2; \
		exit 1; \
	}
	@cargo metadata --no-deps --format-version 1 2>/dev/null \
		| grep -Eq '"manifest_path"[[:space:]]*:[[:space:]]*"[^"]*[/\\]+crates[/\\]+supervisor[/\\]+Cargo\.toml"' || { \
		echo "NG: crates/supervisor が workspace members に登録されていません" >&2; \
		exit 1; \
	}
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

# REPAIR-7 ステージ 3（タイムアウト保護された結合試験。TASK-86.2・#36）。
# CI（ci.yml の integration-test ジョブ）と同じ判定を行う: integration test
# target（`tests/*.rs`。cargo metadata 上で kind が "test" のもの）が 0 件の
# 場合は「no test target matches pattern」で `cargo test --workspace --test '*'`
# が非 0 終了するため、jq で件数を数えてから呼び出す。jq 未導入は fail-closed
# （CI との false-green 乖離を避けるため、無言 skip にはしない）。
# CI 側のみが持つタイムアウト保護（実行ステップ 10 分・ジョブ全体 30 分）と
# ハングプローブはローカルには持ち込まない。`make ci` には含めない
# （`make test` が既に同じ workspace のテストを一括で走らせるため、`make ci` から
# 呼ぶと二重実行になる）。
.PHONY: test-integration
test-integration: ## cargo test --workspace --test '*' --features fandhe-container-io/crash-test-server（結合試験。0 件なら notice で成功終了）
ifneq ($(and $(HAS_CARGO),$(HAS_MEMBERS)),)
	@command -v jq >/dev/null 2>&1 || { \
		echo "jq 未導入: 導入してから再実行してください（brew install jq / apt-get install jq 等）" >&2; \
		exit 1; \
	}; \
	metadata=$$(cargo metadata --no-deps --format-version 1) || { \
		echo "NG: cargo metadata の実行に失敗しました" >&2; \
		exit 1; \
	}; \
	count=$$(printf '%s' "$$metadata" | jq -er '[.packages[].targets[] | select(.kind[]? == "test")] | length') || { \
		echo "NG: integration test target 件数の判定（jq）に失敗しました" >&2; \
		exit 1; \
	}; \
	echo "integration test targets: $$count"; \
	if [ "$$count" = "0" ]; then \
		echo "notice: integration test target が 0 件のため実行対象なし"; \
		exit 0; \
	fi; \
	cargo test --workspace --test '*' --features fandhe-container-io/crash-test-server && \
	cargo test -p fandhe-container-io --bins --features crash-test-server
else
	@echo "skip: Cargo.toml 未追加、または workspace にメンバー crate が無いため test-integration をスキップ"
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
# ベンチ回帰チェック（REPAIR-7 第 4 段階・REPAIR-8）
# --------------------------------------------------
# `make ci` には含めない: (1) ci.md のローカルゲート定義（fmt-check/lint/test/deny）を
# 変えないため、(2) 実ベンチの実行は時間がかかるため。CI 側は `.github/workflows/ci.yml`
# の `bench-regression` 専用ジョブが必ず実行するため、`make ci` に無くてもゲートは
# 抜けない。

# 比較スクリプト自体の自己テスト（scripts/testdata/bench-regression/ の固定 fixture で
# 終了コードを照合。REPAIR-12）。bash + jq のみで完結し、cargo を必要としないため
# HAS_CARGO では判定しない。jq 未導入時は導入方法を案内して fail-closed で止める
# （黙ってスキップしない）。
.PHONY: bench-check-selftest
bench-check-selftest: ## ベンチ回帰比較スクリプトの自己テスト（REPAIR-8）
	@if ! command -v jq >/dev/null 2>&1; then \
		echo "jq is required but not found: install it (e.g. brew install jq / apt-get install jq)" >&2; \
		exit 1; \
	fi
	bash scripts/check-bench-regression-selftest.sh

# プレースホルダベンチ（benches/benches/regression_placeholder.rs）を実行し、
# 結果を基準値（benches/baseline.json）と比較する。一時ディレクトリは trap で
# 必ず削除する（1 レシピ行で完結させ、定義から削除までの経路を保つ）。
.PHONY: bench-check
bench-check: ## ベンチ回帰チェック（REPAIR-7 第 4 段階・REPAIR-8。現状はプレースホルダベンチ）
ifneq ($(and $(HAS_CARGO),$(HAS_MEMBERS)),)
	@tmp=$$(mktemp -d) && trap 'rm -rf "$$tmp"' EXIT && \
	cargo bench -p fandhe-container-benches --bench regression_placeholder -- --output "$$tmp/results.json" && \
	bash scripts/check-bench-regression.sh benches/baseline.json "$$tmp/results.json"
else
	@echo "skip: Cargo.toml 未追加、または workspace にメンバー crate が無いため bench-check をスキップ"
endif

# baseline.json 生成スクリプト（scripts/bench/generate_baseline.sh）の自己テスト
# （TASK-88.1・REPAIR-8・REPAIR-12）。bash + jq のみで完結する。
.PHONY: bench-baseline-selftest
bench-baseline-selftest: ## baseline.json 生成スクリプトの自己テスト（TASK-88.1・REPAIR-12）
	@if ! command -v jq >/dev/null 2>&1; then \
		echo "jq is required but not found: install it (e.g. brew install jq / apt-get install jq)" >&2; \
		exit 1; \
	fi
	bash scripts/bench/generate_baseline_selftest.sh

# 登録済みベンチを実行し、benches/metrics.json（direction・unit の SSOT）と合わせて
# baseline.json を再生成する（TASK-88.1・REPAIR-8）。BENCH_NAMES は TASK-113 で実ベンチ
# （files/s・起動 p95 等）を足す場所。実測値の記録は TASK-88.2（#229）が行う。
# BENCH_METRICS / BENCH_BASELINE_OUT / BENCH_ENVIRONMENT は Make 変数展開でシェル文字列へ
# 埋め込まず、export した環境変数として二重引用符付きで参照する（値に ' 等が含まれても
# 引用が壊れず、インジェクションにならない）。
BENCH_NAMES := regression_placeholder
BENCH_METRICS ?= benches/metrics.json
BENCH_BASELINE_OUT ?= benches/baseline.json
BENCH_ENVIRONMENT ?=
export BENCH_METRICS BENCH_BASELINE_OUT BENCH_ENVIRONMENT

.PHONY: bench-baseline
bench-baseline: ## ベンチを実行し baseline.json を再生成する（TASK-88.1・REPAIR-8）
ifneq ($(and $(HAS_CARGO),$(HAS_MEMBERS)),)
	@tmp=$$(mktemp -d) && trap 'rm -rf "$$tmp"' EXIT && \
	for n in $(BENCH_NAMES); do \
		cargo bench -p fandhe-container-benches --bench "$$n" -- --output "$$tmp/$$n.json" || exit 1; \
	done && \
	bash scripts/bench/generate_baseline.sh --metrics "$$BENCH_METRICS" --output "$$BENCH_BASELINE_OUT" \
		$${BENCH_ENVIRONMENT:+--environment "$$BENCH_ENVIRONMENT"} "$$tmp"/*.json
else
	@echo "skip: Cargo.toml 未追加、または workspace にメンバー crate が無いため bench-baseline をスキップ"
endif

# --------------------------------------------------
# fio 4K ランダム write ベンチ（TASK-25.1・IO-8・MS-1 Phase 2）
# --------------------------------------------------
# `scripts/fio-randwrite-4k.sh` は DB 書き込み相当の 4K ランダム write を fio で
# 実行し、IOPS・レイテンシを機械可読形式で出力する。実機前提（fio・GNU
# coreutils の `timeout`・Linux ホスト）のため `make ci` には含めない
# （AGENTS.md「実機前提テスト」・.claude/rules/ci.md）。cargo を必要としないため
# HAS_CARGO では判定しない。

# 自己テスト（--from-json モード＋固定 fixture＋fio スタブで完結。fio 実機なしで
# 動く。jq 未導入時は導入方法を案内して fail-closed で止める）。
.PHONY: fio-bench-selftest
fio-bench-selftest: ## fio ベンチスクリプトの自己テスト（REPAIR-12。実 fio 不要）
	@if ! command -v jq >/dev/null 2>&1; then \
		echo "jq is required but not found: install it (e.g. brew install jq / apt-get install jq)" >&2; \
		exit 1; \
	fi
	bash scripts/fio-randwrite-4k-selftest.sh

# 実機での run モード実行（fio・GNU coreutils の timeout が必要。root 権限・
# /dev/kvm は不要）。TARGET_DIR 未指定時は案内を出して止める。
# make 変数はレシピのシェルへ文字列として展開されるため、二重引用符で囲むだけでは
# 値中の `"`・`$(...)`・バッククォートがシェルに解釈される。単一引用符で囲み、値中の
# `'` を `'\''` に置換してから渡す（値の検証自体はスクリプト側の許可リストが担う）。
fio_bench_sq = '$(subst ','\'',$(1))'
.PHONY: fio-bench
fio-bench: ## fio 4K ランダム write ベンチを実行する（要 fio・実機。TARGET_DIR/LABEL 必須）
	@if [ -z $(call fio_bench_sq,$(TARGET_DIR)) ] || [ -z $(call fio_bench_sq,$(LABEL)) ]; then \
		echo "usage: make fio-bench TARGET_DIR=<dir> LABEL=<label> [RUNTIME=<seconds>]" >&2; \
		exit 2; \
	fi
	bash scripts/fio-randwrite-4k.sh --target-dir $(call fio_bench_sq,$(TARGET_DIR)) --label $(call fio_bench_sq,$(LABEL)) --runtime $(call fio_bench_sq,$(or $(RUNTIME),30))

# --------------------------------------------------
# fio ベースライン比算出（TASK-25.2・IO-8・MS-1 Phase 2）
# --------------------------------------------------
# `scripts/fio-baseline-ratio.sh` は fio-randwrite-4k.sh の results.json を 2 つ
# （baseline / candidate）受け取り、IOPS・レイテンシの倍率を出す（fio 自体は
# 実行しない。jq のみで完結するため実機前提テストへは分離しない）。

.PHONY: fio-baseline-ratio-selftest
fio-baseline-ratio-selftest: ## fio ベースライン比算出スクリプトの自己テスト（REPAIR-12。実 fio 不要）
	@if ! command -v jq >/dev/null 2>&1; then \
		echo "jq is required but not found: install it (e.g. brew install jq / apt-get install jq)" >&2; \
		exit 1; \
	fi
	bash scripts/fio-baseline-ratio-selftest.sh

.PHONY: fio-baseline-ratio
fio-baseline-ratio: ## fio ベースライン比を算出する（BASELINE/CANDIDATE に results.json のパスを指定）
	@if [ -z $(call fio_bench_sq,$(BASELINE)) ] || [ -z $(call fio_bench_sq,$(CANDIDATE)) ]; then \
		echo "usage: make fio-baseline-ratio BASELINE=<results.json> CANDIDATE=<results.json>" >&2; \
		exit 2; \
	fi
	bash scripts/fio-baseline-ratio.sh --baseline $(call fio_bench_sq,$(BASELINE)) --candidate $(call fio_bench_sq,$(CANDIDATE))

# --------------------------------------------------
# 起動時間計測（TASK-46.1・TASK-46.2・CORE-10・MS-2 Phase 3）
# --------------------------------------------------
# `scripts/bench/startup_latency.sh` は OCI Runtime CLI 契約のランタイムに対し
# create からプロセス実行開始（state が running / stopped を返した時点）までの時間の
# 中央値を計測する。own 実装の実測は CLI（TASK-79）
# 提供後に人間が #213（TASK-46.h1）で行う実機前提（ランタイム・bundle・場合により root）
# のため `make ci` には含めない。自己テストはスタブランタイムで完結し CI に組み込み済み
# （計測スクリプトが単調時計として /proc/uptime を使うため Linux 限定）。
# `startup-latency-docker` は同じスクリプトの `--mode docker` で `docker run --rm ... --entrypoint true <image>` の
# 全体時間を計測し（TASK-46.2。Docker は実機前提・イメージは事前に手動 pull）、
# `startup-latency-report` は own と Docker の結果を 1 つのレポートに統合する。両者の計測区間は
# 異なり（method / methods_differ に明示）、合否判定は #213（TASK-46.h1）で人間が行う。
.PHONY: startup-latency-selftest
startup-latency-selftest: ## 起動時間計測スクリプトの自己テスト（REPAIR-12。実ランタイム不要）
	@if ! command -v jq >/dev/null 2>&1; then \
		echo "jq is required but not found: install it (e.g. brew install jq / apt-get install jq)" >&2; \
		exit 1; \
	fi
	bash scripts/bench/startup_latency_selftest.sh

.PHONY: startup-latency
startup-latency: ## 起動時間を計測する（実機前提。RUNTIME=<絶対パス> BUNDLE=<dir> TARGET=<名前> 必須）
	@if [ -z $(call fio_bench_sq,$(RUNTIME)) ] || [ -z $(call fio_bench_sq,$(BUNDLE)) ] || [ -z $(call fio_bench_sq,$(TARGET)) ]; then \
		echo "usage: make startup-latency RUNTIME=<abs-path> BUNDLE=<dir> TARGET=<name, e.g. own> [ITERATIONS=<n>] [LABEL=<label>]" >&2; \
		exit 2; \
	fi
	bash scripts/bench/startup_latency.sh --runtime $(call fio_bench_sq,$(RUNTIME)) --bundle $(call fio_bench_sq,$(BUNDLE)) --target $(call fio_bench_sq,$(TARGET)) --iterations $(call fio_bench_sq,$(or $(ITERATIONS),10)) --label $(call fio_bench_sq,$(or $(LABEL),$(TARGET)))

.PHONY: startup-latency-docker
startup-latency-docker: ## Docker の起動時間を計測する（実機前提。DOCKER=<docker の絶対パス> 必須。TASK-46.2）
	@if [ -z $(call fio_bench_sq,$(DOCKER)) ]; then \
		echo "usage: make startup-latency-docker DOCKER=<abs-path of docker CLI> [TARGET=<name, default docker>] [IMAGE=<ref, default alpine:3.20 (pull it first)>] [ITERATIONS=<n>] [LABEL=<label>] [OUTPUT=<new file>]" >&2; \
		exit 2; \
	fi
	bash scripts/bench/startup_latency.sh --mode docker --runtime $(call fio_bench_sq,$(DOCKER)) --target $(call fio_bench_sq,$(or $(TARGET),docker)) --iterations $(call fio_bench_sq,$(or $(ITERATIONS),10)) --label $(call fio_bench_sq,$(or $(LABEL),$(or $(TARGET),docker)))$(if $(IMAGE), --image $(call fio_bench_sq,$(IMAGE)))$(if $(OUTPUT), --output $(call fio_bench_sq,$(OUTPUT)))

.PHONY: startup-latency-report
startup-latency-report: ## own と Docker の起動時間の結果を 1 つのレポートに統合する（OWN_RESULT=<file> DOCKER_RESULT=<file> 必須。TASK-46.2）
	@if [ -z $(call fio_bench_sq,$(OWN_RESULT)) ] || [ -z $(call fio_bench_sq,$(DOCKER_RESULT)) ]; then \
		echo "usage: make startup-latency-report OWN_RESULT=<oci-mode result.json> DOCKER_RESULT=<docker-mode result.json> [OUTPUT=<new file>]" >&2; \
		exit 2; \
	fi
	bash scripts/bench/startup_latency.sh --mode report --own-result $(call fio_bench_sq,$(OWN_RESULT)) --docker-result $(call fio_bench_sq,$(DOCKER_RESULT))$(if $(OUTPUT), --output $(call fio_bench_sq,$(OUTPUT)))

# --------------------------------------------------
# アイドル時常駐メモリ計測（TASK-45.1・CORE-7。Linux 限定。bash のみで完結）
# --------------------------------------------------

.PHONY: idle-memory-selftest
idle-memory-selftest: ## アイドル時常駐メモリ計測スクリプトの自己テスト（CORE-7・REPAIR-12）
	bash scripts/bench/idle_memory_selftest.sh

# /proc の読み取りがハングしたプロセスで止まり得るため timeout で包む（REPAIR-5）。
# 秒数は IDLE_MEMORY_TIMEOUT で上書きできる（1〜999999 の整数。0 は timeout 無効になるため拒否）。
# スクリプトの終了コード 0〜3 はそのまま返し、それ以外は契約の値へ変換する:
# timeout の超過（124）・強制終了（137）とシグナル等の想定外の値は計測失敗（3）、
# timeout 自体の失敗（125）・bash / スクリプトを起動できない（126・127）は 2。
# IDLE_MEMORY_SCRIPT は selftest が変換の配線を stub で照合するための差し替え口（実計測はしない）。
IDLE_MEMORY_TIMEOUT ?= 120
IDLE_MEMORY_SCRIPT ?= scripts/bench/idle_memory.sh

.PHONY: idle-memory
idle-memory: ## アイドル時常駐メモリ（プロセス数・PSS・RSS）を JSON で出力する（CORE-7。Linux 限定・timeout 付き）
	@t=$(call fio_bench_sq,$(IDLE_MEMORY_TIMEOUT)); \
	case "$$t" in ''|*[!0-9]*|???????*) t=invalid ;; esac; \
	if [ "$$t" = invalid ] || [ "$$t" -eq 0 ]; then \
		echo "error: invalid-argument: IDLE_MEMORY_TIMEOUT must be an integer from 1 to 999999 (seconds)" >&2; \
		exit 2; \
	fi; \
	if ! command -v timeout >/dev/null 2>&1; then \
		echo "error: unsupported-os: timeout (coreutils) is required" >&2; \
		exit 2; \
	fi; \
	rc=0; \
	timeout --kill-after=10 "$$t" bash $(call fio_bench_sq,$(IDLE_MEMORY_SCRIPT)) --format json || rc=$$?; \
	case "$$rc" in \
		0|1|2|3) exit "$$rc" ;; \
		124|137) echo "error: measurement-failed: timed out after $${t}s reading /proc" >&2; exit 3 ;; \
		125|126|127) echo "error: invalid-input: cannot run the measurement under timeout (exit $$rc)" >&2; exit 2 ;; \
		*) echo "error: measurement-failed: unexpected exit status $$rc" >&2; exit 3 ;; \
	esac

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
