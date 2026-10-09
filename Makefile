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

# rustdoc の警告（壊れた intra-doc リンク・private 項目へのリンク等）を -D warnings で fail させる
# （REPAIR-3・REPAIR-7・#1300）。既定 feature・--no-deps（依存の doc は生成しない）。CI は
# rust-ci-default-features ジョブ（3 OS）が本ターゲットを実行する。cfg(target_os) 限定の項目への
# リンクは他 OS で解決できず fail するため、doc コメントではリンクにせずコード表記にする。
.PHONY: doc
doc: ## cargo doc -D warnings（既定 feature・--no-deps。rustdoc 警告のゲート）
ifneq ($(and $(HAS_CARGO),$(HAS_MEMBERS)),)
	RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps
else
	@echo "skip: Cargo.toml 未追加、または workspace にメンバー crate が無いため doc をスキップ"
endif

# venus 試験治具（workspace 外の独立 PoC パッケージ。GPU-6・TASK-172.4・#888）の fmt / clippy / test。
# `make ci` には含めない。CI は rust-ci-default-features ジョブ（3 OS）が本ターゲットを実行し、
# plugin-macos 側の変更で治具が壊れたことを検出する。実機前提テストは #[ignore] で分離済み。
# clippy / test は --locked で治具の Cargo.lock を固定する（ルート側の依存変更で lock が黙って再解決され、
# 監査していない版でビルドされるのを防ぐ。lock の更新が要る変更は lock の差分として PR に現れる）。
POC_VENUS_JIG_MANIFEST := poc/venus-decoder/jig/Cargo.toml
.PHONY: poc-venus-jig-check
poc-venus-jig-check: ## venus 試験治具（poc/venus-decoder/jig）の fmt-check・clippy・test を実行する（GPU-6・TASK-172.4）
	cargo fmt --manifest-path $(POC_VENUS_JIG_MANIFEST) --check
	cargo clippy --manifest-path $(POC_VENUS_JIG_MANIFEST) --locked --all-targets -- -D warnings
	cargo test --manifest-path $(POC_VENUS_JIG_MANIFEST) --locked

# CLI が macOS / Windows のバックエンド実装へ直接依存しないことの機械判定（CLI-1・PLUG-4・TASK-79.4）。
# macOS / Windows は core の plugin 発見・登録機構経由で呼ぶ。`cargo tree` の通常依存に
# platform-* / plugin-macos / plugin-windows が現れたら NG（cargo tree の失敗も NG）。
.PHONY: check-cli-backend-deps
check-cli-backend-deps: ## cli の依存ツリーに platform-* / plugin-macos / plugin-windows が含まれないことを検証する
ifneq ($(and $(HAS_CARGO),$(HAS_MEMBERS)),)
	@tree=$$(cargo tree -p fandhe-container-cli -e normal --locked) || { \
		echo "NG: cargo tree の実行に失敗しました" >&2; \
		exit 1; \
	}; \
	if printf '%s\n' "$$tree" | grep -Eq 'fandhe-container-(platform|plugin)-(macos|windows)'; then \
		echo "NG: cli の依存ツリーに macOS / Windows のバックエンド crate が含まれています" >&2; \
		exit 1; \
	fi; \
	echo "OK: cli は platform-macos / platform-windows / plugin-macos / plugin-windows に依存しません"
else
	@echo "skip: Cargo.toml 未追加、または workspace にメンバー crate が無いため check-cli-backend-deps をスキップ"
endif

# core の plugin 無効構成の検証（PLUG-3・TASK-111.1・#262。REPAIR-10 (d)）。
# `--no-default-features` で core がビルド・テストでき、依存ツリーに plugin 境界基盤
# （fandhe-container-plugin）が入らないことを確認する。`make ci` には含めない
# （CI の rust-ci-default-features ジョブが同じターゲットを実行する）。
.PHONY: test-core-no-plugin
test-core-no-plugin: ## core を --no-default-features でテストし plugin 依存が入らないことを検証する
ifneq ($(and $(HAS_CARGO),$(HAS_MEMBERS)),)
	cargo test -p fandhe-container-core --no-default-features --lib
	@tree=$$(cargo tree -p fandhe-container-core --no-default-features -e normal) || { \
		echo "NG: cargo tree の実行に失敗しました" >&2; \
		exit 1; \
	}; \
	if printf '%s\n' "$$tree" | grep -q 'fandhe-container-plugin'; then \
		echo "NG: plugin 無効構成の依存ツリーに fandhe-container-plugin が含まれています" >&2; \
		exit 1; \
	fi; \
	echo "OK: plugin 無効構成で fandhe-container-plugin は依存ツリーに含まれません"
else
	@echo "skip: Cargo.toml 未追加、または workspace にメンバー crate が無いため test-core-no-plugin をスキップ"
endif

# core の既定 / plugin 除外構成の release ビルドと成果物サイズの記録（PLUG-3・TASK-111.2・#263）。
# CI の bench-regression ジョブ（ubuntu-latest 単独。サイズは OS 間で比較できないため）が
# 実行し、stdout の markdown 表を $GITHUB_STEP_SUMMARY へ追記する。`make ci` には含めない。
# 記録文書: docs/design/plugin-feature-size-record.md
# - 計測対象は rlib: 最終バイナリ（CLI bin）は TASK-79 で追加予定のため未存在。
#   TASK-79 後に実行ファイルのサイズへ切り替える（REPAIR-3: 実装済みを装わない）。
# - `-p fandhe-container-core` で計測する: workspace 全体の `--no-default-features` は
#   supervisor が core を既定 feature つきで依存するため feature 統合で plugin が再有効化され、
#   除外ビルドにならない。
# - ゲート配下は現状再エクスポートのみで、core rlib の差は僅少（合計差は plugin rlib 自体が占める）。軽量化効果の実測ではない。
# - サイズ差に閾値は設けない（ノイズ程度の差で誤検出するため）。ビルド失敗・rlib 不在・
#   不正値・除外構成での plugin rlib 出現は fail-closed で非ゼロ終了する。
# - target dir は mktemp -d 配下（リポ内の target/ とキャッシュに影響しない）。
.PHONY: plugin-feature-size
plugin-feature-size: ## core の既定 / plugin 除外 release ビルドの rlib サイズを記録する（PLUG-3・TASK-111.2）
ifneq ($(and $(HAS_CARGO),$(HAS_MEMBERS)),)
	@set -euo pipefail; \
	root=$$(mktemp -d); \
	trap 'rm -rf "$$root"' EXIT; \
	CARGO_TARGET_DIR="$$root/default" cargo build --release -p fandhe-container-core >&2; \
	CARGO_TARGET_DIR="$$root/no-plugin" cargo build --release -p fandhe-container-core --no-default-features >&2; \
	size_of() { \
		[ -f "$$1" ] || { echo "NG: rlib not found: $$1" >&2; exit 1; }; \
		n=$$(wc -c < "$$1" | tr -d '[:space:]'); \
		[[ "$$n" =~ ^[1-9][0-9]*$$ ]] || { echo "NG: invalid size for $$1: $$n" >&2; exit 1; }; \
		echo "$$n"; \
	}; \
	core_def=$$(size_of "$$root/default/release/libfandhe_container_core.rlib"); \
	core_np=$$(size_of "$$root/no-plugin/release/libfandhe_container_core.rlib"); \
	plugin_def=""; \
	for f in "$$root"/default/release/deps/libfandhe_container_plugin-*.rlib; do \
		[ -e "$$f" ] || continue; \
		[ -z "$$plugin_def" ] || { echo "NG: multiple plugin rlibs in default build" >&2; exit 1; }; \
		plugin_def=$$(size_of "$$f"); \
	done; \
	[ -n "$$plugin_def" ] || { echo "NG: plugin rlib not found in default build" >&2; exit 1; }; \
	for f in "$$root"/no-plugin/release/deps/libfandhe_container_plugin-*.rlib; do \
		[ ! -e "$$f" ] || { echo "NG: plugin rlib exists in no-default-features build: $$f" >&2; exit 1; }; \
	done; \
	core_diff=$$((core_def - core_np)); \
	total_def=$$((core_def + plugin_def)); \
	diff=$$((total_def - core_np)); \
	pct=$$(awk -v d="$$diff" -v t="$$total_def" 'BEGIN { printf "%.2f", d * 100 / t }'); \
	echo "### plugin feature size record (PLUG-3, TASK-111.2)"; \
	echo; \
	echo "- rustc: $$(rustc --version)"; \
	echo "- platform: $$(uname -sm)"; \
	echo "- profile: release (rlib size; the final binary does not exist yet, see TASK-79)"; \
	echo; \
	echo "| build | core rlib (bytes) | plugin rlib (bytes) | total (bytes) |"; \
	echo "| ----- | ----------------- | ------------------- | ------------- |"; \
	echo "| default | $$core_def | $$plugin_def | $$total_def |"; \
	echo "| --no-default-features | $$core_np | - (not built) | $$core_np |"; \
	echo; \
	echo "- difference (default - no-default-features): $$diff bytes ($$pct %)"; \
	echo "- note: measured on rlibs because no final binary exists yet; switch to the executable after TASK-79."; \
	echo "- note: the total difference is dominated by the plugin rlib itself (an intermediate artifact, not linked size); the core rlib difference is $$core_diff bytes because the gated code is re-exports only. This is not a measurement of the weight-saving effect."
else
	@echo "skip: Cargo.toml 未追加、または workspace にメンバー crate が無いため plugin-feature-size をスキップ"
endif

# PLUG-4（TASK-109.4・REPAIR-12）: plugin crate 追加の前後を別ビルドで比較し、core のソース一覧・
# 依存木・rlib の sha256 が不変であることを判定する（docs/design/crate-naming.md 決定 3）。
# ソース一覧は crates/core 配下全体（src/ に加え tests/ 等を含む）を対象とする。
# 一時 workspace 上で実行し、リポ内のファイルは変更しない。CI の bench-regression ジョブが実行する。
.PHONY: plug4-core-invariance
plug4-core-invariance: ## plugin 追加前後で core の指紋が不変か別ビルドで比較する（PLUG-4・TASK-109.4）
ifneq ($(and $(HAS_CARGO),$(HAS_MEMBERS)),)
	@bash scripts/check-plug4-core-invariance.sh
else
	@echo "skip: Cargo.toml 未追加、または workspace にメンバー crate が無いため plug4-core-invariance をスキップ"
endif

# 判定スクリプトの自己テスト（PLUG-4・TASK-109.4・REPAIR-12）。依存 0 件の最小 workspace を一時 git
# リポジトリとして作って判定スクリプトを走らせるため、実リポの workspace には依存しない（HAS_CARGO では
# 判定しない）。cargo・git 未導入時は黙ってスキップせず fail-closed で止める。CI の integration-test
# ジョブ（ubuntu・macos・windows の 3 OS。Windows は Git Bash）が実行し、GNU / BSD 双方のツールと
# Git Bash で動くことを確かめる。
.PHONY: plug4-core-invariance-selftest
plug4-core-invariance-selftest: ## PLUG-4 判定スクリプトの自己テスト（TASK-109.4・REPAIR-12。fixture workspace）
	@for c in cargo git; do \
		if ! command -v $$c >/dev/null 2>&1; then \
			echo "$$c is required but not found" >&2; \
			exit 1; \
		fi; \
	done
	bash scripts/check-plug4-core-invariance-selftest.sh

# CLI 基本 6 コマンドの 3 OS 同一構文・挙動の比較（TASK-125.1・CLI-1・MS-6）。
# 自己テストはスタブ CLI のみを使い、製品バイナリ・root は使わない（REPAIR-12）。CI の integration-test
# ジョブ（ubuntu・macos・windows の 3 OS）が本ターゲットを実行する。make ci には含めない。
.PHONY: cli-parity-selftest
cli-parity-selftest: ## CLI 3 OS 比較スクリプトの自己テスト（TASK-125.1・REPAIR-12。スタブ CLI のみ）
	bash scripts/cli-parity-check-selftest.sh

# タイムアウト回収がネイティブ exe の子孫に届くかの確認（#1548・TASK-125.1・CLI-1・REPAIR-5）。rustc で
# 一時ヘルパーをビルドする。CI の integration-test ジョブ（3 OS）が実行する。make ci には含めない。
.PHONY: cli-parity-native-reclaim-check
cli-parity-native-reclaim-check: ## capture のタイムアウトでネイティブ exe の子孫が回収されるかの確認（#1548）
	bash scripts/cli-parity-native-reclaim-check.sh

# commit-msg フックの本文行長検査（Issue #1295）。一時ファイルのみで完結する。make ci には含めない。
.PHONY: commit-msg-line-length-selftest
commit-msg-line-length-selftest: ## commit-msg 行長検査スクリプトの自己テスト（Issue #1295・REPAIR-12）
	bash scripts/check-commit-msg-line-length-selftest.sh

# 実機での記録・突き合わせ（実機前提・make ci 対象外。判定は #661〔TASK-125.h1〕で人間が行う）。
# CLI/OUTPUT を指定すると capture、BASELINE/CANDIDATE を指定すると compare を実行する。
# 変数は単一引用符で囲んでシェルへ渡す（fio_bench_sq。値の検証はスクリプト側が担う）。
.PHONY: cli-parity
cli-parity: ## CLI 3 OS 比較の capture（CLI/OUTPUT）または compare（BASELINE/CANDIDATE）を実行する
	@if [ -n $(call fio_bench_sq,$(CLI)) ] && [ -n $(call fio_bench_sq,$(OUTPUT)) ]; then \
		bash scripts/cli-parity-check.sh capture --cli $(call fio_bench_sq,$(CLI)) --output $(call fio_bench_sq,$(OUTPUT)); \
	elif [ -n $(call fio_bench_sq,$(BASELINE)) ] && [ -n $(call fio_bench_sq,$(CANDIDATE)) ]; then \
		bash scripts/cli-parity-check.sh compare --baseline $(call fio_bench_sq,$(BASELINE)) --candidate $(call fio_bench_sq,$(CANDIDATE)); \
	else \
		echo "usage: make cli-parity CLI=<abs-path> OUTPUT=<new-file>  |  make cli-parity BASELINE=<capture> CANDIDATE=<capture>" >&2; \
		exit 2; \
	fi

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
deny: ## cargo deny check advisories bans licenses sources（ルート workspace と venus 試験治具の依存監査。cargo-deny 未導入なら自動導入）
ifneq ($(and $(HAS_CARGO),$(HAS_DENY),$(HAS_MEMBERS)),)
	@export PATH="$$HOME/.cargo/bin:$$PATH"; \
	command -v cargo-deny >/dev/null 2>&1 || { \
		echo "cargo-deny を導入します"; \
		cargo install cargo-deny@$(CARGO_DENY_VERSION) --locked; \
	}; \
	cargo deny --locked check advisories bans licenses sources
	@$(MAKE) --no-print-directory deny-poc-venus-jig
else
	@echo "skip: Cargo.toml・deny.toml のいずれか未追加、または workspace にメンバー crate が無いため deny をスキップ"
endif

# venus 試験治具（ルート workspace 外。独自の Cargo.lock を持つ。GPU-6・TASK-172.4）の依存監査。
# ルートの deny.toml を共有し（--config）、ルートと同じ 4 種を --locked で検査する。CI の rust-ci
# （reusable workflow）の deny はルート workspace だけを見るため、CI では rust-ci-default-features
# ジョブ（ubuntu）が本ターゲットを実行する。cargo-deny 未導入なら deny と同じ版を自動導入する。
# 引数の位置: cargo-deny 0.20.2 では --manifest-path・--config・--locked は `cargo deny` 直下の大域
# オプションで、`check` の後ろに置くと「unexpected argument '--config'」で失敗する（`cargo deny --help`
# と `cargo deny check --help` で確認済み）。--show-stats で 4 種それぞれの ok / 件数を必ずログに出す。
.PHONY: deny-poc-venus-jig
deny-poc-venus-jig: ## venus 試験治具（poc/venus-decoder/jig）の Cargo.lock を cargo deny で検査する（ルートの deny.toml を共有）
	@export PATH="$$HOME/.cargo/bin:$$PATH"; \
	command -v cargo-deny >/dev/null 2>&1 || { \
		echo "cargo-deny を導入します"; \
		cargo install cargo-deny@$(CARGO_DENY_VERSION) --locked; \
	} && \
	cargo deny --manifest-path $(POC_VENUS_JIG_MANIFEST) --config deny.toml --locked \
		check --show-stats advisories bans licenses sources

.PHONY: ci
ci: lint-docs check-workspace-manifest fmt-check lint test doc deny ## ローカルゲート（.claude/rules/ci.md）と同等のチェックを一括実行する

# --------------------------------------------------
# ベンチ回帰チェック（REPAIR-7 第 4 段階・REPAIR-8）
# --------------------------------------------------
# `make ci` には含めない: (1) ci.md のローカルゲート定義（fmt-check/lint/test/doc/deny）を
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
# 対象ベンチは BENCH_CHECK_NAMES（Unix は bench-baseline と同じ BENCH_NAMES）を実行する。
# 絞り込みは plugin 境界ベンチ（plugin_boundary*）の結果だけに適用し、baseline.json に登録済みの
# metric に限って比較する（plugin 系 metric の段階登録を許容するため）。それ以外のベンチ
# （regression_placeholder 等）の未登録 metric は絞り込まず、check-bench-regression.sh が
# 入力エラーにする（登録漏れを検出する）。Windows（OS=Windows_NT）は Unix ドメインソケット前提の
# plugin 境界ベンチが unsupported-platform で失敗するため実行せず、baseline 側も実行した
# ベンチの metric に限って比較する（baseline から plugin_boundary* の metric だけを除外し、
# それ以外の未実行・欠落 metric は Unix と同様に check-bench-regression.sh が入力エラーにする。
# plugin 境界は Unix 専用。PLUG-5）。
# これにより baseline 再生成（plugin 系 metric の登録。TASK-88.h1・TASK-113.h1）後は、再生成した
# metric がそのまま 15% 回帰判定の対象になり、Makefile の追従修正が要らない。未登録の間は
# plugin 系 metric は比較されない（plugin 境界の性能回帰ゲートは未有効）。
BENCH_CHECK_NAMES = $(if $(filter Windows_NT,$(OS)),regression_placeholder,$(BENCH_NAMES))

.PHONY: bench-check
bench-check: ## ベンチ回帰チェック（REPAIR-7 第 4 段階・REPAIR-8。現状はプレースホルダベンチ）
ifneq ($(and $(HAS_CARGO),$(HAS_MEMBERS)),)
	@tmp=$$(mktemp -d) && trap 'rm -rf "$$tmp"' EXIT && \
	mkdir "$$tmp/in" "$$tmp/out" && \
	if [ "$(OS)" != "Windows_NT" ]; then \
		reg=$$(jq -c '[.metrics | keys[] | select(startswith("plugin_boundary"))]' benches/baseline.json) || exit 1; \
		exp=$$(jq -c '[.metrics | keys[] | select(startswith("plugin_boundary"))]' benches/metrics.json) || exit 1; \
		if [ "$$reg" != "[]" ] && [ "$$reg" != "$$exp" ]; then \
			echo "error: invalid-input: baseline.json plugin_boundary metrics $$reg do not match metrics.json $$exp (a registered metric was removed or is missing; recalibrate per TASK-88)" >&2; \
			exit 2; \
		fi; \
	fi && \
	for n in $(BENCH_CHECK_NAMES); do \
		cargo bench -p fandhe-container-benches --bench "$$n" -- --output "$$tmp/in/$$n.json" >/dev/null || exit 1; \
	done && \
	for f in "$$tmp"/in/*.json; do \
		case "$$(basename "$$f")" in \
		plugin_boundary*) \
			jq --slurpfile b benches/baseline.json \
				'{schema_version: 1, metrics: (.metrics | with_entries(select(.key as $$k | $$b[0].metrics | has($$k))))}' \
				"$$f" > "$$tmp/out/$$(basename "$$f")" || exit 1 ;; \
		*) cp "$$f" "$$tmp/out/" || exit 1 ;; \
		esac; \
	done && \
	jq -s '{schema_version: 1, metrics: (map(.metrics) | add)}' "$$tmp"/out/*.json > "$$tmp/results.json" && \
	if [ "$(OS)" = "Windows_NT" ]; then \
		jq '.metrics |= with_entries(select(.key | startswith("plugin_boundary") | not))' \
			benches/baseline.json > "$$tmp/baseline.json" || exit 1; \
	else \
		cp benches/baseline.json "$$tmp/baseline.json" || exit 1; \
	fi && \
	bash scripts/check-bench-regression.sh "$$tmp/baseline.json" "$$tmp/results.json"
else
	@echo "skip: Cargo.toml 未追加、または workspace にメンバー crate が無いため bench-check をスキップ"
endif

# plugin 境界ベンチ（代表操作 A・B。TASK-113.1〜113.3）を実行し、Δp50 と CORE-10 の Linux 実機値
# （0.290〜0.298 秒）に対する割合を stderr へログ出力する（PLUG-5・CORE-10）。基準値との比較は
# しない（plugin 系 metric は baseline.json 未登録。実測基準値は TASK-88.h1・TASK-113.h1 で確定）。
# 一時ディレクトリは trap で必ず削除する。Make 変数はシェル文字列へ埋め込まない。
.PHONY: bench-plugin-boundary
bench-plugin-boundary: ## plugin 境界ベンチを実行し Δp50 と CORE-10 比をログ出力する（TASK-113.3・PLUG-5。基準値比較なし）
ifneq ($(and $(HAS_CARGO),$(HAS_MEMBERS)),)
	@tmp=$$(mktemp -d) && trap 'rm -rf "$$tmp"' EXIT && \
	cargo bench -p fandhe-container-benches --bench plugin_boundary -- --output "$$tmp/a.json" && \
	cargo bench -p fandhe-container-benches --bench plugin_boundary_list_images -- --output "$$tmp/b.json" >/dev/null
else
	@echo "skip: Cargo.toml 未追加、または workspace にメンバー crate が無いため bench-plugin-boundary をスキップ"
endif

# macOS cold start 上乗せ確認（TASK-113.4・PLUG-6・MAC-2）の手動実行。macOS 以外は skip を表示して成功する。
# BENCH_NAMES・基準値比較には接続しない（macOS 専用 metric のため。CI の macOS では結合試験として実行）。
.PHONY: bench-macos-cold-start
bench-macos-cold-start: ## macOS cold start 上乗せを計測する（TASK-113.4・PLUG-6・MAC-2。macOS 以外は skip）
ifneq ($(and $(HAS_CARGO),$(HAS_MEMBERS)),)
	@cargo bench -p fandhe-container-benches --bench plugin_boundary_macos_cold_start
else
	@echo "skip: Cargo.toml 未追加、または workspace にメンバー crate が無いため bench-macos-cold-start をスキップ"
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
# baseline.json を再生成する（TASK-88.1・REPAIR-8）。BENCH_NAMES は実ベンチを追加するときに
# 足す場所（plugin 境界ベンチ〔TASK-113〕は登録済み。files/s・起動 p95 のベンチは担当タスク未定で、
# docs/design/bench-calibration.md「既知の欠落」）。校正記録は同ファイル（TASK-88.2・#229）にあり、
# 実測と基準値の確定は TASK-88.h1・TASK-113.h1。
# BENCH_METRICS / BENCH_BASELINE_OUT / BENCH_ENVIRONMENT は Make 変数展開でシェル文字列へ
# 埋め込まず、export した環境変数として二重引用符付きで参照する（値に ' 等が含まれても
# 引用が壊れず、インジェクションにならない）。
# plugin 境界ベンチ（TASK-113.1〜113.3）は metric を metrics.json に登録済みのため、ここにも
# 同時に載せる（generate_baseline.sh は metrics.json と results の metric 集合が完全一致しないと
# exit 2）。baseline 再生成時は `bench-check` も同じ BENCH_NAMES を実行し baseline 登録済み metric に絞って比較する。
# Windows（OS=Windows_NT）は plugin 境界ベンチ（Unix ドメインソケット前提）を実行できないため
# bench-check と同様に regression_placeholder のみ実行し、metrics.json からも plugin_boundary*
# を除いた一時ファイルを生成スクリプトへ渡す（要求 metric 集合を実行ベンチに合わせる。AGENTS.md「3 OS 対応」）。
# このため Windows で既定の出力先 benches/baseline.json へ書くと共有 baseline から plugin metric が
# 消えるので、Windows では BENCH_BASELINE_OUT を別ファイルに指定しない限りエラーにする。
BENCH_NAMES := regression_placeholder plugin_boundary plugin_boundary_list_images
BENCH_BASELINE_NAMES = $(if $(filter Windows_NT,$(OS)),regression_placeholder,$(BENCH_NAMES))
BENCH_METRICS ?= benches/metrics.json
BENCH_BASELINE_OUT ?= benches/baseline.json
BENCH_ENVIRONMENT ?=
export BENCH_METRICS BENCH_BASELINE_OUT BENCH_ENVIRONMENT

.PHONY: bench-baseline
bench-baseline: ## ベンチを実行し baseline.json を再生成する（TASK-88.1・REPAIR-8）
ifneq ($(and $(HAS_CARGO),$(HAS_MEMBERS)),)
	@tmp=$$(mktemp -d) && trap 'rm -rf "$$tmp"' EXIT && \
	mkdir "$$tmp/res" && \
	for n in $(BENCH_BASELINE_NAMES); do \
		cargo bench -p fandhe-container-benches --bench "$$n" -- --output "$$tmp/res/$$n.json" || exit 1; \
	done && \
	metrics="$$BENCH_METRICS" && \
	if [ "$(OS)" = "Windows_NT" ]; then \
		if [ "$$BENCH_BASELINE_OUT" = "benches/baseline.json" ]; then \
			echo "error: invalid-input: on Windows plugin_boundary metrics are not measured; set BENCH_BASELINE_OUT to a separate file so the shared benches/baseline.json keeps its plugin baselines" >&2; \
			exit 2; \
		fi; \
		jq '.metrics |= with_entries(select(.key | startswith("plugin_boundary") | not))' \
			"$$BENCH_METRICS" > "$$tmp/metrics.json" && metrics="$$tmp/metrics.json" || exit 1; \
	fi && \
	bash scripts/bench/generate_baseline.sh --metrics "$$metrics" --output "$$BENCH_BASELINE_OUT" \
		$${BENCH_ENVIRONMENT:+--environment "$$BENCH_ENVIRONMENT"} "$$tmp"/res/*.json
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

# virtio-gpu ゲスト側確認スクリプトの自己テスト（TASK-172.6・GPU-6・REPAIR-12）。
# 合成 fixture のみで完結し、macOS 27・ゲスト VM は不要。make ci には含めない。CI は integration-test
# ジョブ（ubuntu・macos・windows の 3 OS）が本ターゲットを実行し、BSD 系ツールでの移植性も確かめる。
.PHONY: vz-virtio-gpu-guest-check-selftest
vz-virtio-gpu-guest-check-selftest: ## virtio-gpu ゲスト側確認スクリプトの自己テスト（TASK-172.6・GPU-6・REPAIR-12。fixture のみ）
	bash poc/vz-custom-virtio-gpu/guest/check-virtio-gpu-selftest.sh

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
# ネットワーク作成・接続・削除の所要時間計測（TASK-139.5・NET-1・NET-4。Linux・root・実機前提）
# --------------------------------------------------
# `scripts/bench/net_setup_timing.sh` は network_paths_privileged の `--measure` を実行し、操作ごとの
# 中央値等を単位 ms の JSON で出す。sudo も cargo も呼ばないため、実行は
# `cargo test -p fandhe-container-net --test network_paths_privileged --no-run` で得た実行ファイルを
# `sudo make net-setup-timing EXE=<絶対パス>` で渡す（root 実行は人間の明示操作。実測・比較・判定は TASK-140）。
# 実機前提のため `make ci` には含めない。自己テストはスタブ exe で完結し CI の bench-regression ジョブで実行する。
.PHONY: net-setup-timing-selftest
net-setup-timing-selftest: ## ネットワーク作成/接続/削除の所要時間計測スクリプトの自己テスト（NET-4・REPAIR-12。実機不要）
	@if ! command -v jq >/dev/null 2>&1; then \
		echo "jq is required but not found: install it (e.g. brew install jq / apt-get install jq)" >&2; \
		exit 1; \
	fi
	bash scripts/bench/net_setup_timing_selftest.sh

.PHONY: net-setup-timing
net-setup-timing: ## ネットワーク作成/接続/削除の所要時間を JSON で出力する（実機前提。EXE=<絶対パス> 必須。NET-4・TASK-139.5）
	@if [ -z $(call fio_bench_sq,$(EXE)) ]; then \
		echo "usage: sudo make net-setup-timing EXE=<abs-path of network_paths_privileged built by cargo test --no-run> [TRIALS=<n>] [WARMUP=<n>] [LABEL=<label>] [OUTPUT=<new file>]" >&2; \
		exit 2; \
	fi
	bash scripts/bench/net_setup_timing.sh --exe $(call fio_bench_sq,$(EXE))$(if $(TRIALS), --trials $(call fio_bench_sq,$(TRIALS)))$(if $(WARMUP), --warmup $(call fio_bench_sq,$(WARMUP)))$(if $(LABEL), --label $(call fio_bench_sq,$(LABEL)))$(if $(OUTPUT), --output $(call fio_bench_sq,$(OUTPUT)))

# --------------------------------------------------
# DNS ヘルパーの正答率・レイテンシ・常駐 PSS 計測（TASK-141.3・NET-5。Linux・root・cgroup v2・実機前提）
# --------------------------------------------------
# `scripts/bench/dns_helper_measure.sh` は dns_helper_privileged の `--measure` を実行し、正答率・p50/p99（単位 us）・
# 専用 cgroup の cgroup.procs から取った PID の PSS/RSS（単位 kB）を JSON で出す。計測対象はテストバイナリが組み立てた
# DnsHelperServer + RegistryHandler で、製品の入口 run_dns_helper_main ではない（REPAIR-3）。sudo も cargo も呼ばないため、
# `cargo test -p fandhe-container-net --test dns_helper_privileged --no-run` で得た実行ファイルを
# `sudo make dns-helper-measure EXE=<絶対パス>` で渡す（root 実行は人間の明示操作。実測・比較・判定は TASK-142）。
# 実機前提のため `make ci` には含めない。自己テストはスタブ exe・疑似 cgroup / proc で完結し CI の bench-regression ジョブで実行する。
.PHONY: dns-helper-measure-selftest
dns-helper-measure-selftest: ## DNS ヘルパー計測スクリプトの自己テスト（NET-5・REPAIR-12。実機不要）
	@if ! command -v jq >/dev/null 2>&1; then \
		echo "jq is required but not found: install it (e.g. brew install jq / apt-get install jq)" >&2; \
		exit 1; \
	fi
	bash scripts/bench/dns_helper_measure_selftest.sh

.PHONY: dns-helper-measure
dns-helper-measure: ## DNS ヘルパーの正答率・レイテンシ・常駐 PSS を JSON で出力する（実機前提。EXE=<絶対パス> 必須。NET-5・TASK-141.3）
	@if [ -z $(call fio_bench_sq,$(EXE)) ]; then \
		echo "usage: sudo make dns-helper-measure EXE=<abs-path of dns_helper_privileged built by cargo test --no-run> [QUERIES=<n>] [WARMUP=<n>] [TIMEOUT=<secs>] [LABEL=<label>] [OUTPUT=<new file>]" >&2; \
		exit 2; \
	fi
	bash scripts/bench/dns_helper_measure.sh --exe $(call fio_bench_sq,$(EXE))$(if $(QUERIES), --queries $(call fio_bench_sq,$(QUERIES)))$(if $(WARMUP), --warmup $(call fio_bench_sq,$(WARMUP)))$(if $(TIMEOUT), --timeout $(call fio_bench_sq,$(TIMEOUT)))$(if $(LABEL), --label $(call fio_bench_sq,$(LABEL)))$(if $(OUTPUT), --output $(call fio_bench_sq,$(OUTPUT)))

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

.PHONY: idle-memory-supervised-selftest
idle-memory-supervised-selftest: ## 監視プロセス込みアイドル常駐メモリ回帰テストの自己テスト（TASK-47・CORE-7・REPAIR-12）
	bash scripts/bench/idle_memory_supervised_selftest.sh

# 実機前提（root 権限の操作者が driver を渡して明示実行する。実 driver は製品バイナリ未提供のため現状なし。
# make ci には含めない。ci.md「実機前提テスト」）。全体に timeout を掛け（REPAIR-5）、終了コードの変換規則は
# idle-memory と同じ。IDLE_MEMORY_SUPERVISED_TIMEOUT は全体の秒数（1〜999999・既定 900）、
# IDLE_MEMORY_SUPERVISED_CALL_TIMEOUT は driver・各計測 1 回あたりの秒数（未指定ならスクリプト既定）。
# 外側 timeout の TERM 後、スクリプトは TERM trap で実行中の driver を待ち（最大 call timeout + 10 秒）、続く EXIT trap で
# driver down を実行する（最大 call timeout + 10 秒）。両段階が完走できるよう、--kill-after は余裕 10 秒を含む
# 2 * call timeout + 30 秒（未指定・不正値は既定 120 秒 → 270 秒）を確保する（後始末の時間予算。AGENTS.md「特権操作の後始末」）。
# IDLE_MEMORY_SUPERVISED_SCRIPT は selftest が配線を stub で照合するための差し替え口。
IDLE_MEMORY_SUPERVISED_TIMEOUT ?= 900
IDLE_MEMORY_SUPERVISED_SCRIPT ?= scripts/bench/idle_memory_supervised.sh

.PHONY: idle-memory-supervised
idle-memory-supervised: ## 監視プロセス込みのアイドル常駐メモリ回帰テスト（DRIVER=<絶対パス> [EXPECTED_DIR=] [OUTPUT=]。CORE-7・Linux・実機前提）
	@t=$(call fio_bench_sq,$(IDLE_MEMORY_SUPERVISED_TIMEOUT)); \
	case "$$t" in ''|*[!0-9]*|???????*) t=invalid ;; esac; \
	if [ "$$t" = invalid ] || [ "$$t" -eq 0 ]; then \
		echo "error: invalid-argument: IDLE_MEMORY_SUPERVISED_TIMEOUT must be an integer from 1 to 999999 (seconds)" >&2; \
		exit 2; \
	fi; \
	if [ -z $(call fio_bench_sq,$(DRIVER)) ]; then \
		echo "error: invalid-argument: DRIVER=<absolute-path> is required (an executable taking 'up' / 'down'; see scripts/bench/idle_memory_supervised.sh)" >&2; \
		exit 2; \
	fi; \
	if ! command -v timeout >/dev/null 2>&1; then \
		echo "error: unsupported-os: timeout (coreutils) is required" >&2; \
		exit 2; \
	fi; \
	set -- --driver $(call fio_bench_sq,$(DRIVER)); \
	if [ -n $(call fio_bench_sq,$(EXPECTED_DIR)) ]; then set -- "$$@" --expected-dir $(call fio_bench_sq,$(EXPECTED_DIR)); fi; \
	if [ -n $(call fio_bench_sq,$(OUTPUT)) ]; then set -- "$$@" --output $(call fio_bench_sq,$(OUTPUT)); fi; \
	if [ -n $(call fio_bench_sq,$(IDLE_MEMORY_SUPERVISED_CALL_TIMEOUT)) ]; then set -- "$$@" --timeout $(call fio_bench_sq,$(IDLE_MEMORY_SUPERVISED_CALL_TIMEOUT)); fi; \
	c=$(call fio_bench_sq,$(IDLE_MEMORY_SUPERVISED_CALL_TIMEOUT)); \
	case "$$c" in ''|*[!0-9]*|???????*|0) c=120 ;; esac; \
	k=$$((2 * c + 30)); \
	rc=0; \
	timeout --kill-after="$$k" "$$t" bash $(call fio_bench_sq,$(IDLE_MEMORY_SUPERVISED_SCRIPT)) "$$@" || rc=$$?; \
	case "$$rc" in \
		0|1|2|3) exit "$$rc" ;; \
		124|137) echo "error: measurement-failed: timed out after $${t}s" >&2; exit 3 ;; \
		125|126|127) echo "error: invalid-input: cannot run the measurement under timeout (exit $$rc)" >&2; exit 2 ;; \
		*) echo "error: measurement-failed: unexpected exit status $$rc" >&2; exit 3 ;; \
	esac

# --------------------------------------------------
# 監視プロセス常駐メモリ（PSS）計測（TASK-158・SUP-2。Linux 限定。bash のみで完結）
# --------------------------------------------------
# 実測は製品バイナリ（fandhe-container-supervisor）提供後に人間が #485（TASK-158.h1）で行う。`make ci` には含めない（実機前提）。
# PID=<pid ...>（空白区切りで複数可）または COUNT=<N> のどちらか必須。起動は操作者が事前に行う（スクリプトは起動しない・sudo を呼ばない）。
# /proc の読み取りがハングし得るため timeout で包む（REPAIR-5）。秒数は SUPERVISOR_PSS_TIMEOUT（1〜999999・既定 300）。
# スクリプトの終了コード 0〜3 はそのまま返し、timeout 超過（124・137）と想定外の値は 3、起動不能（125〜127）は 2。
# SUPERVISOR_PSS_SCRIPT は selftest が配線を stub で照合するための差し替え口。
SUPERVISOR_PSS_TIMEOUT ?= 300
SUPERVISOR_PSS_SCRIPT ?= scripts/bench/supervisor_pss.sh

.PHONY: supervisor-pss-selftest
supervisor-pss-selftest: ## 監視プロセス常駐メモリ計測スクリプトの自己テスト（TASK-158・SUP-2・REPAIR-12）
	bash scripts/bench/supervisor_pss_selftest.sh

.PHONY: supervisor-pss
supervisor-pss: ## 監視プロセスの PSS を計測（PID="<pid>..." または COUNT=<N>。[SAMPLES= INTERVAL= EXE_NAME= EXPECTED_DIR= OUTPUT=]。SUP-2・Linux・実機前提）
	@t=$(call fio_bench_sq,$(SUPERVISOR_PSS_TIMEOUT)); \
	case "$$t" in ''|*[!0-9]*|???????*) t=invalid ;; esac; \
	if [ "$$t" = invalid ] || [ "$$t" -eq 0 ]; then \
		echo "error: invalid-argument: SUPERVISOR_PSS_TIMEOUT must be an integer from 1 to 999999 (seconds)" >&2; \
		exit 2; \
	fi; \
	if [ -z $(call fio_bench_sq,$(PID)) ] && [ -z $(call fio_bench_sq,$(COUNT)) ]; then \
		echo "error: invalid-argument: PID=\"<pid> ...\" or COUNT=<N> is required (see scripts/bench/supervisor_pss.sh --help)" >&2; \
		exit 2; \
	fi; \
	if ! command -v timeout >/dev/null 2>&1; then \
		echo "error: unsupported-os: timeout (coreutils) is required" >&2; \
		exit 2; \
	fi; \
	pids=$(call fio_bench_sq,$(PID)); \
	set --; \
	for p in $$pids; do set -- "$$@" --pid "$$p"; done; \
	if [ -n $(call fio_bench_sq,$(COUNT)) ]; then set -- "$$@" --count $(call fio_bench_sq,$(COUNT)); fi; \
	if [ -n $(call fio_bench_sq,$(SAMPLES)) ]; then set -- "$$@" --samples $(call fio_bench_sq,$(SAMPLES)); fi; \
	if [ -n $(call fio_bench_sq,$(INTERVAL)) ]; then set -- "$$@" --interval $(call fio_bench_sq,$(INTERVAL)); fi; \
	if [ -n $(call fio_bench_sq,$(EXE_NAME)) ]; then set -- "$$@" --exe-name $(call fio_bench_sq,$(EXE_NAME)); fi; \
	if [ -n $(call fio_bench_sq,$(EXPECTED_DIR)) ]; then set -- "$$@" --expected-dir $(call fio_bench_sq,$(EXPECTED_DIR)); fi; \
	if [ -n $(call fio_bench_sq,$(OUTPUT)) ]; then set -- "$$@" --output $(call fio_bench_sq,$(OUTPUT)); fi; \
	rc=0; \
	timeout --kill-after=10 "$$t" bash $(call fio_bench_sq,$(SUPERVISOR_PSS_SCRIPT)) --format json "$$@" || rc=$$?; \
	case "$$rc" in \
		0|1|2|3) exit "$$rc" ;; \
		124|137) echo "error: measurement-failed: timed out after $${t}s reading /proc" >&2; exit 3 ;; \
		125|126|127) echo "error: invalid-input: cannot run the measurement under timeout (exit $$rc)" >&2; exit 2 ;; \
		*) echo "error: measurement-failed: unexpected exit status $$rc" >&2; exit 3 ;; \
	esac

# --------------------------------------------------
# 50 コンテナ同時起動の集約メモリ計測（TASK-50.1 own 側・TASK-50.2 Docker 側と統合レポート・CORE-9・SUP-1。Linux 限定。bash のみで完結）
# --------------------------------------------------
# 実測は own の CLI・本番 launcher 提供後に人間が #219（TASK-50.h1）で行う。`make ci` には含めない（実機前提）。
# `concurrent-memory-docker` は同じスクリプトの `--mode docker` で Docker 側を同一手法（PSS 合計の中央値。集計対象は
# デーモン＋各コンテナの shim ツリー）で測り（実 Docker・ローカルデーモン・イメージの事前 pull・他コンテナなし・
# 権限付きシェルが前提）、`concurrent-memory-report` は own・Docker の結果を 1 つのレポートへまとめる（合否は出さない）。
# 計測全体を timeout で包む（REPAIR-5）。秒数は CONCURRENT_MEMORY_TIMEOUT（1〜999999 の整数。既定 1800）。
# スクリプトの終了コード 0〜4 はそのまま返し、timeout 超過（124・137）と想定外の値は 1、起動不能（125〜127）は 2。
CONCURRENT_MEMORY_TIMEOUT ?= 1800
CONCURRENT_MEMORY_SCRIPT ?= scripts/bench/concurrent_50_memory.sh
# timeout の --kill-after（TERM 後に KILL するまでの猶予。60 秒固定）。スクリプトの後始末（ln_stop）の最悪所要時間〔launcher 終了待ち最大 10 秒＋強制終了後の確認 5 秒＋所有プロセス回収 5 秒＋ログ収集プロセスの終了待ち 2 秒＋/proc 走査〕より十分長く取り、
# 後始末の途中で KILL して起動プロセスを残さないようにする（REPAIR-5）。

.PHONY: concurrent-memory-selftest
concurrent-memory-selftest: ## 50 コンテナ同時起動メモリ計測スクリプトの自己テスト（CORE-9・REPAIR-12。スタブ launcher・疑似 /proc）
	bash scripts/bench/concurrent_50_memory_selftest.sh

.PHONY: concurrent-memory-docker
concurrent-memory-docker: ## Docker 側の 50 コンテナ同時起動時の集約 PSS を計測する（実機前提・timeout 付き。DOCKER=<docker の絶対パス> 必須。TASK-50.2）
	@if [ -z $(call fio_bench_sq,$(DOCKER)) ]; then \
		echo "usage: make concurrent-memory-docker DOCKER=<abs-path of docker CLI> [TARGET=<name, default docker>] [IMAGE=<ref, default alpine:3.20 (pull it first)>] [COUNT=<n, default 50>] [TRIALS=<n, default 3>] [OUTPUT=<new file>] [CONCURRENT_MEMORY_TIMEOUT=<secs, default 1800>]" >&2; \
		exit 2; \
	fi; \
	t=$(call fio_bench_sq,$(CONCURRENT_MEMORY_TIMEOUT)); \
	case "$$t" in ''|*[!0-9]*|???????*) t=invalid ;; esac; \
	if [ "$$t" = invalid ] || [ "$$t" -eq 0 ]; then \
		echo "error: invalid-argument: CONCURRENT_MEMORY_TIMEOUT must be an integer from 1 to 999999 (seconds)" >&2; \
		exit 2; \
	fi; \
	if ! command -v timeout >/dev/null 2>&1; then \
		echo "error: unsupported-os: timeout (coreutils) is required" >&2; \
		exit 2; \
	fi; \
	rc=0; \
	timeout --kill-after=60 "$$t" bash $(call fio_bench_sq,$(CONCURRENT_MEMORY_SCRIPT)) --mode docker --docker $(call fio_bench_sq,$(DOCKER)) --target $(call fio_bench_sq,$(or $(TARGET),docker))$(if $(IMAGE), --image $(call fio_bench_sq,$(IMAGE)))$(if $(COUNT), --count $(call fio_bench_sq,$(COUNT)))$(if $(TRIALS), --trials $(call fio_bench_sq,$(TRIALS)))$(if $(OUTPUT), --output $(call fio_bench_sq,$(OUTPUT))) || rc=$$?; \
	case "$$rc" in \
		0|1|2|3|4) exit "$$rc" ;; \
		124|137) echo "error: measurement-failed: timed out after $${t}s (measurement or cleanup stalled)" >&2; exit 1 ;; \
		125|126|127) echo "error: invalid-input: cannot run the measurement under timeout (exit $$rc)" >&2; exit 2 ;; \
		*) echo "error: measurement-failed: unexpected exit status $$rc" >&2; exit 1 ;; \
	esac

.PHONY: concurrent-memory-report
concurrent-memory-report: ## own と Docker の 50 コンテナ集約メモリの結果を 1 つのレポートに統合する（OWN_RESULT=<file> DOCKER_RESULT=<file> 必須。TASK-50.2）
	@if [ -z $(call fio_bench_sq,$(OWN_RESULT)) ] || [ -z $(call fio_bench_sq,$(DOCKER_RESULT)) ]; then \
		echo "usage: make concurrent-memory-report OWN_RESULT=<own-mode result.json> DOCKER_RESULT=<docker-mode result.json> [OUTPUT=<new file>]" >&2; \
		exit 2; \
	fi
	@if ! command -v jq >/dev/null 2>&1; then \
		echo "jq is required but not found: install it (e.g. brew install jq / apt-get install jq)" >&2; \
		exit 1; \
	fi
	bash $(call fio_bench_sq,$(CONCURRENT_MEMORY_SCRIPT)) --mode report --own-result $(call fio_bench_sq,$(OWN_RESULT)) --docker-result $(call fio_bench_sq,$(DOCKER_RESULT))$(if $(OUTPUT), --output $(call fio_bench_sq,$(OUTPUT)))

.PHONY: concurrent-memory
concurrent-memory: ## 50 コンテナ同時起動時の集約 PSS を計測する（実機前提・timeout 付き。LAUNCHER=<絶対パス> BUNDLE=<dir> TARGET=<名前> 必須）
	@if [ -z $(call fio_bench_sq,$(LAUNCHER)) ] || [ -z $(call fio_bench_sq,$(BUNDLE)) ] || [ -z $(call fio_bench_sq,$(TARGET)) ]; then \
		echo "usage: make concurrent-memory LAUNCHER=<abs-path> BUNDLE=<dir> TARGET=<name, e.g. own> [COUNT=<n, default 50>] [TRIALS=<n, default 3>] [OUTPUT=<new file>] [CONCURRENT_MEMORY_TIMEOUT=<secs, default 1800>]" >&2; \
		exit 2; \
	fi; \
	t=$(call fio_bench_sq,$(CONCURRENT_MEMORY_TIMEOUT)); \
	case "$$t" in ''|*[!0-9]*|???????*) t=invalid ;; esac; \
	if [ "$$t" = invalid ] || [ "$$t" -eq 0 ]; then \
		echo "error: invalid-argument: CONCURRENT_MEMORY_TIMEOUT must be an integer from 1 to 999999 (seconds)" >&2; \
		exit 2; \
	fi; \
	if ! command -v timeout >/dev/null 2>&1; then \
		echo "error: unsupported-os: timeout (coreutils) is required" >&2; \
		exit 2; \
	fi; \
	rc=0; \
	timeout --kill-after=60 "$$t" bash $(call fio_bench_sq,$(CONCURRENT_MEMORY_SCRIPT)) --launcher $(call fio_bench_sq,$(LAUNCHER)) --bundle $(call fio_bench_sq,$(BUNDLE)) --target $(call fio_bench_sq,$(TARGET))$(if $(COUNT), --count $(call fio_bench_sq,$(COUNT)))$(if $(TRIALS), --trials $(call fio_bench_sq,$(TRIALS)))$(if $(OUTPUT), --output $(call fio_bench_sq,$(OUTPUT))) || rc=$$?; \
	case "$$rc" in \
		0|1|2|3|4) exit "$$rc" ;; \
		124|137) echo "error: measurement-failed: timed out after $${t}s (measurement or cleanup stalled)" >&2; exit 1 ;; \
		125|126|127) echo "error: invalid-input: cannot run the measurement under timeout (exit $$rc)" >&2; exit 2 ;; \
		*) echo "error: measurement-failed: unexpected exit status $$rc" >&2; exit 1 ;; \
	esac

# 監視プロセス独立性の実証スクリプト（TASK-162・SUP-5。実証・判定は #499 で人間が実機実行する）。
# `supervisor-independence-selftest` はスタブ launcher だけで照合する自己テスト（CI の bench-regression ジョブでも実行）、
# `supervisor-independence` は N（既定 50）個の監視プロセスのうち 1 個を SIGKILL して残りの継続と孤児の稼働継続を確認する
# 実機前提ターゲット（make ci には含めない。スクリプト内で sudo は呼ばない。launcher 契約はスクリプト冒頭を参照）。
# スクリプトの終了コード 0〜4 はそのまま返し、timeout 超過（124・137）と想定外の値は 1、起動不能（125〜127）は 2。
SUPERVISOR_INDEPENDENCE_TIMEOUT ?= 600
SUPERVISOR_INDEPENDENCE_SCRIPT ?= scripts/verify-supervisor-independence.sh

.PHONY: supervisor-independence-selftest
supervisor-independence-selftest: ## 監視プロセス独立性実証スクリプトの自己テスト（SUP-5・REPAIR-12。スタブ launcher のみ）
	bash scripts/verify-supervisor-independence-selftest.sh

.PHONY: supervisor-independence
supervisor-independence: ## 監視プロセス 1 個を kill して他の継続と孤児の稼働継続を確認する（実機前提・timeout 付き。LAUNCHER=<絶対パス> BUNDLE=<dir> 必須。SUP-5）
	@if [ -z $(call fio_bench_sq,$(LAUNCHER)) ] || [ -z $(call fio_bench_sq,$(BUNDLE)) ]; then \
		echo "usage: make supervisor-independence LAUNCHER=<abs-path> BUNDLE=<dir> [COUNT=<n, default 50>] [TARGET_INDEX=<k, default count/2 rounded up>] [OUTPUT=<new file>] [SUPERVISOR_INDEPENDENCE_TIMEOUT=<secs, default 600>]" >&2; \
		exit 2; \
	fi; \
	t=$(call fio_bench_sq,$(SUPERVISOR_INDEPENDENCE_TIMEOUT)); \
	case "$$t" in ''|*[!0-9]*|???????*) t=invalid ;; esac; \
	if [ "$$t" = invalid ] || [ "$$t" -eq 0 ]; then \
		echo "error: invalid-argument: SUPERVISOR_INDEPENDENCE_TIMEOUT must be an integer from 1 to 999999 (seconds)" >&2; \
		exit 2; \
	fi; \
	if ! command -v timeout >/dev/null 2>&1; then \
		echo "error: unsupported-os: timeout (coreutils) is required" >&2; \
		exit 2; \
	fi; \
	rc=0; \
	timeout --kill-after=60 "$$t" bash $(call fio_bench_sq,$(SUPERVISOR_INDEPENDENCE_SCRIPT)) --launcher $(call fio_bench_sq,$(LAUNCHER)) --bundle $(call fio_bench_sq,$(BUNDLE))$(if $(COUNT), --count $(call fio_bench_sq,$(COUNT)))$(if $(TARGET_INDEX), --target-index $(call fio_bench_sq,$(TARGET_INDEX)))$(if $(OUTPUT), --output $(call fio_bench_sq,$(OUTPUT))) || rc=$$?; \
	case "$$rc" in \
		0|1|2|3|4) exit "$$rc" ;; \
		124|137) echo "error: timeout: verification or cleanup stalled for $${t}s" >&2; exit 1 ;; \
		125|126|127) echo "error: invalid-input: cannot run the verification under timeout (exit $$rc)" >&2; exit 2 ;; \
		*) echo "error: verification-failed: unexpected exit status $$rc" >&2; exit 1 ;; \
	esac

# restart レイテンシ実機実測スクリプト（TASK-160・SUP-3。実測・合否判定は #491 で人間が行う）。
# `restart-latency-selftest` はスタブ launcher だけで照合する自己テスト（CI の bench-regression ジョブでも実行）、
# `restart-latency` はバックオフ 0 でコンテナを繰り返し SIGKILL して再起動レイテンシの中央値・p95 を JSON 出力する
# 実機前提ターゲット（make ci には含めない。合否は出さない。スクリプト内で sudo は呼ばない。契約はスクリプト冒頭を参照）。
# 全体期限 RESTART_LATENCY_TIMEOUT（秒・1〜999999）は未指定ならスクリプトの --print-budget の値を使う
# （(試行数 + 2) × 各待機の上限 ＋ 試行ごとの余裕 ＋ 後始末 60 秒。既定の 20 試行・warmup 1・待機 30 秒で 813 秒）。
# 固定値にしないのは、TRIALS・WARMUP・RESTART_LATENCY_WAIT_TIMEOUT を変えたときに正常な計測を途中で打ち切らないため
# （REPAIR-5）。明示した値が上限より短い場合は警告を出してそのまま使う。
# timeout は --preserve-status で使い、スクリプトの終了コードを保つ（期限切れの TERM でも後始末失敗の 4 を隠さない）。
# スクリプトの終了コード 0〜4 はそのまま返す。期限切れ・中断（後始末は完了。129・130・143）と想定外の値は 1、
# 後始末の完了前に SIGKILL された場合（137。--kill-after 60 秒の超過を含む）は残存を否定できないため 4、
# 起動不能（125〜127）は 2。
RESTART_LATENCY_TIMEOUT ?=
RESTART_LATENCY_SCRIPT ?= scripts/measure-restart-latency.sh

.PHONY: restart-latency-selftest
restart-latency-selftest: ## restart レイテンシ計測スクリプトの自己テスト（SUP-3・REPAIR-12。スタブ launcher のみ）
	bash scripts/measure-restart-latency-selftest.sh

.PHONY: restart-latency
restart-latency: ## バックオフ 0 の restart レイテンシを計測する（実機前提・timeout 付き。LAUNCHER=<絶対パス> BUNDLE=<dir> 必須。[TRIALS= WARMUP= OUTPUT= RESTART_LATENCY_WAIT_TIMEOUT=]。SUP-3）
	@if [ -z $(call fio_bench_sq,$(LAUNCHER)) ] || [ -z $(call fio_bench_sq,$(BUNDLE)) ]; then \
		echo "usage: make restart-latency LAUNCHER=<abs-path> BUNDLE=<dir> [TRIALS=<n, default 20>] [WARMUP=<n, default 1>] [OUTPUT=<new file>] [RESTART_LATENCY_WAIT_TIMEOUT=<secs per wait, default 30>] [RESTART_LATENCY_TIMEOUT=<secs for the whole run, default: computed from the above>]" >&2; \
		exit 2; \
	fi; \
	if ! command -v timeout >/dev/null 2>&1; then \
		echo "error: unsupported-os: timeout (coreutils) is required" >&2; \
		exit 2; \
	fi; \
	set --; \
	if [ -n $(call fio_bench_sq,$(TRIALS)) ]; then set -- "$$@" --trials $(call fio_bench_sq,$(TRIALS)); fi; \
	if [ -n $(call fio_bench_sq,$(WARMUP)) ]; then set -- "$$@" --warmup $(call fio_bench_sq,$(WARMUP)); fi; \
	if [ -n $(call fio_bench_sq,$(RESTART_LATENCY_WAIT_TIMEOUT)) ]; then set -- "$$@" --timeout $(call fio_bench_sq,$(RESTART_LATENCY_WAIT_TIMEOUT)); fi; \
	budget="$$(bash $(call fio_bench_sq,$(RESTART_LATENCY_SCRIPT)) --print-budget "$$@")" || exit 2; \
	case "$$budget" in ''|*[!0-9]*|???????*) echo "error: invalid-input: cannot compute the time budget" >&2; exit 2 ;; esac; \
	t=$(call fio_bench_sq,$(RESTART_LATENCY_TIMEOUT)); \
	if [ -z "$$t" ]; then t="$$budget"; fi; \
	case "$$t" in ''|*[!0-9]*|???????*) t=invalid ;; esac; \
	if [ "$$t" = invalid ] || [ "$$t" -eq 0 ]; then \
		echo "error: invalid-argument: RESTART_LATENCY_TIMEOUT must be an integer from 1 to 999999 (seconds)" >&2; \
		exit 2; \
	fi; \
	if [ "$$t" -lt "$$budget" ]; then \
		echo "warning: RESTART_LATENCY_TIMEOUT=$${t}s is shorter than the worst-case duration $${budget}s; a slow but valid run may be cut off" >&2; \
	fi; \
	if [ -n $(call fio_bench_sq,$(OUTPUT)) ]; then set -- "$$@" --output $(call fio_bench_sq,$(OUTPUT)); fi; \
	rc=0; \
	timeout --preserve-status --kill-after=60 "$$t" bash $(call fio_bench_sq,$(RESTART_LATENCY_SCRIPT)) --launcher $(call fio_bench_sq,$(LAUNCHER)) --bundle $(call fio_bench_sq,$(BUNDLE)) "$$@" || rc=$$?; \
	case "$$rc" in \
		0|1|2|3|4) exit "$$rc" ;; \
		129|130|143) echo "error: timeout: the measurement was stopped by a signal (time limit $${t}s or an interrupt); cleanup completed and no result is published" >&2; exit 1 ;; \
		137) echo "error: cleanup-failed: the measurement was killed before cleanup finished; processes may remain, inspect and kill them manually" >&2; exit 4 ;; \
		125|126|127) echo "error: invalid-input: cannot run the measurement under timeout (exit $$rc)" >&2; exit 2 ;; \
		*) echo "error: measurement-failed: unexpected exit status $$rc" >&2; exit 1 ;; \
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
