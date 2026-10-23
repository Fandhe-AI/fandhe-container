# fandhe-container の開発用 Makefile。
#
# Make は scripts/ 配下のスクリプトを呼ぶだけの薄い入口であり、処理の定義（複数行シェル・条件分岐・
# ツール導入・timeout 変換など）は scripts/ 側にのみ置く（各レシピは 1 行の呼び出しに限定し、ここで
# チェック内容を二重定義しない）。cargo 1 コマンドで済む docker-* のみ直接書く。
# Make を使わない場合の同等コマンドは scripts/help.sh を参照。変更時は .claude/rules/makefile.md に従う。
#
# 使い方: `make help`（既定ターゲット）でターゲット一覧を表示する。一覧は各ターゲット行の `## ` コメントから
# 生成されるため、`## ` の無いターゲットは表示されない。ターゲットを追加・改名・削除したら scripts/help.sh も
# 同じ変更で更新すること。中身の無いターゲット（`@true` 等）は呼び出し元が終了コードを信用してしまうため置かない。
#
# 入力は make 変数（`make fio-bench TARGET_DIR=... LABEL=...`）で渡す。コマンドラインの make 変数は環境変数として
# レシピに渡るため、scripts/targets/*.sh は同名の環境変数として読む（必須変数と既定値は各スクリプト冒頭を参照）。
# 固定バージョン（lint ツール・cargo-deny・cargo-about・lefthook）は scripts/versions.sh が単一の定義元。
#
# `make ci` でローカル検証（.claude/rules/ci.md のローカルゲート）を一括実行する。実装は未着手の間
# （`crates/` 配下に実クレート未追加）は cargo 系ターゲットを scripts/ 側で skip し、workspace 作成後に自動で
# 有効化される（冪等セルフヒール）。Docker で環境非依存に開発・検証する場合は docker-* ターゲットを使う
# （compose.yaml 参照）。Fandhe-AI/rust-ai-library の Makefile と同一方針。
#
# GNU Make 3.81（macOS 標準）で動作する書き方に限る。3.82+ 専用機能（.ONESHELL・.RECIPEPREFIX 等）は使わない。

.DEFAULT_GOAL := help
SHELL := /bin/bash

.PHONY: help setup rustup submodule hooks lint-md lint-yaml lint-editorconfig lint-commits lint-docs \
	check-workspace-manifest fmt fmt-check lint test doc poc-venus-jig-check check-cli-backend-deps \
	check-launch-target check-launch-target-selftest \
	test-core-no-plugin plugin-feature-size plug4-core-invariance plug4-core-invariance-selftest \
	test-integration cli-parity-selftest cli-parity-native-reclaim-check \
	cli-parity-native-reclaim-selftest commit-msg-line-length-selftest crash-summary-check \
	crash-summary-check-selftest lib-selftest \
	vz-virtio-gpu-guest-check-selftest guest-kernel-build guest-kernel-build-selftest guest-initrd-build guest-initrd-build-selftest third-party-licenses-selftest deny-license-fail-closed-selftest \
	bench-check-selftest bench-baseline-selftest fio-bench-selftest fio-baseline-ratio-selftest \
	startup-latency-selftest net-setup-timing-selftest small-files-compare-selftest dns-helper-measure-selftest idle-memory-selftest \
	idle-memory-supervised-selftest supervisor-pss-selftest concurrent-memory-selftest \
	supervisor-independence-selftest restart-latency-selftest install-launcher-selftest crictl-smoke-selftest repeat-test repeat-test-selftest deny deny-poc-venus-jig \
	third-party-licenses install-cargo-about ci bench-check bench-check-manual bench-baseline-manual bench-plugin-boundary \
	bench-macos-cold-start bench-baseline cli-parity fio-bench fio-baseline-ratio startup-latency \
	startup-latency-docker startup-latency-report net-setup-timing small-files-compare dns-helper-measure idle-memory \
	idle-memory-supervised supervisor-pss concurrent-memory concurrent-memory-docker \
	concurrent-memory-report supervisor-independence restart-latency crictl-smoke docker-build docker-shell \
	docker-ci

# --------------------------------------------------
# ヘルプ
# --------------------------------------------------

help: ## ターゲット一覧を表示する（Make 非依存の一覧: scripts/help.sh）
	@awk 'BEGIN {FS = ":.*## "} /^[a-zA-Z0-9_-]+:.*## /{printf "  \033[36m%-34s\033[0m %s\n", $$1, $$2}' $(firstword $(MAKEFILE_LIST))

# --------------------------------------------------
# 環境構築
# --------------------------------------------------

setup: ## 開発環境を一括構築する（サブモジュール → rustup → lefthook の順を保証）
	@scripts/targets/setup.sh

rustup: ## rustup（cargo）の導入を確認する（未導入なら公式手順を案内して停止）
	@scripts/targets/rustup.sh

submodule: ## docs/spec サブモジュールを初期化・更新する（private・アクセス権が無ければ警告のみ）
	@scripts/targets/submodule.sh

hooks: ## lefthook の git hooks を導入する（未導入なら lefthook 本体も導入）
	@scripts/targets/hooks.sh

# --------------------------------------------------
# ドキュメント／設定ファイル系 lint（CI の lint-docs ジョブと同等）
# --------------------------------------------------

lint-md: ## markdownlint（.markdownlint.jsonc / .markdownlintignore 参照）
	@scripts/targets/lint-md.sh

lint-yaml: ## yamllint（.yamllint 参照）
	@scripts/targets/lint-yaml.sh

lint-editorconfig: ## editorconfig-checker（.editorconfig + .editorconfig-checker.json 参照）
	@scripts/targets/lint-editorconfig.sh

lint-commits: ## commitlint（origin/main からの分岐点以降のコミットを検証）
	@scripts/targets/lint-commits.sh

lint-docs: lint-md lint-yaml lint-editorconfig lint-commits ## ドキュメント／設定ファイル系 lint を一括実行する

# --------------------------------------------------
# 品質チェック（Rust。Cargo.toml 追加後に有効化。cargo 系は scripts/ 側で Cargo.toml・member crate の有無を判定して skip する）
# --------------------------------------------------

check-workspace-manifest: ## cargo verify-project で workspace manifest の妥当性を検証する
	@scripts/targets/check-workspace-manifest.sh

fmt: ## cargo fmt --all で整形する
	@scripts/targets/cargo-workspace.sh fmt

fmt-check: ## cargo fmt --check（整形差分の検出）
	@scripts/targets/cargo-workspace.sh fmt-check

lint: ## cargo clippy -D warnings（既定 feature。lint ゲート）
	@scripts/targets/cargo-workspace.sh lint

test: ## cargo test（既定 feature。workspace 全体）
	@scripts/targets/cargo-workspace.sh test

doc: ## cargo doc -D warnings（既定 feature・--no-deps。rustdoc 警告のゲート）
	@scripts/targets/cargo-workspace.sh doc

poc-venus-jig-check: ## venus 試験治具（poc/venus-decoder/jig）の fmt-check・clippy・test を実行する（GPU-6・TASK-172.4）
	@scripts/targets/poc-venus-jig-check.sh

check-cli-backend-deps: ## cli の依存ツリー（normal/build/dev・全ターゲット）に platform-* / plugin-macos / plugin-windows / microvm 系が含まれないことを検証する
	@scripts/targets/check-cli-backend-deps.sh

check-launch-target: ## plugin 起動対象の構築口 from_verified_file を呼ぶのが core の変換と許可した試験コードだけか判定する（PLUG-11・#1857）
	@scripts/targets/check-launch-target.sh

check-launch-target-selftest: ## check-launch-target の自己テスト（REPAIR-12。fixture のみ）
	@scripts/check-plugin-launch-target-construction-selftest.sh

test-core-no-plugin: ## core を --no-default-features でテストし plugin 依存が入らないことを検証する
	@scripts/targets/test-core-no-plugin.sh

plugin-feature-size: ## core の既定 / plugin 除外 release ビルドの rlib サイズを記録する（PLUG-3・TASK-111.2）
	@scripts/targets/plugin-feature-size.sh

plug4-core-invariance: ## plugin 追加前後で core の指紋が不変か別ビルドで比較する（PLUG-4・TASK-109.4）
	@scripts/with-workspace.sh plug4-core-invariance bash scripts/check-plug4-core-invariance.sh

plug4-core-invariance-selftest: ## PLUG-4 判定スクリプトの自己テスト（TASK-109.4・REPAIR-12。fixture workspace）
	@scripts/with-tools.sh cargo,git scripts/check-plug4-core-invariance-selftest.sh

test-integration: ## cargo test --workspace --test '*' --features fandhe-container-io/crash-test-server（結合試験。0 件なら notice で成功終了）
	@scripts/targets/test-integration.sh

# --------------------------------------------------
# スクリプトの自己テスト・CI 向け確認（make ci には含めない）
# --------------------------------------------------

cli-parity-selftest: ## CLI 3 OS 比較スクリプトの自己テスト（TASK-125.1・REPAIR-12。スタブ CLI のみ）
	@scripts/cli-parity-check-selftest.sh

cli-parity-native-reclaim-check: ## capture のタイムアウトでネイティブ exe の子孫が回収されるかの確認（#1548）
	@scripts/cli-parity-native-reclaim-check.sh

cli-parity-native-reclaim-selftest: ## 回収確認スクリプトの全体期限の自己テスト（#1688・REPAIR-5・REPAIR-12）
	@scripts/cli-parity-native-reclaim-check-selftest.sh

lib-selftest: ## scripts/lib.sh の workspace 判定と run_limited の回帰テスト（bash 3.2 を含む。一時ディレクトリのみ）
	@scripts/lib-selftest.sh

commit-msg-line-length-selftest: ## commit-msg 行長検査スクリプトの自己テスト（Issue #1295・REPAIR-12）
	@scripts/check-commit-msg-line-length-selftest.sh

crash-summary-check: ## crash_safety の件数サマリーを検証し表で出す。CRASH_SUMMARY_DIR 必須・CRASH_SUMMARY_OS 任意（#1833・IO-3）
	@scripts/check-crash-summary.sh --dir "$(CRASH_SUMMARY_DIR)" $(if $(CRASH_SUMMARY_OS),--os "$(CRASH_SUMMARY_OS)",)

crash-summary-check-selftest: ## crash-summary-check スクリプトの自己テスト（#1833・IO-3・REPAIR-12。fixture のみ）
	@scripts/with-tools.sh jq scripts/check-crash-summary-selftest.sh

vz-virtio-gpu-guest-check-selftest: ## virtio-gpu ゲスト側確認スクリプトの自己テスト（TASK-172.6・GPU-6・REPAIR-12。fixture のみ）
	@poc/vz-custom-virtio-gpu/guest/check-virtio-gpu-selftest.sh

guest-kernel-build: ## macOS ゲストカーネル（arm64）を取得・sha256 照合・ビルドする（TASK-64 追補・#1874・MAC-1。ネットワークと実ビルド。make ci には含めない）
	@guest/kernel/build.sh

guest-kernel-build-selftest: ## ゲストカーネルのビルドスクリプトの自己テスト（#1874・MAC-1・REPAIR-12。スタブのみ）
	@guest/kernel/build-selftest.sh

guest-initrd-build: ## macOS ゲスト init を静的リンクでビルドし /init だけの initrd（newc・gzip）を作る（TASK-64 追補・#1878・MAC-1。ローカルの実ビルド。make ci には含めない）
	@scripts/build-guest-initrd.sh

guest-initrd-build-selftest: ## ゲスト initrd 梱包スクリプトの自己テスト（#1878・MAC-1・REPAIR-12。スタブ・fixture のみ）
	@scripts/build-guest-initrd-selftest.sh

third-party-licenses-selftest: ## ライセンス表記生成スクリプトの自己テスト（スタブ cargo のみ。TASK-103.1）
	@scripts/generate-third-party-licenses-selftest.sh

deny-license-fail-closed-selftest: ## deny.toml のライセンス fail-closed 自己テスト（TASK-90.2・OSS-4・OSS-5）
	@scripts/targets/deny-license-fail-closed-selftest.sh

bench-check-selftest: ## ベンチ回帰比較スクリプトの自己テスト（REPAIR-8）
	@scripts/with-tools.sh jq scripts/check-bench-regression-selftest.sh

bench-baseline-selftest: ## baseline.json 生成スクリプトの自己テスト（TASK-88.1・REPAIR-12）
	@scripts/with-tools.sh jq scripts/bench/generate_baseline_selftest.sh

fio-bench-selftest: ## fio ベンチスクリプトの自己テスト（REPAIR-12。実 fio 不要）
	@scripts/with-tools.sh jq scripts/fio-randwrite-4k-selftest.sh

fio-baseline-ratio-selftest: ## fio ベースライン比算出スクリプトの自己テスト（REPAIR-12。実 fio 不要）
	@scripts/with-tools.sh jq scripts/fio-baseline-ratio-selftest.sh

startup-latency-selftest: ## 起動時間計測スクリプトの自己テスト（REPAIR-12。実ランタイム不要）
	@scripts/with-tools.sh jq scripts/bench/startup_latency_selftest.sh

net-setup-timing-selftest: ## ネットワーク作成/接続/削除の所要時間計測スクリプトの自己テスト（NET-4・REPAIR-12。実機不要）
	@scripts/with-tools.sh jq scripts/bench/net_setup_timing_selftest.sh

small-files-compare-selftest: ## bind / named volume 比較スクリプトの自己テスト（IO-7・REPAIR-12。実ハーネス不要）
	@scripts/with-tools.sh jq scripts/bench/small_files_compare_selftest.sh

dns-helper-measure-selftest: ## DNS ヘルパー計測スクリプトの自己テスト（NET-5・REPAIR-12。実機不要）
	@scripts/with-tools.sh jq scripts/bench/dns_helper_measure_selftest.sh

idle-memory-selftest: ## アイドル時常駐メモリ計測スクリプトの自己テスト（CORE-7・REPAIR-12）
	@scripts/bench/idle_memory_selftest.sh

idle-memory-supervised-selftest: ## 監視プロセス込みアイドル常駐メモリ回帰テストの自己テスト（TASK-47・CORE-7・REPAIR-12）
	@scripts/bench/idle_memory_supervised_selftest.sh

supervisor-pss-selftest: ## 監視プロセス常駐メモリ計測スクリプトの自己テスト（TASK-158・SUP-2・REPAIR-12）
	@scripts/bench/supervisor_pss_selftest.sh

concurrent-memory-selftest: ## 50 コンテナ同時起動メモリ計測スクリプトの自己テスト（CORE-9・REPAIR-12。スタブ・疑似 /proc）
	@scripts/bench/concurrent_50_memory_selftest.sh

supervisor-independence-selftest: ## 監視プロセス独立性実証スクリプトの自己テスト（SUP-5・REPAIR-12。スタブのみ）
	@scripts/verify-supervisor-independence-selftest.sh

restart-latency-selftest: ## restart レイテンシ計測スクリプトの自己テスト（SUP-3・REPAIR-12。スタブのみ）
	@scripts/measure-restart-latency-selftest.sh

install-launcher-selftest: ## 特権ランチャーのインストールスクリプトの自己テスト（SUP-14・SEC-1・REPAIR-12。スタブのみ・root 不要）
	@scripts/install-privileged-launcher-selftest.sh

repeat-test-selftest: ## repeat-test スクリプトの自己テスト（REPAIR-12・#2538。スタブの cargo のみ）
	@scripts/repeat-test-selftest.sh

crictl-smoke-selftest: ## crictl 疎通確認スクリプトの自己テスト（CRI-1・TASK-60・REPAIR-12。スタブの crictl のみ・python3 が必要）
	@scripts/with-tools.sh python3 scripts/cri/crictl-smoke-selftest.sh

# --------------------------------------------------
# 依存監査・ライセンス表記
# --------------------------------------------------

deny: ## cargo deny check advisories bans licenses sources（ルート workspace と venus 試験治具の依存監査。cargo-deny 未導入なら自動導入）
	@scripts/targets/deny.sh

deny-poc-venus-jig: ## venus 試験治具（poc/venus-decoder/jig）の Cargo.lock を cargo deny で検査する（ルートの deny.toml を共有）
	@scripts/targets/deny-poc-venus-jig.sh

third-party-licenses: ## サードパーティのライセンス表記を cargo about で生成する（cargo-about 未導入なら失敗。OUTPUT=<file> 任意）
	@scripts/targets/third-party-licenses.sh

install-cargo-about: ## cargo-about を固定版で導入する（TASK-103.2。版は CARGO_ABOUT_VERSION）
	@scripts/targets/install-cargo-about.sh

# --------------------------------------------------
# ローカルゲート
# --------------------------------------------------

ci: lint-docs check-workspace-manifest fmt-check lint test doc deny ## ローカルゲート（.claude/rules/ci.md）と同等のチェックを一括実行する

# --------------------------------------------------
# ベンチ回帰（REPAIR-7 第 4 段階・REPAIR-8。make ci には含めない）
# --------------------------------------------------

bench-check: ## ベンチ回帰チェック（REPAIR-7 第 4 段階・REPAIR-8。現状はプレースホルダベンチ）
	@scripts/targets/bench-check.sh

bench-check-manual: ## 実機前提ベンチ（起動 p95）の結果を基準値と比較する（REPAIR-8・#1901。CI では実行しない。BENCH_RESULTS=<絶対パス> 必須・基準値があれば結果の host_kind か BENCH_HOST_KIND が必須で環境が違えば 2）
	@scripts/with-tools.sh jq scripts/targets/bench-check-manual.sh

bench-baseline-manual: ## 実機前提ベンチ（起動 p95）の結果から基準値を生成する（REPAIR-8・#2095。BENCH_RESULTS 必須・結果の host_kind が unknown か無ければ BENCH_HOST_KIND も必須。既定の出力先は target/ 配下）
	@scripts/with-tools.sh jq scripts/targets/bench-baseline-manual.sh

bench-plugin-boundary: ## plugin 境界ベンチを実行し Δp50 と CORE-10 比をログ出力する（TASK-113.3・PLUG-5。基準値比較なし）
	@scripts/targets/bench-plugin-boundary.sh

bench-macos-cold-start: ## macOS cold start 上乗せを計測する（TASK-113.4・PLUG-6・MAC-2。macOS 以外は skip）
	@scripts/with-workspace.sh bench-macos-cold-start cargo bench -p fandhe-container-benches --bench plugin_boundary_macos_cold_start

bench-baseline: ## ベンチを実行し baseline.json を再生成する（TASK-88.1・REPAIR-8）
	@scripts/targets/bench-baseline.sh

# --------------------------------------------------
# 実機前提の計測・突き合わせ（make ci には含めない。必須変数は各スクリプト冒頭を参照）
# --------------------------------------------------

cli-parity: ## CLI 3 OS 比較の capture（CLI/OUTPUT）または compare（BASELINE/CANDIDATE）を実行する
	@scripts/targets/cli-parity.sh

fio-bench: ## fio 4K ランダム write ベンチを実行する（要 fio・実機。TARGET_DIR/LABEL 必須）
	@scripts/targets/fio-bench.sh

fio-baseline-ratio: ## fio ベースライン比を算出する（BASELINE/CANDIDATE に results.json のパスを指定）
	@scripts/targets/fio-baseline-ratio.sh

startup-latency: ## 起動時間を計測する（実機前提。RUNTIME=<絶対パス> BUNDLE=<dir> TARGET=<名前> 必須）
	@scripts/targets/startup-latency.sh

startup-latency-docker: ## Docker の起動時間を計測する（実機前提。DOCKER=<docker の絶対パス> 必須。TASK-46.2）
	@scripts/targets/startup-latency-docker.sh

startup-latency-report: ## own と Docker の起動時間の結果を 1 つのレポートに統合する（OWN_RESULT=<file> DOCKER_RESULT=<file> 必須。TASK-46.2）
	@scripts/targets/startup-latency-report.sh

net-setup-timing: ## ネットワーク作成/接続/削除の所要時間を JSON で出力する（実機前提。EXE=<絶対パス> 必須。NET-4・TASK-139.5）
	@scripts/targets/net-setup-timing.sh

small-files-compare: ## bind / named volume の 2 構成で small_files を回し JSON で出力する（実機前提。BIND_ROOT・VOLUME_ROOT 必須。IO-7・TASK-24.1）
	@scripts/targets/small-files-compare.sh

dns-helper-measure: ## DNS ヘルパーの正答率・レイテンシ・常駐 PSS を JSON で出力する（実機前提。EXE=<絶対パス> 必須。NET-5・TASK-141.3）
	@scripts/targets/dns-helper-measure.sh

idle-memory: ## アイドル時常駐メモリ（プロセス数・PSS・RSS）を JSON で出力する（CORE-7。Linux 限定・timeout 付き）
	@scripts/targets/idle-memory.sh

idle-memory-supervised: ## 監視プロセス込みのアイドル常駐メモリ回帰テスト（DRIVER=<絶対パス> [EXPECTED_DIR=] [OUTPUT=]。CORE-7・Linux・実機前提）
	@scripts/targets/idle-memory-supervised.sh

supervisor-pss: ## 監視プロセスの PSS を計測（root で実行。PID="<pid>..." または COUNT=<N> と RUN_AS=<起動した利用者> 必須。[SAMPLES= INTERVAL= EXE_NAME= EXPECTED_DIR= OUTPUT=]。SUP-2・Linux・実機前提）
	@scripts/targets/supervisor-pss.sh

concurrent-memory: ## 50 コンテナ同時起動時の集約 PSS を計測する（root で実行し起動は降格。実機前提・timeout 付き。BIN_DIR=<絶対パス> BUNDLE=<dir> TARGET=<名前> RUN_AS=<利用者> 必須）
	@scripts/targets/concurrent-memory.sh

concurrent-memory-docker: ## Docker 側の 50 コンテナ同時起動時の集約 PSS を計測する（実機前提・timeout 付き。DOCKER=<docker の絶対パス> 必須。TASK-50.2）
	@scripts/targets/concurrent-memory-docker.sh

concurrent-memory-report: ## own と Docker の 50 コンテナ集約メモリの結果を 1 つのレポートに統合する（OWN_RESULT=<file> DOCKER_RESULT=<file> 必須。TASK-50.2）
	@scripts/targets/concurrent-memory-report.sh

supervisor-independence: ## 監視プロセス 1 個を kill して他の継続と孤児の稼働継続を確認する（実機前提・timeout 付き。BIN_DIR=<絶対パス> BUNDLE=<dir> 必須。SUP-5）
	@scripts/targets/supervisor-independence.sh

restart-latency: ## restart レイテンシを計測する（既定バックオフ 100ms 差し引き値も出す）（実機前提・timeout 付き。BIN_DIR=<絶対パス> BUNDLE=<dir> 必須。[TRIALS= WARMUP= OUTPUT= RESTART_LATENCY_WAIT_TIMEOUT=]。SUP-3）
	@scripts/targets/restart-latency.sh

repeat-test: ## 1 つの lib 試験を N 回繰り返す（PACKAGE=fandhe-container-<名> TEST=<完全名> [COUNT=300 RUN_TIMEOUT=120]。REPAIR-12・#2538）
	@scripts/targets/repeat-test.sh

crictl-smoke: ## crictl の runp→create→start の疎通確認（実機前提・timeout 付き。CRI_ENDPOINT=unix:///<絶対パス> 必須。[CRICTL= POD_CONFIG= CONTAINER_CONFIG= LOG_DIR= STEP_TIMEOUT= CRICTL_TIMEOUT= KEEP=1]。CRI-1・TASK-60）
	@scripts/targets/crictl-smoke.sh

# --------------------------------------------------
# Docker（環境非依存の開発・検証。詳細は compose.yaml / Dockerfile 参照）
# --------------------------------------------------

docker-build: ## 開発コンテナイメージをビルドする
	docker compose build

docker-shell: ## 開発コンテナのシェルに入る
	docker compose run --rm dev

docker-ci: ## コンテナ内で make ci を実行する（環境非依存の検証）
	docker compose run --rm dev make ci
