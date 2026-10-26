#!/usr/bin/env bash
# Make を介さない操作一覧。`make help` は Makefile の `## ` コメントから機械的に生成されるのに対し、本ファイルは
# 手動で保守する一覧であり、両者を自動で同期する仕組みは無い。Makefile のターゲットを追加・改名・削除したら
# 同じ変更で本ファイルも更新すること（.claude/rules/makefile.md）。
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./lib.sh
source "${DIR}/lib.sh"

if [ "$#" -ne 0 ]; then
  echo "usage: help.sh (no arguments)" >&2
  exit 2
fi

cat <<'EOF'
このリポジトリの操作と、Make を使わずに直接実行する方法（make <target> は右のコマンドを呼ぶだけ）:

  help                                scripts/help.sh
                                        ターゲット一覧を表示する（Make 非依存の一覧: scripts/help.sh）
  setup                               scripts/targets/setup.sh
                                        開発環境を一括構築する（サブモジュール → rustup → lefthook の順を保証）
  rustup                              scripts/targets/rustup.sh
                                        rustup（cargo）の導入を確認する（未導入なら公式手順を案内して停止）
  submodule                           scripts/targets/submodule.sh
                                        docs/spec サブモジュールを初期化・更新する（private・アクセス権が無ければ警告のみ）
  hooks                               scripts/targets/hooks.sh
                                        lefthook の git hooks を導入する（未導入なら lefthook 本体も導入）
  lint-md                             scripts/targets/lint-md.sh
                                        markdownlint（.markdownlint.jsonc / .markdownlintignore 参照）
  lint-yaml                           scripts/targets/lint-yaml.sh
                                        yamllint（.yamllint 参照）
  lint-editorconfig                   scripts/targets/lint-editorconfig.sh
                                        editorconfig-checker（.editorconfig + .editorconfig-checker.json 参照）
  lint-commits                        scripts/targets/lint-commits.sh
                                        commitlint（origin/main からの分岐点以降のコミットを検証）
  lint-docs                           (make lint-md lint-yaml lint-editorconfig lint-commits)
                                        ドキュメント／設定ファイル系 lint を一括実行する
  check-workspace-manifest            scripts/targets/check-workspace-manifest.sh
                                        cargo verify-project で workspace manifest の妥当性を検証する
  fmt                                 scripts/targets/cargo-workspace.sh fmt
                                        cargo fmt --all で整形する
  fmt-check                           scripts/targets/cargo-workspace.sh fmt-check
                                        cargo fmt --check（整形差分の検出）
  lint                                scripts/targets/cargo-workspace.sh lint
                                        cargo clippy -D warnings（既定 feature。lint ゲート）
  test                                scripts/targets/cargo-workspace.sh test
                                        cargo test（既定 feature。workspace 全体）
  doc                                 scripts/targets/cargo-workspace.sh doc
                                        cargo doc -D warnings（既定 feature・--no-deps。rustdoc 警告のゲート）
  poc-venus-jig-check                 scripts/targets/poc-venus-jig-check.sh
                                        venus 試験治具（poc/venus-decoder/jig）の fmt-check・clippy・test を実行する（GPU-6・TASK-172.4）
  check-cli-backend-deps              scripts/targets/check-cli-backend-deps.sh
                                        cli の依存ツリー（normal/build/dev・全ターゲット）に platform-* / plugin-macos / plugin-windows / microvm 系が含まれないことを検証する
  check-launch-target                 scripts/targets/check-launch-target.sh
                                        plugin 起動対象の構築口 from_verified_file を呼ぶのが core の変換と許可した試験コードだけか判定する（PLUG-11・#1857）
  check-launch-target-selftest        scripts/check-plugin-launch-target-construction-selftest.sh
                                        check-launch-target の自己テスト（REPAIR-12。fixture のみ）
  check-standalone-clippy             scripts/targets/check-standalone-clippy.sh
                                        試験用 feature 無効の -p 単独 lib/bin ビルドの clippy を全メンバーに回す（CLIPPY_TARGET=<triple> で --target。#2640・REPAIR-12）
  check-standalone-clippy-selftest    scripts/check-standalone-clippy-selftest.sh
                                        check-standalone-clippy の自己テスト（REPAIR-12。スタブの cargo のみ。jq が必要）
  test-core-no-plugin                 scripts/targets/test-core-no-plugin.sh
                                        core を --no-default-features でテストし plugin 依存が入らないことを検証する
  plugin-feature-size                 scripts/targets/plugin-feature-size.sh
                                        core の既定 / plugin 除外 release ビルドの rlib サイズを記録する（PLUG-3・TASK-111.2）
  plug4-core-invariance               scripts/with-workspace.sh plug4-core-invariance bash scripts/check-plug4-core-invariance.sh
                                        plugin 追加前後で core の指紋が不変か別ビルドで比較する（PLUG-4・TASK-109.4）
  plug4-core-invariance-selftest      scripts/with-tools.sh cargo,git scripts/check-plug4-core-invariance-selftest.sh
                                        PLUG-4 判定スクリプトの自己テスト（TASK-109.4・REPAIR-12。fixture workspace）
  test-integration                    scripts/targets/test-integration.sh
                                        cargo test --workspace --test '*' --features fandhe-container-io/crash-test-server（結合試験。0 件なら notice で成功終了）
  cli-parity-selftest                 scripts/cli-parity-check-selftest.sh
                                        CLI 3 OS 比較スクリプトの自己テスト（TASK-125.1・REPAIR-12。スタブ CLI のみ）
  cli-parity-native-reclaim-check     scripts/cli-parity-native-reclaim-check.sh
                                        capture のタイムアウトでネイティブ exe の子孫が回収されるかの確認（#1548）
  cli-parity-native-reclaim-selftest  scripts/cli-parity-native-reclaim-check-selftest.sh
                                        回収確認スクリプトの全体期限の自己テスト（#1688・REPAIR-5・REPAIR-12）
  lib-selftest                        scripts/lib-selftest.sh
                                        scripts/lib.sh の workspace 判定の回帰テスト（bash 3.2 を含む。一時ディレクトリのみ）
  commit-msg-line-length-selftest     scripts/check-commit-msg-line-length-selftest.sh
                                        commit-msg 行長検査スクリプトの自己テスト（Issue #1295・REPAIR-12）
  crash-summary-check                 scripts/check-crash-summary.sh
                                        crash_safety の件数サマリーを検証し表で出す（#1833・IO-3。CRASH_SUMMARY_DIR 必須・CRASH_SUMMARY_OS 任意）
  crash-summary-check-selftest        scripts/with-tools.sh jq scripts/check-crash-summary-selftest.sh
                                        crash-summary-check の自己テスト（#1833・IO-3・REPAIR-12。fixture のみ）
  vz-virtio-gpu-guest-check-selftest  poc/vz-custom-virtio-gpu/guest/check-virtio-gpu-selftest.sh
                                        virtio-gpu ゲスト側確認スクリプトの自己テスト（TASK-172.6・GPU-6・REPAIR-12。fixture のみ）
  guest-kernel-build                  guest/kernel/build.sh
                                        macOS ゲストカーネル（arm64）の取得・sha256 照合・ビルド（TASK-64 追補・#1874・MAC-1。ネットワークと実ビルド。make ci には含めない）
  guest-kernel-build-selftest         guest/kernel/build-selftest.sh
                                        ゲストカーネルのビルドスクリプトの自己テスト（#1874・MAC-1・REPAIR-12。スタブのみ）
  guest-initrd-build                  scripts/build-guest-initrd.sh
                                        macOS ゲスト init の静的リンクビルドと /init だけの initrd（newc・gzip）の作成（TASK-64 追補・#1878・MAC-1。ローカルの実ビルド。make ci には含めない）
  guest-initrd-build-selftest         scripts/build-guest-initrd-selftest.sh
                                        ゲスト initrd 梱包スクリプトの自己テスト（#1878・MAC-1・REPAIR-12。スタブ・fixture のみ）
  third-party-licenses-selftest       scripts/generate-third-party-licenses-selftest.sh
                                        ライセンス表記生成スクリプトの自己テスト（スタブ cargo のみ。TASK-103.1）
  deny-license-fail-closed-selftest   scripts/targets/deny-license-fail-closed-selftest.sh
                                        deny.toml のライセンス fail-closed 自己テスト（TASK-90.2・OSS-4・OSS-5）
  bench-check-selftest                scripts/with-tools.sh jq scripts/check-bench-regression-selftest.sh
                                        ベンチ回帰比較スクリプトの自己テスト（REPAIR-8）
  bench-baseline-selftest             scripts/with-tools.sh jq scripts/bench/generate_baseline_selftest.sh
                                        baseline.json 生成スクリプトの自己テスト（TASK-88.1・REPAIR-12）
  fio-bench-selftest                  scripts/with-tools.sh jq scripts/fio-randwrite-4k-selftest.sh
                                        fio ベンチスクリプトの自己テスト（REPAIR-12。実 fio 不要）
  fio-baseline-ratio-selftest         scripts/with-tools.sh jq scripts/fio-baseline-ratio-selftest.sh
                                        fio ベースライン比算出スクリプトの自己テスト（REPAIR-12。実 fio 不要）
  startup-latency-selftest            scripts/with-tools.sh jq scripts/bench/startup_latency_selftest.sh
                                        起動時間計測スクリプトの自己テスト（REPAIR-12。実ランタイム不要）
  net-setup-timing-selftest           scripts/with-tools.sh jq scripts/bench/net_setup_timing_selftest.sh
                                        ネットワーク作成/接続/削除の所要時間計測スクリプトの自己テスト（NET-4・REPAIR-12。実機不要）
  small-files-compare-selftest        scripts/with-tools.sh jq scripts/bench/small_files_compare_selftest.sh
                                        bind / named volume 比較スクリプトの自己テスト（IO-7・REPAIR-12。実ハーネス不要）
  dns-helper-measure-selftest         scripts/with-tools.sh jq scripts/bench/dns_helper_measure_selftest.sh
                                        DNS ヘルパー計測スクリプトの自己テスト（NET-5・REPAIR-12。実機不要）
  idle-memory-selftest                scripts/bench/idle_memory_selftest.sh
                                        アイドル時常駐メモリ計測スクリプトの自己テスト（CORE-7・REPAIR-12）
  idle-memory-supervised-selftest     scripts/bench/idle_memory_supervised_selftest.sh
                                        監視プロセス込みアイドル常駐メモリ回帰テストの自己テスト（TASK-47・CORE-7・REPAIR-12）
  supervisor-pss-selftest             scripts/bench/supervisor_pss_selftest.sh
                                        監視プロセス常駐メモリ計測スクリプトの自己テスト（TASK-158・SUP-2・REPAIR-12）
  concurrent-memory-selftest          scripts/bench/concurrent_50_memory_selftest.sh
                                        50 コンテナ同時起動メモリ計測スクリプトの自己テスト（CORE-9・REPAIR-12。スタブ・疑似 /proc）
  supervisor-independence-selftest    scripts/verify-supervisor-independence-selftest.sh
                                        監視プロセス独立性実証スクリプトの自己テスト（SUP-5・REPAIR-12。スタブのみ）
  restart-latency-selftest            scripts/measure-restart-latency-selftest.sh
                                        restart レイテンシ計測スクリプトの自己テスト（SUP-3・REPAIR-12。スタブのみ）
  install-launcher-selftest           scripts/install-privileged-launcher-selftest.sh
                                        特権ランチャーのインストールスクリプトの自己テスト（SUP-14・SEC-1・REPAIR-12。スタブのみ・root 不要）
  crictl-smoke-selftest               scripts/cri/crictl-smoke-selftest.sh
                                        crictl 疎通確認スクリプトの自己テスト（CRI-1・TASK-60・REPAIR-12。スタブの crictl のみ・python3 が必要）
  docker-hub-ratelimit-probe-selftest scripts/cri/docker-hub-ratelimit-probe-selftest.sh
                                        Docker Hub 匿名 pull 残量プローブの自己テスト（CRI-3・REPAIR-12・#2818。スタブの curl のみ）
  repeat-test-selftest                scripts/repeat-test-selftest.sh
                                        repeat-test.sh の自己テスト（REPAIR-12・#2660。lib と結合試験の両モード。入力検査・回数範囲・1 回ごとの timeout・成功行の照合をスタブで確認）
  check-success-lines-selftest        scripts/check-success-lines-selftest.sh
                                        check-success-lines.sh の自己テスト（REPAIR-7・REPAIR-12・PLUG-12。ソース導出の期待行の照合・双方向照合・forbid の矛盾検査・fail-closed を fixture で確認）
  deny                                scripts/targets/deny.sh
                                        cargo deny check advisories bans licenses sources（ルート workspace と venus 試験治具の依存監査。cargo-deny 未導入なら自動導入）
  deny-poc-venus-jig                  scripts/targets/deny-poc-venus-jig.sh
                                        venus 試験治具（poc/venus-decoder/jig）の Cargo.lock を cargo deny で検査する（ルートの deny.toml を共有）
  third-party-licenses                scripts/targets/third-party-licenses.sh
                                        サードパーティのライセンス表記を cargo about で生成する（cargo-about 未導入なら失敗。OUTPUT=<file> 任意）
  install-cargo-about                 scripts/targets/install-cargo-about.sh
                                        cargo-about を固定版で導入する（TASK-103.2。版は CARGO_ABOUT_VERSION）
  ci                                  (make lint-docs check-workspace-manifest fmt-check lint test doc deny)
                                        ローカルゲート（.claude/rules/ci.md）と同等のチェックを一括実行する
  bench-check                         scripts/targets/bench-check.sh
                                        ベンチ回帰チェック（REPAIR-7 第 4 段階・REPAIR-8。現状はプレースホルダベンチ）
  bench-check-manual                  scripts/targets/bench-check-manual.sh
                                        実機前提ベンチ（起動 p95）の結果を基準値と比較する（REPAIR-8・#1901。CI では実行しない。BENCH_RESULTS=<絶対パス> 必須・基準値があれば結果の host_kind か BENCH_HOST_KIND が必須で環境が違えば 2）
  bench-baseline-manual               scripts/with-tools.sh jq scripts/targets/bench-baseline-manual.sh
                                        実機前提ベンチ（起動 p95）の結果から基準値を生成する（REPAIR-8・#2095。BENCH_RESULTS 必須・結果の host_kind が unknown か無ければ BENCH_HOST_KIND も必須。既定の出力先は target/ 配下）
  bench-plugin-boundary               scripts/targets/bench-plugin-boundary.sh
                                        plugin 境界ベンチを実行し Δp50 と CORE-10 比をログ出力する（TASK-113.3・PLUG-5。基準値比較なし）
  bench-macos-cold-start              scripts/with-workspace.sh bench-macos-cold-start cargo bench -p fandhe-container-benches --bench plugin_boundary_macos_cold_start
                                        macOS cold start 上乗せを計測する（TASK-113.4・PLUG-6・MAC-2。macOS 以外は skip）
  bench-baseline                      scripts/targets/bench-baseline.sh
                                        ベンチを実行し baseline.json を再生成する（TASK-88.1・REPAIR-8）
  cli-parity                          scripts/targets/cli-parity.sh
                                        CLI 3 OS 比較の capture（CLI/OUTPUT）または compare（BASELINE/CANDIDATE）を実行する
  fio-bench                           scripts/targets/fio-bench.sh
                                        fio 4K ランダム write ベンチを実行する（要 fio・実機。TARGET_DIR/LABEL 必須）
  fio-baseline-ratio                  scripts/targets/fio-baseline-ratio.sh
                                        fio ベースライン比を算出する（BASELINE/CANDIDATE に results.json のパスを指定）
  startup-latency                     scripts/targets/startup-latency.sh
                                        起動時間を計測する（実機前提。RUNTIME=<絶対パス> BUNDLE=<dir> TARGET=<名前> 必須）
  startup-latency-docker              scripts/targets/startup-latency-docker.sh
                                        Docker の起動時間を計測する（実機前提。DOCKER=<docker の絶対パス> 必須。TASK-46.2）
  startup-latency-report              scripts/targets/startup-latency-report.sh
                                        own と Docker の起動時間の結果を 1 つのレポートに統合する（OWN_RESULT=<file> DOCKER_RESULT=<file> 必須。TASK-46.2）
  net-setup-timing                    scripts/targets/net-setup-timing.sh
                                        ネットワーク作成/接続/削除の所要時間を JSON で出力する（実機前提。EXE=<絶対パス> 必須。NET-4・TASK-139.5）
  small-files-compare                 scripts/targets/small-files-compare.sh
                                        bind / named volume の 2 構成で small_files を回し JSON で出力する（実機前提。BIND_ROOT・VOLUME_ROOT 必須。IO-7・TASK-24.1）
  dns-helper-measure                  scripts/targets/dns-helper-measure.sh
                                        DNS ヘルパーの正答率・レイテンシ・常駐 PSS を JSON で出力する（実機前提。EXE=<絶対パス> 必須。NET-5・TASK-141.3）
  idle-memory                         scripts/targets/idle-memory.sh
                                        アイドル時常駐メモリ（プロセス数・PSS・RSS）を JSON で出力する（CORE-7。Linux 限定・timeout 付き）
  idle-memory-supervised              scripts/targets/idle-memory-supervised.sh
                                        監視プロセス込みのアイドル常駐メモリ回帰テスト（DRIVER=<絶対パス> [EXPECTED_DIR=] [OUTPUT=]。CORE-7・Linux・実機前提）
  supervisor-pss                      scripts/targets/supervisor-pss.sh
                                        監視プロセスの PSS を計測（PID="<pid>..." または COUNT=<N>。[SAMPLES= INTERVAL= EXE_NAME= EXPECTED_DIR= OUTPUT=]。SUP-2・Linux・実機前提）
  concurrent-memory                   scripts/targets/concurrent-memory.sh
                                        50 コンテナ同時起動時の集約 PSS を計測する（実機前提・timeout 付き。BIN_DIR=<絶対パス> BUNDLE=<dir> TARGET=<名前> 必須）
  concurrent-memory-docker            scripts/targets/concurrent-memory-docker.sh
                                        Docker 側の 50 コンテナ同時起動時の集約 PSS を計測する（実機前提・timeout 付き。DOCKER=<docker の絶対パス> 必須。TASK-50.2）
  concurrent-memory-report            scripts/targets/concurrent-memory-report.sh
                                        own と Docker の 50 コンテナ集約メモリの結果を 1 つのレポートに統合する（OWN_RESULT=<file> DOCKER_RESULT=<file> 必須。TASK-50.2）
  supervisor-independence             scripts/targets/supervisor-independence.sh
                                        監視プロセス 1 個を kill して他の継続と孤児の稼働継続を確認する（実機前提・timeout 付き。BIN_DIR=<絶対パス> BUNDLE=<dir> 必須。SUP-5）
  restart-latency                     scripts/targets/restart-latency.sh
                                        restart レイテンシを計測する（既定バックオフ 100ms 差し引き値も出す）（実機前提・timeout 付き。BIN_DIR=<絶対パス> BUNDLE=<dir> 必須。[TRIALS= WARMUP= OUTPUT= RESTART_LATENCY_WAIT_TIMEOUT=]。SUP-3）
  crictl-smoke                        scripts/targets/crictl-smoke.sh
                                        crictl の runp→create→start の疎通確認（実機前提・timeout 付き。CRI_ENDPOINT=unix:///<絶対パス> 必須。[CRICTL= POD_CONFIG= CONTAINER_CONFIG= LOG_DIR= STEP_TIMEOUT= CRICTL_TIMEOUT= KEEP=1]。CRI-1・TASK-60）
  docker-hub-ratelimit-probe          scripts/cri/docker-hub-ratelimit-probe.sh
                                        Docker Hub の匿名 pull 残量の事前確認（実機前提・外向き通信が要る。[PROBE_REPO= PROBE_TAG= PROBE_TIMEOUT_SECS=]。CRI-3・#2818）
  repeat-test                         scripts/targets/repeat-test.sh
                                        指定した試験を N 回繰り返して間欠失敗を検出する（REPAIR-12。1 回ごとに timeout・成功行 `1 passed` を照合）
  docker-build                        docker compose build
                                        開発コンテナイメージをビルドする
  docker-shell                        docker compose run --rm dev
                                        開発コンテナのシェルに入る
  docker-ci                           docker compose run --rm dev make ci
                                        コンテナ内で make ci を実行する（環境非依存の検証）

入力が要るターゲットは環境変数で渡す（例: TARGET_DIR=... LABEL=... scripts/targets/fio-bench.sh）。
必須変数と既定値は各スクリプト冒頭のコメントを参照。固定バージョンは scripts/versions.sh。
EOF
