# CI・ローカル検証規約（リポ固有。REPAIR 系ビヘイビア）

## ローカルゲート（コミット・PR 前）

開発速度を優先し、ローカルでは変更範囲に限った軽量な確認だけを行う（オーナー決定 2026-10-11）。ワークスペース全体の検証（clippy・test・doc・deny・lint-docs・3 OS・`--all-features`）は GitHub Actions の CI（`.github/workflows/ci.yml` の `rust-ci`・`platform-ci`・`cross-target-check`・`lint-docs`・`bench-regression`）を正のゲートとし、ローカルでは重複実行しない。

コミット・PR 前に必須とするのは次だけである。

1. 整形: `make fmt`（または `cargo fmt --all`）で整形する。`make fmt-check` は速いので通してよい
2. 変更した crate だけの lint とテスト: `cargo clippy -p <パッケージ名> --all-targets -- -D warnings` と `cargo test -p <パッケージ名>`（複数 crate なら `-p` を並べる）。`<パッケージ名>` はディレクトリ名ではなく Cargo のパッケージ名（`fandhe-container-<短縮名>`。例: `crates/io` は `-p fandhe-container-io`）。ワークスペース全体の `make lint`・`make test` は必須にしない
3. Rust 以外の変更: 変更したスクリプトに対応する自己テスト（`make <name>-selftest`）や、変更した Markdown / YAML だけの lint（必要なら）に限る。docs のみの変更ではビルド・テストを省略してよい
4. 他 crate へ波及しうる変更（共有の型・公開トレイト・`Cargo.toml`・feature・`cfg` 分岐の変更）では、`cargo check --workspace --all-targets` を追加で通す（型検査のみで速い）
5. PR のマージゲートは CI。CI が失敗したら、失敗したジョブ・テストの範囲だけを手元で再現して直す

維持するもの（ローカルを軽くしても変えない）:

- fail-closed: 変更した crate のテストを全件実行し、失敗・警告を 1 件でも残したまま進めない。ワークスペース全体は CI が検証し、CI の全ジョブが緑であることをマージの条件とする（失敗・警告を残したままマージしない）
- テストの skip・ignore・アサーション弱体化で通さない。clippy 警告 0 件を維持する
- `git commit --no-verify` を使わない
- 実機前提テストの扱い（下記「実機前提テスト」）と、ビヘイビア ID に対応づけたテストを書く義務（[coding-rust](coding-rust.md)「テスト」）

### 任意（CI の失敗の再現・リリース前の手元確認）

ワークスペース全体を手元で確認したいときは次を使う。ローカル必須ではない。

```bash
make fmt-check   # cargo fmt --all --check
make lint        # cargo clippy --workspace --all-targets -- -D warnings
make test        # cargo test --workspace
make doc         # RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps
make ci          # 上記 + lint-docs + deny を一括実行
```

- Cargo.toml・メンバー crate が未作成の間、cargo 系ターゲットは scripts/targets/ 側で skip される（Cargo.toml・メンバー crate の有無の判定。`scripts/lib.sh` の `skip_unless_workspace`）
- git hooks（lefthook）はこれらを実行しない（CI と重複するため。[git-hooks](git-hooks.md)）。上記の変更範囲の確認は手動で行う

## CI の構成（REPAIR-7 の 5 段階ゲート）

1. ビルド（`cargo build`・型検査）
2. ユニット / 統合テスト
3. タイムアウト保護された結合試験（ACK 未送信等のハングを検出。REPAIR-5）
4. ベンチ回帰チェック（15% 超の悪化で fail。REPAIR-8）
5. セキュリティチェック（`cargo deny`・禁止 API / 禁止クレート検査。REPAIR-9・MVM-4）

現状の `.github/workflows/ci.yml` は lint-docs・1・2（`rust-ci`〔ubuntu〕・`platform-ci`〔PR は ubuntu・main は 3 OS〕）・3（`platform-ci` ジョブ）・4 の比較の仕組み（`bench-regression` ジョブ）・5（rust-base-ci）相当のすべてに加え、アーキ・OS 網羅の型検査ゲート（`cross-target-check` ジョブ）を持ち、発火条件は `workflow_dispatch`・`pull_request`・`push`（main）で稼働している（TASK-86.1・TASK-86.2・TASK-86.3・REPAIR-7）。

crash_safety（IO-3）の有効 / 無効の試行数・損失件数は、「結合試験の実行」ステップだけが環境変数 `FANDHE_CONTAINER_CRASH_SUMMARY_DIR`（`runner.temp` 配下）を受け取り、直後の「crash_safety 件数の集計」ステップが `make crash-summary-check` で検証して `GITHUB_STEP_SUMMARY` に表を出す（#1833。新ジョブなし・check-run 件数不変）。ジョブ全体の env には置かない（macOS・Windows の `--all-features` ステップが同じディレクトリへ書いて排他作成が衝突するため）。

ステージ 3（タイムアウト保護された結合試験）は `platform-ci` ジョブ（PR は ubuntu のみ・main への push と `workflow_dispatch` は 3 OS の matrix。実行ステップ 10 分・ジョブ全体 60 分の timeout-minutes）が担う（TASK-86.2・#36。旧 `integration-test` ジョブ）。

`platform-ci` の ubuntu は、AppArmor の `kernel.apparmor_restrict_unprivileged_userns` を緩和するステップ（sudo の用途はこれだけ）の後に、Linux 限定で `--ignored` の実機前提テスト（`harness = false` の試験と libtest の `#[ignore]` の試験。`unshare_isolation`・`exec_setns_join`・`container_options_ipc`・`tmpfs_mount`・`inject_files`・`readonly_paths`〔SEC-2・#1850〕・`config_paths_implicit_dev`〔SEC-2・#2015。暗黙の `/dev` 系と重なる保護パスの exec 層での観測〕・`lo_self_delivery`〔NET-2・NET-11・#2077。非特権 netns の `lo` の up 前後の自己宛て配送〕・`runtime_service_namespaces`〔CRI-2・#2220。libtest の `#[ignore]`〕・`production_launcher`〔CORE-1・CORE-5・CORE-6・SEC-1・SEC-4・SEC-5・#2376。委譲スコープの中でバイナリを直接実行し、範囲写像のケースを含む〕・`rootless_file_owner`〔CORE-6・SEC-5・#2376。helper ケースを含む〕・`seccomp`〔CORE-5・#2376〕）をビルド・実行の 2 ステップずつで実行する。`--ignored` が届かなくても exit 0 になるため、各成功行（libtest のものは `test <名前> ... ok` の行）をログから grep で照合して false-green を防ぐ（新しい check-run は増えない。詳細は `AGENTS.md`「実機前提テスト」）。

`production_launcher`・`rootless_file_owner`・`seccomp` は、`linux-env-probe.yml` の `id-mapping-probe`（#2244）が ubuntu-latest の前提（`uidmap`・subuid / subgid の行・`systemd --user` の委譲 cgroup）を既定で満たすと実測したため、#2376 で `platform-ci` に組み込んだ。準備ステップは sudo を使わず前提を確認するだけで、欠けていれば fail-closed にする（`ubuntu-latest` の世代交代で落ちたら `id-mapping-probe` を回し直して判断し、確認は緩めない）。root で走る分岐（`root=true`）は CI では回さず、実機確認は #1621（人間担当）に残す。成功行の照合と除外の理由は `AGENTS.md`「実機前提テスト」を参照。

`platform-ci` ジョブは結合試験に続けて、スクリプトの自己テストを実行する（main への push と `workflow_dispatch` では 3 OS。Windows は Git Bash）: `make plug4-core-invariance-selftest`（PLUG-4 判定スクリプト。TASK-109.4）・`make cli-parity-selftest`（CLI 3 OS 比較。TASK-125.1・CLI-1）・`make vz-virtio-gpu-guest-check-selftest`（virtio-gpu ゲスト側確認スクリプト。合成 fixture のみ。TASK-172.6・GPU-6）・`make guest-kernel-build-selftest`（ゲストカーネルのビルドスクリプト。スタブのみで取得も実ビルドもしない。#1874・MAC-1。3 OS）・`make guest-initrd-build-selftest`（ゲスト initrd の梱包スクリプト。疑似 ELF とスタブ cargo のみで実ビルドしない。#1878・MAC-1。3 OS）・`make commit-msg-line-length-selftest`（commit-msg フックの本文行長検査。Issue #1295・REPAIR-12）・`make crash-summary-check-selftest`（crash_safety 件数サマリー検証。#1833・IO-3・REPAIR-12）・`make check-launch-target-selftest`（plugin 起動対象の構築箇所の判定。#1857・PLUG-11・REPAIR-12）・`make lib-selftest`（`scripts/lib.sh` の workspace 判定と `run_limited`〔期限つき実行。3 スクリプトの共通化。#2092・REPAIR-1・REPAIR-5〕の回帰テスト。PR #1756。macOS では `/bin/bash` 3.2 でも回す）。本判定 `make check-launch-target`（構築口 `PluginLaunchTarget::from_verified_file` を呼ぶのが core の変換と許可した試験コードだけか。#1857・PLUG-11）も `platform-ci` のステップとして実行する（`test-core-no-plugin` と同じ扱い）。あわせて `make cli-parity-native-reclaim-check`（タイムアウト回収のネイティブ exe 実測。#1548）と `make cli-parity-native-reclaim-selftest`（その全体期限の自己テスト。#1688・REPAIR-5・REPAIR-12）も実行する（後者の ubuntu 分は約 90 秒の待ちでクリティカルパスだったため `bench-regression` の並列グループへ移した。macOS・Windows は main の `platform-ci` で実行する）。いずれもステップごとに timeout-minutes 5 を付け、新しいジョブ・check-run 名は増やさない。

`cli-parity-native-reclaim-check` はスクリプト自身が wall clock の全体期限（既定 150 秒。`CLI_PARITY_RECLAIM_DEADLINE_SECS`）を持ち、超えたら子孫を回収して `deadline_exceeded` の行つきで失敗する（Windows でステップの timeout-minutes が効かずジョブ上限まで止まらなかったため。#1688）。ハング注入は `CLI_PARITY_RECLAIM_TEST_HANG`、止まり方の実証は `workflow_dispatch` の `reclaim-hang-probe` 入力（none / step-timeout / script-deadline。PR ブランチへ `--ref` で dispatch すると 3 OS で回り、concurrency group が PR の CI と衝突しない）で行う。PR の CI は ubuntu のみのため、Windows での確認は `workflow_dispatch` で行う。

間欠失敗する試験の修正確認は、`workflow_dispatch` の `repeat-package`・`repeat-test`・`repeat-count` 入力（`repeat-test` が空でなければ `platform-ci` のステップが `make repeat-test` で 1 つの lib 試験を N 回繰り返し、毎回ちょうど 1 件 passed を照合する。新ジョブなし・入力は env 経由。#2538・REPAIR-12）で 3 OS 分を採る。手元でも `make repeat-test PACKAGE=fandhe-container-<名> TEST=<完全名> COUNT=300` で同じ照合ができる。

ルート workspace 外の PoC パッケージ `poc/venus-decoder/jig`（venus 試験治具。`crates/plugin-macos` へ path 依存。TASK-172.4・GPU-6）は `cargo build` / `cargo test --workspace` の対象に入らないため、`platform-ci` ジョブ（PR は ubuntu・main は 3 OS）の既定 feature 側ステップの末尾で `make poc-venus-jig-check`（fmt-check・clippy・test。clippy / test は `--locked` で治具の `Cargo.lock` を固定。timeout-minutes 15）を実行し、plugin-macos 側の変更による治具の破損を検出する。PR では macOS 向けの破損を `cross-target-check` の `aarch64-apple-darwin` 型検査（治具の `cargo check` / `cargo clippy --locked`）で検出する。実機前提テストは `#[ignore]` で分離済みで CI では走らない。治具の `Cargo.lock` は rust-ci の `cargo deny`（ルート workspace のみ）の対象外のため、同ジョブの ubuntu で `make deny-poc-venus-jig`（ルートの `deny.toml` を共有し 4 種を `--locked` で検査。timeout-minutes 20）を実行する（ステージ 5）。ローカルの `make deny`（`make ci`）も治具の検査を含む。

rustdoc の警告（壊れた intra-doc リンク・private 項目へのリンク等。REPAIR-3）は `platform-ci` ジョブ（PR は ubuntu・main は 3 OS）の `make doc` ステップ（`RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps`。既定 feature。timeout-minutes 10）で fail させる（#1300）。新ジョブにせず既存ジョブのステップとしたのは check-run 件数を変えないため。main で 3 OS で実行するのは、`cfg(target_os)` 限定の項目へのリンクが OS ごとに解決結果を変えるため（PR では ubuntu のみのため、macOS / Windows でだけ壊れるリンクは `cross-target-check` の `aarch64-apple-darwin`・`x86_64-pc-windows-msvc` 向けの `cargo doc` で検出する）。doc コメントでは他 OS で存在しない項目・private 項目へリンクせず、コード表記（バッククォートのみ）にする。

macOS cold start 上乗せ確認（TASK-113.4・PLUG-6・MAC-2）は `benches/tests/macos_cold_start.rs` の結合試験（`cfg(target_os = "macos")`。他 OS は skip を明示）として `platform-ci` の macos（main への push と `workflow_dispatch`）で実行する。`bench-regression`（ubuntu 単独）のジョブ構成は変えず、基準値比較にも接続しない（模擬制御コアの計測で、実バックエンドは TASK-115）。

`bench-regression` ジョブは次の 21 個の `make`（下記 1〜18・14a・14b と `make cli-parity-native-reclaim-selftest`）を実行する（自己テストはスタブ・疑似 /proc・fixture のみで照合し、実機は使わない）。1〜14・14a・14b の自己テスト（と下記の `make cli-parity-native-reclaim-selftest`）は互いに独立なため、`scripts/run-parallel.sh 3` で最大 3 並列に実行する（所要時間の短縮。経過秒を照合する自己テストがあるため同時実行数は 3 に絞る。1 つでも失敗すればジョブは失敗する）。15 以降は ci.yml の並びどおりに直列で実行する。

1. `make fio-bench-selftest`（fio 4K ランダム write ベンチスクリプトの自己テスト。TASK-25.1・IO-8）
2. `make fio-baseline-ratio-selftest`（fio ベースライン比の算出の自己テスト。TASK-25.2・IO-8）
3. `make bench-check-selftest`（比較スクリプトと段階登録の絞り込み・照合の自己テスト。REPAIR-8・REPAIR-12）
4. `make bench-baseline-selftest`（baseline.json 生成スクリプト `scripts/bench/generate_baseline.sh` の自己テスト。TASK-88.1）
5. `make startup-latency-selftest`（起動レイテンシ計測スクリプトの自己テスト。TASK-46.1・CORE-10）
6. `make net-setup-timing-selftest`（ネットワーク作成/接続/削除の所要時間計測スクリプトの自己テスト。TASK-139.5・NET-4）
7. `make dns-helper-measure-selftest`（DNS ヘルパー計測スクリプトの自己テスト。TASK-141.3・NET-5）
8. `make idle-memory-selftest`（アイドル時常駐メモリ計測スクリプト `scripts/bench/idle_memory.sh` の自己テスト。疑似 /proc のみで照合し実計測はしない。TASK-45.1・CORE-7・SUP-1）
9. `make concurrent-memory-selftest`（50 コンテナ同時起動の集約メモリ計測スクリプトの自己テスト。TASK-50.1・TASK-50.2・CORE-9・SUP-1）
10. `make idle-memory-supervised-selftest`（監視プロセス付きのアイドル時常駐メモリ計測の自己テスト。TASK-47・CORE-7・SUP-1）
11. `make supervisor-independence-selftest`（監視プロセス独立性の実証スクリプトの自己テスト。TASK-162・SUP-5）
12. `make supervisor-pss-selftest`（監視プロセス常駐メモリ計測スクリプト `scripts/bench/supervisor_pss.sh` の自己テスト。疑似 /proc のみ。TASK-158・SUP-2）
13. `make restart-latency-selftest`（restart レイテンシ計測スクリプト `scripts/measure-restart-latency.sh` の自己テスト。スタブ（CLI・systemd-run・supervisor）のみ。TASK-160・SUP-3）
14. `make install-launcher-selftest`（特権ランチャーのインストールスクリプト `scripts/install-privileged-launcher.sh` の自己テスト。スタブ・一時ディレクトリのみで root 不要。TASK-171 追補・#1721・SUP-14）
14a. `make crictl-smoke-selftest`（crictl 疎通確認スクリプト `scripts/cri/crictl-smoke.sh` の自己テスト。スタブの crictl と一時ディレクトリの UNIX ソケットのみ。python3 が必要。実機は #442 で人間が行う。TASK-60・CRI-1）
14b. `make small-files-compare-selftest`（bind / named volume の 2 構成比較スクリプト `scripts/bench/small_files_compare.sh` の自己テスト。スタブのハーネスと fixture のみ。実測は #107、評価は #110。TASK-24.1・IO-7）
15. `make bench-check`（ベンチ実行・基準値比較。現状はプレースホルダの配線確認のみ）
16. `make bench-plugin-boundary`（plugin 境界ベンチの計測と CORE-10 比のログ出力のみ。基準値比較なし。TASK-113.3）
17. `make plugin-feature-size`（core の plugin feature 除外 release ビルドと rlib サイズの記録。PLUG-3・TASK-111.2。最終バイナリ未実装のため rlib 計測で、サイズ差に閾値は設けない）
18. `make plug4-core-invariance`（plugin の追加で core が変わらないことの判定。pull_request では base ブランチを fetch して比較する。自己テスト `make plug4-core-invariance-selftest` は `platform-ci` ジョブ側で実行する。core の成果物は rlib の sha256 を比べる〔理由は crate-naming.md 決定 3 の補足・#2136〕。TASK-109.4・PLUG-4）

`make bench-baseline` は登録ベンチと `benches/metrics.json`（direction・unit の SSOT）から baseline.json を再生成する道具である。ベンチ・基準値の現状は次のとおり（spec 側の判断は先取りしない）。

- 現時点で基準値比較の対象は `benches/benches/regression_placeholder.rs`（決定的な固定値の stub）と `benches/baseline.json`（`placeholder: true` の暫定値）だけで、動作確認の段階にある。計測対象がプレースホルダのため、現時点では実装の性能悪化を検出せず、性能回帰ゲートとして機能しない
- plugin 境界ベンチ（TASK-113〔#269〕・closed。`benches/benches/plugin_boundary*.rs`）は実装済みだが、baseline 未登録のため `bench-check` の比較対象外
- files/s のベンチは TASK-189（`benches/benches/small_files.rs`）で実装済みで、`metrics.json`・`BENCH_NAMES` へ登録済み（#1899。引数は `scripts/lib.sh` の `bench_args_for`、Windows では実行しない）だが、baseline 未登録のため `bench-check` の比較対象外（段階登録の絞り込み・照合は `scripts/bench/assemble_results.sh`、`BENCH_STAGED_NAMES` に名前を足すだけで使える）。起動 p95 のベンチは TASK-190（`benches/benches/startup_latency.rs`・#1900）で実装済みだが、実機前提（Linux・非 root・`systemd-run --user`）で CI では実行せず、`metrics.json` へ実機前提として登録済み（#1901）。`BENCH_NAMES`・共有 baseline.json には入れず（`lib.sh` の `BENCH_MANUAL_NAMES`）、基準値は `benches/baseline-manual.json`（未作成。実測は #230）。人が実機で採った結果を `make bench-check-manual BENCH_RESULTS=<絶対パス> [BENCH_HOST_KIND=<bare-metal|vm|wsl2>]`（結果の `host_kind` が語彙内なら省略可） で比べる（基準値は `make bench-baseline-manual` で作り、arch・ホストの種類が食い違うと 2。#2095。基準値が無い間は `skip:`。`make ci`・CI には含めない）。CI では回帰を検出できず、REPAIR-8 の「CI で 15% 超の悪化を fail」は未充足（CI の扱いは `docs/design/bench-calibration.md`「CI の扱いの決定（TASK-190）」で暫定決定・オーナー確認待ち）
- 校正記録は TASK-88.2（#229）で `docs/design/bench-calibration.md` に整備済み。実測は前提ベンチが無いため保留している
- 実測基準値の確定は TASK-88.h1（#230）・TASK-113.h1（#274）（どちらも open）

plugin 境界ベンチの Δp50（`plugin_boundary_*_delta_p50`。TASK-113.3）は `make bench-plugin-boundary` ステップで計測と CORE-10 比のログ出力のみ行い（基準値比較なし）、15% 回帰判定は `make bench-check-selftest` の fixture で検証している。常時比較は実測基準値の登録と `bench-check` への組み込み（TASK-88.h1・TASK-113.h1）後に有効になる。

## 3 OS CI（macOS・Windows・Linux 一級対応）

- 3 OS のネイティブ実行の時機（2026-10-10 の 2 段階目の再構成。オーナー承認）:
  - **pull_request**: Linux（ubuntu-latest）のネイティブでビルド・テスト・結合試験を行い、macOS・Windows はネイティブランナーを使わず `cross-target-check` の型検査（`aarch64-apple-darwin`・`x86_64-pc-windows-msvc` への `cargo check` / `cargo clippy`〔`--all-features` と既定 feature〕・`cargo doc`。いずれも `-D warnings`）で代える
  - **main への push**: `platform-ci` を ubuntu / macos / windows の 3 OS のネイティブランナーで全ステップ実行する（macOS・Windows の `--all-features` の clippy / test を含む）
  - **release 前**: 3 OS のネイティブで全部回す。`release.yml` は発火条件を無効化中のため、`workflow_dispatch` で `ci.yml` を実行する（`gh workflow run ci.yml --ref <ref>`。`workflow_dispatch` では 3 OS で回る）
  - 理由: macOS ランナーの同時実行枠（1 枠程度）待ちで全 PR の CI が詰まるため。PR で見落とすのは macOS・Windows 固有の実行時の誤り（テストの失敗・BSD / Git Bash のツール差）で、コンパイル・lint・rustdoc の誤りは PR で検出し、実行時の誤りは main への push 後の 3 OS 実行で検出する
  - main の concurrency: group は `${{ github.workflow }}-${{ github.event.pull_request.number || github.ref }}`・`cancel-in-progress: true` のため、main への新しい push は実行中の古い main の CI（3 OS）を取り消す。取り消された commit の macOS・Windows の結果は残らず、後続 commit の 3 OS 実行で検出する（`workflow_dispatch` を main へ向けた場合も同じ group）
  - ruleset の必須チェックには PR で生成される check-run（`platform-ci (ubuntu-latest)`・`cross-target-check` を含む 14 件）だけを登録する。main だけで生成される `platform-ci (macos-latest)`・`platform-ci (windows-latest)` を登録すると PR が待ちのままになる
- ネイティブ実行はクロスコンパイル前提にしない（3 OS のテスト実行は各 OS のネイティブランナーで行い、`cross-target-check` は型検査に限る）
- main への push と `workflow_dispatch` の matrix は ubuntu / macos / windows の 3 OS を必須とし、特定 OS のみの skip で CI を通さない。PR で macOS・Windows のネイティブ実行を省くのは上記のイベント単位の方針であり、個別のテスト・ステップを特定 OS だけ飛ばしてよいという意味ではない
- ジョブ構成（2026-10-10 の 1 段階目の再構成〔#1724〕。オーナー承認）: 3 OS のビルド・テストは `platform-ci`（matrix）の 1 ジョブに集約する。旧 `rust-ci-default-features`（既定 feature の `make lint` / `make test` / `make doc` 等）と旧 `integration-test`（結合試験・スクリプトの自己テスト・Linux 限定の実機前提テスト）のステップをそのまま移し、macOS・Windows では reusable の `rust-ci` が担っていた `cargo clippy --workspace --all-targets --all-features -- -D warnings` と `cargo test --workspace --all-features` もステップとして実行する。`rust-ci`（fmt・clippy / test の `--all-features`・deny）は ubuntu-latest のみ（1 要素の matrix で check-run 名 `rust-ci (ubuntu-latest) / ...` を保つ）。fmt・deny は結果が OS に依らない
- 集約の理由: macOS ランナーの同時実行枠が 1 枠程度しかなく、1 回の CI で macOS ジョブが 7 本（reusable の fmt・clippy・test・deny・complete の 5 本＋旧 2 ジョブ）並び、待ち行列で全 PR の CI が詰まったため。各ジョブ自体は 2〜5 分で、問題はジョブ本数だった。集約後の macOS ジョブは main の CI 1 回で 1 本（PR では 0 本）。ジョブを増やす・3 OS に分ける変更は macOS ジョブの本数を増やすため、既存の `platform-ci` のステップとして追加する
- ベンチ回帰チェック（`bench-regression` ジョブ）は例外として ubuntu-latest 単独で実行する。ベンチの数値は OS 間の実行環境差で比較できず、3 OS matrix にしても意味のある回帰検出にならないため（本節の 3 OS ネイティブ実行はビルド・テストのゲートを対象とする規則であり、ベンチ回帰チェックはその対象外）
- deny.toml のライセンス fail-closed 自己テスト（`platform-ci` の `make deny-license-fail-closed-selftest` ステップ。TASK-90.2・#127・OSS-4・OSS-5・REPAIR-9）も ubuntu-latest のみで実行する。使い捨て workspace と本物の `deny.toml` で GPL / LGPL / AGPL / MPL の拒否を照合する依存方針の検査で、結果が OS に依らないため。`make ci` には含めない
- venus 試験治具の依存監査（`platform-ci` の `make deny-poc-venus-jig` ステップ）も例外として ubuntu-latest のみで実行する。`deny.toml` に `targets` の指定が無く cargo-deny は実行ホストに関係なく全ターゲットの依存グラフ（macOS 専用の objc2 系を含む）を検査するため結果が OS に依らず、ビルド・テストのゲートではなく依存監査であるため 3 OS ネイティブ実行の対象外とする（cargo-deny の導入ビルドを 3 重に払わない）
- サードパーティのライセンス表記の生成（`platform-ci` の `make third-party-licenses-selftest`・`make install-cargo-about` ＋ `make third-party-licenses` ステップ。TASK-103.1・TASK-103.2・OSS-5）も ubuntu-latest のみで実行する。`about.toml` が 5 ターゲットを固定するため生成結果が OS に依らず、cargo-about の導入ビルド（C コンパイラが要る）を 3 回払わないため。cargo-about は Makefile の `CARGO_ABOUT_VERSION`（Dockerfile と同期）へ `--locked --features cli` で固定導入し、版の完全一致を検査する。reusable の `rust-ci` に cargo-about を足す入力が無く、ジョブを増やすと check-run が増えるため `platform-ci` のステップとした。導入版のユーザー承認は未取得（PR で承認待ち）
- クロス型検査（`cross-target-check` ジョブ。旧 `aarch64-linux-check` を拡張。#1120・REPAIR-7）は ubuntu-latest（x86_64）単独で、`aarch64-unknown-linux-gnu`・`aarch64-apple-darwin`・`x86_64-pc-windows-msvc` の 3 ターゲットについて `cargo check --workspace --all-targets --all-features --target <target>` と `cargo clippy --workspace --all-targets --all-features --target <target> -- -D warnings` を順に実行し、`cfg(target_arch = "aarch64")`・`cfg(target_os = "macos")`・`cfg(target_os = "windows")` 分岐をコンパイル検査する。`aarch64-apple-darwin`・`x86_64-pc-windows-msvc` の 2 ターゲットには、既定 feature の `cargo clippy --workspace --all-targets --target <target> -- -D warnings` と `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --target <target>` も実行し、PR で macOS・Windows の既定 feature の lint と `cfg(target_os)` 限定項目への rustdoc リンク（#1300）を検出する。venus 試験治具（`poc/venus-decoder/jig`）も `aarch64-apple-darwin` で `cargo check` / `cargo clippy --locked` する。macOS ゲスト用 init（`crates/guest-init`。#1875・MAC-1）は静的リンクの配布ターゲット `aarch64-unknown-linux-musl` で `cargo check -p fandhe-container-guest-init --all-targets` と `cargo clippy ... -- -D warnings` を型検査する（リンクはしない。実ビルドとサイズ確認は #1878）。`--all-features` は `crash-test-server` 等の feature を要する target も型検査の対象に含めるため。aarch64 Linux の既定 feature の構成・`cfg(not(feature = "exec-test-support"))` 分岐・plugin 無効構成は本ジョブでは未検査（macOS・Windows の plugin 無効構成は main の `platform-ci` が検査する。x86_64 Linux でも lib 側の `cfg_attr` は `cargo build --workspace`、plugin 無効構成は `make test-core-no-plugin` が検査するのみで、テスト側の `cfg(not(feature))` 分岐は feature 統一によりどの CI ジョブでも型検査されない）。リンクもテスト実行もしない型検査ゲートであり、ビルド・テストのゲートではないため「ネイティブ実行」の規則の対象外とする。aarch64 Linux での実行時の正しさの検証はネイティブ arm64 ランナーでのテスト実行がフォローアップ課題であり、現状は保証しない（macOS・Windows の実行時の正しさは main の `platform-ci` が検証する）。現在 `Cargo.toml` に入っている外部依存は純 Rust のみで、`cargo tree -e normal,build --target all` に `cc`・`cmake`・`bindgen` は現れない（`Cargo.lock` には rustls-webpki の optional 依存として `ring`・`cc` の項目が残るが、有効な feature に無くビルドされない。rustls-graviola は inline asm を使う純 Rust）。ターゲットにより libc・objc2 系・windows-sys も入る。proc-macro はホスト側でビルドされる。ワークスペース内の `build.rs` は crates/cri のもの（`tonic-prost-build`・`protox` による `.proto` のコード生成。protoc 不要）で、依存側の `build.rs` は cfg の判定のみのため、クロスリンカ・SDK 不要という前提に立つ。依存ごとの導入状況は本文に列挙せず `docs/design/from-scratch-policy.md` の許容依存リストと「2026-10-10 承認分」の段落を正とする（二重管理による陳腐化を避けるため）。2026-10-10 承認分のうち直接依存として未導入なのは、`hyper`（#678・crates/cri。実装は #679）、crates/cri からの `flate2`・`hyper-util` の参照（#678）、crates/compose-convert からの `serde-saphyr` の参照（#540）で、`tokio-stream`・`tower-service`・`http`（#425）は `tonic::codegen` の再 export を使い直接依存にしない方針である。いずれも判断資料の依存ツリー（`-e normal,build`）では `cc`・`cmake`・`bindgen`・`links` を持たない純 Rust の範囲にあり、導入済みの `tonic-prost-build`・`protox`・`tonic`・`tonic-prost`・`prost` は 3 ターゲットの `cargo tree -e normal,build -p fandhe-container-cri --target <ターゲット>` で同様に確認済み。3 ターゲットでの実ビルド（リンク）は未実施。これらを追加する PR では `cargo tree -e normal,build --target <ターゲット>`（3 ターゲットそれぞれ）でこの前提を確かめ、`cc` 等ネイティブビルドを伴う依存を追加する場合は見直す

## 実機前提テスト

- root 権限・KVM・GPU・特定カーネル版数（Landlock ABI 等）・WSL2 を要するテストは、GitHub ホステッド runner で実行できないため既定のテスト集合から明示的に分離する（分離の仕組みは該当タスクで決め、`AGENTS.md` に実行コマンドと必要環境を記す）
- 分離したテストには理由（必要な権限・環境）とビヘイビア ID を記し、実機での実行結果を PR に記録する
- 既定のテスト集合で動くはずのテストを、CI 通過のために実機前提テストへ移さない
- 実機での実測・判定が「人間」担当のタスクは、Agent は計測スクリプトの準備までに留める

## ワークフロー変更時の注意

- GitHub Actions のサードパーティ action はコミット SHA で固定する（`Fandhe-AI/actions` のみ `@latest` を許可）
- `permissions` は最小権限で明示する
- secrets を `pull_request` イベントのログへ出力しない
- CI 設定の変更は infra-builder が担当し、reviewer / security-auditor のレビューを経る
