# CLAUDE.md

## Overview

Rust でフルスクラッチ開発する軽量なコンテナ実行基盤の実装リポジトリ。Docker の課題（リソース消費の大きさ・ボリューム I/O のボトルネック・macOS / Windows での VM 越境オーバーヘッド）の是正を目指す。

- **本リポは public**。仕様・ビヘイビア定義の SSOT は private リポ [fandhe-container-spec](https://github.com/Fandhe-AI/fandhe-container-spec)（`docs/spec` submodule の `04-behavior/`）。spec の内容は本リポに載せてよいが、ビヘイビア ID を併記して SSOT へ辿れるようにする（[spec-reference](.claude/rules/spec-reference.md)）
- 実装方針の要点は README「実装方針（要点）」を参照（フルスクラッチ・OCI / CRI 互換・I/O レイヤー再設計・3 OS 一級対応・plugin 分割・GPU / network / 複数コンテナ定義 / 監視・AI 自己補修）
- 依存は最小・`=x.y.z` 完全固定・ユーザー承認制。youki / Firecracker / Cloud Hypervisor / rust-vmm のコード・クレートは使わない（[dependency-policy](.claude/rules/dependency-policy.md)）。ライセンスは中核 Apache-2.0 単独、補助 crate `fandhe-container-plugin` のみ `MIT OR Apache-2.0`（[licensing](.claude/rules/licensing.md)）
- **実装の着手はユーザーの明示指示を経てから**行う。タスク定義は spec の `05-tasks.md`（TASK-n・グループ G0〜G12）、マイルストーンは `06-roadmap.md`（MS-1〜14）
- 進捗・ステータスは本ファイルに逐次記録しない（Issue で管理する）

## Repository Structure

「（予定）」は spec のタスク定義に基づく計画上の配置で、まだ存在しない。crate の短縮名は [crate-naming.md](docs/design/crate-naming.md)（TASK-1・REPAIR-1）で確定済み。

```text
fandhe-container/
├── CLAUDE.md                      # Claude 運用方針（本ファイル）
├── AGENTS.md                      # AI PR レビュー観点集 / ビルド・回帰確認コマンド（REPAIR-10）
├── README.md                      # 概要・実装方針（要点）・クイックスタート・開発環境構築
├── CONTRIBUTING.md                # コントリビュータ向け最小骨子（TASK-2・OSS-1/OSS-2・MS-0。PR フロー詳細は TASK-99・OSS-6・MS-6 で後日整備）
├── MAINTAINERS.md                 # メンテナンス体制・コアチーム（TASK-100・OSS-6）
├── LICENSE-APACHE                 # Apache License 2.0（中核 crate は Apache-2.0 単独）
├── LICENSE-MIT                    # MIT License（補助 crate fandhe-container-plugin は MIT OR Apache-2.0）
├── NOTICE                         # 第三者の帰属告知（Apache-2.0 4(d)。moby の readonlyPaths / maskedPaths 既定一覧の出典。#1894・OSS-3・OSS-5）
├── rust-toolchain.toml            # stable + rustfmt/clippy（単一真実源）
├── .editorconfig / .gitattributes # インデント・改行（LF 固定）・文字コード規約
├── skills-lock.json               # 導入スキルのロックファイル
├── Makefile                       # 開発タスク集約の薄い入口（実体は scripts/。lint-docs・fmt・clippy・test・doc・deny・docker-*。`make help`。編集規約は .claude/rules/makefile.md）
├── lefthook.yml                   # git hooks（staged の整形・秘密情報検査・commit-msg。CI と重複する検査は置かない）
├── commitlint.config.mjs          # commitlint 設定（type を 9 種に限定）
├── Dockerfile / compose.yaml      # 開発コンテナ（環境非依存の `make docker-ci`）
├── .markdownlint.jsonc / .yamllint / .editorconfig-checker.json  # lint-docs 設定
├── deny.toml                      # cargo-deny 設定（ライセンス・advisories・sources 検査）
├── about.toml / about.hbs         # cargo-about 設定・テンプレート（サードパーティのライセンス表記の生成。TASK-103.1・OSS-5。導入と CI 接続は TASK-103.2）
├── Cargo.toml                     # workspace 定義（members は TASK-1.3 で有効化）
├── crates/                        # crate 名前空間は fandhe-container-*（Cargo.toml・src/lib.rs は TASK-1.3 雛形。本体は各 TASK）
│   ├── io/                        #   I/O 共有層（バッチ write-back・フラッシュバリア・FS 正規化）
│   ├── core/                      #   実行層（namespace・cgroups v2・seccomp/Landlock・rootless）
│   ├── supervisor/                #   コンテナごとの軽量監視プロセス（bin: fandhe-container-supervisor・特権ランチャー fandhe-container-launcher〔TASK-171 追補・#1719〕）
│   ├── guest-init/                #   macOS ゲスト VM の initrd に入れる Rust 製 PID 1（bin: fandhe-container-guest-init。静的リンクの aarch64-unknown-linux-musl。TASK-64 追補・#1875・MAC-1）
│   ├── oci/ / cri/                #   OCI イメージ・ライフサイクル / CRI
│   │   └── cri/proto/             #     cri-api の .proto（kubernetes/cri-api v0.37.1 無改変）と出典 README（TASK-56.2・CRI-3）
│   ├── platform-macos/ / platform-windows/ / microvm/  # プラットフォーム層
│   ├── gpu/ / net/                #   GPU パススルー（CDI）/ network
│   ├── plugin/                    #   plugin 境界機構（UDS＋長さ接頭辞フレーム。fandhe-container-plugin）
│   ├── cli/ / stack/              #   統一 CLI / 複数コンテナ定義（TOML スキーマ・起動順）
│   ├── compose-convert/           #   compose.yaml → TOML 片方向変換ツール（fandhe-container-compose-convert）
│   └── plugin-*/                  #   fandhe-container-plugin-cri / -macos / -windows / -microvm / -mcp
├── scripts/                       # Makefile ターゲットの実体（targets/<target>.sh）・共通ヘルパー（lib.sh・versions.sh・with-tools.sh・with-workspace.sh・run-parallel.sh・help.sh）・ベンチ回帰比較スクリプト（TASK-86.3・REPAIR-8）・実機前提ベンチの結果比較と基準値生成（scripts/targets/bench-check-manual.sh・bench-baseline-manual.sh。起動 p95・#1901・#2095）・baseline.json 生成スクリプト・段階登録ベンチの結果の絞り込み照合スクリプト assemble_results.sh（scripts/bench/。TASK-88.1・TASK-189 追補・#1899）・アイドル時常駐メモリ計測（scripts/bench/idle_memory.sh。TASK-45.1・CORE-7）・50 コンテナ同時起動の集約メモリ計測（scripts/bench/concurrent_50_memory.sh。own 側 TASK-50.1・Docker 側と統合レポート TASK-50.2・CORE-9・SUP-1）・監視プロセス常駐メモリ（PSS）計測（scripts/bench/supervisor_pss.sh。TASK-158・SUP-2）・ネットワーク作成/接続/削除の所要時間計測（scripts/bench/net_setup_timing.sh。TASK-139.5・NET-1／NET-4）・DNS ヘルパーの正答率・レイテンシ・常駐 PSS 計測（scripts/bench/dns_helper_measure.sh。TASK-141.3・NET-5）・監視プロセス独立性の実証スクリプト（scripts/verify-supervisor-independence.sh。TASK-162・SUP-5。実機実証は #499）・restart レイテンシ実機実測スクリプト（scripts/measure-restart-latency.sh。TASK-160・SUP-3。実測は #491）・特権ランチャー・supervisor・CLI のインストールスクリプト（scripts/install-privileged-launcher.sh と自己テスト。TASK-171 追補・#1721・#2068・SUP-14。実機〔root〕での実行と検証は #538・#539）・fio 4K ランダム write ベンチスクリプト（TASK-25.1・IO-8）・fio ベースライン比の算出（TASK-25.2・IO-8。scripts/testdata/ に fixture）・PLUG-4 の core 不変性判定スクリプト（scripts/check-plug4-core-invariance.sh と自己テスト。TASK-109.4・PLUG-4）・CLI 基本 6 コマンドの 3 OS 比較スクリプト（scripts/cli-parity-check.sh。TASK-125.1・CLI-1。実機確認は #661）・commit-msg フックの本文行長検査（scripts/check-commit-msg-line-length.sh。Issue #1295）・crash_safety 件数サマリーの検証（scripts/check-crash-summary.sh と自己テスト。#1833・IO-3）。plugin 起動対象の構築箇所の機械判定（scripts/check-plugin-launch-target-construction.sh と自己テスト。`make check-launch-target`。#1857・PLUG-11）。macOS ゲスト initrd の梱包スクリプト（scripts/build-guest-initrd.sh と自己テスト。init を静的リンクで作り `/init` だけの newc を作る。`make guest-initrd-build`。#1878・MAC-1）。deny.toml のライセンス fail-closed 自己テスト（scripts/deny-license-fail-closed-selftest.sh。TASK-90.2・OSS-4・OSS-5）。サードパーティのライセンス表記生成（scripts/generate-third-party-licenses.sh と自己テスト。TASK-103.1・OSS-5）。bind / named volume の 2 構成で small_files ハーネスを回す比較スクリプト（scripts/bench/small_files_compare.sh と自己テスト・`make small-files-compare`。TASK-24.1・IO-7。実測は #107、評価は #110）・試験用 feature 無効の -p 単独 lib/bin の clippy（scripts/check-standalone-clippy.sh と自己テスト・`make check-standalone-clippy`。#2640・REPAIR-12）・CRI 疎通確認の自動検証スクリプト（scripts/cri/crictl-smoke.sh と自己テスト・`make crictl-smoke`。TASK-60・CRI-1。実機は #442）。依存禁止判定等は（予定）
├── benches/                       # crate をまたぐベンチ回帰（REPAIR-8。root の workspace メンバー crate fandhe-container-benches、publish = false。benches/benches/regression_placeholder.rs は TASK-86.3 のプレースホルダベンチ、baseline.json は暫定基準値。benches/benches/plugin_boundary.rs は TASK-113.1 の代表操作 A ベンチでゲート未接続、benches/benches/plugin_boundary_list_images.rs は TASK-113.2 の代表操作 B〔イメージ一覧〕計測ハーネス（ゲート未接続）、benches/benches/plugin_boundary_macos_cold_start.rs と benches/tests/macos_cold_start.rs は TASK-113.4 の macOS cold start 上乗せ確認（macOS のみ・ゲート未接続）、plugin 境界ベンチ〔TASK-113〕は実装済みで baseline 未登録のため bench-check の比較対象外、benches/benches/small_files.rs は TASK-189 の小ファイル多数 files/s 計測ハーネスで metrics.json・BENCH_NAMES 登録済み・baseline 未登録のため bench-check の比較対象外〔登録は #1899。docs/design/small-files-bench.md〕、benches/benches/startup_latency.rs は TASK-190 の起動 p95 ベンチ〔実機前提・CI では実行しない。metrics.json へは #1901 で登録済み、基準値は benches/baseline-manual.json〔未作成。実測は #230〕、比較は `make bench-check-manual`。docs/design/startup-latency-bench.md〕、基準値の校正記録は TASK-88.2、基準値の確定は TASK-88.h1・TASK-113.h1）
├── guest/kernel/                  # macOS ゲストカーネル（arm64）の Kconfig フラグメント・ビルドスクリプト・README（TASK-64 追補・#1874・MAC-1。ルート workspace の外。バイナリは置かない。`make guest-kernel-build`〔人間用〕・`make guest-kernel-build-selftest`）
├── poc/                           # 製品外の PoC パッケージ（ルート workspace の外。crate 境界の確定一覧に含めない）
│   ├── venus-decoder/jig/         #   venus 試験治具の capset アダプタ（独立 Cargo パッケージ。TASK-172.4・GPU-6。`make poc-venus-jig-check`。CI は platform-ci が実行〔PR は ubuntu・main は 3 OS〕。macOS 向け型検査は cross-target-check）
│   └── vz-custom-virtio-gpu/      #   VZCustomVirtioDevice による最小 virtio-gpu 登録の可否確認（TASK-172.6・GPU-6。ゲスト側確認スクリプトのみ、ホスト側は承認待ち。自己テストは CI の platform-ci が実行〔PR は ubuntu・main は 3 OS〕）
├── docs/
│   ├── architecture.md            # crate 境界・依存関係グラフ・確定済み設計判断の索引（TASK-6・REPAIR-3・PLUG-1）
│   ├── api/                       # 利用者向け API 契約
│   │   ├── io-barrier.md          # I/O 共有層の ACK と永続化保証の契約（TASK-17・IO-2）
│   │   └── bind-mounts.md         # `config.json` の `mounts[]` の bind mount の書き方・受けるオプション・Docker / runc との差（TASK-29 追補・#1915・OCI-4）
│   ├── design/                    # 設計決定・拡張点・リソース効率目標
│   │   ├── orchestration-scope.md # オーケストレーション スコープ（TASK-5・CRI-8）
│   │   ├── from-scratch-policy.md # フルスクラッチ方針・依存基準（TASK-7・MS-0）
│   │   ├── resource-efficiency-target.md  # リソース効率目標値（TASK-48・CORE-8）
│   │   ├── declarative-config.md  # 宣言的起動設定の方針メモ（TASK-82・CLI-4）
│   │   ├── small-model-repair-policy.md  # 小型モデル自己補修方針（TASK-92・REPAIR-11/13/14）
│   │   ├── cgroups.md             # cgroups v2 単独対応・v1 / systemd cgroup driver 非対応（TASK-34・CORE-4）
│   │   ├── ffi-libc-check.md      # 自前 FFI 宣言と libc の機械照合の方式（dev-dependencies のみ・const 評価。適用状況・CI での評価箇所。#1838・#1837・MVM-4・REPAIR-7・REPAIR-12）
│   │   ├── io-protocol.md         # I/O 共有層のワイヤーフレーム・チェックサム（TASK-11・IO-1・REPAIR-2）
│   │   ├── license-deny-fail-closed-report.md  # 非許可ライセンス検出の fail-closed 確認記録（TASK-90.2・OSS-4・OSS-5・REPAIR-9）
│   │   ├── break-detection-ci-report.md  # BREAK-1/BREAK-2 の CI 検出実証レポート（TASK-89.2・REPAIR-7）
│   │   ├── io-fio-bench.md        # fio 4K ランダム write ベンチスクリプトの契約（TASK-25.1・IO-8）・Docker ベースライン計測手順・目標値案（TASK-25.2）
│   │   ├── small-files-bench.md   # 小ファイル多数の files/s 計測ハーネスの計測定義（TASK-189・IO-6・IO-7・REPAIR-8。metrics.json・BENCH_NAMES 登録済み・baseline 未登録）
│   │   ├── startup-latency-bench.md  # 起動レイテンシ p95 ベンチの計測定義（TASK-190・REPAIR-8・CORE-10。実機前提・ゲート未登録）
│   │   ├── bench-calibration.md   # ベンチ基準値の校正記録・試行ログ（TASK-88.2・REPAIR-8。実測は前提ベンチ未実装のため保留）
│   │   ├── measurements/
│   │   │   ├── idle-memory-local.md  # アイドル時常駐メモリのローカル実測レポート（TASK-45.2・CORE-7。root 権限での確定計測は TASK-47）
│   │   │   ├── state-lock-contention.md  # 状態ストア `@lock` の取り直しによる飢えの計測と対策（#2229・SUP-1・REPAIR-5）
│   │   │   └── oci-pull-e2e-local.md  # pull_e2e の公開イメージ 5 種での実行記録（TASK-55.2・OCI-1・#421。run 段の終了コード 0 は人間へ引き継ぎ・#2313）
│   │   ├── macos-vm-strategy.md   # macOS の VM 利用方式（既定: 常駐 VM 共用＋軽量プロセス分離／オプション: 1 コンテナ = 1 VM。TASK-66・MAC-4）
│   │   ├── macos-shared-vm.md     # macOS 既定方式（常駐 VM 共用）の未決事項の設計案（保持役・bind mount・ゲスト内実行・計測対象。TASK-191・#1905・MAC-4。承認待ち #1906）
│   │   ├── fs-normalization.md   # FS 正規化（NFC/NFD の別表記の衝突を検出して拒否・名前は書き換えない。TASK-21・IO-5）
│   │   ├── oci-layer-special-bits.md  # レイヤー展開の setuid / setgid / sticky を所有者の写像に合わせて保持する条件（既定は落とす。#1810・OCI-1・SEC-5）と、tar の uid/gid を subuid 範囲へ写像して chown する経路・rootful で特殊ビットを残す条件（#2225）
│   │   ├── pull-inventory-wiring.md  # pull の結果を ImageStore の在庫へ登録する配線の判断記録（入口は cri の OciImagePuller::pull・手順と順序・孤児リースの分析と fsync・subuid のずれの検出方針・スコープ外。#2539・OCI-1・OCI-7・CRI-3）
│   │   ├── crate-naming.md        # crate 短縮名・plugin crate 配置の確定内容（TASK-1・REPAIR-1）
│   │   ├── rootless-network.md    # rootless ネットワーク外部ヘルパーの判断記録（TASK-147・NET-9。pasta を採用〔#340〕。実装・実証は #341）
│   │   ├── privilege-separation.md  # 権限分離方式の比較と必要最小権限の設計書（TASK-171.1.1・SUP-14。方式承認済み〔#1454〕）
│   │   ├── user-manager-connect-precheck.md  # start の事前検査への実 connect と connect 先の SO_PEERCRED 照合を足すかの判断記録（#2448・CORE-3・SUP-14。オーナー承認待ち）
│   │   ├── rootful-host-root.md   # RootfulHostRoot（ホスト root のまま分離する権限モデル）を許すかの判断記録（#2241・SEC-5・CORE-6。オーナー承認待ち）
│   │   ├── launch-sealed-copy.md  # launch に封印複製（B'）を適用しない判断の記録（ローカル実測つき。#2687・CORE-5・CORE-7〜9・REPAIR-3）
│   │   ├── runtime-self-sealed-copy.md  # ランタイム自身の封印複製（memfd + seal。方式 B）を組み込むかの判断記録（#2686・CORE-5・REPAIR-3。オーナー承認待ち）
│   │   ├── healthcheck-argv-timeout.md  # healthcheck の argv[0] の解決方式と timeout の上限の判断記録（#2439・SUP-4・TASK-161 追補。オーナー承認待ち）
│   │   ├── subid-owner-resolution.md  # rootless の subuid / subgid の所有者名を passwd 優先・無ければ `getent`（NSS）で解決する方針の判断記録（#2390・SEC-5・CORE-6。shadow 4.13 の `newuidmap` の照合に合わせる）
│   │   ├── dev-default-mounts.md  # OCI 既定の /dev の残り（/dev/pts・/dev/ptmx・/dev/shm・/dev/console）と rootless の /dev 供給方式の設計ドラフト（TASK-29 追補・#1609。方式を確定し実装 issue を #54 配下に起票）
│   │   ├── volume-provider-implementation.md  # VolumeProvider の core 側実装（named volume の実体化）の担当 TASK と時期の判断記録（#2451・CRI-7・PLUG-1・IO-7。オーナー承認待ち）
│   │   ├── image-store-root-trust.md  # イメージストア root の検査の基準（権限ビット・所有者）と ACL・再検査・libc 照合の採否の判断記録（#2547・OCI-7・SEC-1。基準はオーナー承認待ち）
│   │   ├── macos-state-root.md    # macOS の既定の状態ルート（`StateRoot::resolve(None)`）の判断記録（#2431・OCI-5・SEC-4。オーナー承認待ち）
│   │   ├── windows-execution-layout.md  # Windows の実行構成（WSL2 ゲスト内の core とホストの起動役）の設計ドラフト（#1415・#1539 の決定以外はオーナー承認待ち。TASK-116 追補・#1862・WIN-1）
│   │   ├── audit-non-linux.md     # 非 Linux の監査の記録経路（Windows の主経路の隔離・代替経路）の設計ドラフト・判断シート（#2430・SEC-4・オーナー承認待ち）
│   │   ├── audit-delivery.md      # seccomp・Landlock の拒否を監査の記録先へ届ける配送経路の設計（2026-10-15 に方式を採用・#2018。実装は #2023〜#2028・#2004。TASK-41 追補・#1835・SEC-4）
│   │   ├── audit-seccomp-reader.md  # AUDIT_SECCOMP の読み手と CAP_AUDIT_READ の付与の判断記録（v6.12 の原文での確認結果を含む。#2237・SEC-4・SUP-14。オーナー承認待ち）
│   │   ├── plugin-backend-wiring.md  # バックエンド plugin の検証後の起動と RPC の配線の設計案（#1869・TASK-115・TASK-79 追補・PLUG-1・PLUG-7。承認待ち）
│   │   ├── rootless-id-map-holder.md  # 範囲写像の書き込み先を専用の holder プロセスへ分け、中間プロセスが dumpable になる窓をなくす設計（#2374・CORE-6・SEC-5・SEC-1）
│   │   ├── cri-cgroup-parent.md   # CRI の cgroup_parent の受け入れ方針の判断記録（#2672・CRI-2・CORE-4。オーナー承認待ち。判断が出るまで `UNIMPLEMENTED`）
│   │   ├── cri-devices-cdi.md     # CRI の devices・CDI の受け入れ方針の判断記録（#2673・CRI-2・GPU-1・SEC-1。オーナー判断待ち。判断が出るまで `UNIMPLEMENTED`）
│   │   ├── config-id-mappings.md  # config の linux.uidMappings / gidMappings を受けるかの判断記録（#2240・SEC-5・CORE-6。オーナー承認待ち）
│   │   ├── windows-state-store-acl.md  # Windows の FileStateStore の所有者 SID 照合・保護 DACL の実装方式（windows-sys / 自前宣言 / 恒久拒否）の判断記録（#2428・OCI-5・SEC-4。オーナー承認待ち）
│   │   ├── oci-mounts-implicit-entries.md  # mounts[] の bind・sysfs 以外（暗黙に供給済みの /proc・/dev 系・tmpfs 等）を受けるかの判断記録（#2347・TASK-29 追補・OCI-4・SEC-1。オーナー承認待ち）
│   │   ├── network-reclaim-persistence.md  # 作成失敗の回収待ちの記録（請求書）と attach の取り残しの記録を plugin の再起動をまたいで残す設計（置き場所・形式・排他・書く/消す時点・起動時の読み込み・再起動後に回収できる範囲・write-ahead を採らない判断。IPAM 等は #1870 の後続。#2604・#2681・NET-1・NET-6・REPAIR-3・REPAIR-4・REPAIR-5）
│   │   ├── container-ref-reconcile.md  # コンテナ参照の照合とクラッシュ復旧 GC の起動点（create ゲートの共有 / 排他・契機 A / B・probe の写し方。`Present` かつ未確定の扱いはオーナー確認待ち。#2495・OCI-7・CLI-1・CORE-1）
│   │   ├── container-options-delivery.md  # 起動オプション（ulimit・env・label ほか）の CLI から supervisor への受け渡し（状態ルート配下の 0600 の文書 `FCOPT1`・経路・却下案・残余。#2713・SUP-12・CLI-1・SEC-1）
│   │   ├── container-log-removal-wait.md  # コンテナログ削除で sink の閉鎖を期限つきで待つ方式と、失敗のコード別内訳の観測（#2634・SUP-7・CRI-2・REPAIR-4・REPAIR-5）
│   │   ├── image-rootfs-lifetime.md  # イメージ由来 rootfs（core が create_with_image で作ったもの）の所有・delete での削除・失敗時の扱い（#2378・OCI-7・OCI-5）
│   │   ├── exec-without-supervisor.md  # supervisor 不在時（孤児化・再起動後）の exec の方式（起動時の同一性の証跡と re-adopt での pidfd の取り直し）の判断記録（#2688・SUP-4・SUP-6・SUP-8・SEC-1。オーナー承認待ち）
│   │   ├── mount-propagation.md   # mount の propagation（rslave を受け rshared を受けない理由・事前複製の方式・却下案・rshared の緩和点・残余。#2669・CRI-2・OCI-4・SEC-1）
│   │   ├── cri-config-acceptance.md  # CRI の未受理項目の受け入れ順序と担当、イメージ User の名前解決の方式（fd 起点の passwd / group 読み取り。#2606・CRI-2・CRI-7・SEC-1・SEC-5）
│   │   └── plugin-hash-allowlist.md  # plugin の許可済みハッシュ一覧の置き場所・読み込み経路・一覧ファイル自体の検証の設計案（TASK-122 追補・#1868・PLUG-11。オーナー承認待ち）
│   ├── setup/                     # 利用者向けセットアップ手順
│   │   ├── linux.md               # Linux の配置手順（CLI・supervisor・launcher を同じディレクトリに置く。rootful はインストールスクリプト、rootless は利用者所有のディレクトリ。`PATH` 上の symlink。#2068・SUP-14・CORE-6）
│   │   ├── windows.md             # Windows セットアップ前提条件（WSL2・Developer Mode・`.wslconfig` の virtiofs。TASK-69・WIN-5。NTFS セマンティクス差異への対応〔TASK-68・WIN-4〕を統合）
│   │   ├── macos.md               # macOS セットアップ前提条件（対応版・Virtualization.framework の entitlement とコード署名・ゲストカーネル / initrd の用意。実装済み / 未実装・#1906 等の判断待ちを区別。#2602・MAC-1・CLI-2）
│   │   ├── network-reclaim-recovery.md  # 作成失敗で残った資源の観測と、印を刻む前に失敗した別名なし bridge の手動回収の手順（#2604・NET-1・REPAIR-4）
│   │   ├── container-log-recovery.md  # delete の後に残ったコンテナログの見分け方と手動削除の手順（#2698・SUP-7・CLI-1）
│   │   └── plugin-socket-recovery.md  # plugin socket の `ALREADY_EXISTS` の見分け方と記録の無い socket の手動削除の手順（#1859・PLUG-12）
│   ├── verification/              # 実機確認の記録雛形（crictl-smoke.md: crictl runp→create→start の疎通確認の手順書と結果雛形。TASK-60・CRI-1。結果記入は #442。cli-cross-platform-parity.md: CLI 基本 6 コマンドの 3 OS 同一構文・挙動チェックリスト。TASK-125.1・CLI-1。結果記入は #661。supervisor-measurement-runbook.md: 監視プロセス系の実機計測〔#499・#485・#491・#219〕の実行手順。#1820。rootless-start-cgroup.md: 本番の rootless start と委譲 cgroup の prepare の実機確認・delete の通し試験の手順と結果雛形。#2062・CORE-3・CORE-6・SEC-1・CLI-1。rootless-sysfs-readonly.md: rootless の /sys の読み取り専用 rbind の実機確認と、user namespace の root から ro を外せるかの測定の手順と結果雛形。#2305・SEC-2・SEC-1。landlock-audit-exec.md: Landlock ABI 7 以上の実カーネルで LOG_NEW_EXEC_ON 付き restrict_self が受理され拒否が監査ログに残ることの確認手順と結果雛形。#2306・SEC-4・CORE-5。plugin-peer-uid-after-close-macos.md: macOS で connect 直後に close された接続の peer UID 取得（`getpeereid`）の観測手順と結果雛形。PLUG-12・SEC-4・#2252 P2-2。結果記入は #2405。plugin-cri-peer-auth-reject.md: plugin-cri の別 UID connector 拒否の実機確認の手順書と結果雛形。PLUG-12・TASK-114.5。結果記入は #2485。bind-rslave-propagation.md: `rslave` の bind でホスト側で後からマウントした内容がコンテナ内に見えることの実機確認手順と結果雛形。#2669・CRI-2・OCI-4。結果記入は人間担当。subid-nss-ambient-getent.md: LDAP / sssd・`subid: sss` での所有者名の解決と、ambient capability つきの本番構成で `getent` の子に capability が渡らないことの実機確認手順と結果雛形。SEC-5・CORE-6・SUP-14・#2637。結果記入は #2637）
│   └── spec/                      # fandhe-container-spec submodule（private・要アクセス権）
├── .github/workflows/             # ai-review・update-external・ci（稼働）/ release（発火条件無効化中）
├── .agents/skills/                # npx skills add の導入実体
└── .claude/
    ├── agents/                    # カテゴリ別 subagent 定義
    ├── rules/                     # 運用ルール
    ├── skills/                    # 導入スキル（.agents/skills への symlink）
    ├── workflows/                 # implement-issue-tree.js（相対 symlink）
    └── settings.json              # SessionStart / PostToolUse hooks
```

## 委譲方針（必読）

main セッションはオーケストレーションに徹し、調査・実装・レビューは subagent へ委譲してコンテキスト消費を抑える。詳細は [delegation](.claude/rules/delegation.md)（調査）・[delegation-impl](.claude/rules/delegation-impl.md)（実装）を参照。

### パスベース切り替え表

| 対象 | 調査 | 作成・編集 |
| ---- | ---- | ---------- |
| `crates/io/` | explorer | io-builder |
| `crates/core/`・`crates/supervisor/` | explorer | runtime-builder |
| `crates/oci/`・`crates/cri/`・`plugin-cri` | explorer | oci-cri-builder |
| `crates/platform-*/`・`crates/guest-init/`・`crates/microvm/`・`plugin-macos` / `-windows` / `-microvm` | explorer | platform-builder |
| `crates/gpu/` | explorer | gpu-builder |
| `crates/net/` | explorer | net-builder |
| `crates/plugin/`・`plugin-mcp` | explorer | plugin-builder |
| `crates/cli/`・`crates/stack/`・`crates/compose-convert/` | explorer | cli-stack-builder |
| `Cargo.toml`・CI・`deny.toml`・`Makefile`・`lefthook.yml`・`Dockerfile`・`scripts/`・`benches/` | explorer | infra-builder |
| `docs/spec/`（private） | explorer | 変更しない（spec リポ側で管理） |
| 外部仕様（OCI / CRI・Linux カーネル API・Virtualization.framework・WSL2・KVM・CDI・MCP） | reference-researcher | — |
| テスト・lint | test-runner / linter | — |
| ドキュメント・`AGENTS.md`・`.claude/`（agents・rules・settings.json） | explorer | docs-writer |

### model 配分表

| 用途 | model |
| ---- | ----- |
| 複雑な横断判断・アーキテクチャ設計（crate 境界・core/plugin 境界・拡張点トレイト・I/O 契約） | opus または fable（fable は特に大規模設計・横断判断の最上位 tier） |
| 調査・生成・実装・レビュー | sonnet |
| 機械的集計・lint・ドキュメント更新 | haiku |

## Sub-agents

| カテゴリ | subagent_type | model | 役割 |
| -------- | ------------- | ----- | ---- |
| research | explorer | sonnet | コードベース・spec 横断調査 |
| research | reference-researcher | sonnet | 外部仕様・依存候補クレートの調査 |
| implement | io-builder | sonnet | io crate（I/O 共有層・フラッシュバリア・FS 正規化） |
| implement | runtime-builder | sonnet | core・supervisor crate（分離・cgroups・seccomp/Landlock・監視プロセス） |
| implement | oci-cri-builder | sonnet | oci・cri crate・plugin-cri（イメージ・ライフサイクル・CRI） |
| implement | platform-builder | sonnet | macOS / Windows / microVM の platform・plugin crate |
| implement | gpu-builder | sonnet | gpu crate（CDI・`/dev/dxg`・Venus） |
| implement | net-builder | sonnet | net crate（netlink・nftables・bridge/veth/netns・DNS） |
| implement | plugin-builder | sonnet | plugin crate・plugin-mcp（境界機構・信頼性検証・MCP） |
| implement | cli-stack-builder | sonnet | cli・stack・compose-convert crate（統一 CLI・TOML スキーマ・compose 変換） |
| implement | infra-builder | sonnet | workspace・3 OS CI・5 段階ゲート・deny・Makefile・Dockerfile・scripts・benches |
| testing | test-runner | sonnet | cargo test / clippy 実行と失敗解析（実機前提テストの区別を含む） |
| quality | reviewer | sonnet | 設計原則・AI 自己補修性・フルスクラッチ方針・規約準拠のレビュー |
| quality | security-auditor | sonnet | 分離・plugin 信頼境界・外部入力・unsafe/FFI・OWASP 監査 |
| quality | linter | haiku | rustfmt / clippy / cargo deny / lint-docs 等の機械的確認 |
| docs | docs-writer | haiku | README・CLAUDE.md・AGENTS.md・docs/design・.claude/ 更新 |

## Rules

| ファイル | 内容 |
| -------- | ---- |
| [delegation.md](.claude/rules/delegation.md) | 調査フェーズの委譲原則・パスベース切り替え |
| [delegation-impl.md](.claude/rules/delegation-impl.md) | 実装フェーズの委譲マッピング・標準フロー・着手条件（明示指示・人間担当タスク・root 権限） |
| [coding-rust.md](.claude/rules/coding-rust.md) | Rust 規約（crate / plugin 境界・型設計・外部入力・タイムアウト・unsafe/syscall・クロスプラットフォーム・テスト） |
| [security.md](.claude/rules/security.md) | 秘密情報・コンテナ分離・plugin 境界・OWASP Top 10 |
| [japanese-style.md](.claude/rules/japanese-style.md) | 日本語出力スタイル |
| [conventional-commits.md](.claude/rules/conventional-commits.md) | Conventional Commits 詳細規約（type/scope 一覧） |
| [code-comment-style.md](.claude/rules/code-comment-style.md) | コメント規約（役割・呼び出し文脈・契約・スタブの将来仕様） |
| [out-of-scope-tracking.md](.claude/rules/out-of-scope-tracking.md) | スコープ外事項の Issue 追跡フロー |
| [spec-reference.md](.claude/rules/spec-reference.md) | **リポ固有**: spec（SSOT）の参照・ID 併記・編集禁止 |
| [dependency-policy.md](.claude/rules/dependency-policy.md) | **リポ固有**: フルスクラッチ・禁止クレート・`=x.y.z` 固定・ユーザー承認制 |
| [licensing.md](.claude/rules/licensing.md) | **リポ固有**: 中核 Apache-2.0 単独・補助 crate の選択肢・コピーレフト禁止 |
| [ci.md](.claude/rules/ci.md) | **リポ固有**: ローカルゲート（変更範囲に限った確認。全体は CI）・5 段階 CI ゲート・3 OS CI・実機前提テストの扱い |
| [makefile.md](.claude/rules/makefile.md) | **リポ固有**: Makefile は薄い入口・実体は scripts/・ターゲット追加時の手順・スクリプト規約 |
| [github-actions.md](.claude/rules/github-actions.md) | **リポ固有**: runner 方針（public は GitHub ホステッド）・必須チェック名・発火条件・ジョブ追加チェックリスト・所要時間 |
| [git-hooks.md](.claude/rules/git-hooks.md) | **リポ固有**: lefthook の時間予算・CI との役割分担（CI と重複する検査をフックに置かない） |

## Current Skills

`npx skills add`（Fandhe-AI/agent-cli-skills・Fandhe-AI/agent-reference-skills）で導入済み。ロックは `skills-lock.json`。

- **ワークフロー系**: create-commit / create-pr / create-issue / create-issue-tree / create-plan / implement-issue / implement-issue-tree / implement-review / implement-review-pr / update-issue-tree / update-docs / comment-code
- **メンテ系**: init-claude / update-claude / contribute-skill / setup-repo-guards
- **リファレンス系**: make / rust / github-docs / commitlint / lefthook / editorconfig / anthropic-claude-code / anthropic-claude-code-extend / anthropic-api-tools-mcp / nvidia-cuda / dgx-spark / proxmox-ve / windows-interop-modernize

## Conventions

- **ローカル検証**: 変更範囲に限った軽量な確認に留める。`make fmt` で整形し、変更した crate の `cargo clippy -p <パッケージ名> --all-targets -- -D warnings`・`cargo test -p <パッケージ名>` を通してからコミットする（共有の型・公開トレイト・`Cargo.toml`・feature・`cfg` を変えたら `cargo check --workspace --all-targets` も。試験用 feature を持つ crate は `cargo clippy -p <パッケージ名> --lib --bins -- -D warnings` も）。ワークスペース全体の検証は CI がマージゲートとして担い、`make ci` は任意（[ci](.claude/rules/ci.md)「ローカルゲート」）。ビルド・テストは `docs/spec` 抜きで成立させる
- **日本語**: やりとり・報告・コミット説明文・コード内コメントは日本語（プログラム出力文字列は英語）
- **Conventional Commits**: `--no-verify` 禁止
- **セキュリティレビュー**: PR 作成前に OWASP Top 10＋コンテナ分離・plugin 信頼境界を確認
- **ユーザー承認フロー**: 実装の着手 / 依存の追加・更新 / 事前承認の範囲（各 crate の `sys` モジュールの syscall・ioctl・FFI ラッパー）外の `unsafe` の新規追加（[coding-rust](.claude/rules/coding-rust.md)） / ライセンス判断 / root 権限コマンドの実行 / Issue 起票 / 既存ファイル上書き / implement-issue の実装開始（計画承認後）は必ずユーザー承認を経る
- **spec 参照**: `docs/spec` の内容を引用・要約する際は TASK-n・ビヘイビア ID（`<PREFIX>-<N>`）・MS-n を併記する。`docs/spec` は本リポから編集しない
- **implement-issue-tree**: `.claude/workflows/implement-issue-tree.js`（相対 symlink）を named workflow として利用できる

## hooks（settings.json）

- **SessionStart**: 日本語・委譲・Conventional Commits・`--no-verify` 禁止・spec 参照（ID 併記）・依存承認制とフルスクラッチ・実装着手条件・root 権限コマンドのリマインダーを表示
- **PostToolUse**（Edit|Write）: `*.rs` 編集後に rustfmt で自動整形。edition はルート `Cargo.toml` から取得し（未作成時は 2024）、jq / rustfmt 未導入時は何もしない。整形失敗で作業を止めない
