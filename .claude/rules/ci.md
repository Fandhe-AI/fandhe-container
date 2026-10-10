# CI・ローカル検証規約（リポ固有。REPAIR 系ビヘイビア）

## ローカルゲート（コミット・PR 前）

```bash
make fmt-check   # cargo fmt --all --check
make lint        # cargo clippy --workspace --all-targets -- -D warnings
make test        # cargo test --workspace
make doc         # RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps
make ci          # 上記 + lint-docs + deny を一括実行
```

- テストは変更のたびに全件実行し、失敗・警告を 1 件でも残したまま進めない（fail-closed）
- Cargo.toml・メンバー crate が未作成の間、cargo 系ターゲットは Makefile 側で skip される（HAS_CARGO / HAS_MEMBERS）

## CI の構成（REPAIR-7 の 5 段階ゲート）

1. ビルド（`cargo build`・型検査）
2. ユニット / 統合テスト
3. タイムアウト保護された結合試験（ACK 未送信等のハングを検出。REPAIR-5）
4. ベンチ回帰チェック（15% 超の悪化で fail。REPAIR-8）
5. セキュリティチェック（`cargo deny`・禁止 API / 禁止クレート検査。REPAIR-9・MVM-4）

現状の `.github/workflows/ci.yml` は lint-docs・1・2（`rust-ci`〔ubuntu〕・`platform-ci`〔3 OS〕）・3（`platform-ci` ジョブ）・4 の比較の仕組み（`bench-regression` ジョブ）・5（rust-base-ci）相当のすべてに加え、アーキ網羅の型検査ゲート（`aarch64-linux-check` ジョブ）を持ち、発火条件は `workflow_dispatch`・`pull_request`・`push`（main）で稼働している（TASK-86.1・TASK-86.2・TASK-86.3・REPAIR-7）。

ステージ 3（タイムアウト保護された結合試験）は `platform-ci` ジョブ（3 OS matrix。実行ステップ 10 分・ジョブ全体 60 分の timeout-minutes）が担う（TASK-86.2・#36。旧 `integration-test` ジョブ）。

`platform-ci` ジョブは結合試験に続けて、スクリプトの自己テストを 3 OS（Windows は Git Bash）で実行する: `make plug4-core-invariance-selftest`（PLUG-4 判定スクリプト。TASK-109.4）・`make cli-parity-selftest`（CLI 3 OS 比較。TASK-125.1・CLI-1）・`make vz-virtio-gpu-guest-check-selftest`（virtio-gpu ゲスト側確認スクリプト。合成 fixture のみ。TASK-172.6・GPU-6）。いずれもステップごとに timeout-minutes 5 を付け、新しいジョブ・check-run 名は増やさない。

ルート workspace 外の PoC パッケージ `poc/venus-decoder/jig`（venus 試験治具。`crates/plugin-macos` へ path 依存。TASK-172.4・GPU-6）は `cargo build` / `cargo test --workspace` の対象に入らないため、`platform-ci` ジョブ（3 OS）の既定 feature 側ステップの末尾で `make poc-venus-jig-check`（fmt-check・clippy・test。clippy / test は `--locked` で治具の `Cargo.lock` を固定。timeout-minutes 15）を実行し、plugin-macos 側の変更による治具の破損を検出する。実機前提テストは `#[ignore]` で分離済みで CI では走らない。治具の `Cargo.lock` は rust-ci の `cargo deny`（ルート workspace のみ）の対象外のため、同ジョブの ubuntu で `make deny-poc-venus-jig`（ルートの `deny.toml` を共有し 4 種を `--locked` で検査。timeout-minutes 20）を実行する（ステージ 5）。ローカルの `make deny`（`make ci`）も治具の検査を含む。

rustdoc の警告（壊れた intra-doc リンク・private 項目へのリンク等。REPAIR-3）は `platform-ci` ジョブ（3 OS）の `make doc` ステップ（`RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps`。既定 feature。timeout-minutes 10）で fail させる（#1300）。新ジョブにせず既存ジョブのステップとしたのは check-run 件数を変えないため。3 OS で実行するのは、`cfg(target_os)` 限定の項目へのリンクが OS ごとに解決結果を変えるため。doc コメントでは他 OS で存在しない項目・private 項目へリンクせず、コード表記（バッククォートのみ）にする。

macOS cold start 上乗せ確認（TASK-113.4・PLUG-6・MAC-2）は `benches/tests/macos_cold_start.rs` の結合試験（`cfg(target_os = "macos")`。他 OS は skip を明示）として 3 OS matrix の macos で実行する。`bench-regression`（ubuntu 単独）のジョブ構成は変えず、基準値比較にも接続しない（模擬制御コアの計測で、実バックエンドは TASK-115）。

`bench-regression` ジョブは次の 17 個の `make` を ci.yml の並びどおりに実行する（自己テストはスタブ・疑似 /proc・fixture のみで照合し、実機は使わない）。

1. `make fio-bench-selftest`（fio 4K ランダム write ベンチスクリプトの自己テスト。TASK-25.1・IO-8）
2. `make fio-baseline-ratio-selftest`（fio ベースライン比の算出の自己テスト。TASK-25.2・IO-8）
3. `make bench-check-selftest`（比較スクリプトの自己テスト。REPAIR-8・REPAIR-12）
4. `make bench-baseline-selftest`（baseline.json 生成スクリプト `scripts/bench/generate_baseline.sh` の自己テスト。TASK-88.1）
5. `make startup-latency-selftest`（起動レイテンシ計測スクリプトの自己テスト。TASK-46.1・CORE-10）
6. `make net-setup-timing-selftest`（ネットワーク作成/接続/削除の所要時間計測スクリプトの自己テスト。TASK-139.5・NET-4）
7. `make dns-helper-measure-selftest`（DNS ヘルパー計測スクリプトの自己テスト。TASK-141.3・NET-5）
8. `make idle-memory-selftest`（アイドル時常駐メモリ計測スクリプト `scripts/bench/idle_memory.sh` の自己テスト。疑似 /proc のみで照合し実計測はしない。TASK-45.1・CORE-7・SUP-1）
9. `make concurrent-memory-selftest`（50 コンテナ同時起動の集約メモリ計測スクリプトの自己テスト。TASK-50.1・TASK-50.2・CORE-9・SUP-1）
10. `make idle-memory-supervised-selftest`（監視プロセス付きのアイドル時常駐メモリ計測の自己テスト。TASK-47・CORE-7・SUP-1）
11. `make supervisor-independence-selftest`（監視プロセス独立性の実証スクリプトの自己テスト。TASK-162・SUP-5）
12. `make supervisor-pss-selftest`（監視プロセス常駐メモリ計測スクリプト `scripts/bench/supervisor_pss.sh` の自己テスト。疑似 /proc のみ。TASK-158・SUP-2）
13. `make restart-latency-selftest`（restart レイテンシ計測スクリプト `scripts/measure-restart-latency.sh` の自己テスト。スタブ launcher のみ。TASK-160・SUP-3）
14. `make bench-check`（ベンチ実行・基準値比較。現状はプレースホルダの配線確認のみ）
15. `make bench-plugin-boundary`（plugin 境界ベンチの計測と CORE-10 比のログ出力のみ。基準値比較なし。TASK-113.3）
16. `make plugin-feature-size`（core の plugin feature 除外 release ビルドと rlib サイズの記録。PLUG-3・TASK-111.2。最終バイナリ未実装のため rlib 計測で、サイズ差に閾値は設けない）
17. `make plug4-core-invariance`（plugin の追加で core が変わらないことの判定。pull_request では base ブランチを fetch して比較する。自己テスト `make plug4-core-invariance-selftest` は `platform-ci` ジョブ側で実行する。TASK-109.4・PLUG-4）

`make bench-baseline` は登録ベンチと `benches/metrics.json`（direction・unit の SSOT）から baseline.json を再生成する道具である。ベンチ・基準値の現状は次のとおり（spec 側の判断は先取りしない）。

- 現時点で基準値比較の対象は `benches/benches/regression_placeholder.rs`（決定的な固定値の stub）と `benches/baseline.json`（`placeholder: true` の暫定値）だけで、動作確認の段階にある。計測対象がプレースホルダのため、現時点では実装の性能悪化を検出せず、性能回帰ゲートとして機能しない
- plugin 境界ベンチ（TASK-113〔#269〕・closed。`benches/benches/plugin_boundary*.rs`）は実装済みだが、baseline 未登録のため `bench-check` の比較対象外
- files/s・起動 p95 のベンチを実装するタスクは未定（`docs/design/bench-calibration.md`「既知の欠落」）
- 校正記録は TASK-88.2（#229）で `docs/design/bench-calibration.md` に整備済み。実測は前提ベンチが無いため保留している
- 実測基準値の確定は TASK-88.h1（#230）・TASK-113.h1（#274）（どちらも open）

plugin 境界ベンチの Δp50（`plugin_boundary_*_delta_p50`。TASK-113.3）は `make bench-plugin-boundary` ステップで計測と CORE-10 比のログ出力のみ行い（基準値比較なし）、15% 回帰判定は `make bench-check-selftest` の fixture で検証している。常時比較は実測基準値の登録と `bench-check` への組み込み（TASK-88.h1・TASK-113.h1）後に有効になる。

## 3 OS CI（macOS・Windows・Linux 一級対応）

- 各 OS のネイティブランナーでビルド・テストする（クロスコンパイル前提にしない）
- matrix は ubuntu / macos / windows の 3 OS を必須とし、特定 OS のみの skip で CI を通さない（例外は下記の docs のみ変更時の省略だけ）
- ジョブ構成（2026-10-10 の再構成。オーナー承認）: 3 OS のビルド・テストは `platform-ci`（3 OS matrix）の 1 ジョブに集約する。旧 `rust-ci-default-features`（既定 feature の `make lint` / `make test` / `make doc` 等）と旧 `integration-test`（結合試験・スクリプトの自己テスト・Linux 限定の実機前提テスト）のステップをそのまま移し、macOS・Windows では reusable の `rust-ci` が担っていた `cargo clippy --workspace --all-targets --all-features -- -D warnings` と `cargo test --workspace --all-features` もステップとして実行する。`rust-ci`（fmt・clippy / test の `--all-features`・deny）は ubuntu-latest のみ（1 要素の matrix で check-run 名 `rust-ci (ubuntu-latest) / ...` を保つ）。fmt・deny は結果が OS に依らない
- 集約の理由: macOS ランナーの同時実行枠が 1 枠程度しかなく、1 回の CI で macOS ジョブが 7 本（reusable の fmt・clippy・test・deny・complete の 5 本＋旧 2 ジョブ）並び、待ち行列で全 PR の CI が詰まったため。各ジョブ自体は 2〜5 分で、問題はジョブ本数だった。集約後の macOS ジョブは 1 回の CI で 1 本。ジョブを増やす・3 OS に分ける変更は macOS ジョブの本数を増やすため、既存の `platform-ci` のステップとして追加する
- docs のみの変更時の省略: `pull_request` で、マージコミットの第 1 親（base）との差分が docs だけのとき、`platform-ci` の macOS・Windows ではツールチェーン導入・cargo 系・結合試験・自己テストのステップを `if:` で飛ばす。ubuntu は常に全ステップを実行し、`push`（main）・`workflow_dispatch` では判定せず全 OS で全ステップを実行する。ジョブ自体は常に実行されて success を返すため、必須チェック `platform-ci (<os>)` は欠けない
  - docs とみなすパス: `docs/**`（`docs/spec` の gitlink を含む）・`.claude/**`・`.agents/**`・`skills-lock.json`・`*.md`。ただし `crates/`・`benches/`・`poc/`・`scripts/` 配下は `.md` でも docs とみなさない（`crates/cri/tests/proto_placement.rs` が `include_str!` で `crates/cri/proto/README.md` を読むなど、コード側の `.md` はビルド・テストの入力になり得るため）。`docs/spec` を docs 扱いにできるのは、checkout が submodule を取得せず、コード・`build.rs`・テスト・CI の `make` ターゲットが `docs/spec` を読まないため（本ファイル冒頭・[spec-reference](./spec-reference.md)）。コード・テストから docs 配下を読むようにする変更では、この判定の対象パスも見直す
  - 判定は fail-closed: マージコミットでない・第 2 親が PR の head と一致しない・`git diff` の失敗・差分が空・docs 外のパスを含む、のいずれでも省略しない。rename は `--no-renames` で移動元と移動先の両方を判定する
- OS 依存のファイルシステム挙動（パス・大文字小文字・ロック・改行）のテストは 3 OS すべてで実行する
- ベンチ回帰チェック（`bench-regression` ジョブ）は例外として ubuntu-latest 単独で実行する。ベンチの数値は OS 間の実行環境差で比較できず、3 OS matrix にしても意味のある回帰検出にならないため（本節の「3 OS 必須」はビルド・テストのゲートを対象とする規則であり、ベンチ回帰チェックはその対象外）
- venus 試験治具の依存監査（`platform-ci` の `make deny-poc-venus-jig` ステップ）も例外として ubuntu-latest のみで実行する。`deny.toml` に `targets` の指定が無く cargo-deny は実行ホストに関係なく全ターゲットの依存グラフ（macOS 専用の objc2 系を含む）を検査するため結果が OS に依らず、ビルド・テストのゲートではなく依存監査であるため「3 OS 必須」の対象外とする（cargo-deny の導入ビルドを 3 重に払わない）
- Linux aarch64 向けクロス型検査（`aarch64-linux-check` ジョブ。#1120・REPAIR-7）も例外として ubuntu-latest（x86_64）単独で実行する。`cargo check` / `cargo clippy --all-features --target aarch64-unknown-linux-gnu` で `cfg(target_arch = "aarch64")` 分岐をコンパイル検査するだけで（`--all-features` は `crash-test-server` 等の feature を要する target も型検査の対象に含めるため。`cfg(not(feature = "exec-test-support"))` 分岐と plugin 無効構成は aarch64 では未検査。x86_64 でも lib 側の `cfg_attr` は `cargo build --workspace`、plugin 無効構成は `make test-core-no-plugin` が検査するのみで、テスト側の `cfg(not(feature))` 分岐は feature 統一によりどの CI ジョブでも型検査されない）、リンクもテスト実行もしないアーキ網羅の型検査ゲートであり、ビルド・テストのゲートではないため「ネイティブランナーでビルド・テスト」「3 OS 必須」の対象外とする。aarch64 での実行時の正しさの検証はネイティブ arm64 ランナーでのテスト実行がフォローアップ課題であり、現状は保証しない。外部依存は純 Rust のみ（serde / serde_json / sha2 と推移依存。proc-macro はホスト側でビルドされる）でクロスリンカ不要という前提のため、`cc` 等ネイティブビルドを伴う依存を追加する場合は見直す

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
