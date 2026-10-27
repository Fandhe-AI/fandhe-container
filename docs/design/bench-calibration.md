# ベンチ基準値の校正記録

`benches/baseline.json`（ベンチ回帰チェックの基準値）を実測で確定するための校正記録の枠と、試行ログを残す。

- 対象ビヘイビア: REPAIR-8（主要ベンチが直近基準値より 15% 超悪化したら CI を fail させる。基準値は各ベンチ対象の初回実装完了時に実測して確定する）
- 関連タスク: TASK-88（#227）・TASK-88.1（#228。生成パイプライン `scripts/bench/generate_baseline.sh`・`make bench-baseline`）・TASK-88.2（#229。本記録）・TASK-88.h1（#230。基準値の妥当性判断。人間担当）
- 対象マイルストーン: MS-2 Phase 3
- ステータス: **実測は未実施**。`benches/baseline.json` は `placeholder: true` の暫定値のまま（実装済みを装わない。REPAIR-3）

## 校正対象の metric

| metric | 向き | 単位 | 状態 |
| ---- | ---- | ---- | ---- |
| 小ファイル多数ワークロードの files/s | `higher_is_better` | 未確定（実測で確定。TASK-88.h1） | ハーネス実装済み（TASK-189・#1898。metric は `small_files_files_per_sec`）。`metrics.json`・`BENCH_NAMES` へ登録済み（#1899）。baseline 未登録のため `bench-check` の比較対象外 |
| コンテナ起動レイテンシ p95 | `lower_is_better` | 未確定（同上） | ベンチ実装済み（TASK-190・#1900。metric は `startup_create_to_supervisor_ok_p95_ms`。`startup-latency-bench.md`）。実機前提で CI では実行しない。`metrics.json` へ登録済み（#1901。単位は ms）。`BENCH_NAMES` には入れず（`lib.sh` の `BENCH_MANUAL_NAMES`）、基準値は共有の `baseline.json` でなく `benches/baseline-manual.json`（未作成。実測は #230）。比較は人が実機で `make bench-check-manual`。CI では回帰を検出できない |
| plugin 境界 代表操作 A の inproc / framed / Δp50（`plugin_boundary_op_a_{inproc,framed,delta}_p50`） | `lower_is_better`（ns） | 未確定（実測は未実施） | TASK-113.1・113.3 で実装済み。metrics.json・`BENCH_NAMES` に登録済み。baseline 未登録 |
| plugin 境界 代表操作 B の inproc / framed / Δp50（`plugin_boundary_list_images_{inproc,framed,delta}_p50`） | `lower_is_better`（ns） | 未確定（実測は未実施） | TASK-113.2・113.3 で実装済み。登録状況は上と同じ |

## 校正記録（試行ログ）

実測日時は UTC・ISO 8601。実行環境は OS 種別・アーキテクチャ・CPU コア数程度に一般化し、ホスト名・IP・ユーザー名・アカウント識別子は書かない。

| 試行日時（UTC） | 実行環境 | 対象ベンチ | 結果 | 備考 |
| ---- | ---- | ---- | ---- | ---- |
| 2026-10-16 | Linux x86_64（ローカル開発機。ドライランのみ） | `make bench-baseline`（一時パス出力） | 実測なし。exit 0 で生成でき、生成物に `startup_create_to_supervisor_ok_p95_ms` が無いことを確認 | #1901。実機前提 metric を metrics から除く絞り込みの確認。生成物は破棄し、`benches/baseline.json` は変更していない |
| 2026-09-30 | Linux x86_64（ローカル開発機。ドライランのみ） | `regression_placeholder` のみ | 実測不可。files/s・起動 p95 のベンチが存在しない | `make bench-baseline` を一時パス出力で実行し exit 0 で生成できることのみ確認（パイプライン疎通）。生成物は破棄し、`benches/baseline.json` は変更していない |

## 実測の前提条件

1. files/s ベンチ（充足。#1898・#1899）と起動 p95 ベンチ（実装は充足〔#1900〕・`metrics.json` への登録は充足〔#1901〕。実機前提のため `BENCH_NAMES` には入れず `BENCH_MANUAL_NAMES`）が `benches/benches/` に実装されている。files/s は `BENCH_NAMES` と `benches/metrics.json` にも登録されている
2. 起動 p95 は TASK-29（コンテナ create/start）と supervisor の本番 launcher 結線（#1819）が完了している（充足）
3. 計測環境の扱いが TASK-88.h1 で決まっている（下記）

現状は `BENCH_NAMES := regression_placeholder plugin_boundary plugin_boundary_list_images`・metric は placeholder 2 件と plugin 境界 6 件（TASK-113.3 で登録）。`make bench-check` の対象は placeholder のみで、baseline 再生成時は `bench-check` の対象ベンチも同じ集合に揃えること（baseline と results の集合不一致は比較スクリプトが exit 2 にする）。metric だけを先に追加すると `generate_baseline.sh` は `results are missing metrics` で exit 2 になる（fail-closed。設計どおり）。

## 再実行手順

```bash
# ドライラン（一時パスへ出力。コミット対象の baseline.json を上書きしない）
make bench-baseline BENCH_BASELINE_OUT=<一時ファイルの絶対パス> BENCH_ENVIRONMENT="<一般化した環境説明>"

# 本番生成（前提条件充足後）。生成後に往復検証と比較を確認する
make bench-baseline BENCH_ENVIRONMENT="<一般化した環境説明>"
make bench-check
```

placeholder ベンチの結果を `benches/baseline.json` へ書き出さない。値が偽物のまま `generated_at`・`environment` が付き、校正済みに見えてしまうため。校正記録なしに baseline を書き換える差分は回帰検出の後退として扱う（`AGENTS.md`「ベンチ回帰」）。

## TASK-88.h1（人間担当）への判断事項

- 計測環境: `bench-regression` は ubuntu-latest 単独で実行される。ローカル実機の値を基準にすると CI 上の比較が意味を持たない。CI runner 上で採るか、環境差の扱いを決める
- 試行回数と集計: 単発か複数回の中央値か（生成器は 1 ベンチにつき results 1 ファイル）
- 起動 p95 の計測権限: namespace 操作に root / rootless のどちらを使うか。実機前提テストとして分離するか（`.claude/rules/ci.md`）。#1901 は暫定の (b) に沿って実機前提として登録した（下記「CI の扱いの決定（TASK-190）」）。(c)/(d) を選ぶ場合の移行は、`lib.sh` の `BENCH_MANUAL_NAMES` / `BENCH_MANUAL_METRICS` から `startup_latency` を外して `BENCH_NAMES` と `BENCH_STAGED_NAMES` へ移し、基準値を `benches/baseline-manual.json` から共有の `baseline.json` へ移す
- 15% 閾値と、placeholder 段階をいつ終了するか

## CI の扱いの決定（TASK-190）

TASK-190 は「CI で分離込みの起動を測れるか」を実装の前に確かめて決めることを求める。

| 観点 | 確かめた方法 | 結果 |
| ---- | ---- | ---- |
| カーネル版・Landlock ABI | `actions/runner-images` の Ubuntu2404-Readme.md（Image Version 20261012.334.1） | Kernel 6.17.0-1022-azure。ABI 6 に要る 6.12 以上を満たす。LSM に landlock が有効かは未確認 |
| 非特権 user namespace | `.github/workflows/ci.yml` の platform-ci「AppArmor の非特権 user namespace 制限を緩和」ステップ | 既定は `kernel.apparmor_restrict_unprivileged_userns=1`。緩めるのは platform-ci だけで、`bench-regression` は緩めていない |
| 委譲 cgroup | `DelegatedCgroup` の契約（非 root ではルート cgroup を拒否・親に自分以外のプロセスがいれば拒否）と #2049 の観察 | supervisor ごとに `systemd-run --user --scope -p Delegate=yes` が要る。hosted runner に user manager の直結ソケット（`$XDG_RUNTIME_DIR/systemd/private`。本番の start とベンチの事前検査が見るもの）があるかは未確認。用意には `loginctl enable-linger` などの sudo が要り、ci.md の方針（sudo の用途を増やさない）に反する |
| root | — | runner は非 root。supervisor は rootful を拒否する（SEC-5） |
| 揺らぎ | — | 共有 VM で p95 に 15% の閾値をかけると誤検知の恐れがある（未実測） |
| runner 上のプローブ | スモーク（引数なし。`cargo bench -p fandhe-container-benches --bench startup_latency` を手元で実行して採る。CI では実行しない）が 1 行出す（`apparmor_restrict_unprivileged_userns`・`max_user_namespaces`・landlock・user マネージャ（`user_manager=`。`$XDG_RUNTIME_DIR/systemd/private` の lstat で、本番の start・事前検査と同じ `user_manager_env` の判定）・`DelegatedCgroup::detect`・euid） | 未取得（CI にスモークの実行経路は無い。runner で採るには上のコマンドを実行するステップの追加が要り、本 issue では追加しない） |

**暫定の決定（オーナー確認待ち）: (b) ベンチ全体を実機前提として分離し、CI の回帰比較に入れない**（ci.md「実機前提テスト」）。

- (a)（区間を分ける）は採らない。特権なしで通る区間は `create` 単体だけで、それを「起動レイテンシ」と呼ぶと REPAIR-3 に反する
- CI で走るのは単体テスト（`platform-ci` の `cargo test --workspace`。lib 側のテスト）だけ。引数なしのスモーク（何も起動しない）は bench ターゲットのため CI では走らず、`BENCH_NAMES` にも未登録で、手元で実行する
- **REPAIR-8 の「CI で 15% 超の悪化を fail にする」は本 issue の時点では満たされない**。「REPAIR-8 を満たした」とは書かない。#1901 は暫定の (b) に沿って、起動 p95 を実機前提として回帰の仕組みへ登録した（`metrics.json` に metric、`lib.sh` に `BENCH_MANUAL_NAMES`、入口は `make bench-check-manual`）。CI では回帰を検出できず、REPAIR-8 の CI fail は未充足のまま。次の選択肢の判断（上の「起動 p95 の計測権限」）は引き続き #230 で行う
  - (c) hosted runner に sudo を追加して user manager を用意し、揺らぎを許容する
  - (d) self-hosted runner で比較する
  - (e) 実機の定期実測で基準値を管理する

## 既知の欠落（要ユーザー確認）

files/s ベンチは TASK-189（#1898）で実装し、#1899 で `metrics.json`・`BENCH_NAMES` へ登録した（`small-files-bench.md`）。起動 p95 ベンチは TASK-190（#1900）で実装した（`startup-latency-bench.md`）。実機前提のため CI では測れず、#1901 で実機前提として `metrics.json` へ登録した（`BENCH_NAMES`・共有 `baseline.json` には入れない。基準値 `benches/baseline-manual.json` は #230 の実測後に作る）。CI で 15% 超の悪化を fail にする REPAIR-8 は未充足で、(c)/(d)/(e) の判断待ちである（下記「CI の扱いの決定（TASK-190）」）。

## 実機前提ベンチの比較と基準値の作り方（#1901）

- 比較: 実機で `cargo bench -p fandhe-container-benches --bench startup_latency -- <引数> --output <絶対パス>` を実行し、`make bench-check-manual BENCH_RESULTS=<その絶対パス> [BENCH_HOST_KIND=<bare-metal|vm|wsl2>]` で `benches/baseline-manual.json` と比べる（結果の `host_kind` が語彙内なら `BENCH_HOST_KIND` は省略できる）。基準値が無い間は `skip:` を出して 0 で終わる（結果の検査は行う。失敗した実行・後始末の残りがある結果、`arch` が語彙外の結果は 2）。`skip:` は合格の根拠にしない
- 基準値の作り方（実測の後。#230）: `make bench-baseline-manual BENCH_RESULTS=<実測の結果の絶対パス> BENCH_HOST_KIND=<bare-metal|vm|wsl2> [BENCH_ENVIRONMENT="<一般化した環境>"]` を実行する（#2095・REPAIR-8）。既定の出力先は `target/bench-baseline-manual/baseline-manual.json` で、共有の `benches/baseline-manual.json` へは `BENCH_BASELINE_OUT` で明示したときだけ書く。失敗した実行の結果からは作らず 2 で終わる。内部では実機前提 metric に絞った metrics で `scripts/bench/generate_baseline.sh` を呼ぶ。同じ手順は `make bench-check-selftest` が合成 fixture で確かめる。実測値と基準値の確定は人間担当の #230 で、本リポには置かない
- 環境の機械照合（#2095）: 基準値は `host: {arch, kind}` を持つ。`arch` は結果 JSON の `.arch`（`x86_64` / `aarch64`）から取り、ホストの種類（`bare-metal` / `vm` / `wsl2`）はハーネスが結果の `host_kind` に自動判定して載せる（判定できなければ `unknown`）。操作者は `BENCH_HOST_KIND` で指定でき、結果が `unknown` か無いときは必須で、両方あって食い違えば 2 で終わる。`bench-check-manual` は、基準値があるとき結果の `host_kind` か `BENCH_HOST_KIND` のどちらかを必須とし、結果の `arch` と基準値の `host.arch`、または `BENCH_HOST_KIND` と `host.kind` が食い違う、あるいは基準値に `host` が無い場合は、比較せず入力エラー（2）で終わる。自由記述の `environment` は人向けの説明で、照合には使わない
- Linux 以外: `startup_latency` は `bench_names_for_os` がどの OS でも返さず、`bench-baseline` の metrics からも全 OS で除く。ベンチ自体は Linux 以外で何も書かずに終わるため、比較できる結果は Linux の実測だけ

## 関連

- `scripts/bench/generate_baseline.sh`・`scripts/check-bench-regression.sh`
- `AGENTS.md`「タイムアウト保護された結合試験・ベンチ回帰」節
