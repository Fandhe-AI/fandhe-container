# BREAK-1 / BREAK-2 の CI 検出実証レポート

REPAIR-7 の 5 段階 CI 構成が、PoC-8 の破壊 2 種（BREAK-1: ACK 未送信、BREAK-2: フレーム長破壊）をどの段階で検出・拒否したかを、実 CI の実行結果で記録する。

- 対象ビヘイビア: REPAIR-7（5 段階 CI ゲート）。関連: REPAIR-2（フレーム・チェックサム）・REPAIR-5（タイムアウト）・IO-1
- 関連タスク: TASK-89（#121）・TASK-89.1（#122・PR #1134。注入テストコード）・TASK-89.2（#123。本書）・TASK-89.h1（#124。人間による妥当性判断）
- 前提タスク: TASK-83・TASK-85・TASK-86・TASK-87
- 対象マイルストーン: MS-1 Phase 2
- ステータス: 妥当性の判断は #124 が行う。本書はその判断材料であり、事実（CI ログで観測したもの）と推論（観測していないもの）を分けて書く

## 破壊と検出機構の対応

テストは `crates/io/tests/break_detection.rs`（すべて `repair7_` 接頭辞）にある。注入コードはテストターゲット内だけにあり、`crates/io/src/` には含まれない（TASK-89.1 の受け入れ基準）。注入ごとに、破壊なしの対照テストを置き、常に失敗するハーネスが 100% 検出に見える状態を排除している。

| 破壊 | 注入 | 検出機構 | 期待結果 | 注入テスト / 対照テスト |
| ---- | ---- | -------- | -------- | ---------------------- |
| BREAK-1（ACK 未送信） | テストローカルの `AckDropping` が Ack / FlushAck を握りつぶす | `recv_ack` の有限時間打ち切り（REPAIR-5） | `IoErrorCode::Timeout` | `repair7_repair5_break1_ack_dropping_server_detected_as_timeout` / `repair7_repair5_break1_control_ack_arrives_without_injection` |
| BREAK-2（フレーム長破壊。インメモリ・全 OS） | `tamper_declared_len` で申告長を改ざん | `header_crc` と本体チェックサム（REPAIR-2） | `IoErrorCode::DataLoss`。書き込まれたバッチ 0・ACK 0 | `repair7_repair2_break2_declared_len_shorter_rejected_by_server` / `repair7_repair2_break2_control_well_formed_frame_is_written` |
| BREAK-2（同上。エラー文面） | 同上 | エラーメッセージにペイロードを含めない | 文面にペイロード内容なし | `repair7_repair2_break2_error_message_omits_payload_content` |
| BREAK-2（UDS。linux / macos のみ） | 同上 | 本番の受信経路（`mod unix`） | `IoErrorCode::DataLoss` | `unix::repair7_repair2_break2_uds_declared_len_shorter_rejected_by_production_recv` / `unix::repair7_repair2_break2_uds_control_well_formed_frame_is_written` |

タイムアウト設定の `repair7_timeout_setting_*`（3 件）は `FANDHE_CONTAINER_TEST_TIMEOUT_SECS` の解釈（既定 10 秒・範囲外と非数値の拒否）を検証する。

## 根拠 CI run

- run: [36507961727](https://github.com/Fandhe-AI/fandhe-container/actions/runs/36507961727)（`ci.yml`・`push`・main・commit `ec941c4b9603aef33a88308d4957a94629d64bb6`。TASK-89.1 の取り込みコミット）
- 実行日時: 2026-09-29 01:27:08Z 開始・01:31:58Z 更新（UTC）。結論は success（28 ジョブのうち `lint-docs / commitlint` のみ skipped、残りはすべて success。`ci-complete` も success）

### ジョブ別の結果

すべて break_detection のテストバイナリ内の結果。BREAK-1 / BREAK-2 の注入テストは全行 `ok`。

| ステージ | ジョブ | job ID | passed 件数 | BREAK-1 注入 | BREAK-2 注入 |
| -------- | ------ | ------ | ----------- | ------------ | ------------ |
| 3 | `integration-test (ubuntu-latest)` | 109213637245 | 10 | ok | ok |
| 3 | `integration-test (macos-latest)` | 109213637593 | 10 | ok | ok |
| 3 | `integration-test (windows-latest)` | 109213637543 | 8 | ok | ok（インメモリのみ） |
| 2 | `rust-ci (ubuntu-latest) / cargo test`（all-features） | 109213637638 | 10 | ok | ok |
| 2 | `rust-ci (macos-latest) / cargo test`（all-features） | 109213637521 | 10 | ok | ok |
| 2 | `rust-ci (windows-latest) / cargo test`（all-features） | 109213637581 | 8 | ok | ok（インメモリのみ） |
| 2 | `rust-ci-default-features (ubuntu-latest)` | 109213637538 | 10 件を実行（注記） | ok | ok |
| 集約 | `ci-complete` | 109214735960 | 該当なし | success | success |

注記: `rust-ci-default-features (ubuntu-latest)` のログは他のテストバイナリの出力と行が混ざり、break_detection 自身の `test result:` 行を特定できなかった。10 件の `ok` 行（`running 10 tests`）のみを確認済みで、passed 件数の行は確認していない。macOS / Windows の `rust-ci-default-features` ジョブは抜粋を取っていない（未確認）。Windows の 8 件は `mod unix` の 2 件が対象外になるため。

### ログ抜粋（テスト名・結果・時刻の行のみ）

ログは GitHub の保持期限（既定 90 日）で失効するため、該当行を残す。時刻は UTC。

`integration-test (ubuntu-latest)`（ステージ 3）:

```text
2026-09-29T01:27:41.8068351Z      Running tests/break_detection.rs (target/debug/deps/break_detection-9825a355f9d771d5)
2026-09-29T01:27:41.8075862Z running 10 tests
2026-09-29T01:27:41.8082883Z test repair7_repair2_break2_control_well_formed_frame_is_written ... ok
2026-09-29T01:27:41.8086720Z test repair7_repair5_break1_control_ack_arrives_without_injection ... ok
2026-09-29T01:27:41.8089834Z test repair7_repair2_break2_declared_len_shorter_rejected_by_server ... ok
2026-09-29T01:27:41.8097938Z test unix::repair7_repair2_break2_uds_declared_len_shorter_rejected_by_production_recv ... ok
2026-09-29T01:27:51.8085267Z test repair7_repair5_break1_ack_dropping_server_detected_as_timeout ... ok
2026-09-29T01:27:51.8085852Z test result: ok. 10 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 10.00s
```

`integration-test (macos-latest)`（ステージ 3）:

```text
2026-09-29T01:27:43.6207710Z      Running tests/break_detection.rs (target/debug/deps/break_detection-70db35be7fe9f1ed)
2026-09-29T01:27:43.6235880Z running 10 tests
2026-09-29T01:27:43.6238280Z test repair7_repair2_break2_declared_len_shorter_rejected_by_server ... ok
2026-09-29T01:27:43.6246780Z test unix::repair7_repair2_break2_uds_declared_len_shorter_rejected_by_production_recv ... ok
2026-09-29T01:27:53.6336500Z test repair7_repair5_break1_ack_dropping_server_detected_as_timeout ... ok
2026-09-29T01:27:53.6337990Z test result: ok. 10 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 10.01s
```

`integration-test (windows-latest)`（ステージ 3）:

```text
2026-09-29T01:28:03.4345356Z      Running tests\break_detection.rs (target\debug\deps\break_detection-1ff6fbc71418a160.exe)
2026-09-29T01:28:03.4476246Z running 8 tests
2026-09-29T01:28:03.4495154Z test repair7_repair2_break2_declared_len_shorter_rejected_by_server ... ok
2026-09-29T01:28:13.4524392Z test repair7_repair5_break1_ack_dropping_server_detected_as_timeout ... ok
2026-09-29T01:28:13.4525279Z test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 10.00s
```

`rust-ci (ubuntu-latest) / cargo test`（ステージ 2）:

```text
2026-09-29T01:27:44.9831928Z      Running tests/break_detection.rs (target/debug/deps/break_detection-9825a355f9d771d5)
2026-09-29T01:27:44.9840408Z running 10 tests
2026-09-29T01:27:44.9846922Z test repair7_repair2_break2_declared_len_shorter_rejected_by_server ... ok
2026-09-29T01:27:54.9856667Z test repair7_repair5_break1_ack_dropping_server_detected_as_timeout ... ok
2026-09-29T01:27:54.9858118Z test result: ok. 10 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 10.00s
```

`rust-ci (macos-latest) / cargo test`（ステージ 2）:

```text
2026-09-29T01:28:05.8695320Z      Running tests/break_detection.rs (target/debug/deps/break_detection-70db35be7fe9f1ed)
2026-09-29T01:28:05.8819830Z running 10 tests
2026-09-29T01:28:05.8851180Z test repair7_repair2_break2_declared_len_shorter_rejected_by_server ... ok
2026-09-29T01:28:16.0244770Z test repair7_repair5_break1_ack_dropping_server_detected_as_timeout ... ok
2026-09-29T01:28:16.0250630Z test result: ok. 10 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 10.14s
```

`rust-ci (windows-latest) / cargo test`（ステージ 2）:

```text
2026-09-29T01:28:11.9051000Z      Running tests\break_detection.rs (target\debug\deps\break_detection-b7facde8307aeeff.exe)
2026-09-29T01:28:11.9133946Z running 8 tests
2026-09-29T01:28:11.9146835Z test repair7_repair2_break2_declared_len_shorter_rejected_by_server ... ok
2026-09-29T01:28:21.9148316Z test repair7_repair5_break1_ack_dropping_server_detected_as_timeout ... ok
2026-09-29T01:28:21.9149039Z test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 10.00s
```

`rust-ci-default-features (ubuntu-latest)`（ステージ 2。他バイナリの出力が混在するため注入テストの行のみ）:

```text
2026-09-29T01:27:56.4664634Z      Running tests/break_detection.rs (target/debug/deps/break_detection-9825a355f9d771d5)
2026-09-29T01:27:56.4671064Z running 10 tests
2026-09-29T01:27:56.4682497Z test repair7_repair2_break2_declared_len_shorter_rejected_by_server ... ok
2026-09-29T01:28:06.4690582Z test repair7_repair5_break1_ack_dropping_server_detected_as_timeout ... ok
```

BREAK-1 の注入テストは、どの OS でも他のテストの約 10 秒後に ok になっている（例: ubuntu の integration-test で 01:27:41.8 から 01:27:51.8）。`FANDHE_CONTAINER_TEST_TIMEOUT_SECS=10` と一致するため、偶発的な切断ではなく REPAIR-5 のタイムアウトで検出されていると読める（推論。テスト側の期待値は `IoErrorCode::Timeout`）。

## 5 段階ごとの対応付け

| ステージ | 内容 | 本件の検出への寄与 |
| -------- | ---- | ------------------ |
| 1 ビルド | `cargo build`・型検査 | なし。破壊は実行時の挙動で、注入もテストビルド内に限られる。通ることは想定どおりで、検出の根拠にしない |
| 2 ユニット / 統合テスト | `rust-ci (<os>) / cargo test`（all-features）と `rust-ci-default-features`（`cargo test --workspace`） | あり。break_detection を含めて実行し、上表のとおり検出結果が ok |
| 3 タイムアウト保護された結合試験 | `integration-test (<os>)`（`cargo test --workspace --test '*'`・実行ステップ 10 分・`FANDHE_CONTAINER_TEST_TIMEOUT_SECS=10`）。3 OS | あり。上表のとおり 3 OS で検出結果が ok。BREAK-1 は約 10 秒の待ちを含む |
| 4 ベンチ回帰 | `bench-regression` | なし。現状は決定的なプレースホルダベンチ（TASK-86.3）で、本物への置き換えは TASK-113・TASK-88 |
| 5 セキュリティ | `cargo deny` 等 | なし。依存・ライセンスの検査で、本件の破壊とは無関係。禁止 API リントは未導入 |

結論: パイプライン全体としての拒否は、ステージ 2 と 3 の検出で成り立つ。ステージ 1・4・5 が寄与したとは主張しない。

## 「拒否」の 2 層

- プロトコル層（観測済み）: 不正フレームは `DataLoss`、ACK 欠落は `Timeout` のエラーコードで拒否され、BREAK-2 ではバッチが書き込まれない。テストの ok がその証拠
- CI 層（推論）: 検出が効かなくなればテストのアサーションが失敗し、ジョブが失敗し、`ci-complete` が fail-closed で失敗し、必須チェックがマージを止める。ステージ 3 が実際に赤くなることは TASK-87.2 のハングプローブ run（[36335480476](https://github.com/Fandhe-AI/fandhe-container/actions/runs/36335480476)。`ci.yml` のコメントに記録）で実証済み。ただし break_detection のアサーション失敗で CI が赤くなる run は取っておらず、この部分は fail-closed の連鎖からの推論で、実証はしていない

## 「100%」の意味

注入した破壊 2 種（BREAK-1・BREAK-2）と、上表の対象 OS・経路のすべてで検出された、という範囲に限る。BREAK-2 の UDS 経路は linux / macos のみで、Windows は UDS が `Unimplemented` のため対象外とし、インメモリ経路で代替している。これ以外の破壊の種類・経路への網羅性は主張しない。

## 制約・未実施事項（#124 の判断材料）

- 検出を無効化したときに CI が赤くなることの実証（使い捨て PR 等）は、受け入れ基準に含まれないため実施していない。要否は #124 で人間が判断する
- `rust-ci-default-features` は ubuntu のみ抜粋し、passed 件数の行は未確認
- ステージ 4 はプレースホルダ、ステージ 5 に禁止 API リントは未導入で、本件の検出には寄与しない

## 再現手順

- ローカル: `cargo test -p fandhe-container-io --test break_detection`
- CI ログの確認: `gh run view --job <job ID> --log` の出力から、`Running tests/break_detection.rs`（Windows は `tests\break_detection.rs`）のブロックを見る。`test result:` 行は直前に実行したテストバイナリのものなので、`Running` 行との隣接で確かめる
