# IO-3 SIGKILL クラッシュ安全性の実測結果レポート

I/O 共有層の SIGKILL 耐性試験（`crates/io/tests/crash_safety.rs`）を実際に動かして得た試行回数・有効試行数・損失件数を記録する。試験本体は TASK-18.1 系・TASK-18.2 が、CI への組み込みは TASK-18.3.1 が完了している。本書は実測値を文書として残す TASK-18.3.2 の成果物である。

- 対象ビヘイビア: **IO-3**（SIGKILL 耐性）。関連: IO-2・IO-10・REPAIR-3・REPAIR-4・REPAIR-7・REPAIR-12
- 関連タスク: TASK-18（#93）・TASK-18.1 / 18.1.1 / 18.1.2（#94・#825・#826）・TASK-18.2（#95）・TASK-18.3 / 18.3.1（#96・#827）・TASK-18.3.2（#828。本書）・TASK-18.h1（#97。人間による妥当性判断）
- 対象マイルストーン: MS-1 Phase 2
- ステータス: 妥当性の判断は #97 が行う。本書はその判断材料であり、事実（実測・CI ログで観測したもの）と推論（観測していないもの）を分けて書く

## 試験の構成

2 ケースとも、テスト本体が子プロセス（`crash-test-server` feature の I/O サーバー）を起動し、ACK を観測した直後に SIGKILL してから、ディスク上のファイルを再読込して seq 0..n の連続性を照合する（レコード長は `RECORD_LEN` = 8 バイト）。詳細はテストのドキュメントコメントと `crates/io/tests/crash_safety/trial.rs` を参照する。

| テスト | kill 位置 | アサーション |
| ------ | --------- | ------------ |
| `unix::io3_flushed_data_survives_10_valid_sigkills` | 30 件書き込み後、FLUSH ACK を観測した直後 | 有効試行 10 回・損失 0 |
| `unix::io3_unflushed_control_records_loss_without_asserting` | `batch_size=30` で通常 ACK を 30 件観測した直後（フラッシュなし） | `summary.aborted == false`・有効試行 10 回・各試行のディスク照合をアサートする。損失件数だけはアサートしない（記録のみ） |

- 有効試行: 所定の ACK を観測したうえで SIGKILL によりサーバーが終了した試行。それ以外は無効試行として数え直す
- 目標は有効 10 回、試行上限は 30 回（`trial.rs` の `TARGET_VALID_TRIALS` / `MAX_ATTEMPTS`）
- 集計は `crash_summary`、試行ごとの記録は `crash_trial` として、いずれも stderr に JSON 1 行で出る。`cargo test` は既定で出力を捕捉するため、CI ログには件数が出ず、ローカルで `--nocapture` を付けて取得する

## 保証範囲

- 検証するのは、SIGKILL 後にページキャッシュ経由で再読込したときの可視性だけである
- 電源断・カーネルクラッシュ後の媒体への永続化（IO-2）は検証しない
- `/tmp` が tmpfs の環境では `syncfs` が媒体への永続化を意味しない。このため FS 種別ごとに結果を分けて記録する

## 計測環境

- 計測対象コミット: `ef733e2e662ea4b0be1a44f632009e9b4acd48b6`（main）
- 計測日時: 2026-09-29 11:39〜（UTC）
- `rustc 1.98.1 (48a229cea 2026-09-01)`・Linux 7.0.0-34-generic・x86_64
- 条件 A: `TMPDIR=/tmp`（FS 種別 tmpfs）
- 条件 B: `TMPDIR` を `/var/tmp` 配下の `mktemp -d` ディレクトリにしたもの（FS 種別 ext4）。計測後に削除した
- 実行コマンド（2 ケースそれぞれを `--exact` で 1 件ずつ、各条件 3 回実行。全 12 実行で終了コード 0）:

```bash
TMPDIR=<dir> cargo test -p fandhe-container-io --features crash-test-server --test crash_safety -- --exact unix::<テスト名> --nocapture
```

## 実測結果（Linux ローカル）

12 実行すべて同一の集計だった。

| 条件 | 回 | ケース | attempts | valid | invalid | aborted | checked | total_lost | max_lost | trials_with_loss | unexact |
| ---- | -- | ------ | -------- | ----- | ------- | ------- | ------- | ---------- | -------- | ---------------- | ------- |
| A（tmpfs） | 1〜3 | flushed | 10 | 10 | 0 | false | 10 | 0 | 0 | 0 | 0 |
| A（tmpfs） | 1〜3 | unflushed_control | 10 | 10 | 0 | false | 10 | 0 | 0 | 0 | 0 |
| B（ext4） | 1〜3 | flushed | 10 | 10 | 0 | false | 10 | 0 | 0 | 0 | 0 |
| B（ext4） | 1〜3 | unflushed_control | 10 | 10 | 0 | false | 10 | 0 | 0 | 0 | 0 |

- 有効試行の合計は各ケース・各条件で 3 回 × 10 = 30、損失件数の合計は 0
- unflushed_control の全試行で `verdict` は `Valid`、`lost` は 0（`total_lost` = 0 から導かれる）

`crash_summary`（条件 A 1 回目と条件 B 1 回目。他の回も同一）:

```json
{"event":"crash_summary","case":"flushed","attempts":10,"valid":10,"invalid":0,"aborted":false,"checked":10,"total_lost":0,"max_lost":0,"trials_with_loss":0,"unexact":0}
{"event":"crash_summary","case":"unflushed_control","attempts":10,"valid":10,"invalid":0,"aborted":false,"checked":10,"total_lost":0,"max_lost":0,"trials_with_loss":0,"unexact":0}
```

`crash_trial` の抜粋（条件 A 1 回目）:

```json
{"event":"crash_trial","index":0,"kill_point":"AfterFlushAck { writes: 30 }","acks_observed":30,"verdict":"Valid { acks_observed: 30 }","disk":"checked","lost":0,"found":30,"unexpected":0,"trailing_partial_bytes":0}
{"event":"crash_trial","index":0,"kill_point":"AfterWriteAcks(30)","acks_observed":30,"verdict":"Valid { acks_observed: 30 }","disk":"checked","lost":0,"found":30,"unexpected":0,"trailing_partial_bytes":0}
```

## 3 OS の CI 結果

- run: [36562529951](https://github.com/Fandhe-AI/fandhe-container/actions/runs/36562529951)（`ci.yml`・`push`・main・commit `ef733e2e662ea4b0be1a44f632009e9b4acd48b6`。結論は success）
- 事実: 下表の各ジョブで、対象テストが `ok` になったことを CI ログで確認した。ログの保持期限（90 日）を過ぎると再取得できないため、行を抜粋して残す

| ジョブ | job ID | 対象テストの結果 |
| ------ | ------ | ---------------- |
| `integration-test (ubuntu-latest)` | 109386549836 | `unix::io3_*` 9 件 ok（上記 2 ケースを含む） |
| `integration-test (macos-latest)` | 109386549957 | 同 9 件 ok |
| `integration-test (windows-latest)` | 109386549750 | `other::io3_crash_test_server_reports_unsupported_platform` のみ ok |
| `rust-ci (ubuntu-latest) / cargo test` | 109386549823 | `unix::io3_*` 9 件 ok |
| `rust-ci (macos-latest) / cargo test` | 109386549792 | 同 9 件 ok |
| `rust-ci (windows-latest) / cargo test` | 109386550127 | `other::io3_crash_test_server_reports_unsupported_platform` のみ ok |

注記（2026-10-10）: 表のジョブ名は記録時点の CI 構成のもの。ジョブ再構成（macOS ランナー待ちの解消）で、`integration-test (<os>)` と `rust-ci (macos-latest|windows-latest) / cargo test` は `platform-ci (<os>)` のステップに統合され、`rust-ci` は ubuntu のみで実行する（`.claude/rules/ci.md`「3 OS CI」）。記録自体は書き換えない。

```text
test unix::io3_flushed_data_survives_10_valid_sigkills ... ok
test unix::io3_unflushed_control_records_loss_without_asserting ... ok
test other::io3_crash_test_server_reports_unsupported_platform ... ok
```

- 推論: ubuntu と macOS の合格は、アサーションにより「有効 10 回・損失 0」が成立したことを意味する。ただし件数そのものは CI ログに出ないため、直接は観測していない。macOS の永続化対応判定（`PersistSupport`）が `SupportedFileSync` で true になることはコード上の事実だが、macOS の実 FS での挙動は本書の実測範囲外である
- 事実: Windows は UDS 未対応のため、非対応プラットフォームとして終了コード 5 を返す契約の確認だけを行っており、SIGKILL 耐性は検証していない

## spec の PoC（node4）との比較

| ケース | PoC（spec） | 本実装の実測 |
| ------ | ----------- | ------------ |
| FLUSH ACK 直後の kill | 有効 10/10・損失 0 | 有効 10/10・損失 0（tmpfs・ext4 とも） |
| フラッシュなし・ACK 済み未書き込みでの kill | 有効 10/10 の全試行で損失あり（17〜30 件） | 有効 10/10・損失 0（tmpfs・ext4 とも） |

- 事実: flushed は PoC と一致した。未フラッシュ対照は PoC と一致せず、損失が観測されなかった
- 推論: 本実装の通常 ACK は `write()` 完了後に返るため、SIGKILL ではページキャッシュの内容が失われず、ディスク照合で全件が見える。PoC の対照は「ACK を書き込みより先に返す」性質だったと推測されるが、PoC 側のコードは確認していない

## #97 への引き継ぎ事項

判断は行わず、問いとして並べる。

- 未フラッシュ対照が、フラッシュ処理（FLUSH ACK）の必要性を示す対照として妥当か。PoC と同じ損失を再現する対照へ再設計する必要があるか
- 結果として tmpfs と実 FS のどちらを採用するか（本実測では差が出ていない）
- macOS の件数を CI 上で直接観測する仕組み（`--nocapture` 化・アーティファクト保存）を設けるか
- 電源断・カーネルクラッシュ後の媒体永続化（IO-2）の検証をどのタスクで扱うか
