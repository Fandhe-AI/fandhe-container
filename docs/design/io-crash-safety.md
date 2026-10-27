# IO-3 SIGKILL クラッシュ安全性の実測結果レポート

I/O 共有層の SIGKILL 耐性試験（`crates/io/tests/crash_safety.rs`）を実際に動かして得た試行回数・有効試行数・損失件数を記録する。試験本体は TASK-18.1 系・TASK-18.2 が、CI への組み込みは TASK-18.3.1 が完了している。本書は実測値を文書として残す TASK-18.3.2 の成果物である。

- 対象ビヘイビア: **IO-3**（SIGKILL 耐性）。関連: IO-2・IO-10・REPAIR-3・REPAIR-4・REPAIR-7・REPAIR-12
- 関連タスク: TASK-18 追補（#1832。未フラッシュ対照の作り直し）・TASK-18（#93）・TASK-18.1 / 18.1.1 / 18.1.2（#94・#825・#826）・TASK-18.2（#95）・TASK-18.3 / 18.3.1（#96・#827）・TASK-18.3.2（#828。本書）・TASK-18.h1（#97。人間による妥当性判断）
- 対象マイルストーン: MS-1 Phase 2
- ステータス: 妥当性の判断は #97 が行う。本書はその判断材料であり、事実（実測・CI ログで観測したもの）と推論（観測していないもの）を分けて書く。#97 の条件つき承認で指摘された「未フラッシュ対照が損失 0 で対照として働かない」点は #1832 で作り直した（下記）

## 試験の構成

3 ケースとも、テスト本体が子プロセス（`crash-test-server` feature の I/O サーバー）を起動し、ACK を観測した直後に SIGKILL してから、ディスク上のファイルを再読込して seq 0..n の連続性を照合する（レコード長は `RECORD_LEN` = 8 バイト）。詳細はテストのドキュメントコメントと `crates/io/tests/crash_safety/trial.rs` を参照する。

| テスト | sink | kill 位置 | アサーション |
| ------ | ---- | --------- | ------------ |
| `unix::io3_flushed_data_survives_10_valid_sigkills` | 製品の `AppendFileSink` | 30 件書き込み後、FLUSH ACK を観測した直後 | 有効試行 10 回・損失 0 |
| `unix::io3_deferred_sink_unflushed_loses_all_acked_data_in_10_valid_sigkills` | 試験専用 `DeferredPersistSink` | `batch_size=30` で通常 ACK を 30 件観測した直後（Flush なし。`persist` は呼ばれない） | 有効試行 10 回・全試行で 30 件すべて欠落（`found` 空・`lost` 30・合計 300・損失ありの試行 10） |
| `unix::io3_deferred_sink_flushed_keeps_all_data_in_10_valid_sigkills` | 試験専用 `DeferredPersistSink` | 30 件書き込み後、FLUSH ACK を観測した直後 | 有効試行 10 回・損失 0・`found` が 0..30（FLUSH ACK 非対応環境では全試行が FLUSH ACK 経路で無効になる契約確認） |

- 有効試行: 所定の ACK を観測したうえで SIGKILL によりサーバーが終了した試行。それ以外は無効試行として数え直す
- 目標は有効 10 回、試行上限は 30 回（`trial.rs` の `TARGET_VALID_TRIALS` / `MAX_ATTEMPTS`）
- 集計は `crash_summary`、試行ごとの記録は `crash_trial` として、いずれも stderr に JSON 1 行で出る（`crash_trial` には `sink` を含む）。`cargo test` は既定で出力を捕捉するため、件数の取得は環境変数 `FANDHE_CONTAINER_CRASH_SUMMARY_DIR`（#1833）で行う。指定したディレクトリへ `crash_summary` 行を `<case>.json`（case は `flushed`・`deferred_unflushed`・`deferred_flushed`）として排他作成（0600）で書く。FLUSH ACK 非対応環境でも同じ形式で `persist_supported:false` が出る。CI の `platform-ci` は「結合試験の実行」の後の「crash_safety 件数の集計」ステップで `make crash-summary-check` を実行し、検証した結果を `GITHUB_STEP_SUMMARY` に表で出す。

  ローカル手順（ディレクトリは毎回新規にする。排他作成のため既存ファイルがあるとテストが失敗する）:

  ```bash
  d="$(mktemp -d)"
  FANDHE_CONTAINER_CRASH_SUMMARY_DIR="$d" cargo test -p fandhe-container-io --features crash-test-server --test crash_safety
  make crash-summary-check CRASH_SUMMARY_DIR="$d" CRASH_SUMMARY_OS=Linux
  ```

### 相手役 sink（`DeferredPersistSink`）

- 製品の `AppendFileSink` は通常 ACK を `write()` 完了後に返す。SIGKILL ではページキャッシュが残るため、フラッシュしなくても損失は 0 件になり、`BatchSink::persist` が抜けても試験が通ってしまう。旧構成の未フラッシュ対照（製品 sink・損失件数をアサートしない）はこのため対照として働かず、廃止した
- `DeferredPersistSink` は `crates/io/tests/bin/crash_test_server.rs`（feature `crash-test-server` の bin）の中にだけある試験専用 sink で、`--sink deferred` で選ぶ。`write_batch` は body をメモリに積むだけで、`persist` が呼ばれて初めてファイルへ書いて `sync_all` する。ファイルは READY の前に空で作るため、未フラッシュ時のディスク照合は「0 バイト = 全件欠落」になる
- `crates/io/src`（`serve_connection`・`AppendFileSink`）は変更していない。ACK の順序を切り替える経路も製品コードには無い
- 未フラッシュと FLUSH ACK 後の 2 ケースを対にして読む。`persist` が抜けた、または FLUSH ACK が `persist` 成功より先に返る実装は、FLUSH ACK 後のケースが損失ありで落ちる

### この対照で示せる範囲

- 示せること: FLUSH ACK が `persist` の成功の後にだけ返ること（SIGKILL 後の可視性として）、および計測の仕組み（ディスク照合）が損失を検出できること
- 示せないこと: 電源断・カーネルクラッシュ後の媒体への永続化（IO-2）。再読込はページキャッシュ経由であり、この試験では検証していない。追跡は [#1965](https://github.com/Fandhe-AI/fandhe-container/issues/1965)。検証方式の判断記録は [io-power-loss-verification.md](io-power-loss-verification.md)（オーナー承認待ち）

## 保証範囲

- 検証するのは、SIGKILL 後にページキャッシュ経由で再読込したときの可視性だけである
- 電源断・カーネルクラッシュ後の媒体への永続化（IO-2）は検証しない
- `/tmp` が tmpfs の環境では `syncfs` が媒体への永続化を意味しない。このため FS 種別ごとに結果を分けて記録する

## 計測環境

- 計測対象: main の `052b32b9d5277754d644ad463b54e5577fba957e` に #1832 の変更（本書を除く）を適用した作業ツリー（コミット前に計測。PR の head と同一内容）
- 計測日: 2026-10-14
- `rustc 1.99.0 (b940084d7 2026-09-28)`・Linux 7.0.0-34-generic・x86_64
- 条件 A: `TMPDIR=/tmp`（FS 種別 tmpfs）
- 条件 B: `TMPDIR` を `/var/tmp` 配下の `mktemp -d` ディレクトリにしたもの（FS 種別 ext4。`/var/tmp` は `/` の ext4 上）。計測後に削除した
- 実行コマンド（3 ケースそれぞれを `--exact` で 1 件ずつ、各条件 3 回実行。全 18 実行で成功）:

```bash
TMPDIR=<dir> cargo test -p fandhe-container-io --features crash-test-server --test crash_safety -- --exact unix::<テスト名> --nocapture
```

## 実測結果（Linux ローカル）

18 実行すべて、ケースごとに同一の集計だった。

| 条件 | 回 | ケース | attempts | valid | invalid | aborted | checked | total_lost | max_lost | trials_with_loss | unexact |
| ---- | -- | ------ | -------- | ----- | ------- | ------- | ------- | ---------- | -------- | ---------------- | ------- |
| A（tmpfs） | 1〜3 | flushed（製品 sink） | 10 | 10 | 0 | false | 10 | 0 | 0 | 0 | 0 |
| A（tmpfs） | 1〜3 | deferred_unflushed | 10 | 10 | 0 | false | 10 | 300 | 30 | 10 | 10 |
| A（tmpfs） | 1〜3 | deferred_flushed | 10 | 10 | 0 | false | 10 | 0 | 0 | 0 | 0 |
| B（ext4） | 1〜3 | flushed（製品 sink） | 10 | 10 | 0 | false | 10 | 0 | 0 | 0 | 0 |
| B（ext4） | 1〜3 | deferred_unflushed | 10 | 10 | 0 | false | 10 | 300 | 30 | 10 | 10 |
| B（ext4） | 1〜3 | deferred_flushed | 10 | 10 | 0 | false | 10 | 0 | 0 | 0 | 0 |

- 事実: deferred_unflushed は全試行で `found` が 0 件・`lost` が 30 件（`unexact` は「ちょうど 0..30 が並ぶ」でない試行の数で、全件欠落のため 10）。決定的で、20 回連続実行しても `total_lost` は毎回 300 だった
- 事実: 同じ試験専用 sink で FLUSH ACK の後に kill した deferred_flushed は損失 0。2 ケースの差が `persist` の有無で現れている
- 事実: ミューテーション確認（ローカルのみ・コミットしない）として `DeferredPersistSink::persist` を何もしない実装に一時的に変えると、deferred_flushed が失敗することを確認した（確認後に戻した）

`crash_summary`（条件 A 1 回目。他の回も同一）:

```json
{"event":"crash_summary","case":"flushed","attempts":10,"valid":10,"invalid":0,"aborted":false,"checked":10,"total_lost":0,"max_lost":0,"trials_with_loss":0,"unexact":0}
{"event":"crash_summary","case":"deferred_unflushed","attempts":10,"valid":10,"invalid":0,"aborted":false,"checked":10,"total_lost":300,"max_lost":30,"trials_with_loss":10,"unexact":10}
{"event":"crash_summary","case":"deferred_flushed","attempts":10,"valid":10,"invalid":0,"aborted":false,"checked":10,"total_lost":0,"max_lost":0,"trials_with_loss":0,"unexact":0}
```

`crash_trial` の抜粋（deferred_unflushed・条件 A）:

```json
{"event":"crash_trial","index":0,"kill_point":"AfterWriteAcks(30)","sink":"deferred","acks_observed":30,"verdict":"Valid { acks_observed: 30 }","disk":"checked","lost":30,"found":0,"unexpected":0,"trailing_partial_bytes":0}
```

### 旧構成の実測（参考。廃止した製品 sink の未フラッシュ対照）

- 計測対象コミット `ef733e2e662ea4b0be1a44f632009e9b4acd48b6`（2026-09-29）で、製品の `AppendFileSink` に通常 ACK 30 件の直後に kill する未フラッシュ対照は、tmpfs・ext4 とも各 3 回、有効 10/10・損失 0 だった（12 実行）。これが対照として働かない根拠で、#1832 で作り直した

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

注記（2026-10-10）: 表のジョブ名は記録時点の CI 構成のもの。ジョブ再構成（macOS ランナー待ちの解消）で、`integration-test (<os>)` と `rust-ci (macos-latest|windows-latest) / cargo test` は `platform-ci (<os>)` のステップに統合され、`rust-ci` は ubuntu のみで実行する。さらに 2 段階目の再構成で、pull_request の `platform-ci` は ubuntu のみになり、macOS・Windows での実行は main への push と `workflow_dispatch` で行う（`.claude/rules/ci.md`「3 OS CI」）。記録自体は書き換えない。

注記（#1832）: 以下は旧構成のログ。`io3_unflushed_control_records_loss_without_asserting` は廃止し、`io3_deferred_sink_*` の 2 件に置き換えた。新構成の 3 OS の CI 結果は、この PR の merge 後の main の `platform-ci` で確認する（本書では未観測）。

```text
test unix::io3_flushed_data_survives_10_valid_sigkills ... ok
test unix::io3_unflushed_control_records_loss_without_asserting ... ok
test other::io3_crash_test_server_reports_unsupported_platform ... ok
```

- 推論: ubuntu と macOS の合格は、アサーションにより「有効 10 回・損失 0」が成立したことを意味する。ただし本書の実測時点では件数が CI に出ず、直接は観測していなかった（#1833 で CI の実行結果の要約に出るようにした。以降の値は各 run の要約を参照）。macOS の永続化対応判定（`PersistSupport`）が `SupportedFileSync` で true になることはコード上の事実だが、macOS の実 FS での挙動は本書の実測範囲外である
- 事実: Windows は UDS 未対応のため、非対応プラットフォームとして終了コード 5 を返す契約の確認だけを行っており、SIGKILL 耐性は検証していない

## spec の PoC（node4）との比較

| ケース | PoC（spec） | 本実装の実測 |
| ------ | ----------- | ------------ |
| FLUSH ACK 直後の kill | 有効 10/10・損失 0 | 有効 10/10・損失 0（製品 sink・試験専用 sink とも。tmpfs・ext4 とも） |
| フラッシュなし・ACK 済み未書き込みでの kill | 有効 10/10 の全試行で損失あり（17〜30 件） | 試験専用 sink: 有効 10/10・全試行で損失 30 件（tmpfs・ext4 とも）。製品 sink: 損失 0（旧実測 ef733e2e） |

- 事実: 試験専用 sink を相手役にすると、PoC と同じ向き（未フラッシュで ACK 済みデータが失われ、FLUSH ACK 後は失われない）の対が再現できた。件数は PoC が 17〜30 件、本試験は常に 30 件（`persist` が一度も呼ばれず、ファイルが空のまま）で、PoC と完全には一致しない
- 事実: 製品 sink は通常 ACK を `write()` 完了後に返すため、未フラッシュでも損失 0 だった。これは製品の設計どおりで、損失を再現するには相手役が要る
- 推論: PoC の対照は「ACK を書き込みより先に返す」性質だったと推測されるが、PoC 側のコードは確認していない

## #97 への引き継ぎ事項

判断は行わず、状況を並べる。

- 解消（#1832）: 未フラッシュ対照が損失 0 で対照として働かない点は、試験専用 sink を相手役にした 2 ケースの対へ作り直して解消した。この対照で示せる範囲は上記「この対照で示せる範囲」のとおり
- 未解決: 結果として tmpfs と実 FS のどちらを採用するか（本実測では差が出ていない）
- 解消（#1833）: 有効試行数・損失件数を CI の実行結果（`GITHUB_STEP_SUMMARY`）へ出す仕組みを設けた。macOS の件数は main への push 後の `platform-ci (macos-latest)` の要約で確認できる。FLUSH ACK 非対応時は `persist_supported:false` が表と警告に出る
- 未解決: 電源断・カーネルクラッシュ後の媒体永続化（IO-2）の検証をどのタスクで扱うか（追跡は [#1965](https://github.com/Fandhe-AI/fandhe-container/issues/1965)。方式の比較と推奨は [io-power-loss-verification.md](io-power-loss-verification.md)・オーナー承認待ち）
