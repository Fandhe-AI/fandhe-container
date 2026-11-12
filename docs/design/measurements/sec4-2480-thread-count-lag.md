# sec4_2480 の間欠失敗: join 後の `Threads:` 減算の遅れ（SEC-4・SUP-6・SUP-8・REPAIR-5・REPAIR-12・#2766）

`crates/cli/tests/binary_entry.rs` の `sec4_2480_create_rejected_destination_is_audited` が並列の全件実行で間欠的に失敗した原因と、修正・回帰試験の記録。

## 現象

- 期待は stderr がちょうど 1 行（create の `INVALID_ARGUMENT`）。失敗時は、その前に監査の書き込み失敗の通知行が 1 行増えて 2 行になっていた。
- 通知行は、監査の主経路（fork 隔離）と代替経路（カーネル監査。非特権の CI では権限不足）の両方が失敗したことを示す。

## 原因

1. CLI の create は、core の監査 sink（単一スレッド前提の fork）に進む前に、`supervisor_log::run_bounded_*`（ログの残骸の回収・起動オプション文書の I/O）を通る。
2. `run_bounded_with_slot` は作業スレッドを `join` してから戻る。ただし `pthread_join` はスレッド終了の通知で戻り、`/proc/self/status` の `Threads:` の減算はそれより少し後になりうる。
3. その窓で sink が fork しようとすると `Threads: 2` を見て主経路が失敗する。並列の負荷が高いほど窓に当たりやすい。
4. 同じ窓は `thread_settle`（restart の再 launch）と core の `file_sink` に対処済みだったが、`run_bounded_with_slot` には無かった。

## 確認

- 修正前のコードで `bounded_worker_thread_settle`（新設。戻り直後の `Threads:` が 1 であることを毎回照合）を 3 回回すと、いずれも 500 ラウンド中の round 18・127・344 で `Threads:` が 1 でない状態で失敗した（窓を直接観測）。
- 修正前の `sec4_2480_*` 自体の再現は、この環境（10 コア、Linux 7.0.0-43-generic）の負荷なしの繰り返しでは採れていない。本試験の失敗は窓の観測を原因の根拠とする（fork の `EAGAIN` が原因の可能性は、本環境では観測していないため残る）。
- 除外した候補: 枠（`INFLIGHT_LOG_REMOVALS`）の満杯の誤分類（#2868・#2894）。枠はプロセス内で、1 回の CLI の create は作業を順に回すため 8 枠は埋まらず、満杯なら `TIMEOUT` か `RESOURCE_EXHAUSTED` で失敗して観測の形（`INVALID_ARGUMENT` の前に通知行）と合わない。

## 修正

`supervisor_log::run_bounded_with_slot` が、起動前に単一スレッドだった場合に限り、join の後に `Threads:` が 1 に戻るのを `WORKER_EXIT_GRACE`（1 秒）の残りまで待つ（`thread_settle::is_single_threaded` / `wait_single_threaded`）。戻らなければ期限切れ扱い（fail-closed。監査の記録点へ多スレッドのまま進まない）。起動前から多スレッドの呼び出し元（plugin-cri）は待たない。新しい `unsafe`・依存は無い。

## 試行条件と結果

環境: 10 コア、Linux 7.0.0-43-generic、負荷なし。

| コマンド | 結果 |
| -------- | ---- |
| `make repeat-test PACKAGE=fandhe-container-cli TEST_BIN=binary_entry LIBTEST_NAME=sec4_2480_create_rejected_destination_is_audited COUNT=300` | `passed=300 failed=0` |
| `make repeat-test PACKAGE=fandhe-container-cli TEST_BIN=binary_entry PARALLEL=1 COUNT=30` | `passed=30 failed=0`（`tests_per_run=77`） |
| `make repeat-test PACKAGE=fandhe-container-supervisor TEST_BIN=bounded_worker_thread_settle SUCCESS_LINE=... COUNT=100` | `passed=100 failed=0` |

## 回帰試験

- `crates/supervisor/tests/bounded_worker_thread_settle.rs`: 戻り直後の `Threads: 1` を 1500 呼び出しで照合する。
- supervisor 不在時の exec（#2688 の方式のうち「縮退しない」）: `crates/supervisor/tests/control_exec_handover.rs` の `sup6_sup8_sec4_2766_*` と `crates/cli/src/commands/exec/linux/tests.rs` の `sup6_sup8_sec4_2766_*`。制御ソケットが無い・残骸だけ・Hello 前に切断の 3 場面で、固定文言の `Unavailable` になり、生きている pid の記録でも実行役が呼ばれないことを照合する。
- 黙って待つ相手（accept するが応答しない）は `Unavailable` ではなく `Timeout` になる（コードから）。本試験では固定していない。

## 残余

- 解放が 1 秒を超えて遅れると、create は `TIMEOUT` で失敗する（監査を落とさない側に倒す）。
- fork の `EAGAIN` を `isolation_unavailable` に畳む扱いは別経路で、本件では変えていない。

関連: #2626・#2688・#2868・#2894。
