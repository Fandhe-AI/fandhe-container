# チャネル send 後の資源保持の横断点検（supervisor・plugin・plugin-*）

Issue #3507・#3549・PLUG-2・REPAIR-5・SUP-1・SUP-7。#3453（`BoundedWriter::write_all` の作業スレッドが `send` の後も書き手の `Arc` を持ち、複製 fd の close が遅れた）と同じ型が他にないかの点検記録。

## 判定基準

作業スレッドが結果を `send` した後も資源（fd・ロック・枠・`Arc`）を持つと、受け手が「戻った時点で手放されている」前提で観測する場合に間欠失敗の窓ができる。次のいずれかなら無害とする。

- `send` の前に値渡しで消費される（`f()` / `work()` が FnOnce の取り込みごと消費する等）
- 受け手が `recv` の後に `join` する
- 観測する側が無い、または資源が他の所有者も持つ

## 点検結果（範囲: `crates/supervisor/src`・`crates/plugin/src`・`crates/plugin-cri/src`・`crates/plugin-macos/src`・`crates/plugin-mcp/src`・`crates/plugin-windows/src` の本番コード）

| 箇所 | send の後に持つもの | 判定 |
| ---- | ------------------ | ---- |
| supervisor `start_entry.rs` BoundedWriter | なし（`drop(inner)` が send の前） | 修正済み（#3458） |
| supervisor `start_entry.rs` run_bounded / run_options_worker | なし（クロージャが消費される） | 無害 |
| supervisor `start_entry.rs` prepare_supervisor_log | `store`・`root`・`id` | 無害（受け手が join） |
| supervisor `deadline_store.rs` | `inner`（Arc）・ロック guard | 無害（送信と諦め判定を同じロックで行う意図的な構成。`wait_settled` は上限つき） |
| supervisor `control/server.rs` | listener・枠 | 無害（shutdown が join） |
| supervisor `health.rs` cancel_bounded / ProbeSession::run | probe の Arc | 無害（`InFlightGuard` は send の前に drop。Arc は runner も持つ） |
| supervisor `logs.rs` LogCapture のリーダー | 読み取り枠・sink・cancel | 該当。送信の前に手放すよう修正（#3507）。試験 `sup7_3507_reader_releases_slot_and_sink_before_reporting`。`log_pipeline.rs` の `sup7_1471_quiesce_leaves_no_reader_threads` の待ちの補償は直接照合へ置換（#3549） |
| supervisor `logs.rs` gate | なし | 無害 |
| supervisor `logs.rs` flush_bounded | flush 枠・sink | 無害（#3489 で点検済み。成功後に枠の数を待たず観測する呼び出し側がない） |
| supervisor `pasta_attach.rs` teardown_bounded | なし | 無害（値を消費） |
| supervisor `start_client.rs` receive_report | なし | 無害（`out` を値で消費） |
| supervisor `supervisor_log.rs` run_bounded_with_slot | InflightSlot | 無害（受け手が join で確認） |
| supervisor `control/target.rs`・`seccomp_notify.rs`・`stderr_sink.rs` の try_send | 常駐スレッドの所有物のみ | 無害 |
| plugin `lifecycle.rs` plugin-stderr | `shared`・`stop`（Arc） | 無害（source は値で消費。Arc は収集器も持つ） |
| plugin-macos `isolate.rs` run の作業スレッド | 作業枠 `Slot` | 該当。結果と一緒に枠を送り、受け手が受け取った直後に返すよう修正（#3549）。試験 `plug2_3549_repair5_slot_is_returned_before_result_is_received`。残余: 期限切れ直後に送信された値は rx の drop まで残る（既存の挙動で別事象） |
| plugin-cri `adapter.rs` run_startup_pull_recovery | なし | 無害（`f` が消費され、戻り値は集計値のみ） |
| plugin-cri `orphan_bundles.rs` with_deadline | なし | 無害（`f` が取り込みごと消費。期限切れでロックを持ち続けるのは意図した動作） |
| plugin-cri `telemetry.rs` の try_send | 常駐スレッドの所有物のみ | 無害 |
| plugin-mcp `server.rs` write_diagnostic・with_stderr_log・serve_with の各スレッド | 常駐スレッドの所有物・バッファ | 無害（観測する側が無い、またはセッション中常駐） |
| plugin-windows `src/` | - | 対象なし（`.send(`・`.try_send(` が 0 件） |

試験コード（`mod tests`・`tests/`）の `send` は、合図の送信、EOF 後の読み取り端（CLOEXEC、相手の EOF を遅らせない）、消費済みの `f()` の結果の送信のいずれかで無害。plugin 4 crate の試験（plugin-cri の `tests/`、plugin-macos の `replay/tests.rs`・`tests/e2e.rs`、plugin-mcp の `tests/`、plugin-windows の `tests/e2e.rs`）も、合図、EOF まで読み切った後のバッファ、常駐の中継、解放を観測しない e2e の結果送信のいずれかで無害。

## 範囲外

なし（plugin 4 crate の点検と isolate の是正は #3549 で完了）。

## 再点検

```bash
git grep -n '\.send(' -- crates/supervisor crates/plugin crates/plugin-cri crates/plugin-macos crates/plugin-mcp crates/plugin-windows
git grep -n '\.try_send(' -- crates/supervisor/src crates/plugin/src crates/plugin-cri/src crates/plugin-macos/src crates/plugin-mcp/src crates/plugin-windows/src
```
