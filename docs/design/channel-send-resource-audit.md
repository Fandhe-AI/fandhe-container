# チャネル send 後の資源保持の横断点検（supervisor・plugin）

Issue #3507・PLUG-2・REPAIR-5・SUP-1・SUP-7。#3453（`BoundedWriter::write_all` の作業スレッドが `send` の後も書き手の `Arc` を持ち、複製 fd の close が遅れた）と同じ型が他にないかの点検記録。

## 判定基準

作業スレッドが結果を `send` した後も資源（fd・ロック・枠・`Arc`）を持つと、受け手が「戻った時点で手放されている」前提で観測する場合に間欠失敗の窓ができる。次のいずれかなら無害とする。

- `send` の前に値渡しで消費される（`f()` / `work()` が FnOnce の取り込みごと消費する等）
- 受け手が `recv` の後に `join` する
- 観測する側が無い、または資源が他の所有者も持つ

## 点検結果（範囲: `crates/supervisor/src`・`crates/plugin/src` の本番コード）

| 箇所 | send の後に持つもの | 判定 |
| ---- | ------------------ | ---- |
| supervisor `start_entry.rs` BoundedWriter | なし（`drop(inner)` が send の前） | 修正済み（#3458） |
| supervisor `start_entry.rs` run_bounded / run_options_worker | なし（クロージャが消費される） | 無害 |
| supervisor `start_entry.rs` prepare_supervisor_log | `store`・`root`・`id` | 無害（受け手が join） |
| supervisor `deadline_store.rs` | `inner`（Arc）・ロック guard | 無害（送信と諦め判定を同じロックで行う意図的な構成。`wait_settled` は上限つき） |
| supervisor `control/server.rs` | listener・枠 | 無害（shutdown が join） |
| supervisor `health.rs` cancel_bounded / ProbeSession::run | probe の Arc | 無害（`InFlightGuard` は send の前に drop。Arc は runner も持つ） |
| supervisor `logs.rs` LogCapture のリーダー | 読み取り枠・sink・cancel | 該当。送信の前に手放すよう修正（#3507）。試験 `sup7_3507_reader_releases_slot_and_sink_before_reporting` |
| supervisor `logs.rs` gate | なし | 無害 |
| supervisor `logs.rs` flush_bounded | flush 枠・sink | 無害（#3489 で点検済み。成功後に枠の数を待たず観測する呼び出し側がない） |
| supervisor `pasta_attach.rs` teardown_bounded | なし | 無害（値を消費） |
| supervisor `start_client.rs` receive_report | なし | 無害（`out` を値で消費） |
| supervisor `supervisor_log.rs` run_bounded_with_slot | InflightSlot | 無害（受け手が join で確認） |
| supervisor `control/target.rs`・`seccomp_notify.rs`・`stderr_sink.rs` の try_send | 常駐スレッドの所有物のみ | 無害 |
| plugin `lifecycle.rs` plugin-stderr | `shared`・`stop`（Arc） | 無害（source は値で消費。Arc は収集器も持つ） |

試験コード（`mod tests`・`tests/`）の `send` は、合図の送信、EOF 後の読み取り端（CLOEXEC、相手の EOF を遅らせない）、消費済みの `f()` の結果の送信のいずれかで無害。

## 範囲外

- `plugin-cri`・`plugin-macos`・`plugin-mcp`・`plugin-windows` は未点検
- `crates/plugin-macos/src/isolate.rs` の `tx.send(f())` は、作業枠を送信の後まで持つ形で logs.rs と同じ型の候補。後続で点検する

## 再点検

```bash
git grep -n '\.send(' -- crates/supervisor crates/plugin
git grep -n '\.try_send(' -- crates/supervisor/src crates/plugin/src
```
