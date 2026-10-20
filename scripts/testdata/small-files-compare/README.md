# small-files-compare の fixture

`scripts/bench/small_files_compare_selftest.sh` のスタブのハーネスが返す結果 JSON の見本（TASK-24.1・IO-7）。
キー構成は `benches/src/small_files.rs` の `results_json` と同じにしてある。

- `harness-per-file.json`: `--batch-size 1`（`flush-per-file`・`io2_guaranteed: true`）
- `harness-every-k.json`: `--batch-size 100`（`flush-every-k`・`io2_guaranteed: false`）

数値は決定的な固定値で、実測値ではない。
