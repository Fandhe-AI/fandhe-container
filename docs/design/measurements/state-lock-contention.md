# 状態ストア `@lock` の取り直しによる飢えの計測と対策

Issue #2229（SUP-1・REPAIR-5・TASK-157.9・OCI-5）の記録。対象は `crates/core/src/state_store.rs` の `FileStateStore::lock`。

## 問題

`@lock` は std の `File::try_lock` を一定間隔で再試行して待つだけで、待ち順の仕組みが無い。あるプロセスが間を空けずに操作を続けると、解放の数十 µs 後に取り直すため、再試行間隔ごとにしか `try_lock` を打てない別プロセス（CLI と supervisor）はその空き時間に当たりにくく、待ちが延びる。最悪は `STATE_LOCK_TIMEOUT`（5 秒）の `TIMEOUT` まで飢える。

## 計測方法

`crates/core/tests/state_store_lock_fairness.rs`（2 プロセスの競合試験。Linux 限定・root 不要）。

- 連続側（子プロセス。CLI 役）: 自分の ID に対し `get` + `update` を sleep なしで回し続ける
- 待ち側（親。supervisor 役）: 別の ID に対し `get` + `update` を 50ms 間隔で 20 回行い、1 回ごとの所要時間と `TIMEOUT` 件数を測る
- 実行: `cargo test -p fandhe-container-core --test state_store_lock_fairness -- --no-capture`
- 環境: Linux 7.0 の開発機、状態ルートは `/tmp` 配下（fsync が速い FS）。各条件 3 回実行

## 結果

待ち側の 1 操作（get + update）の所要時間と、連続側の成功件数（約 1 秒の運転）。

| 条件 | TIMEOUT | p50 | 最大 | 連続側の成功件数 |
| ---- | ------- | --- | ---- | ---------------- |
| 修正前（再試行 5ms） | 0 件 | 30〜36ms | 127〜203ms | 43206〜50497 |
| 間隔 10ms（再試行 5ms）で試した案 | 0 件 | 約 10ms | 約 20ms | 61 |
| 採用（再試行 1ms・間隔 2ms） | 0 件 | 約 2.2ms | 約 4ms | 249〜251 |

- 修正前は TIMEOUT に至らなかったが、待ちが最大 200ms 台まで延びることを再現した
- 連続側の件数が減るのは意図した動作で、ロックの空き時間を別プロセスに渡した結果である
- 間隔 10ms の案は、既存の同一 ID 競合試験（`sup1_task157_9_cli_and_supervisor_writes_to_same_id_are_serialized`）が成立しなかった。get から update までの窓が延び、もう一方のプロセスの更新が必ずその窓に入って revision 競合（`FAILED_PRECONDITION`）で再試行し続けたため

## 採用した対策

同じプロセスが `@lock` を最後に解放した時刻をプロセス全体の static に記録し、次の取得では解放から `LOCK_HANDOFF_GAP`（2ms）が経つまで眠ってから最初の `try_lock` を打つ。あわせて再試行間隔を 5ms から 1ms に下げ、待ち手が空き時間に少なくとも 1 回 `try_lock` を打てるようにした。

- 眠る時間は期限（`STATE_LOCK_TIMEOUT`）までの残りで頭打ちにする。期限・`TIMEOUT` の返し方は変えない（REPAIR-5）
- 費用は同じプロセスが続けてロックを取るときの 1 回あたり最大 2ms。1 回だけ操作する CLI コマンドには掛からない
- 保証の範囲: 1 つのプロセスが連続して取り直して他を締め出すことを防ぐ。複数の待ち手の間は FIFO にならない。各待ち手は自分の 1 操作が終われば抜けるため、無期限には飢えない

## 不採用にした案

- 補助スレッドでブロッキングの `File::lock()` を呼び `recv_timeout` で待つ: `lock()` のたびにスレッドを作り、supervisor 入口の制約（fork 前にスレッドを増やさない）と衝突する。期限切れで放置したスレッドが後でロックを取る副作用もある。Linux の `flock` は待ち手を FIFO で起こさないため公平性の保証にもならない
- `fcntl` の OFD ロックをタイマー・シグナルで打ち切る: `sys` への unsafe の追加とシグナル処理が要り、3 OS の単体テストも崩れる
- 待ち手が補助ロックファイルで待ちを知らせる: 状態ルートの配置と信頼境界の検査を広げ、毎回の操作に open と try_lock が増える

## 関連

- 同じ形の `lock_file_until` が `crates/oci/src/image_management/store.rs` にもある。本対応の範囲外
