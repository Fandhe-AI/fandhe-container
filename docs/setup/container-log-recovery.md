# 残ったコンテナログの見分け方と手動削除（SUP-7・CLI-1・REPAIR-4・REPAIR-5）

`delete` の後にコンテナログ（`<state_root>/@container-logs/<encoded-id>.log`・`.log.<n>`・`.log.lock`）が残ることがある。
supervisor が `terminate` の既定（5 秒）を超えて sink を閉じなかったときで、delete 自体は成功のまま終わる
（`docs/design/container-log-removal-wait.md`・#2698）。

## 見分け方

- CLI の `delete` が stderr に `{"level":"warn","code":"FAILED_PRECONDITION"|"TIMEOUT",...,"message":"container log removal failed; leftover logs may remain"}` を出した。`FAILED_PRECONDITION` の行には `"reason":"sink_open_after_wait"` が付く（待ちを使い切っても古い supervisor が sink を閉じなかった。`TIMEOUT` など他の失敗には付かない）
- plugin-cri の `{"event":"container_delete_cleanup","target":"container_log",...}` の行（同じく待ち切れなかった場合は `"reason":"sink_open_after_wait"`）、または op 名 `container_log_remove.<code>` の Failure が計上された（`container_log_remove.failed_precondition` が「待ち切れなかった」）
- plugin-cri の起動時に `{"event":"container_log_sweep",...}` の 1 行が出る。`skipped_live`・`skipped_present`・`skipped_undecodable`・`failed` が 0 でなければ、その件数ぶんの残りが自動では消えていない
- ID の符号化の規則: 大文字 `X` は `_x`、`_` は `__`、Windows の予約名には先頭に `_0` が付く

## 自動回収

- CLI の `create`、plugin-cri の `CreateContainer` は、同じ ID の残りを core を呼ぶ前に消す（best effort。古い supervisor が生きていれば消さず、状態がある ID も消さない）
- plugin-cri は起動時に 1 回、`<state_root>/@container-logs` を走査し、状態の記録が無く、sink も生きていない ID のログを消す（#2760）。
  CRI は ID を使い回さないため、delete の待ちを超えて残ったログは plugin-cri を再起動すれば消える
- plugin-cri の `create` / `delete` は、状態の記録が無い ID の起動オプション文書（`<state_root>/@container-options/<id>`）の残骸も消す

自動では消えないもの（次の「手動の手順」の対象）:

- 古い supervisor が生きていて sink のロックを持ち続けているログ（`skipped_live`）
- 状態がある ID のログ（`skipped_present`）。この ID は消さない
- ID に戻せない名前（`skipped_undecodable`。大文字入りなど、sink が作らない名前）
- plugin-cri が動いている間に発生した残り（次の起動まで）と、plugin-cri と異なる `--root` の状態ルート

## 手動の手順

1. その ID の状態が無いことを確かめる（`fandhe-container list` に出ない）。状態がある ID のログは消さない
2. そのログのロックを持つプロセス（古い supervisor）が居ないことを確かめる（Linux・macOS は `lsof <state_root>/@container-logs/<encoded-id>.log.lock`、Linux は `fuser` でも可）。居る場合はそのプロセスが終わるのを待つ
3. 削除候補を先に確認する。対象は次の正確な名前だけで、`<encoded-id>.log*` のような glob は使わない（ID はドットを含み得るため、ID `a` の `a.log*` が別 ID `a.logger` の `a.logger.log` やロックにも一致する）:
   - `<encoded-id>.log`
   - `<encoded-id>.log.lock`
   - `<encoded-id>.log.<n>`（`<n>` は数字だけの世代接尾辞）

   ```sh
   cd <state_root>/@container-logs
   ls -1 | grep -E '^<encoded-id>\.log(\.lock|\.[0-9]+)?$'   # 候補の確認（<encoded-id> 中のドットは \. にする）
   ```

4. 候補が上の名前だけで、他の ID のファイルを含まないことを確かめてから、その名前を 1 つずつ `rm` で消す。他の ID のファイルには触れない
