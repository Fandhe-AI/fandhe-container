# 残ったコンテナログの見分け方と手動削除（SUP-7・CLI-1・REPAIR-4・REPAIR-5）

`delete` の後にコンテナログ（`<state_root>/@container-logs/<encoded-id>.log`・`.log.<n>`・`.log.lock`）が残ることがある。
supervisor が `terminate` の既定（5 秒）を超えて sink を閉じなかったときで、delete 自体は成功のまま終わる
（`docs/design/container-log-removal-wait.md`・#2698）。

## 見分け方

- CLI の `delete` が stderr に `{"level":"warn","code":"FAILED_PRECONDITION"|"TIMEOUT",...,"message":"container log removal failed; leftover logs may remain"}` を出した
- plugin-cri の `container_delete_cleanup` の行、または op 名 `container_log_remove.<code>` の Failure が計上された
- ID の符号化の規則: 大文字 `X` は `_x`、`_` は `__`、Windows の予約名には先頭に `_0` が付く

## 自動回収

同じ ID で CLI の `create` を実行すると、core を呼ぶ前に残りを消す（best effort。古い supervisor が生きていれば消さない）。
ID を再利用しない場合（plugin-cri の CRI など）は自動では回収されない。

## 手動の手順

1. その ID の状態が無いことを確かめる（`fandhe-container list` に出ない）。状態がある ID のログは消さない
2. そのログのロックを持つプロセス（古い supervisor）が居ないことを確かめる（Linux・macOS は `lsof <state_root>/@container-logs/<encoded-id>.log.lock`、Linux は `fuser` でも可）。居る場合はそのプロセスが終わるのを待つ
3. その ID のファイル（`<encoded-id>.log*`）だけを `rm` で消す。他の ID のファイルには触れない
