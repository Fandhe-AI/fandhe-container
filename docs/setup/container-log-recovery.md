# 残ったコンテナログ・supervisor ログの見分け方と手動削除（SUP-7・CRI-2・CLI-1・REPAIR-4・REPAIR-5）

`delete` の後にコンテナログ（`<state_root>/@container-logs/<encoded-id>.log`・`.log.<n>`・`.log.lock`）が残ることがある。
supervisor が `terminate` の既定（5 秒）を超えて sink を閉じなかったときで、delete 自体は成功のまま終わる
（`docs/design/container-log-removal-wait.md`・#2698）。
supervisor の構造化ログ（`<state_root>/@supervisor-logs/<encoded-id>.log`・`.log.<n>`・`.log.lock`）も同様に残り得る（#2892・#2964）。
supervisor ログの扱いは末尾の「supervisor ログ」の節に分けて書く（#3034）。以降の「見分け方」「自動回収」「手動の手順」はコンテナログの記述である。

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

## supervisor ログ（`@supervisor-logs`。#3034・SUP-7・CRI-2・CLI-1・REPAIR-4）

### supervisor ログの見分け方

- CLI の `delete` が stderr に `"message":"supervisor log removal failed; leftover logs may remain"` の警告を出した。待ちを使い切っても古い supervisor がロックを持ち続けた場合は `"code":"FAILED_PRECONDITION","reason":"sink_open_after_wait"` が付く。`INTERNAL`・`RESOURCE_EXHAUSTED` など他の失敗には `reason` が付かない
- 期限切れは `"code":"TIMEOUT"` で、文言は `supervisor log removal did not finish within the deadline; leftover logs may remain`（コンテナログとは文言が違い、`reason` は付かない）
- plugin-cri の `{"event":"container_delete_cleanup","id":"<id>","target":"supervisor_log",...}` の行（待ち切れなかった場合は `"reason":"sink_open_after_wait"`）。`id` が対象のコンテナ ID。記録器の op 名 `supervisor_log_remove` の Failure も同じ意味である（コード別の op 名は無い。`container_log_remove.<code>` はコンテナログ専用）
- 置き場所は `<state_root>/@supervisor-logs/`（unix では 0700）。ファイル名と ID の符号化はコンテナログと同じで、1 ID あたり最大 `.log`・`.log.1`・`.log.2`・`.log.lock` の 4 ファイル（1 MiB × 3 世代 = 3 MiB 以内）

### supervisor ログの自動回収

自動では回収されない。同じ ID の次の `start` で世代として回るだけで、`create` 前の回収と plugin-cri の起動時の走査（`container_log_sweep`）は `@container-logs` だけを対象にする。`container_log_sweep` の件数に supervisor ログは含まれない。CRI は ID を使い回さないため、plugin-cri の残りは次の手順で手動で消す。

### supervisor ログの手動の手順

1. その ID の状態が無いことを確かめる（`fandhe-container list` に出ない。plugin-cri の場合は同じ `--root` を指定する）。状態がある ID（稼働中・再作成済み）のログは消さない
2. そのログのロックを持つプロセスが居ないことを確かめる（Linux・macOS は `lsof <state_root>/@supervisor-logs/<encoded-id>.log.lock`、Linux は `fuser` でも可）。supervisor はコンテナが生きている間ロックを持ち続けるため、居る場合はそのコンテナのログであり、消さずにプロセスが終わるのを待つ
3. 削除候補を先に確認する。対象は次の正確な名前だけで、`<encoded-id>.log*` のような glob は使わない（ID `a` の `a.log*` が別 ID `a.logger` のファイルにも一致するため）:
   - `<encoded-id>.log`
   - `<encoded-id>.log.lock`
   - `<encoded-id>.log.<n>`（`<n>` は数字だけの世代接尾辞）

   ```sh
   cd <state_root>/@supervisor-logs
   ls -1 | grep -E '^<encoded-id>\.log(\.lock|\.[0-9]+)?$'   # 候補の確認（<encoded-id> 中のドットは \. にする）
   ```

4. 候補が上の名前だけで、他の ID のファイルを含まないことを確かめてから、その名前を 1 つずつ `rm` で消す。ディレクトリ `@supervisor-logs` 自体は消さない（0700 のまま残す）。`rm -rf` は使わない。root での実行は不要（rootless の状態ルートは利用者の所有）
