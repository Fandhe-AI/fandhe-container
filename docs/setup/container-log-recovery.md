# 残ったコンテナログ・supervisor ログの見分け方と手動削除（SUP-7・CRI-2・CLI-1・REPAIR-4・REPAIR-5）

`delete` の後にコンテナログ（`<state_root>/@container-logs/<encoded-id>.log`・`.log.<n>`・`.log.lock`）が残ることがある。
supervisor が `terminate` の既定（5 秒）を超えて sink を閉じなかったときで、delete 自体は成功のまま終わる
（`docs/design/container-log-removal-wait.md`・#2698）。
supervisor の構造化ログ（`<state_root>/@supervisor-logs/<encoded-id>.log`・`.log.<n>`・`.log.lock`）も同様に残り得る（#2892・#2964）。
supervisor ログの扱いは末尾の「supervisor ログ」の節に分けて書く（#3034）。以降の「見分け方」「自動回収」「手動の手順」はコンテナログの記述である。plugin-cri の自動回収（起動時の走査と `CreateContainer` の前の回収）は、supervisor ログも同じ規則で対象にする（#4342）。

## 見分け方

- CLI の `delete` が stderr に `{"level":"warn","code":"FAILED_PRECONDITION"|"TIMEOUT",...,"message":"container log removal failed; leftover logs may remain"}` を出した。`FAILED_PRECONDITION` の行には `"reason":"sink_open_after_wait"` が付く（待ちを使い切っても古い supervisor が sink を閉じなかった。`TIMEOUT` など他の失敗には付かない）
- plugin-cri の `{"event":"container_delete_cleanup","target":"container_log",...}` の行（同じく待ち切れなかった場合は `"reason":"sink_open_after_wait"`）、行に `"existence":"unverified"` があれば、`delete` の期限を使い切って段を試しておらず、ファイルがあるかは確かめていない（手動で確かめてから消す。#3260）、または op 名 `container_log_remove.<code>` の Failure が計上された（`container_log_remove.failed_precondition` が「待ち切れなかった」）
- plugin-cri の起動時に `{"event":"container_log_sweep",...}` の 1 行が出る（supervisor ログの走査は別の `{"event":"supervisor_log_sweep",...}` の行で、件数は混ざらない。#4342）。`skipped_live`・`skipped_present`・`skipped_undecodable`・`failed` が 0 でなければ、その件数ぶんの残りが自動では消えていない
- ID の符号化の規則: 大文字 `X` は `_x`、`_` は `__`、Windows の予約名には先頭に `_0` が付く

## 自動回収

- CLI の `create`、plugin-cri の `CreateContainer` は、同じ ID の残りを core を呼ぶ前に消す（best effort。古い supervisor が生きていれば消さず、状態がある ID も消さない）。CLI の `create` が消すのはコンテナログだけで、plugin-cri の `CreateContainer` は supervisor ログも消す（#4342）
- plugin-cri は起動時に 1 回、`<state_root>/@container-logs` を走査し、状態の記録が無く、sink も生きていない ID のログを消す（#2760）。
  CRI は ID を使い回さないため、delete の待ちを超えて残ったログは plugin-cri を再起動すれば消える
- shim v2 の serve は起動時に 1 回、scoped 状態ルート（`<base>-shim-state/...`）の `@container-logs`、続けて `@supervisor-logs` を同じ規則で走査する（期限 30 秒は共有で、supervisor ログは残り時間。裏の thread。#4280・#4343）。要約は `container_log_sweep` と `supervisor_log_sweep` の 2 種の行で、`daemon.log` に出る
- plugin-cri の `create` / `delete` は、状態の記録が無い ID の起動オプション文書（`<state_root>/@container-options/<id>`）の残骸も消す

自動では消えないもの（次の「手動の手順」の対象）:

- 古い supervisor が生きていて sink のロックを持ち続けているログ（`skipped_live`）
- 状態がある ID のログ（`skipped_present`）。この ID は消さない
- ID に戻せない名前（`skipped_undecodable`。大文字入りなど、sink が作らない名前）
- shim v2（`<base>-shim-state/...`）の状態ルートの残り。containerd が同じ ID で delete を呼び直したときは、記録の無い ID の残骸 3 種（supervisor ログ・コンテナログ・起動オプション文書）が自動で回収される（`docs/design/shim-v2-production-binary.md` の D7・#4279）。コンテナログと supervisor ログは shim の serve の起動時の走査でも回収される（#4280・#4343）。呼び直しが無い場合の起動オプション文書（serve の起動時の走査の対象外。同じ ID の Create の前の回収には入っている）、sink が生きていた場合、ロックつきの操作が一度も無い状態ルートの残りは手動で消す
- plugin-cri が動いている間に発生した残り（次の起動まで）と、plugin-cri と異なる `--root` の状態ルート

## 手動の手順

1. その ID の状態が無いことを確かめる（`fandhe-container list` に出ない）。状態がある ID のログは消さない
2. そのログのロックを持つプロセス（古い supervisor）が居ないことを確かめる（Linux・macOS は `lsof <state_root>/@container-logs/<encoded-id>.log.lock`、Linux は `fuser` でも可）。居る場合はそのプロセスが終わるのを待つ。非特権の `lsof` / `fuser` が何も出さなくても「居ない」とは限らない（supervisor は `PR_SET_DUMPABLE=0` のため）。観測できないときの扱いは、末尾の「supervisor ログの手動の手順」の手順 2（非ブロッキングの排他確認。取れなければ中止）と同じにする
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
- plugin-cri の `{"event":"container_delete_cleanup","id":"<id>","target":"supervisor_log",...}` の行（待ち切れなかった場合は `"reason":"sink_open_after_wait"`）。行に `"existence":"unverified"` があれば、期限を使い切って段を試しておらず、ファイルの有無は未確認（#3260）。`id` が対象のコンテナ ID。記録器の op 名 `supervisor_log_remove` の Failure も同じ意味である（コード別の op 名は無い。`container_log_remove.<code>` はコンテナログ専用）
- 置き場所は `<state_root>/@supervisor-logs/`（unix では 0700）。ファイル名と ID の符号化はコンテナログと同じで、1 ID あたり最大 `.log`・`.log.1`・`.log.2`・`.log.lock` の 4 ファイル（1 MiB × 3 世代 = 3 MiB 以内）

### supervisor ログの自動回収

plugin-cri は次の 2 経路で回収する（#4342・#4296）。いずれも guard は「状態の記録が無い」かつ「sink の flock が外れている」で、生きている supervisor のログと状態がある ID のログには触れない。

- 起動時の走査: plugin-cri は起動時に 1 回、コンテナログの走査の後に `<state_root>/@supervisor-logs` を走査する。期限（30 秒）はコンテナログの走査と共有し、supervisor ログは残りの時間を使う。要約は `{"event":"supervisor_log_sweep",...}` の 1 行で、件数だけを出す。消せた ID ごとに op 名 `supervisor_log_reclaim` の Success が計上される
- `CreateContainer` の前の回収: 同じ ID の閉じた supervisor ログを core を呼ぶ前に、待たずに 1 回だけ（上限 5 秒）消す。失敗（sink が生きている等）は op 名 `supervisor_log_reclaim` の Failure で、create は続く。期限切れのときは core を呼ばず `TIMEOUT` で create を失敗させる

自動では消えないものは手動のままとする: 生きている sink・状態がある ID・帰属できない名前、plugin-cri の稼働中に出た残り（次の起動まで）、plugin-cri と異なる `--root` の状態ルート、ロックつきの操作が一度も無い状態ルートの残り。CLI の `create` は supervisor ログを自動では回収しない（shim v2 の serve の起動時の走査は回収する。#4343）。同じ ID の次の `start` では世代として回るだけである。手動の手順は次のとおり。

### supervisor ログの手動の手順

1. その ID の状態が無いことを確かめる（`fandhe-container list` に出ない。plugin-cri の場合は同じ `--root` を指定する）。状態がある ID（稼働中・再作成済み）のログは消さない
2. そのログのロックを持つプロセスが居ないことを確かめる。**非特権の `lsof` / `fuser` が何も表示しないことを「持ち主が居ない」の根拠にしない**。Linux の supervisor は `PR_SET_DUMPABLE=0` で動くため、同じ UID の非特権ユーザーでも `/proc/<pid>/fd` を読めず、持ち主が居ても `lsof` / `fuser` に出ないことがある。次の順で進める:
   1. 観測できる場合（Linux・macOS は `lsof <state_root>/@supervisor-logs/<encoded-id>.log.lock`、Linux は `fuser` でも可。root なら持ち主を観測できる）に持ち主が出たら、消さずにそのプロセスが終わるのを待つ。supervisor はコンテナが生きている間ロックを持ち続けるため、居る場合はそのコンテナのログである
   2. 何も出ない場合も「居ない」と結論しない。まず同じ ID の再作成と `start`（CLI の `create`・`start`、plugin-cri の `CreateContainer`・`StartContainer`）を止める。そのうえで、ロックが `flock(2)` であることを前提に、非ブロッキングで排他を取れるかを確かめる（Linux: `flock -n <state_root>/@supervisor-logs/<encoded-id>.log.lock -c true`。成功〔終了コード 0〕なら誰も保持していない。`flock` が無い環境ではこの確認ができない）
   3. 排他が取れない（終了コード 1）、または観測も排他の確認もできない場合は、持ち主が居る扱いにして手順を中止する。何も削除しない。プロセスが終わるのを待つか、観測できる権限で持ち主を確かめてからやり直す

3. 削除候補を先に確認する。対象は次の正確な名前だけで、`<encoded-id>.log*` のような glob は使わない（ID `a` の `a.log*` が別 ID `a.logger` のファイルにも一致するため）:
   - `<encoded-id>.log`
   - `<encoded-id>.log.lock`
   - `<encoded-id>.log.<n>`（`<n>` は数字だけの世代接尾辞）

   ```sh
   cd <state_root>/@supervisor-logs
   ls -1 | grep -E '^<encoded-id>\.log(\.lock|\.[0-9]+)?$'   # 候補の確認（<encoded-id> 中のドットは \. にする）
   ```

4. 候補が上の名前だけで、他の ID のファイルを含まないことを確かめてから、その名前を 1 つずつ `rm` で消す。ディレクトリ `@supervisor-logs` 自体は消さない（0700 のまま残す）。`rm -rf` は使わない。削除に root は要らない（rootless の状態ルートは利用者の所有）。ただし持ち主の観測には権限が要り得るため、削除の権限と観測の権限は別に考える（手順 2 の確認が済んでいない限り削除しない）
