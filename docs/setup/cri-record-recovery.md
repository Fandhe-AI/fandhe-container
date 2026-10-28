# 照合できない CRI 記録の見分け方と手動回収（CRI-1・CRI-2・REPAIR-4・REPAIR-5）

plugin-cri は再起動をまたいで sandbox とコンテナの記録を残し、起動時に 1 回だけ再採用する
（設計は `docs/design/cri-record-readoption.md`・#2902）。壊れた記録は消さず、登録もせず、件数だけを出す（REPAIR-4）。
件数には ID もパスも出ないため、運用者がファイルを突き止めて手で回収する。この文書はその手順である。

記録の置き場（`<state_root>` は plugin-cri の既定の状態ルート）:

- `<state_root>/.cri/records/sandboxes/<id>.rec`・`<state_root>/.cri/records/containers/<id>.rec`（`<id>` は 64 文字の小文字 16 進）
- 排他用の `<state_root>/.cri/records/.lock` と、書き込み途中の一時ファイル `.tmp-<pid>-<連番>`（各ディレクトリ内）
- plugin-cri の二重起動を防ぐ `<state_root>/.cri/@instance.lock`

CLI を使う手順では plugin-cri と同じ状態ルートを指すこと（`--root` を使うなら同じ値にする）。手順はすべて状態ルートの所有者の権限で行い、root は要らない。

## 見分け方

1. 起動時の要約行（stderr。JSON ではなく 1 行のテキスト）。何かを再採用・回収したときだけ出る。次の 4 段を ` | ` でつないだ 1 行になる:

   ```text
   cri record readoption: kind=sandbox adopted= pending_unresolved= broken= malformed= not_regular_file= too_long= unreadable= unrecognized= duplicate_metadata=
   cri record readoption: kind=container adopted= present= absent_exited= remove_pending= undetermined= stale_create= broken= malformed= not_regular_file= too_long= unreadable= unrecognized= duplicate_metadata= parentless=
   cri stale create release: released= kept= release_failed= record_remove_failed= not_attempted= skipped=
   cri orphan bundle reclamation: scan=<completed|list_failed:<CODE>|timed_out> scanned= reclaimed= kept_has_record= kept_present= kept_undetermined= release_failed= release_timed_out= skipped_unrecognized= skipped_not_dir= not_attempted=
   ```

   `broken` が 0 でなければ照合できない記録が残っている。内訳:

   | キー | 意味 |
   | ---- | ---- |
   | `malformed` | 復号に失敗した（版の行・鍵の順・config の不正、ファイル名と `id=` の不一致を含む） |
   | `not_regular_file` | 通常ファイルでない（symlink・ディレクトリ・FIFO など。辿らない） |
   | `too_long` | 1 件の上限（config の 512 KiB にヘッダ分を足した値）を超えた |
   | `unreadable` | 権限・I/O エラーで読めない |
   | `unrecognized` | `.rec` で終わるが名前が ID の形でない（非 UTF-8 の名前を含む） |
   | `duplicate_metadata` | name・namespace・uid・attempt が重複した。ID の小さい方だけを採る |
   | `parentless` | コンテナ記録の所属 sandbox が再採用されていない |

2. 記録器: 60 秒ごとに `{"event":"op_stats","op":"cri.record_store_load","success":…,"failure":…,…}` が出る。
   `success` は採用の件数（コンテナの `stale_create` を含む）、`failure` は壊れた記録の件数。内訳の区分は出ない。
   記録ストアの操作の失敗は `cri.record_store.put`・`cri.record_store.remove`・`cri.record_store.list` の failure に出る。
   どれも ID を持たないので、要約行と突き合わせる材料にとどめる
3. 起動しない場合は `error: <CODE>: failed to readopt cri records` を出して exit 1 になる:
   - `FAILED_PRECONDITION`: 件数・保持量の上限を超えた（sandbox は 1024 件、コンテナは 4096 件。走査数には `.tmp-*`・`.lock`・壊れた記録も数える）
   - `DEADLINE_EXCEEDED`: ロック 5 秒、1 件 10 秒、列挙 60 秒、全体 120 秒のいずれかの期限切れ
   - `INTERNAL`: 列挙の I/O エラー、または `.lock` が通常ファイルでない
   - `error: <CODE>: failed to prepare the record store`: 置き場の権限・所有者・symlink の不備。ファイルは消されない。状態ルートと `.cri` 配下を所有者のみ 0700（group / other の権限なし）に直す
   - `state root is in use by another cri plugin instance`: 別の plugin-cri が `@instance.lock` を持っている。記録の問題ではない

### どのファイルかを突き止める

要約行は件数だけなので、手で照合する。記録の config 部（labels・annotations・mounts など）は表示も貼り付けもしない。

- 名前: `ls -1Ab` で列挙し、`^[0-9a-f]{64}\.rec$` に合わないもの（`.lock` と `.tmp-*` を除く）が `unrecognized`
- 種類: `ls -l` または `stat` で symlink・ディレクトリなどを見る（`not_regular_file`）。辿らない
- 大きさ: config の上限 512 KiB にヘッダ分を足した値を超えると `too_long`
- 先頭の行: 通常ファイルで symlink でないと確認した記録だけを、バイト数の上限と時間の上限をつけて読む（`head -n` のような行数だけの制限は使わない。ヘッダの改行が欠けた記録では config 部が出てしまう）。形式検証に通った行だけを表示し、不正な行の内容は出さない:

  ```sh
  [ -f <名前> ] && [ ! -L <名前> ] && timeout 5 head -c 256 -- <名前> \
    | LC_ALL=C grep -a -x -m 3 -E 'fandhe-cri-(sandbox|container)-record v1|id=[0-9a-f]{64}|pod_sandbox_id=[0-9a-f]{64}'
  ```

  何も出ない、または 1 行目の版・2 行目の `id=` が揃わない記録はヘッダ不正として扱い、内容は表示しない。見るのは、1 行目が `fandhe-cri-sandbox-record v1` または `fandhe-cri-container-record v1` か、`id=` がファイル名と一致するか、コンテナの `pod_sandbox_id=` の sandbox に `sandboxes/<その ID>.rec` があるか（無い、または壊れていれば `parentless`）。通常ファイル以外（FIFO・symlink・ディレクトリ）は開かない
- 再採用の有無: plugin-cri が動いている間の `crictl pods -q --no-trunc` と `crictl ps -a -q --no-trunc` の ID を控え、どちらにも出ない `.rec` を候補にする
- ヘッダが正しく config 部だけが壊れた `malformed` は手では判定できない。上の条件の消去法で候補とし、既定では残す

## 自動回収

起動時に、受付の前に次の順で 1 回だけ行う（常駐ループは無い）: sandbox の再採用 → コンテナの再採用 → `stale_create` の解放 → 孤児 bundle の回収。

- `stale_create`（`in_flight=create` で core が Absent のもの）: core が `NOT_FOUND` のときだけ、bundle の解放 → 記録の削除の順に行う。失敗（`release_failed`・`record_remove_failed`）は次の起動で再び試みる。手で消さず、まず plugin-cri を再起動する
- 孤児 bundle（`.cri/bundles/<id>` で記録が無く、core が Absent のもの）は回収される。記録がある ID は、壊れていても所有の証明として残る（`kept_has_record`）。壊れた記録を手で消した後に再起動すれば、bundle は自動で回収される。bundle は手で消さない
- 再採用したコンテナで core が Absent のもの（`absent_exited`）は、kubelet の RemoveContainer / RemovePodSandbox が記録と bundle を消す

自動では消えないもの（次の「手動の手順」の対象）:

- `broken` の内訳のすべて（`malformed`・`not_regular_file`・`too_long`・`unreadable`・`unrecognized`・`duplicate_metadata`・`parentless`）
- `.tmp-<pid>-<連番>`。`.rec` 以外は読み飛ばされるので件数には出ないが、走査数の上限は消費する

対象外: `pending_unresolved` の sandbox のネットワーク資源と保持役の素性は #2940・#2941 と `docs/setup/network-reclaim-recovery.md` を参照する。現在の本番は `PodNetworkProvider` を注入していないので該当しない。

## 消してはいけないもの

- `.cri/records/.lock` と `.cri/@instance.lock`（どちらも unlink しない設計）
- core に状態がある（`fandhe-container state <id>` が成功する）、または判定できない ID のコンテナ記録。消すと動いているコンテナが CRI から見えなくなる。停止・削除するかは運用者が判断し、状態が無くなってから手順の対象にする
- `crictl` に出ている（再採用された）記録
- `stale_create` で `release_failed`・`record_remove_failed` の記録（まず再起動で再試行する）
- `.cri/bundles/<id>` と core の `<state_root>/<id>/`

## 手動の手順

削除の対象は正確な名前だけで、`rm` に glob（`*`・`?`・`[`）は使わない。下の `grep -E` の正規表現は一覧の絞り込み用で、削除の対象指定ではない。

1. plugin-cri が動いている間に、`crictl pods -q --no-trunc` と `crictl ps -a -q --no-trunc` の ID を控える。起動できない場合は控えを飛ばし、名前・種類・ヘッダの検査だけで候補を作る。その場合、消すのは明らかに壊れたものと `.tmp-*` に限る
2. 候補を作る:

   ```sh
   cd <state_root>/.cri/records/sandboxes     # containers も同じ
   ls -1Ab
   ls -1Ab | grep -v -E '^[0-9a-f]{64}\.rec$'   # 名前が ID の形でないもの（.lock と .tmp-* は除いて読む）
   ```

3. コンテナ記録の候補ごとに、core の状態が無いことを確かめる。`fandhe-container state <id>` が NOT_FOUND で失敗し、`fandhe-container list` にも出ないこと
4. sandbox 記録の候補ごとに、`containers/` の記録がその sandbox を参照していないことを確かめる:

   ```sh
   [ -f <containers 内の名前> ] && [ ! -L <containers 内の名前> ] \
     && timeout 5 head -c 256 -- <containers 内の名前> | grep -a -x -q "pod_sandbox_id=<id>"
   ```

   通常ファイルかつ symlink でないものだけを、有限時間で検査する（実装の列挙も通常ファイル以外を読まずに分類しているので、手動もこの除外条件を揃える。FIFO は open で待ち続け、symlink は参照先を読むため渡さない）。`not_regular_file` など検査できない記録が `containers/` に残る間は「参照なし」と判断せず、その sandbox 記録の削除を保留する（先にその記録を 6 の手順で片付けてから確かめ直す）。
   参照する記録があればそちらを先に処理する（`parentless` のコンテナ記録 → sandbox 記録の順）。`duplicate_metadata` は ID の大きい方が残っているので、core が Absent の場合に限って対象にする
5. plugin-cri を止め、`<state_root>/.cri/@instance.lock` を持つプロセスが居ないことを確かめる（`lsof <state_root>/.cri/@instance.lock`。Linux は `fuser` でも可）。`.tmp-*` は名前の pid だけで判定しない（pid は再利用される）
6. 候補を正確な名前でもう一度確かめ（`ls -1Ab -- <名前>`）、1 件ずつ消す:

   ```sh
   rm -- <名前>
   ```

   symlink はリンクそのものが消え、辿らない。ディレクトリは中身を確認し、空なら `rmdir -- <名前>`、空でなければ消さずに調べる。`rm -r` は使わない。`unreadable` は先に所有者と権限（0600・状態ルートの所有者）を確かめ、一過性の I/O エラーの可能性もあるので再起動で再現するかを見てから消す
7. plugin-cri を起動し、要約行が `broken=0` になる（または行が出ない）こと、孤児 bundle の `kept_has_record` が減って `reclaimed` が増えることを確かめる
