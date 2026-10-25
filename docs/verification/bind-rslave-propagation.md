# rslave の bind の伝播の実機確認 手順書と結果記録（#2669）

`mounts[]` の bind の `rslave`（CRI の HostToContainer）で、ホスト側で後からマウントした内容がコンテナ内に見えることと、ホスト側の元が private のときに起動が拒否されることを実機で確かめる手順と、結果記録の雛形。対応する ID は OCI-4・CRI-2・SEC-1・TASK-29 追補、REPAIR-3・REPAIR-12。設計は `docs/design/mount-propagation.md`、受けるオプションは `docs/api/bind-mounts.md`。

実行・結果の記録・成否の判定は人間が行う。ホスト側のマウントに root（sudo）が要るため Agent は実行しない。本書のコマンドは作成時に未実行である。CI の `production_launcher` のシナリオ U は、コンテナ内で bind 先が slave であり shared でないことと、ホスト側が private のときの拒否だけを照合する（伝播そのものは確かめない）。

## 事前確認

ホスト名・アドレス・ユーザー名は記録しない。

- Linux 6.12 以上・非特権 user namespace を許可・委譲された cgroup v2（`tests/production_launcher.rs` と同じ前提）
- ホスト側の元ディレクトリを、自分で作る専用の場所にする（例: `/srv/rslave-src`）。他の用途のマウントを巻き込まない

## 手順

1. 元をホスト側で shared にする（root）

   ```bash
   sudo mkdir -p /srv/rslave-src
   sudo mount --bind /srv/rslave-src /srv/rslave-src
   sudo mount --make-rshared /srv/rslave-src
   findmnt -no PROPAGATION /srv/rslave-src   # shared
   ```

2. `config.json` の `mounts[]` に `{"destination":"/data","type":"bind","source":"/srv/rslave-src","options":["rbind","rslave","rw"]}` を書いた bundle を作り、`create` → `start` する。コンテナ内のプロセスは `/data` を数秒ごとに一覧する（例: `ls -R /data` を繰り返す entrypoint）
3. コンテナ内の mountinfo で `/data` の行に `master:N` があり、`shared:N` が無いことを確かめる
4. ホスト側で元の下に後からマウントする（root）

   ```bash
   sudo mkdir /srv/rslave-src/sub
   sudo mount -t tmpfs tmpfs /srv/rslave-src/sub
   echo from-host | sudo tee /srv/rslave-src/sub/marker
   ```

5. コンテナ内から `/data/sub/marker` の内容 `from-host` が読めることを確かめる（伝播した）。`ro` の bind に変えた場合は書けないこと、`nosuid`・`nodev` が伝播した側にも付くとは限らないこと（残余。`docs/design/mount-propagation.md`）も記録する
6. 逆方向: コンテナ内からのマウントはできない（`CAP_SYS_ADMIN` なし・seccomp）ため、ホストへ伝播しないことは構造的に保たれる。ホスト側に `/srv/rslave-src/sub` 以外の新しいマウントが現れていないこと（`findmnt -R /srv/rslave-src`）を確かめる
7. 手順 2 のコンテナを `terminate` → `delete` で終わらせ、rootfs を作り直す（手順 2 の起動で bind 先 `data` が rootfs に作られているため、使い回さない）。`sudo umount /srv/rslave-src/sub` で手順 4 のマウントを外し、`data` のない新しい rootfs で同じ内容の `config.json` から Created 状態の新しいコンテナを `create` する（`start` 済みのコンテナを再 `start` すると Created 状態の検査で `container is not in created state` となり、以下の拒否の検査に到達しない）
8. ホスト側の元が private のときの拒否: `sudo mount --make-rprivate /srv/rslave-src` の後に、手順 7 で作った新しいコンテナを `start` し、`FAILED_PRECONDITION`（メッセージに `not a shared or slave mount on the host`）で失敗し、状態が Created のまま、子が残らず、rootfs に `data` が作られていないことを確かめる
9. 後始末（root）: コンテナを `terminate` → `delete`、`sudo umount /srv/rslave-src; rmdir` で戻す

## 結果記録（雛形）

| 項目 | 期待 | 結果 |
| ---- | ---- | ---- |
| 実行日・カーネル版・ディストリビューション | 未記入 | 未記入 |
| 手順 3: コンテナ内の `/data` の optional fields | `master:N` あり・`shared:` なし | 未記入 |
| 手順 5: `/data/sub/marker` の内容 | `from-host` | 未記入 |
| 手順 6: ホスト側の新しいマウント | `sub` のみ | 未記入 |
| 手順 8: ホスト側が private のときの `start` | `FAILED_PRECONDITION`・Created のまま・子なし・`data` なし | 未記入 |
| 備考（残余の観測） | 未記入 | 未記入 |
