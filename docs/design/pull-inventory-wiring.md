# pull の結果を ImageStore の在庫へ登録する配線（#2539・OCI-1・OCI-7・CRI-3・TASK-183 追補）

## 目的と結論

PR #2520（#2380）で manifest の在庫・タグ・pull リースを `@image-inventory.json` へ永続化したが、本番で在庫を埋める経路が
無かった。このため `image ls` はヘッダだけ、`image rm` / `image tag` / `create --image` は `NOT_FOUND` だった。
本変更で、cri の `OciImagePuller::pull`（`PullImage` が呼ぶ唯一の pull 実装）が oci の `ImageStore` / `PullSession` を通すようにした。

| 決定 | 内容 |
| ---- | ---- |
| 入口 | cri の `OciImagePuller::pull` の 1 か所。`PullConfig::cache_dir` は `ImageStore` の root と同一 |
| CLI の `pull` サブコマンド | 足さない。cli → cri の通常依存（tonic / prost を CLI に持ち込む）か、pull 手順の oci への移設が要り、crate 境界の判断になるため。同じ root を `--image-root` に渡せば CLI の `image ls` / `create --image` から見える |
| 本番の到達 | plugin-cri の ImageService（#2592）待ち。それまで本番の呼び出し元は無い（実装済みを装わない。REPAIR-3） |

## 手順と順序

1. `blobs/sha256` を 0700 で用意し（既存の祖先検証）、`ImageStore::open` → `begin_pull_generated`（`staging/<id>` と `@pull.lock`）
2. blob ごとに、既存ならリース登録 → 信頼条件・digest の検査（合格で再利用、不合格はリース解放して取得）。無ければ
   `staged_blob_path` へ取得し `verify_staged_blob`（サイズは宣言値と完全一致）
3. config を読み、layer を `staging/<id>/unpack/entry/rootfs` へ展開（diff_id 突合）
4. rootfs のエントリを `rootfs/sha256/<config-hex>` へ rename（記録と一緒に原子的）
5. `publish`（blob の公開・manifest とタグの登録・リース解放を排他の下で 1 回の保存）

- 4 を 5 の前にする理由: rootfs は config digest をキーにした冪等なキャッシュで GC に未接続のため、5 が失敗して rootfs だけが
  残っても「余分に残す」側で無害。逆順だと「在庫には載ったが pull は失敗」と返しうる
- タグ参照のときだけタグを付ける。在庫のキーは選択された platform manifest の digest（index の digest ではない）
- cri は `staging/<id>` を消さない。消すのは `abort` / `publish` / 回収 GC（`recover_stale_pulls`）だけ。cri が消すのは自分の
  作業領域 `unpack/` の子だけ（`remove_extracted_tree`。0555 を含む木も消せる）
- 失敗経路は必ず `abort` を通す。panic で抜けた場合は `@pull.lock` が外れ、回収 GC の対象になる

## 孤児リース（PR #2520 の既知の残り）

`staging/<id>` が無いのに永続化されたリースは、この配線が自分の操作では作らない。

- リースの永続化は、`begin_pull` が排他の中で `staging/<id>` と `@pull.lock` を作った後にしか起きない
- 解放は「永続化 → staging の削除」の順（`publish` / `abort` / `recover_stale_pulls`）
- cri は `staging/<id>` を消さない（旧 `StagingDir` の `Drop` による削除は廃止）
- 電源断の窓: 従来は `staging/<id>` の作成後に `staging` と root を fsync していなかったため、リース永続化後の電源断で
  エントリだけが失われうる状態だった。`begin_pull` が `@pull.lock` 作成後・セッションを返す前に `staging` と root を fsync するようにして塞いだ
  （fsync の失敗は作成直後の pull ディレクトリを消して `Internal`）
- 外部から `staging/<id>` を消された場合は不在を確認できず、OCI-7 の「確認できない場合は保持する」に従って解放しない。回復手順はストアの作り直し

## subuid / subgid のずれ（#2528 の事後監査 P3）

展開時の所有者写像の記録（`unpack-record`）で検出する方針。pull と create は同じ `ImageExtractConfig` から値を受け、食い違えば
`FAILED_PRECONDITION`。start 時の写像との照合は、`ChownMapped` 等の本番配線時に足す。本番の値が `Keep` + `Strip` の間は写像が空で
検出は効かない。詳細は [oci-layer-special-bits.md](oci-layer-special-bits.md) の末尾。

## 動作の変更点

- 公開済みの宛先が symlink・FIFO 等の通常ファイルでないとき、oci の `publish` は拒否せず検証済みの実体で名前を差し替える
  （従来の cri の公開と同じ。symlink の先には書き込まない。ディレクトリは `FailedPrecondition`）
- `OciImagePuller::with_recorder` の記録先は、展開に加えて `ImageStore` の操作（開始・リース・検証・公開・中止）も受ける

## スコープ外（追跡）

- CLI の `pull` サブコマンド（crate 境界の判断。起票の要否はオーナー確認）
- plugin-cri の ImageService と本番の `PullConfig`（#2592）、`InMemoryImageStore` の置き換え（TASK-183）
- #2377（本番の `ImageRootfsUnpacker`）には、在庫に layer の mediaType・`diff_ids` が要る。`@image-inventory.json` のスキーマは広げていない
- 展開済み `rootfs/sha256/<hex>` の GC と `image rm` / `prune` への接続、起動時の `recover_stale_pulls` の配線（#2315）
