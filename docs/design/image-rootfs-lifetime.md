# イメージ由来 rootfs の寿命と delete の扱い

`create_with_image` が core 自身で作って公開した rootfs について、所有者・消すタイミング・失敗時の扱いを決める記録（#2378・OCI-7・OCI-5・OCI-6・SEC-1・REPAIR-3 / 4 / 5）。実装は `crates/core`（`oci_runtime::delete`・`oci_runtime::image_rootfs`・`StateRecord::image_rootfs`）。

## 背景

PR #2353（#2342）で、展開器（`ImageRootfsUnpacker`）つきの `create_with_image` は core が bundle 配下に rootfs を作って展開・公開するようになった。一方 `delete` は bundle も rootfs も消さなかったため、core が作った rootfs が残り続け、同じ bundle での再度の `create_with_image` が `AlreadyExists` で止まっていた。

spec では、OCI-6 の delete が消すのは状態ファイルと cgroup、OCI-7 では参照の解除だけが定められており、rootfs の寿命はどちらにも書かれていない。本書は core の実装上の決定であり、spec（OCI-6 / OCI-7）へ追記するかどうかは spec リポ側の判断事項とする。

## 決定

| 論点 | 決定 |
| ---- | ---- |
| 所有者 | 展開器つきの `create_with_image` が作って公開した rootfs だけを core が所有する。所有の印は状態レコードの `imageRootfs`（bundle 相対の経路と作成時の実体の dev・ino。`ImageRootfsRecord`）。利用者が用意した rootfs（通常の `create`・展開器なしの `create_with_image`）は利用者のもので、core は消さない（runc と同じ） |
| 消すタイミング | `delete`（`delete_releasing_image_ref` から呼ばれる場合も含む）の中で、`StateStore::delete` が成功した後に消す。使うのは関数の先頭で読んだレコード（実際に消した revision のもの）に付いた記録 |
| 状態削除の後にする理由 | start は `BundleLock` と revision の予約より前に rootfs の fd を固定する。状態削除の前に消す順だと、Created のコンテナで start が rootfs を固定し、delete が消し、start が予約し、delete の状態削除が `FailedPrecondition` になる窓が残る。状態の削除が成功した後なら、そのコンテナへの start・restart（supervisor）・update は revision 照合つきの `StateStore::update` で `NotFound` になるので、使用中の rootfs を消す窓が無い（supervisor の更新も `UpdateStateRequest::new(status, expected_revision)` を経る） |
| 消し方（fail-closed） | 記録した bundle を開き（bundle 自体は作成時と同じく追従する）、中間要素はリンク非追従の fd 相対で辿り、末尾もリンク非追従で開く。`fstat` の (dev, ino) が記録と一致したときだけ、中身を再帰的に消してから空のディレクトリを消す。symlink・ディレクトリでないもの・同一性の不一致は `FailedPrecondition` にして何も消さない。どの段でも `ENOENT` なら「既に無い」として成功扱いにする（冪等） |
| 失敗時の扱い | delete の戻り値は変えない（状態は既に消えている。エラーを返すと再実行が `NotFound` になる。`image_ref_release` と同じ考え方）。失敗は操作名 `image_rootfs_remove` で `OpRecorder` に記録し、木は残す |
| 作成世代の照合（#2378） | (dev, ino) は rootfs を手で消して同名のディレクトリを作り直すと再利用されうる。そこで create は展開後・公開前に、rootfs 直下の印のファイル `.fandhe-container-rootfs-owner`（0400）へ 128 bit の乱数トークン（小文字 16 進 32 文字）を書き、同じ値を状態レコードの `imageRootfs.token` に記録する。delete は固定した rootfs の fd 直下の印をリンク非追従・通常ファイルのみで読み、記録と完全一致したときだけ消す。印の欠落・不一致・記録のトークン欠落（旧記録）は `FailedPrecondition` で何も消さない。展開済みの木に同名のファイルがあれば（イメージ由来の偽の印）create が拒否する。コンテナ内から rootfs の `/` に印のファイルが見える |
| delete と create・start の排他（#2378） | `StateStore::delete` が成功するとストアのロックは外れる。rootfs を持つコンテナの delete は、状態削除の前から rootfs の後始末の完了まで bundle の所有ロック（`BundleLock`。start と同じ `flock`）を保持する。通常の create・`create_with_image` の状態作成も同じロックを取り、保持中は `FailedPrecondition`（何も変えず再試行）。start は既存の `BundleLock` で排他される。create・delete のロックは bundle が指す実体に取る（祖先が symlink なら解決した実体の経路で取り直す。ロックは inode に掛かるため、表記の違う bundle 経由でも同じ実体なら排他する）。Linux でそれでもロックを取れない create は状態を作らずに拒否し、delete は状態を消すが rootfs は消さずに残して失敗を記録する（fail-closed）。Linux 以外はロックが未実装で、create は排他なしで進み、delete は rootfs を消さない |
| 同じ ID の再作成との競合 | 旧い最終名がある間は、新しい `create_with_image` は `RENAME_NOREPLACE` のため公開できない。同じ名前に別の同一性の実体があるのは差し替えられた場合だけで、そのときは消さない |
| 他コンテナとの共有 | core が所有する rootfs を、別のコンテナ（通常の create で同じ bundle を指す、別 bundle の絶対 `root.path` で指す）が使う構成は支援しない。その場合 delete が使用中の rootfs を消して壊れる（create 間の排他が無いため。#2353 の注記を引き継ぐ） |
| Linux 以外 | 展開の作成が `Unimplemented` なので記録は生じない。記録が現れても経路を再解決して消さず、`Unimplemented` で拒否して失敗として記録する |

## 前提・制約

- 削除は展開と同じ実効 ID で走る前提。rootless の userns 内での展開（oci の既知の未実装）が入ると、subuid 所有の木を euid では消せない（`EPERM`）可能性がある。入れる際に削除の権限経路を決める
- 状態ルートの既定は tmpfs（`/run`・`$XDG_RUNTIME_DIR`）なので、記録は同じブート内のもの。`--root` で永続ストレージを使い再起動を挟むと、`st_dev` が変わるファイルシステムでは同一性が不一致になり、消さずに残す（安全側）
- 件数（100 万）と深さ（256）の上限を超える木は、消し切らずに失敗として記録して残す（無限にかからない。REPAIR-5）
- 所有者 uid の照合はしない。rootful では展開が root ディレクトリの所有者を image の値へ変えうるため、同一性は (dev, ino) で判定する
- 記録は `state.json` の `imageRootfs` に書く。キーの無い既存ファイルは「記録なし」として読み、値が検証（相対・Normal 要素のみ・予約名なし・4096 バイト以下）に通らなければ破損として拒否する（状態ルートは信頼境界。OCI-5）

## 失敗後の手動回復

delete が `image_rootfs_remove` の失敗を記録した、または記録の無い孤児の rootfs が残ったときは、同じ bundle の次の `create_with_image` が `AlreadyExists` で止まる。利用者が `<bundle>/<root.path>` の中身を確認し、不要なら手で削除する。

## 対象外（後続の候補）

- 孤児になった rootfs（状態を失った・delete が失敗した・create 途中で落ちた）の自動回収。参照と blob の起動時照合（#854）は rootfs の木を対象にしていないため、GC・prune の対象にするかは別途決める
- rootless userns 展開時の削除権限
- `DeleteResponse` に rootfs の削除結果を載せること（現状は recorder で観測する）
- CLI / plugin からの配線は #2315 の範囲
