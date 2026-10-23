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
| 公開済みで状態の無い rootfs の回収（#2540・決定 A） | 公開後・状態作成前のクラッシュ、delete の rootfs 削除の失敗、状態の喪失で残った木を、同じ bundle の次の展開器つき `create_with_image` が、展開先を作る前に回収する。次をすべて満たすときだけ消し、確かめられなければ残して従来どおり `AlreadyExists` にする: (1) bundle の所有ロック（`BundleLock`）を取れる（保持中は残す。delete・状態作成と排他）、(2) 最終の名前がリンクでないディレクトリで親と同じマウント、(3) 木への `flock` が取れる（`WouldBlock` は生きている create）かつロック中に開き直した実体が同じ、(4) 印が v2 形式でリンク非追従・通常ファイル・nlink 1・所有者が実効 uid・mode 0400、印の (dev, ino) が木の実体と一致する、(5) `StateStore::list` を全件（ページ数に上限）調べ、印のトークンを持つレコードも同じ bundle（文字列または追従して開いた (dev, ino) が同じ）を指すレコードも無い。一覧の失敗・打ち切りは残す。生きている create は、`CreatedRootfs` が状態作成の完了まで木の `flock` を保持することで見分ける。記録は操作名 `image_rootfs_orphan_reap`（回収した = 成功、使用中・確かめられない・失敗 = 失敗）。ロックは判定と削除の間だけ保持する（展開の全体では保持しない）。別の状態ルート（`--root` 違い）のコンテナが同じ bundle の rootfs を使う構成は、そのレコードが見えないため支援しない |
| 印の v2 形式（#2540・決定 B） | 印は 1 行目 = トークン（小文字 16 進 32 文字）、2 行目 = 木の作成時の `<dev>:<ino>`（10 進）。`cp -a` で別の bundle へ複製した木は inode が新しく、2 行目が一致しないので孤児として消さない。delete は v1（トークンだけ）と v2 の両方を受ける（既存の記録との互換）。孤児の回収は v2 で同一性が一致するときだけ消す（v1 は残す）。印の長さは 128 バイト以下。印はコンテナからも `/` に見え、dev・ino が見える。再起動で `st_dev` が変わる状態ルートでは一致しないので残す（手動で回復する） |
| subuid 所有の木の削除（#2540・決定 C） | rootless で userns の中の展開器が作った木（`OwnershipPolicy::ChownInUserNamespace`）はホストの実効 uid では `chmod`・`read_dir`・`unlink` が `EPERM` になる。権限を `ImageRootfsPrivilege`（既定 `HostEffectiveIds`、`SubordinateIds(SubordinateIdSource)`）で宣言する: create は `ContainerImage::with_rootfs_privilege`（状態の `imageRootfs.ownership` に `subordinate` を記録）、delete は `DeleteOptions`（`delete_with_options`・`delete_releasing_image_ref_with_options`）、展開途中の回収は `ReapOptions`（`reap_stale_unpacks_with`）。`SubordinateIds` のときは、子プロセスの User namespace（コンテナ 0 → 自 euid、1.. → subuid 範囲。`newuidmap` 経由の既存の holder / mapper 方式。Mount ns は分けず `mnt_id` の照合を保つ）の中で、固定済みの親の fd・(dev, ino)・所有者照合を継承して同じ削除を行い（経路を再解決しない）、固定の終了コードで結果を返す。親は期限つきで待ち、超えたら kill して回収する。呼び出しがマルチスレッドなら fork の検査で `FailedPrecondition` となり木を残す。適用先は delete・create 失敗の後始末・展開途中の回収・公開済みの孤児の回収の 4 経路。記録が subordinate なのに権限が無い delete は、木に触れず `FailedPrecondition` を `image_rootfs_remove` の失敗として記録して残す（ホストで試して `EPERM` のときだけ userns で再試行する方式は、部分削除の順序依存を避けるため採らない）。`imageRootfs.ownership` の不明な値は破損として拒否する。削除は印を最後に消すので、途中で失敗・期限切れになっても印が残り、次の孤児の回収が木を見分けられる |
| 展開途中の木の判定と観測（#2540・決定 D） | 展開途中の木（`.fandhe-unpack-*`。節「展開途中の木の回収」）の回収条件から mode 0700 の要求を外す。証拠は予約名・リンクでないディレクトリ・所有者・ロックが取れること・ロック中の同一性の再確認で、mode ではない（userns の展開器はイメージの `./` の項目で展開先 root の mode を変えうる）。所有者は実効 uid、権限が `SubordinateIds` なら subuid の範囲も受ける。rootful でイメージが所有者を 0 以外へ変えた木は `Unverified` で残す。残した理由は `StagingReclamation::kept_unverified_reasons`（`UnverifiedReason`）で見え、`reap_stale_unpacks_with` と create は `image_rootfs_reap_kept_unverified`・`image_rootfs_reap_failed`・`image_rootfs_reap_truncated`・`image_rootfs_reap_scan_failed` を 1 件ずつ失敗として記録する（`OpRecorder::snapshot` の失敗数が件数になる） |
| 状態ルート全体の掃引はしない（#2540・決定 E） | 孤児は状態レコードを持たないので `StateStore::list` でも参照テーブルでも bundle を列挙できず、状態ルート全体を掃引するには create の開始時に bundle を残す意図の記録（journal）が要る。契機は (1) 同じ bundle への次の `create_with_image`（展開途中の木と公開済みの孤児の両方）、(2) 呼び出し元が bundle を指定して呼ぶ `reap_stale_unpacks_with` の 2 つに限る。意図の記録は後続の追跡課題 |
| Linux 以外 | 展開の作成が `Unimplemented` なので記録は生じない。記録が現れても経路を再解決して消さず、`Unimplemented` で拒否して失敗として記録する |

## 前提・制約

- 既定の削除は展開と同じ実効 ID で走る。rootless の userns 内での展開が作る subuid 所有の木は、`ImageRootfsPrivilege::SubordinateIds` を渡したときだけ userns の中で消せる（決定 C）。CLI / CRI / supervisor からの権限の受け渡しは #2315・#2243 の配線の範囲で未実装（REPAIR-3）。マルチスレッドの呼び出し元（CRI の tokio 等）は fork の検査で拒否されるため、子プロセス方式の配線が別途要る
- 状態ルートの既定は tmpfs（`/run`・`$XDG_RUNTIME_DIR`）なので、記録は同じブート内のもの。`--root` で永続ストレージを使い再起動を挟むと、`st_dev` が変わるファイルシステムでは同一性が不一致になり、消さずに残す（安全側）
- 件数（100 万）と深さ（256）の上限を超える木は、消し切らずに失敗として記録して残す（無限にかからない。REPAIR-5）
- 所有者 uid の照合はしない。rootful では展開が root ディレクトリの所有者を image の値へ変えうるため、同一性は (dev, ino) で判定する
- 記録は `state.json` の `imageRootfs` に書く。キーの無い既存ファイルは「記録なし」として読み、値が検証（相対・Normal 要素のみ・予約名なし・4096 バイト以下）に通らなければ破損として拒否する（状態ルートは信頼境界。OCI-5）

## 展開途中の木の回収（#2379・OCI-7）

展開の途中でプロセスが落ちると、非公開の名前 `.fandhe-unpack-<pid>-<seq>` の木が残る。持ち主がいるかは PID ではなく、木のディレクトリへの OS ロック（`flock`）で判定する。作る側は作った直後に排他ロックを取り `CreatedRootfs` が生きている間保持する（プロセスが落ちれば OS が外す）。回収する側は固定した親の fd の下で予約名（`^\.fandhe-unpack-[0-9]{1,10}-[0-9]{1,20}$`）の兄弟を調べ、リンクでないディレクトリ・所有者が実効 uid（権限が `SubordinateIds` なら subuid の範囲も）・ロックが取れる・ロック保持中に開き直した実体が同じ（dev・ino）ものだけを消す。どれかを確かめられなければ残す。走査数（4096）・件数・深さに上限を置き、ロックは `try_lock` だけで待たない。契機は同じ bundle への次の create と `reap_stale_unpacks`（`_with` つきは記録も行う）。

## 失敗後の手動回復

公開済みで状態の無い木は、上の決定 A の条件を満たせば次の `create_with_image` が自動で回収する。回収されずに `AlreadyExists` で止まり続けるとき（`image_rootfs_orphan_reap` の失敗、印が v1・複製・欠落、別の状態ルートの使用、再起動で `st_dev` が変わった等）は、利用者が `<bundle>/<root.path>` の中身を確認し、不要なら手で削除する。`image_rootfs_remove` の失敗が subordinate の木だったときは、delete が状態の削除まで済ませており delete し直しは冒頭の状態取得で `NotFound` になるため使えない。権限（`SubordinateIds`）つきの次の create（`ContainerImage::with_rootfs_privilege`）による公開済みの孤児の回収に任せるか、`podman unshare` 相当の userns の中で手で削除する。

## 対象外（後続の候補）

- 状態ルート全体の掃引のための、bundle の意図の記録（journal）の導入（決定 E）
- CLI / CRI / supervisor から `ImageRootfsPrivilege`・`DeleteOptions`・`ReapOptions` を渡す配線（#2315・#2243）と、マルチスレッド経路の子プロセス方式
- 別の状態ルートのコンテナと同じ bundle の rootfs を共有する構成の支援
- rootful でイメージが所有者を 0 以外へ変えた展開途中の木の自動回収（`Unverified` として観測できるだけ）
- `DeleteResponse` に rootfs の削除結果を載せること（現状は recorder で観測する）
- 参照と blob の起動時照合（#854）が rootfs の木を GC・prune の対象にするか
