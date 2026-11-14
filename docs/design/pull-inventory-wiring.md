# pull の結果を ImageStore の在庫へ登録する配線（#2539・OCI-1・OCI-7・CRI-3・TASK-183 追補）

## 目的と結論

PR #2520（#2380）で manifest の在庫・タグ・pull リースを `@image-inventory.json` へ永続化したが、本番で在庫を埋める経路が
無かった。このため `image ls` はヘッダだけ、`image rm` / `image tag` / `create --image` は `NOT_FOUND` だった。
本変更で、cri の `OciImagePuller::pull`（`PullImage` が呼ぶ唯一の pull 実装）が oci の `ImageStore` / `PullSession` を通すようにした。

| 決定 | 内容 |
| ---- | ---- |
| 入口 | cri の `OciImagePuller::pull` の 1 か所。`PullConfig::cache_dir` は `ImageStore` の root と同一 |
| CLI の `pull` サブコマンド | 足さない。cli → cri の通常依存（tonic / prost を CLI に持ち込む）か、pull 手順の oci への移設が要り、crate 境界の判断になるため。同じ root を `--image-root` に渡せば CLI の `image ls` / `create --image` から見える（`--root` を省けば `image ls` / `image rm` / `image tag` / `image prune` / `system df` の `--image-root` の既定が同じ root になる。#2384・[image-root-default.md](image-root-default.md)） |
| 本番の到達 | plugin-cri の `CriPluginBackends::image_service`（#2592）が本番の `PullConfig`（キャッシュは `<state_root>/.cri/images`）と `OciImagePuller` を組み、`main.rs` が呼ぶため、本番の `PullImage` から在庫へ登録される。CLI から見るには同じ root を `--image-root` に渡す。plugin-cri の CRI 側のタグ在庫は `InMemoryImageStore`（プロセス内だけ） |

## 手順と順序

1. `blobs/sha256` を 0700 で用意し（既存の祖先検証）、`ImageStore::open` → `begin_pull_generated`（`staging/<id>` と `@pull.lock`）
2. blob ごとに、既存ならリース登録 → 信頼条件・digest の検査（合格で再利用、不合格はリース解放して取得）。無ければ
   `open_staged_blob` の writer（検査済み root の fd 起点の `<hex>.part`）へ取得して `commit`、`verify_staged_blob`
   （サイズは宣言値と完全一致。#2765）
3. config を読み、layer を `staging/<id>/unpack/entry/rootfs` へ展開（diff_id 突合）。ステージングの blob は
   `open_verified_staged_blob` で pull ディレクトリ fd 起点に開いたハンドルから読む（#2893）。リース済みの既存 blob は
   `open_leased_blob` で検査済み root の fd 起点に開く（#4179）。`unpack/` の作成・展開・記録・公開元・後始末も pull ディレクトリの fd 起点〔#4180〕）
4. rootfs のエントリを `rootfs/sha256/<config-hex>` へ rename（記録と一緒に原子的。宛先は検査済み root の fd 起点で開いた `PublishedRootfsDir`、公開の直前にパスとの同一性を照合する。#4283）
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
`FAILED_PRECONDITION`。照合は #4799（SEC-5・OCI-1・CRI-3）で実装済み。照合点は 1 つ（`image_pull::match_recorded_settings`）で、
pull の再利用判定（`check_unpack_record`）と create の `read_layers` が共有する。`ownership=` 行（方式の語と id map の全行）が
完全一致しなければ、縮退も再展開もせず固定文言（値を含めない）で拒否する。

| 食い違い | 文言（`FAILED_PRECONDITION`） |
| -------- | ----------------------------- |
| `ownership=` 行（写像・方式の語・`keep` との差） | `image rootfs cache entry was unpacked with a different id mapping` |
| 特殊ビット・config・書式ヘッダ | `image rootfs cache entry was unpacked with different settings` |
| 記録ファイルが無い | `image rootfs cache entry has no unpack record` |

- 旧い展開の扱い: 照合対象外にせず拒否する（fail-closed）。`ownership=keep` の記録は写像ありの期待に対し id mapping の文言で、
  旧い書式ヘッダは different settings の文言で拒否される。現在の本番キャッシュはすべて `keep` だが、本番の値も `Keep` の間は一致して通る
- 利用者の対処: 食い違った展開物（`<image-root>/rootfs/sha256/<config-hex>`）は消されない。展開済み rootfs の GC は未実装
  （#471・#2315）で `image rm` でも消えないため、再 pull では直らない。手動削除は subuid 所有の木のため user namespace の中で行う
  必要があり、手順は subuid 所有の木の削除（H3・#4800）の後に整備する
- 残余: plugin-cri は権限モデルの解決結果をプロセス内で保持する（`extract_options()`）。稼働中に `/etc/subuid` が変わっても再起動までは
  create の写像が変わらず、start の launcher が読む最新の写像との差は検出されない。再起動後は記録と照合される。create ごとの再解決に
  するかは、写像を持たせる H6（#4801）で判断する
- 本番の値が `Keep` + `Strip` の間は写像が空で食い違いは起きない。`ChownInUserNamespace` の配線（H6）で効く。
詳細は [oci-layer-special-bits.md](oci-layer-special-bits.md) の末尾。

## 動作の変更点

- 公開済みの宛先が symlink・FIFO 等の通常ファイルでないとき、oci の `publish` は拒否せず検証済みの実体で名前を差し替える
  （従来の cri の公開と同じ。symlink の先には書き込まない。ディレクトリは `FailedPrecondition`）
- `OciImagePuller::with_recorder` の記録先は、展開に加えて `ImageStore` の操作（開始・リース・検証・公開・中止）も受ける

## スコープ外（追跡）

- CLI の `pull` サブコマンド（crate 境界の判断。起票の要否はオーナー確認）
- `InMemoryImageStore` の置き換え（TASK-183）。plugin-cri の ImageService と本番の `PullConfig` は #2592 で配線済み
- 本番の `ImageRootfsUnpacker`（#2377）の入力は、下の「在庫のスキーマ v2」で解消した（実装済み）。残りの配線は #2791（plugin-cri）・#482 / #2792（rootless の user namespace 内の展開）
- 展開済み `rootfs/sha256/<hex>` の GC と `image rm` / `prune` への接続（#2315・#471）
- Windows ホストは `ImageStore::open` の恒久拒否（#2428 案 C・#4333。#4181 は not planned）で到達しないため対象外。公開先 `rootfs/sha256`・create 経路の読み取りは #4283、`unpack/` は #4180、検証後のステージング blob の読み取りは #2893、リース済み blob の読み取りは #4179 で fd 起点に移した

## 在庫のスキーマ v2（layer の mediaType。#2377・OCI-7・OCI-1）

本番の `ImageRootfsUnpacker`（cli の `image_unpack`）は、manifest digest から下位順のレイヤー（blob・mediaType・diff_id）を `ImageStore::image_layers` で引く。
pull は manifest の本文を blob として保存せず、GC の参照計算にも manifest は入らないため、「登録済みの manifest blob を読み直す」方式は採れない
（保存するように変えると pull・prune・GC の参照計算まで変わる）。そこで次のハイブリッドにした。

- **mediaType は在庫が持つ**: `ManifestComposition` に layers と同じ並びの任意の `layer_media_types` を足し、`@image-inventory.json` を version 2 にした。
  cri の pull の公開（`stage_and_unpack`）が manifest の descriptor から載せる。受理は展開側の閉じた集合（`layer::LAYER_MEDIA_TYPES` の 6 種）に限り、
  登録時と読み込み時の両方で検証する（件数の不一致・集合外・255 バイト超は拒否。読み込みは `DataLoss`）
- **diff_ids は在庫に持たない**: 登録済みの config blob を、検査済み root の fd 起点で開き、信頼条件の確認 → 上限（1 MiB）つきの 1 回読み →
  読んだバイト列そのものの sha256 を config digest と照合 → `rootfs.diff_ids` を解析、の順で得る（cri の `read_verified_config_file` と同じ規律）。
  真実源を config の 1 か所に保ち、在庫の肥大化と二重管理を避ける。layers・mediaType・diff_ids の件数が一致しなければ `DataLoss`
- **v1 からの移行**: 読み込みは version 1 と 2 を受け、v1（または項目なし）の manifest は mediaType が未記録（`None`）になる。未記録のイメージは
  `image_layers` が `FailedPrecondition`（「pull the image again」）で拒否し、同じイメージの再 pull の公開（`reconcile_with`）が未記録の mediaType を埋める
  （既に記録済みで値が違えば `AlreadyExists`、再登録が未記録でも記録済みは落とさない）。書き込みは常に version 2
- **旧バイナリ**: version 2 のファイルを旧バイナリは `unsupported image inventory file version` で拒否する（fail-closed）。新旧のバイナリで同じ root を共有しない前提
- **サイズの見積り**: `BYTES_PER_MANIFEST` は v1 の 10,240 に、受理表で最長の mediaType（const 評価で導出）× 128 層の分を足した値。`MAX_IMAGE_INVENTORY_FILE_BYTES` はそれに従う
  （最長の mediaType を 128 層並べた構成が収まることを試験が固定）

展開自体の排他は `image_layers` の内側（期限つき）で構成を複製して手放し、展開の全体にわたって保持しない（REPAIR-5）。blob は `open_verified_layer` が fd 起点で開き、
同じハンドルで信頼条件・digest・サイズを確かめる（返す `blob_path` は情報用で開くのには使わない）。展開先の `/proc/self/fd/N` は `ExtractRoot::open_proc_fd_link` が字句を
厳密に検査して開く。

## 起動時の pull 回収 GC の配線（#2819・OCI-7・OCI-1・REPAIR-3・REPAIR-4・REPAIR-5）

plugin-cri の `serve`（`main.rs`）が、`image_service()` の成功後・RPC の受け付け前に、`ImageStore::open(<state_root>/.cri/images)` を
開いて `recover_stale_pulls` を 1 回呼ぶ（`adapter::CriPluginBackends::recover_stale_image_pulls`）。root は状態ルート配下の固定位置で、
外部入力から受けない。生存判定は `@pull.lock` の OS ロックで、生きている別プロセスの pull は回収しない（誤るのは「余分に残す」側だけ）。

| 結果 | 扱い | 理由 |
| --- | --- | --- |
| `ImageStore::open` の失敗（root の所有者・権限の検査違反） | 起動しない | root を信頼できない状態で ImageService を広告しない（fail-closed） |
| `recover_stale_pulls` の `Err`（排他の `Timeout` 等） | 起動しない | この状態では `PullImage` も失敗する |
| 期限 `STARTUP_PULL_RECOVERY_BUDGET`（60 秒）超過・worker を作れない | 起動しない | 取り残した worker が `@lock` を握ったまま受け付けると `PullImage` が全て `Timeout` になる。プロセスの終了で OS がロックを解放する |
| `Ok` で `failed` が 1 以上 | 警告ログを出して続行 | 余分に残す側で、次回の起動で再試行される |
| `Ok` で `kept_live` / `kept_undetermined` | ログを出して続行 | 生存中・確認できないものは残す（OCI-7） |

- ログ: 結果が全 0 でなければ `event: image_pull_recovery` を 1 行出す（件数だけ。パス・pull ID は含めない）。記録器には `image_pull_recovery` を計上する
- 挙動の変化: root の検査がプロセスの起動の可否を左右する（RuntimeService も同じプロセスで巻き込まれる）
- CLI（`--image-root`）は `recover_stale_pulls` を呼ばない。pull を持たず、短命の各コマンドに `@lock` の保持を足さないため。同じ root を使う plugin-cri の次回の起動で回収される
- 残る範囲: plugin-cri を再起動しない限り、稼働中に別プロセスが残した残骸は残る（余分に残す側）。oci 内の計装（`OciOpRecorder`）の橋渡しは下の「oci の計装の配線」（#2900）で配線済み

## oci の計装の配線（#2900・REPAIR-4・OCI-1）

plugin-cri の `adapter::CoreOciRecorder` が oci の `OciOpRecorder` を core の `OpRecorder` へ橋渡しする（置き場の判断は #1322。操作を本番で呼び `OpRecorder` を持つ crate に置く。`CoreCriRecorder`・`CoreNetRecorder` と同じ形）。

- 注入点は 4 つ: `image_service` の `OciImagePuller::with_recorder`（展開と pull 内の `ImageStore`）・`OciRegistryClient::with_recorder`（`oci.auth*`・`oci.manifest.fetch`・`oci.blob.fetch`。cri に素通しの口を足した）・`bundle_provider_with` の `ImageRootfsSource::with_recorder`（`CreateContainer` の展開）・`recover_stale_image_pulls_in` の `ImageStore::with_recorder`（起動時の回収）。`PullConfig` 自体に記録先の欄は無い
- 写像: 操作名は `OciOpKind::as_str` と同じ固定 22 種（`oci.layer.extract`・`oci.pull.publish` 等。単体試験で全件を具体値と照合）。`Success` は成功、それ以外は失敗。レイテンシはそのまま。エラー code は名前に混ぜず落とす（種類数が掛け算で増えるため。分類は oci のエラー応答と構造化ログに残る）。`#[non_exhaustive]` の未知の種別は記録しない
- 専用の記録器（`CriPluginBackends::oci_op_recorder`）に分ける理由: core の `OpRecorder` は操作名の種類を `MAX_TRACKED_OPS`（64）までしか持たず、上限後の新しい名前は捨てて `dropped_records` に数える。当初の共有記録器には `cri.*`・`net.*`・`oci_runtime`・plugin-cri の `*_remove` 等が入り、#4380 の数え直しで最悪 98 種（上限超過）だったため、さらに CRI 記録器（最悪 48 種）とライフサイクル記録器（最悪 53 種。core の `oci_runtime`・ログの回収・net。本番のみ）に分けた（いずれも `MAX_TRACKED_OPS - 8` 以下を `repair4_4380_*` が固定）。一方、1 回の pull で通る oci の種別は約 16 ある。共有へ流すと pull が枠を取り、後続の `create`・`delete` の記録を捨てさせる。専用なら 22 種で 64 に収まる（`cri.pull_image.registry_http.*` の 8 種も同じ専用記録器へ入る。#2966）。core の上限は変えない（PLUG-4）
- stderr: `op_stats_export_loop_many` が CRI・ライフサイクル・oci の順に記録器ごとのブロックを出す。1 周期に `op_stats_meta` 行が 3 行になる（#4380）
- 二重計上: `oci.pull.gc_recover`（oci 側。排他の待ちを含む）と `image_pull_recovery`（plugin-cri 側。共有記録器）は同じ回収を別の意味で数える。意図どおり残す
- 範囲外: 操作統計のメトリクス公開口への CLI 側の橋渡し（公開口そのものは `--op-stats-file`〔opt-in の原子的なスナップショットファイル。案 C・#4295・#4340〕で実装済み。詳細は `cri-op-stats-export.md`）

## レジストリの HTTP 状態の区分の計上（#2966・REPAIR-4・CRI-3・OCI-1）

PR #2927（#2898）でレジストリの HTTP 状態を `PullImage` のトレーラーメタデータ `fandhe-registry-http-status` で運ぶようにしたが、操作記録は gRPC コードしか見ず、429 も 503 も `UNAVAILABLE` の失敗 1 件になっていた。#2966 で区分を記録に足す。

- 読み手は 1 か所: `fandhe_container_cri::error::registry_http_status_from_metadata`（ちょうど 3 桁の ASCII 数字で 100..=599 のときだけ `Some`。他は `None` で数えない）。操作記録の `CriOpTimer` と実機前提試験の失敗表示が同じ関数を使う
- 区分は固定の語彙 `instrument::RegistryHttpClass`（8 種）。生の HTTP 状態・URL・資格情報は `CriOpSample` に入れない

| HTTP 状態 | 区分 | 操作名（`cri.pull_image.registry_http.<接尾辞>`） |
| --------- | ---- | ------------------------------------------------ |
| 401 | `Unauthorized` | `unauthorized` |
| 403 | `Forbidden` | `forbidden` |
| 404 | `NotFound` | `not_found` |
| 408 | `RequestTimeout` | `request_timeout` |
| 429 | `RateLimited` | `rate_limited` |
| 上記以外の 400..=499 | `OtherClientError` | `client_error` |
| 500..=599 | `ServerError` | `server_error` |
| 100..=399 | `Other` | `other` |

- 置き場は oci 専用の記録器（`oci_op_recorder`）: 共有記録器へ 8 種を足すと `MAX_TRACKED_OPS`（64）に迫り `create`・`delete` の記録を捨てさせうる。専用は 22 + 8 = 30 種で収まる（単体試験の const 評価で照合）
- 失敗のときだけ記録する（`CoreCriRecorder`）。共有記録器の `cri.pull_image` の失敗 1 件と、区分側の失敗 1 件は同じ失敗を別の切り口で数えたもの（二重計上。意図どおり）
- 実機前提試験 `production_binary_full_lifecycle_real` の pull 失敗時は、メタデータから区分を読み、429 なら `production_binary_full_lifecycle_real: registry rate limit (HTTP 429); ...` の固定行を出す（それ以外は `pull failed with code <CODE> registry_http=<区分>`）。成否の判定は変えない。CI の事前プローブ（`make docker-hub-ratelimit-probe`）は残す
- 範囲外: 操作統計のメトリクス公開口への接続（公開口は `--op-stats-file`〔opt-in の原子的なスナップショットファイル。案 C・#4295・#4340〕で実装済み。詳細は `cri-op-stats-export.md`）

## CRI の在庫の永続化（#4176・CRI-1・CRI-2・OCI-7）

`CriPluginBackends::production()`（unix）の `images` は、cri の `InMemoryImageStore` から plugin-cri の `PersistentImageStore`（`crates/plugin-cri/src/image_inventory.rs`）へ替えた。注入経路（`new`・`with_recorder`）と非 unix は従来どおりメモリのみ。

- 保存先: pull と同じ root（`<state_root>/.cri/images`。oci の `ImageStore::open` の root）直下の `@cri-image-records.json`（0600）。形式の符号化と復号は cri の `image_service::persist`（`ImageRecord` の項目が非公開で、plugin-cri は serde を持たないため）。`top_level_digests` と `auxiliary_digests` を分けて保存し、`from_parts` で読み戻す
- oci の在庫（`@image-inventory.json`）から導出しない理由: 在庫のキーは platform manifest で、multi-arch の index digest（`repo_digests[0]`）とタグ無し pull の repo 名が残らない。読むたびに `@lock` を取る案は同期の RPC を止める。偽の puller の試験は oci の在庫へ publish しない
- 排他: 起動時の読み込みと `upsert` の書き込みは oci の `ImageStore::lock()` の区間の中で行う（root の再検査とプロセス間の排他を oci と共有）。`upsert` は区間の中でファイルを読み直し、cri の `upsert`（統合・タグの付け替え）で組み直してから、一時ファイル → fsync → rename → ディレクトリの fsync で書く。成功したときだけメモリ表示を差し替える。`list` / `get` はメモリだけで I/O しない
- RemoveImage（#4177・CRI-1・CRI-2）: 参照（id・タグ・digest。`ImageStatus` と同じ解決規則と短縮名の正規化）を 1 件の記録に解決し、記録ごと（全タグ・全 digest）外す。CRI の契約どおり冪等で、該当が無ければ成功を返す。`PersistentImageStore::remove` は `upsert` と同じ排他区間・読み直し・原子的な書き込みの手順（共通の `commit_with`）を通し、rename 前の失敗はメモリも永続側も元のまま、rename 後の失敗はメモリ表示を永続側へ揃えて `Io` を返す。該当が無いときはファイルを書かず、メモリ表示だけ読み直した永続側へ揃える。空の参照・上限超過は `InvalidArgument`、store の失敗は `Internal`（文言に参照を含めない）。blob・展開済み rootfs・使用中かどうかの検査には触れない（回収は #471 系。proto も資源の回収は非同期でよいとする）
- fail-closed の分け方: root の不信・排他の失敗・読み取りの I/O 失敗は起動を止める。記録ファイルだけが壊れている（不正・矛盾・symlink・通常ファイルでない・所有者違い・group / other 書き込み権・上限超過）ときは「使えない」状態で開き、`list`・`get`・`upsert` は `Corrupt`（`CriImageService` では `Internal`「image store failure」）。空として扱わず上書きしない。RuntimeService は生かして既存コンテナの stop / remove を通す。直すには記録を手で直して plugin を再起動する
- 残り（REPAIR-3）: 読み書きはパス起点（oci の `RootHandle` は非公開。`lock()` の root 再検査と fstat の dev / ino 照合で守る）。`upsert` は blocking worker の中で呼ばれ、PullImage の取り消しの窓は稼働中に開かない（#4178。決定と残る不一致は `container-log-removal-wait.md`）。並びは top-level 区間→補助区間・各区間と `repo_tags` は辞書順で、永続化しても保つ（#3038）。oci の在庫との突き合わせは #4177 の範囲外で #4264 で追跡、展開済み rootfs の GC は #471 系
