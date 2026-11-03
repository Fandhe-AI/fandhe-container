# pull の結果を ImageStore の在庫へ登録する配線（#2539・OCI-1・OCI-7・CRI-3・TASK-183 追補）

## 目的と結論

PR #2520（#2380）で manifest の在庫・タグ・pull リースを `@image-inventory.json` へ永続化したが、本番で在庫を埋める経路が
無かった。このため `image ls` はヘッダだけ、`image rm` / `image tag` / `create --image` は `NOT_FOUND` だった。
本変更で、cri の `OciImagePuller::pull`（`PullImage` が呼ぶ唯一の pull 実装）が oci の `ImageStore` / `PullSession` を通すようにした。

| 決定 | 内容 |
| ---- | ---- |
| 入口 | cri の `OciImagePuller::pull` の 1 か所。`PullConfig::cache_dir` は `ImageStore` の root と同一 |
| CLI の `pull` サブコマンド | 足さない。cli → cri の通常依存（tonic / prost を CLI に持ち込む）か、pull 手順の oci への移設が要り、crate 境界の判断になるため。同じ root を `--image-root` に渡せば CLI の `image ls` / `create --image` から見える |
| 本番の到達 | plugin-cri の `CriPluginBackends::image_service`（#2592）が本番の `PullConfig`（キャッシュは `<state_root>/.cri/images`）と `OciImagePuller` を組み、`main.rs` が呼ぶため、本番の `PullImage` から在庫へ登録される。CLI から見るには同じ root を `--image-root` に渡す。plugin-cri の CRI 側のタグ在庫は `InMemoryImageStore`（プロセス内だけ） |

## 手順と順序

1. `blobs/sha256` を 0700 で用意し（既存の祖先検証）、`ImageStore::open` → `begin_pull_generated`（`staging/<id>` と `@pull.lock`）
2. blob ごとに、既存ならリース登録 → 信頼条件・digest の検査（合格で再利用、不合格はリース解放して取得）。無ければ
   `open_staged_blob` の writer（検査済み root の fd 起点の `<hex>.part`）へ取得して `commit`、`verify_staged_blob`
   （サイズは宣言値と完全一致。#2765）
3. config を読み、layer を `staging/<id>/unpack/entry/rootfs` へ展開（diff_id 突合）。ステージングの blob は
   `open_verified_staged_blob` で pull ディレクトリ fd 起点に開いたハンドルから読む（#2893。リース済みの既存 blob と
   `unpack/` の作成はパス起点のまま。#2921）
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
- `InMemoryImageStore` の置き換え（TASK-183）。plugin-cri の ImageService と本番の `PullConfig` は #2592 で配線済み
- #2377（本番の `ImageRootfsUnpacker`）には、在庫に layer の mediaType・`diff_ids` が要る。`@image-inventory.json` のスキーマは広げていない
- 展開済み `rootfs/sha256/<hex>` の GC と `image rm` / `prune` への接続（#2315・#471）
- リース済みの既存 blob の読み取りと展開先 `unpack/` の作成の fd 起点化、Windows のパス起点（#2921。検証後のステージング blob の読み取りは #2893 で移した）

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
- 専用の記録器（`CriPluginBackends::oci_op_recorder`）に分ける理由: core の `OpRecorder` は操作名の種類を `MAX_TRACKED_OPS`（64）までしか持たず、上限後の新しい名前は捨てて `dropped_records` に数える。共有記録器には `cri.*`・`net.*`・`oci_runtime`・plugin-cri の `*_remove` 等で約 51〜56 種が入りうる一方、1 回の pull で通る oci の種別は約 16 ある。共有へ流すと pull が枠を取り、後続の `create`・`delete` の記録を捨てさせる。専用なら 22 種で 64 に収まる（`cri.pull_image.registry_http.*` の 8 種も同じ専用記録器へ入る。#2966）。core の上限は変えない（PLUG-4）
- stderr: `op_stats_export_loop_many` が共有・oci の順に記録器ごとのブロックを出す。1 周期に `op_stats_meta` 行が 2 行になる
- 二重計上: `oci.pull.gc_recover`（oci 側。排他の待ちを含む）と `image_pull_recovery`（plugin-cri 側。共有記録器）は同じ回収を別の意味で数える。意図どおり残す
- 範囲外: 操作統計のメトリクス公開口への接続（#1869）・CLI 側の橋渡し

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
- 範囲外: 操作統計のメトリクス公開口への接続（#1869）
