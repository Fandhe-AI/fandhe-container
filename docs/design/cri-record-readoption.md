# plugin-cri の再起動をまたぐ sandbox・コンテナ記録の再採用の設計と実装単位（CRI-1・CRI-2・OCI-7・CORE-1・REPAIR-3）

設計記録（#2902）。コードは本変更で変えない。実装は「実装単位」の各 issue で行う。オーナー確認が要る点は「要確認事項」に分け、オーナー判断は未取得である。

## 背景

- `fandhe-container-cri` の `CriRuntimeService` は、sandbox とコンテナの記録をプロセス内メモリの `SandboxRegistry` にだけ持つ。モジュール doc に「TASK-59 で `StateStore` に置き換えるスタブ」とある（REPAIR-3）が、TASK-59（#436）は closed で、再採用を追う open の issue が無かった
- plugin-cri が再起動すると、コンテナ記録の CRI 層の項目が失われる。対象は `config`（metadata・labels・annotations・mounts・log_path）、`pod_sandbox_id`、重複判定キー `(sandbox_id, name, attempt)`、`resolved_image`（`image_ref`・`image_id`。#2863・#2831）、`resolved_log_path`、`applied_user`、`stop_signal`、各時刻、`exit_code`・`termination`。sandbox 記録も `PodSandboxConfig`、状態、`created_at`、`network_owned`・`pod_netns`、（#2871 以降）保持役の pid が失われる
- 一方、実行層は再起動をまたいで残る。supervisor は `systemd-run --user --scope` で起動され plugin より長く生きる（SUP-5・CORE-1）。core の `FileStateStore`（`<状態ルート>/<id>/state.json`）は永続で、status・pid・supervision・cgroup・annotations を持つ。bundle は `<状態ルート>/.cri/bundles/<id>`、ネットワークの回収待ちは `.cri/net/pending-reclaim/` に残る
- 結果、再起動後の kubelet からは「動いているコンテナが CRI に見えない」状態になり、bundle・core の状態・ネットワーク資源が孤児化する

## 前提と制約

| 事項 | 根拠 |
| ---- | ---- |
| CRI 層の項目は core の `StateStore` に書かない（PLUG-1 の境界） | [cri-config-acceptance.md](cri-config-acceptance.md)（`applied_user` の置き場の記述） |
| plugin-cri は `StateStore` の二つ目の実装を作らない | [crate-naming.md](crate-naming.md) 決定 6 |
| core の状態の写し方は `Ok`→Present／`NotFound`→Absent／その他→Undetermined | [container-ref-reconcile.md](container-ref-reconcile.md) 決定 3 |
| 永続記録のひな形（0700・symlink 拒否・所有者照合・`O_EXCL` 一時ファイル→fsync→rename→ディレクトリ fsync・`.lock` の期限つき `try_lock`・件数と長さの上限） | [network-reclaim-persistence.md](network-reclaim-persistence.md) |
| 保持役は plugin-cri の直接の子で stdin EOF で終了する（再起動をまたがない）。パスは自 sandbox の記録の pid からだけ作る（SEC-5 の P0・#2776） | [pod-namespace-holder.md](pod-namespace-holder.md) |
| `CreatedNetwork`・IPAM は未永続（#1870 の後続） | [network-reclaim-persistence.md](network-reclaim-persistence.md)「未対応（後続）」 |
| 本番の `PodNetworkProvider` は未注入。本番の在庫は `InMemoryImageStore`（プロセス内） | `crates/plugin-cri/src/adapter.rs` |
| 状態ルートを単一の plugin-cri に固定する排他は、`.cri/@instance.lock` で実装済み（#2931。UDS の bind は socket 単位のため別途必要だった） | 現状のコード |

## 範囲

| 対象 | 扱い |
| ---- | ---- |
| sandbox 記録（config・状態・作成時刻・ネットワークのフラグ） | 決定し実装単位へ |
| コンテナ記録（CRI 層の項目一式・`image_ref`・`image_id`） | 決定し実装単位へ |
| 保持役の pid と素性 | 記録の形を決定。再採用の可否は要確認事項 1 |
| ネットワーク資源（`network_owned`・`pod_netns`） | フラグの永続は決定。再起動後の `tear_down` は #1870 の後 |
| plugin-cri の在庫（`InMemoryImageStore`）の永続在庫への配線 | 範囲外。記録の `image_ref`・`image_id` は create 時のスナップショットとして独立に永続化するため依存しない。追跡 issue は #2945 |

## 置き場所

- `<状態ルート>/.cri/records/sandboxes/<sandbox_id>.rec`、`<状態ルート>/.cri/records/containers/<container_id>.rec`（1 件 1 ファイル）
- パスは固定で、要求の入力から受けない。ファイル名はサービスが採番した ID（形式を検証済み）だけ
- `.cri/records` と配下は 0700 で作る。既存のものは symlink でない・ディレクトリ・状態ルートと同じ所有者・group/other 権限なしを確認し、反すれば消さずに拒否する（`bundle_provider_in`・`ReclaimStore` と同じ基準。unix のみ。他 OS は plugin-cri の本番自体が `Unimplemented`）
- core の `<状態ルート>/<id>/` とは名前空間が分かれる（`.` 始まり）
- R2 の実装（#2932。`crates/cri/src/runtime_service/record_store.rs`・`record_store/file.rs`）: トレイト `RecordStore`（`put`・`remove`・`list`）とファイル実装 `FileRecordStore`（unix のみ）。拡張子は `.rec`、一時ファイルは同じディレクトリの `.tmp-<pid>-<連番>`（`O_EXCL`・0600。fsync → rename → ディレクトリの fsync）、排他は `.cri/records/.lock`（期限 5 秒の `try_lock`。決して unlink しない）。比較交換（CAS）は持たない（書き手は R3 のインスタンス排他と registry の `in_flight` で 1 つ）。列挙は専用スレッドで 1 件 10 秒・全体 60 秒の期限つきで、止まった読み取りは継続せず起動失敗（`Timeout`）にする。保持量の上限は `MAX_RETAINED_*_CONFIG_BYTES + 件数上限 × ヘッダ予算`、走査するエントリ数は `件数上限 × 2 + 64` まで。壊れた記録・不正な名前の `.rec` は消さず、列挙結果に失敗・件数として返す
- R2 の残余（#2932）: `put` が fsync 後〜rename 前のプロセス異常終了で残した一時ファイル `.tmp-<pid>-<連番>` は、open・list・put のどこでも回収しない（`list` は `.rec` 以外を読み飛ばすため検出もされない）。残骸は走査するエントリ数の上限（`件数上限 × 2 + 64`）を消費しうる。回収は R10 の手動回収の手順（`docs/setup/cri-record-recovery.md`）に送り、自動の掃除は足さない

## 形式

- serde を使わない。固定のヘッダ行（LF・ASCII。版の行 `fandhe-cri-sandbox-record v1` / `fandhe-cri-container-record v1`、キー順固定のスカラー項目）と、`config=<長さ>` の行に続く長さちょうどの prost 符号化した `PodSandboxConfig` / `ContainerConfig`。prost は既存依存で、新規依存は足さない
- 復号は厳密にする。版の完全一致・キー順固定・重複/未知キー/余分な行/CRLF なし・ID とファイル名の一致・長さの上限（config は `MAX_CONFIG_ENCODED_BYTES`、記録全体の上限を先に確認）。復号後に `config_limits` と同じ上限検証を通し、RunPodSandbox/CreateContainer と同じ上限を再採用時にも効かせる。違反は `InvalidArgument`（入力値をメッセージに載せない。REPAIR-4）
- 秘密の最小化: `ContainerConfig.envs` は記録に書かない（Status/List は返さず、bundle 作成後は不要）。`command`・`args` も応答に出ないため書かない案があるが、推奨は envs だけを除く（要確認事項 2）
- 保持量（`retained_bytes`）は読み込み時に再計算し、記録に書かない
- v1 の実装（R1・#2930。`crates/cri/src/runtime_service/record.rs`）: 「LF・ASCII」はキーと版の行が ASCII という意味で、値は LF 以外の制御文字（CR を含む）を含まない UTF-8（`log_path` は非 ASCII を許す）。sandbox の鍵は `id`・`state`・`created_at`・`runtime_handler`・`pending`・`network_owned`・`network_pending`・`config`、コンテナの鍵は `id`・`pod_sandbox_id`・`state`・`in_flight`（種類。`-` は無し）・`created_at`・`started_at`・`finished_at`・`exit_code`・`termination`・`stop_signal`・`log_path`・`user`・`image_id`・`image_ref`・`image_tag`・`config`（値のない項目は `-`）の順。整数は正準形（先頭 0・`+`・`-0` なし）、ID は 64 文字の小文字 16 進。config 部は復号後に再符号化した長さが `config=` の長さと一致することを要求し、未知フィールド・重複フィールド・非正準な符号化を拒否する。コンテナは `envs` が空であることも要求する。`image_ref`・`image_tag` は `ResolvedImage` と同じ判定を構築の前に適用し、不正値を黙って落とさず拒否する
- 版を上げる条件: 保持役の素性（R11 #2940）や `pod_netns`・provider 識別子（R12 #2941）の鍵を足すときは `v2` とする（版は完全一致のため、旧版の扱いはそれぞれの issue で決める）

## 排他

- インスタンス排他（新設・推奨）: plugin-cri の起動時に `<状態ルート>/.cri/@instance.lock` をプロセスの寿命の間 排他ロックする（期限つき `try_lock`。取れなければ固定文言で起動失敗）。同じ状態ルートに 2 つの plugin-cri が居ると再採用の前提（記録の所有者は 1 つ）が崩れるため。UDS の bind は socket ごとで足りない
- プロセス内は既存の `Mutex<SandboxRegistry>`。記録の書き込み（fsync）は registry のロックを持たずに行い、`in_flight` 等の既存フラグで同じ ID への並行操作を拒否する
- ロック順序: インスタンスロック（最外・常時）＞ registry の `Mutex` ＞ core の `StateStore` の `@lock`。記録ファイルの I/O 中に `StateStore` のロックを持たない

## 書く時点・消す時点

- sandbox: `RunPodSandbox` が副作用（保持役の起動・`set_up`）の前に `pending` 付きで書き、成功後に確定版へ置き換える。`StopPodSandbox` で状態・フラグを更新し、`RemovePodSandbox` の完了後に削除する。`pending` は「副作用が起きたかもしれない」印であり、確定版が書かれる前にクラッシュすると、保持役の素性・`pod_netns` を持たない古い記録のまま残り得る。そのため `pending` の記録は、副作用が無かったと確認できた場合に限って破棄する（次節）
- コンテナ: `CreateContainer` が core の `create` を呼ぶ前に `in_flight=create` 付きで書き（`reserve_container` の後）、`commit_in_flight` で確定版へ、`rollback_in_flight` で、削除してよい場合に限り削除する。削除してよいのは、未作成、または core の削除完了と bundle の解放成功を確認できた Create の巻き戻しだけである。Create の結果が不明な場合や bundle の解放に失敗した場合は、既存の `rollback_in_flight` と同じく記録を `CONTAINER_UNKNOWN` として保持する（消すと core に資源が残っても所有情報を失い、再起動後に回収できなくなる。CRI-2 の fail-closed）。Start / Stop / Remove の巻き戻しでは記録を削除せず、`in_flight` を戻すか unknown で保持する。Start/Stop の遷移で状態と時刻を更新し、`RemoveContainer`（core の delete と bundle の release の成功後）で削除する
- write-ahead を採る理由: #2681 で net が write-ahead を採らなかった理由（成功後か途中かを見分けられない）は、ここでは core の状態（Present/Absent）で見分けられる。逆に後書きにすると「core にコンテナがあるのに CRI 記録が無い」状態が生じ、状態ルートを CLI と共有するため plugin-cri 由来かを証明できず回収できない
- 書けなかった場合: 副作用の前なら RPC を `Internal` で失敗させる（成功を装わない）。確定・更新の書き込み失敗はメモリの記録を保持して `Internal` を返し、次の起動では古い記録と core の状態で照合される（次節の表で安全側に倒れる）
- 性能: RPC ごとに fsync が 1〜2 回増える。CORE-10 の起動 p95 への影響は #3224 で計測した（下記「計測」。暫定値）
- R4 の実装（#2933。`crates/cri/src/runtime_service.rs` の `with_record_store`・`persist_sandbox`・`remove_sandbox`）: sandbox 記録だけを書く（コンテナは R5）。注入しなければ何も書かない
  - 書く時点: ネットワークなしの Run は予約後に確定版を 1 回書く（現時点で副作用が無く、pending を書くと R6 が所有情報不足として保持し続けるため。保持役の起動を入れる #2871 がその前に pending の書き込みを足す）。pod network ありの Run は、予約後に `pending=1`・notready・`network_pending=1` を書き、`set_up` 成功後に `pending=0`・ready・`network_owned=1` へ置き換える。Stop は配下の停止とネットワークの回収が済んだ後に状態を書く（途中の失敗では書かない。ディスクの古い ready は安全側で、R6 は常に NotReady で再採用する）。Remove は資源の回収と除去条件の検査が済んだ後に、先にファイルを消してからメモリを除去する
  - ファイルを先に消す理由: この時点で資源は回収済みで、所有の証明を消しても回収不能な資源は残らない。メモリを先に消すと、削除に失敗した後の再試行が「未知 ID は成功」でファイルに触れず、孤児が再起動まで残る。削除に失敗したらメモリを残して `INTERNAL` を返す
  - 失敗の写し方: `put`・`remove`・符号化の失敗はコード（`DEADLINE_EXCEEDED`・`FAILED_PRECONDITION` を含む）によらず固定文言の `INTERNAL` にする。副作用の前の `put` の失敗は予約を戻し `set_up` を呼ばない。確定の `put` の失敗は notready のままメモリに残す（`network_owned` なので Stop・Remove が回収できる）
  - 並行操作: `SandboxRecord::record_write` を書く間だけ立て、同じ ID への Stop・Remove・CreateContainer を `FAILED_PRECONDITION` で拒否する。`put` / `remove`（fsync）は registry の `Mutex` の外で行い、書くたびにロック下でスナップショットを取り直す
  - ストア I/O の実行方式: `put` / `remove`（fsync）は `store_io_bounded` が `run_bounded` で専用スレッドの worker に渡し、`runtime_timeout` で待つ（tokio の worker を塞がない。REPAIR-5）。`record_write` の guard は worker へ move し、期限超過後も worker の完了まで保つ。副作用の前の予約を戻す `put` は、呼び出し側が手放した（期限超過・future の破棄）あとに遅れて書けた場合、worker が書いた直後に自分で `remove` する（削除を `put` の完了に順序付け、所有者の無い記録を残さない）。確定版の put の失敗（notready 化）も worker が行う。予約（`network_pending`・重複判定・件数・保持量）の解放・回復可能化は、呼び出し側（await の途中で破棄されうる）ではなく、記録ファイルの削除を行う worker 自身が削除の結果に応じて行う（責務を 1 箇所に寄せる）。削除に成功したときだけ予約を戻し、失敗したときは `network_pending` を外した notready の記録として残して Stop・Remove で回収できるようにする。put の失敗・手放し（期限超過・future の破棄）の後始末は put の worker が、set_up 失敗の回収後や起動失敗の後始末は `RemoveFinalize` つきの削除の worker が持ち、削除が終わるまで件数枠と `record_write` を保つ（ハング中の同じ metadata の Run は `ALREADY_EXISTS`、worker は sandbox 上限を超えて増えない）
  - 残余: 確定版の `put` が期限超過した後に worker が遅れて成功した場合と、set_up 失敗の回収後の `remove` が失敗した場合は `pending=1` の記録がディスクに残る（メモリには notready の記録が残り Remove で再回収できる。ディスク側は R6 の pending 解決に委ねる）。Remove の途中で配下の状態が変わりメモリを除去できなかった場合は、記録を書き直して `INTERNAL` を返す（best effort）。Remove の連鎖で消える配下のコンテナ記録ファイルは R5 で扱う（下記）
- R5 の実装（#2934。`InFlightGuard` の `arm_record_store`・`write_ahead`・`commit`・`remove_record`）: コンテナ記録の書く・消す時点を足す。書くのは実行層接続時（`with_runtime` と `with_record_store` の両方を注入）の経路だけで、スタブ経路（`*_impl`）は書かない（core に所有者の無い記録で、R7 の照合の対象にならないため）。I/O はすべて既存の `run_bounded` の worker（guard の所有者）の中で同期的に行い、registry の `Mutex` は持たない。同じ ID への並行操作は既存の `in_flight` が直列化する
  - 順序: Create は `reserve_container` の後、worker の先頭で `in_flight=create` を書き（write-ahead）、`prepare` → core の `create` → 確定版（`attach_prepared` が反映した `user`・`image_*`・`stop_signal` を含む）の順。Start は core の `start` の成功後に running と `started_at`、Stop は core の `stop` の成功後に exited・`finished_at`・終了コード・終了理由を書く。Remove は core の `delete` と bundle の解放の成功後に記録ファイルを消す。`ContainerConfig.envs` は符号化が複製側で消すため書かない
  - 確定版は put してからメモリを commit する（put→commit）: 確定後に put すると、`in_flight` が外れた後に並行する Remove がファイルを消し、遅れた put が所有者の無い記録を作り直す。put の内容は確定後の値の投影（同じ時刻を使う）
  - 失敗の写し方: write-ahead の失敗は `prepare`・`create` を呼ばず固定文言の `INTERNAL`（guard の `Drop` が bundle の解放の後に記録の削除を試みる）。確定・更新の put の失敗はメモリを確定したまま固定文言の `INTERNAL`（Start の確定が親 sandbox の notready で失敗した場合は、ディスクに running が先に書かれるが、再採用時の状態は core を正とするため許容する）。Create の巻き戻しは「未作成」または「削除完了と bundle の解放を確認できた」場合に限って記録を消し、記録の削除に失敗したときは結果不明と同じ扱い（unknown・`runtime_owned` で保持し、RemoveContainer の delete〔NOT_FOUND〕→ 解放〔冪等〕→ 削除で回収する）。Remove の記録の削除に失敗したときは bundle の解放失敗と同じ扱い（exited で保持して再試行）
  - 書かないもの: `in_flight=start` / `stop` / `remove` の write-ahead（再採用時の状態は core を正とするため不要。必要になれば R7 で判断）。結果不明（unknown）に倒すときはファイルを書き直さない（最後に書いた内容のまま。`in_flight=create` で core が Present なら R7 の表で `CONTAINER_UNKNOWN`＋`runtime_owned` になる）
  - 連鎖削除: 実行層接続時の RemovePodSandbox は `runtime_owned` の配下を `runtime_remove_one` が 1 件ずつ処理し、その中で記録ファイルが消える。連鎖（`apply_sandbox_removal`）で消えるのは `runtime_owned` でない配下だけで、ファイルを持たない（ファイルを書く時点より前に `runtime_owned` が立つか、巻き戻しの失敗で `runtime_owned` を立てるため）。配下の記録ファイルを sandbox ファイルより先に消す追加の処理は、この不変条件により不要と判断した

## 計測（#3224・暫定値）

CRI 記録の fsync が RPC のレイテンシと CORE-10 の起動 p95 に与える影響の計測。CI の数値は使っておらず、手元の実測による**暫定値**である。基準値の確定（#230）とは別のもので、`benches/metrics.json`・`BENCH_NAMES`・baseline には登録せず、CI のゲートにも接続しない（REPAIR-8）。

- ハーネス: `crates/cri/benches/record_store_rpc_latency.rs`（`harness = false`。依存の追加なし）。実行は `cargo bench -p fandhe-container-cri --bench record_store_rpc_latency -- --state-root <既存ディレクトリの絶対パス> --trials 1000 --warmup 50 --host-kind <bare-metal|vm|wsl2> --output <新規ファイル>`。引数なしは I/O をしないスモーク（終了コード 0）
- 方法: フェイクの `ContainerRuntime`・`BundleProvider` を `with_runtime` で注入した同一構成で、記録ストア（`FileRecordStore`）を注入した構成（with）と注入しない構成（without）を、試行ごとに順序を入れ替えて回す。1 試行は RunPodSandbox → CreateContainer → StartContainer → StopContainer → RemoveContainer → StopPodSandbox → RemovePodSandbox。RPC の `.await` の前後を計り、p50・p95 は nearest-rank。with では RPC ごとの記録ストアの操作件数（Run 1 put、Create 2 put、Start 1 put、Stop 1 put、Remove 1 remove、StopPod 1 put、RemovePod 1 remove）を機械照合し、不一致は失敗にする
- 読み方: 実行層がフェイクのため、絶対値は CRI 層の費用だけで core の起動費用を含まない。with − without の差は、fsync に加え、sandbox 側の `store_io_bounded`（期限つき実行の専用スレッド生成）の費用を含む。本番でも払う費用なので差の全部を fsync とは呼ばない
- 条件（共通）: release（bench profile）・1000 試行（ウォームアップ 50）・Intel Core i7-13700K（10 コア）・KVM ゲスト（`systemd-detect-virt` = kvm、`--host-kind vm`）・カーネル 7.0.0-34-generic・実行中の load average は約 3〜4（他の並列ビルドあり）・計測日 2026-10-28・base コミット `18c6897f`
- 状態ルートの FS: tmpfs（`/run/user/1000`。rootless の既定の状態ルート `$XDG_RUNTIME_DIR/fandhe-container` と同じ種類。rootful の `/run/fandhe-container` も通常は tmpfs）と ext4（`/dev/sda1` 上の `$HOME/.cache` 配下。ディスク上の FS の例）

RPC のレイテンシ（µs。p50 / p95。差は with − without）:

| RPC | tmpfs without | tmpfs with | tmpfs 差 | ext4 without | ext4 with | ext4 差 |
| --- | --- | --- | --- | --- | --- | --- |
| RunPodSandbox | 1 / 3 | 51 / 90 | 49 / 86 | 3 / 6 | 1511 / 2136 | 1507 / 2130 |
| CreateContainer | 37 / 65 | 69 / 123 | 31 / 58 | 51 / 86 | 2970 / 3780 | 2918 / 3694 |
| StartContainer | 35 / 62 | 56 / 105 | 21 / 43 | 45 / 80 | 1514 / 2171 | 1468 / 2091 |
| StopContainer | 33 / 62 | 51 / 92 | 18 / 29 | 44 / 73 | 1509 / 2170 | 1465 / 2097 |
| RemoveContainer | 35 / 63 | 44 / 75 | 9 / 11 | 43 / 67 | 762 / 875 | 718 / 807 |
| StopPodSandbox（参考） | 0 / 1 | 49 / 90 | 48 / 88 | 1 / 2 | 1506 / 2124 | 1505 / 2122 |
| RemovePodSandbox（参考） | 0 / 1 | 43 / 78 | 43 / 76 | 1 / 1 | 759 / 867 | 758 / 865 |

`put` / `remove` 1 回の所要時間（µs。p50 / p95）。上段は RPC 経由で記録器が受けた値（1000 試行分の件数: container put 4000・sandbox put 2000・remove 各 1000）、下段は `FileRecordStore` を直接呼んだ値（container 記録・同一内容の 1 KiB / 4 KiB・各 500 回）:

| 操作 | tmpfs | ext4 |
| --- | --- | --- |
| put（container・RPC 経由） | 10 / 28 | 1431 / 2093 |
| put（sandbox・RPC 経由） | 10 / 29 | 1444 / 2076 |
| remove（container・RPC 経由） | 6 / 18 | 696 / 807 |
| remove（sandbox・RPC 経由） | 5 / 17 | 696 / 799 |
| put（直接・1 KiB / 4 KiB） | 6 / 17、6 / 10 | 1369 / 1802、1380 / 1732 |
| remove（直接・1 KiB / 4 KiB） | 4 / 9、4 / 4 | 659 / 777、668 / 750 |

CORE-10 への当てはめ（CORE-10 の目標 0.136 秒、Linux の Docker 0.290 秒）: 起動経路（Run → Create → Start）で増えるのは、sandbox の put 1 回と container の put 3 回、RPC の差の合計は Run + Create + Start。いずれも p95 の単純な足し算で、実際の p95 の合成ではない。

| FS | put 4 回の p95 合計 | RPC 差の p95 合計 | 目標 0.136 秒に対する割合 | Docker 0.290 秒に対する割合 |
| --- | --- | --- | --- | --- |
| tmpfs | 約 113 µs | 約 187 µs | 約 0.08〜0.14% | 約 0.04〜0.06% |
| ext4 | 約 8.4 ms | 約 7.9 ms | 約 5.8〜6.1% | 約 2.7〜2.9% |

判断:

- 先に決めた閾値は、tmpfs で目標の 1% 以上、またはディスク上の FS で目標の 5% 以上なら後続の案を書く。tmpfs（既定の状態ルート）は閾値を大きく下回り、現時点で後続は不要。ディスク上の FS（ext4）は閾値の 5% をわずかに超える
- 状態ルートがディスク上にあるのは、`--state-root` の明示や `XDG_RUNTIME_DIR` を持たない環境など既定から外れた運用に限られる。この計測だけでは、そうした運用を CORE-10 の対象に含めるかは決まらない。オーナーの判断を待つ選択肢として、次を並べる（決定ではない）
  1. 状態ルートを tmpfs に置く運用を前提として明記する（コードの変更なし）
  2. CreateContainer の write-ahead と確定版の fsync を、安全が崩れない範囲で 1 組にまとめる（put 4 → 3 回）
  3. 一時ファイルの fsync を `fdatasync` 相当にする。ディレクトリの fsync と合わせた耐久性の保証を再確認してから決める
  4. 安全と言える箇所（write-ahead の後始末など）でディレクトリの fsync を省く
- 再計測は上記コマンドで手元で行える。値は FS・ホストの種類・負荷で大きく変わるため、他の環境では取り直す

## 起動時の読み込みと照合（fail-closed）

- `main.rs` の `serve` が `recover_stale_image_pulls` と同じ位置で、受付前に 1 回だけ読む。1 件ごとの期限と全体の期限を持つ（REPAIR-5。containerd の 10 秒/件を参考に値は実装単位で決める）。件数は `MAX_SANDBOXES`・`MAX_CONTAINERS`、保持量の上限を超えたら起動を失敗させる
- sandbox を先に読み、コンテナは所属 sandbox が読めたものだけ採用する（親の無いコンテナ記録は壊れた記録と同じ扱い）
- コンテナの状態は core を正とする（`StateStore::get` を container-ref-reconcile.md 決定 3 の写し方で）

| CRI 記録 | core | 再採用後 |
| -------- | ---- | -------- |
| 確定（Created/Running/Exited） | Present | core の status へ写す（Running→running、Stopped→exited、Created→created）。終了コードは記録の値、無ければ不明（reason 空） |
| 確定 | Absent | exited＋unknown 扱い（記録は保持。Remove で解放。bundle の release は Remove 時） |
| `in_flight=create` | Absent | create は完了していない。記録を削除し、自分が作った bundle（`.cri/bundles/<id>`）を release |
| `in_flight=create` | Present | `CONTAINER_UNKNOWN` で保持し `runtime_owned=true` に復元する（Remove が core の delete 経由で回収。再 Start は拒否） |
| `in_flight=start/stop` | Present | core の status へ写す。Running なら running |
| `in_flight=remove` | Present/Absent | Remove の続き待ちとして unknown で保持（kubelet の再試行で完了） |
| 任意 | Undetermined | `CONTAINER_UNKNOWN` で保持（fail-closed。何も消さない） |

- `runtime_owned`（Stop/Remove が core の呼び出しに進むかを決める既存のフラグ。true のときだけ core の `stop`/`delete` を呼ぶ）は記録に書かず、再採用時に次の規則で導く。`in_flight=create` の記録は core の `create` より前に書かれるため、復元した値をそのまま使うと false になり、kubelet の Remove が core の `delete` を呼ばずに CRI の記録だけを消して core の資源が回収不能になる
  - core が Present: 状態や `in_flight` の種別を問わず true（`in_flight=create` を含む）。Stop/Remove は core の `stop`/`delete` に進む
  - core が Absent: `in_flight=create` は上表のとおり記録を破棄するので登録しない。確定の記録は exited＋unknown で保持し false（core に呼ぶ先が無い。Remove は CRI の記録と bundle の解放だけを行う）
  - core が Undetermined: true（fail-closed。Stop/Remove は core 側の応答に委ね、CRI の記録だけを先に消さない）
  - 試験で、`in_flight=create` かつ Present の復元後に Remove が core の `delete` を 1 回呼ぶこと、Absent では呼ばないことを固定する
- sandbox の状態は再採用時に必ず `SANDBOX_NOTREADY` にする（保持役は再起動で終了しているため。要確認事項 1 の (b)）。`network_owned`・`network_pending` は保持し、Stop/Remove で回収を試みる。ただし `pending` の sandbox 記録は次の規則で先に解決する
- `pending` の sandbox 記録（`RunPodSandbox` が保持役の起動と `set_up` の前に書いたまま確定しなかったもの）: sandbox には core の `StateStore` の行が無く、Present/Absent では副作用の前に落ちたのか `set_up` の後に落ちたのかを見分けられない。そこで起動時の読み込みの一部として次の順で扱う（Stop/Remove の入口ではなく受付前に 1 回だけ。CORE-1）
  1. 記録に保持役の素性（pid・starttime・ns の dev:ino）と `pod_netns` が書かれていれば、実在を所有確認で調べる。pid からパスやシグナル先を作らない（前節）。確認の対象は、固定の置き場から導いた netns と、所有記録と照合できる資源だけ
  2. 副作用が無かったと確認できた場合だけ記録を破棄する（`pending` の記録ファイルを消し、登録しない）。確認できるのは、副作用の前に書いた `pending` の時点で、固定の置き場の netns・所有記録と照合できる資源・保持役の痕跡のいずれも存在しないと、期限内に I/O エラーなく走査し終えた場合に限る。所有を証明できないこと（素性や `pod_netns` が記録に無い、所有確認で一致しない）は資源が無いことを意味しない。この場合は判定不能（4）として扱い、記録を破棄しない
  3. 資源の実在を証明できた場合は、`ready` へは昇格させない（保持役が再起動で終了しており、再採用後は常に `SANDBOX_NOTREADY`）。`NOTREADY` で登録し、`network_pending` を解除した上で `network_owned=true` に復元する。予約時（`RunPodSandbox` の副作用前）の記録は `network_owned=false` であり、`set_up` の実行中や成功後の確定保存前にクラッシュすると false のまま残る。これをそのまま保持すると、Stop/Remove が `!network_owned` として `tear_down` を省略してしまい、資源が回収不能になる。Stop/Remove が `tear_down` と取り残しの回収（ネットワーク資源の節）を試みる。これが、`set_up` の worker が既に無いのに `network_pending` が残って Stop/Remove が永久にブロックされる事態を防ぐ
  4. 判定不能（所有確認が期限内に終わらない・I/O エラー・素性が部分的にしか読めない・所有情報が不足して副作用が無かったと確認できない）は fail-closed（CRI-2）: 記録を消さず、`network_pending` を解除して `NOTREADY` で登録し、資源があり結果が不明なものとして 3 と同じく `network_owned=true` 相当の回収待ちを復元する。Stop/Remove で回収を試み、回収できない分は記録を残したまま固定文言の `FailedPrecondition` で手動回収と知らせる（何も勝手に消さない）
  - どの分岐でも、再採用後に `network_pending` を持つ sandbox を残さない（`set_up` の担い手が再起動で失われるため、解除の主体は読み込み時の照合だけ）
  - 試験で、`pending` ＋副作用なしと確認できた→破棄、`pending` ＋資源あり→`NOTREADY` で `network_pending` なし・`network_owned=true`、`pending` ＋所有情報不足（素性・`pod_netns` なし）→記録を保持、判定不能→`NOTREADY` で保持・`network_owned=true`、のそれぞれの後に Stop/Remove が `tear_down` を省略せず、完了または固定文言の失敗で返りブロックしないことを固定する
- 壊れた記録（復号失敗・ファイル名と ID の不一致・上限超過・親 sandbox なし）は、ファイルを消さず登録もしない。失敗件数を記録器（`cri.record_store_load`）と固定語彙の stderr 1 行に出す（ID・パスは出さない）。手動回収の手順は `docs/setup/cri-record-recovery.md`（実装単位 R10）に置く
- R6 の実装（#2935。`crates/cri/src/runtime_service/readopt.rs` の `CriRuntimeService::readopt_sandboxes`）: sandbox 記録だけを再採用する（コンテナの再採用と core の状態との照合は R7）。記録ストア未注入なら何もせず、registry が空でなければ `FAILED_PRECONDITION`。列挙の失敗・件数または保持量の上限超過・全体の期限切れは起動失敗で registry は空のまま（壊れた記録も件数・走査数に数えられる fail-closed）。登録する値は常に `NotReady`・`network_pending=false`・`pod_netns=None`。`pending=1` または `network_pending=1` の記録は、v1 に保持役の素性も `pod_netns` も無く「副作用が無かった」と確認できないため、上の分岐 4 に当たるものとして破棄せず `network_owned=true`（回収待ち）へ倒す。分岐 2・3 の精緻化は R11（#2940）・R12（#2941）まで常に 4 になる。再採用中に `PodNetworkProvider` と実行層は呼ばず、記録のファイルは書き換えない・消さない。metadata が重複する記録は ID の小さい方だけ登録し、残りは `duplicate_metadata` として壊れた記録に数える（ALREADY_EXISTS の不変条件の維持）。`port_mappings` は記録を信頼して `UNIMPLEMENTED` の再適用をしない。計測は `cri.record_store_load` を採用 1 件ごとに成功、壊れた記録 1 件ごとに失敗（復号失敗・重複は `INVALID_ARGUMENT`、他は `DATA_LOSS`）で出し、`SandboxReadoption::summary_line` が固定語彙の 1 行を返す（stderr への出力と `serve` への配線は R9）。残余: provider の `tear_down` は未知の ID を `Ok` にするため、再起動後のネットワーク資源の回収は R12 まで不完全
- R7 の実装（#2936。`readopt.rs` の `CriRuntimeService::readopt_containers`。純粋関数 `reconcile` に 15 セルを集める）: `readopt_sandboxes` の後に 1 回だけ呼び、所属 sandbox を再採用できたコンテナ記録だけを登録する。core の状態は `RuntimeAdapter::state`（`ContainerRuntime::state` → `StateStore::get`）を **記録にある ID だけ** 1 件ずつ `min(per_record, 全体の残り)` の期限つきで照会する（切り離したスレッド。registry の `Mutex` は持たない）。応答は Present（状態あり）・Absent（`NOT_FOUND` だけ）・Undetermined（`INTERNAL`〔ID 不一致を含む〕・`DEADLINE_EXCEEDED`・`UNAVAILABLE`・`PERMISSION_DENIED`・`UNIMPLEMENTED`・1 件の期限切れ・実行層未注入）に写す。呼ぶのは `state` だけで、`delete`・`stop`・`kill`・`start`・`RecordStore::put` / `remove`・`BundleProvider::release` は呼ばず、記録のファイルを書き換えない・消さない
  - 登録する記録はどれも `in_flight=false`。確定・`in_flight=start` / `stop` は Present で core の lifecycle を写し（Created→created・Running→running・Stopped→exited・Creating / Unknown→unknown）`runtime_owned=true`、Absent で exited（終了コード・時刻は記録の値で、core の値では上書きしない。無ければ不明）＋`runtime_owned=false`。`in_flight=create` は Present で unknown＋`runtime_owned=true`（再 Start は親 sandbox が NotReady のため拒否）、Absent は **登録しない**（`stale_create`。ファイルも bundle も触らず、ID を `ContainerReadoption::stale_create_ids` で R8 #2937 へ渡す）。`in_flight=remove` は Present / Absent とも unknown（Remove の続き待ち）。Undetermined はすべて `CONTAINER_UNKNOWN`＋`runtime_owned=true`
  - 判断: `in_flight=remove` × Absent を `runtime_owned=true` にする。偽だと kubelet の再試行が `drop_container` によるメモリ上の除去だけになり、記録ファイルと bundle が残って「再試行で完了」が成り立たない。真なら `delete` の `NOT_FOUND` を許容して bundle の release → 記録の削除 → commit まで進める（試験で固定）。`in_flight=start` / `stop` × Absent は上の表に行が無く、R5 が write-ahead を書かないため v1 では生じないが、復号器は受理するので確定 × Absent と同じに扱う
  - 親 sandbox が registry に無い記録は壊れた記録（`parentless`）として数え、登録も照会も削除もしない。`(pod_sandbox_id, name, attempt)` が重複する記録は、`stale_create` を除いた後で ID の小さい方だけ登録し残りは `duplicate_metadata`。CRI 記録の無い core のコンテナは構造上照会されない。保持量は復号した config 分に `resolved_log_path` の長さと `identity_retained_extra`（`attach_prepared` と共通の式）を足して数え直す。件数・保持量の上限超過（`FAILED_PRECONDITION`）と全体の期限切れ（`DEADLINE_EXCEEDED`）は起動失敗で registry は空のまま。計測は `cri.record_store_load` を登録 1 件・`stale_create` 1 件ごとに成功、復号失敗・重複は `INVALID_ARGUMENT`、親なし・読めない記録は `DATA_LOSS` で出し、`ContainerReadoption::summary_line`（`kind=container`）が固定語彙の 1 行を返す（stderr への出力は R9）
  - 残余: (1) 確定 × Absent の記録（`runtime_owned=false`）は、RemoveContainer / RemovePodSandbox の連鎖が `drop_container` でメモリを除くだけで **記録ファイルと bundle が残る**（安全側。R5 の連鎖削除の段落の「`runtime_owned` でない配下はファイルを持たない」は、再採用した Absent の記録では成り立たない）。release と記録の削除は R8 #2937 の範囲。(2) `stale_create` の記録の削除と bundle の release、孤児 bundle の回収も R8。(3) 写像先が exited のときに core の `exit_code` や終了時刻を使う案は、設計の「終了コードは記録の値」に従って採らなかった（要すれば後続で判断）
- R8 の実装（#2937。R7 の残余 (1)(2) への対応。OCI-7・CRI-1・SEC-1・REPAIR-3/4/5）:
  - `stale_create`: `CriRuntimeService::release_stale_creates`（cri）が `readopt_containers` の直後に 1 回、`stale_create_ids` の各 ID を core へ再照会し、`NOT_FOUND` だけのときに `BundleProvider::release` → `RecordStore::remove` の順で消す（所有の証明である記録は最後）。Present・Undetermined は何もしない。解放・削除の失敗と期限切れは件数（`StaleCreateRelease`。固定語彙の `summary_line`）に数えるだけで起動を止めない（記録が残るので次回起動で再び拾われ、release は不在を成功とするため冪等）。registry には触れない
  - 確定 × Absent（`runtime_owned=false`）の Remove: 実行層接続時にこの組が生じるのは再採用だけ（Create の巻き戻しは記録を消すか `runtime_owned=true` にする）。`RemoveContainer` は `runtime_remove_one` の `call_core=false` で core の `delete` を呼ばず、bundle の解放 → 記録ファイルの削除 → 確定だけを行う。`RemovePodSandbox` は配下の全コンテナを 1 件ずつ処理し、件ごとに `call_core` を決める。失敗は exited・`in_flight=false` で保持し再試行で完了する
  - 孤児 bundle: インスタンスロックの型（`InstanceLock`）が plugin-cri にあるため、回収は plugin-cri の `orphan_bundles::reclaim_orphan_bundles`（`&InstanceLock` を引数に取る）と `CriPluginBackends::reclaim_orphan_bundles`（ロックを持たない backends は `FAILED_PRECONDITION`）。候補は `SpecBundleProvider::list_bundle_ids`（root の dev/ino 照合、`symlink_metadata` だけで判定、採番の形〔64 桁の小文字 16 進〕以外と非ディレクトリは数えて触らない、走査数の上限 `MAX_CONTAINERS × 2 + 64`）。記録ファイルのある ID は **読めない・壊れた記録でも** 所有の証明として残し（手動回収は R10）、記録の列挙に失敗したら何も回収しない。記録の無い ID は core が `NOT_FOUND` のときだけ解放する。core の 3 値の写し方は `probe_core_presence` を R7 と共有する
  - 呼び出し順（R9 #2938 が受付の開始前に 1 回だけ配線済み。常駐ループは作らない）: `readopt_sandboxes` → `readopt_containers` → `release_stale_creates` → `reclaim_orphan_bundles`。解放に失敗した `stale_create` の記録が残る間はその bundle が孤児扱いにならないため、この順が要る
  - 残余: 照会から解放までの窓は、受付の開始前・インスタンスロックの下・CLI は `.cri/bundles` を使わない、の 3 点で許容する。`put` の一時ファイル `.tmp-*` は R2 の残余のまま。`serve` への配線と要約行の出力は R9 で実装済み（下記）
- R9 の実装（#2938。plugin-cri の本番配線。CRI-1・CRI-2・CORE-1・REPAIR-4・REPAIR-5）:
  - 配線位置: `main.rs::serve` が、インスタンスロックの取得（`production*`）→ bundle の供給 → `production_record_store`（`FileRecordStore::open`）→ ImageService → pull の回収の後、tokio runtime を作る前に、記録ストアを注入した `CriRuntimeService`（`runtime_service_with_record_store`）を組み、`CriPluginBackends::readopt_records`（`record_readoption::run_startup_readoption`）を 1 回だけ呼ぶ。手順は bin の中でなく lib（`record_readoption`）に置く（`InstanceLock` が `pub(crate)` で、試験から呼べるようにするため）。順序は `readopt_sandboxes` → `readopt_containers` → `release_stale_creates` → 孤児 bundle の回収。
  - 予算: `STARTUP_RECORD_READOPTION_BUDGET`（1 件 10 秒・全体 120 秒）を 4 段で分け合う（各段には全体の残りを渡す）。起動の最悪時間は pull の回収（60 秒）との合計。
  - 起動を止める条件: sandbox・コンテナの再採用の `Err`（列挙の失敗・件数または保持量の上限超過・期限切れ）、`release_stale_creates` の `Err`（registry 汚染という前提違反）、記録ストアを開けない、ロックを持たない backends での呼び出し。stderr は `error: <CODE>: failed to readopt cri records`（固定文言。ID・パスを含めない）で exit 1。止めない条件: 壊れた記録（消さず・登録せず件数に数える）、`stale_create` の解放失敗、孤児 bundle の回収の失敗・期限切れ（余分に残す側）。
  - 要約行: 何かを再採用・回収したときだけ、4 段の `summary_line()` を ` | ` でつないだ 1 行を stderr へ出す。4 段とも空（初回起動など）なら出さない。固定語彙で ID・パス・config を含まない。
  - 計測: 再採用は既存の `cri.record_store_load`（採用 1 件ごとに成功、壊れた記録 1 件ごとに失敗）。記録ストアの操作は `CoreRecordStoreRecorder` が共有 `OpRecorder` へ `cri.record_store.{put,remove,list}` の 3 名で成功 / 失敗に縮約して流す（結果区分・種別は名前に混ぜず、`MAX_TRACKED_OPS` の枠を使い切らない）。
  - 試験: `crates/plugin-cri/tests/container_grpc.rs` の段 D（実バイナリを同じ状態ルートで 2 回、さらに 3 回起動。SIGKILL 後に sandbox が `SANDBOX_NOTREADY`・コンテナが `CONTAINER_CREATED` で見えること、壊れた記録と孤児 bundle の注入、Remove での所有の復元、1025 件の記録での起動失敗）と `tests/record_readoption.rs`（4 段の順序・要約行・`Err` の素通し・ロックの要求）。いずれも root 不要の既定の集合。
  - 残余: 手動回収の手順書は R10 #2939、保持役の素性による pending の解決は R11 #2940、`pod_netns` の永続と再起動後の `tear_down` は R12 #2941、running のコンテナを残した実機での再起動確認は R13 #2942。SIGTERM の正常停止は未実装のため、試験は SIGKILL で止める。
- core に状態があるが CRI 記録の無いコンテナは触らない（CLI と状態ルートを共有するため所有を証明できない）
- 孤児 bundle（`.cri/bundles/<id>` で CRI 記録が無く core が Absent〔`NotFound` だけ〕）は、インスタンスロックの下でだけ回収する。Undetermined は残す

## 保持役の pid と素性

- 記録項目（#2871 以降）: pid、`/proc/<pid>/stat` の starttime、`/proc/<pid>/ns/{user,ipc,net}` の dev:ino
- 再採用した記録の pid からは決して namespace のパスを作らず、シグナルも送らない。plugin-cri はもう親でなく、zombie による pid 固定が効かないため（SEC-5 の P0・SEC-1）。用途は診断と、終了済みであることの確認だけ
- 要確認事項 1 で (a) を採る場合だけ、pidfd で開いて starttime と ns の素性を照合した上で再採用する。(a) が選ばれた場合の追加単位（保持役の切り離し起動と pidfd 照合）は、判断の後に起票する（本 issue では起票しない）

## ネットワーク資源

- `network_owned`・`pod_netns`（パス）と、provider が `tear_down` に要る識別子をフラグとして永続化する。`pod_netns` のパスは ID と固定の置き場から導くか、所有記録と照合してから使う
- 再起動後の `tear_down` は、`CreatedNetwork`・IPAM が未永続（#1870）のため成功できない。network-reclaim-persistence.md の「復元したネットワーク」と同じく、取り残しの回収（veth・pin は所有の証明つき）を試み、本体は固定文言の `FailedPrecondition` で手動回収と知らせる。丸ごと復旧できるとは書かない
- 本番は provider を未注入のため、現時点の本番では該当しない

## core の状態ストアとの関係と CORE-1

- core の `StateStore` が実行時状態（status・pid・supervisor・cgroup）の正、CRI 記録は CRI 層だけの項目の正とする。CRI 記録から pid・シグナル先を導かない。`StateStore` の二つ目の実装を作らない（PLUG-1・crate-naming.md 決定 6）
- 却下案:
  - core の `StateRecord` に CRI の blob を足す: core のトレイト契約の変更になり、sandbox は core に記録が無く、CRI-7 の境界に反する
  - 中央の常駐の照合ループ: CORE-1 に反する。照合は起動時の 1 回と各 RPC の入口だけ
- CORE-1: 新しい常駐プロセスを置かない。常駐するのは CRI サーバーとしての plugin-cri だけ（既存の前提）。記録はただのファイル

## containerd との差

一次情報は containerd の commit `cfb18c48f865669d497115c1734e94fedc338153` で確認した。

- [internal/cri/server/restart.go](https://github.com/containerd/containerd/blob/cfb18c48f865669d497115c1734e94fedc338153/internal/cri/server/restart.go)（45〜53 行の前提コメント、`recover`、`loadContainerTimeout`〔262 行〕、`status.Unknown = true`〔421 行〕、`cleanupOrphanedIDDirs`〔449 行〕）
- [internal/cri/server/podsandbox/recover.go](https://github.com/containerd/containerd/blob/cfb18c48f865669d497115c1734e94fedc338153/internal/cri/server/podsandbox/recover.go)（`RecoverContainer`〔51 行〕。既定 `StateUnknown`〔82 行〕、タスク無しは `StateNotReady`、running なら `StateReady`〔131 行〕）
- [internal/cri/store/container/status.go](https://github.com/containerd/containerd/blob/cfb18c48f865669d497115c1734e94fedc338153/internal/cri/store/container/status.go)（`Unknown` は checkpoint しない〔91〜98 行〕、`StoreStatus` が `status` ファイルを `AtomicWriteFile` で書く〔167〜175 行〕）

| 観点 | containerd | 本設計 |
| ---- | ---------- | ------ |
| メタデータ | 中央デーモンのメタデータストアと、コンテナごとの status checkpoint（`status.go`） | 常駐の中央なし。core の `state.json` と CRI 記録ファイル |
| 前提 | plugin の停止中、ファイルと checkpoint に触れず、コンテナが追加されない（`restart.go` の前提コメント） | 前提にできない（CLI と状態ルートを共有）。所有の証明（CRI 記録）と core の照合で置き換える |
| sandbox | task の状態を引き、取れなければ Unknown→NotReady。running なら Ready（`podsandbox/recover.go`） | 保持役が再起動をまたがないため常に NotReady（(a) 採用時は素性の照合つきで Ready） |
| コンテナ | 10 秒/件で読み、失敗すれば `Unknown`（checkpoint の他の項目は残す） | core を正に写し、不明は `CONTAINER_UNKNOWN`。期限つき |
| 孤児ディレクトリ | `cleanupOrphanedIDDirs` で削除 | CRI 記録なしかつ core が Absent の bundle だけ回収 |
| 自動停止 | しない | しない（kubelet の Stop/Remove に委ねる） |

## 要確認事項（オーナー判断は未取得。既定は安全側）

1. 保持役を再起動をまたいで生かすか
   - (a) supervisor と同じ `systemd-run --user --scope` で切り離して起動し、pidfd・starttime・ns の素性照合で再採用する。#2838 の「直接の子・zombie で pid 固定」と H2（#2874）の修正が要る。#2874 は open なので、採るなら H2 の前に設計を改める
   - (b) #2838 のまま。再起動後は NotReady で、kubelet が pod を作り直す
   - 既定は (b)
2. `ContainerConfig` の `command`・`args` も記録から除くか（推奨は envs だけ除く）
3. インスタンスロックの導入（推奨）

## 実装単位

すべて #2778 の sub-issue で `phase:7`。

| 記号 | issue | 内容 | 依存 |
| ---- | ----- | ---- | ---- |
| R1 | #2930 | cri: sandbox・コンテナ記録の符号化と厳密な復号 | なし |
| R2 | #2932 | cri: 記録ストアのトレイトとファイル実装 | R1 |
| R3 | #2931 | plugin-cri: 状態ルートのインスタンス排他 | なし |
| R4 | #2933 | cri: `with_record_store` の注入点と sandbox の書く・消す時点 | R2 |
| R5 | #2934 | cri: コンテナの書く・消す時点 | R4 |
| R6 | #2935 | cri: 起動時の sandbox の再採用 | R4 |
| R7 | #2936 | cri: 起動時のコンテナの再採用と core の状態との照合 | R5・R6 |
| R8 | #2937 | cri: 再採用したコンテナの bundle の release と孤児 bundle の回収 | R7 |
| R9 | #2938 | plugin-cri: 本番の配線と再起動の結合試験 | R3・R7・R8 |
| R10 | #2939 | docs: 照合できない記録の見分け方と手動回収の手順 | R9 |
| R11 | #2940 | cri: 保持役の素性の記録と再採用時の扱い | #2871・#2877・R6 |
| R12 | #2941 | cri / plugin-cri: `network_owned`・`pod_netns` の永続と再起動後の `tear_down` | #1870・#2879・R6 |
| R13 | #2942 | 実機確認（人間担当）: running のコンテナを残した再起動と再採用（手順書: [plugin-cri-restart-readoption.md](../verification/plugin-cri-restart-readoption.md)） | R9 |

## セキュリティ上の要点

- 記録のパスは状態ルート配下の固定位置とサービス採番の ID だけから作り、記録内のパス文字列を信頼しない
- 置き場は 0700・状態ルートと同じ所有者。インスタンスロックで別の plugin-cri との書き込み競合を防ぐ。CLI のコンテナには触らない
- 読み込みは件数・長さ・保持量の上限つきで、1 件ごと・全体の期限つき（REPAIR-5）
- 記録は再起動時に untrusted として厳密に復号し、`config_limits` を再適用する
- 再採用した保持役の pid から namespace のパスを作らず、シグナルも送らない（#2776）
- `envs` を記録に書かない。エラー文言・ログに ID・パス・config の値を載せない（REPAIR-4）
