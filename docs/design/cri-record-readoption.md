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
| 状態ルートを単一の plugin-cri に固定する排他は無い（UDS の bind は socket 単位） | 現状のコード |

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

## 形式

- serde を使わない。固定のヘッダ行（LF・ASCII。版の行 `fandhe-cri-sandbox-record v1` / `fandhe-cri-container-record v1`、キー順固定のスカラー項目）と、`config=<長さ>` の行に続く長さちょうどの prost 符号化した `PodSandboxConfig` / `ContainerConfig`。prost は既存依存で、新規依存は足さない
- 復号は厳密にする。版の完全一致・キー順固定・重複/未知キー/余分な行/CRLF なし・ID とファイル名の一致・長さの上限（config は `MAX_CONFIG_ENCODED_BYTES`、記録全体の上限を先に確認）。復号後に `config_limits` と同じ上限検証を通し、RunPodSandbox/CreateContainer と同じ上限を再採用時にも効かせる。違反は `InvalidArgument`（入力値をメッセージに載せない。REPAIR-4）
- 秘密の最小化: `ContainerConfig.envs` は記録に書かない（Status/List は返さず、bundle 作成後は不要）。`command`・`args` も応答に出ないため書かない案があるが、推奨は envs だけを除く（要確認事項 2）
- 保持量（`retained_bytes`）は読み込み時に再計算し、記録に書かない

## 排他

- インスタンス排他（新設・推奨）: plugin-cri の起動時に `<状態ルート>/.cri/@instance.lock` をプロセスの寿命の間 排他ロックする（期限つき `try_lock`。取れなければ固定文言で起動失敗）。同じ状態ルートに 2 つの plugin-cri が居ると再採用の前提（記録の所有者は 1 つ）が崩れるため。UDS の bind は socket ごとで足りない
- プロセス内は既存の `Mutex<SandboxRegistry>`。記録の書き込み（fsync）は registry のロックを持たずに行い、`in_flight` 等の既存フラグで同じ ID への並行操作を拒否する
- ロック順序: インスタンスロック（最外・常時）＞ registry の `Mutex` ＞ core の `StateStore` の `@lock`。記録ファイルの I/O 中に `StateStore` のロックを持たない

## 書く時点・消す時点

- sandbox: `RunPodSandbox` が副作用（保持役の起動・`set_up`）の前に `pending` 付きで書き、成功後に確定版へ置き換える。`StopPodSandbox` で状態・フラグを更新し、`RemovePodSandbox` の完了後に削除する。`pending` は「副作用が起きたかもしれない」印であり、確定版が書かれる前にクラッシュすると、保持役の素性・`pod_netns` を持たない古い記録のまま残り得る。そのため `pending` の記録は、副作用が無かったと確認できた場合に限って破棄する（次節）
- コンテナ: `CreateContainer` が core の `create` を呼ぶ前に `in_flight=create` 付きで書き（`reserve_container` の後）、`commit_in_flight` で確定版へ、`rollback_in_flight` で、削除してよい場合に限り削除する。削除してよいのは、未作成、または core の削除完了と bundle の解放成功を確認できた Create の巻き戻しだけである。Create の結果が不明な場合や bundle の解放に失敗した場合は、既存の `rollback_in_flight` と同じく記録を `CONTAINER_UNKNOWN` として保持する（消すと core に資源が残っても所有情報を失い、再起動後に回収できなくなる。CRI-2 の fail-closed）。Start / Stop / Remove の巻き戻しでは記録を削除せず、`in_flight` を戻すか unknown で保持する。Start/Stop の遷移で状態と時刻を更新し、`RemoveContainer`（core の delete と bundle の release の成功後）で削除する
- write-ahead を採る理由: #2681 で net が write-ahead を採らなかった理由（成功後か途中かを見分けられない）は、ここでは core の状態（Present/Absent）で見分けられる。逆に後書きにすると「core にコンテナがあるのに CRI 記録が無い」状態が生じ、状態ルートを CLI と共有するため plugin-cri 由来かを証明できず回収できない
- 書けなかった場合: 副作用の前なら RPC を `Internal` で失敗させる（成功を装わない）。確定・更新の書き込み失敗はメモリの記録を保持して `Internal` を返し、次の起動では古い記録と core の状態で照合される（次節の表で安全側に倒れる）
- 性能: RPC ごとに fsync が 1〜2 回増える。CORE-10 の起動 p95 への影響は実装単位の試験で計測項目に挙げる

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
| R13 | #2942 | 実機確認（人間担当）: running のコンテナを残した再起動と再採用 | R9 |

## セキュリティ上の要点

- 記録のパスは状態ルート配下の固定位置とサービス採番の ID だけから作り、記録内のパス文字列を信頼しない
- 置き場は 0700・状態ルートと同じ所有者。インスタンスロックで別の plugin-cri との書き込み競合を防ぐ。CLI のコンテナには触らない
- 読み込みは件数・長さ・保持量の上限つきで、1 件ごと・全体の期限つき（REPAIR-5）
- 記録は再起動時に untrusted として厳密に復号し、`config_limits` を再適用する
- 再採用した保持役の pid から namespace のパスを作らず、シグナルも送らない（#2776）
- `envs` を記録に書かない。エラー文言・ログに ID・パス・config の値を載せない（REPAIR-4）
