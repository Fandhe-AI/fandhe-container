# shim v2 バイナリに本番の ContainerRuntime を登録する設計（#3684）

CRI-5・CRI-7・PLUG-1・PLUG-4・REPAIR-3・TASK-62.6 の判断記録。配布する shim バイナリ `containerd-shim-fandhe-container-v2` が、Shutdown だけを処理する `EmptyTaskService` ではなく本番の `TaskService`（`CoreLifecycleRuntime`）を登録するようにした経緯と判断を残す。

## 背景

- 本番の `ContainerRuntime`（`CoreLifecycleRuntime`）は `crates/plugin-cri` にしか無い。一方、cri から plugin-cri への依存は `crates/cri/tests/dependency_direction.rs` が禁じている（CRI-7・PLUG-1）
- そのため cri が持っていた bin（`src/bin/shim_v2_main.rs`）が登録できたのは `EmptyTaskService`（動くのは Shutdown だけ）に限られ、Create・Start・State・Kill などは bin 経由では届かなかった
- 既存の `crates/cri/tests/shim_v2.rs` の containerd シナリオ（#676）は、試験バイナリが偽ランタイムで shim 役を兼ねる形で、プロトコル水準の確認にとどまる（実コンテナは動かさない）

## 判断

### D1 置き場所: plugin-cri に bin を足す

- `crates/plugin-cri` に `[[bin]] containerd-shim-fandhe-container-v2`（`src/bin/containerd_shim_v2.rs`）を足し、cri の `[[bin]]` と `src/bin/shim_v2_main.rs` は削除した。同じ workspace に同名の bin が 2 つあると output filename collision になるため
- 採用理由: plugin-cri は cri・core・supervisor への辺を既に持ち、`CoreLifecycleRuntime` と `SupervisedLifecycle` を複製せずに使える（REPAIR-1）。依存の追加も crate 境界の変更も要らず、辺は plugin-cri → cri・core の一方向のままで core は変わらない（PLUG-4）
- 却下: shim 専用の新 crate。crate 境界を変え、workspace メンバーと `Cargo.lock` の構成が変わる。plugin-cri と同じ依存の集合を持つ crate が増えるだけで得るものが無い
- cri は引数解析・start / delete / serve の手順・ttrpc サーバーという共有部品を持ち続ける。bin の main 本体は cri の `bootstrap::run_cli_with_hooks`（`run_cli_with_context` に delete の前段を足した版。D5）にあり、plugin-cri の bin は注入口を渡すだけにした（JSON のエラー行の組み立てに serde_json が要るため、plugin-cri に依存を足さずに済ませる）

### D2 登録簿の組み立て（plugin-cri の `shim::production_registry`）

- Linux: `StateRoot::resolve(None)` の `FileStateStore` の上に `CoreLifecycleRuntime::with_recorder` を作り、`RuntimeAdapter` で包んだ `TaskService`（v2・v3。`with_shared_created` で共有）を登録する
- インスタンスロック（`.cri/@instance.lock`）は取らず、`CriPluginBackends::production()` も使わない。shim は pod（コンテナ）ごとに 1 プロセスで plugin-cri とも状態ルートを共有するため、ロックを取ると 2 つ目の shim と plugin-cri を締め出す。shim は回収記録・CRI 記録・在庫を持たないのでロックが守る対象も無い。並行の制御は core の `StateStore` の `@lock` に任せる（CLI と同じ前提）
- 非 Linux（macOS は既定の状態ルートが未決定で #2431、`start`・`kill`・`stop` も plugin-cri では `Unimplemented`）は、従来どおり Shutdown だけの `EmptyTaskService` を登録する（REPAIR-3）

### D3 監査の記録先の共有（SEC-4）

- デーモンが単一スレッドの間に作った `ControlAuditRelay` を `ServeContext::audit_sink()` で注入側へ渡し、`CoreLifecycleRuntime::with_create_audit_sink` に差す。create の `mounts[].destination` の拒否が peer UID の拒否と同じ `@audit.log` へ残る
- 既存の `bootstrap::run`（注入口が `ShutdownSignal` だけを受ける）は `run_with_context` の薄い包みとして残した

### D4 前提

- rootless のみ。uid 0 の shim の `start` は plugin-cri の `supervised` と同じく `UNIMPLEMENTED`（#2442・#2241）。新しい拒否は足していない
- supervisor は shim の実体（`current_exe()`）と同じディレクトリの固定名から解決する。特権ランチャーは置かない（置くと rootful と判定される）。手順は `docs/setup/linux.md`
- 動く構成は、非 root で直接起動した containerd 2.x を委譲 scope の中で動かす構成

## D5 delete action の入口の検証と照合（#4151）

containerd は shim が死んだ後や start が失敗した後に `-id <id> -bundle <path> delete` を起動する。親 #4102 の実行層の後始末のうち、本節は副作用の無い入口（検証と照合）だけを扱う。停止・回収・応答は #4152（実装済み。D6）、bin 経由の回収試験は #4153（`tests/shim_bin_delete_reclaim.rs`。下の「検証の状況」）。

- 結線: cri の bootstrap に前段の注入口 `run_with_hooks` / `run_cli_with_hooks`（`before_delete`）を足し、plugin-cri の `shim::production_delete`（D5 の時点の名前は `production_delete_preflight`）を渡す（案 A）。前段は `ops.log` の計測区間の中で `run_delete` の前に呼ぶため、拒否も `ShimV2Delete` の失敗として残り、socket・lock には触れない。案 B（plugin-cri の bin が自前で引数を解析して事前検査する）は、失敗時の JSON 行の組み立て（serde_json）が cri にしか無く、複製するか plugin-cri に依存を足す（承認制）ことになるため採らない。既存の `run`・`run_with_context`・`run_cli_with_context` は前段が常に通る包みとして残す
- `-id`: `parse_args` の identifier 規則（76 文字以内）が先に拒否する。core の `ContainerId` への変換は多層防御として残す
- `-bundle`: 絶対パス・`.`/`..` の要素なし・末尾の要素が id と一致・末尾の要素が実在するディレクトリ（symlink でない）を求める。一次情報は containerd v2.1.4 の `core/runtime/v2/bundle.go`（`Path: filepath.Join(state, ns, id)`）と `binary.go`（`-id b.bundle.ID -bundle b.bundle.Path ... delete`）。親の namespace との一致は見ない: 状態ルートの記録の bundle との照合の方が強い同一性検査で、state の配置が変わったときに正当な呼び出しを拒否する危険を増やすだけのため。祖先の symlink は許す（macOS の `/tmp` → `/private/tmp` など）。末尾の区切りと区切りの重複は畳んでから `lstat` する（`link/` が symlink を辿るため）
- 状態ルートの特定: serve と同じ式（`scoped_root_path`。純粋関数）で `<base>-shim-state/<FNV-1a(address)>/<namespace>` を出す。serve 側の `scoped_root` は同じ関数を呼んだ後に階層を作る。インスタンスロックは取らない（D2）
- 読み取り専用での開き方: 階層のどれかが無ければ記録なし。各階層は `ensure_private_dir` と同じ基準（ディレクトリ・symlink でない・group/other に権限なし）を fail-closed で検査する。`@lock` が無いとき、`@` で始まらないエントリ（コンテナの階層）が無ければ記録なし（一度もロックつきの操作が無い）、あれば不整合として拒否する。`@lock` があるときは `FileStateStore::open` を使う。既にエントリがあるルートでは `open` は作成も初期化も `sync_dir` もせず、`get` は既存の `@lock` の flock だけで、木（内容・mtime・mode）が前後で変わらないことを試験（`cri5_4151_*`）で照合する
- 分類（`DeleteRecordMatch`）: `NotRecorded`（階層なし、または一度もロックつきの操作が無い）・`Recorded`（Creating・Created・Running・Stopped のいずれの記録も、id と bundle が対象と一致するとき）・`AlreadyReclaimed`（ストアはあるが id の記録が無い）。`StateStore` に tombstone が無く `get` は「一度も作られなかった」と「削除済み」を共に `NotFound` で返すため、ストアはあるが一度も作られなかった id も `AlreadyReclaimed` に入る（区別できるように装わない）。`NotRecorded` は副作用 0 回（状態ルートも作らない）。`AlreadyReclaimed` は状態記録・cgroup・プロセスに触れず、ID 単位の残骸 3 種（supervisor ログ・コンテナログ・起動オプション文書）の guard つき削除だけを行う（D7・#4279）。一度も作られなかった id は残骸が無いので何も起きない。応答はどちらも固定
- 記録の bundle との照合: create が受けた bundle は正規化されず絶対パスのまま記録されるため、`Path` の比較（区切りの重複・末尾の区切りを無視）で `-bundle` と比べる。食い違いは `FAILED_PRECONDITION`、記録の id の食い違いは `INTERNAL`（ストアの不整合）、読み取りの期限切れは `DEADLINE_EXCEEDED`、その他の読み取り失敗は固定文言の `INTERNAL`
- 非 Linux: 既定の状態ルートが未決定（#2431）のため、引数の検証だけを行い照合は縮退する
- 前段の戻り値は #4151 の時点では `Result<(), CriError>` にとどめ、照合結果を捨てていた。#4152 で `Result<Option<ShimDeleteExit>, CriError>` へ広げた（D6）
- 実機確認: 実際の containerd の bundle の形（`<state>/<ns>/<id>`）で delete が拒否されないことは #3685（人間担当）の記録項目に足す

## D6 delete action の停止・回収・応答（#4152）

照合（D5）が `Recorded` のときだけ、残ったコンテナを止めて回収し、終了状態を containerd へ返す。実装は plugin-cri の `shim/reclaim.rs`。

| 記録の状態 | 実行層の呼び出し | 応答 |
| --- | --- | --- |
| 記録なし | 呼ばない（実行層も作らない・状態ルートも作らない） | 固定応答（pid 0・137・now。runc shim の cleanup と同じ） |
| 回収済み | 残骸 3 種の guard つき削除を 1 回ずつ（状態記録・cgroup・プロセスには触れない。`reclaim_leftovers`・#4279・D7） | 固定応答（同上） |
| Stopped | delete だけ | 記録の終了コード・`exited_at`（未記録は未設定）、pid は 0 |
| pid の無い Created | delete だけ | 終了コード 0 |
| Running・pid つき Created | stop（猶予 0・SIGKILL）→ delete | 停止で得た Stopped の終了コード・`exited_at`、pid は記録の pid |
| Creating | 呼ばない | `FAILED_PRECONDITION`（core の delete も拒否する。クラッシュ復旧の GC に任せる） |

- `delete(force=true)` には寄せない: force は内部で停止しても状態を捨て、応答に要る終了コードが取れないため。変換規則（不明・負値は 255、`exited_at` は Stopped で記録があるときだけ）は `task_service` の関数を共有する（cri の `ShimDeleteExit`）。
- 期限: containerd v2.1.4 の `pkg/shim/util.go` の `Command` は `exec.CommandContext` で shim を起動し、`core/runtime/v2/shim.go` の `cleanupAfterDeadShim` は `io.containerd.timeout.shim.cleanup`（既定 5 秒）の ctx で `binary.Delete`（`core/runtime/v2/binary.go`）を呼ぶ。切れると shim は kill され、失敗として exit_status 255 の TaskExit が publish される。このため全体を `SHIM_DELETE_DEADLINE`（4 秒）に収め、段の予算は停止 2.5 秒・削除 1.5 秒とする。plugin の 47 秒（`PLUGIN_FORCE_DELETE_DEADLINE`）からは導かない。
- 各段は作業スレッドで走らせ `recv_timeout` で待ち、切れたら `DEADLINE_EXCEEDED`（固定文言）を返す。内側の `SupervisedLifecycle::stop_within` の予算は段の最悪値（状態ロックの 5 秒を含む）で admit するため、4 秒未満の予算を渡すと常に拒否される。そのため停止は予算なしの `stop` を呼び、外側の待ちで有界にする。切れた後のスレッドはプロセスの終了で消える。
- 再実行: 毎回、照合からやり直し、記録の状態で続きの段から回収する。停止まで済めば次回は Stopped として delete だけ、delete まで済めば次回は回収済みとなり、状態記録の削除の後の後始末（ログ・起動オプション文書）が中断していても残骸 3 種を回収して成功する（#4279）。containerd に kill された場合も同じ。
- stderr: `CoreLifecycleRuntime::delete` の後始末の警告行は stderr に出うる。containerd は delete の成功時の stderr を warn として記録するだけで stdout の protobuf は汚れない（`binary.go`）。「成功時は stderr へ何も書かない」は start の制約。
- 生の kill をしない: 状態記録の pid へ生のシグナルは送らない（PID 再利用。SEC-1・CORE-1）。supervisor に届かない Running の記録は停止の失敗を構造化エラーのまま返す。
- 回収が触れるのは照合済みの id の記録だけ。`-bundle` は照合にだけ使い、削除の対象やパスの組み立てに使わない。
- 絶対期限の共有（REPAIR-5）: 期限は bootstrap の `delete_recorded` が開始時刻から数える `Instant`（`SHIM_DELETE_DEADLINE`）で、`before_delete` の第 2 引数として前段へ渡す。照合の読み取り（状態ロックの待ちが最大 5 秒）は作業スレッドで走らせ残り時間で打ち切り、各段の待ちは「段の予算と残り時間の短い方」、`run_delete` の socket の lock 待ち（既定 10 秒）は残り時間で短縮し、`ops.log` の計測の記録の待ち（既定 2 秒）は期限 + 0.5 秒で打ち切る。
- 世代の保持（SEC-1・CORE-1）: 照合した記録の世代（bundle と revision）を stop と delete に渡し、本番の窓口 `GuardedCore` が副作用の直前に記録を読み直して一致を確かめる（不一致は `FAILED_PRECONDITION`。再作成された別のコンテナには触れない）。stop の後は停止後の記録から世代を取り直して delete に使う。検証と core の読み出しの間の極小の窓は残る。要求に期待 revision を持たせる core の変更で閉じられるが、`StopRequest`・`DeleteRequest` の全実装に及ぶため別 issue とする。
- 残余: Creating の記録と、supervisor が不在の Running の記録は回収できない（fail-closed）。残骸の回収（#4279）の残余: 呼び直しが無い ID の起動オプション文書（serve の起動時の走査は `@container-logs` と `@supervisor-logs` だけ。#4280・#4343 で実装済み・#4296）、ロックつきの操作が一度も無い状態ルート（`NotRecorded` に分類される）の残骸、残りが下限（`LEFTOVER_MIN_ATTEMPT` 50ms）に満たず試さなかった段（`existence: unverified` の警告行を出す）。`exited_at` が未設定のときの containerd の挙動の実機確認は #3685。

## D7 期限で中断された delete の残骸の回収（#4241。CRI-5・REPAIR-3・REPAIR-4・REPAIR-5・OCI-6・OCI-7・SEC-1・SUP-7・SUP-12）

設計の判断記録。実装 1（`delete_in` の `AlreadyReclaimed` での ID 単位の回収）は #4279 で実装済み（`shim/reclaim.rs` の `reclaim_leftovers`・`adapter.rs` の `reclaim_unrecorded_leftovers`）。実装 2（serve の起動時の `@container-logs` の走査）は #4280 で、`@supervisor-logs` の走査の追加は #4343 で実装済み（`shim/startup_sweep.rs`）。

### 問題

D6 の delete は全体の期限（4 秒）で打ち切られる。状態記録を消す前（cgroup・コミット前）に切れたときは記録が残るため、次の delete が `Recorded` から続きを回収できる。状態記録を消した後の後始末（下記 3 種）が途中で切れると、次の delete は照合で `AlreadyReclaimed` になり、副作用 0 回の固定応答を返すだけで、残りは自動では回収されない。

### 調べた事実（origin/main 58a5985e2 時点）

- shim の経路に、core が所有する rootfs は無い。`create_with_image` を呼ぶ箇所は `crates/cri`・`crates/plugin-cri` に無く、shim の Create は core の通常の `create` を通って bundle（rootfs を含む）は containerd が用意する。このため shim の `DeleteResponse::image_rootfs` は常に `NotApplicable` で、rootfs の木の残骸は今の shim では起きない
- 状態記録を消した後に残りうるのは `CoreLifecycleRuntime::delete`（`adapter.rs`）が core の delete の成功後に消す 3 種。いずれも shim の scoped 状態ルートの `@` 始まりのディレクトリに ID 名で置かれる: supervisor ログ `@supervisor-logs/<encoded-id>.log`・`.log.<n>`・`.log.lock`・コンテナログ `@container-logs/<encoded-id>.log`・`.log.<n>`・`.log.lock`・起動オプション文書 `@container-options/<encoded-id>`
- 3 種には guard つきの削除関数が既にある。guard は「この ID の状態記録が無い」と「sink の flock が外れている」で、ロックを取ったうえで試行ごとに評価する。plugin-cri は起動時の走査（#2760）と、同じ ID の create の前の回収で使っている。`CoreLifecycleRuntime::reclaim_before_create` はコンテナログ・supervisor ログ（#4342）・起動オプション文書を回収する。shim の Create も同じ `create` を通るので、create 前の回収が効く。一方、shim の serve の起動時の走査は #4280 以前には無く（現在は #4280・#4343 で追加済み）、plugin-cri の走査は plugin-cri 自身の状態ルートしか見ない
- 起動オプション文書は作成世代（`gen`）を持ち、読む側が照合する。記録の無い ID の文書を消しても、同じ ID で作り直した新しいインスタンスとは競合しない（`container-options-delivery.md`）
- `AlreadyReclaimed` には「一度も作られなかった ID」も含まれ、両者は区別できない（D5）
- containerd が delete の失敗後に同じ ID・bundle で delete を呼び直すか、bundle をいつ消すかは、一次情報で確かめていない（未確認。#3685 の実機確認で記録する）。D6 の「再実行」は前提であって確認済みではない。呼び直しが無い場合に備え、下の 2 つ目の契機を置く

### 方式の比較

| 案 | 中身 | 判断 |
| --- | --- | --- |
| A: shim 側の進行記録（tombstone） | `@shim-reclaim/<id>` に型つき・0600・fsync の記録を置き、delete が最後まで成功したときだけ消す | 不採用 |
| B: 記録を持たない、ID 単位の回収 | 照合が `AlreadyReclaimed` のとき、既存の guard つき削除関数で、その ID の残骸 3 種を期限内に 1 回だけ試す。加えて shim の serve の起動時に scoped 状態ルートの `@container-logs`・`@supervisor-logs` を走査する | 採用 |
| C: 現状維持（手動回収） | — | 不採用。shim の scoped 状態ルートは plugin-cri の走査の対象外で、残骸が溜まり続ける |

A を採らない理由:

- 残骸は ID 名のファイルで、ID は containerd が毎回 `-id` で渡す。記録に書ける ID・revision・instance では旧インスタンスと新インスタンスのログを区別できず、既存の guard（記録が無いこと・sink のロック）が同じ判断をする。記録が加える情報は無い
- kill に耐えるにはコミット前に書いて fsync する必要があり、1.5 秒の削除段の I/O が増える
- 状態ルート（OCI-5 の信頼境界）に新しいファイル形式が増え、記録自身の寿命の管理も要る。`image-rootfs-lifetime.md` の決定 E（journal を入れない）と同じ重さを、得るもの無しに負う
- 再評価条件: 状態記録を消した後の残骸に、ID から場所を導けないもの（パスや世代を記録しないと特定できないもの）が加わったとき

### 契約の変更案（D5・D6 の更新点）

- `AlreadyReclaimed`: 「副作用 0 回」から、「状態記録・cgroup・プロセスには触れず、記録の無い ID の残骸 3 種の回収だけを行う」へ改める。containerd への応答は今の固定応答（pid 0・137・now）のまま変えない
- `NotRecorded`（状態ルートが無い）は副作用 0 回のまま。状態ルートを作らない
- 実装の定数（#4279）: 末尾に残す余裕 `LEFTOVER_RESERVE` は 500ms（回収の後の `flush_delete_warnings` の fallback の分 200ms と socket 掃除の lock 取得が同じ期限を見るため）、1 段を試す下限 `LEFTOVER_MIN_ATTEMPT` は 50ms（試行は予算の 1/2 以下のため、これ未満では意味のある時間にならない）。回収の失敗・期限切れは delete を失敗にしない（best effort。containerd に TaskExit 255 や再試行を誘発しない）
- 期限: 照合から回収までと同じ絶対期限を共有する（REPAIR-5）。各削除は flock を待たず 1 回だけ試し、上限は「残り時間 - 下限の余裕」と既存の上限の短い方にする。残りが下限に満たなければ試さず、既存の `existence: unverified` の警告行を出す。`reclaim_before_create` の上限（コンテナログ 5 秒・supervisor ログ 5 秒・文書 10 秒）は 4 秒の期限に収まらないので流用しない
- 結果: 既存の `container_delete_cleanup` の警告行（stderr。パス・errno は含めない）と記録器の操作名で残す（REPAIR-4）
- 競合: guard はロックを取ったうえで試行ごとに評価するため、同じ ID の再作成と並んでも、記録がある ID・生きている sink には触れない。文書は世代で照合される
- パスは検証済みの `ContainerId` と、外部入力から受けない状態ルートだけから組み立てる。`-bundle` は照合にだけ使う（D6 の原則）。ファイルの中身からパスを読まない（SEC-1）

### 2 つ目の契機（serve の起動時の走査）

shim の serve の起動時に、scoped 状態ルートの `@container-logs` と `@supervisor-logs` を、plugin-cri の起動時の走査と同じ関数・同じ guard（`sweep_leftover_logs_at_startup`）で、期限つきの裏の thread で 1 回だけ走査する（Linux のみ。serve の開始は待たせない）。`@supervisor-logs` を対象に入れるのは #4296 のオーナー判断（2026-11-09）。

起動時の走査が走査するのは `@container-logs` と `@supervisor-logs` で、起動オプション文書（`@container-options`）は走査しない。起動オプション文書は次の 2 経路だけで回収する。(1) containerd が同じ ID で delete を呼び直したときの再実行（D6）。(2) 同じ ID の create の前の回収（`reclaim_before_create` はコンテナログ・supervisor ログ・起動オプション文書を guard つきの削除関数で回収する。supervisor ログは #4342 で足した）。delete の再呼び出しも同じ ID の再利用も無い場合、起動オプション文書は残り続ける。これは容認する残余で、手動回収とする（supervisor ログも、生きている sink・記録あり・帰属できない名前・serve の稼働中に出た残りは自動では消えず、同じ手動回収になる）: 該当 ID の同じ状態ルートでの create・start を止め、状態記録が無く sink の flock が外れていることを確かめたうえで、符号化済み ID のファイルを個別に指定して削除する。supervisor ログは `@supervisor-logs/<encoded-id>.log`・`.log.lock`・数字だけの世代接尾辞の `.log.<n>` を 1 つずつ指定する（`<id>.log*` の前方一致 glob は ID が前方一致する別 ID のログ・ロックまで消すので使わない。`container-log-recovery.md` の手順に従う）。起動オプション文書 `@container-options/<encoded-id>` は、世代照合が防ぐのは古い文書の採用だけで、確認と削除の間に並行 create が書いた新しい文書を消しうるため、同じ ID の create・start を止めたうえで削除する（`remove_stale_bounded` が ID 単位の options ロックの下で状態を再確認するのと同じ排他が手動では取れないため。SUP-12・SEC-1）。起動時走査へ文書用の走査を足すかは、残骸の実測が出たときに再評価する（追跡: 実装 issue の分割で扱う）。

実装記録（#4280・#4343。`crates/plugin-cri/src/shim/startup_sweep.rs`）:

- 差し込み口: `registry_parts_in` の末尾（登録簿の組み立てに成功した後。失敗した serve では走査しない）。`spawn_startup_log_sweep` が detached の std thread（`cri-shim-log-sweep`）で `sweep_leftover_logs_at_startup`（コンテナログ → supervisor ログの順）を 1 回だけ呼び、serve は待たない。期限は plugin-cri と同じ 30 秒（`STARTUP_LOG_SWEEP_BUDGET`）。ID 数の上限・各削除の期限は supervisor 側の既存実装
- 出力: 結果が既定値（何も無かった）でないときだけ、`sweep_summary_line` の 1 行（`event: container_log_sweep`。件数だけ）を shim の stderr（`daemon.log`）へ出す。thread を作れなかったときは固定の警告行（`outcome: spawn_failed`）を出して serve を続ける。記録器は serve の core のものを共有し、回収が 1 件以上あったときだけ走査の完了時点のスナップショットを `export_json_lines` 形式（`op_stats` 行 + `op_stats_meta` 行）で 1 回だけ同じ stderr へ出す（#4319。送り先が詰まっても走査の結果は変わらない。試験: `cri5_repair4_4319_*`）。serve の終了時には、登録簿の最後の参照が落ちたとき（`serve_end::ServeEndLauncher` の `Drop`。helper の停止の後）に、serve 開始からの累計を同じ形式で 1 回だけ出す（#4408。集計対象が 0 件なら出さない・待ちは 1 秒で打ち切る。SIGKILL と停止の期限切れでは出ない。定期出力・ファイル公開口は無い。試験: `repair4_4408_*`・`cri5_repair4_4408_*`）
- 順序と期限（#4343）: 期限 30 秒は 1 つを共有し、コンテナログを全期限で先に走査して、supervisor ログは残り時間（`saturating_sub`）で走る。コンテナログの期限を食わず、置き去りにされうる thread の壁時計の上限を 30 秒に保ち、2 つを並行させないので共有の削除作業枠（8）を奪い合わない。コンテナログが期限を使い切ると supervisor ログは予算 0 の `timed_out` になり、残りは次の shim の起動で回収される
- supervisor ログの出力（#4343）: コンテナログとは別の `event: supervisor_log_sweep` の 1 行（欄は同じ並び・件数だけ。何も無ければ出さない）。書き出しはどちらかの回収が 1 件以上のときに 1 回で、`supervisor_log_reclaim` の計数を含む（`ops` は最大 2）。thread を作れなかった固定行は共通。起動オプション文書は対象外のまま（容認する残余）
- 残余: 同じ scoped 状態ルートに複数の shim が同時に起動すると走査が競合しうるが、ID ごとの削除はロックの下で guard を評価するので無害（片方が消し、もう片方は見送る）。serve が走査より先に終わるとプロセスの終了で走査が途切れ、次の shim の起動時に回収される。稼働中に発生した残りも次の shim の起動まで残る
- 試験: `shim/startup_sweep_tests.rs` の `cri5_sup7_4280_*`・`cri5_repair5_4280_*`（記録の無い閉じた ID だけが消える・何も無いと行を出さない・guard が止まっても呼び出しは戻り期限で `timed_out`）と、bin を通した `tests/shim_bin_delete_reclaim.rs` の `cri5_sup7_4280_bin_serve_sweeps_unrecorded_container_logs`。supervisor ログは `cri5_sup7_4343_*`・`cri5_repair5_4343_*`・`cri5_sup7_4343_bin_serve_sweeps_unrecorded_supervisor_logs`

### 永続形式

無し。状態ルートに新しいファイル・ディレクトリを足さないので、`@` で始まる名前の fail-closed の規則への影響も無い。

### core 公開 API の要否

今は不要。shim の経路に core が所有する rootfs が無いため。再評価条件: CRI・shim の経路が `create_with_image` を使うようになったとき（`ImageRootfsPrivilege` の配線。#2315・#2243）。そのときは bundle から孤児の回収（core の決定 A。印の識別子の照合つき）を呼べる公開 API（bundle・`ReapOptions`・期限を受け、bundle の所有ロックと subuid の権限を含む）を足す。core の木の削除は所有トークンの印を最後に消すため（#4240）、その時点でも木を見分けられる。

### 実装の分割と見積り

| 単位 | 中身 | 見積り |
| --- | --- | --- |
| 本 PR | 本節と関連文書の更新 | 約 1.5h |
| 実装 1 | `delete_in` の `AlreadyReclaimed` で ID 単位の回収（`shim.rs`・`shim/reclaim.rs`・`adapter.rs` の helper の `pub(crate)` 化。bin 試験で、後始末の期限切れの後の 2 回目の delete で残骸が消え 3 回目が固定応答であることを照合） | 約 2〜3h |
| 実装 2 | serve の起動時の走査（`sweep_leftover_container_logs` を再利用。`@supervisor-logs` の追加は #4343） | 約 1.5h |

実装 issue: 実装 1 は #4279（実装済み。D5 の `AlreadyReclaimed` の記述と D6 の「再実行」「残余」も更新済み）、実装 2 は #4280（実装済み。下の「2 つ目の契機」の実装記録）。

## `exited_at` が未設定のときの containerd の扱い（#3682 の依頼）

本番の経路では supervisor の monitor が終了時刻を状態記録へ書き、State・Wait・Delete が同じ値を返す（`crates/plugin-cri/tests/shim_exited_at.rs` で範囲照合済み）ため、通常は値が入る。未設定のときの containerd 側の挙動は、containerd のソースの一次情報をこの実装では確認できていない（未検証）。人間担当の実機確認（#3685）で、`exited_at` を欠いた応答を返したときの `ctr tasks ls`・`ctr run` の挙動を併せて記録する。

## 検証の状況

- 既定の集合: `crates/plugin-cri/src/shim.rs` の単体（`cri5_3684_*`）、`tests/shim_bin_task_service.rs`（bin 経由の State・Kill が `NOT_FOUND`、Create 後の State が `CREATED` で pid 0、Delete 後は `NOT_FOUND`、Shutdown で socket が消える。v2・v3 の両方）、cri から移設した `shim_bin_bootstrap.rs`・`shim_bin_bootstrap_hardening.rs`（試験名・期待値は同じ。ttrpc の手組みは `tests/support/shim_wire.rs`）、delete action の bin 経由の試験（#4153。`tests/shim_bin_delete_reclaim.rs`: 記録を直接作った Stopped・Created・状態ルートなしの 3 場面と、本物の start → ttrpc の Create → デーモンの SIGKILL → delete で終了コード 0・終了状態 0・状態ルートの `<id>` と残った socket が消え、2 回目は固定の応答〔137・exited_at あり〕で状態ルートが無い場合と欄が一致すること。記録がある状態での bundle 不一致・不正な id の拒否で記録が残ること。v2・v3 の両方）、`shim_bin_bootstrap.rs` の `cri5_4151_*`（記録が無い状態の不正な `-id`・`-bundle` の拒否）
- 実機前提: `tests/shim_v2_containerd_real.rs`（手順は `docs/verification/real-machine-tests.md`）。CI の `platform-ci`（ubuntu）で実行（#4104）。ランナー以外の実機での記録は #3685（人間担当）
- 停止の方法に SIGKILL を使う（コンテナ内のプローブに SIGTERM のハンドラを入れるには core の試験用 feature が要り、plugin-cri の dev-dependencies に足したくないため）。終了コードの期待値 137（128 + SIGKILL）は実機で確かめる

## イベントの publish（#4103・#4154。CRI-5・CRI-7・PLUG-1・REPAIR-3・SEC-1）

本節は `-publish-binary` の検証・保持（#4154）と、送信側が使う呼び出し形の記録である。4 種（TaskCreate・TaskStart・TaskDelete・TaskExit）の送信は実装済み（TaskExit は #4155、他の 3 種は #4156。下の 2 小節）。

### 検証と保持（実装済み）

- 字面の検査（`parse_args`。3 OS 共通）: 絶対パス、4096 バイト以下、NUL なし、`.`・`..` の要素なし。違反は `INVALID_ARGUMENT`。containerd の値は `os.Executable` 由来で、この形になる
- 実体の検査（unix のみ。`PublishBinary::verify`）: `lstat` で、存在しない・symlink・通常ファイル以外・実行ビットなし・other 書き込み可、を固定メッセージの `FAILED_PRECONDITION` で拒否する。PLUG-11 と同じ考え方（shim の権限で exec するため）。パスはメッセージに含めない
- 検査する時点: `start`（置き場所を作る前）とデーモン起動時（`ServeContext` を作る前。start との間の差し替えの窓を狭める）。`delete` は字面だけにする。delete は publish せず、containerd の更新で実体が消えた（`/proc/self/exe` の末尾に「(deleted)」が付く）状態でも後始末を止めないため
- 省略時は `None`（containerd 2.x は必ず渡すが、Go shim の既定も空）。`None` のときは publisher を差し込まず、起動時に `disabled` を 1 件記録して続ける（エラーにしない。#4155）
- 保持: `ServeContext::publish_binary()`（`PublishBinary`）。デーモンへは検証済みの値から argv を作り直して渡す（生の argv は中継しない）
- 残余: 検査から exec までの差し替え（TOCTOU）、祖先ディレクトリの symlink・所有者、ハッシュは検査しない。検査した fd で exec する方式（`O_PATH` と `fexecve`）や所有者の照合は、新しい unsafe が要るため #4155 でも見送った（再評価条件: 差し替えの実害が観測されたとき、または `sys` に fexecve の薄いラッパーを足す判断が出たとき）。containerd を更新して実体が消えた状態では、新しい start が `publish binary not found` で失敗する（対処は containerd の再起動）

### 呼び出し形（containerd v2.1.4 の一次情報）

- containerd が shim に渡す argv: `-namespace <ns> -address <config.Address> -publish-binary <os.Executable()> [config.Args]`（`pkg/shim/util.go` の `Command()`）。環境変数に `TTRPC_ADDRESS`・`GRPC_ADDRESS`（`-address` と同じ値）・`NAMESPACE`・`MAX_SHIM_VERSION=2`・`GOMAXPROCS=2` を足す。`-address` は containerd の gRPC アドレス（`cmd/containerd/command/main.go` のグローバルフラグ `--address`）
- publish バイナリの呼び出し形（`cmd/containerd/command/publish.go`・`main.go`）: `<publish-binary> --address <shim の -address の値> publish --namespace <ns> --topic <topic>`。urfave/cli の仕様でグローバルフラグ `--address` は `publish` より前に置く。`--topic` が空だと `ErrInvalidArgument`
- stdin: `google.protobuf.Any`（`type_url`、`value` = イベントメッセージの protobuf 符号化）をそのまま渡す。長さ接頭辞・改行は付けない（`getEventPayload` が `io.ReadAll` して `proto.Unmarshal` する）
- 送信先: gRPC の `containerd.services.events.v1.Events/Publish`（`PublishRequest{topic = 1, event = 2}`。`api/services/events/v1/events.proto`）。namespace は context（gRPC メタデータ）で運ばれる
- `type_url`: 接頭辞なしの `containerd.events.<Name>` とする（typeurl v2.2.3 が proto メッセージに返す形。受け手は最後の `/` より後ろで照合するため接頭辞の有無はどちらでも解決できる）
- topic（`core/runtime/events.go`）: `/tasks/create`・`/tasks/start`・`/tasks/delete`・`/tasks/exit`（ほかに `/tasks/oom`・`/tasks/exec-added`・`/tasks/exec-started`・`/tasks/paused`・`/tasks/resumed`・`/tasks/checkpointed`）
- メッセージ（`api/events/task.proto`、package `containerd.events`）: `TaskCreate{container_id=1, bundle=2, rootfs=3, io=4, checkpoint=5, pid=6}`、`TaskStart{container_id=1, pid=2}`、`TaskDelete{container_id=1, pid=2, exit_status=3, exited_at=4, id=5}`、`TaskExit{container_id=1, id=2, pid=3, exit_status=4, exited_at=5}`

### 食い違い（正直な記録）と伝送方式

- containerd 2.x 自身の Go shim は `-publish-binary` を無視し（`pkg/shim/shim.go` のフラグ説明）、`TTRPC_ADDRESS` へ ttrpc で `containerd.services.events.ttrpc.v1.Events/Forward` を呼ぶ（`pkg/shim/publisher.go` の `RemoteEventsPublisher`。`Envelope{timestamp, namespace, topic, event: Any}`）。v1.4・v1.5 の `runtime/v2/shim/shim.go` も既に ttrpc 経路。publish バイナリを exec する経路は、それより前の版の名残で、呼び出し口は v2.1.4 にも残っている
- 本リポは親 #4103 の指定どおり exec 経路を採る。exec は、イベントごとに containerd のプロセスが 1 つ起動する費用がある代わりに、cri に events サービスの ttrpc クライアントを持たずに済む。ttrpc 経路は時刻をイベント発生時に付けられ、プロセスも起動しない
- 再評価条件: containerd が `publish` サブコマンドを廃止・非推奨化したとき、cri に ttrpc クライアントを持つ判断が出たとき、イベント頻度による起動費用が問題になったとき

### TaskExit の送信（実装済み。#4155・TASK-62.6・REPAIR-5）

- 実装: `crates/cri/src/shim_v2/publish.rs`（`TaskEvent`・`EventPublisher`・`ExecEventPublisher`）。差し込み口は `publish::exec_publisher_for(&ServeContext)`（plugin-cri の `registry_in` が v2・v3 へ渡す）。#4156 は `TaskEvent` へ種別を足して同じ仕組みを再利用した
- 呼び出し: `<publish-binary> --address <address> publish --namespace <namespace> --topic /tasks/exit`、stdin は `Any`（type URL `containerd.events.TaskExit`）。値は検証済みの `PublishBinary`・`ShimIdentifier`・`-address` だけから組み立て、子は `env_clear()`・cwd `/`・stdout / stderr は null（`daemon.log` の fd を渡さない）
- 契機: init の `Start` 成功時にコンテナごとに終了 watcher を 1 本起こし、`RuntimeAdapter::wait_exit` を期限つきで繰り返す（待ち 1 回は `WaitConfig` で有界。watcher の寿命全体は有界でない）。`Stopped` を観測したら 1 回だけ送る。plugin-cri の `wait_exit` は呼び出しごとに supervisor の終了通知を購読し、枠はコンテナごとに 8（超えたら照会へ縮退）なので、containerd の Wait RPC と並んでも壊れない。Wait・State の経路からは送らない。Delete だけは補完する（#4224）: Delete は登録の `revoked` を立てずに登録表から外し、送信権（`exit_claim`。保持中に enqueue まで行う。ロック順は claim → 登録表）を watcher と取り合う。watcher が取っていれば TaskExit は TaskDelete より先にキューにあるので何もせず、未取得なら Delete が削除前の状態から同じ規則（`task_exit_from`。pid 食い違いは送らず `instance_mismatch`）で TaskExit を送ってから TaskDelete を送る。watcher の起動失敗・上限超過・観測の断念で登録が無い場合も、停止済みなら Delete が送る。これで ctr 型（Wait の直後の Delete）でも TaskExit が TaskDelete より先にちょうど 1 件届く
- 内容: `id` は `container_id` と同じ（init）。`pid` は Stopped の状態の pid、無ければ Start 時の pid。食い違えば作り直しとみなして送らず `instance_mismatch` を記録する。`exit_status` は `stopped_exit_status`（不明は 255）。`exited_at` は core が記録したときだけで、未記録は未設定（containerd 側ではゼロ時刻になりうる）
- 有界性（REPAIR-5）: 子 1 件の期限は `PublishConfig`（既定 5 秒の暫定値、上限 60 秒）。期限切れは kill して 1 秒の猶予内に回収する。キューは 128 件、イベントは 8192 バイト（#4223）、watcher は 1024 本が上限。`publish` は `try_send` だけで RPC スレッドを止めない。worker は 1 本で直列に処理する
- 失敗: RPC の応答は変えず、固定語彙の JSON を stderr（`daemon.log`）へ 1 件。段名は `encode`・`enqueue`・`worker_spawn`・`spawn`・`write_stdin`・`wait`・`deadline`・`exit_status`・`watch_spawn`・`watch_limit`・`watch`・`instance_mismatch`・`disabled`。段名・errno・終了コード・シグナル・`reaped`・topic だけを出し、argv・アドレス・namespace・コンテナ ID・環境変数・本文は出さない
- 残余: (1) 解消（#4224。上の契機の項の Delete の補完）。ただし watcher が送信権を取った後に `try_send` がキュー満杯で失敗した TaskExit は、Delete が取得済みとして再送しないため失われる（満杯時の既存の破棄と同じ性質。再評価条件: `enqueue` の失敗を実機で観測したとき）。(2) `Child::kill` は直接の子だけを止め、孫は止めない（containerd の `publish` は fork しない。プロセスグループの kill は unsafe が要るため不採用）。(3) D 状態で kill が効かない子は猶予の後に放置する。(4) 検査から exec までの TOCTOU。(5) restart による一時的な Stopped は対象外。(6) 実 containerd での受信の確認は実機前提の `shim_v2_containerd_real`（CI 組み込みは #4191）と人間担当の #3685 に委ねる

### TaskCreate・TaskStart・TaskDelete の送信（実装済み。#4156・TASK-62.6・REPAIR-3・REPAIR-5）

本メモは main の設計判断の記録であり、オーナー承認は得ていない。

- 契機と位置: init の `Create` / `Start` / `Delete` が成功する直前（コンテナ単位のゲート保持中）に 1 回だけ `EventPublisher::publish` で投入する。失敗した RPC では送らない。`Start` では `spawn_exit_watcher` より前に投入し、速く終わるコンテナでも TaskExit が TaskStart より先にキューへ入らない。同じコンテナの投入順はゲートが決め、FIFO の worker がそれを保つ
- exec の経路は `Exec` が TaskExecAdded、`Start(exec_id)` が TaskExecStarted を送る（#4281。次節）。`Delete(exec_id)` は送らない（runc shim も TaskDelete は `exec_id` が空のときだけ送る）
- 世代の guard（`publish_guarded`）は使わない。完了済みの RPC の事実の記録で、runc も無条件に送る（Delete が代わりに送る TaskExit〔#4224〕も同じ）。guard は非同期の終了 watcher のためだけにあり、Create（外で消えた ID）と再 Start による旧世代の取り消しで捨てる（後から「直さない」こと）
- 各欄: TaskCreate は `container_id`・`bundle`（Create の字面）・`rootfs` 空・`io` 空メッセージ（runc は常に非 nil で送る）・`checkpoint` 空・`pid`（応答と同じ）。TaskStart は `container_id`・`pid`（応答と同じ）。TaskDelete は `container_id`・`pid`・`exit_status`・`exited_at`（`DeleteResponse` と同じ値）・`id`（init では空。#4222 で直した。出典: containerd/containerd v2.1.4〔commit `75cb2b7193e4e490e9fbdc236c0e811ccaba3376`〕の `cmd/containerd-shim-runc-v2/task/service.go` L352〜374 の `Delete` は init の TaskDelete に `ID` を設定しない。`api/events/task.proto` L42〜50 は「省略時は空で、`container_id` の init に一致する」。`core/runtime/v2/shim.go` L166〜179 も TaskDelete に `ID` を設定しない。TaskExit だけが `p.ID()` を持つので TaskExit の `id = container_id` は変えない。containerd の受け手が `id=container_id` と空を区別するかは確かめていない。runc とバイト単位で揃えるのが安全な既定。実機での観測は #3685）
- 失敗: TaskExit と同じ語彙・同じ構造化ログ（topic は `/tasks/create`・`/tasks/start`・`/tasks/delete`）。bundle・ID・アドレスは出さない。RPC の応答は変えない
- 残余: (1) 【#4223 で対応済み】stdin を socketpair（AF_UNIX の stream）の片端にし、親は非ブロッキングで期限ループの中で書く方式へ変え、`MAX_EVENT_LEN` を 8192 へ上げた（最大の正当な TaskCreate は container_id 255＋bundle 4096 で約 4.4 KiB。上限は確保と送信量の有界化〔REPAIR-2〕のため残す）。子が読まなくても worker は期限で戻り kill・回収される（REPAIR-5）。採らない案: 現行 pipe への `fcntl(O_NONBLOCK)`（`sys` に新しい unsafe が要る）、書き込み専用スレッド（期限つき join が無く、止まった書き手が残りうる）。残余: Linux は `MSG_NOSIGNAL` で EPIPE を返すが、macOS は Rust ランタイムの SIGPIPE 無視に依拠する。socket の stdin を containerd の `publish` が読むことの実機確認は #3685。 (2) Shutdown でのキューの排出（実装済み。#4222・REPAIR-5・REPAIR-4）: containerd は最後の Delete の直後に Shutdown を呼ぶため、排出が無いと TaskDelete が落ちうる。`bootstrap` の `run_serve` が、応答を流し切る → サーバー停止 → ロック・socket の片付け → 排出の順で `PublisherDrains::drain_all` を呼ぶ（socket の消失で抜けた場合も同じ）。Shutdown のハンドラ内では排出しない（containerd の Shutdown 呼び出しの期限は既定 3 秒で、止まった子 1 件で期限切れ → 「shim might be leaked」になるため。runc shim も応答の後に排出して時間で区切る）。排出は新しい投入を止め、worker が残りを送り切るのを `PublishConfig::drain_timeout`（既定 3 秒・暫定。1ns..=60s で検証）まで待ち、超えたら実行中の子を kill・回収して残りを捨てる（最悪 `drain_timeout` + 回収の猶予 1 秒 + 数刻み）。結果は `daemon.log` に固定語彙の 1 行 `{"event":"task_event_publish_drain","outcome":"complete"|"deadline","queued":N,"dropped":M,"worker_finished":bool,"elapsed_ms":T}`（topic・argv・アドレス・ID・本文は出さない）。登録は `ServeContext::publisher_drains()` へ `exec_publisher_for_with` が自動で載せる（追加だけの API）。#4149 の exec helper のように `Drop` に停止を任せないのは、終了 watcher のスレッドが publisher の `Arc` を持ち続け、サーバー停止が期限切れになると登録簿も落ちず `Drop` が走らないため。排出の後の投入（遅れた TaskExit 等）は `enqueue` として記録して捨てる（CRI の流れでは Delete が先に済むので起きない）。残余: D 状態の子と `setsid` した孫は止めない。実機での受信の確認は #3685。再評価条件: #3685 で欠落や期限切れが観測されたとき。 (3) 解消（#4224。Delete は `revoked` を立てないので、キュー済みの TaskExit は捨てられず TaskDelete より先に届く）。(4) 実 containerd での受信の確認は `shim_v2_containerd_real`（CI 組み込みは #4191）と人間担当の #3685 に委ねる

### 送る種別の範囲

- 送る: TaskCreate・TaskStart・TaskDelete・TaskExit（exec の終了を含む。#4317）・TaskExecAdded・TaskExecStarted の 6 種（runc shim の `cmd/containerd-shim-runc-v2/task/service.go` が `s.send` で送る種別のうち、本リポで RPC が実装済みのもの）
- 除く: TaskPaused・TaskResumed・TaskCheckpointed（Pause・Resume・Checkpoint が `UNIMPLEMENTED`）、TaskOOM（memory.events を監視する仕組みが無い）
- 再評価条件: 各 RPC が実装されたとき

### TaskExecAdded・TaskExecStarted の送信（実装済み。#4281・TASK-62.6・REPAIR-3・REPAIR-5）

本メモは main の設計判断の記録であり、オーナー承認は得ていない。

- 契機と位置: `Exec` の登録成功、`Start(exec_id)` の起動成功の直前（コンテナ単位のゲート保持中）に 1 回だけ `EventPublisher::publish` で投入する。失敗した RPC では送らない。世代の guard は使わない（理由は上の節と同じ）。Create → Start → ExecAdded → ExecStarted の投入順はゲートと FIFO の worker が保つ
- 各欄: TaskExecAdded は `container_id`・`exec_id`、TaskExecStarted は `container_id`・`exec_id`・`pid`（`StartResponse.pid` と同じ値）。launch は `Started` の後に `Spawned`（#4316）を最長 `spawned` の予算（既定 2 秒）まで待ってから返すため（#4318）、本番の `pid` は通常実 pid。届かない経路（`Spawned` 無しの `Result`・予算切れ）は 0 のまま（実 pid を装わない。REPAIR-3。State・Delete の応答は後で届けば実 pid になる）。topic は `/tasks/exec-added`・`/tasks/exec-started`、type URL は `containerd.events.TaskExecAdded`・`containerd.events.TaskExecStarted`
- 出典: containerd/containerd v2.1.4（commit `75cb2b7193e4e490e9fbdc236c0e811ccaba3376`）の `api/events/task.proto`（TaskExecAdded 1〜2・TaskExecStarted 1〜3）、`cmd/containerd-shim-runc-v2/task/service.go`（`Start` が成功後に exec なら TaskExecStarted、`Exec` が成功後に TaskExecAdded を `s.send`）、`internal/cri/server/events.go`（CRI は exec の TaskExit を `Use ID instead of ContainerID to rule out TaskExit event for exec.` として無視する）
- 失敗: 既存の 4 種と同じ語彙・構造化ログ（topic は `/tasks/exec-added`・`/tasks/exec-started`）。コンテナ ID・exec ID は出さない。RPC の応答は変えない。上限（`MAX_EVENT_LEN`）は 255 バイトの ID 2 本でも収まることを試験で機械照合する
- 残余: (1) 解消（#4317。次節）。(2) `pid` は `Spawned` が予算（2 秒）内に届かない・届かないまま `Result` が来たときだけ 0（#4318）。予算切れの回は `shim_exec_pid_unreported` で数える（#4379・REPAIR-4。`Spawned` 無しで終わった回は予算の不足ではないので数えない。再評価条件: pid 0 の TaskExit・State が運用で問題になったとき別名で数える）。計数の書き出しは起動時の走査の 1 回だけ。(3) 実 containerd での受信の確認は `shim_v2_containerd_real` と人間担当の #3685 に委ねる

### exec の TaskExit の送信（実装済み。#4317・TASK-62.6・CRI-5・REPAIR-3・REPAIR-5）

本節は main の設計判断の記録であり、オーナー承認は得ていない。

- 契機: `Start(exec_id)` が起動に成功し TaskExecStarted を投入した直後（コンテナのゲート保持中）に、exec ごとに終了 watcher を 1 本起こす（`exec_exit_watch.rs`）。TaskExecStarted を先にキューへ入れるので、速く終わる exec でも FIFO の worker が ExecStarted → TaskExit の順を保つ。publisher が無いとき、起動役が失敗した `Start(exec_id)` では起こさない
- 待ち: `TaskExecProcess::wait_exit` を `WaitConfig` の期限で繰り返す。取り消しは Shutdown と「登録が消えた」（`ExecRegistry::is_live` が偽）で、10 ミリ秒刻みで効く。照会の失敗は連続 3 回で `watch` を 1 件記録して止まる。状態を確かめられないまま終了コードを作らない
- 各欄: `container_id` はコンテナ ID、`id` は exec ID（containerd の CRI は `id != container_id` で exec の TaskExit を除外する）、`pid` は `TaskExecProcess::pid()`（本番は通常実 pid。`Spawned` が届かない経路は 0）、`exit_status` は終了コード（不明・負値は 255）、`exited_at` は未設定。世代の guard は使わない（終了は既に起きた事実）
- 上限: 生存数は共有の `AtomicUsize` と RAII の枠で数え、上限 `MAX_EXEC_EXIT_WATCHERS`（= `MAX_EXECS_TOTAL` の 1024）を超えると `watch_limit`、スレッドの起動失敗は `watch_spawn` を 1 件記録して起こさない（`Start(exec_id)` の応答は変えない）。起動済みの exec は登録数以下なので正常系では超えない
- 送信権: 印（`exit_claim`）は init の watcher の登録表ではなく exec 登録簿のエントリが持つ。エントリの除去経路（`Delete(exec_id)`・purge・作り直しの掃除）で印と生存確認が一緒に消えるため、経路ごとの同期が要らない。watcher・`Delete(exec_id)`・コンテナの Delete のうち先に印を取った 1 者だけが送る。ロック順は ゲート → claim → 登録簿の内部ロックで、watcher はゲートを取らない
- 補完: `Delete(exec_id)` は `Started` かつ `Exited` のとき、印が未取得なら TaskExit を送ってから除去する（watcher が無い場合も同じ）。`Created` / `Starting` の Delete と `Running` の拒否では送らない。コンテナの Delete は、削除の成功後・TaskDelete の前に、そのコンテナの `Started` の exec を列挙し、終了済みなら TaskExit を補完、実行中・照会失敗は印だけ取って送らない。これで exec の TaskExit が TaskDelete より後に届くことは無い
- 残余: (1) `exited_at` は未設定（exec の終了時刻の記録が無い。再評価条件: exec のハンドルが終了時刻を持つとき）。(2) `pid` は TaskExecStarted と同じく、`Spawned` が予算内に届かない経路だけ 0（#4318。予算切れは `shim_exec_pid_unreported` で数える。#4379）。(3) 実行中の exec を持つコンテナが外で消えた・作り直された場合（Create・T4・T5 の除去）は、終了を確かめられないためその exec の TaskExit は送らない。(4) watcher が印を取った後に `try_send` がキュー満杯で失敗した TaskExit は失われる（init の残余 (1) と同じ性質）。(5) 本番の未確認の状態が猶予を超えると watcher は `watch` を記録して止まる。その後の `Delete(exec_id)` が `Exited` を確認できたときだけ補完する。(6) 実 containerd での受信の確認は人間担当の #3685

## Exec の橋渡し（#4147・CRI-5・CRI-1・PLUG-1・SEC-1・REPAIR-3・REPAIR-5・TASK-62.7）

補足（#4286）: T5（#4220）のインスタンス照合の規則は `adapter::instance_matches` にまとめた（挙動は不変）。RuntimeService 側の Exec（ストリーミング）も同じ規則で、URL 発行時に記録した値を起動時に照合する（`cri-streaming-server.md`「Exec」）。

補足（#4323・CRI-5・SEC-1）: `Start(exec_id)` の `purge_mismatched` は shim の読み取りで、起動役 `ShimExecLauncher::launch` の状態読み取りとは別なので、その間に外で作り直されると旧登録の argv が新インスタンスへ起動されうる（TOCTOU）。`TaskExecLauncher::launch` に登録時の `expected_instance` を渡し、起動役が pid を決めるのと同じ `StateRecord` で `instance_matches` により照合する（Running・pid の確認より前。不一致は helper を起動せず `FAILED_PRECONDITION`、文言は `MSG_EXEC_INSTANCE_CHANGED`）。拒否した回の応答は `FAILED_PRECONDITION` のままで（T5 の `NOT_FOUND` は登録簿から除いた結果の語彙）、登録は `Created` に戻り、次の Start で `purge_mismatched` が旧登録を除いて `NOT_FOUND` になる。残余: 識別子を報告しない実装・旧い記録（両側 `None`）は保護されない。起動役の読み取りから helper の読み取りまでの窓は、helper の pid 一致の確認が担う。照合拒否は操作名 `shim_exec_instance_changed` で数える（#4379・REPAIR-4。ほかの `FAILED_PRECONDITION` は数えない。shim の共有記録器で、書き出しは起動時の走査の 1 回だけ）。

shim v2 の `Exec`・`Start(exec_id)`・`exec_id` つきの `State` / `Kill` / `Wait` / `Delete` は、注入トレイト `TaskExecLauncher` / `TaskExecProcess`（`crates/cri/src/shim_v2/exec.rs`）と登録簿 `ExecRegistry` まで実装済みで、本番の起動役は #4148（本体）・#4149（配線）で入った。本節は本番の起動役の橋渡し方式を、後続の #4148（本体）・#4149（配線）・#4150（実機前提試験）が正として読めるよう記録する。本メモは main の設計判断の記録であり、オーナー承認は得ていない（1 時間の上限は #4116 の暫定値に従う）。

### 前提（事実）

- `ContainerRuntime`（core）に exec は無い。本番の exec の入口は supervisor の `exec::run_command_with_pidfd*` で、setns と単一スレッドの fork を使うため呼び出し元は単一スレッドに限られる（`cri-streaming-server.md`「Exec」）
- shim のデーモンは多スレッド（`crates/cri/src/shim_v2/server.rs` の accept スレッドと接続ごとのスレッド）。tokio は使わない
- cri の `Cargo.toml` に supervisor への依存は無い（依存は oci と core〔`default-features = false`〕）。plugin-cri は cri・core・supervisor・net へ path 依存を持つ。`crates/cri/tests/dependency_direction.rs` が機械照合しているのは「core・cri の推移閉包に plugin-cri が入らない」ことだけで、cri → supervisor の辺は照合していない。cri に supervisor を入れない規則の根拠は `cri-streaming-server.md`「crate の担当と依存方向（PLUG-1）」の表と `Cargo.toml` の現状である
- #3761 の `SupervisorExecLauncher`（`crates/plugin-cri/src/streaming/exec_launcher.rs`。Linux のみ）は async の `ExecStreamLauncher` を実装し、同期の中核（`HelperSpawner` / `ProductionHelperSpawner`・`launch_blocking`・`watch_result`・`map_outcome`・`cri_error`・同時 `MAX_EXEC_SESSIONS` = 64・回収できない helper の保持 `MAX_STUCK_HELPERS` = 8）を持つ。helper は自分の実体と同じディレクトリの固定名の supervisor を `stream-exec` で起動する
- stream-exec helper（`crates/supervisor/src/stream_exec/helper.rs` の `serve`）の順序は、状態記録（Running・pid が `--expect-pid` と一致）の照合、`launch_env_for`、監査 sink の作成（作れなければ exec しない）、kind 6 の pidfd 受領（`ControlExecHandover`。孤児なら `Unavailable` で記録 pid へ縮退しない）、stdio の受領と `require_stdio_kinds`、kind 7 の exec 子 cgroup 通知と ack、`Started` 送信、`run_command_with_pidfd_output_notify`、`Result` 送信。env・cwd・user の上書きは受けず（`StreamExecArgs` は root / id / expect_pid / timeout / stdio mask / command だけ）、argv[0] は絶対パスに限る。exec の待ちの刻みごとに fd 0 の `Signal` frame を受けて `SignalAck` を返す（wire v4。`Signal` は #4282、下の「exec のシグナル」）。`Started` にコマンドの pid は載せない（fork の前に送るため。pid は spawn 後の別 frame `Spawned` で運ぶ。下の「`Spawned`（コマンドのホスト側 pid）」）
- shim の `TaskService::exec` は現状 `terminal` と stdio のパスを `UNIMPLEMENTED` で拒否し、`parse_process_spec` は `capabilities`・`rlimits`・`noNewPrivileges`・`apparmorProfile` 等も `UNIMPLEMENTED` で拒否する。`delete_exec` は実行中の exec を `FAILED_PRECONDITION` で除去しないため、実行中のハンドルが drop されるのはコンテナ削除の purge のときだけ
- exec は init と同じ cgroup ではなく、コンテナの cgroup の下の exec 子 cgroup（`exec.rs` の `create_child_cgroup`）で動く。supervisor にはコンテナごとの同時 exec 上限 16（`DEFAULT_MAX_EXEC_GUARDS`、`control/exec_guard.rs` の `ExecGuardLimits`）がある

### 案の比較

| 案 | 内容 | 依存方向 | fail-closed | 孤児時の縮退 | 複製の量 | 判断 |
| -- | ---- | -------- | ----------- | ------------ | -------- | ---- |
| A | plugin-cri に Linux 限定の `TaskExecLauncher` を置き、#3761 の stream-exec helper を再利用する | 既存の辺（plugin-cri → cri・core・supervisor）のみ。新しい辺も外部依存も無い | helper の照合順（状態・監査 sink の先行作成・stdio 種別）をそのまま使う | kind 6 が `Unavailable` になり縮退しない | 同期の中核を plugin-cri 内の共通モジュールへ切り出し、async と sync の薄いアダプタ 2 つで共有する | 採用 |
| B | shim bin から `run_command_with_pidfd` を直接呼ぶ | 辺は増えない | 照合順を plugin-cri 側にもう 1 つ書くことになり、漏れの危険がある | A と同じで得るものが無い | 大きい（照合順の再実装） | 却下 |
| C | cri に supervisor 依存を足し、cri 内に実装を置く | cri → supervisor の辺が増える | A と同じ | A と同じ | A と同程度で辺だけが増える | 却下 |

却下理由:

- **B**: 呼び出し元は単一スレッドに限られるが shim デーモンは多スレッドで、`cri-streaming-server.md` の案 γ と同じ理由で成り立たない。単一スレッドの子を fork しても、状態照合・launch env・監査 sink・kind 6 / 7・stdio 種別の検査を二重に持つことになる。派生案（plugin-cri bin の `/proc/self/exe` に専用サブコマンドを足す）も、exec の領域が分散するため採らない
- **C**: PLUG-1 の担当表（cri には本番の注入トレイトの実装も supervisor 依存も入れない）に反する。cri は非 Linux でもビルドされる共有部品で、supervisor の Linux 専用の sys を推移的に引き込み、PLUG-4 の観点でも core・cri の不変性を崩す

A の共通モジュールの候補は `crates/plugin-cri/src/exec_helper.rs`（Linux のみ）。#4148 では切り出さず `exec_launcher.rs` の項目を `pub(crate)` で再利用した（「後続の作業単位」の実装記録）。

### TaskExecProcess の各メソッドへの対応

`launch`（`Start(exec_id)` から呼ばれる。同期）:

1. spec を受けられるかを確かめる（次節）
2. shim の scoped な状態ルートの `StateStore` で Running と pid を照合する
3. `StreamExecArgs` を組み立てる（root は `registry_in` の scoped root と同じ・timeout は `MAX_EXEC_HOLD_SECS`・stdio mask は 0 で全て `/dev/null`・command は `spec.args()`）
4. helper を起動し、空の `StdioHandover` を送る
5. `Started` を待つ
6. `Result` を監視する std スレッドを起動し、ハンドルを返す

| メソッド | 対応 |
| -------- | ---- |
| `pid()` | launch が `Spawned`（#4316）を最長 2 秒待つため（#4318）、通常は戻りの時点で具体値（`Result` の後も保つ）。予算内に届かなかった・`Spawned` 無しで終わったときは `None`（後で届けば値。予算切れだけ `shim_exec_pid_unreported` で数える。#4379）。`Started` は exec 子 cgroup の作成直後（worker の fork 前）に送るため pid は存在せず、spawn 後の別 frame で運ぶ。値は plugin-cri と同じ pid namespace の値で、**表示用**（State・Delete の応答）。シグナルの宛先にはしない（pid は再利用される。#4282 のシグナルは pidfd で宛先を固定する）。`Spawned` が 2 回来たら違反として helper を kill し未確認に倒す |
| `status()` | `Result` を受けるまで `Running`。`Exited(n)` / `Signaled(s)` / `NotStarted` は `map_outcome` の写像で `Exited { code }`。`Started` 後の `Failed(code)` は消滅の証明にならないため一律には `Exited` にしない。消滅を確認できた種別だけ `Exited { code: None }`（State は 255）にし、確認できない種別はエラーとして保持する（下表） |
| `signal(sig)` | SIGKILL は `HelperGuard::kill` で helper を SIGKILL する。helper の制御チャネルが閉じると supervisor の `exec_guard` が通知済みの exec 子 cgroup を `cgroup.kill` で回収する。届くのは exec 子 cgroup だけで init には届かない。許可リスト（SIGHUP・SIGINT・SIGQUIT・SIGUSR1・SIGUSR2・SIGTERM）の SIGKILL 以外は `Signal` frame で helper へ送り `SignalAck` を待つ（#4282。下の「exec のシグナル」）。許可外の番号は `UNIMPLEMENTED`（"exec signal is not supported"）で拒否し、黙って SIGKILL へ読み替えない（REPAIR-3）。終了済みは `NOT_FOUND` |
| `wait_exit` | 監視スレッドの結果を `Mutex` + `Condvar` で受けるイベント駆動。取り消しは 10 ms 以下の刻みで確認し、期限で `Timeout`、取り消しで `Unavailable`（REPAIR-5） |
| drop | 契約どおり停止は要求しない。helper の持ち主は launcher の追跡一覧に残り、shim の停止時に全 helper を kill する（配線済み。登録簿の drop で `shutdown_all`。#4149） |

`Started` 後の `Failed(code)` の扱い（fail-closed。`TaskExecProcess::status` の「照会失敗は `Err`」の契約に合わせる）:

| 種別 | プロセスの消滅 | `status()` |
| ---- | -------------- | ---------- |
| 期限切れで exec 子 cgroup を `cgroup.kill` し、回収を確認できた | 確認できる | `Exited { code: None }` |
| supervisor へ到達できず、`ExecGuardPool` の回収が `ReclaimOutcome` の成功だった | 確認できる | `Exited { code: None }` |
| exec 子 cgroup の cleanup 失敗（supervisor の `exec.rs` がエラーとして返し helper が `Failed` に変換したもの） | 確認できない | `Err`（エラーを保持） |
| `ExecGuardPool` の切断後の回収が `ReclaimOutcome::Failed` | 確認できない | `Err`（エラーを保持） |
| 上記のどちらか判別できない `Failed` | 確認できない | `Err`（エラーを保持） |

- 消滅を確認できない失敗は `Exited` に変換しない。保持したエラーにより Wait は失敗し、Delete による登録除去も拒否する（生存プロセスが残ったまま終了済みとして除去できてしまうのを防ぐ）。再照会で消滅が確認できたときだけ `Exited` へ遷移し、除去を許す
- 判別の根拠を持たない間は安全側（確認できない）に倒す。helper の `Failed` が回収の成否を区別して運ぶ拡張は #4149 以降の実装で確かめる（未検証）

`status()` と `Kill(exec_id)` の状態遷移（`status()` が `Err` の exec にも SIGKILL を届ける。CRI-6・SUP-6）:

| 状態 | `status()` | `Kill(exec_id)` | 次の状態 |
| ---- | ---------- | --------------- | -------- |
| 実行中（`Result` 未受信） | `Running` | `signal(SIGKILL)` へ進む | `signal` 成功後、下の「SIGKILL 後の消滅確認」で exec 子 cgroup の回収完了を確認できたときだけ `Exited { code: None }` |
| `Started` 後に消滅を確認できた `Failed` | `Exited { code: None }` | `NOT_FOUND`（終了済み） | `Exited` のまま |
| `Started` 後に消滅を確認できない `Failed` | `Err`（保持） | `status()` の `Err` を理由に拒否せず、黙って成功にもせず、`signal(SIGKILL)` まで進む | `signal` が成功し、再照会で消滅を確認できたときだけ `Exited`。失敗は `Err` を保ったまま呼び出し元へ返す |

SIGKILL 後の消滅確認（helper の `Result` に依存しない。SEC-1・SUP-6）:

- `signal(SIGKILL)` は `Result` の送信元である helper 自体を殺すため、`Result` の受信による `Exited` には通常到達できない。監視スレッドが `Result` を受けずにチャネル切断を検知した場合（`watch_result` は切断をエラーに変換する）は、これを `Failed` と同じ「消滅を確認できない」扱いとし、そのまま `Exited` にしない
- 消滅の証明は helper の終了ではなく、supervisor・helper による exec 子 cgroup の回収完了とする（#4221 で実装。方式は下の「#4221 の実装記録」）。helper の制御チャネルが閉じると supervisor の `exec_guard` が、正常終了・期限切れでは helper 自身が、通知済みの exec 子 cgroup を `cgroup.kill` → 空の待ち → `rmdir` の順で回収するので、その名前のディレクトリの **不在** を読み取り専用で確かめられたときだけ `Exited { code: None }`（State は 255）へ遷移する。helper の終了だけを exec の消滅証明にしない
- 確認できない間（材料が無い・照合に失敗・cgroup がまだ残る）は `Err`（保持）のままで、Wait は猶予（`extinction_grace`）の後に失敗し、Delete の除去も拒否する。確認できたときだけ `Exited` へ遷移する

- `Kill` は `status()` を参照して `Exited` と分かった場合だけ `NOT_FOUND` にし、`Err`（実行中か不明）は SIGKILL を試みる側へ倒す。helper の `Failed` が回収の成否を運ぶ拡張が入るまでは、タイムアウトのたびに `Err` の経路になるため、この経路が実際の停止手段になる
- 未実装（REPAIR-3）: 回収成否を運ぶ `Failed` の拡張（回収に失敗したことの確認）は未実装。#4221 で「確認できた消滅」は `Exited` へ進むようになり、確認できないもの（`Unknown`）は従来どおり `Err` を保つ

- `exec_id` とプロセスの対応は cri の `ExecRegistry` だけが持つ。launcher は上限と停止のための helper の追跡だけを持ち、exec_id の表は持たない（二重管理をしない）。永続化せず、shim の再起動で exec の記録は失われる
- 残余: shim が SIGKILL された場合、helper は exec の期限（最長 1 時間）まで残る。PDEATHSIG を使わない設計で #3761 と同じ
- 任意のシグナルのうち許可リスト内は #4282 で対応した（下の「exec のシグナル」）。許可外（STOP 系・CONT・WINCH・実時間シグナル）は対象外のまま

### exec のシグナル（#4282・SUP-6・CRI-5・SEC-1・REPAIR-2・REPAIR-3・REPAIR-5）

shim の `Kill(exec_id)` が受けるシグナルを SIGKILL だけから、許可リストの SIGKILL 以外へ広げた。wire は version 3（`stream_exec/wire.rs` の doc が語彙の正。旧い v1・v2 の相手とは混在させず `BadVersion` で拒否する）。

- frame: kind 5 `Signal`（plugin-cri → helper。payload 1 バイトのシグナル番号。全長 9）、kind 6 `SignalAck`（helper → plugin-cri。`[signal, code]`。全長 10）。いずれも fd なし
- 許可リスト `ExecSignal`: SIGHUP 1・SIGINT 2・SIGQUIT 3・SIGUSR1 10・SIGUSR2 12・SIGTERM 15（x86_64 と aarch64 で同じ番号。型でしか作れず、許可外は作れない）。対象外の理由: SIGKILL は既存の cgroup ごとの停止のほうが強い、STOP・TSTP・TTIN・TTOU・CONT は exec を期限まで止める・再開させる、WINCH は tty 未対応、実時間シグナルは glibc の予約を含む、0 は存在確認でありシグナルではない
- 拒否の語彙: 0 と 65 以上は `SignalOutOfRange`、1〜64 の許可外は `SignalNotAllowed`、ack の未知の code は `UnknownSignalAck`。plugin-cri の `signal()` は許可外の番号を従来の文言の `UNIMPLEMENTED` で返し、frame は 1 バイトも送らない
- ack の code: delivered（1）・not_started（2。コマンドの pidfd がまだ届かず猶予を過ぎた）・exited（3）・unavailable（4）。CRI への写像は delivered → OK、not_started → `FAILED_PRECONDITION`、exited → `NOT_FOUND`、unavailable → `UNAVAILABLE`、ack の期限切れ → `DEADLINE_EXCEEDED`（5 秒）、ack より先に `Result` / 切断 → `NOT_FOUND` / `UNAVAILABLE`。未確認の exec へは送らず `UNAVAILABLE`

#### `Spawned`（コマンドのホスト側 pid。#4316・SUP-6・CRI-5・CRI-6）

- wire は version 4。kind 7 `Spawned`（helper → plugin-cri、payload は pid の `u32` big-endian で 0 は `InvalidPid`、全長 12、fd なし）。語彙の正は `stream_exec/wire.rs` の doc
- 送信順: `Started` →（tty なら `PtyMaster`）→ `Spawned`（高々 1 回）→ `SignalAck`（0 件以上）→ `Result`。`Spawned` は常に `Result` より前。helper は、刻みごとに worker から届いた pid を `SignalAck` の処理より前に送り、刻みより先に終わった短命なコマンドは後始末で `SignalAck` と `Result` の前に送る。送信は 500 ms の予算の最善努力で再送しない（部分書き込みで後続の frame が崩れる窓は `SignalAck` と同じ残余）
- worker → helper の中継は、#4282 の pidfd の送信（socketpair の `SCM_RIGHTS`）に、1 バイトの目印の代わりに pid の 4 バイト（big-endian）を載せる。4 バイトが揃い 0 でないときだけ pid を採り、そうでなければ pid は不明のまま（pidfd の扱いは変えない）。pid は worker と同じ pid namespace（= helper = plugin-cri）の値で、信頼度は結果行の `command_pid`（監査の `target_pid`）と同じ
- 互換の扱い: version 3 以下の相手は `BadVersion` で拒否し、exec の開始前に launch が失敗する（fail-closed。exec の途中で版ずれが露見する経路を作らない。version を上げずに kind だけ足す案は、旧い plugin-cri が exec の途中で `UnknownKind` を受けて helper を kill するため採らない）。version 4 の中で `Spawned` が届かないまま `Result` が来るのは正当で（`NotStarted`・`Failed`・pidfd の中継失敗・送信失敗）、消費側は pid を不明のまま処理する
- 消費側: shim v2 の `ShimExecLauncher` は `Inner` に原子で記録し `pid()` が返す。launch は `Spawned`・終了・予算（`ExecBudgets::spawned`、既定 2 秒）のいずれかまで待つ（#4318。Agent の判断でオーナー承認は未取得。予算は helper が worker の pid を待つ `SIGNAL_START_GRACE` に揃えた。代償: `start_exec` はコンテナ単位のゲートを持ったまま launch を呼ぶため、worker が詰まった異常時は最悪 2 秒、同じコンテナの操作を待たせる。`Result` や違反で即座に抜ける。再評価条件: Start の遅延が実測で問題になったとき、helper の刻みが変わったとき）。2 回目の `Spawned` と `Started` より前の `Spawned` は違反。CRI の Exec（`SupervisorExecLauncher`）は pid を使わないので 1 回だけ読み捨てる
- 確認済み: `crates/cri/src/shim_v2/task_service.rs` は `process.pid()` を State・Start の応答とイベント・Delete の応答の表示にだけ使い、生の pid へシグナルを送る経路は無い
- 残余: `StartResponse.pid` と `TaskExecStarted.pid` は `Start` が `Started` で戻るため通常 0（後続候補）

#### 宛先と権限（pidfd を worker から helper へ渡す）

- 送る主体は helper（親）。worker はコマンドを fork した直後に、`ContainerChild` が fork 直後に開いたコマンドの pidfd を、fork 前に作った socketpair 経由で `SCM_RIGHTS` で 1 本だけ親へ渡す（最善努力。送れなければ not_started のまま猶予を過ぎて unavailable になる）。helper は `pidfd_send_signal` で送る（core の `send_signal_via_pidfd`。新しい `unsafe` は無い）
- 権限の根拠: helper は seccomp・Landlock・cap drop を受けていない。rootless では helper の euid がコンテナの user namespace の所有者で親の namespace にいるため CAP_KILL を持ち、範囲写像で uid が違うコマンドにも送れる。rootful は root。pidfd で送るので pid の再利用で別のプロセスに届かず（SEC-1・CORE-1）、送り先はコマンド本体の 1 プロセスだけで子孫には送らない
- 却下: (A) worker が転送する案は、worker がコンテナの seccomp・Landlock・cap drop を受けた後にコマンドを起動するため、範囲写像で uid の違うコマンドへ CAP_KILL が無く、seccomp profile にも依存して脆い。(B) helper が exec 子 cgroup の `cgroup.procs` を列挙して送る案は、「子孫すべてへ送る」意味に変わり pid の TOCTOU が残り、core に読み取り API も要る。`cgroup.kill` は SIGKILL しか送れないので手段にならない

#### helper の受信規則

- exec の待ちの刻み（応答者の `SERVE_STEP` と終了待ちの `CANCEL_POLL_STEP`）ごとに、要求元の取り消しが偽のときだけ、fd 0 に `POLLIN` があれば `Signal` を 1 件、短い期限（200 ms）で受ける。受けてよいのは `Signal` だけで、fd が付いていれば閉じて拒否する。保留は 1 件までで、pidfd が未着なら刻みごとに再試行し、2 秒を過ぎたら not_started を返す。exec が終わった時点で保留が残っていれば `Result` の前に ack を送る（コマンドが終わっていれば exited、そうでなければ not_started）
- 受信に失敗した後（壊れた frame・許可外・旧い版・fd 付き・向きの違う frame）は以後シグナルを受けず ack も返さない（frame の境界を信頼できない。channel の「受信失敗後は再利用しない」契約）。fd 2 に固定語彙の診断行を 1 行出し、exec は止めず従来の期限で終わる。ack の送信は 500 ms の期限で、刻みの中で長く止めない
- plugin-cri は要求を 1 件ずつ排他し、`watch_result` を helper → plugin-cri の唯一の読み手のままにして `SignalAck` を待っている要求へ渡す。待っていない ack・番号違いの ack はプロトコル違反として helper を止め、未確認にする

#### 残余

- ゾンビへの送信もカーネルは成功にするため、delivered は「コマンドが生きていた」の証明ではない
- worker の `sendmsg` がコンテナの seccomp profile で拒否されると pidfd が届かず、not_started / unavailable になる（fail-closed。応答者の監査に 1 件残りうる）
- SIGKILL 以外の配送は待ちの刻み（最大約 100 ms）の分だけ遅れる
- 試験: 実機前提の `stream_exec_real` のシナリオ `signal_term`（SIGTERM がコマンドへ届き `Signaled(15)`）、既定の集合の `stream_exec_helper`・`wire`・`channel`・plugin-cri の `task_exec/linux/tests.rs`

### spec の欄（env・cwd・user）の扱い

helper も supervisor の exec も env・cwd・user の上書きを受けない。初版の受け入れは env が空・cwd が `/`・user が `None` に限り、それ以外は `UNIMPLEMENTED` で拒否する。黙って捨てない。

- 帰結: containerd が生成する exec の spec（コンテナの `spec.Process` を写したもの）は、TaskService の段（stdio・`capabilities` 等）と合わせて拒否される。containerd の実機で通すには、stdio の FIFO の受け入れ（helper の `require_stdio_kinds` は FIFO を受ける）、spec の欄を `config.json` と照合して受ける拡張、supervisor の exec ごとの env・cwd・user の対応（#2712・#680 の系列）が別に要る。いずれも後続候補（未起票）
- #4150 の実機前提試験は containerd ではなく shim の ttrpc を直接叩き（`crates/plugin-cri/tests/support/shim_wire.rs` の形）、最小の Process spec で行う
- containerd の CRI が exec の spec をどう組むか、ExecSync の期限切れで SIGKILL を送るかは、一次情報（containerd の `internal/cri/server/container_execsync.go`）をこの設計では確認していない（未検証）。#3682 の節と同じ扱いで、実機確認で記録する

### 期限と上限（REPAIR-5）

| 段 | 期限 |
| -- | ---- |
| stdio の受け渡し | 5 秒（`HANDOVER_BUDGET`） |
| `Started` の待ち | 25 秒（`STARTED_BUDGET`） |
| kind 6 / kind 7 | helper 側で 5 秒 / 10 秒 |
| exec 全体 | `MAX_EXEC_HOLD_SECS` = 1 時間（helper の `--timeout-ms`） |
| `Result` の猶予 | 30 秒（`RESULT_GRACE`） |
| kill 後の回収 | 10 秒（`REAP_BUDGET`）。超えたら保持一覧へ移す |
| Wait | TaskService の `min(timeout_nano, WaitConfig::timeout)` |

TaskService は期限を足さず、実装側が持つ（トレイトの契約）。上限は cri の登録簿がコンテナごと 64・全体 1024（`MAX_EXECS_PER_CONTAINER`・`MAX_EXECS_TOTAL`）、plugin-cri の launcher が shim プロセスごとに同時 64・保持 8、supervisor がコンテナごとの同時 exec 16 で、実効の上限は supervisor の 16。

### 失敗時に返す CriError

文言は固定の英文とし、argv・env・ID・パスを含めない。

| 状況 | CriError |
| ---- | -------- |
| 非 Linux・spec の非対応の欄・許可リスト外のシグナル | `UNIMPLEMENTED` |
| argv が相対パス・helper の引数検証の失敗 | `INVALID_ARGUMENT` |
| 状態記録が無い | `NOT_FOUND`（"container not found"） |
| 状態ストアの読み取り失敗 | `UNAVAILABLE` |
| Running でない・pid が一致しない | `FAILED_PRECONDITION`（"container is not running"） |
| supervisor の実行ファイルが無い・実体のパスを解決できない | `FAILED_PRECONDITION` |
| helper の起動失敗・channel の確保失敗・孤児（kind 6 の `Unavailable`）・launcher の停止後 | `UNAVAILABLE`（記録 pid へ縮退しない） |
| 同時数・保持の上限 | `RESOURCE_EXHAUSTED` |
| 各段の期限切れ | `DEADLINE_EXCEEDED`（`CriError::timeout`） |
| helper の `Failed(code)` | 既存の `cri_error` の写像を共通化して再利用 |

### SEC-1 を保証する層と根拠

保証する層は supervisor と core。plugin-cri と cri は、分離を広げる要求を受けない・渡さないという防御の多重化を担う。

- supervisor
  - `stream_exec/helper.rs` の `serve`: 状態記録と pid の照合、監査 sink を exec より先に作る（SEC-4）、kind 6 の pidfd だけを使う、`require_stdio_kinds` でホストの端末 fd を拒否する、kind 7 の通知の後にだけ fork する
  - `exec.rs` の `run_command_with_pidfd_output_notify` → `run_command_with_pidfd_inner`: `create_child_cgroup` で exec 子 cgroup をコンテナの cgroup の配下に作り、`identify_pid1_with_pidfd_staged` / `identify_pid1_with_pidfd` で pidfd の同一性を照合し、pid / mnt / uts / ipc / net（rootless では user も）の namespace に参加する
  - `control/target.rs` の `SignalSlot::handover_pidfd`: pidfd の出所は稼働中の supervisor だけ。`control/client.rs` の `ControlExecHandover`
  - `control/exec_guard.rs` の `ExecGuardPool`: 切断時に exec 子 cgroup を回収する
- core: `exec/reapply.rs` の `prepare_exec_restrictions` / `reapply_restrictions` が capability の集合を launch と同じにし、NNP・Landlock・seccomp を再適用する
- plugin-cri: helper へ渡すのは argv だけ。env・cwd・user・capability を渡さず、非対応の欄は拒否する
- cri: `parse_process_spec` が `capabilities`・`noNewPrivileges`・`apparmorProfile` 等を `UNIMPLEMENTED` で拒否し、`TaskService::exec` が `terminal` と stdio のパスを拒否する

実機前提試験（#4150）で init と照合する関係は、CapEff と Seccomp が init を超えないこと、ns の inode が init と一致すること、cgroup が init の cgroup の直下にある exec 子 cgroup であること（init と同一ではない）の 3 点。

### 後続の作業単位

- **#4148 本体実装**: `exec_launcher.rs` の同期の中核を plugin-cri 内の共通モジュールへ切り出し、Linux 限定で `TaskExecLauncher` / `TaskExecProcess` を実装する（非 Linux は `UNIMPLEMENTED`）。偽の `HelperSpawner` による単体試験で、終了コード 0 / 3、SIGKILL だけが exec 子 cgroup に届き init には届かないこと、SIGKILL 以外が `UNIMPLEMENTED`、存在しないコンテナが `NOT_FOUND`、停止済みが `FAILED_PRECONDITION`、期限切れで helper を回収することを具体値で照合する。cri の依存は変えない。ただし `status()` が `Err` の exec にも `signal(SIGKILL)` を試みる経路と、SIGKILL 後に exec 子 cgroup の回収完了を確認して `Exited` へ遷移させる経路（「SIGKILL 後の消滅確認」）を launcher 側に実装し、単体試験で `Err` 保持中の SIGKILL 到達と、回収失敗時に `Exited` へ遷移しないことを照合する
- **#4148 の追補（`TaskService` の変更。作業範囲に明記）**: `crates/cri/src/shim_v2/task_service.rs` の `kill_exec` は現状 `process.status().map_err(...)?` で早期 return し、`status()` が `Err` のとき `signal(SIGKILL)` に到達しない。`status()` の `Err` では拒否せず `signal(SIGKILL)` まで進める変更（`Exited` のときだけ `NOT_FOUND`）を、#4148 と同じ PR で `crates/cri/` に入れる（cri のコード変更であり、依存は変えない）。本設計の暫定動作の記述は、この変更が入るまでは現状の `kill_exec` と食い違う（REPAIR-3）
- **#4148 の実装記録（本体は実装済み。配線は #4149）**: 起動役は `crates/plugin-cri/src/task_exec.rs`（Linux 実装は `task_exec/linux.rs`、非 Linux は `UNIMPLEMENTED` のスタブ）。共通モジュール `exec_helper.rs` への切り出しは行わず、`streaming/exec_launcher.rs` の `HelperGuard`・`Shared`・各期限定数・`HelperSpawner` を `pub(crate)` にして再利用した（移動のみのリファクタで既存の async 側の試験を動かすリスクを避けるため。重複するのは `launch` の順序だけ）。`TaskService::kill_exec` は `status()` が `Err` でも SIGKILL のときだけ `signal` へ進む。
  - 消滅確認（#4221 で解消。CRI-5・SEC-1・REPAIR-3・REPAIR-5）: #4148 の時点では exec 子 cgroup の名前が plugin-cri に届かず、本番の probe が常に `Unknown` だった。#4221 で stream-exec の wire を version 2 にし、`Started` の payload を固定 65 バイト（`name_len: u8` + 名前 64 バイト。NUL 埋め）にして helper が作った exec 子 cgroup の名前を運ぶ（新しい frame kind にしないのは、`Started` の直後の kill より前に名前が届く必要があり、SIGKILL された helper はもう送れないため）。plugin-cri の本番の probe `CgroupExtinctionProbe` は core の `exec_child_cgroup_presence`（読み取り専用）でコンテナ cgroup 直下にその名前のディレクトリが **無い** ことを確かめ、不在（またはコンテナ cgroup 自体が無い）なら `Confirmed`、残っている・照合に失敗・cgroup ルートを開けない・記録に配置が無いなら `Unknown`。cgroup v2 のディレクトリはプロセスが残る間 `rmdir` できないので、不在はそこにいたプロセス全体の消滅の証拠になる。確認の材料（記録の cgroup 配置と名前）は launch の時点で固定する（restart で別の世代の経路を見て誤って不在と判定しないため）。Wait は未確認の間 `extinction_grace`（既定 10 秒。`REAP_BUDGET` と同じ）だけ刻みごとに照会し、`Confirmed` で `Ok(None)`、猶予切れで従来どおり `UNAVAILABLE`、Wait 全体の期限が先なら `DEADLINE_EXCEEDED`、取り消しは `UNAVAILABLE`。版が合わない旧い supervisor とは `StdioHandover` の version 不一致で `Started` に至らず launch が失敗し、確認済みとして扱わない（v1 を受けて `Unknown` に落とす案は、v1 の `Started` に名前が無く恒久的に未確認になるだけなので採らない）。不採用: pid からの推測（pid 再利用で誤停止）、helper の終了を証拠にする、plugin-cri 自身が `remove_exec_child_cgroup` で回収する（名前の再利用で別の exec を kill しうる）、回収結果を運ぶ新しい frame（kill 経路で役に立たない）。残余: 名前は helper の pid と連番で、回収後に別の helper が同じ名前を作ると「まだある」と見えて `Unknown` のまま残る（安全側。purge で回収）。コンテナ内から cgroupfs に書けない前提は既存の guard の回収と同じ。実 cgroup での kill → 回収 → Wait → Delete の通しは単体試験の範囲外で、実機前提試験（#4150）に後続で足す
  - `pid()` は #4148 の時点では `None`（#4316 で `Spawned` が届いた後は値を返す）。許可リスト外のシグナル・env・cwd・user は `UNIMPLEMENTED`（許可内のシグナルは #4282 で対応）
- **#4149 の実装記録**: `registry_parts_in`（`registry_in` の本体）で、scoped root と同じパス・同じ `StateStore` から `ShimExecLauncher::production` を 1 つ作り、停止用の包み `StopHelpersOnDrop` を通して v2・v3 の両方へ `with_exec_launcher` で差す（同時数の枠と追跡一覧は shim で 1 つ）。停止時の kill は cri の bootstrap に注入口を足さず、`run_serve` の終わりに登録簿が drop されて包みの最後の参照が落ちたとき `shutdown_all` が走る形にした（Shutdown RPC でも socket 消失でも同じ）。採らない案: bootstrap への停止注入口（cri の公開 API が変わる）、`ShutdownSignal` の見張りスレッド（socket 消失の経路を拾えず常駐スレッドが増える）、プロセス全体の `OnceLock`（同一プロセスの複数登録簿で衝突）、`ShimExecLauncher` 本体への `Drop`（#4148 の契約「drop は止めない」を変える）。非 Linux は `EmptyTaskService` のまま。試験: `cri5_4149_registry_exec_reaches_launcher`・`repair5_4149_registry_drop_stops_exec_helpers`・`cri5_4149_non_linux_registry_stays_empty`・bin 経由の `cri5_4149_bin_exec_*`。残余（REPAIR-3）: サーバー停止の期限切れで接続スレッドが残る場合と shim の SIGKILL では `shutdown_all` が走らず、helper は exec の期限（最長 1 時間）まで残る（PDEATHSIG を使わない既存の残余と同じ）。コンテナの削除・停止で cgroup が回収されれば helper は終わる。
- **#4150 実機前提試験**（実装済み。`crates/plugin-cri/tests/shim_v2_exec_real.rs`）: shim の ttrpc を直接叩き、最小の Process spec（env 空・cwd `/`・user なし・stdio なし）で exec し、CapEff・Seccomp・ns の inode・exec 子 cgroup の配置を具体値で init と照合する。実装の判断: (1) `harness = false`（exec は stdio が `/dev/null` で pid も返さないため、試験バイナリ自身が rootfs の `/probe` として init と exec のコマンドを兼ねる再入が要る）、(2) cgroup は「init の直下の `exec-*` 子 cgroup 1 要素」で照合する（init と同じ cgroup にはならない）、(3) 解放は rootfs 直下の合図ファイルによる自然終了（SIGKILL は消滅を確認できず Delete が拒否される）、(4) CI の `platform-ci`（ubuntu）に組み込み済み。残余: 実コンテナのホスト `/proc/<pid>/ns/*` の読み取りは ptrace の READ 権に依存し、CI での初回実行で確認する
- **後続候補（未起票）**: stdio の FIFO の受け入れ、spec の欄を `config.json` と照合して受ける拡張と supervisor の exec ごとの env・cwd・user（#2712・#680 系列）、cri → supervisor の辺の機械照合（`dependency_direction.rs` の拡張）

## 残り（REPAIR-3）

- containerd が shim の死後に呼ぶ `delete` action の停止・回収・応答は実装済みで、bin 経由の試験も済み（D5・D6。#4151・#4152・#4153）。回収しない場合（Creating の記録・supervisor が居ない Running の記録。fail-closed）は D6 の「残余」、実 containerd での確認は #3685
- rootful での shim 対応（#2442・#2241 の判断待ち）
- containerd 実機シナリオの CI への組み込み（ランナーの containerd の版に依存する）

## 再評価条件

- cri から plugin-cri への依存を許す判断が出たとき（bin を cri へ戻せる）
- 非 Linux の状態ルートが決まったとき（#2431。縮退を外せる）
