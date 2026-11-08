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
- 分類（`DeleteRecordMatch`）: `NotRecorded`（階層なし、または一度もロックつきの操作が無い）・`Recorded`（Creating・Created・Running・Stopped のいずれの記録も、id と bundle が対象と一致するとき）・`AlreadyReclaimed`（ストアはあるが id の記録が無い）。`StateStore` に tombstone が無く `get` は「一度も作られなかった」と「削除済み」を共に `NotFound` で返すため、ストアはあるが一度も作られなかった id も `AlreadyReclaimed` に入る（区別できるように装わない）。#4152 はどちらも副作用 0 回で成功させる想定で、挙動は変わらない
- 記録の bundle との照合: create が受けた bundle は正規化されず絶対パスのまま記録されるため、`Path` の比較（区切りの重複・末尾の区切りを無視）で `-bundle` と比べる。食い違いは `FAILED_PRECONDITION`、記録の id の食い違いは `INTERNAL`（ストアの不整合）、読み取りの期限切れは `DEADLINE_EXCEEDED`、その他の読み取り失敗は固定文言の `INTERNAL`
- 非 Linux: 既定の状態ルートが未決定（#2431）のため、引数の検証だけを行い照合は縮退する
- 前段の戻り値は #4151 の時点では `Result<(), CriError>` にとどめ、照合結果を捨てていた。#4152 で `Result<Option<ShimDeleteExit>, CriError>` へ広げた（D6）
- 実機確認: 実際の containerd の bundle の形（`<state>/<ns>/<id>`）で delete が拒否されないことは #3685（人間担当）の記録項目に足す

## D6 delete action の停止・回収・応答（#4152）

照合（D5）が `Recorded` のときだけ、残ったコンテナを止めて回収し、終了状態を containerd へ返す。実装は plugin-cri の `shim/reclaim.rs`。

| 記録の状態 | 実行層の呼び出し | 応答 |
| --- | --- | --- |
| 記録なし・回収済み | 呼ばない（実行層も作らない） | 固定応答（pid 0・137・now。runc shim の cleanup と同じ） |
| Stopped | delete だけ | 記録の終了コード・`exited_at`（未記録は未設定）、pid は 0 |
| pid の無い Created | delete だけ | 終了コード 0 |
| Running・pid つき Created | stop（猶予 0・SIGKILL）→ delete | 停止で得た Stopped の終了コード・`exited_at`、pid は記録の pid |
| Creating | 呼ばない | `FAILED_PRECONDITION`（core の delete も拒否する。クラッシュ復旧の GC に任せる） |

- `delete(force=true)` には寄せない: force は内部で停止しても状態を捨て、応答に要る終了コードが取れないため。変換規則（不明・負値は 255、`exited_at` は Stopped で記録があるときだけ）は `task_service` の関数を共有する（cri の `ShimDeleteExit`）。
- 期限: containerd v2.1.4 の `pkg/shim/util.go` の `Command` は `exec.CommandContext` で shim を起動し、`core/runtime/v2/shim.go` の `cleanupAfterDeadShim` は `io.containerd.timeout.shim.cleanup`（既定 5 秒）の ctx で `binary.Delete`（`core/runtime/v2/binary.go`）を呼ぶ。切れると shim は kill され、失敗として exit_status 255 の TaskExit が publish される。このため全体を `SHIM_DELETE_DEADLINE`（4 秒）に収め、段の予算は停止 2.5 秒・削除 1.5 秒とする。plugin の 47 秒（`PLUGIN_FORCE_DELETE_DEADLINE`）からは導かない。
- 各段は作業スレッドで走らせ `recv_timeout` で待ち、切れたら `DEADLINE_EXCEEDED`（固定文言）を返す。内側の `SupervisedLifecycle::stop_within` の予算は段の最悪値（状態ロックの 5 秒を含む）で admit するため、4 秒未満の予算を渡すと常に拒否される。そのため停止は予算なしの `stop` を呼び、外側の待ちで有界にする。切れた後のスレッドはプロセスの終了で消える。
- 再実行: 毎回、照合からやり直し、記録の状態で続きの段から回収する。停止まで済めば次回は Stopped として delete だけ、delete まで済めば次回は回収済みで何も呼ばず成功する。containerd に kill された場合も同じ。
- stderr: `CoreLifecycleRuntime::delete` の後始末の警告行は stderr に出うる。containerd は delete の成功時の stderr を warn として記録するだけで stdout の protobuf は汚れない（`binary.go`）。「成功時は stderr へ何も書かない」は start の制約。
- 生の kill をしない: 状態記録の pid へ生のシグナルは送らない（PID 再利用。SEC-1・CORE-1）。supervisor に届かない Running の記録は停止の失敗を構造化エラーのまま返す。
- 回収が触れるのは照合済みの id の記録だけ。`-bundle` は照合にだけ使い、削除の対象やパスの組み立てに使わない。
- 絶対期限の共有（REPAIR-5）: 期限は bootstrap の `delete_recorded` が開始時刻から数える `Instant`（`SHIM_DELETE_DEADLINE`）で、`before_delete` の第 2 引数として前段へ渡す。照合の読み取り（状態ロックの待ちが最大 5 秒）は作業スレッドで走らせ残り時間で打ち切り、各段の待ちは「段の予算と残り時間の短い方」、`run_delete` の socket の lock 待ち（既定 10 秒）は残り時間で短縮し、`ops.log` の計測の記録の待ち（既定 2 秒）は期限 + 0.5 秒で打ち切る。
- 世代の保持（SEC-1・CORE-1）: 照合した記録の世代（bundle と revision）を stop と delete に渡し、本番の窓口 `GuardedCore` が副作用の直前に記録を読み直して一致を確かめる（不一致は `FAILED_PRECONDITION`。再作成された別のコンテナには触れない）。stop の後は停止後の記録から世代を取り直して delete に使う。検証と core の読み出しの間の極小の窓は残る。要求に期待 revision を持たせる core の変更で閉じられるが、`StopRequest`・`DeleteRequest` の全実装に及ぶため別 issue とする。
- 残余: Creating の記録と、supervisor が不在の Running の記録は回収できない（fail-closed）。`exited_at` が未設定のときの containerd の挙動の実機確認は #3685。

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
- 契機: init の `Start` 成功時にコンテナごとに終了 watcher を 1 本起こし、`RuntimeAdapter::wait_exit` を期限つきで繰り返す（待ち 1 回は `WaitConfig` で有界。watcher の寿命全体は有界でない）。`Stopped` を観測したら 1 回だけ送る。plugin-cri の `wait_exit` は呼び出しごとに supervisor の終了通知を購読し、枠はコンテナごとに 8（超えたら照会へ縮退）なので、containerd の Wait RPC と並んでも壊れない。Wait・State・Delete の経路からは送らない（重複排除の仕組みが要るため）
- 内容: `id` は `container_id` と同じ（init）。`pid` は Stopped の状態の pid、無ければ Start 時の pid。食い違えば作り直しとみなして送らず `instance_mismatch` を記録する。`exit_status` は `stopped_exit_status`（不明は 255）。`exited_at` は core が記録したときだけで、未記録は未設定（containerd 側ではゼロ時刻になりうる）
- 有界性（REPAIR-5）: 子 1 件の期限は `PublishConfig`（既定 5 秒の暫定値、上限 60 秒）。期限切れは kill して 1 秒の猶予内に回収する。キューは 128 件、イベントは 8192 バイト（#4223）、watcher は 1024 本が上限。`publish` は `try_send` だけで RPC スレッドを止めない。worker は 1 本で直列に処理する
- 失敗: RPC の応答は変えず、固定語彙の JSON を stderr（`daemon.log`）へ 1 件。段名は `encode`・`enqueue`・`worker_spawn`・`spawn`・`write_stdin`・`wait`・`deadline`・`exit_status`・`watch_spawn`・`watch_limit`・`watch`・`instance_mismatch`・`disabled`。段名・errno・終了コード・シグナル・`reaped`・topic だけを出し、argv・アドレス・namespace・コンテナ ID・環境変数・本文は出さない
- 残余: (1) Wait の直後 1 照会間隔以内に Delete する利用者（`ctr` 型）は、観測前に削除が走ると取り逃しうる（CRI の流れは `/tasks/exit` を受けてから Delete するので起きない）。(2) `Child::kill` は直接の子だけを止め、孫は止めない（containerd の `publish` は fork しない。プロセスグループの kill は unsafe が要るため不採用）。(3) D 状態で kill が効かない子は猶予の後に放置する。(4) 検査から exec までの TOCTOU。(5) restart による一時的な Stopped は対象外。(6) 実 containerd での受信の確認は実機前提の `shim_v2_containerd_real`（CI 組み込みは #4191）と人間担当の #3685 に委ねる

### TaskCreate・TaskStart・TaskDelete の送信（実装済み。#4156・TASK-62.6・REPAIR-3・REPAIR-5）

本メモは main の設計判断の記録であり、オーナー承認は得ていない。

- 契機と位置: init の `Create` / `Start` / `Delete` が成功する直前（コンテナ単位のゲート保持中）に 1 回だけ `EventPublisher::publish` で投入する。失敗した RPC では送らない。`Start` では `spawn_exit_watcher` より前に投入し、速く終わるコンテナでも TaskExit が TaskStart より先にキューへ入らない。同じコンテナの投入順はゲートが決め、FIFO の worker がそれを保つ
- exec の経路（`Exec`・`Start(exec_id)`・`Delete(exec_id)`）は送らない。runc shim も TaskDelete は `exec_id` が空のときだけ送り、TaskExecStarted は「除く」種別に入っている
- 世代の guard（`publish_guarded`）は使わない。完了済みの RPC の事実の記録で、runc も無条件に送る。guard は非同期の終了 watcher のためだけにある（後から「直さない」こと）
- 各欄: TaskCreate は `container_id`・`bundle`（Create の字面）・`rootfs` 空・`io` 空メッセージ（runc は常に非 nil で送る）・`checkpoint` 空・`pid`（応答と同じ）。TaskStart は `container_id`・`pid`（応答と同じ）。TaskDelete は `container_id`・`pid`・`exit_status`・`exited_at`（`DeleteResponse` と同じ値）・`id`（init なので `container_id` と同じ。TaskExit と揃えた。runc shim の `p.ID()` に対応）
- 失敗: TaskExit と同じ語彙・同じ構造化ログ（topic は `/tasks/create`・`/tasks/start`・`/tasks/delete`）。bundle・ID・アドレスは出さない。RPC の応答は変えない
- 残余: (1) 【#4223 で対応済み】stdin を socketpair（AF_UNIX の stream）の片端にし、親は非ブロッキングで期限ループの中で書く方式へ変え、`MAX_EVENT_LEN` を 8192 へ上げた（最大の正当な TaskCreate は container_id 255＋bundle 4096 で約 4.4 KiB。上限は確保と送信量の有界化〔REPAIR-2〕のため残す）。子が読まなくても worker は期限で戻り kill・回収される（REPAIR-5）。採らない案: 現行 pipe への `fcntl(O_NONBLOCK)`（`sys` に新しい unsafe が要る）、書き込み専用スレッド（期限つき join が無く、止まった書き手が残りうる）。残余: Linux は `MSG_NOSIGNAL` で EPIPE を返すが、macOS は Rust ランタイムの SIGPIPE 無視に依拠する。socket の stdin を containerd の `publish` が読むことの実機確認は #3685。 (2) containerd は最後の Delete の直後に Shutdown を呼ぶため、キューに残った TaskDelete が `SHUTDOWN_RESPONSE_GRACE`（1 秒）を過ぎると落ちうる（worker は切り離されたスレッドで排出は未実装。CRI の状態は Delete の応答で決まり TaskDelete に依存しない）。再評価条件: #3685 の実機確認で欠落が観測されたとき、または ttrpc の経路へ移るとき。(3) Delete が TaskExit の送信より先に走ると TaskExit は guard で捨てられ TaskDelete だけが出る（CRI の流れでは起きない）。(4) 実 containerd での受信の確認は `shim_v2_containerd_real`（CI 組み込みは #4191）と人間担当の #3685 に委ねる

### 送る種別の範囲

- 送る: TaskCreate・TaskStart・TaskDelete・TaskExit の 4 種（runc shim の `cmd/containerd-shim-runc-v2/task/service.go` が `s.send` で送る種別のうち、本リポで RPC が実装済みのもの）
- 除く: TaskExecAdded・TaskExecStarted（起動役は配線済みだが、送る実装が無い。後続）、TaskPaused・TaskResumed・TaskCheckpointed（Pause・Resume・Checkpoint が `UNIMPLEMENTED`）、TaskOOM（memory.events を監視する仕組みが無い）
- 再評価条件: 各 RPC が実装されたとき

## Exec の橋渡し（#4147・CRI-5・CRI-1・PLUG-1・SEC-1・REPAIR-3・REPAIR-5・TASK-62.7）

shim v2 の `Exec`・`Start(exec_id)`・`exec_id` つきの `State` / `Kill` / `Wait` / `Delete` は、注入トレイト `TaskExecLauncher` / `TaskExecProcess`（`crates/cri/src/shim_v2/exec.rs`）と登録簿 `ExecRegistry` まで実装済みで、本番の起動役は #4148（本体）・#4149（配線）で入った。本節は本番の起動役の橋渡し方式を、後続の #4148（本体）・#4149（配線）・#4150（実機前提試験）が正として読めるよう記録する。本メモは main の設計判断の記録であり、オーナー承認は得ていない（1 時間の上限は #4116 の暫定値に従う）。

### 前提（事実）

- `ContainerRuntime`（core）に exec は無い。本番の exec の入口は supervisor の `exec::run_command_with_pidfd*` で、setns と単一スレッドの fork を使うため呼び出し元は単一スレッドに限られる（`cri-streaming-server.md`「Exec」）
- shim のデーモンは多スレッド（`crates/cri/src/shim_v2/server.rs` の accept スレッドと接続ごとのスレッド）。tokio は使わない
- cri の `Cargo.toml` に supervisor への依存は無い（依存は oci と core〔`default-features = false`〕）。plugin-cri は cri・core・supervisor・net へ path 依存を持つ。`crates/cri/tests/dependency_direction.rs` が機械照合しているのは「core・cri の推移閉包に plugin-cri が入らない」ことだけで、cri → supervisor の辺は照合していない。cri に supervisor を入れない規則の根拠は `cri-streaming-server.md`「crate の担当と依存方向（PLUG-1）」の表と `Cargo.toml` の現状である
- #3761 の `SupervisorExecLauncher`（`crates/plugin-cri/src/streaming/exec_launcher.rs`。Linux のみ）は async の `ExecStreamLauncher` を実装し、同期の中核（`HelperSpawner` / `ProductionHelperSpawner`・`launch_blocking`・`watch_result`・`map_outcome`・`cri_error`・同時 `MAX_EXEC_SESSIONS` = 64・回収できない helper の保持 `MAX_STUCK_HELPERS` = 8）を持つ。helper は自分の実体と同じディレクトリの固定名の supervisor を `stream-exec` で起動する
- stream-exec helper（`crates/supervisor/src/stream_exec/helper.rs` の `serve`）の順序は、状態記録（Running・pid が `--expect-pid` と一致）の照合、`launch_env_for`、監査 sink の作成（作れなければ exec しない）、kind 6 の pidfd 受領（`ControlExecHandover`。孤児なら `Unavailable` で記録 pid へ縮退しない）、stdio の受領と `require_stdio_kinds`、kind 7 の exec 子 cgroup 通知と ack、`Started` 送信、`run_command_with_pidfd_output_notify`、`Result` 送信。env・cwd・user の上書きは受けず（`StreamExecArgs` は root / id / expect_pid / timeout / stdio mask / command だけ）、argv[0] は絶対パスに限る。helper は単一スレッドで exec 中に fd 0 を見張れないため Signal frame は無く、`Started` にコマンドの pid は載らない
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
| `pid()` | `None`。helper がコマンドの pid を返さないため State の pid は 0。返すには `Started` の拡張が要り後続候補 |
| `status()` | `Result` を受けるまで `Running`。`Exited(n)` / `Signaled(s)` / `NotStarted` は `map_outcome` の写像で `Exited { code }`。`Started` 後の `Failed(code)` は消滅の証明にならないため一律には `Exited` にしない。消滅を確認できた種別だけ `Exited { code: None }`（State は 255）にし、確認できない種別はエラーとして保持する（下表） |
| `signal(sig)` | SIGKILL のときだけ受け、`HelperGuard::kill` で helper を SIGKILL する。helper の制御チャネルが閉じると supervisor の `exec_guard` が通知済みの exec 子 cgroup を `cgroup.kill` で回収する。届くのは exec 子 cgroup だけで init には届かない。SIGKILL 以外は `UNIMPLEMENTED`（"exec signal is not supported"）で拒否し、黙って SIGKILL へ読み替えない（REPAIR-3）。終了済みは `NOT_FOUND` |
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
- 消滅の証明は helper の終了ではなく、supervisor による exec 子 cgroup の回収完了とする。helper の制御チャネルが閉じると supervisor の `exec_guard` が通知済みの exec 子 cgroup を `cgroup.kill` で回収するので、launcher は `ExecGuardPool` の `ReclaimOutcome`（成功 / `Failed`）を確認する経路を持つ。成功を確認できたときだけ `Exited { code: None }`（State は 255）へ遷移する。helper の終了だけを exec の消滅証明にしない
- 回収が `ReclaimOutcome::Failed` または確認できない間は `Err`（保持）のままで、Wait は失敗し Delete の除去も拒否する。再照会（`status()` の再呼び出しで回収状態を読み直す）で成功を確認できたときだけ `Exited` へ遷移する。確認経路の実装は #4148 の範囲（下記）

- `Kill` は `status()` を参照して `Exited` と分かった場合だけ `NOT_FOUND` にし、`Err`（実行中か不明）は SIGKILL を試みる側へ倒す。helper の `Failed` が回収の成否を運ぶ拡張が入るまでは、タイムアウトのたびに `Err` の経路になるため、この経路が実際の停止手段になる
- 未実装（REPAIR-3）: 回収成否を運ぶ `Failed` の拡張と、それを使った `Err` の絞り込みは未実装。入るまでの暫定動作が上の表で、将来は消滅を確認できる `Failed` が増えて `Err` の経路が減る（CRI-6・SUP-6。#4149 以降）

- `exec_id` とプロセスの対応は cri の `ExecRegistry` だけが持つ。launcher は上限と停止のための helper の追跡だけを持ち、exec_id の表は持たない（二重管理をしない）。永続化せず、shim の再起動で exec の記録は失われる
- 残余: shim が SIGKILL された場合、helper は exec の期限（最長 1 時間）まで残る。PDEATHSIG を使わない設計で #3761 と同じ
- 任意のシグナルへの対応は stream-exec の wire に Signal frame を足し、helper の待ちで fd 0 を見張る拡張が要る（後続候補）

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
| 非 Linux・spec の非対応の欄・SIGKILL 以外のシグナル | `UNIMPLEMENTED` |
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
  - 消滅確認の暫定（REPAIR-3）: 上の「SIGKILL 後の消滅確認」は launcher からは観測できなかった。`ExecGuardPool` は supervisor の中にあり、`Started` の payload は 0 バイト、`Result` は不透明な `Failed(code)` で、exec 子 cgroup の名前（helper 内で生成）が plugin-cri に届かない。pid からの推測は pid 再利用による誤停止のため採らない。そこで差し込み口 `ExecExtinctionProbe` だけを置き、本番の `UnconfirmedExtinctionProbe` は常に `Unknown` を返す。kill・期限切れ・`Started` 後の `Failed` の exec は `Exited` にならず `status()` が `UNAVAILABLE`（"exec termination is not confirmed"）を保ち、Wait は失敗し Delete は除去を拒む。帰結として、これらの登録はコンテナ削除の purge まで残り、コンテナあたりの exec の枠を消費する。解消には supervisor 側の wire 拡張（`Started` へ cgroup 名を載せる、または新しい frame kind。8 バイトの payload を超えるため version 変更）が要り、後続候補とする
  - `pid()` は `None`（State の pid は 0）。SIGKILL 以外・env・cwd・user は `UNIMPLEMENTED`
- **#4149 の実装記録**: `registry_parts_in`（`registry_in` の本体）で、scoped root と同じパス・同じ `StateStore` から `ShimExecLauncher::production` を 1 つ作り、停止用の包み `StopHelpersOnDrop` を通して v2・v3 の両方へ `with_exec_launcher` で差す（同時数の枠と追跡一覧は shim で 1 つ）。停止時の kill は cri の bootstrap に注入口を足さず、`run_serve` の終わりに登録簿が drop されて包みの最後の参照が落ちたとき `shutdown_all` が走る形にした（Shutdown RPC でも socket 消失でも同じ）。採らない案: bootstrap への停止注入口（cri の公開 API が変わる）、`ShutdownSignal` の見張りスレッド（socket 消失の経路を拾えず常駐スレッドが増える）、プロセス全体の `OnceLock`（同一プロセスの複数登録簿で衝突）、`ShimExecLauncher` 本体への `Drop`（#4148 の契約「drop は止めない」を変える）。非 Linux は `EmptyTaskService` のまま。試験: `cri5_4149_registry_exec_reaches_launcher`・`repair5_4149_registry_drop_stops_exec_helpers`・`cri5_4149_non_linux_registry_stays_empty`・bin 経由の `cri5_4149_bin_exec_*`。残余（REPAIR-3）: サーバー停止の期限切れで接続スレッドが残る場合と shim の SIGKILL では `shutdown_all` が走らず、helper は exec の期限（最長 1 時間）まで残る（PDEATHSIG を使わない既存の残余と同じ）。コンテナの削除・停止で cgroup が回収されれば helper は終わる。
- **#4150 実機前提試験**: shim の ttrpc を直接叩き、最小の Process spec（env 空・cwd `/`・user なし・stdio なし）で exec し、CapEff・Seccomp・ns の inode・exec 子 cgroup の配置を具体値で init と照合する
- **後続候補（未起票）**: stream-exec の Signal frame、`Started` への pid の追加、stdio の FIFO の受け入れ、spec の欄を `config.json` と照合して受ける拡張と supervisor の exec ごとの env・cwd・user（#2712・#680 系列）、cri → supervisor の辺の機械照合（`dependency_direction.rs` の拡張）

## 残り（REPAIR-3）

- containerd が shim の死後に呼ぶ `delete` action の停止・回収・応答は実装済みで、bin 経由の試験も済み（D5・D6。#4151・#4152・#4153）。回収しない場合（Creating の記録・supervisor が居ない Running の記録。fail-closed）は D6 の「残余」、実 containerd での確認は #3685
- rootful での shim 対応（#2442・#2241 の判断待ち）
- containerd 実機シナリオの CI への組み込み（ランナーの containerd の版に依存する）

## 再評価条件

- cri から plugin-cri への依存を許す判断が出たとき（bin を cri へ戻せる）
- 非 Linux の状態ルートが決まったとき（#2431。縮退を外せる）
