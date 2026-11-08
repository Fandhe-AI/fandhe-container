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

containerd は shim が死んだ後や start が失敗した後に `-id <id> -bundle <path> delete` を起動する。親 #4102 の実行層の後始末のうち、本節は副作用の無い入口（検証と照合）だけを扱う。停止・回収・応答は #4152、bin 経由の回収試験と未実装表記の更新は #4153。

- 結線: cri の bootstrap に前段の注入口 `run_with_hooks` / `run_cli_with_hooks`（`before_delete`）を足し、plugin-cri の `shim::production_delete_preflight` を渡す（案 A）。前段は `ops.log` の計測区間の中で `run_delete` の前に呼ぶため、拒否も `ShimV2Delete` の失敗として残り、socket・lock には触れない。案 B（plugin-cri の bin が自前で引数を解析して事前検査する）は、失敗時の JSON 行の組み立て（serde_json）が cri にしか無く、複製するか plugin-cri に依存を足す（承認制）ことになるため採らない。既存の `run`・`run_with_context`・`run_cli_with_context` は前段が常に通る包みとして残す
- `-id`: `parse_args` の identifier 規則（76 文字以内）が先に拒否する。core の `ContainerId` への変換は多層防御として残す
- `-bundle`: 絶対パス・`.`/`..` の要素なし・末尾の要素が id と一致・末尾の要素が実在するディレクトリ（symlink でない）を求める。一次情報は containerd v2.1.4 の `core/runtime/v2/bundle.go`（`Path: filepath.Join(state, ns, id)`）と `binary.go`（`-id b.bundle.ID -bundle b.bundle.Path ... delete`）。親の namespace との一致は見ない: 状態ルートの記録の bundle との照合の方が強い同一性検査で、state の配置が変わったときに正当な呼び出しを拒否する危険を増やすだけのため。祖先の symlink は許す（macOS の `/tmp` → `/private/tmp` など）。末尾の区切りと区切りの重複は畳んでから `lstat` する（`link/` が symlink を辿るため）
- 状態ルートの特定: serve と同じ式（`scoped_root_path`。純粋関数）で `<base>-shim-state/<FNV-1a(address)>/<namespace>` を出す。serve 側の `scoped_root` は同じ関数を呼んだ後に階層を作る。インスタンスロックは取らない（D2）
- 読み取り専用での開き方: 階層のどれかが無ければ記録なし。各階層は `ensure_private_dir` と同じ基準（ディレクトリ・symlink でない・group/other に権限なし）を fail-closed で検査する。`@lock` が無いとき、`@` で始まらないエントリ（コンテナの階層）が無ければ記録なし（一度もロックつきの操作が無い）、あれば不整合として拒否する。`@lock` があるときは `FileStateStore::open` を使う。既にエントリがあるルートでは `open` は作成も初期化も `sync_dir` もせず、`get` は既存の `@lock` の flock だけで、木（内容・mtime・mode）が前後で変わらないことを試験（`cri5_4151_*`）で照合する
- 分類（`DeleteRecordMatch`）: `NotRecorded`（階層なし、または一度もロックつきの操作が無い）・`Recorded`（Creating・Created・Running・Stopped のいずれの記録も、id と bundle が対象と一致するとき）・`AlreadyReclaimed`（ストアはあるが id の記録が無い）。`StateStore` に tombstone が無く `get` は「一度も作られなかった」と「削除済み」を共に `NotFound` で返すため、ストアはあるが一度も作られなかった id も `AlreadyReclaimed` に入る（区別できるように装わない）。#4152 はどちらも副作用 0 回で成功させる想定で、挙動は変わらない
- 記録の bundle との照合: create が受けた bundle は正規化されず絶対パスのまま記録されるため、`Path` の比較（区切りの重複・末尾の区切りを無視）で `-bundle` と比べる。食い違いは `FAILED_PRECONDITION`、記録の id の食い違いは `INTERNAL`（ストアの不整合）、読み取りの期限切れは `DEADLINE_EXCEEDED`、その他の読み取り失敗は固定文言の `INTERNAL`
- 非 Linux: 既定の状態ルートが未決定（#2431）のため、引数の検証だけを行い照合は縮退する
- 前段の戻り値は `Result<(), CriError>` にとどめる。照合結果（`DeleteRecordMatch`）を受け取る形が要る #4152 で広げる。本番の前段は結果を捨てる（REPAIR-3）
- 実機確認: 実際の containerd の bundle の形（`<state>/<ns>/<id>`）で delete が拒否されないことは #3685（人間担当）の記録項目に足す

## `exited_at` が未設定のときの containerd の扱い（#3682 の依頼）

本番の経路では supervisor の monitor が終了時刻を状態記録へ書き、State・Wait・Delete が同じ値を返す（`crates/plugin-cri/tests/shim_exited_at.rs` で範囲照合済み）ため、通常は値が入る。未設定のときの containerd 側の挙動は、containerd のソースの一次情報をこの実装では確認できていない（未検証）。人間担当の実機確認（#3685）で、`exited_at` を欠いた応答を返したときの `ctr tasks ls`・`ctr run` の挙動を併せて記録する。

## 検証の状況

- 既定の集合: `crates/plugin-cri/src/shim.rs` の単体（`cri5_3684_*`）、`tests/shim_bin_task_service.rs`（bin 経由の State・Kill が `NOT_FOUND`、Create 後の State が `CREATED` で pid 0、Delete 後は `NOT_FOUND`、Shutdown で socket が消える。v2・v3 の両方）、cri から移設した `shim_bin_bootstrap.rs`・`shim_bin_bootstrap_hardening.rs`（試験名・期待値は同じ。ttrpc の手組みは `tests/support/shim_wire.rs`）
- 実機前提: `tests/shim_v2_containerd_real.rs`（手順は `docs/verification/real-machine-tests.md`）。作成時に未実行。実行と記録は #3685（人間担当）
- 停止の方法に SIGKILL を使う（コンテナ内のプローブに SIGTERM のハンドラを入れるには core の試験用 feature が要り、plugin-cri の dev-dependencies に足したくないため）。終了コードの期待値 137（128 + SIGKILL）は実機で確かめる

## イベントの publish（#4103・#4154。CRI-5・CRI-7・PLUG-1・REPAIR-3・SEC-1）

本節は `-publish-binary` の検証・保持（#4154）と、送信側（TaskExit は #4155、TaskCreate・TaskStart・TaskDelete は #4156）が使う呼び出し形の記録である。送信そのものは未実装。

### 検証と保持（実装済み）

- 字面の検査（`parse_args`。3 OS 共通）: 絶対パス、4096 バイト以下、NUL なし、`.`・`..` の要素なし。違反は `INVALID_ARGUMENT`。containerd の値は `os.Executable` 由来で、この形になる
- 実体の検査（unix のみ。`PublishBinary::verify`）: `lstat` で、存在しない・symlink・通常ファイル以外・実行ビットなし・other 書き込み可、を固定メッセージの `FAILED_PRECONDITION` で拒否する。PLUG-11 と同じ考え方（shim の権限で exec するため）。パスはメッセージに含めない
- 検査する時点: `start`（置き場所を作る前）とデーモン起動時（`ServeContext` を作る前。start との間の差し替えの窓を狭める）。`delete` は字面だけにする。delete は publish せず、containerd の更新で実体が消えた（`/proc/self/exe` の末尾に「(deleted)」が付く）状態でも後始末を止めないため
- 省略時は `None`（containerd 2.x は必ず渡すが、Go shim の既定も空）。`None` のときの扱いは #4155 で決める
- 保持: `ServeContext::publish_binary()`（`PublishBinary`）。デーモンへは検証済みの値から argv を作り直して渡す（生の argv は中継しない）
- 残余: 検査から exec までの差し替え（TOCTOU）、祖先ディレクトリの symlink・所有者、ハッシュは検査しない。検査した fd で exec する方式（`O_PATH` と `fexecve`）や所有者の照合は #4155 の検討事項。containerd を更新して実体が消えた状態では、新しい start が `publish binary not found` で失敗する（対処は containerd の再起動）

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

### 送る種別の範囲

- 送る: TaskCreate・TaskStart・TaskDelete・TaskExit の 4 種（runc shim の `cmd/containerd-shim-runc-v2/task/service.go` が `s.send` で送る種別のうち、本リポで RPC が実装済みのもの）
- 除く: TaskExecAdded・TaskExecStarted（exec の起動役の本番実装が無く `UNIMPLEMENTED`）、TaskPaused・TaskResumed・TaskCheckpointed（Pause・Resume・Checkpoint が `UNIMPLEMENTED`）、TaskOOM（memory.events を監視する仕組みが無い）
- 再評価条件: 各 RPC が実装されたとき

## 残り（REPAIR-3）

- exec の起動役（`TaskExecLauncher`）の本番実装。exec は `UNIMPLEMENTED` のまま
- containerd が shim の死後に呼ぶ `delete` action での実行層の後始末（入口の検証と照合は実装済み〔D5・#4151〕。停止・回収・応答は #4152）
- `-publish-binary` によるイベントの publish の送信: 検証と保持は済み（#4154）。送信は未実装（#4155: TaskExit、#4156: TaskCreate・TaskStart・TaskDelete）
- rootful での shim 対応（#2442・#2241 の判断待ち）
- containerd 実機シナリオの CI への組み込み（ランナーの containerd の版に依存する）

## 再評価条件

- cri から plugin-cri への依存を許す判断が出たとき（bin を cri へ戻せる）
- 非 Linux の状態ルートが決まったとき（#2431。縮退を外せる）
