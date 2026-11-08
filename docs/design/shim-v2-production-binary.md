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
- 残余: Creating の記録と、supervisor が不在の Running の記録は回収できない（fail-closed）。`exited_at` が未設定のときの containerd の挙動の実機確認は #3685。

## `exited_at` が未設定のときの containerd の扱い（#3682 の依頼）

本番の経路では supervisor の monitor が終了時刻を状態記録へ書き、State・Wait・Delete が同じ値を返す（`crates/plugin-cri/tests/shim_exited_at.rs` で範囲照合済み）ため、通常は値が入る。未設定のときの containerd 側の挙動は、containerd のソースの一次情報をこの実装では確認できていない（未検証）。人間担当の実機確認（#3685）で、`exited_at` を欠いた応答を返したときの `ctr tasks ls`・`ctr run` の挙動を併せて記録する。

## 検証の状況

- 既定の集合: `crates/plugin-cri/src/shim.rs` の単体（`cri5_3684_*`）、`tests/shim_bin_task_service.rs`（bin 経由の State・Kill が `NOT_FOUND`、Create 後の State が `CREATED` で pid 0、Delete 後は `NOT_FOUND`、Shutdown で socket が消える。v2・v3 の両方）、cri から移設した `shim_bin_bootstrap.rs`・`shim_bin_bootstrap_hardening.rs`（試験名・期待値は同じ。ttrpc の手組みは `tests/support/shim_wire.rs`）
- 実機前提: `tests/shim_v2_containerd_real.rs`（手順は `docs/verification/real-machine-tests.md`）。作成時に未実行。実行と記録は #3685（人間担当）
- 停止の方法に SIGKILL を使う（コンテナ内のプローブに SIGTERM のハンドラを入れるには core の試験用 feature が要り、plugin-cri の dev-dependencies に足したくないため）。終了コードの期待値 137（128 + SIGKILL）は実機で確かめる

## 残り（REPAIR-3）

- exec の起動役（`TaskExecLauncher`）の本番実装。exec は `UNIMPLEMENTED` のまま
- containerd が shim の死後に呼ぶ `delete` action の停止・回収・応答は実装済み（D5・D6。#4151・#4152）。bin 経由の試験と未実装表記の全面更新は #4153
- `-publish-binary` によるイベントの publish（TaskExit など）
- rootful での shim 対応（#2442・#2241 の判断待ち）
- containerd 実機シナリオの CI への組み込み（ランナーの containerd の版に依存する）

## 再評価条件

- cri から plugin-cri への依存を許す判断が出たとき（bin を cri へ戻せる）
- 非 Linux の状態ルートが決まったとき（#2431。縮退を外せる）
