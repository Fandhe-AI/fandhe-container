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
- cri は引数解析・start / delete / serve の手順・ttrpc サーバーという共有部品を持ち続ける。bin の main 本体は cri の `bootstrap::run_cli_with_context` にあり、plugin-cri の bin は注入口を渡すだけにした（JSON のエラー行の組み立てに serde_json が要るため、plugin-cri に依存を足さずに済ませる）

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

## `exited_at` が未設定のときの containerd の扱い（#3682 の依頼）

本番の経路では supervisor の monitor が終了時刻を状態記録へ書き、State・Wait・Delete が同じ値を返す（`crates/plugin-cri/tests/shim_exited_at.rs` で範囲照合済み）ため、通常は値が入る。未設定のときの containerd 側の挙動は、containerd のソースの一次情報をこの実装では確認できていない（未検証）。人間担当の実機確認（#3685）で、`exited_at` を欠いた応答を返したときの `ctr tasks ls`・`ctr run` の挙動を併せて記録する。

## 検証の状況

- 既定の集合: `crates/plugin-cri/src/shim.rs` の単体（`cri5_3684_*`）、`tests/shim_bin_task_service.rs`（bin 経由の State・Kill が `NOT_FOUND`、Create 後の State が `CREATED` で pid 0、Delete 後は `NOT_FOUND`、Shutdown で socket が消える。v2・v3 の両方）、cri から移設した `shim_bin_bootstrap.rs`・`shim_bin_bootstrap_hardening.rs`（試験名・期待値は同じ。ttrpc の手組みは `tests/support/shim_wire.rs`）
- 実機前提: `tests/shim_v2_containerd_real.rs`（手順は `docs/verification/real-machine-tests.md`）。作成時に未実行。実行と記録は #3685（人間担当）
- 停止の方法に SIGKILL を使う（コンテナ内のプローブに SIGTERM のハンドラを入れるには core の試験用 feature が要り、plugin-cri の dev-dependencies に足したくないため）。終了コードの期待値 137（128 + SIGKILL）は実機で確かめる

## Exec の橋渡し（#4147・CRI-5・CRI-1・PLUG-1・SEC-1・REPAIR-3・REPAIR-5・TASK-62.7）

shim v2 の `Exec`・`Start(exec_id)`・`exec_id` つきの `State` / `Kill` / `Wait` / `Delete` は、注入トレイト `TaskExecLauncher` / `TaskExecProcess`（`crates/cri/src/shim_v2/exec.rs`）と登録簿 `ExecRegistry` まで実装済みで、本番の起動役だけが無い。本節は本番の起動役の橋渡し方式を、後続の #4148（本体）・#4149（配線）・#4150（実機前提試験）が正として読めるよう記録する。本メモは main の設計判断の記録であり、オーナー承認は得ていない（1 時間の上限は #4116 の暫定値に従う）。

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

A の共通モジュールの候補は `crates/plugin-cri/src/exec_helper.rs`（Linux のみ）。名前と分割の細部は #4148 で確定する。

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
| drop | 契約どおり停止は要求しない。helper の持ち主は launcher の追跡一覧に残り、shim の停止時に全 helper を kill する（配線は #4149） |

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

- **#4148 本体実装**: `exec_launcher.rs` の同期の中核を plugin-cri 内の共通モジュールへ切り出し、Linux 限定で `TaskExecLauncher` / `TaskExecProcess` を実装する（非 Linux は `UNIMPLEMENTED`）。偽の `HelperSpawner` による単体試験で、終了コード 0 / 3、SIGKILL だけが exec 子 cgroup に届き init には届かないこと、SIGKILL 以外が `UNIMPLEMENTED`、存在しないコンテナが `NOT_FOUND`、停止済みが `FAILED_PRECONDITION`、期限切れで helper を回収することを具体値で照合する。cri と依存は変えない
- **#4149 配線**: `registry_in` で scoped root と同じ `StateStore` から launcher を作り、`TaskService::with_exec_launcher` で v2・v3 に差す。shim の停止時に追跡中の helper を kill する。「本番の実装は無い」の表記（`exec.rs`・`shim_v2.rs`・`shim.rs`・本メモの「残り」・`docs/setup/linux.md`）を更新する
- **#4150 実機前提試験**: shim の ttrpc を直接叩き、最小の Process spec（env 空・cwd `/`・user なし・stdio なし）で exec し、CapEff・Seccomp・ns の inode・exec 子 cgroup の配置を具体値で init と照合する
- **後続候補（未起票）**: stream-exec の Signal frame、`Started` への pid の追加、stdio の FIFO の受け入れ、spec の欄を `config.json` と照合して受ける拡張と supervisor の exec ごとの env・cwd・user（#2712・#680 系列）、cri → supervisor の辺の機械照合（`dependency_direction.rs` の拡張）

## 残り（REPAIR-3）

- exec の起動役（`TaskExecLauncher`）の本番実装。exec は `UNIMPLEMENTED` のまま。方式は「Exec の橋渡し」節。実装は #4148・#4149、実機前提試験は #4150
- containerd が shim の死後に呼ぶ `delete` action での実行層の後始末
- `-publish-binary` によるイベントの publish（TaskExit など）
- rootful での shim 対応（#2442・#2241 の判断待ち）
- containerd 実機シナリオの CI への組み込み（ランナーの containerd の版に依存する）

## 再評価条件

- cri から plugin-cri への依存を許す判断が出たとき（bin を cri へ戻せる）
- 非 Linux の状態ルートが決まったとき（#2431。縮退を外せる）
