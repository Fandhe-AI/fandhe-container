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

## 残り（REPAIR-3）

- exec の起動役（`TaskExecLauncher`）の本番実装。exec は `UNIMPLEMENTED` のまま
- containerd が shim の死後に呼ぶ `delete` action での実行層の後始末
- `-publish-binary` によるイベントの publish（TaskExit など）
- rootful での shim 対応（#2442・#2241 の判断待ち）
- containerd 実機シナリオの CI への組み込み（ランナーの containerd の版に依存する）

## 再評価条件

- cri から plugin-cri への依存を許す判断が出たとき（bin を cri へ戻せる）
- 非 Linux の状態ルートが決まったとき（#2431。縮退を外せる）
