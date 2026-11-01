# healthcheck の exec 専用 helper（HealthProbe の本番アダプタ）

> **位置づけ**: 採用した設計の判断記録（#2441・SUP-4・SUP-6・SEC-1・SEC-4・REPAIR-5・TASK-161 追補）。実装は `crates/supervisor/src/healthcheck/exec_{wire,helper,probe}.rs`。
> 結線（monitor / supervisor 入口への `run_periodic` と `ExecHealthProbe` の組み込み・restart の quiesce の参加者・restart での付け替え）は #2953 が担う。argv[0] の PATH 解決と timeout 上限は #2439（オーナー判断待ち）が担い、本書では現行の拒否を保つ。

## 1. 目的と範囲

周期実行エンジン `run_periodic`（#495）と集約（#496）は実装済みだが、`HealthProbe` の本番実装が無く、コマンドは実行されなかった。本書は `HealthProbe` の本番アダプタ `ExecHealthProbe` が、exec 共通関数（`exec::run_command_with_pidfd` 系。TASK-163・SUP-6）で healthcheck コマンドを実行する方式を定める。

## 2. 方式: `/proc/self/exe healthcheck-exec`（単一スレッドの別プロセス）

- exec 共通関数は fork の直前に `Threads: 1` を強制する（`setns` が不可逆なため）。supervisor 本体は logs 捕捉スレッド等を持ち、probe は `ProbeRunner` が作る一時スレッド `healthcheck-probe` の上で呼ばれるため、本体から直接は呼べない
- probe のたびに `/proc/self/exe` を第 1 引数 `healthcheck-exec` で exec し直した helper を起動する。前例は `netns-holder`。`main.rs` では `run_main` より前に振り分ける（`run_main` の `close_fds_from`・結果チャネルの検証は helper の契約と合わないため。特権ランチャーは `StartArgs::parse` を通った argv だけを転送するので、この分岐の入口にならない）
- 新しい `unsafe` は追加しない（`pre_exec`・`SCM_RIGHTS`・`PR_SET_PDEATHSIG` を使わない）

### 却下案

| 案 | 却下理由 |
| -- | -------- |
| #2043 の quiesce 方式（常駐スレッドを止めて `Threads: 1` にする） | healthcheck は interval ごとに捕捉スレッドと並行して走る。毎回 `Threads: 1` へ落とせない。probe は一時スレッド上で呼ばれ、構造上も本体で直接呼べない |
| 常駐の zygote プロセス | 受け渡しと寿命の管理が増える |

## 3. fd の割り当て（`Stdio` だけで渡す）

| helper の fd | 中身 | 作り方 |
| --- | --- | --- |
| 0 | 起動時の pidfd の複製 | `LaunchedProcess::launch_pidfd()` の `try_clone_to_owned()` を `Stdio::from(OwnedFd)` で渡す |
| 1 | コマンドの出力（stdout・stderr を結合した 1 本）の子側 | `UnixStream::pair()`。親側は nonblocking |
| 2 | 結果行・診断行の子側 | 同上 |

- 不正な fd は fail-closed になる。core が pidfd と記録 pid を照合し、不一致を `exec_target_pidfd_mismatch` で拒否する
- pipe ではなく `UnixStream` を使う理由は、(1) 読み取りを nonblocking で待たずに回せる（`sys` に poll ラッパーを足さない）、(2) コマンドの子孫が書き込み端を持ったまま残っても読み手が止まらない、(3) core の診断出力（`emit_diagnostic_line`）が AF_UNIX の stderr にだけ出るため
- helper は `env_clear`・cwd `/`・`argv[0]` 固定。コマンドは `--` の後ろの argv 配列で渡す（シェルを通さない）。コマンドは実行中のプロセス自身の `/proc/<pid>/cmdline` でも見えるため、環境変数などの別経路にはしない

## 4. helper の処理順（`exec_helper::run_health_exec_main`）

1. `close_fds_from(3)`、`set_dumpable(false)`
2. 引数の検証（`--root`・`--id`・`--expect-pid`・`--timeout-ms`・`--` 以降のコマンド。各オプションはちょうど 1 回、argv[0] は絶対パス、timeout は 1ms 以上 60 秒以下）。失敗は `invalid`
3. 状態を読み、記録が `Running`・pid が `expect-pid`・`supervisor_pid` が親（起動した supervisor）と一致することを確かめる。不一致は `stale` で、exec も監査もしない（restart 後の古いアダプタが違反を毎回監査させない。SUP-1）
4. launch 時の env 上書きを読む（`container_options::store::launch_env_for`。期限つきの作業スレッドで包まない: helper は単一スレッドを保つため。helper 全体の期限は exec の期限と supervisor 側の exec 子 cgroup の停止が縛る。固まった helper は保持して次の probe を `Unavailable` にする）
5. `exec::default_audit_sink` で `FileAuditSink` を作る（SEC-4。単一スレッドのため `ControlAuditRelay` を通さず、段が落ちない）
6. `run_command_with_pidfd_output`（core の `spawn_exec_command_with_stdio` を使い、コマンドの fd 1・2 を出力 fd へ付け替える）
7. 結果を 1 行（`FCHX1 ...`）にして fd 2 へ書く

## 5. 結果行（`exec_wire`）

`FCHX1 exited <0-255> <healthy|unhealthy> <audit> <exit_audit>` / `FCHX1 signaled <1-64> unhealthy ...` / `FCHX1 not_started <step|-> <CODE> <0|1> <audit>` / `FCHX1 failed <CODE> <audit>` / `FCHX1 stale` / `FCHX1 invalid`。単一スペース区切り・語数ちょうど・最大 256 バイト。復号は許可リストで、未知の語・範囲外・矛盾（`exited 0 unhealthy`）・結果行が 0 本または 2 本以上は `Internal`（`Healthy` へ倒さない）。コマンドの出力・パス・errno の文字列は運ばない。

`ExecExit::SetupFailed`（コマンドが起動していない）とコマンドの非 0 終了は区別する。失敗した段（`ExecChildStep`）は値を含めない固定文言で `Internal` のメッセージと構造化ログに載せる（REPAIR-4）。

## 6. `probe` の戻り値の写像

| 状況 | 戻り値 |
| --- | --- |
| `exited 0` | `Ok(Healthy)` |
| `exited n≠0`・`signaled` | `Ok(Unhealthy)` |
| `not_started` | `Err(Internal, "healthcheck command did not start: <段の固定文言>")` |
| `failed TIMEOUT`・supervisor 側の期限超過・cancel | `Err(Timeout)` |
| `failed FAILED_PRECONDITION`（rlimit・分離の記録なし等の実行基盤の前提） | `Err(Internal)` |
| `failed` のその他 | 同じコードの `Err`（固定文言 + コード名。core のメッセージは載せない） |
| `stale` | `Err(FailedPrecondition)`（`still_owned` が偽なら loop を正しく止める） |
| `invalid`・結果行なし / 不正 / 複数・helper の起動失敗 | `Err(Internal)`（起動の `PermissionDenied` だけ `PermissionDenied`） |
| 同時実行の 2 本目 | `Err(Unavailable)` |

`periodic.rs` は「コマンドの失敗に `FailedPrecondition` を使ってはならない」と定めているため、実行基盤の前提不成立も `Internal` へ写す。

## 7. 出力（stdout / stderr）の扱い

- 先頭 4096 バイト（`OUTPUT_CAP`。Docker の Output 上限に倣った本実装の判断）だけを `HealthExecReport::output` に保持し、超えた分は読み捨てて合計バイト数と `truncated` を数える
- `state.json` には書かない（`health` は列挙のまま。要約の追加は core の `StateRecord` のスキーマ変更が要るため範囲外）
- 構造化ログ `healthcheck_exec` はバイト数と `truncated` だけを載せ、**本文は載せない**（秘密情報・ログ注入・command の中身を出さない方針）
- 本文は `ExecHealthProbe::last_report()` で読める（後続の inspect や #2953 が使う口）。表示するときは `output_escaped()`（制御文字・非 ASCII をエスケープ）を使う。`TraitError` のメッセージには本文を入れない

## 8. タイムアウトの層と cancel（REPAIR-5）

- `probe(T)` の絶対期限 `T` に対し、helper の exec の期限は `T - min(T/5, 2s)`（30s → 28s、5s → 4s、1s → 800ms）。通常は core が期限切れのコマンドを `cgroup.kill` して `Timeout` を返し、`T` より前に終わる
- `T` を過ぎても終わらない、または cancel されたときは、**helper へシグナルを送らない**（SIGKILL も SIGTERM も）。supervisor がやるのは、作成通知（`FCHC1`）で今回の作成を確認できた exec 子 cgroup の `cgroup.kill` と削除だけで、これで worker 配下のコマンドが止まり、worker が結果を返して helper が自分で終わる。supervisor は helper の終了を最大 1 秒（`REAP_TIMEOUT`）だけ待ち、`probe()` の呼び出し元へは従来どおり `Timeout` / `Cancelled` を返す。待ちきれなかった helper（同期ファイル I/O で固まった等）は `helper_reaped = false` で報告し、`Child` を `ExecHealthProbe` に最大 1 個保持する。保持している間は、次の probe の開始時に `try_wait` を行い（シグナルは送らない）、終わるまで新しい helper を作らず `Unavailable`（`a previous healthcheck exec helper has not been reaped`）を即座に返す。`cancel()` と drop も待たずに回収を試みる。保持は 1 個までなので、未回収 helper は積み上がらない（SUP-4・REPAIR-5）
- helper を SIGKILL しない理由: SIGKILL すると helper の子孫が、child subreaper である本番の supervisor へ再親付けされる。子孫は種類が増える（exec の worker、`FileAuditSink` が主経路のファイル I/O のために fork する使い捨ての子〔`crates/core/src/audit_log/file_sink.rs` のモジュール doc。時間切れの子は helper 自身が SIGKILL し、D 状態の子は helper が追跡して後続の呼び出しで回収する〕など）ため、特定して回収する通知を種類ごとに足す方式では収束しない。helper が生きて自分で終われば、自分の子孫は親の helper が回収し、再親付けが起きない。この前提により supervisor 側に worker などの回収経路は持たない
- worker とコマンドの停止は親死亡シグナルに頼らない（コマンドは `PR_SET_PDEATHSIG` を解除でき、fork した子孫には継承されないため）。helper は exec 子 cgroup の排他作成（同名は `EEXIST` で失敗）に成功した直後、worker の fork 前に、名前を作成通知（`FCHC1 <名前>`）として fd 2 へ 1 回だけ書く。supervisor は、この通知で今回の作成を確認できた cgroup（名前が `exec-<helper pid>-` で始まるもの）だけを `cgroup.kill` して削除する。pid から名前を推定しない。通知が無いときは何も止めない（以前の exec が残した同名の cgroup を誤って止めないため。SUP-6・#2441）
- `cancel()` はフラグを立てるだけですぐ戻る。probe のループが 5ms 刻みで見て、cgroup の停止と helper の終了待ちを自分で行う
- helper の終了後、出力と結果の EOF を 100ms だけ待つ（コマンドの子孫が書き込み端を持ち続けても待ち続けない）
- 結果ストリームは 32 KiB で打ち切る（超過は異常として `Internal`）。診断行は JSON 形（`{"` で始まり 1 KiB 以下）のものを最大 16 本だけ stderr sink へ転送し、残りは捨てて件数を数える
- 極端に短い timeout（1ms 等）は常に `Timeout` になる。上限・下限は #2439 の判断待ちのため変えない

### 残余

- **代償**: 同期 I/O などで固まった helper が居る間は、そのコンテナの healthcheck の probe は `Unavailable` のままになる（保持は 1 個までで、ゾンビは溜まらない。helper が終われば次の probe から進む）。helper を殺して即座に先へ進む方式より可用性は下がるが、再親付けされる子孫を無くすことを優先した（SUP-4・REPAIR-5）
- 作成通知を受ける前（cgroup の作成より前、または作成の完了から通知の書き込みまでの間）に期限切れ・cancel になった場合、supervisor は止められない（helper へもシグナルを送らない）。helper は自分の exec の期限（`T` より短い）まで動き、その間コマンドが起動し得る。helper が終わるまで次の probe は `Unavailable` で、populated な `exec-*` の子 cgroup が残れば delete 前の掃除（`cgroup.kill` を含む）が回収する。次の exec 開始時の掃除が回収するのは空の cgroup だけである
- 作成通知を受けた cgroup の停止に失敗した場合（`cgroup_stop_failed = true`）も、同じく delete 前の掃除が回収する
- supervisor が異常終了した場合、helper は `PR_SET_PDEATHSIG` を持たない（生成元が一時スレッドで、PDEATHSIG はそのスレッドに束縛されるため）。helper 自身の exec 期限と後始末で終わる

## 9. ambient capability（SEC-1）

rootful の supervisor は特権ランチャー由来の ambient capability で setns・cgroup join を行う。helper も同じ集合を継承する必要があるため、helper では落とさない。「子で ambient を落としてから exec する」（`privilege-separation.md` 5 章 5・10 章）は、コマンドの `execveat` の直前に満たされる: core の再適用（`reapply_restrictions`）が bounding 削除 → `PR_CAP_AMBIENT_CLEAR_ALL` → capset → 読み戻しの順で行い、`require_exec_ready`（`ExecReady`）を通らなければコマンドは起動しない。rootless の supervisor は ambient を持たない。実機での `CapAmb=0` の確認は人間担当の #539 の範囲である。

## 10. argv[0] と timeout（#2439 未決）

`ExecHealthProbe::new` は argv[0] が絶対パスでなければ `InvalidArgument`（固定文言。command の中身を出さない）で拒否する。60 秒超の timeout は既存の `HealthcheckSchedule::from_definition` と `probe_and_record` の拒否のまま。helper の `--timeout-ms` の上限も 60 秒。

## 11. 再評価条件

- #2439 が決まり、PATH 解決や 60 秒超の timeout を許すとき
- core が `StateRecord` に healthcheck の出力要約を持てるようになったとき（`state.json` への要約の追加）
- helper の起動コスト（interval が短い構成）が問題になったとき
