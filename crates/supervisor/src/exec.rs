//! exec の入口: 稼働中コンテナの pid1 を特定し、その namespace と cgroup へ参加して制限を再適用し、コマンドを実行する（SUP-6・TASK-163.1〜163.4・#500〜#503・MS-9）。
//!
//! # 役割と呼び出し文脈
//!
//! `state.json` のレコードから対象を決め、`fandhe_container_core::exec` の安全 API（`Pid1Target` /
//! `join_namespaces` / `prepare_cgroup_join` / `join_cgroup` / `prepare_exec_restrictions` /
//! `reapply_restrictions`）へ配線するだけの薄い層で、`unsafe` も OS 分岐も持たない（OS 局所化は core。CLI-1）。
//! 通しの入口は [`run_command`]（#503）。exec 専用プロセスと TASK-161（SUP-4）の healthcheck が同じ関数を使う
//! （`health.rs` の `HealthProbe` が期待する共通コードパス）。
//!
//! # 契約
//!
//! - 記録上の pid は **候補** にすぎず、シグナル送信・回収・`/proc` の宛先にそのまま使わない
//!   （pid 再利用対策。SEC-1）。core の `Pid1Target::open` が pidfd 固定のうえで pid1 であることを検証し、
//!   通ったものだけを [`ExecTarget`] にする。さらに pid が別コンテナに再利用されていないことを、
//!   記録した cgroup 配置（委譲スコープと instance）から core が導くコンテナ固有の cgroup パス
//!   `<scope>/fc-<id>@<instance>` と対象の所属 cgroup の完全一致で確認する（SEC-1）。instance は
//!   ストア全体で再利用されないため、`state.json` へプロセス識別情報（開始時刻等）を追加せずに
//!   「記録したコンテナのプロセスであること」を照合できる（スキーマ変更なし）。この照合が依存する前提
//!   （コンテナから cgroupfs に書けないこと）と見直しの条件は core の `exec/setns.rs` のモジュール doc を参照
//! - 既定のビルドの公開 API に、期待 cgroup パスを文字列で受ける入口は無い（core・supervisor とも
//!   `exec-test-support` feature を付けたビルドに限る）。worker 機構を任意の処理で直接呼ぶ試験専用の入口
//!   （`run_in_worker_for_test`）と core の観測用の入口も同じ feature の下に置き、**リリースビルドでこの feature が
//!   有効だとコンパイルが止まる**（`src/lib.rs` の `compile_error!`。期待 cgroup パスを呼び出し側から渡せると
//!   SEC-1 の同一性照合を迂回できるため。TASK-163 追補・#1460）。supervisor 自身のテストでは dev-dependency の
//!   自己参照で有効になり、試験専用の入口を使う結合試験は既定のテスト集合に残る
//! - [`enter_namespaces`] は呼び出しスレッドの namespace を不可逆に変える。単一スレッドのプロセスから
//!   のみ呼べる。logs 捕捉スレッドを持つ supervisor 本体からは呼ばず、exec 専用プロセスから呼ぶ（[`run_command`]。#503）
//! - 順序: [`prepare_cgroup_join`]（cgroup.procs の fd 確保。#501）は [`enter_namespaces`] の **前**、
//!   [`join_cgroup`] は準備の後（`enter_namespaces` の後・seccomp の前。[`run_command`] が固定する）。
//!   `/proc/self/cgroup` の fd も準備で確保する（`setns` 後は自プロセスを procfs から解決できないため）
//! - 制限の再適用（#502・#503）: [`prepare_restrictions`]（ホスト側の `config.json` を読み、
//!   コンテナの rootfs を固定し、自プロセスの `/proc/self/status` の fd を確保）は [`enter_namespaces`] の **前**、
//!   [`reapply_restrictions`] は [`enter_namespaces`] と [`join_cgroup`] の **後**（seccomp が `setns` を
//!   拒否するため）。**準備したプロセス自身** が単一スレッドで呼ぶ（fork した子から呼ぶと別プロセスの
//!   スレッド数を読むため、core が準備時の pid との不一致を拒否する）。適用は不可逆で、失敗時は制限が
//!   部分的に載った不定状態のため、呼び出し側は続行せず終了する。「適用 → fork → execve」の順にする
//!   （制限は fork / execve を越えて継承される）。準備は不可逆な補助グループ消去を含むため、core の
//!   `spawn_exec_worker` の worker の中でしか得られない証跡 `ExecWorkerProof` を要求する（常駐側から呼べない。#1532）。順序の全体:
//!   `identify_pid1` → `prepare_cgroup_join` → 子 cgroup の作成 → `prepare_restrictions` → `enter_namespaces` → `join_cgroup` →
//!   `reapply_restrictions` → `require_exec_ready` → `spawn_exec_command`
//! - 再適用は、参加後の自プロセスの `/` が **記録したコンテナの rootfs**（[`identify_pid1`] に渡した記録の
//!   bundle から、start と同じ検査・固定で得たディレクトリ）であることを照合してから適用する。不一致
//!   （pivot していない対象・`/` へ別のマウントが重ねられた対象）は違反 `exec_root_not_container_rootfs` で
//!   拒否し、何も適用しない（SEC-1。根拠は core の `exec/reapply.rs` のモジュール doc）。bundle は
//!   [`ExecTarget`] が特定時の記録から保持するため、別の記録の `config.json`・rootfs を取り違えない
//! - **完了は型で表す**: 再適用は rlimit（対象 pid1 の実効値）・capability 削減（OCI 既定集合）・`NO_NEW_PRIVS`・
//!   Landlock・seccomp を載せる（launch 経路と同じ順序。#503）。`ExecRestrictionReport` のフィールドは非公開で、
//!   crate の外から未適用の一覧を書き換えたり値を構築したりできない。exec へ進んでよいことの証跡は core の
//!   `ExecReady` で、[`require_exec_ready`]（core の `ExecRestrictionReport::into_complete`）だけが作る。
//!   core の `spawn_exec_command`（fork → `close_range` → `execveat`）は `ExecReady` を値で受け取り、
//!   `ExecRestrictionReport`・真偽値を受け取る入口はない（SEC-1）
//! - **コマンドの環境と補助グループ**（SEC-1・SEC-5・TASK-163 追補・#1457）: [`run_command`] はコマンドを
//!   [`ExecRequest`]（コンテナ内の絶対パス・argv・明示の環境変数）で受け取る。**環境変数の基底は呼び出し側から
//!   渡せず**、worker が対象の bundle の `config.json` の `process.env`（コンテナ定義。launch がエントリポイントへ
//!   渡すのと同じ出所）から組み立てる。呼び出し側が足せるのは、利用者がその exec に対して明示した値
//!   （`ExecRequest::with_env`。検証済みの `EnvVar`）だけで、`execveat` の envp はこの 2 つだけから作る。exec を
//!   起動したプロセス（CLI・supervisor）の環境は 1 つも渡らず、既定値の補完もしない（入口が `std::env::vars()` を
//!   渡す形は型で書けない。core の `exec/container_env.rs`）。補助グループは launch と同じく空にする（core の
//!   capability 削減が `setgroups(0)` を呼ぶ。exec を起動したプロセスのホスト側の補助グループを持ち越さない）。
//!   **消去は namespace へ参加する前にも行う**（[`prepare_restrictions`]・[`run_command`] の準備の最後。不可逆。
//!   worker の証跡 `ExecWorkerProof` がなければ呼べない。#1532）:
//!   対象の user namespace へ入った後は `setgroups` が `deny` で消せなくなり、exec を起動したプロセス（root・
//!   `sudo` 経由・別のグループ集合のセッション）のグループをコンテナへ持ち込むため。消去できず `deny` も確認
//!   できなければ、参加せずに拒否する。起動者自身が既に `setgroups` を禁じた user namespace の中にいる場合
//!   （rootless）だけは残し、[`ExecOutcome`] の `supplementary_groups` に記録する（残るのは **exec を起動した
//!   プロセスの** 補助グループで、user namespace の作成者と同じとは限らない）。uid / gid は変更しない（launch も同じ）
//! - **`execve` 前の失敗とコマンドの終了を区別する**（REPAIR-3・TASK-163 追補・#1460）: [`ExecOutcome`] の `exit` は
//!   core の `ExecExit` で、`Command`（コマンドが起動して終了した）と `SetupFailed`（コマンドは起動していない。
//!   子が `execve` より前の手順か `execve` 自体で失敗した）を分ける。子の終了コード 125 / 126 / 127 は実行された
//!   コマンド自身も返し得るため、終了コードでは判定しない。子が close-on-exec の pipe で親へ知らせた内容で
//!   判定する（core の `exec/exec_command.rs`）。分離違反による拒否（ランタイム自身のバイナリ・インタープリタ経由・
//!   `/dev/null` の差し替え）は理由コードを持ち、呼び出し側が違反として記録できる（SEC-4。監査ログへの保存は
//!   下記「未実装」）
//! - **rlimit の空集合は拒否する**（TASK-163 追補・#1460）: 対象の実効 rlimit を 1 つも得られなかった場合、core は
//!   適用を省かず `FailedPrecondition` で拒否する（rlimit を載せないまま exec へ進む経路を作らない）
//! - **コンテナから見える窓を閉じる**: exec の子は fork した時点でコンテナの PID namespace に入り、
//!   `close_range` までの間コンテナの procfs から見える。worker は開始時に自分を non-dumpable にし（core の
//!   `spawn_exec_worker`）、core の `spawn_exec_command` は non-dumpable でないプロセスからの fork を拒否する。
//!   同じ uid のコンテナ内プロセスが `/proc/<pid>/fd` 等からホスト側の fd へ届く経路を作らない
//!   （CVE-2016-9962 型の対策。SEC-1。詳細は core の `exec/exec_command.rs`）
//! - **制限は対象へ束縛される**: [`prepare_restrictions`] が対象 pid1 の mount namespace の識別子を記録し、
//!   [`reapply_restrictions`] が参加後の自プロセスのものと照合する。同じ rootfs を共有する別コンテナへ参加した
//!   場合は違反 `exec_joined_namespace_mismatch` で拒否し、何も適用しない（`/` の照合だけでは検出できない）
//! - **全体の上限時間**: [`run_command`] は対象の特定から終了待ちまでの全体に上限時間を課す（REPAIR-5）。
//!   `setns`・cgroup join・制限の再適用・procfs / cgroupfs の読み書きは単一スレッドでブロックし得るため、
//!   同一プロセス内の期限確認では途中のハングを止められない。そこで **準備から実行までを worker プロセスへ
//!   隔離** する: 呼び出しプロセス（単一スレッド）が core の `spawn_exec_worker` で worker を fork し、全体の
//!   期限（worker 内の段の間の確認・fork 後の `wait_timeout` が使う期限と同じ）に猶予を足した時間で worker の
//!   終了を待つ。超過したら worker を `SIGKILL` して回収し、構造化された `Timeout` を返す。worker の結果
//!   （終了状態・適用件数、または `code` / `message`）は pipe の 1 行で返す。worker は `setns` 等で不可逆に
//!   状態を変えるが、変わるのは使い捨ての worker だけで、呼び出しプロセスの namespace・cgroup・制限は変わらない
//!   （コマンドは worker の子として実行される）。worker が起動後のコマンドを待つ間に強制終了された場合に
//!   コマンドを孤児として残さないよう、worker とコマンドはそれぞれ親の死亡シグナル（`SIGKILL`）を設定し、
//!   設定の後に親の生存を親の pidfd で確かめる（core の `spawn_exec_worker` / `spawn_exec_command`）。呼び出し
//!   プロセスの終了 → worker の停止 → コマンドの停止が連鎖する。**限界**: 実行されたコマンド自身は親の死亡
//!   シグナルを `prctl` で解除でき、コマンドがコンテナ内で作った子孫には届かない。そのため停止は下の
//!   「exec 用の子 cgroup」の `cgroup.kill` で行う（親死亡シグナルは多層防御として残す）
//! - **exec 用の子 cgroup と `cgroup.kill`**（SUP-6・SUP-4・REPAIR-5・CORE-4・TASK-163 追補・#1466）: コマンドだけを
//!   コンテナ cgroup 直下の子 cgroup（`exec-<nonce>`。nonce は呼び出しプロセスが exec ごとに生成）へ入れて実行し、
//!   期限切れ・中断・worker 異常終了のいずれでも `cgroup.kill` で子孫ごと止めて削除する。worker はコンテナ cgroup に
//!   留まる（`cgroup.kill` が worker を巻き込まず、期限切れを `Timeout` で返せる）。子 cgroup は
//!   [`prepare_cgroup_join`] の直後（`enter_namespaces` と再適用の前。再適用後の worker は Landlock で cgroupfs を
//!   開けない）に作り、fork した子が `execve` の前に自分を移す。親 cgroup の `memory.max`・`pids.max` 等は階層的に
//!   子孫へ掛かる（controller は子 cgroup に有効化しない）。`cgroup.kill`（Linux 5.14 以降）が使えなければ exec を
//!   拒否する（fail-closed）。**停止は 2 段**: worker は保持 fd への write で `cgroup.kill` する（コマンドの終了後・
//!   期限切れの停止。正常終了後も子孫を止める＝exec の終了後にコマンドの子孫を残さない。`sh -c 'daemon &'` 型の
//!   バックグラウンド化は exec の終了で止まる）。**削除と最終の停止は呼び出しプロセス**が、worker の終了後（どの
//!   経路でも）に記録から導いたコンテナ cgroup を開き直して行う（core の `remove_exec_child_cgroup`。冪等。
//!   待機は 5 秒の上限つき）。後始末の失敗は元のエラーへ併記し、成功を装わない。**限界**: 呼び出しプロセス自身が
//!   `SIGKILL` された場合は子 cgroup が残り得る（未実装: delete 前と次回 exec 開始時の `exec-*` の掃除。TASK-30.3・
//!   OCI-6・SUP-6。残ると `delete` のコンテナ cgroup の `rmdir` が失敗する）
//! - 再適用の Landlock ルールは、launcher が実際にマウントした結果ではなく bundle の `config.json` から
//!   再導出する（launch 時の ruleset は保存されていない）。launch 後に `config.json` が書き換えられると
//!   追従してしまうが、bundle は supervisor と同じ信頼境界（コンテナから書けない場所）にある前提とする。
//!   config の mount destination が稼働中の rootfs に無ければ Landlock の適用が失敗し、exec は拒否される
//!   （fail-closed）
//! - [`join_cgroup`] は呼び出しプロセスをコンテナの cgroup へ移す（`cgroup.procs` はスレッドグループ全体を
//!   移す）。supervisor 本体から呼ばず、委譲スコープの内側で動く exec 専用プロセスからのみ呼ぶ。
//!   失敗時は所属が不定のため、呼び出し側は続行せず終了する（fail-closed）。保持 fd は子が `execve` の前に
//!   `close_range` で閉じる（core の `exec/process.rs`）
//!
//! - **監査記録**（SEC-4・SUP-6・TASK-163 追補・#1465）: [`run_command`] は監査の記録先 [`AuditSink`] を必須の
//!   引数に取り、exec の対象の拒否（種別 `exec_target`。理由 `exec_target_*`・`exec_root_not_container_rootfs`・
//!   `exec_joined_*` の 9 種）を層 `exec_target` のレコードとして **1 拒否につき 1 件** 記録する。監査なしで通す
//!   入口は無い。記録点は worker の結果を復号した直後の **親プロセス（exec を起動したプロセス）** の 1 箇所で、
//!   worker の中では記録しない（worker は `setns` 後にコンテナの mount namespace と cgroup に入っており、そこで
//!   sink の I/O やロックを走らせると、ホストの監査ファイルのロックをコンテナの cgroup 内のプロセスが保持し得る
//!   ため）。記録の PID は記録を行った親プロセスのもの、時刻は親が worker の結果を受け取った時点（拒否から最大で
//!   exec の上限時間ぶん遅れ得る）。**載せるのは層・理由コード（静的トークン）・時刻・PID だけ** で、ホスト側
//!   パス・期待 cgroup パス・namespace 識別子・bundle パスは載せない（`AuditEvent::ExecTarget` がパスを持たない
//!   型）。worker から親へ渡す理由コードは許可リストで引き直した静的値だけを記録へ入れる（ログ注入の経路を作らない）。
//!   記録の成否で拒否は覆らない（fail-closed）。結果は [`AuditedRejection::delivery`] で返し、黙って捨てない。
//!   段単位の公開関数（[`identify_pid1`]・[`enter_namespaces`]・[`join_cgroup`]・[`reapply_restrictions`] 等）は
//!   単体では記録せず、記録するのは通しの入口だけ
//!
//! # `execve` を結線する前の 5 条件（#502 が残し、#503 で満たした）
//!
//! 1. 完了を型で強制する: core の `spawn_exec_command` は `ExecReady` だけを値で受け取る
//! 2. capability 削減と rlimit 適用を実装し、未適用の一覧は空
//! 3. 制限を exec の対象へ束縛する（mount namespace・子が入る PID namespace・所属 cgroup の照合）
//! 4. `setns` を伴う通し試験: `tests/exec.rs`（実機前提。AGENTS.md。root を要し、CI ではビルドのみで実行して
//!    いない）。pivot 済みの対象へ参加した後の `/` が固定した rootfs と一致することだけは、CI で実行する
//!    `tests/exec_setns_join.rs` が非特権の user namespace で照合する
//!    （既定の入口 [`identify_pid1`] が実 cgroup の記録から成功すること・別 instance と特定後の cgroup 移動を拒否
//!    することは、委譲 cgroup を要する実機前提の `tests/exec_identify_cgroup.rs` が照合する。#1464）
//! 5. exec 専用プロセス全体のタイムアウトと、`execve` 前の `close_range`（[`run_command`] と core の
//!    `exec/exec_command.rs`）
//!
//! # 対象の固定: 起動時の pidfd と縮退経路（#1461）
//!
//! - **恒久策**: [`identify_pid1_with_pidfd`] / [`run_command_with_pidfd`] は、supervisor（起動ハンドル）が
//!   起動時（fork 直後・回収前）から保持する pidfd（`LaunchedProcess::launch_pidfd`）で対象を固定し、同一性を
//!   記録 pid との一致で確かめる。cgroup の所属に依存しないため、コンテナ内から cgroupfs に書ける構成でも
//!   兄弟コンテナの cgroup への偽装で別コンテナを対象にされない（SEC-1）。pidfd が得られない
//!   （未対応カーネル・seccomp・起動ハンドルなし）場合、この入口の内部では記録 pid へ縮退せず拒否する
//! - **縮退経路**: [`identify_pid1`] / [`run_command`] は記録 pid から開き、cgroup の所属で同一性を照合する。
//!   supervisor 不在（孤児化・再起動後で起動時の pidfd を失った）場合の明示された縮退経路で、「コンテナの中から
//!   cgroupfs に書けない」前提（core の `exec/setns.rs` のモジュール doc）が成り立つ間だけ使う。cgroupfs の
//!   マウント・cgroup namespace・`/sys/fs/cgroup` の bind mount を導入する変更は、この縮退経路を拒否へ切り替える
//!   こと
//!
//! # 未実装（REPAIR-3）
//!
//! - supervisor から別プロセスの exec 専用プロセスへ pidfd を渡す 1 段目（execve 越しの継承、または外部 CLI への
//!   `SCM_RIGHTS`）。supervisor のバイナリ入口・制御ソケットが無く、`SCM_RIGHTS` は UDS の所有者・peer credential
//!   検証と core `sys` の cmsg ラッパーの設計を要する。fork 継承（[`run_command_with_pidfd`]）は pidfd を保持する
//!   単一スレッドのプロセスが呼ぶ場合に限り成立し、logs 捕捉スレッドを持つ supervisor 本体は直接呼べない
//!   （`setns` が拒否する）
//! - user namespace への参加。既定の rootless（コンテナが user namespace を持つ）では、対象が呼び出し側と別の
//!   user namespace にいることを理由に [`identify_pid1`] が違反 `exec_target_in_other_user_namespace` で拒否する
//!   （[`enter_namespaces`] も `setns` の直前に再照合する。rootful の呼び出し側では `setns` 自体は成功して
//!   しまい、exec したコマンドがコンテナより強い権限で動くため、カーネルの拒否には依存しない。fail-closed。
//!   rootless の exec には必須。通しの結合試験は rootful のみ）
//! - コマンドの標準入出力の受け渡し（CLI の exec・TASK-161 / SUP-4 の healthcheck の出力取得）。現状は launch と
//!   同じく `/dev/null` へ固定し、cwd・ユーザーの指定も未対応（cwd はコンテナの rootfs の根。`config.json` の
//!   `process.user.additionalGids` の解釈〔指定したグループの付与〕も launch・exec とも未実装で、補助グループは
//!   常に空）
//! - 違反記録（SEC-4）の監査ログへの保存のうち、本番の `AuditSink` の実体（`AuditFileWriter` とカーネル監査
//!   フォールバックを束ねたもの）の生成と、CLI・supervisor から [`run_command`] へ渡す配線（TASK-29 / TASK-157 系）。
//!   層 `exec_target` と [`run_command`] での 1 拒否 1 件の記録は実装済み（#1465）。`ExecOutcome::exit` が運ぶ
//!   `execve` 前の違反（`SetupFailed`。種別 `entrypoint`）の監査記録も未実装で、launch 経路と共有する種別のため
//!   層の設計は別に決める
//! - `--ulimit` の指定値の `state.json` への記録。現状は pid1 の実効値を写して代替する（hard は launch を
//!   超えないが、soft は pid1 が hard の範囲で上げていれば launch の指定より高くなり得る。core の
//!   `exec/reapply.rs` のモジュール doc）
//! - 実機前提の通し試験 `tests/exec.rs` の実行結果の記録（root を要し、CI ではビルドのみで実行していない）

use std::io::{BufRead as _, Read as _, Write as _};
use std::os::fd::BorrowedFd;
use std::time::{Duration, Instant};

use fandhe_container_core::audit_log::{AuditSink, AuditedRejection};
use fandhe_container_core::exec::{
    ChildExit, ContainerEnv, ENTRYPOINT_MAX_ARGS, ENTRYPOINT_MAX_ENV, ENTRYPOINT_MAX_STRING_BYTES,
    ENTRYPOINT_MAX_TOTAL_BYTES, ExecCgroupJoin, ExecCgroupJoinReport, ExecCgroupName,
    ExecChildCgroup, ExecCommand, ExecError, ExecExit, ExecReady, ExecRestrictionReport,
    ExecRestrictions, ExecWorkerProof, NamespaceJoinReport, Pid1Target, SupplementaryGroups,
    ViolationReason, join_cgroup as core_join_cgroup, join_namespaces,
    prepare_cgroup_join as core_prepare_cgroup_join,
    prepare_exec_restrictions as core_prepare_exec_restrictions,
    reapply_restrictions as core_reapply_restrictions, record_exec_target_rejection,
    remove_exec_child_cgroup, spawn_exec_command, spawn_exec_worker,
};
use fandhe_container_core::oci_runtime::{OciConfig, RootfsDir, load_config, pin_bundle_rootfs};
use fandhe_container_core::traits::{
    CgroupPlacement, ContainerId, ContainerState, ErrorCode, StateRecord, TraitError,
};

use crate::container_options::env::EnvVar;

/// 検証済みの exec 対象（コンテナ ID と、pidfd で固定した pid1、特定に使った記録の bundle）。
#[derive(Debug)]
pub struct ExecTarget {
    id: ContainerId,
    pid1: Pid1Target,
    /// pid1 の特定に使った記録の bundle。[`prepare_restrictions`] が `config.json` と rootfs をここから
    /// 取るため、pid1 を照合した記録と別の記録の設定で制限を組み立てることがない。
    bundle: std::path::PathBuf,
}

impl ExecTarget {
    /// 対象のコンテナ ID。
    pub fn id(&self) -> &ContainerId {
        &self.id
    }

    /// 検証済みの pid1。
    pub fn pid1(&self) -> &Pid1Target {
        &self.pid1
    }
}

/// `record` が稼働中で pid の記録を持つことを確かめ、記録 pid（候補）を返す。
fn running_pid(record: &StateRecord) -> Result<std::num::NonZeroU32, TraitError> {
    let status = record.status();
    match status.pid() {
        Some(pid) if status.state() == ContainerState::Running => Ok(pid),
        _ => Err(TraitError::new(
            ErrorCode::FailedPrecondition,
            "container is not running or has no recorded pid; cannot identify pid1",
        )),
    }
}

/// `record` の稼働中コンテナから pid1 を特定する。
///
/// `Running` かつ pid 記録ありでなければ `FailedPrecondition`。記録 pid は検証（pidfd 固定・直接入れ子の
/// PID 1・記録の cgroup 配置から導いた cgroup への所属・自分と別の pid / mnt namespace）を通ったときだけ
/// 採用する。期待 cgroup パスは core が記録の型（コンテナ ID・cgroup 配置）から組み立て、ここでは文字列を
/// 扱わない。
pub fn identify_pid1(record: &StateRecord) -> Result<ExecTarget, TraitError> {
    let pid = running_pid(record)?;
    // 記録 pid が別コンテナの PID 1 に再利用されていないことを、コンテナ固有の cgroup で確かめる
    // （pidfd だけでは記録上の元プロセスとの同一性を証明できない。SEC-1）。cgroup 配置の記録がなければ
    // 同一性を確認できないため拒否する（fail-closed）。
    let Some(placement) = record.cgroup() else {
        return Err(TraitError::new(
            ErrorCode::FailedPrecondition,
            "container has no recorded cgroup placement; cannot verify pid1 identity",
        ));
    };
    let id = record.status().id();
    let pid1 = Pid1Target::open(pid, id, placement).map_err(from_exec_error)?;
    Ok(ExecTarget {
        id: id.clone(),
        pid1,
        bundle: record.bundle().to_path_buf(),
    })
}

/// 起動時（fork 直後・回収前）から保持する pidfd で対象を固定して、`record` の稼働中コンテナから pid1 を
/// 特定する（SUP-6・SEC-1・CORE-1・TASK-163 追補・#1461）。
///
/// `pidfd` は起動ハンドルが保持するもの（`LaunchedProcess::launch_pidfd`。`None` なら呼び出し側が拒否する）。
/// [`identify_pid1`] が記録 pid から `pidfd_open` して cgroup の所属で同一性を照合するのに対し、こちらは
/// pidfd の指すプロセスが記録 pid と一致することを同一性の根拠にする（cgroup の所属に依存しない。cgroup の
/// 照合は多層防御として残る）。`pidfd` は複製して core へ渡す（呼び出し側の fd は閉じない。複製は
/// close-on-exec）。稼働中でない記録・cgroup 配置の記録なしは [`identify_pid1`] と同じく
/// `FailedPrecondition`。pidfd の不一致は違反 `exec_target_pidfd_mismatch` で拒否する。
pub fn identify_pid1_with_pidfd(
    record: &StateRecord,
    pidfd: BorrowedFd<'_>,
) -> Result<ExecTarget, TraitError> {
    let pid = running_pid(record)?;
    let Some(placement) = record.cgroup() else {
        return Err(TraitError::new(
            ErrorCode::FailedPrecondition,
            "container has no recorded cgroup placement; cannot verify pid1 identity",
        ));
    };
    let owned = pidfd.try_clone_to_owned().map_err(|e| {
        TraitError::new(
            ErrorCode::Internal,
            format!("failed to duplicate the launch pidfd: {}", e.kind()),
        )
    })?;
    let id = record.status().id();
    let pid1 =
        Pid1Target::open_with_launch_pidfd(owned, pid, id, placement).map_err(from_exec_error)?;
    Ok(ExecTarget {
        id: id.clone(),
        pid1,
        bundle: record.bundle().to_path_buf(),
    })
}

/// 実機結合試験専用の入口: 期待 cgroup 絶対パスを呼び出し側から受け取って pid1 を特定する。
///
/// `exec-test-support` feature を付けたビルドにだけ存在し、既定のビルド（リリース成果物を含む）の公開 API には
/// 含まれない（core の `Pid1Target::open_with_cgroup_path` も同じ feature に限る）。コンテナ用 cgroup を
/// 作れない試験環境で `Pid1Target` 以降の成功経路を通すためのもので、期待値を記録から導かないため
/// 「記録したコンテナのプロセスであること」（SEC-1）の照合にはならない。本番経路は必ず [`identify_pid1`] を使う。
#[cfg(feature = "exec-test-support")]
pub fn identify_pid1_in(
    record: &StateRecord,
    expected_cgroup_path: &str,
) -> Result<ExecTarget, TraitError> {
    let pid = running_pid(record)?;
    let pid1 =
        Pid1Target::open_with_cgroup_path(pid, expected_cgroup_path).map_err(from_exec_error)?;
    Ok(ExecTarget {
        id: record.status().id().clone(),
        pid1,
        bundle: record.bundle().to_path_buf(),
    })
}

/// SUP-6 の 5 種（pid / mnt / uts / ipc / net）の namespace へ参加する。単一スレッドからのみ呼ぶこと。
pub fn enter_namespaces(target: &ExecTarget) -> Result<NamespaceJoinReport, TraitError> {
    join_namespaces(&target.pid1).map_err(from_exec_error)
}

/// 対象のコンテナ cgroup を開き、参加に必要な fd を確保する。[`enter_namespaces`] の **前** に呼ぶ（SUP-6・#501）。
pub fn prepare_cgroup_join(target: &ExecTarget) -> Result<ExecCgroupJoin, TraitError> {
    core_prepare_cgroup_join(&target.pid1).map_err(from_exec_error)
}

/// 自プロセスをコンテナの cgroup へ参加させ、所属を確認する。exec 専用プロセスからのみ呼ぶこと
/// （契約はモジュール doc）。失敗時は続行せず終了すること。
pub fn join_cgroup(join: ExecCgroupJoin) -> Result<ExecCgroupJoinReport, TraitError> {
    core_join_cgroup(join).map_err(from_exec_error)
}

/// コンテナの `config.json` から Landlock ruleset を作り、コンテナの rootfs を固定し、自プロセスの status fd・
/// 対象の mount namespace の識別子・対象の実効 rlimit を確保し、**最後に自プロセスの補助グループを空にする**
/// （不可逆。namespace へ参加する前に消去するため。TASK-163 追補・#1457。契約はモジュール doc）。[`enter_namespaces`] の **前** に、再適用を
/// 行うプロセス自身が呼ぶ（SUP-6・#502・#503。契約はモジュール doc）。
///
/// `config.json` と rootfs は、`target` を特定した記録の bundle から取る（呼び出し側は記録を渡し直さない）。
/// rootfs は start と同じ検査（bundle 配下・symlink なし）で固定し、参加後の `/` と照合する基準にする。
/// Landlock 未対応カーネル・ルール生成失敗・rootfs を固定できない場合は拒否する（fail-closed。CORE-5・SEC-1）。
///
/// `worker` は core の `spawn_exec_worker` の worker の中でしか得られない証跡（[`ExecWorkerProof`]）。準備の最後に
/// 呼び出しプロセスの補助グループを不可逆に消すため、常駐側（supervisor 本体・CLI）から呼べないよう型で絞る
/// （#1532）。本番の `run_command` 系は worker の中で同じ core の関数を直接呼ぶ。
pub fn prepare_restrictions(
    worker: &ExecWorkerProof,
    target: &ExecTarget,
) -> Result<ExecRestrictions, TraitError> {
    let (config, rootfs) = load_exec_bundle(&target.bundle)?;
    core_prepare_exec_restrictions(worker, &target.pid1, &config, &rootfs).map_err(from_exec_error)
}

/// 稼働中コンテナの中で実行するコマンドの要求（コンテナ内の絶対パス・argv・明示の環境変数。
/// SUP-6・SEC-1・TASK-163 追補・#1457）。
///
/// [`run_command`] の入力。**環境変数の基底は呼び出し側から渡せない**: 基底は常に、対象の記録の bundle の
/// `config.json` の `process.env`（コンテナ定義。launch 経路がエントリポイントへ渡すのと同じ出所）で、worker が
/// 読み込んで組み立てる。呼び出し側が足せるのは、利用者がその exec に対して明示した値（[`Self::with_env`]。
/// CLI の `-e KEY=VALUE` 相当）だけで、検証済みの [`EnvVar`]（値なしの `-e KEY` によるホスト環境の継承を拒否する型。
/// `container_options::env`）でしか受け取らない。exec を起動したプロセスの環境は、exec されたコマンドへ
/// 1 つも渡らない（core の `exec/container_env.rs`）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecRequest {
    path: std::path::PathBuf,
    args: Vec<String>,
    env: Vec<EnvVar>,
    /// `env` の `KEY=VALUE` と NUL 終端ぶんの合計バイト数（上限検証用）。
    env_bytes: usize,
}

impl ExecRequest {
    /// 検証して作る。`path` は空でないコンテナ内の絶対パス、`args`（argv）は 1 件以上で NUL を含まない
    /// （違反は `InvalidArgument`。fork する前に呼び出しプロセスで拒否する）。PATH 探索はしない。
    pub fn new<P, A>(path: P, args: A) -> Result<Self, TraitError>
    where
        P: Into<std::path::PathBuf>,
        A: IntoIterator,
        A::Item: Into<String>,
    {
        let invalid = |message: &str| {
            TraitError::new(
                ErrorCode::InvalidArgument,
                format!("exec stage Validate: {message}"),
            )
        };
        // 件数・1 要素・合計の上限は、集めながら確かめる（上限を超えた時点で打ち切り、無制限のイテレータからも
        // 確保し続けない）。上限は core の `Entrypoint` と同じ値で、環境を含めた合計は worker が改めて検証する。
        let mut collected: Vec<String> = Vec::new();
        let mut total = 0usize;
        for arg in args {
            if collected.len() >= ENTRYPOINT_MAX_ARGS {
                return Err(invalid("argv has too many elements"));
            }
            let arg: String = arg.into();
            let size = arg.len().saturating_add(1);
            total = total.saturating_add(size);
            if size > ENTRYPOINT_MAX_STRING_BYTES || total > ENTRYPOINT_MAX_TOTAL_BYTES {
                return Err(invalid("argv exceeds the size limit"));
            }
            collected.push(arg);
        }
        let request = Self {
            path: path.into(),
            args: collected,
            env: Vec::new(),
            env_bytes: 0,
        };
        // パス・argv の書式は、環境を足す前の時点で確かめられる。
        request.command(&ContainerEnv::empty())?;
        Ok(request)
    }

    /// 利用者がこの exec に対して明示した環境変数を足す（コンテナ定義の同じ KEY を上書きする。指定順で後勝ち）。
    ///
    /// 件数（`ENTRYPOINT_MAX_ENV`）・合計のバイト数の上限を、複製する前に確かめる（超える場合は `InvalidArgument` で、
    /// 何も足さない）。コンテナ定義の環境・argv を含めた合計は worker が改めて検証する。
    pub fn with_env(mut self, vars: &[EnvVar]) -> Result<Self, TraitError> {
        let invalid = |message: &str| {
            TraitError::new(
                ErrorCode::InvalidArgument,
                format!("exec stage Validate: {message}"),
            )
        };
        if self.env.len().saturating_add(vars.len()) > ENTRYPOINT_MAX_ENV {
            return Err(invalid("too many env elements"));
        }
        let added = vars.iter().fold(0usize, |acc, var| {
            acc.saturating_add(var.key().len())
                .saturating_add(var.value().len())
                .saturating_add(2)
        });
        let total = self.env_bytes.saturating_add(added);
        if total > ENTRYPOINT_MAX_TOTAL_BYTES {
            return Err(invalid("the env exceeds the total size limit"));
        }
        self.env.extend_from_slice(vars);
        self.env_bytes = total;
        Ok(self)
    }

    /// コンテナ内の絶対パス。
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    /// `base`（コンテナ定義の環境）へ明示の上書きを重ねて、core のコマンドを組み立てる。
    fn command(&self, base: &ContainerEnv) -> Result<ExecCommand, TraitError> {
        let env = self
            .env
            .iter()
            .try_fold(base.clone(), |env, var| {
                env.with_var(var.key(), var.value())
            })
            .map_err(from_exec_error)?;
        ExecCommand::new(&self.path, &self.args, &env).map_err(from_exec_error)
    }
}

/// rlimit → capability 削減 → `NO_NEW_PRIVS` → Landlock → seccomp を自プロセスへ不可逆に適用する。
/// [`enter_namespaces`] と [`join_cgroup`] の **後**、準備したプロセス自身から単一スレッドで呼ぶ（SUP-6・#502・#503）。
/// 適用の前に、参加後の mount namespace が準備時の対象のものであること・参加後の `/` が記録したコンテナの
/// rootfs であることを照合し、不一致なら何も適用せず拒否する。失敗時は制限が部分的に載った不定状態のため、
/// 続行せず終了すること。
///
/// `execve` へ進んでよいことの証跡は [`require_exec_ready`] が返す `ExecReady` だけで、戻り値そのものは
/// exec の許可に使えない（SEC-1）。
pub fn reapply_restrictions(
    restrictions: ExecRestrictions,
) -> Result<ExecRestrictionReport, TraitError> {
    core_reapply_restrictions(restrictions).map_err(from_exec_error)
}

/// 再適用の結果を、exec へ進んでよいことの証跡 `ExecReady` に変える（SUP-6・SEC-1・#502）。
///
/// launch 経路と同じ制限のうち未適用のものが 1 つでも残っていれば `FailedPrecondition`。#503 で capability 削減と
/// rlimit 適用を実装したため、通常の再適用の結果は成功する。fork / execve の入口（[`run_command`] が呼ぶ
/// core の `spawn_exec_command`）は、この関数が返す `ExecReady` を値で受け取る（契約はモジュール doc）。
pub fn require_exec_ready(report: ExecRestrictionReport) -> Result<ExecReady, TraitError> {
    report.into_complete().map_err(from_exec_error)
}

/// [`run_command`] の結果（将来拡張できる構造。REPAIR-3）。
///
/// コマンドの終了状態と、exec プロセスへ載せた制限の件数（実行前に確認した証跡の要約）を持つ。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct ExecOutcome {
    /// コマンドの結果。`Command` はコマンドが起動して終了した状態、`SetupFailed` はコマンドが起動して
    /// いない（子が `execve` より前の手順か `execve` 自体で失敗した。終了コードは 125 / 126 / 127）ことを表す
    /// （TASK-163 追補・#1460）。終了コード 125〜127 はコマンド自身も返し得るため、終了コードではなくこの区別で
    /// 判定すること（healthcheck は `Command` の非 0 を不健全、`SetupFailed` を実行基盤側の失敗として扱える）。
    /// 分離違反による拒否（ランタイム自身のバイナリ・インタープリタ経由・`/dev/null` の差し替え）は理由を持つ。
    pub exit: ExecExit,
    /// 適用した rlimit の種別数（対象 pid1 の実効値。通常は 16）。
    pub rlimits_applied: usize,
    /// bounding set から落とした capability の数。
    pub capability_bounding_dropped: usize,
    /// 追加した Landlock ルール数。
    pub landlock_rules: usize,
    /// 適用した seccomp の BPF 命令数。
    pub seccomp_instructions: usize,
    /// 補助グループの扱いの結果（launch と同じく空にする。`setgroups` が `deny` の user namespace では残して
    /// 記録する。TASK-163 追補・#1457）。
    pub supplementary_groups: SupplementaryGroups,
}

/// 準備から fork までの全体の期限（REPAIR-5）。各段の間で残りを確かめ、超過したら次の段へ進まず `Timeout`。
#[derive(Debug, Clone, Copy)]
struct Deadline {
    at: Instant,
}

impl Deadline {
    /// `timeout` 後を期限にする（`Instant` の加算が溢れる極端に長い指定は、7 日に丸める）。
    fn after(timeout: Duration) -> Self {
        const MAX: Duration = Duration::from_secs(7 * 24 * 60 * 60);
        let now = Instant::now();
        let at = now
            .checked_add(timeout.min(MAX))
            .unwrap_or_else(|| now + MAX);
        Self { at }
    }

    /// 期限内なら残り時間、超過なら `Timeout`（`step` は失敗した段の名前。メッセージへ載せる）。
    fn remaining(&self, step: &'static str) -> Result<Duration, TraitError> {
        let remaining = self.at.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(TraitError::new(
                ErrorCode::Timeout,
                format!("exec timed out before {step}"),
            ));
        }
        Ok(remaining)
    }
}

/// 稼働中コンテナ `record` の中で `request` のコマンドを実行し、終了を待つ（SUP-6・TASK-163.4・#503）。
///
/// コマンドの環境は、記録の bundle の `config.json` の `process.env` へ `request` の明示の指定を重ねたもので、
/// 呼び出しプロセスの環境は使わない（TASK-163 追補・#1457。契約はモジュール doc）。
///
/// 順序は固定: [`identify_pid1`] → [`prepare_cgroup_join`] → [`prepare_restrictions`] → [`enter_namespaces`] →
/// [`join_cgroup`] → [`reapply_restrictions`] → [`require_exec_ready`] → core の `spawn_exec_command`
/// （cwd を照合済み root へ → fork → 子で `close_range` → `execveat`）→ `wait_timeout`。
/// 制限は fork / execve を越えて子へ継承される（「適用 → fork → execve」）。
///
/// `timeout` は準備から終了待ちまでの全体の上限（REPAIR-5）。段の間で期限を確かめ、fork 後は残り時間で
/// `wait_timeout` する（期限超過は子を `SIGKILL` して回収し `Timeout`）。**不可逆な `setns` を行うため、
/// 単一スレッドの exec 専用プロセスからのみ呼ぶこと**（logs 捕捉スレッドを持つ supervisor 本体からは呼ばない。
/// 呼べば `setns` が拒否される）。失敗時は状態を戻せないため、呼び出し側は続行せずプロセスを終了する。
/// エラーメッセージへホスト側パス・ルール内容・期待 cgroup パスを載せない。
///
/// `audit` は exec の対象の拒否の記録先（SEC-4・#1465。契約はモジュール doc「監査記録」）。拒否は `Err` の
/// [`AuditedRejection`] で返り、`error` は記録の成否に関わらず元の拒否、`delivery` が記録の結果。移行: 呼び出しへ
/// sink を渡し、`Err` は `.error` / `.delivery` を見る。`audit` の実装はブロックし得る I/O にタイムアウトを持つこと
/// （REPAIR-5。`AuditSink` の契約）。記録は worker を回収した後に行うため、sink が詰まっても worker・コマンドは残らない。
pub fn run_command(
    record: &StateRecord,
    request: &ExecRequest,
    timeout: Duration,
    audit: &dyn AuditSink,
) -> Result<ExecOutcome, AuditedRejection<TraitError>> {
    let deadline = Deadline::after(timeout);
    // 稼働中でない記録は、fork せず呼び出しプロセスで拒否する（副作用なし。記録の対象外）。
    running_pid(record).map_err(AuditedRejection::not_applicable)?;
    let name = ExecCgroupName::unique();
    let result = run_owning_child_cgroup(
        deadline,
        || create_child_cgroup(record, &name),
        || cleanup_child_cgroup(record, &name),
        |proof, child| {
            let target = identify_pid1(record)?;
            run_with_target(proof, &target, request, deadline, child)
        },
    );
    audit_worker_result(result, audit)
}

/// worker の結果を受け、exec の対象の拒否なら 1 件記録して返す（親プロセス側の記録点。SEC-4・#1465）。
///
/// 違反の理由を持たない失敗（タイムアウト・システムエラー・前提不成立）は記録せず `NotApplicable`。
fn audit_worker_result(
    result: Result<ExecOutcome, WorkerFailure>,
    audit: &dyn AuditSink,
) -> Result<ExecOutcome, AuditedRejection<TraitError>> {
    result.map_err(|failure| match failure.violation {
        Some(reason) => record_exec_target_rejection(failure.error, reason, audit),
        None => AuditedRejection::not_applicable(failure.error),
    })
}

/// [`run_command`] の対象特定だけを [`identify_pid1_with_pidfd`]（起動時から保持する pidfd で対象を固定）に
/// 替えたもの（SUP-6・SEC-1・CORE-1・TASK-163 追補・#1461）。契約（`audit` の扱いと `Err` の
/// [`AuditedRejection`] を含む）は [`run_command`] と同じ。exec の対象の拒否は必ず `audit` へ記録する（SEC-4・#1465）。
///
/// worker は fork で親の fd を継承するため、pidfd は呼び出しプロセスが保持するものをそのまま worker が使う
/// （追加の syscall なし。呼び出しプロセスは単一スレッドであること）。pidfd はコンテナ内コマンドへ渡らない
/// （core が `execveat` の前に `close_range` で閉じ、複製は close-on-exec）。別プロセスの exec 専用プロセスへ
/// 渡す 1 段目（execve 越しの継承・`SCM_RIGHTS`）は未実装（モジュール doc）。
pub fn run_command_with_pidfd(
    record: &StateRecord,
    pidfd: BorrowedFd<'_>,
    request: &ExecRequest,
    timeout: Duration,
    audit: &dyn AuditSink,
) -> Result<ExecOutcome, AuditedRejection<TraitError>> {
    let deadline = Deadline::after(timeout);
    running_pid(record).map_err(AuditedRejection::not_applicable)?;
    let name = ExecCgroupName::unique();
    let result = run_owning_child_cgroup(
        deadline,
        || create_child_cgroup(record, &name),
        || cleanup_child_cgroup(record, &name),
        |proof, child| {
            let target = identify_pid1_with_pidfd(record, pidfd)?;
            run_with_target(proof, &target, request, deadline, child)
        },
    );
    audit_worker_result(result, audit)
}

/// 実機結合試験専用の入口: [`run_command`] の対象特定だけを [`identify_pid1_in`]（期待 cgroup パスを呼び出し側
/// から受け取る）に替えたもの。`exec-test-support` feature を付けたビルドにだけ存在し、既定のビルドの公開
/// API には含まれない。本番経路は必ず [`run_command`] を使う（SEC-1）。
#[cfg(feature = "exec-test-support")]
pub fn run_command_in(
    record: &StateRecord,
    expected_cgroup_path: &str,
    request: &ExecRequest,
    timeout: Duration,
    audit: &dyn AuditSink,
) -> Result<ExecOutcome, AuditedRejection<TraitError>> {
    let deadline = Deadline::after(timeout);
    running_pid(record).map_err(AuditedRejection::not_applicable)?;
    let name = ExecCgroupName::unique();
    let result = run_owning_child_cgroup(
        deadline,
        || {
            ExecChildCgroup::create_in_path_for_test(expected_cgroup_path, &name)
                .map(Some)
                .map_err(from_exec_error)
        },
        || {
            fandhe_container_core::exec::remove_exec_child_cgroup_in(
                expected_cgroup_path,
                &name,
                CHILD_CGROUP_CLEANUP_TIMEOUT,
            )
            .map(|_| ())
            .map_err(from_exec_error)
        },
        |proof, child| {
            let target = identify_pid1_in(record, expected_cgroup_path)?;
            run_with_target(proof, &target, request, deadline, child)
        },
    );
    audit_worker_result(result, audit)
}

/// worker の失敗。拒否のエラーと、exec の対象の違反だった場合のその理由（監査記録の入力。#1465）。
///
/// `violation` は worker の結果行の理由コードを core の許可リスト（`ViolationReason::EXEC_TARGET_REASONS`）で
/// 引き直した値だけを持つ。未知の文字列は結果行の不正として `Internal`（fail-closed）になりここへ来ない。
#[derive(Debug)]
struct WorkerFailure {
    error: TraitError,
    violation: Option<ViolationReason>,
}

impl From<TraitError> for WorkerFailure {
    fn from(error: TraitError) -> Self {
        Self {
            error,
            violation: None,
        }
    }
}

/// worker の終了待ちに足す猶予。worker 自身が期限超過後に子を `SIGKILL` して回収する時間（`wait_or_stop` の
/// 回収待ち上限 5 秒）より長くし、通常は worker 自身の `Timeout` が先に返るようにする（REPAIR-5）。
const WORKER_GRACE: Duration = Duration::from_secs(7);

/// worker の結果 1 行の上限バイト数（pipe から読む量の上限。無制限確保の防止）。
const WORKER_RESULT_MAX: u64 = 4096;

/// worker が書く 1 行の上限バイト数（改行込み）。pipe の最小容量（1 ページ = 4096）未満に収め、親が終了待ちの間は
/// 読まなくても worker の `write_all` が詰まらないようにする。`WORKER_RESULT_MAX` 以下であること。
const WORKER_LINE_MAX: usize = 2048;

/// `work` を worker プロセスで実行し、`deadline + grace` までに終わらなければ worker を `SIGKILL` して回収し
/// `Timeout` を返す（REPAIR-5・SUP-6・TASK-163.4）。契約はモジュール doc「全体の上限時間」。
///
/// 呼び出しプロセスは単一スレッドであること（満たさなければ core が fork せず拒否する）。`work` は fork した
/// 子で実行され、結果は pipe の 1 行（[`encode_worker_result`]）で返る。
fn run_in_worker_with(
    deadline: Deadline,
    grace: Duration,
    cleanup: impl FnOnce() -> Result<(), TraitError>,
    work: impl FnOnce(&ExecWorkerProof) -> Result<ExecOutcome, TraitError>,
) -> Result<ExecOutcome, WorkerFailure> {
    // fork 前に期限を確かめる（切れていれば worker を作らない。fork 後の早期 return で worker を残さないため）。
    deadline.remaining("starting the exec worker")?;
    let (mut reader, writer) = std::io::pipe().map_err(|e| {
        TraitError::new(
            ErrorCode::Internal,
            format!("exec stage Spawn: pipe failed: {}", e.kind()),
        )
    })?;
    let child = spawn_exec_worker(|proof| {
        let line = encode_worker_result(&work(&proof));
        // 書けなければ親は「結果なし」として失敗扱いにする（fail-closed）。
        let _ = (&writer).write_all(&line);
        0
    })
    .map_err(from_exec_error)?;
    // 親は書き込み側を閉じる（worker の終了後に読み取りが EOF で終わるようにする）。
    drop(writer);
    // worker を fork した後は、結果の取得がどう終わっても（正常・期限切れ・異常終了・結果行の不正）worker の
    // 停止・回収の後に exec 用の子 cgroup の後始末を必ず行う（cgroup は呼び出しプロセスが fork 前に作って
    // 所有しており、削除は制限の掛かっていないここでしかできない。作成できなかった場合は呼ばれない。#1466）。
    let result = collect_worker_result(&child, &mut reader, deadline, grace);
    let cleaned = cleanup();
    match (result, cleaned) {
        (Ok(outcome), Ok(())) => Ok(outcome),
        (Ok(_), Err(cleanup_err)) => Err(cleanup_err.into()),
        (Err(err), Ok(())) => Err(err),
        (Err(err), Err(cleanup_err)) => Err(WorkerFailure {
            error: TraitError::new(
                err.error.code(),
                format!(
                    "{}; cleanup also failed: {}",
                    err.error.message(),
                    cleanup_err.message()
                ),
            ),
            violation: err.violation,
        }),
    }
}

/// worker の終了を待って（期限切れなら `SIGKILL` して回収し）、worker が pipe へ書いた結果 1 行を復号する。
fn collect_worker_result(
    child: &fandhe_container_core::exec::ContainerChild,
    reader: &mut std::io::PipeReader,
    deadline: Deadline,
    grace: Duration,
) -> Result<ExecOutcome, WorkerFailure> {
    // fork 後はどの経路でも worker を停止・回収してから返す（`wait_or_stop`。期限切れなら待たずに SIGKILL）。
    let wait_deadline = Deadline {
        at: deadline.at.checked_add(grace).unwrap_or(deadline.at),
    };
    let exit = wait_or_stop(
        &wait_deadline,
        |left| child.wait_timeout(left).map_err(from_exec_error),
        |reap| child.kill_and_reap(reap).map_err(from_exec_error),
    )
    .map_err(|e| {
        if e.code() == ErrorCode::Timeout {
            TraitError::new(
                ErrorCode::Timeout,
                "exec timed out; the exec worker was killed",
            )
        } else {
            e
        }
    })?;
    if exit != ChildExit::Exited(0) {
        return Err(TraitError::new(
            ErrorCode::Internal,
            format!("exec stage Spawn: the exec worker ended abnormally ({exit:?})"),
        )
        .into());
    }
    let mut line = Vec::new();
    std::io::BufReader::new(reader.take(WORKER_RESULT_MAX))
        .read_until(b'\n', &mut line)
        .map_err(|e| {
            TraitError::new(
                ErrorCode::Internal,
                format!(
                    "exec stage Spawn: reading the worker result failed: {}",
                    e.kind()
                ),
            )
        })?;
    decode_worker_result(&line)
}

/// exec 用の子 cgroup を呼び出しプロセスで作り、作成できた場合だけ所有者として後始末する（#1466）。
///
/// `create` は worker の fork 前に呼ぶ。失敗（同名の既存・残骸との衝突を含む）なら何も所有していないため
/// 後始末は呼ばない（他者・残骸の同名 cgroup を止めない）。作成後は、worker を fork できた場合は
/// [`run_in_worker_with`] が worker 回収後に、fork 前に失敗した場合はここで `remove` を呼ぶ。`create` が
/// `Ok(None)` を返すのは cgroup 配置の記録が無い場合で、`work` が対象特定で拒否する（作成物なし）。
fn run_owning_child_cgroup(
    deadline: Deadline,
    create: impl FnOnce() -> Result<Option<ExecChildCgroup>, TraitError>,
    remove: impl Fn() -> Result<(), TraitError>,
    work: impl FnOnce(&ExecWorkerProof, Option<&ExecChildCgroup>) -> Result<ExecOutcome, TraitError>,
) -> Result<ExecOutcome, WorkerFailure> {
    let child = create()?;
    let owned = child.is_some();
    let cleanup_ran = std::cell::Cell::new(false);
    let result = run_in_worker_with(
        deadline,
        WORKER_GRACE,
        || {
            cleanup_ran.set(true);
            if owned { remove() } else { Ok(()) }
        },
        |proof| work(proof, child.as_ref()),
    );
    let mut result = result;
    if owned && !cleanup_ran.get() {
        // worker を fork できなかった（期限切れ・pipe 失敗等）。作成した cgroup は空だが残さない。
        if let Err(cleanup_err) = remove() {
            result = match result {
                Ok(_) => Err(cleanup_err.into()),
                Err(f) => Err(WorkerFailure {
                    error: TraitError::new(
                        f.error.code(),
                        format!(
                            "{}; cleanup also failed: {}",
                            f.error.message(),
                            cleanup_err.message()
                        ),
                    ),
                    violation: f.violation,
                }),
            };
        }
    }
    drop(child);
    result
}

/// 記録から導いたコンテナ cgroup の直下に exec 用の子 cgroup を作る。cgroup 配置の記録が無ければ `None`
/// （worker の `identify_pid1` が拒否する）。
fn create_child_cgroup(
    record: &StateRecord,
    name: &ExecCgroupName,
) -> Result<Option<ExecChildCgroup>, TraitError> {
    let Some(placement) = record.cgroup() else {
        return Ok(None);
    };
    match ExecChildCgroup::create(record.status().id(), placement, name) {
        Ok(child) => Ok(Some(child)),
        // コンテナ cgroup が存在しない記録は、worker の `identify_pid1` が対象の拒否（監査記録の対象）として
        // 返す。ここでは何も作っていない（所有なし）ため `None` にして拒否の経路を保つ。
        Err(e) if e.code == ErrorCode::NotFound => Ok(None),
        Err(e) => Err(from_exec_error(e)),
    }
}

/// 呼び出しプロセスでの exec 用の子 cgroup の後始末（記録から導いたコンテナ cgroup 直下の `name` を
/// `cgroup.kill` で停止して削除する。冪等。#1466）。cgroup 配置の記録が無ければ worker が cgroup を作れない
/// （`identify_pid1` が拒否する）ため何もしない。
fn cleanup_child_cgroup(record: &StateRecord, name: &ExecCgroupName) -> Result<(), TraitError> {
    let Some(placement) = record.cgroup() else {
        return Ok(());
    };
    remove_child_cgroup(record.status().id(), placement, name)
}

fn remove_child_cgroup(
    id: &ContainerId,
    placement: &CgroupPlacement,
    name: &ExecCgroupName,
) -> Result<(), TraitError> {
    remove_exec_child_cgroup(id, placement, name, CHILD_CGROUP_CLEANUP_TIMEOUT)
        .map(|_| ())
        .map_err(from_exec_error)
}

/// 子 cgroup の後始末で、`cgroup.kill` の後に空になるまで待つ上限（REPAIR-5）。
const CHILD_CGROUP_CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);

#[cfg(feature = "exec-test-support")]
#[doc(hidden)]
pub fn run_in_worker_for_test(
    timeout: Duration,
    grace: Duration,
    cleanup: impl FnOnce() -> Result<(), TraitError>,
    work: impl FnOnce() -> Result<ExecOutcome, TraitError>,
) -> Result<ExecOutcome, TraitError> {
    run_in_worker_with(Deadline::after(timeout), grace, cleanup, |_| work()).map_err(|f| f.error)
}

/// worker の結果を pipe 用の 1 行へ符号化する。成功は `ok <command|setup> <違反の理由コードまたは -> <exited|signaled>
/// <値> <rlimit 数> <capability 数> <Landlock 数> <seccomp 命令数> <補助グループの扱い> <その件数>`、失敗は
/// `err <ERR-1 コード> <exec 対象の違反の理由コードまたは -> <メッセージ>`（改行は空白へ置換）。
fn encode_worker_result(result: &Result<ExecOutcome, TraitError>) -> Vec<u8> {
    let line = match result {
        Ok(o) => {
            let (started, violation) = match o.exit {
                ExecExit::Command(_) => ("command", "-"),
                ExecExit::SetupFailed { violation, .. } => {
                    ("setup", violation.map_or("-", ViolationReason::as_str))
                }
                _ => ("unknown", "-"),
            };
            let (kind, value) = match o.exit.child_exit() {
                ChildExit::Exited(n) => ("exited", n),
                ChildExit::Signaled(n) => ("signaled", n),
                _ => ("unknown", 0),
            };
            let groups = match o.supplementary_groups {
                SupplementaryGroups::Cleared { cleared } => cleared,
                other => other.remaining(),
            };
            format!(
                "ok {started} {violation} {kind} {value} {} {} {} {} {} {groups}\n",
                o.rlimits_applied,
                o.capability_bounding_dropped,
                o.landlock_rules,
                o.seccomp_instructions,
                o.supplementary_groups.as_str(),
            )
        }
        Err(e) => format!(
            "err {} {} {}\n",
            e.code().as_str(),
            exec_target_reason_of(e).map_or("-", ViolationReason::as_str),
            e.message().replace(['\n', '\r'], " ")
        ),
    };
    let mut line = line;
    if line.len() > WORKER_LINE_MAX {
        // 長すぎるメッセージは UTF-8 の文字境界で切り詰め、改行で終える（切れた行は親が拒否するため）。
        let mut cut = WORKER_LINE_MAX - 1;
        while cut > 0 && !line.is_char_boundary(cut) {
            cut -= 1;
        }
        line.truncate(cut);
        line.push('\n');
    }
    line.into_bytes()
}

/// [`from_exec_error`] が exec の対象の違反の末尾へ付ける目印（種別と理由コードの前まで）。
const EXEC_TARGET_VIOLATION_MARKER: &str = " (violation: exec_target/";

/// `err` が exec の対象の違反による拒否なら、その理由を返す（[`from_exec_error`] の末尾の目印を許可リストで
/// 引き直す。メッセージは core の静的トークンだけから組み立てられ、外部入力は載らない。#1465）。
fn exec_target_reason_of(err: &TraitError) -> Option<ViolationReason> {
    let tail = err.message().rsplit_once(EXEC_TARGET_VIOLATION_MARKER)?.1;
    let (token, _) = tail.split_once(", ")?;
    ViolationReason::from_exec_target_token(token)
}

/// worker が返し得る違反の理由（`execve` 前の手順が返すもの。[`decode_worker_result`] が名前から引き直す）。
const SETUP_VIOLATIONS: [ViolationReason; 7] = [
    ViolationReason::EntrypointIsRuntimeBinary,
    ViolationReason::EntrypointInterpreterIsRuntimeBinary,
    ViolationReason::StdioNullNotNullDevice,
    ViolationReason::ExecDevNotDirectory,
    ViolationReason::ExecProcNotProcfs,
    ViolationReason::EntrypointCopyTooLarge,
    ViolationReason::EntrypointCopySealUnverified,
];

/// [`encode_worker_result`] の逆変換。形式に合わない入力（空・切れた行・未知の種別）は `Internal`（fail-closed）。
fn decode_worker_result(line: &[u8]) -> Result<ExecOutcome, WorkerFailure> {
    let malformed = || {
        WorkerFailure::from(TraitError::new(
            ErrorCode::Internal,
            "exec stage Spawn: the exec worker returned a malformed result",
        ))
    };
    let text = String::from_utf8_lossy(line);
    let text = text.strip_suffix('\n').ok_or_else(malformed)?;
    if let Some(rest) = text.strip_prefix("err ") {
        let (code, rest) = rest.split_once(' ').ok_or_else(malformed)?;
        let (violation, message) = rest.split_once(' ').unwrap_or((rest, ""));
        let violation = match violation {
            "-" => None,
            token => Some(ViolationReason::from_exec_target_token(token).ok_or_else(malformed)?),
        };
        let code = [
            ErrorCode::InvalidArgument,
            ErrorCode::NotFound,
            ErrorCode::AlreadyExists,
            ErrorCode::FailedPrecondition,
            ErrorCode::Unimplemented,
            ErrorCode::Internal,
            ErrorCode::PermissionDenied,
            ErrorCode::Timeout,
            ErrorCode::Unavailable,
        ]
        .into_iter()
        .find(|c| c.as_str() == code)
        .unwrap_or(ErrorCode::Internal);
        return Err(WorkerFailure {
            error: TraitError::new(code, message),
            violation,
        });
    }
    let rest = text.strip_prefix("ok ").ok_or_else(malformed)?;
    let mut it = rest.split(' ');
    let started = it.next().ok_or_else(malformed)?;
    let violation = match it.next().ok_or_else(malformed)? {
        "-" => None,
        name => Some(
            SETUP_VIOLATIONS
                .into_iter()
                .find(|reason| reason.as_str() == name)
                .ok_or_else(malformed)?,
        ),
    };
    let kind = it.next().ok_or_else(malformed)?;
    let value: i32 = it
        .next()
        .and_then(|v| v.parse().ok())
        .ok_or_else(malformed)?;
    let child = match kind {
        "exited" => ChildExit::Exited(value),
        "signaled" => ChildExit::Signaled(value),
        _ => return Err(malformed()),
    };
    let exit = match (started, violation) {
        ("command", None) => ExecExit::Command(child),
        ("setup", violation) => ExecExit::SetupFailed {
            exit: child,
            violation,
        },
        _ => return Err(malformed()),
    };
    let mut count = || -> Result<usize, WorkerFailure> {
        it.next().and_then(|v| v.parse().ok()).ok_or_else(malformed)
    };
    let (rlimits_applied, capability_bounding_dropped) = (count()?, count()?);
    let (landlock_rules, seccomp_instructions) = (count()?, count()?);
    let groups_kind = it.next().ok_or_else(malformed)?;
    let groups: usize = it
        .next()
        .and_then(|v| v.parse().ok())
        .ok_or_else(malformed)?;
    let supplementary_groups = match groups_kind {
        "already_empty" if groups == 0 => SupplementaryGroups::AlreadyEmpty,
        "cleared" => SupplementaryGroups::Cleared { cleared: groups },
        "kept_setgroups_denied" => SupplementaryGroups::KeptSetgroupsDenied { kept: groups },
        _ => return Err(malformed()),
    };
    if it.next().is_some() {
        return Err(malformed());
    }
    Ok(ExecOutcome {
        exit,
        rlimits_applied,
        capability_bounding_dropped,
        landlock_rules,
        seccomp_instructions,
        supplementary_groups,
    })
}

/// 特定済みの対象に対して、参加 → 制限の再適用 → 実行 → 待機を順に行う（[`run_command`] の本体）。
fn run_with_target(
    proof: &ExecWorkerProof,
    target: &ExecTarget,
    request: &ExecRequest,
    deadline: Deadline,
    child_cgroup: Option<&ExecChildCgroup>,
) -> Result<ExecOutcome, TraitError> {
    // コマンドだけを入れる子 cgroup は、呼び出しプロセスが fork 前に作って所有する（worker は fd を継承して使う。
    // 同名の既存を後始末で止めないため。#1466）。配置の記録が無ければ `identify_pid1` が先に拒否しここへ来ない。
    let child_cgroup = child_cgroup.ok_or_else(|| {
        TraitError::new(
            ErrorCode::Internal,
            "exec stage CgroupJoin: the exec child cgroup was not created",
        )
    })?;
    let cgroup = prepare_cgroup_join(target)?;
    let result = run_in_child_cgroup(proof, target, request, deadline, cgroup, child_cgroup);
    // 成否によらず、コマンドの子孫を子 cgroup ごと止める（exec の終了後に子孫を残さない。削除は呼び出しプロセスが行う）。
    // 失敗しても呼び出しプロセスの後始末が改めて `cgroup.kill` する。
    let _ = child_cgroup.kill_all();
    result
}

/// [`run_with_target`] の本体: 準備 → 参加 → 再適用 → コマンドの起動と待機。
fn run_in_child_cgroup(
    proof: &ExecWorkerProof,
    target: &ExecTarget,
    request: &ExecRequest,
    deadline: Deadline,
    cgroup: ExecCgroupJoin,
    child_cgroup: &ExecChildCgroup,
) -> Result<ExecOutcome, TraitError> {
    // `config.json` は 1 回だけ読み、制限の準備とコマンドの環境の両方に使う（同じ定義から導く）。
    let (config, rootfs) = load_exec_bundle(&target.bundle)?;
    // コマンドの環境はコンテナ定義（`process.env`）が基底で、呼び出しプロセスの環境は使わない（#1457）。
    let command = request.command(&ContainerEnv::from_config(&config).map_err(from_exec_error)?)?;
    let restrictions = core_prepare_exec_restrictions(proof, &target.pid1, &config, &rootfs)
        .map_err(from_exec_error)?;
    deadline.remaining("joining namespaces")?;
    enter_namespaces(target)?;
    deadline.remaining("joining the cgroup")?;
    join_cgroup(cgroup)?;
    deadline.remaining("reapplying restrictions")?;
    let report = reapply_restrictions(restrictions)?;
    let (rlimits_applied, capability_bounding_dropped) = (
        report.rlimits_applied(),
        report.capability_bounding_dropped(),
    );
    let (landlock_rules, seccomp_instructions) =
        (report.landlock_rules(), report.seccomp_instructions());
    // capability 削減を通った結果には必ず載る。無ければ未適用で、下の `require_exec_ready` も拒否する。
    let supplementary_groups = report.supplementary_groups().ok_or_else(|| {
        TraitError::new(
            ErrorCode::FailedPrecondition,
            "exec stage CapabilityDrop: the supplementary groups were not handled",
        )
    })?;
    let ready = require_exec_ready(report)?;
    deadline.remaining("starting the command")?;
    let child = spawn_exec_command(ready, &command, child_cgroup).map_err(from_exec_error)?;
    let exit = wait_or_stop(
        &deadline,
        |left| child.wait_timeout(left).map_err(from_exec_error),
        |reap| {
            // 子孫ごと止める（親死亡シグナルを解除したコマンド・二重 fork した子孫も対象。#1466）。
            let _ = child_cgroup.kill_all();
            child.kill_and_reap(reap).map_err(from_exec_error)
        },
    )?;
    Ok(ExecOutcome {
        exit,
        rlimits_applied,
        capability_bounding_dropped,
        landlock_rules,
        seccomp_instructions,
        supplementary_groups,
    })
}

/// 起動後の子に対する期限内の待機。期限が既に切れていれば待たずに直ちに `kill` で停止・回収してから `Timeout`
/// を返す（`?` で早期 return して子を残さない。REPAIR-5・SUP-6・TASK-163.4）。`wait` は残り時間で待ち、
/// `kill` は回収待ちの上限を受けて SIGKILL と回収を行う。
fn wait_or_stop<T>(
    deadline: &Deadline,
    wait: impl FnOnce(Duration) -> Result<T, TraitError>,
    stop: impl FnOnce(Duration) -> Result<ChildExit, TraitError>,
) -> Result<T, TraitError> {
    /// 期限切れ後の SIGKILL 回収待ちの上限。
    const REAP_TIMEOUT: Duration = Duration::from_secs(5);
    match deadline.remaining("waiting for the command") {
        Ok(left) => match wait(left) {
            Ok(exit) => Ok(exit),
            // 待機エラー後も子が未回収の可能性がある（`ContainerChild::wait_timeout` の契約）。ハンドルを
            // 失って worker・コンテナ内コマンドを残さないよう、回収を試みてから元のエラーを返す。
            // `stop` は回収済みなら kill せず Ok を返すため、`Timeout`（既に kill・回収済み）でも安全。
            Err(wait_err) => match stop(REAP_TIMEOUT) {
                Ok(_) => Err(wait_err),
                Err(stop_err) => Err(TraitError::new(
                    wait_err.code(),
                    format!(
                        "{}; cleanup also failed: {}",
                        wait_err.message(),
                        stop_err.message()
                    ),
                )),
            },
        },
        Err(expired) => {
            stop(REAP_TIMEOUT)?;
            Err(expired)
        }
    }
}

/// `bundle` の `config.json` を読み、その `root.path` が指す rootfs を固定する。
///
/// エラーメッセージに bundle のパスを含めない（core の `OciConfigError`・rootfs の検査は固定文言）。
fn load_exec_bundle(bundle: &std::path::Path) -> Result<(OciConfig, RootfsDir), TraitError> {
    let config = load_config(&bundle.join("config.json"))
        .map_err(|e| TraitError::new(e.code(), format!("exec stage Landlock: {e}")))?;
    let rootfs = pin_bundle_rootfs(bundle, &config)
        .map_err(|e| TraitError::new(e.code(), format!("exec stage Validate: {}", e.message())))?;
    Ok((config, rootfs))
}

/// `ExecError` を `code` を保ったまま `TraitError` へ写す（段名はメッセージへ含める）。
///
/// 分離違反による拒否（`ExecError::violation`。SEC-4）は、種別・理由コード・ビヘイビア ID をメッセージの
/// 末尾に機械可読な形で残す（`TraitError` は違反記録を運べないため）。違反の対象（期待 cgroup パス）は
/// メッセージへ含めない。exec の対象の違反の監査記録は通しの入口 [`run_command`] が親プロセスで行い、worker は
/// 末尾の目印から理由を結果行へ載せる（[`exec_target_reason_of`]。#1465）。
fn from_exec_error(err: ExecError) -> TraitError {
    let violation = err.violation.as_ref().map_or_else(String::new, |v| {
        format!(
            " (violation: {}/{}, {})",
            v.kind.as_str(),
            v.reason.as_str(),
            v.behavior_id
        )
    });
    TraitError::new(
        err.code,
        format!("exec stage {:?}: {}{violation}", err.stage, err.message),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use fandhe_container_core::audit_log::{AuditDelivery, AuditLayer, AuditRecord};
    use fandhe_container_core::traits::{
        CgroupPlacement, CgroupScope, ContainerStatus, StateRevision,
    };
    use std::num::NonZeroU32;

    fn record(status: ContainerStatus) -> StateRecord {
        StateRecord::new(
            status,
            std::env::temp_dir().join("b"),
            StateRevision::from_raw(1),
        )
        .unwrap()
    }

    fn cid() -> ContainerId {
        ContainerId::new("c1").unwrap()
    }

    /// SUP-6: Running 以外・pid なしは FailedPrecondition。
    #[test]
    fn sup6_identify_rejects_non_running_or_pidless() {
        let pid = NonZeroU32::new(std::process::id());
        for st in [
            ContainerStatus::created(cid(), pid),
            ContainerStatus::stopped(cid(), Some(0)),
            ContainerStatus::running(cid(), None),
        ] {
            let err = identify_pid1(&record(st)).unwrap_err();
            assert_eq!(err.code(), ErrorCode::FailedPrecondition);
            assert_eq!(
                err.message(),
                "container is not running or has no recorded pid; cannot identify pid1"
            );
        }
    }

    /// SUP-6・SEC-1: cgroup 配置の記録がなければ pid の同一性を確認できないため拒否する。
    #[test]
    fn sup6_identify_rejects_missing_cgroup_placement() {
        let pid = NonZeroU32::new(std::process::id());
        let err = identify_pid1(&record(ContainerStatus::running(cid(), pid))).unwrap_err();
        assert_eq!(err.code(), ErrorCode::FailedPrecondition);
        assert_eq!(
            err.message(),
            "container has no recorded cgroup placement; cannot verify pid1 identity"
        );
    }

    /// SUP-6・SEC-1・SEC-4: cgroup 配置の記録があれば、記録の型のまま core の検証まで進む。自プロセスは
    /// 入れ子の PID 1 でないため SetNs 段で拒否され、違反の種別・理由コード・ビヘイビア ID がメッセージに残る。
    #[test]
    fn sup6_identify_with_placement_reaches_core_verification() {
        let pid = NonZeroU32::new(std::process::id());
        let rec = record(ContainerStatus::running(cid(), pid)).with_cgroup(CgroupPlacement::new(
            CgroupScope::new("/user.slice/x.scope").unwrap(),
            StateRevision::from_raw(7),
        ));
        let err = identify_pid1(&rec).unwrap_err();
        assert_eq!(err.code(), ErrorCode::FailedPrecondition);
        assert_eq!(
            err.message(),
            "exec stage SetNs: the exec target is not PID 1 of a directly nested PID namespace \
             (violation: exec_target/exec_target_not_nested_pid1, SUP-6)"
        );
    }

    /// SUP-6: 違反記録のないエラー（システムエラー）は、段とメッセージだけを写す。
    #[test]
    fn sup6_identify_missing_pid_has_no_violation_suffix() {
        let rec = record(ContainerStatus::running(cid(), NonZeroU32::new(4_194_305))).with_cgroup(
            CgroupPlacement::new(CgroupScope::new("/").unwrap(), StateRevision::from_raw(7)),
        );
        let err = identify_pid1(&rec).unwrap_err();
        assert_eq!(err.code(), ErrorCode::NotFound);
        assert!(
            err.message().starts_with("exec stage SetNs: pidfd_open"),
            "{}",
            err.message()
        );
        assert!(!err.message().contains("violation"), "{}", err.message());
    }

    /// SUP-6・TASK-163.2: cgroup join の公開入口の型（検証済みの `ExecTarget` だけから準備でき、参加は準備の結果を
    /// 消費する）。実 pid1 を要する成功経路は core のユニットテスト（`sup6_task163_2_*`）と結合試験
    /// `tests/exec.rs` が担い、ここでは配線の型が保たれていることだけを機械照合する。
    #[test]
    fn sup6_task163_2_cgroup_join_entry_points_have_expected_shape() {
        let _prepare: fn(&ExecTarget) -> Result<ExecCgroupJoin, TraitError> = prepare_cgroup_join;
        let _join: fn(ExecCgroupJoin) -> Result<ExecCgroupJoinReport, TraitError> = join_cgroup;
    }

    /// SUP-6・TASK-163.3: seccomp / Landlock 再適用の公開入口の型（検証済みの `ExecTarget` と記録から準備でき、
    /// 適用は準備の結果を消費する）。実 pid1 を要する成功経路は core のユニットテスト・結合試験
    /// （`exec_restrictions_reapply`）と `tests/exec.rs` が担い、ここでは配線の型だけを機械照合する。
    #[test]
    fn sup6_task163_3_restrictions_entry_points_have_expected_shape() {
        let _prepare: fn(&ExecWorkerProof, &ExecTarget) -> Result<ExecRestrictions, TraitError> =
            prepare_restrictions;
        let _reapply: fn(ExecRestrictions) -> Result<ExecRestrictionReport, TraitError> =
            reapply_restrictions;
        // exec の許可は証跡 `ExecReady` だけ（結果そのもの・真偽値では表さない。SEC-1）。
        let _ready: fn(ExecRestrictionReport) -> Result<ExecReady, TraitError> = require_exec_ready;
    }

    /// SUP-6・TASK-163.4: 通しの入口の型（記録・エントリポイント・全体の上限時間を受け、終了状態を含む構造を返す）。
    /// 実 pid1 を要する成功経路は結合試験 `tests/exec.rs`（`-- --ignored`）が担う。
    #[test]
    fn sup6_task163_4_run_command_entry_point_has_expected_shape() {
        type Run = fn(
            &StateRecord,
            &ExecRequest,
            Duration,
            &dyn AuditSink,
        ) -> Result<ExecOutcome, AuditedRejection<TraitError>>;
        let _run: Run = run_command;
    }

    /// SUP-6・SEC-1・TASK-163 追補（#1457）: 要求はパス・argv を fork の前に検証し、コマンドの環境は
    /// 「コンテナ定義の環境 + 明示の上書き」だけから組み立てる（テストプロセスの環境は入らない）。
    #[test]
    fn sup6_sec1_task163_exec_request_builds_env_from_definition_and_explicit_vars() {
        use crate::container_options::env::EnvVar;
        for bad in [
            ExecRequest::new("relative", ["x"]).unwrap_err(),
            ExecRequest::new("/bin/true", [] as [&str; 0]).unwrap_err(),
            ExecRequest::new("/bin/true", ["a\0b"]).unwrap_err(),
        ] {
            assert_eq!(bad.code(), ErrorCode::InvalidArgument);
            assert!(bad.message().starts_with("exec stage Validate: "));
        }
        // 上限は集めながら確かめ、超えた時点で打ち切る（無限のイテレータでも確保し続けず拒否する）。
        let endless = ExecRequest::new("/bin/true", std::iter::repeat("x")).unwrap_err();
        assert_eq!(endless.code(), ErrorCode::InvalidArgument);
        assert_eq!(
            endless.message(),
            "exec stage Validate: argv has too many elements"
        );
        let huge = "x".repeat(ENTRYPOINT_MAX_STRING_BYTES);
        let oversized = ExecRequest::new("/bin/true", [huge.as_str()]).unwrap_err();
        assert_eq!(
            oversized.message(),
            "exec stage Validate: argv exceeds the size limit"
        );
        let var = EnvVar::parse("K=V").unwrap();
        let many = vec![var.clone(); ENTRYPOINT_MAX_ENV];
        let request = ExecRequest::new("/bin/true", ["true"])
            .unwrap()
            .with_env(&many)
            .unwrap();
        let too_many = request.with_env(&[var]).unwrap_err();
        assert_eq!(too_many.code(), ErrorCode::InvalidArgument);
        assert_eq!(
            too_many.message(),
            "exec stage Validate: too many env elements"
        );
        // 対照: テストプロセス自身は環境変数を持つ。
        assert!(std::env::vars_os().next().is_some());
        let base = ContainerEnv::empty()
            .with_var("A", "definition")
            .unwrap()
            .with_var("B", "definition")
            .unwrap();
        let request = ExecRequest::new("/bin/app", ["app", "--flag"])
            .unwrap()
            .with_env(&[
                EnvVar::parse("B=explicit").unwrap(),
                EnvVar::parse("C=explicit").unwrap(),
            ])
            .unwrap();
        assert_eq!(request.path(), std::path::Path::new("/bin/app"));
        let expected_env = ContainerEnv::empty()
            .with_var("A", "definition")
            .unwrap()
            .with_var("B", "explicit")
            .unwrap()
            .with_var("C", "explicit")
            .unwrap();
        assert_eq!(
            request.command(&base).unwrap(),
            ExecCommand::new("/bin/app", ["app", "--flag"], &expected_env).unwrap()
        );
        // 明示の指定が無ければ、コンテナ定義の環境そのまま。
        assert_eq!(
            ExecRequest::new("/bin/app", ["app"])
                .unwrap()
                .command(&base)
                .unwrap(),
            ExecCommand::new("/bin/app", ["app"], &base).unwrap()
        );
    }

    /// SUP-6・TASK-163.4: 稼働中でない記録・pid の無い記録は、参加も fork もせず対象の特定で拒否する。
    #[test]
    fn sup6_task163_4_run_command_rejects_non_running_record() {
        let entry = ExecRequest::new("/bin/true", ["true"]).unwrap();
        let pid = NonZeroU32::new(std::process::id());
        for st in [
            ContainerStatus::created(cid(), pid),
            ContainerStatus::stopped(cid(), Some(0)),
            ContainerStatus::running(cid(), None),
        ] {
            let sink = RecordingSink::new(false);
            let rejected =
                run_command(&record(st), &entry, Duration::from_secs(1), &sink).unwrap_err();
            // 稼働中でない記録は fork 前の前提不成立で、監査の対象外（記録 0 件）。
            assert_eq!(rejected.delivery, AuditDelivery::NotApplicable);
            assert_eq!(sink.snapshot().len(), 0);
            let err = rejected.error;
            assert_eq!(err.code(), ErrorCode::FailedPrecondition);
            assert_eq!(
                err.message(),
                "container is not running or has no recorded pid; cannot identify pid1"
            );
        }
    }

    /// SUP-6・REPAIR-5・TASK-163.4: 期限が 0 なら残り時間が無く、段の名前を含む `Timeout` で打ち切る。
    /// 十分長い期限は残り時間を返し、`Duration::MAX` でも溢れず 7 日に丸める。
    #[test]
    fn sup6_task163_4_deadline_expires_and_clamps() {
        let expired = Deadline::after(Duration::ZERO);
        let err = expired.remaining("joining namespaces").unwrap_err();
        assert_eq!(err.code(), ErrorCode::Timeout);
        assert_eq!(err.message(), "exec timed out before joining namespaces");

        let left = Deadline::after(Duration::from_secs(60))
            .remaining("x")
            .unwrap();
        assert!(left > Duration::from_secs(50) && left <= Duration::from_secs(60));

        let max = Deadline::after(Duration::MAX).remaining("x").unwrap();
        assert!(max <= Duration::from_secs(7 * 24 * 60 * 60));
        assert!(max > Duration::from_secs(6 * 24 * 60 * 60));
    }

    /// SUP-6・REPAIR-5・TASK-163.4: 起動直後に期限が切れていても待たずに子を停止・回収し、`Timeout` を返す
    /// （子を残さない）。期限内なら残り時間で待ち、停止は呼ばない。
    #[test]
    fn sup6_task163_4_expired_deadline_kills_child_without_waiting() {
        use std::cell::Cell;
        let killed = Cell::new(false);
        let err = wait_or_stop::<ChildExit>(
            &Deadline::after(Duration::ZERO),
            |_| panic!("must not wait when the deadline has expired"),
            |_| {
                killed.set(true);
                Ok(ChildExit::Signaled(9))
            },
        )
        .unwrap_err();
        assert!(killed.get());
        assert_eq!(err.code(), ErrorCode::Timeout);
        assert_eq!(
            err.message(),
            "exec timed out before waiting for the command"
        );

        let exit = wait_or_stop(
            &Deadline::after(Duration::from_secs(60)),
            |left| {
                assert!(left > Duration::from_secs(50));
                Ok(ChildExit::Exited(0))
            },
            |_| panic!("must not kill within the deadline"),
        )
        .unwrap();
        assert_eq!(exit, ChildExit::Exited(0));
    }

    /// SUP-6・REPAIR-5・TASK-163.4: 待機が `Timeout` 以外のエラーで失敗しても、子を停止・回収してから
    /// 元のエラーを返す。回収にも失敗したら両方のメッセージを含めて返す。
    #[test]
    fn sup6_task163_4_wait_error_still_kills_and_reaps_child() {
        use std::cell::Cell;
        let killed = Cell::new(false);
        let err = wait_or_stop::<ChildExit>(
            &Deadline::after(Duration::from_secs(60)),
            |_| Err(TraitError::new(ErrorCode::Internal, "waitpid failed")),
            |_| {
                killed.set(true);
                Ok(ChildExit::Signaled(9))
            },
        )
        .unwrap_err();
        assert!(killed.get());
        assert_eq!(err.code(), ErrorCode::Internal);
        assert_eq!(err.message(), "waitpid failed");

        let err = wait_or_stop::<ChildExit>(
            &Deadline::after(Duration::from_secs(60)),
            |_| Err(TraitError::new(ErrorCode::Internal, "waitpid failed")),
            |_| Err(TraitError::new(ErrorCode::Timeout, "not reaped")),
        )
        .unwrap_err();
        assert_eq!(err.code(), ErrorCode::Internal);
        assert_eq!(
            err.message(),
            "waitpid failed; cleanup also failed: not reaped"
        );
    }

    /// SUP-6・REPAIR-5・TASK-163.4: worker の結果は pipe の 1 行で往復でき、壊れた行は `Internal` で拒否する。
    #[test]
    fn sup6_task163_4_worker_result_round_trips() {
        let outcome = ExecOutcome {
            exit: ExecExit::Command(ChildExit::Signaled(15)),
            rlimits_applied: 16,
            capability_bounding_dropped: 23,
            landlock_rules: 3,
            seccomp_instructions: 120,
            supplementary_groups: SupplementaryGroups::Cleared { cleared: 4 },
        };
        let line = encode_worker_result(&Ok(outcome));
        assert_eq!(line, b"ok command - signaled 15 16 23 3 120 cleared 4\n");
        assert_eq!(decode_worker_result(&line).unwrap(), outcome);
        // 補助グループの扱いは 3 通りとも往復する（TASK-163 追補・#1457）。
        for (groups, text) in [
            (SupplementaryGroups::AlreadyEmpty, "already_empty 0"),
            (
                SupplementaryGroups::KeptSetgroupsDenied { kept: 7 },
                "kept_setgroups_denied 7",
            ),
        ] {
            let outcome = ExecOutcome {
                supplementary_groups: groups,
                ..outcome
            };
            let line = encode_worker_result(&Ok(outcome));
            assert_eq!(
                String::from_utf8(line.clone()).unwrap(),
                format!("ok command - signaled 15 16 23 3 120 {text}\n")
            );
            assert_eq!(decode_worker_result(&line).unwrap(), outcome);
        }

        // TASK-163 追補（#1460）: `execve` 前の失敗（コマンドは起動していない）は、終了コードが同じでも
        // コマンドの終了と別の値として往復する。違反の理由コードも運ぶ。
        for (exit, text) in [
            (
                ExecExit::Command(ChildExit::Exited(126)),
                "command - exited 126",
            ),
            (
                ExecExit::SetupFailed {
                    exit: ChildExit::Exited(126),
                    violation: None,
                },
                "setup - exited 126",
            ),
            (
                ExecExit::SetupFailed {
                    exit: ChildExit::Exited(126),
                    violation: Some(ViolationReason::EntrypointInterpreterIsRuntimeBinary),
                },
                "setup entrypoint_interpreter_is_runtime_binary exited 126",
            ),
            (
                ExecExit::SetupFailed {
                    exit: ChildExit::Exited(126),
                    violation: Some(ViolationReason::StdioNullNotNullDevice),
                },
                "setup stdio_null_not_null_device exited 126",
            ),
            (
                ExecExit::SetupFailed {
                    exit: ChildExit::Exited(126),
                    violation: Some(ViolationReason::EntrypointCopyTooLarge),
                },
                "setup entrypoint_copy_too_large exited 126",
            ),
            (
                ExecExit::SetupFailed {
                    exit: ChildExit::Exited(126),
                    violation: Some(ViolationReason::EntrypointCopySealUnverified),
                },
                "setup entrypoint_copy_seal_unverified exited 126",
            ),
            (
                ExecExit::SetupFailed {
                    exit: ChildExit::Exited(126),
                    violation: Some(ViolationReason::EntrypointIsRuntimeBinary),
                },
                "setup entrypoint_is_runtime_binary exited 126",
            ),
            (
                ExecExit::SetupFailed {
                    exit: ChildExit::Exited(126),
                    violation: Some(ViolationReason::ExecDevNotDirectory),
                },
                "setup exec_dev_not_directory exited 126",
            ),
            (
                ExecExit::SetupFailed {
                    exit: ChildExit::Exited(126),
                    violation: Some(ViolationReason::ExecProcNotProcfs),
                },
                "setup exec_proc_not_procfs exited 126",
            ),
            (
                ExecExit::SetupFailed {
                    exit: ChildExit::Signaled(9),
                    violation: None,
                },
                "setup - signaled 9",
            ),
        ] {
            let outcome = ExecOutcome { exit, ..outcome };
            let line = encode_worker_result(&Ok(outcome));
            assert_eq!(
                String::from_utf8(line.clone()).unwrap(),
                format!("ok {text} 16 23 3 120 cleared 4\n")
            );
            assert_eq!(decode_worker_result(&line).unwrap(), outcome);
        }
        assert_ne!(
            ExecExit::Command(ChildExit::Exited(126)),
            ExecExit::SetupFailed {
                exit: ChildExit::Exited(126),
                violation: None
            }
        );

        let err = TraitError::new(ErrorCode::Timeout, "exec timed out\nbefore x");
        let line = encode_worker_result(&Err(err));
        assert_eq!(line, b"err TIMEOUT - exec timed out before x\n");
        let back = decode_worker_result(&line).unwrap_err();
        assert_eq!(back.violation, None);
        assert_eq!(back.error.code(), ErrorCode::Timeout);
        assert_eq!(back.error.message(), "exec timed out before x");

        for bad in [
            &b""[..],
            b"ok command - exited 0 1 2 3 4 cleared 1",
            b"ok command - exited 0 1 2 3\n",
            b"ok command - exited 0 1 2 3 4\n",
            b"ok command - exited 0 1 2 3 4 cleared\n",
            b"ok command - exited 0 1 2 3 4 unknown 1\n",
            b"ok command - exited 0 1 2 3 4 already_empty 2\n",
            b"ok command - exited 0 1 2 3 4 cleared 1 extra\n",
            b"ok command - weird 0 1 2 3 4 cleared 1\n",
            // 旧形式（起動の別が無い）・未知の起動の別・コマンドの終了に違反が付く・子が返さない理由コード。
            b"ok exited 0 1 2 3 4 cleared 1\n",
            b"ok started - exited 0 1 2 3 4 cleared 1\n",
            b"ok command entrypoint_is_runtime_binary exited 0 1 2 3 4 cleared 1\n",
            b"ok setup rootfs_is_host_root exited 126 1 2 3 4 cleared 1\n",
            b"hello\n",
            // 失敗行: 理由の欄が無い旧形式・未知の理由・exec 対象でない理由。
            b"err TIMEOUT\n",
            b"err INTERNAL unknown_reason boom\n",
            b"err INTERNAL entrypoint_is_runtime_binary boom\n",
        ] {
            let e = decode_worker_result(bad).unwrap_err().error;
            assert_eq!(e.code(), ErrorCode::Internal, "{bad:?}");
            assert_eq!(
                e.message(),
                "exec stage Spawn: the exec worker returned a malformed result"
            );
        }
    }

    /// SUP-6・REPAIR-5・TASK-163.4: 期限が既に切れていれば worker を fork せず `Timeout`（`work` は実行されない）。
    #[test]
    fn sup6_task163_4_expired_deadline_does_not_fork_worker() {
        let err = run_in_worker_with(
            Deadline::after(Duration::ZERO),
            Duration::from_secs(1),
            || panic!("cleanup must not run when no worker was forked"),
            |_| panic!("work must not run when the deadline has expired"),
        )
        .unwrap_err()
        .error;
        assert_eq!(err.code(), ErrorCode::Timeout);
        assert_eq!(
            err.message(),
            "exec timed out before starting the exec worker"
        );
    }

    /// SUP-6・TASK-163.4: pipe 容量を超える長さのエラーメッセージは上限で切り詰められ、改行で終わり往復できる。
    #[test]
    fn sup6_task163_create_failure_does_not_run_cleanup() {
        // 作成に失敗（同名の既存との衝突）したら、後始末（既存 cgroup の kill / 削除）を呼ばず fork もしない。
        let err = run_owning_child_cgroup(
            Deadline::after(Duration::from_secs(5)),
            || Err(TraitError::new(ErrorCode::AlreadyExists, "exists")),
            || panic!("cleanup must not run for a cgroup we did not create"),
            |_, _| panic!("worker must not run"),
        )
        .unwrap_err();
        assert_eq!(err.error.code(), ErrorCode::AlreadyExists);
    }

    #[test]
    fn sup6_task163_4_oversized_worker_message_is_truncated() {
        let err = TraitError::new(ErrorCode::Internal, "あ".repeat(100_000));
        let line = encode_worker_result(&Err(err));
        assert!(line.len() <= WORKER_LINE_MAX);
        assert_eq!(line.last(), Some(&b'\n'));
        let back = decode_worker_result(&line).unwrap_err().error;
        assert_eq!(back.code(), ErrorCode::Internal);
        assert!(back.message().starts_with("あ"));
    }

    /// テスト用 sink（件数上限なし。`fail` なら記録に失敗する）。
    struct RecordingSink {
        records: std::sync::Mutex<Vec<AuditRecord>>,
        fail: bool,
    }

    impl RecordingSink {
        fn new(fail: bool) -> Self {
            Self {
                records: std::sync::Mutex::new(Vec::new()),
                fail,
            }
        }

        fn snapshot(&self) -> Vec<AuditRecord> {
            self.records.lock().map(|r| r.clone()).unwrap_or_default()
        }
    }

    impl AuditSink for RecordingSink {
        fn record(&self, record: &AuditRecord) -> Result<(), TraitError> {
            if self.fail {
                return Err(TraitError::new(ErrorCode::Internal, "sink failed"));
            }
            self.records
                .lock()
                .map_err(|_| TraitError::new(ErrorCode::Internal, "poisoned"))?
                .push(record.clone());
            Ok(())
        }
    }

    /// `from_exec_error` が exec 対象の違反へ付ける末尾と同じ形のエラー（実経路は結合試験 `exec_audit` が通す）。
    fn exec_target_failure(reason: ViolationReason) -> TraitError {
        TraitError::new(
            ErrorCode::FailedPrecondition,
            format!(
                "exec stage SetNs: rejected (violation: exec_target/{}, SUP-6)",
                reason.as_str()
            ),
        )
    }

    /// SEC-4・SUP-6・TASK-163 追補（#1465）: 9 理由すべてが結果行へ理由コードとして載り、往復で同じ理由に戻る。
    /// 期待 cgroup パスのような対象はメッセージにも結果行にも載らない。
    #[test]
    fn sec4_sup6_task163_worker_line_carries_exec_target_reason() {
        for reason in ViolationReason::EXEC_TARGET_REASONS {
            let err = exec_target_failure(reason);
            assert_eq!(exec_target_reason_of(&err), Some(reason), "{reason:?}");
            let line = encode_worker_result(&Err(err.clone()));
            let text = String::from_utf8(line.clone()).unwrap();
            assert!(
                text.starts_with(&format!("err FAILED_PRECONDITION {} ", reason.as_str())),
                "{text}"
            );
            let back = decode_worker_result(&line).unwrap_err();
            assert_eq!(back.violation, Some(reason));
            assert_eq!(back.error, err);
        }
        // exec 対象でない違反・違反なしは理由を持たない。
        let other = TraitError::new(
            ErrorCode::FailedPrecondition,
            "exec stage Spawn: x (violation: entrypoint/entrypoint_is_runtime_binary, SEC-1)",
        );
        assert_eq!(exec_target_reason_of(&other), None);
        assert_eq!(
            exec_target_reason_of(&TraitError::new(
                ErrorCode::Internal,
                "x (violation: exec_target/bogus, SUP-6)"
            )),
            None
        );
    }

    /// SEC-4・SUP-6・TASK-163 追補（#1465）: 親側の記録は 9 理由それぞれ 1 件・層 `exec_target`・理由コード一致・
    /// パスなし・自 PID。違反なしの失敗は 0 件で `NotApplicable`、失敗する sink でも拒否は元のまま。
    #[test]
    fn sec4_sup6_task163_parent_records_one_audit_per_exec_target_rejection() {
        for reason in ViolationReason::EXEC_TARGET_REASONS {
            let err = exec_target_failure(reason);
            let sink = RecordingSink::new(false);
            let failure = WorkerFailure {
                error: err.clone(),
                violation: Some(reason),
            };
            let rejected = audit_worker_result(Err(failure), &sink).unwrap_err();
            assert_eq!(rejected.error, err);
            assert_eq!(rejected.delivery, AuditDelivery::Recorded);
            let recs = sink.snapshot();
            assert_eq!(recs.len(), 1, "{reason:?}");
            assert_eq!(recs[0].layer(), AuditLayer::ExecTarget);
            assert_eq!(recs[0].reason().map(|r| r.as_str()), Some(reason.as_str()));
            assert_eq!(recs[0].path(), None);
            assert_eq!(recs[0].pid().get(), std::process::id());

            let failing = RecordingSink::new(true);
            let failure = WorkerFailure {
                error: err.clone(),
                violation: Some(reason),
            };
            let rejected = audit_worker_result(Err(failure), &failing).unwrap_err();
            assert_eq!(rejected.error, err);
            assert_eq!(
                rejected.delivery,
                AuditDelivery::SinkFailed(TraitError::new(ErrorCode::Internal, "sink failed"))
            );
        }
        let sink = RecordingSink::new(false);
        let timeout = TraitError::new(ErrorCode::Timeout, "exec timed out");
        let rejected = audit_worker_result(Err(timeout.clone().into()), &sink).unwrap_err();
        assert_eq!(rejected.error, timeout);
        assert_eq!(rejected.delivery, AuditDelivery::NotApplicable);
        assert_eq!(sink.snapshot().len(), 0);
    }

    /// 祖先に symlink を含まない使い捨ての bundle ディレクトリ（rootfs の固定は symlink を辿らない）。
    fn bundle_dir(name: &str) -> std::path::PathBuf {
        let base = std::fs::canonicalize(std::env::temp_dir()).unwrap();
        let dir = base.join(format!(
            "fandhe-sup-exec-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    const MINIMAL_CONFIG: &[u8] = br#"{"ociVersion":"1.2.0","root":{"path":"rootfs"}}"#;

    /// SUP-6・TASK-163.3: `config.json` が無い bundle は `NotFound` で拒否し、メッセージに bundle のパスを出さない。
    #[test]
    fn sup6_task163_3_missing_config_is_not_found_without_path() {
        let dir = bundle_dir("missing");
        let err = load_exec_bundle(&dir).unwrap_err();
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(err.code(), ErrorCode::NotFound);
        assert_eq!(
            err.message(),
            "exec stage Landlock: failed to read config.json"
        );
    }

    /// SUP-6・TASK-163.3: 不正な JSON の `config.json` は `InvalidArgument`。
    #[test]
    fn sup6_task163_3_invalid_config_is_invalid_argument() {
        let dir = bundle_dir("invalid");
        std::fs::write(dir.join("config.json"), b"{not json").unwrap();
        let err = load_exec_bundle(&dir).unwrap_err();
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        assert!(
            err.message().starts_with("exec stage Landlock: "),
            "{}",
            err.message()
        );
    }

    /// SUP-6・SEC-1・TASK-163.3: 正しい `config.json` と rootfs ディレクトリがあれば、設定を読み rootfs を
    /// 固定できる。固定した fd は bundle 配下の `rootfs` ディレクトリそのもの（`st_dev`・`st_ino` が一致）。
    #[test]
    fn sup6_task163_3_loads_config_and_pins_bundle_rootfs() {
        use std::os::unix::fs::MetadataExt as _;
        let dir = bundle_dir("ok");
        std::fs::write(dir.join("config.json"), MINIMAL_CONFIG).unwrap();
        std::fs::create_dir(dir.join("rootfs")).unwrap();
        let want = std::fs::metadata(dir.join("rootfs")).unwrap();
        let (config, rootfs) = load_exec_bundle(&dir).unwrap();
        let pinned = std::fs::File::from(rootfs.as_fd().try_clone_to_owned().unwrap())
            .metadata()
            .unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(config.root().path(), std::path::Path::new("rootfs"));
        assert_eq!((pinned.dev(), pinned.ino()), (want.dev(), want.ino()));
    }

    /// SUP-6・SEC-1・TASK-163.3: rootfs を固定できない bundle（不在・symlink・bundle の外を指す `root.path`）は
    /// 拒否する（照合の基準を作れないまま再適用へ進まない。fail-closed）。メッセージにパスを出さない。
    #[test]
    fn sup6_task163_3_unpinnable_rootfs_is_rejected() {
        let dir = bundle_dir("norootfs");
        std::fs::write(dir.join("config.json"), MINIMAL_CONFIG).unwrap();
        let err = load_exec_bundle(&dir).unwrap_err();
        assert_eq!(err.code(), ErrorCode::NotFound);
        assert_eq!(
            err.message(),
            "exec stage Validate: rootfs directory not found"
        );

        std::fs::create_dir(dir.join("real")).unwrap();
        std::os::unix::fs::symlink(dir.join("real"), dir.join("rootfs")).unwrap();
        let err = load_exec_bundle(&dir).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        assert_eq!(
            err.message(),
            "exec stage Validate: rootfs must not contain a symlink"
        );

        std::fs::write(
            dir.join("config.json"),
            br#"{"ociVersion":"1.2.0","root":{"path":"/"}}"#,
        )
        .unwrap();
        let err = load_exec_bundle(&dir).unwrap_err();
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        assert_eq!(
            err.message(),
            "exec stage Validate: rootfs must not be the filesystem root"
        );
    }
}
