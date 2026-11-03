# exec 用 pidfd の受け渡し（supervisor の制御チャネルから CLI の exec へ）の判断記録

CLI の `exec` コマンドが `run_command_with_pidfd` を呼ぶために必要な「起動時 pidfd」を、どの経路で CLI プロセスへ渡すかを記録する。

> 位置づけ: **判断記録（案 A はオーナー承認済み）**。#2626 の実装で案 A を採用し（既存の uid 照合・同一性照合を保ち、プロトコルの作り直しや専用 bin を足さない安全側）、2026-11-03 にオーナーが案 A を承認した（[#4 のコメント](https://github.com/Fandhe-AI/fandhe-container/issues/4#issuecomment-6595741383) の 4 番目の項。SUP-6・SEC-4）。同じコメントで、CRI の exec（#3726 の分解、#3752〜#3761）の設計記録 #3752 は、この経路を再利用できるかを先に確かめることとされた。§6 の 2 点目（観測名の語彙）は未決定のまま残る。

- 対象ビヘイビア: SUP-6・SEC-4・CLI-1（関連: SEC-1・CORE-1・REPAIR-2・REPAIR-5・REPAIR-3）
- タスク: TASK-163 追補（exec の入口。#1461・#1617・#1465・#1594）
- 関連 issue: #2626（本件）・#2441（healthcheck の配線）・#2688（supervisor 不在時の exec）・#1869（非 Linux の plugin 経路）
- 作成日: 2026-10-24（2026-11-03 にオーナー承認を反映）

## 1. 背景

- `exec::run_command_with_pidfd(record, pidfd, request, timeout, audit)` は、コンテナの起動時（fork 直後・回収前）に取った pidfd を必須の引数に取る（pid 再利用に対する SEC-1 の恒久策）。記録上の pid からの `pidfd_open` は縮退経路で、本番の通しの入口には存在しない。
- 起動時の pidfd を持つのは、稼働中の supervisor の監視スレッドにある `ControlledProcess` だけ。
- `run_command_with_pidfd` を呼ぶプロセスは単一スレッドでなければならない（`setns` が多スレッドを拒否し、core の `fork_single_threaded` が実行時にも強制する）。supervisor 本体はログ捕捉スレッドと制御チャネルのスレッドを持つため、呼び出し元になれない。
- 制御チャネルの frame は固定長（payload 上限 64 バイト）で 1 接続 1 要求。接続の両側で `SO_PEERCRED` の uid を照合する。
- したがって「sink を渡す 1 行を足す」だけでは本番で動かず、pidfd の受け渡し（1 段目）が要る。

## 2. 案の比較

| 案 | 内容 | 利点 | 欠点 |
| -- | ---- | ---- | ---- |
| A（採用） | 制御チャネルに ExecHandoverRequest（kind 6）を足し、supervisor が起動時 pidfd の複製を `SCM_RIGHTS` で返す。単一スレッドの CLI プロセス自身が `run_command_with_pidfd` を呼ぶ | argv・env・期限・sink が CLI 側にあるので固定長プロトコルを作り直さない。専用 bin 不要。既存の uid 照合と同一性照合を使う | supervisor の `sys` に `sendmsg` / `recvmsg` の `unsafe` を足す（事前承認の範囲の薄いラッパー） |
| B | supervisor 側で exec を実行する | CLI は結果を受けるだけ | argv・env を 64 バイトの frame で運べず、可変長への作り直しが要る（REPAIR-2 の対象が広がる）。supervisor 本体は多スレッドなので単一スレッドの helper bin も要る |
| C | CLI が記録上の pid に `pidfd_open` する | 実装が最小 | pid 再利用に弱い縮退経路そのもの。本番では禁止（SEC-1・#1617） |

## 3. 採用案 A の仕様

### 3.1 frame

| 項目 | 値 |
| ---- | -- |
| 要求 | kind 6、payload は pid `u32`・deadline_ns `u64`（12 バイト、全長 20）。pid 0・deadline 0 は表現できない |
| 応答 | 通常の Response frame（9 バイト）。成功のときだけ、同じ `sendmsg` に `SCM_RIGHTS` で pidfd の複製を 1 本添える。拒否には fd を添えない |
| 版 | `VERSION` は 1 のまま。古い supervisor は kind 6 を `Malformed` で断り、CLI は exec せずに `INVALID_ARGUMENT` で失敗する（fail-closed。kind 4・5 と同じ互換の方針） |

### 3.2 supervisor 側の判定（`SignalSlot::handover_pidfd`）

| スロットの状態 | 結果 |
| -------------- | ---- |
| `Active` かつ要求 pid が記録 pid と一致かつ複製あり | `Ok` + fd 1 本 |
| `Active` かつ pid 不一致 | `PidMismatch` |
| `Active` かつ複製なし（pidfd 非対応のカーネル・起動ハンドルが pidfd を持たない） | `NoHandle` |
| `Exited`（pid 一致） | `ContainerExited`（複製は落ちている） |
| `Exited`（pid 不一致） | `PidMismatch` |
| `Empty` | `NoHandle` |

複製は `ControlledProcess::new` が `launch_pidfd` から `F_DUPFD_CLOEXEC` で作り（std の `try_clone_to_owned`）、`Exited` / `Empty` への遷移や再起動による世代交代で落ちる。古い世代の複製は新しい世代の pid では渡らない。

### 3.3 CLI 側の順序（`commands/exec.rs`）

1. 要求の構築（`ExecRequest`: 絶対パス・argv・`--env` の上限検証）
2. 状態ストアを開き、記録が `Running` で pid を持つことを確かめる。続けて create の起動オプション文書の launch 時 env を状態記録の世代と照合して読む（`container_options::store::launch_env_for`。SUP-12・#2713。欠落・世代不一致は exec しない）
3. 監査の記録先を `default_audit_sink(Some(host_state_root))` で作る。**作れなければ exec しない**（監査なしで実行する経路は無い）。supervisor へ接続する前に作るのは、監査できない exec のために pidfd を複製させないため
4. 制御チャネルから pidfd の複製を受け取る（`SCM_RIGHTS`。受け取る fd はちょうど 1 本で、`MSG_CTRUNC`・2 本以上・Ok なのに 0 本はすべて閉じて失敗）
5. `run_command_with_pidfd_output_notify` を呼ぶ（cgroup の作成直後の通知は 3.5。env は `config.json` の `process.env` の上に launch 時 env、その上に `--env` を重ねる。healthcheck と同じ規則）。受け取った fd は信用せず、`identify_pid1_with_pidfd` が fdinfo の `Pid:` を記録 pid と照合する

### 3.4 終了コードと期限

- コマンドが起動した場合は子の終了状態（`Exited(n)` は `n`、`Signaled(s)` は `128 + s`）。起動前に子が失敗した場合（`SetupFailed`）も子の終了状態（通常 125 / 126 / 127）。
- 拒否・期限超過・到達不能は ERR-2 の `OCI_EXIT_*`（1〜10）と stderr の構造化エラー 1 行。コマンド自身の 1〜10 と重なるため、見分けは stderr の行の有無（docker exec と同じ考え方）。
- 全体の既定は 60 秒、`--timeout` で上書き（1〜3600 秒）。pidfd の受け渡しは全体の期限の内側で 5 秒を上限にする。残りが `run_command_with_pidfd` の `timeout` になる（REPAIR-5）。

### 3.5 子孫の回収（接続の保持と作成通知。codex P1・SUP-6・REPAIR-5・#2626）

**問題**: `PR_SET_PDEATHSIG` は「内側の CLI → worker → 直接のコマンド」の 1 段にしか効かず、コマンドが作った子孫へは継承されない（core の `exec_command.rs` に明記の制限）。子孫は既にコンテナ側の `exec-*` cgroup にいて、cgroup を掃除する CLI 自身も SIGKILL され得るため、CLI 側だけでは `--timeout` を超えた残留を止められない。systemd の委譲スコープの停止でも回収できない（子孫はコンテナ側 cgroup）。

**方式**: 回収役を、生存する supervisor 側に置く。healthcheck の前例（helper が `FCHC1 <name>` を通知し、supervisor が `remove_exec_child_cgroup` で止める）と同じ考え方を、制御チャネルの接続に載せる。

1. pidfd を渡した接続を supervisor は **閉じずに** 専用の「ガード」スレッドへ預ける（accept ループは先へ進むため、Signal・Stop の処理を止めない）。クライアント（`ExecHandover`）も接続を保持し、`run` が戻って CLI の後始末が済むまで drop しない
2. CLI は exec 子 cgroup の排他作成に成功した直後（worker の fork 前）に、同じ接続で **ExecCgroupNotify**（kind 7: 保持期限 `u64` + `ExecCgroupName`）を送り、ack（`Response(Ok)`）を待つ。ack を受けてから worker を fork する＝登録が先に確定する。通知に失敗したら cgroup を消して exec しない（`on_created` が `Result` を返す fail-closed）
3. ガードは名前を `ExecCgroupName::new` で検証して保持し、接続の切断（CLI の正常終了・SIGKILL を含む消滅）か保持期限（通知の期限 + 猶予 30 秒。上限 `MAX_EXEC_HOLD_SECS` = 3600 = `--timeout` の上限）まで待ち、`ExecCgroupReclaimer`（本番は `StoreExecReclaimer`: 回収の時点で自分のコンテナの状態記録を読み、記録の cgroup 配置から `remove_exec_child_cgroup` を呼ぶ）で `cgroup.kill` と削除を行う。冪等で、通常終了では CLI が先に消していて `Absent`
4. 資源は固定: 同時のガードは 16（`ExecGuardLimits::max_guards`）。超えたら **pidfd を渡す前** に `ExecGuardExhausted`（`RESOURCE_EXHAUSTED`）で断る。通知の待ちは 10 秒。回収役が結線されていない supervisor は `ExecReclaimUnavailable` で断る（fail-closed。本番の `start_entry` は必ず配線する）
5. 結果は構造化ログ `exec_cgroup_reclaim`（`trigger`: disconnect / deadline / protocol、`outcome`: removed / absent / failed）と `OpRecorder` へ集計する（REPAIR-4）
6. ガードのプールは `PausableServer` が保持するので、restart の再 launch での accept ループの pause / resume（#2043）の影響を受けない

**残る窓**: (a) 通知の ack より前に CLI が消えた窓（作成から通知まで）は回収されない。cgroup は空なので exec 開始時の掃除（`sweep_before_create`）・delete 前の掃除（KillAll）が回収する。(b) supervisor 自身が消えた場合は回収されない（コンテナ cgroup ごと delete 前の掃除が回収する）。(c) 通知から回収までの間にコンテナが再 launch されて配置（instance）が変わった場合、旧 instance の cgroup は旧コンテナとともに消えるため `Absent` / `Failed` になる。(d) 新しい CLI と古い supervisor の組は、kind 6 の応答で pidfd が渡る一方、kind 7 を `Malformed` として閉じるため通知に失敗し、exec しない（fail-closed）。古い CLI と新しい supervisor の組は、通知なしで接続が切れるだけで何も回収せず従来どおり動く。(e) ガードスレッドは accept ループとは別のスレッドで、cgroup の `cgroup.kill` の待ち（最大 2 秒）は他の要求を止めない。

**接続の複製が残らないことの確認**: 接続は `SOCK_CLOEXEC` で作られ（`sys` の `connect_bytes`）、CLI が fork する監査 sink の子と exec のコマンドの子は `close_range` で fd 3 以上を閉じる。fork のみで exec しない worker は接続の複製を持つが、PDEATHSIG で CLI と同時に終わる。したがって CLI の消滅後に複製が残って切断の検出を遅らせることは通常無い。万一残っても検出は保持期限（`--timeout` + 猶予）で有界。

**却下案**: `PR_SET_PDEATHSIG` を `SIGTERM` に替えて内側の CLI が捕捉し子孫を止める案は、内側の CLI 自身が SIGKILL されると救えず、codex の要求（CLI 消滅時の回収）を満たさないため採らない。CLI が systemd のスコープを使って子孫ごと止める案は、子孫が既にコンテナ側の cgroup へ移っているため回収できない。supervisor が定期的に `exec-*` を走査して持ち主の無い cgroup を止める案は、持ち主の判定（pid の再利用）が曖昧で、走査間隔の分だけ `--timeout` を超えるため採らない。

## 4. 信頼境界の評価

- 渡す相手は、コンテナごとの 0700 のディレクトリの 0600 のソケットに、`SO_PEERCRED` の uid が supervisor の実効 uid と一致する接続だけ（サーバ側の既存の uid ゲートの後。クライアントも listen 側の uid を照合する）。
- 同じ uid のプロセスは元からコンテナのプロセスへシグナルを送れる（rootless では同じ uid）。pidfd が渡ることで増える能力は `pidfd_send_signal` と `setns` の起点になることで、同じ uid の権限の範囲に収まる。root で動かす構成（rootful）は `start` が未対応のため対象外。
- 渡すのは複製（close-on-exec）で、受け取った CLI は `OwnedFd` で持ち、関数を抜けると閉じる。コマンドへは core が `execveat` の前に `close_range` で閉じて渡らない。
- fd の漏れ: クライアントは `recvmsg` の制御バッファを fd 4 本分に限り、溢れた分はカーネルが閉じる。想定外の本数はすべて drop で閉じる。拒否の応答に fd が添えられていても閉じる。
- 新しい `unsafe` は `crates/supervisor/src/sys/linux.rs` の `sendmsg` / `recvmsg` の薄いラッパーだけ（coding-rust.md の事前承認の範囲）。cmsg の解析は純関数（`parse_rights`）に分け、添字アクセスをしない。構造体の大きさと定数は単体テストとコンパイル時の `assert!` で固定する。

## 5. 範囲外（未実装。REPAIR-3）

| 項目 | 担当 |
| ---- | ---- |
| コマンドの標準入出力の受け渡し（現状 `/dev/null` 固定）・cwd・ユーザーの指定 | 未起票（`exec.rs` のモジュール doc「未実装」） |
| supervisor 不在（孤児化・再起動後）の exec | #2688 |
| healthcheck の sink の配線 | #2441 で実装済み（exec 専用 helper が `FileAuditSink` を直接使い、pidfd の複製は helper の stdin へ execve 越しに渡す） |
| 非 Linux の exec（plugin 経由） | #1869 の設計・TASK-125 |
| CLI の exec での execve 越しの継承（supervisor が専用の exec プロセスを起動する方式） | 採らない（healthcheck は supervisor 自身が呼び出し元のため、この方式で #2441 が実装済み） |
| 実 pidfd・実コンテナでの通し試験（root 不要の rootless 環境での実行と記録） | 人間担当（実機前提。#1621 の系列） |

## 6. 確認が必要な点（オーナー判断）

- ~~案 A の採否（不採用なら案 B の可変長プロトコルと helper bin の設計から）。~~ **決定済み**: 2026-11-03 にオーナーが案 A を承認した（[#4 のコメント](https://github.com/Fandhe-AI/fandhe-container/issues/4#issuecomment-6595741383) の 4 番目の項）。
- 制御チャネルの観測名 `control_signal` を exec の受け渡しにも使っている点（集計の語彙を分けるか）。**未決定**。
