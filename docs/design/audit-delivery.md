# seccomp・Landlock の拒否を監査の記録先へ届ける配送経路（設計ドラフト）

カーネルが返す seccomp と Landlock の拒否を、`AuditSink`（`FileAuditSink` ほか）へ届ける配送経路の候補を、同じ比較軸で並べた判断資料。

> **位置づけ**: **方式は採用済み・一部実装（`KILL_PROCESS` 側の補助記録は #2004 で実装。USER_NOTIF 版のフィルタ構築は #2023、start 経路の応答者は #2025、exec 経路の応答者は #2544 で実装済み。ほかは未着手）**。TASK-41 追補・#1835 の設計ドラフトとして作り、2026-10-15 にオーナーが 4 章の組み合わせ案と 7 章の推奨を採用した（判断の記録は #2018 のコメント。11 章の承認事項 1〜4 を含む）。実装は 9 章の issue が担い、本書は実装済みを装わない（REPAIR-3）。SEC-4 の「100% 記録」は記録経路が利用できる環境で満たすと spec に明記した（fandhe-container-spec#21。11 章）。

- 対象ビヘイビア: SEC-4（関連: SEC-2・CORE-1・CORE-5・SUP-2・SUP-6・REPAIR-3・REPAIR-5）
- タスク: TASK-41 追補、MS-2、#1835（前提: #1834 の seccomp 拒否時の動作。origin/main 9a933113 で反映済み）
- 作成日・確認日: 2026-10-15（同日にオーナーが方式を採用。#2018）
- 出典: SSOT は `docs/spec` の `04-behavior/security-isolation.md`（SEC-4）と `03-poc/security-isolation/`（ESC 表・監査ログ設計）。本書は ID で参照し、長い引用はしない

## 1. 背景と目的

SEC-4（Must）は分離違反の試行の 100% 記録を要求する。現状は、記録を組み立てるヘルパは実装済みだが、**カーネルの拒否をヘルパへ渡す配送経路が無い**（#205 の条件つき承認が指摘した未追跡事項）。#206（TASK-43）の「エスケープ成功 0 件」は監査の 100% 記録を含めないため、本書は #206 の前提ではない。

## 2. 一次情報

| 文書 | 版 | 節 | 要点 | 確認 |
| ---- | -- | -- | ---- | ---- |
| `seccomp(2)` man ページ（手元の man-pages） | 手元の版 | `SECCOMP_RET_KILL_PROCESS` | 呼び出し元から見て SIGSYS による終了。SIGSYS のハンドラが登録されていても無視され必ず終了する。親の `waitpid` は SIGSYS 終了を見る（Linux 4.14 以降） | 確認済み（2026-10-15） |
| 同上 | 同上 | `SECCOMP_RET_TRAP` | スレッド宛ての SIGSYS を送り、システムコールは実行しない。ハンドラで捕捉できる | 確認済み |
| 同上 | 同上 | `SECCOMP_RET_USER_NOTIF`（Linux 5.0） | 付属の supervisor へ転送する。`SECCOMP_FILTER_FLAG_NEW_LISTENER` 無し、または listener の fd が閉じられている場合は `ENOSYS` を返す。他のフィルタがより優先順位の高い値を返すと supervisor は通知されない | 確認済み |
| 同上 | 同上 | `SECCOMP_FILTER_FLAG_NEW_LISTENER`（Linux 5.0）・`SECCOMP_FILTER_FLAG_LOG`（Linux 4.14） | スレッドに入れられる NEW_LISTENER 付きフィルタは最大 1 つ（`EBUSY`）。LOG は `actions_logged` に載る動作の記録を要求する | 確認済み |
| 同上 | 同上 | Audit logging of seccomp actions | KILL_PROCESS・KILL_THREAD は `actions_logged` に載っていれば記録される。それ以外の動作は、フィルタが LOG フラグを要求して `actions_logged` に載っているか、監査対象のプロセスのとき記録される。`ALLOW` は記録されない | 確認済み |
| `/proc/sys/kernel/seccomp/actions_logged` | 手元のカーネル（開発機。本リポの対象カーネルの代表ではない） | - | 既定の値は `kill_process kill_thread trap errno user_notif trace log` | 手元で確認済み |
| `seccomp_unotify(2)` man ページ | 手元の版 | 通知と応答 | 通知の cookie（id）を `SECCOMP_IOCTL_NOTIF_ID_VALID`（Linux 5.0）で検証し、PID の再利用による競合を避ける。listener の fd は UDS の `SCM_RIGHTS` または `pidfd_getfd(2)` で受け渡せる | 確認済み |
| 同上 | 同上 | `SECCOMP_USER_NOTIF_FLAG_CONTINUE`（Linux 5.5） | 対象のシステムコールをそのまま実行させる。注意が必要で、安全性の判定には使えない（TOCTOU）。拒否の応答には使わない | 確認済み |
| Linux v6.12 `kernel/seccomp.c`（`seccomp_set_mode_filter`・`init_listener`・`has_duplicate_listener`） | v6.12 | `NEW_LISTENER` の処理 | 重複 listener の検査は祖先の filter が listener を持つかだけを見て、BPF が `USER_NOTIF` を返すかは調べない（`init_listener` が無条件に通知用の状態を作る）。listener fd は `get_unused_fd_flags(O_CLOEXEC)` で確保され syscall の戻り値になる。このため ERRNO 版の filter でも listener を得られ、通知は生じない（#2024 の本番方式はこれを使う） | 確認済み（2026-10-19。GitHub の v6.12 タグの原文） |
| `unix(7)` | 手元の版 | `SO_PASSCRED`・`SCM_CREDENTIALS` | 受信側が `SO_PASSCRED` を有効にすると、送信側が付けなくても送信元の資格情報が届く。pid は受信側の PID namespace の値に変換される。socketpair の `SO_PEERCRED` は作成者を返す | 確認済み（PID namespace の変換は実機の `production_launcher` で #2024 の照合が未実行のため、実機確認は未完） |
| 同上 | 同上 | 通知の `pid` の名前空間 | 通知の `pid` が listener 側の PID namespace の値であること、`/proc/<pid>` の参照に PID 再利用の競合があることの両方は、本書で原文を確認しきれていない | **確認済み（2026-10-19。#2025）**: v6.12 `seccomp_notify_recv` は `unotif.pid = task_pid_vnr(knotif->task)`（RECV を呼んだ側の PID namespace の TID）。`ID_VALID` は RECV 済み（応答待ち）の通知が存在するとき 0、無ければ `ENOENT`。`poll` は未処理の通知で `EPOLLIN`、filter の利用者が 0 で `EPOLLHUP`。利用者が 0 の RECV は待たず `ENOENT`。supervisor は `/proc/<TID>/status` の `NSpid` 末尾へ変換し、読んだ後に `ID_VALID` で検証する |
| Linux `userspace-api/landlock`（docs.kernel.org） | - | 監査ログ（`AUDIT_LANDLOCK_ACCESS`・`AUDIT_LANDLOCK_DOMAIN`）と `landlock_restrict_self` のログ制御フラグ | ABI 7（Linux 6.15 の見込み）で監査ログに対応し、`landlock_restrict_self` のログ制御フラグ（`LANDLOCK_RESTRICT_SELF_LOG_*`）を持つ見込み。execve の後の拒否を記録する指定が必要な見込み。本リポの Landlock は ABI 6・Linux 6.12 前提で差がある | 一部確認済み（2026-10-18）。`linux/landlock.h` で `LOG_SAME_EXEC_OFF`(1)・`LOG_NEW_EXEC_ON`(2)・`LOG_SUBDOMAINS_OFF`(4) を確認し、既定では execve の後の拒否が記録されないため `LOG_NEW_EXEC_ON` だけを渡す。v6.15 のソース（`security/landlock/syscalls.c`・`limits.h`）で ABI 7・flags のマスクが `CONFIG_AUDIT` に依らず、`CONFIG_AUDIT=n` でも flags 2 は受理されることを確認（2026-10-21。#2306）。実機未確認で、手順は `docs/verification/landlock-audit-exec.md` |
| Linux カーネル監査（`AUDIT_SECCOMP`〔1326〕） | v6.12 | 記録項目・有効化・読み出し権限 | `auid uid gid ses pid comm exe sig arch syscall compat ip code` が記録される。`audit_seccomp` は `audit_enabled` に関係なく記録を強制する。`CONFIG_AUDITSYSCALL` が無い・起動時 `audit=0`・exclude 規則・backlog 超過では出ない。読み出し（`AUDIT_NLGRP_READLOG`）は初期 user namespace の `CAP_AUDIT_READ` と初期 network namespace が要る。`contid` は無い | **確認済み（2026-10-20。v6.12 の原文。#2237）**。詳細と読み手の判断材料は `audit-seccomp-reader.md` |
| moby / containerd | - | seccomp の拒否の記録 | 既定は auditd 任せの見込み（moby 既定プロファイルは KILL 系を使わない。`seccomp.rs` のコメントと整合） | **未確認** |

Landlock には USER_NOTIF に相当するユーザー空間への通知経路が無い見込み（`EACCES` は呼び出したプロセスにしか返らない）。この点も上記 Landlock 文書で確かめる（未確認）。

## 3. 現状（本リポ、実装済みを装わない）

| 要素 | 状態 | 場所 |
| ---- | ---- | ---- |
| seccomp 違反の記録の組み立て | フック実装済み。呼び出し元は supervisor の USER_NOTIF listener ループ（#2025。`record_seccomp_denial_for` でコンテナ ID を付ける）。SIGSYS ハンドラ経路は未実装 | `crates/core/src/audit_log/seccomp_hook.rs`（`SeccompDenialReport::from_sigsys`・`from_user_notif`、`record_seccomp_denial`） |
| 拒否時の動作（#1834） | `unshare`・`ptrace`・`kexec_load` の 3 件は `SECCOMP_RET_KILL_PROCESS`、残り 40 件は `ERRNO(EPERM)`（`mount`・`pivot_root`・`umount2` を含む。ESC-03 が EPERM を要求） | `crates/core/src/seccomp.rs`（`DenyAction`・`DeniedSyscall::deny_action`） |
| USER_NOTIF 版のフィルタ構築（#2023） | `ErrnoDelivery::UserNotif` で ERRNO 側 40 件を `SECCOMP_RET_USER_NOTIF` にしたフィルタを構築できる（`build_deny_filter_with`）。KILL の 3 件・arch 不一致・x32 は不変。**既定の launcher の適用経路は ERRNO 版のまま（start と exec は応答者つきで opt-in。#2025・#2544）**（listener が開いたまま誰も応答しないと `USER_NOTIF` 側の syscall が止まり、閉じると `ENOSYS` になり ESC-03 と食い違うため。応答側は #2025） | `crates/core/src/seccomp.rs`・`crates/core/src/exec/seccomp.rs`（テスト） |
| listener の取得と受け渡し（#2024） | 本番の起動（PID 1）は `NEW_LISTENER` 付きで ERRNO 版の filter を載せ、listener fd を socketpair（`SOCK_SEQPACKET`）の `SCM_RIGHTS` で起動側 C へ渡す。C は `SCM_CREDENTIALS` の pid・fd の種別（`anon_inode:seccomp notify`）・close-on-exec・fd がちょうど 1 本であることを検証してから ACK を返す。PID 1 は ACK を待ってから exec に進む。取得・送信・受信・検証・ACK のどれが失敗しても起動を失敗にし（fail-closed）、PID 1 を回収する。受け取った listener は `LaunchedProcess::take_seccomp_listener` で 1 回だけ取り出せる。**既定の launcher は ERRNO 版のまま（通知は生じない）。supervisor の start 経路だけが `ProductionLauncherBuilder::seccomp_errno_delivery(UserNotif)` で opt-in し、listener は #2025 のループ（下の行）が読んで応答する**。制約: ワークロード、または祖先の filter が既に listener を持つ環境（例: syscall の intercept を有効にした Incus のコンテナ）では `EBUSY` となり launch が `FailedPrecondition`（段 `Seccomp`）で失敗する。稼働中コンテナへの exec（SUP-6）の再適用 worker は、#2385 で同じ受け渡しを行う（下の「exec 経路の受け渡し（#2385）」の行） | `crates/core/src/exec/seccomp_listener.rs`・`crates/core/src/sys/seccomp_notify.rs`・`crates/core/src/exec/launch_intermediate.rs` |
| exec 経路の受け渡し（#2385） | 稼働中コンテナへの exec（SUP-6）の worker（exec 専用の親プロセスが fork する使い捨て）も、`reapply_restrictions` の最後（seccomp の段）で `NEW_LISTENER` 付きの ERRNO 版 filter を載せ、listener fd を親へ同じ socketpair 方式で渡す（起動側 C は exec では worker を fork した親）。親は **worker の終了を待つ前に** 期限（exec の全体期限。worker の ACK 待ちは全体期限と 60 秒の短い方）つきで受信・検証して ACK を返す（先に終了を待つと worker の ACK 待ちとの相互待ちになる）。検証・失敗の扱いは launch と同じ（fail-closed）。受け渡しに失敗（拒否・期限切れ）したら worker を待たずに止めて回収し、exec を拒否する（段 `Seccomp`）。worker が何も渡さずに終わったときは、worker の失敗（違反の理由つき）をそのまま返し、成功を返していたら ACK 無しで進んだものとして `Internal` で拒否する。`ExecRestrictions::with_seccomp_listener` で送り手を付けない本番の再適用（`Complete`）は、何も適用せず `FailedPrecondition`（段 `Validate`）で拒否する。成功の証跡は `ExecOutcome::seccomp_listener`（`Verified`）。**filter の届け方は親が fork 前に決め（`spawn_exec_worker_with_listener` の `delivery` 引数）、本番の exec は `USER_NOTIF` で載せる。応答者は exec の親（#2544。次の行と 9.4）で、受け取った listener は worker の回収が済むまで保持してから閉じる**。制約: コンテナの `RLIMIT_NOFILE` が極端に小さいと listener の fd を確保できず（`EMFILE`）exec が段 `Seccomp` で失敗する（fail-closed）。外側の filter が listener を持つ環境は launch と同じく `EBUSY`（`FailedPrecondition`） | `crates/core/src/exec/seccomp_listener.rs`（`ExecListenerSender`・`ExecListenerReceiver`）・`crates/core/src/exec/exec_command.rs`（`spawn_exec_worker_with_listener`）・`crates/core/src/exec/reapply.rs`・`crates/supervisor/src/exec.rs`（`run_in_worker_with`）・試験 `crates/supervisor/tests/exec_seccomp_listener.rs` |
| listener ループ（#2025） | supervisor の `SeccompNotifyHub`（listener スレッド 1 本と recorder スレッド 1 本）が、通知を読んで「`/proc` で PID を変換 → `ID_VALID` で cookie 検証 → `ControlAuditRelay` へ記録（期限 1 秒。超えても応答する）→ `-EPERM` で応答」を行う。応答は `-EPERM` の 1 種類だけで、引数・命令ポインタは core が公開しない（TOCTOU）。記録の段にだけトークンバケット（20 件/秒・バースト 64）と有界キュー（64）を置き、超えた分は記録せず待たずに応答して集計し、固定語彙の構造化ログ（`seccomp_audit_suppressed` 等）を 1 秒以上の間隔で出す。start と restart の再 launch で listener を差し替える（再 launch が本番で成り立つかは #2043）。listener が届かない・スレッドを作れないときは起動を失敗にする。応答者が消えると拒否は `ENOSYS` のまま保たれる。**exec 経路（SUP-6）はこのハブを使わない（exec の親は単一スレッドでなければならずスレッドを持てないため。応答者は #2544 の同期の応答者で、次の行）。記録先（`ControlAuditRelay`）を作れないとき、または応答者（ハブ）の無い構成は起動を拒否する（`FailedPrecondition`。#2027、7.1）** | `crates/supervisor/src/seccomp_notify.rs`・`crates/core/src/exec/seccomp_listener.rs`・`crates/core/src/audit_log/control_relay.rs`（seccomp の枠） |
| exec 経路の応答者（#2544） | exec の親（`exec::run_in_worker_with`）が、listener を受け取った後に **単一スレッドで同期に** 応答する（`seccomp_notify::ExecResponder`）。worker の終了を `wait_for_exit(0)`（kill しない観測）で見ながら 20ms 刻みで listener を待ち、通知ごとに「`/proc` で PID を変換 → `ID_VALID` で cookie 検証 → トークンバケット（20 件/秒・バースト 64）→ `record_seccomp_denial_for_until`（`min(応答期限 1 秒, exec の全体期限)` で打ち切り。記録先は exec の `audit`、本番は `FileAuditSink` → `@audit.log`、コンテナ ID は記録の ID）→ `-EPERM` で応答」を行う。応答は `-EPERM` の 1 種類だけで、記録の可否に関わらず必ず応答する。応答者を続けられなくなったとき（待機・受信の失敗、応答の送信の失敗）は listener を即座に閉じ、カーネルが待機中の syscall を `ENOSYS` で解く（許可に倒れない）。exec は止めず、`ExecOutcome::seccomp_audit`（`responder` が `Served` / `Lost`、`counts.recorded` が記録できた拒否の件数）と固定語彙の構造化ログ（待たない出口。共有の出力口は専用スレッドを作り、後続の `FileAuditSink` の主経路が要する `Threads: 1` を壊すため使わない）に出す。応答者の構成（記録先・コンテナ ID・設定）を値で持つ `ListenerPolicy::Respond` だけが本番の値で、「`USER_NOTIF` なのに応答者がいない」組み合わせは本番の経路で構築できない。判断と残余は 9.4 | `crates/supervisor/src/seccomp_notify.rs`（`ExecResponder`）・`crates/supervisor/src/exec.rs`（`respond_and_collect`）・`crates/core/src/audit_log/seccomp_hook.rs`（`record_seccomp_denial_for_until`）・試験 `crates/supervisor/tests/exec_seccomp_listener.rs` |
| Landlock の記録 | プロセス内で観測した `EACCES` の写像まで（ワークロードの拒否の証拠にしない）。ABI 7 以上では `landlock_restrict_self` に `LOG_NEW_EXEC_ON` を渡してカーネル監査へ要求し、ABI 6 では縮退を `state.json` の `launchIsolation.landlock.audit` と構造化ログに出す（#2026。読み手は外部の auditd 等）。ホストの縮退の判定・警告・厳格モードは #2027（7.1） | `crates/core/src/audit_log/landlock.rs`（`landlock_denial_record`） |
| 本番 sink | `FileAuditSink`（ファイル主経路と NETLINK_AUDIT フォールバック。常時 tee は未実装）。supervisor の exec 経路は `default_audit_sink` で配線済み（#1594） | `crates/core/src/audit_log/file_sink.rs`・`crates/supervisor/src/exec.rs` |
| コンテナ ID | `AuditRecord::container_id`（#1618）。seccomp は #2025 で付与（`record_seccomp_denial_for`）。Landlock の記録への付与は未実装 | `crates/core/src/audit_log.rs` |
| 型の制約 | `AuditEvent::Seccomp` は syscall 番号と arch が必須で、「syscall の無い seccomp 違反」を構築できない | `crates/core/src/audit_log.rs` |
| 試験 | ESC-03（seccomp）・ESC-08（mount の bind の元・create のパース時の destination 拒否〔#2480〕。plugin-cri の create と start の再検証の destination 拒否は結合試験 `crates/plugin-cri/tests/create_destination_audit_relay.rs`・`crates/supervisor/tests/start_destination_audit_relay.rs` が relay 経由で照合する〔#2594〕）は `Required` で、コンテナの外で回収した状態ルートの `@audit.log` を照合する。ESC-01・07（landlock 帰属）・10 は `Required` で、カーネル監査の `LANDLOCK_ACCESS` を opt-in の段（`FANDHE_CONTAINER_TEST_KERNEL_AUDIT=1`）で照合し、opt-in なしは `audit-not-verified`（合格に数えない）。ESC-06 だけ `Deferred`（#2236・#2237）。試験の側が記録を作る経路（`record_landlock_denial`・`audit_mount_config_error` の直接呼び出し〔create_audited 経由に置換。#2480〕・子の pipe の `audit=` 行）は削除した（#2028。9 章の案 7 の結果。9.3） | `crates/core/tests/escape_suite.rs` |

本リポの #1834 から導かれる制約:

- `KILL_PROCESS` では終了するプロセス自身が記録を書けない。プロセス内の SIGSYS ハンドラ経由の `from_sigsys` は使えない
- `ERRNO(EPERM)` はユーザー空間へ何も報告しない
- `SECCOMP_RET_TRAP` は SIGSYS を捕捉・無視できるため、「強制終了」と両立しない

## 4. seccomp の拒否の配送方式の比較

評価軸は 6 章の表。ここでは各候補の内容と論点を示す。

- **(a) `SECCOMP_RET_USER_NOTIF` と supervisor の listener**: 対象の syscall を supervisor（コンテナごとの監視プロセス。CORE-1 と整合し、中央デーモンを要しない）へ転送し、supervisor が記録して `-EPERM` で応答する。ERRNO 側の 40 件に使えば ESC-03 の EPERM と両立する。`KILL_PROCESS` の 3 件には使えない（USER_NOTIF は強制終了を表さない。supervisor が SIGKILL を送ると終了シグナルが SIGSYS でなくなり ESC-06 の期待と食い違う）。論点: listener fd の受け渡し（子から supervisor へ UDS）、exec（SUP-6）の再適用ごとに別フィルタ・別 listener になること、応答の期限（REPAIR-5。無期限に対象を止めない）、supervisor クラッシュ時の対象の挙動（fd が閉じられれば `ENOSYS`。拒否は維持されるが `EPERM` とは異なる）、`pid` の PID namespace 変換、supervisor の常駐メモリ（SUP-2）と syscall レイテンシ、`DenyAction` に variant を足す公開 API の変更
- **(b) `SECCOMP_RET_TRAP` とプロセス内 SIGSYS ハンドラ**: **非推奨**。根拠は 3 点。(1) ハンドラが攻撃コードと同じプロセスで動き、記録を偽造・抑止できるため証拠にならない（`escape_suite.rs` 冒頭の方針）。(2) 一次資料のとおり SIGSYS は捕捉・無視でき、execve でハンドラは既定に戻る見込みのため（execve 後の挙動は未確認。`signal(7)` で確かめる）、イメージ任意の entrypoint には載せにくい。(3) #1834 の強制終了と両立しない
- **(c) カーネルの監査（`AUDIT_SECCOMP`）**: KILL 系を含め syscall・arch・pid が取れる見込みで、fandhe-container のクラッシュや改ざんの後も残る（SEC-4 の spec が求めるフェイルセーフ経路）。`audit_enabled` には依存しない（v6.12 の原文で確認済み。`audit-seccomp-reader.md` 2.2 章。#2237）。一方で、記録の読み取り権限、rootless での可否、コンテナ ID の欠落があり、`AuditSink` へは自前では届かない（auditd 等の別の読み手が要る）。3 件の `KILL_PROCESS` の syscall 情報を得られる唯一の候補になり得る
- **(d) 親が得る終了シグナルだけからの記録（`waitpid`）**: syscall 番号は得られない。SIGSYS はコンテナ内の `kill(SIGSYS)` でも同じになり、seccomp 由来と断定できない。親の側で syscall を推測して記録を作るのは監査の偽造になるため行わない。(c) の記録との突き合わせの補助としては使える。`AuditEvent::Seccomp` の型の制約により、単独で使うには新しいレコード種別が要る
- **(e) `SECCOMP_RET_TRACE` と supervisor の ptrace**: syscall 番号・引数が得られる見込みだが、ptrace の権限と scope、コンテナ内の `ptrace` 禁止との関係、tracer 不在時の `ENOSYS`、複雑さの面で不利と見込む（詳細は未調査）

**組み合わせ案（2026-10-15 採用。#2018）**: 3 件の `KILL_PROCESS` は (c) と (d)、40 件の `ERRNO` は (a)。#1834 の動作を変えずに全 43 件を覆う。(d) は (c) との突き合わせの補助にとどめ、親の側で syscall を推測した記録は作らない。

### #1834 と両立する方式

| 方式 | `KILL_PROCESS` の 3 件 | `ERRNO(EPERM)` の 40 件 |
| ---- | -------------------- | --------------------- |
| (a) | 不可 | 可（応答は `-EPERM`） |
| (b) | 不可（強制終了にならない） | 動作が `EPERM` でなくなる |
| (c) | 可（動作を変えない） | 可（`FILTER_FLAG_LOG` と `actions_logged` の指定が要る） |
| (d) | 可（補助。単独では不十分） | 不可（終了しない） |
| (e) | 不可 | 可（動作が変わる） |

## 5. Landlock の拒否の捕捉方式の比較

- **(L-a) カーネル監査**（`AUDIT_LANDLOCK_ACCESS` 系。ABI 7・Linux 6.15 の見込み。`landlock_restrict_self` のログ制御フラグの指定が要る）: クラッシュの後も残るが、読み手（auditd 等）が要る。本リポの Landlock 適用コードの変更範囲は小さい見込みだが、未確認
- **(L-b) プロセス内の `EACCES` 観測**（現行の `landlock_denial_record`）: ランタイム自身のプローブしか見えず、ワークロードの拒否は捕捉できない。DAC の `EACCES` と区別できない
- **(L-c) USER_NOTIF でファイル系 syscall を横取りして再判定する案、eBPF・fanotify**: 性能（全ファイル操作が往復）、TOCTOU、権限、依存の面で不利と見込む。eBPF は spec が将来案として挙げている点にも触れる（内容は spec を参照）
- **(L-d) 捕捉しない**: カーネルが未対応のホストでの縮退（6 章の判断へ）

## 6. 比較表

| 軸 | (a) USER_NOTIF | (b) TRAP | (c) カーネル監査 | (d) 終了シグナル | (e) TRACE | (L-a) Landlock 監査 | (L-b) EACCES 観測 |
| -- | -------------- | -------- | ---------------- | ---------------- | --------- | ------------------- | ----------------- |
| 必要な版・権限（rootless） | Linux 5.0。rootless 可の見込み（未確認） | 全版 | 監査有効化と読み出し権限が要る。rootless は不可の見込み | 全版 | ptrace の権限 | Linux 6.15 の見込み。読み出しは (c) と同じ | 全版 |
| SEC-4 の記録項目（syscall・パス・PID・時刻） | syscall・pid・arch・時刻 | 同左（偽造可能） | syscall・pid・arch（見込み） | シグナルと pid のみ | syscall・引数 | パス・アクセス種別（見込み） | パスのみ。帰属が曖昧 |
| コンテナ ID | supervisor が付与できる | 付与できる（信頼できない） | 付与できない（見込み） | 付与できる | 付与できる | 付与できない（見込み） | 付与できる |
| fandhe-container のクラッシュ・改ざん後に残る | listener が落ちると失う | 残らない | 残る | 親が落ちると失う | 失う | 残る | 失う |
| 中央デーモン不要（CORE-1） | 適合 | 適合 | 外部の読み手が要る | 適合 | 適合 | 外部の読み手が要る | 適合 |
| syscall レイテンシ | 往復が加わる | シグナル配送 | 小さい | なし | 往復が加わる | 小さい | なし |
| `unsafe` と依存 | `sys` の薄いラッパー（事前承認の範囲）。依存は不要の見込み | 同左 | 既存の `kernel_audit.rs` で足りる見込み | 不要 | `sys` のラッパー | `sys` のラッパー | 不要 |
| #1834 との両立 | 40 件のみ | 不可 | 全 43 件 | 補助 | 不可 | - | - |
| crate 境界 | core にフィルタ構築、supervisor に listener | - | core に読み手、または外部 | supervisor | supervisor | core | core |

「見込み」「不可の見込み」は一次資料で未確認の項目で、確定扱いしない。

## 7. 「100% 記録」を満たせない環境での挙動

対象の例: カーネル監査が無効なホスト、権限が足りない rootless、Landlock の監査に未対応のカーネル（6.15 未満の見込み）。

| 選択肢 | 内容 |
| ------ | ---- |
| 起動を拒否する（fail-closed） | seccomp の適用失敗時の挙動と揃う。環境によっては使えなくなる |
| 警告して続行し、縮退を状態に明示する | inspect・構造化ログ・記録に「記録の網羅が縮退している」と出す |
| 利用者の選択にする（opt-in / opt-out） | 厳格モードの既定を決める必要がある |

**推奨（暫定）**: rootless でも確実に使える層（USER_NOTIF など）は fail-closed、カーネル監査頼みの層は警告して続行し縮退を状態へ明示する。厳格モード（縮退を拒否する）は opt-in で選べるようにする。2026-10-15 にオーナーが採用した（#2018）。

## 8. 配線状況の一覧（マウント検証/API 層など）

| 呼び出し元 | 記録ヘルパ | 配線 | 追う issue |
| ---------- | ---------- | ---- | ---------- |
| supervisor の exec（`exec_target`・`entrypoint`・`rootfs_pivot` の mount） | `AuditSink` | 配線済み（`default_audit_sink`。#1594） | - |
| launch 経路のマウントの拒否 | mount 層 | pivot 前段の失敗の記録は #1815（closed）で対応。読み取り専用化・覆い（固定集合・config 由来）の適用失敗も、理由 `readonly_path_apply_failed`・`masked_path_apply_failed` で同じ経路に載せた（SEC-2・SEC-4。#2013）。マウント操作の失敗は環境起因（古いカーネル・LSM）と rootfs の内容起因を親が区別できず、記録漏れの方が過剰な記録より悪いため記録する（理由トークンは対象の検査の拒否と分ける）。記録に段のフィールドは無く、段は返る `ExecError.stage` に載る（フィールドの追加は #653） | - |
| `mounts[]` の bind mount | mount 層 | 未配線（検証済みの型への変換が先） | #1911（open）ほか |
| `mounts[].destination` の拒否（create・start の再検証） | `audit_mount_config_error`（mount 層・`path` なし） | CLI の create は `FileAuditSink` を直接使う（#2480）。plugin-cri の create は単一スレッドの間に作った `ControlAuditRelay`（#2484 の relay を共有）を使う。start の手順 5（`prepare_cgroup` の `load_resource_limits_audited`）と手順 8（`build_spec`）は supervisor の `rejection_audit`（relay）を使う（#2594）。非 Linux は記録先が無く記録しない | #2430（非 Linux） |
| seccomp・Landlock | `record_seccomp_denial`・`landlock_denial_record` | ERRNO 側と Landlock は配送経路が無い（本書の対象）。`KILL_PROCESS` 側は #2004 で補助の `exit_signal` レコードを本番 launcher の回収点に配線済み（正の記録はカーネルの `AUDIT_SECCOMP`） | #1835（本書）→ 実装は #2023〜#2028・#2004（9 章） |
| plugin 信頼検証（`AuditLayer::PluginTrust`） | `verify_candidate_audited` | CLI の plugin バックエンド（macOS・Windows の本番経路）に配線済み（#2013）。記録先は `FileAuditSink::open_in_state_root`。作れないときは `SinkFailed`（黙って捨てない。拒否は覆らない）。非 Linux では `FileStateStore` が未実装で記録先を作れず `SinkFailed`。レジストリ・spawn への配線は TASK-114 | TASK-114 |
| CLI・healthcheck | - | CLI は plugin 信頼検証の記録先を配線済み（#2013）。healthcheck は未配線 | #495（healthcheck。open） |
| コンテナ ID の付与 | `AuditRecord::container_id` | mount・exec_target・entrypoint は付与済み。plugin_trust は付与しない（検証はコンテナを特定する前にバックエンドを解決するために走り、特定のコンテナに属さないため。#2013）。seccomp は #2025 で付与済み、landlock は未配線 | #1618（closed。型のみ）。seccomp は #2025（実装済み） |

監査ログ・可観測性・エラー出力の統一は #653（TASK-98.2。open）が担う。本書は配送経路に限り、レコード形式の統一とは分ける。着手時に `git grep` と issue 検索で最新の状態を確かめる。

## 9. 実装 issue の分割（2026-10-15 起票。#58 配下）

粒度は 2h・1 PR・1 関心事を目安とする。各案の issue は表の右端の列。

| 案 | 内容 | crate | issue |
| -- | ---- | ----- | ----- |
| 1 | `DenyAction` の拡張と USER_NOTIF 用フィルタの構築（命令数の期待値の更新） | core | #2023（構築関数とテストは実装済み。本番は未適用） |
| 2 | listener fd の取得と受け渡し（`sys` のラッパー） | core・supervisor | #2024（launch 経路は実装済み。supervisor は `take_seccomp_listener` で取り出せる状態まで）・#2385（exec 経路の受け渡しは実装済み）・#2544（exec の filter を `USER_NOTIF` にして親が応答。9.4） |
| 3 | supervisor の listener ループ（期限・PID 変換・`record_seccomp_denial`・`EPERM` 応答） | supervisor | #2025（実装済み。start の経路で結線）・#2544（exec 経路の応答者を実装済み。9.4） |
| 4 | `KILL_PROCESS` 側の記録（親の終了シグナルとカーネル監査の突き合わせ。レコード型の拡張の要否） | core・supervisor | #2004（実装済み。判断は 9.1） |
| 5 | Landlock のカーネル監査対応（ABI 7 のログ制御フラグ）と縮退時の状態表示 | core | #2026 |
| 6 | 縮退時の挙動（起動拒否／警告）の実装 | core・supervisor | #2027（実装済み。7.1。CLI からの `--audit-policy` の受け渡しは後続） |
| 7 | `escape_suite.rs` の整備 | core | #2028（9.3。ESC-06 は残余。supervisor の relay 経由の mount 拒否は #2481 で結合試験を追加。パース時の destination 拒否は #2480 で本番の create 経路に配線） |

### 7.1 実装した挙動（#2027。SEC-4・TASK-41 追補。監査配送 6/6）

| 層 | 使えないとき | 実装 |
| -- | ------------ | ---- |
| 確実な層（seccomp の ERRNO 側 40 件を USER_NOTIF で supervisor が記録） | **起動を拒否**（`FailedPrecondition`、文言は固定の `the seccomp audit record path is unavailable`） | supervisor の入口（`require_seccomp_audit_sink`）が、記録先 `ControlAuditRelay` を作れなければ手順 3 より前に止める。応答者（ハブ）の無い構成も手順 4 で拒否する。listener の取得・受け渡し失敗は #2024・#2025 の fail-closed のまま |
| カーネル監査頼みの層（`KILL_PROCESS` の `AUDIT_SECCOMP` 3 件、Landlock の `AUDIT_LANDLOCK_*`） | **警告して続行**。縮退を 3 か所に出す | core の launcher が fork の前に `audit_log::assess` で評価する。(1) 構造化ログの 1 行（`core.audit` / `audit_coverage` / `degraded`）、(2) 監査記録（層 `audit_coverage`、縮退した層の理由トークン。1 launch につき最大 1 件）、(3) `state.json` の `launchIsolation.audit_coverage` と supervisor の inspect の `auditCoverage`。(2) を記録先へ書けなかったときは、固定の診断行（`core.audit` / `audit_coverage_record` / `failed`）が fd 2 に加えて supervisor のログ（`@supervisor-logs`）にも残り、その事実は `launchIsolation.audit_coverage.record = "failed"` に保存される（#2468・SEC-4・REPAIR-4。inspect の `auditCoverage.record` に `"failed"` として出る〔#2601〕。`null` は「記録された」保証ではなく、縮退なし・記録成功・旧記録を区別しない） |
| 厳格モード | 縮退（調べられなかった場合を含む）を**拒否**（`FailedPrecondition`、固定文言） | opt-in。supervisor の argv `--audit-policy strict`（既定 `best-effort`）。手順 4（cgroup の追記より前）と launcher（fork の前）の 2 か所で判定する |

縮退の判定に使う観測は、非特権で読める 3 点に限る。`/proc/sys/kernel/seccomp/actions_logged` に `kill_process` が無い（`seccomp_kill_not_logged`）、`/proc/cmdline` の `audit=0` 系（`kernel_audit_disabled_at_boot`）、`/proc/self/loginuid` が無い（`kernel_audit_not_built`。`CONFIG_AUDIT` なしのカーネル）、Landlock ABI 7 未満（`landlock_audit_abi_too_old`）。読めなかった観測は `unknown`（理由 `probe_failed`）とし、縮退と同じに扱う。procfs の読み取りは 4 KiB までに上限を設ける。出力は固定語彙だけで、`/proc/cmdline` などホスト由来の文字列は転記しない。

**残余（REPAIR-3）**: `kernel_audit_requested` は「観測できる範囲に否定する証拠が無く、記録を要求した」だけを意味し、「記録された」ではない。外部の読み手がいるか（居ないと記録は間引かれうる dmesg の 1 行しか残らない。`AUDIT_SECCOMP` は `audit_enabled` に依存せず、v6.12 の原文で確認済み。#2237）、exclude 規則と backlog 超過（非特権では観測できない）は、`AUDIT_GET` に `CAP_AUDIT_CONTROL` 等が要り最小権限集合（`privilege-separation.md`）を変えるため判定に使っていない。上記 3 点の観測の条件（`actions_logged` の語彙、`loginuid` が `CONFIG_AUDIT` で作られること、`audit=0` の効き方）は、v6.12 の原文で確認済み（`audit-seccomp-reader.md` 2 章。#2237）。CLI の `start` / `run` から `--audit-policy` を渡す配線は未実装（`--restart` と同じく supervisor の契約までで、後続 issue）。起動した後に relay や recorder が失われた場合は、従来どおり `unrecorded` の集計と構造化ログで、停止はしない。

**完了の条件**に含める: ESC-01・03・06・10 の `AuditExpectation::Deferred` を `Required` へ切り替える。ESC-07・08 が試験の側で作っている記録（`record_landlock_denial`、`audit_mount_config_error` の直接呼び出し）を、本番の配送経路が出した記録に置き換える。本番 sink の出力ファイルを親が回収して照合する形を含める。

達成状況（#2028。9.3）: ESC-01・03・10 は `Required` に切り替え、ESC-07・08 の試験側の記録は削除して本番の記録の照合に置き換えた。ESC-06 は **`Deferred` のまま**（#2236・#2237 の結論待ち）で、この条件は ESC-06 について未達である。

### 9.1 案 4（#2004）の判断と結果

- **正の記録はカーネルの `AUDIT_SECCOMP`**: 読むには `NETLINK_AUDIT` の `AUDIT_NLGRP_READLOG` の購読が要り、初期 user namespace の `CAP_AUDIT_READ` が必要。supervisor の承認済みの最小権限集合（`privilege-separation.md`）に含まれないため、プロセス内の読み手は作らず、auditd 等の外部の読み手に任せる（4 章 (c) と整合）。`CAP_AUDIT_READ` の付与は権限分離の設計変更でオーナー承認が要るため承認事項として残す
- **`SECCOMP_FILTER_FLAG_LOG` は不要**: `seccomp(2)` の Audit logging 節のとおり、`KILL_PROCESS` は `actions_logged` に載っていれば記録される。現行の適用経路（`prctl(PR_SET_SECCOMP)`）はフラグを渡せず、フィルタは変えない。**カーネルソース（`kernel/seccomp.c` の `seccomp_log` 等）での記録が出なくなる条件・pid の名前空間・rootless での記録有無の一次資料確認は未実施**（man ページ以外は未確認。#2027 の縮退判定は、確認できた観測だけを使い、できないものは 7.1 の残余とした）
- **補助の `exit_signal` レコード**: 本番 launcher の回収点（`ContainerChildProcess` の `wait` / `terminate`）が SIGSYS の終了をちょうど 1 回、層 `exit_signal`（`AuditEvent::ExitSignal`。シグナルと回収側の PID namespace の対象 pid だけを持つ）で記録する。コンテナ内の `kill(SIGSYS)` と区別できないため seccomp 由来とは断定せず、syscall・arch は型として持たない（親の側で syscall を推測した記録は作れない）
- **縮退**: カーネル監査を使えない環境では補助レコードだけが残る（syscall は残らない）。検出と表示は #2027（7.1）
- **複数スレッド・rootless での配送（#2236 で実装）**: supervisor は監視の時点で複数スレッドのため `FileAuditSink` の隔離（fork）が使えず、rootless では代替のカーネル監査送信（`CAP_AUDIT_WRITE` が要る）も失敗する。そこで `ControlAuditRelay` が `ExitSignal` の固定長の枠（タグ 0x82。signal 1 バイトと target_pid 4 バイト。復号は長さの厳密一致と値の範囲検査で、壊れた枠は記録にしない）も運ぶようにし、supervisor の入口が単一スレッドの間に作った relay を `ProductionLauncherBuilder::exit_audit_sink` で launcher の**回収点だけ**の記録先に渡す。launch の時点の記録（監査網羅の縮退・pre-pivot の違反）は単一スレッドで出るため従来どおり `FileAuditSink` のままにする（relay は理由つきの `Mount` 等を運べず、sink 全体を差し替えると退行するため）。start の検証（bind・sysfs の拒否）の記録先は #2481 で別に扱う（次の項目）。回収点は `AtomicBool` で 1 回だけ記録し、relay の待ちは `RECORD_WAIT_LIMIT` までで、応答が無ければ helper を SIGKILL して以後は `Unavailable`（REPAIR-5。終了状態の返却は変えない）
- **start の bind・sysfs の拒否の配送（#2481 で実装）**: `claim_start` の検証は作業スレッド `supervisor-start` で走り、入口スレッドが待つ間はプロセスが複数スレッドになる。このため launcher の `audit_sink`（`FileAuditSink`）は主経路を試せず、rootless では代替経路も失敗して mount 層の拒否が `@audit.log` に残らなかった（`claim_start` は記録の結果を捨てる）。そこで `ControlAuditRelay` が理由なしの `Mount` の固定の枠（タグ 0x83。path_present 1・path_len 2・original_len 8 の後にパス本体を生バイトで運ぶ。復号は長さの厳密一致・保持長 4096 以下・`AuditPath` の切り詰めの整合を検査し、矛盾する枠は記録にしない。helper は本体を確保する前に長さを上限と照合する）を運ぶようにし、supervisor の入口が `ProductionLauncherBuilder::rejection_audit_sink` で start の検証の拒否だけの記録先に relay を渡す。relay が記録できなかったときは、記録先を包む `ObservedRejectionSink` が固定語彙の構造化ログ（`rejection_audit_record_failed`・エラーコード）を 1 行出し、拒否の結果は変えない。結合試験は `crates/supervisor/tests/start_bind_audit_relay.rs`
- **`AuditEvent` の種類ごとの relay の扱い（#2481）**: relay で運ぶのは下表の「運ぶ」だけで、運ばない種類は `InvalidArgument` で失敗が見える（黙って捨てない）。運ばない種類は、記録するのが単一スレッドの段か別プロセスのため、`FileAuditSink` で足りる。`audit_sink` を丸ごと relay へ差し替えない（差し替えると理由つきの `Mount` や縮退の記録が `InvalidArgument` で落ちて退行する）

  | 種類 | relay | 記録する段・スレッドの状況 | 使う sink |
  | ---- | ----- | -------------------------- | --------- |
  | `ControlPeer` | 運ぶ | 制御チャネルのサーバスレッド（複数スレッド） | relay |
  | `Seccomp` | 運ぶ | seccomp ハブのスレッド（複数スレッド） | relay |
  | `ExitSignal` | 運ぶ | launcher の回収点（監視スレッド。複数スレッド） | relay（`exit_audit_sink`） |
  | `Mount`（理由なし） | 運ぶ | start の bind・sysfs の拒否（作業スレッド。複数スレッド） | relay（`rejection_audit_sink`） |
  | `Mount`（理由つき） | 運ばない（理由の静的トークンは開いた語彙で、復号側で閉じた表へ戻せない） | launch・create・exec の拒否（単一スレッド） | `FileAuditSink` |
  | `Landlock`・`PluginTrust`・`ExecTarget`・`Entrypoint` | 運ばない | 単一スレッドの段（launch の pre-pivot・exec の親・plugin 検証） | `FileAuditSink` またはカーネル監査 |
  | `AuditCoverageDegraded` | 運ばない | launcher の launch（入口スレッド。単一スレッド）。`start_entry_audit_record_failed.rs` が照合済み。restart の再 launch は複数スレッドでは本番 launcher が拒否する（#2043） | `FileAuditSink`（`audit_sink`） |

- **supervisor の exec コマンド（#2236 で実装）**: exec worker が回収したコマンドの終了状態を pipe の 1 行で返す際に、コマンドの PID も載せる（`ExecOutcome::command_pid`。worker は `pid_for_children` だけをコンテナの PID namespace へ移すため、worker・親と同じ PID namespace の値）。親（単一スレッドの exec 専用プロセス）が、コマンドが SIGSYS で終了した（`Signaled(31)`）ときだけ層 `exit_signal` を 1 件記録し、結果は `AuditedOutcome::exit_audit` で返す（違反の記録の `audit` とは別の欄）
- **残余（未実装。REPAIR-3）: PID 1 以外の子孫と、exec コマンドの子孫の SIGSYS 終了は親から観測できない**。コンテナ内の子孫は同じ PID namespace の中の親が回収し、孤児は namespace 内の init（PID 1）に再親付けされる（`find_new_reaper` は同じ namespace の中で探すため、外にいる supervisor の child subreaper には届かない）。承認済みの最小権限集合（`privilege-separation.md`）の範囲に親が得る手段が無い（proc connector は `CAP_NET_ADMIN`、`PIDFD_INFO_EXIT` は Linux 6.15 以上かつ短命なプロセスの取りこぼしがあり「確実に」を満たせない、コンテナ内の init shim は PID 1 の契約を変える設計変更）。この範囲の正の記録はカーネルの `AUDIT_SECCOMP` が担う（読み手は #2237）。追跡 issue の起票と、spec 側（ESC-06・SEC-4 の受け入れ範囲）の見直しの要否はオーナー判断
- **読み手と `CAP_AUDIT_READ` の判断材料**: 記録されない条件・rootless・選択肢 A/B は `audit-seccomp-reader.md`（#2237・オーナー承認待ち）。上の「カーネルソースでの確認は未実施」は同書 2 章で確認済み（v6.12）
- **実機試験**: `crates/core/tests/seccomp_kill_audit.rs`（`--ignored`。root と auditd が前提。`AGENTS.md` 参照）

### 9.2 保証範囲（ワークロードの追加フィルタ。#2404 の指摘）

- 既定フィルタは Docker / OCI 互換のため `seccomp(2)` と `prctl(PR_SET_SECCOMP)` を許可する（`NO_NEW_PRIVS` は設定済みで、特権なしで追加フィルタを載せられる）。カーネルは複数フィルタの結果を `KILL` > `TRAP` > `ERRNO` > `USER_NOTIF` > `TRACE` > `LOG` > `ALLOW` の優先順位で採るため、ワークロードが自分で `kcmp` 等に `ERRNO` を返すフィルタを載せると、`USER_NOTIF` の通知は出ず supervisor の記録も残らない
- **契約**: 本経路（SEC-4）が記録するのは、ランタイムが載せた最終フィルタが `USER_NOTIF` で拒否した syscall だけである。ワークロード自身が追加した制限による拒否は分離違反ではなく、ランタイムの監査対象に含めない。いずれにせよ拒否は保たれ（許可に倒れない）、失われるのは記録だけ
- **未採用の案**: `seccomp` / `prctl(PR_SET_SECCOMP)` の一律禁止、または両方を `USER_NOTIF` にして追加フィルタの導入を監査する案。前者は Chrome のサンドボックスや systemd 系など追加フィルタを使う正規のワークロードを壊し、Docker 既定との互換を大きく変える。後者は通知側がフィルタ本体のポインタを読む TOCTOU を避けられない。どちらもオーナー判断が要るため実装していない

### 9.3 案 7（#2028）の結果と残余

| ケース | 層 | 本番の配送経路 | 照合する証拠 | 段 |
| ------ | -- | -------------- | ------------ | -- |
| ESC-03 | seccomp（ERRNO 側） | `UserNotif` 版の filter ＋ `NEW_LISTENER` → `SCM_RIGHTS` の受け渡し（本番と同じ検証）→ 応答者が `record_seccomp_denial_for` → `ControlAuditRelay` → `FileAuditSink` → `@audit.log` | seccomp 層の行がちょうど 1 行（`mount` の syscall 番号・arch・攻撃した子の pid・コンテナ ID） | 既定の `--ignored` の段（root 不要）。応答者は試験側の応答ループで、本番の `SeccompNotifyHub` をコンテナ経由で通す同じ攻撃の照合は `supervisor_bin_real` のシナリオ E（実機前提・人間が実行。作成時は未実行。#2482） |
| ESC-08（bind の元） | mount | `create` → `start` → `validate_bind_mounts` → `audit_bind_mount_error` → `ProcessLauncher::rejection_audit_sink` → `FileAuditSink` → `@audit.log` | mount 層の行が要求ごとに 1 行（元が rootfs・bundle・状態ルートの計 3 行・コンテナ ID）。`start` は `InvalidArgument` で拒否され launcher に到達せず、状態は Created のまま | 既定の `--ignored` の段 |
| ESC-01・07（landlock 帰属）・10 | landlock | カーネル監査 `AUDIT_LANDLOCK_ACCESS`（ABI 7。core は `LOG_SAME_EXEC_OFF` を渡さない） | `/var/log/audit/audit.log` のケース開始後の追記で、`blockers=` の要素（`fs.write_file` / `fs.read_file` / `fs.make_reg`）が完全一致し、同じイベント連番の `SYSCALL` の `pid` が攻撃した子のホスト pid で、時刻が開始以降 | opt-in の段（root か audit ログの読み取り権限・auditd・ABI 7） |

試験の側が書く部分は 2 つだけである。(1) ESC-03 の応答ループ（core の公開 API だけで組む。supervisor の `SeccompNotifyHub` の試験ではなく、それは `crates/supervisor/tests/seccomp_notify_audit.rs`。また hub をコンテナ経由で通す照合は `crates/supervisor/tests/supervisor_bin_real.rs` のシナリオ E〔#2482〕）。(2) ESC-08 の launcher（`rejection_audit_sink` を返すだけの最小実装。本番の `ProductionLauncher` は構築にホストの前提〔cgroup 等〕を要するため使わず、sink の転送は `launcher.rs` の単体試験が担う）。子の記録（pipe）の `audit=` 行は拒否する。

**残余（REPAIR-3。実装済みを装わない）**:

- **ESC-06（`KILL_PROCESS` の 3 件）は `Deferred`**: `USER_NOTIF` に載らず、補助の `exit_signal` は本番 launcher の回収点が出して試験の入口（`spawn_container_probe`）では作られず、正の記録はカーネルの `AUDIT_SECCOMP`（読み手が無い。#2237）。`Required` への切り替えは #2237（`AUDIT_SECCOMP` の読み手と `CAP_AUDIT_READ`）の結論の後に行う。#2236 の側は、複数スレッド・rootless での `exit_signal` の配送と exec コマンドの記録を実装した（9.1。実機の照合は `production_launcher` のシナリオ Q〔#1621 で人間が実行〕）。子孫の SIGSYS 終了は親から観測できず未達のまま
- **`create` のパース時の destination 拒否（遡り・`/`・相対 `..`）は、CLI の create だけ本番で監査される（#2480）**: `create_audited` / `create_with_image_audited` が `audit_mount_config_error` を通し、`FileAuditSink`（`<状態ルート>/@audit.log`）へ mount 層で 1 件記録する（`esc-08-config-destination` は `Required` で 3 行を照合。結合試験は `tests/create_mount_audit_delivery.rs`・`crates/cli/tests/binary_entry.rs`）。plugin-cri の `CoreLifecycleRuntime::create` と start の TOCTOU 再検証（create 後に書き換えられた destination の拒否）も #2594 で配線した。新しい中継は作らず、既存の `ControlAuditRelay` が理由なし・`path` なしの `Mount` を運ぶ（plugin-cri は `main.rs` が単一スレッドの間に作った relay を create の記録先として共有する。tokio のマルチスレッドでは `FileAuditSink` の fork 隔離が使えず、rootless では `SinkFailed` になるため）。start は手順 5 の `load_resource_limits_audited` と手順 8 の `build_spec` が supervisor の `rejection_audit` へ記録し、手順 5 で拒否されれば手順 8 へ進まないので 1 回の start で高々 1 件。CLI と plugin-cri の start は同じ supervisor を通るため両方に効く。残余（REPAIR-3）: 非 Linux は記録先が無い（#2430 の判断待ち）。plugin-cri の bin から実 supervisor を通した照合は実機前提（#850・#2062・#1621）で未実施で、本番の `prepare_cgroup` の結線はソース構造の単体試験で固定している
- **supervisor の `start` 経由の bind の元の拒否の監査は、結合試験までを照合済み（#2481）**: supervisor は launcher の launch の時点の監査 sink に `FileAuditSink`（`build_audit_sink`）を渡し、start の検証の拒否の記録先（`rejection_audit_sink`）・回収点の `exit_signal` 専用の記録先（`exit_audit_sink`）・seccomp ハブ・制御チャネルには `ControlAuditRelay` を渡す。`crates/supervisor/tests/start_bind_audit_relay.rs` が、公開の `run_start`（作業スレッドで `claim_start`）から relay 経由で `@audit.log` に mount 層 3 行が届くことを照合する（relay を使わず `FileAuditSink` のままだと 0 行になることも確認済み）。残余: 本番の `ProductionStartDeps::build_launcher` の結線は core の単体試験とソース構造の試験で固定しており、本番 bin から実コンテナまでの通し（委譲 cgroup 等の実機前提。人間担当の #1621 の範囲）での照合は未実施
- カーネル監査の段の実機での実行と記録は人間担当の #206。この環境（AppArmor が非特権 user namespace を制限）では、分離を要するケースを含め実機部は実行できていない

### 9.4 exec 経路の応答者（#2544。SEC-4・SUP-6・REPAIR-5）

exec で起動したコマンドの ERRNO 側 40 件の拒否を記録先へ届けるため、exec の filter を `USER_NOTIF` で載せる。通知に誰が応答するかを次の 2 案から選んだ（なお #2524 は同じスコープの起票で、本 issue が実装した）。

| 案 | 内容 | 判断 |
| -- | ---- | ---- |
| A | supervisor の `SeccompNotifyHub` へ exec の listener を 2 段目の `SCM_RIGHTS` で転送する | **後続**。ハブは供給元を 1 本しか持たず（`attach_with` が先頭で `quiesce()` して直前の監視を畳む）、複数 listener の同時監視への再設計が要る。supervisor から exec 専用プロセスへの経路が本番に無い（`run_command_with_pidfd` の本番の呼び出し元〔CLI・healthcheck。#492・#495・#1314〕が未配線）。転送先の UDS の所有者・peer credential 検証の設計も要る |
| B | exec の親に per-exec の `SeccompNotifyHub` を持たせ、記録先に単一スレッドのうちに fork した `ControlAuditRelay` を渡す | 不採用。`ControlAuditRelay::spawn` は具体型 `FileAuditSink` を取り `&dyn AuditSink` と噛み合わない。exec ごとに helper を fork する。ハブのスレッド 2 本を `audit_worker_result`（`Threads: 1` 必須）より前に必ず畳む生存期間管理が要り、畳めなければ rootless で記録に失敗する |
| **C（採用）** | exec の親が単一スレッドで、worker の終了待ちと listener の待ちを交互に回して同期に応答する | exec の親は fork と `FileAuditSink` の主経路の 2 か所で `Threads: 1` を要するため、スレッドを作らずに済む。期限つきの記録 API（`AuditSink::record_until`）が既にあり、`FileAuditSink` は主経路・代替経路・失敗通知の全段を絶対期限で切る。exec の既存の監査（`exec_target`・`entrypoint`・`exit_signal`）も「worker の結果を受けた親」が同じ `audit` に記録しており、listener の寿命（exec の寿命）とも一致する |

**fail-closed の 2 段**: (1) fork 前: 本番の `ListenerPolicy::Respond` は応答者の構成を値で持ち、filter の届け方（`UserNotif`）もそこから決まる。 (2) 稼働中: `wait` / `receive` の失敗、応答の送信不能（上限つき再送の後）では listener を即座に drop してカーネルに `ENOSYS` で解かせる。worker の回収は通常どおり続け、`ExecOutcome::seccomp_audit` に `Lost` と集計を載せる（start 経路の「起動後の喪失で停止しない」と揃える）。受け渡し自体の失敗は #2385 の fail-closed のまま（worker を止めて回収し exec を拒否）。期限（REPAIR-5）: 記録は応答期限（既定 1 秒・最大 5 秒）で打ち切って必ず応答し、ループは反復ごとに worker の終了と exec の全体期限を確認する。

**残余（REPAIR-3。実装済みを装わない）**:

- ハブは期限超過で応答した後も recorder が記録を続ける（`late`）が、この応答者は応答期限で記録を打ち切る（`unrecorded`）。「記録 → 応答」の順序は保つ。`FileAuditSink` の通常の書き込みはミリ秒で実害は小さい
- 通知は直列に処理するため、通知が詰まると 1 件ごとに最大で応答期限だけ後続の通知が待つ。洪水はトークンバケットで記録を間引き、間引いた分は待たずに応答する
- 期限の保証は `audit` が `record_until` を期限どおりに実装することに依存する（trait の既定実装は期限切れでなければ `record` に委ねる）。`run_command_with_pidfd` の `audit` の契約に反映した
- コマンドが終了した後も残る子孫（exec の子 cgroup は worker の回収後に削除される）が拒否された syscall を発行しても、listener が閉じた後は `ENOSYS` になる（`EPERM` ではない。許可には倒れない）
- 本番の呼び出し元（CLI・healthcheck）の配線は従来どおり範囲外（#492・#495・#1314）。root を要する `crates/supervisor/tests/exec.rs` の実行は人間担当（#1621）
- pid の変換は start と同じ（通知の pid は親の PID namespace の TID、`/proc/<tid>/status` の `NSpid` 末尾がコンテナ内の pid。worker は `pid_for_children` だけをコンテナの PID namespace へ移す）。ワークロードが自分で追加した filter による拒否は記録対象外（9.2 と同じ契約）。`KILL_PROCESS` の 3 件は従来どおり（9.1・9.3）

## 10. セキュリティ上の論点

- USER_NOTIF の応答に `SECCOMP_USER_NOTIF_FLAG_CONTINUE` を使わない。通知の cookie を `NOTIF_ID_VALID` で検証し、`pid` の PID namespace を変換する
- listener の応答には期限を設ける（REPAIR-5）。listener 不在でも拒否が維持される（`ENOSYS`）こと
- 記録内のパスは untrusted。改行・制御文字は書き込み側（`file_writer`・カーネル監査の hex 化）のエスケープを前提にする
- 記録の件数の上限・レート制限（無制限のログによる DoS）
- プロセス内ハンドラの記録を証拠にしない。親の側で syscall を推測した記録を作らない
- カーネル監査の記録の読み取り権限と、listener fd の受け渡し（UDS）の所有者・権限の検証（PLUG-12 と同系統）
- 新規依存は不要の見込み（`sys` の薄いラッパーで足りる）。必要と判明したら承認事項として報告する

## 11. ユーザーへの確認事項と spec 側の課題

**設計の承認事項**（本リポ側）:

1. seccomp の方式の選択（4 章）と Landlock の方式の選択（5 章）
2. 100% を満たせない環境での挙動（7 章）
3. `DenyAction` と `AuditEvent` の公開 API 変更の要否（syscall 必須の制約）
4. `AuditSink` トレイトの変更の要否（現状の `record(&AuditRecord)` で足りる見込みだが未確認）

2026-10-15 にオーナーが 1〜4 を承認した（#2018）。1・2 は 4 章の組み合わせ案と 7 章の推奨を採用し、3・4 は上の方式の実装に必要な範囲で変更を認めた。

**spec 側の課題**（2026-10-15 に spec へ反映済み。fandhe-container-spec#21）:

- SEC-4 の「100% 記録」: 期待に、記録経路が利用できる環境で満たすこと、4 章の配送経路、カーネル監査を使えないホストでは記録できない拒否の種別を明示して縮退し厳格モードを opt-in で選べること（7 章）を追記した
- PoC-9 の監査ログ設計（`03-poc/security-isolation/`）: seccomp の通知に `SECCOMP_RET_TRAP` とシグナルハンドラを使う設計時点の案があった。PoC の記録として本文は残し、実装の方式（4 章）と異なる旨の追記を足した。TASK-41 の内容にも配送経路と縮退を追補した

非 Linux の記録経路（Windows の主経路の隔離・代替経路）は [audit-non-linux.md](audit-non-linux.md)（#2430・設計ドラフト・判断シート・オーナー承認待ち）で扱う。
