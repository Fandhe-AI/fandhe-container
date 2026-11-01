# restart の再 launch を単一スレッドで成り立たせる設計記録

TASK-159.3 追補・#2043・SUP-3・CORE-1・CORE-5・REPAIR-3・REPAIR-5。

## 背景

core の本番 launcher（`ProductionLauncher`、`LaunchMode::SelfBounded`）は fork の前に `/proc/self/status` の `Threads:` が 1
であることを要求する（fork 時点で他スレッドがロックや fd を握っていない前提。CORE-5・SEC-1）。start の手順 8 は入口スレッドが
直接呼ぶことで満たしていた（#1819）。一方、restart の再 launch は専用スレッド `fandhe-relaunch` の上で呼ばれ、さらに常駐スレッド
（`supervisor-stderr`・`control-channel`、捕捉・seccomp 通知のスレッド）が残っていたため、本番では必ず `FailedPrecondition` で拒否され、
`RelaunchFailed` → `Stopped` の記録 → 非 0 終了（fail-closed）になっていた。

## 比較した方式

| 案 | 内容 | 判断 |
| -- | ---- | ---- |
| A（採用） | 常駐スレッドを一時停止し、監視ループのスレッド（入口スレッド）で直接 relaunch する | start の手順 8 と同じ型で、起動経路が 1 本のまま |
| B | 単一スレッドの helper プロセスで relaunch する | 起動経路が 2 本になる。rootfs fd・pidfd・seccomp listener・出力 pipe・netns holder の受け渡し（SCM_RIGHTS）と subreaper の親子関係の再設計が要る |
| C | core の fork 方式を変えて複数スレッドから fork できるようにする | `fork_single_threaded` の不変条件（CORE-5・SEC-1）に手を入れ、影響が core 全体に及ぶ |

## 構成

- `Relauncher::launch_mode()`（既定 `CallerBounded`）を追加し、`LauncherRelauncher`・`ControlledRelauncher` は内側の launcher から転送する
  （転送しないと黙って `CallerBounded` へ降格する。#1816 と同じ罠）。
- `supervise_with_restart` は `SelfBounded` の relauncher を `fandhe-relaunch` スレッドを作らずに直接呼び、期限は launcher 自身が守る。
  未回収ハンドル（`take_stranded`）は従来どおり `LateOrphans` へ積む。
- 再 launch の時点に存在しうるスレッドと扱い:

  | スレッド | 扱い |
  | -------- | ---- |
  | `fandhe-relaunch` | `SelfBounded` のときは作らない |
  | `control-channel`（accept ループ） | `PausableServer::pause` / `resume`。listener は bind したまま保持（unlink も rebind もしない） |
  | `supervisor-log-*`・`supervisor-log-flush`（捕捉） | 既存の `CaptureHub::quiesce` |
  | `seccomp-notify`・`seccomp-audit-rec` | 既存の `SeccompNotifyHub::quiesce` |
  | `supervisor-stderr` | `StderrSink::quiesce` / `resume`。止めている間の行は上限つき（`QUEUE_CAPACITY`）のバッファへ溜め、再開後に順に書く |
  | `fandhe-terminate`（`LateOrphans`） | 失敗・停止経路だけ。変更なし |
  | `healthcheck-*` | 参加者に足さない（#2953 で結線済み）。周期実行のスレッド `healthcheck-periodic`（と probe の一時スレッド `healthcheck-probe`）は monitor の 1 回の呼び出しの間だけ回り、monitor が戻る前に期限（3 秒）つきで止めて join する。再 launch は monitor が戻った後なので居ない。期限内に止まらず残ったスレッドは `thread_settle` が検出して `RelaunchFailed`（fail-closed）。setns を伴う exec 自体は別プロセスの exec 専用 helper（`healthcheck-exec-helper.md`） |

- 順序: 制御チャネルの停止（外側の `ControlledRelauncher`）→ 捕捉・seccomp の quiesce → stderr の quiesce（最後。上の quiesce の報告が
  stderr へ出るため）→ スレッド数が 1 に落ち着くまでの有界の待ち（`thread_settle`、上限 1 秒）→ `launcher.launch(残り時間)` →
  stderr の再開（RAII）→ 新プロセスの出力・listener の attach → 制御チャネルの再開。
- 止められない（期限内に落ち着かない）ときは launch せずに失敗にする（fail-closed）。core の `Threads: 1` の検査は弱めない・迂回しない。
  supervisor 側にスレッド数で拒否する検査は置かない（libtest の試験では常に複数スレッドのため、本番だけ opt-in の
  `StartDeps::single_thread_relaunch` / `LauncherRelauncher::with_single_thread_launch` で有効にする）。

## 制御チャネルの扱い

- pause の間の接続は backlog に積まれ、resume の後に同じ検証（`SO_PEERCRED`・固定長 frame・期限）で処理される。
- pause 中に届いた CancelRestartRequest は resume の後に処理されるため、`Active` の状態で `ContainerRunning` になり得る。CLI は
  これを記録の読み直しとして扱う（`stop_delete`）。client は `ECONNREFUSED`・`ENOENT` を再試行する。
- accept の poll 間隔（100ms）が停止の待ちに載り得る。restart レイテンシ（SUP-3 の中央値 100ms）の実測は #491（人間担当）で、
  短縮や起床の仕組みはその結果を見て判断する。

## 判断: `legacy_tiocsti` の警告を再出力しない

core は launch のたびに 1 行出す（`exec/launch_intermediate.rs`）。restart の再 launch もこの入口を通るため、core 側では
launch ごとに出る。ただし CLI の通常経路では `start_client` が supervisor の stderr を `Stdio::null()` にし、core の警告は
AF_UNIX socket 以外へ書かれないため、再 launch ごとの警告は保存先に**残らない**（未記録範囲。REPAIR-3・REPAIR-4）。
supervisor 側は初回 start の要約 1 回だけにし、再 launch ごとの警告の保存は行わない（必要になったら別 issue で扱う）。

## 残余・再評価の条件

- pasta・netns holder 構成（ユーザー定義の network）での restart の成立は未確認（#341・#3331）。
- `on-failure`・`always` の再起動ストーム抑制（指数バックオフ）は既存の残余のまま。
- 実機（Linux 6.12 以上）での確認は `crates/supervisor/tests/supervisor_bin_real.rs` のシナリオ C（`--restart on-failure:1`）。
  本記録の作成時点のローカル環境には user manager が無く未実行で、CI の `platform-ci`（ubuntu）で確認する。
- 再評価: poll 間隔が #491 の実測で問題になったとき、healthcheck の定期実行の停止が期限内に終わらず再 launch が止まる事象が実測で出たとき（#2953 で結線済み）、core が launch の単一スレッド要求を
  変更したとき。
