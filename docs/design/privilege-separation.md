# 権限分離方式の比較と必要最小権限（方式承認済み）

sudo＋pty に頼らない権限昇格方式（setuid バイナリ・capability ベース）の選択肢と、本リポが rootful で必要とする最小権限を整理する（SUP-14）。

> **位置づけ**: 方式は承認済み（オーナー判断 2026-10-10・[#1454](https://github.com/Fandhe-AI/fandhe-container/issues/1454)）。(c) 特権ランチャー＋ ambient capability を既定とし、xattr 非対応の環境に限り (a) setuid root を代わりに認める。どちらも失敗したら fail-closed にし、sudo へは戻らない。`unsafe` の syscall ラッパーは `crates/supervisor/src/sys`（Linux 版）に置く（事前承認の範囲）。ランチャーは `crates/supervisor` の bin（`fandhe-container-launcher`）とし、実装は #1719 で行う。9 章を採用方式として更新した。7 章に supervisor の入口の dumpable=0 を追記した（SUP-14 の 2026-10-16 明記・#2102）。縮退の適用と読み戻し検証は TASK-171.1.3（#1475）で `privilege::elevate` として実装済みで、境界は 10 章末尾の補足を参照。要素 (B)（セッション切り離しと pty 非経由の検証）は TASK-171.2（#537）で `privilege::detach_session` として実装済み（5 章 1・10 章末尾の補足）。

- 対象ビヘイビア: SUP-14（Must・確定。関連: SUP-1・CORE-1・CORE-5・CORE-6・SEC-1・SEC-5・PLUG-11・ERR-1・REPAIR-5・D-19）
- タスク: TASK-171（MS-9・G12・担当: 共同）。本書は TASK-171.1.1（#857。親 #536・#535）
- 後続: #858（TASK-171.1.2。成果物 `crates/supervisor/src/privilege.rs`〔仮称〕）・#537（TASK-171.2 pty 非経由の起動経路）・#538（TASK-171.3 SIGKILL 継続テスト。`crates/supervisor/tests/privilege.rs` で `script` による模擬として実装済み）・#539（TASK-171.h1。実装後のセキュリティレビュー・実機検証。人間担当）
- 出典: `docs/spec/04-behavior/api-supervisor.md` の `SUP-14`、`03-poc/supervisor-model/README.md` の発見事項 1（PoC-17）、`05-tasks.md` の TASK-171、`api-runtime-core.md` の `CORE-6`、`security-isolation.md` の `SEC-1`・`SEC-5`（submodule リビジョン `984f8a2`。7 章の supervisor の dumpable=0 は SUP-14 の 2026-10-16 明記〔spec#23・リビジョン `6a3e546`〕による）。外部事実の出典は 3 章末尾に URL と確認日（2026-10-06）を付す

## 1. 問題の整理

PoC-17 発見事項 1: コンテナごとに `sudo <supervisor> run ...` を起動すると、`sudo`（`use_pty` 設定下）が子を fork して pty 経由で中継する。この `sudo` を `SIGKILL` すると pty のクローズに伴うシグナル配送で、子孫（supervisor・ランタイム・コンテナ本体）が巻き添えで終了した。PoC の暫定対策は「1 回の `sudo` の中で `setsid` により独立セッションとして起動する」ことで、本番対策は未実装である。

対策は独立した 2 要素に分けて考える。

| 要素 | 内容 | 選択肢 |
| ---- | ---- | ------ |
| (A) 権限の取得手段 | 非特権ユーザーが必要な権限をどう得るか | setuid か capability（2 章） |
| (B) セッション切り離し | supervisor が呼び出し元の制御端末・セッションに紐づかない | `setsid`・制御端末なし・標準入出力が pty を指さない |

- **(B) はどの方式を選んでも必須**である。「capability 方式を選べば SUP-14 が解決する」わけではない。(B) の実装は #537（TASK-171.2）の範囲で、ランチャーの入口に実装済み（5 章 1）
- (A) は pty を介さないことで、昇格プロセスの kill が子孫に波及する経路そのものを除く。(B) は呼び出し元端末の消滅（SIGHUP）に対する独立性を与える

## 2. 前提と制約

- 中央の常駐デーモンを持たない（CORE-1・D-19）。「常駐特権デーモンへ依頼する」案は取らない
- 対象は Linux ネイティブの rootful 経路。macOS・Windows は VM 内で動くため本書の対象外（要確認事項。12 章）
- rootless（CORE-6）は特権昇格が不要で本問題の対象外だが、PoC では AppArmor 制約により rootless 経路が未検証である（rootless-network.md の 1 章と同じ事情）
- コンテナ側の制限段（cgroup 参加 → rlimit → capability 削減 → `PR_SET_NO_NEW_PRIVS` → Landlock → seccomp → exec。`crates/core/src/exec/stages.rs`）が `no_new_privs` を立てる。`no_new_privs` は以後の exec での setuid・file capability による昇格を無効にするため、**昇格は制限段より前（supervisor 起動時点）に済ませる**必要がある。コンテナ内プロセスが昇格経路を再利用できないことは SEC-1・CORE-5 と整合する
- 新規依存は前提にしない。capability 操作は `crates/core/src/sys.rs` の自前 syscall ラッパー系統（`cap_get_thread`・`cap_set_thread`・`cap_bounding_drop`・`cap_ambient_clear_all`・`set_no_new_privs`）で足りる見込みで、依存が必要になれば承認事項として報告する

## 3. 選択肢

| 案 | 内容 |
| -- | ---- |
| 現状の暫定 | `sudo`＋`setsid`（PoC-17）。sudo の存在・sudoers 設定・pty 割り当てに依存し、本番対策ではない |
| (a) setuid root バイナリ | root 所有・setuid ビットの小さなバイナリ。起動直後に必要最小の集合へ縮退し、supervisor を起動する |
| (b) file capabilities | `setcap` でバイナリに必要な capability を付与する。uid は呼び出し元のまま |
| (c) 特権ランチャー＋ambient | file capability を持つ小さなランチャーだけが昇格し、必要最小の集合を ambient に載せて、capability を持たない supervisor を exec する。(a)(b) の配置バリエーション |
| (d) rootless | 特権なしの基準線。CORE-6 の範囲で、rootful の機能（bridge 等。NET-9）とは等価でない |

### 比較

| 観点 | (a) setuid | (b) file caps | (c) ランチャー＋ambient |
| ---- | ---------- | ------------- | ----------------------- |
| 利点 | 配布が単純（chmod のみ）。xattr 非対応の FS でも動く。cgroup・ファイル所有の都合で uid 0 が要る操作も通る | uid 0 にならず、付与した集合だけを得る | supervisor 本体にはファイル属性が不要で、更新・コピー・再配置の自由度が高い。特権付きバイナリが最小になる |
| 欠点 | 常に完全な root。縮退を誤ると全権限を保持する。環境変数・fd・cwd の入口検証が必須 | xattr 依存（コピー・tar・一部 FS で失われる）。付与対象バイナリが supervisor 本体だと攻撃面が大きい | ambient は子孫へ継承されるため、ヘルスチェック exec・ログ処理などの子では明示的に落とす必要がある。2 バイナリ構成になる |
| 必要最小権限 | 縮退後の集合は他案と同じ（4 章）。縮退までの時間だけ root | 4 章の集合を保持 | 4 章の集合。ランチャーは短命、supervisor は集合を保持 |
| 主な攻撃面 | `LD_*`・`PATH` 等の環境変数、引数、fd 継承、cwd、core dump・ptrace | 同左（安全実行モードの扱いは未確認） | 同左（ランチャー側）。ambient 継承の取りこぼし |
| `nosuid` / `no_new_privs` の影響 | `nosuid` マウント上や `no_new_privs` 下では昇格しない（fail-closed に倒せる。未照合は 12 章） | file caps も同様に効かない（同） | ランチャーのみが影響を受ける |
| テスト容易性 | 属性付与に root が必要。GitHub ホステッド runner では昇格の実動作検証が難しい（実機は #539。SIGKILL の継続は #538 の `tests/privilege.rs` で模擬済み） | 同左 | 同左。縮退ロジックは属性なしでも単体テストできる |

外部事実（capabilities(7)。https://man7.org/linux/man-pages/man7/capabilities.7.html。確認日 2026-10-06）:

- ambient set は Linux 4.3 以降で、非特権プログラムの execve をまたいで保持される。ambient に載せるには permitted かつ inheritable である必要がある
- set-user-ID/set-group-ID プログラムの実行、または file capabilities を持つプログラムの実行は ambient set をクリアする。したがって (c) では、capability を持たない supervisor を exec する必要がある
- ambient による権限増加は `ld.so(8)` の secure-execution mode を起動しない
- file capabilities は `security.capability` xattr に格納され、書き込みに `CAP_SETFCAP` を要する
- bounding set の変更には `CAP_SETPCAP` が要る
- seccomp フィルタは `no_new_privs` を立てれば `CAP_SYS_ADMIN` なしで設定できる

`prctl(2)`・`execve(2)`・`setsid(2)`・`mount(8)` の `nosuid`・sudoers の `use_pty` の既定値は本書作成時に原文を照合していない（未確認。12 章）。`use_pty` は PoC-17 の観測として記述しており、一般的な既定値は主張しない。

## 4. 必要最小権限の棚卸し

rootful 時に、本リポのコードが行う特権操作と、それに要する capability の対応（capabilities(7) に基づく。対応が原文で確認できていないものは「想定」）。コンテナ側へ渡す capability（SEC-1）とは別物で、これは**ランタイム側が一時的に保持する権限**である。

| 操作 | 根拠（ファイル・関数） | 必要 capability | 保持が必要な期間 |
| ---- | ---------------------- | --------------- | ---------------- |
| namespace 生成（`unshare`）・hostname 設定 | `crates/core/src/sys.rs` の `unshare_namespaces`・`set_hostname` | `CAP_SYS_ADMIN`（user namespace のみは不要。UTS は想定） | コンテナ作成時 |
| mount・`pivot_root`・procfs マウント・umount | 同 `mount_root_private_recursive`・`mount_proc_at`・`bind_mount_recursive`・`pivot_root_dot`・`umount_cwd_detach` | `CAP_SYS_ADMIN`（想定。chroot 系は `CAP_SYS_CHROOT` の要否を未確認） | コンテナ作成時（子プロセス内） |
| デバイスノード作成 | 同 `make_char_device` | `CAP_MKNOD` | コンテナ作成時 |
| capability 削減・bounding 削除・ambient クリア | 同 `cap_bounding_drop`・`cap_ambient_clear_all`・`cap_set_thread`（`exec/capabilities.rs`） | `CAP_SETPCAP`（bounding 削除） | コンテナ側制限段の直前まで |
| `no_new_privs`・seccomp・Landlock | 同 `set_no_new_privs`・`seccomp_set_filter`・`landlock_*`（`exec/no_new_privs.rs` ほか） | 不要（`no_new_privs` を先に立てるため） | コンテナ側 |
| cgroups v2 の作成・参加 | `crates/core/src/cgroups.rs` | cgroup ディレクトリ・ファイルの書き込み権限（所有者 root を前提にした場合 `CAP_DAC_OVERRIDE` か uid 0。委譲方式は未確認） | コンテナ作成時・削除時 |
| ネットワーク（netns pin・veth・bridge・nftables） | `crates/net/src/netns.rs`・`netlink_route`・`nftables_*` | `CAP_NET_ADMIN`（netns の bind マウントに `CAP_SYS_ADMIN`） | ネットワーク作成・接続・削除時 |
| 監査ログ用 netlink（主経路失敗時のカーネル監査フォールバック。SEC-4） | `sys.rs` の `netlink_audit_socket`・`KernelAuditFallback`（`crates/core/src/audit_log/kernel_audit.rs`） | `CAP_AUDIT_WRITE`（欠如時は `KernelAuditFallback` が `KernelAuditPermissionDenied` を返し何も書き込まない。`crates/core/tests/audit_kernel_fallback.rs`。初期 user namespace が前提で、その外では `KernelAuditUnavailable`） | 監査ログの書き込み（フォールバック発火）が起きうる期間。restart ループ（SUP-1）を担う長寿命の supervisor では稼働中ずっと必要。ランチャーへ縮退する場合は、フォールバックを担うプロセスがこの権限を保持し続ける必要がある |
| シグナル送信（他 UID のプロセス） | `sys.rs` の `kill_pid`・`pidfd_send_signal` | 対象が同一 UID なら不要。他 UID は `CAP_KILL`（想定） | 停止時 |
| uid/gid マップ書き込み | `crates/core/src/rootless.rs`（setuid の `newuidmap`/`newgidmap`） | rootless 用（本書の昇格経路とは別） | - |

論点: rootful の mount・namespace 生成は `CAP_SYS_ADMIN` を要するため、capability 方式でも集合は劇的には小さくならない。差は「長寿命の supervisor が保持するか、短命のランチャーだけが保持するか」にある。supervisor は restart ループ（SUP-1）でコンテナを再作成するため、現設計では supervisor が (4 章の) 集合を保持し続ける。短命の特権ヘルパーへ分離できるかは未決（8 章）。

## 5. 権限の保持期間と縮退手順

1. ランチャーが `setsid` し、制御端末・標準入出力が pty でないことを確認する（(B)。#537。実装済み）。順序は、標準入出力が端末でないことの判定（端末なら `setsid` の前に拒否）→ `setsid` → `/proc/self/stat` の読み戻しで `session == pid`・`pgrp == pid`・`tty_nr == 0` を確認、とする。`setsid` が `EPERM`（プロセスグループのリーダーとして起動された）のときは、読み戻しで上の 3 条件を満たす場合に限り「既に切り離されている」として成功扱いにし、それ以外は拒否する。fork で回避しない（ランチャーは exec で置き換わり待機しない契約のため）。**起動側の契約**: ランチャーを `process_group(0)` で起動しない（`setsid` が新しいセッションとプロセスグループを作るので代わりになる）。標準入出力に pty を渡さない。CLI の `start` は共有クライアント `crates/supervisor/src/start_client.rs` で経路を選ぶ（#2442）: 非 root で CLI の実体の隣に信頼できる（通常ファイル・実行可・所有者が root か euid・g/o 書き込み不可の）`fandhe-container-launcher` があれば rootful のインストールとして `systemd-run --user --scope -p Delegate=yes -- <launcher> start ...` で起動し（`process_group(0)` なし・stdio は null / pipe / null）、無ければ従来どおり supervisor を `process_group(0)` で直接起動する。在るのに信頼できなければ直接経路へ落とさず `FAILED_PRECONDITION`。uid 0 の起動はランチャーの前提（呼び出し元は非 root。`check_method_premise`）に反し、`RootfulHostRoot`（#2241）の判断待ちのため spawn 前に `UNIMPLEMENTED` のまま。**supervisor 側の契約**: exec 後の supervisor はセッションリーダーのままなので、端末になりうる対象の `open` には常に `O_NOCTTY` を付ける（理由: 制御端末の再取得により `TIOCSTI` の入力注入や hangup 時の SIGHUP の波及という、ここで断った経路が再発するため。#2426）。実装上の対応は `crates/supervisor/src/launcher.rs` の module doc
2. 環境変数をサニタイズ（`LD_*`・`PATH` 等を信用しない）し、引数・cwd・継承 fd を検証する
3. 必要最小集合以外を bounding set から落とす（`CAP_SETPCAP` が要る）
4. 必要最小集合だけを inheritable・ambient に載せ、supervisor を exec する（(c)）。(a) の場合は uid を非特権へ戻す前に `PR_SET_KEEPCAPS` を 1 にして、setuid 遷移で permitted が失われないようにする。`setresuid` で非特権 UID へ戻した直後は effective が落ちるため、`capset` で permitted・effective・inheritable を必要最小集合に再設定し、ambient へ載せたうえで `PR_SET_KEEPCAPS` を 0 に戻す。`capget`・`/proc/self/status` の `CapPrm`・`CapEff`・`CapAmb` が期待集合と一致することを exec 前に検証し、不一致なら 6 章に従い fail-closed とする
5. supervisor はヘルスチェック exec・ログ処理などの子で ambient を落としてから exec する
6. コンテナ子プロセスは既存の制限段（`exec/stages.rs`）で capability 削減 → `no_new_privs` → Landlock → seccomp を適用する。昇格経路を `no_new_privs` より後に使わない

## 6. 失敗時の挙動

- 昇格手段（setuid ビット・file capability）が無い、または検証に失敗した場合は fail-closed とし、構造化エラー（機械可読な `code`・`message`。ERR-1）で非ゼロ終了する。黙って `sudo` へフォールバックしない
- 特権バイナリが起動した子（supervisor 等）の待機にはタイムアウトを設ける（REPAIR-5）
- 特権操作に失敗した場合は、作成済みの cgroup・netns・マウントの後始末を行う

## 7. 特権バイナリの入口要件

- root 所有・他ユーザー書き込み不可のパスに置く（PLUG-11 と同じ考え方）。コピー・再配置で属性（setuid ビット・xattr）が失われる、または意図せず残る場合の扱いをインストール手順で定義する
- 受け取る引数・環境変数・パスを未検証で exec・パス連結に使わない。呼び出し元の非特権ユーザーが任意の特権操作をさせられない最小の入口に限る
- (c) では、ランチャーが ambient capability を付けて supervisor を exec するため、supervisor の実行ファイルの改変はそのままランタイム側の権限取得になる。supervisor の実行ファイル本体と、そこへ至る親ディレクトリのすべての要素を、root（または信頼するインストール所有者）所有かつ他ユーザー書き込み不可にする。symlink を辿る場合は、解決後の実体とその親ディレクトリにも同じ条件を課す
- ランチャーは exec の直前に supervisor の実体を検証する。パスを `open` して得た fd に対し `fstat` で所有者・パーミッション（グループ・他者の書き込みビットが無いこと）・通常ファイルであることを確認し、`/proc/self/fd` 経由や `execveat`（fd 指定）で検証した同一の実体を exec する。検証と exec の間の差し替え（TOCTOU）を避けるため、パス文字列で検証して別途パスで exec する方式にしない。許可済みハッシュ・署名との照合の要否は PLUG-11 に合わせて実装時に決める（未確認）。検証に失敗した場合は 6 章に従い fail-closed とする
- supervisor のパスは固定の絶対パスまたは同一インストール先からの相対解決に限り、`PATH` 探索や呼び出し元が与える任意パスを受け付けない（既定）
- core dump・ptrace の可否: `PR_SET_DUMPABLE=0` を `elevate` の前に設定する（#1719 で確定。昇格中の窓で同一 uid の別プロセスから ptrace・`/proc/<pid>/mem`・core dump を受けない）
- supervisor の入口でも `PR_SET_DUMPABLE=0` を設定する（SUP-14。2026-10-16 に spec へ明記、spec#23、本リポへの取り込みは #2101・#2102）。`execve` は dumpable を 1 に戻し、ランチャー経由の昇格は ambient capability の受け渡しで AT_SECURE・資格情報の変化を伴わないため、ランチャー側の設定だけでは足りない。入口で改めて 0 にしないと、同じ UID の親や他プロセスから ptrace・`/proc/<pid>/`（`mem`・`smaps_rollup`・`exe` 等）の読み取り・core dump を受け、昇格した capability を奪われうる。位置は継承 fd を閉じ、結果チャネルを開いた直後で、引数の検証や起動処理より前。直接起動（ランチャー非経由）でも無条件に設定し、特権経路に限らない。設定に失敗したら結果チャネルへ構造化エラー（`code` は `INTERNAL`、メッセージは `PR_SET_DUMPABLE failed: <kind>`。ERR-1）を書いて非ゼロで終了し、起動しない（fail-closed。6 章）。`execve` での dumpable の扱いなどカーネル挙動の原文照合は 12 章の `prctl(2)`・`execve(2)` の未確認の行に含まれる
  - 計測のために dumpable=0 を外さない。特権経路に限ることもしない（SUP-14）。supervisor の PSS の計測は読み取りだけを root で行う（TASK-158 追補。方式は #2090 で決定、実装は #2099 で未完了）。手順は `docs/verification/supervisor-measurement-runbook.md` の「計測の権限」、`scripts/bench/supervisor_pss.sh` を参照
- 実装の対応（#1719。`crates/supervisor/src/launcher.rs`・`src/bin/fandhe-container-launcher.rs`）: 環境は `execveat` に渡す `envp` を許可リスト方式で新規に組む（固定の `PATH` のみ。`LD_*` を渡さない）。引数は supervisor と同じ `StartArgs::parse` で検証して転送する。supervisor のパスはランチャー自身の実体（`/proc/self/exe`）の親ディレクトリ + 固定名。パスは根から全要素を辿り、ディレクトリは root 所有・group / other 書き込み不可（sticky でも免除しない）、symlink は root 所有のみ許可して自前で解決する。最終ファイルは `open` した fd の `fstat` で通常ファイル・setuid / setgid 無し・group / other 書き込み不可・root 所有を確かめ（この順に最初の失敗を報告）、同じ fd を `execveat(AT_EMPTY_PATH)` で exec する。fd 0〜2 が閉じていれば結果チャネルを乗っ取られないため拒否し、fd 3 以降は閉じ、cwd は `/`。許可済みハッシュ・署名との照合は行わない（PLUG-11 との整合は 12 章に未確認として残す）
- 実装の対応（supervisor 側の dumpable。#2102）: `crates/supervisor/src/start_entry.rs` の `run_main_inner`（結果チャネルを開いた直後の手順）が `crate::sys::set_dumpable(false)` を呼ぶ。ラッパーは `crates/supervisor/src/sys/linux.rs` の `set_dumpable` で、設定のみを行い読み戻しはしない。dumpable=0 では `/proc/self` 配下の所有者が変わるため、`ProductionStartDeps::new` は権限モデルを `/proc/self/status` の所有者ではなく内容から決める

## 8. 配置の論点（本書では決めない）

TASK-171 の成果物は `crates/supervisor/src/privilege.rs`（仮称）だが、昇格は CLI が supervisor を起動する地点で起きる。次は crate 境界の判断であり、main / ユーザーの判断事項として残す。

| 論点 | 選択肢 | 影響 |
| ---- | ------ | ---- |
| 特権を持つバイナリ | 専用ランチャー（新 crate）／ CLI／ supervisor 自身 | 攻撃面・配布物の数・新 crate の追加（crate-naming の確定内容の変更を伴う） |
| `unsafe` ラッパーの置き場所 | supervisor の `sys`／ core の `sys` を再利用 | 事前承認は各 crate の `sys` モジュール内に限る（coding-rust.md）。`sys` 外の `unsafe` は 1 件ずつ承認が必要 |
| 特権の分割 | supervisor が集合を保持／短命の特権ヘルパーへ分離 | restart 時に再昇格が要るか。分離すると 5 章の保持期間を短くできるが、境界が増える |

## 9. 採用方式（承認済み。#1454・2026-10-10）

採用: **(c) 特権ランチャー＋ ambient capability**（xattr 非対応環境に限り (a) setuid root を代替として認める）。配置は 8 章の論点に対して次のとおり確定した。

- 特権を持つバイナリ: `crates/supervisor` の bin（`fandhe-container-launcher`。新 crate は作らない。実装は #1719）
- `unsafe` ラッパー: supervisor の `sys`（Linux 版）に置く。core の `sys` の同等関数は `pub(crate)` のため重複を許容する
- 特権の分割: 本方式では supervisor が集合を保持する（短命の特権ヘルパーへの分離は未採用）

採用理由:

- 特権付きファイル属性を持つバイナリを最小のランチャー 1 つに限定でき、supervisor 本体はコピー・更新の自由度を保てる（3 章比較）
- uid 0 にならず、4 章の集合だけを保持できる（(a) は縮退を誤ると全権限が残る）
- pty を経由しないため SUP-14 の巻き添え経路を除ける。(B) は #537 で実装済み

採らない理由・留意点:

- (a) setuid: 常に完全な root である期間が生じる。ただし xattr 非対応環境では唯一の選択肢になりうる
- (b) supervisor 本体への file caps: 特権付きバイナリが大きくなり、配布の自由度も下がる
- 現状の暫定（sudo＋`setsid`）: sudo と pty に依存し続ける
- (c) の欠点（ambient の子への継承）は 5 章の手順で落とす。取りこぼしがないことは #539 の実機検証が必要で、本書では確認していない

方式の承認は #1454 のオーナー判断（2026-10-10）で記録済み。

## 10. #858 以降への引き継ぎ

ユーザー承認が必要な項目:

- `sys` モジュール外の `unsafe` が必要になった場合の 1 件ごと
- 新 crate の追加（ランチャーは supervisor の bin で新 crate は作らない方針。変更する場合）
- 新規依存（必要になった場合）・root 権限コマンドの実行

補足:

- 方式非依存の純ロジック（必要最小集合・`/proc/<pid>/status` のパースと昇格結果の fail-closed 検証・縮退計画の算出。縮退後は uid・gid 0 と補助グループの残存も拒否し、補助グループは空のみ許可する。縮退計画は 5 章 4 のとおり uid 遷移がある場合に `PR_SET_KEEPCAPS` の設定と解除を対で含み、解除を最終手順とする。検証は `PR_GET_KEEPCAPS` の読み戻し結果を入力に取り、残存・未確認を拒否する）は `crates/supervisor/src/privilege.rs` に実装済み（TASK-171.1.2・#858）。縮退を実際に適用する `privilege::elevate`（単一スレッドの確認 → 方式の前提確認 → `plan_reduction` → `ReductionPlan::steps` の順に適用〔補助グループ消去・`setresgid`・bounding 削除・`PR_SET_KEEPCAPS`・`setresuid`・`capset`・ambient 載せ〕→ `PR_GET_KEEPCAPS` と `/proc/self/status` の読み戻し → `verify_elevation`）は TASK-171.1.3（#1475）で実装済み。どの段で失敗しても `Err` を返し、`Err` のときプロセスは部分的に縮退した状態にあるため、呼び出し元は exec も特権操作もせず非ゼロで終了する。目標の uid / gid は呼び出し元の real から決める。方式 (c) の file capability には最小集合に加えて、補助グループを持つ利用者向けに `CAP_SETGID`（effective）が要る。ランチャー bin（入口検証・fd 検証付き `execveat`）は #1719 で実装済み（7 章の「実装の対応」）。file capability / setuid の付与は `scripts/install-privileged-launcher.sh`（#1721。下記「インストールスクリプト」）で実装済み。(B) のセッション切り離しは TASK-171.2（#537）で `privilege::detach_session` として実装済み（ランチャーの入口で `elevate` より前に実行。拒否は `FAILED_PRECONDITION`、syscall の失敗は `INTERNAL`、メッセージの接頭辞は `session detach failed:`）。未実装は子での ambient 解除である。ambient を落とす箇所は、コンテナの子は core の制限段（capability 段で ambient を全消去）、supervisor の healthcheck コマンド実行は未実装（TASK-161.2・#2441。実装時に子で ambient を落としてから exec する）。取りこぼしがないことの確認は実機検証（#539）で行う。実機のランチャー試験は `crates/supervisor/tests/launcher_entry_real.rs`（`-- --ignored`）実機の縮退試験は `crates/supervisor/tests/privilege_elevate.rs`（`-- --ignored`。実行は #539）
- setuid ビット・`setcap` の付与はインストール時の操作で、`scripts/install-privileged-launcher.sh` が行う（下記「インストールスクリプト」）
- 事前承認の範囲は各 crate の `sys` モジュール内の syscall ラッパーに限られる（`elevate` のラッパーは `crates/supervisor/src/sys/linux.rs`。#1719 の `execveat` 等も同じ `sys` に足す）
- `sudo` の `SIGKILL` 後の子孫の継続は `crates/supervisor/tests/privilege.rs`（#538。util-linux の `script` による模擬で既定集合）で確認済み。実 `sudo` での再現・昇格の実動作の実機検証は #539 で扱い、本書の範囲外とする

### インストールスクリプト（#1721・TASK-171 追補）

`scripts/install-privileged-launcher.sh --launcher <file> --launcher-sha256 <hex> --supervisor <file> --supervisor-sha256 <hex> --cli <file> --cli-sha256 <hex> [--dest-dir <絶対パス>]` を root で実行する（パッケージの postinst からも `--dest-dir` を渡して呼べる）。スクリプト内で sudo は呼ばない。自己テストは `make install-launcher-selftest`（スタブのみ・root 不要）。root での実機実行と検証は人間担当（#539）。

- 配置先は既定 `/usr/local/libexec/fandhe-container`。根から配置先までの全要素が root 所有・g/o 書き込み不可の通常ディレクトリ（symlink 不可）でなければ、補修も上書きもせず終了コード 3 で止まる（7 章）。supervisor と CLI（`fandhe-container`）もランチャーと同じ条件で、同じディレクトリに置く（#2068）。CLI の `start` は自分の実体と同じディレクトリの supervisor を起動する（#1718）ため、CLI を別の場所に置くと見つけられない。CLI と supervisor は起動契約（`FCSUP1`）の版が揃っている必要があり、`--cli` は必須にして 3 つを一組で更新する。CLI には capability も setuid も付けず、supervisor と同じく付いていないことと `755` を読み戻す。`PATH` 上の symlink（例: `/usr/local/bin/fandhe-container` から配置先の CLI）はスクリプトでは作らず、root の手作業とする（手順は [docs/setup/linux.md](../setup/linux.md)）。symlink から起動しても、`current_exe()` は実体のパスを返すので実体のディレクトリの supervisor が使われる（CLI の結合試験で照合）。symlink はインストーラの信頼チェーンの外にあるが、CLI と supervisor の間に権限の境界は無く（同一ユーザーで起動する）、特権経路はランチャーが自分の実体の隣の supervisor を自前で検証する（#1719）ため、昇格の経路にはならない。rootless 向けの置き場所も同じ文書に書く。
- 入力元の照合（#2137。SUP-14、方式は PLUG-11 の「許可済み sha256 ハッシュ一覧が既定・署名は opt-in の将来拡張」に倣う）: 3 つの入力元それぞれの許可済み sha256（64 桁の 16 進。大文字は小文字へ正規化）を `--launcher-sha256`・`--supervisor-sha256`・`--cli-sha256` で渡す。3 つとも必須で、省く既定は無い（欠落は終了コード 2）。照合するのは入力元のパスではなく、fd から複製した配置先の一時ファイルである。入力元は開いた後にパスの先を差し替えられうるが、一時ファイルは root 所有の配置先の中にあり root しか変えられず、rename は inode を保つので、照合した中身がそのまま最終名になる（rename 後の再ハッシュはしない）。照合は属性の変更（chown・chmod・setcap）より前に行い、不一致は `error: source-hash-mismatch`（終了コード 3。期待値と実際の値を示す）で属性の変更も置換もせずに止まる。`sha256sum` が無ければ `error: sha256sum-unavailable`（終了コード 3）で、別のツールへは替えない。`sha256sum` の想定外の出力は終了コード 1 の `install-failed`、期限超過は `operation-timeout`。防ぐのはビルドとインストールの間の差し替え・破損・取り違えで、期待値は入力元とは別の経路（リリースの SHA256SUMS、または信頼できるビルドホストで取った値）から得ることが前提になる（入力元と同じ時点で計算し直した値では保護にならない）。期待値をマニフェストファイルで渡す方式は採らない（親シェルが開くファイルが増え、ファイル自体の信頼性検証が要るため）。署名の検証は未実装で、PLUG-11 の opt-in の将来拡張とする。差し込む位置は「一時ファイルへの複製の後、属性の変更の前」で、ハッシュ照合と置き換えるか併用するかは決めていない（形式・鍵の管理も未定）。
- ランチャーにだけ `RUNTIME_REQUIRED_CAPABILITIES`（7 件）に `cap_setgid` を足した 8 件を `+ep` で付け、`getcap` で読み戻して照合する。`cap_setgid` は `elevate` の契約（方式 (c) は補助グループを持つ利用者向けに effective で要る）による。縮退後の保持集合は最小の 7 件に戻る。supervisor には付けず、付いていないことも読み戻す。
- setuid root（`root:root`・`4755`）へ切り替えるのは、`setcap` が非 0 で終わり stderr に `not supported`（ENOTSUP / EOPNOTSUPP。xattr 非対応）を含むときだけ。EPERM・EINVAL・`setcap` 未導入・読み戻し不一致では切り替えず、`error: <code>: <message>` の 1 行を出して終了コード 1 で止まる（fail-closed）。
- `getcap` は読めなかったときも終了コード 0 のまま stderr に診断を出すことがあるため、終了コードだけで成否を決めない。出力が空なら capability なし、`<file> <caps>` の 1 行なら付与あり、それ以外は失敗として止まる。例外は setuid へ切り替えた後だけで、診断が `not supported` を含むとき（2021-09 より前の libcap は xattr 非対応の FS で ENOTSUP を stderr へ出す）に限り capability なしとして扱う。setuid への切り替え条件（`setcap` の結果）は広げない。
- 一時ファイルで検証を済ませてから rename で置換するため、途中失敗で半端な属性を残さない。CLI・supervisor・launcher の順に置換し、途中で止まったら supervisor、CLI の順に旧ファイル（ハードリンクの退避）へ戻す。launcher は最後に置換するので退避を取らない。
- 同じ配置先への並行インストールは、配置先ごとのロックファイル `<dest-dir>/.install.lock`（root 所有・0600。消さずに残す）への `flock(1)` で排他する。既存ファイルの確認から置換・復元・最後の読み戻しまでを 1 つのインストールだけが行い、並行する実行が CLI・launcher・supervisor を別々の版にしたり、他方の更新を旧版へ戻したりしない。ロックは待たずに取り、取れなければ `error: install-locked`（終了コード 3）で何も変えずに止まる。ロックはプロセスの終了で解放される。0600 にするのは、読めるだけの利用者でも `flock` を取れてインストールを止められるため（他の利用者から読めるロックファイルは信頼できない配置先として拒否する）。
- 配置先・入力元に触る外部コマンド（`stat`・`mkdir`・`flock`・`mktemp`・`dd`・`sha256sum`・`chown`・`chmod`・`setcap`・`getcap`・`ln`・`mv`・`rm`）はすべて `timeout(1)` の期限つき（30 秒・超過後 5 秒で KILL）で実行し、親シェルはファイル検査も配置先へのリダイレクトも行わない（REPAIR-5。NFS / FUSE の停止で無期限に待たない。親シェルが開くのは入力元とロックファイルだけで、どちらも watchdog が同じ期限で打ち切る）。期限超過は `error: operation-timeout`（終了コード 1）。期限を超えた操作は実行されたか不明として扱い、置換の有無を inode の読み戻しで確かめてから戻す。結果は stderr の 2 行目以降に `warning: rolled-back`（旧 supervisor・旧 CLI へ戻した・置換済みのファイルは無い）・`error: restore-failed`（戻せなかった。退避ファイルを残し復元コマンドを示す）・`error: state-indeterminate`（launcher の置換を確かめられなかった。2 つの退避ファイルを残す）・`warning: replaced-unverified`（3 つとも置換済みで最後の読み戻しが未完）・`warning: cleanup-incomplete`（一時ファイル・退避ファイルを消せなかっただけ。置換の成否には影響せず、成功時は終了コード 0 のまま）で示す。SIGKILL でも終わらない子（割り込めない I/O 待ち）は `timeout(1)` が回収を待つため、期限では打ち切れない。
- `doctor` の診断（#2599）: `fandhe-container doctor` が、`start` と同じ関数（`start_client::classify_launcher_beside`）でランチャーの信頼条件を、`launcher_probe` で file capability（`security.capability` を `lgetxattr` で読む）と setuid root の代替を読み取り専用で診断し、`check:"launcher"` の JSON Lines で出す。ランチャーの実体（正規化済みパス）が `nosuid` マウント上にあるかも `/proc/self/mountinfo` の per-mount options（上限つきで読む）で検出し、`nosuid` なら `state:"nosuid_mount"`（警告）、読めない・該当マウントが無いときは `state:"mount_unreadable"`（判定不能）にする（#2661）。根拠はカーネル v6.12 の `fs/exec.c` と `security/commoncap.c` が `mnt_may_suid()` が偽なら setuid / file capability を無視すること。doctor 自身の mount namespace から見た情報なので、`start` が systemd-run 経由で起動する環境の mount namespace や、superblock の所有 user namespace による `mnt_may_suid` の偽は検出しない。hash / 署名の照合・LSM は扱わず、診断と実行の間の差し替えも防げない（昇格の可否は実行時にランチャーが検証する）。
- 既知の範囲外: 入力元の署名の検証は未実装（ハッシュの照合は上記のとおり実装済み。12 章）。nosuid マウント上の配置先では file capability / setuid が効かず、ランチャーが実行時に fail-closed で拒否する（`doctor` は上記のとおり事前に警告する）。

## 11. 参照

- [rootless-network.md](./rootless-network.md)（rootless ネットワークの外部ヘルパーの判断記録。起草時は本書と同じ形式のドラフト）
- [cgroups.md](./cgroups.md)（cgroups v2 単独対応）

## 12. 未確認事項・再検証条件

| 項目 | 状態 |
| ---- | ---- |
| `prctl(2)`・`execve(2)`・`setsid(2)`・`mount(8)` の `nosuid`・sudoers `use_pty` の原文照合 | 未確認（`nosuid` のうち、カーネル v6.12 の `fs/exec.c` と `security/commoncap.c` が `mnt_may_suid()` が偽なら setuid / file capability を無視する点と、`security.capability` の `VFS_CAP_*` / `XATTR_CAPS_SZ_*` の値は `capability.h` の原文で確認済み。#2661） |
| `CAP_SYS_CHROOT`・UTS namespace・cgroup 書き込み権限の要否 | 未確認（4 章の「想定」） |
| セッションリーダーが `O_NOCTTY` を付けずに tty を `open` すると制御端末を再取得しうる | 契約として明記（#2426。`launcher.rs` の module doc と 5 章 1 項。env ファイル・ログ等の外部指定パスを開くヘルパーは `O_NOCTTY` を付ける）。カーネル挙動の原文照合と実機での確認は #539 |
| `sudo`（`use_pty`）経由で起動すると標準入出力が pty になりランチャーが拒否する | 設計どおり（「sudo へ戻らない」の帰結。回避手段は設けない） |
| file capabilities 付きバイナリの AppArmor 等の LSM 下の挙動 | 未確認 |
| macOS・Windows（VM 内）で本方式が不要であること | 要確認（MAC・WIN 系ビヘイビア） |
| rootless（CORE-6）経路との関係 | PoC 未検証 |
| ランチャーの実行時の supervisor の hash / 署名照合の要否（PLUG-11 との整合） | 未確認（#1719 は所有権と書き込み権限のみで信頼を判断）。`doctor` のランチャー診断（#2599）も hash / 署名は照合しない。オーナー判断待ちで、判断の記録先は本行。追跡は #2661（受け入れ条件 3）と #2231（PLUG-11 の判断） |
| インストール時の入力元のハッシュ照合 | 決定・実装済み（#2137。許可済み sha256 を引数で渡し、複製した一時ファイルを照合する。10 章） |
| インストール時の署名検証 | 未採用（PLUG-11 の opt-in の将来拡張。差し込む位置は 10 章） |
| `CAP_AUDIT_READ`（`AUDIT_SECCOMP` の READLOG 購読） | 最小集合に含めない。付与の可否は判断待ち（`audit-seccomp-reader.md`。#2237） |
| 再検証条件 | 実機（root 権限・対象カーネル）で #539 を実施するとき |

## 補足: 範囲写像の書き込み先と dumpable（#2374）

subuid / subgid の範囲写像では、`newuidmap` / `newgidmap` が対象の `/proc/<pid>` の所有者を検査するため、対象が non-dumpable だと拒否される。launcher の中間プロセスを一時的に dumpable にする方式（#2243）は、その間に同一 uid のホスト側プロセスが fd と制御フローへ触れられる窓を作る。これをなくすため、書き込み先を使い捨ての holder プロセスへ分け、中間プロセスは終始 non-dumpable のまま `setns` で参加する。設計と残る影響は [rootless-id-map-holder.md](./rootless-id-map-holder.md)（CORE-6・SEC-5・SEC-1）。
