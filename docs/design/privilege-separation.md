# 権限分離方式の比較と必要最小権限（設計ドラフト）

sudo＋pty に頼らない権限昇格方式（setuid バイナリ・capability ベース）の選択肢と、本リポが rootful で必要とする最小権限を整理する（SUP-14）。

> **位置づけ**: 本書はドラフトであり、採否を確定しない。9 章の採用方式案は推奨にすぎず、ユーザーの承認は未取得である。承認が記録されるまで後続の TASK-171.1.2（#858）には着手しない。`docs/design/rootless-network.md` と同じ扱いで、本書は判断材料である。

- 対象ビヘイビア: SUP-14（Must・確定。関連: SUP-1・CORE-1・CORE-5・CORE-6・SEC-1・SEC-5・PLUG-11・ERR-1・REPAIR-5・D-19）
- タスク: TASK-171（MS-9・G12・担当: 共同）。本書は TASK-171.1.1（#857。親 #536・#535）
- 後続: #858（TASK-171.1.2。成果物 `crates/supervisor/src/privilege.rs`〔仮称〕）・#537（TASK-171.2 pty 非経由の起動経路）・#538（TASK-171.3 SIGKILL 継続テスト）・#539（TASK-171.h1。実装後のセキュリティレビュー・実機検証。人間担当）
- 出典: `docs/spec/04-behavior/api-supervisor.md` の `SUP-14`、`03-poc/supervisor-model/README.md` の発見事項 1（PoC-17）、`05-tasks.md` の TASK-171、`api-runtime-core.md` の `CORE-6`、`security-isolation.md` の `SEC-1`・`SEC-5`（submodule リビジョン `984f8a2`）。外部事実の出典は 3 章末尾に URL と確認日（2026-10-06）を付す

## 1. 問題の整理

PoC-17 発見事項 1: コンテナごとに `sudo <supervisor> run ...` を起動すると、`sudo`（`use_pty` 設定下）が子を fork して pty 経由で中継する。この `sudo` を `SIGKILL` すると pty のクローズに伴うシグナル配送で、子孫（supervisor・ランタイム・コンテナ本体）が巻き添えで終了した。PoC の暫定対策は「1 回の `sudo` の中で `setsid` により独立セッションとして起動する」ことで、本番対策は未実装である。

対策は独立した 2 要素に分けて考える。

| 要素 | 内容 | 選択肢 |
| ---- | ---- | ------ |
| (A) 権限の取得手段 | 非特権ユーザーが必要な権限をどう得るか | setuid か capability（2 章） |
| (B) セッション切り離し | supervisor が呼び出し元の制御端末・セッションに紐づかない | `setsid`・制御端末なし・標準入出力が pty を指さない |

- **(B) はどの方式を選んでも必須**である。「capability 方式を選べば SUP-14 が解決する」わけではない。(B) の実装は #537（TASK-171.2）の範囲である
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
| テスト容易性 | 属性付与に root が必要。GitHub ホステッド runner では昇格の実動作検証が難しい（実機は #538・#539） | 同左 | 同左。縮退ロジックは属性なしでも単体テストできる |

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

1. ランチャーが `setsid` し、制御端末・標準入出力が pty でないことを確認する（(B)。#537）
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
- core dump・ptrace の可否（`PR_SET_DUMPABLE` 等）の扱いは実装時に決める（未確認）

## 8. 配置の論点（本書では決めない）

TASK-171 の成果物は `crates/supervisor/src/privilege.rs`（仮称）だが、昇格は CLI が supervisor を起動する地点で起きる。次は crate 境界の判断であり、main / ユーザーの判断事項として残す。

| 論点 | 選択肢 | 影響 |
| ---- | ------ | ---- |
| 特権を持つバイナリ | 専用ランチャー（新 crate）／ CLI／ supervisor 自身 | 攻撃面・配布物の数・新 crate の追加（crate-naming の確定内容の変更を伴う） |
| `unsafe` ラッパーの置き場所 | supervisor の `sys`／ core の `sys` を再利用 | 事前承認は各 crate の `sys` モジュール内に限る（coding-rust.md）。`sys` 外の `unsafe` は 1 件ずつ承認が必要 |
| 特権の分割 | supervisor が集合を保持／短命の特権ヘルパーへ分離 | restart 時に再昇格が要るか。分離すると 5 章の保持期間を短くできるが、境界が増える |

## 9. 採用方式案（推奨。ユーザー承認待ち）

推奨: **(c) 特権ランチャー＋ ambient capability**（フォールバックとして xattr 非対応環境向けに (a) を許容）。

理由:

- 特権付きファイル属性を持つバイナリを最小のランチャー 1 つに限定でき、supervisor 本体はコピー・更新の自由度を保てる（3 章比較）
- uid 0 にならず、4 章の集合だけを保持できる（(a) は縮退を誤ると全権限が残る）
- pty を経由しないため SUP-14 の巻き添え経路を除ける。(B) は #537 で併せて実装する

採らない理由・留意点:

- (a) setuid: 常に完全な root である期間が生じる。ただし xattr 非対応環境では唯一の選択肢になりうる
- (b) supervisor 本体への file caps: 特権付きバイナリが大きくなり、配布の自由度も下がる
- 現状の暫定（sudo＋`setsid`）: sudo と pty に依存し続ける
- (c) の欠点（ambient の子への継承）は 5 章の手順で落とす。取りこぼしがないことは #538・#539 の実機検証が必要で、本書では確認していない

これは推奨であり、方式の承認は未取得である。承認は #857 へのコメントで記録する運用を案とする。なお人間担当ツリー #812 配下には、方式選定の承認そのものを記録する issue が見当たらない（#539 は実装後のレビュー）。起票の要否はユーザー判断とする。

## 10. #858 以降への引き継ぎ

ユーザー承認が必要な項目:

- 方式そのもの（9 章）
- `sys` モジュール外の `unsafe` が必要になった場合の 1 件ごと
- 特権バイナリの crate 配置・新 crate の追加（8 章）
- 新規依存（必要になった場合）・root 権限コマンドの実行

補足:

- setuid ビット・`setcap` の付与はインストール時の操作でコード外である
- 事前承認の範囲は各 crate の `sys` モジュール内の syscall ラッパーに限られる
- 実機検証（sudo の `SIGKILL` 再現・昇格の実動作）は #538・#539 で扱い、本書の範囲外とする

## 11. 参照

- [rootless-network.md](./rootless-network.md)（本書と同じ形式のドラフト）
- [cgroups.md](./cgroups.md)（cgroups v2 単独対応）

## 12. 未確認事項・再検証条件

| 項目 | 状態 |
| ---- | ---- |
| `prctl(2)`・`execve(2)`・`setsid(2)`・`mount(8)` の `nosuid`・sudoers `use_pty` の原文照合 | 未確認 |
| `CAP_SYS_CHROOT`・UTS namespace・cgroup 書き込み権限の要否 | 未確認（4 章の「想定」） |
| file capabilities 付きバイナリの AppArmor 等の LSM 下の挙動 | 未確認 |
| macOS・Windows（VM 内）で本方式が不要であること | 要確認（MAC・WIN 系ビヘイビア） |
| rootless（CORE-6）経路との関係 | PoC 未検証 |
| 再検証条件 | 実機（root 権限・対象カーネル）で #538・#539 を実施するとき |
