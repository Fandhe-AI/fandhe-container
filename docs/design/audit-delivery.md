# seccomp・Landlock の拒否を監査の記録先へ届ける配送経路（設計ドラフト）

カーネルが返す seccomp と Landlock の拒否を、`AuditSink`（`FileAuditSink` ほか）へ届ける配送経路の候補を、同じ比較軸で並べた判断資料。

> **位置づけ**: **方式は採用済み・実装は未着手**。TASK-41 追補・#1835 の設計ドラフトとして作り、2026-10-15 にオーナーが 4 章の組み合わせ案と 7 章の推奨を採用した（判断の記録は #2018 のコメント。11 章の承認事項 1〜4 を含む）。実装は 9 章の issue が担い、本書は実装済みを装わない（REPAIR-3）。SEC-4 の「100% 記録」は記録経路が利用できる環境で満たすと spec に明記した（fandhe-container-spec#21。11 章）。

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
| 同上 | 同上 | 通知の `pid` の名前空間 | 通知の `pid` が listener 側の PID namespace の値であること、`/proc/<pid>` の参照に PID 再利用の競合があることの両方は、本書で原文を確認しきれていない | **未確認**。`seccomp_unotify(2)` の NOTES 節と `seccomp_hook.rs` の doc を突き合わせる |
| Linux `userspace-api/landlock`（docs.kernel.org） | - | 監査ログ（`AUDIT_LANDLOCK_ACCESS`・`AUDIT_LANDLOCK_DOMAIN`）と `landlock_restrict_self` のログ制御フラグ | ABI 7（Linux 6.15 の見込み）で監査ログに対応し、`landlock_restrict_self` のログ制御フラグ（`LANDLOCK_RESTRICT_SELF_LOG_*`）を持つ見込み。execve の後の拒否を記録する指定が必要な見込み。本リポの Landlock は ABI 6・Linux 6.12 前提で差がある | **未確認**（手元に一次資料が無い）。docs.kernel.org の該当ページで版・フラグ名・記録項目を確かめる |
| Linux カーネル監査（`AUDIT_SECCOMP`〔1326〕） | - | 記録項目・有効化・読み出し権限 | pid・syscall・arch・signal・ip・comm・exe が記録される見込み。`audit_enabled` が無効なら出ない。audit netlink の読み出しは `CAP_AUDIT_READ` 等の権限が要る見込み。コンテナ識別子（`contid`）の取り込み状況 | **未確認**。`audit.h`・auditd のドキュメントで確かめる。rootless で読めるかも同時に確かめる |
| moby / containerd | - | seccomp の拒否の記録 | 既定は auditd 任せの見込み（moby 既定プロファイルは KILL 系を使わない。`seccomp.rs` のコメントと整合） | **未確認** |

Landlock には USER_NOTIF に相当するユーザー空間への通知経路が無い見込み（`EACCES` は呼び出したプロセスにしか返らない）。この点も上記 Landlock 文書で確かめる（未確認）。

## 3. 現状（本リポ、実装済みを装わない）

| 要素 | 状態 | 場所 |
| ---- | ---- | ---- |
| seccomp 違反の記録の組み立て | フック実装済み。**呼び出し元（SIGSYS ハンドラ・USER_NOTIF の listener）が無く、本番経路から呼ばれない** | `crates/core/src/audit_log/seccomp_hook.rs`（`SeccompDenialReport::from_sigsys`・`from_user_notif`、`record_seccomp_denial`） |
| 拒否時の動作（#1834） | `unshare`・`ptrace`・`kexec_load` の 3 件は `SECCOMP_RET_KILL_PROCESS`、残り 40 件は `ERRNO(EPERM)`（`mount`・`pivot_root`・`umount2` を含む。ESC-03 が EPERM を要求） | `crates/core/src/seccomp.rs`（`DenyAction`・`DeniedSyscall::deny_action`） |
| Landlock の記録 | プロセス内で観測した `EACCES` の写像まで。ワークロードが受けた拒否をカーネルから捕捉する経路は無い | `crates/core/src/audit_log/landlock.rs`（`landlock_denial_record`） |
| 本番 sink | `FileAuditSink`（ファイル主経路と NETLINK_AUDIT フォールバック。常時 tee は未実装）。supervisor の exec 経路は `default_audit_sink` で配線済み（#1594） | `crates/core/src/audit_log/file_sink.rs`・`crates/supervisor/src/exec.rs` |
| コンテナ ID | `AuditRecord::container_id`（#1618）はあるが、seccomp・Landlock の記録への付与は未実装 | `crates/core/src/audit_log.rs` |
| 型の制約 | `AuditEvent::Seccomp` は syscall 番号と arch が必須で、「syscall の無い seccomp 違反」を構築できない | `crates/core/src/audit_log.rs` |
| 試験 | ESC-01・03・06・10 の監査は `AuditExpectation::Deferred` で合否に使わない。ESC-07（landlock）・ESC-08（mount）は `Required` だが、記録は試験の側が作っており（`record_landlock_denial`・`audit_mount_config_error` の直接呼び出し）、本番の配送経路を通った記録ではない | `crates/core/tests/escape_suite.rs` |

本リポの #1834 から導かれる制約:

- `KILL_PROCESS` では終了するプロセス自身が記録を書けない。プロセス内の SIGSYS ハンドラ経由の `from_sigsys` は使えない
- `ERRNO(EPERM)` はユーザー空間へ何も報告しない
- `SECCOMP_RET_TRAP` は SIGSYS を捕捉・無視できるため、「強制終了」と両立しない

## 4. seccomp の拒否の配送方式の比較

評価軸は 6 章の表。ここでは各候補の内容と論点を示す。

- **(a) `SECCOMP_RET_USER_NOTIF` と supervisor の listener**: 対象の syscall を supervisor（コンテナごとの監視プロセス。CORE-1 と整合し、中央デーモンを要しない）へ転送し、supervisor が記録して `-EPERM` で応答する。ERRNO 側の 40 件に使えば ESC-03 の EPERM と両立する。`KILL_PROCESS` の 3 件には使えない（USER_NOTIF は強制終了を表さない。supervisor が SIGKILL を送ると終了シグナルが SIGSYS でなくなり ESC-06 の期待と食い違う）。論点: listener fd の受け渡し（子から supervisor へ UDS）、exec（SUP-6）の再適用ごとに別フィルタ・別 listener になること、応答の期限（REPAIR-5。無期限に対象を止めない）、supervisor クラッシュ時の対象の挙動（fd が閉じられれば `ENOSYS`。拒否は維持されるが `EPERM` とは異なる）、`pid` の PID namespace 変換、supervisor の常駐メモリ（SUP-2）と syscall レイテンシ、`DenyAction` に variant を足す公開 API の変更
- **(b) `SECCOMP_RET_TRAP` とプロセス内 SIGSYS ハンドラ**: **非推奨**。根拠は 3 点。(1) ハンドラが攻撃コードと同じプロセスで動き、記録を偽造・抑止できるため証拠にならない（`escape_suite.rs` 冒頭の方針）。(2) 一次資料のとおり SIGSYS は捕捉・無視でき、execve でハンドラは既定に戻る見込みのため（execve 後の挙動は未確認。`signal(7)` で確かめる）、イメージ任意の entrypoint には載せにくい。(3) #1834 の強制終了と両立しない
- **(c) カーネルの監査（`AUDIT_SECCOMP`）**: KILL 系を含め syscall・arch・pid が取れる見込みで、fandhe-container のクラッシュや改ざんの後も残る（SEC-4 の spec が求めるフェイルセーフ経路）。一方で、`audit_enabled` の有効化、記録の読み取り権限、rootless での可否、コンテナ ID の欠落があり、`AuditSink` へは自前では届かない（auditd 等の別の読み手が要る）。3 件の `KILL_PROCESS` の syscall 情報を得られる唯一の候補になり得る
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
| launch 経路のマウントの拒否 | mount 層 | pivot 前段の失敗の記録は #1815（closed）で対応 | - |
| `mounts[]` の bind mount | mount 層 | 未配線（検証済みの型への変換が先） | #1911（open）ほか |
| seccomp・Landlock | `record_seccomp_denial`・`landlock_denial_record` | 配送経路が無い（本書の対象） | #1835（本書）→ 実装は #2023〜#2028・#2004（9 章） |
| plugin 信頼検証（`AuditLayer::PluginTrust`） | 監査つき検証ラッパー実装済み | レジストリ・本番 sink への配線は未実装 | #2013 |
| CLI・healthcheck | - | 未配線 | #495（healthcheck。open）。CLI の本番 sink は #2013 |
| コンテナ ID の付与 | `AuditRecord::container_id` | seccomp・landlock・plugin_trust への配線は未実装 | #1618（closed。型のみ）。plugin_trust への付与は #2013、seccomp は #2025 |

監査ログ・可観測性・エラー出力の統一は #653（TASK-98.2。open）が担う。本書は配送経路に限り、レコード形式の統一とは分ける。着手時に `git grep` と issue 検索で最新の状態を確かめる。

## 9. 実装 issue の分割（2026-10-15 起票。#58 配下）

粒度は 2h・1 PR・1 関心事を目安とする。各案の issue は表の右端の列。

| 案 | 内容 | crate | issue |
| -- | ---- | ----- | ----- |
| 1 | `DenyAction` の拡張と USER_NOTIF 用フィルタの構築（命令数の期待値の更新） | core | #2023 |
| 2 | listener fd の取得と受け渡し（`sys` のラッパー） | core・supervisor | #2024 |
| 3 | supervisor の listener ループ（期限・PID 変換・`record_seccomp_denial`・`EPERM` 応答） | supervisor | #2025 |
| 4 | `KILL_PROCESS` 側の記録（親の終了シグナルとカーネル監査の突き合わせ。レコード型の拡張の要否） | core・supervisor | #2004 |
| 5 | Landlock のカーネル監査対応（ABI 7 のログ制御フラグ）と縮退時の状態表示 | core | #2026 |
| 6 | 縮退時の挙動（起動拒否／警告）の実装 | core・supervisor | #2027 |
| 7 | `escape_suite.rs` の整備 | core | #2028 |

**完了の条件**に含める: ESC-01・03・06・10 の `AuditExpectation::Deferred` を `Required` へ切り替える。ESC-07・08 が試験の側で作っている記録（`record_landlock_denial`、`audit_mount_config_error` の直接呼び出し）を、本番の配送経路が出した記録に置き換える。本番 sink の出力ファイルを親が回収して照合する形を含める。

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
