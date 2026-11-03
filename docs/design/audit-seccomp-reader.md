# AUDIT_SECCOMP の読み手と CAP_AUDIT_READ の付与（判断記録）

seccomp の `KILL_PROCESS`（`unshare`・`ptrace`・`kexec_load` の 3 件）の正の記録であるカーネルの `AUDIT_SECCOMP` を、プロセス内で読む読み手を入れるか、そのために `CAP_AUDIT_READ` を付与するかの判断材料を整理する（SEC-4・ESC-06・SUP-14。参照: CORE-1・CORE-6・CORE-7・CORE-9。#2237・#2004・#2027・#2028）。

> **位置づけ**: **オーナー承認待ち**。本書は決定ではなく判断材料である。決まるまでは、プロセス内の読み手も `CAP_AUDIT_READ` も入れない現状（#2004 の判断）を保ち、権限分離の承認済みの最小権限集合（`privilege-separation.md`。#1454）を変えない。判断の窓口は #2237（open のまま。6 章に判断シート）。

## 1. 現状

- 正の記録はカーネルの `AUDIT_SECCOMP`。読むのは auditd 等の外部の読み手で、本リポのプロセスは読まない（`audit-delivery.md` 9.1）
- 補助として、本番 launcher の回収点が SIGSYS の終了を層 `exit_signal` で 1 回記録する。syscall・arch は持たない（コンテナ内の `kill(SIGSYS)` と区別できないため seccomp 由来とは断定しない）
- カーネル監査を使えない環境の検出と表示は #2027（`audit-delivery.md` 7.1）
- ESC-06（`KILL_PROCESS` の 3 件）は `Deferred` のまま。`Required` への切り替えは本件の結論の後（#2028）

## 2. 一次資料の確認結果

Linux v6.12 タグの原文で確認した（2026-10-20）。行番号ではなく関数名で示す。

### 2.1 `KILL_PROCESS` が記録される条件（`kernel/seccomp.c`）

- `seccomp_log` は `KILL_PROCESS`（と default）について `seccomp_actions_logged & SECCOMP_LOG_KILL_PROCESS` だけで記録の有無を決め、`requested`（`SECCOMP_FILTER_FLAG_LOG`）を見ない。`SECCOMP_FILTER_FLAG_LOG` が不要という 9.1 の判断は原文でも成り立つ
- `__seccomp_filter` の KILL 分岐は `seccomp_log(this_syscall, SIGSYS, action, true)` を呼んでから終了の処理に入る
- `seccomp_actions_logged` の既定値は `allow` 以外の全て（`kill_process` を含む）。sysctl の `actions_logged` から `kill_process` を外すと記録されない（#2027 の `seccomp_kill_not_logged`）

### 2.2 記録されなくなる条件（`kernel/auditsc.c`・`kernel/audit.c`・`include/linux/audit.h`・`init/Kconfig`）

- **`audit_enabled` には依存しない**: `audit_seccomp` の doc コメントは「`audit_enabled` と dummy context の状態に関係なく記録を強制する」と述べる。`audit-delivery.md` が「`audit_enabled` が無効なら出ない」としていた点は `AUDIT_SECCOMP` については誤りだった（本件で訂正）
- 対比（#2498）: 代替経路が送る `NETLINK_AUDIT` のユーザーメッセージ（`AUDIT_TRUSTED_APP`）は逆に `audit_enabled` に依存する。v6.12 `kernel/audit.c` の `audit_receive_msg` は `audit_enabled` が無効だと `AUDIT_USER_AVC` 以外を記録せず ACK 0 を返す（例外は `AUDIT_USER_AVC` だけ）。詳細は `audit-delivery.md` の一次情報の表を参照
- (a) `CONFIG_AUDITSYSCALL` が無い: `audit.h` は `audit_seccomp` を空のスタブにする。`AUDITSYSCALL` は `depends on AUDIT && HAVE_ARCH_AUDITSYSCALL` のため、`CONFIG_AUDIT=n` なら必ず無い（#2027 の `kernel_audit_not_built` と対応）
- (b) 起動時の `audit=0`: `audit_enable` が `audit_initialized = AUDIT_DISABLED` にし、`audit_log_start` が NULL を返す（`kernel_audit_disabled_at_boot` と対応）
- (c) `AUDIT_FILTER_EXCLUDE` の規則が msgtype 1326 に一致する（`audit_log_start`）。非特権では観測できない
- (d) backlog の上限超過（`audit_log_lost("backlog limit exceeded")`）。非特権では観測できない
- **読み手が居ない場合**: 記録は `kauditd_hold_skb` で `printk`（`printk_ratelimit` で間引かれる）に出る。起動時の既定（`audit_default`）が off なら、そこで捨てられる。読み手の居ないホストでは、間引かれうる dmesg の 1 行しか残らないことが多い

### 2.3 記録の中身（`audit_log_task`・`audit_seccomp`）

- `auid uid gid ses`（`init_user_ns` で変換）、`pid=`（`task_tgid_nr(current)`。初期 PID namespace の TGID）、`comm`（untrusted 扱い）、`exe`、続けて `sig= arch= syscall= compat= ip= code=`
- v6.12 の `audit.c`・`auditsc.c` には `contid` が無い。コンテナの識別子は記録に入らない。`exit_signal` の補助レコード（回収側の PID namespace の pid）と突き合わせるには namespace の変換が要る

### 2.4 rootless での記録

- **生成**: `seccomp_log`・`audit_seccomp` に user namespace や権限を見る分岐は無い。rootless のコンテナでも 2.2 の (a)〜(d) に当たらなければ記録は生成される
- **読み出し**: `audit_multicast_bind` は `capable(CAP_AUDIT_READ)`（初期 user namespace）で検査し、`kauditd_send_multicast_skb` は `audit_get_sk(&init_net)` に送る。user namespace 内の root では bind できず、購読者は初期 network namespace に居る必要がある。特権ランチャー（CORE-6）が無い純粋な rootless では、プロセス内の読み手は成り立たない

## 3. 選択肢

### A. 付与しない（推奨）

外部の auditd 等に任せる。残るのは、#2027 の 3 つの観測による縮退表示と、`exit_signal` の補助記録（syscall は残らない）。最小権限集合を変えない。

### B. 付与する

要るもの:

- `privilege-separation.md` 4 章の表へ `CAP_AUDIT_READ` を足す（長寿命の supervisor が稼働中ずっと持つ）。特権ランチャーの file capability の集合と `scripts/install-privileged-launcher.sh` を更新する
- supervisor の `sys` に、`NETLINK_AUDIT` のソケット・`NETLINK_ADD_MEMBERSHIP` での READLOG 購読を行う薄いラッパー（事前承認の範囲の `unsafe`。受信の長さの上限と期限〔REPAIR-5〕を持つ）を足す。security-auditor 観点のレビューが必須
- パーサー（`comm`・`exe` は untrusted。固定語彙へ写し、ホスト由来の文字列を転記しない）と、初期 PID namespace の pid の変換、レート制限
- 権限が無いときの縮退を #2027 の語彙へ足す。ESC-06 を `Required` に切り替える（#2028）

不利な点:

1. READLOG は**ホスト全体の監査ストリーム**を購読者すべてに配る。コンテナごとに supervisor を置く設計（CORE-1・SUP-1）では、N 個の supervisor がホストの全記録を受け取り、コンテナの範囲を超えた情報取得になる。CPU とメモリの負担も CORE-7・CORE-9 に効く
2. 純粋な rootless では使えないため、縮退の判定と表示（#2027）はどちらにしても要る
3. `contid` が無く pid に頼るため、pid の再利用による競合が残る

### 参考: C（中央の 1 プロセスが購読して振り分ける）

中央の常駐デーモンになり CORE-1・D-19 と食い違うため採らない。

## 4. 決定後の作業

- A: 位置づけを「決定」に変え、`audit-delivery.md` 9.1 の「承認事項として残す」を確定の文言に変える。ESC-06 の扱いは spec（ESC-06・SEC-4 の受け入れ範囲）との整合をオーナーが判断する
- B: 3 章の「要るもの」を実装 issue に分ける

## 5. 未確認事項・再検証条件

| 項目 | 状態 |
| ---- | ---- |
| `HAVE_ARCH_AUDITSYSCALL` の有無（`CONFIG_AUDIT=y` でも無いアーキテクチャは loginuid で見分けられない） | v6.12 の `arch/x86/Kconfig`・`arch/arm64/Kconfig` に `select HAVE_ARCH_AUDITSYSCALL` があることを確認（2026-10-21）。x86_64・aarch64 では問題にならない |
| Landlock の `AUDIT_LANDLOCK_*` が `audit_enabled` に依存するか | v6.15 の `security/landlock/audit.c` に `if (!audit_enabled)` の早期 return がある（拒否の記録と domain の記録の関数。2026-10-21 確認）。`AUDIT_SECCOMP` と違い依存する。`audit_enabled` の実行時の値は非特権では確かめられない |
| (c) exclude 規則・(d) backlog 超過 | 非特権では観測できない |
| `printk_ratelimit` による間引きの実際 | 未確認 |
| 実機での `seccomp_kill_audit --ignored`（root と auditd が前提） | 人間の担当 |

## 6. 承認事項（判断シート）

承認の窓口は #2237。すべて**未決**（承認済みのものは無い）。返信は「D1: 推奨どおり / D2: …」のように番号で答えられる。

| 番号 | 判断事項 | 選択肢 | 推奨 | 影響 | 判断 |
| ---- | -------- | ------ | ---- | ---- | ---- |
| D1 | プロセス内の読み手と `CAP_AUDIT_READ`（3 章） | A 付与しない / B 付与する | A | A: 最小権限集合は変わらず、残るのは #2027 の縮退表示（`kernel_audit_not_built`・`kernel_audit_disabled_at_boot`・`seccomp_kill_not_logged`・`probe_failed`）と `exit_signal` の補助記録（syscall なし）。B: 3 章の「要るもの」を実装 issue に分ける（親 #2308） | 未決 |
| D2 | D1 が A のときの ESC-06 の監査の扱い | `Deferred` を保つ / spec の ESC-06・SEC-4 の受け入れ範囲を見直す（spec リポ側の課題）/ opt-in のカーネル監査の段で照合する（auditd が前提。Landlock の `FANDHE_CONTAINER_TEST_KERNEL_AUDIT=1` と同じ形） | なし（spec と関わるためオーナー判断） | #2028 が残した ESC-06 の `Required` 化の可否 | 未決 |
| D3 | 子孫と exec コマンドの子孫の SIGSYS 終了が親から観測できない残り（`audit-delivery.md` 9.1）を追う issue | 起票する / spec の受け入れ範囲の見直しに含める | なし | 追跡の置き場 | 未決 |
| D4 | D1 が B のときだけ: READLOG がホスト全体の監査ストリームを各 supervisor に配ること（CORE-1・SUP-1・CORE-7・CORE-9）を受け入れるか | 受け入れる / 受け入れない（= A） | なし（D1 に従属） | 3 章の不利な点 1 | 未決 |

決まった後の作業は 4 章のとおり。この文書の更新時点では、起票も ESC-06 の切り替えも行っていない。
