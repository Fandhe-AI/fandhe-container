# 範囲写像の書き込み先を専用の holder プロセスへ分ける設計

> **位置づけ**: 実装済みの設計記録（#2374。CORE-6・SEC-5・SEC-1・CORE-2・REPAIR-5。TASK-40.2・#2243 の続き）。実機（AppArmor の `restrict_unprivileged_userns` 下・`newuidmap` 経由の範囲写像）での確認は人間担当として残る（末尾）。

## 1. 背景

`newuidmap` / `newgidmap` は、写像の対象プロセスの `/proc/<pid>`（`fd:N` 形式でも fstat の所有者）が呼び出し元の uid と一致することを確かめる。non-dumpable なプロセスの `/proc/<pid>` は root 所有に見えるため、この検査に通らない。所有者はカーネルの `task_dump_owner` が `mm->user_ns`（exec した時点の user namespace）で決めるので、`unshare` した後も事情は変わらない。

PR #2243 の実装では、写像の対象を launcher の中間プロセス I 自身にしていたため、I が書き込みの間だけ `PR_SET_DUMPABLE=1` にして握手の後に戻していた。この窓の間、同じ uid のホスト側プロセスは I を ptrace したり `/proc/<I>/fd` を読んだりできる（Yama の `ptrace_scope` が 0 なら誰でも、1 なら祖先だけ）。I は次を持っている: C（supervisor）への報告 pipe（`K <pid>` / `R ...`）、状態 pipe、seccomp listener の socketpair、Landlock の ruleset、起動識別子。偽の報告・listener の偽造・seccomp / Landlock を飛ばした PID 1 の作成といった改ざんにつながるため、窓そのものをなくす。

## 2. 案の比較

| 案 | 内容 | 判断 |
| -- | ---- | ---- |
| A | 窓を許容する | I の fd と制御フローが露出するため不採用 |
| B | 写像の書き込み先を使い捨ての holder に分ける | **採用** |
| C | `fd:N` 等で helper 側が回避する | 所有者の検査は fd でも同じため不可能 |
| D | 特権ランチャーが写像を書く | `CAP_SETUID` が増え、[privilege-separation.md](./privilege-separation.md) の範囲外 |

## 3. 採用案（holder）

I = 呼び出しプロセス（終始 non-dumpable）、U = holder、M = mapper。

```text
I ─ fork ─> U : fd 3 以上を閉じる → 親が I か確認（PDEATHSIG は設定しない。#2376）
              → unshare(CLONE_NEWUSER) → dumpable にする(U だけ) → READY(固定 3 バイト)
              → RELEASE / EOF（I・M・全 helper が socket の相手側を閉じる）/ 期限まで待つ → _exit
I ─ READY を期限つきで受ける
I ─ fork ─> M : go を待つ → /proc/<U> の fd を開く → 「M の親が I」かつ「U の ppid(fd 経由の stat)が I」を確認
              → U の uid_map / gid_map を書く(newuidmap / newgidmap には U の pid の数値。#2376) → 応答
I ─ go を送り M の応答を期限つきで受ける(2 × timeout + 1s)
I ─ U の pidfd で setns(CLONE_NEWUSER) → /proc/self/ns/user が U のものであること・euid/egid == 0 を確認
I ─ RELEASE を U へ送り、U と M を回収 → 残りの namespace を unshare(従来どおり)
```

- 新しい `unsafe` は無い。既存の sys ラッパー（`fork_single_threaded*`・`close_fds_from_except`・`set_dumpable_user`・`setns_pidfd`・`is_dumpable`・`set_non_dumpable`）だけを使う。`set_dumpable_user` を呼ぶのは U の fork 子だけで、I の経路には dumpable を上げる呼び出しが無い。
- I が user namespace に `setns` できる根拠: I は親の user namespace にいて euid が U の namespace の所有者と一致するため、参加先の全 capability を持つ。単一スレッドで、`fs` も共有していない（`userns_install` の条件）。参加先の同一性は、参加前に `/proc/<U>/ns/user` の (dev, ino) を控え、参加後の `/proc/self/ns/user` と一致することで確かめる（fail-closed）。
- 呼び出し元が non-dumpable だった場合は、参加の後にも `set_non_dumpable` で戻す方向にだけ動かす（カーネルの資格情報の更新による dumpable の変化に備える）。公開 API（`isolate_rootless_subordinate`）も同じ経路に揃えたため、「non-dumpable の呼び出し元を fork 前に拒否する」前提条件（#2243）は不要になり削除した。
- 応答は REPAIR-2 に沿った固定長フレーム（`MapperReply` の 3 バイト、RELEASE は 1 バイト定数）。READY・go・応答・RELEASE の待ちはすべて期限つき（REPAIR-5）。U は RELEASE を `3 × timeout + 5s` まで待つ。I が死んだ場合は、socket の相手側を持つ M と全 helper（stdin に複製を持つ）が終了して EOF になるまで終わらない。期限を過ぎても相手側が残っていれば（helper の停止等）EOF まで待ち続ける（PDEATHSIG は持たない。helper より先に終了して U の pid を解放しないため。待つのは使い捨ての U だけで、I・C はこの待ちに依存しない。#2376）。
- M の TOCTOU（SEC-5）: 対象が「親の pid」から「兄弟の U の pid」に変わる。M は先に `ProcHandle` で `/proc/<U>` の fd を開き、その後で M 自身の親と U の ppid がともに I であることを確かめる。I が生きていて U が I の未回収の子なら pid は再利用されておらず、fd は以後同じプロセスを指す。
- helper へ渡す対象（#2376）: ubuntu-latest の shadow 4.13 の `newuidmap` / `newgidmap` は `fd:N` 形式を受け付けないため、M は U の pid を数値で渡し、各 helper の stdin に U の socket の相手側の複製を持たせる。helper の書き込み先は fd で固定されないので、U の pid が解放（回収）されるのは helper が止まった後に限る（U は全員の EOF まで終了せず、I・C が U を kill するのは下の後始末で helper を止めた後）。成功時は M が helper を回収してから応答する。公開 API の `apply_id_maps_to` は対象の生存を保証できないため `fd:0` のまま（`fd:N` 未対応の helper では失敗する。fail-closed）。
- 失敗時の後始末（CORE-2・CORE-6・SEC-5）: I は先に M へ `SIGKILL`（回収しない）、続けて M のプロセスグループ（M が写像の前に `setsid` で作り、helper が継承する）へ `SIGKILL` を送り、M のセッションの全員（helper を含む）がゾンビ化するか消えたことを期限つきで確かめてから U を kill・回収する（`SIGKILL` は送達と終了が同時でなく、実行中の syscall は `kill(2)` の後も完了し得るため）。グループ宛てが失敗した場合や終了を確かめられない場合は U を kill だけして回収しない（ゾンビの間は pid が保たれる。fail-closed）。M は公開 API では kill・回収し、launcher では回収せず、C の識別子の再探索が helper ごと回収する。U は I の `comm`（起動識別子）を引き継ぎ exec しないため、I が報告せずに死んでも C の再探索で見つけられる。再探索は、識別子つきの全候補（U・M・PID 1）の子孫（helper）を止めてゾンビ化を確かめてから錨を回収し、1 つでも保持になればどの錨も回収しない（U を helper より先に回収しない）。

## 4. 残る影響と許容の根拠

- U は I のメモリの COW 複製を持つ。dumpable な間は、祖先（Yama=1）または同じ uid の任意のプロセス（Yama=0）が U のメモリを読みうる。これは従来 I について生じていた露出と同じ範囲に収まり、fd と制御フローの露出は無くなる（U は fd 3 以上を閉じ、U 側の socket しか持たない）。
- U を乗っ取っても、namespace の所有者（同じ uid）が初めから持つ権限を超えるものは得られない。範囲写像は同じ利用者が `newuidmap` で得られるものと同じで、写像は write-once かつ M が読み戻しを計画と照合するため、先回りの書き込みは失敗になる。I は non-dumpable で `mm->user_ns` は初期の namespace のため、U の namespace の中からは ptrace できない。
- U は、pidfd 経由の `setns` が対象の dumpable を要するかを確認できていないため、I の参加が済む（RELEASE）まで dumpable のままにする。写像の直後に non-dumpable へ戻す最適化は、一次情報で確かめた後の任意の改善とする。

## 5. 試験

- 単体（`rootless.rs`）: mapper が「対象の親が期待した I でない」ことを `FailedPrecondition` で拒否すること、fd 経由の ppid が `parent_id()` と一致すること。
- 結合（`crates/core/tests/unshare_isolation.rs`・実機前提）: 自身を `--subordinate-non-dumpable` で再起動した子が non-dumpable のまま分離し、user namespace 内の uid 0・`uid_map` / `gid_map` の読み戻し・namespace の変化・子プロセス 0 件・呼び出し後も non-dumpable を具体値で照合する。親（I の祖先）は実行中の `/proc/<子>` の所有者 uid を標本し、標本が 1 件以上で全件が 0（non-dumpable は root 所有に見える）であることを照合する。CI では `platform-ci` の ubuntu が既存どおり `--ignored` で実行する。

## 6. 実機で確かめる事項（人間担当）

- AppArmor の `restrict_unprivileged_userns` の下で、`setns` で参加した I の挙動。
- `FANDHE_CONTAINER_TEST_ID_HELPER=1` の `rootless_launch` の helper シナリオと `production_launcher` のシナリオ I（`newuidmap` 経由の範囲写像が holder に対して成功し、PID 1 の `uid_map` が従来と一致すること）。

出典: Linux `user_namespaces(7)`・`setns(2)`・`proc(5)`（`/proc/<pid>` の所有者と dumpable）、shadow の `newuidmap(1)`。カーネル実装（`userns_install`・`task_dump_owner`）の原文での再確認は実機確認と合わせて行う。
