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
              → 制御フレーム(5 バイト)を待つ: MapperPid を 1 回受けて M の /proc/<M> を錨にする
              → RELEASE / EOF（I・M・全 helper が socket の相手側を閉じる）/ 期限まで待つ
              → 期限切れなら、終わる前に M のセッションへ SIGKILL し、EOF を drain_wait まで待つ(#2551) → _exit
I ─ READY を期限つきで受ける
I ─ fork ─> M : go を待つ → /proc/<U> の fd を開く → 「M の親が I」かつ「U の ppid(fd 経由の stat)が I」を確認
              → U の uid_map / gid_map を書く(newuidmap / newgidmap には U の pid の数値。#2376) → 応答
I ─ M の pid を MapperPid フレームで U へ送る(go の前。書けなければ握手を失敗にする。#2551)
I ─ go を送り M の応答を期限つきで受ける(2 × timeout + 1s)
I ─ U の pidfd で setns(CLONE_NEWUSER) → /proc/self/ns/user が U のものであること・euid/egid == 0 を確認
I ─ RELEASE を U へ送り、U と M を回収 → 残りの namespace を unshare(従来どおり)
```

- 新しい `unsafe` は無い。既存の sys ラッパー（`fork_single_threaded*`・`close_fds_from_except`・`set_dumpable_user`・`setns_pidfd`・`is_dumpable`・`set_non_dumpable`）だけを使う。`set_dumpable_user` を呼ぶのは U の fork 子だけで、I の経路には dumpable を上げる呼び出しが無い。
- I が user namespace に `setns` できる根拠: I は親の user namespace にいて euid が U の namespace の所有者と一致するため、参加先の全 capability を持つ。単一スレッドで、`fs` も共有していない（`userns_install` の条件）。参加先の同一性は、参加前に `/proc/<U>/ns/user` の (dev, ino) を控え、参加後の `/proc/self/ns/user` と一致することで確かめる（fail-closed）。
- 呼び出し元が non-dumpable だった場合は、参加の後にも `set_non_dumpable` で戻す方向にだけ動かす（カーネルの資格情報の更新による dumpable の変化に備える）。公開 API（`isolate_rootless_subordinate`）も同じ経路に揃えたため、「non-dumpable の呼び出し元を fork 前に拒否する」前提条件（#2243）は不要になり削除した。
- フレームは REPAIR-2 に沿った固定長。M の応答は `MapperReply` の 3 バイト、I から U への制御は `HolderControl` の 5 バイト `[tag, pid の u32 big-endian]`（`MapperPid` = 2..=i32::MAX、`Release` の payload は 0）で、完全一致のみ受ける。issue（#2551）の案は 4 バイトの pid フレームだったが、1 バイトの RELEASE と同じ socket に別形式を混ぜると壊れた値を表現できるため、tag 付きの 1 種類の固定長に揃えた。書き込むのは I だけ（M・helper は複製を持つが書かない）で、順序は「MapperPid（M の fork 直後・go の前）→ 応答待ち → Release」。READY・go・応答・Release の待ちはすべて期限つき（REPAIR-5）。U は Release を `3 × timeout + 5s` まで待つ。I が死んだ場合は、socket の相手側を持つ M と全 helper（stdin に複製を持つ）が終了して EOF になるか、期限で終わる（PDEATHSIG は持たない。helper の実行中に U の pid を解放しないため。#2376）。
- **期限切れの後始末（#2551・CORE-6・SEC-5・REPAIR-5）**: 待ちを有限にした結果、I が死んだうえで helper が期限を超えて止められていると、U が先に終わって pid が解放され、再開した helper が再利用された pid へ書く残余があった。これを閉じるため、U は期限が来たとき**自分が終わる前に** M のセッション（`kill(-M, SIGKILL)`。M が `setsid` で作り helper が継承する）を止め、EOF を `drain_wait`（5s）まで待ってから終わる（生存は最長 `release_wait + drain_wait`）。SIGKILL は止められたプロセスも終わらせるので、利用者が SIGSTOP で作れる残余は閉じる。kill の宛先は MapperPid を受けた時点で `/proc/<M>` の fd を開いて固定し（開いた**後**にM の ppid が U の現在の親と一致することを確かめる。I が死んでも U と M は同じ親へ再親付けされる）、kill の直前に fd 経由でセッション ID が M の pid であることを確かめる。ID が違えば（M が `setsid` の前＝helper を作っていない）、錨が無ければ、読めなければ kill しない（fail-closed）。M が回収済み（fd 経由の読みが `ESRCH`）なら、送る直前に EOF を確かめ直し、EOF でなければ（生きている helper がセッションを継承している）kill する。根拠: 期限が来ても EOF でないのは相手側の誰かが生きているときだけで、I が生きていれば I は U を kill してから M を回収するため M の pid は保たれる。
- 対応案 1（helper が `fd:N` に対応していれば `fd:0` を使う）は採らない。対応可否の確実な判定が無く、usage エラーで数値 pid へ退避すると失敗の原因を区別できず fail-closed が崩れるため。公開 API の `apply_id_maps_to` は `fd:0` のまま。
- 残る窓（#2551）: (a) 期限の直前に最後の helper が終わり、その pid が `setsid` した無関係なプロセスへ再利用されるまでの極小の TOCTOU（kill の直前の EOF の確かめ直しと、セッション ID の照合で縮める）。(b) SIGKILL の後も `drain_wait` を超えて終わらない helper（カーネル内の割り込み不能な待ち等）。この場合 U は終了し、残余は残る。どちらも利用者が SIGSTOP 等で作れる範囲は閉じている。届く先は同じ利用者のプロセスに限られ（`kill(2)` は実 uid / saved uid の照合）、新しい権限は与えない。
- M の TOCTOU（SEC-5）: 対象が「親の pid」から「兄弟の U の pid」に変わる。M は先に `ProcHandle` で `/proc/<U>` の fd を開き、その後で M 自身の親と U の ppid がともに I であることを確かめる。I が生きていて U が I の未回収の子なら pid は再利用されておらず、fd は以後同じプロセスを指す。
- helper へ渡す対象（#2376）: ubuntu-latest の shadow 4.13 の `newuidmap` / `newgidmap` は `fd:N` 形式を受け付けないため、M は U の pid を数値で渡し、各 helper の stdin に U の socket の相手側の複製を持たせる。helper の書き込み先は fd で固定されないので、U の pid が解放（回収）されるのは helper が止まった後に限る（U は全員の EOF まで終了せず、I・C が U を kill するのは下の後始末で helper を止めた後）。成功時は M が helper を回収してから応答する。公開 API の `apply_id_maps_to` は対象の生存を保証できないため `fd:0` のまま（`fd:N` 未対応の helper では失敗する。fail-closed）。
- 失敗時の後始末（CORE-2・CORE-6・SEC-5）: I は先に M へ `SIGKILL`（回収しない）、続けて M のプロセスグループ（M が写像の前に `setsid` で作り、helper が継承する）へ `SIGKILL` を送り、M のセッションの全員（helper を含む）がゾンビ化するか消えたことを期限つきで確かめてから U を kill・回収する（`SIGKILL` は送達と終了が同時でなく、実行中の syscall は `kill(2)` の後も完了し得るため）。グループ宛てが失敗した場合や終了を確かめられない場合は U を kill だけして回収しない（ゾンビの間は pid が保たれる。fail-closed）。M は公開 API では kill・回収し、launcher では回収せず、C の識別子の再探索が helper ごと回収する。U は I の `comm`（起動識別子）を引き継ぎ exec しないため、I が報告せずに死んでも C の再探索で見つけられる。再探索は、識別子つきの全候補（U・M・PID 1）の子孫（helper）を止めてゾンビ化を確かめてから錨を回収し、1 つでも保持になればどの錨も回収しない（U を helper より先に回収しない）。

## 4. 残る影響と許容の根拠

- U は I のメモリの COW 複製を持つ（exec しない fork のため）。`unshare` から RELEASE までの U は dumpable なので、祖先（Yama=1）または同じ uid の任意のプロセス（Yama=0）が U を ptrace したり `/proc/<U>/mem` を読んだりできる。fd と制御フローの露出は無くなる（U は fd 3 以上を閉じ、U 側の socket しか持たない）が、メモリの露出は残る。
- **呼び出し元の契約（#2546・CORE-6・SEC-5）**: `isolate_rootless_subordinate` を呼ぶプロセス（本番は supervisor C の fork 子の I。公開 API の利用者を含む）は、同じ uid のホスト側プロセスに読まれて困る機密をメモリに置いたまま呼んではならない。U が継承するのは、呼び出し時点の呼び出しプロセスのメモリ全体である。
- **メモリの棚卸し（#2546。grep による確認で、網羅の保証ではない）**: 分離計画・写像・Landlock の規則・起動識別子・config 由来の `process.args` / `env` は同じ利用者が bundle の `config.json` から元々読める範囲にある。レジストリの資格情報を保持する経路は core / supervisor の `src` に見当たらなかった。**一方、注入ファイル（`InjectedFileSet`。secret の内容を `InjectedContent` として持つ。`container_options/secrets.rs`）が起動計画の一部として I のメモリにある可能性が高く、これは機密に当たりうる**。注入は分離後の PID 1 の準備で使うため fork 前にゼロ化できない。解消には、注入ファイルの内容を分離の後に取得する・または写像を exec 型の専用プロセスへ切り出す、といった設計変更が要り、本 issue の範囲を超える（別 issue で追跡する）。それまでは上記の契約と、dumpable な窓が写像の間から RELEASE までに限られること、および同じ uid の攻撃者は secret の元ファイルを初めから読める利用者であることを許容の根拠とする。
- **特権ランチャー経由の capability**: C が ambient / permitted で持つ capability は、U の `unshare(CLONE_NEWUSER)` の後は新しい user namespace を基準にした権限になり、親の namespace に対する権限としては残らない（`set_cred_user_ns`。下の原文確認）。unshare の前の U は I から non-dumpable を受け継いでいる。
- U を乗っ取っても、namespace の所有者（同じ uid）が初めから持つ権限を超えるものは得られない。範囲写像は同じ利用者が `newuidmap` で得られるものと同じで、写像は write-once かつ M が読み戻しを計画と照合するため、先回りの書き込みは失敗になる。I は non-dumpable で `mm->user_ns` は初期の namespace のため、U の namespace の中からは ptrace できない。
- **写像の直後に U を non-dumpable へ戻す案は成立しない（原文で確認済み。#2546）**: I の `setns_pidfd` は `validate_nsset` → `ptrace_may_access(tsk, PTRACE_MODE_READ_REALCREDS)` を通り、対象が dumpable でないと `mm->user_ns`（U は exec せず `mm->user_ns` は初期の namespace）に対する `CAP_SYS_PTRACE` を要求する。rootless の I はこれを持たず `EPERM` になる。`/proc/<U>/ns/user` を開く経路も同じ ptrace 検査（FSCREDS）を通る。そのため U は RELEASE まで dumpable のままにする（窓は最小化済み）。
- **`fs.suid_dumpable=1` の前提（#2546）**: I の `setns` は `commit_creds` を通るが、dumpable を `suid_dumpable` へ書き換える条件（euid / egid / fsuid / fsgid の変化、または `!cred_cap_issubset(old, new)`）に当たらない。ids は変わらず、参加先は I の uid が所有する子 user namespace（親が I の現在の namespace）で、`cred_cap_issubset` は「別 namespace では `set_ns == subset_ns->parent` かつ `owner == set->euid` なら true」の枝で true になる。よって I は `suid_dumpable` の値によらず non-dumpable のまま。参加後の `set_non_dumpable` は多層防御として残す。

## 4.1 カーネル原文での確認（Linux v6.12。#2546）

出典はいずれも Linux v6.12 のソース（git.kernel.org の stable ツリーの tag）。本文の長い引用はせず、結論だけを書く。

| 対象 | 確認した結論 |
| ---- | ------------ |
| `kernel/user_namespace.c` `userns_install` | 同じ namespace・複数スレッド・`fs` 共有を拒否し、参加先で `CAP_SYS_ADMIN` を要する（子 namespace の所有者は持つ）。`set_cred_user_ns` で資格情報の user namespace を替える（kuid は変わらない） |
| `kernel/cred.c` `commit_creds` / `cred_cap_issubset` | dumpable の書き換えは id の変化か `!cred_cap_issubset` のときだけ。親が旧 namespace で所有者が旧 euid の子 namespace への参加は subset と判定され、書き換わらない |
| `kernel/nsproxy.c` `setns` / `validate_nsset` | pidfd 経由は対象に `ptrace_may_access(PTRACE_MODE_READ_REALCREDS)` を要求する |
| `kernel/ptrace.c` `__ptrace_may_access` | uid が一致しても、対象の `get_dumpable(mm) != SUID_DUMP_USER` なら `mm->user_ns` への `CAP_SYS_PTRACE` を要する |
| `fs/proc/base.c` `task_dump_owner` | non-dumpable な対象の `/proc/<pid>` は `mm->user_ns` の root 所有に見える（`newuidmap` の所有者検査が通らない理由） |

## 5. 試験

- 単体（`exec.rs`）: 握手が成功した後の待ちが失敗しても子を kill して回収すること(`reap_after_handshake`。#2546)。
- 単体（`rootless.rs`。#2551）: `HolderControl` の往復と壊れた値の拒否、`holder_await_release` の Release / EOF / 期限切れ（錨なしは kill しない・setsid 前は kill しない・自身と親の pid は錨にしない・kill は 1 回・SIGSTOP で止めた `setsid` 済みの子を本番の kill で終わらせて EOF に届く・`drain_wait` で戻る）。
- 単体（`rootless.rs`）: holder の失敗が固定 3 バイトの応答と `diag` の 1 行になること(`report_holder_outcome`。#2546)。mapper が「対象の親が期待した I でない」ことを `FailedPrecondition` で拒否すること、fd 経由の ppid が `parent_id()` と一致すること。
- 結合（`crates/core/tests/unshare_isolation.rs`・実機前提）: 自身を `--subordinate-non-dumpable` で再起動した子が non-dumpable のまま分離し、user namespace 内の uid 0・`uid_map` / `gid_map` の読み戻し・namespace の変化・子プロセス 0 件・呼び出し後も non-dumpable を具体値で照合する。親（I の祖先）は実行中の `/proc/<子>` の所有者 uid を標本し、標本が 1 件以上で全件が 0（non-dumpable は root 所有に見える）であることを照合する。CI では `platform-ci` の ubuntu が `--ignored` で実行し、成功行 2 本(`full isolation verified (root=false)` と `subordinate isolation kept the caller non-dumpable`)をログで照合する(#2546)。

## 6. 実機で確かめる事項（人間担当）

- AppArmor の `restrict_unprivileged_userns` の下で、`setns` で参加した I の挙動。
- `FANDHE_CONTAINER_TEST_ID_HELPER=1` の `rootless_launch` の helper シナリオと `production_launcher` のシナリオ I（`newuidmap` 経由の範囲写像が holder に対して成功し、PID 1 の `uid_map` が従来と一致すること）。

出典: Linux `user_namespaces(7)`・`setns(2)`・`proc(5)`（`/proc/<pid>` の所有者と dumpable）、shadow の `newuidmap(1)`。カーネル実装は v6.12 の原文で確認済み（§4.1）。
