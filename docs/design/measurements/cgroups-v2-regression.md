# cgroups v2 実効性の回帰テスト実測レポート

委譲済み cgroup v2 上で「子 cgroup 作成 → 自プロセス退避 → controller 有効化」の順序が守られ、`memory.max`（64 MiB）・`memory.swap.max=0` の下で 300 MiB を確保したプロセスが OOM Kill（終了コード 137）されることを、fandhe-container 自身の実装で確認した記録。PoC の Linux 実機（linux-real-machine）の結果を回帰テストとして固定したもの。**2026-10-12 に実測済み（issue #170）。**

- 対象ビヘイビア: CORE-3（cgroups v2 の実効性）。関連: CORE-4・SEC-1・CORE-5・REPAIR-3・REPAIR-5・REPAIR-12
- 関連タスク: TASK-36（#168。共同）・TASK-36.1（#169。本テストと本書の雛形）・TASK-32（#153。`DelegatedCgroup`・`ContainerCgroup` の実装）
- 対象マイルストーン: MS-2 Phase 3
- ステータス: 実測済み（2026-10-12。issue #170。妥当性の判断も済み）

## 計測方法

テスト本体は [`crates/core/tests/cgroups_regression.rs`](../../../crates/core/tests/cgroups_regression.rs)（`harness = false`・実機前提）。`-- --ignored` 指定時のみ実行し、CI には組み込まない（`AGENTS.md`）。

```text
cargo test -p fandhe-container-core --test cgroups_regression --no-run
systemd-run --user --scope -p Delegate=yes <target/debug/deps/cgroups_regression-XXXX> --ignored
```

- 必要環境: 非特権ユーザーに委譲された cgroup v2 サブツリー（`memory`・`cpu` が委譲済み）・swap accounting 有効（無効だと `memory.swap.max` の書き込みが失敗する）・root もしくは非特権 user namespace を許可するホスト（`kernel.apparmor_restrict_unprivileged_userns=1` では user namespace を作れず OOM 検証が実行できない）・実行プロセスの `oom_score_adj` が -1000 でないこと（-1000 だと OOM Kill 対象にならず検証が成立しない。実行前に `cat /proc/self/oom_score_adj` で確認する）
- 成功時の出力: `cgroups_regression: CORE-3 cgroup ordering and OOM kill verified`（終了コード 0）

## 計測環境

| 項目 | 値 |
| ---- | ---- |
| 計測対象コミット | `3b15c98ba5ee096564ff253ac359d3e220c2ebbc` |
| 実施日（UTC） | 2026-10-12 |
| 環境 | Linux x86_64・カーネル 7.0.0-34-generic・Ubuntu 26.04.1 LTS・systemd 259。cgroup v2。委譲方法は `systemd-run --user --scope -p Delegate=yes`（委譲されていた controller は `cpu memory pids`）。KVM の仮想マシン上 |
| 実行ユーザー | 非 root（sudo を使わずに実行） |
| swap accounting | あり（スコープに `memory.swap.max` が存在。swap デバイス自体は無効） |
| `oom_score_adj` | 0 |
| 非特権 user namespace | 既定では AppArmor の制限（`kernel.apparmor_restrict_unprivileged_userns=1`）で作れないため、実測のあいだだけ一時的に `0` にし、終了後に `1` へ戻した |
| 実行回数 | 1 回ごとに新しいスコープで 3 回実行。3 回とも終了コード 0 で成功行を確認。失敗・再実行は無し |
| 後始末 | 子 cgroup と一時 rootfs は残っていない |

## 実測結果

この試験は成功時に 1 行しか出力しない。各段階の値は「試験が期待値を assert で照合して通った」ことで確かめており、実数（たとえば `oom_kill` の値）は取れていない。試験は改造していない。

### 順序の検証

| 段階 | 確認内容 | 観測値 |
| ---- | -------- | ------ |
| `prepare` 前 | `/proc/self/cgroup` が `0::<委譲パス>`・子 cgroup なし・`subtree_control` に `memory`・`cpu` なし | 3 回とも照合に合格（左の確認内容を試験の assert が照合する。値の表示は無い） |
| `prepare` 前（負の対照） | `+memory` の書き込みが EBUSY（16）で失敗 | 3 回とも照合に合格（左の確認内容を試験の assert が照合する。値の表示は無い） |
| `prepare` 後 | 子の `cgroup.procs` が空・自プロセスが `fc-runtime` に退避・親の `cgroup.procs` が空・controller は未有効 | 3 回とも照合に合格（左の確認内容を試験の assert が照合する。値の表示は無い） |
| `enable_controllers` 後 | 戻り値と `cgroup.subtree_control` に `memory`・`cpu`・子に `memory.max` が出現 | 3 回とも照合に合格（左の確認内容を試験の assert が照合する。値の表示は無い） |

### OOM Kill の検証

| 項目 | 期待値 | 観測値 |
| ---- | ------ | ------ |
| `memory.max` / `memory.swap.max`（読み戻し） | `67108864` / `0` | 3 回とも合格。`67108864` / `0`（戻り値と実ファイルの読み戻しを照合） |
| `ChildExit` | `Signaled(9)` | 3 回とも合格。`Signaled(9)` |
| シェル慣例の終了コード（128 + 9） | `137` | 3 回とも合格。`137` |
| `memory.events` の `oom_kill` | `1` 以上 | 3 回とも合格。1 以上を照合（実数は未取得） |
| `memory.events` の `oom` | `1` 以上 | 3 回とも合格。1 以上を照合（実数は未取得） |
| 子 cgroup の削除 | 成功 | 3 回とも合格。成功 |

## 結論

委譲された cgroup v2 の上で、順序（子 cgroup 作成 → 自プロセス退避 → controller 有効化）と、`memory.max` 64 MiB・`memory.swap.max=0` の下での OOM Kill（`Signaled(9)`・終了コード 137）を、fandhe-container の実装で 3 回とも確認した。CORE-3 の回帰確認として足りる。

制約:

- `oom` / `oom_kill` の実数は取れていない（1 以上の照合のみ）
- aarch64 では実測していない（PoC は aarch64、今回は x86_64）

## 妥当性判断（人間担当・TASK-36）

- 判断者・日付: オーナー、2026-10-12（issue #170 に記録）
- 判断:
  - 合格基準「`oom`・`oom_kill` が 1 以上」を追認する。300 MiB の確保中に OOM 判定が複数回起き得るため、2 以上でも失敗としない。`= 1` を要求すると正常でも失敗し得る
  - 観測点が CgroupJoin 段のフックの中であることは、回帰確認として足りる。制限の証跡が無い間の exec は SEC-1・CORE-5 の fail-closed で拒否されるため、entrypoint を観測点にできない
  - spec の CORE-3 の期待（`oom=1 oom_kill=1`。PoC の観測値）を「1 以上」に揃える修正は、spec リポジトリ側で行う
