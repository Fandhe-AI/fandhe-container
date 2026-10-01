# cgroups v2 実効性の回帰テスト実測レポート（雛形）

委譲済み cgroup v2 上で「子 cgroup 作成 → 自プロセス退避 → controller 有効化」の順序が守られ、`memory.max`（64 MiB）・`memory.swap.max=0` の下で 300 MiB を確保したプロセスが OOM Kill（終了コード 137）されることを、fandhe-container 自身の実装で確認した記録の雛形。node4 の PoC（linux-real-machine）の結果を回帰テストとして固定したもの。**結果欄は人間が実機で実行して記入する。**

- 対象ビヘイビア: CORE-3（cgroups v2 の実効性）。関連: CORE-4・SEC-1・CORE-5・REPAIR-3・REPAIR-5・REPAIR-12
- 関連タスク: TASK-36（#168。共同）・TASK-36.1（#169。本テストと本書の雛形）・TASK-32（#153。`DelegatedCgroup`・`ContainerCgroup` の実装）
- 対象マイルストーン: MS-2 Phase 3
- ステータス: **未実測（人間による実機実行・妥当性判断待ち）**。数値は未記入で、実装済みの結果を装わない（REPAIR-3）

## 計測方法

テスト本体は [`crates/core/tests/cgroups_regression.rs`](../../../crates/core/tests/cgroups_regression.rs)（`harness = false`・実機前提）。`-- --ignored` 指定時のみ実行し、CI には組み込まない（`AGENTS.md`）。

```text
cargo test -p fandhe-container-core --test cgroups_regression --no-run
systemd-run --user --scope -p Delegate=yes <target/debug/deps/cgroups_regression-XXXX> --ignored
```

- 必要環境: 非特権ユーザーに委譲された cgroup v2 サブツリー（`memory`・`cpu` が委譲済み）・swap accounting 有効（無効だと `memory.swap.max` の書き込みが失敗する）・root もしくは非特権 user namespace を許可するホスト（`kernel.apparmor_restrict_unprivileged_userns=1` では user namespace を作れず OOM 検証が実行できない）
- 成功時の出力: `cgroups_regression: CORE-3 cgroup ordering and OOM kill verified`（終了コード 0）

## 計測環境

| 項目 | 値 |
| ---- | ---- |
| 計測対象コミット | （未記入） |
| 実施日（UTC） | （未記入） |
| 環境 | （未記入。例: Linux x86_64・カーネル版数・cgroup 委譲方法） |
| 実行ユーザー | （未記入。root か非 root か） |
| swap accounting | （未記入） |

## 実測結果

### 順序の検証

| 段階 | 確認内容 | 観測値 |
| ---- | -------- | ------ |
| `prepare` 前 | `/proc/self/cgroup` が `0::<委譲パス>`・子 cgroup なし・`subtree_control` に `memory`・`cpu` なし | （未記入） |
| `prepare` 前（負の対照） | `+memory` の書き込みが EBUSY（16）で失敗 | （未記入） |
| `prepare` 後 | 子の `cgroup.procs` が空・自プロセスが `fc-runtime` に退避・親の `cgroup.procs` が空・controller は未有効 | （未記入） |
| `enable_controllers` 後 | 戻り値と `cgroup.subtree_control` に `memory`・`cpu`・子に `memory.max` が出現 | （未記入） |

### OOM Kill の検証

| 項目 | 期待値 | 観測値 |
| ---- | ------ | ------ |
| `memory.max` / `memory.swap.max`（読み戻し） | `67108864` / `0` | （未記入） |
| `ChildExit` | `Signaled(9)` | （未記入） |
| シェル慣例の終了コード（128 + 9） | `137` | （未記入） |
| `memory.events` の `oom_kill` | `1` | （未記入） |
| `memory.events` の `oom` | `1` | （未記入） |
| 子 cgroup の削除 | 成功 | （未記入） |

## 結論

（未記入。実測後に人間が記入する）

## 妥当性判断（人間担当・TASK-36）

- 判断者・日付: （未記入）
- 判断: （未記入。`oom` が 1 で安定しない場合は `oom >= 1` への緩和の要否を含めて判断する）
