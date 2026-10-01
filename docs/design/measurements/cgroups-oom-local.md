# cgroups_oom 実機前提テストのローカル実行記録

`cgroups_oom`（`memory.max` 超過での OOM Kill 結合試験）を既定のテスト集合から分離していることの確認と、非特権ローカル環境での実行試行を記録する。

- 対象ビヘイビア: CORE-3（cgroups v2 によるメモリ上限と OOM Kill）
- 関連タスク: TASK-33.1（#164・PR #1214。テスト本体）・TASK-33.2（#165。本書）
- 対象マイルストーン: MS-2 Phase 3
- ステータス: **既定集合からの分離を確認済み。非特権ローカルでの試行は環境制限（AppArmor）により isolate で失敗し、合格の実行結果は未取得。root または sysctl 緩和での合格確認は人間へ引き継ぐ**（実装済みを装わない。REPAIR-3）

## 分離の仕組み

- `crates/core/Cargo.toml` の `[[test]] name = "cgroups_oom"` は `harness = false`。`main` は `--ignored` 引数があるときだけ実機処理を実行する
- 引数なし（`cargo test` / `make test`）では次を出力して終了コード 0 で終わり、OOM Kill 検証は行わない

```text
cgroups_oom: ignored (real-machine test; run with `-- --ignored`, see AGENTS.md)
```

- 確認コマンド: `cargo test -p fandhe-container-core --test cgroups_oom`（`CORE-3 OOM kill verified` 行が出ないことを確認）

## 必要環境・必要権限

- 委譲された cgroup v2 サブツリー（`memory` の委譲と swap accounting 有効）
- root、または非特権 user namespace を許可するホスト（AppArmor の `kernel.apparmor_restrict_unprivileged_userns=0` 等）
- `oom_score_adj` が -1000 でないこと

## 実行手順

```text
cargo test -p fandhe-container-core --test cgroups_oom --no-run 2>&1 | grep -o 'target/[^)]*cgroups_oom-[0-9a-f]*'
systemd-run --user --scope -p Delegate=yes <上で得た実行ファイル> --ignored
```

- `FANDHE_CONTAINER_TEST_TIMEOUT_SECS`（1〜600 秒、既定 10 秒）でタイムアウトを変更できる

## 試行環境（2026-10-01 UTC）

| 項目 | 値 |
| ---- | -- |
| uid | 1000（非 root） |
| カーネル / アーキテクチャ | 7.0.0-34-generic / x86_64 |
| `kernel.apparmor_restrict_unprivileged_userns` | 1 |
| `user.max_user_namespaces` | 102024 |
| `user@<uid>.service` の Delegate | yes（`cgroup.subtree_control`: `cpu memory pids`） |
| swap | 無効（`swapon --show` が空） |
| `oom_score_adj` | 0 |

## 試行結果

非 root で `systemd-run --user --scope -p Delegate=yes <実行ファイル> --ignored` を 1 回実行した。出力は次のとおり（panic。終了コードは取得していない）。

```text
thread 'main' panicked at crates/core/tests/cgroups_oom.rs:293:37:
isolate failed: PERMISSION_DENIED at SetGroups: setgroups failed: Permission denied (os error 13)
cleanup: remove container cgroup failed after panic: PERMISSION_DENIED at Cleanup: stat parent cgroup: errno 13
```

- 失敗は確保ループより前の isolate（user namespace の setgroups）で起きており、メモリは確保していない。原因は `apparmor_restrict_unprivileged_userns=1` による非特権 userns の制限と推定する（未検証）
- 試行後に `fc-*` の残存 cgroup と一時 rootfs（`fandhe-cgroups-oom-*`）は見つからなかった
- panic 後の子 cgroup 削除が errno 13 で失敗する事象は #1214 で報告済みで、本 issue の対象外（別途追跡）

## 合格確認の手順（人間が明示指示のもとで実施）

root 権限を要するため、Agent は実行していない。

1. 手順 (i): `sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0` の後、非 root で上記の実行手順を実行する。終了後に sysctl を元の値へ戻す
2. 手順 (ii): root で同じコマンドを実行する

合格の判定は次の 3 点。結果は本書と #165 に追記する。

- `cgroups_oom: CORE-3 OOM kill verified` が出力される
- 終了状態が `Signaled(9)`（シェル慣習 137）
- 子 cgroup の `memory.events` の `oom` / `oom_kill` が 0 から 1 になる
