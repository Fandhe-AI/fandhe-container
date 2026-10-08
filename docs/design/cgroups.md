# cgroups 対応範囲

MVP のリソース制限が cgroups v2 単独対応であることと、非対応とする範囲を定める（CORE-4）。

- 対象ビヘイビア: CORE-4（関連: SEC-6・CORE-3）
- タスク: TASK-34（MS-2）。前提は TASK-32（#153。cgroup v2 の実装）
- 関連 issue: #166
- 出典: `docs/spec/04-behavior/api-runtime-core.md` の `CORE-4`、`security-isolation.md` の `SEC-6`、`04-behavior/README.md` の制約事項・除外事項（submodule リビジョン `984f8a2`）

## 対応範囲

- cgroups v2（unified hierarchy）単独に対応する
- 非特権ユーザーに委譲された cgroup v2 サブツリー上で子 cgroup を作成し、controller（`memory`・`cpu`・`pids`・`io`）でリソースを制限する（CORE-3・SUP-13・TASK-170）

## 非対応

- cgroups v1
- hybrid 構成（`/proc/self/cgroup` に v1 の行が 1 行でも混在する構成）
- systemd cgroup driver

### 「systemd cgroup driver 非対応」の意味

- 本ランタイムは cgroupfs（`/sys/fs/cgroup` 配下）へ直接書き込んで cgroup を管理する。systemd の D-Bus API（transient unit の作成等）経由で cgroup を操作する driver は持たない
- 一方、systemd が委譲した cgroup v2 サブツリー（例: `systemd-run --user --scope -p Delegate=yes`）の上で動作することは前提環境として許容する。これは委譲を受ける側であり、driver ではない（実機前提テストの実行手順は `AGENTS.md` を参照）

## 非対応とする理由

### spec に明記された理由（SEC-6）

- cgroups v2 には `release_agent` 機構が存在しないため、cgroup release_agent を悪用するコンテナエスケープ手法（クラス 2）が構造的に無効化される
- 本書の主張はこの範囲に限る。cgroups v2 化だけでコンテナエスケープ全般を防げるとは述べない

### 実装上の理由（spec の主張ではなく、本リポの設計判断）

- 階層が単一であり、実装・検証対象を 1 系統に絞れる（改修の波及を最小に保つ。REPAIR-1）
- cgroup v2 の委譲モデルにより rootless でのリソース制限が成立し、no-internal-process 制約に沿った「子 cgroup 作成、自プロセスの退避、controller 有効化」の順序（CORE-3）を一貫して扱える
- v1 の controller ごとの階層や systemd driver を併存させないことで、攻撃面とコード量を抑える（フルスクラッチ・依存最小方針と整合）

## 実装での担保（fail-closed）

`crates/core/src/cgroups.rs` で v1 / hybrid を拒否する。

- `parse_self_cgroup_v2`: `/proc/self/cgroup` に v1 の行が混在する場合、または `0::` 行が無い場合は `FailedPrecondition`（段 `CgroupStep::ReadSelfCgroup`）で拒否する
- `verify_cgroup2`: `/sys/fs/cgroup` と対象 cgroup が cgroup2 ファイルシステム（`CGROUP2_SUPER_MAGIC`）であることを `fstatfs` で確認する（段 `CgroupStep::VerifyCgroup2`）
- 対応するユニットテスト: `core4_sec6_task32_1_parse_self_cgroup_v2_rejects_hybrid`

## exec 用の子 cgroup と `cgroup.kill`（SUP-6・SUP-4・TASK-163 追補・#1466）

exec のコマンドは、コンテナ cgroup（`<scope>/fc-<id>@<instance>`）の直下に exec ごとに作る子 cgroup `exec-<nonce>` へ入れて実行し、期限切れ・中断・worker 異常終了のいずれでも `cgroup.kill` で子孫ごと停止して削除する。

- `cgroup.kill` は Linux 5.14 以降。開けなければ exec を拒否する（fail-closed。親死亡シグナルだけへ縮退しない）
- 内部プロセス禁止規則: `fc-<id>@<instance>` は pid1 を直接持つため、その `cgroup.subtree_control` は空のままにし、`exec-*` にも controller を有効化しない。`memory.max`・`pids.max` 等は親から階層的に子孫へ掛かる
- 名前は `exec-` 接頭辞で、コンテナ用の `fc-` と衝突しない（`Pid1Target` の cgroup 完全一致照合に影響しない）
- 実装は `crates/core/src/cgroups/exec_kill.rs`・`crates/core/src/exec/cgroup_join.rs`。実機前提テストは `crates/core/tests/exec_cgroup_kill.rs`（AGENTS.md）

## 関連・後続

- TASK-35（SEC-6・CORE-4）で release_agent 悪用手法の無効化確認を記録する。本書は当該確認が済んでいるとは主張しない

## 見直し

CORE-4 / SEC-6 が spec 側で変更された場合、または v1・systemd cgroup driver 対応をスコープに加える場合は、spec（SSOT）でビヘイビア・タスクを定義したうえで本書を更新する。
