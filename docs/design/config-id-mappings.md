# config の linux.uidMappings・gidMappings の扱い（判断記録）

OCI config の `linux.uidMappings` / `gidMappings` を受けるか拒むかの判断材料を整理する（SEC-5・CORE-6）。

> **位置づけ**: 状態は **オーナー承認待ち**（[#2240](https://github.com/Fandhe-AI/fandhe-container/issues/2240)）。本書は決定ではなく判断材料である。決まるまで `start` は拒否のままにする（分離を緩めない）。

- 対象ビヘイビア: SEC-5（コンテナ内 root をホストの非特権 UID へ写す）・CORE-6（rootless）
- タスク: TASK-40。関連: #2009・PR #2209（launcher 経由の subuid / subgid 範囲写像 `RootlessSubordinateIds`）

## 現状

- `crates/core/src/oci_runtime/start.rs` の `reject_config_id_mappings` が、どちらかの配列が非空なら `Unimplemented`（message: `start does not support yet: linux.uidMappings / linux.gidMappings`）で拒否する。空配列は受ける。fork・予約より前で、プロセスも状態も残さない
- パース段階（`config.rs`）で件数の上限（340。カーネルの上限）・`size` が 1 以上・`containerID + size` の桁あふれは検証済み
- 写像は launcher が権限モデルから導く。`RootlessSingleId` は呼び出し側の euid / egid への単一写像、`RootlessSubordinateIds` は `/etc/subuid`・`/etc/subgid` 由来の範囲写像

## 選択肢

### A. 拒否を維持して確定する（推奨）

写像は権限モデルから導く。config で指定させると launcher の SEC-5 の契約を迂回できてしまうため。

- 決定後の変更案: code を `InvalidArgument` に替え、固定文言を `linux.uidMappings / linux.gidMappings are not accepted: ID mappings are derived from the runtime privilege model (SEC-5)` とする（config の値を含めない静的な文言）。空配列は従来どおり受ける
- Docker / runc との差: runc は config の写像をそのまま書き込むが、本ランタイムは受けない。利用者向けの doc に書く

### B. 受ける

必要になる設計:

- 各行が呼び出し側の subuid / subgid の範囲（`rootless.rs` の解析と `SubIdOwner` を再利用）か自身の euid に収まること
- hostID 0 を含む行は拒否する。containerID 0 は非 0 の hostID へ写す（SEC-5）
- 件数は上限 340 で縛られている。加えて size の合計と範囲の幅に上限を設ける（DoS 対策）
- container 側・host 側とも行どうしの重なりを拒否する
- `process.user` の uid・gid が写像に含まれること（既存の `check_user_mapped`）
- 写像を `LaunchSpec` に載せる新フィールドを足し、launcher の `RootlessSubordinateIds` 経路へ配線する
- エラーは `InvalidArgument`（割り当て範囲の外を `PermissionDenied` とするかは判断事項）

### C. 未決定のまま `Unimplemented` を続ける

本書時点の状態。"yet" の文言は未決定を表している。

## 本書の時点で済ませたこと・決定後に残る作業

- 済み: 拒否を専用関数に切り出し、code と message の完全一致をテストで固定。コード中の「確認待ち」の参照先を #2240 と本書へ統一
- 残り: A なら `InvalidArgument` への変更と doc。B なら上記の設計の実装（後続の実装 issue）
- 監査（SEC-4）には記録しない。config の誤りであり、脱出の試行ではないため
